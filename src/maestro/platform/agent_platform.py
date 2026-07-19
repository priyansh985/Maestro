"""The agent control loop: LLM proposes, the enforcement point authorizes.

:class:`AgentPlatform` composes the security control plane into a single,
secure-by-default execution path:

* a **reasoner** (offline :class:`~maestro.agent.reasoning.StubReasoner` by
  default, or any connector-backed model) turns a telemetry
  :class:`~maestro.telemetry.detection.Alert` into a *proposed* action;
* the platform deterministically assembles that proposal into a **typed
  :class:`~maestro.security.action.ActionProposal`** (allow-listed intent,
  resolved resource, grounded evidence);
* the **:class:`~maestro.security.enforcement.PolicyEnforcementPoint`** is the
  only thing that may authorize + execute it — under a scoped capability, a
  residual-risk decision, an action-confidence gate, an autonomy budget, a
  circuit breaker, and a tamper-evident ledger.

Every alert produces exactly one authorized *or* denied outcome, and every
outcome is recorded. There is no bypass path from the model to a tool.
"""
from __future__ import annotations

import os
import secrets
from collections.abc import Iterable
from dataclasses import dataclass

from ..memory import MemoryScope, MemoryStore, MemoryTier
from ..security.action import REVERSIBLE_INTENTS, ActionProposal
from ..security.budget import AutonomyBudget
from ..security.circuit_breaker import CircuitBreaker
from ..security.confidence import ConfidenceSignals
from ..security.enforcement import (
    Approver,
    EnforcementResult,
    PolicyEnforcementPoint,
    ToolAdapter,
)
from ..security.identity import SIGNING_KEY_ENV, CapabilityIssuer
from ..security.ledger import Ledger
from ..security.risk_engine import RiskInputs
from ..telemetry.detection import Alert, AlertClass
from .blast_radius import BlastRadius

#: The resource each operational intent touches (the capability's scope + the
#: proposal's target). Bounded, explicit — the executor's vocabulary.
_INTENT_RESOURCE: dict[str, str] = {
    "noop": "agent:self",
    "throttle_telemetry": "telemetry:ws-stream",
    "raise_thresholds": "detection:thresholds",
    "raise_capture_duration": "capture:params",
    "alert_operator": "operator:oncall",
    "rollback_telemetry": "telemetry:checkpoint",
}
#: Default per-intent TTL applied to the proposed action.
_DEFAULT_TTL_S = 900


def default_tool_adapters() -> dict[str, ToolAdapter]:
    """Bounded stand-in adapters that model each mitigation's effect.

    In a real deployment these would call a firewall / SOAR / capture control
    through a sandbox; here they record the intended effect and satisfy the
    postcondition (``ok=True``) so the enforcement pipeline can be exercised
    end-to-end offline.
    """
    def _effect(effect: str) -> ToolAdapter:
        def adapter(p: ActionProposal) -> dict:
            return {"ok": True, "effect": effect, "target": p.target}
        return adapter

    return {
        "noop": lambda p: {"ok": True, "effect": "no-op"},
        "throttle_telemetry": _effect("telemetry stream throttled"),
        "raise_thresholds": _effect("detection thresholds raised"),
        "raise_capture_duration": _effect("capture duration increased"),
        "alert_operator": _effect("operator notified"),
        "rollback_telemetry": _effect("telemetry rolled back to checkpoint"),
    }


def shadow_tool_adapters() -> dict[str, ToolAdapter]:
    """Adapters for **shadow mode** (blueprint §5): the full decision pipeline
    runs and records, but the side effect is *withheld* — the postcondition is
    satisfied so the outcome is logged, yet nothing is actually done. This is how
    a new policy/model is evaluated against real traffic before it is granted
    execution.
    """
    def _withhold(intent: str) -> ToolAdapter:
        def adapter(p: ActionProposal) -> dict:
            return {"ok": True, "shadow": True, "withheld": intent, "target": p.target}
        return adapter

    return {intent: _withhold(intent) for intent in default_tool_adapters()}


@dataclass
class PlatformResult:
    """Outcome of handling one alert through the control plane."""

    alert_class: str
    proposed_action: str
    enforcement: EnforcementResult

    @property
    def allowed(self) -> bool:
        return self.enforcement.allowed

    @property
    def decision(self) -> str:
        return self.enforcement.decision.value

    @property
    def reason(self) -> str:
        return self.enforcement.reason

    @property
    def decision_card(self) -> dict:
        return self.enforcement.decision_card

    @property
    def shadowed(self) -> bool:
        """True if the action was authorized but its side effect was withheld
        (shadow mode) rather than executed."""
        return bool(self.enforcement.output and self.enforcement.output.get("shadow"))


class AgentPlatform:
    """Secure-by-default agent orchestration over the enforcement plane."""

    def __init__(
        self,
        *,
        reasoner: object | None = None,
        tenant: str = "default",
        controller: str = "human:operator",
        agent_id: str = "agent:network-monitor:run",
        key: bytes | str | None = None,
        adapters: dict[str, ToolAdapter] | None = None,
        approver: Approver | None = None,
        budget: AutonomyBudget | None = None,
        breaker: CircuitBreaker | None = None,
        allowed_intents: Iterable[str] | None = None,
        shadow: bool = False,
        capability_ttl_s: float = _DEFAULT_TTL_S,
    ) -> None:
        from ..agent.reasoning import StubReasoner

        # A single signing key backs both capabilities and the ledger HMAC.
        # Fall back to an ephemeral process-local key so the platform runs
        # offline out of the box (capabilities are process-scoped anyway).
        resolved_key = key or os.environ.get(SIGNING_KEY_ENV) or secrets.token_hex(32)

        self._reasoner = reasoner if reasoner is not None else StubReasoner()
        self._tenant = tenant
        self._agent_id = agent_id
        self._issuer = CapabilityIssuer(key=resolved_key)
        self._ledger = Ledger(key=resolved_key)

        # Live memory: every action is grounded in a scoped, provenance-tagged
        # episodic record. The store shares the platform's signing key + ledger,
        # so actions and memory events form one unified tamper-evident trail.
        self._scope = MemoryScope(tenant, agent_id)
        self._memory = MemoryStore(issuer=self._issuer, ledger=self._ledger)

        # Secure-by-default operational controls (non-optional on this path).
        # In shadow mode the pipeline runs fully but withholds side effects.
        self._shadow = shadow
        self._budget = budget if budget is not None else AutonomyBudget(
            max_tool_calls=1000, window_seconds=60.0, max_calls_per_window=120)
        default_adapters = shadow_tool_adapters() if shadow else default_tool_adapters()
        self._pep = PolicyEnforcementPoint(
            issuer=self._issuer,
            ledger=self._ledger,
            evidence_exists=self._evidence_exists,
            tenant=tenant,
            adapters=adapters if adapters is not None else default_adapters,
            approver=approver,
            budget=self._budget,
            breaker=breaker if breaker is not None else CircuitBreaker(
                max_repeats=5, window_seconds=60.0),
        )

        # Capabilities delegated to this agent by its human controller, one per
        # operational intent in this agent's (possibly restricted) vocabulary.
        # A restricted vocabulary is least-privilege: the agent simply holds no
        # capability for intents outside it, so the gateway denies them — which
        # is what makes provisioning secure-by-inheritance (see platform.provisioning).
        from ..security.action import INTENT_REGISTRY

        vocabulary = tuple(_INTENT_RESOURCE) if allowed_intents is None else tuple(allowed_intents)
        self._caps = {}
        for intent in vocabulary:
            if intent not in _INTENT_RESOURCE:
                raise ValueError(
                    f"intent {intent!r} is not in the platform vocabulary {tuple(_INTENT_RESOURCE)}")
            resource = _INTENT_RESOURCE[intent]
            capability = INTENT_REGISTRY[intent][1]
            self._caps[intent] = self._issuer.issue(
                subject=agent_id, capability=capability, resource_constraint=resource,
                tenant=tenant, ttl_seconds=capability_ttl_s,
                delegation_depth=1, parent=controller)

    # -- introspection ------------------------------------------------------- #
    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def pep(self) -> PolicyEnforcementPoint:
        return self._pep

    @property
    def shadow(self) -> bool:
        """True if this platform withholds side effects (evaluation mode)."""
        return self._shadow

    @property
    def memory(self) -> MemoryStore:
        """The scoped, four-tier memory store backing this agent's evidence."""
        return self._memory

    @property
    def scope(self) -> MemoryScope:
        """This agent's ``(tenant, agent)`` memory isolation scope."""
        return self._scope

    def _evidence_exists(self, evidence_id: str) -> bool:
        """Resolve an evidence reference against scoped memory (anti-hallucination).

        Existence — not trust — is the anti-ghost check: a quarantined detection
        is still a real citation. Isolation is enforced here too: an evidence id
        from another scope does not resolve.
        """
        return self._memory.exists(evidence_id, self._scope)

    def blast_radius(self) -> BlastRadius:
        """Enumerate this agent's bounded reach (blueprint §2) — legible on one screen.

        Built from what the agent actually holds: its delegated capabilities, its
        allow-listed intent vocabulary, the reversible/irreversible split, and the
        budget envelope. If this cannot be enumerated, the agent is not bounded.
        """
        from ..security.action import INTENT_REGISTRY, REVERSIBLE_INTENTS

        intents = tuple(sorted(self._caps))
        capabilities = tuple(sorted({INTENT_REGISTRY[i][1] for i in intents}))
        reversible = tuple(i for i in intents if i in REVERSIBLE_INTENTS)
        irreversible = tuple(i for i in intents if i not in REVERSIBLE_INTENTS)
        return BlastRadius(
            agent_id=self._agent_id,
            tenant=self._tenant,
            capabilities=capabilities,
            intent_vocabulary=intents,
            reversible_intents=reversible,
            irreversible_intents=irreversible,
            budget={
                "max_tool_calls": self._budget.max_tool_calls,
                "max_spend": self._budget.max_spend,
                "max_affected": self._budget.max_affected,
                "window_seconds": self._budget.window_seconds,
                "max_calls_per_window": self._budget.max_calls_per_window,
            },
        )

    def halt(self) -> None:
        """Trip the kill switch — deny all further actions."""
        self._pep.halt()

    def resume(self) -> None:
        self._pep.resume()

    # -- the control loop ---------------------------------------------------- #
    def handle_alert(self, alert: Alert) -> PlatformResult:
        """Run one alert through: reason → propose → authorize/execute/record."""
        # 1. Ground the action in a real detection recorded in scoped memory.
        #    quarantine-on-ingest: the record lands UNTRUSTED, so an injected
        #    poison record can never influence the agent — yet the detection is a
        #    real, provenance-tagged, hash-integrity reference the evidence gate
        #    resolves. The *stable alert key* (not the fresh record id) drives
        #    idempotency, so replaying the same alert is still caught.
        alert_key = f"alert:{alert.cls.value}:{alert.ts:.0f}"
        record = self._memory.remember(
            self._scope, MemoryTier.EPISODIC, f"{alert.cls.value}: {alert.detail}",
            source="telemetry:detector",
            attributes={"severity": alert.severity, "class": alert.cls.value},
            record_id=alert_key)
        evidence_id = record.record_id  # == alert_key (stable per detection)

        # 2. The reasoner PROPOSES an action (LLM or offline stub).
        result = self._reasoner.reason(alert)  # type: ignore[attr-defined]
        intent = result.action

        # 3. Deterministically assemble a typed proposal. The model does not get
        #    to choose scope: resource + ttl come from the platform, not the LLM.
        #    An out-of-scope proposal is NOT coerced to a no-op — it is passed
        #    through so the enforcement point denies it (no capability → capability
        #    denial; unknown intent → schema quarantine), and the attempt is
        #    audited rather than silently swallowed.
        raw = {
            "intent": intent,
            "target": _INTENT_RESOURCE.get(intent, f"unscoped:{intent}"),
            "reason": result.summary,
            "evidence_ids": [evidence_id],
            "requested_ttl_seconds": _DEFAULT_TTL_S,
        }

        reversible = intent in REVERSIBLE_INTENTS
        risk = _derive_risk(alert, reversible)
        confidence = _derive_confidence(alert, reversible)
        token = self._caps.get(intent)
        idem = f"{alert_key}:{intent}"

        # 4. The enforcement point is the ONLY path to a side effect.
        enforcement = self._pep.submit_raw(
            raw, token=token, risk=risk, actor=self._agent_id,
            confidence=confidence, idempotency_key=idem)
        return PlatformResult(alert.cls.value, intent, enforcement)


def _clamp(x: float) -> float:
    return max(1.0, min(5.0, x))


def _derive_risk(alert: Alert, reversible: bool) -> RiskInputs:
    """Map an alert to operational risk dimensions.

    Reversible mitigations carry low recoverability cost and blast radius, so
    they can execute with safeguards; irreversible actions escalate. Severity
    (0–1) scales likelihood/impact/exploitability onto the 1–5 scale.
    """
    sev = alert.severity
    return RiskInputs(
        likelihood=_clamp(1.5 + 1.5 * sev),
        impact=_clamp(1.0 + (1.5 if reversible else 4.0) * sev),
        exploitability=_clamp(1.0 + 2.0 * sev),
        exposure=2.0,
        detectability_inverse=2.0,          # we detected it — easy to see
        recoverability_inverse=1.0 if reversible else 4.0,
        blast_radius=2.0 if reversible else 4.0,
        uncertainty=0.1,
    )


def _derive_confidence(alert: Alert, reversible: bool) -> ConfidenceSignals:
    """Confidence from independent signals (not model self-report)."""
    grounded = alert.cls != AlertClass.NORMAL
    # A baseline (NORMAL) reading is still a real detection, just lower-signal;
    # it should not, on its own, escalate a no-op to human approval.
    return ConfidenceSignals(
        evidence_quality=0.9 if grounded else 0.8,
        validator_agreement=1.0,            # proposal passed the typed schema
        policy_compatibility=1.0,           # intent is in the allow-list
        reversibility=1.0 if reversible else 0.4,
        historical_reliability=0.8,
    )
