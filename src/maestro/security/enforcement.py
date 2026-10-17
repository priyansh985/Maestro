"""Policy Enforcement Point — the executor gateway (Enforcement Plane / L3).

This is the single side-effect boundary the research insists on: an LLM may
*propose* a typed action, but only this independent gateway may authorize and
execute it. Authorization is **not** in the planner — a compromised or buggy
planner (or a direct tool call) would bypass a planner-side check — so the
decisive validation lives here, where the side effect actually happens.

The pipeline is fail-closed at every step (any error → deny + audit):

    parse/typed proposal
      → evidence-reference validation
      → risk / blast-radius decision   (security.risk_engine)
      → capability validation          (security.identity)
      → approval gate                  (risk band + capability-required rule)
      → allow-listed, sandboxed adapter execution
      → postcondition verification
      → append tamper-evident audit event   (security.ledger)

Every terminal outcome — allow or deny — is written to the ledger, so a denial
is as auditable as an execution.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from .action import ActionProposal, InvalidProposal, parse_proposal
from .budget import AutonomyBudget, BudgetError
from .circuit_breaker import CircuitBreaker
from .confidence import ConfidenceBand, ConfidenceSignals, action_confidence, confidence_band
from .critique_gate import PreExecutionGate
from .identity import CapabilityError, CapabilityIssuer, CapabilityToken
from .ledger import Ledger
from .policy_bundle import PolicyChangeError, PolicyRegistry
from .risk_engine import (
    WEIGHTS,
    Control,
    Decision,
    RiskInputs,
    decide,
    residual_risk,
    uncertainty_adjusted,
)
from .sandbox import ExecutionSandbox, SandboxViolation


class ActionState(str, Enum):
    """Terminal states of the action lifecycle (see docs/SECOPS.md).

    The full lifecycle is CREATED → CONTEXT_VALIDATED → PLAN_PROPOSED →
    POLICY_EVALUATED → APPROVAL_PENDING → AUTHORIZED → EXECUTING →
    POSTCONDITION_VERIFIED → COMPLETED; the gateway never transitions directly
    from PLAN_PROPOSED to EXECUTING. Only the terminal states are surfaced.
    """

    COMPLETED = "completed"
    DENIED = "denied"
    QUARANTINED = "quarantined"
    ESCALATED = "escalated"


#: Restrictiveness order used to *raise* (never lower) a decision.
_RESTRICTIVENESS = [
    Decision.ALLOW,
    Decision.ALLOW_WITH_SAFEGUARDS,
    Decision.REQUIRE_APPROVAL,
    Decision.DENY_AUTONOMOUS,
    Decision.EMERGENCY_CONTAINMENT,
]


def _most_restrictive(a: Decision, b: Decision) -> Decision:
    return a if _RESTRICTIVENESS.index(a) >= _RESTRICTIVENESS.index(b) else b

#: A bounded tool: takes a validated proposal, performs the side effect through
#: a constrained adapter, and returns a result dict containing at least ``ok``.
ToolAdapter = Callable[[ActionProposal], dict]
#: An approver: given the proposal, decision, and residual risk, returns True to
#: authorize a REQUIRE_APPROVAL-band action.
Approver = Callable[[ActionProposal, Decision, float], bool]

#: Version stamp of the active risk policy, recorded on every audit event so a
#: decision can be reproduced against the exact weights that produced it.
POLICY_DIGEST = "sha256:" + hashlib.sha256(
    json.dumps(WEIGHTS, sort_keys=True).encode("utf-8")).hexdigest()

#: Risk bands that terminate without executing, regardless of capability.
_HARD_DENY = {Decision.DENY_AUTONOMOUS, Decision.EMERGENCY_CONTAINMENT}


@dataclass
class EnforcementResult:
    allowed: bool
    decision: Decision
    reason: str
    residual_risk: float
    output: dict = field(default_factory=dict)
    event_id: str = ""
    state: ActionState = ActionState.DENIED
    decision_card: dict = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "decision": self.decision.value,
            "reason": self.reason,
            "residual_risk": self.residual_risk,
            "output": self.output,
            "event_id": self.event_id,
            "state": self.state.value,
            "decision_card": self.decision_card,
        }


class PolicyEnforcementPoint:
    """Independent authorization + execution boundary for agent-proposed actions."""

    def __init__(
        self,
        *,
        issuer: CapabilityIssuer,
        ledger: Ledger,
        evidence_exists: Callable[[str], bool],
        tenant: str,
        adapters: dict[str, ToolAdapter],
        approver: Approver | None = None,
        budget: AutonomyBudget | None = None,
        breaker: CircuitBreaker | None = None,
        sandbox: ExecutionSandbox | None = None,
        pre_execution_gate: PreExecutionGate | None = None,
        policy_registry: PolicyRegistry | None = None,
    ) -> None:
        self._issuer = issuer
        self._ledger = ledger
        self._evidence_exists = evidence_exists
        self._tenant = tenant
        self._adapters = dict(adapters)
        self._approver = approver
        self._budget = budget
        self._breaker = breaker
        # Governed policy allow-list (CTRL-L6-03): the signed, two-person-approved
        # policy bundle whose intent allow-list is verified at this boundary
        # before every side effect. Optional — when None the boundary behaves as
        # before (the static INTENT_REGISTRY allow-list still applies upstream).
        self._policy = policy_registry
        # Pre-execution critique gate (BP7): runs the proposed action through the
        # HMDC engine + environmental verifier as the last check before the side
        # effect. Optional — when None the boundary behaves exactly as before.
        self._gate = pre_execution_gate
        # The executor sandbox confines the side effect (scope + output bounds)
        # and provides durable exactly-once replay. Default-constructed so the
        # confinement is non-optional on every executed action; callers pass a
        # journal-backed sandbox for cross-crash durability.
        self._sandbox = sandbox if sandbox is not None else ExecutionSandbox()
        self._halted = False
        #: idempotency key -> event_id of the action that already executed it.
        self._executed_keys: dict[str, str] = {}

    # -- kill switch (L7) ---------------------------------------------------- #
    def halt(self) -> None:
        """Trip the kill switch: deny everything until :meth:`resume`."""
        self._halted = True

    def resume(self) -> None:
        self._halted = False

    @property
    def halted(self) -> bool:
        return self._halted

    # -- entry points -------------------------------------------------------- #
    def submit_raw(
        self,
        raw: object,
        *,
        token: CapabilityToken | None,
        risk: RiskInputs,
        actor: str,
        controls: list[Control] | None = None,
        confidence: ConfidenceSignals | None = None,
        cost: float = 0.0,
        affected: int = 0,
        idempotency_key: str | None = None,
        verification_context: dict | None = None,
    ) -> EnforcementResult:
        """Parse untrusted model output, then authorize + execute."""
        try:
            proposal = parse_proposal(raw)
        except InvalidProposal as exc:
            return self._deny("schema", str(exc), Decision.DENY_AUTONOMOUS,
                              actor=actor, input_hash=_hash_raw(raw), residual=5.0,
                              state=ActionState.QUARANTINED)
        return self.authorize_and_execute(
            proposal, token=token, risk=risk, actor=actor, controls=controls,
            confidence=confidence, cost=cost, affected=affected,
            idempotency_key=idempotency_key, verification_context=verification_context)

    def authorize_and_execute(
        self,
        proposal: ActionProposal,
        *,
        token: CapabilityToken | None,
        risk: RiskInputs,
        actor: str,
        controls: list[Control] | None = None,
        confidence: ConfidenceSignals | None = None,
        cost: float = 0.0,
        affected: int = 0,
        idempotency_key: str | None = None,
        verification_context: dict | None = None,
    ) -> EnforcementResult:
        input_hash = proposal.content_hash()

        def deny(stage: str, reason: str, decision: Decision, residual: float,
                 *, state: ActionState = ActionState.DENIED, detail: dict | None = None
                 ) -> EnforcementResult:
            return self._deny(stage, reason, decision, actor=actor, input_hash=input_hash,
                              residual=residual, proposal=proposal, confidence_score=conf_score,
                              state=state, detail=detail)

        conf_score = action_confidence(confidence) if confidence else None

        # 0. Kill switch.
        if self._halted:
            return deny("kill_switch", "enforcement halted", Decision.EMERGENCY_CONTAINMENT,
                        5.0, state=ActionState.ESCALATED)

        # 1. Idempotency — one business request maps to one executed action.
        if idempotency_key and idempotency_key in self._executed_keys:
            return deny("idempotency",
                        f"duplicate intent key already executed as "
                        f"{self._executed_keys[idempotency_key]}",
                        Decision.DENY_AUTONOMOUS, uncertainty_adjusted(risk))

        # 1b. Circuit breaker — halt a runaway loop of identical attempts.
        if self._breaker is not None:
            signature = f"{proposal.intent}|{input_hash}"
            if self._breaker.record_and_check(signature):
                return deny("circuit_breaker",
                            f"action repeated >= {self._breaker.max_repeats} times; halted",
                            Decision.EMERGENCY_CONTAINMENT, uncertainty_adjusted(risk),
                            state=ActionState.ESCALATED)

        # 2. Evidence-reference validation: no ghost justifications.
        missing = [e for e in proposal.evidence_ids if not self._evidence_exists(e)]
        if not proposal.evidence_ids or missing:
            reason = ("no evidence referenced" if not proposal.evidence_ids
                      else f"unknown evidence: {missing}")
            return deny("evidence", reason, Decision.DENY_AUTONOMOUS, uncertainty_adjusted(risk))

        # 3. Risk / blast-radius decision.
        residual = residual_risk(risk, controls or [])
        decision = decide(residual)

        # 4. Confidence gate — an *input* that only raises scrutiny, never
        #    authorizes. Low confidence downgrades an otherwise-permissive band.
        if conf_score is not None:
            band = confidence_band(conf_score)
            if band == ConfidenceBand.DENY:
                return deny("confidence", f"action confidence {conf_score:.2f} below floor",
                            _most_restrictive(decision, Decision.DENY_AUTONOMOUS), residual)
            if band == ConfidenceBand.APPROVAL or (
                    band == ConfidenceBand.REVERSIBLE_ONLY and proposal.requires_capability()):
                decision = _most_restrictive(decision, Decision.REQUIRE_APPROVAL)

        # 5. Capability validation — mandatory for capability-required classes,
        #    and for anything that isn't a clean autonomous allow.
        needs_cap = proposal.requires_capability() or decision != Decision.ALLOW
        if needs_cap:
            try:
                if token is None:
                    raise CapabilityError("no capability presented")
                self._issuer.verify(
                    token,
                    capability=proposal.capability,
                    resource_constraint=proposal.resource,
                    tenant=self._tenant,
                )
            except CapabilityError as exc:
                return deny("capability", str(exc), decision, residual)

        # 6. Hard-deny risk bands never execute autonomously.
        if decision in _HARD_DENY:
            return deny("risk", f"residual risk {residual:.2f} -> {decision.value}",
                        decision, residual, state=ActionState.ESCALATED)

        # 7. Approval gate for the REQUIRE_APPROVAL band.
        if decision == Decision.REQUIRE_APPROVAL:
            approved = bool(self._approver and self._approver(proposal, decision, residual))
            if not approved:
                return deny("approval", "human approval required and not granted",
                            decision, residual, state=ActionState.ESCALATED)

        # 8. Budget / rate limit (the BudgetAvailable conjunct).
        if self._budget is not None:
            try:
                self._budget.check(cost=cost, affected=affected)
            except BudgetError as exc:
                return deny("budget", str(exc), decision, residual, state=ActionState.ESCALATED)

        # 8.5 Governed policy allow-list (CTRL-L6-03). The set of permitted
        #     intents is not merely whatever the code registry says — it is a
        #     signed, versioned, two-person-approved policy bundle whose integrity
        #     is re-verified here, at the boundary, before every side effect. A
        #     tampered/absent active bundle, or an intent the active policy does
        #     not permit, fails closed.
        if self._policy is not None:
            try:
                bundle = self._policy.active().bundle
            except PolicyChangeError as exc:
                return deny("policy_bundle", f"no valid active policy: {exc}",
                            _most_restrictive(decision, Decision.DENY_AUTONOMOUS), residual)
            if not bundle.permits(proposal.intent):
                return deny(
                    "policy_bundle",
                    f"intent {proposal.intent!r} not permitted by active policy bundle "
                    f"v{bundle.version}",
                    _most_restrictive(decision, Decision.DENY_AUTONOMOUS), residual)

        # 9. Allow-listed adapter (the executor only speaks a bounded vocabulary).
        adapter = self._adapters.get(proposal.intent)
        if adapter is None:
            return deny("adapter", f"no adapter for intent {proposal.intent!r}", decision, residual)

        # 9.5 Pre-execution critique gate (BP7) — the last check before the side
        #     effect. Runs the proposed action through the HMDC engine + the
        #     environmental verifier. A deterministic guardrail/verifier failure
        #     denies autonomously; probabilistic judge uncertainty routes to a
        #     human (the existing approver). Fail-closed if the gate itself errors.
        gate_detail: dict | None = None
        if self._gate is not None:
            try:
                outcome = self._gate(proposal, verification_context or {})
            except Exception as exc:  # noqa: BLE001 — a gate failure fails closed.
                return deny("critique", f"critique gate raised: {exc}", decision, residual)
            gate_detail = outcome.detail
            if not outcome.allow:
                if outcome.escalate:
                    approved = bool(
                        self._approver and self._approver(proposal, decision, residual))
                    if not approved:
                        return deny(
                            "critique", f"routed to human [{outcome.verdict}]: {outcome.reason}",
                            _most_restrictive(decision, Decision.REQUIRE_APPROVAL), residual,
                            state=ActionState.ESCALATED, detail={"critique": gate_detail})
                else:
                    return deny(
                        "critique", f"{outcome.verdict}: {outcome.reason}",
                        _most_restrictive(decision, Decision.DENY_AUTONOMOUS), residual,
                        detail={"critique": gate_detail})

        # 10. Sandboxed execution + postcondition verification. The sandbox
        #     confines the side effect (scope + output bounds) and replays a
        #     journaled result exactly-once across a crash; any breach or adapter
        #     failure fails closed.
        try:
            output, replayed = self._sandbox.run(
                adapter, proposal, idempotency_key=idempotency_key)
        except SandboxViolation as exc:
            return deny("sandbox", str(exc), decision, residual)
        except Exception as exc:  # noqa: BLE001 — any adapter failure fails closed.
            return deny("execution", f"adapter raised: {exc}", decision, residual)
        if not isinstance(output, dict) or not output.get("ok", False):
            return deny("postcondition", "adapter postcondition not satisfied", decision,
                        residual, detail={"output": output})

        # 11. Authorized + executed — commit budget, record idempotency, audit.
        if self._budget is not None:
            self._budget.consume(cost=cost, affected=affected)
        card = self._decision_card(
            proposal, decision, residual, conf_score, "executed", actor, "authorized")
        event = self._ledger.append(
            event_type="tool.execution.authorized",
            actor_identity=actor,
            decision=decision.value,
            input_hash=input_hash,
            policy_digest=POLICY_DIGEST,
            risk_before=uncertainty_adjusted(risk),
            risk_after=residual,
            detail={"intent": proposal.intent, "target": proposal.target,
                    "output": output, "replayed": replayed,
                    "critique": gate_detail, "decision_card": card},
        )
        if idempotency_key:
            self._executed_keys[idempotency_key] = event.event_id
        card["decision_id"] = event.event_id
        return EnforcementResult(
            allowed=True, decision=decision, reason="authorized",
            residual_risk=round(residual, 4), output=output, event_id=event.event_id,
            state=ActionState.COMPLETED, decision_card=card)

    # -- helpers ------------------------------------------------------------- #
    def _decision_card(
        self,
        proposal: ActionProposal,
        decision: Decision,
        residual: float,
        confidence: float | None,
        execution_status: str,
        actor: str,
        reason_summary: str,
    ) -> dict:
        """Structured, chain-of-thought-free record for Decision Observability.

        Deliberately excludes any raw model reasoning / scratchpad / prompt
        content: only identity, the *validated* proposal, evidence references,
        the policy result, and the outcome are retained.
        """
        return {
            "decision_id": "",  # filled in with the ledger event id
            "actor_identity": actor,
            "intent": proposal.intent,
            "proposed_action": proposal.intent,
            "action_parameters": {"target": proposal.target,
                                  "ttl_seconds": proposal.requested_ttl_seconds},
            "action_class": proposal.action_class,
            "capability": proposal.capability,
            "evidence_ids": list(proposal.evidence_ids),
            "input_hash": proposal.content_hash(),
            "policy_result": decision.value,
            "risk_score": round(residual, 4),
            "risk_band": decision.value,
            "action_confidence": round(confidence, 4) if confidence is not None else None,
            "execution_status": execution_status,
            "reason_summary": reason_summary,
        }

    def _deny(
        self,
        stage: str,
        reason: str,
        decision: Decision,
        *,
        actor: str,
        input_hash: str,
        residual: float,
        proposal: ActionProposal | None = None,
        confidence_score: float | None = None,
        state: ActionState = ActionState.DENIED,
        detail: dict | None = None,
    ) -> EnforcementResult:
        card = (
            self._decision_card(proposal, decision, residual, confidence_score,
                                "not_executed", actor, f"{stage}: {reason}")
            if proposal is not None else {}
        )
        full = {"stage": stage, "reason": reason, "decision_card": card, **(detail or {})}
        event = self._ledger.append(
            event_type="tool.execution.denied",
            actor_identity=actor,
            decision=decision.value,
            input_hash=input_hash,
            policy_digest=POLICY_DIGEST,
            risk_after=residual,
            detail=full,
        )
        if card:
            card["decision_id"] = event.event_id
        return EnforcementResult(
            allowed=False, decision=decision, reason=f"{stage}: {reason}",
            residual_risk=round(residual, 4), event_id=event.event_id,
            state=state, decision_card=card)


def _hash_raw(raw: object) -> str:
    try:
        payload = json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        payload = repr(raw).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()
