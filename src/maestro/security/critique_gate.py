"""Pre-execution critique gate — HMDC/verifiers on the live boundary (L5 / BP7).

The HMDC engine (blueprint §5) and its environmental verifiers (§5.3) previously
existed only as an *offline evaluation harness* — built and tested, but not
gating any real action (Gap B in the control report). BP7 moves them onto the
enforcement boundary: this module is the adapter that lets the
:class:`~maestro.security.enforcement.PolicyEnforcementPoint` run a candidate
mitigation through the corrected HMDC pipeline as the **last check before the
side effect**, and maps the layered verdict to a fail-closed enforcement
outcome.

The mapping is deliberate — it preserves the blueprint's rule that *a
deterministic gate is a fact and a probabilistic judge is only evidence*:

* ``REJECT`` — a deterministic guardrail hard-failed (a secret/PII leak in the
  justification, empty output). A fact → **deny autonomously**.
* ``REVISE`` **with a failed environmental verifier** (``task_verified is
  False``) — the proposed mitigation is inappropriate/unsafe for the observed
  condition. A fact → **deny autonomously**.
* ``REVISE`` **otherwise** (semantic drift below the floor, or a low judge
  ensemble) — a *soft*, probabilistic signal → **route to a human** (escalate),
  never a silent autonomous deny on a stand-in score.
* ``ROUTE_TO_HUMAN`` — judge disagreement or no independent judge. Uncertainty,
  not a fact → **route to a human** (escalate).
* ``PASS`` — cleared every stage → **execute**.

**Honest scope.** The offline judge/embedder behind the engine are deterministic
lexical stand-ins (see :mod:`maestro.critique.judge`), so the *operative* hard
gate on the live loop is the pair that is genuinely deterministic — the
dispositive **guardrails** and the **environmental verifier**. The judge
ensemble runs, is recorded, and its genuine disagreement routes to a human; the
engine's *contract* (guardrail-dispositive, cross-family, variance-aware,
route-uncertainty-to-human) is what is enforced here, exactly as it would be
with a real connector-backed cross-family judge plugged in behind it.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..critique import Candidate, CritiqueSpec, HMDCEngine, Verdict
from .action import ActionProposal


@dataclass(frozen=True)
class GateOutcome:
    """A critique gate's fail-closed verdict for the enforcement point.

    ``allow`` — proceed to execute. ``escalate`` — do not execute autonomously;
    require human approval (uncertainty routed to a human). When both are False
    the action is denied outright (a deterministic correctness/safety failure).
    """

    allow: bool
    escalate: bool
    verdict: str
    reason: str
    detail: dict = field(default_factory=dict)


#: A pre-execution gate: given the authorized proposal and a verification
#: context (the environment facts — e.g. the observed alert class + grounding),
#: return a fail-closed :class:`GateOutcome`. Domain-agnostic from the PEP's
#: point of view; the concrete gate (below) is domain-aware.
PreExecutionGate = Callable[[ActionProposal, dict], GateOutcome]


class HMDCGate:
    """Runs a proposal through the HMDC engine and maps the verdict fail-closed.

    ``family`` is the generating-agent family stamped on the candidate so the
    engine can enforce cross-family judging (a judge from this family is
    excluded). The default thresholds keep the *probabilistic* stages permissive
    under the offline lexical stand-in — the deterministic guardrails and the
    engine's ``task_gate`` (environmental verifier) are the operative hard gate;
    a strict spec (higher floors) is what a real connector-backed judge would
    run, and is exercised in the tests.
    """

    def __init__(
        self,
        engine: HMDCEngine,
        *,
        family: str = "network-monitor",
        min_semantic_alignment: float = 0.0,
        min_ensemble_score: float = 0.0,
        route_variance_threshold: float = 1.0,
        forbidden_patterns: tuple[str, ...] = (),
    ) -> None:
        self._engine = engine
        self._family = family
        self._min_align = min_semantic_alignment
        self._min_ensemble = min_ensemble_score
        self._route_var = route_variance_threshold
        self._forbidden = forbidden_patterns

    def __call__(self, proposal: ActionProposal, context: dict) -> GateOutcome:
        grounding = tuple(str(g) for g in context.get("grounding", ()))
        spec = CritiqueSpec(
            intent=str(context.get("intent_description")
                       or f"appropriate, safe mitigation for the observed condition "
                          f"({proposal.intent})"),
            grounding=grounding or (proposal.reason,),
            forbidden_patterns=self._forbidden,
            min_semantic_alignment=self._min_align,
            min_ensemble_score=self._min_ensemble,
            route_variance_threshold=self._route_var,
        )
        candidate = Candidate(
            text=proposal.reason,
            family=self._family,
            metadata={"intent": proposal.intent, "target": proposal.target},
        )
        # The engine's task_gate reads the environment facts (alert_class, …)
        # from the context; pass the proposed intent through too for verifiers
        # that prefer it in the context rather than the candidate metadata.
        result = self._engine.critique(
            candidate, spec, context={**context, "intent": proposal.intent})
        detail = result.as_dict()

        if result.verdict is Verdict.PASS:
            return GateOutcome(True, False, "pass", "cleared HMDC critique", detail)
        if result.verdict is Verdict.REJECT:
            return GateOutcome(False, False, "reject", result.reason, detail)
        if result.verdict is Verdict.ROUTE_TO_HUMAN:
            return GateOutcome(False, True, "route_to_human", result.reason, detail)
        # REVISE: a failed *environmental verifier* is a deterministic fact (deny);
        # semantic drift / low ensemble is a soft signal (route to a human).
        if result.task_verified is False:
            return GateOutcome(False, False, "revise", result.reason, detail)
        return GateOutcome(False, True, "revise", result.reason, detail)


__all__ = ["GateOutcome", "HMDCGate", "PreExecutionGate"]
