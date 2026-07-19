"""Domain packs — one control plane, four reasoning patterns (blueprint §7).

The enforcement point, capabilities, memory, and HMDC gates do not change per
domain. What changes is the **pack**: the reasoning pattern, the environmental
**verifier** (the strongest correctness signal), the **autonomy envelope**, and
the **grounding discipline**. The unifying rule — *match the reasoning pattern to
the quality of your verifier*: where the verifier is deterministic and cheap
(sandboxed tests, kinematic limits) you can afford autonomy; where it is
expensive or absent (legal reasoning) you constrain it.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .verifiers import (
    CitationVerifier,
    ReconciliationVerifier,
    SafetyEnvelopeVerifier,
    TaskVerifier,
    TestSuiteVerifier,
)


@dataclass(frozen=True)
class DomainPack:
    """A domain's specialization of the shared control plane."""

    name: str
    reasoning_pattern: str      # "react" | "plan_execute" | "strict_rag" | "htn"
    verifier: TaskVerifier      # the environmental correctness signal (HMDC task_gate)
    autonomy: str               # how much unattended action the verifier justifies
    grounding: str              # the grounding discipline

    def summary(self) -> str:
        return (f"{self.name}: pattern={self.reasoning_pattern} "
                f"verifier={self.verifier.signal} autonomy={self.autonomy!r}")


def software_engineering_pack(run_tests: Callable[[str], Sequence[bool]]) -> DomainPack:
    """ReAct + sandbox execution. The verifier is the test suite, so autonomy is
    high *because* the environment gives deterministic, cheap feedback."""
    return DomainPack(
        name="software_engineering",
        reasoning_pattern="react",
        verifier=TestSuiteVerifier(run_tests),
        autonomy="high — bounded by an isolated, egress-controlled sandbox",
        grounding="tests + static analysis in a disposable sandbox",
    )


def finance_pack(*, max_amount: float | None = None) -> DomainPack:
    """Plan-and-execute + deterministic guardrails. The plan is a reviewable
    artifact; each posting must reconcile and stay within limits."""
    return DomainPack(
        name="finance",
        reasoning_pattern="plan_execute",
        verifier=ReconciliationVerifier(max_amount=max_amount),
        autonomy="bounded — reconciliation gate + four-eyes on threshold-crossing",
        grounding="double-entry reconciliation against authoritative ledgers",
    )


def healthcare_legal_pack(*, min_support: float = 0.6) -> DomainPack:
    """Strict RAG with citation-backed grounding. An uncited claim is a hard
    failure, not a stylistic note; autonomy is advisory."""
    return DomainPack(
        name="healthcare_legal",
        reasoning_pattern="strict_rag",
        verifier=CitationVerifier(min_support=min_support),
        autonomy="advisory — no unattended action; every claim source-grounded",
        grounding="citation entailment against retrieved authoritative sources",
    )


def robotics_pack(limits: dict[str, tuple[float, float]]) -> DomainPack:
    """Hierarchical Task Networks: a deliberative 'brain' proposes; a reactive
    'spinal cord' (the safety-envelope verifier) can veto without consulting it."""
    return DomainPack(
        name="robotics",
        reasoning_pattern="htn",
        verifier=SafetyEnvelopeVerifier(limits),
        autonomy="reactive-safety — spinal cord vetoes; brain never has actuator authority",
        grounding="kinematic / collision / rate limits enforced in real time",
    )


#: Reference table of the four patterns (for docs / the dashboard).
DOMAIN_PATTERNS: dict[str, str] = {
    "software_engineering": "react",
    "finance": "plan_execute",
    "healthcare_legal": "strict_rag",
    "robotics": "htn",
}
