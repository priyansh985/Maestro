"""Cross-domain environmental verifiers (blueprint §5.3 + §7).

The framework is one control plane; what changes per domain is the **verifier** —
the deterministic, environmental correctness signal that is stronger than any
judge model because it is a *fact*, not an opinion:

* **Software engineering** — the tests pass (in a sandbox).
* **Finance / enterprise** — the postings reconcile and stay within limits.
* **Healthcare / legal** — every claim is supported by a cited source.
* **Embodied AI / robotics** — the motion is within the kinematic/safety envelope
  (the "spinal cord" that can veto the "brain").

Each verifier returns a :class:`~maestro.critique.VerifierResult` and is directly
usable as an :class:`~maestro.critique.HMDCEngine` ``task_gate`` (it is callable
as ``verifier(candidate, context)``), so environmental verification runs *before*
the probabilistic judges — matching the corrected HMDC pipeline.
"""
from __future__ import annotations

import abc
import re
from collections.abc import Callable, Sequence

from ..critique import Candidate, VerifierResult

_STOP = frozenset(
    "a an the of to and or is are be for on in it this that with as at by from "
    "we you they i he she them our your its into over under then than".split())


def _content_tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP}


class TaskVerifier(abc.ABC):
    """A deterministic, domain-specific correctness gate."""

    domain: str = "generic"
    signal: str = "task"

    @abc.abstractmethod
    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        ...

    def __call__(
        self, candidate: Candidate, context: dict[str, object] | None = None
    ) -> VerifierResult:
        return self.verify(candidate, context)


class TestSuiteVerifier(TaskVerifier):
    """Software engineering (ReAct + sandbox): the tests are the verifier.

    ``run_tests`` is the sandboxed test runner — it takes the candidate code and
    returns one pass/fail per test. Verification succeeds only if at least one
    test ran and none failed.
    """

    domain = "software_engineering"
    signal = "test-suite"
    __test__ = False  # not a pytest test class despite the "Test" prefix

    def __init__(self, run_tests: Callable[[str], Sequence[bool]]) -> None:
        self._run = run_tests

    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        results = list(self._run(candidate.text))
        if not results:
            return VerifierResult(False, self.signal, "no tests executed")
        failed = sum(1 for r in results if not r)
        if failed:
            return VerifierResult(False, self.signal, f"{failed}/{len(results)} test(s) failed")
        return VerifierResult(True, self.signal, f"all {len(results)} test(s) passed")


class ReconciliationVerifier(TaskVerifier):
    """Finance / enterprise (plan-and-execute): double-entry postings must balance.

    ``context['postings']`` is a list of ``{"debit": x}`` / ``{"credit": y}``.
    Verification fails if debits != credits (within tolerance) or any single
    amount exceeds ``max_amount``.
    """

    domain = "finance"
    signal = "reconciliation"

    def __init__(self, *, max_amount: float | None = None, tolerance: float = 0.005) -> None:
        self._max = max_amount
        self._tol = tolerance

    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        postings = (context or {}).get("postings")
        if not isinstance(postings, list) or not postings:
            return VerifierResult(False, self.signal, "no postings to reconcile")
        debits = sum(float(p.get("debit", 0.0)) for p in postings)
        credits = sum(float(p.get("credit", 0.0)) for p in postings)
        if abs(debits - credits) > self._tol:
            return VerifierResult(
                False, self.signal, f"unbalanced: debits {debits:.2f} != credits {credits:.2f}")
        if self._max is not None:
            biggest = max(max(float(p.get("debit", 0.0)), float(p.get("credit", 0.0)))
                          for p in postings)
            if biggest > self._max:
                return VerifierResult(
                    False, self.signal, f"amount {biggest:.2f} exceeds limit {self._max:.2f}")
        return VerifierResult(True, self.signal, f"balanced at {debits:.2f}")


class CitationVerifier(TaskVerifier):
    """Healthcare / legal (strict RAG): every claim must be source-supported.

    ``context['sources']`` is the list of retrieved passages the answer may rely
    on. Verification requires an explicit citation marker *and* that the answer's
    content is grounded in the sources above ``min_support`` — an uncited or
    unsupported (hallucinated) claim fails.
    """

    domain = "healthcare_legal"
    signal = "citation-grounding"

    def __init__(self, *, min_support: float = 0.6) -> None:
        self._min = min_support

    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        sources = (context or {}).get("sources")
        if not isinstance(sources, list) or not sources:
            return VerifierResult(False, self.signal, "no sources; answer cannot be grounded")
        if not re.search(r"\[[^\]]+\]", candidate.text):
            return VerifierResult(False, self.signal, "no citation marker in the answer")
        answer_tokens = _content_tokens(re.sub(r"\[[^\]]+\]", " ", candidate.text))
        if not answer_tokens:
            return VerifierResult(False, self.signal, "empty answer")
        source_vocab: set[str] = set()
        for src in sources:
            source_vocab |= _content_tokens(str(src))
        support = sum(1 for t in answer_tokens if t in source_vocab) / len(answer_tokens)
        if support < self._min:
            return VerifierResult(
                False, self.signal,
                f"grounding {support:.2f} below {self._min:.2f} (unsupported claim)")
        return VerifierResult(True, self.signal, f"grounded ({support:.2f}) with citations")


class NetworkMitigationVerifier(TaskVerifier):
    """Network monitoring (the reproduction's core domain): the mitigation veto.

    The reproduction's own §5.3 "spinal cord": the LLM reasoner (the "brain")
    *proposes* a mitigation intent for an observed alert; this deterministic gate
    checks that intent against a fixed policy matrix keyed by the alert class —
    **without consulting the model**. A mitigation that is inappropriate or
    unsafe for the observed condition is vetoed *before* it can execute — most
    importantly one that would *degrade detection during an attack* (e.g. raising
    anomaly thresholds while a DoS is in progress, which blinds the detector) or
    that would *act on a benign baseline*. This is a fact about the environment,
    not an opinion, so it short-circuits the probabilistic judges.

    ``context['alert_class']`` is the observed class; the proposed intent is read
    from ``candidate.metadata['intent']`` (the model's claim), so the veto
    compares the model's proposal against the ground-truth condition.
    """

    domain = "network_monitoring"
    signal = "mitigation-policy"

    #: The mitigations that are appropriate *and* safe for each observed alert
    #: class. Anything outside the set for the observed class is vetoed. Notably
    #: ``raise_thresholds`` is absent from ``dos`` (it would blind the detector
    #: mid-attack) and every active mitigation is absent from ``normal`` (acting
    #: on a baseline is itself a self-inflicted disruption).
    _APPROPRIATE: dict[str, frozenset[str]] = {
        "dos": frozenset({
            "throttle_telemetry", "rollback_telemetry",
            "raise_capture_duration", "alert_operator"}),
        "anomaly": frozenset({
            "raise_thresholds", "raise_capture_duration", "alert_operator", "noop"}),
        "port_scan": frozenset({"raise_capture_duration", "alert_operator", "noop"}),
        "bruteforce": frozenset({"alert_operator", "raise_capture_duration", "noop"}),
        "normal": frozenset({"noop", "alert_operator"}),
    }

    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        ctx = context or {}
        alert_class = str(ctx.get("alert_class", "")).strip().lower()
        intent = str((candidate.metadata or {}).get("intent", "")).strip()
        if not alert_class:
            return VerifierResult(False, self.signal, "no alert class to verify the mitigation against")
        if not intent:
            return VerifierResult(False, self.signal, "no proposed mitigation intent to check")
        allowed = self._APPROPRIATE.get(alert_class)
        if allowed is None:
            return VerifierResult(False, self.signal, f"unknown alert class {alert_class!r}")
        if intent not in allowed:
            return VerifierResult(
                False, self.signal,
                f"mitigation {intent!r} is not an appropriate/safe response to a "
                f"{alert_class!r} alert")
        return VerifierResult(
            True, self.signal, f"{intent!r} is an appropriate response to {alert_class!r}")


class SafetyEnvelopeVerifier(TaskVerifier):
    """Embodied AI / robotics (HTN brain/spinal-cord): the deterministic veto.

    The "brain" proposes a motion command; this "spinal cord" checks every
    parameter against its ``limits`` (``{param: (lo, hi)}``) and vetoes anything
    outside the envelope — without consulting the brain. ``context['command']``
    is the proposed ``{param: value}``.
    """

    domain = "robotics"
    signal = "safety-envelope"

    def __init__(self, limits: dict[str, tuple[float, float]]) -> None:
        self._limits = dict(limits)

    def verify(self, candidate: Candidate, context: dict[str, object] | None = None) -> VerifierResult:
        command = (context or {}).get("command")
        if not isinstance(command, dict) or not command:
            return VerifierResult(False, self.signal, "no command to check")
        violations: list[str] = []
        for param, (lo, hi) in self._limits.items():
            if param in command:
                value = float(command[param])
                if value < lo or value > hi:
                    violations.append(f"{param}={value} outside [{lo}, {hi}]")
        if violations:
            return VerifierResult(False, self.signal, "; ".join(violations))
        return VerifierResult(True, self.signal, "within the kinematic/safety envelope")
