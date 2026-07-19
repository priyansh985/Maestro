"""Cross-domain architectural patterns (blueprint §7).

One control plane; four domain packs. Each pack pairs a reasoning pattern with
its **environmental verifier** — the deterministic correctness signal that is
stronger than any judge — and an autonomy envelope sized to that verifier:

* **software_engineering** — ReAct + sandbox; verifier = the test suite;
* **finance** — plan-and-execute; verifier = double-entry reconciliation;
* **healthcare_legal** — strict RAG; verifier = citation grounding;
* **robotics** — HTN brain/spinal-cord; verifier = the safety envelope.

Each verifier is directly usable as an :class:`~maestro.critique.HMDCEngine`
``task_gate``, which is how §7 closes the §5 gap: the "strongest correctness
signal" now runs, per domain, before the probabilistic judges.
"""
from __future__ import annotations

from .packs import (
    DOMAIN_PATTERNS,
    DomainPack,
    finance_pack,
    healthcare_legal_pack,
    robotics_pack,
    software_engineering_pack,
)
from .verifiers import (
    CitationVerifier,
    ReconciliationVerifier,
    SafetyEnvelopeVerifier,
    TaskVerifier,
    TestSuiteVerifier,
)

__all__ = [
    "DOMAIN_PATTERNS",
    "DomainPack",
    "TaskVerifier",
    "TestSuiteVerifier",
    "ReconciliationVerifier",
    "CitationVerifier",
    "SafetyEnvelopeVerifier",
    "software_engineering_pack",
    "finance_pack",
    "healthcare_legal_pack",
    "robotics_pack",
]
