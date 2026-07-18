"""Phase-0 "Truth Audit": honest control-status inventory.

The central thesis of MAESTRO-SecOps is the *declaration-enforcement gap*: a
mitigation named in a catalogue is not the same as a control enforced at a
side-effect boundary and proven by a test. This module classifies every control
this repository actually has today into one of five honest states, so the gap
is measurable rather than implied.

Status ladder (each rung requires the ones below it):
  declared    - named in a catalogue / doc only; no code path.
  implemented - code exists that performs the control.
  enforced    - invoked at a real boundary and non-optional (not default-off).
  tested      - covered by an automated test.
  verified    - covered by an adversarial / bypass test.

The inventory is deliberately conservative: when in doubt, a control is rated
*down*. The invariant in :func:`audit_invariants` fails the build if a control
claims more than its evidence supports.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Status(str, Enum):
    DECLARED = "declared"
    IMPLEMENTED = "implemented"
    ENFORCED = "enforced"
    TESTED = "tested"
    VERIFIED = "verified"


#: Ordering used to compare "how far up the ladder" a status is.
_RANK: dict[Status, int] = {s: i for i, s in enumerate(Status)}


@dataclass(frozen=True)
class Control:
    control_id: str
    name: str
    maestro_layer: str          # L1..L7
    status: Status
    default_state: str          # "enabled" | "disabled" | "n/a"
    enforcement_point: str | None  # where it runs, or None if not wired
    implementation: str | None     # file:symbol, or None if declared-only
    test_id: str | None            # test module/name, or None
    notes: str = ""

    def as_dict(self) -> dict[str, str | None]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "maestro_layer": self.maestro_layer,
            "status": self.status.value,
            "default_state": self.default_state,
            "enforcement_point": self.enforcement_point,
            "implementation": self.implementation,
            "test_id": self.test_id,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# The honest inventory of what this repo actually has today.
# --------------------------------------------------------------------------- #
CONTROLS: list[Control] = [
    # L1 — Foundation models / reasoning
    Control(
        "CTRL-L1-01", "LLM guardrails + output validators", "L1",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Catalogue entry in maestro/mitigation.py; no runtime output "
              "policy validator implemented yet (Phase 2).",
    ),
    Control(
        "CTRL-L1-02", "Deterministic reasoner (offline default)", "L1",
        Status.IMPLEMENTED, "enabled", None,
        "agent/reasoning.py:StubReasoner", "tests/test_reasoning.py",
        notes="Safe default (offline/deterministic) that bounds L1 exposure; a "
              "configuration default, not an enforcement point — hence "
              "implemented, not enforced.",
    ),
    # L2 — Data / memory
    Control(
        "CTRL-L2-01", "Memory isolation (read-only freeze)", "L2",
        Status.IMPLEMENTED, "disabled", "agent/memory.py:AgentMemory.freeze",
        "agent/memory.py:AgentMemory.freeze", "tests/test_memory.py",
        notes="Best-effort POSIX chmod, default-off (config mitigation."
              "memory_isolation=false). Not tamper-evident; superseded by the "
              "signed-promotion + hash-chain design in Phase 3.",
    ),
    Control(
        "CTRL-L2-02", "Memory-poisoning detection (high-severity count)", "L2",
        Status.TESTED, "enabled", "agent/parameter_tuning.py:poisoned_count",
        "agent/memory.py:AgentMemory.poisoned_count", "tests/test_parameter_tuning.py",
        notes="Detection/observability only (drives capture-duration); does "
              "not prevent poisoned writes.",
    ),
    Control(
        "CTRL-L2-03", "Signed/quarantined memory promotion", "L2",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Target control (Phase 3): quarantine namespace, provenance, "
              "independent write authorization, HMAC hash-chain.",
    ),
    # L3 — Agent / tool framework
    Control(
        "CTRL-L3-01", "Planner action allow-list validation", "L3",
        Status.IMPLEMENTED, "disabled", None,
        "agent/planner.py:Planner (validate_plans)", "tests/test_planner.py",
        notes="Implemented + unit-tested but NOT enforced: default-off (config "
              "mitigation.planner_validation=false) and planner-side only, so a "
              "direct executor/tool call bypasses it. Becomes enforced at the "
              "executor gateway in Phase 2.",
    ),
    Control(
        "CTRL-L3-02", "Capability tokens / typed action schema", "L3",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Target control (Phase 2): typed action proposals authorized by "
              "scoped, short-lived capabilities at an executor gateway.",
    ),
    # L4 — Infrastructure
    Control(
        "CTRL-L4-01", "Connector fallback / graceful degradation", "L4",
        Status.TESTED, "enabled", "connectors/fallback.py:FallbackConnector",
        "connectors/fallback.py:FallbackConnector", "tests/test_connectors_fallback.py",
        notes="Availability control for the LLM backend path.",
    ),
    Control(
        "CTRL-L4-02", "Connector provider authentication", "L4",
        Status.TESTED, "enabled", "connectors/providers/http_base.py:HttpConnector",
        "connectors/providers/http_base.py:_headers", "tests/test_connectors_providers.py",
        notes="Per-provider API-key/header auth; keys from env, never persisted.",
    ),
    Control(
        "CTRL-L4-03", "Server auth / rate limiting / zero-trust API", "L4",
        Status.DECLARED, "disabled", None,
        None, None,
        notes="Target control (Phase 1): FastAPI is currently unauthenticated; "
              "config mitigation.zero_trust_api=false.",
    ),
    # L5 — Observability / evaluation
    Control(
        "CTRL-L5-01", "Structured request/response logging", "L5",
        Status.TESTED, "enabled", "server/connectors_api.py:LogStore",
        "server/connectors_api.py:LogStore", "tests/test_connectors_api.py",
        notes="In-memory, bounded; NOT tamper-evident (no hash-chain/anchor). "
              "Superseded by the audit ledger in Phase 3.",
    ),
    Control(
        "CTRL-L5-02", "Tamper-evident audit ledger + evidence graph", "L5",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Target control (Phase 3): append-only, hash-chained, HMAC, "
              "externally anchored; evidence graph for provenance.",
    ),
    Control(
        "CTRL-L5-03", "Operational residual-risk scoring", "L5",
        Status.IMPLEMENTED, "enabled", None,
        "security/risk_engine.py", "tests/test_risk_engine.py",
        notes="Implemented + unit-tested but NOT enforced: the risk->decision "
              "mapping exists as a library and is not yet wired to gate any "
              "action at a side-effect boundary (Phase 2).",
    ),
    # L6 — Governance / compliance
    Control(
        "CTRL-L6-01", "Threat catalogue == Eq.(1) consistency check", "L6",
        Status.TESTED, "enabled", "maestro/threats.py:load_threats",
        "maestro/threats.py:load_threats", "tests/test_threats.py",
        notes="Refuses to load if any risk_score != P*I*E; policy-as-code seed.",
    ),
    Control(
        "CTRL-L6-02", "Control-status truth audit (this module)", "L6",
        Status.TESTED, "enabled", "security/control_status.py:audit_invariants",
        "security/control_status.py", "tests/test_control_status.py",
        notes="Phase-0 deliverable: classifies controls and fails the build if "
              "a control claims more than its evidence supports.",
    ),
    Control(
        "CTRL-L6-03", "Signed policy bundles / two-person change", "L6",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Target control (Phase 1/6): policy-as-code with signatures and "
              "approval friction.",
    ),
    # L7 — Ecosystem / humans
    Control(
        "CTRL-L7-01", "Operator dashboards + manual verification", "L7",
        Status.TESTED, "enabled", "server/playground.py + /api/logs/*/verify",
        "server/connectors_api.py:verify_log", "tests/test_connectors_api.py",
        notes="Human-in-the-loop verify checkmarks; does not yet show blast "
              "radius / contradictory evidence (Phase 3 approval UX).",
    ),
    Control(
        "CTRL-L7-02", "Delegation limits / kill switch / SBOM+AI-BOM", "L7",
        Status.DECLARED, "n/a", None,
        None, None,
        notes="Target control (Phase 2/5): delegation-depth caps, capability "
              "revocation, supply-chain attestation.",
    ),
]


def audit_invariants(controls: list[Control] | None = None) -> list[str]:
    """Return a list of consistency violations (empty == audit passes).

    Enforces that a control cannot claim more than its evidence supports:
      * ``tested`` / ``verified`` require a ``test_id``.
      * ``enforced`` (and above) require an ``enforcement_point``.
      * a control cannot be ``enforced`` while ``default_state == "disabled"``
        (default-off is not enforcement).
      * ``implemented`` and above require an ``implementation`` reference.
    """
    controls = controls if controls is not None else CONTROLS
    violations: list[str] = []
    seen: set[str] = set()
    for c in controls:
        if c.control_id in seen:
            violations.append(f"{c.control_id}: duplicate control_id")
        seen.add(c.control_id)
        rank = _RANK[c.status]
        if rank >= _RANK[Status.IMPLEMENTED] and not c.implementation:
            violations.append(f"{c.control_id}: status '{c.status.value}' but no implementation")
        if rank >= _RANK[Status.TESTED] and not c.test_id:
            violations.append(f"{c.control_id}: status '{c.status.value}' but no test_id")
        if rank >= _RANK[Status.ENFORCED] and not c.enforcement_point:
            violations.append(f"{c.control_id}: status '{c.status.value}' but no enforcement_point")
        # 'enforced' (and, by the ladder, 'tested'/'verified') means the control
        # actually runs and is non-optional — a default-off control cannot claim
        # any of those rungs. This is the guard that stops the audit from
        # overstating enforcement.
        if rank >= _RANK[Status.ENFORCED] and c.default_state == "disabled":
            violations.append(
                f"{c.control_id}: status '{c.status.value}' but default_state is disabled")
    return violations


def coverage_summary(controls: list[Control] | None = None) -> dict[str, object]:
    """Counts by status + layer and the enforcement gap."""
    controls = controls if controls is not None else CONTROLS
    by_status: dict[str, int] = {s.value: 0 for s in Status}
    by_layer: dict[str, int] = {}
    for c in controls:
        by_status[c.status.value] += 1
        by_layer[c.maestro_layer] = by_layer.get(c.maestro_layer, 0) + 1
    total = len(controls)
    enforced = sum(1 for c in controls if _RANK[c.status] >= _RANK[Status.ENFORCED])
    return {
        "total": total,
        "by_status": by_status,
        "by_layer": by_layer,
        "enforced_or_above": enforced,
        "enforcement_ratio": round(enforced / total, 3) if total else 0.0,
    }


def to_report(controls: list[Control] | None = None) -> dict[str, object]:
    controls = controls if controls is not None else CONTROLS
    return {
        "schema_version": "1.0",
        "controls": [c.as_dict() for c in controls],
        "coverage": coverage_summary(controls),
        "violations": audit_invariants(controls),
    }


def write_report(out_dir: str | Path = "results") -> Path:
    """Write ``control_status.json`` and return its path."""
    import json

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "control_status.json"
    path.write_text(json.dumps(to_report(), indent=2), encoding="utf-8")
    return path
