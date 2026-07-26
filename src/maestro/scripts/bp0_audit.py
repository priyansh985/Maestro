"""BP0 Truth Audit generator: emit machine-readable ground-truth artifacts.

BP0 (see ``docs/audit/TRUTH_AUDIT.md``) demands that the starting point of any
further build be *understood* rather than *assumed*. The discipline of this
repository is that ground truth is **generated from the live code**, never
hand-transcribed — a hand-written inventory rots the moment a module moves.

This module walks the actual package and emits, into ``docs/audit/``:

  * ``module_inventory.json``     - every source module, its role, size, package
  * ``endpoint_inventory.json``   - every HTTP/WS route and whether it mutates
  * ``connector_inventory.json``  - every model/provider connector + infra
  * ``side_effect_boundaries.json`` - the curated set of real side-effect sinks
  * ``control_status.json``       - the honest control ladder (from control_status)
  * ``module_disposition.json``   - build-in-place disposition of each package

Run ``python -m maestro.scripts.bp0_audit`` (or the ``maestro-bp0-audit``
console script). Deterministic: identical output on identical source.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from maestro.security.control_status import to_report

# --------------------------------------------------------------------------- #
# Locations
# --------------------------------------------------------------------------- #
_HERE = Path(__file__).resolve()
#: repo root == .../maestro (parent of src/)
_SRC_ROOT = _HERE.parents[2]                 # src/maestro/scripts -> src
_REPO_ROOT = _SRC_ROOT.parent
_PKG_ROOT = _SRC_ROOT / "maestro"
_OUT_DIR = _REPO_ROOT / "docs" / "audit"


# --------------------------------------------------------------------------- #
# 1. Module inventory (walked, not transcribed)
# --------------------------------------------------------------------------- #
def _module_role(source: str) -> str:
    """First sentence of the module docstring, or '' if none."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    doc = ast.get_docstring(tree)
    if not doc:
        return ""
    first = doc.strip().split("\n\n", 1)[0].replace("\n", " ").strip()
    # Trim to the first sentence for a compact one-liner.
    m = re.search(r"^(.*?[.:])(\s|$)", first)
    return (m.group(1) if m else first).strip()


def module_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(_PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(_REPO_ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        dotted = path.relative_to(_SRC_ROOT).with_suffix("").as_posix().replace("/", ".")
        package = path.parent.relative_to(_PKG_ROOT).as_posix() or "."
        rows.append(
            {
                "module": dotted,
                "path": rel,
                "package": package,
                "lines": source.count("\n") + 1,
                "role": _module_role(source),
            }
        )
    return rows


# --------------------------------------------------------------------------- #
# 2. Endpoint inventory (parsed from the server package)
# --------------------------------------------------------------------------- #
_ROUTE_RE = re.compile(
    r"@(?:app|router)\.(get|post|put|delete|patch|websocket)\(\s*[\"']([^\"']+)[\"']"
)
_MUTATING = {"post", "put", "delete", "patch"}


def _auth_note(source: str, method: str, route: str) -> str:
    """The authorization posture of a route. BP3.1 closed CTRL-L4-03 for the
    control plane; BP3.2 extended the same zero-trust boundary over the
    model-testing/connectors API and added per-principal rate limiting."""
    if "control_api" in source:
        if route == "/reset":
            return "ADMIN (bearer token + RBAC + rate limit, CTRL-L4-03/07)"
        if method in _MUTATING:
            return "OPERATOR (bearer token + RBAC + rate limit, CTRL-L4-03/07)"
        return "VIEWER (bearer token + RBAC + rate limit, CTRL-L4-03/07)"
    if "connectors_api" in source:
        if method in _MUTATING:
            return "OPERATOR (bearer token + RBAC + rate limit, CTRL-L4-03/07)"
        return "VIEWER (bearer token + RBAC + rate limit, CTRL-L4-03/07)"
    return "public (health / reference / static shell / websocket)"


def endpoint_inventory() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    server = _PKG_ROOT / "server"
    for path in sorted(server.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for m in _ROUTE_RE.finditer(path.read_text(encoding="utf-8")):
            method, route = m.group(1), m.group(2)
            rows.append(
                {
                    "method": method.upper(),
                    "route": route,
                    "mutating": method in _MUTATING,
                    "source": rel,
                    "auth": _auth_note(rel, method, route),
                }
            )
    return sorted(rows, key=lambda r: (r["source"], r["route"], r["method"]))


# --------------------------------------------------------------------------- #
# 3. Connector inventory
# --------------------------------------------------------------------------- #
def connector_inventory() -> dict[str, list[dict[str, str]]]:
    conn = _PKG_ROOT / "connectors"
    providers: list[dict[str, str]] = []
    prov_dir = conn / "providers"
    if prov_dir.exists():
        for path in sorted(prov_dir.glob("*.py")):
            if path.name == "__init__.py":
                continue
            providers.append(
                {
                    "name": path.stem,
                    "path": path.relative_to(_REPO_ROOT).as_posix(),
                    "role": _module_role(path.read_text(encoding="utf-8")),
                }
            )
    infra: list[dict[str, str]] = []
    for path in sorted(conn.glob("*.py")):
        if path.name == "__init__.py":
            continue
        infra.append(
            {
                "name": path.stem,
                "path": path.relative_to(_REPO_ROOT).as_posix(),
                "role": _module_role(path.read_text(encoding="utf-8")),
            }
        )
    return {"providers": providers, "infrastructure": infra}


# --------------------------------------------------------------------------- #
# 4. Side-effect boundaries (curated analysis — the honest sink map)
# --------------------------------------------------------------------------- #
# A "side-effect boundary" is a point where execution leaves pure computation
# and changes state the system (or the world) can observe. Each is classified
# by side-effect class (see docs/audit/side_effect_classes.md) and by the
# control that gates it. This is analysis, not a regex result — it is curated
# here so there is exactly one source of truth, and reviewed on every change.
SIDE_EFFECT_BOUNDARIES: list[dict[str, object]] = [
    {
        "id": "SEB-01",
        "name": "Operational tool execution (SOC mitigations)",
        "sink": "maestro.platform.agent_platform:default_tool_adapters",
        "class": "SIMULATED_EXTERNAL",
        "reversible": "varies (rollback_telemetry is the compensating action)",
        "gated_by": "CTRL-L3-02 (PEP capability gateway), CTRL-L3-01 (allow-list), "
                    "CTRL-L6-03 (signed policy-bundle allow-list, two-person change), "
                    "CTRL-L5-08 (environmental verifier veto), CTRL-L5-06 (HMDC "
                    "gated critique), CTRL-L3-04 (executor sandbox: scope + output "
                    "confinement), CTRL-L4-05 (durable exactly-once replay)",
        "notes": "THE consequential boundary. In this offline reproduction the "
                 "adapters model the effect (throttle/thresholds/capture/alert/"
                 "rollback). The intent must be permitted by the active signed "
                 "policy bundle (CTRL-L6-03) — a versioned, two-person-approved "
                 "allow-list whose integrity is re-verified here. Before the side "
                 "effect a pre-execution critique gate (BP7) runs the HMDC engine "
                 "+ the deterministic environmental verifier, vetoing a mitigation "
                 "inappropriate/unsafe for the observed alert; the adapter then "
                 "runs inside an in-process ExecutionSandbox that confines the "
                 "result to the authorized scope and replays it exactly-once "
                 "across a crash. In production the adapters would call a firewall/"
                 "SOAR/capture control through an OS-level sandbox (gVisor/"
                 "Firecracker) backed by Temporal.io. No model output reaches here "
                 "except through a typed, authorized, allow-listed, "
                 "environmentally-verified proposal.",
    },
    {
        "id": "SEB-02",
        "name": "Tamper-evident audit ledger append",
        "sink": "maestro.security.ledger:Ledger.append",
        "class": "INTERNAL_STATE",
        "reversible": "no (append-only, hash-chained by design)",
        "gated_by": "CTRL-L5-02 (ledger is the record, not a gated action)",
        "notes": "Append-only, HMAC-signed, hash-chained; optionally persisted to "
                 "disk. Deletion/modification is detectable via verify_chain().",
    },
    {
        "id": "SEB-03",
        "name": "Persistent memory write / promotion",
        "sink": "maestro.memory.store:MemoryStore.promote / .recall_cross_scope",
        "class": "INTERNAL_STATE",
        "reversible": "yes (records are versioned; promotion is audited)",
        "gated_by": "CTRL-L2-03 (independent cap:memory:promote), CTRL-L2-05 "
                    "(cap:memory:cross-tenant-read), CTRL-L2-04 (scope isolation)",
        "notes": "External content lands UNTRUSTED (quarantine-on-ingest). "
                 "Promotion to TRUSTED and cross-tenant reads have no autonomous "
                 "path — each needs an independent scoped capability and is "
                 "recorded in the ledger.",
    },
    {
        "id": "SEB-04",
        "name": "Capability token issuance / delegation",
        "sink": "maestro.security.identity:CapabilityIssuer.issue / .delegate",
        "class": "INTERNAL_STATE",
        "reversible": "n/a (tokens are short-lived; scope only narrows)",
        "gated_by": "CTRL-L7-02 (delegation strictly narrows, depth-capped)",
        "notes": "HMAC-signed, scoped, TTL-bounded authority. Delegation cannot "
                 "widen scope or outlive its parent (MAX_DELEGATION_DEPTH).",
    },
    {
        "id": "SEB-05",
        "name": "Outbound model/provider HTTP call",
        "sink": "maestro.connectors.providers.http_base:HttpConnector",
        "class": "EXTERNAL_NETWORK",
        "reversible": "n/a (read of external model)",
        "gated_by": "CTRL-L4-02 (provider auth), CTRL-L4-06 (policy-aware, "
                    "fail-closed fallback)",
        "notes": "The ONLY egress off the box. OFF the default offline loop, which "
                 "uses the deterministic stub reasoner. Keys from env, never "
                 "persisted; fallback fails closed rather than downgrading tier.",
    },
    {
        "id": "SEB-06",
        "name": "Host packet replay (experiment TC1)",
        "sink": "maestro.experiments.tc1_dos:tcpreplay_pcap / scapy sendp",
        "class": "HOST_ENVIRONMENT",
        "reversible": "no (emits real packets on an interface)",
        "gated_by": "experiment-only; NOT on the agent control plane",
        "notes": "Best-effort side effect of the DoS reproduction; the reported "
                 "metric is the MODELED saturation curve (A13), not this send. "
                 "Never reachable from an agent action.",
    },
    {
        "id": "SEB-07",
        "name": "Filesystem result/log writes",
        "sink": "maestro.experiments.runner / summary, ledger persistence, "
                "control_status.write_report",
        "class": "HOST_ENVIRONMENT",
        "reversible": "yes (results/ artifacts, overwritable)",
        "gated_by": "n/a (developer tooling, not an agent capability)",
        "notes": "Writes to results/ and docs/audit/. Not reachable from a model "
                 "proposal; produced by explicit developer/CI invocation.",
    },
    {
        "id": "SEB-08",
        "name": "Legacy memory file write (pre-enforcement path)",
        "sink": "maestro.agent.memory:AgentMemory (history.json)",
        "class": "INTERNAL_STATE",
        "reversible": "yes",
        "gated_by": "SUPERSEDED — not tamper-evident (CTRL-L2-01 default-off)",
        "notes": "The paper's poisonable history.json. Retained for the TC2 "
                 "reproduction; the enforced path is memory/store.py (SEB-03).",
    },
]


# --------------------------------------------------------------------------- #
# 5. Module disposition (build-in-place mapping to the BP0-BP13 framework)
# --------------------------------------------------------------------------- #
# Decision (this session): adopt the BP framework as a GAP MAP and build in
# place — do NOT demote the working, tested core to legacy/. Each package is
# mapped to the BP part it realizes and given a disposition:
#   KEEP   - realized and tested; no structural change needed.
#   HARDEN - present but a real production gap remains (named).
#   GAP    - not built here yet; net-new work.
MODULE_DISPOSITION: dict[str, dict[str, str]] = {
    "security": {
        "bp": "BP2/BP4 (enforcement plane + runtime kernel)",
        "disposition": "KEEP",
        "note": "PEP, capability tokens, ledger, budget, breaker, confidence, "
                "perimeter, signed policy bundles (CTRL-L6-03: two-person change, "
                "verified at the boundary), control_status. The keystone; "
                "verified/tested.",
    },
    "platform": {
        "bp": "BP2 (walking skeleton, past-skeleton) + BP4",
        "disposition": "KEEP",
        "note": "AgentPlatform live loop is the single side-effect path; "
                "blast_radius + secure-by-inheritance provisioning.",
    },
    "memory": {
        "bp": "BP5 (memory/evidence)",
        "disposition": "HARDEN",
        "note": "Four-tier store + quarantine + scope isolation tested in-process; "
                "gap = Postgres row-level security to move isolation below the app.",
    },
    "orchestration": {
        "bp": "BP4 (durable execution)",
        "disposition": "HARDEN",
        "note": "Offline event-sourced exactly-once engine; BP4 wired its journal "
                "into the executor sandbox so exactly-once replay is now on the "
                "live loop by default (CTRL-L4-05). Remaining gap = prod would back "
                "the journal with Temporal.io rather than the in-repo engine.",
    },
    "connectors": {
        "bp": "BP6 (provider abstraction / model governance)",
        "disposition": "KEEP",
        "note": "Multi-model routing, policy-aware fail-closed fallback, MoA.",
    },
    "critique": {
        "bp": "BP7 (evaluation / adversarial)",
        "disposition": "KEEP",
        "note": "HMDC gated critique wired onto the live boundary (BP7) via "
                "security/critique_gate.py:HMDCGate as a pre-execution gate "
                "(CTRL-L5-06); deterministic guardrails + environmental verifier "
                "hard-gate, judge uncertainty routes to a human. Remaining gap = "
                "no formal release-gate registry and the judges are offline "
                "lexical stand-ins (connector-backed judge = seam).",
    },
    "domains": {
        "bp": "BP7/BP12 (environmental verifiers, SOC + verticals)",
        "disposition": "KEEP",
        "note": "Domain verifier packs feeding the HMDC task_gate; the "
                "NetworkMitigationVerifier now gates the live loop before every "
                "side effect (BP7, CTRL-L5-08).",
    },
    "server": {
        "bp": "BP3 (control plane) + BP11 (console surface)",
        "disposition": "HARDEN",
        "note": "Control API drives the real PEP; BP3.1-3.3 closed the front door "
                "(CTRL-L4-03 verified: auth+RBAC over the whole /api surface, "
                "CTRL-L4-07 rate limiting, CTRL-L4-08 structural multi-tenant "
                "isolation). Remaining seams: OIDC/SSO, external RBAC store, "
                "Postgres RLS, SDK/CLI.",
    },
    "agent": {
        "bp": "BP1 partial / paper reproduction",
        "disposition": "HARDEN",
        "note": "reasoning/planner/memory/parameter_tuning. Legacy planner toggle "
                "and history.json superseded by the enforced path; kept for TC1/TC2.",
    },
    "maestro": {
        "bp": "BP0/BP1 (taxonomy, threat model, risk)",
        "disposition": "KEEP",
        "note": "7-layer taxonomy, Table-4 threats (Eq.1 consistency), risk_score, "
                "mitigation catalogue, mapping/layers.",
    },
    "telemetry": {
        "bp": "BP12 (SOC telemetry integrity)",
        "disposition": "HARDEN",
        "note": "PerformanceMonitor saturation model (drives TC1); gap = signed/"
                "rate-limited telemetry + collector isolation for the SOC ref.",
    },
    "experiments": {
        "bp": "BP7 (adversarial corpus, TC1/TC2)",
        "disposition": "KEEP",
        "note": "TC1 DoS (modeled, A13) + TC2 memory poisoning reproductions.",
    },
    "scripts": {
        "bp": "BP0 (tooling)",
        "disposition": "KEEP",
        "note": "validate_threats + this bp0_audit generator.",
    },
    "config.py": {
        "bp": "cross-cutting",
        "disposition": "KEEP",
        "note": "Typed config + mitigation toggles.",
    },
    "cli.py": {
        "bp": "BP11 (developer surface)",
        "disposition": "HARDEN",
        "note": "maestro-validate entry; gap = full lifecycle CLI/SDK.",
    },
    "logging_setup.py": {
        "bp": "cross-cutting",
        "disposition": "KEEP",
        "note": "Structured logging setup.",
    },
}


# --------------------------------------------------------------------------- #
# Emit
# --------------------------------------------------------------------------- #
def _write(name: str, payload: object) -> Path:
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = _OUT_DIR / name
    # ensure_ascii=True keeps the artifacts portable on Windows cp1252 consoles
    # (module docstrings contain em-dashes/arrows); \uXXXX escapes are universal.
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return path


def generate() -> list[Path]:
    modules = module_inventory()
    endpoints = endpoint_inventory()
    written = [
        _write(
            "module_inventory.json",
            {
                "schema_version": "1.0",
                "package_root": _PKG_ROOT.relative_to(_REPO_ROOT).as_posix(),
                "module_count": len(modules),
                "total_lines": sum(int(m["lines"]) for m in modules),
                "modules": modules,
            },
        ),
        _write(
            "endpoint_inventory.json",
            {
                "schema_version": "1.0",
                "endpoint_count": len(endpoints),
                "mutating_count": sum(1 for e in endpoints if e["mutating"]),
                "endpoints": endpoints,
            },
        ),
        _write(
            "connector_inventory.json",
            {"schema_version": "1.0", **connector_inventory()},
        ),
        _write(
            "side_effect_boundaries.json",
            {
                "schema_version": "1.0",
                "boundary_count": len(SIDE_EFFECT_BOUNDARIES),
                "boundaries": SIDE_EFFECT_BOUNDARIES,
            },
        ),
        _write("control_status.json", to_report()),
        _write(
            "module_disposition.json",
            {
                "schema_version": "1.0",
                "strategy": "build-in-place (BP framework as gap map; no legacy/ "
                            "restructure)",
                "packages": MODULE_DISPOSITION,
            },
        ),
    ]
    return written


def main() -> int:
    paths = generate()
    for p in paths:
        print(f"wrote {p.relative_to(_REPO_ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
