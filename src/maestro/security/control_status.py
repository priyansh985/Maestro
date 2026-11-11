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
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (output validator gate)",
        "security/output_validator.py:OutputValidator",
        "tests/test_output_validator.py + tests/test_platform.py",
        notes="Runtime output policy validator on the model->proposal path: "
              "validates the reasoner's proposed action/summary/metadata against "
              "an allowed-intent set, prompt-injection markers, out-of-scope "
              "targets, length caps and tool-argument smuggling patterns. "
              "Default-on and wired into AgentPlatform.handle_alert; a failing "
              "output is quarantined (not executed) and recorded in the ledger. "
              "Adversarially tested (injected outputs blocked on the live loop).",
    ),
    Control(
        "CTRL-L1-02", "Deterministic reasoner (offline default)", "L1",
        Status.IMPLEMENTED, "enabled", None,
        "agent/reasoning.py:StubReasoner", "tests/test_reasoning.py",
        notes="Safe default (offline/deterministic) that bounds L1 exposure; a "
              "configuration default, not an enforcement point — hence "
              "implemented, not enforced.",
    ),
    Control(
        "CTRL-L1-03", "Action confidence profile (independent signals)", "L1",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (confidence computed per action)",
        "security/confidence.py:action_confidence",
        "tests/test_enforcement_hardening.py + tests/test_platform.py",
        notes="Confidence is built from independently observable signals "
              "(evidence/validator/policy/reversibility/history), NOT model "
              "self-report; it only *raises* scrutiny and can never override a "
              "hard rule. Enforced on the AgentPlatform path: confidence is "
              "computed and gated for every action.",
    ),
    Control(
        "CTRL-L1-04", "Dual-LLM injection perimeter (untrusted input boundary)", "L1",
        Status.TESTED, "enabled",
        "security/perimeter.py:DualLLMPerimeter.ingest",
        "security/perimeter.py:DualLLMPerimeter + InjectionScanner",
        "tests/test_perimeter.py",
        notes="Structural anti-injection: untrusted external content is scanned, "
              "typed variables are the only thing that may cross to the privileged "
              "path, instruction-shaped content is quarantined (admitted only as "
              "inert UNTRUSTED data), and active tool/exfiltration attempts are "
              "blocked. Tested as a standalone boundary; not yet wired into the "
              "AgentPlatform live loop (detector-sourced alerts are internal), so "
              "graded tested, not boundary-enforced.",
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
        "CTRL-L2-03", "Quarantined memory promotion (independent authorization)", "L2",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (every alert quarantined on ingest)",
        "memory/store.py:MemoryStore.promote",
        "tests/test_memory_integrity.py + tests/test_platform.py",
        notes="Now ENFORCED on the live loop: every detection the agent handles "
              "is recorded as an UNTRUSTED episodic record through the scoped "
              "MemoryStore, so quarantine-on-ingest is non-optional and an "
              "injected poison record is inert on the running agent "
              "(test_poisoned_memory_is_quarantined_and_inert_on_the_live_agent). "
              "Promotion to TRUSTED requires an independent, scoped "
              "cap:memory:promote and is recorded in the platform's unified "
              "ledger. In BP5, this promotion is fully wired as a gated action "
              "intent (`promote_memory`) executed through the PEP boundary; "
              "adversarially tested (self-promotion, expired/wrong-tenant "
              "capability, cross-scope promotion all denied).",
    ),
    Control(
        "CTRL-L2-04", "Four-tier memory isolation + read-only procedural tier", "L2",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (evidence grounded via scoped MemoryStore)",
        "memory/store.py:MemoryStore",
        "tests/test_memory_integrity.py + tests/test_platform.py",
        notes="Now ENFORCED on the live loop: every authorized action's evidence "
              "is resolved against the agent's scoped MemoryStore "
              "(isolation-aware existence), so an evidence reference from another "
              "tenant/agent does not resolve (test_evidence_reference_is_scope_"
              "isolated). Strict (tenant, agent) scoping, read-only procedural "
              "memory, and curated-only semantic writes are adversarially tested. "
              "Postgres row-level security remains the production hardening that "
              "moves isolation below the application layer.",
    ),
    Control(
        "CTRL-L2-05", "Capability-gated cross-tenant memory access", "L2",
        Status.IMPLEMENTED, "enabled", None,
        "memory/store.py:MemoryStore.recall_cross_scope", "tests/test_memory_integrity.py",
        notes="Phase-3 build: cross-tenant memory access has *no autonomous path* "
              "(blueprint §4.3) — it requires a cap:memory:cross-tenant-read bound "
              "to the target scope, is deny-by-default, and every access is "
              "recorded in the platform's unified tamper-evident ledger. "
              "Adversarially tested (missing capability, wrong-capability-class, "
              "and wrong-tenant tokens all denied). Rated 'implemented' — a "
              "capability-gated admin path, not part of the automatic live loop.",
    ),
    # L3 — Agent / tool framework
    Control(
        "CTRL-L3-01", "Action allow-list validation (executor boundary)", "L3",
        Status.TESTED, "enabled",
        "platform/agent_platform.py + security/action.py:parse_proposal",
        "security/action.py:INTENT_REGISTRY (allow-list)",
        "tests/test_platform.py + tests/test_enforcement.py",
        notes="Enforced at the executor boundary, not the planner: the platform "
              "parses every proposal against the typed INTENT_REGISTRY allow-list "
              "— an unknown intent is quarantined, an out-of-scope intent denied "
              "at the capability gate. This supersedes the legacy planner-side "
              "toggle (agent/planner.py:validate_plans), which remained "
              "default-off and bypassable.",
    ),
    Control(
        "CTRL-L3-02", "Capability tokens / typed action schema / executor gateway", "L3",
        Status.VERIFIED, "enabled",
        "platform/agent_platform.py:AgentPlatform -> PolicyEnforcementPoint",
        "security/enforcement.py + security/identity.py + security/action.py",
        "tests/test_enforcement.py + tests/test_platform.py",
        notes="Enforcement Plane keystone: untrusted model output is parsed into "
              "a typed proposal, authorized by a signed, scoped, short-lived "
              "capability, and executed only through an allow-listed adapter — "
              "fail-closed. Now ENFORCED on the live path: the AgentPlatform is "
              "the only path that executes tool actions and every action routes "
              "through the gateway (no bypass). Adversarial/bypass tested (forged/"
              "expired/out-of-scope capabilities, rogue and unknown intents) — "
              "hence 'verified'.",
    ),
    Control(
        "CTRL-L3-03", "Autonomy budget / rate limiting + idempotency", "L3",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (budget + idempotency default-on)",
        "security/budget.py:AutonomyBudget",
        "tests/test_enforcement_hardening.py + tests/test_platform.py",
        notes="Bounds tool calls / spend / blast-radius / call-rate before "
              "execution (the 'BudgetAvailable' conjunct); exactly-once "
              "idempotency keys stop a retry from duplicating a side effect. "
              "Enforced on the AgentPlatform path (secure-by-default budget + "
              "per-alert idempotency key); budget consumed only on executed "
              "actions.",
    ),
    Control(
        "CTRL-L3-04", "Executor sandbox — scope + output confinement at the side-effect boundary", "L3",
        Status.VERIFIED, "enabled",
        "platform/agent_platform.py:AgentPlatform -> PolicyEnforcementPoint (sandbox default-on)",
        "security/sandbox.py:ExecutionSandbox",
        "tests/test_sandbox.py + tests/test_platform.py",
        notes="BP4 build: every authorized side effect runs through an in-process "
              "ExecutionSandbox at the executor (default-on, non-optional). The "
              "adapter result must be a JSON dict within a byte cap and may not "
              "claim a target outside the authorized proposal scope; any breach "
              "fails closed (deny 'sandbox') and is audited. Enforced on the "
              "AgentPlatform live loop and adversarially tested (out-of-scope "
              "target, oversized and non-serializable output, and an opt-in "
              "wall-clock timeout all denied). Honest boundary: this is in-process "
              "scope/output confinement, NOT kernel-level isolation - an in-process "
              "wrapper cannot force-kill a thread or contain syscalls, so OS-level "
              "sandboxing (gVisor/Firecracker) remains the documented seam (TB5).",
    ),
    # L4 — Infrastructure
    Control(
        "CTRL-L4-01", "Connector fallback / graceful degradation", "L4",
        Status.TESTED, "enabled", "connectors/fallback.py:FallbackConnector",
        "connectors/fallback.py:FallbackConnector", "tests/test_connectors_fallback.py",
        notes="Availability control for the LLM backend path. Complemented by "
              "latency-aware routing (connectors/routing.py) which routes to the "
              "lowest-p95 healthy connector.",
    ),
    Control(
        "CTRL-L4-02", "Connector provider authentication", "L4",
        Status.TESTED, "enabled", "connectors/providers/http_base.py:HttpConnector",
        "connectors/providers/http_base.py:_headers", "tests/test_connectors_providers.py",
        notes="Per-provider API-key/header auth; keys from env, never persisted.",
    ),
    Control(
        "CTRL-L4-03", "Zero-trust API front door (auth + RBAC, whole /api surface)", "L4",
        Status.VERIFIED, "enabled",
        "server/auth.py:require_role on the control_api AND connectors_api routers "
        "(guards the live PEP-driving surface and the model-testing surface)",
        "server/auth.py:AuthService + require_role",
        "tests/test_api_auth.py",
        notes="BP3.1 + BP3.2 build: every /api route requires a signed HMAC bearer "
              "token and a sufficient role (viewer<operator<admin), fails closed. "
              "The principal's tenant claim is authenticated (signed) and drives "
              "structural per-tenant isolation of the control plane (CTRL-L4-08). "
              "BP3.2 extended the SAME boundary over the "
              "model-testing/connectors API (previously auth=NONE): reads require "
              "VIEWER, every mutation OPERATOR - closing the confused-deputy egress "
              "path where an unauthenticated caller could register a custom "
              "connector at an arbitrary URL. Enforced by default "
              "(mitigation.zero_trust_api=true; set false to restore the paper's "
              "unauthenticated baseline). Adversarially tested "
              "(missing/malformed/forged/expired/revoked tokens and "
              "under-privileged role all denied on both routers; cross-tenant "
              "isolation is proven under CTRL-L4-08) - hence 'verified'. This "
              "gates the API front door, NOT the PEP "
              "execution boundary (so it is not counted in boundary_enforced). "
              "Per-principal rate limiting is now built (CTRL-L4-07); OIDC/SSO "
              "login and an external RBAC/ABAC store remain production seams.",
    ),
    Control(
        "CTRL-L4-04", "Circuit breaker / runaway-loop detection", "L4",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (breaker default-on)",
        "security/circuit_breaker.py:CircuitBreaker",
        "tests/test_operational_safety.py + tests/test_platform.py",
        notes="Halts an agent stuck repeating the same (intent, args) signature "
              ">= N times within a window and escalates; complements idempotency "
              "(which stops re-executing a success). Enforced on the AgentPlatform "
              "path (breaker default-on).",
    ),
    Control(
        "CTRL-L4-05", "Durable execution / exactly-once orchestration", "L4",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (executor runs every side effect "
        "as a journaled activity)",
        "orchestration/engine.py:DurableEngine + security/sandbox.py:ExecutionSandbox",
        "tests/test_orchestration.py + tests/test_sandbox.py + tests/test_platform.py",
        notes="BP4 wiring: the exactly-once mechanism is now ON THE LIVE LOOP by "
              "default. The executor sandbox journals every side effect keyed by "
              "the action's idempotency key and REPLAYS a recorded result instead "
              "of re-invoking the adapter, so a crash-and-retry cannot "
              "double-execute a mitigation. With the default in-memory journal the "
              "guard is process-scoped; AgentPlatform(journal_path=...) uses a "
              "file-backed journal that survives real process death - proven by a "
              "simulated-restart test where a fresh platform over the same on-disk "
              "journal replays the side effect exactly once. The standalone "
              "DurableEngine (event-sourced replay, retries/backoff, timeouts, "
              "replay-divergence detection) remains and is adversarially tested. "
              "Rated 'tested' (not 'verified'): the boundary mechanism and "
              "file-backed durability are tested; production would back the "
              "journal with Temporal.io rather than the in-repo engine.",
    ),
    Control(
        "CTRL-L4-06", "Policy-aware fallback (fail-closed degradation)", "L4",
        Status.TESTED, "enabled",
        "connectors/policy_fallback.py:PolicyAwareFallback",
        "connectors/policy_fallback.py:PolicyAwareFallback", "tests/test_multimodel.py",
        notes="Blueprint §6 correction: fallback degrades only *within* a "
              "request's required capability/trust tier and FAILS CLOSED "
              "(PolicyDegradationRefused) rather than silently downgrading a "
              "high-stakes request to a lower-posture backend — availability is "
              "not permitted to erode the security posture. Tested (low-stakes "
              "degrades freely; high-stakes refuses to drop below its tier). A "
              "connector-layer control (not on the default offline agent loop, "
              "which uses the deterministic stub reasoner).",
    ),
    Control(
        "CTRL-L4-07", "Per-principal API request rate limiting (front-door abuse control)", "L4",
        Status.TESTED, "enabled",
        "server/auth.py:enforce_rate_limit on the control_api + connectors_api routers",
        "server/auth.py:RateLimiter",
        "tests/test_api_auth.py",
        notes="BP3.2 build: a deterministic token-bucket limiter keyed per "
              "principal (tenant:subject) bounds inbound requests on the whole "
              "/api surface and fails closed with HTTP 429 when a bucket is "
              "exhausted, so one credential's burst cannot starve another "
              "principal or the plane. Tested (bucket exhaustion returns 429, "
              "continuous refill re-admits, and each principal has an independent "
              "bucket). Distinct from CTRL-L3-03 (the agent autonomy budget on the "
              "live loop) — this is a front-door (TB0) availability control, so it "
              "is NOT counted in boundary_enforced. Enforced by default "
              "(mitigation.api_rate_limit_per_min=120; <=0 disables; inert when "
              "zero_trust_api is false). A shared (Redis) store so the limit holds "
              "across replicas is the documented production seam.",
    ),
    Control(
        "CTRL-L4-08", "Structural multi-tenant isolation (per-tenant control planes)", "L4",
        Status.VERIFIED, "enabled",
        "server/control_api.py:_TenantPlanes.for_tenant (routes each principal to "
        "its own AgentPlatform+Ledger instance; the sole choke point to live state)",
        "server/control_api.py:_TenantPlanes + viewer_plane/operator_plane/admin_plane",
        "tests/test_tenant_isolation.py",
        notes="BP3.3 build: the control plane is partitioned by tenant. Each "
              "tenant gets its own live AgentPlatform (memory scope (tenant, "
              "agent)), ledger, memory, budget and breaker, created lazily and "
              "reached ONLY through _TenantPlanes.for_tenant keyed by the "
              "authenticated (signed) principal.tenant claim. Isolation is "
              "structural, not a per-call check: a principal for tenant A reaches "
              "a different object graph than tenant B, so there is no shared table "
              "to leak through and no scope argument to forget - and /reset only "
              "ever rebuilds the caller's own tenant's plane. Adversarially tested "
              "(a principal cannot read another tenant's ledger/memory/state/"
              "metrics via ANY route, and cannot reset another tenant's plane; a "
              "spoofed tenant claim fails the token signature). This is a "
              "front-door / data-partition boundary (TB0/TB8), NOT the PEP "
              "execution boundary, so it is not counted in boundary_enforced. "
              "Postgres row-level security is the single-database variant of the "
              "same guarantee and remains the production seam.",
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
        "CTRL-L5-02", "Tamper-evident audit ledger", "L5",
        Status.VERIFIED, "enabled",
        "platform/agent_platform.py:AgentPlatform (every action recorded)",
        "security/ledger.py:Ledger",
        "tests/test_enforcement.py + tests/test_platform.py",
        notes="Append-only, hash-chained, HMAC-signed audit log; verify_chain() "
              "detects insertion/deletion/modification (adversarially tested "
              "against on-disk and in-memory tampering — hence 'verified'). "
              "Enforced on the AgentPlatform path: every outcome (allow AND deny) "
              "is recorded. External anchoring remains a Phase-3 target "
              "(evidence graph integration was completed in BP5); the API's LogStore "
              "is a separate, non-forensic log.",
    ),
    Control(
        "CTRL-L5-03", "Operational residual-risk scoring", "L5",
        Status.IMPLEMENTED, "enabled", None,
        "security/risk_engine.py", "tests/test_risk_engine.py",
        notes="Implemented + unit-tested but NOT enforced: the risk->decision "
              "mapping exists as a library and is not yet wired to gate any "
              "action at a side-effect boundary (Phase 2).",
    ),
    Control(
        "CTRL-L5-04", "Decision observability (CoT-free decision card)", "L5",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform (card emitted per decision)",
        "security/enforcement.py:_decision_card",
        "tests/test_enforcement_hardening.py + tests/test_platform.py",
        notes="Every gateway outcome emits a structured decision card (identity, "
              "validated proposal, evidence refs, policy result, risk, outcome) "
              "and a lifecycle state; raw chain-of-thought / prompts / scratchpad "
              "are deliberately never recorded. Enforced on the AgentPlatform path: "
              "the card is produced for every alert the loop handles and the "
              "absence of chain-of-thought is asserted end-to-end "
              "(test_decision_card_has_evidence_and_no_chain_of_thought).",
    ),
    Control(
        "CTRL-L5-05", "Operational security metrics (ledger-derived)", "L5",
        Status.IMPLEMENTED, "enabled", "security/metrics.py:compute_metrics",
        "security/metrics.py:compute_metrics", "tests/test_operational_safety.py",
        notes="Metrics (authorization rate, denials-by-stage, unsafe-action rate "
              "= bypass proof, tool-failure rate, ledger integrity) are derived "
              "from the tamper-evident ledger, not self-reported counters. "
              "Task-completion / grounding / memory-contamination rates are "
              "omitted (no goal labels / memory subsystem yet), not faked.",
    ),
    Control(
        "CTRL-L5-06", "HMDC gated critique at the side-effect boundary", "L5",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform -> PolicyEnforcementPoint "
        "(pre-execution critique gate default-on)",
        "critique/engine.py:HMDCEngine + security/critique_gate.py:HMDCGate",
        "tests/test_critique.py + tests/test_critique_gate.py + tests/test_platform.py",
        notes="BP7 wiring: the four-stage *gated* HMDC critique (blueprint §5) now "
              "runs as the LAST check before every side effect on the live loop. "
              "Its DETERMINISTIC stages gate autonomously — dispositive guardrails "
              "(a justification that leaks a secret/PII is REJECTed at the boundary "
              "before execution, tested end-to-end) and the environmental verifier "
              "(CTRL-L5-08) — while a probabilistic-judge disagreement / "
              "uncertainty ROUTES TO A HUMAN (escalates to the approver) rather "
              "than autonomously denying on a stand-in score. It never averages "
              "the stages and never lets a judge override a deterministic gate. "
              "Honest limit: the judge/embedder are deterministic lexical "
              "stand-ins, so on the live loop the semantic/ensemble thresholds are "
              "permissive and the operative HARD gate is the guardrail + "
              "environmental-verifier pair; the engine's CONTRACT (cross-family "
              "only, variance-aware, route-uncertainty-to-human) is enforced and "
              "tested — including a no-cross-family-judge routing case and the "
              "PEP escalate/deny mapping. Rated 'tested' not 'verified': the "
              "deterministic gates and the routing contract are tested at the "
              "boundary; a connector-backed cross-family judge would tighten the "
              "probabilistic thresholds.",
    ),
    Control(
        "CTRL-L5-07", "Shadow-mode evaluation (execution withheld)", "L5",
        Status.IMPLEMENTED, "enabled", None,
        "platform/agent_platform.py:shadow_tool_adapters", "tests/test_platform.py",
        notes="Phase-5 build (blueprint §5 sandbox tier): in shadow mode the full "
              "decision pipeline runs and records, but side effects are withheld "
              "(adapters return shadow=True), so a new policy/model can be "
              "evaluated against real traffic before it is granted execution. "
              "Tested: authorized-but-withheld outcome, decision recorded, clean "
              "evaluation metrics. Rated 'implemented' (a mode, not the default).",
    ),
    Control(
        "CTRL-L5-08", "Environmental verifier veto at the side-effect boundary", "L5",
        Status.VERIFIED, "enabled",
        "platform/agent_platform.py:AgentPlatform -> PolicyEnforcementPoint "
        "(pre-execution critique gate default-on)",
        "domains/verifiers.py:NetworkMitigationVerifier + security/critique_gate.py:HMDCGate",
        "tests/test_domains.py + tests/test_critique_gate.py + tests/test_platform.py",
        notes="BP7 wiring: the 'strongest correctness signal' (blueprint §5.3) now "
              "gates the LIVE LOOP. Before any side effect, the deterministic "
              "NetworkMitigationVerifier checks the proposed mitigation against a "
              "fixed policy matrix keyed by the OBSERVED alert class — without "
              "consulting the model — and vetoes anything inappropriate/unsafe: "
              "raising detection thresholds during a DoS (which would blind the "
              "detector mid-attack) or acting on a benign baseline are denied at "
              "the executor even though capability, risk, budget and breaker all "
              "pass. A veto is a fact, so it short-circuits the probabilistic "
              "judges and denies autonomously (deny 'critique'). Default-on "
              "(enable_critique=True); adversarially tested on the live loop "
              "(unsafe mitigation and baseline-action both vetoed) — hence "
              "'verified'. The four cross-domain verifiers (test-suite, "
              "reconciliation, citation-grounding, safety-envelope) remain the "
              "domain-pack library behind the same task_gate contract.",
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
        Status.VERIFIED, "enabled",
        "platform/agent_platform.py:AgentPlatform -> PolicyEnforcementPoint "
        "(signed policy-bundle allow-list verified pre-execution, default-on)",
        "security/policy_bundle.py:PolicyRegistry + PolicyBundle",
        "tests/test_policy_bundle.py + tests/test_platform.py",
        notes="Governance build (blueprint §6 / L6): the executor's effective "
              "intent allow-list is a signed, versioned, content-addressed policy "
              "bundle — not merely static code. TWO enforcement surfaces. (1) "
              "Release-time governance: a change to the policy requires a "
              "two-person rule (separation of duties) — the actor who PROPOSES a "
              "new version may not be the one who APPROVES it; only a distinct "
              "approver's sign-off activates + HMAC-signs the bundle, and every "
              "governed change is recorded in the tamper-evident ledger (version, "
              "proposer, approvers, digest — never a secret). Genesis (v1) is the "
              "deploy-time baseline (single-authority bootstrap, signed for "
              "integrity, not itself a ledger event); every later version goes "
              "through propose->approve->activate with a chained parent_digest. "
              "(2) Execute-time boundary: the active bundle's signature is "
              "re-verified on EVERY read and its allow-list is consulted at the "
              "side-effect boundary before every action — a tampered/absent active "
              "bundle or a disallowed intent fails closed (deny 'policy_bundle'), "
              "which is what makes this boundary_enforced. Default-on "
              "(enable_policy_bundle=True; the genesis baseline admits the agent's "
              "vocabulary so it is non-blocking until a change tightens it). "
              "Adversarially tested (proposer self-approval and duplicate-approval "
              "rejected, a stale concurrent change rejected, a forged signature / "
              "mutated bundle content / wrong key all fail closed, and a "
              "two-person-approved tightening denies the de-listed mitigation on "
              "the LIVE loop) — hence 'verified'. The bundle's numeric limits are "
              "carried as signed, auditable metadata; those are enforced by their "
              "own controls (CTRL-L3-03 budget, CTRL-L4-04 breaker), not "
              "double-claimed. Production seam: external signer identities "
              "(OIDC/KMS key per approver + change-ticket gate) instead of one "
              "shared HMAC key.",
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
        "CTRL-L7-02", "Delegation limits / kill switch", "L7",
        Status.TESTED, "enabled",
        "platform/agent_platform.py:AgentPlatform.halt (kill switch on the live loop)",
        "security/identity.py:CapabilityIssuer.delegate + enforcement.py",
        "tests/test_enforcement.py + tests/test_platform.py",
        notes="Capability delegation strictly narrows scope, cannot outlive the "
              "parent, and is depth-capped (MAX_DELEGATION_DEPTH); the PEP kill "
              "switch denies all actions when tripped. Enforced on the "
              "AgentPlatform path: the agent's capabilities are issued by "
              "delegation from its human controller (delegation_depth=1) and "
              "AgentPlatform.halt() stops the live loop end-to-end "
              "(test_kill_switch_halts_the_platform). SBOM/AI-BOM and "
              "supply-chain attestation remain Phase-5 targets.",
    ),
    Control(
        "CTRL-L7-03", "Secure-by-inheritance agent provisioning", "L7",
        Status.IMPLEMENTED, "enabled", None,
        "platform/provisioning.py:AgentProvisioner", "tests/test_provisioning.py",
        notes="Phase-4 build (blueprint §4.4): a new agent is stood up by "
              "instantiating a bounded PolicyEnvelope (same tenant, intent "
              "vocabulary, budget, and TTL as its cohort) under a capability "
              "delegated from the human controller — never a fresh permissive "
              "default. Least privilege is structural: allowed_intents narrows "
              "the vocabulary and out-of-envelope actions are denied at the "
              "gateway (test_least_privilege_is_enforced_at_the_gateway); "
              "provisioning is health-gated (unavailable provider refused) and "
              "audited. Rated 'implemented' (component): no live "
              "provider-registration event loop drives it yet.",
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


#: The live execution path: a control whose enforcement point is the agent
#: platform gates a *real* side effect, not just a component in isolation.
_BOUNDARY_MARKER = "agent_platform"


def boundary_enforced(controls: list[Control] | None = None) -> list[Control]:
    """Controls actually enforced at the side-effect boundary (the live loop).

    A control counts only if it is ``enforced`` or above *and* its enforcement
    point is the :class:`~maestro.platform.AgentPlatform` execution path — i.e.
    it gates a real tool call, not merely a unit exercised in isolation.
    """
    controls = controls if controls is not None else CONTROLS
    return [
        c for c in controls
        if _RANK[c.status] >= _RANK[Status.ENFORCED]
        and c.enforcement_point is not None
        and _BOUNDARY_MARKER in c.enforcement_point
    ]


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
        "boundary_enforced": len(boundary_enforced(controls)),
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
