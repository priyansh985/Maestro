# MAESTRO Implementation Plan — BP4 Completion, BP7 Completion, BP11

**Context:** Security control plane complete through BP10. 430+ tests passing. Need to finish partial phases before productization.

---

## BP4: Runtime Kernel Hardening — Completion

### Current State
- ✅ In-process sandbox (scope confinement, exactly-once via journal)
- ✅ External sandbox support (Docker/gVisor) — 14/17 tests passing
- ✅ AutonomyBudget, CircuitBreaker, ExecutionSandbox
- ⚠️ **Missing:** Temporal.io backing, compensation actions framework

### 4.1 Temporal.io Backing for Durable Execution

**Goal:** Replace in-memory journal with Temporal workflow engine for production durability.

#### Deliverables
- [ ] `src/maestro/orchestration/temporal_backend.py` — Temporal client + workflow definitions
- [ ] `src/maestro/orchestration/activities.py` — Activity implementations (execute_adapter, verify_postcondition, compensate)
- [ ] `src/maestro/orchestration/workflows.py` — `ActionWorkflow` (idempotent, retryable, compensatable)
- [ ] `src/maestro/orchestration/temporal_journal.py` — `TemporalJournal` implementing `Journal` interface
- [ ] `src/maestro/orchestration/__init__.py` — Export temporal backend
- [ ] Config: `configs/temporal.yaml` — namespace, task queue, retry policies
- [ ] Tests: `tests/test_temporal_backend.py` — mock Temporal server, verify replay/compensation

#### Technical Design
```
┌─────────────────────────────────────────────────────────────┐
│                    ActionWorkflow                            │
├─────────────────────────────────────────────────────────────┤
│  execute()                                                   │
│   ├─ validate_evidence()                                     │
│   ├─ authorize() → PolicyEnforcementPoint                   │
│   ├─ execute_adapter() → Sandbox (in-process/Docker/gVisor) │
│   ├─ verify_postcondition()                                  │
│   └─ on_failure: compensate()                                │
└─────────────────────────────────────────────────────────────┘
```

#### Temporal Workflow Interface
```python
@workflow.defn
class ActionWorkflow:
    @workflow.run
    async def execute(self, action_input: ActionInput) -> ActionResult:
        # Idempotency key = action_input.idempotency_key
        # All steps are activities (retriable, durable)
```

#### Acceptance Criteria
- [ ] Workflow survives process crash + restarts from last checkpoint
- [ ] Exactly-once semantics via idempotency key
- [ ] Compensation activities triggered on failure
- [ ] Configurable retry policies per action class
- [ ] Metrics: workflow duration, retry count, compensation rate

---

### 4.2 Compensation Actions Framework

**Goal:** Every irreversible action has a compensating undo operation.

#### Current State
- `ActionState` enum exists: `CREATED → CONTEXT_VALIDATED → PLAN_PROPOSED → POLICY_EVALUATED → APPROVAL_PENDING → AUTHORIZED → EXECUTING → POSTCONDITION_VERIFIED → COMPLETED`
- No compensation logic implemented

#### Deliverables
- [ ] `src/maestro/security/compensation.py` — Compensation registry + execution
- [ ] `CompensationAction` protocol — `compensate(original_proposal, execution_result)`
- [ ] Built-in compensations for all `CAPABILITY_REQUIRED_ACTIONS`:
  - `block_source_ip` → `unblock_source_ip`
  - `rate_limit_source` → `remove_rate_limit`
  - `rotate_credentials` → `restore_credentials` (from vault backup)
  - `run_containment_script` → `restore_from_backup`
  - `code_git_push` → `git_revert`
  - `code_open_pr` → `close_pr`
- [ ] Compensation journal — records compensation attempts + outcomes
- [ ] Integration: `ExecutionSandbox.run()` → on failure, invoke compensation
- [ ] Tests: `tests/test_compensation.py` — verify each compensation reverts state

#### Technical Design
```python
@dataclass
class CompensationAction:
    original_intent: str
    compensation_intent: str
    compensation_args: Callable[[ActionProposal, dict], dict]

COMPENSATION_REGISTRY: dict[str, CompensationAction] = {
    "block_source_ip": CompensationAction(
        original_intent="block_source_ip",
        compensation_intent="unblock_source_ip",
        compensation_args=lambda p, r: {"ip": p.target, "reason": f"compensate {p.intent}"}
    ),
    # ...
}
```

#### Acceptance Criteria
- [ ] Every `CAPABILITY_REQUIRED_ACTION` has a compensation
- [ ] Compensation executed automatically on postcondition failure
- [ ] Compensation recorded in ledger with link to original action
- [ ] Manual compensation trigger via CLI/API
- [ ] Compensation failure escalates (alert_operator)

---

## BP7: Evaluation, Adversarial Testing, Release Gates — Completion

### Current State
- ✅ HMDC engine + 4 environmental verifiers (TestSuite, Reconciliation, Citation, SafetyEnvelope)
- ✅ Shadow mode (`AgentPlatform(shadow=True)`)
- ✅ TC1 (DoS), TC2 (Memory Poisoning)
- ⚠️ **Missing:** Release-gate registry, TC3–TC15 adversarial corpus

---

### 7.1 Formal Release-Gate Registry

**Goal:** Versioned, signed gate bundles that block unsafe agent deployments.

#### Deliverables
- [ ] `src/maestro/security/release_gate.py` — `ReleaseGate`, `GateBundle`, `GateRegistry`
- [ ] `GateBundle` schema:
  ```python
  @dataclass
  class GateBundle:
      version: str
      agent_spec_hash: str  # hash of AgentSpec (tools, prompts, policies)
      gates: list[Gate]     # e.g., "test_suite_pass", "citation_grounding", "safety_envelope"
      thresholds: dict[str, float]  # min_test_pass_rate, min_citation_coverage, etc.
      signed_by: tuple[str, str]  # (approver1, approver2) — two-person rule
      signature: str
      expires_at: float
  ```
- [ ] `GateRegistry` — CRUD + activation (only one active per agent_spec)
- [ ] `ReleaseGateEvaluator` — runs all gates, produces `GateResult`
- [ ] Integration: `AgentPlatform.deploy()` → requires active `GateBundle` passing
- [ ] CLI: `maestro gate create|list|activate|evaluate`
- [ ] Tests: `tests/test_release_gate.py` — gate creation, evaluation, blocking

#### Acceptance Criteria
- [ ] Gate bundles are signed, versioned, two-person approved
- [ ] Failed gate → deployment blocked (fail-closed)
- [ ] Gate evaluation runs in < 5 min for typical agent
- [ ] Gate history auditable in ledger
- [ ] Rollback to previous gate bundle supported

---

### 7.2 TC3–TC15 Adversarial Corpus

**Goal:** 13 additional threat cases covering the full adversarial surface.

#### Threat Cases to Implement

| TC | Name | Category | Target | Expected Behavior |
|----|------|----------|--------|-------------------|
| TC3 | Prompt Injection (direct) | Injection | LLM reasoner | Perimeter quarantines; no action |
| TC4 | Indirect Injection (RAG) | Injection | Retrieved context | Quarantined; never influences plan |
| TC5 | Tool Argument Smuggling | Injection | Tool calls | Schema validation rejects malformed args |
| TC6 | Confused Deputy | AuthZ | Capability tokens | Cross-tenant capability denied |
| TC7 | Connector Compromise | Supply chain | Provider adapter | Policy-aware fallback refuses degraded provider |
| TC8 | Data Exfiltration | Egress | Outbound calls | SSRF guard blocks; egress allow-list enforced |
| TC9 | Rogue Delegation | AuthZ | Sub-agent creation | Delegation depth=0 enforced; no autonomous delegation |
| TC10 | Log Tampering | Audit | Ledger | Hash-chain detects tampering; alert |
| TC11 | Rollback Attack | Integrity | Journal | Exactly-once prevents replay; compensation recorded |
| TC12 | Cross-Tenant Leak | Isolation | Memory/ledger | RLS + capability-gated cross-tenant read |
| TC13 | Unsafe Code Execution | Sandbox | Code adapter | Docker/gVisor confinement; scope enforced |
| TC14 | Model Supply Chain | Supply chain | Model weights | Connector capability contract validates |
| TC15 | Multi-Agent Collusion | Orchestration | MoA | Disagreement→human; no autonomous consensus |

#### Deliverables
- [ ] `tests/adversarial/` — one test file per TC
- [ ] `tests/adversarial/conftest.py` — shared fixtures (malicious inputs, compromised components)
- [ ] Each test: `assert result.decision == DENY` or `quarantine`
- [ ] CI integration: `pytest tests/adversarial/ -q` must pass
- [ ] Documentation: `docs/ADVERSARIAL_CORPUS.md` — threat model, test descriptions, expected results

#### Acceptance Criteria
- [ ] All 13 new TCs pass (DENY/quarantine)
- [ ] Corpus runs in < 2 min
- [ ] Each TC tests a distinct bypass path
- [ ] Corpus updates with new threat intel (versioned)

---

## BP11: Console, CLI, SDK, Operations — Completion

### Current State
- ✅ CLI structure (`agent`, `policy`, `memory`, `ledger`, `tenant` commands)
- ✅ Control panel SPA (`/control` — 8 tabs)
- ⚠️ **Missing:** CLI→API wiring, Python SDK

---

### 11.1 Wire CLI to Control Plane API

**Goal:** All CLI commands execute via `/api/*` REST endpoints.

#### Deliverables
- [ ] `src/maestro/sdk/http_client.py` — `ControlPlaneClient` (auth, retry, error handling)
- [ ] `src/maestro/sdk/__init__.py` — Export client
- [ ] Refactor each CLI command to use client:
  - `agent create|list|logs|promote|delete` → `POST/GET /api/agents/...`
  - `policy validate|diff|promote|rollback` → `POST/GET /api/policies/...`
  - `memory inspect|promote|quarantine` → `GET/POST /api/memory/...`
  - `ledger verify|export|audit` → `GET /api/ledger/...`
  - `tenant create|isolate|audit` → `POST/GET /api/tenants/...`
- [ ] Auth: CLI reads `MAESTRO_API_KEY` or `~/.maestro/credentials`
- [ ] Output formatting: JSON (default), table, YAML
- [ ] Tests: `tests/test_cli_integration.py` — spin up test server, run CLI commands

#### Acceptance Criteria
- [ ] All CLI commands work against live control plane
- [ ] Auth fails gracefully with clear messages
- [ ] Output formats work consistently
- [ ] Error messages actionable (include request ID)

---

### 11.2 Python SDK

**Goal:** Typed, documented client library for developers.

#### Deliverables
- [ ] `src/maestro/sdk/client.py` — `AgentClient`, `PolicyClient`, `MemoryClient`, `LedgerClient`, `TenantClient`
- [ ] `src/maestro/sdk/models.py` — Pydantic models for all request/response types
- [ ] `src/maestro/sdk/exceptions.py` — Typed exceptions (`NotFound`, `Unauthorized`, `ValidationError`, `Conflict`)
- [ ] `src/maestro/sdk/__init__.py` — Public exports
- [ ] Usage example:
  ```python
  from maestro.sdk import AgentClient, MemoryClient
  
  client = AgentClient(base_url="https://api.maestro.example.com", api_key="...")
  agent = client.create_agent(type="coding", tenant="my-tenant")
  result = client.execute(agent.id, alert=Alert(...))
  
  memory = MemoryClient(client)
  records = memory.recall(agent_id=agent.id, tier="episodic")
  ```
- [ ] Tests: `tests/test_sdk.py` — unit + integration
- [ ] Docs: `docs/SDK.md` — installation, quickstart, API reference

#### Acceptance Criteria
- [ ] SDK installable via `pip install maestro-sdk` (separate package or extra)
- [ ] Full type hints, mypy clean
- [ ] Retry logic with exponential backoff
- [ ] Async support (`aiohttp` backend)
- [ ] Documentation with runnable examples

---

## Dependency Order & Timeline

```
Week 1-2: BP4 Completion
  ├─ 4.1 Temporal.io backing (3 days)
  ├─ 4.2 Compensation framework (3 days)
  └─ Integration testing (1 day)

Week 3-4: BP7 Completion
  ├─ 7.1 Release-gate registry (3 days)
  ├─ 7.2 TC3-TC15 adversarial corpus (4 days)
  └─ Integration testing (1 day)

Week 5-6: BP11 Completion
  ├─ 11.1 CLI→API wiring (3 days)
  ├─ 11.2 Python SDK (3 days)
  └─ Documentation + examples (1 day)

Total: ~6 weeks to v1.0-ready
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Temporal.io adds complexity | Keep in-memory journal as default; Temporal opt-in via config |
| Compensation actions may fail | Compensation failure → alert_operator + manual intervention; never silent |
| Adversarial corpus maintenance | Version corpus; automate via threat intel feeds |
| SDK scope creep | Define v1.0 surface explicitly; defer advanced features |
| Windows CI for Docker/gVisor | Mock external sandbox in CI; integration tests on Linux runners |

---

## Definition of Done for This Plan

- [ ] All BP4, BP7, BP11 deliverables implemented
- [ ] 500+ tests passing (core + new)
- [ ] `maestro-v1-validate` script passes
- [ ] Documentation complete: `docs/TEMPORAL.md`, `docs/COMPENSATION.md`, `docs/RELEASE_GATES.md`, `docs/ADVERSARIAL_CORPUS.md`, `docs/SDK.md`
- [ ] Tag `v1.0.0-rc1` for release candidate