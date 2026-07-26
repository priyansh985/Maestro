# Trust Boundaries (BP0)

A **trust boundary** is a line across which data changes trust level, or control
changes authority. MAESTRO's architecture is a sequence of such lines between
untrusted model output and a real side effect. This document names them so that
any new code can be checked against "which boundary am I crossing, and what
converts trust here?"

## The spine: untrusted intention → authorized side effect

```
 [ untrusted world ]                         [ privileged execution ]
 external content ─► TB1 perimeter ─► symbolic vars ─► TB2 reasoner
   (indirect        (quarantine +                        proposes
    injection)       typed extraction)                   intention
                                                            │
                                                            ▼
   model output ─► TB3 proposal parse ─► TB4 policy gate ─► TB5 executor
   (untrusted)      (typed, allow-list)   (capability +     (allow-listed
                                           budget +          adapter =
                                           fail-closed)      side effect)
                                                            │
                                                            ▼
                                        TB6 ledger (tamper-evident record)
```

## The boundaries

| ID | Boundary | Converts | Enforced by | Control |
|---|---|---|---|---|
| **TB0** | API front door (whole `/api` surface) | anonymous caller → an authenticated `Principal` (signed bearer token) with a role and tenant; fails closed (401/403); bounded per principal (429) | `server/auth.py:require_role` + `enforce_rate_limit` on the control_api **and** connectors_api routers | CTRL-L4-03/07 |
| **TB1** | Untrusted-content perimeter | external text → typed symbolic variables only; instruction-shaped content quarantined as inert `UNTRUSTED` data | `DualLLMPerimeter.ingest` + `InjectionScanner` | CTRL-L1-04 |
| **TB2** | Reasoner / planner | grounding + goal → a *proposed* intention (no authority) | `AgentPlatform` (model only proposes) | CTRL-L1-02/03 |
| **TB3** | Proposal parse | untrusted model string → typed `ActionProposal` against the `INTENT_REGISTRY` allow-list | `security/action.py:parse_proposal` | CTRL-L3-01 |
| **TB4** | Policy enforcement point | typed proposal → *authorized* action (signed scoped capability, budget, breaker, confidence — fail-closed) | `security/enforcement.py:PolicyEnforcementPoint` | CTRL-L3-02/03, L4-04 |
| **TB5** | Executor gateway | authorized action → real side effect via an allow-listed adapter — the intent must be permitted by the active **signed policy bundle** (verified here, fail-closed), then passed through a pre-execution critique gate (HMDC + environmental verifier vetoes an unsafe/inappropriate mitigation), then run inside an executor sandbox (scope + output confinement, durable exactly-once) | `platform/agent_platform.py` tool adapters + `security/policy_bundle.py:PolicyRegistry` + `security/critique_gate.py:HMDCGate` + `security/sandbox.py:ExecutionSandbox` | CTRL-L3-02, L3-04, L4-05, L5-06, L5-08, L6-03 |
| **TB6** | Audit record | every outcome (allow **and** deny) → append-only hash-chained ledger entry | `security/ledger.py:Ledger` | CTRL-L5-02 |
| **TB7** | Memory trust label | external/observed data → `UNTRUSTED` on ingest; `TRUSTED` only via independent capability | `memory/store.py:MemoryStore` (quarantine + promote) | CTRL-L2-03/04/05 |
| **TB8** | Tenant / scope isolation | one tenant → another (no crossing) — the control plane routes each principal to its **own** `AgentPlatform`+ledger+memory, structurally (not a per-call check) | `server/control_api.py:_TenantPlanes` + `MemoryStore` scope checks + capability scope | CTRL-L4-08, L2-04/05, L7-02 |
| **TB9** | Human / delegation | human authority → agent authority by *narrowing* delegation (depth-capped, cannot outlive parent) | `security/identity.py:CapabilityIssuer.delegate` | CTRL-L7-02/03 |
| **TB10** | Host / network egress | in-box computation → outbound provider call | `connectors/providers/http_base.py` (auth, fail-closed fallback) | CTRL-L4-02/06 |

## Invariants across the spine

1. **No bypass.** The `AgentPlatform` path is the *only* route from a model
   proposal to TB5. Nothing crosses TB5 without first crossing TB3 and TB4.
2. **Trust only ever narrows autonomously.** Delegation (TB9) narrows scope;
   promotion to `TRUSTED` (TB7) and cross-tenant reads (TB8) have **no autonomous
   path** — each needs an independent, scoped capability and is recorded at TB6.
3. **Fail closed.** TB4 and TB10 deny on ambiguity rather than degrade posture.
4. **Everything is recorded.** Every crossing of TB4/TB5 — allow *and* deny —
   produces a TB6 ledger entry; the decision card carries evidence refs but never
   raw chain-of-thought.

## The current soft line: TB-host (production gap)

The application-layer boundaries above are enforced in-process. Some are **not yet
backed below the application layer** and BP0 records this honestly:

- **TB0 (API front door)** — **closed for the whole `/api` surface** (BP3.1 +
  BP3.2, CTRL-L4-03 `verified`): every control_api *and* connectors_api route
  requires a signed bearer token + role, is tenant-confined, and is rate-limited
  per principal (CTRL-L4-07) — all fail-closed. **0 `/api` endpoints are
  unauthenticated.** Remaining seams: **OIDC/SSO** login instead of statically
  issued tokens, an external **RBAC/ABAC** store, and a shared (Redis) rate-limit
  store so the bound holds across replicas.
- **TB8 (tenant isolation)** — **structural** (CTRL-L4-08): at TB0 the signed
  `tenant` claim routes each principal to its **own** `AgentPlatform`+ledger+memory
  object graph (`server/control_api.py:_TenantPlanes`), so there is no cross-tenant
  read/reset path to check — isolation is by construction, not a per-call guard.
  `MemoryStore` scope checks back it within a plane. The production hardening is
  Postgres **row-level security** (single-DB variant) so isolation survives an
  application bug even when tenants share one store (BP3 / CTRL-L2-04 note).
- **TB5 correctness gate** — **closed (BP7).** Before any side effect a
  pre-execution critique gate runs the HMDC engine (CTRL-L5-06) + a deterministic
  **environmental verifier** (CTRL-L5-08): the proposed mitigation is checked
  against a fixed policy matrix keyed by the *observed* alert class and vetoed if
  inappropriate/unsafe (e.g. raising detection thresholds mid-DoS, which blinds
  the detector), with the model given no say. Deterministic stages (guardrails +
  verifier) deny autonomously; probabilistic-judge uncertainty routes to a human.
  The seam is a **connector-backed cross-family judge** — the offline judge/
  embedder are deterministic lexical stand-ins, so the operative hard gate is the
  guardrail + verifier pair and the engine's *contract* is what is enforced.
- **TB5 sandboxing** — **partially closed (BP4).** Every side effect then runs
  inside an in-process `ExecutionSandbox` (CTRL-L3-04): the adapter result is
  scope-confined (it may not claim a target outside the authorized proposal) and
  byte-bounded, and execution is a journaled activity replayed **exactly-once**
  across a crash (CTRL-L4-05, file-backed journal). What remains a seam is
  **kernel-level isolation** — an in-process wrapper cannot force-kill a runaway
  thread or contain syscalls; production would execute through an OS sandbox
  (gVisor/Firecracker). In this offline reproduction the adapters are
  `SIMULATED_EXTERNAL`, so the missing OS sandbox does not currently expose the
  host, and the durable runtime is the in-repo engine rather than Temporal.io.

These are named in `control_gap_report.md` and `module_disposition.json`, not
papered over.
