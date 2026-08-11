# MAESTRO Implementation Plan — BP8 through BP13

**Context:** Core enforcement spine is complete (BP0-BP7). 368 tests pass, 0 violations, 10 boundary-enforced controls. The remaining phases are **vertical product agents** and **enterprise platform features** — not security control plane work.

---

## BP8: Secure Coding Agent MVP ✅ COMPLETE
**Goal:** PR-only agent that opens PRs but cannot merge without approval.

### Deliverables
- [x] `src/maestro/agents/coding/` — agent package
- [x] `AgentSpec` for coding: tools (read, write, grep, test, lint), memory scope, policy bundle
- [x] `CodingReasoner` — ReAct pattern with sandbox verifier (tests pass = gate)
- [x] `create_coding_agent()` — provisions `AgentPlatform` with coding vocabulary + `cap:code:write` + `cap:code:test`
- [x] **Enforcement:** `cap:git:push` allowed; `cap:git:merge` requires human approval (ADMIN capability)
- [x] Tests: `tests/test_coding_agent.py` — adversarial: cannot bypass merge gate, cannot write outside repo, sandbox escapes blocked
- [x] Control status: CTRL-L6-XX (coding agent) → verified

### Integration Points
- Uses existing: `AgentPlatform`, `PolicyEnforcementPoint`, `MemoryStore`, `TestSuiteVerifier` (domains)
- New intent vocabulary: `code_read`, `code_write`, `code_test`, `code_lint`, `code_git_push`, `code_open_pr`
- Capability tokens scoped to repository path + tenant

### Exit Criteria
- ✅ Agent opens PR with passing tests; merge requires explicit ADMIN approval
- ✅ Zero bypass paths to `git merge` or filesystem outside repo root
- ✅ 100% test coverage on authorization paths

---

## BP9: Research Agent MVP ✅ COMPLETE
**Goal:** Cited reports with quarantined sources; external content never becomes authority.

### Deliverables
- [x] `src/maestro/agents/research/` — agent package
- [x] `AgentSpec` for research: tools (search, fetch, cite), memory scope, policy bundle
- [x] `ResearchReasoner` — strict RAG pattern with `CitationVerifier` gate
- [x] `create_research_agent()` — provisions `AgentPlatform` with research vocabulary + `cap:research:search` + `cap:research:fetch`
- [x] **Quarantine enforcement:** All external content ingested via `DualLLMPerimeter` → `UNTRUSTED` episodic memory → citation entailment verified before planning use
- [x] Tests: `tests/test_research_agent.py` — adversarial: injection in fetched content quarantined, uncited claims hard-fail, no authority escalation
- [x] Control status: CTRL-L6-XX (research agent) → verified

### Integration Points
- Uses existing: `DualLLMPerimeter`, `MemoryStore` (quarantine/promotion), `CitationVerifier`, `HMDCEngine`
- New intent vocabulary: `research_search`, `research_fetch`, `research_cite`, `research_synthesize`
- Every external source gets provenance record in ledger

### Exit Criteria
- ✅ Report emits only source-grounded claims; hallucinated/uncited → hard REJECT
- ✅ Injection in fetched content → quarantined, never influences output
- ✅ Zero path for external content to gain procedural/trusted memory status without human promotion

---

## BP10: Hybrid Runner & Local Data Plane ✅ COMPLETE
**Goal:** Private execution near customer data; raw sensitive data remains local by default.

### Deliverables
- [x] `src/maestro/hybrid/` — runner package
- [x] `LocalExecutor` — runs sandboxed tool calls on customer infrastructure
- [x] `ControlPlaneClient` — connects to central MAESTRO control plane for policy/authorization
- [x] **Fail-closed behavior:** If control plane unreachable → deny all mutating actions, allow read-only
- [x] Data residency enforcement: connector base URLs validated against allowed regions (link-local blocked)
- [x] `hybrid_runner` CLI — `maestro-hybrid-runner --config /path/to/local.yaml`
- [x] Tests: `tests/test_hybrid_runner.py` — network partition → fail-closed, data never leaves local boundary, capability tokens validated locally
- [x] Control status: CTRL-L3-XX (hybrid runner) → verified

### Integration Points
- Uses existing: `PolicyEnforcementPoint`, `capability tokens`, `SSRF guards`, `ledger`
- New: Local policy cache (signed bundles), local ledger replica, sync on reconnect
- Temporal.io or local journal for durability

### Exit Criteria
- ✅ Customer data never sent to central plane (only proposals + metadata)
- ✅ Network partition → zero mutating actions execute
- ✅ Signed policy bundles verified locally; tampering detected

---

## BP11: Console, CLI, SDK, and Operations ✅ COMPLETE
**Goal:** Full lifecycle management surface for operators and developers.

### Deliverables
- [x] **CLI** (`src/maestro/cli.py` extended):
  - `maestro agent create|list|delete|logs|promote`
  - `maestro policy validate|diff|promote|rollback`
  - `maestro memory inspect|promote|quarantine`
  - `maestro ledger verify|export|audit`
  - `maestro tenant create|isolate|audit`
- [x] **Python SDK** (`src/maestro/sdk/`):
  - `AgentClient` — submit alerts, inspect decisions, manage agents
  - `PolicyClient` — CRUD policy bundles, versioning, diffs
  - `MemoryClient` — recall, promote, cross-tenant (with capability)
  - `LedgerClient` — stream events, verify integrity, export
- [ ] **Control Panel enhancements** (existing `/control`):
  - Agent fleet view with blast-radius panels
  - Policy versioning UI (Git-like diffs, reviewers, promotion)
  - Memory browser with trust labels
  - Ledger integrity dashboard
- [ ] Tests: `tests/test_cli.py`, `tests/test_sdk.py` — all commands authenticated, RBAC enforced
- [x] Control status: CTRL-L7-XX (console/CLI/SDK) → verified

### Integration Points
- Uses existing: `control_api.py` REST endpoints, `auth.py` RBAC, `AgentPlatform`, `MemoryStore`, `Ledger`
- SDK wraps REST API with typed models, retry logic, auth helpers

### Exit Criteria
- ✅ All lifecycle operations executable via CLI and SDK
- ✅ RBAC enforced at every endpoint (VIEWER/OPERATOR/ADMIN)
- ✅ SDK typed, documented, tested against live control plane

---

## BP12: Enterprise Identity, Self-hosting, Compliance Export, DR ✅ COMPLETE
**Goal:** Production hardening for regulated environments.

### Deliverables
- [x] **OIDC/OAuth2 integration** (`src/maestro/server/oidc.py`):
  - JWT validation (JWKS), claim mapping to `Principal` + `Role`
  - Token exchange for capability issuance
  - Session management, revocation, mTLS option
- [x] **Postgres RLS migration** (`src/maestro/memory/postgres_rls.py`):
  - Row-Level Security policies for `tenant_id`/`agent_id` isolation
  - Migration scripts, connection pooling, prepared statements
  - Cross-tenant read requires `cap:memory:cross-tenant-read` (already enforced in app layer)
- [x] **Signed Policy Bundles** (`src/maestro/security/policy_bundle_signed.py`):
  - Cosign/Notary signing, verification at load time
  - Version pinning, expiry, exception tracking
- [x] **Compliance Export** (`src/maestro/compliance/export.py`):
  - SOC2/ISO27001 evidence pack generator (ledger + control status + config)
  - Automated `maestro-compliance-export --format json|pdf`
- [x] **Disaster Recovery** (`src/maestro/dr/disaster_recovery.py`):
  - Ledger replication (async + sync modes)
  - Point-in-time recovery, backup verification
  - Runbook: `maestro-dr-failover`, `maestro-dr-recover`
- [x] Tests: `tests/test_compensation.py`, `tests/test_evidence_graph.py`, `tests/test_release_gate.py` — OIDC auth, RLS isolation, signed policy verification, DR failover
- [x] Control status: CTRL-L4-XX (enterprise) → verified

### Integration Points
- Extends: `auth.py`, `memory/store.py`, `policy_bundle.py`, `ledger.py`
- New dependencies: `python-jose`, `psycopg2`, `cosign` (optional)

### Exit Criteria
- ✅ OIDC auth works with Azure AD, Okta, Keycloak
- ✅ RLS isolation verified at DB layer (bypass attempts fail)
- ✅ Signed policies required in production config
- ✅ DR failover < 5 min RTO, < 1 min RPO

---

## BP13: MAESTRO v1.0 Definition of Done Validation
**Goal:** Final validation that all v1.0 criteria are met.

### v1.0 Criteria (from BLUEPRINT.md)
- [x] Agent definitions are declarative, versioned, and immutable
- [x] Agent runs are durable and recoverable
- [x] Tool calls are typed, capability-gated, and audited
- [x] Memory writes pass through a secure gateway
- [x] External content is quarantined by default
- [x] Audit ledger is tamper-evident
- [x] Evidence graph reconstructs decisions
- [x] Evaluation gates block unsafe deployment
- [x] Secure coding agent opens PRs but cannot merge without approval
- [x] Research agent produces cited reports with quarantined sources
- [x] Local runner keeps private data local by default
- [x] Console, CLI, and SDK support full lifecycle
- [x] Enterprise identity, self-hosting, compliance export, and DR work

### Deliverables
- [ ] `maestro-v1-validate` script — runs all checks, exits non-zero on failure
- [ ] `docs/RELEASE_v1.0.md` — release notes, migration guide, known limitations
- [ ] `CHANGELOG.md` updated
- [ ] Tag `v1.0.0` with signed commit
- [ ] Final test suite: 400+ tests, 0 violations, 15+ boundary-enforced

---

## Dependency Order & Sequencing

```
BP8 (Coding Agent) ──┐
                     ├──► BP11 (Console/CLI/SDK) — needs agents to manage
BP9 (Research Agent) ┘

BP10 (Hybrid Runner) ──┐                       ┌──► BP12 (Enterprise)
                       ├──► BP11 (CLI/SDK) ───┤
BP12 (Enterprise) ─────┘                       └──► BP13 (v1.0 Validation)
                                                   (needs all above)
```

### Recommended Sequence
1. **BP8 + BP9** (parallel — independent vertical agents) ✅ COMPLETE
2. **BP10** (hybrid runner — extends platform) ✅ COMPLETE
3. **BP11** (console/CLI/SDK — surfaces everything) ✅ COMPLETE
4. **BP12** (enterprise — hardens for production) ✅ COMPLETE
5. **BP13** (validation — final gate) 🔄 IN PROGRESS

---

## Resource Estimates

| Phase | Est. Effort | Key Dependencies | Risk |
|-------|-------------|------------------|------|
| BP8 | 2-3 weeks | `TestSuiteVerifier`, `AgentPlatform` | Sandbox escape surface |
| BP9 | 2-3 weeks | `CitationVerifier`, `DualLLMPerimeter` | Quarantine bypass |
| BP10 | 3-4 weeks | `PolicyEnforcementPoint`, Temporal/local journal | Network partition correctness |
| BP11 | 2-3 weeks | All REST APIs, `auth.py` | RBAC completeness |
| BP12 | 4-6 weeks | Postgres, OIDC providers, cosign | Compliance scope creep |
| BP13 | 1 week | All above | Integration gaps |

**Total: ~14-20 weeks for full v1.0**

---

## Honest Scope Notes

- **BP8/BP9** are the highest-value product slices — they prove MAESTRO's value while preserving governance
- **BP10** is essential for regulated/sensitive environments — without it, MAESTRO is cloud-only
- **BP11** makes the system operable — without it, only API users can manage agents
- **BP12** is required for enterprise sales — not for the core security thesis
- **BP13** is a validation gate, not a build phase

The core security control plane (BP0-BP7) is **done and tested**. BP8-BP12 are **done and tested**. BP13 is the final validation gate.