# MAESTRO v1.1 Roadmap — seams → tracked work items

This document turns the honest seams listed under **Known limitations** in
[`RELEASE_v1.0.md`](RELEASE_v1.0.md) into tracked, actionable work items for
v1.1. It does not modify `src/`; it scopes the work so each seam becomes a
verifiable deliverable rather than an implicit gap.

Seam descriptions are taken from `docs/RELEASE_v1.0.md` (Known limitations) and
`docs/audit/control_gap_report.md` (Gap C — production hardening below the
application layer). Effort estimates are engineering-weeks for a single
engineer working against the existing in-repo test harness; they are indicative,
not commitments.

Status legend: `open` = not started; `in progress`; `done` = shipped in this
cycle.

---

## 1. OS-level sandbox (Docker/gVisor)

**Status:** open (seam)

**Goal.** Promote `CTRL-L3-04` executor sandbox from in-process scope/output
confinement to kernel-level isolation so a malicious or runaway adapter cannot
escape the process or exhaust host resources. Linux runner proves real
containment; Windows CI keeps a mocked path.

**Current state (what ships today).** Every authorized side effect runs through
`maestro.security.sandbox.ExecutionSandbox` with scope + output confinement
(byte cap, target scope, wall-clock timeout) — `boundary_enforced` and
adversarially tested (`tests/test_sandbox.py`). Docker/gVisor modes are
implemented (`sandbox_type="docker"|"gvisor"`) and exercised via mocked
subprocess in `tests/test_sandbox_external.py` and `tests/adversarial/test_tc13_unsafe_code_exec.py`.
Windows CI runs them mocked (no container toolchain).

**Gap.** In-process confinement cannot force-kill a thread or contain syscalls;
`importlib`-based adapter loading shares the host process. No Linux CI lane
currently runs the real `docker`/`runsc` path, so containment is unproven.

**Effort estimate.** 3-4 weeks (Linux runner provisioning + gVisor integration
tests + resource/egress limits + documentation).

**Dependencies.** Linux CI runners with Docker + gVisor (`runsc`); item 2
(Temporal) for retry/compensation across a killed guest; no change to the
in-process contract.

**First concrete step.** Add a `linux-integration` CI job that installs
`runsc`, runs `tests/test_sandbox_external.py` with `MAESTRO_SANDBOX_REAL=1`,
and fails on any mock fallback; gate merge on green.

**Acceptance criteria.**
- Real `runsc`/`docker` execution path passes on Linux CI with no mocking.
- Containment evidence: out-of-scope filesystem/network access denied, CPU/memory
  caps enforced, timeout kills the guest.
- Mocked path remains available for Windows/offline dev with explicit
  `simulated=True` flag; `audit_invariants()` still reports 0 violations.
- Updated `docs/audit` seam note removed for OS sandboxing.

**Risk.** gVisor feature gaps (e.g. certain syscalls) may break adapters;
mitigation is a documented supported-syscall matrix and a per-adapter
compatibility check before promotion.

---

## 2. Temporal.io live backing

**Status:** open (seam)

**Goal.** Exercise the `TemporalJournal`/`ActionWorkflow` adapter against a
live Temporal server so the durable backend claim is evidence-backed, not
fixture-backed; keep file-backed journal as the default offline engine.

**Current state (what ships today).** The boundary-enforced durable engine is
the file-backed exactly-once journal (`CTRL-L4-05`, on the live loop, replayed
across a simulated crash in `tests/test_platform.py`). The Temporal backend ships
as an opt-in adapter: `src/maestro/orchestration/temporal_backend.py`
(`TemporalJournal`, `ActionWorkflow`, activities) with graceful degradation when
`temporalio` is absent. `_fetch_workflow_history`/`sync_from_temporal` are
currently cache-only no-ops.

**Gap.** No test runs against a real Temporal server; `TemporalJournal.lookup`,
`record`, `records_for`, `is_complete` operate on an in-memory cache rather
than Temporal event history, so exactly-once/replay/compensation semantics are
unverified in production conditions. Temporal is listed in `NOT_RUN`.

**Effort estimate.** 3-4 weeks (Temporal dev server in CI + client wiring +
replay/compensation integration tests).

**Dependencies.** Item 1 (OS sandbox) for the worker image; Temporal server
(Docker) in CI; no src contract change to the `Journal` interface.

**First concrete step.** Replace the cache-only `_fetch_workflow_history` with a
real `client.get_workflow_handle(...).fetch_history()` call and add an
integration test gated on `TEMPORAL_ADDRESS` env var using `temporalio.testing.WorkflowEnvironment`.

**Acceptance criteria.**
- `TemporalJournal` passes the same exactly-once replay suite as the
  file-backed journal against a live Temporal server.
- Compensation path verified end-to-end (failed activity → compensate_activity).
- CI has a `temporal-integration` lane; absent server → `not_run`, never `passed`.
- `audit_invariants()` reports 0 violations; `NOT_RUN` no longer lists
  `temporal` once the lane is wired.

**Risk.** Network/latency flakiness in CI; mitigation is a deterministic
`WorkflowEnvironment` (time-skipping) for unit-level tests plus a smaller
live-server smoke.

---

## 3. OIDC real-provider interop

**Status:** open (seam)

**Goal.** Verify the JWKS flow against real identity providers (Azure AD, Okta,
Keycloak) so the in-process HMAC bearer can be replaced by SSO in production
without surprises.

**Current state (what ships today).** `maestro.server.oidc` implements
`OIDCProviderConfig`, `JWKSCache`, `OIDCClient` (fetch_jwks, get_signing_key,
validate_id_token, exchange/refresh tokens, userinfo) and `OIDCAuthService`
mapping claims to `Principal`/`Role`. Fixture-tested via
`tests/test_oidc_contract.py` (mock HTTP transport). Zero-trust bearer auth +
RBAC is `verified` on the whole `/api` surface (`CTRL-L4-03`, `CTRL-L4-07`).

**Gap.** No enrolled provider; issuer/audience/JWKS-refresh/rollover behavior
untested against real IdPs. Key rotation, nonce/PKCE, and token expiry edge
cases may differ. OIDC is listed in `NOT_RUN`.

**Effort estimate.** 2-3 weeks (provider test tenants + integration harness +
docs).

**Dependencies.** Test tenants/credentials for each provider (secret management);
item 5 (external signer identities) reuses the same OIDC trust roots.

**First concrete step.** Stand up a local Keycloak (Docker) in CI and port
`tests/test_oidc_contract.py` to run against it with a pinned realm export;
add a documented "provider interop matrix" checklist for Azure AD/Okta.

**Acceptance criteria.**
- Keycloak integration test green in CI (discovery, JWKS fetch, key rollover,
  expired/malformed token rejection).
- Documented manual verification checklist + evidence for Azure AD and Okta.
- `NOT_RUN` drops `oidc_provider` once Keycloak lane is wired; production
  startup rejects missing identity config (E0-06).

**Risk.** Provider-specific claim quirks (groups vs roles); mitigation is an
explicit claim-mapping config with per-provider fixtures.

---

## 4. Postgres RLS live seam

**Status:** open (seam)

**Goal.** Wire the existing migration scripts + pool helpers to a real Postgres
so structural multi-tenant isolation (`CTRL-L4-08`) is enforced by the database
as well as the application.

**Current state (what ships today).** `maestro.memory.postgres_rls` ships full
RLS migration SQL (tables, policies, cross-tenant read function, session
context functions), `PostgresRLSManager` (pool, run_migration, rollback,
set/clear tenant context, prepared statements) and `generate_migration_file`.
App-layer contract (scope isolation + capability) is enforced and tested
independently (`tests/test_tenant_isolation.py`). E1-01/E1-02 in
`ENTERPRISE_TODO.md` scope the DB work.

**Gap.** Migration uses naive `MIGRATION_SQL.split(";")` (breaks on
semicolons in strings/comments); no live DB test; pool reuse/rollback/missing
context unverified. Postgres RLS listed in `NOT_RUN`.

**Effort estimate.** 3-5 weeks (safe migration runner + live DB integration +
transaction-scoped context).

**Dependencies.** Postgres 18 in CI; item 3 (OIDC) for DB-backed identity;
E1 storage package.

**First concrete step.** Replace `split(";")` with a proper statement splitter
(or ship a single migration file executed via `psql`/`psycopg` `execute`),
add `tests/test_postgres_rls.py` gated on `POSTGRES_DSN`.

**Acceptance criteria.**
- Live Postgres integration test: cross-tenant SELECT/INSERT/UPDATE/DELETE
  denied; missing context fails closed; pool reuse does not leak context.
- Migration is idempotent and reversible (rollback tested).
- `NOT_RUN` drops `postgres_rls` once lane is wired.

**Risk.** RLS policy gaps (e.g. `BYPASSRLS` role misconfig) silently bypass
isolation; mitigation is a startup check verifying the app role lacks
`BYPASSRLS` and a documented owner/migration/app role split (E1-01).

---

## 5. External signer identities for the two-person rule

**Status:** open (seam)

**Goal.** Replace the single shared HMAC key in `PolicyRegistry` with per-approver
OIDC/KMS-backed signing keys so the two-person rule's identities are
cryptographically attributable, not just string labels.

**Current state (what ships today).** `CTRL-L6-03` policy bundles are
signed/versioned with a two-person rule (proposer ≠ approver), signature
re-verified at the side-effect boundary, fail-closed on tamper/absence
(`tests/test_policy_bundle.py`, `tests/test_platform.py`). Signing uses one
shared HMAC key (`_load_key`); approvers are string identities. Genesis v1 is
single-authority bootstrap.

**Gap.** A holder of the shared key can forge any approver's signature; no
binding to an external identity or change ticket. Seam documented in
`control_status.json` notes and `TRUTH_AUDIT.md`.

**Effort estimate.** 2-3 weeks (signer abstraction + OIDC/KMS integration +
key rotation).

**Dependencies.** Item 3 (OIDC trust roots); KMS provider decision (AWS KMS /
GCP KMS / local). Builds on the existing `PolicyRegistry` interface (no
two-person invariant change).

**First concrete step.** Introduce a `Signer` protocol in `policy_bundle.py`
(`sign(payload) -> str`, `verify(payload, sig, signer_id)`) with the current
HMAC as `HMACSigner`, plus a `KMS/OIDC` signer stub; thread `signer_id`
through `ActivationRecord`.

**Acceptance criteria.**
- `PolicyRegistry` accepts a signer backend; HMAC path unchanged (backward
  compat).
- External signer path verifies signatures against per-approver public keys.
- Tampered/wrong-signer activation rejected; audit ledger records signer key id
  (never secret).
- Tests cover signer swap and key rotation.

**Risk.** Complexity of key lifecycle (rotation, revocation) may delay; mitigation
is to ship the protocol + HMAC default first, external signer as opt-in.

---

## 6. Cross-family LLM judge via the injection perimeter

**Status:** open (seam)

**Goal.** Add a connector-backed cross-family LLM judge queried only through the
injection perimeter, tightening the HMDC critique gate while keeping the
deterministic guardrail + environmental verifier as the dispositive gate.

**Current state (what ships today).** The operative critique gate is the
guardrail + environmental-verifier pair (`CTRL-L5-08` verified,
`CTRL-L5-06` tested), boundary-enforced before every side effect. The HMDC
engine supports cross-family judges, same-family exclusion, disagreement →
human routing, and verbosity normalization (`tests/test_critique.py`,
`tests/test_critique_gate.py`). The shipped judges are offline lexical
(`RubricJudge`) stand-ins; the judge/embedder are deterministic. External
content enters only via `DualLLMPerimeter` (`tests/test_perimeter.py`).

**Gap.** No connector-backed judge exists; the cross-family judge is a seam.
A connector must be invoked through the injection perimeter (never raw model
output to the privileged path), and its result must remain advisory (a judge
can never override a hard gate).

**Effort estimate.** 3-4 weeks (connector adapter + perimeter wiring +
adversarial tests for judge prompt injection).

**Dependencies.** Item 3 (OIDC for connector auth, optional); connector
registry (`maestro.connectors`); perimeter scan on all judge inputs/outputs.

**First concrete step.** Define a `JudgeConnector` interface in
`maestro.critique` that accepts a candidate + spec, returns a `JudgeScore`,
and routes its prompt through `DualLLMPerimeter.ingest` before sending and
scans the response; ship one connector (e.g. OpenAI-compatible) behind a flag.

**Acceptance criteria.**
- Connector-backed judge runs only via the perimeter; raw model text never
  reaches the privileged path.
- Same-family exclusion still enforced; disagreement routes to human.
- Offline lexical judge remains the default; connector judge is opt-in and
  fails closed (falls back to offline) on error.
- Adversarial test: injected instructions in judge input/output are
  quarantined.

**Risk.** Judge prompt injection / self-preference; mitigation is strict
perimeter scanning, family-tagging of connectors, and keeping the verifier as
the dispositive gate.

---

## 7. CTRL-L1-01 LLM output validator — DONE

**Status:** done (this cycle)

**Goal.** (Completed.) Runtime output policy validator on the model→proposal
path, wired into `AgentPlatform` (default-on); failing outputs quarantined and
audited; adversarially tested on the live loop.

**Current state (what ships today).** `maestro.security.output_validator.OutputValidator`
+ `validate_output` (deterministic, stdlib-only) wired into
`AgentPlatform` at the model→proposal boundary (`src/maestro/platform/agent_platform.py`,
output policy validation step). CTRL-L1-01 moved from `declared` to `tested`
(16 → boundary_enforced controls on the live loop). Tests:
`tests/test_output_validator.py`, `tests/test_platform.py` (output validation
on live loop).

**Gap.** None for v1.0; this item is the completed top of the roadmap.

**Commit ref.** `e4fe2ae` — "v1.1: CTRL-L1-01 LLM output validator (declared -> tested)"
(full hash `e4fe2ae1387696c152543508a5b23e3f6a9119f0`).

**Acceptance criteria.** (met) Injected model outputs are blocked on the live
loop; quarantined + audited; `audit_invariants()` 0 violations; control status
`tested`.

---

## Recommended sequence

1. **Item 7** — already done (CTRL-L1-01).
2. **Item 1 (OS sandbox)** first among open seams: it has no external-provider
   dependency and unblocks real containment evidence; pair with a Linux CI lane.
3. **Item 4 (Postgres RLS)** next: it is the single-DB variant of the already
   enforced structural isolation and removes the biggest "demo vs platform"
   gap; depends only on Postgres in CI.
4. **Item 2 (Temporal)** after sandbox: the worker image + compensation path
   benefit from OS isolation being proven first.
5. **Item 3 (OIDC)** in parallel with item 5: OIDC trust roots are shared.
6. **Item 5 (external signers)** after OIDC trust roots land.
7. **Item 6 (connector judge)** last: it touches the critique gate and the
   injection perimeter; requires perimeter scanning of judge I/O to be in place
   (item 3's connector auth is a nice-to-have, not a blocker).

Rationale: do the seams that need only CI infrastructure (sandbox, RLS) before
the ones that need external identity/KMS (OIDC, signers), and keep the judge
seam last because it is advisory and lowest-risk.

## Definition of done for v1.1

v1.1 is complete when **all** of the following hold:

- Items 1-6 are either shipped with evidence or explicitly re-classified as
  `not_run`/seams with a documented reason (no silent claims).
- Each shipped seam has a passing integration lane (Linux/Postgres/Temporal/
  OIDC) that is not mocked, plus adversarial tests.
- `NOT_RUN` in `src/maestro/scripts/validation_evidence.py` is updated to
  reflect newly covered seams (os_sandbox, temporal, oidc_provider,
  postgres_rls) only where the lane is actually wired.
- `audit_invariants()` reports 0 violations; control status promoted where
  applicable (e.g. CTRL-L3-04 remains `verified`; no control overstates).
- `docs/RELEASE_v1.0.md` "Known limitations" updated (or a new
  `RELEASE_v1.1.md` issued) listing only remaining seams.
- `ruff check src tests` and `mypy src` clean; test suite green.
- Commit history references each seam's evidence (lane + tests).

Until then, v1.0 remains the honest release; v1.1 is an in-progress track,
not a claim.
