# MAESTRO enterprise development to-do

Updated: **30 October 2026**. Goal chosen by the user: an enterprise-ready system;
engineering choices delegated. **E0 implementation is in progress; E1–E4 remain
planned.** Each unchecked item requires code and passing evidence. See the
[dated E0 status](audit/2026-10-30-e0-status.md) for verification limits.

Start with **E0**, then durable state **E1**. Do not claim enterprise readiness
until the named deployment profile passes **E0–E4**.

Read the [research](research/2026-10-30-enterprise-readiness-research.md),
[enterprise design](superpowers/specs/2026-10-30-enterprise-readiness-design.md),
and [existing M0 implementation plan](superpowers/plans/2026-10-24-maestro-verification-baseline.md).
The corrections below take precedence over that older plan. Preserve the
[October 24 audit](audit/2026-10-24-development-analysis.md) as historical evidence.

## What the next development phase should produce

**E0 deliverable:** one honest validation command, a supported clean build,
repaired public interfaces, and a release path that cannot turn missing or
simulated evidence into production approval. E0 alone is not an enterprise release.

| Order | Work item | Done when | Scope / evidence |
|---|---|---|---|
| 1 | Stop false production approval | Missing/expired/tampered/spec-mismatched evidence and simulated results cannot pass production admission | `security/release_gate.py`, focused negative tests; preserve a clearly separated offline simulation mode |
| 2 | Replace the misleading release validator | One full offline suite, actual CLI, lint/types and input/log hashes; failure propagates; required integration lanes are explicit | `scripts/validate_v1.py`, proposed `validation_evidence.py`, `tests/test_validation_runner.py`, CI artifact |
| 3 | Repair type and interface mismatches | Full mypy passes without blanket ignores; real populated export, SDK promotion, policy signer and identity mapping tests pass | Eight files listed in October audit; fresh failing-case regressions with each repair |
| 4 | Establish supported runtime/dependencies | Python 3.12/3.13 clean installs/tests pass; 3.13 deployment image is pinned; unsupported 3.10 claim removed | Manifest, lock, CI, Dockerfile, documented compatibility change |
| 5 | Verify wheel/image installation | Advertised scripts and packaged HTML/config work from outside checkout; no editable install needed | Wheel/image digests, fresh environment smoke test, production image without dev/test tooling |
| 6 | Add production startup checks and accurate status | Missing required identity/storage/keys or a simulated required adapter prevents startup/readiness | Production configuration validation; historical release corrections; no bypass flag in production profile |

Steps 1–3 establish trust in the checks; step 4 is the explicit runtime migration.
Keep each repair small. Do not install every optional service merely to hide an
import/type error. Unsupported enterprise features remain disabled until their
integration checks pass.

## E0 — Verification and supported build

- [x] **E0-01: Make production release evaluation fail closed.** Repair or disable
  the current unconditional-success evaluator. Cover missing runners, invalid
  thresholds, expiry, spec/evidence digest mismatch, changed source, invalid
  signature and duplicated approvers. Production cannot consume simulation
  output. Full signer/governance integration is completed in E1/E2.
- [ ] **E0-02: Implement the offline evidence runner.** Use the October M0 plan,
  corrected to compare the **eight named** unassessed integration entries rather
  than its erroneous count of nine. No ignored offline adversarial/auth/tenant
  suites, fake CLI parser, duplicate pytest subsets or unconditional release-ready
  banner. Save failures/timeouts/logs and continue collecting later checks.
- [ ] **E0-03: Resolve the 41-error historical mypy baseline.** Reproduce before
  editing; fix real model/API mismatches in signing, DR, compliance, OIDC, SDK,
  fleet/CLI/control code. Add a nonempty ledger export and exact required SDK
  request-field regressions. Do not suppress errors by weakening type settings.
- [ ] **E0-04: Migrate runtime support deliberately.** Target Python 3.13 for the
  enterprise image; supported package floor 3.12 with 3.12/3.13 CI. Resolve
  dependency/wheel compatibility, refresh the lock and record patch versions.
  Treat older compatibility removal as a documented package/release change.
- [ ] **E0-05: Fix installable artifacts.** Complete console entry points,
  package HTML/default configuration, declare real optional enterprise extras,
  and install the built wheel in a clean directory/environment. Build a pinned
  non-root runtime image without editable mode or development dependencies.
- [ ] **E0-06: Establish a production configuration boundary.** Production
  rejects absent durable state, required trust roots, identity config and
  simulated execution/gates; local reproduction stays explicitly separate.
  Test environment/profile misconfiguration and redact diagnostics.
- [ ] **E0-07: Consolidate CI evidence.** Publish check manifests/logs on failures;
  run supported Python matrix and Windows/POSIX runner-contract tests. Keep
  deterministic reproduction separate. Use least-privilege jobs and reviewed
  Action SHAs. Existing tests/probes are included in the acceptance inventory.
- [ ] **E0-08: Reconcile status and review the phase.** Update README/release/status
  claims with dated corrections, rerun full source/test/type checks and probes,
  review the diff independently, and record disabled versus supported features.

**E0 exit:** required offline/build checks pass; known unsafe enterprise functions
are repaired or unavailable in production. No OIDC/RLS/DR/vertical claim is green
merely because its module imports. Then plan E1 against the proven artifact.

## E1 — Durable tenant authority and execution integrity

- [ ] **E1-01: Introduce real database migrations and stores.** PostgreSQL 18;
  separate owner/migration/application roles; transaction-scoped tenant/agent
  context; durable tenant, agent, memory, policy, approval, operation and ledger
  models. Extend `memory/postgres_rls.py` by replacing unsafe script splitting,
  and add a focused `storage/` package. Preserve offline in-memory mode only as
  an explicit research/test profile.
- [ ] **E1-02: Prove RLS and pool behavior.** Test cross-tenant SELECT/INSERT/
  UPDATE/DELETE/export, agent scope, missing context, pool reuse, rollback and
  owner/BYPASSRLS misconfiguration using a real database. No agent receives DB
  credentials; cross-tenant admin access is explicit, scoped and audited.
- [ ] **E1-03: Persist tenant lifecycle and quotas.** ACTIVE/CONTAINED/DISABLED
  state gates create/reset/resume/approve/issue/execute paths. Containment must
  survive restart and stop new authority, with explicit audited release.
  Enforce tenant agent/operation limits atomically and test concurrent requests.
- [ ] **E1-04: Add digest-bound operation claims and receipts.** Unique operation
  ID + tenant/actor/proposal/policy binding, atomic claims, RUNNING/UNKNOWN state,
  and recorded observation. Same ID with changed content conflicts. Test API/
  worker crashes before dispatch, after effect and before receipt, and a
  two-worker race. Leases alone must not trigger blind resend.
- [ ] **E1-05: Repair SDK retry and approvals.** Safe read retries can remain;
  mutation retries require the server's durable operation contract. Persist
  approval identity/digest/expiry/consumption. Stale or cross-tenant approval
  cannot authorize execution. Unknown results require reconciliation first.
- [ ] **E1-06: Unify governed policy lifecycle.** API/SDK/CLI propose, diff,
  approve, activate and approved rollback operate on the core registry concept;
  no placeholder “promote=validate.” Separate authenticated approvals from
  signing. Unknown keys, repeated signers and changed digests fail closed.

**E1 exit:** restart/race/partition cases preserve authority and uncertainty;
the original containment, duplicate-effect and self-trust counterexamples have
regressions proving the chosen production behavior.

## E2 — Identity, secrets and the real worker boundary

- [ ] **E2-01: Replace custom OIDC protocol handling.** Authlib + maintained JOSE
  implementation; enrolled discovery, state/nonce/S256 PKCE, explicit issuer/API
  audience, JWKS refresh and access-token policy. Exercise a pinned Keycloak
  fixture, including verifier omission, key rollover and malformed/expired tokens.
- [ ] **E2-02: Add durable sessions and service accounts.** Opaque protected
  browser cookie, server-side encrypted provider tokens, CSRF checks, enforced
  role/tenant membership, logout/session revocation and privileged MFA policy.
  Separate scoped/revocable API credentials; document and test revocation bounds.
- [ ] **E2-03: Isolate the execution worker.** Replace closure/module-name
  serialization with a fixed adapter registry/image contract. Use a Linux
  worker and killable guest process with resource/output/time/egress limits;
  deny host paths, metadata access and secrets outside its scoped contract.
  Prove containment on Linux; mocked subprocess results do not satisfy this item.
- [ ] **E2-04: Establish secret/key lifecycle.** Separate token, capability,
  ledger and artifact-signing trust domains; key IDs/rotation/revocation and a
  recoverable protected key store. No hardcoded key or serialized HMAC secret.
  Record historical verifier trust and safe expiry behavior.
- [ ] **E2-05: Sign the actual release artifacts.** Generate wheel/image SBOMs,
  scan and triage dependencies/images, bind test evidence to artifact digests,
  verify with a configured Cosign trust key, and separate untrusted tests from
  release credentials. Customer KMS/keyless profiles are separate integration
  claims until exercised.

**E2 exit:** named identity/runtime/trust profiles pass real integration and
negative tests; production startup cannot quietly fall back to a stub.

## E3 — Recovery, retention and operator workflows

- [ ] **E3-01: Repair archive verification and restoration.** Verify nonempty
  event hashes/HMACs/head/count and reject tampering/truncation. Restore real
  records; map canonical event fields correctly in replication/compliance code.
  An empty or parsed archive cannot be labeled a verified restore.
- [ ] **E3-02: Deliver clean-target PITR and key recovery.** Base backup + WAL,
  aligned evidence-object manifest, encryption and separate key procedure.
  Restore all authority/operation state. Enter contained recovery under a new
  epoch, invalidate old approvals/leases and reconcile external effects before
  release. Test the proposed ≤15-minute RPO/≤60-minute RTO on a named dataset.
- [ ] **E3-03: Protect audit continuity and retention.** Append-only app
  privileges, transactional ordering, externally retained signed checkpoints,
  agent tombstones, 90-day metadata/30-day payload defaults, configurable holds
  and audited purging. Verify exported evidence independently and redact secrets.
- [ ] **E3-04: Implement the authenticated operator journey.** Shared UI auth/error
  handling, fleet/tenant state, approval inbox, policy diffs/shadow replay,
  receipt/UNKNOWN inspection and recovery status. Protect tenant-scoped WS and
  exports. Verify viewer/operator/admin and expired-session flows in a browser.
- [ ] **E3-05: Add actionable operations.** Separate liveness/readiness, bounded
  queues/backpressure, per-tenant limits, redacted structured logs and metrics;
  alert on dependency failure, ledger/signature failure, UNKNOWN backlog, backup
  lag and quota exhaustion. Add restore, containment, rotation and upgrade runbooks.

**E3 exit:** recovery is measured, the operator can explain and resolve uncertainty,
and persisted authority survives a failure without replaying stale work.

## E4 — Supported workflow and release-candidate evaluation

- [ ] **E4-01: Complete one real SOC workflow.** Alert → bounded proposal →
  authenticated approval → time-bounded collector rate configuration → independent
  observed effect/priority-event preservation → expiry/recovery → receipt. No
  simulated `ok=True` artifact can satisfy its success criterion.
- [ ] **E4-02: Measure useful and adversarial behavior.** Versioned 30 benign +
  30 adversarial cases, held-out evaluation, ≥90% benign completion target and
  no unauthorized effect in that corpus; report denominators and limitations.
- [ ] **E4-03: Run reference load/failure tests.** 10 tenants/100 agents/20
  clients/10 submissions per second for 30 minutes; target p95 acknowledgement
  ≤1 second with durable writes. Test worker/API/DB loss, response loss, disk-full,
  stale worker and rolling restart. Record hardware and actual performance.
- [ ] **E4-04: Rehearse upgrade and assess security.** Fresh and upgraded installs,
  migration failure/rollback contract, retained data/evidence/key verification,
  ASVS 5.0.0 Level 2 applicability mapping and independent review. Fix or explicitly
  exclude unresolved release blockers; no certification claim follows from a checklist.
- [ ] **E4-05: Publish the supported release profile and bounded pilot result.**
  Artifact digests, named versions, limitations, recovery measurements, runbooks,
  pilot observations and support/incident owner. Broader provider/platform
  compatibility is added only with additional evidence.

## Deliberately later

Hybrid execution, Kubernetes/HA, Temporal, broad ADK/framework integrations,
arbitrary coding/PR automation, advanced research agents, SCIM/SAML and additional
cloud/KMS profiles follow demonstrated demand and separate designs. None is
required to begin E0, and none is implicitly covered by the first profile.

## Research completed in this discussion

- [x] Reconcile checkout/history against the previous audit and compare all 182 input hashes.
- [x] Refresh the 12 synthetic boundary probes; retain their raw evidence.
- [x] Check primary documentation for runtime lifecycle, OAuth/OIDC, RLS,
  transaction scope, idempotency, signatures, worker isolation and recovery.
- [x] Select the enterprise reference profile and sequence work by actual dependencies.
- [x] Write this ordered backlog and enterprise design; obtain a builder clarity review.

**Continuation point:** implement E0 as small reviewed changes. Adapt the existing
M0 plan to the enterprise runtime policy and the eight-entry correction first;
do not begin E1–E4 in the same unchecked change set.
