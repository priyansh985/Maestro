# MAESTRO development analysis — 24 October 2026

> Follow-up correction, 30 October 2026: the SDK `MemoryPromoteRequest.capability`
> already had a runtime default. The F13 statement that omitting it necessarily
> failed request construction was not established by the static diagnostic.
> E0 makes the default explicit for type checking. The rest of this report is
> retained as evidence about the October 24 snapshot, not the current working tree.

## Assessment

MAESTRO has a substantial, reusable enforcement core and an offline research
reproduction. It is not yet demonstrated as a production agent platform. The
next useful milestone is **a verifiable control plane with one useful workflow**.
Expanding the number of agent types before closing the current integration gaps
would increase the distance between the release claims and actual behavior.

This assessment covers local HEAD `fb1425235417879e1af227e691a3676ccedd68c0`, on
`development`, 28 commits ahead of the local `origin/development` tracking ref.
No remote fetch was performed; that ahead count is not evidence of the current
GitHub state. The checkout had no tracked modifications at audit start, but did
contain untracked histories, logs, and a debug script. They were preserved.
No production code was changed for this analysis.

Scope: source, configuration, packaging, CI, existing plans, repository notes,
release logs, and harmless local runtime probes. No customer deployment, browser
acceptance, real OIDC provider, Postgres server, Temporal server, container runtime,
cloud LLM, or real coding/research external adapter was validated.

## What has actually developed

The July notes in `.remember/recent.md:7-11` describe BP0 followed by authentication
and tenant isolation, at 368–384 tests. October history adds vertical agent
reasoners, hybrid scaffolding, enterprise helpers, fleet APIs, SDK/CLI wiring,
and an adversarial corpus. The October release log `full_suite3.out` records
**636 passed in 214.49 seconds**. This is historical evidence, separate from the
fresh checks recorded in the evidence directory.

The current source contains **107 Python modules, about 19,066 lines**. Its
architecture remains a Python modular monolith; a rewrite or microservice split
has no demonstrated benefit at this stage.

| Area | Evidence in the current project | Assessment |
|---|---|---|
| Paper reproduction | Threat taxonomy, risk scoring, TC1/TC2 runners, synthetic performance model | Useful deterministic research harness; modeled results are not measured network defense efficacy |
| Enforcement core | Typed proposal parser, capability issuer, policy allow-list, risk/confidence, budgets, breaker, kill switch, memory quarantine, ledger | Preserve and harden; strongest part of the project |
| Governance | `security/policy_bundle.py`, negative tests, executor verification | Real in-process governance mechanism; distinct from broken external-signing extension |
| Fleet/API/SDK | Tenant-partitioned platform instances, authenticated REST API, typed HTTP clients | Meaningful application integration, but state is process-scoped and lifecycle semantics are incomplete |
| Coding/research | Intent vocabularies, deterministic reasoners, standalone verifiers | Scaffolding, not complete task-performing agents |
| Hybrid runner | Local enforcement components and mode logic | Simulated control-plane contact and issuance; not a real hybrid deployment |
| Enterprise | OIDC, RLS, signing, DR/export modules | Mixed helpers and unfinished implementations; not a completed enterprise milestone |
| Evaluation | Adversarial tests, HMDC components, release-gate classes | Good building blocks; deployment evaluation itself is simulated |

## Findings and reproducible evidence

Priority means development order and potential impact if the feature is relied
on. It is not a claim of exploitability in a deployed customer system.
`Runtime` means a synthetic local probe reproduced the behavior. `Source` means
the implementation was inspected; the corresponding infrastructure was not run.
The probe and raw output live in `docs/audit/2026-10-24/`.

### F01 — P0: deployment evaluation manufactures success [Runtime]

`src/maestro/security/release_gate.py:160-187` ignores the supplied agent spec and
sets `passed=True`, `score=1.0` for every gate. Registry registration does not
verify the signature or distinct approvers. An explicit bundle-version evaluation
also bypasses the expiry check in `activate`.

Probe: an expired bundle with an invalid signature, the same approver twice, a
mismatched spec, and a required threshold of 2.0 returned `overall_passed=true`.
The out-of-range threshold is deliberate: no range validation exists either.
This does **not** establish a live fleet API bypass; the fleet creation path does
not appear to consume this evaluator at all. Both missing integration and false
success must be fixed before calling evaluation a deployment gate.

Required outcome: evaluations consume real, immutable evidence; absent runners,
invalid thresholds, mismatched digests, expiry, or invalid signatures fail closed.
Simulation must be a separate mode whose result cannot authorize deployment.

### F02 — P1: coding/research agents have incompatible live-loop wiring [Runtime + Source]

`platform/agent_platform.py:139-157,439-498` uses the network-mitigation gate by
default and passes only an evidence graph to the reasoner. It discards the
reasoner's domain metadata when constructing the action. Coding reasoners expect
task/files/test results; research reasoners expect sources/citations/claims.
Neither factory supplies an appropriate domain gate.

Probe: a coding alert proposes `code_read`; research proposes `research_search`.
Both are denied by `mitigation-policy` as inappropriate network mitigations.
The denial is safe but renders the claimed workflow unusable. Standalone reasoner
and verifier tests do not establish that the assembled workflow works.

Moreover, `default_tool_adapters()` at `agent_platform.py:89-136` returns simulated
`ok=True` dictionaries, including “PR opened” and “report synthesized.” The typed
proposal currently has no code patch, bounded command arguments, query/source
identity, or report body. `allowed_paths`/`allowed_sources` are stored on reasoners
without becoming executor-enforced domain constraints. No real PR creation or
source-supported report delivery was demonstrated.

Required outcome: a typed task entry point, bounded arguments carried through the
proposal hash, a domain-specific verifier, a real adapter, and a workflow test
that observes its artifact. Do not fix this by disabling critique.

### F03 — P1: hybrid health and central authorization are simulated [Runtime + Source]

`hybrid/__init__.py:171-222` refreshes the last-contact timestamp without making
an HTTP call; `_refresh_capabilities` signs its own tokens locally. Its PEP is
constructed without the critique gate or policy registry, and its local adapters
are stand-ins. Policy cache, ledger path, and egress-domain configuration do not
provide the claimed live policy/persistence/network boundaries.

Probe: `http://127.0.0.1:1` reports healthy and ONLINE without contacting that
unreachable control plane. Regular simulated health calls can keep ONLINE alive.
No-control-plane startup degrades to OFFLINE_READONLY, despite release language
describing OFFLINE_DENY as default.

The implementation also conflates reversible and read-only. `REVERSIBLE_INTENTS`
includes mutations such as policy/config changes, credential restoration, and
Git reverts. The current hybrid vocabulary happens to exclude many of them, but
`code_test`/`code_lint` can execute arbitrary project code once adapters become real.

Required outcome: actual authenticated contact, centrally verifiable grants,
lease expiry based on last *successful* contact, signed cache verification,
separate read/write/execute/egress classifications, and observed partition tests.

### F04 — P1: the journal does not guarantee exactly-once external effects [Runtime]

`security/sandbox.py:114-152` calls the adapter and only then writes the outcome.
`orchestration/journal.py:72-87` has no atomic claim, process lock, or fsync
contract. A crash after the effect but before the append leaves nothing to replay.
The operation key is not bound to a proposal digest in the journal replay path.
Concurrent callers can also observe an absent key before either writes it.

Probe: an adapter increments a synthetic counter and raises `SystemExit` before
journaling. Reopening the journal and retrying the same key increments it again:
**two effects**. This simulates the critical ordering window; it is not a real
power-loss durability test. Existing tests demonstrate replay of a recorded
result, a narrower guarantee.

Required outcome: durable operation states, digest-bound keys, atomic claims,
adapter/provider deduplication or reconciliation, and an explicit UNKNOWN result
when completion cannot be established. Temporal alone does not remove this
window; its official documentation also requires idempotent activities [S1].

### F05 — P1: external-signing extension lacks an independent trust root [Runtime + Source]

`security/policy_bundle_signed.py:62-88` trusts the HMAC key supplied in each
signature's `public_key`, and counts signature entries rather than distinct
verified signers. Serialization emits that HMAC secret. `PolicySigner.sign`
calls nonexistent `PolicyBundle.content_hash()`; the actual method is `digest()`.
Cosign/Notary helpers also refer to nonexistent `to_dict()` on the core bundle.
The subclass constructor/register/activate contracts do not match the core
`PolicyRegistry` API and must be reconciled before use.

Probe: two copies of one self-supplied signature satisfy a two-signature check;
the serialized object contains its HMAC key. Calling `PolicySigner.sign` raises
`AttributeError`. The release validator bypasses that signer by manually creating
a signature, so its check does not catch the defect.

This finding concerns the BP12 extension. It does not invalidate the separate
core `policy_bundle.py` HMAC registry and its proposer/approver checks.

### F06 — P1: backup verification and restoration are unfinished [Runtime + Source]

`dr/disaster_recovery.py:186-253` parses the archive but skips event verification;
restore constructs an empty ledger and skips replay. Remote replication is a
placeholder at lines 181-184. The runbooks call unimplemented/unpackaged commands.

Probe: backing up one ledger event restores **zero events**. Altering an event in
the archive still returns `verify_backup=true`. No RPO/RTO claim follows from
these helpers or their dry-run output.

Required outcome: verify every event/hash/HMAC and expected head/count using a
trusted manifest; reject corruption and truncation; restore an identical ledger
into a separate target; validate startup/replay before any failover is enabled.

### F07 — P1: API retry can duplicate a mutation [Runtime + Source]

`sdk/http_client.py:202-270` retries POST and other mutations after a read timeout
or server error without a stable operation ID agreed with the server. A server
may have committed before the response was lost.

Probe uses `httpx.MockTransport`: first POST performs a synthetic effect then
raises `ReadTimeout`; retry performs the effect again. This proves client resend
behavior, not that every endpoint necessarily duplicates. Fleet creation without
an explicit agent ID is a concrete risky caller. Until a server deduplication
contract exists, ambiguous mutations must surface UNKNOWN rather than retry.

### F08 — P1: tenant containment does not govern future agent creation [Runtime + Source]

`control_api.py:523-542` halts the plane and current agents, records `_ISOLATED`,
but the fleet creation path (`agents_api.py:90-110`) and registry do not check
that flag. New agents start with fresh unhalted PEPs. Isolation is an incident
containment action here, separate from ordinary cross-tenant data isolation.
Existing resume behavior is explicitly operator-authorized; that is not itself
called a bypass. The missing rule is what creation/reset/resume must do while a
tenant-level containment condition remains active.

Probe through an isolated FastAPI TestClient: after an admin contains a tenant,
that tenant's operator creates a new generic agent (201). Its alert returns 200
with `allowed=true` while the tenant's isolation flag remains set. The adapter
effect is simulated; the result proves the admission/execution guard gap, not an
external harmful action. No shared/live server or customer state was touched.

Required outcome: define tenant containment as a persisted admission/execution
condition, with an explicit release transition and audit. Test agents created
after containment and process restart, not just agents that already existed.

### F09 — P1 before activation: Postgres RLS helpers are not deployment-ready [Source]

`memory/postgres_rls.py:260-321` splits migration SQL at every semicolon,
including inside PL/pgSQL bodies, and drops chunks beginning with SQL comments.
This cannot safely execute the supplied script. Tenant context is committed on a
borrowed pooled connection that is returned before the actual query; the next
operation need not acquire the same connection. `set_config(..., FALSE)` is
session-scoped. The cross-tenant helper returns a boolean flag without checking
the target argument; its default ALL policy can broaden writes as well as reads.
Agent context is set but not used by the policies.

Required outcome: transactional migrations, same-connection transaction-local
scope, constrained SELECT-only cross-tenant access, application role without
ownership/BYPASSRLS, pool reuse/rollback tests, and a real database integration
lane. PostgreSQL combines permissive policies with OR and normally exempts table
owners; FORCE RLS does not constrain superusers/BYPASSRLS [S2]. No live database
exploit or migration run was performed in this audit.

### F10 — P2: citation verification is lexical support, not entailment [Runtime]

`domains/verifiers.py:124-147` accepts any bracket marker and measures overlap
against the union of source words. It does not resolve a source ID or bind each
claim to a passage, and cannot reliably distinguish negation.

Synthetic probe: “The treatment is safe [invented-source]” against source
“The treatment is not safe” returns verified with 1.00 grounding. This is an
algorithmic counterexample, not medical guidance or a live source assessment.
Promote it as a lexical heuristic only. A real research workflow needs source IDs,
quoted spans, claim-level checks, contradictory-source cases, and abstention.

### F11 — P2: timeout denial does not bound caller latency [Runtime + Source]

`sandbox.py:156-169` raises a timeout inside `with ThreadPoolExecutor(...)`, whose
exit waits for the worker. A nominal 0.01-second timeout with a 0.15-second
adapter returned only after the worker completed (elapsed varies with host load).
The code already states that threads cannot be force-killed, but also claims to
bound the caller's wait. That claim is incorrect for this implementation.
Use a killable worker/container for arbitrary execution. Never treat a returned
denial as proof that a previously-started effect did not occur.

### F12 — P2: external sandbox mode lacks a runnable adapter/image contract [Source]

`sandbox.py:171-269` serializes adapter module/name, but default adapters are nested
closures and cannot be imported as module attributes. The default image is plain
`python:3.11-slim`, with no installation of MAESTRO. The runsc command is shaped
like Docker instead of an OCI bundle invocation. Prefer one documented runtime
contract: a prepared image and Docker with `--runtime=runsc` after configuring that
runtime, or a proper OCI bundle path [S3]. Validate confinement on Linux; mocked
subprocess tests establish command handling only.

### F13 — P2: CLI and packaging overstate lifecycle coverage [Source]

`cli.py:328-353`: policy diff returns layers/state; promote delegates to validation;
rollback returns current state. `PolicyClient` exposes validation, controls and
layers, not proposal/approval/activation/rollback. The core registry does have a
governance mechanism, so surface that mechanism rather than invent another.

`pyproject.toml` declares five console scripts, omitting the documented `maestro`,
`maestro-v1-validate`, hybrid, compliance, and DR executable names. Some are runnable
as modules, but that does not make their advertised console commands installed.
OIDC imports `jose`; no corresponding optional dependency group is declared.
The current environment has no `jose`, `psycopg_pool`, or `temporalio` package.
The July lockfile predates the current manifest; lock/install consistency needs
a clean-wheel check. This audit did not regenerate the lock or install packages.
The real CLI also reports version `0.9.0` at `cli.py:514`, versus manifest 1.0.0.
`sdk/client.py:212,216` constructs `MemoryPromoteRequest` without its required
`capability`; high-level promotion therefore cannot currently satisfy that
request schema. A working low-level HTTP client does not prove this helper works.

### F14 — P2: control panel cannot authenticate its own API calls [Source]

`server/control_panel.py:94-98` sends fetches without Authorization and does not
check HTTP success before rendering. Default API auth is enforced. The main
dashboard/playground have token handling, so the panels have diverged. A 401 body
can reach render code expecting state fields. Reuse an authenticated request
helper and show 401/403/offline/error states; verify in a browser before claiming
the operator panel works. `/ws` currently sends public synthetic heartbeat data;
it is not a tenant-aware audit-event stream. Authenticate and partition it before
ever attaching sensitive events.

### F15 — P2: validation process allows claims to drift [Source + historical evidence]

`scripts/validate_v1.py:37-65` excludes adversarial, auth, tenant, API and connector
suites. It reruns overlapping subsets and checks a newly defined fake CLI parser
instead of the real parser. It omits lint/mypy and does not establish production
infrastructure behavior. CI runs full pytest/lint/mypy separately, but does not
run this release validator as a release gate or install enterprise extras.

`TRUTH_AUDIT.md` still reports 85 modules, 33 endpoints, and 446 tests; machine
inventory and October history are newer. README still reports 361 tests,
optional auth, and reversible-only default capabilities, while the current
default vocabulary includes irreversible intents. `IMPLEMENTATION_PLAN.md`
marks BP11/BP12 complete while their own checklist contains unfinished items.
`audit_invariants()` checks metadata consistency; it cannot establish that the
behavior claimed by a metadata row was exercised. Keep it, but add evidence
bindings and integration gates.

Fresh `.venv\Scripts\python.exe -m ruff check src tests --output-format concise`
passed. Fresh `.venv\Scripts\python.exe -m mypy src` failed with **41 errors in
8 files (107 source files checked)**. These include real interface errors in
signing, DR, compliance, OIDC and SDK helpers; they are not solely annotation
style issues. Fresh `.venv\Scripts\python.exe -m pytest -q` completed with
**636 passed in 1408.14 seconds (23:28)**. The slower local elapsed time is not a
controlled performance measurement. These passing tests coexist with the probe
failures above: the missing cases are acceptance-coverage gaps, not evidence
that the observed behavior is safe. Raw probe results and check summaries are
indexed in `docs/audit/2026-10-24/README.md`.

### F16 — P1 before activation: identity and populated export paths have schema drift [Source]

`server/oidc.py:318` uses a hardcoded session HMAC key. At lines 348-354 the
claim mapper constructs `Principal` with unsupported `email`, `username`, and
`groups` arguments. The OIDC module is not wired into `create_app`'s bearer
authentication path, and its undeclared `jose` dependency is absent here. It is
not enough to configure an issuer and describe this as working SSO. Fix the
mapping, configure a protected session trust root, bind sessions into the API
boundary, then verify a real provider's discovery, issuer/audience, key rotation,
revocation and role/tenant mapping. No live token forgery was attempted.

`compliance/export.py:119` reads `AuditEvent.timestamp`, whereas the actual field
is `timestamp_utc`. The existing release-validator export uses an empty ledger,
so it avoids this populated path. DR replication similarly expects `AuditEvent.seq`
that the core event does not supply. Mypy identifies both mismatches. Any evidence
pack/replication feature needs a nonempty, realistic event fixture and round-trip
tests, not an empty-object smoke check.

## Architectural implications

1. **A denial can be correct and the product can still be unusable.** Track
   allowed-task completion and false refusals alongside attack blocking. The
   vertical-gate mismatch is a concrete example.
2. **A verified result needs an artifact identity.** Bind approval, policy,
   task arguments, evidence, verifier version, and executor result to digests.
   A caller-provided “tests passed” flag is not independent verification.
3. **Execution uncertainty needs its own state.** `DENIED` is not sufficient
   after an effect may have started. Model UNKNOWN, reconcile, and prevent
   blind retry. The SDK, sandbox, journal, and recovery code share this need.
4. **Read-only, reversible, and safe-to-execute are different axes.** Maintain
   one effect declaration per adapter and derive offline policy from that.
5. **Evidence is the product differentiator.** Decision cards, bounded authority,
   provenance, and replayable policy checks are more defensible than adding more
   autonomous agent labels. Demand for them remains a hypothesis to validate.

## Recommended direction and scope decisions

These are audit recommendations, not user-approved product commitments.

| Option | Benefit | Cost / limitation | Recommendation |
|---|---|---|---|
| Verified SOC review workflow | Reuses the existing reasoner, alert model, network verifier and reproduction harness | Still needs a real bounded integration and independent usefulness measurements | First end-to-end pilot candidate |
| Secure coding workflow | Clear artifact: tested patch / draft PR | Requires typed task state, real repo adapter, OS isolation and verifier binding | Second, after core guarantees are corrected; start with local patch artifact |
| Research reports | Read-only fetch can be bounded | Citation entailment and quarantine/usefulness tension are unresolved | Separate evaluation track before product commitment |
| General multi-agent/enterprise platform expansion | Broad demo surface | Multiplies unverified boundaries and operations | Defer until one workflow meets acceptance gates |

The accompanying roadmap orders fixes and defines new features with acceptance
conditions. The focused implementation plan covers the first verification
milestone. Infrastructure and vertical milestones remain conditional on that
baseline and on selecting a concrete user workflow.

## Development process to adopt

Keep one evidence row per feature: intended behavior, actual entry point,
protected boundary, positive workflow test, negative/bypass test, external
integration evidence, source digest, and known limits. A subsystem can be
implemented but unintegrated, integrated but simulated, or externally verified;
one overall “complete” flag obscures those differences. Track demo completion
separately from deployment readiness.

For each behavior change, use the smallest relevant patch and a regression that
fails for the observed reason. Require both a legitimate task succeeding and a
forbidden task being denied; a test asserting only that an `EnforcementResult`
exists is not a workflow acceptance test. Mypy failures exposing real contract
breaks belong on the blocking defect list. Avoid broad refactors while fixing
these interfaces.

Use three named validation lanes:

1. **Offline checks:** deterministic tests, auth/tenant/adversarial cases,
   lint/types, real CLI/API/SDK contracts. Always run; failure stays failure.
2. **External integration checks:** one pinned Postgres/OIDC/container/Temporal
   profile at a time; publish service/runtime versions, setup and actual negative
   tests. A skipped required service is not a passed profile.
3. **Pilot evaluation:** independently scored useful tasks, false refusals,
   unauthorized effects, latency/cost and recovery. Keep attack and benign
   denominators and held-out data; lexical/model fixtures are not empirical
   proof against arbitrary live prompt injection.

Every release candidate should name its exact source and packaging hashes,
installation method, supported profiles, and evidence directories. Test a built
wheel in a clean environment: advertised scripts, config/HTML resources and
extras must work outside the checkout. Preserve test output with the candidate;
a prior green log is not a current result. Bind audit claims to those artifacts
instead of regenerating prose that implies it is live evidence.

Review the next fixes in this order: false evaluation success; operation/retry
ambiguity and backup truth; containment and signing; vertical task correctness;
UI/policy lifecycle; selected deployment profile. Gate external adapters on the
specific safeguards they require. Use small commits/PRs whose scope and tests a
reviewer can reject independently. These process changes reuse the existing
test suite and audit taxonomy rather than replacing them.

## Questions left for later verification

- Default fleet, memory and policy state is process-local; agent deletion removes
  its platform/history. Define retention, tombstones and restart behavior before
  promising an audit system of record.
- Shared auth/router singleton state and in-memory counters need concurrent,
  multi-worker tests before scaling the server beyond one process.
- The alert key rounds timestamps to whole seconds (`agent_platform.py:447`).
  Evaluate collisions for distinct same-class alerts in the same second before
  using it as a production event identity.
- API budgets and configured tenant quotas need observed enforcement tests,
  including concurrent creation/execution and expired capability renewal.
- Real prompt-injection efficacy, provider drift, useful-task completion,
  performance under load, browser UX and infrastructure reliability remain
  unmeasured. This audit establishes concrete defects and a roadmap, not those
  empirical results.

## Sources checked on 24 October 2026

- **S1 — Temporal activity definition and idempotency:**
  https://docs.temporal.io/activity-definition — completed-result replay does
  not eliminate retries after an unreported effect; deduplication must be enforced
  by the downstream operation. Supports F04/F07's proposed contract.
- **S2 — PostgreSQL row security:**
  https://www.postgresql.org/docs/18/ddl-rowsecurity.html — role exceptions,
  policy combination and write checks. Supports F09's integration requirements.
- **S3 — gVisor Docker quick start:**
  https://gvisor.dev/docs/user_guide/quick_start/docker/ — configured Docker
  runtime invocation. Supports F12's proposed runtime path, not a claim that it
  was run here.
- **S4 — OWASP excessive agency:**
  https://genai.owasp.org/llmrisk/llm062025-excessive-agency/?lang=us — independent
  permission boundaries and constrained functionality support the selected
  design direction. This is guidance, not certification of this project.
