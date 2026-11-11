# Enterprise readiness research — 30 October 2026

## Decision and evidence scope

The user selected **enterprise readiness** as the target and delegated engineering
choices. This round remains research, discussion and a to-do list; implementation
comes next. The selected target is a **self-hosted Linux reference deployment**
for one organization with isolated tenants and one bounded SOC workflow.

Current HEAD remains `fb1425235417879e1af227e691a3676ccedd68c0`. All **182**
source/config/test/packaging/CI hashes match the October 24 audit. A fresh run of
the existing **12 synthetic probes** completed with exit 0 and reproduced the
reported defects. Exit 0 means evidence collection completed, not that the
counterexamples are safe. See [fresh evidence](2026-10-30-enterprise/).

The 636-pass pytest run, Ruff pass and 41 mypy errors are **October 24 results**.
They were read from saved artifacts, not rerun as full checks today. Source
equality supports reusing the findings; it does not establish current dependency,
infrastructure or runtime readiness. No packages or services were installed.

## Research conclusions and engineering choices

### R1. Refresh runtime support before promising a new enterprise installation

Python's official status table lists 3.10 as end-of-life since October 1, 2026.
The project still targets it in its manifest, lint/types and CI. **Choice:** use
Python 3.13 for the enterprise image, test package compatibility on 3.12/3.13,
and move the supported package floor to 3.12 in an explicit compatibility change.
Freeze exact interpreter, dependencies and image digests after clean-install tests.
Do not describe 3.10 as a supported enterprise runtime. This corrects the runtime
policy in the October 24 plan; it was not an adequate enterprise baseline.
[Python version status](https://devguide.python.org/versions/)

### R2. Use PostgreSQL as the durable source of truth early

The existing journal, fleets, tenant containment and approval state cannot supply
a reliable shared execution contract while they remain process-local. **Choice:**
PostgreSQL 18 with a current supported minor and a pinned deployment digest;
separate migration and application roles. Persist agents, tenant state, policies,
approvals, operation claims, audit events and memory in one transactional boundary.
No Redis or Temporal service is required for the first reference profile.
PostgreSQL recommends current minor releases within a supported major.
[Versioning policy](https://www.postgresql.org/support/versioning/)

RLS is defense in depth against missing application scope filters. It is not a
boundary against a database administrator, an app-role holder issuing arbitrary
SQL, or an agent given database credentials. Use a non-owner/non-BYPASSRLS app
role; query inside the same transaction that establishes tenant context. Local
context ends at transaction completion; ordinary session context can outlive it.
Default policies must cover both tenant and agent scope where required, and
cross-tenant privileges must not be a caller-controlled boolean. These choices
follow the actual PostgreSQL policy and context semantics.
[RLS](https://www.postgresql.org/docs/18/ddl-rowsecurity.html),
[SET LOCAL](https://www.postgresql.org/docs/18/sql-set.html)

### R3. Treat ambiguous execution as a first-class result

Even Temporal may execute an activity again if an effect happens before completion
is reported. **Choice:** implement a durable operation record, atomic claim and
adapter reconciliation before considering a larger workflow engine. Use a stable
operation key bound to tenant, actor, proposal arguments and policy digest. If a
worker dies after sending a request, hold the operation as UNKNOWN until the
adapter establishes the outcome. Do not equate an expired worker lease with proof
that its external action did not happen. A downstream idempotency contract or a
read-back reconciler is required before retrying an ambiguous mutation.
[Temporal activity semantics](https://docs.temporal.io/activity-definition)

### R4. Replace the custom login protocol with a maintained integration

The code at `server/oidc.py:194-202` does not submit `code_verifier`, even though
authorization URL generation accepts a PKCE challenge at lines 278-293. It also
guesses provider URLs and treats API access-token validation like ID-token
validation. **Choice:** Authlib for the web OAuth/OIDC flow, with discovered
provider metadata, state/nonce/S256 PKCE, and an explicit resource-server access
token policy. Use the current supported JOSE component rather than extending the
broken helper. Authlib's current project separates JOSE work into `joserfc`.
[Authlib](https://authlib.org/),
[web clients](https://docs.authlib.org/en/latest/oauth2/client/web/)

Human login uses Authorization Code + S256 PKCE. CLI/service identities use a
separate enrolled service-account flow, not copied browser cookies. Validate the
resource audience and configured issuer; derive tenant membership from server
configuration plus validated identity, never an untrusted UI field. Use discovery
metadata rather than invented endpoint paths. These are standards-driven
requirements, not proof that any provider interoperation has been tested here.
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

### R5. Separate authorization approval from artifact signing

Two approvals must be two authenticated subjects, tied to a content digest and
expiry. A valid signature on arbitrary bytes does not establish that two humans
approved those bytes. **Choice:** preserve the core policy registry's governance
concept, persist approvals, and verify release artifacts with Cosign against a
configured public key/trust policy. Never accept a key shipped by the untrusted
artifact as its own trust root. A future keyless profile must constrain issuer
and certificate identity. Start with one pinned key-based profile for self-hosting;
adding cloud KMS or offline keyless verification is separate compatibility work.
[Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/)

### R6. Scope worker isolation to a testable deployment profile

Rootless Docker reduces daemon/runtime privilege; seccomp restricts syscalls but
does not prove arbitrary code is safe. **Choice:** a separate execution worker,
non-root guest, read-only base filesystem, bounded writable workspace, no privilege
escalation, resource/time/output limits and deny-by-default egress. The API must
not expose a Docker socket to agents or execute arbitrary tool code in-process.
Use this for allow-listed first-party SOC adapters initially. Arbitrary coding
workloads require stronger isolation evaluation before inclusion; Docker-only
success is not an arbitrary-code containment guarantee.
[Rootless Docker](https://docs.docker.com/engine/security/rootless/),
[seccomp](https://docs.docker.com/engine/security/seccomp/)

### R7. Design recovery around persisted application state

The current backup helper restores an empty ledger. Repairing that helper is a
near-term regression task, but enterprise recovery must restore tenants,
containment, pending operations, approvals, policy lineage, memory and evidence
artifacts as well. **Choice:** use PostgreSQL base backups plus archived WAL for
PITR, protected artifact storage, and a separate key recovery procedure. A logical
dump can be a useful export but cannot substitute for a WAL-based PITR chain.
Require a clean-target recovery drill and independent ledger/head checks before
declaring recovery targets achieved.
[PostgreSQL PITR](https://www.postgresql.org/docs/18/continuous-archiving.html)

### R8. Release evidence needs a secure delivery pipeline

**Choice:** build the wheel and runtime image in CI, install the wheel outside
the checkout, generate an SBOM, scan dependencies/images, record artifact digests,
then sign only artifacts whose required checks passed. Separate untrusted PR
tests from privileged release signing; pin external Actions to reviewed commit
SHAs and grant minimal job permissions. A signature proves provenance under a
trust policy, not security correctness. Scan findings need a triage/expiry
process rather than a claim that a scan makes the image secure.
[GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)

### R9. Define enterprise readiness as evidence across several dimensions

Security alone omits installation, recovery, usability and operational ownership.
**Choice:** assess identity, authorization, isolation, execution, recovery,
operability, installation, retention and supported upgrades against a release
profile. Use ASVS 5.0.0 Level 2 as the application-security requirements target,
with applicability and evidence rows. This is an engineering assessment target;
it is not an assertion of certification or a substitute for organization-specific
regulatory/customer requirements.
[OWASP ASVS](https://asvs.owasp.org/)

## Changes from the previous roadmap

1. Enterprise readiness replaces the earlier unspecified demo/pilot goal.
2. Runtime support refresh is required; preserve old reports as historical.
3. PostgreSQL state/transactions move ahead of durable containment, operation
   receipts and approvals. Avoid building a second temporary persistence layer.
4. False-positive release evaluation is disabled or repaired before any production
   admission, not deferred until a UI exists.
5. Initial release has one self-hosted profile and one workflow. Hybrid/offline
   mutation, many provider combinations, arbitrary coding and broad research
   automation stay outside its supported envelope until separately verified.
6. The older M0 plan says nine external integration entries, but the linked spec
   enumerates eight. Use one shared named list and test its values, not a magic
   count. The new to-do list records this planning defect explicitly.

## Remaining research during implementation

- Resolve and audit dependency versions compatible with Python 3.12/3.13; do not
  infer compatibility from version ranges. Test actual wheels and container image.
- Run Authlib/discovery/PKCE and API-token tests against a pinned Keycloak fixture;
  add Entra ID/Okta only after a named provider acceptance run is available.
- Pin PostgreSQL/Docker/Cosign versions and verify required resource/egress
  behavior on a Linux host. None of these live integrations ran in this research.
- Benchmark the defined workload and the restore drill before publishing an SLO.
- Run independent security review and a bounded operational evaluation before
  enabling a customer deployment. No implementation or certification was
  completed by the research steps above.
