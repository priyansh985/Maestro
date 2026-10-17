# MAESTRO v1.0 Release Notes

MAESTRO v1.0 is the first release-candidate-quality snapshot of the agentic-AI
security control plane: the 7-layer threat-modeling methodology of
arXiv:2508.10043 turned into an enforced, audited, product-level platform.

The release is gated by the machine-checked validation script
(`maestro-v1-validate`); see **Validation evidence** below.

---

## What's in v1.0

| Phase | Delivered |
|---|---|
| BP0-BP3 | Ground-truth audit (`maestro-audit`), typed proposals + capability gateway, tamper-evident ledger, zero-trust bearer auth + per-principal rate limiting + structural multi-tenant isolation on the whole `/api` surface |
| BP4 | Executor sandbox (in-process / Docker / gVisor), replay-safe durable exactly-once journal, Temporal.io backend (opt-in), compensation framework with reversible-action registry |
| BP7 | Pre-execution HMDC critique gate, environmental verifiers (test-suite, reconciliation, citation, safety envelope), adversarial corpus TC3-TC15 |
| BP8/BP9 | Secure coding agent (PR-only; merge gated on admin approval) and research agent (quarantined sources, citation entailment, no authority escalation) |
| BP10 | Hybrid runner + local data plane: private data stays local; network partition is fail-closed (`OFFLINE_DENY` default, `OFFLINE_READONLY` for reversible work) |
| BP11 | `/api/agents` fleet API, Python SDK, CLI (`agent/policy/memory/ledger/tenant` → live control plane), operator control panel + dashboards package |
| BP12 | OIDC (JWKS) identity, Postgres RLS migrations, externally-signed policy bundles, SOC2/ISO27001 compliance export, DR runbooks + replication |
| BP13 | `maestro-v1-validate` release gate, this document, changelog |

## Validation evidence

- **636 tests** in `tests/` — all green; adversarial corpus TC3-TC15 included.
- `ruff check src tests` — clean; `mypy` config present (control plane typed).
- `audit_invariants()` build guard: **0 violations** — a control cannot claim
  `tested`/`verified` while default-off.
- Control status (see `docs/audit/control_gap_report.md`): 35 controls —
  **15 boundary-enforced**, 7 adversarially `verified`, 27/35
  `enforced_or_above` (ratio 0.771), 7 `implemented` (not boundary-wired),
  **1 `declared`** (CTRL-L1-01 LLM output validator — the honest top of the
  roadmap, not a hidden gap).
- Policy bundles: signed, versioned, two-person rule; signature re-verified
  at the side-effect boundary; tamper/absence fails closed.

## Migration guide (0.1.0 beta → 1.0.0)

1. **Auth is on by default.** The whole `/api` surface requires a signed
   bearer token (`MAESTRO_API_TOKEN` / `MAESTRO_SIGNING_KEY`) and a role;
   per-principal rate limits apply (HTTP 429). Setting
   `mitigation.zero_trust_api=false` restores the paper's unauthenticated
   baseline for local experiments only.
2. **Dashboard routes.** The WebSocket stream is fixed at `/ws` (previously
   configurable via `server.ws_path`); `GET /` serves the dashboard, `/control`
   the operator control panel.
3. **Policy bundles.** The executor's intent allow-list is now a signed,
   versioned bundle; production configs must supply the signing key. Policy
   CLI: `maestro policy validate|diff|promote|rollback`.
4. **Fleet & tenants.** Agent lifecycle lives at `/api/agents` (RBAC:
   viewer read, operator mutate); tenants are isolated structurally — use
   `maestro tenant create|isolate` and cross-tenant reads require the
   `cap:memory:cross-tenant-read` capability.
5. **CLI/SDK.** Machine outputs: `--output json|table|yaml` (json default).
   SDK entry point: `from maestro.sdk import ...` (see `docs/SDK.md`).
6. **Env keys.** `MAESTRO_API_KEY` (client auth), `MAESTRO_SIGNING_KEY`
   (server HMAC/signing), `MAESTRO_CONTROL_PLANE` (CLI/SDK base URL),
   `MAESTRO_ALLOW_UNSAFE_HOSTS` (SSRF guard override — local only).

## Known limitations (honest seams, not hidden gaps)

- **OS-level isolation is a seam.** The in-process executor sandbox is
  boundary-enforced; Docker/gVisor modes are implemented but expected to run
  on Linux with the container toolchain present — Windows CI runs them mocked
  (`tests/test_sandbox_external.py`).
- **Temporal.io is opt-in.** The durable engine that is boundary-enforced is
  the file-backed exactly-once journal; the Temporal backend ships as an
  adapter and is not exercised against a live Temporal server in CI.
- **OIDC is tested against fixtures.** JWKS flows are covered with mock
  providers; real interop (Azure AD, Okta, Keycloak) must be verified per
  deployment.
- **Postgres RLS requires a live Postgres.** Migration scripts and pool
  helpers ship; the app-layer contract (scope isolation + capability) is
  enforced and tested independently of the DB seam.
- **Bundle signing uses a shared HMAC key by default.** External signer
  identities (OIDC/KMS per approver) are the declared seam for the two-person
  rule; the approval-by-construction gate is already boundary-enforced.
- **The judge is offline-deterministic.** The operative critique gate is the
  guardrail + environmental-verifier pair; a connector-backed cross-family
  LLM judge remains a seam (queried only via the injection perimeter).
- **CTRL-L1-01 (LLM output validator) is declared-only.** It is the roadmap
  top item; the audit refuses to overstate it.

## Release hygiene

- Code: `development` branch, HEAD at the v1.0.0 tag (signed-commit tag
  pending key provisioning; see commit `72acba4` lineage).
- Docs: `README.md`, `docs/SDK.md`, `docs/audit/*` (machine-generated), this
  document, `CHANGELOG.md`.
- Reproducibility: `reproduce.sh` / `reproduce.bat`; validation via
  `python -m maestro.scripts.validate_v1`.
