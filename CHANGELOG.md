# Changelog

All notable changes to MAESTRO are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows SemVer.

## [1.0.0] - 2026-10-18

First release-candidate-quality definition of MAESTRO: a 7-layer threat-modeling
methodology and enforcement control plane for agentic AI (reproduction of
arXiv:2508.10043, extended into a productized blueprint implementation).

### Added
- **Core control plane (BP0-BP7)** — typed action proposals, capability
  gateway, policy enforcement point, tamper-evident hash-chained ledger,
  four-tier memory with trust labels and tenant isolation, durable
  exactly-once execution journal, executor sandbox (scope + output
  confinement), HMDC gated critique, environmental verifiers, signed policy
  bundles with the two-person approval rule.
- **Vertical agents (BP8/BP9)** — secure coding agent (opens PRs; merge
  requires explicit admin approval) and research agent (strict RAG with
  quarantine + citation entailment gating).
- **Hybrid runner & local data plane (BP10)** — runs near customer data;
  fail-closed on control-plane partition; `OFFLINE_DENY` / `OFFLINE_READONLY`
  modes.
- **Full lifecycle surfaces (BP11)** — `/api/agents` fleet management driving
  real per-agent platforms; Python SDK (`AgentClient`, `PolicyClient`,
  `MemoryClient`, `LedgerClient`, `TenantClient`, …) over
  `ControlPlaneHttpClient`; CLI wired to the live control plane with
  `json|table|yaml` output modes; operator control panel + split dashboards
  package.
- **Enterprise hardening (BP12)** — OIDC (JWKS) identity integration, Postgres
  row-level-security migration scripts and pool helpers, externally-signed
  policy bundles, SOC2/ISO27001 compliance export, disaster-recovery
  runbooks (`maestro-dr-*` failover/recovery), compensation framework for
  reversible actions, evidence graph.
- **Adversarial corpus (TC3-TC15)** — 13 threat cases: direct/indirect
  injection, tool-argument smuggling, confused deputy, connector compromise,
  data exfiltration, rogue delegation, log tampering, rollback attack,
  cross-tenant leak, unsafe code execution, model supply chain, multi-agent
  collusion.
- **Validation gate (BP13)** — `maestro-v1-validate` script enforcing test,
  control-status, policy-signing, compliance-export, hybrid fail-closed, SDK,
  CLI, and zero-violation checks; exits non-zero on any failure.

### Changed
- Agent platform provisions the full blueprint intent vocabulary with
  tenant-interpolated resource scopes; the reasoning loop consults a trusted
  evidence graph; `MemoryStore` gains demote/quarantine (refusal-idempotent)
  mirroring `promote`.
- Dashboard replaced by a `dashboards` package; WebSocket stream moved to a
  fixed `/ws` path.
- Default blast radius reports irreversible intents (e.g. `code_git_push`,
  `code_open_pr`) held by the platform — the release test contract asserts
  them explicitly.

### Validation
- 636 tests green; ruff clean across `src/` and `tests/`; `audit_invariants()`
  build guard passes with 0 violations; 15 boundary-enforced controls,
  27/35 enforced-or-above on a machine-checked, honestly graded control
  status (1 control remains declared-only, by design — see
  `docs/audit/control_gap_report.md`).

## [0.1.0] - beta

Initial reproduction of arXiv:2508.10043 (7-layer threat model, telemetry →
detection → reasoning → planner → mitigation loop, TC1 DoS + TC2 memory
poisoning, risk engine, paper dashboard).
