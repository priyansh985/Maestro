# Enterprise E0 implementation plan

> **For agentic workers:** Use executing-plans for inline execution with a final independent code review. Do not begin E1–E4 in this change set.

**Goal:** Establish truthful release/validation behavior and a supported, installable development baseline.
**Architecture:** Preserve the modular monolith. Disable production admission and production startup until the required real evidence/state/identity/adapter integrations exist. Offline research remains available.
**Tech stack:** Python, pytest, Ruff, mypy, uv, setuptools and existing FastAPI stack.
**Spec:** `docs/superpowers/specs/2026-10-30-enterprise-readiness-design.md`; tasks E0-01–E0-08 in `docs/ENTERPRISE_TODO.md`.

## Constraints and review focus

- Preserve user files and historical evidence; work on `codex/enterprise-e0` in the existing checkout.
- No production-ready claim, disabled security check, fake evidence or automatic mutation retry.
- No new durable DB, OIDC login, arbitrary-code sandbox, recovery guarantee or external side effect in E0.
- Required checks continue after failure, retain UTF-8 logs and fail overall; input changes cannot validate one snapshot.
- Test timeout cleanup only on processes created by this runner. No global process termination.
- Python 3.12/3.13 package compatibility; reference runtime 3.13; freeze resolved versions only after installing/testing them.
- Mark unavailable container/runtime verification accurately; never simulate an image build.

## Tasks

- [ ] **1. Release admission (E0-01).** Add regressions in `tests/test_release_gate.py` for missing evaluators, empty/advisory-only bundles and the audit's invalid bundle. Remove unconditional successful evaluation in `security/release_gate.py`. Production evaluation returns explicit unavailable/failed outcomes until the real verifier is implemented; an explicit separate simulation API may report hypothetical scores but must never make `overall_passed` or `required_gates_passed` true. Remove test-key fallback; validate distinct approvers for bundle creation. Run RED then GREEN plus affected tests.
- [ ] **2. Verification runner (E0-02).** Implement the October 24 M0 plan in `scripts/validate_v1.py` and a focused `validation_evidence.py`, correcting eight integration entries and the supported-runtime policy. Tests cover six real commands once, failure propagation, logs/hashes, directory reservation, changed input and process-tree timeout. Never invoke the full validator recursively from tests.
- [ ] **3. Interface/type repair (E0-03).** Reproduce mypy; read each mismatched contract. Fix actual PolicyBundle/PolicyRegistry, AuditEvent, Principal and SDK interfaces at the responsible layer. Cover behavior changes with failing regressions; preserve successful defaulted model fields rather than assuming mypy errors are runtime failures. Disable unfinished signed registry/replication features explicitly rather than inventing validation or dropping records. Keep actual DR restoration as E3 work.
- [ ] **4. Runtime and distribution (E0-04/05).** Update Python floor/tooling, resolve lock on 3.12/3.13, install dev extras into supported environments and run checks. Package HTML/config with importlib.resources fallbacks. Add truthful CLI entry points/version. Build wheel and sdist and run scripts/app/resource smoke tests from a separate directory in a fresh installed environment.
- [ ] **5. Production boot boundary (E0-06).** Add focused negative startup tests in `tests/test_server.py`. Explicit production profile must fail with an actionable unavailable message until enterprise requirements exist, even with bypass flags. Default research/offline app remains operational.
- [ ] **6. CI/status/review (E0-07/08).** Supported Python CI uses the same offline runner and uploads evidence on failure. Separate deterministic reproduction and wheel smoke jobs. Correct historical claims with dated notes; record genuinely unavailable integrations. Run full tests/lint/types, independent code review, fix important findings with RED→GREEN, update checked items with evidence. No push, merge or deployment.

Task boundaries are independently reviewable. Each completion is recorded in the E0 ledger and committed using only this task's files; existing unrelated untracked files are excluded.
