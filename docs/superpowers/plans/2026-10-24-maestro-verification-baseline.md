# MAESTRO Verification Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the misleading release-ready validator with a reproducible,
truthful offline verification report that records failures and unassessed work.

**Architecture:** Keep the existing module command and Python modular monolith.
Use one ordered check specification, a subprocess runner that preserves logs,
and a digest-bound manifest. CI consumes that same command; integration profiles
remain explicitly unassessed.

**Tech Stack:** Python 3.10/3.11, stdlib subprocess/hashlib/json/pathlib/dataclasses,
existing pytest/ruff/mypy, GitHub Actions. No added dependencies.

**Spec:** `docs/superpowers/specs/2026-10-24-maestro-next-stage-design.md`, M0 only.
The builder check reported “nothing important left.” This is a proposed plan;
the current request delivered analysis and planning, not product implementation.

## Global Constraints

- Python 3.10 remains the declared minimum; preserve support for Python 3.11.
- Default validation must work offline without credentials, raw-packet replay,
  containers, database servers, or paid model calls.
- No simulation result may authorize production admission or be described as
  evidence of a real external effect.
- Do not change dependencies, public APIs, or runtime enforcement in M0.
- Build in place. No new framework, microservice split, model training, public
  marketplace, billing, or broad agent framework integration in this stage.
- Compliance exports are evidence packages, not proof of SOC2/ISO certification.
- Never use total test count or zero ledger violations as a substitute for task
  usefulness, infrastructure validation, or attack success measurements.

M0 implementation can be complete with an honestly failing verification result
if existing mypy/product failures remain. Record them; do not suppress them to
obtain a green status. M1 owns behavior/signing/DR repairs. Passing all checks is
a separate condition from delivering a correct validator.

## Review Focus

- Lost or timed-out child processes: terminate only owned process trees, retain
  partial logs, report timeout and continue later checks (Task 2).
- Repository changes during validation: do not claim one validated snapshot when
  files changed between start and finish (Task 3).
- Spaces, Unicode and missing tools: use argv arrays, UTF-8 logs and explicit
  error records, preserving a manifest even when a check cannot start (Tasks 2–3).
- Empty/fake successes: real CLI help/version and one complete tests directory;
  never a replica parser or an overlapping subset (Tasks 1 and 4).
- Accidental disclosure or artifact overwrite: only approved hash inputs and
  distribution names/versions; refuse a used output directory (Tasks 3–4).

## File structure and interfaces

Modify `src/maestro/scripts/validate_v1.py` for orchestration and the public module
entry point. Create `src/maestro/scripts/validation_evidence.py` for check records,
subprocess lifecycle, hashing and manifest writing. Create
`tests/test_validation_runner.py` for isolated contract tests. Modify
`.github/workflows/ci.yml`, `README.md`, `IMPLEMENTATION_PLAN.md`, and
`docs/RELEASE_v1.0.md`; add `docs/VALIDATION.md` for the command and evidence scope.
Existing immutable historical logs remain untouched.

The new helper module defines:

- `CheckSpec(check_id: str, argv: tuple[str, ...])`, frozen dataclass.
- `CheckRecord(check_id: str, argv: tuple[str, ...], status: str,
  returncode: int | None, elapsed_seconds: float, stdout_log: str,
  stderr_log: str)`, frozen dataclass; status is one of the four spec values.
- `offline_checks(python: str) -> tuple[CheckSpec, ...]` with IDs `threats`,
  `lint`, `types`, `tests`, `cli_help`, `cli_version`, in that order.
- `run_check(check: CheckSpec, *, cwd: Path, output_dir: Path,
  timeout_seconds: int) -> CheckRecord`.
- `snapshot_inputs(root: Path) -> dict[str, str]`, sorted relative POSIX path
  to content SHA-256 hex; missing mandatory root files are errors, not omission.
- `collect_metadata(root: Path) -> dict[str, object]`, including distribution
  names/versions and optional Git identity; never an environment snapshot.
- `write_manifest(path: Path, payload: dict[str, object]) -> None`, atomic
  temporary-file/replace within the newly reserved output directory.
- `run_validation(*, root: Path, output_dir: Path, timeout_seconds: int,
  python: str = sys.executable) -> int` in `validate_v1.py`, returning 0/1.
- `main(argv: list[str] | None = None) -> int`, parsing the M0 command and
  returning 0/1/2 according to the spec.

### Task 1: define the real offline check contract

**Files:** Create `validation_evidence.py`; create `tests/test_validation_runner.py`.

**Interfaces:** Produces `CheckSpec`, `CheckRecord`, and `offline_checks` above.
No subprocess runs in this task.

- [ ] Write `test_offline_checks_cover_real_entrypoints_once` asserting the six
  exact commands from the spec, fixed IDs and order, and that the pytest command
  is exactly `(python, '-m', 'pytest', 'tests', '-q')` without `--ignore` flags.
- [ ] Run `.venv\Scripts\python.exe -m pytest tests/test_validation_runner.py -q`;
  confirm missing-module/function failure.
- [ ] Implement the two frozen records and `offline_checks`; commands always
  begin with the passed Python path, never a bare executable from PATH.
- [ ] Run the focused file and `ruff check` on the two new files; expect pass.
- [ ] Commit only this task's files: `test: define complete offline validation contract`.

### Task 2: run checks with durable logs and owned-process cleanup

**Files:** Modify helper and its tests.

**Interfaces:** Consumes `CheckSpec`; produces `run_check -> CheckRecord`.
Logs are `<check_id>.stdout.log` / `<check_id>.stderr.log` relative to output dir.

- [ ] Write tests `test_run_check_preserves_exit_and_logs` for exit 0 and exit 7,
  stdout and stderr; `test_check_missing_executable_is_error`; and
  `test_argv_spaces_and_unicode_are_preserved`. Use synthetic Python children in
  temporary paths, never run actual project pytest from validator tests.
- [ ] Write `test_timeout_terminates_owned_child_tree` with a synthetic child
  that launches a grandchild and writes their PIDs. Assert status timeout,
  null/nonzero return code as recorded, partial logs retained, and both owned
  processes gone. Cover Windows and POSIX in their native CI jobs; an unrun
  platform is not verified.
- [ ] Run those tests and confirm the new interface/behavior is missing.
- [ ] Implement `run_check` using `Popen(..., shell=False)` and file-backed logs.
  Use a process group on POSIX; on Windows launch an owned process and terminate
  its PID tree with native facilities. Handle startup error, cleanup and log
  closing in `finally`. Normalize timeout/error into a record instead of raising
  past orchestration. No global image-name kills.
- [ ] Run the focused tests. Confirm a timed-out check does not prevent a later
  synthetic success check from running. Verify no test subprocess remains.
- [ ] Commit: `feat: record validation commands and bounded subprocess outcomes`.

### Task 3: bind results to source inputs and write the manifest

**Files:** Modify helper; replace orchestration in `validate_v1.py`; extend tests.

**Interfaces:** Consumes check records; produces `snapshot_inputs`,
`collect_metadata`, `write_manifest`, and `run_validation` as defined above.

- [ ] Write `test_snapshot_covers_declared_inputs_and_ignores_outputs` using a
  temporary miniature repo. Assert source/test/config/HTML/packaging/CI hashes,
  stable POSIX ordering, changed-byte detection, exclusion of caches/output and
  `.env`/credentials/home contents. A symlink resolving outside the approved
  root must be refused, not followed into unrelated files.
- [ ] Write `test_manifest_records_all_checks_after_failure`: inject a fake
  `run_check` at the orchestration boundary returning one failure among six;
  assert all six ordered records, log hashes, schema version 1, exit 1,
  `offline_checks_passed=false`, `production_readiness='not_assessed'`, and all
  nine external-integration not-run entries from the spec.
- [ ] Write `test_changed_snapshot_cannot_pass`, `test_git_unavailable_is_explicit`,
  and `test_manifest_has_no_environment_values`. The first mutates one hashed
  fixture during a mocked check and asserts `snapshot_stable=false`, exit 1.
  The last seeds a synthetic secret environment value and asserts it is absent
  from metadata/manifest; do not print that value.
- [ ] Run focused tests; confirm failures expose absent behavior.
- [ ] Implement metadata collection, approved path hashing, log hashing and
  start/end comparison. Capture Git HEAD/tracked-dirty status with bounded
  read-only commands; absent Git is represented explicitly. Keep metadata
  collection errors visible; an unreadable required input is a failed validation.
- [ ] Implement the six-check orchestration, logging each outcome even after
  failures and writing the manifest before returning. Summaries use the exact
  offline-verification language from the spec.
- [ ] Run focused tests and ruff/mypy on the changed modules. Existing unrelated
  mypy failures belong in the evidence report, not in ignore rules.
- [ ] Commit: `feat: bind offline validation evidence to a stable source snapshot`.

### Task 4: expose and verify the actual module command

**Files:** Modify `validate_v1.py`; extend its tests; create `docs/VALIDATION.md`.

**Interfaces:** Produces `main(argv=None)` and preserves the module entry point.
Arguments: `--profile offline`, `--output-dir`, `--timeout-seconds` default 1800.

- [ ] Write `test_cli_rejects_invalid_timeout_and_profile` for 0, negative and
  non-integer timeout, and unsupported profile; expect exit 2 before checks.
  Write `test_existing_manifest_is_not_overwritten` and assert original bytes
  are unchanged and no child was started. Write
  `test_default_output_directory_is_unique` using a fixed clock and varying
  suffix to ensure no collision or overwrite.
- [ ] Write `test_main_summary_never_claims_production_readiness` for both 0
  and 1 outcomes. Assert real check specs are used; no parser-copy code remains.
- [ ] Run and confirm failures, then implement argument parsing, exclusive
  output reservation and precise exit mapping. Document scopes, commands,
  manifest fields, external lanes, failures and rerun behavior.
- [ ] Run all focused validator tests and a real help command:
  `.venv\Scripts\python.exe -m maestro.scripts.validate_v1 --help`.
- [ ] Run one real validation into a fresh directory. Inspect all six records,
  not just exit status. Current type/signing/DR defects may make it fail; verify
  that its report accurately preserves those failures. Do not rerun all checks
  merely to obtain a preferred result.
- [ ] Commit: `feat: expose truthful offline validation command and report`.

### Task 5: make CI and status documentation consume the same evidence

**Files:** Modify `.github/workflows/ci.yml`, README, implementation status and
release notes; update `docs/VALIDATION.md`.

**Interfaces:** Uses the module command and manifest schema from Tasks 1–4.
No runtime security fixes or new integration claims are permitted here.

- [ ] Replace repeated lint/type/test invocations in the Python 3.10/3.11 job
  with `python -m maestro.scripts.validate_v1 --profile offline --output-dir ...`.
  Upload evidence with `if: always()` and per-matrix artifact names. Keep install
  setup intact; do not cache a virtual environment as test evidence.
- [ ] Add a small Windows validator-contract job for the process-tree tests
  from Task 2. It need not execute all infrastructure profiles. Preserve or
  separate the existing deterministic experiment reproduction outcome rather
  than dropping it from CI; no live packet replay is required.
- [ ] Correct README auth/version/default-capability claims and replace blanket
  BP8–BP13 completion with the audit's per-feature evidence scope. Add a dated
  correction to release notes while preserving the historical 636-test result.
  Explain that installed console-script packaging is a separate pending task.
- [ ] Review diff against the spec: six checks once, manifest input scope,
  stable-source requirement, no external calls, no secrets, failure propagation,
  explicit unassessed infrastructure, no unconditional release-ready message.
- [ ] Run relevant focused tests after any final code change. Verify workflow
  syntax and collect actual CI outcomes when a later authorized push triggers
  them; a locally edited YAML file does not prove CI passed.
- [ ] Commit only these files: `ci: publish truthful validation evidence and status`.

## Next plans after M0

Create separate scoped designs/plans for (1) deployment evidence and signing,
(2) operation receipts/journal/client retries, (3) tenant containment, and
(4) backup restoration. Use F01–F16 as concrete failure examples. OIDC/RLS and
real sandbox profiles require separate infrastructure acceptance; do not hide
those tasks inside lint cleanup. Before M2, select and observe the first real
operator workflow. Feature priorities and proposed measurements are in the spec.
