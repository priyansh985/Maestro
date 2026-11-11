"""Validation exercises real subprocess outcomes, never a copied CLI parser."""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import time

import psutil
import pytest

from maestro.scripts import validate_v1
from maestro.scripts import validation_evidence as evidence
from maestro.scripts.validation_evidence import (
    CheckSpec,
    collect_metadata,
    offline_checks,
    run_check,
    snapshot_inputs,
)


@pytest.fixture
def small_repo(tmp_path):
    for p in ("src/maestro/example.py", "src/maestro/view.html", "src/maestro/py.typed",
              "tests/test_example.py", "configs/default.yaml", "pyproject.toml",
              "requirements.txt", "uv.lock", ".github/workflows/ci.yml"):
        f = tmp_path / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# fixture\n", encoding="utf-8")
    return tmp_path


def test_offline_checks_use_complete_suite_and_actual_cli():
    assert [c.argv for c in offline_checks("python-path")] == [
        ("python-path", "-m", "maestro.scripts.validate_threats"),
        ("python-path", "-m", "ruff", "check", "src", "tests"),
        ("python-path", "-m", "mypy", "src"),
        ("python-path", "-m", "pytest", "tests", "-q"),
        ("python-path", "-m", "maestro.cli", "--help"),
        ("python-path", "-m", "maestro.cli", "--version"),
    ]


@pytest.mark.parametrize("code,status", [(0, "passed"), (7, "failed")])
def test_run_check_retains_actual_exit_and_separate_logs(tmp_path, code, status):
    check = CheckSpec("child", (sys.executable, "-S", "-c",
        f"import sys; print('hello'); print('error', file=sys.stderr); sys.exit({code})"))
    record = run_check(check, cwd=tmp_path, output_dir=tmp_path, timeout_seconds=60)
    assert record.status == status
    assert record.returncode == code
    assert (tmp_path / record.stdout_log).read_text(encoding="utf-8").strip() == "hello"
    assert (tmp_path / record.stderr_log).read_text(encoding="utf-8").strip() == "error"


def test_argv_spaces_and_unicode_survive(tmp_path):
    check = CheckSpec("unicode", (sys.executable, "-S", "-c", "import sys; print(sys.argv[1])", "a b हिन्दी"))
    record = run_check(check, cwd=tmp_path, output_dir=tmp_path, timeout_seconds=60)
    assert record.status == "passed"
    assert (tmp_path / record.stdout_log).read_text(encoding="utf-8").strip() == "a b हिन्दी"


def test_missing_executable_is_recorded(tmp_path):
    r = run_check(CheckSpec("absent", (str(tmp_path / "does-not-exist"),)),
                  cwd=tmp_path, output_dir=tmp_path, timeout_seconds=1)
    assert r.status == "error"
    assert r.returncode is None
    assert (tmp_path / r.stderr_log).read_text(encoding="utf-8")


def test_timeout_stops_owned_child(tmp_path):
    marker = tmp_path / "should-never-be-written"
    code = "import time,pathlib,sys; print('started',flush=True); time.sleep(10); pathlib.Path(sys.argv[1]).touch()"
    r = run_check(CheckSpec("timeout", (sys.executable, "-S", "-c", code, str(marker))),
                  cwd=tmp_path, output_dir=tmp_path, timeout_seconds=1)
    assert r.status == "timeout"
    assert not marker.exists()


def test_cleanup_timeout_is_recorded_instead_of_escaping(tmp_path, monkeypatch):
    class UnresponsiveProcess:
        pid = 123
        returncode = None

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("synthetic-child", timeout)

        def poll(self):
            return None

    monkeypatch.setattr(evidence.subprocess, "Popen", lambda *args, **kwargs: UnresponsiveProcess())

    def cleanup_failure(process):
        raise subprocess.TimeoutExpired("synthetic-cleanup", 30)

    class FailingJob:
        def bind_and_resume(self, process):
            pass

        def finish(self):
            raise OSError("synthetic job cleanup failure")

    monkeypatch.setattr(evidence, "WindowsJob", FailingJob)
    monkeypatch.setattr(evidence, "_stop_owned_process", cleanup_failure)
    result = run_check(CheckSpec("cleanup_error", ("synthetic-child",)),
                       cwd=tmp_path, output_dir=tmp_path, timeout_seconds=1)
    assert result.status == "error"
    assert "cleanup" in (tmp_path / result.stderr_log).read_text(encoding="utf-8")


def _started_identity(log):
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            text = log.read_text(encoding="utf-8")
            if text.endswith("\n") and text.strip().isdigit():
                return psutil.Process(int(text.strip()))
        except (FileNotFoundError, PermissionError, psutil.NoSuchProcess):
            pass
        time.sleep(0.05)
    pytest.fail("owned descendant did not report readiness")


def _terminated(identity):
    try:
        return not identity.is_running() or identity.status() == psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return True


def test_timeout_stops_a_started_descendant(tmp_path, monkeypatch):
    """Wait for a real grandchild before triggering the runner's timeout path."""
    ready = tmp_path / "tree.stdout.log"
    child_code = "import os,time; print(os.getpid(),flush=True); time.sleep(600)"
    parent_code = ("import subprocess,sys,time; "
                   "subprocess.Popen([sys.executable,'-S','-c',sys.argv[1]]); "
                   "time.sleep(600)")
    argv = (sys.executable, "-S", "-c", parent_code, child_code)
    original_wait = subprocess.Popen.wait
    descendants = []

    def wait_after_start(process, timeout=None):
        if process.args == argv and timeout == 1:
            descendants.append(_started_identity(ready))
            raise subprocess.TimeoutExpired(argv, timeout)
        return original_wait(process, timeout=timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", wait_after_start)
    try:
        result = run_check(CheckSpec("tree", argv), cwd=tmp_path,
                           output_dir=tmp_path, timeout_seconds=1)
        assert result.status == "timeout"
        descendant = descendants[0]
        deadline = time.monotonic() + 10
        while not _terminated(descendant) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _terminated(descendant)
    finally:
        for descendant in descendants:
            with contextlib.suppress(psutil.NoSuchProcess):
                descendant.kill()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job lifecycle contract")
def test_completed_check_cannot_leave_an_owned_descendant(tmp_path, monkeypatch):
    ready = tmp_path / "completed_tree.stdout.log"
    child_code = "import os,time; print(os.getpid(),flush=True); time.sleep(600)"
    parent_code = ("import subprocess,sys\n"
                   "child=subprocess.Popen([sys.executable,'-S','-c',sys.argv[1]], "
                   "stdout=subprocess.PIPE,text=True)\n"
                   "print(child.stdout.readline().strip(),flush=True)\n")
    argv = (sys.executable, "-S", "-c", parent_code, child_code)
    original_wait = subprocess.Popen.wait
    descendants = []

    def capture_before_cleanup(process, timeout=None):
        if process.args == argv and timeout == 300:
            descendants.append(_started_identity(ready))
        return original_wait(process, timeout=timeout)

    monkeypatch.setattr(subprocess.Popen, "wait", capture_before_cleanup)
    try:
        result = run_check(CheckSpec("completed_tree", argv),
                           cwd=tmp_path, output_dir=tmp_path, timeout_seconds=300)
        assert result.status == "passed"
        assert _terminated(descendants[0])
    finally:
        for descendant in descendants:
            with contextlib.suppress(psutil.NoSuchProcess):
                descendant.kill()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows suspended ownership contract")
def test_failed_job_assignment_never_starts_the_check(tmp_path, monkeypatch):
    marker = tmp_path / "must-not-run"
    owned = []

    def reject_ownership(job, process):
        owned.append(process)
        raise OSError("synthetic ownership failure")

    monkeypatch.setattr(evidence.WindowsJob, "bind_and_resume", reject_ownership)
    try:
        result = run_check(CheckSpec("ownership", (sys.executable, "-S", "-c",
                           "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(marker))),
                           cwd=tmp_path, output_dir=tmp_path, timeout_seconds=60)
        assert result.status == "error"
        assert len(owned) == 1 and owned[0].poll() is not None
        assert not marker.exists()
        assert "ownership failure" in (tmp_path / result.stderr_log).read_text(encoding="utf-8")
    finally:
        if owned and owned[0].poll() is None:
            owned[0].kill()
            owned[0].wait(timeout=30)


def test_exited_root_never_resumes_a_new_pid_identity(monkeypatch):
    resumed = []
    captured = []

    class NativeAPI:
        def AssignProcessToJobObject(self, job, handle):
            return 1

    class ReusedIdentity:
        def __init__(self, pid):
            captured.append(pid)

        def resume(self):
            resumed.append(True)

    class ExitedRoot:
        pid = 123
        _handle = 456

        def poll(self):
            return 1

    job = evidence.WindowsJob.__new__(evidence.WindowsJob)
    job._api = NativeAPI()
    job._handle = 789
    monkeypatch.setattr(psutil, "Process", ReusedIdentity)
    with pytest.raises(OSError, match="before resume"):
        job.bind_and_resume(ExitedRoot())
    assert captured == [123]
    assert resumed == []


def test_snapshot_tracks_content_but_ignores_secrets_and_outputs(small_repo):
    first = snapshot_inputs(small_repo)
    assert "src/maestro/view.html" in first and "src/maestro/py.typed" in first
    (small_repo / ".env").write_text("secret", encoding="utf-8")
    (small_repo / "results").mkdir()
    (small_repo / "results/run.log").write_text("output", encoding="utf-8")
    assert snapshot_inputs(small_repo) == first
    (small_repo / "src/maestro/example.py").write_text("# changed", encoding="utf-8")
    assert snapshot_inputs(small_repo) != first


def test_missing_required_input_fails(small_repo):
    (small_repo / "uv.lock").unlink()
    with pytest.raises((ValueError, OSError)):
        snapshot_inputs(small_repo)


def test_external_symlink_is_not_read(small_repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "file.py"
    outside.write_text("outside", encoding="utf-8")
    link = small_repo / "src/maestro/link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("host does not permit symlink creation")
    with pytest.raises(ValueError, match="outside"):
        snapshot_inputs(small_repo)


def _synthetic_checks(monkeypatch, first_code):
    checks = (CheckSpec("first", (sys.executable, "-S", "-c", first_code)),
              CheckSpec("second", (sys.executable, "-S", "-c", "print('later check ran')")))
    monkeypatch.setattr(validate_v1, "offline_checks", lambda python: checks)


def test_failure_does_not_skip_later_checks_or_claim_readiness(small_repo, monkeypatch, capsys):
    _synthetic_checks(monkeypatch, "raise SystemExit(7)")
    out = small_repo / "results/one"
    code = validate_v1.run_validation(root=small_repo, output_dir=out, timeout_seconds=60)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert code == 1
    assert [r["status"] for r in manifest["checks"]] == ["failed", "passed"]
    assert manifest["production_readiness"] == "not_assessed"
    assert manifest["offline_checks_passed"] is False
    assert len(manifest["not_run"]) == 8
    assert "later check ran" in (out / "second.stdout.log").read_text(encoding="utf-8")
    assert "READY FOR RELEASE" not in capsys.readouterr().out
    assert manifest["log_hashes"]


def test_changed_input_invalidates_otherwise_green_run(small_repo, monkeypatch):
    target = small_repo / "src/maestro/example.py"
    _synthetic_checks(monkeypatch, f"from pathlib import Path; Path({str(target)!r}).write_text('changed')")
    out = small_repo / "results/changed"
    assert validate_v1.run_validation(root=small_repo, output_dir=out, timeout_seconds=60) == 1
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert m["snapshot_stable"] is False


def test_green_stable_run_has_no_environment_secrets(small_repo, monkeypatch):
    monkeypatch.setenv("MAESTRO_AUDIT_SECRET", "do-not-export-this-test-secret")
    _synthetic_checks(monkeypatch, "print('ok')")
    out = small_repo / "results/green"
    assert validate_v1.run_validation(root=small_repo, output_dir=out, timeout_seconds=60) == 0
    text = (out / "manifest.json").read_text(encoding="utf-8")
    assert "do-not-export-this-test-secret" not in text
    assert json.loads(text)["offline_checks_passed"] is True


def test_existing_output_manifest_cannot_be_overwritten(small_repo, monkeypatch):
    _synthetic_checks(monkeypatch, "raise AssertionError('must not run')")
    out = small_repo / "results/existing"
    out.mkdir(parents=True)
    marker = out / "manifest.json"
    marker.write_text("original", encoding="utf-8")
    with pytest.raises((ValueError, FileExistsError)):
        validate_v1.run_validation(root=small_repo, output_dir=out, timeout_seconds=60)
    assert marker.read_text(encoding="utf-8") == "original"


@pytest.mark.parametrize("args", [["--timeout-seconds", "0"], ["--timeout-seconds", "-1"],
                                  ["--timeout-seconds", "bad"], ["--profile", "production"]])
def test_invalid_cli_configuration_fails_before_execution(args):
    with pytest.raises(SystemExit) as error:
        validate_v1.main(args)
    assert error.value.code == 2


def test_installed_validator_requires_source_checkout(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(validate_v1, "__file__", str(tmp_path / "site-packages/maestro/scripts/validate_v1.py"))
    monkeypatch.setattr(validate_v1, "run_validation", lambda **kwargs: pytest.fail(
        "installed prefix must be rejected before running any checks"))
    with pytest.raises(SystemExit) as error:
        validate_v1.main([])
    assert error.value.code == 2
    assert "source checkout" in capsys.readouterr().err


def test_metadata_reports_unavailable_git_without_dumping_environment(small_repo, monkeypatch):
    monkeypatch.setenv("PATH", "")
    data = collect_metadata(small_repo)
    assert data["git_head"] is None
    assert "environment" not in data
