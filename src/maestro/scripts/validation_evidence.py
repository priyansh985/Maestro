"""Offline verification primitives; results never grant deployment authority."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .windows_job import CREATE_SUSPENDED, WindowsJob

NOT_RUN = ("oidc_provider", "postgres_rls", "os_sandbox", "temporal",
           "hybrid_network", "cloud_models", "real_vertical_adapters", "browser_acceptance")


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.check_id) or not self.argv:
            raise ValueError("check requires a safe identifier and a command")


@dataclass(frozen=True)
class CheckRecord:
    check_id: str
    argv: tuple[str, ...]
    status: str
    returncode: int | None
    elapsed_seconds: float
    stdout_log: str
    stderr_log: str


def offline_checks(python: str) -> tuple[CheckSpec, ...]:
    return tuple(CheckSpec(name, (python, "-m", *args)) for name, args in (
        ("threats", ("maestro.scripts.validate_threats",)),
        ("lint", ("ruff", "check", "src", "tests")),
        ("types", ("mypy", "src")), ("tests", ("pytest", "tests", "-q")),
        ("cli_help", ("maestro.cli", "--help")), ("cli_version", ("maestro.cli", "--version")),
    ))


def _stop_owned_process(process: subprocess.Popen) -> None:
    try:
        if sys.platform != "win32":
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=30)


def run_check(check: CheckSpec, *, cwd: Path, output_dir: Path,
              timeout_seconds: int) -> CheckRecord:
    if timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_log, stderr_log = f"{check.check_id}.stdout.log", f"{check.check_id}.stderr.log"
    started = time.monotonic()
    status, returncode = "error", None
    process: subprocess.Popen | None = None
    job: WindowsJob | None = None
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    with (output_dir / stdout_log).open("wb") as out, (output_dir / stderr_log).open("wb") as err:
        try:
            if sys.platform == "win32":
                job = WindowsJob()
            process = subprocess.Popen(
                check.argv, cwd=cwd, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                env=env, shell=False, start_new_session=os.name != "nt",
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED)
                if os.name == "nt" else 0)
            if job is not None:
                job.bind_and_resume(process)
            try:
                returncode = process.wait(timeout=timeout_seconds)
                status = "passed" if returncode == 0 else "failed"
            except subprocess.TimeoutExpired:
                status = "timeout"
                err.write(b"\nValidation check exceeded its timeout.\n")
        except (OSError, subprocess.SubprocessError) as exc:
            err.write(f"{type(exc).__name__}: {exc}\n".encode())
        finally:
            if job is not None:
                try:
                    job.finish()
                except (OSError, subprocess.SubprocessError) as exc:
                    status = "error"
                    err.write(f"Process cleanup failed: {type(exc).__name__}: {exc}\n".encode())
            if process is not None and process.poll() is None:
                try:
                    _stop_owned_process(process)
                except (OSError, subprocess.SubprocessError) as exc:
                    status = "error"
                    err.write(f"Process cleanup failed: {type(exc).__name__}: {exc}\n".encode())
            if process is not None:
                returncode = process.poll()
    return CheckRecord(check.check_id, check.argv, status, returncode,
                       round(time.monotonic() - started, 6), stdout_log, stderr_log)


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot_inputs(root: Path) -> dict[str, str]:
    root = root.resolve()
    inputs = [root / p for p in ("pyproject.toml", "requirements.txt", "uv.lock")]
    inputs.extend(root / p for p in ("setup.py", "MANIFEST.in", "Dockerfile", ".dockerignore",
                                    "README.md", "LICENSE", "scripts/wheel_smoke.py")
                  if (root / p).is_file())
    for directory in ("src/maestro", "tests", "configs", ".github/workflows"):
        base = root / directory
        if not base.is_dir():
            raise ValueError(f"missing required input directory: {directory}")
        for path in base.rglob("*"):
            if path.is_symlink():
                if not path.resolve().is_relative_to(root):
                    raise ValueError(f"input symlink outside repository: {path}")
                if path.is_dir():
                    raise ValueError(f"input directory symlinks are not supported: {path}")
            if "__pycache__" in path.parts or not path.is_file():
                continue
            if (directory == "configs" or path.suffix in (".py", ".html", ".yml", ".yaml")
                    or path.name == "py.typed"):
                inputs.append(path)
    result = {}
    for path in sorted(inputs):
        if not path.resolve().is_relative_to(root):
            raise ValueError(f"input outside repository: {path}")
        result[path.relative_to(root).as_posix()] = file_hash(path)
    return result


@lru_cache(maxsize=1)
def _installed_versions() -> dict[str, str]:
    return dict(sorted((d.metadata["Name"], d.version)
                       for d in importlib.metadata.distributions() if d.metadata["Name"]))


def collect_metadata(root: Path) -> dict[str, object]:
    data: dict[str, object] = {
        "python_version": platform.python_version(), "python_executable": sys.executable,
        "platform": platform.platform(), "git_head": None, "tracked_dirty": None,
        "distributions": _installed_versions()}
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                              text=True, timeout=10, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                               cwd=root, capture_output=True, text=True, timeout=10, check=True)
        data.update(git_head=head.stdout.strip(), tracked_dirty=bool(dirty.stdout.strip()))
    except (OSError, subprocess.SubprocessError):
        data["git_status"] = "unavailable"
    return data


def write_manifest(path: Path, payload: dict[str, object]) -> None:
    descriptor, temp = tempfile.mkstemp(prefix="manifest-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)
