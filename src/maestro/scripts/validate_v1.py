"""Collect offline checks without implying production readiness."""
from __future__ import annotations

import argparse
import os
import secrets
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .validation_evidence import (
    NOT_RUN,
    collect_metadata,
    file_hash,
    offline_checks,
    run_check,
    snapshot_inputs,
    write_manifest,
)


def run_validation(*, root: Path, output_dir: Path, timeout_seconds: int,
                   python: str = sys.executable) -> int:
    root, output_dir = root.resolve(), output_dir.resolve()
    if timeout_seconds <= 0:
        raise ValueError("timeout must be positive")
    if any(output_dir.is_relative_to(root / p) for p in ("src", "tests", "configs", ".github")):
        raise ValueError("output directory cannot be inside validation inputs")
    output_dir.mkdir(parents=True, exist_ok=True)
    if (output_dir / "manifest.json").exists():
        raise FileExistsError("output directory already contains a manifest; choose a new directory")
    lock = os.open(output_dir / ".validation.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(lock)
    started = datetime.now(UTC).isoformat()
    errors: list[str] = []
    try:
        before = snapshot_inputs(root)
    except (OSError, ValueError) as exc:
        before = {}
        errors.append(str(exc))
    records = []
    checks = offline_checks(python)
    try:
        for check in checks:
            print(f"Checking {check.check_id}...", flush=True)
            record = run_check(check, cwd=root, output_dir=output_dir,
                               timeout_seconds=timeout_seconds)
            records.append(record)
            print(f"{check.check_id}: {record.status}", flush=True)
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        errors.append(f"validation interrupted: {type(exc).__name__}: {exc}")
    try:
        after = snapshot_inputs(root)
    except (OSError, ValueError) as exc:
        after = {}
        errors.append(str(exc))
    stable = bool(before) and before == after
    passed = (not errors and stable and len(records) == len(checks)
              and all(r.status == "passed" for r in records))
    log_hashes = {name: file_hash(output_dir / name) for r in records
                  for name in (r.stdout_log, r.stderr_log)}
    manifest: dict[str, object] = {
        "schema_version": 1, "started_utc": started,
        "finished_utc": datetime.now(UTC).isoformat(),
        **collect_metadata(root), "source_hashes": before, "source_hashes_after": after,
        "snapshot_stable": stable, "checks": [asdict(r) for r in records],
        "log_hashes": log_hashes, "errors": errors, "offline_checks_passed": passed,
        "production_readiness": "not_assessed", "not_run": list(NOT_RUN),
    }
    write_manifest(output_dir / "manifest.json", manifest)
    print(f"Offline verification {'passed' if passed else 'failed'}; production readiness not assessed.")
    print(f"Evidence: {output_dir / 'manifest.json'}")
    return 0 if passed else 1


def _positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["offline"], default="offline")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout-seconds", type=_positive, default=1800)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[3]
    source_script = root / "src" / "maestro" / "scripts" / "validate_v1.py"
    if not source_script.is_file() or source_script.resolve() != Path(__file__).resolve():
        parser.error("offline validation requires an editable source checkout")
    suffix = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    output = args.output_dir or root / "results" / "validation" / suffix
    try:
        return run_validation(root=root, output_dir=output, timeout_seconds=args.timeout_seconds)
    except (ValueError, FileExistsError) as exc:
        parser.error(str(exc))
    except OSError as exc:
        print(f"Offline verification error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
