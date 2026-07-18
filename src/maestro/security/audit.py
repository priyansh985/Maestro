"""Phase-0 truth-audit CLI.

Writes ``results/control_status.json`` and prints a coverage summary. Exits
non-zero if any control claims more than its evidence supports, so it can gate
CI (a control labeled ``enforced`` with no enforcement point, or ``tested`` with
no test, fails the build).

Run with: ``python -m maestro.security.audit``  (or ``maestro-audit``).
"""
from __future__ import annotations

import sys

from .control_status import (
    CONTROLS,
    audit_invariants,
    coverage_summary,
    write_report,
)


def main() -> int:
    violations = audit_invariants()
    path = write_report()
    cov = coverage_summary()

    print(f"MAESTRO-SecOps control audit — {cov['total']} controls")
    print(f"  by status: {cov['by_status']}")
    print(f"  enforced+tested+ (default-on, proven): {cov['enforced_or_above']}/{cov['total']} "
          f"(ratio {cov['enforcement_ratio']})")
    print("  side-effect-boundary security enforcement: 0 (executor gateway is Phase 2)")
    print(f"  report: {path}")

    print("\n  id            layer  status        default   control")
    for c in CONTROLS:
        print(f"  {c.control_id:<13} {c.maestro_layer:<5}  "
              f"{c.status.value:<12} {c.default_state:<8}  {c.name}")

    if violations:
        print(f"\nAUDIT FAILED — {len(violations)} inconsistency(ies):")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("\nAudit OK — every control's status is consistent with its evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
