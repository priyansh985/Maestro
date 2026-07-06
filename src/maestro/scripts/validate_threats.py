"""Sanity-check that ``configs/threats.yaml`` matches Eq. (1) R = P*I*E and
that risk scores match Sec 4.3.2 Table 4 exactly.
"""
from __future__ import annotations

import sys

from ..maestro.threats import load_threats


def main() -> int:
    threats = load_threats()
    expected = {
        1: 12, 2: 9, 3: 18, 4: 12, 5: 12, 6: 18, 7: 27, 8: 9, 9: 12, 10: 18,
    }
    ok = True
    for t in threats:
        if expected[t.id] != t.risk_score:
            print(f"Threat {t.id} ({t.name}): paper says {expected[t.id]} "
                  f"got {t.risk_score}")
            ok = False
    if not ok:
        print("Validation FAILED")
        return 1
    print(f"OK - {len(threats)} threats validated against Table 4")
    return 0


if __name__ == "__main__":
    sys.exit(main())
