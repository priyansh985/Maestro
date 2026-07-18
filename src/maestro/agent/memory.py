"""Agent memory store (Sec 3.1 Reporting & Logging Module + Sec 6.3 memory).

Implements the file-backed episodic memory that the parameter-tuning module
consumes, including the replayed TC2 attack where the attacker inserts 20
fake high-severity entries into ``history.json`` (Sec 6.3).
"""
from __future__ import annotations

import contextlib
import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class HistoryEntry:
    """One row of ``history.json`` (Sec 6.3)."""
    ts: float
    severity: float        # 0..1
    alert_class: str
    detail: str


def _entry_to_dict(e: HistoryEntry) -> dict:
    return {"ts": e.ts, "severity": e.severity, "alert_class": e.alert_class, "detail": e.detail}


class AgentMemory:
    """Episodic + parameter-tuning memory."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.entries: list[HistoryEntry] = []

    def load(self) -> None:
        if not self.path.exists():
            self.entries = []
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self.entries = []
            return
        self.entries = [
            HistoryEntry(
                ts=float(r.get("ts", 0.0)),
                severity=float(r.get("severity", 0.0)),
                alert_class=str(r.get("alert_class", "")),
                detail=str(r.get("detail", "")),
            )
            for r in raw
        ]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([_entry_to_dict(e) for e in self.entries], indent=2),
            encoding="utf-8",
        )

    def append(self, entry: HistoryEntry) -> None:
        self.entries.append(entry)
        self.save()

    def insert_poisoned_entries(self, n: int, severity: float = 0.95) -> int:
        """Sec 6.3 TC2: insert ``n`` fake high-severity entries."""
        import time as _t
        for _ in range(n):
            self.entries.append(
                HistoryEntry(ts=_t.time(),
                            severity=severity,
                            alert_class="dos",
                            detail="synthetic high-severity alert (poisoned)")
            )
        self.save()
        return n

    def poisoned_count(self, threshold: float = 0.7) -> int:
        """Return number of entries with high severity (>=threshold)."""
        return sum(1 for e in self.entries if e.severity >= threshold)

    def clear(self) -> None:
        self.entries = []
        self.save()

    def append_alert_if(self, *, alert_cls: str, severity: float, detail: str) -> None:
        import time as _t
        self.entries.append(HistoryEntry(ts=_t.time(), severity=severity,
                                         alert_class=alert_cls, detail=detail))
        self.save()

    def freeze(self) -> None:
        """Sec 5.3 L2 mitigation: chmod read-only (best-effort on POSIX)."""
        with contextlib.suppress(OSError):
            self.path.chmod(0o444)
