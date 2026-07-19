"""Event-sourced journal for durable execution (the Orchestration Engine).

Durable execution — the property Temporal.io provides in production — rests on
one idea: **the workflow's history is the source of truth, not the process
memory**. Every activity (a non-deterministic, side-effecting step) records its
result here as it completes. If the process crashes and the workflow is
re-run, already-completed activities are *replayed* from this journal instead of
re-executed, which is what makes side effects exactly-once across a crash.

This is a self-contained, offline, stdlib realization of that journal. A record
is written once per ``(run_id, seq)`` (append-only); with a file path it is
also durable across process restarts (one JSON object per line). In production
you would back this with Temporal's event history — the *semantics* here are the
same; the operational scale is not.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


class JournalError(Exception):
    """Raised on an append-only violation (re-writing a recorded activity)."""


@dataclass(frozen=True)
class ActivityRecord:
    """The durable outcome of one activity in one workflow run."""

    run_id: str
    seq: int
    name: str
    status: str                 # "completed" | "failed"
    result: object = None       # JSON-serializable; present when completed
    error: str = ""             # present when failed
    attempts: int = 1


class Journal:
    """Append-only, per-``(run_id, seq)`` activity journal.

    In-memory by default; pass ``path`` for a JSONL file that survives a process
    restart (real crash recovery). Reads reconstruct the in-memory index.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._records: dict[tuple[str, int], ActivityRecord] = {}
        self._order: list[ActivityRecord] = []
        if self._path is not None and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = ActivityRecord(**json.loads(line))
            self._records[(rec.run_id, rec.seq)] = rec
            self._order.append(rec)

    def lookup(self, run_id: str, seq: int) -> ActivityRecord | None:
        """The recorded outcome for a workflow step, or ``None`` if not yet run."""
        return self._records.get((run_id, seq))

    def record(self, rec: ActivityRecord) -> ActivityRecord:
        """Append an activity outcome. A ``(run_id, seq)`` may be written once."""
        key = (rec.run_id, rec.seq)
        if key in self._records:
            raise JournalError(f"activity {key} already journaled (append-only)")
        self._records[key] = rec
        self._order.append(rec)
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(rec), separators=(",", ":")) + "\n")
        return rec

    def records_for(self, run_id: str) -> list[ActivityRecord]:
        """All recorded activities for a run, in journaled order."""
        return [r for r in self._order if r.run_id == run_id]

    def is_complete(self, run_id: str) -> bool:
        """True if the run has any recorded terminal-failure activity."""
        return any(r.run_id == run_id and r.status == "failed" for r in self._order)

    def __len__(self) -> int:
        return len(self._order)
