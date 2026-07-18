"""Tests for the file-backed agent memory (Sec 3.1 logging + Sec 6.3 memory)."""
from __future__ import annotations

import json

from maestro.agent.memory import AgentMemory, HistoryEntry


def test_load_missing_file_is_empty(tmp_path):
    m = AgentMemory(tmp_path / "nope.json")
    m.load()
    assert m.entries == []


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "history.json"
    m = AgentMemory(p)
    m.append(HistoryEntry(ts=1.0, severity=0.9, alert_class="dos", detail="x"))
    m.append(HistoryEntry(ts=2.0, severity=0.1, alert_class="normal", detail="y"))
    m2 = AgentMemory(p)
    m2.load()
    assert len(m2.entries) == 2
    assert m2.entries[0].alert_class == "dos"
    assert m2.entries[1].severity == 0.1


def test_corrupt_json_tolerated(tmp_path):
    p = tmp_path / "history.json"
    p.write_text("{not valid json", encoding="utf-8")
    m = AgentMemory(p)
    m.load()  # must not raise
    assert m.entries == []


def test_poisoned_count_threshold(tmp_path):
    m = AgentMemory(tmp_path / "h.json")
    m.entries = [
        HistoryEntry(ts=0, severity=0.2, alert_class="x", detail=""),
        HistoryEntry(ts=0, severity=0.75, alert_class="x", detail=""),
        HistoryEntry(ts=0, severity=0.95, alert_class="x", detail=""),
    ]
    assert m.poisoned_count(threshold=0.7) == 2
    assert m.poisoned_count(threshold=0.9) == 1


def test_insert_poisoned_and_clear(tmp_path):
    p = tmp_path / "h.json"
    m = AgentMemory(p)
    assert m.insert_poisoned_entries(20, severity=0.95) == 20
    assert m.poisoned_count() == 20
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert len(raw) == 20
    m.clear()
    assert m.entries == []
    assert json.loads(p.read_text(encoding="utf-8")) == []


def test_freeze_is_best_effort(tmp_path):
    p = tmp_path / "h.json"
    m = AgentMemory(p)
    m.insert_poisoned_entries(1)
    m.freeze()  # must not raise even if chmod is a no-op on the platform
    assert p.exists()
