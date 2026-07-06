"""Unit tests for the parameter tuning module (Sec 6.3)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from maestro.agent.memory import AgentMemory
from maestro.agent.parameter_tuning import ParameterTuning


def _history(temp_path: Path, n_high: int) -> Path:
    p = temp_path / "history.json"
    items = []
    for i in range(n_high):
        items.append({"ts": 1700000000.0 + i, "severity": 0.95,
                       "alert_class": "dos", "detail": "x"})
    p.write_text(json.dumps(items), encoding="utf-8")
    return p


def test_baseline_capture_34s_sec63(tmp_path):
    p = _history(tmp_path, 0)
    m = AgentMemory(p)
    m.load()
    t = ParameterTuning(m, base_s=34.0, alpha_s=3.0)
    cap = t.tune_capture_duration()
    assert cap.duration_s == pytest.approx(34.0)


def test_after_poison_20_entries_sec63(tmp_path):
    """Sec 6.3: injecting 20 fake high-severity entries inflates capture."""
    p = _history(tmp_path, 0)
    m = AgentMemory(p)
    m.load()
    inserted = m.insert_poisoned_entries(n=20, severity=0.95)
    assert inserted == 20
    assert m.poisoned_count() == 20
    t = ParameterTuning(m, base_s=34.0, alpha_s=3.0)
    cap = t.tune_capture_duration()
    # 34 + 3*20 = 94 seconds -> much larger PCAP (Sec 6.3).
    assert cap.duration_s == pytest.approx(94.0)


def test_max_duration_clamps():
    p = Path("/tmp/none.json")
    m = AgentMemory(p)
    m.load()
    m.insert_poisoned_entries(n=20, severity=0.95)
    t = ParameterTuning(m, base_s=34.0, alpha_s=3.0, max_duration_s=50.0)
    cap = t.tune_capture_duration()
    assert cap.duration_s == pytest.approx(50.0)


def test_high_severity_threshold_filters_lows(tmp_path):
    p = _history(tmp_path, 0)
    m = AgentMemory(p)
    m.load()
    # 5 low + 3 high
    m.entries = []
    import time as _t
    from maestro.agent.memory import HistoryEntry
    for _ in range(5):
        m.entries.append(HistoryEntry(ts=_t.time(), severity=0.2, alert_class="x", detail=""))
    for _ in range(3):
        m.entries.append(HistoryEntry(ts=_t.time(), severity=0.9, alert_class="dos", detail=""))
    m.save()
    assert m.poisoned_count(threshold=0.7) == 3
    t = ParameterTuning(m, base_s=34.0, alpha_s=3.0, high_severity_threshold=0.7)
    cap = t.tune_capture_duration()
    assert cap.duration_s == pytest.approx(34 + 3 * 3)
