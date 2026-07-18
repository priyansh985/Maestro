"""End-to-end tests for the TC1 (DoS) and TC2 (memory poisoning) experiments.

These reproduce the two headline results of Sec 6.2 / 6.3:
* TC1: telemetry update interval grows from ~7-8 s baseline to ~13 s under a
  10 kpps DoS flood (modeled per assumption A13).
* TC2: injecting 20 fake high-severity entries inflates the capture duration
  from 34 s to 94 s.
"""
from __future__ import annotations

import asyncio

import pytest

from maestro.config import load_config
from maestro.experiments.tc1_dos import TC1Result, _median, _modeled_telemetry_interval, run_tc1
from maestro.experiments.tc2_memory_poison import run_tc2


def _cfg(tmp_path):
    """Load the default config but redirect all writes into a temp dir."""
    cfg = load_config()
    cfg.capture.goldeneye_pcap = str(tmp_path / "goldeneye.pcap")
    cfg.memory_poison.history_path = str(tmp_path / "history.json")
    return cfg


def test_median_helper():
    assert _median([]) == 0.0
    assert _median([5.0]) == 5.0
    assert _median([1.0, 3.0]) == pytest.approx(2.0)
    assert _median([3.0, 1.0, 2.0]) == pytest.approx(2.0)


def test_modeled_interval_reproduces_paper_endpoints():
    # benign ~200 pps -> baseline; DoS 10 kpps -> stressed interval
    assert _modeled_telemetry_interval(200.0, 7.0, 13.0) == pytest.approx(7.0, abs=0.05)
    assert _modeled_telemetry_interval(10000.0, 7.0, 13.0) == pytest.approx(13.0, abs=0.05)
    # monotonic in packet rate
    lo = _modeled_telemetry_interval(1000.0, 7.0, 13.0)
    hi = _modeled_telemetry_interval(8000.0, 7.0, 13.0)
    assert 7.0 <= lo < hi <= 13.0


def test_run_tc1_reproduces_telemetry_lag(tmp_path):
    cfg = _cfg(tmp_path)
    res: TC1Result = asyncio.run(run_tc1(cfg))
    assert isinstance(res, TC1Result)
    # Sec 6.2: baseline 7-8 s -> stressed > 13 s-ish; attack interval must
    # clearly exceed the baseline (the pre-fix bug produced the opposite).
    assert res.baseline_tel_s == pytest.approx(7.0)
    assert res.attack_tel_s > res.baseline_tel_s
    assert res.attack_tel_s == pytest.approx(13.0, abs=0.1)
    d = res.as_dict()
    assert d["tel_lag_ratio"] > 1.5
    # metrics recorded for baseline + attack + recovery windows
    assert len(res.metrics) == 5 + res.iterations + 5
    # under the flood the modeled CPU saturates well past the 80% threshold
    attack_metrics = [m for m in res.metrics if m.pkt_rate_pps > 1000]
    assert max(m.cpu_pct for m in attack_metrics) > 80.0


def test_run_tc2_reproduces_capture_inflation(tmp_path):
    cfg = _cfg(tmp_path)
    res = run_tc2(cfg)
    assert res.n_poisoned == 20
    assert res.baseline_capture_duration_s == pytest.approx(34.0)
    assert res.post_capture_duration_s == pytest.approx(94.0)
    d = res.as_dict()
    assert d["ratio"] == pytest.approx(94.0 / 34.0, rel=1e-3)
    assert res.n_post_high_severity - res.n_baseline_high_severity == 20
