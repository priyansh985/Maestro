"""Unit tests for the telemetry + detection modules (Sec 3.1)."""
from __future__ import annotations

from maestro.telemetry.detection import AlertClass, SecurityDetector
from maestro.telemetry.performance import PerformanceMonitor


def test_performance_monitor_baseline_to_saturated():
    pm = PerformanceMonitor()
    s = pm.update(pkt_rate_pps=200.0)
    assert s.cpu_pct < 30   # baseline benign -> low cpu
    # The model has a first-order lag (alpha=0.3, Sec 5.2 telemetry drift), so
    # a sustained DoS flood saturates over several samples rather than instantly.
    for _ in range(15):
        s = pm.update(pkt_rate_pps=10000.0)  # Sec 6.2 dos rate
    assert s.cpu_pct > 70   # saturated
    assert s.mem_pct > 70


def test_performance_bounds():
    pm = PerformanceMonitor()
    for _ in range(20):
        s = pm.update(pkt_rate_pps=50000.0)
        assert 0 <= s.cpu_pct <= 100
        assert 0 <= s.mem_pct <= 100


def test_security_detector_dos():
    pm = PerformanceMonitor()
    det = SecurityDetector(pm)
    a = det.evaluate(pkt_rate_pps=10000.0)  # Sec 6.2
    assert a.cls == AlertClass.DOS  # classified immediately on packet rate
    # severity tracks the (lagging) CPU saturation, so it climbs as the flood
    # sustains; assert it crosses 0.5 once the modeled CPU saturates.
    for _ in range(15):
        a = det.evaluate(pkt_rate_pps=10000.0)
    assert a.cls == AlertClass.DOS
    assert a.severity > 0.5


def test_security_detector_baseline():
    pm = PerformanceMonitor()
    det = SecurityDetector(pm, baseline_pkt_rate=200.0)
    a = det.evaluate(pkt_rate_pps=100.0)
    assert a.cls == AlertClass.NORMAL
