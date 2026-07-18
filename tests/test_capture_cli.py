"""Tests for the capture base class and the validate CLI entry point."""
from __future__ import annotations

import pytest

from maestro.telemetry.capture import Capture, PacketFeatures


def test_capture_base_is_abstract():
    cap = Capture(iface="lo", duration_s=1.0)
    assert cap.packets == []
    with pytest.raises(NotImplementedError):
        cap.sniff()
    with pytest.raises(NotImplementedError):
        cap.to_pcap("x.pcap")


def test_packet_features_defaults():
    pf = PacketFeatures(ts=1.0)
    assert pf.src == "" and pf.size == 0


def test_validate_threats_cli_returns_zero(capsys):
    from maestro.scripts.validate_threats import main
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "10 threats validated" in out
