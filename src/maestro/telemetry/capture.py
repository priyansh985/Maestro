"""PacketCapture module (Sec 3.1).

The paper uses Scapy for parsing PCAPs during live + replay (Sec 6.1).
Because we want the reproduction to **also work without a NIC**, we capture
synthetic telemetry by default; users with a NIC and libpcap can subclass
this module to attach to a real interface (Sec 3.1 first sentence).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger("maestro.capture")


@dataclass
class PacketFeatures:
    """Packet-level features consumed by downstream telemetry (Sec 6.1)."""
    ts: float
    src: str = ""
    dst: str = ""
    proto: str = ""
    size: int = 0
    flags: str = ""


@dataclass
class Capture:
    """Abstract base for a packet-capture session."""
    iface: str
    duration_s: float
    packets: list[PacketFeatures] = field(default_factory=list)

    def sniff(self, on_packet=None) -> list[PacketFeatures]:
        """Subclasses override. Raises NotImplementedError if unsupported."""
        raise NotImplementedError("Subclasses implement sniff()")

    def to_pcap(self, path: str) -> None:
        raise NotImplementedError
