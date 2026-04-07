"""UDP parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import UDP
from scapy.packet import Packet
from .tcp import WELL_KNOWN_PORTS, SUSPICIOUS_PORTS


@dataclass
class UDPDatagram:
    src_port: int
    dst_port: int
    src_service: str
    dst_service: str
    length: int
    checksum: int
    payload_size: int
    is_suspicious_port: bool

    def to_dict(self) -> dict:
        return {
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_service": self.src_service,
            "dst_service": self.dst_service,
            "length": self.length,
            "payload_size": self.payload_size,
            "is_suspicious_port": self.is_suspicious_port,
        }


def parse_udp(packet: Packet) -> Optional[UDPDatagram]:
    if not packet.haslayer(UDP):
        return None
    udp = packet[UDP]
    return UDPDatagram(
        src_port=udp.sport,
        dst_port=udp.dport,
        src_service=WELL_KNOWN_PORTS.get(udp.sport, ""),
        dst_service=WELL_KNOWN_PORTS.get(udp.dport, ""),
        length=udp.len,
        checksum=udp.chksum,
        payload_size=len(udp.payload),
        is_suspicious_port=(
            udp.sport in SUSPICIOUS_PORTS or udp.dport in SUSPICIOUS_PORTS
        ),
    )
