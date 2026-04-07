"""ICMP parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import ICMP
from scapy.packet import Packet

ICMP_TYPES = {
    0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
}

ICMP_UNREACH = {
    0: "Net Unreachable", 1: "Host Unreachable",
    2: "Protocol Unreachable", 3: "Port Unreachable",
    4: "Fragmentation Needed",
}


@dataclass
class ICMPPacket:
    icmp_type: int
    icmp_type_name: str
    code: int
    code_name: str
    checksum: int
    identifier: Optional[int]
    sequence: Optional[int]
    payload_size: int
    is_ping: bool
    is_unreachable: bool

    def to_dict(self) -> dict:
        return {
            "type": self.icmp_type,
            "type_name": self.icmp_type_name,
            "code": self.code,
            "code_name": self.code_name,
            "identifier": self.identifier,
            "sequence": self.sequence,
            "payload_size": self.payload_size,
        }


def parse_icmp(packet: Packet) -> Optional[ICMPPacket]:
    if not packet.haslayer(ICMP):
        return None
    icmp = packet[ICMP]
    code_name = ICMP_UNREACH.get(icmp.code, "") if icmp.type == 3 else ""
    return ICMPPacket(
        icmp_type=icmp.type,
        icmp_type_name=ICMP_TYPES.get(icmp.type, f"Type{icmp.type}"),
        code=icmp.code,
        code_name=code_name,
        checksum=icmp.chksum,
        identifier=getattr(icmp, "id", None),
        sequence=getattr(icmp, "seq", None),
        payload_size=len(icmp.payload),
        is_ping=icmp.type in (0, 8),
        is_unreachable=icmp.type == 3,
    )
