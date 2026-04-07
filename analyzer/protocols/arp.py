"""ARP parser and spoof detector"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict
from scapy.layers.l2 import ARP
from scapy.packet import Packet

ARP_OPS = {1: "Request", 2: "Reply", 3: "RARP-Req", 4: "RARP-Rep"}


@dataclass
class ARPPacket:
    operation: int
    operation_name: str
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    is_gratuitous: bool
    is_probe: bool
    is_announcement: bool

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "operation_name": self.operation_name,
            "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "is_gratuitous": self.is_gratuitous,
        }


class ARPSpoofDetector:
    def __init__(self):
        self.table: Dict[str, str] = {}
        self.conflicts: Dict[str, int] = {}

    def check(self, arp: ARPPacket) -> tuple[bool, str]:
        ip, mac = arp.sender_ip, arp.sender_mac
        if ip == "0.0.0.0" or mac == "00:00:00:00:00:00":
            return False, ""
        if ip in self.table:
            known = self.table[ip]
            if known != mac:
                self.conflicts[ip] = self.conflicts.get(ip, 0) + 1
                return (
                    True,
                    f"ARP SPOOF: IP {ip} MAC changed {known} \u2192 {mac} "
                    f"(#{self.conflicts[ip]})",
                )
        else:
            self.table[ip] = mac
        return False, ""


def parse_arp(packet: Packet) -> Optional[ARPPacket]:
    if not packet.haslayer(ARP):
        return None
    arp = packet[ARP]
    src, dst = arp.psrc, arp.pdst
    return ARPPacket(
        operation=arp.op,
        operation_name=ARP_OPS.get(arp.op, str(arp.op)),
        sender_mac=arp.hwsrc,
        sender_ip=src,
        target_mac=arp.hwdst,
        target_ip=dst,
        is_gratuitous=src == dst and arp.op == 2,
        is_probe=src == "0.0.0.0",
        is_announcement=src == dst and arp.op == 1,
    )
