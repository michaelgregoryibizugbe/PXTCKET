"""Ethernet frame parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.l2 import Ether
from scapy.packet import Packet

ETHERTYPE_MAP = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "VLAN", 0x88CC: "LLDP", 0x8847: "MPLS",
}


@dataclass
class EthernetFrame:
    src_mac: str
    dst_mac: str
    ethertype: int
    ethertype_name: str
    payload_size: int
    is_broadcast: bool
    is_multicast: bool
    vlan_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "ethertype": hex(self.ethertype),
            "ethertype_name": self.ethertype_name,
            "payload_size": self.payload_size,
            "is_broadcast": self.is_broadcast,
            "is_multicast": self.is_multicast,
            "vlan_id": self.vlan_id,
        }


def parse_ethernet(packet: Packet) -> Optional[EthernetFrame]:
    if not packet.haslayer(Ether):
        return None
    eth = packet[Ether]
    dst = eth.dst or "00:00:00:00:00:00"
    is_broadcast = dst.lower() == "ff:ff:ff:ff:ff:ff"
    is_multicast = int(dst.split(":")[0], 16) & 1 == 1 and not is_broadcast
    vlan_id = None
    if eth.type == 0x8100 and packet.haslayer("Dot1Q"):
        vlan_id = packet["Dot1Q"].vlan
    return EthernetFrame(
        src_mac=eth.src,
        dst_mac=dst,
        ethertype=eth.type,
        ethertype_name=ETHERTYPE_MAP.get(eth.type, f"0x{eth.type:04x}"),
        payload_size=len(eth.payload),
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        vlan_id=vlan_id,
    )
