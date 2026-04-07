"""IPv4 and IPv6 parser"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF",
}

DSCP_MAP = {
    0: "Default", 46: "EF", 10: "AF11", 18: "AF21",
    26: "AF31", 34: "AF41", 8: "CS1", 16: "CS2",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


@dataclass
class IPPacket:
    version: int
    src_ip: str
    dst_ip: str
    protocol: int
    protocol_name: str
    ttl: int
    total_length: int
    flags: Optional[str]
    fragment_offset: Optional[int]
    checksum: Optional[int]
    is_fragmented: bool
    is_private_src: bool
    is_private_dst: bool
    is_loopback: bool
    dscp: Optional[int] = None
    dscp_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "ttl": self.ttl,
            "total_length": self.total_length,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "is_fragmented": self.is_fragmented,
            "is_private_src": self.is_private_src,
            "is_private_dst": self.is_private_dst,
            "is_loopback": self.is_loopback,
        }


def parse_ip(packet: Packet) -> Optional[IPPacket]:
    if packet.haslayer(IP):
        ip = packet[IP]
        flags = []
        if ip.flags.DF:
            flags.append("DF")
        if ip.flags.MF:
            flags.append("MF")
        dscp = ip.tos >> 2
        return IPPacket(
            version=4,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=ip.proto,
            protocol_name=PROTO_MAP.get(ip.proto, str(ip.proto)),
            ttl=ip.ttl,
            total_length=ip.len,
            flags="|".join(flags) or "None",
            fragment_offset=ip.frag,
            checksum=ip.chksum,
            is_fragmented=ip.frag > 0 or bool(ip.flags.MF),
            is_private_src=_is_private(ip.src),
            is_private_dst=_is_private(ip.dst),
            is_loopback=_is_loopback(ip.src),
            dscp=dscp,
            dscp_name=DSCP_MAP.get(dscp, str(dscp)),
        )
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        return IPPacket(
            version=6,
            src_ip=ip6.src,
            dst_ip=ip6.dst,
            protocol=ip6.nh,
            protocol_name=PROTO_MAP.get(ip6.nh, str(ip6.nh)),
            ttl=ip6.hlim,
            total_length=ip6.plen,
            flags=None,
            fragment_offset=None,
            checksum=None,
            is_fragmented=False,
            is_private_src=_is_private(ip6.src),
            is_private_dst=_is_private(ip6.dst),
            is_loopback=_is_loopback(ip6.src),
        )
    return None
