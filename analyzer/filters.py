"""Packet filtering engine"""
from __future__ import annotations
from typing import Callable, List, Optional


class PacketFilter:
    """High-speed packet filter \u2014 all checks in one pass"""

    __slots__ = (
        "ip_whitelist", "ip_blacklist", "port_filter",
        "protocol_filter", "exclude_broadcast", "exclude_multicast",
        "exclude_loopback", "min_packet_size", "max_packet_size",
        "_custom_rules",
    )

    def __init__(self):
        self.ip_whitelist: List[str] = []
        self.ip_blacklist: List[str] = []
        self.port_filter: Optional[List[int]] = None
        self.protocol_filter: Optional[List[str]] = None
        self.exclude_broadcast = False
        self.exclude_multicast = False
        self.exclude_loopback = True
        self.min_packet_size = 0
        self.max_packet_size = 65535
        self._custom_rules: List[Callable] = []

    def set_protocol_filter(self, protos: List[str]):
        self.protocol_filter = [p.upper() for p in protos]

    def set_port_filter(self, ports: List[int]):
        self.port_filter = ports

    def add_ip_to_whitelist(self, ip: str):
        self.ip_whitelist.append(ip)

    def add_ip_to_blacklist(self, ip: str):
        self.ip_blacklist.append(ip)

    def add_custom_rule(self, fn: Callable):
        self._custom_rules.append(fn)

    def should_capture(self, pkt: dict) -> tuple[bool, str]:
        """Single-pass filter \u2014 returns (pass, reason)"""
        size = pkt.get("size", 0)
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        proto = (pkt.get("protocol") or "").upper()
        sp = pkt.get("src_port")
        dp = pkt.get("dst_port")

        if pkt.get("is_loopback") and self.exclude_loopback:
            return False, "loopback"
        if pkt.get("is_broadcast") and self.exclude_broadcast:
            return False, "broadcast"
        if pkt.get("is_multicast") and self.exclude_multicast:
            return False, "multicast"
        if size < self.min_packet_size or size > self.max_packet_size:
            return False, "size"
        if src in self.ip_blacklist or dst in self.ip_blacklist:
            return False, "blacklist"
        if self.ip_whitelist and src not in self.ip_whitelist and dst not in self.ip_whitelist:
            return False, "whitelist"
        if self.protocol_filter and proto not in self.protocol_filter:
            return False, "protocol"
        if self.port_filter:
            if sp not in self.port_filter and dp not in self.port_filter:
                return False, "port"
        for rule in self._custom_rules:
            try:
                if not rule(pkt):
                    return False, "custom"
            except Exception:
                pass
        return True, "pass"

    def from_bpf_like(self, expr: str):
        """Parse simple BPF-like filter expressions"""
        parts = expr.lower().split()
        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok in ("tcp", "udp", "icmp", "arp", "dns"):
                self.set_protocol_filter([tok.upper()])
            elif tok == "port" and i + 1 < len(parts):
                try:
                    self.set_port_filter([int(parts[i + 1])])
                    i += 1
                except ValueError:
                    pass
            elif tok == "host" and i + 1 < len(parts):
                self.add_ip_to_whitelist(parts[i + 1])
                i += 1
            elif tok == "not" and i + 1 < len(parts):
                if parts[i + 1] == "broadcast":
                    self.exclude_broadcast = True
                    i += 1
            i += 1
