"""Network traffic statistics engine"""
from __future__ import annotations

import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SessionInfo:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    bytes_count: int = 0
    is_established: bool = False

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def to_dict(self) -> dict:
        return {
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "packets": self.packet_count,
            "bytes": self.bytes_count,
            "duration": f"{self.duration:.2f}s",
            "established": self.is_established,
        }


class NetworkStatistics:
    """Lock-free statistics engine optimized for high throughput"""

    __slots__ = (
        "start_time", "total_packets", "total_bytes",
        "protocol_counter", "src_ip_counter", "dst_ip_counter",
        "ip_pair_counter", "ip_bytes", "src_port_counter",
        "dst_port_counter", "tcp_flags_counter", "packet_sizes",
        "size_distribution", "pps_samples", "_last_pps_time",
        "_pps_count", "sessions", "bandwidth_samples",
        "dns_queries", "http_methods", "http_status_codes",
        "malformed_packets", "fragment_count",
    )

    def __init__(self):
        self.start_time = time.monotonic()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counter: Counter = Counter()
        self.src_ip_counter: Counter = Counter()
        self.dst_ip_counter: Counter = Counter()
        self.ip_pair_counter: Counter = Counter()
        self.ip_bytes: Dict[str, int] = defaultdict(int)
        self.src_port_counter: Counter = Counter()
        self.dst_port_counter: Counter = Counter()
        self.tcp_flags_counter: Counter = Counter()
        self.packet_sizes: List[int] = []
        self.size_distribution: Dict[str, int] = defaultdict(int)
        self.pps_samples: List[float] = []
        self._last_pps_time = time.monotonic()
        self._pps_count = 0
        self.sessions: Dict[str, SessionInfo] = {}
        self.bandwidth_samples: List[tuple] = []
        self.dns_queries: Counter = Counter()
        self.http_methods: Counter = Counter()
        self.http_status_codes: Counter = Counter()
        self.malformed_packets = 0
        self.fragment_count = 0

    def update(self, pkt: dict):
        """Hot path \u2014 called for every packet. Keep tight."""
        self.total_packets += 1
        size = pkt.get("size", 0)
        self.total_bytes += size

        now = time.monotonic()

        # PPS
        self._pps_count += 1
        elapsed = now - self._last_pps_time
        if elapsed >= 1.0:
            self.pps_samples.append(self._pps_count / elapsed)
            if len(self.pps_samples) > 60:
                del self.pps_samples[0]
            self._pps_count = 0
            self._last_pps_time = now

        # Bandwidth sample
        self.bandwidth_samples.append((now, size))
        if len(self.bandwidth_samples) > 3000:
            cutoff = now - 300
            self.bandwidth_samples = [
                s for s in self.bandwidth_samples if s[0] > cutoff
            ]

        # Packet size
        if len(self.packet_sizes) < 10000:
            self.packet_sizes.append(size)
        if size < 64:
            self.size_distribution["<64B"] += 1
        elif size < 256:
            self.size_distribution["64-255B"] += 1
        elif size < 512:
            self.size_distribution["256-511B"] += 1
        elif size < 1024:
            self.size_distribution["512-1023B"] += 1
        else:
            self.size_distribution["1024B+"] += 1

        # Protocol
        proto = pkt.get("protocol", "")
        if proto:
            self.protocol_counter[proto] += 1

        # IPs
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if src:
            self.src_ip_counter[src] += 1
            self.ip_bytes[src] += size
        if dst:
            self.dst_ip_counter[dst] += 1
        if src and dst:
            self.ip_pair_counter[f"{src}\u2192{dst}"] += 1

        # Ports
        sp = pkt.get("src_port")
        dp = pkt.get("dst_port")
        if sp:
            self.src_port_counter[sp] += 1
        if dp:
            self.dst_port_counter[dp] += 1

        # TCP flags
        for flag in pkt.get("tcp_flags", []):
            self.tcp_flags_counter[flag] += 1

        # Sessions
        if src and dst and sp and dp:
            key = f"{src}:{sp}-{dst}:{dp}"
            rev = f"{dst}:{dp}-{src}:{sp}"
            if key in self.sessions:
                s = self.sessions[key]
                s.packet_count += 1
                s.bytes_count += size
                s.last_seen = now
            elif rev in self.sessions:
                s = self.sessions[rev]
                s.packet_count += 1
                s.bytes_count += size
                s.last_seen = now
            else:
                self.sessions[key] = SessionInfo(
                    src_ip=src, dst_ip=dst,
                    src_port=sp, dst_port=dp,
                    protocol=proto,
                    start_time=now, last_seen=now,
                    packet_count=1, bytes_count=size,
                )

    def current_bandwidth(self) -> float:
        """Mbps over last second"""
        now = time.monotonic()
        recent = sum(b for t, b in self.bandwidth_samples if t > now - 1)
        return (recent * 8) / 1_000_000

    def avg_pps(self) -> float:
        if not self.pps_samples:
            return 0.0
        return sum(self.pps_samples[-10:]) / len(self.pps_samples[-10:])

    def avg_pkt_size(self) -> float:
        if not self.packet_sizes:
            return 0.0
        recent = self.packet_sizes[-1000:]
        return sum(recent) / len(recent)

    def get_summary(self) -> dict:
        return {
            "uptime_seconds": time.monotonic() - self.start_time,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_mb": self.total_bytes / 1048576,
            "avg_pps": self.avg_pps(),
            "current_bandwidth_mbps": self.current_bandwidth(),
            "avg_packet_size": self.avg_pkt_size(),
            "unique_src_ips": len(self.src_ip_counter),
            "unique_dst_ips": len(self.dst_ip_counter),
            "active_sessions": len(self.sessions),
            "protocol_distribution": dict(self.protocol_counter.most_common(15)),
            "size_distribution": dict(self.size_distribution),
            "top_talkers": self.src_ip_counter.most_common(10),
            "top_destinations": self.dst_ip_counter.most_common(10),
            "top_ports": self.dst_port_counter.most_common(10),
            "tcp_flags": dict(self.tcp_flags_counter),
            "ip_bytes": dict(sorted(
                self.ip_bytes.items(), key=lambda x: x[1], reverse=True
            )[:10]),
        }
