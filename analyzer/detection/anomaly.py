"""Statistical anomaly detection"""
from __future__ import annotations
import time
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AnomalyEvent:
    timestamp: float
    event_type: str
    description: str
    score: float
    ip: str


class AnomalyDetector:
    """Z-score based anomaly detection"""

    def __init__(self, window: int = 100):
        self._window = window
        self._pkt_sizes: deque = deque(maxlen=window)
        self._ip_sizes: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self._proto_counts: Dict[str, int] = defaultdict(int)
        self._total = 0
        self._port_access: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.anomalies: list[AnomalyEvent] = []

    def _zscore(self, v: float, data: deque) -> float:
        if len(data) < 10:
            return 0.0
        try:
            mean = statistics.mean(data)
            sd = statistics.stdev(data)
            return abs((v - mean) / sd) if sd > 0 else 0.0
        except Exception:
            return 0.0

    def update_packet_size(self, size: int, ip: str) -> Optional[AnomalyEvent]:
        self._pkt_sizes.append(size)
        self._ip_sizes[ip].append(size)
        z = self._zscore(size, self._pkt_sizes)
        if z > 3.0 and len(self._pkt_sizes) >= 10:
            ev = AnomalyEvent(
                timestamp=time.time(),
                event_type="ANOMALOUS_PACKET_SIZE",
                description=f"Anomalous packet {size}B from {ip} (z={z:.2f})",
                score=min(100, z * 20),
                ip=ip,
            )
            self.anomalies.append(ev)
            return ev
        return None

    def update_protocol(self, proto: str) -> Optional[AnomalyEvent]:
        self._proto_counts[proto] += 1
        self._total += 1
        if self._total < 100:
            return None
        ratio = self._proto_counts[proto] / self._total
        if ratio > 0.95 and proto not in ("TCP", "UDP", "ICMP"):
            ev = AnomalyEvent(
                timestamp=time.time(),
                event_type="PROTOCOL_DOMINANCE",
                description=f"{proto} dominates: {ratio:.1%} of traffic",
                score=ratio * 100,
                ip="network",
            )
            self.anomalies.append(ev)
            return ev
        return None

    def add_port_access(self, ip: str, port: int):
        self._port_access[ip].append(port)

    def port_entropy(self, ip: str) -> float:
        ports = self._port_access.get(ip)
        if not ports or len(ports) < 5:
            return 0.0
        return len(set(ports)) / len(ports)

    def report(self) -> dict:
        return {
            "total_anomalies": len(self.anomalies),
            "high_score": [
                {"type": a.event_type, "desc": a.description, "score": a.score}
                for a in self.anomalies if a.score > 70
            ],
            "protocol_distribution": dict(self._proto_counts),
        }
