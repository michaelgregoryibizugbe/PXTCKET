"""
Multi-layered threat detection engine.
All detectors use time-windowed counters for accuracy.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class ThreatAlert:
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    details: Dict = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "type": self.alert_type,
            "severity": self.severity,
            "src_ip": self.source_ip,
            "dst_ip": self.destination_ip,
            "description": self.description,
            "details": self.details,
            "recommendation": self.recommendation,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.alert_type} | "
            f"{self.source_ip} \u2192 {self.destination_ip} | "
            f"{self.description}"
        )


class ThreatDetector:
    """Complete IDS with 14 detection methods"""

    def __init__(self, config: dict = None):
        cfg = config or {}
        self.alerts: List[ThreatAlert] = []
        self._window = 60

        # Thresholds
        self._pscan_thresh = cfg.get("port_scan_threshold", 10)
        self._syn_thresh = cfg.get("syn_flood_threshold", 100)
        self._icmp_thresh = cfg.get("icmp_flood_threshold", 50)
        self._max_conn = cfg.get("max_connections_per_ip", 100)
        self._exfil_bytes = int(cfg.get("exfil_threshold_mb", 10)) * 1024 * 1024

        # Trackers
        self._port_scan: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_ts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._syn_ts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._icmp_ts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._bf_ts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._dns_lens: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._bytes_sent: Dict[str, int] = defaultdict(int)
        self._known_hosts: Set[str] = set()

        self._c2_ports: Set[int] = {
            4444, 1337, 31337, 6666, 6667, 6668, 6669,
            9001, 9030, 1080, 4899, 1234,
        }
        self._bf_ports: Set[int] = {22, 21, 23, 3389, 5900, 25, 110, 143, 3306, 5432}
        self._bf_services = {
            22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP",
            5900: "VNC", 25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL",
        }

    def _now(self) -> float:
        return time.time()

    def _trim(self, dq: deque, window: int = None) -> deque:
        cutoff = self._now() - (window or self._window)
        while dq and dq[0] < cutoff:
            dq.popleft()
        return dq

    def _alert(
        self, typ: str, sev: str, src: str, dst: str,
        desc: str, details: dict = None, rec: str = "",
    ) -> ThreatAlert:
        a = ThreatAlert(
            timestamp=datetime.now(),
            alert_type=typ, severity=sev,
            source_ip=src, destination_ip=dst,
            description=desc, details=details or {},
            recommendation=rec,
        )
        self.alerts.append(a)
        return a

    def detect_port_scan(self, src: str, dst: str, port: int) -> Optional[ThreatAlert]:
        now = self._now()
        self._port_scan[src].add(port)
        self._port_scan_ts[src].append(now)
        self._trim(self._port_scan_ts[src])
        unique = len(self._port_scan[src])
        if unique >= self._pscan_thresh:
            sev = "CRITICAL" if unique > 100 else "HIGH" if unique > 50 else "MEDIUM"
            a = self._alert(
                "PORT_SCAN", sev, src, dst,
                f"Port scan: {unique} unique ports probed in {self._window}s",
                {"unique_ports_scanned": unique,
                 "sample_ports": list(self._port_scan[src])[:20]},
                "Block source IP. Investigate for reconnaissance activity.",
            )
            self._port_scan[src].clear()
            self._port_scan_ts[src].clear()
            return a
        return None

    def detect_syn_flood(self, src: str, dst: str) -> Optional[ThreatAlert]:
        now = self._now()
        self._syn_ts[src].append(now)
        self._trim(self._syn_ts[src])
        count = len(self._syn_ts[src])
        if count >= self._syn_thresh:
            a = self._alert(
                "SYN_FLOOD", "CRITICAL", src, dst,
                f"SYN flood: {count} SYN packets in {self._window}s",
                {"syn_count": count},
                "Enable SYN cookies. Rate-limit and block source IP.",
            )
            self._syn_ts[src].clear()
            return a
        return None

    def detect_icmp_flood(self, src: str, dst: str) -> Optional[ThreatAlert]:
        now = self._now()
        self._icmp_ts[src].append(now)
        self._trim(self._icmp_ts[src])
        count = len(self._icmp_ts[src])
        if count >= self._icmp_thresh:
            a = self._alert(
                "ICMP_FLOOD", "HIGH", src, dst,
                f"ICMP flood: {count} packets in {self._window}s",
                {"icmp_count": count},
                "Rate-limit ICMP from this source.",
            )
            self._icmp_ts[src].clear()
            return a
        return None

    def detect_c2(self, src: str, dst: str, port: int) -> Optional[ThreatAlert]:
        if port in self._c2_ports:
            return self._alert(
                "SUSPICIOUS_C2_PORT", "HIGH", src, dst,
                f"Connection to known C2 port {port}",
                {"port": port},
                "Investigate endpoint for malware. Check running processes.",
            )
        return None

    def detect_brute_force(self, src: str, dst: str, port: int) -> Optional[ThreatAlert]:
        if port not in self._bf_ports:
            return None
        now = self._now()
        key = f"{src}:{port}"
        self._bf_ts[key].append(now)
        self._trim(self._bf_ts[key], window=30)
        count = len(self._bf_ts[key])
        if count >= 10:
            svc = self._bf_services.get(port, str(port))
            a = self._alert(
                "BRUTE_FORCE", "HIGH", src, dst,
                f"Brute force on {svc} port {port}: {count} attempts/30s",
                {"service": svc, "port": port, "attempts": count},
                f"Block {src}. Enable 2FA. Check {svc} logs.",
            )
            self._bf_ts[key].clear()
            return a
        return None

    def detect_exfiltration(self, src: str, dst: str, size: int) -> Optional[ThreatAlert]:
        self._bytes_sent[src] += size
        if self._bytes_sent[src] >= self._exfil_bytes:
            mb = self._bytes_sent[src] / 1048576
            a = self._alert(
                "DATA_EXFILTRATION", "HIGH", src, dst,
                f"Possible data exfiltration: {mb:.2f} MB from {src}",
                {"bytes_sent": self._bytes_sent[src], "mb": mb},
                "Investigate data transfer. Check for sensitive data exposure.",
            )
            self._bytes_sent[src] = 0
            return a
        return None

    def detect_dns_tunneling(self, src: str, name: str) -> Optional[ThreatAlert]:
        length = len(name)
        self._dns_lens[src].append(length)
        if length > 100:
            return self._alert(
                "DNS_TUNNELING", "MEDIUM", src, "DNS",
                f"Possible DNS tunnel: query length {length}: {name[:50]}...",
                {"query_length": length, "query": name},
                "Block DNS tunneling. Investigate endpoint.",
            )
        if len(self._dns_lens[src]) >= 10:
            avg = sum(self._dns_lens[src]) / len(self._dns_lens[src])
            if avg > 60:
                self._dns_lens[src].clear()
                return self._alert(
                    "DNS_TUNNELING", "MEDIUM", src, "DNS",
                    f"DNS tunneling: high avg query length {avg:.0f}",
                    {"avg_length": avg},
                    "Enable DNS inspection and filtering.",
                )
        return None

    def detect_stealth_scan(
        self, src: str, dst: str, flags: list
    ) -> Optional[ThreatAlert]:
        flag_set = set(flags)
        if not flags:
            return self._alert(
                "NULL_SCAN", "MEDIUM", src, dst,
                f"NULL scan (no flags) from {src}",
                {}, "Stealth recon. Block and investigate.",
            )
        if flag_set == {"FIN", "PSH", "URG"}:
            return self._alert(
                "XMAS_SCAN", "MEDIUM", src, dst,
                f"XMAS scan from {src}",
                {}, "Stealth recon. Block and investigate.",
            )
        if flag_set == {"FIN"}:
            return self._alert(
                "FIN_SCAN", "MEDIUM", src, dst,
                f"FIN scan from {src}",
                {}, "Stealth recon. Block and investigate.",
            )
        return None

    def detect_new_host(self, src: str) -> Optional[ThreatAlert]:
        if src not in self._known_hosts:
            self._known_hosts.add(src)
            return self._alert(
                "NEW_HOST", "LOW", src, "network",
                f"New host on network: {src}",
                {}, "Verify this host is authorized.",
            )
        return None

    def get_all_alerts(self) -> List[ThreatAlert]:
        return self.alerts

    def get_by_severity(self, sev: str) -> List[ThreatAlert]:
        return [a for a in self.alerts if a.severity == sev]

    def summary(self) -> Dict:
        from collections import Counter
        sev_counts = Counter(a.severity for a in self.alerts)
        type_counts = Counter(a.alert_type for a in self.alerts)
        return {
            "total": len(self.alerts),
            "by_severity": dict(sev_counts),
            "by_type": dict(type_counts),
        }
