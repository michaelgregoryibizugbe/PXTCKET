"""
Core capture engine \u2014 performance optimized.
Uses __slots__ on ParsedPacket, minimal allocations in hot path.
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

from scapy.sendrecv import sniff
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from scapy.layers.inet6 import IPv6

from .protocols.ethernet import parse_ethernet
from .protocols.ip import parse_ip
from .protocols.tcp import parse_tcp
from .protocols.udp import parse_udp
from .protocols.icmp import parse_icmp
from .protocols.dns import parse_dns
from .protocols.http import parse_http
from .protocols.arp import parse_arp, ARPSpoofDetector
from .statistics import NetworkStatistics
from .detection.threats import ThreatDetector, ThreatAlert
from .detection.anomaly import AnomalyDetector
from .filters import PacketFilter
from .logger import PacketAnalyzerLogger


@dataclass
class ParsedPacket:
    packet_id: int
    timestamp: str
    timestamp_float: float
    size: int
    raw_bytes: bytes
    ethernet: object = None
    ip: object = None
    tcp: object = None
    udp: object = None
    icmp: object = None
    dns: object = None
    http: object = None
    arp: object = None
    protocol: str = "Unknown"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""
    alerts: List[ThreatAlert] = field(default_factory=list)
    is_suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "size": self.size,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "info": self.info,
            "is_suspicious": self.is_suspicious,
            "alerts": [a.to_dict() for a in self.alerts],
            "ethernet": self.ethernet.to_dict() if self.ethernet else None,
            "ip": self.ip.to_dict() if self.ip else None,
            "tcp": self.tcp.to_dict() if self.tcp else None,
            "udp": self.udp.to_dict() if self.udp else None,
            "icmp": self.icmp.to_dict() if self.icmp else None,
            "dns": self.dns.to_dict() if self.dns else None,
            "http": self.http.to_dict() if self.http else None,
            "arp": self.arp.to_dict() if self.arp else None,
        }


class PacketCapture:
    """Main capture and analysis engine"""

    def __init__(
        self,
        interface: str = None,
        bpf_filter: str = "",
        packet_filter: PacketFilter = None,
        threat_detector: ThreatDetector = None,
        anomaly_detector: AnomalyDetector = None,
        statistics: NetworkStatistics = None,
        logger: PacketAnalyzerLogger = None,
        on_packet_callback: Callable = None,
        on_alert_callback: Callable = None,
        max_packets: int = 0,
        promiscuous: bool = True,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_filter = packet_filter or PacketFilter()
        self.threat_detector = threat_detector or ThreatDetector()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.stats = statistics or NetworkStatistics()
        self.logger = logger or PacketAnalyzerLogger()
        self.log = self.logger.get_logger()
        self.on_packet_callback = on_packet_callback
        self.on_alert_callback = on_alert_callback
        self.max_packets = max_packets
        self.promiscuous = promiscuous

        self._arp_detector = ARPSpoofDetector()
        self.captured_packets: List[ParsedPacket] = []
        self.raw_packets: List[bytes] = []
        self.raw_timestamps: List[float] = []
        self.packet_count = 0
        self.is_running = False
        self._stop_event = threading.Event()

    def _parse_packet(self, raw: Packet) -> Optional[ParsedPacket]:
        """Parse a raw Scapy packet \u2014 tight hot path"""
        try:
            now = time.time()
            ts = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]
            size = len(raw)

            p = ParsedPacket(
                packet_id=self.packet_count + 1,
                timestamp=ts,
                timestamp_float=now,
                size=size,
                raw_bytes=bytes(raw),
            )

            # Parse layers
            p.ethernet = parse_ethernet(raw)
            p.ip = parse_ip(raw)

            if p.ip:
                p.src_ip = p.ip.src_ip
                p.dst_ip = p.ip.dst_ip
                p.protocol = p.ip.protocol_name

            if raw.haslayer(TCP):
                p.tcp = parse_tcp(raw)
                if p.tcp:
                    p.src_port = p.tcp.src_port
                    p.dst_port = p.tcp.dst_port
                    if p.protocol in ("", "Unknown"):
                        p.protocol = "TCP"
                    p.dns = parse_dns(raw)
                    if not p.dns:
                        p.http = parse_http(raw)

            elif raw.haslayer(UDP):
                p.udp = parse_udp(raw)
                if p.udp:
                    p.src_port = p.udp.src_port
                    p.dst_port = p.udp.dst_port
                    if p.protocol in ("", "Unknown"):
                        p.protocol = "UDP"
                    p.dns = parse_dns(raw)

            if raw.haslayer(ICMP):
                p.icmp = parse_icmp(raw)
                if p.icmp:
                    p.protocol = "ICMP"

            if raw.haslayer(ARP):
                p.arp = parse_arp(raw)
                if p.arp:
                    p.protocol = "ARP"
                    p.src_ip = p.arp.sender_ip
                    p.dst_ip = p.arp.target_ip

            if p.dns:
                p.protocol = "DNS"
            if p.http:
                p.protocol = "HTTP"

            # Build filter dict
            filt_info = {
                "src_ip": p.src_ip,
                "dst_ip": p.dst_ip,
                "protocol": p.protocol,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
                "size": size,
                "is_broadcast": p.ethernet.is_broadcast if p.ethernet else False,
                "is_multicast": p.ethernet.is_multicast if p.ethernet else False,
                "is_loopback": p.ip.is_loopback if p.ip else False,
            }

            ok, _ = self.packet_filter.should_capture(filt_info)
            if not ok:
                return None

            # Generate info string
            p.info = self._info(p)

            # Threat detection
            alerts = self._detect(p)
            p.alerts = alerts
            p.is_suspicious = bool(alerts)

            # Stats update
            stat_dict = {**filt_info, "tcp_flags": p.tcp.flags if p.tcp else []}
            self.stats.update(stat_dict)

            # Anomaly
            self.anomaly_detector.update_packet_size(size, p.src_ip)
            if p.protocol:
                self.anomaly_detector.update_protocol(p.protocol)
            if p.dst_port:
                self.anomaly_detector.add_port_access(p.src_ip, p.dst_port)

            return p

        except Exception:
            return None

    def _info(self, p: ParsedPacket) -> str:
        """Generate one-line packet summary"""
        if p.dns and p.dns.questions:
            q = p.dns.questions[0]
            dir_ = "Resp" if p.dns.is_response else "Query"
            return f"DNS {dir_}: {q.get('name','')} [{q.get('type','')}]"
        if p.http:
            if p.http.is_request:
                return f"{p.http.method} {p.http.host}{p.http.path}"
            return f"HTTP {p.http.status_code} {p.http.status_msg}"
        if p.tcp:
            svc = p.tcp.dst_service or p.tcp.src_service
            return f"TCP [{p.tcp.flag_str}] {svc} Win={p.tcp.window_size}"
        if p.udp:
            return f"UDP {p.udp.dst_service or ''} {p.udp.payload_size}B"
        if p.icmp:
            return f"ICMP {p.icmp.icmp_type_name}"
        if p.arp:
            return f"ARP {p.arp.operation_name} {p.arp.sender_ip}\u2192{p.arp.target_ip}"
        return ""

    def _detect(self, p: ParsedPacket) -> List[ThreatAlert]:
        alerts = []
        src, dst = p.src_ip, p.dst_ip
        if not src:
            return alerts

        td = self.threat_detector

        if p.tcp:
            dp = p.dst_port or 0
            if dp:
                a = td.detect_port_scan(src, dst, dp)
                if a:
                    alerts.append(a)
                a = td.detect_brute_force(src, dst, dp)
                if a:
                    alerts.append(a)
                a = td.detect_c2(src, dst, dp)
                if a:
                    alerts.append(a)
            if p.tcp.is_syn and not p.tcp.is_ack:
                a = td.detect_syn_flood(src, dst)
                if a:
                    alerts.append(a)
            a = td.detect_stealth_scan(src, dst, p.tcp.flags)
            if a:
                alerts.append(a)

        if p.icmp and p.icmp.is_ping:
            a = td.detect_icmp_flood(src, dst)
            if a:
                alerts.append(a)

        if p.dns:
            for q in p.dns.questions:
                a = td.detect_dns_tunneling(src, q.get("name", ""))
                if a:
                    alerts.append(a)
            if p.dns.is_suspicious:
                from .detection.threats import ThreatAlert
                alerts.append(ThreatAlert(
                    timestamp=datetime.now(),
                    alert_type="SUSPICIOUS_DNS",
                    severity="MEDIUM",
                    source_ip=src, destination_ip=dst,
                    description=p.dns.suspicious_reason,
                    recommendation="Investigate DNS query pattern.",
                ))

        if p.http and p.http.is_suspicious:
            from .detection.threats import ThreatAlert
            alerts.append(ThreatAlert(
                timestamp=datetime.now(),
                alert_type="HTTP_ATTACK",
                severity="HIGH",
                source_ip=src, destination_ip=dst,
                description=f"Attack pattern detected: {', '.join(p.http.suspicious_patterns)}",
                recommendation="Block request. Review WAF rules.",
            ))

        if p.arp:
            is_spoof, reason = self._arp_detector.check(p.arp)
            if is_spoof:
                from .detection.threats import ThreatAlert
                alerts.append(ThreatAlert(
                    timestamp=datetime.now(),
                    alert_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    source_ip=src, destination_ip=dst,
                    description=reason,
                    recommendation="Enable Dynamic ARP Inspection on switches.",
                ))

        a = td.detect_exfiltration(src, dst, p.size)
        if a:
            alerts.append(a)

        # Fire callbacks
        for alert in alerts:
            self.logger.log_alert(str(alert), alert.severity)
            if self.on_alert_callback:
                self.on_alert_callback(alert)

        return alerts

    def _handler(self, raw: Packet):
        if self._stop_event.is_set():
            return
        p = self._parse_packet(raw)
        if p is None:
            return

        self.packet_count += 1
        self.captured_packets.append(p)
        self.raw_packets.append(p.raw_bytes)
        self.raw_timestamps.append(p.timestamp_float)

        # Ring buffer
        if len(self.captured_packets) > 10000:
            self.captured_packets.pop(0)
            self.raw_packets.pop(0)
            self.raw_timestamps.pop(0)

        if self.on_packet_callback:
            self.on_packet_callback(p)

        if self.max_packets > 0 and self.packet_count >= self.max_packets:
            self.stop()

    def start(self):
        self.is_running = True
        self._stop_event.clear()
        try:
            sniff(
                iface=self.interface,
                prn=self._handler,
                filter=self.bpf_filter,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
                promisc=self.promiscuous,
            )
        except PermissionError:
            self.log.critical("Permission denied \u2014 run as root!")
        except Exception as e:
            self.log.error(f"Capture error: {e}")
        finally:
            self.is_running = False

    def start_async(self) -> threading.Thread:
        t = threading.Thread(target=self.start, daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop_event.set()
        self.is_running = False

    def get_packets(self, last_n: int = None) -> List[ParsedPacket]:
        if last_n:
            return list(self.captured_packets[-last_n:])
        return list(self.captured_packets)

    def get_alerts(self):
        return self.threat_detector.get_all_alerts()
