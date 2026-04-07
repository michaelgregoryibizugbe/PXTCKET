"""Threat detection tests"""
import pytest
from analyzer.detection.threats import ThreatDetector


class TestThreatDetector:
    def setup_method(self):
        self.td = ThreatDetector(config={
            "port_scan_threshold": 5,
            "syn_flood_threshold": 10,
            "icmp_flood_threshold": 5,
        })

    def test_port_scan_detection(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        alert = None
        for port in range(1, 10):
            alert = self.td.detect_port_scan(src, dst, port)
        assert alert is not None
        assert alert.alert_type == "PORT_SCAN"
        assert alert.source_ip == src

    def test_syn_flood_detection(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        alert = None
        for _ in range(15):
            alert = self.td.detect_syn_flood(src, dst)
        assert alert is not None
        assert alert.alert_type == "SYN_FLOOD"
        assert alert.severity == "CRITICAL"

    def test_icmp_flood_detection(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        alert = None
        for _ in range(8):
            alert = self.td.detect_icmp_flood(src, dst)
        assert alert is not None
        assert alert.alert_type == "ICMP_FLOOD"

    def test_c2_port_detection(self):
        alert = self.td.detect_c2("10.0.0.1", "1.2.3.4", 4444)
        assert alert is not None
        assert alert.alert_type == "SUSPICIOUS_C2_PORT"

    def test_brute_force_detection(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        alert = None
        for _ in range(15):
            alert = self.td.detect_brute_force(src, dst, 22)
        assert alert is not None
        assert alert.alert_type == "BRUTE_FORCE"
        assert "SSH" in alert.description

    def test_null_scan_detection(self):
        alert = self.td.detect_stealth_scan("10.0.0.1", "10.0.0.2", [])
        assert alert is not None
        assert alert.alert_type == "NULL_SCAN"

    def test_xmas_scan_detection(self):
        alert = self.td.detect_stealth_scan(
            "10.0.0.1", "10.0.0.2", ["FIN", "PSH", "URG"]
        )
        assert alert is not None
        assert alert.alert_type == "XMAS_SCAN"

    def test_dns_tunneling_long_query(self):
        long_name = "a" * 101 + ".example.com"
        alert = self.td.detect_dns_tunneling("10.0.0.1", long_name)
        assert alert is not None
        assert alert.alert_type == "DNS_TUNNELING"

    def test_alert_count(self):
        self.td.detect_c2("1.1.1.1", "2.2.2.2", 4444)
        self.td.detect_c2("1.1.1.2", "2.2.2.2", 1337)
        assert len(self.td.get_all_alerts()) >= 2

    def test_summary(self):
        self.td.detect_c2("1.1.1.1", "2.2.2.2", 4444)
        s = self.td.summary()
        assert s["total"] >= 1
        assert "by_severity" in s
