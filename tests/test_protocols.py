"""Protocol parser tests"""
import pytest
from unittest.mock import MagicMock, patch
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR

from analyzer.protocols.ethernet import parse_ethernet
from analyzer.protocols.ip import parse_ip
from analyzer.protocols.tcp import parse_tcp, WELL_KNOWN_PORTS
from analyzer.protocols.udp import parse_udp
from analyzer.protocols.icmp import parse_icmp
from analyzer.protocols.arp import parse_arp, ARPSpoofDetector


def make_eth_ip_tcp(src="1.2.3.4", dst="5.6.7.8", sport=12345, dport=80, flags="S"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)


def make_eth_arp(op=1, src_ip="192.168.1.1", dst_ip="192.168.1.2",
                 src_mac="aa:bb:cc:dd:ee:ff"):
    return Ether() / ARP(op=op, psrc=src_ip, pdst=dst_ip, hwsrc=src_mac)


class TestEthernet:
    def test_parse_basic(self):
        pkt = make_eth_ip_tcp()
        result = parse_ethernet(pkt)
        assert result is not None
        assert result.ethertype == 0x0800
        assert result.ethertype_name == "IPv4"

    def test_broadcast_detection(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP()
        result = parse_ethernet(pkt)
        assert result.is_broadcast is True
        assert result.is_multicast is False

    def test_no_ethernet_returns_none(self):
        pkt = IP() / TCP()
        result = parse_ethernet(pkt)
        assert result is None


class TestIP:
    def test_parse_ipv4(self):
        pkt = make_eth_ip_tcp(src="192.168.1.1", dst="8.8.8.8")
        result = parse_ip(pkt)
        assert result is not None
        assert result.version == 4
        assert result.src_ip == "192.168.1.1"
        assert result.dst_ip == "8.8.8.8"
        assert result.is_private_src is True
        assert result.is_private_dst is False

    def test_loopback_detection(self):
        pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP()
        result = parse_ip(pkt)
        assert result.is_loopback is True


class TestTCP:
    def test_syn_flags(self):
        pkt = make_eth_ip_tcp(flags="S")
        result = parse_tcp(pkt)
        assert result is not None
        assert result.is_syn is True
        assert result.is_ack is False
        assert "SYN" in result.flags

    def test_service_identification(self):
        pkt = make_eth_ip_tcp(dport=80)
        result = parse_tcp(pkt)
        assert result.dst_service == "HTTP"

    def test_suspicious_port(self):
        pkt = make_eth_ip_tcp(dport=4444)
        result = parse_tcp(pkt)
        assert result.is_suspicious_port is True

    def test_well_known_ports_coverage(self):
        assert 22 in WELL_KNOWN_PORTS
        assert 443 in WELL_KNOWN_PORTS
        assert 3389 in WELL_KNOWN_PORTS


class TestUDP:
    def test_parse_udp(self):
        pkt = Ether() / IP() / UDP(sport=54321, dport=53)
        result = parse_udp(pkt)
        assert result is not None
        assert result.dst_port == 53
        assert result.dst_service == "DNS"


class TestICMP:
    def test_echo_request(self):
        pkt = Ether() / IP() / ICMP(type=8, code=0)
        result = parse_icmp(pkt)
        assert result is not None
        assert result.is_ping is True
        assert result.icmp_type_name == "Echo Request"

    def test_unreachable(self):
        pkt = Ether() / IP() / ICMP(type=3, code=1)
        result = parse_icmp(pkt)
        assert result.is_unreachable is True


class TestARP:
    def test_parse_request(self):
        pkt = make_eth_arp(op=1)
        result = parse_arp(pkt)
        assert result is not None
        assert result.operation == 1
        assert "Request" in result.operation_name

    def test_spoof_detection(self):
        detector = ARPSpoofDetector()
        from analyzer.protocols.arp import ARPPacket
        pkt1 = ARPPacket(
            operation=2, operation_name="Reply",
            sender_mac="aa:bb:cc:dd:ee:ff", sender_ip="192.168.1.1",
            target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.2",
            is_gratuitous=False, is_probe=False, is_announcement=False,
        )
        pkt2 = ARPPacket(
            operation=2, operation_name="Reply",
            sender_mac="11:22:33:44:55:66", sender_ip="192.168.1.1",
            target_mac="ff:ff:ff:ff:ff:ff", target_ip="192.168.1.2",
            is_gratuitous=False, is_probe=False, is_announcement=False,
        )
        is_spoof1, _ = detector.check(pkt1)
        is_spoof2, reason = detector.check(pkt2)
        assert is_spoof1 is False
        assert is_spoof2 is True
        assert "SPOOF" in reason
