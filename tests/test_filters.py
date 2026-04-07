"""Filter engine tests"""
import pytest
from analyzer.filters import PacketFilter


def make_pkt(**kwargs) -> dict:
    base = {
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "protocol": "TCP",
        "src_port": 12345,
        "dst_port": 80,
        "size": 100,
        "is_broadcast": False,
        "is_multicast": False,
        "is_loopback": False,
    }
    base.update(kwargs)
    return base


class TestPacketFilter:
    def test_default_pass(self):
        f = PacketFilter()
        ok, _ = f.should_capture(make_pkt())
        assert ok is True

    def test_blacklist_blocks(self):
        f = PacketFilter()
        f.add_ip_to_blacklist("192.168.1.1")
        ok, reason = f.should_capture(make_pkt())
        assert ok is False
        assert reason == "blacklist"

    def test_whitelist_allows(self):
        f = PacketFilter()
        f.add_ip_to_whitelist("192.168.1.1")
        ok, _ = f.should_capture(make_pkt(src_ip="192.168.1.1"))
        assert ok is True

    def test_whitelist_blocks_others(self):
        f = PacketFilter()
        f.add_ip_to_whitelist("10.0.0.1")
        ok, reason = f.should_capture(make_pkt())
        assert ok is False
        assert reason == "whitelist"

    def test_protocol_filter(self):
        f = PacketFilter()
        f.set_protocol_filter(["UDP"])
        ok, _ = f.should_capture(make_pkt(protocol="TCP"))
        assert ok is False
        ok2, _ = f.should_capture(make_pkt(protocol="UDP"))
        assert ok2 is True

    def test_port_filter(self):
        f = PacketFilter()
        f.set_port_filter([443])
        ok, _ = f.should_capture(make_pkt(dst_port=80))
        assert ok is False
        ok2, _ = f.should_capture(make_pkt(dst_port=443))
        assert ok2 is True

    def test_size_filter(self):
        f = PacketFilter()
        f.min_packet_size = 100
        f.max_packet_size = 500
        ok, _ = f.should_capture(make_pkt(size=50))
        assert ok is False
        ok2, _ = f.should_capture(make_pkt(size=200))
        assert ok2 is True

    def test_broadcast_exclusion(self):
        f = PacketFilter()
        f.exclude_broadcast = True
        ok, reason = f.should_capture(make_pkt(is_broadcast=True))
        assert ok is False
        assert reason == "broadcast"

    def test_loopback_excluded_by_default(self):
        f = PacketFilter()
        ok, reason = f.should_capture(make_pkt(is_loopback=True))
        assert ok is False
        assert reason == "loopback"

    def test_bpf_port(self):
        f = PacketFilter()
        f.from_bpf_like("tcp port 443")
        ok, _ = f.should_capture(make_pkt(protocol="TCP", dst_port=443))
        assert ok is True

    def test_custom_rule(self):
        f = PacketFilter()
        f.add_custom_rule(lambda p: p.get("size", 0) > 50)
        ok, _ = f.should_capture(make_pkt(size=10))
        assert ok is False
