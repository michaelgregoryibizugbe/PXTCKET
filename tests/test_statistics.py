"""Statistics engine tests"""
import pytest
from analyzer.statistics import NetworkStatistics


def make_pkt(**kwargs) -> dict:
    base = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "protocol": "TCP", "src_port": 12345, "dst_port": 80,
        "size": 500, "tcp_flags": ["SYN"],
    }
    base.update(kwargs)
    return base


class TestNetworkStatistics:
    def test_basic_update(self):
        s = NetworkStatistics()
        s.update(make_pkt())
        assert s.total_packets == 1
        assert s.total_bytes == 500

    def test_multiple_packets(self):
        s = NetworkStatistics()
        for i in range(10):
            s.update(make_pkt(size=100))
        assert s.total_packets == 10
        assert s.total_bytes == 1000

    def test_protocol_counting(self):
        s = NetworkStatistics()
        s.update(make_pkt(protocol="TCP"))
        s.update(make_pkt(protocol="UDP"))
        s.update(make_pkt(protocol="TCP"))
        assert s.protocol_counter["TCP"] == 2
        assert s.protocol_counter["UDP"] == 1

    def test_ip_counting(self):
        s = NetworkStatistics()
        s.update(make_pkt(src_ip="1.2.3.4"))
        s.update(make_pkt(src_ip="1.2.3.4"))
        assert s.src_ip_counter["1.2.3.4"] == 2

    def test_session_tracking(self):
        s = NetworkStatistics()
        s.update(make_pkt(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                           src_port=1234, dst_port=80))
        assert len(s.sessions) == 1

    def test_get_summary(self):
        s = NetworkStatistics()
        s.update(make_pkt())
        summary = s.get_summary()
        assert "total_packets" in summary
        assert "protocol_distribution" in summary
        assert "top_talkers" in summary
        assert summary["total_packets"] == 1

    def test_top_talkers(self):
        s = NetworkStatistics()
        for _ in range(5):
            s.update(make_pkt(src_ip="10.0.0.1"))
        for _ in range(2):
            s.update(make_pkt(src_ip="10.0.0.2"))
        summary = s.get_summary()
        talkers = dict(summary["top_talkers"])
        assert talkers["10.0.0.1"] == 5
        assert talkers["10.0.0.2"] == 2
