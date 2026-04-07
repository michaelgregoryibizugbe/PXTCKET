"""TCP parser with full flag and service analysis"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
from scapy.layers.inet import TCP
from scapy.packet import Packet

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "MS-RPC",
    137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PgSQL",
    5900: "VNC", 6379: "Redis", 6667: "IRC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9001: "Tor", 9030: "Tor-Dir",
    9200: "Elastic", 27017: "MongoDB", 31337: "BackOrifice",
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 9001, 9030, 1080, 4899}

FLAG_MAP = {
    "F": "FIN", "S": "SYN", "R": "RST",
    "P": "PSH", "A": "ACK", "U": "URG",
    "E": "ECE", "C": "CWR",
}


def get_flags(tcp) -> List[str]:
    return [
        name for char, name in FLAG_MAP.items()
        if char in str(tcp.flags)
    ]


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    src_service: str
    dst_service: str
    seq_num: int
    ack_num: int
    flags: List[str]
    flag_str: str
    window_size: int
    payload_size: int
    checksum: int
    urgent_pointer: int
    is_syn: bool
    is_ack: bool
    is_fin: bool
    is_rst: bool
    is_psh: bool
    is_urg: bool
    is_suspicious_port: bool
    options: List[str]

    def to_dict(self) -> dict:
        return {
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_service": self.src_service,
            "dst_service": self.dst_service,
            "seq_num": self.seq_num,
            "ack_num": self.ack_num,
            "flags": self.flags,
            "flag_str": self.flag_str,
            "window_size": self.window_size,
            "payload_size": self.payload_size,
            "is_suspicious_port": self.is_suspicious_port,
        }


def parse_tcp(packet: Packet) -> Optional[TCPSegment]:
    if not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    flags = get_flags(tcp)
    opts = [str(o[0]) for o in tcp.options if isinstance(o, tuple)]
    return TCPSegment(
        src_port=tcp.sport,
        dst_port=tcp.dport,
        src_service=WELL_KNOWN_PORTS.get(tcp.sport, ""),
        dst_service=WELL_KNOWN_PORTS.get(tcp.dport, ""),
        seq_num=tcp.seq,
        ack_num=tcp.ack,
        flags=flags,
        flag_str="|".join(flags),
        window_size=tcp.window,
        payload_size=len(tcp.payload),
        checksum=tcp.chksum,
        urgent_pointer=tcp.urgptr,
        is_syn="SYN" in flags,
        is_ack="ACK" in flags,
        is_fin="FIN" in flags,
        is_rst="RST" in flags,
        is_psh="PSH" in flags,
        is_urg="URG" in flags,
        is_suspicious_port=(
            tcp.sport in SUSPICIOUS_PORTS or tcp.dport in SUSPICIOUS_PORTS
        ),
        options=opts,
    )
