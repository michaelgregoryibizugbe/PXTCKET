"""DNS parser with DGA and tunneling heuristics"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Packet

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

SUSPICIOUS_KW = ["malware", "botnet", "c2", "dga", "darkweb"]


@dataclass
class DNSRecord:
    name: str
    qtype: int
    qtype_name: str
    data: str
    ttl: int = 0


@dataclass
class DNSPacket:
    transaction_id: int
    is_response: bool
    is_recursive: bool
    is_authoritative: bool
    opcode: int
    rcode: int
    rcode_name: str
    questions: List[Dict] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    query_count: int = 0
    answer_count: int = 0
    is_suspicious: bool = False
    suspicious_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "is_response": self.is_response,
            "rcode": self.rcode_name,
            "questions": self.questions,
            "answers": [
                {"name": r.name, "type": r.qtype_name, "data": r.data, "ttl": r.ttl}
                for r in self.answers
            ],
            "is_suspicious": self.is_suspicious,
            "suspicious_reason": self.suspicious_reason,
        }


def _check_suspicious(questions: List[Dict]) -> tuple[bool, str]:
    for q in questions:
        name = q.get("name", "").lower()
        if len(name) > 60:
            return True, f"Unusually long domain ({len(name)} chars) \u2014 possible DGA"
        for kw in SUSPICIOUS_KW:
            if kw in name:
                return True, f"Suspicious keyword in domain: {kw}"
    return False, ""


def parse_dns(packet: Packet) -> Optional[DNSPacket]:
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]

    questions = []
    if dns.qd:
        qr = dns.qd
        while qr and isinstance(qr, DNSQR):
            questions.append({
                "name": qr.qname.decode("utf-8", errors="replace").rstrip("."),
                "type": QTYPES.get(qr.qtype, str(qr.qtype)),
                "class": qr.qclass,
            })
            qr = qr.payload if isinstance(getattr(qr, "payload", None), DNSQR) else None

    answers = []
    if dns.an:
        rr = dns.an
        while rr and isinstance(rr, DNSRR):
            try:
                data = str(rr.rdata)
            except Exception:
                data = ""
            answers.append(DNSRecord(
                name=rr.rrname.decode("utf-8", errors="replace").rstrip("."),
                qtype=rr.type,
                qtype_name=QTYPES.get(rr.type, str(rr.type)),
                data=data,
                ttl=rr.ttl,
            ))
            rr = rr.payload if isinstance(getattr(rr, "payload", None), DNSRR) else None

    sus, reason = _check_suspicious(questions)
    return DNSPacket(
        transaction_id=dns.id,
        is_response=bool(dns.qr),
        is_recursive=bool(dns.rd),
        is_authoritative=bool(dns.aa),
        opcode=dns.opcode,
        rcode=dns.rcode,
        rcode_name=RCODES.get(dns.rcode, str(dns.rcode)),
        questions=questions,
        answers=answers,
        query_count=dns.qdcount,
        answer_count=dns.ancount,
        is_suspicious=sus,
        suspicious_reason=reason,
    )
