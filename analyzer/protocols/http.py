"""HTTP parser with attack pattern detection"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from scapy.layers.inet import TCP
from scapy.packet import Packet

ATTACK_PATTERNS = [
    (r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table)", "SQL Injection"),
    (r"(?i)(<script>|javascript:|onerror\s*=InitialLoad\s*=)", "XSS"),
    (r"(?i)(\.\.\/|\.\.\\|%2e%2e)", "Path Traversal"),
    (r"(?i)(;.*cmd=|;.*exec=|`.*`|\$\(.*\))", "Command Injection"),
    (r"(?i)(wget\s|curl\s|chmod\s+[0-7]|/bin/sh|/bin/bash)", "Shell Command"),
    (r"(?i)(base64_decode|eval\s*\(|phpinfo\(\))", "PHP Attack"),
]

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"}


@dataclass
class HTTPMessage:
    method: Optional[str]
    path: Optional[str]
    version: Optional[str]
    status_code: Optional[int]
    status_msg: Optional[str]
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    host: str = ""
    user_agent: str = ""
    content_type: str = ""
    content_length: int = 0
    is_request: bool = True
    is_suspicious: bool = False
    suspicious_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "version": self.version,
            "status_code": self.status_code,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "is_suspicious": self.is_suspicious,
            "suspicious_patterns": self.suspicious_patterns,
        }


def parse_http(packet: Packet) -> Optional[HTTPMessage]:
    if not packet.haslayer(TCP):
        return None
    tcp = packet[TCP]
    if not tcp.payload:
        return None
    try:
        raw = bytes(tcp.payload).decode("utf-8", errors="replace")
    except Exception:
        return None

    lines = raw.split("\\r\\n")
    if not lines:
        return None

    first = lines[0]
    is_req = any(first.startswith(m) for m in HTTP_METHODS)
    is_resp = first.startswith("HTTP/")

    if not is_req and not is_resp:
        return None

    method = path = version = status_msg = None
    status_code = None
    headers: Dict[str, str] = {}
    host = user_agent = content_type = ""
    content_length = 0

    if is_req:
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else ""
    elif is_resp:
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            version = parts[0]
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = 0
            status_msg = parts[2] if len(parts) > 2 else ""

    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if not line:
            body_start = i + 1
            break
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k] = v
            kl = k.lower()
            if kl == "host":
                host = v
            elif kl == "user-agent":
                user_agent = v
            elif kl == "content-type":
                content_type = v
            elif kl == "content-length":
                try:
                    content_length = int(v)
                except ValueError:
                    pass

    body = "\\r\\n".join(lines[body_start:body_start + 5]) if body_start else ""

    patterns_found = []
    for pattern, name in ATTACK_PATTERNS:
        if re.search(pattern, raw):
            patterns_found.append(name)

    return HTTPMessage(
        method=method, path=path, version=version,
        status_code=status_code, status_msg=status_msg,
        headers=headers, body=body[:300],
        host=host, user_agent=user_agent,
        content_type=content_type, content_length=content_length,
        is_request=is_req,
        is_suspicious=len(patterns_found) > 0,
        suspicious_patterns=patterns_found,
    )
