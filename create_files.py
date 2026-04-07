import os

files = {
    ".gitignore": """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
*.egg
*.egg-info/
dist/
build/
.eggs/
.Python
env/
venv/
.venv/
ENV/

# Captures & Reports (don't commit captures)
captures/*.pcap
reports/*.json
reports/*.csv
reports/*.html
reports/*.md
logs/*.log

# Environment
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store
Thumbs.db

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Distribution
*.tar.gz
*.zip
""",
    "requirements.txt": """# Core capture
scapy>=2.5.0

# TUI framework
textual>=0.47.0
rich>=13.7.0

# Performance
uvloop>=0.19.0; sys_platform != "win32"
orjson>=3.9.0

# Environment
python-dotenv>=1.0.0

# Config & Utils
pyyaml>=6.0
psutil>=5.9.0
pyperclip>=1.8.0
cachetools>=5.3.0
netaddr>=0.9.0

# Testing
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
""",
    ".env.example": """# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# Advanced Packet Analyzer \u2014 Environment Config
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO
""",
    "config/config.yaml": """# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
#   Advanced Packet Analyzer \u2014 Configuration
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

capture:
  interface: \"auto\"
  promiscuous_mode: true
  packet_buffer_size: 65535
  timeout: 0
  max_packets: 0
  bpf_filter: \"\"

analysis:
  enable_deep_inspection: true
  enable_dns_resolution: true
  reassemble_tcp: true
  decode_http: true
  decode_dns: true
  track_sessions: true

detection:
  enable_ids: true
  enable_anomaly_detection: true
  port_scan_threshold: 10
  syn_flood_threshold: 100
  icmp_flood_threshold: 50
  dns_amplification_threshold: 512
  arp_spoof_detection: true
  suspicious_ports:
    - 4444
    - 1337
    - 31337
    - 6666
    - 6667
    - 9001
    - 9030

thresholds:
  max_connections_per_ip: 100
  max_bandwidth_mbps: 1000
  alert_on_new_host: false
  exfil_threshold_mb: 10

export:
  pcap_output: \"captures/\"
  json_output: \"reports/\"
  csv_output: \"reports/\"
  log_file: \"logs/analyzer.log\"
  alert_log: \"logs/alerts.log\"
  auto_export: false
  export_interval: 300

display:
  refresh_rate: 1
  max_packets_display: 2000
  color_output: true
  verbose: false
""",
    "main.py": r"""#!/usr/bin/env python3
\"\"\"
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551         ADVANCED PACKET ANALYZER v3.0                       \u2551
\u2551         Ultra TUI Edition \u2014 Cyberpunk Dark Theme            \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d

Author  : github.com/yourusername
License : MIT
Docs    : See README.md
"""
from __future__ import annotations

import os
import sys
import argparse
import platform

# \u2500\u2500 Performance: Install uvloop ASAP \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
if platform.system() != "Windows":
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

# \u2500\u2500 Load .env before anything else \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def check_root() -> bool:
    """Check for root/admin privileges"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def ensure_directories():
    """Create required runtime directories"""
    for d in ["logs", "reports", "captures", "config", "ai"]:
        os.makedirs(d, exist_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Advanced Packet Analyzer \u2014 Ultra TUI with AI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py
  sudo python main.py -i eth0
  sudo python main.py -i eth0 -f "tcp port 80"
  sudo python main.py -i eth0 --no-auto-start
  sudo python main.py -i wlan0 -f "not broadcast"
  python main.py --read capture.pcap
  python main.py --version

Key Bindings (inside TUI):
  F1 Dashboard  F2 Packets  F3 Alerts  F4 Statistics
  F5 Sessions   F6 Filters  F7 Export  F8 ARIA AI
  F9 Help       S Start     X Stop     Q Quit
  Ctrl+S Quick-Save PCAP
        """,
    )

    parser.add_argument(
        "-i", "--interface",
        default=None,
        metavar="IFACE",
        help="Network interface to capture on (default: auto-detect)",
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        metavar="BPF",
        help="BPF filter expression (e.g. 'tcp port 80')",
    )
    parser.add_argument(
        "-r", "--read",
        default=None,
        metavar="FILE",
        help="Read packets from PCAP file (no root needed)",
    )
    parser.add_argument(
        "--no-auto-start",
        action="store_true",
        help="Don't start capture automatically on launch",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        metavar="FILE",
        help="Path to config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Advanced Packet Analyzer v3.0.0",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI assistant (run fully offline)",
    )

    return parser.parse_args()


def load_config(path: str) -> dict:
    """Load YAML config with graceful fallback"""
    if os.path.exists(path):
        try:
            import yaml
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"  \u26a0\ufe0f  Config load error ({path}): {e}")
    return {}


def print_startup_info(args: argparse.Namespace):
    """Print startup information to terminal"""
    print("\\n" + "\u2550" * 60)
    print("  \U0001f50d  Advanced Packet Analyzer v3.0")
    print("  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550")
    print(f"  Interface : {args.interface or 'auto-detect'}")
    print(f"  Filter    : {args.filter or 'none'}")
    print(f"  Read file : {args.read or 'none (live capture)'}")
    print(f"  AI        : {'disabled' if args.no_ai else 'enabled (ARIA)'}")
    api_key = os.getenv("GROQ_API_KEY", "")
    groq_status = "\u2705 configured" if api_key else "\u26a0\ufe0f  not set (add to .env)"
    print(f"  Groq API  : {groq_status}")
    print("\u2550" * 60 + "\\n")


def main():
    args = parse_args()
    config = load_config(args.config)

    # Privilege check for live capture
    if not check_root() and not args.read:
        print("\\n  \u26a0\ufe0f  Root / Administrator privileges required!")
        print("  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
        print("  Linux/macOS : sudo python main.py")
        print("  Windows     : Run terminal as Administrator\\n")
        sys.exit(1)

    ensure_directories()
    print_startup_info(args)

    # Inject AI disable flag into config
    if args.no_ai:
        config.setdefault("ai", {})["enable"] = False

    # Launch TUI
    from tui.app import PacketAnalyzerApp

    app = PacketAnalyzerApp(
        interface=args.interface,
        bpf_filter=args.filter,
        config=config,
        auto_start=not args.no_auto_start,
        pcap_read=args.read,
    )
    app.run()


if __name__ == "__main__":
    main()
""",
    "ai/__init__.py": r'"""AI Assistant Package"""',
    "ai/assistant.py": r""""""
ARIA \u2014 Advanced Reconnaissance & Intelligence Assistant
Groq-powered AI guide with full context awareness and
proactive threat alerting for beginners.
"""
from __future__ import annotations

import os
import time
import threading
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass, field

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False


# \u2500\u2500 System Prompt \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
SYSTEM_PROMPT = """\
You are ARIA (Advanced Reconnaissance & Intelligence Assistant),
the built-in AI guide for the Advanced Packet Analyzer security tool.

YOUR ROLE:
- Guide beginners and intermediate users through network packet analysis
- Explain what they are seeing in plain, jargon-free language
- Proactively flag suspicious patterns and explain their significance
- Teach cybersecurity concepts naturally as they come up in context
- Provide actionable, step-by-step guidance
- Be encouraging \u2014 most users are students or beginners

PERSONALITY:
- Friendly, clear, and professional
- Like a senior security engineer helping a junior analyst
- Never condescending or dismissive
- Use bullet points and short paragraphs for readability
- Emoji sparingly for emphasis only

TOOL CONTEXT:
- Live packet capture (Scapy-based, multi-interface)
- Protocol parsing: Ethernet, IPv4/6, TCP, UDP, ICMP, ARP, DNS, HTTP
- IDS engine: 14+ detection types (port scan, SYN flood, ARP spoof, etc.)
- Session tracking, statistics, multi-format export
- Filters: BPF syntax + GUI filters

RESPONSE FORMAT:
- Keep replies under 350 words unless deep analysis is requested
- Use sections with headers for complex explanations
- Always end with a practical next step when relevant
- When given network data, be specific about what is suspicious and why
"""

# \u2500\u2500 Proactive trigger templates \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
PROACTIVE = {
    "first_run": (
        "\U0001f44b Welcome! I'm ARIA, your AI network analysis guide.\\n\\n"
        "To get started:\\n"
        "\u2022 Press **S** to begin capturing network traffic\\n"
        "\u2022 Watch the **Dashboard** for an overview\\n"
        "\u2022 Check the **Packets** tab for live traffic\\n\\n"
        "Ask me anything \u2014 I'm here to help you every step of the way!"
    ),
    "no_traffic": (
        "\u26a0\ufe0f No packets captured yet.\\n\\n"
        "Common reasons:\\n"
        "\u2022 Wrong interface selected \u2014 try a different one with `-i eth0`\\n"
        "\u2022 Not running as root \u2014 use `sudo python main.py`\\n"
        "\u2022 No network activity on this interface\\n\\n"
        "Try the **Filters** tab (F6) to check your settings."
    ),
    "port_scan": (
        "\U0001f50d Port scan detected from **{src_ip}**!\\n\\n"
        "They've probed **{port_count}** ports \u2014 this is reconnaissance. "
        "An attacker is mapping your network to find open services.\\n\\n"
        "Next steps:\\n"
        "\u2022 Check the **Alerts** tab (F3) for full details\\n"
        "\u2022 Block the IP in your firewall if unauthorized\\n"
        "\u2022 Investigate what services are on those ports\\n\\n"
        "Want me to explain what a port scan means in detail?"
    ),
    "syn_flood": (
        "\U0001f6a8 SYN flood detected from **{src_ip}**!\\n\\n"
        "**{count}** SYN packets/minute \u2014 this is a Denial of Service attack. "
        "The attacker is overwhelming your server with half-open connections.\\n\\n"
        "Immediate actions:\\n"
        "\u2022 Enable SYN cookies on your server\\n"
        "\u2022 Rate-limit this IP at your firewall\\n"
        "\u2022 Contact your ISP if the attack is large-scale\\n\\n"
        "Go to **Alerts** (F3) to see the full picture."
    ),
    "arp_spoof": (
        "\U0001f534 CRITICAL: ARP spoofing detected!\\n\\n"
        "Someone is trying to intercept your network traffic \u2014 "
        "this is a **Man-in-the-Middle (MITM)** attack.\\n\\n"
        "What's happening: The attacker is sending fake ARP replies "
        "to redirect traffic through their machine.\\n\\n"
        "Defend yourself:\\n"
        "\u2022 Enable Dynamic ARP Inspection on your switch\\n"
        "\u2022 Use static ARP entries for critical hosts\\n"
        "\u2022 Switch to encrypted protocols (HTTPS, SSH, VPN)"
    ),
    "high_alerts": (
        "\U0001f6a8 {count} security alerts detected!\\n\\n"
        "Top threats: **{top}**\\n\\n"
        "Head to the **Alerts** tab (F3) to review each one. "
        "I can help you understand what any of them mean \u2014 just ask!"
    ),
    "dns_tunnel": (
        "\u26a0\ufe0f Possible DNS tunneling detected!\\n\\n"
        "Unusually long DNS queries from **{src_ip}** suggest "
        "data may be smuggled through DNS traffic.\\n\\n"
        "DNS tunneling is used to:\\n"
        "\u2022 Exfiltrate data from networks\\n"
        "\u2022 Bypass firewalls and content filters\\n"
        "\u2022 Establish C2 (command and control) channels\\n\\n"
        "Consider enabling DNS filtering and inspecting that endpoint."
    ),
}


@dataclass
class ChatMessage:
    """Single chat history entry"""
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


class AIAssistant:
    """
    Groq LLM-powered AI assistant.
    Runs all inference in daemon threads \u2014 never blocks UI.
    """

    def __init__(
        self,
        on_response: Callable[[str, str], None] | None = None,
        enabled: bool = True,
        model: str = None,
    ):
        self.on_response = on_response
        self.enabled = enabled
        self._model = model or os.getenv("GROQ_MODEL", "llama3-8b-8192")
        self._history: list[ChatMessage] = []
        self._client: object | None = None
        self._lock = threading.Lock()
        self._context: dict = {}
        self._proactive_sent: set[str] = set()

        if self.enabled:
            self._init_client()

        # Always send first-run greeting
        self._push_greeting()

    def _init_client(self):
        api_key = os.getenv("GROQ_API_KEY", "").strip()
        if GROQ_AVAILABLE and api_key:
            try:
                self._client = Groq(api_key=api_key)
            except Exception:
                self._client = None

    def _push_greeting(self):
        msg = ChatMessage(
            role="assistant",
            content=PROACTIVE["first_run"],
        )
        self._history.append(msg)
        if self.on_response:
            self.on_response("assistant", PROACTIVE["first_run"])

    # \u2500\u2500 Context Update \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def update_context(self, stats: dict, alerts: list, tab: str = ""):
        """Called periodically from background thread \u2014 non-blocking"""
        with self._lock:
            self._context = {
                "total_packets": stats.get("total_packets", 0),
                "bandwidth_mbps": stats.get("current_bandwidth_mbps", 0.0),
                "pps": stats.get("avg_pps", 0.0),
                "unique_ips": stats.get("unique_src_ips", 0),
                "sessions": stats.get("active_sessions", 0),
                "protocols": stats.get("protocol_distribution", {}),
                "top_talkers": stats.get("top_talkers", [])[:5],
                "alert_count": len(alerts),
                "recent_alerts": alerts[-5:],
                "tab": tab,
            }

    def _build_context_block(self) -> str:
        with self._lock:
            ctx = dict(self._context)

        if not ctx:
            return """

        parts = [
            "\\n[LIVE NETWORK STATE]",
            f"Packets: {ctx.get('total_packets', 0):,}",
            f"Bandwidth: {ctx.get('bandwidth_mbps', 0):.3f} Mbps",
            f"PPS: {ctx.get('pps', 0):.1f}",
            f"Unique IPs: {ctx.get('unique_ips', 0)}",
            f"Sessions: {ctx.get('sessions', 0)}",
            f"Alerts: {ctx.get('alert_count', 0)}",
            f"Active tab: {ctx.get('tab', 'unknown')}",
        ]

        protos = ctx.get("protocols", {})
        if protos:
            top = sorted(protos.items(), key=lambda x: x[1], reverse=True)[:5]
            parts.append("Protocols: " + ", ".join(f"{p}={c}" for p, c in top))

        talkers = ctx.get("top_talkers", [])
        if talkers:
            parts.append(
                "Top IPs: " + ", ".join(f"{ip}({c})" for ip, c in talkers[:3])
            )

        recent = ctx.get("recent_alerts", [])
        if recent:
            parts.append(
                "Recent alerts: "
                + ", ".join(
                    f"{a.get('type', '?')}[{a.get('severity', '?')}]"
                    for a in recent
                )
            )

        parts.append("[/LIVE NETWORK STATE]\\n")
        return "\\n".join(parts)

    # \u2500\u2500 Proactive Messages \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def check_proactive(self, alerts: list, total_packets: int) -> str | None:
        """Return a proactive message string if one should be sent"""
        if total_packets == 0 and "no_traffic" not in self._proactive_sent:
            self._proactive_sent.add("no_traffic")
            return PROACTIVE["no_traffic"]

        if len(alerts) >= 5 and "high_alerts" not in self._proactive_sent:
            self._proactive_sent.add("high_alerts")
            top = ", ".join({a.get("type", "") for a in alerts[-5:]})
            return PROACTIVE["high_alerts"].format(count=len(alerts), top=top)

        recent_types = {a.get("type", "") for a in alerts[-10:]}

        if "PORT_SCAN" in recent_types and "port_scan" not in self._proactive_sent:
            self._proactive_sent.add("port_scan")
            a = next(
                (x for x in reversed(alerts) if x.get("type") == "PORT_SCAN"), {}
            )
            return PROACTIVE["port_scan"].format(
                src_ip=a.get("src_ip", "unknown"),
                port_count=a.get("details", {}).get("unique_ports_scanned", "?"),
            )

        if "SYN_FLOOD" in recent_types and "syn_flood" not in self._proactive_sent:
            self._proactive_sent.add("syn_flood")
            a = next(
                (x for x in reversed(alerts) if x.get("type") == "SYN_FLOOD"), {}
            )
            return PROACTIVE["syn_flood"].format(
                src_ip=a.get("src_ip", "unknown"),
                count=a.get("details", {}).get("syn_count", "?"),
            )

        if "ARP_SPOOFING" in recent_types and "arp_spoof" not in self._proactive_sent:
            self._proactive_sent.add("arp_spoof")
            return PROACTIVE["arp_spoof"]

        if "DNS_TUNNELING" in recent_types and "dns_tunnel" not in self._proactive_sent:
            self._proactive_sent.add("dns_tunnel")
            a = next(
                (x for x in reversed(alerts) if x.get("type") == "DNS_TUNNELING"),
                {},
            )
            return PROACTIVE["dns_tunnel"].format(src_ip=a.get("src_ip", "unknown"))

        return None

    # \u2500\u2500 Inference \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

    def ask(
        self,
        user_msg: str,
        chunk_callback: Callable[[str], None] | None = None,
        done_callback: Callable[[], None] | None = None,
    ):
        """
        Send user message \u2014 streams response in background thread.
        chunk_callback(token) called for each streamed token.
        done_callback() called when stream finishes.
        """
        with self._lock:
            self._history.append(ChatMessage(role="user", content=user_msg))

        thread = threading.Thread(
            target=self._inference_thread,
            args=(user_msg, chunk_callback, done_callback),
            daemon=True,
        )
        thread.start()

    def _inference_thread(
        self,
        user_msg: str,
        chunk_cb: Callable[[str], None] | None,
        done_cb: Callable[[], None] | None,
    ):
        if not self._client:
            response = self._offline_response(user_msg)
            if chunk_cb:
                chunk_cb(response)
            if done_cb:
                done_cb()
            with self._lock:
                self._history.append(
                    ChatMessage(role="assistant", content=response)
                )
            return

        ctx = self._build_context_block()
        messages = [{"role": "system", "content": SYSTEM_PROMPT + ctx}]

        with self._lock:
            hist = list(self._history[-14:])

        for m in hist[:-1]:
            if m.role in ("user", "assistant"):
                messages.append({
                    "role": m.role,
                    "content": m.content[:600],
                })
        messages.append({"role": "user", "content": user_msg})

        full = ""
        try:
            stream = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                stream=True,
                max_tokens=int(os.getenv("GROQ_MAX_TOKENS", "512")),
                temperature=0.7,
                top_p=0.9,
            )
            for chunk in stream:
                token = chunk.choices[0].delta.content or ""
                if token:
                    full += token
                    if chunk_cb:
                        chunk_cb(token)
        except Exception as e:
            err = f"\u26a0\ufe0f AI error: {str(e)[:100]}\\n\\nCheck your GROQ_API_KEY in .env"
            full = err
            if chunk_cb:
                chunk_cb(err)

        if done_cb:
            done_cb()

        with self._lock:
            self._history.append(ChatMessage(role="assistant", content=full))

    def _offline_response(self, msg: str) -> str:
        """Smart offline fallback responses"""
        m = msg.lower()

        if any(w in m for w in ["start", "begin", "capture", "how do i", "get started"]):
            return (
                "\U0001f680 **Getting Started**\\n\\n"
                "1. Press **S** to start capturing\\n"
                "2. Make sure you ran: `sudo python main.py`\\n"
                "3. Watch **Packets** tab (F2) for live traffic\\n"
                "4. Check **Dashboard** (F1) for the overview\\n\\n"
                "\U0001f4a1 **Tip:** Use the Filters tab (F6) to focus on specific traffic like:\\n"
                "- `tcp port 80` for HTTP\\n"
                "- `tcp port 443` for HTTPS\\n"
                "- `host 192.168.1.1` for one specific device"
            )

        if any(w in m for w in ["alert", "threat", "attack", "suspicious", "danger"]):
            return (
                "\U0001f6e1\ufe0f **Security Alerts Guide**\\n\\n"
                "The IDS detects these threats automatically:\\n\\n"
                "\u2022 **PORT_SCAN** \u2014 Someone probing ports (reconnaissance)\\n"
                "\u2022 **SYN_FLOOD** \u2014 DDoS attack using fake connection requests\\n"
                "\u2022 **ARP_SPOOFING** \u2014 Man-in-the-middle attack (very dangerous)\\n"
                "\u2022 **BRUTE_FORCE** \u2014 Password guessing on SSH/RDP/FTP\\n"
                "\u2022 **DNS_TUNNELING** \u2014 Data smuggled through DNS queries\\n"
                "\u2022 **HTTP_ATTACK** \u2014 SQL injection, XSS, or command injection\\n"
                "\u2022 **DATA_EXFIL** \u2014 Unusual large data transfers\\n\\n"
                "Go to **Alerts** (F3) to see all detected threats!\\n"
                "Click any alert for full details and recommendations."
            )

        if any(w in m for w in ["port scan", "scanning", "nmap"]):
            return (
                "\U0001f50d **Port Scanning Explained**\\n\\n"
                "A port scan is when someone probes your machine's ports to find\\n"
                "which services are running and potentially vulnerable.\\n\\n"
                "**Types detected:**\\n"
                "\u2022 SYN scan \u2014 most common, sends SYN without completing handshake\\n"
                "\u2022 NULL scan \u2014 sends packet with no flags (sneaky!)\\n"
                "\u2022 XMAS scan \u2014 all flags set (FIN+PSH+URG)\\n"
                "\u2022 FIN scan \u2014 only FIN flag (bypasses some firewalls)\\n\\n"
                "**Response:** Block the source IP, check what services are exposed,\\n"
                "and harden your firewall rules."
            )

        if any(w in m for w in ["tcp", "udp", "icmp", "protocol"]):
            return (
                "\U0001f4e1 **Protocol Overview**\\n\\n"
                "**TCP** \u2014 Reliable, connection-based (web, SSH, email)\\n"
                "- SYN \u2192 SYN-ACK \u2192 ACK = three-way handshake\\n"
                "- RST = connection forcibly closed\\n"
                "- FIN = graceful close\\n\\n"
                "**UDP** \u2014 Fast, connectionless (DNS, video, games)\\n"
                "- No handshake \u2014 just send and hope it arrives\\n\\n"
                "**ICMP** \u2014 Diagnostics (ping, traceroute)\\n"
                "- Type 8 = Echo Request (ping)\\n"
                "- Type 0 = Echo Reply (pong)\\n"
                "- Type 3 = Destination Unreachable\\n\\n"
                "**ARP** \u2014 Maps IP\u2192MAC on local network\\n"
                "- Can be spoofed for MITM attacks!"
            )

        if any(w in m for w in ["dns", "domain name", "resolver"]):
            return (
                "\U0001f50d **DNS Deep Dive**\\n\\n"
                "DNS translates names like `google.com` \u2192 `142.250.x.x`\\n\\n"
                "**Suspicious DNS patterns to watch for:**\\n"
                "\u2022 Very long queries (>100 chars) \u2192 DNS tunneling\\n"
                "\u2022 Random-looking subdomains \u2192 DGA malware beaconing\\n"
                "\u2022 NXDOMAIN flood \u2192 domain brute-forcing\\n"
                "\u2022 High query frequency to one domain \u2192 C2 communication\\n\\n"
                "**DNS record types:**\\n"
                "- A \u2192 IPv4 address\\n"
                "- AAAA \u2192 IPv6 address\\n"
                "- MX \u2192 Mail server\\n"
                "- TXT \u2192 Text (SPF, DKIM, verification)\\n"
                "- CNAME \u2192 Alias\\n"
                "- PTR \u2192 Reverse lookup"
            )

        if any(w in m for w in ["arp", "spoof", "poison", "mitm", "man in the middle"]):
            return (
                "\U0001f534 **ARP Spoofing / MITM Attack**\\n\\n"
                "ARP links IP addresses to MAC addresses on your local network.\\n\\n"
                "**The attack:**\\n"
                "1. Attacker sends fake ARP replies\\n"
                "2. Claims their MAC is the router's IP\\n"
                "3. All your traffic flows through them\\n"
                "4. They can read, modify, or block it\\n\\n"
                "**Defenses:**\\n"
                "\u2022 Enable Dynamic ARP Inspection (DAI) on switches\\n"
                "\u2022 Use static ARP entries for critical hosts\\n"
                "\u2022 VPN encrypts traffic even if intercepted\\n"
                "\u2022 HTTPS ensures content isn't modified"
            )

        if any(w in m for w in ["filter", "bpf", "only show", "narrow"]):
            return (
                "\u2699\ufe0f **Traffic Filtering**\\n\\n"
                "Go to **Filters** (F6) or use BPF expressions:\\n\\n"
                "**Common filters:**\\n"
                "```\\n"
                "tcp port 80          \u2192 HTTP only\\n"
                "tcp port 443         \u2192 HTTPS only\\n"
                "udp port 53          \u2192 DNS only\\n"
                "host 192.168.1.1     \u2192 One device\\n"
                "src 10.0.0.5         \u2192 From specific IP\\n"
                "not broadcast        \u2192 No broadcast\\n"
                "icmp                 \u2192 Pings only\\n"
                "tcp and not port 443 \u2192 TCP except HTTPS\\n"
                "```\\n\\n"
                "Combine with `and`, `or`, `not` operators!"
            )

        if any(w in m for w in ["export", "save", "report", "wireshark", "pcap"]):
            return (
                "\U0001f4e4 **Exporting Your Capture**\\n\\n"
                "Go to **Export** (F7) or press **Ctrl+S** for quick save.\\n\\n"
                "**Formats available:**\\n"
                "\u2022 **PCAP** \u2192 Open in Wireshark for deeper analysis\\n"
                "\u2022 **JSON** \u2192 Full structured data, great for scripting\\n"
                "\u2022 **CSV** \u2192 Import into Excel or pandas\\n"
                "\u2022 **HTML** \u2192 Beautiful shareable security report\\n"
                "\u2022 **Markdown** \u2192 GitHub-friendly documentation\\n\\n"
                "\U0001f4a1 **Tip:** PCAP + Wireshark is the gold standard.\\n"
                "Use display filter `tcp.flags.syn==1 && tcp.flags.ack==0`\\n"
                "in Wireshark to see all SYN packets (connection attempts)."
            )

        if any(w in m for w in ["ssh", "brute force", "rdp", "ftp"]):
            return (
                "\U0001f510 **Brute Force Detection**\\n\\n"
                "The tool monitors these services for login attempts:\\n"
                "SSH (22), FTP (21), Telnet (23), RDP (3389),\\n"
                "VNC (5900), SMTP (25), MySQL (3306)\\n\\n"
                "**10+ attempts in 30 seconds = alert triggered**\\n\\n"
                "**Defend your services:**\\n"
                "\u2022 Change default ports (SSH on 2222 instead of 22)\\n"
                "\u2022 Use key-based auth instead of passwords\\n"
                "\u2022 Install fail2ban to auto-block repeat offenders\\n"
                "\u2022 Enable 2FA on all remote access services\\n"
                "\u2022 Use a VPN to hide services from the internet"
            )

        # Default helpful response
        return (
            "\U0001f4ac **I'm ARIA, your network analysis guide!**\\n\\n"
            "I can help you with:\\n"
            "\u2022 Understanding packets and protocols (TCP, UDP, DNS, HTTP, ARP)\\n"
            "\u2022 Interpreting security alerts and threats\\n"
            "\u2022 Filtering traffic to find what matters\\n"
            "\u2022 Investigating suspicious IPs and behavior\\n"
            "\u2022 Exporting and sharing your captures\\n"
            "\u2022 Learning cybersecurity concepts on the fly\\n\\n"
            "\U0001f511 **For full AI power:** Add your `GROQ_API_KEY` to `.env`\\n"
            "Get a free key at https://console.groq.com"
        )

    def get_history(self) -> list[ChatMessage]:
        with self._lock:
            return list(self._history)
""",
    "analyzer/__init__.py": r'"""Analyzer package \u2014 core capture and detection engine"""' + "\n" + '__version__ = "3.0.0"',
    "analyzer/logger.py": r""""""Centralized logging"""
from __future__ import annotations
import logging
import os
from rich.logging import RichHandler


class PacketAnalyzerLogger:
    def __init__(self, log_file: str = "logs/analyzer.log", verbose: bool = False):
        self.log_file = log_file
        os.makedirs("logs", exist_ok=True)
        self.logger = self._setup()
        self.alert_logger = self._setup_alerts()

    def _setup(self) -> logging.Logger:
        lg = logging.getLogger("PacketAnalyzer")
        lg.setLevel(logging.DEBUG)
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        ch = RichHandler(show_path=False, rich_tracebacks=True)
        ch.setLevel(logging.WARNING)
        lg.addHandler(fh)
        lg.addHandler(ch)
        return lg

    def _setup_alerts(self) -> logging.Logger:
        lg = logging.getLogger("Alerts")
        lg.setLevel(logging.DEBUG)
        fh = logging.FileHandler("logs/alerts.log")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        lg.addHandler(fh)
        return lg

    def log_alert(self, message: str, level: str = "INFO"):
        self.alert_logger.info(f"[{level}] {message}")

    def get_logger(self) -> logging.Logger:
        return self.logger
""",
    "analyzer/protocols/__init__.py": r'"""Protocol parsers"""',
    "analyzer/protocols/ethernet.py": r""""""Ethernet frame parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.l2 import Ether
from scapy.packet import Packet

ETHERTYPE_MAP = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
    0x8100: "VLAN", 0x88CC: "LLDP", 0x8847: "MPLS",
}


@dataclass
class EthernetFrame:
    src_mac: str
    dst_mac: str
    ethertype: int
    ethertype_name: str
    payload_size: int
    is_broadcast: bool
    is_multicast: bool
    vlan_id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "ethertype": hex(self.ethertype),
            "ethertype_name": self.ethertype_name,
            "payload_size": self.payload_size,
            "is_broadcast": self.is_broadcast,
            "is_multicast": self.is_multicast,
            "vlan_id": self.vlan_id,
        }


def parse_ethernet(packet: Packet) -> Optional[EthernetFrame]:
    if not packet.haslayer(Ether):
        return None
    eth = packet[Ether]
    dst = eth.dst
    is_broadcast = dst.lower() == "ff:ff:ff:ff:ff:ff"
    is_multicast = int(dst.split(":")[0], 16) & 1 == 1 and not is_broadcast
    vlan_id = None
    if eth.type == 0x8100 and packet.haslayer("Dot1Q"):
        vlan_id = packet["Dot1Q"].vlan
    return EthernetFrame(
        src_mac=eth.src,
        dst_mac=dst,
        ethertype=eth.type,
        ethertype_name=ETHERTYPE_MAP.get(eth.type, f"0x{eth.type:04x}"),
        payload_size=len(eth.payload),
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        vlan_id=vlan_id,
    )
""",
    "analyzer/protocols/ip.py": r""""""IPv4 and IPv6 parser"""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF",
}

DSCP_MAP = {
    0: "Default", 46: "EF", 10: "AF11", 18: "AF21",
    26: "AF31", 34: "AF41", 8: "CS1", 16: "CS2",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


@dataclass
class IPPacket:
    version: int
    src_ip: str
    dst_ip: str
    protocol: int
    protocol_name: str
    ttl: int
    total_length: int
    flags: Optional[str]
    fragment_offset: Optional[int]
    checksum: Optional[int]
    is_fragmented: bool
    is_private_src: bool
    is_private_dst: bool
    is_loopback: bool
    dscp: Optional[int] = None
    dscp_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "ttl": self.ttl,
            "total_length": self.total_length,
            "flags": self.flags,
            "fragment_offset": self.fragment_offset,
            "is_fragmented": self.is_fragmented,
            "is_private_src": self.is_private_src,
            "is_private_dst": self.is_private_dst,
            "is_loopback": self.is_loopback,
        }


def parse_ip(packet: Packet) -> Optional[IPPacket]:
    if packet.haslayer(IP):
        ip = packet[IP]
        flags = []
        if ip.flags.DF:
            flags.append("DF")
        if ip.flags.MF:
            flags.append("MF")
        dscp = ip.tos >> 2
        return IPPacket(
            version=4,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=ip.proto,
            protocol_name=PROTO_MAP.get(ip.proto, str(ip.proto)),
            ttl=ip.ttl,
            total_length=ip.len,
            flags="|".join(flags) or "None",
            fragment_offset=ip.frag,
            checksum=ip.chksum,
            is_fragmented=ip.frag > 0 or bool(ip.flags.MF),
            is_private_src=_is_private(ip.src),
            is_private_dst=_is_private(ip.dst),
            is_loopback=_is_loopback(ip.src),
            dscp=dscp,
            dscp_name=DSCP_MAP.get(dscp, str(dscp)),
        )
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        return IPPacket(
            version=6,
            src_ip=ip6.src,
            dst_ip=ip6.dst,
            protocol=ip6.nh,
            protocol_name=PROTO_MAP.get(ip6.nh, str(ip6.nh)),
            ttl=ip6.hlim,
            total_length=ip6.plen,
            flags=None,
            fragment_offset=None,
            checksum=None,
            is_fragmented=False,
            is_private_src=_is_private(ip6.src),
            is_private_dst=_is_private(ip6.dst),
            is_loopback=_is_loopback(ip6.src),
        )
    return None
""",
    "analyzer/protocols/tcp.py": r""""""TCP parser with full flag and service analysis"""
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
""",
    "analyzer/protocols/udp.py": r""""""UDP parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import UDP
from scapy.packet import Packet
from .tcp import WELL_KNOWN_PORTS, SUSPICIOUS_PORTS


@dataclass
class UDPDatagram:
    src_port: int
    dst_port: int
    src_service: str
    dst_service: str
    length: int
    checksum: int
    payload_size: int
    is_suspicious_port: bool

    def to_dict(self) -> dict:
        return {
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_service": self.src_service,
            "dst_service": self.dst_service,
            "length": self.length,
            "payload_size": self.payload_size,
            "is_suspicious_port": self.is_suspicious_port,
        }


def parse_udp(packet: Packet) -> Optional[UDPDatagram]:
    if not packet.haslayer(UDP):
        return None
    udp = packet[UDP]
    return UDPDatagram(
        src_port=udp.sport,
        dst_port=udp.dport,
        src_service=WELL_KNOWN_PORTS.get(udp.sport, ""),
        dst_service=WELL_KNOWN_PORTS.get(udp.dport, ""),
        length=udp.len,
        checksum=udp.chksum,
        payload_size=len(udp.payload),
        is_suspicious_port=(
            udp.sport in SUSPICIOUS_PORTS or udp.dport in SUSPICIOUS_PORTS
        ),
    )
""",
    "analyzer/protocols/icmp.py": r""""""ICMP parser"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from scapy.layers.inet import ICMP
from scapy.packet import Packet

ICMP_TYPES = {
    0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded", 12: "Parameter Problem",
}

ICMP_UNREACH = {
    0: "Net Unreachable", 1: "Host Unreachable",
    2: "Protocol Unreachable", 3: "Port Unreachable",
    4: "Fragmentation Needed",
}


@dataclass
class ICMPPacket:
    icmp_type: int
    icmp_type_name: str
    code: int
    code_name: str
    checksum: int
    identifier: Optional[int]
    sequence: Optional[int]
    payload_size: int
    is_ping: bool
    is_unreachable: bool

    def to_dict(self) -> dict:
        return {
            "type": self.icmp_type,
            "type_name": self.icmp_type_name,
            "code": self.code,
            "code_name": self.code_name,
            "identifier": self.identifier,
            "sequence": self.sequence,
            "payload_size": self.payload_size,
        }


def parse_icmp(packet: Packet) -> Optional[ICMPPacket]:
    if not packet.haslayer(ICMP):
        return None
    icmp = packet[ICMP]
    code_name = ICMP_UNREACH.get(icmp.code, "") if icmp.type == 3 else ""
    return ICMPPacket(
        icmp_type=icmp.type,
        icmp_type_name=ICMP_TYPES.get(icmp.type, f"Type{icmp.type}"),
        code=icmp.code,
        code_name=code_name,
        checksum=icmp.chksum,
        identifier=getattr(icmp, "id", None),
        sequence=getattr(icmp, "seq", None),
        payload_size=len(icmp.payload),
        is_ping=icmp.type in (0, 8),
        is_unreachable=icmp.type == 3,
    )
""",
    "analyzer/protocols/dns.py": r""""""DNS parser with DGA and tunneling heuristics"""
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
""",
    "analyzer/protocols/http.py": r""""""HTTP parser with attack pattern detection"""
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
""",
    "analyzer/protocols/arp.py": r""""""ARP parser and spoof detector"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict
from scapy.layers.l2 import ARP
from scapy.packet import Packet

ARP_OPS = {1: "Request", 2: "Reply", 3: "RARP-Req", 4: "RARP-Rep"}


@dataclass
class ARPPacket:
    operation: int
    operation_name: str
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    is_gratuitous: bool
    is_probe: bool
    is_announcement: bool

    def to_dict(self) -> dict:
        return {
            "operation": self.operation,
            "operation_name": self.operation_name,
            "sender_mac": self.sender_mac,
            "sender_ip": self.sender_ip,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "is_gratuitous": self.is_gratuitous,
        }


class ARPSpoofDetector:
    def __init__(self):
        self.table: Dict[str, str] = {}
        self.conflicts: Dict[str, int] = {}

    def check(self, arp: ARPPacket) -> tuple[bool, str]:
        ip, mac = arp.sender_ip, arp.sender_mac
        if ip == "0.0.0.0" or mac == "00:00:00:00:00:00":
            return False, ""
        if ip in self.table:
            known = self.table[ip]
            if known != mac:
                self.conflicts[ip] = self.conflicts.get(ip, 0) + 1
                return (
                    True,
                    f"ARP SPOOF: IP {ip} MAC changed {known} \u2192 {mac} "
                    f"(#{self.conflicts[ip]})",
                )
        else:
            self.table[ip] = mac
        return False, ""


def parse_arp(packet: Packet) -> Optional[ARPPacket]:
    if not packet.haslayer(ARP):
        return None
    arp = packet[ARP]
    src, dst = arp.psrc, arp.pdst
    return ARPPacket(
        operation=arp.op,
        operation_name=ARP_OPS.get(arp.op, str(arp.op)),
        sender_mac=arp.hwsrc,
        sender_ip=src,
        target_mac=arp.hwdst,
        target_ip=dst,
        is_gratuitous=src == dst and arp.op == 2,
        is_probe=src == "0.0.0.0",
        is_announcement=src == dst and arp.op == 1,
    )
""",
    "analyzer/detection/__init__.py": r'"""Detection engine"""',
    "analyzer/detection/threats.py": r""""""
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
        return time.monotonic()

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
""",
    "analyzer/detection/anomaly.py": r""""""Statistical anomaly detection"""
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
""",
    "analyzer/statistics.py": r""""""Network traffic statistics engine"""
from __future__ import annotations

import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SessionInfo:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    bytes_count: int = 0
    is_established: bool = False

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def to_dict(self) -> dict:
        return {
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "packets": self.packet_count,
            "bytes": self.bytes_count,
            "duration": f"{self.duration:.2f}s",
            "established": self.is_established,
        }


class NetworkStatistics:
    """Lock-free statistics engine optimized for high throughput"""

    __slots__ = (
        "start_time", "total_packets", "total_bytes",
        "protocol_counter", "src_ip_counter", "dst_ip_counter",
        "ip_pair_counter", "ip_bytes", "src_port_counter",
        "dst_port_counter", "tcp_flags_counter", "packet_sizes",
        "size_distribution", "pps_samples", "_last_pps_time",
        "_pps_count", "sessions", "bandwidth_samples",
        "dns_queries", "http_methods", "http_status_codes",
        "malformed_packets", "fragment_count",
    )

    def __init__(self):
        self.start_time = time.monotonic()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counter: Counter = Counter()
        self.src_ip_counter: Counter = Counter()
        self.dst_ip_counter: Counter = Counter()
        self.ip_pair_counter: Counter = Counter()
        self.ip_bytes: Dict[str, int] = defaultdict(int)
        self.src_port_counter: Counter = Counter()
        self.dst_port_counter: Counter = Counter()
        self.tcp_flags_counter: Counter = Counter()
        self.packet_sizes: List[int] = []
        self.size_distribution: Dict[str, int] = defaultdict(int)
        self.pps_samples: List[float] = []
        self._last_pps_time = time.monotonic()
        self._pps_count = 0
        self.sessions: Dict[str, SessionInfo] = {}
        self.bandwidth_samples: List[tuple] = []
        self.dns_queries: Counter = Counter()
        self.http_methods: Counter = Counter()
        self.http_status_codes: Counter = Counter()
        self.malformed_packets = 0
        self.fragment_count = 0

    def update(self, pkt: dict):
        """Hot path \u2014 called for every packet. Keep tight."""
        self.total_packets += 1
        size = pkt.get("size", 0)
        self.total_bytes += size

        now = time.monotonic()

        # PPS
        self._pps_count += 1
        elapsed = now - self._last_pps_time
        if elapsed >= 1.0:
            self.pps_samples.append(self._pps_count / elapsed)
            if len(self.pps_samples) > 60:
                del self.pps_samples[0]
            self._pps_count = 0
            self._last_pps_time = now

        # Bandwidth sample
        self.bandwidth_samples.append((now, size))
        if len(self.bandwidth_samples) > 3000:
            cutoff = now - 300
            self.bandwidth_samples = [
                s for s in self.bandwidth_samples if s[0] > cutoff
            ]

        # Packet size
        if len(self.packet_sizes) < 10000:
            self.packet_sizes.append(size)
        if size < 64:
            self.size_distribution["<64B"] += 1
        elif size < 256:
            self.size_distribution["64-255B"] += 1
        elif size < 512:
            self.size_distribution["256-511B"] += 1
        elif size < 1024:
            self.size_distribution["512-1023B"] += 1
        else:
            self.size_distribution["1024B+"] += 1

        # Protocol
        proto = pkt.get("protocol", "")
        if proto:
            self.protocol_counter[proto] += 1

        # IPs
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        if src:
            self.src_ip_counter[src] += 1
            self.ip_bytes[src] += size
        if dst:
            self.dst_ip_counter[dst] += 1
        if src and dst:
            self.ip_pair_counter[f"{src}\u2192{dst}"] += 1

        # Ports
        sp = pkt.get("src_port")
        dp = pkt.get("dst_port")
        if sp:
            self.src_port_counter[sp] += 1
        if dp:
            self.dst_port_counter[dp] += 1

        # TCP flags
        for flag in pkt.get("tcp_flags", []):
            self.tcp_flags_counter[flag] += 1

        # Sessions
        if src and dst and sp and dp:
            key = f"{src}:{sp}-{dst}:{dp}"
            rev = f"{dst}:{dp}-{src}:{sp}"
            if key in self.sessions:
                s = self.sessions[key]
                s.packet_count += 1
                s.bytes_count += size
                s.last_seen = now
            elif rev in self.sessions:
                s = self.sessions[rev]
                s.packet_count += 1
                s.bytes_count += size
                s.last_seen = now
            else:
                self.sessions[key] = SessionInfo(
                    src_ip=src, dst_ip=dst,
                    src_port=sp, dst_port=dp,
                    protocol=proto,
                    start_time=now, last_seen=now,
                    packet_count=1, bytes_count=size,
                )

    def current_bandwidth(self) -> float:
        """Mbps over last second"""
        now = time.monotonic()
        recent = sum(b for t, b in self.bandwidth_samples if t > now - 1)
        return (recent * 8) / 1_000_000

    def avg_pps(self) -> float:
        if not self.pps_samples:
            return 0.0
        return sum(self.pps_samples[-10:]) / len(self.pps_samples[-10:])

    def avg_pkt_size(self) -> float:
        if not self.packet_sizes:
            return 0.0
        recent = self.packet_sizes[-1000:]
        return sum(recent) / len(recent)

    def get_summary(self) -> dict:
        return {
            "uptime_seconds": time.monotonic() - self.start_time,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_mb": self.total_bytes / 1048576,
            "avg_pps": self.avg_pps(),
            "current_bandwidth_mbps": self.current_bandwidth(),
            "avg_packet_size": self.avg_pkt_size(),
            "unique_src_ips": len(self.src_ip_counter),
            "unique_dst_ips": len(self.dst_ip_counter),
            "active_sessions": len(self.sessions),
            "protocol_distribution": dict(self.protocol_counter.most_common(15)),
            "size_distribution": dict(self.size_distribution),
            "top_talkers": self.src_ip_counter.most_common(10),
            "top_destinations": self.dst_ip_counter.most_common(10),
            "top_ports": self.dst_port_counter.most_common(10),
            "tcp_flags": dict(self.tcp_flags_counter),
            "ip_bytes": dict(sorted(
                self.ip_bytes.items(), key=lambda x: x[1], reverse=True
            )[:10]),
        }
""",
    "analyzer/filters.py": r""""""Packet filtering engine"""
from __future__ import annotations
from typing import Callable, List, Optional


class PacketFilter:
    """High-speed packet filter \u2014 all checks in one pass"""

    __slots__ = (
        "ip_whitelist", "ip_blacklist", "port_filter",
        "protocol_filter", "exclude_broadcast", "exclude_multicast",
        "exclude_loopback", "min_packet_size", "max_packet_size",
        "_custom_rules",
    )

    def __init__(self):
        self.ip_whitelist: List[str] = []
        self.ip_blacklist: List[str] = []
        self.port_filter: Optional[List[int]] = None
        self.protocol_filter: Optional[List[str]] = None
        self.exclude_broadcast = False
        self.exclude_multicast = False
        self.exclude_loopback = True
        self.min_packet_size = 0
        self.max_packet_size = 65535
        self._custom_rules: List[Callable] = []

    def set_protocol_filter(self, protos: List[str]):
        self.protocol_filter = [p.upper() for p in protos]

    def set_port_filter(self, ports: List[int]):
        self.port_filter = ports

    def add_ip_to_whitelist(self, ip: str):
        self.ip_whitelist.append(ip)

    def add_ip_to_blacklist(self, ip: str):
        self.ip_blacklist.append(ip)

    def add_custom_rule(self, fn: Callable):
        self._custom_rules.append(fn)

    def should_capture(self, pkt: dict) -> tuple[bool, str]:
        """Single-pass filter \u2014 returns (pass, reason)"""
        size = pkt.get("size", 0)
        src = pkt.get("src_ip", "")
        dst = pkt.get("dst_ip", "")
        proto = (pkt.get("protocol") or "").upper()
        sp = pkt.get("src_port")
        dp = pkt.get("dst_port")

        if pkt.get("is_loopback") and self.exclude_loopback:
            return False, "loopback"
        if pkt.get("is_broadcast") and self.exclude_broadcast:
            return False, "broadcast"
        if pkt.get("is_multicast") and self.exclude_multicast:
            return False, "multicast"
        if size < self.min_packet_size or size > self.max_packet_size:
            return False, "size"
        if src in self.ip_blacklist or dst in self.ip_blacklist:
            return False, "blacklist"
        if self.ip_whitelist and src not in self.ip_whitelist and dst not in self.ip_whitelist:
            return False, "whitelist"
        if self.protocol_filter and proto not in self.protocol_filter:
            return False, "protocol"
        if self.port_filter:
            if sp not in self.port_filter and dp not in self.port_filter:
                return False, "port"
        for rule in self._custom_rules:
            try:
                if not rule(pkt):
                    return False, "custom"
            except Exception:
                pass
        return True, "pass"

    def from_bpf_like(self, expr: str):
        """Parse simple BPF-like filter expressions"""
        parts = expr.lower().split()
        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok in ("tcp", "udp", "icmp", "arp", "dns"):
                self.set_protocol_filter([tok.upper()])
            elif tok == "port" and i + 1 < len(parts):
                try:
                    self.set_port_filter([int(parts[i + 1])])
                    i += 1
                except ValueError:
                    pass
            elif tok == "host" and i + 1 < len(parts):
                self.add_ip_to_whitelist(parts[i + 1])
                i += 1
            elif tok == "not" and i + 1 < len(parts):
                if parts[i + 1] == "broadcast":
                    self.exclude_broadcast = True
                    i += 1
            i += 1
""",
    "analyzer/capture.py": r""""""
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
""",
    "analyzer/exporter.py": r""""""Multi-format packet exporter"""
from __future__ import annotations

import os
import csv
import struct
from datetime import datetime
from typing import Dict, List, Optional

try:
    import orjson
    def _dumps(obj) -> str:
        return orjson.dumps(obj, default=str, option=orjson.OPT_INDENT_2).decode()
except ImportError:
    import json
    def _dumps(obj) -> str:
        return json.dumps(obj, default=str, indent=2)


class PacketExporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs("captures", exist_ok=True)

    def _ts(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_json(self, packets: List[Dict], filename: str = None) -> str:
        fn = filename or f"capture_{self._ts()}.json"
        fp = os.path.join(self.output_dir, fn)
        data = {"export_time": datetime.now().isoformat(),
                "packet_count": len(packets), "packets": packets}
        with open(fp, "w") as f:
            f.write(_dumps(data))
        return fp

    def export_csv(self, packets: List[Dict], filename: str = None) -> str:
        fn = filename or f"capture_{self._ts()}.csv"
        fp = os.path.join(self.output_dir, fn)
        if not packets:
            return fp
        flat = []
        for p in packets:
            row = {}
            for k, v in p.items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        row[f"{k}_{k2}"] = v2
                elif isinstance(v, list):
                    row[k] = str(v)
                else:
                    row[k] = v
            flat.append(row)
        keys = sorted({k for r in flat for k in r})
        with open(fp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(flat)
        return fp

    def export_pcap(
        self, raw_packets: List[bytes], timestamps: List[float],
        filename: str = None,
    ) -> str:
        fn = filename or f"capture_{self._ts()}.pcap"
        fp = os.path.join("captures", fn)
        with open(fp, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for raw, ts in zip(raw_packets, timestamps):
                ts_s = int(ts)
                ts_us = int((ts - ts_s) * 1_000_000)
                ln = len(raw)
                f.write(struct.pack("<IIII", ts_s, ts_us, ln, ln))
                f.write(raw)
        return fp

    def export_html_report(
        self, stats: Dict, alerts: List[Dict],
        packets: List[Dict], filename: str = None,
    ) -> str:
        fn = filename or f"report_{self._ts()}.html"
        fp = os.path.join(self.output_dir, fn)
        crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high = sum(1 for a in alerts if a.get("severity") == "HIGH")
        med  = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        low  = sum(1 for a in alerts if a.get("severity") == "LOW")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Packet Analyzer Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',monospace;background:#020408;color:#c8d8e8}}
.header{{background:linear-gradient(135deg,#020d1a,#050d20);padding:30px;
         border-bottom:2px solid #00d4ff}}
.header h1{{color:#00d4ff;font-size:1.8em}}
.header p{{color:#334455;margin-top:5px}}
.container{{max-width:1400px;margin:0 auto;padding:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:15px;margin:20px 0}}
.card{{background:#030810;border:1px solid #0a2040;border-radius:8px;padding:20px}}
.card h3{{color:#4488aa;margin-bottom:10px;font-size:.85em;text-transform:uppercase}}
.card .val{{font-size:2em;font-weight:bold;color:#00d4ff}}
.card .sub{{color:#334455;font-size:.8em}}
.section{{background:#030810;border:1px solid #0a2040;border-radius:8px;
           padding:20px;margin:15px 0}}
.section h2{{color:#1e90ff;margin-bottom:15px;font-size:1em}}
table{{width:100%;border-collapse:collapse;font-size:.8em}}
th{{background:#040f20;color:#4488aa;padding:8px;text-align:left;font-weight:bold}}
td{{padding:6px 8px;border-bottom:1px solid #0a1020;color:#8899aa}}
tr:hover td{{background:#040c18}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:bold}}
.CRITICAL{{background:#ff000033;color:#ff4444;border:1px solid #ff0000}}
.HIGH{{background:#ff660033;color:#ff8844;border:1px solid #ff6600}}
.MEDIUM{{background:#ffaa0033;color:#ffcc44;border:1px solid #ffaa00}}
.LOW{{background:#00aa4433;color:#44ff88;border:1px solid #00aa44}}
footer{{text-align:center;padding:20px;color:#1a3040;border-top:1px solid #0a1020}}
</style>
</head>
<body>
<div class="header">
  <h1>\U0001f50d Advanced Packet Analyzer \u2014 Security Report</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
     Packets: {stats.get('total_packets',0):,} &nbsp;|&nbsp;
     Alerts: {len(alerts)}</p>
</div>
<div class="container">
  <div class="grid">
    <div class="card"><h3>\U0001f4e6 Total Packets</h3>
      <div class="val">{stats.get('total_packets',0):,}</div>
      <div class="sub">{stats.get('total_mb',0):.2f} MB</div></div>
    <div class="card"><h3>\U0001f4f6 Bandwidth</h3>
      <div class="val">{stats.get('current_bandwidth_mbps',0):.3f}</div>
      <div class="sub">Mbps current</div></div>
    <div class="card"><h3>\u26a1 Avg PPS</h3>
      <div class="val">{stats.get('avg_pps',0):.0f}</div>
      <div class="sub">packets/second</div></div>
    <div class="card"><h3>\U0001f310 Unique IPs</h3>
      <div class="val">{stats.get('unique_src_ips',0)}</div>
      <div class="sub">source addresses</div></div>
    <div class="card"><h3>\U0001f6a8 Alerts</h3>
      <div class="val" style="color:{'#ff4444' if len(alerts)>0 else '#00ff88'}">{len(alerts)}</div>
      <div class="sub">
        <span class="badge CRITICAL">{crit} CRIT</span>
        <span class="badge HIGH">{high} HIGH</span>
        <span class="badge MEDIUM">{med} MED</span>
        <span class="badge LOW">{low} LOW</span>
      </div></div>
    <div class="card"><h3>\U0001f517 Sessions</h3>
      <div class="val">{stats.get('active_sessions',0)}</div>
      <div class="sub">tracked flows</div></div>
  </div>

  <div class="section">
    <h2>\U0001f4e1 Protocol Distribution</h2>
    <table><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>
    {"".join(f'<tr><td>{p}</td><td>{c:,}</td><td>{c/max(stats.get("total_packets",1),1)*100:.1f}%</td></tr>' for p,c in stats.get('protocol_distribution',{}).items())}
    </table>
  </div>

  <div class="section">
    <h2>\U0001f6a8 Security Alerts ({len(alerts)})</h2>
    {"".join(f'<div style="margin:8px 0;padding:10px;background:#040a10;border-left:3px solid {"#ff0000" if a.get("severity")=="CRITICAL" else "#ff6600" if a.get("severity")=="HIGH" else "#ffaa00" if a.get("severity")=="MEDIUM" else "#00aa44"};border-radius:4px"><span class="badge {a.get("severity","LOW")}">{a.get("severity","")}</span> <strong style="color:#ccc">{a.get("type","")}</strong> &nbsp; <span style="color:#445566">{str(a.get("timestamp",""))[:19]}</span><br><span style="color:#6688aa">{a.get("src_ip","")}</span> \u2192 <span style="color:#886688">{a.get("dst_ip","")}</span><br><span style="color:#556677;font-size:.85em">{a.get("description","")}</span><br><span style="color:#446644;font-size:.8em">\U0001f4a1 {a.get("recommendation","")}</span></div>' for a in alerts[-50:])}
  </div>

  <div class="section">
    <h2>\U0001f4e6 Recent Packets (last 100)</h2>
    <table>
      <tr><th>#</th><th>Time</th><th>Proto</th><th>Source</th><th>Dest</th><th>Size</th><th>Info</th></tr>
      {"".join(f'<tr><td>{p.get("packet_id","")}</td><td>{p.get("timestamp","")}</td><td>{p.get("protocol","")}</td><td>{p.get("src_ip","")}:{p.get("src_port","")}</td><td>{p.get("dst_ip","")}:{p.get("dst_port","")}</td><td>{p.get("size",0)}B</td><td style="color:#445566">{p.get("info","")[:60]}</td></tr>' for p in packets[-100:])}
    </table>
  </div>
</div>
<footer>Advanced Packet Analyzer v3.0 &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</body></html>"""
        with open(fp, "w") as f:
            f.write(html)
        return fp

    def export_markdown_report(
        self, stats: Dict, alerts: List[Dict], filename: str = None
    ) -> str:
        fn = filename or f"report_{self._ts()}.md"
        fp = os.path.join(self.output_dir, fn)
        sev_icons = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}
        lines = [
            f"# \U0001f50d Packet Analyzer Security Report\\n",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \\n",
            f"**Total Packets:** {stats.get('total_packets',0):,}  \\n",
            f"**Alerts:** {len(alerts)}\\n\\n---\\n",
            "## \U0001f4ca Traffic Summary\\n",
            "| Metric | Value |", "|--------|-------|",
            f"| Total Packets | {stats.get('total_packets',0):,} |",
            f"| Total Data | {stats.get('total_mb',0):.2f} MB |",
            f"| Avg PPS | {stats.get('avg_pps',0):.1f} |",
            f"| Bandwidth | {stats.get('current_bandwidth_mbps',0):.3f} Mbps |",
            f"| Unique IPs | {stats.get('unique_src_ips',0)} |",
            f"| Sessions | {stats.get('active_sessions',0)} |\\n",
            "\\n## \U0001f6a8 Alerts\\n",
        ]
        for a in alerts[-30:]:
            icon = sev_icons.get(a.get("severity", "LOW"), "\u26aa")
            lines += [
                f"### {icon} [{a.get('severity')}] {a.get('type')}",
                f"- **Time:** {str(a.get('timestamp',''))[:19]}",
                f"- **Source:** `{a.get('src_ip')}` \u2192 `{a.get('dst_ip')}`",
                f"- **Description:** {a.get('description')}",
                f"- **Recommendation:** {a.get('recommendation')}\\n",
            ]
        with open(fp, "w") as f:
            f.write("\\n".join(lines))
        return fp
""",
    "tests/__init__.py": r'"""Test suite"""',
    "tests/test_protocols.py": r""""""Protocol parser tests"""
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
""",
    "tests/test_detection.py": r""""""Threat detection tests"""
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
""",
    "tests/test_filters.py": r""""""Filter engine tests"""
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
""",
    "tests/test_statistics.py": r""""""Statistics engine tests"""
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
""",
    "Makefile": """.PHONY: run install test lint clean help

help:
	@echo ""
	@echo "  Advanced Packet Analyzer \u2014 Commands"
	@echo "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
	@echo "  make install    Install all dependencies"
	@echo "  make run        Run the TUI (requires sudo)"
	@echo "  make test       Run test suite"
	@echo "  make lint       Run linter"
	@echo "  make clean      Remove generated files"
	@echo ""

install:
	pip install -r requirements.txt

run:
	sudo python main.py

run-no-root:
	python main.py --read /dev/null

test:
	pytest tests/ -v --tb=short --cov=analyzer --cov-report=term-missing

test-fast:
	pytest tests/ -x -q

lint:
	python -m py_compile main.py
	python -m py_compile ai/assistant.py
	find analyzer/ -name "*.py" -exec python -m py_compile {} \;
	find tui/ -name "*.py" -exec python -m py_compile {} \;

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	rm -rf .pytest_cache .coverage htmlcov

clean-all: clean
	rm -f logs/*.log reports/*.json reports/*.csv reports/*.html captures/*.pcap
""",
    "setup.py": """from setuptools import setup, find_packages

setup(
    name="advanced-packet-analyzer",
    version="3.0.0",
    description="Advanced network packet analyzer with AI assistant and TUI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourusername/advanced-packet-analyzer",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "textual>=0.47.0",
        "rich>=13.7.0",
        "pyyaml>=6.0",
        "psutil>=5.9.0",
        "groq>=0.4.0",
        "python-dotenv>=1.0.0",
        "orjson>=3.9.0",
    ],
    extras_require={
        "fast": ["uvloop>=0.19.0"],
        "dev": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0", "pytest-cov>=4.1.0"],
    },
    entry_points={
        "console_scripts": [
            "pktanalyzer=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
""",
    ".github/workflows/ci.yml": """name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install system dependencies
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y libpcap-dev

      - name: Install Python dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Syntax check all modules
        run: |
          python -m py_compile main.py
          find analyzer/ -name "*.py" -exec python -m py_compile {} \;
          find ai/ -name "*.py" -exec python -m py_compile {} \;

      - name: Run tests
        run: |
          pytest tests/ -v --tb=short --cov=analyzer --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          fail_ci_if_error: false
""",
    ".github/workflows/codeql.yml": """name: CodeQL Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 8 * * 1'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
""",
    ".github/ISSUE_TEMPLATE.md": """---
name: Bug Report / Feature Request
about: Report a bug or suggest a feature
---

## Type
- [ ] Bug Report
- [ ] Feature Request
- [ ] Question

## Description
<!-- Clear description of the issue or feature -->

## Steps to Reproduce (bugs only)
1.
2.
3.

## Expected Behavior
<!-- What should happen -->

## Actual Behavior
<!-- What actually happens -->

## Environment
- OS:
- Python version:
- Tool version: v3.0.0
- Interface:
- Root/sudo: yes/no

## Logs
```
paste relevant logs from logs/analyzer.log here
```

## Additional Context
<!-- Screenshots, packet captures, etc -->
""",
    ".github/PULL_REQUEST_TEMPLATE.md": """## Description
<!-- What does this PR do? -->

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Refactor

## Testing
- [ ] Tests pass (`make test`)
- [ ] New tests added for new features
- [ ] Syntax checked (`make lint`)

## Checklist
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] No secrets or API keys committed
- [ ] README updated if needed
""",
    "SECURITY.md": """# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.0.x   | \u2705 Yes    |
| 2.x     | \u274c No     |
| 1.x     | \u274c No     |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: security@yourdomain.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and provide a fix within 14 days.

## Scope

This tool is designed for **authorized network analysis only**.
Using it against networks without explicit permission is illegal.
""",
    "CONTRIBUTING.md": """# Contributing to Advanced Packet Analyzer

## Quick Start

```bash
git clone https://github.com/yourusername/advanced-packet-analyzer
cd advanced-packet-analyzer
pip install -r requirements.txt
make test
```

## Development Guidelines

### Code Style
- Python 3.10+ with type hints
- `from __future__ import annotations`
- Docstrings on public methods
- Max line length: 100 chars

### Performance Rules (Critical!)
- No blocking calls in UI thread
- Use queues for capture\u2192UI communication
- Prefer `__slots__` on hot-path dataclasses
- Batch UI updates \u2014 never update per-packet
- All network I/O in daemon threads

### Adding a Protocol Parser
1. Create `analyzer/protocols/myproto.py`
2. Implement `parse_myproto(packet) -> Optional[MyProtoResult]`
3. Add `to_dict()` method to result dataclass
4. Call parser in `analyzer/capture.py::_parse_packet()`
5. Add tests in `tests/test_protocols.py`

### Adding an IDS Detection
1. Add detector method to `ThreatDetector` in `analyzer/detection/threats.py`
2. Call it from `PacketCapture._detect()` in `analyzer/capture.py`
3. Add tests in `tests/test_detection.py`

### Pull Request Process
1. Fork the repo
2. Create feature branch: `git checkout -b feature/my-feature`
3. Write tests for new code
4. Ensure `make test` passes
5. Submit PR with description

## License

By contributing, you agree your contributions are licensed under MIT.
""",
    "CHANGELOG.md": """# Changelog

All notable changes to this project will be documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [3.0.0] \u2014 2024-12-XX

### Added
- \U0001f916 ARIA AI Assistant with Groq LLM integration
- Full TUI rewrite using Textual framework
- Animated gradient ASCII banner (wave-cycling)
- GlowCard stat widgets with per-card color themes
- Protocol distribution gradient bar charts
- Dual-channel bandwidth + PPS sparklines
- Live threat ticker feed
- Streaming AI chat with token-by-token display
- Proactive AI alerts for port scans, floods, ARP spoof
- Offline AI fallback (no API key required)
- uvloop integration for async performance
- orjson for 10x faster JSON serialization
- Batched UI packet updates (20-packet batches)
- Ring-buffer packet queue (never blocks capture)
- Tiered refresh rates (header 10fps, UI 2fps, stats 1fps)
- 9-tab TUI: Dashboard, Packets, Alerts, Stats, Sessions,
  Filters, Export, ARIA AI, Help

### Changed
- Complete rewrite of all TUI components
- Statistics engine uses `__slots__` for performance
- Filter engine single-pass check
- All detection thresholds configurable via config.yaml

### Fixed
- Memory leak in long captures (ring buffer added)
- Capture thread no longer blocks on UI updates
- DNS parser handles malformed responses

## [2.0.0] \u2014 2024-11-XX

### Added
- Rich terminal dashboard
- Multi-format export (PCAP, JSON, CSV, HTML, Markdown)
- Full IDS engine with 14 detection types
- Session tracking

## [1.0.0] \u2014 2024-10-XX

### Added
- Initial release
- Basic packet capture with Scapy
- CLI output
""",
    "README.md": r"""<div align="center">

# \U0001f50d Advanced Packet Analyzer

**Professional network packet analyzer with AI assistant, TUI interface, and built-in IDS**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/yourusername/advanced-packet-analyzer/ci.yml?style=flat-square&label=CI)](https://github.com/yourusername/advanced-packet-analyzer/actions)
[![Version](https://img.shields.io/badge/Version-3.0.0-purple?style=flat-square)](CHANGELOG.md)

</div>

---

## \u2728 Features

### \U0001f5a5\ufe0f Ultra TUI Interface
- Animated gradient ASCII banner with wave-cycling colors
- 9-tab interface: Dashboard, Packets, Alerts, Statistics, Sessions, Filters, Export, AI, Help
- GlowCard stat widgets with hover effects
- Live protocol distribution gradient bar charts
- Dual-channel bandwidth + PPS sparklines
- Real-time threat ticker feed

### \U0001f916 ARIA AI Assistant
- Groq LLM-powered (llama3-8b-8192 \u2014 extremely fast)
- Streaming token-by-token responses
- Full network context awareness (live stats injected)
- Proactive alerts: auto-triggers on port scans, floods, ARP spoofing
- Complete offline fallback (no API key needed)
- Beginner-friendly explanations of every threat type

### \U0001f6e1\ufe0f IDS Engine (14 Detection Types)
| Detection | Severity |
|-----------|----------|
| Port Scan (H/V/Stealth) | MEDIUM\u2013CRITICAL |
| SYN Flood DDoS | CRITICAL |
| ICMP Flood | HIGH |
| ARP Spoofing/Poisoning | CRITICAL |
| DNS Tunneling | MEDIUM |
| Brute Force (SSH/RDP/FTP) | HIGH |
| NULL / FIN / XMAS Scan | MEDIUM |
| C2 Port Detection | HIGH |
| HTTP Attack Patterns | HIGH |
| Data Exfiltration | HIGH |
| Suspicious DNS (DGA) | MEDIUM |
| New Host Detection | LOW |

### \u26a1 Performance
- **uvloop** async event loop (2\u20134x faster than standard asyncio)
- **orjson** JSON serialization (10x faster than stdlib)
- **Batched UI updates** \u2014 20-packet batches, 20fps drain
- **Ring-buffer queues** \u2014 never blocks the capture thread
- **Tiered refresh rates** \u2014 header 10fps, UI 2fps, stats 1fps
- **`__slots__`** on hot-path dataclasses

### \U0001f4e1 Protocol Support
Ethernet \u2022 IPv4/IPv6 \u2022 TCP \u2022 UDP \u2022 ICMP \u2022 ARP \u2022 DNS \u2022 HTTP

### \U0001f4e4 Export Formats
PCAP (Wireshark) \u2022 JSON \u2022 CSV \u2022 HTML Report \u2022 Markdown Report

---

## \U0001f680 Installation

```bash
# 1. Clone
git clone https://github.com/yourusername/advanced-packet-analyzer
cd advanced-packet-analyzer

# 2. Install
pip install -r requirements.txt

# 3. (Optional) Get free Groq API key for AI
# https://console.groq.com \u2014 no credit card required
echo "GROQ_API_KEY=gsk_your_key_here" > .env

# 4. Launch
sudo python main.py
```

---

## \U0001f4d6 Usage

```bash
sudo python main.py                         # Auto-detect interface
sudo python main.py -i eth0                # Specific interface
sudo python main.py -i eth0 -f "tcp port 80"  # BPF filter
sudo python main.py --no-auto-start        # Configure before capture
python main.py --read capture.pcap         # Offline PCAP analysis
python main.py --no-ai                     # Disable AI assistant
```

### TUI Key Bindings

| Key | Action |
|-----|--------|
| `F1` | Dashboard |
| `F2` | Packets |
| `F3` | Alerts |
| `F4` | Statistics |
| `F5` | Sessions |
| `F6` | Filters |
| `F7` | Export |
| `F8` | \U0001f916 ARIA AI |
| `F9` | Help |
| `S` | Start capture |
| `X` | Stop capture |
| `Ctrl+S` | Quick save PCAP |
| `Q` | Quit |

---

## \u2699\ufe0f Configuration

Edit `config/config.yaml`:

```yaml
detection:
  port_scan_threshold: 10
  syn_flood_threshold: 100
  icmp_flood_threshold: 50

ai:
  model: "llama3-8b-8192"
  max_tokens: 512
```

---

## \U0001f9ea Testing

```bash
make test           # Full test suite with coverage
make test-fast      # Quick run, stop on first failure
make lint           # Syntax check all modules
```

---

## \u26a0\ufe0f Legal Disclaimer

This tool is for **educational purposes and authorized security testing only**.
Only use on networks you own or have **explicit written permission** to analyze.
Unauthorized network interception may violate laws in your jurisdiction.

---

## \U0001f4c4 License

MIT License \u2014 see [LICENSE](LICENSE)
""",
    "LICENSE": """MIT License

Copyright (c) 2024 Your Name

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
}

for path, content in files.items():
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

# Ensure empty __init__.py for other packages if needed
for d in ["tui", "tui/screens", "tui/widgets", "tui/styles"]:
    os.makedirs(d, exist_ok=True)
    init_path = os.path.join(d, "__init__.py")
    if not os.path.exists(init_path):
        with open(init_path, "w") as f:
            f.write("")

print("Successfully created all project files.")
