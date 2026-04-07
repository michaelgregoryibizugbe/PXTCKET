#!/usr/bin/env python3
"""
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
    for d in ["logs", "reports", "captures", "config"]:
        os.makedirs(d, exist_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Advanced Packet Analyzer \u2014 Ultra TUI",
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
  F5 Sessions   F6 Filters  F7 Export
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
