<div align=\"center\">

# \U0001f50d Advanced Packet Analyzer

**Professional network packet analyzer with TUI interface and built-in IDS**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/yourusername/advanced-packet-analyzer/ci.yml?style=flat-square&label=CI)](https://github.com/yourusername/advanced-packet-analyzer/actions)
[![Version](https://img.shields.io/badge/Version-3.0.0-purple?style=flat-square)](CHANGELOG.md)

</div>

---

## \u2728 Features

### \U0001f5a5\ufe0f Ultra TUI Interface
- Animated gradient ASCII banner with wave-cycling colors
- 8-tab interface: Dashboard, Packets, Alerts, Statistics, Sessions, Filters, Export, Help
- GlowCard stat widgets with hover effects
- Live protocol distribution gradient bar charts
- Dual-channel bandwidth + PPS sparklines
- Real-time threat ticker feed

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

# 3. Launch
sudo python main.py
```

---

## \U0001f4d6 Usage

```bash
sudo python main.py                         # Auto-detect interface
sudo python main.py -i eth0                # Specific interface
sudo python main.py -i eth0 -f \"tcp port 80\"  # BPF filter
sudo python main.py --no-auto-start        # Configure before capture
python main.py --read capture.pcap         # Offline PCAP analysis
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
