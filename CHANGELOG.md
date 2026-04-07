# Changelog

All notable changes to this project will be documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [3.0.0] — 2024-12-XX

### Added
- Full TUI rewrite using Textual framework
- Animated gradient ASCII banner (wave-cycling)
- GlowCard stat widgets with per-card color themes
- Protocol distribution gradient bar charts
- Dual-channel bandwidth + PPS sparklines
- Live threat ticker feed
- uvloop integration for async performance
- orjson for 10x faster JSON serialization
- Batched UI packet updates (20-packet batches)
- Ring-buffer packet queue (never blocks capture)
- Tiered refresh rates (header 10fps, UI 2fps, stats 1fps)
- 8-tab TUI: Dashboard, Packets, Alerts, Stats, Sessions,
  Filters, Export, Help

### Changed
- Complete rewrite of all TUI components
- Statistics engine uses `__slots__` for performance
- Filter engine single-pass check
- All detection thresholds configurable via config.yaml

### Fixed
- Memory leak in long captures (ring buffer added)
- Capture thread no longer blocks on UI updates
- DNS parser handles malformed responses

## [2.0.0] — 2024-11-XX

### Added
- Rich terminal dashboard
- Multi-format export (PCAP, JSON, CSV, HTML, Markdown)
- Full IDS engine with 14 detection types
- Session tracking

## [1.0.0] — 2024-10-XX

### Added
- Initial release
- Basic packet capture with Scapy
- CLI output
