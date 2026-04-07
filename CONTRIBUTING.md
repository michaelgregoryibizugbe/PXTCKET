# Contributing to Advanced Packet Analyzer

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
- Use queues for capture→UI communication
- Prefer `__slots__` on hot-path dataclasses
- Batch UI updates — never update per-packet
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
