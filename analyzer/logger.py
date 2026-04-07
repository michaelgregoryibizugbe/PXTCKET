"""Centralized logging"""
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
