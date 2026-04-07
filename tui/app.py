from __future__ import annotations
import threading
import time
from typing import Dict, List, Optional

from textual.app import App, ComposeResult
from textual.widgets import TabbedContent, TabPane, Static
from textual.binding import Binding
from textual.reactive import reactive

from analyzer.capture import PacketCapture, ParsedPacket
from analyzer.statistics import NetworkStatistics
from analyzer.detection.threats import ThreatDetector, ThreatAlert

from tui.widgets.header_bar import HeaderBar
from tui.screens.dashboard import DashboardScreen
from tui.screens.packets import PacketsScreen
from tui.screens.alerts import AlertsScreen
from tui.screens.statistics import StatisticsScreen
from tui.screens.sessions import SessionsScreen
from tui.screens.filters import FiltersScreen
from tui.screens.export import ExportScreen
from tui.screens.help import HelpScreen

class PacketAnalyzerApp(App):
    """Advanced Packet Analyzer TUI Application."""
    
    CSS_PATH = "styles/main.tcss"
    
    BINDINGS = [
        Binding("f1", "switch_tab('dashboard')", "Dashboard"),
        Binding("f2", "switch_tab('packets')", "Packets"),
        Binding("f3", "switch_tab('alerts')", "Alerts"),
        Binding("f4", "switch_tab('stats')", "Statistics"),
        Binding("f5", "switch_tab('sessions')", "Sessions"),
        Binding("f6", "switch_tab('filters')", "Filters"),
        Binding("f7", "switch_tab('export')", "Export"),
        Binding("f9", "switch_tab('help')", "Help"),
        Binding("s", "start_capture", "Start"),
        Binding("x", "stop_capture", "Stop"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        config: Dict = None,
        auto_start: bool = True,
        pcap_read: Optional[str] = None,
    ):
        super().__init__()
        self.config = config or {}
        self.interface = interface or self.config.get("capture", {}).get("interface", "auto")
        self.bpf_filter = bpf_filter
        self.pcap_read = pcap_read
        self.auto_start = auto_start

        # Initialize core components
        self.stats = NetworkStatistics()
        self.threat_detector = ThreatDetector(self.config.get("detection", {}))
        self.capture = PacketCapture(
            interface=self.interface,
            bpf_filter=self.bpf_filter,
            statistics=self.stats,
            threat_detector=self.threat_detector,
            on_packet_callback=self._on_packet,
            on_alert_callback=self._on_alert,
        )

        self._capture_thread: Optional[threading.Thread] = None

    def compose(self) -> ComposeResult:
        yield HeaderBar(id="header")
        with TabbedContent(id="main-tabs"):
            with TabPane("Dashboard", id="dashboard"):
                yield DashboardScreen(id="screen-dashboard")
            with TabPane("Packets", id="packets"):
                yield PacketsScreen(id="screen-packets")
            with TabPane("Alerts", id="alerts"):
                yield AlertsScreen(id="screen-alerts")
            with TabPane("Statistics", id="stats"):
                yield StatisticsScreen(id="screen-stats")
            with TabPane("Sessions", id="sessions"):
                yield SessionsScreen()
            with TabPane("Filters", id="filters"):
                yield FiltersScreen()
            with TabPane("Export", id="export"):
                yield ExportScreen()
            with TabPane("Help", id="help"):
                yield HelpScreen()
        yield Static("READY", id="status-bar")

    def on_mount(self) -> None:
        self.query_one("#header").interface = self.interface
        self.set_interval(1.0, self._update_ui)
        if self.auto_start and not self.pcap_read:
            self.action_start_capture()

    def _update_ui(self):
        """Periodic UI refresh for stats and charts."""
        summary = self.stats.get_summary()
        
        # Update Dashboard
        try:
            dash = self.query_one("#screen-dashboard")
            dash.query_one("#stat-packets").value = f"{summary.get('total_packets', 0):,}"
            dash.query_one("#stat-data").value = f"{summary.get('total_mb', 0):.2f}"
            dash.query_one("#stat-sessions").value = str(summary.get("active_sessions", 0))
            dash.query_one("#stat-ips").value = str(summary.get("unique_src_ips", 0))
            dash.query_one("#stat-alerts").value = str(len(self.threat_detector.get_all_alerts()))
            dash.query_one("#stat-pps").value = f"{summary.get('avg_pps', 0):.1f}"
            
            dash.query_one("#spark-bw").update_data(summary.get("current_bandwidth_mbps", 0.0))
            dash.query_one("#spark-pps").update_data(summary.get("avg_pps", 0.0))
        except Exception: pass

        # Update Statistics
        try:
            stats_screen = self.query_one("#screen-stats")
            stats_screen.query_one("#proto-chart").data = summary.get("protocol_distribution", {})
        except Exception: pass

    def _on_packet(self, packet: ParsedPacket):
        """Callback from capture engine for each packet."""
        try:
            table = self.query_one("#live-packet-table")
            table.add_packet(packet)
        except Exception: pass

    def _on_alert(self, alert: ThreatAlert):
        """Callback from capture engine for security alerts."""
        try:
            self.query_one("#screen-alerts").query_one("#threat-alert-list").add_alert(alert)
            self.notify(f"THREAT: {alert.alert_type}", severity="warning")
        except Exception: pass

    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active_pane = tab_id

    def action_start_capture(self) -> None:
        if not self.capture.is_running:
            self.query_one("#header").status = "RUNNING"
            self._capture_thread = self.capture.start_async()
            self.notify("Capture started")

    def action_stop_capture(self) -> None:
        if self.capture.is_running:
            self.capture.stop()
            self.query_one("#header").status = "STOPPED"
            self.notify("Capture stopped")

    def action_quit(self) -> None:
        self.capture.stop()
        self.exit()
