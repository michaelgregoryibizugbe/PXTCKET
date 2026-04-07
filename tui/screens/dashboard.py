from textual.app import ComposeResult
from textual.widgets import Static, TabPane
from textual.containers import Container, Vertical, Horizontal, Grid
from tui.widgets.ascii_banner import AsciiBanner
from tui.widgets.glow_card import GlowCard
from tui.widgets.sparkline_widget import SparklineWidget

class DashboardScreen(Static):
    """Main dashboard with summary stats."""
    
    def compose(self) -> ComposeResult:
        with Vertical(id="dashboard-scroll"):
            with Container(id="banner-container"):
                yield AsciiBanner()
            
            with Grid(id="stats-grid"):
                yield GlowCard("Total Packets", "0", classes="blue", id="stat-packets")
                yield GlowCard("Data Transferred", "0", " MB", classes="pink", id="stat-data")
                yield GlowCard("Active Sessions", "0", classes="green", id="stat-sessions")
                yield GlowCard("Unique IPs", "0", classes="yellow", id="stat-ips")
                yield GlowCard("Security Alerts", "0", classes="red", id="stat-alerts")
                yield GlowCard("Avg PPS", "0.0", classes="blue", id="stat-pps")

            with Horizontal(id="sparklines-container", height=10):
                yield SparklineWidget("Bandwidth (Mbps)", id="spark-bw")
                yield SparklineWidget("Throughput (PPS)", id="spark-pps")
