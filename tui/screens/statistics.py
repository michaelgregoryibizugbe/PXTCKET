from textual.app import ComposeResult
from textual.widgets import Static
from tui.widgets.proto_donut import ProtoBarChart

class StatisticsScreen(Static):
    """Advanced statistics view."""
    
    def compose(self) -> ComposeResult:
        yield Static("Protocol Distribution", classes="label")
        yield ProtoBarChart(id="proto-chart")
        yield Static("\nTop Talkers (Coming Soon)", classes="label")
