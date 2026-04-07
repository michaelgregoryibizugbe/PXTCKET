from textual.app import ComposeResult
from textual.widgets import Static
from tui.widgets.alert_list import AlertList

class AlertsScreen(Static):
    """Security alerts view."""
    
    def compose(self) -> ComposeResult:
        yield AlertList(id="threat-alert-list")
