from textual.app import ComposeResult
from textual.widgets import Static
from tui.widgets.packet_table import PacketTable

class PacketsScreen(Static):
    """Live packet table view."""
    
    def compose(self) -> ComposeResult:
        yield PacketTable(id="live-packet-table")
