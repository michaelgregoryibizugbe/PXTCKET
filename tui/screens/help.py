from textual.app import ComposeResult
from textual.widgets import Static
class HelpScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Help & Keybindings\n\nF1: Dashboard\nF2: Packets\nF3: Alerts\nS: Start\nX: Stop\nQ: Quit", classes="help-section")
