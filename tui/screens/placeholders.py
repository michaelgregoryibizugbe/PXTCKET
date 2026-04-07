from textual.app import ComposeResult
from textual.widgets import Static

class SessionsScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Session Tracking (Work in Progress)", classes="help-section")

class FiltersScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Packet Filters (Work in Progress)", classes="help-section")

class ExportScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Export Capture (Work in Progress)", classes="help-section")

class HelpScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Help & Keybindings\n\nF1: Dashboard\nF2: Packets\nF3: Alerts\nS: Start\nX: Stop\nQ: Quit", classes="help-section")
