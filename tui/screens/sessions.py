from textual.app import ComposeResult
from textual.widgets import Static
class SessionsScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Session Tracking (Work in Progress)", classes="help-section")
