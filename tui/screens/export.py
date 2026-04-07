from textual.app import ComposeResult
from textual.widgets import Static
class ExportScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Export Capture (Work in Progress)", classes="help-section")
