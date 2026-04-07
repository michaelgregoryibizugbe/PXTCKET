from textual.app import ComposeResult
from textual.widgets import Static
class FiltersScreen(Static):
    def compose(self) -> ComposeResult:
        yield Static("Packet Filters (Work in Progress)", classes="help-section")
