from textual.widget import Widget
from textual.reactive import reactive
from textual.app import ComposeResult
from textual.widgets import Static

class GlowCard(Widget):
    """Stat card with neon border and reactive value."""
    
    DEFAULT_CLASSES = "glow-card"
    
    label = reactive("Label")
    value = reactive("0")
    unit = reactive("")

    def __init__(self, label: str, value: str = "0", unit: str = "", classes: str = ""):
        super().__init__(classes=classes)
        self.label = label
        self.value = value
        self.unit = unit

    def compose(self) -> ComposeResult:
        yield Static(self.label, classes="label")
        yield Static(f"{self.value}{self.unit}", id="value-text", classes="value")

    def watch_value(self, new_value: str):
        try:
            self.query_one("#value-text").update(f"{new_value}{self.unit}")
        except Exception:
            pass
