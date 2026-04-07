from textual.widgets import Sparkline
from textual.containers import Vertical
from textual.widgets import Label
from textual.app import ComposeResult

class SparklineWidget(Vertical):
    """Labeled sparkline for real-time metrics."""
    
    def __init__(self, label: str, data: list[float] = None, classes: str = ""):
        super().__init__(classes=classes)
        self.display_label = label
        self.data = data or [0.0] * 20

    def compose(self) -> ComposeResult:
        yield Label(self.display_label)
        yield Sparkline(self.data, id="sparkline")

    def update_data(self, new_val: float):
        sparkline = self.query_one("#sparkline", Sparkline)
        self.data.append(new_val)
        if len(self.data) > 40:
            self.data.pop(0)
        sparkline.data = self.data
