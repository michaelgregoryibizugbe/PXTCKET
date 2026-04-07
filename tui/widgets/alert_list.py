from textual.widgets import ListView, ListItem, Label
from textual.containers import Vertical
from analyzer.detection.threats import ThreatAlert

class AlertItem(ListItem):
    """Single alert entry in the list."""
    def __init__(self, alert: ThreatAlert):
        super().__init__(classes=f"alert-item {alert.severity}")
        self.alert = alert

    def compose(self):
        with Vertical():
            yield Label(f"[bold]{self.alert.alert_type}[/] | {self.alert.timestamp.strftime('%H:%M:%S')}")
            yield Label(f"{self.alert.source_ip} \u2192 {self.alert.destination_ip}")
            yield Label(f"[italic]{self.alert.description}[/]")

class AlertList(ListView):
    """Specialized list for security alerts."""
    def add_alert(self, alert: ThreatAlert):
        self.mount(AlertItem(alert), before=0)
