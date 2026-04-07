from textual.widget import Widget
from textual.reactive import reactive
from collections import deque

class ThreatTicker(Widget):
    """Scrolling ticker for the latest security alerts."""
    
    alerts = reactive([])

    def on_mount(self):
        self.set_interval(2.0, self.refresh)

    def add_alert(self, alert_str: str):
        self.alerts.append(alert_str)
        if len(self.alerts) > 5:
            self.alerts.pop(0)

    def render(self) -> str:
        if not self.alerts:
            return " \U0001f6e1\ufe0f IDS MONITORING ACTIVE - NO THREATS DETECTED"
        
        ticker_text = "  |  ".join(self.alerts)
        return f" \U0001f6a8 LATEST THREATS: {ticker_text}"
