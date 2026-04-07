from textual.widget import Widget
from textual.reactive import reactive
from datetime import datetime

class HeaderBar(Widget):
    """Stylized header with capture status and clock."""
    
    status = reactive("READY")
    interface = reactive("auto")
    clock = reactive("")

    def on_mount(self):
        self.set_interval(1.0, self.update_clock)

    def update_clock(self):
        self.clock = datetime.now().strftime("%H:%M:%S")

    def render(self) -> str:
        status_color = "green" if self.status == "RUNNING" else "yellow" if self.status == "READY" else "red"
        return (
            f" \U0001f50d PACKET ANALYZER v3.0  |  "
            f"IFACE: [bold cyan]{self.interface}[/]  |  "
            f"STATUS: [bold {status_color}]{self.status}[/]  |  "
            f"{self.clock} "
        )
