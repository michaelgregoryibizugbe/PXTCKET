from textual.widget import Widget
from textual.reactive import reactive

class ProtoBarChart(Widget):
    """Simple bar chart for protocol distribution."""
    
    data = reactive({})

    def render(self) -> str:
        if not self.data:
            return "No protocol data yet."
        
        total = sum(self.data.values())
        if total == 0: return ""
        
        lines = []
        # Sort by count
        sorted_protos = sorted(self.data.items(), key=lambda x: x[1], reverse=True)[:8]
        
        for proto, count in sorted_protos:
            percent = (count / total) * 100
            bar_len = int(percent / 5)
            bar = " \u2588" * bar_len
            lines.append(f"{proto:8} |{bar} [cyan]{percent:4.1f}%[/]")
            
        return "\n".join(lines)
