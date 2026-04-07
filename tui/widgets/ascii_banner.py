from textual.widget import Widget
from textual.reactive import reactive
import time

BANNER = r"""
   ___  ___  _______  ________  _______  _________  ________  _______  ________  ___  ___  ________  ________  
  |\  \|\  \|\  ___ \|\   __  \|\  ___ \|\___   ___\\   __  \|\  ___ \|\   __  \|\  \|\  \|\   __  \|\   __  \ 
  \ \  \ \  \ \   __/| \  \|\  \ \   __/\|___ \  \_\ \  \|\  \ \   __/| \  \|\  \ \  \ \  \ \  \|\  \ \  \|\  \
   \ \  \ \  \ \  \_|/_\ \   __  \ \  \_|/    \ \  \ \ \   __  \ \  \_|/_\ \   __  \ \  \ \  \ \   __  \ \   __  \
    \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \_|\ \    \ \  \ \ \  \ \  \ \  \_|\ \ \  \ \  \ \  \ \  \ \  \ \  \ \  \ \
     \ \__\ \__\ \_______\ \__\ \__\ \_______\    \ \__\ \ \__\ \__\ \_______\ \__\ \__\ \__\ \__\ \__\ \__\ \__\
      \|__|\|__|\|_______|\|__|\|__|\|_______|     \|__|  \|__|\|__|\|_______|\|__|\|__|\|__|\|__|\|__|\|__|\|__|
"""

class AsciiBanner(Widget):
    """Animated ASCII Banner with wave-cycling colors."""
    
    colors = ["#00d4ff", "#ff00ff", "#00ff88", "#ffff00", "#ff4444"]
    offset = reactive(0)

    def on_mount(self):
        self.set_interval(0.1, self.update_offset)

    def update_offset(self):
        self.offset = (self.offset + 1) % len(self.colors)

    def render(self) -> str:
        color = self.colors[self.offset]
        return f"[bold {color}]{BANNER}[/]"
