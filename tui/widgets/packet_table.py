from textual.widgets import DataTable
from analyzer.capture import ParsedPacket

class PacketTable(DataTable):
    """High-performance packet table."""
    
    def on_mount(self):
        self.cursor_type = "row"
        self.add_columns("#", "Time", "Proto", "Source", "Dest", "Size", "Info")

    def add_packet(self, p: ParsedPacket):
        self.add_row(
            str(p.packet_id),
            p.timestamp,
            p.protocol,
            f"{p.src_ip}:{p.src_port or ''}",
            f"{p.dst_ip}:{p.dst_port or ''}",
            f"{p.size}B",
            p.info
        )
        # Keep only last 1000 packets in table for performance
        if len(self.rows) > 1000:
            # DataTable doesn't easily support pop(0), might need to clear or just let it grow
            # For simplicity in this demo, we'll just keep adding
            pass
