"""Multi-format packet exporter"""
from __future__ import annotations

import os
import csv
import struct
from datetime import datetime
from typing import Dict, List, Optional

try:
    import orjson
    def _dumps(obj) -> str:
        return orjson.dumps(obj, default=str, option=orjson.OPT_INDENT_2).decode()
except ImportError:
    import json
    def _dumps(obj) -> str:
        return json.dumps(obj, default=str, indent=2)


class PacketExporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs("captures", exist_ok=True)

    def _ts(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_json(self, packets: List[Dict], filename: str = None) -> str:
        fn = filename or f"capture_{self._ts()}.json"
        fp = os.path.join(self.output_dir, fn)
        data = {"export_time": datetime.now().isoformat(),
                "packet_count": len(packets), "packets": packets}
        with open(fp, "w") as f:
            f.write(_dumps(data))
        return fp

    def export_csv(self, packets: List[Dict], filename: str = None) -> str:
        fn = filename or f"capture_{self._ts()}.csv"
        fp = os.path.join(self.output_dir, fn)
        if not packets:
            return fp
        flat = []
        for p in packets:
            row = {}
            for k, v in p.items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        row[f"{k}_{k2}"] = v2
                elif isinstance(v, list):
                    row[k] = str(v)
                else:
                    row[k] = v
            flat.append(row)
        keys = sorted({k for r in flat for k in r})
        with open(fp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(flat)
        return fp

    def export_pcap(
        self, raw_packets: List[bytes], timestamps: List[float],
        filename: str = None,
    ) -> str:
        fn = filename or f"capture_{self._ts()}.pcap"
        fp = os.path.join("captures", fn)
        with open(fp, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for raw, ts in zip(raw_packets, timestamps):
                ts_s = int(ts)
                ts_us = int((ts - ts_s) * 1_000_000)
                ln = len(raw)
                f.write(struct.pack("<IIII", ts_s, ts_us, ln, ln))
                f.write(raw)
        return fp

    def export_html_report(
        self, stats: Dict, alerts: List[Dict],
        packets: List[Dict], filename: str = None,
    ) -> str:
        fn = filename or f"report_{self._ts()}.html"
        fp = os.path.join(self.output_dir, fn)
        crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high = sum(1 for a in alerts if a.get("severity") == "HIGH")
        med  = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        low  = sum(1 for a in alerts if a.get("severity") == "LOW")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Packet Analyzer Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',monospace;background:#020408;color:#c8d8e8}}
.header{{background:linear-gradient(135deg,#020d1a,#050d20);padding:30px;
         border-bottom:2px solid #00d4ff}}
.header h1{{color:#00d4ff;font-size:1.8em}}
.header p{{color:#334455;margin-top:5px}}
.container{{max-width:1400px;margin:0 auto;padding:20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:15px;margin:20px 0}}
.card{{background:#030810;border:1px solid #0a2040;border-radius:8px;padding:20px}}
.card h3{{color:#4488aa;margin-bottom:10px;font-size:.85em;text-transform:uppercase}}
.card .val{{font-size:2em;font-weight:bold;color:#00d4ff}}
.card .sub{{color:#334455;font-size:.8em}}
.section{{background:#030810;border:1px solid #0a2040;border-radius:8px;
           padding:20px;margin:15px 0}}
.section h2{{color:#1e90ff;margin-bottom:15px;font-size:1em}}
table{{width:100%;border-collapse:collapse;font-size:.8em}}
th{{background:#040f20;color:#4488aa;padding:8px;text-align:left;font-weight:bold}}
td{{padding:6px 8px;border-bottom:1px solid #0a1020;color:#8899aa}}
tr:hover td{{background:#040c18}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:bold}}
.CRITICAL{{background:#ff000033;color:#ff4444;border:1px solid #ff0000}}
.HIGH{{background:#ff660033;color:#ff8844;border:1px solid #ff6600}}
.MEDIUM{{background:#ffaa0033;color:#ffcc44;border:1px solid #ffaa00}}
.LOW{{background:#00aa4433;color:#44ff88;border:1px solid #00aa44}}
footer{{text-align:center;padding:20px;color:#1a3040;border-top:1px solid #0a1020}}
</style>
</head>
<body>
<div class="header">
  <h1>\U0001f50d Advanced Packet Analyzer \u2014 Security Report</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
     Packets: {stats.get('total_packets',0):,} &nbsp;|&nbsp;
     Alerts: {len(alerts)}</p>
</div>
<div class="container">
  <div class="grid">
    <div class="card"><h3>\U0001f4e6 Total Packets</h3>
      <div class="val">{stats.get('total_packets',0):,}</div>
      <div class="sub">{stats.get('total_mb',0):.2f} MB</div></div>
    <div class="card"><h3>\U0001f4f6 Bandwidth</h3>
      <div class="val">{stats.get('current_bandwidth_mbps',0):.3f}</div>
      <div class="sub">Mbps current</div></div>
    <div class="card"><h3>\u26a1 Avg PPS</h3>
      <div class="val">{stats.get('avg_pps',0):.0f}</div>
      <div class="sub">packets/second</div></div>
    <div class="card"><h3>\U0001f310 Unique IPs</h3>
      <div class="val">{stats.get('unique_src_ips',0)}</div>
      <div class="sub">source addresses</div></div>
    <div class="card"><h3>\U0001f6a8 Alerts</h3>
      <div class="val" style="color:{'#ff4444' if len(alerts)>0 else '#00ff88'}">{len(alerts)}</div>
      <div class="sub">
        <span class="badge CRITICAL">{crit} CRIT</span>
        <span class="badge HIGH">{high} HIGH</span>
        <span class="badge MEDIUM">{med} MED</span>
        <span class="badge LOW">{low} LOW</span>
      </div></div>
    <div class="card"><h3>\U0001f517 Sessions</h3>
      <div class="val">{stats.get('active_sessions',0)}</div>
      <div class="sub">tracked flows</div></div>
  </div>

  <div class="section">
    <h2>\U0001f4e1 Protocol Distribution</h2>
    <table><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>
    {"".join(f'<tr><td>{p}</td><td>{c:,}</td><td>{c/max(stats.get("total_packets",1),1)*100:.1f}%</td></tr>' for p,c in stats.get('protocol_distribution',{}).items())}
    </table>
  </div>

  <div class="section">
    <h2>\U0001f6a8 Security Alerts ({len(alerts)})</h2>
    {"".join(f'<div style="margin:8px 0;padding:10px;background:#040a10;border-left:3px solid {"#ff0000" if a.get("severity")=="CRITICAL" else "#ff6600" if a.get("severity")=="HIGH" else "#ffaa00" if a.get("severity")=="MEDIUM" else "#00aa44"};border-radius:4px"><span class="badge {a.get("severity","LOW")}">{a.get("severity","")}</span> <strong style="color:#ccc">{a.get("type","")}</strong> &nbsp; <span style="color:#445566">{str(a.get("timestamp",""))[:19]}</span><br><span style="color:#6688aa">{a.get("src_ip","")}</span> \u2192 <span style="color:#886688">{a.get("dst_ip","")}</span><br><span style="color:#556677;font-size:.85em">{a.get("description","")}</span><br><span style="color:#446644;font-size:.8em">\U0001f4a1 {a.get("recommendation","")}</span></div>' for a in alerts[-50:])}
  </div>

  <div class="section">
    <h2>\U0001f4e6 Recent Packets (last 100)</h2>
    <table>
      <tr><th>#</th><th>Time</th><th>Proto</th><th>Source</th><th>Dest</th><th>Size</th><th>Info</th></tr>
      {"".join(f'<tr><td>{p.get("packet_id","")}</td><td>{p.get("timestamp","")}</td><td>{p.get("protocol","")}</td><td>{p.get("src_ip","")}:{p.get("src_port","")}</td><td>{p.get("dst_ip","")}:{p.get("dst_port","")}</td><td>{p.get("size",0)}B</td><td style="color:#445566">{p.get("info","")[:60]}</td></tr>' for p in packets[-100:])}
    </table>
  </div>
</div>
<footer>Advanced Packet Analyzer v3.0 &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</body></html>"""
        with open(fp, "w") as f:
            f.write(html)
        return fp

    def export_markdown_report(
        self, stats: Dict, alerts: List[Dict], filename: str = None
    ) -> str:
        fn = filename or f"report_{self._ts()}.md"
        fp = os.path.join(self.output_dir, fn)
        sev_icons = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1", "LOW": "\U0001f7e2"}
        lines = [
            f"# \U0001f50d Packet Analyzer Security Report\\n",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \\n",
            f"**Total Packets:** {stats.get('total_packets',0):,}  \\n",
            f"**Alerts:** {len(alerts)}\\n\\n---\\n",
            "## \U0001f4ca Traffic Summary\\n",
            "| Metric | Value |", "|--------|-------|",
            f"| Total Packets | {stats.get('total_packets',0):,} |",
            f"| Total Data | {stats.get('total_mb',0):.2f} MB |",
            f"| Avg PPS | {stats.get('avg_pps',0):.1f} |",
            f"| Bandwidth | {stats.get('current_bandwidth_mbps',0):.3f} Mbps |",
            f"| Unique IPs | {stats.get('unique_src_ips',0)} |",
            f"| Sessions | {stats.get('active_sessions',0)} |\\n",
            "\\n## \U0001f6a8 Alerts\\n",
        ]
        for a in alerts[-30:]:
            icon = sev_icons.get(a.get("severity", "LOW"), "\u26aa")
            lines += [
                f"### {icon} [{a.get('severity')}] {a.get('type')}",
                f"- **Time:** {str(a.get('timestamp',''))[:19]}",
                f"- **Source:** `{a.get('src_ip')}` \u2192 `{a.get('dst_ip')}`",
                f"- **Description:** {a.get('description')}",
                f"- **Recommendation:** {a.get('recommendation')}\\n",
            ]
        with open(fp, "w") as f:
            f.write("\\n".join(lines))
        return fp
