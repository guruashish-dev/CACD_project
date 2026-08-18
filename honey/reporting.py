"""Offline HTML threat-intelligence report generator.

Produces a single self-contained ``.html`` file (inline CSS + hand-built
SVG charts, no CDN, no network) that summarises everything the network
observed: KPI tiles, attacks-per-protocol, an attack timeline, the
classification mix, the top sources, every captured credential, and the
alert log.  Used by both the offline demo model and the live system's
report export.
"""

from __future__ import annotations

import html
import math
import time
from pathlib import Path

from .config import data_path

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
BG = "#0d1117"
PANEL = "#161b22"
BORDER = "#30363d"
TEXT = "#e6edf3"
MUTED = "#8b949e"

PROTO_COLORS = {
    "ssh": "#3fb950", "http": "#58a6ff", "ftp": "#d29922",
    "telnet": "#bc8cff", "mysql": "#39c5cf", "smtp": "#f778ba",
}
DEFAULT_COLOR = "#a5d6ff"

SEVERITY_COLORS = {
    "info": "#8b949e", "low": "#3fb950", "medium": "#d29922",
    "high": "#f778ba", "critical": "#f85149",
}

CLASS_COLORS = {
    "multi-vector": "#f85149",
    "brute-force": "#f778ba",
    "credential-stuffing": "#d29922",
    "recon-scan": "#58a6ff",
    "spam-relay": "#39c5cf",
    "unknown": "#8b949e",
}


def _esc(value) -> str:
    return html.escape(str(value))


def _color(proto: str) -> str:
    return PROTO_COLORS.get(proto, DEFAULT_COLOR)


def _severity_color(sev: str) -> str:
    return SEVERITY_COLORS.get(sev.lower(), MUTED)


# ---------------------------------------------------------------------------
# SVG chart primitives
# ---------------------------------------------------------------------------
def _bar_chart(items: list[tuple[str, float]], width: int, height: int,
               color_fn=lambda p: DEFAULT_COLOR) -> str:
    """Horizontal bar chart.  ``items`` = [(label, value)]."""
    if not items:
        return f'<div class="muted" style="height:{height}px;display:flex;align-items:center">No data</div>'
    max_val = max(v for _, v in items) or 1
    n = len(items)
    row_h = max(22, (height - 30) // n)
    parts = []
    for i, (label, value) in enumerate(items):
        y = 6 + i * row_h
        bar_w = max(3, (value / max_val) * (width - 160))
        parts.append(
            f'<text x="0" y="{y + 14}" fill="{MUTED}" font-size="11">{_esc(label)}</text>'
            f'<rect x="90" y="{y}" width="{bar_w:.0f}" height="{row_h - 8}" rx="3" '
            f'fill="{color_fn(label)}" fill-opacity="0.85"/>'
            f'<text x="{90 + bar_w + 6:.0f}" y="{y + 14}" fill="{TEXT}" font-size="11">'
            f'{value:g}</text>')
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">{chr(10).join(parts)}</svg>'


def _donut(items: list[tuple[str, float]], size: int, color_fn=lambda p: DEFAULT_COLOR) -> str:
    """Donut chart with a legend.  ``items`` = [(label, value)]."""
    total = sum(v for _, v in items)
    if not items or total <= 0:
        return f'<div class="muted" style="height:{size}px;display:flex;align-items:center">No data</div>'
    cx = cy = size / 2
    r_out, r_in = size * 0.34, size * 0.19
    start = -math.pi / 2
    arcs = []
    for label, value in items:
        frac = value / total
        end = start + frac * 2 * math.pi
        large = 1 if (end - start) > math.pi else 0
        a0, a1 = start, end
        x0 = cx + r_out * math.cos(a0); y0 = cy + r_out * math.sin(a0)
        x1 = cx + r_out * math.cos(a1); y1 = cy + r_out * math.sin(a1)
        x2 = cx + r_in * math.cos(a1);  y2 = cy + r_in * math.sin(a1)
        x3 = cx + r_in * math.cos(a0);  y3 = cy + r_in * math.sin(a0)
        d = (f"M{x0:.1f},{y0:.1f} A{r_out},{r_out} 0 {large} 1 {x1:.1f},{y1:.1f} "
             f"L{x2:.1f},{y2:.1f} A{r_in},{r_in} 0 {large} 0 {x3:.1f},{y3:.1f} Z")
        arcs.append(f'<path d="{d}" fill="{color_fn(label)}" fill-opacity="0.9"/>')
        start = end
    cx_text = f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" fill="{TEXT}" font-size="20" font-weight="600">{total}</text>'
    legend = "".join(
        f'<div class="legend-item"><span class="swatch" style="background:{color_fn(label)}"></span>'
        f'<span>{_esc(label)}</span><span class="muted">{value:g} · {value / total * 100:.0f}%</span></div>'
        for label, value in items)
    return (f'<div class="donut-row">'
            f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">{chr(10).join(arcs)}{cx_text}</svg>'
            f'<div class="legend">{legend}</div></div>')


def _line_chart(points: list[tuple[float, float]], width: int, height: int, color: str) -> str:
    """Area line chart.  ``points`` = [(x_order, value)]."""
    if len(points) < 2:
        return f'<div class="muted" style="height:{height}px;display:flex;align-items:center">Not enough activity</div>'
    max_val = max(v for _, v in points) or 1
    n = len(points)
    pad_l, pad_r, pad_t, pad_b = 34, 8, 12, 24
    pw, ph = width - pad_l - pad_r, height - pad_t - pad_b

    def px(i):
        return pad_l + (i / (n - 1)) * pw

    def py(v):
        return pad_t + ph - (v / max_val) * ph

    poly = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, (_, v) in enumerate(points))
    area = f"{pad_l},{pad_t + ph} " + poly + f" {px(n - 1):.1f},{pad_t + ph}"
    grid = "".join(
        f'<line x1="{pad_l}" y1="{py(v):.1f}" x2="{width - pad_r}" y2="{py(v):.1f}" '
        f'stroke="{BORDER}" stroke-width="1"/>'
        f'<text x="{pad_l - 6}" y="{py(v) + 4:.0f}" text-anchor="end" fill="{MUTED}" font-size="10">{v:g}</text>'
        for v in _gridlines(max_val))
    labels = []
    step = max(1, n // 8)
    for i in range(0, n, step):
        _, v = points[i]
        labels.append(f'<text x="{px(i):.1f}" y="{height - 6}" text-anchor="middle" fill="{MUTED}" font-size="10">{int(v)}</text>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img">'
            f'{grid}<polygon points="{area}" fill="{color}" fill-opacity="0.18"/>'
            f'<polyline points="{poly}" fill="none" stroke="{color}" stroke-width="2"/>'
            f'{"".join(labels)}</svg>')


def _gridlines(max_val: float, count: int = 4) -> list[int]:
    step = max(1, math.ceil(max_val / count))
    return list(range(0, int(max_val) + step, step))[:count + 1]


# ---------------------------------------------------------------------------
# Report renderer
# ---------------------------------------------------------------------------
def _kpi_tile(label: str, value, accent: str) -> str:
    return (f'<div class="kpi"><div class="kpi-value" style="color:{accent}">{_esc(value)}</div>'
            f'<div class="kpi-label">{_esc(label)}</div></div>')


def render_html(db, *, title: str = "Threat Intelligence Report",
                subtitle: str = "Multi-Protocol Honeypot Network") -> str:
    counts = db.counts()
    protocols = db.protocol_counts()
    timeline = db.timeline("minute", minutes=20)
    classes = db.classification_counts()
    sources = db.top_sources(8)
    intel = db.intel_table(20)
    creds = db.recent_credentials(100)
    alerts = db.recent_alerts(50)

    timeline_points = [(i, r["count"]) for i, r in enumerate(timeline)]
    chart_w, chart_h = 720, 220

    risk_class = {r["src_ip"]: r for r in intel}
    cred_rows = "".join(
        f'<tr><td class="mono">{_esc(c["ts"])}</td>'
        f'<td><span class="proto" style="border-color:{_color(c["protocol"])};color:{_color(c["protocol"])}">{_esc(c["protocol"])}</span></td>'
        f'<td class="mono">{_esc(c["src_ip"])}</td>'
        f'<td class="mono">{_esc(c["username"])}</td>'
        f'<td class="mono">{_esc(c["password"])}</td>'
        f'<td>{_esc(c["outcome"])}</td></tr>'
        for c in creds)
    alert_rows = "".join(
        f'<tr><td class="mono">{_esc(a["ts"])}</td>'
        f'<td><span style="color:{_severity_color(a["severity"])};font-weight:600">{_esc(a["severity"]).upper()}</span></td>'
        f'<td>{_esc(a["title"])}</td>'
        f'<td class="mono">{_esc(a["src_ip"] or "")}</td></tr>'
        for a in alerts)
    intel_rows = "".join(
        f'<tr><td class="mono">{_esc(r["src_ip"])}</td>'
        f'<td><div class="riskbar"><div class="riskfill" style="width:{r["score"]}%;background:{_risk_color(r["score"])}"></div></div></td>'
        f'<td style="color:{_risk_color(r["score"])};font-weight:600">{r["score"]}</td>'
        f'<td>{_esc(r["classification"] or "unknown")}</td>'
        f'<td>{r["attempts"]}</td>'
        f'<td class="mono">{_esc(r["protocols_hit"] or "")}</td></tr>'
        for r in intel)
    src_rows = "".join(
        f'<tr><td class="mono">{_esc(s["src_ip"])}</td><td>{s["attempts"]}</td><td>{s["protocols"]}</td>'
        f'<td>{_risk_label(risk_class.get(s["src_ip"], {}).get("score", 0))}</td></tr>'
        for s in sources)

    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:{BG}; color:{TEXT}; font-family:"Segoe UI",Roboto,Arial,sans-serif; }}
  header {{ padding:28px 36px; border-bottom:1px solid {BORDER}; }}
  h1 {{ margin:0 0 4px; font-size:26px; }}
  header .sub {{ color:{MUTED}; font-size:14px; }}
  .wrap {{ padding:24px 36px; max-width:1200px; margin:0 auto; }}
  .kpis {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
  .kpi {{ background:{PANEL}; border:1px solid {BORDER}; border-radius:10px; padding:16px 22px; min-width:150px; }}
  .kpi-value {{ font-size:30px; font-weight:700; }}
  .kpi-label {{ color:{MUTED}; font-size:12px; text-transform:uppercase; letter-spacing:0.05em; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  .panel {{ background:{PANEL}; border:1px solid {BORDER}; border-radius:10px; padding:18px; }}
  .panel h3 {{ margin:0 0 12px; font-size:15px; color:{TEXT}; }}
  .panel.wide {{ grid-column:1 / -1; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; color:{MUTED}; font-weight:500; padding:6px 8px; border-bottom:1px solid {BORDER}; font-size:11px; text-transform:uppercase; letter-spacing:0.04em; }}
  td {{ padding:6px 8px; border-bottom:1px solid {BORDER}; }}
  tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family:Consolas,Menlo,monospace; font-size:12px; }}
  .muted {{ color:{MUTED}; }}
  .proto {{ border:1px solid; border-radius:4px; padding:1px 6px; font-size:11px; text-transform:uppercase; }}
  .riskbar {{ width:80px; height:8px; background:{BG}; border-radius:4px; overflow:hidden; }}
  .riskfill {{ height:100%; border-radius:4px; }}
  .donut-row {{ display:flex; align-items:center; gap:20px; flex-wrap:wrap; }}
  .legend {{ flex:1; min-width:160px; }}
  .legend-item {{ display:flex; align-items:center; gap:8px; padding:3px 0; font-size:13px; }}
  .legend-item .muted {{ margin-left:auto; }}
  .swatch {{ width:12px; height:12px; border-radius:3px; flex:none; }}
  footer {{ color:{MUTED}; font-size:12px; padding:20px 36px; border-top:1px solid {BORDER}; }}
  @media (max-width:900px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style></head><body>
<header>
  <h1>🛡️ {_esc(title)}</h1>
  <div class="sub">{_esc(subtitle)} — generated {_esc(generated)}</div>
</header>
<div class="wrap">
  <div class="kpis">
    {_kpi_tile("Total attacks", counts.get("connections", 0), "#58a6ff")}
    {_kpi_tile("Sources", counts.get("sources", 0), "#bc8cff")}
    {_kpi_tile("Credentials captured", counts.get("credentials", 0), "#f778ba")}
    {_kpi_tile("Commands logged", counts.get("commands", 0), "#39c5cf")}
    {_kpi_tile("Alerts raised", counts.get("alerts", 0), "#f85149")}
  </div>
  <div class="grid">
    <div class="panel">
      <h3>Attacks per protocol</h3>
      {_bar_chart([(p["protocol"], p["count"]) for p in protocols], chart_w, chart_h, _color)}
    </div>
    <div class="panel">
      <h3>Attack classification</h3>
      {_donut([(c["classification"], c["count"]) for c in classes], 220, lambda p: CLASS_COLORS.get(p, MUTED))}
    </div>
    <div class="panel wide">
      <h3>Attack activity timeline (last 20 min)</h3>
      {_line_chart(timeline_points, chart_w, chart_h, "#58a6ff")}
    </div>
    <div class="panel wide">
      <h3>Threat intelligence — source risk assessment</h3>
      <table><tr><th>Source IP</th><th>Risk</th><th>Score</th><th>Classification</th><th>Attempts</th><th>Protocols</th></tr>
      {intel_rows or '<tr><td colspan="6" class="muted">No activity yet.</td></tr>'}</table>
    </div>
    <div class="panel">
      <h3>Top attack sources</h3>
      <table><tr><th>Source IP</th><th>Attempts</th><th>Protocols</th><th>Risk</th></tr>
      {src_rows or '<tr><td colspan="4" class="muted">No activity yet.</td></tr>'}</table>
    </div>
    <div class="panel">
      <h3>Alert log</h3>
      <table><tr><th>Time</th><th>Severity</th><th>Alert</th><th>Source</th></tr>
      {alert_rows or '<tr><td colspan="4" class="muted">No alerts yet.</td></tr>'}</table>
    </div>
    <div class="panel wide">
      <h3>Captured credentials</h3>
      <table><tr><th>Time</th><th>Protocol</th><th>Source IP</th><th>Username</th><th>Password</th><th>Outcome</th></tr>
      {cred_rows or '<tr><td colspan="6" class="muted">No credentials captured yet.</td></tr>'}</table>
    </div>
  </div>
</div>
<footer>Generated by the Multi-Protocol Honeypot Network · for defensive security training &amp; demonstration only</footer>
</body></html>"""


def _risk_color(score: float) -> str:
    if score >= 80:
        return "#f85149"
    if score >= 50:
        return "#f778ba"
    if score >= 25:
        return "#d29922"
    return "#3fb950"


def _risk_label(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def generate_report(db, output_path: str | Path | None = None, *, title: str | None = None,
                    subtitle: str = "Multi-Protocol Honeypot Network") -> Path:
    """Render the report to ``output_path`` (default ``data/reports/threat_report.html``)."""
    if output_path is None:
        output_path = data_path("reports", "threat_report.html")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_doc = render_html(db, title=title or "Threat Intelligence Report", subtitle=subtitle)
    output_path.write_text(html_doc, encoding="utf-8")
    return output_path
