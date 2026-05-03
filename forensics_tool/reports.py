from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .map_view import write_interactive_map


def write_all_reports(
    case: dict[str, Any],
    output_dir: str | Path = "reports",
    json_output: str | Path | None = None,
    make_map: bool = True,
    make_pdf: bool = True,
) -> dict[str, str]:
    """Generate JSON, HTML, optional map, and optional PDF reports."""
    case_dir = Path(output_dir) / case["case_id"]
    case_dir.mkdir(parents=True, exist_ok=True)
    report_paths: dict[str, str] = {}

    if make_map:
        map_path = write_interactive_map(case, case_dir / "geolocation_map.html")
        report_paths["map"] = str(map_path.resolve())

    html_path = write_html_report(case, case_dir / "forensic_report.html", report_paths.get("map"))
    report_paths["html"] = str(html_path.resolve())

    if make_pdf:
        pdf_path = write_pdf_report(case, case_dir / "forensic_report.pdf")
        if pdf_path:
            report_paths["pdf"] = str(pdf_path.resolve())

    json_path = Path(json_output) if json_output else case_dir / "forensic_report.json"
    case["reports"] = report_paths | {"json": str(json_path.resolve())}
    write_json_report(case, json_path)
    report_paths["json"] = str(json_path.resolve())

    return report_paths


def write_json_report(case: dict[str, Any], output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return output


def write_html_report(case: dict[str, Any], output_path: str | Path, map_path: str | None = None) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_report_html(case, map_path), encoding="utf-8")
    return output


def write_pdf_report(case: dict[str, Any], output_path: str | Path) -> Path | None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    report_title = case.get("case_name") or case["case_id"]
    doc = SimpleDocTemplate(str(output), pagesize=A4, title=f"Forensic Report - {report_title}")
    story: list[Any] = []

    story.append(Paragraph("Digital Image Metadata Forensic Report", styles["Title"]))
    story.append(Paragraph(f"Case name: {html.escape(case.get('case_name', case['case_id']))}", styles["Normal"]))
    story.append(Paragraph(f"Case ID: {html.escape(case['case_id'])}", styles["Normal"]))
    story.append(Paragraph(f"Generated at: {html.escape(case.get('generated_at', ''))}", styles["Normal"]))
    story.append(Paragraph(f"Source folder: {html.escape(case.get('source_folder', ''))}", styles["Normal"]))
    story.append(Spacer(1, 14))

    summary = case.get("summary", {})
    summary_table = Table(
        [
            ["Total images", summary.get("total_images", 0), "GPS images", summary.get("gps_images", 0)],
            ["EXIF success", summary.get("successful_exif", 0), "Anomaly flags", summary.get("images_with_anomalies", 0)],
        ],
        colWidths=[110, 80, 110, 80],
    )
    summary_table.setStyle(_table_style(colors))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Timeline", styles["Heading2"]))
    timeline_rows = [["File", "Captured", "GPS", "Anomalies"]]
    for item in case.get("timeline", []):
        gps = "N/A"
        if item.get("gps_valid"):
            gps = f"{item.get('latitude')}, {item.get('longitude')}"
        anomalies = "; ".join(item.get("anomalies", [])) or "None"
        timeline_rows.append([item.get("filename"), item.get("date_taken") or "N/A", gps, anomalies])
    timeline_table = Table(timeline_rows, repeatRows=1, colWidths=[110, 100, 110, 180])
    timeline_table.setStyle(_table_style(colors))
    story.append(timeline_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Image Metadata Details", styles["Heading2"]))
    detail_rows = [["File", "Camera", "Software", "GPS", "Tags", "Status"]]
    for item in case.get("images", []):
        gps = "N/A"
        if item.get("gps_valid"):
            gps = f"{item.get('latitude')}, {item.get('longitude')}"
        detail_rows.append(
            [
                item.get("filename"),
                item.get("camera_model") or "N/A",
                item.get("software") or "N/A",
                gps,
                item.get("exif_tag_count", 0),
                item.get("status") or "N/A",
            ]
        )
    detail_table = Table(detail_rows, repeatRows=1, colWidths=[100, 100, 90, 100, 45, 65])
    detail_table.setStyle(_table_style(colors))
    story.append(detail_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Evidence Chain", styles["Heading2"]))
    chain_rows = [["Evidence ID", "Filename", "SHA-256"]]
    for item in case.get("evidence_chain", []):
        chain_rows.append([item.get("evidence_id"), item.get("filename"), item.get("sha256")])
    chain_table = Table(chain_rows, repeatRows=1, colWidths=[115, 145, 240])
    chain_table.setStyle(_table_style(colors))
    story.append(chain_table)

    doc.build(story)
    return output


def _table_style(colors: Any) -> Any:
    from reportlab.platypus import TableStyle

    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2933")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7dde5")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
    )


def _report_html(case: dict[str, Any], map_path: str | None) -> str:
    summary = case.get("summary", {})
    map_link = ""
    if map_path:
        map_href = Path(map_path).name
        map_link = f'<a class="button" href="{html.escape(map_href)}">Open Interactive Map</a>'

    timeline_rows = "\n".join(_timeline_row(item) for item in case.get("timeline", []))
    chain_rows = "\n".join(_chain_row(item) for item in case.get("evidence_chain", []))
    detail_rows = "\n".join(_detail_row(item) for item in case.get("images", []))
    correlation_rows = "\n".join(_correlation_row(item) for item in case.get("correlations", []))
    if not correlation_rows:
        correlation_rows = "<tr><td colspan=\"6\">No GPS-to-GPS movement correlations available.</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Forensic Report - {html.escape(case.get("case_name") or case["case_id"])}</title>
  <style>
    :root {{
      --bg: #f7f7f4;
      --paper: #ffffff;
      --ink: #1f2933;
      --muted: #657181;
      --line: #d7dde5;
      --accent: #1b7f79;
      --danger: #b42318;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.5;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 22px 46px;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: flex-start;
      margin-bottom: 22px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 30px;
      letter-spacing: 0;
    }}
    h2 {{
      margin: 30px 0 12px;
      font-size: 20px;
      letter-spacing: 0;
    }}
    .muted {{ color: var(--muted); }}
    .button {{
      display: inline-block;
      padding: 9px 12px;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      text-decoration: none;
      font-weight: 650;
      white-space: nowrap;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 22px;
    }}
    .stat {{
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .stat strong {{
      display: block;
      font-size: 26px;
      line-height: 1.1;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      padding: 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      background: #eef2f5;
      font-size: 12px;
      text-transform: uppercase;
      color: #344054;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    .warning {{ color: var(--danger); font-weight: 650; }}
    code {{
      word-break: break-all;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }}
    @media (max-width: 820px) {{
      header, .stats {{ display: block; }}
      .stat {{ margin-bottom: 10px; }}
      .button {{ margin-top: 12px; }}
      table {{ display: block; overflow-x: auto; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Digital Image Metadata Forensic Report</h1>
        <div class="muted">Case name: {html.escape(case.get("case_name", case["case_id"]))}</div>
        <div class="muted">Case ID: {html.escape(case["case_id"])}</div>
        <div class="muted">Generated at: {html.escape(case.get("generated_at", ""))}</div>
        <div class="muted">Source: {html.escape(case.get("source_folder", ""))}</div>
      </div>
      <div>{map_link}</div>
    </header>

    <section class="stats">
      <div class="stat"><strong>{summary.get("total_images", 0)}</strong><span class="muted">Images analyzed</span></div>
      <div class="stat"><strong>{summary.get("successful_exif", 0)}</strong><span class="muted">EXIF extracted</span></div>
      <div class="stat"><strong>{summary.get("gps_images", 0)}</strong><span class="muted">GPS locations</span></div>
      <div class="stat"><strong>{summary.get("images_with_anomalies", 0)}</strong><span class="muted">Images with anomaly flags</span></div>
    </section>

    <h2>Timeline</h2>
    <table>
      <thead><tr><th>File</th><th>Captured</th><th>Camera</th><th>GPS</th><th>Anomalies</th></tr></thead>
      <tbody>{timeline_rows}</tbody>
    </table>

    <h2>Movement Correlations</h2>
    <table>
      <thead><tr><th>From</th><th>To</th><th>Time gap</th><th>Distance</th><th>Speed</th><th>Note</th></tr></thead>
      <tbody>{correlation_rows}</tbody>
    </table>

    <h2>Image Metadata Details</h2>
    <table>
      <thead><tr><th>File</th><th>Evidence ID</th><th>Camera</th><th>Software</th><th>GPS</th><th>Tags</th><th>Status</th><th>Anomalies</th></tr></thead>
      <tbody>{detail_rows}</tbody>
    </table>

    <h2>Evidence Chain</h2>
    <table>
      <thead><tr><th>Evidence ID</th><th>File</th><th>Size</th><th>Collected</th><th>SHA-256</th></tr></thead>
      <tbody>{chain_rows}</tbody>
    </table>
  </main>
</body>
</html>
"""


def _timeline_row(item: dict[str, Any]) -> str:
    gps = "N/A"
    if item.get("gps_valid"):
        gps = f"{item.get('latitude')}, {item.get('longitude')}"
    anomalies = item.get("anomalies") or []
    anomaly_html = "<br>".join(html.escape(text) for text in anomalies) or "None"
    anomaly_class = " class=\"warning\"" if anomalies else ""
    return (
        "<tr>"
        f"<td>{html.escape(str(item.get('filename') or ''))}</td>"
        f"<td>{html.escape(str(item.get('date_taken') or 'N/A'))}</td>"
        f"<td>{html.escape(str(item.get('camera_model') or 'N/A'))}</td>"
        f"<td>{html.escape(gps)}</td>"
        f"<td{anomaly_class}>{anomaly_html}</td>"
        "</tr>"
    )


def _chain_row(item: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td>{html.escape(str(item.get('evidence_id') or ''))}</td>"
        f"<td>{html.escape(str(item.get('filename') or ''))}</td>"
        f"<td>{html.escape(str(item.get('file_size_bytes') or ''))}</td>"
        f"<td>{html.escape(str(item.get('collected_at') or ''))}</td>"
        f"<td><code>{html.escape(str(item.get('sha256') or ''))}</code></td>"
        "</tr>"
    )


def _detail_row(item: dict[str, Any]) -> str:
    gps = "N/A"
    if item.get("gps_valid"):
        gps = f"{item.get('latitude')}, {item.get('longitude')}"
    anomalies = "; ".join(item.get("anomalies", [])) or "None"
    anomaly_class = " class=\"warning\"" if item.get("anomalies") else ""
    return (
        "<tr>"
        f"<td>{html.escape(str(item.get('filename') or ''))}</td>"
        f"<td>{html.escape(str(item.get('evidence_id') or ''))}</td>"
        f"<td>{html.escape(str(item.get('camera_model') or 'N/A'))}</td>"
        f"<td>{html.escape(str(item.get('software') or 'N/A'))}</td>"
        f"<td>{html.escape(gps)}</td>"
        f"<td>{html.escape(str(item.get('exif_tag_count', 0)))}</td>"
        f"<td>{html.escape(str(item.get('status') or 'N/A'))}</td>"
        f"<td{anomaly_class}>{html.escape(anomalies)}</td>"
        "</tr>"
    )


def _correlation_row(item: dict[str, Any]) -> str:
    speed = item.get("estimated_speed_kmh")
    speed_text = f"{speed} km/h" if speed is not None else "N/A"
    return (
        "<tr>"
        f"<td>{html.escape(str(item.get('from') or ''))}</td>"
        f"<td>{html.escape(str(item.get('to') or ''))}</td>"
        f"<td>{html.escape(str(item.get('time_gap_minutes') or 0))} min</td>"
        f"<td>{html.escape(str(item.get('distance_km') or 0))} km</td>"
        f"<td>{html.escape(speed_text)}</td>"
        f"<td>{html.escape(str(item.get('note') or ''))}</td>"
        "</tr>"
    )
