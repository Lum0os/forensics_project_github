from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_interactive_map(case: dict[str, Any], output_path: str | Path) -> Path:
    """Write an interactive HTML map. Uses folium when installed, otherwise Leaflet."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    points = _gps_points(case)

    try:
        import folium
    except ImportError:
        output.write_text(_leaflet_html(case, points), encoding="utf-8")
        return output

    if not points:
        output.write_text(_leaflet_html(case, points), encoding="utf-8")
        return output

    center = _center(points)
    map_obj = folium.Map(location=center, zoom_start=11, control_scale=True)

    for index, point in enumerate(points, start=1):
        popup = folium.Popup(_popup_html(point), max_width=320)
        folium.Marker(
            location=[point["latitude"], point["longitude"]],
            popup=popup,
            tooltip=f"{index}. {point['filename']}",
            icon=folium.Icon(color="red" if point["anomalies"] else "blue", icon="camera"),
        ).add_to(map_obj)

    if len(points) > 1:
        folium.PolyLine(
            locations=[[point["latitude"], point["longitude"]] for point in points],
            color="#2563eb",
            weight=4,
            opacity=0.75,
            tooltip="Timeline path",
        ).add_to(map_obj)

    map_obj.save(str(output))
    return output


def _gps_points(case: dict[str, Any]) -> list[dict[str, Any]]:
    points = []
    for item in case.get("timeline", []):
        if not item.get("gps_valid"):
            continue
        points.append(
            {
                "filename": item.get("filename") or "image",
                "date_taken": item.get("date_taken") or "Unknown time",
                "latitude": float(item["latitude"]),
                "longitude": float(item["longitude"]),
                "camera_model": item.get("camera_model") or "Unknown camera",
                "anomalies": item.get("anomalies", []),
            }
        )
    return points


def _center(points: list[dict[str, Any]]) -> list[float]:
    return [
        sum(point["latitude"] for point in points) / len(points),
        sum(point["longitude"] for point in points) / len(points),
    ]


def _popup_html(point: dict[str, Any]) -> str:
    anomalies = point.get("anomalies") or []
    anomaly_html = "<br>".join(html.escape(item) for item in anomalies) or "None detected"
    return (
        f"<strong>{html.escape(point['filename'])}</strong><br>"
        f"Time: {html.escape(point['date_taken'])}<br>"
        f"Camera: {html.escape(point['camera_model'])}<br>"
        f"GPS: {point['latitude']:.6f}, {point['longitude']:.6f}<br>"
        f"Anomalies: {anomaly_html}"
    )


def _leaflet_html(case: dict[str, Any], points: list[dict[str, Any]]) -> str:
    case_id = html.escape(case.get("case_id", "Forensics Case"))
    case_name = html.escape(case.get("case_name") or case.get("case_id", "Forensics Case"))
    summary = case.get("summary", {})
    points_json = json.dumps(points, ensure_ascii=False)
    timeline_json = json.dumps(case.get("timeline", []), ensure_ascii=False)
    center = _center(points) if points else [30.0444, 31.2357]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{case_name} - Geolocation Map</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f7f4;
      --panel: #ffffff;
      --ink: #1f2933;
      --muted: #657181;
      --line: #d7dde5;
      --accent: #1b7f79;
      --danger: #b42318;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--ink);
    }}
    .app {{
      display: grid;
      grid-template-columns: minmax(320px, 420px) 1fr;
      height: 100vh;
      min-height: 620px;
    }}
    aside {{
      overflow: auto;
      padding: 22px;
      border-right: 1px solid var(--line);
      background: var(--panel);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 0;
    }}
    .meta {{
      color: var(--muted);
      font-size: 14px;
      line-height: 1.45;
      margin-bottom: 18px;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfd;
    }}
    .stat strong {{
      display: block;
      font-size: 20px;
      line-height: 1.1;
    }}
    .stat span {{
      color: var(--muted);
      font-size: 12px;
    }}
    .timeline {{
      display: grid;
      gap: 10px;
    }}
    .item {{
      border-left: 3px solid var(--accent);
      padding: 8px 0 8px 12px;
    }}
    .item.warning {{
      border-color: var(--danger);
    }}
    .item button {{
      border: 0;
      background: transparent;
      color: var(--ink);
      padding: 0;
      text-align: left;
      font: inherit;
      cursor: pointer;
      font-weight: 650;
    }}
    .item small {{
      display: block;
      color: var(--muted);
      margin-top: 3px;
    }}
    .empty {{
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfd;
      color: var(--muted);
      line-height: 1.5;
    }}
    #map {{
      width: 100%;
      height: 100%;
    }}
    @media (max-width: 820px) {{
      .app {{
        grid-template-columns: 1fr;
        grid-template-rows: minmax(340px, 45vh) minmax(420px, 55vh);
      }}
      aside {{
        order: 2;
        border-right: 0;
        border-top: 1px solid var(--line);
      }}
      #map {{
        order: 1;
      }}
    }}
  </style>
</head>
<body>
  <div class="app">
    <aside>
      <h1>{case_name}</h1>
      <div class="meta">Case ID: {case_id}<br>Generated at {html.escape(case.get("generated_at", ""))}<br>Source: {html.escape(case.get("source_folder", ""))}</div>
      <div class="stats">
        <div class="stat"><strong>{summary.get("total_images", 0)}</strong><span>Images</span></div>
        <div class="stat"><strong>{summary.get("gps_images", 0)}</strong><span>GPS hits</span></div>
        <div class="stat"><strong>{summary.get("successful_exif", 0)}</strong><span>EXIF success</span></div>
        <div class="stat"><strong>{summary.get("images_with_anomalies", 0)}</strong><span>Anomaly flags</span></div>
      </div>
      <div id="timeline" class="timeline"></div>
    </aside>
    <main id="map"></main>
  </div>

  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    const points = {points_json};
    const timeline = {timeline_json};
    const map = L.map('map').setView([{center[0]}, {center[1]}], points.length ? 11 : 5);
    L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap contributors'
    }}).addTo(map);

    const markers = [];
    const escapeHtml = (value) => String(value || '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');

    points.forEach((point, index) => {{
      const marker = L.marker([point.latitude, point.longitude]).addTo(map);
      const anomalyText = point.anomalies.length ? point.anomalies.map(escapeHtml).join('<br>') : 'None detected';
      marker.bindPopup(`
        <strong>${{escapeHtml(point.filename)}}</strong><br>
        Time: ${{escapeHtml(point.date_taken)}}<br>
        Camera: ${{escapeHtml(point.camera_model)}}<br>
        GPS: ${{point.latitude.toFixed(6)}}, ${{point.longitude.toFixed(6)}}<br>
        Anomalies: ${{anomalyText}}
      `);
      markers.push(marker);
    }});

    if (points.length > 1) {{
      L.polyline(points.map((point) => [point.latitude, point.longitude]), {{
        color: '#2563eb',
        weight: 4,
        opacity: 0.75
      }}).addTo(map);
    }}

    const timelineEl = document.querySelector('#timeline');
    if (!timeline.length) {{
      timelineEl.innerHTML = '<div class="empty">No supported images were found in this case.</div>';
    }} else if (!points.length) {{
      timelineEl.innerHTML = '<div class="empty">Images were analyzed, but no valid GPS coordinates were found. Check the HTML/PDF report for metadata and anomaly details.</div>';
    }} else {{
      timelineEl.innerHTML = timeline.map((item) => {{
        const pointIndex = points.findIndex((point) => point.filename === item.filename);
        const warning = item.anomalies && item.anomalies.length;
        const hasPoint = pointIndex >= 0;
        const button = hasPoint
          ? `<button type="button" data-point="${{pointIndex}}">${{escapeHtml(item.filename)}}</button>`
          : `<strong>${{escapeHtml(item.filename)}}</strong>`;
        return `<div class="item ${{warning ? 'warning' : ''}}">
          ${{button}}
          <small>${{escapeHtml(item.date_taken || 'Unknown capture time')}}</small>
          <small>${{hasPoint ? `${{item.latitude}}, ${{item.longitude}}` : 'No valid GPS'}}</small>
        </div>`;
      }}).join('');
    }}

    timelineEl.addEventListener('click', (event) => {{
      const button = event.target.closest('button[data-point]');
      if (!button) return;
      const marker = markers[Number(button.dataset.point)];
      if (!marker) return;
      map.setView(marker.getLatLng(), 15);
      marker.openPopup();
    }});
  </script>
</body>
</html>
"""
