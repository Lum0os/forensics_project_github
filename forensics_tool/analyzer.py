from __future__ import annotations

import hashlib
import math
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

try:
    import exifread
except ImportError:  # Optional: Pillow is the built-in fallback.
    exifread = None


def _supported_extensions() -> set[str]:
    try:
        Image.init()
        return {extension.lower() for extension in Image.registered_extensions()}
    except Exception:
        return {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp"}


SUPPORTED_EXTENSIONS = _supported_extensions() | {".heic", ".heif"}

SUSPICIOUS_SOFTWARE = {
    "photoshop",
    "snapseed",
    "lightroom",
    "canva",
    "gimp",
    "affinity photo",
    "picsart",
    "vsco",
}

DATE_FORMATS = (
    "%Y:%m:%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y:%m:%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
)

GPS_IFD = 34853
EXIF_IFD = 34665


def analyze_folder(folder_path: str | Path, recursive: bool = True) -> list[dict[str, Any]]:
    """Analyze all supported images in a folder."""
    folder = Path(folder_path)
    image_paths = list(_iter_image_paths(folder, recursive=recursive))
    records = [analyze_image(path) for path in image_paths]
    return sorted(records, key=_timeline_sort_key)


def analyze_image(image_path: str | Path) -> dict[str, Any]:
    """Extract metadata, GPS data, anomaly flags, and evidence hashes for one image."""
    path = Path(image_path)
    collected_at = _now_iso()
    record: dict[str, Any] = {
        "evidence_id": _evidence_id(path),
        "filename": path.name,
        "filepath": str(path.resolve()),
        "extension": path.suffix.lower(),
        "status": "Pending",
        "collected_at": collected_at,
        "sha256": None,
        "file_size_bytes": None,
        "file_created_at": None,
        "file_modified_at": None,
        "format": None,
        "mime_type": None,
        "image_width": None,
        "image_height": None,
        "camera_make": None,
        "camera_model": None,
        "lens_model": None,
        "software": None,
        "date_taken": None,
        "date_taken_iso": None,
        "gps_available": False,
        "gps_valid": False,
        "latitude": None,
        "longitude": None,
        "altitude": None,
        "maps_url": None,
        "exif": {},
        "xmp": {},
        "exif_tag_count": 0,
        "gps": {},
        "parser_warnings": [],
        "anomalies": [],
    }

    if not path.exists():
        record["status"] = "Error: file not found"
        record["anomalies"] = ["Evidence file was not found on disk"]
        return record

    if not path.is_file():
        record["status"] = "Error: not a regular file"
        record["anomalies"] = ["Evidence path is not a regular file"]
        return record

    record.update(_file_evidence(path))

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        record["status"] = "Unsupported image format"
        record["anomalies"] = ["File extension is not in the supported image list"]
        return record

    exifread_tags = _extract_exifread_tags(path)
    xmp_tags = _extract_xmp_tags(path)
    pillow_tags: dict[str, Any] = {}
    pillow_gps: dict[str, Any] = {}

    try:
        with Image.open(path) as image:
            record["format"] = image.format
            record["mime_type"] = Image.MIME.get(image.format or "")
            record["image_width"], record["image_height"] = image.size
            pillow_tags, pillow_gps = _extract_pillow_exif(image)
    except UnidentifiedImageError:
        if not exifread_tags and not xmp_tags:
            record["status"] = "Error: image could not be decoded"
            record["anomalies"] = ["Image parser could not identify this file as a valid image"]
            return record
        record["status"] = "Error: image could not be decoded"
        record["parser_warnings"].append("Pillow could not decode image pixels; EXIF was extracted with exifread only")
    except OSError as exc:
        if not exifread_tags and not xmp_tags:
            record["status"] = f"Error: {exc}"
            record["anomalies"] = ["Image could not be opened by the forensic parser"]
            return record
        record["status"] = f"Warning: {exc}"
        record["parser_warnings"].append("Pillow could not open image pixels; EXIF was extracted with exifread only")

    merged_tags = {**xmp_tags, **exifread_tags, **pillow_tags}
    record["exif"] = dict(sorted(merged_tags.items()))
    record["xmp"] = dict(sorted(xmp_tags.items()))
    record["exif_tag_count"] = len(merged_tags)
    record["gps"] = _gps_metadata(pillow_gps, merged_tags)

    if merged_tags:
        record["status"] = "Success"
    else:
        record["status"] = "No EXIF metadata found"

    _apply_common_fields(record, merged_tags)
    _apply_gps_fields(record, pillow_gps, merged_tags)
    record["anomalies"] = detect_anomalies(record)
    return record


def build_case(
    folder_path: str | Path,
    records: list[dict[str, Any]],
    case_id: str | None = None,
    case_name: str | None = None,
) -> dict[str, Any]:
    """Build a full case object containing summary, timeline, correlations, and chain."""
    case_name = (case_name or "").strip() or (case_id or "").strip() or "Digital Image Metadata Case"
    case_id = _safe_case_id(case_id) if case_id else _case_id_from_name(case_name)
    gps_records = [item for item in records if item.get("gps_valid")]
    anomaly_records = [item for item in records if item.get("anomalies")]
    models = sorted(
        {
            item.get("camera_model")
            for item in records
            if item.get("camera_model")
        }
    )

    return {
        "case_id": case_id,
        "case_name": case_name,
        "source_folder": str(Path(folder_path).resolve()),
        "generated_at": _now_iso(),
        "summary": {
            "total_images": len(records),
            "successful_exif": sum(1 for item in records if item.get("status") == "Success"),
            "gps_images": len(gps_records),
            "images_with_anomalies": len(anomaly_records),
            "camera_models": models,
        },
        "timeline": build_timeline(records),
        "correlations": build_correlations(records),
        "evidence_chain": build_evidence_chain(records),
        "images": records,
        "reports": {},
    }


def build_timeline(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a compact chronological timeline from image records."""
    timeline = []
    for item in sorted(records, key=_timeline_sort_key):
        timeline.append(
            {
                "filename": item.get("filename"),
                "date_taken": item.get("date_taken"),
                "date_taken_iso": item.get("date_taken_iso"),
                "camera_model": item.get("camera_model"),
                "latitude": item.get("latitude"),
                "longitude": item.get("longitude"),
                "gps_available": item.get("gps_available"),
                "gps_valid": item.get("gps_valid"),
                "status": item.get("status"),
                "anomalies": item.get("anomalies", []),
            }
        )
    return timeline


def build_correlations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate consecutive GPS images by time and distance."""
    dated_gps = [
        item
        for item in sorted(records, key=_timeline_sort_key)
        if item.get("gps_valid") and _parse_exif_datetime(item.get("date_taken"))
    ]

    correlations: list[dict[str, Any]] = []
    for previous, current in zip(dated_gps, dated_gps[1:]):
        previous_date = _parse_exif_datetime(previous.get("date_taken"))
        current_date = _parse_exif_datetime(current.get("date_taken"))
        if not previous_date or not current_date:
            continue

        distance_km = _haversine_km(
            float(previous["latitude"]),
            float(previous["longitude"]),
            float(current["latitude"]),
            float(current["longitude"]),
        )
        minutes = max((current_date - previous_date).total_seconds() / 60.0, 0.0)
        speed_kmh = (distance_km / (minutes / 60.0)) if minutes else None
        note = "Normal movement"

        if distance_km <= 0.1 and minutes <= 30:
            note = "Same-area image cluster"
        elif speed_kmh is not None and speed_kmh > 300:
            note = "Unusually high travel speed; verify timestamps and GPS"

        correlations.append(
            {
                "from": previous.get("filename"),
                "to": current.get("filename"),
                "from_time": previous.get("date_taken"),
                "to_time": current.get("date_taken"),
                "distance_km": round(distance_km, 3),
                "time_gap_minutes": round(minutes, 2),
                "estimated_speed_kmh": round(speed_kmh, 2) if speed_kmh is not None else None,
                "note": note,
            }
        )

    return correlations


def build_evidence_chain(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a chain-of-custody friendly evidence summary."""
    chain = []
    for item in records:
        chain.append(
            {
                "evidence_id": item.get("evidence_id"),
                "filename": item.get("filename"),
                "filepath": item.get("filepath"),
                "sha256": item.get("sha256"),
                "file_size_bytes": item.get("file_size_bytes"),
                "collected_at": item.get("collected_at"),
                "analysis_status": item.get("status"),
            }
        )
    return chain


def detect_anomalies(record: dict[str, Any]) -> list[str]:
    """Apply practical forensic rules to flag metadata risks."""
    anomalies: list[str] = []
    status = record.get("status")

    if status == "No EXIF metadata found":
        anomalies.append("No EXIF metadata found; possible metadata stripping or platform re-save")
    elif status != "Success":
        anomalies.append("Image could not be fully processed")

    if status == "Success" and not record.get("date_taken"):
        anomalies.append("Missing original capture timestamp")

    if status == "Success" and not record.get("gps_available"):
        anomalies.append("No GPS data embedded")

    if record.get("gps_available") and not record.get("gps_valid"):
        anomalies.append("GPS coordinates are outside valid latitude/longitude ranges")

    if status == "Success" and not record.get("camera_make") and not record.get("camera_model"):
        anomalies.append("No camera make/model recorded")

    anomalies.extend(record.get("parser_warnings") or [])

    software = str(record.get("software") or "")
    for tool in sorted(SUSPICIOUS_SOFTWARE):
        if tool in software.lower():
            anomalies.append(f"Edited or exported with suspicious software tag: {software}")
            break

    date_taken = _parse_exif_datetime(record.get("date_taken"))
    if date_taken:
        if date_taken > datetime.now() + timedelta(days=1):
            anomalies.append("Capture timestamp is in the future")

        exif_modified = _parse_exif_datetime(
            (record.get("exif") or {}).get("DateTime")
            or (record.get("exif") or {}).get("Image DateTime")
        )
        if exif_modified and exif_modified > date_taken + timedelta(days=1):
            anomalies.append("EXIF modified timestamp is later than original capture time")

    return anomalies


def _iter_image_paths(folder: Path, recursive: bool) -> list[Path]:
    if not folder.exists():
        return []

    iterator = folder.rglob("*") if recursive else folder.iterdir()
    paths = [
        path
        for path in iterator
        if path.is_file()
        and not path.name.startswith(".")
        and path.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    return sorted(paths, key=lambda item: str(item).lower())


def _extract_pillow_exif(image: Image.Image) -> tuple[dict[str, Any], dict[str, Any]]:
    tags: dict[str, Any] = {}
    gps: dict[str, Any] = {}

    try:
        exif = image.getexif()
    except Exception:
        return tags, gps

    if not exif:
        return tags, gps

    for tag_id, value in exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag_name in {"ExifOffset", "GPSInfo"}:
            continue
        tags[tag_name] = _jsonable(value)

    if hasattr(exif, "get_ifd"):
        for ifd_id, mapping in ((EXIF_IFD, ExifTags.TAGS), (GPS_IFD, ExifTags.GPSTAGS)):
            try:
                ifd = exif.get_ifd(ifd_id)
            except Exception:
                ifd = {}

            for tag_id, value in ifd.items():
                tag_name = mapping.get(tag_id, str(tag_id))
                if ifd_id == GPS_IFD:
                    gps[tag_name] = value
                    tags[f"GPS {tag_name}"] = _jsonable(value)
                else:
                    tags[tag_name] = _jsonable(value)

    return tags, gps


def _extract_exifread_tags(path: Path) -> dict[str, Any]:
    if exifread is None:
        return {}

    try:
        with path.open("rb") as file:
            tags = exifread.process_file(file, details=False, strict=False)
    except Exception:
        return {}

    return {str(key): str(value) for key, value in tags.items()}


def _extract_xmp_tags(path: Path) -> dict[str, Any]:
    xmp_text = _read_xmp_packet(path)
    if not xmp_text:
        return {}

    tags: dict[str, Any] = {}
    try:
        root = ET.fromstring(xmp_text)
    except ET.ParseError:
        root = None

    if root is not None:
        for element in root.iter():
            for raw_key, value in element.attrib.items():
                if value in (None, ""):
                    continue
                tags[_xmp_key(raw_key)] = value.strip()
            if element.text and element.text.strip():
                tags[_xmp_key(element.tag)] = element.text.strip()

    # Regex fallback catches common attribute forms even if the packet is not clean XML.
    for match in re.finditer(r"([A-Za-z0-9_:-]+)\s*=\s*['\"]([^'\"]+)['\"]", xmp_text):
        key, value = match.groups()
        if ":" in key and value.strip():
            tags.setdefault(_xmp_key(key), value.strip())

    return _normalize_xmp_tags(tags)


def _read_xmp_packet(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    match = re.search(rb"<x:xmpmeta[\s\S]*?</x:xmpmeta>", raw)
    if not match:
        match = re.search(rb"<rdf:RDF[\s\S]*?</rdf:RDF>", raw)
    if not match:
        return None

    packet = match.group(0)
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return packet.decode(encoding, errors="ignore").strip()
        except UnicodeError:
            continue
    return None


def _xmp_key(raw_key: str) -> str:
    key = raw_key.split("}", 1)[-1]
    return key.replace(":", " ").strip()


def _normalize_xmp_tags(tags: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(tags)
    mappings = {
        "tiff Make": "Make",
        "Make": "Make",
        "tiff Model": "Model",
        "Model": "Model",
        "xmp CreatorTool": "Software",
        "CreatorTool": "Software",
        "Software": "Software",
        "exif DateTimeOriginal": "DateTimeOriginal",
        "DateTimeOriginal": "DateTimeOriginal",
        "xmp CreateDate": "DateTimeOriginal",
        "CreateDate": "DateTimeOriginal",
        "photoshop DateCreated": "DateTimeOriginal",
        "DateCreated": "DateTimeOriginal",
        "xmp ModifyDate": "DateTime",
        "ModifyDate": "DateTime",
        "exif GPSLatitude": "GPS GPSLatitude",
        "GPSLatitude": "GPS GPSLatitude",
        "exif GPSLongitude": "GPS GPSLongitude",
        "GPSLongitude": "GPS GPSLongitude",
        "exif GPSAltitude": "GPS GPSAltitude",
        "GPSAltitude": "GPS GPSAltitude",
    }
    for source, target in mappings.items():
        if source in tags and target not in normalized:
            normalized[target] = tags[source]
    return normalized


def _apply_common_fields(record: dict[str, Any], tags: dict[str, Any]) -> None:
    record["camera_make"] = _first(tags, "Make", "Image Make")
    record["camera_model"] = _first(tags, "Model", "Image Model")
    record["software"] = _first(tags, "Software", "Image Software")
    record["lens_model"] = _first(tags, "LensModel", "EXIF LensModel")

    record["date_taken"] = _first(
        tags,
        "DateTimeOriginal",
        "EXIF DateTimeOriginal",
        "DateTimeDigitized",
        "DateTime",
        "Image DateTime",
    )
    parsed_date = _parse_exif_datetime(record["date_taken"])
    if parsed_date:
        record["date_taken_iso"] = parsed_date.isoformat(timespec="seconds")

    record["iso"] = _first(tags, "ISOSpeedRatings", "PhotographicSensitivity", "EXIF ISOSpeedRatings")
    record["exposure_time"] = _first(tags, "ExposureTime", "EXIF ExposureTime")
    record["f_number"] = _first(tags, "FNumber", "EXIF FNumber")
    record["focal_length"] = _first(tags, "FocalLength", "EXIF FocalLength")
    record["flash"] = _first(tags, "Flash", "EXIF Flash")
    record["orientation"] = _first(tags, "Orientation", "Image Orientation")

    width = _first(tags, "ExifImageWidth", "ImageWidth", "EXIF ExifImageWidth")
    height = _first(tags, "ExifImageHeight", "ExifImageLength", "ImageLength", "EXIF ExifImageLength")
    record["exif_image_width"] = width
    record["exif_image_height"] = height


def _apply_gps_fields(
    record: dict[str, Any],
    pillow_gps: dict[str, Any],
    tags: dict[str, Any],
) -> None:
    gps_lookup = {**tags, **pillow_gps}
    lat_value = gps_lookup.get("GPSLatitude") or gps_lookup.get("GPS GPSLatitude")
    lon_value = gps_lookup.get("GPSLongitude") or gps_lookup.get("GPS GPSLongitude")
    latitude = _dms_to_decimal(
        lat_value,
        gps_lookup.get("GPSLatitudeRef") or gps_lookup.get("GPS GPSLatitudeRef"),
    )
    longitude = _dms_to_decimal(
        lon_value,
        gps_lookup.get("GPSLongitudeRef") or gps_lookup.get("GPS GPSLongitudeRef"),
    )

    altitude = gps_lookup.get("GPSAltitude") or gps_lookup.get("GPS GPSAltitude")
    altitude_ref = str(gps_lookup.get("GPSAltitudeRef") or gps_lookup.get("GPS GPSAltitudeRef") or "0")

    if latitude is None or longitude is None:
        return

    record["gps_available"] = True
    record["latitude"] = round(latitude, 8)
    record["longitude"] = round(longitude, 8)
    record["gps_valid"] = -90 <= latitude <= 90 and -180 <= longitude <= 180
    record["maps_url"] = f"https://maps.google.com/?q={latitude:.8f},{longitude:.8f}"

    if altitude is not None:
        altitude_value = _ratio_to_float(altitude)
        if altitude_value is not None:
            if altitude_ref.strip() == "1":
                altitude_value *= -1
            record["altitude"] = round(altitude_value, 3)


def _dms_to_decimal(value: Any, ref: Any) -> float | None:
    if value is None:
        return None

    embedded_ref = None
    if isinstance(value, str):
        match = re.search(r"([NSEW])\s*$", value.strip(), flags=re.IGNORECASE)
        if match:
            embedded_ref = match.group(1).upper()

    ref = ref or embedded_ref
    parts = _coerce_dms(value)
    if len(parts) == 1:
        decimal = parts[0]
    elif len(parts) == 2:
        decimal = parts[0] + (parts[1] / 60.0)
    elif len(parts) == 3:
        degrees, minutes, seconds = parts
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
    else:
        return None

    ref_text = str(ref or "").strip().upper()
    if ref_text in {"S", "W"}:
        decimal *= -1
    return decimal


def _coerce_dms(value: Any) -> list[float]:
    if isinstance(value, str):
        cleaned = value.strip().strip("[]()")
        cleaned = re.sub(r"[NSEW]\s*$", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = cleaned.replace("deg", " ").replace("'", " ").replace('"', " ")
        pieces = [piece for piece in re.split(r"[\s,;]+", cleaned) if piece]
        return [_ratio_to_float(piece) or 0.0 for piece in pieces]

    if isinstance(value, (list, tuple)):
        return [_ratio_to_float(part) or 0.0 for part in value]

    if hasattr(value, "values"):
        return [_ratio_to_float(part) or 0.0 for part in value.values]

    return []


def _ratio_to_float(value: Any) -> float | None:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        text = value.strip()
        if "/" in text:
            numerator, denominator = text.split("/", 1)
            try:
                denominator_float = float(denominator)
                return float(numerator) / denominator_float if denominator_float else None
            except ValueError:
                return None
        try:
            return float(text)
        except ValueError:
            return None

    for numerator_name, denominator_name in (("num", "den"), ("numerator", "denominator")):
        if hasattr(value, numerator_name) and hasattr(value, denominator_name):
            numerator = getattr(value, numerator_name)
            denominator = getattr(value, denominator_name)
            try:
                denominator_float = float(denominator)
                return float(numerator) / denominator_float if denominator_float else None
            except (TypeError, ValueError, ZeroDivisionError):
                return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first(tags: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = tags.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return None


def _parse_exif_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    text = str(value).strip().replace("\x00", "")
    if not text:
        return None

    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=None)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return None


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).replace(tzinfo=None)
    except ValueError:
        return None


def _timeline_sort_key(item: dict[str, Any]) -> tuple[datetime, str]:
    return (_parse_exif_datetime(item.get("date_taken")) or datetime.max, item.get("filename", ""))


def _file_evidence(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "sha256": _sha256(path),
        "file_size_bytes": stat.st_size,
        "file_created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(timespec="seconds"),
        "file_modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_id(path: Path) -> str:
    safe_name = path.stem.replace(" ", "_")[:24] or "image"
    path_digest = hashlib.sha1(str(path.resolve()).lower().encode("utf-8")).hexdigest()[:8]
    return f"IMG-{safe_name}-{path_digest}"


def _case_id_from_name(case_name: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _safe_case_id(case_name).lower()
    if slug == "case":
        return f"case_{stamp}"
    return f"{slug}_{stamp}"


def _safe_case_id(value: str | None) -> str:
    text = (value or "").strip()
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("_")
    return safe[:80] or "case"


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return value.hex()

    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]

    ratio = _ratio_to_float(value)
    if ratio is not None and value.__class__.__name__.lower().endswith("rational"):
        return ratio

    return str(value)


def _jsonable_dict(values: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _jsonable(value) for key, value in sorted(values.items())}


def _gps_metadata(pillow_gps: dict[str, Any], tags: dict[str, Any]) -> dict[str, Any]:
    gps_values = _jsonable_dict(pillow_gps)
    for key, value in tags.items():
        key_text = str(key)
        if key_text.startswith("GPS ") or key_text.startswith("GPS"):
            clean_key = key_text[4:] if key_text.startswith("GPS ") else key_text
            gps_values[clean_key] = _jsonable(value)
    return dict(sorted(gps_values.items()))


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0088
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")
