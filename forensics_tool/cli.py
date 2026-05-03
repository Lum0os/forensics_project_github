from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .analyzer import analyze_folder, build_case
from .reports import write_all_reports


DEFAULT_FOLDER = "sample_images"
DEFAULT_OUTPUT_DIR = "reports"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.gui:
        return _launch_gui()

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"[ERROR] Folder not found: {folder}")
        return 1

    print(f"[INFO] Analyzing images in: {folder.resolve()}")
    records = analyze_folder(folder, recursive=not args.no_recursive)
    case = build_case(folder, records, case_id=args.case_id, case_name=args.case_name)
    print_console_report(case)

    if args.no_save:
        return 0

    paths = write_all_reports(
        case,
        output_dir=args.output_dir,
        json_output=args.output,
        make_map=not args.no_map,
        make_pdf=not args.no_pdf,
    )

    print("[INFO] Reports generated:")
    for report_type, path in paths.items():
        print(f"  {report_type:<5} -> {path}")

    return 0


def print_console_report(case: dict[str, Any]) -> None:
    summary = case.get("summary", {})
    print()
    print("=" * 64)
    print("DIGITAL IMAGE METADATA & GEOLOCATION FORENSIC REPORT")
    print("=" * 64)
    print(f"Case name        : {case.get('case_name')}")
    print(f"Case ID          : {case.get('case_id')}")
    print(f"Generated at     : {case.get('generated_at')}")
    print(f"Images analyzed  : {summary.get('total_images', 0)}")
    print(f"EXIF successes   : {summary.get('successful_exif', 0)}")
    print(f"GPS locations    : {summary.get('gps_images', 0)}")
    print(f"Anomaly images   : {summary.get('images_with_anomalies', 0)}")
    print("-" * 64)

    for index, item in enumerate(case.get("timeline", []), start=1):
        gps = "N/A"
        if item.get("gps_valid"):
            gps = f"{item.get('latitude')}, {item.get('longitude')}"
        anomalies = item.get("anomalies") or ["None detected"]
        print(f"[{index}] {item.get('filename')}")
        print(f"    Captured : {item.get('date_taken') or 'N/A'}")
        print(f"    Camera   : {item.get('camera_model') or 'N/A'}")
        print(f"    GPS      : {gps}")
        print(f"    Flags    : {'; '.join(anomalies)}")
    print()


def _launch_gui() -> int:
    try:
        from .gui import run_gui
    except ImportError as exc:
        print("[ERROR] GUI dependencies are missing. Install them with:")
        print("        pip install -r requirements.txt")
        print(f"        Details: {exc}")
        return 1

    run_gui()
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Digital Image Metadata Extraction and Geolocation Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py -f sample_images\n"
            "  python main.py -f C:\\photos -d reports\n"
            "  python main.py -f C:\\photos -o forensics_report.json\n"
            "  python main.py --gui\n"
        ),
    )
    parser.add_argument("-f", "--folder", default=DEFAULT_FOLDER, help="Folder containing images")
    parser.add_argument("-d", "--output-dir", default=DEFAULT_OUTPUT_DIR, help="Report output directory")
    parser.add_argument("-o", "--output", default=None, help="Optional exact JSON report path")
    parser.add_argument("--case-id", default=None, help="Optional case identifier")
    parser.add_argument("--case-name", default=None, help="Human-readable case name")
    parser.add_argument("--no-save", action="store_true", help="Print console report only")
    parser.add_argument("--no-map", action="store_true", help="Skip interactive map generation")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report generation")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan the top level of the folder")
    parser.add_argument("--gui", action="store_true", help="Launch the PyQt5 desktop interface")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
