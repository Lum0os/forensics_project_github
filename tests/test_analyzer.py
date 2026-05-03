from __future__ import annotations

import unittest
from pathlib import Path

from PIL import Image

from forensics_tool.analyzer import analyze_folder, analyze_image, build_case


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample_images"


class AnalyzerTests(unittest.TestCase):
    def test_sample_images_extract_timeline_and_gps(self) -> None:
        records = analyze_folder(SAMPLES)
        case = build_case(SAMPLES, records, case_id="unit_test_case", case_name="Unit Test Case")

        self.assertEqual(len(records), 5)
        self.assertEqual(case["case_name"], "Unit Test Case")
        self.assertEqual(case["summary"]["successful_exif"], 5)
        self.assertEqual(case["summary"]["gps_images"], 2)
        self.assertEqual(records[0]["filename"], "Fujifilm_FinePix6900ZOOM.jpg")

        nokia = next(item for item in records if item["filename"] == "HMD_Nokia_8.3_5G.jpg")
        self.assertTrue(nokia["gps_valid"])
        self.assertAlmostEqual(nokia["latitude"], 60.14670556, places=5)
        self.assertAlmostEqual(nokia["longitude"], 24.90677222, places=5)
        self.assertTrue(case["correlations"])

    def test_evidence_id_and_hash_are_repeatable(self) -> None:
        image_path = SAMPLES / "HMD_Nokia_8.3_5G.jpg"
        first = analyze_image(image_path)
        second = analyze_image(image_path)

        self.assertEqual(first["evidence_id"], second["evidence_id"])
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(len(first["sha256"]), 64)

    def test_xmp_only_gps_metadata_is_detected(self) -> None:
        xmp_packet = b"""
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description
      xmlns:tiff="http://ns.adobe.com/tiff/1.0/"
      xmlns:exif="http://ns.adobe.com/exif/1.0/"
      tiff:Make="Apple"
      tiff:Model="iPhone 12 Pro Max"
      exif:DateTimeOriginal="2022-02-24T10:15:00+02:00"
      exif:GPSLatitude="29,58,30.10N"
      exif:GPSLongitude="31,8,16.90E" />
  </rdf:RDF>
</x:xmpmeta>
"""
        temp_root = ROOT / "reports"
        temp_root.mkdir(exist_ok=True)
        image_path = temp_root / "_forensics_xmp_location_test.jpg"
        try:
            Image.new("RGB", (32, 24), color=(34, 64, 98)).save(image_path, format="JPEG")
            with image_path.open("ab") as file:
                file.write(xmp_packet)

            record = analyze_image(image_path)
        finally:
            image_path.unlink(missing_ok=True)

        self.assertEqual(record["status"], "Success")
        self.assertEqual(record["camera_model"], "iPhone 12 Pro Max")
        self.assertTrue(record["gps_valid"])
        self.assertAlmostEqual(record["latitude"], 29.97502778, places=5)
        self.assertAlmostEqual(record["longitude"], 31.13802778, places=5)


if __name__ == "__main__":
    unittest.main()
