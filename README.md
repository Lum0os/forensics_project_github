# Digital Image Metadata Extraction & Geolocation Analysis

Python forensic tool for extracting EXIF metadata from images, decoding GPS coordinates, building a geolocation timeline, detecting metadata anomalies, and generating evidence reports.

بالمصري: البرنامج بياخد فولدر صور، يطلع الميتاداتا المخفية زي نوع الكاميرا ووقت التصوير و GPS، وبعدها يعمل timeline وخريطة وتقرير forensic منظم. لو الصورة metadata بتاعتها متشالة أو فيها علامات تعديل، البرنامج بيطلع warning واضح.

## Features

- EXIF metadata extraction for Pillow-supported image formats, plus HEIC/HEIF EXIF candidates when `exifread` can parse them.
- GPS latitude/longitude decoding and Google Maps links.
- Interactive HTML map with chronological markers.
- Timeline sorted by capture time.
- Metadata anomaly detection for missing EXIF, missing timestamps, missing GPS, suspicious editing software, invalid GPS, and EXIF modified timestamps.
- Movement correlation between GPS-tagged images by distance, time gap, and estimated travel speed.
- JSON, HTML, and PDF forensic reports.
- Evidence chain with absolute path, file size, collection time, evidence ID, and SHA-256 hash.
- Premium PyQt5 desktop GUI with named cases, evidence/timeline/correlation/chain tabs, report buttons, and responsive background analysis.

## Install

```bash
pip install -r requirements.txt
```

On this machine, dependencies are already installed in the local `.venv`.

## Run The CLI

```bash
python main.py
```

On Windows, you can use the included launcher:

```bat
run_cli.bat
```

Analyze a custom folder:

```bash
python main.py --folder "C:\path\to\images"
```

Name a case:

```bash
python main.py --folder sample_images --case-name "Downtown Camera Timeline"
```

Write an exact JSON path:

```bash
python main.py --folder sample_images --output forensics_report.json
```

Skip saved reports and print only:

```bash
python main.py --folder sample_images --no-save
```

## Run The GUI

```bash
python main.py --gui
```

Or on Windows:

```bat
run_gui.bat
```

From the GUI, enter a case name, choose the evidence folder, choose the output folder, then run analysis. The generated report folder is named from the case.

لو PyQt5 مش متسطب، استخدم الأمر ده الأول:

```bash
pip install PyQt5
```

## Run Tests

```bash
python -m unittest discover -s tests
```

لو Windows مش شايف `python` في PATH، افتح Python من Start Menu أو ثبته من python.org وبعدها فعل اختيار `Add Python to PATH`.

## Output

Reports are created under:

```text
reports/<case_id>/
```

Each case folder can contain:

- `forensic_report.json`
- `forensic_report.html`
- `forensic_report.pdf`
- `geolocation_map.html`

## Workflow

```text
Select image folder
  -> Enter case name
  -> Extract EXIF metadata
  -> Decode and verify GPS coordinates
  -> Detect anomalies
  -> Build timeline and movement correlations
  -> Generate JSON, HTML, PDF, and map reports
```

## Requirement Coverage

- EXIF data extraction: implemented with Pillow plus `exifread` enrichment across the image formats available in the installed parser stack.
- GPS coordinate decoding and verification: implemented with decimal conversion, range validation, and map links.
- Interactive map visualization with timeline: generated as `geolocation_map.html`.
- Metadata anomaly detection: flags missing EXIF, missing timestamps, missing GPS, suspicious editing software, invalid GPS, and EXIF modified timestamps.
- Forensic report generation with evidence chain: JSON, HTML, PDF, SHA-256 hashes, file paths, collection time, and evidence IDs.

## Forensic Note

غياب EXIF أو GPS مش دليل لوحده إن الصورة متلاعب فيها. تطبيقات زي WhatsApp و Facebook و Instagram ساعات بتشيل metadata تلقائيا. اعتبرها indicator محتاج مقارنة مع باقي الأدلة وسلسلة الحيازة.
