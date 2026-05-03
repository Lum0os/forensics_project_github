from __future__ import annotations

import html
import sys
from pathlib import Path
from typing import Any

from PyQt5.QtCore import QObject, Qt, QThread, QUrl, pyqtSignal, qInstallMessageHandler
from PyQt5.QtGui import QColor, QDesktopServices, QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .analyzer import analyze_folder, build_case
from .reports import write_all_reports


def _qt_message_handler(_mode: Any, _context: Any, message: str) -> None:
    if "OpenType support missing" in message:
        return
    if "QFontDatabase: Cannot find font directory" in message:
        return
    if "Qt no longer ships fonts" in message:
        return
    sys.stderr.write(f"{message}\n")


class AnalysisWorker(QObject):
    finished = pyqtSignal(dict, dict)
    failed = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(
        self,
        folder: Path,
        case_name: str,
        output_dir: Path,
        recursive: bool,
        make_pdf: bool,
    ) -> None:
        super().__init__()
        self.folder = folder
        self.case_name = case_name
        self.output_dir = output_dir
        self.recursive = recursive
        self.make_pdf = make_pdf

    def run(self) -> None:
        try:
            self.status.emit("Extracting EXIF metadata and decoding GPS coordinates")
            records = analyze_folder(self.folder, recursive=self.recursive)
            self.status.emit("Building timeline, correlations, and evidence chain")
            case = build_case(self.folder, records, case_name=self.case_name)
            self.status.emit("Generating forensic reports and interactive map")
            report_paths = write_all_reports(case, output_dir=self.output_dir, make_pdf=self.make_pdf)
            self.finished.emit(case, report_paths)
        except Exception as exc:  # noqa: BLE001 - surfaced to investigator in the GUI.
            self.failed.emit(str(exc))


class StatCard(QFrame):
    def __init__(self, label: str, accent: str) -> None:
        super().__init__()
        self.setObjectName("StatCard")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.value_label = QLabel("0")
        self.value_label.setObjectName("StatValue")
        self.caption_label = QLabel(label)
        self.caption_label.setObjectName("StatCaption")
        self.accent = QFrame()
        self.accent.setFixedHeight(3)
        self.accent.setStyleSheet(f"background: {accent}; border-radius: 1px;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        layout.addWidget(self.value_label)
        layout.addWidget(self.caption_label)
        layout.addSpacing(4)
        layout.addWidget(self.accent)

    def set_value(self, value: Any) -> None:
        self.value_label.setText(str(value))


class ForensicsWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Digital Image Metadata & Geolocation Forensics")
        self.resize(1320, 820)
        self.setMinimumSize(1080, 680)

        self.folder = Path("sample_images")
        self.output_dir = Path("reports")
        self.case: dict[str, Any] = {}
        self.records: list[dict[str, Any]] = []
        self.report_paths: dict[str, str] = {}
        self.thread: QThread | None = None
        self.worker: AnalysisWorker | None = None

        self._build_ui()
        self._apply_style()
        self._set_empty_state()
        self.statusBar().showMessage("Ready")

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(22, 18, 22, 18)
        root_layout.setSpacing(16)

        root_layout.addLayout(self._build_header())

        body = QSplitter(Qt.Horizontal)
        body.setChildrenCollapsible(False)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_workspace())
        body.setStretchFactor(0, 0)
        body.setStretchFactor(1, 1)
        body.setSizes([360, 920])
        root_layout.addWidget(body, stretch=1)

        self.progress = QProgressBar()
        self.progress.setObjectName("FooterProgress")
        self.progress.setFixedWidth(160)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)
        self.setCentralWidget(root)

    def _build_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        title_block = QVBoxLayout()
        title_block.setSpacing(2)

        title = QLabel("Digital Image Metadata Forensics")
        title.setObjectName("AppTitle")
        subtitle = QLabel("EXIF extraction, geolocation timeline, anomaly review, and report generation")
        subtitle.setObjectName("AppSubtitle")

        title_block.addWidget(title)
        title_block.addWidget(subtitle)
        layout.addLayout(title_block)
        layout.addStretch(1)

        self.open_report_button = self._button("HTML Report", QStyle.SP_FileIcon)
        self.open_report_button.setToolTip("Open the generated forensic HTML report")
        self.open_report_button.clicked.connect(lambda: self.open_report("html"))
        self.open_report_button.setEnabled(False)

        self.open_map_button = self._button("Map", QStyle.SP_DialogOpenButton)
        self.open_map_button.setToolTip("Open the generated interactive geolocation map")
        self.open_map_button.clicked.connect(lambda: self.open_report("map"))
        self.open_map_button.setEnabled(False)

        self.open_pdf_button = self._button("PDF", QStyle.SP_FileDialogDetailedView)
        self.open_pdf_button.setToolTip("Open the generated PDF report")
        self.open_pdf_button.clicked.connect(lambda: self.open_report("pdf"))
        self.open_pdf_button.setEnabled(False)

        self.open_folder_button = self._button("Reports Folder", QStyle.SP_DirOpenIcon)
        self.open_folder_button.setToolTip("Open the report output folder")
        self.open_folder_button.clicked.connect(self.open_reports_folder)
        self.open_folder_button.setEnabled(False)

        layout.addWidget(self.open_report_button)
        layout.addWidget(self.open_map_button)
        layout.addWidget(self.open_pdf_button)
        layout.addWidget(self.open_folder_button)
        return layout

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setMinimumWidth(330)
        sidebar.setMaximumWidth(390)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        section = QLabel("Case Setup")
        section.setObjectName("SectionTitle")
        layout.addWidget(section)

        self.case_name_input = QLineEdit()
        self.case_name_input.setPlaceholderText("Case name")
        self.case_name_input.setText("Image Metadata Investigation")
        self.case_name_input.setClearButtonEnabled(True)
        layout.addWidget(self._field("Case Name", self.case_name_input))

        self.folder_input = QLineEdit(str(self.folder.resolve()))
        self.folder_input.setReadOnly(True)
        self.folder_input.setToolTip(str(self.folder.resolve()))
        folder_button = self._icon_button(QStyle.SP_DirOpenIcon, "Choose evidence folder")
        folder_button.clicked.connect(self.select_folder)
        layout.addWidget(self._path_picker("Evidence Folder", self.folder_input, folder_button))

        self.output_input = QLineEdit(str(self.output_dir.resolve()))
        self.output_input.setReadOnly(True)
        self.output_input.setToolTip(str(self.output_dir.resolve()))
        output_button = self._icon_button(QStyle.SP_DirHomeIcon, "Choose report output folder")
        output_button.clicked.connect(self.select_output_dir)
        layout.addWidget(self._path_picker("Output Folder", self.output_input, output_button))

        self.recursive_check = QCheckBox("Scan subfolders")
        self.recursive_check.setChecked(True)
        self.pdf_check = QCheckBox("Generate PDF report")
        self.pdf_check.setChecked(True)
        layout.addWidget(self.recursive_check)
        layout.addWidget(self.pdf_check)

        self.run_button = self._button("Run Analysis", QStyle.SP_MediaPlay, primary=True)
        self.run_button.setToolTip("Extract metadata, build timeline, detect anomalies, and generate reports")
        self.run_button.clicked.connect(self.run_analysis)
        layout.addWidget(self.run_button)

        layout.addSpacing(6)
        summary_title = QLabel("Case Summary")
        summary_title.setObjectName("SectionTitle")
        layout.addWidget(summary_title)

        self.stat_cards = {
            "total_images": StatCard("Images", "#38bdf8"),
            "successful_exif": StatCard("EXIF Success", "#34d399"),
            "gps_images": StatCard("GPS Hits", "#a78bfa"),
            "images_with_anomalies": StatCard("Anomaly Flags", "#fb7185"),
        }
        cards = QGridLayout()
        cards.setSpacing(10)
        cards.addWidget(self.stat_cards["total_images"], 0, 0)
        cards.addWidget(self.stat_cards["successful_exif"], 0, 1)
        cards.addWidget(self.stat_cards["gps_images"], 1, 0)
        cards.addWidget(self.stat_cards["images_with_anomalies"], 1, 1)
        layout.addLayout(cards)

        self.case_status = QLabel("No case analyzed yet")
        self.case_status.setObjectName("CaseStatus")
        self.case_status.setWordWrap(True)
        layout.addWidget(self.case_status)
        layout.addStretch(1)
        return sidebar

    def _build_workspace(self) -> QWidget:
        workspace = QFrame()
        workspace.setObjectName("Workspace")
        layout = QVBoxLayout(workspace)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.evidence_table = self._table(
            ["Evidence ID", "File", "Captured", "Camera", "GPS", "Tags", "Resolution", "Status", "Flags"]
        )
        self.evidence_table.itemSelectionChanged.connect(self.show_selected_evidence)

        self.detail_view = QTextBrowser()
        self.detail_view.setObjectName("DetailView")
        self.detail_view.setOpenExternalLinks(True)

        evidence_split = QSplitter(Qt.Vertical)
        evidence_split.addWidget(self.evidence_table)
        evidence_split.addWidget(self.detail_view)
        evidence_split.setStretchFactor(0, 3)
        evidence_split.setStretchFactor(1, 2)
        evidence_split.setSizes([470, 250])
        self.tabs.addTab(evidence_split, "Evidence")

        self.timeline_table = self._table(["Step", "Captured", "File", "GPS", "Camera", "Flags"])
        self.tabs.addTab(self.timeline_table, "Timeline")

        self.correlation_table = self._table(["From", "To", "Time Gap", "Distance", "Speed", "Assessment"])
        self.tabs.addTab(self.correlation_table, "Correlations")

        self.chain_table = self._table(["Evidence ID", "File", "Size", "Collected", "SHA-256", "Path"])
        self.tabs.addTab(self.chain_table, "Evidence Chain")

        self.report_view = QTextBrowser()
        self.report_view.setObjectName("ReportView")
        self.report_view.setOpenExternalLinks(True)
        self.tabs.addTab(self.report_view, "Reports")

        layout.addWidget(self.tabs)
        return workspace

    def _field(self, label: str, widget: QWidget) -> QWidget:
        frame = QWidget()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        label_widget = QLabel(label)
        label_widget.setObjectName("FieldLabel")
        layout.addWidget(label_widget)
        layout.addWidget(widget)
        return frame

    def _path_picker(self, label: str, line_edit: QLineEdit, button: QPushButton) -> QWidget:
        wrapper = QWidget()
        outer = QVBoxLayout(wrapper)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)
        label_widget = QLabel(label)
        label_widget.setObjectName("FieldLabel")
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(line_edit, stretch=1)
        row.addWidget(button)
        outer.addWidget(label_widget)
        outer.addLayout(row)
        return wrapper

    def _button(self, text: str, icon: QStyle.StandardPixmap, primary: bool = False) -> QPushButton:
        button = QPushButton(text)
        button.setIcon(self.style().standardIcon(icon))
        button.setMinimumHeight(36)
        button.setCursor(Qt.PointingHandCursor)
        button.setProperty("primary", "true" if primary else "false")
        return button

    def _icon_button(self, icon: QStyle.StandardPixmap, tooltip: str) -> QPushButton:
        button = QPushButton()
        button.setIcon(self.style().standardIcon(icon))
        button.setToolTip(tooltip)
        button.setFixedSize(38, 36)
        button.setCursor(Qt.PointingHandCursor)
        return button

    def _table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.setSortingEnabled(False)
        table.setShowGrid(False)
        return table

    def _apply_style(self) -> None:
        font = QFont("Segoe UI", 10)
        QApplication.instance().setFont(font)
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #0b1020;
                color: #e5edf7;
            }
            #AppTitle {
                font-size: 28px;
                font-weight: 700;
                color: #f8fbff;
            }
            #AppSubtitle {
                color: #9fb0c7;
                font-size: 12px;
            }
            #Sidebar {
                background: #111827;
                border: 1px solid #263247;
                border-radius: 10px;
            }
            #Workspace {
                background: #101827;
                border: 1px solid #263247;
                border-radius: 10px;
            }
            #SectionTitle {
                color: #f8fbff;
                font-size: 14px;
                font-weight: 700;
            }
            #FieldLabel {
                color: #9fb0c7;
                font-size: 12px;
                font-weight: 650;
            }
            QLineEdit {
                background: #0b1220;
                border: 1px solid #31415c;
                border-radius: 8px;
                min-height: 34px;
                padding: 0 10px;
                color: #eef5ff;
                selection-background-color: #2563eb;
            }
            QLineEdit:focus {
                border: 1px solid #38bdf8;
                background: #0e1729;
            }
            QCheckBox {
                color: #d7e3f3;
                spacing: 8px;
                min-height: 22px;
            }
            QPushButton {
                background: #172033;
                border: 1px solid #34445f;
                border-radius: 8px;
                padding: 7px 11px;
                color: #e5edf7;
                font-weight: 650;
            }
            QPushButton:hover {
                border-color: #38bdf8;
                background: #1e2a44;
            }
            QPushButton:disabled {
                color: #64748b;
                background: #111827;
                border-color: #253044;
            }
            QPushButton[primary="true"] {
                background: #2563eb;
                color: white;
                border-color: #38bdf8;
            }
            QPushButton[primary="true"]:hover {
                background: #1d4ed8;
                border-color: #7dd3fc;
            }
            #StatCard {
                background: #0f172a;
                border: 1px solid #28364f;
                border-radius: 10px;
            }
            #StatValue {
                color: #f8fbff;
                font-size: 24px;
                font-weight: 750;
            }
            #StatCaption {
                color: #9fb0c7;
                font-size: 12px;
            }
            #CaseStatus {
                color: #d7e3f3;
                background: #0f172a;
                border: 1px solid #28364f;
                border-radius: 10px;
                padding: 10px;
                line-height: 1.4;
            }
            QTabWidget::pane {
                border: 0;
                background: #101827;
                border-radius: 10px;
            }
            QTabBar::tab {
                background: #101827;
                color: #9fb0c7;
                padding: 12px 15px;
                border: 0;
                border-bottom: 2px solid transparent;
                font-weight: 650;
            }
            QTabBar::tab:selected {
                color: #7dd3fc;
                border-bottom: 2px solid #38bdf8;
            }
            QTableWidget {
                background: #101827;
                alternate-background-color: #0f172a;
                border: 0;
                color: #e5edf7;
                selection-background-color: #1e3a8a;
                selection-color: #f8fbff;
            }
            QHeaderView::section {
                background: #172033;
                color: #a9bad3;
                border: 0;
                border-bottom: 1px solid #2b3954;
                padding: 9px;
                font-size: 12px;
                font-weight: 700;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #1f2b40;
            }
            #DetailView, #ReportView {
                background: #0f172a;
                border: 1px solid #28364f;
                border-radius: 10px;
                padding: 12px;
                color: #e5edf7;
            }
            QSplitter::handle {
                background: #172033;
            }
            QStatusBar {
                background: #0b1020;
                color: #9fb0c7;
            }
            #FooterProgress {
                border: 1px solid #31415c;
                border-radius: 5px;
                background: #111827;
                text-align: center;
            }
            #FooterProgress::chunk {
                background: #38bdf8;
                border-radius: 4px;
            }
            """
        )

    def select_folder(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select image evidence folder", str(self.folder.resolve()))
        if selected:
            self.folder = Path(selected)
            self.folder_input.setText(str(self.folder.resolve()))
            self.folder_input.setToolTip(str(self.folder.resolve()))

    def select_output_dir(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select report output folder", str(self.output_dir.resolve()))
        if selected:
            self.output_dir = Path(selected)
            self.output_input.setText(str(self.output_dir.resolve()))
            self.output_input.setToolTip(str(self.output_dir.resolve()))

    def run_analysis(self) -> None:
        if self.thread and self.thread.isRunning():
            return

        if not self.folder.is_dir():
            QMessageBox.warning(self, "Folder not found", f"The folder does not exist:\n{self.folder}")
            return

        case_name = self.case_name_input.text().strip() or "Digital Image Metadata Case"
        self._set_busy(True, "Starting analysis")

        self.thread = QThread(self)
        self.worker = AnalysisWorker(
            folder=self.folder,
            case_name=case_name,
            output_dir=self.output_dir,
            recursive=self.recursive_check.isChecked(),
            make_pdf=self.pdf_check.isChecked(),
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.status.connect(self._set_status)
        self.worker.finished.connect(self._analysis_finished)
        self.worker.failed.connect(self._analysis_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.failed.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: setattr(self, "thread", None))
        self.thread.start()

    def _analysis_finished(self, case: dict[str, Any], report_paths: dict[str, str]) -> None:
        self.case = case
        self.records = case.get("images", [])
        self.report_paths = report_paths
        self.populate(case)
        self._set_busy(False, "Analysis complete")
        self._update_report_buttons()
        self.tabs.setCurrentIndex(0)

    def _analysis_failed(self, message: str) -> None:
        self._set_busy(False, "Analysis failed")
        QMessageBox.critical(self, "Analysis failed", message)

    def populate(self, case: dict[str, Any]) -> None:
        self._populate_evidence(case.get("images", []))
        self._populate_timeline(case.get("timeline", []))
        self._populate_correlations(case.get("correlations", []))
        self._populate_chain(case.get("evidence_chain", []))
        self._populate_reports()
        self._populate_stats(case)
        if self.evidence_table.rowCount():
            self.evidence_table.selectRow(0)
        else:
            self.detail_view.setHtml(self._empty_html("No supported images were found."))

    def _populate_evidence(self, records: list[dict[str, Any]]) -> None:
        rows = []
        for item in records:
            gps = self._gps_text(item)
            resolution = "N/A"
            if item.get("image_width") and item.get("image_height"):
                resolution = f"{item.get('image_width')} x {item.get('image_height')}"
            rows.append(
                [
                    item.get("evidence_id"),
                    item.get("filename"),
                    item.get("date_taken") or "N/A",
                    item.get("camera_model") or "N/A",
                    gps,
                    item.get("exif_tag_count", 0),
                    resolution,
                    item.get("status"),
                    self._flags_text(item),
                ]
            )
        self._fill_table(self.evidence_table, rows, records)

    def _populate_timeline(self, timeline: list[dict[str, Any]]) -> None:
        rows = []
        for index, item in enumerate(timeline, start=1):
            rows.append(
                [
                    index,
                    item.get("date_taken") or "Unknown",
                    item.get("filename"),
                    self._gps_text(item),
                    item.get("camera_model") or "N/A",
                    self._flags_text(item),
                ]
            )
        self._fill_table(self.timeline_table, rows, timeline)

    def _populate_correlations(self, correlations: list[dict[str, Any]]) -> None:
        rows = []
        for item in correlations:
            speed = item.get("estimated_speed_kmh")
            rows.append(
                [
                    item.get("from"),
                    item.get("to"),
                    f"{item.get('time_gap_minutes', 0)} min",
                    f"{item.get('distance_km', 0)} km",
                    f"{speed} km/h" if speed is not None else "N/A",
                    item.get("note") or "N/A",
                ]
            )
        self._fill_table(self.correlation_table, rows, correlations)

    def _populate_chain(self, chain: list[dict[str, Any]]) -> None:
        rows = []
        for item in chain:
            rows.append(
                [
                    item.get("evidence_id"),
                    item.get("filename"),
                    self._size_text(item.get("file_size_bytes")),
                    item.get("collected_at"),
                    item.get("sha256"),
                    item.get("filepath"),
                ]
            )
        self._fill_table(self.chain_table, rows, chain)

    def _populate_stats(self, case: dict[str, Any]) -> None:
        summary = case.get("summary", {})
        for key, card in self.stat_cards.items():
            card.set_value(summary.get(key, 0))

        models = ", ".join(summary.get("camera_models", [])) or "No camera models recorded"
        self.case_status.setText(
            f"{case.get('case_name')} | {case.get('case_id')}\n"
            f"Generated: {case.get('generated_at')}\n"
            f"Camera models: {models}"
        )

    def _populate_reports(self) -> None:
        if not self.report_paths:
            self.report_view.setHtml(self._empty_html("Reports have not been generated yet."))
            return

        links = []
        for label, key in (("Interactive map", "map"), ("HTML report", "html"), ("PDF report", "pdf"), ("JSON evidence", "json")):
            path = self.report_paths.get(key)
            if not path:
                continue
            url = Path(path).resolve().as_uri()
            links.append(f'<p><b>{html.escape(label)}</b><br><a href="{url}">{html.escape(path)}</a></p>')

        self.report_view.setHtml(
            """
            <html><body style="font-family: Segoe UI; color: #e5edf7; background: #0f172a;">
            <h2 style="margin-top: 0; color:#f8fbff;">Generated Reports</h2>
            """
            + "".join(links)
            + "</body></html>"
        )

    def _fill_table(self, table: QTableWidget, rows: list[list[Any]], row_payloads: list[dict[str, Any]]) -> None:
        table.setRowCount(len(rows))
        for row_index, values in enumerate(rows):
            payload = row_payloads[row_index] if row_index < len(row_payloads) else {}
            has_warning = bool(payload.get("anomalies")) or "Unusually" in str(payload.get("note", ""))
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(str(value if value is not None else "N/A"))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                item.setToolTip(str(value if value is not None else "N/A"))
                if column_index == 0:
                    item.setData(Qt.UserRole, row_index)
                if has_warning:
                    item.setBackground(QColor("#402033"))
                    item.setForeground(QColor("#ffe4e6"))
                elif payload.get("gps_valid"):
                    item.setBackground(QColor("#123426"))
                    item.setForeground(QColor("#d1fae5"))
                table.setItem(row_index, column_index, item)
        table.resizeRowsToContents()

    def show_selected_evidence(self) -> None:
        row = self.evidence_table.currentRow()
        if row < 0 or row >= len(self.records):
            return
        self.detail_view.setHtml(self._record_html(self.records[row]))

    def _record_html(self, item: dict[str, Any]) -> str:
        gps = self._gps_text(item)
        anomalies = item.get("anomalies") or []
        anomalies_html = "".join(f"<li>{html.escape(flag)}</li>" for flag in anomalies) or "<li>None detected</li>"
        maps_link = ""
        if item.get("maps_url"):
            maps_link = f'<tr><th>Maps URL</th><td><a href="{html.escape(item["maps_url"])}">{html.escape(item["maps_url"])}</a></td></tr>'

        exif_rows = []
        for key, value in sorted((item.get("exif") or {}).items()):
            exif_rows.append(
                f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
            )
        exif_html = "".join(exif_rows) or '<tr><td colspan="2">No EXIF tags found.</td></tr>'

        preview = ""
        path = Path(str(item.get("filepath") or ""))
        if path.exists() and item.get("format"):
            preview = (
                f'<img src="{path.resolve().as_uri()}" '
                'style="max-width: 360px; max-height: 230px; border-radius: 12px; '
                'border: 1px solid #334155; object-fit: contain; background: #020617;">'
            )

        return f"""
        <html>
        <body style="font-family: Segoe UI; color: #e5edf7; background: #0f172a;">
          <h2 style="margin-top:0; color:#f8fbff;">{html.escape(str(item.get("filename") or "Evidence"))}</h2>
          {preview}
          <table width="100%" cellspacing="0" cellpadding="6" style="margin-top: 12px;">
            <tr><th align="left">Evidence ID</th><td>{html.escape(str(item.get("evidence_id") or "N/A"))}</td></tr>
            <tr><th align="left">Status</th><td>{html.escape(str(item.get("status") or "N/A"))}</td></tr>
            <tr><th align="left">EXIF/XMP Tags</th><td>{html.escape(str(item.get("exif_tag_count") or 0))}</td></tr>
            <tr><th align="left">Captured</th><td>{html.escape(str(item.get("date_taken") or "N/A"))}</td></tr>
            <tr><th align="left">Camera</th><td>{html.escape(str(item.get("camera_model") or "N/A"))}</td></tr>
            <tr><th align="left">Software</th><td>{html.escape(str(item.get("software") or "N/A"))}</td></tr>
            <tr><th align="left">GPS</th><td>{html.escape(gps)}</td></tr>
            {maps_link}
            <tr><th align="left">SHA-256</th><td><code>{html.escape(str(item.get("sha256") or "N/A"))}</code></td></tr>
            <tr><th align="left">Path</th><td>{html.escape(str(item.get("filepath") or "N/A"))}</td></tr>
          </table>
          <h3 style="color:#7dd3fc;">Anomaly Review</h3>
          <ul>{anomalies_html}</ul>
          <h3 style="color:#7dd3fc;">Extracted EXIF/XMP Tags</h3>
          <table width="100%" cellspacing="0" cellpadding="5">{exif_html}</table>
        </body>
        </html>
        """

    def _set_empty_state(self) -> None:
        for card in self.stat_cards.values():
            card.set_value(0)
        self.evidence_table.setRowCount(0)
        self.timeline_table.setRowCount(0)
        self.correlation_table.setRowCount(0)
        self.chain_table.setRowCount(0)
        self.detail_view.setHtml(self._empty_html("Select an evidence folder and run analysis."))
        self.report_view.setHtml(self._empty_html("Reports will appear after analysis."))

    def _empty_html(self, message: str) -> str:
        return (
            '<html><body style="font-family: Segoe UI; color: #9fb0c7; background: #0f172a;">'
            f'<div style="padding: 18px;">{html.escape(message)}</div>'
            "</body></html>"
        )

    def _set_busy(self, busy: bool, message: str) -> None:
        self.run_button.setEnabled(not busy)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
        self._set_status(message)

    def _set_status(self, message: str) -> None:
        self.statusBar().showMessage(message)

    def _update_report_buttons(self) -> None:
        self.open_report_button.setEnabled("html" in self.report_paths)
        self.open_map_button.setEnabled("map" in self.report_paths)
        self.open_pdf_button.setEnabled("pdf" in self.report_paths)
        self.open_folder_button.setEnabled(bool(self.report_paths))

    def open_report(self, key: str) -> None:
        path = self.report_paths.get(key)
        if not path:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).resolve())))

    def open_reports_folder(self) -> None:
        if self.report_paths:
            folder = Path(next(iter(self.report_paths.values()))).resolve().parent
        else:
            folder = self.output_dir.resolve()
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _gps_text(self, item: dict[str, Any]) -> str:
        if item.get("gps_valid"):
            return f"{item.get('latitude')}, {item.get('longitude')}"
        if item.get("gps_available"):
            return "Invalid GPS"
        return "N/A"

    def _flags_text(self, item: dict[str, Any]) -> str:
        flags = item.get("anomalies") or []
        return "; ".join(flags) if flags else "None"

    def _size_text(self, size: Any) -> str:
        if not isinstance(size, int):
            return "N/A"
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        if size >= 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size} B"


def run_gui() -> None:
    qInstallMessageHandler(_qt_message_handler)
    app = QApplication(sys.argv)
    window = ForensicsWindow()
    window.show()
    app.exec_()
