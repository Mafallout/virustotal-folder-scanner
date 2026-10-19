"""Ventana principal con tres pantallas: Inicio, Análisis y Resultados."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QPoint, QSettings, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import (
    QCloseEvent,
    QColor,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QFontMetrics,
    QGuiApplication,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QSystemTrayIcon,
    QTableView,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..config import DEFAULT_CONFIG_PATH, Config
from ..db import Database
from ..pipeline import ScanOptions, ScanOutcome, format_minutes
from ..ratelimit import RateLimiter, format_local_time
from ..report import ReportRow, ReportSummary, engines_text, human_size, plural
from ..ui import UploadCost, UploadItem
from ..verdict import LEVEL_ORDER, Level
from ..winutils import open_in_default_app
from .bridge import ScanWorker
from .dialogs import ApiKeyDialog, UploadDialog, plain_label
from .results import ROW_ROLE, ResultsFilter, ResultsModel
from .theme import ACCENT, MUTED, WARNING, level_color, pick

log = logging.getLogger(__name__)

STEPS = [
    ("defender", "Defender"),
    ("walk", "Archivos"),
    ("hash", "Hashes"),
    ("sig", "Firmas"),
    ("vt", "VirusTotal"),
    ("upload", "Subidas"),
    ("report", "Informe"),
]
LIVE_LEVELS = [Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW, Level.UNKNOWN, Level.CLEAN]


def step_for(text: str) -> str | None:
    """A qué paso corresponde una fase o tarea del análisis."""
    t = text.lower()
    if "defender" in t:
        return "defender"
    if "buscando" in t or "recorriendo" in t:
        return "walk"
    if "sha-256" in t or "hashes" in t:
        return "hash"
    if "firmas" in t:
        return "sig"
    if "subid" in t or "subiendo" in t:
        return "upload"
    if "virustotal" in t or "consultando" in t:
        return "vt"
    return None


def format_wait(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds >= 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"
    if seconds >= 60:
        return f"{seconds // 60} min {seconds % 60:02d} s"
    return f"{seconds} s"


def title_label(text: str, scale: float = 1.5) -> QLabel:
    label = plain_label(text, word_wrap=False)
    font = label.font()
    font.setPointSizeF(font.pointSizeF() * scale)
    font.setBold(True)
    label.setFont(font)
    return label


def muted(label: QLabel) -> QLabel:
    label.setStyleSheet(f"color: {pick(MUTED)};")
    return label


def rgba(color: QColor, alpha: int) -> str:
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


def primary_button(text: str) -> QPushButton:
    """Botón principal, con el color de acento."""
    button = QPushButton(text)
    accent = QColor(pick(ACCENT))
    button.setStyleSheet(
        "QPushButton { color: white; font-weight: bold; border: none; border-radius: 5px; "
        f"padding: 7px 22px; background: {accent.name()}; }}"
        f"QPushButton:hover {{ background: {accent.lighter(112).name()}; }}"
        f"QPushButton:pressed {{ background: {accent.darker(115).name()}; }}"
        f"QPushButton:disabled {{ background: {rgba(accent, 90)}; color: {rgba(QColor('white'), 160)}; }}"
    )
    return button


def chip_style(color: QColor) -> str:
    """Filtro por nivel: con borde y fondo suave del color del nivel; apagado, en gris."""
    grey = QColor(pick(MUTED))
    return (
        f"QPushButton {{ color: {color.name()}; font-weight: bold; border: 1px solid {color.name()}; "
        f"border-radius: 12px; padding: 4px 12px; background: {rgba(color, 40)}; }}"
        f"QPushButton:hover {{ background: {rgba(color, 70)}; }}"
        f"QPushButton:!checked {{ color: {grey.name()}; border-color: {rgba(grey, 120)}; background: transparent; }}"
    )


class ElidedLabel(QLabel):
    """Etiqueta de una línea que recorta el texto por el medio (rutas largas)."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.full_text = ""
        self.setMinimumWidth(10)
        self.set_full_text(text)

    def set_full_text(self, text: str) -> None:
        self.full_text = text
        self.setToolTip(text)
        self._update()

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update()

    def _update(self) -> None:
        metrics = QFontMetrics(self.font())
        self.setText(metrics.elidedText(self.full_text, Qt.TextElideMode.ElideMiddle, max(10, self.width())))


class ElideDelegate(QStyledItemDelegate):
    """En la tabla, las rutas se recortan por el medio (se ve el nombre del archivo)
    y el resto de columnas por el final."""

    def initStyleOption(self, option: QStyleOptionViewItem, index: Any) -> None:  # noqa: N802
        super().initStyleOption(option, index)
        option.textElideMode = (
            Qt.TextElideMode.ElideMiddle if index.column() == 1 else Qt.TextElideMode.ElideRight
        )


# ---------------------------------------------------------------------------
# Inicio
# ---------------------------------------------------------------------------


class DropZone(QFrame):
    """Zona para arrastrar una carpeta o un archivo, con botón para elegirla."""

    path_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.path = ""
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(170)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = title_label("Arrastra aquí una carpeta", 1.25)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        choose = QPushButton("Elegir carpeta...")
        choose.clicked.connect(self._choose)
        self.path_label = muted(ElidedLabel("Ninguna carpeta elegida"))
        self.path_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        layout.addSpacing(6)
        layout.addWidget(choose, 0, Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(6)
        layout.addWidget(self.path_label)
        self._set_hover(False)

    def _set_hover(self, on: bool) -> None:
        color = pick(ACCENT) if on else pick(MUTED)
        self.setStyleSheet(f"#dropZone {{ border: 2px dashed {color}; border-radius: 12px; }}")

    def set_path(self, path: str) -> None:
        self.path = path
        self.path_label.set_full_text(path or "Ninguna carpeta elegida")

    def _choose(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Elige la carpeta que quieres analizar", self.path)
        if path:
            path = os.path.normpath(path)
            self.set_path(path)
            self.path_selected.emit(path)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            event.acceptProposedAction()
            self._set_hover(True)

    def dragLeaveEvent(self, event: Any) -> None:  # noqa: N802
        self._set_hover(False)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        self._set_hover(False)
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            path = os.path.normpath(urls[0].toLocalFile())
            self.set_path(path)
            self.path_selected.emit(path)
            event.acceptProposedAction()


class StartPage(QWidget):
    analyze_requested = Signal(bool)  # True = solo calcular el coste
    resume_requested = Signal()
    change_key_requested = Signal()

    def __init__(self, cfg: Config, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.cfg = cfg
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(12)
        layout.addWidget(title_label("vtscan", 1.8))
        layout.addWidget(muted(plain_label("Revisa una carpeta en busca de malware con VirusTotal.")))

        self.resume_box = QFrame()
        self.resume_box.setObjectName("resumeBox")
        self.resume_box.setStyleSheet(
            f"#resumeBox {{ border: 1px solid {pick(ACCENT)}; border-radius: 8px; }}"
        )
        resume_layout = QHBoxLayout(self.resume_box)
        self.resume_label = plain_label()
        resume_button = QPushButton("Continuar")
        resume_button.clicked.connect(self.resume_requested.emit)
        resume_layout.addWidget(self.resume_label, 1)
        resume_layout.addWidget(resume_button)
        self.resume_box.hide()
        layout.addWidget(self.resume_box)

        self.drop = DropZone()
        self.drop.path_selected.connect(lambda _: self._update_buttons())
        layout.addWidget(self.drop)

        options = QGroupBox("Opciones")
        options_layout = QVBoxLayout(options)
        self.defender = QCheckBox("Pasar Microsoft Defender antes (es rápido y solo avisa)")
        self.defender.setChecked(True)
        self.upload = QCheckBox("Subir a VirusTotal los archivos que no conozca (te pregunta antes cuáles)")
        self.wait = QCheckBox("Si se acaban las consultas del día, esperar y seguir solo")
        self.advanced_toggle = QToolButton()
        self.advanced_toggle.setText("Avanzado")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.advanced_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.advanced = QWidget()
        advanced_layout = QVBoxLayout(self.advanced)
        advanced_layout.setContentsMargins(18, 0, 0, 0)
        self.all_files = QCheckBox("Revisar todos los archivos, no solo ejecutables (gasta muchas más consultas)")
        self.refresh = QCheckBox("Volver a consultar aunque ya esté en la caché")
        advanced_layout.addWidget(self.all_files)
        advanced_layout.addWidget(self.refresh)
        self.advanced.hide()
        self.advanced_toggle.toggled.connect(self._toggle_advanced)
        for widget in (self.defender, self.upload, self.wait, self.advanced_toggle, self.advanced):
            options_layout.addWidget(widget)
        layout.addWidget(options)

        buttons = QHBoxLayout()
        self.analyze = primary_button("Analizar")
        self.analyze.setDefault(True)
        self.analyze.setMinimumWidth(140)
        self.analyze.clicked.connect(lambda: self.analyze_requested.emit(False))
        self.estimate_button = QPushButton("Calcular coste")
        self.estimate_button.setToolTip("Dice cuántas consultas y cuánto tiempo harán falta, sin gastar ninguna")
        self.estimate_button.clicked.connect(lambda: self.analyze_requested.emit(True))
        buttons.addWidget(self.analyze)
        buttons.addWidget(self.estimate_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.estimate_label = plain_label()
        self.estimate_label.hide()
        layout.addWidget(self.estimate_label)
        layout.addStretch(1)

        footer = QHBoxLayout()
        self.quota_label = muted(plain_label(word_wrap=False))
        footer.addWidget(self.quota_label)
        footer.addStretch(1)
        for text, handler in (
            ("Cambiar clave", self.change_key_requested.emit),
            ("Configuración", self._open_config),
            ("Informes", self._open_reports),
        ):
            button = QPushButton(text)
            button.setFlat(True)
            button.clicked.connect(handler)
            footer.addWidget(button)
        layout.addLayout(footer)
        self._update_buttons()

    def _toggle_advanced(self, on: bool) -> None:
        self.advanced.setVisible(on)
        self.advanced_toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    def _update_buttons(self) -> None:
        has_path = bool(self.drop.path)
        self.analyze.setEnabled(has_path)
        self.estimate_button.setEnabled(has_path)

    def _open_config(self) -> None:
        path = self.cfg.source_path or DEFAULT_CONFIG_PATH
        if not open_in_default_app(Path(path)):
            QMessageBox.information(self, "vtscan", f"Edita este archivo con el Bloc de notas:\n{path}")

    def _open_reports(self) -> None:
        self.cfg.reports_path.mkdir(parents=True, exist_ok=True)
        open_in_default_app(self.cfg.reports_path)

    def options(self, dry_run: bool) -> ScanOptions:
        return ScanOptions(
            target=self.drop.path,
            upload=self.upload.isChecked() and not dry_run,
            defender=self.defender.isChecked() and not dry_run,
            all_files=self.all_files.isChecked(),
            wait=self.wait.isChecked(),
            dry_run=dry_run,
            refresh=self.refresh.isChecked(),
        )

    def show_estimate(self, text: str, warn: bool = False) -> None:
        self.estimate_label.setText(text)
        self.estimate_label.setStyleSheet(f"color: {pick(WARNING)};" if warn else "")
        self.estimate_label.show()


# ---------------------------------------------------------------------------
# Análisis en marcha
# ---------------------------------------------------------------------------


class ProgressPage(QWidget):
    stop_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.total: float | None = None
        self.unit = ""
        self.started = time.monotonic()
        self.visible_steps: list[str] = []
        self.current_step: str | None = None
        self.counts = {level: 0 for level in LIVE_LEVELS}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(10)
        self.title = title_label("Analizando", 1.4)
        layout.addWidget(self.title)
        self.target_label = muted(ElidedLabel())
        layout.addWidget(self.target_label)

        steps = QHBoxLayout()
        self.step_labels: dict[str, QLabel] = {}
        for key, name in STEPS:
            label = plain_label(name, word_wrap=False)
            self.step_labels[key] = label
            steps.addWidget(label)
        steps.addStretch(1)
        layout.addLayout(steps)

        self.task_label = plain_label()
        font = self.task_label.font()
        font.setBold(True)
        self.task_label.setFont(font)
        layout.addWidget(self.task_label)
        self.bar = QProgressBar()
        self.bar.setTextVisible(True)
        layout.addWidget(self.bar)
        self.detail = muted(plain_label())
        layout.addWidget(self.detail)
        self.notice = plain_label()
        self.notice.setStyleSheet(f"color: {pick(WARNING)};")
        self.notice.hide()
        layout.addWidget(self.notice)

        info = QHBoxLayout()
        self.quota_label = plain_label(word_wrap=False)
        self.elapsed_label = muted(plain_label(word_wrap=False))
        info.addWidget(self.quota_label)
        info.addStretch(1)
        info.addWidget(self.elapsed_label)
        layout.addLayout(info)

        counters = QHBoxLayout()
        self.counter_labels: dict[Level, QLabel] = {}
        for level in LIVE_LEVELS:
            label = plain_label(word_wrap=False)
            label.setStyleSheet(f"color: {level_color(level).name()}; font-weight: bold;")
            self.counter_labels[level] = label
            counters.addWidget(label)
            counters.addSpacing(10)
        counters.addStretch(1)
        layout.addLayout(counters)

        layout.addWidget(plain_label("Resultados según llegan (lo que merece atención sale arriba):"))
        self.findings = QListWidget()
        self.findings.setAlternatingRowColors(True)
        self.findings.setUniformItemSizes(True)
        self.top_count = 0  # cuántos de arriba son de nivel Bajo o más
        layout.addWidget(self.findings, 2)

        self.activity_toggle = QToolButton()
        self.activity_toggle.setText("Ver actividad")
        self.activity_toggle.setCheckable(True)
        self.activity_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.activity_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(5000)
        self.activity.hide()
        self.activity_toggle.toggled.connect(self._toggle_activity)
        layout.addWidget(self.activity_toggle)
        layout.addWidget(self.activity, 1)

        bottom = QHBoxLayout()
        bottom.addWidget(
            muted(plain_label("Si lo detienes, se guarda lo hecho y puedes continuar más tarde.", word_wrap=False))
        )
        bottom.addStretch(1)
        self.stop_button = QPushButton("Detener")
        self.stop_button.clicked.connect(self._stop)
        bottom.addWidget(self.stop_button)
        layout.addLayout(bottom)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)

    def _toggle_activity(self, on: bool) -> None:
        self.activity.setVisible(on)
        self.activity_toggle.setArrowType(Qt.ArrowType.DownArrow if on else Qt.ArrowType.RightArrow)

    def _stop(self) -> None:
        self.stop_button.setEnabled(False)
        self.stop_button.setText("Deteniendo...")
        self.stop_requested.emit()

    def _tick(self) -> None:
        self.elapsed_label.setText(f"Tiempo: {format_wait(time.monotonic() - self.started)}")

    def reset(self, options: ScanOptions) -> None:
        self.started = time.monotonic()
        self.title.setText("Calculando el coste" if options.dry_run else "Analizando")
        self.target_label.set_full_text(options.target)
        hidden = set()
        if not options.defender:
            hidden.add("defender")
        if not options.upload:
            hidden.add("upload")
        if options.dry_run:
            hidden.update({"vt", "upload"})
        self.visible_steps = [key for key, _ in STEPS if key not in hidden]
        for key, label in self.step_labels.items():
            label.setVisible(key in self.visible_steps)
        self.current_step = None
        self._paint_steps()
        self.task_label.setText("Preparando...")
        self.bar.setRange(0, 0)
        self.detail.clear()
        self.notice.hide()
        self.quota_label.clear()
        self.counts = {level: 0 for level in LIVE_LEVELS}
        self._paint_counters()
        self.findings.clear()
        self.top_count = 0
        self.activity.clear()
        self.stop_button.setEnabled(True)
        self.stop_button.setText("Detener")
        self._tick()
        self.timer.start(1000)

    def _paint_steps(self, all_done: bool = False) -> None:
        current = self.visible_steps.index(self.current_step) if self.current_step in self.visible_steps else -1
        for i, key in enumerate(self.visible_steps):
            label = self.step_labels[key]
            name = dict(STEPS)[key]
            if all_done or i < current:
                label.setText(f"✓ {name}")
                label.setStyleSheet("")
            elif i == current:
                label.setText(name)
                label.setStyleSheet(f"color: {pick(ACCENT)}; font-weight: bold;")
            else:
                label.setText(name)
                label.setStyleSheet(f"color: {pick(MUTED)};")

    def _set_step(self, key: str | None) -> None:
        if key and key in self.visible_steps and key != self.current_step:
            self.current_step = key
            self._paint_steps()

    def _paint_counters(self) -> None:
        for level, label in self.counter_labels.items():
            label.setText(f"{level.label} {self.counts[level]}")

    # ---- señales del análisis -----------------------------------------------

    def on_phase(self, title: str) -> None:
        self._set_step(step_for(title))

    def on_task_start(self, description: str, total: object, unit: str) -> None:
        self._set_step(step_for(description))
        self.task_label.setText(description)
        self.unit = unit
        self.total = float(total) if isinstance(total, (int, float)) and total else None
        if self.total:
            self.bar.setRange(0, 1000)
            self.bar.setValue(0)
            self.bar.setFormat(self._amount(0))
        else:
            self.bar.setRange(0, 0)
        self.detail.clear()

    def _amount(self, completed: float) -> str:
        if not self.total:
            return ""
        if self.unit == "bytes":
            return f"{human_size(int(completed))} de {human_size(int(self.total))}"
        return f"{int(completed)} de {int(self.total)}"

    def on_task_update(self, completed: object, total: object, detail: object) -> None:
        if isinstance(total, (int, float)) and total:
            self.total = float(total)
            if self.bar.maximum() == 0:
                self.bar.setRange(0, 1000)
        if isinstance(completed, (int, float)) and self.total:
            self.bar.setValue(int(1000 * min(1.0, completed / self.total)))
            self.bar.setFormat(self._amount(completed))
        if isinstance(detail, str):
            self.detail.setText(detail)

    def on_task_end(self, summary: object) -> None:
        if self.total:
            self.bar.setValue(1000)
        self.detail.clear()
        if isinstance(summary, str) and summary:
            self.detail.setText(summary)
            self.add_message(summary, "info")

    def on_waiting(self, seconds: float, reason: str) -> None:
        self.detail.setText(f"{reason[:1].upper()}{reason[1:]}: {format_wait(seconds)}")

    def on_quota(self, used: int, limit: int) -> None:
        self.quota_label.setText(f"Consultas hoy: {used} de {limit}")

    def on_result(self, rel_path: str, level: object, reason: str, engines: list[str]) -> None:
        if not isinstance(level, Level):
            return
        if level in self.counts:
            self.counts[level] += 1
            self._paint_counters()
        text = f"{level.label}   {rel_path}"
        if engines:
            text += f"   (detectado por {engines_text(engines)})"
            reason += "\nDetectado por: " + ", ".join(engines)
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, int(level))
        item.setToolTip(reason)
        if level >= Level.LOW:
            # Arriba, de más a menos grave; el resto, debajo y el último primero
            row = 0
            while row < self.top_count and self.findings.item(row).data(Qt.ItemDataRole.UserRole) >= level:
                row += 1
            self.top_count += 1
            item.setForeground(level_color(level))
        else:
            row = self.top_count
            item.setForeground(level_color(level) if level == Level.UNKNOWN else QColor(pick(MUTED)))
        self.findings.insertItem(row, item)

    def add_message(self, text: str, kind: str) -> None:
        self.activity.appendPlainText(f"{datetime.now():%H:%M:%S}  {text}")
        if kind in ("warn", "error"):
            self.notice.setText(text)
            self.notice.show()

    def finish(self) -> None:
        self.timer.stop()
        self._tick()
        self._paint_steps(all_done=True)


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------


class ResultsPage(QWidget):
    new_scan_requested = Signal()
    continue_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.report_paths: list[Path] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(10)
        layout.addWidget(title_label("Resultados", 1.4))
        self.target_label = muted(ElidedLabel())
        layout.addWidget(self.target_label)

        status_row = QHBoxLayout()
        self.status = plain_label()
        self.continue_button = QPushButton("Continuar el análisis")
        self.continue_button.clicked.connect(self.continue_requested.emit)
        self.continue_button.hide()
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.continue_button)
        layout.addLayout(status_row)

        chips = QHBoxLayout()
        self.chips: dict[Level, QPushButton] = {}
        for level in LEVEL_ORDER:
            chip = QPushButton()
            chip.setCheckable(True)
            chip.setChecked(True)
            chip.setStyleSheet(chip_style(level_color(level)))
            chip.setToolTip("Mostrar u ocultar este nivel")
            chip.toggled.connect(self._apply_levels)
            self.chips[level] = chip
            chips.addWidget(chip)
        chips.addStretch(1)
        layout.addLayout(chips)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar por ruta, antivirus, etiqueta, motivo o hash...")
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)

        self.model = ResultsModel(parent=self)
        self.proxy = ResultsFilter(self)
        self.proxy.setSourceModel(self.model)
        self.search.textChanged.connect(self.proxy.set_text)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setItemDelegate(ElideDelegate(self.table))
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        for column, mode in enumerate(
            [
                QHeaderView.ResizeMode.ResizeToContents,
                QHeaderView.ResizeMode.Stretch,
                QHeaderView.ResizeMode.ResizeToContents,
                QHeaderView.ResizeMode.Interactive,
                QHeaderView.ResizeMode.Interactive,
                QHeaderView.ResizeMode.Stretch,
                QHeaderView.ResizeMode.Interactive,
                QHeaderView.ResizeMode.ResizeToContents,
            ]
        ):
            header.setSectionResizeMode(column, mode)
        header.resizeSection(3, 160)
        header.resizeSection(4, 160)
        header.resizeSection(6, 160)
        self.table.doubleClicked.connect(lambda index: self._open_vt(self._row(index)))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        self.html_button = QPushButton("Abrir informe HTML")
        self.csv_button = QPushButton("Abrir CSV")
        new_button = QPushButton("Nuevo análisis")
        self.html_button.clicked.connect(lambda: self._open_report(".html"))
        self.csv_button.clicked.connect(lambda: self._open_report(".csv"))
        new_button.clicked.connect(self.new_scan_requested.emit)
        buttons.addWidget(self.html_button)
        buttons.addWidget(self.csv_button)
        buttons.addStretch(1)
        buttons.addWidget(muted(plain_label("Doble clic en una fila: abrirla en VirusTotal", word_wrap=False)))
        buttons.addSpacing(12)
        buttons.addWidget(new_button)
        layout.addLayout(buttons)

    def set_data(
        self, rows: list[ReportRow], summary: ReportSummary, report_paths: list[Path], outcome: ScanOutcome
    ) -> None:
        self.report_paths = list(report_paths)
        self.model.set_rows(rows)
        self.target_label.set_full_text(summary.root)
        counts = {level: 0 for level in LEVEL_ORDER}
        for row in rows:
            counts[row.level] += 1
        hide_clean = len(rows) > 300
        for level, chip in self.chips.items():
            chip.blockSignals(True)
            chip.setText(f"{level.label} {counts[level]}")
            chip.setVisible(counts[level] > 0)
            chip.setChecked(not (hide_clean and level == Level.CLEAN))
            chip.blockSignals(False)
        self._apply_levels()
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)

        incomplete = outcome.interrupted or not outcome.complete
        if not incomplete:
            text, color = "Análisis completo.", level_color(Level.CLEAN).name()
        else:
            reason = "Lo detuviste" if outcome.interrupted else "Quedan cosas pendientes"
            text = f"{reason}: {plural(summary.pending, 'archivo pendiente', 'archivos pendientes')}."
            if summary.reset_local and not outcome.interrupted:
                text += f" Las consultas se reinician a las {summary.reset_local} (hora local)."
            color = pick(WARNING)
        findings = sum(counts[level] for level in (Level.CRITICAL, Level.HIGH))
        if findings:
            text += f" Hay {plural(findings, 'archivo')} de nivel Alto o Crítico: revísalos antes de ejecutar nada."
            worst = Level.CRITICAL if counts[Level.CRITICAL] else Level.HIGH
            color = level_color(worst).name()
        self.status.setText(text)
        self.status.setStyleSheet(f"color: {color}; font-weight: bold;")
        self.continue_button.setVisible(incomplete)
        has_reports = bool(self.report_paths)
        self.html_button.setEnabled(has_reports)
        self.csv_button.setEnabled(has_reports)

    def _apply_levels(self) -> None:
        self.proxy.set_levels({level for level, chip in self.chips.items() if chip.isChecked()})

    def _row(self, index: Any) -> ReportRow | None:
        return index.data(ROW_ROLE) if index.isValid() else None

    @staticmethod
    def _open_vt(row: ReportRow | None) -> None:
        if row is not None and row.vt_link:
            QDesktopServices.openUrl(QUrl(row.vt_link))

    def _open_report(self, suffix: str) -> None:
        for path in self.report_paths:
            if path.suffix == suffix:
                open_in_default_app(path)

    def _context_menu(self, pos: QPoint) -> None:
        row = self._row(self.table.indexAt(pos))
        if row is None:
            return
        menu = QMenu(self)
        open_vt = menu.addAction("Abrir en VirusTotal")
        open_vt.setEnabled(bool(row.vt_link))
        open_vt.triggered.connect(lambda: self._open_vt(row))
        menu.addAction("Mostrar en el Explorador").triggered.connect(lambda: show_in_explorer(row.path))
        menu.addAction("Copiar ruta").triggered.connect(lambda: QGuiApplication.clipboard().setText(row.path))
        copy_hash = menu.addAction("Copiar SHA-256")
        copy_hash.setEnabled(bool(row.sha256))
        copy_hash.triggered.connect(lambda: QGuiApplication.clipboard().setText(row.sha256 or ""))
        menu.exec(self.table.viewport().mapToGlobal(pos))


def show_in_explorer(path: str) -> None:
    if os.path.exists(path):
        subprocess.Popen(f'explorer /select,"{path}"')
    else:
        folder = os.path.dirname(path)
        if os.path.isdir(folder):
            open_in_default_app(Path(folder))


# ---------------------------------------------------------------------------
# Ventana
# ---------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(
        self,
        cfg: Config,
        api_key: str | None,
        warnings: list[str] | None = None,
        settings: QSettings | None = None,
        scanner_kwargs: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.cfg = cfg
        self.api_key = api_key
        self.scanner_kwargs = scanner_kwargs or {}
        cfg.data_path.mkdir(parents=True, exist_ok=True)
        self.settings = settings or QSettings(str(cfg.data_path / "ventana.ini"), QSettings.Format.IniFormat)
        self.worker: ScanWorker | None = None
        self.options: ScanOptions | None = None
        self.summary_data: tuple[list[ReportRow], ReportSummary, list[Path]] | None = None
        self.estimate_data: tuple[int, int, float] | None = None
        self.resume_scan: Any = None
        self.close_requested = False
        self.tray: QSystemTrayIcon | None = None

        self.setWindowTitle(f"vtscan {__version__}")
        self.setMinimumSize(880, 640)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.start_page = StartPage(cfg)
        self.progress_page = ProgressPage()
        self.results_page = ResultsPage()
        for page in (self.start_page, self.progress_page, self.results_page):
            self.stack.addWidget(page)

        self.start_page.analyze_requested.connect(self._start_from_page)
        self.start_page.resume_requested.connect(self._resume)
        self.start_page.change_key_requested.connect(self._change_key)
        self.progress_page.stop_requested.connect(self.cancel_scan)
        self.results_page.new_scan_requested.connect(self.show_start)
        self.results_page.continue_requested.connect(self._continue_last)

        self._restore_settings()
        if warnings:
            self.start_page.show_estimate("Aviso de config.toml: " + "; ".join(warnings), warn=True)
        self.refresh_start_info()

    # ---- ajustes ------------------------------------------------------------

    def _restore_settings(self) -> None:
        geometry = self.settings.value("geometria")
        if geometry is not None:
            self.restoreGeometry(geometry)
        else:
            self.resize(1080, 760)
        folder = self.settings.value("carpeta", "", str)
        if folder and os.path.exists(folder):
            self.start_page.drop.set_path(folder)
            self.start_page._update_buttons()
        page = self.start_page
        for name, box, default in (
            ("defender", page.defender, True),
            ("subir", page.upload, False),
            ("esperar", page.wait, False),
        ):
            box.setChecked(str(self.settings.value(name, default)).lower() == "true")

    def _save_settings(self) -> None:
        page = self.start_page
        self.settings.setValue("geometria", self.saveGeometry())
        self.settings.setValue("carpeta", page.drop.path)
        self.settings.setValue("defender", page.defender.isChecked())
        self.settings.setValue("subir", page.upload.isChecked())
        self.settings.setValue("esperar", page.wait.isChecked())
        self.settings.sync()

    # ---- inicio -------------------------------------------------------------

    def refresh_start_info(self) -> None:
        """Consultas usadas hoy y análisis a medias (conexión propia, solo en este hilo)."""
        try:
            with Database(self.cfg.db_path) as db:
                limiter = RateLimiter(db, self.cfg.virustotal.requests_per_minute, self.cfg.virustotal.daily_limit)
                used, limit = limiter.used_today(), limiter.effective_daily_limit()
                reset = format_local_time(limiter.next_reset())
                self.resume_scan = db.find_resumable_scan(None)
        except Exception:  # noqa: BLE001 - la información es secundaria
            log.exception("No se pudo leer el estado")
            return
        self.start_page.quota_label.setText(
            f"Consultas usadas hoy: {used} de {limit} (se reinician a las {reset})"
        )
        if self.resume_scan is not None:
            started = datetime.fromtimestamp(self.resume_scan.started_at).strftime("%d/%m %H:%M")
            self.start_page.resume_label.setText(
                f"Hay un análisis sin terminar de {self.resume_scan.root} (empezado el {started})."
            )
            self.start_page.resume_box.show()
        else:
            self.start_page.resume_box.hide()

    def show_start(self) -> None:
        self.refresh_start_info()
        self.stack.setCurrentWidget(self.start_page)

    def _start_from_page(self, dry_run: bool) -> None:
        options = self.start_page.options(dry_run)
        if not options.target or not os.path.exists(options.target):
            QMessageBox.warning(self, "vtscan", "Elige primero una carpeta que exista.")
            return
        self.start_scan(options)

    def _resume(self) -> None:
        scan = self.resume_scan
        if scan is None:
            return
        if not os.path.exists(scan.root):
            QMessageBox.warning(self, "vtscan", f"Ya no existe la carpeta del análisis pendiente:\n{scan.root}")
            return
        stored = scan.options
        options = ScanOptions(
            target=scan.root,
            upload=bool(stored.get("upload")),
            defender=bool(stored.get("defender")),
            all_files=bool(stored.get("all_files")),
            wait=self.start_page.wait.isChecked(),
        )
        self.start_scan(options, resume_id=scan.id)

    def _continue_last(self) -> None:
        if self.options is not None:
            options = ScanOptions(
                target=self.options.target,
                upload=self.options.upload,
                defender=self.options.defender,
                all_files=self.options.all_files,
                wait=self.start_page.wait.isChecked(),
            )
            self.start_scan(options)

    def _change_key(self, problem: str = "") -> bool:
        dialog = ApiKeyDialog(self, problem)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.api_key = dialog.key
            return True
        return False

    # ---- análisis -----------------------------------------------------------

    def start_scan(self, options: ScanOptions, resume_id: int | None = None) -> None:
        if self.worker is not None:
            return
        if not options.dry_run and not self.api_key and not self._change_key():
            return
        self._save_settings()
        self.options = options
        self.summary_data = None
        self.estimate_data = None
        self.worker = ScanWorker(self.cfg, self.api_key, options, resume_id, self.scanner_kwargs, self)
        ui = self.worker.ui
        page = self.progress_page
        ui.message_sig.connect(page.add_message)
        ui.phase_sig.connect(page.on_phase)
        ui.task_started.connect(page.on_task_start)
        ui.task_progress.connect(page.on_task_update)
        ui.task_ended.connect(page.on_task_end)
        ui.waiting_sig.connect(page.on_waiting)
        ui.quota_sig.connect(page.on_quota)
        ui.result_sig.connect(page.on_result)
        ui.estimate_sig.connect(self._on_estimate)
        ui.summary_sig.connect(self._on_summary)
        ui.confirm_requested.connect(self._on_confirm)
        ui.uploads_requested.connect(self._on_uploads)
        self.worker.finished_ok.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.worker.finished.connect(self._on_thread_finished)
        page.reset(options)
        self.stack.setCurrentWidget(page)
        log.info("Ventana: análisis de %s %s", options.target, options.labels())
        self.worker.start()

    def cancel_scan(self) -> None:
        if self.worker is not None:
            self.worker.cancel()

    def _on_estimate(self, needed: int, remaining: int, minutes: float) -> None:
        self.estimate_data = (needed, remaining, minutes)
        if needed and not (self.options and self.options.dry_run):
            text = f"Hacen falta {plural(needed, 'consulta')} (unos {format_minutes(minutes)}); quedan {remaining} hoy."
            self.progress_page.add_message(text, "info")

    def _on_summary(self, rows: list[ReportRow], summary: ReportSummary, paths: list[Path]) -> None:
        self.summary_data = (rows, summary, paths)

    def _on_confirm(self, question: str, default: bool) -> None:
        if self.worker is None:
            return
        buttons = QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        default_button = QMessageBox.StandardButton.Yes if default else QMessageBox.StandardButton.No
        answer = QMessageBox.question(self, "vtscan", question, buttons, default_button)
        self.worker.ui.answer(answer == QMessageBox.StandardButton.Yes)

    def _on_uploads(self, items: list[UploadItem], cost: UploadCost) -> None:
        if self.worker is None:
            return
        big = self.cfg.virustotal.direct_upload_max_mb * 1024 * 1024
        dialog = UploadDialog(items, cost, big, self)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        self.worker.ui.answer(dialog.selected() if accepted else [])

    def _on_finished(self, outcome: ScanOutcome) -> None:
        self.progress_page.finish()
        options = self.options
        if options is not None and options.dry_run:
            self._show_estimate()
            self.show_start()
            return
        if self.summary_data is not None:
            rows, summary, paths = self.summary_data
            self.results_page.set_data(rows, summary, paths, outcome)
            self.stack.setCurrentWidget(self.results_page)
            self._notify(rows, outcome)
        else:
            self.show_start()

    def _show_estimate(self) -> None:
        if self.estimate_data is None:
            self.start_page.show_estimate("No hay ejecutables que analizar en esa carpeta.")
            return
        needed, remaining, minutes = self.estimate_data
        if needed == 0:
            self.start_page.show_estimate("Todo está ya en la caché: el análisis no gastará consultas.")
            return
        text = f"Hacen falta {plural(needed, 'consulta')}, unos {format_minutes(minutes)}. Hoy quedan {remaining}."
        warn = needed > remaining
        if warn:
            text += " No cabe todo hoy: seguirá cuando se reinicien (o marca la opción de esperar y seguir)."
        self.start_page.show_estimate(text, warn)

    def _notify(self, rows: list[ReportRow], outcome: ScanOutcome) -> None:
        counts: dict[Level, int] = {}
        for row in rows:
            counts[row.level] = counts.get(row.level, 0) + 1
        parts = [f"{level.label} {counts[level]}" for level in LEVEL_ORDER if counts.get(level)]
        title = "Análisis terminado" if outcome.complete else "Análisis detenido"
        QApplication.alert(self, 0)
        if self.isActiveWindow() or not QSystemTrayIcon.isSystemTrayAvailable():
            return
        if self.tray is None:
            self.tray = QSystemTrayIcon(self.windowIcon(), self)
        self.tray.show()
        self.tray.showMessage(title, " · ".join(parts), self.windowIcon(), 8000)
        QTimer.singleShot(12000, self.tray.hide)

    def _on_failed(self, kind: str, message: str) -> None:
        self.progress_page.finish()
        if kind == "auth":
            self.show_start()
            if self._change_key(message + " Escribe una clave válida."):
                QMessageBox.information(self, "vtscan", "Clave guardada. Vuelve a pulsar Analizar.")
            return
        QMessageBox.warning(self, "vtscan", message)
        self.show_start()

    def _on_thread_finished(self) -> None:
        if self.worker is not None:
            self.worker.deleteLater()
        self.worker = None
        if self.close_requested:
            self.close()

    # ---- cerrar -------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.worker is not None and self.worker.isRunning():
            if not self.close_requested:
                answer = QMessageBox.question(
                    self,
                    "vtscan",
                    "Hay un análisis en marcha. ¿Detenerlo y cerrar? Lo hecho queda guardado.",
                )
                if answer != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
                self.close_requested = True
                self.progress_page._stop()
                self.cancel_scan()
            event.ignore()  # se cierra al terminar el hilo
            return
        self._save_settings()
        event.accept()
