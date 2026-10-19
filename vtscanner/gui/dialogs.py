"""Diálogos: clave de VirusTotal y elección de archivos para subir."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .. import vtclient
from ..bootstrap import looks_like_api_key, save_api_key
from ..report import SIGNAL_LABELS, human_size, plural
from ..ui import UploadCost, UploadItem
from .theme import WARNING, pick


def plain_label(text: str = "", word_wrap: bool = True) -> QLabel:
    """QLabel que nunca interpreta HTML (rutas y textos de VirusTotal)."""
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(word_wrap)
    return label


class ApiKeyDialog(QDialog):
    def __init__(self, parent: Any = None, problem: str = "") -> None:
        super().__init__(parent)
        self.key = ""
        self.setWindowTitle("Clave de VirusTotal")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)

        intro = QLabel(
            "vtscan necesita una clave de la API de VirusTotal. Es gratis: crea una cuenta en "
            '<a href="https://www.virustotal.com/gui/join-us">virustotal.com</a>, entra en tu perfil '
            "y copia tu <b>API key</b>."
        )
        intro.setTextFormat(Qt.TextFormat.RichText)
        intro.setOpenExternalLinks(True)
        intro.setWordWrap(True)
        layout.addWidget(intro)
        if problem:
            warning = plain_label(problem)
            warning.setStyleSheet(f"color: {pick(WARNING)};")
            layout.addWidget(warning)

        row = QHBoxLayout()
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText("Pega aquí tu clave (64 caracteres)")
        show = QCheckBox("Mostrar")
        show.toggled.connect(
            lambda on: self.edit.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password)
        )
        row.addWidget(self.edit, 1)
        row.addWidget(show)
        layout.addLayout(row)

        note = plain_label("Se guarda en el archivo .env junto al programa y nunca se sube a ningún sitio.")
        layout.addWidget(note)
        self.status = plain_label()
        layout.addWidget(self.status)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Comprobar y guardar")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accept(self) -> None:
        key = self.edit.text().strip()
        if not looks_like_api_key(key):
            self.status.setText("Eso no parece una clave: son 64 letras y números.")
            return
        self.status.setText("Comprobando con VirusTotal...")
        QGuiApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            valid = vtclient.check_api_key(key)
        finally:
            QGuiApplication.restoreOverrideCursor()
        if valid is False:
            self.status.setText("VirusTotal rechaza esa clave. Revisa que la has copiado entera.")
            return
        save_api_key(key)
        self.key = key
        super().accept()


class UploadDialog(QDialog):
    """Lista de archivos desconocidos con casillas. Ninguno va marcado de serie."""

    def __init__(self, items: list[UploadItem], cost: UploadCost, big_bytes: int, parent: Any = None) -> None:
        super().__init__(parent)
        self.items = items
        self.cost = cost
        self.big_bytes = big_bytes
        self.setWindowTitle("Subir a VirusTotal")
        self.resize(820, 480)
        layout = QVBoxLayout(self)

        layout.addWidget(
            plain_label(
                f"VirusTotal no conoce {plural(len(items), 'archivo')}. "
                "Marca los que quieras subir para que los analice."
            )
        )
        warning = plain_label(
            "Lo que subes queda disponible para la comunidad de VirusTotal: investigadores y empresas "
            "con cuenta de pago pueden descargarlo. No subas archivos personales."
        )
        warning.setStyleSheet(f"color: {pick(WARNING)};")
        layout.addWidget(warning)

        self.table = QTableWidget(len(items), 5)
        self.table.setHorizontalHeaderLabels(["Subir", "Tamaño", "Firma", "Señales", "Ruta"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for row, item in enumerate(items):
            check = QTableWidgetItem(str(item.number))
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            check.setCheckState(Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, check)
            values = [
                human_size(item.size),
                item.signature,
                ", ".join(SIGNAL_LABELS.get(s, s) for s in item.signals),
                item.rel_path,
            ]
            for column, value in enumerate(values, start=1):
                cell = QTableWidgetItem(value)
                cell.setToolTip(item.path if column == 4 else value)
                self.table.setItem(row, column, cell)
        self.table.itemChanged.connect(self._update_summary)
        layout.addWidget(self.table, 1)

        row_buttons = QHBoxLayout()
        all_button = QPushButton("Marcar todos")
        none_button = QPushButton("Desmarcar todos")
        all_button.clicked.connect(lambda: self._set_all(True))
        none_button.clicked.connect(lambda: self._set_all(False))
        row_buttons.addWidget(all_button)
        row_buttons.addWidget(none_button)
        row_buttons.addStretch(1)
        layout.addLayout(row_buttons)

        self.summary = plain_label()
        layout.addWidget(self.summary)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Subir los marcados")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("No subir nada")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._update_summary()

    def _set_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.table.rowCount()):
            self.table.item(row, 0).setCheckState(state)

    def selected(self) -> list[int]:
        return [
            self.items[row].number
            for row in range(self.table.rowCount())
            if self.table.item(row, 0).checkState() == Qt.CheckState.Checked
        ]

    def _update_summary(self, *_: object) -> None:
        chosen = [item for item in self.items if item.number in set(self.selected())]
        requests = sum(2 if item.size > self.big_bytes else 1 for item in chosen)
        size = human_size(sum(item.size for item in chosen))
        self.summary.setText(
            f"Marcados: {plural(len(chosen), 'archivo')} ({size}), "
            f"{plural(requests, 'consulta', 'consultas')} más la recogida de resultados. "
            f"Quedan {self.cost.remaining_today} hoy."
        )
        self.ok_button.setEnabled(bool(chosen))
