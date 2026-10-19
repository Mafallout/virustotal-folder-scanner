"""Modelo y filtro de la tabla de resultados."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QFont

from ..report import SIGNAL_LABELS, ReportRow, engines_text, human_size
from ..verdict import LEVEL_ORDER, Level
from .theme import level_color

COLUMNS = ["Nivel", "Archivo", "Detecciones", "Antivirus", "Etiqueta", "Motivo", "Firma y señales", "Tamaño"]
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
ROW_ROLE = Qt.ItemDataRole.UserRole + 2

Index = QModelIndex | QPersistentModelIndex


def signature_and_signals(row: ReportRow) -> str:
    """Primero las señales de riesgo (lo importante) y después la firma."""
    parts = [SIGNAL_LABELS.get(s, s) for s in row.signals if s != "trusted"]
    if row.signature:
        parts.append(row.signature)
    return " · ".join(parts)


def search_text(row: ReportRow) -> str:
    fields = [row.rel_path, row.label, row.reason, row.sha256 or "", row.signature]
    fields += [f"{engine} {result}" for engine, result in row.detected_by]
    return " ".join(fields).lower()


class ResultsModel(QAbstractTableModel):
    def __init__(self, rows: list[ReportRow] | None = None, parent: Any = None) -> None:
        super().__init__(parent)
        self._rows = list(rows or [])

    def set_rows(self, rows: list[ReportRow]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> list[ReportRow]:
        return self._rows

    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: N802 (nombre de Qt)
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: Index = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()
        if role == ROW_ROLE:
            return row
        if role == Qt.ItemDataRole.DisplayRole:
            return self._text(row, column)
        if role == SORT_ROLE:
            return self._sort_key(row, column)
        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 0 or (column == 2 and (row.malicious or 0) > 0):
                return level_color(row.level)
            return None
        if role == Qt.ItemDataRole.FontRole and column == 0:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(row, column)
        if role == Qt.ItemDataRole.TextAlignmentRole and column in (2, 7):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    @staticmethod
    def _text(row: ReportRow, column: int) -> str:
        if column == 0:
            return row.level.label
        if column == 1:
            return row.rel_path
        if column == 2:
            return "-" if row.total is None else f"{row.malicious or 0}/{row.suspicious or 0} de {row.total}"
        if column == 3:
            return engines_text([engine for engine, _ in row.detected_by])
        if column == 4:
            if row.label:
                return row.label
            return row.main_detections[0][1] if row.main_detections else ""
        if column == 5:
            return row.reason
        if column == 6:
            return signature_and_signals(row)
        return human_size(row.size)

    @staticmethod
    def _sort_key(row: ReportRow, column: int) -> Any:
        if column == 0:
            return (LEVEL_ORDER.index(row.level), -(row.malicious or 0), -(row.suspicious or 0), row.rel_path.lower())
        if column == 2:
            return (row.malicious if row.total is not None else -1, row.suspicious or 0)
        if column == 7:
            return row.size if row.size is not None else -1
        return ResultsModel._text(row, column).lower()

    @staticmethod
    def _tooltip(row: ReportRow, column: int) -> str:
        if column == 1:
            return row.path
        if column == 3:
            return "\n".join(f"{engine}: {result}" for engine, result in row.detected_by)
        if column in (4, 5):
            return ResultsModel._text(row, column)
        if column == 6:
            return signature_and_signals(row)
        return ""


class ResultsFilter(QSortFilterProxyModel):
    """Filtra por niveles y por texto, y ordena por la clave de cada columna."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self.levels: set[Level] = set(LEVEL_ORDER)
        self.text = ""
        self.setSortRole(SORT_ROLE)

    def _refilter(self, change: Any) -> None:
        # Qt 6.9 sustituyó invalidateRowsFilter() por begin/endFilterChange()
        if hasattr(self, "beginFilterChange"):
            self.beginFilterChange()
            change()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            change()
            self.invalidateRowsFilter()

    def set_levels(self, levels: set[Level]) -> None:
        self._refilter(lambda: setattr(self, "levels", set(levels)))

    def set_text(self, text: str) -> None:
        self._refilter(lambda: setattr(self, "text", text.strip().lower()))

    def filterAcceptsRow(self, source_row: int, source_parent: Index) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, ResultsModel):
            return True
        row = model.rows()[source_row]
        if row.level not in self.levels:
            return False
        return not self.text or self.text in search_text(row)

    def lessThan(self, left: Index, right: Index) -> bool:  # noqa: N802
        return left.data(SORT_ROLE) < right.data(SORT_ROLE)
