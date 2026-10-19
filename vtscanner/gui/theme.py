"""Colores por nivel (los mismos que el informe HTML), en claro y oscuro, e icono
de la aplicación dibujado con Qt (sin imágenes de terceros)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap

from ..verdict import Level

# (modo claro, modo oscuro)
LEVEL_COLORS = {
    Level.CRITICAL: ("#c0161f", "#ff6b6f"),
    Level.HIGH: ("#d9531e", "#ff9a5c"),
    Level.MEDIUM: ("#a87900", "#f1c84b"),
    Level.LOW: ("#77723a", "#c9c27a"),
    Level.UNKNOWN: ("#3f6a92", "#8fb6e0"),
    Level.PENDING: ("#687180", "#a3abb7"),
    Level.CLEAN: ("#1d7f47", "#5fd18f"),
    Level.SKIPPED: ("#8a909a", "#8a909a"),
}
ACCENT = ("#2f6fdf", "#6ea0ff")
MUTED = ("#5d6877", "#9aa5b3")
WARNING = ("#a87900", "#f1c84b")


def is_dark() -> bool:
    app = QGuiApplication.instance()
    if app is None:
        return False
    scheme = app.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Dark:
        return True
    if scheme == Qt.ColorScheme.Light:
        return False
    return app.palette().window().color().lightness() < 128


def pick(pair: tuple[str, str]) -> str:
    return pair[1] if is_dark() else pair[0]


def level_color(level: Level) -> QColor:
    return QColor(pick(LEVEL_COLORS[level]))


def draw_icon(size: int) -> QImage:
    """Escudo blanco con una marca verde sobre un cuadrado azul redondeado."""
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = float(size)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#2f6fdf"))
    painter.drawRoundedRect(QRectF(s * 0.04, s * 0.04, s * 0.92, s * 0.92), s * 0.22, s * 0.22)

    cx, top, bottom, half = s / 2, s * 0.17, s * 0.85, s * 0.30
    shield = QPainterPath()
    shield.moveTo(cx, top)
    shield.lineTo(cx + half, top + s * 0.10)
    shield.lineTo(cx + half, s * 0.48)
    shield.cubicTo(cx + half, s * 0.66, cx + half * 0.45, s * 0.78, cx, bottom)
    shield.cubicTo(cx - half * 0.45, s * 0.78, cx - half, s * 0.66, cx - half, s * 0.48)
    shield.lineTo(cx - half, top + s * 0.10)
    shield.closeSubpath()
    painter.setBrush(QColor("white"))
    painter.drawPath(shield)

    pen = QPen(QColor("#1d9a55"), max(1.5, s * 0.075))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    check = QPainterPath()
    check.moveTo(cx - half * 0.48, s * 0.50)
    check.lineTo(cx - half * 0.08, s * 0.62)
    check.lineTo(cx + half * 0.52, s * 0.38)
    painter.drawPath(check)
    painter.end()
    return image


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        icon.addPixmap(QPixmap.fromImage(draw_icon(size)))
    return icon


def save_ico(path: Path) -> bool:
    """Para el .exe empaquetado."""
    return draw_icon(256).save(str(path), "ICO")
