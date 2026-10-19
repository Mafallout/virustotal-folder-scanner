"""Arranque de la ventana: estilo, icono, configuración y clave."""

from __future__ import annotations

import logging
import os
import sys
from types import TracebackType

from PySide6.QtCore import QLibraryInfo, QLocale, QTimer, QTranslator
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from .. import __version__
from ..bootstrap import load_api_key, setup_logging
from ..config import ConfigError, load_config
from . import theme
from .dialogs import ApiKeyDialog
from .main_window import MainWindow

log = logging.getLogger("vtscanner.gui")


def _guard_stdio() -> None:
    """Sin consola (pythonw o el .exe), sys.stdout y sys.stderr son None."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def _set_taskbar_identity() -> None:
    """Para que la barra de tareas muestre el icono de vtscan y no el de Python."""
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("vtscan.ventana")
    except (AttributeError, OSError):
        pass


def _excepthook(kind: type[BaseException], error: BaseException, trace: TracebackType | None) -> None:
    log.error("Error no controlado en la ventana", exc_info=(kind, error, trace))
    QMessageBox.critical(None, "vtscan", f"Error inesperado: {error}\n\nLos detalles están en data\\logs.")


def main(argv: list[str] | None = None) -> int:
    _guard_stdio()
    _set_taskbar_identity()
    app = QApplication.instance() or QApplication(sys.argv if argv is None else argv)
    app.setOrganizationName("vtscan")
    app.setApplicationName("vtscan")
    app.setWindowIcon(theme.app_icon())
    # Botones estándar de Qt (Sí, No, Cancelar...) en español
    translator = QTranslator(app)
    translations = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    if translator.load(QLocale("es_ES"), "qtbase", "_", translations):
        app.installTranslator(translator)
    try:
        cfg, warnings = load_config()
    except ConfigError as exc:
        QMessageBox.critical(None, "vtscan", f"Hay un error en config.toml:\n\n{exc}")
        return 2
    setup_logging(cfg, verbose=False)
    sys.excepthook = _excepthook
    log.info("Inicio de la ventana (vtscan %s, estilo %s)", __version__, app.style().name())

    # Prueba de arranque del .exe: abre la ventana, guarda una captura y sale
    screenshot = os.environ.get("VTSCAN_SCREENSHOT")
    key = load_api_key(prefer_file=True)
    if not key and not screenshot:
        dialog = ApiKeyDialog()
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return 0
        key = dialog.key

    window = MainWindow(cfg, key, warnings)
    window.show()
    if screenshot:
        QTimer.singleShot(1500, lambda: (window.grab().save(screenshot), app.quit()))
    return app.exec()
