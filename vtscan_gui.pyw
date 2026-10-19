"""vtscan con ventana. Doble clic para abrirlo (sin consola)."""

import sys

if sys.version_info < (3, 11):
    import ctypes

    ctypes.windll.user32.MessageBoxW(None, "vtscan necesita Python 3.11 o superior.", "vtscan", 0x10)
    sys.exit(1)

from vtscanner.gui.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
