#!.venv\Scripts\pythonw.exe
# Con doble clic, el lanzador de Python lee la línea de arriba y usa el Python de .venv
"""vtscan con ventana. Doble clic para abrirlo (sin consola)."""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV_PYTHONW = HERE / ".venv" / "Scripts" / "pythonw.exe"


def show_error(text: str) -> None:
    import ctypes

    ctypes.windll.user32.MessageBoxW(None, text, "vtscan", 0x10)


if sys.version_info < (3, 11):
    show_error("vtscan necesita Python 3.11 o superior.")
    sys.exit(1)

try:
    import PySide6  # noqa: F401
except ImportError:
    # Si se abre con otro Python, por ejemplo desde la terminal, se vuelve a lanzar con el de .venv
    if VENV_PYTHONW.exists() and Path(sys.executable).resolve() != VENV_PYTHONW.resolve():
        subprocess.Popen([str(VENV_PYTHONW), str(Path(__file__).resolve())], cwd=str(HERE))
        sys.exit(0)
    show_error(
        "Faltan dependencias. Desde la carpeta del proyecto ejecuta:\n\n"
        ".venv\\Scripts\\python.exe -m pip install -r requirements.txt"
    )
    sys.exit(1)

from vtscanner.gui.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
