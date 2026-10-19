"""Utilidades específicas de Windows: rutas largas, atributos, bloqueo, PC despierto."""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path
from typing import Iterator

IS_WINDOWS = os.name == "nt"

# Atributos de archivo de Windows (st_file_attributes)
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
CLOUD_PLACEHOLDER_ATTRIBUTES = (
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

# Errores que devuelve Windows cuando Defender bloquea un archivo
ERROR_VIRUS_INFECTED = 225
ERROR_VIRUS_DELETED = 226


def fs_path(path: str) -> str:
    """Añade el prefijo \\\\?\\ a rutas largas para que funcionen aunque Windows
    no tenga activadas las rutas largas."""
    if not IS_WINDOWS or len(path) < 240 or path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def path_key(path: str) -> str:
    """Clave normalizada de una ruta (Windows no distingue mayúsculas)."""
    return os.path.normcase(os.path.abspath(path))


def is_defender_block(exc: BaseException) -> bool:
    """True si el error es porque Defender ha bloqueado el archivo."""
    return getattr(exc, "winerror", None) in (ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED)


class AlreadyRunningError(Exception):
    """Ya hay otra instancia de vtscan en marcha."""


class SingleInstanceLock:
    """Bloqueo de instancia única con un archivo. Windows lo libera solo si el
    proceso muere, así que no quedan bloqueos huérfanos."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            if IS_WINDOWS:
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - solo para ejecutar los tests fuera de Windows
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise AlreadyRunningError(str(self.path)) from exc
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            if IS_WINDOWS:
                import msvcrt

                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "SingleInstanceLock":
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


_ES_CONTINUOUS = 0x80000000
_ES_SYSTEM_REQUIRED = 0x00000001


def prevent_sleep() -> None:
    """Evita que Windows entre en suspensión mientras trabajamos (la pantalla sí
    puede apagarse)."""
    if IS_WINDOWS:
        import ctypes

        ctypes.windll.kernel32.SetThreadExecutionState(_ES_CONTINUOUS | _ES_SYSTEM_REQUIRED)


def allow_sleep() -> None:
    if IS_WINDOWS:
        import ctypes

        ctypes.windll.kernel32.SetThreadExecutionState(_ES_CONTINUOUS)


@contextlib.contextmanager
def keep_awake() -> Iterator[None]:
    prevent_sleep()
    try:
        yield
    finally:
        allow_sleep()


def open_in_default_app(path: Path) -> bool:
    """Abre un archivo con la aplicación predeterminada (el informe en el navegador)."""
    try:
        if IS_WINDOWS:
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True
    except OSError:
        return False
    return False


def configure_stdio() -> None:
    """Evita que un carácter raro en una ruta rompa la salida si se redirige a un archivo."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
