"""Recorrido recursivo de la carpeta: decide qué archivos se analizan y detecta
señales locales (oculto, camuflado, doble extensión...)."""

from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from .config import ScanConfig
from .winutils import (
    CLOUD_PLACEHOLDER_ATTRIBUTES,
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM,
    fs_path,
    is_defender_block,
)

# Extensiones con cabecera MZ que son normales (no se marcan como "camuflado")
LEGIT_PE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".asi", ".ax",
    ".acm", ".drv", ".efi", ".pyd", ".node", ".bpl", ".xll", ".ime", ".flt",
    ".tsp", ".rll", ".winmd", ".msstyles", ".api", ".wll", ".ds", ".8bf",
    ".mexw64", ".pif", ".mui", ".fon",
}

# Extensiones que un archivo malicioso suele fingir antes de la real (factura.pdf.exe)
DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mkv",
    ".mov", ".wav", ".zip", ".rar", ".7z", ".iso", ".html", ".htm", ".nfo",
}

# Carpetas del sistema que nunca interesan
ALWAYS_SKIP_DIRS = {"$recycle.bin", "system volume information"}

RTLO = "‮"  # carácter que invierte el texto y se usa para disfrazar extensiones
SNIFF_WORKERS = 8

# Señales locales
SIGNAL_HIDDEN = "hidden"
SIGNAL_DISGUISED = "disguised"
SIGNAL_DOUBLE_EXT = "double_ext"
SIGNAL_RTLO = "rtlo"


@dataclass
class FileEntry:
    path: str  # ruta absoluta
    rel_path: str  # ruta relativa a la raíz del escaneo
    size: int
    mtime_ns: int
    ext: str  # extensión en minúsculas, con punto
    reason: str  # extension | content | all | explicit
    depth: int
    signals: set[str] = field(default_factory=set)


@dataclass
class SkippedEntry:
    path: str
    rel_path: str
    size: int | None
    reason: str  # too_large | cloud | access_denied | defender_blocked | error
    detail: str = ""


@dataclass
class WalkResult:
    root: str
    files: list[FileEntry] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    files_seen: int = 0
    bytes_seen: int = 0
    dirs_seen: int = 0


def _has_mz_header(path: str) -> bool:
    with open(fs_path(path), "rb") as f:
        return f.read(2) == b"MZ"


def _name_signals(name: str, ext: str, executable_exts: set[str]) -> set[str]:
    signals: set[str] = set()
    if RTLO in name:
        signals.add(SIGNAL_RTLO)
    parts = name.lower().split(".")
    if len(parts) >= 3 and ext in executable_exts:
        decoy = "." + parts[-2].strip()
        if decoy in DECOY_EXTENSIONS:
            signals.add(SIGNAL_DOUBLE_EXT)
    return signals


class Walker:
    def __init__(
        self,
        cfg: ScanConfig,
        all_files: bool = False,
        on_progress: Callable[[int, int], None] | None = None,
        checkpoint: Callable[[], None] | None = None,
    ) -> None:
        """checkpoint se llama a menudo; si lanza una excepción, el recorrido se para."""
        self.cfg = cfg
        self.all_files = all_files
        self.on_progress = on_progress
        self.checkpoint = checkpoint or (lambda: None)
        self.extensions = set(cfg.extensions)
        self.no_sniff = set(cfg.no_sniff_extensions)
        self.exclude_dirs = set(cfg.exclude_dirs) | ALWAYS_SKIP_DIRS
        self.max_bytes = cfg.max_file_size_mb * 1024 * 1024

    def walk(self, target: str) -> WalkResult:
        target = os.path.abspath(target)
        self._pending_sniff = []
        if os.path.isfile(target):
            return self._single_file(target)
        result = WalkResult(root=target)
        stack = [target]
        while stack:
            self.checkpoint()
            directory = stack.pop()
            result.dirs_seen += 1
            try:
                with os.scandir(fs_path(directory)) as it:
                    entries = list(it)
            except OSError as exc:
                rel = os.path.relpath(directory, target)
                result.skipped.append(
                    SkippedEntry(directory, rel, None, "access_denied", str(exc.strerror or exc))
                )
                continue
            for entry in entries:
                path = os.path.join(directory, entry.name)
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    if is_defender_block(exc):
                        rel = os.path.relpath(path, target)
                        result.skipped.append(SkippedEntry(path, rel, None, "defender_blocked"))
                    continue
                attrs = getattr(st, "st_file_attributes", 0)
                if stat.S_ISDIR(st.st_mode):
                    # Enlaces simbólicos y junctions: se saltan para evitar bucles
                    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                        continue
                    if entry.name.lower() in self.exclude_dirs:
                        continue
                    stack.append(path)
                    continue
                if not stat.S_ISREG(st.st_mode) or entry.is_symlink():
                    continue
                result.files_seen += 1
                result.bytes_seen += st.st_size
                self._consider(path, target, st, attrs, result)
                if self.on_progress and result.files_seen % 500 == 0:
                    self.on_progress(result.files_seen, result.dirs_seen)
        if self.on_progress:
            self.on_progress(result.files_seen, result.dirs_seen)
        self._sniff_pending(result)
        result.files.sort(key=lambda e: e.rel_path.lower())
        return result

    def _sniff_pending(self, result: WalkResult) -> None:
        """Lee los 2 primeros bytes de los archivos dudosos. En paralelo, porque
        Defender analiza cada archivo que se abre y en frío eso es lento."""
        pending, self._pending_sniff = self._pending_sniff, []
        if not pending:
            return

        def sniff(entry: FileEntry) -> str:
            try:
                return "mz" if _has_mz_header(entry.path) else "no"
            except OSError as exc:
                return "blocked" if is_defender_block(exc) else "no"

        pool = ThreadPoolExecutor(max_workers=SNIFF_WORKERS)
        try:
            for entry, outcome in zip(pending, pool.map(sniff, pending)):
                self.checkpoint()
                if outcome == "mz":
                    if entry.ext not in LEGIT_PE_EXTENSIONS:
                        entry.signals.add(SIGNAL_DISGUISED)
                    result.files.append(entry)
                elif outcome == "blocked":
                    result.skipped.append(SkippedEntry(entry.path, entry.rel_path, entry.size, "defender_blocked"))
        except BaseException:
            # Si se detiene, no esperar a los que quedan en cola
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        pool.shutdown()

    def _single_file(self, path: str) -> WalkResult:
        root = os.path.dirname(path)
        result = WalkResult(root=root, files_seen=1, dirs_seen=0)
        st = os.stat(fs_path(path))
        result.bytes_seen = st.st_size
        attrs = getattr(st, "st_file_attributes", 0)
        self._consider(path, root, st, attrs, result, explicit=True)
        return result

    def _consider(
        self,
        path: str,
        root: str,
        st: os.stat_result,
        attrs: int,
        result: WalkResult,
        explicit: bool = False,
    ) -> None:
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        rel = os.path.relpath(path, root)
        size = st.st_size

        if attrs & CLOUD_PLACEHOLDER_ATTRIBUTES:
            # Archivo de OneDrive (o similar) sin descargar: leerlo lo descargaría
            if explicit or self.all_files or ext in self.extensions:
                result.skipped.append(SkippedEntry(path, rel, size, "cloud"))
            return

        signals = _name_signals(name, ext, self.extensions | LEGIT_PE_EXTENSIONS)
        if attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
            signals.add(SIGNAL_HIDDEN)

        if explicit:
            reason = "explicit"
        elif self.all_files:
            reason = "all"
        elif ext in self.extensions:
            reason = "extension"
        else:
            reason = ""

        too_large = size > self.max_bytes
        if not reason:
            # Puede ser un ejecutable camuflado: se mira su cabecera al final, en
            # paralelo (salvo en archivos de datos obvios)
            if (
                self.cfg.detect_executables_by_content
                and ext not in self.no_sniff
                and not too_large
                and size >= 64
            ):
                self._pending_sniff.append(
                    FileEntry(path, rel, size, st.st_mtime_ns, ext, "content", rel.count(os.sep), signals)
                )
            return

        if too_large:
            result.skipped.append(
                SkippedEntry(path, rel, size, "too_large", f"más de {self.cfg.max_file_size_mb} MB")
            )
            return

        depth = rel.count(os.sep)
        result.files.append(
            FileEntry(
                path=path,
                rel_path=rel,
                size=size,
                mtime_ns=st.st_mtime_ns,
                ext=ext,
                reason=reason,
                depth=depth,
                signals=signals,
            )
        )
