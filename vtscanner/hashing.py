"""Cálculo de SHA-256 en paralelo, reutilizando la caché por ruta."""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Callable

from .db import Database
from .walker import FileEntry
from .winutils import fs_path, is_defender_block, path_key

CHUNK_SIZE = 1024 * 1024


class HashingCancelled(Exception):
    pass


@dataclass
class HashResult:
    entry: FileEntry
    sha256: str | None
    is_pe: bool
    from_cache: bool
    error: str | None = None
    defender_blocked: bool = False
    sig_status: str | None = None
    sig_signer: str | None = None


def sha256_of_file(path: str, stop: threading.Event | None = None) -> tuple[str, bool]:
    """Devuelve (sha256, empieza_por_MZ). Lee en bloques de 1 MB sin cargar el archivo."""
    digest = hashlib.sha256()
    buffer = bytearray(CHUNK_SIZE)
    view = memoryview(buffer)
    with open(fs_path(path), "rb", buffering=0) as f:
        n = f.readinto(buffer)
        is_pe = n >= 2 and buffer[0:2] == b"MZ"
        while n:
            if stop is not None and stop.is_set():
                raise HashingCancelled()
            digest.update(view[:n])
            n = f.readinto(buffer)
    return digest.hexdigest(), is_pe


def hash_entries(
    entries: list[FileEntry],
    db: Database,
    workers: int = 4,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[HashResult]:
    """Calcula el hash de cada archivo. on_progress(bytes_hechos, bytes_totales)."""
    total_bytes = sum(e.size for e in entries)
    done_bytes = 0
    results: list[HashResult] = []
    pending: list[FileEntry] = []

    for entry in entries:
        cached = db.get_file_hash(path_key(entry.path), entry.size, entry.mtime_ns)
        if cached is not None:
            results.append(
                HashResult(
                    entry,
                    cached.sha256,
                    cached.is_pe,
                    True,
                    sig_status=cached.sig_status,
                    sig_signer=cached.sig_signer,
                )
            )
            done_bytes += entry.size
        else:
            pending.append(entry)
    if on_progress:
        on_progress(done_bytes, total_bytes)
    if not pending:
        return results

    stop = threading.Event()
    batch: list[tuple[str, int, int, str, bool]] = []
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures: dict[Future[tuple[str, bool]], FileEntry] = {
            executor.submit(sha256_of_file, e.path, stop): e for e in pending
        }
        not_done = set(futures)
        while not_done:
            # Espera con timeout para que Ctrl+C funcione en Windows
            finished, not_done = wait(not_done, timeout=0.5, return_when=FIRST_COMPLETED)
            for future in finished:
                entry = futures[future]
                try:
                    sha, is_pe = future.result()
                except OSError as exc:
                    if is_defender_block(exc):
                        results.append(
                            HashResult(entry, None, False, False, "Bloqueado por Defender", True)
                        )
                    else:
                        results.append(
                            HashResult(entry, None, False, False, str(exc.strerror or exc))
                        )
                else:
                    results.append(HashResult(entry, sha, is_pe, False))
                    batch.append((path_key(entry.path), entry.size, entry.mtime_ns, sha, is_pe))
                    if len(batch) >= 50:
                        db.put_file_hashes(batch)
                        batch.clear()
                done_bytes += entry.size
                if on_progress:
                    on_progress(done_bytes, total_bytes)
    except BaseException:
        stop.set()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    finally:
        if batch:
            db.put_file_hashes(batch)
    executor.shutdown(wait=True)
    return results


def group_by_hash(results: list[HashResult]) -> dict[str, list[HashResult]]:
    """Agrupa los archivos con el mismo contenido (deduplicación)."""
    groups: dict[str, list[HashResult]] = {}
    for r in results:
        if r.sha256:
            groups.setdefault(r.sha256, []).append(r)
    return groups
