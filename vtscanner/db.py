"""Base de datos SQLite: caché de hashes y resultados, registro de peticiones,
escaneos (para reanudar) y cola de subidas."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Ruta -> hash, para no volver a leer archivos que no han cambiado
CREATE TABLE IF NOT EXISTS file_hashes (
    path_key   TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    mtime_ns   INTEGER NOT NULL,
    file_id    TEXT NOT NULL DEFAULT '',  -- identificador en el disco; en NTFS no cabe en un INTEGER
    sha256     TEXT NOT NULL,
    is_pe      INTEGER NOT NULL DEFAULT 0,
    sig_status TEXT,
    sig_signer TEXT,
    updated_at REAL NOT NULL
);

-- Resultado de VirusTotal por hash
CREATE TABLE IF NOT EXISTS vt_results (
    sha256        TEXT PRIMARY KEY,
    state         TEXT NOT NULL,          -- found | not_found | pending_analysis
    malicious     INTEGER,
    suspicious    INTEGER,
    total         INTEGER,
    data_json     TEXT,                   -- datos reducidos del informe
    analysis_id   TEXT,
    next_check_at REAL,
    checks        INTEGER NOT NULL DEFAULT 0,
    source        TEXT,                   -- lookup | upload
    updated_at    REAL NOT NULL
);

-- Registro de peticiones a la API (límite por minuto y cuenta diaria)
CREATE TABLE IF NOT EXISTS api_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    endpoint    TEXT NOT NULL,
    http_status INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_requests_ts ON api_requests(ts);

-- Cada escaneo, para poder reanudarlo
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    root          TEXT NOT NULL,
    root_key      TEXT NOT NULL,
    options_json  TEXT NOT NULL,
    defender_json TEXT,
    started_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    status        TEXT NOT NULL           -- running | paused | interrupted | done
);

-- Cosas que no se pueden volver a averiguar recorriendo la carpeta
-- (por ejemplo, un archivo que Defender bloqueó y puso en cuarentena)
CREATE TABLE IF NOT EXISTS scan_events (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path    TEXT NOT NULL,
    kind    TEXT NOT NULL,                -- defender_blocked
    detail  TEXT,
    PRIMARY KEY (scan_id, path, kind)
);

-- Subidas confirmadas por el usuario que aún no se han hecho
CREATE TABLE IF NOT EXISTS upload_queue (
    sha256    TEXT PRIMARY KEY,
    path      TEXT NOT NULL,
    size      INTEGER NOT NULL,
    scan_id   INTEGER,
    queued_at REAL NOT NULL
);
"""


@dataclass
class CachedHash:
    sha256: str
    is_pe: bool
    sig_status: str | None
    sig_signer: str | None


@dataclass
class VtRecord:
    sha256: str
    state: str
    malicious: int | None
    suspicious: int | None
    total: int | None
    data: dict[str, Any] | None
    analysis_id: str | None
    next_check_at: float | None
    checks: int
    source: str | None
    updated_at: float


@dataclass
class ScanRecord:
    id: int
    root: str
    root_key: str
    options: dict[str, Any]
    defender: dict[str, Any] | None
    started_at: float
    updated_at: float
    status: str


class Database:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.clock = clock
        self.conn = sqlite3.connect(str(path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        self.conn.executescript(SCHEMA)
        if version == 1:
            self.conn.execute("ALTER TABLE file_hashes ADD COLUMN file_id TEXT NOT NULL DEFAULT ''")
        self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ---- meta ---------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # ---- caché de hashes ----------------------------------------------------

    def get_file_hash(self, key: str, size: int, mtime_ns: int, file_id: str) -> CachedHash | None:
        row = self.conn.execute(
            "SELECT sha256, is_pe, sig_status, sig_signer FROM file_hashes "
            "WHERE path_key = ? AND size = ? AND mtime_ns = ? AND file_id = ?",
            (key, size, mtime_ns, file_id),
        ).fetchone()
        if row is None:
            return None
        return CachedHash(row["sha256"], bool(row["is_pe"]), row["sig_status"], row["sig_signer"])

    def put_file_hashes(self, rows: Iterable[tuple[str, int, int, str, str, bool]]) -> None:
        """rows: (path_key, size, mtime_ns, file_id, sha256, is_pe). Borra la firma guardada
        si el archivo ha cambiado."""
        now = self.clock()
        with self.conn:
            self.conn.executemany(
                "INSERT INTO file_hashes (path_key, size, mtime_ns, file_id, sha256, is_pe, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(path_key) DO UPDATE SET size = excluded.size, "
                "mtime_ns = excluded.mtime_ns, file_id = excluded.file_id, sha256 = excluded.sha256, "
                "is_pe = excluded.is_pe, sig_status = NULL, sig_signer = NULL, "
                "updated_at = excluded.updated_at",
                [(k, s, m, i, h, int(pe), now) for k, s, m, i, h, pe in rows],
            )

    def put_signatures(self, rows: Iterable[tuple[str, str, str]]) -> None:
        """rows: (path_key, sig_status, sig_signer)."""
        with self.conn:
            self.conn.executemany(
                "UPDATE file_hashes SET sig_status = ?, sig_signer = ? WHERE path_key = ?",
                [(status, signer, key) for key, status, signer in rows],
            )

    # ---- resultados de VirusTotal -------------------------------------------

    def _vt_from_row(self, row: sqlite3.Row) -> VtRecord:
        data = json.loads(row["data_json"]) if row["data_json"] else None
        return VtRecord(
            sha256=row["sha256"],
            state=row["state"],
            malicious=row["malicious"],
            suspicious=row["suspicious"],
            total=row["total"],
            data=data,
            analysis_id=row["analysis_id"],
            next_check_at=row["next_check_at"],
            checks=row["checks"],
            source=row["source"],
            updated_at=row["updated_at"],
        )

    def get_vt_records(self, hashes: Iterable[str]) -> dict[str, VtRecord]:
        result: dict[str, VtRecord] = {}
        hashes = list(hashes)
        for start in range(0, len(hashes), 500):
            chunk = hashes[start : start + 500]
            marks = ",".join("?" * len(chunk))
            for row in self.conn.execute(
                f"SELECT * FROM vt_results WHERE sha256 IN ({marks})", chunk
            ):
                result[row["sha256"]] = self._vt_from_row(row)
        return result

    def get_vt_record(self, sha256: str) -> VtRecord | None:
        return self.get_vt_records([sha256]).get(sha256)

    def put_vt_found(
        self,
        sha256: str,
        malicious: int,
        suspicious: int,
        total: int,
        data: dict[str, Any],
        source: str,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO vt_results (sha256, state, malicious, suspicious, total, data_json, "
                "analysis_id, next_check_at, checks, source, updated_at) "
                "VALUES (?, 'found', ?, ?, ?, ?, NULL, NULL, 0, ?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET state = 'found', malicious = excluded.malicious, "
                "suspicious = excluded.suspicious, total = excluded.total, "
                "data_json = excluded.data_json, analysis_id = NULL, next_check_at = NULL, "
                "checks = 0, source = excluded.source, updated_at = excluded.updated_at",
                (sha256, malicious, suspicious, total, json.dumps(data, ensure_ascii=False), source, self.clock()),
            )

    def put_vt_not_found(self, sha256: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO vt_results (sha256, state, updated_at, source) "
                "VALUES (?, 'not_found', ?, 'lookup') "
                "ON CONFLICT(sha256) DO UPDATE SET state = 'not_found', malicious = NULL, "
                "suspicious = NULL, total = NULL, data_json = NULL, analysis_id = NULL, "
                "next_check_at = NULL, checks = 0, source = 'lookup', updated_at = excluded.updated_at",
                (sha256, self.clock()),
            )

    def put_vt_pending(self, sha256: str, analysis_id: str, next_check_at: float) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO vt_results (sha256, state, analysis_id, next_check_at, checks, source, updated_at) "
                "VALUES (?, 'pending_analysis', ?, ?, 0, 'upload', ?) "
                "ON CONFLICT(sha256) DO UPDATE SET state = 'pending_analysis', "
                "analysis_id = excluded.analysis_id, next_check_at = excluded.next_check_at, "
                "checks = 0, source = 'upload', updated_at = excluded.updated_at",
                (sha256, analysis_id, next_check_at, self.clock()),
            )

    def reschedule_pending(self, sha256: str, next_check_at: float, checks: int) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE vt_results SET next_check_at = ?, checks = ?, updated_at = ? "
                "WHERE sha256 = ? AND state = 'pending_analysis'",
                (next_check_at, checks, self.clock(), sha256),
            )

    def pending_analyses(self) -> list[VtRecord]:
        rows = self.conn.execute(
            "SELECT * FROM vt_results WHERE state = 'pending_analysis' ORDER BY next_check_at"
        ).fetchall()
        return [self._vt_from_row(r) for r in rows]

    # ---- registro de peticiones ---------------------------------------------

    def log_request(self, ts: float, endpoint: str, http_status: int | None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO api_requests (ts, endpoint, http_status) VALUES (?, ?, ?)",
                (ts, endpoint, http_status),
            )

    def request_times_after(self, ts: float) -> list[float]:
        """Horas de las peticiones posteriores (estrictamente) a ts."""
        rows = self.conn.execute(
            "SELECT ts FROM api_requests WHERE ts > ? ORDER BY ts", (ts,)
        ).fetchall()
        return [r["ts"] for r in rows]

    def count_requests_since(self, ts: float) -> int:
        """Peticiones que gastan cuota diaria. Consultar la propia cuota (users) no
        gasta (comprobado contra la API), aunque sí cuenta para el límite por minuto."""
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM api_requests WHERE ts >= ? AND endpoint != 'users'", (ts,)
        ).fetchone()
        return int(row["n"])

    def prune_requests(self, before_ts: float) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM api_requests WHERE ts < ?", (before_ts,))

    # ---- escaneos -----------------------------------------------------------

    def _scan_from_row(self, row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=row["id"],
            root=row["root"],
            root_key=row["root_key"],
            options=json.loads(row["options_json"]),
            defender=json.loads(row["defender_json"]) if row["defender_json"] else None,
            started_at=row["started_at"],
            updated_at=row["updated_at"],
            status=row["status"],
        )

    def create_scan(self, root: str, root_key: str, options: dict[str, Any]) -> int:
        now = self.clock()
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO scans (root, root_key, options_json, started_at, updated_at, status) "
                "VALUES (?, ?, ?, ?, ?, 'running')",
                (root, root_key, json.dumps(options), now, now),
            )
        return int(cur.lastrowid)

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def set_scan_status(self, scan_id: int, status: str) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE scans SET status = ?, updated_at = ? WHERE id = ?",
                (status, self.clock(), scan_id),
            )

    def set_scan_options(self, scan_id: int, options: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE scans SET options_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(options), self.clock(), scan_id),
            )

    def set_scan_defender(self, scan_id: int, defender: dict[str, Any]) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE scans SET defender_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(defender, ensure_ascii=False), self.clock(), scan_id),
            )

    def find_resumable_scan(self, root_key: str | None = None) -> ScanRecord | None:
        """Último escaneo sin terminar (de esa carpeta, si se indica)."""
        query = "SELECT * FROM scans WHERE status IN ('running', 'paused', 'interrupted')"
        params: tuple[Any, ...] = ()
        if root_key is not None:
            query += " AND root_key = ?"
            params = (root_key,)
        row = self.conn.execute(query + " ORDER BY updated_at DESC LIMIT 1", params).fetchone()
        return self._scan_from_row(row) if row else None

    def add_event(self, scan_id: int, path: str, kind: str, detail: str = "") -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO scan_events (scan_id, path, kind, detail) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scan_id, path, kind) DO UPDATE SET detail = excluded.detail",
                (scan_id, path, kind, detail),
            )

    def events_for_scan(self, scan_id: int) -> list[tuple[str, str, str]]:
        rows = self.conn.execute(
            "SELECT path, kind, detail FROM scan_events WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [(r["path"], r["kind"], r["detail"] or "") for r in rows]

    # ---- cola de subidas ----------------------------------------------------

    def queue_uploads(self, rows: Iterable[tuple[str, str, int]], scan_id: int | None) -> None:
        """rows: (sha256, path, size)."""
        now = self.clock()
        with self.conn:
            self.conn.executemany(
                "INSERT INTO upload_queue (sha256, path, size, scan_id, queued_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(sha256) DO NOTHING",
                [(h, p, s, scan_id, now) for h, p, s in rows],
            )

    def queued_uploads(self) -> list[tuple[str, str, int]]:
        rows = self.conn.execute(
            "SELECT sha256, path, size FROM upload_queue ORDER BY queued_at, size"
        ).fetchall()
        return [(r["sha256"], r["path"], r["size"]) for r in rows]

    def remove_from_queue(self, sha256: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM upload_queue WHERE sha256 = ?", (sha256,))

    def clear_queue(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM upload_queue")
