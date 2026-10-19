"""Orquesta un escaneo completo: Defender, recorrido, hashes, firmas, VirusTotal,
subidas e informe. No imprime nada: habla con el usuario a través de BaseUI."""

from __future__ import annotations

import logging
import math
import os
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import defender as defender_mod
from .config import Config
from .db import Database, VtRecord
from .defender import DefenderResult
from .hashing import HashResult, group_by_hash, hash_entries
from .ratelimit import DailyQuotaExceeded, RateLimiter, format_local_time
from .report import ReportRow, ReportSummary, human_size, plural, report_basename, write_csv, write_html
from .signatures import (
    STATUS_LABELS,
    STATUS_TAMPERED,
    STATUS_UNSIGNED,
    STATUS_UNTRUSTED,
    STATUS_ERROR,
    check_signatures,
    is_trusted,
    needs_signature_check,
)
from .ui import BaseUI, UploadCost, UploadItem
from .verdict import (
    Classifier,
    Level,
    Verdict,
    classify_defender,
    combine,
    defender_blocked_verdict,
)
from .vtclient import AuthError, FileReport, TransientError, VTClient, VTError, gui_url
from .walker import SIGNAL_DISGUISED, SIGNAL_DOUBLE_EXT, SIGNAL_HIDDEN, SIGNAL_RTLO, Walker, WalkResult
from .winutils import IS_WINDOWS, allow_sleep, fs_path, path_key, prevent_sleep

log = logging.getLogger(__name__)

SCRIPT_EXTS = {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".lnk"}
TOP_EXEC_EXTS = {".exe", ".scr", ".com", ".pif"}
LIB_EXTS = {".dll", ".sys", ".asi", ".cpl", ".ocx"}
PACKAGE_EXTS = {".msi", ".msp", ".jar"}
RISKY_SIGNALS = {SIGNAL_HIDDEN, SIGNAL_DOUBLE_EXT, SIGNAL_RTLO}
STATUS_SUMMARY = {
    "valid": "válidas",
    "unsigned": "sin firma",
    "tampered": "rotas (archivo modificado)",
    "untrusted": "no válidas",
    "unverifiable": "no verificables",
    "error": "sin comprobar",
}
CHECK_DELAYS = (120, 240, 480, 900)  # esperas entre comprobaciones de un análisis
LOG_LEVELS = {"warn": logging.WARNING, "error": logging.ERROR}


@dataclass
class ScanOptions:
    target: str
    upload: bool = False
    defender: bool = False
    all_files: bool = False
    wait: bool = False
    dry_run: bool = False
    refresh: bool = False

    def stored(self) -> dict[str, Any]:
        """Lo que se guarda para --resume."""
        return {"upload": self.upload, "defender": self.defender, "all_files": self.all_files}

    def labels(self) -> list[str]:
        flags = [
            ("--upload", self.upload),
            ("--defender", self.defender),
            ("--all-files", self.all_files),
            ("--wait", self.wait),
            ("--dry-run", self.dry_run),
            ("--refresh", self.refresh),
        ]
        return [name for name, on in flags if on]


@dataclass
class ScanOutcome:
    scan_id: int
    complete: bool
    findings: bool
    interrupted: bool = False
    report_html: Path | None = None
    report_csv: Path | None = None


@dataclass
class _Check:
    analysis_id: str
    next_at: float
    checks: int
    this_run: int = 0


@dataclass
class _RunState:
    walk: WalkResult | None = None
    hashes: list[HashResult] = field(default_factory=list)
    groups: dict[str, list[HashResult]] = field(default_factory=dict)
    defender: DefenderResult | None = None
    errors: dict[str, str] = field(default_factory=dict)  # sha256 -> error en esta ejecución
    trusted_skip: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


def file_priority(r: HashResult, trusted: list[str]) -> tuple[int, int, str]:
    """Cuanto más bajo, antes se consulta."""
    e = r.entry
    if SIGNAL_DISGUISED in e.signals:
        base = 0
    elif e.ext in SCRIPT_EXTS or e.ext in TOP_EXEC_EXTS:
        base = 1
    elif e.ext in LIB_EXTS or e.ext in PACKAGE_EXTS or r.is_pe:
        base = 2
    elif e.ext == ".js":
        base = 3
    else:
        base = 4
    if RISKY_SIGNALS & e.signals or r.sig_status in (STATUS_TAMPERED, STATUS_UNTRUSTED):
        base -= 1
    if is_trusted(r.sig_signer, r.sig_status, trusted):
        base += 3
    return (base, e.depth, e.rel_path.lower())


def upload_priority(r: HashResult) -> tuple[int, int]:
    risky = (
        r.entry.ext in SCRIPT_EXTS
        or SIGNAL_DISGUISED in r.entry.signals
        or r.sig_status in (STATUS_TAMPERED, STATUS_UNTRUSTED, STATUS_UNSIGNED)
    )
    return (0 if risky else 1, r.entry.size)


def signature_text(status: str | None, signer: str | None) -> str:
    if not status:
        return ""
    text = STATUS_LABELS.get(status, status)
    if signer and status != STATUS_UNSIGNED:
        text += f" ({signer})"
    return text


def format_minutes(minutes: float) -> str:
    minutes = math.ceil(minutes)
    if minutes < 60:
        return f"{minutes} min"
    hours, rest = divmod(minutes, 60)
    return f"{hours} h {rest:02d} min"


class Scanner:
    def __init__(
        self,
        cfg: Config,
        ui: BaseUI,
        api_key: str | None,
        db: Database | None = None,
        client_factory: Callable[..., VTClient] = VTClient,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
        defender_runner: Callable[..., DefenderResult] = defender_mod.run_scan,
    ) -> None:
        self.cfg = cfg
        self.ui = ui
        self.api_key = api_key
        self.db = db or Database(cfg.db_path, clock)
        self.client_factory = client_factory
        self.clock = clock
        self.sleeper = sleeper
        self.defender_runner = defender_runner
        self.classifier = Classifier(cfg.verdict)
        self.limiter = RateLimiter(
            self.db, cfg.virustotal.requests_per_minute, cfg.virustotal.daily_limit, clock, sleeper
        )

    # ---- mensajes: se muestran al usuario y quedan en el log ----------------

    def _say(self, text: str, kind: str = "info") -> None:
        log.log(LOG_LEVELS.get(kind, logging.INFO), text)
        self.ui.message(text, kind)

    def _phase(self, title: str) -> None:
        log.info("== %s", title)
        self.ui.phase(title)

    def _end(self, summary: str | None = None) -> None:
        if summary:
            log.info(summary)
        self.ui.task_end(summary)

    # ======================================================================
    # Escaneo
    # ======================================================================

    def run(self, options: ScanOptions, resume_scan_id: int | None = None) -> ScanOutcome:
        started = self.clock()
        target = os.path.abspath(options.target)
        root_key = path_key(target)
        scan_id, stored_defender = self._open_scan(target, root_key, options, resume_scan_id)
        state = _RunState()
        interrupted = False
        network_done = False
        try:
            client = None if options.dry_run else self._connect()
            if options.defender:
                self._defender_phase(scan_id, target, stored_defender, state)
            self._walk_phase(options, state)
            self._hash_phase(scan_id, state)
            self._signature_phase(state)
            lookups = self._plan_lookups(options, state)
            if options.dry_run:
                self._estimate(lookups, state, dry_run=True)
            elif client is not None:
                network_done = self._network_phase(client, lookups, options, scan_id, state)
        except KeyboardInterrupt:
            interrupted = True
            self._end()
            self._say("Interrumpido. Se guarda lo hecho y se genera un informe parcial.", "warn")
        except Exception:
            self._end()
            log.exception("Error inesperado durante el escaneo")
            self.db.set_scan_status(scan_id, "interrupted")
            raise
        rows = self._build_rows(scan_id, state)
        pending = sum(1 for r in rows if r.level == Level.PENDING)
        complete = not interrupted and pending == 0 and (network_done or options.dry_run)
        if options.dry_run:
            complete = pending == 0
        findings = any(r.level >= Level.HIGH for r in rows)
        summary = self._summary(target, started, options, state, rows, complete, pending)
        html_path, csv_path = self._write_reports(target, rows, summary)
        if interrupted:
            status = "interrupted"
        elif complete:
            status = "done"
        else:
            status = "paused"
        self.db.set_scan_status(scan_id, status)
        counts = Counter(r.level.label for r in rows)
        log.info("Resultado: %s", ", ".join(f"{name} {n}" for name, n in counts.most_common()) or "sin archivos")
        log.info(
            "Peticiones en esta ejecución: %s; usadas hoy: %s de %s; estado: %s",
            self.limiter.requests_this_run,
            self.limiter.used_today(),
            self.limiter.effective_daily_limit(),
            status,
        )
        log.info("Informes: %s | %s", html_path, csv_path)
        self.ui.show_summary(rows, summary, [html_path, csv_path])
        return ScanOutcome(scan_id, complete, findings, interrupted, html_path, csv_path)

    def _open_scan(
        self, target: str, root_key: str, options: ScanOptions, resume_scan_id: int | None
    ) -> tuple[int, dict[str, Any] | None]:
        scan = None
        if resume_scan_id is not None:
            scan = self.db.get_scan(resume_scan_id)
        if scan is None:
            scan = self.db.find_resumable_scan(root_key)
        if scan is not None and scan.root_key == root_key:
            self.db.set_scan_options(scan.id, options.stored())
            self.db.set_scan_status(scan.id, "running")
            self._say("Se continúa el escaneo anterior de esta carpeta (no se repite lo ya hecho).")
            return scan.id, scan.defender
        return self.db.create_scan(target, root_key, options.stored()), None

    # ---- conexión -----------------------------------------------------------

    def _connect(self) -> VTClient:
        client = self.client_factory(
            self.api_key, self.limiter, self.cfg.virustotal, on_wait=self.ui.waiting
        )
        limit = self.limiter.effective_daily_limit()
        if self.limiter.remaining_today() <= 0:
            self._say(
                f"La cuota diaria ya está agotada; se reinicia a las "
                f"{format_local_time(self.limiter.next_reset())} (hora local).",
                "warn",
            )
            return client
        quota = client.get_user_quota()  # lanza AuthError si la clave no vale
        if quota is not None:
            used, allowed = quota
            self.limiter.sync_with_server(used, allowed)
            limit = self.limiter.effective_daily_limit()
            self._say(
                f"Clave de VirusTotal válida. Cuota de hoy: {self.limiter.used_today()} de {limit} usadas.",
                "ok",
            )
        else:
            self._say(
                f"No se pudo leer la cuota en VirusTotal; se usa el contador local "
                f"({self.limiter.used_today()} de {limit} hoy).",
                "warn",
            )
        return client

    # ---- Defender -----------------------------------------------------------

    def _defender_phase(
        self, scan_id: int, target: str, stored: dict[str, Any] | None, state: _RunState
    ) -> None:
        self._phase("Microsoft Defender")
        if stored is not None:
            state.defender = DefenderResult.from_dict(stored)
            self._say("Se reutiliza el análisis de Defender de la ejecución anterior.")
        else:
            mode = "solo informe" if self.cfg.defender.report_only else "con acciones de Defender"
            self.ui.task_start(f"Analizando con Defender ({mode})", None)
            result = self.defender_runner(
                target,
                report_only=self.cfg.defender.report_only,
                on_tick=lambda s: self.ui.task_update(detail=f"{s:.0f} s"),
            )
            self._end()
            self.db.set_scan_defender(scan_id, result.to_dict())
            state.defender = result
        result = state.defender
        if not result.ok:
            self._say(f"Defender no pudo analizar la carpeta: {result.error}", "warn")
            state.notes.append(f"Defender no pudo analizar la carpeta: {result.error}")
        elif not result.threats:
            self._say(f"Defender: sin amenazas ({result.duration:.0f} s).", "ok")
        else:
            self._say(f"Defender encontró {len(result.threats)} amenaza(s):", "warn")
            for threat in result.threats:
                where = ", ".join(threat.resources) or "(sin ruta)"
                self._say(f"  {threat.name}: {where}", "warn")

    # ---- recorrido y hashes -------------------------------------------------

    def _walk_phase(self, options: ScanOptions, state: _RunState) -> None:
        self._phase("Buscando archivos")
        self.ui.task_start("Recorriendo la carpeta", None)
        walker = Walker(
            self.cfg.scan,
            options.all_files,
            on_progress=lambda f, d: self.ui.task_update(detail=f"{f} archivos, {d} carpetas"),
        )
        walk = walker.walk(options.target)
        state.walk = walk
        kind = "todos los archivos" if options.all_files else "ejecutables y scripts"
        self._end(
            f"{plural(walk.files_seen, 'archivo')} ({human_size(walk.bytes_seen)}) en "
            f"{plural(walk.dirs_seen, 'carpeta')}; {len(walk.files)} para analizar ({kind})."
        )
        disguised = sum(1 for e in walk.files if SIGNAL_DISGUISED in e.signals)
        if disguised:
            self._say(f"{disguised} ejecutable(s) con una extensión que no es la suya.", "warn")
        reasons = {
            "too_large": f"de más de {self.cfg.scan.max_file_size_mb} MB se omiten (VirusTotal no los admite)",
            "cloud": "están en la nube sin descargar y se omiten",
            "access_denied": "no se pudieron abrir (permisos)",
        }
        for reason, text in reasons.items():
            count = sum(1 for s in walk.skipped if s.reason == reason)
            if count:
                note = f"{count} archivo(s) o carpeta(s) {text}."
                self._say(note, "warn")
                state.notes.append(note)

    def _hash_phase(self, scan_id: int, state: _RunState) -> None:
        assert state.walk is not None
        files = state.walk.files
        if not files:
            self._say("No hay archivos que analizar.", "warn")
            return
        self._phase("Calculando SHA-256")
        self.ui.task_start("Calculando hashes", sum(e.size for e in files), unit="bytes")
        state.hashes = hash_entries(
            files,
            self.db,
            self.cfg.scan.hash_workers,
            on_progress=lambda done, total: self.ui.task_update(completed=done),
        )
        state.groups = group_by_hash(state.hashes)
        cached = sum(1 for r in state.hashes if r.from_cache)
        hashed = sum(1 for r in state.hashes if r.sha256)
        self._end(
            f"{plural(hashed, 'archivo')}, {plural(len(state.groups), 'distinto')}"
            + (f" ({cached} sin releer gracias a la caché)" if cached else "")
            + "."
        )
        blocked = [r for r in state.hashes if r.defender_blocked]
        for r in blocked:
            self.db.add_event(scan_id, r.entry.path, "defender_blocked")
        for s in state.walk.skipped:
            if s.reason == "defender_blocked":
                self.db.add_event(scan_id, s.path, "defender_blocked")
        if blocked:
            self._say(f"Defender bloqueó la lectura de {len(blocked)} archivo(s).", "warn")
        failed = [r for r in state.hashes if r.error and not r.defender_blocked]
        if failed:
            self._say(f"{len(failed)} archivo(s) no se pudieron leer.", "warn")

    def _signature_phase(self, state: _RunState) -> None:
        if not self.cfg.signatures.enabled or not IS_WINDOWS:
            return
        need = [
            r
            for r in state.hashes
            if r.sha256 and r.sig_status is None and needs_signature_check(r.entry.ext, r.is_pe)
        ]
        if not need:
            return
        self.ui.task_start("Comprobando firmas digitales", len(need), unit="files")
        infos = check_signatures(
            [r.entry.path for r in need],
            on_progress=lambda done, total: self.ui.task_update(completed=done),
        )
        rows = []
        for r, info in zip(need, infos):
            r.sig_status, r.sig_signer = info.status, info.signer
            if info.status != STATUS_ERROR:
                rows.append((path_key(r.entry.path), info.status, info.signer))
        self.db.put_signatures(rows)
        counts: dict[str, int] = {}
        for info in infos:
            counts[info.status] = counts.get(info.status, 0) + 1
        parts = [f"{STATUS_SUMMARY[s]}: {n}" for s, n in sorted(counts.items(), key=lambda x: -x[1])]
        self._end("Firmas digitales. " + ", ".join(parts) + ".")

    # ---- planificación ------------------------------------------------------

    def _plan_lookups(self, options: ScanOptions, state: _RunState) -> list[str]:
        """Hashes que hay que consultar, ordenados por prioridad."""
        records = self.db.get_vt_records(state.groups.keys())
        now = self.clock()
        not_found_ttl = self.cfg.virustotal.not_found_cache_days * 86400
        trusted = self.cfg.signatures.trusted_publishers
        planned: list[tuple[tuple[int, int, str], str]] = []
        for sha, results in state.groups.items():
            record = records.get(sha)
            if record is not None and record.state == "pending_analysis":
                continue
            if (
                self.cfg.signatures.skip_trusted_signed
                and record is None
                and all(is_trusted(r.sig_signer, r.sig_status, trusted) for r in results)
            ):
                state.trusted_skip.add(sha)
                continue
            needed = (
                record is None
                or options.refresh
                or (record.state == "not_found" and now - record.updated_at > not_found_ttl)
            )
            if needed:
                planned.append((min(file_priority(r, trusted) for r in results), sha))
        planned.sort()
        return [sha for _, sha in planned]

    def _estimate(self, lookups: list[str], state: _RunState, dry_run: bool = False) -> None:
        checks = self._pending_checks(state)
        needed = len(lookups) + len(checks)
        cached = len(state.groups) - len(lookups) - len(checks) - len(state.trusted_skip)
        per_minute = self.cfg.virustotal.requests_per_minute
        limit = self.limiter.effective_daily_limit()
        remaining = self.limiter.remaining_today()
        distinct = plural(len(state.groups), "archivo distinto", "archivos distintos")
        if needed == 0:
            if state.groups:
                self._say(f"{distinct}, todo ya en caché: no hace falta consultar nada.")
            return
        self._say(
            f"{distinct}: {cached} ya en caché, {needed} por consultar "
            f"(unos {format_minutes(needed / per_minute)} a {per_minute} por minuto)."
        )
        days = math.ceil(max(0, needed - remaining) / limit)
        self._say(f"Cuota de hoy: quedan {remaining} de {limit}.")
        if needed > remaining:
            self._say(
                f"No cabe todo hoy: harán falta unos {days} día(s) más. La cuota se reinicia a las "
                f"{format_local_time(self.limiter.next_reset())} (hora local); continúa con --resume "
                "o usa --wait para que siga solo.",
                "warn",
            )
        if dry_run:
            self._say("Modo --dry-run: no se ha hecho ninguna consulta.", "ok")

    # ======================================================================
    # VirusTotal
    # ======================================================================

    def _pending_checks(self, state: _RunState, immediate: bool = True) -> dict[str, _Check]:
        """Análisis pendientes de subidas anteriores. Con immediate, se comprueban ya;
        si no, cuando toque según lo programado."""
        checks: dict[str, _Check] = {}
        now = self.clock()
        for record in self.db.pending_analyses():
            if record.sha256 in state.groups and record.analysis_id:
                next_at = now if immediate else (record.next_check_at or now)
                checks[record.sha256] = _Check(record.analysis_id, next_at, record.checks)
        return checks

    def _network_phase(
        self,
        client: VTClient,
        lookups: list[str],
        options: ScanOptions,
        scan_id: int,
        state: _RunState,
    ) -> bool:
        """Devuelve True si no queda nada pendiente de VirusTotal."""
        checks = self._pending_checks(state)
        self._estimate(lookups, state)
        needed = len(lookups) + len(checks)
        remaining = self.limiter.remaining_today()
        if options.all_files and needed > remaining:
            days = math.ceil(needed / self.limiter.effective_daily_limit())
            if not self.ui.confirm(
                f"Con --all-files hacen falta {needed} consultas (unos {days} días de cuota). ¿Seguir?",
                default=False,
            ):
                state.notes.append("Escaneo con --all-files cancelado antes de consultar VirusTotal.")
                return False

        queue = deque(lookups)
        if queue or checks:
            self._phase("VirusTotal")
            ok = self._process(client, queue, checks, deque(), options, state, wait_checks=False)
            if not ok:
                return False

        if options.upload:
            uploads = self._choose_uploads(scan_id, state)
            checks = self._pending_checks(state, immediate=False)
            if uploads or checks:
                self._phase("Subidas a VirusTotal")
                ok = self._process(client, deque(), checks, uploads, options, state, wait_checks=True)
                if not ok:
                    return False

        records = self.db.get_vt_records(state.groups.keys())
        pending = [
            sha
            for sha in state.groups
            if sha not in state.trusted_skip
            and (records.get(sha) is None or records[sha].state == "pending_analysis")
        ]
        return not pending

    def _process(
        self,
        client: VTClient,
        lookups: deque[str],
        checks: dict[str, _Check],
        uploads: deque[tuple[str, str, int]],
        options: ScanOptions,
        state: _RunState,
        wait_checks: bool,
    ) -> bool:
        """Bucle de trabajo: comprobaciones de análisis, consultas y subidas, una a una,
        siempre a través del limitador. Devuelve False si hay que parar (cuota o red)."""
        total = len(lookups) + len(checks) + len(uploads)
        done = 0
        description = "Subiendo y recogiendo resultados" if uploads or wait_checks else "Consultando VirusTotal"
        self.ui.task_start(description, total, unit="files")
        transient_in_a_row = 0
        max_checks = self.cfg.virustotal.analysis_max_checks_per_run
        try:
            while True:
                now = self.clock()
                due = [sha for sha, c in checks.items() if c.next_at <= now]
                if due:
                    kind, item = "check", min(due, key=lambda s: checks[s].next_at)
                elif uploads:
                    kind, item = "upload", uploads[0][0]
                elif lookups:
                    kind, item = "lookup", lookups[0]
                elif checks and wait_checks:
                    target = min(c.next_at for c in checks.values())
                    self.limiter.cooldown(
                        target - now, "esperando a que VirusTotal termine el análisis", self.ui.waiting
                    )
                    continue
                else:
                    return True
                try:
                    if kind == "check":
                        finished = self._do_check(client, item, checks[item])
                        if finished or checks[item].this_run >= max_checks or not wait_checks:
                            # Si no ha terminado, se recogerá en otra ejecución
                            del checks[item]
                            done += 1
                    elif kind == "upload":
                        sha, path, size = uploads[0]
                        analysis_id = self._do_upload(client, sha, path, size)
                        uploads.popleft()
                        done += 1
                        if analysis_id:
                            first = self.cfg.virustotal.analysis_first_check_seconds
                            checks[sha] = _Check(analysis_id, self.clock() + first, 0)
                            total += 1
                    else:
                        self._do_lookup(client, item)
                        lookups.popleft()
                        done += 1
                    transient_in_a_row = 0
                except DailyQuotaExceeded:
                    if options.wait:
                        self._wait_for_reset()
                        continue
                    reset = format_local_time(self.limiter.next_reset())
                    self._end()
                    self._say(
                        f"Cuota diaria agotada. Se ha guardado el progreso; continúa después de las "
                        f"{reset} (hora local) con: python vtscan.py --resume",
                        "warn",
                    )
                    state.notes.append(f"Cuota diaria agotada; la cuota se reinicia a las {reset}.")
                    return False
                except AuthError:
                    raise
                except TransientError as exc:
                    transient_in_a_row += 1
                    self._drop(item, kind, lookups, uploads, checks)
                    state.errors[item] = str(exc)
                    done += 1
                    log.warning("Error temporal con %s: %s", item, exc)
                    if transient_in_a_row >= 3:
                        self._end()
                        self._say(
                            f"No hay conexión estable con VirusTotal ({exc}). Lo pendiente se "
                            "reintentará en la próxima ejecución.",
                            "warn",
                        )
                        state.notes.append(f"Problemas de conexión con VirusTotal: {exc}")
                        return False
                except VTError as exc:
                    self._drop(item, kind, lookups, uploads, checks)
                    if kind == "upload":
                        self.db.remove_from_queue(item)
                    state.errors[item] = str(exc)
                    done += 1
                    log.warning("Error de VirusTotal con %s: %s", item, exc)
                self.ui.task_update(
                    completed=done,
                    total=total,
                    detail=f"peticiones: {self.limiter.requests_this_run} · quedan hoy: "
                    f"{self.limiter.remaining_today()}",
                )
        finally:
            self._end()

    @staticmethod
    def _drop(
        item: str,
        kind: str,
        lookups: deque[str],
        uploads: deque[tuple[str, str, int]],
        checks: dict[str, _Check],
    ) -> None:
        if kind == "lookup" and lookups and lookups[0] == item:
            lookups.popleft()
        elif kind == "upload" and uploads and uploads[0][0] == item:
            uploads.popleft()
        elif kind == "check":
            checks.pop(item, None)

    def _store_report(self, report: FileReport, source: str) -> None:
        self.db.put_vt_found(
            report.sha256, report.malicious, report.suspicious, report.total, report.to_data(), source
        )

    def _do_lookup(self, client: VTClient, sha: str) -> None:
        report = client.get_file(sha)
        if report is None:
            self.db.put_vt_not_found(sha)
        else:
            report.sha256 = sha
            self._store_report(report, "lookup")

    def _do_check(self, client: VTClient, sha: str, check: _Check) -> bool:
        status = client.get_analysis(check.analysis_id, sha)
        report = status.report
        if status.status == "missing":
            report = client.get_file(sha)
        if report is not None:
            report.sha256 = sha
            self._store_report(report, "upload")
            return True
        check.checks += 1
        check.this_run += 1
        delay = CHECK_DELAYS[min(check.checks - 1, len(CHECK_DELAYS) - 1)]
        check.next_at = self.clock() + delay
        self.db.reschedule_pending(sha, check.next_at, check.checks)
        return False

    def _do_upload(self, client: VTClient, sha: str, path: str, size: int) -> str | None:
        try:
            st = os.stat(fs_path(path))
        except OSError:
            st = None
        if st is None or st.st_size != size:
            self.db.remove_from_queue(sha)
            self._say(f"No se sube {os.path.basename(path)}: el archivo ya no está o ha cambiado.", "warn")
            return None
        name = os.path.basename(path)
        self.ui.task_update(detail=f"subiendo {name} ({human_size(size)})")

        def progress(sent: int, total: int) -> None:
            pct = 100 * sent / total if total else 100
            self.ui.task_update(detail=f"subiendo {name}: {pct:.0f} %")

        analysis_id = client.upload_file(path, size, on_progress=progress)
        first = self.cfg.virustotal.analysis_first_check_seconds
        self.db.put_vt_pending(sha, analysis_id, self.clock() + first)
        self.db.remove_from_queue(sha)
        return analysis_id

    def _choose_uploads(self, scan_id: int, state: _RunState) -> deque[tuple[str, str, int]]:
        records = self.db.get_vt_records(state.groups.keys())
        queued = [q for q in self.db.queued_uploads() if q[0] in state.groups]
        if queued:
            if self.ui.confirm(
                f"Hay {len(queued)} subida(s) que confirmaste en una ejecución anterior. ¿Continuar con ellas?",
                default=True,
            ):
                pass
            else:
                for sha, _, _ in queued:
                    self.db.remove_from_queue(sha)
                queued = []
        queued_hashes = {q[0] for q in queued}
        unknown = [
            sha
            for sha, results in state.groups.items()
            if sha not in queued_hashes
            and records.get(sha) is not None
            and records[sha].state == "not_found"
        ]
        if unknown:
            unknown.sort(key=lambda sha: min(upload_priority(r) for r in state.groups[sha]))
            items: list[UploadItem] = []
            for number, sha in enumerate(unknown, start=1):
                r = state.groups[sha][0]
                signals = sorted(r.entry.signals)
                items.append(
                    UploadItem(
                        number,
                        r.entry.path,
                        r.entry.rel_path,
                        r.entry.size,
                        signature_text(r.sig_status, r.sig_signer),
                        signals,
                    )
                )
            big = self.cfg.virustotal.direct_upload_max_mb * 1024 * 1024
            cost = UploadCost(
                files=len(items),
                requests=sum(2 if i.size > big else 1 for i in items),
                total_bytes=sum(i.size for i in items),
                remaining_today=self.limiter.remaining_today(),
            )
            chosen = self.ui.select_uploads(items, cost)
            rows = [(unknown[n - 1], items[n - 1].path, items[n - 1].size) for n in chosen]
            self.db.queue_uploads(rows, scan_id)
            queued.extend(rows)
            if chosen:
                self._say(f"{len(chosen)} archivo(s) en cola para subir.", "ok")
            else:
                self._say("No se sube nada.")
        return deque(queued)

    def _wait_for_reset(self) -> None:
        target = self.limiter.next_reset() + 60
        self.ui.task_update(detail="")
        self._say(
            f"Cuota diaria agotada. Con --wait se continúa solo a las {format_local_time(target)} (hora local).",
            "warn",
        )
        allow_sleep()  # mientras se espera, el PC puede suspenderse
        try:
            self.limiter.cooldown(target - self.clock(), "esperando al reinicio de la cuota diaria", self.ui.waiting)
        finally:
            prevent_sleep()

    # ======================================================================
    # Informe
    # ======================================================================

    def _main_detections(self, report: FileReport) -> list[tuple[str, str]]:
        """Detecciones de los motores principales. Si ninguno lo detecta, las de
        quien sí lo detecte (hasta 3), para que se vea quién lo marca."""
        wanted = [e.lower() for e in self.cfg.report.main_engines]
        found = {name.lower(): (name, result) for name, (_, result) in report.detections.items()}
        main = [found[w] for w in wanted if w in found]
        if main or not report.detections:
            return main
        others = sorted(report.detections.items(), key=lambda kv: (kv[1][0] != "malicious", kv[0].lower()))
        return [(name, result) for name, (_, result) in others[:3]]

    def _vt_verdict(self, sha: str, record: VtRecord | None, state: _RunState) -> tuple[Verdict, FileReport | None, str]:
        if sha in state.trusted_skip:
            return Verdict(Level.SKIPPED, "Firmado por un fabricante de confianza; no consultado (skip_trusted_signed)"), None, "omitido"
        if record is None:
            if sha in state.errors:
                return Verdict(Level.PENDING, f"Error al consultar ({state.errors[sha]}); se reintentará"), None, "error"
            return Verdict(Level.PENDING, "Sin consultar todavía"), None, "pendiente"
        if record.state == "not_found":
            reason = "VirusTotal no conoce este archivo"
            if sha in state.errors:
                reason += f"; la subida falló ({state.errors[sha]})"
            return Verdict(Level.UNKNOWN, reason), None, "desconocido"
        if record.state == "pending_analysis":
            return Verdict(Level.PENDING, "Subido a VirusTotal; análisis en curso"), None, "analizando"
        report = FileReport.from_data(
            sha, record.malicious or 0, record.suspicious or 0, record.total or 0, record.data or {}
        )
        return self.classifier.classify_report(report), report, "analizado"

    def _build_rows(self, scan_id: int, state: _RunState) -> list[ReportRow]:
        rows: list[ReportRow] = []
        if state.walk is None:
            return rows
        root = state.walk.root
        defender_map = state.defender.threat_by_path() if state.defender and state.defender.ok else {}
        used_defender: set[str] = set()
        records = self.db.get_vt_records(state.groups.keys())
        trusted = self.cfg.signatures.trusted_publishers
        seen_paths: set[str] = set()

        def defender_verdict(path: str) -> Verdict | None:
            key = path_key(path)
            name = defender_map.get(key)
            if name:
                used_defender.add(key)
                return classify_defender(name)
            return None

        hashed_paths = {r.entry.path for r in state.hashes}
        for r in state.hashes:
            e = r.entry
            seen_paths.add(path_key(e.path))
            signals = sorted(e.signals)
            if r.sig_status == STATUS_TAMPERED:
                signals.append("sig_tampered")
            elif r.sig_status == STATUS_UNTRUSTED:
                signals.append("sig_untrusted")
            elif is_trusted(r.sig_signer, r.sig_status, trusted):
                signals.append("trusted")
            row = ReportRow(
                level=Level.PENDING,
                reason="",
                label="",
                path=e.path,
                rel_path=e.rel_path,
                state="",
                sha256=r.sha256,
                size=e.size,
                signature=signature_text(r.sig_status, r.sig_signer),
                signals=signals,
            )
            dv = defender_verdict(e.path)
            if r.sha256 is None:
                if r.defender_blocked:
                    verdict = combine([defender_blocked_verdict(), dv])
                    row.state = "bloqueado por Defender"
                else:
                    verdict = combine([Verdict(Level.SKIPPED, f"No se pudo leer: {r.error}"), dv])
                    row.state = "error"
            else:
                vt_verdict, report, row.state = self._vt_verdict(r.sha256, records.get(r.sha256), state)
                verdict = combine([vt_verdict, dv])
                if report is not None:
                    row.malicious, row.suspicious, row.total = report.malicious, report.suspicious, report.total
                    row.main_detections = self._main_detections(report)
                    row.detections_count = len(report.detections)
                    row.first_seen = report.first_submission_date
                    row.last_analysis = report.last_analysis_date
                if records.get(r.sha256) is not None and records[r.sha256].state != "not_found":
                    row.vt_link = gui_url(r.sha256)
            row.level, row.reason, row.label = verdict.level, verdict.reason, verdict.label
            rows.append(row)

        # Archivos detectados pero sin hash (recorrido interrumpido o sin procesar)
        for e in state.walk.files:
            if e.path not in hashed_paths:
                seen_paths.add(path_key(e.path))
                rows.append(
                    ReportRow(
                        Level.PENDING, "Sin procesar (escaneo interrumpido)", "", e.path, e.rel_path,
                        "pendiente", size=e.size, signals=sorted(e.signals),
                    )
                )

        skipped_text = {
            "too_large": f"Más de {self.cfg.scan.max_file_size_mb} MB: VirusTotal no admite archivos tan grandes",
            "cloud": "Archivo en la nube sin descargar (no se lee para no descargarlo)",
        }
        for s in state.walk.skipped:
            seen_paths.add(path_key(s.path))
            dv = defender_verdict(s.path)
            if s.reason == "defender_blocked":
                verdict = combine([defender_blocked_verdict(), dv])
                state_text = "bloqueado por Defender"
            else:
                text = skipped_text.get(s.reason) or f"Sin acceso: {s.detail or s.reason}"
                verdict = combine([Verdict(Level.SKIPPED, text), dv])
                state_text = "omitido"
            rows.append(
                ReportRow(verdict.level, verdict.reason, verdict.label, s.path, s.rel_path, state_text, size=s.size)
            )

        # Archivos que Defender bloqueó en ejecuciones anteriores y ya no están (cuarentena)
        for path, kind, _ in self.db.events_for_scan(scan_id):
            if kind != "defender_blocked" or path_key(path) in seen_paths:
                continue
            seen_paths.add(path_key(path))
            verdict = combine([defender_blocked_verdict(), defender_verdict(path)])
            rows.append(
                ReportRow(
                    verdict.level,
                    verdict.reason + "; ya no está en la carpeta (probablemente en cuarentena)",
                    verdict.label,
                    path,
                    os.path.relpath(path, root) if path_key(path).startswith(path_key(root)) else path,
                    "bloqueado por Defender",
                )
            )

        # Lo que Defender encontró y no está entre los archivos analizados (p. ej. dentro de un comprimido)
        if state.defender and state.defender.ok:
            extra: dict[str, tuple[str, str, list[str]]] = {}
            for threat in state.defender.threats:
                for resource in threat.resources:
                    path, _, inner = resource.partition("->")
                    path, inner = path.strip(), inner.strip()
                    key = path_key(path)
                    if key in used_defender:
                        continue
                    name, _, inners = extra.setdefault(key, (threat.name, path, []))
                    if inner and inner not in inners:
                        inners.append(inner)
            for key, (name, path, inners) in extra.items():
                verdict = classify_defender(name)
                reason = verdict.reason
                if inners:
                    reason += f" (dentro del comprimido: {', '.join(inners)})"
                rel = os.path.relpath(path, root) if key.startswith(path_key(root)) else path
                rows.append(ReportRow(verdict.level, reason, verdict.label, path, rel, "detectado por Defender"))
        return rows

    def _summary(
        self,
        target: str,
        started: float,
        options: ScanOptions,
        state: _RunState,
        rows: list[ReportRow],
        complete: bool,
        pending: int,
    ) -> ReportSummary:
        walk = state.walk
        defender = state.defender.to_dict() if state.defender else None
        used = None if options.dry_run else self.limiter.used_today()
        return ReportSummary(
            root=target,
            started_at=started,
            finished_at=self.clock(),
            options=options.labels(),
            complete=complete,
            files_seen=walk.files_seen if walk else 0,
            bytes_seen=walk.bytes_seen if walk else 0,
            candidates=len(walk.files) if walk else 0,
            unique_hashes=len(state.groups),
            requests_this_run=self.limiter.requests_this_run,
            used_today=used,
            daily_limit=self.limiter.effective_daily_limit(),
            reset_local=None if complete else format_local_time(self.limiter.next_reset()),
            pending=pending,
            defender=defender,
            notes=state.notes,
            dry_run=options.dry_run,
        )

    def _write_reports(self, target: str, rows: list[ReportRow], summary: ReportSummary) -> tuple[Path, Path]:
        base = report_basename(target, summary.finished_at)
        out_dir = self.cfg.reports_path
        html_path = out_dir / f"{base}.html"
        csv_path = out_dir / f"{base}.csv"
        write_html(rows, summary, html_path)
        write_csv(rows, csv_path, self.cfg.report.csv_delimiter)
        return html_path, csv_path
