"""Puente entre el análisis (que corre en otro hilo) y la ventana.

QtUI implementa BaseUI emitiendo señales de Qt, que llegan a la ventana de forma
segura entre hilos. Cuando el análisis pregunta algo (confirmar o elegir qué
subir), el hilo espera hasta que la ventana responda o se pida detener."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal

from ..config import Config
from ..pipeline import ScanOptions, ScanOutcome, Scanner
from ..report import ReportRow, ReportSummary
from ..ui import BaseUI, UploadCost, UploadItem
from ..verdict import Level
from ..vtclient import AuthError
from ..winutils import AlreadyRunningError, SingleInstanceLock, keep_awake

log = logging.getLogger(__name__)

PROGRESS_INTERVAL = 0.05  # como mucho unas 20 actualizaciones de progreso por segundo


class QtUI(QObject, BaseUI):
    message_sig = Signal(str, str)
    phase_sig = Signal(str)
    task_started = Signal(str, object, str)
    task_progress = Signal(object, object, object)
    task_ended = Signal(object)
    waiting_sig = Signal(float, str)
    quota_sig = Signal(int, int)
    estimate_sig = Signal(int, int, float)
    result_sig = Signal(str, object, str)
    summary_sig = Signal(object, object, object)
    confirm_requested = Signal(str, bool)
    uploads_requested = Signal(object, object)

    def __init__(self, cancel_event: threading.Event) -> None:
        QObject.__init__(self)
        self.cancel_event = cancel_event
        self._answered = threading.Event()
        self._answer: Any = None
        self._last_progress = 0.0

    # ---- lo que el análisis cuenta (se llama desde su hilo) -----------------

    def message(self, text: str, kind: str = "info") -> None:
        self.message_sig.emit(text, kind)

    def phase(self, title: str) -> None:
        self.phase_sig.emit(title)

    def task_start(self, description: str, total: float | None = None, unit: str = "") -> None:
        self._last_progress = 0.0
        self.task_started.emit(description, total, unit)

    def task_update(
        self, completed: float | None = None, total: float | None = None, detail: str | None = None
    ) -> None:
        now = time.monotonic()
        if detail is None and total is None and now - self._last_progress < PROGRESS_INTERVAL:
            return
        self._last_progress = now
        self.task_progress.emit(completed, total, detail)

    def task_end(self, summary: str | None = None) -> None:
        self.task_ended.emit(summary)

    def waiting(self, seconds_left: float, reason: str) -> None:
        self.waiting_sig.emit(seconds_left, reason)

    def quota(self, used: int, limit: int) -> None:
        self.quota_sig.emit(used, limit)

    def estimate(self, needed: int, remaining: int, minutes: float) -> None:
        self.estimate_sig.emit(needed, remaining, minutes)

    def result(self, rel_path: str, level: Level, reason: str) -> None:
        self.result_sig.emit(rel_path, level, reason)

    def show_summary(self, rows: list[ReportRow], summary: ReportSummary, report_paths: list[Path]) -> None:
        self.summary_sig.emit(rows, summary, report_paths)

    # ---- preguntas: el hilo del análisis espera la respuesta de la ventana --

    def confirm(self, question: str, default: bool = False) -> bool:
        return bool(self._ask(lambda: self.confirm_requested.emit(question, default), default))

    def select_uploads(self, items: list[UploadItem], cost: UploadCost) -> list[int]:
        return list(self._ask(lambda: self.uploads_requested.emit(items, cost), []))

    def _ask(self, emit: Callable[[], None], default: Any) -> Any:
        if self.cancel_event.is_set():
            return default
        self._answered.clear()
        self._answer = default
        emit()
        while not self._answered.wait(0.2):
            if self.cancel_event.is_set():
                return default
        return self._answer

    def answer(self, value: Any) -> None:
        """La ventana responde (desde su hilo)."""
        self._answer = value
        self._answered.set()


class ScanWorker(QThread):
    """Ejecuta un análisis completo en segundo plano."""

    finished_ok = Signal(object)  # ScanOutcome
    failed = Signal(str, str)  # tipo (busy | auth | error) y mensaje

    def __init__(
        self,
        cfg: Config,
        api_key: str | None,
        options: ScanOptions,
        resume_id: int | None = None,
        scanner_kwargs: dict[str, Any] | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.cfg = cfg
        self.api_key = api_key
        self.options = options
        self.resume_id = resume_id
        self.scanner_kwargs = scanner_kwargs or {}
        self.cancel_event = threading.Event()
        self.ui = QtUI(self.cancel_event)

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        lock = SingleInstanceLock(self.cfg.lock_path)
        try:
            lock.acquire()
        except AlreadyRunningError:
            self.failed.emit("busy", "Ya hay otro análisis en marcha (¿quizá en la terminal?). Espera a que termine.")
            return
        try:
            # Evitar la suspensión funciona por hilo: se activa aquí, no en la ventana
            with keep_awake():
                scanner = Scanner(
                    self.cfg, self.ui, self.api_key, cancel_event=self.cancel_event, **self.scanner_kwargs
                )
                try:
                    outcome: ScanOutcome = scanner.run(self.options, self.resume_id)
                finally:
                    scanner.db.close()
            self.finished_ok.emit(outcome)
        except AuthError as exc:
            self.failed.emit("auth", f"VirusTotal rechaza la clave ({exc}).")
        except Exception as exc:  # noqa: BLE001 - cualquier fallo se muestra en la ventana
            log.exception("Error inesperado en el análisis")
            self.failed.emit("error", f"{type(exc).__name__}: {exc}")
        finally:
            lock.release()
