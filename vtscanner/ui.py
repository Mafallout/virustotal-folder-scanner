"""Interfaz entre el núcleo y el usuario. BaseUI define lo que el núcleo necesita
(mensajes, progreso, esperas y confirmaciones); ConsoleUI lo muestra en la
terminal con rich. Una interfaz gráfica futura solo tendría que heredar de BaseUI."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .report import SIGNAL_LABELS, ReportRow, ReportSummary, engines_text, human_size, plural, sort_key
from .verdict import LEVEL_ORDER, Level


@dataclass
class UploadItem:
    number: int  # número que ve el usuario (empieza en 1)
    path: str
    rel_path: str
    size: int
    signature: str
    signals: list[str] = field(default_factory=list)


@dataclass
class UploadCost:
    files: int
    requests: int  # subidas (+ peticiones de URL para los grandes)
    total_bytes: int
    remaining_today: int


class BaseUI:
    """Interfaz mínima. Por defecto no muestra nada y responde que no a todo."""

    def message(self, text: str, kind: str = "info") -> None:
        """kind: info | ok | warn | error."""

    def phase(self, title: str) -> None:
        pass

    def task_start(self, description: str, total: float | None = None, unit: str = "") -> None:
        """unit: bytes | files | ''."""

    def task_update(
        self, completed: float | None = None, total: float | None = None, detail: str | None = None
    ) -> None:
        pass

    def task_end(self, summary: str | None = None) -> None:
        pass

    def waiting(self, seconds_left: float, reason: str) -> None:
        pass

    def quota(self, used: int, limit: int) -> None:
        """Consultas gastadas hoy y límite diario, tras cada petición."""

    def estimate(self, needed: int, remaining: int, minutes: float) -> None:
        """Consultas que hacen falta, las que quedan hoy y el tiempo aproximado."""

    def result(self, rel_path: str, level: Level, reason: str, engines: list[str]) -> None:
        """Resultado de un archivo recién consultado (en vivo) y los motores que lo detectan."""

    def confirm(self, question: str, default: bool = False) -> bool:
        return default

    def select_uploads(self, items: list[UploadItem], cost: UploadCost) -> list[int]:
        """Devuelve los números (1..n) elegidos."""
        return []

    def show_summary(
        self, rows: list[ReportRow], summary: ReportSummary, report_paths: list[Path]
    ) -> None:
        pass


def parse_selection(text: str, count: int) -> list[int] | None:
    """'t' = todos, 'n' o vacío = ninguno, '1,3,5-8' = esos. None si no es válido."""
    text = text.strip().lower()
    if text in ("", "n", "ninguno", "no"):
        return []
    if text in ("t", "todos", "todo", "s", "si", "sí"):
        return list(range(1, count + 1))
    chosen: set[int] = set()
    for part in re.split(r"[,\s]+", text):
        if not part:
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            return None
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start > end or start < 1 or end > count:
            return None
        chosen.update(range(start, end + 1))
    return sorted(chosen)


class _SiNo(Confirm):
    choices = ["s", "n"]
    validate_error_message = "[prompt.invalid]Responde s o n"


LEVEL_STYLES = {
    Level.CRITICAL: "bold white on red3",
    Level.HIGH: "bold dark_orange",
    Level.MEDIUM: "bold yellow3",
    Level.LOW: "khaki3",
    Level.UNKNOWN: "steel_blue1",
    Level.PENDING: "grey62",
    Level.CLEAN: "green3",
    Level.SKIPPED: "grey50",
}

# Señales por las que un archivo desconocido merece salir en el resumen de consola
RISKY_SIGNALS = {"disguised", "double_ext", "rtlo", "hidden", "sig_tampered", "sig_untrusted"}

_KIND_STYLE = {
    "info": ("", ""),
    "ok": ("green3", "✓ "),
    "warn": ("yellow3", "! "),
    "error": ("bold red", "X "),
}


class ConsoleUI(BaseUI):
    def __init__(self, console: Console | None = None, interactive: bool | None = None) -> None:
        self.console = console or Console(highlight=False)
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self._progress: Progress | None = None
        self._task: TaskID | None = None
        self._auto_task = False

    # ---- mensajes -----------------------------------------------------------

    def _clear_auto(self) -> None:
        if self._auto_task:
            self._auto_task = False
            self.task_end()

    def message(self, text: str, kind: str = "info") -> None:
        self._clear_auto()
        style, prefix = _KIND_STYLE.get(kind, ("", ""))
        target = self._progress.console if self._progress else self.console
        target.print(f"{prefix}{text}", style=style or None, markup=False)

    def phase(self, title: str) -> None:
        self._clear_auto()
        self.console.rule(f"[bold]{title}", align="left", style="grey37")

    # ---- progreso -----------------------------------------------------------

    def task_start(self, description: str, total: float | None = None, unit: str = "") -> None:
        self._clear_auto()
        self.task_end()
        amount = DownloadColumn() if unit == "bytes" else MofNCompleteColumn()
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=28),
            amount,
            TimeRemainingColumn(compact=True, elapsed_when_finished=True),
            TextColumn("[grey62]{task.fields[detail]}"),
            console=self.console,
            transient=True,
        )
        self._progress.start()
        self._task = self._progress.add_task(description, total=total, detail="")

    def task_update(
        self, completed: float | None = None, total: float | None = None, detail: str | None = None
    ) -> None:
        if self._progress is None or self._task is None:
            return
        kwargs: dict[str, object] = {}
        if completed is not None:
            kwargs["completed"] = completed
        if total is not None:
            kwargs["total"] = total
        if detail is not None:
            # Los nombres de archivo pueden llevar corchetes ("Programa [v2.1]")
            kwargs["detail"] = escape(detail)
        self._progress.update(self._task, **kwargs)  # type: ignore[arg-type]

    def task_end(self, summary: str | None = None) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._task = None
        if summary:
            self.console.print(f"  {summary}", markup=False)

    def waiting(self, seconds_left: float, reason: str) -> None:
        text = f"{reason}: {seconds_left:.0f} s"
        if seconds_left >= 3600:
            hours, rest = divmod(int(seconds_left), 3600)
            text = f"{reason}: {hours} h {rest // 60:02d} min"
        elif seconds_left >= 120:
            text = f"{reason}: {int(seconds_left) // 60} min {int(seconds_left) % 60:02d} s"
        if self._progress is None:
            self.task_start("Esperando", None)
            self._auto_task = True
        self.task_update(detail=text)

    def result(self, rel_path: str, level: Level, reason: str, engines: list[str]) -> None:
        """En la terminal solo se avisa en vivo de lo que merece atención."""
        if level < Level.MEDIUM:
            return
        if engines:
            reason += f" ({engines_text(engines)})"
        target = self._progress.console if self._progress else self.console
        target.print(
            Text.assemble((f"{level.label}: ", LEVEL_STYLES[level]), rel_path, (f"  {reason}", "grey62"))
        )

    # ---- preguntas ----------------------------------------------------------

    def _pause_progress(self) -> None:
        if self._progress is not None:
            self._progress.stop()

    def _resume_progress(self) -> None:
        if self._progress is not None:
            self._progress.start()

    def confirm(self, question: str, default: bool = False) -> bool:
        self._clear_auto()
        if not self.interactive:
            self.message(f"{question} -> {'sí' if default else 'no'} (sin terminal interactiva)", "warn")
            return default
        self._pause_progress()
        try:
            return _SiNo.ask(Text(question), default=default, console=self.console, show_default=True)
        finally:
            self._resume_progress()

    def select_uploads(self, items: list[UploadItem], cost: UploadCost) -> list[int]:
        self._clear_auto()
        self._pause_progress()
        try:
            table = Table(title=f"Archivos que VirusTotal no conoce ({len(items)})", title_justify="left")
            table.add_column("#", justify="right")
            table.add_column("Tamaño", justify="right")
            table.add_column("Firma")
            table.add_column("Señales")
            table.add_column("Ruta", overflow="fold")
            for item in items:
                table.add_row(
                    str(item.number),
                    human_size(item.size),
                    Text(item.signature),
                    ", ".join(SIGNAL_LABELS.get(s, s) for s in item.signals),
                    Text(item.rel_path),
                )
            self.console.print(table)
            self.console.print(
                f"Subir todos: {plural(cost.files, 'archivo')}, {human_size(cost.total_bytes)}, "
                f"{plural(cost.requests, 'petición', 'peticiones')} más la recogida de resultados. "
                f"Quedan {cost.remaining_today} hoy.",
                markup=False,
            )
            self.console.print(
                "Aviso: lo que subes queda disponible para la comunidad de VirusTotal "
                "(investigadores y clientes de pago pueden descargarlo). No subas archivos personales.",
                style="yellow3",
                markup=False,
            )
            if not self.interactive:
                self.message("Sin terminal interactiva: no se sube nada.", "warn")
                return []
            while True:
                answer = Prompt.ask(
                    Text("¿Qué subo? [t]odos, [n]inguno o una lista (ej. 1,3,5-8)"),
                    default="n",
                    console=self.console,
                    show_default=True,
                )
                selection = parse_selection(answer, len(items))
                if selection is not None:
                    return selection
                self.console.print("No lo entiendo. Escribe t, n o números como 1,3,5-8.", style="red")
        finally:
            self._resume_progress()

    # ---- resumen final ------------------------------------------------------

    def show_summary(
        self, rows: list[ReportRow], summary: ReportSummary, report_paths: list[Path]
    ) -> None:
        self._clear_auto()
        self.task_end()
        self.console.rule("[bold]Resultado", align="left", style="grey37")
        counts = {level: 0 for level in LEVEL_ORDER}
        for row in rows:
            counts[row.level] += 1
        parts = [
            f"[{LEVEL_STYLES[level]}]{level.label} {counts[level]}[/]" for level in LEVEL_ORDER if counts[level]
        ]
        self.console.print("  " + "  ·  ".join(parts) if parts else "  No hay archivos que mostrar.")

        notable = [
            r
            for r in sorted(rows, key=sort_key)
            if r.level >= Level.LOW or (r.level == Level.UNKNOWN and RISKY_SIGNALS & set(r.signals))
        ]
        if notable:
            table = Table(show_edge=False, pad_edge=False, box=None, padding=(0, 2, 0, 0))
            table.add_column("Nivel")
            table.add_column("Det.", justify="right")
            table.add_column("Archivo", overflow="fold")
            table.add_column("Motivo", overflow="fold")
            for row in notable[:15]:
                det = f"{row.malicious}/{row.total}" if row.total is not None else "-"
                table.add_row(
                    Text(row.level.label, style=LEVEL_STYLES[row.level]),
                    det,
                    Text(row.rel_path),
                    Text(row.reason),
                )
            self.console.print()
            self.console.print(table)
            if len(notable) > 15:
                self.console.print(f"  ... y {len(notable) - 15} más en el informe.", style="grey62")
        self.console.print()
        for path in report_paths:
            self.console.print(f"  Informe: [link={path.as_uri()}]{escape(str(path))}[/link]")
        if summary.dry_run:
            if summary.pending:
                self.console.print(
                    f"\n  Simulación: {summary.pending} archivo(s) sin consultar. "
                    "Ejecuta el mismo comando sin --dry-run para analizarlos.",
                    style="grey62",
                    markup=False,
                )
        elif not summary.complete:
            when = f" La cuota se reinicia a las {summary.reset_local} (hora local)." if summary.reset_local else ""
            self.console.print(
                f"\n  Quedan {summary.pending} archivo(s) pendientes. Continúa con: "
                f"python vtscan.py --resume{when}",
                style="yellow3",
                markup=False,
            )
