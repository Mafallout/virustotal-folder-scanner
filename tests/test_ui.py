import io
from pathlib import Path

from rich.console import Console

from vtscanner.report import ReportRow, ReportSummary
from vtscanner.ui import ConsoleUI, UploadCost, UploadItem
from vtscanner.verdict import Level

BRACKETS = "Programa [Edición 2024]\\[beta]\\App.exe"


def make_ui():
    out = io.StringIO()
    console = Console(file=out, width=200, color_system=None, force_terminal=False)
    return ConsoleUI(console, interactive=False), out


def test_paths_with_brackets_are_shown_literally():
    ui, out = make_ui()
    rows = [
        ReportRow(Level.CRITICAL, "VT: [raro] 12 de 70", "x", "D:\\" + BRACKETS, BRACKETS, "analizado", total=70, malicious=12),
        ReportRow(Level.UNKNOWN, "VirusTotal no conoce este archivo", "", "D:\\a.dat", "a.dat", "x", signals=["disguised"]),
        ReportRow(Level.UNKNOWN, "VirusTotal no conoce este archivo", "", "D:\\b.bat", "b.bat", "x"),
    ]
    summary = ReportSummary("D:\\", 0, 0, [], True, 3, 0, 3, 3, 0)
    ui.show_summary(rows, summary, [Path("D:\\reports\\[x].html")])
    text = out.getvalue()
    assert BRACKETS in text
    assert "[raro]" in text
    assert "a.dat" in text  # desconocido con señal de riesgo: se muestra
    assert "b.bat" not in text  # desconocido sin señales: solo en el informe
    assert "[x].html" in text


def test_upload_list_with_brackets_and_no_terminal():
    ui, out = make_ui()
    items = [UploadItem(1, "D:\\" + BRACKETS, BRACKETS, 1234, "sin firma", ["hidden"])]
    chosen = ui.select_uploads(items, UploadCost(1, 1, 1234, 500))
    assert chosen == []  # sin terminal interactiva nunca se sube nada
    assert BRACKETS in out.getvalue()


def test_live_results_only_show_what_matters():
    ui, out = make_ui()
    ui.result("Programa [beta]\\bueno.dll", Level.CLEAN, "VT: 0 de 70")
    ui.result("voz.dll", Level.LOW, "probable falso positivo")
    ui.result("Programa [beta]\\malo.exe", Level.HIGH, "VT: 5 de 70 motores lo detectan")
    text = out.getvalue()
    assert "Alto: Programa [beta]\\malo.exe" in text
    assert "bueno.dll" not in text and "voz.dll" not in text


def test_progress_detail_with_brackets():
    ui, _ = make_ui()
    ui.task_start("Subiendo", 1, unit="files")
    ui.task_update(completed=0, detail="subiendo [beta] App.exe")
    ui.waiting(75, "límite de 4 peticiones por minuto")
    ui.task_end("hecho")
