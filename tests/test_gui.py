"""Pruebas de la ventana (pytest-qt, sin mostrarla en pantalla)."""

import threading
import time

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog

from conftest import MZ, write
from fakes import Factory, no_defender, sha_of
from vtscanner.gui import dialogs, main_window, theme
from vtscanner.gui.bridge import QtUI, ScanWorker
from vtscanner.gui.dialogs import ApiKeyDialog, UploadDialog
from vtscanner.gui.main_window import MainWindow, ProgressPage, format_wait, step_for
from vtscanner.gui.results import ResultsFilter, ResultsModel
from vtscanner.pipeline import ScanOptions
from vtscanner.report import ReportRow
from vtscanner.ui import UploadCost, UploadItem
from vtscanner.verdict import Level
from vtscanner.vtclient import FileReport

KEY = "ab" * 32


def report_row(level, rel, malicious=None):
    total = None if malicious is None else 70
    return ReportRow(level, f"motivo de {rel}", "", f"C:\\r\\{rel}", rel, "x", malicious=malicious, total=total)


def two_file_folder(tmp_path):
    folder = tmp_path / "programa"
    clean = write(folder / "bin" / "a.dll", MZ + b"a")
    write(folder / "b.exe", MZ + b"b")
    return folder, {sha_of(clean): FileReport("", 0, 0, 70)}


def make_window(cfg, tmp_path, qtbot, factory):
    window = MainWindow(
        cfg,
        "clave",
        settings=QSettings(str(tmp_path / "ventana.ini"), QSettings.Format.IniFormat),
        scanner_kwargs={"client_factory": factory, "defender_runner": no_defender},
    )
    qtbot.addWidget(window)
    return window


# ---- piezas sueltas ----------------------------------------------------------


def test_results_sort_and_filter(qtbot):
    model = ResultsModel(
        [
            report_row(Level.CLEAN, "b.dll", 0),
            report_row(Level.CRITICAL, "a.exe", 30),
            report_row(Level.HIGH, "c.exe", 5),
            report_row(Level.HIGH, "d.exe", 9),
        ]
    )
    proxy = ResultsFilter()
    proxy.setSourceModel(model)
    proxy.sort(0, Qt.SortOrder.AscendingOrder)
    assert [proxy.index(r, 1).data() for r in range(proxy.rowCount())] == ["a.exe", "d.exe", "c.exe", "b.dll"]
    proxy.set_levels({Level.HIGH})
    assert proxy.rowCount() == 2
    proxy.set_levels(set(Level))
    proxy.set_text("C.EXE")
    assert proxy.rowCount() == 1


def test_results_name_the_engines(qtbot):
    row = report_row(Level.LOW, "voz.dll", 1)
    row.detected_by = [("Cynet", "Malicious (score: 100)")]
    model = ResultsModel([row, report_row(Level.CLEAN, "a.dll", 0)])
    assert model.index(0, 3).data() == "Cynet"
    assert model.index(0, 3).data(Qt.ItemDataRole.ToolTipRole) == "Cynet: Malicious (score: 100)"
    assert model.index(1, 3).data() == ""
    proxy = ResultsFilter()
    proxy.setSourceModel(model)
    proxy.set_text("cynet")
    assert proxy.rowCount() == 1


def test_live_list_puts_findings_on_top(qtbot):
    page = ProgressPage()
    qtbot.addWidget(page)
    page.reset(ScanOptions(target="C:\\juego"))
    page.on_result("a.dll", Level.CLEAN, "VT: 0 de 70", [])
    page.on_result("voz.dll", Level.LOW, "probable falso positivo", ["Cynet"])
    page.on_result("b.dll", Level.CLEAN, "VT: 0 de 70", [])
    page.on_result("malo.exe", Level.HIGH, "VT: 5 de 70", ["Kaspersky", "ESET-NOD32", "Avast", "Cynet"])
    texts = [page.findings.item(i).text() for i in range(page.findings.count())]
    assert texts == [
        "Alto   malo.exe   (detectado por Kaspersky, ESET-NOD32, Avast y 1 más)",
        "Bajo   voz.dll   (detectado por Cynet)",
        "Limpio   b.dll",
        "Limpio   a.dll",
    ]
    assert "Detectado por: Kaspersky, ESET-NOD32, Avast, Cynet" in page.findings.item(0).toolTip()
    assert page.counter_labels[Level.CLEAN].text() == "Limpio 2"


def test_upload_dialog_selection(qtbot):
    items = [
        UploadItem(1, "C:\\a.bat", "a.bat", 100, "", []),
        UploadItem(2, "C:\\b.exe", "b.exe", 50 * 1024 * 1024, "sin firma", ["hidden"]),
        UploadItem(3, "C:\\c.js", "c.js", 10, "", []),
    ]
    dialog = UploadDialog(items, UploadCost(3, 4, 0, 400), big_bytes=32 * 1024 * 1024)
    qtbot.addWidget(dialog)
    assert dialog.selected() == [] and not dialog.ok_button.isEnabled()  # nada marcado de serie
    dialog.table.item(0, 0).setCheckState(Qt.CheckState.Checked)
    dialog.table.item(1, 0).setCheckState(Qt.CheckState.Checked)
    assert dialog.selected() == [1, 2]
    assert "3 consultas" in dialog.summary.text()  # el grande necesita 2
    assert dialog.ok_button.isEnabled()


def test_upload_dialog_marks_hundreds_quickly(qtbot):
    items = [UploadItem(i + 1, f"C:\\x\\f{i}.exe", f"f{i}.exe", 1000, "sin firma", []) for i in range(400)]
    dialog = UploadDialog(items, UploadCost(400, 400, 400_000, 500), big_bytes=32 * 1024 * 1024)
    qtbot.addWidget(dialog)
    started = time.perf_counter()
    dialog._set_all(True)
    assert time.perf_counter() - started < 2  # antes, más de un minuto y medio
    assert len(dialog.selected()) == 400 and "400 archivos" in dialog.summary.text()


def test_api_key_dialog_validates_and_saves(qtbot, no_api_key, monkeypatch):
    monkeypatch.setattr(dialogs.vtclient, "check_api_key", lambda key: True)
    dialog = ApiKeyDialog()
    qtbot.addWidget(dialog)
    dialog.edit.setText("corta")
    dialog.accept()
    assert "64" in dialog.status.text() and dialog.key == ""
    dialog.edit.setText(KEY)
    dialog.accept()
    assert dialog.key == KEY
    assert (no_api_key / ".env").read_text(encoding="utf-8") == f"VT_API_KEY={KEY}\n"


def test_api_key_dialog_rejected_key(qtbot, no_api_key, monkeypatch):
    monkeypatch.setattr(dialogs.vtclient, "check_api_key", lambda key: False)
    dialog = ApiKeyDialog()
    qtbot.addWidget(dialog)
    dialog.edit.setText(KEY)
    dialog.accept()
    assert "rechaza" in dialog.status.text()
    assert not (no_api_key / ".env").exists()


def test_question_waits_for_the_window(qtbot):
    ui = QtUI(threading.Event())
    ui.confirm_requested.connect(lambda question, default: ui.answer(True))
    result = []
    thread = threading.Thread(target=lambda: result.append(ui.confirm("¿Seguir?", False)))
    thread.start()
    # La respuesta llega por el bucle de eventos de la ventana: hay que dejarlo correr
    qtbot.waitUntil(lambda: bool(result), timeout=3000)
    thread.join(3)
    assert result == [True]


def test_question_gives_up_when_cancelled(qtbot):
    cancel = threading.Event()
    ui = QtUI(cancel)
    result = []
    thread = threading.Thread(target=lambda: result.append(ui.select_uploads([], None)))
    thread.start()
    cancel.set()
    thread.join(3)
    assert result == [[]]


def test_helpers():
    assert step_for("Calculando SHA-256") == "hash"
    assert step_for("Subidas a VirusTotal") == "upload"
    assert step_for("Consultando VirusTotal") == "vt"
    assert step_for("Analizando con Defender (solo informe)") == "defender"
    assert format_wait(9) == "9 s"
    assert format_wait(125) == "2 min 05 s"
    assert format_wait(3 * 3600 + 600) == "3 h 10 min"


def test_icon(qtbot, tmp_path):
    assert not theme.app_icon().isNull()
    assert theme.save_ico(tmp_path / "vtscan.ico")
    assert (tmp_path / "vtscan.ico").stat().st_size > 0


# ---- análisis en segundo plano -----------------------------------------------


def test_worker_runs_a_scan(qtbot, cfg, tmp_path):
    folder, known = two_file_folder(tmp_path)
    worker = ScanWorker(
        cfg,
        "clave",
        ScanOptions(target=str(folder)),
        scanner_kwargs={"client_factory": Factory(known), "defender_runner": no_defender},
    )
    levels = []
    worker.ui.result_sig.connect(lambda rel, level, reason, engines: levels.append(level))
    with qtbot.waitSignal(worker.finished_ok, timeout=20000) as blocker:
        worker.start()
    assert blocker.args[0].complete
    assert sorted(levels) == [Level.CLEAN, Level.UNKNOWN]
    worker.wait(5000)


def test_worker_stops_while_waiting(qtbot, cfg, tmp_path):
    cfg.virustotal.requests_per_minute = 1
    folder, known = two_file_folder(tmp_path)
    worker = ScanWorker(
        cfg,
        "clave",
        ScanOptions(target=str(folder)),
        scanner_kwargs={"client_factory": Factory(known), "defender_runner": no_defender},
    )
    worker.ui.waiting_sig.connect(lambda seconds, reason: worker.cancel())  # Detener en plena espera
    with qtbot.waitSignal(worker.finished_ok, timeout=20000) as blocker:
        worker.start()
    assert blocker.args[0].interrupted
    worker.wait(5000)


# ---- la ventana completa -----------------------------------------------------


def test_window_analyzes_and_shows_results(qtbot, cfg, tmp_path):
    folder, known = two_file_folder(tmp_path)
    window = make_window(cfg, tmp_path, qtbot, Factory(known))
    window.start_page.drop.set_path(str(folder))
    window.start_page._update_buttons()
    window.start_page.defender.setChecked(False)
    qtbot.mouseClick(window.start_page.analyze, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.worker is None and window.stack.currentWidget() is window.results_page, timeout=20000)
    page = window.results_page
    assert page.model.rowCount() == 2 and page.proxy.rowCount() == 2
    assert page.chips[Level.CLEAN].text() == "Limpio 1"
    assert page.html_button.isEnabled()
    assert "completo" in page.status.text()


def test_window_estimate_only(qtbot, cfg, tmp_path):
    folder, known = two_file_folder(tmp_path)
    factory = Factory(known)
    window = make_window(cfg, tmp_path, qtbot, factory)
    window.start_page.drop.set_path(str(folder))
    window.start_page._update_buttons()
    qtbot.mouseClick(window.start_page.estimate_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.worker is None and not window.start_page.estimate_label.isHidden(), timeout=20000)
    assert "2 consultas" in window.start_page.estimate_label.text()
    assert factory.instances == []  # la simulación no se conecta
    assert window.start_page.resume_box.isHidden()  # ni deja un análisis "sin terminar"


def test_window_estimate_without_executables(qtbot, cfg, tmp_path):
    folder = tmp_path / "docs"
    write(folder / "leeme.txt", b"hola")
    window = make_window(cfg, tmp_path, qtbot, Factory())
    window.start_page.drop.set_path(str(folder))
    window.start_page._update_buttons()
    qtbot.mouseClick(window.start_page.estimate_button, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.worker is None and not window.start_page.estimate_label.isHidden(), timeout=20000)
    assert "No hay ejecutables" in window.start_page.estimate_label.text()


def test_window_upload_flow(qtbot, cfg, tmp_path, monkeypatch):
    cfg.virustotal.analysis_first_check_seconds = 0
    folder = tmp_path / "programa"
    write(folder / "instalar.bat", b"@echo off\r\necho unico\r\n")

    class AcceptFirst:
        def __init__(self, items, cost, big_bytes, parent=None):
            self.items = items

        def exec(self):
            return QDialog.DialogCode.Accepted

        def selected(self):
            return [1]

    monkeypatch.setattr(main_window, "UploadDialog", AcceptFirst)
    factory = Factory(analysis_rounds=1)
    window = make_window(cfg, tmp_path, qtbot, factory)
    window.start_page.drop.set_path(str(folder))
    window.start_page._update_buttons()
    window.start_page.defender.setChecked(False)
    window.start_page.upload.setChecked(True)
    qtbot.mouseClick(window.start_page.analyze, Qt.MouseButton.LeftButton)
    qtbot.waitUntil(lambda: window.worker is None and window.stack.currentWidget() is window.results_page, timeout=20000)
    assert factory.calls.count("upload") == 1
    (row,) = window.results_page.model.rows()
    assert row.level == Level.CLEAN
