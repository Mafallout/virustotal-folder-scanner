"""Detener un análisis (botón Detener de la ventana) y avisos en vivo."""

import threading

from conftest import MZ, write
from fakes import Factory, RecordingUI, make_scanner
from vtscanner import hashing
from vtscanner.pipeline import ScanOptions
from vtscanner.verdict import Level


def make_folder(tmp_path, n=3):
    folder = tmp_path / "juego"
    for i in range(n):
        write(folder / f"f{i}.exe", MZ + bytes([i]))
    return folder


def assert_partial(outcome, db):
    assert outcome.interrupted and not outcome.complete
    assert db.get_scan(outcome.scan_id).status == "interrupted"
    assert outcome.report_html.exists()


def test_cancel_while_waiting_for_rate_limit(tmp_path, cfg, db, clock):
    cfg.virustotal.requests_per_minute = 1
    folder = make_folder(tmp_path)
    cancel = threading.Event()
    # Tras la primera consulta se pide detener: la espera del límite por minuto se corta
    factory = Factory(after_call=lambda calls: cancel.set() if calls.count("files") == 1 else None)
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, factory, cancel_event=cancel).run(ScanOptions(target=str(folder)))
    assert_partial(outcome, db)
    assert factory.calls.count("files") == 1
    assert sum(1 for r in ui.summary[0] if r.level == Level.PENDING) == 2
    assert "Interrumpido" in ui.text()


def test_cancel_during_hashing(tmp_path, cfg, db, clock, monkeypatch):
    folder = make_folder(tmp_path)
    cancel = threading.Event()
    real = hashing.sha256_of_file

    def hash_and_cancel(path, stop=None):
        cancel.set()
        return real(path, stop)

    monkeypatch.setattr(hashing, "sha256_of_file", hash_and_cancel)
    factory = Factory()
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, factory, cancel_event=cancel).run(ScanOptions(target=str(folder)))
    assert_partial(outcome, db)
    assert "files" not in factory.calls  # no llegó a consultar nada


def test_cancel_during_defender(tmp_path, cfg, db, clock):
    folder = make_folder(tmp_path)
    cancel = threading.Event()

    def defender(target, report_only=True, on_tick=None):
        cancel.set()
        on_tick(1.0)  # el bucle que espera a MpCmdRun comprueba la cancelación
        raise AssertionError("no debería seguir")

    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, Factory(), defender_runner=defender, cancel_event=cancel).run(
        ScanOptions(target=str(folder), defender=True)
    )
    assert_partial(outcome, db)


def test_live_hooks(tmp_path, cfg, db, clock):
    folder = make_folder(tmp_path, 2)
    write(folder / "copia" / "f0.exe", MZ + bytes([0]))
    ui = RecordingUI()
    make_scanner(cfg, db, clock, ui, Factory()).run(ScanOptions(target=str(folder)))
    assert ui.estimates == [(2, 500, 0.5)]
    assert [level for _, level, _ in ui.results] == [Level.UNKNOWN, Level.UNKNOWN]
    assert any("(y 1 copia(s))" in path for path, _, _ in ui.results)
    assert ui.quotas[-1] == (2, 500)  # consultar la cuota no cuenta
