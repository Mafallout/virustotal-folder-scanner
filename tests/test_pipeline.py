"""Pruebas del flujo completo con un VirusTotal simulado (sin red)."""

import hashlib
import os

import pytest

from conftest import MZ, write
from vtscanner import hashing, pipeline
from vtscanner.defender import DefenderResult, DefenderThreat
from vtscanner.pipeline import ScanOptions, Scanner
from vtscanner.ratelimit import next_reset
from vtscanner.signatures import SignatureInfo
from vtscanner.ui import BaseUI
from vtscanner.verdict import Level
from vtscanner.vtclient import AnalysisStatus, FileReport


def sha_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RecordingUI(BaseUI):
    def __init__(self, uploads=None, confirm=False):
        self.messages = []
        self.uploads = uploads or []
        self.confirm_answer = confirm
        self.upload_items = None
        self.summary = None

    def message(self, text, kind="info"):
        self.messages.append((kind, text))

    def task_end(self, summary=None):
        if summary:
            self.messages.append(("task", summary))

    def confirm(self, question, default=False):
        self.messages.append(("confirm", question))
        return self.confirm_answer

    def select_uploads(self, items, cost):
        self.upload_items = items
        return self.uploads

    def show_summary(self, rows, summary, report_paths):
        self.summary = (rows, summary, report_paths)

    def text(self):
        return "\n".join(t for _, t in self.messages)


class FakeVT:
    """Imita VTClient. Cada llamada pasa por el limitador real."""

    def __init__(self, limiter, known, analysis_rounds=2):
        self.limiter = limiter
        self.known = known
        self.analysis_rounds = analysis_rounds
        self.calls = []
        self.analysis_calls = {}

    def _hit(self, label):
        self.limiter.wait_for_slot()
        self.limiter.record(label, 200)
        self.calls.append(label)

    def get_user_quota(self):
        self._hit("users")
        return None

    def get_file(self, sha):
        self._hit("files")
        report = self.known.get(sha)
        if report is None:
            return None
        return FileReport(sha, report.malicious, report.suspicious, report.total, dict(report.detections))

    def upload_file(self, path, size, on_progress=None):
        self._hit("upload")
        with open(path, "rb") as f:
            return "an-" + hashlib.sha256(f.read()).hexdigest()

    def get_analysis(self, analysis_id, sha):
        self._hit("analyses")
        n = self.analysis_calls.get(sha, 0) + 1
        self.analysis_calls[sha] = n
        if n < self.analysis_rounds:
            return AnalysisStatus("queued")
        return AnalysisStatus("completed", FileReport(sha, 0, 0, 70))


class Factory:
    def __init__(self, known=None, analysis_rounds=2):
        self.known = known or {}
        self.analysis_rounds = analysis_rounds
        self.instances = []

    def __call__(self, api_key, limiter, cfg, on_wait=None):
        fake = FakeVT(limiter, self.known, self.analysis_rounds)
        self.instances.append(fake)
        return fake

    @property
    def calls(self):
        return self.instances[-1].calls


def make_scanner(cfg, db, clock, ui, factory, defender_runner=None):
    return Scanner(
        cfg,
        ui,
        "clave",
        db=db,
        client_factory=factory,
        clock=clock.time,
        sleeper=clock.sleep,
        defender_runner=defender_runner or (lambda *a, **k: DefenderResult(ok=True, found=0)),
    )


def make_game(folder):
    files = {
        "game": write(folder / "Game.exe", MZ + b"game"),
        "dll": write(folder / "bin" / "engine.dll", MZ + b"engine"),
        "dup": write(folder / "copia" / "Game.exe", MZ + b"game"),
        "bat": write(folder / "instalar.bat", b"@echo off\r\necho hola\r\n"),
        "txt": write(folder / "leeme.txt", b"texto"),
    }
    return files


def rows_by_name(ui):
    rows, _, _ = ui.summary
    return {os.path.basename(r.path) + ("@" + r.rel_path if "copia" in r.rel_path else ""): r for r in rows}


def test_first_run_queries_and_second_run_uses_cache(tmp_path, cfg, db, clock):
    folder = tmp_path / "juego"
    files = make_game(folder)
    known = {
        sha_of(files["game"]): FileReport("", 15, 0, 70, {f"E{i}": ("malicious", "HackTool:Win32/Crack") for i in range(15)}),
        sha_of(files["dll"]): FileReport("", 0, 0, 70),
    }
    factory = Factory(known)
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, factory).run(ScanOptions(target=str(folder)))
    assert factory.calls == ["users", "files", "files", "files"]  # 3 hashes distintos
    assert outcome.complete and outcome.findings
    assert outcome.report_html.exists() and outcome.report_csv.exists()
    rows = {r.rel_path: r for r in ui.summary[0]}
    assert rows["Game.exe"].level == Level.HIGH  # 15 motores, pero solo etiquetas de herramientas (HackTool)
    assert rows[os.path.join("copia", "Game.exe")].level == Level.HIGH  # duplicado, mismo veredicto
    assert rows[os.path.join("bin", "engine.dll")].level == Level.CLEAN
    assert rows["instalar.bat"].level == Level.UNKNOWN
    assert "leeme.txt" not in rows

    ui2 = RecordingUI()
    outcome2 = make_scanner(cfg, db, clock, ui2, factory).run(ScanOptions(target=str(folder)))
    assert factory.calls == ["users"]  # nada que consultar: todo en caché
    assert outcome2.complete
    assert "sin releer gracias a la caché" in ui2.text()


def test_quota_exhaustion_pauses_and_resume_continues(tmp_path, cfg, db, clock):
    cfg.virustotal.daily_limit = 4
    folder = tmp_path / "juego"
    for i in range(5):
        write(folder / f"f{i}.exe", MZ + bytes([i]))
    factory = Factory()
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, factory).run(ScanOptions(target=str(folder)))
    # Consultar la cuota (users) no gasta cuota diaria: caben 4 consultas
    assert factory.calls == ["users", "files", "files", "files", "files"]
    assert not outcome.complete
    assert db.get_scan(outcome.scan_id).status == "paused"
    assert "Cuota diaria agotada" in ui.text()
    pending = [r for r in ui.summary[0] if r.level == Level.PENDING]
    assert len(pending) == 1

    clock.now = next_reset(clock.now) + 10
    ui2 = RecordingUI()
    outcome2 = make_scanner(cfg, db, clock, ui2, factory).run(
        ScanOptions(target=str(folder)), resume_scan_id=outcome.scan_id
    )
    assert factory.calls == ["users", "files"]
    assert outcome2.complete and outcome2.scan_id == outcome.scan_id
    assert db.get_scan(outcome.scan_id).status == "done"


def test_wait_mode_continues_after_reset(tmp_path, cfg, db, clock):
    cfg.virustotal.daily_limit = 4
    folder = tmp_path / "juego"
    for i in range(5):
        write(folder / f"f{i}.exe", MZ + bytes([i]))
    factory = Factory()
    start = clock.now
    outcome = make_scanner(cfg, db, clock, RecordingUI(), factory).run(
        ScanOptions(target=str(folder), wait=True)
    )
    assert outcome.complete
    assert clock.now > next_reset(start)
    assert factory.calls.count("files") == 5


def test_upload_flow(tmp_path, cfg, db, clock):
    folder = tmp_path / "juego"
    bat = write(folder / "instalar.bat", b"@echo off\r\necho unico\r\n")
    write(folder / "otro.cmd", b"@echo otro\r\n")
    factory = Factory(analysis_rounds=2)
    ui = RecordingUI(uploads=[1])
    outcome = make_scanner(cfg, db, clock, ui, factory).run(
        ScanOptions(target=str(folder), upload=True)
    )
    assert len(ui.upload_items) == 2
    assert factory.calls.count("upload") == 1
    assert factory.calls.count("analyses") == 2
    rows = {r.rel_path: r for r in ui.summary[0]}
    uploaded = rows[ui.upload_items[0].rel_path]
    assert uploaded.level == Level.CLEAN and uploaded.total == 70
    assert outcome.complete
    assert db.queued_uploads() == []
    assert db.get_vt_record(sha_of(bat)) is not None


def test_pending_analysis_is_collected_on_next_run(tmp_path, cfg, db, clock):
    folder = tmp_path / "juego"
    write(folder / "instalar.bat", b"@echo off\r\n")
    cfg.virustotal.analysis_max_checks_per_run = 1
    factory = Factory(analysis_rounds=3)
    ui = RecordingUI(uploads=[1])
    outcome = make_scanner(cfg, db, clock, ui, factory).run(ScanOptions(target=str(folder), upload=True))
    assert not outcome.complete
    assert any(r.level == Level.PENDING for r in ui.summary[0])

    cfg.virustotal.analysis_max_checks_per_run = 6
    ui2 = RecordingUI()
    outcome2 = make_scanner(cfg, db, clock, ui2, factory).run(ScanOptions(target=str(folder), upload=True))
    assert outcome2.complete
    assert ui2.upload_items is None  # ya no queda nada desconocido que proponer


def test_dry_run_makes_no_requests(tmp_path, cfg, db, clock):
    folder = tmp_path / "juego"
    make_game(folder)

    def no_client(*args, **kwargs):
        raise AssertionError("--dry-run no debe conectarse")

    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, no_client).run(ScanOptions(target=str(folder), dry_run=True))
    assert outcome.report_html.exists()
    assert "--dry-run" in ui.text()
    assert all(r.level == Level.PENDING for r in ui.summary[0])


def test_defender_results_are_merged(tmp_path, cfg, db, clock):
    folder = tmp_path / "juego"
    files = make_game(folder)
    zip_path = str(folder / "extras.zip")
    threats = [
        DefenderThreat("Trojan:Win32/RedLine.A", [str(files["dll"])]),
        DefenderThreat("HackTool:Win32/Crack", [zip_path, zip_path + "->herramienta.exe"]),
    ]

    def runner(target, report_only=True, on_tick=None):
        assert report_only
        return DefenderResult(ok=True, exit_code=2, found=2, threats=threats)

    ui = RecordingUI()
    make_scanner(cfg, db, clock, ui, Factory(), defender_runner=runner).run(
        ScanOptions(target=str(folder), defender=True)
    )
    rows = {r.rel_path: r for r in ui.summary[0]}
    assert rows[os.path.join("bin", "engine.dll")].level == Level.CRITICAL
    assert rows["extras.zip"].level == Level.MEDIUM
    assert "herramienta.exe" in rows["extras.zip"].reason


def test_defender_blocked_file_is_remembered(tmp_path, cfg, db, clock, monkeypatch):
    folder = tmp_path / "juego"
    bad = write(folder / "malo.exe", MZ + b"malo")
    write(folder / "bueno.exe", MZ + b"bueno")
    real = hashing.sha256_of_file

    def maybe_blocked(path, stop=None):
        if path.endswith("malo.exe"):
            raise OSError(0, "virus", None, 225)
        return real(path, stop)

    monkeypatch.setattr(hashing, "sha256_of_file", maybe_blocked)
    cfg.virustotal.daily_limit = 2  # que quede pendiente para reanudar el mismo escaneo
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, Factory()).run(ScanOptions(target=str(folder)))
    rows = {r.rel_path: r for r in ui.summary[0]}
    assert rows["malo.exe"].level == Level.HIGH

    bad.unlink()  # Defender lo mueve a cuarentena
    clock.now = next_reset(clock.now) + 10
    ui2 = RecordingUI()
    make_scanner(cfg, db, clock, ui2, Factory()).run(
        ScanOptions(target=str(folder)), resume_scan_id=outcome.scan_id
    )
    rows2 = {r.rel_path: r for r in ui2.summary[0]}
    assert rows2["malo.exe"].level == Level.HIGH
    assert "cuarentena" in rows2["malo.exe"].reason


def test_trusted_signed_files_go_last_or_are_skipped(tmp_path, cfg, db, clock, monkeypatch):
    folder = tmp_path / "juego"
    signed = write(folder / "a_firmado.dll", MZ + b"ms")
    write(folder / "z_sin_firma.dll", MZ + b"nada")

    def fake_signatures(paths, on_progress=None):
        return [
            SignatureInfo("valid", "Microsoft Corporation") if p.endswith("a_firmado.dll") else SignatureInfo("unsigned", "")
            for p in paths
        ]

    monkeypatch.setattr(pipeline, "check_signatures", fake_signatures)
    monkeypatch.setattr(pipeline, "IS_WINDOWS", True)
    cfg.signatures.enabled = True

    scanner = make_scanner(cfg, db, clock, RecordingUI(), Factory())
    state = pipeline._RunState()
    scanner._walk_phase(ScanOptions(target=str(folder)), state)
    scanner._hash_phase(0, state)
    scanner._signature_phase(state)
    order = scanner._plan_lookups(ScanOptions(target=str(folder)), state)
    assert order[-1] == sha_of(signed)  # el firmado por Microsoft, el último

    cfg.signatures.skip_trusted_signed = True
    ui = RecordingUI()
    factory = Factory()
    make_scanner(cfg, db, clock, ui, factory).run(ScanOptions(target=str(folder)))
    assert factory.calls.count("files") == 1
    rows = {r.rel_path: r for r in ui.summary[0]}
    assert rows["a_firmado.dll"].level == Level.SKIPPED


def test_all_files_asks_before_spending_days_of_quota(tmp_path, cfg, db, clock):
    cfg.virustotal.daily_limit = 3
    folder = tmp_path / "juego"
    for i in range(6):
        write(folder / f"textura{i}.png", bytes([i]) * 100)
    factory = Factory()
    ui = RecordingUI(confirm=False)
    outcome = make_scanner(cfg, db, clock, ui, factory).run(ScanOptions(target=str(folder), all_files=True))
    assert any(kind == "confirm" for kind, _ in ui.messages)
    assert factory.calls == ["users"]
    assert not outcome.complete


@pytest.mark.parametrize("interrupt_in", ["hash"])
def test_ctrl_c_writes_partial_report(tmp_path, cfg, db, clock, monkeypatch, interrupt_in):
    folder = tmp_path / "juego"
    make_game(folder)

    def boom(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(pipeline, "hash_entries", boom)
    ui = RecordingUI()
    outcome = make_scanner(cfg, db, clock, ui, Factory()).run(ScanOptions(target=str(folder)))
    assert outcome.interrupted and not outcome.complete
    assert outcome.report_html.exists()
    assert db.get_scan(outcome.scan_id).status == "interrupted"
