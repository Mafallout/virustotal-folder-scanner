"""VirusTotal e interfaz simulados, compartidos por los tests del núcleo y de la ventana."""

import hashlib

from conftest import MZ, write
from vtscanner.defender import DefenderResult
from vtscanner.pipeline import Scanner
from vtscanner.ui import BaseUI
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
        self.results = []
        self.quotas = []
        self.estimates = []

    def message(self, text, kind="info"):
        self.messages.append((kind, text))

    def task_end(self, summary=None):
        if summary:
            self.messages.append(("task", summary))

    def quota(self, used, limit):
        self.quotas.append((used, limit))

    def estimate(self, needed, remaining, minutes):
        self.estimates.append((needed, remaining, minutes))

    def result(self, rel_path, level, reason):
        self.results.append((rel_path, level, reason))

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

    def __init__(self, limiter, known, analysis_rounds=2, after_call=None):
        self.limiter = limiter
        self.known = known
        self.analysis_rounds = analysis_rounds
        self.after_call = after_call
        self.calls = []
        self.analysis_calls = {}

    def _hit(self, label):
        self.limiter.wait_for_slot()
        self.limiter.record(label, 200)
        self.calls.append(label)
        if self.after_call:
            self.after_call(self.calls)

    def get_user_quota(self):
        self._hit("users")
        return None

    def get_file(self, sha):
        self._hit("files")
        report = self.known.get(sha)
        if report is None:
            return None
        return FileReport(
            sha, report.malicious, report.suspicious, report.total, dict(report.detections), report.threat_label
        )

    def upload_file(self, path, size, on_progress=None):
        self._hit("upload")
        if on_progress:
            on_progress(size, size)
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
    def __init__(self, known=None, analysis_rounds=2, after_call=None):
        self.known = known or {}
        self.analysis_rounds = analysis_rounds
        self.after_call = after_call
        self.instances = []

    def __call__(self, api_key, limiter, cfg, on_wait=None):
        fake = FakeVT(limiter, self.known, self.analysis_rounds, self.after_call)
        self.instances.append(fake)
        return fake

    @property
    def calls(self):
        return self.instances[-1].calls


def no_defender(*args, **kwargs):
    return DefenderResult(ok=True, found=0)


def make_scanner(cfg, db, clock, ui, factory, defender_runner=None, cancel_event=None):
    return Scanner(
        cfg,
        ui,
        "clave",
        db=db,
        client_factory=factory,
        clock=clock.time,
        sleeper=clock.sleep,
        defender_runner=defender_runner or no_defender,
        cancel_event=cancel_event,
    )


def make_game(folder):
    return {
        "game": write(folder / "Game.exe", MZ + b"game"),
        "dll": write(folder / "bin" / "engine.dll", MZ + b"engine"),
        "dup": write(folder / "copia" / "Game.exe", MZ + b"game"),
        "bat": write(folder / "instalar.bat", b"@echo off\r\necho hola\r\n"),
        "txt": write(folder / "leeme.txt", b"texto"),
    }
