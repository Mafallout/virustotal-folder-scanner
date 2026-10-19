import os
import sys
from pathlib import Path

import pytest

# La ventana se prueba sin mostrarla en pantalla
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QPA_FONTDIR", os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"))

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vtscanner.config import Config  # noqa: E402
from vtscanner.db import Database  # noqa: E402

MZ = b"MZ" + b"\x90" * 254


class FakeClock:
    """Reloj simulado: sleep() avanza el tiempo al instante."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:  # 15/01/2027 08:00 UTC
        self.now = start

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, seconds)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    c = Config()
    c.general.data_dir = str(tmp_path / "data")
    c.report.output_dir = str(tmp_path / "reports")
    c.report.open_html = False
    c.signatures.enabled = False
    return c


@pytest.fixture
def db(cfg: Config, clock: FakeClock):
    d = Database(cfg.db_path, clock=clock.time)
    yield d
    d.close()


@pytest.fixture
def no_api_key(monkeypatch, tmp_path):
    """Sin clave: ni variable de entorno ni .env (se buscan en una carpeta temporal)."""
    from vtscanner import bootstrap

    monkeypatch.setattr(bootstrap, "PROJECT_DIR", tmp_path)
    monkeypatch.setattr(bootstrap, "writable_base", lambda: tmp_path)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    return tmp_path


def write(path: Path, data: bytes = b"x" * 100) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path
