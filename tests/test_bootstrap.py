import sys
from pathlib import Path

from vtscanner import bootstrap, config

KEY = "a1" * 32


def test_clean_path():
    assert bootstrap.clean_path('D:\\Juegos"') == "D:\\Juegos"
    assert bootstrap.clean_path('  "D:\\Juegos\\X"  ') == "D:\\Juegos\\X"
    assert bootstrap.clean_path("D:") == "D:\\"


def test_looks_like_api_key():
    assert bootstrap.looks_like_api_key(KEY)
    assert bootstrap.looks_like_api_key(f"  {KEY.upper()} ")
    assert not bootstrap.looks_like_api_key("corta")
    assert not bootstrap.looks_like_api_key("z" * 64)


def test_load_api_key_from_env(no_api_key, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "  desde_entorno ")
    assert bootstrap.load_api_key() == "desde_entorno"


def test_load_api_key_from_dotenv(no_api_key):
    assert bootstrap.load_api_key() is None
    (no_api_key / ".env").write_text('# comentario\nOTRA=1\nexport VT_API_KEY="desde_env"\n', encoding="utf-8")
    assert bootstrap.load_api_key() == "desde_env"


def test_prefer_file_over_environment(no_api_key, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "de_entorno")
    (no_api_key / ".env").write_text("VT_API_KEY=de_archivo\n", encoding="utf-8")
    assert bootstrap.load_api_key() == "de_entorno"  # la terminal: primero la variable
    assert bootstrap.load_api_key(prefer_file=True) == "de_archivo"  # la ventana: primero el .env


def test_save_api_key_keeps_other_lines(no_api_key):
    env = no_api_key / ".env"
    env.write_text("# mis cosas\nOTRA=1\nVT_API_KEY=vieja\nVT_API_KEY=duplicada\n", encoding="utf-8")
    assert bootstrap.save_api_key(f" {KEY} ") == env
    assert env.read_text(encoding="utf-8") == f"# mis cosas\nOTRA=1\nVT_API_KEY={KEY}\n"
    assert bootstrap.load_api_key() == KEY


def test_dotenv_in_other_encodings_and_with_comment(no_api_key):
    env = no_api_key / ".env"
    env.write_text(f"VT_API_KEY={KEY}\n", encoding="utf-16")  # PowerShell 5.1: "..." > .env
    assert bootstrap.load_api_key() == KEY
    env.write_bytes(f"# clave ñ\r\nVT_API_KEY={KEY}  # mi clave\r\n".encode("cp1252"))  # Bloc de notas antiguo
    assert bootstrap.load_api_key() == KEY
    bootstrap.save_api_key("cd" * 32)
    assert env.read_text(encoding="utf-8") == f"# clave ñ\nVT_API_KEY={'cd' * 32}\n"


def test_save_api_key_creates_file(no_api_key):
    bootstrap.save_api_key(KEY)
    assert (no_api_key / ".env").read_text(encoding="utf-8") == f"VT_API_KEY={KEY}\n"


def test_base_dir_when_packaged(monkeypatch, tmp_path):
    exe = tmp_path / "vtscan" / "vtscan.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    assert config._base_dir() == exe.parent.resolve()


def test_base_dir_from_source():
    assert config._base_dir() == Path(config.__file__).resolve().parent.parent


def test_fallback_when_not_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert config.fallback_dir() == tmp_path / "vtscan"
    assert config.is_writable(tmp_path / "nueva")
    blocker = tmp_path / "soy_un_archivo"
    blocker.write_text("x", encoding="ascii")
    assert not config.is_writable(blocker / "carpeta")  # no se puede crear una carpeta dentro de un archivo
