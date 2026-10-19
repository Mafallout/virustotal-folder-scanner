from pathlib import Path

from conftest import MZ, write
from vtscanner import cli
from vtscanner.ui import parse_selection


def test_clean_path():
    assert cli.clean_path('D:\\Juegos"') == "D:\\Juegos"
    assert cli.clean_path('  "D:\\Juegos\\X"  ') == "D:\\Juegos\\X"
    assert cli.clean_path("D:") == "D:\\"


def test_parse_selection():
    assert parse_selection("", 5) == []
    assert parse_selection("n", 5) == []
    assert parse_selection("t", 3) == [1, 2, 3]
    assert parse_selection("1,3, 5-6", 6) == [1, 3, 5, 6]
    assert parse_selection("0", 5) is None
    assert parse_selection("4-2", 5) is None
    assert parse_selection("7", 5) is None
    assert parse_selection("abc", 5) is None


def test_load_api_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "PROJECT_DIR", tmp_path)
    monkeypatch.setenv("VT_API_KEY", "  desde_entorno ")
    assert cli.load_api_key() == "desde_entorno"


def test_load_api_key_from_dotenv(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "PROJECT_DIR", tmp_path)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert cli.load_api_key() is None
    (tmp_path / ".env").write_text('# comentario\nOTRA=1\nexport VT_API_KEY="desde_env"\n', encoding="utf-8")
    assert cli.load_api_key() == "desde_env"


def config_file(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    reports = tmp_path / "reports"
    path = tmp_path / "config.toml"
    path.write_text(
        f"[general]\ndata_dir = '{data}'\n[report]\noutput_dir = '{reports}'\nopen_html = false\n"
        "[signatures]\nenabled = false\n",
        encoding="utf-8",
    )
    return path


def test_main_dry_run(tmp_path):
    folder = tmp_path / "juego"
    write(folder / "a.exe", MZ)
    code = cli.main([str(folder), "--dry-run", "--config", str(config_file(tmp_path))])
    assert code == cli.EXIT_OK
    assert list((tmp_path / "reports").glob("*.html"))
    assert list((tmp_path / "data" / "logs").glob("vtscan_*.log"))


def test_main_without_key_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "PROJECT_DIR", tmp_path)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    folder = tmp_path / "juego"
    write(folder / "a.exe", MZ)
    assert cli.main([str(folder), "--config", str(config_file(tmp_path))]) == cli.EXIT_ERROR


def test_main_errors(tmp_path):
    cfg = str(config_file(tmp_path))
    assert cli.main(["--config", cfg]) == cli.EXIT_ERROR  # sin carpeta
    assert cli.main([str(tmp_path / "no_existe"), "--config", cfg]) == cli.EXIT_ERROR
    assert cli.main(["--resume", "--config", cfg]) == cli.EXIT_ERROR  # nada que reanudar
