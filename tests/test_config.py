from pathlib import Path

import pytest

from vtscanner.config import ConfigError, load_config


def write_toml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_project_config_matches_defaults():
    cfg, warnings = load_config()
    assert warnings == []
    assert cfg.virustotal.requests_per_minute == 4
    assert cfg.virustotal.daily_limit == 500
    assert ".asi" in cfg.scan.extensions and ".exe" in cfg.scan.extensions
    assert cfg.defender.report_only is True
    assert cfg.signatures.skip_trusted_signed is False


def test_overrides_and_normalizes(tmp_path):
    path = write_toml(
        tmp_path,
        '[scan]\nextensions = ["EXE", ".Dll"]\nhash_workers = 2\n[report]\ncsv_delimiter = ","\n',
    )
    cfg, warnings = load_config(path)
    assert cfg.scan.extensions == [".dll", ".exe"]
    assert cfg.scan.hash_workers == 2
    assert cfg.report.csv_delimiter == ","
    assert warnings == []


def test_unknown_keys_are_warnings(tmp_path):
    path = write_toml(tmp_path, "[scan]\nnope = 1\n[otra]\nx = 2\n")
    _, warnings = load_config(path)
    assert len(warnings) == 2


@pytest.mark.parametrize(
    "text",
    [
        "[scan]\nhash_workers = \"4\"\n",
        "[scan]\nmax_file_size_mb = 700\n",
        "[virustotal]\ndirect_upload_max_mb = 64\n",
        "[report]\ncsv_delimiter = \";;\"\n",
        "[verdict]\ncritical_threshold = 2\nhigh_threshold = 3\n",
        "[defender]\nreport_only = 1\n",
        "esto no es toml",
    ],
)
def test_invalid_values(tmp_path, text):
    with pytest.raises(ConfigError):
        load_config(write_toml(tmp_path, text))


def test_missing_explicit_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "no_existe.toml")


def test_relative_paths_resolve_to_project(tmp_path):
    cfg, _ = load_config(write_toml(tmp_path, '[general]\ndata_dir = "datos"\n'))
    assert cfg.db_path.parent.name == "datos"
    assert cfg.db_path.parent.parent == Path(__file__).resolve().parent.parent
