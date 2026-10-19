import os

import pytest

from vtscanner import defender
from vtscanner.defender import DefenderResult, find_mpcmdrun, parse_output, run_scan

CLEAN = "Scan starting...\r\nScan finished.\r\nScanning D:\\x found no threats.\r\n"

THREATS = """Scan starting...
Scan finished.
Scanning D:\\Juegos\\X found 2 threats.

<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 1 total
    file                : D:\\Juegos\\X\\eicar.com
-------------------------------------------------------------------------------
----------------------------- Threat information ------------------------------
Threat                  : Trojan:Win32/Wacatac.B!ml
Resources               : 3 total
    file                : D:\\Juegos\\X\\mods\\loader.exe
    containerfile       : D:\\Juegos\\X\\extras.zip
    file                : D:\\Juegos\\X\\extras.zip->setup.exe
-------------------------------------------------------------------------------
"""


def test_parse_clean():
    assert parse_output(CLEAN) == (0, [])


def test_parse_threats():
    found, threats = parse_output(THREATS)
    assert found == 2
    assert [t.name for t in threats] == ["Virus:DOS/EICAR_Test_File", "Trojan:Win32/Wacatac.B!ml"]
    assert threats[1].resources == [
        "D:\\Juegos\\X\\mods\\loader.exe",
        "D:\\Juegos\\X\\extras.zip",
        "D:\\Juegos\\X\\extras.zip->setup.exe",
    ]


def test_threat_by_path_and_roundtrip():
    found, threats = parse_output(THREATS)
    result = DefenderResult(ok=True, exit_code=2, found=found, threats=threats, raw_output=THREATS)
    restored = DefenderResult.from_dict(result.to_dict())
    mapping = restored.threat_by_path()
    key = os.path.normcase(os.path.abspath("D:\\Juegos\\X\\extras.zip"))
    assert mapping[key] == "Trojan:Win32/Wacatac.B!ml"


def test_find_mpcmdrun_picks_newest_version(tmp_path, monkeypatch):
    platform = tmp_path / "Microsoft" / "Windows Defender" / "Platform"
    for version in ("4.18.9-0", "4.18.10-0"):
        folder = platform / version
        folder.mkdir(parents=True)
        (folder / "MpCmdRun.exe").write_bytes(b"")
    monkeypatch.setenv("ProgramData", str(tmp_path))
    assert find_mpcmdrun() == str(platform / "4.18.10-0" / "MpCmdRun.exe")


def test_run_scan_with_fake_mpcmdrun(tmp_path):
    (tmp_path / "salida.txt").write_text(THREATS, encoding="utf-8")
    fake = tmp_path / "fake.cmd"
    fake.write_text('@type "%~dp0salida.txt"\r\n@exit /b 2\r\n', encoding="ascii")
    ticks = []
    result = run_scan(str(tmp_path), on_tick=ticks.append, exe=str(fake))
    assert result.ok and result.exit_code == 2 and result.found == 2
    assert len(result.threats) == 2


def test_run_scan_reports_failures(tmp_path):
    fake = tmp_path / "roto.cmd"
    fake.write_text("@echo Failed with hr = 0x800106BA\r\n@exit /b 1\r\n", encoding="ascii")
    result = run_scan(str(tmp_path), exe=str(fake))
    assert not result.ok
    assert "Defender no está activo" in result.error


@pytest.mark.skipif(find_mpcmdrun() is None, reason="Defender no está instalado")
def test_real_defender_on_empty_folder(tmp_path):
    result = defender.run_scan(str(tmp_path))
    assert result.ok, result.error
    assert result.found == 0 and result.threats == []
