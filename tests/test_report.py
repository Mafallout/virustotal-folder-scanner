import codecs
import csv
import io

from vtscanner.report import (
    ReportRow,
    ReportSummary,
    human_size,
    report_basename,
    write_csv,
    write_html,
)
from vtscanner.verdict import Level


def row(level, rel, **extra):
    return ReportRow(level, extra.pop("reason", "motivo"), extra.pop("label", ""), "C:\\r\\" + rel, rel, "x", **extra)


def summary(**extra):
    data = dict(
        root="C:\\r", started_at=1_800_000_000, finished_at=1_800_000_100, options=[], complete=True,
        files_seen=3, bytes_seen=1000, candidates=3, unique_hashes=3, requests_this_run=2,
    )
    data.update(extra)
    return ReportSummary(**data)


def read_csv(path):
    raw = path.read_bytes()
    assert raw.startswith(codecs.BOM_UTF8)
    return list(csv.reader(io.StringIO(raw.decode("utf-8-sig")), delimiter=";"))


def test_csv_sorted_by_danger_and_formula_safe(tmp_path):
    rows = [
        row(Level.CLEAN, "b.exe", malicious=0, suspicious=0, total=70),
        row(Level.CRITICAL, "=evil.exe", reason="=cmd|' /C calc'!A0", malicious=40, suspicious=1, total=70),
        row(Level.HIGH, "c.dll", malicious=5, suspicious=0, total=70),
        row(Level.HIGH, "d.dll", malicious=9, suspicious=0, total=70),
        row(Level.UNKNOWN, "e.bat"),
    ]
    path = tmp_path / "r.csv"
    write_csv(rows, path, ";")
    data = read_csv(path)
    assert data[0][0] == "nivel"
    assert [r[3] for r in data[1:]] == ["'=evil.exe", "d.dll", "c.dll", "e.bat", "b.exe"]
    assert data[1][1].startswith("'=")
    assert data[1][6] == "40"


def test_html_escapes_everything(tmp_path):
    rows = [
        row(
            Level.CRITICAL,
            "dir\\a&b'.exe",
            label="<script>alert(1)</script>",
            sha256="a" * 64,
            malicious=3,
            suspicious=0,
            total=70,
            main_detections=[("Kaspersky", "<img src=x onerror=alert(1)>")],
            detections_count=3,
            vt_link="https://www.virustotal.com/gui/file/" + "a" * 64,
        )
    ]
    path = tmp_path / "r.html"
    write_html(rows, summary(complete=False, pending=1, reset_local="02:00"), path)
    text = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    assert "<img src=x" not in text
    assert "a&amp;b&#x27;.exe" in text
    assert "--resume" in text and "02:00" in text
    assert "y 2 motores más" in text


def test_html_dry_run_status(tmp_path):
    path = tmp_path / "r.html"
    write_html([row(Level.PENDING, "a.exe")], summary(complete=False, pending=1, dry_run=True), path)
    assert "Simulación" in path.read_text(encoding="utf-8")


def test_human_size():
    assert human_size(None) == ""
    assert human_size(0) == "0 B"
    assert human_size(1536) == "1,5 KB"
    assert human_size(3 * 1024**3) == "3,0 GB"


def test_report_basename():
    assert report_basename("D:\\", 1_800_000_000).startswith("vtscan_D_")
    assert "Mi_Juego" in report_basename("C:\\Juegos\\Mi Juego", 1_800_000_000)
