import ctypes
import os
import subprocess

import pytest

from conftest import MZ, write
from vtscanner.config import ScanConfig
from vtscanner.hashing import sha256_of_file
from vtscanner.walker import (
    SIGNAL_DISGUISED,
    SIGNAL_DOUBLE_EXT,
    SIGNAL_HIDDEN,
    SIGNAL_RTLO,
    Walker,
)


def rels(result):
    return {e.rel_path for e in result.files}


def test_default_mode_extensions_and_disguised(tmp_path):
    write(tmp_path / "game.exe", MZ)
    write(tmp_path / "bin" / "lib.dll", MZ)
    write(tmp_path / "run.bat", b"@echo off\r\n" * 10)
    write(tmp_path / "readme.txt", b"hola" * 30)
    write(tmp_path / "data" / "texture.png", MZ)  # extensión de datos: no se abre
    write(tmp_path / "data" / "payload.dat", MZ)  # camuflado
    write(tmp_path / "data" / "plain.dat", b"\x00" * 200)
    write(tmp_path / "sinextension", MZ)
    result = Walker(ScanConfig()).walk(str(tmp_path))
    payload = os.path.join("data", "payload.dat")
    assert rels(result) == {"game.exe", os.path.join("bin", "lib.dll"), "run.bat", payload, "sinextension"}
    by_rel = {e.rel_path: e for e in result.files}
    assert by_rel[payload].reason == "content"
    assert SIGNAL_DISGUISED in by_rel[payload].signals
    assert SIGNAL_DISGUISED in by_rel["sinextension"].signals
    assert SIGNAL_DISGUISED not in by_rel["game.exe"].signals
    assert result.files_seen == 8


def test_documents_with_mz_and_names_ending_in_dot(tmp_path):
    write(tmp_path / "leeme.txt", MZ + b"x")
    write(tmp_path / "foto.png", MZ + b"x")  # las imágenes no se abren: en un juego hay miles
    odd = "\\\\?\\" + str(tmp_path / "raro.exe.")  # sin el prefijo, Windows recorta el punto final
    with open(odd, "wb") as f:
        f.write(MZ + b"x")
    try:
        files = Walker(ScanConfig()).walk(str(tmp_path)).files
        assert {os.path.basename(e.path) for e in files} == {"leeme.txt", "raro.exe."}
        assert all(sha256_of_file(e.path)[1] for e in files)  # y se pueden leer para el hash
    finally:
        os.remove(odd)


def test_content_detection_can_be_disabled(tmp_path):
    write(tmp_path / "payload.dat", MZ)
    result = Walker(ScanConfig(detect_executables_by_content=False)).walk(str(tmp_path))
    assert result.files == []


def test_legit_pe_extension_is_not_disguised(tmp_path):
    write(tmp_path / "plugin.pyd", MZ)
    (entry,) = Walker(ScanConfig()).walk(str(tmp_path)).files
    assert entry.reason == "content"
    assert SIGNAL_DISGUISED not in entry.signals


def test_all_files_mode(tmp_path):
    write(tmp_path / "a.txt")
    write(tmp_path / "b.png")
    result = Walker(ScanConfig(), all_files=True).walk(str(tmp_path))
    assert rels(result) == {"a.txt", "b.png"}


def test_too_large_is_skipped_and_reported(tmp_path):
    big = MZ + b"\x00" * (1024 * 1024 + 10)
    write(tmp_path / "big.exe", big)
    write(tmp_path / "big.pak", big)  # no es candidato: ni se analiza ni se avisa
    result = Walker(ScanConfig(max_file_size_mb=1)).walk(str(tmp_path))
    assert result.files == []
    assert [(s.rel_path, s.reason) for s in result.skipped] == [("big.exe", "too_large")]


def test_name_signals(tmp_path):
    write(tmp_path / "factura.pdf.exe", MZ)
    write(tmp_path / "foto‮gnp.exe", MZ)
    hidden = write(tmp_path / "oculto.exe", MZ)
    ctypes.windll.kernel32.SetFileAttributesW(str(hidden), 0x2)
    by_rel = {e.rel_path: e for e in Walker(ScanConfig()).walk(str(tmp_path)).files}
    assert SIGNAL_DOUBLE_EXT in by_rel["factura.pdf.exe"].signals
    assert SIGNAL_RTLO in by_rel["foto‮gnp.exe"].signals
    assert SIGNAL_HIDDEN in by_rel["oculto.exe"].signals
    assert by_rel["oculto.exe"].signals == {SIGNAL_HIDDEN}


def test_excluded_dirs(tmp_path):
    write(tmp_path / "node_modules" / "x.js")
    write(tmp_path / "keep" / "y.js")
    result = Walker(ScanConfig(exclude_dirs=["node_modules"])).walk(str(tmp_path))
    assert rels(result) == {os.path.join("keep", "y.js")}


def test_single_file_target_is_always_analyzed(tmp_path):
    target = write(tmp_path / "cualquiera.txt")
    result = Walker(ScanConfig()).walk(str(target))
    assert [e.reason for e in result.files] == ["explicit"]
    assert result.root == str(tmp_path)


def test_long_and_unicode_paths(tmp_path):
    deep = tmp_path
    for i in range(8):
        deep = deep / ("carpeta_larga_ñ_&_'_" + str(i) * 12)
    target = write(deep / "juego ñ & 'x'.exe", MZ)
    assert len(str(target)) > 260
    (entry,) = Walker(ScanConfig()).walk(str(tmp_path)).files
    assert entry.path == str(target)


def test_junction_is_not_followed(tmp_path):
    write(tmp_path / "real" / "a.exe", MZ)
    junction = tmp_path / "real" / "bucle"
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(tmp_path)], capture_output=True
    )
    if made.returncode != 0:
        pytest.skip("no se pudo crear la junction")
    try:
        result = Walker(ScanConfig()).walk(str(tmp_path))
        assert rels(result) == {os.path.join("real", "a.exe")}
    finally:
        os.rmdir(junction)  # borra la junction, no su destino
