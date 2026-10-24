import hashlib
import os
import sqlite3

from conftest import MZ, write
from vtscanner import hashing
from vtscanner.config import ScanConfig
from vtscanner.db import Database
from vtscanner.hashing import group_by_hash, hash_entries, sha256_of_file
from vtscanner.walker import Walker


def entries(folder):
    return Walker(ScanConfig()).walk(str(folder)).files


def test_sha256_matches_hashlib(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 123)
    target = write(tmp_path / "x.bin", data)
    sha, is_pe = sha256_of_file(str(target))
    assert sha == hashlib.sha256(data).hexdigest()
    assert not is_pe
    assert sha256_of_file(str(write(tmp_path / "y.exe", MZ)))[1] is True


def test_cache_avoids_rehashing_and_detects_changes(tmp_path, db):
    target = write(tmp_path / "a.exe", MZ + b"1")
    first = hash_entries(entries(tmp_path), db, workers=2)
    assert len(first) == 1 and not first[0].from_cache and first[0].is_pe
    second = hash_entries(entries(tmp_path), db, workers=2)
    assert second[0].from_cache and second[0].sha256 == first[0].sha256
    target.write_bytes(MZ + b"22")
    os.utime(target, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    third = hash_entries(entries(tmp_path), db, workers=2)
    assert not third[0].from_cache and third[0].sha256 != first[0].sha256


def test_replaced_file_with_same_size_and_date_is_rehashed(tmp_path, db):
    target = write(tmp_path / "game.exe", MZ + b"ORIGINAL")
    st = os.stat(target)
    first = hash_entries(entries(tmp_path), db, workers=2)
    os.remove(target)
    target.write_bytes(MZ + b"INFECTED")  # otro archivo con el mismo tamaño y la misma fecha
    os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))
    second = hash_entries(entries(tmp_path), db, workers=2)
    assert not second[0].from_cache and second[0].sha256 != first[0].sha256


def test_old_database_gets_the_file_id_column(tmp_path):
    path = tmp_path / "vieja.sqlite3"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE file_hashes (path_key TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, "
        "sha256 TEXT NOT NULL, is_pe INTEGER NOT NULL DEFAULT 0, sig_status TEXT, sig_signer TEXT, "
        "updated_at REAL NOT NULL)"
    )
    conn.execute("PRAGMA user_version=1")
    conn.close()
    with Database(path) as db:
        db.put_file_hashes([("clave", 1, 2, "123", "abc", True)])
        assert db.get_file_hash("clave", 1, 2, "123").sha256 == "abc"


def test_duplicates_are_grouped(tmp_path, db):
    write(tmp_path / "a.exe", MZ)
    write(tmp_path / "sub" / "b.exe", MZ)
    write(tmp_path / "c.exe", MZ + b"distinto")
    groups = group_by_hash(hash_entries(entries(tmp_path), db))
    assert sorted(len(v) for v in groups.values()) == [1, 2]


def test_defender_block_is_reported(tmp_path, db, monkeypatch):
    write(tmp_path / "malo.exe", MZ)

    def blocked(path, stop=None):
        raise OSError(0, "contiene un virus", None, 225)

    monkeypatch.setattr(hashing, "sha256_of_file", blocked)
    (result,) = hash_entries(entries(tmp_path), db)
    assert result.defender_blocked and result.sha256 is None


def test_read_error_is_reported(tmp_path, db, monkeypatch):
    write(tmp_path / "a.exe", MZ)

    def denied(path, stop=None):
        raise PermissionError(13, "Acceso denegado")

    monkeypatch.setattr(hashing, "sha256_of_file", denied)
    (result,) = hash_entries(entries(tmp_path), db)
    assert result.error and not result.defender_blocked
