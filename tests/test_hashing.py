import hashlib
import os

from conftest import MZ, write
from vtscanner import hashing
from vtscanner.config import ScanConfig
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
