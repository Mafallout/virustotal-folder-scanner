import sys

import pytest

from conftest import write
from vtscanner.signatures import (
    STATUS_UNSIGNED,
    STATUS_VALID,
    check_signatures,
    is_trusted,
    signer_from_subject,
)


def test_signer_from_subject():
    subject = 'CN=NVIDIA Corporation, O="NVIDIA, Corp", L=Santa Clara, C=US'
    assert signer_from_subject(subject) == "NVIDIA, Corp"
    assert signer_from_subject("CN=Solo Nombre, C=ES") == "Solo Nombre"
    assert signer_from_subject("") == ""


def test_is_trusted():
    trusted = ["Microsoft Corporation"]
    assert is_trusted("microsoft corporation", STATUS_VALID, trusted)
    assert not is_trusted("Microsoft Corporation", "tampered", trusted)
    assert not is_trusted("Otra", STATUS_VALID, trusted)


@pytest.mark.skipif(sys.platform != "win32", reason="solo Windows")
def test_real_signatures(tmp_path):
    unsigned = write(tmp_path / "sin firma ñ [1].exe", b"MZ" + b"\x00" * 300)
    results = check_signatures([sys.executable, str(unsigned)])
    assert len(results) == 2
    # Un "ejecutable" de mentira: sin firma o no verificable, pero nunca válido
    assert results[1].status in (STATUS_UNSIGNED, "unverifiable")
    # El python.exe oficial está firmado por la Python Software Foundation
    if results[0].status == STATUS_VALID:
        assert results[0].signer
