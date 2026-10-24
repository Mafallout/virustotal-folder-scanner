import pytest
import requests
import responses
from responses.registries import OrderedRegistry

from conftest import write
from vtscanner.config import VirusTotalConfig
from vtscanner.ratelimit import DailyQuotaExceeded, RateLimiter
from vtscanner.vtclient import (
    API_BASE,
    AuthError,
    TransientError,
    VTClient,
    VTError,
    safe_upload_name,
)

KEY = "k" * 64
SHA = "a" * 64

FILE_JSON = {
    "data": {
        "id": SHA,
        "type": "file",
        "attributes": {
            "sha256": SHA,
            "last_analysis_stats": {
                "malicious": 2, "suspicious": 1, "undetected": 60, "harmless": 0,
                "type-unsupported": 5, "timeout": 1,
            },
            "last_analysis_results": {
                "Microsoft": {"category": "malicious", "engine_name": "Microsoft",
                              "result": "Trojan:Win32/Wacatac.B!ml"},
                "Kaspersky": {"category": "suspicious", "engine_name": "Kaspersky",
                              "result": "HEUR:Trojan.Win32.Generic"},
                "ESET-NOD32": {"category": "malicious", "engine_name": "ESET-NOD32",
                               "result": "a variant of Win32/Kryptik.HXYZ"},
                "Avast": {"category": "undetected", "engine_name": "Avast", "result": None},
            },
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.wacatac/kryptik",
                "popular_threat_category": [{"value": "trojan", "count": 3}],
                "popular_threat_name": [{"value": "wacatac", "count": 2}],
            },
            "first_submission_date": 1700000000,
            "last_analysis_date": 1750000000,
            "meaningful_name": "game.exe",
            "type_description": "Win32 EXE",
        },
    }
}


def make_client(db, clock, cfg=None):
    lim = RateLimiter(db, 4, 500, clock.time, clock.sleep)
    return VTClient(KEY, lim, cfg or VirusTotalConfig()), lim


@responses.activate
def test_get_file_found(db, clock):
    responses.get(f"{API_BASE}/files/{SHA}", json=FILE_JSON)
    client, lim = make_client(db, clock)
    report = client.get_file(SHA)
    assert (report.malicious, report.suspicious, report.total) == (2, 1, 63)
    assert set(report.detections) == {"Microsoft", "Kaspersky", "ESET-NOD32"}
    assert report.threat_label == "trojan.wacatac/kryptik"
    assert report.threat_names == [("wacatac", 2)]
    assert responses.calls[0].request.headers["x-apikey"] == KEY
    assert lim.used_today() == 1


@responses.activate
def test_get_file_not_found(db, clock):
    responses.get(
        f"{API_BASE}/files/{SHA}", status=404, json={"error": {"code": "NotFoundError", "message": "x"}}
    )
    client, lim = make_client(db, clock)
    assert client.get_file(SHA) is None
    assert lim.used_today() == 1  # las consultas fallidas también gastan cuota


@responses.activate(registry=OrderedRegistry)
def test_429_waits_and_retries(db, clock):
    url = f"{API_BASE}/files/{SHA}"
    responses.get(url, status=429, json={"error": {"code": "QuotaExceededError"}})
    responses.get(url, json=FILE_JSON)
    client, _ = make_client(db, clock)
    start = clock.now
    assert client.get_file(SHA) is not None
    assert clock.now - start >= 61


@responses.activate(registry=OrderedRegistry)
def test_two_429_in_a_row_mean_daily_quota(db, clock):
    url = f"{API_BASE}/files/{SHA}"
    responses.get(url, status=429, json={"error": {"code": "QuotaExceededError"}})
    responses.get(url, status=429, json={"error": {"code": "QuotaExceededError"}})
    client, lim = make_client(db, clock)
    with pytest.raises(DailyQuotaExceeded):
        client.get_file(SHA)
    assert lim.remaining_today() == 0


@responses.activate
def test_odd_responses_are_errors_not_crashes(db, clock):
    responses.get(f"{API_BASE}/files/{SHA}", status=403, json={"error": "Forbidden"})
    responses.get(f"{API_BASE}/files/{'b' * 64}", json={"data": "x"})
    responses.get(f"{API_BASE}/files/{'c' * 64}", body=requests.exceptions.TooManyRedirects("bucle"))
    client, _ = make_client(db, clock)
    with pytest.raises(VTError, match="403"):
        client.get_file(SHA)
    with pytest.raises(VTError):
        client.get_file("b" * 64)
    with pytest.raises(TransientError):
        client.get_file("c" * 64)


@responses.activate(registry=OrderedRegistry)
def test_server_errors_are_retried_then_transient(db, clock):
    url = f"{API_BASE}/files/{SHA}"
    for _ in range(4):
        responses.get(url, status=503, json={"error": {"code": "TransientError"}})
    client, _ = make_client(db, clock)
    with pytest.raises(TransientError):
        client.get_file(SHA)
    assert len(responses.calls) == 4


@responses.activate(registry=OrderedRegistry)
def test_server_error_then_success(db, clock):
    url = f"{API_BASE}/files/{SHA}"
    responses.get(url, status=503)
    responses.get(url, json=FILE_JSON)
    client, _ = make_client(db, clock)
    assert client.get_file(SHA) is not None


@responses.activate
def test_connection_error_does_not_leak_key(db, clock):
    responses.get(f"{API_BASE}/users/{KEY}", body=requests.ConnectionError(f"fallo en /users/{KEY}"))
    client, _ = make_client(db, clock)
    assert client.get_user_quota() is None


@responses.activate(registry=OrderedRegistry)
def test_connection_errors_become_transient_without_key(db, clock):
    url = f"{API_BASE}/files/{SHA}"
    for _ in range(4):
        responses.get(url, body=requests.ConnectionError(f"clave {KEY}"))
    client, _ = make_client(db, clock)
    with pytest.raises(TransientError) as info:
        client.get_file(SHA)
    assert KEY not in str(info.value)


@responses.activate
def test_401_is_auth_error_and_redacted(db, clock):
    responses.get(
        f"{API_BASE}/users/{KEY}",
        status=401,
        json={"error": {"code": "WrongCredentialsError", "message": f"bad key {KEY}"}},
    )
    client, _ = make_client(db, clock)
    with pytest.raises(AuthError) as info:
        client.get_user_quota()
    assert KEY not in str(info.value)
    assert "WrongCredentialsError" in str(info.value)


@responses.activate
@pytest.mark.parametrize(
    "daily",
    [{"used": 12, "allowed": 500}, {"user": {"used": 12, "allowed": 500}, "group": {"used": 9}}],
)
def test_get_user_quota(db, clock, daily):
    responses.get(
        f"{API_BASE}/users/{KEY}", json={"data": {"attributes": {"quotas": {"api_requests_daily": daily}}}}
    )
    client, _ = make_client(db, clock)
    assert client.get_user_quota() == (12, 500)


@responses.activate
def test_get_user_quota_429_does_not_wait(db, clock):
    responses.get(f"{API_BASE}/users/{KEY}", status=429)
    client, _ = make_client(db, clock)
    start = clock.now
    assert client.get_user_quota() is None
    assert clock.now == start


@responses.activate
def test_upload_small_file(db, clock, tmp_path):
    target = write(tmp_path / "prueba ñ.bat", b"@echo hola\r\n")
    responses.post(f"{API_BASE}/files", json={"data": {"type": "analysis", "id": "abc=="}})
    client, lim = make_client(db, clock)
    progress = []
    assert client.upload_file(str(target), target.stat().st_size, lambda s, t: progress.append(s)) == "abc=="
    request = responses.calls[0].request
    assert request.headers["Content-Type"].startswith("multipart/form-data")
    assert lim.used_today() == 1


@responses.activate
def test_upload_large_file_uses_upload_url(db, clock, tmp_path):
    target = write(tmp_path / "grande.exe", b"\x00" * (2 * 1024 * 1024))
    responses.get(f"{API_BASE}/files/upload_url", json={"data": "http://www.virustotal.com/_ah/upload/XYZ"})
    responses.post("https://www.virustotal.com/_ah/upload/XYZ", json={"data": {"id": "big=="}})
    client, lim = make_client(db, clock, VirusTotalConfig(direct_upload_max_mb=1))
    assert client.upload_file(str(target), target.stat().st_size) == "big=="
    assert responses.calls[1].request.url.startswith("https://")  # se fuerza https
    assert lim.used_today() == 2


@responses.activate
def test_upload_url_from_other_host_is_rejected(db, clock, tmp_path):
    target = write(tmp_path / "grande.exe", b"\x00" * (2 * 1024 * 1024))
    responses.get(f"{API_BASE}/files/upload_url", json={"data": "https://otro.example.com/subir"})
    client, _ = make_client(db, clock, VirusTotalConfig(direct_upload_max_mb=1))
    with pytest.raises(VTError):
        client.upload_file(str(target), target.stat().st_size)
    assert len(responses.calls) == 1


@responses.activate
def test_get_analysis(db, clock):
    responses.get(f"{API_BASE}/analyses/q==", json={"data": {"attributes": {"status": "queued"}}})
    responses.get(
        f"{API_BASE}/analyses/c==",
        json={
            "data": {
                "attributes": {
                    "status": "completed",
                    "date": 1750000000,
                    "stats": {"malicious": 1, "suspicious": 0, "undetected": 69, "harmless": 0},
                    "results": {"DrWeb": {"category": "malicious", "engine_name": "DrWeb", "result": "Trojan.X"}},
                }
            }
        },
    )
    client, _ = make_client(db, clock)
    assert client.get_analysis("q==", SHA).status == "queued"
    done = client.get_analysis("c==", SHA)
    assert done.status == "completed"
    assert (done.report.malicious, done.report.total, done.report.sha256) == (1, 70, SHA)


def test_safe_upload_name():
    assert safe_upload_name("Juego ñ (v2) ✓.exe") == "Juego n _v2_ .exe"
    assert safe_upload_name("игра") == "archivo"
