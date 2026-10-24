"""Cliente de la API v3 de VirusTotal con requests. Cada petición pasa por el
limitador, así nunca se supera la cuota del plan gratuito."""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable

import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor

from . import __version__
from .config import VirusTotalConfig
from .ratelimit import DailyQuotaExceeded, RateLimiter, WaitCallback
from .winutils import fs_path

log = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3"
GUI_FILE_URL = "https://www.virustotal.com/gui/file/{}"

# Motores que dieron veredicto (los que cuentan para el total "X de Y")
COUNTED_CATEGORIES = ("malicious", "suspicious", "undetected", "harmless")
TRANSIENT_STATUS = {500, 502, 503, 504}
BACKOFF_SECONDS = (5, 20, 60)
QUOTA_COOLDOWN_SECONDS = 61


class VTError(Exception):
    """Error de la API que no se arregla reintentando."""


class AuthError(VTError):
    """La API key no es válida o la cuenta no está activa."""


class TransientError(VTError):
    """Error de red o del servidor que puede arreglarse más tarde."""


@dataclass
class FileReport:
    sha256: str
    malicious: int
    suspicious: int
    total: int
    detections: dict[str, tuple[str, str]] = field(default_factory=dict)  # motor -> (categoría, nombre)
    threat_label: str = ""
    threat_categories: list[tuple[str, int]] = field(default_factory=list)
    threat_names: list[tuple[str, int]] = field(default_factory=list)
    meaningful_name: str = ""
    type_description: str = ""
    first_submission_date: int | None = None
    last_analysis_date: int | None = None
    times_submitted: int | None = None
    reputation: int | None = None

    def to_data(self) -> dict[str, Any]:
        """Versión reducida para guardar en la base de datos."""
        return {
            "detections": {k: list(v) for k, v in self.detections.items()},
            "label": self.threat_label,
            "categories": [list(c) for c in self.threat_categories],
            "names": [list(n) for n in self.threat_names],
            "meaningful_name": self.meaningful_name,
            "type": self.type_description,
            "first_seen": self.first_submission_date,
            "last_analysis": self.last_analysis_date,
            "times_submitted": self.times_submitted,
            "reputation": self.reputation,
        }

    @classmethod
    def from_data(
        cls, sha256: str, malicious: int, suspicious: int, total: int, data: dict[str, Any]
    ) -> "FileReport":
        return cls(
            sha256=sha256,
            malicious=malicious,
            suspicious=suspicious,
            total=total,
            detections={k: (v[0], v[1]) for k, v in (data.get("detections") or {}).items()},
            threat_label=data.get("label") or "",
            threat_categories=[(c[0], int(c[1])) for c in data.get("categories") or []],
            threat_names=[(n[0], int(n[1])) for n in data.get("names") or []],
            meaningful_name=data.get("meaningful_name") or "",
            type_description=data.get("type") or "",
            first_submission_date=data.get("first_seen"),
            last_analysis_date=data.get("last_analysis"),
            times_submitted=data.get("times_submitted"),
            reputation=data.get("reputation"),
        )


@dataclass
class AnalysisStatus:
    status: str  # completed | queued | in-progress | missing
    report: FileReport | None = None


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _parse_stats(stats: dict[str, Any]) -> tuple[int, int, int]:
    malicious = _int(stats.get("malicious"))
    suspicious = _int(stats.get("suspicious"))
    total = sum(_int(stats.get(c)) for c in COUNTED_CATEGORIES)
    return malicious, suspicious, total


def _parse_detections(results: dict[str, Any]) -> dict[str, tuple[str, str]]:
    detections: dict[str, tuple[str, str]] = {}
    for engine, item in (results or {}).items():
        if not isinstance(item, dict):
            continue
        category = item.get("category") or ""
        if category in ("malicious", "suspicious"):
            detections[str(item.get("engine_name") or engine)] = (category, str(item.get("result") or ""))
    return detections


def _parse_counts(items: Any) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for item in items or []:
        if isinstance(item, dict) and item.get("value"):
            out.append((str(item["value"]), _int(item.get("count"))))
    return out


def parse_file_object(data: dict[str, Any]) -> FileReport:
    attrs = data.get("attributes") or {}
    malicious, suspicious, total = _parse_stats(attrs.get("last_analysis_stats") or {})
    ptc = attrs.get("popular_threat_classification") or {}
    return FileReport(
        sha256=str(attrs.get("sha256") or data.get("id") or "").lower(),
        malicious=malicious,
        suspicious=suspicious,
        total=total,
        detections=_parse_detections(attrs.get("last_analysis_results") or {}),
        threat_label=str(ptc.get("suggested_threat_label") or ""),
        threat_categories=_parse_counts(ptc.get("popular_threat_category")),
        threat_names=_parse_counts(ptc.get("popular_threat_name")),
        meaningful_name=str(attrs.get("meaningful_name") or ""),
        type_description=str(attrs.get("type_description") or ""),
        first_submission_date=attrs.get("first_submission_date"),
        last_analysis_date=attrs.get("last_analysis_date"),
        times_submitted=attrs.get("times_submitted"),
        reputation=attrs.get("reputation"),
    )


def parse_analysis_object(sha256: str, data: dict[str, Any]) -> AnalysisStatus:
    attrs = data.get("attributes") or {}
    status = str(attrs.get("status") or "queued")
    if status != "completed":
        return AnalysisStatus(status)
    malicious, suspicious, total = _parse_stats(attrs.get("stats") or {})
    report = FileReport(
        sha256=sha256,
        malicious=malicious,
        suspicious=suspicious,
        total=total,
        detections=_parse_detections(attrs.get("results") or {}),
        last_analysis_date=attrs.get("date"),
    )
    return AnalysisStatus("completed", report)


def safe_upload_name(name: str) -> str:
    """Nombre en ASCII para la subida (el servidor de subidas no acepta bien otros)."""
    base = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    base = re.sub(r"[^A-Za-z0-9._ -]+", "_", base).strip(" ._")
    return base or "archivo"


class VTClient:
    def __init__(
        self,
        api_key: str,
        limiter: RateLimiter,
        cfg: VirusTotalConfig,
        session: requests.Session | None = None,
        on_wait: WaitCallback | None = None,
    ) -> None:
        self._key = api_key
        self.limiter = limiter
        self.cfg = cfg
        self.on_wait = on_wait
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "x-apikey": api_key,
                "Accept": "application/json",
                "User-Agent": f"vtscan/{__version__}",
            }
        )

    # ---- utilidades ---------------------------------------------------------

    def redact(self, text: str) -> str:
        return text.replace(self._key, "***") if self._key else text

    def _error_message(self, resp: requests.Response) -> str:
        code = message = None
        try:
            data = resp.json()
        except ValueError:
            data = None
        error = data.get("error") if isinstance(data, dict) else None
        if isinstance(error, dict):
            code, message = error.get("code"), error.get("message")
        text = f"HTTP {resp.status_code}"
        if code:
            text += f" {code}"
        if message:
            text += f": {message}"
        return self.redact(text)

    def _request(
        self,
        label: str,
        send: Callable[[], requests.Response],
        retries: int = len(BACKOFF_SECONDS),
        quota_retry: bool = True,
        daily: bool = True,
    ) -> requests.Response:
        """Hace una petición respetando los límites y reintentando lo que tenga sentido."""
        transient_attempts = 0
        quota_hits = 0
        while True:
            self.limiter.wait_for_slot(self.on_wait, daily)
            try:
                resp = send()
            except requests.RequestException as exc:
                self.limiter.record(label, None)
                log.debug("Error de red en %s: %s", label, self.redact(str(exc)))
                transient_attempts += 1
                if transient_attempts > retries:
                    raise TransientError(f"Error de red ({type(exc).__name__})") from None
                delay = BACKOFF_SECONDS[min(transient_attempts, len(BACKOFF_SECONDS)) - 1]
                self.limiter.cooldown(delay, "reintentando tras un error de red", self.on_wait)
                continue
            self.limiter.record(label, resp.status_code)
            log.debug("%s -> HTTP %s", label, resp.status_code)
            if resp.status_code == 429:
                if not quota_retry:
                    return resp
                quota_hits += 1
                if quota_hits >= 2:
                    self.limiter.mark_exhausted()
                    raise DailyQuotaExceeded()
                self.limiter.cooldown(
                    QUOTA_COOLDOWN_SECONDS, "VirusTotal pide esperar (límite de peticiones)", self.on_wait
                )
                continue
            if resp.status_code in TRANSIENT_STATUS:
                transient_attempts += 1
                if transient_attempts > retries:
                    raise TransientError(f"VirusTotal no responde ({self._error_message(resp)})")
                delay = BACKOFF_SECONDS[min(transient_attempts, len(BACKOFF_SECONDS)) - 1]
                self.limiter.cooldown(delay, "VirusTotal no responde, reintentando", self.on_wait)
                continue
            if resp.status_code == 401:
                raise AuthError(self._error_message(resp))
            return resp

    def _get(self, path: str) -> Callable[[], requests.Response]:
        url = f"{API_BASE}{path}"
        return lambda: self.session.get(url, timeout=self.cfg.request_timeout_seconds)

    # ---- endpoints ----------------------------------------------------------

    def get_user_quota(self) -> tuple[int, int | None] | None:
        """(usadas hoy, permitidas hoy) según VirusTotal, o None si no se sabe.
        Sirve también para comprobar que la clave es válida (lanza AuthError)."""
        try:
            resp = self._request(
                "users", self._get(f"/users/{self._key}"), retries=1, quota_retry=False, daily=False
            )
        except TransientError:
            return None
        if resp.status_code != 200:
            return None
        try:
            quotas = ((resp.json().get("data") or {}).get("attributes") or {}).get("quotas") or {}
        except (ValueError, AttributeError):
            return None
        daily = quotas.get("api_requests_daily") or {}
        if isinstance(daily.get("user"), dict):
            daily = daily["user"]
        used, allowed = daily.get("used"), daily.get("allowed")
        if not isinstance(used, int):
            return None
        return used, allowed if isinstance(allowed, int) else None

    def get_file(self, sha256: str) -> FileReport | None:
        """Informe de un hash, o None si VirusTotal no lo conoce."""
        resp = self._request("files", self._get(f"/files/{sha256}"))
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise VTError(self._error_message(resp))
        try:
            return parse_file_object(resp.json()["data"])
        except (ValueError, KeyError, TypeError, AttributeError):
            raise VTError("Respuesta inesperada de VirusTotal") from None

    def upload_file(
        self,
        path: str,
        size: int,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> str:
        """Sube un archivo y devuelve el id del análisis."""
        filename = safe_upload_name(os.path.basename(path))
        if size > self.cfg.direct_upload_max_mb * 1024 * 1024:
            resp = self._request("files/upload_url", self._get("/files/upload_url"))
            if resp.status_code != 200:
                raise VTError(self._error_message(resp))
            try:
                url = str(resp.json()["data"])
            except (ValueError, KeyError, TypeError, AttributeError):
                raise VTError("Respuesta inesperada al pedir la URL de subida") from None
            if url.startswith("http://www.virustotal.com/"):
                url = "https://" + url[len("http://") :]
            if not url.startswith("https://www.virustotal.com/"):
                raise VTError("La URL de subida no es de virustotal.com; se cancela por seguridad")
            label, retries = "files/upload_large", 0  # cada URL de subida sirve una sola vez
        else:
            url, label, retries = f"{API_BASE}/files", "files/upload", 2

        def send() -> requests.Response:
            with open(fs_path(path), "rb") as f:
                encoder = MultipartEncoder(fields={"file": (filename, f, "application/octet-stream")})
                body: MultipartEncoder | MultipartEncoderMonitor = encoder
                if on_progress:
                    body = MultipartEncoderMonitor(
                        encoder, lambda m: on_progress(m.bytes_read, encoder.len)
                    )
                return self.session.post(
                    url,
                    data=body,
                    headers={"Content-Type": body.content_type},
                    timeout=(15, self.cfg.upload_timeout_seconds),
                )

        resp = self._request(label, send, retries=retries)
        if resp.status_code != 200:
            raise VTError(self._error_message(resp))
        try:
            return str(resp.json()["data"]["id"])
        except (ValueError, KeyError, TypeError, AttributeError):
            raise VTError("Respuesta inesperada tras la subida") from None

    def get_analysis(self, analysis_id: str, sha256: str) -> AnalysisStatus:
        resp = self._request("analyses", self._get(f"/analyses/{analysis_id}"))
        if resp.status_code == 404:
            return AnalysisStatus("missing")
        if resp.status_code != 200:
            raise VTError(self._error_message(resp))
        try:
            return parse_analysis_object(sha256, resp.json()["data"])
        except (ValueError, KeyError, TypeError, AttributeError):
            raise VTError("Respuesta inesperada al consultar el análisis") from None


def gui_url(sha256: str) -> str:
    return GUI_FILE_URL.format(sha256)


def check_api_key(api_key: str, timeout: float = 15) -> bool | None:
    """True si VirusTotal acepta la clave, False si la rechaza y None si no se
    pudo comprobar (sin conexión, por ejemplo). Consultar el propio usuario no
    gasta cuota."""
    try:
        resp = requests.get(
            f"{API_BASE}/users/{api_key}",
            headers={"x-apikey": api_key, "User-Agent": f"vtscan/{__version__}"},
            timeout=timeout,
        )
    except requests.RequestException:
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code in (401, 403, 404):
        return False
    return None
