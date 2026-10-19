"""Límite de peticiones: 4 por minuto (ventana deslizante) y cuota diaria que se
reinicia a las 00:00 UTC. Todo se guarda en SQLite para que sobreviva a reinicios."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from .db import Database

WaitCallback = Callable[[float, str], None]

WINDOW_SECONDS = 61.0  # 60 s + 1 s de margen
META_EXHAUSTED = "quota_exhausted_day"
META_SYNC = "quota_server_sync"


class DailyQuotaExceeded(Exception):
    """Se ha agotado la cuota diaria de la API."""


def utc_day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def utc_day_start(ts: float) -> float:
    day = datetime.fromtimestamp(ts, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return day.timestamp()


def next_reset(ts: float) -> float:
    """Momento del próximo reinicio de la cuota diaria (00:00 UTC)."""
    return (datetime.fromtimestamp(utc_day_start(ts), timezone.utc) + timedelta(days=1)).timestamp()


def format_local_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


class RateLimiter:
    def __init__(
        self,
        db: Database,
        per_minute: int = 4,
        daily_limit: int = 500,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.db = db
        self.per_minute = per_minute
        self.daily_limit = daily_limit
        self.clock = clock
        self.sleeper = sleeper
        self.requests_this_run = 0
        db.prune_requests(clock() - 3 * 86400)

    # ---- cuota diaria -------------------------------------------------------

    def _server_offset(self, now: float) -> int:
        raw = self.db.get_meta(META_SYNC)
        if not raw:
            return 0
        try:
            sync = json.loads(raw)
        except ValueError:
            return 0
        if sync.get("day") != utc_day(now):
            return 0
        return max(0, int(sync.get("offset", 0)))

    def effective_daily_limit(self, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        raw = self.db.get_meta(META_SYNC)
        if raw:
            try:
                sync = json.loads(raw)
                if sync.get("day") == utc_day(now) and sync.get("allowed"):
                    return min(self.daily_limit, int(sync["allowed"]))
            except (ValueError, TypeError):
                pass
        return self.daily_limit

    def used_today(self, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        local = self.db.count_requests_since(utc_day_start(now))
        return local + self._server_offset(now)

    def remaining_today(self, now: float | None = None) -> int:
        now = self.clock() if now is None else now
        if self.db.get_meta(META_EXHAUSTED) == utc_day(now):
            return 0
        return max(0, self.effective_daily_limit(now) - self.used_today(now))

    def sync_with_server(self, used: int, allowed: int | None) -> None:
        """Ajusta la cuenta local con el dato real de VirusTotal."""
        now = self.clock()
        local = self.db.count_requests_since(utc_day_start(now))
        sync = {"day": utc_day(now), "offset": max(0, used - local), "allowed": allowed}
        self.db.set_meta(META_SYNC, json.dumps(sync))

    def mark_exhausted(self) -> None:
        self.db.set_meta(META_EXHAUSTED, utc_day(self.clock()))

    def next_reset(self) -> float:
        return next_reset(self.clock())

    # ---- límite por minuto --------------------------------------------------

    def _sleep_until(self, target: float, reason: str, on_wait: WaitCallback | None) -> None:
        while True:
            left = target - self.clock()
            if left <= 0:
                return
            if on_wait:
                on_wait(left, reason)
            self.sleeper(min(1.0, left))

    def wait_for_slot(self, on_wait: WaitCallback | None = None) -> None:
        """Bloquea hasta que se pueda hacer una petición sin pasarse de los límites."""
        if self.remaining_today() <= 0:
            raise DailyQuotaExceeded()
        while True:
            now = self.clock()
            recent = self.db.request_times_after(now - WINDOW_SECONDS)
            if len(recent) < self.per_minute:
                return
            oldest_blocking = recent[len(recent) - self.per_minute]
            self._sleep_until(
                oldest_blocking + WINDOW_SECONDS,
                f"límite de {self.per_minute} peticiones por minuto",
                on_wait,
            )

    def cooldown(self, seconds: float, reason: str, on_wait: WaitCallback | None = None) -> None:
        self._sleep_until(self.clock() + seconds, reason, on_wait)

    def record(self, endpoint: str, http_status: int | None) -> None:
        self.db.log_request(self.clock(), endpoint, http_status)
        self.requests_this_run += 1
