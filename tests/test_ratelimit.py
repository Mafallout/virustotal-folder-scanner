from datetime import datetime, timezone

import pytest

from vtscanner.ratelimit import DailyQuotaExceeded, RateLimiter, next_reset


def limiter(db, clock, per_minute=4, daily=500):
    return RateLimiter(db, per_minute, daily, clock.time, clock.sleep)


def spend(lim, n):
    for _ in range(n):
        lim.wait_for_slot()
        lim.record("files", 200)


def test_four_per_minute_then_waits(db, clock):
    lim = limiter(db, clock)
    start = clock.now
    spend(lim, 4)
    assert clock.now == start
    waits = []
    lim.wait_for_slot(lambda left, reason: waits.append(left))
    assert clock.now >= start + 61
    assert waits and waits[0] > 59


def test_sliding_window_survives_restart(db, clock):
    spend(limiter(db, clock), 4)
    start = clock.now
    limiter(db, clock).wait_for_slot()  # otra instancia, misma base de datos
    assert clock.now >= start + 61


def test_daily_limit(db, clock):
    lim = limiter(db, clock, per_minute=100, daily=3)
    spend(lim, 3)
    assert lim.remaining_today() == 0
    with pytest.raises(DailyQuotaExceeded):
        lim.wait_for_slot()


def test_daily_quota_resets_at_utc_midnight(db, clock):
    lim = limiter(db, clock, per_minute=100, daily=3)
    spend(lim, 3)
    clock.now = next_reset(clock.now) + 1
    assert lim.remaining_today() == 3
    lim.wait_for_slot()


def test_server_sync(db, clock):
    lim = limiter(db, clock)
    spend(lim, 2)
    lim.sync_with_server(used=10, allowed=500)
    assert lim.used_today() == 10
    spend(lim, 1)
    assert lim.used_today() == 11
    assert lim.remaining_today() == 489
    lim.sync_with_server(used=11, allowed=200)
    assert lim.effective_daily_limit() == 200


def test_mark_exhausted_until_next_day(db, clock):
    lim = limiter(db, clock)
    lim.mark_exhausted()
    with pytest.raises(DailyQuotaExceeded):
        lim.wait_for_slot()
    clock.now = next_reset(clock.now) + 5
    lim.wait_for_slot()


def test_quota_lookups_do_not_count_for_daily_quota(db, clock):
    lim = limiter(db, clock)
    lim.wait_for_slot()
    lim.record("users", 200)
    assert lim.used_today() == 0
    spend(lim, 3)
    start = clock.now
    lim.wait_for_slot()  # pero sí cuentan para el límite por minuto
    assert clock.now >= start + 60


def test_next_reset_is_utc_midnight(clock):
    reset = datetime.fromtimestamp(next_reset(clock.now), timezone.utc)
    assert (reset.hour, reset.minute, reset.second) == (0, 0, 0)
    assert 0 < next_reset(clock.now) - clock.now <= 86400
