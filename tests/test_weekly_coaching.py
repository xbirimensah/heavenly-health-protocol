from __future__ import annotations

from datetime import datetime, timedelta, timezone

from heavenly_health.weekly_coaching import build_weekly_coaching


def _event(metric_type: str, value: float, at: datetime) -> dict[str, object]:
    return {
        "metric_type": metric_type,
        "value_numeric": value,
        "event_at": at.isoformat(),
    }


def test_weekly_coaching_reports_sleep_recovery_and_actionable_priority() -> None:
    now = datetime(2026, 8, 9, 9, 30, tzinfo=timezone.utc)
    events = [
        _event("sleep_analysis", minutes, now - timedelta(days=day, hours=8))
        for day, minutes in enumerate((525, 300, 350, 251, 431, 246))
    ] + [
        _event("resting_heart_rate", value, now - timedelta(days=day + 1))
        for day, value in enumerate((56, 57, 60, 63, 63, 63, 63))
    ] + [
        _event("steps", 4_000, now - timedelta(days=day + 1))
        for day in range(6)
    ]

    result = build_weekly_coaching(events, now=now)

    assert result["status"] == "ready"
    assert result["sleep"]["main_sessions"] == 6
    assert result["sleep"]["average_minutes"] == 350.5
    assert result["sleep"]["sessions_under_7h"] == 4
    assert result["recovery"]["resting_heart_rate"]["latest"] == 56
    assert result["activity"]["steps"]["total"] == 24_000
    assert result["primary_focus"]["kind"] == "sleep_consistency"
    assert "HRV" in result["data_quality"]["missing_metrics"]


def test_weekly_coaching_is_candid_when_data_is_sparse() -> None:
    now = datetime(2026, 8, 9, 9, 30, tzinfo=timezone.utc)

    result = build_weekly_coaching([_event("sleep_analysis", 480, now - timedelta(hours=8))], now=now)

    assert result["status"] == "insufficient_data"
    assert result["primary_focus"] is None
    assert result["data_quality"]["available_metrics"] == ["sleep_analysis"]
    assert any("At least 3 main sleep sessions" in item for item in result["data_quality"]["limitations"])


def test_weekly_coaching_does_not_count_short_naps_as_main_sleep() -> None:
    now = datetime(2026, 8, 9, 9, 30, tzinfo=timezone.utc)
    events = [
        _event("sleep_analysis", 480, now - timedelta(days=day + 1, hours=8))
        for day in range(3)
    ] + [_event("sleep_analysis", 30, now - timedelta(days=1, hours=2))]

    result = build_weekly_coaching(events, now=now)

    assert result["sleep"]["main_sessions"] == 3
    assert result["sleep"]["short_sleep_entries"] == 1
