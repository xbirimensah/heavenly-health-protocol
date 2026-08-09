"""Bounded, evidence-led weekly coaching from normalized owner-approved events.

This module reports observed trends and coverage gaps.  It deliberately avoids
medical claims, opaque readiness scores, or coaching from missing metrics.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any, Mapping, Sequence

_MAIN_SLEEP_MINUTES = 180
_SLEEP_TARGET_MINUTES = 420
_MIN_MAIN_SLEEP_SESSIONS = 3
_COACHING_WINDOW = timedelta(days=7)
_METRIC_LABELS = {
    "heart_rate_variability": "HRV",
    "resting_heart_rate": "resting heart rate",
    "sleep_analysis": "sleep",
    "sleep_deep": "deep sleep",
    "sleep_rem": "REM sleep",
    "steps": "steps",
    "active_energy": "active energy",
    "walking_running_distance": "walking/running distance",
    "workout_duration": "workout duration",
    "body_mass": "body mass",
}
WEEKLY_COACHING_METRICS = (
    "sleep_analysis",
    "resting_heart_rate",
    "heart_rate_variability",
    "steps",
    "active_energy",
    "walking_running_distance",
    "workout_duration",
)
_ACTIVITY_METRICS = ("steps", "active_energy", "walking_running_distance", "workout_duration")


def build_weekly_coaching(
    events: Sequence[Mapping[str, object]], *, now: datetime | None = None
) -> dict[str, Any]:
    """Summarize the last seven days of bounded normalized health events.

    A report is only *ready* once enough main sleep sessions exist to say
    something useful about consistency. Other metrics remain optional and are
    explicitly reported as coverage gaps rather than inferred.
    """
    reference = _aware_now(now)
    window_start = reference - _COACHING_WINDOW
    observations = [
        observation
        for observation in _parse_observations(events)
        if window_start <= observation[2] <= reference
    ]
    available = sorted({metric for metric, _, _ in observations})
    data_through = max((at for _, _, at in observations), default=None)

    sleep_values = sorted(
        ((value, at) for metric, value, at in observations if metric == "sleep_analysis" and value >= _MAIN_SLEEP_MINUTES),
        key=lambda item: item[1],
    )
    short_sleep_entries = sum(
        1
        for metric, value, _ in observations
        if metric == "sleep_analysis" and value < _MAIN_SLEEP_MINUTES
    )
    sleep = _sleep_summary(sleep_values, short_sleep_entries)
    recovery = _recovery_summary(observations)
    activity = _activity_summary(observations)

    missing = [
        _METRIC_LABELS[metric]
        for metric in WEEKLY_COACHING_METRICS
        if metric not in available
    ]
    limitations: list[str] = []
    if len(sleep_values) < _MIN_MAIN_SLEEP_SESSIONS:
        limitations.append(f"At least {_MIN_MAIN_SLEEP_SESSIONS} main sleep sessions are required for weekly coaching.")
    if missing:
        limitations.append("Not available this week: " + ", ".join(missing) + ".")

    ready = len(sleep_values) >= _MIN_MAIN_SLEEP_SESSIONS
    return {
        "status": "ready" if ready else "insufficient_data",
        "period": {"start": window_start.isoformat(), "end": reference.isoformat()},
        "data_quality": {
            "data_through": data_through.isoformat() if data_through else None,
            "available_metrics": available,
            "missing_metrics": missing,
            "limitations": limitations,
        },
        "sleep": sleep,
        "recovery": recovery,
        "activity": activity,
        "primary_focus": _primary_focus(sleep) if ready else None,
    }


def _sleep_summary(
    sessions: Sequence[tuple[float, datetime]], short_entries: int
) -> dict[str, Any]:
    values = [value for value, _ in sessions]
    latest = sessions[-1] if sessions else None
    return {
        "main_sessions": len(values),
        "average_minutes": round(mean(values), 1) if values else None,
        "sessions_under_7h": sum(value < _SLEEP_TARGET_MINUTES for value in values),
        "latest_minutes": latest[0] if latest else None,
        "latest_observed_at": latest[1].isoformat() if latest else None,
        "short_sleep_entries": short_entries,
    }


def _recovery_summary(observations: Sequence[tuple[str, float, datetime]]) -> dict[str, Any]:
    values = sorted(
        ((value, at) for metric, value, at in observations if metric == "resting_heart_rate"),
        key=lambda item: item[1],
    )
    if not values:
        return {"resting_heart_rate": None}
    first, latest = values[0], values[-1]
    return {
        "resting_heart_rate": {
            "samples": len(values),
            "average": round(mean(value for value, _ in values), 1),
            "first": first[0],
            "latest": latest[0],
            "direction": "lower" if latest[0] < first[0] else "higher" if latest[0] > first[0] else "stable",
            "latest_observed_at": latest[1].isoformat(),
        }
    }


def _activity_summary(observations: Sequence[tuple[str, float, datetime]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for metric in _ACTIVITY_METRICS:
        values = [value for observed_metric, value, _ in observations if observed_metric == metric]
        if values:
            result[metric] = {"total": round(sum(values), 1), "samples": len(values)}
    return result


def _primary_focus(sleep: Mapping[str, object]) -> dict[str, str]:
    raw_sessions_under_target = sleep.get("sessions_under_7h")
    sessions_under_target = int(raw_sessions_under_target) if isinstance(raw_sessions_under_target, (int, float)) else 0
    if sessions_under_target:
        return {
            "kind": "sleep_consistency",
            "title": "Make 7+ hours the default",
            "reason": f"{sessions_under_target} of your recorded main sleep sessions were under 7 hours.",
        }
    return {
        "kind": "maintain_sleep",
        "title": "Protect your sleep consistency",
        "reason": "Your recorded main sleep sessions met the 7-hour consistency target.",
    }


def _parse_observations(events: Sequence[Mapping[str, object]]) -> list[tuple[str, float, datetime]]:
    parsed: list[tuple[str, float, datetime]] = []
    for event in events:
        metric = event.get("metric_type")
        value = event.get("value_numeric")
        timestamp = event.get("event_at")
        if not isinstance(metric, str) or not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        if not isinstance(timestamp, str):
            continue
        try:
            observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if observed_at.tzinfo is None:
            continue
        parsed.append((metric, float(value), observed_at.astimezone(timezone.utc)))
    return parsed


def _aware_now(value: datetime | None) -> datetime:
    reference = value or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return reference.astimezone(timezone.utc)
