from __future__ import annotations

from heavenly_health.providers.google_health import _google_filter, data_types_for_metrics, normalize_google_data_point


def test_google_exercise_normalizes_to_allowlisted_workout_duration() -> None:
    events = normalize_google_data_point(
        "exercise",
        {
            "name": "users/1/dataTypes/exercise/dataPoints/workout-1",
            "exercise": {
                "interval": {
                    "startTime": "2026-08-08T08:00:00Z",
                    "endTime": "2026-08-08T09:15:00Z",
                },
                "activeDuration": "4500s",
            },
        },
        allowed_metrics=frozenset({"workout_duration"}),
    )

    assert events[0]["metric_type"] == "workout_duration"
    assert events[0]["value_numeric"] == 75
    assert events[0]["unit"] == "min"
    assert data_types_for_metrics(frozenset({"workout_duration"})) == ("exercise",)
    assert _google_filter("exercise", "2026-08-01T00:00:00Z", "2026-08-08T00:00:00Z") == (
        'exercise.interval.civil_start_time >= "2026-08-01" '
        'AND exercise.interval.civil_start_time < "2026-08-08"'
    )
