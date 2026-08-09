from __future__ import annotations

from datetime import datetime, timezone

import httpx

from heavenly_health.health_storage import SupabaseHealthStore, SupabaseSettings


def _settings() -> SupabaseSettings:
    configured = SupabaseSettings.from_environ(
        {
            "SUPABASE_URL": "https://project.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "private-test-service-role-key",
            "HEAVENLY_HEALTH_TABLE": "heavenly_health_events",
            "HEAVENLY_RAW_HEALTH_TABLE": "heavenly_health_raw_events",
            "HEAVENLY_ALLOWED_METRICS": "sleep_analysis,steps,resting_heart_rate",
        }
    )
    assert configured is not None
    return configured


def test_weekly_coaching_reads_a_bounded_week_of_all_relevant_allowlisted_metrics() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=[
                {
                    "metric_type": "sleep_analysis",
                    "value_numeric": 480,
                    "event_at": "2026-08-08T00:00:00Z",
                }
            ],
        )

    configured = _settings()
    store = SupabaseHealthStore(
        configured,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: datetime(2026, 8, 9, 9, 30, tzinfo=timezone.utc),
    )

    result = store.weekly_coaching()

    assert result["status"] == "insufficient_data"
    assert requests[0].url.params["metric_type"] == "in.(resting_heart_rate,sleep_analysis,steps)"
    assert requests[0].url.params["limit"] == "1000"
