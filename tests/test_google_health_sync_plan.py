from __future__ import annotations

from heavenly_health.providers.google_health import data_types_for_metrics


def test_google_sync_plan_prefers_daily_summaries_and_reserves_raw_budget_for_activity() -> None:
    plan = data_types_for_metrics(
        frozenset(
            {
                "steps",
                "active_energy",
                "walking_running_distance",
                "heart_rate_variability",
                "oxygen_saturation",
                "vo2_max",
            }
        )
    )

    assert "daily-heart-rate-variability" in plan
    assert "daily-oxygen-saturation" in plan
    assert "daily-vo2-max" in plan
    assert "heart-rate-variability" not in plan
    assert "oxygen-saturation" not in plan
    assert "vo2-max" not in plan
    assert plan.index("distance") < plan.index("steps")
    assert plan.index("active-energy-burned") < plan.index("steps")
