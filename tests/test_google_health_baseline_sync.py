from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from heavenly_health.providers.common import ProviderStateStore
from heavenly_health.providers.google_health import GoogleHealthConnector


class _API:
    def __init__(self) -> None:
        self.starts: list[str] = []

    def identity(self):
        return {"healthUserId": "owner"}

    def list_data_points(self, data_type, *, start, end, limit):
        self.starts.append(start)
        return []


class _Store:
    settings = type("Settings", (), {"allowed_metrics": frozenset({"resting_heart_rate"})})()

    def ingest_provider_resource(self, **kwargs):
        return 0


def test_google_initial_sync_defaults_to_a_31_day_baseline_window(tmp_path: Path) -> None:
    api = _API()
    connector = GoogleHealthConnector(
        api,
        _Store(),
        ProviderStateStore(tmp_path / "provider-state"),
        data_types=("daily-resting-heart-rate",),
        clock=lambda: datetime(2026, 8, 9, tzinfo=timezone.utc),
    )

    connector.sync(limit=1)

    assert api.starts == ["2026-07-09T00:00:00Z"]
