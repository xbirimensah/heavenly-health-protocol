from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from heavenly_health.providers.common import MemorySecretStore, ProviderStateStore
from heavenly_health.providers.google_health import (
    GOOGLE_CALLBACK_URL,
    GOOGLE_HEALTH_SCOPES,
    GoogleClientCredentials,
    GoogleHealthAPI,
    GoogleHealthConnector,
    GoogleHealthError,
    GoogleOAuthClient,
    normalize_google_data_point,
)


NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
ALLOWED = frozenset(
    {
        "steps",
        "heart_rate",
        "resting_heart_rate",
        "heart_rate_variability",
        "sleep_analysis",
        "body_mass",
    }
)


def client_json() -> dict[str, object]:
    return {
        "web": {
            "client_id": "client.apps.googleusercontent.com",
            "client_secret": "client-secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_CALLBACK_URL],
        }
    }


def test_google_client_import_requires_private_web_client_and_redacts(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    path.write_text(json.dumps(client_json()))
    path.chmod(0o600)

    credentials = GoogleClientCredentials.from_private_json(path)

    assert credentials.client_id.endswith(".apps.googleusercontent.com")
    assert credentials.redirect_uri == GOOGLE_CALLBACK_URL
    assert "client-secret" not in repr(credentials)

    path.chmod(0o644)
    with pytest.raises(GoogleHealthError, match="owner-only"):
        GoogleClientCredentials.from_private_json(path)


def test_google_authorization_uses_pkce_state_offline_and_read_only_scopes() -> None:
    oauth = GoogleOAuthClient(
        GoogleClientCredentials.from_payload(client_json()),
        MemorySecretStore(),
        clock=lambda: NOW,
    )

    request = oauth.authorization_request(ALLOWED)
    query = parse_qs(urlparse(request.url).query)

    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [request.state]
    assert query["redirect_uri"] == [GOOGLE_CALLBACK_URL]
    assert set(query["scope"][0].split()) == set(GOOGLE_HEALTH_SCOPES)
    assert request.code_verifier not in request.url


def test_google_code_exchange_and_refresh_preserve_refresh_token_without_leaks() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = parse_qs(request.content.decode())
        if body["grant_type"] == ["authorization_code"]:
            assert body["code"] == ["one-time-code"]
            assert body["code_verifier"] == ["pkce-verifier"]
            return httpx.Response(
                200,
                json={
                    "access_token": "first-access",
                    "refresh_token": "durable-refresh",
                    "expires_in": 3600,
                    "scope": " ".join(GOOGLE_HEALTH_SCOPES),
                    "token_type": "Bearer",
                },
            )
        assert body["refresh_token"] == ["durable-refresh"]
        return httpx.Response(
            200,
            json={
                "access_token": "second-access",
                "expires_in": 3600,
                "scope": " ".join(GOOGLE_HEALTH_SCOPES),
                "token_type": "Bearer",
            },
        )

    secrets = MemorySecretStore()
    oauth = GoogleOAuthClient(
        GoogleClientCredentials.from_payload(client_json()),
        secrets,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
    )

    first = oauth.exchange_code("one-time-code", code_verifier="pkce-verifier")
    refreshed = oauth.refresh(first)

    assert refreshed.access_token == "second-access"
    assert refreshed.refresh_token == "durable-refresh"
    assert secrets.get("google-health", "oauth-token") is not None
    assert all("first-access" not in repr(request) for request in requests)


def test_google_saved_token_access_and_revocation_lifecycle() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    secrets = MemorySecretStore()
    credentials = GoogleClientCredentials.from_payload(client_json())
    secrets.set(GoogleOAuthClient.SERVICE, GoogleOAuthClient.CLIENT_ACCOUNT, credentials.to_json())
    secrets.set(
        GoogleOAuthClient.SERVICE,
        GoogleOAuthClient.TOKEN_ACCOUNT,
        json.dumps(
            {
                "access_token": "live-access",
                "refresh_token": "live-refresh",
                "expires_at": "2026-07-14T13:00:00Z",
                "scopes": list(GOOGLE_HEALTH_SCOPES),
                "token_type": "Bearer",
            }
        ),
    )
    oauth = GoogleOAuthClient.load(
        secrets,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: NOW,
    )

    assert oauth.access_token() == "live-access"
    oauth.revoke()

    assert secrets.get(GoogleOAuthClient.SERVICE, GoogleOAuthClient.TOKEN_ACCOUNT) is None
    assert requests[-1].url == httpx.URL("https://oauth2.googleapis.com/revoke")


def test_google_import_credentials_and_missing_connection_fail_safely(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    path.write_text(json.dumps(client_json()))
    path.chmod(0o600)
    secrets = MemorySecretStore()

    GoogleOAuthClient.import_credentials(path, secrets)
    assert GoogleOAuthClient.load(secrets).credentials.redirect_uri == GOOGLE_CALLBACK_URL

    secrets.delete(GoogleOAuthClient.SERVICE, GoogleOAuthClient.TOKEN_ACCOUNT)
    with pytest.raises(GoogleHealthError, match="not connected"):
        GoogleOAuthClient.load(secrets).access_token()


def test_google_revalidates_stored_client_before_using_endpoints() -> None:
    secrets = MemorySecretStore()
    secrets.set(
        GoogleOAuthClient.SERVICE,
        GoogleOAuthClient.CLIENT_ACCOUNT,
        json.dumps(
            {
                "client_id": "client.apps.googleusercontent.com",
                "client_secret": "secret",
                "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_url": "https://attacker.example/token",
                "redirect_uri": GOOGLE_CALLBACK_URL,
            }
        ),
    )

    with pytest.raises(GoogleHealthError, match="approved public HTTPS"):
        GoogleOAuthClient.load(secrets)


def test_google_api_verifies_identity_and_pages_a_bounded_data_window() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer access-token"
        if request.url.path.endswith("/identity"):
            return httpx.Response(
                200,
                json={"name": "users/me/identity", "healthUserId": "health-user-1"},
            )
        if "pageToken=next-page" in str(request.url):
            return httpx.Response(200, json={"dataPoints": [{"name": "step-2"}]})
        return httpx.Response(
            200,
            json={"dataPoints": [{"name": "step-1"}], "nextPageToken": "next-page"},
        )

    api = GoogleHealthAPI(
        token_provider=lambda: "access-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    assert api.identity()["healthUserId"] == "health-user-1"
    points = api.list_data_points(
        "steps",
        start="2026-07-13T00:00:00Z",
        end="2026-07-14T00:00:00Z",
        limit=2,
    )

    assert [point["name"] for point in points] == ["step-1", "step-2"]
    assert requests[-1].url.params["pageToken"] == "next-page"


def test_google_api_rejects_unknown_data_type_and_invalid_identity() -> None:
    api = GoogleHealthAPI(
        token_provider=lambda: "token",
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={}))
        ),
    )

    with pytest.raises(GoogleHealthError, match="identity"):
        api.identity()
    with pytest.raises(GoogleHealthError, match="Unsupported"):
        api.list_data_points(
            "unknown",
            start="2026-07-13T00:00:00Z",
            end="2026-07-14T00:00:00Z",
            limit=10,
        )


def test_google_sleep_page_size_respects_provider_limit() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"dataPoints": []})

    api = GoogleHealthAPI(
        token_provider=lambda: "token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    api.list_data_points(
        "sleep",
        start="2026-07-13T00:00:00Z",
        end="2026-07-14T00:00:00Z",
        limit=1000,
    )

    assert requests[0].url.params["pageSize"] == "25"


def test_google_api_retries_rate_limits_and_transient_server_failures() -> None:
    attempts = 0
    delays: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if attempts == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"dataPoints": []})

    api = GoogleHealthAPI(
        token_provider=lambda: "token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        sleeper=delays.append,
    )
    api.list_data_points(
        "steps",
        start="2026-07-13T00:00:00Z",
        end="2026-07-14T00:00:00Z",
        limit=10,
    )

    assert attempts == 3
    assert len(delays) == 2
    assert all(0 <= delay <= 5 for delay in delays)


@pytest.mark.parametrize(
    ("data_type", "point", "metric", "value", "unit"),
    [
        (
            "steps",
            {
                "name": "users/1/dataTypes/steps/dataPoints/a",
                "steps": {
                    "interval": {
                        "startTime": "2026-07-14T10:00:00Z",
                        "endTime": "2026-07-14T10:01:00Z",
                    },
                    "count": "40",
                },
            },
            "steps",
            40,
            "count",
        ),
        (
            "heart-rate",
            {
                "name": "users/1/dataTypes/heart-rate/dataPoints/b",
                "heartRate": {
                    "sampleTime": {"physicalTime": "2026-07-14T10:02:00Z"},
                    "beatsPerMinute": 64,
                },
            },
            "heart_rate",
            64,
            "bpm",
        ),
        (
            "daily-resting-heart-rate",
            {
                "name": "users/1/dataTypes/daily-resting-heart-rate/dataPoints/c",
                "dailyRestingHeartRate": {
                    "date": {"year": 2026, "month": 7, "day": 14},
                    "beatsPerMinute": 52,
                },
            },
            "resting_heart_rate",
            52,
            "bpm",
        ),
        (
            "weight",
            {
                "name": "users/1/dataTypes/weight/dataPoints/d",
                "weight": {
                    "sampleTime": {"physicalTime": "2026-07-14T10:03:00Z"},
                    "kilograms": 78.2,
                },
            },
            "body_mass",
            78.2,
            "kg",
        ),
    ],
)
def test_google_normalizer_uses_stable_native_identity_and_allowlist(
    data_type: str,
    point: dict[str, object],
    metric: str,
    value: float,
    unit: str,
) -> None:
    events = normalize_google_data_point(data_type, point, allowed_metrics=ALLOWED)

    assert len(events) == 1
    assert events[0]["source"] == "google_health"
    assert events[0]["metric_type"] == metric
    assert events[0]["value_numeric"] == value
    assert events[0]["unit"] == unit
    assert events[0]["source_record_id"].startswith("google-health:")
    assert "dataSource" not in events[0]["metadata"]


def test_google_connector_commits_checkpoint_only_after_raw_and_normalized_storage(
    tmp_path: Path,
) -> None:
    class FakeAPI:
        def identity(self):
            return {"healthUserId": "stable-health-user"}

        def list_data_points(self, data_type, *, start, end, limit):
            assert data_type == "steps"
            return [
                {
                    "name": "users/1/dataTypes/steps/dataPoints/a",
                    "steps": {
                        "interval": {
                            "startTime": start,
                            "endTime": end,
                        },
                        "count": "100",
                    },
                }
            ]

    class FakeStore:
        settings = type("Settings", (), {"allowed_metrics": frozenset({"steps"})})()

        def __init__(self):
            self.records = []

        def ingest_provider_resource(self, **kwargs):
            self.records.append(kwargs)
            return len(kwargs["events"])

    state = ProviderStateStore(tmp_path / "state")
    store = FakeStore()
    connector = GoogleHealthConnector(
        FakeAPI(),
        store,
        state,
        data_types=("steps",),
        clock=lambda: NOW,
    )

    result = connector.sync(days=1, limit=10)

    assert result == {
        "source": "google_health",
        "records_processed": 1,
        "events_upserted": 1,
        "status": "completed",
    }
    assert store.records[0]["source"] == "google_health"
    saved = state.load("google_health")
    assert saved["identity_hash"] != "stable-health-user"
    assert saved["checkpoints"]["steps"] == "2026-07-14T12:00:00Z"
    assert connector.status()["connected"] is True


def test_google_sleep_normalization_and_metric_scope_selection() -> None:
    events = normalize_google_data_point(
        "sleep",
        {
            "name": "users/1/dataTypes/sleep/dataPoints/a",
            "sleep": {
                "interval": {
                    "startTime": "2026-07-14T00:00:00Z",
                    "endTime": "2026-07-14T08:00:00Z",
                }
            },
        },
        allowed_metrics=frozenset({"sleep_analysis"}),
    )

    assert events[0]["value_numeric"] == 8.0
    assert events[0]["unit"] == "h"
    assert normalize_google_data_point("sleep", {}, allowed_metrics=frozenset({"steps"})) == []


def test_google_daily_filter_uses_snake_case_data_type_restriction() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"dataPoints": []})

    api = GoogleHealthAPI(
        token_provider=lambda: "token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    api.list_data_points(
        "daily-resting-heart-rate",
        start="2026-07-08T00:00:00Z",
        end="2026-07-15T00:00:00Z",
        limit=10,
    )

    assert requests[0].url.params["filter"] == (
        'daily_resting_heart_rate.date >= "2026-07-08"'
        ' AND daily_resting_heart_rate.date < "2026-07-15"'
    )


@pytest.mark.parametrize(
    ("data_type", "expected_filter"),
    [
        (
            "daily-resting-heart-rate",
            'daily_resting_heart_rate.date >= "2026-07-15"'
            ' AND daily_resting_heart_rate.date < "2026-07-16"',
        ),
        (
            "sleep",
            'sleep.interval.civil_end_time >= "2026-07-15"'
            ' AND sleep.interval.civil_end_time < "2026-07-16"',
        ),
    ],
)
def test_google_date_filters_never_collapse_same_day_windows(
    data_type: str, expected_filter: str
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"dataPoints": []})

    api = GoogleHealthAPI(
        token_provider=lambda: "token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    api.list_data_points(
        data_type,
        start="2026-07-15T07:13:00Z",
        end="2026-07-15T08:20:00Z",
        limit=10,
    )

    assert requests[0].url.params["filter"] == expected_filter


def test_google_connector_keeps_checkpoint_when_budget_truncates_window(
    tmp_path: Path,
) -> None:
    class FakeAPI:
        def identity(self):
            return {"healthUserId": "stable-health-user"}

        def list_data_points(self, data_type, *, start, end, limit):
            return [
                {
                    "name": f"users/1/dataTypes/steps/dataPoints/{index}",
                    "steps": {
                        "interval": {
                            "startTime": "2026-07-14T10:00:00Z",
                            "endTime": "2026-07-14T10:01:00Z",
                        },
                        "count": "1",
                    },
                }
                for index in range(limit)
            ]

    class FakeStore:
        settings = type("Settings", (), {"allowed_metrics": frozenset({"steps"})})()

        def ingest_provider_resource(self, **kwargs):
            return len(kwargs["events"])

    state = ProviderStateStore(tmp_path / "state")
    connector = GoogleHealthConnector(
        FakeAPI(),
        FakeStore(),
        state,
        data_types=("steps",),
        clock=lambda: NOW,
    )

    result = connector.sync(days=7, limit=5)

    assert result["records_processed"] == 5
    saved = state.load("google_health")
    assert "steps" not in saved["checkpoints"]

    follow_up = connector.sync(days=7, limit=5)
    assert follow_up["records_processed"] == 5
    assert "steps" not in state.load("google_health")["checkpoints"]


def test_google_data_types_order_low_volume_summaries_before_samples() -> None:
    from heavenly_health.providers.google_health import data_types_for_metrics

    ordered = data_types_for_metrics(
        frozenset(
            {
                "steps",
                "heart_rate",
                "resting_heart_rate",
                "heart_rate_variability",
                "sleep_analysis",
                "body_mass",
                "walking_running_distance",
                "active_energy",
                "oxygen_saturation",
                "respiratory_rate",
                "vo2_max",
            }
        )
    )

    high_volume = {"steps", "heart-rate", "distance", "active-energy-burned", "oxygen-saturation"}
    first_high_volume = min(ordered.index(item) for item in high_volume if item in ordered)
    low_volume = [item for item in ordered if item not in high_volume]
    assert low_volume, "expected summary data types in the plan"
    assert all(ordered.index(item) < first_high_volume for item in low_volume)


def _sleep_point_with_stages() -> dict:
    return {
        "name": "users/1/dataTypes/sleep/dataPoints/a",
        "sleep": {
            "interval": {
                "startTime": "2026-07-14T00:00:00Z",
                "endTime": "2026-07-14T08:00:00Z",
            },
            "summary": {
                "stagesSummary": [
                    {"type": "DEEP", "minutes": 90},
                    {"type": "REM", "minutes": 105},
                    {"type": "../../etc/passwd", "minutes": 5},
                ]
            },
        },
    }


def test_google_sleep_stages_are_emitted_only_when_the_owner_allowlists_them() -> None:
    events = normalize_google_data_point(
        "sleep",
        _sleep_point_with_stages(),
        allowed_metrics=frozenset({"sleep_analysis", "sleep_deep"}),
    )

    emitted = {event["metric_type"]: event for event in events}
    assert set(emitted) == {"sleep_analysis", "sleep_deep"}
    assert emitted["sleep_deep"]["value_numeric"] == 90
    assert emitted["sleep_deep"]["unit"] == "min"
    assert emitted["sleep_deep"]["source_record_id"].endswith(":deep")


def test_google_sleep_stage_names_never_become_unvetted_metric_identifiers() -> None:
    """A provider-supplied stage label must not reach storage as a new metric."""
    events = normalize_google_data_point(
        "sleep",
        _sleep_point_with_stages(),
        allowed_metrics=frozenset({"sleep_analysis"}),
    )

    assert [event["metric_type"] for event in events] == ["sleep_analysis"]
