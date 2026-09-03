from __future__ import annotations

from datetime import datetime, timezone
import json

import httpx
import pytest

from heavenly_health.health_storage import (
    HealthStorageError,
    SupabaseHealthStore,
    SupabaseSettings,
    normalize_health_auto_export_delivery,
)


def storage_environ(**overrides: str | None) -> dict[str, str]:
    environ = {
        "SUPABASE_URL": "https://project.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "private-test-service-role-key",
        "HEAVENLY_HEALTH_TABLE": "heavenly_health_events",
        "HEAVENLY_RAW_HEALTH_TABLE": "heavenly_health_raw_events",
        "HEAVENLY_ALLOWED_METRICS": "steps,resting_heart_rate,walking_step_length",
        "HEAVENLY_APPLE_HEALTH_DELIVERY_TABLE": "private_health_deliveries",
        "HEAVENLY_CONTEXT_TABLE": "private_documents",
        "HEAVENLY_CONTEXT_ID_COLUMN": "document_id",
        "HEAVENLY_CONTEXT_TITLE_COLUMN": "title",
        "HEAVENLY_CONTEXT_BODY_COLUMN": "body_text",
        "HEAVENLY_CONTEXT_SEARCH_COLUMN": "search_tsv",
        "HEAVENLY_CONTEXT_UPDATED_COLUMN": "updated_at",
    }
    for name, value in overrides.items():
        if value is None:
            environ.pop(name, None)
        else:
            environ[name] = value
    return environ


def settings() -> SupabaseSettings:
    configured = SupabaseSettings.from_environ(storage_environ())
    assert configured is not None
    return configured


def test_storage_is_disabled_when_both_supabase_values_are_absent() -> None:
    assert SupabaseSettings.from_environ({}) is None


def test_partial_or_unsafe_storage_configuration_fails_without_leaking_values() -> None:
    secret = "do-not-leak-service-role-key"
    with pytest.raises(HealthStorageError, match="SUPABASE_SERVICE_ROLE_KEY") as exc_info:
        SupabaseSettings.from_environ({"SUPABASE_URL": "https://project.supabase.co"})
    assert secret not in str(exc_info.value)

    with pytest.raises(HealthStorageError, match="HTTPS origin"):
        SupabaseSettings.from_environ(
            storage_environ(SUPABASE_URL="http://127.0.0.1:54321")
        )
    with pytest.raises(HealthStorageError, match="public HTTPS origin"):
        SupabaseSettings.from_environ(
            storage_environ(SUPABASE_URL="https://10.0.0.5")
        )
    with pytest.raises(HealthStorageError, match="public HTTPS origin"):
        SupabaseSettings.from_environ(
            storage_environ(SUPABASE_URL="https://credential-recipient.example")
        )
    with pytest.raises(HealthStorageError, match="identifier"):
        SupabaseSettings.from_environ(
            storage_environ(HEAVENLY_HEALTH_TABLE="events;drop table users")
        )


def test_storage_settings_hide_connection_values_and_require_an_explicit_metric_allowlist() -> None:
    configured = settings()
    rendered = repr(configured)

    assert configured.allowed_metrics == frozenset(
        {"steps", "resting_heart_rate", "walking_step_length"}
    )
    assert "private-test-service-role-key" not in rendered
    assert "project.supabase.co" not in rendered

    with pytest.raises(HealthStorageError, match="HEAVENLY_ALLOWED_METRICS"):
        SupabaseSettings.from_environ(storage_environ(HEAVENLY_ALLOWED_METRICS=""))


def test_query_health_events_enforces_allowlist_date_bounds_and_result_limit() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=[
                {
                    "id": "00000000-0000-4000-8000-000000000001",
                    "source": "health_auto_export",
                    "metric_type": "steps",
                    "event_at": "2026-07-14T06:00:00Z",
                    "value_numeric": 50,
                    "value_text": None,
                    "unit": "count",
                    "received_at": "2026-07-14T06:05:00Z",
                }
            ],
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    store = SupabaseHealthStore(settings(), http_client=client)

    result = store.query_events(
        start="2026-07-13T00:00:00Z",
        end="2026-07-15T00:00:00Z",
        metrics=["steps"],
        sources=["health_auto_export"],
        limit=500,
    )

    assert result["count"] == 1
    assert result["events"][0]["value_numeric"] == 50
    request = requests[0]
    assert request.url.path.endswith("/rest/v1/heavenly_health_events")
    assert request.url.params["metric_type"] == "in.(steps)"
    assert request.url.params["source"] == "in.(health_auto_export)"
    assert request.url.params["limit"] == "200"
    assert request.url.params["order"] == "event_at.asc"
    assert request.headers["apikey"] == "private-test-service-role-key"

    latest = store.query_events(
        start="2026-07-13T00:00:00Z",
        end="2026-07-15T00:00:00Z",
        metrics=["steps"],
        newest_first=True,
    )
    assert latest["count"] == 1
    assert requests[-1].url.params["order"] == "event_at.desc"

    with pytest.raises(HealthStorageError, match="not allowed"):
        store.query_events(
            start="2026-07-13T00:00:00Z",
            end="2026-07-15T00:00:00Z",
            metrics=["clinical_record"],
        )
    with pytest.raises(HealthStorageError, match="31 days"):
        store.query_events(
            start="2026-01-01T00:00:00Z",
            end="2026-07-15T00:00:00Z",
            metrics=["steps"],
        )


def test_connector_status_reports_real_freshness_without_returning_health_values() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["select"] == "source,event_at,received_at"
        return httpx.Response(
            200,
            json=[
                {
                    "source": "health_auto_export",
                    "event_at": "2026-07-14T05:30:00Z",
                    "received_at": "2026-07-14T05:35:00Z",
                }
            ],
        )

    store = SupabaseHealthStore(
        settings(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: datetime(2026, 7, 14, 6, 0, tzinfo=timezone.utc),
    )

    result = store.connector_status()

    assert result == {
        "storage": "supabase",
        "credential_scope": "service_role",
        "configured_connectors": [
            {
                "source": "health_auto_export",
                "mode": "push-delivery-with-bounded-normalization",
                "sync_supported": True,
                "latest_event_at": "2026-07-14T05:30:00Z",
                "last_received_at": "2026-07-14T05:35:00Z",
                "freshness": "fresh",
            }
        ],
    }
    assert "value_numeric" not in json.dumps(result)


def test_connector_status_and_sync_include_attached_google_and_garmin_runtime() -> None:
    class ProviderRuntime:
        def __init__(self):
            self.calls = []

        def statuses(self):
            return [
                {"source": "google_health", "connected": True, "sync_supported": True},
                {"source": "garmin", "connected": True, "sync_supported": True},
            ]

        def sync(self, source, store, *, limit):
            self.calls.append((source, store, limit))
            return {"source": source, "status": "completed"}

    runtime = ProviderRuntime()
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json=[]))
    )
    store = SupabaseHealthStore(settings(), http_client=client, provider_runtime=runtime)

    status = store.connector_status()
    synced = store.sync_source("google_health", limit=10)

    assert [item["source"] for item in status["configured_connectors"]][-2:] == [
        "google_health",
        "garmin",
    ]
    assert synced == {"source": "google_health", "status": "completed"}
    assert runtime.calls == [("google_health", store, 10)]


def test_normalizer_is_idempotent_allowlisted_and_drops_source_device_names() -> None:
    delivery = {
        "id": "00000000-0000-4000-8000-000000000010",
        "received_at": "2026-07-14T06:05:00Z",
        "payload": {
            "data": {
                "metrics": [
                    {
                        "name": "step_count",
                        "units": "count",
                        "data": [
                            {
                                "date": "2026-07-14T06:00:00Z",
                                "qty": 50,
                                "source": "Owner's private phone name",
                            }
                        ],
                    },
                    {
                        "name": "clinical_record",
                        "units": "record",
                        "data": [{"date": "2026-07-14T06:00:00Z", "qty": "private"}],
                    },
                ],
                "workouts": [],
            }
        },
    }

    first = normalize_health_auto_export_delivery(
        delivery,
        raw_event_id="00000000-0000-4000-8000-000000000020",
        allowed_metrics=frozenset({"steps"}),
    )
    second = normalize_health_auto_export_delivery(
        delivery,
        raw_event_id="00000000-0000-4000-8000-000000000020",
        allowed_metrics=frozenset({"steps"}),
    )

    assert first == second
    assert len(first) == 1
    event = first[0]
    assert event["metric_type"] == "steps"
    assert event["value_numeric"] == 50
    assert event["source_record_id"].startswith("health-auto-export:")
    assert event["metadata"]["provider_metric"] == "step_count"
    assert "source_hash" in event["metadata"]
    assert "Owner's private phone name" not in json.dumps(event)


def test_sync_health_auto_export_preserves_raw_provenance_and_upserts_normalized_rows() -> None:
    requests: list[httpx.Request] = []
    delivery = {
        "id": "00000000-0000-4000-8000-000000000010",
        "received_at": "2026-07-14T06:05:00Z",
        "payload_hash": "a" * 64,
        "payload": {
            "data": {
                "metrics": [
                    {
                        "name": "step_count",
                        "units": "count",
                        "data": [
                            {"date": "2026-07-14T06:00:00Z", "qty": 50, "source": "Phone"}
                        ],
                    }
                ],
                "workouts": [],
            }
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            assert request.url.path.endswith("/private_health_deliveries")
            return httpx.Response(200, json=[delivery])
        if request.url.path.endswith("/heavenly_health_raw_events"):
            body = json.loads(request.content)
            assert body["payload"] == delivery["payload"]
            assert body["source_record_id"] == delivery["id"]
            assert body["is_synthetic"] is False
            return httpx.Response(
                201,
                json=[{"id": "00000000-0000-4000-8000-000000000020"}],
            )
        if request.url.path.endswith("/heavenly_health_events"):
            body = json.loads(request.content)
            assert len(body) == 1
            assert body[0]["raw_event_id"] == "00000000-0000-4000-8000-000000000020"
            return httpx.Response(201, json=[{"id": "normalized-id"}])
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    store = SupabaseHealthStore(
        settings(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = store.sync_source("health_auto_export", limit=10)

    assert result == {
        "source": "health_auto_export",
        "deliveries_processed": 1,
        "events_upserted": 1,
        "status": "completed",
    }
    assert [request.method for request in requests] == ["GET", "POST", "POST"]
    assert requests[1].url.params["on_conflict"] == "source,source_record_id"
    assert requests[2].url.params["on_conflict"] == "source,source_record_id"


def test_context_search_returns_bounded_previews_from_only_the_configured_table() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/rest/v1/private_documents")
        assert request.url.params["search_tsv"] == "plfts.sleep recovery"
        return httpx.Response(
            200,
            json=[
                {
                    "document_id": "doc-1",
                    "title": "Recovery notes",
                    "body_text": "x" * 2000,
                    "updated_at": "2026-07-10T00:00:00Z",
                }
            ],
        )

    store = SupabaseHealthStore(
        settings(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = store.search_context("sleep recovery", limit=100, body_chars=200)

    assert result["count"] == 1
    assert len(result["matches"][0]["body_preview"]) == 200
    assert result["matches"][0]["body_preview"].endswith("…")


def test_manual_health_event_validation_never_accepts_synthetic_or_unallowlisted_payloads() -> None:
    store = SupabaseHealthStore(settings(), http_client=httpx.Client())

    event = store.build_manual_event(
        metric_type="resting_heart_rate",
        event_at="2026-07-14T06:00:00Z",
        value_numeric=55,
        value_text=None,
        unit="bpm",
        note="measured manually",
    )

    assert event["source"] == "manual"
    assert event["is_synthetic"] is False
    assert event["ingest_mode"] == "manual"
    assert event["metadata"] == {"note": "measured manually", "schema_version": "1.0"}
    assert datetime.fromisoformat(event["event_at"].replace("Z", "+00:00")).tzinfo == timezone.utc

    with pytest.raises(HealthStorageError, match="not allowed"):
        store.build_manual_event(
            metric_type="medication",
            event_at="2026-07-14T06:00:00Z",
            value_numeric=None,
            value_text="private",
            unit=None,
            note=None,
        )
    with pytest.raises(HealthStorageError, match="exactly one"):
        store.build_manual_event(
            metric_type="steps",
            event_at="2026-07-14T06:00:00Z",
            value_numeric=10,
            value_text="ten",
            unit="count",
            note=None,
        )


def scoped_environ(**overrides: str) -> dict[str, str]:
    return storage_environ(
        SUPABASE_HEALTH_ROLE_KEY="scoped-role-token",
        SUPABASE_PUBLISHABLE_KEY="project-publishable",
        **overrides,
    )


def test_a_scoped_role_token_replaces_service_role_on_the_authorization_header() -> None:
    """An operator drops project-wide rights by setting two values."""
    scoped = SupabaseSettings.from_environ(scoped_environ())
    assert scoped is not None
    assert scoped.bearer_token == "scoped-role-token"
    assert scoped.gateway_key == "project-publishable"
    assert scoped.uses_service_role is False

    service_role_only = settings()
    assert service_role_only.bearer_token == "private-test-service-role-key"
    assert service_role_only.gateway_key == "private-test-service-role-key"
    assert service_role_only.uses_service_role is True


def test_storage_accepts_a_scoped_token_without_any_service_role_key() -> None:
    configured = SupabaseSettings.from_environ(
        scoped_environ(SUPABASE_SERVICE_ROLE_KEY=None)
    )
    assert configured is not None
    assert configured.bearer_token == "scoped-role-token"


def test_a_scoped_token_alone_is_rejected_because_it_cannot_identify_the_project() -> None:
    """Supabase validates `apikey` against registered keys; a minted token is not one."""
    with pytest.raises(HealthStorageError, match="SUPABASE_PUBLISHABLE_KEY"):
        SupabaseSettings.from_environ(
            storage_environ(SUPABASE_HEALTH_ROLE_KEY="scoped-role-token")
        )


def test_the_anon_key_is_accepted_as_the_project_identifier() -> None:
    configured = SupabaseSettings.from_environ(
        storage_environ(
            SUPABASE_HEALTH_ROLE_KEY="scoped-role-token",
            SUPABASE_ANON_KEY="project-anon",
        )
    )
    assert configured is not None
    assert configured.gateway_key == "project-anon"


def test_the_project_key_and_the_role_token_are_sent_on_separate_headers() -> None:
    """Sending the role token as `apikey` fails every request as Invalid API key."""
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.headers["apikey"], request.headers["Authorization"]))
        return httpx.Response(200, json=[])

    configured = SupabaseSettings.from_environ(scoped_environ())
    assert configured is not None
    store = SupabaseHealthStore(
        configured,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    store.available_metrics()

    assert seen == [("project-publishable", "Bearer scoped-role-token")]
    assert store.connector_status()["credential_scope"] == "scoped_role"
