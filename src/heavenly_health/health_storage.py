"""Schema-aware Supabase health storage with bounded, allowlisted operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse
from uuid import UUID

import httpx

from heavenly_health.daily_briefing import build_daily_briefing
from heavenly_health.daily_state import DAILY_STATE_METRICS, evaluate_daily_state
from heavenly_health.weekly_coaching import WEEKLY_COACHING_METRICS, build_weekly_coaching

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_FILTER_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_MAX_QUERY_DAYS = 31
_MAX_QUERY_RESULTS = 200
_MAX_SYNC_DELIVERIES = 100
_MAX_AGGREGATE_EVENTS = 10_000
_AGGREGATE_PAGE_SIZE = 1_000
_PROVIDER_SOURCES = frozenset({"google_health", "garmin", "whoop", "oura"})
_PROVIDER_RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PROVIDER_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,511}$")

_PROVIDER_METRICS = {
    "step count": "steps",
    "steps": "steps",
    "walking running distance": "walking_running_distance",
    "walking step length": "walking_step_length",
    "active energy": "active_energy",
    "active energy burned": "active_energy",
    "basal energy": "basal_energy",
    "basal energy burned": "basal_energy",
    "sleep analysis": "sleep_analysis",
    "heart rate": "heart_rate",
    "resting heart rate": "resting_heart_rate",
    "heart rate variability": "heart_rate_variability",
    "body mass": "body_mass",
    "weight": "body_mass",
}


class HealthStorageError(RuntimeError):
    """A health storage request is absent, unsafe, invalid, or unavailable."""


@dataclass(frozen=True)
class SupabaseSettings:
    """Validated settings whose endpoint and credential are never represented."""

    supabase_url: str = field(repr=False)
    service_role_key: str = field(repr=False)
    health_table: str
    raw_health_table: str
    allowed_metrics: frozenset[str]
    health_role_key: str | None = field(default=None, repr=False)
    publishable_key: str | None = field(default=None, repr=False)
    apple_health_delivery_table: str | None = None
    context_table: str | None = None
    context_id_column: str | None = None
    context_title_column: str | None = None
    context_body_column: str | None = None
    context_search_column: str | None = None
    context_updated_column: str | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> SupabaseSettings | None:
        url = environ.get("SUPABASE_URL", "").strip()
        key = environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        scoped_key = environ.get("SUPABASE_HEALTH_ROLE_KEY", "").strip()
        publishable_key = (
            environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
            or environ.get("SUPABASE_ANON_KEY", "").strip()
        )
        if not url and not key and not scoped_key:
            return None
        missing = [name for name, value in (("SUPABASE_URL", url),) if not value]
        if not key and not scoped_key:
            missing.append("SUPABASE_HEALTH_ROLE_KEY or SUPABASE_SERVICE_ROLE_KEY")
        if missing:
            raise HealthStorageError("Incomplete Supabase configuration; missing: " + ", ".join(missing))
        if scoped_key and not publishable_key:
            # Supabase validates `apikey` against the project's registered keys and
            # reads the role from `Authorization`. A minted role token is not a
            # registered key, so on its own every request fails as "Invalid API key"
            # before RLS is ever consulted.
            raise HealthStorageError(
                "SUPABASE_HEALTH_ROLE_KEY also requires SUPABASE_PUBLISHABLE_KEY "
                "(or SUPABASE_ANON_KEY) to identify the project"
            )
        _validate_supabase_origin(url)

        health_table = _validated_identifier(
            "HEAVENLY_HEALTH_TABLE",
            environ.get("HEAVENLY_HEALTH_TABLE", "heavenly_health_events"),
        )
        raw_table = _validated_identifier(
            "HEAVENLY_RAW_HEALTH_TABLE",
            environ.get("HEAVENLY_RAW_HEALTH_TABLE", "heavenly_health_raw_events"),
        )
        raw_metrics = environ.get("HEAVENLY_ALLOWED_METRICS", "").strip()
        metrics = frozenset(item.strip() for item in raw_metrics.split(",") if item.strip())
        if not metrics or any(_IDENTIFIER.fullmatch(metric) is None for metric in metrics):
            raise HealthStorageError(
                "HEAVENLY_ALLOWED_METRICS must be an explicit comma-separated metric identifier allowlist"
            )

        context_table = _optional_identifier("HEAVENLY_CONTEXT_TABLE", environ)
        context_names = {
            name: _optional_identifier(name, environ)
            for name in (
                "HEAVENLY_CONTEXT_ID_COLUMN",
                "HEAVENLY_CONTEXT_TITLE_COLUMN",
                "HEAVENLY_CONTEXT_BODY_COLUMN",
                "HEAVENLY_CONTEXT_SEARCH_COLUMN",
                "HEAVENLY_CONTEXT_UPDATED_COLUMN",
            )
        }
        if context_table and not all(context_names.values()):
            missing_context = ", ".join(name for name, value in context_names.items() if not value)
            raise HealthStorageError(f"Context table configuration is incomplete; missing: {missing_context}")
        if not context_table and any(context_names.values()):
            raise HealthStorageError("HEAVENLY_CONTEXT_TABLE is required when context columns are configured")

        return cls(
            supabase_url=url.rstrip("/"),
            service_role_key=key,
            health_table=health_table,
            raw_health_table=raw_table,
            allowed_metrics=metrics,
            health_role_key=scoped_key or None,
            publishable_key=publishable_key or None,
            apple_health_delivery_table=_optional_identifier(
                "HEAVENLY_APPLE_HEALTH_DELIVERY_TABLE", environ
            ),
            context_table=context_table,
            context_id_column=context_names["HEAVENLY_CONTEXT_ID_COLUMN"],
            context_title_column=context_names["HEAVENLY_CONTEXT_TITLE_COLUMN"],
            context_body_column=context_names["HEAVENLY_CONTEXT_BODY_COLUMN"],
            context_search_column=context_names["HEAVENLY_CONTEXT_SEARCH_COLUMN"],
            context_updated_column=context_names["HEAVENLY_CONTEXT_UPDATED_COLUMN"],
        )

    @property
    def gateway_key(self) -> str:
        """Return the registered project key for the `apikey` header.

        This header identifies the project to Supabase's gateway; it does not
        select a database role. Service-role doubles as both, but a scoped
        deployment must present the publishable key here.
        """
        if self.health_role_key:
            return self.publishable_key or ""
        return self.service_role_key

    @property
    def bearer_token(self) -> str:
        """Return the credential that selects the database role.

        The scoped role token is preferred whenever one is configured, so an
        operator moves off service-role by setting two values.
        """
        return self.health_role_key or self.service_role_key

    @property
    def uses_service_role(self) -> bool:
        """Report whether requests still run with RLS-bypassing service-role rights."""
        return not self.health_role_key


class SupabaseHealthStore:
    """Perform only fixed-table REST operations; arbitrary SQL is never accepted."""

    def __init__(
        self,
        settings: SupabaseSettings,
        *,
        http_client: httpx.Client | None = None,
        clock: Callable[[], datetime] | None = None,
        provider_runtime: Any | None = None,
    ) -> None:
        self.settings = settings
        self._client = http_client or httpx.Client(timeout=30)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._provider_runtime = provider_runtime

    def query_events(
        self,
        *,
        start: str,
        end: str,
        metrics: Sequence[str],
        sources: Sequence[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        start_at = _parse_timestamp("start", start)
        end_at = _parse_timestamp("end", end)
        if end_at <= start_at:
            raise HealthStorageError("end must be later than start")
        if end_at - start_at > timedelta(days=_MAX_QUERY_DAYS):
            raise HealthStorageError(f"Health queries are bounded to {_MAX_QUERY_DAYS} days")
        selected_metrics = _validated_allowed_metrics(metrics, self.settings.allowed_metrics)
        selected_sources = _validated_filter_values("source", sources or ())
        params: dict[str, str] = {
            "select": (
                "id,source,metric_type,event_at,value_numeric,value_text,unit,"
                "received_at,raw_event_id,ingest_mode"
            ),
            "is_synthetic": "eq.false",
            "metric_type": _in_filter(selected_metrics),
            "and": (
                f"(event_at.gte.{_format_timestamp(start_at)},"
                f"event_at.lte.{_format_timestamp(end_at)})"
            ),
            "order": "event_at.asc",
            "limit": str(max(1, min(int(limit), _MAX_QUERY_RESULTS))),
        }
        if selected_sources:
            params["source"] = _in_filter(selected_sources)
        rows = self._request_json("GET", self.settings.health_table, params=params)
        if not isinstance(rows, list):
            raise HealthStorageError("Supabase returned an unexpected health event response")
        return {"events": rows, "count": len(rows), "bounded": True}

    def daily_state(self) -> dict[str, object]:
        """Classify fresh recovery signals against a bounded personal baseline."""
        selected_metrics = tuple(metric for metric in DAILY_STATE_METRICS if metric in self.settings.allowed_metrics)
        reference = self._clock()
        if not selected_metrics:
            return evaluate_daily_state([], now=reference)
        events = self._aggregate_events(
            start=reference - timedelta(days=30),
            end=reference,
            metrics=selected_metrics,
        )
        return evaluate_daily_state(events, now=reference)

    def daily_briefing(self) -> dict[str, object]:
        """Build the delivery-ready, non-diagnostic briefing from the daily state."""
        return build_daily_briefing(self.daily_state(), now=self._clock())

    def weekly_coaching(self) -> dict[str, Any]:
        """Build a bounded, evidence-led seven-day coaching report.

        Aggregation happens locally so the MCP response contains a compact report,
        not thousands of raw high-frequency samples.
        """
        reference = self._clock()
        selected_metrics = tuple(
            sorted(set(WEEKLY_COACHING_METRICS) & set(self.settings.allowed_metrics))
        )
        if not selected_metrics:
            return build_weekly_coaching([], now=reference)
        rows = self._aggregate_events(
            start=reference - timedelta(days=7),
            end=reference,
            metrics=selected_metrics,
        )
        return build_weekly_coaching(rows, now=reference)

    def _aggregate_events(
        self,
        *,
        start: datetime,
        end: datetime,
        metrics: Sequence[str],
    ) -> list[Mapping[str, Any]]:
        """Read a bounded internal analysis window without returning raw samples to MCP."""
        events: list[Mapping[str, Any]] = []
        for offset in range(0, _MAX_AGGREGATE_EVENTS, _AGGREGATE_PAGE_SIZE):
            rows = self._request_json(
                "GET",
                self.settings.health_table,
                params={
                    "select": "metric_type,event_at,value_numeric",
                    "is_synthetic": "eq.false",
                    "metric_type": _in_filter(metrics),
                    "and": (
                        f"(event_at.gte.{_format_timestamp(start)},"
                        f"event_at.lte.{_format_timestamp(end)})"
                    ),
                    "order": "event_at.asc,id.asc",
                    "limit": str(_AGGREGATE_PAGE_SIZE),
                    "offset": str(offset),
                },
            )
            if not isinstance(rows, list):
                raise HealthStorageError("Supabase returned an unexpected aggregate health response")
            events.extend(row for row in rows if isinstance(row, Mapping))
            if len(rows) < _AGGREGATE_PAGE_SIZE:
                break
        return events

    def available_metrics(self) -> dict[str, Any]:
        rows = self._request_json(
            "GET",
            self.settings.health_table,
            params={
                "select": "source,metric_type",
                "is_synthetic": "eq.false",
                "limit": "1000",
            },
        )
        if not isinstance(rows, list):
            raise HealthStorageError("Supabase returned an unexpected metric response")
        present_metrics = sorted(
            {
                str(row.get("metric_type"))
                for row in rows
                if isinstance(row, Mapping) and row.get("metric_type") in self.settings.allowed_metrics
            }
        )
        sources = sorted(
            {
                str(row.get("source"))
                for row in rows
                if isinstance(row, Mapping) and isinstance(row.get("source"), str)
            }
        )
        return {
            "allowed_metrics": sorted(self.settings.allowed_metrics),
            "available_metrics": present_metrics,
            "sources": sources,
        }

    def connector_status(self) -> dict[str, Any]:
        rows = self._request_json(
            "GET",
            self.settings.health_table,
            params={
                "select": "source,event_at,received_at",
                "is_synthetic": "eq.false",
                "order": "event_at.desc",
                "limit": "1000",
            },
        )
        if not isinstance(rows, list):
            raise HealthStorageError("Supabase returned an unexpected connector status response")
        latest: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("source"), str):
                continue
            source = str(row["source"])
            if source not in latest:
                latest[source] = row
        configured: list[dict[str, Any]] = []
        if self.settings.apple_health_delivery_table:
            item: dict[str, Any] = {
                "source": "health_auto_export",
                "mode": "push-delivery-with-bounded-normalization",
                "sync_supported": True,
            }
            record = latest.get("health_auto_export")
            if record is None:
                item["latest_event_at"] = None
                item["last_received_at"] = None
                item["freshness"] = "no_data"
            else:
                event_at = record.get("event_at")
                item["latest_event_at"] = event_at
                item["last_received_at"] = record.get("received_at")
                try:
                    age = self._clock().astimezone(timezone.utc) - _parse_timestamp(
                        "latest event_at", str(event_at)
                    )
                except (HealthStorageError, ValueError):
                    item["freshness"] = "unknown"
                else:
                    item["freshness"] = "fresh" if age <= timedelta(hours=48) else "stale"
            configured.append(item)
        if self._provider_runtime is not None:
            configured.extend(self._provider_runtime.statuses())
        return {
            "storage": "supabase",
            "credential_scope": "service_role" if self.settings.uses_service_role else "scoped_role",
            "configured_connectors": configured,
        }

    def event_provenance(self, event_id: str) -> dict[str, Any]:
        try:
            normalized_id = str(UUID(event_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise HealthStorageError("event_id must be a UUID") from exc
        rows = self._request_json(
            "GET",
            self.settings.health_table,
            params={
                "select": "id,source,source_record_id,raw_event_id,received_at,ingest_mode",
                "id": f"eq.{normalized_id}",
                "is_synthetic": "eq.false",
                "limit": "1",
            },
        )
        if not isinstance(rows, list) or not rows:
            raise HealthStorageError("Health event provenance was not found")
        return dict(rows[0])

    def search_context(self, query: str, *, limit: int = 10, body_chars: int = 800) -> dict[str, Any]:
        if not self.settings.context_table:
            raise HealthStorageError("Personal context search is not configured")
        normalized_query = " ".join(query.split())
        if len(normalized_query) < 2 or len(normalized_query) > 200 or any(
            ord(character) < 32 for character in normalized_query
        ):
            raise HealthStorageError("Context query must contain 2 to 200 printable characters")
        bounded_limit = max(1, min(int(limit), 50))
        bounded_chars = max(100, min(int(body_chars), 4000))
        identifier = self.settings.context_id_column
        title = self.settings.context_title_column
        body = self.settings.context_body_column
        search = self.settings.context_search_column
        updated = self.settings.context_updated_column
        if (
            identifier is None
            or title is None
            or body is None
            or search is None
            or updated is None
        ):
            raise HealthStorageError("Personal context search configuration is incomplete")
        rows = self._request_json(
            "GET",
            self.settings.context_table,
            params={
                "select": f"{identifier},{title},{body},{updated}",
                search: f"plfts.{normalized_query}",
                "order": f"{updated}.desc.nullslast",
                "limit": str(bounded_limit),
            },
        )
        if not isinstance(rows, list):
            raise HealthStorageError("Supabase returned an unexpected context response")
        matches = [
            {
                "context_id": row.get(identifier),
                "title": row.get(title),
                "updated_at": row.get(updated),
                "body_preview": _truncate(str(row.get(body) or ""), bounded_chars),
            }
            for row in rows
            if isinstance(row, Mapping)
        ]
        return {"matches": matches, "count": len(matches)}

    def sync_source(self, source: str, *, limit: int = 25) -> dict[str, Any]:
        if source in _PROVIDER_SOURCES:
            try:
                runtime = self._provider_runtime
                if runtime is None:
                    from heavenly_health.providers.runtime import ProviderRuntime

                    runtime = ProviderRuntime()
                return runtime.sync(source, self, limit=limit)
            except Exception as error:
                from heavenly_health.providers.common import ProviderConfigurationError

                if isinstance(error, ProviderConfigurationError):
                    raise HealthStorageError(str(error)) from error
                raise
        if source != "health_auto_export":
            raise HealthStorageError("The requested health source is not supported")
        delivery_table = self.settings.apple_health_delivery_table
        if not delivery_table:
            raise HealthStorageError("health_auto_export sync is not configured")
        rows = self._request_json(
            "GET",
            delivery_table,
            params={
                "select": "id,received_at,payload_hash,payload",
                "order": "received_at.asc",
                "limit": str(max(1, min(int(limit), _MAX_SYNC_DELIVERIES))),
            },
        )
        if not isinstance(rows, list):
            raise HealthStorageError("Supabase returned an unexpected delivery response")
        events_upserted = 0
        deliveries_processed = 0
        for delivery in rows:
            if not isinstance(delivery, Mapping):
                continue
            raw_event_id = self._upsert_raw_delivery(delivery)
            events = normalize_health_auto_export_delivery(
                delivery,
                raw_event_id=raw_event_id,
                allowed_metrics=self.settings.allowed_metrics,
            )
            if events:
                saved = self._request_json(
                    "POST",
                    self.settings.health_table,
                    params={"on_conflict": "source,source_record_id"},
                    json_body=events,
                    prefer="resolution=merge-duplicates,return=representation",
                )
                if not isinstance(saved, list):
                    raise HealthStorageError("Supabase returned an unexpected normalized event response")
                events_upserted += len(saved)
            deliveries_processed += 1
        return {
            "source": source,
            "deliveries_processed": deliveries_processed,
            "events_upserted": events_upserted,
            "status": "completed",
        }

    def ingest_provider_resource(
        self,
        *,
        source: str,
        resource_type: str,
        source_record_id: str,
        event_at: str,
        payload: Mapping[str, Any],
        events: Sequence[Mapping[str, Any]],
        ingest_mode: str,
    ) -> int:
        """Persist one provider record before its allowlisted normalized events."""
        if source not in _PROVIDER_SOURCES:
            raise HealthStorageError("Unsupported provider source")
        if _PROVIDER_RESOURCE.fullmatch(resource_type) is None:
            raise HealthStorageError("Provider resource type is invalid")
        if _PROVIDER_RECORD_ID.fullmatch(source_record_id) is None:
            raise HealthStorageError("Provider source record identity is invalid")
        normalized_time = _format_timestamp(_parse_timestamp("provider event_at", event_at))
        if ingest_mode not in {"live", "backfill"}:
            raise HealthStorageError("Provider ingest mode is invalid")
        if not isinstance(payload, Mapping):
            raise HealthStorageError("Provider payload must be a JSON object")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        normalized_events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for event in events:
            item = dict(event)
            if item.get("source") != source:
                raise HealthStorageError("Normalized provider event source does not match")
            metric = item.get("metric_type")
            if not isinstance(metric, str) or metric not in self.settings.allowed_metrics:
                raise HealthStorageError("Normalized provider metric is not allowed")
            identity = item.get("source_record_id")
            if (
                not isinstance(identity, str)
                or _PROVIDER_RECORD_ID.fullmatch(identity) is None
                or identity in seen_ids
            ):
                raise HealthStorageError("Normalized provider event identity is invalid")
            seen_ids.add(identity)
            item["event_at"] = _format_timestamp(
                _parse_timestamp("normalized provider event_at", str(item.get("event_at", "")))
            )
            item["is_synthetic"] = False
            item["ingest_mode"] = ingest_mode
            normalized_events.append(item)
        raw = {
            "source": source,
            "resource_type": resource_type,
            "source_record_id": source_record_id,
            "event_at": normalized_time,
            "payload": dict(payload),
            "payload_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            "is_synthetic": False,
            "ingest_mode": ingest_mode,
        }
        saved_raw = self._request_json(
            "POST",
            self.settings.raw_health_table,
            params={"on_conflict": "source,source_record_id"},
            json_body=raw,
            prefer="resolution=merge-duplicates,return=representation",
        )
        if not isinstance(saved_raw, list) or not saved_raw or not isinstance(saved_raw[0], Mapping):
            raise HealthStorageError("Supabase did not confirm provider raw provenance storage")
        raw_id = saved_raw[0].get("id")
        if not isinstance(raw_id, str):
            raise HealthStorageError("Supabase did not return provider raw provenance identity")
        for item in normalized_events:
            item["raw_event_id"] = raw_id
        if not normalized_events:
            return 0
        saved_events = self._request_json(
            "POST",
            self.settings.health_table,
            params={"on_conflict": "source,source_record_id"},
            json_body=normalized_events,
            prefer="resolution=merge-duplicates,return=representation",
        )
        if not isinstance(saved_events, list):
            raise HealthStorageError("Supabase returned an unexpected normalized provider response")
        return len(saved_events)

    def build_manual_event(
        self,
        *,
        metric_type: str,
        event_at: str,
        value_numeric: float | int | None,
        value_text: str | None,
        unit: str | None,
        note: str | None,
    ) -> dict[str, Any]:
        selected_metric = _validated_allowed_metrics([metric_type], self.settings.allowed_metrics)[0]
        normalized_time = _format_timestamp(_parse_timestamp("event_at", event_at))
        has_numeric = value_numeric is not None
        has_text = value_text is not None and bool(value_text.strip())
        if has_numeric == has_text:
            raise HealthStorageError("Provide exactly one of value_numeric or value_text")
        if has_numeric and (isinstance(value_numeric, bool) or not math.isfinite(float(value_numeric))):
            raise HealthStorageError("value_numeric must be a finite number")
        cleaned_text = value_text.strip() if has_text and value_text else None
        if cleaned_text and len(cleaned_text) > 500:
            raise HealthStorageError("value_text must not exceed 500 characters")
        cleaned_unit = unit.strip() if unit else None
        if cleaned_unit and len(cleaned_unit) > 32:
            raise HealthStorageError("unit must not exceed 32 characters")
        cleaned_note = note.strip() if note else None
        if cleaned_note and len(cleaned_note) > 500:
            raise HealthStorageError("note must not exceed 500 characters")
        metadata: dict[str, Any] = {"schema_version": "1.0"}
        if cleaned_note:
            metadata["note"] = cleaned_note
        return {
            "source": "manual",
            "metric_type": selected_metric,
            "event_at": normalized_time,
            "value_numeric": value_numeric,
            "value_text": cleaned_text,
            "unit": cleaned_unit,
            "source_record_id": "assigned-at-execution",
            "metadata": metadata,
            "is_synthetic": False,
            "ingest_mode": "manual",
        }

    def execute_approved_event(self, payload: Mapping[str, Any]) -> str:
        if payload.get("source") != "manual" or payload.get("is_synthetic") is not False:
            raise HealthStorageError("Approved health event payload is outside the manual write boundary")
        source_record_id = payload.get("source_record_id")
        if not isinstance(source_record_id, str) or not source_record_id.startswith("heavenly-proposal:"):
            raise HealthStorageError("Approved health event has no valid proposal identity")
        saved = self._request_json(
            "POST",
            self.settings.health_table,
            params={"on_conflict": "source,source_record_id"},
            json_body=dict(payload),
            prefer="resolution=merge-duplicates,return=representation",
        )
        if not isinstance(saved, list) or not saved or not isinstance(saved[0], Mapping):
            raise HealthStorageError("Supabase did not confirm the approved health event write")
        reference = saved[0].get("id")
        if not isinstance(reference, str):
            raise HealthStorageError("Supabase did not return a health event reference")
        return reference

    def _upsert_raw_delivery(self, delivery: Mapping[str, Any]) -> str:
        delivery_id = delivery.get("id")
        payload = delivery.get("payload")
        received_at = delivery.get("received_at")
        if not isinstance(delivery_id, str) or not isinstance(payload, Mapping):
            raise HealthStorageError("Health delivery is missing its stable identity or payload")
        payload_hash = delivery.get("payload_hash")
        if not isinstance(payload_hash, str) or _SHA256.fullmatch(payload_hash) is None:
            payload_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        raw = {
            "source": "health_auto_export",
            "resource_type": "health_auto_export_delivery",
            "source_record_id": delivery_id,
            "event_at": received_at,
            "payload": dict(payload),
            "payload_sha256": payload_hash.lower(),
            "is_synthetic": False,
            "ingest_mode": "live",
        }
        saved = self._request_json(
            "POST",
            self.settings.raw_health_table,
            params={"on_conflict": "source,source_record_id"},
            json_body=raw,
            prefer="resolution=merge-duplicates,return=representation",
        )
        if not isinstance(saved, list) or not saved or not isinstance(saved[0], Mapping):
            raise HealthStorageError("Supabase did not confirm raw health provenance storage")
        raw_id = saved[0].get("id")
        if not isinstance(raw_id, str):
            raise HealthStorageError("Supabase did not return a raw health provenance reference")
        return raw_id

    def _request_json(
        self,
        method: str,
        table: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Any | None = None,
        prefer: str | None = None,
    ) -> Any:
        headers = {
            "apikey": self.settings.gateway_key,
            "Authorization": f"Bearer {self.settings.bearer_token}",
            "Accept": "application/json",
        }
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if prefer:
            headers["Prefer"] = prefer
        try:
            response = self._client.request(
                method,
                f"{self.settings.supabase_url}/rest/v1/{table}",
                params=params,
                headers=headers,
                json=json_body,
            )
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise HealthStorageError("Supabase health storage request failed") from exc


def normalize_health_auto_export_delivery(
    delivery: Mapping[str, Any],
    *,
    raw_event_id: str,
    allowed_metrics: frozenset[str],
) -> list[dict[str, Any]]:
    """Normalize a sanitized Health Auto Export delivery without exposing device names."""
    payload = delivery.get("payload")
    if not isinstance(payload, Mapping):
        return []
    data = payload.get("data")
    if not isinstance(data, Mapping) or not isinstance(data.get("metrics"), list):
        return []
    received_at = delivery.get("received_at")
    events: list[dict[str, Any]] = []
    for metric in data["metrics"]:
        if not isinstance(metric, Mapping):
            continue
        provider_name = metric.get("name")
        canonical = _canonical_provider_metric(provider_name)
        if canonical is None or canonical not in allowed_metrics:
            continue
        unit = str(metric.get("units") or "").strip() or None
        samples = metric.get("data")
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if not isinstance(sample, Mapping):
                continue
            event_at = _try_timestamp(sample.get("date"))
            if event_at is None:
                continue
            numeric, text = _normalize_sample_value(sample.get("qty"))
            if numeric is None and text is None:
                continue
            source = str(sample.get("source") or "")
            source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
            identity = hashlib.sha256(
                "\0".join((canonical, event_at, source)).encode("utf-8")
            ).hexdigest()
            events.append(
                {
                    "source": "health_auto_export",
                    "metric_type": canonical,
                    "event_at": event_at,
                    "value_numeric": numeric,
                    "value_text": text,
                    "unit": unit,
                    "source_record_id": f"health-auto-export:{identity}",
                    "metadata": {
                        "schema_version": "1.0",
                        "provider_metric": str(provider_name)[:80],
                        "source_hash": source_hash,
                    },
                    "received_at": received_at,
                    "raw_event_id": raw_event_id,
                    "is_synthetic": False,
                    "ingest_mode": "live",
                }
            )
    return events


def _canonical_provider_metric(value: object) -> str | None:
    normalized = re.sub(r"[+_/-]+", " ", str(value or "").lower())
    normalized = " ".join(normalized.split())
    return _PROVIDER_METRICS.get(normalized)


def _normalize_sample_value(value: object) -> tuple[float | int | None, str | None]:
    if isinstance(value, bool) or value is None:
        return None, None
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)):
            return None, None
        return value, None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None, None
        try:
            numeric = Decimal(cleaned)
        except InvalidOperation:
            return None, cleaned[:500]
        if not numeric.is_finite():
            return None, None
        return (int(numeric) if numeric == numeric.to_integral_value() else float(numeric)), None
    return None, None


def _validated_allowed_metrics(
    metrics: Sequence[str], allowed: frozenset[str]
) -> tuple[str, ...]:
    selected = tuple(dict.fromkeys(metric.strip() for metric in metrics if metric.strip()))
    if not selected:
        raise HealthStorageError("At least one metric is required")
    rejected = [metric for metric in selected if metric not in allowed]
    if rejected:
        raise HealthStorageError("Requested health metric is not allowed")
    return selected


def _validated_filter_values(name: str, values: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(value.strip() for value in values if value.strip()))
    if len(normalized) > 10 or any(_FILTER_VALUE.fullmatch(value) is None for value in normalized):
        raise HealthStorageError(f"{name} filters contain an invalid value")
    return normalized


def _in_filter(values: Sequence[str]) -> str:
    return "in.(" + ",".join(values) + ")"


def _parse_timestamp(name: str, value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HealthStorageError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HealthStorageError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _try_timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return _format_timestamp(_parse_timestamp("sample date", value))
    except HealthStorageError:
        return None


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validated_identifier(name: str, value: str) -> str:
    normalized = value.strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise HealthStorageError(f"{name} must be a safe SQL identifier")
    return normalized


def _optional_identifier(name: str, environ: Mapping[str, str]) -> str | None:
    value = environ.get(name, "").strip()
    return _validated_identifier(name, value) if value else None


def _validate_supabase_origin(value: str) -> None:
    parsed = urlparse(value)
    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip_address = False
    else:
        is_ip_address = True
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or "." not in hostname
        or hostname == "localhost"
        or is_ip_address
        or not hostname.endswith(".supabase.co")
    ):
        raise HealthStorageError("SUPABASE_URL must be a public HTTPS origin under supabase.co")
    try:
        port = parsed.port
    except ValueError:
        raise HealthStorageError("SUPABASE_URL must use a valid HTTPS port") from None
    if port not in (None, 443):
        raise HealthStorageError("SUPABASE_URL must use the standard HTTPS port")


def _truncate(value: str, limit: int) -> str:
    cleaned = value.strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1].rstrip() + "…"
