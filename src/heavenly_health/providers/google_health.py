"""Google Health API v4 OAuth, bounded synchronization, and normalization."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlencode

import httpx

from heavenly_health.providers.common import (
    OAuthToken,
    ProviderConfigurationError,
    ProviderStateStore,
    SecretStore,
    bounded_retry_delay,
    read_private_json,
    validate_https_url,
)


GOOGLE_CALLBACK_URL = "http://127.0.0.1:8791/providers/google-health/oauth/callback"
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_API_BASE = "https://health.googleapis.com/v4"
GOOGLE_HEALTH_SCOPES = (
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
    "https://www.googleapis.com/auth/googlehealth.sleep.readonly",
)
_GOOGLE_HOSTS = frozenset({"accounts.google.com", "oauth2.googleapis.com"})
# Provider-supplied sleep stage names become metric identifiers, so they are
# constrained here before they can ever reach storage.
_SLEEP_STAGE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
# Ordered so low-volume summaries sync before high-frequency samples; a shared
# record budget must never let per-second samples starve the daily summaries.
_DATA_TYPE_METRICS = {
    "daily-resting-heart-rate": "resting_heart_rate",
    "daily-heart-rate-variability": "heart_rate_variability",
    "daily-oxygen-saturation": "oxygen_saturation",
    "daily-respiratory-rate": "respiratory_rate",
    "daily-vo2-max": "vo2_max",
    "sleep": "sleep_analysis",
    "exercise": "workout_duration",
    "weight": "body_mass",
    # Keep raw HRV with low-volume recovery observations: it complements the
    # daily summary when a wearable omits an aggregate for a night.
    "heart-rate-variability": "heart_rate_variability",
    "distance": "walking_running_distance",
    "active-energy-burned": "active_energy",
    "steps": "steps",
    "vo2-max": "vo2_max",
    "oxygen-saturation": "oxygen_saturation",
    "heart-rate": "heart_rate",
}
_INTERVAL_TYPES = frozenset({"steps", "distance", "active-energy-burned", "exercise"})
_DAILY_TYPES = frozenset(
    {
        "daily-resting-heart-rate",
        "daily-heart-rate-variability",
        "daily-oxygen-saturation",
        "daily-respiratory-rate",
        "daily-vo2-max",
    }
)
_PREFER_DAILY_SUMMARY = {
    # HRV raw samples are kept alongside daily summaries for resilience
    # when the wearable fails to produce a daily aggregate on some nights.
    "oxygen-saturation": "daily-oxygen-saturation",
    "vo2-max": "daily-vo2-max",
}


class GoogleHealthError(ProviderConfigurationError):
    """Google Health credentials, OAuth, API data, or synchronization is invalid."""


@dataclass(frozen=True)
class GoogleClientCredentials:
    """Validated Google Web OAuth credentials with a fixed loopback callback."""

    client_id: str
    client_secret: str = field(repr=False)
    authorization_url: str = GOOGLE_AUTHORIZATION_URL
    token_url: str = GOOGLE_TOKEN_URL
    redirect_uri: str = GOOGLE_CALLBACK_URL

    @classmethod
    def from_private_json(cls, path: Path) -> GoogleClientCredentials:
        try:
            return cls.from_payload(read_private_json(path))
        except ProviderConfigurationError as error:
            raise GoogleHealthError(str(error)) from error

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> GoogleClientCredentials:
        web = payload.get("web")
        if not isinstance(web, Mapping):
            raise GoogleHealthError("Google credential JSON must contain a Web OAuth client")
        client_id = web.get("client_id")
        client_secret = web.get("client_secret")
        auth_uri = web.get("auth_uri", GOOGLE_AUTHORIZATION_URL)
        token_uri = web.get("token_uri", GOOGLE_TOKEN_URL)
        redirects = web.get("redirect_uris")
        if (
            not isinstance(client_id, str)
            or not client_id.endswith(".apps.googleusercontent.com")
            or not isinstance(client_secret, str)
            or not client_secret.strip()
            or not isinstance(auth_uri, str)
            or not isinstance(token_uri, str)
            or not isinstance(redirects, list)
            or GOOGLE_CALLBACK_URL not in redirects
        ):
            raise GoogleHealthError(
                "Google Web OAuth client is incomplete or missing the exact loopback callback"
            )
        try:
            validate_https_url(auth_uri, name="Google authorization URL", allowed_hosts=_GOOGLE_HOSTS)
            validate_https_url(token_uri, name="Google token URL", allowed_hosts=_GOOGLE_HOSTS)
        except ProviderConfigurationError as error:
            raise GoogleHealthError(str(error)) from error
        return cls(client_id.strip(), client_secret.strip(), auth_uri, token_uri)

    def to_json(self) -> str:
        return json.dumps(
            {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "authorization_url": self.authorization_url,
                "token_url": self.token_url,
                "redirect_uri": self.redirect_uri,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, value: str) -> GoogleClientCredentials:
        try:
            payload = json.loads(value)
            if not isinstance(payload, Mapping) or payload.get("redirect_uri") != GOOGLE_CALLBACK_URL:
                raise GoogleHealthError("Stored Google OAuth client is invalid")
            return cls.from_payload(
                {
                    "web": {
                        "client_id": payload.get("client_id"),
                        "client_secret": payload.get("client_secret"),
                        "auth_uri": payload.get("authorization_url"),
                        "token_uri": payload.get("token_url"),
                        "redirect_uris": [payload.get("redirect_uri")],
                    }
                }
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise GoogleHealthError("Stored Google OAuth client is invalid") from error


@dataclass(frozen=True)
class OAuthAuthorizationRequest:
    url: str
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)


class GoogleOAuthClient:
    """Perform Google authorization-code/PKCE exchange, refresh, and revocation."""

    SERVICE = "google-health"
    CLIENT_ACCOUNT = "oauth-client"
    TOKEN_ACCOUNT = "oauth-token"

    def __init__(
        self,
        credentials: GoogleClientCredentials,
        secret_store: SecretStore,
        *,
        http_client: httpx.Client | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.credentials = credentials
        self.secret_store = secret_store
        self._client = http_client or httpx.Client(timeout=30, follow_redirects=False)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def load(cls, secret_store: SecretStore, **kwargs: Any) -> GoogleOAuthClient:
        saved = secret_store.get(cls.SERVICE, cls.CLIENT_ACCOUNT)
        if saved is None:
            raise GoogleHealthError("Google OAuth client is not imported")
        return cls(GoogleClientCredentials.from_json(saved), secret_store, **kwargs)

    @classmethod
    def import_credentials(
        cls,
        path: Path,
        secret_store: SecretStore,
    ) -> GoogleClientCredentials:
        credentials = GoogleClientCredentials.from_private_json(path)
        secret_store.set(cls.SERVICE, cls.CLIENT_ACCOUNT, credentials.to_json())
        return credentials

    def authorization_request(
        self,
        allowed_metrics: frozenset[str],
    ) -> OAuthAuthorizationRequest:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        scopes = scopes_for_metrics(allowed_metrics)
        query = urlencode(
            {
                "client_id": self.credentials.client_id,
                "redirect_uri": self.credentials.redirect_uri,
                "response_type": "code",
                "access_type": "offline",
                "prompt": "consent",
                "scope": " ".join(scopes),
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return OAuthAuthorizationRequest(
            url=f"{self.credentials.authorization_url}?{query}",
            state=state,
            code_verifier=verifier,
        )

    def exchange_code(self, code: str, *, code_verifier: str) -> OAuthToken:
        if not code.strip() or not code_verifier.strip():
            raise GoogleHealthError("Google OAuth callback is incomplete")
        token = self._token_request(
            {
                "client_id": self.credentials.client_id,
                "client_secret": self.credentials.client_secret,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": self.credentials.redirect_uri,
            }
        )
        if token.refresh_token is None:
            raise GoogleHealthError("Google did not return the offline refresh token")
        self.secret_store.set(self.SERVICE, self.TOKEN_ACCOUNT, token.to_json())
        return token

    def refresh(self, token: OAuthToken) -> OAuthToken:
        if not token.refresh_token:
            raise GoogleHealthError("Google refresh token is unavailable; reconnect is required")
        refreshed = self._token_request(
            {
                "client_id": self.credentials.client_id,
                "client_secret": self.credentials.client_secret,
                "refresh_token": token.refresh_token,
                "grant_type": "refresh_token",
            },
            previous_refresh_token=token.refresh_token,
        )
        self.secret_store.set(self.SERVICE, self.TOKEN_ACCOUNT, refreshed.to_json())
        return refreshed

    def access_token(self) -> str:
        saved = self.secret_store.get(self.SERVICE, self.TOKEN_ACCOUNT)
        if saved is None:
            raise GoogleHealthError("Google Health is not connected")
        token = OAuthToken.from_json(saved)
        if token.needs_refresh(self._clock()):
            token = self.refresh(token)
        return token.access_token

    def revoke(self) -> None:
        saved = self.secret_store.get(self.SERVICE, self.TOKEN_ACCOUNT)
        if saved is not None:
            token = OAuthToken.from_json(saved)
            value = token.refresh_token or token.access_token
            try:
                response = self._client.post(
                    GOOGLE_REVOKE_URL,
                    data={"token": value},
                    headers={"Accept": "application/json"},
                )
                if response.status_code not in {200, 400}:
                    raise GoogleHealthError("Google token revocation failed")
            except httpx.HTTPError as error:
                raise GoogleHealthError("Google token revocation failed") from error
        self.secret_store.delete(self.SERVICE, self.TOKEN_ACCOUNT)

    def _token_request(
        self,
        data: Mapping[str, str],
        *,
        previous_refresh_token: str | None = None,
    ) -> OAuthToken:
        try:
            response = self._client.post(
                self.credentials.token_url,
                data=data,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as error:
            raise GoogleHealthError("Google OAuth token exchange failed") from error
        if not isinstance(payload, Mapping):
            raise GoogleHealthError("Google OAuth token response is invalid")
        try:
            return OAuthToken.from_response(
                payload,
                now=self._clock(),
                previous_refresh_token=previous_refresh_token,
            )
        except ProviderConfigurationError as error:
            raise GoogleHealthError(str(error)) from error


class GoogleHealthAPI:
    """Bounded read-only Google Health API v4 client."""

    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        http_client: httpx.Client | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._token_provider = token_provider
        self._client = http_client or httpx.Client(timeout=30, follow_redirects=False)
        self._sleep = sleeper or time.sleep

    def identity(self) -> dict[str, Any]:
        payload = self._get("/users/me/identity")
        identity = payload.get("healthUserId")
        if not isinstance(identity, str) or not identity:
            raise GoogleHealthError("Google Health identity response is invalid")
        return payload

    def list_data_points(
        self,
        data_type: str,
        *,
        start: str,
        end: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        if data_type not in _DATA_TYPE_METRICS:
            raise GoogleHealthError("Unsupported Google Health data type")
        bounded_limit = max(1, min(int(limit), 10_000))
        page_limit = 25 if data_type == "sleep" else 10_000
        params: dict[str, str] = {
            "pageSize": str(min(bounded_limit, page_limit)),
            "filter": _google_filter(data_type, start, end),
        }
        points: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()
        for _ in range(100):
            payload = self._get(
                f"/users/me/dataTypes/{data_type}/dataPoints",
                params=params,
            )
            page = payload.get("dataPoints", [])
            if not isinstance(page, list) or not all(isinstance(item, Mapping) for item in page):
                raise GoogleHealthError("Google Health data page is invalid")
            points.extend(dict(item) for item in page[: bounded_limit - len(points)])
            if len(points) >= bounded_limit:
                break
            next_token = payload.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token:
                break
            if next_token in seen_tokens:
                raise GoogleHealthError("Google Health pagination token repeated")
            seen_tokens.add(next_token)
            params["pageToken"] = next_token
        return points

    def _get(
        self,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        for attempt in range(3):
            try:
                response = self._client.get(
                    f"{GOOGLE_API_BASE}{path}",
                    params=params,
                    headers={
                        "Authorization": f"Bearer {self._token_provider()}",
                        "Accept": "application/json",
                    },
                )
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < 2:
                        self._sleep(bounded_retry_delay(response.headers, attempt))
                        continue
                response.raise_for_status()
                payload = response.json()
            except httpx.TransportError as error:
                if attempt < 2:
                    self._sleep(bounded_retry_delay({}, attempt))
                    continue
                raise GoogleHealthError("Google Health API request failed") from error
            except (httpx.HTTPError, ValueError, TypeError) as error:
                raise GoogleHealthError("Google Health API request failed") from error
            if not isinstance(payload, dict):
                raise GoogleHealthError("Google Health API response is invalid")
            return payload
        raise GoogleHealthError("Google Health API request failed")


class ProviderHealthStore(Protocol):
    settings: Any

    def ingest_provider_resource(self, **kwargs: Any) -> int: ...


class GoogleHealthConnector:
    """Synchronize selected Google Health data types into Heavenly storage."""

    SOURCE = "google_health"

    def __init__(
        self,
        api: GoogleHealthAPI | Any,
        store: ProviderHealthStore,
        state_store: ProviderStateStore,
        *,
        data_types: tuple[str, ...] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.api = api
        self.store = store
        self.state_store = state_store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        selected = data_types or data_types_for_metrics(store.settings.allowed_metrics)
        self.data_types = tuple(dict.fromkeys(selected))
        if not self.data_types:
            raise GoogleHealthError("No allowlisted metric maps to a Google Health data type")

    def sync(self, *, days: int = 31, limit: int = 1000) -> dict[str, Any]:
        bounded_days = max(1, min(int(days), 31))
        bounded_limit = max(1, min(int(limit), 10_000))
        now = self._aware_now()
        state = self.state_store.load(self.SOURCE)
        checkpoints = dict(state.get("checkpoints", {})) if isinstance(state.get("checkpoints"), Mapping) else {}
        identity = self.api.identity()
        identity_value = str(identity["healthUserId"])
        records_processed = 0
        events_upserted = 0
        next_checkpoints = dict(checkpoints)
        for data_type in self.data_types:
            remaining = bounded_limit - records_processed
            if remaining <= 0:
                break
            default_start = now - timedelta(days=bounded_days)
            checkpoint = checkpoints.get(data_type)
            start = _parse_timestamp(checkpoint) - timedelta(hours=1) if isinstance(checkpoint, str) else default_start
            points = self.api.list_data_points(
                data_type,
                start=_timestamp(start),
                end=_timestamp(now),
                limit=remaining,
            )
            for point in points:
                events = normalize_google_data_point(
                    data_type,
                    point,
                    allowed_metrics=self.store.settings.allowed_metrics,
                )
                source_record_id = _google_source_record_id(data_type, point)
                event_at = str(events[0]["event_at"]) if events else _timestamp(now)
                events_upserted += self.store.ingest_provider_resource(
                    source=self.SOURCE,
                    resource_type=data_type,
                    source_record_id=source_record_id,
                    event_at=event_at,
                    payload=point,
                    events=events,
                    ingest_mode="backfill" if bounded_days > 1 else "live",
                )
                records_processed += 1
            # A full page means the budget may have truncated the window; advancing
            # the checkpoint would silently skip the unfetched remainder forever.
            if len(points) < remaining:
                next_checkpoints[data_type] = _timestamp(now)
        self.state_store.save(
            self.SOURCE,
            {
                "connected": True,
                "identity_hash": hashlib.sha256(identity_value.encode()).hexdigest(),
                "checkpoints": next_checkpoints,
                "last_sync_at": _timestamp(now),
                "data_types": list(self.data_types),
            },
        )
        return {
            "source": self.SOURCE,
            "records_processed": records_processed,
            "events_upserted": events_upserted,
            "status": "completed",
        }

    def status(self) -> dict[str, Any]:
        state = self.state_store.load(self.SOURCE)
        return {
            "source": self.SOURCE,
            "connected": state.get("connected") is True,
            "sync_supported": True,
            "last_sync_at": state.get("last_sync_at"),
            "data_types": list(state.get("data_types", self.data_types)),
        }

    def disconnect(self, oauth: GoogleOAuthClient) -> None:
        oauth.revoke()
        self.state_store.delete(self.SOURCE)

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise GoogleHealthError("Google Health clock must be timezone-aware")
        return now.astimezone(timezone.utc)


def scopes_for_metrics(allowed_metrics: frozenset[str]) -> tuple[str, ...]:
    scopes: list[str] = []
    if allowed_metrics & {
        "steps",
        "walking_running_distance",
        "active_energy",
        "workout_duration",
        "vo2_max",
    }:
        scopes.append(GOOGLE_HEALTH_SCOPES[0])
    if allowed_metrics & {
        "heart_rate",
        "resting_heart_rate",
        "heart_rate_variability",
        "body_mass",
        "oxygen_saturation",
        "respiratory_rate",
    }:
        scopes.append(GOOGLE_HEALTH_SCOPES[1])
    if "sleep_analysis" in allowed_metrics:
        scopes.append(GOOGLE_HEALTH_SCOPES[2])
    if not scopes:
        raise GoogleHealthError("Selected metrics do not map to Google Health read scopes")
    return tuple(scopes)


def data_types_for_metrics(allowed_metrics: frozenset[str]) -> tuple[str, ...]:
    """Select one bounded Google Health source per metric.

    Daily summaries provide the coaching-relevant value without letting dense
    raw observations consume a shared sync budget.  Raw types remain available
    only where Google Health has no daily equivalent.
    """
    preferred_daily = {
        daily_type
        for raw_type, daily_type in _PREFER_DAILY_SUMMARY.items()
        if _DATA_TYPE_METRICS[raw_type] in allowed_metrics
    }
    return tuple(
        data_type
        for data_type, metric in _DATA_TYPE_METRICS.items()
        if metric in allowed_metrics
        and (data_type not in _PREFER_DAILY_SUMMARY or _PREFER_DAILY_SUMMARY[data_type] not in preferred_daily)
    )


def normalize_google_data_point(
    data_type: str,
    point: Mapping[str, Any],
    *,
    allowed_metrics: frozenset[str],
) -> list[dict[str, Any]]:
    metric = _DATA_TYPE_METRICS.get(data_type)
    if metric is None or metric not in allowed_metrics:
        return []
    payload_key = _camel(data_type)
    data = point.get(payload_key)
    if not isinstance(data, Mapping):
        return []
    event_at = _event_timestamp(data_type, data)
    value, unit = _metric_value(data_type, data)
    if event_at is None or value is None:
        return []

    base_event = {
        "source": "google_health",
        "metric_type": metric,
        "event_at": event_at,
        "value_numeric": value,
        "value_text": None,
        "unit": unit,
        "source_record_id": _google_source_record_id(data_type, point),
        "metadata": {
            "schema_version": "1.0",
            "provider_data_type": data_type,
        },
        "is_synthetic": False,
    }

    if data_type == "sleep":
        # Emit the total plus any stage breakdown the owner has explicitly allowlisted.
        events = [base_event]
        summary = data.get("summary")
        stages = summary.get("stagesSummary") if isinstance(summary, Mapping) else None
        for stage in stages if isinstance(stages, list) else ():
            if not isinstance(stage, Mapping):
                continue
            stage_type = str(stage.get("type", "")).strip().lower()
            if _SLEEP_STAGE.fullmatch(stage_type) is None:
                continue
            stage_metric = f"sleep_{stage_type}"
            if stage_metric not in allowed_metrics:
                continue
            minutes = _number(stage.get("minutes"))
            if minutes is None:
                continue
            stage_event = dict(base_event)
            stage_event["metric_type"] = stage_metric
            stage_event["value_numeric"] = minutes
            stage_event["unit"] = "min"
            stage_event["source_record_id"] = f"{base_event['source_record_id']}:{stage_type}"
            events.append(stage_event)
        return events

    return [base_event]


def _metric_value(data_type: str, data: Mapping[str, Any]) -> tuple[float | int | None, str | None]:
    candidates: dict[str, tuple[tuple[str, ...], str]] = {
        "steps": (("count",), "count"),
        "heart-rate": (("beatsPerMinute",), "bpm"),
        "daily-resting-heart-rate": (("beatsPerMinute", "restingHeartRate"), "bpm"),
        "heart-rate-variability": (
            (
                "rootMeanSquareOfSuccessiveDifferencesMilliseconds",
                "rmssdMilliseconds",
                "heartRateVariabilityMilliseconds",
            ),
            "ms",
        ),
        "daily-heart-rate-variability": (
            ("averageHeartRateVariabilityMilliseconds", "rmssdMilliseconds"),
            "ms",
        ),
        "weight": (("kilograms", "weightKilograms"), "kg"),
        "distance": (("meters", "distanceMeters"), "m"),
        "active-energy-burned": (("kilocalories", "calories"), "kcal"),
        "oxygen-saturation": (("percentage", "oxygenSaturationPercentage"), "%"),
        "daily-oxygen-saturation": (("averagePercentage", "percentage"), "%"),
        "daily-respiratory-rate": (("averageBreathsPerMinute", "breathsPerMinute"), "breaths/min"),
        "vo2-max": (("millilitersPerKilogramPerMinute", "vo2Max"), "mL/kg/min"),
        "daily-vo2-max": (("millilitersPerKilogramPerMinute", "vo2Max"), "mL/kg/min"),
    }
    if data_type == "sleep":
        interval = data.get("interval")
        if isinstance(interval, Mapping):
            start = _physical_time(interval.get("startTime"))
            end = _physical_time(interval.get("endTime"))
            if start is not None and end is not None and end > start:
                return round((end - start).total_seconds() / 60, 3), "min"
        duration = data.get("durationSeconds")
        numeric = _number(duration)
        return (round(float(numeric) / 60, 3), "min") if numeric is not None else (None, None)
    if data_type == "exercise":
        seconds = _duration_seconds(data.get("activeDuration"))
        if seconds is not None:
            return round(seconds / 60, 3), "min"
        interval = data.get("interval")
        if isinstance(interval, Mapping):
            start = _physical_time(interval.get("startTime"))
            end = _physical_time(interval.get("endTime"))
            if start is not None and end is not None and end > start:
                return round((end - start).total_seconds() / 60, 3), "min"
        return None, None
    names, unit = candidates.get(data_type, ((), ""))
    for name in names:
        numeric = _number(data.get(name))
        if numeric is not None:
            return numeric, unit
    return None, None


def _event_timestamp(data_type: str, data: Mapping[str, Any]) -> str | None:
    if data_type in _DAILY_TYPES:
        return _date_timestamp(data.get("date"))
    sample = data.get("sampleTime")
    if isinstance(sample, Mapping):
        physical = sample.get("physicalTime")
        parsed = _physical_time(physical)
        if parsed is not None:
            return _timestamp(parsed)
    interval = data.get("interval")
    if isinstance(interval, Mapping):
        for key in ("startTime", "endTime"):
            parsed = _physical_time(interval.get(key))
            if parsed is not None:
                return _timestamp(parsed)
    return None


def _google_filter(data_type: str, start: str, end: str) -> str:
    start_at = _parse_timestamp(start)
    end_at = _parse_timestamp(end)
    if end_at <= start_at or end_at - start_at > timedelta(days=32):
        raise GoogleHealthError("Google Health sync window is invalid")
    snake = data_type.replace("-", "_")
    if data_type in _DAILY_TYPES or data_type in {"sleep", "exercise"}:
        # Date filters use an exclusive upper bound; a window inside one civil day
        # must still span a whole day or the API rejects the empty range.
        start_date = start_at.date()
        end_date = end_at.date() if end_at == _midnight(end_at) else end_at.date() + timedelta(days=1)
        end_date = max(end_date, start_date + timedelta(days=1))
        if data_type in _DAILY_TYPES:
            field = f"{snake}.date"
        elif data_type == "sleep":
            field = "sleep.interval.civil_end_time"
        else:
            field = "exercise.interval.civil_start_time"
        return f'{field} >= "{start_date.isoformat()}" AND {field} < "{end_date.isoformat()}"'
    field = "interval.start_time" if data_type in _INTERVAL_TYPES else "sample_time.physical_time"
    return f'{snake}.{field} >= "{_timestamp(start_at)}" AND {snake}.{field} < "{_timestamp(end_at)}"'


def _midnight(value: datetime) -> datetime:
    return value.replace(hour=0, minute=0, second=0, microsecond=0)


def _google_source_record_id(data_type: str, point: Mapping[str, Any]) -> str:
    name = point.get("name")
    if isinstance(name, str) and name.strip():
        identity = name.strip()
    else:
        identity = hashlib.sha256(
            json.dumps(point, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    return f"google-health:{data_type}:{hashlib.sha256(identity.encode()).hexdigest()}"


def _camel(value: str) -> str:
    first, *rest = value.split("-")
    return first + "".join(part[:1].upper() + part[1:] for part in rest)


def _number(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if not (float("-inf") < numeric < float("inf")):
        return None
    return int(numeric) if numeric.is_integer() else numeric


def _duration_seconds(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    matched = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)s", value.strip())
    if matched is None:
        return None
    seconds = float(matched.group(1))
    return seconds if 0 <= seconds < float("inf") else None


def _date_timestamp(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    try:
        parsed = datetime(
            int(value["year"]),
            int(value["month"]),
            int(value["day"]),
            tzinfo=timezone.utc,
        )
    except (KeyError, TypeError, ValueError):
        return None
    return _timestamp(parsed)


def _physical_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    parsed = _physical_time(value)
    if parsed is None:
        raise GoogleHealthError("Google Health sync timestamp is invalid")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
