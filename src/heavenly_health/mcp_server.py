"""Local-first MCP server with an opt-in standards-compliant OAuth mode."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from fastmcp import FastMCP
from fastmcp.server.auth import OIDCProxy
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration
import httpx
from key_value.aio.stores.filetree import (
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware import Middleware

from heavenly_health.approvals import ApprovalStore, approval_state_path
from heavenly_health.briefing import briefing_schedule
from heavenly_health.cloudflare_managed_oauth import (
    CloudflareAccessJWTMiddleware,
    CloudflareAccessJWTVerifier,
    CloudflareManagedOAuthSettings,
)
from heavenly_health.health_storage import SupabaseHealthStore, SupabaseSettings
from heavenly_health.providers.runtime import ProviderRuntime
from heavenly_health.oauth_runtime import OAuthRuntimeSettings, OAuthSettingsError

SERVER_NAME = "Heavenly Health Protocol"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8791
OAUTH_CALLBACK_PATH = "/auth/callback"
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class PrevalidatedOIDCProxy(OIDCProxy):
    """OIDCProxy variant that consumes metadata verified before credentials are usable."""

    def __init__(self, *, oidc_configuration: OIDCConfiguration, **kwargs: Any) -> None:
        self._prevalidated_oidc_configuration = oidc_configuration
        super().__init__(**kwargs)

    def get_oidc_configuration(self, config_url, strict, timeout_seconds) -> OIDCConfiguration:
        return self._prevalidated_oidc_configuration


def public_transport_security(public_host: str | None = None) -> TransportSecuritySettings:
    """Allow the local listener and one optional HTTPS DNS hostname only."""
    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    allowed_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

    if public_host:
        host = public_host.strip().rstrip(".").lower()
        if not _is_public_dns_hostname(host):
            raise ValueError("HEAVENLY_MCP_PUBLIC_HOST must be a public DNS hostname only")
        allowed_hosts.extend([host, f"{host}:*"])
        allowed_origins.extend([f"https://{host}", f"https://{host}:*"])

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def _is_public_dns_hostname(host: str) -> bool:
    if not host or any(character.isspace() for character in host):
        return False
    if any(character in host for character in ":/@?#[]"):
        return False
    if host == "localhost" or host.endswith(".localhost") or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    return len(host) <= 253 and all(_HOSTNAME_LABEL.fullmatch(label) for label in host.split("."))


def server_info(*, health_data_exposed: bool = False) -> dict[str, Any]:
    """Describe the server without reading or exposing health records."""
    return {
        "name": SERVER_NAME,
        "transport": "streamable-http",
        "privacy": "local-first",
        "health_data_exposed": health_data_exposed,
        "endpoint": "/mcp",
    }


def default_oauth_storage_path(settings: OAuthRuntimeSettings) -> Path:
    """Return the validated durable OAuth directory selected by runtime settings."""
    return settings.oauth_state_dir


def encrypted_client_storage(settings: OAuthRuntimeSettings) -> FernetEncryptionWrapper:
    """Build encrypted, persistent storage required by FastMCP's OIDC proxy."""
    try:
        fernet = Fernet(settings.encryption_key.encode("ascii"))
    except (ValueError, TypeError, InvalidToken) as exc:
        raise OAuthSettingsError("HEAVENLY_OAUTH_ENCRYPTION_KEY must be a valid Fernet key") from exc
    storage_path = default_oauth_storage_path(settings)
    if storage_path.is_symlink():
        raise OAuthSettingsError("HEAVENLY_OAUTH_STATE_DIR must not be a symbolic link")
    try:
        storage_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        storage_path.chmod(0o700)
    except OSError as exc:
        raise OAuthSettingsError("HEAVENLY_OAUTH_STATE_DIR must be a private writable directory") from exc
    store = FileTreeStore(
        data_directory=storage_path,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(storage_path),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(storage_path),
    )
    return FernetEncryptionWrapper(key_value=store, fernet=fernet)


def validate_cloudflare_oidc_metadata(
    metadata: Mapping[str, object], expected_host: str
) -> OIDCConfiguration:
    """Validate every security-critical endpoint before any client secret is used."""
    expected_host = expected_host.rstrip(".").lower()
    for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = metadata.get(field)
        if not isinstance(value, str):
            raise OAuthSettingsError(f"OIDC metadata {field} must be an HTTPS Cloudflare Access URL")
        parsed = urlparse(value)
        try:
            port = parsed.port
        except ValueError:
            raise OAuthSettingsError(f"OIDC metadata {field} must use a valid HTTPS URL") from None
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or port not in (None, 443)
            or (parsed.hostname or "").rstrip(".").lower() != expected_host
            or not _is_public_dns_hostname((parsed.hostname or "").rstrip(".").lower())
            or not expected_host.endswith(".cloudflareaccess.com")
        ):
            raise OAuthSettingsError(
                f"OIDC metadata {field} must use the configured HTTPS Cloudflare Access host"
            )
    try:
        return OIDCConfiguration.model_validate(dict(metadata))
    except ValueError as exc:
        raise OAuthSettingsError("OIDC metadata is incomplete or invalid") from exc


def fetch_cloudflare_oidc_configuration(
    settings: OAuthRuntimeSettings,
    *,
    http_get: Callable[..., httpx.Response] | None = None,
) -> OIDCConfiguration:
    """Fetch and verify discovery metadata before constructing a confidential proxy."""
    get = http_get or httpx.get
    try:
        response = get(settings.oidc_config_url, timeout=10, follow_redirects=False)
        response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise OAuthSettingsError("Unable to retrieve Cloudflare Access OIDC discovery metadata") from exc
    if not isinstance(metadata, Mapping):
        raise OAuthSettingsError("Cloudflare Access OIDC discovery metadata must be an object")
    discovery_host = urlparse(settings.oidc_config_url).hostname
    if discovery_host is None:
        raise OAuthSettingsError("Cloudflare Access OIDC discovery URL must include a hostname")
    return validate_cloudflare_oidc_metadata(metadata, discovery_host)


def create_mcp_server(
    *,
    settings: OAuthRuntimeSettings | None,
    health_store: SupabaseHealthStore | Any | None = None,
    approval_store: ApprovalStore | None = None,
    briefing_answers_path: Path | None = None,
    oidc_proxy_factory: Callable[..., Any] = OIDCProxy,
    fastmcp_factory: Callable[..., Any] = FastMCP,
) -> Any:
    """Construct the local server or OAuth-protected server for the supplied mode."""
    kwargs: dict[str, Any] = {
        "name": SERVER_NAME,
        "instructions": (
            "This is a local-first health protocol MCP server: a bridge to the owner's "
            "health data, meant to be driven by you, the agent. Health reads are bounded "
            "by explicit metric and date allowlists. Health writes require a separate "
            "owner approval through the local CLI. To deliver the owner's briefing, "
            "self-schedule from health_briefing_schedule: wake at recommended_fetch_at, "
            "call sync_health_source for each connected source, then query_health_events, "
            "and present the analysis by next_briefing_at."
            if health_store is not None
            else "This is a local-first health protocol MCP server, a bridge meant to be "
            "driven by you, the agent. It reports configuration status and the owner's "
            "briefing schedule (health_briefing_schedule) until the owner enables storage."
        ),
    }
    if settings is not None:
        proxy_kwargs = {
            "config_url": settings.oidc_config_url,
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
            "audience": settings.audience,
            "base_url": settings.mcp_base_url,
            "redirect_path": OAUTH_CALLBACK_PATH,
            "client_storage": encrypted_client_storage(settings),
            "jwt_signing_key": settings.jwt_signing_key,
            "require_authorization_consent": True,
        }
        if oidc_proxy_factory is OIDCProxy:
            configuration = fetch_cloudflare_oidc_configuration(settings)
            kwargs["auth"] = PrevalidatedOIDCProxy(
                oidc_configuration=configuration,
                **proxy_kwargs,
            )
        else:
            kwargs["auth"] = oidc_proxy_factory(**proxy_kwargs)
    server = fastmcp_factory(**kwargs)
    if hasattr(server, "tool"):
        _register_protocol_tools(
            server,
            health_store=health_store,
            approval_store=approval_store,
            briefing_answers_path=briefing_answers_path,
        )
    return server


def _register_protocol_tools(
    server: Any,
    *,
    health_store: SupabaseHealthStore | Any | None,
    approval_store: ApprovalStore | None,
    briefing_answers_path: Path | None = None,
) -> None:
    @server.tool(name="protocol_status")
    def _protocol_status() -> dict[str, Any]:
        """Return privacy-safe Heavenly runtime and storage status."""
        return server_info(health_data_exposed=health_store is not None)

    @server.tool(name="health_briefing_schedule")
    def _health_briefing_schedule() -> dict[str, Any]:
        """Report when the owner wants their briefing and when an agent should fetch.

        Heavenly never runs the briefing itself. Use this to self-schedule: wake at
        ``recommended_fetch_at`` (``fetch_lead_minutes`` before delivery), call
        ``sync_health_source`` then ``query_health_events``, and have the analysis
        ready by ``next_briefing_at``. Returns ``{"configured": false}`` until the
        owner completes setup.
        """
        return briefing_schedule(briefing_answers_path)

    if health_store is None:
        return
    if approval_store is None:
        raise ValueError("A health storage adapter requires an owner approval store")

    @server.tool(name="health_connector_status")
    def _health_connector_status() -> dict[str, Any]:
        """List configured health connectors without returning credentials or records."""
        return health_store.connector_status()

    @server.tool(name="health_available_metrics")
    def _health_available_metrics() -> dict[str, Any]:
        """List allowlisted metrics and sources currently present in normalized storage."""
        return health_store.available_metrics()

    @server.tool(name="query_health_events")
    def _query_health_events(
        start: str,
        end: str,
        metrics: list[str],
        sources: list[str] | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """Read real normalized events within a maximum 31-day, allowlisted query."""
        return health_store.query_events(
            start=start,
            end=end,
            metrics=metrics,
            sources=sources,
            limit=limit,
        )

    @server.tool(name="health_daily_state")
    def _health_daily_state() -> dict[str, Any]:
        """Return an explainable daily health state from fresh, allowlisted recovery signals."""
        return health_store.daily_state()

    @server.tool(name="health_daily_briefing")
    def _health_daily_briefing() -> dict[str, Any]:
        """Return a delivery-ready action, evidence, freshness, and feedback options."""
        return health_store.daily_briefing()

    @server.tool(name="health_weekly_coaching")
    def _health_weekly_coaching() -> dict[str, Any]:
        """Return a bounded, evidence-led weekly health coaching report and coverage gaps."""
        return health_store.weekly_coaching()

    @server.tool(name="propose_daily_briefing_feedback")
    def _propose_daily_briefing_feedback(feedback: str) -> dict[str, Any]:
        """Stage one owner-reported outcome; only local CLI approval makes it learnable."""
        state = health_store.daily_state()
        if state.get("status") != "ready" or state.get("daily_state") not in {"recover", "maintain"}:
            raise ValueError("Daily feedback requires a current ready daily state")
        data_through = state.get("data_through")
        return approval_store.propose_daily_feedback(
            daily_state=str(state["daily_state"]),
            feedback=feedback,
            data_through=data_through if isinstance(data_through, str) else None,
        )

    @server.tool(name="health_feedback_history")
    def _health_feedback_history(limit: int = 50) -> dict[str, Any]:
        """Return compact outcomes that were explicitly approved through the local CLI."""
        feedback = approval_store.feedback_history(limit=limit)
        return {"feedback": feedback, "count": len(feedback)}

    @server.tool(name="health_event_provenance")
    def _health_event_provenance(event_id: str) -> dict[str, Any]:
        """Return source identity and raw-record linkage without exposing raw payloads."""
        return health_store.event_provenance(event_id)

    @server.tool(name="sync_health_source")
    def _sync_health_source(source: str, limit: int = 25) -> dict[str, Any]:
        """Normalize bounded deliveries from one explicitly configured health source."""
        return health_store.sync_source(source, limit=limit)

    @server.tool(name="propose_health_event_write")
    def _propose_health_event_write(
        metric_type: str,
        event_at: str,
        value_numeric: float | None = None,
        value_text: str | None = None,
        unit: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Validate and stage one manual event; this tool cannot approve or write it."""
        payload = health_store.build_manual_event(
            metric_type=metric_type,
            event_at=event_at,
            value_numeric=value_numeric,
            value_text=value_text,
            unit=unit,
            note=note,
        )
        value = value_numeric if value_numeric is not None else value_text
        rendered_value = f"{value} {unit or ''}".strip()
        return approval_store.propose_health_event(
            payload,
            preview={
                "operation": "insert_health_event",
                "metric_type": metric_type,
                "event_at": event_at,
                "value": rendered_value,
                "confirmation": "Run heavenly approval approve <approval-id> locally",
            },
        )

    @server.tool(name="execute_approved_health_write")
    def _execute_approved_health_write(approval_id: str) -> dict[str, Any]:
        """Execute one exact, integrity-checked event already approved through the local CLI."""
        executable = approval_store.consume_approved(approval_id)
        try:
            event_id = health_store.execute_approved_event(executable["payload"])
        except Exception:
            approval_store.release_failed_execution(approval_id)
            raise
        approval_store.mark_executed(approval_id, result_reference=event_id)
        return {"approval_id": approval_id, "status": "executed", "event_id": event_id}

    @server.tool(name="health_mutation_audit")
    def _health_mutation_audit(limit: int = 50) -> dict[str, Any]:
        """List bounded proposal status and previews without returning write payloads."""
        history = approval_store.audit_history(limit=limit)
        return {"mutations": history, "count": len(history)}

    if getattr(health_store.settings, "context_table", None):

        @server.tool(name="search_personal_context")
        def _search_personal_context(
            query: str,
            limit: int = 10,
            body_chars: int = 800,
        ) -> dict[str, Any]:
            """Search the configured private Second Me context with bounded previews."""
            return health_store.search_context(query, limit=limit, body_chars=body_chars)


def resolve_auth_modes(
    environ: Mapping[str, str],
) -> tuple[OAuthRuntimeSettings | None, CloudflareManagedOAuthSettings | None]:
    """Resolve exactly one optional OAuth mode from an environment mapping."""
    oidc_settings = OAuthRuntimeSettings.from_environ(environ)
    managed_settings = CloudflareManagedOAuthSettings.from_environ(environ)
    if oidc_settings is not None and managed_settings is not None:
        raise OAuthSettingsError(
            "FastMCP OIDC proxy and Cloudflare Managed OAuth are mutually exclusive"
        )
    return oidc_settings, managed_settings


def create_runtime_http_app(
    server: Any,
    security: TransportSecuritySettings,
    *,
    managed_access_verifier: CloudflareAccessJWTVerifier | None = None,
) -> Any:
    """Build one guarded app for native, container, and test runtimes."""
    middleware = (
        [Middleware(CloudflareAccessJWTMiddleware, verifier=managed_access_verifier)]
        if managed_access_verifier is not None
        else None
    )
    return server.http_app(
        path="/mcp",
        middleware=middleware,
        stateless_http=True,
        transport="streamable-http",
        host_origin_protection=True,
        allowed_hosts=security.allowed_hosts,
        allowed_origins=security.allowed_origins,
    )


def create_oauth_http_app(server: Any, security: TransportSecuritySettings) -> Any:
    """Backward-compatible HTTP app factory for the FastMCP OIDC proxy mode."""
    return create_runtime_http_app(server, security)


_storage_settings = SupabaseSettings.from_environ(os.environ)
_provider_runtime = ProviderRuntime() if _storage_settings else None
_health_store = (
    SupabaseHealthStore(_storage_settings, provider_runtime=_provider_runtime)
    if _storage_settings
    else None
)
_approval_store = ApprovalStore(approval_state_path(os.environ)) if _health_store else None
_oauth_settings, _managed_access_settings = resolve_auth_modes(os.environ)
_managed_access_verifier = (
    CloudflareAccessJWTVerifier(_managed_access_settings)
    if _managed_access_settings is not None
    else None
)
mcp = create_mcp_server(
    settings=_oauth_settings,
    health_store=_health_store,
    approval_store=_approval_store,
)


def validated_bind_host(host: str, *, authenticated: bool) -> str:
    """Refuse a non-loopback listener unless an authentication mode is configured.

    Container images bind 0.0.0.0 by necessity, and that is safe only while the
    published port stays on host loopback. Without an OAuth mode there is nothing
    in front of the tools, so a reachable listener would be an open health-data
    endpoint; fail at startup rather than serve one.
    """
    candidate = host.strip()
    if authenticated:
        return candidate
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if candidate in {"localhost", ""}:
            return candidate or DEFAULT_HOST
        raise OAuthSettingsError(
            f"HEAVENLY_MCP_HOST={candidate!r} is not loopback and no OAuth mode is configured"
        ) from None
    if not address.is_loopback and not address.is_unspecified:
        raise OAuthSettingsError(
            f"HEAVENLY_MCP_HOST={candidate!r} is not loopback and no OAuth mode is configured"
        )
    return candidate


def run() -> None:
    """Serve Streamable HTTP MCP locally at http://127.0.0.1:8791/mcp by default."""
    security = public_transport_security(os.environ.get("HEAVENLY_MCP_PUBLIC_HOST"))
    host = validated_bind_host(
        os.environ.get("HEAVENLY_MCP_HOST", DEFAULT_HOST),
        authenticated=_oauth_settings is not None or _managed_access_verifier is not None,
    )
    middleware = (
        [Middleware(CloudflareAccessJWTMiddleware, verifier=_managed_access_verifier)]
        if _managed_access_verifier is not None
        else None
    )
    mcp.run(
        transport="streamable-http",
        host=host,
        port=int(os.environ.get("HEAVENLY_MCP_PORT", str(DEFAULT_PORT))),
        path="/mcp",
        middleware=middleware,
        stateless_http=True,
        host_origin_protection=True,
        allowed_hosts=security.allowed_hosts,
        allowed_origins=security.allowed_origins,
    )


if __name__ == "__main__":
    run()
