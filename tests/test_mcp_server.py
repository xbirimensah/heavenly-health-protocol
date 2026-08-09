import asyncio
import json

from cryptography.fernet import Fernet
from fastmcp.exceptions import ToolError
from joserfc import jwt
from joserfc.jwk import OctKey
import httpx
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
import pytest
from starlette.testclient import TestClient

from heavenly_health.approvals import ApprovalStore
from heavenly_health.cloudflare_managed_oauth import (
    CloudflareAccessJWTVerifier,
    CloudflareManagedOAuthSettings,
)
from heavenly_health.mcp_server import (
    create_oauth_http_app,
    create_mcp_server,
    create_runtime_http_app,
    encrypted_client_storage,
    public_transport_security,
    resolve_auth_modes,
    server_info,
    validate_cloudflare_oidc_metadata,
    validated_bind_host,
)
from heavenly_health.oauth_runtime import OAuthRuntimeSettings, OAuthSettingsError


DISCOVERY_URL = "https://team.cloudflareaccess.com/cdn-cgi/access/sso/oidc/test-client/.well-known/openid-configuration"


def oauth_settings(*, state_dir: str | None = None) -> OAuthRuntimeSettings:
    environ = {
        "HEAVENLY_OIDC_CONFIG_URL": DISCOVERY_URL,
        "HEAVENLY_OIDC_CLIENT_ID": "test-client-id",
        "HEAVENLY_OIDC_CLIENT_SECRET": "test-client-secret-not-for-production",
        "HEAVENLY_OIDC_AUDIENCE": "test-access-audience",
        "HEAVENLY_MCP_BASE_URL": "https://mcp.example.test",
        "HEAVENLY_OAUTH_JWT_SIGNING_KEY": "test-jwt-signing-key-not-for-production",
        "HEAVENLY_OAUTH_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    }
    if state_dir is not None:
        environ["HEAVENLY_OAUTH_STATE_DIR"] = state_dir
    settings = OAuthRuntimeSettings.from_environ(environ)
    assert settings is not None
    return settings


def cloudflare_metadata(**overrides: str) -> dict[str, object]:
    metadata: dict[str, object] = {
        "issuer": "https://team.cloudflareaccess.com",
        "authorization_endpoint": "https://team.cloudflareaccess.com/authorize",
        "token_endpoint": "https://team.cloudflareaccess.com/token",
        "jwks_uri": "https://team.cloudflareaccess.com/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    metadata.update(overrides)
    return metadata


def test_server_info_identifies_private_local_mcp() -> None:
    info = server_info()

    assert info["name"] == "Heavenly Health Protocol"
    assert info["transport"] == "streamable-http"
    assert info["privacy"] == "local-first"
    assert info["health_data_exposed"] is False


def test_public_host_is_allowed_without_disabling_rebinding_protection() -> None:
    security = public_transport_security("health-mcp.example.com")

    assert security.enable_dns_rebinding_protection is True
    assert "health-mcp.example.com" in security.allowed_hosts
    assert "https://health-mcp.example.com" in security.allowed_origins


def test_public_host_rejects_non_dns_or_non_public_values() -> None:
    for value in (
        "https://health-mcp.example.com",
        "health-mcp.example.com/path",
        "health-mcp.example.com:443",
        "user@health-mcp.example.com",
        "health-mcp.example.com?query=value",
        "[::1]",
        "127.0.0.1",
        "localhost",
        "-bad.example.com",
        "bad_.example.com",
        "single-label",
    ):
        try:
            public_transport_security(value)
        except ValueError as exc:
            assert "HEAVENLY_MCP_PUBLIC_HOST" in str(exc)
        else:
            raise AssertionError(f"unsafe public host accepted: {value}")


def test_local_mode_does_not_construct_an_oauth_proxy() -> None:
    called = False

    def unexpected_proxy(**kwargs):
        nonlocal called
        called = True
        raise AssertionError("OAuth proxy must not be constructed in local mode")

    server = create_mcp_server(settings=None, oidc_proxy_factory=unexpected_proxy)

    assert server is not None
    assert called is False


def test_oauth_mode_constructs_oidc_proxy_with_audience_consent_and_safe_discovery_settings() -> None:
    observed: dict[str, object] = {}

    def proxy_factory(**kwargs):
        observed.update(kwargs)
        return object()

    server = create_mcp_server(settings=oauth_settings(), oidc_proxy_factory=proxy_factory)

    assert server is not None
    assert observed["config_url"] == DISCOVERY_URL
    assert observed["client_id"] == "test-client-id"
    assert observed["audience"] == "test-access-audience"
    assert observed["redirect_path"] == "/auth/callback"
    assert observed["require_authorization_consent"] is True
    assert observed["jwt_signing_key"] == "test-jwt-signing-key-not-for-production"
    assert "client_storage" in observed


def test_encrypted_client_storage_uses_fernet_over_a_durable_writable_state_directory(tmp_path) -> None:
    storage_path = tmp_path / "mounted-data" / "oauth-state"
    storage = encrypted_client_storage(oauth_settings(state_dir=str(storage_path)))

    assert isinstance(storage, FernetEncryptionWrapper)
    assert isinstance(storage.key_value, FileTreeStore)

    secret = "representative-access-token-should-never-be-plaintext"

    async def write_and_read() -> dict[str, str] | None:
        await storage.put("oauth-client", {"access_token": secret, "client_secret": secret})
        result = await storage.get("oauth-client")
        return result

    assert asyncio.run(write_and_read()) == {"access_token": secret, "client_secret": secret}
    durable_bytes = b"".join(path.read_bytes() for path in storage_path.rglob("*") if path.is_file())
    assert secret.encode() not in durable_bytes
    assert storage_path.stat().st_mode & 0o777 == 0o700


def test_encrypted_client_storage_rejects_a_symlink_state_directory(tmp_path) -> None:
    target = tmp_path / "real-oauth-state"
    target.mkdir()
    link = tmp_path / "oauth-state-link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(OAuthSettingsError, match="must not be a symbolic link"):
        encrypted_client_storage(oauth_settings(state_dir=str(link)))


def test_default_fastmcp_proxy_uses_prevalidated_metadata_without_second_discovery_fetch(monkeypatch, tmp_path) -> None:
    """The confidential proxy receives only metadata vetted before its construction."""
    monkeypatch.setattr("heavenly_health.mcp_server.default_oauth_storage_path", lambda settings: tmp_path / "oauth")
    calls: list[str] = []

    def one_discovery_fetch(url: str, **kwargs):
        calls.append(url)
        if calls != [DISCOVERY_URL]:
            raise AssertionError("FastMCP attempted an unvalidated second discovery fetch")
        return httpx.Response(
            200,
            json=cloudflare_metadata(),
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("heavenly_health.mcp_server.httpx.get", one_discovery_fetch)
    server = create_mcp_server(settings=oauth_settings())

    assert calls == [DISCOVERY_URL]
    assert str(server.auth.oidc_config.token_endpoint) == "https://team.cloudflareaccess.com/token"


def test_default_fastmcp_proxy_rejects_wrong_audience_after_verified_jwt_signature(monkeypatch, tmp_path) -> None:
    """Exercise FastMCP's actual configured verifier boundary, not just constructor kwargs."""
    monkeypatch.setattr("heavenly_health.mcp_server.default_oauth_storage_path", lambda settings: tmp_path / "oauth")
    monkeypatch.setattr(
        "heavenly_health.mcp_server.httpx.get",
        lambda url, **kwargs: httpx.Response(
            200,
            json=cloudflare_metadata(),
            request=httpx.Request("GET", url),
        ),
    )
    verifier = create_mcp_server(settings=oauth_settings()).auth._token_validator
    signing_key = b"test-only-verifier-key-with-sufficient-length"
    signing_jwk = OctKey.import_key(signing_key)
    verifier.public_key = signing_key
    verifier.jwks_uri = None
    verifier.algorithm = "HS256"

    def signed_token(audience: str) -> str:
        return jwt.encode(
            {"alg": "HS256"},
            {
                "iss": "https://team.cloudflareaccess.com",
                "aud": audience,
                "exp": 4_102_444_800,
                "sub": "test-client",
            },
            signing_jwk,
        )

    assert asyncio.run(verifier.verify_token(signed_token("test-access-audience"))) is not None
    assert asyncio.run(verifier.verify_token(signed_token("wrong-audience"))) is None


def test_oauth_proxy_mode_uses_fastmcp_auth_instead_of_a_browser_redirect() -> None:
    """FastMCP auth is expected to return OAuth metadata + 401, not an edge 302."""
    observed: dict[str, object] = {}

    create_mcp_server(
        settings=oauth_settings(),
        oidc_proxy_factory=lambda **kwargs: object(),
        fastmcp_factory=lambda **kwargs: observed.update(kwargs) or object(),
    )

    assert observed["auth"] is not None


def test_unauthenticated_oauth_resource_request_returns_metadata_401_not_redirect(tmp_path, monkeypatch) -> None:
    """The server-level OAuth challenge remains visible through the MCP app."""
    monkeypatch.setattr("heavenly_health.mcp_server.default_oauth_storage_path", lambda settings: tmp_path / "oauth")

    def oidc_discovery_response(url: str, **kwargs):
        return httpx.Response(
            200,
            json=cloudflare_metadata(),
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("fastmcp.server.auth.oidc_proxy.httpx.get", oidc_discovery_response)
    server = create_mcp_server(settings=oauth_settings())

    with TestClient(create_oauth_http_app(server, public_transport_security())) as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

    assert response.status_code == 401
    assert "oauth-protected-resource" in response.headers["www-authenticate"]
    assert "resource_metadata" in response.headers["www-authenticate"]
    assert "location" not in response.headers


def test_locked_fastmcp_oauth_route_set_is_explicit(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("heavenly_health.mcp_server.default_oauth_storage_path", lambda settings: tmp_path / "oauth")
    monkeypatch.setattr(
        "heavenly_health.mcp_server.httpx.get",
        lambda url, **kwargs: httpx.Response(
            200,
            json=cloudflare_metadata(),
            request=httpx.Request("GET", url),
        ),
    )
    app = create_oauth_http_app(
        create_mcp_server(settings=oauth_settings()),
        public_transport_security(),
    )

    routes = {(route.path, frozenset(route.methods or set())) for route in app.routes}

    assert routes == {
        ("/.well-known/oauth-authorization-server", frozenset({"GET", "HEAD", "OPTIONS"})),
        ("/authorize", frozenset({"GET", "HEAD", "POST"})),
        ("/token", frozenset({"POST", "OPTIONS"})),
        ("/register", frozenset({"POST", "OPTIONS"})),
        ("/.well-known/oauth-protected-resource/mcp", frozenset({"GET", "HEAD", "OPTIONS"})),
        ("/auth/callback", frozenset({"GET", "HEAD"})),
        ("/consent", frozenset({"GET", "HEAD", "POST"})),
        ("/mcp", frozenset({"POST", "DELETE"})),
    }


def test_explicit_host_origin_protection_rejects_disallowed_host_and_origin() -> None:
    server = create_mcp_server(settings=None)
    app = create_oauth_http_app(server, public_transport_security())

    with TestClient(app) as client:
        host_response = client.post(
            "/mcp",
            headers={"Host": "attacker.example", "Origin": "http://attacker.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        origin_response = client.post(
            "/mcp",
            headers={"Host": "localhost", "Origin": "https://attacker.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )

    assert host_response.status_code == 421
    assert origin_response.status_code == 403


def test_runtime_http_app_enforces_managed_access_before_fastmcp() -> None:
    settings = CloudflareManagedOAuthSettings.from_environ(
        {
            "HEAVENLY_CLOUDFLARE_TEAM_DOMAIN": "https://team.cloudflareaccess.com",
            "HEAVENLY_CLOUDFLARE_ACCESS_AUDIENCE": "a" * 64,
            "HEAVENLY_CLOUDFLARE_ALLOWED_EMAILS": "owner@example.com",
            "HEAVENLY_MCP_PUBLIC_HOST": "health-mcp.example.com",
        }
    )
    assert settings is not None
    verifier = CloudflareAccessJWTVerifier(
        settings,
        signing_key_resolver=lambda _token: object(),
    )
    app = create_runtime_http_app(
        create_mcp_server(settings=None),
        public_transport_security("health-mcp.example.com"),
        managed_access_verifier=verifier,
    )

    with TestClient(app) as client:
        response = client.post(
            "https://health-mcp.example.com/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )

    assert response.status_code == 403
    assert response.json() == {"error": "Cloudflare Access authentication failed"}


def test_runtime_rejects_two_simultaneous_oauth_implementations() -> None:
    environ = {
        "HEAVENLY_OIDC_CONFIG_URL": DISCOVERY_URL,
        "HEAVENLY_OIDC_CLIENT_ID": "test-client-id",
        "HEAVENLY_OIDC_CLIENT_SECRET": "test-client-secret-not-for-production",
        "HEAVENLY_OIDC_AUDIENCE": "test-access-audience",
        "HEAVENLY_MCP_BASE_URL": "https://mcp.example.test",
        "HEAVENLY_OAUTH_JWT_SIGNING_KEY": "test-jwt-signing-key-not-for-production",
        "HEAVENLY_OAUTH_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "HEAVENLY_CLOUDFLARE_TEAM_DOMAIN": "https://team.cloudflareaccess.com",
        "HEAVENLY_CLOUDFLARE_ACCESS_AUDIENCE": "a" * 64,
        "HEAVENLY_CLOUDFLARE_ALLOWED_EMAILS": "owner@example.com",
        "HEAVENLY_MCP_PUBLIC_HOST": "health-mcp.example.com",
    }

    with pytest.raises(OAuthSettingsError, match="mutually exclusive"):
        resolve_auth_modes(environ)


def test_cloudflare_metadata_boundary_rejects_non_cloudflare_endpoints_before_proxy_setup() -> None:
    metadata = cloudflare_metadata(authorization_endpoint="https://attacker.example/authorize")

    try:
        validate_cloudflare_oidc_metadata(metadata, "team.cloudflareaccess.com")
    except OAuthSettingsError as exc:
        assert "authorization_endpoint" in str(exc)
    else:
        raise AssertionError("untrusted OIDC endpoint accepted")


class FakeHealthStore:
    class Settings:
        context_table = "private_documents"

    settings = Settings()

    def connector_status(self):
        return {"storage": "supabase", "configured_connectors": []}

    def available_metrics(self):
        return {"allowed_metrics": ["steps"], "available_metrics": ["steps"], "sources": []}

    def query_events(self, **kwargs):
        return {"events": [], "count": 0, "bounded": True, "request": kwargs}

    def event_provenance(self, event_id):
        return {"id": event_id, "source": "manual"}

    def daily_state(self):
        return {
            "status": "ready",
            "daily_state": "maintain",
            "primary_action": {"kind": "maintain"},
            "data_confidence": "high",
            "data_through": "2026-07-20T07:00:00Z",
        }

    def daily_briefing(self):
        return {
            "status": "ready",
            "headline": "Maintain your planned movement",
            "primary_action": {"kind": "maintain"},
        }

    def weekly_coaching(self):
        return {"status": "ready", "primary_focus": {"kind": "sleep_consistency"}}

    def sync_source(self, source, *, limit):
        return {"source": source, "deliveries_processed": 1, "events_upserted": 2, "limit": limit}

    def search_context(self, query, *, limit, body_chars):
        return {"matches": [], "count": 0, "query": query, "limit": limit, "body_chars": body_chars}

    def build_manual_event(self, **kwargs):
        return {
            "source": "manual",
            "source_record_id": "assigned-at-execution",
            "is_synthetic": False,
            "ingest_mode": "manual",
            "metadata": {"schema_version": "1.0"},
            **kwargs,
        }

    def execute_approved_event(self, payload):
        assert str(payload["source_record_id"]).startswith("heavenly-proposal:")
        return "00000000-0000-4000-8000-000000000099"


def test_storage_enabled_server_registers_real_tools_but_no_agent_approval_tool(tmp_path) -> None:
    server = create_mcp_server(
        settings=None,
        health_store=FakeHealthStore(),
        approval_store=ApprovalStore(tmp_path / "approvals"),
    )

    tools = {tool.name for tool in asyncio.run(server.list_tools())}

    assert tools == {
        "protocol_status",
        "health_briefing_schedule",
        "health_connector_status",
        "health_available_metrics",
        "query_health_events",
        "health_daily_state",
        "health_daily_briefing",
        "health_weekly_coaching",
        "propose_daily_briefing_feedback",
        "health_feedback_history",
        "health_event_provenance",
        "sync_health_source",
        "propose_health_event_write",
        "execute_approved_health_write",
        "health_mutation_audit",
        "search_personal_context",
    }
    assert "approve_health_event_write" not in tools


def test_storage_enabled_server_exposes_an_explainable_daily_health_state(tmp_path) -> None:
    server = create_mcp_server(
        settings=None,
        health_store=FakeHealthStore(),
        approval_store=ApprovalStore(tmp_path / "approvals"),
    )

    state = asyncio.run(server.call_tool("health_daily_state", {})).structured_content

    assert state == {
        "status": "ready",
        "daily_state": "maintain",
        "primary_action": {"kind": "maintain"},
        "data_confidence": "high",
        "data_through": "2026-07-20T07:00:00Z",
    }


def test_storage_enabled_server_exposes_a_delivery_ready_daily_briefing(tmp_path) -> None:
    server = create_mcp_server(
        settings=None,
        health_store=FakeHealthStore(),
        approval_store=ApprovalStore(tmp_path / "approvals"),
    )

    briefing = asyncio.run(server.call_tool("health_daily_briefing", {})).structured_content

    assert briefing == {
        "status": "ready",
        "headline": "Maintain your planned movement",
        "primary_action": {"kind": "maintain"},
    }


def test_daily_briefing_feedback_requires_local_approval_before_it_is_retrievable(tmp_path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    server = create_mcp_server(settings=None, health_store=FakeHealthStore(), approval_store=approvals)

    proposal = asyncio.run(
        server.call_tool("propose_daily_briefing_feedback", {"feedback": "partly"})
    ).structured_content

    assert proposal is not None
    assert proposal["status"] == "pending"
    assert proposal["preview"]["daily_state"] == "maintain"
    assert asyncio.run(server.call_tool("health_feedback_history", {})).structured_content == {
        "feedback": [],
        "count": 0,
    }

    approvals.approve(str(proposal["approval_id"]))

    history = asyncio.run(server.call_tool("health_feedback_history", {})).structured_content
    assert history is not None
    assert history["count"] == 1
    assert history["feedback"][0]["feedback"] == "partly"


def test_briefing_schedule_tool_is_available_without_storage(tmp_path) -> None:
    answers = tmp_path / "onboarding.json"
    answers.write_text(
        json.dumps(
            {
                "schedule": {
                    "frequency": "daily",
                    "arrival": "morning",
                    "time": "09:30",
                    "timezone": "UTC",
                },
                "metrics": ["steps"],
            }
        ),
        encoding="utf-8",
    )
    server = create_mcp_server(settings=None, briefing_answers_path=answers)

    tools = {tool.name for tool in asyncio.run(server.list_tools())}
    assert tools == {"protocol_status", "health_briefing_schedule"}

    schedule = asyncio.run(
        server.call_tool("health_briefing_schedule", {})
    ).structured_content
    assert schedule["configured"] is True
    assert schedule["fetch_lead_minutes"] == 10
    assert schedule["recommended_fetch_at"].endswith("09:20:00+00:00")
    assert schedule["next_briefing_at"].endswith("09:30:00+00:00")


def test_storage_enabled_tools_query_propose_and_execute_only_after_owner_approval(tmp_path) -> None:
    approvals = ApprovalStore(tmp_path / "approvals")
    server = create_mcp_server(
        settings=None,
        health_store=FakeHealthStore(),
        approval_store=approvals,
    )

    status = asyncio.run(server.call_tool("protocol_status", {})).structured_content
    queried = asyncio.run(
        server.call_tool(
            "query_health_events",
            {
                "start": "2026-07-13T00:00:00Z",
                "end": "2026-07-14T00:00:00Z",
                "metrics": ["steps"],
            },
        )
    ).structured_content
    proposed = asyncio.run(
        server.call_tool(
            "propose_health_event_write",
            {
                "metric_type": "steps",
                "event_at": "2026-07-14T06:00:00Z",
                "value_numeric": 50,
                "unit": "count",
            },
        )
    ).structured_content

    assert status is not None and status["health_data_exposed"] is True
    assert queried is not None and queried["bounded"] is True
    assert proposed is not None and proposed["status"] == "pending"
    approval_id = str(proposed["approval_id"])

    with pytest.raises(ToolError, match="not owner-approved"):
        asyncio.run(
            server.call_tool("execute_approved_health_write", {"approval_id": approval_id})
        )

    approvals.approve(approval_id)
    executed = asyncio.run(
        server.call_tool("execute_approved_health_write", {"approval_id": approval_id})
    ).structured_content
    assert executed == {
        "approval_id": approval_id,
        "status": "executed",
        "event_id": "00000000-0000-4000-8000-000000000099",
    }


def test_an_unauthenticated_server_refuses_to_bind_a_reachable_address() -> None:
    """Without an OAuth mode there is nothing in front of the health tools."""
    for reachable in ("192.168.1.20", "203.0.113.9", "::1234"):
        with pytest.raises(OAuthSettingsError, match="no OAuth mode is configured"):
            validated_bind_host(reachable, authenticated=False)


def test_loopback_and_container_defaults_still_bind_without_oauth() -> None:
    assert validated_bind_host("127.0.0.1", authenticated=False) == "127.0.0.1"
    assert validated_bind_host("::1", authenticated=False) == "::1"
    assert validated_bind_host("localhost", authenticated=False) == "localhost"
    # Container images bind 0.0.0.0 and rely on a loopback-only published port.
    assert validated_bind_host("0.0.0.0", authenticated=False) == "0.0.0.0"


def test_an_authenticated_server_may_bind_a_reachable_address() -> None:
    assert validated_bind_host("203.0.113.9", authenticated=True) == "203.0.113.9"
