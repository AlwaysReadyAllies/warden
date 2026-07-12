"""Tests for the HTTP transport + OAuth enforcement (BearerAuthMiddleware, PRM endpoint)."""
import json
import time

import pytest

pytest.importorskip("starlette")
jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.testclient import TestClient

from warden.auth import JwksCache, TokenValidator, protected_resource_metadata
from warden.http import BearerAuthMiddleware, METADATA_PATH

RESOURCE = "https://warden.example/mcp"
ISSUER = "https://auth.example/"
KID = "k1"


@pytest.fixture(scope="module")
def keyset():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk["kid"] = KID
    jwk["alg"] = "RS256"
    return priv, {"keys": [jwk]}


def _token(priv, *, aud=RESOURCE, scope="mcp:call"):
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "sub": "u", "aud": aud, "iat": now, "exp": now + 300,
                       "scope": scope}, priv, algorithm="RS256", headers={"kid": KID})


def _app(keyset, required_scopes=("mcp:call",)):
    priv, jwks = keyset
    validator = TokenValidator(resource=RESOURCE, issuer=ISSUER,
                               jwks=JwksCache(static_jwks=jwks), required_scopes=required_scopes)

    # a stand-in for the MCP handler: records that it was reached
    reached = {"count": 0}

    async def inner(scope, receive, send):
        reached["count"] += 1
        resp = PlainTextResponse("mcp-handler-reached")
        await resp(scope, receive, send)

    guarded = BearerAuthMiddleware(inner, validator, METADATA_PATH)
    prm = protected_resource_metadata(RESOURCE, [ISSUER], scopes_supported=["mcp:call"])

    async def metadata(_req):
        return JSONResponse(prm)

    app = Starlette(routes=[Route(METADATA_PATH, metadata, methods=["GET"]),
                            Mount("/mcp", app=guarded)])
    return TestClient(app), reached, priv


def test_metadata_endpoint_is_public(keyset):
    client, _, _ = _app(keyset)
    r = client.get(METADATA_PATH)
    assert r.status_code == 200
    assert r.json()["resource"] == RESOURCE
    assert r.json()["authorization_servers"] == [ISSUER]


def test_mcp_without_token_is_401_with_challenge(keyset):
    client, reached, _ = _app(keyset)
    r = client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
    assert r.status_code == 401
    assert "www-authenticate" in {k.lower() for k in r.headers}
    assert 'resource_metadata=' in r.headers["www-authenticate"]
    assert reached["count"] == 0  # never reached the MCP handler


def test_mcp_with_bad_token_is_401(keyset):
    client, reached, _ = _app(keyset)
    r = client.post("/mcp", headers={"authorization": "Bearer not.a.jwt"},
                    json={"jsonrpc": "2.0"})
    assert r.status_code == 401
    assert reached["count"] == 0


def test_mcp_with_wrong_audience_is_401(keyset):
    client, reached, priv = _app(keyset)
    tok = _token(priv, aud="https://someone-else/api")  # RFC 8707 violation
    r = client.post("/mcp", headers={"authorization": f"Bearer {tok}"}, json={})
    assert r.status_code == 401
    assert reached["count"] == 0


def test_mcp_missing_scope_is_403(keyset):
    client, reached, priv = _app(keyset)  # requires mcp:call
    tok = _token(priv, scope="mcp:read")  # lacks mcp:call
    r = client.post("/mcp", headers={"authorization": f"Bearer {tok}"}, json={})
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers.get("www-authenticate", "")
    assert reached["count"] == 0


def test_mcp_with_valid_token_reaches_handler(keyset):
    client, reached, priv = _app(keyset)
    r = client.post("/mcp", headers={"authorization": f"Bearer {_token(priv)}"}, json={})
    assert r.status_code == 200
    assert r.text == "mcp-handler-reached"
    assert reached["count"] == 1  # auth gate passed → handler reached


# --- build_asgi_app integration (the real app: dispatch + auth + PRM) ----------------------------

def test_build_asgi_app_dispatch_and_auth(keyset):
    from types import SimpleNamespace
    from warden.http import build_asgi_app

    priv, jwks = keyset
    validator = TokenValidator(resource=RESOURCE, issuer=ISSUER,
                               jwks=JwksCache(static_jwks=jwks), required_scopes=("mcp:call",))
    prm = protected_resource_metadata(RESOURCE, [ISSUER], scopes_supported=["mcp:call"])

    # a fake proxy: build_asgi_app only touches proxy.server (for the session manager) and .start/.close
    class _FakeSM:
        pass
    # stub the session manager by monkeypatching is heavy; instead assert routing/auth without MCP:
    fake_proxy = SimpleNamespace(server=object(), _started=True,
                                 start=None, close=None)
    # build with a validator; we only exercise the metadata + auth-reject paths (no MCP session needed)
    app = build_asgi_app(fake_proxy, validator=validator, resource_metadata=prm)
    client = TestClient(app)

    # PRM is public
    assert client.get(METADATA_PATH).json()["resource"] == RESOURCE
    # unauthenticated MCP → 401 before any handler
    r = client.post("/mcp", json={"jsonrpc": "2.0"})
    assert r.status_code == 401 and "www-authenticate" in {k.lower() for k in r.headers}
    # unknown path → 404
    assert client.get("/nope").status_code == 404
