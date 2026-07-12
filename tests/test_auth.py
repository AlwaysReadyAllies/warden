"""Tests for the MCP OAuth 2.1 Resource-Server auth (RFC 9728 / RFC 8707 / JWKS)."""
import json
import time

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import rsa

from warden.auth import (
    AuthConfig, AuthError, JwksCache, TokenValidator,
    protected_resource_metadata, www_authenticate,
)

RESOURCE = "https://warden.example/mcp"
ISSUER = "https://auth.example/"
KID = "test-key-1"


@pytest.fixture(scope="module")
def keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = KID
    pub_jwk["alg"] = "RS256"
    return priv, {"keys": [pub_jwk]}


def _token(priv, *, aud=RESOURCE, iss=ISSUER, scope="mcp:call", exp_delta=300, sub="user-1",
           extra=None, kid=KID, alg="RS256"):
    now = int(time.time())
    claims = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + exp_delta,
              "scope": scope, "client_id": "client-abc"}
    if extra:
        claims.update(extra)
    return jwt.encode(claims, priv, algorithm=alg, headers={"kid": kid})


def _validator(jwks, required_scopes=("mcp:call",)):
    return TokenValidator(resource=RESOURCE, issuer=ISSUER,
                          jwks=JwksCache(static_jwks=jwks), required_scopes=required_scopes)


# --- happy path ----------------------------------------------------------------------------------

def test_valid_token_authenticates(keys):
    priv, jwks = keys
    p = _validator(jwks).authenticate(f"Bearer {_token(priv)}")
    assert p.subject == "user-1" and p.client_id == "client-abc"
    assert "mcp:call" in p.scopes and RESOURCE in p.audience


# --- RFC 8707 audience binding: THE load-bearing control -----------------------------------------

def test_token_for_another_resource_is_rejected(keys):
    priv, jwks = keys
    tok = _token(priv, aud="https://some-other-service/api")  # minted for a different RS
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(tok)
    assert e.value.error == "invalid_token" and "audience" in e.value.description


# --- signature / algorithm attacks ---------------------------------------------------------------

def test_expired_token_rejected(keys):
    priv, jwks = keys
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(_token(priv, exp_delta=-120))  # beyond the 60s leeway
    assert e.value.error == "invalid_token" and "expired" in e.value.description


def test_wrong_signing_key_rejected(keys):
    _, jwks = keys
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _token(attacker)  # signed by a key not in the JWKS (same kid)
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(forged)
    assert e.value.error == "invalid_token"


def test_alg_none_rejected(keys):
    priv, jwks = keys
    unsigned = jwt.encode({"iss": ISSUER, "sub": "x", "aud": RESOURCE,
                           "iat": int(time.time()), "exp": int(time.time()) + 60, "scope": "mcp:call"},
                          key=None, algorithm="none")
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(unsigned)
    assert e.value.error == "invalid_token" and "algorithm" in e.value.description


def test_wrong_issuer_rejected(keys):
    priv, jwks = keys
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(_token(priv, iss="https://evil.example/"))
    assert e.value.error == "invalid_token"


# --- scopes --------------------------------------------------------------------------------------

def test_missing_scope_is_insufficient_scope(keys):
    priv, jwks = keys
    v = _validator(jwks, required_scopes=("mcp:call", "mcp:admin"))
    with pytest.raises(AuthError) as e:
        v.validate(_token(priv, scope="mcp:call"))  # lacks mcp:admin
    assert e.value.error == "insufficient_scope" and e.value.status == 403


def test_scp_array_scopes_supported(keys):
    priv, jwks = keys
    tok = _token(priv, scope="", extra={"scp": ["mcp:call", "mcp:read"]})
    # remove the string 'scope' claim path by passing scope=None → _token still sets scope=None
    p = _validator(jwks).validate(tok)
    assert "mcp:call" in p.scopes


# --- header parsing ------------------------------------------------------------------------------

def test_missing_header_is_invalid_request(keys):
    _, jwks = keys
    for bad in [None, "", "Basic abc", "Bearer", "Bearer   "]:
        with pytest.raises(AuthError) as e:
            _validator(jwks).authenticate(bad)
        assert e.value.error == "invalid_request"


def test_unknown_kid_rejected(keys):
    priv, jwks = keys
    with pytest.raises(AuthError) as e:
        _validator(jwks).validate(_token(priv, kid="nope"))
    assert e.value.error == "invalid_token"


# --- metadata + challenge (RFC 9728 / RFC 6750) --------------------------------------------------

def test_protected_resource_metadata_shape():
    doc = protected_resource_metadata(RESOURCE, [ISSUER], scopes_supported=["mcp:call"])
    assert doc["resource"] == RESOURCE
    assert doc["authorization_servers"] == [ISSUER]
    assert doc["bearer_methods_supported"] == ["header"]
    assert doc["scopes_supported"] == ["mcp:call"]


def test_www_authenticate_points_at_prm():
    h = www_authenticate("https://warden.example/.well-known/oauth-protected-resource",
                         error="invalid_token", description="token expired")
    assert 'resource_metadata="https://warden.example/.well-known/oauth-protected-resource"' in h
    assert 'error="invalid_token"' in h


# --- config fail-closed --------------------------------------------------------------------------

def test_authconfig_absent_is_disabled():
    assert AuthConfig.from_mapping(None).enabled is False
    assert AuthConfig.from_mapping({}).enabled is False


def test_authconfig_enabled_requires_fields():
    with pytest.raises(ValueError):
        AuthConfig.from_mapping({"enabled": True, "resource": RESOURCE})  # missing issuer/jwks


def test_authconfig_builds_validator(keys):
    priv, jwks = keys
    cfg = AuthConfig.from_mapping({
        "resource": RESOURCE, "issuer": ISSUER, "jwks_uri": "https://auth.example/jwks",
        "required_scopes": ["mcp:call"],
    })
    v = cfg.build_validator(static_jwks=jwks)  # static jwks overrides the uri for the test
    assert v.validate(f"{_token(priv)}".replace("Bearer ", "")).subject == "user-1"
    assert cfg.metadata()["resource"] == RESOURCE
