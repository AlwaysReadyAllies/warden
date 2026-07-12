"""MCP OAuth 2.1 Resource-Server authorization for Warden.

The MCP authorization spec (2025-06-18, extended 2025-11-25) makes an MCP server an **OAuth 2.1
Resource Server**: it *consumes* access tokens, never issues them. This module implements exactly that
role for Warden's upstream (client-facing) side:

  * **RFC 9728 Protected Resource Metadata** — Warden advertises, at
    ``/.well-known/oauth-protected-resource``, which authorization server(s) issue tokens for it and
    which scopes exist, so a client can discover where to get a token.
  * **RFC 8707 Resource Indicators (audience binding)** — the load-bearing control. A presented token
    is accepted ONLY if its ``aud`` names *this* resource. A token minted for some other service
    cannot be replayed at Warden. This is the direct defense against the confused-deputy / token-
    passthrough attacks the MCP security-best-practices page calls out.
  * **Asymmetric signature verification via JWKS** — the token signature is checked against the
    authorization server's published keys. The algorithm allow-list is asymmetric-only, so the
    classic ``alg:none`` and RS/HS confusion attacks are refused.
  * **Scope enforcement** — required scopes must be present, else ``403 insufficient_scope``.

NON-GOALS / boundaries (stated):
  * Warden does not ISSUE tokens and does not proxy the authorization-code/PKCE dance — that is the
    authorization server's job; Warden only validates.
  * **No token passthrough.** The validated token authorizes the client to Warden; it is NEVER
    forwarded to downstream MCP servers (Warden's downstreams are local/stdio and get no token).
  * The **stdio** transport is a local, single-user trust boundary — auth engages on the **HTTP**
    transport, where a remote client presents ``Authorization: Bearer <token>``.

Requires the ``auth`` extra (``pip install warden-mcp[auth]``): PyJWT + cryptography + httpx. Import
is lazy so the core proxy runs without these installed.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


class AuthError(Exception):
    """An OAuth 2.0 bearer-token error (RFC 6750). Carries the error code + HTTP status."""

    def __init__(self, error: str, description: str = "", status: int = 401) -> None:
        super().__init__(f"{error}: {description}" if description else error)
        self.error = error            # invalid_request | invalid_token | insufficient_scope
        self.description = description
        self.status = status


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, derived from a validated token."""

    subject: str
    client_id: str | None
    scopes: frozenset[str]
    audience: tuple[str, ...]
    claims: Mapping[str, Any] = field(default_factory=dict)

    def has_scopes(self, required: Iterable[str]) -> bool:
        return set(required).issubset(self.scopes)


def protected_resource_metadata(
    resource: str,
    authorization_servers: list[str],
    *,
    scopes_supported: list[str] | None = None,
    bearer_methods_supported: list[str] | None = None,
) -> dict[str, Any]:
    """RFC 9728 document served at ``/.well-known/oauth-protected-resource``."""
    doc: dict[str, Any] = {
        "resource": resource,
        "authorization_servers": list(authorization_servers),
        "bearer_methods_supported": bearer_methods_supported or ["header"],
    }
    if scopes_supported:
        doc["scopes_supported"] = list(scopes_supported)
    return doc


def www_authenticate(resource_metadata_url: str, error: str | None = None,
                     description: str = "") -> str:
    """The ``WWW-Authenticate`` header value for a 401/403 (points clients at the PRM, per MCP)."""
    parts = [f'Bearer resource_metadata="{resource_metadata_url}"']
    if error:
        parts.append(f'error="{error}"')
        if description:
            parts.append(f'error_description="{description}"')
    return ", ".join(parts)


def _extract_scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    # RFC 8693 uses space-delimited "scope"; some ASes emit a "scp" array. An empty/whitespace
    # "scope" string is treated as absent so the "scp" fallback still applies.
    scope = claims.get("scope")
    if isinstance(scope, str) and scope.strip():
        return frozenset(scope.split())
    scp = claims.get("scp")
    if isinstance(scp, list):
        return frozenset(str(s) for s in scp)
    if isinstance(scope, list):
        return frozenset(str(s) for s in scope)
    return frozenset()


class JwksCache:
    """Fetches + caches an authorization server's JWKS, refreshing on an unknown ``kid``.

    A static ``keys`` dict may be supplied instead of a URL (tests / offline). Unknown-kid refresh is
    rate-limited so a token with a bogus kid can't force unbounded fetches (DoS).
    """

    def __init__(self, jwks_uri: str | None = None, static_jwks: Mapping[str, Any] | None = None,
                 ttl: float = 3600.0, min_refresh_interval: float = 60.0) -> None:
        if not jwks_uri and static_jwks is None:
            raise ValueError("JwksCache needs jwks_uri or static_jwks")
        self.jwks_uri = jwks_uri
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        if static_jwks is not None:
            self._load(static_jwks)
            self._fetched_at = float("inf")  # static keys never expire

    def _load(self, jwks: Mapping[str, Any]) -> None:
        from jwt import PyJWK  # lazy
        keys: dict[str, Any] = {}
        for jwk in jwks.get("keys", []):
            try:
                keys[jwk.get("kid", "")] = PyJWK(jwk)
            except Exception:
                continue  # skip malformed keys; a bad key must not poison the whole set
        self._keys = keys

    def _refresh(self) -> None:
        if not self.jwks_uri:
            return
        import httpx  # lazy
        resp = httpx.get(self.jwks_uri, timeout=10.0)
        resp.raise_for_status()
        self._load(resp.json())
        self._fetched_at = time.monotonic()

    def get_key(self, kid: str) -> Any:
        now = time.monotonic()
        if self._fetched_at != float("inf") and now - self._fetched_at > self.ttl:
            self._refresh()
        if kid in self._keys:
            return self._keys[kid].key
        # unknown kid → maybe the AS rotated; refresh once, rate-limited
        if self.jwks_uri and now - self._fetched_at > self.min_refresh_interval:
            self._refresh()
        if kid in self._keys:
            return self._keys[kid].key
        raise AuthError("invalid_token", f"unknown signing key kid={kid!r}")


# Asymmetric algorithms ONLY. Never HS* (symmetric-key confusion with a public JWKS) and never "none".
_ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "EdDSA")


@dataclass
class TokenValidator:
    """Validates a bearer access token for this resource (RFC 8707 audience-bound)."""

    resource: str
    issuer: str
    jwks: JwksCache
    required_scopes: tuple[str, ...] = ()
    algorithms: tuple[str, ...] = _ALLOWED_ALGS
    leeway: float = 60.0  # clock-skew tolerance (bounded)

    def validate(self, token: str) -> Principal:
        import jwt  # lazy
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise AuthError("invalid_token", f"malformed token header: {exc}")
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise AuthError("invalid_token", f"disallowed algorithm: {alg!r}")
        key = self.jwks.get_key(header.get("kid", ""))
        try:
            claims = jwt.decode(
                token, key=key, algorithms=list(self.algorithms), issuer=self.issuer,
                audience=self.resource,  # RFC 8707: token MUST be for THIS resource
                leeway=self.leeway,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("invalid_token", "token expired")
        except jwt.InvalidAudienceError:
            raise AuthError("invalid_token", f"token audience does not include {self.resource!r}")
        except jwt.InvalidIssuerError:
            raise AuthError("invalid_token", "token issuer mismatch")
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token", f"token verification failed: {exc}")

        scopes = _extract_scopes(claims)
        if self.required_scopes and not set(self.required_scopes).issubset(scopes):
            missing = sorted(set(self.required_scopes) - scopes)
            raise AuthError("insufficient_scope", f"missing scopes: {missing}", status=403)

        aud = claims.get("aud")
        aud_tuple = tuple(aud) if isinstance(aud, list) else (aud,) if aud else ()
        return Principal(
            subject=str(claims.get("sub", "")),
            client_id=claims.get("client_id") or claims.get("azp"),
            scopes=scopes,
            audience=aud_tuple,
            claims=claims,
        )

    def authenticate(self, authorization_header: str | None) -> Principal:
        """Validate an ``Authorization: Bearer <token>`` header value → Principal, or raise."""
        if not authorization_header:
            raise AuthError("invalid_request", "missing Authorization header")
        parts = authorization_header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            raise AuthError("invalid_request", "expected 'Authorization: Bearer <token>'")
        return self.validate(parts[1].strip())


@dataclass
class AuthConfig:
    """Parsed ``auth:`` config block. Absent/disabled ⇒ no auth (stdio local-trust default)."""

    enabled: bool = False
    resource: str = ""
    issuer: str = ""
    authorization_servers: tuple[str, ...] = ()
    jwks_uri: str = ""
    required_scopes: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "AuthConfig":
        if not raw:
            return cls(enabled=False)
        # fail closed: if auth is declared, resource + issuer + a key source are mandatory
        enabled = bool(raw.get("enabled", True))
        cfg = cls(
            enabled=enabled,
            resource=str(raw.get("resource", "")),
            issuer=str(raw.get("issuer", "")),
            authorization_servers=tuple(raw.get("authorization_servers", ()) or ()),
            jwks_uri=str(raw.get("jwks_uri", "")),
            required_scopes=tuple(raw.get("required_scopes", ()) or ()),
            scopes_supported=tuple(raw.get("scopes_supported", ()) or ()),
        )
        if enabled and (not cfg.resource or not cfg.issuer or not (cfg.jwks_uri or cfg.authorization_servers)):
            raise ValueError("auth.enabled requires resource, issuer, and jwks_uri (or authorization_servers)")
        return cfg

    def build_validator(self, static_jwks: Mapping[str, Any] | None = None) -> TokenValidator:
        jwks = JwksCache(jwks_uri=self.jwks_uri or None, static_jwks=static_jwks)
        return TokenValidator(
            resource=self.resource, issuer=self.issuer, jwks=jwks,
            required_scopes=self.required_scopes,
        )

    def metadata(self) -> dict[str, Any]:
        # RFC 9728 requires at least one authorization server; default to the issuer if not listed.
        servers = list(self.authorization_servers) or ([self.issuer] if self.issuer else [])
        return protected_resource_metadata(
            self.resource, servers,
            scopes_supported=list(self.scopes_supported) or None,
        )


__all__ = [
    "AuthError", "Principal", "TokenValidator", "JwksCache", "AuthConfig",
    "protected_resource_metadata", "www_authenticate",
]
