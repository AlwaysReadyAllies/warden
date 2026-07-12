"""HTTP transport for Warden — a deployable MCP gateway with OAuth 2.1 enforcement.

Turns Warden from a local stdio proxy into a remote MCP server over streamable-HTTP, fronted by the
OAuth 2.1 Resource-Server auth in ``auth.py``. Two surfaces:

  * ``GET /.well-known/oauth-protected-resource`` — the RFC 9728 Protected Resource Metadata, so a
    client can discover which authorization server issues tokens for this Warden and what scopes exist.
  * ``/mcp`` — the streamable-HTTP MCP endpoint, wrapped in ``BearerAuthMiddleware``: every request
    must carry a valid ``Authorization: Bearer <token>`` (audience-bound to this resource per RFC 8707)
    or it is rejected with ``401`` + a ``WWW-Authenticate`` challenge pointing at the metadata — before
    the request ever reaches the MCP handler. If no validator is configured the endpoint is open
    (use only behind your own trust boundary).

Requires the ``http`` extra (starlette + uvicorn) and, for auth, the ``auth`` extra. Imports are lazy
so the stdio core needs neither.
"""
from __future__ import annotations

import json
from typing import Any

from .auth import AuthError, TokenValidator, www_authenticate

DEFAULT_MCP_PATH = "/mcp"
METADATA_PATH = "/.well-known/oauth-protected-resource"


async def _send_json(send, status: int, body: dict[str, Any], extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    payload = json.dumps(body).encode("utf-8")
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


class BearerAuthMiddleware:
    """ASGI middleware: validate the bearer token before delegating to the wrapped app.

    Wraps ANY ASGI app (here, the MCP streamable-HTTP handler). Rejects missing/invalid/wrong-audience
    tokens with the correct OAuth 2.0 bearer error + a WWW-Authenticate challenge (RFC 6750 / MCP).
    """

    def __init__(self, app, validator: TokenValidator, metadata_url: str) -> None:
        self.app = app
        self.validator = validator
        self.metadata_url = metadata_url

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        try:
            self.validator.authenticate(headers.get("authorization"))
        except AuthError as exc:
            challenge = www_authenticate(self.metadata_url, error=exc.error, description=exc.description)
            await _send_json(
                send, exc.status,
                {"error": exc.error, "error_description": exc.description},
                extra_headers=[(b"www-authenticate", challenge.encode("latin-1"))],
            )
            return
        await self.app(scope, receive, send)


def build_asgi_app(
    proxy: Any,
    *,
    validator: TokenValidator | None = None,
    resource_metadata: dict[str, Any] | None = None,
    mcp_path: str = DEFAULT_MCP_PATH,
):
    """Build a pure-ASGI app fronting ``proxy`` (a started or startable WardenProxy).

    Hand-rolled dispatch (no framework routing) so the auth gate runs BEFORE any path handling and a
    bare ``POST /mcp`` is never redirected around it. ``validator`` enables auth on the MCP endpoint;
    ``resource_metadata`` is served (publicly) at the RFC 9728 well-known path.
    """
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    session_manager = StreamableHTTPSessionManager(app=proxy.server, stateless=False)
    mcp_prefix = mcp_path.rstrip("/")

    async def handle_mcp(scope, receive, send):
        if not getattr(proxy, "_started", False):
            await proxy.start()
        await session_manager.handle_request(scope, receive, send)

    # auth wraps ONLY the MCP handler; the metadata endpoint is always public (RFC 9728)
    guarded_mcp = BearerAuthMiddleware(handle_mcp, validator, METADATA_PATH) if validator else handle_mcp

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            await _lifespan(scope, receive, send, session_manager, proxy)
            return
        if scope["type"] != "http":
            return
        path = scope.get("path", "")
        if path == METADATA_PATH and scope.get("method") == "GET":
            await _send_json(send, 200, resource_metadata or {})
            return
        if path == mcp_prefix or path.startswith(mcp_prefix + "/"):
            await guarded_mcp(scope, receive, send)
            return
        await _send_json(send, 404, {"error": "not_found"})

    return app


async def _lifespan(scope, receive, send, session_manager, proxy) -> None:
    """Minimal ASGI lifespan: hold ``session_manager.run()`` open for the server's lifetime."""
    ctx = None
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            try:
                ctx = session_manager.run()
                await ctx.__aenter__()
                await send({"type": "lifespan.startup.complete"})
            except Exception as exc:  # pragma: no cover
                await send({"type": "lifespan.startup.failed", "message": str(exc)})
                return
        elif message["type"] == "lifespan.shutdown":
            try:
                if ctx is not None:
                    await ctx.__aexit__(None, None, None)
                await proxy.close()
            finally:
                await send({"type": "lifespan.shutdown.complete"})
            return


def run_http(proxy: Any, *, host: str = "127.0.0.1", port: int = 8080,
             validator: TokenValidator | None = None,
             resource_metadata: dict[str, Any] | None = None,
             mcp_path: str = DEFAULT_MCP_PATH) -> None:
    """Serve Warden over HTTP with uvicorn (blocking)."""
    import uvicorn
    app = build_asgi_app(proxy, validator=validator, resource_metadata=resource_metadata, mcp_path=mcp_path)
    uvicorn.run(app, host=host, port=port, log_level="info")


__all__ = ["build_asgi_app", "run_http", "BearerAuthMiddleware", "DEFAULT_MCP_PATH", "METADATA_PATH"]
