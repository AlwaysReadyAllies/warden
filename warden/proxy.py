"""MCP proxy core for Warden.

The proxy exposes configured downstream MCP tools under stable
``server__tool`` names and routes calls through the supplied interceptor.
"""
from __future__ import annotations

import asyncio
import copy
import inspect
import re
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .schemas import Forwarder, ToolCall


SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10.0
DEFAULT_CALL_TIMEOUT_SECONDS = 30.0


class ProxySecurityError(ValueError):
    """Raised when a requested route is not authorized by proxy policy."""


@dataclass(frozen=True)
class DownstreamSpec:
    server_id: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = None
    cwd: str | None = None
    url: str | None = None
    allowed_tools: frozenset[str] = frozenset()
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS
    call_timeout_seconds: float = DEFAULT_CALL_TIMEOUT_SECONDS


@dataclass
class Downstream:
    spec: DownstreamSpec
    session: Any
    tools: dict[str, Tool]


def parse_qualified_name(name: str) -> tuple[str, str]:
    """Return ``(server_id, bare_tool)`` from an upstream ``server__tool`` name."""
    # SECURITY: Qualified names must have exactly one namespace separator so
    # malicious tool names cannot smuggle an alternate server id or confuse
    # authorization with strings like "a__b__c".
    if name.count("__") != 1:
        raise ProxySecurityError(f"invalid qualified tool name: {name!r}")
    server_id, tool_name = name.split("__", 1)
    # SECURITY: Server ids and exposed tool names are restricted to a stable
    # ASCII identifier subset. This rejects control characters, path-like
    # payloads, whitespace tricks, and prompt-looking names before routing.
    if not _is_safe_identifier(server_id) or not _is_safe_identifier(tool_name):
        raise ProxySecurityError(f"unsafe qualified tool name: {name!r}")
    return server_id, tool_name


async def dispatch(
    call: ToolCall,
    sessions: Mapping[str, Any],
    interceptor: Any,
    *,
    allowed_tools: Mapping[str, frozenset[str]] | None = None,
    timeout_seconds: Mapping[str, float] | float | None = None,
) -> Any:
    """Route one authorized ``ToolCall`` through the interceptor.

    This function has no process-spawning or network setup, so unit tests can
    pass mock sessions and a fake interceptor directly.
    """
    allowed_tools = allowed_tools or {}
    # SECURITY: Authorization is checked from local config-derived state, never
    # from downstream metadata, so a server cannot expose or call itself into
    # extra privileges by changing its tools/list response.
    if call.server not in sessions:
        raise ProxySecurityError(f"unknown downstream server: {call.server!r}")
    # SECURITY: Calls are denied unless the requested bare tool is in the
    # configured allow-list for that server. Missing allow-lists are default
    # deny rather than default allow.
    if call.tool not in allowed_tools.get(call.server, frozenset()):
        raise ProxySecurityError(f"tool is not permitted: {call.qualified!r}")

    session = sessions[call.server]
    call_timeout = _timeout_for(call.server, timeout_seconds)

    def forward(forwarded: ToolCall) -> Any:
        # SECURITY: The interceptor is not allowed to rewrite the destination
        # server/tool when using this route's forwarder. A policy bug or hostile
        # interceptor result cannot convert approval for one tool into a call to
        # another tool.
        if forwarded.server != call.server or forwarded.tool != call.tool:
            raise ProxySecurityError("forwarder destination rewrite refused")
        # SECURITY: Each downstream call is individually time-bounded so a hung
        # server consumes only this request, not the proxy process or other
        # downstream sessions.
        return _call_tool_with_optional_timeout(session, forwarded.tool, forwarded.args, call_timeout)

    result = interceptor.run(call, forward)
    if inspect.isawaitable(result):
        result = await result
    return result


class WardenProxy:
    """MCP upstream server plus downstream MCP clients."""

    def __init__(self, config: Mapping[str, Any], interceptor: Any):
        self.config = config
        self.interceptor = interceptor
        self.specs = parse_config(config)
        self.server = Server("warden-proxy")
        self._exit_stack = AsyncExitStack()
        self._downstreams: dict[str, Downstream] = {}
        self._advertised_tools: list[Tool] = []
        self._started = False
        self._install_handlers()

    async def start(self) -> None:
        """Connect configured downstreams and build the upstream tool list."""
        if self._started:
            return
        advertised: list[Tool] = []
        for spec in self.specs:
            try:
                downstream = await self._connect_downstream(spec)
            except Exception:
                # SECURITY: A failing or malicious downstream must not prevent
                # the proxy from serving other configured servers. We isolate
                # startup failures per server and simply expose no tools for the
                # failed server.
                continue
            self._downstreams[spec.server_id] = downstream
            advertised.extend(_advertised_tools_for(downstream))
        # SECURITY: The advertised list is derived after validation and
        # namespacing. It is not a direct pass-through of downstream tools/list,
        # preventing name shadowing and untrusted metadata propagation.
        self._advertised_tools = advertised
        self._started = True

    async def close(self) -> None:
        await self._exit_stack.aclose()
        self._downstreams.clear()
        self._advertised_tools.clear()
        self._started = False

    async def run_stdio(self) -> None:
        await self.start()
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream, self.server.create_initialization_options())

    async def _connect_downstream(self, spec: DownstreamSpec) -> Downstream:
        # SECURITY: Exactly one transport is selected from config. Ambiguous
        # transport settings are rejected during config parsing so a malicious
        # config cannot make the proxy connect somewhere other than intended.
        if spec.command:
            params = StdioServerParameters(
                command=spec.command,
                args=list(spec.args),
                env=dict(spec.env) if spec.env is not None else None,
                cwd=spec.cwd,
            )
            streams = await asyncio.wait_for(
                self._exit_stack.enter_async_context(stdio_client(params)),
                timeout=spec.connect_timeout_seconds,
            )
            read_stream, write_stream = streams
        else:
            streams = await asyncio.wait_for(
                self._exit_stack.enter_async_context(
                    streamablehttp_client(
                        spec.url or "",
                        timeout=spec.connect_timeout_seconds,
                        sse_read_timeout=spec.call_timeout_seconds,
                    )
                ),
                timeout=spec.connect_timeout_seconds,
            )
            read_stream, write_stream, _get_session_id = streams

        session = await self._exit_stack.enter_async_context(
            ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=spec.call_timeout_seconds),
            )
        )
        await asyncio.wait_for(session.initialize(), timeout=spec.connect_timeout_seconds)
        listed = await asyncio.wait_for(session.list_tools(), timeout=spec.connect_timeout_seconds)

        tools: dict[str, Tool] = {}
        for tool in listed.tools:
            # SECURITY: Downstream tool names are untrusted. We only accept
            # configured, safe bare names and refuse "__" so upstream namespace
            # parsing cannot be bypassed.
            if "*" not in spec.allowed_tools and tool.name not in spec.allowed_tools:
                continue
            if not _is_safe_tool_name(tool.name):
                continue
            tools[tool.name] = tool

        return Downstream(spec=spec, session=session, tools=tools)

    def _install_handlers(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            if not self._started:
                await self.start()
            return self._advertised_tools

        @self.server.call_tool(validate_input=True)
        async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
            if not self._started:
                await self.start()
            try:
                server_id, tool_name = parse_qualified_name(name)
                call = ToolCall(server=server_id, tool=tool_name, args=arguments or {})
                result = await dispatch(
                    call,
                    {server_id: downstream.session for server_id, downstream in self._downstreams.items()},
                    self.interceptor,
                    allowed_tools={
                        server_id: frozenset(downstream.tools)
                        for server_id, downstream in self._downstreams.items()
                    },
                    timeout_seconds={
                        server_id: downstream.spec.call_timeout_seconds
                        for server_id, downstream in self._downstreams.items()
                    },
                )
                if inspect.isawaitable(result):
                    result = await result
                return result
            except Exception as exc:
                return _error_result(str(exc))


def parse_config(config: Mapping[str, Any]) -> list[DownstreamSpec]:
    servers = config.get("servers", config)
    if not isinstance(servers, Mapping):
        raise ValueError("proxy config must contain a mapping of servers")

    specs: list[DownstreamSpec] = []
    seen: set[str] = set()
    for server_id, raw in servers.items():
        if not isinstance(server_id, str) or not _is_safe_identifier(server_id) or "__" in server_id:
            # SECURITY: Server ids are trusted config but still validated so a
            # mistaken or compromised config cannot create ambiguous upstream
            # names or non-printing spoofed namespaces.
            raise ValueError(f"unsafe server id: {server_id!r}")
        if server_id in seen:
            # SECURITY: Duplicate server ids would make one downstream shadow
            # another inside the routing map, so they are rejected.
            raise ValueError(f"duplicate server id: {server_id!r}")
        seen.add(server_id)
        if not isinstance(raw, Mapping):
            raise ValueError(f"server config must be a mapping: {server_id!r}")

        command = raw.get("command", raw.get("cmd"))
        url = raw.get("url", raw.get("http_url"))
        if bool(command) == bool(url):
            # SECURITY: A server gets exactly one downstream transport. Requiring
            # this prevents fallback surprises and config smuggling.
            raise ValueError(f"configure exactly one of command/cmd or url/http_url for {server_id!r}")

        allowed = _configured_tools(raw)
        # SECURITY: Least privilege is enforced by requiring an explicit
        # allow-list. Use the literal "*" only as an intentional opt-in to all
        # currently listed tools.
        if not allowed:
            raise ValueError(f"server {server_id!r} must configure allowed tools")
        if "*" in allowed and len(allowed) > 1:
            raise ValueError(f"server {server_id!r} cannot mix '*' with named tools")
        for tool_name in allowed:
            if tool_name != "*" and not _is_safe_tool_name(tool_name):
                # SECURITY: Configured tool names are validated with the same
                # rules as downstream names so namespace parsing has one policy.
                raise ValueError(f"unsafe tool name in config: {server_id!r}.{tool_name!r}")

        specs.append(
            DownstreamSpec(
                server_id=server_id,
                command=str(command) if command else None,
                args=tuple(str(arg) for arg in raw.get("args", ())),
                env=raw.get("env"),
                cwd=raw.get("cwd"),
                url=str(url) if url else None,
                allowed_tools=frozenset(allowed),
                connect_timeout_seconds=float(
                    raw.get("connect_timeout_seconds", DEFAULT_CONNECT_TIMEOUT_SECONDS)
                ),
                call_timeout_seconds=float(raw.get("call_timeout_seconds", DEFAULT_CALL_TIMEOUT_SECONDS)),
            )
        )
    return specs


def _configured_tools(raw: Mapping[str, Any]) -> set[str]:
    value = raw.get("allowed_tools", raw.get("allow_tools", raw.get("tools")))
    if value == "*":
        return {"*"}
    if isinstance(value, str):
        return {value}
    if value is None:
        return set()
    return {str(item) for item in value}


def _advertised_tools_for(downstream: Downstream) -> list[Tool]:
    allowed = downstream.spec.allowed_tools
    tools: list[Tool] = []
    for name, tool in downstream.tools.items():
        if "*" not in allowed and name not in allowed:
            continue
        qualified_name = f"{downstream.spec.server_id}__{name}"
        # SECURITY: Do not propagate downstream descriptions, titles,
        # annotations, icons, or metadata. Tool metadata is prompt-visible to
        # clients and can contain prompt-injection from a malicious MCP server.
        tools.append(
            Tool(
                name=qualified_name,
                description=f"Configured Warden proxy tool: {qualified_name}",
                inputSchema=_sanitized_schema(tool.inputSchema),
            )
        )
    return tools


def _sanitized_schema(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, Mapping):
        return {"type": "object", "additionalProperties": True}
    schema_copy = copy.deepcopy(dict(schema))
    # SECURITY: JSON Schema annotations such as description/title/examples are
    # also prompt-visible untrusted metadata. We preserve validation structure
    # while removing prose and examples that can carry instructions or secrets.
    return _strip_schema_annotations(schema_copy)


def _strip_schema_annotations(value: Any) -> Any:
    blocked = {"description", "title", "examples", "default", "$comment"}
    if isinstance(value, dict):
        return {
            key: _strip_schema_annotations(item)
            for key, item in value.items()
            if key not in blocked
        }
    if isinstance(value, list):
        return [_strip_schema_annotations(item) for item in value]
    return value


def _is_safe_identifier(name: str) -> bool:
    return bool(name) and bool(SAFE_NAME_RE.fullmatch(name))


def _is_safe_tool_name(name: str) -> bool:
    return _is_safe_identifier(name) and "__" not in name


def _timeout_for(server_id: str, timeouts: Mapping[str, float] | float | None) -> float | None:
    if isinstance(timeouts, Mapping):
        return timeouts.get(server_id)
    return timeouts


def _call_tool_with_optional_timeout(
    session: Any,
    tool: str,
    args: dict[str, Any],
    timeout_seconds: float | None,
) -> Any:
    result = session.call_tool(tool, args)
    if inspect.isawaitable(result):
        return _await_with_timeout(result, timeout_seconds)
    return result


async def _await_with_timeout(awaitable: Any, timeout_seconds: float | None) -> Any:
    if timeout_seconds is None:
        return await awaitable
    return await asyncio.wait_for(awaitable, timeout=timeout_seconds)


def _error_result(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], isError=True)


__all__ = [
    "WardenProxy",
    "DownstreamSpec",
    "Downstream",
    "ProxySecurityError",
    "parse_config",
    "parse_qualified_name",
    "dispatch",
]
