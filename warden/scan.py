"""mcp-scan — audit an MCP server BEFORE you trust it.

Warden guards tool calls at runtime; this is the static, pre-install companion. Point it at an MCP
server (or a tool list) and it inspects every tool DEFINITION for the agent-supply-chain risks the
research is full of and no OPEN tool currently owns (Invariant's mcp-scan went closed to Snyk):

  * **Tool poisoning / prompt injection** hidden in a tool's description or schema prose — the model
    reads it, the user doesn't (reuses Warden's guard corpus).
  * **Secrets** leaked in descriptions/schemas.
  * **Dangerous capabilities** — a tool that reads untrusted content (a *source*), one that can
    exfiltrate (a *sink*), one that is destructive, or one that reads private data; and the
    **lethal-trifecta combination** when a single server offers both a source and a sink.
  * **Rug-pull baseline** — a definition fingerprint so a re-scan detects a silently-changed tool.

Output: a risk report + severity; exit non-zero on high/critical so it gates CI. Reuses
``guard.py`` (detection), ``pinning.py`` (fingerprint), ``flow.py`` (source/sink taxonomy).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .guard import WardenGuard
from .pinning import tool_fingerprint

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# capability taxonomy — keyword heuristics over tool name + description
_CAP_PATTERNS = {
    "source_untrusted": re.compile(r"\b(fetch|browse|crawl|scrape|read[_-]?url|web|http[_-]?get|"
                                   r"search|download|rss|email[_-]?read|read[_-]?mail|open[_-]?url)\b", re.I),
    "sink_exfil": re.compile(r"\b(send|post|upload|publish|webhook|slack|tweet|email[_-]?send|"
                             r"http[_-]?post|message|notify|export|share)\b", re.I),
    "destructive": re.compile(r"\b(delete|drop|destroy|wipe|truncate|remove|rm|shell|exec|eval|"
                              r"run[_-]?command|kill)\b", re.I),
    "private_data": re.compile(r"\b(secret|credential|password|api[_-]?key|token|keychain|env|"
                               r"read[_-]?file|database|query|ssh|private)\b", re.I),
}


@dataclass
class Finding:
    kind: str
    severity: str
    detail: str


@dataclass
class ToolReport:
    name: str
    fingerprint: str
    capabilities: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=lambda s: _SEVERITY_ORDER.get(s, 0),
                   default="info")


@dataclass
class ScanReport:
    server: str
    tools: list[ToolReport] = field(default_factory=list)
    server_findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        sevs = [f.severity for t in self.tools for f in t.findings] + [f.severity for f in self.server_findings]
        return max(sevs, key=lambda s: _SEVERITY_ORDER.get(s, 0), default="info")

    @property
    def risky(self) -> bool:
        return _SEVERITY_ORDER.get(self.worst, 0) >= _SEVERITY_ORDER["high"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "mcp-scan/v1",
            "server": self.server,
            "worst_severity": self.worst,
            "tools": [{
                "name": t.name, "fingerprint": t.fingerprint, "capabilities": t.capabilities,
                "findings": [{"kind": f.kind, "severity": f.severity, "detail": f.detail} for f in t.findings],
            } for t in self.tools],
            "server_findings": [{"kind": f.kind, "severity": f.severity, "detail": f.detail}
                                for f in self.server_findings],
        }


def _tool_text(tool: Any) -> str:
    parts = [str(getattr(tool, "description", "") or "")]
    schema = getattr(tool, "inputSchema", None)
    if isinstance(schema, dict):
        # descriptions/titles inside the schema are also model-visible prose (poisoning surface)
        parts.append(_schema_prose(schema))
    return "\n".join(p for p in parts if p)


def _schema_prose(value: Any) -> str:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k in ("description", "title", "examples", "default") and isinstance(v, str):
                out.append(v)
            else:
                out.append(_schema_prose(v))
    elif isinstance(value, list):
        out.extend(_schema_prose(v) for v in value)
    return " ".join(p for p in out if p)


def _capabilities(name: str, text: str) -> list[str]:
    hay = f"{name} {text}"
    return [cap for cap, pat in _CAP_PATTERNS.items() if pat.search(hay)]


def scan_tool(tool: Any, guard: WardenGuard) -> ToolReport:
    """Inspect one tool definition."""
    name = str(getattr(tool, "name", "?"))
    text = _tool_text(tool)
    rep = ToolReport(name=name, fingerprint=tool_fingerprint(tool))
    rep.capabilities = _capabilities(name, text)

    # prompt injection / secrets in the description or schema prose (tool poisoning)
    if text.strip():
        _redacted, guard_findings = guard.scan_result(text)
        for gf in guard_findings:
            sev = "critical" if gf.kind in ("prompt_injection", "secret_egress") else "high"
            rep.findings.append(Finding(kind=f"tool_poisoning:{gf.kind}", severity=sev, detail=gf.detail))

    if "destructive" in rep.capabilities:
        rep.findings.append(Finding("dangerous_capability", "high",
                                    f"'{name}' appears able to run destructive/irreversible actions"))
    return rep


def assess_server(server: str, tools: list[Any]) -> ScanReport:
    """Scan all of a server's tools and assess cross-tool risk (the lethal-trifecta combination)."""
    guard = WardenGuard()
    report = ScanReport(server=server, tools=[scan_tool(t, guard) for t in tools])

    caps = {c for t in report.tools for c in t.capabilities}
    if "source_untrusted" in caps and "sink_exfil" in caps:
        report.server_findings.append(Finding(
            "lethal_trifecta_capability", "high",
            "this server exposes BOTH an untrusted-content source and an exfiltration sink — an "
            "injected instruction in fetched content could drive data exfil. Gate the sink with "
            "Warden's flow policy."))
    if "private_data" in caps and "sink_exfil" in caps:
        report.server_findings.append(Finding(
            "private_to_sink_capability", "medium",
            "this server can read private data AND exfiltrate — verify the two can't be chained."))
    return report


async def list_tools(*, command: str | None = None, args: tuple[str, ...] = (),
                     env: dict[str, str] | None = None, cwd: str | None = None,
                     url: str | None = None, timeout: float = 15.0) -> list[Any]:
    """Connect to an MCP server (stdio or streamable-HTTP) and return its advertised tools."""
    import asyncio
    from contextlib import AsyncExitStack
    from datetime import timedelta
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.streamable_http import streamablehttp_client

    async with AsyncExitStack() as stack:
        if command:
            params = StdioServerParameters(command=command, args=list(args),
                                           env=env, cwd=cwd)
            read, write = await stack.enter_async_context(stdio_client(params))
        else:
            read, write, _ = await stack.enter_async_context(streamablehttp_client(url or "", timeout=timeout))
        session = await stack.enter_async_context(
            ClientSession(read, write, read_timeout_seconds=timedelta(seconds=timeout)))
        await asyncio.wait_for(session.initialize(), timeout=timeout)
        listed = await asyncio.wait_for(session.list_tools(), timeout=timeout)
        return list(listed.tools)


__all__ = ["Finding", "ToolReport", "ScanReport", "scan_tool", "assess_server", "list_tools"]
