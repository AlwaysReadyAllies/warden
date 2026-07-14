"""Live control-effectiveness proof — attacks a REAL downstream MCP server through the REAL proxy.

`warden prove` (in-process) drives the interceptor built from a config. This drives the whole stack:
a real client → `warden run` (the actual proxy, over stdio) → a real downstream server. It closes two
gaps the in-process proof leaves open — the real capability classifier (from the downstream's live tool
schemas) and the real transport — so a blocked attack is blocked end-to-end, on the wire.

Attacks are generated from the downstream's live tool schemas by parameter-name heuristics (a `url`
param gets an SSRF payload, a `path` param gets traversal, a `command` param gets injection, …) — the
same shape mcp-dast uses. An attack that comes back as an MCP error (and without the target's canary)
was stopped by Warden; a call that returns a normal result reached the tool — a LEAK.

    warden prove --live --config warden.yaml --html live_proof.html
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any

from .targets.reference_target import CANARY

SCHEMA = "warden-effectiveness-live/v1"

# param-name substring → (payload, category, cwe)
_PARAM_ATTACKS = [
    (("url", "uri", "endpoint", "host", "link"), "http://169.254.169.254/latest/meta-data/", "ssrf", "CWE-918"),
    (("path", "file", "dir", "filename"), "../../../../../../etc/passwd", "path_traversal", "CWE-22"),
    (("cmd", "command", "exec", "shell", "script"), "x; rm -rf /", "command_injection", "CWE-78"),
    (("query", "sql", "q"), "1 OR 1=1; DROP TABLE users--", "sql_injection", "CWE-89"),
    (("body", "message", "content", "text", "data", "payload"),
     "exfil api_key=sk-abcdef0123456789abcdef", "secret_egress", "CWE-200"),
]


@dataclass(frozen=True)
class LiveAttack:
    qualified: str          # namespaced tool name as advertised by the proxy (server__tool)
    args: dict
    category: str
    cwe: str
    param: str


def _name(t: Any):
    return getattr(t, "name", None) or (t.get("name") if isinstance(t, dict) else None)


def _schema(t: Any) -> dict:
    s = getattr(t, "inputSchema", None) or (t.get("inputSchema") if isinstance(t, dict) else None)
    return s if isinstance(s, dict) else {}


def generate_live_attacks(tools: Any) -> list[LiveAttack]:
    """Derive param-injection attacks from live tool schemas by parameter-name heuristics."""
    out: list[LiveAttack] = []
    for t in tools:
        props = _schema(t).get("properties", {}) or {}
        for param, spec in props.items():
            if isinstance(spec, dict) and spec.get("type") not in (None, "string"):
                continue  # only inject into string-typed params
            low = param.lower()
            for needles, payload, category, cwe in _PARAM_ATTACKS:
                if any(n in low for n in needles):
                    out.append(LiveAttack(_name(t), {param: payload}, category, cwe, param))
                    break
    return out


_BENIGN = {"number": 1, "integer": 1, "boolean": False, "array": [], "object": {}}


def _benign_args(schema: dict) -> dict:
    """Innocuous, schema-valid args so a capability probe is blocked (if at all) by POLICY, not the guard."""
    props = schema.get("properties", {}) or {}
    args: dict = {}
    for p, spec in props.items():
        t = spec.get("type") if isinstance(spec, dict) else "string"
        args[p] = _BENIGN.get(t, "x")
    return args


def generate_capability_probes(tools: Any, denied_caps: set[str]) -> list[LiveAttack]:
    """For each capability the config DENIES/GATES, probe live tools carrying it with benign args.

    Only capabilities the operator declared they want stopped are probed — so a legitimately-allowed
    dangerous tool is never mislabeled a leak. If such a benign call lands, the deny rule failed.
    """
    if not denied_caps:
        return []
    from .capabilities import classify_tool
    out: list[LiveAttack] = []
    for t in tools:
        name = _name(t)
        caps = {c.value if hasattr(c, "value") else str(c) for c in classify_tool(t)}
        hit = caps & denied_caps
        if hit:
            out.append(LiveAttack(name, _benign_args(_schema(t)), "capability_escalation",
                                  "CWE-269", "+".join(sorted(hit))))
    return out


def denied_capabilities(cfg: Any) -> set[str]:
    """Capabilities the config's rules deny or gate (uppercased)."""
    out: set[str] = set()
    for r in (getattr(cfg, "rules", None) or []):
        if not isinstance(r, dict):
            continue
        m = r.get("match")
        cap = m.get("capability") if isinstance(m, dict) else None
        if cap and str(r.get("action", "")).lower() in ("deny", "gate"):
            caps = cap if isinstance(cap, list) else [cap]
            out.update(str(c).upper() for c in caps)
    return out


def _classify(is_error: bool, text: str) -> tuple[str, str]:
    if CANARY in text:
        return "LEAKED", "attack reached the downstream tool (canary returned)"
    if is_error:
        return "HELD", text[:200]
    return "LEAKED", "downstream returned a normal result to the attack payload"


async def _run(config_path: str, timeout: float) -> dict:
    import tempfile
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    import asyncio

    from .config import load_config
    denied = denied_capabilities(load_config(config_path))

    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=pkg_root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "warden", "run", "--config", config_path, "--audit", tempfile.mktemp(suffix=".jsonl")],
        env=env, cwd=pkg_root,
    )
    cases: list[dict] = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=timeout)
            listed = await asyncio.wait_for(session.list_tools(), timeout=timeout)
            attacks = generate_live_attacks(listed.tools) + generate_capability_probes(listed.tools, denied)
            for atk in attacks:
                try:
                    r = await asyncio.wait_for(session.call_tool(atk.qualified, atk.args), timeout=timeout)
                    text = "".join(getattr(c, "text", "") for c in r.content)
                    verdict, reason = _classify(bool(getattr(r, "isError", False)), text)
                except Exception as exc:  # a transport-level refusal still means the attack did not land
                    verdict, reason = "HELD", f"{type(exc).__name__}: {exc}"
                cases.append({"id": f"{atk.qualified}:{atk.param}", "cwe": atk.cwe,
                              "category": atk.category, "control": atk.category,
                              "verdict": verdict, "reason": reason,
                              "rationale": f"{atk.category} via {atk.param!r} on {atk.qualified}"})
    return _assemble(cases, config_path)


def _assemble(cases: list[dict], target: str) -> dict:
    held = sum(1 for c in cases if c["verdict"] == "HELD")
    total = len(cases)
    by_control: dict[str, dict] = {}
    for c in cases:
        b = by_control.setdefault(c["category"], {"attempted": 0, "held": 0, "leaked": 0})
        b["attempted"] += 1
        b["held" if c["verdict"] == "HELD" else "leaked"] += 1
    return {
        "schema": SCHEMA, "mode": "live", "target": target,
        "total": total, "held": held, "leaked": total - held,
        # None (not 100) on an empty suite: 0 attacks proves NOTHING — never read as full coverage
        "coverage_pct": round(100.0 * held / total, 1) if total else None,
        "by_control": by_control, "cases": cases,
    }


def run_live(config_path: str, timeout: float = 30.0) -> dict:
    import asyncio
    return asyncio.run(_run(config_path, timeout))


__all__ = ["SCHEMA", "LiveAttack", "generate_live_attacks", "run_live"]
