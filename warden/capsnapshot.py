"""Capability snapshots + the CI expansion gate.

Records the capability SET of every tool a server exposes, and — on a later run — fails the build if
any tool GAINED a dangerous capability (a read tool that became write/delete/execute, gained network,
credential, financial, or admin reach) or a new dangerous tool appeared. This is capability
supply-chain control: a compromised or updated MCP server that quietly grows what its tools can do is
caught in CI, before it ships. Deterministic; no LLM.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .capabilities import Capability, DANGEROUS, caps_to_list, classify_tools, dangerous_gained

SCHEMA = "warden-capabilities/v1"


def snapshot(tools: Any) -> dict[str, Any]:
    """A serialisable capability snapshot: tool name -> sorted capability list."""
    return {"schema": SCHEMA,
            "tools": {name: caps_to_list(caps) for name, caps in classify_tools(tools).items()}}


def _caps(names: list[str]) -> frozenset[Capability]:
    out = set()
    for n in names:
        try:
            out.add(Capability(n))
        except ValueError:
            pass
    return frozenset(out)


@dataclass
class Expansion:
    tool: str
    kind: str          # "new_tool" | "expanded"
    reasons: list[str]


def diff(baseline: dict[str, Any], current: dict[str, Any]) -> list[Expansion]:
    """Capability EXPANSIONS in ``current`` vs ``baseline`` (empty if none). A new READ-only tool is not
    an expansion; a new tool carrying any dangerous capability is."""
    base = baseline.get("tools", {})
    cur = current.get("tools", {})
    out: list[Expansion] = []
    for name, cur_names in cur.items():
        cur_caps = _caps(cur_names)
        if name not in base:
            dangerous = sorted(c.value for c in cur_caps & DANGEROUS)
            if dangerous:
                out.append(Expansion(name, "new_tool", [f"new tool with {', '.join(dangerous)}"]))
        else:
            gained = dangerous_gained(_caps(base[name]), cur_caps)
            if gained:
                out.append(Expansion(name, "expanded", [f"gained {g}" for g in gained]))
    return out


def render_diff(baseline: dict[str, Any], current: dict[str, Any]) -> str:
    """A GitHub-style before/after capability diff (for the CI log / report)."""
    lines = ["Previous capability set:"]
    for name in sorted(baseline.get("tools", {})):
        lines.append(f"  {name}: {', '.join(baseline['tools'][name]) or 'UNKNOWN'}")
    lines.append("\nNew capability set:")
    base = baseline.get("tools", {})
    for name in sorted(current.get("tools", {})):
        caps = current["tools"][name]
        gained = dangerous_gained(_caps(base.get(name, [])), _caps(caps)) if name in base else \
            sorted(c.value for c in _caps(caps) & DANGEROUS)
        mark = "+" if (name not in base and gained) or gained else " "
        lines.append(f"{mark} {name}: {', '.join(caps) or 'UNKNOWN'}")
    exps = diff(baseline, current)
    lines.append(f"\nResult: {'BLOCKED — capabilities expanded without approval' if exps else 'OK — no capability expansion'}")
    return "\n".join(lines)


def load(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(path: str, snap: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=2, sort_keys=True)


__all__ = ["SCHEMA", "snapshot", "diff", "render_diff", "Expansion", "load", "save"]
