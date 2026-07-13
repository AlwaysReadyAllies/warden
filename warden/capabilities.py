"""Deterministic tool-capability classification (capability-SET model).

Every tool Warden ingests is classified — from its name, description, and inputSchema alone (no LLM) —
into a SET of capabilities drawn from a fixed operational taxonomy. A tool has all the capabilities it
exhibits (e.g. a ``fetch_url`` tool is ``{READ, NETWORK}``; ``transfer_funds`` is ``{WRITE, FINANCIAL}``;
``run_command`` is ``{EXECUTE}``). This set is the substrate for:
  * **policy that matches on capabilities, not tool names** — a customer writes one rule
    (``capability: [DELETE, FINANCIAL, ADMIN] → deny``) instead of enumerating every tool,
  * the **CI gate** that fails a build when a tool GAINS a dangerous capability, and
  * the security report / evidence.

Heuristics over well-known verbs/nouns, conservative by design: when in doubt about a dangerous verb,
the capability is included, so the CI gate and policy never *under*-report. A tool with no recognizable
capability is ``UNKNOWN`` (which policy can treat as gate/deny).
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any


class Capability(str, Enum):
    READ = "READ"              # observes state
    WRITE = "WRITE"            # creates/modifies state
    DELETE = "DELETE"          # removes/irreversibly changes state
    EXECUTE = "EXECUTE"        # runs code / shell / arbitrary commands
    NETWORK = "NETWORK"        # makes outbound network requests
    CREDENTIAL = "CREDENTIAL"  # touches secrets / keys / credentials
    FINANCIAL = "FINANCIAL"    # moves money / makes purchases
    ADMIN = "ADMIN"            # changes authorization / roles / policy
    UNKNOWN = "UNKNOWN"        # nothing recognized — treat cautiously


# READ is the low-privilege baseline; everything else is a privileged/dangerous capability.
DANGEROUS = frozenset(c for c in Capability if c not in (Capability.READ, Capability.UNKNOWN))

_PATTERNS: dict[Capability, re.Pattern] = {
    Capability.READ:    re.compile(r"\b(read|get|list|fetch|search|query|describe|view|show|lookup|"
                                   r"find|inspect|status|info|download|browse|crawl|scrape)\b", re.I),
    Capability.WRITE:   re.compile(r"\b(write|create|update|insert|set|put|post|patch|append|save|edit|"
                                   r"modify|upload|send|publish|commit|deploy|move|rename|add|register|"
                                   r"provision|invoke|trigger|comment|merge|transfer)\b", re.I),
    Capability.DELETE:  re.compile(r"\b(delete|destroy|remove|wipe|truncate|drop|purge|erase|rm|unlink|"
                                   r"clear|reset)\b", re.I),
    Capability.EXECUTE: re.compile(r"\b(exec|execute|eval|command|cmd|shell|spawn|system|run|"
                                   r"subprocess|bash|sh|powershell|script)\b", re.I),
    Capability.NETWORK: re.compile(r"\b(url|uri|http|https|fetch|request|webhook|api|endpoint|host|"
                                   r"port|download|ssrf|proxy)\b", re.I),
    Capability.CREDENTIAL: re.compile(r"\b(secret|credential|password|passwd|api[_-]?key|token|keychain|"
                                      r"private[_-]?key|ssh|vault|env|dotenv)\b", re.I),
    Capability.FINANCIAL: re.compile(r"\b(pay|payment|transfer|charge|invoice|refund|purchase|buy|"
                                     r"billing|wire|checkout|order|price|subscription|card)\b", re.I),
    Capability.ADMIN:   re.compile(r"\b(grant|revoke|role|permission|policy|admin|sudo|privilege|iam|"
                                   r"acl|owner|superuser|escalate|impersonate)\b", re.I),
}


def _normalize(text: str) -> str:
    # split camelCase and turn identifier separators into spaces so \b word boundaries fire on names
    # like fetch_url / deleteFile / run-command (otherwise '_' is a word char and \b never matches).
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return re.sub(r"[_\-./]+", " ", text)


def _tool_text(tool: Any) -> str:
    parts = [str(getattr(tool, "name", "") or ""), str(getattr(tool, "description", "") or "")]
    schema = getattr(tool, "inputSchema", None)
    if isinstance(schema, dict):
        props = schema.get("properties", {})
        if isinstance(props, dict):
            parts.extend(props.keys())  # param names are strong signals (path, url, command, amount…)
    return _normalize(" ".join(p for p in parts if p))


def classify_tool(tool: Any) -> frozenset[Capability]:
    text = _tool_text(tool)
    caps = {cap for cap, pat in _PATTERNS.items() if pat.search(text)}
    if not caps:
        return frozenset({Capability.UNKNOWN})
    # a tool that only matched READ verbs is a pure reader; otherwise READ is implied but the
    # dangerous capabilities are what matter — keep the full set as detected.
    return frozenset(caps)


def classify_tools(tools: Any) -> dict[str, frozenset[Capability]]:
    return {str(getattr(t, "name", "?")): classify_tool(t) for t in tools}


def dangerous_gained(prior: frozenset[Capability], current: frozenset[Capability]) -> list[str]:
    """The DANGEROUS capabilities present in ``current`` but not ``prior`` — the CI-gate expansion signal."""
    return sorted(c.value for c in (current - prior) & DANGEROUS)


def caps_to_list(caps: frozenset[Capability]) -> list[str]:
    return sorted(c.value for c in caps)


__all__ = ["Capability", "DANGEROUS", "classify_tool", "classify_tools", "dangerous_gained", "caps_to_list"]
