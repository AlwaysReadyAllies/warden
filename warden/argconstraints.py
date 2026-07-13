"""Typed argument constraints — per-tool, per-argument value rules enforced at call time.

Capability policy governs whether/which tools; boundaries govern where; argument constraints govern the
SHAPE of a specific call. Declared per tool in its config, they let an operator pin the values a tool
may be invoked with — a transfer capped at an amount, a git tool restricted to a branch prefix, a
dangerous flag forced off, email recipients confined to a domain. Candidate constraints can be seeded
from the tool's inputSchema, then tightened. Deterministic; a violating call is denied.

    servers:
      github:
        tools:
          create_pr:
            action: gate
            arguments:
              branch:     { pattern: "^warden/" }
              draft:      { const: true }
      payments:
        tools:
          transfer:
            arguments:
              amount:     { type: number, maximum: 100 }
              recipients: { items: { email_domain: company.com } }
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Mapping

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, (list, tuple)),
    "object": lambda v: isinstance(v, Mapping),
}


def _validate(arg: str, value: Any, rule: Mapping[str, Any]) -> str | None:
    if "type" in rule:
        check = _TYPES.get(str(rule["type"]))
        if check and not check(value):
            return f"argument {arg!r}={value!r} is not of type {rule['type']}"
    if "const" in rule and value != rule["const"]:
        return f"argument {arg!r} must equal {rule['const']!r} (got {value!r})"
    if "enum" in rule and value not in rule["enum"]:
        return f"argument {arg!r}={value!r} is not one of {rule['enum']}"
    if "minimum" in rule and isinstance(value, (int, float)) and value < rule["minimum"]:
        return f"argument {arg!r}={value} is below minimum {rule['minimum']}"
    if "maximum" in rule and isinstance(value, (int, float)) and value > rule["maximum"]:
        return f"argument {arg!r}={value} exceeds maximum {rule['maximum']}"
    if "maxLength" in rule and hasattr(value, "__len__") and len(value) > rule["maxLength"]:
        return f"argument {arg!r} exceeds maxLength {rule['maxLength']}"
    if "minLength" in rule and hasattr(value, "__len__") and len(value) < rule["minLength"]:
        return f"argument {arg!r} is below minLength {rule['minLength']}"
    if "pattern" in rule:
        try:
            if re.search(str(rule["pattern"]), str(value)) is None:
                return f"argument {arg!r}={value!r} does not match pattern {rule['pattern']!r}"
        except re.error:
            return f"argument {arg!r} constraint has an invalid pattern (failing closed)"
    if "email_domain" in rule:
        dom = str(rule["email_domain"]).lower()
        addr = str(value).lower()
        if "@" not in addr or not addr.rsplit("@", 1)[1] == dom and not addr.endswith("." + dom):
            return f"argument {arg!r}={value!r} is not an email in domain {dom!r}"
    if "items" in rule and isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            v = _validate(f"{arg}[{i}]", item, rule["items"])
            if v:
                return v
    return None


@dataclass(frozen=True)
class ArgumentConstraints:
    servers: Mapping[str, Any]

    @property
    def active(self) -> bool:
        for s in (self.servers or {}).values():
            if isinstance(s, Mapping):
                for tc in (s.get("tools") or {}).values():
                    if isinstance(tc, Mapping) and tc.get("arguments"):
                        return True
        return False

    def _rules_for(self, call: Any) -> Mapping[str, Any] | None:
        server = (self.servers or {}).get(call.server)
        if not isinstance(server, Mapping):
            return None
        tools = server.get("tools") or {}
        for pat, cfg in tools.items():
            if isinstance(cfg, Mapping) and fnmatch.fnmatchcase(call.tool, pat):
                return cfg.get("arguments")
        return None

    def check(self, call: Any) -> str | None:
        rules = self._rules_for(call)
        if not rules:
            return None
        args = getattr(call, "args", {}) or {}
        for arg, rule in rules.items():
            if not isinstance(rule, Mapping):
                continue
            if rule.get("required") and arg not in args:
                return f"required argument {arg!r} is missing"
            if arg in args:
                v = _validate(arg, args[arg], rule)
                if v:
                    return v
        return None


__all__ = ["ArgumentConstraints"]
