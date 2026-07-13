"""Explicit postconditions — declarative, per-tool result assertions.

Result *inspection* (guard) asks "did the server return something safe-looking?" A *postcondition*
asks "does the intended state actually hold?" — it evaluates the tool's result against operator-
declared invariants (a JSONPath-lite field equals / matches / exists / is-in a value). A call whose
result violates its postcondition is surfaced as a failure rather than silently returned — the
Verify-Then-Commit posture. Deterministic; tool-specific; no universal semantic guessing.

    servers:
      github:
        tools:
          create_issue:
            postconditions:
              - path: "$.status"      # dot-path into the JSON result
                equals: "created"
              - path: "$.id"
                exists: true
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

_MISSING = object()


def _extract(root: Any, path: str) -> Any:
    if path in ("$", "$.", ""):
        return root
    cur = root
    for part in path.lstrip("$").lstrip(".").split("."):
        if not part:
            continue
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        elif isinstance(cur, (list, tuple)) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _check_one(root: Any, pc: Mapping[str, Any]) -> str | None:
    path = str(pc.get("path", "$"))
    val = _extract(root, path)
    if "exists" in pc:
        present = val is not _MISSING
        if bool(pc["exists"]) != present:
            return f"postcondition {path} exists={present}, expected {pc['exists']}"
    needs_value = any(k in pc for k in ("equals", "not_equals", "in", "matches"))
    if needs_value and val is _MISSING:
        return f"postcondition {path} is not present in the result"
    if "equals" in pc and val != pc["equals"]:
        return f"postcondition {path}={val!r} != expected {pc['equals']!r}"
    if "not_equals" in pc and val == pc["not_equals"]:
        return f"postcondition {path} must not equal {pc['not_equals']!r}"
    if "in" in pc and val not in pc["in"]:
        return f"postcondition {path}={val!r} not in {pc['in']}"
    if "matches" in pc:
        try:
            if re.search(str(pc["matches"]), str(val)) is None:
                return f"postcondition {path}={val!r} does not match {pc['matches']!r}"
        except re.error:
            return f"postcondition {path} has an invalid pattern (failing closed)"
    return None


@dataclass(frozen=True)
class Postconditions:
    servers: Mapping[str, Any]

    @property
    def active(self) -> bool:
        for s in (self.servers or {}).values():
            if isinstance(s, Mapping):
                for tc in (s.get("tools") or {}).values():
                    if isinstance(tc, Mapping) and tc.get("postconditions"):
                        return True
        return False

    def _for(self, call: Any) -> list | None:
        server = (self.servers or {}).get(call.server)
        if not isinstance(server, Mapping):
            return None
        for pat, cfg in (server.get("tools") or {}).items():
            if isinstance(cfg, Mapping) and fnmatch.fnmatchcase(call.tool, pat):
                pcs = cfg.get("postconditions")
                return pcs if isinstance(pcs, list) else None
        return None

    def check(self, call: Any, result_text: str) -> str | None:
        pcs = self._for(call)
        if not pcs:
            return None
        try:
            root: Any = json.loads(result_text)
        except Exception:
            root = result_text  # non-JSON result — only "$"/matches checks are meaningful
        for pc in pcs:
            if isinstance(pc, Mapping):
                v = _check_one(root, pc)
                if v:
                    return v
        return None


__all__ = ["Postconditions"]
