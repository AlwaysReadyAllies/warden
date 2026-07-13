"""Resource-scoped authorization — destination / resource boundaries.

Capability policy says *whether* a tool may act; boundaries say *where*. A ``fetch`` tool that is
allowed may still only be permitted to reach ``api.github.com``; a ``read_file`` tool only under
``/workspace/project``. Boundaries are enforced at call time against the tool's arguments — a URL
whose host isn't allow-listed, or a path that resolves outside the allowed roots (including via
``../`` traversal), is denied. Deterministic; no LLM. Empty config ⇒ no constraint (backward compatible).

Config shape (top-level ``constraints`` block):

    constraints:
      network:
        domains: ["api.github.com", "*.company.internal"]
      filesystem:
        roots: ["/workspace/project"]
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse

_URL_SCHEMES = ("http", "https", "ws", "wss", "ftp", "ftps", "gopher", "file")


@dataclass(frozen=True)
class Boundaries:
    network_domains: tuple[str, ...] = ()   # allow-list globs; () = no network constraint
    filesystem_roots: tuple[str, ...] = ()  # allowed absolute roots; () = no fs constraint

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "Boundaries":
        if not raw:
            return cls()
        net = (raw.get("network") or {}).get("domains", ()) or ()
        fs = (raw.get("filesystem") or {}).get("roots", ()) or ()
        return cls(
            network_domains=tuple(str(d) for d in net),
            filesystem_roots=tuple(os.path.normpath(str(r)) for r in fs),
        )

    @property
    def active(self) -> bool:
        return bool(self.network_domains) or bool(self.filesystem_roots)

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower()
        return any(fnmatch.fnmatchcase(host, pat.lower()) for pat in self.network_domains)

    def _path_violation(self, value: str) -> str | None:
        norm = os.path.normpath(value)
        # traversal that escapes (leading '..') is a violation regardless of roots
        if norm == ".." or norm.startswith(".." + os.sep):
            return f"path {value!r} escapes the workspace via traversal"
        if os.path.isabs(norm):
            if not any(norm == root or norm.startswith(root + os.sep) for root in self.filesystem_roots):
                return f"path {value!r} is outside the allowed roots {list(self.filesystem_roots)}"
        return None

    def check(self, call: Any) -> str | None:
        """Return a violation reason if any argument breaches a boundary, else None."""
        if not self.active:
            return None
        for value in _iter_strings(getattr(call, "args", {}) or {}):
            parsed = urlparse(value)
            if parsed.scheme.lower() in _URL_SCHEMES and (parsed.hostname or parsed.scheme == "file"):
                if self.network_domains and parsed.scheme != "file":
                    host = parsed.hostname or ""
                    if not self._domain_allowed(host):
                        return (f"destination {host!r} is not in the allowed domains "
                                f"{list(self.network_domains)}")
                continue  # a URL is not also a filesystem path
            if self.filesystem_roots and _looks_like_path(value):
                v = self._path_violation(value)
                if v:
                    return v
        return None


def _iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _iter_strings(v)


def _looks_like_path(value: str) -> bool:
    if not value or "://" in value:
        return False
    return value.startswith(("/", "./", "../", "~")) or os.sep in value or ".." in value


__all__ = ["Boundaries"]
