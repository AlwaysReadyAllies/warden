"""TOFU tool-definition pinning — the direct rug-pull countermeasure.

THREAT (Invariant Labs, "MCP rug pulls", 2025): an MCP server presents a benign tool at approval
time, then swaps that tool's definition later. MCP's ``notifications/tools/list_changed`` lets a
server push new definitions with **no re-approval trigger** — so the model's tool-selection is
silently redirected by a description or schema the operator never approved.

Warden already strips downstream descriptions from what it ADVERTISES upstream, but that does not
detect the swap itself. This module closes it: on first sight we pin (trust-on-first-use) a
fingerprint of each tool's security-relevant definition; any later definition change is a rug pull,
and the tool is quarantined until an operator explicitly re-approves it.

SECURITY decisions (justified):
- DECISION: fingerprint = sha256 over canonical (name, description, inputSchema).
  WHY: those three are exactly what a rug pull alters — the description carries the injected
  instructions, the schema carries parameters an attacker adds to exfiltrate. ALTERNATIVE: name-only
  (misses the attack); whole-Tool incl. volatile fields (false alarms on benign metadata churn).
- DECISION: a CHANGED tool is QUARANTINED and its pin is NOT updated automatically.
  WHY: auto-repinning makes the pin worthless — the whole point is that a change is never silently
  accepted. Re-approval is an explicit operator action (``repin``). THREAT: a rug pull sailing
  through because the tool "looks like" the approved one.
- DECISION: a genuinely NEW tool (no prior pin) is pinned-on-first-use and allowed, but recorded.
  WHY: a brand-new tool is not a *rug pull*; strict deployments still gate it via ``allowed_tools``.
- DECISION: a corrupt/unreadable pin file is treated as empty (re-pin everything on next connect).
  WHY: the pin file is LOCAL OPERATOR STATE, not attacker-controlled in this threat model (the
  adversary is the downstream server, not the local filesystem); erroring out would take the whole
  proxy down on an operator's disk glitch. The residual risk (rug pull immediately after local file
  corruption) is out of the modeled threat surface and is noted, not silently ignored.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def tool_fingerprint(tool: Any) -> str:
    """Stable sha256 over the security-relevant parts of a tool definition."""
    payload = {
        "name": getattr(tool, "name", None),
        "description": getattr(tool, "description", None),
        "inputSchema": getattr(tool, "inputSchema", None),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class PinResult:
    """Outcome of reconciling a server's currently-offered tools against the pins."""

    unchanged: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)  # rug pulls — definition differs from the pin

    @property
    def quarantine(self) -> set[str]:
        """Tools the proxy must drop (neither advertise nor route)."""
        return set(self.changed)


class ToolPinStore:
    """Persistent trust-on-first-use store of tool-definition fingerprints."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        # key: f"{server_id}\x00{tool}" -> {"fp": str, "first_seen": iso, "repinned": iso?}
        self._pins: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _key(server_id: str, tool: str) -> str:
        return f"{server_id}\x00{tool}"

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._pins = {str(k): dict(v) for k, v in data.items() if isinstance(v, Mapping)}
        except Exception:
            # Corrupt/unreadable pin file → treat as empty (see module DECISION on corrupt files).
            self._pins = {}

    def _save(self) -> None:
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._pins, fh, sort_keys=True, separators=(",", ":"))
        os.replace(tmp, self.path)  # atomic swap so a crash never leaves a half-written pin file

    def fingerprint_of(self, server_id: str, tool: str) -> str | None:
        pin = self._pins.get(self._key(server_id, tool))
        return pin.get("fp") if pin else None

    def reconcile(self, server_id: str, tools: Mapping[str, Any]) -> PinResult:
        """Classify each offered tool as unchanged / new / changed, pinning new ones.

        NEW tools are pinned now (TOFU). CHANGED tools (rug pulls) are reported and their pin is
        left intact so a later re-offer of the ORIGINAL definition is recognised as unchanged.
        """
        result = PinResult()
        for name, tool in tools.items():
            fp = tool_fingerprint(tool)
            key = self._key(server_id, name)
            pin = self._pins.get(key)
            if pin is None:
                self._pins[key] = {"fp": fp, "first_seen": _utcnow()}
                result.new.append(name)
            elif pin.get("fp") == fp:
                result.unchanged.append(name)
            else:
                result.changed.append(name)  # rug pull — do NOT update the pin
        self._save()
        return result

    def repin(self, server_id: str, tool: str, tool_obj: Any = None, fp: str | None = None) -> None:
        """Explicit operator re-approval: accept the current definition as the new baseline."""
        if fp is None:
            if tool_obj is None:
                raise ValueError("repin requires tool_obj or fp")
            fp = tool_fingerprint(tool_obj)
        key = self._key(server_id, tool)
        prev = self._pins.get(key, {})
        self._pins[key] = {
            "fp": fp,
            "first_seen": prev.get("first_seen", _utcnow()),
            "repinned": _utcnow(),
        }
        self._save()


__all__ = ["tool_fingerprint", "PinResult", "ToolPinStore"]
