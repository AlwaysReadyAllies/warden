"""Cross-server dataflow policy — the lethal-trifecta defense.

Per-call guards (guard.py) and per-call policy (policy.py) cannot see the ATTACK that spans a session:
an agent reads untrusted content from server A (a web page, an email), that content carries injected
instructions, and the agent is then steered to exfiltrate private data via server B (send an email,
POST to a URL). Simon Willison's "lethal trifecta" — (1) access to private data, (2) exposure to
untrusted content, (3) ability to communicate externally — becomes exploitable, and MCP's mix-and-
match tools make assembling it trivial.

Warden closes it with session-scoped taint tracking: once any tool tagged as an untrusted **source**
returns a result into the model's context, any subsequent call to a tool tagged as an exfiltration
**sink** is denied (or gated for human approval). This is a coarse, honest flow rule — it does not
prove data actually flowed, it enforces that untrusted-content-touched context may not reach an
exfil-capable tool without a human in the loop.

SECURITY decisions:
- DECISION: taint is set AFTER a source's result is returned (the content is now in context), and the
  sink is checked BEFORE forwarding. So the ordering that matters — read-untrusted-then-exfil — is the
  one caught. WHY: matches the actual attack sequence.
- DECISION: default on_violation is DENY (fail closed); GATE is opt-in for workflows that legitimately
  read-then-send. WHY: silent exfil is the worst outcome; make the human decide.
- DECISION: taint is per-interceptor (per Warden process = per trust boundary). WHY: Warden's model is
  one process per agent/boundary; per-HTTP-session isolation is a future refinement (noted, not hidden)
  — until then a shared HTTP deployment taints conservatively across sessions.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Mapping

from .schemas import Action, Decision, ToolCall


@dataclass(frozen=True)
class FlowPolicy:
    """Which tools produce untrusted content (sources) and which can exfiltrate (sinks)."""

    sources: tuple[str, ...] = ()      # glob patterns on qualified `server__tool` (or bare tool)
    sinks: tuple[str, ...] = ()
    on_violation: str = "deny"         # deny | gate

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "FlowPolicy":
        if not raw:
            return cls()
        on_v = str(raw.get("on_violation", "deny")).lower()
        if on_v not in ("deny", "gate"):
            on_v = "deny"  # fail closed on a typo
        return cls(
            sources=tuple(raw.get("sources", ()) or ()),
            sinks=tuple(raw.get("sinks", ()) or ()),
            on_violation=on_v,
        )

    @property
    def enabled(self) -> bool:
        # a flow rule needs both ends; either alone enforces nothing
        return bool(self.sources) and bool(self.sinks)

    @staticmethod
    def _matches(call: ToolCall, patterns: tuple[str, ...]) -> bool:
        for p in patterns:
            if fnmatch.fnmatchcase(call.qualified, p) or fnmatch.fnmatchcase(call.tool, p):
                return True
        return False

    def is_source(self, call: ToolCall) -> bool:
        return self._matches(call, self.sources)

    def is_sink(self, call: ToolCall) -> bool:
        return self._matches(call, self.sinks)


class FlowTracker:
    """Session-scoped taint state. One per interceptor (per Warden process)."""

    def __init__(self, policy: FlowPolicy) -> None:
        self.policy = policy
        self.tainted = False
        self.sources_seen: list[str] = []

    def check(self, call: ToolCall) -> Decision | None:
        """Called BEFORE forwarding. Returns a blocking/gating Decision if this is a tainted sink."""
        if not self.policy.enabled or not self.tainted:
            return None
        if not self.policy.is_sink(call):
            return None
        action = Action.GATE if self.policy.on_violation == "gate" else Action.DENY
        last = self.sources_seen[-1] if self.sources_seen else "untrusted content"
        return Decision(
            action=action,
            reason=(f"dataflow: {call.qualified} can exfiltrate and untrusted content has entered this "
                    f"session (via {last}) — potential lethal-trifecta exfiltration"),
            rule_id="flow_taint",
        )

    def observe(self, call: ToolCall) -> bool:
        """Called AFTER a call's result is returned. Marks the session tainted if it was a source."""
        if self.policy.enabled and self.policy.is_source(call):
            self.tainted = True
            self.sources_seen.append(call.qualified)
            return True
        return False


__all__ = ["FlowPolicy", "FlowTracker"]
