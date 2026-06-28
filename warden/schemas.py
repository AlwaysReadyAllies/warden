"""Warden shared contract — the interfaces every module is built against.

Security posture baked into these types (justified):
- Decisions are an explicit closed enum, never free strings — a typo can't silently become "allow".
- Audit records hash the args/results by DEFAULT (args_preview is truncated) so the audit log itself
  is not a secret-exfil surface. Storing full payloads is opt-in.
- TIMEOUT on approval is a *distinct* outcome from DENY so the interceptor can enforce default-deny
  without conflating "human said no" with "human never answered".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    GATE = "gate"                      # require human approval
    REDACT = "redact"                  # strip matched content, continue
    REDACT_AND_FLAG = "redact_and_flag"


class ApprovalOutcome(str, Enum):
    APPROVE = "approve"
    DENY = "deny"
    TIMEOUT = "timeout"               # MUST be treated as default-deny by the interceptor


class Direction(str, Enum):
    REQUEST = "request"               # args going out to a tool
    RESULT = "result"                 # content coming back from a tool


@dataclass
class ToolCall:
    server: str                       # downstream server id (e.g. "filesystem")
    tool: str                         # bare tool name (e.g. "write_file")
    args: dict[str, Any] = field(default_factory=dict)

    @property
    def qualified(self) -> str:       # the namespaced name exposed upstream
        return f"{self.server}__{self.tool}"


@dataclass
class Decision:
    action: Action
    reason: str = ""
    rule_id: str | None = None        # which rule/precedence level fired (for audit + explainability)


@dataclass
class GuardFinding:
    kind: str                         # "prompt_injection" | "secret_egress" | "shell_injection" | ...
    severity: str                     # "low" | "medium" | "high" | "critical"
    detail: str
    span: str | None = None           # the matched substring (already truncated/safe to log)


@dataclass
class AuditRecord:
    seq: int
    ts: str
    server: str
    tool: str
    decision: str
    args_digest: str
    args_preview: str
    result_digest: str | None = None
    approver: str | None = None
    duration_ms: int | None = None
    flags: list[str] = field(default_factory=list)
    prev_hash: str = ""
    hash: str = ""


# ---- module interfaces (concrete impls live in policy.py / guard.py / proxy.py / approval/) ----

class PolicyEngine(Protocol):
    def decide(self, call: ToolCall) -> Decision: ...
    def is_sensitive(self, call: ToolCall) -> bool: ...


class Guard(Protocol):
    def scan_args(self, call: ToolCall) -> list[GuardFinding]: ...
    # returns (possibly-redacted content, findings)
    def scan_result(self, content: Any) -> tuple[Any, list[GuardFinding]]: ...


class ApprovalChannel(Protocol):
    # MUST block until a human responds or the timeout elapses; TIMEOUT => default-deny upstream.
    def request(self, call: ToolCall, decision: Decision, findings: list[GuardFinding]) -> ApprovalOutcome: ...


class AuditSink(Protocol):
    def append(self, record: dict[str, Any]) -> AuditRecord: ...   # computes hash-chain
    def verify(self) -> tuple[bool, str]: ...                       # (intact?, message)


# forward(call) -> raw tool result; supplied by the proxy to the interceptor
Forwarder = Callable[[ToolCall], Any]
