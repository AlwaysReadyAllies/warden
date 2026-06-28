"""CLI approval channel (dev default).

SECURITY: blocks until a human answers or the timeout elapses; ANY non-yes answer, EOF, or timeout
returns DENY/TIMEOUT (never APPROVE). Fail closed — silence is not consent.
"""
from __future__ import annotations

import sys
import threading

from ..schemas import ApprovalChannel, ApprovalOutcome, Decision, GuardFinding, ToolCall


class CliApproval(ApprovalChannel):
    def __init__(self, timeout_sec: float = 120.0, stream=None) -> None:
        self.timeout_sec = timeout_sec
        self.stream = stream or sys.stderr

    def request(
        self, call: ToolCall, decision: Decision, findings: list[GuardFinding]
    ) -> ApprovalOutcome:
        flags = ", ".join(f"{f.severity}:{f.kind}" for f in findings) or "none"
        self.stream.write(
            f"\n🛡️  Warden approval needed\n"
            f"    tool:    {call.qualified}\n"
            f"    args:    {call.args}\n"
            f"    reason:  {decision.reason or decision.rule_id}\n"
            f"    guard:   {flags}\n"
            f"    approve? [y/N] (auto-DENY in {self.timeout_sec:.0f}s): "
        )
        self.stream.flush()

        answer: list[str] = []

        def _read() -> None:
            try:
                answer.append(sys.stdin.readline().strip().lower())
            except Exception:
                pass

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(self.timeout_sec)
        if not answer:
            self.stream.write("    -> TIMEOUT (default-deny)\n")
            return ApprovalOutcome.TIMEOUT
        if answer[0] in ("y", "yes"):
            return ApprovalOutcome.APPROVE
        return ApprovalOutcome.DENY
