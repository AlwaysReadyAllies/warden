"""CLI approval channel (dev default).

SECURITY: blocks until a human answers or the timeout elapses; ANY non-yes answer, EOF, or timeout
returns DENY/TIMEOUT (never APPROVE). Fail closed — silence is not consent.

CRITICAL: in `warden run` the proxy speaks MCP over stdin/stdout, so the approval prompt MUST NOT use
sys.stdin/stdout (that's the protocol channel — using it would corrupt MCP framing). We prompt and read
on the controlling terminal (/dev/tty). If there is no TTY (headless/non-interactive), there is no human
to ask, so we fail closed (TIMEOUT) rather than touch the MCP stream.
"""
from __future__ import annotations

import sys
import threading

from ..schemas import ApprovalChannel, ApprovalOutcome, Decision, GuardFinding, ToolCall


class CliApproval(ApprovalChannel):
    def __init__(self, timeout_sec: float = 120.0, use_tty: bool = True) -> None:
        self.timeout_sec = timeout_sec
        self.use_tty = use_tty

    def request(
        self, call: ToolCall, decision: Decision, findings: list[GuardFinding]
    ) -> ApprovalOutcome:
        tty = None
        if self.use_tty:
            try:
                tty = open("/dev/tty", "r+")  # controlling terminal, NOT the MCP stdio channel
            except OSError:
                tty = None

        out = tty if tty is not None else sys.stderr
        flags = ", ".join(f"{f.severity}:{f.kind}" for f in findings) or "none"
        out.write(
            f"\n🛡️  Warden approval needed\n"
            f"    tool:    {call.qualified}\n"
            f"    args:    {call.args}\n"
            f"    reason:  {decision.reason or decision.rule_id}\n"
            f"    guard:   {flags}\n"
            f"    approve? [y/N] (auto-DENY in {self.timeout_sec:.0f}s): "
        )
        out.flush()

        if tty is None:
            # No human terminal to read from; refuse to read sys.stdin (it's the MCP transport).
            out.write("    -> no TTY available, default-DENY\n")
            out.flush()
            return ApprovalOutcome.TIMEOUT

        answer: list[str] = []

        def _read() -> None:
            try:
                answer.append(tty.readline().strip().lower())
            except Exception:
                pass

        t = threading.Thread(target=_read, daemon=True)
        t.start()
        t.join(self.timeout_sec)
        try:
            outcome = ApprovalOutcome.TIMEOUT
            if answer:
                outcome = ApprovalOutcome.APPROVE if answer[0] in ("y", "yes") else ApprovalOutcome.DENY
            if not answer:
                out.write("    -> TIMEOUT (default-deny)\n")
                out.flush()
            return outcome
        finally:
            tty.close()
