"""The interceptor pipeline — the heart of Warden.

Every tool call flows: policy → audit(request) → [guard args] → branch(deny|gate→approval|allow)
→ forward → guard(result) → audit(response) → return.

SECURITY decisions (justified):
- DECISION: audit the REQUEST before any forward/approval, and always audit the RESPONSE.
  WHY: blocked and timed-out calls are exactly the security-interesting ones; logging only successes
  would erase the attacks. THREAT: an attacker relying on failed attempts going unrecorded.
- DECISION: approval TIMEOUT and any non-APPROVE outcome => DENY (fail closed).
  WHY: "the human never answered" must never become "so we did it anyway". THREAT: an agent firing a
  dangerous call when the operator is away.
- DECISION: scan tool ARGS before approval so the human sees the guard findings, and scan RESULTS
  before returning to the model. WHY: the lethal trifecta — untrusted content reaching the model can
  carry injected instructions, and outbound args can carry shell/secret payloads. THREAT: prompt
  injection via returned content; credential exfil via args.
- DECISION: a critical guard finding on args hard-denies even an 'allow' policy verdict.
  WHY: policy is coarse (per-tool); the guard sees the actual payload. Defense in depth.
"""
from __future__ import annotations

import time
from typing import Any

from .schemas import (
    Action,
    ApprovalChannel,
    ApprovalOutcome,
    AuditSink,
    Decision,
    Forwarder,
    Guard,
    GuardFinding,
    PolicyEngine,
    ToolCall,
)
from .audit import digest, preview


class Blocked(Exception):
    """Raised when Warden refuses a call; the proxy turns this into a structured MCP error."""

    def __init__(self, message: str, findings: list[GuardFinding] | None = None) -> None:
        super().__init__(message)
        self.findings = findings or []


class Interceptor:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditSink,
        guard: Guard | None = None,
        approval: ApprovalChannel | None = None,
        approver: str = "operator",
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.guard = guard
        self.approval = approval
        self.approver = approver

    def run(self, call: ToolCall, forward: Forwarder) -> Any:
        started = time.monotonic()
        decision = self.policy.decide(call)

        arg_findings: list[GuardFinding] = self.guard.scan_args(call) if self.guard else []
        critical_args = [f for f in arg_findings if f.severity in ("high", "critical")]

        base = {
            "server": call.server,
            "tool": call.tool,
            "decision": decision.action.value,
            "rule_id": decision.rule_id,
            "args_digest": digest(call.args),
            "args_preview": preview(call.args),
            "flags": [f.kind for f in arg_findings],
        }
        self.audit.append({**base, "phase": "request"})

        # defense in depth: a dangerous payload overrides a permissive policy verdict
        if critical_args:
            self._audit_block(base, "guard_denied_args", started, critical_args)
            raise Blocked(
                f"blocked: dangerous argument ({critical_args[0].kind}: {critical_args[0].detail})",
                critical_args,
            )

        if decision.action == Action.DENY:
            self._audit_block(base, "denied", started, arg_findings)
            raise Blocked(f"denied by policy: {decision.reason or decision.rule_id or 'rule'}")

        if decision.action == Action.GATE:
            outcome = (
                self.approval.request(call, decision, arg_findings)
                if self.approval
                else ApprovalOutcome.TIMEOUT  # no channel configured => fail closed
            )
            if outcome != ApprovalOutcome.APPROVE:
                self._audit_block(base, f"gate_{outcome.value}", started, arg_findings, approver=self.approver)
                raise Blocked(f"blocked: approval {outcome.value}")

        result = forward(call)

        result_findings: list[GuardFinding] = []
        if self.guard:
            result, result_findings = self.guard.scan_result(result)

        self.audit.append(
            {
                **base,
                "phase": "response",
                "result_digest": digest(result),
                "approver": self.approver if decision.action == Action.GATE else None,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "flags": [f.kind for f in arg_findings + result_findings],
            }
        )
        return result

    def _audit_block(
        self,
        base: dict[str, Any],
        decision_label: str,
        started: float,
        findings: list[GuardFinding],
        approver: str | None = None,
    ) -> None:
        self.audit.append(
            {
                **base,
                "phase": "response",
                "decision": decision_label,
                "approver": approver,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "flags": [f.kind for f in findings],
            }
        )
