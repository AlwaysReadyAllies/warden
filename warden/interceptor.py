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

import asyncio
import inspect
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
        flow: Any = None,
        boundaries: Any = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.guard = guard
        self.approval = approval
        self.approver = approver
        # optional session-scoped cross-server dataflow tracker (lethal-trifecta defense)
        self.flow = flow
        # optional resource-scoped authorization (destination/filesystem boundaries)
        self.boundaries = boundaries

    async def run(self, call: ToolCall, forward: Forwarder) -> Any:
        # SECURITY/correctness: async so we AWAIT the downstream call in THIS task and inspect the REAL
        # result (a sync interceptor only ever saw an un-awaited coroutine — redaction was a no-op and
        # the await happened in the wrong task, causing anyio cancel-scope errors). Proven by the live smoke.
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

        # resource-scoped authorization: a destination/path argument outside the configured boundaries
        # is denied outright (fail closed), regardless of a permissive policy verdict.
        if self.boundaries is not None:
            violation = self.boundaries.check(call)
            if violation:
                base["flags"] = base["flags"] + ["boundary_violation"]
                self._audit_block(base, "boundary_denied", started, arg_findings)
                raise Blocked(f"blocked: {violation}")

        # cross-server dataflow: if untrusted content has entered this session, an exfil-capable
        # sink is denied/gated (lethal-trifecta defense). Overrides a permissive policy verdict.
        if self.flow is not None:
            flow_decision = self.flow.check(call)
            if flow_decision is not None:
                if flow_decision.action == Action.DENY:
                    base["flags"] = base["flags"] + ["flow_taint"]
                    self._audit_block(base, "flow_denied", started, arg_findings)
                    raise Blocked(f"blocked: {flow_decision.reason}")
                # GATE: escalate so the human decides on the tainted exfil
                decision = flow_decision

        if decision.action == Action.DENY:
            self._audit_block(base, "denied", started, arg_findings)
            raise Blocked(f"denied by policy: {decision.reason or decision.rule_id or 'rule'}")

        if decision.action == Action.GATE:
            if self.approval:
                # run the (blocking) approval channel off the event loop so it can't stall the proxy
                outcome = await asyncio.to_thread(self.approval.request, call, decision, arg_findings)
            else:
                outcome = ApprovalOutcome.TIMEOUT  # no channel configured => fail closed
            if outcome != ApprovalOutcome.APPROVE:
                self._audit_block(base, f"gate_{outcome.value}", started, arg_findings, approver=self.approver)
                raise Blocked(f"blocked: approval {outcome.value}")

        # REDACT / REDACT_AND_FLAG proceed like ALLOW but PROMISE the result is redacted. That promise
        # can only be kept with a guard, so a redact policy with no guard fails closed (never silently
        # returns un-redacted content the policy said to scrub). REDACT_AND_FLAG additionally raises an
        # explicit alert flag so a monitored-but-allowed tool is visible in the audit trail.
        redact_required = decision.action in (Action.REDACT, Action.REDACT_AND_FLAG)
        if redact_required and self.guard is None:
            self._audit_block(base, "denied_redact_without_guard", started, arg_findings)
            raise Blocked("blocked: policy requires redaction but no guard is configured")

        result = forward(call)
        if inspect.isawaitable(result):
            result = await result

        policy_flags: list[str] = []
        if decision.action == Action.REDACT_AND_FLAG:
            policy_flags.append("policy_redact_and_flag")

        # RESULT-direction policy rules (e.g. deny a result that leaks a private key). Applied here so
        # `direction: result` rules are actually enforced, not silently ignored.
        decide_result = getattr(self.policy, "decide_result", None)
        if decide_result is not None:
            result_text = self._result_text(result)
            if result_text is not None:
                result_decision = decide_result(call, result_text)
                if result_decision is not None:
                    policy_flags.append(f"result_rule:{result_decision.rule_id}")
                    if result_decision.action == Action.DENY:
                        self._audit_block(base, f"result_denied:{result_decision.rule_id}", started,
                                          arg_findings)
                        raise Blocked(
                            f"blocked: result denied by policy "
                            f"({result_decision.reason or result_decision.rule_id})")
                    if result_decision.action in (Action.REDACT, Action.REDACT_AND_FLAG):
                        redact_required = True  # a result rule can escalate an allowed call to redacted

        result_findings: list[GuardFinding] = []
        if self.guard:
            result, result_findings = self._guard_result(result)

        # taint the session AFTER an untrusted source's result has entered the model's context
        if self.flow is not None and self.flow.observe(call):
            policy_flags = policy_flags + ["flow_source_tainted"]

        self.audit.append(
            {
                **base,
                "phase": "response",
                "result_digest": digest(result),
                "approver": self.approver if decision.action == Action.GATE else None,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "flags": [f.kind for f in arg_findings + result_findings] + policy_flags,
            }
        )
        return result

    @staticmethod
    def _result_text(result: Any) -> str | None:
        """Best-effort textual view of a tool result for result-direction rule matching."""
        content = getattr(result, "content", None)
        if isinstance(content, list) and content and all(hasattr(c, "text") for c in content):
            return "\n".join(str(getattr(c, "text", "")) for c in content)
        if isinstance(result, str):
            return result
        try:
            return str(result)
        except Exception:
            return None

    def _guard_result(self, result: Any) -> tuple[Any, list[GuardFinding]]:
        """Run the guard over a tool result, including MCP CallToolResult content objects.

        SECURITY: a downstream returns an mcp.CallToolResult whose payload lives in `.content[i].text`
        (pydantic objects, not dict/list/str). A live smoke test proved a raw secret in that text reached
        the model unredacted because the guard only traverses primitives. We extract those text fields,
        guard them, and write the redacted text back — so redaction holds on the real wire, not just in
        unit tests. Falls back to scanning the object directly for plain (dict/str) results.
        """
        content = getattr(result, "content", None)
        if isinstance(content, list) and content and all(hasattr(c, "text") for c in content):
            findings: list[GuardFinding] = []
            for item in content:
                if isinstance(getattr(item, "text", None), str):
                    redacted, f = self.guard.scan_result(item.text)
                    try:
                        item.text = redacted
                    except Exception:  # frozen model: rebuild defensively
                        pass
                    findings.extend(f)
            return result, findings
        return self.guard.scan_result(result)

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
