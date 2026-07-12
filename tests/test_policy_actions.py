"""Tests for the previously-inert policy actions: REDACT/REDACT_AND_FLAG + direction:result rules."""
import pytest

from warden.config import WardenConfig
from warden.guard import WardenGuard
from warden.interceptor import Blocked, Interceptor
from warden.policy import WardenPolicy
from warden.schemas import Action, ToolCall


class _CollectingAudit:
    def __init__(self):
        self.records = []

    def append(self, rec):
        self.records.append(dict(rec))

    def verify(self):
        return True, "ok"

    def last_flags(self):
        resp = [r for r in self.records if r.get("phase") == "response"]
        return resp[-1]["flags"] if resp else []


def _run(policy, call, forward_result, guard=None):
    audit = _CollectingAudit()
    icept = Interceptor(policy, audit, guard=guard)
    import asyncio
    out = asyncio.run(icept.run(call, lambda c: forward_result))
    return out, audit


# --- REDACT_AND_FLAG raises a distinct audit flag ------------------------------------------------

def test_redact_and_flag_adds_flag():
    cfg = WardenConfig(mode="allow", servers={"web": {"tools": {"fetch": {"action": "redact_and_flag"}}}})
    policy = WardenPolicy(cfg)
    call = ToolCall("web", "fetch", {"url": "http://x"})
    out, audit = _run(policy, call, "some result", guard=WardenGuard())
    assert "policy_redact_and_flag" in audit.last_flags()


def test_redact_action_without_guard_fails_closed():
    cfg = WardenConfig(mode="allow", servers={"web": {"tools": {"fetch": {"action": "redact"}}}})
    policy = WardenPolicy(cfg)
    call = ToolCall("web", "fetch", {"url": "http://x"})
    with pytest.raises(Blocked):
        _run(policy, call, "result", guard=None)  # no guard → can't honor redaction → deny


def test_redact_action_with_guard_proceeds_and_redacts():
    cfg = WardenConfig(mode="allow", servers={"web": {"tools": {"fetch": {"action": "redact"}}}})
    policy = WardenPolicy(cfg)
    call = ToolCall("web", "fetch", {"url": "http://x"})
    leaky = "here is a key sk-ABCDEFGHIJKLMNOPQRSTUVWX and more"
    out, _ = _run(policy, call, leaky, guard=WardenGuard())
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out  # guard redacted it


# --- direction:result rules are now ENFORCED -----------------------------------------------------

def _result_rule_cfg(action="deny"):
    return WardenConfig(
        mode="allow",
        servers={"web": {"tools": {"fetch": {"action": "allow"}}}},
        rules=[{
            "id": "no_private_keys_out",
            "match": {"direction": "result", "contains": "BEGIN RSA PRIVATE KEY"},
            "action": action,
            "reason": "private key in tool output",
        }],
    )


def test_result_rule_denies_leaky_result():
    policy = WardenPolicy(_result_rule_cfg("deny"))
    call = ToolCall("web", "fetch", {"url": "http://x"})
    leaky = "output:\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    with pytest.raises(Blocked) as e:
        _run(policy, call, leaky, guard=WardenGuard())
    assert "result denied by policy" in str(e.value)


def test_result_rule_does_not_fire_on_clean_result():
    policy = WardenPolicy(_result_rule_cfg("deny"))
    call = ToolCall("web", "fetch", {"url": "http://x"})
    out, audit = _run(policy, call, "a perfectly clean webpage summary", guard=WardenGuard())
    assert out is not None
    assert not any(f.startswith("result_rule:") for f in audit.last_flags())


def test_result_rule_flag_recorded_when_fired_non_deny():
    policy = WardenPolicy(_result_rule_cfg("redact"))
    call = ToolCall("web", "fetch", {"url": "http://x"})
    leaky = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
    out, audit = _run(policy, call, leaky, guard=WardenGuard())
    assert any(f == "result_rule:no_private_keys_out" for f in audit.last_flags())


# --- direct policy.decide_result unit checks -----------------------------------------------------

def test_decide_result_regex_and_no_matcher():
    cfg = WardenConfig(mode="allow", rules=[
        {"id": "ssn", "match": {"direction": "result", "regex": r"\d{3}-\d{2}-\d{4}"}, "action": "deny"},
        {"id": "empty", "match": {"direction": "result"}, "action": "deny"},  # no matcher → never fires
    ])
    policy = WardenPolicy(cfg)
    call = ToolCall("web", "fetch", {})
    assert policy.decide_result(call, "ssn 123-45-6789 here").action == Action.DENY
    assert policy.decide_result(call, "no pii here") is None


def test_decide_result_ignores_request_direction_rules():
    cfg = WardenConfig(mode="allow", rules=[
        {"id": "req", "match": {"direction": "request", "contains": "secret"}, "action": "deny"},
    ])
    policy = WardenPolicy(cfg)
    assert policy.decide_result(ToolCall("web", "fetch", {}), "contains secret") is None
