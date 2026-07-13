"""Tests for typed per-tool argument constraints."""
import asyncio

import pytest

from warden.argconstraints import ArgumentConstraints
from warden.config import WardenConfig
from warden.interceptor import Blocked, Interceptor
from warden.policy import WardenPolicy
from warden.schemas import ToolCall


def _ac(tool_args):
    return ArgumentConstraints({"srv": {"tools": {"tool": {"arguments": tool_args}}}})


def _call(**args):
    return ToolCall("srv", "tool", dict(args))


def test_maximum_and_minimum():
    ac = _ac({"amount": {"type": "number", "maximum": 100}})
    assert ac.check(_call(amount=50)) is None
    assert ac.check(_call(amount=500)) is not None


def test_const_forces_value():
    ac = _ac({"recursive": {"const": False}})
    assert ac.check(_call(recursive=False)) is None
    assert "must equal" in ac.check(_call(recursive=True))


def test_pattern():
    ac = _ac({"branch": {"pattern": "^warden/"}})
    assert ac.check(_call(branch="warden/fix")) is None
    assert ac.check(_call(branch="main")) is not None


def test_enum():
    ac = _ac({"env": {"enum": ["staging", "dev"]}})
    assert ac.check(_call(env="dev")) is None
    assert ac.check(_call(env="prod")) is not None


def test_type_mismatch():
    ac = _ac({"amount": {"type": "number"}})
    assert ac.check(_call(amount="lots")) is not None


def test_email_domain_items():
    ac = _ac({"recipients": {"items": {"email_domain": "company.com"}}})
    assert ac.check(_call(recipients=["a@company.com", "b@company.com"])) is None
    assert ac.check(_call(recipients=["a@company.com", "evil@attacker.com"])) is not None


def test_required_argument():
    ac = _ac({"token": {"required": True}})
    assert "missing" in ac.check(_call())
    assert ac.check(_call(token="x")) is None


def test_unconstrained_args_pass():
    ac = _ac({"amount": {"maximum": 100}})
    assert ac.check(_call(other="anything", amount=10)) is None


def test_not_active_when_no_constraints():
    assert not ArgumentConstraints({"srv": {"tools": {"tool": {"action": "allow"}}}}).active


# --- interceptor enforcement ---------------------------------------------------------------------

class _Audit:
    def append(self, rec): pass
    def verify(self): return True, "ok"


def test_interceptor_denies_constraint_violation():
    ac = _ac({"amount": {"maximum": 100}})
    icept = Interceptor(WardenPolicy(WardenConfig(mode="allow")), _Audit(), arg_constraints=ac)
    with pytest.raises(Blocked):
        asyncio.run(icept.run(_call(amount=9999), lambda c: "ok"))
    out = asyncio.run(icept.run(_call(amount=10), lambda c: "sent"))
    assert out == "sent"
