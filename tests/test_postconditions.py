"""Tests for explicit per-tool result postconditions (Verify-Then-Commit)."""
import asyncio
import json

import pytest

from warden.config import WardenConfig
from warden.interceptor import Blocked, Interceptor
from warden.policy import WardenPolicy
from warden.postconditions import Postconditions
from warden.schemas import ToolCall


def _pc(conds):
    return Postconditions({"srv": {"tools": {"tool": {"postconditions": conds}}}})


def _call():
    return ToolCall("srv", "tool", {})


def test_equals_pass_and_fail():
    pc = _pc([{"path": "$.status", "equals": "created"}])
    assert pc.check(_call(), json.dumps({"status": "created"})) is None
    v = pc.check(_call(), json.dumps({"status": "error"}))
    assert v and "$.status" in v


def test_exists():
    pc = _pc([{"path": "$.id", "exists": True}])
    assert pc.check(_call(), json.dumps({"id": 7})) is None
    assert pc.check(_call(), json.dumps({"other": 1})) is not None


def test_exists_false_rejects_present_field():
    pc = _pc([{"path": "$.error", "exists": False}])
    assert pc.check(_call(), json.dumps({"ok": True})) is None
    assert pc.check(_call(), json.dumps({"error": "boom"})) is not None


def test_nested_path_and_array_index():
    pc = _pc([{"path": "$.data.items.0.state", "equals": "open"}])
    body = json.dumps({"data": {"items": [{"state": "open"}]}})
    assert pc.check(_call(), body) is None
    bad = json.dumps({"data": {"items": [{"state": "closed"}]}})
    assert pc.check(_call(), bad) is not None


def test_in_and_not_equals():
    pc = _pc([{"path": "$.state", "in": ["open", "reopened"]}])
    assert pc.check(_call(), json.dumps({"state": "open"})) is None
    assert pc.check(_call(), json.dumps({"state": "deleted"})) is not None
    pc2 = _pc([{"path": "$.role", "not_equals": "admin"}])
    assert pc2.check(_call(), json.dumps({"role": "user"})) is None
    assert pc2.check(_call(), json.dumps({"role": "admin"})) is not None


def test_matches_on_whole_non_json_result():
    pc = _pc([{"path": "$", "matches": r"^OK\b"}])
    assert pc.check(_call(), "OK done") is None
    assert pc.check(_call(), "FAILED") is not None


def test_missing_field_for_value_assertion_fails_closed():
    pc = _pc([{"path": "$.status", "equals": "created"}])
    assert pc.check(_call(), json.dumps({"unrelated": 1})) is not None


def test_no_postconditions_is_noop():
    pc = Postconditions({"srv": {"tools": {"tool": {"action": "allow"}}}})
    assert not pc.active
    assert pc.check(_call(), json.dumps({"anything": 1})) is None


def test_unmatched_tool_passes():
    pc = Postconditions({"srv": {"tools": {"other": {"postconditions": [{"path": "$.x", "equals": 1}]}}}})
    assert pc.check(_call(), json.dumps({"x": 2})) is None


# --- interceptor enforcement ---------------------------------------------------------------------

class _Audit:
    def append(self, rec): pass
    def verify(self): return True, "ok"


def _run(postconditions, result):
    icept = Interceptor(WardenPolicy(WardenConfig(mode="allow")), _Audit(),
                        postconditions=postconditions)
    return asyncio.run(icept.run(_call(), lambda c: result))


def test_interceptor_blocks_failed_postcondition():
    pc = _pc([{"path": "$.status", "equals": "created"}])
    with pytest.raises(Blocked) as e:
        _run(pc, json.dumps({"status": "error"}))
    assert "postcondition" in str(e.value)


def test_interceptor_passes_satisfied_postcondition():
    pc = _pc([{"path": "$.status", "equals": "created"}])
    out = _run(pc, json.dumps({"status": "created"}))
    assert json.loads(out)["status"] == "created"
