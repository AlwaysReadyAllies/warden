"""Policy that decides on tool CAPABILITIES, not tool names (the governance keystone)."""
from warden.config import WardenConfig
from warden.policy import WardenPolicy
from warden.schemas import Action, ToolCall


def _policy(rules):
    return WardenPolicy(WardenConfig(mode="allow", rules=rules))


def _call(tool, caps):
    return ToolCall("srv", tool, {}, capabilities=frozenset(caps))


DENY_DANGEROUS = [{"id": "no-dangerous", "match": {"capability": ["DELETE", "FINANCIAL", "ADMIN"]},
                   "action": "deny"}]
GATE_WRITES = [{"id": "gate-writes", "match": {"capability": "WRITE"}, "action": "gate"}]


def test_capability_deny():
    p = _policy(DENY_DANGEROUS)
    assert p.decide(_call("delete_repo", {"DELETE"})).action == Action.DENY
    assert p.decide(_call("wire_money", {"WRITE", "FINANCIAL"})).action == Action.DENY
    assert p.decide(_call("grant_admin", {"ADMIN"})).action == Action.DENY


def test_capability_any_of_semantics():
    # a rule matching [DELETE, NETWORK] fires when the tool has EITHER
    p = _policy([{"id": "r", "match": {"capability": ["DELETE", "NETWORK"]}, "action": "deny"}])
    assert p.decide(_call("fetch", {"READ", "NETWORK"})).action == Action.DENY


def test_capability_gate():
    p = _policy(GATE_WRITES)
    assert p.decide(_call("create_issue", {"WRITE"})).action == Action.GATE


def test_no_match_falls_through_to_allow():
    p = _policy(DENY_DANGEROUS)
    assert p.decide(_call("get_weather", {"READ"})).action == Action.ALLOW  # allow-mode fallback


def test_case_insensitive():
    p = _policy([{"id": "r", "match": {"capability": "delete"}, "action": "deny"}])
    assert p.decide(_call("rm", {"DELETE"})).action == Action.DENY


def test_explicit_tool_rule_overrides_capability_rule():
    # DEFAULT (capability_deny_overrides off): an admin can allow ONE known-destructive tool by name
    cfg = WardenConfig(mode="allow",
                       servers={"srv": {"tools": {"safe_delete": {"action": "allow"}}}},
                       rules=DENY_DANGEROUS)
    p = WardenPolicy(cfg)
    # explicit tool rule (allow) wins over the capability deny (precedence: explicit > rules[])
    assert p.decide(_call("safe_delete", {"DELETE"})).action == Action.ALLOW
    # but any OTHER delete tool still hits the capability deny
    assert p.decide(_call("delete_prod_db", {"DELETE"})).action == Action.DENY


def test_capability_deny_overrides_makes_capability_deny_authoritative():
    # opt-in: a capability DENY wins even over an explicit per-tool allow
    cfg = WardenConfig(mode="allow",
                       servers={"srv": {"tools": {"safe_delete": {"action": "allow"}}}},
                       rules=DENY_DANGEROUS, capability_deny_overrides=True)
    p = WardenPolicy(cfg)
    d = p.decide(_call("safe_delete", {"DELETE"}))
    assert d.action == Action.DENY
    assert "no-dangerous" in d.rule_id
    # a non-dangerous tool is unaffected by the override
    assert p.decide(_call("get_weather", {"READ"})).action == Action.ALLOW


def test_capability_deny_overrides_does_not_touch_gate_rules():
    # only DENY rules are authoritative; a capability GATE does not override an explicit allow
    cfg = WardenConfig(mode="allow",
                       servers={"srv": {"tools": {"editor": {"action": "allow"}}}},
                       rules=GATE_WRITES, capability_deny_overrides=True)
    p = WardenPolicy(cfg)
    assert p.decide(_call("editor", {"WRITE"})).action == Action.ALLOW


def test_precedence_deny_before_gate_within_rules():
    # a DELETE+WRITE tool: deny rule listed first wins over the later gate rule
    p = _policy(DENY_DANGEROUS + GATE_WRITES)
    assert p.decide(_call("purge", {"DELETE", "WRITE"})).action == Action.DENY
