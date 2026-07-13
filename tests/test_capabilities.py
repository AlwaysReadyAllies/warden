"""Tests for deterministic capability-SET classification."""
from mcp.types import Tool

from warden.capabilities import Capability as C
from warden.capabilities import caps_to_list, classify_tool, dangerous_gained


def _t(name, desc="", schema=None):
    return Tool(name=name, description=desc, inputSchema=schema or {"type": "object"})


def test_read_baseline():
    assert classify_tool(_t("get_weather", "return the weather")) == frozenset({C.READ})
    assert classify_tool(_t("list_issues", "list issues")) == frozenset({C.READ})


def test_write_delete_execute():
    assert classify_tool(_t("create_issue", "open an issue")) == frozenset({C.WRITE})
    assert C.DELETE in classify_tool(_t("delete_file", "remove a file"))
    assert C.EXECUTE in classify_tool(_t("run_command", "execute a shell command"))


def test_multiple_capabilities_per_tool():
    caps = classify_tool(_t("fetch_url", "download a web page"))
    assert C.READ in caps and C.NETWORK in caps                      # a tool holds all it exhibits
    funds = classify_tool(_t("transfer_funds", "wire money to a payee"))
    assert C.FINANCIAL in funds and C.WRITE in funds


def test_credential_and_admin():
    assert C.CREDENTIAL in classify_tool(_t("read_secret", "read a credential"))
    assert C.ADMIN in classify_tool(_t("grant_role", "grant an admin role"))


def test_param_names_are_signals():
    schema = {"type": "object", "properties": {"command": {"type": "string"}}}
    assert C.EXECUTE in classify_tool(_t("helper", "does things", schema))
    schema2 = {"type": "object", "properties": {"amount": {"type": "number"}}}
    # 'amount' alone isn't financial, but a 'charge' name is
    assert C.FINANCIAL in classify_tool(_t("charge_card", "charge the card", schema2))


def test_unknown_when_nothing_matches():
    assert classify_tool(_t("frobnicate", "xyzzy plugh")) == frozenset({C.UNKNOWN})


def test_caps_to_list_is_sorted_strings():
    assert caps_to_list(frozenset({C.WRITE, C.READ})) == ["READ", "WRITE"]


# --- dangerous_gained (the CI-gate signal) -------------------------------------------------------

def test_dangerous_gained_flags_new_dangerous():
    assert dangerous_gained(frozenset({C.READ}), frozenset({C.READ, C.DELETE})) == ["DELETE"]
    assert dangerous_gained(frozenset({C.READ}), frozenset({C.READ, C.NETWORK, C.EXECUTE})) == ["EXECUTE", "NETWORK"]


def test_gaining_read_is_not_dangerous():
    assert dangerous_gained(frozenset({C.WRITE}), frozenset({C.WRITE, C.READ})) == []


def test_narrowing_gains_nothing():
    assert dangerous_gained(frozenset({C.WRITE, C.DELETE}), frozenset({C.READ})) == []
