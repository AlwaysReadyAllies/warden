"""Tests for the governance-posture evidence report."""
from types import SimpleNamespace

from warden.config import WardenConfig
from warden import report as R


def _tool(server, name, description=""):
    return SimpleNamespace(server=server, name=name, description=description)


def _cfg(**kw):
    base = dict(
        mode="strict",
        servers={
            "github": {"tools": {
                "create_issue": {"postconditions": [{"path": "$.id", "exists": True}]},
                "transfer": {"arguments": {"amount": {"maximum": 100}}},
            }},
        },
        constraints={"network": {"domains": ["api.github.com"]}},
        rules=[{"match": {"capability": "FINANCIAL"}, "action": "gate"}],
    )
    base.update(kw)
    return WardenConfig(**base)


def test_controls_reflect_active_configuration():
    rep = R.build_report(_cfg(), tools=[])
    c = rep["controls"]
    assert c["boundaries"]["active"] is True
    assert c["boundaries"]["network_domains"] == ["api.github.com"]
    assert c["argument_constraints"]["tools_covered"] == 1
    assert c["postconditions"]["tools_covered"] == 1
    assert c["capability_policy"]["capability_rules"] == 1


def test_tool_rows_classify_and_flag_controls():
    tools = [_tool("github", "transfer", "move money"),
             _tool("github", "create_issue", "open an issue"),
             _tool("github", "get_file", "read a file")]
    rep = R.build_report(_cfg(), tools=tools)
    by_name = {r["name"]: r for r in rep["tools"]}
    assert "FINANCIAL" in by_name["transfer"]["capabilities"]
    assert by_name["transfer"]["dangerous"] is True
    assert by_name["transfer"]["argument_constraints"] is True
    assert by_name["create_issue"]["postconditions"] is True
    assert by_name["get_file"]["dangerous"] is False


def test_audit_summary_buckets_decisions():
    records = [
        {"phase": "request", "decision": "allow"},         # ignored (request phase)
        {"phase": "response", "decision": "allow"},
        {"phase": "response", "decision": "boundary_denied"},
        {"phase": "response", "decision": "postcondition_failed:x"},
        {"phase": "response", "decision": "gate_approve"},
    ]
    rep = R.build_report(_cfg(), tools=[], audit_records=records,
                         chain_verified=(True, "ok"))
    a = rep["audit"]
    assert a["total"] == 4
    assert a["allowed"] == 1
    assert a["blocked"] == 2
    assert a["gated"] == 1
    assert a["chain_verified"]["ok"] is True


def test_no_audit_records_yields_none():
    rep = R.build_report(_cfg(), tools=[])
    assert rep["audit"] is None


def test_render_html_is_self_contained_and_escapes():
    tools = [_tool("github", "transfer", "<script>alert(1)</script>")]
    rep = R.build_report(_cfg(), tools=tools)
    out = R.render_html(rep)
    assert out.startswith("<!doctype html>")
    assert "http" not in out.split("<style>")[1].split("</style>")[0] or "://" not in out  # no external URLs in CSS
    assert "<script>alert(1)</script>" not in out  # tool metadata rendered as data, escaped
    assert "FINANCIAL" in out
