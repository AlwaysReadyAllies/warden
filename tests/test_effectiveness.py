"""Tests for the closed-loop control-effectiveness proof."""
from warden.config import WardenConfig
from warden import effectiveness as E
from warden.schemas import ToolCall


def _cfg(**kw):
    base = dict(
        mode="allow",  # let the specific control fire, not a blanket policy deny
        servers={"github": {"tools": {
            "transfer": {"arguments": {"amount": {"maximum": 100}}},
            "create_issue": {"postconditions": [{"path": "$.id", "exists": True}]},
        }}},
        constraints={"network": {"domains": ["api.github.com"]},
                     "filesystem": {"roots": ["/workspace"]}},
        rules=[{"match": {"capability": "FINANCIAL"}, "action": "deny"}],
    )
    base.update(kw)
    return WardenConfig(**base)


def test_well_configured_blocks_everything():
    rep = E.run_effectiveness(_cfg())
    assert rep["total"] > 0
    assert rep["leaked"] == 0
    assert rep["coverage_pct"] == 100.0
    assert all(c["verdict"] == "HELD" for c in rep["cases"])


def test_each_control_is_exercised():
    rep = E.run_effectiveness(_cfg())
    controls = set(rep["by_control"])
    assert {"guard", "boundaries", "arg_constraints", "postconditions", "capability_policy"} <= controls


def test_boundary_attacks_absent_when_not_configured():
    rep = E.run_effectiveness(_cfg(constraints=None))
    assert "boundaries" not in rep["by_control"]
    # guard attacks still present and still held
    assert rep["by_control"]["guard"]["held"] == rep["by_control"]["guard"]["attempted"]
    assert rep["leaked"] == 0


def test_arg_constraint_violation_is_generated_and_blocked():
    rep = E.run_effectiveness(_cfg())
    ac = [c for c in rep["cases"] if c["control"] == "arg_constraints"]
    assert ac and all(c["verdict"] == "HELD" for c in ac)


def test_leak_is_detected_and_reported():
    # a custom suite whose one "attack" nothing catches (mode allow, no matching control)
    cfg = WardenConfig(mode="allow", servers={"s": {"tools": {"noop": {"action": "allow"}}}})
    suite = [E.AttackCase("uncaught", "CWE-0", "noop", "none",
                          ToolCall("s", "noop", {"harmless": "x"}))]
    rep = E.run_effectiveness(cfg, suite=suite)
    assert rep["leaked"] == 1
    assert rep["coverage_pct"] == 0.0
    assert rep["cases"][0]["verdict"] == "LEAKED"


def test_render_html_self_contained():
    rep = E.run_effectiveness(_cfg())
    out = E.render_html(rep)
    assert out.startswith("<!doctype html>")
    assert "://" not in out.split("<style>")[1].split("</style>")[0]  # no external URLs in CSS
    assert "100.0%" in out
