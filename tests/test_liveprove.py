"""Tests for the live (over-the-wire) control-effectiveness proof.

The attack GENERATOR is unit-tested in-process (fast, no subprocess). The full end-to-end proof
(real client → warden run → reference target) is gated behind WARDEN_LIVE=1 because it spawns
subprocesses and is slower; run it with `WARDEN_LIVE=1 pytest tests/test_liveprove.py`.
"""
import os
from types import SimpleNamespace

import pytest

from warden import liveprove as LP


def _tool(name, props):
    return SimpleNamespace(name=name, inputSchema={"type": "object", "properties": props})


def test_generator_maps_param_names_to_attack_classes():
    tools = [
        _tool("srv__fetch_url", {"url": {"type": "string"}}),
        _tool("srv__read_file", {"path": {"type": "string"}}),
        _tool("srv__run_command", {"command": {"type": "string"}}),
        _tool("srv__run_query", {"query": {"type": "string"}}),
        _tool("srv__send_message", {"body": {"type": "string"}, "to": {"type": "string"}}),
    ]
    attacks = LP.generate_live_attacks(tools)
    cats = {a.category for a in attacks}
    assert {"ssrf", "path_traversal", "command_injection", "sql_injection", "secret_egress"} <= cats
    ssrf = next(a for a in attacks if a.category == "ssrf")
    assert "169.254.169.254" in ssrf.args["url"]


def test_generator_skips_non_string_params():
    tools = [_tool("srv__transfer", {"amount": {"type": "number"}, "note": {"type": "integer"}})]
    assert LP.generate_live_attacks(tools) == []


def test_classify_leak_vs_held():
    assert LP._classify(True, "blocked: dangerous argument")[0] == "HELD"
    assert LP._classify(False, "normal result")[0] == "LEAKED"
    assert LP._classify(False, f"{LP.CANARY}:reference__fetch_url:...")[0] == "LEAKED"


@pytest.mark.skipif(not os.environ.get("WARDEN_LIVE"), reason="subprocess proof; set WARDEN_LIVE=1")
def test_live_proof_reference_target_blocks_everything():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rep = LP.run_live(os.path.join(here, "policies", "reference.yaml"), timeout=45)
    assert rep["total"] >= 5, rep
    assert rep["leaked"] == 0, [c for c in rep["cases"] if c["verdict"] == "LEAKED"]
    assert rep["coverage_pct"] == 100.0
