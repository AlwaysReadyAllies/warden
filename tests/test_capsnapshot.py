"""Tests for capability snapshots + the CI expansion gate (capability-SET model)."""
from mcp.types import Tool

from warden.capsnapshot import SCHEMA, diff, render_diff, snapshot


def _t(name, desc=""):
    return Tool(name=name, description=desc, inputSchema={"type": "object"})


def test_snapshot_shape():
    snap = snapshot([_t("get_x", "read x"), _t("delete_x", "remove x")])
    assert snap["schema"] == SCHEMA
    assert snap["tools"]["get_x"] == ["READ"]
    assert "DELETE" in snap["tools"]["delete_x"]


def test_no_diff_when_identical():
    snap = snapshot([_t("get_x", "read x")])
    assert diff(snap, snap) == []


def test_capability_gain_caught():
    base = snapshot([_t("sync", "read the data")])              # {READ}
    curr = snapshot([_t("sync", "read then delete the data")])  # {READ, DELETE}
    exps = diff(base, curr)
    assert len(exps) == 1 and exps[0].tool == "sync" and exps[0].kind == "expanded"
    assert any("DELETE" in r for r in exps[0].reasons)


def test_new_network_and_exec_caught():
    base = snapshot([_t("report", "generate a report")])
    curr = snapshot([_t("report", "generate a report and run a shell command via http")])
    exps = diff(base, curr)
    reasons = " ".join(exps[0].reasons)
    assert "EXECUTE" in reasons and "NETWORK" in reasons


def test_new_dangerous_tool_is_expansion():
    base = snapshot([_t("get_x", "read x")])
    curr = snapshot([_t("get_x", "read x"), _t("delete_repo", "destroy the repo")])
    exps = diff(base, curr)
    assert len(exps) == 1 and exps[0].tool == "delete_repo" and exps[0].kind == "new_tool"


def test_new_readonly_tool_is_not_expansion():
    base = snapshot([_t("get_x", "read x")])
    curr = snapshot([_t("get_x", "read x"), _t("get_y", "read y")])
    assert diff(base, curr) == []


def test_narrowing_is_not_expansion():
    base = snapshot([_t("sync", "read then delete data")])
    curr = snapshot([_t("sync", "read the data")])
    assert diff(base, curr) == []


def test_render_diff_is_github_style():
    base = snapshot([_t("read_files", "read repository files"), _t("search_issues", "search issues")])
    curr = snapshot([_t("read_files", "read repository files"), _t("search_issues", "search issues"),
                     _t("create_pr", "create a pull request"), _t("run_command", "execute a shell command")])
    out = render_diff(base, curr)
    assert "Previous capability set:" in out and "New capability set:" in out
    assert "+ create_pr" in out and "+ run_command" in out
    assert "BLOCKED" in out
