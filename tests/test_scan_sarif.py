from warden.scan import Finding, ScanReport, ToolReport
from warden.sarif import reports_to_sarif


def _report():
    rep = ScanReport(server="filesystem")
    t = ToolReport(name="read_file", fingerprint="abc")
    t.findings.append(Finding("tool_poisoning", "high", "hidden instruction in tool description"))
    rep.tools.append(t)
    rep.server_findings.append(Finding("no_auth", "critical", "server exposes tools with no auth"))
    return rep


def test_reports_map_to_sarif():
    d = reports_to_sarif([_report()])
    assert d["version"] == "2.1.0"
    run = d["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-scan"
    results = run["results"]
    assert len(results) == 2
    locs = {r["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]: r for r in results}
    assert "filesystem/read_file" in locs and locs["filesystem/read_file"]["level"] == "error"
    assert "filesystem" in locs and locs["filesystem"]["ruleId"] == "no_auth"


def test_empty_reports_valid():
    d = reports_to_sarif([])
    assert d["runs"][0]["results"] == [] and d["version"] == "2.1.0"
