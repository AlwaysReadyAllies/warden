"""SARIF 2.1.0 output for mcp-scan — findings land in the GitHub Security tab / any SARIF consumer.

Upload from a workflow with `github/codeql-action/upload-sarif@v3`. mcp-scan findings are about a
server's tool *definitions* (not a source file), so they use logicalLocations (server / tool).
"""
from __future__ import annotations

from typing import Any

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"critical": "9.0", "high": "8.0", "medium": "5.0", "low": "3.0", "info": "0.0"}
INFO_URI = "https://github.com/AlwaysReadyAllies/warden"


def _result(kind: str, severity: str, detail: str, where: str) -> dict:
    sev = (severity or "medium").lower()
    return {
        "ruleId": kind,
        "level": _LEVEL.get(sev, "warning"),
        "message": {"text": detail},
        "locations": [{"logicalLocations": [{"name": where.split("/")[-1],
                                             "fullyQualifiedName": where, "kind": "module"}]}],
        "properties": {"security-severity": _SCORE.get(sev, "5.0")},
    }


def reports_to_sarif(reports: list[Any], *, version: str = "0.1.0") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for rep in reports:
        for f in rep.server_findings:
            rules.setdefault(f.kind, {"id": f.kind, "name": f.kind.replace("_", " "),
                                      "shortDescription": {"text": f.kind.replace("_", " ")},
                                      "properties": {"tags": ["security", "mcp"]}})
            results.append(_result(f.kind, f.severity, f.detail, rep.server))
        for t in rep.tools:
            for f in t.findings:
                rules.setdefault(f.kind, {"id": f.kind, "name": f.kind.replace("_", " "),
                                          "shortDescription": {"text": f.kind.replace("_", " ")},
                                          "properties": {"tags": ["security", "mcp"]}})
                results.append(_result(f.kind, f.severity, f.detail, f"{rep.server}/{t.name}"))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcp-scan", "version": version, "informationUri": INFO_URI,
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
