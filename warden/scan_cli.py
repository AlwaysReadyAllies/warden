"""CLI for mcp-scan — `mcp-scan` console script and the `warden scan` subcommand."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .scan import ScanReport, assess_server, list_tools

_ICON = {"info": "·", "low": "•", "medium": "⚠", "high": "⚠", "critical": "⛔"}


def _print_report(report: ScanReport) -> None:
    sys.stderr.write(f"\n🔍 mcp-scan · {report.server}\n   worst severity: {report.worst.upper()}\n\n")
    for t in report.tools:
        caps = f"  [{', '.join(t.capabilities)}]" if t.capabilities else ""
        sys.stderr.write(f"  {_ICON.get(t.worst, '·')} {t.name}{caps}\n")
        for f in t.findings:
            sys.stderr.write(f"        {f.severity}: {f.kind} — {f.detail}\n")
    if report.server_findings:
        sys.stderr.write("  server:\n")
        for f in report.server_findings:
            sys.stderr.write(f"    {_ICON.get(f.severity, '·')} {f.kind} ({f.severity}): {f.detail}\n")
    verdict = "RISKY" if report.risky else "OK"
    sys.stderr.write(f"\n  verdict: {verdict}\n")


async def _scan_one(name: str, *, command=None, args=(), env=None, url=None) -> ScanReport:
    try:
        tools = await list_tools(command=command, args=tuple(args), env=env, url=url)
    except Exception as exc:
        rep = ScanReport(server=name)
        from .scan import Finding
        rep.server_findings.append(Finding("scan_error", "medium", f"could not enumerate tools: {exc}"))
        return rep
    return assess_server(name, tools)


def _servers_from_mcp_json(path: str) -> list[tuple[str, dict]]:
    data = json.loads(open(path, encoding="utf-8").read())
    servers = data.get("mcpServers", data.get("servers", {}))
    return list(servers.items())


def run(*, command=None, args=(), url=None, config=None, name="server", json_out=False,
        sarif_out=None) -> int:
    """Scan one server (command/url) or every server in a .mcp.json; return an exit code."""
    reports: list[ScanReport] = []
    if config:
        for sname, cfg in _servers_from_mcp_json(config):
            scommand, cargs = cfg.get("command"), cfg.get("args", [])
            if isinstance(cfg.get("cmd"), list) and cfg["cmd"]:      # cmd: [prog, arg, ...] form
                scommand, cargs = cfg["cmd"][0], cfg["cmd"][1:]
            reports.append(asyncio.run(_scan_one(
                sname, command=scommand, args=cargs, env=cfg.get("env"), url=cfg.get("url"))))
    elif command or url:
        reports.append(asyncio.run(_scan_one(name, command=command, args=tuple(args), url=url)))
    else:
        sys.stderr.write("mcp-scan: provide --command, --url, or --config\n")
        return 2

    for r in reports:
        _print_report(r)
    if json_out:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    if sarif_out:
        from .sarif import reports_to_sarif
        with open(sarif_out, "w", encoding="utf-8") as fh:
            json.dump(reports_to_sarif(reports), fh, indent=2)
        sys.stderr.write(f"  SARIF → {sarif_out}\n")
    # exit non-zero if any scanned server is high/critical — gates CI
    return 1 if any(r.risky for r in reports) else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-scan",
                                description="Audit an MCP server's tools for supply-chain risk before you trust it.")
    p.add_argument("--command", help="stdio server command (e.g. npx)")
    p.add_argument("--arg", action="append", default=[], dest="args", help="argument for --command (repeatable)")
    p.add_argument("--url", help="streamable-HTTP MCP server URL")
    p.add_argument("--config", help="a .mcp.json to scan every configured server")
    p.add_argument("--name", default="server", help="label for the scanned server")
    p.add_argument("--json", action="store_true", help="emit the JSON report to stdout")
    p.add_argument("--sarif", metavar="PATH", help="write a SARIF 2.1.0 report (GitHub Security tab)")
    a = p.parse_args(argv)
    return run(command=a.command, args=a.args, url=a.url, config=a.config, name=a.name,
               json_out=a.json, sarif_out=a.sarif)


if __name__ == "__main__":
    raise SystemExit(main())
