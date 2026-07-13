"""Evidence reports — render Warden's governance posture and audit summary as HTML/JSON.

This is the "Evidence" pillar: a buyer or auditor gets one artifact showing, deterministically,
WHAT controls are enforced and WHAT the log recorded. It reads the same config the proxy runs and,
optionally, the hash-chained audit log — no behaviour, no inference, just the posture and the record.

    warden report --config warden.yaml --audit warden_audit.jsonl --html posture.html

Sections:
  - Controls: which deterministic controls are active (capability policy, boundaries, argument
    constraints, postconditions, flow policy, pinning, sealing) and their coverage counts.
  - Tools: per tool — its classified capability set, whether it is dangerous, and which per-tool
    controls (argument constraints, postconditions) are declared for it.
  - Audit: (if a log is given) call totals bucketed allowed / blocked / gated, denials by reason,
    and the tamper-evident chain-verification result.
"""
from __future__ import annotations

import html
import json
from typing import Any, Iterable, Mapping

SCHEMA = "warden-report/v1"


def _servers(cfg: Any) -> Mapping[str, Any]:
    return getattr(cfg, "servers", None) or {}


def _tool_cfg(cfg: Any, server: str, tool: str) -> Mapping[str, Any]:
    import fnmatch
    s = _servers(cfg).get(server)
    if not isinstance(s, Mapping):
        return {}
    for pat, tc in (s.get("tools") or {}).items():
        if isinstance(tc, Mapping) and fnmatch.fnmatchcase(tool, pat):
            return tc
    return {}


def _count_declared(cfg: Any, key: str) -> int:
    n = 0
    for s in _servers(cfg).values():
        if isinstance(s, Mapping):
            for tc in (s.get("tools") or {}).values():
                if isinstance(tc, Mapping) and tc.get(key):
                    n += 1
    return n


def _controls(cfg: Any, tools: Iterable[Any] | None) -> dict:
    from .boundaries import Boundaries
    b = Boundaries.from_mapping(getattr(cfg, "constraints", None))
    rules = getattr(cfg, "rules", None) or []
    cap_rules = sum(1 for r in rules if isinstance(r, Mapping)
                    and isinstance(r.get("match"), Mapping) and r["match"].get("capability"))
    return {
        "mode": getattr(cfg, "mode", "unknown"),
        "capability_policy": {"total_rules": len(rules), "capability_rules": cap_rules},
        "boundaries": {
            "active": b.active,
            "network_domains": list(getattr(b, "network_domains", ()) or ()),
            "filesystem_roots": list(getattr(b, "filesystem_roots", ()) or ()),
        },
        "argument_constraints": {"tools_covered": _count_declared(cfg, "arguments")},
        "postconditions": {"tools_covered": _count_declared(cfg, "postconditions")},
        "flow_policy": {"active": bool(getattr(cfg, "flow", None))},
        "auth": {"active": bool(getattr(cfg, "auth", None))},
    }


def _tool_rows(cfg: Any, tools: Iterable[Any] | None) -> list[dict]:
    from .capabilities import caps_to_list, classify_tool
    rows: list[dict] = []
    for t in tools or []:
        server = getattr(t, "server", "") or getattr(t, "server_id", "")
        name = getattr(t, "name", None) or (t.get("name") if isinstance(t, Mapping) else str(t))
        caps = caps_to_list(classify_tool(t))
        tc = _tool_cfg(cfg, server, name)
        rows.append({
            "server": server,
            "name": name,
            "capabilities": caps,
            "dangerous": bool(set(caps) - {"READ", "UNKNOWN"}),
            "argument_constraints": bool(tc.get("arguments")),
            "postconditions": bool(tc.get("postconditions")),
        })
    rows.sort(key=lambda r: (r["server"], r["name"]))
    return rows


_ALLOW = {"allow", "redact", "redact_and_flag", "flag"}


def _audit_summary(records: Iterable[Mapping[str, Any]] | None) -> dict | None:
    if records is None:
        return None
    total = allowed = blocked = gated = 0
    by_decision: dict[str, int] = {}
    for rec in records:
        if rec.get("phase") != "response":
            continue
        total += 1
        decision = str(rec.get("decision", "unknown"))
        by_decision[decision] = by_decision.get(decision, 0) + 1
        if decision in _ALLOW:
            allowed += 1
        elif decision.startswith("gate_"):
            gated += 1
        else:
            blocked += 1
    return {"total": total, "allowed": allowed, "blocked": blocked, "gated": gated,
            "by_decision": dict(sorted(by_decision.items(), key=lambda kv: -kv[1]))}


def build_report(cfg: Any, tools: Iterable[Any] | None = None,
                 audit_records: Iterable[Mapping[str, Any]] | None = None,
                 chain_verified: tuple[bool, str] | None = None) -> dict:
    report = {
        "schema": SCHEMA,
        "controls": _controls(cfg, tools),
        "tools": _tool_rows(cfg, tools),
        "audit": _audit_summary(audit_records),
    }
    if report["audit"] is not None and chain_verified is not None:
        report["audit"]["chain_verified"] = {"ok": chain_verified[0], "detail": chain_verified[1]}
    return report


# --- rendering ------------------------------------------------------------------------------------

def _e(v: Any) -> str:
    return html.escape(str(v))


def _badge(caps: list[str]) -> str:
    out = []
    for c in caps:
        cls = "cap-read" if c in ("READ", "UNKNOWN") else "cap-danger"
        out.append(f'<span class="badge {cls}">{_e(c)}</span>')
    return " ".join(out) or '<span class="badge cap-read">UNKNOWN</span>'


def render_html(report: dict) -> str:
    c = report["controls"]
    b = c["boundaries"]
    rows = "".join(
        f"<tr><td>{_e(r['server'])}</td><td><code>{_e(r['name'])}</code></td>"
        f"<td>{_badge(r['capabilities'])}</td>"
        f"<td>{'✅' if r['argument_constraints'] else '—'}</td>"
        f"<td>{'✅' if r['postconditions'] else '—'}</td></tr>"
        for r in report["tools"]
    ) or '<tr><td colspan="5" class="muted">no tools enumerated</td></tr>'

    def ctrl(label: str, on: bool, detail: str = "") -> str:
        dot = "on" if on else "off"
        return (f'<div class="ctrl"><span class="dot {dot}"></span><b>{_e(label)}</b>'
                f'<span class="muted">{_e(detail)}</span></div>')

    controls_html = "".join([
        ctrl("Policy mode", True, c["mode"]),
        ctrl("Capability policy", c["capability_policy"]["capability_rules"] > 0,
             f"{c['capability_policy']['capability_rules']} capability rule(s) of {c['capability_policy']['total_rules']}"),
        ctrl("Resource boundaries", b["active"],
             f"{len(b['network_domains'])} domain(s), {len(b['filesystem_roots'])} fs root(s)"),
        ctrl("Argument constraints", c["argument_constraints"]["tools_covered"] > 0,
             f"{c['argument_constraints']['tools_covered']} tool(s)"),
        ctrl("Postconditions", c["postconditions"]["tools_covered"] > 0,
             f"{c['postconditions']['tools_covered']} tool(s)"),
        ctrl("Flow policy", c["flow_policy"]["active"]),
        ctrl("Auth", c["auth"]["active"]),
    ])

    audit_html = ""
    a = report.get("audit")
    if a is not None:
        cv = a.get("chain_verified")
        cv_html = ""
        if cv is not None:
            cv_html = (f'<p class="{"ok" if cv["ok"] else "bad"}">Chain verification: '
                       f'{"✅ intact" if cv["ok"] else "❌ " + _e(cv["detail"])}</p>')
        by = "".join(f"<tr><td><code>{_e(k)}</code></td><td>{v}</td></tr>"
                     for k, v in a["by_decision"].items())
        audit_html = f"""
        <h2>Audit</h2>
        <div class="stats">
          <div class="stat"><span class="n">{a['total']}</span>calls</div>
          <div class="stat ok"><span class="n">{a['allowed']}</span>allowed</div>
          <div class="stat bad"><span class="n">{a['blocked']}</span>blocked</div>
          <div class="stat warn"><span class="n">{a['gated']}</span>gated</div>
        </div>
        {cv_html}
        <table><thead><tr><th>decision</th><th>count</th></tr></thead><tbody>{by}</tbody></table>
        """

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden — Security Posture</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; max-width: 900px; margin: 2rem auto;
         padding: 0 1rem; color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{ body {{ color: #e6e6e6; background: #16171a; }}
    table, .ctrl, .stat {{ border-color: #333 !important; }} code {{ background:#26282c; }} }}
  h1 {{ font-size: 1.5rem; margin-bottom: .2rem; }}
  h2 {{ font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid #8884; padding-bottom: .3rem; }}
  .muted {{ color: #8a8a8a; font-size: .85em; margin-left: .5rem; }}
  code {{ background: #f0f0f2; padding: .1em .35em; border-radius: 4px; font-size: .9em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .6rem; overflow-x: auto; display: block; }}
  th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #ddd; }}
  th {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: #888; }}
  .badge {{ display: inline-block; padding: .05em .5em; border-radius: 999px; font-size: .72rem;
           font-weight: 600; }}
  .cap-read {{ background: #e3f0ff; color: #1b5cad; }}
  .cap-danger {{ background: #ffe1e1; color: #b02020; }}
  .ctrl {{ display: flex; align-items: center; gap: .5rem; padding: .4rem .1rem;
          border-bottom: 1px solid #eee; }}
  .dot {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; }}
  .dot.on {{ background: #2ea043; }} .dot.off {{ background: #bbb; }}
  .stats {{ display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }}
  .stat {{ border: 1px solid #ddd; border-radius: 8px; padding: .6rem 1rem; min-width: 90px; }}
  .stat .n {{ display: block; font-size: 1.6rem; font-weight: 700; }}
  .stat.ok .n {{ color: #2ea043; }} .stat.bad .n {{ color: #cf222e; }} .stat.warn .n {{ color: #bf8700; }}
  p.ok {{ color: #2ea043; }} p.bad {{ color: #cf222e; }}
</style></head><body>
  <h1>Warden — Security Posture</h1>
  <p class="muted">Deterministic governance evidence · schema {SCHEMA}</p>
  <h2>Controls</h2>
  {controls_html}
  <h2>Tools <span class="muted">{len(report['tools'])} enumerated</span></h2>
  <table><thead><tr><th>server</th><th>tool</th><th>capabilities</th>
    <th>arg&nbsp;constraints</th><th>postconditions</th></tr></thead>
    <tbody>{rows}</tbody></table>
  {audit_html}
</body></html>"""


def load_audit_records(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


__all__ = ["SCHEMA", "build_report", "render_html", "load_audit_records"]
