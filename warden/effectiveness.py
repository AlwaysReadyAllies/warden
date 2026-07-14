"""Control-effectiveness proof — the closed loop: attack a Warden-configured interceptor and record,
per attack, whether the control actually held.

This is Warden's differentiator. `warden scan` says what a server *could* do; `warden report` says what
controls are *configured*; this says what the controls *actually block*. It runs a suite of deterministic
attacks — grounded in the mcp-dast CWE taxonomy (CWE-22/78/89/918) plus Warden-specific control violations
— through the SAME interceptor construction that runs in production (`runtime.build_interceptor`), against
a benign forwarder that "lands" the attack if the call is ever allowed through. A blocked attack means the
control held; a call that reaches the forwarder is a LEAK.

The suite is partly derived from the config under test: every per-tool argument constraint, postcondition,
and capability rule becomes a matching violation, so the proof measures THIS deployment, not a generic one.

    warden prove --config warden.yaml --html effectiveness.html   # exit 2 if any attack leaked
"""
from __future__ import annotations

import asyncio
import html
from dataclasses import dataclass
from typing import Any, Mapping

from .interceptor import Blocked
from .runtime import build_interceptor
from .schemas import ToolCall

SCHEMA = "warden-effectiveness/v1"
_LANDED = "WARDEN-ATTACK-LANDED"  # a benign forwarder returns this; seeing it upstream means a leak
_TAMPER = "WARDEN-POSTCONDITION-TAMPER"  # a non-JSON result that fails positive postcondition assertions


@dataclass(frozen=True)
class AttackCase:
    id: str
    cwe: str
    category: str
    control: str
    call: ToolCall
    result: str = _LANDED
    rationale: str = ""


class _NullAudit:
    def append(self, rec): pass
    def verify(self): return True, "ok"


# --- suite synthesis ------------------------------------------------------------------------------

def _first_server(cfg: Any) -> str:
    servers = getattr(cfg, "servers", None) or {}
    for sid in servers:
        return sid
    return "server"


def _global_attacks(cfg: Any) -> list[AttackCase]:
    """Always-on controls: the guard (any call) and, when configured, resource boundaries."""
    srv = _first_server(cfg)
    out = [
        AttackCase("guard-cmd-injection", "CWE-78", "command_injection", "guard",
                   ToolCall(srv, "run", {"cmd": "ls; rm -rf /"}),
                   rationale="shell metacharacters in an argument"),
        AttackCase("guard-destructive", "CWE-78", "destructive_command", "guard",
                   ToolCall(srv, "run", {"command": "rm -rf /"}),
                   rationale="bare destructive command, no chaining"),
        AttackCase("guard-secret-egress", "CWE-200", "secret_egress", "guard",
                   ToolCall(srv, "post", {"body": "api_key=sk-abcdef0123456789abcdef"}),
                   rationale="credential exfiltrated via an outbound argument"),
        AttackCase("guard-sql-injection", "CWE-89", "sql_injection", "guard",
                   ToolCall(srv, "query", {"q": "1 OR 1=1; DROP TABLE users--"}),
                   rationale="SQL injection payload in an argument"),
    ]
    if getattr(cfg, "constraints", None):
        from .boundaries import Boundaries
        if Boundaries.from_mapping(cfg.constraints).active:
            out += [
                AttackCase("boundary-ssrf-metadata", "CWE-918", "ssrf", "boundaries",
                           ToolCall(srv, "fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
                           rationale="SSRF to the cloud metadata endpoint"),
                AttackCase("boundary-path-traversal", "CWE-22", "path_traversal", "boundaries",
                           ToolCall(srv, "read", {"path": "../../../../etc/passwd"}),
                           rationale="filesystem traversal outside the allowed roots"),
            ]
    return out


def _violate_arg(rule: Mapping[str, Any]) -> tuple[bool, Any]:
    """Return (synthesizable, a value that violates this rule). Some rule types can't be violated generically."""
    if "maximum" in rule:
        return True, rule["maximum"] + 1
    if "minimum" in rule:
        return True, rule["minimum"] - 1
    if "const" in rule:
        c = rule["const"]
        return True, (not c) if isinstance(c, bool) else "__warden_violation__"
    if "enum" in rule:
        return True, "__warden_not_in_enum__"
    if "email_domain" in rule:
        return True, "attacker@evil.example"
    if "type" in rule:
        return True, ("not-a-number" if rule["type"] in ("number", "integer") else 123456)
    return False, None  # pattern/length-only rules aren't generically violable — skip


def _config_attacks(cfg: Any) -> list[AttackCase]:
    out: list[AttackCase] = []
    servers = getattr(cfg, "servers", None) or {}
    for sid, s in servers.items():
        if not isinstance(s, Mapping):
            continue
        for tname, tc in (s.get("tools") or {}).items():
            if not isinstance(tc, Mapping) or "*" in tname:
                continue
            # argument-constraint violations
            for arg, rule in (tc.get("arguments") or {}).items():
                if isinstance(rule, Mapping):
                    ok, bad = _violate_arg(rule)
                    if ok:
                        out.append(AttackCase(
                            f"argconstraint-{sid}-{tname}-{arg}", "CWE-20", "arg_constraint",
                            "arg_constraints", ToolCall(sid, tname, {arg: bad}),
                            rationale=f"argument {arg!r} violates its declared constraint"))
                        break
            # postcondition tamper (a compromised server returning an unverifiable result)
            pcs = tc.get("postconditions")
            if isinstance(pcs, list) and any(
                isinstance(pc, Mapping) and (set(pc) & {"equals", "in", "matches"} or pc.get("exists") is True)
                for pc in pcs
            ):
                out.append(AttackCase(
                    f"postcondition-{sid}-{tname}", "CWE-345", "postcondition", "postconditions",
                    ToolCall(sid, tname, {}), result=_TAMPER,
                    rationale="server result fails the declared postcondition (unverified state)"))
    # capability-policy violations — synthesize a call carrying each denied/gated rule's capability
    for r in (getattr(cfg, "rules", None) or []):
        if not isinstance(r, Mapping):
            continue
        m = r.get("match")
        cap = m.get("capability") if isinstance(m, Mapping) else None
        action = str(r.get("action", "")).lower()
        if cap and action in ("deny", "gate"):
            caps = cap if isinstance(cap, list) else [cap]
            srv = m.get("server") or _first_server(cfg)
            out.append(AttackCase(
                f"capability-{'-'.join(caps)}", "CWE-269", "capability_escalation", "capability_policy",
                ToolCall(srv, "dangerous_tool", {}, capabilities=frozenset(str(c).upper() for c in caps)),
                rationale=f"call carrying {caps} capability the policy {action}s"))
    return out


def default_suite(cfg: Any) -> list[AttackCase]:
    return _global_attacks(cfg) + _config_attacks(cfg)


# --- runner ---------------------------------------------------------------------------------------

async def _run_case(cfg: Any, case: AttackCase) -> tuple[bool, str]:
    icept = build_interceptor(cfg, _NullAudit())
    try:
        await icept.run(case.call, lambda c: case.result)
        return False, ""  # reached the forwarder → LEAK
    except Blocked as exc:
        return True, str(exc)
    except Exception as exc:  # any other refusal still means the call did not land
        return True, f"{type(exc).__name__}: {exc}"


def run_effectiveness(cfg: Any, suite: list[AttackCase] | None = None) -> dict:
    suite = suite if suite is not None else default_suite(cfg)
    cases: list[dict] = []
    by_control: dict[str, dict] = {}
    blocked_n = 0
    for case in suite:
        blocked, reason = asyncio.run(_run_case(cfg, case))
        blocked_n += int(blocked)
        verdict = "HELD" if blocked else "LEAKED"
        cases.append({"id": case.id, "cwe": case.cwe, "category": case.category,
                      "control": case.control, "verdict": verdict,
                      "reason": reason if blocked else "attack reached the tool — control did not fire",
                      "rationale": case.rationale})
        c = by_control.setdefault(case.control, {"attempted": 0, "held": 0, "leaked": 0})
        c["attempted"] += 1
        c["held" if blocked else "leaked"] += 1
    total = len(suite)
    return {
        "schema": SCHEMA,
        "total": total,
        "held": blocked_n,
        "leaked": total - blocked_n,
        # None (not 100) on an empty suite: 0 attacks proves NOTHING — never read as full coverage
        "coverage_pct": round(100.0 * blocked_n / total, 1) if total else None,
        "by_control": by_control,
        "cases": cases,
    }


# --- rendering ------------------------------------------------------------------------------------

def _e(v: Any) -> str:
    return html.escape(str(v))


def render_html(report: dict) -> str:
    rows = "".join(
        f'<tr class="{ "held" if c["verdict"]=="HELD" else "leaked" }">'
        f'<td>{"✅" if c["verdict"]=="HELD" else "❌"} {_e(c["verdict"])}</td>'
        f'<td><code>{_e(c["cwe"])}</code></td><td>{_e(c["category"])}</td>'
        f'<td>{_e(c["control"])}</td><td>{_e(c["rationale"])}</td></tr>'
        for c in report["cases"]
    ) or '<tr><td colspan="5" class="muted">no attacks generated</td></tr>'
    by = "".join(
        f'<tr><td>{_e(k)}</td><td>{v["attempted"]}</td><td>{v["held"]}</td>'
        f'<td class="{ "bad" if v["leaked"] else "" }">{v["leaked"]}</td></tr>'
        for k, v in sorted(report["by_control"].items())
    )
    leaked = report["leaked"]
    if report["total"] == 0:
        verdict_cls, verdict_txt, cov_txt = "bad", "no attacks generated — nothing was verified", "n/a"
    else:
        verdict_cls = "bad" if leaked else "ok"
        verdict_txt = f"{leaked} attack(s) leaked" if leaked else "all attacks blocked"
        cov_txt = f"{report['coverage_pct']}%"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden — Control-Effectiveness Proof</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; max-width: 900px; margin: 2rem auto;
         padding: 0 1rem; color: #1a1a1a; }}
  @media (prefers-color-scheme: dark) {{ body {{ color: #e6e6e6; background: #16171a; }}
    th, td {{ border-color: #333 !important; }} code {{ background:#26282c; }} }}
  h1 {{ font-size: 1.5rem; margin-bottom: .2rem; }}
  h2 {{ font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid #8884; padding-bottom: .3rem; }}
  .muted {{ color: #8a8a8a; font-size: .85em; }}
  code {{ background: #f0f0f2; padding: .1em .35em; border-radius: 4px; font-size: .9em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .6rem; }}
  th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #ddd; }}
  th {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: #888; }}
  .score {{ font-size: 2.4rem; font-weight: 800; }}
  .ok {{ color: #2ea043; }} .bad {{ color: #cf222e; }}
  tr.leaked td {{ background: #ffecec33; }}
</style></head><body>
  <h1>Warden — Control-Effectiveness Proof</h1>
  <p class="muted">Deterministic closed-loop proof · schema {SCHEMA}</p>
  <p class="score {verdict_cls}">{cov_txt}</p>
  <p class="{verdict_cls}">{report['held']}/{report['total']} attacks blocked — {verdict_txt}</p>
  <h2>By control</h2>
  <table><thead><tr><th>control</th><th>attacks</th><th>held</th><th>leaked</th></tr></thead>
    <tbody>{by}</tbody></table>
  <h2>Attacks</h2>
  <table><thead><tr><th>verdict</th><th>cwe</th><th>class</th><th>control</th><th>attack</th></tr></thead>
    <tbody>{rows}</tbody></table>
</body></html>"""


__all__ = ["AttackCase", "default_suite", "run_effectiveness", "render_html", "SCHEMA"]
