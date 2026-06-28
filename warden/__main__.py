"""Warden CLI:  warden run | init | audit verify

Wires the pieces: config → policy + guard + audit + approval → interceptor → proxy.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys

from .audit import AuditLog


def _build_runtime(config_path: str, audit_path: str, approval_timeout: float):
    from .config import load_config
    from .policy import WardenPolicy
    from .guard import WardenGuard
    from .interceptor import Interceptor
    from .approval.cli import CliApproval

    cfg = load_config(config_path)
    policy = WardenPolicy(cfg)
    guard = WardenGuard()
    audit = AuditLog(audit_path)
    approval = CliApproval(timeout_sec=approval_timeout)
    interceptor = Interceptor(policy, audit, guard=guard, approval=approval, approver=os.environ.get("USER", "operator"))
    return cfg, interceptor


def _proxy_config(cfg) -> dict:
    """Adapt the policy-shaped config (cmd=[...], tools={t:{action}}) to the proxy's downstream specs.

    SECURITY: least privilege — the proxy only ADVERTISES tools that aren't denied; deny/gate are still
    enforced by the interceptor, but a denied tool is never even exposed upstream.
    """
    servers = {}
    for sid, s in (cfg.servers or {}).items():
        tools = s.get("tools", {}) or {}
        allowed = [t for t, rule in tools.items() if (rule or {}).get("action") != "deny"]
        if "*" in tools and (tools["*"] or {}).get("action") != "deny":
            allowed = ["*"]
        spec: dict = {"allowed_tools": allowed}
        cmd = s.get("cmd") or s.get("command")
        if isinstance(cmd, list) and cmd:
            spec["command"], spec["args"] = cmd[0], cmd[1:]
        elif isinstance(cmd, str):
            spec["command"] = cmd
        if s.get("url"):
            spec["url"] = s["url"]
        servers[sid] = spec
    return {"servers": servers}


def _cmd_run(args) -> int:
    from .proxy import WardenProxy

    cfg, interceptor = _build_runtime(args.config, args.audit, args.approval_timeout)
    proxy = WardenProxy(_proxy_config(cfg), interceptor)
    sys.stderr.write(f"🛡️  warden proxy starting · policy={args.config} · audit={args.audit}\n")
    asyncio.run(proxy.run_stdio())
    return 0


def _cmd_init(args) -> int:
    target = args.path
    if os.path.exists(target) and not args.force:
        sys.stderr.write(f"refusing to overwrite {target} (use --force)\n")
        return 1
    starter = os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies", "balanced.yaml")
    if os.path.exists(starter):
        shutil.copyfile(starter, target)
    else:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("mode: strict\nservers: {}\nsensitive_actions: [transfer, send, delete, purchase, grant, deploy]\nrules: []\n")
    sys.stderr.write(f"wrote starter policy → {target}\n")
    return 0


def _cmd_audit(args) -> int:
    ok, msg = AuditLog(args.log).verify()
    sys.stderr.write(("✅ " if ok else "❌ ") + msg + "\n")
    return 0 if ok else 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="warden", description="Drop-in MCP security middleware")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="start the proxy (stdio MCP server)")
    pr.add_argument("--config", default="warden.yaml")
    pr.add_argument("--audit", default="warden_audit.jsonl")
    pr.add_argument("--approval-timeout", type=float, default=120.0)
    pr.set_defaults(func=_cmd_run)

    pi = sub.add_parser("init", help="write a starter warden.yaml")
    pi.add_argument("path", nargs="?", default="warden.yaml")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(func=_cmd_init)

    pa = sub.add_parser("audit", help="audit log tools")
    asub = pa.add_subparsers(dest="audit_cmd", required=True)
    pav = asub.add_parser("verify", help="verify the tamper-evident chain")
    pav.add_argument("--log", default="warden_audit.jsonl")
    pav.set_defaults(func=_cmd_audit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
