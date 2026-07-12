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


def _build_runtime(config_path: str, audit_path: str, approval_timeout: float,
                   seal_state: str | None = None, anchor_path: str | None = None):
    from .config import load_config
    from .policy import WardenPolicy
    from .guard import WardenGuard
    from .interceptor import Interceptor
    from .approval.cli import CliApproval

    cfg = load_config(config_path)
    policy = WardenPolicy(cfg)
    guard = WardenGuard()
    sealer = anchor = None
    if seal_state:
        from .sealing import ForwardSecureSealer, AnchorSink
        sealer = ForwardSecureSealer(seal_state)
        if not sealer.is_setup:
            raise SystemExit(f"seal state {seal_state} not initialised — run `warden audit setup-keys` first")
        anchor = AnchorSink(path=anchor_path) if anchor_path else None
    audit = AuditLog(audit_path, sealer=sealer, anchor=anchor)
    approval = CliApproval(timeout_sec=approval_timeout)
    interceptor = Interceptor(policy, audit, guard=guard, approval=approval, approver=os.environ.get("USER", "operator"))
    # Return the audit sink too: the proxy records rug-pull quarantines to the SAME hash-chained log,
    # and we seal it on shutdown when forward-secure sealing is enabled.
    return cfg, interceptor, audit


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
    from .pinning import ToolPinStore

    cfg, interceptor, audit = _build_runtime(
        args.config, args.audit, args.approval_timeout,
        seal_state=args.seal_state, anchor_path=args.anchor)
    # SECURITY: enable TOFU rug-pull defense in the live runtime. A downstream tool whose definition
    # changed since first sight is quarantined (dropped from the advertised + routable set) and the
    # event is recorded to the tamper-evident audit chain. Without this wiring the pin store is
    # dormant. Disable only with --no-pinning (e.g. first run against a trusted, still-churning server).
    pin_store = None if args.no_pinning else ToolPinStore(args.pins)
    proxy = WardenProxy(_proxy_config(cfg), interceptor, pin_store=pin_store, audit=audit)
    pin_note = "off" if args.no_pinning else args.pins
    seal_note = f" · seal={args.seal_state}" if args.seal_state else ""
    sys.stderr.write(
        f"🛡️  warden proxy starting · policy={args.config} · audit={args.audit} · pins={pin_note}{seal_note}\n")
    try:
        asyncio.run(proxy.run_stdio())
    finally:
        # Seal the session's audit head on shutdown (forward-secure boundary). Periodic mid-run
        # sealing is available via a cron'd `warden audit seal`.
        if args.seal_state:
            audit.seal_now()
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


def _read_seed(args) -> bytes | None:
    seed_hex = getattr(args, "seed", None)
    if not seed_hex:
        return None
    if os.path.exists(seed_hex):  # a path to a seed file
        seed_hex = open(seed_hex, encoding="utf-8").read().strip()
    return bytes.fromhex(seed_hex)


def _cmd_audit_verify(args) -> int:
    ok, msg = AuditLog(args.log).verify(seed=_read_seed(args))
    sys.stderr.write(("✅ " if ok else "❌ ") + msg + "\n")
    return 0 if ok else 2


def _cmd_audit_setup_keys(args) -> int:
    from .sealing import ForwardSecureSealer
    if os.path.exists(args.state):
        sys.stderr.write(f"refusing to overwrite sealer state {args.state} (delete it to re-init)\n")
        return 1
    seed = ForwardSecureSealer.setup(args.state)
    seed_hex = seed.hex()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(seed_hex + "\n")
        os.chmod(args.out, 0o600)
        sys.stderr.write(f"🔑 verification seed written → {args.out} (chmod 600)\n")
    sys.stderr.write(
        "🔑 VERIFICATION SEED (store OFF this box — email it to yourself / a vault; the box cannot\n"
        "   prove its own history to you without it, and forward security is pointless if it stays here):\n"
        f"\n   {seed_hex}\n\n"
        f"sealer state → {args.state}. Run `warden run --seal-state {args.state}` to enable sealing.\n")
    return 0


def _cmd_audit_seal(args) -> int:
    from .sealing import ForwardSecureSealer, AnchorSink
    sealer = ForwardSecureSealer(args.state)
    if not sealer.is_setup:
        sys.stderr.write(f"❌ no sealer state at {args.state} (run `warden audit setup-keys` first)\n")
        return 2
    anchor = AnchorSink(path=args.anchor) if args.anchor else None
    rec = AuditLog(args.log, sealer=sealer, anchor=anchor).seal_now()
    sys.stderr.write(f"🔒 sealed epoch {rec['epoch']} at seq {rec['seq']}"
                     + (f" · anchored → {args.anchor}" if args.anchor else "") + "\n")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="warden", description="Drop-in MCP security middleware")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="start the proxy (stdio MCP server)")
    pr.add_argument("--config", default="warden.yaml")
    pr.add_argument("--audit", default="warden_audit.jsonl")
    pr.add_argument("--pins", default="warden_pins.json",
                    help="TOFU tool-definition pin store (rug-pull defense)")
    pr.add_argument("--no-pinning", action="store_true",
                    help="disable TOFU rug-pull quarantine (not recommended)")
    pr.add_argument("--seal-state",
                    help="enable forward-secure sealing using this sealer state (see `warden audit setup-keys`)")
    pr.add_argument("--anchor", help="append signed heads to this off-box anchor file")
    pr.add_argument("--approval-timeout", type=float, default=120.0)
    pr.set_defaults(func=_cmd_run)

    pi = sub.add_parser("init", help="write a starter warden.yaml")
    pi.add_argument("path", nargs="?", default="warden.yaml")
    pi.add_argument("--force", action="store_true")
    pi.set_defaults(func=_cmd_init)

    pa = sub.add_parser("audit", help="audit log tools")
    asub = pa.add_subparsers(dest="audit_cmd", required=True)
    pav = asub.add_parser("verify", help="verify the tamper-evident chain (+ seals with --seed)")
    pav.add_argument("--log", default="warden_audit.jsonl")
    pav.add_argument("--seed", help="verification seed (hex or path to seed file) to check forward-secure seals")
    pav.set_defaults(func=_cmd_audit_verify)

    pak = asub.add_parser("setup-keys", help="initialise forward-secure sealing; prints the off-box verification seed")
    pak.add_argument("--state", default="warden_seal_state.json")
    pak.add_argument("--out", help="write the verification seed to this file (chmod 600)")
    pak.set_defaults(func=_cmd_audit_setup_keys)

    pas = asub.add_parser("seal", help="seal the current audit head and advance the epoch (run periodically)")
    pas.add_argument("--log", default="warden_audit.jsonl")
    pas.add_argument("--state", default="warden_seal_state.json")
    pas.add_argument("--anchor", help="append the signed head to this off-box anchor file")
    pas.set_defaults(func=_cmd_audit_seal)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
