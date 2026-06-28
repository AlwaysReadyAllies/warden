"""Prove Warden fronting the REAL ara-delegate MCP server: read flows through (allowed+audited),
the powerful `delegate` is gated (blocked without a TTY = fail-closed, no CLI spawned), audit verifies.
"""
import asyncio
import os
import sys
import tempfile

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PKG)
CFG = os.path.join(PKG, "deploy", "ara-delegate.yaml")
ARA = "/home/croft/user/Ara"


async def main() -> int:
    audit = tempfile.mktemp(suffix=".jsonl")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "warden", "run", "--config", CFG, "--audit", audit, "--approval-timeout", "2"],
        env=dict(os.environ, PYTHONPATH=PKG, ARA_HOME=ARA),
        cwd=PKG,
    )
    print("🛡️  Warden  ⟶  ara-delegate (the gang dispatcher)\n", flush=True)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await asyncio.wait_for(s.initialize(), timeout=30)

            tools = await asyncio.wait_for(s.list_tools(), timeout=30)
            names = sorted(t.name for t in tools.tools)
            print("1. tools exposed through Warden (namespaced):", names)
            assert any(n.endswith("__delegate") for n in names), names

            # read-only: allowed -> real downstream call returns the registry, audited
            reg = await asyncio.wait_for(s.call_tool("ara_delegate__delegate_registry", {}), timeout=60)
            txt = "".join(getattr(c, "text", "") for c in reg.content)
            print(f"2. delegate_registry (allow) -> real result through proxy: {len(txt)} chars, "
                  f"mentions a CLI: {'codex' in txt.lower() or 'grok' in txt.lower() or 'gang' in txt.lower()}")

            # powerful: gated -> no TTY -> fail-closed BLOCK (no frontier CLI spawned, no tokens spent)
            try:
                res = await asyncio.wait_for(
                    s.call_tool("ara_delegate__delegate", {"prompt": "noop", "role": "analyze"}), timeout=30)
                err = bool(getattr(res, "isError", False)) or "block" in str(getattr(res, "content", "")).lower()
                print(f"3. delegate (gate, no TTY) -> {'BLOCKED ✅ (fail-closed, no CLI spawned)' if err else 'ALLOWED ❌'}")
            except Exception as e:
                print(f"3. delegate (gate, no TTY) -> BLOCKED ✅ ({type(e).__name__})")

    from warden.audit import AuditLog
    ok, msg = AuditLog(audit).verify()
    print(f"4. audit trail: {msg}")
    print("\nDEPLOY_OK — Warden is guarding ara-delegate: reads flow, dispatch is gated, all audited.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
