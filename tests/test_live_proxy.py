"""Live end-to-end: a real client → Warden proxy → a real downstream MCP server, over stdio.

Proves the proxy actually runs as an MCP server, namespaces downstream tools, and routes calls
through the full interceptor pipeline (policy + guard) against a live server — not mocks.
"""
import asyncio
import os
import sys
import tempfile

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)


def _write_config() -> str:
    echo = os.path.join(HERE, "echo_server.py").replace("\\", "\\\\")
    cfg = f"""
mode: allow
servers:
  echo:
    cmd: ["{sys.executable}", "{echo}"]
    tools:
      echo:   {{ action: allow }}
      leak:   {{ action: allow }}
      danger: {{ action: allow }}
"""
    p = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    p.write(cfg)
    p.close()
    return p.name


async def main() -> int:
    cfg = _write_config()
    env = dict(os.environ, PYTHONPATH=PKG_ROOT)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "warden", "run", "--config", cfg, "--audit", tempfile.mktemp(suffix=".jsonl")],
        env=env,
        cwd=PKG_ROOT,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=20)

            tools = await asyncio.wait_for(session.list_tools(), timeout=20)
            names = {t.name for t in tools.tools}
            assert "echo__echo" in names, f"namespaced tool missing: {names}"
            print("1. namespaced tools advertised:", sorted(names))

            r = await asyncio.wait_for(session.call_tool("echo__echo", {"text": "hello warden"}), timeout=20)
            text = "".join(getattr(c, "text", "") for c in r.content)
            assert "hello warden" in text, f"echo failed: {text!r}"
            print("2. echo round-trip through pipeline:", text)

            r = await asyncio.wait_for(session.call_tool("echo__leak", {}), timeout=20)
            text = "".join(getattr(c, "text", "") for c in r.content)
            assert "sk-ABCDEF0123456789" not in text, f"secret NOT redacted live: {text!r}"
            print("3. result secret redacted live:", "REDACTED ✅" if "REDACT" in text.upper() else text)

            print("LIVE_PROXY_OK — real client → Warden → real server, namespaced + guarded")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
