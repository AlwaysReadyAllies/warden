"""A deliberately-permissive reference MCP server — the target for `warden prove --live`.

It is INTENTIONALLY vulnerable: every tool executes whatever it's given and returns a distinct
canary string proving the call actually reached it. Fronted by Warden, the attacks in the live proof
should never reach these canaries. Standalone (no Warden), they all "succeed" — that's the point: it
demonstrates what Warden is preventing. NEVER expose this server without Warden in front of it.

Tool names/descriptions are realistic so Warden's capability classifier tags them correctly
(fetch_url→NETWORK, run_command→EXECUTE, transfer_funds→FINANCIAL, delete_record→DELETE).
"""
import asyncio

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server("reference")

CANARY = "WARDEN-CANARY"  # if this appears in a proof result, the attack REACHED the tool → a leak


@server.list_tools()
async def list_tools():
    return [
        types.Tool(name="fetch_url", description="Fetch the contents of a URL over the network.",
                   inputSchema={"type": "object", "properties": {"url": {"type": "string"}},
                                "required": ["url"]}),
        types.Tool(name="read_file", description="Read a file from the local filesystem by path.",
                   inputSchema={"type": "object", "properties": {"path": {"type": "string"}},
                                "required": ["path"]}),
        types.Tool(name="run_command", description="Execute a shell command and return its output.",
                   inputSchema={"type": "object", "properties": {"command": {"type": "string"}},
                                "required": ["command"]}),
        types.Tool(name="run_query", description="Run a SQL query against the database.",
                   inputSchema={"type": "object", "properties": {"query": {"type": "string"}},
                                "required": ["query"]}),
        types.Tool(name="send_message", description="Send a message with the given body to a recipient.",
                   inputSchema={"type": "object", "properties": {"body": {"type": "string"},
                                                                 "to": {"type": "string"}}}),
        types.Tool(name="transfer_funds", description="Transfer money to a recipient account.",
                   inputSchema={"type": "object", "properties": {"amount": {"type": "number"},
                                                                 "to": {"type": "string"}}}),
        types.Tool(name="delete_record", description="Permanently delete a record by id.",
                   inputSchema={"type": "object", "properties": {"id": {"type": "string"}}}),
    ]


@server.call_tool()
async def call_tool(name, arguments):
    a = arguments or {}
    detail = a.get("url") or a.get("path") or a.get("command") or a.get("query") or a.get("body") or ""
    return [types.TextContent(type="text", text=f"{CANARY}:{name}:{detail}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
