# 🛡️ Warden

**Drop-in security middleware for MCP.** Point your AI client at Warden instead of the raw
tool-server — one line of config, zero code changes — and every tool call is logged tamper-evidently,
allowed/denied/gated by policy, held for human approval when it's dangerous, and scanned for
prompt-injection and secret/PII exfiltration.

> Everyone's building agents. Warden makes them safe to run.

## How it works

```
AI client ──MCP──▶  WARDEN  ──MCP──▶  downstream MCP servers
                   policy · audit · approval · guard       (filesystem, github, payments, …)
```

Warden is an MCP **server** to your client and an MCP **client** to each real server. It aggregates
their tools (namespaced `server__tool`) and routes every `tools/call` through:

**policy → audit(request) → guard(args) → [deny | approve | allow] → forward → guard(result) → audit(response)**

## Quickstart

```bash
uvx warden-mcp init                 # write a starter warden.yaml
uvx warden-mcp run --config warden.yaml
uvx warden-mcp audit verify         # prove the audit log wasn't altered
```

Point your client at it (e.g. `.mcp.json` / Claude Desktop / Cursor):

```json
{ "mcpServers": { "warden": { "command": "uvx", "args": ["warden-mcp", "run"] } } }
```

## Policy (`warden.yaml`)

```yaml
mode: allow            # allow (log all, gate listed) | strict (deny unless allowed)
servers:
  filesystem:
    cmd: ["npx","-y","@modelcontextprotocol/server-filesystem","/work"]
    tools:
      read_file:  { action: allow }
      write_file: { action: gate, reason: "file write" }
      delete_*:   { action: deny }
  payments:
    url: "http://localhost:9001/mcp"
    tools: { "*": { action: gate } }
sensitive_actions: [transfer, send, delete, purchase, grant, deploy]
rules:
  - id: dangerous-shell
    match: { arg_regex: "rm\\s+-rf|DROP\\s+TABLE" }
    action: deny
  - id: secret-egress
    match: { direction: result, contains: ["BEGIN PRIVATE KEY", "password="] }
    action: redact_and_flag
```

Starter policies in `policies/`: **paranoid · balanced · dev**.

## Why it's trustworthy

- **Tamper-evident audit** — hash-chained JSONL; `warden audit verify` detects any edit/insert/delete.
  Args/results are stored as digests + truncated previews so the log isn't itself a secret store.
- **Fail closed** — approval timeout, no channel, or any non-yes ⇒ the call is blocked.
- **Defense in depth** — the guard hard-denies an unambiguously destructive payload (`rm -rf`,
  `mkfs`, `DROP TABLE`) and redacts leaked secrets (provider keys, JWTs, private keys) even when
  policy says allow.
- **Untrusted-by-default downstream** — tool metadata is namespaced + validated, never passed through
  raw; a malicious downstream can't shadow another or inject via tool descriptions. A failing server
  is isolated, not fatal.
- **Zero egress** — Warden makes no network calls of its own. It eats its own dog food.

## Layout

```
warden/
  schemas.py      shared contract (closed-enum decisions, hash-by-default audit)
  proxy.py        MCP upstream server + downstream clients + namespacing
  interceptor.py  the policy→audit→approval→guard pipeline
  policy.py       YAML → allow/deny/gate/redact (with precedence)
  guard.py        prompt-injection corpus + secret/PII + shell/SQL/path detection
  audit.py        hash-chained tamper-evident log + verify
  approval/       human-in-the-loop (CLI; Telegram next)
```

Apache-2.0 · built by Always Ready Allies LLC.
