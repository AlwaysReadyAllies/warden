# 🛡️ Warden

[![PyPI](https://img.shields.io/pypi/v/warden-mcp?color=2d7)](https://pypi.org/project/warden-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/warden-mcp)](https://pypi.org/project/warden-mcp/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

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

Rug-pull defense (TOFU tool-definition pinning) is **on by default** — a downstream tool whose
definition changes after you first approved it is quarantined until you re-approve it.

### Optional: tamper-evidence against a hostile operator

The plain audit log detects edits-without-rechain. To make tampering detectable even by someone with
write access to the host, enable **forward-secure sealing** (stdlib, no extra deps):

```bash
uvx warden-mcp audit setup-keys --out warden.seed   # prints a VERIFICATION SEED — store it OFF-box
uvx warden-mcp run --seal-state warden_seal_state.json --anchor heads.jsonl
uvx warden-mcp audit verify --log warden_audit.jsonl --seed warden.seed   # verifies the seals
```

A record sealed before a compromise cannot be forged or rewritten afterward — the key that sealed it
is ratcheted forward and destroyed. (Tamper-**evident**, not tamper-proof: deletion is always
possible, you detect it via the off-box anchored heads.)

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

### Cross-server dataflow: the lethal-trifecta defense

Per-call rules can't see an attack that spans a session — read untrusted content from one server,
get steered by an injected instruction, exfiltrate via another. Tag the ends and Warden tracks the
flow: once an untrusted **source** has returned content into the session, any **sink** that can
exfiltrate is denied (or gated):

```yaml
flow:
  on_violation: gate        # gate (ask a human) | deny (default, fail closed)
  sources: ["web__*", "email__read*"]      # tools whose results are untrusted content
  sinks:   ["email__send*", "http__post", "slack__*"]   # tools that can send data out
```

"Untrusted-content-touched context may not reach an exfil-capable tool without a human in the loop."

## Remote deployment: HTTP gateway + OAuth 2.1

Run Warden as a deployable HTTP MCP gateway (streamable transport) instead of stdio:

```bash
pip install "warden-mcp[http,auth]"
uvx warden-mcp run --http --host 0.0.0.0 --port 8080 --config warden.yaml
```

With an `auth:` block, Warden is an **OAuth 2.1 Resource Server** — every request to the `/mcp`
endpoint must carry a valid bearer token or it's rejected **before reaching any tool** with `401` +
a `WWW-Authenticate` challenge. It validates per the MCP authorization spec: RFC 9728 Protected
Resource Metadata (served at `/.well-known/oauth-protected-resource`), **RFC 8707 audience binding**
(a token minted for another service is rejected), JWKS signature verification (asymmetric only — no
`alg:none`), and scope enforcement.

```yaml
auth:
  resource: https://warden.example/mcp
  issuer: https://auth.example/
  jwks_uri: https://auth.example/.well-known/jwks.json
  required_scopes: [mcp:call]
```

(stdio is a local single-user trust boundary and needs no token; `--http` without an `auth:` block
serves openly — put it behind your own boundary.)

### Remote approvals (Telegram)

In headless / `--http` mode there's no terminal, so gated calls would fail closed. Approve them from
your phone instead — `pip install "warden-mcp[telegram]"` and add:

```yaml
approval:
  channel: telegram
  bot_token_env: WARDEN_TELEGRAM_TOKEN   # token read from the environment, never the file
  chat_id: "123456789"
```

Each gated call sends a message with inline **Approve** / **Deny** buttons; timeout or any error
fails closed.

## `mcp-scan` — audit a server before you trust it

Warden guards tool calls at runtime; `mcp-scan` is the static, pre-install companion. Point it at an
MCP server and it inspects every tool **definition** for tool-poisoning / prompt-injection hidden in
descriptions, secrets in schemas, dangerous capabilities, and the **lethal-trifecta combination** (a
server that can both read untrusted content *and* exfiltrate). Exits non-zero on risk, so it gates CI.

```bash
mcp-scan --command npx --arg -y --arg @some/mcp-server   # or --url https://…/mcp, or --config .mcp.json
warden scan --config .mcp.json --json                    # same, as a warden subcommand
```

It reuses Warden's own guard corpus, pin fingerprints, and dataflow taxonomy — the static half of the
same engine. (Fills the gap left when Invariant's `mcp-scan` was acquired and closed.)

## Why it's trustworthy

- **Tamper-evident audit** — hash-chained JSONL; `warden audit verify` detects any edit/insert/delete.
  Add **forward-secure sealing** to catch even a hostile operator who rewrites and re-chains the log.
- **Rug-pull defense** — TOFU pinning quarantines a tool whose definition changes after approval.
- **Fail closed** — approval timeout, no channel, redaction-without-a-guard, or any non-yes ⇒ blocked.
- **Defense in depth** — the guard hard-denies an unambiguously destructive payload (`rm -rf`,
  `mkfs`, `DROP TABLE`) and redacts leaked secrets (provider keys, JWTs, private keys) even when
  policy says allow. `direction: result` rules can deny a response that leaks (e.g. a private key).
- **Untrusted-by-default downstream** — tool metadata is namespaced + validated + stripped, never
  passed through raw; a malicious downstream can't shadow another or inject via tool descriptions.
- **Zero egress** — the core proxy + guard make no network calls of their own. The guard is pure
  local regex — no LLM in the request path (deterministic, fast, nothing leaves the box).

## Layout

```
warden/
  schemas.py      shared contract (closed-enum decisions, hash-by-default audit)
  proxy.py        MCP upstream server + downstream clients + namespacing + pin check
  interceptor.py  the policy→audit→approval→guard pipeline (+ REDACT + result rules)
  policy.py       YAML → allow/deny/gate/redact/redact_and_flag (request + result direction)
  guard.py        prompt-injection corpus + secret/PII + shell/SQL/path detection
  audit.py        hash-chained tamper-evident log + verify (+ forward-secure seals)
  sealing.py      forward-secure sealing + external anchoring (hostile-operator defense)
  pinning.py      TOFU tool-definition pinning (rug-pull defense)
  auth.py         OAuth 2.1 Resource Server — RFC 9728/8707, JWKS, scopes (extra: [auth])
  http.py         deployable HTTP MCP gateway + bearer-auth middleware (extra: [http])
  flow.py         cross-server dataflow / lethal-trifecta defense (session taint tracking)
  scan.py         mcp-scan — static pre-install risk audit of an MCP server's tools
  scan_cli.py     the `mcp-scan` console script + `warden scan` subcommand
  approval/       human-in-the-loop — CLI (/dev/tty) + Telegram (headless/remote, extra: [telegram])
```

Apache-2.0 · built by Always Ready Allies LLC. Security contact: see `SECURITY.md`.
