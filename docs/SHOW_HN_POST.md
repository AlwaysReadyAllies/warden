# Show HN — paste-ready (plain text, no markdown)

HN doesn't render markdown — no blockquotes, no bold, no inline code. Everything below is plain text
you can copy straight in. (HN keeps paragraph breaks and turns bare URLs into links; that's all.)

═══════════════════════════════════════════════════════════════════════════════
TITLE (paste into the title field)
═══════════════════════════════════════════════════════════════════════════════

Show HN: Warden – a drop-in security proxy for MCP (audit, policy, injection defense)

═══════════════════════════════════════════════════════════════════════════════
URL (paste into the url field)
═══════════════════════════════════════════════════════════════════════════════

https://github.com/AlwaysReadyAllies/warden

═══════════════════════════════════════════════════════════════════════════════
FIRST COMMENT (post this immediately as a reply to your own submission)
═══════════════════════════════════════════════════════════════════════════════

Everyone's wiring agents up to MCP tool-servers — filesystem, GitHub, payments, shells. Almost nobody has a layer that says "no" before the agent does something irreversible, or that catches a prompt-injection hidden in a web page a tool returned. So I built Warden.

Warden is an MCP proxy: your client points at Warden instead of the raw server (one line in .mcp.json, no code change), and Warden speaks MCP in both directions — aggregating each server's tools and routing every call through: policy → audit → human-approval → guard → forward.

What it does:

- Policy (warden.yaml): allow / deny / gate / redact per tool, with precedence + glob/regex rules. Denied tools aren't even advertised (least privilege).

- Human-in-the-loop: dangerous actions block for approval (CLI or Telegram), fail-closed on timeout.

- Guard: strips prompt-injection from tool results (normalizes unicode + decodes base64/hex/url first, so the obvious evasions don't work) and redacts leaked secrets (provider keys, JWTs, private keys, PII). Hard-denies "rm -rf" / "DROP TABLE" style payloads in args even if policy allows the tool.

- Tamper-evident audit: hash-chained JSONL; "warden audit verify" catches any edit/insert/delete. Optional forward-secure sealing makes a rewrite detectable even by a privileged local operator — the key that sealed a record is ratcheted forward and destroyed, so past records can't be forged after a compromise.

- Capability policy: decide on what a tool can do (read/write/exec/network/…), not its name — so a renamed or shadowed tool can't slip past a name-based rule.

- It proves itself: "warden prove" fires a CWE-grounded attack suite through the real proxy and records, per attack, whether the control actually held — anchored into the audit chain as a verifiable certificate. If it can't verify a control, it fails loudly rather than reporting a false pass.

It's local-first and makes zero network calls of its own (it sees all tool traffic — it must not become an exfil path). ~1.4 ms overhead per call. There's also a static companion, mcp-scan, that audits a server's tool definitions before you ever connect.

Honest about limits: the injection corpus is ongoing work — that's the part I most want adversarial eyes on. And regex/normalization-based injection stripping is inherently a moving target, not a solved problem.

Try it: uvx warden-mcp init && uvx warden-mcp run — or run examples/hero_demo.py to watch it block a destructive call, redact a leaked key, and catch a forged audit record. Apache-2.0. Feedback / new injection bypasses very welcome.

═══════════════════════════════════════════════════════════════════════════════
Reminders: post Tue–Thu ~8–10am ET · paste the comment the SECOND it's live ·
answer every reply for 3+ hours · never ask for upvotes.
═══════════════════════════════════════════════════════════════════════════════
