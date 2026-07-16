# Warden — Launch Kit (drafts for review; nothing is published)

Open-core distribution. The hero demo IS the pitch: `python examples/hero_demo.py`.

---

## 1. Install one-liner (goes in README top + every listing)

```bash
# zero install — run it
uvx warden-mcp init && uvx warden-mcp run

# point any MCP client at it (.mcp.json / Claude Desktop / Cursor)
{ "mcpServers": { "warden": { "command": "uvx", "args": ["warden-mcp", "run"] } } }
```

---

## 2. Registry listing (mcp.so / glama / mcpservers.org / awesome-mcp-servers)

**Name:** Warden
**Tagline:** Drop-in security middleware for MCP — audit, policy, human-approval, injection defense.
**Categories:** security, middleware, proxy, guardrails, observability
**One-paragraph:**
> Warden sits between your AI client and its MCP tool-servers — one line of config, zero code. Every
> tool call is logged tamper-evidently, allowed/denied/gated by policy, held for human approval when it's
> dangerous, and scanned for prompt-injection and secret/PII exfiltration. Universal (any MCP client × any
> MCP server), local-first, zero egress, ~1.4 ms overhead.
**Links:** repo · `examples/hero_demo.py` · SECURITY.md
**Config snippet:** (the install one-liner above)

---

## 3. Show HN

**Title:** `Show HN: Warden – a drop-in security proxy for MCP (audit, policy, injection defense)`

**Body:**
> Everyone's wiring agents up to MCP tool-servers — filesystem, GitHub, payments, shells. Almost nobody
> has a layer that says "no" before the agent does something irreversible, or that catches a prompt-
> injection hidden in a web page a tool returned. So I built Warden.
>
> Warden is an MCP proxy: your client points at Warden instead of the raw server (one line in `.mcp.json`,
> no code change), and Warden speaks MCP in both directions — aggregating each server's tools and routing
> every call through: **policy → audit → human-approval → guard → forward**.
>
> What it does:
> - **Policy** (`warden.yaml`): allow / deny / gate / redact per tool, with precedence + glob/regex rules.
>   Denied tools aren't even advertised (least privilege).
> - **Human-in-the-loop**: dangerous actions block for approval (CLI or Telegram), fail-closed on
>   timeout.
> - **Guard**: strips prompt-injection from tool *results* (normalizes unicode + decodes base64/hex/url
>   first, so the obvious evasions don't work) and redacts leaked secrets (provider keys, JWTs, private
>   keys, PII). Hard-denies `rm -rf` / `DROP TABLE` style payloads in args even if policy allows the tool.
> - **Tamper-evident audit**: hash-chained JSONL; `warden audit verify` catches any edit/insert/delete.
>   Optional forward-secure sealing makes a rewrite detectable even by a privileged local operator — the
>   key that sealed a record is ratcheted forward and destroyed, so past records can't be forged after a
>   compromise.
> - **Capability policy**: decide on *what a tool can do* (read/write/exec/network/…), not its name — so a
>   renamed or shadowed tool can't slip past a name-based rule.
> - **It proves itself**: `warden prove` fires a CWE-grounded attack suite through the real proxy and
>   records, per attack, whether the control actually held — anchored into the audit chain as a
>   verifiable certificate. If it can't verify a control, it fails loudly rather than reporting a false pass.
>
> It's local-first and makes zero network calls of its own (it sees all tool traffic — it must not become
> an exfil path). ~1.4 ms overhead per call. There's also a static companion, `mcp-scan`, that audits a
> server's tool definitions before you ever connect.
>
> Honest about limits: the injection corpus is ongoing work — that's the part I most want adversarial eyes
> on. And regex/normalization-based injection stripping is inherently a moving target, not a solved problem.
>
> Try it: `uvx warden-mcp init && uvx warden-mcp run`, or run `examples/hero_demo.py` to watch it block
> a destructive call, redact a leaked key, and catch a forged audit record. Apache-2.0. Feedback / new
> injection bypasses very welcome.

*(Post Tue–Thu, ~9am ET. Be in the thread to answer. Lead with the demo, not the architecture.)*

---

## 4. X / short post

> Wired your AI agent to MCP tool-servers? There's nothing stopping it from running `rm -rf` or leaking a
> key from an injected web page.
>
> Warden: a drop-in MCP security proxy. Policy + human-approval + tamper-evident audit + injection/secret
> defense. One line of config, zero egress, ~1.4ms.
>
> `uvx warden-mcp` · Apache-2.0 🛡️

---

## 5. Launch checklist (publish steps — operator does these)

- [ ] Repo public (GitHub mirror of the local repo); CI runs `pytest` + the live smoke
- [ ] `pip`/PyPI: `python -m build && twine upload` so `uvx warden-mcp` resolves
- [ ] README has the install one-liner + an asciinema/GIF of `hero_demo.py`
- [ ] List on: modelcontextprotocol/servers, mcp.so, glama.ai, mcpservers.org, awesome-mcp-servers (PRs)
- [ ] Show HN (title above) + cross-post r/LocalLLaMA, the MCP Discord, security-AI communities
- [ ] SECURITY.md disclosure email is real before launch
- [ ] Pin: "new injection bypasses → issues welcome" (turns the community into the corpus's maintainers)

## Positioning (why this wins, for our own clarity)
Low floor (one config line), high ceiling (compliance-grade audit). Security×AI is the moat. Standards/
benchmarks self-distribute — the v2 move is a public **agent-security benchmark + audited-safe-MCP
registry** so Warden becomes the *reference*, not just a tool. "Everyone's building agents. Warden makes
them safe to run."
