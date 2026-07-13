# Warden — Launch Checklist (do these in order)

Everything below is prepped. The only blocking manual step is **#1 (flip public)**.
PyPI is live (`warden-mcp` 0.1.1), the `uvx` one-liner is verified working, repo metadata + topics
+ release are set. Post the Show HN when you have a ~3-hour window to answer comments (Tue–Thu ~9am ET).

---

## 1. Flip the repo public  ⬅ the one blocker
`github.com/AlwaysReadyAllies/warden` → **Settings → Danger Zone → Change visibility → Public**.
(Pre-public secret/PII scan already passed; `deploy/` with private paths removed.)

## 2. Verify the public front door (30 sec, after flipping)
- Repo README renders with PyPI/Python/license badges.
- `github.com/AlwaysReadyAllies/warden/releases/tag/v0.1.1` is visible.
- A stranger's command works: `uvx warden-mcp init && uvx warden-mcp run`  (already verified from PyPI).

## 3. Registry listings (each is a submission form or a PR — links go live once public)

**awesome-mcp-servers** (github.com/punkpeye/awesome-mcp-servers or wong2/awesome-mcp-servers):
fork → add under the **Security** section → PR. Entry:
```markdown
- [Warden](https://github.com/AlwaysReadyAllies/warden) 🐍 🏠 - Drop-in MCP security proxy: policy, tamper-evident audit, human approval, prompt-injection & secret-exfil defense. One line of config, zero code.
```
(🐍 = Python, 🏠 = local/self-hosted — match the list's legend.)

**mcp.so** — submit at mcp.so/submit. Name: Warden · Category: Security ·
Tagline: "Drop-in security middleware for MCP — audit, policy, human-approval, injection defense." ·
Repo + PyPI links · config snippet:
```json
{ "mcpServers": { "warden": { "command": "uvx", "args": ["warden-mcp", "run"] } } }
```

**Glama** (glama.ai/mcp/servers) — auto-indexes public GitHub MCP servers; ensure the repo has the
`mcp` topic (done) and a clear README (done). May appear automatically; can submit manually too.

**mcpservers.org / modelcontextprotocol servers list** — PR to the community list if desired.

## 4. Show HN (the adoption driver — the non-me-too one)
Title + body are in `docs/LAUNCH.md §3`. Key discipline:
- **Lead with the demo, not the architecture.** First line points at the 15-sec `hero_demo.py`.
- Be honest about limits (the post already is — "injection corpus is ongoing, adversarial eyes welcome").
- Reply to every comment in the first 3 hours; fix any real bug live.
- Don't claim to be the only MCP-security tool — position: "genuinely open, local-first, one-line."

## 5. X / short post — `docs/LAUNCH.md §4`.

---

## Deliberately NOT done (by decision)
- **No paywall.** Warden is Apache-2.0 open-lane brand play; revenue is depfirewall + a future
  hosted/audit-compliance tier once there's a user base. Don't gate the OSS core.
- **History scrub** not run (old commits contain `/home/croft/...` path strings — low-risk path
  disclosure, not secrets; rewriting SHAs on a tagged repo isn't worth it. Ask if you want it.)

## Post-launch hygiene (when things settle)
- Move the **PyPI / GitHub / Cloudflare tokens off the Desktop into Vaultwarden**; swap the
  account-wide PyPI token for a `warden-mcp`-scoped one.
