# Warden — Security Model

Warden is the security layer, so it states its own threat model and limits plainly.

## What Warden defends against
- **Indirect prompt injection** — malicious instructions embedded in tool *results* (web pages, files,
  issues) are detected and stripped before they reach the model. Detection normalizes (NFKC + zero-width/
  BiDi stripping) and decodes (URL/base64/hex) before matching, and recurses into nested dict/list/JSON/
  bytes payloads — so common evasions don't slip through.
- **Credential / PII exfiltration** — provider keys (`sk-…`, `ghp_…`, `AKIA…`, `AIza…`), JWTs, private
  keys, password assignments, emails, SSNs are redacted from tool results.
- **Destructive / injection payloads in tool args** — `rm -rf`, `mkfs`, `dd` to a device, fork bombs,
  `DROP TABLE`, shell metacharacter chaining, SQLi, path traversal — hard-denied even if policy says allow
  (defense in depth).
- **Over-broad tool access** — policy allow/deny/gate per tool; denied tools are never even advertised
  upstream (least privilege). Dangerous actions require human approval.
- **Hostile downstream MCP servers** — tool metadata is namespaced + validated, never passed through raw;
  one server can't shadow another or spoof a namespace; a hung/crashing server is isolated by per-call
  and per-connect timeouts and cannot take down the proxy or sibling servers.
- **Interceptor/route tampering** — the forwarder refuses any destination rewrite (approval for one tool
  can't be converted into a call to another), validated against immutable saved identifiers.

## Tamper-evident audit — and its honest limit
The audit log is an append-only, hash-chained JSONL: `hash = sha256(prev_hash + canonical(record))`.
`warden audit verify` recomputes the chain and pinpoints any edited/inserted/deleted record.

**Limitation (stated plainly):** a hash chain with no secret key detects *edit-without-rechain*, but an
attacker with write access to the log file AND the ability to run could recompute the entire chain after
an edit. Mitigations, in order of strength:
1. **Anchor the head hash** out-of-band (print/ship `head_hash` to an append-only or external sink
   periodically) — then any rewrite is detectable by comparing anchors. *(recommended operationally)*
2. **Signed records** (per-record HMAC/asymmetric signature with a key the agent host can't read) —
   on the v2 roadmap.
Until anchoring/signing is enabled, treat the chain as integrity-evident against tampering by anything
*other* than a privileged local attacker, and anchor the head hash for the stronger guarantee.

## Fail-closed posture
Approval timeout, a missing approval channel, or any non-affirmative answer ⇒ the call is **blocked**.
Silence is never consent. Unconfigured tools default to deny.

## Warden's own footprint
Warden makes **no network calls of its own** — detection is local regex/normalization, zero egress. It
sees all tool traffic, so it must not become an exfil path itself. (We eat our own dog food.)

## Reporting a vulnerability
Report privately via a GitHub security advisory on this repository, or email
security@alwaysreadyallies.com, with a proof of concept. Please do not open a public issue for an
unpatched vulnerability. The injection-pattern corpus in `warden/guard.py` is intentionally
maintained — new evasion techniques are especially welcome as advisories or PRs.
