# Warden — Controls, Proof & Evidence (engineering notes)

Durable notes for the deterministic control set and the scan → govern → prove → sign story. Every
control is deterministic (no LLM in the hot path); every claim here is backed by a module + tests.

## The four verbs

| Verb | Command | Question it answers | Module |
|---|---|---|---|
| **Scan** | `warden scan` | What could this server's tools *do* before I trust it? | `scan.py`, `scan_cli.py` |
| **Govern** | `warden run` | Enforce policy on every call, in front of the real server | `proxy.py`, `interceptor.py`, `runtime.py` |
| **Prove** | `warden prove [--live]` | Do the configured controls *actually block* attacks? | `effectiveness.py`, `liveprove.py` |
| **Sign** | `warden prove --sign` / `warden audit` | Is this proof tamper-evident evidence? | `evidence.py`, `audit.py`, `sealing.py` |

Commercial umbrella: **Warden = Proxy / Scan / Verify / Evidence.**

## Deterministic controls (enforced in `interceptor.py`)

Pipeline order per call:
`policy → audit(request) → guard(args) → arg_constraints → boundaries → flow → deny|gate|allow → forward → result-rules → postconditions → guard(result) → audit(response)`

1. **Capability taxonomy + policy** — `capabilities.py`
   Deterministic classification of a tool into a capability SET: `READ / WRITE / DELETE / EXECUTE /
   NETWORK / CREDENTIAL / FINANCIAL / ADMIN / UNKNOWN`. Policy rules match on `capability` (any-of,
   case-insensitive) so one rule governs WHAT a tool can do without naming each tool.
   *Gotcha:* `_normalize()` splits camelCase + separators to spaces first — a `\b`-based regex never
   matches inside `fetch_url`/`transfer_funds` otherwise.

2. **Capability-expansion diff gate** — `capsnapshot.py`
   `warden capabilities --snapshot base.json` pins a baseline; `--check base.json` exits 2 in CI when a
   tool gains a dangerous capability (a rug-pull or a new dependency's tool). A new READ-only tool is
   not an expansion; a new dangerous tool is.

3. **Resource / destination boundaries** — `boundaries.py`
   `constraints: {network: {domains:[…]}, filesystem: {roots:[…]}}`. URL hosts must match a domain glob;
   paths must resolve under an allowed root (normpath catches `../` escape). Recurses nested args.

4. **Typed argument constraints** — `argconstraints.py`
   Per-tool, per-argument value rules: `type / const / enum / minimum / maximum / minLength / maxLength /
   pattern / email_domain / items`. Governs the SHAPE of a call (a transfer capped, a branch prefixed, a
   dangerous flag forced off). A violating call is denied before forward.

5. **Explicit postconditions** — `postconditions.py`
   Verify-Then-Commit: after the result returns, assert the intended state actually holds via a
   JSONPath-lite path (`$.data.items.0.state`) with `equals / not_equals / in / matches / exists`. A
   violation is surfaced as a Blocked failure, not silently returned. Distinct from a result *guard*
   ("did the server return something dangerous?").

Always-on / pre-existing controls: **guard** (`guard.py` — shell/SQL injection, path traversal, secret
egress, prompt injection; high+critical findings hard-deny), **flow** (`flow.py` — lethal-trifecta
cross-server dataflow), **pinning** (`pinning.py` — TOFU rug-pull quarantine), **auth** (`auth.py` —
OAuth 2.1 Resource Server), **sealing** (`sealing.py` — forward-secure audit).

## Policy precedence (`policy.py`)

```
[capability-DENY if capability_deny_overrides] > explicit tool rule > rules[] > sensitive_actions > server default > mode
```

- **`capability_deny_overrides` (config flag, default `false`)** — when `true`, a capability-scoped DENY
  is *authoritative*: it wins even over a per-tool `action: allow`, so a coarse "no FINANCIAL/DELETE
  tools, ever" net can't be silently allow-listed past. Only DENY (not gate) becomes authoritative.
- **Default (`false`)** preserves the escape hatch: an admin may allow ONE vetted dangerous tool by name
  above a capability deny (`test_explicit_tool_rule_overrides_capability_rule`).
- *Design note:* because the proxy only advertises tools it's configured to expose, a capability deny
  does NOT protect an explicitly-exposed tool unless `capability_deny_overrides` is on. The live
  capability probe surfaces this; the flag is the operator's choice of posture.

## Prove — closed-loop control-effectiveness

**In-process** (`warden prove`, `effectiveness.py`): attacks the interceptor built by
`runtime.build_interceptor` — the SAME construction production uses. The suite is grounded in the
mcp-dast CWE taxonomy (CWE-22/78/89/918) plus Warden-specific violations, and is **config-derived**:
every per-tool arg constraint, postcondition, and capability rule becomes a matching violation. A call
that reaches the benign forwarder is a LEAK. `--html`, `--json`; exit 2 if any attack leaks.

**Live / over-the-wire** (`warden prove --live`, `liveprove.py`): a real MCP client → `warden run` (the
real proxy, over stdio) → a real downstream. Closes two gaps: the real capability classifier (from live
tool schemas) and the real transport. Attacks are generated from the downstream's advertised schemas by
parameter-name heuristics (`url`→SSRF, `path`→traversal, `command`→injection, `query`→SQLi,
`body`→secret-egress), plus capability probes for each config-declared-denied capability (benign,
schema-valid args, so an allowed tool is never mislabeled a leak). Verdict: an MCP error (no canary) =
HELD; a normal result / the target canary = LEAK.

- **Reference vulnerable target** — `warden/targets/reference_target.py`: a deliberately-permissive MCP
  server whose tools return a `WARDEN-CANARY` if reached. Never expose it without Warden in front.
- **Demo config** — `policies/reference.yaml`: fronts the target with every control on +
  `capability_deny_overrides: true` (advertises `delete_record` yet denies DELETE). Live proof = 6
  attacks, 100% held.
- The downstream `cmd` must be a python that exists on PATH (`python3`, not `python`).

## Sign — tamper-evident evidence (`evidence.py`)

An HTML proof anyone can edit proves nothing. `warden prove --sign <audit.jsonl> --cert cert.json`
appends an `evidence` record (`sha256(report)` + summary) to the hash-chained audit log and emits a
certificate binding the report digest to its chain position (`seq` + `record_hash`). With
`--seal-state`, the anchor is also forward-secure. To trust a certificate later:

1. recompute `sha256` of the report file → must equal `report_digest`;
2. `warden audit verify --log <path>` → chain intact;
3. the record at `audit.seq` carries `audit.record_hash`.

## Config schema (keys added/used by these controls)

```yaml
mode: allow | strict
capability_deny_overrides: false        # capability DENY beats a per-tool allow when true
servers:
  <server_id>:
    cmd: ["python3", "-m", "..."]        # downstream launch (stdio)
    tools:
      <tool | glob>:
        action: allow | deny | gate
        arguments:                        # typed argument constraints (control #4)
          <arg>: { type: number, maximum: 100, pattern: "^…", enum: […], email_domain: co.com, items: {…} }
        postconditions:                   # Verify-Then-Commit (control #5)
          - { path: "$.status", equals: "completed" }
constraints:                              # resource boundaries (control #3)
  network:    { domains: ["api.github.com", "*.corp.internal"] }
  filesystem: { roots: ["/workspace"] }
rules:                                    # capability + payload rules (controls #1 / guard)
  - { id: deny_delete, match: { capability: DELETE }, action: deny }
flow:    { sources: […], sinks: […], on_violation: deny }   # lethal-trifecta
approval:{ channel: cli | telegram, … }
auth:    { … }                            # OAuth 2.1 RS (HTTP transport)
```

## Module map (added/changed this line of work)

| Module | Purpose |
|---|---|
| `capabilities.py` | tool → capability set; `dangerous_gained` for the diff gate |
| `capsnapshot.py` | capability baseline snapshot + CI expansion check |
| `boundaries.py` | network-domain / filesystem-root allowlists |
| `argconstraints.py` | typed per-argument value constraints |
| `postconditions.py` | declarative result invariants (Verify-Then-Commit) |
| `runtime.py` | **single source** of control wiring — `build_controls` / `build_interceptor` (prod == proof) |
| `effectiveness.py` | in-process config-derived attack suite + report + HTML |
| `liveprove.py` | over-the-wire proof: schema-derived attacks + capability probes |
| `targets/reference_target.py` | deliberately-vulnerable canary MCP server |
| `report.py` | governance-posture + audit-summary evidence report (HTML/JSON) |
| `evidence.py` | anchor a report into the hash chain → verifiable certificate |
| `policies/reference.yaml` | live-proof demo config (all controls + `capability_deny_overrides`) |

Tests: `tests/test_{capabilities,capsnapshot,boundaries,argconstraints,postconditions,effectiveness,evidence,report,liveprove,capability_policy}.py`. Full suite green; the over-the-wire e2e is gated behind `WARDEN_LIVE=1`.
