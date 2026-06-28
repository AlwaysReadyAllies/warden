"""Warden guard module.

Implements the Guard interface to scan outbound tool call arguments for injections
and outbound tool results for prompt injections and secret/PII egress.
"""

import re
import base64
import binascii
import html
import json
import unicodedata
from typing import Any, Iterable, List, Tuple
from warden.schemas import Guard, GuardFinding, ToolCall

# SECURITY: DECISION: We use pre-compiled regexes with a local, maintained corpus instead of an LLM-based classifier.
# ALTERNATIVES: Use an LLM-classifier (e.g., GPT-4o-mini or small local model) to judge input/output safety.
# WHY:
# 1. Latency: Regex matching completes in sub-milliseconds, whereas an LLM-classifier adds 100ms-1000ms latency.
# 2. Determinism: Regex rules are 100% deterministic, whereas LLMs suffer from hallucination and prompt-evasion.
# 3. Zero-egress: Regex checks run locally with zero network calls, preventing sensitive payloads from leaking to external model providers.
# THREAT: LLM classifier bypass via prompt-injection-on-classifier, latency degradation, and credentials leakage to third-party LLMs.

# SECURITY: DECISION: Redact vs Block policy:
# - Outbound Arguments (scan_args): Represent active exploit attempts (shell/SQL injection, path traversal). We flag them as high/critical severity so the PolicyEngine can block them (fail closed).
# - Outbound Results (scan_result): Represent content retrieved from external tools. We redact secrets/PII in-place and strip prompt injections to neutralize threats without crashing the entire agent workflow, preserving system availability while ensuring security.
# THREAT: Local machine compromise via argument injection, and LLM controller hijack via poisoned tool results.

# SECURITY: DECISION: Lethal-Trifecta Threat Model.
# The lethal-trifecta consists of:
# 1. Indirect Prompt Injection (malicious data retrieved from a tool).
# 2. Privileged Tool Access (agent can run bash, filesystem, sql tools).
# 3. Missing Guardrails (no parameter/result validation).
# Warden blocks this by intercepting arguments (scan_args) and sanitizing results (scan_result) to break the compromise chain.

class WardenGuard:
    MAX_SCAN_CHARS = 32768
    MAX_RECURSION_DEPTH = 20

    ZERO_WIDTH_CHARS = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060\u180e"), None)
    BIDI_OVERRIDE_CHARS = dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"), None)

    # 25+ real-world prompt injection patterns (this is the moat)
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
        r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|guidelines|rules)",
        r"(?i)system\s+override",
        r"(?i)bypass\s+(?:safety|authorization|security|filters)",
        r"(?i)switch\s+to\s+developer\s+mode",
        r"(?i)enter\s+developer\s+mode",
        r"(?i)you\s+are\s+now\s+(?:a|an|in|in\s+developer)\s+(?:uncensored|developer|role|dan\b|jailbroken)",
        r"(?i)\bDAN\b\s+mode",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)ignore\s+everything\s+(?:before|after)",
        r"(?i)assume\s+the\s+role\s+of",
        r"(?i)stop\s+following\s+instructions",
        r"(?i)override\s+(?:security|safety)\s+(?:guidelines|rules|policies)",
        r"(?i)new\s+instructions\s*:",
        r"(?i)terminate\s+current\s+task\s+and",
        r"(?i)ignore\s+the\s+system\s+prompt",
        r"(?i)<system\s*override>",
        r"(?i)\[system\s*override\]",
        r"(?i)assistant\s*:\s*override",
        r"(?i)role\s*:\s*system",
        r"(?i)you\s+must\s+now\s+forget\s+your",
        r"(?i)execute\s+the\s+following\s+command\s*:",
        r"(?i)please\s+output\s+the\s+entire\s+instructions",
        r"(?i)reveal\s+(?:your\s+)?system\s+(?:prompt|instructions)",
        r"(?i)you\s+are\s+no\s+longer\s+an\s+AI\s+assistant"
    ]

    SECRET_PII_PATTERNS = {
        "private_key": r"-----BEGIN\s+(?:[A-Z0-9\s_]+)?PRIVATE\s+KEY-----",
        "jwt": r"\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b",
        "aws_key": r"\b(AKIA[0-9A-Z]{16})\b",
        # SECURITY: provider keys carry a recognizable prefix, so they can be caught BARE (no key= assignment)
        #   with ~zero false positives — covers the common case of a tool returning a raw token. An
        #   adversarial test showed a bare `sk-...` slipped past the assignment-gated api_key rule.
        "provider_key": r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_\-]{20,}|glpat-[A-Za-z0-9_\-]{16,})\b",
        "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        # Check assignments like password="abc" or password = 'abc' or password: abc
        "password": r"(?i)\bpassword\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.\@\#\$\%\^\&\*\(\)\+]{6,})[\"']?",
        # Catch standard API keys / bearer tokens
        "api_key": r"(?i)\b(?:api[_-]?key|secret|auth[_-]?token|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{16,})[\"']?"
    }

    # SECURITY: DECISION: All rule matching runs over bounded, canonical variants of the input.
    # WHY: Attackers can hide the same payload behind NFKC-normalizable glyphs, zero-width splits,
    # HTML/URL/base64/hex encodings, JSON strings, or bytes. Canonicalization makes those equivalent
    # before matching, while MAX_SCAN_CHARS and MAX_RECURSION_DEPTH cap regex work to avoid ReDoS.
    # FALSE POSITIVES: Decoded variants only add findings when the decoded text matches the same
    # high-confidence security rules; benign encoded text remains clean.
    def _canonicalize_text(self, content: str) -> str:
        content = content[:self.MAX_SCAN_CHARS]
        content = unicodedata.normalize("NFKC", content)
        content = content.translate(self.ZERO_WIDTH_CHARS)
        content = content.translate(self.BIDI_OVERRIDE_CHARS)
        return content

    def _as_text(self, val: Any) -> str:
        if isinstance(val, bytes):
            return val[:self.MAX_SCAN_CHARS].decode("utf-8", errors="ignore")
        return str(val)

    def _decode_variants(self, content: str) -> Iterable[tuple[str, str]]:
        canonical = self._canonicalize_text(content)
        yield "canonical", canonical

        decoded = html.unescape(canonical)
        decoded = self._canonicalize_text(decoded)
        if decoded != canonical:
            yield "html_entity", decoded

        decoded = self._canonicalize_text(html.unescape(re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), canonical)))
        if decoded != canonical:
            yield "url_encoding", decoded

        tokens = re.findall(r"\b[A-Za-z0-9+/=_-]{12,}\b", canonical)
        for token in tokens[:32]:
            padded = token + ("=" * (-len(token) % 4))
            for altchars in (None, b"-_"):
                try:
                    raw = base64.b64decode(padded.encode("ascii"), altchars=altchars, validate=False)
                    text = raw.decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                if text and sum(ch.isprintable() or ch.isspace() for ch in text) / max(len(text), 1) > 0.85:
                    yield "base64", self._canonicalize_text(text)

        for token in re.findall(r"\b(?:0x)?[0-9a-fA-F]{16,}\b", canonical)[:32]:
            hex_text = token[2:] if token.lower().startswith("0x") else token
            if len(hex_text) % 2:
                continue
            try:
                text = bytes.fromhex(hex_text).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            yield "hex", self._canonicalize_text(text)

    def _iter_values(self, val: Any, path: str, depth: int = 0) -> Iterable[tuple[str, str]]:
        if depth > self.MAX_RECURSION_DEPTH:
            return
        if isinstance(val, dict):
            for k, v in val.items():
                yield from self._iter_values(k, f"{path}.<key>", depth + 1)
                yield from self._iter_values(v, f"{path}.{k}", depth + 1)
        elif isinstance(val, (list, tuple, set, frozenset)):
            for idx, item in enumerate(val):
                yield from self._iter_values(item, f"{path}[{idx}]", depth + 1)
        else:
            text = self._as_text(val)
            yield path, text
            stripped = text.strip()
            if stripped[:1] in ("{", "[") and len(stripped) <= self.MAX_SCAN_CHARS:
                try:
                    parsed = json.loads(stripped)
                except (TypeError, ValueError):
                    return
                yield from self._iter_values(parsed, f"{path}<json>", depth + 1)

    def _safe_search(self, pattern: str, content: str):
        return re.search(pattern, content[:self.MAX_SCAN_CHARS])

    def _safe_sub(self, pattern: str, repl, content: str) -> str:
        prefix = content[:self.MAX_SCAN_CHARS]
        suffix = content[self.MAX_SCAN_CHARS:]
        return re.sub(pattern, repl, prefix) + suffix

    def _extract_span(self, content: str, pattern: str) -> str:
        m = self._safe_search(pattern, content)
        if m:
            matched = m.group(0)
            # Truncate to protect audit log from full exfil
            return matched[:100] + "..." if len(matched) > 100 else matched
        return ""

    def _has_pattern(self, content: str, pattern: str) -> tuple[bool, str, str]:
        for source, variant in self._decode_variants(content):
            if self._safe_search(pattern, variant):
                return True, source, self._extract_span(variant, pattern)
        return False, "", ""

    def scan_args(self, call: ToolCall) -> List[GuardFinding]:
        """Scans outbound tool call arguments for injection attacks."""
        findings = []
        for key, val_str in self._iter_values(call.args, "args"):

            # 1. Path Traversal
            # SECURITY: DECISION: Match dot-dot-slash variations and common absolute paths.
            # ALTERNATIVES: Path.resolve check.
            # WHY: Path.resolve requires accessing the real filesystem; regex matching on arguments is faster, local, and works before the path is ever passed to filesystem APIs.
            # THREAT: Local File Inclusion (LFI) / arbitrary directory read.
            traversal_pattern = r'(?:\.\.[/\\]|%2e%2e%2f|%2e%2e%5c|%2e%2e\/|%2e%2e\\|/etc/passwd|/etc/shadow|/etc/hosts)'
            found, source, span = self._has_pattern(val_str, traversal_pattern)
            if found:
                findings.append(GuardFinding(
                    kind="path_traversal",
                    severity="high",
                    detail=f"Path traversal pattern detected in argument '{key}' via {source}",
                    span=span
                ))

            # 2. Shell Injection
            # SECURITY: DECISION: We avoid simple metacharacter matching (like single semicolons or pipes) to prevent high false positive rates, but flag metacharacters when followed by commands or combined with execution constructs (&&, ||, backticks, $()).
            # ALTERNATIVES: Block all semicolons or pipes.
            # WHY: High false positives render the guard unusable. Narrowing to command keywords prevents actual shell exploitation.
            # THREAT: Remote command execution (RCE) via command chaining or subshells.
            shell_pattern = r'(?i)(?:[;&|`]\s*(?:cat|rm|sh|bash|curl|wget|echo|id|whoami|uname|sleep|ping|nc|python|perl|ruby|php|touch|mkdir|chmod|chown|ls|cd|pwd|rmdir|env|export|set)\b|\$\(|\$\{|\|\||&&|\`[\w\s.-]+\`|>\s*[\w/.-]+|>>\s*[\w/.-]+|<\s*[\w/.-]+)'
            found, source, span = self._has_pattern(val_str, shell_pattern)
            if found:
                findings.append(GuardFinding(
                    kind="shell_injection",
                    severity="critical",
                    detail=f"Shell injection metacharacter/operator detected in argument '{key}' via {source}",
                    span=span
                ))

            # 2b. Unambiguously-destructive BARE commands (no metacharacter needed)
            # SECURITY: DECISION: Flag a small set of irreversibly-destructive commands even when they
            #   appear bare (no ;/|/&& chaining) — rm -rf, mkfs, dd to a device, fork bombs, chmod -R on /,
            #   overwriting block devices, DROP/TRUNCATE without quotes.
            # ALTERNATIVES: rely only on the metacharacter-gated shell_pattern (Antigravity's original).
            # WHY: an adversarial test showed `rm -rf /` passed BOTH layers — an explicit tool `allow`
            #   short-circuits rules[] (documented precedence), leaving the guard as the only backstop,
            #   and the original pattern required a leading metacharacter so a bare `rm -rf` was missed.
            #   These specific tokens have ~zero natural-language false-positive risk, unlike a lone `;`.
            # THREAT: destructive RCE via a tool that legitimately accepts a command/path argument.
            destructive_pattern = (
                r'(?i)(?:\brm\s+-[rf]{1,2}\b|\br\s*m\s+-\s*r\s*f\b|\bmkfs(?:\.\w+)?\b|\bdd\s+if=|>\s*/dev/[sh]d[a-z]|'
                r'\bchmod\s+-R\s+0?777\s+/|:\(\)\s*\{\s*:\|:&\s*\}|\bDROP\s+(?:TABLE|DATABASE)\b|'
                r'\bTRUNCATE\s+TABLE\b|\bshutdown\b|\breboot\b)'
            )
            found, source, span = self._has_pattern(val_str, destructive_pattern)
            if found:
                findings.append(GuardFinding(
                    kind="destructive_command",
                    severity="critical",
                    detail=f"Irreversibly-destructive command detected in argument '{key}' via {source}",
                    span=span
                ))

            # 3. SQL Injection
            # SECURITY: DECISION: Target SQL query structures like UNION SELECT, OR tautologies, and SQL comments.
            # ALTERNATIVES: Check every quote.
            # WHY: A quote alone is extremely common in natural language (false positives). Matching query structures blocks SQL injection without breaking normal text argument pass-through.
            # THREAT: Database schema theft or manipulation.
            sql_pattern = r'(?i)(?:UNION\s+(?:ALL\s+)?SELECT|OR\s+\d+=\d+|OR\s+\'[^\\\']\'\s*=\s*\'[^\\\']\'|--\s*$|--\s+\w+|\/\*.*?\*\/)'
            found, source, span = self._has_pattern(val_str, sql_pattern)
            if found:
                findings.append(GuardFinding(
                    kind="sql_injection",
                    severity="high",
                    detail=f"SQL injection syntax detected in argument '{key}' via {source}",
                    span=span
                ))

            # 4. Prompt injection in outbound tool inputs.
            # SECURITY: DECISION: Requests to tools can carry poisoned text that later returns as trusted
            # result content. Blocking prompt-injection phrases at argument time closes that pass-through
            # gap, and the patterns are explicit enough to keep ordinary prose false positives near zero.
            # THREAT: A malicious nested/encoded argument is stored by a tool and returned unredacted to
            # the controller in a later step.
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                found, source, span = self._has_pattern(val_str, pattern)
                if found:
                    findings.append(GuardFinding(
                        kind="prompt_injection",
                        severity="high",
                        detail=f"Prompt injection pattern detected in argument '{key}' via {source}",
                        span=span
                    ))
                    break

            # 5. Secret egress in outbound tool inputs.
            # SECURITY: DECISION: Provider-prefixed keys and assignment-shaped tokens are low-ambiguity
            # secrets. Catching them in arguments prevents tool calls from exfiltrating credentials.
            # THREAT: Credential leakage through write, network, shell, or database tools.
            for name, pattern in self.SECRET_PII_PATTERNS.items():
                if name in ("email", "ssn"):
                    continue
                found, source, _span = self._has_pattern(val_str, pattern)
                if found:
                    findings.append(GuardFinding(
                        kind="secret_egress",
                        severity="critical",
                        detail=f"Potential sensitive egress of {name} detected in argument '{key}' via {source}",
                        span=f"<{name} matched>"
                    ))
                    break

        return findings

    def scan_result(self, content: Any) -> Tuple[Any, List[GuardFinding]]:
        """Scans returned content recursively to strip prompt injections and redact secrets/PII."""
        findings = []
        redacted_content = self._scan_and_redact(content, findings)
        return redacted_content, findings

    def _scan_and_redact(self, val: Any, findings: List[GuardFinding]) -> Any:
        if isinstance(val, str):
            redacted_str = val
            decoded_prompt_hit = False
            decoded_secret_hit = False

            # (a) Check Prompt Injection (Strip/Replace)
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                def prompt_repl(match):
                    span_text = match.group(0)
                    findings.append(GuardFinding(
                        kind="prompt_injection",
                        severity="high",
                        detail="Potential prompt injection pattern detected in returned content",
                        span=span_text[:100] + "..." if len(span_text) > 100 else span_text
                    ))
                    return "[STRIPPED_PROMPT_INJECTION]"
                
                redacted_str = self._safe_sub(pattern, prompt_repl, redacted_str)
                for source, variant in self._decode_variants(redacted_str):
                    if self._safe_search(pattern, variant):
                        decoded_prompt_hit = True
                        findings.append(GuardFinding(
                            kind="prompt_injection",
                            severity="high",
                            detail=f"Encoded prompt injection pattern detected in returned content via {source}",
                            span=self._extract_span(variant, pattern)
                        ))
                        break
                if decoded_prompt_hit:
                    break

            # (b) Check Secret / PII egress (Redact)
            for name, pattern in self.SECRET_PII_PATTERNS.items():
                def secret_repl(match):
                    findings.append(GuardFinding(
                        kind="secret_egress",
                        severity="critical" if name in ("private_key", "jwt", "api_key", "aws_key", "provider_key") else "high",
                        detail=f"Potential sensitive egress of {name} detected",
                        span=f"<{name} matched>"  # SECURITY: Never log the actual secret in findings!
                    ))
                    return f"[REDACTED_{name.upper()}]"
                
                redacted_str = self._safe_sub(pattern, secret_repl, redacted_str)
                for source, variant in self._decode_variants(redacted_str):
                    if self._safe_search(pattern, variant):
                        decoded_secret_hit = True
                        findings.append(GuardFinding(
                            kind="secret_egress",
                            severity="critical" if name in ("private_key", "jwt", "api_key", "aws_key", "provider_key") else "high",
                            detail=f"Encoded sensitive egress of {name} detected via {source}",
                            span=f"<{name} matched>"
                        ))
                        break
                if decoded_secret_hit:
                    break

            if decoded_secret_hit:
                return "[REDACTED_ENCODED_SECRET]"
            if decoded_prompt_hit:
                return "[STRIPPED_PROMPT_INJECTION]"

            return redacted_str

        elif isinstance(val, dict):
            new_dict = {}
            for k, v in val.items():
                new_dict[k] = self._scan_and_redact(v, findings)
            return new_dict

        elif isinstance(val, list):
            return [self._scan_and_redact(item, findings) for item in val]

        elif isinstance(val, tuple):
            return tuple(self._scan_and_redact(item, findings) for item in val)

        elif isinstance(val, bytes):
            return self._scan_and_redact(self._as_text(val), findings)

        else:
            return val
