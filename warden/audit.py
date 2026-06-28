"""Tamper-evident audit log — append-only, hash-chained JSONL.

SECURITY decisions (justified):
- DECISION: hash-chain each record as sha256(prev_hash + canonical(record)).
  ALTERNATIVES: plain log (no integrity); per-record signatures (needs key mgmt, heavier).
  WHY: a hash chain detects ANY insertion/deletion/edit with zero key management — the whole
  point of a compliance artifact is "you can prove it wasn't altered after the fact."
  THREAT: an attacker (or a careless operator) who edits the log to hide a malicious tool call;
  re-chaining would require rewriting every subsequent record, which `verify()` catches.
- DECISION: store args/results as sha256 DIGESTS + a truncated preview by default.
  WHY: the audit log records that payments.transfer(amount=500) happened without itself becoming a
  copy of every secret/PII the agent ever touched. THREAT: the audit log as a secondary exfil target.
- DECISION: log the request BEFORE forwarding (intent), and the response after.
  WHY: a blocked or crashing call must still leave a trace — "what did the agent try" is the
  security question, and only logging successes would hide exactly the attacks you care about.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from .schemas import AuditRecord

GENESIS = "0" * 64


def digest(obj: Any) -> str:
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def preview(obj: Any, limit: int = 200) -> str:
    text = json.dumps(obj, sort_keys=True, default=str) if not isinstance(obj, str) else obj
    return text if len(text) <= limit else text[:limit] + "…"


def _canonical(record: dict[str, Any]) -> str:
    # hash everything except the hash field itself
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Append-only hash-chained JSONL. Recovers seq/last-hash on construction."""

    def __init__(self, path: str = "warden_audit.jsonl") -> None:
        self.path = path
        self._seq = 0
        self._last_hash = GENESIS
        self._recover()

    def _recover(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._seq = rec.get("seq", self._seq)
                self._last_hash = rec.get("hash", self._last_hash)

    def append(self, record: dict[str, Any]) -> AuditRecord:
        self._seq += 1
        record = dict(record)
        record["seq"] = self._seq
        record["ts"] = datetime.now(timezone.utc).isoformat()
        record["prev_hash"] = self._last_hash
        record["hash"] = hashlib.sha256(
            (self._last_hash + _canonical(record)).encode("utf-8")
        ).hexdigest()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        self._last_hash = record["hash"]
        return AuditRecord(
            seq=record["seq"],
            ts=record["ts"],
            server=record.get("server", ""),
            tool=record.get("tool", ""),
            decision=record.get("decision", ""),
            args_digest=record.get("args_digest", ""),
            args_preview=record.get("args_preview", ""),
            result_digest=record.get("result_digest"),
            approver=record.get("approver"),
            duration_ms=record.get("duration_ms"),
            flags=record.get("flags", []),
            prev_hash=record["prev_hash"],
            hash=record["hash"],
        )

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain end-to-end; report the first break."""
        if not os.path.exists(self.path):
            return True, "no audit log yet (empty chain is intact)"
        prev = GENESIS
        n = 0
        with open(self.path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                n += 1
                if rec.get("prev_hash") != prev:
                    return False, f"chain break at seq {rec.get('seq')} (line {lineno}): prev_hash mismatch"
                expected = hashlib.sha256((prev + _canonical(rec)).encode("utf-8")).hexdigest()
                if rec.get("hash") != expected:
                    return False, f"record tampered at seq {rec.get('seq')} (line {lineno}): hash mismatch"
                prev = rec["hash"]
        return True, f"audit chain intact: {n} records verified"
