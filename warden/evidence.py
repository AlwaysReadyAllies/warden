"""Evidence anchoring — bind a report (a control-effectiveness proof, a posture report) into the
tamper-evident audit chain so it becomes trustworthy evidence, not just an editable HTML file.

An HTML proof anyone can edit proves nothing. Anchoring writes an `evidence` record —
sha256(report) + a small summary — into the hash-chained log and returns a CERTIFICATE binding the
report digest to its position (seq + record hash) in the chain. To trust a certificate later:

  1. recompute sha256 of the report file and check it equals `report_digest`;
  2. run `warden audit verify --log <path>` to prove the chain (including this record) is intact;
  3. confirm the record at `audit.seq` has `audit.record_hash`.

If the log is sealed (`warden audit setup-keys` + `--seal-state`), the anchor is additionally
forward-secure — a hostile operator cannot rewrite the proof's history without the destroyed epoch key.
"""
from __future__ import annotations

from typing import Any, Mapping

from .audit import digest

SCHEMA = "warden-evidence/v1"


def anchor_report(audit: Any, kind: str, report: Mapping[str, Any],
                  summary: Mapping[str, Any] | None = None) -> dict:
    """Append an evidence record for `report` to the audit chain; return a verifiable certificate."""
    report_digest = digest(report)
    rec = audit.append({
        "phase": "evidence",
        "kind": kind,
        "report_schema": report.get("schema") if isinstance(report, Mapping) else None,
        "report_digest": report_digest,
        "summary": dict(summary or {}),
    })
    return {
        "schema": SCHEMA,
        "kind": kind,
        "report_digest": report_digest,
        "summary": dict(summary or {}),
        "audit": {"seq": rec.seq, "ts": rec.ts, "record_hash": rec.hash, "prev_hash": rec.prev_hash},
        "verify": "recompute sha256 of the report and run `warden audit verify --log <the audit log>`",
    }


def effectiveness_summary(report: Mapping[str, Any]) -> dict:
    return {k: report.get(k) for k in ("total", "held", "leaked", "coverage_pct")}


def posture_summary(report: Mapping[str, Any]) -> dict:
    controls = report.get("controls", {}) if isinstance(report, Mapping) else {}
    return {"mode": controls.get("mode"), "tools": len(report.get("tools", []) or [])}


__all__ = ["SCHEMA", "anchor_report", "effectiveness_summary", "posture_summary"]
