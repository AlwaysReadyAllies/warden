"""Tests for evidence anchoring — a proof bound into the tamper-evident chain."""
import json

from warden.audit import AuditLog, digest
from warden import evidence as EV


def _report():
    return {"schema": "warden-effectiveness/v1", "total": 9, "held": 9, "leaked": 0,
            "coverage_pct": 100.0, "cases": [{"id": "x", "verdict": "HELD"}]}


def test_certificate_binds_digest_to_chain(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    audit = AuditLog(log)
    rep = _report()
    cert = EV.anchor_report(audit, "control_effectiveness", rep, EV.effectiveness_summary(rep))
    assert cert["report_digest"] == digest(rep)
    assert cert["kind"] == "control_effectiveness"
    assert cert["summary"] == {"total": 9, "held": 9, "leaked": 0, "coverage_pct": 100.0}
    assert cert["audit"]["seq"] == 1
    assert cert["audit"]["record_hash"]


def test_anchored_record_is_in_the_verified_chain(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    audit = AuditLog(log)
    rep = _report()
    cert = EV.anchor_report(audit, "control_effectiveness", rep)
    ok, msg = AuditLog(log).verify()
    assert ok, msg
    # the record at the certificate's seq carries the certificate's hash and the report digest
    lines = [json.loads(l) for l in open(log)]
    rec = next(r for r in lines if r.get("seq") == cert["audit"]["seq"])
    assert rec["hash"] == cert["audit"]["record_hash"]
    assert rec["report_digest"] == cert["report_digest"]
    assert rec["phase"] == "evidence"


def test_tampering_with_the_report_breaks_the_binding(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    rep = _report()
    cert = EV.anchor_report(AuditLog(log), "control_effectiveness", rep)
    # an attacker edits the proof to claim 0 leaks were actually all-held on a different result
    forged = dict(rep, leaked=5, held=4)
    assert digest(forged) != cert["report_digest"]  # the digest no longer matches the certificate


def test_editing_the_anchored_record_breaks_chain_verify(tmp_path):
    log = str(tmp_path / "audit.jsonl")
    cert = EV.anchor_report(AuditLog(log), "control_effectiveness", _report())
    # an attacker swaps in a digest for a different (forged) report, leaving the stored hash untouched
    raw = open(log).read()
    forged_digest = "sha256:" + "0" * 64
    assert cert["report_digest"] in raw
    with open(log, "w") as fh:
        fh.write(raw.replace(cert["report_digest"], forged_digest))
    ok, _ = AuditLog(log).verify()
    assert not ok  # rewriting the record body is detected by the hash chain
