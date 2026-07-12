"""Tests for forward-secure sealing + its audit-log integration (hostile-operator defense)."""
import hashlib
import json

import pytest

from warden.audit import AuditLog, _canonical
from warden.sealing import (
    AnchorSink, ForwardSecureSealer, epoch_key, ratchet, seal, verify_seal,
)


# --- crypto core ---------------------------------------------------------------------------------

def test_ratchet_is_one_way_and_deterministic():
    k = b"\x01" * 32
    assert ratchet(k) == ratchet(k)          # deterministic
    assert ratchet(k) != k                    # moves
    assert epoch_key(k, 0) == k
    assert epoch_key(k, 3) == ratchet(ratchet(ratchet(k)))


def test_seal_verifies_with_seed_and_rejects_tampering():
    seed = b"\x02" * 32
    s = seal(epoch_key(seed, 2), 2, 10, "HEADHASH")
    assert verify_seal(seed, 2, 10, "HEADHASH", s)
    assert not verify_seal(seed, 2, 10, "OTHERHEAD", s)   # different head
    assert not verify_seal(seed, 3, 10, "HEADHASH", s)    # wrong epoch
    assert not verify_seal(b"\x03" * 32, 2, 10, "HEADHASH", s)  # wrong seed


def test_forward_security_after_advance(tmp_path):
    state = str(tmp_path / "seal_state.json")
    seed = ForwardSecureSealer.setup(state)
    box = ForwardSecureSealer(state)
    assert box.epoch == 0
    box.seal_head(5, "H0")
    box.advance()                              # destroy K0
    assert box.epoch == 1
    # the box can no longer produce K0 — its stored key is K1, and K0 is unrecoverable from it
    assert box._key != seed
    assert box._key == ratchet(seed)
    # a verifier with the seed can still check the old epoch-0 seal
    old_seal = seal(epoch_key(seed, 0), 0, 5, "H0")
    assert verify_seal(seed, 0, 5, "H0", old_seal)


def test_setup_refuses_to_clobber(tmp_path):
    state = str(tmp_path / "s.json")
    ForwardSecureSealer.setup(state)
    with pytest.raises(FileExistsError):
        ForwardSecureSealer.setup(state)


# --- audit integration ---------------------------------------------------------------------------

def _seed_log(tmp_path, anchor_path=None):
    state = str(tmp_path / "seal_state.json")
    seed = ForwardSecureSealer.setup(state)
    sealer = ForwardSecureSealer(state)
    anchor = AnchorSink(path=anchor_path) if anchor_path else None
    log = AuditLog(str(tmp_path / "audit.jsonl"), sealer=sealer, anchor=anchor)
    return log, seed


def test_sealed_log_verifies(tmp_path):
    log, seed = _seed_log(tmp_path)
    log.append({"server": "s", "tool": "t", "decision": "allow"})
    log.seal_now()                              # seal epoch 0, advance to 1
    log.append({"server": "s", "tool": "u", "decision": "deny"})
    ok, msg = log.verify(seed=seed)
    assert ok, msg
    assert "forward-secure" in msg


def test_no_sealer_is_backward_compatible(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))   # no sealer
    log.append({"server": "s", "tool": "t", "decision": "allow"})
    assert log.seal_now() is None
    ok, _ = log.verify()
    assert ok


def test_HOSTILE_OPERATOR_edit_plus_full_rechain_is_detected(tmp_path):
    """The defining test: an operator edits a record in a SEALED past epoch and rechains the ENTIRE
    file so the keyless chain re-verifies. With the seed, the forward-secure seal still catches it."""
    path = str(tmp_path / "audit.jsonl")
    log, seed = _seed_log(tmp_path)
    log.append({"server": "pay", "tool": "transfer", "decision": "gate", "amount": 5})
    log.append({"server": "pay", "tool": "transfer", "decision": "gate", "amount": 500})
    log.seal_now()                              # seals the head over both records; K0 now destroyed

    # sanity: honest verify passes
    assert AuditLog(path).verify(seed=seed)[0]

    # HOSTILE OPERATOR: rewrite the amount on seq 1, then recompute the WHOLE hash chain.
    lines = [json.loads(l) for l in open(path) if l.strip()]
    prev = "0" * 64
    for rec in lines:
        if rec.get("type") == "seal":
            continue
        if rec.get("amount") == 500:
            rec["amount"] = 5  # tamper: shrink the flagged transfer
        rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k != "hash"}
        rec["hash"] = hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
        prev = rec["hash"]
    with open(path, "w") as fh:
        for rec in lines:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    tampered = AuditLog(path)
    # keyless verify is FOOLED (they rechained) — this is exactly the documented gap
    assert tampered.verify()[0] is True
    # but forward-secure verify with the seed CATCHES it
    ok, msg = tampered.verify(seed=seed)
    assert not ok and ("history was rewritten" in msg or "does not verify" in msg)


def test_operator_cannot_reforge_seal_after_epoch_advanced(tmp_path):
    """Even if the operator also rewrites the seal record's head to match their tampered chain, they
    cannot produce a valid seal because the epoch key was destroyed."""
    path = str(tmp_path / "audit.jsonl")
    log, seed = _seed_log(tmp_path)
    log.append({"server": "pay", "tool": "transfer", "amount": 500})
    log.seal_now()

    lines = [json.loads(l) for l in open(path) if l.strip()]
    prev = "0" * 64
    new_head = None
    for rec in lines:
        if rec.get("type") == "seal":
            continue
        rec["amount"] = 5
        rec["prev_hash"] = prev
        body = {k: v for k, v in rec.items() if k != "hash"}
        rec["hash"] = hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
        prev = new_head = rec["hash"]
    for rec in lines:                            # forge the seal's head to match
        if rec.get("type") == "seal":
            rec["head"] = new_head               # but the seal MAC still references the old key
    with open(path, "w") as fh:
        for rec in lines:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    ok, msg = AuditLog(path).verify(seed=seed)
    assert not ok and "does not verify" in msg   # seal MAC can't be reforged → caught


def test_anchor_sink_writes_off_box_copy(tmp_path):
    anchor_path = str(tmp_path / "anchor.jsonl")
    log, seed = _seed_log(tmp_path, anchor_path=anchor_path)
    log.append({"server": "s", "tool": "t"})
    rec = log.seal_now()
    anchored = [json.loads(l) for l in open(anchor_path) if l.strip()]
    assert len(anchored) == 1 and anchored[0]["seal"] == rec["seal"]
