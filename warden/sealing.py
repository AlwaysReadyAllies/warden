"""Forward-secure sealing for the audit log — the hostile-operator defense.

The audit log's keyless hash chain (``audit.py``) only detects edit-without-rechain: an operator with
write access edits a record, recomputes every hash, and it verifies clean. This module closes that
window using the systemd-journald FSS / Schneier–Kelsey / Ma–Tsudik forward-secure construction, in
pure stdlib (``hashlib`` + ``hmac``), so it adds NO dependency.

HOW IT WORKS (one-way key ratchet):
  * setup: generate a random 32-byte SEED. The seed is the *verification key* — it goes OFF the box
    (to the customer/auditor). The box starts sealing with epoch key K0 = seed.
  * seal: at a sequence boundary, MAC the current chain head under the current epoch key:
        seal = HMAC(K_epoch, "epoch:seq:head").
  * advance: K_{n+1} = H(K_n) (one-way), then OVERWRITE/DELETE K_n on disk. A hostile operator who
    captures the box at epoch T holds only K_T; because H is one-way they cannot recover K_0..K_{T-1},
    so they cannot re-seal any record in an earlier epoch after tampering with it.
  * verify: the holder of the SEED re-derives any past epoch key by ratcheting the seed forward, and
    checks every seal against the chain head that actually exists at that sequence.

WHAT THIS BUYS (state it exactly, never more): every record sealed in an epoch BEFORE the compromise
is **tamper-evident even against a host-level attacker** — the key that could re-seal a forgery no
longer exists on the box. HONEST LIMITS: it does NOT prevent (a) forging records in the *current*
(post-compromise) epoch, or (b) deleting/truncating the log — those need external anchoring
(``AnchorSink`` below + shipping the seed/heads off-box). Symmetric MAC ⇒ the seed holder can also
forge; that is fine because the seed holder is the trusted verifier, not the adversary. For public
(verify-without-forge) verifiability, use the optional Ed25519 signing extra instead (see spec §3.3).
Never claim "tamper-proof" — the correct term is tamper-EVIDENT, for the pre-compromise window.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

_RATCHET_INFO = b"warden-fss-ratchet\x00"
_SEAL_ALG = "hmac-sha256"


def ratchet(key: bytes) -> bytes:
    """One-way key evolution: K_{n+1} = H(info ‖ K_n). Irreversible on the box."""
    return hashlib.sha256(_RATCHET_INFO + key).digest()


def epoch_key(seed: bytes, epoch: int) -> bytes:
    """Re-derive the key for any epoch from the seed (verifier side only)."""
    if epoch < 0:
        raise ValueError("epoch must be >= 0")
    key = seed
    for _ in range(epoch):
        key = ratchet(key)
    return key


def _seal_message(epoch: int, seq: int, head: str) -> bytes:
    return f"{epoch}:{seq}:{head}".encode("utf-8")


def seal(key: bytes, epoch: int, seq: int, head: str) -> str:
    mac = hmac.new(key, _seal_message(epoch, seq, head), hashlib.sha256).hexdigest()
    return f"{_SEAL_ALG}:{mac}"


def verify_seal(seed: bytes, epoch: int, seq: int, head: str, sealed: str) -> bool:
    """Check a seal with the off-box verification seed. Constant-time compare."""
    expected = seal(epoch_key(seed, epoch), epoch, seq, head)
    return hmac.compare_digest(sealed, expected)


class ForwardSecureSealer:
    """Box-side sealer. Holds ONLY the current epoch key; ratchets forward and forgets the past."""

    def __init__(self, state_path: str) -> None:
        self.state_path = state_path
        self._epoch = 0
        self._key: bytes | None = None
        self._load()

    # --- lifecycle -------------------------------------------------------------------------------
    @classmethod
    def setup(cls, state_path: str, seed: bytes | None = None) -> bytes:
        """Initialise sealing state and RETURN the verification seed (caller ships it off-box).

        The seed is intentionally the return value and is NOT stored anywhere by us beyond the live
        key state — the operator must record it off the box, or forward security is pointless.
        """
        if os.path.exists(state_path):
            raise FileExistsError(f"sealer state already exists: {state_path}")
        seed = seed or os.urandom(32)
        cls._write_state(state_path, 0, seed)
        return seed

    def _load(self) -> None:
        if not os.path.exists(self.state_path):
            return
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self._epoch = int(data["epoch"])
        self._key = bytes.fromhex(data["key"])

    @staticmethod
    def _write_state(path: str, epoch: int, key: bytes) -> None:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"epoch": epoch, "key": key.hex()}, fh)
        os.replace(tmp, path)  # atomic; the old key file content is overwritten in place

    @property
    def is_setup(self) -> bool:
        return self._key is not None

    @property
    def epoch(self) -> int:
        return self._epoch

    # --- sealing ---------------------------------------------------------------------------------
    def seal_head(self, seq: int, head: str) -> dict[str, Any]:
        """Seal the current chain head at ``seq``; return a seal record for the audit log."""
        if self._key is None:
            raise RuntimeError("sealer not set up (run ForwardSecureSealer.setup first)")
        return {
            "type": "seal",
            "epoch": self._epoch,
            "seq": seq,
            "head": head,
            "alg": _SEAL_ALG,
            "seal": seal(self._key, self._epoch, seq, head),
        }

    def advance(self) -> int:
        """Ratchet to the next epoch and DESTROY the previous key. Returns the new epoch.

        After this, records sealed in the previous epoch can no longer be re-sealed on this box.
        """
        if self._key is None:
            raise RuntimeError("sealer not set up")
        self._key = ratchet(self._key)
        self._epoch += 1
        self._write_state(self.state_path, self._epoch, self._key)  # overwrites old key on disk
        return self._epoch


class AnchorSink:
    """External-anchor emitter — append each signed head to a place the operator can't rewrite.

    Default = append the seal record to a separate anchor file the operator SHIPS OFF-BOX (email,
    off-box git, a customer webhook). A ``callback`` may be supplied to push it live (e.g. Telegram /
    webhook). The strength of the anchor equals the strength of the destination: an anchor file left
    on the same box is worthless — it must leave the host to defeat truncation/backdating.
    """

    def __init__(self, path: str | None = None, callback=None) -> None:
        self.path = path
        self.callback = callback

    def emit(self, seal_record: dict[str, Any]) -> None:
        line = json.dumps(seal_record, separators=(",", ":"))
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.callback:
            self.callback(seal_record)


__all__ = [
    "ratchet", "epoch_key", "seal", "verify_seal",
    "ForwardSecureSealer", "AnchorSink",
]
