"""Telegram approval channel — human-in-the-loop gating for headless / HTTP deployments.

``CliApproval`` needs ``/dev/tty``; in ``--http`` or any headless run there is no terminal, so every
GATE fails closed (unusable). This channel sends the pending call to a Telegram chat with inline
[Approve]/[Deny] buttons and waits (bounded) for the operator's tap — so gates work from a phone.

Fail-closed by construction: any timeout, API error, or missing config ⇒ ``TIMEOUT`` (blocked).
The bot token comes from the environment/config, never hard-coded. Requires the ``telegram`` extra
(httpx); the transport is injectable for tests so no network is needed to verify the logic.

SECURITY: the callback token is random per request and matched exactly, so a stale or unrelated
button press cannot approve a different pending call. Old updates are skipped via the initial offset.
"""
from __future__ import annotations

import os
import time
from typing import Any, Callable

from ..schemas import ApprovalOutcome, Decision, GuardFinding, ToolCall

_API = "https://api.telegram.org/bot{token}/{method}"


def _default_transport(token: str) -> Callable[[str, dict], dict]:
    import httpx  # lazy

    def call(method: str, params: dict) -> dict:
        resp = httpx.post(_API.format(token=token, method=method), json=params, timeout=15.0)
        resp.raise_for_status()
        return resp.json()

    return call


class TelegramApproval:
    """Implements the ApprovalChannel protocol via the Telegram Bot API (polling)."""

    def __init__(self, bot_token: str, chat_id: str | int, timeout_sec: float = 120.0,
                 poll_interval: float = 2.0, transport: Callable[[str, dict], dict] | None = None) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout_sec = timeout_sec
        self.poll_interval = poll_interval
        self._call = transport or _default_transport(bot_token)

    @classmethod
    def from_config(cls, raw: dict[str, Any], *, timeout_sec: float = 120.0) -> "TelegramApproval":
        # token from env by name (never store it in the policy file) or inline as a fallback
        token = os.environ.get(raw.get("bot_token_env", "WARDEN_TELEGRAM_TOKEN"), "") or raw.get("bot_token", "")
        chat_id = raw.get("chat_id", "")
        if not token or not chat_id:
            raise ValueError("telegram approval needs a bot token (env WARDEN_TELEGRAM_TOKEN) and chat_id")
        return cls(token, chat_id, timeout_sec=float(raw.get("timeout", timeout_sec)),
                   poll_interval=float(raw.get("poll_interval", 2.0)))

    def _token(self) -> str:
        return os.urandom(8).hex()

    def request(self, call: ToolCall, decision: Decision, findings: list[GuardFinding]) -> ApprovalOutcome:
        token = self._token()
        try:
            # skip any updates that predate this request so an old tap can't answer it
            base_offset = self._latest_offset()
            self._send_prompt(call, decision, findings, token)
            deadline = time.monotonic() + self.timeout_sec
            offset = base_offset
            while time.monotonic() < deadline:
                updates = self._get_updates(offset)
                for upd in updates:
                    offset = max(offset, int(upd.get("update_id", offset)) + 1)
                    outcome = self._match(upd, token)
                    if outcome is not None:
                        return outcome
                time.sleep(self.poll_interval)
            return ApprovalOutcome.TIMEOUT  # no tap in time → fail closed
        except Exception:
            return ApprovalOutcome.TIMEOUT  # any API/network error → fail closed

    # --- Telegram plumbing -----------------------------------------------------------------------
    def _latest_offset(self) -> int:
        data = self._call("getUpdates", {"timeout": 0, "offset": -1})
        results = data.get("result", []) if data.get("ok", True) else []
        return (int(results[-1]["update_id"]) + 1) if results else 0

    def _send_prompt(self, call, decision, findings, token) -> None:
        flags = ", ".join(sorted({f.kind for f in findings})) or "none"
        text = (f"🛡️ *Warden approval*\n`{call.qualified}`\n"
                f"reason: {decision.reason or decision.rule_id or 'sensitive action'}\n"
                f"guard flags: {flags}")
        keyboard = {"inline_keyboard": [[
            {"text": "✅ Approve", "callback_data": f"{token}:approve"},
            {"text": "⛔ Deny", "callback_data": f"{token}:deny"},
        ]]}
        self._call("sendMessage", {"chat_id": self.chat_id, "text": text,
                                   "parse_mode": "Markdown", "reply_markup": keyboard})

    def _get_updates(self, offset: int) -> list[dict]:
        data = self._call("getUpdates", {"timeout": 0, "offset": offset,
                                         "allowed_updates": ["callback_query"]})
        return data.get("result", []) if data.get("ok", True) else []

    def _match(self, update: dict, token: str) -> ApprovalOutcome | None:
        cq = update.get("callback_query")
        if not cq:
            return None
        data = str(cq.get("data", ""))
        if not data.startswith(token + ":"):
            return None  # a tap for a different pending request — ignore
        # best-effort acknowledge (don't fail the decision if this errors)
        try:
            self._call("answerCallbackQuery", {"callback_query_id": cq.get("id", "")})
        except Exception:
            pass
        return ApprovalOutcome.APPROVE if data.endswith(":approve") else ApprovalOutcome.DENY


__all__ = ["TelegramApproval"]
