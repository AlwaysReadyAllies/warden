"""Tests for the Telegram approval channel — with a fake Bot API transport (no network)."""
from warden.approval.telegram import TelegramApproval
from warden.schemas import ApprovalOutcome, Decision, ToolCall


class FakeTelegram:
    """Simulates the Telegram Bot API. Queues a callback tap to be returned by getUpdates."""

    def __init__(self, tap=None, error=False):
        self.tap = tap                # "approve" | "deny" | None (no response)
        self.error = error
        self.sent = []
        self._next_update_id = 100
        self._token = None

    def __call__(self, method, params):
        if self.error:
            raise RuntimeError("telegram down")
        if method == "getUpdates":
            # first call (offset -1) returns nothing → base offset 0
            if params.get("offset") == -1:
                return {"ok": True, "result": []}
            if self.tap and self._token:
                upd = {"update_id": self._next_update_id,
                       "callback_query": {"id": "cb1", "data": f"{self._token}:{self.tap}"}}
                self.tap = None  # deliver once
                return {"ok": True, "result": [upd]}
            return {"ok": True, "result": []}
        if method == "sendMessage":
            self.sent.append(params)
            # extract the callback token from the inline keyboard we were sent
            btn = params["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
            self._token = btn.split(":")[0]
            return {"ok": True, "result": {"message_id": 1}}
        if method == "answerCallbackQuery":
            return {"ok": True}
        return {"ok": True, "result": []}


def _chan(fake, timeout=2.0):
    return TelegramApproval("token", "chat1", timeout_sec=timeout, poll_interval=0.01, transport=fake)


_CALL = ToolCall("payments", "transfer", {"amount": 500})
_DEC = Decision(action=None, reason="sensitive", rule_id="sensitive_actions")


def test_approve_tap_returns_approve():
    fake = FakeTelegram(tap="approve")
    assert _chan(fake).request(_CALL, _DEC, []) == ApprovalOutcome.APPROVE
    assert fake.sent and "Warden approval" in fake.sent[0]["text"]


def test_deny_tap_returns_deny():
    assert _chan(FakeTelegram(tap="deny")).request(_CALL, _DEC, []) == ApprovalOutcome.DENY


def test_no_response_times_out_fail_closed():
    assert _chan(FakeTelegram(tap=None), timeout=0.1).request(_CALL, _DEC, []) == ApprovalOutcome.TIMEOUT


def test_api_error_fails_closed():
    assert _chan(FakeTelegram(error=True)).request(_CALL, _DEC, []) == ApprovalOutcome.TIMEOUT


def test_stale_token_is_ignored():
    # a callback for a DIFFERENT token must not approve this request
    class WrongToken(FakeTelegram):
        def __call__(self, method, params):
            if method == "getUpdates" and params.get("offset") != -1:
                return {"ok": True, "result": [{"update_id": 200,
                        "callback_query": {"id": "x", "data": "someoneelse:approve"}}]}
            return super().__call__(method, params)

    assert _chan(WrongToken(tap=None), timeout=0.1).request(_CALL, _DEC, []) == ApprovalOutcome.TIMEOUT


def test_from_config_requires_token_and_chat(monkeypatch):
    import pytest
    monkeypatch.delenv("WARDEN_TELEGRAM_TOKEN", raising=False)
    with pytest.raises(ValueError):
        TelegramApproval.from_config({"chat_id": "c"})  # no token
    monkeypatch.setenv("WARDEN_TELEGRAM_TOKEN", "tok")
    chan = TelegramApproval.from_config({"chat_id": "c", "timeout": 30})
    assert chan.chat_id == "c" and chan.timeout_sec == 30
