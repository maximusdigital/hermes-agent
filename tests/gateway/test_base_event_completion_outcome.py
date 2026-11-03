"""BasePlatformAdapter fires `event.on_complete` exactly once with an explicitly tracked outcome."""
import asyncio

import pytest

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent
from gateway.session import SessionSource


class _Adapter(BasePlatformAdapter):
    def __init__(self):
        super().__init__(PlatformConfig(enabled=True, typing_indicator=False), Platform.TELEGRAM)
        self.sent = []

    async def connect(self, *, is_reconnect=False):
        return True

    async def disconnect(self):
        pass

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append(content)
        return SendResult(success=True, message_id="m")


def _run(handler):
    adapter, outcomes, calls = _Adapter(), [], []

    async def wrapped(event):
        calls.append(event)
        return await handler(event)

    adapter.set_message_handler(wrapped)
    source = SessionSource(platform=Platform.TELEGRAM, chat_id="c", chat_type="dm", user_id="u")
    event = MessageEvent(text="hi", source=source)
    event.on_complete = lambda outcome: outcomes.append(outcome)
    return adapter, event, outcomes, calls


def test_successful_handler_completes_exactly_once():
    async def ok(event):
        return "answer"

    adapter, event, outcomes, calls = _run(ok)
    asyncio.run(adapter._process_message_background(event, "k"))
    assert outcomes == ["completed"] and len(calls) == 1


def test_raising_handler_is_failed_not_completed_and_a_retry_runs_the_handler_again():
    state = {"n": 0}

    async def flaky(event):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("model exploded")
        return "answer"

    adapter, event, outcomes, calls = _run(flaky)
    asyncio.run(adapter._process_message_background(event, "k"))
    assert outcomes == ["failed"]  # never "completed" (the old code inferred it after leaving the except)
    asyncio.run(adapter._process_message_background(event, "k"))  # recovery re-drives the same event
    assert len(calls) == 2 and outcomes == ["failed", "completed"]


def test_cancellation_is_reported_cancelled_exactly_once():
    async def cancelled(event):
        raise asyncio.CancelledError()

    adapter, event, outcomes, _ = _run(cancelled)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(adapter._process_message_background(event, "k"))
    assert outcomes == ["cancelled"]
