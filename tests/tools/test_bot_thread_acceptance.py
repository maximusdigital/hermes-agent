"""R2b acceptance contracts exercised through the production ThreadSync seams."""
from __future__ import annotations

import pytest
from pathlib import Path

from tests.tools.bot_thread_support import envelope, make_sync
from tools.bot_thread_sync import (
    BACKOFF_CAP_SECONDS,
    MAX_ATTEMPTS,
    TTL_SECONDS,
    EvidenceRegistry,
    OutboundStateMachine,
    build_evidence_entries,
)

pytest_plugins = ("tests.tools.test_bot_thread_provider",)


def _audit_rows(sync, conversation_id="conv-1"):
    return [row for row in sync.journal.events(conversation_id) if row.get("kind") == "audit"]


def test_a1_transport_failure_is_never_audited_as_sent(tmp_path):
    def unavailable(_payload):
        raise RuntimeError("offline")

    sync = make_sync(tmp_path, sender_project=lambda *_: "sender-ref", transport=unavailable)
    result = sync.send(envelope())

    assert result.status == "queued"
    assert not [row for row in _audit_rows(sync) if row.get("status") == "sent"]


def test_a2_invalid_target_thread_is_audited_as_contract_breach(world):
    cap = world.cap("neo")
    result = cap.send(target="linus", recipient="linus", message="placeholder", transport="a2a",
                      peer_thread={"platform": "telegram", "thread_id": "invalid"},
                      wire_transport=lambda _payload: pytest.fail("transport must not run"))

    assert (result.status, result.reason) == ("blocked", "envelope_ungueltig")
    conversation_id = cap._sync.journal.conversations()[0]
    rows = _audit_rows(cap._sync, conversation_id)
    assert len(rows) == 1
    assert rows[0]["status"] == "fehlgeschlagen"
    assert rows[0]["reason"] == "envelope_ungueltig"
    assert rows[0]["vertragsbruch"] is True
    assert not ({"text", "chat_id", "source_thread", "target_thread"} & set(rows[0]))


def test_t8_doku_registry_entry_is_never_proven():
    root = Path(__file__).resolve().parents[2]
    entries = build_evidence_entries(root, "rev")
    evidence = EvidenceRegistry("rev", entries, repo_root=root)
    evidence.bind(instance="i", owner_token="o", turn="t")
    assert evidence.attest("audit") is True
    assert evidence.proven("audit") is True
    entries["audit"]["kind"] = "Doku"
    assert evidence.proven("audit") is False


def test_t11_two_transports_keep_the_same_conversation_and_distinct_transport_rows(world):
    cap = world.cap("neo")
    seen = []
    first = cap.send(target="linus", recipient="linus", message="placeholder", transport="a2a",
                     peer_thread=dict(cap._ctx.thread),
                     wire_transport=lambda payload: seen.append(payload))
    second = cap.send(target="linus", message="placeholder", transport="message_agent")

    assert (first.status, second.status) == ("sent", "sent")
    conversation_id = cap._sync.journal.conversations()[0]
    projections = [cap._sync.journal.load_projection(conversation_id, row["message_id"])
                   for row in cap._sync.journal.events(conversation_id) if row.get("kind") == "projection"]
    assert {projection.transport for projection in projections} == {"a2a", "message_agent"}
    assert len({projection.conversation_id for projection in projections}) == 1
    assert len({projection.message_id for projection in projections}) == 2
    assert len(seen) == 1


def test_t13_queue_contract_values_are_pinned(tmp_path):
    assert [OutboundStateMachine._delay(k) for k in range(1, 10)] == [5, 10, 20, 40, 80, 160, 300, 300, 300]
    assert BACKOFF_CAP_SECONDS == 300
    assert MAX_ATTEMPTS == 8
    assert TTL_SECONDS == 86400

    sync = make_sync(tmp_path)
    sync.outbound._queue(envelope(), "out", "target_busy", 0, None)
    row = [r for r in sync.journal.events("conv-1") if r.get("kind") == "eingereiht"][-1]
    assert row["attempts"] == 0


def _t10_roundtrip(world, monkeypatch):
    """A sends via A2A, B dispatches and answers, and A durably recovers that one reply."""
    import asyncio
    import concurrent.futures
    import time
    from types import SimpleNamespace
    from plugins.platforms.a2a import protocol
    from tests.tools import test_bot_thread_provider as provider

    def submit(coro, loop):
        future = concurrent.futures.Future()
        future.set_result(asyncio.run(coro))
        return future

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    current = {}

    def post(url, body, headers, timeout):
        terminal, pending = current["adapter"]._prepare_task(body["params"], "p")
        assert pending is None
        return protocol.jsonrpc_result(body["id"], terminal)

    a2a = provider._a2a_world(world, monkeypatch, post)
    current["adapter"] = provider._receiver_adapter(world, ready=False)
    a = world.cap("neo")
    a2a.a2a_call({"agent": "r", "message": "frage alpha-secret"},
                 agent=SimpleNamespace(_thread_sync_capability=a))
    conversation_id = a._sync.journal.conversations()[0]
    question = a._sync.journal.load_projection(conversation_id, next(
        event["message_id"] for event in a._sync.journal.events(conversation_id)
        if event.get("kind") == "projection"))

    current["adapter"]._loop = object()
    b = world.cap("linus", dispatcher=current["adapter"].dispatch_thread_message)
    b._sync.clock = lambda: time.time() + 30
    b.recover()
    asyncio.run(current["adapter"].send(conversation_id, "antwort beta-secret", metadata={"notify": True}))
    current["adapter"]._completion_pool.shutdown(wait=True)
    asyncio.run(current["adapter"].events[-1].on_complete("completed"))

    a2 = world.cap("neo")
    a2._sync.clock = lambda: time.time() + 120
    assert a2.recover() >= 1
    a2a.a2a_call({"agent": "r", "message": "folgefrage"},
                 agent=SimpleNamespace(_thread_sync_capability=a2))
    b._sync.clock = lambda: time.time() + 150
    assert b.recover() >= 1
    return a2, b, conversation_id, question


def test_t10_a2a_roundtrip_uses_prepare_task_adapter(world, monkeypatch):
    a2, b, conversation_id, _question = _t10_roundtrip(world, monkeypatch)
    assert a2._sync.journal.conversations() == b._sync.journal.conversations() == [conversation_id]
    for home in world.homes.values():
        for record in home.rglob("*"):
            if record.is_file():
                text = record.read_bytes().decode("utf-8", "replace")
                assert "alpha-secret" not in text and "beta-secret" not in text


def test_t10_a2a_roundtrip_reply_keeps_question_parent(world, monkeypatch):
    a2, _b, conversation_id, question = _t10_roundtrip(world, monkeypatch)
    reply = next(event for event in a2._sync.journal.events(conversation_id)
                 if event.get("kind") == "inbound_receipt"
                 and event["message_id"] != question.message_id)
    assert reply["parent_message_id"] == question.message_id


def test_t10_a2a_roundtrip_projects_each_message_once_per_side(world, monkeypatch):
    a2, b, conversation_id, question = _t10_roundtrip(world, monkeypatch)
    for capability in (a2, b):
        rows = [event for event in capability._sync.journal.events(conversation_id)
                if event.get("kind") in {"projection", "inbound_receipt"}
                and (event.get("sender_projection") or event.get("recipient_projection"))]
        assert len(rows) == 3 and len({event["message_id"] for event in rows}) == 3
    reply = next(event for event in a2._sync.journal.events(conversation_id)
                 if event.get("kind") == "inbound_receipt" and event["message_id"] != question.message_id)
    follow_up = next(event for event in a2._sync.journal.events(conversation_id)
                     if event.get("kind") == "projection" and event["message_id"] != question.message_id)
    assert follow_up["parent_message_id"] == reply["message_id"]
