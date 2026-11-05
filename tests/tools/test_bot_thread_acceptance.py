"""R2b acceptance contracts exercised through the production ThreadSync seams."""
from __future__ import annotations

import pytest

from tests.tools.bot_thread_support import envelope, make_sync
from tools.bot_thread_sync import (
    BACKOFF_CAP_SECONDS,
    MAX_ATTEMPTS,
    TTL_SECONDS,
    EvidenceRegistry,
    OutboundStateMachine,
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
    evidence = EvidenceRegistry("rev", {"adapter": {"proven": True, "revision": "rev", "kind": "Doku",
                                                       "file": "tools/bot_thread_sync.py", "line": 1,
                                                       "seam": "x", "sha256": "0" * 64}})
    evidence.bind(instance="i", owner_token="o", turn="t")
    assert evidence.proven("adapter") is False


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


@pytest.mark.xfail(strict=True, reason="bta R2b Befund: acceptance adapter wiring pending")
def test_t10_a2a_roundtrip_uses_prepare_task_adapter():
    """A2A acceptance is kept strict until the adapter can be built from the provider fixture."""
    pytest.fail("adapter wiring not available in the acceptance fixture")
