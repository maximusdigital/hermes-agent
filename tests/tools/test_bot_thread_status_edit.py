"""R1a contract: one mirrored Telegram entry is edited for every status change."""
from __future__ import annotations

from dataclasses import asdict

from tools.bot_thread_sync import ThreadEnvelope, mask_text
from tests.tools.bot_thread_support import envelope, make_ctx, make_sync


class StubEgress:
    """Record the platform operations; an edit never silently becomes a send."""

    def __init__(self, *, editable: bool = True):
        self.editable = editable
        self.sends: list[dict] = []
        self.edits: list[tuple[str, dict]] = []

    def send(self, _owner, payload: dict) -> str:
        self.sends.append(dict(payload))
        return "telegram-entry-1"

    def edit(self, _owner, message_id: str, payload: dict) -> dict:
        self.edits.append((message_id, dict(payload)))
        return {"success": self.editable, "message_id": message_id}


def _sync_with_status_egress(tmp_path, egress: StubEgress, **kw):
    """The status edit capability is deliberately separate from initial projection."""
    return make_sync(tmp_path, sender_project=egress.send, sender_edit=egress.edit,
                     transport=lambda _payload: None, **kw)


def test_sender_statuses_edit_the_single_telegram_entry(tmp_path):
    egress = StubEgress()
    sync = _sync_with_status_egress(tmp_path, egress)
    event = envelope()

    assert sync.send(event).status == "sent"
    assert sync.update_status(event, "empfangen").status == "empfangen"
    assert sync.update_status(event, "beantwortet").status == "beantwortet"

    assert len(egress.sends) == 1
    assert [message_id for message_id, _payload in egress.edits] == ["telegram-entry-1", "telegram-entry-1"]
    assert [payload["status"] for _message_id, payload in egress.edits] == ["empfangen", "beantwortet"]


def test_failed_after_sent_edits_instead_of_sending_a_followup(tmp_path):
    egress = StubEgress()
    sync = _sync_with_status_egress(tmp_path, egress)
    event = envelope()

    assert sync.send(event).status == "sent"
    result = sync.update_status(event, "fehlgeschlagen", reason="retry_erschoepft")

    assert result.status == "fehlgeschlagen"
    assert len(egress.sends) == 1
    assert [(message_id, payload["status"]) for message_id, payload in egress.edits] == [
        ("telegram-entry-1", "fehlgeschlagen")]


def test_unsupported_status_edit_is_unvollstaendig_and_never_follows_up(tmp_path):
    egress = StubEgress(editable=False)
    sync = _sync_with_status_egress(tmp_path, egress)
    event = envelope()

    assert sync.send(event).status == "sent"
    result = sync.update_status(event, "empfangen")

    assert (result.status, result.reason) == ("unvollständig", "bearbeiten_nicht_unterstuetzt")
    assert len(egress.sends) == 1
    assert len(egress.edits) == 1
    rows = sync.journal.events(event.conversation_id)
    status = [row for row in rows if row.get("kind") == "sender_status"]
    assert [{key: row[key] for key in ("kind", "conversation_id", "message_id", "spiegel", "status", "unvollstaendig")}
            for row in status] == [{"kind": "sender_status", "conversation_id": event.conversation_id,
                                    "message_id": event.message_id, "spiegel": True,
                                    "status": "empfangen", "unvollstaendig": True}]


def test_spiegel_marker_blocks_dispatch_but_unmarked_conversation_is_processed(tmp_path):
    ctx = make_ctx(tmp_path / "recipient", profile="linus", thread="linus-t", live="live-linus")
    dispatched: list[dict] = []
    projected: list[dict] = []
    masked = mask_text("hello")
    base = envelope(
        source_thread={"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
        target_thread=ctx.thread,
        tenant=ctx.tenant,
        tenant_source="gateway_context",
        text=masked.text,
        masking=masked.proof(),
    )
    mirror = ThreadEnvelope(**{**asdict(base), "spiegel": True})
    sync = make_sync(tmp_path, ctx, name="recipient", project=lambda _owner, payload: projected.append(payload) or "entry-1",
                     process=lambda payload: dispatched.append(payload))

    result = sync.receive(mirror)

    assert (result.status, result.reason) == ("blocked", "spiegel_nicht_ausfuehrbar")
    assert dispatched == []
    assert sync.audit(mirror.conversation_id)[-1]["reason"] == "spiegel_nicht_ausfuehrbar"

    normal = ThreadEnvelope(**{**asdict(base), "message_id": "msg-2", "spiegel": False})
    assert sync.receive(normal).status == "received"
    assert len(dispatched) == 1
