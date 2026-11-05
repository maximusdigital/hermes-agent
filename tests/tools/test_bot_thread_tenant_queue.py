"""R1e contract coverage through the production ThreadSync seam."""
from __future__ import annotations

import time

from tests.tools.bot_thread_support import ATTEST, envelope, make_sync
from tools.bot_thread_sync import mask_text


def _masked(**over):
    masked = mask_text("hello")
    return envelope(text=masked.text, masking=masked.proof(), **over)


def test_missing_tenant_evidence_blocks_outbound_and_inbound_as_tenant_unknown(tmp_path):
    out = make_sync(tmp_path / "out")
    incoming = make_sync(tmp_path / "in", name="in")
    for sync in (out, incoming):
        sync.evidence.entries.pop("tenant")
        sync.attest(*ATTEST)
    assert out.send(envelope()).reason == "tenant_unbekannt"
    assert incoming.receive(_masked(tenant="tenant-1", tenant_source="kontext",
                                    target_thread=dict(incoming.auth.thread))).reason == "tenant_unbekannt"


def test_new_message_without_tenant_records_kontext_source(tmp_path):
    sync = make_sync(tmp_path, sender_project=lambda *_: "projected", transport=lambda *_: None)
    assert sync.send(envelope()).status == "sent"
    assert sync.journal.load_projection("conv-1", "msg-1").tenant_source == "kontext"


def test_legacy_gateway_context_projection_retries_unchanged(tmp_path):
    sync = make_sync(tmp_path, sender_project=lambda *_: "projected", transport=lambda *_: None)
    sync.attest("a2a_ids")
    stored = _masked(tenant="tenant-1", tenant_source="gateway_context")
    sync.journal.save_projection(stored)
    sync.journal.append("conv-1", {"kind": "queue", "direction": "out", "conversation_id": "conv-1",
                                    "message_id": "msg-1", "attempts": 0, "reason": "offline",
                                    "dispatch": "local", "dispatch_kind": "a2a", "next_at": 0,
                                    "enqueued_at": time.time()})
    assert sync.retry_due(now=time.time())[0].status == "sent"
    assert sync.journal.load_projection("conv-1", "msg-1").tenant_source == "gateway_context"


def test_new_queue_events_use_contract_names_after_retry_success(tmp_path):
    up = [0]
    def transport(_payload):
        if up[0] < 2:
            up[0] += 1
            raise RuntimeError("offline")
    sync = make_sync(tmp_path, sender_project=lambda *_: "projected", transport=transport)
    assert sync.send(envelope()).status == "queued"
    row = next(row for row in reversed(sync.journal.events("conv-1")) if row["kind"] == "queue")
    assert sync.retry_due(now=row["next_at"] + 1)[0].status == "queued"
    row = next(row for row in reversed(sync.journal.events("conv-1")) if row["kind"] == "queue")
    assert sync.retry_due(now=row["next_at"] + 1)[0].status == "sent"
    kinds = [row["kind"] for row in sync.journal.events("conv-1")]
    assert {"eingereiht", "versuch", "bestaetigt"} <= set(kinds)
    assert not ({"queue", "outbound_done"} & set(kinds))


def test_legacy_queue_recovers_and_legacy_done_is_not_resent(tmp_path):
    calls = []
    sync = make_sync(tmp_path, sender_project=lambda *_: "projected", transport=lambda *_: calls.append(1))
    sync.attest("a2a_ids")
    stored = _masked(tenant="tenant-1", tenant_source="gateway_context")
    sync.journal.save_projection(stored)
    legacy = {"kind": "queue", "direction": "out", "conversation_id": "conv-1", "message_id": "msg-1",
              "attempts": 0, "reason": "offline", "dispatch": "local", "dispatch_kind": "a2a",
              "next_at": 0, "enqueued_at": time.time()}
    sync.journal.append("conv-1", legacy)
    assert sync.retry_due(now=time.time())[0].status == "sent"
    assert "bestaetigt" in [r["kind"] for r in sync.journal.events("conv-1")]
    sync.journal.append("conv-1", {"kind": "outbound_done", "conversation_id": "conv-1", "message_id": "other"})
    assert sync.send(_masked(message_id="other", tenant="tenant-1", tenant_source="kontext")).status == "sent"
    assert calls == [1]


def test_dead_letter_remains_terminal_for_legacy_and_contract_queue_names(tmp_path):
    sync = make_sync(tmp_path, sender_project=lambda *_: "projected", transport=lambda *_: None)
    for mid, kind in (("legacy", "queue"), ("new", "eingereiht")):
        stored = _masked(message_id=mid, tenant="tenant-1", tenant_source="gateway_context")
        sync.journal.save_projection(stored)
        sync.journal.append("conv-1", {"kind": kind, "direction": "out", "conversation_id": "conv-1",
                                        "message_id": mid, "attempts": 0, "next_at": 0, "enqueued_at": time.time()})
        sync.journal.append("conv-1", {"kind": "dead_letter", "conversation_id": "conv-1", "message_id": mid})
    assert sync.retry_due(now=time.time()) == []
