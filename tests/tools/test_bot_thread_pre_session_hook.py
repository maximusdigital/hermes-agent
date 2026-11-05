"""The recipient session starts only after its own projection is journal-confirmed."""
from __future__ import annotations

import pytest

import tools.bot_live_delivery as bld
import tools.bot_thread_provider as provider
from tools.bot_thread_sync import Owner, ThreadEnvelope
from tests.tools.bot_thread_support import envelope, make_ctx, make_grant, make_sync, registry
from tools.bot_thread_sync import mask_text


def _incoming():
    masked = mask_text("hello")
    return envelope(text=masked.text, masking=masked.proof(), tenant="tenant-1", tenant_source="gateway_context")


def test_inbound_without_pre_session_hook_blocks_before_projection_or_processing(tmp_path):
    ctx = make_ctx(tmp_path / "recipient", profile="linus", thread="linus-t", live="live-b")
    projected, dispatched = [], []
    sync = make_sync(tmp_path, ctx, name="recipient", pre_session_hook=None,
                     project=lambda _owner, payload: projected.append(payload) or "receipt",
                     process=lambda payload: dispatched.append(payload))

    result = sync.receive(_incoming())

    assert (result.status, result.reason) == ("blocked", "sitzung_unmaskiert")
    assert len(projected) == 1 and dispatched == []
    assert not [row for row in sync.journal.events("conv-1") if row["kind"] == "inbound_processed"]


def test_false_pre_session_hook_keeps_message_queued_without_dispatch(tmp_path):
    ctx = make_ctx(tmp_path / "recipient", profile="linus", thread="linus-t", live="live-b")
    dispatched = []
    sync = make_sync(tmp_path, ctx, name="recipient", pre_session_hook=lambda _payload: False,
                     project=lambda *_args: "receipt", process=lambda payload: dispatched.append(payload))

    result = sync.receive(_incoming())

    assert (result.status, result.reason) == ("queued", "eingangsprojektion_unbestatigt")
    assert dispatched == []


def test_provider_wires_hook_and_delivers_after_confirmed_recipient_projection(tmp_path, monkeypatch):
    home = tmp_path / "recipient"
    home.mkdir()
    monkeypatch.setattr(provider, "_egress_ready", lambda: True)
    monkeypatch.setattr(provider, "profile_secret_values", lambda _home: ("fixture-only",))
    monkeypatch.setattr(bld, "_send_canonical_thread_message", lambda *_args: {"success": True, "message_id": "p"})

    monkeypatch.setattr(provider, "_active_owner", lambda ctx, thread: Owner(
        ctx.profile_home, ctx.profile, "telegram", str(thread["chat_id"]), str(thread["thread_id"]),
        "lease-recipient", ctx.live_session_id, ctx.lease_expires_at))
    issued = make_grant(home, profile="recipient", thread="recipient-t", live="live-recipient")
    capability = provider.build_thread_sync(*issued, evidence=registry())
    assert capability is not None and capability._sync.pre_session_hook is not None
    masked = mask_text("hello")
    incoming = ThreadEnvelope(conversation_id="conv-1", message_id="incoming-1", parent_message_id=None,
                              sender="sender", recipient=capability._sync.auth.profile, tenant="tenant-1",
                              tenant_source="gateway_context",
                              source_thread={"platform": "telegram", "chat_id": "test", "thread_id": "sender-t"},
                              target_thread=dict(capability._sync.auth.thread),
                              text=masked.text, masking=masked.proof(), transport="native", art="gespraech",
                              projection_requested=False, is_root=True)

    result = capability._sync.receive(incoming)
    assert (result.status, result.reason) == ("received", "")


def test_unattested_pre_session_hook_blocks_before_recipient_projection(tmp_path):
    ctx = make_ctx(tmp_path / "recipient", profile="linus", thread="linus-t", live="live-b")
    projected = []
    sync = make_sync(tmp_path, ctx, name="recipient", pre_session_hook=lambda _payload: True,
                     project=lambda *_args: projected.append(True) or "receipt")
    sync.evidence._attested.pop("pre_session_hook", None)

    result = sync.receive(_incoming())

    assert (result.status, result.reason) == ("blocked", "spiegel_unbelegt")
    assert projected == []
