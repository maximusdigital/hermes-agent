"""R1b contract tests exercise the live A2A and ThreadSync seams."""
import uuid
from types import SimpleNamespace

import pytest

pytest_plugins = ("tests.tools.test_bot_thread_provider",)

from plugins.platforms.a2a import protocol
from tools.bot_thread_sync import new_message_id


def _peer(monkeypatch, post):
    import plugins.platforms.a2a.tools as tools
    monkeypatch.setattr(tools, "_load_config", lambda: {"a2a_agents": {"r": {
        "url": "http://x", "profile": "linus",
        "telegram_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"}}}})
    monkeypatch.setattr(tools, "_http_get_json", lambda *args: None)
    monkeypatch.setattr(tools, "_http_post_json", post)
    return tools


def test_t1_wire_uses_envelope_ids():
    msg = protocol.text_message("user", "x", context_id="conv", message_id="018f0000-0000-7000-8000-000000000001")
    assert msg["messageId"] == "018f0000-0000-7000-8000-000000000001"
    assert msg["contextId"] == "conv"


@pytest.mark.parametrize("field, value", [("messageId", "other-message"), ("contextId", "other-context")])
def test_t2_receiver_rejects_unbacked_wire_ids(monkeypatch, field, value):
    from tests.plugins.test_a2a_plugin import TestConversationalAdmissionAndTransport as Admission
    adapter, calls = Admission._adapter(), []
    adapter.set_gateway_context_factory(lambda: SimpleNamespace(
        attest=lambda *n: True, receive_wire=lambda *a, **k: pytest.fail("must not admit")))
    monkeypatch.setattr("plugins.platforms.a2a.adapter.security.audit", lambda *a: calls.append("audit"))
    monkeypatch.setattr("plugins.platforms.a2a.adapter.protocol.persist_message", lambda *a: calls.append("persist"))
    params = Admission._params()
    params["message"][field] = value
    with pytest.raises(RuntimeError, match="a2a_id_unbelegt"):
        adapter._receive_thread_sync(params, params["thread_contract"]["text"], peer="peer", agent={})
    terminal, pending = adapter._prepare_task(params, "peer")
    assert pending is None and terminal["status"]["state"] == protocol.STATE_FAILED
    assert calls == [] and not adapter.tasks._tasks


def test_t3_sender_rejects_unbacked_receipt_ids(world, monkeypatch):
    def post(url, body, headers, timeout):
        env, ctx = body["params"]["thread_contract"], body["params"]["message"]["contextId"]
        receipt = {"message_id": env["message_id"], "envelope_digest": env["envelope_digest"],
                   "wire_message_id": "other-message", "wire_context_id": ctx, "status": "admitted"}
        return protocol.jsonrpc_result(body["id"], protocol.build_task("t", ctx, protocol.STATE_COMPLETED, "ok", metadata={"thread_admission": receipt}))
    tools, cap = _peer(monkeypatch, post), world.cap("neo")
    cap._sync.sender_edit = lambda owner, reference, payload: {"success": True}
    out = tools.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=cap))
    assert "a2a_id_unbelegt" in out
    conv, rows = cap._sync.journal.conversations()[0], None
    rows = cap._sync.journal.events(conv)
    assert [(r["kind"], r.get("reason")) for r in rows if r["kind"] == "dead_letter"] == [("dead_letter", "a2a_id_unbelegt")]
    assert not [r for r in rows if r["kind"] == "queue"]
    assert len([r for r in rows if r["kind"] == "projection"]) == 1
    assert len([r for r in rows if r["kind"] == "sender_status" and r["status"] == "fehlgeschlagen"]) == 1


def test_t4_a2a_requires_ids_evidence(world, monkeypatch):
    cap = world.cap("neo")
    cap._sync.evidence.entries["a2a_ids"]["proven"] = False
    _peer(monkeypatch, lambda *a: pytest.fail("HTTP must not run"))
    result = cap.send(target="r", recipient="linus", message="hallo", transport="a2a",
                      peer_thread={"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"},
                      wire_transport=lambda payload: pytest.fail("transport must not run"), message_id=new_message_id())
    assert (result.status, result.reason) == ("blocked", "a2a_id_unbelegt")
    assert cap._sync.journal.conversations() == []


def test_t5_provider_requires_a_sender_uuidv7(world):
    cap, common = world.cap("neo"), dict(target="linus", message="hallo")
    for bad in (None, str(uuid.uuid4()), new_message_id().upper()):
        assert cap._inner.send(**common, message_id=bad).reason == "envelope_ungueltig"
    valid = new_message_id()
    assert cap._inner.send(**common, message_id=valid).status == "sent"
    assert cap._inner.send(**common, message_id=valid).reason == "envelope_ungueltig"
    conv = cap._sync.journal.conversations()[0]
    assert {r["message_id"] for r in cap._sync.journal.events(conv) if r.get("message_id")} == {valid}


def test_t6_new_message_id_is_increasing_uuidv7():
    first, second = new_message_id(), new_message_id()
    a, b = uuid.UUID(first), uuid.UUID(second)
    assert a.version == b.version == 7 and a.variant == b.variant == "specified in RFC 4122" and first < second


def test_t7_missing_admission_receipt_stays_retryable(world, monkeypatch):
    def post(url, body, headers, timeout):
        ctx = body["params"]["message"]["contextId"]
        return protocol.jsonrpc_result(body["id"], protocol.build_task("t", ctx, protocol.STATE_COMPLETED, "ok"))
    tools, cap = _peer(monkeypatch, post), world.cap("neo")
    out = tools.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=cap))
    assert "queued" in out
    conv = cap._sync.journal.conversations()[0]
    assert any(r["kind"] == "queue" and r["reason"] == "transport_unavailable" for r in cap._sync.journal.events(conv))
