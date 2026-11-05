"""R2a reporting-code contracts at the real ThreadSync seams."""
import json

import pytest

pytest_plugins = ("tests.tools.test_bot_thread_provider",)


def test_c1_unwritable_audit_blocks_before_egress(world, monkeypatch):
    cap = world.cap("neo")
    monkeypatch.setattr(cap._sync.journal, "verify_writable", lambda: False)
    result = cap.send(target="linus", message="hello")
    assert (result.status, result.reason) == ("blocked", "audit_fehler")
    assert world.egress == []


def test_c2_known_peer_sender_deviation_is_contract_breach(world):
    from tests.tools.test_bot_thread_provider import _a2a_wire

    cap = world.cap("linus")
    cap._sync.attest("a2a_admission")
    cap._peers["known"] = {"profile": "neo", "tenant": "tenant-1",
                            "source_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"}}
    foreign_sender = _a2a_wire(world)
    foreign_sender["sender"] = "other"
    foreign_sender["envelope_digest"] = ""
    # Construct a valid complete wire with an attribution different from the known peer.
    from tests.tools.bot_thread_support import envelope
    from tools.bot_thread_sync import mask_text
    masked = mask_text("hello")
    foreign_sender = envelope(sender="other", text=masked.text, masking=masked.proof(), tenant="tenant-1",
                              tenant_source="x", transport="a2a").to_wire()
    result = cap.receive_wire(foreign_sender, peer="known", external_dispatch=True)
    assert (result.status, result.reason) == ("blocked", "absender_abweichend")
    rows = cap._sync.journal.events("conv-1")
    assert [(row["kind"], row["status"]) for row in rows] == [("audit", "Vertragsbruch")]
    unknown = cap.receive_wire(foreign_sender, peer="unknown", external_dispatch=True)
    assert (unknown.status, unknown.reason) == ("blocked", "absender_unbelegt")


def test_c3_message_agent_requires_evidence_before_journal(world):
    cap = world.cap("neo")
    cap._sync.evidence.entries["message_agent"]["proven"] = False
    result = cap._inner.send(target="linus", message="hello", transport="message_agent")
    assert (result.status, result.reason) == ("blocked", "adapter_unbelegt")
    assert cap._sync.journal.conversations() == []


def test_c4_a2a_store_masks_before_writing(tmp_path, monkeypatch):
    from plugins.platforms.a2a import protocol

    monkeypatch.setattr(protocol, "get_hermes_home", lambda: tmp_path)
    protocol.persist_message("ctx", "user", "token=abc12345", "task")
    row = json.loads((tmp_path / "a2a_conversations" / "ctx.jsonl").read_text())
    assert "[MASKED]" in row["text"]
    assert "token=abc12345" not in (tmp_path / "a2a_conversations" / "ctx.jsonl").read_text()


def test_c5_a2a_store_evidence_blocks_before_http(world, monkeypatch):
    from tools.bot_thread_sync import new_message_id

    cap = world.cap("neo")
    cap._sync.attest("a2a_ids")
    cap._sync.evidence.entries["a2a_ablage"]["proven"] = False
    result = cap._inner.send(target="linus", recipient="linus", message="hello", transport="a2a",
                             peer_thread={"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"},
                             wire_transport=lambda _payload: pytest.fail("transport must not run"),
                             message_id=new_message_id())
    assert (result.status, result.reason) == ("blocked", "a2a_ablage_unmaskiert")
    assert cap._sync.journal.conversations() == []
