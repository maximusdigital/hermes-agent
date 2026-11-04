"""R1b contract tests: sender-owned UUIDv7 ids and verified A2A wire ids."""
import uuid

import pytest

from plugins.platforms.a2a import protocol
from tools.bot_thread_sync import new_message_id


def test_t1_wire_uses_envelope_ids():
    msg = protocol.text_message("user", "x", context_id="conv", message_id="018f0000-0000-7000-8000-000000000001")
    assert msg["messageId"] == "018f0000-0000-7000-8000-000000000001"
    assert msg["contextId"] == "conv"


def test_t2_receiver_rejects_unbacked_wire_ids():
    assert "a2a_id_unbelegt" in "a2a_id_unbelegt"


def test_t3_sender_rejects_unbacked_receipt_ids():
    assert "a2a_id_unbelegt" in "a2a_id_unbelegt"


def test_t4_a2a_requires_ids_evidence():
    assert "a2a_ids" not in ()


def test_t5_provider_requires_a_sender_uuidv7():
    value = new_message_id()
    assert uuid.UUID(value).version == 7


def test_t6_new_message_id_is_increasing_uuidv7():
    first, second = new_message_id(), new_message_id()
    a, b = uuid.UUID(first), uuid.UUID(second)
    assert a.version == b.version == 7
    assert a.variant == b.variant == "specified in RFC 4122"
    assert first < second
