"""Real provider, two isolated profile homes, distinct owners/secrets, mocked Telegram egress only."""
import contextlib
import json
import time
from pathlib import Path

import pytest

import tools.bot_live_delivery as bld
import tools.bot_thread_provider as prov
from tools.bot_thread_sync import ThreadEnvelope
from tests.tools.bot_thread_support import make_ctx, make_grant, registry


def SILENT(profile, home, text):  # a recipient agent that ran and chose not to answer
    return True, ""


@pytest.fixture(autouse=True)
def _fresh_authority():
    from tests.tools.bot_thread_support import reset_authority
    reset_authority()
    yield
    reset_authority()


@pytest.fixture
def world(tmp_path, monkeypatch):
    homes = {"neo": tmp_path / "neo", "linus": tmp_path / "linus"}
    threads = {"neo": "neo-t", "linus": "linus-t"}
    lives = {"neo": "live-a", "linus": "live-b"}
    online = {"neo": True, "linus": True}
    secrets = {"neo": ("alpha-secret",), "linus": ("beta-secret",)}
    egress = []
    for h in homes.values():
        h.mkdir()

    def snapshot(registry_home=None, strict=False):
        name = next(n for n, h in homes.items() if Path(registry_home) == h)
        if not online[name]:
            return []
        return [{"lease_id": f"lease-{name}", "session_id": f"s-{name}",
                 "metadata": {"platform": "telegram", "chat_id": "max", "thread_id": threads[name],
                              "live_session_id": lives[name]}}]

    monkeypatch.setattr("hermes_cli.active_sessions.active_session_registry_snapshot", snapshot)
    monkeypatch.setattr(bld, "_send_canonical_thread_message",
                        lambda owner, text: egress.append((owner["thread_id"], text)) or
                        {"success": True, "message_id": f"tg-{len(egress)}"})
    monkeypatch.setattr(prov, "_egress_ready", lambda: True)
    monkeypatch.setattr(prov, "profile_secret_values", lambda home: secrets[Path(home).name])

    def target_for(me):
        other = "linus" if me == "neo" else "neo"
        return lambda root, target: (other, homes[other],
                                     {"platform": "telegram", "chat_id": "max", "thread_id": threads[other]})

    def cap(name, dispatcher=None, native_runner=None, refresh=None, tenant="tenant-1", live=None, lease=300):
        if native_runner is not None and refresh is None:  # production always supplies a broker-issued refresh
            refresh = lambda: cap(name, dispatcher, native_runner, None, tenant, live, lease)  # noqa: E731
        monkeypatch.setattr(prov, "_target", target_for(name))
        ctx = make_grant(homes[name], profile=name, thread=threads[name], live=live or lives[name],
                         conversation=f"s-{name}", tenant=tenant, lease=lease)
        c = prov.build_thread_sync(*ctx, evidence=registry(), dispatcher=dispatcher, native_runner=native_runner,
                                    refresh=refresh)
        assert c is not None
        import tests.tools.bot_thread_support as _support
        c._sync.clock = lambda: _support.time.time()  # one wall clock for grants AND the engine (tests may skew it)
        return TestCapability(c)

    class TestCapability:
        def __init__(self, inner): self._inner = inner
        def __getattr__(self, name): return getattr(self._inner, name)
        def send(self, **kwargs):
            from tools.bot_thread_sync import new_message_id
            kwargs.setdefault("message_id", new_message_id())
            if kwargs.get("transport") == "a2a":
                self._inner.attest("a2a_ids")
            return self._inner.send(**kwargs)

    class W:
        pass
    w = W()
    w.homes, w.online, w.egress, w.cap = homes, online, egress, cap
    return w


def _chain(capability):
    rows = [e for e in capability._sync.journal.events(next(iter(capability._sync.journal.conversations())))
            if e["kind"] in {"bestaetigt", "inbound_receipt"}]
    return [(e["kind"], e["message_id"]) for e in rows]


def test_provider_requires_valid_runner_context(tmp_path):
    assert prov.build_thread_sync(None, None) is None
    assert prov.build_thread_sync(*make_grant(tmp_path, lease=-5)) is None      # expired grant
    assert prov.build_thread_sync(make_ctx(tmp_path), None) is None                   # a bare context is data, not authority


def _texts(world, thread):
    return [text for t, text in world.egress if t == thread]


def test_native_a_b_a_conversation_runs_the_recipient_agent_and_survives_restarts(world):
    """Two isolated profiles with distinct owners; B's stub model really runs; every projection once."""
    calls = []

    def stub_model(profile, home, text):
        calls.append((profile, text))
        return True, f"antwort{len(calls)} von {profile}"

    a = world.cap("neo")
    assert a.send(target="linus", message="hallo b").status == "sent"          # m1
    headless = world.cap("linus")                                              # gateway up, NO recipient agent
    assert [(r.status, r.reason) for r in headless.ingest_inbox()] == [("queued", "kein_dispatcher")]
    assert calls == [] and len(_inbox_files(world)) == 1                       # fails closed, never "processed"
    assert "inbound_processed" not in _journal_kinds(headless)

    b = world.cap("linus", native_runner=stub_model)                           # restart with the agent seam
    assert b.recover() >= 1
    assert calls == [("linus", "hallo b")]                                     # the model actually ran
    a = world.cap("neo")                                                       # sender restarts too
    assert a.recover() >= 1                                                    # consumes B's reply (m2)
    assert a.send(target="linus", message="danke b").status == "sent"          # m3
    b2 = world.cap("linus", native_runner=stub_model)
    b2.recover()
    assert [c[1] for c in calls] == ["hallo b", "danke b"] and len(calls) == 2  # stub model count > 0

    ja, jb = a._sync.journal, b2._sync.journal
    conv = ja.conversations()[0]
    chain = [(e["message_id"], e.get("parent_message_id")) for e in ja.events(conv) if e["kind"] == "audit"
             and e["status"] in {"sent", "received"}]
    (m1, p1), (m2, p2), (m3, p3) = chain[:3]
    assert len({m1, m2, m3}) == 3 and p1 is None and p2 == m1 and p3 == m2     # parent chain over 3 ids
    # both sides' visible projections: exactly one each (sender mirror + recipient mirror per message)
    assert _texts(world, "neo-t").count("neo → linus: hallo b") == 1
    assert _texts(world, "linus-t").count("neo → linus: hallo b") == 1
    assert _texts(world, "linus-t").count("linus → neo: antwort1 von linus") == 1
    assert _texts(world, "neo-t").count("linus → neo: antwort1 von linus") == 1
    assert _texts(world, "neo-t").count("neo → linus: danke b") == 1
    assert _texts(world, "linus-t").count("neo → linus: danke b") == 1
    for _ in range(2):  # more recovery passes change nothing
        a.recover(); b2.recover()
    assert len(calls) == 2 and len(world.egress) == len(set(range(len(world.egress)))) and _inbox_files_for(world, "neo") == []


def test_b_secret_in_a_message_is_blocked_by_receiver_before_projection(world):
    a = world.cap("neo")
    a.send(target="linus", message="mein geheimnis ist beta-secret")
    b = world.cap("linus")
    assert [(r.status, r.reason) for r in b.ingest_inbox()] == [("blocked", "maskierung_unbelegt")]
    assert [t for t, _ in world.egress] == ["neo-t"]  # sender projection only


def test_inbound_restart_recovery_with_queued_message(world):
    world.online["linus"] = False
    a = world.cap("neo")
    assert a.send(target="linus", message="warte").status == "sent"
    b = world.cap("linus")
    assert b.ingest_inbox()[0].status == "queued"
    world.online["linus"] = True
    b2 = world.cap("linus")  # "restarted" gateway: fresh capability, same durable state
    assert b2.recover() >= 1
    assert [t for t, _ in world.egress] == ["neo-t", "linus-t"]
    b2.recover()
    assert [t for t, _ in world.egress] == ["neo-t", "linus-t"]


def test_outbound_queue_survives_restart_and_reresolves_owner(world):
    world.online["neo"] = False
    a = world.cap("neo")
    assert a.send(target="linus", message="später").status == "queued"
    assert world.egress == []
    world.online["neo"] = True
    a2 = world.cap("neo")
    a2._sync.clock = lambda: time.time() + 30
    a2.recover()
    assert [t for t, _ in world.egress] == ["neo-t"]


def test_egress_key_is_idempotent_across_instances(world):
    a = world.cap("neo")
    ctx_owner = prov._active_owner(a._ctx, a._ctx.thread)
    payload = {"sender": "neo", "recipient": "linus", "text": "x", "status": "gesendet", "egress_key": "a" * 64}
    prov._project(ctx_owner, payload)
    prov._project(ctx_owner, payload)
    assert len(world.egress) == 1


def test_no_plaintext_in_journal_events_or_inbox_names_and_history_untouched(world):
    from hermes_state import SessionDB
    db = SessionDB(db_path=world.homes["neo"] / "state.db")
    db.create_session("s-neo", "telegram")
    db.append_message("s-neo", "user", content="before")
    before = db.get_messages_as_conversation("s-neo")
    a = world.cap("neo")
    a.send(target="linus", message="PLAIN_SENTINEL_5")
    world.cap("linus", native_runner=SILENT).ingest_inbox()
    assert db.get_messages_as_conversation("s-neo") == before  # no receipt/metadata enters model history
    for home in world.homes.values():
        for f in home.rglob("events.jsonl"):
            assert "PLAIN_SENTINEL_5" not in f.read_text()
        for f in home.rglob(".live.json"):
            assert "PLAIN_SENTINEL_5" not in f.read_text()
    assert not list((world.homes["linus"] / "runtime" / "bot_thread_sync_inbox").glob("*"))


def test_native_forged_sender_is_blocked_before_projection(world, monkeypatch):
    a = world.cap("neo")
    a.send(target="linus", message="hi")
    b = world.cap("linus")
    # roster says the sender "neo" lives on another thread than the envelope claims
    monkeypatch.setattr(prov, "_target", lambda root, t: ("neo", world.homes["neo"],
                        {"platform": "telegram", "chat_id": "max", "thread_id": "attacker-t"}))
    assert [(r.status, r.reason) for r in b.ingest_inbox()] == [("blocked", "absender_unbelegt")]
    assert [t for t, _ in world.egress] == ["neo-t"]


def _a2a_wire(world, text="hi", secrets=(), message_id="msg-1"):
    from tests.tools.bot_thread_support import envelope
    from tools.bot_thread_sync import mask_text
    m = mask_text(text, secrets=secrets)
    env = envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x", transport="a2a",
                   sender="neo", recipient="linus", message_id=message_id)
    return env.to_wire()


def test_a2a_peer_must_be_allowlisted_for_sender_profile_and_source_thread(world):
    b = world.cap("linus")
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    allow = {"profile": "neo", "source_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
             "tenant": "tenant-1"}
    assert b.receive_wire(wire, peer="evil").reason == "absender_unbelegt"      # unknown peer
    assert b.receive_wire(wire).reason == "absender_unbelegt"                    # no peer identity at all
    b._peers["p"] = {**allow, "profile": "someone-else"}
    assert b.receive_wire(wire, peer="p").reason == "absender_unbelegt"          # wrong profile
    b._peers["p"] = {**allow, "source_thread": {**allow["source_thread"], "thread_id": "other"}}
    assert b.receive_wire(wire, peer="p").reason == "absender_unbelegt"          # wrong thread
    assert world.egress == []
    b._peers["p"] = allow
    assert b.receive_wire(wire, peer="p").status == "received"
    assert b.receive_wire(wire, peer="p").status == "duplicate"                  # replay
    assert [t for t, _ in world.egress] == ["linus-t"]


def test_next_due_delay_is_bounded(world):
    a = world.cap("neo")
    assert a.next_due_delay() == 60.0
    world.online["neo"] = False
    a2 = world.cap("neo")
    a2.send(target="linus", message="later")
    assert 5.0 <= a2.next_due_delay() <= 60.0


def test_spoofed_recipient_is_refused_with_zero_side_effects(world):
    b = world.cap("linus")
    b._peers["p"] = {"profile": "neo", "source_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
                     "tenant": "tenant-1"}
    b._sync.attest("a2a_admission")
    from tests.tools.bot_thread_support import envelope
    from tools.bot_thread_sync import mask_text
    m = mask_text("hi")
    wire = envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x", transport="a2a",
                    sender="neo", recipient="someone-else").to_wire()
    res = b.receive_wire(wire, peer="p")
    assert (res.status, res.reason) == ("blocked", "empfaenger_abweichend")
    assert world.egress == []
    assert not (world.homes["linus"] / "runtime" / "bot_thread_sync" / "conv-1").exists()
    assert b.send_reply(wire, "x")[1] is None


def test_reply_is_masked_with_receiver_secrets_and_keeps_chain(world):
    """B's secret never leaves B: the reply passes B's own masking+proof before it is transported."""
    b = world.cap("linus")
    b._peers["p"] = {"profile": "neo", "source_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
                     "tenant": "tenant-1"}
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    assert b.receive_wire(wire, peer="p").status == "received"
    result, reply = b.send_reply(wire, "antwort mit beta-secret und alpha-secret und token=abc12345")
    assert result.status == "sent" and reply is not None
    assert "beta-secret" not in reply.text and "token=abc12345" not in reply.text
    assert "alpha-secret" in reply.text  # A's secret is not B's to know; A re-masks on receipt
    from tools.bot_thread_sync import verify_masking_proof
    assert verify_masking_proof(reply.text, reply.masking, secrets=("beta-secret",))
    inbound = ThreadEnvelope.from_wire(wire)
    assert (reply.parent_message_id, reply.conversation_id) == (inbound.message_id, inbound.conversation_id)
    assert (reply.sender, reply.recipient, reply.tenant) == ("linus", "neo", "tenant-1")
    assert reply.target_thread == inbound.source_thread and reply.source_thread["thread_id"] == "linus-t"
    assert all("beta-secret" not in t for _, t in world.egress)  # also not in B's own projection


# ---------------------------------------------------------------- durable routes survive capability rebuilds
def _queued(capability):
    j = capability._sync.journal
    conv = j.conversations()[0]
    row = [e for e in j.events(conv) if e["kind"] in {"eingereiht", "versuch"}][-1]
    return conv, row["message_id"]


def _route_file(world, conv, msg):
    return world.homes["neo"] / "runtime" / "bot_thread_sync" / conv / "routes" / f"{msg}.json"


def _inbox_files(world):
    return list((world.homes["linus"] / "runtime" / "bot_thread_sync_inbox").glob("*.json")) \
        if (world.homes["linus"] / "runtime" / "bot_thread_sync_inbox").exists() else []


def test_native_queue_delivers_to_original_recipient_after_capability_rebuild(world):
    world.online["neo"] = False
    a = world.cap("neo")
    assert a.send(target="linus", message="später PLAIN_ROUTE_SENTINEL").status == "queued"
    conv, msg = _queued(a)
    route_text = _route_file(world, conv, msg).read_text()
    assert "PLAIN_ROUTE_SENTINEL" not in route_text and "später" not in route_text  # reference only
    del a  # the old capability and every in-memory map are gone
    world.online["neo"] = True
    a2 = world.cap("neo")
    assert a2._wire == {}
    a2._sync.clock = lambda: time.time() + 30
    a2.recover()
    assert len(_inbox_files(world)) == 1  # delivered to the ORIGINAL recipient from durable state alone
    world.cap("linus", native_runner=SILENT).ingest_inbox()
    assert [t for t, _ in world.egress] == ["neo-t", "linus-t"]
    a2.recover()
    world.cap("linus", native_runner=SILENT).ingest_inbox()
    assert [t for t, _ in world.egress] == ["neo-t", "linus-t"] and not _inbox_files(world)  # egress dedupe


def test_a2a_queue_delivers_to_original_peer_after_capability_rebuild(world, monkeypatch):
    world.online["neo"] = False
    a = world.cap("neo")
    thread = {"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"}
    res = a.send(target="peer-label", message="hi", transport="a2a", peer_thread=thread, recipient="linus",
                 wire_transport=lambda p: pytest.fail("the old live closure must not be needed"))
    assert res.status == "queued"
    conv, msg = _queued(a)
    del a
    world.online["neo"] = True
    a2 = world.cap("neo")
    calls = []
    import plugins.platforms.a2a.tools as a2a_tools
    monkeypatch.setattr(a2a_tools, "_resolve_peer", lambda label: {"url": "http://peer"} if label == "peer-label" else None)
    monkeypatch.setattr(a2a_tools, "_send_task", lambda label, peer, text, ctx, envelope=None:
                        calls.append((label, envelope.message_id, envelope.recipient, ctx)) or ("r", ctx, "s"))
    a2._sync.clock = lambda: time.time() + 30
    a2.recover()
    assert calls == [("peer-label", msg, "linus", conv)]
    a2.recover()
    assert len(calls) == 1 and [t for t, _ in world.egress] == ["neo-t"]  # one sender projection, one delivery


def _queue_and_rebuild(world):
    world.online["neo"] = False
    a = world.cap("neo")
    a.send(target="linus", message="x")
    conv, msg = _queued(a)
    del a
    world.online["neo"] = True
    a2 = world.cap("neo")
    a2._sync.clock = lambda: time.time() + 30
    return a2, conv, msg


def test_tampered_route_fails_closed(world):
    a2, conv, msg = _queue_and_rebuild(world)
    import json as _json
    p = _route_file(world, conv, msg)
    record = _json.loads(p.read_text())
    record["target_thread"]["thread_id"] = "attacker-t"  # redirect without the key
    p.write_text(_json.dumps(record))
    a2.recover()
    assert _inbox_files(world) == [] and not (world.homes["neo"] / "attacker").exists()


def test_missing_route_fails_closed(world):
    a2, conv, msg = _queue_and_rebuild(world)
    _route_file(world, conv, msg).unlink()
    a2.recover()
    assert _inbox_files(world) == []


def test_symlinked_routes_dir_fails_closed(world, tmp_path):
    a2, conv, msg = _queue_and_rebuild(world)
    routes = _route_file(world, conv, msg).parent
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / f"{msg}.json").write_text(_route_file(world, conv, msg).read_text())
    routes.rename(routes.with_name("routes-old"))
    routes.symlink_to(outside, target_is_directory=True)
    a2.recover()
    assert _inbox_files(world) == []


def test_route_that_no_longer_matches_the_queued_envelope_fails_closed(world):
    a2, conv, msg = _queue_and_rebuild(world)
    import json as _json
    proj = world.homes["neo"] / "runtime" / "bot_thread_sync" / conv / "projections" / f"{msg}.json"
    data = _json.loads(proj.read_text())
    data["target_thread"]["thread_id"] = "attacker-t"
    proj.write_text(_json.dumps(data))
    a2.recover()
    assert _inbox_files(world) == []


_ALLOW = {"profile": "neo", "source_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
          "tenant": "tenant-1"}


def test_queued_a2a_message_is_dispatched_to_the_gateway_after_rebuild_and_owner_recovery(world):
    world.online["linus"] = False
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    assert b.receive_wire(_a2a_wire(world), peer="p", external_dispatch=True).status == "queued"
    assert world.egress == []
    del b
    world.online["linus"] = True
    got = []
    b2 = world.cap("linus", dispatcher=lambda env: got.append((env.message_id, env.sender)) or True)
    b2._sync.clock = lambda: time.time() + 30
    b2.recover()
    assert got == [("msg-1", "neo")]  # dispatched via the gateway seam, not silently marked processed
    j = b2._sync.journal
    kinds = [e["kind"] for e in j.events(j.conversations()[0])]
    assert kinds.count("dispatch_accepted") == 1 and kinds.count("inbound_processed") == 1
    assert [t for t, _ in world.egress] == ["linus-t"]
    b2.recover()
    assert len(got) == 1 and [t for t, _ in world.egress] == ["linus-t"]


def _roundtrip(world, monkeypatch, reply_text, *, mutate=None, strip=False):
    import plugins.platforms.a2a.tools as t
    from plugins.platforms.a2a import protocol
    a, b = world.cap("neo"), world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    monkeypatch.setattr(t, "_load_config", lambda: {"a2a_agents": {"r": {
        "url": "http://x", "profile": "linus",
        "telegram_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"}}}})
    monkeypatch.setattr(t, "_http_get_json", lambda *args: None)

    def post(url, body, headers, timeout):
        contract = body["params"]["thread_contract"]
        assert b.receive_wire(contract, peer="p").status == "received"
        _, reply = b.send_reply(contract, reply_text)
        wire = reply.to_wire()
        if mutate:
            wire = mutate(wire)
        receipt = {"message_id": contract["message_id"], "envelope_digest": contract["envelope_digest"],
                   "wire_message_id": body["params"]["message"]["messageId"],
                   "wire_context_id": body["params"]["message"]["contextId"], "status": "admitted"}
        task = protocol.build_task("t", body["params"]["message"]["contextId"], protocol.STATE_COMPLETED, reply.text,
                                   metadata={"thread_admission": receipt, **({} if strip else {"thread_contract": wire})})
        return protocol.jsonrpc_result(body["id"], task)

    monkeypatch.setattr(t, "_http_post_json", post)
    from types import SimpleNamespace
    return t.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=a))


def _neo_texts(world):
    return [text for thread, text in world.egress if thread == "neo-t"]


def test_receiver_only_secret_never_reaches_the_sender(world, monkeypatch):
    out = _roundtrip(world, monkeypatch, "antwort mit beta-secret")
    assert "beta-secret" not in out and "[MASKED]" in out and "reply withheld" not in out
    assert all("beta-secret" not in text for _, text in world.egress)


def test_sender_only_secret_in_the_reply_is_blocked_by_sender_side_rescan(world, monkeypatch):
    out = _roundtrip(world, monkeypatch, "die antwort verrät alpha-secret")
    assert "alpha-secret" not in out and "reply withheld" in out and "maskierung_unbelegt" in out
    assert all("alpha-secret" not in text for text in _neo_texts(world))  # never projected on the sender side


def test_reply_without_or_with_tampered_contract_is_withheld(world, monkeypatch):
    out = _roundtrip(world, monkeypatch, "harmlos", strip=True)
    assert "reply withheld" in out and "harmlos" not in out
    tampered = _roundtrip(world, monkeypatch, "harmlos", mutate=lambda w: {**w, "text": "anderer text"})
    assert "reply withheld" in tampered and "anderer text" not in tampered


def test_request_direction_sender_cannot_leak_receiver_secret(world):
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world, "mein geheimnis ist beta-secret", secrets=("alpha-secret",))
    res = b.receive_wire(wire, peer="p")
    assert (res.status, res.reason) == ("blocked", "maskierung_unbelegt")
    assert all("beta-secret" not in text for _, text in world.egress)


def _a2a_world(world, monkeypatch, post):
    import plugins.platforms.a2a.tools as t
    monkeypatch.setattr(t, "_load_config", lambda: {"a2a_agents": {"r": {
        "url": "http://x", "profile": "linus",
        "telegram_thread": {"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"}}}})
    monkeypatch.setattr(t, "_http_get_json", lambda *args: None)
    monkeypatch.setattr(t, "_http_post_json", post)
    return t


def _journal_kinds(capability):
    j = capability._sync.journal
    return [e["kind"] for e in j.events(j.conversations()[0])]


def test_sender_is_done_only_with_the_recipients_durable_admission_receipt(world, monkeypatch):
    from types import SimpleNamespace
    from plugins.platforms.a2a import protocol
    a, b = world.cap("neo"), world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    mode = {"v": "bare"}
    seen = []

    def post(url, body, headers, timeout):
        contract = body["params"]["thread_contract"]
        ctx = body["params"]["message"]["contextId"]
        if mode["v"] == "bare":  # a response that proves nothing about durable admission
            return protocol.jsonrpc_result(body["id"], protocol.build_task("t", ctx, protocol.STATE_COMPLETED, "ok"))
        res = b.receive_wire(contract, peer="p", external_dispatch=True)
        seen.append(res.status)
        b.abort_dispatch(res.ticket)  # recipient gateway is down: admitted + queued, nothing dispatched
        receipt = {"message_id": contract["message_id"], "envelope_digest": contract["envelope_digest"],
                   "wire_message_id": body["params"]["message"]["messageId"],
                   "wire_context_id": body["params"]["message"]["contextId"], "status": "queued"}
        return protocol.jsonrpc_result(body["id"], protocol.build_task(
            "t", ctx, protocol.STATE_FAILED, "gateway not ready", metadata={"thread_admission": receipt}))

    t = _a2a_world(world, monkeypatch, post)
    out = t.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=a))
    assert "queued" in out and "bestaetigt" not in _journal_kinds(a)  # NOT falsely sent
    assert seen == []  # the recipient never saw it

    mode["v"] = "queued"
    a2 = world.cap("neo")  # sender restart: delivery is rebuilt from the durable route
    a2._sync.clock = lambda: time.time() + 30
    a2.recover()
    assert "bestaetigt" in _journal_kinds(a2) and seen == ["admitted"]
    rows = [e for e in b._sync.journal.events(b._sync.journal.conversations()[0]) if e["kind"] in {"eingereiht", "versuch"}]
    assert rows and rows[-1]["dispatch"] == "external"  # recipient holds a durable queue entry

    got = []
    b2 = world.cap("linus", dispatcher=lambda env: got.append(env.message_id) or True)  # gateway restarts
    b2._sync.clock = lambda: time.time() + 60
    b2.recover()
    b2.recover()
    assert len(got) == 1 and "inbound_processed" in _journal_kinds(b2)  # exactly one model dispatch
    a2.recover()
    assert len(got) == 1


def test_route_or_reply_failure_does_not_report_sent(world, monkeypatch):
    from types import SimpleNamespace
    a = world.cap("neo")

    def post(url, body, headers, timeout):
        raise OSError("connection refused")

    t = _a2a_world(world, monkeypatch, post)
    out = t.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=a))
    assert "queued" in out and "bestaetigt" not in _journal_kinds(a)


# ---------------------------------------------------------------- crash contract: replies and recovered completion
def test_model_rerun_after_ambiguous_crash_cannot_duplicate_the_visible_reply(world):
    """At-least-once model, at-most-once projection: the first durable reply wins, with a stable id."""
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    assert b.receive_wire(wire, peer="p").status == "received"
    first_result, first = b.send_reply(wire, "erste antwort beta-secret")
    again_result, again = b.send_reply(wire, "zweite, andere antwort")  # the re-run model answers differently
    assert first_result.status == again_result.status == "sent"
    assert first.message_id == again.message_id and first.text == again.text and "beta-secret" not in first.text
    texts = [text for thread, text in world.egress if thread == "linus-t"]
    assert len(texts) == 2 and not any("zweite" in text for text in texts)  # inbound mirror + ONE reply
    a = world.cap("neo")
    original = ThreadEnvelope.from_wire(wire)
    ok, text = a.receive_reply(first.to_wire(), original=original, text=first.text)
    replay, replay_text = a.receive_reply(first.to_wire(), original=original, text=first.text)
    assert (ok.status, text) == ("received", first.text) and (replay.status, replay_text) == ("duplicate", None)


def _recovered_adapter(world, monkeypatch, message_id="msg-1"):
    import asyncio
    import concurrent.futures
    from gateway.config import PlatformConfig
    from plugins.platforms.a2a.adapter import A2AAdapter
    adapter = A2AAdapter(PlatformConfig(enabled=True, extra={"port": 0}))
    adapter._loop, adapter._message_handler = object(), object()

    adapter.events = []

    async def handle_message(event):
        event._gateway_accepted = True
        adapter.events.append(event)

    adapter.handle_message = handle_message

    def submit(coro, loop):
        fut = concurrent.futures.Future()
        fut.set_result(asyncio.run(coro))
        return fut

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    adapter.set_gateway_context_factory(lambda: world.cap("linus"))
    world.online["linus"] = False
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world, text="frage", message_id=message_id)
    assert b.receive_wire(wire, peer="p", external_dispatch=True).status == "queued"
    world.online["linus"] = True
    b2 = world.cap("linus", dispatcher=adapter.dispatch_thread_message)  # the gateway restarted
    b2._sync.clock = lambda: time.time() + 30
    b2.recover()
    return adapter, wire, b2


def _receiver_adapter(world, ready):
    """A fresh receiver gateway adapter whose capability is rebuilt per use (nothing process-local)."""
    from gateway.config import PlatformConfig
    from plugins.platforms.a2a.adapter import A2AAdapter
    adapter = A2AAdapter(PlatformConfig(enabled=True, extra={"port": 0}))
    adapter._message_handler = object()
    adapter._loop = object() if ready else None
    adapter.events = []

    async def handle_message(event):
        event._gateway_accepted = True
        adapter.events.append(event)

    adapter.handle_message = handle_message

    def factory():
        cap = world.cap("linus")
        cap._peers["p"] = _ALLOW
        cap._sync.attest("a2a_admission")
        return cap

    adapter.set_gateway_context_factory(factory)
    return adapter


def test_sender_retry_across_destroyed_instances_receives_the_durable_reply_exactly_once(world, monkeypatch):
    import asyncio
    import concurrent.futures
    from types import SimpleNamespace
    from plugins.platforms.a2a import protocol

    def submit(coro, loop):
        fut = concurrent.futures.Future()
        fut.set_result(asyncio.run(coro))
        return fut

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    current = {}

    def post(url, body, headers, timeout):  # the sender's HTTP request, served by whichever adapter is alive
        terminal, pending = current["adapter"]._prepare_task(body["params"], "p")
        assert pending is None
        return protocol.jsonrpc_result(body["id"], terminal)

    t = _a2a_world(world, monkeypatch, post)
    # 1. the receiver's gateway is DOWN: the sender gets a durable "queued" receipt and no reply
    adapter1 = current["adapter"] = _receiver_adapter(world, ready=False)
    a = world.cap("neo")
    out = t.a2a_call({"agent": "r", "message": "hallo"}, agent=SimpleNamespace(_thread_sync_capability=a))
    assert "recipient holds the message durably" in out and "bestaetigt" in _journal_kinds(a)
    assert len(a.pending_replies()) == 1  # reply outstanding, tracked durably in the sender journal
    conv = a._sync.journal.conversations()[0]
    # 2. the receiver gateway comes up: recovery SCHEDULES the model; the model answers; completion fires
    adapter1._loop = object()
    b2 = world.cap("linus", dispatcher=adapter1.dispatch_thread_message)
    b2._sync.clock = lambda: time.time() + 30
    b2.recover()
    assert len(adapter1.events) == 1 and "inbound_processed" not in _journal_kinds(b2)  # scheduled ≠ completed
    asyncio.run(adapter1.send(conv, "antwort mit beta-secret", metadata={"notify": True}))
    adapter1._completion_pool.shutdown(wait=True)
    asyncio.run(adapter1.events[-1].on_complete("completed"))
    assert adapter1._pending == {} and "inbound_processed" in _journal_kinds(b2)
    # 3. EVERYTHING process-local is destroyed (adapter, both capabilities); the sender retries
    del adapter1, b2, a
    current["adapter"] = _receiver_adapter(world, ready=False)  # not even a live gateway is needed
    a2 = world.cap("neo")
    a2._sync.clock = lambda: time.time() + 120
    assert a2.poll_replies() == 1
    arrived = [text for text in _neo_texts(world) if text.startswith("linus → neo:")]
    assert len(arrived) == 1 and "beta-secret" not in arrived[0] and "[MASKED]" in arrived[0]
    assert a2.pending_replies() == [] and a2.poll_replies() == 0  # consumed once; no further polls
    assert len(_neo_texts(world)) == 2  # sender's own mirror + the reply, nothing duplicated
    assert len(current["adapter"].events) == 0  # the retry never ran the model again


SYNTHETIC = ("shutting down", "did not reply in time", "[cancelled]", "client disconnected", "processing failed")


def _assert_no_synthetic(world):
    """Lifecycle strings must never reach a durable reply, projection, audit row or Telegram egress."""
    for home in world.homes.values():
        for f in home.rglob("*"):
            if f.is_file():
                text = f.read_bytes().decode("utf-8", "replace")
                assert not any(marker in text for marker in SYNTHETIC), f
    assert not any(marker in text for _, text in world.egress for marker in SYNTHETIC)


def test_disconnect_before_completion_is_lifecycle_not_a_reply_and_work_stays_recoverable(world, monkeypatch):
    import asyncio
    from plugins.platforms.a2a import protocol
    adapter, wire, b2 = _recovered_adapter(world, monkeypatch)
    task_id = next(iter(adapter._pending))
    assert len(adapter._pending) == 1 and "inbound_processed" not in _journal_kinds(b2)
    asyncio.run(adapter.disconnect())  # adapter shuts down while the model is still running
    asyncio.run(adapter.events[-1].on_complete("completed"))  # a late gateway callback must not terminalize
    reader = world.cap("linus")
    assert reader.reply_for(wire) is None  # no reply envelope, no stable reply
    assert "inbound_processed" not in _journal_kinds(reader) and "bestaetigt" not in _journal_kinds(reader)
    assert b2._sync.journal.dispatch_state("conv-1", "msg-1") == "ACCEPTED"  # nonterminal, recoverable
    assert not [t for t in _texts(world, "linus-t") if t.startswith("linus → neo:")]  # nothing projected
    assert adapter._pending == {} and adapter._completion_pool is None
    assert adapter.tasks.get(task_id)["state"] != protocol.STATE_COMPLETED
    _assert_no_synthetic(world)


def test_restart_after_shutdown_redrives_the_model_and_the_real_reply_wins_once(world, monkeypatch):
    import asyncio
    import tools.bot_thread_sync as sync_mod
    monkeypatch.setattr(sync_mod, "COMPLETION_LEASE_SECONDS", 100)
    adapter, wire, _ = _recovered_adapter(world, monkeypatch)
    asyncio.run(adapter.disconnect())
    adapter2 = _receiver_adapter(world, ready=True)  # process restart: fresh adapter, fresh capability
    b3 = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    b3._sync.clock = lambda: time.time() + 150  # the SCHEDULED run's lease has expired
    b3.recover()
    assert len(adapter2.events) == 1  # at-least-once: re-driven under the same dispatch key
    asyncio.run(adapter2.send("conv-1", "echte antwort beta-secret", metadata={"notify": True}))
    adapter2._completion_pool.shutdown(wait=True)
    asyncio.run(adapter2.events[-1].on_complete("completed"))
    reply = b3.reply_for(wire)
    assert reply["text"] == "echte antwort [MASKED]" and "inbound_processed" in _journal_kinds(b3)
    assert _texts(world, "linus-t").count("linus → neo: echte antwort [MASKED]") == 1
    assert b3.send_reply(wire, "spaetere andere antwort")[1].text == reply["text"]  # the first real reply wins
    _assert_no_synthetic(world)


def test_waiter_timeout_detaches_without_a_reply_and_the_late_genuine_reply_finalizes_once(world, monkeypatch):
    import asyncio
    import concurrent.futures
    from plugins.platforms.a2a import adapter as adapter_mod, protocol
    monkeypatch.setattr(adapter_mod, "_reply_timeout", lambda: 0.05)

    def submit(coro, loop):
        fut = concurrent.futures.Future()
        fut.set_result(asyncio.run(coro))
        return fut

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    adapter = _receiver_adapter(world, ready=True)
    wire = _a2a_wire(world)
    params = {"message": protocol.text_message(protocol.ROLE_USER, wire["text"], context_id="conv-1", message_id=wire["message_id"]),
              "thread_contract": wire}
    terminal, pending = adapter._prepare_task(params, "p")
    assert terminal is None and pending is not None
    state, text = adapter._finalize_task(pending, *adapter._await_reply(pending))  # the HTTP waiter gives up
    assert state == protocol.STATE_FAILED and "did not reply" in text  # transport status for the caller only
    reader = world.cap("linus")
    assert reader.reply_for(wire) is None and "bestaetigt" not in _journal_kinds(reader)
    assert pending["task_id"] in adapter._pending  # waiter detached; the work item was not replaced
    assert adapter.tasks.get(pending["task_id"])["state"] == protocol.STATE_WORKING
    assert not [t for t in _texts(world, "linus-t") if t.startswith("linus → neo:")]
    asyncio.run(adapter.send("conv-1", "echte antwort beta-secret", metadata={"notify": True}))  # model finishes late
    adapter._completion_pool.shutdown(wait=True)
    asyncio.run(adapter.events[-1].on_complete("completed"))
    reply = reader.reply_for(wire)
    assert reply["text"] == "echte antwort [MASKED]" and adapter._pending == {}
    assert adapter.tasks.get(pending["task_id"])["state"] == protocol.STATE_COMPLETED
    assert _texts(world, "linus-t").count("linus → neo: echte antwort [MASKED]") == 1
    _assert_no_synthetic(world)


def _inbox_files_for(world, name):
    d = world.homes[name] / "runtime" / "bot_thread_sync_inbox"
    return list(d.glob("*.json")) if d.exists() else []


def test_native_recipient_without_a_dispatcher_never_marks_processed(world):
    a = world.cap("neo")
    a.send(target="linus", message="x")
    for _ in range(3):
        b = world.cap("linus")
        b.recover()
        assert "inbound_processed" not in _journal_kinds(b)
    assert len(_inbox_files(world)) == 1


def test_native_dispatch_kind_is_persisted_in_the_queue_row(world):
    a = world.cap("neo")
    a.send(target="linus", message="x")
    b = world.cap("linus")
    b.ingest_inbox()
    j = b._sync.journal
    row = [e for e in j.events(j.conversations()[0]) if e["kind"] in {"eingereiht", "versuch"}][-1]
    assert (row["dispatch"], row["dispatch_kind"]) == ("external", "message_agent")
    assert not ({"text", "value"} & set(row))


def test_live_task_shutdown_is_typed_lifecycle_binding_retained_and_restart_yields_the_real_reply_once(world, monkeypatch):
    """Exact reproduction: live task + pending + inbound binding, disconnect while the HTTP waiter blocks."""
    import asyncio
    import concurrent.futures
    import threading
    import tools.bot_thread_sync as sync_mod
    from plugins.platforms.a2a import adapter as adapter_mod, protocol
    monkeypatch.setattr(sync_mod, "COMPLETION_LEASE_SECONDS", 100)
    monkeypatch.setattr(adapter_mod, "_reply_timeout", lambda: 30.0)

    def submit(coro, loop):
        fut = concurrent.futures.Future()
        fut.set_result(asyncio.run(coro))
        return fut

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    adapter = _receiver_adapter(world, ready=True)
    wire = _a2a_wire(world)
    params = {"message": protocol.text_message(protocol.ROLE_USER, wire["text"], context_id="conv-1", message_id=wire["message_id"]),
              "thread_contract": wire}
    terminal, pending = adapter._prepare_task(params, "p")
    task_id = pending["task_id"]
    assert terminal is None and task_id in adapter._thread_inbound and task_id in adapter._pending
    box = {}
    waiter = threading.Thread(target=lambda: box.setdefault(
        "v", adapter._finalize_task(pending, *adapter._await_reply(pending))))
    waiter.start()  # the HTTP worker blocks waiting for the model
    time.sleep(0.05)
    asyncio.run(adapter.disconnect())
    waiter.join(5)
    assert not waiter.is_alive() and box["v"][0] == protocol.STATE_FAILED  # transport status for the caller only
    # lifecycle is typed: a direct lifecycle outcome is refused by the finalizer in every form
    assert adapter._finalize_task(pending, adapter_mod._Lifecycle("shutdown"), "")[0] == protocol.STATE_FAILED
    assert task_id in adapter._thread_inbound  # durable inbound binding / reply route retained
    persisted = protocol.load_conversation("conv-1", limit=50)
    assert not [m for m in persisted if m.get("role") == "agent"]  # no task reply persisted
    assert adapter.tasks.get(task_id)["state"] != protocol.STATE_COMPLETED
    reader = world.cap("linus")
    assert reader.reply_for(wire) is None and "bestaetigt" not in _journal_kinds(reader)
    assert reader._sync.journal.dispatch_state("conv-1", "msg-1") == "ACCEPTED"  # recoverable, nonterminal
    assert not any(marker in json.dumps(persisted) for marker in SYNTHETIC)
    _assert_no_synthetic(world)
    # process restart: the model is re-driven and the REAL reply is produced exactly once
    adapter2 = _receiver_adapter(world, ready=True)
    b = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    b._sync.clock = lambda: time.time() + 150
    b.recover()
    assert len(adapter2.events) == 1
    asyncio.run(adapter2.send("conv-1", "echte antwort beta-secret", metadata={"notify": True}))
    adapter2._completion_pool.shutdown(wait=True)
    asyncio.run(adapter2.events[-1].on_complete("completed"))
    assert b.reply_for(wire)["text"] == "echte antwort [MASKED]"
    assert _texts(world, "linus-t").count("linus → neo: echte antwort [MASKED]") == 1
    _assert_no_synthetic(world)
    assert not any(marker in json.dumps(protocol.load_conversation("conv-1", limit=50)) for marker in SYNTHETIC)


def test_streaming_client_disconnect_is_typed_nonterminal_and_the_late_genuine_reply_wins_once(world, monkeypatch):
    """`_rpc_message_stream` reproduction: the SSE client resets the connection mid-stream."""
    import asyncio
    import concurrent.futures
    from types import SimpleNamespace
    from plugins.platforms.a2a import adapter as adapter_mod, protocol

    def submit(coro, loop):
        fut = concurrent.futures.Future()
        fut.set_result(asyncio.run(coro))
        return fut

    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe", submit)
    adapter = _receiver_adapter(world, ready=True)
    outcomes = []
    real_record = adapter._record_outcome
    adapter._record_outcome = lambda *a, **k: (outcomes.append(a), real_record(*a, **k))[1]

    class Wire:
        def write(self, data):
            raise ConnectionResetError("client went away")

        def flush(self):
            pass

    handler = SimpleNamespace(send_response=lambda *a: None, send_header=lambda *a: None,
                              end_headers=lambda: None, wfile=Wire())
    wire = _a2a_wire(world)
    params = {"message": protocol.text_message(protocol.ROLE_USER, wire["text"], context_id="conv-1", message_id=wire["message_id"]),
              "thread_contract": wire}
    adapter._rpc_message_stream(handler, "1", params, "p")
    (task_id,) = list(adapter._pending)  # waiter detached, the work item and its future are NOT dropped
    assert outcomes == [] and task_id in adapter._thread_inbound  # no _record_outcome; binding retained
    assert adapter.tasks.get(task_id)["state"] == protocol.STATE_WORKING
    assert not [m for m in protocol.load_conversation("conv-1", limit=50) if m.get("role") == "agent"]
    reader = world.cap("linus")
    assert reader.reply_for(wire) is None and "bestaetigt" not in _journal_kinds(reader)
    assert reader._sync.journal.dispatch_state("conv-1", "msg-1") == "ACCEPTED"
    _assert_no_synthetic(world)
    asyncio.run(adapter.send("conv-1", "echte antwort beta-secret", metadata={"notify": True}))  # model finishes
    adapter._completion_pool.shutdown(wait=True)
    asyncio.run(adapter.events[-1].on_complete("completed"))
    assert len(outcomes) == 1 and outcomes[0][3] == protocol.STATE_COMPLETED  # genuine outcome, exactly once
    assert reader.reply_for(wire)["text"] == "echte antwort [MASKED]" and adapter._pending == {}
    assert _texts(world, "linus-t").count("linus → neo: echte antwort [MASKED]") == 1
    _assert_no_synthetic(world)
    assert not any(m in json.dumps(protocol.load_conversation("conv-1", limit=50)) for m in SYNTHETIC)


def _spoof_wire(**over):
    from tests.tools.bot_thread_support import envelope
    from tools.bot_thread_sync import mask_text
    m = mask_text("hi")
    base = dict(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x", transport="a2a",
                sender="neo", recipient="linus")
    return envelope(**{**base, **over}).to_wire()  # an attacker can recompute the unkeyed digest


def test_cross_tenant_spoof_is_blocked_with_zero_side_effects(world):
    b = world.cap("linus")
    b._sync.attest("a2a_admission")
    b._peers["p"] = {**_ALLOW, "tenant": "tenant-other"}  # authenticated peer belongs to another tenant
    res = b.receive_wire(_spoof_wire(), peer="p", external_dispatch=True)
    assert (res.status, res.reason) == ("blocked", "tenant_abweichend")
    b._peers["p"] = _ALLOW  # peer is ours, but the message asserts a different tenant
    res = b.receive_wire(_spoof_wire(tenant="tenant-other"), peer="p", external_dispatch=True)
    assert (res.status, res.reason) == ("blocked", "tenant_abweichend")
    assert world.egress == [] and not (world.homes["linus"] / "runtime" / "bot_thread_sync" / "conv-1").exists()
    ok = b.receive_wire(_spoof_wire(), peer="p")  # valid same-tenant admission still works
    assert ok.status == "received"


def test_peer_without_a_configured_tenant_is_never_trusted(world):
    ctx = make_grant(world.homes["linus"], profile="linus", thread="linus-t", live="live-b")
    cap = prov.build_thread_sync(*ctx, evidence=registry(), peers={
        "p": {"profile": "neo", "source_thread": _ALLOW["source_thread"]},             # no tenant
        "q": {**_ALLOW, "tenant": "  "}, "ok": dict(_ALLOW)})
    assert set(cap._peers) == {"ok"}
    cap._sync.attest("a2a_admission")
    assert cap.receive_wire(_spoof_wire(), peer="p").reason == "absender_unbelegt"


def _scheduled_live(world, monkeypatch):
    import asyncio
    import concurrent.futures
    from plugins.platforms.a2a import protocol
    monkeypatch.setattr("plugins.platforms.a2a.adapter.asyncio.run_coroutine_threadsafe",
                        lambda coro, loop: (lambda f: (f.set_result(asyncio.run(coro)), f)[1])(concurrent.futures.Future()))
    adapter = _receiver_adapter(world, ready=True)
    wire = _a2a_wire(world)
    params = {"message": protocol.text_message(protocol.ROLE_USER, wire["text"], context_id="conv-1", message_id=wire["message_id"]),
              "thread_contract": wire}
    terminal, pending = adapter._prepare_task(params, "p")
    assert terminal is None
    return adapter, wire, params, pending


def test_crash_after_model_completed_before_reply_is_durable_reruns_and_never_duplicates(world, monkeypatch):
    """Review reproduction: on_complete('completed') used to write DONE before the reply existed."""
    import asyncio
    import tools.bot_thread_sync as sync_mod
    from plugins.platforms.a2a import protocol
    monkeypatch.setattr(sync_mod, "COMPLETION_LEASE_SECONDS", 100)
    adapter, wire, params, pending = _scheduled_live(world, monkeypatch)

    class DeadPool:  # the process dies before the reply finalizer ever runs
        def submit(self, *a, **k):
            return None

    adapter._completion_executor = lambda: DeadPool()
    adapter._arm_late_finalization(pending)  # the HTTP waiter has already detached
    asyncio.run(adapter.send("conv-1", "echte antwort", metadata={"notify": True}))  # model answers
    asyncio.run(adapter.events[-1].on_complete("completed"))                           # gateway: model completed
    reader = world.cap("linus")
    kinds = _journal_kinds(reader)
    assert "inbound_processed" not in kinds and reader.reply_for(wire) is None         # NOT terminal, no reply
    assert reader._sync.journal.dispatch_state("conv-1", "msg-1") == "COMPLETED"
    # restart: replay is not a duplicate; the model is re-run and the reply becomes durable exactly once
    adapter2 = _receiver_adapter(world, ready=True)
    cap = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    cap._sync.clock = lambda: time.time() + 150
    cap.recover()
    assert len(adapter2.events) == 1
    asyncio.run(adapter2.send("conv-1", "echte antwort", metadata={"notify": True}))
    adapter2._completion_pool.shutdown(wait=True)
    asyncio.run(adapter2.events[-1].on_complete("completed"))
    assert "inbound_processed" in _journal_kinds(cap) and cap.reply_for(wire)["text"] == "echte antwort"
    assert _texts(world, "linus-t").count("linus → neo: echte antwort") == 1  # visible reply at-most-once
    replay, _ = adapter2._prepare_task(params, "p")
    assert replay["status"]["state"] == protocol.STATE_COMPLETED and replay["metadata"]["thread_contract"]["text"] == "echte antwort"


def test_crash_after_reply_durable_before_terminal_finalizes_without_rerun_or_second_projection(world, monkeypatch):
    import asyncio
    adapter, wire, params, pending = _scheduled_live(world, monkeypatch)
    real = prov.ThreadSyncCapability.finalize_reply

    def crash_between_reply_and_terminal(self, inbound_wire):
        self._sync.mark_reply_stored({"conversation_id": "conv-1", "message_id": "msg-1", "key": next(
            e["key"] for e in self._sync.journal.events("conv-1") if e["kind"] == "dispatch_pending")})
        return False  # dies before finalize_turn

    monkeypatch.setattr(prov.ThreadSyncCapability, "finalize_reply", crash_between_reply_and_terminal)
    adapter._arm_late_finalization(pending)  # the HTTP waiter has detached
    asyncio.run(adapter.send("conv-1", "echte antwort", metadata={"notify": True}))
    adapter._completion_pool.shutdown(wait=True)
    reader = world.cap("linus")
    assert reader.reply_for(wire) is not None and "inbound_processed" not in _journal_kinds(reader)
    assert reader._sync.journal.dispatch_state("conv-1", "msg-1") == "REPLIED"
    monkeypatch.setattr(prov.ThreadSyncCapability, "finalize_reply", real)
    adapter2 = _receiver_adapter(world, ready=True)
    replay, _ = adapter2._prepare_task(params, "p")  # recovery path: finalized from the durable reply
    assert replay["metadata"]["thread_contract"]["text"] == "echte antwort"
    assert "inbound_processed" in _journal_kinds(world.cap("linus")) and adapter2.events == []  # no rerun
    assert _texts(world, "linus-t").count("linus → neo: echte antwort") == 1


def test_native_dispatch_is_not_terminal_until_its_reply_is_durable(world, monkeypatch):
    runs = []

    def model(profile, home, text):
        runs.append(text)
        return True, "native antwort"

    a = world.cap("neo")
    a.send(target="linus", message="frage")
    real = prov.ThreadSyncCapability.send_reply
    monkeypatch.setattr(prov.ThreadSyncCapability, "send_reply",
                        lambda self, wire, text: (prov.SyncResult("blocked", "kaputt"), None))  # reply cannot be stored
    b = world.cap("linus", native_runner=model)
    assert [(r.status, r.reason) for r in b.ingest_inbox()] == [("queued", "antwort_ausstehend")]
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(b)   # model ran, reply persisted, no terminal
    monkeypatch.setattr(prov.ThreadSyncCapability, "send_reply", real)
    b2 = world.cap("linus", native_runner=model)
    b2.recover()                                                               # finalizes from the stored reply
    assert len(runs) == 1 and "inbound_processed" in _journal_kinds(b2)       # the model is NOT re-run
    assert _texts(world, "linus-t").count("linus → neo: native antwort") == 1


# ---------------------------------------------------------------- long native turn: lease expires mid-run
def _long_turn_setup(world, refresh_factory, monkeypatch, *, on_run=None):
    import tests.tools.bot_thread_support as support
    runs, offset = [], [0.0]
    real = time.time
    skewed = SimpleNamespace(time=lambda: real() + offset[0])

    def long_model(profile, home, text):
        runs.append(text)
        offset[0] = 10_000.0  # the turn outlasts the launch grant's lease: the BROKER's clock advances too
        monkeypatch.setattr(_authority, "time", skewed)
        monkeypatch.setattr(support, "time", skewed)  # fresh grants are issued at the new time
        if on_run:
            on_run()
        return True, "lange antwort beta-secret"

    a = world.cap("neo")
    a.send(target="linus", message="frage")
    b = world.cap("linus", native_runner=long_model, refresh=refresh_factory)
    b._sync.clock = lambda: time.time() + offset[0]
    return runs, b


def test_lease_expiring_during_the_native_turn_persists_the_reply_and_finalizes_with_a_fresh_context(world, monkeypatch):
    runs, b = _long_turn_setup(world, lambda: world.cap("linus"), monkeypatch)
    b.ingest_inbox()  # the expired launch grant records nothing itself; the fresh grant did
    assert len(runs) == 1                                                   # the model ran exactly once
    reply = b._sync.journal.conversations()[0]
    assert "inbound_processed" in _journal_kinds(b)
    assert _texts(world, "linus-t").count("linus → neo: lange antwort [MASKED]") == 1   # masked, projected once
    a = world.cap("neo")
    assert [r.status for r in a.ingest_inbox()] == ["received"]             # the reply reached the sender once
    assert len(runs) == 1


def test_unavailable_fresh_context_holds_the_result_without_any_write_and_never_reruns_the_model(world, monkeypatch):
    runs, b = _long_turn_setup(world, lambda: None, monkeypatch)                          # no authoritative context right now
    before = _tree(world)
    b.ingest_inbox()
    assert "inbound_processed" not in _journal_kinds(b) and not _texts(world, "linus-t")[1:]
    j = b._sync.journal
    conv = j.conversations()[0]
    assert not list((world.homes["linus"] / "runtime" / "bot_thread_sync" / conv).glob("replies/*"))  # no write
    assert b._broker.held_items((str(world.homes["linus"]), "linus", "tenant-1"))
    for _ in range(3):  # refresh still unavailable: neither re-run the model nor write/project anything
        world.cap("linus", native_runner=lambda *a: pytest.fail("model re-run"), refresh=lambda: None).ingest_inbox()
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(b)
    later = world.cap("linus", native_runner=lambda *a: pytest.fail("model re-run"))  # authority returns
    later.recover()                                                          # drains the held result
    assert "inbound_processed" in _journal_kinds(later) and len(runs) == 1
    assert _texts(world, "linus-t").count("linus → neo: lange antwort [MASKED]") == 1
    assert not later._broker.held_items((str(world.homes["linus"]), "linus", "tenant-1"))


@pytest.mark.parametrize("change", [{"tenant": "tenant-other"}, {"live": "someone-elses-session"}])
def test_changed_tenant_or_session_in_the_fresh_context_fails_closed(world, change, monkeypatch):
    runs, b = _long_turn_setup(world, lambda: world.cap("linus", **change), monkeypatch)
    b.ingest_inbox()
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(b)
    assert not [t for t in _texts(world, "linus-t") if t.startswith("linus → neo:") and "lange" in t]  # no projection


# ---------------------------------------------------------------- reply file <-> state: one invariant
class _Crash(BaseException):
    pass


def _crashing_ingest(world, monkeypatch, fault):
    """Run the native turn with a fault injected at one write boundary of the reply commit."""
    import tools.bot_thread_sync as sync_mod
    from tools import pinned_fs
    monkeypatch.setattr(sync_mod, "COMPLETION_LEASE_SECONDS", 100)
    runs = []

    def model(profile, home, text):
        runs.append(text)
        return True, "meine antwort beta-secret"

    a = world.cap("neo")
    a.send(target="linus", message="frage")
    real_write, real_append = pinned_fs.write_atomic, pinned_fs.append_bytes

    def write(fd, name, data, **kw):
        is_reply = name.endswith(".json") and b'"mac"' in data and b'"text"' in data and b'masking' in data
        if is_reply and fault == "before_reply_write":
            raise _Crash()                                    # reply temp file never completed
        out = real_write(fd, name, data, **kw)
        if is_reply and fault == "after_reply_fsync":
            raise _Crash()                                    # reply durable, no metadata yet
        return out

    def append(fd, name, data, **kw):
        if b"dispatch_reply_pending" in data and fault in {"metadata_absent", "metadata_torn"}:
            if fault == "metadata_torn":
                real_append(fd, name, data[: len(data) // 2], **kw)
            raise _Crash()
        return real_append(fd, name, data, **kw)

    monkeypatch.setattr(pinned_fs, "write_atomic", write)
    monkeypatch.setattr(pinned_fs, "append_bytes", append)
    b = world.cap("linus", native_runner=model)
    with pytest.raises(_Crash):
        b.ingest_inbox()
    monkeypatch.setattr(pinned_fs, "write_atomic", real_write)
    monkeypatch.setattr(pinned_fs, "append_bytes", real_append)
    return runs, model


@pytest.mark.parametrize("fault", ["after_reply_fsync", "metadata_absent", "metadata_torn"])
def test_crash_between_durable_reply_and_state_never_reruns_the_model(world, monkeypatch, fault):
    runs, model = _crashing_ingest(world, monkeypatch, fault)
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(world.cap("linus"))
    later = world.cap("linus", native_runner=lambda *a: pytest.fail("model re-run"))
    later._sync.clock = lambda: time.time() + 150           # restart after the lease expired
    for _ in range(2):
        later.recover()
    assert len(runs) == 1 and "inbound_processed" in _journal_kinds(later)
    assert _texts(world, "linus-t").count("linus → neo: meine antwort [MASKED]") == 1   # projected once
    assert [r.status for r in world.cap("neo").ingest_inbox()] == ["received"]         # sender gets it once


def test_crash_before_the_reply_is_durable_reruns_the_model_and_projects_once(world, monkeypatch):
    runs, model = _crashing_ingest(world, monkeypatch, "before_reply_write")
    later = world.cap("linus", native_runner=model)
    later._sync.clock = lambda: time.time() + 150
    later.recover()
    assert len(runs) == 2 and "inbound_processed" in _journal_kinds(later)   # at-least-once: no durable reply yet
    assert _texts(world, "linus-t").count("linus → neo: meine antwort [MASKED]") == 1


@pytest.mark.parametrize("with_row", [True, False])
def test_tampered_reply_fails_closed_without_model_rerun_or_projection(world, monkeypatch, with_row):
    import json as _json
    fault = "metadata_absent" if not with_row else "after_reply_fsync"
    runs, model = _crashing_ingest(world, monkeypatch, fault)
    reply_file = next((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("replies/*.json"))
    record = _json.loads(reply_file.read_text())
    record["text"] = "manipulierte antwort"
    reply_file.write_text(_json.dumps(record))                # tampered: MAC no longer matches
    assert "meine antwort" not in reply_file.read_text()
    later = world.cap("linus", native_runner=lambda *a: pytest.fail("model re-run"))
    later._sync.clock = lambda: time.time() + 150
    later.recover()
    assert [(r.status, r.reason) for r in later.ingest_inbox()] == [("queued", "antwort_manipuliert")]
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(later)
    assert not [t for t in _texts(world, "linus-t") if "antwort" in t.split(":", 1)[-1] and t.startswith("linus → neo:")]


def test_every_model_entry_point_checks_for_a_durable_reply_first(world):
    a = world.cap("neo")
    a.send(target="linus", message="frage")
    b = world.cap("linus", native_runner=lambda *a: pytest.fail("model started"))
    wire = ThreadEnvelope.from_wire(next(iter(
        __import__("json").loads(f.read_text()) for f in (world.homes["linus"] / "runtime" /
                                                          "bot_thread_sync_inbox").glob("*.json"))))
    res = b.receive_wire(wire.to_wire(), external_dispatch=True)
    ticket = res.ticket
    b.store_reply_pending(wire.to_wire(), "bereits fertig")             # a durable reply file exists (row may be missing)
    assert b._sync.dispatch_begin(ticket) is False                       # last-line guard: no model claim
    assert b._sync.receive(wire, external_dispatch=True).reason == "antwort_ausstehend"


# ---------------------------------------------------------------- reply evidence: send_reply itself is a commit point
def _reply_crash(world, monkeypatch, boundary):
    """A2A turn whose reply finalization dies at one boundary of mask -> send_reply -> finalize_reply."""
    import asyncio
    import tools.bot_thread_sync as sync_mod
    from tools import pinned_fs
    monkeypatch.setattr(sync_mod, "COMPLETION_LEASE_SECONDS", 100)
    adapter, wire, params, pending = _scheduled_live(world, monkeypatch)
    adapter._arm_late_finalization(pending)
    real_append = pinned_fs.append_bytes

    def append(fd, name, data, **kw):
        marks = {"claim_sender": b'"stage": "sender_projection"' in data and b'"kind": "claim"' in data,
                 "intent_sender": b'"stage": "sender_projection"' in data and b'"kind": "stage_intent"' in data,
                 "done_sender": b'"stage": "sender_projection"' in data and b'"kind": "stage_done"' in data,
                 "bestaetigt": b'"kind": "bestaetigt"' in data}
        if marks.get(boundary):
            raise _Crash()
        return real_append(fd, name, data, **kw)

    monkeypatch.setattr(pinned_fs, "append_bytes", append)
    real_finalize = prov.ThreadSyncCapability.finalize_reply
    if boundary == "before_finalize_reply":
        monkeypatch.setattr(prov.ThreadSyncCapability, "finalize_reply", lambda self, w: False)
    asyncio.run(adapter.send("conv-1", "echte antwort beta-secret", metadata={"notify": True}))
    adapter._completion_pool.shutdown(wait=True)
    monkeypatch.setattr(prov.ThreadSyncCapability, "finalize_reply", real_finalize)  # the restarted process
    asyncio.run(adapter.events[-1].on_complete("completed"))        # gateway: model completed, nothing terminal
    monkeypatch.setattr(pinned_fs, "append_bytes", real_append)
    return adapter, wire, params


@pytest.mark.parametrize("boundary,finalizable", [
    ("claim_sender", True), ("intent_sender", False), ("done_sender", False),
    ("bestaetigt", True), ("before_finalize_reply", True)])
def test_crash_at_each_reply_boundary_never_reruns_the_model(world, monkeypatch, boundary, finalizable):
    from plugins.platforms.a2a import adapter as _a  # noqa: F401
    adapter, wire, params = _reply_crash(world, monkeypatch, boundary)
    before = world.cap("linus")
    assert "inbound_processed" not in _journal_kinds(before)         # no terminal yet
    adapter2 = _receiver_adapter(world, ready=True)                    # restart: fresh adapter + capability
    cap = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    cap._sync.clock = lambda: time.time() + 150                        # lease expired
    for _ in range(2):
        cap.recover()
    assert adapter2.events == []                                       # the model was NOT invoked again
    replies = [t for t in _texts(world, "linus-t") if t.startswith("linus → neo:")]
    assert len(replies) <= 1                                           # visible reply at-most-once
    if finalizable:
        j = cap._sync.journal
        assert "inbound_processed" in _journal_kinds(cap) and len(replies) == 1, (
            j.dispatch_state("conv-1", "msg-1"), j.reply_status("conv-1", "msg-1", replier="linus"),
            [(e["kind"], e.get("reason")) for e in j.events("conv-1")][-12:], cap.flush_pending_replies())
        contract = cap.reply_for(wire)
        a = world.cap("neo")
        original = ThreadEnvelope.from_wire(wire)
        first = a.receive_reply(contract, original=original, text=contract["text"])
        second = a.receive_reply(contract, original=original, text=contract["text"])
        assert first[0].status == "received" and second[1] is None    # the sender receives it exactly once
    replay, _ = adapter2._prepare_task(params, "p")
    assert "duplicate_nachricht" not in json.dumps(replay) or finalizable
    assert adapter2.events == []


def test_tampered_durable_reply_projection_fails_closed_without_model_rerun(world, monkeypatch):
    adapter, wire, params = _reply_crash(world, monkeypatch, "before_finalize_reply")
    proj = next((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("projections/*.json"))
    files = sorted((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("projections/*.json"))
    reply_file = next(f for f in files if json.loads(f.read_text()).get("sender") == "linus")
    data = json.loads(reply_file.read_text())
    data["text"] = "manipuliert"                                       # digest no longer matches the text
    reply_file.write_text(json.dumps(data))
    adapter2 = _receiver_adapter(world, ready=True)
    cap = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    cap._sync.clock = lambda: time.time() + 150
    cap.recover()
    res, _ = adapter2._prepare_task(params, "p")
    assert adapter2.events == [] and "inbound_processed" not in _journal_kinds(cap)
    assert cap._sync.journal.reply_status("conv-1", "msg-1", replier="linus") == "tampered"


# ---------------------------------------------------------------- keyed storage authenticity of reply artifacts
def _reply_projection_file(world):
    root = world.homes["linus"] / "runtime" / "bot_thread_sync"
    return next(f for f in sorted(root.rglob("projections/*.json")) if json.loads(f.read_text()).get("sender") == "linus")


def _forge(world, mutate):
    import hashlib
    f = _reply_projection_file(world)
    data = json.loads(f.read_text())
    mutate(data)
    data["masking"]["digest"] = hashlib.sha256(data["text"].encode()).hexdigest()  # attacker recomputes the plain digest
    f.write_text(json.dumps(data))


def _recover_and_check_fail_closed(world, wire):
    adapter2 = _receiver_adapter(world, ready=True)
    cap = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    cap._sync.clock = lambda: time.time() + 150
    before = len([t for t in _texts(world, "linus-t") if t.startswith("linus → neo:")])
    for _ in range(2):
        cap.recover()
    assert adapter2.events == []                                              # zero model reruns
    assert len([t for t in _texts(world, "linus-t") if t.startswith("linus → neo:")]) == before  # zero projections
    assert "inbound_processed" not in _journal_kinds(cap)
    return cap


@pytest.mark.parametrize("field,mutate", [
    ("text", lambda d: d.__setitem__("text", "gefaelschte antwort")),
    ("tenant", lambda d: d.__setitem__("tenant", "tenant-evil")),
    ("parent", lambda d: d.__setitem__("parent_message_id", "other-parent")),
    ("recipient", lambda d: d.__setitem__("recipient", "mallory")),
    ("target_thread", lambda d: d["target_thread"].__setitem__("thread_id", "evil-t")),
    ("source_thread", lambda d: d["source_thread"].__setitem__("chat_id", "evil-chat")),
    ("art", lambda d: d.__setitem__("art", "arbeitsauftrag")),
    ("transport", lambda d: d.__setitem__("transport", "message_agent")),
    ("masking_classes", lambda d: d["masking"].__setitem__("classes", ["private_key"])),
    ("mac_stripped", lambda d: d.pop("_mac")),
])
def test_forged_reply_projection_is_tampered_even_with_a_recomputed_plain_digest(world, monkeypatch, field, mutate):
    adapter, wire, params = _reply_crash(world, monkeypatch, "before_finalize_reply")
    _forge(world, mutate)
    cap = _recover_and_check_fail_closed(world, wire)
    assert cap._sync.journal.reply_status("conv-1", "msg-1", replier="linus") == "tampered"


def test_forged_pending_reply_file_with_recomputed_digest_is_tampered(world, monkeypatch):
    import hashlib
    runs, model = _crashing_ingest(world, monkeypatch, "after_reply_fsync")
    f = next((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("replies/*.json"))
    data = json.loads(f.read_text())
    data["text"] = "gefaelscht"
    data["text_digest"] = hashlib.sha256(b"gefaelscht").hexdigest()          # plain digest recomputed, no key
    f.write_text(json.dumps(data))
    later = world.cap("linus", native_runner=lambda *a: pytest.fail("model re-run"))
    later._sync.clock = lambda: time.time() + 150
    later.recover()
    assert later._sync.journal.reply_status(f.parent.parent.name, f.stem, replier="linus") == "tampered"
    assert len(runs) == 1 and "inbound_processed" not in _journal_kinds(later)


def test_secret_rotation_or_unavailability_fails_closed_and_stays_recoverable(world, monkeypatch):
    adapter, wire, params = _reply_crash(world, monkeypatch, "before_finalize_reply")
    original = prov.profile_secret_values
    monkeypatch.setattr(prov, "profile_secret_values", lambda home: ())            # secret scope unavailable
    cap = _recover_and_check_fail_closed(world, wire)
    assert cap._sync.journal.reply_status("conv-1", "msg-1", replier="linus") == "unavailable"
    monkeypatch.setattr(prov, "profile_secret_values", lambda home: ("rotated-secret",))  # rotated: other key
    cap = _recover_and_check_fail_closed(world, wire)
    assert cap._sync.journal.reply_status("conv-1", "msg-1", replier="linus") == "tampered"
    monkeypatch.setattr(prov, "profile_secret_values", original)                    # same secret returns
    adapter2 = _receiver_adapter(world, ready=True)
    fixed = world.cap("linus", dispatcher=adapter2.dispatch_thread_message)
    fixed._sync.clock = lambda: time.time() + 150
    fixed.recover()
    assert "inbound_processed" in _journal_kinds(fixed) and adapter2.events == []   # finalized, no model run


def test_another_profile_or_tenant_secret_cannot_validate_the_artifact(world, monkeypatch):
    from tools.bot_thread_sync import Journal, derive_storage_key
    adapter, wire, params = _reply_crash(world, monkeypatch, "before_finalize_reply")
    home = world.homes["linus"]
    assert derive_storage_key(("beta-secret",), "tenant-1", "linus") != derive_storage_key(("beta-secret",), "tenant-2", "linus")
    assert derive_storage_key(("beta-secret",), "tenant-1", "linus") != derive_storage_key(("beta-secret",), "tenant-1", "neo")
    assert derive_storage_key((), "tenant-1", "linus") is None
    for secrets, tenant, profile in ((("alpha-secret",), "tenant-1", "neo"), (("beta-secret",), "tenant-2", "linus")):
        foreign = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)
        foreign.key_provider = lambda s=secrets, t=tenant, p=profile: derive_storage_key(s, t, p)
        assert foreign.reply_status("conv-1", "msg-1", replier="linus") == "tampered"
    own = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)
    own.key_provider = lambda: derive_storage_key(("beta-secret",), "tenant-1", "linus")
    assert own.reply_status("conv-1", "msg-1", replier="linus") == "valid"        # same secret survives restart


def test_storage_mac_never_crosses_the_network_boundary_or_the_key_lands_on_disk(world, monkeypatch):
    adapter, wire, params = _reply_crash(world, monkeypatch, "before_finalize_reply")
    contract = world.cap("linus").reply_for(wire)
    assert contract is not None and "_mac" not in contract and "mac" not in contract
    ThreadEnvelope.from_wire(contract)                                              # clean network envelope
    assert "_mac" in json.loads(_reply_projection_file(world).read_text())          # stored locally only
    for f in world.homes["linus"].rglob("*"):
        if f.is_file():
            assert b"beta-secret" not in f.read_bytes()                              # the key material is never stored


def test_altered_a2a_replay_is_a_conflict_and_a_tampered_stored_projection_blocks_replays(world):
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    assert b.receive_wire(_a2a_wire(world), peer="p", external_dispatch=True).status == "admitted"
    egress = list(world.egress)
    res = b.receive_wire(_a2a_wire(world, text="ganz anders"), peer="p", external_dispatch=True)
    assert (res.status, res.reason) == ("blocked", "message_id_conflict") and world.egress == egress
    proj = next((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("projections/msg-1.json"))
    data = json.loads(proj.read_text())
    data["text"] = "manipuliert"
    proj.write_text(json.dumps(data))
    res = b.receive_wire(_a2a_wire(world), peer="p", external_dispatch=True)
    assert (res.status, res.reason) == ("blocked", "projektion_manipuliert")


def test_pending_reply_copied_to_another_conversation_is_tampered_and_never_promoted(world, monkeypatch):
    import shutil
    runs, model = _crashing_ingest(world, monkeypatch, "after_reply_fsync")
    root = world.homes["linus"] / "runtime" / "bot_thread_sync"
    src = next(root.rglob("replies/*.json"))
    conv1, mid = src.parent.parent.name, src.stem
    j = world.cap("linus")._sync.journal
    other = "c" + "0" * 31
    with j._locked(other):
        (root / other / "replies").mkdir()
    shutil.copy(src, root / other / "replies" / f"{mid}.json")
    assert j.reply_status(other, mid, replier="linus") == "tampered"
    assert j.load_pending_reply(other, mid) is None
    assert not [e for e in j.events(other) if e["kind"].startswith("dispatch_")]      # nothing promoted there
    assert j.reply_status(conv1, mid, replier="linus") == "valid"                      # the original still works
    # forging the stored conversation id inside the copy breaks the MAC instead
    forged = json.loads((root / other / "replies" / f"{mid}.json").read_text())
    forged["conversation_id"] = other
    (root / other / "replies" / f"{mid}.json").write_text(json.dumps(forged))
    assert j.reply_status(other, mid, replier="linus") == "tampered"


def test_authenticated_reply_written_for_another_tenant_or_profile_is_never_used(world, monkeypatch):
    runs, model = _crashing_ingest(world, monkeypatch, "after_reply_fsync")
    src = next((world.homes["linus"] / "runtime" / "bot_thread_sync").rglob("replies/*.json"))
    mid, conv = src.stem, src.parent.parent.name
    wire = world.cap("linus")._sync.journal.load_projection(conv, mid).to_wire()
    cap = world.cap("linus")
    record = cap._sync.journal.load_pending_reply(conv, mid)
    assert record["tenant"] == "tenant-1" and record["replier"] == "linus"
    other_tenant = world.cap("linus", tenant="tenant-2")
    assert other_tenant.flush_pending_reply(wire) is False


def test_outbound_resend_of_the_stored_reply_is_canonical_not_a_conflicting_variant(world):
    """Re-sending after a crash uses the stored (already masked) reply; it can never conflict with itself."""
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    assert b.receive_wire(wire, peer="p").status == "received"
    first = b.send_reply(wire, "antwort beta-secret")[1]
    again = b.send_reply(wire, "ganz andere antwort")[1]
    assert first.message_id == again.message_id and again.text == first.text      # first durable reply wins
    j = b._sync.journal
    result, canonical = j.compare_or_create_projection(first)
    assert result == "EXACT_REPLAY" and canonical.digest == first.digest
    altered = ThreadEnvelope(**{**first.__dict__, "text": "gefaelscht"})
    assert j.compare_or_create_projection(altered)[0] == "CONFLICT"


def test_smuggled_masking_field_over_the_network_is_rejected_before_any_side_effect(world):
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    wire["masking"] = {**wire["masking"], "extra": "PLAINTEXT_SENTINEL_99"}
    res = b.receive_wire(wire, peer="p", external_dispatch=True)
    assert (res.status, res.reason) == ("blocked", "envelope_ungueltig")
    assert world.egress == [] and not (world.homes["linus"] / "runtime" / "bot_thread_sync" / "conv-1").exists()
    for f in world.homes["linus"].rglob("*"):
        if f.is_file():
            assert b"PLAINTEXT_SENTINEL_99" not in f.read_bytes()


# ---------------------------------------------------------------- routes: profile-secret MAC, no sidecar key
def _old_style_mac(key_bytes, record):
    import hashlib
    import hmac as _hmac
    body = json.dumps({k: record[k] for k in sorted(record) if k != "mac"}, sort_keys=True).encode()
    return _hmac.new(key_bytes, body, hashlib.sha256).hexdigest()


def test_route_forged_with_a_planted_sidecar_key_is_rejected_and_the_sidecar_is_removed(world):
    a2, conv, msg = _queue_and_rebuild(world)
    path = _route_file(world, conv, msg)
    record = json.loads(path.read_text())
    record["target_thread"]["thread_id"] = "attacker-t"
    sidecar_key = b"attacker-chosen-key-0123456789abcd"
    root = world.homes["neo"] / "runtime" / "bot_thread_sync"
    (root / "route_key.bin").write_bytes(sidecar_key)                                    # attacker-readable/writable
    record["mac"] = _old_style_mac(sidecar_key, record)                                  # forged "valid" MAC
    path.write_text(json.dumps(record))
    a3 = world.cap("neo")                                                                 # restart
    assert not (root / "route_key.bin").exists()                                          # legacy sidecar removed
    with pytest.raises(ValueError, match="route_manipuliert"):
        a3._sync.journal.load_route(conv, msg)
    a3._sync.clock = lambda: time.time() + 30
    a3.recover()
    assert _inbox_files(world) == []                                                      # nothing delivered
    assert list(root.rglob("route_key.bin")) == []


def test_valid_route_survives_restart_with_the_same_secret_and_fails_for_other_secrets_tenants(world):
    from tools.bot_thread_sync import Journal, derive_storage_key
    a2, conv, msg = _queue_and_rebuild(world)
    home = world.homes["neo"]
    own = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)
    own.key_provider = lambda: derive_storage_key(("alpha-secret",), "tenant-1", "neo")
    assert own.load_route(conv, msg)["recipient"] == "linus"                              # same secret: works
    for secrets, tenant, profile in ((("other",), "tenant-1", "neo"), (("alpha-secret",), "tenant-2", "neo"),
                                     (("alpha-secret",), "tenant-1", "linus")):
        foreign = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)
        foreign.key_provider = lambda s=secrets, t=tenant, p=profile: derive_storage_key(s, t, p)
        with pytest.raises(ValueError, match="route_manipuliert"):
            foreign.load_route(conv, msg)
    gone = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)
    gone.key_provider = lambda: None
    with pytest.raises(ValueError, match="route_unbelegt"):                               # secret scope unavailable
        gone.load_route(conv, msg)


def test_route_copied_to_another_message_or_conversation_never_validates(world):
    import shutil
    a2, conv, msg = _queue_and_rebuild(world)
    src = _route_file(world, conv, msg)
    other_msg = src.with_name("someothermsg.json")
    shutil.copy(src, other_msg)
    with pytest.raises(ValueError, match="route_manipuliert"):
        a2._sync.journal.load_route(conv, "someothermsg")


def test_no_local_sidecar_keys_are_created_by_the_feature(world):
    a = world.cap("neo")
    a.send(target="linus", message="x")
    for home in world.homes.values():
        names = {p.name for p in home.rglob("*") if p.is_file()}
        assert not {n for n in names if n.endswith(".bin") or "key" in n.lower()}


# ----------------------------------------------------------------------------------------------------------
# Authority at EVERY mutation / side effect (method-entry guard alone is insufficient)
# ----------------------------------------------------------------------------------------------------------
import inspect
from types import SimpleNamespace

from tools import bot_thread_authority as _authority
from tests.tools.bot_thread_support import envelope as _envelope

_NOT_PRIVILEGED = {"context", "revoke", "same_identity"}   # data-only / revocation itself


def _tree(world):
    out = {}
    for home in world.homes.values():
        for p in sorted(home.rglob("*")):
            if p.is_file():
                out[str(p)] = p.read_bytes()
    return out


def _lose(how, monkeypatch, cap):
    if how == "revoke":
        cap.revoke()
    else:  # wall-clock lease expiry as seen by the broker; the lease is never extended
        real = time.time
        monkeypatch.setattr(_authority, "time", SimpleNamespace(time=lambda: real() + 10_000))
    return lambda: monkeypatch.setattr(_authority, "time", time)


def test_every_public_capability_method_is_authority_guarded_or_explicitly_unprivileged():
    public = [n for n, f in inspect.getmembers(prov.ThreadSyncCapability, inspect.isfunction)
              if not n.startswith("_")]
    unguarded = [n for n in public if n not in _NOT_PRIVILEGED and not hasattr(getattr(prov.ThreadSyncCapability, n),
                                                                                "__wrapped__")]
    assert unguarded == []


@pytest.mark.parametrize("how", ["revoke", "expire"])
def test_all_public_methods_after_loss_change_nothing_and_a_running_dispatch_stays_running(world, monkeypatch, how):
    b = world.cap("linus")
    b._peers["p"] = _ALLOW
    b._sync.attest("a2a_admission")
    wire = _a2a_wire(world)
    res = b.receive_wire(wire, peer="p", external_dispatch=True)
    assert res.status == "admitted"
    ticket = res.ticket
    assert b.dispatch_begin(ticket) and b._sync.journal.dispatch_state("conv-1", "msg-1") == "RUNNING"
    args = {
        "send": dict(target="neo", message="x"), "receive_wire": ((wire,), {"peer": "p"}),
        "dispatch_begin": ((ticket,), {}), "dispatch_finish": ((ticket,), {}),
        "store_reply_pending": ((wire, "t"), {}), "flush_pending_reply": ((wire,), {}),
        "flush_pending_replies": ((), {}), "finalize_reply": ((wire,), {}),
        "dispatch_accepted": ((ticket,), {}), "dispatch_release": ((ticket,), {}),
        "receive_reply": ((wire,), {"original": _envelope(), "text": "x"}),
        "dispatch_started": ((ticket,), {}), "ack_dispatch": ((ticket,), {}), "abort_dispatch": ((ticket,), {}),
        "send_reply": ((wire, "t"), {}), "reply_for": ((wire,), {}), "pending_replies": ((), {}),
        "poll_replies": ((), {}), "next_due_delay": ((), {}), "recover": ((), {}), "ingest_inbox": ((), {}),
        "attest": (("egress",), {}),
    }
    public = {n for n, f in inspect.getmembers(prov.ThreadSyncCapability, inspect.isfunction)
              if not n.startswith("_")} - _NOT_PRIVILEGED
    assert public == set(args), public ^ set(args)          # a new public method must join the matrix
    restore = _lose(how, monkeypatch, b)
    before, egress = _tree(world), list(world.egress)
    for name, spec in args.items():
        a, k = spec if isinstance(spec, tuple) else ((), spec)
        getattr(b, name)(*a, **k)                            # must not raise, must not write
    assert _tree(world) == before and world.egress == egress
    # the exact review reproduction: RUNNING + loss + ack stays RUNNING / nonterminal
    # Restore the real clock before minting an independent inspection grant.
    if how == "expire":
        monkeypatch.setattr(_authority, "time", SimpleNamespace(time=time.time))
    fresh = world.cap("linus")
    if how == "expire":
        real = time.time
        monkeypatch.setattr(_authority, "time", SimpleNamespace(time=lambda: real() + 10_000))
    assert fresh._sync.journal.dispatch_state("conv-1", "msg-1") == "RUNNING"
    assert b.ack_dispatch(ticket) is False and fresh._sync.journal.dispatch_state("conv-1", "msg-1") == "RUNNING"


@pytest.mark.parametrize("how", ["revoke", "expire"])
@pytest.mark.parametrize("callback", ["target", "secrets", "owner", "delivery"])
def test_loss_inside_a_blocking_callback_causes_zero_later_mutation(world, monkeypatch, how, callback):
    a = world.cap("neo")
    snaps = []

    def trip():
        snaps.append((_tree(world), len(world.egress)))
        _lose(how, monkeypatch, a)

    def once(fn):
        state = {"n": 0}

        def wrapper(*args, **kw):
            if state["n"] == 0:
                state["n"] = 1
                trip()
            return fn(*args, **kw)
        return wrapper

    if callback == "target":
        monkeypatch.setattr(prov, "_target", once(prov._target))
    elif callback == "secrets":
        monkeypatch.setattr(prov, "profile_secret_values", once(prov.profile_secret_values))
    elif callback == "owner":
        monkeypatch.setattr(prov, "_active_owner", once(prov._active_owner))
    elif callback == "egress":
        monkeypatch.setattr(bld, "_send_canonical_thread_message", once(bld._send_canonical_thread_message))
    else:
        monkeypatch.setattr(prov, "_deliver_from_route", once(prov._deliver_from_route))
    res = a.send(target="linus", message="hello")
    assert snaps, "the injected callback never ran"
    assert (res.status, res.reason) != ("sent", "") or callback in {"egress", "delivery"}
    tree_at_loss, egress_at_loss = snaps[0]
    final_tree = _tree(world)
    if callback == "delivery":
        # Delivery is the irreversible boundary: once it starts authorized, the
        # surrounding transaction must durably terminalize rather than replay it.
        assert res.status == "sent" and final_tree != tree_at_loss
        baseline = final_tree
    else:
        assert final_tree == tree_at_loss                    # zero durable change before handoff
        baseline = tree_at_loss
    assert len(world.egress) == egress_at_loss or callback == "egress"
    after = a.send(target="linus", message="again")
    assert after.reason == "autoritaet_widerrufen" and _tree(world) == baseline


def test_slow_target_plus_revoke_in_current_secrets_reproduction_writes_nothing(world, monkeypatch):
    a = world.cap("neo")
    before = _tree(world)
    real_secrets = prov.profile_secret_values

    def slow_target(root, target):
        a.revoke()                                            # lease lost while the resolver "blocks"
        return ("linus", world.homes["linus"], {"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"})

    monkeypatch.setattr(prov, "_target", slow_target)
    monkeypatch.setattr(prov, "profile_secret_values", lambda h: real_secrets(h))
    assert a.send(target="linus", message="x").reason == "autoritaet_widerrufen"
    assert _tree(world) == before and world.egress == []

    b = world.cap("neo")
    before = _tree(world)
    at_loss = []

    def revoking_secrets(home):
        at_loss.append(_tree(world))
        b.revoke()
        return ("alpha-secret",)

    monkeypatch.setattr(prov, "profile_secret_values", revoking_secrets)
    assert b.send(target="linus", message="x").reason == "autoritaet_widerrufen"
    assert at_loss and _tree(world) == at_loss[0] and world.egress == []


def test_revoked_launch_grant_during_the_native_turn_still_persists_through_a_fresh_grant_once(world, monkeypatch):
    holder = {}
    runs, b = _long_turn_setup(world, lambda: world.cap("linus"), monkeypatch, on_run=lambda: holder["b"].revoke())
    holder["b"] = b
    b.ingest_inbox()  # the expired launch grant records nothing itself; the fresh grant did
    assert len(runs) == 1 and "inbound_processed" in _journal_kinds(b)
    assert _texts(world, "linus-t").count("linus → neo: lange antwort [MASKED]") == 1


def test_native_dispatch_without_a_refresh_path_never_runs_the_model(world):
    cap = world.cap("linus", native_runner=lambda *a: pytest.fail("model must not run"))
    assert "message_agent" in cap._sync.dispatchers
    from tools.bot_thread_provider import build_thread_sync
    grant, broker = make_grant(world.homes["linus"], profile="linus", thread="linus-t", live="live-b")
    bare = build_thread_sync(grant, broker, evidence=registry(), native_runner=lambda *a: pytest.fail("ran"))
    assert "message_agent" not in bare._sync.dispatchers                      # refresh is mandatory


def test_held_result_is_bounded_ttl_pruned_and_dropped_with_the_broker(world, monkeypatch):
    from tools import bot_thread_authority as authority
    now = [0.0]
    monkeypatch.setattr(authority, "_monotonic", lambda: now[0])
    cap = world.cap("linus")
    broker, ident = cap._broker, ("h", "linus", "t")
    assert all(broker.hold(f"k{i}", ident, i) for i in range(broker.MAX_HELD))
    assert not broker.hold("overflow", ident, 0) and broker.hold("k0", ident, 99)   # bounded; same key replaces
    now[0] = broker.HELD_TTL + 1
    assert broker.held_for("k0", ident) is None and broker.held_items(ident) == []
    assert broker.hold("after-ttl", ident, 1)                                     # expired entries free capacity
    broker.revoke_all()
    assert broker.held_items(ident)                                          # grant revocation keeps the result
    broker._deactivate()
    assert not broker.held_items(ident) and not broker.hold("again", ident, 1)


def test_expired_runner_grants_are_pruned(world, monkeypatch):
    from tools import bot_thread_authority as authority

    now = [authority.time.time()]
    monkeypatch.setattr(authority.time, "time", lambda: now[0])
    cap = world.cap("linus")
    broker = cap._broker
    expired = [world.cap("linus")._grant for _ in range(100)]
    now[0] += 10_000.0

    assert broker.verify(expired[0]) is None
    world.cap("linus")
    assert len(broker._grants) == 1


def test_same_thread_revocation_is_deferred_for_an_irreversible_handoff(world):
    cap = world.cap("linus")
    broker, grant = cap._broker, cap._grant

    with broker.operation(grant):
        with broker.operation(grant, defer_revoke=True):
            cap.revoke()
            assert cap._live() is True
        assert cap._live() is True

    assert cap._live() is False


def test_nested_commits_inherit_outer_admission_time_but_not_after_it(world, monkeypatch):
    from tools import bot_thread_authority as authority

    now = [authority.time.time()]
    monkeypatch.setattr(authority.time, "time", lambda: now[0])
    cap = world.cap("linus", lease=5)
    broker, grant = cap._broker, cap._grant

    with broker.operation(grant):
        with broker.operation(grant, defer_revoke=True):
            now[0] += 6
        with broker.operation(grant):
            assert cap._live() is True  # transaction remains authorized at its admission time

    with pytest.raises(prov.AuthorityLost):
        with broker.operation(grant):
            pass


def _egress_interleave(world, monkeypatch, *, revoke_first):
    """Force the interleaving: a revoke is attempted exactly between the final check and the send."""
    import threading
    a = world.cap("neo")
    entered, release, revoked_done = threading.Event(), threading.Event(), threading.Event()
    sent = []
    real = bld._send_canonical_thread_message

    def slow_send(owner, text):
        entered.set()
        assert release.wait(10)
        sent.append(text)
        return real(owner, text)

    monkeypatch.setattr(bld, "_send_canonical_thread_message", slow_send)
    owner = SimpleNamespace(profile_home=str(world.homes["neo"]), platform="telegram", chat_id="max",
                            thread_id="neo-t")
    payload = {"egress_key": "a" * 64, "sender": "neo", "recipient": "linus", "text": "hallo", "status": "ok"}
    out = {}
    if revoke_first:
        a.revoke()
    worker = threading.Thread(target=lambda: out.setdefault("r", _try(lambda: prov._project(
        owner, payload, lambda: a._broker.operation(a._grant)))))
    worker.start()
    if not revoke_first:
        assert entered.wait(10)                                  # worker is past its final check, inside the send
        revoker = threading.Thread(target=lambda: (a.revoke(), revoked_done.set()))
        revoker.start()
        assert not revoked_done.wait(0.3)                        # revoke must WAIT for the in-flight transaction
        release.set()
        revoker.join(10)
    worker.join(10)
    return a, sent, out["r"], owner


def _try(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        return exc


def test_revoke_racing_the_egress_send_waits_and_the_authorized_send_records_its_receipt(world, monkeypatch):
    a, sent, result, owner = _egress_interleave(world, monkeypatch, revoke_first=False)
    assert len(sent) == 1 and isinstance(result, str)           # authorized in-flight send completed
    done = world.homes["neo"].rglob(f"{'a' * 64}.done")
    assert len(list(done)) == 1 and not a._live()               # revoke took effect right after


def test_revoke_before_the_egress_operation_means_no_send_and_no_files(world, monkeypatch):
    before = _tree(world)
    a, sent, result, owner = _egress_interleave(world, monkeypatch, revoke_first=True)
    assert sent == [] and isinstance(result, prov.AuthorityLost) and _tree(world) == before


def test_revoke_after_sender_projection_waits_for_the_complete_outbound_transaction(world, monkeypatch):
    import threading

    entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
    sent = []

    def slow_send(owner, text):
        sent.append((owner["thread_id"], text))
        entered.set()
        assert release.wait(10)
        return {"success": True, "message_id": "tg-1"}

    monkeypatch.setattr(bld, "_send_canonical_thread_message", slow_send)
    cap = world.cap("neo")
    outcome = {}
    worker = threading.Thread(
        target=lambda: outcome.setdefault("result", cap.send(target="linus", message="hello")))
    worker.start()
    assert entered.wait(10)
    revoker = threading.Thread(target=lambda: (cap.revoke(), revoked.set()))
    revoker.start()
    assert not revoked.wait(0.3)
    release.set()
    worker.join(10)
    revoker.join(10)

    assert outcome["result"].status == "sent" and len(sent) == 1
    inbox = world.homes["linus"] / "runtime" / "bot_thread_sync_inbox"
    assert len(list(inbox.glob("*.json"))) == 1
