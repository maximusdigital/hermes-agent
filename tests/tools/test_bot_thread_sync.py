"""Behaviour contracts for ThreadSync: authority, proofs, claims, masking, crash safety."""
import contextlib
import json
import multiprocessing
import os
import time
from dataclasses import asdict

import pytest

from tools.bot_thread_sync import (
    CLAIM_LEASE_SECONDS, SCANNER_VERSION, EvidenceRegistry, Journal, ThreadEnvelope, ThreadSync, TTL_SECONDS,
    mask_text, verify_masking_proof,
)
from tests.tools.bot_thread_support import (
    ATTEST, REPO, envelope, make_ctx, make_sync, owner_for, registry,
)


class Crash(BaseException):
    """Simulates process death: skips every `except Exception` handler."""


# ---------------------------------------------------------------- masking
@pytest.mark.parametrize("text,cls", [
    ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "private_key"),
    ("key sk_live_abcdefghijklmnop1234", "api_key"),
    ("token=hunter2hunter2", "credential"),
    ("Passwort: geheim123", "credential"),
    ("Karte 4111 1111 1111 1111", "card"),
    ("IBAN DE89 3704 0044 0532 0130 00 bitte", "iban"),
    ("PIN 4711", "pin"), ("cvc=123", "pin"), ("2fa: 654321", "pin"),
    ("passport no: AB1234567", "document"),
])
def test_mask_minimum_classes_and_proof(text, cls):
    result = mask_text(text)
    assert cls in result.classes and "[MASKED]" in result.text
    assert verify_masking_proof(result.text, result.proof())


def test_mask_harmless_name_secret_and_differing_secret_sets():
    a = mask_text("Treffen mit Berlin2024 morgen", secrets=("Berlin2024",))
    assert "Berlin2024" not in a.text and "profile_secret" in a.classes
    # B's secret set is different: A could not know it, so B's rescan must refuse the text.
    leaked = mask_text("Treffen mit Karotte77 morgen", secrets=("Berlin2024",))
    assert verify_masking_proof(leaked.text, leaked.proof(), secrets=("Berlin2024",))
    assert not verify_masking_proof(leaked.text, leaked.proof(), secrets=("Karotte77",))


def test_proof_binds_digest_version_and_spans():
    m = mask_text("token=abcdefgh")
    proof = m.proof()
    assert proof["scanner_version"] == SCANNER_VERSION
    assert not verify_masking_proof(m.text + " x", proof)
    assert not verify_masking_proof(m.text, {**proof, "spans": []})
    assert not verify_masking_proof(m.text, {**proof, "scanner_version": "old"})


# ---------------------------------------------------------------- authority
def test_expired_infinite_or_forged_context_fails_closed(tmp_path):
    now = time.time()
    cases = {
        "owner_veraltet": make_ctx(tmp_path / "x", lease=-1),
        "tenant_unbekannt": make_ctx(tmp_path / "z", tenant=" "),
    }
    inf = make_ctx(tmp_path / "i")
    cases["owner_veraltet#inf"] = type(inf)(**{**asdict(inf), "lease_expires_at": float("inf")})
    wrong_instance = make_ctx(tmp_path / "w", instance="other-runtime")
    cases["owner_abweichend#inst"] = wrong_instance
    for expected, ctx in cases.items():
        sync = make_sync(tmp_path, ctx, name=expected.replace("#", "_"),
                         sender_project=lambda *_: pytest.fail("projected"))
        result = sync.send(envelope())
        assert (result.status, result.reason) == ("blocked", expected.split("#")[0])


def test_tenant_comes_from_context_only(tmp_path):
    sync = make_sync(tmp_path, sender_project=lambda o, p: "r1")
    assert sync.send(envelope(tenant="evil", tenant_source="msg")).reason == "tenant_abweichend"
    ok = make_sync(tmp_path, name="b", sender_project=lambda o, p: "r1", transport=lambda p: None)
    assert ok.send(envelope()).status == "sent"
    assert ok.audit("conv-1")[-1]["tenant"] == "tenant-1"
    assert ok.audit("conv-1")[-1]["tenant_source"] == "gateway_context"


def test_owner_must_match_thread_not_default_same_owner(tmp_path):
    ctx = make_ctx(tmp_path / "a")
    foreign = owner_for(make_ctx(tmp_path / "a", thread="linus-t"))
    sync = make_sync(tmp_path, ctx, owner_resolver=lambda thread: foreign,
                     sender_project=lambda *_: pytest.fail("projected"))
    assert sync.send(envelope()).reason == "owner_abweichend"
    # a sender envelope for a thread that is not the authenticated one is refused outright
    sync2 = make_sync(tmp_path, name="b", sender_project=lambda *_: pytest.fail("projected"))
    other = envelope(source_thread={"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"})
    assert sync2.send(other).reason == "owner_abweichend"


def test_ambiguous_owner_never_projects(tmp_path):
    ctx = make_ctx(tmp_path / "a")
    sync = make_sync(tmp_path, ctx, owner_resolver=lambda t: [owner_for(ctx), owner_for(ctx)],
                     sender_project=lambda *_: pytest.fail("projected"))
    assert sync.send(envelope()).reason == "owner_mehrdeutig"


# ---------------------------------------------------------------- evidence
def test_unattested_registry_blocks_and_each_binding_dimension_matters(tmp_path):
    sync = make_sync(tmp_path, attest=(), sender_project=lambda *_: pytest.fail("projected"))
    assert sync.send(envelope()).reason == "spiegel_unbelegt"
    sync.attest(*ATTEST)
    assert all(sync.evidence.proven(n) for n in ATTEST)
    sync.evidence.bind(instance="other", owner_token=sync.auth.owner_token, turn=sync.auth.turn_id)
    assert not any(sync.evidence.proven(n) for n in ATTEST)  # wrong instance
    sync.evidence.bind(instance=sync.auth.runtime_instance, owner_token="x", turn=sync.auth.turn_id)
    assert not sync.evidence.proven("egress")  # wrong owner
    sync.evidence.bind(instance=sync.auth.runtime_instance, owner_token=sync.auth.owner_token, turn="t2")
    assert not sync.evidence.proven("egress")  # wrong turn


@pytest.mark.parametrize("mutate", [
    lambda e: {**e, "sha256": "0" * 64}, lambda e: {**e, "line": e["line"] + 1},
    lambda e: {**e, "revision": "other"}, lambda e: {**e, "seam": "def nothing_like_this"},
    lambda e: {k: v for k, v in e.items() if k != "file"}])
def test_hash_line_revision_drift_stays_unproven(tmp_path, mutate):
    sync = make_sync(tmp_path)
    reg = sync.evidence
    reg.entries["egress"] = mutate(reg.entries["egress"])
    assert reg.attest("egress") is False and reg.proven("egress") is False


# ---------------------------------------------------------------- outbound / inbound split
def test_outbound_projects_sender_only_then_transports_complete_envelope(tmp_path):
    seen = []
    sync = make_sync(tmp_path, sender_project=lambda o, p: seen.append(("sender", o.thread_id, p["egress_key"])) or "s1",
                     project=lambda *_: pytest.fail("recipient projection must be inbound-only"),
                     transport=lambda p: seen.append(("transport", p["message_id"], p["parent_message_id"])))
    assert sync.send(envelope()).status == "sent"
    assert sync.send(envelope()).status == "sent"  # idempotent
    assert [s[0] for s in seen] == ["sender", "transport"]
    assert seen[0][1] == "neo-t" and len(seen[0][2]) == 64


def test_inbound_roundtrip_preserves_envelope_and_projects_under_recipient_owner(tmp_path):
    out = make_sync(tmp_path, name="a", sender_project=lambda o, p: "s1", transport=lambda p: wires.append(p))
    wires = []
    out.send(envelope(message_id="m2", parent_message_id="m1", is_root=False)) if False else None
    out.journal.append("conv-1", {"kind": "outbound_done", "message_id": "m1", "conversation_id": "conv-1"})
    assert out.send(envelope(message_id="m2", parent_message_id="m1", is_root=False, text="pin=1234 hi")).status == "sent"
    sent = ThreadEnvelope.from_payload(wires[0])
    projected, processed = [], []
    ctx_b = make_ctx(tmp_path / "b", profile="linus", thread="linus-t", live="live-b")
    inb = make_sync(tmp_path, ctx_b, name="b", project=lambda o, p: projected.append((o.profile, p["status"], p["text"])) or "r1",
                    process=lambda p: processed.append(p["text"]))
    wire = sent.to_wire()
    back = ThreadEnvelope.from_wire(json.loads(json.dumps(wire)))
    for key in ("conversation_id", "message_id", "parent_message_id", "tenant", "masking", "source_thread",
                "target_thread", "art", "transport", "text"):
        assert getattr(back, key) == getattr(sent, key)
    assert inb.receive(back).status == "received"
    assert projected == [("linus", "empfangen", "pin=[MASKED] hi")]
    assert processed == ["pin=[MASKED] hi"]
    dup = inb.receive(back)
    assert (dup.status, dup.reason) == ("duplicate", "bereits_verarbeitet") and len(projected) == 1 and len(processed) == 1


def test_wire_tamper_and_unknown_fields_rejected():
    wire = envelope().to_wire()
    with pytest.raises(ValueError):
        ThreadEnvelope.from_wire({**wire, "text": "other"})
    with pytest.raises(ValueError):
        ThreadEnvelope.from_wire({**wire, "extra": 1})


def test_inbound_new_receiver_hit_blocks_before_any_side_effect(tmp_path):
    ctx_b = make_ctx(tmp_path / "b", profile="linus", thread="linus-t", live="live-b")
    inb = make_sync(tmp_path, ctx_b, name="b", secrets=("Karotte77",),
                    project=lambda *_: pytest.fail("projected"), process=lambda *_: pytest.fail("processed"))
    m = mask_text("hallo Karotte77")  # sender A did not know B's secret
    env = envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x")
    result = inb.receive(env)
    assert (result.status, result.reason) == ("blocked", "maskierung_unbelegt")
    assert not (tmp_path / "b" / "journal" / "conv-1" / "projections").exists()
    # unproven masking (no proof at all) is refused the same way
    assert inb.receive(envelope(tenant="tenant-1", tenant_source="x")).reason == "maskierung_unbelegt"


def test_inbound_requires_a2a_admission_attestation_and_matching_tenant(tmp_path):
    ctx_b = make_ctx(tmp_path / "b", profile="linus", thread="linus-t", live="live-b")
    m = mask_text("hi")
    env = envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x")
    no_adm = make_sync(tmp_path, ctx_b, name="b", attest=tuple(n for n in ATTEST if n != "a2a_admission"),
                       project=lambda *_: pytest.fail("projected"))
    assert no_adm.receive(env).reason == "spiegel_unbelegt"
    other_tenant = make_sync(tmp_path, ctx_b, name="c", project=lambda *_: pytest.fail("projected"))
    assert other_tenant.receive(envelope(text=m.text, masking=m.proof(), tenant="t-2", tenant_source="x")).reason == "tenant_abweichend"


# ---------------------------------------------------------------- queue / recovery / status
def test_outbound_queue_restart_recovery_and_visible_dead_letter_status(tmp_path):
    ctx = make_ctx(tmp_path / "a")
    online = [False]
    statuses = []
    def resolver(thread):
        return owner_for(ctx) if online[0] else None
    sync = make_sync(tmp_path, ctx, owner_resolver=resolver, sender_project=lambda o, p: statuses.append(p) or "s1",
                     transport=lambda p: None)
    assert sync.send(envelope(text="SENTINEL_BODY")).reason == "kein_aktiver_owner"
    online[0] = True
    restarted = make_sync(tmp_path, ctx, owner_resolver=resolver, sender_project=lambda o, p: statuses.append(p) or "s1",
                          transport=lambda p: None)
    assert restarted.retry_due(now=time.time() + 10)[0].status == "sent"
    assert [s["status"] for s in statuses] == ["gesendet"]


def test_dead_letter_posts_status_without_text(tmp_path):
    ctx = make_ctx(tmp_path / "a", lease=900)
    posted = []
    def project(owner, payload):
        posted.append(payload)
        if payload["status"] != "fehlgeschlagen":
            raise RuntimeError("offline")
        return "status-1"
    sync = make_sync(tmp_path, ctx, sender_project=project, transport=lambda p: None)
    assert sync.send(envelope(text="SENTINEL_BODY")).status == "queued"
    last = None
    for _ in range(12):
        row = [e for e in sync.journal.events("conv-1") if e["kind"] == "queue"][-1]
        res = sync.retry_due(now=row["next_at"] + 1)
        last = res[0] if res else last
        if last and last.status == "dead_letter":
            break
    assert last.status == "dead_letter"
    assert posted[-1]["status"] == "fehlgeschlagen" and "SENTINEL_BODY" not in posted[-1]["text"]


def test_inbound_queue_recovers_after_restart(tmp_path):
    ctx_b = make_ctx(tmp_path / "b", profile="linus", thread="linus-t", live="live-b")
    online = [False]
    got = []
    def mk():
        return make_sync(tmp_path, ctx_b, name="b", owner_resolver=lambda t: owner_for(ctx_b) if online[0] else None,
                         project=lambda o, p: got.append(p["message_id"]) or "r")
    m = mask_text("hi")
    env = envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x")
    assert mk().receive(env).status == "queued"
    online[0] = True
    assert mk().retry_due(now=time.time() + 10)[0].status == "received"
    assert got == ["msg-1"]


def test_ttl_measured_from_original_enqueue(tmp_path):
    sync = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    sync.send(envelope())
    row = [e for e in sync.journal.events("conv-1") if e["kind"] == "queue"][-1]
    res = sync.retry_due(now=row["enqueued_at"] + TTL_SECONDS + 1)
    assert (res[0].status, res[0].reason) == ("dead_letter", "ttl_abgelaufen")


# ---------------------------------------------------------------- claims / crash consistency
def _crash_run(tmp_path, where):
    t = [time.time()]
    count = {"proj": 0, "tx": 0}
    def project(owner, payload):
        count["proj"] += 1
        if where == "in_projection":
            raise Crash()
        return "s1"
    def transport(payload):
        count["tx"] += 1
        if where == "in_transport" and count["tx"] == 1:
            raise Crash()
    def build():
        return make_sync(tmp_path, sender_project=project, transport=transport, clock=lambda: t[0])
    sync = build()
    if where == "after_claim":
        orig = sync.journal.mark
        def mark(conv, kind, *a, **k):
            if kind == "stage_intent":
                raise Crash()
            return orig(conv, kind, *a, **k)
        sync.journal.mark = mark
    if where == "after_projection":
        sync.transport = lambda p: (_ for _ in ()).throw(Crash())
    with pytest.raises(Crash):
        sync.send(envelope())
    t[0] += CLAIM_LEASE_SECONDS + 1
    restarted = build()
    restarted.send(envelope())
    return count, restarted


@pytest.mark.parametrize("where,projections,final", [
    ("after_claim", 1, "sent"),          # died before intent: nothing visible yet, safe to take over
    ("in_projection", 1, "dead_letter"),  # died with intent: sent-or-not unknown → never resend
    ("after_projection", 1, "sent"),     # projection done: only transport resumes
    ("in_transport", 1, "sent"),
])
def test_crash_injection_never_yields_two_visible_projections(tmp_path, where, projections, final):
    count, restarted = _crash_run(tmp_path, where)
    assert count["proj"] == projections
    assert restarted.send(envelope()).status == final
    assert count["proj"] == projections
    done = [e for e in restarted.journal.events("conv-1")
            if e["kind"] == "stage_done" and e["stage"] == "sender_projection"]
    assert len(done) <= 1


def test_live_claim_by_other_worker_is_busy_not_duplicated(tmp_path):
    sync = make_sync(tmp_path, sender_project=lambda *_: pytest.fail("duplicate"))
    claim = sync.journal.claim("conv-1", "msg-1", "sender_projection", token="other", now=time.time())
    assert claim["state"] == "claimed"
    assert sync.send(envelope()).reason == "in_bearbeitung"


def _race(tmp_path_str, log_path):
    ctx = make_ctx(tmp_path_str + "/a")
    def project(owner, payload):
        time.sleep(0.05)
        fd = os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY)
        os.write(fd, b"x"); os.close(fd)
        return "s"
    sync = ThreadSync(journal=Journal(tmp_path_str + "/a/journal", trusted_base=tmp_path_str + "/a"), auth=ctx,
                      owner_resolver=lambda t: owner_for(ctx), sender_project=project, transport=lambda p: None,
                      evidence=registry())
    sync.attest(*ATTEST)
    sync.send(envelope())


def test_parallel_processes_project_at_most_once(tmp_path):
    (tmp_path / "a").mkdir()
    log = str(tmp_path / "egress.log")
    mp = multiprocessing.get_context("fork")
    procs = [mp.Process(target=_race, args=(str(tmp_path), log)) for _ in range(6)]
    for p in procs: p.start()
    for p in procs: p.join(30)
    assert all(p.exitcode == 0 for p in procs)
    assert os.path.getsize(log) == 1


# ---------------------------------------------------------------- no raw text in routing files
def test_no_plaintext_in_events_queue_or_audit(tmp_path):
    sync = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    sync.send(envelope(text="RAW_SENTINEL_9"))
    for e in sync.journal.events("conv-1"):
        assert "RAW_SENTINEL_9" not in json.dumps(e) and not ({"text", "value"} & set(e))
    with pytest.raises(ValueError):
        sync.journal.append("conv-1", {"kind": "x", "text": "y"})


def test_stale_worker_cannot_complete_a_newer_workers_stage(tmp_path):
    sync = make_sync(tmp_path)
    j = sync.journal
    now = time.time()
    old = j.claim("conv-1", "msg-1", "sender_projection", token="old", now=now)
    assert j.mark("conv-1", "stage_intent", "msg-1", "sender_projection", token="old", fence=old["fence"])
    j.mark("conv-1", "stage_failed", "msg-1", "sender_projection", token="old", fence=old["fence"])
    new = j.claim("conv-1", "msg-1", "sender_projection", token="new", now=now + CLAIM_LEASE_SECONDS + 1)
    assert new["fence"] > old["fence"]
    assert not j.mark("conv-1", "stage_done", "msg-1", "sender_projection", token="old", fence=old["fence"], ref="x")
    assert j.mark("conv-1", "stage_done", "msg-1", "sender_projection", token="new", fence=new["fence"], ref="y")


def test_stage_reports_busy_when_done_mark_is_fenced(tmp_path):
    sync = make_sync(tmp_path)
    def project(owner, payload):
        # a newer claimant takes over while this worker is mid-flight
        sync.journal._put_for_test = None
        sync.journal.append("conv-1", {"kind": "claim", "conversation_id": "conv-1", "message_id": "msg-1",
                                       "stage": "sender_projection", "token": "other", "fence": 99,
                                       "expires_at": time.time() + 99})
        return "s1"
    sync.sender_project = project
    assert sync.send(envelope()).reason == "in_bearbeitung"
    assert not [e for e in sync.journal.events("conv-1") if e["kind"] == "stage_done"]


def test_next_due_at_reports_earliest_queue_entry(tmp_path):
    sync = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    assert sync.next_due_at() is None
    sync.send(envelope())
    row = [e for e in sync.journal.events("conv-1") if e["kind"] == "queue"][-1]
    assert sync.next_due_at() == row["next_at"]


# ---------------------------------------------------------------- journal torn tail / corruption
def _events_path(tmp_path):
    return tmp_path / "a" / "journal" / "conv-1" / "events.jsonl"


def test_crash_truncated_tail_is_quarantined_and_recovery_continues(tmp_path):
    sync = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    sync.send(envelope())  # queued: leaves complete rows incl. a queue entry
    before = sync.journal.events("conv-1")
    with open(_events_path(tmp_path), "ab") as f:
        f.write(b'{"kind": "queue", "message_id": "msg-9", "att')  # power cut mid-record
    restarted = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    assert restarted.journal.events("conv-1") == before  # complete records unchanged
    assert list(_events_path(tmp_path).parent.glob("events.torn-*"))  # torn bytes kept, not trusted
    restarted.journal.append("conv-1", {"kind": "audit", "message_id": "after"})
    rows = [json.loads(l) for l in _events_path(tmp_path).read_text().splitlines()]
    assert rows[-1]["message_id"] == "after" and len(rows) == len(before) + 1
    assert restarted.retry_due(now=time.time() + 10) is not None  # recovery not blocked
    assert restarted.send(envelope()).status == "queued"  # dedupe invariant intact (queued row survived)


def test_complete_tail_missing_only_its_newline_is_kept(tmp_path):
    sync = make_sync(tmp_path)
    sync.journal.append("conv-1", {"kind": "audit", "message_id": "m1"})
    p = _events_path(tmp_path)
    p.write_bytes(p.read_bytes().rstrip(b"\n"))
    assert [e["message_id"] for e in sync.journal.events("conv-1")] == ["m1"]
    assert p.read_bytes().endswith(b"\n")


@pytest.mark.parametrize("bad", [b"{not json}\n", b"[1,2]\n", b"\xff\xfe\n"])
def test_malformed_complete_or_interior_record_fails_closed(tmp_path, bad):
    sync = make_sync(tmp_path, sender_project=lambda *_: pytest.fail("projected"), transport=lambda p: None)
    sync.journal.append("conv-1", {"kind": "audit", "message_id": "m1"})
    p = _events_path(tmp_path)
    p.write_bytes(p.read_bytes() + bad)  # complete (newline-terminated) garbage is NOT a torn write
    with pytest.raises(ValueError, match="journal_corrupt"):
        sync.journal.events("conv-1")
    with pytest.raises(ValueError):
        sync.send(envelope())
    interior = p.read_bytes() + b'{"kind":"audit","message_id":"m3"}\n'
    p.write_bytes(interior)
    with pytest.raises(ValueError, match="journal_corrupt"):
        sync.journal.events("conv-1")
    assert not list(p.parent.glob("events.torn-*"))


# ---------------------------------------------------------------- admission != processed
def _inbound(tmp_path, projections, *, clock=None, name="b"):
    ctx = make_ctx(tmp_path / name, profile="linus", thread="linus-t", live="live-b", lease=900)
    kw = {"clock": clock} if clock else {}
    return make_sync(tmp_path, ctx, name=name, project=lambda o, p: projections.append(p["message_id"]) or "r", **kw)


def _wire_env():
    m = mask_text("hi")
    return envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x")


def _processed(sync):
    return [e for e in sync.journal.events("conv-1") if e["kind"] == "inbound_processed"]


def test_admission_is_durable_but_not_processed_until_dispatch_ack(tmp_path):
    proj = []
    sync = _inbound(tmp_path, proj)
    first = sync.receive(_wire_env(), external_dispatch=True)
    assert first.status == "admitted" and first.ticket and not _processed(sync)
    sync.abort_dispatch(first.ticket)  # gateway not ready
    again = sync.receive(_wire_env(), external_dispatch=True)
    assert again.status == "admitted" and proj == ["msg-1"] and not _processed(sync)  # resumed, one projection
    assert sync.dispatch_started(again.ticket) and sync.ack_dispatch(again.ticket)
    assert len(_processed(sync)) == 1
    replay = sync.receive(_wire_env(), external_dispatch=True)
    assert (replay.status, replay.reason) == ("duplicate", "bereits_verarbeitet") and proj == ["msg-1"]


def test_crash_between_admission_and_dispatch_resumes_after_claim_expiry(tmp_path):
    t = [time.time()]
    proj = []
    sync = _inbound(tmp_path, proj, clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    assert ticket  # ...process dies here: no abort, no intent, no ack
    restarted = _inbound(tmp_path, proj, clock=lambda: t[0])
    assert restarted.receive(_wire_env(), external_dispatch=True).reason == "in_bearbeitung"  # lease still live
    t[0] += CLAIM_LEASE_SECONDS + 1
    resumed = restarted.receive(_wire_env(), external_dispatch=True)
    assert resumed.status == "admitted" and proj == ["msg-1"]
    assert not sync.ack_dispatch(ticket)  # the dead worker's stale ticket can never complete it
    assert restarted.dispatch_started(resumed.ticket) and restarted.ack_dispatch(resumed.ticket)
    assert len(_processed(restarted)) == 1


def test_dispatch_intent_alone_is_retryable_after_lease_and_never_implies_dispatch(tmp_path):
    t = [time.time()]
    proj = []
    sync = _inbound(tmp_path, proj, clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    assert sync.dispatch_started(ticket)  # intent recorded, then the process dies before/at submission
    assert not _processed(sync)
    t[0] += CLAIM_LEASE_SECONDS + 1
    again = _inbound(tmp_path, proj, clock=lambda: t[0]).receive(_wire_env(), external_dispatch=True)
    assert again.status == "admitted" and proj == ["msg-1"]  # resumes; no second Telegram projection
    assert not sync.ack_dispatch(ticket)  # the dead worker can no longer complete it


def test_concurrent_retries_yield_exactly_one_dispatcher(tmp_path):
    import threading
    proj, results = [], []
    syncs = [_inbound(tmp_path, proj) for _ in range(8)]
    barrier = threading.Barrier(len(syncs))

    def run(s):
        barrier.wait()
        results.append(s.receive(_wire_env(), external_dispatch=True))

    threads = [threading.Thread(target=run, args=(s,)) for s in syncs]
    for th in threads: th.start()
    for th in threads: th.join(30)
    admitted = [r for r in results if r.status == "admitted"]
    assert len(results) == 8 and len(admitted) == 1
    assert all(r.reason == "in_bearbeitung" for r in results if r.status != "admitted")
    assert proj == ["msg-1"]


def test_failed_admission_has_no_dispatch_or_journal_side_effects(tmp_path):
    proj = []
    sync = _inbound(tmp_path, proj)
    bad = envelope(tenant="tenant-1", tenant_source="x")  # no masking proof
    r = sync.receive(bad, external_dispatch=True)
    assert (r.status, r.ticket) == ("blocked", None) and proj == []
    assert not [e for e in sync.journal.events("conv-1") if e["kind"] in {"claim", "stage_intent", "inbound_processed"}]


def _queue_rows(sync):
    return [e for e in sync.journal.events("conv-1") if e["kind"] == "queue"]


def _mk_inbound(tmp_path, online, proj, **kw):
    ctx = make_ctx(tmp_path / "b", profile="linus", thread="linus-t", live="live-b")
    return make_sync(tmp_path, ctx, name="b", owner_resolver=lambda t: owner_for(ctx) if online[0] else None,
                     project=lambda o, p: proj.append(p["message_id"]) or "r", **kw)


def test_queued_external_inbound_keeps_its_dispatch_type_and_is_acked_only_after_gateway_dispatch(tmp_path):
    online, proj, dispatched = [False], [], []
    queued = _mk_inbound(tmp_path, online, proj).receive(_wire_env(), external_dispatch=True)
    assert (queued.status, queued.reason) == ("queued", "kein_aktiver_owner")
    row = _queue_rows(_mk_inbound(tmp_path, online, proj))[-1]
    assert row["dispatch"] == "external" and not ({"text", "value"} & set(row))  # a type, never content
    online[0] = True
    bare = _mk_inbound(tmp_path, online, proj)  # rebuilt capability WITHOUT a gateway dispatcher
    assert bare.retry_due(now=time.time() + 10)[0].reason == "kein_dispatcher"
    assert not _processed(bare)  # nothing recorded as processed without a dispatch
    live = _mk_inbound(tmp_path, online, proj, dispatcher=lambda env: dispatched.append(env.message_id) or True)
    assert live.retry_due(now=time.time() + 10)[0].status == "received"
    assert dispatched == ["msg-1"] and len(_processed(live)) == 1 and proj == ["msg-1"]
    assert live.retry_due(now=time.time() + 20) == []


def test_local_queue_entries_stay_explicitly_non_external(tmp_path):
    online, proj = [False], []
    _mk_inbound(tmp_path, online, proj).receive(_wire_env())
    assert _queue_rows(_mk_inbound(tmp_path, online, proj))[-1]["dispatch"] == "local"
    online[0] = True
    sync = _mk_inbound(tmp_path, online, proj)
    assert sync.retry_due(now=time.time() + 10)[0].status == "received" and len(_processed(sync)) == 1


def test_recovery_gateway_rejection_and_lost_ack_never_dispatch_twice(tmp_path):
    online, proj, dispatched = [True], [], []
    _mk_inbound(tmp_path, [False], proj).receive(_wire_env(), external_dispatch=True)
    now = time.time() + 10
    rejecting = _mk_inbound(tmp_path, online, proj, dispatcher=lambda env: False)
    assert rejecting.retry_due(now=now)[0].reason == "gateway_abgelehnt" and not _processed(rejecting)
    flaky = _mk_inbound(tmp_path, online, proj, dispatcher=lambda env: dispatched.append(1) or True)
    real_ack = flaky.ack_dispatch
    flaky.ack_dispatch = lambda t: False  # transient durable-ack failure after the gateway took the message
    assert flaky.retry_due(now=now)[0].reason == "ack_ausstehend" and not _processed(flaky)
    flaky.ack_dispatch = real_ack
    again = _mk_inbound(tmp_path, online, proj, dispatcher=lambda env: dispatched.append(1) or True)
    result = again.retry_due(now=now)[0]
    assert (result.status, result.reason) == ("duplicate", "bereits_verarbeitet")  # finalized by receipt
    assert dispatched == [1] and len(_processed(again)) == 1 and proj == ["msg-1"]


def test_admission_durably_enqueues_recipient_dispatch_before_returning_a_ticket(tmp_path):
    proj = []
    sync = _inbound(tmp_path, proj)
    result = sync.receive(_wire_env(), external_dispatch=True)
    assert result.status == "admitted"
    assert sync.journal.dispatch_state("conv-1", "msg-1") == "PENDING"
    rows = [e for e in sync.journal.events("conv-1") if e["kind"] == "queue"]
    assert len(rows) == 1 and rows[0]["dispatch"] == "external" and rows[0]["direction"] == "in"
    assert not ({"text", "value"} & set(rows[0]))
    from tools.bot_thread_sync import dispatch_key
    assert result.ticket["key"] == dispatch_key("tenant-1", "conv-1", "msg-1", "linus")  # authenticated identity


def test_running_lease_expiry_resubmits_under_the_same_dispatch_key(tmp_path):
    t = [time.time()]
    sync = _inbound(tmp_path, [], clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    assert sync.dispatch_begin(ticket) and not sync.dispatch_begin(ticket)  # one live claim at a time
    other = _inbound(tmp_path, [], clock=lambda: t[0])
    assert other.receive(_wire_env(), external_dispatch=True).reason == "in_bearbeitung"
    t[0] += CLAIM_LEASE_SECONDS + 1  # ambiguous crash: nobody finished the handoff
    again = other.receive(_wire_env(), external_dispatch=True)
    assert again.status == "admitted" and again.ticket["key"] == ticket["key"]  # resubmit, same identity
    assert other.dispatch_begin(again.ticket)
    assert not sync.dispatch_begin(ticket) and not sync.accept_dispatch(ticket)  # stale claimant is fenced out
    assert other.accept_dispatch(again.ticket) and other.ack_dispatch(again.ticket)
    running = [e for e in other.journal.events("conv-1") if e["kind"] == "dispatch_running"]
    assert len(running) == 2 and {e["key"] for e in running} == {ticket["key"]} and len(_processed(other)) == 1


def test_recovery_crash_inside_gateway_handoff_is_retried_after_the_lease_with_the_same_message(tmp_path):
    t = [time.time()]
    online, calls = [False], []
    queued = _mk_inbound(tmp_path, online, [], clock=lambda: t[0]).receive(_wire_env(), external_dispatch=True)
    assert queued.status == "queued"
    online[0] = True

    def dying(env):
        calls.append(env.message_id)
        raise KeyboardInterrupt()  # process death inside the gateway hand-off (after the durable claim)

    with pytest.raises(KeyboardInterrupt):
        _mk_inbound(tmp_path, online, [], clock=lambda: t[0], dispatcher=dying).retry_due(now=t[0] + 10)
    t[0] += CLAIM_LEASE_SECONDS + 20
    survivor = _mk_inbound(tmp_path, online, [], clock=lambda: t[0], dispatcher=lambda e: calls.append(e.message_id) or True)
    assert survivor.retry_due(now=t[0])[0].status == "received"
    assert calls == ["msg-1", "msg-1"] and len(_processed(survivor)) == 1  # at-least-once, one terminal record
    assert survivor.retry_due(now=t[0] + 5) == []


# ---------------------------------------------------------------- atomic terminal record: fault injection
def _drive(sync):
    r = sync.receive(_wire_env(), external_dispatch=True)
    if r.status == "admitted" and sync.dispatch_begin(r.ticket):
        sync.accept_dispatch(r.ticket)
        sync.ack_dispatch(r.ticket)
    return r


def _faulty_appends(index, how):
    """Fail the Nth journal append: 'before' the write, 'torn' (half a record), or 'after' the fsync."""
    from tools import pinned_fs
    real, calls = pinned_fs.append_bytes, [0]

    def patched(fd, name, data, *, mode=0o600):
        calls[0] += 1
        if calls[0] - 1 == index:
            if how == "torn":
                real(fd, name, data[: len(data) // 2], mode=mode)
            elif how == "after":
                real(fd, name, data, mode=mode)
            raise Crash()
        return real(fd, name, data, mode=mode)

    return pinned_fs, real, patched, calls


def test_terminal_record_is_atomic_at_every_journal_write_boundary(tmp_path):
    from tools import pinned_fs
    real, calls = pinned_fs.append_bytes, [0]
    pinned_fs.append_bytes = lambda *a, **k: calls.__setitem__(0, calls[0] + 1) or real(*a, **k)
    try:
        _drive(_inbound(tmp_path, [], name="count"))
    finally:
        pinned_fs.append_bytes = real
    total = calls[0]
    assert total >= 6  # claims, projection stages, queue row, dispatch records, terminal record
    for how in ("before", "torn", "after"):
        for i in range(total):
            t, proj, name = [time.time()], [], f"{how}{i}"
            first = _inbound(tmp_path, proj, clock=lambda: t[0], name=name)
            mod, real_fn, patched, _ = _faulty_appends(i, how)
            mod.append_bytes = patched
            try:
                with contextlib.suppress(Crash):
                    _drive(first)
            finally:
                mod.append_bytes = real_fn
            for attempt in range(5):  # restart, expire leases, recover
                t[0] += CLAIM_LEASE_SECONDS + 1
                survivor = _inbound(tmp_path, proj, clock=lambda: t[0], name=name)
                rows = survivor.journal.events("conv-1")
                stage_done = [e for e in rows if e["kind"] == "stage_done" and e.get("stage") == "dispatch"]
                assert not stage_done  # never a stage_done-only limbo
                processed_before = bool([e for e in rows if e["kind"] == "inbound_processed"])
                result = _drive(survivor)
                if processed_before:  # every reader agrees: claim, queue and dispatch record are terminal
                    assert (result.status, result.reason) == ("duplicate", "bereits_verarbeitet")
                else:
                    assert result.status != "duplicate" or result.reason == "bereits_verarbeitet"
            rows = survivor.journal.events("conv-1")
            processed = [e for e in rows if e["kind"] == "inbound_processed"]
            assert len(processed) <= 1 and len(proj) <= 1  # at-most-once terminal + projection
            if not processed:  # only an ambiguous *projection* may leave a message blocked (never re-projected)
                assert result.reason in {"eingangsprojektion_unbestatigt", "in_bearbeitung"} or result.status == "blocked"


def test_crash_after_terminal_write_is_fully_terminal_and_before_it_fully_retryable(tmp_path):
    from tools import pinned_fs
    for how, terminal in (("before", False), ("torn", False), ("after", True)):
        t = [time.time()]
        sync = _inbound(tmp_path, [], clock=lambda: t[0], name=f"x{how}")
        ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
        assert sync.dispatch_begin(ticket) and sync.accept_dispatch(ticket)
        mod, real_fn, patched, _ = _faulty_appends(0, how)
        mod.append_bytes = patched
        try:
            with pytest.raises(Crash):
                sync.ack_dispatch(ticket)  # exactly one write: the single terminal record
        finally:
            mod.append_bytes = real_fn
        rows = sync.journal.events("conv-1")
        assert bool([e for e in rows if e["kind"] == "inbound_processed"]) is terminal
        assert not [e for e in rows if e["kind"] == "stage_done" and e.get("stage") == "dispatch"]
        if terminal:
            assert sync.journal.claim("conv-1", "msg-1", "dispatch", token="p", now=t[0])["state"] == "done"
        else:
            assert sync.ack_dispatch(ticket) and len(_processed(sync)) == 1  # retryable, then terminal


def test_only_a_genuinely_completed_run_terminalizes_failed_or_cancelled_stay_recoverable(tmp_path):
    t = [time.time()]
    sync = _inbound(tmp_path, [], clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    assert sync.dispatch_begin(ticket) and sync.accept_dispatch(ticket)
    assert not sync.finish_dispatch(ticket, "failed") and not sync.finish_dispatch(ticket, "cancelled")
    assert not _processed(sync) and sync.journal.dispatch_state("conv-1", "msg-1") == "ACCEPTED"
    assert sync.finish_dispatch(ticket, "completed") and not _processed(sync)  # MODEL_COMPLETED is nonterminal
    assert sync.journal.dispatch_state("conv-1", "msg-1") == "COMPLETED"
    assert not sync.finalize_turn(ticket)  # terminal refused until the reply is durable
    assert sync.mark_reply_stored(ticket) and sync.finalize_turn(ticket) and len(_processed(sync)) == 1


# ---------------------------------------------------------------- reply-before-terminal invariant
def _full_turn(sync):
    r = sync.receive(_wire_env(), external_dispatch=True)
    if r.status == "admitted" and sync.dispatch_begin(r.ticket):
        sync.accept_dispatch(r.ticket)
        sync.finish_dispatch(r.ticket, "completed")      # MODEL_COMPLETED (nonterminal)
        sync.mark_reply_stored(r.ticket)                 # authenticated reply durable
        sync.finalize_turn(r.ticket)                     # TURN_FINALIZED (the single terminal record)
    return r


def test_terminal_requires_a_durable_reply_at_every_write_boundary(tmp_path):
    from tools import pinned_fs
    real, calls = pinned_fs.append_bytes, [0]
    pinned_fs.append_bytes = lambda *a, **k: calls.__setitem__(0, calls[0] + 1) or real(*a, **k)
    try:
        _full_turn(_inbound(tmp_path, [], name="count"))
    finally:
        pinned_fs.append_bytes = real
    for how in ("before", "torn", "after"):
        for i in range(calls[0]):
            t, proj, name = [time.time()], [], f"r{how}{i}"
            mod, real_fn, patched, _ = _faulty_appends(i, how)
            mod.append_bytes = patched
            try:
                with contextlib.suppress(Crash):
                    _full_turn(_inbound(tmp_path, proj, clock=lambda: t[0], name=name))
            finally:
                mod.append_bytes = real_fn
            for _ in range(5):
                t[0] += CLAIM_LEASE_SECONDS + 1
                survivor = _inbound(tmp_path, proj, clock=lambda: t[0], name=name)
                rows = survivor.journal.events("conv-1")
                if [e for e in rows if e["kind"] == "inbound_processed"]:  # terminal => reply was durable first
                    assert [e for e in rows if e["kind"] == "dispatch_replied"]
                _full_turn(survivor)
            rows = survivor.journal.events("conv-1")
            assert len([e for e in rows if e["kind"] == "inbound_processed"]) <= 1 and len(proj) <= 1


def test_model_completed_without_a_durable_reply_is_never_a_duplicate_and_is_rerun(tmp_path):
    t = [time.time()]
    sync = _inbound(tmp_path, [], clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    assert sync.dispatch_begin(ticket) and sync.accept_dispatch(ticket) and sync.finish_dispatch(ticket, "completed")
    assert not sync.finalize_turn(ticket) and not _processed(sync)           # no reply, no terminal
    assert _inbound(tmp_path, [], clock=lambda: t[0]).receive(_wire_env(), external_dispatch=True).reason == "in_bearbeitung"
    t[0] += CLAIM_LEASE_SECONDS + 1                                          # crash: reply never became durable
    again = _inbound(tmp_path, [], clock=lambda: t[0]).receive(_wire_env(), external_dispatch=True)
    assert again.status == "admitted"                                        # re-run (at-least-once), NOT duplicate


def test_durable_reply_without_terminal_is_finalized_without_rerun(tmp_path):
    t = [time.time()]
    sync = _inbound(tmp_path, [], clock=lambda: t[0])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    sync.dispatch_begin(ticket); sync.accept_dispatch(ticket); sync.finish_dispatch(ticket, "completed")
    assert sync.mark_reply_stored(ticket)                                    # crash before finalize_turn
    t[0] += CLAIM_LEASE_SECONDS + 1
    res = _inbound(tmp_path, [], clock=lambda: t[0]).receive(_wire_env(), external_dispatch=True)
    assert (res.status, res.reason) == ("duplicate", "bereits_verarbeitet") and len(_processed(sync)) == 1


def test_typed_no_reply_outcome_terminalizes(tmp_path):
    sync = _inbound(tmp_path, [])
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    sync.dispatch_begin(ticket); sync.accept_dispatch(ticket)
    assert sync.finish_dispatch(ticket, "completed", reply_expected=False) and len(_processed(sync)) == 1
    assert [e for e in sync.journal.events("conv-1") if e["kind"] == "dispatch_replied"][0]["no_reply"] is True


# ---------------------------------------------------------------- message identity: conflicting replay, MAC coverage
def test_altered_replay_with_the_same_ids_is_a_conflict_with_zero_side_effects(tmp_path):
    proj, called = [], []
    sync = _inbound(tmp_path, proj, name="c")
    first = sync.receive(_wire_env(), external_dispatch=True)
    assert first.status == "admitted"
    before = sync.journal.events("conv-1")
    stored = sync.journal.load_projection("conv-1", "msg-1")
    m2 = mask_text("ganz anderer text")
    altered = envelope(text=m2.text, masking=m2.proof(), tenant="tenant-1", tenant_source="x")  # same ids, valid proof
    for external in (True, False):
        res = sync.receive(altered, external_dispatch=external)
        assert (res.status, res.reason) == ("blocked", "message_id_conflict")
    assert sync.journal.events("conv-1") == before                       # no audit/claim/queue/dispatch rows
    assert sync.journal.load_projection("conv-1", "msg-1") == stored      # the ORIGINAL stays the message
    assert proj == ["msg-1"] and called == []
    exact = sync.receive(_wire_env(), external_dispatch=True)             # an exact replay still follows the state
    assert exact.reason != "message_id_conflict" and exact.status in {"admitted", "queued"}


def _signed_journal(tmp_path, name="s"):
    from tools.bot_thread_sync import Journal
    j = Journal(tmp_path / name / "journal", trusted_base=tmp_path / name)
    j.key_provider = lambda: b"k" * 32
    return j


def _full_envelope():
    m = mask_text("token=abcdefgh und mehr")
    return envelope(conversation_id="c1", message_id="m1", parent_message_id="m0", is_root=False,
                    tenant="t1", tenant_source="gateway_context", text=m.text, masking=m.proof(),
                    projection_requested=True, art="gespraech", transport="a2a", status="eingereiht")


def test_storage_mac_covers_every_envelope_field(tmp_path):
    from dataclasses import fields
    from tools.bot_thread_sync import ThreadEnvelope
    j = _signed_journal(tmp_path)
    j.save_projection(_full_envelope())
    path = tmp_path / "s" / "journal" / "c1" / "projections" / "m1.json"
    good = path.read_text()
    assert j.load_projection("c1", "m1").tenant_source == "gateway_context"
    flipped = []
    for f in fields(ThreadEnvelope):
        data = json.loads(good)
        value = data[f.name]
        data[f.name] = (not value if isinstance(value, bool) else value + "x" if isinstance(value, str)
                        else {**value, "zz": 1} if isinstance(value, dict) else "x")
        path.write_text(json.dumps(data))
        with pytest.raises(ValueError, match="storage_"):
            j.load_projection("c1", "m1")
        flipped.append(f.name)
    assert {"projection_requested", "tenant_source", "is_root"} <= set(flipped)
    assert set(flipped) == {f.name for f in fields(ThreadEnvelope)}         # schema-complete, nothing skipped
    path.write_text(good)
    assert j.load_projection("c1", "m1").message_id == "m1"


def test_projection_copied_to_another_path_never_validates(tmp_path):
    import shutil
    j = _signed_journal(tmp_path)
    j.save_projection(_full_envelope())
    base = tmp_path / "s" / "journal"
    with j._locked("c2"):
        (base / "c2" / "projections").mkdir()
    shutil.copy(base / "c1" / "projections" / "m1.json", base / "c2" / "projections" / "m1.json")   # other conv
    with pytest.raises(ValueError, match="storage_tampered"):
        j.load_projection("c2", "m1")
    shutil.copy(base / "c1" / "projections" / "m1.json", base / "c1" / "projections" / "m2.json")   # other message
    with pytest.raises(ValueError, match="storage_tampered"):
        j.load_projection("c1", "m2")


# ---------------------------------------------------------------- atomic canonicalization under concurrency
def _texting_inbound(tmp_path, texts, name, **kw):
    ctx = make_ctx(tmp_path / name, profile="linus", thread="linus-t", live="live-b", lease=900)
    return make_sync(tmp_path, ctx, name=name, project=lambda o, p: texts.append(p["text"]) or "r", **kw)


def _conflicting_env():
    m = mask_text("konkurrierender text")
    return envelope(text=m.text, masking=m.proof(), tenant="tenant-1", tenant_source="x")


def _barrier_race(syncs, envs, *, external=True):
    import threading
    barrier, out = threading.Barrier(len(syncs)), []

    def run(i):
        barrier.wait()
        out.append((i, syncs[i].receive(envs[i], external_dispatch=external)))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(syncs))]
    for th in threads: th.start()
    for th in threads: th.join(30)
    return out


def test_concurrent_canonical_vs_conflicting_envelope_has_exactly_one_canonical_effect(tmp_path):
    for it in range(20):
        texts = []
        syncs = [_texting_inbound(tmp_path, texts, f"x{it}") for _ in range(2)]
        envs = [_wire_env(), _conflicting_env()]
        out = _barrier_race(syncs, envs)
        losers = [i for i, r in out if (r.status, r.reason) == ("blocked", "message_id_conflict")]
        winners = [i for i, r in out if i not in losers]
        assert len(losers) == 1 and len(winners) == 1                     # exactly one canonical, one conflict
        j = syncs[0].journal
        stored = j.load_projection("conv-1", "msg-1")
        assert stored.text == envs[winners[0]].text                       # the winner's object IS the projection
        kinds = [e["kind"] for e in j.events("conv-1")]
        assert kinds.count("inbound_receipt") == 1 and len(texts) == 1    # one receipt, one visible projection
        assert texts == [envs[winners[0]].text]                           # never the loser's text
        assert not [e for e in j.events("conv-1") if e["kind"] == "audit" and e.get("reason") == "message_id_conflict"]


def test_concurrent_exact_replays_produce_one_visible_effect_and_one_completion(tmp_path):
    texts, processed = [], []
    syncs = [_texting_inbound(tmp_path, texts, "e", process=lambda p: processed.append(p["text"]))
             for _ in range(6)]
    out = _barrier_race(syncs, [_wire_env()] * 6, external=False)
    assert len(texts) == 1 and len(processed) == 1                        # one projection, one processing
    kinds = [e["kind"] for e in syncs[0].journal.events("conv-1")]
    assert kinds.count("inbound_receipt") == 1 and kinds.count("inbound_processed") == 1
    assert {r.reason for _, r in out} <= {"", "in_bearbeitung", "bereits_verarbeitet", "verarbeitung_busy"}


def _mp_worker(tmp_path_str, idx, alt, q):
    texts = []
    ctx = make_ctx(tmp_path_str + "/m", profile="linus", thread="linus-t", live="live-b", lease=900)
    sync = make_sync(__import__("pathlib").Path(tmp_path_str), ctx, name="m",
                     project=lambda o, p: texts.append(p["text"]) or "r")
    res = sync.receive(_conflicting_env() if alt else _wire_env(), external_dispatch=True)
    q.put((alt, res.reason, len(texts)))


def test_multiprocess_canonical_vs_conflict_race_has_a_single_winner(tmp_path):
    mp = multiprocessing.get_context("fork")
    q = mp.Queue()
    (tmp_path / "m").mkdir()
    procs = [mp.Process(target=_mp_worker, args=(str(tmp_path), i, i % 2 == 1, q)) for i in range(4)]
    for p in procs: p.start()
    results = [q.get(timeout=60) for _ in procs]
    for p in procs: p.join(30)
    assert all(p.exitcode == 0 for p in procs)
    sides = {alt for alt, reason, _ in results if reason != "message_id_conflict"}
    assert len(sides) == 1                                               # only ONE side's content ever proceeds
    assert sum(n for *_, n in results) == 1                              # exactly one visible projection overall
    from tools.bot_thread_sync import Journal
    j = Journal(tmp_path / "m" / "journal", trusted_base=tmp_path / "m")
    assert len([e for e in j.events("conv-1") if e["kind"] == "inbound_receipt"]) == 1


# ---------------------------------------------------------------- identity check precedes every idempotent shortcut
def _out_sync(tmp_path, name, *, online=True, signed=False):
    ctx = make_ctx(tmp_path / name, lease=900)
    sync = make_sync(tmp_path, ctx, name=name, owner_resolver=(lambda t: owner_for(ctx)) if online else (lambda t: None),
                     sender_project=lambda o, p: "s", transport=lambda p: None)
    if signed:
        sync.journal.key_provider = lambda: b"k" * 32
    return sync


def _dead_letter(sync):
    sync.journal.append("conv-1", {"kind": "dead_letter", "conversation_id": "conv-1", "message_id": "msg-1",
                                   "status": "fehlgeschlagen", "reason": "retry_erschoepft", "attempts": 8})


@pytest.mark.parametrize("state", ["sent", "queued", "dead_letter"])
def test_outbound_conflict_blocks_and_exact_replay_returns_prior_state_in_every_terminal_or_queued_state(tmp_path, state):
    sync = _out_sync(tmp_path, state, online=state == "sent")
    first = sync.send(envelope())
    if state == "dead_letter":
        _dead_letter(sync)
    expected = {"sent": "sent", "queued": "queued", "dead_letter": "dead_letter"}[state]
    assert first.status == ("sent" if state == "sent" else "queued")
    stored = sync.journal.load_projection("conv-1", "msg-1")
    exact = sync.send(envelope())
    assert exact.status == expected and exact.reason != "message_id_conflict"          # exact replay: prior status
    rows = sync.journal.events("conv-1")
    conflict = sync.send(envelope(text="ganz anderer inhalt"))
    assert (conflict.status, conflict.reason) == ("blocked", "message_id_conflict")    # never the prior success
    assert sync.journal.events("conv-1") == rows                                        # zero new effects
    assert sync.journal.load_projection("conv-1", "msg-1") == stored                    # canonical object unchanged


@pytest.mark.parametrize("state", ["sent", "queued", "dead_letter"])
def test_outbound_conflict_has_zero_new_effects(tmp_path, state):
    calls = []
    ctx = make_ctx(tmp_path / f"z{state}", lease=900)
    sync = make_sync(tmp_path, ctx, name=f"z{state}", owner_resolver=(lambda t: owner_for(ctx)) if state == "sent" else (lambda t: None),
                     sender_project=lambda o, p: calls.append(p["text"]) or "s", transport=lambda p: calls.append("tx"))
    sync.send(envelope())
    if state == "dead_letter":
        _dead_letter(sync)
    rows, n = len(sync.journal.events("conv-1")), len(calls)
    for _ in range(3):
        assert sync.send(envelope(text="konflikt")).reason == "message_id_conflict"
    assert len(sync.journal.events("conv-1")) == rows and len(calls) == n


def test_tampered_canonical_artifact_never_returns_the_prior_success(tmp_path):
    sync = _out_sync(tmp_path, "t", signed=True)
    assert sync.send(envelope()).status == "sent"
    path = tmp_path / "t" / "journal" / "conv-1" / "projections" / "msg-1.json"
    data = json.loads(path.read_text())
    data["text"] = "manipuliert"
    path.write_text(json.dumps(data))
    res = sync.send(envelope())                                                          # even an "exact" replay
    assert (res.status, res.reason) == ("blocked", "projektion_manipuliert")


def test_concurrent_exact_and_conflicting_outbound_replays_after_sent(tmp_path):
    import threading
    ctx = make_ctx(tmp_path / "c", lease=900)
    syncs = [make_sync(tmp_path, ctx, name="c", owner_resolver=lambda t: owner_for(ctx),
                       sender_project=lambda o, p: "s", transport=lambda p: None) for _ in range(4)]
    assert syncs[0].send(envelope()).status == "sent"
    rows = len(syncs[0].journal.events("conv-1"))
    envs = [envelope(), envelope(text="x1"), envelope(), envelope(text="x2")]
    barrier, out = threading.Barrier(4), {}

    def run(i):
        barrier.wait()
        out[i] = syncs[i].send(envs[i])

    ts = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for t in ts: t.start()
    for t in ts: t.join(30)
    assert [out[i].status for i in (0, 2)] == ["sent", "sent"]
    assert [out[i].reason for i in (1, 3)] == ["message_id_conflict"] * 2
    assert len(syncs[0].journal.events("conv-1")) == rows                                # zero new effects


def test_inbound_conflict_and_exact_replay_matrix_processed_and_reply_pending(tmp_path):
    proj = []
    sync = _inbound(tmp_path, proj, name="p")
    ticket = sync.receive(_wire_env(), external_dispatch=True).ticket
    sync.dispatch_begin(ticket); sync.accept_dispatch(ticket)
    assert sync.journal.dispatch_mark_reply_pending("conv-1", "msg-1", ticket["key"])                # REPLY_PENDING
    rows = len(sync.journal.events("conv-1"))
    assert sync.receive(_wire_env(), external_dispatch=True).reason == "antwort_ausstehend"          # exact replay
    assert sync.receive(_conflicting_env(), external_dispatch=True).reason == "message_id_conflict"
    sync.mark_reply_stored(ticket); assert sync.finalize_turn(ticket)                                # processed
    rows = len(sync.journal.events("conv-1"))
    exact = sync.receive(_wire_env(), external_dispatch=True)
    assert (exact.status, exact.reason) == ("duplicate", "bereits_verarbeitet")
    for external in (True, False):
        assert sync.receive(_conflicting_env(), external_dispatch=external).reason == "message_id_conflict"
    assert len(sync.journal.events("conv-1")) == rows and proj == ["msg-1"]


def test_tampered_projection_blocks_even_when_the_message_was_already_processed(tmp_path):
    sync = _inbound(tmp_path, [], name="q")
    sync.journal.key_provider = lambda: b"k" * 32
    sync.receive(_wire_env())                                                                       # non-external: processed
    assert len(_processed(sync)) == 1
    path = tmp_path / "q" / "journal" / "conv-1" / "projections" / "msg-1.json"
    data = json.loads(path.read_text()); data["text"] = "manipuliert"; path.write_text(json.dumps(data))
    res = sync.receive(_wire_env())
    assert (res.status, res.reason) == ("blocked", "projektion_manipuliert")                         # not "duplicate"


# ---------------------------------------------------------------- closed masking-proof schema
def _proof():
    return mask_text("token=abcdefgh und card 4111 1111 1111 1111").proof()


def _bad_proofs():
    good = _proof()
    big = [[i * 10, i * 10 + 8] for i in range(1025)]
    return {
        "unknown_top_key": {**good, "klartext": "PLAINTEXT_SENTINEL"},
        "missing_key": {k: v for k, v in good.items() if k != "digest"},
        "nested_extra_in_span": {**good, "spans": [[0, 8, "PLAINTEXT_SENTINEL"]]},
        "string_in_classes": {**good, "classes": ["PLAINTEXT_SENTINEL"]},
        "unsorted_classes": {**good, "classes": ["pin", "card"]},
        "duplicate_classes": {**good, "classes": ["card", "card"]},
        "oversized_spans": {**good, "spans": big},
        "overlapping_spans": {**good, "spans": [[0, 8], [4, 12]]},
        "reversed_span": {**good, "spans": [[8, 8]]},
        "negative_span": {**good, "spans": [[-1, 8]]},
        "huge_span": {**good, "spans": [[0, 5000]]},
        "bool_count": {**good, "match_count": True},
        "huge_count": {**good, "match_count": 10**9},
        "freeform_provenance": {**good, "provenance": "scan:local-v3;matches=2;PLAINTEXT_SENTINEL"},
        "wrong_version": {**good, "scanner_version": "x" * 5000},
        "upper_digest": {**good, "digest": good["digest"].upper()},
        "short_digest": {**good, "digest": "ab"},
        "not_a_dict": ["PLAINTEXT_SENTINEL"],
    }


@pytest.mark.parametrize("name", sorted(_bad_proofs()))
def test_non_canonical_masking_proofs_are_rejected_everywhere(name):
    from tools.bot_thread_sync import canonical_masking_proof
    bad = _bad_proofs()[name]
    assert canonical_masking_proof(bad) is None
    assert verify_masking_proof("irrelevant", bad) is False
    with pytest.raises(ValueError, match="masking_proof_ungueltig"):
        envelope(masking=bad)
    with pytest.raises(ValueError):
        ThreadEnvelope.from_wire({**envelope().to_wire(), "masking": bad})


def test_canonical_proof_survives_roundtrip_and_is_rebuilt_not_aliased():
    from tools.bot_thread_sync import canonical_masking_proof
    m = mask_text("token=abcdefgh und card 4111 1111 1111 1111")
    env = envelope(text=m.text, masking=m.proof())
    assert env.masking == m.proof() and set(env.masking) == {"provenance", "scanner_version", "match_count",
                                                            "classes", "spans", "digest"}
    again = ThreadEnvelope.from_wire(json.loads(json.dumps(env.to_wire())))
    assert again.masking == env.masking and again.digest == env.digest
    caller = m.proof()
    built = envelope(text=m.text, masking=caller)
    assert built.masking is not caller and canonical_masking_proof(caller) == built.masking
    assert verify_masking_proof(m.text, built.masking)


def test_smuggled_proof_fields_have_zero_side_effects_and_nothing_reaches_disk(tmp_path):
    proj, sentinel = [], "PLAINTEXT_SENTINEL_77"
    sync = _inbound(tmp_path, proj, name="s")
    wire = _wire_env().to_wire()
    wire["masking"] = {**wire["masking"], "klartext": sentinel * 50}
    with pytest.raises(ValueError):
        ThreadEnvelope.from_wire(wire)                      # rejected at the wire boundary, nothing built
    assert proj == [] and not (tmp_path / "s" / "journal" / "conv-1").exists()
    good = _wire_env()
    assert sync.receive(good, external_dispatch=True).status == "admitted"
    for path in (tmp_path / "s").rglob("*"):
        if path.is_file():
            assert sentinel.encode() not in path.read_bytes()
    rows = [e for e in sync.journal.events("conv-1") if "masking" in e]
    assert rows and all(set(e["masking"]) <= {"provenance", "scanner_version", "match_count", "classes",
                                              "spans", "digest"} for e in rows)
    assert all(len(json.dumps(e["masking"])) < 20_000 for e in rows)                        # hard size bound


# ---------------------------------------------------------------- strict spans, closed payload/thread schemas
@pytest.mark.parametrize("spans", [
    [[0, 10 ** 1000]], [[10 ** 1000, 10 ** 1000 + 8]], [[-10 ** 1000, 8]], [[-1, 7]], [[0, 9]], [[0, 7]],
    [[5, 5]], [[True, 8]], [[0, 8.0]], [[0, 8], [4, 12]], [[8, 16], [0, 8]], [[131072, 131080]], [[0, 8, 0]], ["ab"],
])
def test_span_coordinates_are_strictly_bounded_before_any_work(spans):
    from tools.bot_thread_sync import canonical_masking_proof
    started = time.perf_counter()
    assert canonical_masking_proof({**_proof(), "spans": spans}) is None
    assert time.perf_counter() - started < 0.5                       # no allocation / amplification on huge ints


def test_span_beyond_the_actual_text_is_not_verified_and_oversized_text_is_rejected():
    m = mask_text("token=abcdefgh")
    assert verify_masking_proof(m.text, m.proof())
    shorter = {**m.proof(), "spans": [[len(m.text) + 4, len(m.text) + 12]]}
    assert not verify_masking_proof(m.text, shorter)
    with pytest.raises(ValueError, match="text too large"):
        envelope(text="x" * 131073)


def test_from_payload_rejects_unknown_fields_like_from_wire_and_threads_are_schema_closed(tmp_path):
    from tools import bot_thread_provider as prov
    env = envelope()
    payload = {**asdict(env), "status": "gesendet", "egress_key": "e" * 64}
    assert ThreadEnvelope.from_payload(payload).message_id == "msg-1"                # known machine extras allowed
    with pytest.raises(ValueError, match="unknown payload fields"):
        ThreadEnvelope.from_payload({**payload, "unknown_field": "PLAINTEXT_SENTINEL"})
    with pytest.raises(ValueError, match="unknown"):
        envelope(source_thread={"platform": "telegram", "chat_id": "max", "thread_id": "t", "x": "PLAINTEXT_SENTINEL"})
    with pytest.raises(ValueError):
        envelope(target_thread={"platform": "telegram", "chat_id": 5, "thread_id": "t"})
    with pytest.raises(ValueError, match="unknown"):
        ThreadEnvelope.from_wire({**env.to_wire(), "target_thread": {**env.target_thread, "extra": "x"}})
    inbox = tmp_path / "inbox-home"
    inbox.mkdir()
    with pytest.raises(ValueError):                                                   # fails before persistence
        prov._drop_in_inbox(inbox, {**payload, "unknown_field": "PLAINTEXT_SENTINEL"})
    assert not (inbox / "runtime").exists()
