"""Authenticated production seam for Bot ThreadSync.

The provider is built ONLY from a runner-issued ``GatewayAuthContext``. Model arguments,
profile names, env and chat text are never authority.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import time
import types
from dataclasses import asdict
from pathlib import Path
from typing import Any

from tools import pinned_fs
from tools.bot_thread_authority import GrantBroker
from tools.bot_thread_sync import (
    AuthorityLost, GatewayAuthContext, Journal, dispatch_key, Owner, SyncResult, ThreadEnvelope, ThreadSync, _valid_message_id, derive_storage_key, mask_text,
    profile_secret_values,
)

logger = logging.getLogger(__name__)
REPLY_POLL_SECONDS = 60
INBOX_PARTS = ("runtime", "bot_thread_sync_inbox")
EGRESS_PARTS = ("runtime", "bot_thread_sync_egress")


def _active_owner(ctx: GatewayAuthContext, thread: dict[str, Any]) -> Owner | list[Owner] | None:
    """Resolve no owner, one owner, or an ambiguous set; lease expiry stays context-bound."""
    from hermes_cli.active_sessions import active_session_registry_snapshot
    home = Path(ctx.profile_home)
    rows = [e for e in active_session_registry_snapshot(registry_home=home, strict=True)
            if str((e.get("metadata") or {}).get("platform") or "") == "telegram"
            and str((e.get("metadata") or {}).get("chat_id") or "") == str(thread.get("chat_id"))
            and str((e.get("metadata") or {}).get("thread_id") or "") == str(thread.get("thread_id"))]
    if not rows:
        return None
    owners = [Owner(profile_home=str(home), profile=ctx.profile, platform="telegram",
                    chat_id=str(thread["chat_id"]), thread_id=str(thread["thread_id"]),
                    lease_id=str(entry.get("lease_id") or ""),
                    live_session_id=str((entry.get("metadata") or {}).get("live_session_id") or ""),
                    lease_expires_at=ctx.lease_expires_at)
              for entry in rows]
    return owners[0] if len(owners) == 1 else owners


def _render(payload: dict[str, Any]) -> str:
    return f"{payload['sender']} → {payload['recipient']}: {payload['text']}"


def _project(owner: Owner, payload: dict[str, Any], gate: Any = None) -> str:
    """Telegram egress through this process' own gateway credential, once per stable egress key.

    ONE broker operation context spans the final authority check, intent handling, the external send and the
    receipt/failure classification: a revoke either runs after this in-flight transaction (the send was
    authorized and its receipt is recorded) or wins before it starts (no send at all). There is no window
    between the check and the send."""
    from tools.bot_live_delivery import _send_canonical_thread_message
    key = str(payload.get("egress_key") or "")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise RuntimeError("egress_key_missing")
    gate = gate or contextlib.nullcontext
    with gate():
        fd = pinned_fs.open_chain(owner.profile_home, EGRESS_PARTS)
        try:
            if not pinned_fs.write_atomic(fd, f"{key}.intent", b"1"):
                try:
                    return str(json.loads(pinned_fs.read_bytes(fd, f"{key}.done"))["ref"])
                except ValueError:
                    raise RuntimeError("egress_ambiguous")  # sent-or-not unknown: never resend
            text = payload["text"] if payload.get("status") == "fehlgeschlagen" else _render(payload)
            result = _send_canonical_thread_message(
                {"platform": owner.platform, "chat_id": owner.chat_id, "thread_id": owner.thread_id}, text)
            if not result.get("success"):
                os.unlink(f"{key}.intent", dir_fd=fd)  # definitive provider failure → retry is safe
                raise RuntimeError("telegram_projection_failed")
            ref = str(result.get("message_id") or result.get("id") or "sent")
            pinned_fs.write_atomic(fd, f"{key}.done", json.dumps({"ref": ref}).encode())
            return ref
        finally:
            os.close(fd)


def _edit_projection(owner: Owner, message_id: str, payload: dict[str, Any], gate: Any = None) -> dict[str, Any]:
    """Edit the initial projection through the gateway; an unsupported edit is never a send fallback."""
    from tools.bot_live_delivery import _edit_canonical_thread_message
    key = str(payload.get("egress_key") or "")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise RuntimeError("egress_key_missing")
    gate = gate or contextlib.nullcontext
    with gate():
        fd = pinned_fs.open_chain(owner.profile_home, EGRESS_PARTS)
        try:
            if not pinned_fs.write_atomic(fd, f"{key}.intent", b"1"):
                try:
                    return {"success": True, "message_id": str(json.loads(pinned_fs.read_bytes(fd, f"{key}.done"))["ref"])}
                except ValueError:
                    raise RuntimeError("egress_ambiguous")
            result = _edit_canonical_thread_message(
                {"platform": owner.platform, "chat_id": owner.chat_id, "thread_id": owner.thread_id},
                message_id, _render(payload))
            if not result.get("success"):
                os.unlink(f"{key}.intent", dir_fd=fd)
                return {"success": False, "error": "Not supported"}
            pinned_fs.write_atomic(fd, f"{key}.done", json.dumps({"ref": message_id}).encode())
            return {"success": True, "message_id": message_id}
        finally:
            os.close(fd)


def _egress_ready() -> bool:
    try:
        from gateway.config import Platform, load_gateway_config
        cfg = load_gateway_config().platforms.get(Platform.TELEGRAM)
        return bool(cfg and getattr(cfg, "enabled", False))
    except Exception:
        return False


def _target(root: Path, target: str):
    """(profile, home, target_thread) for a roster target; the recipient re-authenticates on receipt."""
    from tools.bot_live_delivery import find_canonical_live_thread
    from tools.bot_mode_dm import _resolve_local_name
    from tools.bot_mode_probe import _hermes_root, _roster
    base = _hermes_root(root)
    roster = dict(_roster(base))
    profile = _resolve_local_name(str(target), list(roster), base)
    if not profile or profile not in roster:
        return None
    home = Path(roster[profile]).resolve()
    row = find_canonical_live_thread(home)
    if not row or not row.get("thread_id"):
        return None
    return profile, home, {"platform": "telegram", "chat_id": str(row["chat_id"]), "thread_id": str(row["thread_id"])}


def _reply_id(conversation_id: str, inbound_message_id: str, replier: str) -> str:
    from tools.bot_thread_sync import reply_id_for
    return reply_id_for(conversation_id, inbound_message_id, replier)


def _norm_thread(thread: dict[str, Any]) -> dict[str, str]:
    return {k: str((thread or {}).get(k) or "") for k in ("platform", "chat_id", "thread_id")}


@contextlib.contextmanager
def _profile_scope(home: str):
    """Bind the owning profile (home, secrets, config) around work that runs outside a turn."""
    from gateway.run import _profile_runtime_scope
    with _profile_runtime_scope(Path(home), hydrate_secrets=False):
        yield


def conversation_id_for(tenant: str, a: str, b: str) -> str:
    pair = "|".join([tenant, *sorted([a, b])])
    return "c" + hashlib.sha256(pair.encode()).hexdigest()[:31]


def _requires_authority(default):
    """Every privileged capability entry point re-verifies the live grant (revocation/expiry/shutdown)."""
    def wrap(fn):
        import functools

        @functools.wraps(fn)
        def inner(self, *a, **k):
            if not self._live():
                return default() if callable(default) else default
            try:
                return fn(self, *a, **k)
            except AuthorityLost:  # lost mid-operation: nothing further was written
                return default() if callable(default) else default
        return inner
    return wrap


def _atomic_authority(default):
    """Hold revocation behind one complete multi-write capability operation."""
    def wrap(fn):
        import functools

        @functools.wraps(fn)
        def inner(self, *a, **k):
            broker: Any = self._broker
            grant: Any = self._grant
            if broker is None or grant is None:
                return default() if callable(default) else default
            try:
                with broker.operation(grant):
                    return fn(self, *a, **k)
            except AuthorityLost:
                return default() if callable(default) else default
        return inner
    return wrap


def _blocked():
    return SyncResult("blocked", "autoritaet_widerrufen")


class ThreadSyncCapability:
    """Opaque handle; holds no model-controllable authority."""
    __slots__ = ("_ctx", "_sync", "_wire", "_peers", "_refresh", "_grant", "_broker", "_live")

    def __init__(self, ctx: GatewayAuthContext, sync: ThreadSync):
        self._ctx, self._sync, self._wire, self._peers, self._refresh = ctx, sync, {}, {}, None
        self._grant, self._broker, self._live = None, None, (lambda: False)  # set by build_thread_sync; default fails closed

    @property
    def context(self):
        return types.MappingProxyType({"profile": self._ctx.profile, "thread": dict(self._ctx.thread)})

    @_requires_authority(False)
    def attest(self, *names: str) -> bool:
        return self._sync.attest(*names)

    def _parent(self, conversation_id: str) -> str | None:
        rows = [r for r in self._sync.journal.events(conversation_id)
                if r.get("kind") in {"outbound_done", "inbound_receipt"}]
        return str(rows[-1]["message_id"]) if rows else None

    @_requires_authority(_blocked)
    def send(self, *, target: str, message: str, art: str = "gespraech", projection_requested: bool = False,
             transport: str = "message_agent", peer_thread: dict | None = None,
             wire_transport: Any = None, recipient: str | None = None, message_id: str | None = None,
             **_ignored: Any) -> SyncResult:
        """Model-supplied ids/threads/tenant are ignored: identity is derived from context + journal."""
        resolved = _target(Path(self._ctx.profile_home), target) if peer_thread is None else None
        if not self._live():  # blocking target resolver: re-validate before any journal/route write
            return _blocked()
        if peer_thread is not None:
            profile, home, thread = str(recipient or target), None, dict(peer_thread)
        elif resolved is None:
            return SyncResult("blocked", "ziel_unbelegt")
        else:
            profile, home, thread = resolved
        if wire_transport is not None:
            self._wire[transport] = wire_transport
        if transport == "a2a" and not self._sync.evidence.proven("a2a_ids"):
            return SyncResult("blocked", "a2a_id_unbelegt", message_id=message_id)
        conversation_id = conversation_id_for(self._ctx.tenant, self._ctx.profile, profile)
        if not _valid_message_id(message_id):
            return SyncResult("blocked", "envelope_ungueltig")
        if any(row.get("message_id") == message_id for row in self._sync.journal.events(conversation_id)):
            return SyncResult("blocked", "envelope_ungueltig", message_id=message_id)
        parent = self._parent(conversation_id)
        envelope = ThreadEnvelope(
            conversation_id=conversation_id, message_id=message_id, parent_message_id=parent,
            sender=self._ctx.profile, recipient=profile, tenant=self._ctx.tenant,
            tenant_source="gateway_context", source_thread=dict(self._ctx.thread), target_thread=thread,
            text=str(message), transport=transport, art=art if art in {"gespraech", "arbeitsauftrag"} else "gespraech",
            projection_requested=bool(projection_requested), is_root=parent is None)
        # Route, projections, transport and terminal journal state are one authorized
        # operation. Nested journal/egress gates use the broker's RLock. Revocation
        # therefore wins before this transaction or waits until its outcome is durable.
        broker: Any = self._broker
        grant: Any = self._grant
        if broker is None or grant is None:
            return _blocked()
        with broker.operation(grant):
            self._sync.journal.save_route(conversation_id, envelope.message_id, {
                "kind": "a2a" if peer_thread is not None else "native", "recipient": profile,
                "peer": str(target) if peer_thread is not None else "", "target_thread": _norm_thread(thread),
                "tenant": self._ctx.tenant})
            return self._sync.send(envelope)

    def _sender_authenticated(self, envelope: ThreadEnvelope, peer: str | None) -> bool:
        """The claimed sender profile + source thread must match an independently known identity:
        the authenticated A2A peer's allowlist entry, or the local roster profile's own live thread."""
        claimed = _norm_thread(envelope.source_thread)
        if envelope.transport == "a2a":
            allowed = self._peers.get(str(peer or ""))
            return bool(allowed and envelope.sender == allowed["profile"]
                        and claimed == _norm_thread(allowed["source_thread"]))
        # native path: the roster profile is local to this tenant
        resolved = _target(Path(self._ctx.profile_home), envelope.sender)
        return bool(resolved and resolved[0] == envelope.sender and _norm_thread(resolved[2]) == claimed)

    @_requires_authority(_blocked)
    @_atomic_authority(_blocked)
    def receive_wire(self, wire: dict, *, peer: str | None = None, external_dispatch: bool = False) -> SyncResult:
        try:
            envelope = ThreadEnvelope.from_wire(wire)
        except (TypeError, ValueError):
            return SyncResult("blocked", "envelope_ungueltig")
        if envelope.recipient != self._ctx.profile:  # addressed to someone else: no side effects at all
            return SyncResult("blocked", "empfaenger_abweichend", message_id=envelope.message_id)
        if not self._sender_authenticated(envelope, peer):
            return SyncResult("blocked", "absender_unbelegt", message_id=envelope.message_id)
        if envelope.transport == "a2a":
            # The authenticated peer's configured tenant must equal BOTH the envelope's and this
            # recipient's tenant: the message never supplies its own authority.
            tenant = self._peers[str(peer)].get("tenant")
            if not tenant or tenant != envelope.tenant or tenant != self._ctx.tenant:
                return SyncResult("blocked", "tenant_abweichend", message_id=envelope.message_id)
        with _profile_scope(self._ctx.profile_home):
            return self._sync.receive(envelope, external_dispatch=external_dispatch)

    @_requires_authority(False)
    def dispatch_begin(self, ticket: dict) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.dispatch_begin(ticket)

    @_requires_authority(False)
    def dispatch_finish(self, ticket: dict, outcome: str = "completed", reply_expected: bool = True) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.finish_dispatch(ticket, outcome, reply_expected)

    # ---- durable reply pipeline: persist the model's reply BEFORE any lease-gated step -------
    def _ticket_for(self, inbound: ThreadEnvelope) -> dict:
        from tools.bot_thread_sync import dispatch_key
        return {"conversation_id": inbound.conversation_id, "message_id": inbound.message_id, "token": "",
                "fence": 0, "key": dispatch_key(inbound.tenant, inbound.conversation_id, inbound.message_id,
                                                inbound.recipient)}

    @_requires_authority(False)
    def store_reply_pending(self, inbound_wire: dict, text: str) -> bool:
        """Mask with THIS profile's secrets and persist under the stable dispatch key. No lease is needed
        and none is synthesized; afterwards the model is never re-run for this message."""
        try:
            inbound = ThreadEnvelope.from_wire(inbound_wire)
            masked = mask_text(str(text), secrets=self._sync.current_secrets())
        except (TypeError, ValueError):
            return False
        if inbound.recipient != self._ctx.profile:
            return False
        ticket = self._ticket_for(inbound)
        # The fsynced, MAC-authenticated reply file is the commit point; the row below is an optimization
        # (a crash between them is recovered by `reply_status`, never by re-running the model).
        self._sync.journal.save_pending_reply(inbound.conversation_id, inbound.message_id,
                                              {"text": masked.text, "masking": masked.proof(),
                                               "tenant": self._ctx.tenant, "replier": self._ctx.profile,
                                               "recipient": inbound.sender, "parent": inbound.message_id,
                                               "source_thread": _norm_thread(self._ctx.thread),
                                               "target_thread": _norm_thread(inbound.source_thread),
                                               "art": "gespraech", "transport": inbound.transport},
                                              key=ticket["key"])
        return self._sync.mark_reply_pending(ticket)

    def revoke(self) -> None:
        if self._broker is not None:
            self._broker.revoke(self._grant)

    def same_identity(self, other: "ThreadSyncCapability") -> bool:
        a, b = self._ctx, other._ctx
        return ((a.profile, a.profile_home, a.tenant, a.owner, a.live_session_id, _norm_thread(a.thread))
                == (b.profile, b.profile_home, b.tenant, b.owner, b.live_session_id, _norm_thread(b.thread)))

    @_requires_authority(False)
    def flush_pending_reply(self, inbound_wire: dict) -> bool:
        """Validate/store/project/finalize an already-persisted reply under THIS capability's (valid) lease."""
        try:
            inbound = ThreadEnvelope.from_wire(inbound_wire)
        except (TypeError, ValueError):
            return False
        record = self._sync.journal.load_pending_reply(inbound.conversation_id, inbound.message_id)
        if record is not None and (record.get("tenant") != self._ctx.tenant or record.get("replier") != self._ctx.profile):
            return False  # authenticated, but written for another tenant/profile: never used
        text = record["text"] if record is not None else None
        if text is None:  # reply evidence without a pending file: the validated reply projection
            try:
                text = self._sync.journal.load_projection(
                    inbound.conversation_id, _reply_id(inbound.conversation_id, inbound.message_id,
                                                       self._ctx.profile)).text
            except (ValueError, OSError):
                return False
        result, _ = self.send_reply(inbound_wire, text)
        return result.status in {"sent", "queued"} and self.finalize_reply(inbound_wire)

    @_requires_authority(0)
    def flush_pending_replies(self) -> int:
        """Finalize every persisted-but-unfinalized reply (recovery pass; never re-runs a model)."""
        j, done = self._sync.journal, 0
        for conv in j.conversations():
            try:
                rows = j.events(conv)
            except ValueError:
                continue
            # every nonterminal dispatch: validated reply evidence (pending file OR durable reply projection)
            # is authoritative -> promote it; tampered evidence fails closed
            candidates = {r["message_id"] for r in rows if str(r.get("kind", "")).startswith("dispatch_")}
            candidates |= set(j.pending_reply_ids(conv))
            for mid in candidates:
                if j.dispatch_state(conv, mid) in {"DONE", None} or \
                        j.reply_status(conv, mid, replier=self._ctx.profile) != "valid" or \
                        j.dispatch_state(conv, mid) != "REPLY_PENDING":
                    continue
                try:
                    wire = j.load_projection(conv, mid).to_wire()
                except (ValueError, OSError):
                    continue
                done += bool(self.flush_pending_reply(wire))
        return done

    @_requires_authority(False)
    @_atomic_authority(False)
    def finalize_reply(self, inbound_wire: dict) -> bool:
        """The authenticated reply for this inbound message is durable: record REPLIED, then terminalize."""
        try:
            inbound = ThreadEnvelope.from_wire(inbound_wire)
        except (TypeError, ValueError):
            return False
        from tools.bot_thread_sync import dispatch_key
        ticket = {"conversation_id": inbound.conversation_id, "message_id": inbound.message_id, "token": "",
                  "fence": 0, "key": dispatch_key(inbound.tenant, inbound.conversation_id, inbound.message_id,
                                                  inbound.recipient)}
        with _profile_scope(self._ctx.profile_home):
            return self._sync.mark_reply_stored(ticket) and self._sync.finalize_turn(ticket)

    @_requires_authority(False)
    def dispatch_accepted(self, ticket: dict) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.accept_dispatch(ticket)

    @_requires_authority(False)
    def dispatch_release(self, ticket: dict) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.release_dispatch(ticket)

    @_requires_authority(lambda: (_blocked(), None))
    @_atomic_authority(lambda: (_blocked(), None))
    def receive_reply(self, wire: dict, *, original: ThreadEnvelope, text: str) -> tuple[SyncResult, str | None]:
        """Sender-side authentication of a peer's reply: the complete reply envelope must answer exactly
        what we sent, and ThreadSync re-scans it under THIS profile's secrets before text is exposed."""
        try:
            reply = ThreadEnvelope.from_wire(wire)
        except (TypeError, ValueError):
            return SyncResult("blocked", "envelope_ungueltig"), None
        if (reply.transport != "a2a" or reply.recipient != self._ctx.profile or reply.text != text
                or reply.conversation_id != original.conversation_id
                or reply.parent_message_id != original.message_id or reply.sender != original.recipient
                or _norm_thread(reply.source_thread) != _norm_thread(original.target_thread)
                or _norm_thread(reply.target_thread) != _norm_thread(original.source_thread)):
            return SyncResult("blocked", "antwort_unbelegt", message_id=reply.message_id), None
        self._sync.attest("a2a_admission")  # the peer is the one this call addressed
        with _profile_scope(self._ctx.profile_home):
            result = self._sync.receive(reply)
        return result, (reply.text if result.status == "received" else None)

    @_requires_authority(False)
    def dispatch_started(self, ticket: dict) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.dispatch_started(ticket)

    @_requires_authority(False)
    def ack_dispatch(self, ticket: dict) -> bool:
        with _profile_scope(self._ctx.profile_home):
            return self._sync.ack_dispatch(ticket)

    @_requires_authority(None)  # a revoked worker leaves its claim to lease expiry: nothing durable
    def abort_dispatch(self, ticket: dict) -> None:
        with _profile_scope(self._ctx.profile_home):
            self._sync.abort_dispatch(ticket)

    @_requires_authority(lambda: (_blocked(), None))
    @_atomic_authority(lambda: (_blocked(), None))
    def send_reply(self, inbound_wire: dict, text: str) -> tuple[SyncResult, ThreadEnvelope | None]:
        """Receiver-side egress of a conversational reply: masked with THIS profile's secrets, proven,
        projected in the receiver's own thread, parented to the inbound message."""
        try:
            inbound = ThreadEnvelope.from_wire(inbound_wire)
        except (TypeError, ValueError):
            return SyncResult("blocked", "envelope_ungueltig"), None
        if inbound.recipient != self._ctx.profile:
            return SyncResult("blocked", "empfaenger_abweichend"), None
        is_a2a = inbound.transport == "a2a"
        if is_a2a:  # the live HTTP response carries it; nothing is transported from here
            self._wire["a2a"] = lambda payload: None
            self._sync.attest("a2a_ids")
        # Stable reply identity: a re-run of the model (ambiguous crash) can never create a second
        # visible reply projection; the first durable reply wins and is returned again.
        reply_id = _reply_id(inbound.conversation_id, inbound.message_id, self._ctx.profile)
        if any(e.get("kind") == "outbound_done" and e.get("message_id") == reply_id
               for e in self._sync.journal.events(inbound.conversation_id)):
            return (SyncResult("sent", message_id=reply_id),
                    self._sync.journal.load_projection(inbound.conversation_id, reply_id))
        try:  # a stored reply is canonical: re-send IT, never a rebuilt/re-masked variant
            stored = self._sync.journal.load_projection(inbound.conversation_id, reply_id)
        except ValueError:
            stored = None
        if stored is not None:
            with _profile_scope(self._ctx.profile_home):
                result = self._sync.outbound.send(stored, force=True, canonical=True)
            return result, (stored if result.status == "sent" else None)
        reply = ThreadEnvelope(
            conversation_id=inbound.conversation_id, message_id=reply_id,
            parent_message_id=inbound.message_id, sender=self._ctx.profile, recipient=inbound.sender,
            tenant=self._ctx.tenant, tenant_source="gateway_context", source_thread=dict(self._ctx.thread),
            target_thread=dict(inbound.source_thread), text=str(text), transport=inbound.transport,
            art="gespraech", projection_requested=True, is_root=False)
        if not is_a2a:  # native: delivery to the original sender is rebuilt from this durable route
            self._sync.journal.save_route(inbound.conversation_id, reply_id, {
                "kind": "native", "recipient": inbound.sender, "peer": "",
                "target_thread": _norm_thread(inbound.source_thread), "tenant": self._ctx.tenant})
        with _profile_scope(self._ctx.profile_home):
            result = self._sync.send(reply)
        if result.status != "sent":
            return result, None
        return result, self._sync.journal.load_projection(inbound.conversation_id, reply_id)

    @_requires_authority(None)
    def reply_for(self, inbound_wire: dict) -> dict | None:
        """The durable reply envelope already produced for this inbound message (stable key), if any."""
        try:
            inbound = ThreadEnvelope.from_wire(inbound_wire)
        except (TypeError, ValueError):
            return None
        if inbound.recipient != self._ctx.profile:
            return None
        reply_id = _reply_id(inbound.conversation_id, inbound.message_id, self._ctx.profile)
        if not any(e.get("kind") == "outbound_done" and e.get("message_id") == reply_id
                   for e in self._sync.journal.events(inbound.conversation_id)):
            return None
        return self._sync.journal.load_projection(inbound.conversation_id, reply_id).to_wire()

    # ---- sender side: durable reply retrieval --------------------------------------------
    @_requires_authority(list)
    def pending_replies(self, *, due_only: bool = False) -> list[ThreadEnvelope]:
        """A2A messages we delivered whose reply never arrived (queued/duplicate receipt only)."""
        j, out = self._sync.journal, []
        for conv in j.conversations():
            try:
                rows = j.events(conv)
            except ValueError:
                continue
            answered = {r.get("parent_message_id") for r in rows if r.get("kind") == "inbound_receipt"}
            polls: dict[str, int] = {}
            last: dict[str, float] = {}
            for r in rows:
                if r.get("kind") == "reply_poll":
                    polls[r["message_id"]] = polls.get(r["message_id"], 0) + 1
                if r.get("kind") in {"reply_poll", "outbound_done"}:
                    last[r["message_id"]] = float(r.get("at", 0.0))
            for r in rows:
                mid = r.get("message_id")
                if r.get("kind") != "outbound_done" or mid in answered or polls.get(mid, 0) >= 8:
                    continue
                if due_only and self._sync.clock() < last.get(mid, 0.0) + REPLY_POLL_SECONDS * (1 + polls.get(mid, 0)):
                    continue  # bounded, backed-off retrieval
                try:
                    env = j.load_projection(conv, mid)
                    j.load_route(conv, mid)
                except (ValueError, OSError):
                    continue
                if env.transport == "a2a" and env.sender == self._ctx.profile:
                    out.append(env)
        return out

    @_requires_authority(0)
    @_atomic_authority(0)
    def poll_replies(self) -> int:
        """Retry the SAME A2A message (same id): the receiver answers `duplicate` with its durable reply
        contract; it is validated by `receive_reply` and projected once. Bounded per message."""
        try:
            from plugins.platforms.a2a import tools as a2a_tools
        except ImportError:
            return 0
        got = 0
        for env in self.pending_replies(due_only=True):
            route = self._sync.journal.load_route(env.conversation_id, env.message_id)
            peer = a2a_tools._resolve_peer(route["peer"])
            if not peer or not peer.get("url"):
                continue
            self._sync.journal.append(env.conversation_id, {
                "kind": "reply_poll", "conversation_id": env.conversation_id, "message_id": env.message_id})

            def receiver(contract, text, _env=env):
                result, clean = self.receive_reply(contract, original=_env, text=text)
                if clean is None:
                    raise ValueError(f"reply_unbelegt: {result.reason or result.status}")
                return clean

            try:
                broker: Any = self._broker
                grant: Any = self._grant
                with broker.operation(grant, defer_revoke=True):
                    reply, _ctx, _state = a2a_tools._send_task(
                        route["peer"], peer, env.text, env.conversation_id,
                        envelope=env, reply_receiver=receiver)
            except (ValueError, RuntimeError, OSError):
                continue
            got += bool(reply)
        return got

    @_requires_authority(lambda: 60.0)
    def next_due_delay(self, *, floor: float = 5.0, ceiling: float = 60.0) -> float:
        """Seconds until the next queued retry, bounded so the gateway loop stays responsive."""
        due = self._sync.next_due_at()
        return ceiling if due is None else min(ceiling, max(floor, due - time.time()))

    @_requires_authority(0)
    def recover(self) -> int:
        """Startup: ingest the recipient inbox, then retry both queues. Bounded, no polling."""
        # Queued conversational entries exist only because an authenticated admission happened first.
        self._sync.attest("a2a_admission")
        self._sync.attest("a2a_ids")
        with _profile_scope(self._ctx.profile_home):
            count = self._drain_held()  # finished-but-unstored model results first (no rerun)
            count += self.flush_pending_replies()  # persisted replies first: never re-run a model for them
            count += len(self.ingest_inbox())
            count += len(self._sync.retry_due())
            return count + self.poll_replies()

    def _drain_held(self) -> int:
        """Store + finalize model results the broker retained while no fresh authority existed."""
        broker, done = self._broker, 0
        for key, (wire, reply) in broker.held_items((self._ctx.profile_home, self._ctx.profile, self._ctx.tenant)):
            if self.store_reply_pending(wire, reply):
                broker.release_held(key)
                done += 1 if self.flush_pending_reply(wire) else 0
        return done

    def _ingest_native(self, wire: dict) -> SyncResult:
        """Native message_agent conversation: a REPLY to our own message is consumed (projected);
        anything else must reach the recipient's agent through a concrete dispatcher, or stay queued."""
        try:
            env = ThreadEnvelope.from_wire(wire)
        except (TypeError, ValueError):
            return SyncResult("blocked", "envelope_ungueltig")
        mine = {e.get("message_id") for e in self._sync.journal.events(env.conversation_id)
                if e.get("kind") == "outbound_done"}
        # A REPLY is the recipient agent's answer to something we sent (its id is the stable reply id of
        # that parent); a follow-up from the peer's agent merely has a parent of ours and must be run.
        if env.parent_message_id in mine and env.message_id == _reply_id(
                env.conversation_id, env.parent_message_id, env.sender):
            return self.receive_wire(wire)
        result = self.receive_wire(wire, external_dispatch=True)
        if result.status == "admitted":
            with _profile_scope(self._ctx.profile_home):
                return self._sync.dispatch_admitted(env, result.ticket)
        return result

    @_requires_authority(list)
    def ingest_inbox(self) -> list[SyncResult]:
        results = []
        fd = pinned_fs.open_chain(self._ctx.profile_home, INBOX_PARTS)
        try:
            for name in pinned_fs.list_names(fd):
                if not name.endswith(".json") or name.startswith("."):
                    continue
                try:
                    wire = json.loads(pinned_fs.read_bytes(fd, name))
                except ValueError:
                    with self._sync.journal._commit():
                        os.unlink(name, dir_fd=fd)
                    continue
                result = self._ingest_native(wire)
                results.append(result)
                if result.status in {"received", "blocked", "duplicate"}:
                    with self._sync.journal._commit():
                        os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)
        return results


def _drop_in_inbox(home: Path, payload: dict[str, Any]) -> None:
    envelope = ThreadEnvelope.from_payload(payload)
    fd = pinned_fs.open_chain(home, INBOX_PARTS)
    try:
        pinned_fs.write_atomic(fd, f"{envelope.conversation_id}-{envelope.message_id}.json",
                               json.dumps(envelope.to_wire(), sort_keys=True).encode())
    finally:
        os.close(fd)


def run_native_agent(profile: str, home: str, text: str) -> tuple[bool, str]:
    """Production native recipient seam: the existing Bot Chat turn of `profile` (same transport the
    message_agent work-task path uses). Returns (ran, reply)."""
    import io
    from contextlib import redirect_stdout
    from tools import bot_mode_dm as dm
    from tools.bot_relay import delivery_env
    dm_file = dm._write_dm_file(text)  # masked designated payload file
    try:
        argv = [dm._hermes_cli(), "-p", profile, *dm.BOT_CHAT_TURN_ARGS]
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = dm._run_local_turn(argv, dm_file, env=delivery_env(None, Path(home)))
        return code == 0, buf.getvalue().strip()
    finally:
        dm._unlink_dm_file(dm_file)


def _deliver_from_route(ctx: GatewayAuthContext, journal: Journal, payload: dict[str, Any]) -> None:
    """Re-create the recipient transport from the MAC-checked route + live re-resolution. A missing,
    altered or no-longer-matching route raises, so nothing is delivered to a guessed destination."""
    route = journal.load_route(str(payload["conversation_id"]), str(payload["message_id"]))
    kind = "a2a" if payload.get("transport") == "a2a" else "native"
    if route.get("kind") != kind or route.get("recipient") != payload.get("recipient") \
            or route.get("target_thread") != _norm_thread(payload.get("target_thread") or {}) \
            or route.get("tenant") != ctx.tenant or payload.get("tenant") != ctx.tenant:
        raise RuntimeError("route_manipuliert")
    if kind == "native":
        resolved = _target(Path(ctx.profile_home), route["recipient"])
        if not resolved or resolved[0] != route["recipient"] or _norm_thread(resolved[2]) != route["target_thread"]:
            raise RuntimeError("route_unbelegt")
        _drop_in_inbox(resolved[1], payload)
        return
    try:
        from plugins.platforms.a2a import tools as a2a_tools
    except ImportError as exc:
        raise RuntimeError("transport_unavailable") from exc
    peer = a2a_tools._resolve_peer(route["peer"])
    if not peer or not peer.get("url"):
        raise RuntimeError("route_unbelegt")
    envelope = ThreadEnvelope.from_payload(payload)
    a2a_tools._send_task(route["peer"], peer, envelope.text, envelope.conversation_id, envelope=envelope)


def default_callbacks() -> dict[str, Any]:
    """Concrete owner / egress / egress-readiness callbacks the gateway runner binds into every grant."""
    return {"owner_resolver": lambda ctx, thread: _active_owner(ctx, thread),
            "egress": lambda owner, payload, gate=None: _project(owner, payload, gate),
            "egress_edit": lambda owner, message_id, payload, gate=None: _edit_projection(owner, message_id, payload, gate),
            "egress_ready": lambda: _egress_ready()}


def build_thread_sync(grant: Any, broker: Any, *, service_scope: bool = False,
                      evidence=None, peers: dict | None = None, dispatcher: Any = None,
                      native_runner: Any = None, refresh: Any = None) -> ThreadSyncCapability | None:
    """Build ONLY from a live RunnerGrant AND the broker of the same active, runner-owned adapter that issued
    it. A bare context, a copied/forged/revoked/expired grant, a broker that is not the registered broker of a
    running adapter, or objects from another process → None (fail closed)."""
    if type(broker) is not GrantBroker:
        return None
    ctx = broker.verify(grant)
    cbs = broker.callbacks(grant)
    if ctx is None or cbs is None:
        return None

    def live() -> bool:
        return broker.verify_current(grant) is not None

    home = Path(ctx.profile_home)
    wire_transports: dict[str, Any] = {}
    journal = Journal(home / "runtime" / "bot_thread_sync", trusted_base=home)

    def commit_gate():
        return broker.operation(grant)  # every durable write: validity + write under the revocation lock

    def check() -> None:
        if not live():
            raise AuthorityLost("autoritaet_widerrufen")

    def secrets_now():
        values = tuple(profile_secret_values(home))  # untrusted/blocking callback: re-validate afterwards
        check()
        return values

    journal.commit_gate = commit_gate
    # Storage authentication key: derived from THIS profile's secret scope at use time (never stored).
    journal.key_provider = lambda: derive_storage_key(secrets_now(), ctx.tenant, ctx.profile)

    def transport(payload):
        check()
        with broker.operation(grant, defer_revoke=True):
            custom = wire_transports.get(str(payload.get("transport")))  # live call in this process
            if custom is not None:
                out = custom(payload)
            else:
                out = _deliver_from_route(ctx, journal, payload)  # recovery: rebuilt solely from durable state
        check()  # a delivery receipt needs fresh authority; otherwise nothing is persisted
        return out

    def guarded_egress(owner, payload):
        check()  # revoked at turn end / shutdown / profile switch
        # The callback's broker operation spans intent, external send and receipt.
        # Once it returns, that authorized irreversible transaction is successful;
        # a revocation that wins immediately afterwards must not reinterpret it as blocked.
        with broker.operation(grant, defer_revoke=True):
            return cbs["egress"](owner, payload, commit_gate)

    def guarded_egress_edit(owner, message_id, payload):
        check()
        with broker.operation(grant, defer_revoke=True):
            callback = cbs.get("egress_edit")
            if callback is None:
                return {"success": False, "error": "Not supported"}
            return callback(owner, message_id, payload, commit_gate)

    def owner_now(thread):
        owner = cbs["owner_resolver"](ctx, thread) if live() else None
        return owner if live() else None

    def guarded_dispatcher(fn):
        import inspect
        try:  # the engine picks the asynchronous (completion-callback) protocol by arity: preserve it
            two = len([p for p in inspect.signature(fn).parameters.values()
                       if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]) >= 2
        except (TypeError, ValueError):
            two = False

        def run(envelope, complete=None):
            # Admission into the external gateway/model dispatcher is irreversible.
            # Keep revocation behind the complete handoff; once accepted, do not
            # reinterpret that authorized result because a revoke follows it.
            return fn(envelope, complete) if two else fn(envelope)
        if not two:
            return lambda envelope: run(envelope)
        return run

    sync = ThreadSync(
        journal=journal, auth=ctx,
        owner_resolver=owner_now,
        sender_project=guarded_egress, sender_edit=guarded_egress_edit, project=guarded_egress,
        transport=transport, authority=live,
        secrets_provider=secrets_now, evidence=evidence,
        dispatchers={"a2a": guarded_dispatcher(dispatcher)} if dispatcher is not None else {},
        dispatch_gate=lambda event: broker.operation(grant, defer_revoke=True)
        if event.transport == "a2a" else contextlib.nullcontext(),
    )
    capability = ThreadSyncCapability(ctx, sync)
    capability._refresh = refresh
    if native_runner is not None and callable(refresh):  # no refresh/finalization path → the model is never run
        identity = (ctx.profile_home, ctx.profile, ctx.tenant)

        def _finish(wire: dict, reply: str, key: str):
            """Persist + finalize through a FRESH broker-issued same-identity capability; the expired launch
            capability is never required. Nothing is written when no fresh authority exists: the result stays
            in the broker's bounded in-memory hold and is retried (never re-running the model)."""
            try:
                fresh = refresh()
            except Exception:
                fresh = None
            if fresh is None or not capability.same_identity(fresh):
                broker.hold(key, identity, (wire, reply))
                return None
            if not fresh.store_reply_pending(wire, reply):
                broker.hold(key, identity, (wire, reply))
                return None
            broker.release_held(key)
            return True if fresh.flush_pending_reply(wire) else "reply_pending"

        def native_dispatch(envelope: ThreadEnvelope) -> bool:
            """Concrete recipient dispatcher for native conversation: really runs the target agent."""
            key = dispatch_key(envelope.tenant, envelope.conversation_id, envelope.message_id, envelope.recipient)
            wire = envelope.to_wire()
            held = broker.held_for(key, identity)
            if held is not None:  # result already produced: finalize it, never re-run the model
                return _finish(held[0], held[1], key)
            check()
            try:
                ok, reply = native_runner(ctx.profile, ctx.profile_home, envelope.text)
            except Exception:
                return False
            if ok and reply:
                return _finish(wire, reply, key)
            return bool(ok) if live() else None
        sync.dispatchers["message_agent"] = native_dispatch
    capability._wire = wire_transports
    for name, entry in (peers or {}).items():  # allowlist: only well-formed entries are ever honoured
        if isinstance(entry, dict) and isinstance(entry.get("profile"), str) and entry["profile"] \
                and isinstance(entry.get("source_thread"), dict) \
                and isinstance(entry.get("tenant"), str) and entry["tenant"].strip():  # tenant is mandatory
            capability._peers[str(name)] = {"profile": entry["profile"], "source_thread": entry["source_thread"],
                                            "tenant": entry["tenant"].strip()}
    sync.attest("provider_binding", "tenant")
    capability._grant, capability._broker, capability._live = grant, broker, live
    owner = cbs["owner_resolver"](ctx, ctx.thread)
    if isinstance(owner, Owner) and owner.valid(time.time()) is None:
        sync.attest("owner_lease")
    if sync.journal.verify_writable():
        sync.attest("audit")
    if cbs["egress_ready"]():
        sync.attest("egress")
        if callable(cbs.get("egress_edit")):
            sync.attest("sender_edit")
    return capability
