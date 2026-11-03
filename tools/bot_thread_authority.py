"""Adapter-owned runner authority for Bot ThreadSync.

There is NO importable mint API, no caller-name/stack authorization, and no process-wide registry that
module import or construction can populate. The registry of active brokers starts empty in every process
(and is cleared in forked children). Authority exists only as:

* a ``GrantBroker`` INSTANCE created by an active ``BasePlatformAdapter`` during its (authenticated) startup
  (``BasePlatformAdapter._mark_connected``). It is bound to that adapter object, the PID and a per-activation
  nonce, the event loop running at startup, the adapter's platform and the concrete owner/egress/audit
  callbacks registered at that moment;
* ``RunnerGrant`` objects that only that broker instance can issue, verified against the broker's own table.

The runner obtains a grant solely through the adapter's non-exported ``_issue_thread_grant`` after
authenticated ingress/session resolution. ``build_thread_sync`` needs BOTH the grant and that same broker.
Disconnect/fatal/shutdown deactivate the broker and invalidate every grant it issued.

Threat model: this separates separate processes (model-facing terminals, other tools) and untrusted
serialized data from the gateway. Arbitrary code already executing inside the live gateway process can
introspect Python state; that is not a boundary Python offers and is not claimed here.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import weakref
import contextlib
from typing import Any, Callable, Mapping

from tools.bot_thread_sync import RUNTIME_INSTANCE, AuthorityLost, GatewayAuthContext

_monotonic = time.monotonic              # held-result TTL uses a monotonic clock, independent of wall-clock leases
_LOCK = threading.RLock()
_ACTIVE: dict[int, "GrantBroker"] = {}   # id(adapter) -> broker; EMPTY at import in every process
_REQUIRED_CALLBACKS = ("owner_resolver", "egress", "egress_ready")
_BUILD = object()                        # construction key: only `_activate` passes it


def _after_fork_in_child() -> None:
    _ACTIVE.clear()  # a forked child inherits no active gateway; grants minted by the parent are void


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


class RunnerGrant:
    """Opaque capability handle. Not constructible, copyable, picklable or printable with its identity."""
    __slots__ = ("_id", "_ctx", "_tag", "_broker", "__weakref__")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("RunnerGrant is issued by an active adapter's broker only")

    def __repr__(self) -> str:
        return "<RunnerGrant>"

    __str__ = __repr__

    def __reduce__(self):  # noqa: D105
        raise TypeError("RunnerGrant cannot be serialized")

    def __reduce_ex__(self, protocol):  # noqa: D105
        raise TypeError("RunnerGrant cannot be serialized")

    def __copy__(self):  # noqa: D105
        raise TypeError("RunnerGrant cannot be copied")

    def __deepcopy__(self, memo):  # noqa: D105
        raise TypeError("RunnerGrant cannot be copied")


class GrantBroker:
    """Per-active-adapter issuer/verifier. Created only by ``_activate`` (from the adapter's startup)."""
    __slots__ = ("_adapter", "_runner", "_pid", "_nonce", "_loop", "_platform", "_callbacks", "_grants",
                 "_active", "_oplock", "_oplocal", "_held", "__weakref__")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if len(args) != 1 or args[0] is not _BUILD:
            raise TypeError("GrantBroker is created by an active platform adapter only")
        self._active = False

    def __repr__(self) -> str:
        return "<GrantBroker>"

    __str__ = __repr__

    def __reduce__(self):  # noqa: D105
        raise TypeError("GrantBroker cannot be serialized")

    def __reduce_ex__(self, protocol):  # noqa: D105
        raise TypeError("GrantBroker cannot be serialized")

    def __copy__(self):  # noqa: D105
        raise TypeError("GrantBroker cannot be copied")

    def __deepcopy__(self, memo):  # noqa: D105
        raise TypeError("GrantBroker cannot be copied")

    # ------------------------------------------------------------------ liveness
    def is_active(self) -> bool:
        """True only for the registered broker of a currently running adapter in THIS process."""
        try:
            adapter = self._adapter()
            if not (self._active and self._pid == os.getpid() and adapter is not None
                    and self._runner() is not None
                    and getattr(adapter, "gateway_runner", None) is self._runner()):
                return False
            if getattr(adapter, "_running", False) is not True:
                return False
            if self._loop is not None and self._loop.is_closed():
                return False
            with _LOCK:
                return _ACTIVE.get(id(adapter)) is self
        except AttributeError:
            return False  # object.__new__ without activation

    def adapter_is(self, adapter: Any) -> bool:
        try:
            return self.is_active() and self._adapter() is adapter
        except AttributeError:
            return False

    @property
    def platform(self) -> str:
        return self._platform

    # ------------------------------------------------------------------ issue / verify
    def _tag_of(self, grant_id: str, ctx: GatewayAuthContext) -> str:
        body = json.dumps(dataclasses.asdict(ctx), sort_keys=True, default=str)
        material = f"{grant_id}|{self._pid}|{id(self._adapter())}|{self._platform}|{body}"
        return hmac.new(self._nonce, material.encode(), hashlib.sha256).hexdigest()

    def _issue(self, ctx: GatewayAuthContext) -> RunnerGrant:
        if not self.is_active():
            raise PermissionError("adapter_not_active")
        if not isinstance(ctx, GatewayAuthContext) or ctx.runtime_instance != RUNTIME_INSTANCE:
            raise ValueError("context does not belong to this runtime")
        if str((ctx.thread or {}).get("platform") or "") != self._platform:
            raise ValueError("context platform differs from the adapter platform")
        grant_id = secrets.token_hex(16)
        bound = dataclasses.replace(ctx, owner_token=grant_id)  # the opaque id IS the owner token
        grant = object.__new__(RunnerGrant)
        grant._id, grant._ctx, grant._broker = grant_id, bound, weakref.ref(self)
        grant._tag = self._tag_of(grant_id, bound)
        with _LOCK:
            self._prune_grants_locked(time.time())
            self._grants[grant_id] = grant
        return grant

    def _prune_grants_locked(self, now: float) -> None:
        for grant_id in [grant_id for grant_id, grant in self._grants.items()
                         if grant._ctx.invalid(now) is not None]:
            del self._grants[grant_id]

    def verify(self, grant: Any, now: float | None = None) -> GatewayAuthContext | None:
        """The bound context iff this exact grant was issued by THIS active broker, is untampered, live and
        unexpired."""
        if type(grant) is not RunnerGrant or not self.is_active():
            return None
        try:
            grant_id, ctx, tag, owner = grant._id, grant._ctx, grant._tag, grant._broker
        except AttributeError:
            return None  # object.__new__ without issuing
        if owner() is not self:
            return None
        with _LOCK:
            if self._grants.get(grant_id) is not grant:
                return None
        if not hmac.compare_digest(tag, self._tag_of(grant_id, ctx)):
            return None
        checked_at = time.time() if now is None else now
        if ctx.invalid(checked_at) is None:
            return ctx
        with _LOCK:
            if self._grants.get(grant_id) is grant:
                del self._grants[grant_id]
        return None

    def verify_current(self, grant: Any) -> GatewayAuthContext | None:
        """Verify against an active transaction's admission time on its owning thread."""
        if getattr(self._oplocal, "depth", 0) > 0 and getattr(self._oplocal, "preserve_lease", False) \
                and grant is getattr(self._oplocal, "grant", None):
            return self.verify(grant, now=getattr(self._oplocal, "handoff_at", 0.0))
        return self.verify(grant)

    @contextlib.contextmanager
    def operation(self, grant: Any, *, defer_revoke: bool = False):
        """Operation lease for ONE durable mutation: validity is checked and the write happens under the same
        lock revocation takes, so the write either commits while the grant was valid or never starts. Revoke
        waits for an in-flight write; nothing new starts after revoke. Nested commits inherit the outer
        transaction's admission time so an in-flight irreversible handoff can durably terminalize even when
        its wall-clock lease expires; membership/revocation is still checked on every nested gate."""
        with self._oplock:  # per broker: an in-flight egress never blocks other profiles' writes
            depth = getattr(self._oplocal, "depth", 0)
            preserving = bool(getattr(self._oplocal, "preserve_lease", False))
            if depth and preserving:
                valid = grant is getattr(self._oplocal, "grant", None) and \
                    self.verify(grant, now=getattr(self._oplocal, "handoff_at", 0.0)) is not None
            else:
                valid = self.verify(grant) is not None
            if not valid:
                raise AuthorityLost("autoritaet_widerrufen")
            if not depth:
                self._oplocal.grant = grant
            if defer_revoke and not preserving:
                self._oplocal.preserve_lease = True
                self._oplocal.handoff_at = time.time()
            self._oplocal.depth = depth + 1
            if defer_revoke:
                self._oplocal.defer_depth = getattr(self._oplocal, "defer_depth", 0) + 1
            try:
                yield
            finally:
                if defer_revoke:
                    self._oplocal.defer_depth -= 1
                self._oplocal.depth -= 1
                if self._oplocal.depth == 0:
                    self._apply_deferred_revocation()
                    self._oplocal.grant = None
                    self._oplocal.preserve_lease = False
                    self._oplocal.handoff_at = 0.0

    def _apply_deferred_revocation(self) -> None:
        ids = set(getattr(self._oplocal, "pending_ids", set()))
        deactivate = bool(getattr(self._oplocal, "pending_deactivate", False))
        self._oplocal.pending_ids = set()
        self._oplocal.pending_deactivate = False
        with _LOCK:
            for grant_id in ids:
                self._grants.pop(grant_id, None)
            if deactivate:
                self._active = False
                self._grants.clear()
                self._held.clear()
                adapter = self._adapter() if hasattr(self, "_adapter") else None
                if adapter is not None and _ACTIVE.get(id(adapter)) is self:
                    del _ACTIVE[id(adapter)]

    def callbacks(self, grant: Any) -> dict[str, Callable[..., Any]] | None:
        return dict(self._callbacks) if self.verify(grant) is not None else None

    # ------------------------------------------------------------------ revocation
    def revoke(self, grant: Any) -> None:
        self._drop(lambda candidate: candidate is grant)

    def revoke_turn(self, turn_id: str) -> int:
        return self._drop(lambda g: g._ctx.turn_id == turn_id)

    def revoke_profile(self, profile_home: str) -> int:
        return self._drop(lambda g: g._ctx.profile_home == str(profile_home))

    def revoke_all(self) -> int:
        return self._drop(lambda g: True)

    def _drop(self, match: Callable[[RunnerGrant], bool]) -> int:
        with self._oplock:
            with _LOCK:
                gone = [k for k, g in self._grants.items() if match(g)]
                if getattr(self._oplocal, "defer_depth", 0) > 0:
                    pending = set(getattr(self._oplocal, "pending_ids", set()))
                    pending.update(gone)
                    self._oplocal.pending_ids = pending
                else:
                    for k in gone:
                        del self._grants[k]
        return len(gone)

    # ------------------------------------------------------------------ bounded in-memory completions
    MAX_HELD = 32
    HELD_TTL = 3600.0

    def _prune_held_locked(self, now: float) -> None:
        for key in [key for key, (created, _identity, _item) in self._held.items()
                    if now - created > self.HELD_TTL]:
            del self._held[key]

    def hold(self, key: str, identity: tuple, item: Any) -> bool:
        """Retain a finished model result (never persisted) until a fresh same-identity grant can store it.
        Bounded and TTL'd; tied to the stable dispatch key so the model is never re-run for it."""
        now = _monotonic()
        with _LOCK:
            if not self._active:
                return False
            self._prune_held_locked(now)
            if key not in self._held and len(self._held) >= self.MAX_HELD:
                return False
            self._held[key] = (now, identity, item)
            return True

    def held_for(self, key: str, identity: tuple) -> Any:
        with _LOCK:
            self._prune_held_locked(_monotonic())
            entry = self._held.get(key)
            return entry[2] if entry is not None and entry[1] == identity else None

    def held_items(self, identity: tuple) -> list[tuple[str, Any]]:
        with _LOCK:
            self._prune_held_locked(_monotonic())
            return [(k, x) for k, (_t, i, x) in self._held.items() if i == identity]

    def release_held(self, key: str) -> None:
        with _LOCK:
            self._held.pop(key, None)

    def grant_count(self) -> int:
        with _LOCK:
            return len(self._grants)

    def _deactivate(self) -> None:
        oplock: Any = self._oplock
        with oplock:
            if getattr(self._oplocal, "defer_depth", 0) > 0:
                self._oplocal.pending_deactivate = True
                return
            self._oplocal.pending_deactivate = True
            self._apply_deferred_revocation()


def _activate(adapter: Any, loop: Any, callbacks: Mapping[str, Callable[..., Any]]) -> GrantBroker | None:
    """Called by ``BasePlatformAdapter`` startup only. Refuses anything that is not a real, running
    ``BasePlatformAdapter`` with concrete callbacks; replaces (and invalidates) a previous broker."""
    from gateway.platforms.base import BasePlatformAdapter
    runner = getattr(adapter, "gateway_runner", None)
    if not isinstance(adapter, BasePlatformAdapter) or getattr(adapter, "_running", False) is not True \
            or runner is None:
        return None  # detached / not started / not owned by a gateway runtime
    if not all(callable(callbacks.get(name)) for name in _REQUIRED_CALLBACKS):
        return None
    platform = str(getattr(getattr(adapter, "platform", None), "value", "") or "")
    if not platform:
        return None
    broker = GrantBroker(_BUILD)
    try:
        broker._runner = weakref.ref(runner)
    except TypeError:
        return None
    broker._adapter = weakref.ref(adapter, lambda _r, key=id(adapter): _forget(key))
    broker._pid, broker._nonce, broker._loop = os.getpid(), secrets.token_bytes(32), loop
    broker._platform, broker._callbacks, broker._grants = platform, dict(callbacks), {}
    broker._oplock, broker._oplocal, broker._held = threading.RLock(), threading.local(), {}
    with _LOCK:
        previous = _ACTIVE.get(id(adapter))
        if previous is not None:
            previous._active = False
            previous._grants.clear()
            previous._held.clear()
        broker._active = True
        _ACTIVE[id(adapter)] = broker
    return broker


def _forget(key: int) -> None:
    with _LOCK:
        broker = _ACTIVE.pop(key, None)
        if broker is not None:
            broker._active = False
            broker._grants.clear()
            broker._held.clear()


def deactivate_adapter(adapter: Any) -> None:
    """Disconnect/fatal/shutdown: unregister the adapter's broker and invalidate every grant it issued."""
    with _LOCK:
        broker = _ACTIVE.get(id(adapter))
    if broker is not None:
        broker._deactivate()


def deactivate_all() -> int:
    """Gateway shutdown: no broker (hence no grant) of this process stays valid. Revocation-only."""
    with _LOCK:
        brokers = list(_ACTIVE.values())
    for broker in brokers:
        broker._deactivate()
    return len(brokers)


def active_broker_count() -> int:
    with _LOCK:
        return len(_ACTIVE)
