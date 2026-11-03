"""Shared fixtures for ThreadSync tests: real runner-style contexts, real evidence, no fakes of authority."""
from __future__ import annotations

import time
from pathlib import Path

from tools.bot_thread_sync import (
    RUNTIME_INSTANCE, SEAMS, EvidenceRegistry, GatewayAuthContext, Journal, Owner, ThreadEnvelope, ThreadSync,
    build_evidence_entries,
)
from types import SimpleNamespace

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter

REPO = Path(__file__).resolve().parents[2]
ATTEST = tuple(n for n in SEAMS if n != "message_agent")


def make_ctx(home, *, profile="neo", chat="max", thread="neo-t", tenant="tenant-1", live="live-1",
             conversation="conv-1", now=None, lease=300, instance=RUNTIME_INSTANCE, token=None):
    now = time.time() if now is None else now
    th = {"platform": "telegram", "chat_id": chat, "thread_id": thread}
    return GatewayAuthContext(
        profile_home=str(home), profile=profile, owner="max", tenant=tenant, conversation_id=conversation,
        thread=th, live_session_id=live, runtime_instance=instance,
        owner_token=token or "test-opaque-token",
        turn_id=f"{conversation}:{now}", observed_at=now, lease_expires_at=now + lease)


def registry(revision="rev-test"):
    return EvidenceRegistry(revision, build_evidence_entries(REPO, revision), repo_root=REPO)


def owner_for(ctx):
    t = ctx.thread
    return Owner(ctx.profile_home, ctx.profile, "telegram", t["chat_id"], t["thread_id"], "lease-1",
                 ctx.live_session_id, ctx.lease_expires_at)


def make_sync(tmp_path, ctx=None, *, name="a", attest=ATTEST, **kw):
    home = Path(tmp_path) / name
    home.mkdir(parents=True, exist_ok=True)
    ctx = ctx or make_ctx(home)
    kw.setdefault("owner_resolver", lambda thread: owner_for(ctx) if thread.get("thread_id") == ctx.thread["thread_id"] else None)
    kw.setdefault("evidence", registry())
    sync = ThreadSync(journal=Journal(home / "journal", trusted_base=home), auth=ctx, **kw)
    if attest:
        sync.attest(*attest)
    return sync


def envelope(**over):
    data = dict(conversation_id="conv-1", message_id="msg-1", parent_message_id=None, sender="neo",
                recipient="linus", tenant=None, tenant_source=None,
                source_thread={"platform": "telegram", "chat_id": "max", "thread_id": "neo-t"},
                target_thread={"platform": "telegram", "chat_id": "max", "thread_id": "linus-t"},
                text="hello", transport="a2a", art="gespraech", projection_requested=False, is_root=True)
    data.update(over)
    return ThreadEnvelope(**data)


class _StartedAdapter(BasePlatformAdapter):
    """Strictly test-local Telegram adapter: started through the REAL `_mark_connected` startup path."""
    async def connect(self, *, is_reconnect=False): return True
    async def disconnect(self): self._mark_disconnected()
    async def send(self, chat_id, content, reply_to=None, metadata=None): raise AssertionError("no live traffic")
    async def get_chat_info(self, chat_id): return {}


_ADAPTERS: dict = {}   # profile -> (runner, adapter), kept alive for the test process


class _Runner:
    """Test-local stand-in for GatewayRunner's ownership surface."""
    def __init__(self, adapters, profile):
        self.adapters, self._profile_adapters, self._primary_profile_name = adapters, {}, profile


def started_adapter(profile="neo", *, start=True, runner=True):
    """A real BasePlatformAdapter owned by a runner stub; `start` runs the production startup hook."""
    adapter = _StartedAdapter(PlatformConfig(enabled=True), Platform.TELEGRAM)
    adapter._hermes_profile_name = profile
    run = _Runner({Platform.TELEGRAM: adapter}, profile)
    if runner:
        adapter.gateway_runner = run
    adapter._test_runner = run
    if start:
        adapter._mark_connected()
    return adapter


def make_grant(home, **kw):
    """(grant, broker) issued by a started adapter through the production `_issue_thread_grant` path."""
    ctx = make_ctx(home, **kw)
    cached = _ADAPTERS.get(ctx.profile)
    if cached is None or cached._thread_broker is None or not cached._thread_broker.is_active():
        cached = _ADAPTERS[ctx.profile] = started_adapter(ctx.profile)
    issued = cached._issue_thread_grant(cached._test_runner, ctx)
    assert issued is not None
    return issued


def build(issued, **kw):
    """build_thread_sync from an `(grant, broker)` pair."""
    from tools.bot_thread_provider import build_thread_sync
    return build_thread_sync(*issued, **kw)


def reset_authority() -> None:
    """Fixture lifecycle: no broker (and no held result) outlives its test."""
    from tools import bot_thread_authority
    bot_thread_authority.deactivate_all()
    _ADAPTERS.clear()
