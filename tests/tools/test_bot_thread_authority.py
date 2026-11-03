"""Runner authority belongs to an ACTIVE adapter's broker instance: no module-level mint, no name/stack checks."""
import copy
import gc
import pickle
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.bot_thread_provider as prov
import tools.bot_thread_sync as sync_mod
from tools import bot_thread_authority as authority
from tests.tools.bot_thread_support import (
    build, envelope, _Runner, make_ctx, make_grant, registry, started_adapter,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _fresh_authority():
    from tests.tools.bot_thread_support import reset_authority
    reset_authority()
    yield
    reset_authority()


def test_no_module_level_mint_or_caller_name_authorization_exists():
    for name in ("mint", "_allow_test_minter", "_ALLOWED_MINTERS", "revoke_all", "verify", "callbacks"):
        assert not hasattr(authority, name), name
    assert not hasattr(sync_mod, "issue_owner_token")


def test_grant_hides_identity_and_context_data_confers_nothing(tmp_path):
    grant, broker = make_grant(tmp_path)
    ctx = broker.verify(grant)
    assert repr(grant) == str(grant) == "<RunnerGrant>" and not hasattr(grant, "__dict__")
    assert ctx.owner_token not in repr(grant)
    for fake in (make_ctx(tmp_path), vars(ctx), SimpleNamespace(**vars(ctx)), None, "g", 7,
                 object.__new__(authority.RunnerGrant)):
        assert prov.build_thread_sync(fake, broker, evidence=registry()) is None


def test_spoofed_module_name_stack_and_bare_construction_register_nothing(tmp_path):
    code = compile("import tools.bot_thread_authority as a\nr = []\n"
                   "for f in (lambda: a.GrantBroker(), lambda: a.GrantBroker(object()), lambda: a.RunnerGrant()):\n"
                   "    try: f()\n    except TypeError: r.append('denied')\n"
                   "r.append(hasattr(a, 'mint'))", "<spoof>", "exec")
    scope = {"__name__": "gateway.run_thread_context"}
    exec(code, scope)
    assert scope["r"] == ["denied", "denied", "denied", False]
    bare = object.__new__(authority.GrantBroker)
    assert not bare.is_active() and bare.verify(object.__new__(authority.RunnerGrant)) is None
    grant, real = make_grant(tmp_path)
    before = authority.active_broker_count()
    assert prov.build_thread_sync(grant, bare, evidence=registry()) is None       # grant of another broker
    make_ctx(tmp_path)                                                             # context data is inert
    assert authority.active_broker_count() == before          # constructing data/brokers registers nothing
    assert build((grant, real), evidence=registry()) is not None


def test_copied_pickled_or_field_cloned_grants_and_brokers_are_rejected(tmp_path):
    grant, broker = make_grant(tmp_path)
    for obj in (grant, broker):
        for attempt in (lambda: copy.copy(obj), lambda: copy.deepcopy(obj), lambda: pickle.dumps(obj)):
            with pytest.raises(TypeError):
                attempt()
    clone = object.__new__(authority.RunnerGrant)
    for slot in ("_id", "_ctx", "_tag", "_broker"):
        setattr(clone, slot, getattr(grant, slot))
    assert broker.verify(clone) is None and prov.build_thread_sync(clone, broker, evidence=registry()) is None


def test_inactive_detached_or_runnerless_adapters_cannot_issue_or_register(tmp_path):
    ctx = make_ctx(tmp_path)
    for adapter in (started_adapter(start=False), started_adapter(runner=False)):
        assert adapter._thread_broker is None and adapter._issue_thread_grant(adapter._test_runner, ctx) is None
    stranger = started_adapter()
    assert stranger._issue_thread_grant(SimpleNamespace(adapters={}), ctx) is None   # not the adapter's runner
    foreign = _Runner({}, "neo")
    stranger.gateway_runner = foreign                                                  # runner does not own it
    assert stranger._issue_thread_grant(foreign, ctx) is None
    plain = SimpleNamespace(_running=True, gateway_runner=object(), platform=SimpleNamespace(value="telegram"))
    assert authority._activate(plain, None, prov.default_callbacks()) is None          # not a BasePlatformAdapter
    wrong = started_adapter("other")
    assert wrong._issue_thread_grant(wrong._test_runner, ctx) is None                  # adapter serves another profile


def test_wrong_platform_context_is_refused(tmp_path):
    adapter = started_adapter()
    ctx = make_ctx(tmp_path)
    other = sync_mod.GatewayAuthContext(**{**vars(ctx), "thread": {**ctx.thread, "platform": "discord"}})
    assert adapter._issue_thread_grant(adapter._test_runner, other) is None


def test_disconnect_fatal_and_shutdown_deactivate_the_broker_and_invalidate_grants(tmp_path):
    for how in ("disconnect", "fatal", "running_flag", "deactivate_all"):
        adapter = started_adapter()
        grant, broker = adapter._issue_thread_grant(adapter._test_runner, make_ctx(tmp_path / how))
        cap = build((grant, broker), evidence=registry())
        assert cap is not None and cap._live()
        {"disconnect": adapter._mark_disconnected,
         "fatal": lambda: adapter._set_fatal_error("x", "y", retryable=False),
         "running_flag": lambda: setattr(adapter, "_running", False),
         "deactivate_all": authority.deactivate_all}[how]()
        assert not cap._live() and broker.verify(grant) is None and not broker.is_active()
        assert (cap.send(target="linus", message="x").reason, cap.recover()) == ("autoritaet_widerrufen", 0)
        assert prov.build_thread_sync(grant, broker, evidence=registry()) is None
    adapter = started_adapter()                       # reconnect = a NEW broker; old grants stay dead
    old_grant, old_broker = adapter._issue_thread_grant(adapter._test_runner, make_ctx(tmp_path / "re"))
    adapter._mark_connected()
    assert adapter._thread_broker is not old_broker and old_broker.verify(old_grant) is None
    assert adapter._issue_thread_grant(adapter._test_runner, make_ctx(tmp_path / "re")) is not None


def test_turn_profile_and_single_revocation_and_expiry(tmp_path):
    for how in ("turn", "profile", "all", "single"):
        grant, broker = make_grant(tmp_path / how, conversation=f"s-{how}")
        ctx = broker.verify(grant)
        cap = build((grant, broker), evidence=registry())
        assert cap is not None and cap._live()
        {"turn": lambda: broker.revoke_turn(ctx.turn_id), "profile": lambda: broker.revoke_profile(ctx.profile_home),
         "all": broker.revoke_all, "single": cap.revoke}[how]()
        assert not cap._live()
        assert cap.send(target="linus", message="x").reason == "autoritaet_widerrufen"
    kept, broker = make_grant(tmp_path / "keep")
    assert broker.revoke_turn("other-turn") == 0 and broker.verify(kept) is not None
    expired = make_grant(tmp_path / "exp", lease=-5)
    assert prov.build_thread_sync(*expired, evidence=registry()) is None


def test_revoked_grant_stops_egress_inside_a_running_sync(tmp_path):
    projected = []
    grant, broker = make_grant(tmp_path / "a")
    cap = build((grant, broker), evidence=registry())
    cap._sync.sender_project = lambda o, p: projected.append(p) or "x"
    broker.revoke(grant)
    assert cap._sync.send(envelope()).reason == "autoritaet_widerrufen" and projected == []


def test_refreshing_a_cached_agent_capability_requires_a_new_grant_and_revokes_the_old(monkeypatch, tmp_path):
    import gateway.run_thread_context as ctx_mod
    issued = []

    def new_grant(**kw):
        issued.append(make_grant(tmp_path / f"t{len(issued)}"))
        return issued[-1]

    monkeypatch.setattr(ctx_mod, "build_thread_auth_context", new_grant)
    agent = SimpleNamespace()
    kw = dict(runner=object(), source=object(), session_id="s", session_key="k", user_config={})
    ctx_mod.refresh_thread_capability(agent, **kw)
    first = agent._thread_sync_capability
    ctx_mod.refresh_thread_capability(agent, **kw)
    (g0, b0), (g1, b1) = issued
    assert b0.verify(g0) is None and b1.verify(g1) is not None and agent._thread_sync_capability is not first


def test_real_runner_seam_issues_through_the_started_adapter_only(tmp_path):
    import gateway.run_thread_context as ctx_mod
    adapter = started_adapter()
    issued = ctx_mod._issue(runner=adapter._test_runner, adapter=adapter, home=tmp_path / "h", profile="neo",
                            tenant="tenant-1", conversation_id="s-1", chat_id="max", thread_id="neo-t",
                            live_session_id="live-a", now=time.time())
    grant, broker = issued
    ctx = broker.verify(grant)
    assert ctx is not None and ctx.runtime_instance == sync_mod.RUNTIME_INSTANCE and ctx.owner_token
    assert build(issued, evidence=registry()) is not None
    assert set(broker.callbacks(grant)) >= {"owner_resolver", "egress", "egress_ready"}
    idle = started_adapter(start=False)
    assert ctx_mod._issue(runner=idle._test_runner, adapter=idle, home=tmp_path / "h", profile="neo",
                          tenant="t", conversation_id="s", chat_id="max", thread_id="neo-t",
                          live_session_id="l", now=time.time()) is None
    assert ctx_mod._issue(runner=adapter._test_runner, adapter=object(), home=tmp_path, profile="neo", tenant="t",
                          conversation_id="s", chat_id="m", thread_id="t", live_session_id="l",
                          now=time.time()) is None


def test_garbage_collected_adapter_unregisters_its_broker(tmp_path):
    adapter = started_adapter("gc-profile")
    grant, broker = adapter._issue_thread_grant(adapter._test_runner, make_ctx(tmp_path, profile="gc-profile"))
    assert broker.is_active()
    del adapter
    gc.collect()
    assert not broker.is_active() and broker.verify(grant) is None


def test_isolated_process_cannot_mint_build_or_register_anything():
    code = f"""
import sys
sys.path.insert(0, {str(REPO)!r})
from tools import bot_thread_authority as a, bot_thread_provider as p, bot_thread_sync as s
import gateway.run_thread_context
out = []
out.append("empty" if a.active_broker_count() == 0 else "nonempty")
out.append("no-mint" if not any(hasattr(a, n) for n in ("mint", "issue", "verify")) else "mint")
for f in (lambda: a.GrantBroker(), lambda: a.RunnerGrant()):
    try: f()
    except TypeError: out.append("denied")
ctx = s.GatewayAuthContext(profile_home="/tmp/x", profile="neo", owner="max", tenant="t", conversation_id="c",
    thread={{"platform": "telegram", "chat_id": "1", "thread_id": "2"}}, live_session_id="l",
    runtime_instance=s.RUNTIME_INSTANCE, owner_token="", turn_id="t", observed_at=0.0, lease_expires_at=9e12)
bare, fake = object.__new__(a.GrantBroker), object.__new__(a.RunnerGrant)
out.append("fake-none" if p.build_thread_sync(fake, bare) is None and p.build_thread_sync(ctx, bare) is None else "built")
out.append("still-empty" if a.active_broker_count() == 0 else "registered")
print(",".join(out))
"""
    res = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert res.stdout.strip() == "empty,no-mint,denied,denied,fake-none,still-empty", res.stderr
