"""Gateway lifecycle for ThreadSync: periodic next-due recovery, shutdown cancel, per-turn capability refresh."""
import asyncio
import inspect
from types import SimpleNamespace

import pytest
from pathlib import Path

import gateway.run_thread_context as ctx_mod
from gateway.run_startup import GatewayStartupMixin


class _Runner(GatewayStartupMixin):
    def __init__(self):
        self._running = True


def test_recovery_loop_reschedules_by_next_due_and_survives_errors(monkeypatch):
    delays, passes = [], []

    def fake_pass(runner, scope=None):
        passes.append(1)
        if len(passes) == 1:
            raise RuntimeError("transient")
        return 7.0

    async def fake_sleep(d):
        delays.append(d)
        if len(delays) >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(ctx_mod, "thread_sync_recovery_pass", fake_pass)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_Runner()._thread_sync_recovery_loop(("neo", None)))
    assert delays == [60.0, 7.0, 7.0] and len(passes) == 3  # later due entries are retried, not skipped


def test_recovery_loop_is_cancelled_on_stop_and_not_duplicated(monkeypatch):
    async def scenario():
        r = _Runner()
        started = []

        async def loop():
            started.append(1)
            await asyncio.sleep(3600)

        r._thread_sync_recovery_loop = lambda scope: loop()
        monkeypatch.setattr(ctx_mod, "active_profile_scopes", lambda runner: [("neo", None)])
        r._recover_thread_sync()
        first = r._thread_sync_tasks["neo"]
        r._recover_thread_sync()
        assert r._thread_sync_tasks["neo"] is first
        await asyncio.sleep(0)
        # the shipped stop() path cancels exactly this attribute
        from gateway.run_shutdown import GatewayShutdownMixin
        stop = GatewayShutdownMixin.stop
        r._stop_task = SimpleNamespace()  # not None → stop() awaits it; give it a done future
        fut = asyncio.get_running_loop().create_future(); fut.set_result(None)
        r._stop_task = fut
        await stop(r)
        await asyncio.sleep(0)
        return first.cancelled()
    assert asyncio.run(scenario()) is True


def test_pass_uses_capability_next_due(monkeypatch):
    cap = SimpleNamespace(recover=lambda: 1, next_due_delay=lambda: 12.0)
    monkeypatch.setattr(ctx_mod, "build_gateway_extension_context", lambda r, a: cap)
    assert ctx_mod.thread_sync_recovery_pass(SimpleNamespace()) == 12.0
    monkeypatch.setattr(ctx_mod, "build_gateway_extension_context", lambda r, a: None)
    assert ctx_mod.thread_sync_recovery_pass(SimpleNamespace()) == 60.0


def test_cached_agent_gets_fresh_capability_each_turn_and_loses_stale_one(monkeypatch):
    import tools.bot_thread_provider as prov
    built = []
    monkeypatch.setattr(ctx_mod, "build_thread_auth_context", lambda **kw: built.append(kw) or (len(built),))
    monkeypatch.setattr(prov, "build_thread_sync", lambda *auth: SimpleNamespace(n=auth[0]))
    agent = SimpleNamespace(_thread_sync_capability="stale-from-previous-turn")
    kw = dict(runner=object(), source=object(), session_id="s", session_key="k", user_config={})
    ctx_mod.refresh_thread_capability(agent, **kw)
    first = agent._thread_sync_capability
    ctx_mod.refresh_thread_capability(agent, **kw)
    assert first.n == 1 and agent._thread_sync_capability.n == 2 and agent._thread_sync_capability is not first
    monkeypatch.setattr(ctx_mod, "build_thread_auth_context", lambda **k: None)  # context expired/unprovable
    monkeypatch.setattr(prov, "build_thread_sync", lambda *auth: None)
    ctx_mod.refresh_thread_capability(agent, **kw)
    assert agent._thread_sync_capability is None


def test_turn_runner_refreshes_capability_for_reused_agents():
    """Behavioural: _resolve_turn_agent must call the refresh for the reused-agent branch too."""
    from gateway.run_turn_runner import TurnRunner
    calls = []
    cached = SimpleNamespace(_thread_sync_capability="stale")
    runner = SimpleNamespace(
        _agent_config_signature=lambda *a, **k: "sig", _extract_cache_busting_config=lambda c: {},
        _agent_cache_lock=None, _agent_cache=None, _apply_fallback_chain_to_agent=lambda *a: None,
        _refresh_fallback_model=lambda: None)
    ctx = SimpleNamespace(source=SimpleNamespace(user_id=None, user_id_alt=None), enabled_toolsets=[], user_config={},
                          session_id="s", session_key="k")
    tr = TurnRunner.__new__(TurnRunner)
    tr._ctx, tr._runner = ctx, runner
    tr._skip_context_files = lambda p: False
    tr._cached_sid_is_dead = lambda *a: (None, False)
    tr._current_message_count = lambda: 0
    tr._lookup_cached_agent = lambda *a: SimpleNamespace(agent=cached, reused=True, evicted=None)
    import gateway.run_thread_context as m
    orig = m.refresh_thread_capability
    m.refresh_thread_capability = lambda agent, **kw: calls.append(agent)
    try:
        agent, reused = tr._resolve_turn_agent({"model": "m", "runtime": {}}, "telegram", "", 1, None, None)
    finally:
        m.refresh_thread_capability = orig
    assert reused and agent is cached and calls == [cached]


def test_multiplex_runs_and_stops_one_recovery_loop_per_active_profile(monkeypatch, tmp_path):
    homes = {"neo": tmp_path / "neo", "linus": tmp_path / "linus"}
    seen = []

    def fake_pass(runner, scope):
        seen.append(scope[0])
        return 3600.0

    monkeypatch.setattr(ctx_mod, "thread_sync_recovery_pass", fake_pass)
    monkeypatch.setattr(ctx_mod, "primary_scope", lambda: ("neo", homes["neo"]))
    monkeypatch.setattr("gateway.run._multiplex_profile_homes", lambda cfg: list(homes.items()))

    class R(_Runner):
        config = SimpleNamespace()
        def _multiplex_on(self):
            return True

    async def scenario():
        r = R()
        r._recover_thread_sync()
        assert set(r._thread_sync_tasks) == {"neo", "linus"}
        for _ in range(100):
            if len(seen) == 2:
                break
            await asyncio.sleep(0.01)
        from gateway.run_shutdown import GatewayShutdownMixin
        fut = asyncio.get_running_loop().create_future(); fut.set_result(None)
        r._stop_task = fut
        await GatewayShutdownMixin.stop(r)
        await asyncio.sleep(0)
        return sorted(seen), all(t.cancelled() for t in r._thread_sync_tasks.values())

    assert asyncio.run(scenario()) == (["linus", "neo"], True)


def _adapter(runner, name=None):
    return SimpleNamespace(gateway_runner=runner, _hermes_profile_name=name)


def test_adapter_scope_comes_from_the_concrete_adapter_not_ambient_process(monkeypatch, tmp_path):
    homes = {"neo": tmp_path / "neo", "linus": tmp_path / "linus"}
    monkeypatch.setattr(ctx_mod, "primary_scope", lambda: ("neo", homes["neo"]))
    monkeypatch.setattr("gateway.run._multiplex_profile_homes", lambda cfg: list(homes.items()))
    runner = SimpleNamespace(config=SimpleNamespace(), _multiplex_on=lambda: True)
    assert ctx_mod.resolve_scope(runner, _adapter(runner, "linus")) == ("linus", homes["linus"].resolve())
    assert ctx_mod.resolve_scope(runner, _adapter(runner)) == ("neo", homes["neo"])
    assert ctx_mod.resolve_scope(runner, _adapter(runner, "ghost")) is None          # not a served profile
    assert ctx_mod.resolve_scope(runner, _adapter(SimpleNamespace(), "linus")) is None  # foreign runner
    solo = SimpleNamespace(config=SimpleNamespace(), _multiplex_on=lambda: False)
    assert ctx_mod.resolve_scope(solo, _adapter(solo, "linus")) is None              # secondary without multiplex


def test_extension_context_is_built_under_the_secondary_profile_scope(monkeypatch, tmp_path):
    import contextlib
    homes = {"neo": tmp_path / "neo", "linus": tmp_path / "linus"}
    entered, built = [], []
    monkeypatch.setattr(ctx_mod, "primary_scope", lambda: ("neo", homes["neo"]))
    monkeypatch.setattr("gateway.run._multiplex_profile_homes", lambda cfg: list(homes.items()))

    @contextlib.contextmanager
    def scope(home, **kw):
        entered.append(Path(home).name)
        yield
    monkeypatch.setattr("gateway.run._profile_runtime_scope", scope)
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: {"bot_mode": {"thread_sync": {"tenant": "t"}}})
    monkeypatch.setattr(ctx_mod, "build_service_auth_context",
                        lambda *, runner, adapter, home, profile, user_config: built.append((profile, Path(home).name)) or None)
    monkeypatch.setattr(ctx_mod, "telegram_adapter_for", lambda runner, name: object())
    runner = SimpleNamespace(config=SimpleNamespace(), _multiplex_on=lambda: True)
    assert ctx_mod.build_gateway_extension_context(runner, _adapter(runner, "linus")) is None  # no live thread → closed
    assert built == [("linus", "linus")] and entered == ["linus"]  # never the primary's authority
    assert ctx_mod.build_gateway_extension_context(runner, _adapter(SimpleNamespace(), "linus")) is None
    assert built == [("linus", "linus")]  # foreign adapter: nothing built at all


def test_recovery_hands_each_profile_its_own_adapters_gateway_dispatcher(monkeypatch, tmp_path):
    neo_fn, linus_fn = (lambda env: True), (lambda env: True)
    runner = SimpleNamespace(
        adapters={"tg": SimpleNamespace(), "a2a": SimpleNamespace(dispatch_thread_message=neo_fn)},
        _profile_adapters={"linus": {"a2a": SimpleNamespace(dispatch_thread_message=linus_fn)}})
    monkeypatch.setattr(ctx_mod, "primary_scope", lambda: ("neo", tmp_path / "neo"))
    assert ctx_mod.find_dispatcher(runner, "neo") is neo_fn
    assert ctx_mod.find_dispatcher(runner, "linus") is linus_fn
    assert ctx_mod.find_dispatcher(runner, "ghost") is None  # no adapter → recovery cannot dispatch

    seen = {}
    monkeypatch.setattr(ctx_mod, "build_scoped_capability",
                        lambda runner, name, home, dispatcher=None: seen.setdefault(name, dispatcher) and None)
    ctx_mod.thread_sync_recovery_pass(runner, ("linus", tmp_path / "linus"))
    assert seen["linus"] is linus_fn
@pytest.mark.asyncio
async def test_busy_text_coalescing_completes_every_accepted_dispatch():
    from gateway.platforms.base import MessageEvent, merge_pending_message_event

    completed = []
    first = MessageEvent(text="first", message_id="task-1")
    setattr(first, "on_complete", lambda outcome: completed.append(("task-1", outcome)))
    second = MessageEvent(text="second", message_id="task-2")
    setattr(second, "on_complete", lambda outcome: completed.append(("task-2", outcome)))

    pending = {"same-session": first}
    merge_pending_message_event(pending, "same-session", second, merge_text=True)
    result = getattr(pending["same-session"], "on_complete")("completed")
    if inspect.isawaitable(result):
        await result

    assert pending["same-session"].text == "first\nsecond"
    assert completed == [("task-1", "completed"), ("task-2", "completed")]
