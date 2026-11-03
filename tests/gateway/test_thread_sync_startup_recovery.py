"""Startup seam: ThreadSync recovery is scheduled once at gateway start; failures never abort startup."""
import asyncio
from types import SimpleNamespace

import gateway.run_thread_context as ctx_mod
from gateway.run_startup import GatewayStartupMixin


class _Runner(GatewayStartupMixin):
    _running = True


def test_startup_schedules_one_recovery_task_that_runs_a_pass(monkeypatch):
    passes = []
    monkeypatch.setattr(ctx_mod, "thread_sync_recovery_pass", lambda runner, scope=None: passes.append(runner) or 3600.0)
    monkeypatch.setattr(ctx_mod, "active_profile_scopes", lambda runner: [("neo", None)])

    async def scenario():
        r = _Runner()
        r._recover_thread_sync()
        task = r._thread_sync_tasks["neo"]
        r._recover_thread_sync()
        assert r._thread_sync_tasks["neo"] is task  # not duplicated
        for _ in range(50):
            if passes:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        return passes

    assert asyncio.run(scenario()) and len(passes) == 1


def test_recovery_without_context_is_noop_and_errors_do_not_escape(monkeypatch):
    monkeypatch.setattr(ctx_mod, "build_gateway_extension_context", lambda r, a: None)
    monkeypatch.setattr(ctx_mod, "build_scoped_capability", lambda runner, name, home, **kw: None)
    assert ctx_mod.recover_thread_sync_queues(SimpleNamespace()) == 0
    assert ctx_mod.thread_sync_recovery_pass(SimpleNamespace()) == 60.0
