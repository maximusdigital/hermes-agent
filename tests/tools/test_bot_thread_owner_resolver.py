"""Provider owner resolution distinguishes no owner from ambiguous ownership."""
import tools.bot_thread_provider as prov
from tests.tools.test_bot_thread_provider import world
from tests.tools.bot_thread_support import make_grant, registry


def _rows(ctx, count):
    """Make matching live-registry rows without inventing a second thread identity."""
    return [{
        "lease_id": f"lease-{index}",
        "metadata": {
            "platform": "telegram",
            "chat_id": str(ctx.thread["chat_id"]),
            "thread_id": str(ctx.thread["thread_id"]),
            "live_session_id": ctx.live_session_id,
        },
    } for index in range(count)]


def test_no_owner_is_queued_as_kein_aktiver_owner(world, monkeypatch):
    capability = world.cap("neo")
    monkeypatch.setattr("hermes_cli.active_sessions.active_session_registry_snapshot",
                        lambda **_kwargs: [])

    assert prov._active_owner(capability._ctx, capability._ctx.thread) is None
    result = capability.send(target="linus", message="ohne owner")

    assert (result.status, result.reason) == ("queued", "kein_aktiver_owner")
    assert world.egress == []


def test_ambiguous_owners_are_blocked_before_projection(world, monkeypatch):
    capability = world.cap("neo")
    monkeypatch.setattr("hermes_cli.active_sessions.active_session_registry_snapshot",
                        lambda **_kwargs: _rows(capability._ctx, 2))

    owners = prov._active_owner(capability._ctx, capability._ctx.thread)
    assert isinstance(owners, list) and len(owners) == 2
    result = capability.send(target="linus", message="mehrere owner")

    assert (result.status, result.reason) == ("blocked", "owner_mehrdeutig")
    assert world.egress == []


def test_one_owner_is_returned_and_message_is_sent(world):
    capability = world.cap("neo")

    owner = prov._active_owner(capability._ctx, capability._ctx.thread)
    assert owner is not None and not isinstance(owner, list)
    assert capability.send(target="linus", message="ein owner").status == "sent"


def test_ambiguous_owner_build_does_not_attest_lease(world, monkeypatch):
    reference = world.cap("neo")
    monkeypatch.setattr("hermes_cli.active_sessions.active_session_registry_snapshot",
                        lambda **_kwargs: _rows(reference._ctx, 2))
    issued = make_grant(world.homes["neo"], profile="neo", thread="neo-t", live="live-a",
                        conversation="s-neo", tenant="tenant-1", lease=300)
    capability = prov.build_thread_sync(*issued, evidence=registry())

    assert capability is not None
    resolved = capability._sync.owner_resolver(capability._ctx.thread)
    assert isinstance(resolved, list) and len(resolved) == 2
    assert not capability._sync.evidence.proven("owner_lease")
