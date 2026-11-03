"""Runner-owned authenticated context for Bot ThreadSync.

This is the only place that builds a ``GatewayAuthContext`` (data). Authority is NOT created here: the runner
asks the concrete, started, runner-owned Telegram adapter for a grant (``adapter._issue_thread_grant``) after
authenticated ingress/session resolution, and gets back ``(grant, broker)`` from that adapter's own
``GrantBroker``. Context facts come from the routing identity pinned at ingress (``identity_of``), the
live-session registry, and the operator's explicit ``bot_mode.thread_sync.tenant`` config; never from env,
profile names, chat ids or message text.  Anything missing yields ``None`` (fail closed).
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUTH_LEASE_SECONDS = 300


def _tenant(user_config: Any) -> str | None:
    node = ((user_config or {}).get("bot_mode") or {}).get("thread_sync") or {}
    tenant = node.get("tenant") if isinstance(node, dict) else None
    return tenant.strip() if isinstance(tenant, str) and tenant.strip() else None


def _live_entry(home: Path, chat_id: str, thread_id: str) -> dict[str, Any] | None:
    from hermes_cli.active_sessions import active_session_registry_snapshot
    rows = [e for e in active_session_registry_snapshot(registry_home=home, strict=True)
            if str((e.get("metadata") or {}).get("platform") or "") == "telegram"
            and str((e.get("metadata") or {}).get("chat_id") or "") == chat_id
            and str((e.get("metadata") or {}).get("thread_id") or "") == thread_id]
    return rows[0] if len(rows) == 1 else None


def telegram_adapter_for(runner: Any, profile: str):
    """The started Telegram adapter owned by ``profile`` in this runner, or None."""
    if profile == primary_scope()[0]:
        adapters = list((getattr(runner, "adapters", None) or {}).items())
    else:
        adapters = list(((getattr(runner, "_profile_adapters", None) or {}).get(profile) or {}).items())
    return next((a for p, a in adapters if str(getattr(p, "value", p)) == "telegram"), None)


def _issue(*, runner: Any, adapter: Any, home: Path, profile: str, tenant: str, conversation_id: str,
           chat_id: str, thread_id: str, live_session_id: str, now: float):
    """Ask the ACTIVE adapter for authority bound to this runtime instance, profile home/profile, tenant,
    live session, thread, turn and a finite lease. Returns ``(grant, broker)`` or None; the runner never
    creates authority itself."""
    from tools.bot_thread_sync import RUNTIME_INSTANCE, GatewayAuthContext
    issue = getattr(adapter, "_issue_thread_grant", None)
    if not callable(issue):
        return None
    thread = {"platform": "telegram", "chat_id": chat_id, "thread_id": thread_id}
    ctx = GatewayAuthContext(
        profile_home=str(home), profile=profile, owner="max", tenant=tenant, conversation_id=conversation_id,
        thread=thread, live_session_id=live_session_id, runtime_instance=RUNTIME_INSTANCE, owner_token="",
        turn_id=f"{conversation_id}:{now:.3f}", observed_at=now, lease_expires_at=now + AUTH_LEASE_SECONDS)
    return issue(runner, ctx)


def build_thread_auth_context(*, runner: Any, source: Any, session_id: str, session_key: str,
                              user_config: Any, now: float | None = None):
    """Per-turn ``(grant, broker)`` for the agent's own session, issued by the adapter that received the
    message; None when anything is unproven."""
    try:
        from gateway.session_identity import identity_of
        identity = identity_of(source)
        platform = getattr(source, "platform", None)
        if identity is None or str(getattr(platform, "value", platform) or "") != "telegram":
            return None
        chat_id, thread_id = str(getattr(source, "chat_id", "") or ""), str(getattr(source, "thread_id", "") or "")
        tenant = _tenant(user_config)
        if not (chat_id and thread_id and tenant and session_id):
            return None
        adapter = identity.adapter()  # the live receiving adapter; restored/synthetic sources have none
        if adapter is None:
            return None
        home = Path(identity.runtime_home).resolve()
        entry = _live_entry(home, chat_id, thread_id)
        live_id = str(((entry or {}).get("metadata") or {}).get("live_session_id") or "")
        if entry is None or not live_id or live_id != str(session_key):
            return None
        return _issue(runner=runner, adapter=adapter, home=home, profile=str(identity.runtime_profile),
                      tenant=tenant,
                     conversation_id=str(session_id), chat_id=chat_id, thread_id=thread_id,
                     live_session_id=live_id, now=time.time() if now is None else now)
    except Exception:
        logger.debug("thread auth context unavailable", exc_info=True)
        return None


def build_service_auth_context(*, runner: Any, adapter: Any, home: Path, profile: str, user_config: Any,
                               now: float | None = None):
    """Gateway-level (no turn) ``(grant, broker)`` for the profile's canonical live thread."""
    try:
        from tools.bot_live_delivery import find_canonical_live_thread
        row = find_canonical_live_thread(home)
        tenant = _tenant(user_config)
        if not row or not tenant or not row.get("thread_id"):
            return None
        return _issue(runner=runner, adapter=adapter, home=Path(home).resolve(), profile=profile, tenant=tenant,
                      conversation_id="service",
                     chat_id=str(row["chat_id"]), thread_id=str(row["thread_id"]),
                     live_session_id=str(row["live_session_id"]), now=time.time() if now is None else now)
    except Exception:
        logger.debug("service thread auth context unavailable", exc_info=True)
        return None


def resolve_scope(runner: Any, adapter: Any) -> tuple[str, Path] | None:
    """(profile, home) of the concrete adapter instance, or None. A secondary multiplex adapter
    resolves to its OWN profile from the served set; anything unprovable fails closed."""
    from gateway.run import _multiplex_profile_homes
    owner = getattr(adapter, "gateway_runner", None)
    if owner is not runner:
        return None
    name = getattr(adapter, "_hermes_profile_name", None)
    if name:
        if not runner._multiplex_on():
            return None
        home = dict(_multiplex_profile_homes(runner.config)).get(name)
        return (str(name), Path(home).resolve()) if home else None
    return primary_scope()


def primary_scope() -> tuple[str, Path]:
    from hermes_cli.profiles import get_active_profile_name
    from hermes_constants import get_hermes_home
    return get_active_profile_name(), get_hermes_home().resolve()


def active_profile_scopes(runner: Any) -> list[tuple[str, Path]]:
    """Every profile this gateway process serves (primary + multiplexed secondaries), deduplicated."""
    scopes = [primary_scope()]
    multiplex = getattr(runner, "_multiplex_on", None)
    if callable(multiplex) and multiplex():
        from gateway.run import _multiplex_profile_homes
        scopes += [(str(n), Path(h).resolve()) for n, h in _multiplex_profile_homes(runner.config)]
    seen, out = set(), []
    for name, home in scopes:
        if home not in seen:
            seen.add(home)
            out.append((name, home))
    return out


def find_dispatcher(runner: Any, profile: str):
    """The profile's own adapter that can hand a recovered conversational message to its gateway."""
    if profile == primary_scope()[0]:
        adapters = list((getattr(runner, "adapters", None) or {}).values())
    else:
        adapters = list(((getattr(runner, "_profile_adapters", None) or {}).get(profile) or {}).values())
    return next((fn for a in adapters if callable(fn := getattr(a, "dispatch_thread_message", None))), None)


def build_scoped_capability(runner: Any, name: str, home: Path, dispatcher: Any = None):
    """Capability for one profile, derived under that profile's own scope (config, secrets, home) from a grant
    issued by that profile's own started Telegram adapter."""
    try:
        from gateway.run import _profile_runtime_scope
        from hermes_cli.config import load_config
        from tools.bot_thread_provider import build_thread_sync, run_native_agent
        adapter = telegram_adapter_for(runner, name)  # resolved outside the scope: it names the launch view
        if adapter is None:
            return None
        with _profile_runtime_scope(Path(home), hydrate_secrets=False):
            config = load_config()
            issued = build_service_auth_context(runner=runner, adapter=adapter, home=Path(home), profile=name,
                                                user_config=config)
            if issued is None:
                return None
            peers = (((config or {}).get("bot_mode") or {}).get("thread_sync") or {}).get("peers") or {}
            return build_thread_sync(
                *issued, service_scope=True, peers=peers, dispatcher=dispatcher, native_runner=run_native_agent,
                # fresh grant from the same active adapter (new lease, same identity)
                refresh=lambda: build_scoped_capability(runner, name, home, dispatcher))
    except Exception:
        logger.debug("scoped thread capability unavailable", exc_info=True)
        return None


def build_gateway_extension_context(runner: Any, adapter: Any):
    """Generic adapter seam: capability for the concrete adapter's own profile, else None."""
    try:
        scope = resolve_scope(runner, adapter) if adapter is not None else primary_scope()
    except Exception:
        logger.debug("adapter scope unresolved", exc_info=True)
        return None
    return build_scoped_capability(runner, *scope) if scope else None


def refresh_thread_capability(agent: Any, *, runner: Any, source: Any, session_id: str, session_key: str,
                              user_config: Any) -> None:
    """Replace (or drop) the agent's capability on EVERY turn, including cached/reused agents, so a
    short-lived authenticated lease never outlives its turn. No valid context → no capability."""
    from tools.bot_thread_provider import build_thread_sync
    capability = None
    previous = getattr(agent, "_thread_sync_capability", None)
    if previous is not None and hasattr(previous, "revoke"):
        previous.revoke()  # a cached capability never survives its turn: refresh requires a NEW grant
    try:
        issued = build_thread_auth_context(runner=runner, source=source, session_id=session_id,
                                           session_key=session_key, user_config=user_config)
        capability = build_thread_sync(*issued) if issued is not None else None
    except Exception:
        logger.debug("ThreadSync capability refresh failed; egress stays fail-closed", exc_info=True)
    object.__setattr__(agent, "_thread_sync_capability", capability)


def thread_sync_recovery_pass(runner: Any, scope: tuple[str, Path] | None = None) -> float:
    """One bounded recovery pass for ONE profile scope; returns seconds until its next pass."""
    capability = (build_scoped_capability(runner, *scope, dispatcher=find_dispatcher(runner, scope[0]))
                  if scope else build_gateway_extension_context(runner, None))
    if capability is None:
        return 60.0
    capability.recover()
    return capability.next_due_delay()


def recover_thread_sync_queues(runner: Any) -> int:
    """Recover every active profile's queues (owners re-resolved per profile)."""
    total = 0
    for scope in active_profile_scopes(runner):
        capability = build_scoped_capability(runner, *scope, dispatcher=find_dispatcher(runner, scope[0]))
        total += 0 if capability is None else capability.recover()
    return total
