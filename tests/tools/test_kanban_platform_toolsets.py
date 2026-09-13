"""Regression tests for platform-scoped Kanban tool selection."""

from __future__ import annotations

from tools.kanban_toolset_context import (
    kanban_toolset_requested,
    scoped_kanban_toolset_selection,
)
import tools.kanban_tools as kanban_tools


def test_platform_resolver_keeps_kanban_opt_in():
    from hermes_cli.tools_config import _get_platform_tools

    disabled = _get_platform_tools(
        {"platform_toolsets": {"cli": ["web"]}},
        "cli",
        include_default_mcp_servers=False,
    )
    enabled = _get_platform_tools(
        {"platform_toolsets": {"cli": ["web", "kanban"]}},
        "cli",
        include_default_mcp_servers=False,
    )

    assert "kanban" not in disabled
    assert "kanban" in enabled


def test_kanban_selection_context_resets_after_exception():
    assert kanban_toolset_requested() is None

    try:
        with scoped_kanban_toolset_selection(["kanban"]):
            assert kanban_toolset_requested() is True
            raise RuntimeError("probe")
    except RuntimeError:
        pass

    assert kanban_toolset_requested() is None


def test_explicit_kanban_selection_controls_availability(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(kanban_tools, "load_config", lambda: {"toolsets": []})

    with scoped_kanban_toolset_selection(["kanban"]):
        assert kanban_tools._profile_has_kanban_toolset() is True

    with scoped_kanban_toolset_selection(["web"]):
        assert kanban_tools._profile_has_kanban_toolset() is False


def test_explicit_platform_deselection_overrides_global_kanban(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(
        kanban_tools,
        "load_config",
        lambda: {"toolsets": ["kanban"], "platform_toolsets": {"telegram": ["web"]}},
    )

    with scoped_kanban_toolset_selection(["web"]):
        assert kanban_tools._profile_has_kanban_toolset() is False


def test_unscoped_discovery_does_not_borrow_platform_opt_in(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(
        kanban_tools,
        "load_config",
        lambda: {"platform_toolsets": {"telegram": ["web", "kanban"]}},
    )

    assert kanban_tools._profile_has_kanban_toolset() is False


def test_unscoped_schema_build_honors_global_kanban(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(
        kanban_tools, "load_config", lambda: {"toolsets": ["kanban"]}
    )

    from model_tools import _clear_tool_defs_cache, get_tool_definitions

    _clear_tool_defs_cache()
    definitions = get_tool_definitions(
        enabled_toolsets=None,
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )

    names = {tool["function"]["name"] for tool in definitions}
    assert "kanban_create" in names


def test_schema_builder_propagates_explicit_selection(monkeypatch):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(kanban_tools, "load_config", lambda: {"toolsets": []})

    from model_tools import _clear_tool_defs_cache, get_tool_definitions

    _clear_tool_defs_cache()
    enabled = get_tool_definitions(
        enabled_toolsets=["kanban"],
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )
    _clear_tool_defs_cache()
    disabled = get_tool_definitions(
        enabled_toolsets=["web"],
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )

    enabled_names = {tool["function"]["name"] for tool in enabled}
    disabled_names = {tool["function"]["name"] for tool in disabled}
    assert "kanban_create" in enabled_names
    assert "kanban_create" not in disabled_names


def test_skill_prompt_does_not_borrow_another_platforms_kanban_opt_in(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("HERMES_KANBAN_TASK", raising=False)
    monkeypatch.setattr(
        kanban_tools,
        "load_config",
        lambda: {"platform_toolsets": {"telegram": ["kanban"]}},
    )
    skill_dir = tmp_path / "kanban-probe"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: kanban-platform-isolation-probe\n"
        "description: Probe that must stay hidden without Kanban.\n"
        "environments: [kanban]\n"
        "---\n"
        "# Probe\n",
        encoding="utf-8",
    )

    from agent.prompt_builder import build_skills_system_prompt

    prompt = build_skills_system_prompt(
        available_tools=set(),
        available_toolsets={"web"},
        skills_dir_override=tmp_path,
    )

    assert "kanban-platform-isolation-probe" not in prompt
