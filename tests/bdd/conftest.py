"""Shared pytest-bdd bindings for approved scenario metadata."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pytest_bdd import given, parsers, then, when

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry, build_registry
from tools.generate_bdd_mirrors import parse_specs


def pytest_bdd_apply_tag(tag: str, function: Callable[..., Any]) -> Callable[..., Any]:
    """Keep traceability-only tags out of pytest's marker namespace."""

    if tag.startswith(("cap_", "req_", "scn_")):
        return function
    return getattr(pytest.mark, tag)(function)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--change",
        action="store",
        default=None,
        help="select one active OpenSpec change adapter registry",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Select source-owned mappers without dropping unrelated unit-test items."""

    change_name = config.getoption("--change")
    root = Path(__file__).resolve().parents[2]
    scenarios = parse_specs(root, change_name)
    selected_mappers = {
        f"tests/bdd/mappers/test_{scenario.capability.slug}_bdd.py" for scenario in scenarios
    }
    mapper_directory = "tests/bdd/mappers/"

    def should_keep(item: pytest.Item) -> bool:
        try:
            relative = Path(str(item.path)).resolve().relative_to(root).as_posix()
        except ValueError:
            return True
        # Only filter mapper modules: tests/tools, adapter unit tests, and traceability checks
        # remain part of mixed/root pytest invocations.
        return not relative.startswith(mapper_directory) or relative in selected_mappers

    items[:] = [item for item in items if should_keep(item)]


@pytest.fixture
def scenario_registry(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> ScenarioRegistry:
    change_name = request.config.getoption("--change")
    monkeypatch.setenv("BEF_SPEC_PROFILE", "active-delta" if change_name is not None else "synced-main")
    return build_registry(change_name)


@given(
    parsers.parse('the approved {gate} setup for "{scenario_id}"'),
    target_fixture="scenario_context",
)
def approved_gate_setup(
    gate: str, scenario_id: str, scenario_registry: ScenarioRegistry
) -> ScenarioContext:
    del gate  # Gate class is declared by the selected proposal and audited separately.
    context = ScenarioContext(scenario_id=scenario_id)
    scenario_registry.setup(context)
    return context


@when(parsers.re(r"(?P<when_text>.+)"))
def execute_approved_behavior(
    when_text: str, scenario_context: ScenarioContext, scenario_registry: ScenarioRegistry
) -> None:
    scenario_registry.execute(scenario_context, when_text)


@then(parsers.re(r"(?P<then_text>.+)"))
def verify_approved_behavior(
    then_text: str, scenario_context: ScenarioContext, scenario_registry: ScenarioRegistry
) -> None:
    scenario_registry.verify(scenario_context, then_text)
    if scenario_context.scenario_id in {"BEF-SC-009", "BEF-SC-010"}:
        from tests.bdd.adapters.bef_generation_cleanup import cleanup_after_verified_scenario

        cleanup_result = cleanup_after_verified_scenario(scenario_context)
        if cleanup_result is not None:
            scenario_context.state["post_verification_cleanup"] = cleanup_result

