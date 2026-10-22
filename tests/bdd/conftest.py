"""Shared pytest-bdd bindings for approved scenario metadata."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pytest_bdd import given, parsers, then, when

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry, build_registry


def pytest_bdd_apply_tag(tag: str, function: Callable[..., Any]) -> Callable[..., Any]:
    """Keep traceability-only tags out of pytest's marker namespace."""

    if tag.startswith(("cap_", "req_", "scn_")):
        return function
    return getattr(pytest.mark, tag)(function)


@pytest.fixture
def scenario_registry() -> ScenarioRegistry:
    return build_registry()


@given(
    parsers.parse('the approved local setup for "{scenario_id}"'),
    target_fixture="scenario_context",
)
def approved_local_setup(
    scenario_id: str, scenario_registry: ScenarioRegistry
) -> ScenarioContext:
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

