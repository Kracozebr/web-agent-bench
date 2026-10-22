"""Fail-closed registry for approved scenario adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from tools.harness_contracts import HarnessContract, load_manifest


@dataclass
class ScenarioContext:
    """Mutable state belonging to one isolated approved scenario execution."""

    scenario_id: str
    state: dict[str, Any] = field(default_factory=dict)
    outcome: Any = None
    observations: set[str] = field(default_factory=set)

    def check(self, name: str, condition: bool) -> bool:
        """Assert and record a named semantic observation."""

        if not name or not name.strip():
            raise ValueError("scenario observation name must be non-empty")
        if type(condition) is not bool:
            raise TypeError(
                f"{self.scenario_id} observation {name!r} must be bool, got {type(condition).__name__}"
            )
        if not condition:
            raise AssertionError(f"{self.scenario_id} observation failed: {name}")
        self.observations.add(name)
        return True

    def observe(self, name: str, condition: bool) -> bool:
        """Record a named composite observation with the same fail-closed behavior."""

        return self.check(name, condition)


class ScenarioCase(Protocol):
    def setup(self, context: ScenarioContext) -> None: ...

    def execute(self, context: ScenarioContext, when_text: str) -> None: ...

    def verify(self, context: ScenarioContext, then_text: str) -> None: ...


class ScenarioRegistry:
    """Map every normative ID to a real capability-bound execution case."""

    def __init__(self) -> None:
        self._cases: dict[str, ScenarioCase] = {}
        repository_root = __import__("pathlib").Path(__file__).resolve().parents[3]
        _, self._contracts = load_manifest(repository_root)

    def register(self, scenario_id: str, case: ScenarioCase) -> None:
        if scenario_id in self._cases:
            raise ValueError(f"duplicate scenario adapter: {scenario_id}")
        self._cases[scenario_id] = case

    def setup(self, context: ScenarioContext) -> None:
        self._require(context.scenario_id).setup(context)

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        self._require(context.scenario_id).execute(context, when_text)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        self._require(context.scenario_id).verify(context, then_text)
        contract = self._contracts.get(context.scenario_id)
        if contract is None:
            raise AssertionError(f"scenario has no semantic contract: {context.scenario_id}")
        missing = set(contract.required_observations) - context.observations
        if missing:
            raise AssertionError(
                f"{context.scenario_id} did not record required observations: {sorted(missing)}"
            )

    def inventory(self) -> frozenset[str]:
        return frozenset(self._cases)

    def cases(self) -> dict[str, ScenarioCase]:
        return dict(self._cases)

    def contracts(self) -> dict[str, HarnessContract]:
        return dict(self._contracts)

    def _require(self, scenario_id: str) -> ScenarioCase:
        try:
            return self._cases[scenario_id]
        except KeyError as error:
            raise AssertionError(f"approved scenario has no real adapter: {scenario_id}") from error


def build_registry() -> ScenarioRegistry:
    """Compose the capability adapters without import cycles during collection."""

    from . import benchmarking_core, realtime_pvp

    registry = ScenarioRegistry()
    benchmarking_core.register(registry)
    realtime_pvp.register(registry)
    return registry

