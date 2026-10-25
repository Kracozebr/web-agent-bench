"""Fail-closed registry for approved scenario adapters."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from tools.harness_contracts import (
    HarnessContract,
    load_manifest,
    load_proposal,
    validate_change_name,
)


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

    def __init__(self, change_name: str | None = None) -> None:
        self._cases: dict[str, ScenarioCase] = {}
        self._adapter_profiles: dict[str, str | None] = {}
        self.change_name = validate_change_name(change_name) if change_name is not None else None
        repository_root = __import__("pathlib").Path(__file__).resolve().parents[3]
        _, self._contracts = load_manifest(repository_root, self.change_name)
        if self.change_name is not None:
            load_proposal(repository_root, self.change_name)

    def register(
        self, scenario_id: str, case: ScenarioCase, *, adapter_profile: str | None = None
    ) -> None:
        if scenario_id in self._cases:
            raise ValueError(f"duplicate scenario adapter: {scenario_id}")
        if adapter_profile is not None and (not isinstance(adapter_profile, str) or not adapter_profile.strip()):
            raise ValueError(f"invalid adapter profile for {scenario_id}")
        self._cases[scenario_id] = case
        self._adapter_profiles[scenario_id] = adapter_profile

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

    def adapter_profiles(self) -> dict[str, str | None]:
        return dict(self._adapter_profiles)

    def _require(self, scenario_id: str) -> ScenarioCase:
        try:
            return self._cases[scenario_id]
        except KeyError as error:
            raise AssertionError(f"approved scenario has no real adapter: {scenario_id}") from error


def build_registry(change_name: str | None = None) -> ScenarioRegistry:
    """Build the synchronized baseline registry or one explicitly selected active delta."""

    registry = ScenarioRegistry(change_name)
    if change_name is None:
        from . import benchmarking_core, realtime_pvp

        benchmarking_core.register(registry)
        realtime_pvp.register(registry)
        contract_ids = set(registry.contracts())
        bef_ids = {f"BEF-SC-{number:03d}" for number in range(1, 13)}
        if bef_ids.intersection(contract_ids):
            if not bef_ids.issubset(contract_ids):
                raise ValueError("main BEF contract inventory is incomplete")
            from . import benchmark_environment_feasibility

            if set(benchmark_environment_feasibility.SCENARIO_IDS) != bef_ids:
                raise ValueError("main BEF adapter inventory is inconsistent")
            benchmark_environment_feasibility.register(registry)
        return registry

    module_name = validate_change_name(change_name).replace("-", "_")
    module = importlib.import_module(f"tests.bdd.adapters.{module_name}")
    register = getattr(module, "register", None)
    if not callable(register):
        raise ValueError(f"active adapter module {module.__name__} must expose register(registry)")
    profiles = getattr(module, "ADAPTER_PROFILES", None)
    if not isinstance(profiles, (set, frozenset, tuple, list)) or not profiles or not all(
        isinstance(profile, str) and profile.strip() for profile in profiles
    ):
        raise ValueError(
            f"active adapter module {module.__name__} must declare non-empty ADAPTER_PROFILES"
        )
    register(registry)
    registered_profiles = set(registry.adapter_profiles().values())
    registered_profiles.discard(None)
    if registered_profiles != set(profiles):
        raise ValueError(
            f"active adapter profile inventory drifted: "
            f"declared={sorted(profiles)}, registered={sorted(registered_profiles)}"
        )
    return registry

