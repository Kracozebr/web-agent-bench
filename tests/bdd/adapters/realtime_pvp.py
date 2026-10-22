"""Reference-model adapter for the real-time PvP contract."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .registry import ScenarioContext, ScenarioRegistry


class ReferenceMatchAuthority:
    """Deterministic local authority for protocol checks; no sockets or chain calls."""

    def create_match(self, *, ready: tuple[bool, bool], seed: int) -> dict[str, Any] | None:
        if ready != (True, True):
            return None
        return {
            "match_id": "match-reference-1",
            "participants": ("agent-alpha", "agent-beta"),
            "rules_version": "pvp-v1",
            "seed": seed,
            "clock_policy": "fixed-deadline-1000ms",
            "benchmark_version": "bench-v1",
            "settlement_policy": "single-intent-v1",
            "events": [],
            "accepted_events": [],
            "terminal_result": None,
            "settlement": None,
        }

    @staticmethod
    def submit_action(match: dict[str, Any], actor: str, action: str, *, deadline: str) -> dict[str, Any]:
        if match["terminal_result"] is not None:
            event = {"sequence": len(match["events"]) + 1, "type": "action_rejected", "actor": actor, "reason": "terminal"}
            match["events"].append(event)
            return event
        event = {
            "sequence": len(match["events"]) + 1,
            "type": "action_accepted",
            "actor": actor,
            "action": action,
            "deadline": deadline,
            "authority_timestamp": f"2026-01-01T00:00:0{len(match['events'])}Z",
        }
        match["events"].append(event)
        match["accepted_events"].append(event)
        return event

    @staticmethod
    def finish(match: dict[str, Any], winner: str) -> None:
        if match["terminal_result"] is None:
            match["terminal_result"] = {"winner": winner, "reason": "rules_complete"}

    @staticmethod
    def settle(match: dict[str, Any], deduplication_key: str) -> dict[str, Any]:
        if match["settlement"] is None:
            match["settlement"] = {"key": deduplication_key, "status": "accepted", "effect_count": 1}
        return deepcopy(match["settlement"])


class RealtimePvpCase:
    def __init__(self, scenario_id: str) -> None:
        self._scenario_id = scenario_id

    def setup(self, context: ScenarioContext) -> None:
        context.state["authority"] = ReferenceMatchAuthority()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        assert when_text
        getattr(self, "_execute_" + self._scenario_id.replace("-", "_"))(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        assert then_text
        getattr(self, "_verify_" + self._scenario_id.replace("-", "_"))(context)

    def _authority(self, context: ScenarioContext) -> ReferenceMatchAuthority:
        return context.state["authority"]

    def _execute_PV_SC_001(self, context: ScenarioContext) -> None:
        authority = self._authority(context)
        one_sided = authority.create_match(ready=(True, False), seed=7)
        match = authority.create_match(ready=(True, True), seed=7)
        context.outcome = one_sided, match, deepcopy(match)

    def _verify_PV_SC_001(self, context: ScenarioContext) -> None:
        one_sided, match, snapshot = context.outcome
        context.check("one_sided_rejected", one_sided is None)
        context.check("match_started_after_both_ready", match is not None and match["terminal_result"] is None)
        context.check("rules_snapshot_immutable", all(match[key] == snapshot[key] for key in ("participants", "rules_version", "seed", "clock_policy", "settlement_policy")))

    def _execute_PV_SC_002(self, context: ScenarioContext) -> None:
        match = self._authority(context).create_match(ready=(True, True), seed=13)
        assert match is not None
        self._authority(context).submit_action(match, "agent-alpha", "play-a", deadline="accepted")
        self._authority(context).submit_action(match, "agent-beta", "play-b", deadline="accepted")
        context.outcome = match

    def _verify_PV_SC_002(self, context: ScenarioContext) -> None:
        match = context.outcome
        events = match["accepted_events"]
        context.check("monotonic_sequence", [event["sequence"] for event in events] == [1, 2])
        context.check("authority_timestamped", all(event["authority_timestamp"] for event in events))
        context.check("deadline_decisions_recorded", all(event["deadline"] == "accepted" for event in events))

    def _execute_PV_SC_003(self, context: ScenarioContext) -> None:
        match = self._authority(context).create_match(ready=(True, True), seed=17)
        assert match is not None
        self._authority(context).submit_action(match, "agent-alpha", "play-a", deadline="accepted")
        self._authority(context).finish(match, "agent-alpha")
        late_event = self._authority(context).submit_action(match, "agent-beta", "late-play", deadline="late")
        context.outcome = match, late_event, deepcopy(match["terminal_result"]), list(match["accepted_events"])

    def _verify_PV_SC_003(self, context: ScenarioContext) -> None:
        match, late_event, result, accepted_events = context.outcome
        context.check("terminal_result_stable", match["terminal_result"] == result)
        context.check("late_action_recorded", late_event["type"] == "action_rejected" and late_event["reason"] == "terminal")
        context.check("accepted_history_preserved", match["accepted_events"] == accepted_events)

    def _execute_PV_SC_004(self, context: ScenarioContext) -> None:
        match = self._authority(context).create_match(ready=(True, True), seed=29)
        assert match is not None
        self._authority(context).finish(match, "agent-beta")
        first = self._authority(context).settle(match, "settle-match-reference-1")
        second = self._authority(context).settle(match, "settle-match-reference-1")
        context.outcome = match, first, second

    def _verify_PV_SC_004(self, context: ScenarioContext) -> None:
        match, first, second = context.outcome
        context.check("stable_outcome", first == second and first["status"] == "accepted")
        context.check("single_effect", first["effect_count"] == 1 and match["settlement"]["effect_count"] == 1)
        context.check("dedup_key_recorded", first["key"] == "settle-match-reference-1")


def register(registry: ScenarioRegistry) -> None:
    for scenario_id in ("PV-SC-001", "PV-SC-002", "PV-SC-003", "PV-SC-004"):
        registry.register(scenario_id, RealtimePvpCase(scenario_id))

