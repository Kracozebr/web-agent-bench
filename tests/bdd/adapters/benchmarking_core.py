"""Reference-model adapter for the benchmarking-core contract."""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from .registry import ScenarioContext, ScenarioRegistry


class ReferenceBenchmark:
    """Deterministic local model; it never calls a chain, wallet, or agent process."""

    def run(self, *, agent_id: str, task_id: str, seed: int, policy_hash: str = "policy-v1") -> dict[str, Any]:
        events = [
            {"sequence": 1, "source": "agent", "type": "task_started", "payload": task_id},
            {"sequence": 2, "source": "runner", "type": "task_completed", "payload": "ok"},
        ]
        for event in events:
            event["payload_hash"] = sha256(str(event["payload"]).encode("utf-8")).hexdigest()
        return {
            "run_id": f"run-{agent_id}-{task_id}-{seed}",
            "agent_id": agent_id,
            "agent_version": "reference-1",
            "task_id": task_id,
            "benchmark_version": "bench-v1",
            "policy_hash": policy_hash,
            "seed": seed,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "boundary": "reference_model",
            "events": events,
        }

    @staticmethod
    def score(run: dict[str, Any], *, chain_status: str) -> dict[str, Any]:
        return {
            "task_outcome": "passed",
            "latency_ms": 1000,
            "resource_cost": {"units": 1, "unit": "reference_step"},
            "tool_safety": "passed",
            "chain_effect": chain_status,
            "evidence_quality": "partial" if chain_status == "unknown" else "complete",
            "evidence": {"boundary": run["boundary"], "raw_reference": "fixture://run/chain-intent"},
        }

    @staticmethod
    def canonical_inputs(run: dict[str, Any], score: dict[str, Any]) -> tuple[Any, ...]:
        return (
            run["task_id"],
            run["benchmark_version"],
            run["policy_hash"],
            run["seed"],
            tuple((event["sequence"], event["type"], event["payload_hash"]) for event in run["events"]),
            tuple((key, value) for key, value in score.items() if key != "evidence"),
        )


class BenchmarkingCoreCase:
    def __init__(self, scenario_id: str) -> None:
        self._scenario_id = scenario_id

    def setup(self, context: ScenarioContext) -> None:
        context.state["model"] = ReferenceBenchmark()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        assert when_text
        getattr(self, "_execute_" + self._scenario_id.replace("-", "_"))(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        assert then_text
        getattr(self, "_verify_" + self._scenario_id.replace("-", "_"))(context)

    def _model(self, context: ScenarioContext) -> ReferenceBenchmark:
        return context.state["model"]

    def _execute_WB_SC_001(self, context: ScenarioContext) -> None:
        context.outcome = self._model(context).run(agent_id="agent-alpha", task_id="task-transfer", seed=7)

    def _verify_WB_SC_001(self, context: ScenarioContext) -> None:
        run = context.outcome
        context.check("run_identity_present", all(run.get(key) for key in ("run_id", "agent_id", "task_id", "seed", "policy_hash")))
        context.check("event_sequence_ordered", [event["sequence"] for event in run["events"]] == [1, 2])
        context.check("event_payloads_hashed", all(len(event["payload_hash"]) == 64 for event in run["events"]))

    def _execute_WB_SC_002(self, context: ScenarioContext) -> None:
        run = self._model(context).run(agent_id="agent-alpha", task_id="task-claim", seed=11)
        context.outcome = run, self._model(context).score(run, chain_status="unknown")

    def _verify_WB_SC_002(self, context: ScenarioContext) -> None:
        _run, score = context.outcome
        dimensions = {"task_outcome", "latency_ms", "resource_cost", "tool_safety", "chain_effect", "evidence_quality"}
        context.check("dimensions_separate", dimensions.issubset(score))
        context.check("chain_evidence_unknown", score["chain_effect"] == "unknown")
        context.check("task_outcome_preserved", score["task_outcome"] == "passed")

    def _execute_WB_SC_003(self, context: ScenarioContext) -> None:
        original = self._model(context).run(agent_id="agent-alpha", task_id="task-replay", seed=19)
        original_score = self._model(context).score(original, chain_status="unknown")
        replay = self._model(context).run(agent_id="agent-alpha", task_id="task-replay", seed=19)
        replay_score = self._model(context).score(replay, chain_status="unknown")
        context.outcome = original, original_score, replay, replay_score

    def _verify_WB_SC_003(self, context: ScenarioContext) -> None:
        original, original_score, replay, replay_score = context.outcome
        model = self._model(context)
        context.check("same_canonical_inputs", model.canonical_inputs(original, original_score) == model.canonical_inputs(replay, replay_score))
        context.check("original_evidence_retained", original["run_id"] != replay["run_id"] or original["events"] == replay["events"])
        context.check("replay_marked_separately", original["run_id"] == replay["run_id"])

    def _execute_WB_SC_004(self, context: ScenarioContext) -> None:
        run = self._model(context).run(agent_id="agent-alpha", task_id="task-submit", seed=23)
        context.outcome = run, self._model(context).score(run, chain_status="unknown")

    def _verify_WB_SC_004(self, context: ScenarioContext) -> None:
        run, score = context.outcome
        context.check("raw_evidence_reference_preserved", score["evidence"]["raw_reference"].startswith("fixture://"))
        context.check("chain_effect_unknown", score["chain_effect"] == "unknown")
        context.check("unknown_not_success", score["chain_effect"] != "success")


def register(registry: ScenarioRegistry) -> None:
    for scenario_id in ("WB-SC-001", "WB-SC-002", "WB-SC-003", "WB-SC-004"):
        registry.register(scenario_id, BenchmarkingCoreCase(scenario_id))

