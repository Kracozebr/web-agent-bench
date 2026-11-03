"""Fail-closed evidence adapter for the approved S2 and H1 delta scenarios."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .benchmarking_core import ReferenceBenchmark
from .registry import ScenarioContext, ScenarioRegistry

ROOT = Path(__file__).resolve().parents[3]
CHANGE = "s2-answer-review-h1-cutoff-evaluation"
PROFILE = "s2_answer_review_h1_cutoff_evaluation"
ADAPTER_PROFILES = {"benchmarking_core", PROFILE}
RUNTIME_INPUTS = ROOT / "tests" / "bdd" / "changes" / CHANGE / "runtime-inputs.json"


def _read_runtime_case(scenario_id: str) -> dict[str, Any]:
    try:
        payload = json.loads(RUNTIME_INPUTS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{scenario_id}: mandatory environment capture is unavailable") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"{scenario_id}: runtime input must be an object")
    if payload.get("schemaVersion") != "oar-h1-runtime-inputs/v1" or payload.get("status") != "ready":
        blockers = payload.get("blockers", [])
        codes = ",".join(item.get("code", "unknown") for item in blockers if isinstance(item, dict))
        raise RuntimeError(f"{scenario_id}: mandatory environment gate is blocked ({codes or 'capture_not_ready'})")
    scenarios = payload.get("scenarios")
    case = scenarios.get(scenario_id) if isinstance(scenarios, dict) else None
    if not isinstance(case, dict) or case.get("boundary") != "actual_browser_api_postgres_local_bef":
        raise RuntimeError(f"{scenario_id}: missing actual boundary capture")
    references = case.get("evidence")
    if not isinstance(references, list) or not references:
        raise RuntimeError(f"{scenario_id}: raw evidence references are required")
    for reference in references:
        if not isinstance(reference, dict) or not isinstance(reference.get("path"), str) or not isinstance(reference.get("sha256"), str):
            raise RuntimeError(f"{scenario_id}: malformed raw evidence reference")
        relative = Path(reference["path"])
        if not relative.parts or relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "artifacts":
            raise RuntimeError(f"{scenario_id}: evidence path is outside artifacts")
        path = (ROOT / relative).resolve()
        if not path.is_relative_to((ROOT / "artifacts").resolve()) or not path.is_file():
            raise RuntimeError(f"{scenario_id}: evidence file is missing or outside artifacts")
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
            raise RuntimeError(f"{scenario_id}: evidence hash mismatch")
    return case


def _check_variants_and_effects(case: dict[str, Any], variants: tuple[str, ...], effects: tuple[str, ...]) -> None:
    negative = case.get("negativeVariants")
    durable = case.get("durableEffects")
    if not isinstance(negative, dict) or not all(negative.get(name) is True for name in variants):
        raise AssertionError("captured adversarial variants are incomplete or failed")
    if not isinstance(durable, dict) or not all(durable.get(name) is True for name in effects):
        raise AssertionError("captured durable-effect checks are incomplete or failed")


class DeltaCase:
    def __init__(self, scenario_id: str) -> None:
        self.scenario_id = scenario_id

    def setup(self, context: ScenarioContext) -> None:
        if context.scenario_id != self.scenario_id:
            raise AssertionError("scenario ID does not match registered case")
        if self.scenario_id == "WB-SC-002":
            context.state["reference_model"] = ReferenceBenchmark()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        if not when_text:
            raise AssertionError("approved scenario must retain its WHEN clause")
        getattr(self, "_execute_" + self.scenario_id.replace("-", "_"))(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        if not then_text:
            raise AssertionError("approved scenario must retain its THEN clause")
        getattr(self, "_verify_" + self.scenario_id.replace("-", "_"))(context)

    def _execute_WB_SC_002(self, context: ScenarioContext) -> None:
        model: ReferenceBenchmark = context.state["reference_model"]
        run = model.run(agent_id="agent-alpha", task_id="task-claim", seed=11)
        context.outcome = run, model.score(run, chain_status="unknown")

    def _verify_WB_SC_002(self, context: ScenarioContext) -> None:
        _run, score = context.outcome
        dimensions = {"task_outcome", "latency_ms", "resource_cost", "tool_safety", "chain_effect", "evidence_quality"}
        context.check("dimensions_separate", dimensions.issubset(score))
        context.check("chain_evidence_unknown", score["chain_effect"] == "unknown")
        context.check("task_outcome_preserved", score["task_outcome"] == "passed")

    def _execute_OAR_SC_001(self, context: ScenarioContext) -> None:
        context.outcome = _read_runtime_case(self.scenario_id)

    def _verify_OAR_SC_001(self, context: ScenarioContext) -> None:
        observations = context.outcome.get("observations", {})
        context.check("owner_identity", observations.get("owner_identity") is True)
        context.check("terminal_gate", observations.get("terminal_gate") is True)
        context.check("retained_input_hash", observations.get("retained_input_hash") is True)
        context.check("exact_answer_equality", observations.get("exact_answer_equality") is True)
        context.check("response_dom_allowlist", observations.get("response_dom_allowlist") is True)
        context.check("read_only_rows", observations.get("read_only_rows") is True)
        _check_variants_and_effects(context.outcome, ("hidden_field_injection",), ("no_answer_duplication", "unchanged_evaluation_rows"))

    def _execute_OAR_SC_002(self, context: ScenarioContext) -> None:
        context.outcome = _read_runtime_case(self.scenario_id)

    def _verify_OAR_SC_002(self, context: ScenarioContext) -> None:
        observations = context.outcome.get("observations", {})
        context.check("foreign_owner_denied", observations.get("foreign_owner_denied") is True)
        context.check("nonterminal_answer_hidden", observations.get("nonterminal_answer_hidden") is True)
        context.check("missing_or_bad_hash_hidden", observations.get("missing_or_bad_hash_hidden") is True)
        context.check("no_response_answer_content", observations.get("no_response_answer_content") is True)
        context.check("no_durable_mutation", observations.get("no_durable_mutation") is True)
        _check_variants_and_effects(context.outcome, ("foreign_owner", "active_run_or_task", "missing_input", "mismatched_input_hash"), ("unchanged_owner_and_evaluation_rows",))

    def _execute_WB_SC_006(self, context: ScenarioContext) -> None:
        context.outcome = _read_runtime_case(self.scenario_id)

    def _verify_WB_SC_006(self, context: ScenarioContext) -> None:
        observations = context.outcome.get("observations", {})
        context.check("complete_action_cutoff", observations.get("complete_action_cutoff") is True)
        context.check("exact_payment_linkage", observations.get("exact_payment_linkage") is True)
        context.check("paid_child_proof_hash", observations.get("paid_child_proof_hash") is True)
        context.check("no_same_payment_retrieve", observations.get("no_same_payment_retrieve") is True)
        context.check("validated_child_source", observations.get("validated_child_source") is True)
        context.check("existing_h1_partial_grade", observations.get("existing_h1_partial_grade") is True)
        context.check("single_ordinary_handoff", observations.get("single_ordinary_handoff") is True)
        _check_variants_and_effects(context.outcome, ("unrelated_payment_retrieve", "duplicate_handoff"), ("one_existing_payment", "at_most_one_evaluation_and_handoff", "no_refund_or_fabricated_delivery"))

    def _execute_WB_SC_007(self, context: ScenarioContext) -> None:
        context.outcome = _read_runtime_case(self.scenario_id)

    def _verify_WB_SC_007(self, context: ScenarioContext) -> None:
        observations = context.outcome.get("observations", {})
        context.check("proof_predicate_failure", observations.get("proof_predicate_failure") is True)
        context.check("unknown_without_score", observations.get("unknown_without_score") is True)
        context.check("no_new_terminal_cause", observations.get("no_new_terminal_cause") is True)
        context.check("payment_identity_unchanged", observations.get("payment_identity_unchanged") is True)
        _check_variants_and_effects(context.outcome, ("missing_or_incomplete_census", "contradictory_proof", "foreign_or_hash_mismatched_source", "admitted_same_payment_retrieve"), ("no_fabricated_delivery_or_score", "unchanged_payment_identity"))


def register(registry: ScenarioRegistry) -> None:
    for scenario_id, profile in (
        ("OAR-SC-001", PROFILE),
        ("OAR-SC-002", PROFILE),
        ("WB-SC-002", "benchmarking_core"),
        ("WB-SC-006", PROFILE),
        ("WB-SC-007", PROFILE),
    ):
        registry.register(scenario_id, DeltaCase(scenario_id), adapter_profile=profile)
