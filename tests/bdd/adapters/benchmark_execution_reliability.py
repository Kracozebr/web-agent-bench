"""Approved BER boundary adapters. Missing independent evidence blocks acceptance.

Catalog checks reuse the existing source-bound BTS producer and independent reader.
Other scenarios remain blocked until their full approved native/browser/worker
negative matrices have independently replayable proof. Partial recovery evidence is
actually verified before reporting its missing variants; unit tests cannot promote
it to an environment pass.
"""
from pathlib import Path
import json
import pytest
from tests.bdd.adapters.registry import ScenarioContext, ScenarioRegistry, build_registry

ROOT = Path(__file__).resolve().parents[3]
CHANGE = "benchmark-execution-reliability"
ADAPTER_PROFILES = {"benchmark_execution_reliability"}
SCENARIO_IDS = tuple(f"BER-SC-{n:03d}" for n in range(1,9))

class BenchmarkExecutionReliabilityCase:
    def __init__(self, scenario_id):
        self.scenario_id = scenario_id

    def setup(self, context):
        assert context.scenario_id == self.scenario_id

    def execute(self, context, when_text):
        del when_text
        getattr(self, "_execute_" + self.scenario_id.replace("-", "_"))(context)

    def verify(self, context, then_text):
        del then_text
        getattr(self, "_verify_" + self.scenario_id.replace("-", "_"))(context)

    def _blocked(self, scenario_id):
        pytest.skip("BLOCKED: " + scenario_id + " requires the full approved actual-boundary capture and independent negative replay; isolated unit/HTTP integration is partial proof only")

    def _runtime_inputs(self):
        path = ROOT / "tests/bdd/changes/benchmark-execution-reliability/runtime-inputs.json"
        if not path.is_file():
            pytest.skip("BLOCKED: hash-pinned BER runtime inputs have not been recorded")
        assert path.stat().st_size <= 65536, "BER input manifest exceeds its finite bound"
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        assert isinstance(value, dict) and value.get("schemaVersion") == "ber-runtime-inputs/v1", "invalid BER input manifest"
        assert isinstance(value.get("captures"), dict), "BER capture references missing"
        return value["captures"]

    def _catalog_facts(self):
        registry = build_registry("benchmark-task-suite")
        contexts = []
        for sid in ("BTS-SC-001", "BTS-SC-002"):
            legacy = ScenarioContext(sid)
            registry.setup(legacy)
            registry.execute(legacy, "")
            registry.verify(legacy, "")
            contexts.append(legacy)
        one, two = (c.state["bts_verified_facts"] for c in contexts)
        negatives = ("training_set_mismatch", "training_weight_or_sum_mismatch", "ranked_or_training_case_count_mismatch", "release_identity_reuse")
        complete = all(two.get(n) is True for n in negatives)
        return {**{n: two.get(n) is True for n in negatives},
          "raw_four_negative_inputs": complete and two.get("raw_paths_hashes") is True,
          "actual_validator_rejections": complete,
          "independent_replay_agreement": complete and two.get("cutoff") is True,
          "active_release_unchanged": two.get("admission_charge_absence") is True,
          "no_invalid_release_activation": two.get("admission_charge_absence") is True,
          "no_reservation_or_grant_mutation": two.get("admission_charge_absence") is True}

    def _execute_BER_SC_001(self, context):
        self._blocked("BER-SC-001")

    def _verify_BER_SC_001(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("advertised_schema_matches_accepted_payloads", facts.get("advertised_schema_matches_accepted_payloads") is True)
        context.check("valid_swap_and_answer_reach_handler", facts.get("valid_swap_and_answer_reach_handler") is True)
        context.check("invalid_payload_no_effect", facts.get("invalid_payload_no_effect") is True)
        context.check("minimal_valid_swap", facts.get("minimal_valid_swap") is True)
        context.check("full_optional_swap", facts.get("full_optional_swap") is True)
        context.check("full_s2_auth_fields", facts.get("full_s2_auth_fields") is True)
        context.check("oversize_depth_or_bytes", facts.get("oversize_depth_or_bytes") is True)
        context.check("foreign_task", facts.get("foreign_task") is True)
        context.check("unknown_fields", facts.get("unknown_fields") is True)
        context.check("one_admission_per_operation", facts.get("one_admission_per_operation") is True)
        context.check("unchanged_ledger_on_rejection", facts.get("unchanged_ledger_on_rejection") is True)

    def _execute_BER_SC_002(self, context):
        self._blocked("BER-SC-002")

    def _verify_BER_SC_002(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("issued_answer_schema", facts.get("issued_answer_schema") is True)
        context.check("validation_field_paths", facts.get("validation_field_paths") is True)
        context.check("closure_rows", facts.get("closure_rows") is True)
        context.check("hidden_material_absent", facts.get("hidden_material_absent") is True)
        context.check("structured_answer_for_s1", facts.get("structured_answer_for_s1") is True)
        context.check("wrong_s2_fields", facts.get("wrong_s2_fields") is True)
        context.check("missing_or_wrong_s3_type", facts.get("missing_or_wrong_s3_type") is True)
        context.check("foreign_or_queued_schema_request", facts.get("foreign_or_queued_schema_request") is True)
        context.check("one_valid_closure", facts.get("one_valid_closure") is True)
        context.check("invalid_answer_no_task_or_action_mutation", facts.get("invalid_answer_no_task_or_action_mutation") is True)

    def _execute_BER_SC_003(self, context):
        from tests.bdd.adapters.ber_recovery_replay import verify_fault_core
        inputs = self._runtime_inputs()
        if "h1CutoffMatrix" in inputs:
            from tests.bdd.adapters.ber_h1_replay import verify_h1_matrix
            report = verify_h1_matrix(inputs["h1CutoffMatrix"], repository_root=ROOT)
            context.state["ber_facts"] = report["facts"]
            context.state["ber_independent_replay"] = report
            if report.get("missingVariants") or report.get("fullScenarioAcceptance") != "passed":
                pytest.skip("BLOCKED: BER-SC-003 independently verified available H1 cases; missing " +
                            ", ".join(report.get("missingVariants") or ["complete approved cutoff matrix"]))
            return
        if "faultCore" not in inputs:
            self._blocked("BER-SC-003")
        report = verify_fault_core(inputs["faultCore"], repository_root=ROOT)
        context.state["ber_independent_replay"] = report
        pytest.skip("BLOCKED: BER-SC-003 verified S1 response-loss subset; missing " +
                    ", ".join(report["missingVariants"]))

    def _verify_BER_SC_003(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("accepted_cutoff_order", facts.get("accepted_cutoff_order") is True)
        context.check("outbox_and_receipt_history", facts.get("outbox_and_receipt_history") is True)
        context.check("effect_count", facts.get("effect_count") is True)
        context.check("closure_progress", facts.get("closure_progress") is True)
        context.check("exact_generation_fence", facts.get("exact_generation_fence") is True)
        context.check("before_at_after_deadline", facts.get("before_at_after_deadline") is True)
        context.check("response_loss_before_and_after_dispatch", facts.get("response_loss_before_and_after_dispatch") is True)
        context.check("worker_restart", facts.get("worker_restart") is True)
        context.check("late_duplicate", facts.get("late_duplicate") is True)
        context.check("revoked_agent", facts.get("revoked_agent") is True)
        context.check("immutable_action_and_cutoff", facts.get("immutable_action_and_cutoff") is True)
        context.check("bounded_pending_resolution", facts.get("bounded_pending_resolution") is True)
        context.check("no_duplicate_effect_or_charge", facts.get("no_duplicate_effect_or_charge") is True)

    def _execute_BER_SC_004(self, context):
        from tests.bdd.adapters.ber_recovery_replay import verify_unknown_matrix
        inputs = self._runtime_inputs()
        if "unknownMatrix" not in inputs:
            self._blocked("BER-SC-004")
        report = verify_unknown_matrix(inputs["unknownMatrix"], repository_root=ROOT)
        context.state["ber_facts"] = report["facts"]
        context.state["ber_independent_replay"] = report
        if report.get("missingVariants") or report.get("fullScenarioAcceptance") != "passed":
            pytest.skip("BLOCKED: BER-SC-004 independently verified available cases; missing " +
                        ", ".join(report.get("missingVariants") or ["complete approved unknown-grading matrix"]))

    def _verify_BER_SC_004(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("raw_unknown_reasons", facts.get("raw_unknown_reasons") is True)
        context.check("recovery_deadline", facts.get("recovery_deadline") is True)
        context.check("closure_evaluation_binding", facts.get("closure_evaluation_binding") is True)
        context.check("terminal_and_refund_source", facts.get("terminal_and_refund_source") is True)
        context.check("no_public_result", facts.get("no_public_result") is True)
        context.check("missing_or_conflicting_receipt", facts.get("missing_or_conflicting_receipt") is True)
        context.check("unknown_preflight", facts.get("unknown_preflight") is True)
        context.check("recovery_success_or_exhaustion", facts.get("recovery_success_or_exhaustion") is True)
        context.check("cancel_recovery_race", facts.get("cancel_recovery_race") is True)
        context.check("forged_failure_report", facts.get("forged_failure_report") is True)
        context.check("one_recovery_terminal_transition", facts.get("one_recovery_terminal_transition") is True)
        context.check("at_most_one_authorized_source_refund", facts.get("at_most_one_authorized_source_refund") is True)
        context.check("retained_unknown", facts.get("retained_unknown") is True)

    def _execute_BER_SC_005(self, context):
        self._blocked("BER-SC-005")

    def _verify_BER_SC_005(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("original_failure_provenance", facts.get("original_failure_provenance") is True)
        context.check("preparation_operations", facts.get("preparation_operations") is True)
        context.check("predecessor_proof", facts.get("predecessor_proof") is True)
        context.check("full12_task_and_fence_tail", facts.get("full12_task_and_fence_tail") is True)
        context.check("wrong_origin", facts.get("wrong_origin") is True)
        context.check("case_or_facilitator_pin_mismatch", facts.get("case_or_facilitator_pin_mismatch") is True)
        context.check("preparation_timeout", facts.get("preparation_timeout") is True)
        context.check("restart_before_ready", facts.get("restart_before_ready") is True)
        context.check("unavailable_evidence", facts.get("unavailable_evidence") is True)
        context.check("one_successor_binding", facts.get("one_successor_binding") is True)
        context.check("unchanged_original_charge", facts.get("unchanged_original_charge") is True)
        context.check("no_active_generation_leak", facts.get("no_active_generation_leak") is True)

    def _execute_BER_SC_006(self, context):
        context.state["ber_facts"] = self._catalog_facts()

    def _verify_BER_SC_006(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("raw_four_negative_inputs", facts.get("raw_four_negative_inputs") is True)
        context.check("actual_validator_rejections", facts.get("actual_validator_rejections") is True)
        context.check("independent_replay_agreement", facts.get("independent_replay_agreement") is True)
        context.check("active_release_unchanged", facts.get("active_release_unchanged") is True)
        context.check("training_set_mismatch", facts.get("training_set_mismatch") is True)
        context.check("training_weight_or_sum_mismatch", facts.get("training_weight_or_sum_mismatch") is True)
        context.check("ranked_or_training_case_count_mismatch", facts.get("ranked_or_training_case_count_mismatch") is True)
        context.check("release_identity_reuse", facts.get("release_identity_reuse") is True)
        context.check("no_invalid_release_activation", facts.get("no_invalid_release_activation") is True)
        context.check("no_reservation_or_grant_mutation", facts.get("no_reservation_or_grant_mutation") is True)

    def _execute_BER_SC_007(self, context):
        from tests.bdd.adapters.ber_recovery_replay import verify_matrix
        report = verify_matrix(ROOT, self._runtime_inputs())
        context.state["ber_facts"] = report["facts"]
        context.state["ber_independent_replay"] = report
        # A malformed supplied proof raises before this branch. Missing approved
        # transition experiments remain blocked even when the retained history replays.
        missing = report.get("missingVariants", [])
        if missing or report.get("fullScenarioAcceptance") != "passed":
            pytest.skip("BLOCKED: BER-SC-007 independently verified partial history; missing " +
                        ", ".join(missing or ["complete approved recovery/replay matrix"]))

    def _verify_BER_SC_007(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("source_and_artifact_hashes", facts.get("source_and_artifact_hashes") is True)
        context.check("task_action_closure_evaluation_chain", facts.get("task_action_closure_evaluation_chain") is True)
        context.check("completion_handoff", facts.get("completion_handoff") is True)
        context.check("before_after_ledger_and_slots", facts.get("before_after_ledger_and_slots") is True)
        context.check("crash_recovery_once_only_write_vs_readonly_replay_zero_write", facts.get("crash_recovery_once_only_write_vs_readonly_replay_zero_write") is True)
        context.check("duplicate_out_of_order_completion", facts.get("duplicate_out_of_order_completion") is True)
        context.check("missing_or_tampered_artifact", facts.get("missing_or_tampered_artifact") is True)
        context.check("restart_each_transition", facts.get("restart_each_transition") is True)
        context.check("late_callback", facts.get("late_callback") is True)
        context.check("crash_before_first_authorized_refund_commit", facts.get("crash_before_first_authorized_refund_commit") is True)
        context.check("idempotent_authorized_recovery_completion", facts.get("idempotent_authorized_recovery_completion") is True)
        context.check("readonly_replay_zero_business_writes", facts.get("readonly_replay_zero_business_writes") is True)
        context.check("exact_resource_release", facts.get("exact_resource_release") is True)

    def _execute_BER_SC_008(self, context):
        self._blocked("BER-SC-008")

    def _verify_BER_SC_008(self, context):
        facts = context.state.get("ber_facts", {})
        context.check("browser_result_projection", facts.get("browser_result_projection") is True)
        context.check("durable_evaluation_receipt_links", facts.get("durable_evaluation_receipt_links") is True)
        context.check("causal_classification", facts.get("causal_classification") is True)
        context.check("no_score_overwrite", facts.get("no_score_overwrite") is True)
        context.check("participant_forged_platform_error", facts.get("participant_forged_platform_error") is True)
        context.check("missing_causal_evidence", facts.get("missing_causal_evidence") is True)
        context.check("unissued_task", facts.get("unissued_task") is True)
        context.check("stale_prior_source_capture", facts.get("stale_prior_source_capture") is True)
        context.check("read_only_historical_feedback", facts.get("read_only_historical_feedback") is True)
        context.check("no_regrading_or_refund_from_display", facts.get("no_regrading_or_refund_from_display") is True)

def register(registry):
    for sid in SCENARIO_IDS:
        registry.register(sid, BenchmarkExecutionReliabilityCase(sid), adapter_profile="benchmark_execution_reliability")
