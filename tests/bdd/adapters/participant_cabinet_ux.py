"""Fail-closed PCU environment adapter; local UI checks never establish runtime acceptance.

The owner acceptance runner records real controls, actual API projections and
independent read-only PostgreSQL rows. Replay derives facts from hash-pinned raw
captures. Missing approved variants remain blocked; producer facts are ignored.
"""
from pathlib import Path
import json
import pytest
from tests.bdd.adapters.participant_cabinet_replay import verify_capture

ADAPTER_PROFILES = {"participant_cabinet_ux"}
SCENARIO_IDS = tuple(f"PCU-SC-{number:03d}" for number in range(1, 9))


class ParticipantCabinetCase:
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

    def _capture(self, context):
        root = Path(__file__).resolve().parents[3]
        manifest = root / "tests/bdd/changes/participant-cabinet-ux/runtime-inputs.json"
        if not manifest.is_file():
            pytest.skip("BLOCKED: " + self.scenario_id + " has no hash-pinned actual browser capture")
        assert manifest.stat().st_size <= 65536, "PCU runtime inputs exceed bound"
        inputs = json.loads(manifest.read_text(encoding="utf-8-sig"))
        assert inputs.get("schemaVersion") == "pcu-runtime-inputs/v1", "Invalid PCU runtime inputs"
        replay = verify_capture(root, inputs["capture"])
        scenario = replay["scenarios"][self.scenario_id]
        context.state["pcu_independently_verified_facts"] = scenario["facts"]
        context.state["pcu_independent_replay"] = replay
        if scenario["status"] != "passed":
            pytest.skip("BLOCKED: " + self.scenario_id + " missing actual variants " + ", ".join(scenario["missingVariants"]) + "; observations " + ", ".join(scenario["missingObservations"]))

    def _execute_PCU_SC_001(self, context):
        self._capture(context)

    def _verify_PCU_SC_001(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("displayed_price_mode_source", facts.get("displayed_price_mode_source") is True)
        context.check("exact_quote_and_reservation", facts.get("exact_quote_and_reservation") is True)
        context.check("stale_quote_reconfirmation", facts.get("stale_quote_reconfirmation") is True)
        context.check("single_launch", facts.get("single_launch") is True)

    def _execute_PCU_SC_002(self, context):
        self._capture(context)

    def _verify_PCU_SC_002(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("two_decimal_and_subcent_render", facts.get("two_decimal_and_subcent_render") is True)
        context.check("exact_detail_units", facts.get("exact_detail_units") is True)
        context.check("before_after_ledger_fingerprint", facts.get("before_after_ledger_fingerprint") is True)
        context.check("allocation_validation", facts.get("allocation_validation") is True)

    def _execute_PCU_SC_003(self, context):
        self._capture(context)

    def _verify_PCU_SC_003(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("initial_five_and_order", facts.get("initial_five_and_order") is True)
        context.check("complete_cursor_traversal", facts.get("complete_cursor_traversal") is True)
        context.check("compact_and_expanded_fields", facts.get("compact_and_expanded_fields") is True)
        context.check("foreign_cursor_denial", facts.get("foreign_cursor_denial") is True)

    def _execute_PCU_SC_004(self, context):
        self._capture(context)

    def _verify_PCU_SC_004(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("accessible_help_interaction", facts.get("accessible_help_interaction") is True)
        context.check("safe_state_error_mapping", facts.get("safe_state_error_mapping") is True)
        context.check("correlation_id_binding", facts.get("correlation_id_binding") is True)
        context.check("no_secret_render", facts.get("no_secret_render") is True)
        context.check("distinct_active_vs_hovered_nav_background", facts.get("distinct_active_vs_hovered_nav_background") is True)
        context.check("no_automatic_paid_retry", facts.get("no_automatic_paid_retry") is True)

    def _execute_PCU_SC_005(self, context):
        self._capture(context)

    def _verify_PCU_SC_005(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("actual_feedback_click", facts.get("actual_feedback_click") is True)
        context.check("timeline_matches_receipts", facts.get("timeline_matches_receipts") is True)
        context.check("safe_goal_diagnostics", facts.get("safe_goal_diagnostics") is True)
        context.check("ranked_and_foreign_projection", facts.get("ranked_and_foreign_projection") is True)
        context.check("completed_training_only_action_detail", facts.get("completed_training_only_action_detail") is True)
        context.check("no_ranked_or_public_trace_viewer", facts.get("no_ranked_or_public_trace_viewer") is True)

    def _execute_PCU_SC_006(self, context):
        self._capture(context)

    def _verify_PCU_SC_006(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("browser_submit_receipt", facts.get("browser_submit_receipt") is True)
        context.check("validated_context_and_client_source", facts.get("validated_context_and_client_source") is True)
        context.check("normalized_image_hash", facts.get("normalized_image_hash") is True)
        context.check("admin_visibility", facts.get("admin_visibility") is True)
        context.check("financial_task_fingerprint", facts.get("financial_task_fingerprint") is True)

    def _execute_PCU_SC_007(self, context):
        self._capture(context)

    def _verify_PCU_SC_007(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("http_status_and_headers", facts.get("http_status_and_headers") is True)
        context.check("role_bound_nav_and_hydration", facts.get("role_bound_nav_and_hydration") is True)
        context.check("api_role_csrf_denials", facts.get("api_role_csrf_denials") is True)
        context.check("unchanged_admin_records", facts.get("unchanged_admin_records") is True)

    def _execute_PCU_SC_008(self, context):
        self._capture(context)

    def _verify_PCU_SC_008(self, context):
        facts = context.state.get("pcu_independently_verified_facts", {})
        context.check("main_vs_advanced_fields", facts.get("main_vs_advanced_fields") is True)
        context.check("actual_connection_observation", facts.get("actual_connection_observation") is True)
        context.check("replacement_scope_warning", facts.get("replacement_scope_warning") is True)
        context.check("grant_and_policy_readback", facts.get("grant_and_policy_readback") is True)


def register(registry):
    for scenario_id in SCENARIO_IDS:
        registry.register(scenario_id, ParticipantCabinetCase(scenario_id), adapter_profile="participant_cabinet_ux")
