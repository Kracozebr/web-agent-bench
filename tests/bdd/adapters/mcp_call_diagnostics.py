"""Fail-closed MCD boundary registry and bounded source/evidence loading.

The adapter never dispatches HTTP, database or task operations. Current runtime
gates remain blocked until their actual captures exist. Producer observation
flags cannot pass the independent physical replay.
"""
from pathlib import Path
import hashlib
import json
import pytest
from tests.bdd.adapters.ber_recovery_replay import read_reference
from tests.bdd.adapters.mcd_physical_replay import REPLAY, load_variants

ROOT = Path(__file__).resolve().parents[3]
ADAPTER_PROFILES = {"mcp_call_diagnostics"}
CHANGE = "mcp-call-diagnostics"


class ReplayUnavailable(RuntimeError):
    """A real boundary has no complete independent replay implementation yet."""


def need(value, message):
    if not value:
        raise AssertionError(message)


def load_physical(reference, scenario_id, root=ROOT):
    """Verify file identity/source scope before any future boundary derivation."""
    capture = read_reference(root, reference)
    need(capture.get("schemaVersion") == "mcd-physical-capture/v1", "MCD physical capture schema")
    need(capture.get("scenarioId") == scenario_id, "MCD scenario binding")
    observer = capture.get("observer", {})
    need(observer.get("role") == "oid_observer" and observer.get("readOnly") is True, "MCD independent observer boundary")
    need(isinstance(observer.get("databaseName"),str) and bool(observer["databaseName"]), "MCD observer database identity missing")
    before, after = (capture.get("sourceInputs", {}).get(key) for key in ("before", "after"))
    need(isinstance(before, dict) and before and before == after, "MCD stable source inventory")
    for path, expected in before.items():
        file = (root / path).resolve()
        need(file.is_relative_to(root.resolve()) and file.is_file(), "MCD unsafe source path")
        need(hashlib.sha256(file.read_bytes()).hexdigest() == expected, "MCD current source drift")
    raw = capture.get("raw")
    need(isinstance(raw, dict) and raw, "MCD independent raw boundary references missing")
    for ref in raw.values():
        read_reference(root, ref)
    return capture


def physical(reference, scenario_id, root=ROOT):
    capture = load_physical(reference, scenario_id, root)
    manifest = json.loads((ROOT / "tests/bdd/changes/mcp-call-diagnostics/harness-contracts.json").read_text(encoding="utf-8-sig"))
    required = manifest["protected_scenarios"][scenario_id]["negative_variants"]
    variants = load_variants(capture, root, required)
    raw = {key: read_reference(root, value) for key,value in capture["raw"].items()}
    # AICODE-NOTE: Never use capture.observations, passed flags or application
    # counters as observations. Each reader replays its own exact boundary rules.
    try:
        return REPLAY[scenario_id](raw, variants, root)
    except KeyError as error:
        raise AssertionError("MCD physical evidence contract incomplete: " + str(error)) from error


class Case:
    def __init__(self, scenario_id): self.scenario_id = scenario_id
    def setup(self, context): need(context.scenario_id == self.scenario_id, "MCD scenario mismatch")
    def execute(self, context, when_text): getattr(self, "_execute_" + self.scenario_id.replace("-", "_"))(context)
    def verify(self, context, then_text): getattr(self, "_verify_" + self.scenario_id.replace("-", "_"))(context)
    def _capture(self, context):
        file = ROOT / "tests/bdd/changes/mcp-call-diagnostics/runtime-inputs.json"
        if not file.is_file(): pytest.skip("BLOCKED: MCD physical runtime inputs missing")
        inputs = json.loads(file.read_text(encoding="utf-8-sig"))
        need(inputs.get("schemaVersion") == "mcd-runtime-inputs/v1", "MCD runtime input schema")
        reference = inputs.get("captures", {}).get(self.scenario_id)
        if not reference: pytest.skip(f"BLOCKED: {self.scenario_id} actual boundary capture missing")
        try: context.state["mcd_observations"] = physical(reference, self.scenario_id)
        except ReplayUnavailable as error: pytest.skip("BLOCKED: " + str(error))

    def _execute_MCD_SC_001(self, context): self._capture(context)
    def _verify_MCD_SC_001(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("stage_and_error_identity", facts.get("stage_and_error_identity") is True)
        context.check("source_local_timings", facts.get("source_local_timings") is True)
        context.check("validated_links", facts.get("validated_links") is True)
        context.check("survives_restart", facts.get("survives_restart") is True)

    def _execute_MCD_SC_002(self, context): self._capture(context)
    def _verify_MCD_SC_002(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("native_call_events", facts.get("native_call_events") is True)
        context.check("helper_oauth_scope_and_revocation", facts.get("helper_oauth_scope_and_revocation") is True)
        context.check("native_case_trace_carrier", facts.get("native_case_trace_carrier") is True)
        context.check("canonical_case_identity", facts.get("canonical_case_identity") is True)
        context.check("automatic_report_and_watermark_receipt", facts.get("automatic_report_and_watermark_receipt") is True)
        context.check("admin_report_visible", facts.get("admin_report_visible") is True)
        context.check("deduplicated_delivery", facts.get("deduplicated_delivery") is True)
        context.check("blocked_delivery_zero_report_writes", facts.get("blocked_delivery_zero_report_writes") is True)

    def _execute_MCD_SC_003(self, context): self._capture(context)
    def _verify_MCD_SC_003(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("schema_contract_compatibility", facts.get("schema_contract_compatibility") is True)
        context.check("positive_matrix_categories", facts.get("positive_matrix_categories") is True)
        context.check("classification_evidence", facts.get("classification_evidence") is True)
        context.check("reject_all_unknown_projection", facts.get("reject_all_unknown_projection") is True)
        context.check("unknown_preserved", facts.get("unknown_preserved") is True)
        context.check("business_hashes_unchanged", facts.get("business_hashes_unchanged") is True)

    def _execute_MCD_SC_004(self, context): self._capture(context)
    def _verify_MCD_SC_004(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("own_rows_visible", facts.get("own_rows_visible") is True)
        context.check("admin_authorized", facts.get("admin_authorized") is True)
        context.check("foreign_denied", facts.get("foreign_denied") is True)
        context.check("source_trust_visible", facts.get("source_trust_visible") is True)
        context.check("diagnostic_trigger_distinct", facts.get("diagnostic_trigger_distinct") is True)

    def _execute_MCD_SC_005(self, context): self._capture(context)
    def _verify_MCD_SC_005(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("canaries_absent", facts.get("canaries_absent") is True)
        context.check("exact_finite_bounds", facts.get("exact_finite_bounds") is True)
        context.check("independently_proven_dominance", facts.get("independently_proven_dominance") is True)
        context.check("shared_quota_reservations", facts.get("shared_quota_reservations") is True)
        context.check("anonymous_fixed_buckets", facts.get("anonymous_fixed_buckets") is True)
        context.check("gap_markers", facts.get("gap_markers") is True)
        context.check("no_duplicate_effect", facts.get("no_duplicate_effect") is True)

    def _execute_MCD_SC_006(self, context): self._capture(context)
    def _verify_MCD_SC_006(self, context):
        facts = context.state.get("mcd_observations", {})
        context.check("server_received_inventory_and_hashes", facts.get("server_received_inventory_and_hashes") is True)
        context.check("remote_pending_excluded", facts.get("remote_pending_excluded") is True)
        context.check("partial_retained", facts.get("partial_retained") is True)
        context.check("write_disabled", facts.get("write_disabled") is True)
        context.check("revocation_retained", facts.get("revocation_retained") is True)
        context.check("separate_retention_boundaries", facts.get("separate_retention_boundaries") is True)
        context.check("case_batch_report_identity_retained", facts.get("case_batch_report_identity_retained") is True)


def register(registry):
    for number in range(1, 7):
        sid = f"MCD-SC-{number:03d}"
        registry.register(sid, Case(sid), adapter_profile="mcp_call_diagnostics")
