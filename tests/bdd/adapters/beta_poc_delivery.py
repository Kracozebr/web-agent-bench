"""Fail-closed reader for approved beta PoC runtime captures.

The adapter replays only hash-pinned target-bound evidence. Missing or blocked
captures become blocked BDD results; local fixture observations never satisfy
the approved environment contracts.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry

CHANGE_NAME = "beta-poc-delivery"
SCENARIO_IDS = tuple(f"BPC-SC-{number:03d}" for number in range(1, 27))
ADAPTER_PROFILES = frozenset({
    "beta_poc_bonus_code_adapter",
    "beta_poc_execution_adapter",
    "beta_poc_identity_browser_adapter",
    "beta_poc_native_client_adapter",
    "beta_poc_public_result_adapter",
    "beta_poc_release_bundle_adapter",
    "beta_poc_report_attachment_adapter",
    "beta_poc_report_retention_adapter",
    "beta_poc_reports_browser_adapter",
    "beta_poc_target_host_adapter",
})
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY_ROOT / "artifacts" / "runs" / "acceptance"
CHANGE_ROOT = REPOSITORY_ROOT / "openspec" / "changes" / CHANGE_NAME
PROPOSAL_PATH = CHANGE_ROOT / "bdd-harness-proposal.json"
CONTRACT_PATH = REPOSITORY_ROOT / "tests" / "bdd" / "changes" / CHANGE_NAME / "harness-contracts.json"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARTIFACT_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\.(?:json|png|jpe?g|webp)$", re.IGNORECASE)
SECRET_KEY_RE = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|"
    r"codeverifiersecret|verifiersecret|dburl|plaintextcode|"
    r"manualtoken|tokenvalue|authorization|privatekey|mnemonic|seedphrase|rawsignature|"
    r"signature|walletmaterial|databaseurl|rpcurl|oauthcode|oauthstate)$",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+|"
    r"(?<![A-Za-z0-9_-])BPC-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])|"
    r"\b(?:aap1|oid1|oat1)_[A-Za-z0-9_-]{32,}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)


def _assert_secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY_RE.fullmatch(normalized):
                raise AssertionError(f"credential-bearing evidence field at {path}.{key}")
            _assert_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_TEXT_RE.search(value):
        raise AssertionError(f"credential-like evidence text at {path}")


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"Expected a JSON object in {path.name}")
    _assert_secret_free(value, path.name)
    return value


def _inside(root: Path, path: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved_root not in resolved.parents:
        raise AssertionError("BPC evidence path escapes its declared root")
    return resolved


def _load_contract_sources(
    *, proposal_path: Path = PROPOSAL_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    proposal_bytes = proposal_path.read_bytes()
    contract_bytes = contract_path.read_bytes()
    proposal = json.loads(proposal_bytes.decode("utf-8"))
    contract = json.loads(contract_bytes.decode("utf-8"))
    expected = set(SCENARIO_IDS)
    proposal_rows = proposal.get("protected_scenarios") if isinstance(proposal, dict) else None
    contract_rows = contract.get("protected_scenarios") if isinstance(contract, dict) else None
    if (
        proposal.get("proposal_schema") != "bdd-harness-contract-proposal/v1"
        or proposal.get("review_status") != "approved"
        or not isinstance(proposal_rows, dict)
        or set(proposal_rows) != expected
        or not isinstance(contract_rows, dict)
        or set(contract_rows) != expected
        or contract.get("coverage_policy", {}).get("required_protected_scenarios") != list(SCENARIO_IDS)
        or contract.get("coverage_policy", {}).get("status") != "complete"
    ):
        raise AssertionError("BPC approved and runtime contract inventories are incomplete")
    observed_profiles: set[str] = set()
    for scenario_id in SCENARIO_IDS:
        approved = proposal_rows[scenario_id]
        runtime = contract_rows[scenario_id]
        for proposal_key, contract_key in (
            ("requirement_id", "requirement_id"),
            ("title", "title"),
            ("named_mapper", "named_mapper"),
            ("adapter", "adapter"),
            ("boundary", "boundary"),
            ("boundary_detail", "boundary_detail"),
            ("required_observations", "required_observations"),
            ("negative_variants", "negative_variants"),
            ("durable_effects", "durable_effects"),
            ("evidence_mode", "evidence_mode"),
        ):
            if approved.get(proposal_key) != runtime.get(contract_key):
                raise AssertionError(f"{scenario_id} approved/runtime {proposal_key} inventory drifted")
        if approved.get("mandatory") is not True or approved.get("gate") not in {"environment", "artifact"}:
            raise AssertionError(f"{scenario_id} is not an approved mandatory BPC gate")
        if approved.get("adapter") not in ADAPTER_PROFILES:
            raise AssertionError(f"{scenario_id} uses an unregistered BPC adapter profile")
        observed_profiles.add(approved["adapter"])
    if observed_profiles != ADAPTER_PROFILES:
        raise AssertionError("BPC adapter profile inventory drifted")
    return proposal, contract, contract_bytes


def _verify_source_inventory(
    provenance: dict[str, Any], scenario_id: str, repository_root: Path = REPOSITORY_ROOT
) -> None:
    before = provenance.get("inputHashesBefore")
    after = provenance.get("inputHashesAfter")
    if (
        provenance.get("sourceStableDuringRun") is not True
        or not isinstance(before, dict)
        or not before
        or before != after
    ):
        raise AssertionError(f"{scenario_id} provenance lacks identical before/after source inventories")
    replay_readers = {
        "tests/bdd/adapters/beta_poc_delivery.py",
        "tests/bdd/adapters/test_beta_poc_delivery_evidence.py",
    }
    for relative, expected in before.items():
        if (
            not isinstance(relative, str)
            or "\\" in relative
            or ":" in relative
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or not isinstance(expected, str)
            or not SHA256_RE.fullmatch(expected)
        ):
            raise AssertionError(f"{scenario_id} provenance contains an unsafe source inventory entry")
        if relative in replay_readers:
            continue
        source = _inside(repository_root, repository_root.joinpath(*PurePosixPath(relative).parts))
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected.lower():
            raise AssertionError(f"{scenario_id} captured source no longer matches {relative}")


def load_capture(
    scenario_id: str,
    *,
    evidence_root: Path = EVIDENCE_ROOT,
    repository_root: Path = REPOSITORY_ROOT,
    proposal_path: Path = PROPOSAL_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    """Load and hash-check one captured run; a missing index is not evidence."""

    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"Unsupported BPC scenario identity: {scenario_id}")
    scenario_root = evidence_root / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_object(index_path)
    if (
        index.get("schemaVersion") != "beta-poc-delivery-evidence-index/v1"
        or index.get("scenarioId") != scenario_id
        or index.get("status") not in {"running", "blocked", "failed", "passed"}
    ):
        raise AssertionError(f"{scenario_id} evidence index identity or schema is invalid")
    run_id = index.get("latestRunId")
    runs = index.get("runs")
    if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id) or not isinstance(runs, list) or run_id not in runs:
        raise AssertionError(f"{scenario_id} evidence index does not bind its latest run")
    if index["status"] == "running":
        return {"status": "running", "blockedReasonCode": "capture_not_terminal"}, {}

    _, contract, contract_bytes = _load_contract_sources(proposal_path=proposal_path, contract_path=contract_path)
    contract_row = contract["protected_scenarios"][scenario_id]
    run_root = _inside(scenario_root, scenario_root / "runs" / run_id)
    manifest = _read_object(run_root / "manifest.json")
    if (
        manifest.get("schemaVersion") != "beta-poc-delivery-acceptance/v1"
        or manifest.get("specProfile") != "active-delta"
        or manifest.get("scenarioId") != scenario_id
        or manifest.get("runId") != run_id
        or manifest.get("status") not in {"blocked", "failed", "passed"}
        or manifest.get("status") != index.get("status")
        or manifest.get("boundaryDetail") != contract_row["boundary_detail"]
    ):
        raise AssertionError(f"{scenario_id} run manifest identity or status is invalid")

    inventory = manifest.get("artifacts")
    if not isinstance(inventory, list) or not inventory:
        raise AssertionError(f"{scenario_id} must inventory its raw evidence artifacts")
    loaded: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise AssertionError(f"{scenario_id} artifact inventory contains a malformed row")
        relative = item.get("path")
        digest = item.get("sha256")
        content_type = item.get("contentType")
        if (
            not isinstance(relative, str)
            or not ARTIFACT_PATH_RE.fullmatch(relative)
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or relative in seen_paths
        ):
            raise AssertionError(f"{scenario_id} has an unsafe or duplicate artifact path")
        seen_paths.add(relative)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise AssertionError(f"{scenario_id} has an invalid artifact digest")
        expected_types = {
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
        }
        if (
            content_type != expected_types[Path(relative).suffix.lower()]
            or item.get("boundary") != contract_row["boundary_detail"]
        ):
            raise AssertionError(f"{scenario_id} artifact metadata is invalid")
        artifact_path = _inside(run_root, run_root.joinpath(*PurePosixPath(relative).parts))
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest.lower():
            raise AssertionError(f"{scenario_id} artifact hash mismatch for {relative}")
        if content_type == "application/json":
            payload = json.loads(content.decode("utf-8"))
            if not isinstance(payload, dict):
                raise AssertionError(f"{scenario_id} artifact {relative} is not a JSON object")
            _assert_secret_free(payload, relative)
            loaded[relative] = payload

    provenance = loaded.get("provenance.json")
    if not isinstance(provenance, dict) or provenance.get("contractSha256") != hashlib.sha256(contract_bytes).hexdigest():
        raise AssertionError(f"{scenario_id} evidence is not bound to the current BPC runtime contract")
    required_observations = set(contract_row["required_observations"])
    required_negatives = set(contract_row["negative_variants"])
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != required_observations:
        raise AssertionError(f"{scenario_id} observation inventory drifted")
    if not isinstance(negatives, dict) or set(negatives) != required_negatives:
        raise AssertionError(f"{scenario_id} negative-variant inventory drifted")
    for name, row in [*observations.items(), *negatives.items()]:
        if not isinstance(row, dict) or row.get("status") not in {"not_run", "verified", "failed"}:
            raise AssertionError(f"{scenario_id} observation {name} has an invalid status")
        if row.get("status") == "verified" and row.get("value") is not True:
            raise AssertionError(f"{scenario_id} observation {name} has a contradictory verified value")
    if manifest.get("status") == "blocked":
        reason = manifest.get("blockedReasonCode")
        if not isinstance(reason, str) or not reason.strip():
            raise AssertionError(f"{scenario_id} blocked capture lacks a reason code")
        if any(row.get("status") != "not_run" for row in (*observations.values(), *negatives.values())):
            raise AssertionError(f"{scenario_id} blocked capture cannot promote unverified partial claims")
    if manifest.get("status") == "passed":
        if any(row.get("status") != "verified" for row in (*observations.values(), *negatives.values())):
            raise AssertionError(f"{scenario_id} pass claim lacks verified observations and negative variants")
        _verify_source_inventory(provenance, scenario_id, repository_root)
    return manifest, loaded


class BetaPocEvidenceCase:
    """Read approved evidence only; never substitute a fixture for an environment gate."""

    def __init__(self, scenario_id: str, proposal_row: dict[str, Any], contract_row: dict[str, Any]) -> None:
        self.scenario_id = scenario_id
        self.proposal_row = proposal_row
        self.contract_row = contract_row

    def setup(self, context: ScenarioContext) -> None:
        if context.scenario_id != self.scenario_id:
            raise AssertionError("BPC mapper and scenario identity differ")
        context.state["bpc_boundary_detail"] = self.proposal_row["boundary_detail"]
        context.state["bpc_evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        method = getattr(self, "_execute_" + self.scenario_id.replace("-", "_"))
        method(context)

    def _execute_evidence(self, context: ScenarioContext, scenario_id: str) -> None:
        if scenario_id != self.scenario_id or context.scenario_id != scenario_id:
            raise AssertionError("BPC evidence executor identity mismatch")
        loaded = load_capture(self.scenario_id, evidence_root=EVIDENCE_ROOT)
        if loaded is None:
            pytest.skip(f"BLOCKED: no hash-pinned BPC runtime capture exists for {self.proposal_row['boundary_detail']}")
        manifest, artifacts = loaded
        context.state["bpc_manifest"] = manifest
        context.state["bpc_artifacts"] = artifacts
        if manifest.get("status") == "running":
            pytest.skip("BLOCKED: BPC evidence capture is not terminal")
        if manifest.get("status") == "blocked":
            pytest.skip(f"BLOCKED: {manifest['blockedReasonCode']}")
        if manifest.get("status") == "failed":
            raise AssertionError(f"{self.scenario_id} recorded a failed target-bound runtime capture")
        facts = _derive_raw_boundary_facts(self.scenario_id, artifacts)
        if facts is None:
            raise AssertionError(
                f"{self.scenario_id} claims a pass but has no scenario-specific raw-boundary replay verifier"
            )
        expected = set(self.contract_row["required_observations"]) | set(self.contract_row["negative_variants"])
        if set(facts) != expected or any(type(value) is not bool for value in facts.values()):
            raise AssertionError(f"{self.scenario_id} replay verifier returned an incomplete or malformed fact inventory")
        context.state["bpc_replay_facts"] = facts

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        method = getattr(self, "_verify_" + self.scenario_id.replace("-", "_"))
        method(context)

    def _verified_facts(self, context: ScenarioContext, scenario_id: str) -> dict[str, bool]:
        if scenario_id != self.scenario_id or context.scenario_id != scenario_id:
            raise AssertionError("BPC evidence verifier identity mismatch")
        facts = context.state.get("bpc_replay_facts")
        if not isinstance(facts, dict):
            raise AssertionError(f"{self.scenario_id} has no scenario-specific raw-boundary replay facts")
        failed_negatives = [name for name in self.contract_row["negative_variants"] if facts[name] is not True]
        if failed_negatives:
            raise AssertionError(f"{self.scenario_id} negative variants were not independently verified: {failed_negatives}")
        return facts

    def _execute_BPC_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-001")

    def _verify_BPC_SC_001(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-001")
        context.check("google_subject_and_owner_stable", facts["google_subject_and_owner_stable"])
        context.check("callback_verified", facts["callback_verified"])
        context.check("no_signup_bonus", facts["no_signup_bonus"])
        context.check("invalid_callback_no_session", facts["invalid_callback_no_session"])

    def _execute_BPC_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-002")

    def _verify_BPC_SC_002(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-002")
        context.check("owner_ui_persisted", facts["owner_ui_persisted"])
        context.check("foreign_reads_denied", facts["foreign_reads_denied"])
        context.check("admin_subject_enforced", facts["admin_subject_enforced"])
        context.check("csrf_origin_enforced", facts["csrf_origin_enforced"])

    def _execute_BPC_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-003")

    def _verify_BPC_SC_003(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-003")
        context.check("one_code_per_operation", facts["one_code_per_operation"])
        context.check("exact_immutable_terms", facts["exact_immutable_terms"])
        context.check("one_time_secret", facts["one_time_secret"])
        context.check("safe_issue_retry", facts["safe_issue_retry"])

    def _execute_BPC_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-004")

    def _verify_BPC_SC_004(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-004")
        context.check("disable_claim_order_serialized", facts["disable_claim_order_serialized"])
        context.check("usage_exact", facts["usage_exact"])
        context.check("old_grants_preserved", facts["old_grants_preserved"])
        context.check("unauthorized_disable_denied", facts["unauthorized_disable_denied"])

    def _execute_BPC_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-005")

    def _verify_BPC_SC_005(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-005")
        context.check("group_and_single_claim_exact", facts["group_and_single_claim_exact"])
        context.check("code_lot_funds_training_and_full12", facts["code_lot_funds_training_and_full12"])
        context.check("independent_balance_and_debit", facts["independent_balance_and_debit"])
        context.check("no_cash_fallback", facts["no_cash_fallback"])

    def _execute_BPC_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-006")

    def _verify_BPC_SC_006(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-006")
        context.check("last_use_one_winner", facts["last_use_one_winner"])
        context.check("one_claim_per_owner", facts["one_claim_per_owner"])
        context.check("counter_grant_atomic", facts["counter_grant_atomic"])
        context.check("original_receipt_recovered", facts["original_receipt_recovered"])

    def _execute_BPC_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-007")

    def _verify_BPC_SC_007(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-007")
        context.check("owner_policy_saved", facts["owner_policy_saved"])
        context.check("four_client_preflights", facts["four_client_preflights"])
        context.check("token_replacement_and_revoke_observed", facts["token_replacement_and_revoke_observed"])
        context.check("restart_retains_revocation", facts["restart_retains_revocation"])

    def _execute_BPC_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-008")

    def _verify_BPC_SC_008(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-008")
        context.check("profile_allowlist_checked", facts["profile_allowlist_checked"])
        context.check("exact_callback_auth", facts["exact_callback_auth"])
        context.check("one_intent_run_reservation", facts["one_intent_run_reservation"])
        context.check("replay_no_economic_effect", facts["replay_no_economic_effect"])
        context.check("local_default_guards_retained", facts["local_default_guards_retained"])

    def _execute_BPC_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-009")

    def _verify_BPC_SC_009(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-009")
        context.check("real_client_and_external_model_observed", facts["real_client_and_external_model_observed"])
        context.check("training_and_full12_completed", facts["training_and_full12_completed"])
        context.check("known_grades_and_private_results", facts["known_grades_and_private_results"])
        context.check("reconnect_rules_retained", facts["reconnect_rules_retained"])
        context.check("original_resources_clean", facts["original_resources_clean"])

    def _execute_BPC_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-010")

    def _verify_BPC_SC_010(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-010")
        context.check("real_client_and_external_model_observed", facts["real_client_and_external_model_observed"])
        context.check("training_and_full12_completed", facts["training_and_full12_completed"])
        context.check("known_grades_and_private_results", facts["known_grades_and_private_results"])
        context.check("reconnect_rules_retained", facts["reconnect_rules_retained"])
        context.check("original_resources_clean", facts["original_resources_clean"])

    def _execute_BPC_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-011")

    def _verify_BPC_SC_011(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-011")
        context.check("real_client_and_external_model_observed", facts["real_client_and_external_model_observed"])
        context.check("training_and_full12_completed", facts["training_and_full12_completed"])
        context.check("known_grades_and_private_results", facts["known_grades_and_private_results"])
        context.check("reconnect_rules_retained", facts["reconnect_rules_retained"])
        context.check("original_resources_clean", facts["original_resources_clean"])

    def _execute_BPC_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-012")

    def _verify_BPC_SC_012(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-012")
        context.check("real_client_and_external_model_observed", facts["real_client_and_external_model_observed"])
        context.check("training_and_full12_completed", facts["training_and_full12_completed"])
        context.check("known_grades_and_private_results", facts["known_grades_and_private_results"])
        context.check("reconnect_rules_retained", facts["reconnect_rules_retained"])
        context.check("original_resources_clean", facts["original_resources_clean"])

    def _execute_BPC_SC_013(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-013")

    def _verify_BPC_SC_013(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-013")
        context.check("actual_readiness_verified", facts["actual_readiness_verified"])
        context.check("task_effect_bound", facts["task_effect_bound"])
        context.check("independent_isolation_observed", facts["independent_isolation_observed"])
        context.check("generation_fenced", facts["generation_fenced"])
        context.check("private_interfaces_denied", facts["private_interfaces_denied"])
        context.check("qualification_accepts_declared_unverified_client", facts["qualification_accepts_declared_unverified_client"])
        context.check("cohort_release_requires_all_verified_families", facts["cohort_release_requires_all_verified_families"])

    def _execute_BPC_SC_014(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-014")

    def _verify_BPC_SC_014(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-014")
        context.check("all_eight_runtime_covered", facts["all_eight_runtime_covered"])
        context.check("single_multi_full_selection", facts["single_multi_full_selection"])
        context.check("ordered_effects", facts["ordered_effects"])
        context.check("exact_open_denominator_charge", facts["exact_open_denominator_charge"])
        context.check("authoritative_feedback", facts["authoritative_feedback"])

    def _execute_BPC_SC_015(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-015")

    def _verify_BPC_SC_015(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-015")
        context.check("twelve_bound_results", facts["twelve_bound_results"])
        context.check("aggregate_exact", facts["aggregate_exact"])
        context.check("mandatory_zero_irreversible", facts["mandatory_zero_irreversible"])
        context.check("independent_tasks_continue", facts["independent_tasks_continue"])
        context.check("ranked_feedback_timing", facts["ranked_feedback_timing"])
        context.check("closed_feedback_allowlist", facts["closed_feedback_allowlist"])

    def _execute_BPC_SC_016(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-016")

    def _verify_BPC_SC_016(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-016")
        context.check("pending_and_accepted_caps_serialized", facts["pending_and_accepted_caps_serialized"])
        context.check("fair_owner_turn", facts["fair_owner_turn"])
        context.check("original_deadline", facts["original_deadline"])
        context.check("slot_exclusive", facts["slot_exclusive"])
        context.check("start_debit_once", facts["start_debit_once"])
        context.check("original_hold_release", facts["original_hold_release"])
        context.check("deadline_86400_seconds_from_original_admission", facts["deadline_86400_seconds_from_original_admission"])
        context.check("no_local_3600_second_clamp", facts["no_local_3600_second_clamp"])
        context.check("expiry_blocks_start_before_fence_release", facts["expiry_blocks_start_before_fence_release"])
        context.check("owner_sees_expiry_fence_pending", facts["owner_sees_expiry_fence_pending"])

    def _execute_BPC_SC_017(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-017")

    def _verify_BPC_SC_017(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-017")
        context.check("cancel_start_order_exact", facts["cancel_start_order_exact"])
        context.check("original_action_reconciled", facts["original_action_reconciled"])
        context.check("bounded_recovery_clock", facts["bounded_recovery_clock"])
        context.check("unknown_retained", facts["unknown_retained"])
        context.check("refund_once_source_linked", facts["refund_once_source_linked"])
        context.check("own_slots_fenced", facts["own_slots_fenced"])

    def _execute_BPC_SC_018(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-018")

    def _verify_BPC_SC_018(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-018")
        context.check("linked_and_unlinked_report_saved", facts["linked_and_unlinked_report_saved"])
        context.check("safe_auto_context", facts["safe_auto_context"])
        context.check("one_receipt_retry", facts["one_receipt_retry"])
        context.check("no_billing_or_task_effect", facts["no_billing_or_task_effect"])
        context.check("owner_form_image_upload_and_preview", facts["owner_form_image_upload_and_preview"])
        context.check("report_image_links_match_private_storage", facts["report_image_links_match_private_storage"])

    def _execute_BPC_SC_019(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-019")

    def _verify_BPC_SC_019(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-019")
        context.check("four_clients_report_as_principal", facts["four_clients_report_as_principal"])
        context.check("valid_links_or_no_run", facts["valid_links_or_no_run"])
        context.check("original_receipt_after_restart", facts["original_receipt_after_restart"])
        context.check("unchanged_ledger_task_timer", facts["unchanged_ledger_task_timer"])
        context.check("native_agent_optional_image_upload_reference", facts["native_agent_optional_image_upload_reference"])
        context.check("screenshot_links_owned_by_agent", facts["screenshot_links_owned_by_agent"])
        context.check("native_chunk_or_audited_owner_upload_path", facts["native_chunk_or_audited_owner_upload_path"])

    def _execute_BPC_SC_024(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-024")

    def _verify_BPC_SC_024(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-024")
        context.check("decoded_format_size_pixels_validated", facts["decoded_format_size_pixels_validated"])
        context.check("normalized_bytes_metadata_stripped", facts["normalized_bytes_metadata_stripped"])
        context.check("principal_bound_upload_and_report_link", facts["principal_bound_upload_and_report_link"])
        context.check("three_image_cap_atomic", facts["three_image_cap_atomic"])
        context.check("image_retry_recovers_original", facts["image_retry_recovers_original"])
        context.check("private_owner_admin_preview", facts["private_owner_admin_preview"])
        context.check("orphan_cleanup_preserves_committed", facts["orphan_cleanup_preserves_committed"])
        context.check("no_task_billing_refund_effect", facts["no_task_billing_refund_effect"])
        context.check("mcp_chunk_frames_under_64kib", facts["mcp_chunk_frames_under_64kib"])
        context.check("output_and_aggregate_upload_quotas_enforced", facts["output_and_aggregate_upload_quotas_enforced"])

    def _execute_BPC_SC_020(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-020")

    def _verify_BPC_SC_020(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-020")
        context.check("list_filters_match_db", facts["list_filters_match_db"])
        context.check("safe_detail_text", facts["safe_detail_text"])
        context.check("status_audit_revision", facts["status_audit_revision"])
        context.check("own_owner_projection", facts["own_owner_projection"])
        context.check("admin_and_own_owner_image_preview_hash_match", facts["admin_and_own_owner_image_preview_hash_match"])

    def _execute_BPC_SC_021(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-021")

    def _verify_BPC_SC_021(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-021")
        context.check("pause_denies_new_start", facts["pause_denies_new_start"])
        context.check("healthy_reads_reports_available", facts["healthy_reads_reports_available"])
        context.check("persistent_state_same", facts["persistent_state_same"])
        context.check("readiness_fails_closed", facts["readiness_fails_closed"])
        context.check("resources_reconciled", facts["resources_reconciled"])

    def _execute_BPC_SC_022(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-022")

    def _verify_BPC_SC_022(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-022")
        context.check("consistent_checkpoint_verified", facts["consistent_checkpoint_verified"])
        context.check("code_ledger_reports_results_equal", facts["code_ledger_reports_results_equal"])
        context.check("hashes_and_original_ids_match", facts["hashes_and_original_ids_match"])
        context.check("safe_retry", facts["safe_retry"])
        context.check("no_external_resubmission", facts["no_external_resubmission"])
        context.check("rpo_rto_disclosed", facts["rpo_rto_disclosed"])
        context.check("restored_screenshot_bytes_and_hashes_match", facts["restored_screenshot_bytes_and_hashes_match"])
        context.check("expired_reports_checked_against_deletion_receipts", facts["expired_reports_checked_against_deletion_receipts"])

    def _execute_BPC_SC_023(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-023")

    def _verify_BPC_SC_023(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-023")
        context.check("all_mandatory_observations_complete", facts["all_mandatory_observations_complete"])
        context.check("real_client_model_matrix", facts["real_client_model_matrix"])
        context.check("source_hash_stable", facts["source_hash_stable"])
        context.check("old_mvp_states_unchanged", facts["old_mvp_states_unchanged"])
        context.check("deduplicated_owner_usage", facts["deduplicated_owner_usage"])
        context.check("bonus_not_revenue", facts["bonus_not_revenue"])

    def _execute_BPC_SC_025(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-025")

    def _verify_BPC_SC_025(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-025")
        context.check("anonymous_public_summary", facts["anonymous_public_summary"])
        context.check("marker_matches_original_event", facts["marker_matches_original_event"])
        context.check("coherent_best_overall_and_tiers", facts["coherent_best_overall_and_tiers"])
        context.check("no_private_payload_leak", facts["no_private_payload_leak"])
        context.check("safe_cache_rebuild", facts["safe_cache_rebuild"])

    def _execute_BPC_SC_026(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "BPC-SC-026")

    def _verify_BPC_SC_026(self, context: ScenarioContext) -> None:
        facts = self._verified_facts(context, "BPC-SC-026")
        context.check("retention_from_beta_end", facts["retention_from_beta_end"])
        context.check("access_denied_at_expiry", facts["access_denied_at_expiry"])
        context.check("content_and_images_purged", facts["content_and_images_purged"])
        context.check("tombstones_retained", facts["tombstones_retained"])
        context.check("no_restore_resurrection", facts["no_restore_resurrection"])
        context.check("ledger_grades_unchanged", facts["ledger_grades_unchanged"])



def _derive_raw_boundary_facts(
    scenario_id: str, artifacts: dict[str, dict[str, Any]]
) -> dict[str, bool] | None:
    """Replay only raw evidence with a domain-specific verifier; producer booleans are not proof."""

    runtime = artifacts.get("runtime-evidence.json")
    if not isinstance(runtime, dict):
        return None
    contract_row = _load_contract_sources()[1]["protected_scenarios"][scenario_id]
    if runtime.get("boundaryDetail") != contract_row["boundary_detail"]:
        return None
    if runtime.get("localBoundary") is not None or runtime.get("testedBoundary") is not None:
        return None
    if scenario_id in {"BPC-SC-018", "BPC-SC-019", "BPC-SC-020", "BPC-SC-024", "BPC-SC-026"}:
        from .beta_poc_report_verifier import derive_observations

        return derive_observations(scenario_id, runtime)
    return None


def register(registry: ScenarioRegistry) -> None:
    proposal, contract, _ = _load_contract_sources()
    for scenario_id in SCENARIO_IDS:
        registry.register(
            scenario_id,
            BetaPocEvidenceCase(
                scenario_id,
                proposal["protected_scenarios"][scenario_id],
                contract["protected_scenarios"][scenario_id],
            ),
            adapter_profile=proposal["protected_scenarios"][scenario_id]["adapter"],
        )
