"""Verifier for durable OID browser/API/PostgreSQL acceptance artifacts.

This adapter never performs application mutations. The Node acceptance runner owns those
actions; BDD only replays the redacted, hash-checked observations it produced.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry
from tests.bdd.adapters.oid_evidence_verifier import derive_evidence

ADAPTER_PROFILES = frozenset(
    {
        "owner_identity_http_crypto_adapter",
        "owner_identity_browser_http_adapter",
        "owner_actual_provider_wallet_adapter",
    }
)

SCENARIO_IDS = tuple(f"OID-SC-{number:03d}" for number in range(1, 13))
EVIDENCE_ROOT = Path(__file__).resolve().parents[3] / "artifacts" / "runs" / "acceptance"
SECRET_KEY = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|"
    r"invitationcode|invitationsecret|privatekey|mnemonic|seedphrase|authorization|"
    r"databaseurl|rpcurl|oauthcode|oauthstate|rawsignature|signaturevalue)$",
    re.IGNORECASE,
)
SECRET_TEXT = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+",
    re.IGNORECASE,
)


def _assert_secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY.fullmatch(normalized):
                raise AssertionError(f"credential-bearing evidence key at {path}.{key}")
            _assert_secret_free(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_secret_free(item, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_TEXT.search(value):
        raise AssertionError(f"unredacted credential-like text at {path}")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _latest_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        pytest.skip(f"BLOCKED: no durable acceptance run exists for {scenario_id}")
    index = _read_json(index_path)
    if index.get("schemaVersion") != "owner-identity-evidence-index/v1":
        raise AssertionError(f"{scenario_id} evidence index schema is invalid")
    if index.get("scenarioId") != scenario_id:
        raise AssertionError(f"{scenario_id} evidence index identifies another scenario")
    run_id = index.get("latestRunId")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise AssertionError(f"{scenario_id} evidence index has an invalid latest run ID")
    if run_id not in index.get("runs", []):
        raise AssertionError(f"{scenario_id} evidence index does not inventory its latest run")
    run_root = (scenario_root / "runs" / run_id).resolve()
    if scenario_root.resolve() not in run_root.parents:
        raise AssertionError(f"{scenario_id} evidence run escapes its directory")
    manifest = _read_json(run_root / "manifest.json")
    _assert_secret_free(manifest, "manifest.json")
    if manifest.get("schemaVersion") != "owner-identity-acceptance/v1":
        raise AssertionError(f"{scenario_id} evidence manifest schema is invalid")
    if manifest.get("scenarioId") != scenario_id or manifest.get("runId") != run_id:
        raise AssertionError(f"{scenario_id} run identity is inconsistent")
    if manifest.get("status") not in {"passed", "blocked", "failed"}:
        raise AssertionError(f"{scenario_id} has an invalid evidence status")
    artifacts: dict[str, Any] = {}
    inventory = manifest.get("artifacts")
    if not isinstance(inventory, list):
        raise AssertionError(f"{scenario_id} artifact inventory is missing")
    for entry in inventory:
        relative = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(relative, str) or not re.fullmatch(r"[a-z][a-z0-9-]*\.json", relative):
            raise AssertionError(f"{scenario_id} contains an unsafe artifact path")
        artifact_path = (run_root / relative).resolve()
        if run_root not in artifact_path.parents:
            raise AssertionError(f"{scenario_id} artifact path escapes its run")
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
            raise AssertionError(f"{scenario_id} artifact hash mismatch for {relative}")
        payload = json.loads(content.decode("utf-8"))
        _assert_secret_free(payload, relative)
        artifacts[relative] = payload
    return manifest, artifacts


class OwnerIdentityEvidenceCase:
    def __init__(self) -> None:
        self._manifest: dict[str, Any] | None = None
        self._artifacts: dict[str, Any] = {}

    def setup(self, context: ScenarioContext) -> None:
        context.state["evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        scenario_id = context.scenario_id
        method = getattr(self, "_execute_" + scenario_id.replace("-", "_"))
        method(context)

    def _execute_evidence(self, context: ScenarioContext, scenario_id: str) -> None:
        manifest, artifacts = _latest_run(scenario_id)
        context.state["oid_evidence_manifest"] = manifest
        context.state["oid_evidence_artifacts"] = artifacts
        derived_observations, derived_negatives = derive_evidence(scenario_id, manifest, artifacts)
        if manifest["status"] == "blocked":
            reason = manifest.get("blockedReasonCode", "acceptance_boundary_unavailable")
            pytest.skip(f"BLOCKED: {scenario_id} remains {reason}")
        if manifest["status"] == "failed":
            raise AssertionError(f"{scenario_id} latest real acceptance run failed")
        observations = manifest.get("observations", {})
        negatives = manifest.get("negativeVariants", {})
        if not isinstance(observations, dict) or not isinstance(negatives, dict):
            raise AssertionError(f"{scenario_id} named observation inventory is missing")
        if any(item.get("status") != "observed" for item in observations.values()):
            raise AssertionError(f"{scenario_id} cannot pass with unobserved required evidence")
        if any(item.get("status") != "observed" for item in negatives.values()):
            raise AssertionError(f"{scenario_id} cannot pass with untested negative variants")
        if manifest["status"] == "passed" and (
            not all(derived_observations.get(name) is True for name in observations)
            or not all(derived_negatives.get(name) is True for name in negatives)
        ):
            raise AssertionError(f"{scenario_id} passed flag does not follow from raw artifacts")
        database = artifacts.get("database.json")
        provenance = artifacts.get("provenance.json")
        if not isinstance(database, dict) or database.get("observer", {}).get("role") != "oid_observer":
            raise AssertionError(f"{scenario_id} lacks independent read-only database evidence")
        if database.get("observer", {}).get("transaction_read_only") != "on":
            raise AssertionError(f"{scenario_id} observer transaction was not read-only")
        if not isinstance(provenance, dict):
            raise AssertionError(f"{scenario_id} lacks runtime provenance")
        context.outcome = {
            "manifest": manifest,
            "observations": observations,
            "negativeVariants": negatives,
        }
        context.state["oid_observations_derived"] = derived_observations
        context.state["oid_negatives_derived"] = derived_negatives

    def _execute_OID_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-001")

    def _execute_OID_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-002")

    def _execute_OID_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-003")

    def _execute_OID_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-004")

    def _execute_OID_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-005")

    def _execute_OID_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-006")

    def _execute_OID_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-007")

    def _execute_OID_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-008")

    def _execute_OID_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-009")

    def _execute_OID_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-010")

    def _execute_OID_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-011")

    def _execute_OID_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "OID-SC-012")

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        method = getattr(self, "_verify_" + context.scenario_id.replace("-", "_"))
        method(context)

    @staticmethod
    def _is_observed(context: ScenarioContext, name: str) -> bool:
        return context.state.get("oid_observations_derived", {}).get(name) is True

    def _verify_OID_SC_001(self, context: ScenarioContext) -> None:
        context.check("provider_subject_verified", self._is_observed(context, "provider_subject_verified"))
        context.check("callback_state_correlated", self._is_observed(context, "callback_state_correlated"))
        context.check("token_claims_validated", self._is_observed(context, "token_claims_validated"))
        context.check("invalid_exchange_no_session", self._is_observed(context, "invalid_exchange_no_session"))

    def _verify_OID_SC_002(self, context: ScenarioContext) -> None:
        context.check("signature_and_message_verified", self._is_observed(context, "signature_and_message_verified"))
        context.check("nonce_consumed_once", self._is_observed(context, "nonce_consumed_once"))
        context.check("domain_uri_chain_time_checked", self._is_observed(context, "domain_uri_chain_time_checked"))
        context.check("browser_purpose_bound", self._is_observed(context, "browser_purpose_bound"))
        context.check("wallet_email_not_google_proof", self._is_observed(context, "wallet_email_not_google_proof"))

    def _verify_OID_SC_003(self, context: ScenarioContext) -> None:
        context.check("one_redemption_one_owner", self._is_observed(context, "one_redemption_one_owner"))
        context.check("activation_atomic", self._is_observed(context, "activation_atomic"))
        context.check("retry_original_result", self._is_observed(context, "retry_original_result"))
        context.check("competitor_not_admitted", self._is_observed(context, "competitor_not_admitted"))
        context.check("no_automatic_bonus", self._is_observed(context, "no_automatic_bonus"))

    def _verify_OID_SC_004(self, context: ScenarioContext) -> None:
        context.check("invalid_invite_no_activation", self._is_observed(context, "invalid_invite_no_activation"))
        context.check("abandoned_auth_no_redemption", self._is_observed(context, "abandoned_auth_no_redemption"))
        context.check("unadmitted_private_effects_denied", self._is_observed(context, "unadmitted_private_effects_denied"))
        context.check("anonymous_public_reads_available", self._is_observed(context, "anonymous_public_reads_available"))

    def _verify_OID_SC_005(self, context: ScenarioContext) -> None:
        context.check("explicit_link_owner_bound", self._is_observed(context, "explicit_link_owner_bound"))
        context.check("new_identity_proven", self._is_observed(context, "new_identity_proven"))
        context.check("same_owner_and_agents", self._is_observed(context, "same_owner_and_agents"))
        context.check("same_source_balances", self._is_observed(context, "same_source_balances"))
        context.check("no_new_bonus_address_or_withdrawal_proof", self._is_observed(context, "no_new_bonus_address_or_withdrawal_proof"))

    def _verify_OID_SC_006(self, context: ScenarioContext) -> None:
        context.check("explicit_link_required", self._is_observed(context, "explicit_link_required"))
        context.check("existing_identity_conflict_denied", self._is_observed(context, "existing_identity_conflict_denied"))
        context.check("session_operation_binding", self._is_observed(context, "session_operation_binding"))
        context.check("no_asset_or_role_merge", self._is_observed(context, "no_asset_or_role_merge"))

    def _verify_OID_SC_007(self, context: ScenarioContext) -> None:
        context.check("mode_revision_at_commit", self._is_observed(context, "mode_revision_at_commit"))
        context.check("returning_owner_no_new_invite", self._is_observed(context, "returning_owner_no_new_invite"))
        context.check("existing_data_preserved", self._is_observed(context, "existing_data_preserved"))
        context.check("race_one_activation", self._is_observed(context, "race_one_activation"))
        context.check("no_auto_bonus_or_price_change", self._is_observed(context, "no_auto_bonus_or_price_change"))

    def _verify_OID_SC_008(self, context: ScenarioContext) -> None:
        context.check("session_verified_each_request", self._is_observed(context, "session_verified_each_request"))
        context.check("foreign_expired_agent_denied", self._is_observed(context, "foreign_expired_agent_denied"))
        context.check("origin_csrf_checked", self._is_observed(context, "origin_csrf_checked"))
        context.check("logout_session_invalidated", self._is_observed(context, "logout_session_invalidated"))
        context.check("no_implicit_agent_revoke_or_withdrawal_proof", self._is_observed(context, "no_implicit_agent_revoke_or_withdrawal_proof"))

    def _verify_OID_SC_009(self, context: ScenarioContext) -> None:
        context.check("actual_admin_pages", self._is_observed(context, "actual_admin_pages"))
        context.check("configured_admin_only", self._is_observed(context, "configured_admin_only"))
        context.check("invitation_verifier_not_plaintext_history", self._is_observed(context, "invitation_verifier_not_plaintext_history"))
        context.check("mode_change_audited", self._is_observed(context, "mode_change_audited"))
        context.check("no_first_signup_admin", self._is_observed(context, "no_first_signup_admin"))

    def _verify_OID_SC_010(self, context: ScenarioContext) -> None:
        context.check("unadmitted_domain_gate", self._is_observed(context, "unadmitted_domain_gate"))
        context.check("admitted_shared_principal", self._is_observed(context, "admitted_shared_principal"))
        context.check("no_admission_bonus_grant", self._is_observed(context, "no_admission_bonus_grant"))
        context.check("bonus_only_no_withdraw_setup", self._is_observed(context, "bonus_only_no_withdraw_setup"))
        context.check("funding_requires_confirmation_method", self._is_observed(context, "funding_requires_confirmation_method"))

    def _verify_OID_SC_011(self, context: ScenarioContext) -> None:
        context.check("actual_auth_admission_link_pages", self._is_observed(context, "actual_auth_admission_link_pages"))
        context.check("real_server_verification", self._is_observed(context, "real_server_verification"))
        context.check("failed_flow_no_fake_success", self._is_observed(context, "failed_flow_no_fake_success"))
        context.check("safe_secret_free_evidence", self._is_observed(context, "safe_secret_free_evidence"))
        context.check("local_provider_scope_label", self._is_observed(context, "local_provider_scope_label"))

    def _verify_OID_SC_012(self, context: ScenarioContext) -> None:
        context.check("actual_google_login", self._is_observed(context, "actual_google_login"))
        context.check("actual_wallet_edition_and_signature", self._is_observed(context, "actual_wallet_edition_and_signature"))
        context.check("actual_invitation_activation", self._is_observed(context, "actual_invitation_activation"))
        context.check("linked_return_same_owner", self._is_observed(context, "linked_return_same_owner"))
        context.check("no_payment_operation", self._is_observed(context, "no_payment_operation"))
        context.check("external_gate_provenance", self._is_observed(context, "external_gate_provenance"))


def register(registry: ScenarioRegistry) -> None:
    case = OwnerIdentityEvidenceCase()
    profile_by_scenario = {
        "OID-SC-001": "owner_identity_http_crypto_adapter",
        "OID-SC-002": "owner_identity_http_crypto_adapter",
        "OID-SC-003": "owner_identity_http_crypto_adapter",
        "OID-SC-004": "owner_identity_http_crypto_adapter",
        "OID-SC-005": "owner_identity_http_crypto_adapter",
        "OID-SC-006": "owner_identity_http_crypto_adapter",
        "OID-SC-007": "owner_identity_http_crypto_adapter",
        "OID-SC-008": "owner_identity_http_crypto_adapter",
        "OID-SC-009": "owner_identity_browser_http_adapter",
        "OID-SC-010": "owner_identity_http_crypto_adapter",
        "OID-SC-011": "owner_identity_browser_http_adapter",
        "OID-SC-012": "owner_actual_provider_wallet_adapter",
    }
    if set(profile_by_scenario) != set(SCENARIO_IDS):
        raise ValueError("OID scenario adapter inventory is inconsistent")
    for scenario_id in SCENARIO_IDS:
        registry.register(scenario_id, case, adapter_profile=profile_by_scenario[scenario_id])
