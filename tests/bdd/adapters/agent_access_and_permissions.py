"""Evidence consumer for the approved active AAP delta.

The browser runner owns mutations and writes immutable, secret-safe captures.
This adapter only verifies those artifacts and recomputes the partial card facts
from browser/API captures plus independent read-only PostgreSQL rows. A blocked
domain or client boundary remains blocked even when those setup facts exist.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

from .registry import ScenarioContext, ScenarioRegistry


CHANGE_NAME = "agent-access-and-permissions"
SCENARIO_IDS = tuple(f"AAP-SC-{number:03d}" for number in range(1, 17))
PARTIAL_CARD_SCENARIOS = frozenset({"AAP-SC-001", "AAP-SC-006", "AAP-SC-014"})
ADAPTER_PROFILES = frozenset(
    {
        "agent_access_http_mcp_adapter",
        "agent_access_browser_mcp_adapter",
        "agent_actual_clients_adapter",
    }
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY_ROOT / "artifacts" / "runs" / "acceptance"
CONTRACT_PATH = (
    REPOSITORY_ROOT / "tests" / "bdd" / "changes" / CHANGE_NAME / "harness-contracts.json"
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARTIFACT_RE = re.compile(r"^[a-z][a-z0-9-]*\.json$")
SECRET_KEY_RE = re.compile(
    r"^(?:access(?:token)?|accesstoken|authtoken|bearer|cookie|cookies|password|"
    r"secret|clientsecret|manualtoken|tokenvalue|authorization|privatekey|"
    r"mnemonic|seedphrase|rawsignature|signature|walletmaterial|databaseurl|"
    r"oauthcode|oauthstate)$",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+",
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
        raise AssertionError(f"unredacted credential-like text at {path}")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"AAP evidence object expected at {path.name}")
    _assert_secret_free(payload, path.name)
    return payload


def _load_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_json(index_path)
    if (
        index.get("schemaVersion") != "agent-access-evidence-index/v1"
        or index.get("scenarioId") != scenario_id
        or index.get("status") != "blocked"
    ):
        raise AssertionError(f"{scenario_id} evidence index identity or schema is invalid")
    run_id = index.get("latestRunId")
    if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id):
        raise AssertionError(f"{scenario_id} evidence index has an invalid latest run ID")
    if not isinstance(index.get("runs"), list) or run_id not in index["runs"]:
        raise AssertionError(f"{scenario_id} evidence index does not inventory its latest run")
    run_root = (scenario_root / "runs" / run_id).resolve(strict=True)
    if scenario_root.resolve(strict=True) not in run_root.parents:
        raise AssertionError(f"{scenario_id} evidence run escapes its scenario directory")
    manifest = _read_json(run_root / "manifest.json")
    if (
        manifest.get("schemaVersion") != "agent-access-acceptance/v1"
        or manifest.get("scenarioId") != scenario_id
        or manifest.get("runId") != run_id
        or manifest.get("specProfile") != "active-delta"
        or manifest.get("status") not in {"blocked", "failed", "passed"}
    ):
        raise AssertionError(f"{scenario_id} run manifest identity or schema is invalid")

    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    contract_row = contract.get("protected_scenarios", {}).get(scenario_id)
    if not isinstance(contract_row, dict):
        raise AssertionError(f"{scenario_id} is missing from its active runtime contract")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise AssertionError(f"{scenario_id} run has no artifact inventory")
    if {item.get("path") for item in artifacts if isinstance(item, dict)} != {
        "browser.json",
        "database.json",
        "provenance.json",
    } or len(artifacts) != 3:
        raise AssertionError(f"{scenario_id} must inventory exactly its three safe artifacts")

    loaded: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        relative = item.get("path")
        digest = item.get("sha256")
        if not isinstance(relative, str) or not SAFE_ARTIFACT_RE.fullmatch(relative):
            raise AssertionError(f"{scenario_id} has an unsafe artifact path")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise AssertionError(f"{scenario_id} has an invalid artifact digest")
        if item.get("contentType") != "application/json" or not isinstance(item.get("boundary"), str):
            raise AssertionError(f"{scenario_id} artifact metadata is invalid")
        artifact_path = (run_root / relative).resolve(strict=True)
        if run_root not in artifact_path.parents:
            raise AssertionError(f"{scenario_id} artifact escapes its immutable run")
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise AssertionError(f"{scenario_id} artifact hash mismatch for {relative}")
        payload = json.loads(content.decode("utf-8"))
        if not isinstance(payload, dict):
            raise AssertionError(f"{scenario_id} artifact {relative} is not an object")
        _assert_secret_free(payload, relative)
        loaded[relative] = payload

    provenance = loaded["provenance.json"]
    if provenance.get("contractSha256") != hashlib.sha256(contract_bytes).hexdigest():
        raise AssertionError(f"{scenario_id} evidence was captured against another runtime contract")
    database = loaded["database.json"]
    observer = database.get("observer")
    if not isinstance(observer, dict) or observer.get("role") != "oid_observer":
        raise AssertionError(f"{scenario_id} lacks independent oid_observer evidence")
    if observer.get("transaction_read_only") != "on":
        raise AssertionError(f"{scenario_id} observer transaction was not read-only")

    expected_observations = set(contract_row["required_observations"])
    expected_negatives = set(contract_row["negative_variants"])
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != expected_observations:
        raise AssertionError(f"{scenario_id} observation inventory drifted")
    if not isinstance(negatives, dict) or set(negatives) != expected_negatives:
        raise AssertionError(f"{scenario_id} negative-variant inventory drifted")
    if manifest.get("status") == "blocked":
        if not manifest.get("blockedReasonCode"):
            raise AssertionError(f"{scenario_id} blocked evidence needs a reason code")
        if manifest.get("observationStatus") != "not_run" or manifest.get("negativeVariantStatus") != "not_run":
            raise AssertionError(f"{scenario_id} blocked capture must retain not_run aggregate statuses")
        for collection in (observations, negatives):
            if any(
                not isinstance(item, dict)
                or item.get("status") != "not_run"
                or not isinstance(item.get("reasonCode"), str)
                or not item["reasonCode"]
                for item in collection.values()
            ):
                raise AssertionError(f"{scenario_id} blocked capture must keep every claim at not_run")
    return manifest, loaded


def _all_false(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    return all(row.get(key) is False for key in ("training", "ranked", "forum_messages", "custom_topics"))


def _derive_partial_facts(scenario_id: str, artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    """Derive only owner-card/policy setup facts; never infer full domain acceptance."""

    if scenario_id not in PARTIAL_CARD_SCENARIOS:
        return {}
    browser = artifacts["browser.json"]
    database = artifacts["database.json"]
    capture = browser.get("capture")
    if not isinstance(capture, dict):
        return {"owner_card_persisted": False, "initial_policy_all_false": False, "policy_edit_committed": False}
    actions = capture.get("actions", [])
    requests = capture.get("requests", [])
    responses = capture.get("responses", [])
    operation_ids = browser.get("operationIds", [])
    final = database.get("final", {})
    initial = database.get("initial", {})
    if not all(isinstance(value, list) for value in (actions, requests, responses, operation_ids)):
        return {"owner_card_persisted": False, "initial_policy_all_false": False, "policy_edit_committed": False}
    agent_id = browser.get("agentId")
    owner_id = browser.get("ownerId")
    create_operation = operation_ids[0] if operation_ids else None
    policy_operation = operation_ids[2] if len(operation_ids) > 2 else None
    create_clicked = any(item.get("action") == "click" and item.get("selector") == "agent-create" for item in actions if isinstance(item, dict))
    create_requested = any(
        item.get("method") == "POST" and item.get("path") == "/api/owner/agents" and item.get("operationId") == create_operation
        for item in requests if isinstance(item, dict)
    )
    create_succeeded = any(
        item.get("method") == "POST" and item.get("path") == "/api/owner/agents" and item.get("status") == 201
        for item in responses if isinstance(item, dict)
    )
    final_agents = final.get("agents", []) if isinstance(final, dict) else []
    final_policies = final.get("policies", []) if isinstance(final, dict) else []
    final_operations = final.get("operations", []) if isinstance(final, dict) else []
    final_audits = final.get("audits", []) if isinstance(final, dict) else []
    initial_policies = initial.get("policies", []) if isinstance(initial, dict) else []
    agent = next((row for row in final_agents if isinstance(row, dict) and row.get("id") == agent_id and row.get("owner_id") == owner_id), None)
    create_operation_row = any(isinstance(row, dict) and row.get("operation_id") == create_operation and row.get("agent_id") == agent_id for row in final_operations)
    create_audit = any(
        isinstance(row, dict) and row.get("operation_id") == create_operation
        and row.get("event_type") == "agent.created" and row.get("actor_owner_id") == owner_id
        for row in final_audits
    )
    card_persisted = bool(create_clicked and create_requested and create_succeeded and agent and create_operation_row and create_audit)
    initial_defaults = bool(initial_policies and _all_false(initial_policies[0]))
    policy_clicked = any(item.get("action") == "click" and item.get("selector") == "agent-permissions-save" for item in actions if isinstance(item, dict))
    policy_requested = any(
        isinstance(item, dict) and item.get("operationId") == policy_operation
        and item.get("method") == "PUT" and item.get("path") == f"/api/owner/agents/{agent_id}/permissions"
        for item in requests
    )
    policy = next((row for row in final_policies if isinstance(row, dict) and row.get("agent_id") == agent_id), None)
    policy_operation_row = any(isinstance(row, dict) and row.get("operation_id") == policy_operation and row.get("agent_id") == agent_id for row in final_operations)
    policy_audit = any(
        isinstance(row, dict) and row.get("operation_id") == policy_operation
        and row.get("event_type") == "agent.permissions_updated" and row.get("actor_owner_id") == owner_id
        for row in final_audits
    )
    policy_committed = bool(policy_clicked and policy_requested and policy and policy_operation_row and policy_audit)
    created = browser.get("created", {})
    edited = browser.get("edited", {})
    policy_result = browser.get("policy", {})
    negatives = browser.get("protocolNegatives", {})
    metadata = agent.get("client_metadata") if isinstance(agent, dict) else None
    declared_metadata = bool(
        isinstance(created, dict)
        and created.get("metadataTrust") == "owner-declared-unverified"
        and isinstance(metadata, dict)
        and metadata.get("clientName")
        and metadata.get("modelName")
    )
    edited_persisted = bool(
        isinstance(edited, dict)
        and isinstance(agent, dict)
        and agent.get("revision") == edited.get("revision")
        and agent.get("declared_version") == edited.get("declaredVersion")
        and any(
            isinstance(row, dict) and row.get("operation_id") == (operation_ids[1] if len(operation_ids) > 1 else None)
            and row.get("event_type") == "agent.profile_updated" and row.get("actor_owner_id") == owner_id
            for row in final_audits
        )
    )
    policy_matches_response = bool(
        isinstance(policy_result, dict)
        and isinstance(policy, dict)
        and policy.get("policy_revision") == policy_result.get("policyRevision")
        and policy_result.get("permissions") == {
            "training": policy.get("training"),
            "ranked": policy.get("ranked"),
            "forumMessages": policy.get("forum_messages"),
            "customTopics": policy.get("custom_topics"),
        }
    )
    foreign_denials = bool(
        isinstance(negatives, dict)
        and negatives.get("foreignReadStatus") == 404
        and negatives.get("foreignEditStatus") == 404
        and edited_persisted
        and policy_matches_response
    )
    caller_visibility_denied = bool(
        isinstance(negatives, dict)
        and negatives.get("forgedPublicationStatus") == 400
        and edited_persisted
        and policy_matches_response
        and isinstance(agent, dict)
        and "is_public" not in agent
    )
    return {
        "owner_card_persisted": card_persisted,
        "declared_metadata_labelled": declared_metadata,
        "foreign_owner_denied": foreign_denials,
        "caller_visibility_change_cannot_publish": caller_visibility_denied,
        "profile_edit_correlated_to_postgres": edited_persisted,
        "initial_policy_all_false": initial_defaults,
        "policy_edit_committed": bool(policy_committed and policy_matches_response),
    }


class AgentAccessEvidenceCase:
    def setup(self, context: ScenarioContext) -> None:
        context.state["aap_evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        method = getattr(self, "_execute_" + context.scenario_id.replace("-", "_"), None)
        if not callable(method):
            raise AssertionError(f"no AAP executor for {context.scenario_id}")
        method(context)

    def _execute_evidence(self, context: ScenarioContext, scenario_id: str) -> None:
        loaded = _load_run(scenario_id)
        if loaded is None:
            pytest.skip(f"BLOCKED: no immutable AAP acceptance run exists for {scenario_id}")
        manifest, artifacts = loaded
        derived = _derive_partial_facts(scenario_id, artifacts)
        context.state["aap_manifest"] = manifest
        context.state["aap_artifacts"] = artifacts
        context.state["aap_partial_facts"] = derived
        context.state["aap_derived_observations"] = derived
        if manifest["status"] == "failed":
            raise AssertionError(f"{scenario_id} latest AAP browser/database run failed")
        if manifest["status"] == "passed":
            raise AssertionError(
                f"{scenario_id} cannot pass through the card-only adapter; its full approved boundary is not verified here"
            )
        pytest.skip(f"BLOCKED: {scenario_id} remains {manifest['blockedReasonCode']}; card facts are partial only")

    def _execute_AAP_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-001")

    def _execute_AAP_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-002")

    def _execute_AAP_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-003")

    def _execute_AAP_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-004")

    def _execute_AAP_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-005")

    def _execute_AAP_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-006")

    def _execute_AAP_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-007")

    def _execute_AAP_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-008")

    def _execute_AAP_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-009")

    def _execute_AAP_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-010")

    def _execute_AAP_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-011")

    def _execute_AAP_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-012")

    def _execute_AAP_SC_013(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-013")

    def _execute_AAP_SC_014(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-014")

    def _execute_AAP_SC_015(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-015")

    def _execute_AAP_SC_016(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-016")

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        method = getattr(self, "_verify_" + context.scenario_id.replace("-", "_"), None)
        if not callable(method):
            raise AssertionError(f"no AAP verifier for {context.scenario_id}")
        method(context)

    def _verify_AAP_SC_001(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("owner_card_persisted", facts.get("owner_card_persisted") is True)
        context.check("foreign_owner_denied", facts.get("foreign_owner_denied") is True)
        context.check("agent_owner_mutation_denied", facts.get("agent_owner_mutation_denied") is True)
        context.check("declared_metadata_labelled", facts.get("declared_metadata_labelled") is True)
        context.check("run_snapshot_unchanged", facts.get("run_snapshot_unchanged") is True)
        context.check("new_card_no_public_marker", facts.get("new_card_no_public_marker") is True)
        context.check("caller_visibility_change_cannot_publish", facts.get("caller_visibility_change_cannot_publish") is True)

    def _verify_AAP_SC_002(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("consent_owner_agent_bound", facts.get("consent_owner_agent_bound") is True)
        context.check("effective_scopes_displayed", facts.get("effective_scopes_displayed") is True)
        context.check("approved_grant_identity", facts.get("approved_grant_identity") is True)
        context.check("denied_consent_no_grant", facts.get("denied_consent_no_grant") is True)

    def _verify_AAP_SC_003(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("binding_validation", facts.get("binding_validation") is True)
        context.check("code_consumed_once", facts.get("code_consumed_once") is True)
        context.check("invalid_exchange_denied", facts.get("invalid_exchange_denied") is True)
        context.check("no_scope_escalation", facts.get("no_scope_escalation") is True)

    def _verify_AAP_SC_004(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("owner_issuance", facts.get("owner_issuance") is True)
        context.check("token_agent_binding", facts.get("token_agent_binding") is True)
        context.check("header_authentication", facts.get("header_authentication") is True)
        context.check("unauthorized_issuance_denied", facts.get("unauthorized_issuance_denied") is True)

    def _verify_AAP_SC_005(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("show_once_response", facts.get("show_once_response") is True)
        context.check("stored_verifier_not_plaintext", facts.get("stored_verifier_not_plaintext") is True)
        context.check("safe_replacement_identity", facts.get("safe_replacement_identity") is True)
        context.check("old_credential_denied", facts.get("old_credential_denied") is True)
        context.check("secret_absent_from_audit", facts.get("secret_absent_from_audit") is True)

    def _verify_AAP_SC_006(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("four_action_permissions_independent", facts.get("four_action_permissions_independent") is True)
        context.check("topic_first_post_included", facts.get("topic_first_post_included") is True)
        context.check("standalone_message_permission_checked", facts.get("standalone_message_permission_checked") is True)
        context.check("denied_actions_no_effect", facts.get("denied_actions_no_effect") is True)
        context.check("omitted_owner_selections_default_all_false", facts.get("omitted_owner_selections_default_all_false") is True)
        context.check("free_preflight_without_action_flags", facts.get("free_preflight_without_action_flags") is True)
        context.check("explicit_owner_selection_required", facts.get("explicit_owner_selection_required") is True)

    def _verify_AAP_SC_007(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("current_revision_loaded", facts.get("current_revision_loaded") is True)
        context.check("fixed_credential_identity_resource_role", facts.get("fixed_credential_identity_resource_role") is True)
        context.check("owner_increase_works_without_reconnect", facts.get("owner_increase_works_without_reconnect") is True)
        context.check("same_oauth_and_manual_credentials_used", facts.get("same_oauth_and_manual_credentials_used") is True)
        context.check("disabled_and_foreign_authority_denied", facts.get("disabled_and_foreign_authority_denied") is True)
        context.check("agent_cannot_change_permissions", facts.get("agent_cannot_change_permissions") is True)
        context.check("re_enable_does_not_reopen_cancelled_runs", facts.get("re_enable_does_not_reopen_cancelled_runs") is True)

    def _verify_AAP_SC_008(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("shared_owner_funds", facts.get("shared_owner_funds") is True)
        context.check("same_agent_utc_caps", facts.get("same_agent_utc_caps") is True)
        context.check("bonus_first_sources", facts.get("bonus_first_sources") is True)
        context.check("separate_cash_permission", facts.get("separate_cash_permission") is True)
        context.check("no_duplicate_or_partial_charge", facts.get("no_duplicate_or_partial_charge") is True)

    def _verify_AAP_SC_009(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("agent_withdrawal_denied", facts.get("agent_withdrawal_denied") is True)
        context.check("recovery_authority_denied", facts.get("recovery_authority_denied") is True)
        context.check("owner_controls_denied", facts.get("owner_controls_denied") is True)
        context.check("human_session_post_denied", facts.get("human_session_post_denied") is True)
        context.check("no_signing_intent", facts.get("no_signing_intent") is True)

    def _verify_AAP_SC_010(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("revocation_admission_fence", facts.get("revocation_admission_fence") is True)
        context.check("queue_release_once", facts.get("queue_release_once") is True)
        context.check("started_cancel_no_voluntary_refund", facts.get("started_cancel_no_voluntary_refund") is True)
        context.check("mode_scope_preserved", facts.get("mode_scope_preserved") is True)
        context.check("other_agents_unchanged", facts.get("other_agents_unchanged") is True)
        context.check("regrant_no_reopen", facts.get("regrant_no_reopen") is True)
        context.check("re_enable_mode_no_reopen", facts.get("re_enable_mode_no_reopen") is True)

    def _verify_AAP_SC_011(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("expiry_denies_calls", facts.get("expiry_denies_calls") is True)
        context.check("no_disconnect_revoke_event", facts.get("no_disconnect_revoke_event") is True)
        context.check("same_run_deadline", facts.get("same_run_deadline") is True)
        context.check("refresh_scope_preserved", facts.get("refresh_scope_preserved") is True)
        context.check("revoked_refresh_denied", facts.get("revoked_refresh_denied") is True)

    def _verify_AAP_SC_012(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("same_operation_across_transports", facts.get("same_operation_across_transports") is True)
        context.check("original_receipt_recovered", facts.get("original_receipt_recovered") is True)
        context.check("conflict_rejected", facts.get("conflict_rejected") is True)
        context.check("foreign_reuse_denied", facts.get("foreign_reuse_denied") is True)

    def _verify_AAP_SC_013(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("pinned_profile_validation", facts.get("pinned_profile_validation") is True)
        context.check("resource_token_rejection", facts.get("resource_token_rejection") is True)
        context.check("origin_policy", facts.get("origin_policy") is True)
        context.check("metadata_fetch_constrained", facts.get("metadata_fetch_constrained") is True)
        context.check("no_private_projection", facts.get("no_private_projection") is True)

    def _verify_AAP_SC_014(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("actual_owner_pages", facts.get("actual_owner_pages") is True)
        context.check("four_flags_and_separate_limits", facts.get("four_flags_and_separate_limits") is True)
        context.check("safe_token_display", facts.get("safe_token_display") is True)
        context.check("changes_affect_admission", facts.get("changes_affect_admission") is True)
        context.check("foreign_control_denied", facts.get("foreign_control_denied") is True)

    def _verify_AAP_SC_015(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("discovery_and_browser_flow", facts.get("discovery_and_browser_flow") is True)
        context.check("resource_bound_access", facts.get("resource_bound_access") is True)
        context.check("tool_catalog_and_preflight", facts.get("tool_catalog_and_preflight") is True)
        context.check("actual_operation_receipt", facts.get("actual_operation_receipt") is True)
        context.check("revoked_call_denied", facts.get("revoked_call_denied") is True)
        context.check("local_scope_label", facts.get("local_scope_label") is True)

    def _verify_AAP_SC_016(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("four_selected_editions_pinned", facts.get("four_selected_editions_pinned") is True)
        context.check("no_platform_connector_install", facts.get("no_platform_connector_install") is True)
        context.check("chosen_auth_route_recorded", facts.get("chosen_auth_route_recorded") is True)
        context.check("actual_preflight_and_operation", facts.get("actual_preflight_and_operation") is True)
        context.check("post_revoke_denial_per_client", facts.get("post_revoke_denial_per_client") is True)
        context.check("unsupported_alternatives_disclosed", facts.get("unsupported_alternatives_disclosed") is True)


def _profile_for(scenario_id: str) -> str:
    if scenario_id in {"AAP-SC-002", "AAP-SC-014", "AAP-SC-015"}:
        return "agent_access_browser_mcp_adapter"
    if scenario_id == "AAP-SC-016":
        return "agent_actual_clients_adapter"
    return "agent_access_http_mcp_adapter"


def register(registry: ScenarioRegistry) -> None:
    for scenario_id in SCENARIO_IDS:
        registry.register(scenario_id, AgentAccessEvidenceCase(), adapter_profile=_profile_for(scenario_id))
