"""Replay TBB acceptance evidence without mutating the owner service.

Only TBB-SC-001 and TBB-SC-002 have a runnable browser/API/PostgreSQL boundary in
this slice. All other approved cases stay blocked until their product boundary
exists; this adapter never turns a missing boundary into a pass.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest

from tests.bdd.adapters import ScenarioContext, ScenarioRegistry

CHANGE_NAME = "tester-bonus-billing"
SCENARIO_IDS = tuple(f"TBB-SC-{number:03d}" for number in range(1, 16))
PASSABLE_SCENARIOS = frozenset({"TBB-SC-001", "TBB-SC-002"})
ADAPTER_PROFILES = frozenset({"tester_bonus_http_adapter", "tester_bonus_browser_http_adapter"})
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY_ROOT / "artifacts" / "runs" / "acceptance"
CONTRACT_PATH = REPOSITORY_ROOT / "tests" / "bdd" / "changes" / CHANGE_NAME / "harness-contracts.json"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARTIFACT_RE = re.compile(r"^[a-z][a-z0-9-]*\.json$")
SECRET_KEY_RE = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|"
    r"manualtoken|tokenvalue|authorization|privatekey|mnemonic|seedphrase|rawsignature|"
    r"signature|walletmaterial|databaseurl|rpcurl|oauthcode|oauthstate)$",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+|"
    r"\b(?:aap1|oid1|oat1)_[A-Za-z0-9_-]{32,}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)
EXPECTED_ARTIFACTS = frozenset({"browser.json", "database.json", "provenance.json"})


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


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"Expected a JSON object in {path.name}")
    _assert_secret_free(value, path.name)
    return value


def _read_contract() -> tuple[dict[str, Any], bytes]:
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes.decode("utf-8"))
    rows = contract.get("protected_scenarios") if isinstance(contract, dict) else None
    if not isinstance(rows, dict) or set(rows) != set(SCENARIO_IDS):
        raise AssertionError("Active TBB runtime contract inventory is incomplete")
    return contract, contract_bytes


def _load_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"Unsupported TBB scenario identity: {scenario_id}")
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_object(index_path)
    if (
        index.get("schemaVersion") != "tester-bonus-billing-evidence-index/v1"
        or index.get("scenarioId") != scenario_id
        or index.get("status") not in {"blocked", "failed", "passed"}
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
    manifest = _read_object(run_root / "manifest.json")
    if (
        manifest.get("schemaVersion") != "tester-bonus-billing-acceptance/v1"
        or manifest.get("specProfile") != "active-delta"
        or manifest.get("scenarioId") != scenario_id
        or manifest.get("runId") != run_id
        or manifest.get("status") not in {"blocked", "failed", "passed"}
        or index.get("status") != manifest.get("status")
    ):
        raise AssertionError(f"{scenario_id} run manifest identity or status is invalid")

    contract, contract_bytes = _read_contract()
    contract_row = contract["protected_scenarios"].get(scenario_id)
    inventory = manifest.get("artifacts")
    if not isinstance(inventory, list) or len(inventory) != len(EXPECTED_ARTIFACTS):
        raise AssertionError(f"{scenario_id} must inventory exactly three safe artifacts")
    if {item.get("path") for item in inventory if isinstance(item, dict)} != EXPECTED_ARTIFACTS:
        raise AssertionError(f"{scenario_id} artifact inventory is incomplete or unexpected")

    loaded: dict[str, dict[str, Any]] = {}
    for item in inventory:
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
        raise AssertionError(f"{scenario_id} evidence was captured against another TBB runtime contract")
    required_observations = set(contract_row.get("required_observations", []))
    required_negatives = set(contract_row.get("negative_variants", []))
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != required_observations:
        raise AssertionError(f"{scenario_id} observation inventory drifted")
    if not isinstance(negatives, dict) or set(negatives) != required_negatives:
        raise AssertionError(f"{scenario_id} negative-variant inventory drifted")

    if manifest["status"] == "blocked":
        if not manifest.get("blockedReasonCode"):
            raise AssertionError(f"{scenario_id} blocked evidence needs a machine-readable reason")
        if manifest.get("observationStatus") != "not_run" or manifest.get("negativeVariantStatus") != "not_run":
            raise AssertionError(f"{scenario_id} blocked capture cannot mark aggregate checks complete")
        for collection in (observations, negatives):
            if any(
                not isinstance(item, dict)
                or item.get("status") != "not_run"
                or not isinstance(item.get("reasonCode"), str)
                or not item["reasonCode"]
                for item in collection.values()
            ):
                raise AssertionError(f"{scenario_id} blocked capture must keep every claim not_run")
    elif manifest["status"] == "passed":
        if scenario_id not in PASSABLE_SCENARIOS:
            raise AssertionError(f"{scenario_id} passed without an implemented TBB boundary")
        if manifest.get("observationStatus") != "complete" or manifest.get("negativeVariantStatus") != "complete":
            raise AssertionError(f"{scenario_id} passed without complete observations and negatives")
        for collection in (observations, negatives):
            if any(not isinstance(item, dict) or item.get("status") != "observed" for item in collection.values()):
                raise AssertionError(f"{scenario_id} passed while a named fact was not observed")
        if (
            provenance.get("sourceStableDuringRun") is not True
            or not provenance.get("inputHashesBefore")
            or provenance.get("inputHashesBefore") != provenance.get("inputHashesAfter")
            or "docker" not in str(provenance.get("source", "")).lower()
        ):
            raise AssertionError(f"{scenario_id} cannot pass without stable local Docker source provenance")
        observer = loaded["database.json"].get("observer")
        if not isinstance(observer, dict) or observer.get("role") != "oid_observer" or observer.get("transaction_read_only") != "on":
            raise AssertionError(f"{scenario_id} lacks independent read-only oid_observer PostgreSQL evidence")

    return manifest, loaded


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _denied(value: Any) -> bool:
    status = _dict(value).get("status")
    return status in {401, 403}


def _operation_rows(database: dict[str, Any], operation_id: Any, collection: str) -> list[dict[str, Any]]:
    return [
        row for row in _list(_dict(database.get("after")).get(collection))
        if isinstance(row, dict) and row.get("operation_id") == operation_id
    ]


def _matches_issuance_audit(audit: Any, *, actor_id: Any, owner_id: Any, amount: str, reason: str, expiry: str | None) -> bool:
    row = _dict(audit)
    metadata = _dict(row.get("metadata"))
    return bool(
        row.get("event_type") == "bonus_grant_issued"
        and row.get("actor_owner_id") == actor_id
        and row.get("subject_owner_id") == owner_id
        and metadata.get("amount") == amount
        and metadata.get("reason") == reason
        and metadata.get("expiresAt") == expiry
    )


def derive_sc001_facts(browser: dict[str, Any], database: dict[str, Any]) -> tuple[dict[str, bool], dict[str, bool]]:
    ui = _dict(browser.get("ui"))
    owner = _dict(browser.get("owner"))
    admin = _dict(browser.get("admin"))
    capture = _dict(ui.get("capture"))
    actions = {item.get("selector") for item in _list(capture.get("actions")) if isinstance(item, dict)}
    first = _dict(ui.get("firstGrant"))
    replay = _dict(ui.get("replay"))
    request = _dict(first.get("request"))
    replay_request = _dict(replay.get("request"))
    first_grant = _dict(first.get("grant"))
    changed = _dict(ui.get("changedAmount"))
    unauthorized = _dict(ui.get("unauthorized"))
    invalid = _dict(ui.get("invalid"))
    changed_operation = request.get("operationId")
    grant_id = first_grant.get("id")
    owner_id = owner.get("id")
    actor_id = admin.get("id")
    db_grants = [row for row in _list(_dict(database.get("after")).get("grants")) if isinstance(row, dict)]
    db_grant = next((row for row in db_grants if row.get("id") == grant_id), {})
    entry_rows = _operation_rows(database, changed_operation, "entries")
    op_rows = _operation_rows(database, changed_operation, "operations")
    grant_rows = [row for row in db_grants if row.get("operation_id") == changed_operation]
    audit = _dict(database.get("issuanceAudit"))
    agent_denial = _dict(unauthorized.get("agentDenied"))
    no_effect = database.get("invalidAttemptsNoFinancialEffect") is True
    changed_preserved = database.get("changedRetryPreservedOriginal") is True
    ui_request_seen = (
        "bonus-grant-submit-response-loss" in actions
        and any(
            isinstance(row, dict) and row.get("path") == "/api/admin/bonus-grants"
            and row.get("method") == "POST" and row.get("operationId") == changed_operation
            for row in _list(capture.get("requests"))
        )
    )
    grant_shape = bool(
        grant_id and changed_operation and db_grant
        and db_grant.get("owner_id") == owner_id
        and db_grant.get("issued_by_owner_id") == actor_id
        and db_grant.get("amount_units") == "1250000"
        and db_grant.get("reason") == "Synthetic acceptance grant for TBB-SC-001"
        and db_grant.get("operation_id") == changed_operation
        and db_grant.get("expires_at") is None
    )
    entry_shape = bool(
        len(entry_rows) == 1
        and entry_rows[0].get("entry_type") == "bonus_grant"
        and entry_rows[0].get("source_kind") == "tester_bonus"
        and entry_rows[0].get("bonus_grant_id") == grant_id
        and entry_rows[0].get("actor_owner_id") == actor_id
        and entry_rows[0].get("amount_units") == "1250000"
        and entry_rows[0].get("available_delta_units") == "1250000"
        and entry_rows[0].get("reserved_delta_units") == "0"
        and entry_rows[0].get("expired_delta_units") == "0"
    )
    replay_once = bool(
        replay.get("status") == 200 and replay.get("replayed") is True
        and _dict(replay.get("grant")).get("id") == grant_id
        and replay_request.get("operationId") == changed_operation
        and replay.get("browserResultVisible") is True
    )
    conflict_preserved = bool(
        changed.get("status") == 409 and changed.get("errorCode") == "IDEMPOTENCY_CONFLICT"
        and changed.get("requestOperationId") == changed_operation and changed_preserved
        and len(grant_rows) == 1 and len(op_rows) == 1
    )
    facts = {
        "admin_only_grant": bool(
            admin.get("isAdmin") is True and _denied(unauthorized.get("ownerDenied"))
            and _denied(unauthorized.get("foreignDenied")) and _denied(agent_denial)
            and ui_request_seen and grant_shape and len(grant_rows) == 1
        ),
        "single_grant_after_restart": bool(
            ui.get("apiRestartedBeforeReplay") is True and replay_once and len(grant_rows) == 1
            and len(op_rows) == 1 and len(entry_rows) == 1
        ),
        "actor_reason_terms_preserved": bool(
            grant_shape and entry_shape
            and _matches_issuance_audit(audit, actor_id=actor_id, owner_id=owner_id,
                                        amount="1.250000", reason="Synthetic acceptance grant for TBB-SC-001", expiry=None)
        ),
        "invalid_or_conflicting_grant_no_effect": bool(
            conflict_preserved and _dict(invalid.get("zeroAmount")).get("status") == 400
            and _dict(invalid.get("excessPrecision")).get("status") == 400
            and _dict(invalid.get("pastExpiry")).get("status") == 409 and no_effect
        ),
    }
    negatives = {
        "owner_grant_attempt": bool(_denied(unauthorized.get("ownerDenied")) and no_effect),
        "agent_grant_attempt": bool(
            _denied(agent_denial)
            and agent_denial.get("requestMode") == "synthetic-agent-bearer-without-owner-cookies"
            and no_effect
        ),
        "negative_zero_or_excess_precision": bool(
            _dict(invalid.get("zeroAmount")).get("status") == 400
            and _dict(invalid.get("excessPrecision")).get("status") == 400 and no_effect
        ),
        "past_expiry": bool(
            _dict(invalid.get("pastExpiry")).get("status") == 409
            and _dict(invalid.get("pastExpiry")).get("errorCode") == "EXPIRY_NOT_FUTURE" and no_effect
        ),
        "same_key_changed_amount": conflict_preserved,
        "lost_response_restart": bool(
            ui.get("browserSawInitialResponse") is False and ui.get("apiRestartedBeforeReplay") is True
            and first.get("status") == 200 and replay_once
        ),
    }
    return facts, negatives


def derive_sc002_facts(browser: dict[str, Any], database: dict[str, Any]) -> tuple[dict[str, bool], dict[str, bool]]:
    ui = _dict(browser.get("ui"))
    owner = _dict(browser.get("owner"))
    admin = _dict(browser.get("admin"))
    capture = _dict(ui.get("capture"))
    ui_actions = [item.get("selector") for item in _list(capture.get("actions")) if isinstance(item, dict)]
    ui_requests = [item for item in _list(capture.get("requests")) if isinstance(item, dict)]
    ui_grant_operations = {
        item.get("operationId") for item in ui_requests
        if item.get("path") == "/api/admin/bonus-grants" and item.get("method") == "POST"
    }
    no_expiry = _dict(ui.get("originalNoExpiry"))
    explicit = _dict(ui.get("explicitExpiry"))
    later = _dict(ui.get("laterGrant"))
    ui_explicit_and_later_grants = (
        ui_actions.count("bonus-grant-submit") >= 2
        and explicit.get("operationId") in ui_grant_operations
        and later.get("operationId") in ui_grant_operations
    )
    boundary = _dict(ui.get("expiryBoundary"))
    boundary_outcome = _dict(boundary.get("outcome"))
    edits = [row for row in _list(ui.get("editAttempts")) if isinstance(row, dict)]
    before = _dict(database.get("beforeLaterGrant"))
    after = _dict(database.get("after"))
    db_grants = [row for row in _list(after.get("grants")) if isinstance(row, dict)]
    no_expiry_row = next((row for row in db_grants if row.get("id") == no_expiry.get("id")), {})
    explicit_row = next((row for row in db_grants if row.get("id") == explicit.get("id")), {})
    later_row = next((row for row in db_grants if row.get("id") == later.get("id")), {})
    edit_audits = [row for row in _list(database.get("rejectionAudits")) if isinstance(row, dict)]
    issued_audits = [row for row in _list(database.get("issuanceAudits")) if isinstance(row, dict)]
    before_ids = {no_expiry.get("id"), explicit.get("id")}
    before_rows = [row for row in _list(before.get("grants")) if isinstance(row, dict) and row.get("id") in before_ids]
    after_original_rows = [row for row in db_grants if row.get("id") in before_ids]
    original_terms_unchanged = bool(before_rows and len(before_rows) == 2 and before_rows == after_original_rows)

    def audit_for_edit(edit: dict[str, Any]) -> bool:
        return any(
            row.get("operation_id") == edit.get("requestOperationId")
            and row.get("event_type") == "bonus_grant_rejected"
            and row.get("subject_owner_id") == owner.get("id")
            and _dict(row.get("metadata")).get("grantId") == explicit.get("id")
            and _dict(row.get("metadata")).get("reasonCode") == "IMMUTABLE_GRANT"
            for row in edit_audits
        )

    expiry_audit = any(
        row.get("operation_id") == boundary_outcome.get("requestOperationId")
        and row.get("event_type") == "bonus_grant_rejected"
        and _dict(row.get("metadata")).get("reasonCode") == "EXPIRY_NOT_FUTURE"
        for row in edit_audits
    )
    exact_expiry = explicit.get("expiresAt")
    issuance_by_operation = {row.get("operation_id"): row for row in issued_audits}
    no_expiry_audit = issuance_by_operation.get(no_expiry.get("operationId"))
    explicit_audit = issuance_by_operation.get(explicit.get("operationId"))
    later_audit = issuance_by_operation.get(later.get("operationId"))
    facts = {
        "default_no_expiry": bool(
            no_expiry.get("expiresAt") is None and no_expiry_row.get("expires_at") is None
            and _matches_issuance_audit(no_expiry_audit, actor_id=admin.get("id"), owner_id=owner.get("id"),
                                        amount="1.250000", reason="Synthetic acceptance grant for TBB-SC-001", expiry=None)
        ),
        "explicit_expiry_pinned": bool(
            isinstance(exact_expiry, str) and no_expiry_row and explicit_row
            and ui_explicit_and_later_grants
            and explicit_row.get("expires_at") == exact_expiry
            and _matches_issuance_audit(explicit_audit, actor_id=admin.get("id"), owner_id=owner.get("id"),
                                        amount="0.750000", reason="Synthetic acceptance grant for TBB-SC-002", expiry=exact_expiry)
        ),
        "original_terms_immutable": bool(
            original_terms_unchanged and len(edits) == 3
            and {row.get("field") for row in edits} == {"expiresAt", "ownerId", "amount"}
            and all(row.get("status") == 409 and row.get("errorCode") == "IMMUTABLE_GRANT" and audit_for_edit(row) for row in edits)
        ),
        "later_grant_independent": bool(
            ui_explicit_and_later_grants and later_row and later_row.get("id") not in before_ids
            and later.get("operationId") != no_expiry.get("operationId")
            and later.get("operationId") != explicit.get("operationId")
            and later_row.get("owner_id") == owner.get("id") and later_row.get("issued_by_owner_id") == admin.get("id")
            and later_row.get("amount_units") == "125000" and later_row.get("reason") == "Synthetic later TBB grant with independent terms"
            and later_row.get("expires_at") is None
            and _matches_issuance_audit(later_audit, actor_id=admin.get("id"), owner_id=owner.get("id"),
                                        amount="0.125000", reason="Synthetic later TBB grant with independent terms", expiry=None)
        ),
    }
    negatives = {
        "expiry_boundary_timestamp": bool(
            isinstance(boundary.get("submittedExpiresAt"), str)
            and boundary_outcome.get("status") == 409
            and boundary_outcome.get("errorCode") == "EXPIRY_NOT_FUTURE" and expiry_audit
        ),
        "change_existing_expiry": bool(
            any(row.get("field") == "expiresAt" and row.get("status") == 409
                and row.get("errorCode") == "IMMUTABLE_GRANT" and audit_for_edit(row) for row in edits)
        ),
        "change_existing_owner": bool(
            any(row.get("field") == "ownerId" and row.get("status") == 409
                and row.get("errorCode") == "IMMUTABLE_GRANT" and audit_for_edit(row) for row in edits)
        ),
        "change_existing_amount": bool(
            any(row.get("field") == "amount" and row.get("status") == 409
                and row.get("errorCode") == "IMMUTABLE_GRANT" and audit_for_edit(row) for row in edits)
        ),
    }
    return facts, negatives


def derive_tbb_facts(scenario_id: str, artifacts: dict[str, dict[str, Any]]) -> tuple[dict[str, bool], dict[str, bool]]:
    if scenario_id == "TBB-SC-001":
        return derive_sc001_facts(artifacts["browser.json"], artifacts["database.json"])
    if scenario_id == "TBB-SC-002":
        return derive_sc002_facts(artifacts["browser.json"], artifacts["database.json"])
    return {}, {}


def _require_pass_facts(scenario_id: str, facts: dict[str, bool], negatives: dict[str, bool]) -> None:
    contract, _ = _read_contract()
    row = contract["protected_scenarios"][scenario_id]
    missing_observations = [name for name in row["required_observations"] if facts.get(name) is not True]
    missing_negatives = [name for name in row["negative_variants"] if negatives.get(name) is not True]
    if missing_observations or missing_negatives:
        raise AssertionError(
            f"{scenario_id} pass does not follow from raw evidence; "
            f"observations={missing_observations}, negatives={missing_negatives}"
        )


class TesterBonusBillingEvidenceCase:
    """Scenario registry adapter; all business mutations belong to the Docker runner."""

    def setup(self, context: ScenarioContext) -> None:
        context.state["tbb_evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        method = getattr(self, "_execute_" + context.scenario_id.replace("-", "_"))
        method(context)

    def _execute_evidence(self, context: ScenarioContext) -> None:
        loaded = _load_run(context.scenario_id)
        if loaded is None:
            pytest.skip(f"BLOCKED: no durable Docker acceptance run exists for {context.scenario_id}")
        manifest, artifacts = loaded
        context.state["tbb_manifest"] = manifest
        context.state["tbb_artifacts"] = artifacts
        facts, negatives = derive_tbb_facts(context.scenario_id, artifacts)
        context.state["tbb_facts"] = facts
        context.state["tbb_negatives"] = negatives
        if manifest["status"] == "blocked":
            reason = manifest.get("blockedReasonCode", "required_product_boundary_unavailable")
            pytest.skip(f"BLOCKED: {context.scenario_id} remains {reason}")
        if manifest["status"] == "failed":
            raise AssertionError(f"{context.scenario_id} Docker acceptance run is marked failed")
        _require_pass_facts(context.scenario_id, facts, negatives)

    def _execute_TBB_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_013(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_014(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def _execute_TBB_SC_015(self, context: ScenarioContext) -> None:
        self._execute_evidence(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        method = getattr(self, "_verify_" + context.scenario_id.replace("-", "_"))
        method(context)

    def _verify_pass(self, context: ScenarioContext) -> tuple[dict[str, bool], dict[str, bool], dict[str, Any]]:
        manifest = context.state.get("tbb_manifest")
        facts = context.state.get("tbb_facts")
        negatives = context.state.get("tbb_negatives")
        if not isinstance(manifest, dict) or not isinstance(facts, dict) or not isinstance(negatives, dict):
            raise AssertionError(f"{context.scenario_id} evidence was not loaded")
        if manifest.get("status") != "passed":
            raise AssertionError(f"{context.scenario_id} cannot verify a non-passed evidence run")
        contract, _ = _read_contract()
        row = contract["protected_scenarios"][context.scenario_id]
        for name in row["negative_variants"]:
            if negatives.get(name) is not True:
                raise AssertionError(f"{context.scenario_id} negative variant is not derived: {name}")
            if manifest["negativeVariants"][name].get("status") != "observed":
                raise AssertionError(f"{context.scenario_id} manifest does not record negative variant {name}")
        return facts, negatives, manifest

    def _check_negative(self, context: ScenarioContext, name: str, negatives: dict[str, bool], manifest: dict[str, Any]) -> None:
        if negatives.get(name) is not True:
            raise AssertionError(f"{context.scenario_id} negative variant is not derived: {name}")
        if manifest["negativeVariants"][name].get("status") != "observed":
            raise AssertionError(f"{context.scenario_id} manifest does not record negative variant {name}")

    def _verify_TBB_SC_001(self, context: ScenarioContext) -> None:
        facts, negatives, manifest = self._verify_pass(context)
        context.check("admin_only_grant", facts.get("admin_only_grant") is True)
        context.check("single_grant_after_restart", facts.get("single_grant_after_restart") is True)
        context.check("actor_reason_terms_preserved", facts.get("actor_reason_terms_preserved") is True)
        context.check("invalid_or_conflicting_grant_no_effect", facts.get("invalid_or_conflicting_grant_no_effect") is True)
        self._check_negative(context, "owner_grant_attempt", negatives, manifest)
        self._check_negative(context, "agent_grant_attempt", negatives, manifest)
        self._check_negative(context, "negative_zero_or_excess_precision", negatives, manifest)
        self._check_negative(context, "past_expiry", negatives, manifest)
        self._check_negative(context, "same_key_changed_amount", negatives, manifest)
        self._check_negative(context, "lost_response_restart", negatives, manifest)

    def _verify_TBB_SC_002(self, context: ScenarioContext) -> None:
        facts, negatives, manifest = self._verify_pass(context)
        context.check("default_no_expiry", facts.get("default_no_expiry") is True)
        context.check("explicit_expiry_pinned", facts.get("explicit_expiry_pinned") is True)
        context.check("original_terms_immutable", facts.get("original_terms_immutable") is True)
        context.check("later_grant_independent", facts.get("later_grant_independent") is True)
        self._check_negative(context, "expiry_boundary_timestamp", negatives, manifest)
        self._check_negative(context, "change_existing_expiry", negatives, manifest)
        self._check_negative(context, "change_existing_owner", negatives, manifest)
        self._check_negative(context, "change_existing_amount", negatives, manifest)

    def _verify_TBB_SC_003(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("cash_bonus_separate", facts.get("cash_bonus_separate") is True)
        context.check("fractional_units_exact", facts.get("fractional_units_exact") is True)
        context.check("expired_not_available", facts.get("expired_not_available") is True)
        context.check("reserved_not_available", facts.get("reserved_not_available") is True)
        context.check("foreign_owner_read_denied", facts.get("foreign_owner_read_denied") is True)
        context.check("bonus_not_withdrawable_cash", facts.get("bonus_not_withdrawable_cash") is True)

    def _verify_TBB_SC_004(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("four_services_bonus_eligible", facts.get("four_services_bonus_eligible") is True)
        context.check("denied_classes_no_bonus_effect", facts.get("denied_classes_no_bonus_effect") is True)
        context.check("unknown_service_closed", facts.get("unknown_service_closed") is True)
        context.check("client_label_not_authoritative", facts.get("client_label_not_authoritative") is True)

    def _verify_TBB_SC_005(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("bonus_first_allocation", facts.get("bonus_first_allocation") is True)
        context.check("permitted_cash_remainder_exact", facts.get("permitted_cash_remainder_exact") is True)
        context.check("one_publication_receipt", facts.get("one_publication_receipt") is True)
        context.check("topic_first_message_not_double_charged", facts.get("topic_first_message_not_double_charged") is True)
        context.check("ledger_and_publication_atomic", facts.get("ledger_and_publication_atomic") is True)

    def _verify_TBB_SC_006(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("no_cash_without_owner_permission", facts.get("no_cash_without_owner_permission") is True)
        context.check("insufficient_funds_no_partial_effect", facts.get("insufficient_funds_no_partial_effect") is True)
        context.check("rollback_preserves_sources", facts.get("rollback_preserves_sources") is True)
        context.check("postcommit_response_loss_recovers_once", facts.get("postcommit_response_loss_recovers_once") is True)

    def _verify_TBB_SC_007(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("no_double_bonus_allocation", facts.get("no_double_bonus_allocation") is True)
        context.check("cash_reservations_respected", facts.get("cash_reservations_respected") is True)
        context.check("one_receipt_after_restart", facts.get("one_receipt_after_restart") is True)
        context.check("source_conservation_per_lot", facts.get("source_conservation_per_lot") is True)

    def _verify_TBB_SC_008(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("queued_sources_held_not_debited", facts.get("queued_sources_held_not_debited") is True)
        context.check("quote_split_immutable", facts.get("quote_split_immutable") is True)
        context.check("start_sources_and_task_atomic", facts.get("start_sources_and_task_atomic") is True)
        context.check("no_silent_cash_increase", facts.get("no_silent_cash_increase") is True)
        context.check("normal_ranked_eligibility_handoff", facts.get("normal_ranked_eligibility_handoff") is True)

    def _verify_TBB_SC_009(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("expired_grant_start_rejected", facts.get("expired_grant_start_rejected") is True)
        context.check("both_holds_released_once", facts.get("both_holds_released_once") is True)
        context.check("expired_release_not_spendable", facts.get("expired_release_not_spendable") is True)
        context.check("no_expiry_cash_substitution", facts.get("no_expiry_cash_substitution") is True)

    def _verify_TBB_SC_010(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("cash_permission_checked_at_start", facts.get("cash_permission_checked_at_start") is True)
        context.check("disabled_cash_no_debit", facts.get("disabled_cash_no_debit") is True)
        context.check("source_holds_released", facts.get("source_holds_released") is True)
        context.check("bonus_only_no_cash_permission_needed", facts.get("bonus_only_no_cash_permission_needed") is True)

    def _verify_TBB_SC_011(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("cash_refund_matches_cash_debit", facts.get("cash_refund_matches_cash_debit") is True)
        context.check("bonus_refund_matches_original_lots", facts.get("bonus_refund_matches_original_lots") is True)
        context.check("refund_once_after_restart", facts.get("refund_once_after_restart") is True)
        context.check("nonrefundable_sources_retained", facts.get("nonrefundable_sources_retained") is True)

    def _verify_TBB_SC_012(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("refund_expiry_decided_at_serialized_commit_time", facts.get("refund_expiry_decided_at_serialized_commit_time") is True)
        context.check("expired_original_grant_and_history_unchanged", facts.get("expired_original_grant_and_history_unchanged") is True)
        context.check("replacement_grant_linked_to_original_and_refund_receipt", facts.get("replacement_grant_linked_to_original_and_refund_receipt") is True)
        context.check("replacement_grant_has_ordinary_no_expiry_default", facts.get("replacement_grant_has_ordinary_no_expiry_default") is True)
        context.check("live_original_lot_restored_under_original_expiry", facts.get("live_original_lot_restored_under_original_expiry") is True)
        context.check("cash_refund_returns_to_original_source", facts.get("cash_refund_returns_to_original_source") is True)
        context.check("retry_returns_same_refund_and_grant_result", facts.get("retry_returns_same_refund_and_grant_result") is True)

    def _verify_TBB_SC_013(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("actual_admin_form_commits_grant", facts.get("actual_admin_form_commits_grant") is True)
        context.check("owner_views_separate_sources_and_terms", facts.get("owner_views_separate_sources_and_terms") is True)
        context.check("owner_cash_control_enforced", facts.get("owner_cash_control_enforced") is True)
        context.check("nonadmin_grant_denied", facts.get("nonadmin_grant_denied") is True)
        context.check("public_financial_data_absent", facts.get("public_financial_data_absent") is True)

    def _verify_TBB_SC_014(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("full_nominal_price_in_caps", facts.get("full_nominal_price_in_caps") is True)
        context.check("bonus_not_limit_bypass", facts.get("bonus_not_limit_bypass") is True)
        context.check("current_utc_start_recheck", facts.get("current_utc_start_recheck") is True)
        context.check("refund_original_usage_bucket", facts.get("refund_original_usage_bucket") is True)

    def _verify_TBB_SC_015(self, context: ScenarioContext) -> None:
        facts, _, _ = self._verify_pass(context)
        context.check("grant_not_customer_revenue", facts.get("grant_not_customer_revenue") is True)
        context.check("mixed_only_cash_portion_paid", facts.get("mixed_only_cash_portion_paid") is True)
        context.check("source_refunds_deduct_correctly", facts.get("source_refunds_deduct_correctly") is True)
        context.check("operation_projection_idempotent", facts.get("operation_projection_idempotent") is True)
        context.check("synthetic_cash_provenance_explicit", facts.get("synthetic_cash_provenance_explicit") is True)


def register(registry: ScenarioRegistry) -> None:
    case = TesterBonusBillingEvidenceCase()
    profile_by_scenario = {
        scenario_id: "tester_bonus_browser_http_adapter" if scenario_id == "TBB-SC-013"
        else "tester_bonus_http_adapter"
        for scenario_id in SCENARIO_IDS
    }
    if set(profile_by_scenario) != set(SCENARIO_IDS):
        raise ValueError("TBB scenario adapter inventory is inconsistent")
    for scenario_id in SCENARIO_IDS:
        registry.register(scenario_id, case, adapter_profile=profile_by_scenario[scenario_id])
