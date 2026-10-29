from __future__ import annotations

import copy
import hashlib

from tests.bdd.adapters.beta_poc_report_verifier import (
    BOUNDARY_DETAILS,
    NEGATIVE_NAMES,
    OBSERVATION_NAMES,
    SCENARIO_IDS,
    SNAPSHOT_KEYS,
    _derive_negatives,
    derive_observations,
)


def _row_attempt(name: str, status: int, error: str | None = None) -> dict[str, object]:
    return {
        "name": name,
        "responseStatus": status,
        "errorCode": error,
        "databaseRole": "oid_observer",
        "transactionReadOnly": "on",
        "reportRowsBefore": 0,
        "reportRowsAfter": 0,
        "uploadRowsBefore": 0,
        "uploadRowsAfter": 0,
    }


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sc018_evidence() -> dict[str, object]:
    op_linked = "1" * 64
    op_unlinked = "2" * 64
    report_linked = "10000000-0000-4000-8000-000000000001"
    report_unlinked = "10000000-0000-4000-8000-000000000002"
    owner_hash = "3" * 64
    image_id = "20000000-0000-4000-8000-000000000001"
    image_hash = "4" * 64
    root_hash = "5" * 64
    storage_key_hash = "6" * 64
    body_hash = "7" * 64
    owner_run_id = "40000000-0000-4000-8000-000000000001"
    foreign_run_id = "40000000-0000-4000-8000-000000000002"
    foreign_action_id = "30000000-0000-4000-8000-000000000001"
    foreign_owner_hash = "c" * 64
    linked = {
        "id": report_linked,
        "source": "owner",
        "runIdSha256": _digest(owner_run_id),
        "operationIdSha256": op_linked,
        "safeContextKeys": ["runContext", "requestId"],
        "safeContext": {"runContext": "linked", "requestId": {"sha256": "9" * 64}},
        "ownerIdSha256": owner_hash,
        "bodySha256": body_hash,
        "imageIds": [image_id],
    }
    unlinked = {
        "id": report_unlinked,
        "source": "owner",
        "runIdSha256": None,
        "operationIdSha256": op_unlinked,
        "safeContextKeys": ["runContext"],
        "safeContext": {"runContext": "unavailable"},
        "ownerIdSha256": owner_hash,
        "bodySha256": "a" * 64,
        "imageIds": [],
    }
    upload = {
        "id": image_id,
        "reportId": report_linked,
        "status": "attached",
        "outputSha256": image_hash,
        "outputBytes": 1234,
        "storageKeySha256": storage_key_hash,
    }
    attempts = [
        _row_attempt("foreign_run_or_action", 404, "REPORT_LINK_NOT_FOUND") | {
            "runIdSha256": _digest(foreign_run_id), "foreignOwnerIdSha256": foreign_owner_hash,
        },
        _row_attempt("foreign_action_link", 404, "REPORT_LINK_NOT_FOUND") | {
            "requestRunIdSha256": _digest(owner_run_id), "requestOwnerIdSha256": owner_hash,
            "actionIdSha256": _digest(foreign_action_id), "actionRunIdSha256": _digest(foreign_run_id),
            "actionOwnerIdSha256": foreign_owner_hash,
        },
        _row_attempt("forbidden_secret_fields", 400, "REPORT_CONTAINS_CREDENTIAL_MATERIAL"),
        _row_attempt("oversized_payload", 413, "REQUEST_BODY_TOO_LARGE"),
        _row_attempt("html_text", 200),
        _row_attempt("report_flood", 429, "REPORT_RATE_LIMITED"),
        _row_attempt("response_loss", 200),
        _row_attempt("conflicting_retry", 409, "IDEMPOTENCY_CONFLICT"),
    ]
    snapshots = {key: [] for key in SNAPSHOT_KEYS}
    snapshots["runRows"] = [
        {"id": owner_run_id, "ownerIdSha256": owner_hash},
        {"id": foreign_run_id, "ownerIdSha256": foreign_owner_hash},
    ]
    snapshots["actionRows"] = [{"id": foreign_action_id, "runId": foreign_run_id, "ownerIdSha256": foreign_owner_hash}]
    after = copy.deepcopy(snapshots)
    after["reports"] = [linked, unlinked]
    after["uploads"] = [upload]
    return {
        "schemaVersion": "bpc-report-runtime-observation/v1",
        "scenarioId": "BPC-SC-018",
        "boundaryDetail": BOUNDARY_DETAILS["BPC-SC-018"],
        "captureBoundary": "actual_target_host",
        "browser": {
            "originScheme": "https",
            "actions": [
                {"action": "click", "controlId": "owner-report-submit-linked"},
                {"action": "click", "controlId": "owner-report-submit-unlinked"},
                {"action": "click", "controlId": "owner-report-image-preview"},
            ],
            "requests": [
                {"method": "POST", "path": "/api/owner/reports", "status": 201, "operationIdSha256": op_linked},
                {"method": "POST", "path": "/api/owner/reports", "status": 201, "operationIdSha256": op_unlinked},
                {"method": "POST", "path": "/api/owner/report-images/uploads/multipart", "status": 201},
            ],
            "previews": [{"accessRole": "owner", "status": 200, "sha256": image_hash}],
            "textProbes": [{"probe": "html-report-render", "status": 200, "scriptElementCount": 0,
                             "expectedTextSha256": body_hash, "observedTextSha256": body_hash}],
        },
        "observer": {
            "databaseRole": "oid_observer",
            "transactionReadOnly": "on",
            "before": snapshots,
            "after": after,
        },
        "storage": {"images": [{
            "imageId": image_id,
            "sha256FromDatabase": image_hash,
            "sha256FromDisk": image_hash,
            "databaseBytes": 1234,
            "diskBytes": 1234,
            "modeBits": 0o600,
            "contentType": "image/webp",
            "storageKeySha256": storage_key_hash,
            "privateRootSha256": root_hash,
            "parentDirectorySha256": root_hash,
        }]},
        "negativeAttempts": attempts,
        "responseLossRetries": [{
            "firstResponse": "lost", "retryStatus": 200, "operationIdSha256": op_linked,
            "originalReportIdSha256": "b" * 64, "retryReportIdSha256": "b" * 64,
            "persistedRowsForOperation": 1,
        }],
    }


def test_unknown_or_local_capture_is_not_observation_evidence() -> None:
    local = {
        "schemaVersion": "bpc-report-runtime-observation/v1",
        "scenarioId": "BPC-SC-018",
        "boundaryDetail": BOUNDARY_DETAILS["BPC-SC-018"],
        "captureBoundary": "local_synthetic",
        "observations": {name: True for name in OBSERVATION_NAMES["BPC-SC-018"]},
        "negativeVariants": {name: True for name in NEGATIVE_NAMES["BPC-SC-018"]},
    }
    assert derive_observations("BPC-SC-018", local) is None
    assert derive_observations("BPC-SC-999", local) is None


def test_report_observations_are_replayed_from_raw_evidence_not_claimed_booleans() -> None:
    evidence = _sc018_evidence()
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None
    assert set(facts) == set(OBSERVATION_NAMES["BPC-SC-018"]) | set(NEGATIVE_NAMES["BPC-SC-018"])
    assert all(type(value) is bool for value in facts.values())
    assert facts["linked_and_unlinked_report_saved"] is True
    assert facts["report_image_links_match_private_storage"] is True
    assert facts["html_text"] is True

    changed = copy.deepcopy(evidence)
    changed["observations"] = {name: False for name in facts}
    changed["negativeVariants"] = {name: False for name in facts}
    assert derive_observations("BPC-SC-018", changed) == facts


def test_incomplete_observer_and_missing_negative_attempt_are_blocked() -> None:
    evidence = _sc018_evidence()
    del evidence["observer"]["after"]["actionRows"]
    assert derive_observations("BPC-SC-018", evidence) is None

    evidence = _sc018_evidence()
    evidence["negativeAttempts"] = [row for row in evidence["negativeAttempts"] if row["name"] != "conflicting_retry"]
    assert derive_observations("BPC-SC-018", evidence) is None


def test_negative_attempt_with_boolean_or_database_delta_does_not_pass() -> None:
    evidence = _sc018_evidence()
    attempt = next(row for row in evidence["negativeAttempts"] if row["name"] == "forbidden_secret_fields")
    attempt["responseStatus"] = True
    assert derive_observations("BPC-SC-018", evidence) is None

    evidence = _sc018_evidence()
    attempt = next(row for row in evidence["negativeAttempts"] if row["name"] == "forbidden_secret_fields")
    attempt["reportRowsAfter"] = 1
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None
    assert facts["forbidden_secret_fields"] is False


def test_foreign_run_and_foreign_action_each_need_bound_rejection_evidence() -> None:
    evidence = _sc018_evidence()
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None and facts["foreign_run_or_action"] is True

    action_attempt = next(row for row in evidence["negativeAttempts"] if row["name"] == "foreign_action_link")
    action_attempt["responseStatus"] = 201
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None and facts["foreign_run_or_action"] is False

    evidence = _sc018_evidence()
    evidence["observer"]["before"]["actionRows"] = []
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None and facts["foreign_run_or_action"] is False


def test_admin_status_denial_requires_production_403_forbidden_code() -> None:
    accepted = _derive_negatives("BPC-SC-020", {
        "negativeAttempts": [_row_attempt("unauthorized_status", 403, "FORBIDDEN")],
    })
    rejected_alias = _derive_negatives("BPC-SC-020", {
        "negativeAttempts": [_row_attempt("unauthorized_status", 403, "ADMIN_REQUIRED")],
    })
    assert accepted["unauthorized_status"] is True
    assert rejected_alias["unauthorized_status"] is False


def test_report_action_side_effect_is_detected_by_approved_observation() -> None:
    evidence = _sc018_evidence()
    facts = derive_observations("BPC-SC-018", evidence)
    assert facts is not None
    assert facts["no_billing_or_task_effect"] is True

    evidence["observer"]["after"]["actionRows"].append({
        "id": "30000000-0000-4000-8000-000000000001",
        "runId": "40000000-0000-4000-8000-000000000001",
        "ownerIdSha256": "c" * 64,
        "agentIdSha256": "d" * 64,
        "taskId": "S1",
        "actionSequence": 1,
        "actionKind": "report",
        "acceptedAt": "2026-10-28T00:00:00Z",
    })
    changed = derive_observations("BPC-SC-018", evidence)
    assert changed is not None
    assert changed["no_billing_or_task_effect"] is False
