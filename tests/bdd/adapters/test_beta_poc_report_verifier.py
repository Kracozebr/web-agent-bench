from __future__ import annotations

import copy
import hashlib
import json

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


def _effect_projection_fields(report_count: int = 0, upload_count: int = 0) -> dict[str, object]:
    report_json = json.dumps({"totalCounts": {"reports": report_count, "uploads": upload_count}, "reports": [], "audits": [], "uploads": [],
                              "imageUsageRows": [], "reportDeletionReceipts": [], "uploadGcReceipts": []}, separators=(",", ":"))
    domain_json = json.dumps({"financialRows": [], "runRows": [], "taskRows": [], "actionRows": [], "timerRows": []}, separators=(",", ":"))
    return {
        "effectScope": "report_and_domain_rows_excluding_oid_rate_limit",
        "noReportOrDomainEffects": True,
        "reportStateBeforeJson": report_json,
        "reportStateAfterJson": report_json,
        "domainStateBeforeJson": domain_json,
        "domainStateAfterJson": domain_json,
        "reportStateBeforeSha256": _digest(report_json),
        "reportStateAfterSha256": _digest(report_json),
        "domainStateBeforeSha256": _digest(domain_json),
        "domainStateAfterSha256": _digest(domain_json),
    }


def _report_flood_attempt() -> dict[str, object]:
    bucket_index = 30_000_000
    bucket_start = bucket_index * 60
    key_hash = "a" * 64
    database_name = "oid_acceptance_" + "b" * 32
    observer = {"databaseRole": "oid_observer", "databaseName": database_name, "transactionReadOnly": "on"}
    return _row_attempt("report_flood", 429, "RATE_LIMITED") | {
        "attemptCap": 121, "configuredRateLimitMax": 120, "windowSeconds": 60,
        "elapsedMs": 2200,
        "prefillAttempts": [
            {"responseStatus": 400, "errorCode": "INVALID_REPORT"},
            {"responseStatus": 429, "errorCode": "RATE_LIMITED"},
        ],
        "validPayloadShape": {"fieldNames": ["body", "operationId", "title"],
                               "operationIdIsCanonical": True, "titleLength": 8, "bodyLength": 9},
        "validOperationIdSha256": "c" * 64,
        "rateLimitObservation": {
            "table": "oid_rate_limit", "group": "support-report-owner-create", "maxPerWindow": 120,
            "windowSeconds": 60, **observer,
            "before": observer | {"databaseClockEpochSeconds": bucket_start + 1, "bucketIndex": bucket_index,
                                  "bucketStartSeconds": bucket_start,
                                  "rows": [{"keyHashSha256": key_hash, "bucketStart": bucket_index, "requestCount": 119}]},
            "after": observer | {"databaseClockEpochSeconds": bucket_start + 4, "bucketIndex": bucket_index,
                                 "bucketStartSeconds": bucket_start,
                                 "rows": [{"keyHashSha256": key_hash, "bucketStart": bucket_index, "requestCount": 122}]},
            "targetKeyHashSha256": key_hash, "priorRequestCount": 119, "finalRequestCount": 122,
            "requestCountDelta": 3,
        },
        **_effect_projection_fields(),
    }


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
        _report_flood_attempt(),
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
    assert facts["report_flood"] is True

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


def _agent_admin_evidence() -> dict[str, object]:
    report_id = "10000000-0000-4000-8000-000000000001"
    image_id = "20000000-0000-4000-8000-000000000001"
    agent_id = "30000000-0000-4000-8000-000000000001"
    owner_hash = "a" * 64
    agent_hash = hashlib.sha256(agent_id.encode()).hexdigest()
    credential_hash = "c" * 64
    grant_hash = "d" * 64
    image_hash = "e" * 64
    resource_hash = "f" * 64
    report = {"id": report_id, "ownerIdSha256": owner_hash, "imageIds": [image_id]}
    upload = {"id": image_id, "reportId": report_id, "ownerIdSha256": owner_hash,
              "status": "attached", "outputSha256": image_hash}
    snapshot = {key: [] for key in SNAPSHOT_KEYS}
    snapshot["reports"] = [report]
    snapshot["uploads"] = [upload]
    routes = {
        "admin_list": ("GET", "/api/admin/reports"),
        "admin_detail": ("GET", "/api/admin/reports/{reportId}"),
        "admin_status": ("PATCH", "/api/admin/reports/{reportId}/status"),
        "admin_image": ("GET", "/api/admin/reports/{reportId}/images/{imageId}"),
    }
    attempts = []
    for probe, (method, path_template) in routes.items():
        attempts.append(_row_attempt("agent_admin_attempt", 401, "UNAUTHORIZED") | {
            "probe": probe, "method": method, "pathTemplate": path_template,
            "transport": "cookie_free_agent_bearer_http", "authorizationScheme": "Bearer",
            "sessionCookiePresent": False, "credentialIdSha256": credential_hash,
            "grantIdSha256": grant_hash, "agentIdSha256": agent_hash, "ownerIdSha256": owner_hash,
            "targetReportIdSha256": hashlib.sha256(report_id.encode()).hexdigest(),
            "targetImageIdSha256": hashlib.sha256(image_id.encode()).hexdigest(),
            "reportRowsBefore": 1, "reportRowsAfter": 1, "uploadRowsBefore": 1, "uploadRowsAfter": 1,
            **_effect_projection_fields(report_count=1, upload_count=1),
        })
    return {
        "agentBearerProof": {
            "credentialSource": "owner_ui_issue_once", "fixtureType": "synthetic_local_agent_credential",
            "authorizationScheme": "Bearer", "sessionCookiePresent": False,
            "ownerUiIssuance": {
                "originScheme": "http",
                "issueResponseIdHashes": {"status": 201, "agentIdSha256": agent_hash,
                                           "credentialIdSha256": credential_hash, "grantIdSha256": grant_hash},
                "actions": [
                    {"action": "click", "controlId": "agent-create"},
                    {"action": "click", "controlId": f"credential-issue-{agent_id}"},
                ],
                "requests": [
                    {"method": "POST", "path": "/api/owner/agents", "status": 201},
                    {"method": "POST", "path": f"/api/owner/agents/{agent_id}/manual-credential", "status": 201},
                ],
            },
            "credentialBinding": {
                "databaseRole": "oid_observer", "transactionReadOnly": "on",
                "matchingCredentialGrantRows": 1, "grantSource": "manual", "grantRole": "agent",
                "grantRevokedAt": None, "grantExpiresAt": "2026-10-30T00:00:00+00:00",
                "observedAt": "2026-10-29T00:00:00+00:00", "resourceSha256": resource_hash,
                "credentialIdSha256": credential_hash,
                "grantIdSha256": grant_hash, "ownerIdSha256": owner_hash, "agentIdSha256": agent_hash,
            },
            "preflight": {"method": "GET", "path": "/api/agent/preflight", "responseStatus": 200,
                          "allowed": True, "role": "agent", "authorizationScheme": "Bearer",
                          "sessionCookiePresent": False, "resourceMatches": True, "agentIdSha256": agent_hash,
                          "resourceSha256": resource_hash},
            "targetReportIdSha256": hashlib.sha256(report_id.encode()).hexdigest(),
            "targetImageIdSha256": hashlib.sha256(image_id.encode()).hexdigest(),
        },
        "browser": {"previews": [{"accessRole": "admin", "status": 200, "sha256": image_hash}]},
        "observer": {"databaseRole": "oid_observer", "transactionReadOnly": "on", "before": snapshot, "after": copy.deepcopy(snapshot)},
        "negativeAttempts": attempts,
    }


def test_report_flood_requires_observed_rate_transition_and_raw_no_effect_projections() -> None:
    attempt = _report_flood_attempt()
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [attempt]})["report_flood"] is True
    attempt["errorCode"] = "REPORT_RATE_LIMITED"
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [attempt]})["report_flood"] is False
    attempt["errorCode"] = "RATE_LIMITED"
    attempt["reportStateAfterSha256"] = "d" * 64
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [attempt]})["report_flood"] is False

    wrong_table = _report_flood_attempt()
    wrong_table["rateLimitObservation"]["table"] = "oid_auth_rate_limit"
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [wrong_table]})["report_flood"] is False

    wrong_delta = _report_flood_attempt()
    wrong_delta["rateLimitObservation"]["after"]["rows"][0]["requestCount"] = 121
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [wrong_delta]})["report_flood"] is False

    no_threshold_crossing = _report_flood_attempt()
    no_threshold_crossing["rateLimitObservation"]["before"]["rows"][0]["requestCount"] = 120
    no_threshold_crossing["rateLimitObservation"]["after"]["rows"][0]["requestCount"] = 123
    no_threshold_crossing["rateLimitObservation"]["priorRequestCount"] = 120
    no_threshold_crossing["rateLimitObservation"]["finalRequestCount"] = 123
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [no_threshold_crossing]})["report_flood"] is False

    changed_projection_with_fake_hashes = _report_flood_attempt()
    changed_projection_with_fake_hashes["reportStateAfterJson"] = json.dumps({
        "totalCounts": {"reports": 1, "uploads": 0}, "reports": [{"id": "changed"}], "audits": [],
        "uploads": [], "imageUsageRows": [], "reportDeletionReceipts": [], "uploadGcReceipts": [],
    }, separators=(",", ":"))
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [changed_projection_with_fake_hashes]})["report_flood"] is False

    for invalid_projection in ("null", "[]", "{}"):
        empty_projection = _report_flood_attempt()
        for suffix in ("BeforeJson", "AfterJson"):
            empty_projection[f"reportState{suffix}"] = invalid_projection
            empty_projection[f"reportState{suffix.removesuffix('Json')}Sha256"] = _digest(invalid_projection)
        assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [empty_projection]})["report_flood"] is False

    missing_raw_domain = _report_flood_attempt()
    missing_raw_domain["domainStateBeforeJson"] = "{}"
    missing_raw_domain["domainStateAfterJson"] = "{}"
    missing_raw_domain["domainStateBeforeSha256"] = _digest("{}")
    missing_raw_domain["domainStateAfterSha256"] = _digest("{}")
    assert _derive_negatives("BPC-SC-018", {"negativeAttempts": [missing_raw_domain]})["report_flood"] is False


def test_agent_admin_denial_requires_owner_issued_preflighted_bearer_and_all_routes() -> None:
    evidence = _agent_admin_evidence()
    assert _derive_negatives("BPC-SC-020", evidence)["agent_admin_attempt"] is True

    missing_control = copy.deepcopy(evidence)
    missing_control["agentBearerProof"]["preflight"]["allowed"] = False
    assert _derive_negatives("BPC-SC-020", missing_control)["agent_admin_attempt"] is False

    missing_route = copy.deepcopy(evidence)
    missing_route["negativeAttempts"].pop()
    assert _derive_negatives("BPC-SC-020", missing_route)["agent_admin_attempt"] is False

    leaked_cookie = copy.deepcopy(evidence)
    leaked_cookie["negativeAttempts"][0]["sessionCookiePresent"] = True
    assert _derive_negatives("BPC-SC-020", leaked_cookie)["agent_admin_attempt"] is False

    arbitrary_bearer = copy.deepcopy(evidence)
    arbitrary_bearer["agentBearerProof"]["credentialSource"] = "arbitrary_test_string"
    assert _derive_negatives("BPC-SC-020", arbitrary_bearer)["agent_admin_attempt"] is False

    missing_ui_issue = copy.deepcopy(evidence)
    del missing_ui_issue["agentBearerProof"]["ownerUiIssuance"]
    assert _derive_negatives("BPC-SC-020", missing_ui_issue)["agent_admin_attempt"] is False

    mismatched_issue_ids = copy.deepcopy(evidence)
    mismatched_issue_ids["agentBearerProof"]["ownerUiIssuance"]["issueResponseIdHashes"]["credentialIdSha256"] = "9" * 64
    assert _derive_negatives("BPC-SC-020", mismatched_issue_ids)["agent_admin_attempt"] is False

    altered_admin_projection = copy.deepcopy(evidence)
    altered_admin_projection["negativeAttempts"][0]["domainStateAfterJson"] = json.dumps({
        "financialRows": [], "runRows": [], "taskRows": [], "actionRows": [{"id": "changed"}], "timerRows": [],
    }, separators=(",", ":"))
    assert _derive_negatives("BPC-SC-020", altered_admin_projection)["agent_admin_attempt"] is False

    leaked_image = copy.deepcopy(evidence)
    leaked_image["observer"]["after"]["uploads"] = []
    assert _derive_negatives("BPC-SC-020", leaked_image)["agent_admin_attempt"] is False

    admin_route_allowed = copy.deepcopy(evidence)
    admin_route_allowed["negativeAttempts"][3]["responseStatus"] = 200
    assert _derive_negatives("BPC-SC-020", admin_route_allowed)["agent_admin_attempt"] is False

    leaked_token = copy.deepcopy(evidence)
    leaked_token["agentBearerProof"]["bearerToken"] = "aap1_" + "A" * 43
    assert _derive_negatives("BPC-SC-020", leaked_token)["agent_admin_attempt"] is False


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
