"""Scenario-specific replay for private reports, screenshots and retention.

Only sanitized raw browser/client, read-only PostgreSQL and private-file facts
can satisfy these BPC gates. Producer-supplied observation booleans are ignored.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any

SCENARIO_IDS = (
    "BPC-SC-018",
    "BPC-SC-019",
    "BPC-SC-020",
    "BPC-SC-024",
    "BPC-SC-026",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_CONTEXT_KEYS = {"capturedAt", "runContext", "requestId", "runMode", "runStatus"}
BOUNDARY_DETAILS = {
    "BPC-SC-018": "owner_browser_reports_postgres",
    "BPC-SC-019": "four_native_clients_support_tool_postgres",
    "BPC-SC-020": "admin_browser_report_triage_postgres",
    "BPC-SC-024": "authenticated_image_upload_private_storage_postgres",
    "BPC-SC-026": "report_retention_purge_backup_restore",
}
OBSERVATION_NAMES = {
    "BPC-SC-018": ("linked_and_unlinked_report_saved", "safe_auto_context", "one_receipt_retry", "no_billing_or_task_effect", "owner_form_image_upload_and_preview", "report_image_links_match_private_storage"),
    "BPC-SC-019": ("four_clients_report_as_principal", "valid_links_or_no_run", "original_receipt_after_restart", "unchanged_ledger_task_timer", "native_agent_optional_image_upload_reference", "screenshot_links_owned_by_agent", "native_chunk_or_audited_owner_upload_path"),
    "BPC-SC-020": ("list_filters_match_db", "safe_detail_text", "status_audit_revision", "own_owner_projection", "admin_and_own_owner_image_preview_hash_match"),
    "BPC-SC-024": ("decoded_format_size_pixels_validated", "normalized_bytes_metadata_stripped", "principal_bound_upload_and_report_link", "three_image_cap_atomic", "image_retry_recovers_original", "private_owner_admin_preview", "orphan_cleanup_preserves_committed", "no_task_billing_refund_effect", "mcp_chunk_frames_under_64kib", "output_and_aggregate_upload_quotas_enforced"),
    "BPC-SC-026": ("retention_from_beta_end", "access_denied_at_expiry", "content_and_images_purged", "tombstones_retained", "no_restore_resurrection", "ledger_grades_unchanged"),
}
NEGATIVE_NAMES = {
    "BPC-SC-018": ("foreign_run_or_action", "forbidden_secret_fields", "oversized_payload", "html_text", "report_flood", "response_loss", "conflicting_retry"),
    "BPC-SC-019": ("revoked_credential", "foreign_context", "forged_owner", "report_as_action", "conflicting_retry", "excess_submission", "foreign_image_reference", "owner_attaches_to_foreign_agent_report"),
    "BPC-SC-020": ("stale_revision", "foreign_owner_read", "agent_admin_attempt", "unauthorized_status", "html_injection", "foreign_attachment_preview"),
    "BPC-SC-024": ("corrupt_image", "disguised_html_or_svg", "input_over_5mib", "pixel_limit_exceeded", "fourth_image_race", "foreign_upload_reference", "foreign_image_read", "path_traversal", "external_url_input", "lost_upload_response_restart", "conflicting_retry_bytes", "cleanup_attach_race", "chunk_sequence_conflict", "rolling_owner_quota", "staging_capacity_race", "normalized_output_over_limit", "insufficient_disk_or_backup_space"),
    "BPC-SC-026": ("read_at_deadline", "late_upload_attach", "delete_failure", "repeated_cleanup", "old_backup_restore", "service_restart"),
}
SNAPSHOT_KEYS = {
    "reports", "audits", "uploads", "imageUsageRows", "reportDeletionReceipts",
    "uploadGcReceipts", "financialRows", "runRows", "taskRows", "actionRows", "timerRows",
}


def _is_rows(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(row, dict) for row in value)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _contains_agent_credential_material(value: Any) -> bool:
    if isinstance(value, dict):
        forbidden_fragments = ("token", "bearer", "secret", "verifier")
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key).lower())
            if any(fragment in normalized for fragment in forbidden_fragments) \
                    or (normalized.startswith("authorization") and normalized != "authorizationscheme") \
                    or _contains_agent_credential_material(item):
                return True
    elif isinstance(value, list):
        return any(_contains_agent_credential_material(item) for item in value)
    elif isinstance(value, str):
        return re.search(r"\baap1_[A-Za-z0-9_-]{43}\b", value) is not None
    return False


def _sha256_text(value: Any) -> str | None:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if isinstance(value, str) else None


def _same(left: Any, right: Any) -> bool:
    return left == right


def _snapshot_pair(evidence: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    observer = evidence.get("observer")
    if not isinstance(observer, dict) or observer.get("databaseRole") != "oid_observer" or observer.get("transactionReadOnly") != "on":
        return None
    before = observer.get("before")
    after = observer.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    if any(not _is_rows(before.get(key)) or not _is_rows(after.get(key)) for key in SNAPSHOT_KEYS):
        return None
    return before, after


def _report_rows(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    pair = _snapshot_pair(evidence)
    return pair[1]["reports"] if pair else []


def _click(evidence: dict[str, Any], control_id: str) -> bool:
    browser = evidence.get("browser")
    actions = browser.get("actions") if isinstance(browser, dict) else None
    return isinstance(actions, list) and any(
        isinstance(row, dict) and row.get("action") == "click" and row.get("controlId") == control_id
        for row in actions
    )


def _request(evidence: dict[str, Any], path: str, status: int, *, method: str | None = None, error_code: str | None = None) -> dict[str, Any] | None:
    browser = evidence.get("browser")
    requests = browser.get("requests") if isinstance(browser, dict) else None
    if not isinstance(requests, list):
        return None
    for row in requests:
        if not isinstance(row, dict):
            continue
        if row.get("path") == path and row.get("status") == status and (method is None or row.get("method") == method):
            if error_code is None or row.get("errorCode") == error_code:
                return row
    return None


def _attempt(evidence: dict[str, Any], name: str) -> dict[str, Any] | None:
    attempts = evidence.get("negativeAttempts")
    if not isinstance(attempts, list):
        return None
    rows = [row for row in attempts if isinstance(row, dict) and row.get("name") == name]
    return rows[-1] if rows else None


def _attempt_rejected(evidence: dict[str, Any], name: str, statuses: set[int], error_codes: set[str] | None = None) -> bool:
    row = _attempt(evidence, name)
    if not row or type(row.get("responseStatus")) is not int or row.get("responseStatus") not in statuses:
        return False
    if row.get("databaseRole") != "oid_observer" or row.get("transactionReadOnly") != "on":
        return False
    if error_codes is not None and row.get("errorCode") not in error_codes:
        return False
    for key in ("reportRowsBefore", "reportRowsAfter", "uploadRowsBefore", "uploadRowsAfter"):
        if type(row.get(key)) is not int:
            return False
    return row["reportRowsBefore"] == row["reportRowsAfter"] and row["uploadRowsBefore"] == row["uploadRowsAfter"]


def _same_state_projections(row: dict[str, Any]) -> bool:
    if row.get("effectScope") != "report_and_domain_rows_excluding_oid_rate_limit" \
            or row.get("noReportOrDomainEffects") is not True:
        return False
    for prefix in ("reportState", "domainState"):
        before_text = row.get(f"{prefix}BeforeJson")
        after_text = row.get(f"{prefix}AfterJson")
        before_hash = row.get(f"{prefix}BeforeSha256")
        after_hash = row.get(f"{prefix}AfterSha256")
        if not isinstance(before_text, str) or not isinstance(after_text, str) \
                or len(before_text.encode("utf-8")) > 8 * 1024 * 1024 \
                or len(after_text.encode("utf-8")) > 8 * 1024 * 1024 \
                or not _hash(before_hash) or not _hash(after_hash) \
                or _sha256_text(before_text) != before_hash or _sha256_text(after_text) != after_hash:
            return False
        try:
            before_value = json.loads(before_text)
            after_value = json.loads(after_text)
        except (json.JSONDecodeError, TypeError):
            return False
        if prefix == "reportState":
            expected_keys = {"totalCounts", "reports", "audits", "uploads", "imageUsageRows",
                             "reportDeletionReceipts", "uploadGcReceipts"}
            for value in (before_value, after_value):
                if not isinstance(value, dict) or set(value) != expected_keys \
                        or not isinstance(value.get("totalCounts"), dict) \
                        or set(value["totalCounts"]) != {"reports", "uploads"} \
                        or any(type(value["totalCounts"][key]) is not int or value["totalCounts"][key] < 0
                               for key in ("reports", "uploads")) \
                        or any(not _is_rows(value.get(key)) for key in expected_keys - {"totalCounts"}):
                    return False
            if any(type(row.get(key)) is not int for key in (
                "reportRowsBefore", "reportRowsAfter", "uploadRowsBefore", "uploadRowsAfter"
            )) \
                    or before_value["totalCounts"]["reports"] != row["reportRowsBefore"] \
                    or after_value["totalCounts"]["reports"] != row["reportRowsAfter"] \
                    or before_value["totalCounts"]["uploads"] != row["uploadRowsBefore"] \
                    or after_value["totalCounts"]["uploads"] != row["uploadRowsAfter"]:
                return False
        else:
            expected_keys = {"financialRows", "runRows", "taskRows", "actionRows", "timerRows"}
            if any(not isinstance(value, dict) or set(value) != expected_keys
                   or any(not _is_rows(value.get(key)) for key in expected_keys)
                   for value in (before_value, after_value)):
                return False
        if before_value != after_value:
            return False
    return True


def _rate_limit_snapshot_rows(value: Any, bucket_index: int) -> dict[str, int] | None:
    if not isinstance(value, list):
        return None
    rows: dict[str, int] = {}
    for item in value:
        if not isinstance(item, dict) or not _hash(item.get("keyHashSha256")) \
                or type(item.get("bucketStart")) is not int or item.get("bucketStart") != bucket_index \
                or type(item.get("requestCount")) is not int or item.get("requestCount") < 0:
            return None
        key_hash = item["keyHashSha256"]
        if key_hash in rows:
            return None
        rows[key_hash] = item["requestCount"]
    return rows


def _rate_limit_transition(row: dict[str, Any], prefill_attempt_count: int) -> bool:
    observation = row.get("rateLimitObservation")
    if not isinstance(observation, dict) or observation.get("table") != "oid_rate_limit" \
            or observation.get("group") != "support-report-owner-create" \
            or observation.get("maxPerWindow") != 120 or observation.get("windowSeconds") != 60 \
            or observation.get("databaseRole") != "oid_observer" \
            or observation.get("transactionReadOnly") != "on" \
            or not isinstance(observation.get("databaseName"), str) \
            or re.fullmatch(r"oid_acceptance_[a-f0-9]{32}", observation["databaseName"]) is None:
        return False
    before = observation.get("before")
    after = observation.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    for snapshot in (before, after):
        if snapshot.get("databaseRole") != "oid_observer" or snapshot.get("transactionReadOnly") != "on" \
                or snapshot.get("databaseName") != observation.get("databaseName"):
            return False
    try:
        before_clock = before["databaseClockEpochSeconds"]
        after_clock = after["databaseClockEpochSeconds"]
        before_bucket = before["bucketIndex"]
        after_bucket = after["bucketIndex"]
        before_start = before["bucketStartSeconds"]
        after_start = after["bucketStartSeconds"]
    except KeyError:
        return False
    if any(type(value) is not int for value in (before_clock, after_clock, before_bucket, after_bucket, before_start, after_start)) \
            or before_clock <= 0 or after_clock < before_clock or before_bucket != after_bucket \
            or before_bucket != before_clock // 60 or after_bucket != after_clock // 60 \
            or before_start != before_bucket * 60 or after_start != after_bucket * 60:
        return False
    before_rows = _rate_limit_snapshot_rows(before.get("rows"), before_bucket)
    after_rows = _rate_limit_snapshot_rows(after.get("rows"), after_bucket)
    if before_rows is None or after_rows is None:
        return False
    request_count_delta = prefill_attempt_count + 1
    candidates = []
    for key_hash, final_count in after_rows.items():
        prior_count = before_rows.get(key_hash, 0)
        delta = final_count - prior_count
        if prior_count < 120 and delta == request_count_delta:
            candidates.append((key_hash, prior_count, final_count, delta))
    if len(candidates) != 1:
        return False
    key_hash, prior_count, final_count, delta = candidates[0]
    return observation.get("targetKeyHashSha256") == key_hash \
        and observation.get("priorRequestCount") == prior_count \
        and observation.get("finalRequestCount") == final_count \
        and observation.get("requestCountDelta") == delta \
        and prior_count + prefill_attempt_count == 121 \
        and final_count == prior_count + request_count_delta


def _report_flood_rejected(evidence: dict[str, Any]) -> bool:
    row = _attempt(evidence, "report_flood")
    if row is None or not _attempt_rejected(evidence, "report_flood", {429}, {"RATE_LIMITED"}):
        return False
    attempts = row.get("prefillAttempts")
    valid_shape = row.get("validPayloadShape")
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= 121 or not all(isinstance(item, dict) for item in attempts):
        return False
    if row.get("attemptCap") != 121 or row.get("configuredRateLimitMax") != 120 or row.get("windowSeconds") != 60 \
            or type(row.get("elapsedMs")) is not int \
            or not 0 <= row["elapsedMs"] < 55_000:
        return False
    if any(item.get("responseStatus") != 400 or item.get("errorCode") != "INVALID_REPORT" for item in attempts[:-1]):
        return False
    if attempts[-1].get("responseStatus") != 429 or attempts[-1].get("errorCode") != "RATE_LIMITED":
        return False
    if not isinstance(valid_shape, dict) or valid_shape.get("fieldNames") != ["body", "operationId", "title"] \
            or valid_shape.get("operationIdIsCanonical") is not True \
            or type(valid_shape.get("titleLength")) is not int or not 1 <= valid_shape["titleLength"] <= 160 \
            or type(valid_shape.get("bodyLength")) is not int or not 1 <= valid_shape["bodyLength"] <= 4000 \
            or not _hash(row.get("validOperationIdSha256")):
        return False
    return _rate_limit_transition(row, len(attempts)) and _same_state_projections(row)


def _owner_ui_issue_response_matches_binding(issuance: dict[str, Any], binding: dict[str, Any], agent_id: str) -> bool:
    response_ids = issuance.get("issueResponseIdHashes")
    return isinstance(response_ids, dict) and response_ids.get("status") == 201 \
        and response_ids.get("agentIdSha256") == _sha256_text(agent_id) \
        and response_ids.get("credentialIdSha256") == binding.get("credentialIdSha256") \
        and response_ids.get("grantIdSha256") == binding.get("grantIdSha256")


def _agent_admin_attempt_rejected(evidence: dict[str, Any]) -> bool:
    proof = evidence.get("agentBearerProof")
    binding = proof.get("credentialBinding") if isinstance(proof, dict) else None
    preflight = proof.get("preflight") if isinstance(proof, dict) else None
    issuance = proof.get("ownerUiIssuance") if isinstance(proof, dict) else None
    if not isinstance(proof, dict) or not isinstance(binding, dict) or not isinstance(preflight, dict) \
            or not isinstance(issuance, dict):
        return False
    if _contains_agent_credential_material(proof):
        return False
    if proof.get("credentialSource") != "owner_ui_issue_once" or proof.get("fixtureType") != "synthetic_local_agent_credential" \
            or proof.get("authorizationScheme") != "Bearer" or proof.get("sessionCookiePresent") is not False:
        return False
    if binding.get("databaseRole") != "oid_observer" or binding.get("transactionReadOnly") != "on" \
            or type(binding.get("matchingCredentialGrantRows")) is not int \
            or binding.get("matchingCredentialGrantRows") != 1 or binding.get("grantSource") != "manual" \
            or binding.get("grantRole") != "agent" or binding.get("grantRevokedAt") is not None:
        return False
    binding_hashes = (binding.get("credentialIdSha256"), binding.get("grantIdSha256"),
                      binding.get("ownerIdSha256"), binding.get("agentIdSha256"), binding.get("resourceSha256"))
    if not all(_hash(value) for value in binding_hashes):
        return False
    try:
        grant_expiry = datetime.fromisoformat(str(binding.get("grantExpiresAt")).replace("Z", "+00:00"))
        binding_observed = datetime.fromisoformat(str(binding.get("observedAt")).replace("Z", "+00:00"))
        if grant_expiry.tzinfo is None or binding_observed.tzinfo is None or grant_expiry <= binding_observed:
            return False
    except (ValueError, TypeError):
        return False
    issuance_actions = issuance.get("actions")
    issuance_requests = issuance.get("requests")
    if not isinstance(issuance_actions, list) or not isinstance(issuance_requests, list):
        return False
    issued_agent_id = None
    for row in issuance_requests:
        if not isinstance(row, dict) or row.get("method") != "POST" or row.get("status") != 201 \
                or not isinstance(row.get("path"), str):
            continue
        match = re.fullmatch(r"/api/owner/agents/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/manual-credential", row["path"])
        if match:
            issued_agent_id = match.group(1)
            break
    if not issued_agent_id or _sha256_text(issued_agent_id) != binding.get("agentIdSha256") \
            or not _owner_ui_issue_response_matches_binding(issuance, binding, issued_agent_id) \
            or not any(isinstance(row, dict) and row.get("method") == "POST" and row.get("path") == "/api/owner/agents"
                       and row.get("status") == 201 for row in issuance_requests) \
            or not any(isinstance(row, dict) and row.get("action") == "click" and row.get("controlId") == "agent-create"
                       for row in issuance_actions) \
            or not any(isinstance(row, dict) and row.get("action") == "click"
                       and row.get("controlId") == f"credential-issue-{issued_agent_id}" for row in issuance_actions):
        return False
    if preflight.get("method") != "GET" or preflight.get("path") != "/api/agent/preflight" \
            or preflight.get("responseStatus") != 200 or preflight.get("allowed") is not True \
            or preflight.get("role") != "agent" or preflight.get("authorizationScheme") != "Bearer" \
            or preflight.get("sessionCookiePresent") is not False or preflight.get("resourceMatches") is not True \
            or preflight.get("agentIdSha256") != binding.get("agentIdSha256") \
            or preflight.get("resourceSha256") != binding.get("resourceSha256"):
        return False

    pair = _snapshot_pair(evidence)
    if pair is None:
        return False
    before, after = pair
    report_hash = proof.get("targetReportIdSha256")
    image_hash = proof.get("targetImageIdSha256")
    if not _hash(report_hash) or not _hash(image_hash):
        return False
    report = next((item for item in after["reports"] if _sha256_text(item.get("id")) == report_hash), None)
    if not isinstance(report, dict) or report.get("ownerIdSha256") != binding.get("ownerIdSha256") \
            or not isinstance(report.get("imageIds"), list) \
            or not any(_sha256_text(image_id) == image_hash for image_id in report["imageIds"]):
        return False
    image = next((item for item in after["uploads"] if _sha256_text(item.get("id")) == image_hash), None)
    if not isinstance(image, dict) or image.get("status") != "attached" or image.get("reportId") != report.get("id") \
            or image.get("ownerIdSha256") != binding.get("ownerIdSha256") or not _hash(image.get("outputSha256")):
        return False
    previews = evidence.get("browser", {}).get("previews") if isinstance(evidence.get("browser"), dict) else None
    if not isinstance(previews, list) or not any(
        isinstance(item, dict) and item.get("accessRole") == "admin" and item.get("status") == 200
        and item.get("sha256") == image.get("outputSha256") for item in previews
    ):
        return False

    attempts = evidence.get("negativeAttempts")
    rows = [item for item in attempts if isinstance(item, dict) and item.get("name") == "agent_admin_attempt"] \
        if isinstance(attempts, list) else []
    if _contains_agent_credential_material(rows):
        return False
    expected = {
        "admin_list": ("GET", "/api/admin/reports"),
        "admin_detail": ("GET", "/api/admin/reports/{reportId}"),
        "admin_status": ("PATCH", "/api/admin/reports/{reportId}/status"),
        "admin_image": ("GET", "/api/admin/reports/{reportId}/images/{imageId}"),
    }
    if len(rows) != len(expected) or {item.get("probe") for item in rows} != set(expected):
        return False
    for item in rows:
        route = expected.get(item.get("probe"))
        if route is None or (item.get("method"), item.get("pathTemplate")) != route:
            return False
        if item.get("responseStatus") != 401 or item.get("errorCode") != "UNAUTHORIZED" \
                or item.get("databaseRole") != "oid_observer" or item.get("transactionReadOnly") != "on" \
                or type(item.get("reportRowsBefore")) is not int \
                or type(item.get("reportRowsAfter")) is not int \
                or item.get("reportRowsBefore") != item.get("reportRowsAfter") \
                or type(item.get("uploadRowsBefore")) is not int \
                or type(item.get("uploadRowsAfter")) is not int \
                or item.get("uploadRowsBefore") != item.get("uploadRowsAfter") \
                or not _same_state_projections(item):
            return False
        if item.get("transport") != "cookie_free_agent_bearer_http" \
                or item.get("authorizationScheme") != "Bearer" or item.get("sessionCookiePresent") is not False \
                or item.get("credentialIdSha256") != binding.get("credentialIdSha256") \
                or item.get("grantIdSha256") != binding.get("grantIdSha256") \
                or item.get("agentIdSha256") != binding.get("agentIdSha256") \
                or item.get("ownerIdSha256") != binding.get("ownerIdSha256") \
                or item.get("targetReportIdSha256") != report_hash or item.get("targetImageIdSha256") != image_hash:
            return False
    return True


def _side_effects_unchanged(evidence: dict[str, Any]) -> bool:
    pair = _snapshot_pair(evidence)
    if not pair:
        return False
    before, after = pair
    return all(_same(before[name], after[name]) for name in ("financialRows", "runRows", "taskRows", "actionRows", "timerRows"))


def _foreign_run_and_action_rejected(evidence: dict[str, Any]) -> bool:
    pair = _snapshot_pair(evidence)
    run_attempt = _attempt(evidence, "foreign_run_or_action")
    action_attempt = _attempt(evidence, "foreign_action_link")
    if pair is None or not _attempt_rejected(evidence, "foreign_run_or_action", {400, 404}, {"REPORT_LINK_NOT_FOUND", "INVALID_REPORT_LINK"}):
        return False
    if not _attempt_rejected(evidence, "foreign_action_link", {400, 404}, {"REPORT_LINK_NOT_FOUND", "INVALID_REPORT_LINK"}):
        return False
    assert run_attempt is not None and action_attempt is not None
    before, _after = pair
    run_rows = before["runRows"]
    action_rows = before["actionRows"]
    foreign_run_id_hash = run_attempt.get("runIdSha256")
    foreign_owner_hash = run_attempt.get("foreignOwnerIdSha256")
    request_run_id_hash = action_attempt.get("requestRunIdSha256")
    request_owner_hash = action_attempt.get("requestOwnerIdSha256")
    action_id_hash = action_attempt.get("actionIdSha256")
    action_run_id_hash = action_attempt.get("actionRunIdSha256")
    action_owner_hash = action_attempt.get("actionOwnerIdSha256")
    if not all(_hash(value) for value in (foreign_run_id_hash, foreign_owner_hash, request_run_id_hash,
                                          request_owner_hash, action_id_hash, action_run_id_hash, action_owner_hash)):
        return False
    foreign_run = next((row for row in run_rows if _sha256_text(row.get("id")) == foreign_run_id_hash), None)
    request_run = next((row for row in run_rows if _sha256_text(row.get("id")) == request_run_id_hash), None)
    foreign_action = next((row for row in action_rows if _sha256_text(row.get("id")) == action_id_hash), None)
    if not foreign_run or not request_run or not foreign_action:
        return False
    return (
        foreign_run.get("ownerIdSha256") == foreign_owner_hash
        and request_run.get("ownerIdSha256") == request_owner_hash
        and request_owner_hash != foreign_owner_hash
        and request_run_id_hash != foreign_run_id_hash
        and _sha256_text(foreign_action.get("runId")) == action_run_id_hash == foreign_run_id_hash
        and foreign_action.get("ownerIdSha256") == action_owner_hash == foreign_owner_hash
    )


def _report_for_operation(evidence: dict[str, Any], operation_hash: str) -> dict[str, Any] | None:
    return next((row for row in _report_rows(evidence) if row.get("operationIdSha256") == operation_hash), None)


def _report_id(report: dict[str, Any]) -> str | None:
    value = report.get("id")
    return value if isinstance(value, str) and value else None


def _report_has_action_link(evidence: dict[str, Any], report: dict[str, Any]) -> bool:
    pair = _snapshot_pair(evidence)
    if not pair:
        return False
    action_id = report.get("actionId")
    run_id = report.get("runId")
    if not isinstance(action_id, str) or not isinstance(run_id, str):
        return False
    return any(
        row.get("id") == action_id and row.get("runId") == run_id
        and row.get("ownerIdSha256") == report.get("ownerIdSha256")
        and row.get("agentIdSha256") == report.get("reporterIdSha256")
        for row in pair[1]["actionRows"]
    )


def _image_links_match_files(evidence: dict[str, Any], report: dict[str, Any]) -> bool:
    pair = _snapshot_pair(evidence)
    storage = evidence.get("storage")
    files = storage.get("images") if isinstance(storage, dict) else None
    if not pair or not isinstance(files, list) or not isinstance(report.get("imageIds"), list):
        return False
    uploads = pair[1]["uploads"]
    linked_ids = set(report["imageIds"])
    if not linked_ids:
        return False
    by_upload = {row.get("id"): row for row in uploads if isinstance(row.get("id"), str)}
    by_file = {row.get("imageId"): row for row in files if isinstance(row, dict)}
    for image_id in linked_ids:
        upload = by_upload.get(image_id)
        file = by_file.get(image_id)
        if not upload or not file or upload.get("reportId") != report.get("id") or upload.get("status") != "attached":
            return False
        digest = upload.get("outputSha256")
        if not _hash(digest) or file.get("sha256FromDatabase") != digest or file.get("sha256FromDisk") != digest:
            return False
        if type(upload.get("outputBytes")) is not int or upload.get("outputBytes") != file.get("databaseBytes") or file.get("databaseBytes") != file.get("diskBytes"):
            return False
        if file.get("modeBits") not in (0o600, 0o640) or file.get("contentType") != "image/webp":
            return False
        if not _hash(upload.get("storageKeySha256")) or file.get("storageKeySha256") != upload.get("storageKeySha256"):
            return False
        if not _hash(file.get("privateRootSha256")) or file.get("parentDirectorySha256") != file.get("privateRootSha256"):
            return False
    return True


def _safe_context(report: dict[str, Any]) -> bool:
    keys = report.get("safeContextKeys")
    context = report.get("safeContext")
    if not isinstance(keys, list) or not isinstance(context, dict) or set(keys) != set(context) or not set(keys) <= SAFE_CONTEXT_KEYS:
        return False
    if context.get("runContext") not in ("linked", "unavailable"):
        return False
    if "capturedAt" in context:
        try:
            datetime.fromisoformat(str(context["capturedAt"]).replace("Z", "+00:00"))
        except ValueError:
            return False
    if isinstance(context.get("requestId"), dict) and not _hash(context["requestId"].get("sha256")):
        return False
    if isinstance(context.get("requestId"), dict) and set(context["requestId"]) != {"sha256"}:
        return False
    if isinstance(context.get("requestId"), str):
        return False
    if "requestIdSha256" in report and not _hash(report["requestIdSha256"]):
        return False
    return True


def _html_is_text(evidence: dict[str, Any]) -> bool:
    browser = evidence.get("browser")
    probes = browser.get("textProbes") if isinstance(browser, dict) else None
    if not isinstance(probes, list):
        return False
    reports = _report_rows(evidence)
    return any(
        isinstance(row, dict) and row.get("probe") == "html-report-render"
        and type(row.get("scriptElementCount")) is int and row["scriptElementCount"] == 0
        and _hash(row.get("expectedTextSha256")) and row.get("expectedTextSha256") == row.get("observedTextSha256")
        and any(report.get("bodySha256") == row.get("expectedTextSha256") for report in reports)
        and row.get("status") in (200, 201)
        for row in probes
    )


def _derive_018(evidence: dict[str, Any]) -> dict[str, bool]:
    pair = _snapshot_pair(evidence)
    reports = pair[1]["reports"] if pair else []
    linked = [row for row in reports if row.get("source") == "owner" and isinstance(row.get("runIdSha256"), str)]
    unlinked = [row for row in reports if row.get("source") == "owner" and row.get("runIdSha256") is None]
    previews = evidence.get("browser", {}).get("previews", []) if isinstance(evidence.get("browser"), dict) else []
    requests = evidence.get("browser", {}).get("requests", []) if isinstance(evidence.get("browser"), dict) else []
    submit_requests = [row for row in requests if isinstance(row, dict) and row.get("method") == "POST" and row.get("path") == "/api/owner/reports" and row.get("status") in (200, 201)]
    submitted_hashes = {row.get("operationIdSha256") for row in submit_requests if _hash(row.get("operationIdSha256"))}
    persisted_hashes = {row.get("operationIdSha256") for row in linked + unlinked if _hash(row.get("operationIdSha256"))}
    retry_rows = evidence.get("responseLossRetries")
    retry_ok = isinstance(retry_rows, list) and any(
        isinstance(row, dict) and row.get("firstResponse") == "lost" and type(row.get("retryStatus")) is int and row["retryStatus"] == 200
        and _hash(row.get("operationIdSha256")) and row.get("operationIdSha256") in persisted_hashes
        and _hash(row.get("originalReportIdSha256")) and row.get("originalReportIdSha256") == row.get("retryReportIdSha256")
        and type(row.get("persistedRowsForOperation")) is int and row["persistedRowsForOperation"] == 1
        for row in retry_rows
    )
    owner_image_request = any(
        isinstance(row, dict) and row.get("method") == "POST" and row.get("path") == "/api/owner/report-images/uploads/multipart"
        and row.get("status") in (200, 201) for row in requests
    )
    return {
        "linked_and_unlinked_report_saved": _click(evidence, "owner-report-submit-linked") and _click(evidence, "owner-report-submit-unlinked")
        and bool(linked) and bool(unlinked) and bool(submitted_hashes & persisted_hashes)
        and all(_hash(row.get("operationIdSha256")) for row in linked + unlinked),
        "safe_auto_context": bool(linked or unlinked) and all(_safe_context(row) for row in linked + unlinked),
        "one_receipt_retry": retry_ok,
        "no_billing_or_task_effect": _side_effects_unchanged(evidence),
        "owner_form_image_upload_and_preview": _click(evidence, "owner-report-image-preview") and owner_image_request and any(
            isinstance(row, dict) and row.get("accessRole") == "owner" and row.get("status") == 200
            and isinstance(row.get("sha256"), str) and _hash(row["sha256"]) for row in previews
        ),
        "report_image_links_match_private_storage": any(_image_links_match_files(evidence, report) for report in linked + unlinked),
    }


def _derive_019(evidence: dict[str, Any]) -> dict[str, bool]:
    pair = _snapshot_pair(evidence)
    reports = pair[1]["reports"] if pair else []
    clients = evidence.get("nativeClients")
    required_families = {"codex", "claude-code", "claude-desktop", "hermes"}
    client_rows = [row for row in clients if isinstance(row, dict)] if isinstance(clients, list) else []
    clients_by_family = {row.get("family"): row for row in client_rows if row.get("family") in required_families}
    agent_reports = [row for row in reports if row.get("source") == "agent" and row.get("reporterKind") == "agent"]
    report_agents = {row.get("reporterIdSha256") for row in agent_reports if _hash(row.get("reporterIdSha256"))}
    reports_by_id = {row.get("id"): row for row in agent_reports if isinstance(row.get("id"), str)}
    client_reports = [reports_by_id.get(row.get("reportId")) for row in clients_by_family.values()]
    all_clients_persisted = len(clients_by_family) == 4 and len(client_rows) == 4 and all(
        isinstance(report, dict) and client.get("responseStatus") in (200, 201)
        and _hash(client.get("clientSnapshotSha256")) and _hash(client.get("operationIdSha256"))
        and report.get("operationIdSha256") == client.get("operationIdSha256")
        and report.get("reporterIdSha256") == client.get("agentIdSha256")
        for client in clients_by_family.values() for report in [reports_by_id.get(client.get("reportId"))]
    )
    run_rows = pair[1]["runRows"] if pair else []
    task_rows = pair[1]["taskRows"] if pair else []
    action_rows = pair[1]["actionRows"] if pair else []
    links_valid = bool(agent_reports) and all(
        (row.get("runId") is None and row.get("taskId") is None and row.get("actionId") is None)
        or (
            isinstance(row.get("runId"), str)
            and any(run.get("id") == row.get("runId") and run.get("ownerIdSha256") == row.get("ownerIdSha256") for run in run_rows)
            and (row.get("taskId") is None or any(task.get("runId") == row.get("runId") and task.get("taskId") == row.get("taskId") for task in task_rows))
            and (row.get("actionId") is None or _report_has_action_link(evidence, row))
        ) for row in agent_reports
    )
    uploads = pair[1]["uploads"] if pair else []
    agent_uploads = [row for row in uploads if row.get("uploaderKind") == "agent" and row.get("status") == "attached"]
    owned_uploads = [row for row in agent_uploads if row.get("uploaderIdSha256") in report_agents and row.get("reportId") in reports_by_id
                     and row.get("uploaderIdSha256") == reports_by_id[row["reportId"]].get("reporterIdSha256")]
    chunks = evidence.get("mcpFrames")
    chunk_rows = [row for row in chunks if isinstance(row, dict)] if isinstance(chunks, list) else []
    chunk_bound = bool(chunk_rows) and all(
        row.get("tool") == "support.screenshot.chunk"
        and type(row.get("serializedBytes")) is int and 0 < row["serializedBytes"] <= 64 * 1024
        and type(row.get("decodedBytes")) is int and 0 < row["decodedBytes"] <= 24 * 1024
        for row in chunk_rows
    )
    owner_audit = any(
        row.get("eventType") == "owner_attached_image" and row.get("reportId") in reports_by_id
        and row.get("actorOwnerIdSha256") == reports_by_id[row["reportId"]].get("ownerIdSha256")
        for row in (pair[1]["audits"] if pair else [])
    )
    restart_rows = evidence.get("restartReceipts")
    return {
        "four_clients_report_as_principal": set(clients_by_family) == required_families and all_clients_persisted,
        "valid_links_or_no_run": links_valid,
        "original_receipt_after_restart": isinstance(restart_rows, list) and any(
            isinstance(row, dict) and _hash(row.get("operationIdSha256"))
            and row.get("beforeReportIdSha256") == row.get("afterReportIdSha256")
            and _hash(row.get("beforeReportIdSha256"))
            and any(report.get("operationIdSha256") == row.get("operationIdSha256") and report.get("idSha256") == row.get("beforeReportIdSha256") for report in agent_reports)
            for row in restart_rows
        ),
        "unchanged_ledger_task_timer": _side_effects_unchanged(evidence),
        "native_agent_optional_image_upload_reference": bool(agent_uploads),
        "screenshot_links_owned_by_agent": bool(owned_uploads),
        "native_chunk_or_audited_owner_upload_path": chunk_bound or owner_audit,
    }


def _derive_020(evidence: dict[str, Any]) -> dict[str, bool]:
    pair = _snapshot_pair(evidence)
    reports = pair[1]["reports"] if pair else []
    browser = evidence.get("browser")
    list_probe = browser.get("adminListProbe") if isinstance(browser, dict) else None
    text_ok = _html_is_text(evidence)
    audits = pair[1]["audits"] if pair else []
    status_rows = [row for row in audits if row.get("eventType") == "status_changed"]
    completed_cycle = any(row.get("nextStatus") == "closed" for row in status_rows) and any(row.get("nextStatus") == "in_progress" for row in status_rows)
    previews = browser.get("previews", []) if isinstance(browser, dict) else []
    private_reads = browser.get("privateReads", []) if isinstance(browser, dict) else []
    report_by_id = {row.get("id"): row for row in reports if isinstance(row, dict)}
    admin_hashes = {row.get("sha256") for row in previews if isinstance(row, dict) and row.get("accessRole") == "admin" and row.get("status") == 200}
    owner_hashes = {row.get("sha256") for row in previews if isinstance(row, dict) and row.get("accessRole") == "owner" and row.get("status") == 200}
    persisted_preview_hashes = {
        image.get("outputSha256") for image in (pair[1]["uploads"] if pair else [])
        if isinstance(image, dict) and image.get("status") == "attached" and _hash(image.get("outputSha256"))
    }
    revision_ok = False
    for report in reports:
        matching = [row for row in status_rows if row.get("reportId") == report.get("id")]
        transitions = [(row.get("previousStatus"), row.get("nextStatus")) for row in matching]
        revisions = [row.get("revision") for row in matching]
        if (report.get("revision") == max(revisions, default=0) and type(report.get("revision")) is int
            and all(type(revision) is int for revision in revisions)
            and all(right == left + 1 for left, right in zip(revisions, revisions[1:]))
            and ("new", "closed") in transitions and ("closed", "in_progress") in transitions):
            revision_ok = True
    return {
        "list_filters_match_db": _click(evidence, "admin-report-filter") and isinstance(list_probe, dict)
        and isinstance(list_probe.get("displayedReportIds"), list) and list_probe.get("displayedReportIds") == list_probe.get("observerReportIds"),
        "safe_detail_text": text_ok,
        "status_audit_revision": completed_cycle and revision_ok,
        "own_owner_projection": any(
            row.get("method") == "GET" and row.get("accessRole") == "owner" and row.get("status") == 200
            and row.get("reportId") in report_by_id and row.get("reportOwnerIdSha256") == report_by_id[row["reportId"]].get("ownerIdSha256")
            for row in private_reads if isinstance(row, dict)
        ) and any(
            row.get("method") == "GET" and row.get("accessRole") == "foreign-owner" and row.get("status") == 404
            for row in private_reads if isinstance(row, dict)
        ),
        "admin_and_own_owner_image_preview_hash_match": bool(admin_hashes & owner_hashes & persisted_preview_hashes),
    }


def _derive_024(evidence: dict[str, Any]) -> dict[str, bool]:
    pair = _snapshot_pair(evidence)
    uploads = pair[1]["uploads"] if pair else []
    storage = evidence.get("storage")
    files = storage.get("images") if isinstance(storage, dict) else None
    valid_uploads = [row for row in uploads if row.get("status") in ("ready", "attached")]
    pixel_and_bytes = bool(valid_uploads) and all(
        row.get("inputMime") in ("image/png", "image/jpeg", "image/webp")
        and type(row.get("expectedInputBytes")) is int and 1 <= row["expectedInputBytes"] <= 5 * 1024 * 1024
        and row.get("outputMime") == "image/webp"
        and type(row.get("outputBytes")) is int and 1 <= row["outputBytes"] <= 5 * 1024 * 1024
        and type(row.get("width")) is int and type(row.get("height")) is int
        and row["width"] * row["height"] <= 16_000_000
        and _hash(row.get("inputSha256")) and _hash(row.get("outputSha256"))
        for row in valid_uploads
    )
    clean_metadata = isinstance(files, list) and bool(files) and all(
        isinstance(row, dict) and row.get("metadataKeys") == []
        and _hash(row.get("sha256FromDatabase"))
        and row.get("sha256FromDatabase") == row.get("sha256FromDisk")
        and row.get("databaseBytes") == row.get("diskBytes")
        and type(row.get("databaseBytes")) is int and row["databaseBytes"] > 0
        and _hash(row.get("storageKeySha256"))
        and _hash(row.get("privateRootSha256")) and row.get("parentDirectorySha256") == row.get("privateRootSha256")
        and row.get("modeBits") in (0o600, 0o640)
        for row in files
    )
    reports = pair[1]["reports"] if pair else []
    by_report = {row.get("id"): row for row in reports}
    principal_bound = bool([row for row in uploads if row.get("status") == "attached"]) and all(
        row.get("reportId") in by_report
        and row.get("ownerIdSha256") == by_report[row["reportId"]].get("ownerIdSha256")
        and _hash(row.get("ownerIdSha256")) and _hash(row.get("uploaderIdSha256"))
        and ((row.get("uploaderKind") == "owner" and row.get("uploaderIdSha256") == row.get("ownerIdSha256"))
             or (row.get("uploaderKind") == "agent" and row.get("uploaderIdSha256") == by_report[row["reportId"]].get("reporterIdSha256")))
        and by_report[row["reportId"]].get("imageIds") and row.get("id") in by_report[row["reportId"]].get("imageIds", [])
        for row in uploads if row.get("status") == "attached"
    )
    retries = evidence.get("uploadRetries")
    retry_ok = isinstance(retries, list) and any(
        isinstance(row, dict) and _hash(row.get("operationIdSha256"))
        and row.get("firstUploadIdSha256") == row.get("retryUploadIdSha256")
        and _hash(row.get("firstUploadIdSha256"))
        and row.get("firstPayloadSha256") == row.get("retryPayloadSha256") and _hash(row.get("firstPayloadSha256"))
        and type(row.get("persistedRowsForOperation")) is int and row.get("persistedRowsForOperation") == 1
        and row.get("firstUploadIdSha256") in {upload.get("idSha256") for upload in uploads}
        for row in retries
    )
    previews = evidence.get("browser", {}).get("previews", []) if isinstance(evidence.get("browser"), dict) else []
    preview_roles = {row.get("accessRole") for row in previews if isinstance(row, dict) and row.get("status") == 200 and _hash(row.get("sha256"))}
    preview_hashes = {row.get("sha256") for row in previews if isinstance(row, dict) and row.get("status") == 200 and _hash(row.get("sha256"))}
    persisted_hashes = {row.get("outputSha256") for row in uploads if row.get("status") == "attached" and _hash(row.get("outputSha256"))}
    private_preview = {"owner", "admin"} <= preview_roles and bool(preview_hashes & persisted_hashes)
    sweep = evidence.get("orphanSweep")
    preserved = isinstance(sweep, dict) and isinstance(sweep.get("committedImagesBefore"), list) and sweep.get("committedImagesBefore") == sweep.get("committedImagesAfter")
    frames = evidence.get("mcpFrames")
    frame_rows = [row for row in frames if isinstance(row, dict)] if isinstance(frames, list) else []
    frame_bound = bool(frame_rows) and all(
        isinstance(row, dict) and row.get("tool") == "support.screenshot.chunk"
        and type(row.get("serializedBytes")) is int and 1 <= row["serializedBytes"] <= 64 * 1024
        and type(row.get("decodedBytes")) is int and 1 <= row["decodedBytes"] <= 24 * 1024 for row in frame_rows
    )
    cap = evidence.get("imageCapRace")
    cap_ok = isinstance(cap, dict) and type(cap.get("attachedCountAfter")) is int and cap.get("attachedCountAfter") == 3 \
        and isinstance(cap.get("responseStatuses"), list) and all(type(status) is int for status in cap["responseStatuses"]) \
        and sorted(cap["responseStatuses"]) == [201, 201, 409]
    quota_ok = all((
        _attempt_rejected(evidence, "rolling_owner_quota", {429}, {"REPORT_IMAGE_ROLLING_QUOTA"}),
        _attempt_rejected(evidence, "staging_capacity_race", {429}, {"REPORT_IMAGE_STAGING_LIMIT"}),
        _attempt_rejected(evidence, "normalized_output_over_limit", {400}, {"INVALID_REPORT_IMAGE"}),
        _attempt_rejected(evidence, "insufficient_disk_or_backup_space", {507}, {"REPORT_IMAGE_STORAGE_LOW", "REPORT_IMAGE_STORAGE_LIMIT"}),
    ))
    return {
        "decoded_format_size_pixels_validated": pixel_and_bytes,
        "normalized_bytes_metadata_stripped": clean_metadata,
        "principal_bound_upload_and_report_link": principal_bound,
        "three_image_cap_atomic": cap_ok,
        "image_retry_recovers_original": retry_ok,
        "private_owner_admin_preview": private_preview,
        "orphan_cleanup_preserves_committed": preserved,
        "no_task_billing_refund_effect": _side_effects_unchanged(evidence),
        "mcp_chunk_frames_under_64kib": frame_bound,
        "output_and_aggregate_upload_quotas_enforced": quota_ok,
    }


def _derive_026(evidence: dict[str, Any]) -> dict[str, bool]:
    retention = evidence.get("retention")
    pair = _snapshot_pair(evidence)
    if not isinstance(retention, dict) or not pair:
        return {}
    ended_at = retention.get("betaEndedAt")
    expires_at = retention.get("expiresAt")
    try:
        ended = datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        deadline_matches = ended.tzinfo is not None and expires.tzinfo is not None \
            and ended.utcoffset() == timedelta(0) and expires.utcoffset() == timedelta(0) \
            and expires == ended + timedelta(days=30)
    except (ValueError, TypeError):
        deadline_matches = False
    before, after = pair
    receipts = after["reportDeletionReceipts"]
    expired_before = {
        row.get("id") for row in before["reports"] if isinstance(row.get("id"), str)
        and isinstance(row.get("expiresAt"), str) and _is_expired(row["expiresAt"], expires_at)
    }
    expired_after = {
        row.get("id") for row in after["reports"] if isinstance(row.get("id"), str)
        and isinstance(row.get("expiresAt"), str) and _is_expired(row["expiresAt"], expires_at)
    }
    receipts_by_report = {row.get("reportId"): row for row in receipts if isinstance(row.get("reportId"), str)}
    receipts_ok = bool(expired_before) and expired_before <= receipts_by_report.keys() and all(
        row.get("purgeStatus") in ("pending", "failed", "complete")
        and type(row.get("imageCount")) is int and row.get("imageCount") >= 0
        and isinstance(row.get("pendingStorageKeySha256s"), list)
        and all(_hash(key_hash) for key_hash in row["pendingStorageKeySha256s"])
        and not (set(row) & {"body", "title", "safeContext", "storageKey", "pendingStorageKeys"})
        for row in receipts_by_report.values()
    )
    expired_read = retention.get("readAtExpiry")
    upload_attempt = retention.get("uploadAtExpiry")
    expired_image_ids_before = {
        row.get("id") for row in before["uploads"] if row.get("status") == "attached" and row.get("reportId") in expired_before
    }
    expired_image_ids_after = {
        row.get("id") for row in after["uploads"] if row.get("status") == "attached" and row.get("reportId") in expired_before
    }
    storage = evidence.get("storage")
    storage_before = storage.get("imagesBefore") if isinstance(storage, dict) else None
    storage_after = storage.get("imagesAfter") if isinstance(storage, dict) else None
    stored_before = {row.get("imageId") for row in storage_before if isinstance(row, dict)} if isinstance(storage_before, list) else set()
    stored_after = {row.get("imageId") for row in storage_after if isinstance(row, dict)} if isinstance(storage_after, list) else set()
    image_files_purged = expired_image_ids_before <= stored_before and not (expired_image_ids_before & stored_after)
    restore = retention.get("restore")
    restore_pair = _snapshot_pair({"observer": restore.get("observer")}) if isinstance(restore, dict) else None
    restore_storage_before = restore.get("storageImagesBefore") if isinstance(restore, dict) else None
    restore_storage_after = restore.get("storageImagesAfter") if isinstance(restore, dict) else None
    restore_files_before = {row.get("imageId") for row in restore_storage_before if isinstance(row, dict)} if isinstance(restore_storage_before, list) else set()
    restore_files_after = {row.get("imageId") for row in restore_storage_after if isinstance(row, dict)} if isinstance(restore_storage_after, list) else set()
    restore_api = restore.get("readAfterPurge") if isinstance(restore, dict) else None
    no_restore = bool(restore_pair) and bool(expired_before) \
        and expired_before <= {row.get("id") for row in restore_pair[0]["reports"]} \
        and not (expired_before & {row.get("id") for row in restore_pair[1]["reports"]}) \
        and expired_image_ids_before <= restore_files_before and not (expired_image_ids_before & restore_files_after) \
        and isinstance(restore_api, dict) and restore_api.get("status") == 410 and restore_api.get("errorCode") == "REPORT_RETENTION_EXPIRED"
    cleanup_attempts = retention.get("cleanupAttempts")
    cleanup_rows = [row for row in cleanup_attempts if isinstance(row, dict)] if isinstance(cleanup_attempts, list) else []
    delete_failure_observed = any(
        row.get("deleteStatus") == "failed" and type(row.get("readStatus")) is int and row.get("readStatus") == 410
        and row.get("reportId") in receipts_by_report and receipts_by_report[row["reportId"]].get("purgeStatus") == "failed"
        for row in cleanup_rows
    )
    repeated_cleanup = len(cleanup_rows) >= 2 and all(
        type(row.get("httpStatus")) is int and row.get("httpStatus") == 200
        and type(row.get("receiptCount")) is int and row.get("receiptCount") >= 0
        for row in cleanup_rows[-2:]
    ) and cleanup_rows[-1].get("receiptCount") == cleanup_rows[-2].get("receiptCount") \
        and cleanup_rows[-1].get("receiptIdsSha256") == cleanup_rows[-2].get("receiptIdsSha256")
    restart_read = retention.get("restartRead")
    restart_ok = isinstance(restart_read, dict) and type(restart_read.get("status")) is int \
        and restart_read.get("status") == 410 and restart_read.get("errorCode") == "REPORT_RETENTION_EXPIRED"
    return {
        "retention_from_beta_end": deadline_matches and retention.get("closeAudit") == "beta_closed"
        and retention.get("authoritativeBetaEndedAt") == ended_at and _hash(retention.get("closureEvidenceSha256"))
        and _click(evidence, "admin-close-beta-retention"),
        "access_denied_at_expiry": isinstance(expired_read, dict) and type(expired_read.get("status")) is int
        and expired_read.get("status") == 410 and expired_read.get("errorCode") == "REPORT_RETENTION_EXPIRED"
        and isinstance(upload_attempt, dict) and type(upload_attempt.get("status")) is int
        and upload_attempt.get("status") in (410, 409),
        "content_and_images_purged": bool(expired_before) and expired_before <= receipts_by_report.keys()
        and not (expired_before & expired_after) and not expired_image_ids_after and image_files_purged
        and all(receipts_by_report[report_id].get("purgeStatus") == "complete" for report_id in expired_before),
        "tombstones_retained": receipts_ok and all(row.get("purgeStatus") in ("complete", "failed") for row in receipts_by_report.values()),
        "no_restore_resurrection": no_restore,
        "ledger_grades_unchanged": _side_effects_unchanged(evidence),
    }


def _is_expired(value: Any, cutoff_value: Any) -> bool:
    if not isinstance(value, str) or not isinstance(cutoff_value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        cutoff = datetime.fromisoformat(cutoff_value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.tzinfo is not None and cutoff.tzinfo is not None and timestamp <= cutoff


def _required_inventory(evidence: dict[str, Any], scenario_id: str) -> bool:
    if evidence.get("schemaVersion") != "bpc-report-runtime-observation/v1" or evidence.get("scenarioId") != scenario_id:
        return False
    if evidence.get("boundaryDetail") != BOUNDARY_DETAILS[scenario_id] or evidence.get("captureBoundary") != "actual_target_host":
        return False
    browser = evidence.get("browser")
    if _snapshot_pair(evidence) is None:
        return False
    attempts = evidence.get("negativeAttempts")
    if not isinstance(attempts, list) or not set(NEGATIVE_NAMES[scenario_id]) <= {item.get("name") for item in attempts if isinstance(item, dict)}:
        return False
    for item in attempts:
        if isinstance(item, dict) and item.get("name") in NEGATIVE_NAMES[scenario_id]:
            if item.get("databaseRole") != "oid_observer" or item.get("transactionReadOnly") != "on":
                return False
            if not all(type(item.get(key)) is int for key in (
                "responseStatus", "reportRowsBefore", "reportRowsAfter", "uploadRowsBefore", "uploadRowsAfter"
            )):
                return False
    if scenario_id == "BPC-SC-019":
        clients = evidence.get("nativeClients")
        if not isinstance(clients, list) or len(clients) != 4 or any(
            not isinstance(item, dict) or item.get("transportScheme") != "https"
            or not _hash(item.get("clientSnapshotSha256")) or type(item.get("responseStatus")) is not int
            or not _hash(item.get("operationIdSha256")) or not _hash(item.get("agentIdSha256"))
            for item in clients
        ):
            return False
        if not isinstance(evidence.get("mcpFrames"), list) or not isinstance(evidence.get("restartReceipts"), list):
            return False
    else:
        if not isinstance(browser, dict) or browser.get("originScheme") != "https":
            return False
        actions = browser.get("actions")
        if not isinstance(actions, list) or not actions:
            return False
        requests = browser.get("requests")
        if not isinstance(requests, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("method"), str)
            or not isinstance(row.get("path"), str) or type(row.get("status")) is not int
            for row in requests
        ):
            return False
        if not isinstance(browser.get("previews"), list):
            return False
    if scenario_id == "BPC-SC-018":
        if not all(_hash(row.get("operationIdSha256")) for row in _report_rows(evidence)):
            return False
        if not isinstance(browser.get("textProbes"), list) or not isinstance(evidence.get("responseLossRetries"), list):
            return False
    if scenario_id == "BPC-SC-019":
        if not all(_hash(row.get("operationIdSha256")) and _hash(row.get("reporterIdSha256")) for row in _report_rows(evidence)):
            return False
    if scenario_id == "BPC-SC-020":
        if not isinstance(browser.get("adminListProbe"), dict) or not isinstance(browser.get("privateReads"), list):
            return False
    if scenario_id == "BPC-SC-024":
        if not isinstance(evidence.get("storage"), dict) or not isinstance(evidence["storage"].get("images"), list):
            return False
        if not isinstance(evidence.get("mcpFrames"), list) or not isinstance(evidence.get("uploadRetries"), list):
            return False
        if not isinstance(evidence.get("orphanSweep"), dict) or not isinstance(evidence.get("imageCapRace"), dict):
            return False
    if scenario_id == "BPC-SC-026":
        retention = evidence.get("retention")
        storage = evidence.get("storage")
        if not isinstance(retention, dict) or not isinstance(storage, dict):
            return False
        if not isinstance(retention.get("cleanupAttempts"), list) or not isinstance(retention.get("restore"), dict):
            return False
        if not isinstance(storage.get("imagesBefore"), list) or not isinstance(storage.get("imagesAfter"), list):
            return False
    return True


def derive_observations(scenario_id: str, evidence: dict[str, Any]) -> dict[str, bool] | None:
    """Derive every approved report fact from sanitized raw boundary records.

    Returns None when the target boundary or complete raw inventory is missing;
    the caller must preserve that gate as blocked/not_run.
    """

    if scenario_id not in SCENARIO_IDS or not isinstance(evidence, dict) or not _required_inventory(evidence, scenario_id):
        return None
    derivations = {
        "BPC-SC-018": _derive_018,
        "BPC-SC-019": _derive_019,
        "BPC-SC-020": _derive_020,
        "BPC-SC-024": _derive_024,
        "BPC-SC-026": _derive_026,
    }
    derived = derivations[scenario_id](evidence)
    if set(derived) != set(OBSERVATION_NAMES[scenario_id]):
        return None
    negatives = _derive_negatives(scenario_id, evidence)
    if set(negatives) != set(NEGATIVE_NAMES[scenario_id]):
        return None
    if not all(type(value) is bool for value in (*derived.values(), *negatives.values())):
        return None
    return {name: derived[name] for name in OBSERVATION_NAMES[scenario_id]} | {name: negatives[name] for name in NEGATIVE_NAMES[scenario_id]}


def _derive_negatives(scenario_id: str, evidence: dict[str, Any]) -> dict[str, bool]:
    rules: dict[str, tuple[set[int], set[str] | None]] = {
        "BPC-SC-018": {
            "foreign_run_or_action": ({400, 404}, {"REPORT_LINK_NOT_FOUND", "INVALID_REPORT_LINK"}),
            "forbidden_secret_fields": ({400}, {"INVALID_REPORT", "REPORT_CONTAINS_CREDENTIAL_MATERIAL"}),
            "oversized_payload": ({413}, {"REQUEST_BODY_TOO_LARGE"}),
            "html_text": ({200, 201}, None),
            "report_flood": ({429}, {"RATE_LIMITED"}),
            "response_loss": ({200}, None),
            "conflicting_retry": ({409}, {"IDEMPOTENCY_CONFLICT"}),
        },
        "BPC-SC-019": {
            "revoked_credential": ({401}, {"UNAUTHORIZED"}),
            "foreign_context": ({400, 404}, {"REPORT_LINK_NOT_FOUND", "INVALID_REPORT_LINK"}),
            "forged_owner": ({400}, {"INVALID_REPORT", "INVALID_REPORT_LINK"}),
            "report_as_action": ({400, 404}, {"MCP_TOOL_NOT_FOUND", "INVALID_TOOL", "UNKNOWN_TOOL"}),
            "conflicting_retry": ({409}, {"IDEMPOTENCY_CONFLICT"}),
            "excess_submission": ({429}, {"REPORT_RATE_LIMITED"}),
            "foreign_image_reference": ({404}, {"REPORT_IMAGE_NOT_FOUND"}),
            "owner_attaches_to_foreign_agent_report": ({404}, {"REPORT_NOT_FOUND"}),
        },
        "BPC-SC-020": {
            "stale_revision": ({409}, {"REPORT_STATUS_CONFLICT", "REPORT_REVISION_CONFLICT"}),
            "foreign_owner_read": ({404}, {"REPORT_NOT_FOUND"}),
            "agent_admin_attempt": ({401}, {"UNAUTHORIZED"}),
            "unauthorized_status": ({403}, {"FORBIDDEN"}),
            "html_injection": ({200, 201}, None),
            "foreign_attachment_preview": ({404}, {"REPORT_IMAGE_NOT_FOUND"}),
        },
        "BPC-SC-024": {
            "corrupt_image": ({400}, {"INVALID_REPORT_IMAGE"}),
            "disguised_html_or_svg": ({400}, {"INVALID_REPORT_IMAGE"}),
            "input_over_5mib": ({413}, {"REPORT_IMAGE_TOO_LARGE"}),
            "pixel_limit_exceeded": ({400}, {"INVALID_REPORT_IMAGE"}),
            "fourth_image_race": ({409}, {"REPORT_IMAGE_LIMIT"}),
            "foreign_upload_reference": ({404}, {"REPORT_IMAGE_NOT_FOUND"}),
            "foreign_image_read": ({404}, {"REPORT_IMAGE_NOT_FOUND"}),
            "path_traversal": ({400, 404}, {"INVALID_REPORT_IMAGE_ID", "REPORT_IMAGE_NOT_FOUND"}),
            "external_url_input": ({400, 415}, {"INVALID_REPORT_IMAGE_UPLOAD", "REPORT_IMAGE_TYPE_UNSUPPORTED", "UNSUPPORTED_MEDIA_TYPE"}),
            "lost_upload_response_restart": ({200}, None),
            "conflicting_retry_bytes": ({409}, {"REPORT_IMAGE_CHUNK_CONFLICT", "IDEMPOTENCY_CONFLICT"}),
            "cleanup_attach_race": ({409}, {"REPORT_IMAGE_NOT_FOUND", "REPORT_IMAGE_CONFLICT", "REPORT_IMAGE_UPLOAD_CLOSED"}),
            "chunk_sequence_conflict": ({409}, {"REPORT_IMAGE_CHUNK_ORDER", "REPORT_IMAGE_CHUNK_CONFLICT"}),
            "rolling_owner_quota": ({429}, {"REPORT_IMAGE_ROLLING_QUOTA"}),
            "staging_capacity_race": ({429}, {"REPORT_IMAGE_STAGING_LIMIT"}),
            "normalized_output_over_limit": ({400}, {"INVALID_REPORT_IMAGE"}),
            "insufficient_disk_or_backup_space": ({507}, {"REPORT_IMAGE_STORAGE_LOW", "REPORT_IMAGE_STORAGE_LIMIT"}),
        },
        "BPC-SC-026": {
            "read_at_deadline": ({410}, {"REPORT_RETENTION_EXPIRED"}),
            "late_upload_attach": ({410, 409}, {"REPORT_RETENTION_EXPIRED", "REPORT_IMAGE_UPLOAD_CLOSED"}),
            "delete_failure": ({410}, {"REPORT_RETENTION_EXPIRED"}),
            "repeated_cleanup": ({200}, None),
            "old_backup_restore": ({410, 200}, {"REPORT_RETENTION_EXPIRED", "RESTORE_PURGE_COMPLETE"}),
            "service_restart": ({200}, None),
        },
    }
    result: dict[str, bool] = {}
    for name, (statuses, errors) in rules[scenario_id].items():
        if name == "foreign_run_or_action":
            result[name] = _foreign_run_and_action_rejected(evidence)
        elif name == "report_flood":
            result[name] = _report_flood_rejected(evidence)
        elif name == "agent_admin_attempt":
            result[name] = _agent_admin_attempt_rejected(evidence)
        elif name == "html_text" or name == "html_injection":
            result[name] = _html_is_text(evidence)
        elif name == "response_loss":
            rows = evidence.get("responseLossRetries")
            result[name] = isinstance(rows, list) and any(
                isinstance(row, dict) and row.get("firstResponse") == "lost" and type(row.get("retryStatus")) is int
                and row.get("retryStatus") == 200 and _hash(row.get("operationIdSha256"))
                and row.get("originalReportIdSha256") == row.get("retryReportIdSha256")
                and _hash(row.get("originalReportIdSha256")) and type(row.get("persistedRowsForOperation")) is int
                and row.get("persistedRowsForOperation") == 1 and any(report.get("operationIdSha256") == row.get("operationIdSha256") for report in _report_rows(evidence))
                for row in rows
            )
        elif name == "lost_upload_response_restart":
            rows = evidence.get("uploadRetries")
            result[name] = isinstance(rows, list) and any(
                isinstance(row, dict) and row.get("firstResponse") == "lost" and _hash(row.get("operationIdSha256"))
                and row.get("retryUploadIdSha256") == row.get("originalUploadIdSha256") and _hash(row.get("originalUploadIdSha256"))
                and type(row.get("persistedRowsForOperation")) is int and row.get("persistedRowsForOperation") == 1
                and any(upload.get("operationIdSha256") == row.get("operationIdSha256") for upload in (evidence.get("observer", {}).get("after", {}).get("uploads", []) if isinstance(evidence.get("observer"), dict) else []))
                for row in rows
            )
        elif name == "repeated_cleanup":
            result[name] = _derive_026(evidence).get("tombstones_retained") is True and _derive_026(evidence).get("content_and_images_purged") is True \
                and len(evidence.get("retention", {}).get("cleanupAttempts", [])) >= 2
        elif name == "old_backup_restore":
            result[name] = _derive_026(evidence).get("no_restore_resurrection") is True
        elif name == "delete_failure":
            retention = evidence.get("retention")
            cleanup = retention.get("cleanupAttempts") if isinstance(retention, dict) else None
            result[name] = isinstance(cleanup, list) and any(
                isinstance(row, dict) and row.get("deleteStatus") == "failed" and type(row.get("readStatus")) is int
                and row.get("readStatus") == 410 and row.get("reportId") in {
                    receipt.get("reportId") for receipt in (evidence.get("observer", {}).get("after", {}).get("reportDeletionReceipts", []) if isinstance(evidence.get("observer"), dict) else [])
                    if isinstance(receipt, dict) and receipt.get("purgeStatus") == "failed"
                } for row in cleanup
            )
        elif name == "service_restart":
            retention = evidence.get("retention", {})
            result[name] = isinstance(retention, dict) and isinstance(retention.get("restartRead"), dict) \
                and type(retention["restartRead"].get("status")) is int and retention["restartRead"].get("status") == 410 \
                and retention["restartRead"].get("errorCode") == "REPORT_RETENTION_EXPIRED"
        else:
            result[name] = _attempt_rejected(evidence, name, statuses, errors)
    return result
