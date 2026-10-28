"""Derive BRL-023/024 observations from sanitized HTTP/MCP and PostgreSQL evidence.

This verifier deliberately ignores manifest outcome labels. It computes every
observation from the raw request/response records and independent observer rows.
Scenarios without a producer remain unavailable to the adapter.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _rows(snapshot: Any, name: str) -> list[dict[str, Any]]:
    database = snapshot.get("database") if isinstance(snapshot, dict) else None
    data = database if isinstance(database, dict) else {}
    values = data.get(name)
    return [row for row in values if isinstance(row, dict)] if isinstance(values, list) else []


def _observer_ok(snapshot: Any) -> bool:
    identity = snapshot.get("observer") if isinstance(snapshot, dict) else None
    return bool(
        isinstance(identity, dict)
        and identity.get("role") == "oid_observer"
        and identity.get("transaction_read_only") == "on"
    )


def _response(record: Any) -> dict[str, Any]:
    return record if isinstance(record, dict) else {}


def _status(record: Any) -> int | None:
    value = _response(record).get("status")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _body(record: Any) -> dict[str, Any]:
    value = _response(record).get("body")
    return value if isinstance(value, dict) else {}


def _error_code(record: Any) -> str | None:
    body = _body(record)
    error = body.get("error")
    return error.get("code") if isinstance(error, dict) and isinstance(error.get("code"), str) else None


def _same(value: Any, expected: Any) -> bool:
    return value == expected and expected is not None


def _same_time(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        def parse(value: str) -> datetime:
            normalized = value.replace("Z", "+00:00")
            if len(normalized) > 6 and normalized[-6] in {"+", "-"} and normalized[-3] != ":":
                normalized = normalized[:-2] + ":" + normalized[-2:]
            return datetime.fromisoformat(normalized)
        return parse(left).timestamp() == parse(right).timestamp()
    except (ValueError, OverflowError):
        return False


def _at_or_after(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        def parse(value: str) -> datetime:
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        return parse(left).timestamp() >= parse(right).timestamp()
    except (ValueError, OverflowError):
        return False


def _no_delta(before: Any, after: Any, key: str) -> bool:
    before_rows = _rows(before, key)
    after_rows = _rows(after, key)
    return before_rows == after_rows


def _derive_023(capture: dict[str, Any]) -> dict[str, bool]:
    cases = capture.get("cases") if isinstance(capture.get("cases"), dict) else {}
    seed = cases.get("seed") if isinstance(cases.get("seed"), dict) else {}
    duplicate = cases.get("duplicateCreate") if isinstance(cases.get("duplicateCreate"), dict) else {}
    accepted = cases.get("acceptance") if isinstance(cases.get("acceptance"), dict) else {}
    before = accepted.get("before") if isinstance(accepted.get("before"), dict) else {}
    after = accepted.get("after") if isinstance(accepted.get("after"), dict) else {}
    preaccept = cases.get("preAcceptance") if isinstance(cases.get("preAcceptance"), dict) else {}
    pre_before = preaccept.get("before") if isinstance(preaccept.get("before"), dict) else {}
    pre_after = preaccept.get("after") if isinstance(preaccept.get("after"), dict) else {}
    intent = seed.get("intent") if isinstance(seed.get("intent"), dict) else {}
    release = seed.get("release") if isinstance(seed.get("release"), dict) else {}
    intent_id = intent.get("id")
    before_intents = _rows(before, "intents")
    def pending_snapshot_clear(snapshot: dict[str, Any]) -> bool:
        rows = _rows(snapshot, "intents")
        pending = next((row for row in rows if row.get("id") == intent_id), {})
        return bool(
            _observer_ok(snapshot)
            and pending.get("status") == "pending"
            and pending.get("run_id") is None
            and not _rows(snapshot, "runs")
            and not _rows(snapshot, "reservations")
            and not _rows(snapshot, "budgetHolds")
            and not _rows(snapshot, "slots")
        )

    pending_clear = pending_snapshot_clear(pre_before) and pending_snapshot_clear(pre_after) and pending_snapshot_clear(before)

    duplicate_intent = _response(duplicate).get("body")
    duplicate_intent = duplicate_intent.get("intent") if isinstance(duplicate_intent, dict) else None
    duplicate_create_same = bool(
        _status(duplicate) in {200, 201}
        and isinstance(duplicate_intent, dict)
        and duplicate_intent.get("id") == intent_id
        and _same_time(duplicate_intent.get("expiresAt"), intent.get("expires_at"))
    )

    attempts = accepted.get("attempts") if isinstance(accepted.get("attempts"), dict) else {}
    primary_mcp = attempts.get("primaryMcp") if isinstance(attempts.get("primaryMcp"), dict) else {}
    http_replay = attempts.get("httpReplay") if isinstance(attempts.get("httpReplay"), dict) else {}
    lost = attempts.get("lostHttp") if isinstance(attempts.get("lostHttp"), dict) else {}
    http_retry = attempts.get("httpRetry") if isinstance(attempts.get("httpRetry"), dict) else {}
    mcp_retry = attempts.get("mcpRetry") if isinstance(attempts.get("mcpRetry"), dict) else {}
    run_ids = [
        _body(primary_mcp).get("run", {}).get("id") if isinstance(_body(primary_mcp).get("run"), dict) else None,
        _body(http_replay).get("run", {}).get("id") if isinstance(_body(http_replay).get("run"), dict) else None,
        _body(http_retry).get("run", {}).get("id") if isinstance(_body(http_retry).get("run"), dict) else None,
        _body(mcp_retry).get("run", {}).get("id") if isinstance(_body(mcp_retry).get("run"), dict) else None,
    ]
    run_ids = [value for value in run_ids if isinstance(value, str)]
    after_intents = _rows(after, "intents")
    after_runs = _rows(after, "runs")
    linked_intent = next((row for row in after_intents if row.get("id") == intent_id), {})
    linked_run = next((row for row in after_runs if row.get("id") == linked_intent.get("run_id")), {})
    run_id = linked_run.get("id")
    linked_reservations = [row for row in _rows(after, "reservations") if row.get("run_id") == run_id]
    linked_holds = [row for row in _rows(after, "budgetHolds") if row.get("run_id") == run_id]
    linked_events = [row for row in _rows(after, "events") if row.get("run_id") == run_id]
    linked_outbox = [row for row in _rows(after, "outbox") if row.get("run_id") == run_id]
    linked_ledger = [row for row in _rows(after, "ledgerEntries") if row.get("operation_id") == "runacc_" + str(run_id).replace("-", "")]
    post_change = accepted.get("postChangeRetry") if isinstance(accepted.get("postChangeRetry"), dict) else {}
    atomic_link = bool(
        _observer_ok(after)
        and isinstance(run_id, str)
        and linked_intent.get("status") == "accepted"
        and linked_intent.get("run_id") == run_id
        and linked_run.get("intent_id") == intent_id
        and linked_run.get("owner_id") == intent.get("owner_id")
        and linked_run.get("agent_id") == intent.get("agent_id")
        and linked_reservations
        and linked_holds
        and linked_events
        and any(row.get("event_type") == "run.accepted" for row in linked_events)
        and linked_outbox
        and linked_ledger
    )
    retry_same = bool(
        isinstance(run_id, str)
        and run_ids == [run_id, run_id, run_id, run_id]
        and _status(primary_mcp) == 200
        and primary_mcp.get("clientBoundary") == "codex_native_mcp_agent_case"
        and _status(http_replay) == 200
        and http_replay.get("request", {}).get("operationId") == primary_mcp.get("operationId")
        and _status(http_retry) == 200
        and _status(mcp_retry) == 200
        and http_retry.get("request", {}).get("operationId") == mcp_retry.get("operationId")
        and http_retry.get("request", {}).get("operationId") == post_change.get("retryOperationId")
        and _response(mcp_retry).get("toolName") == "runs.accept_launch_intent"
        and accepted.get("restart", {}).get("healthStatus") == 200
        and lost.get("responseDroppedAfterCommit") is True
        and lost.get("responseStatusAtDropShim") in {200, 201}
        and _body({"body": lost.get("serverBodyAtDropShim")}).get("run", {}).get("id") == run_id
    )
    seed_pending_row = next((row for row in before_intents if row.get("id") == intent_id), {})
    exact_quote = bool(
        seed_pending_row
        and linked_run
        and str(seed_pending_row.get("quote_price_units")) == str(intent.get("quote_price_units"))
        and str(linked_run.get("quote_price_units")) == str(intent.get("quote_price_units"))
        and str(linked_run.get("cash_ceiling_units")) == str(intent.get("cash_ceiling_units"))
        and intent.get("release_identity") == release.get("releaseIdentity")
        and intent.get("manifest_hash") == release.get("manifestHash")
        and linked_run.get("release_identity") == release.get("releaseIdentity")
        and linked_run.get("manifest_hash") == release.get("manifestHash")
        and sum(int(row.get("amount_units", 0)) for row in linked_reservations)
        == int(linked_run.get("quote_price_units", -1))
        and sum(int(row.get("amount_units", 0)) for row in linked_ledger if row.get("entry_type") == "reserve")
        == int(linked_run.get("quote_price_units", -1))
    )
    catalog_before = post_change.get("catalogBefore") if isinstance(post_change.get("catalogBefore"), dict) else {}
    catalog_after = post_change.get("catalogAfter") if isinstance(post_change.get("catalogAfter"), dict) else {}
    active_before = catalog_before.get("activeRelease") if isinstance(catalog_before.get("activeRelease"), dict) else {}
    active_after = catalog_after.get("activeRelease") if isinstance(catalog_after.get("activeRelease"), dict) else {}
    release_changed = bool(
        active_before and active_after and (
            active_before.get("releaseIdentity") != active_after.get("releaseIdentity")
            or active_before.get("manifestHash") != active_after.get("manifestHash")
            or active_before.get("rankedPrice") != active_after.get("rankedPrice")
            or active_before.get("trainingPrice") != active_after.get("trainingPrice")
        )
    )
    before_retry = post_change.get("beforeRetry") if isinstance(post_change.get("beforeRetry"), dict) else {}
    before_retry_intent = next((row for row in _rows(before_retry, "intents") if row.get("id") == intent_id), {})
    expiry_observed = _at_or_after(
        before_retry.get("database", {}).get("observedAt") if isinstance(before_retry.get("database"), dict) else None,
        before_retry_intent.get("expires_at"),
    )
    after_retry = post_change.get("afterRetry") if isinstance(post_change.get("afterRetry"), dict) else {}
    stable_retry_rows = all(
        _no_delta(post_change.get("beforeChange"), after_retry, name)
        for name in ("runs", "reservations", "budgetHolds", "ledgerEntries", "events", "outbox", "slots")
    )
    post_change_http = post_change.get("httpRetry") if isinstance(post_change.get("httpRetry"), dict) else {}
    post_change_mcp = post_change.get("mcpRetry") if isinstance(post_change.get("mcpRetry"), dict) else {}
    post_change_ok = bool(
        release_changed
        and expiry_observed
        and post_change.get("releaseChanged") is True
        and _status(post_change_http) == 200
        and _status(post_change_mcp) == 200
        and post_change.get("restart", {}).get("healthStatus") == 200
        and _body(post_change_http).get("run", {}).get("id") == run_id
        and _body(post_change_mcp).get("run", {}).get("id") == run_id
        and post_change_http.get("request", {}).get("operationId") == post_change.get("retryOperationId")
        and post_change_mcp.get("operationId") == post_change.get("retryOperationId")
        and post_change.get("lostHttp", {}).get("responseDroppedAfterCommit") is True
        and post_change.get("lostHttp", {}).get("responseStatusAtDropShim") in {200, 201}
        and _body({"body": post_change.get("lostHttp", {}).get("serverBodyAtDropShim")}).get("run", {}).get("id") == run_id
        and post_change.get("retryOperationId") != post_change.get("primaryOperationId")
        and stable_retry_rows
    )
    client_model = primary_mcp.get("clientModel") if isinstance(primary_mcp.get("clientModel"), dict) else {}
    publication_count = len(_rows(after, "publicActionMarkers")) + len(_rows(after, "rankedBestResults"))
    no_execution = bool(
        isinstance(run_id, str)
        and not _rows(after, "actions")
        and client_model.get("externalModelCalls") == 0
        and client_model.get("llmBenchmarkInvocation") is False
        and publication_count == 0
    )
    observations = {
        "owner_bound_immutable_intent": bool(
            intent_id
            and intent.get("owner_id") == capture.get("ownerId")
            and intent.get("agent_id") == capture.get("agentId")
            and intent.get("status") == "pending"
            and duplicate_create_same
        ),
        "pending_no_run_hold_slot_or_timer": pending_clear,
        "one_server_derived_admission_identity": bool(
            atomic_link
            and run_ids == [run_id, run_id, run_id, run_id]
            and len([row for row in after_runs if row.get("intent_id") == intent_id]) == 1
        ),
        "atomic_intent_run_reservation_link": atomic_link,
        "exact_reviewed_quote_and_cash_ceiling": exact_quote,
        "retry_after_expiry_price_or_version_change_same_run": post_change_ok,
        "no_card_publication_or_model_execution": no_execution,
    }
    negatives = {
        "duplicate_create_or_accept": bool(duplicate_create_same and retry_same),
        "new_caller_key_same_intent": bool(
            run_ids == [run_id, run_id, run_id, run_id]
            and post_change.get("retryOperationId") != post_change.get("primaryOperationId")
        ),
        "cross_transport_retry": bool(
            _status(http_retry) == 200 and _status(mcp_retry) == 200
            and run_ids[0] == run_ids[1] == run_ids[2] == run_ids[3]
        ),
        "lost_response_restart": bool(lost.get("responseDroppedAfterCommit") is True and retry_same),
        "admitted_retry_after_expiry": post_change_ok,
        "admitted_retry_after_version_or_tariff_change": post_change_ok,
    }
    return {**observations, **negatives}


def _derive_024(capture: dict[str, Any]) -> dict[str, bool]:
    cases = capture.get("cases") if isinstance(capture.get("cases"), dict) else {}
    authorization = cases.get("authorizationChecks") if isinstance(cases.get("authorizationChecks"), dict) else {}
    stale = cases.get("stalePolicy") if isinstance(cases.get("stalePolicy"), dict) else {}
    rejected = cases.get("rejectedEffects") if isinstance(cases.get("rejectedEffects"), dict) else {}
    race = cases.get("cancelAcceptRace") if isinstance(cases.get("cancelAcceptRace"), dict) else {}
    expiry = cases.get("expiryIntent") if isinstance(cases.get("expiryIntent"), dict) else {}
    post_admission = cases.get("postAdmissionCancel") if isinstance(cases.get("postAdmissionCancel"), dict) else {}
    capacity = cases.get("capacity") if isinstance(cases.get("capacity"), dict) else {}
    foreign = cases.get("foreignAccess") if isinstance(cases.get("foreignAccess"), dict) else {}

    unauthorized = authorization.get("ownerSessionAsAgent")
    foreign_agent = authorization.get("foreignAgent")
    stale_create = stale.get("staleCreate")
    changed_payload = stale.get("sameKeyChangedPayload")
    rejected_before = rejected.get("before")
    rejected_after = rejected.get("after")
    race_before = race.get("before")
    race_after = race.get("after")
    race_intent_id = race.get("intentId")
    race_intent = next((row for row in _rows(race_after, "intents") if row.get("id") == race_intent_id), {})
    race_runs = [row for row in _rows(race_after, "runs") if row.get("intent_id") == race_intent_id]
    race_terminal = (
        (race_intent.get("status") == "cancelled" and not race_runs)
        or (race_intent.get("status") == "accepted" and len(race_runs) == 1 and race_intent.get("run_id") == race_runs[0].get("id"))
    )
    post_intent = post_admission.get("intent") if isinstance(post_admission.get("intent"), dict) else {}
    post_run = post_admission.get("run") if isinstance(post_admission.get("run"), dict) else {}
    post_cancel_event = any(
        row.get("event_type") in {"run.cancellation_requested", "run.cancelled.before_start", "run.expired"}
        for row in _rows(post_admission.get("after"), "events")
        if row.get("run_id") == post_run.get("id")
    )
    capacity_ok = bool(
        capacity.get("configuredOwnerLimit") == capacity.get("observedOwnerLimit")
        and isinstance(capacity.get("rejectedExtra"), dict)
        and _status(capacity.get("rejectedExtra")) in {409, 429, 503}
        and capacity.get("cleanupComplete") is True
        and capacity.get("maxPendingObserved") == capacity.get("configuredOwnerLimit")
    )
    foreign_data_absent = bool(
        foreign.get("foreignOwnerReadStatus") == 404
        and foreign.get("foreignOwnerResponseOmitsIntent") is True
        and foreign_agent is not None
        and _status(foreign_agent) in {403, 404}
        and foreign.get("foreignAgentResponseOmitsRun") is True
    )
    no_rejection_delta = bool(
        _observer_ok(rejected_before)
        and _observer_ok(rejected_after)
        and all(_no_delta(rejected_before, rejected_after, name) for name in ("runs", "reservations", "budgetHolds", "ledgerEntries", "slots"))
    )
    observer_order = bool(_observer_ok(race_before) and _observer_ok(race_after))
    stale_rejected = bool(
        _status(stale_create) == 409
        and _error_code(stale_create) == "STALE_RUN_INTENT"
        and _status(changed_payload) == 409
        and _error_code(changed_payload) in {"IDEMPOTENCY_CONFLICT", "OPERATION_CONFLICT"}
    )
    stale_release = stale.get("staleRelease") if isinstance(stale.get("staleRelease"), dict) else {}
    catalog_before = stale_release.get("catalogBefore") if isinstance(stale_release.get("catalogBefore"), dict) else {}
    catalog_after = stale_release.get("catalogAfter") if isinstance(stale_release.get("catalogAfter"), dict) else {}
    release_before = catalog_before.get("activeRelease") if isinstance(catalog_before.get("activeRelease"), dict) else {}
    release_after = catalog_after.get("activeRelease") if isinstance(catalog_after.get("activeRelease"), dict) else {}
    release_changed = bool(
        release_before and release_after and (
            release_before.get("releaseIdentity") != release_after.get("releaseIdentity")
            or release_before.get("manifestHash") != release_after.get("manifestHash")
            or release_before.get("rankedPrice") != release_after.get("rankedPrice")
            or release_before.get("trainingPrice") != release_after.get("trainingPrice")
        )
    )
    stale_release_before = stale_release.get("before")
    stale_release_after = stale_release.get("after")
    stale_release_rows_before = _rows(stale_release_before, "intents")
    stale_release_intent_id = stale_release_rows_before[0].get("id") if stale_release_rows_before else None
    stale_release_row_after = next(
        (row for row in _rows(stale_release_after, "intents") if row.get("id") == stale_release_intent_id), {}
    )
    stale_release_rejected = bool(
        release_changed
        and _status(stale_release.get("acceptance")) == 409
        and _error_code(stale_release.get("acceptance")) == "STALE_RUN_INTENT"
        and _observer_ok(stale_release_before)
        and _observer_ok(stale_release_after)
        and stale_release_row_after.get("status") == "pending"
        and all(_no_delta(stale_release_before, stale_release_after, name)
            for name in ("runs", "reservations", "budgetHolds", "ledgerEntries", "slots"))
    )
    deadline = stale.get("deadlineAttempt") if isinstance(stale.get("deadlineAttempt"), dict) else {}
    deadline_attempt = deadline.get("attempt")
    deadline_before = deadline.get("before")
    deadline_after = deadline.get("after")
    deadline_intent_id = expiry.get("intentId")
    deadline_intent = next((row for row in _rows(deadline_before, "intents")
        if row.get("id") == deadline_intent_id), {})
    deadline_final_intent = next((row for row in _rows(deadline_after, "intents")
        if row.get("id") == deadline_intent_id), {})
    deadline_elapsed = False
    observed_at = deadline_before.get("database", {}).get("observedAt") if isinstance(deadline_before, dict) else None
    expires_at = deadline_intent.get("expires_at")
    if isinstance(observed_at, str) and isinstance(expires_at, str):
        deadline_elapsed = _at_or_after(observed_at, expires_at)
    deadline_rejected = bool(
        deadline_elapsed
        and _status(deadline_attempt) in {409, 410}
        and _error_code(deadline_attempt) in {"RUN_INTENT_TERMINAL", "RUN_INTENT_EXPIRED"}
        and _observer_ok(deadline_before)
        and _observer_ok(deadline_after)
        and all(_no_delta(deadline_before, deadline_after, name)
            for name in ("runs", "reservations", "budgetHolds", "ledgerEntries", "slots"))
        and deadline_final_intent.get("status") in {"pending", "expired"}
        and not [row for row in _rows(deadline_after, "runs") if row.get("intent_id") == deadline_intent_id]
    )
    cancel_before = rejected.get("cancelBefore")
    cancel_after = rejected.get("cancelAfter")
    cancelled_id = next((row.get("id") for row in _rows(cancel_before, "intents")), None)
    cancelled_row = next((row for row in _rows(cancel_after, "intents") if row.get("id") == cancelled_id), {})
    pending_cancel_ok = bool(
        _status(rejected.get("pendingCancel")) == 200
        and _status(rejected.get("cancelledAccept")) in {409, 410}
        and cancelled_row.get("status") in {"cancelled", "expired"}
        and not [row for row in _rows(cancel_after, "runs") if row.get("intent_id") == cancelled_id]
        and all(_no_delta(cancel_before, cancel_after, name)
            for name in ("runs", "reservations", "budgetHolds", "ledgerEntries", "slots"))
    )
    accepted_cancel = bool(
        post_intent.get("status") == "accepted"
        and post_intent.get("run_id") == post_run.get("id")
        and post_cancel_event
        and post_run.get("status") in {"cancellation_requested", "cancelled", "expired"}
        and any(row.get("event_type") == "run.cancel.requested"
            for row in _rows(post_admission.get("after"), "outbox")
            if row.get("run_id") == post_run.get("id"))
    )
    observations = {
        "matching_current_agent_authority_required": bool(
            _status(unauthorized) == 401
            and _error_code(unauthorized) == "UNAUTHORIZED"
            and _status(stale_create) == 409
            and foreign_agent is not None
            and _status(foreign_agent) in {403, 404}
        ),
        "changed_quote_version_selection_or_cash_rejected": stale_rejected and stale_release_rejected,
        "no_run_or_holds_on_rejection": no_rejection_delta,
        "cancel_expiry_accept_serialized": observer_order and race_terminal and pending_cancel_ok and deadline_rejected,
        "postadmission_cancel_uses_run_rules": accepted_cancel,
        "bounded_intent_admission": capacity_ok,
        "foreign_data_absent": foreign_data_absent,
    }
    negatives = {
        "owner_session_as_agent": _status(unauthorized) == 401,
        "foreign_owner_or_card": foreign_data_absent,
        "changed_payload": _status(changed_payload) == 409,
        "stale_tariff_or_benchmark": stale_release_rejected,
        "increased_cash_need": stale.get("increasedCashRejected") is True,
        "cash_permission_revoked": stale.get("cashPermissionRevokedRejected") is True,
        "at_deadline_accept": deadline_rejected,
        "cancel_accept_race": observer_order and race_terminal and pending_cancel_ok,
        "pending_intent_capacity_exhaustion": capacity_ok,
        "same_key_conflicting_creation": _status(changed_payload) == 409,
    }
    return {**observations, **negatives}


def derive_observations(scenario_id: str, evidence: Any) -> dict[str, bool] | None:
    """Recompute supported BRL facts from the producer's raw evidence object."""

    if not isinstance(evidence, dict) or evidence.get("schemaVersion") != "benchmark-run-lifecycle-runtime-evidence/v1":
        return None
    if evidence.get("scenarioId") != scenario_id:
        return None
    if not _observer_ok(evidence.get("database")):
        return None
    if scenario_id == "BRL-SC-023":
        return _derive_023(evidence)
    if scenario_id == "BRL-SC-024":
        return _derive_024(evidence)
    return None
