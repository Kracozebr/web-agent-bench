"""Strict local raw-evidence replay for the BPC-SC-017 recovery capture.

This verifier deliberately keeps the local owner/BEF fixture boundary separate
from the approved target-host gate. It derives only facts present in the
captured HTTP fault, source-operation, PostgreSQL, and hash-pinned file evidence.
Producer summary booleans and claim strings are never used as proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

SCENARIO_ID = "BPC-SC-017"
RECOVERY_SCHEMA = "bpc-platform-recovery-runtime-observation/v1"
CASE_SCHEMA = "bpc-platform-recovery-case/v1"
LOCAL_BOUNDARY = "isolated_local_owner_browser_api_postgres_bef_observer_and_real_loopback_fault_proxies"
RECOVERY_WINDOW_MS = 180_000
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ACCEPTANCE_DB_RE = re.compile(r"^oid_acceptance_[0-9a-f]{32}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$", re.IGNORECASE)

OBSERVATION_NAMES = (
    "cancel_start_order_exact",
    "original_action_reconciled",
    "bounded_recovery_clock",
    "unknown_retained",
    "refund_once_source_linked",
    "own_slots_fenced",
)
NEGATIVE_NAMES = (
    "cancel_before_start",
    "revoke_after_start",
    "response_lost_after_effect",
    "recovery_exhaustion",
    "duplicate_terminal",
    "restart",
    "stale_callback",
    "forged_failure_report",
)
_REPLAY_READER_PATHS = {
    "tests/bdd/adapters/beta_poc_recovery_verifier.py",
    "tests/bdd/adapters/test_beta_poc_recovery_verifier.py",
    "tools/replay_bpc_recovery_restore_local.py",
}


def _obj(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssertionError(f"{name} must be an object")
    return value


def _rows(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise AssertionError(f"{name} must be an array of objects")
    return value


def _uuid(value: Any) -> bool:
    return isinstance(value, str) and UUID_RE.fullmatch(value) is not None


def _hash(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _one(rows: list[dict[str, Any]], name: str) -> dict[str, Any]:
    if len(rows) != 1:
        raise AssertionError(f"{name} must contain exactly one row")
    return rows[0]


def _epoch_ms(value: Any, name: str) -> int:
    if not isinstance(value, str) or not value.strip():
        raise AssertionError(f"{name} timestamp is missing")
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AssertionError(f"{name} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise AssertionError(f"{name} timestamp must include a timezone")
    return int(parsed.timestamp() * 1000)


def _observer(identity: Any, expected_database: str, *, role: str = "oid_observer") -> bool:
    if not isinstance(identity, dict):
        return False
    return identity.get("role") == role and identity.get("databaseName") == expected_database \
        and identity.get("transactionReadOnly") == "on"


def _reference_bytes(reference: Any, repository_root: Path, name: str) -> tuple[bytes, Path]:
    reference = _obj(reference, name)
    path_text, digest = reference.get("path"), reference.get("sha256")
    if not isinstance(path_text, str) or not _hash(digest) or "\\" in path_text or path_text.startswith("/") \
            or re.match(r"^[A-Za-z]:", path_text):
        raise AssertionError(f"{name} reference shape is invalid")
    parts = PurePosixPath(path_text).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise AssertionError(f"{name} reference path is unsafe")
    root = repository_root.resolve(strict=True)
    path = root.joinpath(*parts).resolve(strict=True)
    if root not in path.parents or not path.is_file():
        raise AssertionError(f"{name} reference escapes the repository or is not a file")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise AssertionError(f"{name} reference hash does not match its file")
    if len(data) > 2 * 1024 * 1024:
        raise AssertionError(f"{name} evidence file exceeds the replay bound")
    return data, path


def _action_evidence(reference: Any, *, repository_root: Path, action: dict[str, Any], binding: dict[str, Any],
                     expected_statuses: set[str], name: str) -> dict[str, Any]:
    data, _ = _reference_bytes(reference, repository_root, name)
    try:
        packet = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{name} evidence is not valid JSON") from exc
    packet = _obj(packet, name)
    expected = {
        "schema": "bef-task-action-observation-v1",
        "actionId": action.get("actionId"),
        "runId": binding.get("runId"),
        "taskIndex": action.get("taskIndex"),
        "actionSequence": str(action.get("actionSequence")),
        "ownerOperationId": action.get("ownerOperationId"),
        "actionKind": action.get("kind"),
        "commandSha256": action.get("payloadHash"),
        "environmentId": binding.get("environmentId"),
        "generationId": binding.get("generationId"),
        "idempotencyKey": f"task-action-{action.get('actionId')}",
    }
    if any(packet.get(key) != value for key, value in expected.items()) or packet.get("status") not in expected_statuses:
        raise AssertionError(f"{name} evidence does not bind the exact recovered action")
    # Reuse the repository scanner so no credential-like values cross the local replay boundary.
    from tests.bdd.adapters.beta_poc_delivery import _assert_secret_free

    _assert_secret_free(packet, name)
    return packet


def _fence_evidence(reference: Any, *, repository_root: Path, binding: dict[str, Any], name: str) -> dict[str, Any]:
    data, _ = _reference_bytes(reference, repository_root, name)
    try:
        packet = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{name} evidence is not valid JSON") from exc
    packet = _obj(packet, name)
    details = _obj(packet.get("evidence"), f"{name}.evidence")
    before = _obj(details.get("before"), f"{name}.before")
    after = _obj(details.get("after"), f"{name}.after")
    before_request = _obj(before.get("request"), f"{name}.before.request")
    before_fixture = _obj(before.get("fixture"), f"{name}.before.fixture")
    if packet.get("schemaVersion") != "owner-bef-task-preparation-evidence/v1" \
            or packet.get("kind") != "fence" or packet.get("preparationId") != binding.get("preparationId") \
            or packet.get("environmentId") != binding.get("environmentId") \
            or packet.get("publicPinsSha256") != details.get("publicPinsSha256") \
            or not _hash(packet.get("publicPinsSha256")) or details.get("fenceConfirmed") is not True \
            or details.get("actualBefGenerationId") != binding.get("generationId") \
            or details.get("expectedOwnerGenerationId") != binding.get("generationId") \
            or before.get("schemaVersion") != "bef-preparation-status/v1" or before.get("status") != "ready" \
            or after.get("schemaVersion") != "bef-preparation-status/v1" or after.get("status") != "fenced" \
            or before.get("preparationId") != binding.get("preparationId") \
            or before.get("envId") != binding.get("environmentId") \
            or before.get("generationId") != binding.get("generationId") \
            or before_request.get("publicPinsSha256") != packet.get("publicPinsSha256") \
            or before_fixture.get("state") != "observed" or not _hash(before_fixture.get("fixtureHash")) \
            or not isinstance(after.get("fenceConfirmedAt"), str):
        raise AssertionError(f"{name} file does not prove the exact preparation/generation fence")
    _epoch_ms(after["fenceConfirmedAt"], f"{name}.fenceConfirmedAt")
    from tests.bdd.adapters.beta_poc_delivery import _assert_secret_free

    _assert_secret_free(packet, name)
    return packet


def _source_operation(source: Any, action: dict[str, Any], binding: dict[str, Any], *, name: str) -> dict[str, Any]:
    source = _obj(source, name)
    identity = _obj(source.get("identity"), f"{name}.identity")
    if not _observer(identity, "bef", role="bef_observer"):
        raise AssertionError(f"{name} is not an independent read-only BEF observer snapshot")
    key_hash = hashlib.sha256(f"task-action-{action['actionId']}".encode("utf-8")).hexdigest()
    if source.get("keySha256") != key_hash:
        raise AssertionError(f"{name} idempotency-key hash does not bind the action")
    operations = _rows(source.get("operations"), f"{name}.operations")
    operation = _one(operations, f"{name}.operations")
    result_rows = _rows(source.get("result"), f"{name}.result")
    if result_rows != operations:
        raise AssertionError(f"{name} duplicate source projections disagree")
    selected = _one(_rows(source.get("selectedExecutions"), f"{name}.selectedExecutions"),
                    f"{name}.selectedExecutions")
    recovery_source = _obj(source.get("recoverySource"), f"{name}.recoverySource")
    if set(recovery_source) != {"schema", "sourceSnapshotSha256", "selectedMeasurementSha256", "sourceResponseSha256"} \
            or recovery_source.get("schema") != "bef-recovery-source/v1" \
            or not _hash(recovery_source.get("sourceSnapshotSha256")) \
            or not _hash(recovery_source.get("selectedMeasurementSha256")) \
            or recovery_source.get("sourceResponseSha256") is not None:
        raise AssertionError(f"{name} source recovery proof is malformed or invents a wire response")
    exact = (
        operation.get("environmentId") == binding.get("environmentId")
        and operation.get("generationId") == binding.get("generationId")
        and operation.get("participantIdSha256") == binding.get("participantIdSha256")
        and operation.get("idempotencyKeySha256") == key_hash
        and operation.get("operationKind") == action.get("kind")
        and operation.get("status") == "settled"
        and operation.get("receiptStatus") == "success"
        and operation.get("generationStatus") == "fenced"
        and isinstance(operation.get("fencedAt"), str)
        and _uuid(operation.get("operationId"))
        and _hash(operation.get("requestSha256"))
        and "responseSha256" in operation and operation.get("responseSha256") is None
        and TX_HASH_RE.fullmatch(operation.get("transactionHash", "")) is not None
    )
    if not exact:
        raise AssertionError(f"{name} source row does not prove the exact fenced terminal operation")
    receipt = _obj(selected.get("receipt"), f"{name}.selectedExecution.receipt")
    selected_exact = (
        selected.get("operationId") == operation.get("operationId")
        and selected.get("selectedActionKind") == operation.get("operationKind") == action.get("kind")
        and _hash(selected.get("selectedActionSha256"))
        and selected.get("selectedActionEventCount") == 1
        and selected.get("selectedActionEventKind") == "selected_action_bound"
        and selected.get("selectedActionEventActionKind") == action.get("kind")
        and selected.get("selectedActionEventRequestSha256") == operation.get("requestSha256")
        and selected.get("selectedActionEventSelectedActionSha256") == selected.get("selectedActionSha256")
        and _hash(selected.get("selectedActionEventSha256"))
        and selected.get("selectedMeasurementSha256") == recovery_source.get("selectedMeasurementSha256")
        and selected.get("selectedOutcome") == operation.get("receiptStatus") == "success"
        and selected.get("selectedTransactionHash") == operation.get("transactionHash")
        and _hash(selected.get("generationManifestSha256"))
        and _hash(selected.get("environmentManifestSha256"))
        and receipt.get("transactionHash") == operation.get("transactionHash")
        and receipt.get("status") == operation.get("receiptStatus")
        and isinstance(receipt.get("gasUsed"), str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", receipt["gasUsed"])
        and isinstance(receipt.get("effectiveGasPriceWei"), str)
        and re.fullmatch(r"(?:0|[1-9][0-9]*)", receipt["effectiveGasPriceWei"])
    )
    if not selected_exact:
        raise AssertionError(f"{name} selected execution, measurement, receipt, and bound event are inconsistent")
    return operation


def _verify_recovery_action_packet(packet: dict[str, Any], source: dict[str, Any], operation: dict[str, Any], *, name: str) -> None:
    proof = _obj(packet.get("recoverySource"), f"{name}.recoverySource")
    source_proof = _obj(source.get("recoverySource"), f"{name}.sourceRecoveryProof")
    selected = _one(_rows(source.get("selectedExecutions"), f"{name}.selectedExecutions"),
                    f"{name}.selectedExecutions")
    if proof != source_proof or packet.get("reasonCode") != "platform_recovery_original_operation_terminal" \
            or packet.get("befOperationId") != operation.get("operationId") \
            or packet.get("transactionHash") != operation.get("transactionHash") \
            or packet.get("receiptStatus") != "success" or packet.get("outcome") != "success" \
            or packet.get("receiptGasUsed") != selected["receipt"]["gasUsed"] \
            or packet.get("receiptEffectiveGasPriceWei") != selected["receipt"]["effectiveGasPriceWei"] \
            or "httpStatus" in packet or "rawResponseSha256" in packet:
        raise AssertionError(f"{name} does not use the original source receipt without inventing a wire response")


def _proxy_fault(proxy: Any, action_id: str, *, path: str | None = None) -> bool:
    if not isinstance(proxy, dict) or proxy.get("schemaVersion") != "beta-recovery-transport-fault/v1" \
            or proxy.get("boundary") != "real_upstream_http_response_withheld_after_complete_read":
        return False
    fault = proxy.get("fault")
    if not isinstance(fault, dict) or fault.get("actionId") != action_id \
            or fault.get("upstreamResponseComplete") is not True or fault.get("downstreamResponseDelivered") is not False \
            or type(fault.get("upstreamStatus")) is not int or not 200 <= fault["upstreamStatus"] < 300 \
            or not _hash(fault.get("upstreamResponseSha256")) or type(fault.get("responseBytes")) is not int \
            or fault["responseBytes"] < 1:
        return False
    if path is not None and fault.get("path") != path:
        return False
    return _proxy_submission_count(proxy, action_id) == 1


def _proxy_submission_count(proxy: Any, action_id: str) -> int | None:
    if not isinstance(proxy, dict):
        return None
    submissions = [row for row in _rows(proxy.get("submissions"), "proxy.submissions")
                   if row.get("actionId") == action_id]
    if len(submissions) != 1:
        return None
    count = submissions[0].get("count")
    return count if type(count) is int and count > 0 else None


def _validate_case_common(case: Any, name: str, *, task_id: str = "S1") -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    case = _obj(case, name)
    if case.get("schemaVersion") != CASE_SCHEMA or not _uuid(case.get("captureId")):
        raise AssertionError(f"{name} schema or capture identity is invalid")
    binding = _obj(case.get("binding"), f"{name}.binding")
    action = _obj(case.get("action"), f"{name}.action")
    for key in ("runId", "ownerId", "agentId", "preparationId", "generationId", "leaseId"):
        if not _uuid(binding.get(key)):
            raise AssertionError(f"{name} binding is missing {key}")
    if not isinstance(binding.get("environmentId"), str) \
            or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", binding["environmentId"]) is None:
        raise AssertionError(f"{name} binding has an invalid environment id")
    if binding.get("mode") != "training" or binding.get("taskId") != task_id \
            or not _hash(binding.get("participantIdSha256")):
        raise AssertionError(f"{name} is not bound to the expected training S1 execution")
    if not _uuid(action.get("actionId")) or action.get("taskIndex") != 0 \
            or not isinstance(action.get("actionSequence"), str) or not action["actionSequence"].isdigit() \
            or not isinstance(action.get("ownerOperationId"), str) or not action["ownerOperationId"] \
            or not _hash(action.get("payloadHash")):
        raise AssertionError(f"{name} action binding is malformed")
    if action.get("initialReceiptStatus") != "unknown" or action.get("outboxStatus") != "delivered":
        raise AssertionError(f"{name} lacks the durable unknown receipt and delivered original outbox")
    return case, binding, action


def _verify_recovered_case(case: Any, database_name: str, repository_root: Path, *, task_id: str = "S1") -> dict[str, bool]:
    case, binding, action = _validate_case_common(case, "committedActionRecovery", task_id=task_id)
    if action.get("kind") != {"S1": "transfer", "S4": "approve", "M3": "approve"}.get(task_id):
        raise AssertionError("Recovery action kind does not match the selected collector case")
    if case.get("status") != "verified_local_recovery" or case.get("boundary") != \
            "real_owner_ui_bonus_code_real_bef_action_response_dropped_then_server_monitor_reconciled":
        raise AssertionError("Committed-action recovery case boundary is invalid")
    genuine = _obj(case.get("genuineRun"), "committedActionRecovery.genuineRun")
    if genuine.get("runId") != binding["runId"] or genuine.get("mode") != "training" \
            or genuine.get("taskIds") != [task_id] \
            or genuine.get("status") != f"captured_{task_id.lower()}_training_run_completed_by_server_worker":
        raise AssertionError("Recovery case does not bind the completed genuine S1 run")
    completion = _obj(genuine.get("runCompletion"), "committedActionRecovery.genuineRun.runCompletion")
    if completion.get("runStatus") != "completed" or completion.get("status") != "verified":
        raise AssertionError("Genuine run did not complete through the worker path")

    action_row = _obj(case.get("action"), "committedActionRecovery.action")
    if action_row.get("finalReceiptStatus") != "observed" or action_row.get("upstreamSubmissionCount") != 1:
        raise AssertionError("Original action did not reconcile without replay")
    source_operation = _source_operation(case.get("beFSource"), action_row, binding, name="committedActionRecovery.beFSource")
    if source_operation.get("receiptStatus") != "success":
        raise AssertionError("Recovered source operation has no successful terminal receipt")
    packet = _action_evidence(action_row.get("evidence"), repository_root=repository_root,
                              action=action_row, binding=binding,
                              expected_statuses={"observed", "unknown"}, name="committedActionRecovery.actionEvidence")
    if packet.get("status") != "observed":
        raise AssertionError("Committed-action final evidence is not observed")
    _verify_recovery_action_packet(packet, case.get("beFSource"), source_operation,
                                   name="committedActionRecovery.actionEvidence")

    recovery = _obj(case.get("recovery"), "committedActionRecovery.recovery")
    if recovery.get("status") != "recovered" or recovery.get("run_id") != binding["runId"] \
            or recovery.get("action_id") != action_row["actionId"] or recovery.get("refundCount") != 0 \
            or recovery.get("sourceOperationCount") != 1:
        raise AssertionError("Recovery journal does not bind a single original source operation")
    start_ms = _epoch_ms(recovery.get("started_at"), "committed recovery started_at")
    deadline_ms = _epoch_ms(recovery.get("deadline_at"), "committed recovery deadline_at")
    if deadline_ms != start_ms + RECOVERY_WINDOW_MS or type(recovery.get("clock_excluded_ms")) is not int \
            or not 0 <= recovery["clock_excluded_ms"] <= RECOVERY_WINDOW_MS:
        raise AssertionError("Committed recovery deadline or excluded clock is invalid")
    observations = _rows(recovery.get("observations"), "committedActionRecovery.recovery.observations")
    if not observations or any(not _hash(row.get("evidence_hash")) for row in observations):
        raise AssertionError("Recovery observation journal is missing hash-backed rows")
    proxy_ok = _proxy_fault(case.get("proxy"), action_row["actionId"])
    extra_resubmissions = (_proxy_submission_count(case.get("proxy"), action_row["actionId"]) or 0) - 1

    observer = _obj(case.get("observer"), "committedActionRecovery.observer")
    if not _observer(observer.get("identity"), database_name):
        raise AssertionError("Owner recovery snapshot is not independently read-only")
    evaluations = _rows(observer.get("evaluations"), "committedActionRecovery.observer.evaluations")
    if len(evaluations) != 1 or evaluations[0].get("taskId") != task_id \
            or not _hash(evaluations[0].get("resultHash")) or not _hash(evaluations[0].get("evaluatorSourceHash")):
        raise AssertionError("Recovered genuine run does not have one independently observed S1 evaluation")
    if task_id != "S1" and (evaluations[0].get("outcomeStatus") != "known"
                            or evaluations[0].get("outcome") != "passed"
                            or evaluations[0].get("credit") != {"numerator": "1", "denominator": "1"}
                            or evaluations[0].get("mandatoryViolationPresent") is not False):
        raise AssertionError("Recovered collector case did not receive a passing durable evaluation")
    slots = _rows(observer.get("slots"), "committedActionRecovery.observer.slots")
    claims = _rows(observer.get("claims"), "committedActionRecovery.observer.claims")
    fence = _obj(observer.get("fenceEvidence"), "committedActionRecovery.observer.fenceEvidence")
    _fence_evidence(fence, repository_root=repository_root, binding=binding,
                    name="committedActionRecovery.fenceEvidence")
    fenced = len(slots) == 1 and all(row.get("run_id") == binding["runId"] and row.get("agent_id") == binding["agentId"]
                                     and row.get("released_at") is not None for row in slots) \
        and len(claims) >= 1 and all(row.get("released_at") is not None for row in claims)
    return {
        "original_action_reconciled": source_operation["status"] == "settled" and action_row["finalReceiptStatus"] == "observed"
        and proxy_ok and extra_resubmissions == 0,
        "bounded_recovery_clock": True,
        "own_slots_fenced": fenced,
    }


def _verify_exhausted_case(case: Any, database_name: str, repository_root: Path) -> dict[str, bool]:
    case, binding, action = _validate_case_common(case, "recoveryDeadlineExhaustion")
    if case.get("status") != "verified_local_exhaustion" or case.get("boundary") != \
            "real_owner_ui_committed_bef_action_observer_outage_through_database_recovery_deadline_then_late_reconciliation":
        raise AssertionError("Recovery exhaustion case boundary is invalid")
    genuine = _obj(case.get("genuineRun"), "recoveryDeadlineExhaustion.genuineRun")
    if genuine.get("runId") != binding["runId"] or genuine.get("status") != \
            "captured_platform_recovery_exhausted_without_grade":
        raise AssertionError("Exhaustion case does not retain an ungraded terminal run")
    terminal = _obj(case.get("finalState"), "recoveryDeadlineExhaustion.finalState")
    if not _observer(terminal.get("observerIdentity"), database_name):
        raise AssertionError("Exhaustion snapshot is not independently read-only")
    run = _obj(terminal.get("run"), "recoveryDeadlineExhaustion.finalState.run")
    if run.get("id") != binding["runId"] or run.get("status") != "failed" \
            or run.get("terminal_reason") != "platform_failure_recovery_exhausted" \
            or run.get("cancellation_reason") != "coordinator_platform_failure" \
            or not _hash(run.get("cancellation_evidence_hash")):
        raise AssertionError("Exhaustion run does not preserve its fenced platform-failure terminal outcome")
    evaluations = _rows(terminal.get("evaluations"), "recoveryDeadlineExhaustion.finalState.evaluations")
    if evaluations:
        raise AssertionError("Exhausted platform failure must remain ungraded")

    action_rows = _rows(terminal.get("actions"), "recoveryDeadlineExhaustion.finalState.actions")
    owner_action = _one(action_rows, "exhausted action")
    if owner_action.get("id") != action["actionId"] or owner_action.get("operation_id") != action["ownerOperationId"] \
            or owner_action.get("payload_hash") != action["payloadHash"] \
            or owner_action.get("receipt_status") not in {"unknown", "observed"} \
            or owner_action.get("outbox_status") != "delivered":
        raise AssertionError("Exhausted action does not preserve its original durable receipt and outbox")
    if action.get("originalActionCount") != 1 or action.get("outboxStatus") != "delivered" \
            or action.get("upstreamSubmissionCount") != 1:
        raise AssertionError("Exhaustion did not retain one original action without resubmission")
    source_operation = _source_operation(case.get("sourceOperation"), action, binding, name="recoveryDeadlineExhaustion.sourceOperation")

    recovery = _obj(case.get("recovery"), "recoveryDeadlineExhaustion.recovery")
    row = _obj(recovery.get("row"), "recoveryDeadlineExhaustion.recovery.row")
    if row.get("status") != "refunded" or row.get("run_id") != binding["runId"] \
            or row.get("action_id") != action["actionId"] or row.get("operation_id") != action["ownerOperationId"]:
        raise AssertionError("Exhausted recovery row does not bind the original action/run/operation")
    start_ms = _epoch_ms(row.get("started_at"), "exhaustion started_at")
    deadline_ms = _epoch_ms(row.get("deadline_at"), "exhaustion deadline_at")
    if deadline_ms != start_ms + RECOVERY_WINDOW_MS or type(row.get("clock_excluded_ms")) is not int \
            or not 0 <= row["clock_excluded_ms"] <= RECOVERY_WINDOW_MS:
        raise AssertionError("Exhaustion recovery deadline or clock exclusion is invalid")
    deadline_observation = _obj(recovery.get("deadlineObservation"), "recoveryDeadlineExhaustion.deadlineObservation")
    deadline_row = _obj(deadline_observation.get("row"), "recoveryDeadlineExhaustion.deadlineObservation.row")
    # AICODE-NOTE: API restart consumes part of the fixed window before this callback
    # starts. The database cutoff and containing outage interval prove the full wait.
    if _epoch_ms(deadline_row.get("deadline_at"), "deadline observation deadline") != deadline_ms \
            or type(deadline_observation.get("wallWaitMs")) is not int \
            or not 0 <= deadline_observation["wallWaitMs"] <= 240_000 \
            or _epoch_ms(deadline_observation.get("observedAtDatabase"), "deadline database observation") < deadline_ms:
        raise AssertionError("Exhaustion did not wait through the real persisted recovery deadline")
    intervals = _rows(_obj(case.get("observerFault"), "recoveryDeadlineExhaustion.observerFault").get("intervals"),
                      "recoveryDeadlineExhaustion.observerFault.intervals")
    interval = _one(intervals, "observer outage interval")
    outage_started = _epoch_ms(interval.get("startedAt"), "observer outage startedAt")
    outage_ended = _epoch_ms(interval.get("endedAt"), "observer outage endedAt")
    outage_ms = outage_ended - outage_started
    if outage_ms < RECOVERY_WINDOW_MS or outage_started > start_ms or outage_ended < deadline_ms:
        raise AssertionError("Read-only source observer outage did not span the recovery deadline")

    proxy_ok = _proxy_fault(case.get("proxy"), action["actionId"])
    extra_resubmissions = (_proxy_submission_count(case.get("proxy"), action["actionId"]) or 0) - 1
    if not proxy_ok:
        raise AssertionError("Exhaustion lacks the real committed-response-drop boundary")
    if extra_resubmissions != 0:
        raise AssertionError("Exhaustion submitted an extra source operation after the original request")
    reservations = _rows(terminal.get("reservations"), "exhausted reservations")
    ledger = _rows(terminal.get("ledger"), "exhausted ledger")
    refunds = _rows(terminal.get("refunds"), "exhausted refunds")
    audits = _rows(terminal.get("refundAudits"), "exhausted refund audits")
    if len(reservations) != 1 or reservations[0].get("source_kind") != "tester_bonus" \
            or reservations[0].get("state") != "debited":
        raise AssertionError("Exhaustion did not preserve exactly one original bonus reservation")
    if not _hash(row.get("latest_evidence_hash")) or not _hash(row.get("incident_evidence_hash")):
        raise AssertionError("Exhaustion evidence lineage is not hash-bound")
    refund = _one(refunds, "platform recovery refund")
    audit = _one(audits, "platform recovery refund audit")
    run_suffix = binding["runId"].replace("-", "")
    expected_refund_operation = f"runref_{run_suffix}"
    if refund.get("run_id") != binding["runId"] or refund.get("operation_id") != expected_refund_operation \
            or refund.get("evidence_hash") != row["latest_evidence_hash"] \
            or audit.get("operation_id") != expected_refund_operation or audit.get("event_type") != "run_platform_failure_refunded" \
            or audit.get("actor_owner_id") != binding["ownerId"] or audit.get("subject_owner_id") != binding["ownerId"] \
            or audit.get("run_id") != binding["runId"] or audit.get("evidence_hash") != row["latest_evidence_hash"] \
            or audit.get("original_action_id") != action["actionId"] \
            or audit.get("original_operation_id") != action["ownerOperationId"]:
        raise AssertionError("Refund is not linked exactly once to the original owner/action/operation evidence")
    refund_entries = [entry for entry in ledger if entry.get("entry_type") == "refund"]
    if len(refund_entries) != 1 or refund_entries[0].get("source_kind") != "tester_bonus" \
            or any(entry.get("source_kind") != "tester_bonus" for entry in ledger):
        raise AssertionError("Exhaustion ledger contains an unexpected refund or cash-side effect")
    cash_refunds = [entry for entry in ledger if entry.get("entry_type") == "refund" and entry.get("source_kind") == "cash_usdc"]
    refund_units = _int_string(refund["bonus_refunded_units"], "refund bonus")
    reservation_units = _int_string(reservations[0].get("amount_units"), "reservation amount")
    if refund_units <= 0 or refund_units != reservation_units \
            or _int_string(audit["bonus_refunded_units"], "audit refund bonus") != _int_string(refund["bonus_refunded_units"], "refund bonus") \
            or cash_refunds:
        raise AssertionError("Exhaustion refund amount or cash boundary is invalid")
    if _int_string(refund_entries[0].get("amount_units"), "refund ledger amount") != refund_units \
            or _int_string(audit.get("bonus_refunded_units"), "audit refund bonus") != refund_units:
        raise AssertionError("Refund table, audit and ledger amount do not agree")
    terminal_events = _rows(terminal.get("terminalEvents"), "exhausted terminal events")
    failure_events = [event for event in terminal_events if event.get("event_type") == "run.failed.platform_recovery_exhausted"]
    if len(failure_events) != 1 or failure_events[0].get("action_id") != action["actionId"] \
            or failure_events[0].get("operation_id") != action["ownerOperationId"] \
            or failure_events[0].get("evidence_hash") != row["latest_evidence_hash"] \
            or failure_events[0].get("cash_refunded_units") != "0":
        raise AssertionError("Exactly one source-linked platform recovery terminal event is required")

    slots = _rows(terminal.get("slots"), "exhausted slots")
    claims = _rows(terminal.get("claims"), "exhausted claims")
    cancellation_events = [event for event in terminal_events if event.get("event_type") == "run.cancelled.after_start"]
    if len(cancellation_events) != 1 or cancellation_events[0].get("reason") != "coordinator_platform_failure" \
            or cancellation_events[0].get("fence_evidence_hash") != run.get("cancellation_evidence_hash"):
        raise AssertionError("Exhaustion has no durable cancellation and original slot-release fence proof")
    # Cancellation deletes its slot in the same transaction that releases the
    # claim and appends the exact after-start fence event; completion retains it.
    if len(slots) not in {0, 1} or any(slot.get("run_id") != binding["runId"] or
            slot.get("agent_id") != binding["agentId"] or slot.get("released_at") is None for slot in slots) \
            or not claims or any(claim.get("released_at") is None for claim in claims):
        raise AssertionError("Exhausted run did not fence and release only its own claim/slot")
    execution_fences = _rows(terminal.get("execution"), "exhausted execution fences") if "execution" in terminal else []
    # The terminal verifier callback returns references only; its booleans are ignored.
    terminal_evidence = _obj(case.get("terminalEvidence"), "exhausted recovery terminal evidence")
    action_evidence = terminal_evidence.get("actionEvidence")
    if not isinstance(action_evidence, dict):
        raise AssertionError("Exhaustion has no hash-backed durable action evidence reference")
    packet = _action_evidence(action_evidence, repository_root=repository_root, action={
        "actionId": action["actionId"], "ownerOperationId": action["ownerOperationId"],
        "taskIndex": action["taskIndex"], "actionSequence": action["actionSequence"],
        "kind": action["kind"], "payloadHash": action["payloadHash"],
    }, binding=binding, expected_statuses={"unknown", "observed"}, name="exhausted action evidence")
    if packet.get("status") != owner_action.get("receipt_status"):
        raise AssertionError("Exhaustion action evidence status differs from the durable receipt")
    if packet.get("status") == "observed" or "recoverySource" in packet:
        _verify_recovery_action_packet(packet, case.get("sourceOperation"), source_operation,
                                       name="exhausted action evidence")
    fence_files = _rows(terminal_evidence.get("fenceEvidenceFiles"), "exhausted fence evidence files")
    if not fence_files or any(not _hash(ref.get("sha256")) for ref in fence_files):
        raise AssertionError("Exhaustion has no hash-backed exact generation fence evidence")
    for index, reference in enumerate(fence_files):
        _fence_evidence(reference, repository_root=repository_root, binding=binding,
                        name=f"exhaustion fence evidence {index}")
    if execution_fences:
        for row_fence in execution_fences:
            if row_fence.get("lease_state") != "fenced":
                raise AssertionError("A recovery execution lease is not fenced")
    restart = _obj(recovery.get("restartReceipt"), "recoveryDeadlineExhaustion.recovery.restartReceipt")
    restart_started = _epoch_ms(restart.get("startedAt"), "API restart startedAt")
    restart_finished = _epoch_ms(restart.get("finishedAt"), "API restart finishedAt")
    fault_observed = _epoch_ms(case["proxy"]["fault"].get("observedAt"), "committed response loss observedAt")
    restart_ok = restart.get("schemaVersion") == "beta-local-api-restart-receipt/v1" \
        and restart.get("boundary") == "runner_owned_process_stop_start_and_real_health_http" \
        and type(restart.get("previousPid")) is int and type(restart.get("currentPid")) is int \
        and restart["previousPid"] != restart["currentPid"] \
        and restart.get("healthHttpStatus") == 200 \
        and fault_observed <= restart_started <= restart_finished <= deadline_ms \
        and start_ms <= restart_finished
    # Do not require a late original source receipt to remain unknown: observing it later must not reopen the run.
    unknown_retained = run["status"] == "failed" and run["terminal_reason"] == "platform_failure_recovery_exhausted" and not evaluations
    return {
        "bounded_recovery_clock": True,
        "unknown_retained": unknown_retained,
        "refund_once_source_linked": True,
        "own_slots_fenced": True,
        "original_action_reconciled": source_operation["status"] == "settled" and proxy_ok,
        "response_lost_after_effect": proxy_ok,
        "recovery_exhaustion": outage_ms >= RECOVERY_WINDOW_MS and deadline_ms == start_ms + RECOVERY_WINDOW_MS,
        "restart": restart_ok,
    }


def _int_string(value: Any, name: str) -> int:
    if not isinstance(value, (str, int)) or isinstance(value, bool) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", str(value)):
        raise AssertionError(f"{name} must be a nonnegative integer unit string")
    return int(value)


def derive_observations(scenario_id: str, evidence: dict[str, Any], *, repository_root: Path | None = None) -> dict[str, bool] | None:
    """Return full SC017 fact inventory from raw local producer evidence.

    ``False`` means the fact is not established by this local capture; it never
    means an official target-host negative has been disproved.
    """
    if scenario_id != SCENARIO_ID or not isinstance(evidence, dict):
        return None
    if evidence.get("schemaVersion") != RECOVERY_SCHEMA or evidence.get("scenarioId") != SCENARIO_ID \
            or evidence.get("boundary") != LOCAL_BOUNDARY:
        return None
    database = _obj(evidence.get("database"), "recovery.database")
    database_name = database.get("name")
    if not isinstance(database_name, str) or not ACCEPTANCE_DB_RE.fullmatch(database_name) \
            or database.get("uniquePerCapture") is not True:
        raise AssertionError("Recovery evidence is not bound to one unique isolated acceptance database")
    repo = repository_root or Path(__file__).resolve().parents[3]
    cases = _obj(evidence.get("cases"), "recovery.cases")
    recovered_facts = _verify_recovered_case(cases.get("committedActionRecovery"), database_name, repo)
    exhausted_facts = _verify_exhausted_case(cases.get("recoveryDeadlineExhaustion"), database_name, repo)
    collector_cases = evidence.get("collectorCases")
    if collector_cases is not None:
        collector_cases = _obj(collector_cases, "recovery.collectorCases")
        if set(collector_cases) != {"S4", "M3"}:
            raise AssertionError("Collector recovery cases must cover both S4 and chain")
        for task_id, collector_case in collector_cases.items():
            collector_facts = _verify_recovered_case(collector_case, database_name, repo, task_id=task_id)
            if not all(collector_facts.values()):
                raise AssertionError(f"Collector recovery not proven for {task_id}")
    facts = {name: False for name in (*OBSERVATION_NAMES, *NEGATIVE_NAMES)}
    facts.update(recovered_facts)
    facts.update(exhausted_facts)
    # The local suite explicitly has not exercised ordered owner-cancel/revoke races,
    # duplicate terminal delivery, stale callbacks or forged failure reports.
    return facts


def _verify_provenance(capture: dict[str, Any], repository_root: Path) -> tuple[str, dict[str, Any]]:
    provenance = _obj(capture.get("provenance"), "capture.provenance")
    if provenance.get("sourceStableDuringRun") is not True:
        raise AssertionError("Recovery capture source was not stable during the run")
    before, after = provenance.get("inputHashesBefore"), provenance.get("inputHashesAfter")
    if not isinstance(before, dict) or not before or before != after:
        raise AssertionError("Recovery capture is missing an identical source inventory")
    root = repository_root.resolve(strict=True)
    for relative, digest in before.items():
        if not isinstance(relative, str) or "\\" in relative or ":" in relative \
                or PurePosixPath(relative).is_absolute() or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts) \
                or not _hash(digest):
            raise AssertionError("Recovery provenance contains an unsafe source inventory entry")
        if relative in _REPLAY_READER_PATHS:
            continue
        path = root.joinpath(*PurePosixPath(relative).parts).resolve(strict=True)
        if root not in path.parents or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise AssertionError(f"Recovery source inventory no longer matches {relative}")
    isolation = _obj(provenance.get("databaseIsolation"), "capture.provenance.databaseIsolation")
    name = isolation.get("databaseName")
    if not isinstance(name, str) or not ACCEPTANCE_DB_RE.fullmatch(name) or isolation.get("uniquePerCapture") is not True:
        raise AssertionError("Capture provenance does not identify a unique acceptance database")
    return name, provenance


def verify_local_recovery_result(result: dict[str, Any], database_name: str, *, repository_root: Path | None = None) -> dict[str, bool]:
    """Derive local SC017 facts from a result embedded in either runner capture."""
    repo = repository_root or Path(__file__).resolve().parents[3]
    if not isinstance(result, dict) or result.get("schemaVersion") != RECOVERY_SCHEMA \
            or result.get("scenarioId") != SCENARIO_ID or result.get("status") != "verified" \
            or _obj(result.get("database"), "embedded recovery database").get("name") != database_name:
        raise AssertionError("Embedded recovery result does not match its capture/database identity")
    facts = derive_observations(SCENARIO_ID, result, repository_root=repo)
    if facts is None:
        raise AssertionError("Embedded recovery result has an unsupported local boundary")
    return facts


def verify_local_recovery_capture(capture: dict[str, Any], *, repository_root: Path | None = None) -> dict[str, Any]:
    """Verify the standalone runner artifact and report local SC017 facts only."""
    capture = _obj(capture, "capture")
    if capture.get("schemaVersion") != "beta-platform-recovery-capture/v1" \
            or not _uuid(capture.get("captureId")) \
            or capture.get("boundary") != "isolated_local_browser_backend_postgres_bef_files":
        raise AssertionError("Standalone recovery capture wrapper identity is invalid")
    root = repository_root or Path(__file__).resolve().parents[3]
    database_name, provenance = _verify_provenance(capture, root)
    result = _obj(capture.get("result"), "capture.result")
    if result.get("schemaVersion") != RECOVERY_SCHEMA or result.get("scenarioId") != SCENARIO_ID:
        raise AssertionError("Standalone recovery result schema or scenario is invalid")
    if result.get("database", {}).get("name") != database_name:
        raise AssertionError("Recovery result and runner provenance refer to different databases")
    if result.get("status") != "verified":
        return _local_result(capture["captureId"], database_name, provenance, {}, blocked=True,
                             blocked_reason=result.get("status", "capture_not_verified"))
    facts = verify_local_recovery_result(result, database_name, repository_root=root)
    return _local_result(capture["captureId"], database_name, provenance, facts)


def _local_result(capture_id: str, database_name: str, provenance: dict[str, Any], facts: dict[str, bool],
                  *, blocked: bool = False, blocked_reason: Any = None) -> dict[str, Any]:
    observations = {name: ("verified" if facts.get(name) else "not_run") for name in OBSERVATION_NAMES}
    negatives = {name: ("verified" if facts.get(name) else "not_run") for name in NEGATIVE_NAMES}
    return {
        "schemaVersion": "bpc-local-platform-recovery-replay/v1",
        "captureId": capture_id,
        "databaseName": database_name,
        "localStatus": "blocked" if blocked else "observed_partial",
        "sourceStableDuringRun": provenance.get("sourceStableDuringRun") is True,
        "observations": observations,
        "negativeVariants": negatives,
        "targetHostAcceptance": "not_run",
        "fullScenarioAcceptance": "not_run",
        **({"blockedReason": blocked_reason} if blocked else {}),
    }
