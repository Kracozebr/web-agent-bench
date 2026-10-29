from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.bdd.adapters.beta_poc_recovery_verifier import (
    NEGATIVE_NAMES,
    OBSERVATION_NAMES,
    _verify_recovered_case,
    derive_observations,
    verify_local_recovery_capture,
)


DATABASE = "oid_acceptance_" + "a" * 32
NOW = "2026-10-29T10:00:00.000Z"
DEADLINE = "2026-10-29T10:03:00.000Z"
LATEST_EVIDENCE = "b" * 64
INCIDENT_EVIDENCE = "c" * 64
TRANSACTION = "0x" + "d" * 64


def _hash(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _write_json(root: Path, relative: str, value: dict) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(data)
    return {"path": relative, "sha256": _hash(data), "bytes": len(data)}


def _evidence_packet(binding: dict, action: dict, status: str, source: dict | None = None) -> dict:
    packet = {
        "schema": "bef-task-action-observation-v1",
        "actionId": action["actionId"],
        "runId": binding["runId"],
        "taskIndex": action["taskIndex"],
        "actionSequence": action["actionSequence"],
        "ownerOperationId": action["ownerOperationId"],
        "actionKind": action["kind"],
        "commandSha256": action["payloadHash"],
        "environmentId": binding["environmentId"],
        "generationId": binding["generationId"],
        "idempotencyKey": f"task-action-{action['actionId']}",
        "status": status,
        "reasonCode": "platform_recovery_original_operation_observed" if status == "observed" else "platform_recovery_observer_unavailable",
    }
    if status == "observed" and source is not None:
        operation = source["operations"][0]
        selected = source["selectedExecutions"][0]
        packet.update({
            "reasonCode": "platform_recovery_original_operation_terminal",
            "befOperationId": operation["operationId"],
            "transactionHash": operation["transactionHash"],
            "receiptStatus": "success",
            "outcome": "success",
            "receiptGasUsed": selected["receipt"]["gasUsed"],
            "receiptEffectiveGasPriceWei": selected["receipt"]["effectiveGasPriceWei"],
            "recoverySource": source["recoverySource"],
        })
    return packet


def _fence_packet(binding: dict) -> dict:
    pins = "e" * 64
    return {
        "schemaVersion": "owner-bef-task-preparation-evidence/v1",
        "kind": "fence",
        "preparationId": binding["preparationId"],
        "environmentId": binding["environmentId"],
        "publicPinsSha256": pins,
        "evidence": {
            "publicPinsSha256": pins,
            "actualBefGenerationId": binding["generationId"],
            "expectedOwnerGenerationId": binding["generationId"],
            "fenceConfirmed": True,
            "before": {
                "schemaVersion": "bef-preparation-status/v1",
                "status": "ready",
                "preparationId": binding["preparationId"],
                "envId": binding["environmentId"],
                "generationId": binding["generationId"],
                "request": {"publicPinsSha256": pins},
                "fixture": {"state": "observed", "fixtureHash": "f" * 64},
            },
            "after": {
                "schemaVersion": "bef-preparation-status/v1",
                "status": "fenced",
                "fenceConfirmedAt": "2026-10-29T10:04:00.000Z",
            },
        },
    }


def _source(binding: dict, action: dict) -> dict:
    key_hash = _hash(f"task-action-{action['actionId']}")
    operation = {
        "operationId": str(uuid4()),
        "environmentId": binding["environmentId"],
        "generationId": binding["generationId"],
        "participantIdSha256": binding["participantIdSha256"],
        "idempotencyKeySha256": key_hash,
        "requestSha256": "1" * 64,
        "operationKind": action["kind"],
        "status": "settled",
        "transactionHash": TRANSACTION,
        "receiptStatus": "success",
        "responseSha256": None,
        "generationStatus": "fenced",
        "fencedAt": DEADLINE,
    }
    selected = {
        "operationId": operation["operationId"],
        "selectedActionKind": "transfer",
        "selectedActionSha256": "2" * 64,
        "selectedOutcome": "success",
        "selectedTransactionHash": TRANSACTION,
        "selectedMeasurementSha256": "3" * 64,
        "selectedActionEventCount": 1,
        "selectedActionEventKind": "selected_action_bound",
        "selectedActionEventActionKind": "transfer",
        "selectedActionEventRequestSha256": operation["requestSha256"],
        "selectedActionEventSelectedActionSha256": "2" * 64,
        "selectedActionEventSha256": "4" * 64,
        "generationManifestSha256": "5" * 64,
        "environmentManifestSha256": "6" * 64,
        "receipt": {"transactionHash": TRANSACTION, "status": "success", "gasUsed": "21000",
                    "effectiveGasPriceWei": "100"},
    }
    recovery_source = {"schema": "bef-recovery-source/v1", "sourceSnapshotSha256": "7" * 64,
                      "selectedMeasurementSha256": selected["selectedMeasurementSha256"],
                      "sourceResponseSha256": None}
    rows = [operation]
    return {
        "identity": {"role": "bef_observer", "databaseName": "bef", "transactionReadOnly": "on"},
        "keySha256": key_hash,
        "result": rows,
        "operations": rows,
        "selectedExecutions": [selected],
        "recoverySource": recovery_source,
    }


def _proxy(action_id: str) -> dict:
    return {
        "schemaVersion": "beta-recovery-transport-fault/v1",
        "boundary": "real_upstream_http_response_withheld_after_complete_read",
        "fault": {
            "actionId": action_id,
            "method": "POST",
            "path": "/pay",
            "upstreamStatus": 200,
            "upstreamResponseSha256": "3" * 64,
            "responseBytes": 160,
            "upstreamResponseComplete": True,
            "downstreamResponseDelivered": False,
            "observedAt": "2026-10-29T10:00:10.000Z",
        },
        "submissions": [{"actionId": action_id, "count": 1}],
    }


def _case_ids() -> tuple[dict, dict]:
    binding = {
        "runId": str(uuid4()),
        "ownerId": str(uuid4()),
        "agentId": str(uuid4()),
        "mode": "training",
        "taskId": "S1",
        "environmentId": "bef-env-a",
        "preparationId": str(uuid4()),
        "generationId": str(uuid4()),
        "participantIdSha256": "4" * 64,
        "leaseId": str(uuid4()),
    }
    action = {
        "actionId": str(uuid4()),
        "ownerOperationId": str(uuid4()),
        "taskIndex": 0,
        "actionSequence": "1",
        "kind": "transfer",
        "payloadHash": "5" * 64,
        "initialReceiptStatus": "unknown",
        "outboxStatus": "delivered",
    }
    return binding, action


def _make_result(root: Path) -> dict:
    success_binding, success_action = _case_ids()
    success_action.update({"finalReceiptStatus": "observed", "upstreamSubmissionCount": 1})
    success_source = _source(success_binding, success_action)
    success_action["evidence"] = _write_json(root, "evidence/success-action.json",
                                               _evidence_packet(success_binding, success_action, "observed", success_source))
    success_fence = _write_json(root, "evidence/success-fence.json", _fence_packet(success_binding))
    success_claim_id = str(uuid4())
    success_started = NOW
    success_deadline = DEADLINE
    success = {
        "schemaVersion": "bpc-platform-recovery-case/v1",
        "captureId": str(uuid4()),
        "status": "verified_local_recovery",
        "boundary": "real_owner_ui_bonus_code_real_bef_action_response_dropped_then_server_monitor_reconciled",
        "genuineRun": {"runId": success_binding["runId"],
                       "status": "captured_s1_training_run_completed_by_server_worker", "mode": "training",
                       "taskIds": ["S1"], "runCompletion": {"status": "verified", "runStatus": "completed"}},
        "action": success_action,
        "binding": success_binding,
        "recovery": {"status": "recovered", "run_id": success_binding["runId"],
                     "action_id": success_action["actionId"], "refundCount": 0, "sourceOperationCount": 1,
                     "started_at": success_started, "deadline_at": success_deadline, "clock_excluded_ms": 0,
                     "observations": [{"evidence_hash": LATEST_EVIDENCE, "receipt_status": "observed",
                                       "clock_excluded_ms": 0, "observed_at": "2026-10-29T10:00:15.000Z"}]},
        "beFSource": success_source,
        "proxy": _proxy(success_action["actionId"]),
        "observer": {"identity": {"role": "oid_observer", "databaseName": DATABASE, "transactionReadOnly": "on"},
                     "evaluations": [{"taskId": "S1", "resultHash": "6" * 64, "evaluatorSourceHash": "7" * 64}],
                     "slots": [{"run_id": success_binding["runId"], "agent_id": success_binding["agentId"],
                                "claim_id": success_claim_id, "state": "running", "released_at": DEADLINE}],
                     "claims": [{"run_id": success_binding["runId"], "claim_id": success_claim_id,
                                 "status": "released", "released_at": DEADLINE}],
                     "fenceEvidence": success_fence},
    }

    exhausted_binding, exhausted_action = _case_ids()
    exhausted_action.update({"finalReceiptStatus": "unknown", "originalActionCount": 1,
                             "upstreamSubmissionCount": 1, "refundEntryCount": 1, "cashRefundedUnits": "0"})
    exhausted_source = _source(exhausted_binding, exhausted_action)
    exhausted_ref = _write_json(root, "evidence/exhausted-action.json",
                                _evidence_packet(exhausted_binding, exhausted_action, "unknown"))
    exhausted_fence = _write_json(root, "evidence/exhausted-fence.json", _fence_packet(exhausted_binding))
    refund_operation = "runref_" + exhausted_binding["runId"].replace("-", "")
    refund_units = "500000"
    recovery_row = {"status": "refunded", "action_id": exhausted_action["actionId"],
                    "run_id": exhausted_binding["runId"], "operation_id": exhausted_action["ownerOperationId"],
                    "owner_id": exhausted_binding["ownerId"], "agent_id": exhausted_binding["agentId"],
                    "environment_id": exhausted_binding["environmentId"], "task_index": 0,
                    "payload_hash": exhausted_action["payloadHash"], "started_at": NOW, "deadline_at": DEADLINE,
                    "clock_excluded_ms": 0, "incident_evidence_hash": INCIDENT_EVIDENCE,
                    "latest_evidence_hash": LATEST_EVIDENCE}
    exhaustion = {
        "schemaVersion": "bpc-platform-recovery-case/v1",
        "captureId": str(uuid4()),
        "status": "verified_local_exhaustion",
        "boundary": "real_owner_ui_committed_bef_action_observer_outage_through_database_recovery_deadline_then_late_reconciliation",
        "genuineRun": {"runId": exhausted_binding["runId"], "status": "captured_platform_recovery_exhausted_without_grade"},
        "action": exhausted_action,
        "binding": exhausted_binding,
        "recovery": {"row": recovery_row,
                     "deadlineObservation": {"row": {"deadline_at": DEADLINE}, "wallWaitMs": 181_000,
                                             "observedAtDatabase": "2026-10-29T10:03:02.000Z"},
                     "restartReceipt": {"schemaVersion": "beta-local-api-restart-receipt/v1",
                                        "startedAt": "2026-10-29T10:00:01.000Z", "finishedAt": "2026-10-29T10:00:03.000Z",
                                        "previousPid": 101, "currentPid": 102, "healthHttpStatus": 200,
                                        "boundary": "runner_owned_process_stop_start_and_real_health_http"}},
        "sourceOperation": exhausted_source,
        "proxy": _proxy(exhausted_action["actionId"]),
        "observerFault": {"intervals": [{"startedAt": "2026-10-29T10:00:00.000Z",
                                           "endedAt": "2026-10-29T10:03:01.000Z"}]},
        "terminalEvidence": {"actionEvidence": exhausted_ref, "fenceEvidenceFiles": [exhausted_fence]},
        "finalState": {
            "observerIdentity": {"role": "oid_observer", "databaseName": DATABASE, "transactionReadOnly": "on"},
            "run": {"id": exhausted_binding["runId"], "owner_id": exhausted_binding["ownerId"],
                    "status": "failed", "terminal_reason": "platform_failure_recovery_exhausted",
                    "cancellation_reason": "coordinator_platform_failure", "cancellation_evidence_hash": "8" * 64},
            "actions": [{"id": exhausted_action["actionId"], "operation_id": exhausted_action["ownerOperationId"],
                         "payload_hash": exhausted_action["payloadHash"], "receipt_status": "unknown", "outbox_status": "delivered"}],
            "evaluations": [],
            "reservations": [{"source_kind": "tester_bonus", "state": "debited", "amount_units": refund_units}],
            "ledger": [
                {"entry_type": "reserve", "source_kind": "tester_bonus", "amount_units": refund_units},
                {"entry_type": "debit", "source_kind": "tester_bonus", "amount_units": refund_units},
                {"entry_type": "refund", "source_kind": "tester_bonus", "amount_units": refund_units},
            ],
            "refunds": [{"run_id": exhausted_binding["runId"], "operation_id": refund_operation,
                         "evidence_hash": LATEST_EVIDENCE, "bonus_refunded_units": refund_units}],
            "refundAudits": [{"operation_id": refund_operation, "event_type": "run_platform_failure_refunded",
                              "actor_owner_id": exhausted_binding["ownerId"], "subject_owner_id": exhausted_binding["ownerId"],
                              "run_id": exhausted_binding["runId"], "evidence_hash": LATEST_EVIDENCE,
                              "bonus_refunded_units": refund_units, "original_action_id": exhausted_action["actionId"],
                              "original_operation_id": exhausted_action["ownerOperationId"]}],
            "slots": [{"run_id": exhausted_binding["runId"], "agent_id": exhausted_binding["agentId"], "released_at": DEADLINE}],
            "claims": [{"released_at": DEADLINE}],
            "terminalEvents": [{"event_type": "run.failed.platform_recovery_exhausted",
                                "action_id": exhausted_action["actionId"], "operation_id": exhausted_action["ownerOperationId"],
                                "evidence_hash": LATEST_EVIDENCE, "bonus_refunded_units": refund_units,
                                "cash_refunded_units": "0"},
                               {"event_type": "run.cancelled.after_start", "reason": "coordinator_platform_failure",
                                "fence_evidence_hash": "8" * 64}],
        },
    }
    exhaustion["proxy"]["fault"]["observedAt"] = "2026-10-29T09:59:59.000Z"
    return {
        "schemaVersion": "bpc-platform-recovery-runtime-observation/v1",
        "scenarioId": "BPC-SC-017",
        "status": "verified",
        "boundary": "isolated_local_owner_browser_api_postgres_bef_observer_and_real_loopback_fault_proxies",
        "database": {"name": DATABASE, "uniquePerCapture": True, "retainedForInspection": True},
        "cases": {"committedActionRecovery": success, "recoveryDeadlineExhaustion": exhaustion},
        "claims": {"responseLostAfterEffect": False, "fakeEvidence": False},
    }


def _wrapper(root: Path, result: dict) -> dict:
    source = root / "src" / "runtime.mjs"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("stable source\n", encoding="utf-8")
    digest = _hash(source.read_bytes())
    return {
        "schemaVersion": "beta-platform-recovery-capture/v1",
        "captureId": str(uuid4()),
        "boundary": "isolated_local_browser_backend_postgres_bef_files",
        "result": result,
        "provenance": {"sourceStableDuringRun": True,
                       "inputHashesBefore": {"src/runtime.mjs": digest},
                       "inputHashesAfter": {"src/runtime.mjs": digest},
                       "databaseIsolation": {"databaseName": DATABASE, "uniquePerCapture": True}},
        "targetHostAcceptance": "blocked_target_not_selected",
    }


def test_local_sc017_facts_are_derived_from_exact_original_operation_and_postgres_rows(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    facts = derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    assert set(facts) == set((*OBSERVATION_NAMES, *NEGATIVE_NAMES))
    assert facts["original_action_reconciled"] is True
    assert facts["bounded_recovery_clock"] is True
    assert facts["unknown_retained"] is True
    assert facts["refund_once_source_linked"] is True
    assert facts["own_slots_fenced"] is True
    assert facts["response_lost_after_effect"] is True
    assert facts["recovery_exhaustion"] is True
    assert facts["restart"] is True
    success = result["cases"]["committedActionRecovery"]
    source_operation = success["beFSource"]["operations"][0]
    assert source_operation["responseSha256"] is None
    assert success["beFSource"]["recoverySource"]["sourceResponseSha256"] is None
    assert success["proxy"]["fault"]["upstreamResponseSha256"] is not None
    assert facts["cancel_start_order_exact"] is False
    assert facts["cancel_before_start"] is False
    assert facts["revoke_after_start"] is False
    assert facts["duplicate_terminal"] is False
    assert facts["stale_callback"] is False
    assert facts["forged_failure_report"] is False


def test_completed_recovery_accepts_deleted_slot_only_with_exact_fence_and_released_claim(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    case = result["cases"]["committedActionRecovery"]
    case["observer"]["slots"] = []

    facts = _verify_recovered_case(case, DATABASE, tmp_path)
    assert facts["own_slots_fenced"] is True

    fence_path = tmp_path / case["observer"]["fenceEvidence"]["path"]
    fence_packet = json.loads(fence_path.read_text(encoding="utf-8"))
    fence_packet["evidence"]["fenceConfirmed"] = False
    case["observer"]["fenceEvidence"] = _write_json(tmp_path, "evidence/unconfirmed-fence.json", fence_packet)
    with pytest.raises(AssertionError, match="does not prove the exact preparation/generation fence"):
        _verify_recovered_case(case, DATABASE, tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["active_slot", "foreign_slot_run", "foreign_slot_agent", "foreign_slot_claim", "multiple_slots",
     "foreign_claim", "missing_claim", "missing_claim_after_slot_deletion", "claimed_claim", "null_claim_release"],
)
def test_completed_recovery_rejects_unreleased_or_foreign_slot_and_claim_rows(
    tmp_path: Path, mutation: str,
) -> None:
    result = _make_result(tmp_path)
    observer = result["cases"]["committedActionRecovery"]["observer"]
    if mutation == "active_slot":
        observer["slots"][0]["released_at"] = None
    elif mutation == "foreign_slot_run":
        observer["slots"][0]["run_id"] = str(uuid4())
    elif mutation == "foreign_slot_agent":
        observer["slots"][0]["agent_id"] = str(uuid4())
    elif mutation == "foreign_slot_claim":
        observer["slots"][0]["claim_id"] = str(uuid4())
    elif mutation == "multiple_slots":
        observer["slots"].append(copy.deepcopy(observer["slots"][0]))
    elif mutation == "foreign_claim":
        observer["claims"][0]["run_id"] = str(uuid4())
    elif mutation == "missing_claim":
        observer["claims"] = []
    elif mutation == "missing_claim_after_slot_deletion":
        observer["claims"] = []
        observer["slots"] = []
    elif mutation == "claimed_claim":
        observer["claims"][0]["status"] = "claimed"
    elif mutation == "null_claim_release":
        observer["claims"][0]["released_at"] = None

    facts = _verify_recovered_case(result["cases"]["committedActionRecovery"], DATABASE, tmp_path)
    assert facts["own_slots_fenced"] is False


def test_producer_claim_booleans_cannot_promote_missing_race_negative(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    result["claims"].update({name: True for name in NEGATIVE_NAMES})
    facts = derive_observations("BPC-SC-017", result, repository_root=tmp_path)
    assert facts["cancel_before_start"] is False
    assert facts["forged_failure_report"] is False


def test_collector_coverage_cannot_relabel_s1_or_omit_chain(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    success = result["cases"]["committedActionRecovery"]
    result["collectorCases"] = {"S4": copy.deepcopy(success)}
    with pytest.raises(AssertionError, match="cover both"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)
    result["collectorCases"]["M3"] = copy.deepcopy(success)
    with pytest.raises(AssertionError, match="expected training"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_deleted_cancelled_slot_requires_the_original_durable_fence_and_released_claim(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    terminal = result["cases"]["recoveryDeadlineExhaustion"]["finalState"]
    terminal["slots"] = []
    assert derive_observations("BPC-SC-017", result, repository_root=tmp_path)["own_slots_fenced"]
    terminal["terminalEvents"] = [row for row in terminal["terminalEvents"] if row["event_type"] != "run.cancelled.after_start"]
    with pytest.raises(AssertionError, match="slot-release fence proof"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_replay_rejects_duplicate_source_operation_and_mismatched_refund_lineage(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    result["cases"]["committedActionRecovery"]["beFSource"]["operations"].append(
        copy.deepcopy(result["cases"]["committedActionRecovery"]["beFSource"]["operations"][0]))
    with pytest.raises(AssertionError, match="exactly one row"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    result["cases"]["recoveryDeadlineExhaustion"]["finalState"]["refundAudits"][0]["original_action_id"] = str(uuid4())
    with pytest.raises(AssertionError, match="Refund is not linked exactly once"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_replay_rejects_fabricated_wire_hash_and_unbound_selected_measurement(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    source = result["cases"]["committedActionRecovery"]["beFSource"]
    source["operations"][0]["responseSha256"] = "9" * 64
    source["result"][0]["responseSha256"] = "9" * 64
    with pytest.raises(AssertionError, match="does not prove the exact fenced terminal operation"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    source = result["cases"]["committedActionRecovery"]["beFSource"]
    source["operations"][0].pop("responseSha256", None)
    source["result"][0].pop("responseSha256", None)
    with pytest.raises(AssertionError, match="does not prove the exact fenced terminal operation"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    result["cases"]["committedActionRecovery"]["beFSource"]["recoverySource"]["selectedMeasurementSha256"] = "9" * 64
    with pytest.raises(AssertionError, match="selected execution, measurement, receipt, and bound event"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    selected = result["cases"]["committedActionRecovery"]["beFSource"]["selectedExecutions"][0]
    selected["selectedActionEventRequestSha256"] = "9" * 64
    with pytest.raises(AssertionError, match="selected execution, measurement, receipt, and bound event"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_recovered_action_evidence_must_match_source_proof_and_omit_wire_response_claims(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    case = result["cases"]["committedActionRecovery"]
    evidence_path = tmp_path / case["action"]["evidence"]["path"]
    packet = json.loads(evidence_path.read_text(encoding="utf-8"))
    packet["recoverySource"]["sourceSnapshotSha256"] = "9" * 64
    case["action"]["evidence"] = _write_json(tmp_path, "evidence/success-action-mismatch.json", packet)
    with pytest.raises(AssertionError, match="does not use the original source receipt"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    case = result["cases"]["committedActionRecovery"]
    evidence_path = tmp_path / case["action"]["evidence"]["path"]
    packet = json.loads(evidence_path.read_text(encoding="utf-8"))
    packet["httpStatus"] = 200
    case["action"]["evidence"] = _write_json(tmp_path, "evidence/success-action-wire-claim.json", packet)
    with pytest.raises(AssertionError, match="does not use the original source receipt"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    case = result["cases"]["committedActionRecovery"]
    evidence_path = tmp_path / case["action"]["evidence"]["path"]
    packet = json.loads(evidence_path.read_text(encoding="utf-8"))
    packet["rawResponseSha256"] = None
    case["action"]["evidence"] = _write_json(tmp_path, "evidence/success-action-response-property.json", packet)
    with pytest.raises(AssertionError, match="does not use the original source receipt"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_upstream_submission_count_is_one_and_extra_resubmissions_are_derived(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    result["cases"]["committedActionRecovery"]["action"]["upstreamSubmissionCount"] = 2
    with pytest.raises(AssertionError, match="Original action did not reconcile without replay"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    result["cases"]["recoveryDeadlineExhaustion"]["proxy"]["submissions"][0]["count"] = 2
    with pytest.raises(AssertionError, match="Exhaustion lacks the real committed-response-drop boundary"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_replay_rejects_cash_refund_and_fence_path_escape(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    result["cases"]["recoveryDeadlineExhaustion"]["finalState"]["ledger"].append(
        {"entry_type": "refund", "source_kind": "cash_usdc", "amount_units": "1"})
    with pytest.raises(AssertionError, match="unexpected refund or cash-side effect"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)

    result = _make_result(tmp_path)
    result["cases"]["committedActionRecovery"]["observer"]["fenceEvidence"]["path"] = "../outside.json"
    with pytest.raises(AssertionError, match="reference shape is invalid|reference path is unsafe"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


def test_restart_variant_requires_new_process_and_health_receipt(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    result["cases"]["recoveryDeadlineExhaustion"]["recovery"]["restartReceipt"]["currentPid"] = 101
    facts = derive_observations("BPC-SC-017", result, repository_root=tmp_path)
    assert facts["restart"] is False


def test_restart_time_is_part_of_the_full_outage_not_repeated_by_the_callback_wait(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    case = result["cases"]["recoveryDeadlineExhaustion"]
    case["recovery"]["deadlineObservation"]["wallWaitMs"] = 174_000
    assert derive_observations("BPC-SC-017", result, repository_root=tmp_path)["recovery_exhaustion"] is True
    case["observerFault"]["intervals"][0].update(
        startedAt="2026-10-29T10:00:01.000Z", endedAt="2026-10-29T10:03:02.000Z")
    with pytest.raises(AssertionError, match="outage did not span"):
        derive_observations("BPC-SC-017", result, repository_root=tmp_path)


@pytest.mark.parametrize("started,finished,expected", [
    ("2026-10-29T09:59:59.500Z", "2026-10-29T10:00:01.000Z", True),
    ("2026-10-29T09:59:58.000Z", "2026-10-29T10:00:01.000Z", False),
    ("2026-10-29T09:59:59.100Z", "2026-10-29T09:59:59.500Z", True),
    ("2026-10-29T10:02:59.000Z", "2026-10-29T10:03:01.000Z", False),
])
def test_restart_must_follow_response_loss_and_finish_before_recovery_deadline(
        tmp_path: Path, started: str, finished: str, expected: bool) -> None:
    result = _make_result(tmp_path)
    receipt = result["cases"]["recoveryDeadlineExhaustion"]["recovery"]["restartReceipt"]
    receipt.update(startedAt=started, finishedAt=finished)
    assert derive_observations("BPC-SC-017", result, repository_root=tmp_path)["restart"] is expected


def test_restart_can_finish_just_before_monitor_persists_recovery_row(tmp_path: Path) -> None:
    result = _make_result(tmp_path)
    case = result["cases"]["recoveryDeadlineExhaustion"]
    recovery = case["recovery"]
    recovery["row"].update(started_at="2026-10-29T10:00:03.024Z",
                           deadline_at="2026-10-29T10:03:03.024Z")
    recovery["deadlineObservation"]["row"]["deadline_at"] = "2026-10-29T10:03:03.024Z"
    recovery["deadlineObservation"]["observedAtDatabase"] = "2026-10-29T10:03:04.024Z"
    recovery["restartReceipt"].update(startedAt="2026-10-29T10:00:01.000Z",
                                      finishedAt="2026-10-29T10:00:03.000Z")
    case["observerFault"]["intervals"][0]["endedAt"] = "2026-10-29T10:03:04.024Z"

    facts = derive_observations("BPC-SC-017", result, repository_root=tmp_path)
    assert facts["restart"] is True


def test_standalone_wrapper_verifies_provenance_and_never_promotes_target_gate(tmp_path: Path) -> None:
    capture = _wrapper(tmp_path, _make_result(tmp_path))
    replay = verify_local_recovery_capture(capture, repository_root=tmp_path)
    assert replay["schemaVersion"] == "bpc-local-platform-recovery-replay/v1"
    assert replay["localStatus"] == "observed_partial"
    assert replay["targetHostAcceptance"] == "not_run"
    assert replay["fullScenarioAcceptance"] == "not_run"
    assert replay["observations"]["original_action_reconciled"] == "verified"
    assert replay["observations"]["cancel_start_order_exact"] == "not_run"

    capture["provenance"]["inputHashesAfter"]["src/runtime.mjs"] = "0" * 64
    with pytest.raises(AssertionError, match="identical source inventory"):
        verify_local_recovery_capture(capture, repository_root=tmp_path)
