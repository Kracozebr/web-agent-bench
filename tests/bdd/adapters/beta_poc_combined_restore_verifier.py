"""Local SC022/026 replay from source, restore, HTTP and file observations.

This never enables a restored executor or changes the target-host BPC gate.
Producer status/claims booleans are not acceptance evidence.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

OBSERVATIONS = (
    "consistent_checkpoint_verified", "code_ledger_reports_results_equal",
    "hashes_and_original_ids_match", "safe_retry", "no_external_resubmission",
    "rpo_rto_disclosed", "restored_screenshot_bytes_and_hashes_match",
    "expired_reports_checked_against_deletion_receipts",
)
NEGATIVES = (
    "interrupted_run", "missing_artifact", "hash_mismatch", "missing_recovery_secret",
    "repeated_operation", "missing_screenshot_file", "corrupt_screenshot_bytes",
    "restore_past_report_retention",
)
HASH = re.compile(r"^[0-9a-f]{64}$")
RESTORE_DB = re.compile(r"^oid_restore_[0-9a-f]{32}$")
REQUIRED_TABLES = {
    "oid_benchmark_run", "oid_bonus_code", "oid_bonus_grant", "oid_ledger_entry",
    "oid_run_operation", "oid_run_task_action_receipt", "oid_run_task_evaluation",
    "oid_task_preparation_generation", "oid_support_report", "oid_support_image_upload",
}


def _need(condition: Any, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _hash(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def _file(root: Path, reference: dict) -> bytes:
    rel = reference.get("path", reference.get("relativePath"))
    _need(isinstance(rel, str) and rel and "\\" not in rel and ":" not in rel,
          "unsafe_artifact_reference")
    path = PurePosixPath(rel)
    _need(not path.is_absolute() and all(p not in (".", "..") for p in path.parts),
          "unsafe_artifact_reference")
    candidate = root.joinpath(*path.parts)
    _need(candidate.resolve().is_relative_to(root.resolve()), "artifact_escaped_repository")
    cursor = root
    for component in path.parts:
        cursor = cursor / component
        _need(not cursor.is_symlink(), "artifact_symlink")
    raw = candidate.read_bytes()
    _need(HASH.fullmatch(str(reference.get("sha256", ""))) and
          hashlib.sha256(raw).hexdigest() == reference["sha256"], "artifact_hash_mismatch")
    if "bytes" in reference:
        _need(len(raw) == reference["bytes"], "artifact_size_mismatch")
    return raw


def _snapshot(snapshot: dict, database: str) -> dict:
    identity = snapshot.get("observerIdentity", {})
    _need(identity.get("databaseRole") == "oid_observer" and
          identity.get("databaseName") == database and identity.get("transactionReadOnly") == "on",
          "independent_observer_identity_missing")
    tables = snapshot.get("tableFingerprints", {})
    _need(isinstance(tables, dict) and REQUIRED_TABLES <= tables.keys(), "domain_inventory_incomplete")
    for row in tables.values():
        _need(type(row.get("rowCount")) is int and row["rowCount"] >= 0 and
              HASH.fullmatch(str(row.get("sha256", ""))), "invalid_table_fingerprint")
    _need(HASH.fullmatch(str(snapshot.get("sequenceSha256", ""))), "sequence_inventory_missing")
    _need(_hash({"tableFingerprints": tables, "sequenceSha256": snapshot["sequenceSha256"]}) ==
          snapshot.get("databaseTotalsSha256"), "database_fingerprint_not_recomputed")
    financial = {k: v for k, v in tables.items() if k.startswith(("oid_ledger_", "oid_bonus_")) or
                 k in {"oid_run_reservation", "oid_run_budget_hold"}}
    benchmark = {k: v for k, v in tables.items() if k == "oid_benchmark_run" or k.startswith(("oid_run_", "oid_task_", "oid_ranked_"))}
    report_names = {"oid_support_report", "oid_support_report_audit", "oid_support_image_upload",
                    "oid_support_image_chunk", "oid_support_report_deletion_receipt", "oid_support_upload_gc_receipt",
                    "oid_support_image_input_usage", "oid_support_report_retention_state"}
    reports = {k: v for k, v in tables.items() if k in report_names}
    _need(_hash(financial) == snapshot.get("financialStateSha256") and
          _hash(benchmark) == snapshot.get("benchmarkStateSha256"), "business_fingerprints_not_recomputed")
    _need(_hash(reports) == snapshot.get("reportStateSha256") and
          isinstance(snapshot.get("operationBindings"), dict), "business_receipts_missing")
    return snapshot


def _business_unchanged(baseline: dict, before: dict, after: dict, database: str) -> None:
    for value in (baseline, before, after):
        _snapshot(value, database)
    for key in ("financialStateSha256", "benchmarkStateSha256", "reportStateSha256", "operationBindings"):
        _need(baseline[key] == before[key] == after[key], f"retry_changed_{key}")


def verify_local_combined_restore_capture(capture: dict, repository_root: Path | str) -> dict:
    root = Path(repository_root)
    errors: list[str] = []
    passed: set[str] = set()
    negatives: set[str] = set()

    def check(name: str, callback) -> None:
        try:
            callback()
            passed.add(name)
        except (ValueError, KeyError, TypeError, OSError, AttributeError, IndexError) as error:
            errors.append(f"{name}:{error}")

    try:
        _need(capture.get("schemaVersion") == "beta-combined-restore-capture/v1", "capture_schema_invalid")
        provenance = capture["provenance"]
        pins = provenance["inputHashesBefore"]
        _need(pins and pins == provenance["inputHashesAfter"], "source_changed_during_capture")
        for path, digest in pins.items():
            _file(root, {"path": path, "sha256": digest})
        result = capture["result"]
        _need(result.get("schemaVersion") == "bpc-combined-restore-runtime-observation/v1" and
              result.get("scenarioId") == "BPC-SC-022", "runtime_schema_invalid")
        source_db = result["sourceDatabase"]
        _need(source_db == provenance["databaseIsolation"]["databaseName"] and
              re.fullmatch(r"oid_acceptance_[0-9a-f]{32}", source_db), "source_database_binding_invalid")
        checkpoint = result["checkpoint"]
        before = _snapshot(checkpoint["sourceSnapshots"]["before"], source_db)
        after = _snapshot(checkpoint["sourceSnapshots"]["after"], source_db)
        restore = result["restore"]
        restore_db = restore["restoreDatabaseName"]
        _need(RESTORE_DB.fullmatch(restore_db) and restore_db != source_db, "restore_database_not_isolated")
        restored = _snapshot(restore["observations"]["beforeRetention"], restore_db)
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as error:
        return _report([], [], [f"capture:{error}"])

    def consistency():
        _need(before["tableFingerprints"] == after["tableFingerprints"] and
              before["sequenceSha256"] == after["sequenceSha256"] and
              before["databaseTotalsSha256"] == checkpoint["databaseTotalsSha256"], "checkpoint_changed")
        _need(before["snapshotBoundaryId"] == after["snapshotBoundaryId"] and
              before["snapshotBoundary"] == "admission_frozen_database_quiescent", "checkpoint_freeze_missing")
    check("consistent_checkpoint_verified", consistency)

    def totals():
        _need(before["tableFingerprints"] == restored["tableFingerprints"] and
              before["sequenceSha256"] == restored["sequenceSha256"], "restored_database_differs")
        for name in ("oid_bonus_code", "oid_bonus_grant", "oid_ledger_entry", "oid_run_task_evaluation", "oid_support_report"):
            _need(before["tableFingerprints"][name]["rowCount"] > 0, f"combined_fixture_missing_{name}")
        _need(before["originalIds"]["completedRunIds"] and before["originalIds"]["queuedInterruptedUnknownRunIds"],
              "completed_or_queued_fixture_missing")
    check("code_ledger_reports_results_equal", totals)

    def original_ids():
        _need(before["originalIds"] == after["originalIds"] == restore["originalIds"] == checkpoint["originalIds"],
              "original_ids_changed")
        _need(before["operationBindings"] == restored["operationBindings"] == checkpoint["operationBindings"],
              "original_receipts_changed")
        references = checkpoint["verifiedOfficialEvidenceFiles"]
        _need(references, "official_evidence_missing")
        for reference in references:
            _file(root, reference)
        source = json.loads(_file(root, checkpoint["sourceObserverEvidence"]["observationFile"]))
        _need(source.get("runs") and source.get("verifiedEvidenceFiles"), "raw_source_domain_observation_missing")
        _need(source["observer"]["role"] == "oid_observer" and source["observer"]["databaseName"] == source_db and
              source["observer"]["transactionReadOnly"] == "on", "raw_source_observer_identity_missing")
    check("hashes_and_original_ids_match", original_ids)

    def retry():
        replay = result["retries"]
        _business_unchanged(restore["observations"]["afterRetention"], replay["snapshots"]["before"],
                            replay["snapshots"]["after"], restore_db)
        for name in ("recoveryRun", "blockerRun", "queuedRun"):
            for kind in ("intent", "accept"):
                row = replay[name][kind]
                _need(row["status"] == 200 and row["replayed"] is True and
                      HASH.fullmatch(row["operationIdSha256"]), "original_run_retry_not_observed")
        _need(replay["queuedRun"]["accept"]["runId"] == result["queueAndPause"]["queuedRunId"] and
              replay["queuedRun"]["accept"]["runStatus"] == "queued", "queued_run_reexecuted")
        for name in ("bonusRedemption", "report"):
            _need(replay[name]["status"] == 200 and replay[name]["replayed"] is True, f"{name}_not_replayed")
        negatives.add("repeated_operation")
    check("safe_retry", retry)

    def no_resubmit():
        observed = result["sourceOperationsAfterRestore"]
        _need(observed["identity"]["role"] == "bef_observer" and observed["identity"]["databaseName"] == "bef" and
              observed["identity"]["transactionReadOnly"] == "on", "post_restore_bef_observer_missing")
        rows = {row["caseName"]: row for row in observed["result"]}
        for name, case in result["recovery"]["cases"].items():
            old = case.get("sourceOperation", case.get("beFSource", {}))["result"]
            new = rows[name]["operations"]
            _need(len(old) == len(new) == 1 and rows[name]["actionId"] == case["action"]["actionId"], "source_operation_repeated")
            for key in ("operationId", "environmentId", "generationId", "idempotencyKeySha256", "transactionHash", "receiptStatus"):
                _need(old[0][key] == new[0][key], f"source_operation_changed_{key}")
    check("no_external_resubmission", no_resubmit)

    def timing():
        value = restore["timing"]
        start, end = (datetime.fromisoformat(value[k].replace("Z", "+00:00")) for k in ("startedAt", "finishedAt"))
        _need(end >= start and abs((end - start).total_seconds() * 1000 - value["restoreElapsedMs"]) < 2,
              "restore_elapsed_not_bound")
        _need(value["localCheckpointAgeSecondsAtRestoreStart"] >= 0 and value["failureDomain"] == "same_host" and
              value["checkpointLossWindowStatus"] == "local_checkpoint_age_measured_target_rpo_unknown", "rpo_rto_scope_missing")
    check("rpo_rto_disclosed", timing)

    def screenshots():
        ui = result["restoredUi"]
        _need(ui["ui"]["reportDetailStatus"] == 200 and ui["ui"]["imageStatus"] == 200 and
              ui["ui"]["completedRunStatus"] == "completed" and ui["ui"]["queuedRunStatus"] == "queued", "restored_ui_read_missing")
        uploads = ui["observer"]["uploads"]
        originals = {(row["bytes"], row["sha256"]) for row in before["imageFiles"]}
        _need(uploads and all((row["bytes"], row["sha256"]) in originals for row in uploads) and
              any(row["sha256"] == ui["ui"]["imageSha256"] for row in uploads), "restored_image_not_original")
        _need(ui["observer"]["report"]["id"] == result["reportCases"]["reportId"] and
              ui["observer"]["report"]["actionId"] == result["reportCases"]["linkedActionId"], "restored_report_binding_changed")
    check("restored_screenshot_bytes_and_hashes_match", screenshots)

    def expiry():
        expired = result["retentionExpiry"]
        observation = expired["cloneObservation"]
        replay = expired["safeRetry"]
        receipts = replay["snapshots"]["before"]["reportDeletionReceipts"]
        _need(RESTORE_DB.fullmatch(observation["databaseName"]) and observation["databaseName"] != restore_db,
              "expired_clone_not_isolated")
        _need(observation["reportCount"] == observation["uploadCount"] == observation["imageFileCount"] == 0 and
              observation["deletionReceiptCount"] == len(receipts) > 0 and
              all(row.get("reportId") and row["status"] == "complete" for row in receipts),
              "expired_content_not_purged")
        cleanup = expired["cleanup"]
        _need(_hash(receipts) == cleanup["cleanupReceiptSha256"], "purge_receipt_missing")
        for group in ("financial", "benchmark"):
            _need(cleanup[f"{group}StateBeforeSha256"] == cleanup[f"{group}StateAfterSha256"] ==
                  before[f"{group}StateSha256"] == observation[f"{group}StateSha256"], "purge_changed_ledger_or_grades")
        access = expired["accessDenial"]
        _need(access["ui"]["listStatus"] == access["reportDetail"]["status"] == access["image"]["status"] == 410,
              "expired_access_not_denied")
        _need(expired["boundary"] == "synthetic_31_day_closure_in_second_restored_clone_only" and
              expired["actualThirtyDayPassage"] == "not_claimed", "synthetic_retention_scope_missing")
        _business_unchanged(replay["snapshots"]["before"], replay["snapshots"]["before"],
                            replay["snapshots"]["after"], observation["databaseName"])
        negatives.add("restore_past_report_retention")
    check("expired_reports_checked_against_deletion_receipts", expiry)
    return _report(passed, negatives, errors)


def _report(observations, negatives, errors) -> dict:
    return {"scenarioId": "BPC-SC-022", "localStatus": "verified" if not errors and set(observations) == set(OBSERVATIONS) else "blocked",
            "observations": sorted(observations), "negativeVariants": sorted(negatives),
            "missingObservations": sorted(set(OBSERVATIONS) - set(observations)),
            "missingNegativeVariants": sorted(set(NEGATIVES) - set(negatives)), "errors": list(errors),
            "fullScenarioAcceptance": False, "targetGateStatus": "blocked"}
