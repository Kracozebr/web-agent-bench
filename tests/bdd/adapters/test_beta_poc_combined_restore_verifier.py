"""Adversarial replay checks for SC022/026; these fixtures are not runtime proof."""
from copy import deepcopy
import hashlib
import json

import pytest

from .beta_poc_combined_restore_verifier import (
    REQUIRED_TABLES, _business_unchanged, _file, _hash, _snapshot, _original_source_operation_unchanged,
    _official_evidence_projection, _restore_boundary, _retry_receipts,
    verify_local_combined_restore_capture,
)

DATABASE = "oid_restore_" + "a" * 32


def test_restore_requires_the_actual_hex_host_job_and_original_dump_receipts():
    checkpoint_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    common = {"schemaVersion": "beta-backup-host-result/v1", "status": "complete",
              "databaseName": DATABASE, "checkpointId": checkpoint_id, "creationJobId": "b" * 32}
    restore = {"status": "verified_unserved", "writesMayBeEnabled": False, "targetHostAcceptance": "not_run",
               "checkpointId": checkpoint_id, "restoreDatabaseName": DATABASE,
               "checkpoint": {"databaseDumpSha256": "d" * 64},
               "creationReceipt": {**common, "jobId": "b" * 32, "kind": "create_restore_database", "createdFresh": True},
               "restoreReceipt": {**common, "status": "restored", "jobId": "c" * 32, "kind": "pg_restore", "restored": True,
                                  "dumpSha256": "d" * 64}}
    _restore_boundary(restore, checkpoint_id)
    for section, key, value in (("creationReceipt", "createdFresh", False),
                                ("restoreReceipt", "creationJobId", "e" * 32),
                                ("restoreReceipt", "dumpSha256", "e" * 64),
                                ("restoreReceipt", "databaseName", "oid_restore_" + "e" * 32)):
        changed = deepcopy(restore)
        changed[section][key] = value
        with pytest.raises(ValueError, match="restore_"):
            _restore_boundary(changed, checkpoint_id)
    restore["writesMayBeEnabled"] = True
    with pytest.raises(ValueError, match="restore_not_verified_unserved"):
        _restore_boundary(restore, checkpoint_id)


def test_successful_replayed_http_responses_cannot_substitute_original_receipt_ids():
    bindings, replay = {}, {}
    for name in ("recoveryRun", "blockerRun", "queuedRun"):
        bindings[name] = {"intentId": name + "-intent", "runId": name + "-run",
                          "intentOperationIdSha256": "a" * 64, "acceptOperationIdSha256": "b" * 64}
        replay[name] = {"intent": {"status": 200, "replayed": True, "intentId": bindings[name]["intentId"],
                                    "operationIdSha256": "a" * 64},
                        "accept": {"status": 200, "replayed": True, "runId": bindings[name]["runId"],
                                   "operationIdSha256": "b" * 64,
                                   "runStatus": "queued" if name == "queuedRun" else "completed"}}
    bindings["bonusRedemption"] = {"redemptionId": "redemption", "grantId": "grant", "codeId": "code",
                                    "operationIdSha256": "c" * 64}
    bindings["report"] = {"reportId": "report", "operationIdSha256": "d" * 64}
    for name in ("bonusRedemption", "report"):
        replay[name] = {**bindings[name], "status": 200, "replayed": True}
    replay["originalReceiptBindings"] = bindings
    _retry_receipts(replay)
    for name, kind, key in (("recoveryRun", "accept", "runId"), ("blockerRun", "intent", "intentId"),
                             ("queuedRun", "accept", "operationIdSha256")):
        changed = deepcopy(replay)
        changed[name][kind][key] = "e" * 64
        with pytest.raises(ValueError, match="original_run_retry_not_bound"):
            _retry_receipts(changed)
    for name, key in (("bonusRedemption", "grantId"), ("report", "reportId")):
        changed = deepcopy(replay)
        changed[name][key] = "substituted"
        with pytest.raises(ValueError, match="retry_not_bound"):
            _retry_receipts(changed)
    replay["report"].update(status="not_submitted_after_expiry", replayed=False)
    _retry_receipts(replay, expired=True)


def test_restore_cannot_substitute_original_source_request_or_unfence_generation():
    original = {"operationId": "original", "environmentId": "env-a", "generationId": "generation",
                "participantIdSha256": "a" * 64, "idempotencyKeySha256": "b" * 64,
                "requestSha256": "c" * 64, "operationKind": "transfer", "status": "settled",
                "transactionHash": "0x" + "d" * 64, "receiptStatus": "success",
                "responseSha256": None, "generationStatus": "fenced"}
    _original_source_operation_unchanged(original, deepcopy(original))
    for key in original:
        changed = {**original, key: "substituted"}
        with pytest.raises(ValueError, match="source_operation_changed"):
            _original_source_operation_unchanged(original, changed)
        missing = deepcopy(original)
        del missing[key]
        with pytest.raises(ValueError, match="source_operation_changed"):
            _original_source_operation_unchanged(original, missing)


def snapshot():
    tables = {name: {"rowCount": 1, "sha256": "b" * 64} for name in REQUIRED_TABLES}
    tables["oid_rate_limit"] = {"rowCount": 0, "sha256": "c" * 64}
    reports = {k: v for k, v in tables.items() if k.startswith("oid_support_")}
    return {"observerIdentity": {"databaseRole": "oid_observer", "databaseName": DATABASE,
                                "transactionReadOnly": "on"},
            "tableFingerprints": tables, "sequenceSha256": "d" * 64,
            "databaseTotalsSha256": _hash({"tableFingerprints": tables, "sequenceSha256": "d" * 64}),
            "financialStateSha256": _hash({k: v for k, v in tables.items() if k.startswith(("oid_bonus_", "oid_ledger_"))}),
            "benchmarkStateSha256": _hash({k: v for k, v in tables.items() if k == "oid_benchmark_run" or
                                           k.startswith(("oid_run_", "oid_task_", "oid_ranked_"))}),
            "reportStateSha256": _hash(reports), "operationBindings": {"fixture": "e" * 64}}


def test_claimed_success_without_raw_source_and_restore_observations_is_blocked(tmp_path):
    result = verify_local_combined_restore_capture({"status": "verified", "claims": {
        "sourceWritesResubmitted": False, "bonusGrantOrLedgerChanged": False}}, tmp_path)
    assert result["localStatus"] == "blocked"
    assert result["observations"] == []
    assert result["targetGateStatus"] == "blocked"


def test_database_total_is_recomputed_and_cannot_hide_changed_grade_or_report():
    before = snapshot()
    _snapshot(before, DATABASE)
    for table in ("oid_run_task_evaluation", "oid_support_report", "oid_benchmark_run"):
        changed = deepcopy(before)
        changed["tableFingerprints"][table]["sha256"] = "f" * 64
        with pytest.raises(ValueError, match="fingerprint"):
            _snapshot(changed, DATABASE)


def test_recomputed_total_cannot_hide_changed_report_behind_stale_business_hash():
    value = snapshot()
    value["tableFingerprints"]["oid_support_report"]["sha256"] = "f" * 64
    value["databaseTotalsSha256"] = _hash({"tableFingerprints": value["tableFingerprints"],
                                           "sequenceSha256": value["sequenceSha256"]})
    with pytest.raises(ValueError, match="business_receipts_missing"):
        _snapshot(value, DATABASE)


def test_auth_rate_counter_changes_do_not_mask_or_invalidate_original_business_receipts():
    before = snapshot()
    after = deepcopy(before)
    after["tableFingerprints"]["oid_rate_limit"] = {"rowCount": 4, "sha256": "f" * 64}
    after["databaseTotalsSha256"] = _hash({"tableFingerprints": after["tableFingerprints"],
                                           "sequenceSha256": after["sequenceSha256"]})
    _business_unchanged(before, before, after, DATABASE)
    after["operationBindings"] = {"fixture": "f" * 64}
    with pytest.raises(ValueError, match="operationBindings"):
        _business_unchanged(before, before, after, DATABASE)


def test_observer_cannot_substitute_owner_role_or_another_database():
    for key, value in (("databaseRole", "oid_owner"), ("databaseName", "owner_identity"),
                       ("transactionReadOnly", "off")):
        current = snapshot()
        current["observerIdentity"][key] = value
        with pytest.raises(ValueError, match="observer_identity"):
            _snapshot(current, DATABASE)


def test_required_artifact_bytes_and_containment_are_verified_before_replay(tmp_path):
    path = tmp_path / "receipt.json"
    raw = json.dumps({"runId": "fixture", "operationId": "original"}).encode()
    path.write_bytes(raw)
    reference = {"path": "receipt.json", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    assert _file(tmp_path, reference) == raw
    path.write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="artifact_hash_mismatch"):
        _file(tmp_path, reference)
    with pytest.raises(ValueError, match="unsafe_artifact_reference"):
        _file(tmp_path, {"path": "../receipt.json", "sha256": reference["sha256"]})


def _official_restore_fixture(tmp_path, database=DATABASE):
    checkpoint_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    relative_path = "artifacts/runs/beta-platform-recovery/example.json"
    source_file = {"path": relative_path, "role": "runtime_evidence", "bytes": 17, "sha256": "a" * 64}
    clone_file = {"path": "official-evidence/" + relative_path, "relativePath": relative_path,
                  "role": "runtime_evidence", "bytes": 17, "sha256": "a" * 64}
    checkpoint = {"checkpointId": checkpoint_id, "officialEvidenceManifestSha256": "b" * 64,
                  "sourceSnapshots": {"afterRestore": {"sourceBuildSha256": "c" * 64}}}
    restore = {"checkpointId": checkpoint_id, "restoreDatabaseName": database,
               "officialEvidenceRoot": "/local-report-captures/beta-restores/" + database + "/official-evidence",
               "officialEvidenceManifestPath": "operator/official-evidence-manifest.json",
               "verifiedOfficialEvidenceFiles": [clone_file],
               "officialEvidenceRestoreReceipt": {"path": "operator/official-evidence-restore.json",
                                                  "sha256": "d" * 64, "bytes": 128},
               "checkpoint": {"officialEvidenceManifestSha256": "b" * 64, "sourceBuildSha256": "c" * 64}}
    return restore, [source_file], checkpoint, database


def test_both_restore_clones_must_bind_exact_checkpoint_official_evidence_inventory(tmp_path):
    restore, source_files, checkpoint, database = _official_restore_fixture(tmp_path)
    _official_evidence_projection(restore, source_files, checkpoint, database, "normal")
    expired_database = "oid_restore_" + "e" * 32
    expired, _, _, _ = _official_restore_fixture(tmp_path, expired_database)
    _official_evidence_projection(expired, source_files, checkpoint, expired_database, "expired")


@pytest.mark.parametrize("mutation,code", [
    ("missing_inventory", "inventory_differs_from_checkpoint"),
    ("corrupt_file_hash", "inventory_differs_from_checkpoint"),
    ("extra_file", "inventory_differs_from_checkpoint"),
    ("foreign_root", "official_root_foreign"),
    ("missing_receipt", "operator_receipt_reference_invalid"),
    ("receipt_path_escape", "operator_receipt_reference_invalid"),
    ("receipt_hash_invalid", "operator_receipt_reference_invalid"),
    ("manifest_path", "operator_receipt_reference_invalid"),
    ("manifest_hash", "manifest_hash_mismatch"),
    ("source_build", "source_build_mismatch"),
    ("checkpoint_id", "checkpoint_or_database_mismatch"),
    ("database_name", "checkpoint_or_database_mismatch"),
])
def test_official_evidence_restore_rejects_missing_corrupt_foreign_or_unbound_claims(tmp_path, mutation, code):
    restore, source_files, checkpoint, database = _official_restore_fixture(tmp_path)
    if mutation == "missing_inventory":
        restore["verifiedOfficialEvidenceFiles"] = []
    elif mutation == "corrupt_file_hash":
        restore["verifiedOfficialEvidenceFiles"][0]["sha256"] = "f" * 64
    elif mutation == "extra_file":
        extra = deepcopy(restore["verifiedOfficialEvidenceFiles"][0])
        extra["relativePath"] = "artifacts/runs/foreign.json"
        extra["path"] = "official-evidence/" + extra["relativePath"]
        restore["verifiedOfficialEvidenceFiles"].append(extra)
    elif mutation == "foreign_root":
        restore["officialEvidenceRoot"] = "/local-report-captures/beta-restores/" + ("oid_restore_" + "f" * 32) + "/official-evidence"
    elif mutation == "missing_receipt":
        restore["officialEvidenceRestoreReceipt"] = None
    elif mutation == "receipt_path_escape":
        restore["officialEvidenceRestoreReceipt"]["path"] = "../foreign/receipt.json"
    elif mutation == "receipt_hash_invalid":
        restore["officialEvidenceRestoreReceipt"]["sha256"] = "invalid"
    elif mutation == "manifest_path":
        restore["officialEvidenceManifestPath"] = "../manifest.json"
    elif mutation == "manifest_hash":
        checkpoint["officialEvidenceManifestSha256"] = "f" * 64
    elif mutation == "source_build":
        restore["checkpoint"]["sourceBuildSha256"] = "f" * 64
    elif mutation == "checkpoint_id":
        restore["checkpointId"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    elif mutation == "database_name":
        restore["restoreDatabaseName"] = "oid_restore_" + "f" * 32
    with pytest.raises(ValueError, match=code):
        _official_evidence_projection(restore, source_files, checkpoint, database, "negative")
