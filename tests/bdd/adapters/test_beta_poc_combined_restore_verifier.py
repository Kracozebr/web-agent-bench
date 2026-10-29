"""Adversarial replay checks for SC022/026; these fixtures are not runtime proof."""
from copy import deepcopy
import hashlib
import json

import pytest

from .beta_poc_combined_restore_verifier import (
    REQUIRED_TABLES, _business_unchanged, _file, _hash, _snapshot,
    verify_local_combined_restore_capture,
)

DATABASE = "oid_restore_" + "a" * 32


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
