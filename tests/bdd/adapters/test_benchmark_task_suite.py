from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from tests.bdd.adapters import benchmark_task_suite as adapter
from tests.bdd.adapters import benchmark_run_lifecycle as brl_adapter


def _hash_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def test_pinned_raw_artifact_requires_contained_path_and_matching_hash(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    payload = {"schemaVersion": "raw/v1", "value": 1}
    path = root / "evidence" / "raw.json"
    path.parent.mkdir()
    content = json.dumps(payload).encode()
    path.write_bytes(content)

    assert adapter._read_pinned_repo_json(root, "evidence/raw.json", hashlib.sha256(content).hexdigest()) == payload
    with pytest.raises(AssertionError, match="path is unsafe"):
        adapter._read_pinned_repo_json(root, "../outside.json", "a" * 64)
    with pytest.raises(AssertionError, match="hash mismatch"):
        adapter._read_pinned_repo_json(root, "evidence/raw.json", "0" * 64)


def test_secret_scanner_allows_only_exact_redacted_http_authorization_marker() -> None:
    adapter._assert_secret_free({"request": {"headers": {"Authorization": "[REDACTED]"}}})
    adapter._assert_secret_free({"request": {"headers": {"authorization": "<ReDaCtEd>"}}})
    with pytest.raises(AssertionError, match="credential-bearing evidence field"):
        adapter._assert_secret_free({"request": {"headers": {"authorization": "Bearer local-token"}}})
    with pytest.raises(AssertionError, match="credential-bearing evidence field"):
        adapter._assert_secret_free({"request": {"body": {"authorization": "[REDACTED]"}}})


def test_release_candidate_pass_label_cannot_substitute_for_raw_proof() -> None:
    facts = adapter._derive_release_facts("BTS-SC-001", {"status": "verified", "facts": {"all": True}}, adapter.REPOSITORY_ROOT)

    assert facts
    assert not any(facts.values())
    assert "BTS-SC-009" not in adapter.PASSABLE_SCENARIOS


def test_variant_candidate_hash_and_mutation_are_independently_recomputed() -> None:
    base = {
        "benchmarkVersion": "fixture-version",
        "policyHash": "a" * 64,
        "executionIdentityHash": "b" * 64,
        "executionIdentity": {},
        "cases": {"training": [], "ranked": [
            {"taskId": "M1", "caseId": "m1", "caseHash": "0" * 64},
            {"taskId": "U1", "caseId": "u1", "caseHash": "0" * 64},
        ]},
    }
    candidate, expected_path = adapter._expected_release_candidate(base, "placeholder") or ({}, "")
    state_hash = "c" * 64
    variant = {
        "id": "placeholder",
        "status": "verified",
        "candidateHash": candidate.get("manifestHash"),
        "candidateManifest": candidate,
        "mutationPath": expected_path,
        "observedBlockers": [{"code": "placeholder_or_latest_value", "subject": "ranked/M1/m1-placeholder"}],
        "databaseStateSha256Before": state_hash,
        "databaseStateSha256After": state_hash,
        "databaseUnchanged": True,
        "activationErrorCode": None,
    }

    assert adapter._variant_matches(None, variant, base, {state_hash: {}})
    forged = {**variant, "candidateManifest": {**candidate, "manifestHash": "f" * 64}}
    assert not adapter._variant_matches(None, forged, base, {state_hash: {}})


def test_retained_release_fixture_recomputes_bounded_u1_allocation_negative() -> None:
    fixture_path = os.environ.get("BTS_RELEASE_PROBE_FIXTURE")
    if not fixture_path:
        pytest.skip("BTS_RELEASE_PROBE_FIXTURE is required for retained-release regression")
    capture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    manifest = capture.get("release", {}).get("manifest")
    assert isinstance(manifest, dict)
    all_cases = manifest["cases"]["training"] + manifest["cases"]["ranked"]
    expected_case_summary = [{
        "mode": row["mode"], "taskId": row["taskId"], "caseId": row["caseId"],
        "caseHash": row["caseHash"], "rubricHash": row["rubricHash"], "taskWeight": row["taskWeight"],
        "referenceActionCount": row["referencePath"]["actionCount"],
        "referenceEvidence": {"path": row["referencePath"]["evidence"]["path"],
                              "sha256": row["referencePath"]["evidence"]["sha256"]},
    } for row in all_cases]
    assert capture["release"].get("caseHashes") == expected_case_summary
    variants = capture.get("variants")
    assert isinstance(variants, list)
    historical_variant_ids = {row.get("id") for row in variants if isinstance(row, dict)}
    missing_current_controls = {
        "training_set_mismatch", "training_weight_or_sum_mismatch",
        "ranked_or_training_case_count_mismatch", "release_identity_reuse",
    }
    assert historical_variant_ids == set(adapter.RELEASE_VARIANT_REQUIREMENTS) - missing_current_controls
    snapshots_raw = capture.get("database", {}).get("snapshots")
    assert isinstance(snapshots_raw, list)
    snapshots = {row["stateSha256"]: row for row in snapshots_raw if adapter._verify_release_database_snapshot(row)}
    for variant in variants:
        if variant.get("id") == "initially_satisfied_u1_allocation":
            assert not adapter._variant_matches(None, variant, manifest, snapshots)
        else:
            assert adapter._variant_matches(None, variant, manifest, snapshots), variant.get("id")

    expected = adapter._expected_release_candidate(manifest, "initially_satisfied_u1_allocation")
    assert expected is not None
    candidate, mutation_path = expected
    assert mutation_path == "cases.ranked.U1.initialState.balances"
    u1 = next(row for row in candidate["cases"]["ranked"] if row["taskId"] == "U1")
    participant_balances = [row for row in u1["initialState"]["balances"] if row["account"] == "participant"]
    assert participant_balances
    assert all(adapter._valid_units(row["amountUnits"]) for row in participant_balances)
    assert adapter._u1_allocation_satisfied(u1)

    malformed_source = json.loads(json.dumps(manifest))
    malformed_u1 = next(row for row in malformed_source["cases"]["ranked"] if row["taskId"] == "U1")
    malformed_u1["initialState"]["balances"].append(
        {"account": "participant", "assetId": "unrelated-invalid-balance", "amountUnits": "9" * 79}
    )
    assert adapter._expected_release_candidate(malformed_source, "initially_satisfied_u1_allocation") is None


def test_current_release_controls_require_independent_mutation_and_store_rejection_proof() -> None:
    fixture_path = os.environ.get("BTS_RELEASE_CURRENT_FIXTURE")
    if not fixture_path:
        pytest.skip("BTS_RELEASE_CURRENT_FIXTURE is required for current-catalog replay regression")
    capture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    source = capture["release"]["manifest"]
    before_hash = "c" * 64
    snapshot = {"tables": {"oid_task_release": {"rows": [{
        "release_identity": source["releaseIdentity"], "manifest_hash": source["manifestHash"],
        "sealed_manifest": source,
    }]}}}
    snapshots = {before_hash: snapshot}
    controls = ("training_set_mismatch", "training_weight_or_sum_mismatch",
                "ranked_or_training_case_count_mismatch", "release_identity_reuse")
    for variant_id in controls:
        expected = adapter._expected_release_candidate(source, variant_id)
        assert expected is not None, variant_id
        candidate, path = expected
        blockers = [{"code": code, "subject": subject}
                    for code, subject in adapter.RELEASE_VARIANT_REQUIREMENTS[variant_id][1]]
        variant = {
            "id": variant_id, "status": "verified", "candidateHash": candidate["manifestHash"],
            "candidateManifest": candidate, "mutationPath": path, "observedBlockers": blockers,
            "databaseStateSha256Before": before_hash, "databaseStateSha256After": before_hash,
            "databaseUnchanged": True, "activationErrorCode": None,
        }
        if variant_id == "release_identity_reuse":
            variant["activationErrorCode"] = "release_identity_immutable_conflict"
            variant["preActivationValidation"] = {
                "status": "validated", "manifestHash": candidate["manifestHash"],
                "validationEvidence": [
                    {"kind": "feasibility", "sha256": candidate["feasibilityEvidence"]["sha256"]},
                    *({"kind": "reference_path", "sha256": row["referencePath"]["evidence"]["sha256"]}
                      for row in candidate["cases"]["training"] + candidate["cases"]["ranked"]),
                    {"kind": "difficulty_review", "sha256": candidate["difficultyReviewEvidence"]["sha256"]},
                ],
            }
            assert not adapter._variant_matches(None, {**variant, "preActivationValidation": None}, source, snapshots)
            assert not adapter._variant_matches(None, {**variant, "activationErrorCode": "generic_error"}, source, snapshots)
            assert not adapter._variant_matches(None, variant, source, {before_hash: {}})
        assert adapter._variant_matches(None, variant, source, snapshots), variant_id
        assert not adapter._variant_matches(None, {**variant, "candidateManifest": source}, source, snapshots)
        assert not adapter._variant_matches(None, {**variant, "databaseStateSha256After": "d" * 64}, source, snapshots)
        if blockers:
            assert not adapter._variant_matches(None, {**variant, "observedBlockers": []}, source, snapshots)


def test_ranked_capture_summary_without_snapshots_does_not_derive_pass() -> None:
    facts = adapter._derive_ranked_facts({"status": "verified", "checks": [{"status": "verified"}]}, adapter.REPOSITORY_ROOT)

    assert facts
    assert not any(facts.values())


def test_passing_release_requires_current_source_inventory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source_root = tmp_path / "repo"
    source_root.mkdir()
    source = source_root / "src" / "release.ts"
    source.parent.mkdir()
    source.write_text("release-source", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    provenance = {
        "sourceStableDuringRun": True,
        "inputHashesBefore": {"src/release.ts": digest},
        "inputHashesAfter": {"src/release.ts": digest},
    }
    monkeypatch.setattr(brl_adapter, "REPOSITORY_ROOT", source_root)

    brl_adapter._verify_source_inventory(provenance, "BTS-SC-001")
    source.write_text("changed-source", encoding="utf-8")
    with pytest.raises(AssertionError, match="captured source no longer matches"):
        brl_adapter._verify_source_inventory(provenance, "BTS-SC-001")

def test_reader_replay_preserves_historical_inventory_and_rejects_changed_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "repo"
    paths = ["tests/bdd/adapters/benchmark_task_suite.py", "packages/owner-identity/src/service.ts",
             "openspec/changes/benchmark-task-suite/specs/suite/spec.md"]
    hashes = {}
    for relative in paths:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original", encoding="utf-8")
        hashes[relative] = hashlib.sha256(target.read_bytes()).hexdigest()
    provenance = {"sourceStableDuringRun": True, "inputHashesBefore": dict(hashes), "inputHashesAfter": dict(hashes)}
    monkeypatch.setattr(brl_adapter, "REPOSITORY_ROOT", root)
    (root / paths[0]).write_text("fixed-independent-reader", encoding="utf-8")
    brl_adapter._verify_source_inventory(provenance, "BTS-SC-002")
    for relative in paths[1:]:
        (root / relative).write_text("changed", encoding="utf-8")
        with pytest.raises(AssertionError, match="captured source no longer matches"):
            brl_adapter._verify_source_inventory(provenance, "BTS-SC-002")
        (root / relative).write_text("original", encoding="utf-8")
    provenance["inputHashesAfter"][paths[0]] = "f" * 64
    with pytest.raises(AssertionError, match="identical before/after"):
        brl_adapter._verify_source_inventory(provenance, "BTS-SC-002")
