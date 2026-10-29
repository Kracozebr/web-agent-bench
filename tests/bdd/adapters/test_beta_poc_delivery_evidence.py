from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from tests.bdd.adapters import ScenarioContext, build_registry
from tests.bdd.adapters.beta_poc_delivery import (
    CONTRACT_PATH,
    PROPOSAL_PATH,
    REPOSITORY_ROOT,
    SCENARIO_IDS,
    BetaPocEvidenceCase,
    _assert_secret_free,
    _derive_raw_boundary_facts,
    _load_contract_sources,
    load_capture,
)


def _write_capture(
    evidence_root: Path,
    scenario_id: str,
    *,
    status: str = "blocked",
    mutate_observation: str | None = None,
) -> Path:
    proposal, contract, contract_bytes = _load_contract_sources()
    row = contract["protected_scenarios"][scenario_id]
    run_id = "cb5e2f43-182c-4f7c-9864-a91e1dc64649"
    scenario_root = evidence_root / scenario_id
    run_root = scenario_root / "runs" / run_id
    run_root.mkdir(parents=True)
    (scenario_root / "manifest.json").write_text(json.dumps({
        "schemaVersion": "beta-poc-delivery-evidence-index/v1",
        "scenarioId": scenario_id,
        "status": status,
        "latestRunId": run_id,
        "runs": [run_id],
    }), encoding="utf-8")

    capture = {
        "scenarioId": scenario_id,
        "localBoundary": "local_synthetic_google_and_postgres",
        "localObservations": {name: True for name in row["required_observations"]},
    }
    provenance = {
        "contractSha256": hashlib.sha256(contract_bytes).hexdigest(),
        "sourceStableDuringRun": True,
        "inputHashesBefore": {"AGENTS.md": hashlib.sha256((REPOSITORY_ROOT / "AGENTS.md").read_bytes()).hexdigest()},
        "inputHashesAfter": {"AGENTS.md": hashlib.sha256((REPOSITORY_ROOT / "AGENTS.md").read_bytes()).hexdigest()},
    }
    (run_root / "runtime-evidence.json").write_text(json.dumps(capture), encoding="utf-8")
    (run_root / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
    artifacts = []
    for name in ("runtime-evidence.json", "provenance.json"):
        content = (run_root / name).read_bytes()
        artifacts.append({
            "path": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "contentType": "application/json",
            "boundary": row["boundary_detail"],
        })
    record_status = "verified" if status == "passed" else "not_run"
    observations = {name: {"status": record_status, "value": True} if status == "passed" else
                    {"status": record_status, "reasonCode": "target_boundary_missing"}
                    for name in row["required_observations"]}
    negatives = {name: {"status": record_status, "value": True} if status == "passed" else
                 {"status": record_status, "reasonCode": "target_boundary_missing"}
                 for name in row["negative_variants"]}
    if mutate_observation:
        observations[mutate_observation] = {"status": "verified", "value": True}
    (run_root / "manifest.json").write_text(json.dumps({
        "schemaVersion": "beta-poc-delivery-acceptance/v1",
        "specProfile": "active-delta",
        "scenarioId": scenario_id,
        "runId": run_id,
        "status": status,
        "blockedReasonCode": "external_beta_boundary_unavailable" if status == "blocked" else None,
        "boundaryDetail": row["boundary_detail"],
        "artifacts": artifacts,
        "observations": observations,
        "negativeVariants": negatives,
    }), encoding="utf-8")
    return run_root


def test_missing_capture_is_absent_evidence(tmp_path: Path) -> None:
    assert load_capture("BPC-SC-013", evidence_root=tmp_path) is None


def test_blocked_capture_cannot_promote_local_fixture_observations(tmp_path: Path) -> None:
    _write_capture(tmp_path, "BPC-SC-013")
    loaded = load_capture("BPC-SC-013", evidence_root=tmp_path)
    assert loaded is not None
    manifest, artifacts = loaded
    assert manifest["status"] == "blocked"
    assert artifacts["runtime-evidence.json"]["localObservations"]


def test_blocked_capture_rejects_any_promoted_observation(tmp_path: Path) -> None:
    _write_capture(tmp_path, "BPC-SC-013", mutate_observation="actual_readiness_verified")
    with pytest.raises(AssertionError, match="cannot promote unverified partial claims"):
        load_capture("BPC-SC-013", evidence_root=tmp_path)


def test_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    run_root = _write_capture(tmp_path, "BPC-SC-013")
    (run_root / "runtime-evidence.json").write_text('{"changed":true}', encoding="utf-8")
    with pytest.raises(AssertionError, match="artifact hash mismatch"):
        load_capture("BPC-SC-013", evidence_root=tmp_path)


def test_artifact_boundary_must_match_the_approved_contract(tmp_path: Path) -> None:
    run_root = _write_capture(tmp_path, "BPC-SC-013")
    manifest_path = run_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["boundary"] = "local_synthetic_runtime"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(AssertionError, match="artifact metadata is invalid"):
        load_capture("BPC-SC-013", evidence_root=tmp_path)


def test_raw_replay_dispatch_requires_exact_nonlocal_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.bdd.adapters import beta_poc_report_verifier

    row = _load_contract_sources()[1]["protected_scenarios"]["BPC-SC-018"]
    facts = {name: True for name in (*row["required_observations"], *row["negative_variants"])}
    evidence = {"boundaryDetail": row["boundary_detail"], "browser": {"actions": []}}
    monkeypatch.setattr(beta_poc_report_verifier, "derive_observations", lambda _scenario, _evidence: facts)
    assert _derive_raw_boundary_facts("BPC-SC-018", {"runtime-evidence.json": evidence}) == facts

    evidence["localBoundary"] = "local_synthetic_google_and_postgres"
    assert _derive_raw_boundary_facts("BPC-SC-018", {"runtime-evidence.json": evidence}) is None


def test_secret_scanner_rejects_plaintext_bonus_codes_and_secret_fields() -> None:
    for suffix in ("A", "-", "_"):
        with pytest.raises(AssertionError, match="credential-like evidence text"):
            _assert_secret_free({"supportNote": f"issued code BPC-{'A' * 42}{suffix}"})
    for field in ("codeVerifierSecret", "verifierSecret", "dbUrl", "plaintextCode"):
        with pytest.raises(AssertionError, match="credential-bearing evidence field"):
            _assert_secret_free({field: "must-not-be-recorded"})


def test_passed_capture_needs_a_scenario_specific_replay_verifier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.bdd.adapters import beta_poc_delivery

    monkeypatch.setattr(beta_poc_delivery, "EVIDENCE_ROOT", tmp_path)
    _write_capture(tmp_path, "BPC-SC-013", status="passed")
    proposal, contract, _ = _load_contract_sources()
    case = BetaPocEvidenceCase("BPC-SC-013", proposal["protected_scenarios"]["BPC-SC-013"],
                               contract["protected_scenarios"]["BPC-SC-013"])
    context = ScenarioContext(scenario_id="BPC-SC-013")
    case.setup(context)
    with pytest.raises(AssertionError, match="no scenario-specific raw-boundary replay verifier"):
        case.execute(context, "")


def test_registry_covers_only_the_approved_bpc_inventory() -> None:
    registry = build_registry("beta-poc-delivery")
    assert registry.inventory() == frozenset(SCENARIO_IDS)
    assert set(registry.adapter_profiles().values()) == {
        row["adapter"] for row in _load_contract_sources()[0]["protected_scenarios"].values()
    }
