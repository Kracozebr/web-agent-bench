from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools import bef_resource_sampler as sampler
from tools import run_bef_sc011_trials as trial_runner

from tests.bdd.adapters import bef_generation_cleanup as cleanup
from tests.bdd.adapters.bef_generation_cleanup import CleanupRefused, CleanupTarget


class Evidence:
    def __init__(self, scenario_id: str) -> None:
        self.scenario_id = scenario_id
        self.status = "captured"
        self.manifest = {"local": {"environments": [{"id": "bef-env-a"}, {"id": "bef-env-b"}]}}
        self.manifest_sha256 = "a" * 64
        self.index = {"applicationSourceSha256": "b" * 64, "probeSourceSha256": "c" * 64}
        self.artifacts: list[Any] = []


@pytest.fixture
def workspace_tmp_path() -> Any:
    sampler.ARTIFACTS_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bef-cleanup-test-", dir=sampler.ARTIFACTS_ROOT) as directory:
        yield Path(directory)


def _checkpoint(phase: str, env_id: str, generation_id: str, payer: str) -> dict[str, Any]:
    return {
        "generationId": generation_id,
        "service": {"environmentId": env_id, "generationId": generation_id, "phase": phase},
        "chain": {
            "environmentId": env_id,
            "generationId": generation_id,
            "phase": phase,
            "addresses": {"payer": payer},
        },
    }


def _configure_proof(
    monkeypatch: pytest.MonkeyPatch,
    evidence: Evidence,
    checkpoints: dict[tuple[str, str], dict[str, Any]],
    *,
    wrong_generation: tuple[str, str] | None = None,
    payment_rows_override: list[dict[str, Any]] | None = None,
) -> None:
    expected = {
        "BEF-SC-009": {
            "independent_chain_state", "independent_service_state",
            "reset_not_crossing_boundary", "foreign_access_denied",
        },
        "BEF-SC-010": {
            "stale_generation_fenced", "chain_baseline", "service_baseline",
            "fixture_hash", "equivalent_probe_outcome",
        },
    }[evidence.scenario_id]
    monkeypatch.setattr(cleanup.sc009010, "evaluate_sc009010", lambda *_: dict.fromkeys(expected, True))
    monkeypatch.setattr(cleanup.sc009010, "_checkpoint_map", lambda *_: checkpoints)
    monkeypatch.setattr(cleanup.sc009010, "_expected_chain_reads", lambda _e, _s: {"ok": True})

    def service_tables(_evidence: Any, snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        env_id, generation_id = snapshot["environmentId"], snapshot["generationId"]
        if wrong_generation == (snapshot["phase"], env_id):
            generation_id = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        active_work = (
            evidence.scenario_id == "BEF-SC-009" and snapshot["phase"] == "after_reset" and env_id == "bef-env-b"
            or evidence.scenario_id == "BEF-SC-010" and snapshot["phase"] == "fresh_trial" and env_id == "bef-env-a"
        )
        operations = ([{
            "operation_id": "purchase-op",
            "env_id": env_id, "generation_id": generation_id,
            "operation_kind": "purchase",
            "status": "delivered", "receipt_status": "success",
            "transaction_hash": "0x" + "1" * 64,
        }] if active_work else [])
        payments = ([{
            "operation_id": "purchase-op",
            "env_id": env_id,
            "generation_id": generation_id,
            "receipt_status": "success",
            "transaction_hash": "0x" + "1" * 64,
        }] if active_work else [])
        if active_work and payment_rows_override is not None:
            payments = payment_rows_override
        return {
            "generation-by-id": [{
                "env_id": env_id,
                "generation_id": generation_id,
                "status": "active",
                "participant_id": f"participant-{env_id}",
                "payer_address": "0x0000000000000000000000000000000000000021" if env_id.endswith("a") else "0x0000000000000000000000000000000000000031",
            }],
            "operations-by-generation": operations,
            "payments-by-operation": payments,
            "deliveries-by-operation": [],
            "denials-by-generation": [],
            "x402-observations-by-operation": [],
            "selected-execution-by-generation": [],
            "selected-execution-events-by-generation": [],
        }

    monkeypatch.setattr(cleanup.sc009010, "_service_tables", service_tables)
    monkeypatch.setattr(cleanup.sc009010, "_has_successful_execution", lambda _tables: True)
    monkeypatch.setattr(cleanup.sc009010, "_successful_purchase_rows", lambda *_: True)
    monkeypatch.setattr(cleanup.sc009010, "_successful_selected_actions", lambda *_: True)


def test_sc009_cleanup_selects_only_verified_final_active_generations(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = Evidence("BEF-SC-009")
    checkpoints = {
        ("baseline", "bef-env-a"): _checkpoint("baseline", "bef-env-a", "a-old", "0x0000000000000000000000000000000000000021"),
        ("mutated", "bef-env-a"): _checkpoint("mutated", "bef-env-a", "a-old", "0x0000000000000000000000000000000000000021"),
        ("reset", "bef-env-a"): _checkpoint("reset", "bef-env-a", "a-new", "0x0000000000000000000000000000000000000021"),
        ("baseline", "bef-env-b"): _checkpoint("baseline", "bef-env-b", "b-old", "0x0000000000000000000000000000000000000031"),
        ("mutated", "bef-env-b"): _checkpoint("mutated", "bef-env-b", "b-old", "0x0000000000000000000000000000000000000031"),
        ("after_reset", "bef-env-b"): _checkpoint("after_reset", "bef-env-b", "b-old", "0x0000000000000000000000000000000000000031"),
    }
    _configure_proof(monkeypatch, evidence, checkpoints)

    targets = cleanup.select_cleanup_targets(evidence, "BEF-SC-009")

    assert [(target.environment_id, target.generation_id) for target in targets] == [
        ("bef-env-a", "a-new"), ("bef-env-b", "b-old"),
    ]


def test_cleanup_refuses_checkpoint_when_database_generation_differs(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = Evidence("BEF-SC-010")
    checkpoints = {
        (phase, "bef-env-a"): _checkpoint(phase, "bef-env-a", f"g-{phase}", "0x0000000000000000000000000000000000000021")
        for phase in ("baseline", "trial", "reset", "after_stale", "fresh_trial")
    }
    _configure_proof(monkeypatch, evidence, checkpoints, wrong_generation=("fresh_trial", "bef-env-a"))

    with pytest.raises(CleanupRefused, match="cleanup_generation_identity_or_active_status_invalid"):
        cleanup.select_cleanup_targets(evidence, "BEF-SC-010")


@pytest.mark.parametrize(
    "payment_rows",
    [
        [
            {"operation_id": "purchase-op", "env_id": "bef-env-a", "generation_id": "g-fresh_trial",
             "receipt_status": "success", "transaction_hash": "0x" + "1" * 64},
            {"operation_id": "wrap-op", "env_id": "bef-env-a", "generation_id": "g-fresh_trial",
             "receipt_status": "not_submitted", "transaction_hash": None},
        ],
        [{"operation_id": "purchase-op", "env_id": "bef-env-a", "generation_id": "g-fresh_trial",
          "receipt_status": "failed", "transaction_hash": "0x" + "1" * 64}],
        [{"operation_id": "wrap-op", "env_id": "bef-env-a", "generation_id": "g-fresh_trial",
          "receipt_status": "success", "transaction_hash": "0x" + "1" * 64}],
    ],
    ids=("extra-not-submitted-payment", "non-success-canonical-payment", "selected-action-masquerades-as-payment"),
)
def test_cleanup_rejects_noncanonical_or_unsubmitted_payment_rows(
    monkeypatch: pytest.MonkeyPatch, payment_rows: list[dict[str, Any]],
) -> None:
    evidence = Evidence("BEF-SC-010")
    checkpoints = {
        (phase, "bef-env-a"): _checkpoint(phase, "bef-env-a", f"g-{phase}", "0x0000000000000000000000000000000000000021")
        for phase in ("baseline", "trial", "reset", "after_stale", "fresh_trial")
    }
    _configure_proof(monkeypatch, evidence, checkpoints, payment_rows_override=payment_rows)

    with pytest.raises(CleanupRefused, match="cleanup_generation_has_unresolved_or_incomplete_work"):
        cleanup.select_cleanup_targets(evidence, "BEF-SC-010")


def test_not_submitted_is_an_unresolved_payment_state() -> None:
    tables = {
        name: [] for name in cleanup._EFFECT_TABLES
    }
    tables["payments-by-operation"] = [{"receipt_status": "not_submitted"}]

    assert cleanup._no_unresolved_values(tables) is False


def test_cleanup_fence_failure_is_recorded_and_fails_scenario(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = Evidence("BEF-SC-010")
    evidence.directory = workspace_tmp_path / "probe"
    evidence.directory.mkdir()
    (evidence.directory / "probe.json").write_text("{}\n", encoding="utf-8")
    target = CleanupTarget(
        "bef-env-a", "a7d73b37-2b34-48df-870f-f29a7f2ca115", "fresh_trial", "participant-a",
        "0x0000000000000000000000000000000000000021",
    )
    context = SimpleNamespace(
        scenario_id="BEF-SC-010",
        outcome=evidence,
        observations={"stale_generation_fenced", "chain_baseline", "service_baseline", "fixture_hash", "equivalent_probe_outcome"},
    )
    cleanup_root = workspace_tmp_path / "cleanup"
    cleanup_root.mkdir()
    monkeypatch.setattr(cleanup, "_new_cleanup_root", lambda *_: cleanup_root)
    monkeypatch.setattr(cleanup, "select_cleanup_targets", lambda *_: (target,))
    monkeypatch.setattr(trial_runner, "_runtime_environment", lambda: {"BEF_DUMMY": "ok"})
    monkeypatch.setattr(trial_runner, "_relative", lambda path: Path(path).as_posix())

    def fail_fence(**_kwargs: Any) -> dict[str, Any]:
        raise trial_runner.TrialBlocked("cleanup_workload_failed")

    monkeypatch.setattr(trial_runner, "_run_unbounded_workload", fail_fence)

    with pytest.raises(AssertionError, match="cleanup_workload_failed") as error:
        cleanup.cleanup_after_verified_scenario(context, repository_root=workspace_tmp_path)

    summary_path = cleanup_root / "cleanup.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "failed"
    assert summary["reasonCode"] == "cleanup_workload_failed"
    assert "cleanup.json#" in str(error.value)


@pytest.mark.parametrize(
    "reference_mutation",
    [None, "path", "sha256", "status"],
    ids=("actual-producer-proof", "wrong-reference-path", "wrong-reference-sha", "unverified-status"),
)
def test_cleanup_checks_direct_fence_workload_evidence_shape(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    reference_mutation: str | None,
) -> None:
    evidence = Evidence("BEF-SC-010")
    evidence.directory = workspace_tmp_path / "probe"
    evidence.directory.mkdir()
    (evidence.directory / "probe.json").write_text("{}\n", encoding="utf-8")
    target = CleanupTarget(
        "bef-env-a", "a7d73b37-2b34-48df-870f-f29a7f2ca115", "fresh_trial", "participant-a",
        "0x0000000000000000000000000000000000000021",
    )
    context = SimpleNamespace(
        scenario_id="BEF-SC-010",
        outcome=evidence,
        observations={"stale_generation_fenced", "chain_baseline", "service_baseline", "fixture_hash", "equivalent_probe_outcome"},
    )
    cleanup_root = workspace_tmp_path / "cleanup-positive"
    cleanup_root.mkdir()
    monkeypatch.setattr(cleanup, "_new_cleanup_root", lambda *_: cleanup_root)
    monkeypatch.setattr(cleanup, "select_cleanup_targets", lambda *_: (target,))
    monkeypatch.setattr(trial_runner, "_runtime_environment", lambda: {"BEF_DUMMY": "ok"})
    monkeypatch.setattr(trial_runner, "_relative", lambda path: Path(path).as_posix())

    def write_direct_fence_reports(**kwargs: Any) -> dict[str, Any]:
        workload_dir = kwargs["evidence_dir"]
        workload_dir.mkdir(parents=True, exist_ok=False)
        fence_report = {
            "fenceHttpStatus": 200,
            "serverReportedChainState": "not_touched",
            "databaseRowsUnchangedAcrossFence": True,
            "generationFenced": True,
            "returnedCountsMatch": True,
            "returnedStatusesMatch": True,
            "protectedStateEqual": True,
            "generationIdentityMatchesBeforeFence": True,
            "envId": "bef-env-a",
            "generationId": "a7d73b37-2b34-48df-870f-f29a7f2ca115",
            "fencePurpose": "trial_cleanup",
            "phase": "cold",
            "persistedEffectsUnchangedSinceReadiness": None,
            "protectedStateUnchangedSinceReadiness": None,
            "guardrailGenerationHadNoEffects": None,
        }
        verification_path = workload_dir / "fence-verification.json"
        verification_path.write_text(json.dumps(fence_report), encoding="utf-8")
        fence_digest = trial_runner._sha256(verification_path.read_bytes())
        workload_report = {
            "schemaVersion": "bef-resource-purchase-workload/v1",
            "scenarioId": "BEF-SC-011",
            "phase": "cold",
            "mode": "fence",
            "status": "captured",
            "environmentId": "bef-env-a",
            "environment": {"envId": "bef-env-a", "generation": {
                "generationId": "a7d73b37-2b34-48df-870f-f29a7f2ca115",
                "participantId": "participant-a",
                "payerAddress": "0x0000000000000000000000000000000000000021",
            }},
            "generationId": "a7d73b37-2b34-48df-870f-f29a7f2ca115",
            "fencePurpose": "trial_cleanup",
            "fenceVerification": {"path": "fence-verification.json", "sha256": fence_digest, "status": "verified"},
        }
        if reference_mutation == "path":
            workload_report["fenceVerification"]["path"] = "other-report.json"
        elif reference_mutation == "sha256":
            workload_report["fenceVerification"]["sha256"] = "0" * 64
        elif reference_mutation == "status":
            workload_report["fenceVerification"]["status"] = "failed"
        (workload_dir / "workload.json").write_text(json.dumps(workload_report), encoding="utf-8")
        return workload_report

    monkeypatch.setattr(trial_runner, "_run_unbounded_workload", write_direct_fence_reports)

    if reference_mutation is None:
        result = cleanup.cleanup_after_verified_scenario(context, repository_root=workspace_tmp_path)
        assert result is not None and result["status"] == "fenced"
        summary = json.loads((cleanup_root / "cleanup.json").read_text(encoding="utf-8"))
        fenced = summary["targets"][0]
        assert fenced["status"] == "fenced"
        assert fenced["workloadPath"].endswith("workload/workload.json")
        assert fenced["fenceReportPath"].endswith("workload/fence-verification.json")
        assert len(fenced["workloadSha256"]) == 64
        assert len(fenced["fenceReportSha256"]) == 64
    else:
        with pytest.raises(AssertionError, match="cleanup_fence_target_proof_mismatch"):
            cleanup.cleanup_after_verified_scenario(context, repository_root=workspace_tmp_path)
        summary = json.loads((cleanup_root / "cleanup.json").read_text(encoding="utf-8"))
        assert summary["status"] == "failed"
        assert summary["reasonCode"] == "cleanup_fence_target_proof_mismatch"
