from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.bdd.adapters.benchmark_environment_feasibility import EvidenceInvalid, ProbeBlocked
from tools.replay_bef_evidence import (
    REPOSITORY_ROOT,
    ReplayInputError,
    _evidence_root_reference,
    main,
    replay_evidence,
)


@pytest.fixture(autouse=True)
def _select_synced_main_replay_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEF_SPEC_PROFILE", "synced-main")


HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def _write_json(path: Path, payload: dict) -> bytes:
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _captured_evidence(tmp_path: Path, scenario_id: str = "BEF-SC-012") -> Path:
    evidence = tmp_path / "original"
    evidence.mkdir()
    manifest = {
        "schemaVersion": "bef-runtime-manifest/v1",
        "change": "benchmark-environment-feasibility",
        "source": {
            "chainId": 8453,
            "blockNumber": "0x1234",
            "blockHash": "0x" + HASH_C,
            "allowedMethods": ["eth_chainId", "eth_getBlockByNumber"],
            "maxRequestBytes": 8192,
        },
        "contracts": {},
    }
    manifest_bytes = _write_json(evidence / "manifest.json", manifest)
    rpc = {
        "schemaVersion": "bef-rpc-observation/v1",
        "boundary": "source-readonly-proxy",
        "operationId": "replay-op-1",
        "variantId": None,
        "endpointBoundary": "source-readonly-proxy",
        "method": "eth_chainId",
        "params": [],
        "requestedBlock": None,
        "result": "0x2105",
        "forwarded": True,
        "requestBytes": 42,
    }
    rpc_bytes = _write_json(evidence / "source/rpc.json", rpc)
    index = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": scenario_id,
        "status": "captured",
        "manifest": {
            "path": "manifest.json",
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "environment": {
            "envId": "bef-env-replay-test",
            "generation": {"generationId": "bef-generation-replay-test"},
        },
        "operations": [{"operationId": "replay-op-1", "kind": "read"}],
        "observations": [],
        "artifacts": [
            {
                "path": "manifest.json",
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "contentType": "application/json",
                "boundary": "runtime-manifest",
            },
            {
                "path": "source/rpc.json",
                "sha256": hashlib.sha256(rpc_bytes).hexdigest(),
                "contentType": "application/json",
                "boundary": "source-readonly-proxy",
            },
        ],
        "applicationSourceSha256": HASH_A,
        "probeSourceSha256": HASH_B,
        "runtimeVersions": {"probeNode": "v24.test"},
        "sourceBlock": {"number": "0x1234", "hash": "0x" + HASH_C},
    }
    _write_json(evidence / "probe.json", index)
    return evidence


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _forbid_external_execution(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("offline evidence replay attempted external execution")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def test_replay_is_offline_uses_original_scenario_and_preserves_input(tmp_path: Path, monkeypatch) -> None:
    evidence = _captured_evidence(tmp_path, "BEF-SC-004")
    report_path = tmp_path / "replay-report.json"
    before = _tree_bytes(evidence)

    _forbid_external_execution(monkeypatch)

    report = replay_evidence(evidence, report_path, source_profile="synced-main")

    assert report["schemaVersion"] == "bef-evidence-replay/v1"
    assert report["evaluatedScenarioId"] == "BEF-SC-004"
    assert report["original"]["scenarioId"] == "BEF-SC-004"
    assert report["replayStatus"] == "not_matched"
    assert report["original"]["applicationSourceSha256"] == HASH_A
    assert report["original"]["probeSourceSha256"] == HASH_B
    assert report["original"]["generationId"] == "bef-generation-replay-test"
    assert report["original"]["operationIds"] == ["replay-op-1"]
    assert report["original"]["probeIndexSha256"] == hashlib.sha256(before["probe.json"]).hexdigest()
    assert {item["path"] for item in report["original"]["artifacts"]} == {
        "manifest.json",
        "source/rpc.json",
    }
    assert report["gateStatus"] == "not_established_by_replay"
    assert report["replay"]["contractChange"] == "synchronized-main"
    assert report["replay"]["sourceProfile"] == "synced-main/v1"
    assert set(report["replay"]["approvedSources"]) == {
        "harnessContract",
        "normativeSpec",
        "predicateSource",
    }
    assert report["replay"]["predicateCompleted"] is True
    assert report["replay"]["checksMatchContract"] is True
    assert report["replay"]["execution"]["httpRequests"] == 0
    assert report["replay"]["execution"]["rpcCalls"] == 0
    assert report["replay"]["execution"]["databaseQueries"] == 0
    assert report["replay"]["execution"]["broadcasts"] == 0
    assert report["replay"]["execution"]["newTrials"] == 0
    assert _tree_bytes(evidence) == before
    assert json.loads(report_path.read_text(encoding="utf-8")) == report


def test_cli_prints_only_replay_status_and_report_path(tmp_path: Path, capsys) -> None:
    evidence = _captured_evidence(tmp_path, "BEF-SC-004")
    report_path = tmp_path / "cli-report.json"

    result = main([
        "--evidence-dir", str(evidence),
        "--report", str(report_path),
        "--source-profile", "synced-main",
    ])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.err == ""
    assert captured.out == f"status=not_matched report={report_path}\n"
    assert report_path.is_file()


def test_replay_rejects_tampered_artifact_without_writing_report(tmp_path: Path, monkeypatch) -> None:
    evidence = _captured_evidence(tmp_path)
    artifact = evidence / "source/rpc.json"
    artifact.write_bytes(artifact.read_bytes() + b" ")
    before = _tree_bytes(evidence)
    report_path = tmp_path / "must-not-exist.json"
    _forbid_external_execution(monkeypatch)

    with pytest.raises(EvidenceInvalid):
        replay_evidence(evidence, report_path, source_profile="synced-main")

    assert not report_path.exists()
    assert _tree_bytes(evidence) == before


@pytest.mark.parametrize("kind", ["missing_index", "blocked_index"])
def test_replay_rejects_missing_or_blocked_input_without_report(tmp_path: Path, kind: str) -> None:
    evidence = tmp_path / "original"
    evidence.mkdir()
    if kind == "blocked_index":
        _write_json(
            evidence / "probe.json",
            {
                "schemaVersion": "bef-runtime-probe/v1",
                "scenarioId": "BEF-SC-012",
                "status": "blocked",
                "blockedReasonCode": "missing_environment",
                "missingPrerequisites": ["BEF_API_BASE_URL"],
                "manifest": None,
                "environment": None,
                "operations": [],
                "observations": [],
                "artifacts": [],
            },
        )
    report_path = tmp_path / "must-not-exist.json"

    with pytest.raises((ProbeBlocked, ReplayInputError)):
        replay_evidence(evidence, report_path, source_profile="synced-main")

    assert not report_path.exists()


def test_report_cannot_be_written_inside_original_evidence(tmp_path: Path) -> None:
    evidence = _captured_evidence(tmp_path)

    with pytest.raises(ReplayInputError, match="outside_original_evidence"):
        replay_evidence(evidence, evidence / "replay.json", source_profile="synced-main")

    assert not (evidence / "replay.json").exists()


def test_report_evidence_root_resolves_from_repository_capture() -> None:
    runs_root = REPOSITORY_ROOT / "artifacts/runs"
    runs_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bef-replay-root-test-", dir=runs_root) as temporary:
        run_root = Path(temporary)
        evidence = _captured_evidence(run_root, "BEF-SC-004")
        report_path = run_root / "replay-report.json"

        report = replay_evidence(evidence, report_path, source_profile="synced-main")

        root_reference = report["original"]["evidenceRoot"]
        assert root_reference["kind"] == "repository_relative"
        assert report["original"]["externalResolutionRequired"] is False
        assert (REPOSITORY_ROOT / root_reference["path"]).resolve() == evidence.resolve()


def test_external_report_root_uses_safe_resolution_handle(tmp_path: Path) -> None:
    repository_root = tmp_path / "workspace"
    evidence_root = tmp_path / "private-user-path"
    repository_root.mkdir()
    evidence_root.mkdir()

    reference = _evidence_root_reference(evidence_root, repository_root)
    encoded = json.dumps(reference)

    assert reference["evidenceRoot"]["kind"] == "external"
    assert reference["evidenceRoot"]["handle"].startswith("sha256:")
    assert reference["externalResolutionRequired"] is True
    assert str(evidence_root) not in encoded
