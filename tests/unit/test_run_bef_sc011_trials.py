"""Offline validation of SC011 orchestration guards and evidence parsing."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import bef_resource_sampler as sampler
from tools import run_bef_sc011_trials as trials


@pytest.fixture
def workspace_tmp_path():
    parent = sampler.ARTIFACTS_ROOT
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sc011-test-", dir=parent) as directory:
        yield Path(directory)


def _write_json(path: Path, value: object) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def _valid_resource_metric_sample(host: dict[str, object]) -> dict[str, object]:
    containers = []
    for service in sampler.SERVICES:
        row: dict[str, object] = {
            "service": service,
            "cgroupStatus": "observed",
            "cpuUsageStatus": "observed",
            "cpuUsageDeltaNanoseconds": 1,
        }
        if service in sampler.POLICY_MEMORY_KEYS:
            row.update({
                "memoryLimitCheck": {"status": "within_limit"},
                "memoryCurrentWindowMaximumBytes": 10,
                "memoryCurrentWindowSampleCount": 2,
                "memoryPeakBytesSinceContainerStart": 12,
            })
        containers.append(row)
    return {
        "host": host,
        "containers": containers,
        "sourceProxy": {"windowDelta": {"status": "observed", "sourceCallsReserved": 0}},
        "artifactDirectory": {"guardrailCheck": {"status": "within_limit", "observedMaximumBytes": 100}},
        "cacheDirectories": {
            name: {"guardrailCheck": {"status": "within_limit"}, "maximumObservedBytes": 10, "byteLimit": 100}
            for name in ("anvil-a-state", "anvil-a-rpc")
        },
    }


def test_default_cli_is_plan_only_and_never_calls_executor(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fail_if_called() -> object:
        raise AssertionError("default mode must not execute Docker or runtime actions")

    monkeypatch.setattr(trials, "_execute", fail_if_called)

    assert trials.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["execution"] == "plan_only"
    assert report["scenarioId"] == "BEF-SC-011"
    assert report["gateStatus"] == "not_established_by_plan"


def test_warm_restart_uses_combined_nonempty_cache_and_allows_empty_root() -> None:
    expected = {"anvil-a-state", "anvil-a-rpc"}
    prepared = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 80,
            "fileCount": 1,
            "files": [{"fileKey": "f" * 64, "sha256": "a" * 64, "sizeBytes": 80}],
        },
    }
    after_restart = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 100,
            "fileCount": 2,
            "files": [
                {"fileKey": "f" * 64, "sha256": "a" * 64, "sizeBytes": 80},
                {"fileKey": "e" * 64, "sha256": "b" * 64, "sizeBytes": 20},
            ],
        },
    }

    summary = trials._cache_inventory_summary(prepared, expected_cache_names=expected)
    diff = trials._cache_inventory_diff(prepared, after_restart, expected_cache_names=expected)

    assert summary == {"status": "observed", "cacheDirectoryCount": 2, "fileCount": 1, "bytes": 80, "hasEntries": True}
    assert diff["status"] == "observed"
    assert diff["beforeHadEntries"] is True
    assert diff["allBeforeEntriesRetained"] is True
    assert diff["retainedFileCount"] == 1
    assert diff["addedFileCount"] == 1


def test_warm_prepared_cache_requires_positive_combined_bytes() -> None:
    expected = {"anvil-a-state", "anvil-a-rpc"}
    inventories = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 0,
            "fileCount": 1,
            "files": [{"fileKey": "f" * 64, "sha256": "a" * 64, "sizeBytes": 0}],
        },
    }

    summary = trials._cache_inventory_summary(inventories, expected_cache_names=expected)

    assert summary == {"status": "observed", "cacheDirectoryCount": 2, "fileCount": 1, "bytes": 0, "hasEntries": False}


def test_warm_restart_diff_rejects_an_empty_combined_prepared_cache() -> None:
    expected = {"anvil-a-state", "anvil-a-rpc"}
    empty = {
        name: {"status": "observed", "bytes": 0, "fileCount": 0, "files": []}
        for name in expected
    }
    after_restart = {
        **empty,
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 20,
            "fileCount": 1,
            "files": [{"fileKey": "e" * 64, "sha256": "b" * 64, "sizeBytes": 20}],
        },
    }

    diff = trials._cache_inventory_diff(empty, after_restart, expected_cache_names=expected)

    assert diff["status"] == "observed"
    assert diff["beforeHadEntries"] is False
    assert diff["allBeforeEntriesRetained"] is False
    assert diff["beforeFileCount"] == 0
    assert diff["afterFileCount"] == 1


def test_cache_diff_records_warm_purchase_mutation_without_hiding_it() -> None:
    before = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 80,
            "fileCount": 1,
            "files": [{"fileKey": "f" * 64, "sha256": "a" * 64, "sizeBytes": 80}],
        },
    }
    after = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {
            "status": "observed",
            "bytes": 40,
            "fileCount": 1,
            "files": [{"fileKey": "f" * 64, "sha256": "c" * 64, "sizeBytes": 40}],
        },
    }

    diff = trials._cache_inventory_diff(before, after)

    assert diff["status"] == "observed"
    assert diff["beforeHadEntries"] is True
    assert diff["allBeforeEntriesRetained"] is False
    assert diff["changedFileCount"] == 1
    assert diff["changedFileKeysSample"] == [
        {
            "cache": "anvil-a-rpc",
            "fileKey": "f" * 64,
            "beforeSha256": "a" * 64,
            "afterSha256": "c" * 64,
        }
    ]


def test_cache_inventory_diff_fails_closed_on_unknown_or_missing_roots() -> None:
    expected = {"anvil-a-state", "anvil-a-rpc"}
    before = {
        "anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []},
        "anvil-a-rpc": {"status": "unknown", "reason": "read_failed"},
    }
    after = {"anvil-a-state": {"status": "observed", "bytes": 0, "fileCount": 0, "files": []}}

    assert trials._cache_inventory_summary(before, expected_cache_names=expected)["status"] == "unknown"
    assert trials._cache_inventory_diff(before, after, expected_cache_names=expected)["status"] == "unknown"


@pytest.mark.parametrize(
    ("stdout", "expected_verified"),
    [
        ("exited|0|false|\n", True),
        ("exited|143|false|\n", True),
        ("exited|137|false|\n", False),
        ("exited|143|true|\n", False),
        ("exited|0|false|container error\n", False),
    ],
)
def test_anvil_stop_inspection_rejects_forced_kill_oom_or_container_error(
    monkeypatch: pytest.MonkeyPatch, stdout: str, expected_verified: bool
) -> None:
    def fake_run_checked(command: list[str], **_kwargs: object) -> str:
        assert command[:3] == ["docker", "inspect", "--format"]
        assert command[-1] == "a" * 64
        return stdout

    monkeypatch.setattr(trials, "_run_checked", fake_run_checked)

    result = trials._anvil_a_stop_outcome("a" * 64)

    assert result.get("status") == "observed"
    assert result.get("gracefulStopVerified") is expected_verified
    assert "container error" not in json.dumps(result)


def test_scenario_deadline_caps_each_child_and_expires_monotonically(monkeypatch: pytest.MonkeyPatch) -> None:
    deadline = trials.ScenarioDeadline(900)
    assert 0 < deadline.bounded_timeout(120, reserve_seconds=45) <= 120

    monkeypatch.setattr(trials.time, "monotonic_ns", lambda: deadline.deadline_ns)
    with pytest.raises(trials.TrialBlocked, match="max_resource_scenario_deadline_exhausted"):
        deadline.bounded_timeout(30)


def test_complete_docker_info_producer_shape_passes_resource_metric_consumer(monkeypatch: pytest.MonkeyPatch) -> None:
    docker_info = (
        "Docker Desktop (containerized)|6.6.87.2-microsoft-standard-WSL2+|x86_64|20|"
        "8120688640|2|overlay2|29.7.2"
    )
    monkeypatch.setattr(sampler, "_run_command", lambda *_args, **_kwargs: docker_info)

    host = sampler._docker_host_info()
    assert host == {
        "status": "observed",
        "source": "docker-info",
        "operatingSystem": "Docker Desktop (containerized)",
        "kernelVersion": "6.6.87.2-microsoft-standard-WSL2+",
        "architecture": "x86_64",
        "cpuCount": 20,
        "memoryTotalBytes": 8_120_688_640,
        "cgroupVersion": "2",
        "storageDriver": "overlay2",
        "engineVersion": "29.7.2",
    }

    trials._require_resource_metrics(_valid_resource_metric_sample(host))


def test_workload_command_uses_direct_tsx_loader_uri(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    loader = tmp_path / "loader.mjs"
    workload = tmp_path / "workload.ts"
    loader.write_text("", encoding="utf-8")
    workload.write_text("", encoding="utf-8")
    monkeypatch.setattr(trials, "TSX_LOADER_ENTRY", loader)
    monkeypatch.setattr(trials, "WORKLOAD_ENTRY", workload)
    monkeypatch.setattr(shutil, "which", lambda name: "node" if name == "node" else None)

    command = trials._workload_command("purchase", "cold", tmp_path / "evidence", "bef-env-a")

    assert command[:4] == ["node", "--import", loader.resolve().as_uri(), str(workload)]
    assert str(loader.parent / "cli.mjs") not in command


@pytest.mark.skipif(
    shutil.which("node") is None or not trials.TSX_LOADER_ENTRY.is_file(),
    reason="requires the installed Node runtime and pinned TSX loader",
)
def test_pinned_tsx_loader_runs_typescript_in_the_sampler_direct_child_pid(tmp_path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    workload = tmp_path / "pid-probe.ts"
    workload.write_text("process.stdout.write(String(process.pid))\n", encoding="utf-8")

    commands = (
        ("tsx-cli", [node, str(trials.TSX_LOADER_ENTRY.parent / "cli.mjs"), str(workload)], False),
        ("direct-loader", [node, "--import", trials.TSX_LOADER_ENTRY.as_uri(), str(workload)], True),
    )
    for _name, command, runs_in_direct_child in commands:
        process = subprocess.Popen(
            command,
            cwd=trials.REPO,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            shell=False,
            close_fds=True,
        )
        stdout, _ = process.communicate(timeout=15)
        assert process.returncode == 0
        assert stdout.strip().isdigit()
        script_pid = int(stdout.strip())
        assert (script_pid == process.pid) is runs_in_direct_child, _name


def test_allocated_evidence_root_accepts_only_the_preflight_control(workspace_tmp_path: Path) -> None:
    control = {
        "schemaVersion": "bef-resource-missing-sampler-control/v1",
        "variantId": "missing_sampler",
        "operationId": None,
    }
    _write_json(workspace_tmp_path / "missing-sampler-control.json", control)
    assert trials._new_run_root(workspace_tmp_path) == workspace_tmp_path.resolve()

    _write_json(workspace_tmp_path / "unrelated.json", {"status": "not-allowed"})
    with pytest.raises(trials.TrialBlocked, match="allocated_trial_evidence_directory_not_empty"):
        trials._new_run_root(workspace_tmp_path)


def test_allocated_evidence_root_must_remain_under_ignored_runs() -> None:
    with pytest.raises(trials.TrialBlocked, match="outside_ignored_runs"):
        trials._new_run_root(Path(__file__).resolve().parents[2] / "outside-bef-sc011")


def test_cache_binding_parser_reason_is_preserved_in_blocked_orchestration(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = workspace_tmp_path / "cache-binding-diagnostic"
    monkeypatch.setattr(trials, "RUNS", workspace_tmp_path)
    monkeypatch.setattr(trials, "_load_manifest_guardrails", lambda: ({
        "maxTrialSeconds": 120,
        "maxEvidenceBytesPerTrial": 1_000_000,
        "maxAnvilCacheBytesEach": 1_000,
        "maxResourceReadOverrunSeconds": 2,
        "maxResourceScenarioSeconds": 900,
    }, "a" * 64))
    monkeypatch.setattr(trials, "_runtime_environment", lambda: {})
    monkeypatch.setattr(trials, "_acquire_lock", lambda: "test-lock")
    monkeypatch.setattr(trials, "_release_lock", lambda _token: None)
    monkeypatch.setattr(trials.shutil, "disk_usage", lambda _path: SimpleNamespace(free=1 << 40))
    monkeypatch.setattr(trials, "_assert_isolation", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        trials,
        "_anvil_a_info",
        lambda **_kwargs: sampler.ContainerInfo("b" * 64, "anvil-a", "foundry-image", "running", 1_000, 1_000),
    )
    monkeypatch.setattr(sampler, "_compose_anvil_cache_sources", lambda: ({
        "anvil-a": {"state": str(workspace_tmp_path / "state"), "rpc": str(workspace_tmp_path / "rpc")},
        "anvil-b": {"state": str(workspace_tmp_path / "state-b"), "rpc": str(workspace_tmp_path / "rpc-b")},
    }, "c" * 64))
    monkeypatch.setattr(trials, "_cache_inventory", lambda paths, *_args, **_kwargs: {
        name: {"status": "observed", "bytes": 0, "fileCount": 0} for name in paths
    })
    monkeypatch.setattr(trials, "_run_checked", lambda *_args, **_kwargs: "")

    def failed_binding(*_args, **_kwargs):
        raise trials.TrialBlocked("anvil_a_cache_mount_binding_unverified", diagnostics={
            "cacheBindingStatus": "unknown",
            "cacheBindingReason": "foundry_rpc_cache_not_writable_by_container_user",
            "anvilContainerIdPrefix": "b" * 12,
            "composeConfigSha256": "d" * 64,
        })

    monkeypatch.setattr(trials, "_bind_observation", failed_binding)

    with pytest.raises(trials.TrialBlocked, match="anvil_a_cache_mount_binding_unverified") as error:
        trials._execute(run_root)

    assert error.value.evidence_path == run_root / "orchestration.json"
    report = json.loads(error.value.evidence_path.read_text(encoding="utf-8"))
    assert report["status"] == "blocked"
    assert report["diagnostics"]["cacheBindingReason"] == "foundry_rpc_cache_not_writable_by_container_user"
    assert report["diagnostics"]["composeConfigSha256"] == "d" * 64


def test_protective_fence_cli_is_distinct_from_reset_execution(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(trials, "_protective_fence_only", lambda path, env_id="bef-env-a": {
        "status": "protected", "exitCode": 0, "fencePurpose": "protective_only",
        "reportPath": "recovery/workload.json", "envId": env_id,
    })

    assert trials.main(["--protective-fence-only", "--evidence-dir", str(workspace_tmp_path), "--env-id", "B"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "protected"
    assert summary["fencePurpose"] == "protective_only"
    assert summary["envId"] == "bef-env-b"

    monkeypatch.setattr(trials, "_protective_fence_only", lambda _path, _env_id="bef-env-a": {
        "status": "protected", "exitCode": 0, "fencePurpose": "protective_only",
        "envId": "bef-env-a",
    })
    assert trials.main(["--protective-fence-only", "--evidence-dir", str(workspace_tmp_path), "--env-id", "B"]) == 2


def test_fence_verifier_accepts_only_requested_environment(workspace_tmp_path: Path) -> None:
    report = {
        "fenceHttpStatus": 200,
        "serverReportedChainState": "not_touched",
        "databaseRowsUnchangedAcrossFence": True,
        "generationFenced": True,
        "returnedCountsMatch": True,
        "returnedStatusesMatch": True,
        "protectedStateEqual": True,
        "generationIdentityMatchesBeforeFence": True,
        "envId": "bef-env-b",
        "generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115",
        "fencePurpose": "protective_only",
        "phase": "guardrail_exceeded",
        "persistedEffectsUnchangedSinceReadiness": None,
        "protectedStateUnchangedSinceReadiness": None,
        "guardrailGenerationHadNoEffects": None,
    }
    _write_json(workspace_tmp_path / "fence-verification.json", report)

    accepted = trials._verify_fence_report(
        workspace_tmp_path, expected_purpose="protective_only", expected_env_id="bef-env-b"
    )
    assert accepted["generationId"] == report["generationId"]
    with pytest.raises(trials.TrialBlocked, match="independent_generation_fence_proof_failed"):
        trials._verify_fence_report(workspace_tmp_path, expected_purpose="protective_only")


def test_protective_fence_proof_does_not_claim_guardrail_readiness_or_no_effects(workspace_tmp_path: Path) -> None:
    core = {
        "fenceHttpStatus": 200,
        "serverReportedChainState": "not_touched",
        "databaseRowsUnchangedAcrossFence": True,
        "generationFenced": True,
        "returnedCountsMatch": True,
        "returnedStatusesMatch": True,
        "protectedStateEqual": True,
        "generationIdentityMatchesBeforeFence": True,
        "envId": "bef-env-a",
        "generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115",
    }
    report_path = workspace_tmp_path / "fence-verification.json"
    protective = {
        **core,
        "fencePurpose": "protective_only",
        "phase": "guardrail_exceeded",
        "persistedEffectsUnchangedSinceReadiness": None,
        "protectedStateUnchangedSinceReadiness": None,
        "guardrailGenerationHadNoEffects": None,
    }
    _write_json(report_path, protective)

    accepted = trials._verify_fence_report(workspace_tmp_path, expected_purpose="protective_only")
    assert accepted["fencePurpose"] == "protective_only"
    assert accepted["generationId"] == protective["generationId"]

    invalid_protective = {**protective, "guardrailGenerationHadNoEffects": True}
    report_path.write_bytes((json.dumps(invalid_protective, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    with pytest.raises(trials.TrialBlocked, match="non_guardrail_fence_claimed_readiness_comparison"):
        trials._verify_fence_report(workspace_tmp_path, expected_purpose="protective_only")

    trial_cleanup = {
        **core,
        "fencePurpose": "trial_cleanup",
        "phase": "cold",
        "persistedEffectsUnchangedSinceReadiness": None,
        "protectedStateUnchangedSinceReadiness": None,
        "guardrailGenerationHadNoEffects": None,
    }
    report_path.write_bytes((json.dumps(trial_cleanup, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    assert trials._verify_fence_report(workspace_tmp_path, expected_purpose="trial_cleanup")["fencePurpose"] == "trial_cleanup"
    trial_cleanup["persistedEffectsUnchangedSinceReadiness"] = True
    report_path.write_bytes((json.dumps(trial_cleanup, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    with pytest.raises(trials.TrialBlocked, match="non_guardrail_fence_claimed_readiness_comparison"):
        trials._verify_fence_report(workspace_tmp_path, expected_purpose="trial_cleanup")

    readonly_guardrail = {
        **core,
        "fencePurpose": "readonly_guardrail",
        "phase": "guardrail_exceeded",
        "persistedEffectsUnchangedSinceReadiness": True,
        "protectedStateUnchangedSinceReadiness": True,
        "guardrailGenerationHadNoEffects": True,
    }
    report_path.write_bytes((json.dumps(readonly_guardrail, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    assert trials._verify_fence_report(workspace_tmp_path, expected_purpose="readonly_guardrail")["fencePurpose"] == "readonly_guardrail"
    readonly_guardrail["guardrailGenerationHadNoEffects"] = False
    report_path.write_bytes((json.dumps(readonly_guardrail, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    with pytest.raises(trials.TrialBlocked, match="guardrail_generation_changed_before_fence"):
        trials._verify_fence_report(workspace_tmp_path, expected_purpose="readonly_guardrail")


def test_guardrail_trial_summary_reads_direct_fence_mode_output(workspace_tmp_path: Path) -> None:
    run_root = workspace_tmp_path / "guardrail-run"
    fence_dir = run_root / "guardrail-fence-active"
    fence_dir.mkdir(parents=True)
    report = {
        "fencePurpose": "readonly_guardrail",
        "phase": "guardrail_exceeded",
        "fenceHttpStatus": 200,
        "serverReportedChainState": "not_touched",
        "databaseRowsUnchangedAcrossFence": True,
        "generationFenced": True,
        "returnedCountsMatch": True,
        "returnedStatusesMatch": True,
        "protectedStateEqual": True,
        "generationIdentityMatchesBeforeFence": True,
        "persistedEffectsUnchangedSinceReadiness": True,
        "protectedStateUnchangedSinceReadiness": True,
        "guardrailGenerationHadNoEffects": True,
        "envId": "bef-env-a",
        "generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115",
    }
    (fence_dir / "fence-verification.json").write_text(json.dumps(report), encoding="utf-8")

    verified = trials._verify_guardrail_readonly_fence_report(run_root)
    assert verified["fencePurpose"] == "readonly_guardrail"
    assert verified["path"].endswith("guardrail-fence-active/fence-verification.json")
    assert not (fence_dir / "fence").exists()


def test_active_fence_callback_selects_trial_cleanup_or_readonly_purpose(
    workspace_tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def verify(_directory: Path, *, expected_purpose: str) -> dict:
        observed.append(expected_purpose)
        return {"generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115", "fencePurpose": expected_purpose}

    monkeypatch.setattr(trials, "_run_unbounded_workload", lambda **_kwargs: {"status": "captured"})
    monkeypatch.setattr(trials, "_verify_fence_report", verify)
    for phase, expected_purpose in (
        ("cold", "trial_cleanup"),
        ("warm", "trial_cleanup"),
        ("guardrail_exceeded", "readonly_guardrail"),
    ):
        evidence_dir = workspace_tmp_path / phase
        evidence_dir.mkdir()
        report_path = evidence_dir / "workload.json"
        report_path.write_text("safe", encoding="utf-8")
        callback = trials._make_active_fence_callback(
            phase=phase,
            evidence_dir=evidence_dir,
            marker=evidence_dir / "marker.json",
            runtime_env={},
        )
        summary = callback(None)
        assert summary is not None
        assert summary["status"] == "captured"
        assert summary["fencePurpose"] == expected_purpose

    assert observed == ["trial_cleanup", "trial_cleanup", "readonly_guardrail"]


def test_read_progress_requires_actual_hashed_successful_http_artifacts(workspace_tmp_path: Path) -> None:
    tmp_path = workspace_tmp_path
    env_id = "bef-env-a"
    generation_id = str(uuid.uuid4())
    payer = "0x" + "12" * 20
    _write_json(tmp_path / "identity.json", {
        "schemaVersion": "bef-resource-workload-identity/v1",
        "phase": "guardrail_exceeded",
        "envId": env_id,
        "generationId": generation_id,
        "payerAddress": payer,
    })
    observation = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": "guardrail_exceeded",
        "request": {"method": "GET", "path": f"/tools/{env_id}/balances"},
        "response": {
            "status": 200,
            "body": {
                "boundary": "local-chain-readonly-proxy",
                "envId": env_id,
                "generationId": generation_id,
                "payer": payer,
            },
        },
    }
    observation_bytes = _write_json(tmp_path / "http" / "0001-read.json", observation)
    _write_json(tmp_path / "read-progress.ndjson", {
        "schemaVersion": "bef-resource-read-progress/v1",
        "envId": env_id,
        "generationId": generation_id,
        "variantId": "guardrail_exceeded",
        "sequence": 1,
        "observationId": "read-1",
        "status": 200,
        "artifact": {
            "path": "http/0001-read.json",
            "sha256": hashlib.sha256(observation_bytes).hexdigest(),
            "contentType": "application/json",
            "boundary": "actual-tool-http",
        },
    })

    result = trials._verify_read_progress(tmp_path, env_id)
    assert result["status"] == "observed"
    assert result["verifiedHttpObservations"] == 1

    (tmp_path / "http" / "0001-read.json").write_bytes(observation_bytes + b" ")
    with pytest.raises(trials.TrialBlocked, match="read_loop_http_artifact_hash_mismatch"):
        trials._verify_read_progress(tmp_path, env_id)


def test_resource_metric_gate_rejects_memory_or_cache_over_limit() -> None:
    containers = []
    for service in sampler.SERVICES:
        row = {"service": service, "cgroupStatus": "observed", "cpuUsageStatus": "observed", "cpuUsageDeltaNanoseconds": 1}
        if service in sampler.POLICY_MEMORY_KEYS:
            row.update({
                "memoryLimitCheck": {"status": "within_limit"},
                "memoryCurrentWindowMaximumBytes": 10,
                "memoryCurrentWindowSampleCount": 2,
                "memoryPeakBytesSinceContainerStart": 12,
            })
        containers.append(row)
    sample = {
        "host": {"status": "observed"},
        "containers": containers,
        "sourceProxy": {"windowDelta": {"status": "observed", "sourceCallsReserved": 0}},
        "artifactDirectory": {"guardrailCheck": {"status": "within_limit", "observedMaximumBytes": 100}},
        "cacheDirectories": {
            name: {"guardrailCheck": {"status": "within_limit"}, "maximumObservedBytes": 10, "byteLimit": 100}
            for name in ("anvil-a-state", "anvil-a-rpc")
        },
    }

    trials._require_resource_metrics(sample)
    sample["containers"][0]["memoryLimitCheck"] = {"status": "exceeded"}
    with pytest.raises(trials.TrialBlocked, match="resource_memory_window_or_limit_unavailable"):
        trials._require_resource_metrics(sample)

    sample["containers"][0]["memoryLimitCheck"] = {"status": "within_limit"}
    sample["cacheDirectories"]["anvil-a-state"]["maximumObservedBytes"] = 101
    with pytest.raises(trials.TrialBlocked, match="anvil_cache_bound_not_within_limit"):
        trials._require_resource_metrics(sample)
