"""Focused parser and guardrail-input tests for the read-only BEF sampler."""

from __future__ import annotations

import json
import base64
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
from itertools import count
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.bef_resource_sampler import (
    ContainerInfo,
    SamplerBlocked,
    _container_report,
    _counter_delta,
    _parse_args,
    _safe_int,
    collect_resource_window,
    measure_directory_inventory,
    parse_anvil_cache_binding,
    parse_cgroup_v2_bundle,
    parse_cpu_stat,
    run_bounded_trial_command,
)


@pytest.fixture
def workspace_tmp_path():
    import tools.bef_resource_sampler as sampler

    parent = sampler.REPOSITORY_ROOT / "artifacts" / "runs"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sampler-test-", dir=parent) as directory:
        yield Path(directory)


def test_cgroup_v2_counters_remain_exact_and_peak_scope_is_explicit() -> None:
    usage_usec = 9_007_199_254_740_993
    memory_current = 9_007_199_254_740_995
    memory_peak = 9_007_199_254_741_001
    bundle = "\n".join((
        "cpu memory io",
        f"usage_usec {usage_usec}",
        "user_usec 17",
        "system_usec 29",
        "max 100000",
        str(memory_current),
        str(memory_peak),
        "1073741824",
    ))

    observed = parse_cgroup_v2_bundle(bundle)

    assert observed["cpuUsageMicroseconds"] == usage_usec
    assert observed["cpuUsageNanoseconds"] == usage_usec * 1_000
    assert observed["memoryCurrentBytes"] == memory_current
    assert observed["memoryPeakBytes"] == memory_peak
    assert observed["memoryPeakScope"] == "since-container-cgroup-creation"
    assert observed["cpuLimit"] == {"quota": None, "period": 100_000, "unlimited": True}

    limited = parse_cgroup_v2_bundle(bundle.replace("max 100000", "150000 100000"))
    assert limited["cpuLimit"] == {"quota": 150_000, "period": 100_000, "unlimited": False}


def test_container_report_separates_window_current_max_from_lifetime_peak() -> None:
    info = ContainerInfo("a" * 64, "api", "node:test", "running", 805_306_368, 250_000_000)
    samples = [
        {"offsetNanoseconds": 0, "cgroup": {
            "status": "observed", "cpuUsageNanoseconds": 9_007_199_254_741_000,
            "memoryCurrentBytes": 400, "memoryPeakBytes": 900, "memoryLimitBytes": 805_306_368,
            "cpuLimit": {"quota": 25_000, "period": 100_000, "unlimited": False},
        }},
        {"offsetNanoseconds": 500_000_000, "cgroup": {
            "status": "observed", "cpuUsageNanoseconds": 9_007_199_254_741_123,
            "memoryCurrentBytes": 700, "memoryPeakBytes": 900, "memoryLimitBytes": 805_306_368,
            "cpuLimit": {"quota": 25_000, "period": 100_000, "unlimited": False},
        }},
    ]
    guardrails = {"maxApiMemoryBytes": 805_306_368}

    report = _container_report(info, samples, guardrails)

    assert report["cpuUsageDeltaNanoseconds"] == 123
    assert report["memoryCurrentWindowMaximumBytes"] == 700
    assert report["memoryPeakBytesSinceContainerStart"] == 900
    assert report["memoryPeakScope"] == "since-container-cgroup-creation"
    assert report["memoryLimitCheck"]["status"] == "within_limit"
    assert report["cpuLimitCheck"]["status"] == "compatible"
    assert report["memoryCurrentWindowSampleCount"] == 2

    one_sample = _container_report(info, samples[:1], guardrails)
    assert one_sample["cpuUsageStatus"] == "unknown"
    assert one_sample["cpuUsageDeltaNanoseconds"] is None
    assert one_sample["memoryCurrentWindowMaximumBytes"] is None
    assert one_sample["memoryLimitCheck"]["status"] == "unknown"


def test_cgroup_bundle_blocks_missing_or_malformed_required_metrics() -> None:
    with pytest.raises(ValueError, match="usage_missing"):
        parse_cpu_stat("user_usec 5\nsystem_usec 2")

    with pytest.raises(ValueError, match="controllers_unavailable"):
        parse_cgroup_v2_bundle("cpu\nusage_usec 1\nmax 100000\n1\n1\n1")

    with pytest.raises(ValueError, match="memory_metric_invalid"):
        parse_cgroup_v2_bundle("cpu memory\nusage_usec 1\nmax 100000\n1\nunknown\n1")


def test_counter_delta_rejects_reset_instead_of_reporting_negative_usage() -> None:
    result = _counter_delta(
        {"status": "observed", "forwardedItems": 8},
        {"status": "observed", "forwardedItems": 3},
        ("forwardedItems",),
    )
    assert result == {"status": "unknown", "reason": "counter_reset_or_invalid"}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 0, -1, 3601])
def test_non_finite_or_out_of_range_duration_is_blocked_before_external_reads(value: float) -> None:
    with pytest.raises(SamplerBlocked, match="duration_out_of_range"):
        collect_resource_window(duration_seconds=value)


def test_safe_integer_parser_never_accepts_negative_or_fractional_values() -> None:
    assert _safe_int("9007199254740993") == 9_007_199_254_740_993
    assert _safe_int("-1") is None
    assert _safe_int("1.5") is None


@pytest.mark.parametrize(("output", "reason"), [
    ("Docker Desktop|Linux|x86_64|20|8120688640|2|overlay2", "docker_host_info_invalid"),
    ("Docker Desktop|Linux|x86_64|bad|8120688640|2|overlay2|29.7.2", "docker_host_info_incomplete"),
    ("Docker Desktop|Linux|x86_64|20|bad|2|overlay2|29.7.2", "docker_host_info_incomplete"),
    ("|Linux|x86_64|20|8120688640|2|overlay2|29.7.2", "docker_host_info_incomplete"),
    ("Docker Desktop|Linux|x86_64|20|8120688640||overlay2|29.7.2", "docker_host_info_incomplete"),
])
def test_docker_host_info_keeps_invalid_or_incomplete_results_unobserved(
    output: str, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.bef_resource_sampler as sampler

    monkeypatch.setattr(sampler, "_run_command", lambda *_args, **_kwargs: output)
    with pytest.raises(SamplerBlocked, match=reason):
        sampler._docker_host_info()


def test_directory_inventory_hashes_actual_cache_files_without_exposing_names(workspace_tmp_path: Path) -> None:
    cache = workspace_tmp_path / "inventory" / "rpc-cache"
    (cache / "8453" / "52982196").mkdir(parents=True)
    first_file = cache / "8453" / "52982196" / "entry-one.json"
    second_file = cache / "8453" / "52982196" / "entry-two.json"
    first_file.write_bytes(b"cached-response-one")
    second_file.write_bytes(b"cached-response-two")

    before = measure_directory_inventory(cache)
    first_file.write_bytes(b"changed-response-one")
    after = measure_directory_inventory(cache)

    assert before["status"] == after["status"] == "observed"
    assert before["fileCount"] == after["fileCount"] == 2
    assert before["bytes"] == len(b"cached-response-one") + len(b"cached-response-two")
    assert after["bytes"] == len(b"changed-response-one") + len(b"cached-response-two")
    assert before["inventorySha256"] != after["inventorySha256"]
    assert before["pathRef"].startswith("artifacts/runs/")
    serialized = json.dumps(before)
    assert "entry-one.json" not in serialized
    assert "entry-two.json" not in serialized
    assert before["fileNamesRedacted"] is True


def test_directory_inventory_keeps_empty_and_over_budget_states_distinct(workspace_tmp_path: Path) -> None:
    empty = workspace_tmp_path / "empty-cache"
    empty.mkdir()
    empty_inventory = measure_directory_inventory(empty)
    (empty / "cache-entry").write_bytes(b"12345")
    over_budget = measure_directory_inventory(empty, max_bytes=4)

    assert empty_inventory["status"] == "observed"
    assert empty_inventory["fileCount"] == 0
    assert empty_inventory["bytes"] == 0
    assert over_budget == {
        "status": "exceeded",
        "observedBytesAtLeast": 5,
        "limitBytes": 4,
        "reason": "cache_inventory_byte_limit_exceeded",
        "fileNamesRedacted": True,
    }


def test_directory_inventory_rejects_paths_outside_ignored_run_root(workspace_tmp_path: Path) -> None:
    import tools.bef_resource_sampler as sampler

    outside = sampler.REPOSITORY_ROOT.parent / "outside-cache"
    assert measure_directory_inventory(outside) == {
        "status": "unknown", "reason": "cache_directory_outside_ignored_artifacts"
    }


def test_default_proxy_host_port_is_parsed_to_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEF_SOURCE_PROXY_HOST_PORT", "19544")
    assert _parse_args([]).source_proxy_port == 19_544


def test_observation_duration_cannot_exceed_manifest_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.bef_resource_sampler as sampler

    monkeypatch.setattr(
        sampler,
        "_load_guardrails",
        lambda: ({"maxTrialSeconds": 4}, {"manifestPath": "manifest.json", "manifestSha256": "0" * 64}),
    )
    monkeypatch.setattr(sampler, "_docker_host_info", lambda: pytest.fail("Docker must not be queried"))

    with pytest.raises(SamplerBlocked, match="duration_exceeds_manifest_observation_bound"):
        collect_resource_window(duration_seconds=4.01)


def _trial_sampler_setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, memory_values: list[int] | None = None):
    import tools.bef_resource_sampler as sampler

    repo = tmp_path / "repo"
    artifacts = repo / "artifacts" / "runs"
    artifacts.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", artifacts)
    monkeypatch.setattr(sampler, "_load_guardrails", lambda: ({
        "maxTrialSeconds": 2,
        "maxAnvilMemoryBytesEach": 1_000,
        "maxApiMemoryBytes": 1_000,
        "maxDatabaseMemoryBytes": 1_000,
        "maxSourceCallsPerTrial": 10,
        "maxEvidenceBytesPerTrial": 10_000,
        "maxAnvilCacheBytesEach": 250,
        "maxResourceReadOverrunSeconds": 1,
    }, {"manifestPath": "manifest.json", "manifestSha256": "a" * 64}))
    monkeypatch.setattr(sampler, "_docker_host_info", lambda: {"source": "test-docker", "cpuCount": 2})
    containers = [ContainerInfo(f"{index:064x}", service, "image:test", "running", 1_000, 100_000_000) for index, service in enumerate(sampler.SERVICES, 1)]
    monkeypatch.setattr(sampler, "_container_inventory", lambda: (containers, []))
    monkeypatch.setattr(sampler, "_read_service_key", lambda: "never-write-this-test-key")
    monkeypatch.setattr(sampler, "_inspect_anvil_cache_binding", lambda info: {
        "service": info.service, "status": "unconfigured", "reason": "anvil_cache_path_not_configured"
    })
    cache_sources = {
        "anvil-a": {"state": str(artifacts / "cache-a-state"), "rpc": str(artifacts / "cache-a-rpc")},
        "anvil-b": {"state": str(artifacts / "cache-b-state"), "rpc": str(artifacts / "cache-b-rpc")},
    }
    monkeypatch.setattr(sampler, "_compose_anvil_cache_sources", lambda: (cache_sources, "b" * 64))
    monkeypatch.setattr(
        sampler,
        "_inspect_anvil_cache_binding",
        lambda info, **kwargs: {"service": info.service, "status": "observed", "reason": None},
    )
    snapshot_index = count()
    memory_values = memory_values or [100, 200, 200]

    def snapshot(infos, *, source_proxy_port, service_key, artifact_path, cache_path):
        index = min(next(snapshot_index), len(memory_values) - 1)
        cpu_value = 10_000 + index * 1_000
        rows = []
        for info in infos:
            rows.append({
                "service": info.service,
                "containerId": info.container_id[:12],
                "state": "running",
                "cgroup": {
                    "status": "observed",
                    "cpuUsageNanoseconds": cpu_value,
                    "memoryCurrentBytes": memory_values[index],
                    "memoryPeakBytes": max(500, memory_values[index]),
                },
            })
        return {
            "containers": rows,
            "sourceProxy": {
                "status": "observed", "forwardedItems": index, "deniedItems": 0,
                "upstreamErrors": 0, "sourceCallsReserved": index,
            },
            "artifactDirectory": sampler._measure_tree(artifact_path),
            "cacheDirectory": sampler._measure_tree(cache_path),
        }

    monkeypatch.setattr(sampler, "_trial_resource_snapshot", snapshot)
    return sampler, artifacts


def test_bounded_trial_records_real_child_window_without_claiming_cache_or_gate(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    sampler, artifacts = _trial_sampler_setup(monkeypatch, workspace_tmp_path)
    evidence_dir = artifacts / "trial-one"
    probe = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": "BEF-SC-011",
        "status": "captured",
        "environment": {"envId": "bef-env-a", "generation": {"generationId": "gen-public-1"}},
        "operations": [{"operationId": "op-public-1"}],
    }
    code = "import json,pathlib,sys; (pathlib.Path(sys.argv[1])/'probe.json').write_text(json.dumps(" + repr(probe) + "))"
    report = run_bounded_trial_command(
        [sys.executable, "-c", code, str(evidence_dir)],
        artifact_path=evidence_dir,
        interval_seconds=0.1,
        timeout_seconds=1,
    )

    assert report["trialProcess"]["exitCode"] == 0
    assert report["trialProcess"]["probeEvidence"]["probeIndexSha256"]
    assert report["trialCorrelation"] == {
        "status": "observed", "generationId": "gen-public-1", "operationIds": ["op-public-1"]
    }
    assert report["containers"][0]["cpuUsageDeltaNanoseconds"] >= 1_000
    assert report["containers"][0]["memoryPeakScope"] == "since-container-cgroup-creation"
    assert report["cacheCondition"]["status"] == "unknown"
    assert report["sourceProxy"]["perTrialCalls"] is None
    assert report["gateStatus"] == "not_established_by_resource_trial_collector"
    assert report["status"] == "blocked"
    assert "never-write-this-test-key" not in json.dumps(report)


def test_bounded_trial_stops_owned_command_on_measured_limit_but_does_not_claim_generation_fence(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    _, artifacts = _trial_sampler_setup(monkeypatch, workspace_tmp_path, memory_values=[100, 1_001, 1_001])
    callback_events = []

    def stop_owned_process(process):
        process.kill()
        process.wait(timeout=2)
        return {"status": "test_owned_child_stopped", "directChildExited": True, "descendants": "unknown"}

    monkeypatch.setattr(sampler, "_terminate_owned_process_tree", stop_owned_process)
    report = run_bounded_trial_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        artifact_path=artifacts / "trial-over-limit",
        interval_seconds=0.1,
        timeout_seconds=1,
        on_fence=callback_events.append,
    )

    assert report["status"] == "guardrail_exceeded"
    assert report["guardrails"]["trigger"]["code"] == "postgres_memory"
    assert report["trialProcess"]["processTreeCleanup"]["directChildExited"] is True
    assert len(callback_events) == 1
    assert report["guardrails"]["generationFence"]["status"] == "callback_invoked_unverified"
    assert report["gateStatus"] == "not_established_by_resource_trial_collector"


def test_anvil_cache_classification_requires_explicit_path_and_task_owned_writable_mount(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    repo = workspace_tmp_path / "repo"
    cache_path = repo / "artifacts" / "runs" / "trial-cache"
    cache_path.mkdir(parents=True)
    rpc_cache_path = repo / "artifacts" / "runs" / "trial-rpc-cache"
    rpc_cache_path.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", repo / "artifacts" / "runs")
    cache_command = json.dumps(["--fork-url", "http://source-proxy:8545", "--cache-path", "/var/cache/anvil"])
    cache_mounts = json.dumps([
        {"Type": "bind", "Source": str(cache_path), "Destination": "/var/cache/anvil", "RW": True},
        {"Type": "bind", "Source": str(rpc_cache_path), "Destination": "/root/.foundry/cache", "RW": True},
    ])

    observed = parse_anvil_cache_binding(
        cache_command, cache_mounts, "2026-10-23T12:00:00Z", home_directory="/root"
    )
    unconfigured = parse_anvil_cache_binding(
        json.dumps(["--silent"]), "[]", "2026-10-23T12:00:00Z", home_directory="/root"
    )
    shared = parse_anvil_cache_binding(
        cache_command,
        json.dumps([
            {"Type": "bind", "Source": str(workspace_tmp_path / "shared-cache"), "Destination": "/var/cache/anvil", "RW": True},
            {"Type": "bind", "Source": str(workspace_tmp_path / "shared-rpc-cache"), "Destination": "/root/.foundry/cache", "RW": True},
        ]),
        "2026-10-23T12:00:00Z",
        home_directory="/root",
    )
    missing_fork_cache = parse_anvil_cache_binding(
        cache_command,
        json.dumps([{"Type": "bind", "Source": str(cache_path), "Destination": "/var/cache/anvil", "RW": True}]),
        "2026-10-23T12:00:00Z",
        home_directory="/root",
    )

    assert observed["status"] == "observed"
    assert observed["stateCacheHostPath"] == "artifacts/runs/trial-cache"
    assert observed["rpcCacheHostPath"] == "artifacts/runs/trial-rpc-cache"
    assert unconfigured == {
        "status": "unconfigured",
        "reason": "anvil_state_cache_path_not_configured",
        "stateCacheConfigured": False,
        "rpcCacheMountStatus": "missing",
    }
    assert shared["status"] == "unknown"
    assert shared["reason"] == "anvil_cache_mount_not_task_owned"
    assert missing_fork_cache["status"] == "unknown"
    assert missing_fork_cache["reason"] == "foundry_rpc_cache_bind_mount_missing"


def test_anvil_cache_mount_matches_docker_desktop_inspect_spelling_against_compose_path(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    repo = workspace_tmp_path / "repo"
    cache_path = repo / "artifacts" / "runs" / "trial-cache"
    cache_path.mkdir(parents=True)
    rpc_cache_path = repo / "artifacts" / "runs" / "trial-rpc-cache"
    rpc_cache_path.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", repo / "artifacts" / "runs")
    cache_command = json.dumps(["--cache-path", "/var/cache/anvil"])
    normalized = str(cache_path).replace("\\", "/")
    drive = normalized[0].lower()
    desktop_state = f"/run/desktop/mnt/host/{drive}/{normalized[3:]}"
    rpc_normalized = str(rpc_cache_path).replace("\\", "/")
    desktop_rpc = f"/run/desktop/mnt/host/{rpc_normalized[0].lower()}/{rpc_normalized[3:]}"
    mounts = json.dumps([
        {"Type": "bind", "Source": desktop_state, "Destination": "/var/cache/anvil", "RW": True},
        {"Type": "bind", "Source": desktop_rpc, "Destination": "/root/.foundry/cache", "RW": True},
    ])

    observed = parse_anvil_cache_binding(
        cache_command,
        mounts,
        "2026-10-23T12:00:00Z",
        home_directory="/root",
        expected_state_source=str(cache_path),
        expected_rpc_source=str(rpc_cache_path),
    )
    mismatched = parse_anvil_cache_binding(
        cache_command,
        mounts.replace("trial-cache", "other-cache"),
        "2026-10-23T12:00:00Z",
        home_directory="/root",
        expected_state_source=str(cache_path),
        expected_rpc_source=str(rpc_cache_path),
    )

    assert observed["status"] == "observed"
    assert observed["stateCacheHostPath"].endswith("trial-cache")
    assert mismatched == {"status": "unknown", "reason": "inspected_cache_mount_differs_from_compose_config"}


def test_anvil_cache_binding_uses_named_user_home_and_checks_actual_write_access(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path,
) -> None:
    import subprocess
    import tools.bef_resource_sampler as sampler

    repo = workspace_tmp_path / "repo"
    artifacts = repo / "artifacts" / "runs"
    state_path = artifacts / "trial-cache" / "state"
    rpc_path = artifacts / "trial-cache" / "foundry-cache"
    state_path.mkdir(parents=True)
    rpc_path.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", artifacts)
    command = json.dumps(["--cache-path", "/var/lib/anvil/state-cache"])
    mounts = json.dumps([
        {"Type": "bind", "Source": str(state_path), "Destination": "/var/lib/anvil/state-cache", "RW": True},
        {"Type": "bind", "Source": str(rpc_path), "Destination": "/root/.foundry/cache", "RW": True},
    ])
    inspect_output = "|".join((command, mounts, "2026-10-24T00:00:00Z", "foundry", json.dumps(["HOME=/root"])))
    monkeypatch.setattr(sampler, "_run_command", lambda *_args, **_kwargs: inspect_output)
    access_results = iter((0, 1))
    probed_targets: list[str] = []

    def run_probe(args, **kwargs):
        probed_targets.append(args[-1])
        return subprocess.CompletedProcess(args, next(access_results))

    monkeypatch.setattr(sampler.subprocess, "run", run_probe)
    info = sampler.ContainerInfo("a" * 64, "anvil-a", "foundry-image", "running", 1_000, 1_000)

    result = sampler._inspect_anvil_cache_binding(
        info,
        expected_sources={"state": str(state_path), "rpc": str(rpc_path)},
        compose_config_sha256="b" * 64,
    )

    assert probed_targets == ["/var/lib/anvil/state-cache", "/root/.foundry/cache"]
    assert result["stateCacheWritableByContainerUser"] is True
    assert result["rpcCacheWritableByContainerUser"] is False
    assert result["status"] == "unknown"
    assert result["reason"] == "foundry_rpc_cache_not_writable_by_container_user"
    assert sampler._container_home_directory(json.dumps([])) is None


def test_anvil_cache_binding_is_observed_only_when_both_targets_are_writable(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path,
) -> None:
    import subprocess
    import tools.bef_resource_sampler as sampler

    repo = workspace_tmp_path / "repo"
    artifacts = repo / "artifacts" / "runs"
    state_path = artifacts / "trial-cache" / "state"
    rpc_path = artifacts / "trial-cache" / "foundry-cache"
    state_path.mkdir(parents=True)
    rpc_path.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", artifacts)
    command = json.dumps(["--cache-path", "/var/lib/anvil/state-cache"])
    mounts = json.dumps([
        {"Type": "bind", "Source": str(state_path), "Destination": "/var/lib/anvil/state-cache", "RW": True},
        {"Type": "bind", "Source": str(rpc_path), "Destination": "/home/foundry/.foundry/cache", "RW": True},
    ])
    inspect_output = "|".join((command, mounts, "2026-10-24T00:00:00Z", "foundry", json.dumps(["HOME=/home/foundry"])))
    monkeypatch.setattr(sampler, "_run_command", lambda *_args, **_kwargs: inspect_output)
    probed_targets: list[str] = []

    def run_probe(args, **kwargs):
        probed_targets.append(args[-1])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(sampler.subprocess, "run", run_probe)
    info = sampler.ContainerInfo("a" * 64, "anvil-a", "foundry-image", "running", 1_000, 1_000)

    result = sampler._inspect_anvil_cache_binding(
        info,
        expected_sources={"state": str(state_path), "rpc": str(rpc_path)},
        compose_config_sha256="b" * 64,
    )

    assert probed_targets == ["/var/lib/anvil/state-cache", "/home/foundry/.foundry/cache"]
    assert result["stateCacheWritableByContainerUser"] is True
    assert result["rpcCacheWritableByContainerUser"] is True
    assert result["status"] == "observed"


def test_compose_cache_sources_must_be_expanded_explicit_bind_mounts_under_ignored_runs(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    repo = workspace_tmp_path / "repo"
    artifacts = repo / "artifacts" / "runs"
    artifacts.mkdir(parents=True)
    monkeypatch.setattr(sampler, "REPOSITORY_ROOT", repo)
    monkeypatch.setattr(sampler, "ARTIFACTS_ROOT", artifacts)
    config = {"services": {}}
    for name in ("anvil-a", "anvil-b"):
        config["services"][name] = {"environment": {"HOME": "/home/foundry"}, "volumes": [
            {"type": "bind", "source": str(artifacts / f"{name}-state"), "target": "/var/lib/anvil/state-cache", "bind": {"create_host_path": False}},
            {"type": "bind", "source": str(artifacts / f"{name}-rpc"), "target": "/home/foundry/.foundry/cache", "bind": {"create_host_path": False}},
        ]}
    monkeypatch.setattr(sampler, "_run_command", lambda command, **kwargs: json.dumps(config))

    sources, digest = sampler._compose_anvil_cache_sources()

    assert set(sources) == {"anvil-a", "anvil-b"}
    assert sources["anvil-a"]["state"].endswith("anvil-a-state")
    assert sources["anvil-a"]["rpc"].endswith("anvil-a-rpc")
    assert len(digest) == 64
    config["services"]["anvil-a"]["volumes"][0]["bind"]["create_host_path"] = True
    monkeypatch.setattr(sampler, "_run_command", lambda command, **kwargs: json.dumps(config))
    with pytest.raises(SamplerBlocked, match="compose_cache_bind_not_explicit_task_owned"):
        sampler._compose_anvil_cache_sources()

    config["services"]["anvil-a"]["volumes"][0]["bind"]["create_host_path"] = False
    config["services"]["anvil-a"]["environment"].pop("HOME")
    monkeypatch.setattr(sampler, "_run_command", lambda command, **kwargs: json.dumps(config))
    with pytest.raises(SamplerBlocked, match="compose_anvil_home_directory_unavailable"):
        sampler._compose_anvil_cache_sources()


def test_overrun_timer_starts_only_after_real_first_read_marker_and_fences_after_owned_stop(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    sampler, artifacts = _trial_sampler_setup(monkeypatch, workspace_tmp_path)
    evidence_dir = artifacts / "trial-overrun"
    marker_path = artifacts / "overrun-ready.json"
    release_path = artifacts / "overrun-release.json"
    report_path = artifacts / "fence-verification.json"
    generation_id = "123e4567-e89b-42d3-a456-426614174000"
    payer = "0xAa" + "12" * 19
    balances = {
        "blockNumber": "52982197",
        "payerNativeWei": "10000000000000000000",
        "payerWethUnits": "0",
        "payerUsdcUnits": "100000000",
        "recipientUsdcUnits": "100000000",
        "wethRouterAllowance": "0",
        "poolWethUnits": "2583319483055206054090",
        "poolUsdcUnits": "2491594720540",
        "poolLiquidity": "1018126055295016476",
        "poolSqrtPriceX96": "3875630849719270719639802",
    }
    http_observation = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": "guardrail_exceeded",
        "request": {"method": "GET", "path": "/tools/bef-env-a/balances", "headers": {}, "body": None},
        "response": {
            "status": 200,
            "headers": {},
            "body": {
                "boundary": "local-chain-readonly-proxy",
                "envId": "bef-env-a",
                "generationId": generation_id,
                "payer": payer.lower(),
                "balances": balances,
            },
        },
    }
    http_bytes = json.dumps(http_observation, separators=(",", ":")).encode()
    marker = {
        "schemaVersion": "bef-resource-workload-ready/v1",
        "phase": "guardrail_exceeded",
        "envId": "bef-env-a",
        "generationId": generation_id,
        "payerAddress": payer,
        "manifestSha256": "1" * 64,
        "applicationSourceSha256": "2" * 64,
        "probeSourceSha256": "3" * 64,
        "completedReadsBeforeDeadline": 1,
        "firstRead": {
            "status": 200,
            "responseIdentity": {
                "boundary": "local-chain-readonly-proxy",
                "envId": "bef-env-a",
                "generationId": generation_id,
                "payer": payer.lower(),
            },
            "artifact": {
                "path": "http/first-balance.json",
                "sha256": hashlib.sha256(http_bytes).hexdigest(),
                "contentType": "application/json",
                "boundary": "actual-tool-http",
            },
        },
    }
    marker_json = json.dumps(marker)
    child = (
        "import base64,json,pathlib,sys,time; "
        "http_path=pathlib.Path(sys.argv[4]); http_path.parent.mkdir(parents=True); "
        "http_path.write_bytes(base64.b64decode(sys.argv[5])); "
        "time.sleep(0.25); target=pathlib.Path(sys.argv[1]); temp=pathlib.Path(str(target)+'.pending'); "
        "temp.write_text(sys.argv[3]); temp.replace(target); "
        "release=pathlib.Path(sys.argv[2]); "
        "while_not_ready=True; "
        "exec('while not release.exists():\\n time.sleep(0.005)'); "
        "exec('while True:\\n time.sleep(0.005)')"
    )

    def stop_owned_process(process):
        process.kill()
        process.wait(timeout=2)
        return {"status": "test_owned_child_stopped", "directChildExited": True, "descendants": "unknown"}

    def fence_owned_generation(_violation):
        report_path.write_text("fence evidence")
        import hashlib
        return {
            "status": "captured",
            "exitCode": 0,
            "reportPath": str(report_path),
            "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "generationId": generation_id,
            "envId": "bef-env-a",
        }

    monkeypatch.setattr(sampler, "_terminate_owned_process_tree", stop_owned_process)
    report = run_bounded_trial_command(
        [sys.executable, "-c", child, str(marker_path), str(release_path), marker_json,
         str(evidence_dir / "http" / "first-balance.json"), base64.b64encode(http_bytes).decode("ascii")],
        artifact_path=evidence_dir,
        interval_seconds=0.1,
        timeout_seconds=1.8,
        readiness_marker=marker_path,
        readiness_release=release_path,
        active_limit_seconds=1,
        fence_generation=fence_owned_generation,
    )

    assert report["status"] == "guardrail_exceeded"
    assert report["trialProcess"]["readiness"]["status"] == "observed_first_successful_get"
    assert report["trialProcess"]["readiness"]["envId"] == "bef-env-a"
    assert report["trialProcess"]["readiness"]["generationId"] == generation_id
    assert report["guardrails"]["trigger"]["code"] == "max_resource_read_overrun_seconds"
    assert report["guardrails"]["trigger"]["observed"] > 1_000
    assert report["trialProcess"]["processTreeCleanup"]["directChildExited"] is True
    assert report["guardrails"]["generationFence"]["status"] == "fence_process_result_recorded"
    assert report["guardrails"]["generationFenceProcessResult"]["generationId"] == generation_id
    assert release_path.is_file()
    assert "never-write-this-test-key" not in json.dumps(report)


def test_readiness_marker_requires_actual_balance_schema_and_hash(workspace_tmp_path: Path) -> None:
    import tools.bef_resource_sampler as sampler

    artifact_root = workspace_tmp_path / "readiness-validation"
    evidence_root = artifact_root / "guardrail-read"
    http_root = evidence_root / "http"
    http_root.mkdir(parents=True)
    marker_path = evidence_root / "ready.json"
    http_path = http_root / "first-read.json"
    generation = "123e4567-e89b-42d3-a456-426614174000"
    payer = "0xAa" + "12" * 19
    balances = {
        "blockNumber": "52982197",
        "payerNativeWei": "10000000000000000000",
        "payerWethUnits": "0",
        "payerUsdcUnits": "100000000",
        "recipientUsdcUnits": "100000000",
        "wethRouterAllowance": "0",
        "poolWethUnits": "2583319483055206054090",
        "poolUsdcUnits": "2491594720540",
        "poolLiquidity": "1018126055295016476",
        "poolSqrtPriceX96": "3875630849719270719639802",
    }

    def load_case(snapshot: object, *, response_payer: str | None = None):
        observation = {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "actual-tool-http",
            "operationId": None,
            "variantId": "guardrail_exceeded",
            "request": {
                "method": "GET",
                "path": "/tools/bef-env-a/balances",
                "headers": {"X-BEF-Generation": generation},
                "body": None,
            },
            "response": {
                "status": 200,
                "headers": {},
                "body": {
                    "boundary": "local-chain-readonly-proxy",
                    "envId": "bef-env-a",
                    "generationId": generation,
                    "payer": response_payer if response_payer is not None else payer.lower(),
                    "balances": snapshot,
                },
            },
        }
        http_bytes = json.dumps(observation, separators=(",", ":")).encode()
        http_path.write_bytes(http_bytes)
        marker = {
            "schemaVersion": "bef-resource-workload-ready/v1",
            "phase": "guardrail_exceeded",
            "envId": "bef-env-a",
            "generationId": generation,
            "payerAddress": payer,
            "manifestSha256": "1" * 64,
            "applicationSourceSha256": "2" * 64,
            "probeSourceSha256": "3" * 64,
            "completedReadsBeforeDeadline": 1,
            "firstRead": {
                "status": 200,
                "responseIdentity": {
                    "boundary": "local-chain-readonly-proxy",
                    "envId": "bef-env-a",
                    "generationId": generation,
                    "payer": payer.lower(),
                },
                "artifact": {
                    "path": "http/first-read.json",
                    "sha256": hashlib.sha256(http_bytes).hexdigest(),
                    "contentType": "application/json",
                    "boundary": "actual-tool-http",
                },
            },
        }
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
        return sampler._load_readiness_marker(
            marker_path, artifact_root=artifact_root, evidence_root=evidence_root,
        )

    accepted, error = load_case(balances)
    assert error is None
    assert accepted is not None
    assert accepted["generationId"] == generation

    invalid_snapshots = [
        [],
        {**balances, "extra": "0"},
        {**balances, "poolLiquidity": 1},
        {key: value for key, value in balances.items() if key != "blockNumber"},
    ]
    for invalid_snapshot in invalid_snapshots:
        rejected, error = load_case(invalid_snapshot)
        assert rejected is None
        assert error == "readiness_marker_http_artifact_not_actual_matching_read"

    rejected, error = load_case(balances, response_payer="0xBb" + "12" * 19)
    assert rejected is None
    assert error == "readiness_marker_http_artifact_not_actual_matching_read"

    load_case(balances)
    http_path.write_bytes(http_path.read_bytes() + b" ")
    rejected, error = sampler._load_readiness_marker(
        marker_path, artifact_root=artifact_root, evidence_root=evidence_root,
    )
    assert rejected is None
    assert error == "readiness_marker_http_artifact_hash_mismatch"


def test_per_mount_cache_byte_bound_stops_only_owned_child_and_calls_fence(
    monkeypatch: pytest.MonkeyPatch, workspace_tmp_path: Path
) -> None:
    import tools.bef_resource_sampler as sampler

    sampler, artifacts = _trial_sampler_setup(monkeypatch, workspace_tmp_path)
    evidence_dir = artifacts / "trial-cache-bound"
    cache_path = artifacts / "cache-state"
    cache_path.mkdir()
    captured_violations = []
    child = (
        "import pathlib,sys,time; "
        "pathlib.Path(sys.argv[1]).write_bytes(b'x'*251); "
        "exec('while True:\\n time.sleep(0.005)')"
    )

    def stop_owned_process(process):
        process.kill()
        process.wait(timeout=2)
        return {"status": "test_owned_child_stopped", "directChildExited": True, "descendants": "unknown"}

    def fence_owned_generation(violation):
        captured_violations.append(violation)
        return {"status": "captured", "exitCode": 0, "generationId": "123e4567-e89b-42d3-a456-426614174000", "envId": "bef-env-a"}

    monkeypatch.setattr(sampler, "_terminate_owned_process_tree", stop_owned_process)
    report = run_bounded_trial_command(
        [sys.executable, "-c", child, str(cache_path / "state.bin")],
        artifact_path=evidence_dir,
        cache_paths={"anvil-a-state": cache_path},
        interval_seconds=0.1,
        timeout_seconds=1.8,
        fence_generation=fence_owned_generation,
    )

    assert report["status"] == "guardrail_exceeded"
    assert report["guardrails"]["trigger"] == {
        "code": "anvil-a-state_cache_bytes", "observed": 251, "limit": 250, "unit": "bytes"
    }
    assert report["trialProcess"]["processTreeCleanup"]["directChildExited"] is True
    assert report["cacheDirectories"]["anvil-a-state"]["guardrailCheck"]["status"] == "exceeded"
    assert [violation.observed for violation in captured_violations] == [251]


def test_windows_trial_cleanup_targets_only_the_owned_process_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    import tools.bef_resource_sampler as sampler

    calls = []

    class OwnedProcess:
        pid = 48123
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def wait(self, timeout):
            assert timeout == 5.0
            self.exited = True
            return 0

    monkeypatch.setattr(sampler.os, "name", "nt")
    monkeypatch.setattr(
        sampler.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or SimpleNamespace(returncode=0),
    )

    cleanup = sampler._terminate_owned_process_tree(OwnedProcess())

    assert calls[0][0] == ["taskkill", "/PID", "48123", "/T", "/F"]
    assert calls[0][1]["timeout"] == 5.0
    assert cleanup == {
        "status": "stopped",
        "directChildExited": True,
        "descendants": "stopped",
        "treeExitConfirmed": True,
    }


@pytest.mark.skipif(os.name == "nt" or not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_posix_trial_cleanup_stops_inherited_group_child_without_killing_owner() -> None:
    import tools.bef_resource_sampler as sampler

    owner_group = os.getpgrp()
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        close_fds=True,
    )
    try:
        assert os.getpgid(process.pid) == owner_group
        cleanup = sampler._terminate_owned_process_tree(process, grace_seconds=0.2)
        assert cleanup == {
            "status": "direct_child_tree_stopped",
            "directChildExited": True,
            "descendants": "stopped",
            "treeExitConfirmed": True,
        }
        assert os.getpgrp() == owner_group
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


@pytest.mark.skipif(os.name == "nt" or not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_posix_trial_cleanup_does_not_claim_tree_stop_when_child_has_descendant() -> None:
    import tools.bef_resource_sampler as sampler

    child_code = """import subprocess,sys,threading,time
ready=threading.Event()
release=threading.Event()
def spawn_from_worker_thread():
    child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print(child.pid,flush=True)
    ready.set()
    release.wait()
thread=threading.Thread(target=spawn_from_worker_thread)
thread.start()
ready.wait()
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        shell=False,
        close_fds=True,
    )
    descendant_pid = None
    try:
        assert process.stdout is not None
        descendant_pid = int(process.stdout.readline().strip())
        cleanup = sampler._terminate_owned_process_tree(process, grace_seconds=0.2)
        assert cleanup["directChildExited"] is True
        assert cleanup["descendants"] == "unknown"
        assert cleanup["treeExitConfirmed"] is False
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        if descendant_pid is not None:
            try:
                os.kill(descendant_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
