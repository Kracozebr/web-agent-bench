"""Offline tests for raw SC-011 evidence predicates and recovery bounds."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest


from tests.bdd.adapters import sc011_resource_evidence as adapter
from tests.bdd.adapters.benchmark_environment_feasibility import ProbeEvidence


GUARDRAILS = {
    "maxTrialSeconds": 120,
    "maxAnvilMemoryBytesEach": 1_000,
    "maxApiMemoryBytes": 1_000,
    "maxDatabaseMemoryBytes": 1_000,
    "maxSourceCallsPerTrial": 50,
    "maxEvidenceBytesPerTrial": 1_000_000,
    "maxAnvilCacheBytesEach": 500,
    "maxResourceReadOverrunSeconds": 2,
    "maxResourceScenarioSeconds": 900,
}
BALANCE_SNAPSHOT = {
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


def test_secret_filter_accepts_only_digest_shaped_authorization_metadata() -> None:
    assert adapter._secret_free({"headers": {"authorization-sha256": "a" * 64}})
    assert not adapter._secret_free({"headers": {"authorization-sha256": "not-a-digest"}})
    assert not adapter._secret_free({"headers": {"authorization": "Bearer must-not-be-retained"}})


def test_secret_filter_allows_only_hex_digest_for_decoded_payload_signature() -> None:
    actual_shape = {"request": {"decodedPaymentPayload": {"payloadSignatureSha256": "a" * 64}}}
    assert adapter._secret_free(actual_shape)
    assert not adapter._secret_free({
        "request": {"decodedPaymentPayload": {"payloadSignatureSha256": "a" * 63}}
    })
    assert not adapter._secret_free({
        "request": {"decodedPaymentPayload": {"payloadSignatureSha256": "g" * 64}}
    })
    assert not adapter._secret_free({
        "request": {"decodedPaymentPayload": {"payloadSignature": "0x" + "a" * 130}}
    })


def _resource_sample() -> dict:
    services = ("postgres", "source-proxy", "anvil-a", "anvil-b", "local-proxy-a", "local-proxy-b", "facilitator-a", "facilitator-b", "api", "gateway")
    containers = []
    for service in services:
        row = {
            "service": service,
            "cgroupStatus": "observed",
            "cpuUsageStatus": "observed",
            "cpuUsageDeltaNanoseconds": 1_000_000,
            "cpuLimitCheck": {"status": "compatible"},
        }
        if service in {"postgres", "anvil-a", "anvil-b", "api"}:
            limit = GUARDRAILS["maxDatabaseMemoryBytes" if service == "postgres" else "maxApiMemoryBytes" if service == "api" else "maxAnvilMemoryBytesEach"]
            row.update({
                "memoryCurrentWindowMaximumBytes": 400,
                "memoryPeakBytesSinceContainerStart": 450,
                "memoryPeakScope": "since-container-cgroup-creation",
                "memoryCurrentWindowSampleCount": 4,
                "memoryLimitCheck": {"status": "within_limit", "observedBytes": 400, "limitBytes": limit},
                "dockerConfiguredMemoryLimitMatchesPolicy": True,
                "policyMemoryLimitBytes": limit,
                "cgroupMemoryLimitBytes": limit,
            })
        containers.append(row)
    return {
        "schemaVersion": adapter.SAMPLER_SCHEMA,
        "scenarioId": adapter.SCENARIO_ID,
        "status": "captured",
        "elapsedMonotonicNanoseconds": 2_000_000_000,
        "host": {"status": "observed", "operatingSystem": "Docker Desktop", "architecture": "x86_64"},
        "manifest": {"manifestPath": adapter.SAMPLER_MANIFEST_PATH, "manifestSha256": "f" * 64},
        "guardrails": {"manifestValues": {
            key: value for key, value in GUARDRAILS.items() if key != "maxResourceScenarioSeconds"
        }},
        "containers": containers,
        "sourceProxy": {
            "counterScope": "aggregate_proxy_process",
            "start": {"status": "observed", "sourceCallsReserved": 10},
            "end": {"status": "observed", "sourceCallsReserved": 13},
            "windowDelta": {"status": "observed", "sourceCallsReserved": 3},
            "perTrialCalls": None,
            "providerComputeUnits": "unknown",
        },
        "artifactDirectory": {
            "guardrailCheck": {"status": "within_limit", "observedMaximumBytes": 1_200, "limitBytes": GUARDRAILS["maxEvidenceBytesPerTrial"]},
        },
        "cacheDirectories": {
            name: {"maximumObservedBytes": 100, "byteLimit": GUARDRAILS["maxAnvilCacheBytesEach"], "guardrailCheck": {"status": "within_limit"}}
            for name in ("anvil-a-state", "anvil-a-rpc")
        },
    }


@dataclass(frozen=True)
class Artifact:
    relative_path: str
    sha256: str
    boundary: str
    payload: dict


class Evidence:
    def __init__(self, directory: Path, artifacts: list[Artifact]):
        self.directory = directory
        self.artifacts = tuple(artifacts)
        self.manifest = {"guardrails": GUARDRAILS}
        self.index = {"operations": []}

    def resource_artifacts(self):
        return tuple(item for item in self.artifacts if item.boundary == "resource-data")

    def database_artifacts(self):
        return tuple(item for item in self.artifacts if item.boundary == "readonly-database")

    def rpc_artifacts(self, endpoint_boundary=None):
        values = tuple(item for item in self.artifacts if item.boundary in {"source-readonly-proxy", "local-chain-readonly-proxy"})
        return tuple(item for item in values if item.payload.get("endpointBoundary") == endpoint_boundary) if endpoint_boundary else values

    def http_events(self, *, variant_id=None):
        values = tuple(item for item in self.artifacts if item.boundary in {"actual-tool-http", "private-admin-http"})
        return tuple(item for item in values if variant_id is None or item.payload.get("variantId") == variant_id)

    def variants_are_exact(self, expected):
        actual = {
            item.payload["variantId"] for item in self.artifacts
            if isinstance(item.payload.get("variantId"), str)
        }
        return actual == set(expected)


def _write_json(path: Path, value: object) -> bytes:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def test_raw_sample_requires_real_monotonic_counters_cpu_and_cgroup_peak() -> None:
    sample = _resource_sample()
    assert adapter._sample_metrics_valid(sample, GUARDRAILS, "f" * 64)

    sample["manifest"]["manifestSha256"] = "0" * 64
    assert not adapter._sample_metrics_valid(sample, GUARDRAILS, "f" * 64)
    sample = _resource_sample()
    sample["guardrails"]["manifestValues"]["maxResourceScenarioSeconds"] = 900
    assert not adapter._sample_metrics_valid(sample, GUARDRAILS, "f" * 64)
    sample = _resource_sample()
    sample["sourceProxy"]["end"]["sourceCallsReserved"] = 9
    assert not adapter._sample_metrics_valid(sample, GUARDRAILS, "f" * 64)


def test_sample_reference_is_reloaded_from_hash_bound_raw_file(tmp_path: Path) -> None:
    sample = _resource_sample()
    raw = _write_json(tmp_path / "cold-purchase" / "resource-sampler.json", sample)
    digest = hashlib.sha256(raw).hexdigest()
    wrapper = {
        "schemaVersion": adapter.OBSERVATION_SCHEMA,
        "boundary": "resource-data",
        "scenarioId": adapter.SCENARIO_ID,
        "variantId": "empty_dedicated_cache",
        "operationId": "purchase-cold",
        "sampleArtifact": {"path": "cold-purchase/resource-sampler.json", "sha256": digest},
        "rawSampleSchemaVersion": adapter.SAMPLER_SCHEMA,
    }
    evidence = Evidence(tmp_path, [Artifact("resource-observations/cold.json", "1" * 64, "resource-data", wrapper)])

    selected = adapter._sample_for(evidence, "empty_dedicated_cache")
    assert selected is not None and selected[1] == sample

    _write_json(tmp_path / "cold-purchase" / "resource-sampler.json", dict(sample, status="blocked"))
    assert adapter._sample_for(evidence, "empty_dedicated_cache") is None

    sample = _resource_sample()
    sample["containers"][0]["memoryPeakBytesSinceContainerStart"] = 399
    assert not adapter._sample_metrics_valid(sample, GUARDRAILS, "f" * 64)


def test_blocked_sampler_metadata_requires_each_independent_proof() -> None:
    sample = _resource_sample()
    sample["status"] = "blocked"
    sample["gateStatus"] = "not_established_by_resource_trial_collector"
    sample["issues"] = [{"code": code} for code in sorted(adapter._UNRESOLVED_SAMPLER_METADATA)]
    proofs = {
        "cache_provenance": True,
        "source_count": True,
        "guardrail_stop": True,
        "provider_cu_unknown": True,
    }

    assert adapter._blocked_sampler_metadata_is_independently_proven(sample, **proofs)
    for proof_name in proofs:
        assert not adapter._blocked_sampler_metadata_is_independently_proven(
            sample,
            **{**proofs, proof_name: False},
        )


def test_raw_progress_hashes_each_generation_bound_read_and_keeps_null_operation_id(tmp_path: Path) -> None:
    generation = "b7d73b37-2b34-48df-870f-f29a7f2ca115"
    payer = "0xAa" + "12" * 19
    observation = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": "guardrail_exceeded",
        "request": {"method": "GET", "path": "/tools/bef-env-a/balances"},
        "response": {"status": 200, "body": {
            "boundary": "local-chain-readonly-proxy",
            "envId": "bef-env-a",
            "generationId": generation,
            "payer": payer.lower(),
            "balances": BALANCE_SNAPSHOT,
        }},
    }
    observation_path = tmp_path / "guardrail-read" / "http" / "0001-read.json"
    observation_raw = _write_json(observation_path, observation)
    observation_sha = hashlib.sha256(observation_raw).hexdigest()
    row = {
        "schemaVersion": "bef-resource-read-progress/v1",
        "envId": "bef-env-a",
        "generationId": generation,
        "variantId": "guardrail_exceeded",
        "sequence": 1,
        "observationId": "read-1",
        "status": 200,
        "artifact": {
            "path": "http/0001-read.json",
            "sha256": observation_sha,
            "contentType": "application/json",
            "boundary": "actual-tool-http",
        },
    }
    progress_raw = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    progress_path = tmp_path / "guardrail-read" / "read-progress.ndjson"
    progress_path.write_bytes(progress_raw)
    digest = hashlib.sha256(progress_raw).hexdigest()
    envelope = {
        "schemaVersion": adapter.OBSERVATION_SCHEMA,
        "boundary": "resource-data",
        "variantId": "guardrail_exceeded",
        "readProgress": {
            "path": "guardrail-read/read-progress.ndjson",
            "sha256": digest,
            "lineCount": 1,
            "firstSequence": 1,
            "lastSequence": 1,
            "httpArtifacts": [{"path": "guardrail-read/http/0001-read.json", "sha256": observation_sha}],
        },
    }
    evidence = Evidence(tmp_path, [
        Artifact("resource-observations/guardrail-read-progress.json", "0" * 64, "resource-data", envelope),
        Artifact("resource-observations/guardrail_exceeded.json", "1" * 64, "resource-data", {
            **envelope,
            "readProgress": {"path": "guardrail-read/read-progress.ndjson", "sha256": digest, "lineCount": 1},
        }),
        Artifact("guardrail-read/http/0001-read.json", observation_sha, "actual-tool-http", observation),
    ])
    assert adapter._read_progress_is_raw_and_generation_bound(evidence, generation, payer)

    progress_path.write_bytes(progress_raw + b" ")
    assert not adapter._read_progress_is_raw_and_generation_bound(evidence, generation, payer)


def test_readiness_get_is_raw_hash_indexed_and_generation_bound() -> None:
    generation = "b7d73b37-2b34-48df-870f-f29a7f2ca115"
    payer = "0xAa" + "12" * 19
    payload = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": "guardrail_exceeded",
        "request": {
            "method": "GET",
            "path": "/tools/bef-env-a/balances",
            "headers": {"X-BEF-Generation": generation},
        },
        "response": {"status": 200, "body": {
            "boundary": "local-chain-readonly-proxy",
            "envId": "bef-env-a",
            "generationId": generation,
            "payer": payer.lower(),
            "balances": BALANCE_SNAPSHOT,
        }},
    }
    digest = "a" * 64
    evidence = Evidence(Path("."), [Artifact(
        "guardrail-read/http/0001-readiness.json", digest, "actual-tool-http", payload,
    )])
    ready = {
        "firstRead": {
            "status": 200,
            "observationId": "sc011-guardrail-read-before-deadline",
            "responseIdentity": {
                "boundary": "local-chain-readonly-proxy",
                "envId": "bef-env-a",
                "generationId": generation,
                "payer": payer,
            },
            "artifact": {
                "path": "http/0001-readiness.json",
                "sha256": digest,
                "contentType": "application/json",
                "boundary": "actual-tool-http",
            },
        },
        "completedReadsBeforeDeadline": 1,
    }
    assert adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)

    payload["response"]["body"]["balances"] = []
    assert not adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)
    payload["response"]["body"]["balances"] = {**BALANCE_SNAPSHOT, "extra": "0"}
    assert not adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)
    payload["response"]["body"]["balances"] = {**BALANCE_SNAPSHOT, "payerUsdcUnits": 100}
    assert not adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)
    payload["response"]["body"]["balances"] = BALANCE_SNAPSHOT
    payload["response"]["body"]["payer"] = "0xBb" + "12" * 19
    assert not adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)
    payload["response"]["body"]["payer"] = payer.lower()
    payload["operationId"] = "unexpected-operation"
    assert not adapter._readiness_get_is_raw_and_generation_bound(evidence, ready, generation, "bef-env-a", payer)


def test_guardrail_fence_lookup_uses_direct_fence_mode_output_path(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    identity = {"generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115", "envId": "bef-env-a"}

    def indexed_payload(_evidence: Any, path: str) -> dict[str, Any] | None:
        calls.append(path)
        return identity if path == "guardrail-read/identity.json" else None

    monkeypatch.setattr(adapter, "_indexed_payload", indexed_payload)
    assert not adapter._raw_guardrail_no_effects(object(), {})
    assert calls == [
        "guardrail-read/identity.json",
        "guardrail-fence-active/fence-verification.json",
    ]


def test_guardrail_overrun_units_and_active_bound_are_independently_checked() -> None:
    trigger = {
        "code": "max_resource_read_overrun_seconds",
        "limit": 2_000,
        "observed": 2_469,
        "unit": "milliseconds",
    }
    active_bound = {
        "status": "exceeded",
        "limitSeconds": 2,
        "observedNanoseconds": 2_469_000_000,
    }

    assert adapter._read_overrun_trigger_matches(trigger, 2)
    assert adapter._active_bound_exceeded(active_bound, 2)
    assert not adapter._read_overrun_trigger_matches({**trigger, "limit": 2}, 2)
    assert not adapter._read_overrun_trigger_matches({**trigger, "unit": "seconds"}, 2)
    assert not adapter._read_overrun_trigger_matches({**trigger, "observed": 2_000}, 2)
    assert not adapter._read_overrun_trigger_matches({**trigger, "observed": float("inf")}, 2)
    assert not adapter._active_bound_exceeded({**active_bound, "observedNanoseconds": 2_000_000_000}, 2)
    assert not adapter._active_bound_exceeded({**active_bound, "observedNanoseconds": True}, 2)


_CACHE_TEST_ROOTS = {
    "anvil-a-state": "artifacts/runs/sc011-cache-test/cache-a/state",
    "anvil-a-rpc": "artifacts/runs/sc011-cache-test/cache-a/foundry-cache",
}


def _cache_inventory(cache_name: str, files: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "observed",
        "pathRef": _CACHE_TEST_ROOTS[cache_name],
        "bytes": sum(row["sizeBytes"] for row in files),
        "fileCount": len(files),
        "files": files,
    }


def _valid_cache_restart_orchestration() -> dict[str, Any]:
    cache_names = {"anvil-a-state", "anvil-a-rpc"}
    roots = dict(_CACHE_TEST_ROOTS)
    compose_sha = "f" * 64
    cold_id, warm_id = "1" * 64, "2" * 64
    empty = {name: _cache_inventory(name, []) for name in cache_names}
    cold_entry = {"fileKey": "a" * 64, "sha256": "b" * 64, "sizeBytes": 80}
    prepared_entry = {"fileKey": "c" * 64, "sha256": "d" * 64, "sizeBytes": 100}
    new_entry = {"fileKey": "e" * 64, "sha256": "f" * 64, "sizeBytes": 20}
    warm_changed_entry = {"fileKey": "c" * 64, "sha256": "1" * 64, "sizeBytes": 120}
    prepared = {
        "anvil-a-state": _cache_inventory("anvil-a-state", []),
        "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [prepared_entry]),
    }
    after_restart = {
        "anvil-a-state": _cache_inventory("anvil-a-state", []),
        "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [prepared_entry, new_entry]),
    }
    warm_after_purchase = {
        "anvil-a-state": _cache_inventory("anvil-a-state", []),
        "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [warm_changed_entry, new_entry]),
    }
    warm_restart_diff = adapter._cache_inventory_diff(
        prepared, after_restart, maximum_bytes=500, expected_cache_paths=roots,
    )
    purchase_diff = adapter._cache_inventory_diff(
        after_restart, warm_after_purchase, maximum_bytes=500, expected_cache_paths=roots,
    )

    def binding(container_id: str) -> dict[str, Any]:
        return {
            "containerId": container_id,
            "state": "running",
            "composeConfigSha256": compose_sha,
            "sources": {"state": roots["anvil-a-state"], "rpc": roots["anvil-a-rpc"]},
            "binding": {
                "status": "observed",
                "bindMountWritable": True,
                "stateCacheHostPath": roots["anvil-a-state"],
                "rpcCacheHostPath": roots["anvil-a-rpc"],
            },
        }

    return {
        "expandedComposeSha256": compose_sha,
        "warmComposeConfigSha256": compose_sha,
        "cacheRoots": roots,
        "coldAnvil": binding(cold_id),
        "warmAnvil": binding(warm_id),
        "anvilABeforeWarmStop": {"containerId": cold_id, "state": "running"},
        "anvilAAfterWarmStop": {"containerId": cold_id, "state": "exited"},
        "anvilAWarmStopOutcome": {
            "status": "observed",
            "containerId": cold_id,
            "state": "exited",
            "exitCode": 0,
            "oomKilled": False,
            "errorEmpty": True,
            "gracefulStopVerified": True,
        },
        "cacheCondition": {
            "status": "observed",
            "warm": {
                "sameBindRoots": True,
                "cacheSnapshotTakenAfterColdCleanupAndGracefulStop": True,
                "combinedPreparedCacheWasNonempty": True,
                "preparedEntriesRetainedAcrossRestart": True,
                "warmPurchaseCacheMutationsRecordedWithoutRetentionGate": True,
                "anvilProcessRecreated": True,
            },
        },
        "coldCacheBeforeWorkload": empty,
        "coldTrial": {"cacheAfter": {
            "anvil-a-state": _cache_inventory("anvil-a-state", []),
            "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [cold_entry]),
        }},
        "coldCacheAfterFence": {
            "anvil-a-state": _cache_inventory("anvil-a-state", []),
            "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [cold_entry]),
        },
        "warmCacheBeforeGracefulStop": {
            "anvil-a-state": _cache_inventory("anvil-a-state", []),
            "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [cold_entry]),
        },
        "warmCachePreparedAfterGracefulStop": prepared,
        "warmCachePreparedSummary": {
            "status": "observed", "cacheDirectoryCount": 2, "fileCount": 1, "bytes": 100, "hasEntries": True,
        },
        "warmCacheAfterRestart": after_restart,
        "warmCacheBeforeWorkload": after_restart,
        "warmCacheRestartDiff": warm_restart_diff,
        "warmTrial": {
            "cacheBefore": after_restart,
            "cacheAfter": warm_after_purchase,
            "cacheDiff": purchase_diff,
        },
        "warmCacheDuringPurchaseDiff": purchase_diff,
    }


def test_cache_restart_provenance_uses_nonempty_prepared_snapshot_and_allows_warm_churn() -> None:
    orchestration = _valid_cache_restart_orchestration()

    assert adapter._cache_restart_provenance_valid(orchestration, 500)


def test_cache_restart_provenance_rejects_zero_byte_prepared_placeholder() -> None:
    orchestration = _valid_cache_restart_orchestration()
    zero_placeholder = {"fileKey": "c" * 64, "sha256": "d" * 64, "sizeBytes": 0}
    prepared = {
        "anvil-a-state": _cache_inventory("anvil-a-state", []),
        "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [zero_placeholder]),
    }
    orchestration["warmCachePreparedAfterGracefulStop"] = prepared
    orchestration["warmCachePreparedSummary"] = {
        "status": "observed", "cacheDirectoryCount": 2, "fileCount": 1, "bytes": 0, "hasEntries": False,
    }
    orchestration["warmCacheAfterRestart"] = prepared
    orchestration["warmCacheBeforeWorkload"] = prepared
    orchestration["warmTrial"]["cacheBefore"] = prepared
    restart_diff = adapter._cache_inventory_diff(
        prepared, prepared, maximum_bytes=500, expected_cache_paths=orchestration["cacheRoots"],
    )
    orchestration["warmCacheRestartDiff"] = restart_diff

    assert not adapter._cache_restart_provenance_valid(orchestration, 500)


def test_cache_restart_provenance_requires_exact_prepared_entries_after_restart() -> None:
    orchestration = _valid_cache_restart_orchestration()
    changed = {
        "anvil-a-state": _cache_inventory("anvil-a-state", []),
        "anvil-a-rpc": _cache_inventory("anvil-a-rpc", [{"fileKey": "c" * 64, "sha256": "9" * 64, "sizeBytes": 100}]),
    }
    orchestration["warmCacheAfterRestart"] = changed
    orchestration["warmCacheBeforeWorkload"] = changed
    orchestration["warmTrial"]["cacheBefore"] = changed
    orchestration["warmTrial"]["cacheAfter"] = changed
    restart_diff = adapter._cache_inventory_diff(
        orchestration["warmCachePreparedAfterGracefulStop"], changed,
        maximum_bytes=500, expected_cache_paths=orchestration["cacheRoots"],
    )
    orchestration["warmCacheRestartDiff"] = restart_diff
    orchestration["warmTrial"]["cacheDiff"] = adapter._cache_inventory_diff(
        changed, changed, maximum_bytes=500, expected_cache_paths=orchestration["cacheRoots"],
    )
    orchestration["warmCacheDuringPurchaseDiff"] = orchestration["warmTrial"]["cacheDiff"]

    assert not adapter._cache_restart_provenance_valid(orchestration, 500)


def test_cache_restart_provenance_rejects_boolean_exit_code() -> None:
    orchestration = _valid_cache_restart_orchestration()
    orchestration["anvilAWarmStopOutcome"]["exitCode"] = False

    assert not adapter._cache_restart_provenance_valid(orchestration, 500)


def test_cache_restart_provenance_binds_each_snapshot_to_its_expected_mount() -> None:
    orchestration = _valid_cache_restart_orchestration()
    orchestration["warmCachePreparedAfterGracefulStop"]["anvil-a-rpc"]["pathRef"] = orchestration["cacheRoots"]["anvil-a-state"]

    assert not adapter._cache_restart_provenance_valid(orchestration, 500)


def test_operation_inventory_comes_only_from_two_actual_purchases_and_read_loop_is_null(tmp_path: Path) -> None:
    payer = "0x" + "12" * 20
    asset = "0x" + "11" * 20
    pay_to = "0x" + "22" * 20
    resource_id = "bef-resource"

    def workload(phase: str, operation_id: str) -> tuple[dict, dict, list[Artifact]]:
        generation_id = f"generation-{phase}"
        participant_id = f"participant-{phase}"
        transaction_hash = "0x" + ("a" if phase == "cold" else "b") * 64
        operation = {
            "operationId": operation_id,
            "kind": "purchase",
            "idempotencyKeyHash": ("c" if phase == "cold" else "d") * 64,
            "observedStatus": "settled",
            "transactionHash": transaction_hash,
            "receiptStatus": "success",
        }
        references: list[dict] = []
        raw_artifacts: list[Artifact] = []
        resource_bytes = b"sample-resource"
        resource_sha = hashlib.sha256(resource_bytes).hexdigest()
        resource_b64 = base64.b64encode(resource_bytes).decode()

        def add(path: str, boundary: str, payload: dict) -> None:
            relative_path = f"{phase}-purchase/{path}"
            digest = hashlib.sha256(relative_path.encode()).hexdigest()
            references.append({"path": path, "sha256": digest, "contentType": "application/json", "boundary": boundary})
            raw_artifacts.append(Artifact(relative_path, digest, boundary, payload))

        add("http/0001-probe-capabilities.json", "private-admin-http", {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "private-admin-http",
            "operationId": None,
            "variantId": None,
            "request": {"method": "GET", "path": "/internal/admin/environments/bef-env-a/probe-capabilities"},
            "response": {"status": 200, "body": {"services": {"facilitator": {"address": pay_to}}}},
        })

        response_body = {
            "operationId": operation_id,
            "resourceId": resource_id,
            "contentType": "application/json",
            "contentHash": resource_sha,
            "contentBytes": resource_b64,
        }
        add("http/0001-purchase.json", "actual-tool-http", {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "actual-tool-http",
            "operationId": operation_id,
            "variantId": None,
            "request": {
                "method": "POST",
                "path": "/tools/bef-env-a/purchase",
                "headers": {"X-BEF-Generation": generation_id},
                "body": {"resourceId": resource_id},
            },
            "response": {
                "status": 200,
                "body": response_body,
                "bodyBase64": base64.b64encode(json.dumps(response_body).encode()).decode(),
            },
        })
        rows_by_query = {
            "generation-by-id": [{
                "generation_id": generation_id,
                "env_id": "bef-env-a",
                "participant_id": participant_id,
                "payer_address": payer,
                "status": "active",
            }],
            "operation-by-id": [{
                "operation_id": operation_id,
                "env_id": "bef-env-a",
                "generation_id": generation_id,
                "participant_id": participant_id,
                "operation_kind": "purchase",
                "status": "settled",
                "transaction_hash": transaction_hash,
                "receipt_status": "success",
            }],
            "payments-by-operation": [{
                "operation_id": operation_id,
                "env_id": "bef-env-a",
                "generation_id": generation_id,
                "payer_address": payer,
                "network": "eip155:31337",
                "asset_address": asset,
                "amount_units": "100000",
                "facilitator_address": pay_to,
                "transaction_hash": transaction_hash,
                "receipt_status": "success",
            }],
            "deliveries-by-operation": [{
                "operation_id": operation_id,
                "resource_id": resource_id,
                "content_sha256": resource_sha,
                "content_bytes": str(len(resource_bytes)),
            }],
            "denials-by-generation": [],
            "x402-observations-by-operation": [],
        }
        add("db/pre-challenge-operation-by-id.json", "readonly-database", {
            "schemaVersion": "bef-db-observation/v1",
            "boundary": "readonly-database",
            "operationId": operation_id,
            "variantId": None,
            "readOnly": True,
            "databaseRole": "bef_readonly_observer",
            "transactionReadOnly": "on",
            "envId": "bef-env-a",
            "generationId": generation_id,
            "queryName": "operation-by-id",
            "rows": [{
                "operation_id": operation_id,
                "env_id": "bef-env-a",
                "generation_id": generation_id,
                "participant_id": participant_id,
                "operation_kind": "purchase",
                "status": "awaiting_payment",
                "transaction_hash": None,
                "receipt_status": "unknown",
            }],
        })
        for query_name, rows in rows_by_query.items():
            add(f"db/{query_name}.json", "readonly-database", {
                "schemaVersion": "bef-db-observation/v1",
                "boundary": "readonly-database",
                "operationId": operation_id,
                "variantId": None,
                "readOnly": True,
                "databaseRole": "bef_readonly_observer",
                "transactionReadOnly": "on",
                "envId": "bef-env-a",
                "generationId": generation_id,
                "queryName": query_name,
                "rows": rows,
            })
        transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        add("rpc/0001-purchase-receipt.json", "local-chain-readonly-proxy", {
            "schemaVersion": "bef-rpc-observation/v1",
            "boundary": "local-chain-readonly-proxy",
            "endpointBoundary": "local-chain-readonly-proxy",
            "environmentId": "bef-env-a",
            "operationId": operation_id,
            "variantId": None,
            "method": "eth_getTransactionReceipt",
            "params": [transaction_hash],
            "result": {
                "transactionHash": transaction_hash,
                "status": "0x1",
                "logs": [{
                    "address": asset,
                    "topics": [
                        transfer_topic,
                        "0x" + "0" * 24 + payer[2:],
                        "0x" + "0" * 24 + pay_to[2:],
                    ],
                    "data": "0x186a0",
                }],
            },
        })
        report = {
            "schemaVersion": adapter.WORKLOAD_SCHEMA,
            "boundary": "resource-workload",
            "scenarioId": adapter.SCENARIO_ID,
            "phase": phase,
            "mode": "purchase",
            "variantId": "empty_dedicated_cache" if phase == "cold" else "warm_cache",
            "status": "captured",
            "environment": {"envId": "bef-env-a", "generation": {
                "generationId": generation_id,
                "participantId": participant_id,
                "payerAddress": payer,
            }},
            "operationId": operation_id,
            "purchaseOperation": operation,
            "operations": [operation],
            "artifacts": references,
        }
        return report, operation, raw_artifacts

    cold, cold_op, cold_raw = workload("cold", "op-cold")
    warm, warm_op, warm_raw = workload("warm", "op-warm")

    read = {
        "schemaVersion": adapter.WORKLOAD_SCHEMA,
        "boundary": "resource-workload",
        "scenarioId": adapter.SCENARIO_ID,
        "phase": "guardrail_exceeded",
        "mode": "read-loop",
        "status": "running",
        "variantId": "guardrail_exceeded",
        "operationId": None,
    }
    wrapper_rows = [
        {"schemaVersion": adapter.OBSERVATION_SCHEMA, "boundary": "resource-data", "variantId": "empty_dedicated_cache", "operationId": "op-cold"},
        {"schemaVersion": adapter.OBSERVATION_SCHEMA, "boundary": "resource-data", "variantId": "warm_cache", "operationId": "op-warm"},
        {"schemaVersion": adapter.OBSERVATION_SCHEMA, "boundary": "resource-data", "variantId": "provider_cu_unavailable", "operationId": "op-cold"},
    ]
    artifacts = [
        Artifact("cold-purchase/workload.json", "1" * 64, "resource-workload", cold),
        Artifact("warm-purchase/workload.json", "2" * 64, "resource-workload", warm),
        Artifact("guardrail-read/workload.json", "3" * 64, "resource-workload", read),
        *cold_raw,
        *warm_raw,
        *(Artifact(f"resource-observations/{row['variantId']}.json", "4" * 64, "resource-data", row) for row in wrapper_rows),
    ]
    evidence = Evidence(tmp_path, artifacts)
    evidence.manifest = {
        "guardrails": GUARDRAILS,
        "x402": {
            "resourceId": resource_id,
            "network": "eip155:31337",
            "asset": asset,
            "amount": "100000",
            "resourceSha256": hashlib.sha256(b"sample-resource").hexdigest(),
        },
    }
    evidence.index["operations"] = [cold_op, warm_op]
    assert adapter._purchase_operation_inventory_valid(evidence)

    # A later contradictory settlement snapshot must invalidate the operation
    # even though the earlier terminal snapshot remains hash-indexed.
    terminal_payload = next(
        item.payload for item in cold_raw
        if item.boundary == "readonly-database" and item.payload.get("queryName") == "operation-by-id"
    )
    contradictory_payload = {
        **terminal_payload,
        "rows": [{
            **terminal_payload["rows"][0],
            "status": "failed",
        }],
    }
    contradictory_path = "db/post-terminal-operation-by-id.json"
    contradictory_relative = f"cold-purchase/{contradictory_path}"
    contradictory_digest = hashlib.sha256(contradictory_relative.encode()).hexdigest()
    cold["artifacts"].append({
        "path": contradictory_path,
        "sha256": contradictory_digest,
        "contentType": "application/json",
        "boundary": "readonly-database",
    })
    evidence.artifacts = tuple(artifacts) + (
        Artifact(contradictory_relative, contradictory_digest, "readonly-database", contradictory_payload),
    )
    assert not adapter._purchase_operation_inventory_valid(evidence)
    cold["artifacts"].pop()
    evidence.artifacts = tuple(artifacts)

    purchase_http = next(item for item in artifacts if item.boundary == "actual-tool-http")
    mismatched_http = dict(purchase_http.payload)
    mismatched_response = dict(mismatched_http["response"])
    mismatched_response["body"] = {"operationId": "different-operation", "contentBytes": 17}
    mismatched_http["response"] = mismatched_response
    evidence.artifacts = tuple(
        Artifact(item.relative_path, item.sha256, item.boundary, mismatched_http)
        if item.relative_path == purchase_http.relative_path else item
        for item in artifacts
    )
    assert not adapter._purchase_operation_inventory_valid(evidence)
    evidence.artifacts = tuple(artifacts)

    purchase_receipt = next(item for item in artifacts if item.boundary == "local-chain-readonly-proxy")
    failed_receipt = dict(purchase_receipt.payload)
    failed_receipt["result"] = {**failed_receipt["result"], "status": "0x0"}
    evidence.artifacts = tuple(
        Artifact(item.relative_path, item.sha256, item.boundary, failed_receipt)
        if item.relative_path == purchase_receipt.relative_path else item
        for item in artifacts
    )
    assert not adapter._purchase_operation_inventory_valid(evidence)
    evidence.artifacts = tuple(artifacts)

    wrong_read = dict(read, operationId="op-cold")
    evidence.artifacts = tuple(item for item in artifacts if item.relative_path != "guardrail-read/workload.json") + (
        Artifact("guardrail-read/workload.json", "5" * 64, "resource-workload", wrong_read),
    )
    assert not adapter._purchase_operation_inventory_valid(evidence)


def test_outer_timeout_uses_the_pinned_scenario_plus_overrun_window(tmp_path: Path) -> None:
    manifest = {"guardrails": GUARDRAILS}
    path = tmp_path / "manifest.json"
    _write_json(path, manifest)
    assert adapter.resource_probe_timeout_seconds(path) == 902

    manifest["guardrails"]["maxResourceScenarioSeconds"] = 901
    _write_json(path, manifest)
    with pytest.raises(ValueError, match="approved manifest"):
        adapter.resource_probe_timeout_seconds(path)


def test_outer_timeout_attempts_protective_fence_even_when_tree_exit_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    fence_calls: list[str] = []
    generation_id = "b7d73b37-2b34-48df-870f-f29a7f2ca115"

    def unknown_cleanup(process: subprocess.Popen[str]) -> dict:
        process.terminate()
        process.wait(timeout=3)
        return {"status": "unknown", "directChildExited": True, "descendants": "unknown", "treeExitConfirmed": False}

    def fence() -> dict:
        fence_calls.append("attempted")
        fence_root = evidence_dir / "recovery" / "fence"
        fence_root.mkdir(parents=True, exist_ok=True)
        report_path = fence_root / "workload.json"
        verification_path = fence_root / "fence-verification.json"
        report_path.write_text("fenced", encoding="utf-8")
        verification_path.write_text("verified", encoding="utf-8")
        return {
            "status": "protected",
            "exitCode": 0,
            "reportPath": report_path,
            "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "fenceReportPath": verification_path,
            "fenceReportSha256": hashlib.sha256(verification_path.read_bytes()).hexdigest(),
            "generationId": generation_id,
            "fencePurpose": "protective_only",
            "envId": "bef-env-a",
            "databaseVerified": True,
            "rpcVerified": True,
        }

    monkeypatch.setattr(adapter, "terminate_owned_process_tree", unknown_cleanup)
    result = adapter.run_sc011_orchestrator_bounded(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        cwd=tmp_path,
        evidence_dir=evidence_dir,
        timeout_seconds=0.1,
        protective_fence=fence,
    )

    raw = (evidence_dir / "outer-timeout-recovery.json").read_bytes()
    report = json.loads(raw)
    assert result["status"] == "blocked"
    assert result["gateStatus"] == "unknown"
    assert fence_calls == ["attempted"]
    assert report["processTreeCleanup"]["treeExitConfirmed"] is False
    assert report["protectiveFenceAttempted"] is True
    assert report["protectiveFence"]["status"] == "protected"
    assert report["protectiveFence"]["fencePurpose"] == "protective_only"
    assert report["protectiveFence"]["reportSha256"] == hashlib.sha256(b"fenced").hexdigest()
    assert report["protectiveFence"]["reportPath"] == "recovery/fence/workload.json"
    assert str(evidence_dir) not in raw.decode("utf-8")
    assert adapter._safe_evidence_reference_path("../outside/workload.json", evidence_dir) is None
    assert adapter._safe_evidence_reference_path(evidence_dir.parent / "outside-workload.json", evidence_dir) is None
    assert hashlib.sha256(raw).hexdigest() == result["recoverySha256"]


def test_protective_attempt_is_single_and_does_not_reenter_bounded_orchestrator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    calls: list[str] = []

    def forbidden_reentry(*_args, **_kwargs):
        raise AssertionError("a failed protective attempt must not launch another bounded recovery")

    monkeypatch.setattr(adapter, "run_sc011_orchestrator_bounded", forbidden_reentry)
    result = adapter.run_sc011_protective_attempt_once(
        [sys.executable, "-c", "raise SystemExit(7)"],
        cwd=tmp_path,
        timeout_seconds=1.0,
    )
    calls.append(str(result.get("reason")))

    assert calls == ["protective_fence_nonzero_exit"]
    assert result["status"] == "unknown"
    assert not (evidence_dir / "outer-timeout-recovery.json").exists()


def test_protected_fence_summary_requires_canonical_hashed_proof_files(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    fence_dir = evidence_dir / "recovery" / "fence"
    fence_dir.mkdir(parents=True)
    report_path = fence_dir / "workload.json"
    verification_path = fence_dir / "fence-verification.json"
    report_path.write_text("workload", encoding="utf-8")
    verification_path.write_text("verification", encoding="utf-8")
    valid = {
        "status": "protected",
        "exitCode": 0,
        "reportPath": report_path,
        "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "fenceReportPath": verification_path,
        "fenceReportSha256": hashlib.sha256(verification_path.read_bytes()).hexdigest(),
        "generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115",
        "fencePurpose": "protective_only",
        "envId": "bef-env-a",
        "databaseVerified": True,
        "rpcVerified": True,
    }

    accepted = adapter._safe_fence_summary(valid, evidence_dir=evidence_dir)
    assert accepted["status"] == "protected"
    assert accepted["reportPath"] == "recovery/fence/workload.json"
    assert accepted["fenceReportPath"] == "recovery/fence/fence-verification.json"

    wrong_digest = {**valid, "reportSha256": "a" * 64}
    rejected = adapter._safe_fence_summary(wrong_digest, evidence_dir=evidence_dir)
    assert rejected["status"] == "unknown"
    assert "reportPath" not in rejected

    missing_purpose = {**valid, "fencePurpose": "readonly_guardrail"}
    rejected_purpose = adapter._safe_fence_summary(missing_purpose, evidence_dir=evidence_dir)
    assert rejected_purpose["status"] == "unknown"


def test_one_shot_protective_cli_normalizes_only_in_root_hashed_paths(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    fence_dir = evidence_dir / "recovery" / "fence"
    fence_dir.mkdir(parents=True)
    report_path = fence_dir / "workload.json"
    verification_path = fence_dir / "fence-verification.json"
    report_path.write_text("workload", encoding="utf-8")
    verification_path.write_text("verification", encoding="utf-8")
    payload = {
        "status": "protected",
        "exitCode": 0,
        "reportPath": "evidence/recovery/fence/workload.json",
        "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "fenceReportPath": "evidence/recovery/fence/fence-verification.json",
        "fenceReportSha256": hashlib.sha256(verification_path.read_bytes()).hexdigest(),
        "generationId": "b7d73b37-2b34-48df-870f-f29a7f2ca115",
        "fencePurpose": "protective_only",
        "envId": "bef-env-a",
        "databaseVerified": True,
        "rpcVerified": True,
    }
    code = "import json,sys; print(json.dumps(json.loads(sys.argv[1])))"
    result = adapter.run_sc011_protective_attempt_once(
        [sys.executable, "-c", code, json.dumps(payload)],
        cwd=tmp_path,
        timeout_seconds=2.0,
    )

    summary = adapter._safe_fence_summary(result, evidence_dir=evidence_dir)
    assert summary["status"] == "protected"
    assert summary["reportPath"] == "recovery/fence/workload.json"
    assert summary["fenceReportPath"] == "recovery/fence/fence-verification.json"


def test_one_shot_timeout_preserves_process_tree_cleanup_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_row = {
        "status": "unknown",
        "directChildExited": True,
        "descendants": "unknown",
        "treeExitConfirmed": False,
    }

    def scoped_cleanup(process: subprocess.Popen[str]) -> dict:
        process.terminate()
        process.wait(timeout=3)
        return cleanup_row

    monkeypatch.setattr(adapter, "terminate_owned_process_tree", scoped_cleanup)
    result = adapter.run_sc011_protective_attempt_once(
        [sys.executable, "-c", "import time; time.sleep(20)"],
        cwd=tmp_path,
        timeout_seconds=0.05,
    )

    assert result["status"] == "unknown"
    assert result["reason"] == "protective_fence_timeout"
    assert result["processTreeCleanup"] == cleanup_row


@pytest.mark.skipif(os.name == "nt" or not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_posix_one_shot_timeout_stops_its_owned_runner_and_descendant_group(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "owned-child.pid"
    runner_code = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)"
    )

    result = adapter.run_sc011_protective_attempt_once(
        [sys.executable, "-c", runner_code, str(child_pid_path)],
        cwd=tmp_path,
        timeout_seconds=0.2,
    )

    cleanup = result["processTreeCleanup"]
    assert result["status"] == "unknown"
    assert result["reason"] == "protective_fence_timeout"
    assert cleanup["status"] == "stopped"
    assert cleanup["directChildExited"] is True
    assert cleanup["descendants"] == "stopped"
    assert cleanup["treeExitConfirmed"] is True


@pytest.mark.skipif(os.name == "nt" or not Path("/proc").is_dir(), reason="requires Linux procfs")
def test_posix_outer_cleanup_stops_inherited_workload_group_after_runner_exits(tmp_path: Path) -> None:
    runner_code = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(30)\"], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "print(child.pid,flush=True)"
    )
    runner = subprocess.Popen(
        [sys.executable, "-c", runner_code],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )
    workload_pid: int | None = None
    try:
        assert runner.stdout is not None
        workload_pid = int(runner.stdout.readline().strip())
        runner.wait(timeout=3)
        assert runner.poll() == 0
        assert os.getpgid(workload_pid) == runner.pid
        assert adapter._process_group_exists(runner.pid)

        cleanup = adapter.terminate_owned_process_tree(runner, grace_seconds=0.25)

        assert cleanup == {
            "status": "stopped",
            "directChildExited": True,
            "descendants": "stopped",
            "treeExitConfirmed": True,
        }
        assert not adapter._process_group_exists(runner.pid)
    finally:
        if workload_pid is not None and adapter._process_group_exists(runner.pid):
            try:
                os.killpg(runner.pid, 9)
            except ProcessLookupError:
                pass


def test_missing_sampler_negative_control_fails_before_runner_main(tmp_path: Path) -> None:
    runner = Path(__file__).resolve().parents[2] / "tools" / "run_bef_sc011_trials.py"
    result = adapter.run_missing_sampler_control(tmp_path, runner)
    control = json.loads((tmp_path / "missing-sampler-control.json").read_text(encoding="utf-8"))

    assert result["sha256"] == hashlib.sha256((tmp_path / "missing-sampler-control.json").read_bytes()).hexdigest()
    assert control["variantId"] == "missing_sampler"
    assert control["childExitCode"] == 0
    assert control["childResult"] == {
        "status": "blocked_before_main",
        "exception": "ModuleNotFoundError",
        "module": "bef_resource_sampler",
    }


def test_raw_collector_bridge_builds_loadable_probe_index(tmp_path: Path) -> None:
    generation = "b7d73b37-2b34-48df-870f-f29a7f2ca115"
    payer = "0x" + "12" * 20
    source_block = {"number": "123", "hash": "c" * 64}
    manifest = {
        "schemaVersion": "bef-runtime-manifest/v1",
        "source": {"blockNumber": "123", "blockHash": "c" * 64},
        "guardrails": GUARDRAILS,
        "x402": {
            "resourceId": "bef-resource",
            "network": "eip155:31337",
            "asset": "0x" + "11" * 20,
            "amount": "100000",
            "payTo": "0x" + "22" * 20,
            "resourceSha256": hashlib.sha256(b"sample-resource").hexdigest(),
        },
    }
    manifest_bytes = _write_json(tmp_path / "runtime-source.json", manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    _write_json(tmp_path / "orchestration.json", {
        "schemaVersion": adapter.ORCHESTRATION_SCHEMA,
        "scenarioId": adapter.SCENARIO_ID,
        "status": "captured",
        "manifestSha256": manifest_sha,
        "guardrails": GUARDRAILS,
    })
    missing_control = {
        "schemaVersion": adapter.MISSING_SAMPLER_SCHEMA,
        "boundary": "resource-data",
        "scenarioId": adapter.SCENARIO_ID,
        "variantId": "missing_sampler",
        "operationId": None,
        "childExitCode": 0,
    }
    missing_bytes = _write_json(tmp_path / "missing-sampler-control.json", missing_control)
    for phase, directory in (("cold", "cold-purchase"), ("warm", "warm-purchase"), ("guardrail-read", "guardrail-read")):
        _write_json(tmp_path / directory / "resource-sampler.json", {
            "schemaVersion": adapter.SAMPLER_SCHEMA,
            "scenarioId": adapter.SCENARIO_ID,
            "status": "guardrail_exceeded" if phase == "guardrail-read" else "captured",
        })

    app_sha, probe_sha = "a" * 64, "b" * 64
    versions = {"probeNode": "v22.0.0"}
    resource_bytes = b"sample-resource"
    resource_b64 = base64.b64encode(resource_bytes).decode()
    resource_sha = hashlib.sha256(resource_bytes).hexdigest()
    asset = manifest["x402"]["asset"]
    pay_to = manifest["x402"]["payTo"]
    purchase_operations = {
        "cold": [{
            "operationId": "op-cold", "kind": "purchase", "idempotencyKeyHash": "d" * 64,
            "observedStatus": "settled", "transactionHash": "0x" + "a" * 64, "receiptStatus": "success",
        }],
        "warm": [{
            "operationId": "op-warm", "kind": "purchase", "idempotencyKeyHash": "e" * 64,
            "observedStatus": "settled", "transactionHash": "0x" + "b" * 64, "receiptStatus": "success",
        }],
    }
    for phase in ("cold", "warm"):
        operation = purchase_operations[phase][0]
        operation_id = operation["operationId"]
        generation_id = f"generation-{phase}"
        participant_id = f"participant-{phase}"
        transaction_hash = operation["transactionHash"]
        references: list[dict[str, Any]] = []

        def add_purchase_artifact(path: str, boundary: str, payload: dict[str, Any]) -> None:
            raw = _write_json(tmp_path / f"{phase}-purchase" / path, payload)
            references.append({
                "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "contentType": "application/json",
                "boundary": boundary,
            })

        add_purchase_artifact("http/0001-probe-capabilities.json", "private-admin-http", {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "private-admin-http",
            "operationId": None,
            "variantId": None,
            "request": {"method": "GET", "path": "/internal/admin/environments/bef-env-a/probe-capabilities"},
            "response": {"status": 200, "body": {"services": {"facilitator": {"address": pay_to}}}},
        })
        response_body = {
            "operationId": operation_id,
            "resourceId": manifest["x402"]["resourceId"],
            "contentType": "application/json",
            "contentHash": resource_sha,
            "contentBytes": resource_b64,
        }
        add_purchase_artifact("http/0001-purchase.json", "actual-tool-http", {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "actual-tool-http",
            "operationId": operation_id,
            "variantId": None,
            "request": {
                "method": "POST",
                "path": "/tools/bef-env-a/purchase",
                "headers": {"X-BEF-Generation": generation_id},
                "body": {"resourceId": manifest["x402"]["resourceId"]},
            },
            "response": {
                "status": 200,
                "body": response_body,
                "bodyBase64": base64.b64encode(json.dumps(response_body).encode()).decode(),
            },
        })
        rows_by_query = {
            "generation-by-id": [{
                "generation_id": generation_id, "env_id": "bef-env-a", "participant_id": participant_id,
                "payer_address": payer, "status": "active",
            }],
            "operation-by-id": [{
                "operation_id": operation_id, "env_id": "bef-env-a", "generation_id": generation_id,
                "participant_id": participant_id, "operation_kind": "purchase", "status": "settled",
                "transaction_hash": transaction_hash, "receipt_status": "success",
            }],
            "payments-by-operation": [{
                "operation_id": operation_id, "env_id": "bef-env-a", "generation_id": generation_id,
                "payer_address": payer, "network": manifest["x402"]["network"],
                "asset_address": asset, "amount_units": manifest["x402"]["amount"],
                "facilitator_address": pay_to, "transaction_hash": transaction_hash, "receipt_status": "success",
            }],
            "deliveries-by-operation": [{
                "operation_id": operation_id, "resource_id": manifest["x402"]["resourceId"],
                "content_sha256": resource_sha, "content_bytes": str(len(resource_bytes)),
            }],
            "denials-by-generation": [],
            "x402-observations-by-operation": [],
        }
        for query_name, rows in rows_by_query.items():
            add_purchase_artifact(f"db/{query_name}.json", "readonly-database", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
                "operationId": operation_id, "variantId": None, "readOnly": True,
                "databaseRole": "bef_readonly_observer", "transactionReadOnly": "on",
                "envId": "bef-env-a", "generationId": generation_id,
                "queryName": query_name, "rows": rows,
            })
        add_purchase_artifact("rpc/0001-purchase-receipt.json", "local-chain-readonly-proxy", {
            "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
            "endpointBoundary": "local-chain-readonly-proxy", "environmentId": "bef-env-a",
            "operationId": operation_id, "variantId": None, "method": "eth_getTransactionReceipt",
            "params": [transaction_hash],
            "result": {
                "transactionHash": transaction_hash, "status": "0x1",
                "logs": [{
                    "address": asset,
                    "topics": [
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x" + "0" * 24 + payer[2:], "0x" + "0" * 24 + pay_to[2:],
                    ],
                    "data": "0x186a0",
                }],
            },
        })
        _write_json(tmp_path / f"{phase}-purchase" / "workload.json", {
            "schemaVersion": adapter.WORKLOAD_SCHEMA,
            "boundary": "resource-workload",
            "scenarioId": adapter.SCENARIO_ID,
            "phase": phase,
            "mode": "purchase",
            "variantId": "empty_dedicated_cache" if phase == "cold" else "warm_cache",
            "status": "captured",
            "environment": {"envId": "bef-env-a", "generation": {
                "generationId": generation_id,
                "participantId": participant_id,
                "payerAddress": payer,
            }},
            "manifestSha256": manifest_sha,
            "applicationSourceSha256": app_sha,
            "probeSourceSha256": probe_sha,
            "sourceBlock": source_block,
            "runtimeVersions": versions,
            "operationId": operation["operationId"],
            "purchaseOperation": operation,
            "operations": [operation],
            "observations": [],
            "artifacts": references,
        })
    _write_json(tmp_path / "guardrail-read" / "workload.json", {
        "schemaVersion": adapter.WORKLOAD_SCHEMA,
        "boundary": "resource-workload",
        "scenarioId": adapter.SCENARIO_ID,
        "phase": "guardrail_exceeded",
        "mode": "read-loop",
        "variantId": "guardrail_exceeded",
        "status": "running",
        "environment": {"envId": "bef-env-a", "generation": {
            "generationId": generation, "participantId": "participant-read", "payerAddress": payer,
        }},
        "manifestSha256": manifest_sha,
        "applicationSourceSha256": app_sha,
        "probeSourceSha256": probe_sha,
        "sourceBlock": source_block,
        "runtimeVersions": versions,
        "operationId": None,
        "operations": [],
        "observations": [],
        "artifacts": [],
    })
    _write_json(tmp_path / "guardrail-read" / "identity.json", {
        "schemaVersion": "bef-resource-workload-identity/v1",
        "phase": "guardrail_exceeded",
        "envId": "bef-env-a",
        "generationId": generation,
        "payerAddress": payer,
        "manifestSha256": manifest_sha,
        "applicationSourceSha256": app_sha,
        "probeSourceSha256": probe_sha,
    })
    http = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": "guardrail_exceeded",
        "request": {"method": "GET", "path": "/tools/bef-env-a/balances"},
        "response": {"status": 200, "body": {
            "boundary": "local-chain-readonly-proxy",
            "envId": "bef-env-a",
            "generationId": generation,
            "payer": payer,
            "balances": BALANCE_SNAPSHOT,
        }},
    }
    http_bytes = _write_json(tmp_path / "guardrail-read" / "http" / "0001-read.json", http)
    progress = {
        "schemaVersion": "bef-resource-read-progress/v1",
        "envId": "bef-env-a",
        "generationId": generation,
        "variantId": "guardrail_exceeded",
        "sequence": 1,
        "observationId": "read-1",
        "status": 200,
        "operationId": None,
        "artifact": {
            "path": "http/0001-read.json",
            "sha256": hashlib.sha256(http_bytes).hexdigest(),
            "contentType": "application/json",
            "boundary": "actual-tool-http",
        },
    }
    _write_json(tmp_path / "guardrail-read" / "read-progress.ndjson", progress)

    index = adapter.build_probe_index(
        tmp_path,
        tmp_path / "runtime-source.json",
        missing_sampler_control={
            "path": tmp_path / "missing-sampler-control.json",
            "sha256": hashlib.sha256(missing_bytes).hexdigest(),
        },
    )
    loaded = ProbeEvidence.load(Path(__file__).resolve().parents[2], adapter.SCENARIO_ID, tmp_path)

    assert index["operations"] == purchase_operations["cold"] + purchase_operations["warm"]
    assert loaded.environment_id == "bef-env-a"
    assert loaded.generation_id == generation
    assert any(item.boundary == "actual-tool-http" for item in loaded.artifacts)
    assert any(item.boundary == "resource-data" and item.payload.get("schemaVersion") == adapter.SAMPLER_SCHEMA for item in loaded.artifacts)
    assert adapter._purchase_operation_inventory_valid(loaded)
