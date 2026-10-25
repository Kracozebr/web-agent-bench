"""Hash-preserving bridge and strict predicates for actual SC-011 evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCENARIO_ID = "BEF-SC-011"
VARIANTS = frozenset({
    "missing_sampler",
    "empty_dedicated_cache",
    "warm_cache",
    "guardrail_exceeded",
    "provider_cu_unavailable",
})
_UNRESOLVED_SAMPLER_METADATA = frozenset({
    "cold_warm_cache_provenance_unavailable",
    "source_call_trial_attribution_unavailable",
    "independent_generation_fence_not_verified",
    "provider_compute_units_unobservable",
})
SAMPLER_SCHEMA = "bef-resource-trial/v1"
ORCHESTRATION_SCHEMA = "bef-sc011-resource-trials/v1"
WORKLOAD_SCHEMA = "bef-resource-purchase-workload/v1"
OBSERVATION_SCHEMA = "bef-resource-observation/v1"
MISSING_SAMPLER_SCHEMA = "bef-resource-missing-sampler-control/v1"
SAMPLER_MANIFEST_PATH = "infrastructure/benchmark-environment/manifest.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REDACTED = {"", "<redacted>", "[redacted]", "redacted", "***", "omitted"}
_SENSITIVE_KEY_PARTS = (
    "privatekey", "seedphrase", "mnemonic", "password", "secret", "authorization",
    "bearer", "runtoken", "adminkey", "accesstoken", "authtoken", "apitoken", "signature",
    "paymentsignature", "rawsignature", "credential", "databaseurl", "rpcurl", "sourceurl",
)
_BALANCE_READ_FIELDS = frozenset({
    "blockNumber",
    "payerNativeWei",
    "payerWethUnits",
    "payerUsdcUnits",
    "recipientUsdcUnits",
    "wethRouterAllowance",
    "poolWethUnits",
    "poolUsdcUnits",
    "poolLiquidity",
    "poolSqrtPriceX96",
})
_UINT_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]{0,77})$")
_EVM_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$", re.IGNORECASE)


def _actual_balance_snapshot(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != _BALANCE_READ_FIELDS:
        return False
    return all(isinstance(value[field], str) and _UINT_DECIMAL.fullmatch(value[field]) for field in _BALANCE_READ_FIELDS)


def _actual_balance_read_matches(value: Any, *, env_id: str, generation_id: str, payer: str) -> bool:
    if not isinstance(value, dict):
        return False
    returned_payer = value.get("payer")
    return (
        value.get("boundary") == "local-chain-readonly-proxy"
        and value.get("envId") == env_id
        and value.get("generationId") == generation_id
        and isinstance(returned_payer, str)
        and _EVM_ADDRESS.fullmatch(returned_payer) is not None
        and returned_payer.lower() == payer.lower()
        and _actual_balance_snapshot(value.get("balances"))
    )


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def _write_json_new(path: Path, value: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)
    return sha256_bytes(raw)


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _has_symlink_component(root: Path, path: Path) -> bool:
    try:
        resolved_root = root.resolve(strict=True)
        cursor = path
        while cursor != resolved_root:
            if cursor.is_symlink():
                return True
            if cursor.parent == cursor:
                return True
            cursor = cursor.parent
        return resolved_root.is_symlink()
    except OSError:
        return True


def _relative(root: Path, path: Path) -> str:
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if not _inside(resolved_root, resolved_path):
        raise ValueError("resource evidence path escaped run root")
    return resolved_path.relative_to(resolved_root).as_posix()


def _require_safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("resource evidence reference path is invalid")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts):
        raise ValueError("resource evidence reference path escaped its directory")
    return result


def _secret_free(value: Any, path: str = "root") -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            normalized_key = re.sub(r"[^a-z0-9]", "", key_text.lower())
            sensitive_key = any(part in normalized_key for part in _SENSITIVE_KEY_PARTS)
            safe_metadata = (
                normalized_key in {
                    "authorizationpresent", "proxyauthorizationpresent", "paymentsignaturepresent",
                    "xpaymentsignaturepresent", "xbefadminkeypresent", "xbefservicekeypresent",
                    "requireruntokenandgeneration",
                }
                and isinstance(child, bool)
            ) or (
                normalized_key == "rpcurlenv"
                and isinstance(child, str)
                and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*_URL", child))
            ) or (
                normalized_key in {
                    "paymentsignaturesha256", "xpaymentsignaturesha256", "authorizationsha256",
                    "payloadsignaturesha256",
                }
                and _DIGEST.fullmatch(str(child)) is not None
            )
            if sensitive_key and not safe_metadata:
                if not (isinstance(child, str) and child.strip().lower() in _REDACTED):
                    return False
            if not _secret_free(child, f"{path}.{key_text}"):
                return False
    elif isinstance(value, list):
        return all(_secret_free(child, f"{path}[]") for child in value)
    elif isinstance(value, str):
        if re.search(r"(?i)\bbearer\s+(?!<redacted>|\[redacted\]|\*{3})[^\s,;]+", value):
            return False
        if re.search(r"(?i)(?:[?&](?:api[_-]?key|access[_-]?token|token|secret|password|signature)=)(?!<redacted>|\[redacted\]|%3Credacted%3E)[^&#\s]+", value):
            return False
        if re.search(r"(?i)\b(?:0x)?[0-9a-f]{64}\b", value) and any(
            token in value.lower() for token in ("private key", "seed phrase", "mnemonic", "secret")
        ):
            return False
    return True


def _index_file(root: Path, path: Path, boundary: str, entries: list[dict[str, Any]], seen: dict[str, tuple[str, str]]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or not _inside(root, path) or _has_symlink_component(root, path):
        raise ValueError("resource evidence file is missing, linked, or outside run root")
    raw = path.read_bytes()
    relative = _relative(root, path)
    digest = sha256_bytes(raw)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("resource JSON evidence exceeds per-file validation bound")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not _secret_free(payload):
        raise ValueError("resource JSON evidence is invalid or not secret-safe")
    payload_boundary = payload.get("boundary")
    if boundary not in {"resource-data", "runtime-manifest"} and payload_boundary != boundary:
        raise ValueError("resource evidence boundary differs from raw payload")
    existing = seen.get(relative)
    if existing is not None:
        if existing != (digest, boundary):
            raise ValueError("one path has conflicting indexed evidence identities")
        return {"path": relative, "sha256": digest, "contentType": "application/json", "boundary": boundary}
    seen[relative] = (digest, boundary)
    entry = {"path": relative, "sha256": digest, "contentType": "application/json", "boundary": boundary}
    entries.append(entry)
    return entry


def run_missing_sampler_control(run_root: Path, runner_path: Path) -> dict[str, Any]:
    """Exercise the real runner import boundary in a no-site isolated child.

    The child deliberately removes the collector module search path, runs the
    actual runner entry point, and succeeds only when import fails before its
    ``main`` function or any Docker side effect can run.
    """

    output_path = run_root / "missing-sampler-control.json"
    code = r"""
import json, runpy, sys, sysconfig
target = sys.argv[1]
paths = [sysconfig.get_path('stdlib'), sysconfig.get_path('platstdlib')]
sys.path = [entry for entry in paths if entry]
try:
    runpy.run_path(target, run_name='__main__')
except ModuleNotFoundError as error:
    if error.name != 'bef_resource_sampler':
        print(json.dumps({'status':'unexpected_import_failure','module':error.name}))
        raise SystemExit(3)
    print(json.dumps({'status':'blocked_before_main','exception':'ModuleNotFoundError','module':error.name}))
    raise SystemExit(0)
except BaseException as error:
    print(json.dumps({'status':'unexpected_failure','exception':type(error).__name__}))
    raise SystemExit(4)
print(json.dumps({'status':'unexpectedly_imported_without_sampler'}))
raise SystemExit(5)
"""
    command = [sys.executable, "-B", "-S", "-c", code, str(runner_path.resolve(strict=True))]
    completed = subprocess.run(command, cwd=run_root, capture_output=True, text=True, timeout=10, check=False)
    try:
        child_result = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as error:
        raise ValueError("missing sampler control did not return machine-readable evidence") from error
    if completed.returncode != 0 or child_result != {
        "status": "blocked_before_main",
        "exception": "ModuleNotFoundError",
        "module": "bef_resource_sampler",
    }:
        raise ValueError("missing sampler control failed to prove fail-closed import behavior")
    control = {
        "schemaVersion": MISSING_SAMPLER_SCHEMA,
        "boundary": "resource-data",
        "scenarioId": SCENARIO_ID,
        "variantId": "missing_sampler",
        "operationId": None,
        "commandSha256": sha256_bytes("\0".join(command).encode("utf-8")),
        "runnerSha256": sha256_bytes(runner_path.read_bytes()),
        "childExitCode": completed.returncode,
        "childStdout": completed.stdout.strip(),
        "childStderr": completed.stderr,
        "childResult": child_result,
    }
    _write_json_new(output_path, control)
    return {"path": output_path, "sha256": sha256_bytes(output_path.read_bytes())}


def _copy_workload_artifacts(
    root: Path,
    workload_dir: Path,
    workload: dict[str, Any],
    entries: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    seen: dict[str, tuple[str, str]],
) -> None:
    raw_artifacts = workload.get("artifacts")
    raw_observations = workload.get("observations")
    if not isinstance(raw_artifacts, list) or not isinstance(raw_observations, list):
        raise ValueError("resource workload is missing raw artifact or observation inventory")
    by_source: dict[str, str] = {}
    for item in raw_artifacts:
        if not isinstance(item, dict):
            raise ValueError("resource workload artifact entry is invalid")
        if item.get("boundary") == "runtime-manifest":
            relative = _require_safe_relative(item.get("path"))
            source_path = workload_dir.joinpath(*relative.parts)
            raw = source_path.read_bytes()
            if sha256_bytes(raw) != item.get("sha256"):
                raise ValueError("embedded workload manifest copy hash mismatch")
            continue
        relative = _require_safe_relative(item.get("path"))
        boundary = item.get("boundary")
        digest = item.get("sha256")
        if not isinstance(boundary, str) or not _DIGEST.fullmatch(str(digest)):
            raise ValueError("resource workload artifact lacks a boundary or digest")
        source_path = workload_dir.joinpath(*relative.parts)
        raw = source_path.read_bytes()
        if sha256_bytes(raw) != digest:
            raise ValueError("resource workload artifact hash mismatch")
        indexed = _index_file(root, source_path, boundary, entries, seen)
        by_source[relative.as_posix()] = indexed["path"]
    for observation in raw_observations:
        if not isinstance(observation, dict) or not isinstance(observation.get("id"), str):
            raise ValueError("resource workload observation reference is invalid")
        source = observation.get("sourceArtifact")
        if source is not None:
            safe_source = _require_safe_relative(source).as_posix()
            if safe_source not in by_source:
                raise ValueError("workload observation points outside its hashed artifact inventory")
        observations.append({
            "id": observation["id"],
            "sourceArtifact": by_source.get(str(source)) if source is not None else None,
        })


def _index_read_progress(
    root: Path,
    entries: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    seen: dict[str, tuple[str, str]],
) -> dict[str, Any]:
    read_dir = root / "guardrail-read"
    progress_path = read_dir / "read-progress.ndjson"
    identity = read_json(read_dir / "identity.json")
    if (
        identity.get("schemaVersion") != "bef-resource-workload-identity/v1"
        or identity.get("phase") != "guardrail_exceeded"
        or identity.get("envId") != "bef-env-a"
        or not isinstance(identity.get("generationId"), str)
        or not isinstance(identity.get("payerAddress"), str)
    ):
        raise ValueError("SC-011 read-loop generation identity is invalid")
    raw = progress_path.read_bytes()
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise ValueError("SC-011 raw read progress is missing or over its byte bound")
    lines = raw.splitlines()
    if not lines or len(lines) > 10_000:
        raise ValueError("SC-011 raw read progress line count is invalid")
    http_refs: list[dict[str, str]] = []
    expected_generation: str | None = None
    for sequence, line in enumerate(lines, start=1):
        row = json.loads(line.decode("utf-8"))
        if (
            not isinstance(row, dict)
            or row.get("schemaVersion") != "bef-resource-read-progress/v1"
            or row.get("variantId") != "guardrail_exceeded"
            or row.get("envId") != "bef-env-a"
            or row.get("sequence") != sequence
            or row.get("status") != 200
            or row.get("operationId") is not None
            or not isinstance(row.get("generationId"), str)
            or not isinstance(row.get("observationId"), str)
        ):
            raise ValueError("SC-011 raw read progress row identity is invalid")
        if expected_generation is None:
            expected_generation = row["generationId"]
        elif row["generationId"] != expected_generation:
            raise ValueError("SC-011 read progress changed generation during the trial")
        if row["generationId"] != identity["generationId"]:
            raise ValueError("SC-011 read progress differs from the recorded generation")
        artifact = row.get("artifact")
        rel = _require_safe_relative(artifact.get("path") if isinstance(artifact, dict) else None)
        raw_hash = artifact.get("sha256") if isinstance(artifact, dict) else None
        if (
            not isinstance(artifact, dict)
            or artifact.get("boundary") != "actual-tool-http"
            or artifact.get("contentType") != "application/json"
            or not _DIGEST.fullmatch(str(raw_hash))
        ):
            raise ValueError("SC-011 read progress lacks a hash-bound HTTP artifact")
        artifact_path = read_dir.joinpath(*rel.parts)
        actual = json.loads(artifact_path.read_text(encoding="utf-8"))
        if (
            not isinstance(actual, dict)
            or _has_symlink_component(root, artifact_path)
            or not _inside(read_dir, artifact_path)
            or sha256_bytes(artifact_path.read_bytes()) != raw_hash
            or actual.get("schemaVersion") != "bef-http-observation/v1"
            or actual.get("boundary") != "actual-tool-http"
            or actual.get("operationId") is not None
            or actual.get("variantId") != "guardrail_exceeded"
        ):
            raise ValueError("SC-011 read progress HTTP artifact failed raw hash or operation checks")
        request = actual.get("request")
        response = actual.get("response")
        body = response.get("body") if isinstance(response, dict) else None
        if (
            not isinstance(request, dict)
            or request.get("method") != "GET"
            or request.get("path") != "/tools/bef-env-a/balances"
            or not isinstance(response, dict)
            or response.get("status") != 200
            or not _actual_balance_read_matches(
                body,
                env_id="bef-env-a",
                generation_id=expected_generation,
                payer=identity["payerAddress"],
            )
        ):
            raise ValueError("SC-011 read progress did not record an actual generation-bound GET")
        indexed = _index_file(root, artifact_path, "actual-tool-http", entries, seen)
        observations.append({"id": row["observationId"], "sourceArtifact": indexed["path"]})
        http_refs.append({"path": indexed["path"], "sha256": indexed["sha256"]})
    envelope = {
        "schemaVersion": OBSERVATION_SCHEMA,
        "boundary": "resource-data",
        "scenarioId": SCENARIO_ID,
        "variantId": "guardrail_exceeded",
        "operationId": None,
        "readProgress": {
            "path": _relative(root, progress_path),
            "sha256": sha256_bytes(raw),
            "lineCount": len(lines),
            "firstSequence": 1,
            "lastSequence": len(lines),
            "httpArtifacts": http_refs,
        },
    }
    envelope_path = root / "resource-observations" / "guardrail-read-progress.json"
    _write_json_new(envelope_path, envelope)
    _index_file(root, envelope_path, "resource-data", entries, seen)
    return {"path": _relative(root, progress_path), "sha256": sha256_bytes(raw), "lineCount": len(lines)}


def build_probe_index(run_root: Path, manifest_path: Path, *, missing_sampler_control: dict[str, Any]) -> dict[str, Any]:
    """Index raw SC-011 collector evidence without replacing it with summaries."""

    root = run_root.resolve(strict=True)
    orchestration_path = root / "orchestration.json"
    orchestration = read_json(orchestration_path)
    if orchestration.get("schemaVersion") != ORCHESTRATION_SCHEMA or orchestration.get("status") != "captured":
        raise ValueError("SC-011 orchestration is not a captured run")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != "bef-runtime-manifest/v1":
        raise ValueError("SC-011 runtime manifest is invalid")
    manifest_hash = sha256_bytes(manifest_bytes)
    if orchestration.get("manifestSha256") != manifest_hash:
        raise ValueError("SC-011 orchestration manifest hash is mismatched")
    manifest_copy = root / "manifest.json"
    if manifest_copy.exists() or manifest_copy.is_symlink():
        raise ValueError("allocated SC-011 run directory already contains manifest.json")
    with manifest_copy.open("xb") as stream:
        stream.write(manifest_bytes)

    entries: list[dict[str, Any]] = []
    seen: dict[str, tuple[str, str]] = {}
    observations: list[dict[str, Any]] = []
    manifest_entry = _index_file(root, root / "manifest.json", "runtime-manifest", entries, seen)
    sample_paths = {
        "empty_dedicated_cache": root / "cold-purchase" / "resource-sampler.json",
        "warm_cache": root / "warm-purchase" / "resource-sampler.json",
        "guardrail_exceeded": root / "guardrail-read" / "resource-sampler.json",
        "provider_cu_unavailable": root / "cold-purchase" / "resource-sampler.json",
    }

    workload_paths = sorted(root.rglob("workload.json"))
    workloads: list[tuple[Path, dict[str, Any]]] = []
    for path in workload_paths:
        if any(part in {"state", "foundry-cache"} for part in path.parts):
            continue
        workload = read_json(path)
        if workload.get("schemaVersion") != WORKLOAD_SCHEMA or workload.get("scenarioId") != SCENARIO_ID:
            raise ValueError("SC-011 workload summary schema or scenario identity mismatch")
        if workload.get("boundary") != "resource-workload":
            raise ValueError("SC-011 workload summary boundary is missing")
        _index_file(root, path, "resource-workload", entries, seen)
        _copy_workload_artifacts(root, path.parent, workload, entries, observations, seen)
        workloads.append((path, workload))

    progress_ref = _index_read_progress(root, entries, observations, seen)

    # Every successful per-trial sampler payload is indexed in its actual raw
    # schema. Its source file is retained as-written by the collector.
    for variant, sample_path in sample_paths.items():
        sample = read_json(sample_path)
        if sample.get("schemaVersion") != SAMPLER_SCHEMA or sample.get("scenarioId") != SCENARIO_ID:
            raise ValueError("SC-011 raw sampler schema is invalid")
        _index_file(root, sample_path, "resource-data", entries, seen)

    # Independently written fence verifications and task-owned markers are raw
    # JSON too; index each file by its natural boundary or the narrow resource
    # boundary accepted by the SC-011 evidence loader.
    for path in sorted(root.rglob("*.json")):
        if path == root / "manifest.json" or any(part in {"state", "foundry-cache"} for part in path.parts):
            continue
        relative = _relative(root, path)
        if relative in seen:
            continue
        payload = read_json(path)
        schema = payload.get("schemaVersion")
        if schema == MISSING_SAMPLER_SCHEMA:
            _index_file(root, path, "resource-data", entries, seen)
        elif schema == "bef-resource-fence-verification/v1":
            _index_file(root, path, str(payload.get("boundary")), entries, seen)
        elif schema in {
            "bef-resource-workload-identity/v1",
            "bef-resource-workload-ready/v1",
            "bef-resource-workload-release/v1",
            "bef-resource-workload-fence-target/v1",
        }:
            _index_file(root, path, "resource-data", entries, seen)
    _index_file(root, orchestration_path, "resource-data", entries, seen)

    for variant, sample_path in sample_paths.items():
        sample = read_json(sample_path)
        sample_ref = {"path": _relative(root, sample_path), "sha256": sha256_bytes(sample_path.read_bytes())}
        operation_id = None
        phase = "guardrail_exceeded" if variant == "guardrail_exceeded" else "cold" if variant != "warm_cache" else "warm"
        if phase in {"cold", "warm"}:
            purchase = read_json(root / f"{phase}-purchase" / "workload.json")
            operation_id = purchase.get("operationId")
        wrapper = {
            "schemaVersion": OBSERVATION_SCHEMA,
            "boundary": "resource-data",
            "scenarioId": SCENARIO_ID,
            "variantId": variant,
            "operationId": operation_id,
            "phase": phase,
            "sampleArtifact": sample_ref,
            "rawSampleSchemaVersion": sample.get("schemaVersion"),
            **({"readProgress": progress_ref} if variant == "guardrail_exceeded" else {}),
        }
        wrapper_path = root / "resource-observations" / f"{variant}.json"
        _write_json_new(wrapper_path, wrapper)
        _index_file(root, wrapper_path, "resource-data", entries, seen)

    missing_path = Path(missing_sampler_control["path"])
    missing_raw = read_json(missing_path)
    if missing_raw.get("variantId") != "missing_sampler" or missing_raw.get("schemaVersion") != MISSING_SAMPLER_SCHEMA:
        raise ValueError("SC-011 missing-sampler negative control is invalid")
    missing_wrapper = {
        "schemaVersion": OBSERVATION_SCHEMA,
        "boundary": "resource-data",
        "scenarioId": SCENARIO_ID,
        "variantId": "missing_sampler",
        "operationId": None,
        "rawArtifact": {
            "path": _relative(root, missing_path),
            "sha256": sha256_bytes(missing_path.read_bytes()),
        },
    }
    missing_wrapper_path = root / "resource-observations" / "missing_sampler-reference.json"
    _write_json_new(missing_wrapper_path, missing_wrapper)
    _index_file(root, missing_wrapper_path, "resource-data", entries, seen)

    purchase_reports = [read_json(root / f"{phase}-purchase" / "workload.json") for phase in ("cold", "warm")]
    operations: list[dict[str, Any]] = []
    for report in purchase_reports:
        raw_operations = report.get("operations")
        if not isinstance(raw_operations, list) or not raw_operations:
            raise ValueError("SC-011 actual purchase operation inventory is missing")
        operations.extend(item for item in raw_operations if isinstance(item, dict))
    guardrail_identity = read_json(root / "guardrail-read" / "identity.json")
    environment = {
        "envId": guardrail_identity.get("envId"),
        "generation": {
            "generationId": guardrail_identity.get("generationId"),
            "participantId": guardrail_identity.get("participantId"),
            "payerAddress": guardrail_identity.get("payerAddress"),
        },
    }
    source_report = purchase_reports[0]
    if any(source_report.get(key) != purchase_reports[1].get(key) for key in ("applicationSourceSha256", "probeSourceSha256", "runtimeVersions", "sourceBlock")):
        raise ValueError("SC-011 workload source/runtime identity changed between trials")
    source_block = manifest.get("source")
    if not isinstance(source_block, dict):
        raise ValueError("SC-011 runtime manifest source identity is missing")
    index = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": SCENARIO_ID,
        "status": "captured",
        "gateStatus": "not_established_by_resource_orchestrator",
        "manifest": {"path": manifest_entry["path"], "sha256": manifest_entry["sha256"]},
        "environment": environment,
        "operations": operations,
        "observations": observations,
        "artifacts": entries,
        "applicationSourceSha256": source_report.get("applicationSourceSha256"),
        "probeSourceSha256": source_report.get("probeSourceSha256"),
        "runtimeVersions": source_report.get("runtimeVersions"),
        "sourceBlock": {"number": source_block.get("blockNumber"), "hash": source_block.get("blockHash")},
        "resourceOrchestration": {"path": _relative(root, orchestration_path), "sha256": sha256_bytes(orchestration_path.read_bytes())},
        "missingSamplerControl": {"path": _relative(root, missing_path), "sha256": sha256_bytes(missing_path.read_bytes())},
    }
    if not isinstance(environment["envId"], str) or not isinstance(environment["generation"]["generationId"], str):
        raise ValueError("SC-011 guardrail generation identity is missing")
    index_path = root / "probe.json"
    _write_json_new(index_path, index)
    return index


def _sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _manifest_guardrails(evidence: Any) -> dict[str, Any]:
    manifest = evidence.manifest
    guardrails = manifest.get("guardrails") if isinstance(manifest, dict) else None
    return guardrails if isinstance(guardrails, dict) else {}


def resource_probe_timeout_seconds(manifest_path: Path) -> int:
    """Return the pinned SC-011 outer timeout, including the two-second bound."""

    manifest = read_json(manifest_path)
    guardrails = manifest.get("guardrails")
    if not isinstance(guardrails, dict):
        raise ValueError("SC-011 manifest guardrails are missing")
    scenario = guardrails.get("maxResourceScenarioSeconds")
    overrun = guardrails.get("maxResourceReadOverrunSeconds")
    per_trial = guardrails.get("maxTrialSeconds")
    if (
        isinstance(scenario, bool) or not isinstance(scenario, int) or scenario != 900
        or isinstance(overrun, bool) or not isinstance(overrun, int) or overrun != 2
        or isinstance(per_trial, bool) or not isinstance(per_trial, int) or per_trial != 120
    ):
        raise ValueError("SC-011 scenario, read-overrun, or per-trial pin differs from the approved manifest")
    return scenario + overrun


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def terminate_owned_process_tree(process: subprocess.Popen[str], *, grace_seconds: float = 2.0) -> dict[str, Any]:
    """Stop only the orchestrator process tree created by this adapter."""

    if isinstance(grace_seconds, bool) or not isinstance(grace_seconds, (int, float)) or grace_seconds <= 0:
        return {"status": "unknown", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}
    if os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill is None or not isinstance(process.pid, int) or process.pid <= 0:
            return {"status": "unknown", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}
        try:
            result = subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=max(1.0, grace_seconds),
                check=False,
                shell=False,
            )
            try:
                process.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                return {"status": "unknown", "directChildExited": False, "descendants": "unknown", "treeExitConfirmed": False}
            confirmed = result.returncode == 0 and process.poll() is not None
            return {
                "status": "stopped" if confirmed else "unknown",
                "directChildExited": process.poll() is not None,
                "descendants": "stopped" if confirmed else "unknown",
                "treeExitConfirmed": confirmed,
            }
        except (OSError, subprocess.TimeoutExpired):
            return {"status": "unknown", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}

    # run_sc011_orchestrator_bounded starts this Popen with start_new_session=True,
    # so its PID is the owned PGID even after the direct Python process exits.
    process_group_id = process.pid
    if process.poll() is None:
        try:
            if os.getpgid(process.pid) != process_group_id:
                try:
                    process.kill()
                    process.wait(timeout=grace_seconds)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                return {"status": "owned_process_group_unverified", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}
        except OSError:
            try:
                process.kill()
                process.wait(timeout=grace_seconds)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return {"status": "owned_process_group_unavailable", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}
    if not _process_group_exists(process_group_id):
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            return {"status": "unknown", "directChildExited": False, "descendants": "unknown", "treeExitConfirmed": False}
        direct_exited = process.poll() is not None
        return {
            "status": "stopped" if direct_exited else "unknown",
            "directChildExited": direct_exited,
            "descendants": "stopped" if direct_exited else "unknown",
            "treeExitConfirmed": direct_exited,
        }
    for sig, wait_seconds in ((signal.SIGTERM, grace_seconds), (signal.SIGKILL, grace_seconds)):
        try:
            os.killpg(process_group_id, sig)
        except ProcessLookupError:
            pass
        except OSError:
            return {"status": "unknown", "directChildExited": process.poll() is not None, "descendants": "unknown", "treeExitConfirmed": False}
        end = time.monotonic() + wait_seconds
        while time.monotonic() < end:
            if not _process_group_exists(process_group_id):
                try:
                    process.wait(timeout=max(0.05, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
                confirmed = not _process_group_exists(process_group_id) and process.poll() is not None
                return {
                    "status": "stopped" if confirmed else "unknown",
                    "directChildExited": process.poll() is not None,
                    "descendants": "stopped" if confirmed else "unknown",
                    "treeExitConfirmed": confirmed,
                }
            time.sleep(0.05)
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    confirmed = process.poll() is not None and not _process_group_exists(process_group_id)
    return {
        "status": "stopped" if confirmed else "unknown",
        "directChildExited": process.poll() is not None,
        "descendants": "stopped" if confirmed else "unknown",
        "treeExitConfirmed": confirmed,
    }


def _safe_evidence_reference_path(value: Any, evidence_dir: Path) -> str | None:
    if isinstance(value, Path):
        candidate = value
    elif isinstance(value, str):
        candidate = Path(value)
    else:
        return None
    try:
        root = evidence_dir.resolve(strict=True)
        if not candidate.is_absolute():
            candidate = root.joinpath(*_require_safe_relative(candidate.as_posix()).parts)
        resolved = candidate.resolve(strict=True)
        if (
            not resolved.is_file()
            or not _inside(root, resolved)
            or _has_symlink_component(root, resolved)
        ):
            return None
        return resolved.relative_to(root).as_posix()
    except ValueError:
        return None
    except OSError:
        return None


def _safe_fence_summary(value: Any, *, evidence_dir: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "unknown", "reason": "unstructured_protective_fence_result"}
    allowed = {
        "status", "exitCode", "reportPath", "reportSha256", "fenceReportPath", "fenceReportSha256",
        "generationId", "envId", "fencePurpose", "databaseVerified", "rpcVerified",
    }
    summary: dict[str, Any] = {}
    for key in allowed:
        if key not in value or key in {"reportPath", "fenceReportPath", "reportSha256", "fenceReportSha256"}:
            continue
        summary[key] = value[key]
    safe_reasons = {
        "protective_fence_runner_unavailable",
        "protective_fence_timeout",
        "protective_fence_nonzero_exit",
        "protective_fence_output_invalid",
    }
    if value.get("reason") in safe_reasons:
        summary["reason"] = value["reason"]
    for path_key, digest_key in (("reportPath", "reportSha256"), ("fenceReportPath", "fenceReportSha256")):
        if path_key not in value and digest_key not in value:
            continue
        relative = _safe_evidence_reference_path(value.get(path_key), evidence_dir)
        digest = value.get(digest_key)
        if relative is None or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            continue
        try:
            raw = evidence_dir.joinpath(*PurePosixPath(relative).parts).read_bytes()
        except OSError:
            continue
        if sha256_bytes(raw) != digest:
            continue
        summary[path_key] = relative
        summary[digest_key] = digest
    if "exitCode" in summary and (isinstance(summary["exitCode"], bool) or not isinstance(summary["exitCode"], int)):
        summary.pop("exitCode")
    if summary.get("status") not in {"protected", "failed", "unknown", "blocked"}:
        summary["status"] = "unknown"
    cleanup = value.get("processTreeCleanup")
    if isinstance(cleanup, dict):
        allowed_cleanup_status = {"not_started", "stopped", "unknown", "owned_process_group_unverified", "owned_process_group_unavailable"}
        if (
            cleanup.get("status") in allowed_cleanup_status
            and isinstance(cleanup.get("directChildExited"), bool)
            and cleanup.get("descendants") in {"not_applicable", "stopped", "unknown"}
            and isinstance(cleanup.get("treeExitConfirmed"), bool)
        ):
            summary["processTreeCleanup"] = {
                "status": cleanup["status"],
                "directChildExited": cleanup["directChildExited"],
                "descendants": cleanup["descendants"],
                "treeExitConfirmed": cleanup["treeExitConfirmed"],
            }
    if summary.get("status") == "protected":
        generation_id = summary.get("generationId")
        valid_generation = isinstance(generation_id, str) and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            generation_id,
            re.IGNORECASE,
        ) is not None
        required_refs = all(key in summary for key in ("reportPath", "reportSha256", "fenceReportPath", "fenceReportSha256"))
        if not (
            summary.get("exitCode") == 0
            and summary.get("fencePurpose") == "protective_only"
            and summary.get("envId") == "bef-env-a"
            and valid_generation
            and summary.get("databaseVerified") is True
            and summary.get("rpcVerified") is True
            and required_refs
        ):
            summary["status"] = "unknown"
            summary["reason"] = "protective_fence_proof_incomplete"
    return summary


def run_sc011_protective_attempt_once(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Launch one bounded protective-fence CLI attempt without a fallback callback.

    This intentionally does not call ``run_sc011_orchestrator_bounded``: a
    protective attempt that fails must be reported unknown, not recursively
    start another protective attempt.
    """

    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part or "\x00" in part for part in command)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("SC-011 one-shot protective runner arguments are invalid")
    popen_options: dict[str, Any] = {
        "cwd": cwd,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "text": True,
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True
    try:
        process = subprocess.Popen(command, **popen_options)
    except (OSError, ValueError):
        return {"status": "unknown", "reason": "protective_fence_runner_unavailable"}
    try:
        stdout, _discarded_stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        cleanup = terminate_owned_process_tree(process)
        try:
            stdout, _discarded_stderr = process.communicate(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            stdout = ""
        del stdout
        return {
            "status": "unknown",
            "reason": "protective_fence_timeout",
            "exitCode": process.poll(),
            "processTreeCleanup": cleanup,
        }
    if process.returncode != 0:
        cleanup = terminate_owned_process_tree(process)
        return {
            "status": "unknown",
            "reason": "protective_fence_nonzero_exit",
            "exitCode": process.returncode,
            "processTreeCleanup": cleanup,
        }
    try:
        payload = json.loads(stdout.strip())
    except (json.JSONDecodeError, TypeError):
        return {"status": "unknown", "reason": "protective_fence_output_invalid", "exitCode": process.returncode}
    if not isinstance(payload, dict):
        return {"status": "unknown", "reason": "protective_fence_output_invalid", "exitCode": process.returncode}
    for key in ("reportPath", "fenceReportPath"):
        path = payload.get(key)
        if isinstance(path, str):
            candidate = Path(path)
            payload[key] = candidate if candidate.is_absolute() else cwd / candidate
    return payload


def run_sc011_orchestrator_bounded(
    command: list[str],
    *,
    cwd: Path,
    evidence_dir: Path,
    timeout_seconds: float,
    protective_fence: Any,
) -> dict[str, Any]:
    """Run the adapter-owned orchestrator and fence after every abnormal exit.

    Raw stdout and stderr are never persisted because subprocess diagnostics may
    contain local configuration. The stable recovery file records only a
    command digest, stop status, and a sanitized protective-fence summary.
    """

    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part or "\x00" in part for part in command)
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or evidence_dir.is_symlink()
    ):
        raise ValueError("SC-011 bounded runner arguments are invalid")
    popen_options: dict[str, Any] = {
        "cwd": cwd,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_options["start_new_session"] = True

    process: subprocess.Popen[str] | None = None
    outcome = "launch_failed"
    cleanup: dict[str, Any] = {"status": "not_started", "directChildExited": None, "descendants": "not_applicable", "treeExitConfirmed": False}
    exit_code: int | None = None
    stdout = ""
    try:
        process = subprocess.Popen(command, **popen_options)
        try:
            stdout, _discarded_stderr = process.communicate(timeout=timeout_seconds)
            exit_code = process.returncode
            outcome = "completed" if exit_code == 0 else "nonzero_exit"
            if outcome != "completed":
                cleanup = terminate_owned_process_tree(process)
        except subprocess.TimeoutExpired:
            outcome = "outer_timeout"
            cleanup = terminate_owned_process_tree(process)
            try:
                stdout, _discarded_stderr = process.communicate(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                stdout = ""
            exit_code = process.poll()
    except OSError:
        outcome = "launch_failed"
        if process is not None:
            cleanup = terminate_owned_process_tree(process)
            exit_code = process.poll()
    except BaseException:
        outcome = "adapter_exception"
        if process is not None:
            cleanup = terminate_owned_process_tree(process)
        try:
            protective = _safe_fence_summary(protective_fence(), evidence_dir=evidence_dir)
        except BaseException:
            protective = {"status": "unknown", "reason": "protective_fence_attempt_failed"}
        report = {
            "schemaVersion": "bef-sc011-outer-recovery/v1",
            "boundary": "resource-data",
            "scenarioId": SCENARIO_ID,
            "operationId": None,
            "outcome": outcome,
            "runnerExitCode": process.poll() if process is not None else None,
            "processTreeCleanup": cleanup,
            "protectiveFenceAttempted": True,
            "protectiveFence": protective,
            "gateStatus": "unknown",
        }
        recovery_path = evidence_dir / "outer-timeout-recovery.json"
        digest = _write_json_new(recovery_path, report)
        raise

    if outcome == "completed":
        return {"status": "completed", "exitCode": exit_code, "stdout": stdout}

    # This is deliberately attempted even if the owned child tree could not be
    # confirmed stopped. Fencing revokes new admissions but is not a reset and
    # cannot turn an unknown in-flight effect into success.
    try:
        protective = _safe_fence_summary(protective_fence(), evidence_dir=evidence_dir)
    except BaseException:
        protective = {"status": "unknown", "reason": "protective_fence_attempt_failed"}
    report = {
        "schemaVersion": "bef-sc011-outer-recovery/v1",
        "boundary": "resource-data",
        "scenarioId": SCENARIO_ID,
        "operationId": None,
        "outcome": outcome,
        "runnerExitCode": exit_code,
        "processTreeCleanup": cleanup,
        "protectiveFenceAttempted": True,
        "protectiveFence": protective,
        "gateStatus": "unknown",
    }
    recovery_path = evidence_dir / "outer-timeout-recovery.json"
    digest = _write_json_new(recovery_path, report)
    return {
        "status": "blocked",
        "reason": outcome,
        "exitCode": exit_code,
        "recoveryPath": recovery_path,
        "recoverySha256": digest,
        "processTreeCleanup": cleanup,
        "protectiveFence": protective,
        "gateStatus": "unknown",
    }


def _resource_payloads(evidence: Any) -> tuple[dict[str, Any], ...]:
    return tuple(item.payload for item in evidence.resource_artifacts())


def _reference_payload(evidence: Any, reference: Any) -> dict[str, Any] | None:
    if not isinstance(reference, dict):
        return None
    path = reference.get("path")
    digest = reference.get("sha256")
    if not isinstance(path, str) or not _DIGEST.fullmatch(str(digest)):
        return None
    try:
        relative = _require_safe_relative(path)
        raw_path = evidence.directory.joinpath(*relative.parts)
        if raw_path.is_symlink() or not raw_path.is_file() or not _inside(evidence.directory, raw_path):
            return None
        raw = raw_path.read_bytes()
        if sha256_bytes(raw) != digest:
            return None
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) and _secret_free(payload) else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _indexed_payload(evidence: Any, relative_path: str) -> dict[str, Any] | None:
    for artifact in evidence.artifacts:
        if artifact.relative_path == relative_path:
            return artifact.payload
    return None


def _sample_for(evidence: Any, variant: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    for wrapper in _resource_payloads(evidence):
        if wrapper.get("schemaVersion") != OBSERVATION_SCHEMA or wrapper.get("variantId") != variant:
            continue
        sample = _reference_payload(evidence, wrapper.get("sampleArtifact"))
        if (
            sample
            and sample.get("schemaVersion") == SAMPLER_SCHEMA
            and wrapper.get("rawSampleSchemaVersion") == sample.get("schemaVersion")
            and sample.get("scenarioId") == SCENARIO_ID
        ):
            return wrapper, sample
        raw_ref = wrapper.get("rawArtifact")
        raw = _reference_payload(evidence, raw_ref)
        if raw and raw.get("schemaVersion") == MISSING_SAMPLER_SCHEMA:
            return wrapper, raw
    return None


def _workload_for(evidence: Any, relative_path: str) -> dict[str, Any] | None:
    payload = _indexed_payload(evidence, relative_path)
    if (
        isinstance(payload, dict)
        and payload.get("schemaVersion") == WORKLOAD_SCHEMA
        and payload.get("scenarioId") == SCENARIO_ID
        and payload.get("boundary") == "resource-workload"
    ):
        return payload
    return None


def _workload_raw_artifacts(evidence: Any, relative_path: str, workload: dict[str, Any]) -> tuple[Any, ...] | None:
    references = workload.get("artifacts")
    if not isinstance(references, list):
        return None
    by_path = {item.relative_path: item for item in evidence.artifacts}
    base = PurePosixPath(relative_path).parent
    selected: list[Any] = []
    seen: set[str] = set()
    for reference in references:
        if not isinstance(reference, dict):
            return None
        try:
            source = _require_safe_relative(reference.get("path"))
        except ValueError:
            return None
        boundary = reference.get("boundary")
        digest = reference.get("sha256")
        if not isinstance(boundary, str) or not _DIGEST.fullmatch(str(digest)):
            return None
        if boundary == "runtime-manifest":
            continue
        indexed_path = (base / source).as_posix()
        if indexed_path in seen:
            return None
        seen.add(indexed_path)
        item = by_path.get(indexed_path)
        if item is None or item.boundary != boundary or item.sha256 != digest:
            return None
        selected.append(item)
    return tuple(selected)


def _successful_purchase_is_bound_to_raw_artifacts(
    evidence: Any, phase: str, workload: dict[str, Any], operation: dict[str, Any],
) -> bool:
    operation_id = workload.get("operationId")
    environment = workload.get("environment")
    generation = environment.get("generation") if isinstance(environment, dict) else None
    env_id = environment.get("envId") if isinstance(environment, dict) else None
    generation_id = generation.get("generationId") if isinstance(generation, dict) else None
    participant_id = generation.get("participantId") if isinstance(generation, dict) else None
    payer = generation.get("payerAddress") if isinstance(generation, dict) else None
    transaction_hash = operation.get("transactionHash")
    manifest_x402 = evidence.manifest.get("x402") if isinstance(evidence.manifest, dict) else None
    if not isinstance(manifest_x402, dict):
        return False
    if (
        not isinstance(operation_id, str)
        or not isinstance(env_id, str)
        or not isinstance(generation_id, str)
        or not isinstance(participant_id, str)
        or not isinstance(payer, str)
        or not re.fullmatch(r"0x[0-9a-f]{40}", payer, re.IGNORECASE)
        or not isinstance(transaction_hash, str)
        or not re.fullmatch(r"0x[0-9a-f]{64}", transaction_hash, re.IGNORECASE)
    ):
        return False
    artifacts = _workload_raw_artifacts(evidence, f"{phase}-purchase/workload.json", workload)
    if artifacts is None:
        return False

    purchase_http: list[dict[str, Any]] = []
    delivered_byte_lengths: list[int] = []
    database_by_query: dict[str, list[Any]] = {}
    receipts: list[dict[str, Any]] = []
    for artifact in artifacts:
        payload = artifact.payload
        if artifact.boundary == "actual-tool-http" and payload.get("operationId") == operation_id:
            request = payload.get("request")
            response = payload.get("response")
            if (
                payload.get("schemaVersion") == "bef-http-observation/v1"
                and payload.get("variantId") is None
                and isinstance(request, dict)
                and request.get("method") == "POST"
                and request.get("path") == f"/tools/{env_id}/purchase"
                and isinstance(request.get("headers"), dict)
                and next((value for key, value in request["headers"].items() if str(key).lower() == "x-bef-generation"), None) == generation_id
                and isinstance(request.get("body"), dict)
                and request["body"].get("resourceId") == evidence.manifest.get("x402", {}).get("resourceId")
                and isinstance(response, dict)
                and response.get("status") == 200
                and isinstance(response.get("body"), dict)
                and response["body"].get("operationId") == operation_id
            ):
                response_body = response["body"]
                raw_b64 = response.get("bodyBase64")
                resource_b64 = response_body.get("contentBytes")
                resource_sha = response_body.get("contentHash")
                if (
                    not isinstance(raw_b64, str)
                    or not isinstance(resource_b64, str)
                    or not isinstance(resource_sha, str)
                    or response_body.get("resourceId") != manifest_x402.get("resourceId")
                    or response_body.get("contentType") != "application/json"
                ):
                    return False
                try:
                    raw_response = json.loads(base64.b64decode(raw_b64, validate=True).decode("utf-8"))
                    delivered_bytes = base64.b64decode(resource_b64, validate=True)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    return False
                delivered_sha = sha256_bytes(delivered_bytes)
                if (
                    not isinstance(raw_response, dict)
                    or not _secret_free(raw_response)
                    or raw_response.get("operationId") != operation_id
                    or raw_response.get("contentHash") != resource_sha
                    or raw_response.get("resourceId") != response_body.get("resourceId")
                    or raw_response.get("contentType") != response_body.get("contentType")
                    or raw_response.get("contentBytes") != resource_b64
                    or delivered_sha.lower() != resource_sha.lower()
                    or delivered_sha.lower() != str(manifest_x402.get("resourceSha256", "")).lower()
                ):
                    return False
                delivered_byte_lengths.append(len(delivered_bytes))
                purchase_http.append(payload)
        elif artifact.boundary == "readonly-database":
            query_name = payload.get("queryName")
            if query_name in {
                "generation-by-id", "operation-by-id", "payments-by-operation",
                "deliveries-by-operation", "denials-by-generation", "x402-observations-by-operation",
            }:
                # Generation creation and the initial payment challenge may
                # have no correlated operation. They are not settlement
                # snapshots; retain only reads explicitly bound to this op.
                if payload.get("operationId") is None:
                    continue
                if (
                    payload.get("schemaVersion") != "bef-db-observation/v1"
                    or payload.get("boundary") != "readonly-database"
                    or payload.get("readOnly") is not True
                    or not isinstance(payload.get("databaseRole"), str)
                    or not payload["databaseRole"].strip()
                    or payload.get("operationId") != operation_id
                    or payload.get("variantId") is not None
                    or payload.get("envId") != env_id
                    or payload.get("generationId") != generation_id
                    or payload.get("transactionReadOnly") != "on"
                    or not isinstance(payload.get("rows"), list)
                ):
                    return False
                database_by_query.setdefault(query_name, []).append(artifact)
        elif artifact.boundary == "local-chain-readonly-proxy" and payload.get("operationId") == operation_id:
            if (
                payload.get("schemaVersion") == "bef-rpc-observation/v1"
                and payload.get("method") == "eth_getTransactionReceipt"
                and payload.get("variantId") is None
            ):
                receipts.append(payload)

    if len(purchase_http) != 1 or len(receipts) != 1:
        return False
    required_queries = {
        "generation-by-id", "operation-by-id", "payments-by-operation",
        "deliveries-by-operation", "denials-by-generation", "x402-observations-by-operation",
    }
    operation_snapshots = database_by_query.get("operation-by-id", [])
    if not operation_snapshots:
        return False
    terminal_operation_snapshots = []
    expected_status = operation.get("observedStatus")
    for artifact in operation_snapshots:
        rows = artifact.payload.get("rows")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            continue
        row = rows[0]
        if row.get("operation_id") != operation_id:
            return False
        has_settlement_identity = row.get("transaction_hash") is not None or row.get("receipt_status") == "success"
        if has_settlement_identity and (
            row.get("status") != expected_status
            or not isinstance(row.get("transaction_hash"), str)
            or row["transaction_hash"].lower() != transaction_hash.lower()
            or row.get("receipt_status") != "success"
        ):
            return False
        if (
            row.get("status") == expected_status
            and isinstance(row.get("transaction_hash"), str)
            and row["transaction_hash"].lower() == transaction_hash.lower()
            and row.get("receipt_status") == "success"
        ):
            terminal_operation_snapshots.append(artifact)
    # The latest operation-by-id observation must independently show the
    # terminal settlement. Earlier challenge/lookup snapshots may be pending.
    terminal = terminal_operation_snapshots[-1] if terminal_operation_snapshots else None
    if terminal is None or operation_snapshots[-1] is not terminal:
        return False
    terminal_path = terminal.relative_path
    operation_suffix = "operation-by-id.json"
    if not terminal_path.endswith(operation_suffix):
        return False
    group_prefix = terminal_path[:-len(operation_suffix)]
    selected_group: dict[str, dict[str, Any]] = {}
    for query_name in required_queries:
        expected_path = f"{group_prefix}{query_name}.json"
        matches = [artifact for artifact in database_by_query.get(query_name, []) if artifact.relative_path == expected_path]
        if len(matches) != 1:
            return False
        selected_group[query_name] = matches[0].payload
    if any(
        payload.get("operationId") != operation_id
        or payload.get("envId") != env_id
        or payload.get("generationId") != generation_id
        or payload.get("variantId") is not None
        or payload.get("transactionReadOnly") != "on"
        for payload in selected_group.values()
    ):
        return False
    rows = {query: payload["rows"] for query, payload in selected_group.items()}
    generation_rows = rows["generation-by-id"]
    operation_rows = rows["operation-by-id"]
    payment_rows = rows["payments-by-operation"]
    delivery_rows = rows["deliveries-by-operation"]
    if (
        len(generation_rows) != 1
        or len(operation_rows) != 1
        or len(payment_rows) != 1
        or len(delivery_rows) != 1
        or rows["denials-by-generation"]
    ):
        return False
    db_generation, db_operation = generation_rows[0], operation_rows[0]
    payment, delivery = payment_rows[0], delivery_rows[0]
    x402_rows = rows["x402-observations-by-operation"]
    if not all(isinstance(row, dict) for row in (db_generation, db_operation, payment, delivery)):
        return False
    if not all(isinstance(row, dict) and row.get("operation_id") == operation_id for row in x402_rows):
        return False
    asset = manifest_x402.get("asset")
    capabilities = [
        artifact.payload for artifact in artifacts
        if artifact.boundary == "private-admin-http"
        and artifact.payload.get("schemaVersion") == "bef-http-observation/v1"
        and artifact.payload.get("boundary") == "private-admin-http"
        and isinstance(artifact.payload.get("request"), dict)
        and artifact.payload["request"].get("method") == "GET"
        and artifact.payload["request"].get("path") == f"/internal/admin/environments/{env_id}/probe-capabilities"
    ]
    if len(capabilities) != 1:
        return False
    capability = capabilities[0]
    capability_response = capability.get("response")
    capability_body = capability_response.get("body") if isinstance(capability_response, dict) else None
    capability_services = capability_body.get("services") if isinstance(capability_body, dict) else None
    facilitator = capability_services.get("facilitator") if isinstance(capability_services, dict) else None
    pay_to = facilitator.get("address") if isinstance(facilitator, dict) else None
    amount = manifest_x402.get("amount")
    network = manifest_x402.get("network")
    resource_sha = manifest_x402.get("resourceSha256")
    if (
        not all(isinstance(value, str) and value for value in (asset, pay_to, amount, network, resource_sha))
        or capability.get("operationId") is not None
        or capability.get("variantId") is not None
        or not isinstance(capability_response, dict)
        or capability_response.get("status") != 200
        or not _secret_free(capability)
        or not re.fullmatch(r"0x[0-9a-f]{40}", asset, re.IGNORECASE)
        or not re.fullmatch(r"0x[0-9a-f]{40}", pay_to, re.IGNORECASE)
        or not _DIGEST.fullmatch(resource_sha.lower())
        or not re.fullmatch(r"[0-9]+", amount)
        or int(amount, 10) <= 0
    ):
        return False
    receipt = receipts[0]
    try:
        delivered_content_bytes = int(delivery.get("content_bytes"))
    except (TypeError, ValueError):
        return False
    result = receipt.get("result")
    params = receipt.get("params")
    if (
        receipt.get("endpointBoundary") != "local-chain-readonly-proxy"
        or receipt.get("environmentId") != env_id
        or not isinstance(params, list)
        or params != [transaction_hash]
        or not isinstance(result, dict)
        or not isinstance(result.get("transactionHash"), str)
        or result["transactionHash"].lower() != transaction_hash.lower()
        or str(result.get("status", "")).lower() != "0x1"
        or not isinstance(result.get("logs"), list)
    ):
        return False
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    payer_topic = "0x" + "0" * 24 + payer[2:].lower()
    pay_to_topic = "0x" + "0" * 24 + pay_to[2:].lower() if re.fullmatch(r"0x[0-9a-f]{40}", pay_to, re.IGNORECASE) else ""
    try:
        amount_value = int(amount, 10)
    except ValueError:
        return False
    transfer_found = False
    for log in result["logs"]:
        if (
            not isinstance(log, dict)
            or not isinstance(log.get("topics"), list)
            or len(log["topics"]) < 3
            or not isinstance(log.get("address"), str)
            or log["address"].lower() != asset.lower()
            or str(log["topics"][0]).lower() != transfer_topic
            or str(log["topics"][1]).lower() != payer_topic
            or str(log["topics"][2]).lower() != pay_to_topic
            or not isinstance(log.get("data"), str)
            or not re.fullmatch(r"0x[0-9a-f]+", log["data"], re.IGNORECASE)
        ):
            continue
        try:
            if int(log["data"], 16) == amount_value:
                transfer_found = True
                break
        except ValueError:
            continue
    return bool(
        db_generation.get("generation_id") == generation_id
        and db_generation.get("env_id") == env_id
        and db_generation.get("participant_id") == participant_id
        and str(db_generation.get("payer_address", "")).lower() == payer.lower()
        and db_generation.get("status") == "active"
        and db_operation.get("operation_id") == operation_id
        and db_operation.get("env_id") == env_id
        and db_operation.get("generation_id") == generation_id
        and db_operation.get("participant_id") == participant_id
        and db_operation.get("operation_kind") == "purchase"
        and db_operation.get("status") == operation.get("observedStatus")
        and isinstance(db_operation.get("transaction_hash"), str)
        and db_operation["transaction_hash"].lower() == transaction_hash.lower()
        and db_operation.get("receipt_status") == "success"
        and payment.get("operation_id") == operation_id
        and payment.get("env_id") == env_id
        and payment.get("generation_id") == generation_id
        and str(payment.get("payer_address", "")).lower() == payer.lower()
        and payment.get("network") == network
        and str(payment.get("asset_address", "")).lower() == asset.lower()
        and str(payment.get("amount_units")) == amount
        and str(payment.get("facilitator_address", "")).lower() == pay_to.lower()
        and str(payment.get("transaction_hash", "")).lower() == transaction_hash.lower()
        and payment.get("receipt_status") == "success"
        and delivery.get("operation_id") == operation_id
        and delivery.get("resource_id") == manifest_x402.get("resourceId")
        and delivery.get("content_sha256") == resource_sha
        and isinstance(delivery.get("content_bytes"), (str, int))
        and not isinstance(delivery.get("content_bytes"), bool)
        and len(delivered_byte_lengths) == 1
        and delivered_content_bytes == delivered_byte_lengths[0]
        and transfer_found
    )


def _purchase_operation_inventory_valid(evidence: Any) -> bool:
    cold = _workload_for(evidence, "cold-purchase/workload.json")
    warm = _workload_for(evidence, "warm-purchase/workload.json")
    if not isinstance(cold, dict) or not isinstance(warm, dict):
        return False
    purchase_ids: set[str] = set()
    actual_operations: list[dict[str, Any]] = []
    for phase, report in (("cold", cold), ("warm", warm)):
        environment = report.get("environment")
        generation = environment.get("generation") if isinstance(environment, dict) else None
        purchase = report.get("purchaseOperation")
        operation_id = report.get("operationId")
        if (
            report.get("phase") != phase
            or report.get("mode") != "purchase"
            or report.get("status") != "captured"
            or not isinstance(environment, dict)
            or environment.get("envId") != "bef-env-a"
            or not isinstance(generation, dict)
            or not isinstance(purchase, dict)
            or purchase.get("operationId") != operation_id
            or purchase.get("kind") != "purchase"
            or purchase.get("receiptStatus") != "success"
            or not isinstance(operation_id, str)
        ):
            return False
        purchase_ids.add(operation_id)
        records = report.get("operations")
        if (
            not isinstance(records, list)
            or len(records) != 1
            or not isinstance(records[0], dict)
            or records[0] != purchase
            or records[0].get("operationId") != operation_id
            or records[0].get("kind") != "purchase"
            or records[0].get("receiptStatus") != "success"
            or not isinstance(records[0].get("observedStatus"), str)
            or not records[0]["observedStatus"].strip()
            or not isinstance(records[0].get("idempotencyKeyHash"), str)
            or not _DIGEST.fullmatch(records[0]["idempotencyKeyHash"])
        ):
            return False
        if not _successful_purchase_is_bound_to_raw_artifacts(evidence, phase, report, purchase):
            return False
        actual_operations.extend(records)
    if len(purchase_ids) != 2:
        return False
    indexed_operations = evidence.index.get("operations") if isinstance(evidence.index, dict) else None
    if not isinstance(indexed_operations, list):
        return False
    if indexed_operations != actual_operations:
        return False
    indexed_ids = {item.get("operationId") for item in indexed_operations if isinstance(item, dict)}
    if not purchase_ids.issubset(indexed_ids):
        return False
    for item in evidence.artifacts:
        operation_id = item.payload.get("operationId")
        if operation_id is not None and operation_id not in purchase_ids:
            return False
    for variant, expected_id in (
        ("empty_dedicated_cache", cold.get("operationId")),
        ("warm_cache", warm.get("operationId")),
        ("provider_cu_unavailable", cold.get("operationId")),
    ):
        rows = [
            item.payload for item in evidence.resource_artifacts()
            if item.payload.get("schemaVersion") == OBSERVATION_SCHEMA and item.payload.get("variantId") == variant
        ]
        if len(rows) != 1:
            return False
        if rows[0].get("operationId") != expected_id:
            return False
    read = _workload_for(evidence, "guardrail-read/workload.json")
    return isinstance(read, dict) and read.get("operationId") is None and read.get("variantId") == "guardrail_exceeded"


def _source_identity_matches(evidence: Any, orchestration: dict[str, Any]) -> bool:
    cold = _workload_for(evidence, "cold-purchase/workload.json")
    warm = _workload_for(evidence, "warm-purchase/workload.json")
    read = _workload_for(evidence, "guardrail-read/workload.json")
    if not all(isinstance(value, dict) for value in (cold, warm, read)):
        return False
    fields = ("manifestSha256", "applicationSourceSha256", "probeSourceSha256", "runtimeVersions", "sourceBlock")
    if any(cold.get(key) != warm.get(key) or cold.get(key) != read.get(key) for key in fields):
        return False
    index = evidence.index
    if (
        not isinstance(index, dict)
        or cold.get("manifestSha256") != evidence.manifest_sha256
        or orchestration.get("manifestSha256") != evidence.manifest_sha256
        or index.get("applicationSourceSha256") != cold.get("applicationSourceSha256")
        or index.get("probeSourceSha256") != cold.get("probeSourceSha256")
        or index.get("runtimeVersions") != cold.get("runtimeVersions")
        or index.get("sourceBlock") != cold.get("sourceBlock")
    ):
        return False
    source = evidence.manifest.get("source")
    if not isinstance(source, dict):
        return False
    recorded = index.get("sourceBlock")
    if (
        not isinstance(recorded, dict)
        or not isinstance(recorded.get("number"), str)
        or not isinstance(recorded.get("hash"), str)
    ):
        return False
    if recorded.get("number", "").lower() != str(source.get("blockNumber", "")).lower():
        return False
    if recorded.get("hash", "").lower() != str(source.get("blockHash", "")).lower():
        return False
    identity = _indexed_payload(evidence, "guardrail-read/identity.json")
    return (
        isinstance(identity, dict)
        and identity.get("manifestSha256") == evidence.manifest_sha256
        and identity.get("applicationSourceSha256") == cold.get("applicationSourceSha256")
        and identity.get("probeSourceSha256") == cold.get("probeSourceSha256")
        and evidence.environment_id == "bef-env-a"
        and evidence.generation_id == identity.get("generationId")
    )


def _sample_metrics_valid(
    sample: dict[str, Any], guardrails: dict[str, Any], expected_manifest_sha256: str | None = None,
) -> bool:
    status = sample.get("status")
    if status == "blocked":
        issues = sample.get("issues")
        issue_codes = [item.get("code") for item in issues if isinstance(item, dict)] if isinstance(issues, list) else []
        if (
            sample.get("gateStatus") != "not_established_by_resource_trial_collector"
            or len(issue_codes) != len(_UNRESOLVED_SAMPLER_METADATA)
            or not all(isinstance(code, str) for code in issue_codes)
            or set(issue_codes) != _UNRESOLVED_SAMPLER_METADATA
        ):
            return False
    elif status not in {"captured", "guardrail_exceeded"}:
        return False
    manifest = sample.get("manifest")
    sample_guardrails = sample.get("guardrails")
    raw_guardrails = sample_guardrails.get("manifestValues") if isinstance(sample_guardrails, dict) else None
    expected_guardrail_keys = (
        "maxTrialSeconds", "maxAnvilMemoryBytesEach", "maxApiMemoryBytes", "maxDatabaseMemoryBytes",
        "maxSourceCallsPerTrial", "maxEvidenceBytesPerTrial", "maxAnvilCacheBytesEach",
        "maxResourceReadOverrunSeconds",
    )
    expected_sample_guardrails = {key: guardrails[key] for key in expected_guardrail_keys if key in guardrails}
    if (
        not isinstance(manifest, dict)
        or manifest.get("manifestPath") != SAMPLER_MANIFEST_PATH
        or not _DIGEST.fullmatch(str(manifest.get("manifestSha256")))
        or expected_manifest_sha256 is not None
        and manifest.get("manifestSha256") != expected_manifest_sha256
        or raw_guardrails != expected_sample_guardrails
    ):
        return False
    host = sample.get("host")
    if (
        not isinstance(host, dict)
        or host.get("status") != "observed"
        or not isinstance(host.get("operatingSystem"), str)
        or not host["operatingSystem"].strip()
        or not isinstance(host.get("architecture"), str)
        or not host["architecture"].strip()
    ):
        return False
    elapsed_ns = _number(sample.get("elapsedMonotonicNanoseconds"))
    maximum_seconds = _number(guardrails.get("maxTrialSeconds"))
    if elapsed_ns is None or maximum_seconds is None or elapsed_ns < 0 or elapsed_ns > maximum_seconds * 1_000_000_000:
        return False
    containers = sample.get("containers")
    expected_services = {"postgres", "source-proxy", "anvil-a", "anvil-b", "local-proxy-a", "local-proxy-b", "facilitator-a", "facilitator-b", "api", "gateway"}
    if not isinstance(containers, list) or {row.get("service") for row in containers if isinstance(row, dict)} != expected_services:
        return False
    for row in containers:
        if not isinstance(row, dict) or row.get("cgroupStatus") != "observed" or row.get("cpuUsageStatus") != "observed":
            return False
        if _number(row.get("cpuUsageDeltaNanoseconds")) is None or row["cpuUsageDeltaNanoseconds"] < 0:
            return False
        cpu_check = row.get("cpuLimitCheck")
        if not isinstance(cpu_check, dict) or cpu_check.get("status") != "compatible":
            return False
        if row.get("service") in {"anvil-a", "anvil-b", "api", "postgres"}:
            current_max = _number(row.get("memoryCurrentWindowMaximumBytes"))
            peak = _number(row.get("memoryPeakBytesSinceContainerStart"))
            sample_count = row.get("memoryCurrentWindowSampleCount")
            if current_max is None or peak is None or peak < current_max or not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count < 2:
                return False
            if row.get("memoryPeakScope") != "since-container-cgroup-creation":
                return False
            limit_name = {"anvil-a": "maxAnvilMemoryBytesEach", "anvil-b": "maxAnvilMemoryBytesEach", "api": "maxApiMemoryBytes", "postgres": "maxDatabaseMemoryBytes"}[row["service"]]
            limit = _number(guardrails.get(limit_name))
            check = row.get("memoryLimitCheck")
            if (
                limit is None
                or current_max > limit
                or not isinstance(check, dict)
                or check.get("status") != "within_limit"
                or check.get("observedBytes") != current_max
                or check.get("limitBytes") != limit
            ):
                return False
            if (
                row.get("dockerConfiguredMemoryLimitMatchesPolicy") is not True
                or row.get("policyMemoryLimitBytes") != limit
                or row.get("cgroupMemoryLimitBytes") != limit
            ):
                return False
    source = sample.get("sourceProxy")
    window = source.get("windowDelta") if isinstance(source, dict) else None
    calls = window.get("sourceCallsReserved") if isinstance(window, dict) else None
    source_limit = _number(guardrails.get("maxSourceCallsPerTrial"))
    if not isinstance(window, dict) or window.get("status") != "observed" or not isinstance(calls, int) or isinstance(calls, bool) or calls < 0:
        return False
    if source_limit is None or calls > source_limit or _monotonic_counter_delta(source) != calls:
        return False
    artifacts = sample.get("artifactDirectory")
    check = artifacts.get("guardrailCheck") if isinstance(artifacts, dict) else None
    measured = check.get("observedMaximumBytes") if isinstance(check, dict) else None
    byte_limit = _number(guardrails.get("maxEvidenceBytesPerTrial"))
    return (
        isinstance(check, dict)
        and check.get("status") == "within_limit"
        and isinstance(measured, int)
        and not isinstance(measured, bool)
        and measured >= 0
        and byte_limit is not None
        and measured <= byte_limit
    )


def _blocked_sampler_metadata_is_independently_proven(
    sample: dict[str, Any],
    *,
    cache_provenance: bool,
    source_count: bool,
    guardrail_stop: bool,
    provider_cu_unknown: bool,
) -> bool:
    if sample.get("status") != "blocked":
        return True
    issues = sample.get("issues")
    codes = [item.get("code") for item in issues if isinstance(item, dict)] if isinstance(issues, list) else []
    if (
        sample.get("gateStatus") != "not_established_by_resource_trial_collector"
        or len(codes) != len(_UNRESOLVED_SAMPLER_METADATA)
        or set(codes) != _UNRESOLVED_SAMPLER_METADATA
    ):
        return False
    independent_proofs = {
        "cold_warm_cache_provenance_unavailable": cache_provenance,
        "source_call_trial_attribution_unavailable": source_count,
        "independent_generation_fence_not_verified": guardrail_stop,
        "provider_compute_units_unobservable": provider_cu_unknown,
    }
    return all(independent_proofs[code] for code in codes)


def _cache_inventory_index(
    inventories: Any, *, maximum_bytes: int, expected_cache_paths: dict[str, str]
) -> dict[tuple[str, str], tuple[str, int]] | None:
    if (
        not isinstance(inventories, dict)
        or set(inventories) != set(expected_cache_paths)
        or isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
    ):
        return None
    entries: dict[tuple[str, str], tuple[str, int]] = {}
    for cache_name, inventory in inventories.items():
        if (
            not isinstance(cache_name, str)
            or not isinstance(inventory, dict)
            or inventory.get("status") != "observed"
            or inventory.get("pathRef") != expected_cache_paths.get(cache_name)
        ):
            return None
        files = inventory.get("files")
        byte_count = inventory.get("bytes")
        file_count = inventory.get("fileCount")
        if (
            not isinstance(files, list)
            or isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or not 0 <= byte_count <= maximum_bytes
            or isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or file_count != len(files)
        ):
            return None
        observed_bytes = 0
        for item in files:
            if not isinstance(item, dict):
                return None
            file_key = item.get("fileKey")
            digest = item.get("sha256")
            size = item.get("sizeBytes")
            if (
                not isinstance(file_key, str)
                or not _DIGEST.fullmatch(file_key)
                or not isinstance(digest, str)
                or not _DIGEST.fullmatch(digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
            ):
                return None
            key = (cache_name, file_key)
            if key in entries:
                return None
            entries[key] = (digest, size)
            observed_bytes += size
        if observed_bytes != byte_count:
            return None
    return entries


def _cache_inventory_diff(
    before: Any,
    after: Any,
    *,
    maximum_bytes: int,
    expected_cache_paths: dict[str, str],
) -> dict[str, Any] | None:
    old = _cache_inventory_index(before, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    new = _cache_inventory_index(after, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    if old is None or new is None:
        return None
    retained = {key for key, row in old.items() if new.get(key) == row}
    removed = set(old) - set(new)
    changed = {key for key in set(old) & set(new) if old[key] != new[key]}
    added = set(new) - set(old)
    return {
        "status": "observed",
        "beforeFileCount": len(old),
        "afterFileCount": len(new),
        "beforeHadEntries": bool(old),
        "retainedFileCount": len(retained),
        "removedFileCount": len(removed),
        "changedFileCount": len(changed),
        "addedFileCount": len(added),
        "allBeforeEntriesRetained": bool(old) and not removed and not changed,
    }


def _cache_diff_record_matches(record: Any, computed: dict[str, Any] | None) -> bool:
    if not isinstance(record, dict) or computed is None or record.get("status") != "observed":
        return False
    if any(record.get(name) is not value for name, value in (
        ("beforeHadEntries", computed["beforeHadEntries"]),
        ("allBeforeEntriesRetained", computed["allBeforeEntriesRetained"]),
    )):
        return False
    count_fields = (
        "beforeFileCount", "afterFileCount", "retainedFileCount",
        "removedFileCount", "changedFileCount", "addedFileCount",
    )
    return all(
        isinstance(record.get(name), int)
        and not isinstance(record.get(name), bool)
        and record.get(name) == computed[name]
        for name in count_fields
    )


def _cache_restart_provenance_valid(orchestration: Any, maximum_bytes: Any) -> bool:
    expected_names = {"anvil-a-state", "anvil-a-rpc"}
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        return False
    if not isinstance(orchestration, dict):
        return False

    cache_condition = orchestration.get("cacheCondition")
    if not isinstance(cache_condition, dict) or cache_condition.get("status") != "observed":
        return False
    warm_condition = cache_condition.get("warm")
    if not isinstance(warm_condition, dict) or any(warm_condition.get(name) is not True for name in (
        "sameBindRoots",
        "cacheSnapshotTakenAfterColdCleanupAndGracefulStop",
        "combinedPreparedCacheWasNonempty",
        "preparedEntriesRetainedAcrossRestart",
        "warmPurchaseCacheMutationsRecordedWithoutRetentionGate",
        "anvilProcessRecreated",
    )):
        return False

    roots = orchestration.get("cacheRoots")
    if not isinstance(roots, dict) or set(roots) != expected_names or not all(
        isinstance(value, str) and value for value in roots.values()
    ):
        return False
    root_parts: dict[str, tuple[str, ...]] = {}
    for cache_name, raw_path in roots.items():
        relative = PurePosixPath(raw_path)
        if (
            relative.is_absolute()
            or len(relative.parts) < 3
            or relative.parts[:2] != ("artifacts", "runs")
            or any(part in {".", ".."} for part in relative.parts)
        ):
            return False
        root_parts[cache_name] = relative.parts
    expected_cache_paths = roots
    expected_names = set(expected_cache_paths)
    expected_sources = {"state": roots["anvil-a-state"], "rpc": roots["anvil-a-rpc"]}
    state_parts, rpc_parts = root_parts["anvil-a-state"], root_parts["anvil-a-rpc"]
    if (
        state_parts == rpc_parts
        or state_parts[:len(rpc_parts)] == rpc_parts
        or rpc_parts[:len(state_parts)] == state_parts
    ):
        return False

    cold_binding = orchestration.get("coldAnvil")
    warm_binding = orchestration.get("warmAnvil")
    before_stop = orchestration.get("anvilABeforeWarmStop")
    after_stop = orchestration.get("anvilAAfterWarmStop")
    stop_outcome = orchestration.get("anvilAWarmStopOutcome")
    expanded_compose_sha = orchestration.get("expandedComposeSha256")
    if not all(isinstance(value, dict) for value in (cold_binding, warm_binding, before_stop, after_stop, stop_outcome)):
        return False
    cold_id = cold_binding.get("containerId")
    warm_id = warm_binding.get("containerId")
    stop_exit_code = stop_outcome.get("exitCode")
    if (
        not isinstance(cold_id, str)
        or not re.fullmatch(r"[0-9a-f]{12,64}", cold_id)
        or not isinstance(warm_id, str)
        or not re.fullmatch(r"[0-9a-f]{12,64}", warm_id)
        or cold_id == warm_id
        or cold_binding.get("state") != "running"
        or warm_binding.get("state") != "running"
        or before_stop.get("containerId") != cold_id
        or before_stop.get("state") != "running"
        or after_stop.get("containerId") != cold_id
        or after_stop.get("state") != "exited"
        or stop_outcome.get("containerId") != cold_id
        or stop_outcome.get("state") != "exited"
        or stop_outcome.get("status") != "observed"
        or isinstance(stop_exit_code, bool)
        or not isinstance(stop_exit_code, int)
        or stop_exit_code not in {0, 143}
        or stop_outcome.get("oomKilled") is not False
        or stop_outcome.get("errorEmpty") is not True
        or stop_outcome.get("gracefulStopVerified") is not True
    ):
        return False

    compose_sha = cold_binding.get("composeConfigSha256")
    if (
        not isinstance(expanded_compose_sha, str)
        or not _DIGEST.fullmatch(expanded_compose_sha)
        or compose_sha != expanded_compose_sha
        or warm_binding.get("composeConfigSha256") != compose_sha
        or orchestration.get("warmComposeConfigSha256") != compose_sha
    ):
        return False
    for binding_row in (cold_binding, warm_binding):
        sources = binding_row.get("sources")
        binding = binding_row.get("binding")
        if (
            sources != expected_sources
            or not isinstance(binding, dict)
            or binding.get("status") != "observed"
            or binding.get("bindMountWritable") is not True
            or binding.get("stateCacheHostPath") != roots["anvil-a-state"]
            or binding.get("rpcCacheHostPath") != roots["anvil-a-rpc"]
        ):
            return False

    cold_before = orchestration.get("coldCacheBeforeWorkload")
    cold_trial = orchestration.get("coldTrial")
    cold_after = cold_trial.get("cacheAfter") if isinstance(cold_trial, dict) else None
    cold_after_fence = orchestration.get("coldCacheAfterFence")
    warm_before_stop = orchestration.get("warmCacheBeforeGracefulStop")
    prepared = orchestration.get("warmCachePreparedAfterGracefulStop")
    warm_after_restart = orchestration.get("warmCacheAfterRestart")
    warm_before = orchestration.get("warmCacheBeforeWorkload")
    warm_trial = orchestration.get("warmTrial")
    warm_trial_before = warm_trial.get("cacheBefore") if isinstance(warm_trial, dict) else None
    warm_after = warm_trial.get("cacheAfter") if isinstance(warm_trial, dict) else None
    snapshots = (cold_before, cold_after, cold_after_fence, warm_before_stop, prepared, warm_after_restart, warm_before, warm_trial_before, warm_after)
    if not all(_cache_inventory_index(item, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths) is not None for item in snapshots):
        return False
    if any(
        cold_before[name].get("bytes") != 0 or cold_before[name].get("fileCount") != 0
        for name in expected_names
    ):
        return False

    prepared_entries = _cache_inventory_index(prepared, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    restarted_entries = _cache_inventory_index(warm_after_restart, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    before_entries = _cache_inventory_index(warm_before, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    trial_before_entries = _cache_inventory_index(warm_trial_before, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    if prepared_entries is None or restarted_entries is None or before_entries is None or trial_before_entries is None:
        return False
    prepared_bytes = sum(row[1] for row in prepared_entries.values())
    if not prepared_entries or prepared_bytes <= 0:
        return False
    if any(restarted_entries.get(key) != row for key, row in prepared_entries.items()):
        return False
    if before_entries != restarted_entries or trial_before_entries != restarted_entries:
        return False

    summary = orchestration.get("warmCachePreparedSummary")
    if not isinstance(summary, dict) or any(summary.get(key) != value for key, value in {
        "status": "observed",
        "cacheDirectoryCount": len(expected_names),
        "fileCount": len(prepared_entries),
        "bytes": prepared_bytes,
        "hasEntries": True,
    }.items()):
        return False
    restart_diff = _cache_inventory_diff(prepared, warm_after_restart, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    if not _cache_diff_record_matches(orchestration.get("warmCacheRestartDiff"), restart_diff):
        return False

    purchase_diff = _cache_inventory_diff(warm_after_restart, warm_after, maximum_bytes=maximum_bytes, expected_cache_paths=expected_cache_paths)
    if (
        not isinstance(warm_trial, dict)
        or not _cache_diff_record_matches(warm_trial.get("cacheDiff"), purchase_diff)
        or not _cache_diff_record_matches(orchestration.get("warmCacheDuringPurchaseDiff"), purchase_diff)
    ):
        return False
    return True


def _repository_root(evidence: Any) -> Path | None:
    for candidate in evidence.directory.parents:
        if (candidate / "infrastructure" / "benchmark-environment" / "manifest.json").is_file():
            return candidate
    return None


def _directory_inventory(path: Path, *, maximum_bytes: int) -> dict[str, Any] | None:
    if path.is_symlink() or not path.is_dir():
        return None
    files: list[dict[str, Any]] = []
    total = 0
    try:
        for file_path in sorted(path.rglob("*")):
            if file_path.is_symlink():
                return None
            if not file_path.is_file():
                continue
            relative = file_path.relative_to(path).as_posix()
            raw = file_path.read_bytes()
            total += len(raw)
            if total > maximum_bytes:
                return None
            files.append({
                "fileKey": sha256_bytes(relative.encode("utf-8")),
                "sha256": sha256_bytes(raw),
                "sizeBytes": len(raw),
            })
    except OSError:
        return None
    files.sort(key=lambda row: row["fileKey"])
    inventory = {"fileCount": len(files), "bytes": total, "files": files}
    inventory_hash = sha256_bytes(json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return {"status": "observed", **inventory, "inventorySha256": inventory_hash, "stateHash": inventory_hash}


def _trial_directory_bytes(path: Path, *, maximum_bytes: int) -> int | None:
    if path.is_symlink() or not path.is_dir():
        return None
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_symlink():
                return None
            if entry.is_file():
                total += entry.stat().st_size
                if total > maximum_bytes:
                    return total
    except OSError:
        return None
    return total


def _cache_artifact_bytes_valid(evidence: Any, orchestration: dict[str, Any], guardrails: dict[str, Any]) -> bool:
    root = evidence.directory
    maximum = guardrails.get("maxEvidenceBytesPerTrial")
    cache_limit = guardrails.get("maxAnvilCacheBytesEach")
    if (
        isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0
        or isinstance(cache_limit, bool) or not isinstance(cache_limit, int) or cache_limit <= 0
    ):
        return False
    # Independently re-count the final actual files in each workload evidence
    # directory; the sampler's in-window total excludes its own report file.
    for phase in ("cold-purchase", "warm-purchase", "guardrail-read"):
        trial_dir = root / phase
        final_bytes = _trial_directory_bytes(trial_dir, maximum_bytes=maximum)
        if final_bytes is None or final_bytes > maximum:
            return False
        sample_path = trial_dir / "resource-sampler.json"
        try:
            sample = read_json(sample_path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return False
        artifact_dir = sample.get("artifactDirectory")
        guard = artifact_dir.get("guardrailCheck") if isinstance(artifact_dir, dict) else None
        if (
            not isinstance(guard, dict)
            or guard.get("status") != "within_limit"
            or guard.get("limitBytes") != maximum
            or not isinstance(guard.get("observedMaximumBytes"), int)
            or isinstance(guard.get("observedMaximumBytes"), bool)
            or guard["observedMaximumBytes"] > maximum
        ):
            return False
        measured_caches = sample.get("cacheDirectories")
        if not isinstance(measured_caches, dict) or set(measured_caches) != {"anvil-a-state", "anvil-a-rpc"}:
            return False
        for cache in measured_caches.values():
            cache_guard = cache.get("guardrailCheck") if isinstance(cache, dict) else None
            observed_maximum = cache.get("maximumObservedBytes") if isinstance(cache, dict) else None
            if (
                not isinstance(cache_guard, dict)
                or cache_guard.get("status") != "within_limit"
                or isinstance(observed_maximum, bool)
                or not isinstance(observed_maximum, int)
                or observed_maximum < 0
                or observed_maximum > cache_limit
            ):
                return False
    if not _cache_restart_provenance_valid(orchestration, cache_limit):
        return False
    roots = orchestration.get("cacheRoots")
    if not isinstance(roots, dict):
        return False
    repo = _repository_root(evidence)
    if repo is None:
        return False
    state_path = repo / str(roots.get("anvil-a-state", ""))
    rpc_path = repo / str(roots.get("anvil-a-rpc", ""))
    if not _inside(root, state_path) or not _inside(root, rpc_path):
        return False
    final_state = _directory_inventory(state_path, maximum_bytes=cache_limit)
    final_rpc = _directory_inventory(rpc_path, maximum_bytes=cache_limit)
    if final_state is None or final_rpc is None:
        return False
    # Later read requests may legitimately update or evict cache files. The
    # final inventory remains bounded and observable without asserting immutability.
    return final_state.get("status") == "observed" and final_rpc.get("status") == "observed"


def _monotonic_counter_delta(source: Any) -> int | None:
    if not isinstance(source, dict):
        return None
    start = source.get("start")
    end = source.get("end")
    window = source.get("windowDelta")
    if not isinstance(start, dict) or not isinstance(end, dict) or not isinstance(window, dict):
        return None
    if start.get("status") != "observed" or end.get("status") != "observed" or window.get("status") != "observed":
        return None
    before, after, declared = start.get("sourceCallsReserved"), end.get("sourceCallsReserved"), window.get("sourceCallsReserved")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (before, after, declared)):
        return None
    if before < 0 or after < before or declared != after - before:
        return None
    return declared


def _raw_database_snapshot(
    evidence: Any,
    directory_prefix: str,
    artifact_prefix: str,
    *,
    env_id: str,
    generation_id: str,
) -> dict[str, list[Any]] | None:
    expected_queries = {
        "generation": "generation-by-id",
        "operations": "operations-by-generation",
        "payments": "payments-by-operation",
        "deliveries": "deliveries-by-operation",
        "denials": "denials-by-generation",
        "x402Observations": "x402-observations-by-operation",
    }
    observed: dict[str, list[Any]] = {}
    for key, query_name in expected_queries.items():
        matches = [
            item.payload for item in evidence.database_artifacts()
            if item.relative_path == f"{directory_prefix}/db/{artifact_prefix}-{query_name}.json"
        ]
        if len(matches) != 1:
            return None
        payload = matches[0]
        if (
            payload.get("schemaVersion") != "bef-db-observation/v1"
            or payload.get("boundary") != "readonly-database"
            or payload.get("readOnly") is not True
            or payload.get("operationId") is not None
            or payload.get("variantId") != "guardrail_exceeded"
            or not isinstance(payload.get("databaseRole"), str)
            or not payload["databaseRole"].strip()
            or payload.get("transactionReadOnly") != "on"
            or payload.get("envId") != env_id
            or payload.get("generationId") != generation_id
            or not isinstance(payload.get("rows"), list)
        ):
            return None
        observed[key] = payload["rows"]
    return observed


def _raw_chain_snapshot(
    evidence: Any, directory_prefix: str, label_prefix: str, payer_address: str,
) -> dict[str, Any] | None:
    fields = {
        "chain-id": ("chainId", "eth_chainId"),
        "head": ("head", "eth_getBlockByNumber"),
        "payer-native-balance": ("nativeBalance", "eth_getBalance"),
        "payer-nonce": ("transactionCount", "eth_getTransactionCount"),
        "payer-token-balance": ("tokenBalance", "eth_call"),
        "payer-token-code": ("tokenCodeSha256", "eth_getCode"),
    }
    selected: dict[str, dict[str, Any]] = {}
    observed_account: str | None = None
    for artifact in evidence.rpc_artifacts(endpoint_boundary="local-chain-readonly-proxy"):
        path = artifact.relative_path
        if not path.startswith(f"{directory_prefix}/rpc/") or label_prefix not in path:
            continue
        payload = artifact.payload
        if (
            payload.get("schemaVersion") != "bef-rpc-observation/v1"
            or payload.get("endpointBoundary") != "local-chain-readonly-proxy"
            or payload.get("environmentId") != "bef-env-a"
            or payload.get("operationId") is not None
            or payload.get("variantId") != "guardrail_exceeded"
        ):
            return None
        filename = PurePosixPath(artifact.relative_path).name
        suffix = next((name for name in fields if filename.endswith(f"-{name}.json")), None)
        if suffix is None or suffix in selected or payload.get("method") != fields[suffix][1]:
            return None
        params = payload.get("params")
        if not isinstance(params, list):
            return None
        if suffix in {"payer-native-balance", "payer-nonce"}:
            if (
                len(params) != 2
                or not isinstance(params[0], str)
                or not _EVM_ADDRESS.fullmatch(params[0])
                or params[0].lower() != payer_address.lower()
                or params[1] != "latest"
                or observed_account is not None and params[0] != observed_account
            ):
                return None
            observed_account = params[0]
        elif suffix == "payer-token-balance":
            token = evidence.manifest.get("contracts", {}).get("usdc", {}).get("address")
            data = params[0].get("data") if len(params) == 2 and isinstance(params[0], dict) else None
            if (
                len(params) != 2
                or not isinstance(token, str)
                or not isinstance(params[0].get("to"), str)
                or params[0]["to"].lower() != token.lower()
                or not isinstance(data, str)
                or data.lower() != "0x70a08231" + "0" * 24 + payer_address.lower().removeprefix("0x")
                or params[1] != "latest"
            ):
                return None
        elif suffix == "payer-token-code":
            token = evidence.manifest.get("contracts", {}).get("usdc", {}).get("address")
            if len(params) != 2 or not isinstance(token, str) or not isinstance(params[0], str) or params[0].lower() != token.lower() or params[1] != "latest":
                return None
        elif suffix == "head" and (params != ["latest", False] or payload.get("requestedBlock") != "latest"):
            return None
        elif suffix == "chain-id" and params != []:
            return None
        selected[suffix] = payload
    if set(selected) != set(fields):
        return None
    results = {suffix: payload.get("result") for suffix, payload in selected.items()}
    if any(value is None for value in results.values()):
        return None
    code = results["payer-token-code"]
    if not isinstance(code, str) or not code.startswith("0x") or len(code) % 2 != 0:
        return None
    try:
        code_hash = sha256_bytes(bytes.fromhex(code[2:]))
    except ValueError:
        return None
    return {
        "chainId": results["chain-id"],
        "head": results["head"],
        "payer": {
            "account": observed_account,
            "nativeBalance": results["payer-native-balance"],
            "transactionCount": results["payer-nonce"],
            "tokenBalance": results["payer-token-balance"],
            "tokenCodeSha256": code_hash,
        },
    }


def _readiness_get_is_raw_and_generation_bound(
    evidence: Any, ready: dict[str, Any], generation_id: str, env_id: str, payer: str,
) -> bool:
    first_read = ready.get("firstRead")
    reference = first_read.get("artifact") if isinstance(first_read, dict) else None
    if (
        not isinstance(first_read, dict)
        or first_read.get("status") != 200
        or first_read.get("observationId") != "sc011-guardrail-read-before-deadline"
        or ready.get("completedReadsBeforeDeadline") != 1
        or not isinstance(reference, dict)
        or reference.get("boundary") != "actual-tool-http"
        or reference.get("contentType") != "application/json"
        or not _DIGEST.fullmatch(str(reference.get("sha256")))
    ):
        return False
    try:
        local_path = _require_safe_relative(reference.get("path"))
    except ValueError:
        return False
    global_path = (Path("guardrail-read") / Path(*local_path.parts)).as_posix()
    artifact = next((item for item in evidence.artifacts if item.relative_path == global_path), None)
    payload = artifact.payload if artifact is not None else None
    if (
        artifact is None
        or artifact.boundary != "actual-tool-http"
        or artifact.sha256 != reference.get("sha256")
        or not isinstance(payload, dict)
        or payload.get("schemaVersion") != "bef-http-observation/v1"
        or payload.get("boundary") != "actual-tool-http"
        or payload.get("operationId") is not None
        or payload.get("variantId") != "guardrail_exceeded"
    ):
        return False
    request = payload.get("request")
    response = payload.get("response")
    body = response.get("body") if isinstance(response, dict) else None
    headers = request.get("headers") if isinstance(request, dict) else None
    recorded_identity = first_read.get("responseIdentity")
    return bool(
        isinstance(request, dict)
        and request.get("method") == "GET"
        and request.get("path") == f"/tools/{env_id}/balances"
        and isinstance(headers, dict)
        and next((value for key, value in headers.items() if str(key).lower() == "x-bef-generation"), None) == generation_id
        and isinstance(response, dict)
        and response.get("status") == 200
        and _actual_balance_read_matches(
            body, env_id=env_id, generation_id=generation_id, payer=payer,
        )
        and isinstance(recorded_identity, dict)
        and recorded_identity.get("boundary") == body.get("boundary")
        and recorded_identity.get("envId") == body.get("envId")
        and recorded_identity.get("generationId") == body.get("generationId")
        and isinstance(recorded_identity.get("payer"), str)
        and _EVM_ADDRESS.fullmatch(recorded_identity["payer"]) is not None
        and recorded_identity["payer"].lower() == body["payer"].lower()
    )


def _raw_guardrail_no_effects(evidence: Any, orchestration: dict[str, Any]) -> bool:
    identity = _indexed_payload(evidence, "guardrail-read/identity.json")
    fence = _indexed_payload(evidence, "guardrail-fence-active/fence-verification.json")
    if not isinstance(identity, dict):
        return False
    if not isinstance(fence, dict):
        return False
    generation_id = identity.get("generationId")
    env_id = identity.get("envId")
    payer = identity.get("payerAddress")
    if not all(isinstance(value, str) and value for value in (generation_id, env_id, payer)):
        return False
    if fence.get("generationId") != generation_id or fence.get("envId") != env_id or fence.get("phase") != "guardrail_exceeded":
        return False
    if fence.get("fenceHttpStatus") != 200 or fence.get("serverReportedChainState") != "not_touched":
        return False
    ready = _indexed_payload(evidence, "guardrail-ready.json")
    if not isinstance(ready, dict) or ready.get("generationId") != generation_id or ready.get("envId") != env_id:
        return False
    effect_names = ("operations", "payments", "deliveries", "denials", "x402Observations")
    before = fence.get("databaseBefore")
    after = fence.get("databaseAfter")
    ready_db = ready.get("databaseBefore")
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(ready_db, dict):
        return False
    if any(
        not isinstance(before.get(key), list)
        or not isinstance(after.get(key), list)
        or not isinstance(ready_db.get(key), list)
        or before[key] != after[key]
        or ready_db[key] != after[key]
        for key in effect_names
    ):
        return False
    if any(ready_db[key] for key in effect_names):
        return False
    if (
        identity.get("schemaVersion") != "bef-resource-workload-identity/v1"
        or ready.get("schemaVersion") != "bef-resource-workload-ready/v1"
        or identity.get("phase") != "guardrail_exceeded"
        or ready.get("phase") != "guardrail_exceeded"
        or identity.get("participantId") != ready.get("participantId")
        or not isinstance(ready.get("payerAddress"), str)
        or payer.lower() != ready["payerAddress"].lower()
        or identity.get("manifestSha256") != evidence.manifest_sha256
        or ready.get("manifestSha256") != evidence.manifest_sha256
        or identity.get("applicationSourceSha256") != ready.get("applicationSourceSha256")
        or identity.get("probeSourceSha256") != ready.get("probeSourceSha256")
    ):
        return False
    if not _readiness_get_is_raw_and_generation_bound(evidence, ready, generation_id, env_id, payer):
        return False
    ready_chain = ready.get("chainBefore")
    after_chain = fence.get("protectedStateAfter")
    if not isinstance(ready_chain, dict) or not isinstance(after_chain, dict):
        return False
    if ready_chain != after_chain:
        return False
    generation_before = before.get("generation")
    generation_after = after.get("generation")
    ready_generation = ready_db.get("generation")
    if (
        not isinstance(generation_before, list)
        or len(generation_before) != 1
        or not isinstance(generation_before[0], dict)
        or not isinstance(generation_after, list)
        or len(generation_after) != 1
        or not isinstance(generation_after[0], dict)
        or not isinstance(ready_generation, list)
        or len(ready_generation) != 1
        or not isinstance(ready_generation[0], dict)
        or any(
            generation.get("generation_id") != generation_id
            or generation.get("env_id") != env_id
            or generation.get("participant_id") != identity.get("participantId")
            or str(generation.get("payer_address", "")).lower() != payer.lower()
            for generation in (generation_before[0], generation_after[0], ready_generation[0])
        )
        or generation_before[0].get("status") != "active"
        or ready_generation[0].get("status") != "active"
        or generation_after[0].get("status") != "fenced"
        or not fence.get("generationIdentityMatchesBeforeFence")
        or fence.get("generationFenced") is not True
    ):
        return False
    readiness_raw = _raw_database_snapshot(
        evidence, "guardrail-read", "sc011-guardrail-database-before", env_id=env_id, generation_id=generation_id,
    )
    fence_before_raw = _raw_database_snapshot(
        evidence, "guardrail-fence-active", "sc011-generation-before-fence", env_id=env_id, generation_id=generation_id,
    )
    fence_after_raw = _raw_database_snapshot(
        evidence, "guardrail-fence-active", "sc011-guardrail-database-after-fence", env_id=env_id, generation_id=generation_id,
    )
    if readiness_raw is None or fence_before_raw is None or fence_after_raw is None:
        return False
    if readiness_raw != ready_db or fence_before_raw != before or fence_after_raw != after:
        return False
    before_rpc = _raw_chain_snapshot(evidence, "guardrail-read", "sc011-guardrail-chain-before", payer)
    after_rpc = _raw_chain_snapshot(evidence, "guardrail-fence-active", "sc011-generation-chain-after-fence", payer)
    if before_rpc is None or after_rpc is None or before_rpc != ready_chain or after_rpc != after_chain:
        return False
    fence_http = [
        item.payload for item in evidence.http_events(variant_id="guardrail_exceeded")
        if item.payload.get("boundary") == "private-admin-http"
        and isinstance(item.payload.get("request"), dict)
        and item.payload["request"].get("method") == "POST"
        and item.payload["request"].get("path") == f"/internal/admin/environments/{env_id}/generations/{generation_id}/fence"
    ]
    return (
        len(fence_http) == 1
        and isinstance(fence_http[0].get("response"), dict)
        and fence_http[0]["response"].get("status") == 200
        and isinstance(fence_http[0]["response"].get("body"), dict)
        and fence_http[0]["response"]["body"].get("status") == "fenced"
        and fence_http[0]["response"]["body"].get("envId") == env_id
        and fence_http[0]["response"]["body"].get("generationId") == generation_id
        and fence_http[0]["response"]["body"].get("chainState") == "not_touched"
        and all(
            item.payload.get("operationId") is None
            for item in evidence.rpc_artifacts(endpoint_boundary="local-chain-readonly-proxy")
            if item.payload.get("variantId") == "guardrail_exceeded"
        )
    )


def _read_progress_is_raw_and_generation_bound(evidence: Any, generation_id: str, payer: str) -> bool:
    envelopes = [
        item for item in evidence.resource_artifacts()
        if item.payload.get("schemaVersion") == OBSERVATION_SCHEMA
        and item.payload.get("variantId") == "guardrail_exceeded"
        and isinstance(item.payload.get("readProgress"), dict)
    ]
    expected_envelope_paths = {
        "resource-observations/guardrail_exceeded.json",
        "resource-observations/guardrail-read-progress.json",
    }
    if len(envelopes) != 2 or {item.relative_path for item in envelopes} != expected_envelope_paths:
        return False
    references = [item.payload["readProgress"] for item in envelopes]
    full_reference = next((item for item in references if isinstance(item.get("httpArtifacts"), list)), None)
    if (
        full_reference is None
        or any(
            reference.get("path") != full_reference.get("path")
            or reference.get("sha256") != full_reference.get("sha256")
            or reference.get("lineCount") != full_reference.get("lineCount")
            for reference in references
        )
    ):
        return False
    reference = full_reference
    path = reference.get("path")
    digest = reference.get("sha256")
    if not isinstance(path, str) or not _DIGEST.fullmatch(str(digest)):
        return False
    try:
        relative = _require_safe_relative(path)
        raw_path = evidence.directory.joinpath(*relative.parts)
        if raw_path.is_symlink() or _has_symlink_component(evidence.directory, raw_path) or not _inside(evidence.directory, raw_path):
            return False
        raw = raw_path.read_bytes()
        if sha256_bytes(raw) != digest or len(raw) > 4 * 1024 * 1024:
            return False
        lines = raw.splitlines()
        if not lines or len(lines) != reference.get("lineCount") or len(lines) > 10_000:
            return False
        if reference.get("firstSequence") != 1 or reference.get("lastSequence") != len(lines):
            return False
        seen_ids: set[str] = set()
        seen_paths: set[str] = set()
        indexed_refs = reference.get("httpArtifacts")
        if not isinstance(indexed_refs, list) or len(indexed_refs) != len(lines):
            return False
        expected_index_refs = {
            (item.get("path"), item.get("sha256"))
            for item in indexed_refs if isinstance(item, dict)
        }
        actual_index_refs: set[tuple[Any, Any]] = set()
        for sequence, raw_line in enumerate(lines, start=1):
            row = json.loads(raw_line.decode("utf-8"))
            if (
                not isinstance(row, dict)
                or row.get("schemaVersion") != "bef-resource-read-progress/v1"
                or row.get("variantId") != "guardrail_exceeded"
                or row.get("envId") != "bef-env-a"
                or row.get("generationId") != generation_id
                or row.get("sequence") != sequence
                or row.get("status") != 200
                or row.get("operationId") is not None
                or not isinstance(row.get("observationId"), str)
                or row["observationId"] in seen_ids
                or not isinstance(row.get("artifact"), dict)
            ):
                return False
            artifact_ref = row["artifact"]
            relative_http = _require_safe_relative(artifact_ref.get("path"))
            global_http_path = (Path("guardrail-read") / Path(*relative_http.parts)).as_posix()
            artifact_digest = artifact_ref.get("sha256")
            if (
                artifact_ref.get("boundary") != "actual-tool-http"
                or artifact_ref.get("contentType") != "application/json"
                or not _DIGEST.fullmatch(str(artifact_digest))
                or global_http_path in seen_paths
            ):
                return False
            actual_artifact = _indexed_payload(evidence, global_http_path)
            indexed_entry = next((item for item in evidence.artifacts if item.relative_path == global_http_path), None)
            if actual_artifact is None or indexed_entry is None or indexed_entry.boundary != "actual-tool-http" or indexed_entry.sha256 != artifact_digest:
                return False
            request = actual_artifact.get("request")
            response = actual_artifact.get("response")
            body = response.get("body") if isinstance(response, dict) else None
            if (
                actual_artifact.get("schemaVersion") != "bef-http-observation/v1"
                or actual_artifact.get("boundary") != "actual-tool-http"
                or actual_artifact.get("operationId") is not None
                or actual_artifact.get("variantId") != "guardrail_exceeded"
                or not isinstance(request, dict)
                or request.get("method") != "GET"
                or request.get("path") != "/tools/bef-env-a/balances"
                or not isinstance(response, dict)
                or response.get("status") != 200
                or not _actual_balance_read_matches(
                    body,
                    env_id="bef-env-a",
                    generation_id=generation_id,
                    payer=payer,
                )
            ):
                return False
            seen_ids.add(row["observationId"])
            seen_paths.add(global_http_path)
            actual_index_refs.add((global_http_path, artifact_digest))
        return expected_index_refs == actual_index_refs
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return False


def _read_overrun_trigger_matches(trigger: Any, read_limit_seconds: Any) -> bool:
    if type(read_limit_seconds) is not int or read_limit_seconds <= 0 or not isinstance(trigger, dict):
        return False
    limit_milliseconds = read_limit_seconds * 1_000
    observed = trigger.get("observed")
    return (
        trigger.get("code") == "max_resource_read_overrun_seconds"
        and trigger.get("unit") == "milliseconds"
        and type(trigger.get("limit")) is int
        and trigger["limit"] == limit_milliseconds
        and type(observed) in {int, float}
        and (type(observed) is int or math.isfinite(observed))
        and observed > limit_milliseconds
    )


def _active_bound_exceeded(active_bound: Any, read_limit_seconds: Any) -> bool:
    return (
        type(read_limit_seconds) is int
        and read_limit_seconds > 0
        and isinstance(active_bound, dict)
        and active_bound.get("status") == "exceeded"
        and active_bound.get("limitSeconds") == read_limit_seconds
        and type(active_bound.get("observedNanoseconds")) is int
        and active_bound["observedNanoseconds"] > read_limit_seconds * 1_000_000_000
    )


def _variant_inventory_valid(evidence: Any) -> bool:
    raw_variant_ids = (
        evidence.variant_ids()
        if callable(getattr(evidence, "variant_ids", None))
        else frozenset(
            item.payload["variantId"] for item in evidence.artifacts
            if isinstance(item.payload.get("variantId"), str) and item.payload["variantId"]
        )
    )
    if raw_variant_ids != VARIANTS | {"primary"}:
        return False

    wrappers = [
        item for item in evidence.resource_artifacts()
        if item.payload.get("schemaVersion") == OBSERVATION_SCHEMA
        and item.relative_path.startswith("resource-observations/")
    ]
    expected_wrapper_paths = {
        *(f"resource-observations/{variant}.json" for variant in VARIANTS if variant != "missing_sampler"),
        "resource-observations/missing_sampler-reference.json",
        "resource-observations/guardrail-read-progress.json",
    }
    if len(wrappers) != len(expected_wrapper_paths) or {item.relative_path for item in wrappers} != expected_wrapper_paths:
        return False
    by_path = {item.relative_path: item.payload for item in wrappers}
    for variant in VARIANTS - {"missing_sampler"}:
        wrapper = by_path.get(f"resource-observations/{variant}.json")
        if (
            not isinstance(wrapper, dict)
            or wrapper.get("variantId") != variant
            or wrapper.get("scenarioId") != SCENARIO_ID
            or wrapper.get("boundary") != "resource-data"
        ):
            return False
    missing_wrapper = by_path.get("resource-observations/missing_sampler-reference.json")
    missing = _sample_for(evidence, "missing_sampler")
    if (
        not isinstance(missing_wrapper, dict)
        or missing_wrapper.get("variantId") != "missing_sampler"
        or missing_wrapper.get("scenarioId") != SCENARIO_ID
        or missing_wrapper.get("operationId") is not None
        or missing is None
        or missing[1].get("schemaVersion") != MISSING_SAMPLER_SCHEMA
        or missing[1].get("variantId") != "missing_sampler"
        or missing[1].get("childExitCode") != 0
        or missing[1].get("childResult") != {
            "status": "blocked_before_main",
            "exception": "ModuleNotFoundError",
            "module": "bef_resource_sampler",
        }
        or missing[1].get("childStderr") != ""
        or not _DIGEST.fullmatch(str(missing[1].get("commandSha256")))
        or not _DIGEST.fullmatch(str(missing[1].get("runnerSha256")))
    ):
        return False
    try:
        if json.loads(missing[1].get("childStdout", "")) != missing[1].get("childResult"):
            return False
    except (TypeError, json.JSONDecodeError):
        return False
    progress_wrapper = by_path.get("resource-observations/guardrail-read-progress.json")
    if (
        not isinstance(progress_wrapper, dict)
        or progress_wrapper.get("variantId") != "guardrail_exceeded"
        or progress_wrapper.get("operationId") is not None
        or not isinstance(progress_wrapper.get("readProgress"), dict)
    ):
        return False

    # `primary` is a diagnostic label for the two preserved fence snapshots,
    # not an additional execution variant. Bind every such read to its exact
    # account, method, value, and fence phase.
    primary = [item for item in evidence.artifacts if item.payload.get("variantId") == "primary"]
    if len(primary) != 16:
        return False
    token = evidence.manifest.get("contracts", {}).get("usdc", {}).get("address")
    if not isinstance(token, str) or not _EVM_ADDRESS.fullmatch(token):
        return False
    expected_methods = {
        "payer-native-balance": "eth_getBalance",
        "payer-nonce": "eth_getTransactionCount",
        "payer-token-balance": "eth_call",
        "payer-token-code": "eth_getCode",
    }
    seen: set[tuple[str, str, str]] = set()
    for artifact in primary:
        payload = artifact.payload
        directory = artifact.relative_path.split("/", 1)[0]
        if directory not in {"cold-fence", "warm-fence"} or artifact.boundary != "local-chain-readonly-proxy":
            return False
        fence = _indexed_payload(evidence, f"{directory}/fence-verification.json")
        if not isinstance(fence, dict):
            return False
        filename = PurePosixPath(artifact.relative_path).name
        phase = "before" if "-before-fence-" in filename else "after" if "-after-fence-" in filename else None
        suffix = next((name for name in expected_methods if filename.endswith(f"-{name}.json")), None)
        if (
            phase is None or suffix is None or payload.get("schemaVersion") != "bef-rpc-observation/v1"
            or payload.get("endpointBoundary") != "local-chain-readonly-proxy"
            or payload.get("environmentId") != "bef-env-a"
            or payload.get("operationId") is not None
            or payload.get("method") != expected_methods[suffix]
        ):
            return False
        state_name = "protectedStateBefore" if phase == "before" else "protectedStateAfter"
        protected = fence.get(state_name)
        payer_state = protected.get("payer") if isinstance(protected, dict) else None
        account = payer_state.get("account") if isinstance(payer_state, dict) else None
        if not isinstance(account, str) or not _EVM_ADDRESS.fullmatch(account):
            return False
        params = payload.get("params")
        result = payload.get("result")
        if not isinstance(params, list):
            return False
        if suffix in {"payer-native-balance", "payer-nonce"}:
            state_key = "nativeBalance" if suffix == "payer-native-balance" else "transactionCount"
            if params != [account, "latest"] or result != payer_state.get(state_key):
                return False
        elif suffix == "payer-token-balance":
            expected_data = "0x70a08231" + "0" * 24 + account[2:].lower()
            call = params[0] if len(params) == 2 and isinstance(params[0], dict) else None
            if (
                not isinstance(call, dict) or call.get("to", "").lower() != token.lower()
                or call.get("data", "").lower() != expected_data or params[1] != "latest"
                or result != payer_state.get("tokenBalance")
            ):
                return False
        else:
            if params != [token, "latest"] or not isinstance(result, str) or not result.startswith("0x"):
                return False
            try:
                code_hash = sha256_bytes(bytes.fromhex(result[2:]))
            except ValueError:
                return False
            if code_hash != payer_state.get("tokenCodeSha256"):
                return False
        identity = (directory, phase, suffix)
        if identity in seen:
            return False
        seen.add(identity)
    expected_reads = {
        (directory, phase, suffix)
        for directory in ("cold-fence", "warm-fence")
        for phase in ("before", "after")
        for suffix in expected_methods
    }
    return seen == expected_reads


def validate_sc011_resource_evidence(evidence: Any) -> dict[str, bool]:
    """Recompute SC-011 predicates from raw indexed collector evidence."""

    guardrails = _manifest_guardrails(evidence)
    payloads = _resource_payloads(evidence)
    wrappers = [item for item in payloads if item.get("schemaVersion") == OBSERVATION_SCHEMA]
    variants = {item.get("variantId") for item in wrappers if isinstance(item.get("variantId"), str)}
    orchestration_artifact = next((item for item in evidence.artifacts if item.boundary == "resource-data" and item.payload.get("schemaVersion") == ORCHESTRATION_SCHEMA), None)
    orchestration = orchestration_artifact.payload if orchestration_artifact is not None else {}
    samples = {
        variant: _sample_for(evidence, variant)
        for variant in ("empty_dedicated_cache", "warm_cache", "guardrail_exceeded", "provider_cu_unavailable")
    }
    raw_host_limits = bool(orchestration_artifact) and all(
        samples.get(variant) is not None
        and _sample_metrics_valid(samples[variant][1], guardrails, evidence.manifest_sha256)
        for variant in ("empty_dedicated_cache", "warm_cache", "guardrail_exceeded")
    )
    cache_provenance = _cache_restart_provenance_valid(
        orchestration, guardrails.get("maxAnvilCacheBytesEach")
    )
    resource_metrics = (
        samples.get("empty_dedicated_cache") is not None
        and samples.get("warm_cache") is not None
        and samples.get("guardrail_exceeded") is not None
        and all(_sample_metrics_valid(samples[key][1], guardrails, evidence.manifest_sha256) for key in ("empty_dedicated_cache", "warm_cache", "guardrail_exceeded"))
    )
    source_count = all(
        samples.get(key) is not None and _monotonic_counter_delta(samples[key][1].get("sourceProxy")) is not None
        for key in ("empty_dedicated_cache", "warm_cache", "guardrail_exceeded")
    )
    scenario_limit = guardrails.get("maxResourceScenarioSeconds")
    elapsed = orchestration.get("elapsedMonotonicNanoseconds") if isinstance(orchestration, dict) else None
    outer = (
        scenario_limit == 900
        and guardrails.get("maxResourceReadOverrunSeconds") == 2
        and guardrails.get("maxTrialSeconds") == 120
        and isinstance(scenario_limit, int)
        and not isinstance(scenario_limit, bool)
        and isinstance(elapsed, int)
        and not isinstance(elapsed, bool)
        and elapsed <= scenario_limit * 1_000_000_000
        and orchestration.get("outerScenarioDeadlineSeconds") == scenario_limit
    )
    read_sample = samples.get("guardrail_exceeded")
    sample_raw = read_sample[1] if read_sample else {}
    trigger = sample_raw.get("guardrails", {}).get("trigger") if isinstance(sample_raw.get("guardrails"), dict) else None
    cleanup = sample_raw.get("trialProcess", {}).get("processTreeCleanup") if isinstance(sample_raw.get("trialProcess"), dict) else None
    trial_process = sample_raw.get("trialProcess") if isinstance(sample_raw.get("trialProcess"), dict) else {}
    active_bound = sample_raw.get("guardrails", {}).get("activeBound") if isinstance(sample_raw.get("guardrails"), dict) else None
    read_limit = guardrails.get("maxResourceReadOverrunSeconds")
    guardrail_identity = _indexed_payload(evidence, "guardrail-read/identity.json")
    guardrail_generation = guardrail_identity.get("generationId") if isinstance(guardrail_identity, dict) else None
    guardrail_payer = guardrail_identity.get("payerAddress") if isinstance(guardrail_identity, dict) else None
    actual_stop = (
        sample_raw.get("status") == "guardrail_exceeded"
        and isinstance(trial_process.get("exitCode"), int)
        and not isinstance(trial_process.get("exitCode"), bool)
        and trial_process["exitCode"] != 0
        and _read_overrun_trigger_matches(trigger, read_limit)
        and isinstance(cleanup, dict)
        and cleanup.get("directChildExited") is True
        and (
            cleanup.get("descendants") == "stopped"
            or cleanup.get("treeExitConfirmed") is True
        )
        and _active_bound_exceeded(active_bound, read_limit)
        and isinstance(guardrail_generation, str)
        and isinstance(guardrail_payer, str)
    )
    # The raw fence is evaluated even when cleanup is unknown because it is a
    # protective action. A passing gate still requires independently proven
    # process-tree exit plus DB/RPC state equality.
    fence_observed = _raw_guardrail_no_effects(evidence, orchestration)
    progress_observed = (
        isinstance(guardrail_generation, str)
        and isinstance(guardrail_payer, str)
        and _read_progress_is_raw_and_generation_bound(evidence, guardrail_generation, guardrail_payer)
    )
    fence_ok = actual_stop and fence_observed and progress_observed
    cu = samples.get("provider_cu_unavailable")
    cu_raw = cu[1] if cu else {}
    provider_cu_unknown = (
        cu is not None
        and cu[0].get("operationId") is not None
        and cu_raw.get("sourceProxy", {}).get("providerComputeUnits") == "unknown"
        and orchestration.get("providerComputeUnits") == {"status": "unknown", "value": None}
    )
    blocked_metadata_reconciled = all(
        sample is not None
        and _blocked_sampler_metadata_is_independently_proven(
            sample[1],
            cache_provenance=cache_provenance,
            source_count=source_count,
            guardrail_stop=bool(fence_ok),
            provider_cu_unknown=provider_cu_unknown,
        )
        for sample in samples.values()
    )
    return {
        "variant_inventory": _variant_inventory_valid(evidence),
        "operation_inventory": _purchase_operation_inventory_valid(evidence),
        "source_identity": _source_identity_matches(evidence, orchestration),
        "host_and_limits": raw_host_limits and outer and blocked_metadata_reconciled,
        "cold_warm_state": cache_provenance,
        "cpu_peak_ram_elapsed": resource_metrics and blocked_metadata_reconciled,
        "cache_artifact_bytes": _cache_artifact_bytes_valid(evidence, orchestration, guardrails),
        "source_request_count": source_count,
        "guardrail_stop": bool(fence_ok),
        "cu_unknown_if_unobservable": provider_cu_unknown,
    }
