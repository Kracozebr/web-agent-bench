"""Collect resource evidence for the local BEF Compose project.

The standalone CLI is read-only and never starts or stops containers. The
internal bounded runner can own a child process, but process cleanup does not
prove a runtime-generation fence. Cache condition and activity attribution
remain unknown until independently observed provenance is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import posixpath
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPOSITORY_ROOT / "infrastructure" / "benchmark-environment" / "compose.yaml"
MANIFEST_FILE = REPOSITORY_ROOT / "infrastructure" / "benchmark-environment" / "manifest.json"
SECRET_FILE = REPOSITORY_ROOT / "infrastructure" / "benchmark-environment" / ".local" / "secrets" / "service-key"
ARTIFACTS_ROOT = (REPOSITORY_ROOT / "artifacts" / "runs").resolve()
PROJECT_NAME = "web-agent-bench-bef"
SCENARIO_ID = "BEF-SC-011"
SCHEMA_VERSION = "bef-resource-sample/v1"
POLLUTION_PRONE_PARTS = frozenset({".local", ".git", ".venv", "node_modules"})
SERVICES = (
    "postgres",
    "source-proxy",
    "anvil-a",
    "anvil-b",
    "local-proxy-a",
    "local-proxy-b",
    "facilitator-a",
    "facilitator-b",
    "api",
    "gateway",
)
POLICY_MEMORY_KEYS = {
    "anvil-a": "maxAnvilMemoryBytesEach",
    "anvil-b": "maxAnvilMemoryBytesEach",
    "api": "maxApiMemoryBytes",
    "postgres": "maxDatabaseMemoryBytes",
}
CGROUP_FILES = (
    "/sys/fs/cgroup/cgroup.controllers",
    "/sys/fs/cgroup/cpu.stat",
    "/sys/fs/cgroup/cpu.max",
    "/sys/fs/cgroup/memory.current",
    "/sys/fs/cgroup/memory.peak",
    "/sys/fs/cgroup/memory.max",
)
_CPU_STAT_LINE = re.compile(r"^([a-z][a-z0-9_]*)\s+([0-9]+)$")
_CPU_MAX_LINE = re.compile(r"^(max|[0-9]+)\s+([0-9]+)$")
_DECIMAL_LINE = re.compile(r"^[0-9]+$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


class SamplerBlocked(RuntimeError):
    """A required source or observation could not be verified."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ContainerInfo:
    container_id: str
    service: str
    image: str
    state: str
    configured_memory_bytes: int | None
    configured_nano_cpus: int | None


@dataclass(frozen=True)
class GuardrailViolation:
    """Measured bound violation delivered to an optional owner-supplied fence hook."""

    scenario_id: str
    project_name: str
    container_ids: tuple[str, ...]
    code: str
    observed: int
    limit: int
    unit: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_int(value: str) -> int | None:
    try:
        parsed = int(value.strip(), 10)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def parse_cpu_stat(text: str) -> dict[str, int]:
    """Parse cgroup-v2 cpu.stat without converting counters through float."""

    result: dict[str, int] = {}
    for line in text.splitlines():
        match = _CPU_STAT_LINE.fullmatch(line.strip())
        if not match:
            continue
        result[match.group(1)] = int(match.group(2), 10)
    if "usage_usec" not in result:
        raise ValueError("cgroup_cpu_usage_missing")
    return result


def parse_cgroup_v2_bundle(text: str) -> dict[str, Any]:
    """Parse concatenated cgroup-v2 files in ``CGROUP_FILES`` order.

    ``memory.peak`` is the kernel counter since cgroup creation; this parser
    does not mislabel it as a trial-window peak.
    """

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("cgroup_bundle_empty")

    controllers = frozenset(lines[0].split())
    index = 1
    cpu_lines: list[str] = []
    while (
        index < len(lines)
        and _CPU_STAT_LINE.fullmatch(lines[index])
        and not lines[index].startswith("max ")
    ):
        cpu_lines.append(lines[index])
        index += 1
    cpu_stats = parse_cpu_stat("\n".join(cpu_lines))
    if index >= len(lines):
        raise ValueError("cgroup_cpu_max_missing")
    cpu_max_match = _CPU_MAX_LINE.fullmatch(lines[index])
    if not cpu_max_match:
        raise ValueError("cgroup_cpu_max_invalid")
    cpu_quota = None if cpu_max_match.group(1) == "max" else int(cpu_max_match.group(1), 10)
    cpu_period = int(cpu_max_match.group(2), 10)
    if cpu_period <= 0 or (cpu_quota is not None and cpu_quota <= 0):
        raise ValueError("cgroup_cpu_limit_invalid")
    index += 1

    memory_values: list[str] = []
    for _ in range(3):
        if index >= len(lines):
            raise ValueError("cgroup_memory_metric_missing")
        value = lines[index]
        if value != "max" and not _DECIMAL_LINE.fullmatch(value):
            raise ValueError("cgroup_memory_metric_invalid")
        memory_values.append(value)
        index += 1
    if index != len(lines):
        raise ValueError("cgroup_bundle_unexpected_fields")

    memory_current = int(memory_values[0], 10)
    memory_peak = int(memory_values[1], 10)
    memory_limit = None if memory_values[2] == "max" else int(memory_values[2], 10)
    if "cpu" not in controllers or "memory" not in controllers:
        raise ValueError("cgroup_v2_controllers_unavailable")
    return {
        "version": "v2",
        "controllers": sorted(controllers),
        "cpuUsageMicroseconds": cpu_stats["usage_usec"],
        "cpuUsageNanoseconds": cpu_stats["usage_usec"] * 1_000,
        "cpuStat": cpu_stats,
        "cpuLimit": {
            "quota": cpu_quota,
            "period": cpu_period,
            "unlimited": cpu_quota is None,
        },
        "memoryCurrentBytes": memory_current,
        "memoryPeakBytes": memory_peak,
        "memoryPeakScope": "since-container-cgroup-creation",
        "memoryLimitBytes": memory_limit,
        "memoryUnlimited": memory_limit is None,
    }


def _run_command(command: list[str], *, timeout: float = 10.0) -> str:
    """Run a fixed read-only CLI command, discarding all stderr on failure."""

    try:
        process = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise SamplerBlocked("docker_cli_unavailable") from error
    except subprocess.TimeoutExpired as error:
        raise SamplerBlocked("docker_command_timed_out") from error
    if process.returncode != 0:
        raise SamplerBlocked("docker_read_failed")
    return process.stdout


def _load_guardrails() -> tuple[dict[str, int], dict[str, str]]:
    try:
        manifest_bytes = MANIFEST_FILE.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as error:
        raise SamplerBlocked("runtime_manifest_unavailable") from error
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != "bef-runtime-manifest/v1":
        raise SamplerBlocked("runtime_manifest_schema_invalid")
    raw_guardrails = manifest.get("guardrails")
    if not isinstance(raw_guardrails, dict):
        raise SamplerBlocked("runtime_guardrails_unavailable")
    required = (
        "maxTrialSeconds",
        "maxAnvilMemoryBytesEach",
        "maxApiMemoryBytes",
        "maxDatabaseMemoryBytes",
        "maxSourceCallsPerTrial",
        "maxEvidenceBytesPerTrial",
    )
    values: dict[str, int] = {}
    for key in required:
        value = raw_guardrails.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SamplerBlocked("runtime_guardrail_invalid")
        values[key] = value
    # SC-011's short read-overrun bound is being added by the runtime owner.
    # Keep older manifests usable for ordinary bounded sampling, but never
    # start an overrun trial unless this explicit positive bound is present.
    optional_positive = ("maxAnvilCacheBytesEach", "maxResourceReadOverrunSeconds")
    for key in optional_positive:
        value = raw_guardrails.get(key)
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise SamplerBlocked("runtime_guardrail_invalid")
            values[key] = value
    metadata = {
        "manifestPath": MANIFEST_FILE.relative_to(REPOSITORY_ROOT).as_posix(),
        "manifestSha256": _sha256(manifest_bytes),
    }
    return values, metadata


def _docker_host_info() -> dict[str, Any]:
    template = (
        "{{.OperatingSystem}}|{{.KernelVersion}}|{{.Architecture}}|{{.NCPU}}|"
        "{{.MemTotal}}|{{.CgroupVersion}}|{{.Driver}}|{{.ServerVersion}}"
    )
    output = _run_command(["docker", "info", "--format", template], timeout=15.0).strip()
    fields = output.split("|")
    if len(fields) != 8:
        raise SamplerBlocked("docker_host_info_invalid")
    cpu_count = _safe_int(fields[3])
    memory_total = _safe_int(fields[4])
    required_text = {
        "operatingSystem": fields[0].strip(),
        "kernelVersion": fields[1].strip(),
        "architecture": fields[2].strip(),
        "cgroupVersion": fields[5].strip(),
        "storageDriver": fields[6].strip(),
        "engineVersion": fields[7].strip(),
    }
    if (
        cpu_count is None
        or cpu_count <= 0
        or memory_total is None
        or memory_total <= 0
        or any(not value for value in required_text.values())
    ):
        raise SamplerBlocked("docker_host_info_incomplete")
    return {
        "status": "observed",
        "source": "docker-info",
        **required_text,
        "cpuCount": cpu_count,
        "memoryTotalBytes": memory_total,
    }


def _list_container_id(service: str) -> str:
    output = _run_command(
        [
            "docker",
            "compose",
            "--project-name",
            PROJECT_NAME,
            "-f",
            str(COMPOSE_FILE),
            "ps",
            "--all",
            "--quiet",
            service,
        ],
        timeout=15.0,
    )
    ids = [line.strip() for line in output.splitlines() if line.strip()]
    if len(ids) != 1 or not _CONTAINER_ID.fullmatch(ids[0]):
        raise SamplerBlocked(f"compose_container_inventory_invalid_{service.replace('-', '_')}")
    return ids[0]


def _inspect_container(service: str, container_id: str) -> ContainerInfo:
    template = (
        '{{.Id}}|{{.Config.Image}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|'
        '{{.State.Status}}|{{index .Config.Labels "com.docker.compose.project"}}|'
        '{{index .Config.Labels "com.docker.compose.service"}}'
    )
    output = _run_command(["docker", "inspect", "--format", template, container_id]).strip()
    fields = output.split("|")
    if len(fields) != 7:
        raise SamplerBlocked("container_inspection_invalid")
    actual_id, image, memory_raw, nano_cpus_raw, state, project_label, service_label = fields
    if (
        not _CONTAINER_ID.fullmatch(actual_id)
        or actual_id.lower() != container_id.lower()
        or project_label != PROJECT_NAME
        or service_label != service
        or not image
    ):
        raise SamplerBlocked("container_scope_mismatch")
    memory = _safe_int(memory_raw)
    nano_cpus = _safe_int(nano_cpus_raw)
    return ContainerInfo(
        container_id=actual_id,
        service=service,
        image=image,
        state=state,
        configured_memory_bytes=memory if memory else None,
        configured_nano_cpus=nano_cpus if nano_cpus else None,
    )


def _container_inventory() -> tuple[list[ContainerInfo], list[dict[str, str]]]:
    result: list[ContainerInfo] = []
    issues: list[dict[str, str]] = []
    for service in SERVICES:
        try:
            container_id = _list_container_id(service)
            info = _inspect_container(service, container_id)
        except SamplerBlocked as error:
            issues.append({"service": service, "code": error.code})
            continue
        result.append(info)
        if info.state != "running":
            issues.append({"service": service, "code": "container_not_running"})
    return result, issues


def _cgroup_snapshot(info: ContainerInfo) -> dict[str, Any]:
    if info.state != "running":
        return {"status": "unknown", "reason": "container_not_running"}
    try:
        output = _run_command(["docker", "exec", info.container_id, "cat", *CGROUP_FILES], timeout=8.0)
        return {"status": "observed", **parse_cgroup_v2_bundle(output)}
    except SamplerBlocked as error:
        return {"status": "unknown", "reason": error.code}
    except ValueError as error:
        return {"status": "unknown", "reason": str(error)}


def _measure_tree(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"status": "unknown", "reason": "path_not_configured", "bytes": None, "files": None}
    try:
        if not path.exists() or not path.is_dir():
            return {"status": "unknown", "reason": "directory_unavailable", "bytes": None, "files": None}
        total_bytes = 0
        total_files = 0
        stack = [path]
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        stat = entry.stat(follow_symlinks=False)
                        total_bytes += stat.st_size
                        total_files += 1
        return {"status": "observed", "bytes": total_bytes, "files": total_files}
    except OSError:
        return {"status": "unknown", "reason": "directory_read_failed", "bytes": None, "files": None}


def measure_directory_inventory(
    path: Path | None,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    max_files: int = 10_000,
) -> dict[str, Any]:
    """Hash a bounded cache-directory inventory without exposing file names.

    This proves which file contents and sizes existed at one sampling point;
    it does not by itself prove that a later process read any cached entry.
    Paths must remain inside ignored ``artifacts/runs`` and symbolic links are
    rejected so an inventory cannot silently include external user data.
    """

    if path is None:
        return {"status": "unknown", "reason": "cache_path_not_configured"}
    if (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0
        or isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 0
    ):
        return {"status": "unknown", "reason": "inventory_bound_invalid"}
    try:
        root = path.resolve(strict=False)
        relative_root = root.relative_to(ARTIFACTS_ROOT)
    except (OSError, ValueError):
        return {"status": "unknown", "reason": "cache_directory_outside_ignored_artifacts"}
    if not root.is_dir() or not relative_root.parts or any(
        part.lower() in POLLUTION_PRONE_PARTS for part in relative_root.parts
    ):
        return {"status": "unknown", "reason": "cache_directory_not_task_owned"}

    files: list[dict[str, Any]] = []
    total_bytes = 0
    stack = [root]
    try:
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        return {"status": "unknown", "reason": "cache_inventory_symlink_rejected"}
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        return {"status": "unknown", "reason": "cache_inventory_special_file_rejected"}
                    before = entry.stat(follow_symlinks=False)
                    if before.st_size < 0:
                        return {"status": "unknown", "reason": "cache_inventory_size_invalid"}
                    if total_bytes + before.st_size > max_bytes:
                        # File metadata establishes a strict lower bound above
                        # the configured cap. Stop before reading or hashing
                        # the oversized file; callers can fence the owning
                        # workload from this measured violation.
                        return {
                            "status": "exceeded",
                            "observedBytesAtLeast": total_bytes + before.st_size,
                            "limitBytes": max_bytes,
                            "reason": "cache_inventory_byte_limit_exceeded",
                            "fileNamesRedacted": True,
                        }
                    if len(files) >= max_files:
                        return {"status": "unknown", "reason": "cache_inventory_file_limit_exceeded"}
                    file_path = Path(entry.path)
                    relative_file = file_path.relative_to(root).as_posix()
                    digest = hashlib.sha256()
                    observed_bytes = 0
                    with file_path.open("rb") as stream:
                        while True:
                            chunk = stream.read(1024 * 1024)
                            if not chunk:
                                break
                            observed_bytes += len(chunk)
                            if observed_bytes > before.st_size or total_bytes + observed_bytes > max_bytes:
                                return {"status": "unknown", "reason": "cache_inventory_changed_during_read"}
                            digest.update(chunk)
                    after = file_path.stat(follow_symlinks=False)
                    if (
                        observed_bytes != before.st_size
                        or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                        or (before.st_ino not in (0, after.st_ino))
                    ):
                        return {"status": "unknown", "reason": "cache_inventory_changed_during_read"}
                    total_bytes += observed_bytes
                    files.append({
                        "fileKey": _sha256(relative_file.encode("utf-8")),
                        "sha256": digest.hexdigest(),
                        "sizeBytes": observed_bytes,
                    })
    except OSError:
        return {"status": "unknown", "reason": "cache_inventory_read_failed"}

    files.sort(key=lambda item: item["fileKey"])
    inventory = {"fileCount": len(files), "bytes": total_bytes, "files": files}
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    inventory_hash = _sha256(canonical)
    return {
        "status": "observed",
        "pathRef": (Path("artifacts") / "runs" / relative_root).as_posix(),
        **inventory,
        "inventorySha256": inventory_hash,
        "stateHash": inventory_hash,
        "fileNamesRedacted": True,
    }


def _resolve_run_path(raw_path: str | None, *, required: bool, label: str) -> Path | None:
    if raw_path is None:
        if required:
            raise SamplerBlocked(f"{label}_path_required")
        return None
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = REPOSITORY_ROOT / candidate
    resolved = candidate.resolve(strict=False)
    try:
        relative = resolved.relative_to(ARTIFACTS_ROOT)
    except ValueError as error:
        raise SamplerBlocked("measurement_path_outside_ignored_artifacts") from error
    if not relative.parts or any(part.lower() in POLLUTION_PRONE_PARTS for part in relative.parts):
        raise SamplerBlocked("measurement_path_invalid")
    return resolved


def _read_service_key() -> str | None:
    try:
        key = SECRET_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if len(key) < 32:
        return None
    return key


def _source_proxy_metrics(port: int, service_key: str | None) -> dict[str, Any]:
    if service_key is None:
        return {"status": "unknown", "reason": "service_key_unavailable"}
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/internal/admin/metrics",
        headers={"X-BEF-Service-Key": service_key},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=3.0) as response:
            payload = json.loads(response.read(16_384))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return {"status": "unknown", "reason": "source_proxy_metrics_unavailable"}
    if not isinstance(payload, dict) or payload.get("mode") != "source":
        return {"status": "unknown", "reason": "source_proxy_metrics_invalid"}
    numeric_fields = ("forwardedItems", "deniedItems", "upstreamErrors", "sourceCallsReserved", "sourceCallLimit")
    counts: dict[str, int] = {}
    for field in numeric_fields:
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return {"status": "unknown", "reason": "source_proxy_metrics_invalid"}
        counts[field] = value
    method_counts: dict[str, dict[str, int]] = {}
    for field in ("forwardedByMethod", "deniedByMethod"):
        values = payload.get(field)
        if not isinstance(values, dict):
            return {"status": "unknown", "reason": "source_proxy_metrics_invalid"}
        parsed: dict[str, int] = {}
        for name, value in values.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
                return {"status": "unknown", "reason": "source_proxy_metrics_invalid"}
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return {"status": "unknown", "reason": "source_proxy_metrics_invalid"}
            parsed[name] = value
        method_counts[field] = parsed
    return {"status": "observed", **counts, **method_counts}


def _counter_delta(start: dict[str, Any], end: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    if start.get("status") != "observed" or end.get("status") != "observed":
        return {"status": "unknown", "reason": "counter_snapshot_unavailable"}
    delta: dict[str, int] = {}
    for field in fields:
        before = start.get(field)
        after = end.get(field)
        if not isinstance(before, int) or not isinstance(after, int) or after < before:
            return {"status": "unknown", "reason": "counter_reset_or_invalid"}
        delta[field] = after - before
    return {"status": "observed", **delta}


def _container_report(
    info: ContainerInfo,
    samples: list[dict[str, Any]],
    guardrails: dict[str, int],
) -> dict[str, Any]:
    observed = [sample for sample in samples if sample.get("cgroup", {}).get("status") == "observed"]
    base: dict[str, Any] = {
        "service": info.service,
        "containerId": info.container_id[:12],
        "image": info.image,
        "state": info.state,
        "dockerConfiguredMemoryBytes": info.configured_memory_bytes,
        "dockerConfiguredNanoCpus": info.configured_nano_cpus,
        "cgroupVersion": "v2" if observed else None,
        "samples": samples,
    }
    if not observed:
        base.update(
            cgroupStatus="unknown",
            cpuUsageStatus="unknown",
            cpuUsageDeltaNanoseconds=None,
            memoryCurrentWindowMaximumBytes=None,
            memoryCurrentWindowSampleCount=0,
            memoryPeakBytesSinceContainerStart=None,
            memoryPeakScope="since-container-cgroup-creation",
        )
        return base

    first = observed[0]["cgroup"]
    last = observed[-1]["cgroup"]
    start_cpu = first.get("cpuUsageNanoseconds") if len(observed) >= 2 else None
    end_cpu = last.get("cpuUsageNanoseconds") if len(observed) >= 2 else None
    cpu_delta = end_cpu - start_cpu if isinstance(start_cpu, int) and isinstance(end_cpu, int) and end_cpu >= start_cpu else None
    current_values = [sample["cgroup"].get("memoryCurrentBytes") for sample in observed]
    current_values = [value for value in current_values if isinstance(value, int)]
    window_max = max(current_values) if len(current_values) >= 2 else None
    peak_values = [sample["cgroup"].get("memoryPeakBytes") for sample in observed]
    peak_values = [value for value in peak_values if isinstance(value, int)]
    lifetime_peak = max(peak_values) if peak_values else None
    policy_key = POLICY_MEMORY_KEYS.get(info.service)
    policy_limit = guardrails.get(policy_key) if policy_key else None
    actual_memory_limits = [sample["cgroup"].get("memoryLimitBytes") for sample in observed]
    actual_memory_limits = [value for value in actual_memory_limits if isinstance(value, int)]
    actual_memory_limit = actual_memory_limits[-1] if actual_memory_limits else None
    configured_matches = (
        info.configured_memory_bytes == policy_limit == actual_memory_limit
        if policy_limit is not None
        else None
    )
    actual_cpu_limit = last.get("cpuLimit")
    if not isinstance(actual_cpu_limit, dict):
        cpu_limit_matches = None
    elif info.configured_nano_cpus is None:
        cpu_limit_matches = actual_cpu_limit.get("unlimited") is True
    else:
        quota = actual_cpu_limit.get("quota")
        period = actual_cpu_limit.get("period")
        cpu_limit_matches = (
            isinstance(quota, int)
            and not isinstance(quota, bool)
            and isinstance(period, int)
            and not isinstance(period, bool)
            and period > 0
            and quota * 1_000_000_000 == info.configured_nano_cpus * period
        )
    base.update(
        cgroupStatus="observed",
        cpuUsageStartNanoseconds=start_cpu,
        cpuUsageEndNanoseconds=end_cpu,
        cpuUsageDeltaNanoseconds=cpu_delta,
        cpuUsageStatus="observed" if cpu_delta is not None else "unknown",
        memoryCurrentWindowMaximumBytes=window_max,
        memoryCurrentWindowSampleCount=len(current_values),
        memoryPeakBytesSinceContainerStart=lifetime_peak,
        memoryPeakScope="since-container-cgroup-creation",
        dockerConfiguredMemoryLimitMatchesPolicy=configured_matches,
        policyMemoryLimitBytes=policy_limit,
        cgroupMemoryLimitBytes=actual_memory_limit,
        dockerConfiguredCpuLimitMatchesCgroup=cpu_limit_matches,
        cgroupCpuLimit=actual_cpu_limit,
    )
    if cpu_limit_matches is True:
        base["cpuLimitCheck"] = {"status": "compatible"}
    elif cpu_limit_matches is False:
        base["cpuLimitCheck"] = {"status": "incompatible", "reason": "docker_and_cgroup_cpu_limits_differ"}
    else:
        base["cpuLimitCheck"] = {"status": "unknown", "reason": "cpu_limit_unavailable"}
    if policy_limit is not None:
        if configured_matches is False:
            base["memoryLimitCheck"] = {"status": "incompatible", "reason": "configured_limits_do_not_match_manifest"}
        elif configured_matches is None:
            base["memoryLimitCheck"] = {"status": "unknown", "reason": "configured_limit_unavailable"}
        elif window_max is None:
            base["memoryLimitCheck"] = {"status": "unknown", "reason": "window_memory_samples_unavailable"}
        elif window_max > policy_limit:
            base["memoryLimitCheck"] = {"status": "exceeded", "observedBytes": window_max, "limitBytes": policy_limit}
        else:
            base["memoryLimitCheck"] = {"status": "within_limit", "observedBytes": window_max, "limitBytes": policy_limit}
    return base


def collect_resource_window(
    *,
    duration_seconds: float = 5.0,
    interval_seconds: float = 1.0,
    artifact_path: Path | None = None,
    cache_path: Path | None = None,
    source_proxy_port: int = 18544,
    on_violation: Callable[[GuardrailViolation], bool | None] | None = None,
) -> dict[str, Any]:
    """Observe this fixed Compose project; never starts or stops a container.

    The optional callback is supplied only by a future owner of the active
    trial. A ``True`` return is only the owner's report and is not independent
    fence evidence. The collector itself has no destructive Docker path.
    """

    if (
        isinstance(duration_seconds, bool)
        or not isinstance(duration_seconds, (int, float))
        or not math.isfinite(duration_seconds)
        or duration_seconds <= 0
        or duration_seconds > 3_600
    ):
        raise SamplerBlocked("duration_out_of_range")
    if (
        isinstance(interval_seconds, bool)
        or not isinstance(interval_seconds, (int, float))
        or not math.isfinite(interval_seconds)
        or interval_seconds < 0.1
        or interval_seconds > 30
    ):
        raise SamplerBlocked("interval_out_of_range")
    if isinstance(source_proxy_port, bool) or not isinstance(source_proxy_port, int) or not 0 < source_proxy_port <= 65_535:
        raise SamplerBlocked("source_proxy_port_invalid")
    guardrails, manifest_meta = _load_guardrails()
    if duration_seconds > guardrails["maxTrialSeconds"]:
        raise SamplerBlocked("duration_exceeds_manifest_observation_bound")
    compose_bytes = COMPOSE_FILE.read_bytes()
    compose_meta = {
        "composePath": COMPOSE_FILE.relative_to(REPOSITORY_ROOT).as_posix(),
        "composeSha256": _sha256(compose_bytes),
        "projectName": PROJECT_NAME,
    }

    host_info: dict[str, Any]
    try:
        host_info = {"status": "observed", **_docker_host_info()}
    except SamplerBlocked as error:
        host_info = {"status": "unknown", "reason": error.code}

    containers, inventory_issues = _container_inventory()
    if not containers:
        raise SamplerBlocked("compose_project_containers_unavailable")

    service_key = _read_service_key()
    initial_metrics = _source_proxy_metrics(source_proxy_port, service_key)
    start_utc = _utc_now()
    start_monotonic = time.monotonic_ns()
    container_series: dict[str, list[dict[str, Any]]] = {container.service: [] for container in containers}
    source_series: list[dict[str, Any]] = []
    artifact_series: list[dict[str, Any]] = []
    cache_series: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    callback_result: dict[str, Any] = {"status": "not_configured"}
    callback_called = False

    def sample_once() -> None:
        offset_ns = time.monotonic_ns() - start_monotonic
        for info in containers:
            cgroup = _cgroup_snapshot(info)
            container_series[info.service].append({"offsetNanoseconds": offset_ns, "cgroup": cgroup})
        source_series.append({"offsetNanoseconds": offset_ns, "metrics": _source_proxy_metrics(source_proxy_port, service_key)})
        artifact_series.append({"offsetNanoseconds": offset_ns, **_measure_tree(artifact_path)})
        cache_series.append({"offsetNanoseconds": offset_ns, **_measure_tree(cache_path)})

    sample_once()
    end_target = start_monotonic + int(duration_seconds * 1_000_000_000)
    violation_notified = False
    while True:
        now = time.monotonic_ns()
        remaining_ns = end_target - now
        if remaining_ns <= 0:
            break
        time.sleep(min(interval_seconds, remaining_ns / 1_000_000_000))
        sample_once()
        candidate_violations: list[GuardrailViolation] = []
        for info in containers:
            policy_key = POLICY_MEMORY_KEYS.get(info.service)
            if not policy_key:
                continue
            samples = container_series[info.service]
            current = [
                sample["cgroup"].get("memoryCurrentBytes")
                for sample in samples
                if sample.get("cgroup", {}).get("status") == "observed"
            ]
            current = [value for value in current if isinstance(value, int)]
            if current and max(current) > guardrails[policy_key]:
                candidate_violations.append(
                    GuardrailViolation(SCENARIO_ID, PROJECT_NAME, (info.container_id,), f"{info.service}_memory", max(current), guardrails[policy_key], "bytes")
                )
        if artifact_path is not None:
            artifact_sizes = [sample.get("bytes") for sample in artifact_series if sample.get("status") == "observed"]
            artifact_sizes = [value for value in artifact_sizes if isinstance(value, int)]
            if artifact_sizes and artifact_sizes[0] == 0 and max(artifact_sizes) > guardrails["maxEvidenceBytesPerTrial"]:
                candidate_violations.append(
                    GuardrailViolation(SCENARIO_ID, PROJECT_NAME, tuple(c.container_id for c in containers), "max_evidence_bytes", max(artifact_sizes), guardrails["maxEvidenceBytesPerTrial"], "bytes")
                )
        if candidate_violations:
            violations.extend(
                {"code": item.code, "observed": item.observed, "limit": item.limit, "unit": item.unit}
                for item in candidate_violations
            )
            if not violation_notified and on_violation is not None:
                callback_called = True
                try:
                    confirmed = on_violation(candidate_violations[0])
                    callback_result = {
                        "status": "owner_reported_fence_unverified" if confirmed is True else "called_without_fence_evidence",
                        "independentEvidenceRequired": True,
                    }
                except Exception:
                    callback_result = {"status": "callback_failed"}
                violation_notified = True
            # Stop sampling at the first measured overrun. This does not stop
            # the workload; only the explicit owner callback can fence it.
            break

    end_monotonic = time.monotonic_ns()
    end_utc = _utc_now()
    elapsed_ns = end_monotonic - start_monotonic
    maximum_observation_ns = guardrails["maxTrialSeconds"] * 1_000_000_000
    collector_window_check = {
        "status": "within_bound" if elapsed_ns <= maximum_observation_ns else "collector_window_exceeded",
        "observedNanoseconds": elapsed_ns,
        "maximumObservationSeconds": guardrails["maxTrialSeconds"],
        "scope": "sampler_observation_window_only; no_trial_runtime_assertion",
    }
    final_metrics = source_series[-1]["metrics"] if source_series else {"status": "unknown", "reason": "no_source_metric_samples"}
    source_delta = _counter_delta(
        initial_metrics,
        final_metrics,
        ("forwardedItems", "deniedItems", "upstreamErrors", "sourceCallsReserved"),
    )
    if source_delta.get("status") == "observed":
        for field in ("forwardedByMethod", "deniedByMethod"):
            before = initial_metrics.get(field)
            after = final_metrics.get(field)
            if not isinstance(before, dict) or not isinstance(after, dict):
                source_delta[field] = None
                continue
            keys = set(before) | set(after)
            per_method: dict[str, int] = {}
            for method in sorted(keys):
                first_value = before.get(method, 0)
                last_value = after.get(method, 0)
                if not isinstance(first_value, int) or not isinstance(last_value, int) or last_value < first_value:
                    per_method = {}
                    break
                per_method[method] = last_value - first_value
            source_delta[field] = per_method if per_method else ({} if not keys else None)
    else:
        source_delta["forwardedByMethod"] = None
        source_delta["deniedByMethod"] = None

    source_limit_expected = guardrails["maxSourceCallsPerTrial"]
    source_proxy_limit_check = {
        "status": "unknown",
        "reason": "source_proxy_policy_limit_unavailable",
        "expectedLimitPerTrial": source_limit_expected,
    }
    if initial_metrics.get("status") == "observed" and final_metrics.get("status") == "observed":
        initial_limit = initial_metrics.get("sourceCallLimit")
        final_limit = final_metrics.get("sourceCallLimit")
        if initial_limit == final_limit == source_limit_expected:
            source_proxy_limit_check = {"status": "compatible", "expectedLimitPerTrial": source_limit_expected}
        else:
            source_proxy_limit_check = {
                "status": "incompatible",
                "reason": "source_proxy_limit_does_not_match_manifest",
                "expectedLimitPerTrial": source_limit_expected,
                "startLimit": initial_limit,
                "endLimit": final_limit,
            }

    container_reports = [
        _container_report(info, container_series[info.service], guardrails)
        for info in containers
    ]
    artifact_observed = [sample.get("bytes") for sample in artifact_series if sample.get("status") == "observed"]
    artifact_observed = [value for value in artifact_observed if isinstance(value, int)]
    artifact_guardrail: dict[str, Any]
    if artifact_path is None or len(artifact_observed) < 2:
        artifact_guardrail = {"status": "unknown", "reason": "trial_artifact_directory_not_measured"}
    else:
        start_bytes = artifact_observed[0]
        final_bytes = artifact_observed[-1]
        if start_bytes != 0:
            artifact_guardrail = {"status": "unknown", "reason": "trial_artifact_directory_not_empty_at_window_start"}
        else:
            max_bytes = max(artifact_observed)
            artifact_guardrail = {
                "status": "exceeded" if max_bytes > guardrails["maxEvidenceBytesPerTrial"] else "within_limit",
                "observedMaximumBytes": max_bytes,
                "finalBytes": final_bytes,
                "limitBytes": guardrails["maxEvidenceBytesPerTrial"],
                "scope": "sampled_task_artifact_directory; collector_report_not_included",
            }

    memory_checks = [report.get("memoryLimitCheck", {"status": "unknown", "reason": "memory_limit_not_observed"}) for report in container_reports if report["service"] in POLICY_MEMORY_KEYS]
    source_delta_calls = source_delta.get("sourceCallsReserved") if source_delta.get("status") == "observed" else None
    source_limit_check = {
        "status": "unknown",
        "reason": "aggregate_proxy_counter_is_not_generation_attributed",
        "observedWindowDelta": source_delta_calls,
        "limitPerTrial": guardrails["maxSourceCallsPerTrial"],
    }
    if source_delta_calls is not None and source_delta_calls > guardrails["maxSourceCallsPerTrial"]:
        source_limit_check.update(status="exceeded", reason="aggregate_window_delta_exceeds_limit_but_trial_attribution_is_unknown")

    missing_cgroup_services = [report["service"] for report in container_reports if report.get("cgroupStatus") != "observed"]
    missing_cpu_services = [report["service"] for report in container_reports if report.get("cpuUsageStatus") != "observed"]
    manifest_memory_checks = [check.get("status") for check in memory_checks]
    overall_issues = list(inventory_issues)
    if host_info.get("status") != "observed":
        overall_issues.append({"service": "docker-host", "code": "host_info_unavailable"})
    if missing_cgroup_services:
        overall_issues.extend({"service": service, "code": "cgroup_v2_metrics_unavailable"} for service in missing_cgroup_services)
    if missing_cpu_services:
        overall_issues.extend({"service": service, "code": "cpu_window_measurement_unavailable"} for service in missing_cpu_services)
    if collector_window_check["status"] != "within_bound":
        overall_issues.append({"service": "collector", "code": "observation_window_exceeded_manifest_time_bound"})
    if source_delta.get("status") != "observed":
        overall_issues.append({"service": "source-proxy", "code": "source_request_counter_unavailable"})
    overall_issues.append({"service": "source-proxy", "code": "per_trial_source_call_attribution_unknown"})
    if source_limit_check.get("status") == "exceeded":
        overall_issues.append({"service": "source-proxy", "code": "aggregate_source_call_delta_exceeds_limit_without_trial_attribution"})
    if artifact_guardrail.get("status") == "unknown":
        overall_issues.append({"service": "artifact-directory", "code": "artifact_byte_measurement_unavailable"})
    overall_issues.append({"service": "cache-directory", "code": "cold_warm_cache_provenance_unavailable"})
    if any(status == "incompatible" for status in manifest_memory_checks):
        overall_issues.append({"service": "memory-limits", "code": "configured_limit_mismatch"})
    if any(status == "unknown" for status in manifest_memory_checks):
        overall_issues.append({"service": "memory-limits", "code": "memory_window_measurement_unavailable"})
    if any(report.get("cpuLimitCheck", {}).get("status") == "incompatible" for report in container_reports):
        overall_issues.append({"service": "cpu-limits", "code": "configured_limit_mismatch"})
    if source_proxy_limit_check.get("status") == "incompatible":
        overall_issues.append({"service": "source-proxy", "code": "configured_source_call_limit_mismatch"})
    overall_status = "guardrail_exceeded" if violations else ("captured" if not overall_issues else "blocked")
    report = {
        "schemaVersion": SCHEMA_VERSION,
        "scenarioId": SCENARIO_ID,
        "status": overall_status,
        "gateStatus": "not_established_by_resource_window",
        "trialCorrelation": {"status": "unknown", "reason": "no_actual_probe_operation_or_generation_binding"},
        "cacheCondition": {"status": "unknown", "reason": "dedicated_cold_warm_cache_provenance_not_supplied"},
        "providerComputeUnits": {"status": "unknown", "reason": "provider_cu_not_observable"},
        "startedAtUtc": start_utc,
        "finishedAtUtc": end_utc,
        "elapsedMonotonicNanoseconds": elapsed_ns,
        "sampleIntervalSecondsRequested": interval_seconds,
        "sampleCount": len(next(iter(container_series.values()))) if container_series else 0,
        "manifest": manifest_meta,
        "compose": compose_meta,
        "host": host_info,
        "containers": container_reports,
        "sourceProxy": {
            "status": final_metrics.get("status", "unknown"),
            "boundary": "loopback-protected-source-proxy-admin-metrics",
            "counterScope": "aggregate_proxy_process",
            "trialAttribution": "unknown_if_concurrent_or_unbound",
            "start": initial_metrics,
            "end": final_metrics,
            "windowDelta": source_delta,
            "configuredLimitCheck": source_proxy_limit_check,
            "guardrailCheck": source_limit_check,
            "providerComputeUnits": "unknown",
        },
        "artifactDirectory": {
            "path": artifact_path.relative_to(REPOSITORY_ROOT).as_posix() if artifact_path else None,
            "samples": artifact_series,
            "guardrailCheck": artifact_guardrail,
        },
        "cacheDirectory": {
            "path": cache_path.relative_to(REPOSITORY_ROOT).as_posix() if cache_path else None,
            "samples": cache_series,
            "condition": {"status": "unknown", "reason": "directory_bytes_do_not_prove_cold_or_warm_state"},
        },
        "guardrails": {
            "manifestValues": guardrails,
            "collectorObservationWindow": collector_window_check,
            "memoryLimits": memory_checks,
            "artifactBytes": artifact_guardrail,
            "sourceCalls": source_limit_check,
            "violations": violations,
            "fenceCallback": callback_result,
            "fenceCallbackInvoked": callback_called,
        },
        "issues": overall_issues,
    }
    return report


def _trial_resource_snapshot(
    containers: Sequence[ContainerInfo],
    *,
    source_proxy_port: int,
    service_key: str | None,
    artifact_path: Path,
    cache_path: Path | None,
) -> dict[str, Any]:
    """Read one bounded snapshot using only fixed-project containers and paths."""

    container_rows = []
    for info in containers:
        container_rows.append({
            "service": info.service,
            "containerId": info.container_id[:12],
            "state": info.state,
            "dockerConfiguredMemoryBytes": info.configured_memory_bytes,
            "dockerConfiguredNanoCpus": info.configured_nano_cpus,
            "cgroup": _cgroup_snapshot(info),
        })
    return {
        "containers": container_rows,
        "sourceProxy": _source_proxy_metrics(source_proxy_port, service_key),
        "artifactDirectory": _measure_tree(artifact_path),
        "cacheDirectory": _measure_tree(cache_path),
    }


def parse_anvil_cache_binding(
    command_json: str,
    mounts_json: str,
    created_at: str,
    *,
    home_directory: str | None,
    expected_state_source: str | None = None,
    expected_rpc_source: str | None = None,
) -> dict[str, Any]:
    """Verify both Anvil state-cache and Foundry fork-RPC-cache bind mounts."""

    try:
        command = json.loads(command_json)
        mounts = json.loads(mounts_json)
    except json.JSONDecodeError:
        return {"status": "unknown", "reason": "container_cache_inspection_invalid"}
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command) or not isinstance(mounts, list):
        return {"status": "unknown", "reason": "container_cache_inspection_invalid"}

    cache_targets: list[str] = []
    for index, item in enumerate(command):
        if item == "--cache-path" and index + 1 < len(command):
            cache_targets.append(command[index + 1])
        elif item.startswith("--cache-path="):
            cache_targets.append(item.partition("=")[2])
    if not cache_targets:
        rpc_mount_status = "unknown"
        if isinstance(home_directory, str) and home_directory.startswith("/"):
            rpc_target = str(Path(home_directory) / ".foundry" / "cache").replace("\\", "/")
            rpc_matching = [item for item in mounts if isinstance(item, dict) and item.get("Destination") == rpc_target]
            if not rpc_matching:
                rpc_mount_status = "missing"
            elif len(rpc_matching) == 1:
                rpc_mount = rpc_matching[0]
                source = rpc_mount.get("Source")
                if rpc_mount.get("Type") == "bind" and rpc_mount.get("RW") is True and isinstance(source, str):
                    try:
                        Path(source).resolve(strict=False).relative_to(ARTIFACTS_ROOT)
                        rpc_mount_status = "observed_task_owned_bind"
                    except (OSError, ValueError):
                        rpc_mount_status = "not_task_owned"
                else:
                    rpc_mount_status = "not_writable_bind"
        return {
            "status": "unconfigured",
            "reason": "anvil_state_cache_path_not_configured",
            "stateCacheConfigured": False,
            "rpcCacheMountStatus": rpc_mount_status,
        }
    if len(cache_targets) != 1:
        return {"status": "unknown", "reason": "anvil_cache_path_ambiguous"}

    target = cache_targets[0]
    if not target.startswith("/") or ".." in Path(target).parts:
        return {"status": "unknown", "reason": "anvil_cache_path_invalid"}
    state_matching = [
        item for item in mounts
        if isinstance(item, dict) and item.get("Destination") == target
    ]
    if len(state_matching) != 1:
        return {"status": "unknown", "reason": "anvil_state_cache_bind_mount_missing"}
    state_mount = state_matching[0]
    if state_mount.get("Type") != "bind" or state_mount.get("RW") is not True:
        return {"status": "unknown", "reason": "anvil_state_cache_bind_mount_not_writable"}
    state_source = state_mount.get("Source")
    if not isinstance(state_source, str) or not state_source:
        return {"status": "unknown", "reason": "anvil_state_cache_bind_source_missing"}

    if not isinstance(home_directory, str) or not home_directory.startswith("/"):
        return {"status": "unknown", "reason": "anvil_home_directory_unavailable"}
    rpc_target = str(Path(home_directory) / ".foundry" / "cache").replace("\\", "/")
    rpc_matching = [item for item in mounts if isinstance(item, dict) and item.get("Destination") == rpc_target]
    if len(rpc_matching) != 1:
        return {"status": "unknown", "reason": "foundry_rpc_cache_bind_mount_missing"}
    rpc_mount = rpc_matching[0]
    if rpc_mount.get("Type") != "bind" or rpc_mount.get("RW") is not True:
        return {"status": "unknown", "reason": "foundry_rpc_cache_bind_mount_not_writable"}
    rpc_source = rpc_mount.get("Source")
    if not isinstance(rpc_source, str) or not rpc_source:
        return {"status": "unknown", "reason": "foundry_rpc_cache_bind_source_missing"}

    try:
        if expected_state_source is not None or expected_rpc_source is not None:
            if not expected_state_source or not expected_rpc_source:
                return {"status": "unknown", "reason": "compose_cache_source_expectation_incomplete"}
            if (
                _canonical_host_mount_source(state_source) != _canonical_host_mount_source(expected_state_source)
                or _canonical_host_mount_source(rpc_source) != _canonical_host_mount_source(expected_rpc_source)
            ):
                return {"status": "unknown", "reason": "inspected_cache_mount_differs_from_compose_config"}
            # Compose config is the host-side source of truth. Docker Desktop
            # can rewrite its inspect-side spelling to
            # /run/desktop/mnt/host/<drive>/..., so containment is checked on
            # the Compose source after applying only that observed mapping.
            state_source = expected_state_source
            rpc_source = expected_rpc_source
        resolved_state_source = _resolve_compose_host_source(state_source)
        resolved_rpc_source = _resolve_compose_host_source(rpc_source)
        relative_state_source = resolved_state_source.relative_to(ARTIFACTS_ROOT)
        relative_rpc_source = resolved_rpc_source.relative_to(ARTIFACTS_ROOT)
    except (OSError, ValueError):
        return {"status": "unknown", "reason": "anvil_cache_mount_not_task_owned"}
    if (
        not relative_state_source.parts
        or not relative_rpc_source.parts
        or any(part.lower() in POLLUTION_PRONE_PARTS for part in relative_state_source.parts + relative_rpc_source.parts)
    ):
        return {"status": "unknown", "reason": "anvil_cache_mount_not_task_owned"}
    try:
        relative_state_source.relative_to(relative_rpc_source)
        shared_cache_roots = True
    except ValueError:
        try:
            relative_rpc_source.relative_to(relative_state_source)
            shared_cache_roots = True
        except ValueError:
            shared_cache_roots = False
    if shared_cache_roots:
        return {"status": "unknown", "reason": "anvil_cache_mounts_must_be_separate"}

    parsed_created: str | None = None
    try:
        parsed_created = datetime.fromisoformat(created_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (AttributeError, TypeError, ValueError):
        pass
    return {
        "status": "observed",
        "reason": None,
        "stateCacheContainerPath": target,
        "stateCacheHostPath": resolved_state_source.relative_to(REPOSITORY_ROOT).as_posix(),
        "rpcCacheContainerPath": rpc_target,
        "rpcCacheHostPath": resolved_rpc_source.relative_to(REPOSITORY_ROOT).as_posix(),
        "containerCreatedAtUtc": parsed_created,
        "bindMountWritable": True,
    }


_DESKTOP_MOUNT_SOURCE = re.compile(r"^/run/desktop/mnt/host/([a-z])(?:/(.*))?$", re.IGNORECASE)
_WINDOWS_DRIVE_SOURCE = re.compile(r"^([a-z]):(?:/(.*))?$", re.IGNORECASE)


# AICODE-NOTE: The bind's RW flag does not prove the Anvil uid can use it; verify each cache target as the container's configured user after resolving that user's effective HOME.
def _container_home_directory(container_env_json: str) -> str | None:
    """Resolve the effective container HOME without assuming named users' homes."""

    try:
        container_env = json.loads(container_env_json)
    except json.JSONDecodeError:
        return None
    if not isinstance(container_env, list) or not all(isinstance(item, str) for item in container_env):
        return None
    home_values = [item.partition("=")[2] for item in container_env if item.startswith("HOME=")]
    if len(home_values) != 1:
        return None
    home = home_values[0]
    if not home.startswith("/") or "\x00" in home or ".." in PurePosixPath(home).parts:
        return None
    return posixpath.normpath(home)


def _compose_home_directory(environment: Any) -> str | None:
    """Read an explicit absolute HOME from one expanded Compose service."""

    values: list[str] = []
    if isinstance(environment, dict):
        value = environment.get("HOME")
        if isinstance(value, str):
            values = [value]
    elif isinstance(environment, list):
        values = [item.partition("=")[2] for item in environment if isinstance(item, str) and item.startswith("HOME=")]
    if len(values) != 1:
        return None
    home = values[0]
    if not home.startswith("/") or "\x00" in home or ".." in PurePosixPath(home).parts:
        return None
    return posixpath.normpath(home)


def _canonical_host_mount_source(raw_source: str) -> str:
    """Normalize Docker Desktop inspect paths against Compose host paths."""

    value = raw_source.strip().replace("\\", "/")
    desktop = _DESKTOP_MOUNT_SOURCE.fullmatch(value)
    if desktop:
        drive = desktop.group(1).lower()
        tail = posixpath.normpath(desktop.group(2) or "")
        return f"drive:{drive}/{'' if tail == '.' else tail.strip('/').casefold()}".rstrip("/")
    windows = _WINDOWS_DRIVE_SOURCE.fullmatch(value)
    if windows:
        drive = windows.group(1).lower()
        tail = posixpath.normpath(windows.group(2) or "")
        return f"drive:{drive}/{'' if tail == '.' else tail.strip('/').casefold()}".rstrip("/")
    if not value.startswith("/"):
        return "relative:" + posixpath.normpath(value).lower()
    return "posix:" + posixpath.normpath(value).lower()


def _resolve_compose_host_source(raw_source: str) -> Path:
    """Resolve a Compose source using the local host's path semantics."""

    normalized = raw_source.strip().replace("\\", "/")
    desktop = _DESKTOP_MOUNT_SOURCE.fullmatch(normalized)
    if desktop:
        normalized = f"{desktop.group(1).upper()}:/{desktop.group(2) or ''}"
    return Path(normalized).resolve(strict=False)


def _compose_anvil_cache_sources() -> tuple[dict[str, dict[str, str]], str]:
    """Read expanded Compose config and return its four task-owned bind roots."""

    output = _run_command(
        ["docker", "compose", "--project-name", PROJECT_NAME, "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        timeout=15.0,
    )
    try:
        config = json.loads(output)
    except json.JSONDecodeError as error:
        raise SamplerBlocked("compose_config_invalid") from error
    services = config.get("services") if isinstance(config, dict) else None
    if not isinstance(services, dict):
        raise SamplerBlocked("compose_config_services_missing")
    result: dict[str, dict[str, str]] = {}
    for service in ("anvil-a", "anvil-b"):
        definition = services.get(service)
        volumes = definition.get("volumes") if isinstance(definition, dict) else None
        if not isinstance(volumes, list):
            raise SamplerBlocked("compose_cache_volumes_missing")
        home_directory = _compose_home_directory(definition.get("environment")) if isinstance(definition, dict) else None
        if home_directory is None:
            raise SamplerBlocked("compose_anvil_home_directory_unavailable")
        parsed: dict[str, str] = {}
        expected_targets = {
            "/var/lib/anvil/state-cache": "state",
            posixpath.join(home_directory, ".foundry", "cache"): "rpc",
        }
        for volume in volumes:
            if not isinstance(volume, dict):
                continue
            target = volume.get("target")
            kind = volume.get("type")
            source = volume.get("source")
            bind = volume.get("bind")
            create_host_path = bind.get("create_host_path") if isinstance(bind, dict) else None
            label = expected_targets.get(target)
            if label is None:
                continue
            if kind != "bind" or not isinstance(source, str) or not source or create_host_path is not False:
                raise SamplerBlocked("compose_cache_bind_not_explicit_task_owned")
            resolved = _resolve_compose_host_source(source)
            try:
                relative = resolved.relative_to(ARTIFACTS_ROOT.resolve(strict=False))
            except (OSError, ValueError) as error:
                raise SamplerBlocked("compose_cache_bind_outside_ignored_runs") from error
            if not relative.parts or any(part.lower() in POLLUTION_PRONE_PARTS for part in relative.parts):
                raise SamplerBlocked("compose_cache_bind_not_task_owned")
            parsed[label] = source
        if set(parsed) != {"state", "rpc"}:
            raise SamplerBlocked("compose_cache_bind_pair_incomplete")
        result[service] = parsed
    return result, _sha256(output.encode("utf-8"))


def _container_path_writable(info: ContainerInfo, target: str) -> bool | None:
    """Probe mount write access as the container's configured default user."""

    if (
        not re.fullmatch(_CONTAINER_ID, info.container_id)
        or not target.startswith("/")
        or "\x00" in target
        or ".." in PurePosixPath(target).parts
    ):
        return None
    try:
        result = subprocess.run(
            ["docker", "exec", info.container_id, "test", "-w", target],
            cwd=REPOSITORY_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
            check=False,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _inspect_anvil_cache_binding(
    info: ContainerInfo,
    *,
    expected_sources: dict[str, str] | None = None,
    compose_config_sha256: str | None = None,
) -> dict[str, Any]:
    if info.service not in {"anvil-a", "anvil-b"}:
        return {"status": "unknown", "reason": "not_anvil_service"}
    template = "{{json .Config.Cmd}}|{{json .Mounts}}|{{.Created}}|{{.Config.User}}|{{json .Config.Env}}"
    try:
        output = _run_command(["docker", "inspect", "--format", template, info.container_id], timeout=8.0).strip()
    except SamplerBlocked as error:
        return {"status": "unknown", "reason": error.code}
    fields = output.split("|", 4)
    if len(fields) != 5:
        return {"status": "unknown", "reason": "container_cache_inspection_invalid"}
    command_json, mounts_json, created_at, container_user, container_env_json = fields
    home_directory = _container_home_directory(container_env_json)
    if expected_sources is None:
        try:
            configured, compose_config_sha256 = _compose_anvil_cache_sources()
            expected_sources = configured[info.service]
        except (SamplerBlocked, KeyError) as error:
            code = error.code if isinstance(error, SamplerBlocked) else "compose_cache_service_missing"
            return {"service": info.service, "containerId": info.container_id[:12], "status": "unknown", "reason": code}
    result = parse_anvil_cache_binding(
        command_json,
        mounts_json,
        created_at,
        home_directory=home_directory,
        expected_state_source=expected_sources.get("state"),
        expected_rpc_source=expected_sources.get("rpc"),
    )
    if result.get("status") == "observed":
        state_target = result.get("stateCacheContainerPath")
        rpc_target = result.get("rpcCacheContainerPath")
        if not isinstance(state_target, str) or not isinstance(rpc_target, str):
            return {
                "service": info.service,
                "containerId": info.container_id[:12],
                "composeConfigSha256": compose_config_sha256,
                "status": "unknown",
                "reason": "anvil_cache_writeability_target_unavailable",
            }
        state_writable = _container_path_writable(info, state_target)
        rpc_writable = _container_path_writable(info, rpc_target)
        result["stateCacheWritableByContainerUser"] = state_writable
        result["rpcCacheWritableByContainerUser"] = rpc_writable
        if state_writable is not True or rpc_writable is not True:
            if state_writable is False:
                reason = "anvil_state_cache_not_writable_by_container_user"
            elif rpc_writable is False:
                reason = "foundry_rpc_cache_not_writable_by_container_user"
            else:
                reason = "anvil_cache_path_writeability_unverified"
            result["status"] = "unknown"
            result["reason"] = reason
    return {
        "service": info.service,
        "containerId": info.container_id[:12],
        "composeConfigSha256": compose_config_sha256,
        **result,
    }


def _trial_memory_violations(sample: dict[str, Any], guardrails: dict[str, int]) -> list[GuardrailViolation]:
    violations: list[GuardrailViolation] = []
    containers = sample.get("containers")
    if isinstance(containers, list):
        for row in containers:
            if not isinstance(row, dict):
                continue
            service = row.get("service")
            policy_key = POLICY_MEMORY_KEYS.get(service) if isinstance(service, str) else None
            cgroup = row.get("cgroup")
            current = cgroup.get("memoryCurrentBytes") if isinstance(cgroup, dict) else None
            if policy_key and isinstance(current, int) and not isinstance(current, bool) and current > guardrails[policy_key]:
                violations.append(GuardrailViolation(
                    SCENARIO_ID, PROJECT_NAME, (), f"{service}_memory", current, guardrails[policy_key], "bytes"
                ))
    artifact = sample.get("artifactDirectory")
    artifact_bytes = artifact.get("bytes") if isinstance(artifact, dict) else None
    if isinstance(artifact_bytes, int) and not isinstance(artifact_bytes, bool) and artifact_bytes > guardrails["maxEvidenceBytesPerTrial"]:
        violations.append(GuardrailViolation(
            SCENARIO_ID, PROJECT_NAME, (), "max_evidence_bytes", artifact_bytes,
            guardrails["maxEvidenceBytesPerTrial"], "bytes"
        ))
    return violations


def _linux_stopped_process_has_descendants(pid: int, *, wait_seconds: float) -> bool | None:
    """Inspect every Linux task's children only after the process is stopped."""

    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return None
    task_root = proc_root / str(pid) / "task"
    deadline = time.monotonic() + max(0.1, min(wait_seconds, 1.0))
    while time.monotonic() < deadline:
        try:
            tasks = sorted(task_root.iterdir(), key=lambda item: item.name)
            if not tasks:
                return None
            all_stopped = True
            for task in tasks:
                status_text = (task / "status").read_text(encoding="ascii")
                state_line = next((line for line in status_text.splitlines() if line.startswith("State:")), None)
                state = state_line.partition(":")[2].strip().split()[0] if state_line else ""
                if state not in {"T", "t"}:
                    all_stopped = False
            if not all_stopped:
                time.sleep(0.01)
                continue

            has_children = False
            for task in tasks:
                raw_children = (task / "children").read_text(encoding="ascii").strip()
                if any(not child.isdecimal() for child in raw_children.split()):
                    return None
                has_children = has_children or bool(raw_children)

            # Re-check the frozen task set after reading every children file.
            if sorted(task_root.iterdir(), key=lambda item: item.name) != tasks:
                return None
            for task in tasks:
                status_text = (task / "status").read_text(encoding="ascii")
                state_line = next((line for line in status_text.splitlines() if line.startswith("State:")), None)
                state = state_line.partition(":")[2].strip().split()[0] if state_line else ""
                if state not in {"T", "t"}:
                    return None
            return has_children
        except (OSError, UnicodeDecodeError, IndexError):
            return None
    return None


def _terminate_owned_process_tree(process: subprocess.Popen[Any], *, grace_seconds: float = 1.0) -> dict[str, Any]:
    """Stop only this trial's workload process, and fail closed on descendants.

    On Windows, taskkill is targeted at the exact Popen PID and includes its
    descendants. If that tree operation is unavailable, only the direct child
    is killed and the report retains unknown descendant cleanup status.

    On POSIX, the workload child inherits the dedicated SC011 orchestrator
    process group so the outer adapter can stop the complete scenario group.
    This inner stop targets the direct workload process only. It claims a
    complete stop only after freezing the child and confirming it has no
    descendants; an unexpected child makes cleanup unknown so the outer
    adapter can terminate the whole owned group and the gate remains blocked.
    """

    if process.poll() is not None:
        return {"status": "already_exited", "directChildExited": True, "descendants": "unknown", "treeExitConfirmed": False}

    if os.name == "nt":
        tree_status = "unknown"
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=5.0,
                check=False,
            )
            if result.returncode == 0:
                tree_status = "task_tree_stopped"
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.wait(timeout=5.0)
            confirmed = tree_status == "task_tree_stopped" and process.poll() is not None
            return {
                "status": "stopped" if confirmed else "direct_child_exited" if process.poll() is not None else "unknown",
                "directChildExited": process.poll() is not None,
                "descendants": "stopped" if confirmed else "unknown",
                "treeExitConfirmed": confirmed,
            }
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=5.0)
                return {"status": "direct_child_killed", "directChildExited": True, "descendants": "unknown", "treeExitConfirmed": False}
            except (OSError, subprocess.TimeoutExpired):
                return {"status": "cleanup_failed", "directChildExited": False, "descendants": "unknown", "treeExitConfirmed": False}

    try:
        child_group = os.getpgid(process.pid)
        owner_group = os.getpgrp()
    except OSError:
        child_group = owner_group = -1
    if child_group != owner_group:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return {
            "status": "owned_process_group_unverified",
            "directChildExited": process.poll() is not None,
            "descendants": "unknown",
            "treeExitConfirmed": False,
        }

    # The SC011 workload is a single Node process. Freeze all its threads before
    # checking every task's children so no thread can race a new descendant in.
    try:
        os.kill(process.pid, signal.SIGSTOP)
        has_descendants = _linux_stopped_process_has_descendants(process.pid, wait_seconds=grace_seconds)
    except OSError:
        has_descendants = None
    try:
        os.kill(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        return {"status": "cleanup_failed", "directChildExited": False, "descendants": "unknown", "treeExitConfirmed": False}
    if has_descendants is True:
        return {"status": "child_descendants_observed", "directChildExited": True, "descendants": "unknown", "treeExitConfirmed": False}
    if has_descendants is None:
        return {"status": "child_descendants_unobservable", "directChildExited": True, "descendants": "unknown", "treeExitConfirmed": False}
    return {"status": "direct_child_tree_stopped", "directChildExited": True, "descendants": "stopped", "treeExitConfirmed": True}


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


def _actual_balance_read_matches(
    value: Any, *, env_id: str, generation_id: str, payer: str,
) -> bool:
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


def _load_readiness_marker(
    path: Path,
    *,
    artifact_root: Path,
    evidence_root: Path,
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate the child's real first-read marker before starting an active bound."""

    try:
        symlink = path.is_symlink()
        is_file = path.is_file()
    except OSError:
        return None, "readiness_marker_metadata_unavailable"
    if symlink or not is_file:
        return None, "readiness_marker_not_available"
    try:
        resolved = path.resolve(strict=False)
        root = artifact_root.resolve(strict=False)
    except OSError:
        return None, "readiness_marker_resolution_failed"
    try:
        resolved.relative_to(root)
    except ValueError:
        return None, "readiness_marker_outside_artifacts_root"
    try:
        raw = resolved.read_bytes()
    except OSError:
        return None, "readiness_marker_read_failed"
    if len(raw) > 16_384:
        return None, "readiness_marker_too_large"
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "readiness_marker_json_invalid"
    if not isinstance(payload, dict) or payload.get("schemaVersion") != "bef-resource-workload-ready/v1":
        return None, "readiness_marker_schema_invalid"
    first_read = payload.get("firstRead")
    identity = first_read.get("responseIdentity") if isinstance(first_read, dict) else None
    artifact = first_read.get("artifact") if isinstance(first_read, dict) else None
    if (
        payload.get("phase") != "guardrail_exceeded"
        or not isinstance(payload.get("envId"), str)
        or not isinstance(payload.get("generationId"), str)
        or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", str(payload.get("generationId", "")), re.IGNORECASE)
        or not isinstance(payload.get("payerAddress"), str)
        or not re.fullmatch(r"0x[0-9a-f]{40}", str(payload.get("payerAddress", "")), re.IGNORECASE)
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("manifestSha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("applicationSourceSha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("probeSourceSha256", "")))
        or not isinstance(first_read, dict)
        or first_read.get("status") != 200
        or not isinstance(identity, dict)
        or identity.get("boundary") != "local-chain-readonly-proxy"
        or identity.get("envId") != payload.get("envId")
        or identity.get("generationId") != payload.get("generationId")
        or not isinstance(identity.get("payer"), str)
        or _EVM_ADDRESS.fullmatch(identity["payer"]) is None
        or identity["payer"].lower() != payload["payerAddress"].lower()
        or not isinstance(artifact, dict)
        or not isinstance(artifact.get("path"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", "")))
        or artifact.get("boundary") != "actual-tool-http"
        or artifact.get("contentType") != "application/json"
        or payload.get("completedReadsBeforeDeadline") != 1
    ):
        return None, "readiness_marker_first_read_proof_incomplete"

    try:
        evidence_resolved = evidence_root.resolve(strict=False)
        evidence_resolved.relative_to(root)
        relative_artifact = Path(str(artifact["path"]))
        if relative_artifact.is_absolute() or "\\" in str(artifact["path"]) or any(
            part in {"", ".", ".."} for part in relative_artifact.parts
        ):
            return None, "readiness_marker_artifact_path_invalid"
        observed_artifact = evidence_resolved.joinpath(*relative_artifact.parts)
        if observed_artifact.is_symlink() or not observed_artifact.is_file():
            return None, "readiness_marker_http_artifact_unavailable"
        observed_artifact = observed_artifact.resolve(strict=False)
        observed_artifact.relative_to(evidence_resolved)
        artifact_bytes = observed_artifact.read_bytes()
    except (OSError, ValueError):
        return None, "readiness_marker_http_artifact_path_invalid"
    if len(artifact_bytes) > 1_048_576 or _sha256(artifact_bytes) != artifact.get("sha256"):
        return None, "readiness_marker_http_artifact_hash_mismatch"
    try:
        http_observation = json.loads(artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "readiness_marker_http_artifact_json_invalid"
    request = http_observation.get("request") if isinstance(http_observation, dict) else None
    response = http_observation.get("response") if isinstance(http_observation, dict) else None
    response_body = response.get("body") if isinstance(response, dict) else None
    expected_path = f"/tools/{payload['envId']}/balances"
    if (
        not isinstance(http_observation, dict)
        or http_observation.get("schemaVersion") != "bef-http-observation/v1"
        or http_observation.get("boundary") != "actual-tool-http"
        or http_observation.get("operationId") is not None
        or http_observation.get("variantId") != "guardrail_exceeded"
        or not isinstance(request, dict)
        or request.get("method") != "GET"
        or request.get("path") != expected_path
        or not isinstance(response, dict)
        or response.get("status") != 200
        or not _actual_balance_read_matches(
            response_body,
            env_id=payload["envId"],
            generation_id=payload["generationId"],
            payer=payload["payerAddress"],
        )
    ):
        return None, "readiness_marker_http_artifact_not_actual_matching_read"
    return {
        "path": resolved.relative_to(REPOSITORY_ROOT).as_posix(),
        "sha256": _sha256(raw),
        "envId": payload["envId"],
        "generationId": payload["generationId"],
        "firstRead": first_read,
        "httpArtifactSha256": _sha256(artifact_bytes),
    }, None


def _write_release_signal(path: Path, *, marker_sha256: str) -> None:
    """Create a one-shot child release signal after readiness proof is observed."""

    if path.exists() or path.is_symlink():
        raise SamplerBlocked("trial_readiness_release_path_not_new")
    payload = {
        "schemaVersion": "bef-resource-workload-release/v1",
        "markerSha256": marker_sha256,
        "releasedAtUtc": _utc_now(),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    except OSError as error:
        raise SamplerBlocked("trial_readiness_release_write_failed") from error


def run_bounded_trial_command(
    command: Sequence[str],
    *,
    artifact_path: Path,
    cache_path: Path | None = None,
    cache_paths: dict[str, Path] | None = None,
    source_proxy_port: int = 18_544,
    interval_seconds: float = 1.0,
    timeout_seconds: float | None = None,
    on_fence: Callable[[GuardrailViolation], Any] | None = None,
    readiness_marker: Path | None = None,
    readiness_release: Path | None = None,
    active_limit_seconds: float | None = None,
    fence_generation: Callable[[GuardrailViolation], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Run one task-owned command inside a sampled, manifest-bounded window.

    The standalone CLI remains read-only. The explicit SC011 task-owned
    orchestrator supplies its own probe command and a post-stop independent
    fence callback. Process-group cleanup is only a process stop; it does not
    prove that an in-flight API/chain effect was fenced.
    """

    if not isinstance(command, (list, tuple)) or not command or any(not isinstance(part, str) or not part or "\x00" in part for part in command):
        raise SamplerBlocked("trial_command_invalid")
    if len(command) > 128 or sum(len(part.encode("utf-8")) for part in command) > 32_768:
        raise SamplerBlocked("trial_command_too_large")
    if (
        isinstance(interval_seconds, bool)
        or not isinstance(interval_seconds, (int, float))
        or not math.isfinite(interval_seconds)
        or interval_seconds < 0.1
        or interval_seconds > 30
    ):
        raise SamplerBlocked("interval_out_of_range")

    guardrails, manifest_meta = _load_guardrails()
    maximum_seconds = float(guardrails["maxTrialSeconds"])
    if timeout_seconds is not None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > maximum_seconds
        ):
            raise SamplerBlocked("trial_timeout_exceeds_manifest_bound")
        maximum_seconds = float(timeout_seconds)
    if active_limit_seconds is not None:
        declared_bound = guardrails.get("maxResourceReadOverrunSeconds")
        if (
            readiness_marker is None
            or readiness_release is None
            or isinstance(active_limit_seconds, bool)
            or not isinstance(active_limit_seconds, (int, float))
            or not math.isfinite(active_limit_seconds)
            or active_limit_seconds <= 0
            or not isinstance(declared_bound, int)
            or isinstance(declared_bound, bool)
            or active_limit_seconds != float(declared_bound)
        ):
            raise SamplerBlocked("resource_read_overrun_bound_not_explicitly_pinned")
    elif readiness_marker is not None or readiness_release is not None:
        raise SamplerBlocked("readiness_handshake_requires_active_bound")

    resolved_artifact = _resolve_run_path(str(artifact_path), required=True, label="artifact")
    assert resolved_artifact is not None
    if resolved_artifact.exists():
        if not resolved_artifact.is_dir() or any(resolved_artifact.iterdir()):
            raise SamplerBlocked("trial_artifact_directory_must_be_empty")
    else:
        resolved_artifact.mkdir(parents=True, exist_ok=False)
    resolved_readiness = _resolve_run_path(str(readiness_marker), required=True, label="readiness") if readiness_marker is not None else None
    resolved_release = _resolve_run_path(str(readiness_release), required=True, label="release") if readiness_release is not None else None
    if resolved_readiness is not None:
        if resolved_readiness.is_symlink() or resolved_readiness.exists():
            raise SamplerBlocked("trial_readiness_marker_path_not_new")
        try:
            resolved_readiness.relative_to(ARTIFACTS_ROOT)
        except ValueError as error:
            raise SamplerBlocked("trial_readiness_marker_outside_run_root") from error
    if resolved_release is not None:
        if resolved_release.is_symlink() or resolved_release.exists():
            raise SamplerBlocked("trial_readiness_release_path_not_new")
        try:
            resolved_release.relative_to(ARTIFACTS_ROOT)
        except ValueError as error:
            raise SamplerBlocked("trial_readiness_release_outside_run_root") from error
    resolved_cache = _resolve_run_path(str(cache_path), required=False, label="cache") if cache_path is not None else None
    resolved_caches: dict[str, Path] = {}
    if cache_paths is not None:
        allowed_cache_names = {"anvil-a-state", "anvil-a-rpc", "anvil-b-state", "anvil-b-rpc"}
        if not isinstance(cache_paths, dict) or not cache_paths or set(cache_paths) - allowed_cache_names:
            raise SamplerBlocked("trial_cache_paths_invalid")
        if "maxAnvilCacheBytesEach" not in guardrails:
            raise SamplerBlocked("runtime_cache_guardrail_missing")
        for cache_name, raw_cache_path in cache_paths.items():
            if not isinstance(raw_cache_path, Path):
                raise SamplerBlocked("trial_cache_paths_invalid")
            resolved = _resolve_run_path(str(raw_cache_path), required=True, label=f"{cache_name}-cache")
            assert resolved is not None
            resolved_caches[cache_name] = resolved
    if isinstance(source_proxy_port, bool) or not isinstance(source_proxy_port, int) or not 0 < source_proxy_port <= 65_535:
        raise SamplerBlocked("source_proxy_port_invalid")

    host_info = _docker_host_info()
    containers, inventory_issues = _container_inventory()
    if inventory_issues or len(containers) != len(SERVICES):
        raise SamplerBlocked("trial_compose_project_incomplete")
    service_key = _read_service_key()
    if service_key is None:
        raise SamplerBlocked("source_proxy_service_key_unavailable")
    try:
        compose_cache_sources, compose_config_sha256 = _compose_anvil_cache_sources()
    except SamplerBlocked as error:
        raise SamplerBlocked(error.code) from error
    cache_bindings = [
        _inspect_anvil_cache_binding(
            info,
            expected_sources=compose_cache_sources.get(info.service),
            compose_config_sha256=compose_config_sha256,
        )
        for info in containers
        if info.service in {"anvil-a", "anvil-b"}
    ]

    def take_snapshot() -> dict[str, Any]:
        return _trial_resource_snapshot(
            containers,
            source_proxy_port=source_proxy_port,
            service_key=service_key,
            artifact_path=resolved_artifact,
            cache_path=resolved_cache,
        ) | {"cacheDirectories": {name: _measure_tree(path) for name, path in resolved_caches.items()}}

    start_snapshot = take_snapshot()
    start_utc = _utc_now()
    command_bytes = "\0".join(command).encode("utf-8")
    command_hash = _sha256(command_bytes)
    popen_options: dict[str, Any] = {
        "cwd": REPOSITORY_ROOT,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    # AICODE-NOTE: On POSIX this child must inherit the adapter-created
    # orchestrator group; its inner stop is PID-scoped and the outer timeout
    # can then terminate the entire owned group, including this workload.

    try:
        process = subprocess.Popen(list(command), **popen_options)
    except (OSError, ValueError) as error:
        del error
        raise SamplerBlocked("trial_command_start_failed") from None

    trial_start_ns = time.monotonic_ns()
    deadline_ns = trial_start_ns + int(maximum_seconds * 1_000_000_000)
    samples: list[dict[str, Any]] = [{"phase": "before_process_start", "offsetNanoseconds": None, **start_snapshot}]
    stop_reason: str | None = None
    violation: GuardrailViolation | None = None
    stop_trigger: GuardrailViolation | None = None
    cleanup: dict[str, Any] = {"status": "not_needed", "directChildExited": None, "descendants": "not_applicable"}
    fence_status: dict[str, Any] = {"status": "unknown", "reason": "no_independent_generation_fence_observer"}
    source_start = start_snapshot.get("sourceProxy", {})
    callback_called = False
    readiness_proof: dict[str, Any] = {"status": "not_requested"}
    active_start_ns: int | None = None
    active_elapsed_ns: int | None = None
    fence_result: dict[str, Any] | None = None

    try:
        while process.poll() is None:
            now_ns = time.monotonic_ns()
            remaining_ns = deadline_ns - now_ns
            if remaining_ns <= 0:
                violation = GuardrailViolation(
                    SCENARIO_ID, PROJECT_NAME, tuple(item.container_id for item in containers),
                    "max_trial_seconds", int((time.monotonic_ns() - trial_start_ns) / 1_000_000),
                    int(maximum_seconds * 1_000), "milliseconds"
                )
                stop_trigger = violation
                stop_reason = "time_guardrail_exceeded"
                break
            if resolved_readiness is not None and active_start_ns is None and resolved_readiness.exists():
                readiness_proof, readiness_error = _load_readiness_marker(
                    resolved_readiness,
                    artifact_root=ARTIFACTS_ROOT,
                    evidence_root=resolved_artifact,
                )
                if readiness_error is not None or readiness_proof is None:
                    stop_reason = readiness_error or "readiness_marker_invalid"
                    break
                assert resolved_release is not None
                _write_release_signal(resolved_release, marker_sha256=str(readiness_proof["sha256"]))
                active_start_ns = time.monotonic_ns()
                readiness_proof["status"] = "observed_first_successful_get"
                readiness_proof["releasePath"] = resolved_release.relative_to(REPOSITORY_ROOT).as_posix()
                readiness_proof["activeTimerStartedMonotonicNanoseconds"] = active_start_ns
            if active_start_ns is not None and active_limit_seconds is not None:
                active_elapsed_ns = now_ns - active_start_ns
                active_limit_ns = int(float(active_limit_seconds) * 1_000_000_000)
                if active_elapsed_ns > active_limit_ns:
                    violation = GuardrailViolation(
                        SCENARIO_ID, PROJECT_NAME, tuple(item.container_id for item in containers),
                        "max_resource_read_overrun_seconds", int(active_elapsed_ns / 1_000_000),
                        int(active_limit_ns / 1_000_000), "milliseconds",
                    )
                    stop_trigger = violation
                    stop_reason = "resource_read_overrun"
                    break
            sleep_seconds = min(float(interval_seconds), remaining_ns / 1_000_000_000)
            if resolved_readiness is not None and active_start_ns is None:
                sleep_seconds = min(sleep_seconds, 0.05)
            if active_start_ns is not None and active_limit_seconds is not None:
                active_remaining_ns = max(
                    0,
                    int(active_limit_seconds * 1_000_000_000) - (now_ns - active_start_ns),
                )
                sleep_seconds = min(sleep_seconds, active_remaining_ns / 1_000_000_000)
            time.sleep(max(0.005, sleep_seconds))
            snapshot = take_snapshot()
            samples.append({"phase": "during_process", "offsetNanoseconds": time.monotonic_ns() - trial_start_ns, **snapshot})
            candidates = _trial_memory_violations(snapshot, guardrails)
            cache_limit = guardrails.get("maxAnvilCacheBytesEach")
            cache_rows = snapshot.get("cacheDirectories")
            if isinstance(cache_limit, int) and not isinstance(cache_limit, bool) and isinstance(cache_rows, dict):
                for cache_name, cache_row in cache_rows.items():
                    if not isinstance(cache_row, dict) or cache_row.get("status") != "observed":
                        continue
                    cache_bytes = cache_row.get("bytes")
                    if isinstance(cache_bytes, int) and cache_bytes > cache_limit:
                        candidates.append(GuardrailViolation(
                            SCENARIO_ID, PROJECT_NAME, tuple(item.container_id for item in containers),
                            f"{cache_name}_cache_bytes", cache_bytes, cache_limit, "bytes",
                        ))
            if candidates:
                violation = candidates[0]
                stop_trigger = violation
                stop_reason = "numeric_guardrail_exceeded"
                break
            source_end = snapshot.get("sourceProxy", {})
            source_delta = _counter_delta(source_start, source_end, ("sourceCallsReserved",))
            source_calls = source_delta.get("sourceCallsReserved") if source_delta.get("status") == "observed" else None
            if isinstance(source_calls, int) and source_calls > guardrails["maxSourceCallsPerTrial"]:
                stop_trigger = GuardrailViolation(
                    SCENARIO_ID, PROJECT_NAME, tuple(item.container_id for item in containers),
                    "aggregate_source_call_window_over_limit", source_calls, guardrails["maxSourceCallsPerTrial"], "calls"
                )
                stop_reason = "aggregate_source_counter_window_exceeded_unattributed"
                break
    except Exception:
        stop_reason = "resource_observer_failed"

    if stop_reason is not None and process.poll() is None:
        cleanup = _terminate_owned_process_tree(process)
    if stop_reason is not None and stop_trigger is not None:
        if fence_generation is not None and stop_trigger is not None:
            callback_called = True
            try:
                candidate = fence_generation(stop_trigger)
                if isinstance(candidate, dict):
                    allowed = {"status", "exitCode", "reportPath", "reportSha256", "generationId", "envId"}
                    fence_result = {key: candidate[key] for key in allowed if key in candidate}
                    if "reportPath" in fence_result:
                        report_path = _resolve_run_path(str(fence_result["reportPath"]), required=True, label="fence-report")
                        fence_result["reportPath"] = report_path.relative_to(REPOSITORY_ROOT).as_posix() if report_path else None
                    if not isinstance(fence_result.get("reportSha256"), str) or not re.fullmatch(
                        r"[0-9a-f]{64}", str(fence_result.get("reportSha256", ""))
                    ):
                        fence_result.pop("reportSha256", None)
                    fence_status = {"status": "fence_process_result_recorded", "result": fence_result}
                else:
                    fence_status = {"status": "fence_process_returned_unstructured"}
            except Exception:
                fence_status = {"status": "fence_process_failed"}
        elif on_fence is not None:
            callback_called = True
            try:
                # The callback result is deliberately not treated as proof.
                on_fence(stop_trigger)
                fence_status = {"status": "callback_invoked_unverified", "reason": "independent_post_stop_database_and_chain_reads_required"}
            except Exception:
                fence_status = {"status": "callback_failed", "reason": "independent_post_stop_database_and_chain_reads_required"}
        elif on_fence is not None:
            callback_called = True
            try:
                on_fence(GuardrailViolation(
                    SCENARIO_ID, PROJECT_NAME, tuple(item.container_id for item in containers),
                    "resource_observer_failed", 0, 0, "unknown"
                ))
                fence_status = {"status": "callback_invoked_unverified", "reason": "independent_post_stop_database_and_chain_reads_required"}
            except Exception:
                fence_status = {"status": "callback_failed", "reason": "independent_post_stop_database_and_chain_reads_required"}

    try:
        return_code = process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        cleanup = _terminate_owned_process_tree(process)
        return_code = process.poll()
    process_finished_ns = time.monotonic_ns()
    try:
        final_snapshot = take_snapshot()
        samples.append({"phase": "after_process_exit", "offsetNanoseconds": time.monotonic_ns() - trial_start_ns, **final_snapshot})
    except Exception:
        final_snapshot = {"sourceProxy": {"status": "unknown"}, "containers": [],
                          "artifactDirectory": {"status": "unknown", "bytes": None},
                          "cacheDirectory": {"status": "unknown", "bytes": None}}

    elapsed_ns = process_finished_ns - trial_start_ns
    source_end = final_snapshot.get("sourceProxy", {})
    source_delta = _counter_delta(source_start, source_end, ("forwardedItems", "deniedItems", "upstreamErrors", "sourceCallsReserved"))
    source_delta["trialAttribution"] = "unknown_aggregate_proxy_process_counter"
    container_samples: dict[str, list[dict[str, Any]]] = {info.service: [] for info in containers}
    for sample in samples:
        offset = sample.get("offsetNanoseconds")
        for service_row in sample.get("containers", []):
            if not isinstance(service_row, dict) or service_row.get("service") not in container_samples:
                continue
            container_samples[service_row["service"]].append({
                "offsetNanoseconds": offset,
                "cgroup": service_row.get("cgroup", {"status": "unknown", "reason": "sample_invalid"}),
            })
    container_reports = []
    for info in containers:
        container_report = _container_report(info, container_samples[info.service], guardrails)
        container_report["trialAttribution"] = "unknown_container_activity_during_sample_window"
        container_reports.append(container_report)

    artifact_rows = [sample.get("artifactDirectory", {}) for sample in samples]
    artifact_values = [row.get("bytes") for row in artifact_rows if isinstance(row, dict) and row.get("status") == "observed" and isinstance(row.get("bytes"), int)]
    artifact_guardrail = {
        "status": "unknown",
        "reason": "trial_artifact_byte_samples_unavailable_or_directory_not_empty_at_start",
    }
    if len(artifact_values) >= 2 and artifact_values[0] == 0:
        max_artifact_bytes = max(artifact_values)
        artifact_guardrail = {
            "status": "exceeded" if max_artifact_bytes > guardrails["maxEvidenceBytesPerTrial"] else "within_limit",
            "observedMaximumBytes": max_artifact_bytes,
            "finalBytes": artifact_values[-1],
            "limitBytes": guardrails["maxEvidenceBytesPerTrial"],
            "scope": "task_owned_empty_artifact_directory_sampled_during_command",
        }

    cache_directory_reports: dict[str, dict[str, Any]] = {}
    cache_limit = guardrails.get("maxAnvilCacheBytesEach")
    for cache_name, path in resolved_caches.items():
        rows = [
            sample.get("cacheDirectories", {}).get(cache_name)
            for sample in samples
            if isinstance(sample.get("cacheDirectories"), dict)
        ]
        observed = [
            row.get("bytes") for row in rows
            if isinstance(row, dict) and row.get("status") == "observed" and isinstance(row.get("bytes"), int)
        ]
        if len(observed) != len(rows) or not observed or not isinstance(cache_limit, int):
            check_status = "unknown"
        elif max(observed) > cache_limit:
            check_status = "exceeded"
        else:
            check_status = "within_limit"
        cache_directory_reports[cache_name] = {
            "path": path.relative_to(REPOSITORY_ROOT).as_posix(),
            "samples": rows,
            "byteLimit": cache_limit,
            "maximumObservedBytes": max(observed) if observed else None,
            "guardrailCheck": {"status": check_status, "scope": "individual_bind_mount_directory"},
        }

    probe_path = resolved_artifact / "probe.json"
    workload_path = resolved_artifact / "workload.json"
    probe_summary: dict[str, Any] = {"status": "unknown", "reason": "probe_index_missing_or_invalid"}
    try:
        summary_path = probe_path if probe_path.is_file() else workload_path
        probe_bytes = summary_path.read_bytes()
        probe_payload = json.loads(probe_bytes)
        if (
            isinstance(probe_payload, dict)
            and probe_payload.get("schemaVersion") in {"bef-runtime-probe/v1", "bef-resource-purchase-workload/v1"}
            and probe_payload.get("scenarioId") == SCENARIO_ID
            and probe_payload.get("status") in {"captured", "blocked", "error", "running"}
        ):
            environment = probe_payload.get("environment")
            generation = environment.get("generation") if isinstance(environment, dict) else None
            if not isinstance(generation, dict) and isinstance(environment, dict):
                generation = environment
            operations = probe_payload.get("operations")
            operation_ids = [
                item.get("operationId") for item in operations
                if isinstance(item, dict) and isinstance(item.get("operationId"), str)
            ] if isinstance(operations, list) else []
            probe_summary = {
                "status": probe_payload["status"],
                "schemaVersion": probe_payload["schemaVersion"],
                "scenarioId": SCENARIO_ID,
                "probeIndexPath": summary_path.relative_to(REPOSITORY_ROOT).as_posix(),
                "probeIndexSha256": _sha256(probe_bytes),
                "environmentId": environment.get("envId", probe_payload.get("environmentId")) if isinstance(environment, dict) else probe_payload.get("environmentId"),
                "generationId": generation.get("generationId") if isinstance(generation, dict) else (
                    readiness_proof.get("generationId") if readiness_proof.get("status") == "observed_first_successful_get" else None
                ),
                "operationIds": operation_ids,
            }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass

    issues = [
        {"code": "cold_warm_cache_provenance_unavailable"},
        {"code": "source_call_trial_attribution_unavailable"},
        {"code": "independent_generation_fence_not_verified"},
        {"code": "provider_compute_units_unobservable"},
    ]
    if artifact_guardrail.get("status") == "unknown":
        issues.append({"code": "trial_artifact_byte_measurement_unavailable"})
    if stop_reason == "resource_observer_failed":
        issues.append({"code": "resource_observer_failed_during_trial"})
    if stop_reason == "aggregate_source_counter_window_exceeded_unattributed":
        issues.append({"code": "aggregate_source_counter_exceeded_without_trial_attribution"})
    if violation is not None and cleanup.get("descendants") == "unknown":
        issues.append({"code": "task_owned_process_tree_cleanup_unverified"})
    if return_code is None:
        issues.append({"code": "task_owned_process_exit_unconfirmed"})
    if return_code != 0:
        issues.append({"code": "probe_command_nonzero_exit"})

    actual_overrun = violation is not None
    status = "guardrail_exceeded" if actual_overrun else (
        "failed"
        if (
            probe_summary.get("status") == "error"
            or return_code not in (0, None)
            and probe_summary.get("status") not in {"blocked"}
            and stop_reason not in {"resource_observer_failed", "aggregate_source_counter_window_exceeded_unattributed"}
        )
        else "blocked"
    )
    return {
        "schemaVersion": "bef-resource-trial/v1",
        "scenarioId": SCENARIO_ID,
        "status": status,
        "gateStatus": "not_established_by_resource_trial_collector",
        "startedAtUtc": start_utc,
        "finishedAtUtc": _utc_now(),
        "elapsedMonotonicNanoseconds": elapsed_ns,
        "manifest": manifest_meta,
        "host": host_info,
        "trialProcess": {
            "commandSha256": command_hash,
            "exitCode": return_code,
            "stopReason": stop_reason,
            "timedOut": stop_reason == "time_guardrail_exceeded",
            "processTreeCleanup": cleanup,
            "probeEvidence": probe_summary,
            "readiness": readiness_proof,
            "activeLimitElapsedNanoseconds": active_elapsed_ns,
        },
        "trialCorrelation": {
            "status": "observed" if probe_summary.get("status") == "captured" and probe_summary.get("generationId") else "unknown",
            "generationId": probe_summary.get("generationId"),
            "operationIds": probe_summary.get("operationIds", []),
        },
        "anvilCacheBindings": cache_bindings,
        "cacheCondition": {"status": "unknown", "reason": "existing_anvil_instances_are_not_created_and_bound_by_this_trial"},
        "sourceProxy": {
            "counterScope": "aggregate_proxy_process",
            "start": source_start,
            "end": source_end,
            "windowDelta": source_delta,
            "perTrialCalls": None,
            "providerComputeUnits": "unknown",
        },
        "containers": container_reports,
        "resourceSamples": samples,
        "artifactDirectory": {
            "path": resolved_artifact.relative_to(REPOSITORY_ROOT).as_posix(),
            "samples": [sample.get("artifactDirectory") for sample in samples],
            "guardrailCheck": artifact_guardrail,
        },
        "cacheDirectory": {
            "path": resolved_cache.relative_to(REPOSITORY_ROOT).as_posix() if resolved_cache else None,
            "samples": [sample.get("cacheDirectory") for sample in samples],
            "condition": "unknown",
        },
        "cacheDirectories": cache_directory_reports,
        "guardrails": {
            "manifestValues": guardrails,
            "time": {
                "status": "exceeded" if stop_reason == "time_guardrail_exceeded" else "within_limit" if elapsed_ns <= int(maximum_seconds * 1_000_000_000) else "exceeded",
                "observedNanoseconds": elapsed_ns,
                "limitSeconds": maximum_seconds,
            },
            "artifactBytes": artifact_guardrail,
            "trigger": {
                "code": violation.code,
                "observed": violation.observed,
                "limit": violation.limit,
                "unit": violation.unit,
            } if violation else None,
            "stopTrigger": {
                "code": stop_trigger.code,
                "observed": stop_trigger.observed,
                "limit": stop_trigger.limit,
                "unit": stop_trigger.unit,
            } if stop_trigger else None,
            "generationFence": fence_status,
            "generationFenceCallbackInvoked": callback_called,
            "generationFenceProcessResult": fence_result,
            "activeBound": {
                "status": "exceeded" if violation is not None and violation.code == "max_resource_read_overrun_seconds" else "within_limit" if active_start_ns is not None else "unknown",
                "limitSeconds": active_limit_seconds,
                "observedNanoseconds": active_elapsed_ns,
                "readiness": readiness_proof,
            },
        },
        "issues": issues,
    }


def _output_path(raw_path: str | None) -> Path:
    if raw_path is None:
        return ARTIFACTS_ROOT / "acceptance" / SCENARIO_ID / f"resource-sample-{uuid.uuid4().hex}.json"
    output = _resolve_run_path(raw_path, required=True, label="output")
    assert output is not None
    if output.exists():
        raise SamplerBlocked("output_file_already_exists")
    return output


def _write_report(path: Path, report: dict[str, Any], service_key: str | None) -> str:
    serialized = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if service_key and service_key in serialized:
        raise SamplerBlocked("secret_redaction_invariant_failed")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise SamplerBlocked("output_file_already_exists")
    content = serialized.encode("utf-8")
    with path.open("xb") as stream:
        stream.write(content)
    return _sha256(content)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=float, default=5.0)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--artifact-path", help="task-owned evidence directory under artifacts/runs to measure")
    parser.add_argument("--cache-path", help="dedicated cache directory under artifacts/runs; only byte counts are measured")
    parser.add_argument("--source-proxy-port", type=int, default=os.environ.get("BEF_SOURCE_PROXY_HOST_PORT", "18544"))
    parser.add_argument("--output", help="new JSON evidence path under ignored artifacts/runs; default is generated")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        output_path = _output_path(args.output)
        artifact_path = _resolve_run_path(args.artifact_path, required=False, label="artifact")
        cache_path = _resolve_run_path(args.cache_path, required=False, label="cache")
        if args.source_proxy_port <= 0 or args.source_proxy_port > 65_535:
            raise SamplerBlocked("source_proxy_port_invalid")
        service_key = _read_service_key()
        report = collect_resource_window(
            duration_seconds=args.duration_seconds,
            interval_seconds=args.interval_seconds,
            artifact_path=artifact_path,
            cache_path=cache_path,
            source_proxy_port=args.source_proxy_port,
        )
        digest = _write_report(output_path, report, service_key)
        print(json.dumps({
            "status": report["status"],
            "gateStatus": report["gateStatus"],
            "evidencePath": output_path.relative_to(REPOSITORY_ROOT).as_posix(),
            "evidenceSha256": digest,
        }, sort_keys=True))
        return 0 if report["status"] == "captured" else 2
    except SamplerBlocked as error:
        print(json.dumps({"status": "blocked", "reason": error.code}, sort_keys=True), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError) as error:
        # Do not print operating-system details or input paths that might include
        # local account names. They are not useful evidence and can reveal data.
        del error
        print(json.dumps({"status": "blocked", "reason": "collector_input_or_io_error"}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
