"""Run the task-owned BEF-SC-011 cache and resource trials.

Without ``--execute`` this command only prints a plan. Execution is fixed to
the local BEF Compose project, a fresh cache directory beneath ignored
``artifacts/runs``, and the Anvil-A container; it never runs ``compose down``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote

if __package__:
    from tools import bef_resource_sampler as sampler
else:
    import bef_resource_sampler as sampler


REPO = sampler.REPOSITORY_ROOT
RUNS = sampler.ARTIFACTS_ROOT
WORKLOAD_ENTRY = REPO / "packages" / "benchmark-environment" / "src" / "probe" / "resource-workload.ts"
TSX_LOADER_ENTRY = REPO / "packages" / "benchmark-environment" / "node_modules" / "tsx" / "dist" / "loader.mjs"
LOCK_PATH = RUNS / ".bef-sc011-trials.lock"
DEFAULT_HOST_PORTS = {
    "BEF_API_HOST_PORT": "8783",
    "BEF_DATABASE_HOST_PORT": "55432",
    "BEF_SOURCE_PROXY_HOST_PORT": "18544",
    "BEF_LOCAL_RPC_A_HOST_PORT": "18545",
    "BEF_LOCAL_RPC_B_HOST_PORT": "28545",
    "BEF_FACILITATOR_A_HOST_PORT": "14021",
    "BEF_FACILITATOR_B_HOST_PORT": "24021",
}
ENVIRONMENT_IDS = ("bef-env-a", "bef-env-b")


class TrialBlocked(RuntimeError):
    def __init__(
        self,
        code: str,
        evidence_path: Path | None = None,
        diagnostics: dict[str, str | int | bool | None] | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.evidence_path = evidence_path
        self.diagnostics = diagnostics or {}


class ScenarioDeadline:
    def __init__(self, maximum_seconds: int):
        self.maximum_seconds = maximum_seconds
        self.started_ns = time.monotonic_ns()
        self.deadline_ns = self.started_ns + maximum_seconds * 1_000_000_000

    def remaining_seconds(self, *, reserve_seconds: float = 0.0) -> float:
        remaining = (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000 - reserve_seconds
        if remaining <= 0:
            raise TrialBlocked("max_resource_scenario_deadline_exhausted")
        return remaining

    def bounded_timeout(self, requested_seconds: float, *, reserve_seconds: float = 0.0) -> float:
        remaining = self.remaining_seconds(reserve_seconds=reserve_seconds)
        return min(requested_seconds, remaining)

    def elapsed_nanoseconds(self) -> int:
        return time.monotonic_ns() - self.started_ns


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrialBlocked("trial_evidence_json_unavailable") from error
    if not isinstance(value, dict):
        raise TrialBlocked("trial_evidence_json_invalid")
    return value


def _write_json_new(path: Path, value: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError as error:
        raise TrialBlocked("trial_evidence_path_already_exists") from error
    return _sha256(raw)


def _replace_json(path: Path, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextlib.contextmanager
def _temporary_environment(values: dict[str, str]) -> Iterator[None]:
    prior = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, old_value in prior.items():
            if old_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old_value


def _read_secret(name: str) -> str:
    path = REPO / "infrastructure" / "benchmark-environment" / ".local" / "secrets" / name
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise TrialBlocked("local_runtime_secret_unavailable") from error
    if not value or len(value) > 4096:
        raise TrialBlocked("local_runtime_secret_invalid")
    return value


def _host_ports() -> dict[str, str]:
    ports: dict[str, str] = {}
    for name, default in DEFAULT_HOST_PORTS.items():
        value = os.environ.get(name, default)
        if not value.isdecimal() or not 1 <= int(value) <= 65_535:
            raise TrialBlocked("local_host_port_invalid")
        ports[name] = str(int(value))
    return ports


def _runtime_environment() -> dict[str, str]:
    ports = _host_ports()
    observer_password = quote(_read_secret("database-observer-password"), safe="")
    values = {
        **ports,
        "BEF_API_BASE_URL": f"http://127.0.0.1:{ports['BEF_API_HOST_PORT']}",
        "BEF_DATABASE_OBSERVER_URL": f"postgres://bef_observer:{observer_password}@127.0.0.1:{ports['BEF_DATABASE_HOST_PORT']}/bef",
        "BEF_ADMIN_KEY": _read_secret("admin-key"),
        "BEF_SERVICE_KEY": _read_secret("service-key"),
        "BEF_SOURCE_PROXY_URL": f"http://127.0.0.1:{ports['BEF_SOURCE_PROXY_HOST_PORT']}",
        "BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_A": f"http://127.0.0.1:{ports['BEF_LOCAL_RPC_A_HOST_PORT']}",
        "BEF_LOCAL_RPC_PROXY_URL_BEF_ENV_B": f"http://127.0.0.1:{ports['BEF_LOCAL_RPC_B_HOST_PORT']}",
        "BEF_FACILITATOR_URL_BEF_ENV_A": f"http://127.0.0.1:{ports['BEF_FACILITATOR_A_HOST_PORT']}",
        "BEF_FACILITATOR_URL_BEF_ENV_B": f"http://127.0.0.1:{ports['BEF_FACILITATOR_B_HOST_PORT']}",
    }
    if len(values["BEF_ADMIN_KEY"]) < 32 or len(values["BEF_SERVICE_KEY"]) < 32:
        raise TrialBlocked("local_runtime_secret_invalid")
    return values


def _load_manifest_guardrails() -> tuple[dict[str, int], str]:
    try:
        raw = sampler.MANIFEST_FILE.read_bytes()
        manifest = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise TrialBlocked("runtime_manifest_unavailable") from error
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != "bef-runtime-manifest/v1":
        raise TrialBlocked("runtime_manifest_schema_invalid")
    guardrails = manifest.get("guardrails")
    if not isinstance(guardrails, dict):
        raise TrialBlocked("runtime_guardrails_unavailable")
    names = (
        "maxTrialSeconds", "maxEvidenceBytesPerTrial", "maxAnvilCacheBytesEach",
        "maxResourceReadOverrunSeconds", "maxResourceScenarioSeconds",
    )
    parsed: dict[str, int] = {}
    for name in names:
        value = guardrails.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise TrialBlocked("required_sc011_guardrail_not_pinned")
        parsed[name] = value
    return parsed, _sha256(raw)


def _compose_prefix() -> list[str]:
    return [
        "docker", "compose", "--project-name", sampler.PROJECT_NAME,
        "-f", str(sampler.COMPOSE_FILE),
    ]


def _run_checked(
    command: list[str], *, timeout: float = 30.0, deadline: ScenarioDeadline | None = None,
    reserve_seconds: float = 0.0,
) -> str:
    if deadline is not None:
        timeout = deadline.bounded_timeout(timeout, reserve_seconds=reserve_seconds)
    try:
        result = subprocess.run(
            command,
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrialBlocked("task_owned_command_unavailable_or_timed_out") from error
    if result.returncode != 0:
        # stderr/stdout can contain local paths or unexpected service details;
        # the stable code is sufficient for a blocked precondition.
        raise TrialBlocked("task_owned_command_failed")
    return result.stdout


def _acquire_lock() -> str:
    RUNS.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    try:
        with LOCK_PATH.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(token + "\n")
    except FileExistsError as error:
        raise TrialBlocked("another_sc011_orchestrator_holds_lock") from error
    return token


def _release_lock(token: str) -> None:
    try:
        current = LOCK_PATH.read_text(encoding="ascii").strip()
        if current == token:
            LOCK_PATH.unlink()
    except OSError:
        pass


def _new_run_root(evidence_dir: Path | None = None) -> Path:
    if evidence_dir is None:
        run_root = RUNS / "bef-sc011-trials" / uuid.uuid4().hex
        try:
            run_root.mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise TrialBlocked("trial_evidence_root_create_failed") from error
        return run_root

    candidate = evidence_dir if evidence_dir.is_absolute() else REPO / evidence_dir
    if any(part in {".", ".."} for part in candidate.parts):
        raise TrialBlocked("trial_evidence_root_invalid")
    candidate = Path(os.path.abspath(candidate))
    run_root = candidate.resolve(strict=False)
    try:
        relative = run_root.relative_to(RUNS.resolve(strict=False))
    except ValueError as error:
        raise TrialBlocked("trial_evidence_root_outside_ignored_runs") from error
    if not relative.parts or any(part.lower() in {"node_modules", "secrets", "secret"} for part in relative.parts):
        raise TrialBlocked("trial_evidence_root_invalid")
    cursor = candidate
    runs_root = RUNS.resolve(strict=False)
    while cursor != runs_root:
        if cursor.is_symlink() or cursor.parent == cursor:
            raise TrialBlocked("trial_evidence_root_symlink_rejected")
        cursor = cursor.parent
    if runs_root.is_symlink():
        raise TrialBlocked("trial_evidence_root_symlink_rejected")
    try:
        run_root.mkdir(parents=True, exist_ok=True)
        if not run_root.is_dir() or run_root.is_symlink():
            raise TrialBlocked("trial_evidence_root_invalid")
        entries = list(run_root.iterdir())
        control = run_root / "missing-sampler-control.json"
        if entries and (len(entries) != 1 or entries[0] != control or not control.is_file() or control.is_symlink()):
            raise TrialBlocked("allocated_trial_evidence_directory_not_empty")
        if control.is_file():
            record = _json_record(control)
            if record.get("schemaVersion") != "bef-resource-missing-sampler-control/v1" or record.get("variantId") != "missing_sampler":
                raise TrialBlocked("missing_sampler_control_invalid")
    except OSError as error:
        raise TrialBlocked("trial_evidence_root_create_failed") from error
    return run_root


def _relative(path: Path) -> str:
    return path.resolve(strict=False).relative_to(REPO.resolve(strict=False)).as_posix()


def _workload_command(mode: str, phase: str, evidence_dir: Path, env_id: str, *, marker: Path | None = None, release: Path | None = None) -> list[str]:
    node = shutil.which("node")
    if not node or not TSX_LOADER_ENTRY.is_file() or not WORKLOAD_ENTRY.is_file():
        raise TrialBlocked("sc011_resource_workload_entry_not_ready")
    command = [
        node, "--import", TSX_LOADER_ENTRY.as_uri(), str(WORKLOAD_ENTRY),
        "--mode", mode, "--phase", phase,
        "--env-id", env_id,
        "--evidence-dir", str(evidence_dir),
    ]
    if marker is not None:
        command.extend(["--marker", str(marker)])
    if release is not None:
        command.extend(["--continue-file", str(release)])
    return command


def _run_unbounded_workload(
    *, mode: str, phase: str, env_id: str, evidence_dir: Path,
    runtime_env: dict[str, str], marker: Path | None = None,
    timeout: float = 45.0, deadline: ScenarioDeadline | None = None,
    reserve_seconds: float = 45.0, expected_status: str = "captured",
) -> dict[str, Any]:
    if expected_status not in {"captured", "protected"} or (
        expected_status == "protected" and not (mode == "fence-active" and phase == "guardrail_exceeded")
    ):
        raise TrialBlocked("probe_workload_expected_status_invalid")
    if deadline is not None:
        timeout = deadline.bounded_timeout(timeout, reserve_seconds=reserve_seconds)
    command = _workload_command(mode, phase, evidence_dir, env_id, marker=marker)
    with _temporary_environment(runtime_env):
        try:
            options: dict[str, Any] = {
                "cwd": REPO,
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "shell": False,
                "close_fds": True,
            }
            if os.name == "nt":
                options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            # AICODE-NOTE: On POSIX the workload inherits the adapter's
            # dedicated orchestrator process group so outer timeout cleanup
            # cannot orphan a separate Node session.
            process = subprocess.Popen(command, **options)
            try:
                stdout, _stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                cleanup = sampler._terminate_owned_process_tree(process)
                try:
                    process.communicate(timeout=6.0)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if (
                    cleanup.get("directChildExited") is not True
                    or cleanup.get("descendants") != "stopped"
                    and cleanup.get("treeExitConfirmed") is not True
                ):
                    raise TrialBlocked("probe_workload_process_tree_cleanup_unknown") from error
                raise TrialBlocked("probe_workload_process_unavailable_or_timed_out") from error
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TrialBlocked("probe_workload_process_unavailable_or_timed_out") from error
    report_path = evidence_dir / "workload.json"
    report = _json_record(report_path)
    if process.returncode != 0 or report.get("status") != expected_status:
        raise TrialBlocked("probe_workload_not_captured")
    return report


def _run_sampled_workload(
    *, mode: str, phase: str, env_id: str, evidence_dir: Path,
    runtime_env: dict[str, str], cache_paths: dict[str, Path],
    marker: Path | None = None, release: Path | None = None,
    active_limit_seconds: int | None = None,
    fence_generation: Any = None,
    timeout: float, deadline: ScenarioDeadline | None = None,
    fence_reserve_seconds: float = 0.0,
) -> dict[str, Any]:
    if deadline is not None:
        timeout = deadline.bounded_timeout(timeout, reserve_seconds=fence_reserve_seconds)
    command = _workload_command(mode, phase, evidence_dir, env_id, marker=marker, release=release)
    with _temporary_environment(runtime_env):
        sample = sampler.run_bounded_trial_command(
            command,
            artifact_path=evidence_dir,
            cache_paths=cache_paths,
            interval_seconds=0.25,
            timeout_seconds=timeout,
            readiness_marker=marker if active_limit_seconds is not None else None,
            readiness_release=release if active_limit_seconds is not None else None,
            active_limit_seconds=active_limit_seconds,
            fence_generation=fence_generation,
        )
    sample_path = evidence_dir / "resource-sampler.json"
    _write_json_new(sample_path, sample)
    guardrails = sample.get("guardrails")
    manifest_values = guardrails.get("manifestValues") if isinstance(guardrails, dict) else None
    evidence_limit = manifest_values.get("maxEvidenceBytesPerTrial") if isinstance(manifest_values, dict) else None
    if isinstance(evidence_limit, bool) or not isinstance(evidence_limit, int) or evidence_limit <= 0:
        raise TrialBlocked("resource_evidence_byte_bound_unavailable")
    complete_inventory = sampler.measure_directory_inventory(evidence_dir, max_bytes=evidence_limit, max_files=50_000)
    if complete_inventory.get("status") != "observed" or complete_inventory.get("bytes", evidence_limit + 1) > evidence_limit:
        raise TrialBlocked("resource_evidence_limit_exceeded_after_sampler_report")
    return sample


def _assert_isolation(
    runtime_env: dict[str, str], evidence_root: Path, *, deadline: ScenarioDeadline | None = None
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for env_id, other_id in (("bef-env-a", "bef-env-b"), ("bef-env-b", "bef-env-a")):
        report = _run_unbounded_workload(
            mode="isolation-snapshot", phase="cold", env_id=env_id,
            evidence_dir=evidence_root / f"preflight-{env_id}", runtime_env=runtime_env,
            deadline=deadline,
        )
        if report.get("observedEnvironmentId") != other_id or report.get("activeGenerationObserved") is not False:
            raise TrialBlocked("active_generation_preflight_not_clear")
        checks.append({
            "queriedFromEnvironment": env_id,
            "observedOtherEnvironment": other_id,
            "activeGenerationObserved": False,
            "workloadPath": _relative(evidence_root / f"preflight-{env_id}" / "workload.json"),
        })
    return checks


def _anvil_a_info(*, deadline: ScenarioDeadline | None = None) -> sampler.ContainerInfo:
    if deadline is not None:
        deadline.remaining_seconds(reserve_seconds=30)
    container_id = sampler._list_container_id("anvil-a")
    info = sampler._inspect_container("anvil-a", container_id)
    if deadline is not None:
        deadline.remaining_seconds()
    return info


def _anvil_a_stop_outcome(container_id: str, *, deadline: ScenarioDeadline | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
        return {"status": "unknown", "reason": "anvil_container_id_invalid"}
    if deadline is not None:
        deadline.remaining_seconds(reserve_seconds=30)
    raw = _run_checked([
        "docker", "inspect", "--format",
        "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.State.Error}}",
        container_id,
    ], timeout=15, deadline=deadline, reserve_seconds=30)
    fields = raw.strip().split("|", 3)
    if len(fields) != 4 or fields[0] != "exited" or fields[1] not in {"0", "143", "137"} or fields[2] not in {"true", "false"}:
        return {"status": "unknown", "reason": "anvil_stop_inspection_invalid"}
    exit_code = int(fields[1])
    oom_killed = fields[2] == "true"
    error_empty = fields[3] == ""
    graceful_stop_verified = exit_code in {0, 143} and not oom_killed and error_empty
    return {
        "status": "observed",
        "containerId": container_id,
        "state": fields[0],
        "exitCode": exit_code,
        "oomKilled": oom_killed,
        "errorEmpty": error_empty,
        "gracefulStopVerified": graceful_stop_verified,
    }


def _bind_observation(
    runtime_env: dict[str, str], expected_paths: dict[str, str], *, deadline: ScenarioDeadline | None = None
) -> tuple[dict[str, Any], str]:
    if deadline is not None:
        deadline.remaining_seconds(reserve_seconds=60)
    with _temporary_environment(runtime_env):
        sources, config_sha = sampler._compose_anvil_cache_sources()
        info = _anvil_a_info(deadline=deadline)
        binding = sampler._inspect_anvil_cache_binding(
            info,
            expected_sources=sources["anvil-a"],
            compose_config_sha256=config_sha,
        )
    if binding.get("status") != "observed":
        container_id = info.container_id[:12] if re.fullmatch(r"[0-9a-f]{12,64}", info.container_id) else None
        reason = binding.get("reason")
        raise TrialBlocked(
            "anvil_a_cache_mount_binding_unverified",
            diagnostics={
                "cacheBindingStatus": binding.get("status") if isinstance(binding.get("status"), str) else None,
                "cacheBindingReason": reason if isinstance(reason, str) and re.fullmatch(r"[a-z0-9_]+", reason) else None,
                "anvilContainerIdPrefix": container_id,
                "composeConfigSha256": config_sha if re.fullmatch(r"[0-9a-f]{64}", config_sha) else None,
            },
        )
    resolved_actual = {
        key: sampler._resolve_compose_host_source(value)
        for key, value in sources["anvil-a"].items()
    }
    resolved_expected = {key: Path(value).resolve(strict=False) for key, value in expected_paths.items()}
    if resolved_actual != resolved_expected:
        raise TrialBlocked("anvil_a_cache_mount_does_not_match_trial_paths")
    if deadline is not None:
        deadline.remaining_seconds()
    return {
        "containerId": info.container_id,
        "image": info.image,
        "state": info.state,
        "binding": binding,
        "composeConfigSha256": config_sha,
        "sources": {key: _relative(value) for key, value in resolved_actual.items()},
    }, config_sha


def _cache_inventory(
    paths: dict[str, Path], limit: int, *, deadline: ScenarioDeadline | None = None
) -> dict[str, dict[str, Any]]:
    if deadline is not None:
        deadline.remaining_seconds(reserve_seconds=5)
    inventory: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        measured = sampler.measure_directory_inventory(path, max_bytes=limit, max_files=50_000)
        inventory[name] = {**measured, "pathRef": _relative(path)}
    if deadline is not None:
        deadline.remaining_seconds()
    return inventory


def _is_empty_cache(inventory: dict[str, Any]) -> bool:
    return inventory.get("status") == "observed" and inventory.get("bytes") == 0 and inventory.get("fileCount") == 0


def _cache_inventory_index(
    inventories: dict[str, Any], *, expected_cache_names: set[str] | None = None
) -> tuple[dict[tuple[str, str], dict[str, Any]] | None, str | None]:
    if not isinstance(inventories, dict) or not inventories:
        return None, "cache_inventory_roots_missing"
    if expected_cache_names is not None and set(inventories) != expected_cache_names:
        return None, "cache_inventory_roots_mismatch"

    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for cache_name, inventory in inventories.items():
        if not isinstance(cache_name, str) or not isinstance(inventory, dict):
            return None, "cache_inventory_shape_invalid"
        if inventory.get("status") != "observed":
            return None, "cache_inventory_not_observed"
        files = inventory.get("files")
        byte_count = inventory.get("bytes")
        file_count = inventory.get("fileCount")
        if (
            not isinstance(files, list)
            or isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0
            or isinstance(file_count, bool) or not isinstance(file_count, int) or file_count != len(files)
        ):
            return None, "cache_inventory_shape_invalid"
        observed_bytes = 0
        for row in files:
            if not isinstance(row, dict):
                return None, "cache_inventory_file_invalid"
            file_key = row.get("fileKey")
            digest = row.get("sha256")
            size = row.get("sizeBytes")
            if (
                not isinstance(file_key, str) or not re.fullmatch(r"[0-9a-f]{64}", file_key)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or isinstance(size, bool) or not isinstance(size, int) or size < 0
            ):
                return None, "cache_inventory_file_invalid"
            key = (cache_name, file_key)
            if key in entries:
                return None, "cache_inventory_duplicate_file_key"
            entries[key] = {"sha256": digest, "sizeBytes": size}
            observed_bytes += size
        if observed_bytes != byte_count:
            return None, "cache_inventory_byte_count_mismatch"
    return entries, None


def _cache_inventory_summary(
    inventories: dict[str, Any], *, expected_cache_names: set[str] | None = None
) -> dict[str, Any]:
    entries, reason = _cache_inventory_index(inventories, expected_cache_names=expected_cache_names)
    if reason is not None or entries is None:
        return {"status": "unknown", "reason": reason or "cache_inventory_unavailable"}
    total_bytes = sum(row["sizeBytes"] for row in entries.values())
    return {
        "status": "observed",
        "cacheDirectoryCount": len(inventories),
        "fileCount": len(entries),
        "bytes": total_bytes,
        "hasEntries": bool(entries) and total_bytes > 0,
    }


def _cache_inventory_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    expected_cache_names: set[str] | None = None,
) -> dict[str, Any]:
    before_entries, before_reason = _cache_inventory_index(before, expected_cache_names=expected_cache_names)
    after_entries, after_reason = _cache_inventory_index(after, expected_cache_names=expected_cache_names)
    if before_reason is not None or after_reason is not None or before_entries is None or after_entries is None:
        return {
            "status": "unknown",
            "reason": before_reason or after_reason or "cache_inventory_unavailable",
            "beforeFileCount": len(before_entries) if before_entries is not None else None,
            "afterFileCount": len(after_entries) if after_entries is not None else None,
        }

    retained = {
        key for key, row in before_entries.items()
        if key in after_entries and after_entries[key] == row
    }
    removed = set(before_entries) - set(after_entries)
    changed = {
        key for key in set(before_entries) & set(after_entries)
        if before_entries[key] != after_entries[key]
    }
    added = set(after_entries) - set(before_entries)
    return {
        "status": "observed",
        "beforeFileCount": len(before_entries),
        "afterFileCount": len(after_entries),
        "beforeHadEntries": bool(before_entries),
        "retainedFileCount": len(retained),
        "removedFileCount": len(removed),
        "changedFileCount": len(changed),
        "addedFileCount": len(added),
        "allBeforeEntriesRetained": bool(before_entries) and not removed and not changed,
        "removedFileKeysSample": [
            {"cache": cache_name, "fileKey": file_key}
            for cache_name, file_key in sorted(removed)[:10]
        ],
        "changedFileKeysSample": [
            {
                "cache": cache_name,
                "fileKey": file_key,
                "beforeSha256": before_entries[(cache_name, file_key)]["sha256"],
                "afterSha256": after_entries[(cache_name, file_key)]["sha256"],
            }
            for cache_name, file_key in sorted(changed)[:10]
        ],
        "addedFileKeysSample": [
            {"cache": cache_name, "fileKey": file_key}
            for cache_name, file_key in sorted(added)[:10]
        ],
    }


def _purchase_identity(workload: dict[str, Any], env_id: str) -> dict[str, str]:
    environment = workload.get("environment")
    generation = environment.get("generation") if isinstance(environment, dict) else None
    if (
        workload.get("schemaVersion") != "bef-resource-purchase-workload/v1"
        or workload.get("status") != "captured"
        or not isinstance(environment, dict)
        or environment.get("envId") != env_id
        or not isinstance(generation, dict)
    ):
        raise TrialBlocked("canonical_purchase_workload_identity_missing")
    generation_id = generation.get("generationId")
    payer = generation.get("payerAddress")
    operation_id = workload.get("operationId")
    participant_id = generation.get("participantId")
    if not all(isinstance(value, str) and value for value in (generation_id, payer, operation_id, participant_id)):
        raise TrialBlocked("canonical_purchase_workload_identity_missing")
    return {
        "envId": env_id, "generationId": generation_id, "payerAddress": payer,
        "participantId": participant_id, "operationId": operation_id,
    }


def _write_fence_target(path: Path, identity: dict[str, str], phase: str, source_hashes: dict[str, str]) -> None:
    _write_json_new(path, {
        "schemaVersion": "bef-resource-workload-fence-target/v1",
        "phase": phase,
        **{key: identity[key] for key in ("envId", "generationId", "payerAddress")},
        "participantId": identity["participantId"],
        "manifestSha256": source_hashes["manifestSha256"],
        "applicationSourceSha256": source_hashes["applicationSourceSha256"],
        "probeSourceSha256": source_hashes["probeSourceSha256"],
    })


def _verify_fence_report(
    evidence_dir: Path, *, expected_purpose: str, expected_env_id: str = "bef-env-a"
) -> dict[str, Any]:
    path = evidence_dir / "fence-verification.json"
    report = _json_record(path)
    if expected_purpose not in {"readonly_guardrail", "protective_only", "trial_cleanup"}:
        raise TrialBlocked("fence_verification_expected_purpose_invalid")
    required_true = (
        "databaseRowsUnchangedAcrossFence", "generationFenced", "returnedCountsMatch",
        "returnedStatusesMatch", "protectedStateEqual", "generationIdentityMatchesBeforeFence",
    )
    if (
        report.get("fencePurpose") != expected_purpose
        or
        report.get("fenceHttpStatus") != 200
        or report.get("serverReportedChainState") != "not_touched"
        or any(report.get(key) is not True for key in required_true)
        or expected_env_id not in ENVIRONMENT_IDS
        or report.get("envId") != expected_env_id
        or not isinstance(report.get("generationId"), str)
        or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", report["generationId"], re.IGNORECASE)
    ):
        raise TrialBlocked("independent_generation_fence_proof_failed")
    readiness_fields = (
        "persistedEffectsUnchangedSinceReadiness",
        "protectedStateUnchangedSinceReadiness",
        "guardrailGenerationHadNoEffects",
    )
    if expected_purpose == "readonly_guardrail":
        if report.get("phase") != "guardrail_exceeded" or any(report.get(key) is not True for key in readiness_fields):
            raise TrialBlocked("guardrail_generation_changed_before_fence")
    elif any(report.get(key) is not None for key in readiness_fields):
        raise TrialBlocked("non_guardrail_fence_claimed_readiness_comparison")
    if expected_purpose == "trial_cleanup" and report.get("phase") not in {"cold", "warm"}:
        raise TrialBlocked("trial_cleanup_fence_phase_invalid")
    if expected_purpose == "protective_only" and report.get("phase") != "guardrail_exceeded":
        raise TrialBlocked("protective_fence_phase_invalid")
    return {
        "path": _relative(path), "sha256": _sha256(path.read_bytes()),
        "generationId": report.get("generationId"), "fencePurpose": expected_purpose,
    }


def _make_active_fence_callback(
    *, phase: str, evidence_dir: Path, marker: Path, runtime_env: dict[str, str],
    deadline: ScenarioDeadline | None = None,
):
    def fence(_violation: sampler.GuardrailViolation) -> dict[str, Any] | None:
        try:
            workload = _run_unbounded_workload(
                mode="fence-active", phase=phase, env_id="bef-env-a",
                evidence_dir=evidence_dir, runtime_env=runtime_env, marker=marker,
                timeout=35.0, deadline=deadline, reserve_seconds=0.0,
            )
            expected_purpose = "readonly_guardrail" if phase == "guardrail_exceeded" else "trial_cleanup"
            verification = _verify_fence_report(evidence_dir / "fence", expected_purpose=expected_purpose)
            report_path = evidence_dir / "workload.json"
            return {
                "status": "captured" if workload.get("status") == "captured" else "failed",
                "exitCode": 0 if workload.get("status") == "captured" else 2,
                "reportPath": str(report_path),
                "reportSha256": _sha256(report_path.read_bytes()),
                "generationId": verification.get("generationId"),
                "fencePurpose": verification.get("fencePurpose"),
                "envId": "bef-env-a",
            }
        except TrialBlocked:
            return {"status": "failed", "exitCode": 2, "generationId": "unknown", "envId": "bef-env-a"}
    return fence


def _require_purchase_process_completed(sample: dict[str, Any]) -> None:
    trial = sample.get("trialProcess")
    probe = trial.get("probeEvidence") if isinstance(trial, dict) else None
    if isinstance(trial, dict) and trial.get("exitCode") == 0 and isinstance(probe, dict) and probe.get("status") == "captured":
        return
    trigger = sample.get("guardrails", {}).get("trigger") if isinstance(sample.get("guardrails"), dict) else None
    if isinstance(trigger, dict) and trigger.get("code", "").endswith("_cache_bytes"):
        raise TrialBlocked("per_mount_cache_guardrail_exceeded_and_purchase_stopped")
    raise TrialBlocked("probe_workload_not_captured")


def _require_resource_metrics(sample: dict[str, Any]) -> None:
    host = sample.get("host")
    containers = sample.get("containers")
    source = sample.get("sourceProxy")
    artifact = sample.get("artifactDirectory")
    caches = sample.get("cacheDirectories")
    if not isinstance(host, dict) or host.get("status") != "observed":
        raise TrialBlocked("resource_host_metrics_unavailable")
    if not isinstance(containers, list) or len(containers) != len(sampler.SERVICES):
        raise TrialBlocked("resource_container_inventory_incomplete")
    observed_services: set[str] = set()
    for row in containers:
        if not isinstance(row, dict) or row.get("cgroupStatus") != "observed" or row.get("cpuUsageStatus") != "observed":
            raise TrialBlocked("resource_cgroup_cpu_window_unavailable")
        service = row.get("service")
        cpu_delta = row.get("cpuUsageDeltaNanoseconds")
        if (
            not isinstance(service, str)
            or service in observed_services
            or isinstance(cpu_delta, bool)
            or not isinstance(cpu_delta, int)
            or cpu_delta < 0
        ):
            raise TrialBlocked("resource_container_cpu_observation_invalid")
        observed_services.add(service)
        if row.get("service") in sampler.POLICY_MEMORY_KEYS:
            memory_check = row.get("memoryLimitCheck")
            current_window = row.get("memoryCurrentWindowMaximumBytes")
            window_samples = row.get("memoryCurrentWindowSampleCount")
            lifetime_peak = row.get("memoryPeakBytesSinceContainerStart")
            if (
                not isinstance(memory_check, dict)
                or memory_check.get("status") != "within_limit"
                or isinstance(current_window, bool)
                or not isinstance(current_window, int)
                or current_window < 0
                or isinstance(window_samples, bool)
                or not isinstance(window_samples, int)
                or window_samples < 2
                or isinstance(lifetime_peak, bool)
                or not isinstance(lifetime_peak, int)
                or lifetime_peak < current_window
            ):
                raise TrialBlocked("resource_memory_window_or_limit_unavailable")
    if observed_services != set(sampler.SERVICES):
        raise TrialBlocked("resource_container_service_set_incomplete")
    if not isinstance(source, dict) or not isinstance(source.get("windowDelta"), dict) or source["windowDelta"].get("status") != "observed":
        raise TrialBlocked("source_proxy_counter_window_unavailable")
    source_calls = source["windowDelta"].get("sourceCallsReserved")
    if isinstance(source_calls, bool) or not isinstance(source_calls, int) or source_calls < 0:
        raise TrialBlocked("source_proxy_counter_window_invalid")
    artifact_check = artifact.get("guardrailCheck") if isinstance(artifact, dict) else None
    artifact_bytes = artifact_check.get("observedMaximumBytes") if isinstance(artifact_check, dict) else None
    if (
        not isinstance(artifact_check, dict)
        or artifact_check.get("status") != "within_limit"
        or isinstance(artifact_bytes, bool)
        or not isinstance(artifact_bytes, int)
        or artifact_bytes < 0
    ):
        raise TrialBlocked("resource_evidence_byte_bound_unverified")
    if not isinstance(caches, dict) or set(caches) != {"anvil-a-state", "anvil-a-rpc"}:
        raise TrialBlocked("resource_cache_directory_samples_missing")
    for row in caches.values():
        check = row.get("guardrailCheck") if isinstance(row, dict) else None
        maximum_bytes = row.get("maximumObservedBytes") if isinstance(row, dict) else None
        limit_bytes = row.get("byteLimit") if isinstance(row, dict) else None
        if (
            not isinstance(check, dict)
            or check.get("status") != "within_limit"
            or isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or isinstance(limit_bytes, bool)
            or not isinstance(limit_bytes, int)
            or maximum_bytes > limit_bytes
        ):
            raise TrialBlocked("anvil_cache_bound_not_within_limit")


def _verify_read_progress(evidence_dir: Path, env_id: str) -> dict[str, Any]:
    identity = _json_record(evidence_dir / "identity.json")
    if (
        identity.get("schemaVersion") != "bef-resource-workload-identity/v1"
        or identity.get("phase") != "guardrail_exceeded"
        or identity.get("envId") != env_id
        or not isinstance(identity.get("generationId"), str)
        or not isinstance(identity.get("payerAddress"), str)
    ):
        raise TrialBlocked("read_loop_identity_missing")
    path = evidence_dir / "read-progress.ndjson"
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise TrialBlocked("read_loop_progress_unavailable") from error
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise TrialBlocked("read_loop_progress_size_invalid")
    lines = raw.splitlines()
    if not lines or len(lines) > 10_000:
        raise TrialBlocked("read_loop_progress_count_invalid")
    expected_path = f"/tools/{env_id}/balances"
    seen_observations: set[str] = set()
    seen_artifacts: set[str] = set()
    for sequence, line in enumerate(lines, start=1):
        if len(line) > 16_384:
            raise TrialBlocked("read_loop_progress_line_too_large")
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TrialBlocked("read_loop_progress_json_invalid") from error
        if (
            not isinstance(row, dict)
            or row.get("schemaVersion") != "bef-resource-read-progress/v1"
            or row.get("envId") != env_id
            or row.get("generationId") != identity["generationId"]
            or row.get("variantId") != "guardrail_exceeded"
            or row.get("sequence") != sequence
            or row.get("status") != 200
            or not isinstance(row.get("observationId"), str)
            or not isinstance(row.get("artifact"), dict)
        ):
            raise TrialBlocked("read_loop_progress_identity_invalid")
        artifact = row["artifact"]
        artifact_path = artifact.get("path")
        digest = artifact.get("sha256")
        observation_id = row.get("observationId")
        if (
            artifact.get("boundary") != "actual-tool-http"
            or artifact.get("contentType") != "application/json"
            or not isinstance(artifact_path, str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
            or Path(artifact_path).is_absolute()
            or "\\" in artifact_path
            or any(part in {"", ".", ".."} for part in Path(artifact_path).parts)
            or observation_id in seen_observations
            or artifact_path in seen_artifacts
        ):
            raise TrialBlocked("read_loop_http_artifact_reference_invalid")
        seen_observations.add(observation_id)
        seen_artifacts.add(artifact_path)
        artifact_parts = Path(artifact_path).parts
        evidence_root = Path(os.path.abspath(os.fspath(evidence_dir)))
        observed_path = evidence_root.joinpath(*artifact_parts)
        try:
            cursor = evidence_root
            if cursor.is_symlink():
                raise TrialBlocked("read_loop_http_artifact_path_invalid")
            for part in artifact_parts[:-1]:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise TrialBlocked("read_loop_http_artifact_path_invalid")
            if observed_path.is_symlink() or not observed_path.is_file():
                raise TrialBlocked("read_loop_http_artifact_missing")
            observation_bytes = observed_path.read_bytes()
        except (OSError, ValueError) as error:
            raise TrialBlocked("read_loop_http_artifact_path_invalid") from error
        if len(observation_bytes) > 1_048_576 or _sha256(observation_bytes) != digest:
            raise TrialBlocked("read_loop_http_artifact_hash_mismatch")
        try:
            observation = json.loads(observation_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TrialBlocked("read_loop_http_artifact_json_invalid") from error
        request = observation.get("request") if isinstance(observation, dict) else None
        response = observation.get("response") if isinstance(observation, dict) else None
        body = response.get("body") if isinstance(response, dict) else None
        if (
            not isinstance(observation, dict)
            or observation.get("schemaVersion") != "bef-http-observation/v1"
            or observation.get("boundary") != "actual-tool-http"
            or observation.get("operationId") is not None
            or observation.get("variantId") != "guardrail_exceeded"
            or not isinstance(request, dict)
            or request.get("method") != "GET"
            or request.get("path") != expected_path
            or not isinstance(response, dict)
            or response.get("status") != 200
            or not isinstance(body, dict)
            or body.get("boundary") != "local-chain-readonly-proxy"
            or body.get("envId") != env_id
            or body.get("generationId") != identity["generationId"]
            or not isinstance(body.get("payer"), str)
            or body["payer"].lower() != identity["payerAddress"].lower()
        ):
            raise TrialBlocked("read_loop_http_observation_not_matching_generation")
    return {
        "status": "observed",
        "lineCount": len(lines),
        "rawProgressSha256": _sha256(raw),
        "firstSequence": 1,
        "lastSequence": len(lines),
        "verifiedHttpObservations": len(lines),
    }


def _preflight_report(directory: Path) -> dict[str, Any]:
    report = _json_record(directory / "workload.json")
    if report.get("status") != "captured" or report.get("activeGenerationObserved") is not False:
        raise TrialBlocked("active_generation_preflight_not_clear")
    return report


def _verify_guardrail_readonly_fence_report(run_root: Path) -> dict[str, Any]:
    """Read the direct fence-mode output under guardrail-fence-active."""

    return _verify_fence_report(
        run_root / "guardrail-fence-active",
        expected_purpose="readonly_guardrail",
    )


def _plan() -> dict[str, Any]:
    return {
        "schemaVersion": "bef-sc011-orchestration-plan/v1",
        "execution": "plan_only",
        "scenarioId": "BEF-SC-011",
        "gateStatus": "not_established_by_plan",
        "steps": [
            "verify both environments have no active generation",
            "create fresh task-owned Anvil-A state and Foundry RPC cache bind roots",
            "recreate only Anvil-A with those roots; require empty caches after startup",
            "sample one actual canonical purchase and fence its generation",
            "verify cold cleanup, gracefully stop Anvil-A, and snapshot the combined cache roots",
            "require a nonempty combined prepared cache and retain its exact entries across same-bind Anvil-A recreation",
            "sample another actual canonical purchase and fence its generation",
            "run actual authorized balance reads until pinned overrun, stop owned child, fence, and compare DB/RPC state",
        ],
        "cacheLabels": {
            "cold": "empty dedicated disk caches after Anvil startup",
            "warm": "nonempty post-cleanup disk-cache entries retained across graceful Anvil-A process recreation",
        },
        "limitations": [
            "provider compute units remain unknown unless directly observed",
            "current cgroup sampler begins after Anvil startup, so startup CPU and memory are not part of the trial window",
            "the cold label is accepted only when dedicated state and RPC caches remain empty after Anvil startup",
            "an individual state or RPC cache root may be empty; warm preparation requires entries across the combined roots",
            "cache changes during the warm purchase are recorded and are not treated as failed restart retention",
            "resource measurements do not establish the BEF-SC-011 gate",
        ],
    }


def _execute(evidence_dir: Path | None = None) -> tuple[Path, dict[str, Any]]:
    guardrails, manifest_sha = _load_manifest_guardrails()
    if not WORKLOAD_ENTRY.is_file():
        raise TrialBlocked("sc011_resource_workload_entry_not_ready")
    runtime_env = _runtime_environment()
    deadline = ScenarioDeadline(guardrails["maxResourceScenarioSeconds"])
    lock_token = _acquire_lock()
    run_root: Path | None = None
    report: dict[str, Any] = {
        "schemaVersion": "bef-sc011-resource-trials/v1",
        "scenarioId": "BEF-SC-011",
        "status": "running",
        "gateStatus": "not_established_by_resource_orchestrator",
        "manifestSha256": manifest_sha,
        "guardrails": guardrails,
        "outerScenarioDeadlineSeconds": guardrails["maxResourceScenarioSeconds"],
        "providerComputeUnits": {"status": "unknown", "value": None},
        "peakMemorySemantics": {
            "windowMetric": "maximum sampled memory.current",
            "lifetimeMetric": "memory.peak since each container cgroup creation",
            "perTrialClaim": "only recreated Anvil-A has a fresh cgroup lifetime beginning at its recreation; reused services are window samples",
        },
        "cacheCondition": {"status": "unknown", "reason": "trial_not_completed"},
        "steps": [],
        "issues": [],
    }
    try:
        run_root = _new_run_root(evidence_dir)
        report["evidenceRoot"] = _relative(run_root)
        report["freeDiskBytesBefore"] = shutil.disk_usage(RUNS).free
        minimum_free = 2 * guardrails["maxAnvilCacheBytesEach"] + 4 * guardrails["maxEvidenceBytesPerTrial"]
        if report["freeDiskBytesBefore"] < minimum_free:
            raise TrialBlocked("insufficient_free_disk_for_pinned_trial_bounds")

        cache_root = run_root / "cache-a"
        state_path = cache_root / "state"
        rpc_path = cache_root / "foundry-cache"
        state_path.mkdir(parents=True, exist_ok=False)
        rpc_path.mkdir(parents=True, exist_ok=False)
        cache_paths = {"anvil-a-state": state_path, "anvil-a-rpc": rpc_path}
        expected_paths = {"state": str(state_path), "rpc": str(rpc_path)}
        runtime_env.update({
            "BEF_ANVIL_A_STATE_CACHE_HOST_DIR": str(state_path),
            "BEF_ANVIL_A_RPC_CACHE_HOST_DIR": str(rpc_path),
        })
        report["cacheRoots"] = {name: _relative(path) for name, path in cache_paths.items()}
        report["steps"].append({"name": "active_generation_preflight", "status": "running"})
        isolation_checks = _assert_isolation(runtime_env, run_root / "preflight", deadline=deadline)
        report["steps"][-1] = {"name": "active_generation_preflight", "status": "observed_clear", "checks": isolation_checks}

        with _temporary_environment(runtime_env):
            old_a = _anvil_a_info(deadline=deadline)
            sources, compose_sha = sampler._compose_anvil_cache_sources()
        report["anvilABeforeTrial"] = {"containerId": old_a.container_id, "image": old_a.image, "state": old_a.state}
        report["expandedComposeSha256"] = compose_sha
        initial_cache = _cache_inventory(cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline)
        report["cacheInventoryBeforeAnvilRecreation"] = initial_cache
        if not all(_is_empty_cache(item) for item in initial_cache.values()):
            raise TrialBlocked("new_dedicated_cache_roots_not_empty")

        report["steps"].append({"name": "recreate_anvil_a_with_empty_caches", "status": "running"})
        with _temporary_environment(runtime_env):
            _run_checked(
                _compose_prefix() + ["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "180", "anvil-a"],
                timeout=200, deadline=deadline, reserve_seconds=300,
            )
            cold_binding, cold_compose_sha = _bind_observation(runtime_env, expected_paths, deadline=deadline)
        if cold_binding["containerId"] == old_a.container_id or cold_binding["state"] != "running":
            raise TrialBlocked("anvil_a_container_recreation_not_observed")
        cold_preworkload_cache = _cache_inventory(cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline)
        report["coldAnvil"] = cold_binding
        report["coldCacheBeforeWorkload"] = cold_preworkload_cache
        report["steps"][-1] = {"name": "recreate_anvil_a_with_empty_caches", "status": "observed", "containerChanged": True, "cacheMountsVerified": True}
        if cold_compose_sha != compose_sha or not all(_is_empty_cache(item) for item in cold_preworkload_cache.values()):
            raise TrialBlocked("cold_cache_not_empty_after_anvil_startup")

        cold_dir = run_root / "cold-purchase"
        cold_cache_fence_dir = run_root / "cold-cache-fence"
        cold_cache_fence_marker = run_root / "cold-cache-fence-target.json"
        report["steps"].append({"name": "cold_canonical_purchase", "status": "running"})
        cold_sample = _run_sampled_workload(
            mode="purchase", phase="cold", env_id="bef-env-a", evidence_dir=cold_dir,
            runtime_env=runtime_env, cache_paths=cache_paths,
            fence_generation=_make_active_fence_callback(
                phase="cold", evidence_dir=cold_cache_fence_dir,
                marker=cold_cache_fence_marker, runtime_env=runtime_env, deadline=deadline,
            ),
            timeout=float(guardrails["maxTrialSeconds"]),
            deadline=deadline, fence_reserve_seconds=45,
        )
        report["coldTrial"] = {
            "samplePath": _relative(cold_dir / "resource-sampler.json"),
            "sampleStatus": cold_sample.get("status"),
            "sample": cold_sample,
            "cacheBefore": cold_preworkload_cache,
        }
        cold_post_cache = _cache_inventory(cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline)
        report["coldTrial"]["cacheAfter"] = cold_post_cache
        if any(value.get("status") != "observed" for value in cold_post_cache.values()):
            raise TrialBlocked("cold_cache_inventory_unavailable_after_purchase")
        _require_purchase_process_completed(cold_sample)
        _require_resource_metrics(cold_sample)
        cold_workload = _json_record(cold_dir / "workload.json")
        cold_identity = _purchase_identity(cold_workload, "bef-env-a")
        report["coldTrial"].update({
            "workloadPath": _relative(cold_dir / "workload.json"),
            "workloadSha256": _sha256((cold_dir / "workload.json").read_bytes()),
            "identity": cold_identity,
        })
        report["steps"][-1] = {"name": "cold_canonical_purchase", "status": "captured", "operationId": cold_identity["operationId"]}
        cold_source_hashes = {
            "manifestSha256": str(cold_workload.get("manifestSha256")),
            "applicationSourceSha256": str(cold_workload.get("applicationSourceSha256")),
            "probeSourceSha256": str(cold_workload.get("probeSourceSha256")),
        }
        cold_marker = run_root / "cold-fence-target.json"
        _write_fence_target(cold_marker, cold_identity, "cold", cold_source_hashes)
        cold_fence_dir = run_root / "cold-fence"
        cold_fence = _run_unbounded_workload(
            mode="fence", phase="cold", env_id="bef-env-a", evidence_dir=cold_fence_dir,
            runtime_env=runtime_env, marker=cold_marker, deadline=deadline,
        )
        report["coldFence"] = {"workloadPath": _relative(cold_fence_dir / "workload.json"), **_verify_fence_report(cold_fence_dir, expected_purpose="trial_cleanup")}
        report["coldCacheAfterFence"] = _cache_inventory(
            cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline
        )

        pre_warm_checks = _assert_isolation(runtime_env, run_root / "pre-warm-preflight", deadline=deadline)
        report["steps"].append({"name": "pre_warm_active_generation_preflight", "status": "observed_clear", "checks": pre_warm_checks})
        warm_cache_before_stop = _cache_inventory(
            cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline
        )
        report["warmCacheBeforeGracefulStop"] = warm_cache_before_stop
        before_stop = _anvil_a_info(deadline=deadline)
        report["anvilABeforeWarmStop"] = {"containerId": before_stop.container_id, "state": before_stop.state}
        if before_stop.state != "running":
            raise TrialBlocked("anvil_a_not_running_before_warm_cache_flush")

        report["steps"].append({"name": "gracefully_stop_anvil_a_before_warm_cache_snapshot", "status": "running"})
        with _temporary_environment(runtime_env):
            _run_checked(
                _compose_prefix() + ["stop", "--timeout", "20", "anvil-a"],
                timeout=30, deadline=deadline, reserve_seconds=180,
            )
        stopped_info = _anvil_a_info(deadline=deadline)
        report["anvilAAfterWarmStop"] = {"containerId": stopped_info.container_id, "state": stopped_info.state}
        if stopped_info.container_id != before_stop.container_id or stopped_info.state != "exited":
            raise TrialBlocked("anvil_a_graceful_stop_not_observed_before_warm_snapshot")
        stop_outcome = _anvil_a_stop_outcome(stopped_info.container_id, deadline=deadline)
        report["anvilAWarmStopOutcome"] = stop_outcome
        if stop_outcome.get("status") != "observed" or stop_outcome.get("gracefulStopVerified") is not True:
            raise TrialBlocked("anvil_a_graceful_stop_outcome_unverified")
        report["steps"][-1] = {
            "name": "gracefully_stop_anvil_a_before_warm_cache_snapshot",
            "status": "observed_graceful_stop",
            "containerIdUnchanged": True,
            "exitCode": stop_outcome["exitCode"],
            "oomKilled": stop_outcome["oomKilled"],
        }

        warm_cache_prepared = _cache_inventory(
            cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline
        )
        report["warmCachePreparedAfterGracefulStop"] = warm_cache_prepared
        warm_cache_prepared_summary = _cache_inventory_summary(
            warm_cache_prepared, expected_cache_names=set(cache_paths)
        )
        report["warmCachePreparedSummary"] = warm_cache_prepared_summary
        if any(value.get("status") == "exceeded" for value in warm_cache_prepared.values()):
            raise TrialBlocked("warm_cache_prepared_exceeded_pinned_bound")
        if warm_cache_prepared_summary.get("status") != "observed":
            raise TrialBlocked("warm_cache_inventory_unavailable_after_cold_cleanup")
        if not warm_cache_prepared_summary.get("hasEntries"):
            raise TrialBlocked("warm_cache_empty_after_cold_cleanup")

        before_recreate = stopped_info
        with _temporary_environment(runtime_env):
            _run_checked(
                _compose_prefix() + ["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "180", "anvil-a"],
                timeout=200, deadline=deadline, reserve_seconds=180,
            )
            warm_binding, warm_compose_sha = _bind_observation(runtime_env, expected_paths, deadline=deadline)
        report["warmAnvil"] = warm_binding
        report["warmComposeConfigSha256"] = warm_compose_sha
        warm_cache_after_start = _cache_inventory(
            cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline
        )
        report["warmCacheAfterRestart"] = warm_cache_after_start
        report["warmCacheBeforeWorkload"] = warm_cache_after_start
        warm_restart_diff = _cache_inventory_diff(
            warm_cache_prepared,
            warm_cache_after_start,
            expected_cache_names=set(cache_paths),
        )
        report["warmCacheRestartDiff"] = warm_restart_diff
        if warm_binding["containerId"] == before_recreate.container_id or warm_binding["containerId"] == cold_binding["containerId"]:
            raise TrialBlocked("warm_anvil_process_recreation_not_observed")
        if warm_compose_sha != cold_compose_sha:
            raise TrialBlocked("cache_compose_binding_changed_between_trials")
        if any(value.get("status") == "exceeded" for value in warm_cache_after_start.values()):
            raise TrialBlocked("warm_cache_exceeded_pinned_bound_after_restart")
        if warm_restart_diff.get("status") != "observed":
            raise TrialBlocked("warm_cache_inventory_unavailable_after_restart")
        if not warm_restart_diff.get("beforeHadEntries"):
            raise TrialBlocked("warm_cache_prepared_baseline_empty")
        if not warm_restart_diff.get("allBeforeEntriesRetained"):
            raise TrialBlocked("warm_cache_prepared_entries_not_retained_after_restart")

        warm_dir = run_root / "warm-purchase"
        warm_cache_fence_dir = run_root / "warm-cache-fence"
        warm_cache_fence_marker = run_root / "warm-cache-fence-target.json"
        report["steps"].append({"name": "warm_canonical_purchase", "status": "running"})
        warm_sample = _run_sampled_workload(
            mode="purchase", phase="warm", env_id="bef-env-a", evidence_dir=warm_dir,
            runtime_env=runtime_env, cache_paths=cache_paths,
            fence_generation=_make_active_fence_callback(
                phase="warm", evidence_dir=warm_cache_fence_dir,
                marker=warm_cache_fence_marker, runtime_env=runtime_env, deadline=deadline,
            ),
            timeout=float(guardrails["maxTrialSeconds"]),
            deadline=deadline, fence_reserve_seconds=45,
        )
        report["warmTrial"] = {
            "samplePath": _relative(warm_dir / "resource-sampler.json"),
            "sampleStatus": warm_sample.get("status"),
            "sample": warm_sample,
            "cacheBefore": warm_cache_after_start,
        }
        warm_post_cache = _cache_inventory(cache_paths, guardrails["maxAnvilCacheBytesEach"], deadline=deadline)
        report["warmTrial"]["cacheAfter"] = warm_post_cache
        warm_purchase_cache_diff = _cache_inventory_diff(
            warm_cache_after_start,
            warm_post_cache,
            expected_cache_names=set(cache_paths),
        )
        report["warmTrial"]["cacheDiff"] = warm_purchase_cache_diff
        report["warmCacheDuringPurchaseDiff"] = warm_purchase_cache_diff
        if any(value.get("status") == "exceeded" for value in warm_post_cache.values()):
            raise TrialBlocked("warm_cache_exceeded_pinned_bound")
        if warm_purchase_cache_diff.get("status") != "observed":
            raise TrialBlocked("warm_cache_inventory_unavailable_after_purchase")
        _require_purchase_process_completed(warm_sample)
        _require_resource_metrics(warm_sample)
        warm_workload = _json_record(warm_dir / "workload.json")
        warm_identity = _purchase_identity(warm_workload, "bef-env-a")
        report["warmTrial"].update({
            "workloadPath": _relative(warm_dir / "workload.json"),
            "workloadSha256": _sha256((warm_dir / "workload.json").read_bytes()),
            "identity": warm_identity,
        })
        report["steps"][-1] = {"name": "warm_canonical_purchase", "status": "captured", "operationId": warm_identity["operationId"]}
        warm_source_hashes = {
            "manifestSha256": str(warm_workload.get("manifestSha256")),
            "applicationSourceSha256": str(warm_workload.get("applicationSourceSha256")),
            "probeSourceSha256": str(warm_workload.get("probeSourceSha256")),
        }
        warm_marker = run_root / "warm-fence-target.json"
        _write_fence_target(warm_marker, warm_identity, "warm", warm_source_hashes)
        warm_fence_dir = run_root / "warm-fence"
        warm_fence = _run_unbounded_workload(
            mode="fence", phase="warm", env_id="bef-env-a", evidence_dir=warm_fence_dir,
            runtime_env=runtime_env, marker=warm_marker, deadline=deadline,
        )
        report["warmFence"] = {"workloadPath": _relative(warm_fence_dir / "workload.json"), **_verify_fence_report(warm_fence_dir, expected_purpose="trial_cleanup")}

        _assert_isolation(runtime_env, run_root / "pre-overrun-preflight", deadline=deadline)
        read_dir = run_root / "guardrail-read"
        fence_dir = run_root / "guardrail-fence-active"
        ready_marker = run_root / "guardrail-ready.json"
        release_marker = run_root / "guardrail-release.json"
        def fence_after_stop(_violation: sampler.GuardrailViolation) -> dict[str, Any] | None:
            try:
                fence_report = _run_unbounded_workload(
                    mode="fence", phase="guardrail_exceeded", env_id="bef-env-a",
                    evidence_dir=fence_dir, runtime_env=runtime_env, marker=ready_marker,
                    timeout=30.0, deadline=deadline, reserve_seconds=0.0,
                )
                verification = _verify_fence_report(fence_dir, expected_purpose="readonly_guardrail")
                return {
                    "status": "captured" if fence_report.get("status") == "captured" else "failed",
                    "exitCode": 0,
                    "reportPath": str(fence_dir / "workload.json"),
                    "reportSha256": _sha256((fence_dir / "workload.json").read_bytes()),
                    "generationId": verification.get("generationId"),
                    "envId": "bef-env-a",
                }
            except TrialBlocked:
                return {"status": "failed", "exitCode": 2, "generationId": "unknown", "envId": "bef-env-a"}

        read_sample = _run_sampled_workload(
            mode="read-loop", phase="guardrail_exceeded", env_id="bef-env-a", evidence_dir=read_dir,
            runtime_env=runtime_env, cache_paths=cache_paths,
            marker=ready_marker, release=release_marker,
            active_limit_seconds=guardrails["maxResourceReadOverrunSeconds"],
            fence_generation=fence_after_stop,
            timeout=float(guardrails["maxTrialSeconds"]),
            deadline=deadline, fence_reserve_seconds=30,
        )
        trigger = read_sample.get("guardrails", {}).get("trigger")
        cleanup = read_sample.get("trialProcess", {}).get("processTreeCleanup")
        if (
            read_sample.get("status") != "guardrail_exceeded"
            or not isinstance(trigger, dict)
            or trigger.get("code") != "max_resource_read_overrun_seconds"
            or not isinstance(cleanup, dict)
            or cleanup.get("directChildExited") is not True
            or cleanup.get("descendants") != "stopped" and cleanup.get("treeExitConfirmed") is not True
        ):
            raise TrialBlocked("resource_read_overrun_stop_not_proven")
        _require_resource_metrics(read_sample)
        read_progress = _verify_read_progress(read_dir, "bef-env-a")
        report["guardrailTrial"] = {
            "sample": read_sample,
            "samplePath": _relative(read_dir / "resource-sampler.json"),
            "readProgress": read_progress,
            "fenceWorkloadPath": _relative(fence_dir / "workload.json"),
            "fence": _verify_guardrail_readonly_fence_report(run_root),
            "readinessMarkerSha256": _sha256(ready_marker.read_bytes()),
            "releaseMarkerSha256": _sha256(release_marker.read_bytes()),
        }
        report["cacheCondition"] = {
            "status": "observed",
            "startupResourceWindow": "not_sampled",
            "cold": {
                "stateAndRpcCachesEmptyBeforeStartup": True,
                "stateAndRpcCachesEmptyAfterStartup": True,
                "coldExecutionWindowBeginsAfterAnvilStartup": True,
            },
            "warm": {
                "sameBindRoots": True,
                "cacheSnapshotTakenAfterColdCleanupAndGracefulStop": True,
                "combinedPreparedCacheWasNonempty": True,
                "preparedEntriesRetainedAcrossRestart": True,
                "warmPurchaseCacheMutationsRecordedWithoutRetentionGate": True,
                "anvilProcessRecreated": True,
            },
        }
        report["status"] = "captured"
        report["elapsedMonotonicNanoseconds"] = deadline.elapsed_nanoseconds()
        if report["elapsedMonotonicNanoseconds"] > guardrails["maxResourceScenarioSeconds"] * 1_000_000_000:
            raise TrialBlocked("max_resource_scenario_deadline_exceeded")
        report["issues"] = ["provider_compute_units_unknown", "resource_sample_is_not_the_scenario_gate"]
        _write_json_new(run_root / "orchestration.json", report)
        return run_root, report
    except (TrialBlocked, sampler.SamplerBlocked) as error:
        blocked_code = error.code if isinstance(error, (TrialBlocked, sampler.SamplerBlocked)) else "trial_blocked"
        report["status"] = "blocked"
        report["elapsedMonotonicNanoseconds"] = deadline.elapsed_nanoseconds()
        report["issues"].append(blocked_code)
        if isinstance(error, TrialBlocked) and error.diagnostics:
            report["diagnostics"] = error.diagnostics
        evidence_path = None
        if run_root is not None:
            evidence_path = run_root / "orchestration.json"
            _write_json_new(evidence_path, report)
        raise TrialBlocked(blocked_code, evidence_path) from error
    except (OSError, ValueError, TypeError) as error:
        del error
        report["status"] = "blocked"
        report["elapsedMonotonicNanoseconds"] = deadline.elapsed_nanoseconds()
        report["issues"].append("task_owned_io_or_observation_invalid")
        evidence_path = None
        if run_root is not None:
            evidence_path = run_root / "orchestration.json"
            _write_json_new(evidence_path, report)
        raise TrialBlocked("task_owned_io_or_observation_invalid", evidence_path) from None
    finally:
        _release_lock(lock_token)


def _protective_fence_only(evidence_dir: Path, env_id: str = "bef-env-a") -> dict[str, Any]:
    """Fence the sole observed active task generation without resetting anything."""

    if env_id not in ENVIRONMENT_IDS:
        raise TrialBlocked("protective_fence_environment_invalid")
    root = _new_run_root(evidence_dir)
    runtime_env = _runtime_environment()
    deadline = ScenarioDeadline(60)
    marker = root / "fence-target.json"
    workload_dir = root / "fence-active"
    workload = _run_unbounded_workload(
        mode="fence-active",
        phase="guardrail_exceeded",
        env_id=env_id,
        evidence_dir=workload_dir,
        runtime_env=runtime_env,
        marker=marker,
        timeout=45.0,
        deadline=deadline,
        reserve_seconds=5.0,
        expected_status="protected",
    )
    verification = _verify_fence_report(
        workload_dir / "fence", expected_purpose="protective_only", expected_env_id=env_id
    )
    if (workload.get("environmentId") != env_id
            or workload.get("generationId") != verification.get("generationId")
            or workload.get("fencePurpose") != "protective_only"):
        raise TrialBlocked("protective_fence_workload_identity_mismatch")
    report_path = workload_dir / "workload.json"
    verification_path = workload_dir / "fence" / "fence-verification.json"
    return {
        "status": "protected",
        "exitCode": 0,
        "reportPath": _relative(report_path),
        "reportSha256": _sha256(report_path.read_bytes()),
        "fenceReportPath": _relative(verification_path),
        "fenceReportSha256": _sha256(verification_path.read_bytes()),
        "generationId": verification.get("generationId"),
        "fencePurpose": verification.get("fencePurpose"),
        "envId": env_id,
        "databaseVerified": True,
        "rpcVerified": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="run the task-owned local trial sequence")
    parser.add_argument("--allow-task-owned-reset", action="store_true", help="acknowledge Anvil-A recreation and participant environment resets")
    parser.add_argument("--evidence-dir", type=Path, help="use this fresh task-owned artifacts/runs directory")
    parser.add_argument("--protective-fence-only", action="store_true", help="fence the sole active task generation without resetting")
    parser.add_argument(
        "--env-id", choices=("A", "B"), default="A",
        help="environment to protectively fence (default: A)",
    )
    args = parser.parse_args(argv)
    if args.protective_fence_only:
        if args.evidence_dir is None:
            print(json.dumps({"status": "blocked", "reason": "protective_fence_evidence_directory_required"}, sort_keys=True), file=sys.stderr)
            return 2
        try:
            environment_id = f"bef-env-{args.env_id.lower()}"
            report = _protective_fence_only(args.evidence_dir, environment_id)
        except TrialBlocked as error:
            blocked: dict[str, Any] = {"status": "blocked", "reason": error.code}
            if error.evidence_path and error.evidence_path.is_file():
                blocked["evidencePath"] = _relative(error.evidence_path)
                blocked["evidenceSha256"] = _sha256(error.evidence_path.read_bytes())
            print(json.dumps(blocked, sort_keys=True), file=sys.stderr)
            return 2
        print(json.dumps(report, sort_keys=True))
        return 0 if (report.get("status") == "protected"
                     and report.get("fencePurpose") == "protective_only"
                     and report.get("envId") == environment_id) else 2
    if not args.execute:
        print(json.dumps(_plan(), indent=2, sort_keys=True))
        return 0
    if not args.allow_task_owned_reset:
        print(json.dumps({"status": "blocked", "reason": "explicit_task_owned_reset_acknowledgement_required"}, sort_keys=True), file=sys.stderr)
        return 2
    try:
        run_root, report = _execute(args.evidence_dir)
    except TrialBlocked as error:
        blocked: dict[str, Any] = {"status": "blocked", "reason": error.code}
        if error.evidence_path and error.evidence_path.is_file():
            blocked["evidencePath"] = _relative(error.evidence_path)
            blocked["evidenceSha256"] = _sha256(error.evidence_path.read_bytes())
        print(json.dumps(blocked, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report.get("status"),
        "scenarioId": "BEF-SC-011",
        "evidencePath": _relative(run_root / "orchestration.json"),
        "evidenceSha256": _sha256((run_root / "orchestration.json").read_bytes()),
        "gateStatus": report.get("gateStatus"),
    }, sort_keys=True))
    return 0 if report.get("status") == "captured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
