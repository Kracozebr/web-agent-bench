"""Fence only completed BEF generations proven by a successful SC009/010 capture."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import bef_sc009010_resource_adapter as sc009010


_SCENARIOS = {"BEF-SC-009", "BEF-SC-010"}
_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_EFFECT_TABLES = (
    "operations-by-generation",
    "payments-by-operation",
    "deliveries-by-operation",
    "denials-by-generation",
    "x402-observations-by-operation",
    "selected-execution-by-generation",
    "selected-execution-events-by-generation",
)
_UNRESOLVED = {
    "pending", "unknown", "unresolved", "awaiting_payment", "processing", "submitted", "not_submitted",
}


class CleanupRefused(RuntimeError):
    """Cleanup cannot prove the exact task-owned generation and completed state."""


@dataclass(frozen=True)
class CleanupTarget:
    environment_id: str
    generation_id: str
    phase: str
    participant_id: str
    payer_address: str


def _no_unresolved_values(tables: dict[str, list[dict[str, Any]]]) -> bool:
    for name in _EFFECT_TABLES:
        rows = tables.get(name)
        if not isinstance(rows, list):
            return False
        for row in rows:
            for value in row.values():
                if isinstance(value, str) and value.strip().lower() in _UNRESOLVED:
                    return False
    return True


def _completed_generation(evidence: Any, tables: dict[str, list[dict[str, Any]]],
                          environment_id: str, generation_id: str, scenario_id: str,
                          phase: str) -> bool:
    if not _no_unresolved_values(tables):
        return False
    if scenario_id == "BEF-SC-009" and phase == "reset":
        return all(not tables[name] for name in _EFFECT_TABLES)

    operations = tables["operations-by-generation"]
    if not operations or any(
        row.get("env_id") != environment_id
        or str(row.get("generation_id")) != generation_id
        or row.get("status") not in {"delivered", "settled"}
        or row.get("receipt_status") != "success"
        or not sc009010._is_digest(row.get("transaction_hash"))
        for row in operations
    ):
        return False
    purchase_rows = [
        row for row in operations if str(row.get("operation_kind", "")).lower() == "purchase"
    ]
    payments = tables["payments-by-operation"]
    if len(purchase_rows) != 1 or len(payments) != 1:
        return False
    purchase = purchase_rows[0]
    payment = payments[0]
    if (
        payment.get("operation_id") != purchase.get("operation_id")
        or payment.get("env_id") != environment_id
        or str(payment.get("generation_id")) != generation_id
        or payment.get("receipt_status") != "success"
        or str(payment.get("transaction_hash", "")).lower()
            != str(purchase.get("transaction_hash", "")).lower()
    ):
        return False
    return (
        sc009010._has_successful_execution(tables)
        and sc009010._successful_purchase_rows(evidence, tables, environment_id, generation_id)
        and sc009010._successful_selected_actions(evidence, tables, environment_id, generation_id)
    )


def select_cleanup_targets(evidence: Any, scenario_id: str) -> tuple[CleanupTarget, ...]:
    """Return only final active generations covered by every strict scenario predicate."""

    if scenario_id not in _SCENARIOS or getattr(evidence, "scenario_id", None) != scenario_id:
        raise CleanupRefused("cleanup_scenario_identity_unverified")
    if getattr(evidence, "status", None) != "captured":
        raise CleanupRefused("cleanup_capture_not_successful")

    predicates = sc009010.evaluate_sc009010(evidence, scenario_id)
    expected_predicates = {
        "BEF-SC-009": {
            "independent_chain_state", "independent_service_state",
            "reset_not_crossing_boundary", "foreign_access_denied",
        },
        "BEF-SC-010": {
            "stale_generation_fenced", "chain_baseline", "service_baseline",
            "fixture_hash", "equivalent_probe_outcome",
        },
    }[scenario_id]
    if set(predicates) != expected_predicates or any(value is not True for value in predicates.values()):
        raise CleanupRefused("cleanup_requires_complete_strict_scenario_proof")

    envs = sc009010._manifest_envs(evidence)
    checkpoints = sc009010._checkpoint_map(evidence, scenario_id)
    if envs is None or checkpoints is None:
        raise CleanupRefused("cleanup_checkpoint_inventory_invalid")
    if scenario_id == "BEF-SC-009":
        expected = {
            ("baseline", envs[0]), ("mutated", envs[0]), ("reset", envs[0]),
            ("baseline", envs[1]), ("mutated", envs[1]), ("after_reset", envs[1]),
        }
        requested = (("reset", envs[0]), ("after_reset", envs[1]))
    else:
        expected = {(phase, envs[0]) for phase in ("baseline", "trial", "reset", "after_stale", "fresh_trial")}
        requested = (("fresh_trial", envs[0]),)
    if set(checkpoints) != expected:
        raise CleanupRefused("cleanup_checkpoint_inventory_invalid")

    targets: list[CleanupTarget] = []
    for phase, environment_id in requested:
        checkpoint = checkpoints.get((phase, environment_id))
        if not isinstance(checkpoint, dict):
            raise CleanupRefused("cleanup_final_checkpoint_missing")
        generation_id = checkpoint.get("generationId")
        service_snapshot = checkpoint.get("service")
        chain_snapshot = checkpoint.get("chain")
        tables = sc009010._service_tables(evidence, service_snapshot)
        if (not isinstance(generation_id, str) or not isinstance(service_snapshot, dict)
                or not isinstance(chain_snapshot, dict) or tables is None
                or sc009010._expected_chain_reads(evidence, chain_snapshot) is None
                or service_snapshot.get("environmentId") != environment_id
                or service_snapshot.get("generationId") != generation_id
                or service_snapshot.get("phase") != phase
                or chain_snapshot.get("environmentId") != environment_id
                or chain_snapshot.get("generationId") != generation_id
                or chain_snapshot.get("phase") != phase):
            raise CleanupRefused("cleanup_final_checkpoint_binding_invalid")
        rows = tables.get("generation-by-id")
        if not isinstance(rows, list) or len(rows) != 1:
            raise CleanupRefused("cleanup_generation_row_cardinality_invalid")
        generation = rows[0]
        participant_id, payer_address = generation.get("participant_id"), generation.get("payer_address")
        chain_addresses = chain_snapshot.get("addresses")
        if (generation.get("env_id") != environment_id
                or str(generation.get("generation_id")) != generation_id
                or generation.get("status") != "active"
                or not isinstance(participant_id, str) or not participant_id
                or not isinstance(payer_address, str) or not sc009010._ADDRESS_RE.fullmatch(payer_address)
                or not isinstance(chain_addresses, dict)
                or str(chain_addresses.get("payer", "")).lower() != payer_address.lower()):
            raise CleanupRefused("cleanup_generation_identity_or_active_status_invalid")
        if not _completed_generation(evidence, tables, environment_id, generation_id, scenario_id, phase):
            raise CleanupRefused("cleanup_generation_has_unresolved_or_incomplete_work")
        targets.append(CleanupTarget(environment_id, generation_id, phase, participant_id, payer_address))
    if len({target.environment_id for target in targets}) != len(targets):
        raise CleanupRefused("cleanup_environment_target_collision")
    return tuple(targets)


def _new_cleanup_root(repository_root: Path, scenario_id: str) -> Path:
    expected_root = Path(__file__).resolve().parents[3]
    if repository_root.resolve(strict=True) != expected_root:
        raise CleanupRefused("cleanup_repository_root_invalid")
    runs_root = repository_root / "artifacts" / "runs"
    parent = runs_root / "bef-generation-cleanup"
    cursor = parent
    while cursor != repository_root:
        if cursor.is_symlink() or cursor.parent == cursor:
            raise CleanupRefused("cleanup_evidence_symlink_rejected")
        cursor = cursor.parent
    parent.mkdir(parents=True, exist_ok=True)
    candidate = parent / f"{scenario_id.lower()}-{uuid.uuid4().hex}"
    candidate.mkdir(parents=False, exist_ok=False)
    return candidate


def _write_json_new(path: Path, value: dict[str, Any]) -> str:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _source_hashes(evidence: Any) -> dict[str, str]:
    index = getattr(evidence, "index", None)
    manifest_hash = getattr(evidence, "manifest_sha256", None)
    values = {
        "manifestSha256": manifest_hash,
        "applicationSourceSha256": index.get("applicationSourceSha256") if isinstance(index, dict) else None,
        "probeSourceSha256": index.get("probeSourceSha256") if isinstance(index, dict) else None,
    }
    if any(not isinstance(value, str) or not _DIGEST.fullmatch(value) for value in values.values()):
        raise CleanupRefused("cleanup_source_hash_identity_invalid")
    return {key: str(value).lower() for key, value in values.items()}


def cleanup_after_verified_scenario(context: Any, *, repository_root: Path | None = None) -> dict[str, Any] | None:
    """Fence scenario-owned final generations after the ordinary gate has passed."""

    scenario_id = getattr(context, "scenario_id", None)
    if scenario_id not in _SCENARIOS:
        return None
    required_observations = {
        "BEF-SC-009": {"independent_chain_state", "independent_service_state", "reset_not_crossing_boundary", "foreign_access_denied"},
        "BEF-SC-010": {"stale_generation_fenced", "chain_baseline", "service_baseline", "fixture_hash", "equivalent_probe_outcome"},
    }[scenario_id]
    if not required_observations.issubset(getattr(context, "observations", set())):
        raise AssertionError("post-verification cleanup requires all ordinary scenario observations")
    evidence = getattr(context, "outcome", None)
    root = repository_root or Path(__file__).resolve().parents[3]
    cleanup_root = _new_cleanup_root(root, scenario_id)
    summary_path = cleanup_root / "cleanup.json"
    probe_path = getattr(evidence, "directory", Path()) / "probe.json"
    probe_hash = hashlib.sha256(probe_path.read_bytes()).hexdigest() if probe_path.is_file() else None
    summary: dict[str, Any] = {
        "schemaVersion": "bef-generation-cleanup/v1",
        "boundary": "task-owned-generation-cleanup",
        "scenarioId": scenario_id,
        "status": "running",
        "sourceEvidence": {
            "probeIndexPath": probe_path.as_posix() if probe_hash else None,
            "probeIndexSha256": probe_hash,
        },
        "targets": [],
    }
    from tools import run_bef_sc011_trials as trial_runner

    try:
        targets = select_cleanup_targets(evidence, scenario_id)
        source_hashes = _source_hashes(evidence)
        runtime_env = trial_runner._runtime_environment()
        for target in targets:
            target_root = cleanup_root / target.environment_id
            workload_dir = target_root / "workload"
            marker = target_root / "fence-target.json"
            target_record: dict[str, Any] = {
                "envId": target.environment_id,
                "generationId": target.generation_id,
                "checkpointPhase": target.phase,
                "fencePurpose": "trial_cleanup",
                "status": "running",
            }
            summary["targets"].append(target_record)
            identity = {
                "envId": target.environment_id,
                "generationId": target.generation_id,
                "participantId": target.participant_id,
                "payerAddress": target.payer_address,
            }
            trial_runner._write_fence_target(marker, identity, "cold", source_hashes)
            target_record["markerPath"] = trial_runner._relative(marker)
            target_record["markerSha256"] = trial_runner._sha256(marker.read_bytes())
            workload = trial_runner._run_unbounded_workload(
                mode="fence", phase="cold", env_id=target.environment_id,
                evidence_dir=workload_dir, runtime_env=runtime_env, marker=marker,
                timeout=45.0, deadline=trial_runner.ScenarioDeadline(60),
                reserve_seconds=5.0, expected_status="captured",
            )
            # Direct `fence` mode emits both JSON reports in its evidence directory.
            fence_dir = workload_dir
            verification = trial_runner._verify_fence_report(
                fence_dir, expected_purpose="trial_cleanup", expected_env_id=target.environment_id,
            )
            workload_path = workload_dir / "workload.json"
            verification_path = fence_dir / "fence-verification.json"
            workload_payload = trial_runner._json_record(workload_path)
            actual_fence_digest = trial_runner._sha256(verification_path.read_bytes())
            fence_reference = workload_payload.get("fenceVerification")
            if (workload.get("status") != "captured"
                    or workload_payload.get("status") != "captured"
                    or workload_payload.get("mode") != "fence"
                    or workload_payload.get("fencePurpose") != "trial_cleanup"
                    or workload_payload.get("environment", {}).get("envId") != target.environment_id
                    or workload_payload.get("generationId") != target.generation_id
                    or verification.get("generationId") != target.generation_id
                    or verification.get("path") != trial_runner._relative(verification_path)
                    or verification.get("sha256") != actual_fence_digest
                    or not isinstance(fence_reference, dict)
                    or fence_reference.get("path") != "fence-verification.json"
                    or fence_reference.get("sha256") != actual_fence_digest
                    or fence_reference.get("status") != "verified"):
                raise trial_runner.TrialBlocked("cleanup_fence_target_proof_mismatch")
            target_record.update({
                "status": "fenced",
                "workloadPath": trial_runner._relative(workload_path),
                "workloadSha256": trial_runner._sha256(workload_path.read_bytes()),
                "fenceReportPath": verification["path"],
                "fenceReportSha256": verification["sha256"],
            })
        summary["status"] = "fenced"
        summary["cleanupEvidencePath"] = trial_runner._relative(summary_path)
        digest = _write_json_new(summary_path, summary)
        return {"path": trial_runner._relative(summary_path), "sha256": digest, "status": "fenced"}
    except Exception as error:
        if isinstance(error, CleanupRefused):
            reason = str(error)
        elif hasattr(error, "code") and isinstance(getattr(error, "code"), str):
            reason = str(getattr(error, "code"))
        else:
            reason = "task_owned_generation_cleanup_failed"
        summary["status"] = "failed"
        summary["reasonCode"] = reason
        for target_record in summary["targets"]:
            if not isinstance(target_record, dict):
                continue
            target_root = cleanup_root / str(target_record.get("envId", ""))
            marker = target_root / "fence-target.json"
            workload_path = target_root / "workload" / "workload.json"
            fence_path = target_root / "workload" / "fence-verification.json"
            if marker.is_file():
                target_record.setdefault("markerPath", trial_runner._relative(marker))
                target_record.setdefault("markerSha256", trial_runner._sha256(marker.read_bytes()))
            if workload_path.is_file():
                target_record.setdefault("workloadPath", trial_runner._relative(workload_path))
                target_record.setdefault("workloadSha256", trial_runner._sha256(workload_path.read_bytes()))
            if fence_path.is_file():
                target_record.setdefault("fenceReportPath", trial_runner._relative(fence_path))
                target_record.setdefault("fenceReportSha256", trial_runner._sha256(fence_path.read_bytes()))
            target_record["status"] = "failed"
        summary["cleanupEvidencePath"] = trial_runner._relative(summary_path)
        try:
            digest = _write_json_new(summary_path, summary)
        except OSError:
            digest = None
        suffix = f"#{digest}" if digest else ""
        raise AssertionError(
            f"post-verification generation cleanup failed: {reason}; "
            f"evidence={trial_runner._relative(summary_path)}{suffix}"
        ) from None
