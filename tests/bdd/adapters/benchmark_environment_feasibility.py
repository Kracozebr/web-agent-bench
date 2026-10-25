"""Evidence-backed adapters for the approved BEF acceptance scenarios.

The runtime probe is responsible for collecting observations. This module only
accepts secret-safe, hash-verified artifacts and recomputes gate predicates
from raw HTTP, database, RPC, receipt, and resource observations. The probe's
``observations`` labels are inventoried for traceability but never used as proof.
"""

from __future__ import annotations

import hashlib
import base64
import json
import math
import os
import re
import signal
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import pytest

from .registry import ScenarioContext, ScenarioRegistry
from . import sc011_resource_evidence


ADAPTER_PROFILES = {
    "benchmark_environment_http_evm_adapter",
    "benchmark_environment_resource_adapter",
    "benchmark_source_rpc_evidence_adapter",
}

CHANGE_NAME = "benchmark-environment-feasibility"
SCENARIO_IDS = tuple(f"BEF-SC-{number:03d}" for number in range(1, 13))
MANIFEST_RELATIVE = Path("infrastructure") / "benchmark-environment" / "manifest.json"
PROBE_SOURCE_RELATIVE = Path("packages") / "benchmark-environment" / "src" / "probe.ts"
TSX_LOADER_RELATIVE = Path("packages") / "benchmark-environment" / "node_modules" / "tsx" / "dist" / "loader.mjs"
EVIDENCE_ROOT_RELATIVE = Path("artifacts") / "benchmark-environment-feasibility" / "probes"
PROBE_SETUP_MARGIN_SECONDS = 30
PROBE_FALLBACK_TIMEOUT_SECONDS = 60
MAX_DECLARED_TRIAL_SECONDS = 3600
MAX_REPLAY_CAPTURE_FILES = 4096
MAX_REPLAY_CAPTURE_FILE_BYTES = 16 * 1024 * 1024
MAX_REPLAY_CAPTURE_TOTAL_BYTES = 64 * 1024 * 1024

_HEX_32_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_HEX_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+(?!<redacted>|\[redacted\]|\*{3})[^\s,;]+")
_URL_SECRET_RE = re.compile(
    r"(?i)(?:[?&](?:api[_-]?key|access[_-]?token|token|secret|password|signature)=)(?!<redacted>|\[redacted\]|%3Credacted%3E)[^&#\s]+"
)
_SENSITIVE_NAMES = frozenset(
    {
        "privatekey",
        "seedphrase",
        "mnemonic",
        "password",
        "secret",
        "authorization",
        "authorizationheader",
        "bearer",
        "runtoken",
        "adminkey",
        "accesstoken",
        "authtoken",
        "apitoken",
        "paymentsignature",
        "x402paymentsignature",
        "rawsignature",
        "signature",
        "databaseurl",
        "rpcurl",
        "sourceurl",
    }
)
_REDACTED_VALUES = frozenset({"", "<redacted>", "[redacted]", "redacted", "***", "omitted"})


class ProbeBlocked(RuntimeError):
    """The environment prerequisites were absent, so a real gate could not run."""


class EvidenceInvalid(ValueError):
    """The probe output is malformed, tampered, contradictory, or unsafe."""


@dataclass(frozen=True)
class EvidenceArtifact:
    """One content-addressed raw observation within a probe evidence directory."""

    relative_path: str
    sha256: str
    boundary: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class ProbeEvidence:
    """Validated probe index plus independently readable raw artifact contents."""

    scenario_id: str
    status: str
    directory: Path
    index: dict[str, Any]
    manifest: dict[str, Any]
    manifest_sha256: str
    artifacts: tuple[EvidenceArtifact, ...]
    environment_id: str
    generation_id: str

    @classmethod
    def load(cls, repository_root: Path, scenario_id: str, directory: Path) -> "ProbeEvidence":
        root = directory.resolve(strict=True)
        if not root.is_dir():
            raise EvidenceInvalid("probe evidence path is not a directory")
        index_path = root / "probe.json"
        if not index_path.is_file():
            raise ProbeBlocked("runtime probe did not produce probe.json")
        index_bytes = index_path.read_bytes()
        index = _decode_json(index_bytes, "probe index")
        if index.get("schemaVersion") != "bef-runtime-probe/v1":
            raise EvidenceInvalid("probe index schema version is unsupported")
        if index.get("scenarioId") != scenario_id:
            raise EvidenceInvalid("probe index scenario does not match the requested scenario")
        status = index.get("status")
        if status not in {"captured", "blocked", "error"}:
            raise EvidenceInvalid("probe index has an invalid collection status")
        _reject_secrets(index, "probe index")

        # A blocked probe is allowed to carry only a machine-readable reason.
        # It must not invent a partial environment or observation inventory.
        if status == "blocked":
            if index.get("manifest") is not None or index.get("environment") is not None:
                raise EvidenceInvalid("blocked probe must not claim a manifest or environment")
            for name in ("operations", "observations", "artifacts"):
                if index.get(name) != []:
                    raise EvidenceInvalid(f"blocked probe must have an empty {name} inventory")
            reason = index.get("blockedReasonCode") or index.get("reasonCode")
            if not _nonempty(reason):
                raise EvidenceInvalid("blocked probe needs a machine-readable reason code")
            missing = index.get("missingPrerequisites", [])
            if not isinstance(missing, list) or not all(_nonempty(item) for item in missing):
                raise EvidenceInvalid("blocked probe prerequisite list is malformed")
            raise ProbeBlocked(f"runtime probe blocked: {reason}")
        if status == "error":
            # Error indexes are failures, even when the runtime could not finish
            # collecting the captured-path fields.
            raise EvidenceInvalid("runtime probe reported an execution error")

        environment = index.get("environment")
        if not isinstance(environment, dict) or not _nonempty(environment.get("envId")):
            raise EvidenceInvalid("probe index is missing environment and generation identity")
        generation = environment.get("generation")
        generation_id = generation.get("generationId") if isinstance(generation, dict) else generation
        if not _nonempty(generation_id):
            raise EvidenceInvalid("probe index is missing environment and generation identity")

        manifest_ref = index.get("manifest")
        if not isinstance(manifest_ref, dict):
            raise EvidenceInvalid("probe index is missing its runtime manifest reference")
        manifest_path_value = manifest_ref.get("path")
        expected_manifest_hash = manifest_ref.get("sha256")
        if not isinstance(manifest_path_value, str) or not _is_digest(expected_manifest_hash):
            raise EvidenceInvalid("runtime manifest reference needs a path and SHA-256")
        manifest_path = _resolve_manifest_path(repository_root, root, manifest_path_value)
        manifest_bytes = manifest_path.read_bytes()
        actual_manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        if actual_manifest_hash != expected_manifest_hash.lower():
            raise EvidenceInvalid("runtime manifest SHA-256 does not match the referenced file")
        manifest = _decode_json(manifest_bytes, "runtime manifest")
        _reject_secrets(manifest, "runtime manifest")

        raw_artifacts = index.get("artifacts")
        if not isinstance(raw_artifacts, list) or not raw_artifacts:
            raise ProbeBlocked("probe index contains no raw evidence artifacts")
        artifacts: list[EvidenceArtifact] = []
        seen_paths: set[str] = set()
        raw_operations = index.get("operations", [])
        if not isinstance(raw_operations, list):
            raise EvidenceInvalid("probe operations inventory must be a list")
        known_operations = {
            item.get("operationId")
            for item in raw_operations
            if isinstance(item, dict) and _nonempty(item.get("operationId"))
        }
        for entry in raw_artifacts:
            if not isinstance(entry, dict):
                raise EvidenceInvalid("probe artifact index contains a non-object entry")
            relative = entry.get("path")
            expected_hash = entry.get("sha256")
            boundary = entry.get("boundary")
            content_type = entry.get("contentType")
            if (
                not isinstance(relative, str)
                or not relative
                or not _is_digest(expected_hash)
                or not _nonempty(boundary)
                or not isinstance(content_type, str)
                or "json" not in content_type.lower()
            ):
                raise EvidenceInvalid("probe artifact entry is missing its path, digest, boundary, or JSON type")
            normalized = Path(relative)
            if normalized.is_absolute() or ".." in normalized.parts:
                raise EvidenceInvalid("probe artifact path escapes the evidence directory")
            resolved = (root / normalized).resolve(strict=True)
            if not _is_relative_to(resolved, root) or not resolved.is_file():
                raise EvidenceInvalid("probe artifact path is outside the evidence directory")
            canonical_relative = resolved.relative_to(root).as_posix()
            if canonical_relative in seen_paths:
                raise EvidenceInvalid("probe artifact index contains a duplicate path")
            seen_paths.add(canonical_relative)
            contents = resolved.read_bytes()
            if hashlib.sha256(contents).hexdigest() != expected_hash.lower():
                raise EvidenceInvalid(f"probe artifact SHA-256 mismatch: {canonical_relative}")
            payload = _decode_json(contents, f"probe artifact {canonical_relative}")
            payload_boundary = payload.get("boundary")
            sc011_raw_resource_schemas = {
                "bef-resource-trial/v1",
                "bef-sc011-resource-trials/v1",
                "bef-resource-missing-sampler-control/v1",
                "bef-resource-workload-identity/v1",
                "bef-resource-workload-ready/v1",
                "bef-resource-workload-release/v1",
                "bef-resource-workload-fence-target/v1",
                "bef-sc011-outer-recovery/v1",
            }
            is_raw_resource_bytes = (
                boundary == "resource-data"
                and payload_boundary is None
                and (
                    payload.get("schemaVersion") is None
                    or scenario_id == "BEF-SC-011"
                    and payload.get("schemaVersion") in sc011_raw_resource_schemas
                )
            )
            if boundary != "runtime-manifest" and not is_raw_resource_bytes and payload_boundary != boundary:
                raise EvidenceInvalid(f"probe artifact boundary mismatch: {canonical_relative}")
            if boundary == "resource-data" and payload.get("schemaVersion") not in {
                None,
                "bef-resource-observation/v1",
                *(sc011_raw_resource_schemas if scenario_id == "BEF-SC-011" else set()),
            }:
                raise EvidenceInvalid(f"resource artifact schema mismatch: {canonical_relative}")
            if payload.get("operationId") is not None and payload.get("operationId") not in known_operations:
                raise EvidenceInvalid(f"probe artifact has an unindexed operation: {canonical_relative}")
            _reject_secrets(payload, f"probe artifact {canonical_relative}")
            artifacts.append(EvidenceArtifact(canonical_relative, expected_hash.lower(), boundary, payload))

        manifest_artifacts = [item for item in artifacts if item.boundary == "runtime-manifest"]
        if len(manifest_artifacts) != 1 or manifest_artifacts[0].payload != manifest:
            raise EvidenceInvalid("probe evidence must include exactly one copy of the hashed runtime manifest")
        if manifest_ref.get("path") != manifest_artifacts[0].relative_path:
            raise EvidenceInvalid("runtime manifest reference does not point to its indexed evidence copy")

        # The source labels must point into the verified artifact inventory. They
        # remain pointers only; their expected/observed text is never a predicate.
        observations = index.get("observations", [])
        if not isinstance(observations, list):
            raise EvidenceInvalid("probe observations inventory must be a list")
        for observation in observations:
            if not isinstance(observation, dict):
                raise EvidenceInvalid("probe observations inventory contains a non-object")
            source = observation.get("sourceArtifact")
            if source is not None and source not in seen_paths:
                raise EvidenceInvalid("probe observation points to an unverified artifact")

        for digest_field in ("applicationSourceSha256", "probeSourceSha256"):
            if not _is_digest(index.get(digest_field)):
                raise EvidenceInvalid(f"captured probe is missing {digest_field}")
        runtime_versions = index.get("runtimeVersions")
        if not isinstance(runtime_versions, dict) or not runtime_versions or not all(
            _nonempty(key) and _nonempty(value) for key, value in runtime_versions.items()
        ):
            raise EvidenceInvalid("captured probe is missing runtime version observations")
        source_block = index.get("sourceBlock")
        if not isinstance(source_block, dict) or not _nonempty(source_block.get("number")) or not _is_digest(
            source_block.get("hash")
        ):
            raise EvidenceInvalid("captured probe is missing pinned source block identity")
        if not artifacts:
            raise ProbeBlocked("runtime probe captured no usable observations")
        return cls(
            scenario_id=scenario_id,
            status=status,
            directory=root,
            index=index,
            manifest=manifest,
            manifest_sha256=actual_manifest_hash,
            artifacts=tuple(artifacts),
            environment_id=str(environment["envId"]),
            generation_id=str(generation_id),
        )

    def boundary_artifacts(self, *boundaries: str) -> tuple[EvidenceArtifact, ...]:
        allowed = set(boundaries)
        return tuple(item for item in self.artifacts if item.boundary in allowed)

    def http_artifacts(self) -> tuple[EvidenceArtifact, ...]:
        return self.boundary_artifacts(
            "participant-http", "actual-tool-http", "admin-http", "private-admin-http", "facilitator-http"
        )

    def resource_artifacts(self) -> tuple[EvidenceArtifact, ...]:
        return self.boundary_artifacts("resource-data")

    def database_artifacts(self) -> tuple[EvidenceArtifact, ...]:
        return self.boundary_artifacts("readonly-database")

    def rpc_artifacts(self, endpoint_boundary: str | None = None) -> tuple[EvidenceArtifact, ...]:
        artifacts = self.boundary_artifacts("source-readonly-proxy", "local-chain-readonly-proxy")
        if endpoint_boundary is None:
            return artifacts
        return tuple(
            item
            for item in artifacts
            if item.payload.get("endpointBoundary") == endpoint_boundary
        )

    def http_events(self, *, variant_id: str | None = None) -> tuple[EvidenceArtifact, ...]:
        return tuple(
            item
            for item in self.http_artifacts()
            if variant_id is None or item.payload.get("variantId") == variant_id
        )

    def db_rows(self, *, variant_id: str | None = None) -> tuple[dict[str, Any], ...]:
        result: list[dict[str, Any]] = []
        for artifact in self.database_artifacts():
            payload = artifact.payload
            if payload.get("readOnly") is not True:
                continue
            role = payload.get("databaseRole")
            if not isinstance(role, str) or not role.strip() or "admin" in role.lower() or "superuser" in role.lower():
                continue
            if variant_id is not None and payload.get("variantId") != variant_id:
                continue
            rows = payload.get("rows")
            if isinstance(rows, list):
                result.extend(row for row in rows if isinstance(row, dict))
        return tuple(result)

    def rpc_events(
        self, *, endpoint_boundary: str | None = None, variant_id: str | None = None
    ) -> tuple[EvidenceArtifact, ...]:
        events = self.rpc_artifacts(endpoint_boundary)
        return tuple(
            item
            for item in events
            if (variant_id is None or item.payload.get("variantId") == variant_id)
            and item.payload.get("forwarded") is not False
            and isinstance(item.payload.get("method"), str)
            and item.payload["method"].startswith("eth_")
        )

    def variant_ids(self) -> frozenset[str]:
        return frozenset(
            item.payload["variantId"]
            for item in self.artifacts
            if isinstance(item.payload.get("variantId"), str) and item.payload["variantId"]
        )

    def variants_are_exact(self, expected: Iterable[str]) -> bool:
        """Require each declared negative variant and reject undeclared variants."""

        return self.variant_ids() == frozenset(expected)


def register(registry: ScenarioRegistry) -> None:
    """Register the approved twelve BEF gates with their reviewed adapter profiles."""

    all_contracts = registry.contracts()
    expected = set(SCENARIO_IDS)
    if not expected.issubset(all_contracts):
        raise ValueError("BEF adapter requires BEF-SC-001 through BEF-SC-012 contracts")
    contracts = {scenario_id: all_contracts[scenario_id] for scenario_id in SCENARIO_IDS}
    profiles = {
        **{scenario_id: "benchmark_environment_http_evm_adapter" for scenario_id in SCENARIO_IDS[:10]},
        "BEF-SC-011": "benchmark_environment_resource_adapter",
        "BEF-SC-012": "benchmark_source_rpc_evidence_adapter",
    }
    if set(profiles.values()) != ADAPTER_PROFILES:
        raise ValueError("BEF adapter profile declaration is inconsistent")
    for scenario_id in SCENARIO_IDS:
        registry.register(
            scenario_id,
            BenchmarkEnvironmentCase(scenario_id, contracts[scenario_id]),
            adapter_profile=profiles[scenario_id],
        )


class BenchmarkEnvironmentCase:
    """One scenario-specific probe with raw-evidence predicates for its contract."""

    def __init__(self, scenario_id: str, contract: Any) -> None:
        if scenario_id not in SCENARIO_IDS:
            raise ValueError(f"unsupported BEF scenario {scenario_id!r}")
        self._scenario_id = scenario_id
        self._contract = contract
        self._repository_root = Path(__file__).resolve().parents[3]

    def setup(self, context: ScenarioContext) -> None:
        context.state["scenario_id"] = self._scenario_id
        context.state["contract"] = self._contract

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        if not when_text:
            raise AssertionError(f"{self._scenario_id} has no WHEN action")
        method = getattr(self, "_execute_" + self._scenario_id.replace("-", "_"))
        method(context)

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        if not then_text:
            raise AssertionError(f"{self._scenario_id} has no THEN expectation")
        method = getattr(self, "_verify_" + self._scenario_id.replace("-", "_"))
        method(context)

    def _capture(self, context: ScenarioContext) -> None:
        node = shutil.which("node")
        probe_source = self._repository_root / PROBE_SOURCE_RELATIVE
        try:
            tsx_loader = (self._repository_root / TSX_LOADER_RELATIVE).resolve(strict=True)
        except (OSError, RuntimeError):
            tsx_loader = None
        if node is None or tsx_loader is None or not tsx_loader.is_file() or not probe_source.is_file():
            pytest.skip("BLOCKED: BEF runtime deployment or local Node/tsx probe entry point is unavailable")

        evidence_root_value = os.environ.get("BEF_EVIDENCE_ROOT")
        evidence_root = (
            Path(evidence_root_value).expanduser()
            if evidence_root_value
            else self._repository_root / EVIDENCE_ROOT_RELATIVE
        )
        evidence_root.mkdir(parents=True, exist_ok=True)
        evidence_dir = evidence_root / f"{self._scenario_id.lower()}-{uuid.uuid4().hex}"
        evidence_dir.mkdir(parents=False, exist_ok=False)
        command = [
            node,
            "--import",
            tsx_loader.as_uri(),
            str(probe_source),
            "--scenario",
            self._scenario_id,
            "--evidence-dir",
            str(evidence_dir),
        ]
        if self._scenario_id == "BEF-SC-012":
            sc004_directory = os.environ.get("BEF_SC004_EVIDENCE_DIR")
            sc005_directory = os.environ.get("BEF_SC005_EVIDENCE_DIR")
            if sc004_directory:
                command.extend(["--sc004-evidence-dir", sc004_directory])
            if sc005_directory:
                command.extend(["--sc005-evidence-dir", sc005_directory])
        if os.name == "nt" and node.lower().endswith(".cmd"):
            command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", *command]
        timeout_seconds = _probe_timeout_seconds(self._repository_root / MANIFEST_RELATIVE, self._scenario_id)
        try:
            process = _run_probe_command(
                command,
                cwd=self._repository_root,
                env=os.environ.copy(),
                timeout_seconds=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            index_path = evidence_dir / "probe.json"
            if index_path.is_file():
                try:
                    ProbeEvidence.load(self._repository_root, self._scenario_id, evidence_dir)
                except ProbeBlocked as error:
                    pytest.skip(f"BLOCKED: {error}")
                except EvidenceInvalid:
                    pass
            raise AssertionError(
                f"{self._scenario_id} probe exceeded its bounded {timeout_seconds:g}s execution window"
            ) from None
        index_path = evidence_dir / "probe.json"
        if not index_path.is_file():
            if process.returncode != 0:
                raise AssertionError(
                    f"{self._scenario_id} probe exited {process.returncode} without a secret-safe evidence index"
                )
            raise ProbeBlocked("runtime probe completed without a probe evidence index")
        try:
            evidence = ProbeEvidence.load(self._repository_root, self._scenario_id, evidence_dir)
        except ProbeBlocked as error:
            pytest.skip(f"BLOCKED: {error}")
        if process.returncode != 0:
            raise AssertionError(f"{self._scenario_id} probe exited {process.returncode}")
        context.outcome = evidence

    def _capture011(self, context: ScenarioContext) -> None:
        """Capture SC-011 through its bounded Python orchestrator, then hash-index raw output."""

        repository_root = self._repository_root
        manifest_path = repository_root / MANIFEST_RELATIVE
        runner_path = repository_root / "tools" / "run_bef_sc011_trials.py"
        if not manifest_path.is_file() or not runner_path.is_file():
            raise ProbeBlocked("SC-011 resource runner or manifest is unavailable")
        try:
            timeout_seconds = sc011_resource_evidence.resource_probe_timeout_seconds(manifest_path)
        except (OSError, ValueError) as error:
            raise ProbeBlocked("SC-011 resource guardrail pins are unavailable or incompatible") from error

        evidence_root_value = os.environ.get("BEF_EVIDENCE_ROOT")
        evidence_root = (
            Path(evidence_root_value).expanduser()
            if evidence_root_value
            else repository_root / "artifacts" / "runs" / "bef-sc011-adapter"
        )
        if not evidence_root.is_absolute():
            evidence_root = repository_root / evidence_root
        evidence_root = Path(os.path.abspath(evidence_root))
        runs_root = repository_root / "artifacts" / "runs"
        try:
            evidence_root.relative_to(runs_root.resolve(strict=False))
        except ValueError as error:
            raise ProbeBlocked("SC-011 evidence root must remain under ignored artifacts/runs") from error
        if sc011_resource_evidence._has_symlink_component(runs_root, evidence_root):
            raise ProbeBlocked("SC-011 evidence root contains a symbolic link")
        try:
            evidence_root.mkdir(parents=True, exist_ok=True)
            evidence_dir = evidence_root / f"bef-sc011-{uuid.uuid4().hex}"
            evidence_dir.mkdir(parents=False, exist_ok=False)
        except OSError as error:
            raise ProbeBlocked("SC-011 evidence directory could not be allocated") from error

        try:
            missing_sampler_control = sc011_resource_evidence.run_missing_sampler_control(evidence_dir, runner_path)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise ProbeBlocked("SC-011 missing-sampler control did not prove fail-closed startup") from error

        def protective_fence() -> dict[str, Any]:
            recovery_dir = evidence_dir / "outer-recovery-fence"
            command = [
                sys.executable,
                str(runner_path),
                "--protective-fence-only",
                "--evidence-dir",
                str(recovery_dir),
            ]
            try:
                return sc011_resource_evidence.run_sc011_protective_attempt_once(
                    command,
                    cwd=repository_root,
                    timeout_seconds=50.0,
                )
            except (OSError, ValueError, subprocess.SubprocessError):
                return {"status": "unknown", "reason": "protective_fence_runner_unavailable"}

        command = [
            sys.executable,
            str(runner_path),
            "--execute",
            "--allow-task-owned-reset",
            "--evidence-dir",
            str(evidence_dir),
        ]
        result = sc011_resource_evidence.run_sc011_orchestrator_bounded(
            command,
            cwd=repository_root,
            evidence_dir=evidence_dir,
            timeout_seconds=timeout_seconds,
            protective_fence=protective_fence,
        )
        if result.get("status") != "completed" or result.get("exitCode") != 0:
            recovery_path = result.get("recoveryPath")
            recovery_hash = result.get("recoverySha256")
            fence = result.get("protectiveFence")
            fence_ref = ""
            if isinstance(fence, dict):
                fence_path = fence.get("fenceReportPath") or fence.get("reportPath")
                fence_hash = fence.get("fenceReportSha256") or fence.get("reportSha256")
                if isinstance(fence_path, str) and _is_digest(fence_hash):
                    fence_ref = f"; protective_fence={fence_path}#{fence_hash}"
            raise ProbeBlocked(
                f"SC-011 resource run blocked ({result.get('reason', 'runner_failed')}); "
                f"recovery={recovery_path}#{recovery_hash}{fence_ref}; gate_status=unknown"
            )

        try:
            runner_summary = json.loads(str(result.get("stdout", "")))
        except json.JSONDecodeError as error:
            raise EvidenceInvalid("SC-011 runner did not return a machine-readable summary") from error
        if (
            not isinstance(runner_summary, dict)
            or runner_summary.get("status") != "captured"
            or runner_summary.get("scenarioId") != SCENARIO_IDS[10]
            or runner_summary.get("gateStatus") != "not_established_by_resource_orchestrator"
        ):
            raise EvidenceInvalid("SC-011 runner summary is missing captured status or scenario identity")
        try:
            orchestration_relative = sc011_resource_evidence._require_safe_relative(runner_summary.get("evidencePath"))
            orchestration_path = repository_root.joinpath(*orchestration_relative.parts)
            if not _is_relative_to(orchestration_path.resolve(strict=True), evidence_dir.resolve(strict=True)):
                raise ValueError("orchestration evidence escaped allocated SC-011 directory")
            orchestration_bytes = orchestration_path.read_bytes()
        except (OSError, ValueError) as error:
            raise EvidenceInvalid("SC-011 runner summary points to missing orchestration evidence") from error
        if (
            not _is_digest(runner_summary.get("evidenceSha256"))
            or hashlib.sha256(orchestration_bytes).hexdigest() != runner_summary["evidenceSha256"]
        ):
            raise EvidenceInvalid("SC-011 orchestration report hash does not match runner summary")
        try:
            sc011_resource_evidence.build_probe_index(
                evidence_dir,
                manifest_path,
                missing_sampler_control=missing_sampler_control,
            )
            evidence = ProbeEvidence.load(repository_root, SCENARIO_IDS[10], evidence_dir)
        except ProbeBlocked:
            raise
        except (OSError, ValueError) as error:
            raise EvidenceInvalid("SC-011 raw evidence could not be hash-indexed") from error
        context.outcome = evidence

    def _evidence(self, context: ScenarioContext) -> ProbeEvidence:
        if not isinstance(context.outcome, ProbeEvidence):
            raise AssertionError(f"{self._scenario_id} has no validated probe evidence")
        return context.outcome

    def _variant_coverage(self, evidence: ProbeEvidence) -> bool:
        return evidence.variants_are_exact(self._contract.negative_variants)

    def _has_http(self, evidence: ProbeEvidence, *, method: str | None = None, path: str | None = None,
                  status: int | None = None, variant_id: str | None = None,
                  boundary: str | None = None) -> bool:
        for artifact in evidence.http_events(variant_id=variant_id):
            payload = artifact.payload
            if boundary is not None:
                aliases = {
                    "participant-http": {"participant-http", "actual-tool-http"},
                    "admin-http": {"admin-http", "private-admin-http"},
                }.get(boundary, {boundary})
                if artifact.boundary not in aliases:
                    continue
            request = payload.get("request")
            response = payload.get("response")
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue
            request_method = request.get("method")
            if method is not None and (
                not isinstance(request_method, str) or request_method.upper() != method.upper()
            ):
                continue
            if path is not None:
                observed_path = request.get("path")
                if not isinstance(observed_path, str) or not (
                    observed_path == path or observed_path.endswith(path)
                ):
                    continue
            if status is not None and response.get("status") != status:
                continue
            return True
        return False

    def _db_has_row(self, evidence: ProbeEvidence, predicate: Any, *, variant_id: str | None = None) -> bool:
        return any(predicate(row) for row in evidence.db_rows(variant_id=variant_id))

    def _rpc_has(self, evidence: ProbeEvidence, *, method: str, endpoint_boundary: str,
                 variant_id: str | None = None, predicate: Any | None = None) -> bool:
        for artifact in evidence.rpc_events(endpoint_boundary=endpoint_boundary, variant_id=variant_id):
            payload = artifact.payload
            if payload.get("method") != method:
                continue
            if predicate is None or predicate(payload):
                return True
        return False

    def _registered_http_operations(self, evidence: ProbeEvidence) -> tuple[dict[str, Any], ...]:
        return tuple(
            item.payload
            for item in evidence.http_artifacts()
            if item.boundary in {"participant-http", "actual-tool-http"}
            and isinstance(item.payload.get("request"), dict)
            and isinstance(item.payload.get("response"), dict)
        )

    def _success_receipt(self, evidence: ProbeEvidence, *, variant_id: str | None = None) -> bool:
        return self._rpc_has(
            evidence,
            method="eth_getTransactionReceipt",
            endpoint_boundary="local-chain-readonly-proxy",
            variant_id=variant_id,
            predicate=lambda item: _receipt_status(item.get("result")) == 1,
        )

    def _failed_receipt(self, evidence: ProbeEvidence, *, variant_id: str | None = None) -> bool:
        return self._rpc_has(
            evidence,
            method="eth_getTransactionReceipt",
            endpoint_boundary="local-chain-readonly-proxy",
            variant_id=variant_id,
            predicate=lambda item: _receipt_status(item.get("result")) == 0,
        )

    def _has_independent_db_evidence(self, evidence: ProbeEvidence) -> bool:
        database_artifacts = evidence.database_artifacts()
        return bool(database_artifacts) and all(
            item.payload.get("readOnly") is True
            and isinstance(item.payload.get("databaseRole"), str)
            and item.payload["databaseRole"].strip()
            and "admin" not in item.payload["databaseRole"].lower()
            and isinstance(item.payload.get("queryName"), str)
            and bool(item.payload["queryName"].strip())
            and isinstance(item.payload.get("rows"), list)
            for item in database_artifacts
        )

    def _has_source_reads(self, evidence: ProbeEvidence) -> bool:
        return bool(evidence.rpc_events(endpoint_boundary="source-readonly-proxy"))

    def _has_local_reads(self, evidence: ProbeEvidence) -> bool:
        return bool(evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"))

    def _execute_BEF_SC_001(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_001(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check("manifest_hash", _manifest_digest_valid(evidence))
        context.check("source_block_hash", _source_block_matches(evidence))
        context.check("local_identity", _local_identity_matches(evidence))
        context.check("contract_code_hashes", _contract_code_hashes_match(evidence))
        context.check(
            "compatibility_status",
            _x402_compatibility_matches(evidence)
            and _manifest_negative_variants_rejected(evidence)
            and self._variant_coverage(evidence),
        )
        context.check("manifest_enforced_vs_evaluated_rule_classification", _rule_classes_are_separate(evidence))

    def _execute_BEF_SC_002(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_002(self, context: ScenarioContext) -> None:
        from .bef_sc002_predicates import verify_sc002_strict

        evidence = self._evidence(context)
        strict = verify_sc002_strict(evidence)
        context.check("authenticated_scope", strict["authenticated_scope"])
        context.check("observed_reads", strict["observed_reads"])
        context.check("explicit_choices", strict["explicit_choices"])
        context.check("actual_selected_effect", strict["actual_selected_effect"])
        context.check("technical_steps_declared", strict["technical_steps_declared"])
        context.check("technically_valid_learning_mistake_executed", strict["technically_valid_learning_mistake_executed"])
        context.check("selected_parameters_not_repaired", strict["selected_parameters_not_repaired"])
        context.check("no_goal_based_rejection_or_corrective_reset", strict["no_goal_based_rejection_or_corrective_reset"])
        context.check("actual_effect_vs_task_criteria_recorded", strict["actual_effect_vs_task_criteria_recorded"])
        context.check("protocol_failure_not_silent_correction", strict["protocol_failure_not_silent_correction"])
        context.check("preexecution_variants_rejected", strict["preexecution_variants_rejected"])

    def _execute_BEF_SC_003(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_003(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check("scope_checked", _foreign_and_stale_requests_are_denied(evidence))
        context.check("admin_unreachable", _participant_admin_routes_are_denied(evidence))
        context.check("no_signature_or_transaction", _denials_have_no_sign_or_transaction(evidence))
        context.check("protected_state_unchanged", _denied_state_is_unchanged(evidence))
        context.check(
            "learning_mistake_policy_does_not_waive_isolation",
            _isolation_denials_stay_denied(evidence) and self._variant_coverage(evidence),
        )

    def _execute_BEF_SC_004(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_004(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check("offer_identity", _offer_identity_is_read_from_http(evidence))
        context.check("payment_requirements", _payment_requirements_match_manifest(evidence))
        context.check("no_token_delta", _inspection_has_no_token_delta(evidence))
        context.check("no_settlement", _inspection_has_no_settlement(evidence))
        context.check(
            "no_purchased_delivery",
            _inspection_has_no_delivery(evidence) and self._variant_coverage(evidence),
        )

    def _execute_BEF_SC_005(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_005(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check("scheme_asset_domain", _paid_request_matches_x402_requirements(evidence))
        context.check("verified_authorization", _facilitator_verified_authorization(evidence))
        context.check("local_receipt", self._success_receipt(evidence))
        context.check("token_effects", _purchase_token_effects_match_receipt(evidence))
        context.check("delivery_hash", _delivered_bytes_match_pinned_hash(evidence))
        context.check(
            "payer_identity",
            _payer_is_linked_to_receipt_and_database(evidence)
            and _x402_negative_variants_are_not_paid_success(evidence)
            and self._variant_coverage(evidence),
        )

    def _execute_BEF_SC_006(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_006(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check("invalid_payment_denied", _invalid_payment_variants_are_denied(evidence))
        context.check("original_identity_recovered", _duplicate_retries_keep_identity(evidence))
        context.check("one_settlement", _one_durable_settlement(evidence))
        context.check("one_logical_delivery", _one_durable_delivery(evidence))
        context.check(
            "unknown_not_success",
            _unknown_receipt_is_not_success(evidence) and self._variant_coverage(evidence),
        )

    def _execute_BEF_SC_007(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_007(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        from .bef_sc007_predicates import verify_sc007_strict

        strict = verify_sc007_strict(evidence)
        context.check("selected_contract_code", strict["selected_contract_code_hashes"])
        context.check(
            "receipt_events",
            strict["typed_http_db_tx_receipt_bindings"]
            and strict["raw_swap_events_transfers_and_recipient"]
            and strict["genuine_reverts_keep_receipts_and_gas"],
        )
        context.check("token_deltas", strict["typed_http_db_tx_receipt_bindings"] and strict["raw_before_after_rpc_state_bindings"])
        context.check("allowance", strict["allowance_reads_and_approval_events"] and strict["raw_before_after_rpc_state_bindings"])
        context.check("reserve", strict["actual_native_reserve_goal_mismatch"] and strict["raw_before_after_rpc_state_bindings"])
        context.check("representation_wrapping", strict["explicit_wrap_unwrap_and_native_weth_separation"])
        context.check(
            "executed_goal_mismatch_not_task_success",
            strict["actual_task_goal_output_mismatch"] and strict["selected_goal_inputs_not_repaired"],
        )
        context.check(
            "in_scope_wrong_recipient_or_reserve_effect_observed",
            strict["in_scope_wrong_recipient_executes"] and strict["actual_native_reserve_goal_mismatch"],
        )
        context.check(
            "boundary_denial_distinct_from_contract_revert",
            strict["security_denials_have_no_operation"]
            and strict["malformed_conversion_rejected_preexecution"]
            and strict["genuine_reverts_keep_receipts_and_gas"],
        )
        context.check(
            "distinct_native_eth_and_pinned_weth",
            strict["raw_before_after_rpc_state_bindings"]
            and strict["raw_local_chain_and_fork_identity_per_variant"],
        )
        context.check("explicit_wrap_unwrap_direction_and_amount", strict["explicit_wrap_unwrap_and_native_weth_separation"])
        context.check(
            "actual_wrap_and_unwrap_receipts",
            strict["explicit_wrap_unwrap_and_native_weth_separation"]
            and strict["genuine_reverts_keep_receipts_and_gas"],
        )
        context.check("no_automatic_conversion_by_swap_or_signer", strict["swaps_have_no_implicit_conversion"])
        context.check(
            "weth_not_counted_as_native_target_or_gas_reserve",
            strict["actual_native_reserve_goal_mismatch"] and strict["raw_before_after_rpc_state_bindings"],
        )
        context.check(
            "conversion_gas_attributed_once",
            strict["exact_variant_inventory"]
            and strict["typed_http_db_tx_receipt_bindings"]
            and strict["raw_before_after_rpc_state_bindings"]
            and strict["explicit_wrap_unwrap_and_native_weth_separation"],
        )

    def _execute_BEF_SC_008(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_008(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        from .bef_sc008_predicates import verify_sc008_strict

        strict = verify_sc008_strict(evidence)
        context.check(
            "successful_and_reverted_receipts",
            self._success_receipt(evidence) and self._failed_receipt(evidence)
            and strict["pinned_fee_and_raw_receipts"],
        )
        context.check("pinned_fee_fx", strict["pinned_fee_and_raw_receipts"])
        context.check("actual_payer", strict["actual_payer_roles"])
        context.check("no_double_count", strict["principal_and_service_separate"])
        context.check("no_fabricated_rejection_fee", strict["rejection_has_no_fee"])
        context.check("l1_unmodelled", strict["base_l1_unmodelled"] and strict["required_negative_inventory"])
        context.check("required_variant_inventory", strict["required_negative_inventory"])
        context.check("readonly_observer_role", strict["readonly_observer_role"])
        context.check("missing_receipt_is_unknown", strict["missing_receipt_is_unknown"])
        context.check("strict_cost_gate_complete", strict["complete"])

    def _execute_BEF_SC_009(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_009(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        from .bef_sc009010_resource_adapter import evaluate_sc009010

        strict = evaluate_sc009010(evidence, "BEF-SC-009")
        context.check("independent_chain_state", strict["independent_chain_state"])
        context.check("independent_service_state", strict["independent_service_state"])
        context.check("reset_not_crossing_boundary", strict["reset_not_crossing_boundary"])
        context.check("foreign_access_denied", strict["foreign_access_denied"])

    def _execute_BEF_SC_010(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_010(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        from .bef_sc009010_resource_adapter import evaluate_sc009010

        strict = evaluate_sc009010(evidence, "BEF-SC-010")
        context.check("stale_generation_fenced", strict["stale_generation_fenced"])
        context.check("chain_baseline", strict["chain_baseline"])
        context.check("service_baseline", strict["service_baseline"])
        context.check("fixture_hash", strict["fixture_hash"])
        context.check("equivalent_probe_outcome", strict["equivalent_probe_outcome"])

    def _execute_BEF_SC_011(self, context: ScenarioContext) -> None:
        self._capture011(context)

    def _verify_BEF_SC_011(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        predicates = sc011_resource_evidence.validate_sc011_resource_evidence(evidence)
        context.check("host_and_limits", predicates["host_and_limits"] and predicates["source_identity"])
        context.check("cold_warm_state", predicates["cold_warm_state"])
        context.check("cpu_peak_ram_elapsed", predicates["cpu_peak_ram_elapsed"])
        context.check("cache_artifact_bytes", predicates["cache_artifact_bytes"])
        context.check("source_request_count", predicates["source_request_count"] and predicates["operation_inventory"])
        context.check("guardrail_stop", predicates["guardrail_stop"])
        context.check("cu_unknown_if_unobservable", predicates["cu_unknown_if_unobservable"] and predicates["variant_inventory"])

    def _execute_BEF_SC_012(self, context: ScenarioContext) -> None:
        self._capture(context)

    def _verify_BEF_SC_012(self, context: ScenarioContext) -> None:
        evidence = self._evidence(context)
        context.check(
            "source_chain_block_code",
            _source_block_matches(evidence)
            and _contract_code_hashes_match(evidence)
            and _sc012_required_source_reads_are_bound(evidence),
        )
        context.check("allowed_read_provenance", _source_reads_are_allowlisted(evidence))
        context.check("prohibited_not_forwarded", _prohibited_source_methods_are_not_forwarded(evidence))
        context.check("evidence_paths_hashes", _all_evidence_paths_are_verified(evidence))
        context.check("replay_no_broadcast", _replay_is_read_only(evidence, self._repository_root))
        context.check(
            "secrets_absent",
            _all_artifacts_are_redacted(evidence)
            and _synthetic_validation_faults_are_rejected(evidence)
            and self._variant_coverage(evidence),
        )


def _decode_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceInvalid(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise EvidenceInvalid(f"{label} root must be an object")
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX_32_RE.fullmatch(value))


def _nonempty(value: Any) -> bool:
    return isinstance(value, (str, int)) and not isinstance(value, bool) and bool(str(value).strip())


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolve_manifest_path(repository_root: Path, evidence_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise EvidenceInvalid("runtime manifest path must stay inside the evidence directory")
    resolved = (evidence_root / candidate).resolve(strict=True)
    if not _is_relative_to(resolved, evidence_root) or not resolved.is_file():
        raise EvidenceInvalid("runtime manifest path escapes the evidence directory")
    return resolved


def _sensitive_value_is_redacted(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return value.strip().lower() in {item.lower() for item in _REDACTED_VALUES} or value.strip().upper() == "[REDACTED]"


def _reject_secrets(value: Any, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            sensitive_key = (
                normalized_key in _SENSITIVE_NAMES
                or any(part in normalized_key for part in (
                    "privatekey", "seedphrase", "mnemonic", "password", "secret", "authorization",
                    "bearer", "runtoken", "adminkey", "accesstoken", "authtoken", "apitoken",
                    "paymentsignature", "rawsignature", "credential", "databaseurl", "rpcurl", "sourceurl",
                ))
            )
            safe_metadata = (
                normalized_key in {
                    "authorizationpresent", "proxyauthorizationpresent", "paymentsignaturepresent",
                    "xpaymentsignaturepresent", "xbefadminkeypresent", "xbefservicekeypresent",
                }
                and isinstance(child, bool)
            ) or (
                normalized_key == "requireruntokenandgeneration"
                and isinstance(child, bool)
            ) or (
                normalized_key in {"authorizationsha256", "paymentsignaturesha256", "xpaymentsignaturesha256"}
                and _is_digest(child)
            ) or (
                normalized_key == "rpcurlenv"
                and isinstance(child, str)
                and bool(re.fullmatch(r"[A-Z][A-Z0-9_]*_URL", child))
            )
            if sensitive_key and not safe_metadata and not _sensitive_value_is_redacted(child):
                raise EvidenceInvalid(f"{label} contains an unredacted sensitive field")
            _reject_secrets(child, label)
    elif isinstance(value, list):
        for child in value:
            _reject_secrets(child, label)
    elif isinstance(value, str):
        if _BEARER_RE.search(value) or _URL_SECRET_RE.search(value):
            raise EvidenceInvalid(f"{label} contains an unredacted credential-like value")
        if re.search(r"(?i)\b(?:0x)?[0-9a-f]{64}\b", value) and any(
            token in value.lower() for token in ("private key", "seed phrase", "mnemonic", "secret")
        ):
            raise EvidenceInvalid(f"{label} contains likely key material")


def _receipt_status(value: Any) -> int | None:
    if isinstance(value, dict) and isinstance(value.get("result"), dict):
        value = value["result"]
    if not isinstance(value, dict):
        return None
    status = value.get("status")
    if isinstance(status, int) and status in {0, 1}:
        return status
    if isinstance(status, str) and status.lower() in {"0x0", "0x00", "0x1", "0x01"}:
        return int(status, 16)
    return None


def _hex_or_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return None
    return None


def _rpc_result(payload: dict[str, Any]) -> Any:
    result = payload.get("result")
    if isinstance(result, dict) and "result" in result:
        return result.get("result")
    return result


def _requested_block_matches(payload: dict[str, Any], expected: Any) -> bool:
    requested = payload.get("requestedBlock")
    if requested is None:
        params = payload.get("params")
        if isinstance(params, list) and params:
            first = params[0]
            requested = first.get("blockNumber") if isinstance(first, dict) else first
    return isinstance(expected, str) and isinstance(requested, str) and requested.lower() == expected.lower()


def _block_hash_from_result(value: Any) -> str | None:
    return value.get("hash", "").lower() if isinstance(value, dict) and isinstance(value.get("hash"), str) else None


def _keccak256(data: bytes) -> bytes:
    """Small legacy Keccak-256 implementation (Ethereum, not standardized SHA3)."""

    rotation = (
        (0, 36, 3, 41, 18),
        (1, 44, 10, 45, 2),
        (62, 6, 43, 15, 61),
        (28, 55, 25, 21, 56),
        (27, 20, 39, 8, 14),
    )
    round_constants = (
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    )
    mask = (1 << 64) - 1
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((136 - (len(padded) % 136)) % 136))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        block = padded[offset : offset + 136]
        for lane in range(17):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        for constant in round_constants:
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & mask) for x in range(5)]
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] ^= d[x]
            b = [0] * 25
            for y in range(5):
                for x in range(5):
                    value = state[x + 5 * y]
                    shift = rotation[x][y]
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = ((value << shift) | (value >> ((64 - shift) % 64))) & mask
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
            state[0] ^= constant
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def _probe_timeout_seconds(manifest_path: Path, scenario_id: str | None = None) -> int:
    """Bound the probe by its declared scenario cap plus startup/teardown time."""

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        guardrails = manifest.get("guardrails") if isinstance(manifest, dict) else None
        trial_seconds = guardrails.get("maxTrialSeconds") if isinstance(guardrails, dict) else None
        if scenario_id == "BEF-SC-007" and isinstance(guardrails, dict):
            trial_seconds = guardrails.get("maxSwapScenarioSeconds")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        trial_seconds = None
    if (
        isinstance(trial_seconds, int)
        and not isinstance(trial_seconds, bool)
        and 1 <= trial_seconds <= MAX_DECLARED_TRIAL_SECONDS
    ):
        return trial_seconds + PROBE_SETUP_MARGIN_SECONDS
    # Missing or malformed manifest is a runtime prerequisite/configuration
    # failure. Keep its diagnostic probe bounded even though no trial limit can
    # be trusted or derived from that file.
    return PROBE_FALLBACK_TIMEOUT_SECONDS


def _run_probe_command(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout_seconds: int
) -> subprocess.CompletedProcess[str]:
    """Run only this adapter-owned process tree and stop it when its trial ends."""

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as timeout_error:
        if os.name == "nt":
            # taskkill is scoped to the process tree rooted at the exact PID
            # started above; it does not search for or stop unrelated services.
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.communicate()
        # Do not expose stdout/stderr: runtime tools can include sensitive
        # request diagnostics there even when their evidence writer redacts.
        raise subprocess.TimeoutExpired(command, timeout_seconds) from timeout_error
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _manifest(evidence: ProbeEvidence, key: str) -> dict[str, Any]:
    value = evidence.manifest.get(key)
    return value if isinstance(value, dict) else {}


def _manifest_digest_valid(evidence: ProbeEvidence) -> bool:
    manifest_ref = evidence.index.get("manifest")
    return (
        evidence.manifest.get("schemaVersion") == "bef-runtime-manifest/v1"
        and evidence.manifest.get("change") == CHANGE_NAME
        and _is_digest(evidence.manifest_sha256)
        and isinstance(manifest_ref, dict)
        and manifest_ref.get("sha256") == evidence.manifest_sha256
    )


def _source_block_matches(evidence: ProbeEvidence) -> bool:
    source = _manifest(evidence, "source")
    recorded = evidence.index.get("sourceBlock")
    number = source.get("blockNumber")
    block_hash = source.get("blockHash")
    if not isinstance(recorded, dict) or not isinstance(number, str) or not _is_digest(block_hash):
        return False
    if str(recorded.get("number", "")).lower() != number.lower() or str(recorded.get("hash", "")).lower() != block_hash.lower():
        return False
    chain_read = any(
        item.payload.get("method") == "eth_chainId"
        and _hex_or_int(_rpc_result(item.payload)) == source.get("chainId")
        for item in evidence.rpc_events(endpoint_boundary="source-readonly-proxy")
    )
    block_read = any(
        item.payload.get("method") == "eth_getBlockByNumber"
        and _requested_block_matches(item.payload, number)
        and _block_hash_from_result(_rpc_result(item.payload)) == block_hash.lower()
        for item in evidence.rpc_events(endpoint_boundary="source-readonly-proxy")
    )
    return chain_read and block_read


def _local_identity_matches(evidence: ProbeEvidence) -> bool:
    local = _manifest(evidence, "local")
    source = _manifest(evidence, "source")
    if local.get("identity") != "private-anvil-fork" or local.get("chainId") != 8453:
        return False
    if not isinstance(local.get("forkBlock"), str) or local["forkBlock"].lower() != str(source.get("blockNumber", "")).lower():
        return False
    observed_chain = any(
        _hex_or_int(_rpc_result(item.payload)) == local.get("chainId")
        for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
        if item.payload.get("method") == "eth_chainId"
    )
    observed_fork = any(
        _requested_block_matches(item.payload, local.get("forkBlock"))
        and _block_hash_from_result(_rpc_result(item.payload)) == str(source.get("blockHash", "")).lower()
        for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
        if item.payload.get("method") == "eth_getBlockByNumber"
    )
    return observed_chain and observed_fork


def _contract_code_hashes_match(evidence: ProbeEvidence) -> bool:
    contracts = _manifest(evidence, "contracts")
    expected: dict[str, str] = {}
    for name, field in (
        ("usdc", "proxyCodeHash"), ("weth", "codeHash"), ("factory", "codeHash"),
        ("swapRouter02", "codeHash"), ("quoterV2", "codeHash"), ("pool", "codeHash"),
    ):
        descriptor = contracts.get(name)
        if isinstance(descriptor, dict):
            address = descriptor.get("address")
            digest = descriptor.get(field)
            if isinstance(address, str) and _is_digest(digest):
                expected[address.lower()] = digest.lower().removeprefix("0x")
    implementation = contracts.get("usdc", {})
    if isinstance(implementation, dict):
        address = implementation.get("implementation")
        digest = implementation.get("implementationCodeHash")
        if isinstance(address, str) and _is_digest(digest):
            expected[address.lower()] = digest.lower().removeprefix("0x")
    observed: dict[str, set[str]] = {}
    source_block = _manifest(evidence, "source").get("blockNumber")
    for artifact in evidence.rpc_events(endpoint_boundary="source-readonly-proxy"):
        payload = artifact.payload
        if payload.get("method") != "eth_getCode":
            continue
        if not _requested_block_matches(payload, source_block):
            continue
        params = payload.get("params")
        address = params[0].lower() if isinstance(params, list) and params and isinstance(params[0], str) else None
        code = _rpc_result(payload)
        if address is None or not isinstance(code, str) or not _HEX_RE.fullmatch(code):
            continue
        observed.setdefault(address, set()).add(_keccak256(bytes.fromhex(code[2:])).hex())
    return bool(expected) and all(address in observed and digest in observed[address] for address, digest in expected.items())


def _x402_compatibility_matches(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    contracts = _manifest(evidence, "contracts")
    usdc = contracts.get("usdc", {})
    local = _manifest(evidence, "local")
    expected_versions = local.get("versions") if isinstance(local.get("versions"), dict) else {}
    observed_versions = evidence.index.get("runtimeVersions", {})
    runtime_versions_match = (
        isinstance(observed_versions, dict)
        and isinstance(expected_versions, dict)
        and all(
            observed_versions.get(key) == expected_versions.get(manifest_key)
            for key, manifest_key in (
                ("x402Core", "x402Core"),
                ("x402Evm", "x402Evm"),
                ("x402Fastify", "x402Fastify"),
            )
            if _nonempty(expected_versions.get(manifest_key))
        )
        and all(_nonempty(expected_versions.get(name)) for name in ("x402Core", "x402Evm", "x402Fastify"))
        and _nonempty(_version_text(local.get("nodeVersion")))
        and all(
            _version_text(observed_versions.get(name)) == _version_text(local.get("nodeVersion"))
            for name in ("apiNode", "facilitatorNode")
        )
    )
    declared_identity_matches = (
        x402.get("sdk") == "@x402" and x402.get("scheme") == "exact"
        and x402.get("assetTransferMethod") == "eip3009" and x402.get("network") == "eip155:8453"
        and x402.get("version") == expected_versions.get("x402Core")
        and isinstance(usdc, dict) and str(x402.get("asset", "")).lower() == str(usdc.get("address", "")).lower()
        and isinstance(x402.get("amount"), str) and x402["amount"].isdigit()
        and _nonempty(x402.get("resourceId")) and _is_digest(x402.get("resourceSha256"))
    )
    # Manifest and version strings alone are declarations. Require the real
    # HTTP challenge, facilitator verification, and exact receipt/DB effects
    # before treating the installed x402 path as compatible.
    return bool(
        declared_identity_matches
        and runtime_versions_match
        and _payment_requirements_match_manifest(evidence)
        and _facilitator_verified_authorization(evidence)
        and _purchase_token_effects_match_receipt(evidence)
    )


def _version_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return value.removeprefix("v").strip()


def _manifest_negative_variants_rejected(evidence: ProbeEvidence) -> bool:
    """Recompute SC001 invalid-prerequisite decisions from bound observations."""

    source = _manifest(evidence, "source")
    local = _manifest(evidence, "local")
    x402 = _manifest(evidence, "x402")
    contracts = _manifest(evidence, "contracts")
    expected_block = source.get("blockNumber")
    expected_block_hash = source.get("blockHash")
    expected_chain = source.get("chainId")
    expected_asset = _address(x402.get("asset"))
    expected_scheme = x402.get("scheme")
    usdc = contracts.get("usdc", {})
    expected_proxy_code_hash = usdc.get("proxyCodeHash") if isinstance(usdc, dict) else None
    if (
        not isinstance(expected_block, str)
        or not _is_digest(expected_block_hash)
        or not isinstance(expected_chain, int)
        or isinstance(expected_chain, bool)
        or not isinstance(local.get("chainId"), int)
        or isinstance(local.get("chainId"), bool)
        or not isinstance(local.get("forkBlock"), str)
        or expected_asset is None
        or not _nonempty(expected_scheme)
        or not _is_digest(expected_proxy_code_hash)
    ):
        return False

    reasons = {
        "wrong_block": "source_block_mismatch",
        "wrong_chain": "source_chain_mismatch",
        "missing_code": "required_code_missing",
        "per_trial_latest": "latest_block_disallowed",
    }

    for variant in ("wrong_block", "wrong_chain", "missing_code", "unsupported_asset_scheme", "per_trial_latest"):
        records = _variant_http(evidence, variant)
        if not records:
            return False
        if variant == "unsupported_asset_scheme":
            rejected = [
                (artifact, request, response)
                for artifact, request, response in records
                if artifact.boundary == "facilitator-http"
                and request.get("method") == "POST"
                and _path_matches(request, "/verify")
                and _response_status(response) == 400
                and _response_body(response).get("error") == "unsupported_payment_requirements"
                and _response_body(response).get("reasonCode") == "unsupported_asset_scheme"
            ]
            if len(rejected) != 1:
                return False
            _, request, _ = rejected[0]
            request_body = _body_object(request.get("body"))
            payment_requirements = request_body.get("paymentRequirements")
            if not _actual_unsupported_payment_requirements(payment_requirements, expected_scheme, expected_asset):
                return False
            if not _variant_pinned_identity_is_unchanged(evidence, variant):
                return False
        else:
            rejected = [
                (artifact, request, response)
                for artifact, request, response in records
                if artifact.boundary == "private-admin-http"
                and request.get("method") == "POST"
                and _path_matches(request, "/prerequisite-validations")
                and _response_status(response) == 200
            ]
            if len(rejected) != 1:
                return False
            artifact, request, response = rejected[0]
            request_body = _body_object(request.get("body"))
            candidate = request_body.get("candidate")
            body = _response_body(response)
            if (
                request_body.get("variantId") != variant
                or body.get("variantId") != variant
                or body.get("envId") != evidence.environment_id
                or body.get("accepted") is not False
                or body.get("manifestSha256") != evidence.manifest_sha256
                or str(body.get("applicationSourceSha256", "")).lower()
                != str(evidence.index.get("applicationSourceSha256", "")).lower()
                or not _nonempty(body.get("boundary"))
                or not isinstance(candidate, dict)
                or body.get("candidate") != candidate
                or body.get("reasonCode") != reasons.get(variant)
                or not _preflight_observed_identity_matches(body, source, local)
            ):
                return False

            if variant == "wrong_block":
                number = candidate.get("blockNumber")
                block_hash = candidate.get("blockHash")
                bad_input_seen = (
                    isinstance(number, str)
                    and number.lower().startswith("0x")
                    and _hex_or_int(number) is not None
                    and number.lower() != expected_block.lower()
                    and _is_digest(block_hash)
                    and str(block_hash).lower() != str(expected_block_hash).lower()
                    and _preflight_observation_matches(
                        body, "source", "block", "eth_getBlockByNumber", [expected_block, False],
                        lambda result: isinstance(result, dict)
                        and str(result.get("number", "")).lower() == expected_block.lower()
                        and str(result.get("hash", "")).lower() == str(expected_block_hash).lower(),
                    )
                )
            elif variant == "wrong_chain":
                candidate_chain = _hex_or_int(candidate.get("chainId"))
                bad_input_seen = (
                    candidate_chain is not None
                    and candidate_chain != expected_chain
                    and _preflight_observation_matches(
                        body, "source", "chainId", "eth_chainId", [],
                        lambda result: _hex_or_int(result) == expected_chain,
                    )
                )
            elif variant == "missing_code":
                address = _address(candidate.get("contractAddress"))
                bad_input_seen = (
                    address == "0x" + "0" * 40
                    and str(candidate.get("codeHash", "")).lower() == str(expected_proxy_code_hash).lower()
                    and _preflight_observation_matches(
                        body, "source", "code", "eth_getCode", [address, expected_block],
                        lambda result: result == "0x",
                    )
                    and _variant_missing_code_rpc_matches(evidence, variant, address, expected_block)
                )
            else:  # per_trial_latest
                bad_input_seen = (
                    candidate.get("requestedBlock") == "latest"
                    and body.get("requestedBlock") == "latest"
                    and body.get("forwarded") is False
                    and _preflight_observation_matches(
                        body, "source", "block", "eth_getBlockByNumber", [expected_block, False],
                        lambda result: isinstance(result, dict)
                        and str(result.get("number", "")).lower() == expected_block.lower()
                        and str(result.get("hash", "")).lower() == str(expected_block_hash).lower(),
                    )
                )
            if not bad_input_seen:
                return False
            if not _variant_pinned_identity_is_unchanged(evidence, variant):
                return False

        if not _variant_database_state_is_unchanged(evidence, variant):
            return False
        if any(
            artifact.payload.get("variantId") == variant
            and artifact.payload.get("method") == "eth_getTransactionReceipt"
            and _receipt_status(_rpc_result(artifact.payload)) == 1
            for artifact in evidence.rpc_artifacts(endpoint_boundary="local-chain-readonly-proxy")
        ):
            return False
        if any(
            artifact.payload.get("variantId") == variant
            and artifact.payload.get("method") in {"eth_sendRawTransaction", "eth_sendTransaction"}
            for artifact in evidence.rpc_artifacts()
        ):
            return False

        if variant == "unsupported_asset_scheme":
            continue
        if any(
            artifact.payload.get("variantId") == variant
            and artifact.boundary in {"private-admin-http", "admin-http"}
            and _path_matches(request, "/generations")
            and _successful_http(response)
            for artifact, request, response in _http_records(evidence)
        ):
            return False

    return _observer_role_is_read_only(evidence)


def _actual_unsupported_payment_requirements(value: Any, expected_scheme: Any, expected_asset: str) -> bool:
    requirements = _body_object(value)
    scheme = requirements.get("scheme")
    asset = _address(requirements.get("asset"))
    return (
        isinstance(scheme, str)
        and bool(scheme.strip())
        and (scheme != expected_scheme or (asset is not None and asset != expected_asset))
        and (asset is not None or scheme != expected_scheme)
    )


def _preflight_observation_matches(
    body: dict[str, Any],
    endpoint: str,
    observation_name: str,
    method: str,
    params: list[Any],
    result_matches: Any,
) -> bool:
    observations = body.get("observations")
    endpoint_observations = observations.get(endpoint) if isinstance(observations, dict) else None
    read = endpoint_observations.get(observation_name) if isinstance(endpoint_observations, dict) else None
    return (
        isinstance(read, dict)
        and read.get("method") == method
        and read.get("params") == params
        and result_matches(read.get("result"))
    )


def _preflight_observed_identity_matches(body: dict[str, Any], source: dict[str, Any], local: dict[str, Any]) -> bool:
    source_chain = source.get("chainId")
    source_block = source.get("blockNumber")
    source_hash = source.get("blockHash")
    local_chain = local.get("chainId")
    local_block = local.get("forkBlock")
    if not isinstance(source_chain, int) or not isinstance(source_block, str) or not _is_digest(source_hash):
        return False
    if not isinstance(local_chain, int) or not isinstance(local_block, str):
        return False
    return (
        _preflight_observation_matches(
            body, "source", "chainId", "eth_chainId", [], lambda result: _hex_or_int(result) == source_chain
        )
        and _preflight_observation_matches(
            body, "source", "block", "eth_getBlockByNumber", [source_block, False],
            lambda result: isinstance(result, dict)
            and str(result.get("number", "")).lower() == source_block.lower()
            and str(result.get("hash", "")).lower() == str(source_hash).lower(),
        )
        and _preflight_observation_matches(
            body, "local", "chainId", "eth_chainId", [], lambda result: _hex_or_int(result) == local_chain
        )
        and _preflight_observation_matches(
            body, "local", "block", "eth_getBlockByNumber", [local_block, False],
            lambda result: isinstance(result, dict)
            and str(result.get("number", "")).lower() == local_block.lower()
            and str(result.get("hash", "")).lower() == str(source_hash).lower(),
        )
    )


def _variant_missing_code_rpc_matches(evidence: ProbeEvidence, variant: str, address: str, block: str) -> bool:
    matches = [
        artifact for artifact in evidence.rpc_artifacts(endpoint_boundary="source-readonly-proxy")
        if artifact.payload.get("variantId") == variant
        and artifact.payload.get("method") == "eth_getCode"
        and isinstance(artifact.payload.get("params"), list)
        and len(artifact.payload["params"]) >= 2
        and str(artifact.payload["params"][0]).lower() == address.lower()
        and _requested_block_matches(artifact.payload, block)
        and _rpc_result(artifact.payload) == "0x"
    ]
    return len(matches) == 1


def _variant_database_state_is_unchanged(evidence: ProbeEvidence, variant: str) -> bool:
    query_names = (
        "generation-by-id",
        "operations-by-generation",
        "payments-by-operation",
        "deliveries-by-operation",
        "denials-by-generation",
        "x402-observations-by-operation",
    )
    artifacts = evidence.database_artifacts()
    roles: set[str] = set()
    for query_name in query_names:
        phases: dict[str, list[EvidenceArtifact]] = {"before": [], "after": []}
        for artifact in artifacts:
            payload = artifact.payload
            if payload.get("variantId") != variant or payload.get("queryName") != query_name:
                continue
            if payload.get("readOnly") is not True or not _nonempty(payload.get("databaseRole")):
                return False
            role = str(payload["databaseRole"])
            if "admin" in role.lower() or "superuser" in role.lower():
                return False
            roles.add(role)
            path = artifact.relative_path.lower()
            phase = "before" if "before" in path else "after" if "after" in path else None
            if phase is not None:
                phases[phase].append(artifact)
        if len(phases["before"]) != 1 or len(phases["after"]) != 1:
            return False
        before = phases["before"][0].payload.get("rows")
        after = phases["after"][0].payload.get("rows")
        if not isinstance(before, list) or not isinstance(after, list) or before != after:
            return False
        if query_name == "generation-by-id":
            if len(before) != 1 or not _contains_value(
                before[0], {"generationId", "generation_id"}, evidence.generation_id
            ) or not _contains_value(before[0], {"envId", "env_id"}, evidence.environment_id):
                return False
    return len(roles) == 1


def _observer_role_is_read_only(evidence: ProbeEvidence) -> bool:
    proofs = [
        artifact.payload for artifact in evidence.database_artifacts()
        if artifact.payload.get("queryName") == "observer-role-effective-privileges"
        and artifact.payload.get("readOnly") is True
    ]
    if len(proofs) != 1:
        return False
    proof = proofs[0]
    role = proof.get("role")
    rows = proof.get("rows")
    if not isinstance(role, dict) or not isinstance(rows, list) or not rows:
        return False
    forbidden_role_flags = (
        "is_superuser", "can_create_db", "can_create_role", "can_replicate", "can_bypass_rls",
        "can_create_in_schema", "can_create_in_database",
    )
    if any(role.get(flag) is not False for flag in forbidden_role_flags):
        return False
    return all(
        row.get("can_select") is True
        and all(row.get(flag) is False for flag in (
            "can_insert", "can_update", "can_delete", "can_truncate", "can_references", "can_trigger"
        ))
        for row in rows if isinstance(row, dict)
    ) and all(isinstance(row, dict) for row in rows)


def _has_mismatching_block(request: dict[str, Any], expected: Any) -> bool:
    if not isinstance(expected, str):
        return False
    return any(
        isinstance(value, str) and value.lower() not in {expected.lower(), "latest"}
        for value in _nested_values(request, {"blockNumber", "forkBlock", "sourceBlock"})
    )


def _has_latest_block(request: dict[str, Any]) -> bool:
    return any(
        isinstance(value, str) and value.lower() == "latest"
        for value in _nested_values(request, {"blockNumber", "forkBlock", "sourceBlock", "blockTag"})
    )


def _requested_block_is_latest(payload: dict[str, Any]) -> bool:
    if str(payload.get("requestedBlock", "")).lower() == "latest":
        return True
    params = payload.get("params")
    return isinstance(params, list) and any(isinstance(value, str) and value.lower() == "latest" for value in params)


def _has_mismatching_chain(request: dict[str, Any], expected: Any) -> bool:
    if not isinstance(expected, int) or isinstance(expected, bool):
        return False
    chain_ids = _nested_values(request, {"chainId"})
    networks = _nested_values(request, {"network"})
    return any(_hex_or_int(value) not in {expected, None} for value in chain_ids) or any(
        isinstance(value, str) and value.lower() != f"eip155:{expected}".lower()
        for value in networks
    )


def _variant_pinned_identity_is_unchanged(evidence: ProbeEvidence, variant: str) -> bool:
    source = _manifest(evidence, "source")
    local = _manifest(evidence, "local")
    expected = {
        "source-readonly-proxy": (source.get("chainId"), source.get("blockNumber"), source.get("blockHash")),
        "local-chain-readonly-proxy": (local.get("chainId"), local.get("forkBlock"), source.get("blockHash")),
    }
    for boundary, (chain_id, block_number, block_hash) in expected.items():
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not isinstance(block_number, str) or not _is_digest(block_hash):
            return False
        for phase in ("before", "after"):
            chain_reads = [
                artifact for artifact in evidence.rpc_artifacts(endpoint_boundary=boundary)
                if artifact.payload.get("variantId") == variant
                and artifact.payload.get("method") == "eth_chainId"
                and phase in artifact.relative_path.lower()
                and _hex_or_int(_rpc_result(artifact.payload)) == chain_id
                and artifact.payload.get("forwarded") is not False
            ]
            block_reads = [
                artifact for artifact in evidence.rpc_artifacts(endpoint_boundary=boundary)
                if artifact.payload.get("variantId") == variant
                and artifact.payload.get("method") == "eth_getBlockByNumber"
                and phase in artifact.relative_path.lower()
                and _requested_block_matches(artifact.payload, block_number)
                and _block_hash_from_result(_rpc_result(artifact.payload)) == block_hash.lower()
                and artifact.payload.get("forwarded") is not False
            ]
            if len(chain_reads) != 1 or len(block_reads) != 1:
                return False
    return True


def _rule_classes_are_separate(evidence: ProbeEvidence) -> bool:
    rules = _manifest(evidence, "ruleClassification")
    enforced, evaluated = rules.get("alwaysEnforced"), rules.get("taskEvaluation")
    return (
        isinstance(enforced, list) and isinstance(evaluated, list)
        and len(enforced) >= 9 and len(evaluated) >= 6
        and len(set(enforced)) == len(enforced) and len(set(evaluated)) == len(evaluated)
        and not (set(enforced) & set(evaluated)) and bool(_manifest(evidence, "taskGoal"))
    )


def _http_records(evidence: ProbeEvidence) -> tuple[tuple[EvidenceArtifact, dict[str, Any], dict[str, Any]], ...]:
    records = []
    for artifact in evidence.http_artifacts():
        payload = artifact.payload
        request, response = payload.get("request"), payload.get("response")
        if isinstance(request, dict) and isinstance(response, dict):
            records.append((artifact, request, response))
    return tuple(records)


def _body_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _response_body(response: dict[str, Any]) -> dict[str, Any]:
    return _body_object(response.get("body"))


def _headers(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key).lower(): child for key, child in value.items()}


def _path_matches(request: dict[str, Any], fragment: str) -> bool:
    path = request.get("path")
    return isinstance(path, str) and fragment.lower() in path.lower()


def _response_status(response: dict[str, Any]) -> int | None:
    value = response.get("status")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _successful_http(response: dict[str, Any]) -> bool:
    status = _response_status(response)
    return status is not None and 200 <= status < 300


def _denied_http(response: dict[str, Any]) -> bool:
    return _response_status(response) in {400, 401, 403, 404, 405, 409, 413, 422, 429}


def _iter_values(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_values(child)


def _nested_values(value: Any, names: set[str]) -> list[Any]:
    found = []
    normalized_names = {re.sub(r"[^a-z0-9]", "", name.lower()) for name in names}
    for item in _iter_values(value):
        if isinstance(item, dict):
            for key, child in item.items():
                if re.sub(r"[^a-z0-9]", "", str(key).lower()) in normalized_names:
                    found.append(child)
    return found


def _contains_value(value: Any, names: set[str], expected: Any) -> bool:
    for child in _nested_values(value, names):
        if isinstance(child, bool) or isinstance(expected, bool):
            if type(child) is type(expected) and child is expected:
                return True
            continue
        if isinstance(child, str) and isinstance(expected, str):
            if child.lower() == expected.lower():
                return True
        if child == expected:
            return True
        left, right = _numeric(child), _numeric(expected)
        if left is not None and right is not None:
            try:
                if Decimal(str(left)) == Decimal(str(right)):
                    return True
            except InvalidOperation:
                pass
    return False


def _numeric(value: Any) -> int | float | Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    if isinstance(value, str):
        try:
            if value.lower().startswith("0x"):
                return int(value, 16)
            if re.fullmatch(r"[+-]?\d+", value.strip()):
                return int(value)
            parsed = Decimal(value)
            return parsed if parsed.is_finite() else None
        except (ValueError, InvalidOperation):
            return None
    return None


def _db_artifacts(evidence: ProbeEvidence, query_fragments: tuple[str, ...] = ()) -> tuple[EvidenceArtifact, ...]:
    fragments = tuple(fragment.lower() for fragment in query_fragments)
    return tuple(
        artifact
        for artifact in evidence.database_artifacts()
        if artifact.payload.get("readOnly") is True
        and isinstance(artifact.payload.get("databaseRole"), str)
        and "admin" not in artifact.payload["databaseRole"].lower()
        and isinstance(artifact.payload.get("queryName"), str)
        and (not fragments or any(fragment in artifact.payload["queryName"].lower() for fragment in fragments))
    )


def _db_rows_with_source(
    evidence: ProbeEvidence,
    query_fragments: tuple[str, ...] = (),
    variant_id: str | None = None,
) -> tuple[tuple[EvidenceArtifact, dict[str, Any]], ...]:
    result = []
    for artifact in _db_artifacts(evidence, query_fragments):
        payload = artifact.payload
        if variant_id is not None and payload.get("variantId") != variant_id:
            continue
        rows = payload.get("rows")
        if isinstance(rows, list):
            result.extend((artifact, row) for row in rows if isinstance(row, dict))
    return tuple(result)


def _bound_database_rows(
    evidence: ProbeEvidence, query_name: str, operation_id: str, variant_id: str | None
) -> tuple[dict[str, Any], ...]:
    result = []
    for artifact in _db_artifacts(evidence):
        payload = artifact.payload
        if (
            payload.get("queryName") != query_name
            or payload.get("operationId") != operation_id
            or payload.get("variantId") != variant_id
        ):
            continue
        rows = payload.get("rows")
        if isinstance(rows, list):
            result.extend(row for row in rows if isinstance(row, dict))
    return tuple(result)


def _payer_for_database_operation(
    evidence: ProbeEvidence, operation_id: str, variant_id: str | None
) -> str | None:
    """Resolve payer only through the independent operation -> generation DB join."""
    generation_id = _generation_for_database_operation(evidence, operation_id, variant_id)
    if generation_id is None:
        return None
    generation_rows = _bound_database_rows(evidence, "generation-by-id", operation_id, variant_id)
    payers = {
        address
        for row in generation_rows
        if row.get("generation_id") == generation_id
        for address in [_address(row.get("payer_address"))]
        if address is not None
    }
    return next(iter(payers)) if len(payers) == 1 else None


def _generation_for_database_operation(
    evidence: ProbeEvidence, operation_id: str, variant_id: str | None
) -> str | None:
    """Resolve exactly one generation from the independent operation DB row."""
    operation_rows = _bound_database_rows(evidence, "operation-by-id", operation_id, variant_id)
    generation_ids = {
        value
        for row in operation_rows
        if row.get("operation_id") == operation_id
        for value in [row.get("generation_id")]
        if isinstance(value, str) and value
    }
    return next(iter(generation_ids)) if len(generation_ids) == 1 else None


def _x402_verify_observation_matches(
    evidence: ProbeEvidence,
    operation_id: str,
    variant_id: str | None,
    payer: str,
    challenge: dict[str, Any],
) -> bool:
    generation_id = _generation_for_database_operation(evidence, operation_id, variant_id)
    if generation_id is None or _payer_for_database_operation(evidence, operation_id, variant_id) != payer:
        return False

    # The participant-side primary observation is indexed with variantId=null,
    # while the runtime persists canonical x402 rows as variant_id="baseline".
    # Allow that one storage label only for a primary observation. Named
    # negative variants must continue to match their exact declared IDs.
    allowed_row_variants = {variant_id} if variant_id is not None else {None, "baseline"}
    rows = []
    for row in _bound_database_rows(evidence, "x402-observations-by-operation", operation_id, variant_id):
        if (
            row.get("operation_id") == operation_id
            and row.get("variant_id") in allowed_row_variants
            and row.get("generation_id") == generation_id
            and row.get("phase") == "verify"
            and row.get("outcome") == "success"
            and row.get("transaction_hash") is None
        ):
            rows.append(row)
    if len(rows) != 1:
        return False
    observation = rows[0]
    safe_response = observation.get("safe_response")
    safe_request = observation.get("safe_request")
    if not isinstance(safe_response, dict) or not isinstance(safe_request, dict):
        return False
    response_payer = _address(safe_response.get("payer"))
    requirements = safe_request.get("paymentRequirements")
    if response_payer != payer or safe_response.get("isValid") is not True or not isinstance(requirements, dict):
        return False
    for field, aliases in (
        ("scheme", {"scheme"}),
        ("network", {"network"}),
        ("asset", {"asset", "token"}),
        ("amount", {"amount", "price"}),
        ("payTo", {"payTo"}),
    ):
        expected = _first_nested_value(challenge, aliases)
        if expected is None or not _contains_value(requirements, {field}, expected):
            return False
    return True


def _db_has_empty_query(evidence: ProbeEvidence, *fragments: str, variant_id: str | None = None) -> bool:
    for artifact in _db_artifacts(evidence, tuple(fragments)):
        if variant_id is not None and artifact.payload.get("variantId") != variant_id:
            continue
        if artifact.payload.get("rows") == []:
            return True
    return False


def _operation_records(evidence: ProbeEvidence) -> tuple[dict[str, Any], ...]:
    operations = evidence.index.get("operations")
    return tuple(item for item in operations if isinstance(item, dict)) if isinstance(operations, list) else ()


def _operation_id(item: EvidenceArtifact) -> str | None:
    value = item.payload.get("operationId")
    return value if isinstance(value, str) and value else None


def _same_operation(left: EvidenceArtifact, right: EvidenceArtifact) -> bool:
    return _operation_id(left) is not None and _operation_id(left) == _operation_id(right)


def _receipt_records(evidence: ProbeEvidence, status: int | None = None) -> tuple[EvidenceArtifact, ...]:
    found = []
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        payload = artifact.payload
        if payload.get("method") != "eth_getTransactionReceipt":
            continue
        result = _rpc_result(payload)
        if isinstance(result, dict) and (status is None or _receipt_status(result) == status):
            found.append(artifact)
    return tuple(found)


def _tx_hash_from_receipt(payload: dict[str, Any]) -> str | None:
    value = _rpc_result(payload)
    tx_hash = value.get("transactionHash") if isinstance(value, dict) else None
    return tx_hash.lower() if isinstance(tx_hash, str) else None


def _operation_hashes(evidence: ProbeEvidence) -> set[str]:
    return {
        item["transactionHash"].lower()
        for item in _operation_records(evidence)
        if isinstance(item.get("transactionHash"), str)
    }


def _receipt_has_operation_identity(evidence: ProbeEvidence, receipt: EvidenceArtifact) -> bool:
    tx_hash = _tx_hash_from_receipt(receipt.payload)
    if tx_hash is None:
        return False
    matching_operations = [item for item in _operation_records(evidence) if str(item.get("transactionHash", "")).lower() == tx_hash]
    return len(matching_operations) == 1 and _operation_id(receipt) is not None


def _address(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) else None


def _all_http(evidence: ProbeEvidence, predicate: Any, *, variant_id: str | None = None) -> tuple[EvidenceArtifact, ...]:
    return tuple(
        artifact
        for artifact, request, response in _http_records(evidence)
        if (variant_id is None or artifact.payload.get("variantId") == variant_id)
        and predicate(artifact, request, response)
    )


def _http_header_value(response: dict[str, Any], header_name: str) -> Any:
    return _headers(response.get("headers")).get(header_name.lower())


def _matches_network(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value.lower() == expected.lower()
    if isinstance(value, dict):
        return any(_matches_network(child, expected) for child in value.values())
    if isinstance(value, list):
        return any(_matches_network(child, expected) for child in value)
    return False


def _is_primary_or_variant(evidence: ProbeEvidence, artifact: EvidenceArtifact, variant_id: str | None) -> bool:
    return artifact.payload.get("variantId") == variant_id


def _participant_scope_is_bound(evidence: ProbeEvidence) -> bool:
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"}:
            continue
        headers = _headers(request.get("headers"))
        authorization = headers.get("authorization")
        generation = headers.get("x-bef-generation")
        if authorization is None or not _sensitive_value_is_redacted(authorization) or str(generation) != evidence.generation_id:
            continue
        if evidence.environment_id.lower() in str(request.get("path", "")).lower():
            return True
    return False


def _participant_reads_are_observed(evidence: ProbeEvidence) -> bool:
    seen = set()
    for _, request, response in _http_records(evidence):
        path = str(request.get("path", "")).lower()
        if request.get("method") == "GET" and _successful_http(response) and _response_body(response):
            for read in ("balances", "offer", "quote"):
                if f"/{read}" in path:
                    seen.add(read)
    return seen == {"balances", "offer", "quote"}


def _selected_write_choices_are_preserved(evidence: ProbeEvidence) -> bool:
    participant_writes = []
    for artifact, request, response in _http_records(evidence):
        body = _body_object(request.get("body"))
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or request.get("method") != "POST":
            continue
        if not body or not _successful_http(response):
            continue
        response_body = _response_body(response)
        # At least one consequential, caller-provided selector must survive in
        # an independently read database row associated with the operation.
        selectors = {key: value for key, value in body.items() if key.lower() in {
            "amount", "amountin", "amountoutminimum", "recipient", "route", "tokenin", "tokenout", "fee", "direction", "spender"
        }}
        if not selectors:
            continue
        op_id = artifact.payload.get("operationId")
        rows = [row for db_artifact, row in _db_rows_with_source(evidence) if db_artifact.payload.get("operationId") == op_id]
        if rows and any(all(_contains_value(row, {key}, value) for key, value in selectors.items()) for row in rows):
            participant_writes.append(artifact)
    return bool(participant_writes)


def _technical_step_receipts_are_linked(evidence: ProbeEvidence) -> bool:
    steps = []
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or request.get("method") != "POST":
            continue
        if any(step in str(request.get("path", "")).lower() for step in ("approve", "wrap", "unwrap", "swap")) and _successful_http(response):
            steps.append(artifact)
    receipts = _receipt_records(evidence, 1)
    return bool(steps) and all(
        any(_operation_id(step) == _operation_id(receipt) for receipt in receipts)
        or any(_tx_hash_from_receipt(receipt.payload) in _operation_hashes(evidence) for receipt in receipts)
        for step in steps
    )


def _valid_goal_mistake_has_effect(evidence: ProbeEvidence) -> bool:
    task_goal = _manifest(evidence, "taskGoal")
    goal_keys = ("recipient", "expenseBudgetUsdcUnits", "minimumOutput", "nativeEthReserveWei")
    receipt_ids = {_operation_id(item) for item in _receipt_records(evidence, 1)}
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _successful_http(response):
            continue
        body = _body_object(request.get("body"))
        if any(key in body for key in ("recipient", "amountIn", "amount")) and _operation_id(artifact) in receipt_ids:
            for key in goal_keys:
                expected = task_goal.get(key)
                if expected is not None and any(_contains_value(body, {key}, expected) for key in body):
                    return True
            # A caller-selected recipient with a real receipt is itself a valid
            # in-scope goal mistake only when the durable row records evaluation.
            if "recipient" in body and any(
                _contains_value(row, {"goalMet", "taskGoalMet", "goalMismatch"}, False)
                for _, row in _db_rows_with_source(evidence)
            ):
                return True
    return False


def _selected_parameters_match_durable_rows(evidence: ProbeEvidence) -> bool:
    matched = False
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or request.get("method") != "POST":
            continue
        body = _body_object(request.get("body"))
        selected = {key: value for key, value in body.items() if key.lower() in {
            "amount", "amountin", "amountoutminimum", "recipient", "route", "tokenin", "tokenout", "fee", "direction", "spender"
        }}
        op_id = _operation_id(artifact)
        if not selected or op_id is None:
            continue
        rows = [row for db_artifact, row in _db_rows_with_source(evidence) if db_artifact.payload.get("operationId") == op_id]
        if not rows or not any(all(_contains_value(row, {key}, value) for key, value in selected.items()) for row in rows):
            return False
        matched = True
    return matched


def _no_corrective_reset(evidence: ProbeEvidence) -> bool:
    for artifact, request, response in _http_records(evidence):
        path = str(request.get("path", "")).lower()
        if "reset" in path and _successful_http(response):
            return False
    rows = _db_rows_with_source(evidence, ("reset", "correction", "repair"))
    return not rows


def _goal_mismatch_is_recorded(evidence: ProbeEvidence) -> bool:
    for _, row in _db_rows_with_source(evidence):
        if _contains_value(row, {"goalMet", "taskGoalMet", "goalMismatch"}, False):
            if _contains_value(row, {"actualOutput", "actualRecipient", "actualExpense", "actualReserve", "actualAmount"}, None):
                continue
            if any(_nested_values(row, {key}) for key in ("actualOutput", "actualRecipient", "actualExpense", "actualReserve", "actualAmount")):
                return True
    return False


def _protocol_failure_is_observed(evidence: ProbeEvidence) -> bool:
    failed_operations = []
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"}:
            continue
        if _response_status(response) is not None and _response_status(response) >= 400:
            op_id = _operation_id(artifact)
            has_receipt = any(_operation_id(receipt) == op_id for receipt in _receipt_records(evidence))
            audit = any(db_artifact.payload.get("operationId") == op_id for db_artifact, _ in _db_rows_with_source(evidence, ("failure", "operation", "denial")))
            if not has_receipt and audit:
                failed_operations.append(artifact)
    return bool(failed_operations)


_SC003_VARIANT_STATUS = {
    "foreign_environment": 403,
    "stale_generation": 403,
    "arbitrary_url": 400,
    "raw_transaction": 400,
    "admin_rpc": 404,
    "learning_error_claim_for_foreign_or_admin_access": 403,
    "real_fund_or_external_write_route": 400,
    "request_exceeds_preexecution_resource_bound": 413,
}
_SC003_DB_SELECTORS = ("stale-a", "current-a", "foreign-b-owner", "foreign-b-at-target-a")
_SC003_DB_STATE_QUERIES = (
    "generation-by-id",
    "operations-by-generation",
    "payments-by-operation",
    "deliveries-by-operation",
    "x402-observations-by-operation",
)
_SC003_REASON_BY_STATUS = {
    400: "participant_request_invalid",
    401: "participant_authentication_denied",
    403: "participant_generation_scope_denied",
    404: "participant_route_not_found",
    413: "participant_request_limit_exceeded",
}
_SC003_FORBIDDEN_RPC_PREFIXES = ("personal_", "wallet_", "anvil_", "hardhat_", "debug_", "miner_")
_SC003_FORBIDDEN_RPC_METHODS = {
    "eth_sendtransaction", "eth_sendrawtransaction", "eth_sign", "eth_signtransaction",
    "eth_signtypeddata", "eth_signtypeddata_v1", "eth_signtypeddata_v3", "eth_signtypeddata_v4",
    "eth_requestaccounts", "eth_accounts", "eth_coinbase",
}


def _sc003_environment_pair(evidence: ProbeEvidence) -> tuple[str, str] | None:
    local = _manifest(evidence, "local")
    environments = local.get("environments")
    if not isinstance(environments, list) or len(environments) != 2:
        return None
    ids = [item.get("id") for item in environments if isinstance(item, dict)]
    if len(ids) != 2 or not all(isinstance(value, str) and value for value in ids):
        return None
    if evidence.environment_id not in ids or ids[0] == ids[1]:
        return None
    other = ids[1] if ids[0] == evidence.environment_id else ids[0]
    return evidence.environment_id, other


def _sc003_variant_http(
    evidence: ProbeEvidence, variant_id: str
) -> tuple[EvidenceArtifact, dict[str, Any], dict[str, Any]] | None:
    matches = [
        item for item in _http_records(evidence)
        if item[0].boundary in {"actual-tool-http", "participant-http"}
        and item[0].payload.get("variantId") == variant_id
    ]
    return matches[0] if len(matches) == 1 else None


def _sc003_route_for_request(path: Any, target_env: str) -> str | None:
    if not isinstance(path, str):
        return None
    route = path.split("?", 1)[0]
    if route in {f"/tools/{target_env}/offer", f"/tools/{target_env}/purchase"}:
        return route
    if route.startswith(f"/tools/{target_env}/"):
        return f"/tools/{target_env}/[unknown]"
    return None


def _sc003_db_snapshot(
    evidence: ProbeEvidence, phase: str, selector: str, query_name: str
) -> tuple[EvidenceArtifact, list[dict[str, Any]]] | None:
    expected_path_prefix = f"db/sc003-{phase}-{selector}-"
    matches = [
        artifact for artifact in _db_artifacts(evidence)
        if artifact.relative_path.startswith(expected_path_prefix)
        and artifact.payload.get("schemaVersion") == "bef-db-observation/v1"
        and artifact.payload.get("queryName") == query_name
        and artifact.payload.get("operationId") is None
        and artifact.payload.get("variantId") is None
    ]
    if len(matches) != 1:
        return None
    rows = matches[0].payload.get("rows")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return None
    return matches[0], rows


def _sc003_snapshot_matrix(
    evidence: ProbeEvidence, phase: str
) -> dict[tuple[str, str], tuple[EvidenceArtifact, list[dict[str, Any]]]] | None:
    matrix: dict[tuple[str, str], tuple[EvidenceArtifact, list[dict[str, Any]]]] = {}
    for selector in _SC003_DB_SELECTORS:
        for query_name in (*_SC003_DB_STATE_QUERIES, "denials-by-generation"):
            snapshot = _sc003_db_snapshot(evidence, phase, selector, query_name)
            if snapshot is None:
                return None
            matrix[(selector, query_name)] = snapshot
    return matrix


def _sc003_rows_by_generation(
    matrix: dict[tuple[str, str], tuple[EvidenceArtifact, list[dict[str, Any]]]], selector: str
) -> list[dict[str, Any]]:
    value = matrix.get((selector, "generation-by-id"))
    return value[1] if value else []


def _sc003_rows_for_denials(
    matrix: dict[tuple[str, str], tuple[EvidenceArtifact, list[dict[str, Any]]]]
) -> dict[str, dict[str, Any]] | None:
    result: dict[str, dict[str, Any]] = {}
    for (selector, query_name), (_artifact, rows) in matrix.items():
        if query_name != "denials-by-generation":
            continue
        for row in rows:
            denial_id = row.get("denial_id")
            if not isinstance(denial_id, str) or not denial_id:
                return None
            existing = result.get(denial_id)
            if existing is not None and existing != row:
                return None
            result[denial_id] = row
    return result


def _sc003_generation_row(
    matrix: dict[tuple[str, str], tuple[EvidenceArtifact, list[dict[str, Any]]]],
    selector: str,
    generation_id: str,
) -> dict[str, Any] | None:
    rows = [row for row in _sc003_rows_by_generation(matrix, selector) if row.get("generation_id") == generation_id]
    return rows[0] if len(rows) == 1 else None


def _sc003_denial_rows_match_http(
    evidence: ProbeEvidence, variants: Iterable[str]
) -> bool:
    requested_variants = tuple(variants)
    pair = _sc003_environment_pair(evidence)
    before = _sc003_snapshot_matrix(evidence, "before")
    after = _sc003_snapshot_matrix(evidence, "after")
    if pair is None or before is None or after is None:
        return False
    target_env, _foreign_env = pair
    before_rows = _sc003_rows_for_denials(before)
    after_rows = _sc003_rows_for_denials(after)
    if before_rows is None or after_rows is None:
        return False
    before_ids = set(before_rows)
    new_ids = set(after_rows) - before_ids
    response_ids: list[str] = []
    for variant_id in requested_variants:
        match = _sc003_variant_http(evidence, variant_id)
        if match is None:
            return False
        artifact, request, response = match
        if artifact.payload.get("operationId") is not None:
            return False
        status = _response_status(response)
        if status != _SC003_VARIANT_STATUS.get(variant_id):
            return False
        headers = _headers(response.get("headers"))
        if headers.get("x-bef-operation-id") is not None:
            return False
        denial_id = headers.get("x-bef-denial-id")
        if not isinstance(denial_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            denial_id,
            re.IGNORECASE,
        ):
            return False
        response_ids.append(denial_id)
        row = after_rows.get(denial_id)
        if row is None or denial_id in before_ids:
            return False
        request_headers = _headers(request.get("headers"))
        generation_id = request_headers.get("x-bef-generation")
        if not isinstance(generation_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            generation_id,
            re.IGNORECASE,
        ) or request_headers.get("authorization-present") is not True:
            return False
        expected_route = _sc003_route_for_request(request.get("path"), target_env)
        if (
            expected_route is None
            or row.get("denial_id") != denial_id
            or row.get("env_id") != target_env
            or row.get("generation_id") != generation_id
            or row.get("operation_id") is not None
            or row.get("route") != expected_route
            or row.get("reason_code") != _SC003_REASON_BY_STATUS.get(status)
            or not _is_digest(row.get("request_sha256"))
        ):
            return False
    if len(response_ids) != len(set(response_ids)):
        return False
    if set(requested_variants) == set(_SC003_VARIANT_STATUS):
        return set(response_ids) == new_ids
    return set(response_ids).issubset(new_ids)


def _foreign_and_stale_requests_are_denied(evidence: ProbeEvidence) -> bool:
    pair = _sc003_environment_pair(evidence)
    before = _sc003_snapshot_matrix(evidence, "before")
    after = _sc003_snapshot_matrix(evidence, "after")
    if pair is None or before is None or after is None:
        return False
    target_env, foreign_env = pair
    if not _sc003_denial_rows_match_http(evidence, ("foreign_environment", "stale_generation")):
        return False
    claims: dict[str, str] = {}
    for variant_id in ("foreign_environment", "stale_generation"):
        match = _sc003_variant_http(evidence, variant_id)
        if match is None:
            return False
        headers = _headers(match[1].get("headers"))
        claimed = headers.get("x-bef-generation")
        if not isinstance(claimed, str):
            return False
        claims[variant_id] = claimed
    foreign_before = _sc003_generation_row(before, "foreign-b-owner", claims["foreign_environment"])
    foreign_after = _sc003_generation_row(after, "foreign-b-owner", claims["foreign_environment"])
    foreign_target = _sc003_generation_row(after, "foreign-b-at-target-a", claims["foreign_environment"])
    stale_before = _sc003_generation_row(before, "stale-a", claims["stale_generation"])
    stale_after = _sc003_generation_row(after, "stale-a", claims["stale_generation"])
    current_before = _sc003_generation_row(before, "current-a", evidence.generation_id)
    current_after = _sc003_generation_row(after, "current-a", evidence.generation_id)
    return bool(
        foreign_before and foreign_after and foreign_target is None
        and foreign_before.get("env_id") == foreign_env and foreign_after.get("env_id") == foreign_env
        and foreign_before.get("status") == "active" and foreign_after.get("status") == "active"
        and stale_before and stale_after and stale_before.get("env_id") == target_env
        and stale_after.get("env_id") == target_env
        and stale_before.get("status") == "fenced" and stale_after.get("status") == "fenced"
        and current_before and current_after and current_before.get("status") == "active"
        and current_after.get("status") == "active"
        and claims["foreign_environment"] != evidence.generation_id
        and claims["stale_generation"] != evidence.generation_id
    )


def _participant_admin_routes_are_denied(evidence: ProbeEvidence) -> bool:
    match = _sc003_variant_http(evidence, "admin_rpc")
    if match is None:
        return False
    request_path = str(match[1].get("path", "")).split("?", 1)[0].lower()
    return (
        request_path.endswith("/admin/rpc")
        and _response_status(match[2]) == 404
        and _sc003_denial_rows_match_http(evidence, ("admin_rpc",))
    )


def _denials_have_no_sign_or_transaction(evidence: ProbeEvidence) -> bool:
    if set(_SC003_VARIANT_STATUS) != set(evidence.variant_ids()):
        return False
    if evidence.index.get("operations") != []:
        return False
    for variant_id in _SC003_VARIANT_STATUS:
        match = _sc003_variant_http(evidence, variant_id)
        if match is None:
            return False
        artifact, request, response = match
        if artifact.payload.get("operationId") is not None or not _denied_http(response):
            return False
        request_headers = _headers(request.get("headers"))
        for name in ("payment-signature-present", "x-payment-signature-present", "x-payment-present"):
            if request_headers.get(name) is True:
                return False
        response_headers = _headers(response.get("headers"))
        if response_headers.get("x-bef-operation-id") is not None:
            return False
        body = _response_body(response)
        if any(key in body for key in ("transactionHash", "signature", "paymentSignature")):
            return False
    for artifact in evidence.rpc_artifacts():
        method = artifact.payload.get("method")
        if not isinstance(method, str):
            continue
        normalized = method.lower()
        if normalized in _SC003_FORBIDDEN_RPC_METHODS or normalized.startswith(_SC003_FORBIDDEN_RPC_PREFIXES):
            return False
    before = _sc003_snapshot_matrix(evidence, "before")
    after = _sc003_snapshot_matrix(evidence, "after")
    if before is None or after is None:
        return False
    return all(
        before[(selector, query)][1] == after[(selector, query)][1]
        for selector in _SC003_DB_SELECTORS
        for query in _SC003_DB_STATE_QUERIES
    )


def _sc003_endpoint_identity_matches(evidence: ProbeEvidence, env_id: str) -> bool:
    bindings = [
        artifact for artifact in evidence.artifacts
        if artifact.payload.get("schemaVersion") == "bef-rpc-endpoint-binding/v1"
        and artifact.payload.get("environmentId") == env_id
    ]
    if len(bindings) != 1:
        return False
    binding = bindings[0].payload
    endpoint = binding.get("endpointRef")
    if not isinstance(endpoint, dict) or endpoint.get("scheme") != "http" \
        or endpoint.get("host") not in {"localhost", "127.0.0.1", "::1", "[::1]"} \
        or not isinstance(endpoint.get("port"), int) or not 1 <= endpoint["port"] <= 65535:
        return False
    health_path = binding.get("healthArtifactPath")
    health_hash = binding.get("healthArtifactSha256")
    health = [artifact for artifact in evidence.artifacts if artifact.relative_path == health_path]
    return bool(
        binding.get("boundary") == "local-chain-readonly-proxy"
        and binding.get("operationId") is None and binding.get("variantId") is None
        and
        len(health) == 1
        and health[0].sha256 == health_hash
        and health[0].boundary == "local-chain-readonly-proxy"
        and health[0].payload.get("boundary") == "local-chain-readonly-proxy"
        and health[0].payload.get("envId") == env_id
        and health[0].payload.get("status") == "ok"
        and health[0].payload.get("manifestSha256") == evidence.manifest_sha256
        and binding.get("health") == health[0].payload
    )


def _sc003_rpc_for_phase(
    evidence: ProbeEvidence, env_id: str, phase: str
) -> list[EvidenceArtifact] | None:
    if not _sc003_endpoint_identity_matches(evidence, env_id):
        return None
    marker = f"sc003-{phase}-{env_id}-"
    result = [
        artifact for artifact in evidence.rpc_artifacts("local-chain-readonly-proxy")
        if artifact.relative_path.startswith("rpc/")
        and marker in artifact.relative_path
        and artifact.payload.get("schemaVersion") == "bef-rpc-observation/v1"
        and artifact.payload.get("environmentId") == env_id
        and isinstance(artifact.payload.get("method"), str)
        and artifact.payload.get("operationId") is None
        and artifact.payload.get("variantId") is None
    ]
    if not result:
        return None
    binding = next(
        artifact for artifact in evidence.artifacts
        if artifact.payload.get("schemaVersion") == "bef-rpc-endpoint-binding/v1"
        and artifact.payload.get("environmentId") == env_id
    )
    if any(artifact.payload.get("endpointIdentityArtifact") != binding.relative_path for artifact in result):
        return None
    return result


def _sc003_call_key(artifact: EvidenceArtifact) -> tuple[str, str] | None:
    method = artifact.payload.get("method")
    params = artifact.payload.get("params")
    if not isinstance(method, str) or not isinstance(params, list):
        return None
    return method, json.dumps(params, sort_keys=True, separators=(",", ":"))


def _sc003_state_reads_unchanged(evidence: ProbeEvidence) -> bool:
    pair = _sc003_environment_pair(evidence)
    if pair is None:
        return False
    env_a, env_b = pair
    binding_a = next((item.payload for item in evidence.artifacts
                      if item.payload.get("schemaVersion") == "bef-rpc-endpoint-binding/v1"
                      and item.payload.get("environmentId") == env_a), None)
    binding_b = next((item.payload for item in evidence.artifacts
                      if item.payload.get("schemaVersion") == "bef-rpc-endpoint-binding/v1"
                      and item.payload.get("environmentId") == env_b), None)
    if not isinstance(binding_a, dict) or not isinstance(binding_b, dict) \
        or binding_a.get("endpointRef") == binding_b.get("endpointRef"):
        return False
    before = {env_id: _sc003_rpc_for_phase(evidence, env_id, "before") for env_id in (env_a, env_b)}
    after = {env_id: _sc003_rpc_for_phase(evidence, env_id, "after") for env_id in (env_a, env_b)}
    if any(not before[env_id] or not after[env_id] for env_id in (env_a, env_b)):
        return False

    contracts = _manifest(evidence, "contracts")
    local_chain_id = _manifest(evidence, "local").get("chainId")
    if not isinstance(local_chain_id, int) or isinstance(local_chain_id, bool) or local_chain_id < 0:
        return False
    expected_chain_id = f"0x{local_chain_id:x}"
    usdc = contracts.get("usdc")
    router = _address(contracts.get("swapRouter02", {}).get("address")) if isinstance(contracts.get("swapRouter02"), dict) else None
    if not isinstance(usdc, dict) or not router:
        return False
    usdc_address = _address(usdc.get("address"))
    if not usdc_address:
        return False

    expected_codes: dict[str, str] = {}
    for name, address_key, hash_key in (
        ("usdc", "address", "proxyCodeHash"),
        ("usdc-implementation", "implementation", "implementationCodeHash"),
        ("weth", "address", "codeHash"),
        ("factory", "address", "codeHash"),
        ("swapRouter02", "address", "codeHash"),
        ("quoterV2", "address", "codeHash"),
        ("pool", "address", "codeHash"),
    ):
        contract = usdc if name.startswith("usdc") else contracts.get(name)
        if not isinstance(contract, dict):
            return False
        address = _address(contract.get(address_key))
        code_hash = contract.get(hash_key)
        if not address or not _is_digest(code_hash):
            return False
        expected_codes[address] = str(code_hash).lower().removeprefix("0x")

    before_generation_rows: list[dict[str, Any]] = []
    for selector in _SC003_DB_SELECTORS:
        snapshot = _sc003_db_snapshot(evidence, "before", selector, "generation-by-id")
        if snapshot is None:
            return False
        before_generation_rows.extend(snapshot[1])
    payer_addresses = {
        value for row in before_generation_rows
        for value in [_address(row.get("payer_address"))]
        if value is not None
    }
    donor = _address(_manifest(evidence, "funding").get("donor"))
    if donor:
        payer_addresses.add(donor)
    for artifact, _request, response in _http_records(evidence):
        if artifact.boundary not in {"private-admin-http", "admin-http"}:
            continue
        body = _response_body(response)
        services = body.get("services")
        facilitator = services.get("facilitator") if isinstance(services, dict) else None
        address = _address(facilitator.get("address")) if isinstance(facilitator, dict) else None
        if address:
            payer_addresses.add(address)
    if not payer_addresses:
        return False

    expected_balance_calls = {
        (usdc_address, "0x70a08231" + address[2:].zfill(64)) for address in payer_addresses
    }
    expected_allowance_calls = {
        (usdc_address, "0xdd62ed3e" + address[2:].zfill(64) + router[2:].zfill(64))
        for address in payer_addresses
    }

    for env_id in (env_a, env_b):
        phase_maps: dict[str, dict[tuple[str, str], Any]] = {}
        for phase, artifacts in (("before", before[env_id]), ("after", after[env_id])):
            assert artifacts is not None
            mapping: dict[tuple[str, str], Any] = {}
            for artifact in artifacts:
                key = _sc003_call_key(artifact)
                if key is None or key in mapping:
                    return False
                mapping[key] = _rpc_result(artifact.payload)
            phase_maps[phase] = mapping

            chain = mapping.get(("eth_chainId", "[]"))
            if chain != expected_chain_id:
                return False
            block_reads = [
                value for (method, params), value in mapping.items()
                if method == "eth_getBlockByNumber" and params == '["latest",false]'
            ]
            if len(block_reads) != 1 or not isinstance(block_reads[0], dict) \
                or not isinstance(block_reads[0].get("hash"), str) \
                or not _is_digest(block_reads[0].get("hash")):
                return False

            observed_balances: set[tuple[str, str]] = set()
            observed_allowances: set[tuple[str, str]] = set()
            observed_native_accounts: set[str] = set()
            observed_nonce_accounts: set[str] = set()
            for (method, params_json), result in mapping.items():
                params = json.loads(params_json)
                if method == "eth_chainId":
                    # This identity read is required for both endpoints and was
                    # validated above. Permit only its parameterless form.
                    if params != [] or result != expected_chain_id:
                        return False
                    continue
                if method == "eth_getBlockByNumber":
                    # The latest header is also a protected-state read. Keep the
                    # exact non-pending request and require a real quantity/hash;
                    # the complete result must match between before and after.
                    if params != ["latest", False] or not isinstance(result, dict):
                        return False
                    number = result.get("number")
                    block_hash = result.get("hash")
                    if not isinstance(number, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", number) \
                        or not _is_digest(block_hash):
                        return False
                    continue
                if method in {"eth_getBalance", "eth_getTransactionCount"}:
                    if len(params) != 2 or params[1] != "latest" or _address(params[0]) not in payer_addresses:
                        return False
                    if _hex_or_int(result) is None:
                        return False
                    if method == "eth_getBalance":
                        observed_native_accounts.add(_address(params[0]) or "")
                    else:
                        observed_nonce_accounts.add(_address(params[0]) or "")
                elif method == "eth_call":
                    if len(params) != 2 or params[1] != "latest" or not isinstance(params[0], dict):
                        return False
                    call = params[0]
                    to = _address(call.get("to"))
                    data = call.get("data")
                    if to != usdc_address or not isinstance(data, str) or not isinstance(result, str) or not _HEX_RE.fullmatch(result):
                        return False
                    call_data = data.lower()
                    if call_data.startswith("0x70a08231"):
                        if len(call_data) != 74:
                            return False
                        account = "0x" + call_data[-40:]
                        candidate = (to, call_data)
                        if account not in payer_addresses or candidate not in expected_balance_calls:
                            return False
                        observed_balances.add(candidate)
                    elif call_data.startswith("0xdd62ed3e"):
                        if len(call_data) != 138:
                            return False
                        owner = "0x" + call_data[10 + 24:10 + 64]
                        spender = "0x" + call_data[10 + 64 + 24:10 + 128]
                        candidate = (to, call_data)
                        if owner not in payer_addresses or spender != router or candidate not in expected_allowance_calls:
                            return False
                        observed_allowances.add(candidate)
                    else:
                        return False
                elif method == "eth_getCode":
                    if len(params) != 2 or params[1] != "latest":
                        return False
                    address = _address(params[0])
                    code_hash = _keccak256(bytes.fromhex(result[2:])).hex() if isinstance(result, str) and _HEX_RE.fullmatch(result) else None
                    if address not in expected_codes or code_hash != expected_codes[address]:
                        return False
                else:
                    return False
            if observed_balances != expected_balance_calls or observed_allowances != expected_allowance_calls:
                return False
            if observed_native_accounts != payer_addresses or observed_nonce_accounts != payer_addresses:
                return False
            observed_codes = {
                _address(json.loads(params)[0])
                for (method, params) in mapping
                if method == "eth_getCode"
            }
            if observed_codes != set(expected_codes):
                return False
        if phase_maps["before"] != phase_maps["after"]:
            return False
    return True


def _denied_state_is_unchanged(evidence: ProbeEvidence) -> bool:
    before = _sc003_snapshot_matrix(evidence, "before")
    after = _sc003_snapshot_matrix(evidence, "after")
    if before is None or after is None:
        return False
    database_unchanged = all(
        before[(selector, query)][1] == after[(selector, query)][1]
        for selector in _SC003_DB_SELECTORS
        for query in _SC003_DB_STATE_QUERIES
    )
    return database_unchanged and _sc003_state_reads_unchanged(evidence)


def _isolation_denials_stay_denied(evidence: ProbeEvidence) -> bool:
    expected = set(_SC003_VARIANT_STATUS)
    if not evidence.variants_are_exact(expected):
        return False
    if not _sc003_denial_rows_match_http(evidence, expected):
        return False
    if not all(
        (match := _sc003_variant_http(evidence, variant_id)) is not None
        and _response_status(match[2]) == expected_status
        for variant_id, expected_status in _SC003_VARIANT_STATUS.items()
    ):
        return False
    requests = {
        variant: match[1]
        for variant in expected
        if (match := _sc003_variant_http(evidence, variant)) is not None
    }
    if set(requests) != expected:
        return False
    foreign_headers = _headers(requests["foreign_environment"].get("headers"))
    learning_headers = _headers(requests["learning_error_claim_for_foreign_or_admin_access"].get("headers"))
    if (
        foreign_headers.get("x-bef-generation") != learning_headers.get("x-bef-generation")
        or not _contains_value(requests["learning_error_claim_for_foreign_or_admin_access"].get("body"), {"learningErrorClaim"}, True)
    ):
        return False
    arbitrary_body = _body_object(requests["arbitrary_url"].get("body"))
    if arbitrary_body.get("url") != "https://example.invalid/never-fetch-this":
        return False
    raw_body = _body_object(requests["raw_transaction"].get("body"))
    if raw_body.get("method") != "eth_sendRawTransaction" or raw_body.get("rawTransaction") != "0x":
        return False
    admin_request = requests["admin_rpc"]
    if str(admin_request.get("path", "")).split("?", 1)[0].lower().endswith("/admin/rpc") is False:
        return False
    admin_body = _body_object(admin_request.get("body"))
    if admin_body.get("method") != "anvil_getAutomine":
        return False
    external_body = _body_object(requests["real_fund_or_external_write_route"].get("body"))
    if external_body.get("targetUrl") != "https://example.invalid/never-fetch-this" \
        or external_body.get("method") != "eth_sendTransaction":
        return False
    guardrails = _manifest(evidence, "guardrails")
    max_request_bytes = guardrails.get("maxHttpRequestBytes")
    oversized_body = requests["request_exceeds_preexecution_resource_bound"].get("body")
    if not isinstance(max_request_bytes, int) or isinstance(max_request_bytes, bool) \
        or not isinstance(oversized_body, dict):
        return False
    try:
        oversized_bytes = len(json.dumps(oversized_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return False
    return oversized_bytes > max_request_bytes


def _offer_identity_is_read_from_http(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or request.get("method") != "GET" or not _path_matches(request, "/offer"):
            continue
        body = _response_body(response)
        if _successful_http(response) and _contains_value(body, {"resourceId", "id"}, x402.get("resourceId")) and _contains_value(body, {"sha256", "resourceSha256"}, x402.get("resourceSha256")):
            return True
    return False


def _payment_requirements_match_manifest(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"}:
            continue
        candidates = _payment_requirement_candidates(response)
        if not (_response_status(response) == 402 or _path_matches(request, "/offer")):
            continue
        if any(
            _contains_value(candidate, {"scheme"}, x402.get("scheme"))
            and _payment_network_matches(candidate, str(x402.get("network", "")))
            and _contains_value(candidate, {"asset", "token"}, x402.get("asset"))
            and _contains_value(candidate, {"amount", "price"}, x402.get("amount"))
            for candidate in candidates
        ):
            return True
    return False


def _payment_requirement_candidates(response: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    candidates = []
    decoded = response.get("decodedPaymentRequired")
    if isinstance(decoded, dict):
        candidates.append(decoded)
    decoded_protocol = response.get("decodedProtocol")
    if isinstance(decoded_protocol, dict):
        for key in ("paymentRequired", "selectedPaymentRequirements", "paymentRequirements"):
            candidate = decoded_protocol.get(key)
            if isinstance(candidate, dict):
                candidates.append(candidate)
    body = _response_body(response)
    if body:
        candidates.append(body)
    headers = _headers(response.get("headers"))
    encoded = headers.get("payment-required", headers.get("x-payment-required"))
    if isinstance(encoded, str):
        try:
            raw = base64.b64decode(encoded, validate=True).decode("utf-8")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    return tuple(candidates)


def _payment_network_matches(value: Any, expected: str) -> bool:
    if _contains_value(value, {"network"}, expected):
        return True
    chain_id = _nested_values(value, {"chainId"})
    return any(_hex_or_int(item) == 8453 for item in chain_id) and expected.lower() == "eip155:8453"


def _balance_reads(evidence: ProbeEvidence, variant_id: str | None = None) -> tuple[tuple[EvidenceArtifact, Any], ...]:
    usdc = _manifest(evidence, "contracts").get("usdc", {})
    address = _address(usdc.get("address")) if isinstance(usdc, dict) else None
    found = []
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy", variant_id=variant_id):
        payload = artifact.payload
        if payload.get("method") != "eth_call":
            continue
        params = payload.get("params")
        if not isinstance(params, list) or not params or not isinstance(params[0], dict):
            continue
        call = params[0]
        if _address(call.get("to")) != address or _balance_call_account(call, address) is None:
            continue
        value = _rpc_result(payload)
        if isinstance(value, str) and _HEX_RE.fullmatch(value):
            found.append((artifact, value.lower()))
    return tuple(found)


def _balance_call_account(call: dict[str, Any], asset: str | None) -> str | None:
    if asset is None or _address(call.get("to")) != asset:
        return None
    data = call.get("data")
    if not isinstance(data, str) or not re.fullmatch(r"0x70a08231[0-9a-fA-F]{64}", data):
        return None
    return _topic_address("0x" + data[-64:])


def _inspection_has_no_token_delta(evidence: ProbeEvidence) -> bool:
    usdc = _manifest(evidence, "contracts").get("usdc", {})
    asset = _address(usdc.get("address")) if isinstance(usdc, dict) else None
    snapshots: dict[tuple[str, str], list[tuple[str, int]]] = {}
    for artifact, value in _balance_reads(evidence):
        params = artifact.payload.get("params")
        call = params[0] if isinstance(params, list) and params and isinstance(params[0], dict) else {}
        account = _balance_call_account(call, asset)
        role = "payer" if "payer" in artifact.relative_path.lower() else "payto" if "payto" in artifact.relative_path.lower() else None
        path = artifact.relative_path.lower()
        phase = "before" if role and "before" in path else "after" if role and "after" in path else None
        number = _hex_or_int(value)
        if account is None or role is None or phase is None or number is None:
            continue
        key = (role, phase)
        snapshots.setdefault(key, []).append((account, number))
    if any(len(snapshots.get((role, phase), [])) != 1 for role in ("payer", "payto") for phase in ("before", "after")):
        return False
    # Each holder must remain unchanged across offer/challenge inspection. The
    # two holders may and normally do have different balances.
    return all(
        snapshots[(role, "before")][0][0] == snapshots[(role, "after")][0][0]
        and snapshots[(role, "before")][0][1] == snapshots[(role, "after")][0][1]
        for role in ("payer", "payto")
    )


def _has_independent_snapshot_rows(evidence: ProbeEvidence, fragments: tuple[str, ...]) -> bool:
    for artifact in _db_artifacts(evidence, fragments):
        rows = artifact.payload.get("rows")
        if isinstance(rows, list) and len(rows) >= 2 and rows[0] == rows[-1]:
            return True
    return False


def _inspection_has_no_settlement(evidence: ProbeEvidence) -> bool:
    return _db_has_empty_query(evidence, "settlement", "payment") and not _successful_purchase_delivery(evidence)


def _successful_purchase_delivery(evidence: ProbeEvidence) -> bool:
    return bool(_all_http(evidence, lambda _a, request, response: request.get("method") == "POST" and _path_matches(request, "/purchase") and _successful_http(response)))


def _inspection_has_no_delivery(evidence: ProbeEvidence) -> bool:
    return _db_has_empty_query(evidence, "deliver", "resource") and not _successful_purchase_delivery(evidence)


def _paid_request_matches_x402_requirements(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    payment_challenge = []
    authorized_success = []
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _path_matches(request, "/purchase"):
            continue
        if _response_status(response) == 402:
            for challenge in _payment_requirement_candidates(response):
                if all(_contains_value(challenge, names, expected) for names, expected in (
                    ({"scheme"}, x402.get("scheme")), ({"network"}, x402.get("network")),
                    ({"asset", "token"}, x402.get("asset")), ({"amount", "price"}, x402.get("amount")),
                )) and _payment_network_matches(challenge, str(x402.get("network", ""))):
                    payment_challenge.append((artifact, challenge))
                    break
        headers = _headers(request.get("headers"))
        signed = artifact.payload.get("paymentSignaturePresent") is True or (
            "payment-signature" in headers and _sensitive_value_is_redacted(headers.get("payment-signature"))
        )
        if _successful_http(response) and signed:
            authorized_success.append(artifact)
    return bool(payment_challenge) and any(
        _operation_id(challenge) is not None and _operation_id(challenge) == _operation_id(success)
        for challenge, _ in payment_challenge for success in authorized_success
    )


def _facilitator_verified_authorization(evidence: ProbeEvidence) -> bool:
    for operation_id, challenge in _accepted_primary_purchases(evidence):
        payer = _payer_for_database_operation(evidence, operation_id, None)
        if payer is not None and _x402_verify_observation_matches(evidence, operation_id, None, payer, challenge):
            return True
    return False


_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _receipt_transfer_logs(receipt: EvidenceArtifact) -> tuple[dict[str, Any], ...]:
    value = _rpc_result(receipt.payload)
    logs = value.get("logs") if isinstance(value, dict) else None
    if not isinstance(logs, list):
        return ()
    return tuple(log for log in logs if isinstance(log, dict))


def _decoded_transfers(receipt: EvidenceArtifact) -> tuple[dict[str, Any], ...]:
    decoded = []
    for log in _receipt_transfer_logs(receipt):
        topics = log.get("topics")
        data = log.get("data")
        if not isinstance(topics, list) or len(topics) < 3 or str(topics[0]).lower() != _TRANSFER_TOPIC or not isinstance(data, str):
            continue
        try:
            amount = int(data, 16)
        except ValueError:
            continue
        decoded.append({"token": _address(log.get("address")), "from": _topic_address(topics[1]), "to": _topic_address(topics[2]), "amount": amount})
    return tuple(decoded)


def _topic_address(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        return "0x" + value[-40:].lower()
    return None


def _purchase_token_effects_match_receipt(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    expected_asset = _address(x402.get("asset"))
    expected_amount = _numeric(x402.get("amount"))
    if expected_asset is None or expected_amount is None:
        return False
    for operation_id, challenge in _accepted_primary_purchases(evidence):
        payer = _payer_for_database_operation(evidence, operation_id, None)
        if payer is None:
            continue
        pay_to = _address(_first_nested_value(challenge, {"payTo"}))
        if pay_to is None:
            continue
        for receipt in _receipt_records(evidence, 1):
            if _operation_id(receipt) != operation_id:
                continue
            transfers = [
                item for item in _decoded_transfers(receipt)
                if item["token"] == expected_asset and item["from"] == payer and item["to"] == pay_to
            ]
            if sum(item["amount"] for item in transfers) != expected_amount:
                continue
            if not _purchase_balance_deltas_match(
                evidence, operation_id, payer, pay_to, expected_asset, expected_amount
            ):
                continue
            tx_hash = _tx_hash_from_receipt(receipt.payload)
            primary_settlement_rows = _bound_database_rows(evidence, "payments-by-operation", operation_id, None)
            primary_delivery_rows = _bound_database_rows(evidence, "deliveries-by-operation", operation_id, None)
            if len(primary_settlement_rows) != 1 or len(primary_delivery_rows) != 1:
                continue
            settlement_rows = [
                row for row in primary_settlement_rows
                if _contains_value(row, {"transactionHash", "txHash"}, tx_hash)
                and _contains_value(row, {"payer", "payerAddress", "from"}, payer)
                and _contains_value(row, {"payTo", "recipient", "to", "facilitatorAddress", "facilitator_address"}, pay_to)
                and _contains_value(row, {"asset", "assetAddress", "token"}, expected_asset)
                and _contains_value(row, {"amount", "amountUnits"}, str(expected_amount))
            ]
            delivery_rows = [
                row for row in primary_delivery_rows
                if _contains_value(row, {"operationId", "operation_id"}, operation_id)
                and _contains_value(row, {"resourceSha256", "contentHash", "contentSha256", "sha256"}, x402.get("resourceSha256"))
                and _delivery_row_is_durable(row)
            ]
            if len(settlement_rows) == 1 and len(delivery_rows) == 1:
                return True
    return False


def _delivered_bytes(evidence: ProbeEvidence) -> tuple[bytes, ...]:
    chunks: list[bytes] = []
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _path_matches(request, "/purchase") or not _successful_http(response):
            continue
        raw_body = response.get("bodyBase64", response.get("rawBodyBase64"))
        if isinstance(raw_body, str):
            try:
                chunks.append(base64.b64decode(raw_body, validate=True))
            except (ValueError, base64.binascii.Error):
                pass
    return tuple(chunks)


def _delivered_http_bytes_by_operation(evidence: ProbeEvidence) -> dict[str, bytes]:
    result = {}
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _path_matches(request, "/purchase") or not _successful_http(response):
            continue
        operation_id = _operation_id(artifact)
        body = _delivered_content_bytes_from_http_response(response)
        if operation_id is not None and body is not None:
            result[operation_id] = body
    return result


def _delivered_content_bytes_from_http_response(response: dict[str, Any]) -> bytes | None:
    raw_body = _decoded_http_body(response)
    if raw_body is None:
        return None
    try:
        parsed = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw_body
    if isinstance(parsed, dict):
        for candidate in _nested_values(parsed, {"contentBytes", "contentBytesBase64", "resourceBytesBase64"}):
            if not isinstance(candidate, str):
                continue
            try:
                return base64.b64decode(candidate, validate=True)
            except (ValueError, base64.binascii.Error):
                continue
    # Some tools return the pinned resource bytes directly as the HTTP body.
    return raw_body


def _delivered_bytes_match_pinned_hash(evidence: ProbeEvidence) -> bool:
    expected = _manifest(evidence, "x402").get("resourceSha256")
    if not _is_digest(expected):
        return False
    expected_raw = expected.lower().removeprefix("0x")
    delivered = _delivered_http_bytes_by_operation(evidence)
    for operation_id, _ in _accepted_primary_purchases(evidence):
        body = delivered.get(operation_id)
        if body is None or hashlib.sha256(body).hexdigest() != expected_raw:
            continue
        if any(
            _contains_value(row, {"operationId", "operation_id"}, operation_id)
            and _contains_value(row, {"resourceSha256", "contentHash", "contentSha256", "sha256"}, expected)
            and _delivery_row_is_durable(row)
            for artifact, row in _db_rows_with_source(evidence, ("deliver", "resource"))
            if artifact.payload.get("operationId") == operation_id
        ):
            return True
    return False


def _delivery_row_is_durable(row: dict[str, Any]) -> bool:
    delivered_at = _first_nested_value(row, {"deliveredAt"})
    if delivered_at is not None:
        if not isinstance(delivered_at, str) or not delivered_at.strip():
            return False
        try:
            timestamp = datetime.fromisoformat(delivered_at.strip().replace("Z", "+00:00"))
        except ValueError:
            return False
        return timestamp.tzinfo is not None
    if _contains_value(row, {"delivered"}, True):
        return True
    status = _first_nested_value(row, {"status", "deliveryStatus"})
    if isinstance(status, str) and status.lower() in {"delivered", "success", "succeeded"}:
        return True
    return False


def _purchase_balance_deltas_match(
    evidence: ProbeEvidence,
    operation_id: str,
    payer: str,
    pay_to: str,
    asset: str,
    amount: int | float | Decimal,
) -> bool:
    values: dict[tuple[str, str], list[int]] = {}
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        payload = artifact.payload
        if payload.get("operationId") != operation_id or payload.get("method") != "eth_call":
            continue
        params = payload.get("params")
        if not isinstance(params, list) or not params or not isinstance(params[0], dict):
            continue
        call = params[0]
        data = call.get("data")
        if _address(call.get("to")) != asset or not isinstance(data, str) or not re.fullmatch(r"0x70a08231[0-9a-fA-F]{64}", data):
            continue
        account = _topic_address("0x" + data[-64:])
        role = "payer" if account == payer else "payto" if account == pay_to else None
        if role is None:
            continue
        path = artifact.relative_path.lower()
        phase = "before" if role + "-before" in path else "after" if role + "-balance-after" in path or role + "-after" in path else None
        result = _rpc_result(payload)
        value = _numeric(result)
        if phase is not None and isinstance(value, int) and value >= 0:
            values.setdefault((role, phase), []).append(value)
    if any(len(values.get((role, phase), [])) != 1 for role in ("payer", "payto") for phase in ("before", "after")):
        return False
    payer_before = values[("payer", "before")][0]
    payer_after = values[("payer", "after")][0]
    payto_before = values[("payto", "before")][0]
    payto_after = values[("payto", "after")][0]
    exact_amount = int(amount) if isinstance(amount, int) else int(Decimal(str(amount)))
    return payer_before - payer_after == exact_amount and payto_after - payto_before == exact_amount


def _payer_is_linked_to_receipt_and_database(evidence: ProbeEvidence) -> bool:
    for operation_id, challenge in _accepted_primary_purchases(evidence):
        payer = _payer_for_database_operation(evidence, operation_id, None)
        if payer is None:
            continue
        pay_to = _address(_first_nested_value(challenge, {"payTo"}))
        if pay_to is None:
            continue
        for receipt in _receipt_records(evidence, 1):
            if _operation_id(receipt) != operation_id:
                continue
            tx_hash = _tx_hash_from_receipt(receipt.payload)
            if not any(item["from"] == payer and item["to"] == pay_to for item in _decoded_transfers(receipt)):
                continue
            if any(art.payload.get("operationId") == operation_id
                   and _contains_value(row, {"payer", "payerAddress", "from"}, payer)
                   and _contains_value(row, {"payTo", "recipient", "to", "facilitatorAddress", "facilitator_address"}, pay_to)
                   and _contains_value(row, {"transactionHash", "txHash"}, tx_hash)
                   for art, row in _db_rows_with_source(evidence, ("settlement", "payment"))):
                return True
    return False


def _first_nested_value(value: Any, names: set[str]) -> Any:
    values = _nested_values(value, names)
    return values[0] if values else None


def _accepted_primary_purchases(evidence: ProbeEvidence) -> tuple[tuple[str, dict[str, Any]], ...]:
    challenges: dict[str, dict[str, Any]] = {}
    successes: set[str] = set()
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _path_matches(request, "/purchase"):
            continue
        if artifact.payload.get("variantId") is not None:
            continue
        operation_id = _operation_id(artifact)
        if operation_id is None:
            continue
        if _response_status(response) == 402:
            for candidate in _payment_requirement_candidates(response):
                if _first_nested_value(candidate, {"payTo"}) is not None:
                    challenges[operation_id] = candidate
                    break
        headers = _headers(request.get("headers"))
        signed = artifact.payload.get("paymentSignaturePresent") is True or (
            "payment-signature" in headers and _sensitive_value_is_redacted(headers.get("payment-signature"))
        )
        if _successful_http(response) and signed:
            successes.add(operation_id)
    return tuple((operation_id, challenge) for operation_id, challenge in challenges.items() if operation_id in successes)


def _x402_negative_variants_are_not_paid_success(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    pinned_hash = x402.get("resourceSha256")
    asset = _address(x402.get("asset"))
    if not _is_digest(pinned_hash) or asset is None:
        return False

    for variant in ("wrong_token_representation", "verification_without_receipt"):
        events = _variant_http(evidence, variant)
        operation_ids = {_operation_id(item[0]) for item in events}
        if not events or None in operation_ids or len(operation_ids) != 1:
            return False
        operation_id = next(iter(operation_ids))
        payer = _payer_for_database_operation(evidence, operation_id, variant)
        if payer is None:
            return False
        if any(
            _operation_id(artifact) == operation_id
            for artifact in _receipt_records(evidence)
        ):
            return False
        if not _variant_database_has_no_payment_or_delivery(evidence, variant, operation_id):
            return False
        if not _variant_balances_are_unchanged(evidence, operation_id, payer, _variant_pay_to(events, x402), asset):
            return False
        participant_purchases = [
            (artifact, request, response)
            for artifact, request, response in events
            if artifact.boundary in {"actual-tool-http", "participant-http"}
            and _path_matches(request, "/purchase")
        ]
        if any(_successful_http(response) for _, _, response in participant_purchases):
            return False
        if variant == "wrong_token_representation":
            pinned_challenge = _variant_purchase_challenge(events, x402)
            retry_pay_to = _address(_first_nested_value(pinned_challenge, {"payTo"})) if pinned_challenge else None
            if not any(
                _signed_wrong_token_retry_was_rejected(
                    artifact, request, response, pinned_challenge, asset, retry_pay_to
                )
                for artifact, request, response in participant_purchases
            ):
                return False
            if not _wrong_token_database_rejection_is_proven(evidence, operation_id, variant):
                return False
            if _bound_database_rows(evidence, "x402-observations-by-operation", operation_id, variant):
                return False
        else:
            challenge = None
            for artifact, request, response in events:
                if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _path_matches(request, "/purchase") or _response_status(response) != 402:
                    continue
                challenge = next(
                    (candidate for candidate in _payment_requirement_candidates(response)
                     if _first_nested_value(candidate, {"payTo"}) is not None),
                    None,
                )
                if challenge is not None:
                    break
            if challenge is None or not _x402_verify_observation_matches(
                evidence, operation_id, variant, payer, challenge
            ):
                return False

    mismatch_events = _variant_http(evidence, "mismatched_data")
    mismatch_ids = {_operation_id(item[0]) for item in mismatch_events}
    if not mismatch_events or None in mismatch_ids or len(mismatch_ids) != 1:
        return False
    mismatch_id = next(iter(mismatch_ids))
    bad_purchase = [
        (artifact, request, response)
        for artifact, request, response in mismatch_events
        if artifact.boundary in {"actual-tool-http", "participant-http"}
        and _path_matches(request, "/purchase")
    ]
    if not bad_purchase or any(_successful_http(response) for _, _, response in bad_purchase):
        return False
    if not _variant_database_has_no_delivery(evidence, "mismatched_data", mismatch_id):
        return False
    if any(_operation_id(receipt) == mismatch_id and _receipt_status(_rpc_result(receipt.payload)) != 1
           for receipt in _receipt_records(evidence)):
        return False
    return _mismatched_resource_bytes_are_proven(evidence, mismatch_id, str(pinned_hash))


def _signed_wrong_token_retry_was_rejected(
    artifact: EvidenceArtifact,
    request: dict[str, Any],
    response: dict[str, Any],
    pinned_challenge: dict[str, Any] | None,
    pinned_asset: str,
    expected_pay_to: str | None,
) -> bool:
    """Validate a rejected signed wrong-asset payload without exposing it."""
    if (
        pinned_challenge is None
        or expected_pay_to is None
        or _response_status(response) != 402
        or not _payment_signature_was_present(artifact, request)
    ):
        return False

    headers = _headers(request.get("headers"))
    signature_header = headers.get("payment-signature", headers.get("x-payment-signature"))
    signature_digest = headers.get("payment-signature-sha256", headers.get("x-payment-signature-sha256"))
    if (
        not _sensitive_value_is_redacted(signature_header)
        or headers.get("payment-signature-present", headers.get("x-payment-signature-present")) is not True
        or not _is_digest(signature_digest)
    ):
        return False

    decoded_payload = request.get("decodedPaymentPayload")
    selected = decoded_payload.get("accepted") if isinstance(decoded_payload, dict) else None
    if (
        not isinstance(decoded_payload, dict)
        or decoded_payload.get("x402Version") != 2
        or decoded_payload.get("sourceHeaderSha256") != signature_digest
        or not isinstance(selected, dict)
    ):
        return False

    selected_asset = _address(selected.get("asset"))
    if selected_asset is None or selected_asset == pinned_asset:
        return False

    for field, aliases in (
        ("scheme", {"scheme"}),
        ("network", {"network"}),
        ("amount", {"amount", "price"}),
        ("payTo", {"payTo"}),
    ):
        expected = _first_nested_value(pinned_challenge, aliases)
        if expected is None or not _contains_value({field: selected.get(field)}, {field}, expected):
            return False
    if _address(selected.get("payTo")) != expected_pay_to:
        return False
    expected_extra = _first_nested_value(pinned_challenge, {"extra"})
    selected_extra = selected.get("extra")
    if isinstance(expected_extra, dict):
        if not isinstance(selected_extra, dict):
            return False
        for key in ("name", "version", "paymentFlow", "assetTransferMethod"):
            if key in expected_extra and selected_extra.get(key) != expected_extra[key]:
                return False

    # A 402 is only accepted as a rejection when the actual SDK-decoded
    # PAYMENT-REQUIRED response states this exact protocol error and reoffers
    # the pinned requirement for the same operation.
    response_headers = _headers(response.get("headers"))
    if not _nonempty(response_headers.get("payment-required")):
        return False
    decoded_required = response.get("decodedPaymentRequired")
    raw_required = _decode_payment_required_header(response)
    if (
        not isinstance(decoded_required, dict)
        or not isinstance(raw_required, dict)
        or decoded_required.get("error") != "No matching payment requirements"
        or raw_required.get("error") != decoded_required.get("error")
        or raw_required.get("x402Version") != decoded_required.get("x402Version")
    ):
        return False
    accepts = decoded_required.get("accepts")
    raw_accepts = raw_required.get("accepts")
    if not isinstance(accepts, list) or not isinstance(raw_accepts, list) or not raw_accepts:
        return False
    raw_projection = [_public_payment_requirement_projection(candidate) for candidate in raw_accepts]
    decoded_projection = [_public_payment_requirement_projection(candidate) for candidate in accepts]
    if any(candidate is None for candidate in raw_projection + decoded_projection) or raw_projection != decoded_projection:
        return False
    return any(
        isinstance(candidate, dict)
        and _contains_value(candidate, {"scheme"}, _first_nested_value(pinned_challenge, {"scheme"}))
        and _payment_network_matches(candidate, str(_first_nested_value(pinned_challenge, {"network"})))
        and _address(_first_nested_value(candidate, {"asset", "token"})) == pinned_asset
        and _contains_value(candidate, {"amount", "price"}, _first_nested_value(pinned_challenge, {"amount", "price"}))
        and _address(_first_nested_value(candidate, {"payTo"})) == expected_pay_to
        for candidate in raw_accepts
    )


def _decode_payment_required_header(response: dict[str, Any]) -> dict[str, Any] | None:
    headers = _headers(response.get("headers"))
    values = [headers.get(name) for name in ("payment-required", "x-payment-required") if headers.get(name) is not None]
    if not values or any(not isinstance(value, str) or value != values[0] for value in values):
        return None
    encoded = values[0]
    if not encoded or len(encoded) > 65_536:
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            return None
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, base64.binascii.Error):
        return None
    return parsed if isinstance(parsed, dict) else None


def _public_payment_requirement_projection(candidate: Any) -> dict[str, Any] | None:
    if not isinstance(candidate, dict):
        return None
    projected: dict[str, Any] = {}
    for key in ("scheme", "network", "asset", "amount", "payTo"):
        value = candidate.get(key)
        if not isinstance(value, str) or not value or len(value) > 256:
            return None
        if key in {"asset", "payTo"}:
            value = _address(value)
            if value is None:
                return None
        projected[key] = value
    timeout = candidate.get("maxTimeoutSeconds")
    if isinstance(timeout, int) and not isinstance(timeout, bool) and timeout > 0:
        projected["maxTimeoutSeconds"] = timeout
    extra = candidate.get("extra")
    if isinstance(extra, dict):
        safe_extra = {
            key: value
            for key, value in extra.items()
            if key in {"name", "version", "paymentFlow", "assetTransferMethod"}
            and isinstance(value, str)
            and value
            and len(value) <= 256
        }
        if safe_extra:
            projected["extra"] = safe_extra
    return projected


def _variant_purchase_challenge(
    events: tuple[tuple[EvidenceArtifact, dict[str, Any], dict[str, Any]], ...],
    x402: dict[str, Any],
) -> dict[str, Any] | None:
    pinned_asset = _address(x402.get("asset"))
    for artifact, request, response in events:
        if artifact.boundary not in {"actual-tool-http", "participant-http"}:
            continue
        if not _path_matches(request, "/purchase") or _response_status(response) != 402:
            continue
        for candidate in _payment_requirement_candidates(response):
            if (
                pinned_asset is not None
                and _contains_value(candidate, {"scheme"}, x402.get("scheme"))
                and _payment_network_matches(candidate, str(x402.get("network", "")))
                and _address(_first_nested_value(candidate, {"asset", "token"})) == pinned_asset
                and _contains_value(candidate, {"amount", "price"}, x402.get("amount"))
                and _address(_first_nested_value(candidate, {"payTo"})) is not None
            ):
                return candidate
    return None


def _wrong_token_database_rejection_is_proven(
    evidence: ProbeEvidence, operation_id: str, variant_id: str
) -> bool:
    generation_id = _generation_for_database_operation(evidence, operation_id, variant_id)
    if generation_id is None:
        return False
    operation_rejected = any(
        row.get("operation_id") == operation_id
        and row.get("generation_id") == generation_id
        and row.get("status") == "rejected"
        and row.get("transaction_hash") is None
        for row in _bound_database_rows(evidence, "operation-by-id", operation_id, variant_id)
    )
    denial_recorded = any(
        row.get("operation_id") == operation_id
        and row.get("generation_id") == generation_id
        and row.get("reason_code") == "payment_protocol_rejected"
        for row in _bound_database_rows(evidence, "denials-by-generation", operation_id, variant_id)
    )
    return operation_rejected and denial_recorded


def _payment_signature_was_present(artifact: EvidenceArtifact, request: dict[str, Any]) -> bool:
    if artifact.payload.get("paymentSignaturePresent") is True:
        return True
    headers = _headers(request.get("headers"))
    return headers.get("payment-signature-present") is True or (
        "payment-signature" in headers and _sensitive_value_is_redacted(headers.get("payment-signature"))
    )


def _variant_pay_to(
    events: tuple[tuple[EvidenceArtifact, dict[str, Any], dict[str, Any]], ...], x402: dict[str, Any]
) -> str | None:
    for artifact, request, response in events:
        if _response_status(response) != 402:
            continue
        for candidate in _payment_requirement_candidates(response):
            address = _address(_first_nested_value(candidate, {"payTo"}))
            if address is not None:
                return address
    return _address(_first_nested_value(x402, {"payTo"}))


def _variant_database_has_no_payment_or_delivery(
    evidence: ProbeEvidence, variant: str, operation_id: str
) -> bool:
    empty_queries = set()
    for artifact in evidence.database_artifacts():
        payload = artifact.payload
        if payload.get("variantId") != variant or payload.get("operationId") != operation_id:
            continue
        if payload.get("queryName") in {"payments-by-operation", "deliveries-by-operation"} and payload.get("rows") == []:
            empty_queries.add(payload["queryName"])
    return empty_queries == {"payments-by-operation", "deliveries-by-operation"}


def _variant_database_has_no_delivery(evidence: ProbeEvidence, variant: str, operation_id: str) -> bool:
    return any(
        artifact.payload.get("variantId") == variant
        and artifact.payload.get("operationId") == operation_id
        and artifact.payload.get("queryName") == "deliveries-by-operation"
        and artifact.payload.get("rows") == []
        for artifact in evidence.database_artifacts()
    )


def _variant_balances_are_unchanged(evidence: ProbeEvidence, operation_id: str, payer: str, pay_to: str | None, asset: str) -> bool:
    if pay_to is None:
        return False
    values: dict[tuple[str, str], list[int]] = {}
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        payload = artifact.payload
        if payload.get("operationId") != operation_id or payload.get("method") != "eth_call":
            continue
        params = payload.get("params")
        if not isinstance(params, list) or not params or not isinstance(params[0], dict):
            continue
        call = params[0]
        data = call.get("data")
        if _address(call.get("to")) != asset or not isinstance(data, str) or not re.fullmatch(r"0x70a08231[0-9a-fA-F]{64}", data):
            continue
        account = _topic_address("0x" + data[-64:])
        role = "payer" if account == payer else "payto" if account == pay_to else None
        path = artifact.relative_path.lower()
        phase = "before" if role and role + "-before" in path else "after" if role and role + "-after" in path else None
        value = _numeric(_rpc_result(payload))
        if role is not None and phase is not None and isinstance(value, int) and value >= 0:
            values.setdefault((role, phase), []).append(value)
    return all(
        len(values.get((role, "before"), [])) == len(values.get((role, "after"), [])) == 1
        and values[(role, "before")][0] == values[(role, "after")][0]
        for role in ("payer", "payto")
    )


def _mismatched_resource_bytes_are_proven(evidence: ProbeEvidence, operation_id: str, pinned_hash: str) -> bool:
    expected = pinned_hash.lower().removeprefix("0x")
    for artifact in evidence.resource_artifacts():
        payload = artifact.payload
        if payload.get("variantId") != "mismatched_data" or payload.get("operationId") != operation_id:
            continue
        claimed = payload.get("claimedSha256")
        actual = payload.get("actualDataSha256")
        raw = payload.get("actualContentBytesBase64", payload.get("contentBytesBase64"))
        if not _is_digest(claimed) or not _is_digest(actual) or not isinstance(raw, str):
            continue
        try:
            actual_bytes = base64.b64decode(raw, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        actual_digest = hashlib.sha256(actual_bytes).hexdigest()
        if claimed.lower().removeprefix("0x") == expected and actual.lower().removeprefix("0x") != expected and actual_digest == actual.lower().removeprefix("0x"):
            return True
    return False


def _decoded_http_body(response: dict[str, Any]) -> bytes | None:
    value = response.get("bodyBase64", response.get("rawBodyBase64"))
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def _sc006_observer_is_read_only(evidence: ProbeEvidence) -> bool:
    proofs = [
        artifact.payload for artifact in evidence.database_artifacts()
        if artifact.payload.get("queryName") == "observer-role-effective-privileges"
    ]
    if len(proofs) != 1:
        return False
    proof = proofs[0]
    role = proof.get("role")
    rows = proof.get("rows")
    if (
        proof.get("readOnly") is not True
        or proof.get("databaseRole") != "bef_observer"
        or proof.get("transactionReadOnly") not in (None, "on")
        or not isinstance(role, dict)
        or role.get("role_name") != "bef_observer"
        or not isinstance(rows, list)
    ):
        return False
    required_tables = {
        "bef_operation", "bef_generation", "bef_denial", "bef_payment", "bef_delivery",
        "bef_x402_observation",
    }
    table_names = {
        row.get("table_name") for row in rows if isinstance(row, dict)
    }
    return (
        required_tables.issubset(table_names)
        and len(table_names) == len(rows)
        and _observer_role_is_read_only(evidence)
    )


def _sc006_query_artifacts(
    evidence: ProbeEvidence,
    operation_id: str,
    variant: str,
    query_name: str,
    label_fragment: str | None = None,
) -> tuple[EvidenceArtifact, ...]:
    matching = tuple(
        artifact
        for artifact in evidence.database_artifacts()
        if artifact.payload.get("operationId") == operation_id
        and artifact.payload.get("variantId") == variant
        and artifact.payload.get("queryName") == query_name
        and (label_fragment is None or label_fragment.lower() in artifact.relative_path.lower())
    )
    if not matching or not _sc006_observer_is_read_only(evidence):
        return ()
    if any(
        artifact.payload.get("readOnly") is not True
        or artifact.payload.get("databaseRole") != "bef_observer"
        or artifact.payload.get("transactionReadOnly") != "on"
        for artifact in matching
    ):
        return ()
    return matching


def _sc006_snapshot_rows(
    evidence: ProbeEvidence,
    operation_id: str,
    variant: str,
    query_name: str,
    label_fragment: str,
) -> list[dict[str, Any]] | None:
    artifacts = _sc006_query_artifacts(evidence, operation_id, variant, query_name, label_fragment)
    if len(artifacts) != 1:
        return None
    rows = artifacts[0].payload.get("rows")
    return rows if isinstance(rows, list) and all(isinstance(row, dict) for row in rows) else None


def _sc006_null_receipt(evidence: ProbeEvidence, operation_id: str, transaction_hash: str) -> bool:
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        payload = artifact.payload
        params = payload.get("params")
        if (
            payload.get("operationId") == operation_id
            and payload.get("variantId") == "missing_receipt"
            and payload.get("method") == "eth_getTransactionReceipt"
            and isinstance(params, list)
            and params[:1] == [transaction_hash]
            and _rpc_result(payload) is None
        ):
            return True
    return False


def _sc006_payment_required_offer(response: dict[str, Any], expected_error: str) -> dict[str, Any] | None:
    if _response_status(response) != 402:
        return None
    decoded = response.get("decodedPaymentRequired")
    raw = _decode_payment_required_header(response)
    decoded_protocol = response.get("decodedProtocol")
    protocol_required = decoded_protocol.get("paymentRequired") if isinstance(decoded_protocol, dict) else None
    if (
        not isinstance(decoded, dict)
        or not isinstance(raw, dict)
        or not isinstance(protocol_required, dict)
        or decoded.get("error") != expected_error
        or raw.get("error") != expected_error
        or protocol_required.get("error") != expected_error
        or decoded.get("x402Version") != 2
        or raw.get("x402Version") != 2
        or protocol_required.get("x402Version") != 2
    ):
        return None
    decoded_accepts = decoded.get("accepts")
    raw_accepts = raw.get("accepts")
    protocol_accepts = protocol_required.get("accepts")
    if (
        not isinstance(decoded_accepts, list) or len(decoded_accepts) != 1
        or not isinstance(raw_accepts, list) or len(raw_accepts) != 1
        or not isinstance(protocol_accepts, list) or len(protocol_accepts) != 1
    ):
        return None
    decoded_offer = _sc006_offer_projection(decoded_accepts[0])
    raw_offer = _sc006_offer_projection(raw_accepts[0])
    protocol_offer = _sc006_offer_projection(protocol_accepts[0])
    selected_offer = _sc006_offer_projection(decoded_protocol.get("selectedPaymentRequirements"))
    if (
        decoded_offer is None
        or decoded_offer != raw_offer
        or decoded_offer != protocol_offer
        or decoded_offer != selected_offer
    ):
        return None
    return decoded_offer


def _sc006_offer_projection(candidate: Any) -> dict[str, Any] | None:
    required_fields = {"scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds", "extra"}
    allowed_extra = {"name", "version", "paymentFlow", "assetTransferMethod"}
    if not isinstance(candidate, dict) or set(candidate) != required_fields:
        return None
    extra = candidate.get("extra")
    timeout = candidate.get("maxTimeoutSeconds")
    if (
        not isinstance(extra, dict)
        or set(extra) != allowed_extra
        or isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or timeout <= 0
    ):
        return None
    return _public_payment_requirement_projection(candidate)


def _sc006_offer_matches_manifest(offer: dict[str, Any], x402: dict[str, Any]) -> bool:
    domain = x402.get("eip712Domain")
    if not isinstance(domain, dict):
        return False
    extra = offer.get("extra")
    expected_extra = {
        "name": domain.get("name"),
        "version": domain.get("version"),
        "paymentFlow": "authorization",
        "assetTransferMethod": x402.get("assetTransferMethod"),
    }
    return (
        offer.get("scheme") == x402.get("scheme")
        and offer.get("network") == x402.get("network")
        and _address(offer.get("asset")) == _address(x402.get("asset"))
        and offer.get("amount") == x402.get("amount")
        and offer.get("maxTimeoutSeconds") == x402.get("maxTimeoutSeconds")
        and _address(offer.get("payTo")) is not None
        and isinstance(extra, dict)
        and extra == expected_extra
    )


def _sc006_signed_payload(
    artifact: EvidenceArtifact, request: dict[str, Any], expected_resource_id: str
) -> tuple[dict[str, Any], str] | None:
    headers = _headers(request.get("headers"))
    signature = headers.get("payment-signature", headers.get("x-payment-signature"))
    signature_digest = headers.get("payment-signature-sha256", headers.get("x-payment-signature-sha256"))
    decoded = request.get("decodedPaymentPayload")
    body = request.get("body")
    selected = decoded.get("accepted") if isinstance(decoded, dict) else None
    if (
        not _payment_signature_was_present(artifact, request)
        or headers.get("payment-signature-present", headers.get("x-payment-signature-present")) is not True
        or not _sensitive_value_is_redacted(signature)
        or not _is_digest(signature_digest)
        or not isinstance(decoded, dict)
        or decoded.get("x402Version") != 2
        or decoded.get("sourceHeaderSha256") != signature_digest
        or not isinstance(selected, dict)
        or not isinstance(body, dict)
        or body.get("resourceId") != expected_resource_id
    ):
        return None
    projection = _sc006_offer_projection(selected)
    return (projection, signature_digest) if projection is not None else None


def _sc006_reused_authorization_digest(
    evidence: ProbeEvidence,
    resource_id: str,
    operation_id: str,
    canonical_offer: dict[str, Any],
) -> str | None:
    originals = [
        (artifact, request)
        for artifact, request, _response in _variant_http(evidence, "missing_receipt")
        if artifact.boundary == "actual-tool-http"
        and request.get("method") == "POST"
        and _path_matches(request, "/purchase")
        and _payment_signature_was_present(artifact, request)
    ]
    if len(originals) != 1:
        return None
    artifact, request = originals[0]
    if _operation_id(artifact) in {None, operation_id}:
        return None
    signed = _sc006_signed_payload(artifact, request, resource_id)
    if signed is None or signed[0] != canonical_offer:
        return None
    return signed[1]


def _sc006_reused_authorization_observation_is_rejected(
    evidence: ProbeEvidence,
    operation_id: str,
    variant: str,
    generation_id: str,
    payer: str,
    canonical_offer: dict[str, Any],
) -> bool:
    artifacts = _sc006_query_artifacts(
        evidence, operation_id, variant, "x402-observations-by-operation"
    )
    if not artifacts:
        return False
    rows: list[dict[str, Any]] = []
    for artifact in artifacts:
        values = artifact.payload.get("rows")
        if not isinstance(values, list) or not all(isinstance(row, dict) for row in values):
            return False
        rows.extend(values)
    rows = [row for row in rows if row]
    if not rows:
        return False
    for row in rows:
        safe_request = row.get("safe_request")
        safe_response = row.get("safe_response")
        payment_payload = safe_request.get("paymentPayload") if isinstance(safe_request, dict) else None
        accepted = payment_payload.get("accepted") if isinstance(payment_payload, dict) else None
        payment_requirements = safe_request.get("paymentRequirements") if isinstance(safe_request, dict) else None
        if (
            row.get("operation_id") != operation_id
            or row.get("generation_id") != generation_id
            or row.get("variant_id") not in {variant, "baseline"}
            or row.get("phase") != "verify"
            or row.get("outcome") != "rejected"
            or row.get("transaction_hash") is not None
            or not isinstance(safe_response, dict)
            or safe_response.get("isValid") is not False
            or safe_response.get("invalidReason") != "verification_rejected"
            or safe_response.get("invalidMessage") != "verification_rejected"
            or _address(safe_response.get("payer")) != payer
            or _sc006_offer_projection(accepted) != canonical_offer
            or _sc006_offer_projection(payment_requirements) != canonical_offer
        ):
            return False
    return True


def _invalid_payment_variants_are_denied(evidence: ProbeEvidence) -> bool:
    x402 = _manifest(evidence, "x402")
    resource_id = x402.get("resourceId")
    if not _sc006_observer_is_read_only(evidence) or not isinstance(resource_id, str):
        return False
    expected_errors = {
        "wrong_domain": "No matching payment requirements",
        "amount_mismatch": "No matching payment requirements",
        "reused_authorization": "verification_rejected",
    }
    canonical_offer: dict[str, Any] | None = None
    for variant, expected_error in expected_errors.items():
        events = [
            (artifact, request, response)
            for artifact, request, response in _variant_http(evidence, variant)
            if artifact.boundary == "actual-tool-http"
            and _path_matches(request, "/purchase")
            and request.get("method") == "POST"
        ]
        challenges = [
            (artifact, request, response) for artifact, request, response in events
            if not _payment_signature_was_present(artifact, request)
        ]
        signed = [
            (artifact, request, response) for artifact, request, response in events
            if _payment_signature_was_present(artifact, request)
        ]
        if len(events) != 2 or len(challenges) != 1 or len(signed) != 1:
            return False
        challenge_artifact, challenge_request, challenge_response = challenges[0]
        signed_artifact, signed_request, signed_response = signed[0]
        operation_ids = {
            _operation_id(challenge_artifact), _operation_id(signed_artifact),
        }
        if len(operation_ids) != 1 or None in operation_ids:
            return False
        operation_id = next(iter(operation_ids))
        if (
            not isinstance(challenge_request.get("body"), dict)
            or challenge_request["body"].get("resourceId") != resource_id
            or not isinstance(signed_request.get("body"), dict)
            or signed_request["body"].get("resourceId") != resource_id
        ):
            return False
        challenge_offer = _sc006_payment_required_offer(challenge_response, "Payment required")
        if challenge_offer is None or not _sc006_offer_matches_manifest(challenge_offer, x402):
            return False
        if canonical_offer is None:
            canonical_offer = challenge_offer
        elif challenge_offer != canonical_offer:
            return False
        signed_payload = _sc006_signed_payload(signed_artifact, signed_request, resource_id)
        if signed_payload is None:
            return False
        selected_offer, signature_digest = signed_payload
        if _sc006_payment_required_offer(signed_response, expected_error) != canonical_offer:
            return False
        if variant == "wrong_domain":
            selected_extra = selected_offer.get("extra")
            expected_extra = canonical_offer.get("extra")
            if (
                not isinstance(selected_extra, dict)
                or not isinstance(expected_extra, dict)
                or selected_extra.get("name") == expected_extra.get("name")
                or {**selected_offer, "extra": {**selected_extra, "name": expected_extra.get("name")}} != canonical_offer
            ):
                return False
        elif variant == "amount_mismatch":
            amount = selected_offer.get("amount")
            canonical_amount = canonical_offer.get("amount")
            if (
                not isinstance(amount, str)
                or not re.fullmatch(r"[0-9]+", amount)
                or not isinstance(canonical_amount, str)
                or not re.fullmatch(r"[0-9]+", canonical_amount)
                or int(amount) <= 0
                or int(amount) == int(canonical_amount)
                or {**selected_offer, "amount": canonical_amount} != canonical_offer
            ):
                return False
        elif (
            selected_offer != canonical_offer
            or (reused_digest := _sc006_reused_authorization_digest(
                evidence, resource_id, operation_id, canonical_offer
            )) is None
            or signature_digest != reused_digest
        ):
            return False

        operation_artifacts = _sc006_query_artifacts(evidence, operation_id, variant, "operation-by-id")
        operation_rows: list[dict[str, Any]] = []
        for artifact in operation_artifacts:
            rows = artifact.payload.get("rows")
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return False
            if any(row.get("operation_id") != operation_id for row in rows):
                return False
            operation_rows.extend(rows)
        if not operation_rows:
            return False
        operation_signature = {
            (
                row.get("generation_id"), row.get("status"), row.get("receipt_status"),
                row.get("transaction_hash"), row.get("operation_kind"), row.get("env_id"),
            )
            for row in operation_rows
        }
        if len(operation_signature) != 1:
            return False
        generation_id, status, receipt_status, transaction_hash, operation_kind, env_id = next(iter(operation_signature))
        if (
            not isinstance(generation_id, str)
            or status != "rejected"
            or receipt_status != "not_submitted"
            or transaction_hash is not None
            or operation_kind != "purchase"
            or env_id != evidence.environment_id
        ):
            return False
        generation_artifacts = _sc006_query_artifacts(evidence, operation_id, variant, "generation-by-id")
        generation_rows: list[dict[str, Any]] = []
        for artifact in generation_artifacts:
            rows = artifact.payload.get("rows")
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return False
            if any(row.get("generation_id") != generation_id for row in rows):
                return False
            generation_rows.extend(rows)
        payers = {_address(row.get("payer_address")) for row in generation_rows}
        payers.discard(None)
        if not generation_rows or len(payers) != 1:
            return False
        payer = next(iter(payers))
        denial_artifacts = _sc006_query_artifacts(evidence, operation_id, variant, "denials-by-generation")
        denial_rows: list[dict[str, Any]] = []
        for artifact in denial_artifacts:
            rows = artifact.payload.get("rows")
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return False
            if any(row.get("operation_id") != operation_id for row in rows):
                return False
            denial_rows.extend(rows)
        denial_ids = {
            row.get("denial_id") for row in denial_rows
            if row.get("operation_id") == operation_id
            and row.get("generation_id") == generation_id
            and row.get("env_id") == evidence.environment_id
            and row.get("reason_code") == "payment_protocol_rejected"
        }
        if not denial_artifacts or not denial_rows or None in denial_ids or len(denial_ids) != 1:
            return False
        if any(
            row.get("generation_id") != generation_id
            or row.get("env_id") != evidence.environment_id
            or row.get("reason_code") != "payment_protocol_rejected"
            for row in denial_rows
        ):
            return False
        for query_name in ("payments-by-operation", "deliveries-by-operation"):
            query_artifacts = _sc006_query_artifacts(evidence, operation_id, variant, query_name)
            if not query_artifacts or any(item.payload.get("rows") != [] for item in query_artifacts):
                return False
        x402_artifacts = _sc006_query_artifacts(evidence, operation_id, variant, "x402-observations-by-operation")
        if not x402_artifacts:
            return False
        if variant == "reused_authorization":
            if not _sc006_reused_authorization_observation_is_rejected(
                evidence, operation_id, variant, generation_id, payer, canonical_offer
            ):
                return False
        elif any(item.payload.get("rows") != [] for item in x402_artifacts):
            return False
        if any(_operation_id(receipt) == operation_id for receipt in _receipt_records(evidence)):
            return False
        pay_to = _address(canonical_offer.get("payTo"))
        asset = _address(x402.get("asset"))
        if payer is None or pay_to is None or asset is None:
            return False
        if not _variant_balances_are_unchanged(evidence, operation_id, payer, pay_to, asset):
            return False
    return True


def _duplicate_retries_keep_identity(evidence: ProbeEvidence) -> bool:
    loss = [
        item for item in _http_records(evidence)
        if item[0].payload.get("variantId") == "response_loss"
        and item[0].boundary == "actual-tool-http"
        and _path_matches(item[1], "/purchase")
    ]
    duplicates = [
        item for item in _http_records(evidence)
        if item[0].payload.get("variantId") == "concurrent_duplicate"
        and item[0].boundary == "actual-tool-http"
        and _path_matches(item[1], "/purchase")
        and _successful_http(item[2])
    ]
    if len(loss) != 1 or len(duplicates) < 2:
        return False
    operation_ids = {_operation_id(item[0]) for item in [loss[0], *duplicates]}
    if len(operation_ids) != 1 or None in operation_ids:
        return False
    operation_id = next(iter(operation_ids))
    loss_response = loss[0][2]
    relay_event_payload: dict[str, Any] | None = None
    if _response_status(loss_response) in {502, 503}:
        loss_body = _response_body(loss_response)
        if not isinstance(loss_body.get("error"), str) or "unknown" not in loss_body["error"]:
            return False
    else:
        relay_events = [
            artifact.payload for artifact in evidence.artifacts
            if artifact.boundary == "probe-owned-response-loss-relay"
            and artifact.payload.get("schemaVersion") == "bef-sc006-response-loss-relay/v1"
            and artifact.payload.get("operationId") == operation_id
            and artifact.payload.get("variantId") == "response_loss"
        ]
        if len(relay_events) == 1:
            relay_event_payload = relay_events[0]
        expected_resource = _manifest(evidence, "x402")
        if (loss_response.get("transportError") != "connection_closed"
            or loss_response.get("relayUpstreamStatus") != 200
            or len(relay_events) != 1
            or relay_event_payload is None
            or relay_event_payload.get("upstreamStatus") != 200
            or relay_event_payload.get("downstreamClosedWithoutResponse") is not True
            or relay_event_payload.get("deliveredOperationId") != operation_id
            or relay_event_payload.get("deliveredResourceId") != expected_resource.get("resourceId")
            or str(relay_event_payload.get("deliveredContentSha256", "")).lower()
                != str(expected_resource.get("resourceSha256", "")).lower().removeprefix("0x")
            or relay_event_payload.get("idempotencyKeySha256") != hashlib.sha256(
                str(_headers(loss[0][1].get("headers")).get("idempotency-key", "")).encode("utf-8")
            ).hexdigest()):
            return False
    requests = [item[1] for item in duplicates]
    keys = [
        _headers(request.get("headers")).get("idempotency-key")
        for request in requests
    ]
    if not all(isinstance(key, str) and key for key in keys) or len(set(keys)) != 1:
        return False
    authorization_hashes = [
        _headers(request.get("headers")).get("authorization-sha256")
        for request in [loss[0][1], *requests]
    ]
    if not all(_is_digest(value) for value in authorization_hashes) or len(set(authorization_hashes)) != 1:
        return False
    if any(_headers(request.get("headers")).get("payment-signature-present") is True for request in requests):
        return False
    bodies = [_body_object(request.get("body")) for request in requests]
    responses = [_response_body(item[2]) for item in duplicates]
    if any(body != bodies[0] for body in bodies[1:]) or any(
        _operation_id(item[0]) != operation_id or _response_body(item[2]).get("operationId") != operation_id
        for item in duplicates
    ):
        return False
    if any(response.get("contentHash") != responses[0].get("contentHash")
           or response.get("contentBytes") != responses[0].get("contentBytes") for response in responses[1:]):
        return False
    expected_key_hash = hashlib.sha256(keys[0].encode("utf-8")).hexdigest()
    operations = [op for op in _operation_records(evidence) if op.get("operationId") == operation_id]
    if len(operations) != 1 or operations[0].get("idempotencyKeyHash") != expected_key_hash:
        return False
    if operations[0].get("observedStatus") != "delivered" or operations[0].get("receiptStatus") != "success":
        return False
    order = {artifact.relative_path: index for index, artifact in enumerate(evidence.artifacts)}
    loss_position = order.get(loss[0][0].relative_path)
    duplicate_positions = [order.get(item[0].relative_path) for item in duplicates]
    if relay_event_payload is not None:
        relay_start = _numeric(relay_event_payload.get("upstreamMonotonicStartMs"))
        relay_end = _numeric(relay_event_payload.get("upstreamMonotonicObservedMs"))
        if relay_start is None or relay_end is None or relay_end <= relay_start:
            return False
        overlapping = 0
        for artifact, request, response in duplicates:
            request_start = _numeric(request.get("monotonicStartMs"))
            response_end = _numeric(response.get("monotonicObservedMs"))
            if request_start is not None and response_end is not None and request_start < relay_end and response_end > relay_start:
                overlapping += 1
        if overlapping < 2:
            return False
        return loss_position is not None and all(position is not None for position in duplicate_positions)
    return loss_position is not None and all(position is not None and position > loss_position for position in duplicate_positions)


def _one_durable_settlement(evidence: ProbeEvidence) -> bool:
    loss_ids = {
        _operation_id(artifact)
        for artifact, request, _ in _http_records(evidence)
        if artifact.payload.get("variantId") == "response_loss" and _path_matches(request, "/purchase")
    }
    if len(loss_ids) != 1 or None in loss_ids:
        return False
    operation_id = next(iter(loss_ids))
    original_rows = _sc006_snapshot_rows(evidence, operation_id, "response_loss", "payments-by-operation", "after-original-reconciliation")
    final_rows = _sc006_snapshot_rows(evidence, operation_id, "concurrent_duplicate", "payments-by-operation", "after-concurrent-duplicate")
    if original_rows is None or final_rows is None or len(original_rows) != 1 or len(final_rows) != 1:
        return False
    payments = [original_rows[0], final_rows[0]]
    payment_ids = {row.get("payment_id") for row in payments}
    hashes = {str(row.get("transaction_hash", "")).lower() for row in payments}
    if len(payment_ids) != 1 or None in payment_ids or len(hashes) != 1 or "" in hashes:
        return False
    transaction_hash = next(iter(hashes))
    if not _HEX_32_RE.fullmatch(transaction_hash):
        return False
    manifest = _manifest(evidence, "x402")
    expected_payer = _payer_for_database_operation(evidence, operation_id, "response_loss")
    expected_amount = str(manifest.get("amount", ""))
    expected_asset = _address(manifest.get("asset"))
    expected_network = manifest.get("network")
    if expected_payer is None or expected_asset is None or not expected_amount or not isinstance(expected_network, str):
        return False
    if any(
        row.get("operation_id") != operation_id
        or row.get("receipt_status") != "success"
        or str(row.get("amount_units")) != expected_amount
        or str(row.get("token_delta_units")) != expected_amount
        or _address(row.get("payer_address")) != expected_payer
        or _address(row.get("asset_address")) != expected_asset
        or row.get("network") != expected_network
        for row in payments
    ):
        return False
    successful_receipts = [
        receipt for receipt in _receipt_records(evidence, 1)
        if _operation_id(receipt) == operation_id and _tx_hash_from_receipt(receipt.payload) == transaction_hash
    ]
    if not successful_receipts or {
        _tx_hash_from_receipt(receipt.payload) for receipt in successful_receipts
    } != {transaction_hash}:
        return False
    observations: dict[str, dict[str, Any]] = {}
    for variant, label in (("response_loss", "after-original-reconciliation"), ("concurrent_duplicate", "after-concurrent-duplicate")):
        for artifact in _sc006_query_artifacts(evidence, operation_id, variant, "x402-observations-by-operation", label):
            for row in artifact.payload.get("rows", []):
                if isinstance(row, dict) and row.get("phase") == "settle":
                    if row.get("operation_id") != operation_id or row.get("outcome") not in {"success", "unknown"}:
                        return False
                    observation_id = row.get("observation_id")
                    if not isinstance(observation_id, str) or not observation_id:
                        return False
                    previous = observations.get(observation_id)
                    if previous is not None and previous != row:
                        return False
                    observations[observation_id] = row
    if not 1 <= len(observations) <= 2:
        return False
    settles = list(observations.values())
    variant_ids = {row.get("variant_id") for row in settles}
    if len(variant_ids) != 1 or not isinstance(next(iter(variant_ids)), str) or not next(iter(variant_ids)):
        return False
    request_hashes = {str(row.get("request_sha256", "")).strip().lower() for row in settles}
    if len(request_hashes) != 1 or not _is_digest(next(iter(request_hashes))):
        return False
    safe_requests = [row.get("safe_request") for row in settles]
    if any(not isinstance(request, dict) for request in safe_requests) or any(request != safe_requests[0] for request in safe_requests[1:]):
        return False
    safe_request = safe_requests[0]
    requirements = safe_request.get("paymentRequirements")
    if not isinstance(requirements, dict):
        return False
    x402_scheme = manifest.get("scheme")
    if (isinstance(x402_scheme, str) and requirements.get("scheme") != x402_scheme
        or requirements.get("network") != expected_network
        or _address(requirements.get("asset")) != expected_asset
        or str(requirements.get("amount")) != expected_amount):
        return False
    pay_to = _address(requirements.get("payTo"))
    settle_hashes = {
        str(row.get("transaction_hash")).lower()
        for row in settles if row.get("transaction_hash") is not None
    }
    if settle_hashes != {transaction_hash}:
        return False
    return (
        pay_to is not None
        and _address(payments[0].get("facilitator_address")) == pay_to
        and _address(payments[1].get("facilitator_address")) == pay_to
    )


def _one_durable_delivery(evidence: ProbeEvidence) -> bool:
    operation_ids = {
        _operation_id(artifact)
        for artifact, request, _ in _http_records(evidence)
        if artifact.payload.get("variantId") == "concurrent_duplicate" and _path_matches(request, "/purchase")
    }
    if len(operation_ids) != 1 or None in operation_ids:
        return False
    operation_id = next(iter(operation_ids))
    rows = _sc006_snapshot_rows(evidence, operation_id, "concurrent_duplicate", "deliveries-by-operation", "after-concurrent-duplicate")
    if rows is None or len(rows) != 1:
        return False
    row = rows[0]
    x402 = _manifest(evidence, "x402")
    pinned_hash = x402.get("resourceSha256")
    pinned_resource_id = x402.get("resourceId")
    if (
        row.get("operation_id", row.get("operationId")) != operation_id
        or row.get("resource_id", row.get("resourceId")) != pinned_resource_id
        or not isinstance(pinned_hash, str)
        or not _is_digest(pinned_hash)
        or str(row.get("content_sha256", row.get("contentSha256", ""))).lower() != pinned_hash.lower()
    ):
        return False
    responses = [
        _response_body(response)
        for artifact, request, response in _http_records(evidence)
        if artifact.payload.get("variantId") == "concurrent_duplicate"
        and _path_matches(request, "/purchase") and _successful_http(response)
        and _operation_id(artifact) == operation_id
    ]
    if len(responses) < 2:
        return False
    for response in responses:
        encoded = response.get("contentBytes")
        response_hash = response.get("contentHash")
        if (
            response.get("resourceId") != pinned_resource_id
            or not isinstance(response_hash, str)
            or response_hash.lower().removeprefix("0x") != pinned_hash.lower().removeprefix("0x")
            or not isinstance(encoded, str)
        ):
            return False
        try:
            raw = base64.b64decode(encoded, validate=True)
            expected_bytes = int(row.get("content_bytes", row.get("contentBytes", -1)))
        except (TypeError, ValueError, base64.binascii.Error):
            return False
        if hashlib.sha256(raw).hexdigest() != pinned_hash.lower().removeprefix("0x"):
            return False
        if len(raw) != expected_bytes:
            return False
    return any(
        op.get("operationId") == operation_id and op.get("observedStatus") == "delivered"
        and op.get("receiptStatus") == "success" for op in _operation_records(evidence)
    )


def _unknown_receipt_is_not_success(evidence: ProbeEvidence) -> bool:
    http = _http_records(evidence)
    failed_purchase = [
        item for item in http
        if item[0].boundary == "actual-tool-http"
        and item[0].payload.get("variantId") == "missing_receipt"
        and _path_matches(item[1], "/purchase")
        and _response_status(item[2]) == 502
    ]
    if len(failed_purchase) != 1:
        return False
    operation_id = _operation_id(failed_purchase[0][0])
    if operation_id is None:
        return False
    initial_key = _headers(failed_purchase[0][1].get("headers")).get("idempotency-key")
    if not isinstance(initial_key, str) or not initial_key:
        return False
    unknown_retries = [
        item for item in http
        if item[0].boundary == "actual-tool-http"
        and item[0].payload.get("variantId") == "missing_receipt"
        and _operation_id(item[0]) == operation_id
        and _path_matches(item[1], "/purchase")
        and _response_status(item[2]) == 409
    ]
    if (len(unknown_retries) != 1
        or _headers(unknown_retries[0][1].get("headers")).get("idempotency-key") != initial_key
        or _headers(unknown_retries[0][1].get("headers")).get("payment-signature-present") is True
        or "unknown" not in str(_response_body(unknown_retries[0][2]).get("error", "")).lower()):
        return False
    unresolved = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "operation-by-id", "missing-receipt-after-unavailable")
    unresolved_payments = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "payments-by-operation", "missing-receipt-after-unavailable")
    unresolved_deliveries = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "deliveries-by-operation", "missing-receipt-after-unavailable")
    if (unresolved is None or len(unresolved) != 1 or unresolved[0].get("status") != "settlement_unknown"
        or unresolved[0].get("receipt_status") != "unknown" or unresolved_payments is None or len(unresolved_payments) != 1
        or unresolved_payments[0].get("receipt_status") != "unknown" or unresolved_deliveries != []):
        return False
    transaction_hash = str(unresolved[0].get("transaction_hash") or unresolved_payments[0].get("transaction_hash") or "").lower()
    if not _HEX_32_RE.fullmatch(transaction_hash):
        return False
    retried_unresolved = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "operation-by-id", "after-unknown-retry")
    retried_payments = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "payments-by-operation", "after-unknown-retry")
    retried_deliveries = _sc006_snapshot_rows(evidence, operation_id, "missing_receipt", "deliveries-by-operation", "after-unknown-retry")
    if (retried_unresolved is None or len(retried_unresolved) != 1
        or retried_unresolved[0].get("status") != "settlement_unknown"
        or retried_unresolved[0].get("receipt_status") != "unknown"
        or str(retried_unresolved[0].get("transaction_hash", "")).lower() != transaction_hash
        or retried_payments is None or len(retried_payments) != 1
        or retried_payments[0].get("receipt_status") != "unknown"
        or str(retried_payments[0].get("transaction_hash", "")).lower() != transaction_hash
        or retried_deliveries != []):
        return False

    fault_status = [
        item for item in http
        if item[0].boundary == "facilitator-http"
        and item[0].payload.get("variantId") == "missing_receipt"
        and _path_matches(item[1], "/receipt-read-fault/status/")
    ]
    fault_restore = [
        item for item in http
        if item[0].boundary == "facilitator-http"
        and item[0].payload.get("variantId") == "missing_receipt"
        and _path_matches(item[1], "/receipt-read-fault/restore")
    ]
    reconciliations = [
        item for item in http
        if item[0].boundary == "facilitator-http"
        and item[0].payload.get("variantId") == "missing_receipt"
        and _path_matches(item[1], "/reconcile-original-settlement")
    ]
    if len(fault_status) != 1 or len(fault_restore) != 1 or len(reconciliations) != 1:
        return False
    fault = _response_body(fault_status[0][2])
    restore = _response_body(fault_restore[0][2])
    reconciliation = _response_body(reconciliations[0][2])
    broadcasts = fault.get("broadcastHashes")
    if (fault.get("applied") is not True or fault.get("faultedReads") != 1
        or str(fault.get("transactionHash", "")).lower() != transaction_hash
        or not isinstance(broadcasts, list) or len(broadcasts) != 1
        or str(broadcasts[0]).lower() != transaction_hash
        or restore.get("restored") is not True or restore.get("applied") is not True
        or str(restore.get("transactionHash", "")).lower() != transaction_hash
        or reconciliation.get("accepted") is not True
        or reconciliation.get("reasonCode") != "original_settlement_reconciled"):
        return False

    successful_receipts = [
        artifact for artifact in _receipt_records(evidence, 1)
        if _operation_id(artifact) == operation_id and _tx_hash_from_receipt(artifact.payload) == transaction_hash
    ]
    if not successful_receipts:
        return False
    settled = _sc006_snapshot_rows(evidence, operation_id, "response_loss", "operation-by-id", "after-original-reconciliation")
    settled_payments = _sc006_snapshot_rows(evidence, operation_id, "response_loss", "payments-by-operation", "after-original-reconciliation")
    settled_deliveries = _sc006_snapshot_rows(evidence, operation_id, "response_loss", "deliveries-by-operation", "after-original-reconciliation")
    if (settled is None or len(settled) != 1 or settled[0].get("status") != "settled"
        or settled[0].get("receipt_status") != "success" or str(settled[0].get("transaction_hash", "")).lower() != transaction_hash
        or settled_payments is None or len(settled_payments) != 1 or settled_payments[0].get("receipt_status") != "success"
        or str(settled_payments[0].get("transaction_hash", "")).lower() != transaction_hash
        or settled_deliveries != []):
        return False

    response_loss = [
        item for item in http
        if item[0].boundary == "actual-tool-http"
        and item[0].payload.get("variantId") == "response_loss"
        and _operation_id(item[0]) == operation_id and _path_matches(item[1], "/purchase")
    ]
    relay_events = [
        artifact for artifact in evidence.artifacts
        if artifact.boundary == "probe-owned-response-loss-relay"
        and artifact.payload.get("operationId") == operation_id
        and artifact.payload.get("variantId") == "response_loss"
    ]
    duplicates = [
        item for item in http
        if item[0].boundary == "actual-tool-http"
        and item[0].payload.get("variantId") == "concurrent_duplicate"
        and _operation_id(item[0]) == operation_id and _path_matches(item[1], "/purchase")
        and _successful_http(item[2])
    ]
    if len(response_loss) != 1 or len(relay_events) != 1 or len(duplicates) < 2:
        return False
    response = response_loss[0][2]
    relay = relay_events[0].payload
    if (response.get("transportError") != "connection_closed" or response.get("relayUpstreamStatus") != 200
        or relay.get("upstreamStatus") != 200 or relay.get("downstreamClosedWithoutResponse") is not True
        or relay.get("idempotencyKeySha256") != hashlib.sha256(initial_key.encode("utf-8")).hexdigest()
        or any(_headers(item[1].get("headers")).get("idempotency-key") != initial_key for item in duplicates)):
        return False
    final = _sc006_snapshot_rows(evidence, operation_id, "concurrent_duplicate", "operation-by-id", "after-concurrent-duplicate")
    final_deliveries = _sc006_snapshot_rows(evidence, operation_id, "concurrent_duplicate", "deliveries-by-operation", "after-concurrent-duplicate")
    if (final is None or len(final) != 1 or final[0].get("status") != "delivered"
        or final[0].get("receipt_status") != "success" or str(final[0].get("transaction_hash", "")).lower() != transaction_hash
        or final_deliveries is None or len(final_deliveries) != 1):
        return False
    settled_artifacts = _sc006_query_artifacts(evidence, operation_id, "response_loss", "operation-by-id", "after-original-reconciliation")
    final_artifacts = _sc006_query_artifacts(evidence, operation_id, "concurrent_duplicate", "operation-by-id", "after-concurrent-duplicate")
    retried_unresolved_artifacts = _sc006_query_artifacts(evidence, operation_id, "missing_receipt", "operation-by-id", "after-unknown-retry")
    if len(settled_artifacts) != 1 or len(final_artifacts) != 1 or len(retried_unresolved_artifacts) != 1:
        return False
    positions = {artifact.relative_path: index for index, artifact in enumerate(evidence.artifacts)}
    ordered_before_recovery = [
        failed_purchase[0][0], unknown_retries[0][0], retried_unresolved_artifacts[0], fault_status[0][0],
        successful_receipts[0], fault_restore[0][0], reconciliations[0][0], settled_artifacts[0],
    ]
    if not all(positions.get(left.relative_path, -1) < positions.get(right.relative_path, -1)
               for left, right in zip(ordered_before_recovery, ordered_before_recovery[1:])):
        return False
    settled_position = positions.get(settled_artifacts[0].relative_path, -1)
    final_position = positions.get(final_artifacts[0].relative_path, -1)
    concurrent_request_positions = [positions.get(response_loss[0][0].relative_path)] + [
        positions.get(item[0].relative_path) for item in duplicates
    ]
    return settled_position >= 0 and final_position > settled_position and all(
        position is not None and settled_position < position < final_position
        for position in concurrent_request_positions
    )


def _variant_http(evidence: ProbeEvidence, variant: str) -> tuple[tuple[EvidenceArtifact, dict[str, Any], dict[str, Any]], ...]:
    return tuple(item for item in _http_records(evidence) if item[0].payload.get("variantId") == variant)


def _variant_receipt(evidence: ProbeEvidence, variant: str, status: int | None = None) -> bool:
    return any(
        item.payload.get("variantId") == variant
        and (status is None or _receipt_status(_rpc_result(item.payload)) == status)
        for item in _receipt_records(evidence)
    )


def _selected_contract_code_matches(evidence: ProbeEvidence) -> bool:
    contracts = _manifest(evidence, "contracts")
    expected = []
    for name in ("swapRouter02", "pool", "weth"):
        item = contracts.get(name)
        if isinstance(item, dict) and isinstance(item.get("address"), str) and _is_digest(item.get("codeHash")):
            expected.append((item["address"].lower(), item["codeHash"].lower().removeprefix("0x")))
    observed = {}
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        payload = artifact.payload
        if payload.get("method") != "eth_getCode":
            continue
        params = payload.get("params")
        code = _rpc_result(payload)
        if isinstance(params, list) and params and isinstance(params[0], str) and isinstance(code, str) and _HEX_RE.fullmatch(code):
            observed[params[0].lower()] = _keccak256(bytes.fromhex(code[2:])).hex()
    return bool(expected) and all(observed.get(address) == digest for address, digest in expected)


_V3_SWAP_TOPIC = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"


def _swap_receipts_contain_events(evidence: ProbeEvidence) -> bool:
    pool = _address(_manifest(evidence, "contracts").get("pool", {}).get("address"))
    if pool is None:
        return False
    for receipt in _receipt_records(evidence, 1):
        for log in _receipt_transfer_logs(receipt):
            topics = log.get("topics")
            if _address(log.get("address")) == pool and isinstance(topics, list) and topics and str(topics[0]).lower() == _V3_SWAP_TOPIC:
                return _receipt_has_operation_identity(evidence, receipt)
    return False


def _swap_token_deltas_are_observed(evidence: ProbeEvidence) -> bool:
    successful = _receipt_records(evidence, 1)
    if not successful:
        return False
    for receipt in successful:
        tx_hash = _tx_hash_from_receipt(receipt.payload)
        transfer_amounts = [item["amount"] for item in _decoded_transfers(receipt)]
        matching_rows = [row for art, row in _db_rows_with_source(evidence, ("swap", "balance", "effect"))
                         if art.payload.get("operationId") == _operation_id(receipt)
                         and _contains_value(row, {"transactionHash", "txHash"}, tx_hash)]
        if transfer_amounts and matching_rows and any(_nested_values(row, {"amountIn", "amountOut", "inputDelta", "outputDelta"}) for row in matching_rows):
            return True
    return False


def _allowance_reads_match_selected_approval(evidence: ProbeEvidence) -> bool:
    approval_receipts = [
        artifact for artifact, request, response in _http_records(evidence)
        if artifact.boundary in {"actual-tool-http", "participant-http"}
        and _path_matches(request, "/approve") and _successful_http(response)
    ]
    reads = []
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        if artifact.payload.get("method") != "eth_call":
            continue
        params = artifact.payload.get("params")
        if isinstance(params, list) and params and isinstance(params[0], dict):
            data = params[0].get("data")
            if isinstance(data, str) and data.lower().startswith("0xdd62ed3e") and _rpc_result(artifact.payload) is not None:
                reads.append(artifact)
    return bool(approval_receipts) and bool(reads) and any(_operation_id(read) in {_operation_id(item) for item in approval_receipts} for read in reads)


def _pool_reserve_reads_are_pinned(evidence: ProbeEvidence) -> bool:
    pool = _address(_manifest(evidence, "contracts").get("pool", {}).get("address"))
    observed = []
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        if artifact.payload.get("method") != "eth_call":
            continue
        params = artifact.payload.get("params")
        if isinstance(params, list) and params and isinstance(params[0], dict) and _address(params[0].get("to")) == pool:
            data = params[0].get("data")
            if isinstance(data, str) and data.lower().startswith(("0x3850c7bd", "0x1a686502")) and _rpc_result(artifact.payload) is not None:
                observed.append(artifact.payload)
    return len(observed) >= 2 and all(item.get("requestedBlock") is not None or item.get("params", [None, None])[-1] is not None for item in observed)


def _native_and_wrapped_assets_are_separate(evidence: ProbeEvidence) -> bool:
    weth = _address(_manifest(evidence, "contracts").get("weth", {}).get("address"))
    native = [item for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
              if item.payload.get("method") == "eth_getBalance"]
    wrapped = [item for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
               if item.payload.get("method") == "eth_call"
               and isinstance(item.payload.get("params"), list)
               and item.payload["params"] and isinstance(item.payload["params"][0], dict)
               and _address(item.payload["params"][0].get("to")) == weth
               and isinstance(item.payload["params"][0].get("data"), str)
               and item.payload["params"][0]["data"].lower().startswith("0x70a08231")]
    return bool(native) and bool(wrapped) and all(_rpc_result(item.payload) is not None for item in native + wrapped)


def _swap_goal_mismatch_is_recorded(evidence: ProbeEvidence) -> bool:
    return any(
        _contains_value(row, {"goalMet", "taskGoalMet", "goalMismatch"}, False)
        and any(_nested_values(row, {key}) for key in ("actualOutput", "actualRecipient", "actualReserve", "actualExpense"))
        for _, row in _db_rows_with_source(evidence, ("swap", "evaluation", "goal"))
    )


def _wrong_goal_choice_has_receipt_effect(evidence: ProbeEvidence) -> bool:
    variants = ("wrong_goal_recipient_within_test_scope_executes", "technically_valid_wrong_test_recipient")
    for variant in variants:
        requests = _variant_http(evidence, variant)
        successful = [item for item in requests if _successful_http(item[2])]
        if not successful:
            continue
        op_ids = {_operation_id(item[0]) for item in successful}
        if any(_operation_id(receipt) in op_ids for receipt in _receipt_records(evidence, 1)):
            if any(art.payload.get("operationId") in op_ids for art, _ in _db_rows_with_source(evidence, ("swap", "effect"), variant)):
                return True
    return False


def _boundary_denial_and_revert_are_distinct(evidence: ProbeEvidence) -> bool:
    denied_variants = ("unsupported_asset_boundary_rejected", "unsupported_route_boundary_rejected")
    denied = all(_variant_http(evidence, variant) and all(_denied_http(item[2]) for item in _variant_http(evidence, variant)) for variant in denied_variants)
    reverted = _variant_receipt(evidence, "local_revert", 0)
    return denied and reverted and not any(item.payload.get("variantId") in denied_variants for item in _receipt_records(evidence))


def _native_and_weth_have_distinct_rpc_evidence(evidence: ProbeEvidence) -> bool:
    return _native_and_wrapped_assets_are_separate(evidence)


def _explicit_conversion_inputs_match(evidence: ProbeEvidence) -> bool:
    conversions = []
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary not in {"actual-tool-http", "participant-http"} or not _successful_http(response):
            continue
        if _path_matches(request, "/wrap") or _path_matches(request, "/unwrap"):
            body = _body_object(request.get("body"))
            direction = "wrap" if _path_matches(request, "/wrap") else "unwrap"
            if _numeric(body.get("amount")) and _numeric(body.get("amount")) > 0 and body.get("direction", direction).lower() == direction:
                conversions.append(artifact)
    return len({str(item.payload.get("variantId")) for item in conversions}) >= 2 or {"wrap", "unwrap"}.issubset(
        {"wrap" if any(_path_matches(req, "/wrap") for _, req, _ in _http_records(evidence)) else "", "unwrap" if any(_path_matches(req, "/unwrap") for _, req, _ in _http_records(evidence)) else ""}
    )


def _wrap_and_unwrap_have_receipts(evidence: ProbeEvidence) -> bool:
    operation_ids = set()
    for artifact, request, response in _http_records(evidence):
        if artifact.boundary in {"actual-tool-http", "participant-http"} and _successful_http(response) and (_path_matches(request, "/wrap") or _path_matches(request, "/unwrap")):
            if _operation_id(artifact):
                operation_ids.add(_operation_id(artifact))
    observed = {_operation_id(item) for item in _receipt_records(evidence, 1)}
    return len(operation_ids) >= 2 and operation_ids.issubset(observed)


def _swap_has_no_implicit_conversion(evidence: ProbeEvidence) -> bool:
    swaps = [
        (artifact, request, response)
        for artifact, request, response in _http_records(evidence)
        if artifact.boundary in {"actual-tool-http", "participant-http"} and _path_matches(request, "/swap")
    ]
    conversions = [
        (artifact, request, response)
        for artifact, request, response in _http_records(evidence)
        if artifact.boundary in {"actual-tool-http", "participant-http"} and (_path_matches(request, "/wrap") or _path_matches(request, "/unwrap"))
    ]
    if not swaps or not conversions:
        return False
    return all(_operation_id(swap[0]) != _operation_id(conversion[0]) for swap in swaps for conversion in conversions)


def _native_goal_uses_native_balance(evidence: ProbeEvidence) -> bool:
    native = [item for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy") if item.payload.get("method") == "eth_getBalance"]
    weth = _address(_manifest(evidence, "contracts").get("weth", {}).get("address"))
    wrapped = [item for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
               if item.payload.get("method") == "eth_call" and isinstance(item.payload.get("params"), list)
               and item.payload["params"] and isinstance(item.payload["params"][0], dict)
               and _address(item.payload["params"][0].get("to")) == weth
               and isinstance(item.payload["params"][0].get("data"), str)
               and item.payload["params"][0]["data"].lower().startswith("0x70a08231")]
    return bool(native) and bool(wrapped) and any(_rpc_result(item.payload) != _rpc_result(other.payload) for item in native for other in wrapped)


def _conversion_gas_is_attributed_once(evidence: ProbeEvidence) -> bool:
    conversion_ids = {
        _operation_id(artifact)
        for artifact, request, response in _http_records(evidence)
        if _path_matches(request, "/wrap") or _path_matches(request, "/unwrap")
    }
    conversion_ids.discard(None)
    tx_hashes = [_tx_hash_from_receipt(item.payload) for item in _receipt_records(evidence, 1) if _operation_id(item) in conversion_ids]
    if not conversion_ids or len(tx_hashes) != len(set(tx_hashes)) or None in tx_hashes:
        return False
    cost_rows = _db_rows_with_source(evidence, ("gas", "cost"))
    attributed = [row for artifact, row in cost_rows if artifact.payload.get("operationId") in conversion_ids]
    return len(attributed) == len(conversion_ids) and all(_contains_value(row, {"transactionHash", "txHash"}, tx_hash)
                                                         for row in attributed for tx_hash in tx_hashes)


def _receipt_cost(receipt: EvidenceArtifact) -> tuple[int, int] | None:
    value = _rpc_result(receipt.payload)
    if not isinstance(value, dict):
        return None
    gas_used = _hex_or_int(value.get("gasUsed"))
    effective_price = _hex_or_int(value.get("effectiveGasPrice"))
    if gas_used is None or effective_price is None or gas_used < 0 or effective_price < 0:
        return None
    return gas_used, effective_price


def _cost_row_for_receipt(evidence: ProbeEvidence, receipt: EvidenceArtifact) -> tuple[dict[str, Any], ...]:
    tx_hash = _tx_hash_from_receipt(receipt.payload)
    op_id = _operation_id(receipt)
    if tx_hash is None or op_id is None:
        return ()
    return tuple(
        row for artifact, row in _db_rows_with_source(evidence, ("gas", "cost", "expense"))
        if artifact.payload.get("operationId") == op_id
        and _contains_value(row, {"transactionHash", "txHash"}, tx_hash)
    )


def _fee_cost_matches_receipts_and_manifest(evidence: ProbeEvidence) -> bool:
    policy = _manifest(evidence, "feePolicy")
    numerator, denominator = _numeric(policy.get("ethUsdcRateNumerator")), _numeric(policy.get("ethUsdcRateDenominator"))
    if not numerator or not denominator or policy.get("rounding") != "floor-to-6-decimal-usdc-units":
        return False
    receipts = _receipt_records(evidence)
    if not any(_receipt_status(_rpc_result(item.payload)) == 1 for item in receipts) or not any(
        _receipt_status(_rpc_result(item.payload)) == 0 for item in receipts
    ):
        return False
    for receipt in receipts:
        components = _receipt_cost(receipt)
        rows = _cost_row_for_receipt(evidence, receipt)
        if components is None or len(rows) != 1:
            return False
        gas_used, price = components
        expected = gas_used * price * int(numerator) // (10**18 * int(denominator))
        observed = _numeric(rows[0].get("costUsdcUnits", rows[0].get("amountUsdcUnits")))
        if observed != expected:
            return False
    return True


def _transaction_payers_are_observed(evidence: ProbeEvidence) -> bool:
    receipts = _receipt_records(evidence)
    if not receipts:
        return False
    payer = _address(evidence.index.get("environment", {}).get("generation", {}).get("payerAddress"))
    for receipt in receipts:
        value = _rpc_result(receipt.payload)
        tx_from = _address(value.get("from")) if isinstance(value, dict) else None
        rows = _cost_row_for_receipt(evidence, receipt)
        if tx_from is None or not rows or not any(_contains_value(row, {"payer", "payerAddress", "from"}, tx_from) for row in rows):
            return False
        if tx_from == payer and not any(_contains_value(row, {"payer", "payerAddress", "from"}, payer) for row in rows):
            return False
    return True


def _receipt_costs_are_unique_and_principal_separate(evidence: ProbeEvidence) -> bool:
    hashes = [_tx_hash_from_receipt(receipt.payload) for receipt in _receipt_records(evidence)]
    if not hashes or None in hashes or len(hashes) != len(set(hashes)):
        return False
    rows = [row for _, row in _db_rows_with_source(evidence, ("gas", "cost", "expense"))]
    tx_refs = [str(value).lower() for row in rows for value in _nested_values(row, {"transactionHash", "txHash"}) if isinstance(value, str)]
    principal_fields = {"principal", "principalAmount", "serviceFee", "swapInput", "payoutAmount"}
    return all(tx_refs.count(tx_hash.lower()) == 1 for tx_hash in hashes) and any(
        any(_nested_values(row, {field}) for field in principal_fields)
        and _contains_value(row, {"principalSeparateFromExpense", "principalSeparate"}, True)
        for row in rows
    )


def _unsubmitted_rejection_has_no_gas_charge(evidence: ProbeEvidence) -> bool:
    rejections = [
        artifact for artifact, _, response in _http_records(evidence)
        if artifact.payload.get("variantId") == "preexecution_rejection" and _denied_http(response)
    ]
    if not rejections:
        return False
    for rejection in rejections:
        op_id = _operation_id(rejection)
        if op_id is None:
            return False
        if any(_operation_id(receipt) == op_id for receipt in _receipt_records(evidence)):
            return False
        if any(artifact.payload.get("operationId") == op_id for artifact, _ in _db_rows_with_source(evidence, ("gas", "cost", "expense"))):
            return False
    return True


def _l1_cost_is_explicitly_unmodelled(evidence: ProbeEvidence) -> bool:
    policy = _manifest(evidence, "feePolicy")
    if policy.get("baseL1Fee") != "unmodelled":
        return False
    return any(
        _contains_value(row, {"l1Fee", "baseL1Fee", "l1CostStatus"}, "unmodelled")
        or _contains_value(row, {"l1Mode", "baseL1Fee"}, "unmodelled")
        for _, row in _db_rows_with_source(evidence, ("gas", "cost", "expense"))
    )


def _environment_ids(evidence: ProbeEvidence) -> set[str]:
    return {
        str(item.get("id"))
        for item in _manifest(evidence, "local").get("environments", [])
        if isinstance(item, dict) and _nonempty(item.get("id"))
    }


def _two_environment_chain_state_is_independent(evidence: ProbeEvidence) -> bool:
    expected_ids = _environment_ids(evidence)
    observed_ids = {
        str(item.payload.get("environmentId"))
        for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
        if _nonempty(item.payload.get("environmentId"))
    }
    identities = {
        str(item.payload.get("chainInstanceId"))
        for item in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy")
        if _nonempty(item.payload.get("chainInstanceId"))
    }
    return len(expected_ids) == 2 and expected_ids.issubset(observed_ids) and len(identities) == 2


def _two_environment_db_state_is_independent(evidence: ProbeEvidence) -> bool:
    expected = _environment_ids(evidence)
    states: dict[str, set[str]] = {}
    for artifact in evidence.database_artifacts():
        env_id = artifact.payload.get("environmentId")
        state_hash = artifact.payload.get("stateHash")
        if isinstance(env_id, str) and _is_digest(state_hash):
            states.setdefault(env_id, set()).add(state_hash.lower())
    return len(expected) == 2 and expected.issubset(states) and all(states[item] for item in expected)


def _reset_preserves_other_environment(evidence: ProbeEvidence) -> bool:
    expected = _environment_ids(evidence)
    reset_calls = [
        (artifact, request, response)
        for artifact, request, response in _http_records(evidence)
        if artifact.boundary in {"private-admin-http", "admin-http"} and _path_matches(request, "/reset") and _successful_http(response)
    ]
    if len(expected) != 2 or not reset_calls:
        return False
    before_after = {}
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        env_id = artifact.payload.get("environmentId")
        if env_id not in expected:
            continue
        snapshot = artifact.payload.get("stateSnapshot")
        phase = artifact.payload.get("phase")
        if isinstance(snapshot, dict) and phase in {"before", "after"}:
            before_after.setdefault((env_id, phase), []).append(snapshot)
    reset_env = reset_calls[0][0].payload.get("environmentId")
    other = next((item for item in expected if item != reset_env), None)
    return bool(
        other is not None
        and before_after.get((other, "before"))
        and before_after.get((other, "after"))
        and before_after[(other, "before")][-1] == before_after[(other, "after")][-1]
    )


def _foreign_environment_http_is_denied(evidence: ProbeEvidence) -> bool:
    return bool(_variant_http(evidence, "foreign_environment_reference")) and all(
        _denied_http(item[2]) for item in _variant_http(evidence, "foreign_environment_reference")
    )


def _stale_generation_has_no_effect(evidence: ProbeEvidence) -> bool:
    stale = _variant_http(evidence, "late_worker")
    if not stale or not all(_denied_http(item[2]) for item in stale):
        return False
    operation_ids = {_operation_id(item[0]) for item in stale}
    operation_ids.discard(None)
    if not operation_ids:
        return False
    if any(_operation_id(receipt) in operation_ids for receipt in _receipt_records(evidence)):
        return False
    if any(artifact.payload.get("operationId") in operation_ids for artifact in evidence.database_artifacts()):
        return False
    return True


def _chain_baseline_matches_after_reset(evidence: ProbeEvidence) -> bool:
    snapshots = []
    for artifact in evidence.rpc_events(endpoint_boundary="local-chain-readonly-proxy"):
        snapshot = artifact.payload.get("stateSnapshot")
        if isinstance(snapshot, dict) and artifact.payload.get("phase") in {"beforeReset", "afterReset", "baseline"}:
            snapshots.append((artifact.payload.get("phase"), snapshot))
    before = [snapshot for phase, snapshot in snapshots if phase == "beforeReset"]
    after = [snapshot for phase, snapshot in snapshots if phase == "afterReset"]
    baseline = [snapshot for phase, snapshot in snapshots if phase == "baseline"]
    return bool(before and after and baseline and after[-1] == baseline[-1] and before[-1] != after[-1])


def _service_baseline_matches_after_reset(evidence: ProbeEvidence) -> bool:
    artifacts = _db_artifacts(evidence, ("baseline", "reset", "generation"))
    phases = {}
    for artifact in artifacts:
        phase = artifact.payload.get("phase")
        rows = artifact.payload.get("rows")
        if phase in {"beforeReset", "afterReset", "baseline"} and isinstance(rows, list):
            phases[phase] = rows
    return all(key in phases for key in ("beforeReset", "afterReset", "baseline")) and phases["afterReset"] == phases["baseline"] and phases["beforeReset"] != phases["afterReset"]


def _reset_fixture_hash_matches_manifest(evidence: ProbeEvidence) -> bool:
    expected = _manifest(evidence, "x402").get("resourceSha256")
    recorded = [item.payload.get("fixtureSha256") for item in evidence.database_artifacts() if _is_digest(item.payload.get("fixtureSha256"))]
    return _is_digest(expected) and bool(recorded) and all(str(item).lower() == expected.lower() for item in recorded)


def _new_trial_is_equivalent_and_distinct(evidence: ProbeEvidence) -> bool:
    generations = [item for item in _http_records(evidence)
                   if item[0].boundary in {"private-admin-http", "admin-http"} and _path_matches(item[1], "/generations") and _successful_http(item[2])]
    ids = {_operation_id(item[0]) for item in generations}
    generation_headers = {str(_headers(item[1].get("headers")).get("x-bef-generation")) for item in _http_records(evidence)}
    fixture_hashes = [item.payload.get("fixtureSha256") for item in evidence.database_artifacts() if _is_digest(item.payload.get("fixtureSha256"))]
    return len(generations) >= 2 and len(ids) >= 2 and len(generation_headers) >= 2 and len(set(map(str.lower, fixture_hashes))) == 1


def _source_reads_are_allowlisted(evidence: ProbeEvidence) -> bool:
    source = _manifest(evidence, "source")
    allowed = set(source.get("allowedMethods", []))
    events = evidence.rpc_events(endpoint_boundary="source-readonly-proxy")
    max_bytes = source.get("maxRequestBytes")
    if not allowed or not events or not isinstance(max_bytes, int) or max_bytes <= 0:
        return False
    block_number = source.get("blockNumber")
    block_methods = {
        "eth_getCode": 1,
        "eth_getStorageAt": 2,
        "eth_call": 1,
        "eth_getBalance": 1,
        "eth_getTransactionCount": 1,
    }
    for artifact in events:
        payload = artifact.payload
        method = payload.get("method")
        if payload.get("forwarded") is False:
            if not _sc012_source_rpc_is_bound(payload, evidence, forwarded=False):
                return False
            continue
        if payload.get("forwarded") is not True:
            return False
        if method not in allowed or not isinstance(method, str) or not method.startswith("eth_"):
            return False
        params = payload.get("params", [])
        if not isinstance(params, list):
            return False
        if not _sc012_source_rpc_is_bound(payload, evidence, forwarded=True):
            return False
        request_bytes = payload.get("requestBytes")
        if not isinstance(request_bytes, int):
            request_bytes = len(json.dumps({"method": method, "params": params}, separators=(",", ":"), default=str).encode("utf-8"))
        if request_bytes < 0 or request_bytes > max_bytes:
            return False
        request_body = payload.get("requestBody")
        if not isinstance(request_body, dict) or request_body.get("method") != method or request_body.get("params") != params:
            return False
        if request_bytes != len(json.dumps(request_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")):
            return False
        if method == "eth_chainId" and params != []:
            return False
        if method == "eth_chainId" and _hex_or_int(_rpc_result(payload)) != source.get("chainId"):
            return False
        if method == "eth_getBlockByNumber" and (not params or str(params[0]).lower() != str(block_number).lower()):
            return False
        if method == "eth_getBlockByHash" and (not params or str(params[0]).lower() != str(_manifest(evidence, "source").get("blockHash", "")).lower()):
            return False
        if method in block_methods:
            block_index = block_methods[method]
            if len(params) <= block_index or not isinstance(params[block_index], str) or params[block_index].lower() != str(block_number).lower():
                return False
        if method == "eth_getLogs":
            if len(params) != 1 or not isinstance(params[0], dict):
                return False
            query = params[0]
            if str(query.get("fromBlock", "")).lower() != str(block_number).lower() or str(query.get("toBlock", "")).lower() != str(block_number).lower():
                return False
    return True


def _sc012_source_rpc_is_bound(payload: dict[str, Any], evidence: ProbeEvidence, *, forwarded: bool) -> bool:
    """Bind the source observation to its raw JSON-RPC response and proxy counters."""

    request = payload.get("requestBody")
    encoded_response = payload.get("responseBodyBase64")
    response_digest = payload.get("responseBodySha256")
    if not isinstance(request, dict) or not isinstance(encoded_response, str) or not _is_digest(response_digest):
        return False
    try:
        response_bytes = base64.b64decode(encoded_response, validate=True)
        if hashlib.sha256(response_bytes).hexdigest() != response_digest.lower():
            return False
        envelope = json.loads(response_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0" or envelope.get("id") != request.get("id"):
        return False
    if payload.get("responseCorrelated") is not True or payload.get("responseStatus", 0) not in range(200, 300):
        return False
    if payload.get("responseBytes") != len(response_bytes) or payload.get("requestId") != request.get("id"):
        return False
    raw_error = envelope.get("error")
    observed_result = payload.get("result")
    if isinstance(raw_error, dict):
        expected_result = {"error": {"code": raw_error.get("code"), "message": raw_error.get("message", "rpc_error")}}
        if observed_result != expected_result:
            return False
    elif "result" not in envelope or observed_result != envelope["result"]:
        return False

    counter = payload.get("sourceProxyCounterDelta")
    if not isinstance(counter, dict):
        return False
    method = payload.get("method")
    before = counter.get("before")
    after = counter.get("after")
    if (counter.get("method") != method or counter.get("sourceProxyManifestSha256") != evidence.manifest_sha256
        or not isinstance(counter.get("sourceCallLimit"), int) or counter["sourceCallLimit"] <= 0
        or not isinstance(before, dict) or not isinstance(after, dict)):
        return False
    expected = {"forwarded": 1 if forwarded else 0, "denied": 0 if forwarded else 1,
                "sourceCallsReserved": 1 if forwarded else 0}
    for field, delta in expected.items():
        if (not isinstance(before.get(field), int) or isinstance(before.get(field), bool)
            or not isinstance(after.get(field), int) or isinstance(after.get(field), bool)
            or after[field] - before[field] != delta or counter.get(field) != delta):
            return False
    return True


def _sc012_required_source_reads_are_bound(evidence: ProbeEvidence) -> bool:
    source = _manifest(evidence, "source")
    chain_id = source.get("chainId")
    block_number = source.get("blockNumber")
    block_hash = source.get("blockHash")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not isinstance(block_number, str) or not _is_digest(block_hash):
        return False
    forwarded = [
        item.payload for item in evidence.rpc_events(endpoint_boundary="source-readonly-proxy")
        if item.payload.get("forwarded") is True
    ]
    chain_reads = [item for item in forwarded if item.get("method") == "eth_chainId" and item.get("params") == []]
    block_reads = [
        item for item in forwarded
        if item.get("method") == "eth_getBlockByNumber"
        and _requested_block_matches(item, block_number)
        and _block_hash_from_result(_rpc_result(item)) == block_hash.lower()
    ]
    code_reads = [
        item for item in forwarded
        if item.get("method") == "eth_getCode" and _requested_block_matches(item, block_number)
    ]
    return (
        bool(chain_reads) and all(_sc012_source_rpc_is_bound(item, evidence, forwarded=True) for item in chain_reads)
        and any(_hex_or_int(_rpc_result(item)) == chain_id for item in chain_reads)
        and bool(block_reads) and all(_sc012_source_rpc_is_bound(item, evidence, forwarded=True) for item in block_reads)
        and bool(code_reads) and all(_sc012_source_rpc_is_bound(item, evidence, forwarded=True) for item in code_reads)
    )


def _prohibited_source_methods_are_not_forwarded(evidence: ProbeEvidence) -> bool:
    variants = {
        "send_raw_transaction": ("eth_sendRawTransaction", ["0x00"]),
        "admin_method": ("anvil_reset", []),
        "sign_method": ("eth_sign", ["0x0000000000000000000000000000000000000000", "0x00"]),
    }
    for variant, (method, params) in variants.items():
        calls = [
            item for item in evidence.rpc_artifacts("source-readonly-proxy")
            if item.payload.get("variantId") == variant and item.payload.get("method") == method
        ]
        if len(calls) != 1:
            return False
        call = calls[0].payload
        if call.get("params") != params or call.get("forwarded") is not False:
            return False
        if not _sc012_source_rpc_is_bound(call, evidence, forwarded=False):
            return False

    source = _manifest(evidence, "source")
    chain_id = source.get("chainId")
    block_number = source.get("blockNumber")
    block_hash = source.get("blockHash")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not isinstance(block_number, str) or not _is_digest(block_hash):
        return False

    candidate_calls = [
        (artifact, request, response)
        for artifact, request, response in _http_records(evidence)
        if artifact.boundary == "private-admin-http"
        and artifact.payload.get("variantId") == "wrong_source_identity"
        and request.get("method") == "POST"
        and _path_matches(request, "/prerequisite-validations")
    ]
    if len(candidate_calls) != 1:
        return False
    artifact, request, response = candidate_calls[0]
    request_body = _body_object(request.get("body"))
    response_body = _response_body(response)
    candidate = request_body.get("candidate")
    if (response.get("status") != 200 or request_body.get("variantId") != "wrong_chain"
        or not isinstance(candidate, dict) or candidate.get("chainId") == chain_id
        or response_body.get("boundary") != "private-admin-prerequisite-validation"
        or response_body.get("variantId") != "wrong_chain" or response_body.get("accepted") is not False
        or response_body.get("reasonCode") != "source_chain_mismatch"
        or response_body.get("envId") != evidence.environment_id
        or response_body.get("manifestSha256") != evidence.manifest_sha256
        or response_body.get("applicationSourceSha256") != evidence.index.get("applicationSourceSha256")):
        return False
    observations = response_body.get("observations")
    observed_source = observations.get("source") if isinstance(observations, dict) else None
    observed_chain = observed_source.get("chainId") if isinstance(observed_source, dict) else None
    observed_block = observed_source.get("block") if isinstance(observed_source, dict) else None
    chain_result = observed_chain.get("result") if isinstance(observed_chain, dict) else None
    block_result = observed_block.get("result") if isinstance(observed_block, dict) else None
    if (not isinstance(observed_chain, dict) or observed_chain.get("method") != "eth_chainId"
        or observed_chain.get("params") != [] or _hex_or_int(chain_result) != chain_id
        or not isinstance(observed_block, dict) or observed_block.get("method") != "eth_getBlockByNumber"
        or not isinstance(block_result, dict)
        or str(block_result.get("number", "")).lower() != block_number.lower()
        or _block_hash_from_result(block_result) != block_hash.lower()):
        return False

    for phase in ("before", "after"):
        chain_reads = [
            item.payload for item in evidence.rpc_artifacts("source-readonly-proxy")
            if item.payload.get("variantId") == "wrong_source_identity"
            and item.payload.get("method") == "eth_chainId"
            and f"wrong-source-identity-{phase}-source-chain-id" in item.relative_path
        ]
        block_reads = [
            item.payload for item in evidence.rpc_artifacts("source-readonly-proxy")
            if item.payload.get("variantId") == "wrong_source_identity"
            and item.payload.get("method") == "eth_getBlockByNumber"
            and f"wrong-source-identity-{phase}-source-pinned-block" in item.relative_path
        ]
        if (len(chain_reads) != 1 or len(block_reads) != 1
            or chain_reads[0].get("params") != []
            or _hex_or_int(_rpc_result(chain_reads[0])) != chain_id
            or not _requested_block_matches(block_reads[0], block_number)
            or _block_hash_from_result(_rpc_result(block_reads[0])) != block_hash.lower()
            or not all(_sc012_source_rpc_is_bound(item, evidence, forwarded=True) for item in chain_reads + block_reads)):
            return False

    wrong_block_reads = [
        item.payload for item in evidence.rpc_artifacts("source-readonly-proxy")
        if item.payload.get("variantId") == "wrong_source_identity"
        and item.payload.get("method") == "eth_getBlockByNumber"
        and isinstance(item.payload.get("params"), list)
        and item.payload["params"]
        and str(item.payload["params"][0]).lower() != block_number.lower()
    ]
    if len(wrong_block_reads) != 1:
        return False
    denied_block = wrong_block_reads[0]
    return denied_block.get("forwarded") is False and _sc012_source_rpc_is_bound(denied_block, evidence, forwarded=False)


def _synthetic_validation_faults_are_rejected(
    evidence: ProbeEvidence, repository_root: Path | None = None
) -> bool:
    """Require hashed records for both actual offline validator fault trials."""

    expected = {
        "secret_in_artifact": "synthetic_secret_key_in_artifact",
        "missing_hash": "artifact_sha256_field_removed",
    }
    artifacts = [
        artifact for artifact in evidence.boundary_artifacts("recorded-evidence-validation")
        if artifact.payload.get("schemaVersion") == "bef-source-validation-fault-observation/v1"
    ]
    if len(artifacts) != len(expected):
        return False

    repository_root = repository_root or Path(__file__).resolve().parents[3]
    validator_path = _safe_repository_path(repository_root, "tools/replay_bef_evidence.py")
    if validator_path is None or not validator_path.is_file():
        return False
    try:
        validator_digest = hashlib.sha256(validator_path.read_bytes()).hexdigest()
    except OSError:
        return False

    observed: dict[str, EvidenceArtifact] = {}
    for artifact in artifacts:
        payload = artifact.payload
        variant = payload.get("variantId")
        if not isinstance(variant, str) or variant not in expected or variant in observed:
            return False
        if artifact.relative_path != f"replay/{variant}-validator-rejection.json":
            return False
        original_index_digest = payload.get("originalProbeIndexSha256")
        original_tree_before = payload.get("originalEvidenceTreeSha256Before")
        original_tree_after = payload.get("originalEvidenceTreeSha256After")
        original_path = payload.get("originalEvidenceRootPath")
        original_scenario = payload.get("inputScenario")
        if (
            original_scenario != "BEF-SC-004"
            or not _is_digest(original_index_digest)
            or not _is_digest(original_tree_before)
            or original_tree_before != original_tree_after
            or original_path is None
        ):
            return False
        references = evidence.index.get("replayedOriginalCaptures")
        if not isinstance(references, list):
            return False
        matching_references = [
            reference for reference in references
            if isinstance(reference, dict)
            and reference.get("provenance") == "replayed-original"
            and reference.get("scenarioId") == original_scenario
            and reference.get("probeIndexPath") == "probe.json"
            and reference.get("probeIndexSha256") == original_index_digest
            and isinstance(reference.get("evidenceRoot"), dict)
            and reference["evidenceRoot"].get("kind") == "repository_relative"
            and reference["evidenceRoot"].get("path") == original_path
        ]
        if len(matching_references) != 1:
            return False
        reference = matching_references[0]
        root_path = reference["evidenceRoot"]["path"]
        original_root = _safe_repository_path(repository_root, root_path)
        original_index = _safe_repository_path(repository_root, f"{root_path}/probe.json")
        if original_root is None or not original_root.is_dir() or original_index is None or not original_index.is_file():
            return False
        try:
            if original_index.stat().st_size > MAX_REPLAY_CAPTURE_FILE_BYTES:
                return False
            original_index_bytes = original_index.read_bytes()
            original_index_payload = _decode_json(original_index_bytes, "SC012 synthetic-fault source index")
        except (OSError, EvidenceInvalid):
            return False
        if (
            hashlib.sha256(original_index_bytes).hexdigest() != original_index_digest.lower()
            or original_index_payload.get("scenarioId") != original_scenario
            or original_index_payload.get("status") != "captured"
        ):
            return False
        current_tree_digest = _sc012_evidence_tree_digest(original_root)
        if current_tree_digest is None or current_tree_digest != original_tree_before.lower():
            return False
        if (
            payload.get("boundary") != "recorded-evidence-validation"
            or payload.get("operationId") is not None
            or payload.get("inputFault") != expected[variant]
            or payload.get("validator") != "tools/replay_bef_evidence.py -> ProbeEvidence.load"
            or payload.get("validatorSourcePath") != "tools/replay_bef_evidence.py"
            or payload.get("validatorSourceSha256") != validator_digest
            or type(payload.get("replayerExitCode")) is not int or payload.get("replayerExitCode") != 1
            or payload.get("replayerTimedOut") is not False
            or payload.get("replayerProcessClosed") is not True
            or payload.get("rejected") is not True
            or payload.get("reportCreated") is not False
            or payload.get("originalEvidenceUnchanged") is not True
            or payload.get("syntheticCopyRemoved") is not True
            or payload.get("recordingBoundary") != "hashed_probe_evidence_artifact"
        ):
            return False
        observed[variant] = artifact
    return set(observed) == set(expected)


def _sc012_evidence_tree_digest(root: Path) -> str | None:
    """Hash a bounded, symlink-free recorded capture using the probe's path+bytes format."""

    if not root.is_dir() or root.is_symlink():
        return None
    files: list[Path] = []
    total_bytes = 0
    try:
        for current, directories, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            if any((current_path / name).is_symlink() for name in directories + names):
                return None
            for name in names:
                path = current_path / name
                if not path.is_file():
                    return None
                size = path.stat().st_size
                total_bytes += size
                if size > MAX_REPLAY_CAPTURE_FILE_BYTES or total_bytes > MAX_REPLAY_CAPTURE_TOTAL_BYTES:
                    return None
                files.append(path)
                if len(files) > MAX_REPLAY_CAPTURE_FILES:
                    return None
    except OSError:
        return None
    if not files:
        return None
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        try:
            contents = path.read_bytes()
        except OSError:
            return None
        digest.update(relative)
        digest.update(b"\0")
        digest.update(contents)
        digest.update(b"\0")
    return digest.hexdigest()


def _all_evidence_paths_are_verified(evidence: ProbeEvidence) -> bool:
    if len(evidence.artifacts) != len(evidence.index.get("artifacts", [])):
        return False
    for artifact in evidence.artifacts:
        path = evidence.directory / artifact.relative_path
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != next(
            (entry.get("sha256") for entry in evidence.index["artifacts"] if entry.get("path") == artifact.relative_path), None
        ):
            return False
    return True


def _safe_repository_path(repository_root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value or ":" in value:
        return None
    relative = PurePosixPath(value)
    if not relative.parts or relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    root = repository_root.resolve(strict=True)
    if not root.is_dir():
        return None
    candidate = root
    try:
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                return None
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if _is_relative_to(resolved, root) else None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _verified_original_capture(repository_root: Path, original: dict[str, Any], scenario_id: str) -> dict[str, Any] | None:
    root_reference = original.get("evidenceRoot")
    if not isinstance(root_reference, dict) or root_reference.get("kind") != "repository_relative":
        return None
    if original.get("externalResolutionRequired") is not False or original.get("probeIndexPath") != "probe.json":
        return None
    relative_root = root_reference.get("path")
    if not isinstance(relative_root, str) or not relative_root.startswith("artifacts/benchmark-environment-feasibility/probes/"):
        return None
    capture_root = _safe_repository_path(repository_root, relative_root)
    if capture_root is None or not capture_root.is_dir():
        return None
    index_path = _safe_repository_path(repository_root, f"{relative_root}/probe.json")
    if index_path is None or not index_path.is_file():
        return None
    try:
        if index_path.stat().st_size > MAX_REPLAY_CAPTURE_FILE_BYTES:
            return None
        index_bytes = index_path.read_bytes()
        index = _decode_json(index_bytes, "replay original index")
    except (OSError, EvidenceInvalid):
        return None
    index_sha = hashlib.sha256(index_bytes).hexdigest()
    if (index_sha != original.get("probeIndexSha256") or index.get("schemaVersion") != "bef-runtime-probe/v1"
        or index.get("status") != "captured" or index.get("scenarioId") != scenario_id
        or original.get("scenarioId") != scenario_id or original.get("status") != "captured"):
        return None
    environment = index.get("environment")
    generation = environment.get("generation") if isinstance(environment, dict) else None
    if (not isinstance(environment, dict) or environment.get("envId") != original.get("environmentId")
        or not isinstance(generation, dict) or generation.get("generationId") != original.get("generationId")
        or not _nonempty(environment.get("envId")) or not _nonempty(generation.get("generationId"))
        or index.get("applicationSourceSha256") != original.get("applicationSourceSha256")
        or index.get("probeSourceSha256") != original.get("probeSourceSha256")
        or not _is_digest(index.get("applicationSourceSha256")) or not _is_digest(index.get("probeSourceSha256"))
        or index.get("sourceBlock") != original.get("sourceBlock")):
        return None
    source_block = index.get("sourceBlock")
    if (not isinstance(source_block, dict) or not _nonempty(source_block.get("number"))
        or not _is_digest(source_block.get("hash"))):
        return None
    operations = index.get("operations")
    expected_operation_ids = [
        item.get("operationId") for item in operations
        if isinstance(item, dict) and _nonempty(item.get("operationId"))
    ] if isinstance(operations, list) else []
    if (not expected_operation_ids or len(set(expected_operation_ids)) != len(expected_operation_ids)
        or original.get("operationIds") != expected_operation_ids):
        return None

    artifact_entries = index.get("artifacts")
    original_entries = original.get("artifacts")
    if not isinstance(artifact_entries, list) or not artifact_entries or not isinstance(original_entries, list):
        return None
    expected_files = {"probe.json"}
    normalized_entries: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    total_bytes = len(index_bytes)
    if total_bytes > MAX_REPLAY_CAPTURE_TOTAL_BYTES:
        return None
    if len(artifact_entries) > MAX_REPLAY_CAPTURE_FILES:
        return None
    for entry in artifact_entries:
        if not isinstance(entry, dict):
            return None
        path = entry.get("path")
        digest = entry.get("sha256")
        boundary = entry.get("boundary")
        content_type = entry.get("contentType")
        if (not isinstance(path, str) or not _is_digest(digest) or not _nonempty(boundary)
            or not isinstance(content_type, str) or "json" not in content_type.lower()):
            return None
        pure_path = PurePosixPath(path)
        if (pure_path.is_absolute() or "\\" in path or "\x00" in path or ":" in path
            or not pure_path.parts or any(part in {"", ".", ".."} for part in pure_path.parts)):
            return None
        normalized = pure_path.as_posix()
        if normalized in seen_paths:
            return None
        seen_paths.add(normalized)
        artifact_path = _safe_repository_path(repository_root, f"{relative_root}/{normalized}")
        if artifact_path is None or not artifact_path.is_file():
            return None
        try:
            if artifact_path.stat().st_size > MAX_REPLAY_CAPTURE_FILE_BYTES:
                return None
            actual_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        except OSError:
            return None
        total_bytes += artifact_path.stat().st_size
        if total_bytes > MAX_REPLAY_CAPTURE_TOTAL_BYTES:
            return None
        if actual_digest != digest.lower():
            return None
        expected_files.add(normalized)
        normalized_entries.append({"path": normalized, "sha256": digest.lower(), "boundary": boundary})
    if original_entries != normalized_entries:
        return None
    actual_files: set[str] = set()
    tree_bytes = 0
    try:
        for current, directories, files in os.walk(capture_root, followlinks=False):
            current_path = Path(current)
            if any((current_path / name).is_symlink() for name in directories + files):
                return None
            for name in files:
                file_path = current_path / name
                file_size = file_path.stat().st_size
                if file_size > MAX_REPLAY_CAPTURE_FILE_BYTES:
                    return None
                tree_bytes += file_size
                if tree_bytes > MAX_REPLAY_CAPTURE_TOTAL_BYTES:
                    return None
                actual_files.add(file_path.relative_to(capture_root).as_posix())
                if len(actual_files) > MAX_REPLAY_CAPTURE_FILES:
                    return None
    except OSError:
        return None
    if actual_files != expected_files:
        return None

    manifest_ref = index.get("manifest")
    if not isinstance(manifest_ref, dict) or manifest_ref.get("path") != original.get("manifestPath"):
        return None
    manifest_path = manifest_ref.get("path")
    manifest_digest = manifest_ref.get("sha256")
    if not isinstance(manifest_path, str) or not _is_digest(manifest_digest) or manifest_digest != original.get("manifestSha256"):
        return None
    manifest_artifact = next((item for item in artifact_entries if isinstance(item, dict) and item.get("path") == manifest_path
                              and item.get("boundary") == "runtime-manifest"), None)
    manifest_file = _safe_repository_path(repository_root, f"{relative_root}/{manifest_path}")
    if manifest_artifact is None or manifest_file is None or not manifest_file.is_file():
        return None
    try:
        if manifest_file.stat().st_size > MAX_REPLAY_CAPTURE_FILE_BYTES:
            return None
        manifest_bytes = manifest_file.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest.lower():
            return None
        manifest = _decode_json(manifest_bytes, "replay original manifest")
    except (OSError, EvidenceInvalid):
        return None
    return {
        "root": capture_root,
        "index": index,
        "indexSha256": index_sha,
        "operationIds": expected_operation_ids,
        "artifactEntries": normalized_entries,
        "manifest": manifest,
        "manifestSha256": manifest_digest.lower(),
    }


_REPLAY_SOURCE_PROFILE_VERSIONS = {
    "active-delta": "active-delta/v1",
    "synced-main": "synced-main/v1",
}
_REPLAY_MAIN_CONTRACT_CHANGE = "synchronized-main"


def _replay_source_profile(replay: dict[str, Any]) -> str | None:
    """Read an exact versioned source profile; unversioned reports are legacy active evidence."""

    value = replay.get("sourceProfile")
    if value is None:
        return "active-delta"
    for name, versioned in _REPLAY_SOURCE_PROFILE_VERSIONS.items():
        if value == versioned:
            return name
    return None


def _configured_replay_source_profile() -> str | None:
    value = os.environ.get("BEF_SPEC_PROFILE")
    if value is None:
        return "active-delta"
    if value in _REPLAY_SOURCE_PROFILE_VERSIONS:
        return value
    return None


def _replay_source_bindings_match(repository_root: Path, replay: dict[str, Any]) -> bool:
    approved = replay.get("approvedSources")
    source_profile = _replay_source_profile(replay)
    if source_profile is None or source_profile != _configured_replay_source_profile():
        return False
    expected_source_names = (
        {"proposal", "harnessContract", "normativeSpec", "predicateSource"}
        if source_profile == "active-delta"
        else {"harnessContract", "normativeSpec", "predicateSource"}
    )
    if not isinstance(approved, dict) or set(approved) != expected_source_names:
        return False
    if source_profile == "active-delta":
        expected_paths = {
            "proposal": "openspec/changes/benchmark-environment-feasibility/bdd-harness-proposal.json",
            "harnessContract": "tests/bdd/changes/benchmark-environment-feasibility/harness-contracts.json",
            "predicateSource": "tests/bdd/adapters/benchmark_environment_feasibility.py",
        }
    else:
        if not (repository_root / "infrastructure/benchmark-environment/manifest.json").is_file():
            return False
        expected_paths = {
            "harnessContract": "tests/bdd/harness-contracts.json",
            "normativeSpec": "openspec/specs/benchmark-environment-feasibility/spec.md",
            "predicateSource": "tests/bdd/adapters/benchmark_environment_feasibility.py",
        }
    for name, source in approved.items():
        if not isinstance(source, dict) or not _is_digest(source.get("sha256")):
            return False
        path = source.get("path")
        if not isinstance(path, str):
            return False
        if name in expected_paths and path != expected_paths[name]:
            return False
        if name == "normativeSpec" and source_profile == "active-delta" and not (
            path.startswith("openspec/changes/benchmark-environment-feasibility/specs/")
            and path.endswith("/spec.md") and ".." not in PurePosixPath(path).parts
        ):
            return False
        file_path = _safe_repository_path(repository_root, path)
        if file_path is None or not file_path.is_file():
            return False
        try:
            if hashlib.sha256(file_path.read_bytes()).hexdigest() != source["sha256"].lower():
                return False
        except OSError:
            return False
    replayer_path = replay.get("replayerSourcePath")
    replayer_hash = replay.get("replayerSourceSha256")
    if replayer_path != "tools/replay_bef_evidence.py" or not _is_digest(replayer_hash):
        return False
    replayer_file = _safe_repository_path(repository_root, replayer_path)
    if replayer_file is None or not replayer_file.is_file():
        return False
    try:
        return hashlib.sha256(replayer_file.read_bytes()).hexdigest() == replayer_hash.lower()
    except OSError:
        return False


def _replay_payment_recipients_by_operation(capture: dict[str, Any]) -> dict[str, set[str]] | None:
    """Read payTo only from hash-verified recorded 402 challenge headers."""

    manifest = capture.get("manifest")
    x402 = manifest.get("x402") if isinstance(manifest, dict) else None
    if not isinstance(x402, dict):
        return None
    expected_operation_ids = set(capture.get("operationIds", []))
    root = capture.get("root")
    entries = capture.get("artifactEntries")
    if not isinstance(root, Path) or not isinstance(entries, list) or not expected_operation_ids:
        return None
    recipients: dict[str, set[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("boundary") != "actual-tool-http":
            continue
        relative_path = entry.get("path")
        if not isinstance(relative_path, str):
            return None
        artifact_path = root / PurePosixPath(relative_path)
        if not _is_relative_to(artifact_path.resolve(), root.resolve()):
            return None
        try:
            artifact = _decode_json(artifact_path.read_bytes(), "original replay HTTP artifact")
        except (OSError, EvidenceInvalid):
            return None
        if (not isinstance(artifact, dict) or artifact.get("schemaVersion") != "bef-http-observation/v1"
            or artifact.get("boundary") != "actual-tool-http"):
            return None
        operation_id = artifact.get("operationId")
        response = artifact.get("response")
        if not isinstance(response, dict) or response.get("status") != 402:
            continue
        if operation_id not in expected_operation_ids:
            return None
        headers = response.get("headers")
        if not isinstance(headers, dict):
            return None
        response_operation_id = next((value for name, value in headers.items()
                                      if isinstance(name, str) and name.lower() == "x-bef-operation-id"), None)
        if response_operation_id != operation_id:
            return None
        encoded = next((value for name, value in headers.items()
                        if isinstance(name, str) and name.lower() == "payment-required"), None)
        if not isinstance(encoded, str) or len(encoded) > 1_048_576:
            return None
        try:
            declaration_bytes = base64.b64decode(encoded, validate=True)
            if base64.b64encode(declaration_bytes).decode("ascii").rstrip("=") != encoded.rstrip("="):
                return None
            declaration = json.loads(declaration_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        accepts = declaration.get("accepts") if isinstance(declaration, dict) else None
        if (not isinstance(declaration, dict) or declaration.get("x402Version") != 2
            or not isinstance(accepts, list) or len(accepts) != 1 or not isinstance(accepts[0], dict)):
            return None
        accepted = accepts[0]
        pay_to = accepted.get("payTo")
        if (accepted.get("scheme") != x402.get("scheme")
            or accepted.get("network") != x402.get("network")
            or str(accepted.get("asset", "")).lower() != str(x402.get("asset", "")).lower()
            or accepted.get("amount") != x402.get("amount")
            or not isinstance(pay_to, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", pay_to)):
            return None
        recipients.setdefault(operation_id, set()).add(pay_to.lower())
    if not recipients or any(len(values) != 1 for values in recipients.values()):
        return None
    return recipients


def _replay_local_rpc_states_match(
    evidence: ProbeEvidence, original: dict[str, Any], capture: dict[str, Any]
) -> bool:
    reference = next((item for item in evidence.index.get("replayedOriginalCaptures", [])
                     if isinstance(item, dict) and item.get("probeIndexSha256") == capture["indexSha256"]), None)
    if not isinstance(reference, dict):
        return False
    generation_operations = _replayed_original_generation_map(evidence, reference)
    if not generation_operations:
        return False
    pay_to_by_operation = _replay_payment_recipients_by_operation(capture)
    if not pay_to_by_operation:
        return False
    env_id = original.get("environmentId")
    index_sha = capture["indexSha256"]
    bindings = {
        artifact.relative_path: artifact
        for artifact in evidence.boundary_artifacts("local-chain-readonly-proxy")
        if artifact.payload.get("schemaVersion") == "bef-rpc-endpoint-binding/v1"
    }
    health_artifacts = {artifact.relative_path: artifact for artifact in evidence.boundary_artifacts("local-chain-readonly-proxy")}
    phase_states: dict[str, dict[str, Any]] = {"before": {}, "after": {}}
    for artifact in evidence.boundary_artifacts("local-chain-readonly-proxy"):
        payload = artifact.payload
        phase = payload.get("phase")
        if payload.get("replayOfProbeIndexSha256") != index_sha:
            continue
        if not isinstance(phase, str) or phase not in phase_states:
            return False
        generation_id = payload.get("generationId")
        expected_operations = generation_operations.get(generation_id)
        if (payload.get("operationId") is not None or payload.get("envId") != env_id
            or payload.get("environmentId") != env_id or expected_operations is None
            or payload.get("operationIds") != expected_operations or payload.get("forwarded") is not True
            or payload.get("requestedBlock") != "latest"):
            return False
        method = payload.get("method")
        params = payload.get("params")
        if method not in {"eth_getBalance", "eth_getTransactionCount", "eth_call"} or not isinstance(params, list):
            return False
        if not params or params[-1] != "latest":
            return False
        endpoint_path = payload.get("endpointIdentityArtifact")
        binding_artifact = bindings.get(endpoint_path) if isinstance(endpoint_path, str) else None
        if binding_artifact is None:
            return False
        binding = binding_artifact.payload
        endpoint_ref = payload.get("endpointRef")
        if (binding.get("environmentId") != env_id or binding.get("endpointRef") != endpoint_ref
            or not isinstance(endpoint_ref, dict) or endpoint_ref.get("scheme") != "http"
            or endpoint_ref.get("host") not in {"localhost", "127.0.0.1", "::1"}
            or isinstance(endpoint_ref.get("port"), bool) or not isinstance(endpoint_ref.get("port"), int)
            or endpoint_ref["port"] < 1 or endpoint_ref["port"] > 65535):
            return False
        health_path = binding.get("healthArtifactPath")
        health_artifact = health_artifacts.get(health_path) if isinstance(health_path, str) else None
        if (health_artifact is None or health_artifact.boundary != "local-chain-readonly-proxy"
            or health_artifact.sha256 != binding.get("healthArtifactSha256")):
            return False
        health = health_artifact.payload
        if (health.get("status") != "ok" or health.get("boundary") != "local-chain-readonly-proxy"
            or health.get("envId") != env_id or health.get("manifestSha256") != capture["manifestSha256"]):
            return False
        request = payload.get("requestBody")
        encoded = payload.get("responseBodyBase64")
        digest = payload.get("responseBodySha256")
        if (not isinstance(request, dict) or request.get("method") != method or request.get("params") != params
            or not isinstance(encoded, str) or not _is_digest(digest)):
            return False
        try:
            raw_response = base64.b64decode(encoded, validate=True)
            if hashlib.sha256(raw_response).hexdigest() != digest.lower():
                return False
            envelope = json.loads(raw_response.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        if (not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0"
            or envelope.get("id") != request.get("id") or "error" in envelope
            or payload.get("responseCorrelated") is not True or payload.get("responseStatus") not in range(200, 300)
            or payload.get("responseBytes") != len(raw_response) or payload.get("result") != envelope.get("result")):
            return False
        key = _canonical_json({"generationId": generation_id, "method": method, "params": params})
        if key in phase_states[phase]:
            return False
        phase_states[phase][key] = envelope.get("result")

    expected_addresses: dict[str, set[str]] = {generation_id: set() for generation_id in generation_operations}
    db_snapshots = [artifact for artifact in evidence.database_artifacts()
                    if artifact.payload.get("observationScope") == "generation"
                    and artifact.payload.get("replayedOriginalCapture") == reference
                    and artifact.payload.get("replayPhase") == "before"]
    for generation_id, operation_ids in generation_operations.items():
        generation_rows = [row for artifact in db_snapshots
                           if artifact.payload.get("generationId") == generation_id
                           and artifact.payload.get("queryName") == "generation-by-id"
                           for row in artifact.payload.get("rows", []) if isinstance(row, dict)]
        if len(generation_rows) != 1 or generation_rows[0].get("generation_id", generation_rows[0].get("generationId")) != generation_id:
            return False
        generation_payer = generation_rows[0].get("payer_address", generation_rows[0].get("payerAddress"))
        if not isinstance(generation_payer, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", generation_payer):
            return False
        expected_addresses[generation_id].add(generation_payer.lower())
        payment_rows = [row for artifact in db_snapshots
                        if artifact.payload.get("generationId") == generation_id
                        and artifact.payload.get("queryName") == "payments-by-operation"
                        for row in artifact.payload.get("rows", []) if isinstance(row, dict)]
        for row in payment_rows:
            operation_id = row.get("operation_id", row.get("operationId"))
            if operation_id not in operation_ids:
                return False
            for field in ("payer_address", "facilitator_address"):
                address = row.get(field, row.get("payerAddress" if field == "payer_address" else "facilitatorAddress"))
                if isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                    expected_addresses[generation_id].add(address.lower())
            facilitator = row.get("facilitator_address", row.get("facilitatorAddress"))
            operation_pay_to = pay_to_by_operation.get(operation_id)
            if facilitator is not None and (not isinstance(facilitator, str) or operation_pay_to is None
                                             or facilitator.lower() != next(iter(operation_pay_to))):
                return False
        for operation_id in operation_ids:
            recipients = pay_to_by_operation.get(operation_id, set())
            expected_addresses[generation_id].update(recipients)
        if not expected_addresses[generation_id]:
            return False

    manifest = capture.get("manifest")
    x402 = manifest.get("x402") if isinstance(manifest, dict) else None
    contracts = manifest.get("contracts") if isinstance(manifest, dict) else None
    usdc = contracts.get("usdc") if isinstance(contracts, dict) else None
    token = usdc.get("address") if isinstance(usdc, dict) else None
    if not isinstance(token, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", token):
        return False
    expected_keys: set[str] = set()
    expected_inventory: list[dict[str, Any]] = []
    for generation_id in sorted(generation_operations):
        addresses = sorted(expected_addresses[generation_id])
        expected_inventory.append({
            "generationId": generation_id,
            "operationIds": generation_operations[generation_id],
            "addresses": addresses,
        })
        for address in addresses:
            expected_params = {
                "eth_getBalance": [address, "latest"],
                "eth_getTransactionCount": [address, "latest"],
                "eth_call": [{"to": token, "data": "0x70a08231" + address[2:].rjust(64, "0")}, "latest"],
            }
            for method, params in expected_params.items():
                expected_keys.add(_canonical_json({"generationId": generation_id, "method": method, "params": params}))
    if len(phase_states["before"]) != len(expected_keys) or set(phase_states["before"]) != expected_keys:
        return False
    if len(phase_states["after"]) != len(expected_keys) or set(phase_states["after"]) != expected_keys:
        return False
    report = next((artifact.payload for artifact in evidence.boundary_artifacts("recorded-evidence-replay")
                   if artifact.payload.get("schemaVersion") == "bef-evidence-replay-observation/v1"
                   and isinstance(artifact.payload.get("original"), dict)
                   and artifact.payload["original"].get("probeIndexSha256") == index_sha), None)
    state_comparison = report.get("stateComparison") if isinstance(report, dict) else None
    if not isinstance(state_comparison, dict) or state_comparison.get("localRpcExpectedAccounts") != expected_inventory:
        return False
    return phase_states["before"] == phase_states["after"]


def _replay_bracket_is_bound(
    evidence: ProbeEvidence,
    report: dict[str, Any],
    capture: dict[str, Any],
    reference: dict[str, Any],
) -> bool:
    """Require the actual offline replay event between exact DB/RPC snapshot inventories."""

    bracket = report.get("replayBracket")
    expected_kinds = [
        "before_database_snapshot",
        "before_local_rpc_snapshot",
        "offline_evidence_replay",
        "after_database_snapshot",
        "after_local_rpc_snapshot",
    ]
    if not isinstance(bracket, dict) or bracket.get("sequence") != expected_kinds:
        return False
    events = bracket.get("events")
    if not isinstance(events, list) or len(events) != len(expected_kinds):
        return False
    if [item.get("kind") if isinstance(item, dict) else None for item in events] != expected_kinds:
        return False
    if [item.get("ordinal") if isinstance(item, dict) else None for item in events] != list(range(1, 6)):
        return False

    identity = {
        "schemaVersion": "bef-evidence-replay/v1",
        "evaluatedScenarioId": report.get("evaluatedScenarioId"),
        "replayStatus": report.get("replayStatus"),
        "gateStatus": report.get("gateStatus"),
        "original": report.get("original"),
        "replay": report.get("replay"),
    }
    identity_hash = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    if (bracket.get("preflightIdentitySha256") != identity_hash
        or bracket.get("replayIdentitySha256") != identity_hash):
        return False
    replay_event = events[2]
    if (replay_event.get("scenarioId") != capture.get("index", {}).get("scenarioId")
        or replay_event.get("originalProbeIndexSha256") != capture.get("indexSha256")
        or replay_event.get("replayIdentitySha256") != identity_hash):
        return False

    artifacts_by_path = {artifact.relative_path: artifact for artifact in evidence.artifacts}
    for event, expected_boundary in (
        (events[0], "readonly-database"),
        (events[1], "local-chain-readonly-proxy"),
        (events[3], "readonly-database"),
        (events[4], "local-chain-readonly-proxy"),
    ):
        references = event.get("artifacts")
        if not isinstance(references, list) or not references:
            return False
        seen_paths: set[str] = set()
        for item in references:
            if not isinstance(item, dict):
                return False
            path, digest, boundary = item.get("path"), item.get("sha256"), item.get("boundary")
            artifact = artifacts_by_path.get(path) if isinstance(path, str) else None
            boundary_allowed = boundary == expected_boundary or (
                expected_boundary == "local-chain-readonly-proxy" and boundary == "replay-local-state"
            )
            if (not isinstance(path, str) or path in seen_paths or not _is_digest(digest)
                or not boundary_allowed or artifact is None or artifact.sha256 != digest.lower()
                or artifact.boundary != boundary):
                return False
            seen_paths.add(path)

        phase = "before" if event["ordinal"] in {1, 2} else "after"
        if expected_boundary == "readonly-database":
            expected_paths = {
                artifact.relative_path for artifact in evidence.database_artifacts()
                if artifact.payload.get("replayedOriginalCapture") == reference
                and artifact.payload.get("replayPhase") == phase
                and artifact.payload.get("observationScope") in {"generation", "original-operation-bindings"}
            }
            if seen_paths != expected_paths:
                return False
        else:
            required_paths = {
                artifact.relative_path for artifact in evidence.artifacts
                if artifact.payload.get("replayOfProbeIndexSha256") == capture.get("indexSha256")
                and artifact.payload.get("phase") == phase
                and artifact.boundary in {"local-chain-readonly-proxy", "replay-local-state"}
            }
            if not required_paths or not required_paths.issubset(seen_paths):
                return False
    return True


def _replay_is_read_only(evidence: ProbeEvidence, repository_root: Path | None = None) -> bool:
    """Verify offline file replay plus independent, unchanged DB and local-RPC state."""

    root = repository_root
    if root is None:
        root = next(
            (
                parent
                for parent in (evidence.directory, *evidence.directory.parents)
                if (parent / "openspec/changes/benchmark-environment-feasibility/bdd-harness-proposal.json").is_file()
                or (
                    (parent / "openspec/specs/benchmark-environment-feasibility/spec.md").is_file()
                    and (parent / "tests/bdd/harness-contracts.json").is_file()
                    and (parent / "infrastructure/benchmark-environment/manifest.json").is_file()
                )
            ),
            None,
        )
    if root is None:
        return False
    root = root.resolve()
    reports = [
        artifact for artifact in evidence.boundary_artifacts("recorded-evidence-replay")
        if artifact.payload.get("schemaVersion") == "bef-evidence-replay-observation/v1"
    ]
    if len(reports) != 2:
        return False
    if not _replayed_original_references_are_bound(evidence, reports):
        return False
    scenarios = {"BEF-SC-004", "BEF-SC-005"}
    seen_scenarios: set[str] = set()
    for artifact in reports:
        report = artifact.payload
        original = report.get("original")
        replay = report.get("replay")
        if not isinstance(original, dict) or not isinstance(replay, dict):
            return False
        scenario = original.get("scenarioId")
        if not isinstance(scenario, str) or scenario not in scenarios or scenario in seen_scenarios:
            return False
        seen_scenarios.add(scenario)
        capture = _verified_original_capture(root, original, scenario)
        if capture is None:
            return False
        expected_reference = next((item for item in evidence.index.get("replayedOriginalCaptures", [])
                                   if isinstance(item, dict)
                                   and item.get("scenarioId") == scenario
                                   and item.get("probeIndexSha256") == capture["indexSha256"]), None)
        if not isinstance(expected_reference, dict):
            return False
        if not _replay_bracket_is_bound(evidence, report, capture, expected_reference):
            return False
        generation_operations = _replayed_original_generation_map(evidence, expected_reference)
        if not generation_operations:
            return False
        required = replay.get("requiredChecks")
        source_profile = _replay_source_profile(replay)
        expected_contract_change = (
            CHANGE_NAME if source_profile == "active-delta" else _REPLAY_MAIN_CONTRACT_CHANGE
        )
        check_results = replay.get("checkResults")
        execution = replay.get("execution")
        checks: dict[str, bool] = {}
        if isinstance(check_results, list):
            for item in check_results:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("name"), str)
                    or not item["name"]
                    or type(item.get("passed")) is not bool
                    or item["name"] in checks
                ):
                    return False
                checks[item["name"]] = item["passed"]
        if (report.get("evaluatedScenarioId") != scenario or report.get("replayStatus") != "matched"
            or report.get("gateStatus") != "not_established_by_replay"
            or report.get("replayExecutionBoundary") != "offline-file-only-no-http-rpc-db-or-broadcast-by-replayer"
            or not isinstance(required, list) or not required
            or any(not isinstance(name, str) or not name for name in required)
            or len(set(required)) != len(required) or set(checks) != set(required)
            or source_profile is None
            or replay.get("contractChange") != expected_contract_change
            or replay.get("contractScenarioId") != scenario
            or replay.get("checksMatchContract") is not True or replay.get("predicateCompleted") is not True
            or replay.get("predicateErrorType") is not None or replay.get("missingChecks") != []
            or any(checks.get(name) is not True for name in required)
            or not isinstance(execution, dict) or execution.get("mode") != "offline_recorded_observations"
            or any(execution.get(name) != 0 for name in ("httpRequests", "rpcCalls", "databaseQueries", "broadcasts", "newTrials"))
            or not _replay_source_bindings_match(root, replay)):
            return False

        state_comparison = report.get("stateComparison")
        if (not isinstance(state_comparison, dict)
            or state_comparison.get("databaseRowsEqual") is not True
            or state_comparison.get("databaseOperationIdsMatch") is not True
            or state_comparison.get("databaseGenerationBindingsEqual") is not True
            or state_comparison.get("localChainReadsEqual") is not True
            or state_comparison.get("environmentId") != original.get("environmentId")
            or state_comparison.get("generationIds") != sorted(generation_operations)
            or state_comparison.get("operationIds") != capture["operationIds"]):
            return False
        if not _replay_local_rpc_states_match(evidence, original, capture):
            return False

    if seen_scenarios != scenarios:
        return False
    # The replayer itself is offline; all local-RPC work surrounding it must
    # remain read-only. Source write attempts are separately required to carry
    # forwarded=false in _prohibited_source_methods_are_not_forwarded.
    return not any(
        item.payload.get("method") in {"eth_sendRawTransaction", "eth_sendTransaction"}
        and item.payload.get("forwarded") is not False
        for item in evidence.rpc_artifacts()
    )


def _replayed_original_references_are_bound(
    evidence: ProbeEvidence,
    reports: list[EvidenceArtifact],
) -> bool:
    """Keep replayed capture operations distinct from this probe's operations."""

    expected_queries = {
        "generation-by-id",
        "operations-by-generation",
        "payments-by-operation",
        "deliveries-by-operation",
        "denials-by-generation",
        "x402-observations-by-operation",
    }
    expected_by_scenario: dict[str, dict[str, Any]] = {}
    report_by_index_hash: dict[str, dict[str, Any]] = {}
    all_replayed_operation_ids: set[str] = set()
    for artifact in reports:
        original = artifact.payload.get("original")
        if not isinstance(original, dict):
            return False
        scenario_id = original.get("scenarioId")
        root = original.get("evidenceRoot")
        operation_ids = original.get("operationIds")
        index_hash = original.get("probeIndexSha256")
        environment_id = original.get("environmentId")
        generation_id = original.get("generationId")
        if (scenario_id not in {"BEF-SC-004", "BEF-SC-005"}
            or not isinstance(root, dict) or root.get("kind") != "repository_relative"
            or not _nonempty(root.get("path")) or original.get("probeIndexPath") != "probe.json"
            or not _is_digest(index_hash) or not _nonempty(environment_id) or not _nonempty(generation_id)
            or not isinstance(operation_ids, list) or not operation_ids
            or not all(_nonempty(item) for item in operation_ids)
            or len(operation_ids) != len(set(operation_ids))):
            return False
        reference = {
            "provenance": "replayed-original",
            "scenarioId": scenario_id,
            "evidenceRoot": root,
            "probeIndexPath": "probe.json",
            "probeIndexSha256": index_hash,
            "environmentId": environment_id,
            "generationId": generation_id,
            "operationIds": operation_ids,
        }
        if scenario_id in expected_by_scenario or any(item in all_replayed_operation_ids for item in operation_ids):
            return False
        expected_by_scenario[scenario_id] = reference
        all_replayed_operation_ids.update(operation_ids)
        report_by_index_hash[index_hash] = reference

    if set(expected_by_scenario) != {"BEF-SC-004", "BEF-SC-005"}:
        return False
    declared = evidence.index.get("replayedOriginalCaptures")
    if not isinstance(declared, list) or len(declared) != 2:
        return False
    if {item.get("scenarioId") for item in declared if isinstance(item, dict)} != set(expected_by_scenario):
        return False
    for item in declared:
        if not isinstance(item, dict) or expected_by_scenario.get(item.get("scenarioId")) != item:
            return False

    current_operations = evidence.index.get("operations")
    if not isinstance(current_operations, list):
        return False
    current_operation_ids = {
        item.get("operationId") for item in current_operations
        if isinstance(item, dict) and _nonempty(item.get("operationId"))
    }
    if current_operation_ids & all_replayed_operation_ids:
        return False

    generation_snapshots = [artifact for artifact in evidence.database_artifacts()
                            if artifact.payload.get("observationScope") == "generation"]
    expected_snapshot_count = 0
    for reference in expected_by_scenario.values():
        generation_operations = _replayed_original_generation_map(evidence, reference)
        if not generation_operations:
            return False
        expected_snapshot_count += len(generation_operations) * 12
        source_key = _canonical_json(reference)
        matching = [
            artifact for artifact in generation_snapshots
            if _canonical_json(artifact.payload.get("replayedOriginalCapture")) == source_key
        ]
        if len(matching) != len(generation_operations) * 12:
            return False
        seen: set[tuple[str, str, str]] = set()
        for artifact in matching:
            payload = artifact.payload
            phase = payload.get("replayPhase")
            query_name = payload.get("queryName")
            snapshot_generation_id = payload.get("generationId")
            expected_generation_operation_ids = generation_operations.get(snapshot_generation_id)
            if (payload.get("schemaVersion") != "bef-db-observation/v1"
                or payload.get("boundary") != "readonly-database"
                or payload.get("readOnly") is not True
                or payload.get("observationScope") != "generation"
                or payload.get("observationOperationId") is not None
                or payload.get("operationId") is not None
                or payload.get("replayedOriginalCapture") != reference
                or payload.get("envId") != reference["environmentId"]
                or expected_generation_operation_ids is None
                or payload.get("generationOperationIds") != expected_generation_operation_ids
                or phase not in {"before", "after"}
                or query_name not in expected_queries
                or (snapshot_generation_id, phase, query_name) in seen):
                return False
            seen.add((snapshot_generation_id, phase, query_name))
            rows = payload.get("rows")
            if not isinstance(rows, list):
                return False
            row_operation_ids: set[str] = set()
            for row in rows:
                if not isinstance(row, dict):
                    return False
                row_operation_id = row.get("operation_id", row.get("operationId"))
                if row_operation_id is not None:
                    if not _nonempty(row_operation_id) or row_operation_id not in expected_generation_operation_ids:
                        return False
                    row_operation_ids.add(row_operation_id)
                row_environment_id = row.get("env_id", row.get("envId"))
                row_generation_id = row.get("generation_id", row.get("generationId"))
                if (row_environment_id is not None and row_environment_id != reference["environmentId"]
                    or row_generation_id is not None and row_generation_id != snapshot_generation_id):
                    return False
            if query_name == "generation-by-id":
                if (len(rows) != 1 or rows[0].get("env_id", rows[0].get("envId")) != reference["environmentId"]
                    or rows[0].get("generation_id", rows[0].get("generationId")) != snapshot_generation_id):
                    return False
            elif query_name == "operations-by-generation":
                operation_rows = [row.get("operation_id", row.get("operationId")) for row in rows]
                if (row_operation_ids != set(expected_generation_operation_ids)
                    or len(operation_rows) != len(expected_generation_operation_ids)
                    or sorted(operation_rows) != expected_generation_operation_ids):
                    return False
        expected_seen = {
            (generation_id, phase, query)
            for generation_id in generation_operations
            for phase in ("before", "after")
            for query in expected_queries
        }
        if seen != expected_seen:
            return False
        for generation_id in generation_operations:
            for query_name in expected_queries:
                phase_rows = {
                    str(item.payload.get("replayPhase")): item.payload.get("rows")
                    for item in matching
                    if item.payload.get("generationId") == generation_id
                    and item.payload.get("queryName") == query_name
                }
                if (set(phase_rows) != {"before", "after"}
                    or _canonical_json(phase_rows["before"]) != _canonical_json(phase_rows["after"])):
                    return False

    if len(generation_snapshots) != expected_snapshot_count:
        return False

    for artifact in evidence.artifacts:
        payload = artifact.payload
        index_hash = payload.get("replayOfProbeIndexSha256")
        if index_hash is None:
            continue
        reference = report_by_index_hash.get(index_hash)
        if (reference is None or payload.get("replayedOriginalCapture") != reference
            or payload.get("envId", payload.get("environmentId")) != reference["environmentId"]
            ):
            return False
        generation_operations = _replayed_original_generation_map(evidence, reference)
        if not generation_operations:
            return False
        scope = payload.get("observationScope")
        if scope == "generation":
            generation_id = payload.get("generationId")
            if (generation_id not in generation_operations
                or payload.get("generationOperationIds") != generation_operations[generation_id]):
                return False
        elif scope == "original-operation-bindings":
            if payload.get("operationIds") != reference["operationIds"]:
                return False
        else:
            generation_id = payload.get("generationId")
            operation_ids = payload.get("operationIds")
            if (generation_id not in generation_operations
                or operation_ids != generation_operations[generation_id]):
                return False
    return True


def _replayed_original_generation_map(
    evidence: ProbeEvidence,
    reference: dict[str, Any],
) -> dict[str, list[str]] | None:
    """Read operation-to-generation bindings from paired read-only DB observations."""

    operation_ids = reference.get("operationIds")
    if not isinstance(operation_ids, list) or not operation_ids:
        return None
    artifacts = [
        item for item in evidence.database_artifacts()
        if item.payload.get("queryName") == "replayed-original-operation-generation-bindings"
        and item.payload.get("replayedOriginalCapture") == reference
    ]
    if len(artifacts) != 2:
        return None
    by_phase: dict[str, dict[str, str]] = {}
    for artifact in artifacts:
        payload = artifact.payload
        phase = payload.get("replayPhase")
        rows = payload.get("rows")
        if (phase not in {"before", "after"} or phase in by_phase
            or payload.get("schemaVersion") != "bef-db-observation/v1"
            or payload.get("boundary") != "readonly-database" or payload.get("readOnly") is not True
            or payload.get("observationScope") != "original-operation-bindings"
            or payload.get("observationOperationId") is not None or payload.get("operationId") is not None
            or payload.get("envId") != reference.get("environmentId")
            or payload.get("operationIds") != operation_ids or not isinstance(rows, list)):
            return None
        bindings: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict):
                return None
            operation_id = row.get("operation_id", row.get("operationId"))
            environment_id = row.get("env_id", row.get("envId"))
            generation_id = row.get("generation_id", row.get("generationId"))
            if (not _nonempty(operation_id) or operation_id in bindings
                or environment_id != reference.get("environmentId") or not _nonempty(generation_id)):
                return None
            bindings[operation_id] = generation_id
        if set(bindings) != set(operation_ids):
            return None
        by_phase[phase] = bindings
    if by_phase.get("before") != by_phase.get("after"):
        return None
    grouped: dict[str, list[str]] = {}
    for operation_id, generation_id in by_phase["before"].items():
        grouped.setdefault(generation_id, []).append(operation_id)
    if reference.get("generationId") not in grouped:
        return None
    return {generation_id: sorted(ids) for generation_id, ids in grouped.items()}


def _all_artifacts_are_redacted(evidence: ProbeEvidence) -> bool:
    try:
        _reject_secrets(evidence.index, "probe index")
        _reject_secrets(evidence.manifest, "runtime manifest")
        for artifact in evidence.artifacts:
            _reject_secrets(artifact.payload, artifact.relative_path)
    except EvidenceInvalid:
        return False
    return True

