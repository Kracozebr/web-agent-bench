"""Replay validated BEF evidence against the currently approved predicates.

This tool is deliberately offline. It loads an existing captured probe directory,
validates its indexed bytes, then invokes only the selected scenario's verifier
against those recorded observations. It never executes a probe or calls a service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHANGE_NAME = "benchmark-environment-feasibility"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

REPORT_SCHEMA = "bef-evidence-replay/v1"
SOURCE_PROFILE_ENV = "BEF_SPEC_PROFILE"
SOURCE_PROFILE_VERSIONS = {
    "active-delta": "active-delta/v1",
    "synced-main": "synced-main/v1",
}
MAIN_PROFILE_CHANGE = "synchronized-main"


class ReplayInputError(ValueError):
    """Replay cannot safely evaluate or write the requested report."""


class _ReplayContext:
    """Collect predicate results without asserting or invoking scenario setup."""

    def __init__(self, scenario_id: str, evidence: Any) -> None:
        self.scenario_id = scenario_id
        self.outcome = evidence
        self.state: dict[str, Any] = {}
        self.observations: set[str] = set()
        self.checks: dict[str, bool] = {}

    def check(self, name: str, condition: bool) -> bool:
        if not isinstance(name, str) or not name.strip() or name in self.checks:
            raise ReplayInputError("predicate_check_inventory_invalid")
        passed = condition is True
        self.checks[name] = passed
        if passed:
            self.observations.add(name)
        return passed


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _evidence_snapshot(evidence: Any) -> dict[str, str]:
    """Hash only the index and files accepted by ProbeEvidence.load."""

    index_path = evidence.directory / "probe.json"
    snapshot = {"probe.json": _sha256(index_path)}
    for artifact in evidence.artifacts:
        path = evidence.directory / Path(artifact.relative_path)
        relative = path.resolve(strict=True).relative_to(evidence.directory).as_posix()
        digest = _sha256(path)
        if digest != artifact.sha256:
            raise ReplayInputError("indexed_artifact_changed")
        snapshot[relative] = digest
    return snapshot


def _evidence_root_reference(evidence_root: Path, repository_root: Path) -> dict[str, Any]:
    """Return a resolvable in-repository path or a non-path external handle."""

    resolved_root = evidence_root.resolve(strict=True)
    resolved_repository = repository_root.resolve(strict=True)
    try:
        relative = resolved_root.relative_to(resolved_repository)
    except ValueError:
        path_bytes = os.fsencode(str(resolved_root))
        handle_digest = hashlib.sha256(b"bef-evidence-root:v1\0" + path_bytes).hexdigest()
        return {
            "evidenceRoot": {"kind": "external", "handle": f"sha256:{handle_digest}"},
            "externalResolutionRequired": True,
        }
    return {
        "evidenceRoot": {"kind": "repository_relative", "path": relative.as_posix()},
        "externalResolutionRequired": False,
    }


def _select_source_profile(requested: str | None = None) -> str:
    """Resolve a profile from explicit CLI intent or the caller's scoped environment."""

    if requested is not None and requested not in SOURCE_PROFILE_VERSIONS:
        raise ReplayInputError("source_profile_invalid")
    configured = os.environ.get(SOURCE_PROFILE_ENV)
    if configured is not None and configured not in SOURCE_PROFILE_VERSIONS:
        raise ReplayInputError("source_profile_invalid")
    if requested is not None and configured is not None and requested != configured:
        raise ReplayInputError("source_profile_conflict")
    return requested or configured or "active-delta"


def _approved_inputs(
    repository_root: Path, scenario_id: str, source_profile: str
) -> tuple[Any, Any, dict[str, dict[str, str]]]:
    """Load one exact active-delta or synchronized-main verifier source set."""

    from tools.generate_bdd_mirrors import parse_specs
    from tools.harness_contracts import (
        change_root,
        load_manifest,
        load_proposal,
        manifest_path,
        proposal_path,
        validate_proposal_inventory,
        validate_spec_snapshot,
    )
    from tests.bdd.adapters import build_registry

    if source_profile == "active-delta":
        proposal = load_proposal(repository_root, CHANGE_NAME)
        manifest_payload, contracts = load_manifest(repository_root, CHANGE_NAME)
        scenarios = parse_specs(repository_root, CHANGE_NAME)
        validate_proposal_inventory(proposal, scenarios, contracts)
        validate_spec_snapshot(repository_root, scenarios, manifest_payload, CHANGE_NAME)
        registry = build_registry(CHANGE_NAME)
    elif source_profile == "synced-main":
        # The infrastructure manifest is a stable root sentinel after the active
        # change is archived; main replay never resolves through change-owned paths.
        if not (repository_root / "infrastructure/benchmark-environment/manifest.json").is_file():
            raise ReplayInputError("synced_main_repository_root_invalid")
        manifest_payload, contracts = load_manifest(repository_root)
        scenarios = parse_specs(repository_root)
        validate_spec_snapshot(repository_root, scenarios, manifest_payload)
        registry = build_registry()
    else:
        raise ReplayInputError("source_profile_invalid")

    registered = registry.contracts()
    if registered != contracts:
        raise ReplayInputError("registered_contract_drift")
    case = registry.cases().get(scenario_id)
    contract = contracts.get(scenario_id)
    if case is None or contract is None:
        raise ReplayInputError("scenario_not_in_approved_contract")

    if source_profile == "active-delta":
        proposal_file = proposal_path(repository_root, CHANGE_NAME)
        spec_path = change_root(repository_root, CHANGE_NAME) / proposal["normative_delta"]
        contract_file = manifest_path(repository_root, CHANGE_NAME)
        source_hashes = {
            "proposal": {
                "path": proposal_file.relative_to(repository_root).as_posix(),
                "sha256": _sha256(proposal_file),
            },
            "harnessContract": {
                "path": contract_file.relative_to(repository_root).as_posix(),
                "sha256": _sha256(contract_file),
            },
            "normativeSpec": {
                "path": spec_path.relative_to(repository_root).as_posix(),
                "sha256": _sha256(spec_path),
            },
        }
    else:
        selected_scenario = next(item for item in scenarios if item.scenario_id == scenario_id)
        spec_path = repository_root / "openspec" / "specs" / selected_scenario.capability.directory / "spec.md"
        contract_file = manifest_path(repository_root)
        source_hashes = {
            "harnessContract": {
                "path": contract_file.relative_to(repository_root).as_posix(),
                "sha256": _sha256(contract_file),
            },
            "normativeSpec": {
                "path": spec_path.relative_to(repository_root).as_posix(),
                "sha256": _sha256(spec_path),
            },
        }
    adapter_module = __import__(case.__class__.__module__, fromlist=["__file__"])
    adapter_path = Path(adapter_module.__file__).resolve()
    source_hashes["predicateSource"] = {
        "path": adapter_path.relative_to(repository_root).as_posix(),
        "sha256": _sha256(adapter_path),
    }
    return case, contract, source_hashes


def _operation_ids(index: dict[str, Any]) -> list[str]:
    operations = index.get("operations")
    if not isinstance(operations, list):
        raise ReplayInputError("operation_inventory_invalid")
    return [
        item["operationId"]
        for item in operations
        if isinstance(item, dict)
        and isinstance(item.get("operationId"), str)
        and item["operationId"].strip()
    ]


def _write_new_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".bef-replay-", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        # A hard-link create is atomic and refuses to overwrite an existing report.
        os.link(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def replay_evidence(
    evidence_dir: Path | str,
    report_path: Path | str,
    *,
    source_profile: str | None = None,
) -> dict[str, Any]:
    """Validate and replay a captured probe directory, writing a new report only."""

    selected_profile = _select_source_profile(source_profile)

    try:
        evidence_path = Path(evidence_dir).expanduser().resolve(strict=True)
    except FileNotFoundError:
        raise ReplayInputError("original_probe_missing") from None
    report = Path(report_path).expanduser().resolve(strict=False)
    if _inside(report, evidence_path):
        raise ReplayInputError("report_must_be_outside_original_evidence")
    if report.exists():
        raise ReplayInputError("report_already_exists")

    # Read status/scenario from the index only to select the matching approved
    # verifier. ProbeEvidence.load then validates the complete index and every
    # referenced byte before any predicate runs.
    try:
        index = json.loads((evidence_path / "probe.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ReplayInputError("original_probe_missing") from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ReplayInputError("original_probe_index_unreadable") from None
    if not isinstance(index, dict):
        raise ReplayInputError("original_probe_index_invalid")
    scenario_id = index.get("scenarioId")
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise ReplayInputError("original_scenario_missing")

    from tests.bdd.adapters.benchmark_environment_feasibility import ProbeEvidence

    evidence = ProbeEvidence.load(REPOSITORY_ROOT, scenario_id, evidence_path)
    if evidence.status != "captured":
        raise ReplayInputError("original_probe_not_captured")

    original_snapshot = _evidence_snapshot(evidence)
    case, contract, approved_sources = _approved_inputs(
        REPOSITORY_ROOT, evidence.scenario_id, selected_profile
    )
    source_snapshot = {name: values["sha256"] for name, values in approved_sources.items()}
    context = _ReplayContext(evidence.scenario_id, evidence)
    verifier_name = "_verify_" + evidence.scenario_id.replace("-", "_")
    verifier = getattr(case, verifier_name, None)
    if not callable(verifier):
        raise ReplayInputError("scenario_verifier_missing")

    predicate_completed = True
    predicate_error_type: str | None = None
    try:
        # This invokes only the verifier. Never call setup(), execute(), or _capture().
        verifier(context)
    except ReplayInputError:
        raise
    except Exception as error:  # Keep malformed recorded evidence fail-closed and secret-safe.
        predicate_completed = False
        predicate_error_type = type(error).__name__

    required = tuple(contract.required_observations)
    checks_match_contract = set(context.checks) == set(required)
    missing_checks = [name for name in required if name not in context.checks]
    matched = (
        predicate_completed
        and checks_match_contract
        and all(context.checks.get(name) is True for name in required)
    )

    # Ensure the replay itself did not alter any accepted original bytes and that
    # all code/contracts used for evaluation remained stable during the run.
    if _evidence_snapshot(evidence) != original_snapshot:
        raise ReplayInputError("original_evidence_changed_during_replay")
    _, current_contract, current_sources = _approved_inputs(
        REPOSITORY_ROOT, evidence.scenario_id, selected_profile
    )
    if current_contract != contract or {
        name: values["sha256"] for name, values in current_sources.items()
    } != source_snapshot:
        raise ReplayInputError("approved_predicate_sources_changed_during_replay")

    report_payload: dict[str, Any] = {
        "schemaVersion": REPORT_SCHEMA,
        "evaluatedScenarioId": evidence.scenario_id,
        "replayStatus": "matched" if matched else "not_matched",
        "gateStatus": "not_established_by_replay",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "original": {
            "scenarioId": evidence.scenario_id,
            "status": evidence.status,
            **_evidence_root_reference(evidence.directory, REPOSITORY_ROOT),
            "probeIndexPath": "probe.json",
            "probeIndexSha256": original_snapshot["probe.json"],
            "manifestPath": evidence.index["manifest"]["path"],
            "manifestSha256": evidence.manifest_sha256,
            "applicationSourceSha256": evidence.index["applicationSourceSha256"],
            "probeSourceSha256": evidence.index["probeSourceSha256"],
            "sourceBlock": evidence.index["sourceBlock"],
            "environmentId": evidence.environment_id,
            "generationId": evidence.generation_id,
            "operationIds": _operation_ids(evidence.index),
            "artifacts": [
                {
                    "path": artifact.relative_path,
                    "sha256": artifact.sha256,
                    "boundary": artifact.boundary,
                }
                for artifact in evidence.artifacts
            ],
        },
        "replay": {
            "contractChange": CHANGE_NAME if selected_profile == "active-delta" else MAIN_PROFILE_CHANGE,
            "contractScenarioId": contract.scenario_id,
            "sourceProfile": SOURCE_PROFILE_VERSIONS[selected_profile],
            "approvedSources": approved_sources,
            "replayerSourcePath": Path(__file__).resolve().relative_to(REPOSITORY_ROOT).as_posix(),
            "replayerSourceSha256": _sha256(Path(__file__).resolve()),
            "checks": context.checks,
            "requiredChecks": list(required),
            "checksMatchContract": checks_match_contract,
            "missingChecks": missing_checks,
            "predicateCompleted": predicate_completed,
            "predicateErrorType": predicate_error_type,
            "execution": {
                "mode": "offline_recorded_observations",
                "httpRequests": 0,
                "rpcCalls": 0,
                "databaseQueries": 0,
                "broadcasts": 0,
                "newTrials": 0,
                "counterMeaning": "descriptive replay code path counters; not independent gate proof",
            },
        },
    }
    _write_new_report(report, report_payload)
    return report_payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay captured BEF evidence offline.")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument(
        "--source-profile",
        choices=tuple(SOURCE_PROFILE_VERSIONS),
        help="select the active-delta or synchronized-main predicates; defaults to BEF_SPEC_PROFILE or active-delta",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = replay_evidence(
            args.evidence_dir, args.report, source_profile=args.source_profile
        )
    except Exception as error:
        # Deliberately avoid exception text: probe artifacts and paths are not
        # echoed to the console, and blocked/tampered inputs receive no report.
        from tests.bdd.adapters.benchmark_environment_feasibility import EvidenceInvalid, ProbeBlocked

        if isinstance(error, ProbeBlocked):
            print("status=blocked reason=original_probe_blocked")
            return 2
        if isinstance(error, ReplayInputError) and str(error) == "original_probe_missing":
            print("status=blocked reason=original_probe_missing")
            return 2
        if isinstance(error, (EvidenceInvalid, ReplayInputError)):
            print("status=invalid reason=evidence_or_replay_validation_failed")
            return 1
        print("status=invalid reason=replay_failed_closed")
        return 1
    print(f"status={report['replayStatus']} report={args.report}")
    return 0 if report["replayStatus"] == "matched" else 1


if __name__ == "__main__":
    raise SystemExit(main())
