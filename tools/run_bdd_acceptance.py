#!/usr/bin/env python3
"""Run every approved local gate and record one result per normative scenario."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.generate_bdd_mirrors import (
    CHANGE_NAME,
    LIFECYCLE_PHASE,
    NORMATIVE_SOURCE,
    parse_specs,
    _gate_metadata,
)
from tools.harness_contracts import (
    active_delta_source_paths,
    acceptance_path,
    harness_source_paths,
    load_manifest,
    load_proposal,
    main_spec_paths,
    manifest_path,
    scenario_map_path,
    sha256_files,
    validate_change_name,
)


EVIDENCE_SCHEMA_VERSION = 1


def _git_metadata(root: Path) -> tuple[str, bool]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=False
    )
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=False
    )
    if commit.returncode != 0 or status.returncode != 0 or not commit.stdout.strip():
        raise RuntimeError("cannot record reproducible Git metadata; commit the repository first")
    return commit.stdout.strip(), bool(status.stdout.strip())


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_source_integrity(
    root: Path, change_name: str | None, evidence: dict[str, object]
) -> bool:
    """Record a post-run digest and fail evidence if executable inputs changed."""

    expected = evidence.get("harness_sources_sha256")
    if not isinstance(expected, str):
        evidence.update(
            acceptance_state="failed",
            source_unchanged=False,
            error="missing_pre_execution_harness_source_sha256",
        )
        return False
    try:
        observed = sha256_files(root, harness_source_paths(root, change_name))
    except (OSError, RuntimeError) as error:
        evidence.update(
            acceptance_state="failed",
            source_unchanged=False,
            error=f"cannot_verify_harness_sources_after_execution: {error}",
        )
        return False
    evidence["harness_sources_sha256_after"] = observed
    unchanged = observed == expected
    evidence["source_unchanged"] = unchanged
    if not unchanged:
        evidence.update(
            acceptance_state="failed",
            error="harness_sources_changed_during_acceptance",
        )
    return unchanged


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_evidence(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _scenario_results_from_junit(junit_path: Path, scenarios: list[object]) -> dict[str, str]:
    """Map every normative scenario to its single pytest mapper result, failing closed."""

    root = ET.parse(junit_path).getroot()
    by_name: dict[str, list[ET.Element]] = {}
    for testcase in root.iter("testcase"):
        by_name.setdefault(testcase.attrib.get("name", ""), []).append(testcase)

    results: dict[str, str] = {}
    expected_names = {scenario.mapper_name for scenario in scenarios}
    for scenario in scenarios:
        matches = by_name.get(scenario.mapper_name, [])
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one JUnit testcase for {scenario.scenario_id}/{scenario.mapper_name}, found {len(matches)}"
            )
        testcase = matches[0]
        skipped = testcase.find("skipped")
        if skipped is not None:
            reason = skipped.attrib.get("message", "").strip()
            if reason.startswith("Skipped: "):
                reason = reason.removeprefix("Skipped: ").strip()
            result = "blocked" if reason.startswith("BLOCKED:") else "skipped"
        elif testcase.find("failure") is not None or testcase.find("error") is not None:
            result = "failed"
        else:
            result = "passed"
        results[scenario.scenario_id] = result

    mapper_names = {name for name in by_name if name.startswith("test_") and name in expected_names}
    if mapper_names != expected_names:
        raise RuntimeError(
            f"JUnit mapper inventory drifted; missing={sorted(expected_names - mapper_names)}, "
            f"extra={sorted(mapper_names - expected_names)}"
        )
    return results


def _pytest_targets(scenarios: list[object], change_name: str | None) -> list[str]:
    capabilities = sorted({scenario.capability.slug for scenario in scenarios})
    if not capabilities:
        raise ValueError("selected BDD source has no scenario mappers")
    mapper_paths = [f"tests/bdd/mappers/test_{slug}_bdd.py" for slug in capabilities]
    if change_name is None:
        return [*mapper_paths, "tests/bdd/traceability"]
    return mapper_paths


def _pytest_command(
    python: str,
    scenarios: list[object],
    junit_relative: str,
    change_name: str | None,
) -> list[str]:
    command = [python, "-m", "pytest", *_pytest_targets(scenarios, change_name)]
    if change_name is not None:
        command.extend(["--change", validate_change_name(change_name)])
    command.extend(["-q", "-p", "no:cacheprovider", f"--junitxml={junit_relative}"])
    return command


def _acceptance_spec_profile(change_name: str | None) -> str:
    """Select the replay profile from the acceptance runner's normative source."""

    return "active-delta" if change_name is not None else "synced-main"


def _acceptance_child_environment(
    change_name: str | None, base_environment: dict[str, str] | None = None
) -> dict[str, str]:
    """Propagate an authoritative source profile to pytest and its replay children."""

    environment = dict(os.environ if base_environment is None else base_environment)
    environment["BEF_SPEC_PROFILE"] = _acceptance_spec_profile(change_name)
    return environment


def _selected_gate_metadata(
    root: Path, scenarios: list[object], change_name: str | None
) -> dict[str, object]:
    """Record the declared gate class without converting an environment gate to local."""

    if change_name is None:
        gate_source, _contracts = load_manifest(root)
    else:
        gate_source = load_proposal(root, change_name)
    scenario_classes = {}
    for scenario in scenarios:
        gate_class, mandatory = _gate_metadata(scenario, gate_source)
        scenario_classes[scenario.scenario_id] = {
            "class": gate_class,
            "mandatory": mandatory,
        }
    classes = {entry["class"] for entry in scenario_classes.values()}
    mandatory_values = {entry["mandatory"] for entry in scenario_classes.values()}
    if len(classes) == 1 and len(mandatory_values) == 1:
        return {"class": next(iter(classes)), "mandatory": next(iter(mandatory_values))}
    return {
        "class": "per_scenario",
        "mandatory": all(entry["mandatory"] for entry in scenario_classes.values()),
        "scenario_classes": scenario_classes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--change",
        default=None,
        help="select one active OpenSpec change; omit to run the synchronized-main baseline",
    )
    args = parser.parse_args(argv)
    root = REPOSITORY_ROOT
    try:
        change_name = validate_change_name(args.change) if args.change is not None else None
        scenarios = parse_specs(root, change_name)
        gate_metadata = _selected_gate_metadata(root, scenarios, change_name)
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Cannot select BDD acceptance source: {error}", file=sys.stderr)
        return 1
    selected_change = CHANGE_NAME if change_name is None else change_name
    lifecycle_phase = LIFECYCLE_PHASE if change_name is None else "active-delta"
    source_profile = _acceptance_spec_profile(change_name)
    normative_source = (
        NORMATIVE_SOURCE
        if change_name is None
        else f"openspec/changes/{change_name}/specs/*/spec.md"
    )
    evidence_directory = root / "artifacts" / "bdd-evidence"
    evidence_directory.mkdir(parents=True, exist_ok=True)
    junit_path = evidence_directory / f"{selected_change}-pytest.xml"
    junit_relative = junit_path.relative_to(root).as_posix()
    python_label = ".venv/Scripts/python.exe" if os.name == "nt" else ".venv/bin/python"
    command = _pytest_command(python_label, scenarios, junit_relative, change_name)
    execution_command = _pytest_command(sys.executable, scenarios, junit_relative, change_name)
    started_at = _utc_now()
    evidence_path = acceptance_path(root, change_name)
    preflight: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "change": selected_change,
        "lifecycle_phase": lifecycle_phase,
        "bef_spec_profile": source_profile,
        "normative_source": normative_source,
        "gate": gate_metadata,
        "command": command,
        "acceptance_state": "running",
        "started_at_utc": started_at,
        "finished_at_utc": None,
        "exit_code": None,
        "git_commit": None,
        "git_worktree_dirty": None,
        "main_specs_sha256": None,
        "active_delta_sha256": None,
        "harness_contract_sha256": None,
        "harness_sources_sha256": None,
        "harness_sources_sha256_after": None,
        "source_unchanged": None,
        "scenario_map_sha256": None,
        "harness_audit": {"status": "not_run"},
        "scenario_results": {scenario.scenario_id: "not_run" for scenario in scenarios},
    }
    try:
        git_commit, git_worktree_dirty = _git_metadata(root)
        main_specs_sha256 = sha256_files(root, main_spec_paths(root))
        active_delta_sha256 = (
            sha256_files(root, active_delta_source_paths(root, change_name))
            if change_name is not None
            else None
        )
        harness_contract_sha256 = _sha256_file(manifest_path(root, change_name))
        harness_sources_sha256 = sha256_files(root, harness_source_paths(root, change_name))
    except (OSError, RuntimeError) as error:
        print(f"Mandatory reproducibility gate failed: {error}", file=sys.stderr)
        preflight.update(acceptance_state="failed", finished_at_utc=_utc_now(), exit_code=1, error=str(error))
        _write_evidence(evidence_path, preflight)
        return 1

    preflight.update(
        git_commit=git_commit,
        git_worktree_dirty=git_worktree_dirty,
        main_specs_sha256=main_specs_sha256,
        active_delta_sha256=active_delta_sha256,
        harness_contract_sha256=harness_contract_sha256,
        harness_sources_sha256=harness_sources_sha256,
    )
    # AICODE-NOTE: Capture Git metadata before writing the running record so the dirty flag
    # describes the caller's pre-acceptance worktree, not the evidence file created by this runner.
    # The running record is still written before the audit, mirror generation, and pytest subprocesses
    # so an interruption cannot leave an older pass looking current.
    _write_evidence(evidence_path, preflight)
    audit_command = [sys.executable, str(root / "tools" / "check_bdd_harness.py"), "--json"]
    if change_name is not None:
        audit_command.extend(["--change", change_name])
    audit_process = subprocess.run(
        audit_command,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        audit = json.loads(audit_process.stdout)
    except json.JSONDecodeError as error:
        audit = {"status": "failed", "errors": [f"invalid audit JSON: {error}"]}
        if audit_process.stderr:
            audit["errors"].append(audit_process.stderr.strip())
    preflight["harness_audit"] = audit
    _write_evidence(evidence_path, preflight)
    if audit_process.returncode != 0 or audit.get("status") != "passed":
        print("Mandatory BDD harness audit failed; pytest was not started.", file=sys.stderr)
        print(json.dumps(audit, indent=2, sort_keys=True), file=sys.stderr)
        preflight.update(acceptance_state="failed", finished_at_utc=_utc_now(), exit_code=1)
        _write_evidence(evidence_path, preflight)
        return 1

    generate_command = [sys.executable, str(root / "tools" / "generate_bdd_mirrors.py")]
    if change_name is not None:
        generate_command.extend(["--change", change_name])
    regenerate = subprocess.run(generate_command, cwd=root, check=False)
    if regenerate.returncode != 0:
        preflight.update(acceptance_state="failed", finished_at_utc=_utc_now(), exit_code=1)
        _write_evidence(evidence_path, preflight)
        return regenerate.returncode

    result = subprocess.run(
        execution_command,
        cwd=root,
        text=True,
        check=False,
        env=_acceptance_child_environment(change_name),
    )
    finished_at = _utc_now()
    try:
        scenario_results = _scenario_results_from_junit(junit_path, scenarios)
    except (ET.ParseError, OSError, RuntimeError) as error:
        print(f"Mandatory BDD evidence gate failed: {error}", file=sys.stderr)
        failed = dict(preflight)
        failed.update(acceptance_state="failed", finished_at_utc=finished_at, exit_code=result.returncode or 1, error=str(error))
        _write_evidence(evidence_path, failed)
        return 1

    non_passing = {scenario_id: status for scenario_id, status in scenario_results.items() if status != "passed"}
    evidence: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "change": selected_change,
        "lifecycle_phase": lifecycle_phase,
        "bef_spec_profile": source_profile,
        "normative_source": normative_source,
        "gate": gate_metadata,
        "command": command,
        "acceptance_state": "complete" if result.returncode == 0 and not non_passing else "failed",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "exit_code": result.returncode,
        "git_commit": git_commit,
        "git_worktree_dirty": git_worktree_dirty,
        "main_specs_sha256": main_specs_sha256,
        "active_delta_sha256": active_delta_sha256,
        "harness_contract_sha256": harness_contract_sha256,
        "harness_sources_sha256": harness_sources_sha256,
        "harness_sources_sha256_after": None,
        "source_unchanged": None,
        "scenario_map_sha256": None,
        "harness_audit": audit,
        "scenario_results": scenario_results,
    }

    candidate_fd, candidate_name = tempfile.mkstemp(
        prefix=f"{selected_change}-candidate-", suffix=".json", dir=evidence_directory
    )
    os.close(candidate_fd)
    candidate_path = Path(candidate_name)
    try:
        _write_evidence(candidate_path, evidence)
        final_generate_command = [
            sys.executable,
            str(root / "tools" / "generate_bdd_mirrors.py"),
            "--acceptance-evidence",
            str(candidate_path),
        ]
        if change_name is not None:
            final_generate_command.extend(["--change", change_name])
        final_regenerate = subprocess.run(final_generate_command, cwd=root, check=False)
    finally:
        candidate_path.unlink(missing_ok=True)
    if final_regenerate.returncode != 0:
        evidence.update(acceptance_state="failed", exit_code=result.returncode or 1, error="final mirror regeneration failed")
        _write_evidence(evidence_path, evidence)
        return final_regenerate.returncode

    if not _record_source_integrity(root, change_name, evidence):
        evidence.update(finished_at_utc=_utc_now(), exit_code=result.returncode or 1)
        _write_evidence(evidence_path, evidence)
        print("Harness sources changed during acceptance; rejecting the result.", file=sys.stderr)
        return 1
    try:
        evidence["scenario_map_sha256"] = _sha256_file(scenario_map_path(root, change_name))
    except OSError as error:
        evidence.update(
            acceptance_state="failed",
            finished_at_utc=_utc_now(),
            exit_code=result.returncode or 1,
            error=f"cannot_hash_final_scenario_map: {error}",
        )
        _write_evidence(evidence_path, evidence)
        return 1

    # AICODE-NOTE: Commit the evidence only after candidate-driven mirror validation succeeds.
    _write_evidence(evidence_path, evidence)
    if result.returncode != 0 or non_passing:
        print(f"Recorded per-scenario evidence with {len(non_passing)} non-passing results.", file=sys.stderr)
        return result.returncode or 1
    print(
        f"Recorded {len(scenarios)} passing mandatory {selected_change} scenario results "
        f"in {evidence_path}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

