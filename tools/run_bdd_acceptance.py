#!/usr/bin/env python3
"""Run every approved local gate and record one result per normative scenario."""

from __future__ import annotations

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
    ACCEPTANCE_RELATIVE,
    CHANGE_NAME,
    LIFECYCLE_PHASE,
    NORMATIVE_SOURCE,
    parse_specs,
)
from tools.harness_contracts import harness_source_paths, main_spec_paths, manifest_path, sha256_files


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
        if testcase.find("skipped") is not None:
            result = "skipped"
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


def main() -> int:
    root = REPOSITORY_ROOT
    scenarios = parse_specs(root)
    evidence_directory = root / "artifacts" / "bdd-evidence"
    evidence_directory.mkdir(parents=True, exist_ok=True)
    junit_path = evidence_directory / f"{CHANGE_NAME}-pytest.xml"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/bdd",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--junitxml={junit_path}",
    ]
    started_at = _utc_now()
    evidence_path = root / ACCEPTANCE_RELATIVE
    preflight: dict[str, object] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "change": CHANGE_NAME,
        "lifecycle_phase": LIFECYCLE_PHASE,
        "normative_source": NORMATIVE_SOURCE,
        "gate": {"class": "local", "mandatory": True},
        "command": command,
        "acceptance_state": "running",
        "started_at_utc": started_at,
        "finished_at_utc": None,
        "exit_code": None,
        "git_commit": None,
        "git_worktree_dirty": None,
        "main_specs_sha256": None,
        "harness_contract_sha256": None,
        "harness_sources_sha256": None,
        "harness_audit": {"status": "not_run"},
        "scenario_results": {scenario.scenario_id: "not_run" for scenario in scenarios},
    }
    # AICODE-NOTE: Record running before subprocesses so interruption cannot leave an older pass
    # looking current to the traceability generator.
    _write_evidence(evidence_path, preflight)

    try:
        git_commit, git_worktree_dirty = _git_metadata(root)
        main_specs_sha256 = sha256_files(root, main_spec_paths(root))
        harness_contract_sha256 = _sha256_file(manifest_path(root))
        harness_sources_sha256 = sha256_files(root, harness_source_paths(root))
    except (OSError, RuntimeError) as error:
        print(f"Mandatory reproducibility gate failed: {error}", file=sys.stderr)
        preflight.update(acceptance_state="failed", finished_at_utc=_utc_now(), exit_code=1, error=str(error))
        _write_evidence(evidence_path, preflight)
        return 1

    preflight.update(
        git_commit=git_commit,
        git_worktree_dirty=git_worktree_dirty,
        main_specs_sha256=main_specs_sha256,
        harness_contract_sha256=harness_contract_sha256,
        harness_sources_sha256=harness_sources_sha256,
    )
    audit_process = subprocess.run(
        [sys.executable, str(root / "tools" / "check_bdd_harness.py"), "--json"],
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

    regenerate = subprocess.run(
        [sys.executable, str(root / "tools" / "generate_bdd_mirrors.py")], cwd=root, check=False
    )
    if regenerate.returncode != 0:
        preflight.update(acceptance_state="failed", finished_at_utc=_utc_now(), exit_code=1)
        _write_evidence(evidence_path, preflight)
        return regenerate.returncode

    result = subprocess.run(command, cwd=root, text=True, check=False, env=os.environ.copy())
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
        "change": CHANGE_NAME,
        "lifecycle_phase": LIFECYCLE_PHASE,
        "normative_source": NORMATIVE_SOURCE,
        "gate": {"class": "local", "mandatory": True},
        "command": command,
        "acceptance_state": "complete" if result.returncode == 0 and not non_passing else "failed",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "exit_code": result.returncode,
        "git_commit": git_commit,
        "git_worktree_dirty": git_worktree_dirty,
        "main_specs_sha256": main_specs_sha256,
        "harness_contract_sha256": harness_contract_sha256,
        "harness_sources_sha256": harness_sources_sha256,
        "harness_audit": audit,
        "scenario_results": scenario_results,
    }

    candidate_fd, candidate_name = tempfile.mkstemp(
        prefix=f"{CHANGE_NAME}-candidate-", suffix=".json", dir=evidence_directory
    )
    os.close(candidate_fd)
    candidate_path = Path(candidate_name)
    try:
        _write_evidence(candidate_path, evidence)
        final_regenerate = subprocess.run(
            [
                sys.executable,
                str(root / "tools" / "generate_bdd_mirrors.py"),
                "--acceptance-evidence",
                str(candidate_path),
            ],
            cwd=root,
            check=False,
        )
    finally:
        candidate_path.unlink(missing_ok=True)
    if final_regenerate.returncode != 0:
        evidence.update(acceptance_state="failed", exit_code=result.returncode or 1, error="final mirror regeneration failed")
        _write_evidence(evidence_path, evidence)
        return final_regenerate.returncode

    # AICODE-NOTE: Commit the evidence only after candidate-driven mirror validation succeeds.
    _write_evidence(evidence_path, evidence)
    if result.returncode != 0 or non_passing:
        print(f"Recorded per-scenario evidence with {len(non_passing)} non-passing results.", file=sys.stderr)
        return result.returncode or 1
    print(f"Recorded {len(scenarios)} passing mandatory scenario results in {evidence_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

