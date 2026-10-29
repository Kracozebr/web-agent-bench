"""Replay local BPC-SC-017/022/026 captures without promoting target gates."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from tests.bdd.adapters.beta_poc_recovery_verifier import (
    NEGATIVE_NAMES,
    OBSERVATION_NAMES,
    verify_local_recovery_capture,
    verify_local_recovery_result,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RUN_ROOT = REPOSITORY_ROOT / "artifacts" / "runs"


def _read_capture(path: Path, repository_root: Path) -> tuple[dict[str, Any], str]:
    root = repository_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if root not in resolved.parents or not resolved.is_file() or resolved.name != "capture.json":
        raise AssertionError("Capture path must be a repository-contained capture.json file")
    data = resolved.read_bytes()
    if len(data) > 64 * 1024 * 1024:
        raise AssertionError("Capture exceeds the replay file size bound")
    try:
        capture = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError("Capture is not valid UTF-8 JSON") from exc
    if not isinstance(capture, dict):
        raise AssertionError("Capture root must be a JSON object")
    from tests.bdd.adapters.beta_poc_delivery import _assert_secret_free

    _assert_secret_free(capture, resolved.name)
    return capture, hashlib.sha256(data).hexdigest()


def _latest_capture(root: Path) -> Path | None:
    if not root.is_dir():
        return None
    candidates = []
    for child in root.iterdir():
        if not child.is_dir() or child.is_symlink():
            continue
        capture_path = child / "capture.json"
        if capture_path.is_file() and not capture_path.is_symlink():
            candidates.append(capture_path)
    return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None


def _local_status_map(facts: dict[str, bool]) -> tuple[dict[str, str], dict[str, str]]:
    observations = {name: "verified" if facts.get(name) is True else "not_run" for name in OBSERVATION_NAMES}
    negatives = {name: "verified" if facts.get(name) is True else "not_run" for name in NEGATIVE_NAMES}
    return observations, negatives


def _replay_standalone(path: Path, repository_root: Path) -> dict[str, Any]:
    capture, digest = _read_capture(path, repository_root)
    replay = verify_local_recovery_capture(capture, repository_root=repository_root)
    if path.parent.name != capture.get("captureId"):
        raise AssertionError("Capture directory does not match its capture id")
    return {**replay, "artifact": {"path": path.relative_to(repository_root).as_posix(), "sha256": digest}}


def _replay_combined_nested_recovery(capture: dict[str, Any], path: Path, digest: str,
                                     repository_root: Path) -> dict[str, Any]:
    result = capture.get("result")
    if not isinstance(result, dict):
        raise AssertionError("Combined capture result is malformed")
    recovery = result.get("recovery")
    if not isinstance(recovery, dict):
        return {"localStatus": "not_run", "targetHostAcceptance": "not_run",
                "reasonCode": "combined_capture_has_no_completed_recovery_result",
                "artifact": {"path": path.relative_to(repository_root).as_posix(), "sha256": digest}}
    database_name = recovery.get("database", {}).get("name") if isinstance(recovery.get("database"), dict) else None
    facts = verify_local_recovery_result(recovery, database_name, repository_root=repository_root)
    observations, negatives = _local_status_map(facts)
    return {"schemaVersion": "bpc-local-platform-recovery-replay/v1",
            "captureId": capture.get("captureId"), "databaseName": database_name,
            "localStatus": "observed_partial", "observations": observations, "negativeVariants": negatives,
            "targetHostAcceptance": "not_run", "fullScenarioAcceptance": "not_run",
            "artifact": {"path": path.relative_to(repository_root).as_posix(), "sha256": digest}}


def _replay_combined_capture(path: Path, repository_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    capture, digest = _read_capture(path, repository_root)
    if capture.get("schemaVersion") != "beta-combined-restore-capture/v1" \
            or not isinstance(capture.get("captureId"), str) or path.parent.name != capture.get("captureId"):
        raise AssertionError("Combined capture wrapper identity is invalid")
    from tests.bdd.adapters import beta_poc_combined_restore_verifier

    combined = beta_poc_combined_restore_verifier.verify_local_combined_restore_capture(
        capture, repository_root=repository_root)
    if not isinstance(combined, dict) or combined.get("scenarioId") != "BPC-SC-022" \
            or combined.get("fullScenarioAcceptance") is not False or combined.get("targetGateStatus") != "blocked":
        raise AssertionError("Combined restore verifier returned an invalid local-only result")
    combined = {**combined, "artifact": {"path": path.relative_to(repository_root).as_posix(), "sha256": digest}}
    recovery = _replay_combined_nested_recovery(capture, path, digest, repository_root)
    return combined, recovery


def replay_local_captures(*, repository_root: Path = REPOSITORY_ROOT,
                          recovery_capture: Path | None = None,
                          combined_capture: Path | None = None) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    standalone_path = recovery_capture or _latest_capture(repository_root / "artifacts" / "runs" / "beta-platform-recovery")
    combined_path = combined_capture or _latest_capture(repository_root / "artifacts" / "runs" / "beta-combined-restore")
    standalone = _replay_standalone(standalone_path, repository_root) if standalone_path else None
    combined_result = None
    combined_recovery = None
    if combined_path:
        combined_result, combined_recovery = _replay_combined_capture(combined_path, repository_root)
    if standalone is None and combined_recovery is None:
        raise AssertionError("No standalone or combined local recovery capture is available")
    return {
        "schemaVersion": "bpc-local-recovery-restore-replay/v1",
        "recoveryCaptures": [row for row in (standalone, combined_recovery) if row is not None],
        "combinedRestore": combined_result or {"scenarioId": "BPC-SC-022", "localStatus": "not_run",
                                                "targetGateStatus": "blocked", "fullScenarioAcceptance": False},
        "officialTargetGates": {"BPC-SC-017": "not_run", "BPC-SC-022": "not_run", "BPC-SC-026": "not_run"},
        "nativeClients": "not_run",
        "externalFailureDomain": "not_run",
        "productionRecoveryAuthority": "not_run",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--recovery-capture", type=Path)
    parser.add_argument("--combined-capture", type=Path)
    args = parser.parse_args()
    result = replay_local_captures(repository_root=args.repository_root,
                                   recovery_capture=args.recovery_capture,
                                   combined_capture=args.combined_capture)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

