#!/usr/bin/env python3
"""Verify OID acceptance artifacts from disk without contacting services."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
EVIDENCE_ROOT = ROOT / "artifacts" / "runs" / "acceptance"
SCENARIOS = tuple(f"OID-SC-{index:03d}" for index in range(1, 13))
SECRET_KEY = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|"
    r"invitationcode|invitationsecret|privatekey|mnemonic|seedphrase|authorization|"
    r"databaseurl|rpcurl|oauthcode|oauthstate|rawsignature|signaturevalue)$",
    re.IGNORECASE,
)
SECRET_TEXT = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+",
    re.IGNORECASE,
)


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY.fullmatch(normalized):
                raise ValueError(f"credential-bearing key at {path}.{key}")
            _secret_free(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _secret_free(item, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_TEXT.search(value):
        raise ValueError(f"unredacted credential-like text at {path}")


def _contract_inventory() -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    from tools.harness_contracts import load_manifest

    _manifest, contracts = load_manifest(ROOT, "owner-identity-and-pilot-admission")
    return {
        scenario_id: (contract.required_observations, contract.negative_variants)
        for scenario_id, contract in contracts.items()
    }


def _verify(scenario_id: str, requirements: tuple[tuple[str, ...], tuple[str, ...]]) -> dict[str, Any]:
    scenario_root = EVIDENCE_ROOT / scenario_id
    index = _json(scenario_root / "manifest.json")
    if index.get("schemaVersion") != "owner-identity-evidence-index/v1":
        raise ValueError("unsupported evidence index")
    if index.get("scenarioId") != scenario_id:
        raise ValueError("scenario index mismatch")
    run_id = index.get("latestRunId")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", run_id):
        raise ValueError("invalid latest run ID")
    if run_id not in index.get("runs", []):
        raise ValueError("latest run is absent from run inventory")
    run_root = (scenario_root / "runs" / run_id).resolve()
    if scenario_root.resolve() not in run_root.parents:
        raise ValueError("run path escapes the scenario directory")
    manifest = _json(run_root / "manifest.json")
    _secret_free(manifest, "manifest.json")
    if manifest.get("schemaVersion") != "owner-identity-acceptance/v1":
        raise ValueError("unsupported evidence schema")
    if manifest.get("scenarioId") != scenario_id or manifest.get("runId") != run_id:
        raise ValueError("manifest run identity mismatch")
    if manifest.get("status") not in {"passed", "blocked", "failed"}:
        raise ValueError("invalid scenario status")
    if index.get("status") != manifest.get("status"):
        raise ValueError("evidence index status differs from its latest run")

    required_observations, required_negatives = requirements
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != set(required_observations):
        raise ValueError("named observation inventory differs from the active contract")
    if not isinstance(negatives, dict) or set(negatives) != set(required_negatives):
        raise ValueError("negative variant inventory differs from the active contract")

    artifacts: dict[str, Any] = {}
    inventory = manifest.get("artifacts")
    if not isinstance(inventory, list):
        raise ValueError("artifact inventory missing")
    for item in inventory:
        if not isinstance(item, dict):
            raise ValueError("invalid artifact entry")
        name = item.get("path")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]*\.json", name):
            raise ValueError("unsafe artifact name")
        artifact_path = (run_root / name).resolve()
        if run_root not in artifact_path.parents:
            raise ValueError("artifact path escapes run directory")
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item.get("sha256"):
            raise ValueError(f"artifact hash mismatch: {name}")
        payload = json.loads(content.decode("utf-8"))
        _secret_free(payload, name)
        artifacts[name] = payload

    all_observed = all(
        row.get("status") == "observed" and bool(row.get("evidence"))
        for row in observations.values()
    )
    all_negative = all(
        row.get("status") == "observed" and bool(row.get("evidence"))
        for row in negatives.values()
    )
    from tests.bdd.adapters.oid_evidence_verifier import derive_evidence

    derived_observations, derived_negatives = derive_evidence(scenario_id, manifest, artifacts)
    if manifest["status"] == "passed" and not (all_observed and all_negative):
        raise ValueError("passed status lacks complete named observations and negative evidence")
    if manifest["status"] == "passed" and (
        not all(derived_observations.get(name) is True for name in required_observations)
        or not all(derived_negatives.get(name) is True for name in required_negatives)
    ):
        raise ValueError("passed status does not follow from browser, provider, crypto, and SQL evidence")
    database = artifacts.get("database.json")
    if database and database.get("observer"):
        observer = database["observer"]
        if observer.get("role") != "oid_observer" or observer.get("transaction_read_only") != "on":
            raise ValueError("database evidence is not from a read-only observer")
    return {
        "scenarioId": scenario_id,
        "runId": run_id,
        "status": manifest["status"],
        "artifactCount": len(artifacts),
        "observationStatus": manifest.get("observationStatus"),
        "negativeVariantStatus": manifest.get("negativeVariantStatus"),
        **({"blockedReasonCode": manifest["blockedReasonCode"]} if manifest.get("blockedReasonCode") else {}),
        "integrity": "verified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario_pos", nargs="?", choices=(*SCENARIOS, "all"))
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"))
    parser.add_argument("--require-passed", action="store_true")
    args = parser.parse_args(argv)
    scenario = args.scenario or args.scenario_pos or "all"
    selected = SCENARIOS if scenario == "all" else (scenario,)
    try:
        contracts = _contract_inventory()
        results = [_verify(item, contracts[item]) for item in selected]
    except (OSError, ValueError, json.JSONDecodeError, KeyError) as error:
        report = {
            "schemaVersion": "owner-identity-evidence-replay/v1",
            "replayMode": "filesystem-only; no network, browser, or database access",
            "status": "failed",
            "errorType": type(error).__name__,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    blocked = args.require_passed and any(item["status"] != "passed" for item in results)
    report = {
        "schemaVersion": "owner-identity-evidence-replay/v1",
        "replayMode": "filesystem-only; no network, browser, or database access",
        "status": "blocked" if blocked else "verified",
        "scenarios": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
