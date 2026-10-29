"""Replay local website report facts without promoting external beta acceptance."""
from __future__ import annotations

import json
import re

from tests.bdd.adapters.beta_poc_delivery import load_capture
from tests.bdd.adapters.beta_poc_report_verifier import NEGATIVE_NAMES, _derive_018, _derive_020, _derive_negatives


def verify_local_report_path() -> dict:
    captures = {}
    capture_ids = set()
    for scenario_id in ("BPC-SC-018", "BPC-SC-020"):
        loaded = load_capture(scenario_id)
        if loaded is None:
            raise AssertionError(f"No saved local capture for {scenario_id}")
        manifest, artifacts = loaded
        evidence, provenance = artifacts["runtime-evidence.json"], artifacts["provenance.json"]
        before, after = provenance.get("inputHashesBefore"), provenance.get("inputHashesAfter")
        if not before or before != after or provenance.get("sourceStableDuringRun") is not True:
            raise AssertionError("Report capture source changed or has no source inventory")
        if evidence.get("captureBoundary") != "local_acceptance_runner":
            raise AssertionError("This replay is limited to the declared local runner")
        observer = evidence.get("observer", {})
        if (observer.get("databaseRole") != "oid_observer"
                or observer.get("transactionReadOnly") != "on"
                or not re.fullmatch(r"oid_acceptance_[a-f0-9]{32}", observer.get("databaseName", ""))):
            raise AssertionError("Missing isolated independent read-only PostgreSQL observer")
        capture_ids.add(provenance["runId"])
        captures[scenario_id] = (manifest, evidence)
    if len(capture_ids) != 1:
        raise AssertionError("Website creation and admin triage must come from the same capture")

    # Use raw fact derivations, never rewrite local evidence to pretend it came from a target host.
    # The complete external verifier separately requires its target boundary and all negatives.
    owner_facts = _derive_018(captures["BPC-SC-018"][1])
    admin_facts = _derive_020(captures["BPC-SC-020"][1])
    missing = [name for facts in (owner_facts, admin_facts) for name, value in facts.items() if value is not True]
    if missing:
        raise AssertionError(f"Local report facts unverified: {', '.join(missing)}")
    owner_negatives = _derive_negatives("BPC-SC-018", captures["BPC-SC-018"][1])
    admin_negatives = _derive_negatives("BPC-SC-020", captures["BPC-SC-020"][1])
    if set(owner_negatives) != set(NEGATIVE_NAMES["BPC-SC-018"]) or set(admin_negatives) != set(NEGATIVE_NAMES["BPC-SC-020"]):
        raise AssertionError("The raw report verifier returned an incomplete local negative inventory")
    missing_negatives = [name for facts in (owner_negatives, admin_negatives) for name, value in facts.items() if value is not True]
    if missing_negatives:
        raise AssertionError(f"Local report negative facts unverified: {', '.join(missing_negatives)}")
    admin = captures["BPC-SC-020"][1]["browser"]
    controls = {row.get("controlId") for row in admin.get("actions", []) if row.get("action") == "click"}
    if not {"admin-report-close", "admin-report-reopen"} <= controls:
        raise AssertionError("Admin status changes lack initiating browser clicks")
    return {
        "schemaVersion": "bpc-local-report-path-replay/v1",
        "captureId": next(iter(capture_ids)),
        "ownerFormScreenshotPrivateStorageAndAdminTriage": "verified",
        "ownerObservations": owner_facts,
        "adminObservations": admin_facts,
        "ownerNegativeObservations": owner_negatives,
        "adminNegativeObservations": admin_negatives,
        "localNegativeMatrix": "verified_for_BPC-SC-018_and_BPC-SC-020",
        "betaGateStatuses": {key: value[0]["status"] for key, value in captures.items()},
        "externalGoogleAndTargetHost": "not_run",
        "fourNativeClients": "not_run",
        "retentionPurgeAndBackupRestore": "not_run",
        "completeNegativeMatrix": "not_run",
    }


if __name__ == "__main__":
    print(json.dumps(verify_local_report_path(), ensure_ascii=False))
