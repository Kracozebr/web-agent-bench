"""Replay the narrow local browser issue/claim path; never promote a beta gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.bdd.adapters.beta_poc_delivery import load_capture


def one(rows: list[dict], **matches: str) -> dict:
    found = [row for row in rows if all(row.get(key) == value for key, value in matches.items())]
    if len(found) != 1:
        raise AssertionError(f"Expected exactly one correlated row: {','.join(matches)}")
    return found[0]


def units(value: str) -> int:
    import re
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{6}", value):
        raise AssertionError("UI money value must have exact six-place precision")
    return int(value.replace(".", ""))


def verify_local_bonus_path() -> dict:
    loaded = load_capture("BPC-SC-005")
    if loaded is None:
        raise AssertionError("No local bonus capture exists")
    manifest, artifacts = loaded
    evidence, provenance = artifacts["runtime-evidence.json"], artifacts["provenance.json"]
    before, after = provenance.get("inputHashesBefore"), provenance.get("inputHashesAfter")
    if not before or before != after or provenance.get("sourceStableDuringRun") is not True:
        raise AssertionError("Capture source changed or has no source inventory")
    database, browser = evidence["database"], evidence["browser"]
    observer = database["observer"]
    if observer.get("role") != "oid_observer" or observer.get("transaction_read_only") != "on":
        raise AssertionError("No independent read-only database observation")
    outcomes = browser["outcomes"]
    verified = []
    for prefix, owner_capture, before_balance, after_balance in (
        ("group", "owner", "ownerBalanceBefore", "ownerBalanceAfter"),
        ("single", "secondOwner", "secondBalanceBefore", "secondBalanceAfter"),
    ):
        issue, claim = outcomes[f"{prefix}Issue"], outcomes[f"{prefix}Claim"]
        if issue["status"] != 201 or claim["status"] != 200 or claim["replayed"] is not False:
            raise AssertionError("Initial issue/claim did not commit successfully")
        admin, owner = browser["admin"], browser[owner_capture]
        for capture, operation, path, selector in (
            (admin, issue["operationId"], "/api/admin/bonus-codes", "bonus-code-issue-submit"),
            (owner, claim["operationId"], "/api/owner/bonus-codes/redeem", "bonus-code-redeem-submit"),
        ):
            if not any(row.get("action") == "click" and row.get("selector") == selector for row in capture["actions"]):
                raise AssertionError("Initiating browser click is absent")
            one(capture["requests"], operationId=operation, path=path, method="POST")
            if not any(row.get("path") == path and row.get("method") == "POST" and row.get("status") in {200, 201} for row in capture["responses"]):
                raise AssertionError("Browser success response is absent")
        code = one(database["codes"], id=issue["codeId"], issue_operation_id=issue["operationId"])
        redemption = one(database["redemptions"], id=claim["redemptionId"], code_id=code["id"], bonus_grant_id=claim["grantId"])
        grant = one(database["grants"], id=claim["grantId"], owner_id=redemption["owner_id"])
        key = "bcg_" + hashlib.sha256(f"{code['id']}\0{redemption['owner_id']}".encode()).hexdigest()
        if code["used_count"] != 1 or grant["amount_units"] != code["amount_units"] or grant["expires_at"] is not None:
            raise AssertionError("Claim quantity, exact amount or no-expiry terms diverged")
        if redemption["financial_operation_id"] != key or grant["operation_id"] != key:
            raise AssertionError("Financial lineage diverged")
        one(database["claimOperations"], owner_id=redemption["owner_id"], operation_id=claim["operationId"], redemption_id=redemption["id"])
        entry = one(database["entries"], bonus_grant_id=grant["id"], operation_id=key, entry_type="bonus_grant", source_kind="tester_bonus")
        if int(entry["available_delta_units"]) != int(code["amount_units"]) or int(entry["reserved_delta_units"]) != 0:
            raise AssertionError("Ledger credit diverged")
        one(database["operations"], operation_id=key, action="bonus_grant", subject_owner_id=redemption["owner_id"])
        one(database["audits"], operation_id=key, event_type="bonus_grant_issued")
        one(database["audits"], operation_id=claim["operationId"], event_type="bonus_code_redeemed")
        ui_before, ui_after = outcomes[before_balance], outcomes[after_balance]
        if units(ui_after["bonus"]["available"]) - units(ui_before["bonus"]["available"]) != int(entry["available_delta_units"]):
            raise AssertionError("Visible UI balance increase does not match independent ledger credit")
        if ui_before["cash"] != ui_after["cash"] or database["cashEffectCount"] != 0:
            raise AssertionError("Bonus journey changed cash")
        verified.append({"kind": code["kind"], "creditedBonusUsdc": ui_after["bonus"]["available"]})
    return {"schemaVersion": "bpc-local-bonus-path-replay/v1", "captureId": provenance["runId"],
            "localBrowserIssueClaimLedgerPath": "verified", "claims": verified,
            "betaGateStatus": manifest["status"], "trainingAndFull12Funding": "not_run",
            "externalGoogleAndTargetHost": "not_run"}


if __name__ == "__main__":
    print(json.dumps(verify_local_bonus_path(), ensure_ascii=False))
