"""Independently replay the local BPC-SC-005 bonus restrictions.

This module only reads saved evidence. It derives the negative results from the
HTTP outcomes and raw read-only PostgreSQL snapshots, and never changes a BDD
gate or manifest.
"""
from __future__ import annotations

import hashlib
import json
import re

from tests.bdd.adapters.beta_poc_delivery import load_capture


ACCEPTANCE_DB = re.compile(r"^oid_acceptance_[0-9a-f]{32}$", re.IGNORECASE)
CODE_SNAPSHOT_FIELDS = (
    "codes", "redemptions", "claimOperations", "grants", "entries", "operations", "audits",
    "ownerBalances", "cashEffectCount",
)
RUN_SNAPSHOT_FIELDS = (
    "intent", "agentIntents", "runs", "reservations", "budgetHolds", "tasks", "ledgerEntries",
    "ledgerOperations", "runOperations", "ledgerAudits", "agentPolicy", "bonusGrants",
    "bonusAvailableUnits", "financialPolicy",
)
CODE_SNAPSHOT_SHAPES = {field: list for field in CODE_SNAPSHOT_FIELDS if field != "cashEffectCount"}
CODE_SNAPSHOT_SHAPES["cashEffectCount"] = int
RUN_SNAPSHOT_SHAPES = {
    "intent": (dict, type(None)), "agentIntents": list, "runs": list, "reservations": list,
    "budgetHolds": list, "tasks": list, "ledgerEntries": list, "ledgerOperations": list,
    "runOperations": list, "ledgerAudits": list, "agentPolicy": dict, "bonusGrants": list,
    "bonusAvailableUnits": str, "financialPolicy": dict,
}


def one(rows: list[dict], **matches: object) -> dict:
    found = [row for row in rows if all(row.get(key) == value for key, value in matches.items())]
    if len(found) != 1:
        raise AssertionError(f"Expected exactly one correlated row: {','.join(matches)}")
    return found[0]


def units(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{6}", value):
        raise AssertionError("UI money value must have exact six-place precision")
    return int(value.replace(".", ""))


def _assert_readonly_identity(snapshot: dict, expected_database: str | None = None) -> str:
    identity = snapshot.get("identity") or snapshot.get("observer")
    if not isinstance(identity, dict):
        raise AssertionError("Raw snapshot has no database identity")
    database = identity.get("database") or identity.get("database_name")
    if identity.get("role") != "oid_observer" or identity.get("transaction_read_only") != "on":
        raise AssertionError("Raw snapshot is not from the read-only oid_observer transaction")
    if not isinstance(database, str) or not ACCEPTANCE_DB.fullmatch(database):
        raise AssertionError("Raw snapshot is not from a uniquely named acceptance database")
    if expected_database is not None and database != expected_database:
        raise AssertionError("Raw snapshots do not bind to the same isolated acceptance database")
    return database


def _unchanged(before: dict, after: dict, fields: tuple[str, ...], expected_database: str,
               shapes: dict[str, type | tuple[type, ...]]) -> bool:
    for snapshot in (before, after):
        _assert_readonly_identity(snapshot, expected_database)
        for field in fields:
            if field not in snapshot:
                raise AssertionError(f"Raw snapshot is missing required relation or scalar: {field}")
            expected_shape = shapes.get(field)
            if expected_shape is None or not isinstance(snapshot[field], expected_shape):
                raise AssertionError(f"Raw snapshot has an invalid shape for: {field}")
    if "cashEffectCount" in fields and (type(before["cashEffectCount"]) is not int
                                        or type(after["cashEffectCount"]) is not int):
        raise AssertionError("Raw cash-effect count is not an integer")
    if "bonusAvailableUnits" in fields and any(
            not re.fullmatch(r"(?:0|[1-9][0-9]*)", snapshot["bonusAvailableUnits"])
            for snapshot in (before, after)):
        raise AssertionError("Raw bonus balance is not an integer unit string")
    return all(before.get(field) == after.get(field) for field in fields)


def _require_no_run_effects(snapshot: dict, denied_operation_id: str) -> None:
    for field in ("runs", "reservations", "budgetHolds", "tasks"):
        if snapshot.get(field) != []:
            raise AssertionError(f"Denied run request left durable {field}")
    if any(row.get("entry_type") in {"reserve", "debit"} for row in snapshot.get("ledgerEntries", [])):
        raise AssertionError("Denied run request left a bonus reserve or debit")
    for field in ("ledgerEntries", "ledgerOperations", "runOperations", "ledgerAudits"):
        if any(row.get("operation_id") == denied_operation_id for row in snapshot.get(field, [])):
            raise AssertionError("Denied run operation was recorded despite the rejection")


def _verify_ui_request(capture: dict, *, operation_id: str, path: str, status: int, action: str) -> None:
    if not any(row.get("action") == "click" and row.get("selector") == action
               for row in capture.get("actions", [])):
        raise AssertionError("Required initiating UI action is absent")
    _verify_captured_post(capture, operation_id=operation_id, path=path, status=status)


def _verify_captured_post(capture: dict, *, operation_id: str, path: str, status: int) -> None:
    if not any(row.get("method") == "POST" and row.get("path") == path
               and row.get("operationId") == operation_id for row in capture.get("requests", [])):
        raise AssertionError("Required browser POST is absent or not bound to its operation")
    if not any(row.get("method") == "POST" and row.get("path") == path and row.get("status") == status
               for row in capture.get("responses", [])):
        raise AssertionError("Required browser response status is absent")


def _verify_browser_http_probe(capture: dict, outcome: dict, *, operation_id: str,
                               path: str, status: int, probe: str) -> None:
    if not any(row.get("action") == "http-probe" and row.get("selector") == probe
               for row in capture.get("actions", [])):
        raise AssertionError("Explicit browser HTTP probe marker is absent")
    _verify_captured_post(capture, operation_id=operation_id, path=path, status=status)
    response = outcome.get("response") if isinstance(outcome, dict) else None
    if (not isinstance(response, dict) or response.get("method") != "POST" or response.get("path") != path
            or response.get("status") != status or response.get("operationId") != operation_id
            or outcome.get("status") != status or outcome.get("operationId") != operation_id):
        raise AssertionError("Browser HTTP probe response is not correlated to the denied request")


def verify_code_claim_denial(case: dict, expected_database: str | None = None) -> dict:
    """Derive anonymous/agent claim denial from the raw code and ledger rows."""
    outcome = case.get("outcome", {})
    if outcome.get("method") != "POST" or outcome.get("path") != "/api/owner/bonus-codes/redeem":
        raise AssertionError("Bonus claim denial did not use the owner redemption HTTP route")
    if outcome.get("status") != 401 or outcome.get("errorCode") != "UNAUTHORIZED":
        raise AssertionError("Bonus claim route did not deny the unauthenticated principal")
    if case.get("cookieCountBefore") != 0 or case.get("cookieCountAfter") != 0:
        raise AssertionError("Bonus claim denial was not exercised without owner cookies")
    boundary = case.get("boundary")
    if boundary == "valid_agent_bearer_without_owner_cookie":
        preflight = case.get("preflight") or {}
        if (preflight.get("status") != 200 or preflight.get("allowed") is not True
                or preflight.get("agentId") != case.get("agentId") or preflight.get("cookieCount") != 0):
            raise AssertionError("Agent claim denial did not use a separately preflighted valid agent bearer")
    elif boundary != "anonymous_without_owner_cookie":
        raise AssertionError("Unknown bonus-claim denial boundary")

    before, after = case.get("before"), case.get("after")
    database = _assert_readonly_identity(before, expected_database)
    if not _unchanged(before, after, CODE_SNAPSHOT_FIELDS, database, CODE_SNAPSHOT_SHAPES):
        raise AssertionError("Denied bonus claim changed raw code, ledger, audit, balance, or cash rows")
    code = one(after.get("codes", []), id=case.get("codeId"), issue_operation_id=case.get("issueOperationId"))
    if code.get("used_count") != 0 or code.get("maximum_uses") != 1:
        raise AssertionError("Denied bonus claim consumed or changed its single-use code")
    attempt = outcome.get("operationId")
    if not isinstance(attempt, str) or any(row.get("operation_id") == attempt
            for field in ("claimOperations", "operations", "audits", "entries") for row in after.get(field, [])):
        raise AssertionError("Denied bonus claim left an operation, audit, or ledger row")
    grant_operation = "bcg_" + hashlib.sha256(
        f"{case.get('codeId')}\0{case.get('claimOwnerId')}".encode("utf-8")
    ).hexdigest()
    if (any(row.get("operation_id") == grant_operation for row in after.get("grants", []))
            or any(row.get("operation_id") == grant_operation for row in after.get("entries", []))
            or after.get("cashEffectCount") != 0):
        raise AssertionError("Denied bonus claim created a grant, ledger credit, or cash effect")
    if any(row.get("code_id") == case.get("codeId") for row in after.get("redemptions", [])):
        raise AssertionError("Denied bonus claim created a redemption")
    return {"boundary": boundary, "httpStatus": outcome["status"], "database": database,
            "denialWithoutMutation": True}


def verify_run_denial(case: dict, *, expected_database: str | None = None,
                      expected_status: int, expected_error: str, kind: str) -> dict:
    """Verify a rejected owner/agent run request from HTTP plus raw snapshots."""
    request = case.get("request") if kind == "missing_mode_permission" else case.get("accept")
    if not isinstance(request, dict) or request.get("method") != "POST":
        raise AssertionError("Run denial has no real POST request observation")
    if kind == "missing_mode_permission":
        if request.get("path") != "/api/owner/runs/intents":
            raise AssertionError("Missing-permission denial did not exercise owner intent creation")
        denied_operation = case.get("ownerOperationId")
        if request.get("operationId") != denied_operation:
            raise AssertionError("Missing-permission request operation binding diverged")
    else:
        intent_id = case.get("intent", {}).get("intentId")
        if request.get("path") != f"/api/agent/run-intents/{intent_id}/accept":
            raise AssertionError("Agent denial did not exercise the matching intent accept route")
        denied_operation = request.get("operationId")
    if request.get("status") != expected_status or request.get("errorCode") != expected_error:
        raise AssertionError(f"Run request was not rejected with {expected_error}")

    before, after = case.get("before"), case.get("after")
    database = _assert_readonly_identity(before, expected_database)
    if not _unchanged(before, after, RUN_SNAPSHOT_FIELDS, database, RUN_SNAPSHOT_SHAPES):
        raise AssertionError("Denied run request changed raw run, policy, budget, or ledger state")
    if not isinstance(denied_operation, str):
        raise AssertionError("Run denial has no correlated operation id")
    _require_no_run_effects(after, denied_operation)

    if kind == "missing_mode_permission":
        if before.get("agentPolicy", {}).get("training") is not False:
            raise AssertionError("Missing-permission request was not tested with training disabled")
        if before.get("intent") is not None or before.get("agentIntents"):
            raise AssertionError("Forbidden owner request persisted a launch intent")
        return {"kind": kind, "httpStatus": request["status"], "database": database,
                "denialWithoutMutation": True}

    intent = case.get("intent", {})
    intent_row = one(after.get("agentIntents", []), id=intent.get("intentId"))
    if (intent_row.get("operation_id") != intent.get("operationId") or intent_row.get("status") != "pending"
            or intent_row.get("run_id") is not None):
        raise AssertionError("Rejected agent acceptance did not leave only the pre-existing pending intent")
    expected_tasks = ["S1"] if kind == "nominal_cap_exceeded" else ["S1", "S2", "S4", "M1", "M3", "M4", "H1", "H2"]
    if (intent_row.get("mode") != "training" or intent.get("mode") != "training"
            or intent_row.get("task_ids") != expected_tasks or intent.get("taskIds") != expected_tasks):
        raise AssertionError("Rejected acceptance does not bind the intended training selection")
    quote_units = int(intent_row.get("quote_price_units", "-1"))
    if kind == "nominal_cap_exceeded" and quote_units != int(case.get("operationQuoteUnits", "-2")):
        raise AssertionError("Observed pending quote diverges from the prepared cap-denial quote")
    if kind == "insufficient_bonus" and quote_units != int(case.get("quoteUnits", "-2")):
        raise AssertionError("Observed pending quote diverges from the prepared shortfall quote")
    if kind == "nominal_cap_exceeded":
        quote = quote_units
        limit = int((after.get("financialPolicy") or {}).get("operation_limit_units", "-1"))
        if quote <= limit or after.get("financialPolicy", {}).get("allow_cash_shortfall") is not False:
            raise AssertionError("Nominal cap denial lacks a lower persisted operation cap")
        if limit != int(case.get("operationLimitUnits", "-2")):
            raise AssertionError("Observed operation cap diverges from the policy confirmed by the owner UI")
    elif kind == "insufficient_bonus":
        quote = quote_units
        balance = int(before.get("bonusAvailableUnits", "-1"))
        if quote <= balance or balance != 0:
            raise AssertionError("Insufficient-bonus denial does not have a positive observed shortfall")
        if int(case.get("shortfallUnits", "-2")) != quote - balance:
            raise AssertionError("Reported shortfall diverges from the independently observed quote and bonus balance")
        policy = after.get("financialPolicy") or {}
        if policy.get("allow_cash_shortfall") is not False or policy.get("operation_limit_units") is not None:
            raise AssertionError("Insufficient-bonus request was confounded by cash permission or an operation cap")
        if int(after.get("bonusAvailableUnits", "-1")) != balance:
            raise AssertionError("Observed bonus balance changed during the rejected acceptance")
        if intent_row.get("task_ids") != case.get("intent", {}).get("taskIds"):
            raise AssertionError("Insufficient-bonus full selection diverged from the pending intent")
    else:
        raise AssertionError("Unknown run denial kind")
    cleanup = case.get("cleanup") or {}
    if cleanup.get("status") != 200 or cleanup.get("statusAfterCleanup") != "cancelled":
        raise AssertionError("Pending fixture intent was not explicitly cancelled after the denial snapshot")
    return {"kind": kind, "httpStatus": request["status"], "database": database,
            "denialWithoutMutation": True, "pendingIntentCancelledAfterSnapshot": True}


def _totals(snapshot: dict) -> dict[str, dict]:
    return {row.get("source_kind"): row for row in snapshot.get("totals", [])}


def verify_bonus_only_cash_substitution(case: dict, expected_database: str | None = None) -> dict:
    """Derive direct-service bonusOnly shortfall proof from its raw relations."""
    if case.get("boundary") != "local_isolated_direct_service_with_independent_read_only_postgres":
        raise AssertionError("Bonus-only cash probe has an unapproved evidence boundary")
    rejection = case.get("rejection") or {}
    if rejection.get("status") != 409 or rejection.get("code") != "BETA_BONUS_BALANCE_REQUIRED":
        raise AssertionError("Injected bonusOnly service did not reject cash substitution")
    before, after = case.get("before"), case.get("after")
    database = _assert_readonly_identity(before, expected_database)
    _assert_readonly_identity(after, database)
    funding = case.get("funding") or {}
    code = one([after.get("code")], id=funding.get("codeId"))
    grant = one([after.get("grant")], id=funding.get("grantId"))
    redemption = one([after.get("redemption")], id=funding.get("redemptionId"))
    owner_id, issuer_id = funding.get("ownerId"), funding.get("issuerOwnerId")
    grant_operation = "bcg_" + hashlib.sha256(f"{code['id']}\0{owner_id}".encode()).hexdigest()
    if (code.get("issuer_owner_id") != issuer_id or code.get("issue_operation_id") != funding.get("issueOperationId")
            or code.get("used_count") != 1 or code.get("maximum_uses") != 1 or code.get("amount_units") != "250000"):
        raise AssertionError("Raw issued single-use code facts diverged")
    if (redemption.get("code_id") != code.get("id") or redemption.get("owner_id") != owner_id
            or redemption.get("bonus_grant_id") != grant.get("id")
            or redemption.get("financial_operation_id") != grant_operation):
        raise AssertionError("Raw redemption does not bind the code, owner, grant, and financial operation")
    if (grant.get("owner_id") != owner_id or grant.get("issued_by_owner_id") != issuer_id
            or grant.get("operation_id") != grant_operation or grant.get("amount_units") != "250000"
            or grant.get("expires_at") is not None):
        raise AssertionError("Raw grant does not match the redeemed code lot")
    claim_operation = funding.get("redemptionOperationId")
    one(after.get("claimOperations", []), owner_id=owner_id, operation_id=claim_operation,
        code_id=code.get("id"), redemption_id=redemption.get("id"))
    grant_op = one(after.get("ledgerOperations", []), operation_id=grant_operation, action="bonus_grant",
                   actor_owner_id=issuer_id, subject_owner_id=owner_id)
    del grant_op
    grant_audit = one(after.get("audits", []), operation_id=grant_operation, event_type="bonus_grant_issued")
    if grant_audit.get("metadata", {}).get("grantId") != grant.get("id"):
        raise AssertionError("Grant audit does not bind the persisted grant")
    one(after.get("audits", []), operation_id=claim_operation, event_type="bonus_code_redeemed")
    entry = one(after.get("ledgerEntries", []), bonus_grant_id=grant.get("id"), operation_id=grant_operation,
                entry_type="bonus_grant", source_kind="tester_bonus")
    if (entry.get("owner_id") != owner_id or entry.get("actor_owner_id") != issuer_id
            or entry.get("available_delta_units") != "250000" or entry.get("reserved_delta_units") != "0"):
        raise AssertionError("Raw ledger grant row does not match the grant/code lineage")

    before_totals, after_totals = _totals(before), _totals(after)
    bonus_units = int(after_totals.get("tester_bonus", {}).get("available_units", "-1"))
    cash_units = int(after_totals.get("cash_usdc", {}).get("available_units", "-1"))
    quote_units = int((after.get("intent") or {}).get("quote_price_units", "-1"))
    if case.get("syntheticRelease", {}).get("selectedQuoteUnits") != str(quote_units):
        raise AssertionError("Selected synthetic release quote does not match the persisted intent")
    if (bonus_units != 250000 or quote_units - bonus_units != 750000 or cash_units < quote_units - bonus_units
            or (after.get("policy") or {}).get("allow_cash_shortfall") is not True):
        raise AssertionError("Raw bonus shortfall is not backed by enough cash and owner cash permission")
    direct_fields = (
            "code", "redemption", "grant", "claimOperations", "ledgerEntries", "ledgerOperations", "audits",
            "totals", "policy", "intent", "runs", "runOperations", "reservations", "budgetHolds")
    direct_shapes = {field: list for field in direct_fields if field in {
        "claimOperations", "ledgerEntries", "ledgerOperations", "audits", "totals", "runs", "runOperations",
        "reservations", "budgetHolds",
    }}
    direct_shapes.update({field: dict for field in direct_fields if field in {
        "code", "redemption", "grant", "policy", "intent",
    }})
    if not _unchanged(before, after, direct_fields, database, direct_shapes):
        raise AssertionError("Rejected bonus-only accept changed code, balances, run, or ledger state")
    intent = after.get("intent") or {}
    if intent.get("quote_price_units") != str(quote_units):
        raise AssertionError("Selected synthetic release quote diverges from the persisted intent")
    if (intent.get("status") != "pending" or intent.get("run_id") is not None
            or intent.get("quote_price_units") != str(quote_units)
            or intent.get("cash_ceiling_units") != str(quote_units)
            or after.get("runs") or after.get("reservations") or after.get("budgetHolds")):
        raise AssertionError("Rejected bonus-only acceptance did not preserve only the pending intent")
    if any(row.get("entry_type") in {"reserve", "debit"} for row in after.get("ledgerEntries", [])):
        raise AssertionError("Rejected bonus-only acceptance left reserve or debit entries")
    accept_operation_id = funding.get("acceptOperationId")
    if not isinstance(accept_operation_id, str) or any(
            row.get("operation_id") == accept_operation_id for row in after.get("runOperations", [])):
        raise AssertionError("Rejected bonus-only acceptance left a persisted run-operation row")
    if before_totals != after_totals:
        raise AssertionError("Raw cash or bonus totals changed during bonus-only rejection")
    return {"boundary": case["boundary"], "database": database,
            "bonusOnlyCashSubstitutionRejected": True, "bonusAvailableUnits": str(bonus_units),
            "cashAvailableUnits": str(cash_units), "shortfallUnits": str(quote_units - bonus_units)}


def verify_local_bonus_path() -> dict:
    loaded = load_capture("BPC-SC-005")
    if loaded is None:
        raise AssertionError("No local bonus capture exists")
    manifest, artifacts = loaded
    evidence, provenance = artifacts["runtime-evidence.json"], artifacts["provenance.json"]
    before, after = provenance.get("inputHashesBefore"), provenance.get("inputHashesAfter")
    if not before or before != after or provenance.get("sourceStableDuringRun") is not True:
        raise AssertionError("Capture source changed or has no source inventory")
    if manifest.get("status") != "blocked":
        raise AssertionError("A local bonus replay must preserve the external acceptance gate as blocked")
    database, browser = evidence["database"], evidence["browser"]
    observer = database["observer"]
    expected_database = _assert_readonly_identity({"observer": observer})
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
            if not any(row.get("path") == path and row.get("method") == "POST" and row.get("status") in {200, 201}
                       for row in capture["responses"]):
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
        entry = one(database["entries"], bonus_grant_id=grant["id"], operation_id=key,
                    entry_type="bonus_grant", source_kind="tester_bonus")
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

    negatives = browser.get("transportNegatives")
    if not isinstance(negatives, dict):
        raise AssertionError("SC005 capture has no authenticated transport-negative evidence")
    claim_proofs = [verify_code_claim_denial(negatives.get("bonusClaimDenials", {}).get(name, {}), expected_database)
                    for name in ("anonymous", "agent")]
    admin_capture = browser.get("admin", {})
    for claim_case in negatives.get("bonusClaimDenials", {}).values():
        _verify_ui_request(admin_capture, operation_id=claim_case.get("issueOperationId", ""),
                           path="/api/admin/bonus-codes", status=201,
                           action="bonus-code-issue-submit")
    run_denials = negatives.get("runDenials", {})
    run_capture = negatives.get("browser", {}).get("runLaunch", {})
    mode_case = run_denials.get("missingModePermission", {})
    _verify_browser_http_probe(run_capture, mode_case.get("request", {}),
                               operation_id=mode_case.get("ownerOperationId", ""),
                               path="/api/owner/runs/intents", status=403,
                               probe="run-intent-create-disabled-by-current-mode-permission")
    for run_case_name in ("nominalCapExceeded", "insufficientBonus"):
        run_case = run_denials.get(run_case_name, {})
        intent = run_case.get("intent", {})
        _verify_ui_request(run_capture, operation_id=intent.get("operationId", ""),
                           path="/api/owner/runs/intents", status=201, action="run-intent-create")
    run_proofs = [
        verify_run_denial(run_denials.get("missingModePermission", {}), expected_database=expected_database,
                          expected_status=403, expected_error="MODE_NOT_AUTHORIZED", kind="missing_mode_permission"),
        verify_run_denial(run_denials.get("nominalCapExceeded", {}), expected_database=expected_database,
                          expected_status=409, expected_error="AGENT_BUDGET_EXCEEDED", kind="nominal_cap_exceeded"),
        verify_run_denial(run_denials.get("insufficientBonus", {}), expected_database=expected_database,
                          expected_status=409, expected_error="CASH_PERMISSION_REQUIRED", kind="insufficient_bonus"),
    ]
    direct = evidence.get("supplementaryEvidence", {}).get("syntheticDirectServiceBetaBonusOnlyCashSubstitution")
    direct_proof = verify_bonus_only_cash_substitution(direct or {}, expected_database)
    if negatives.get("externalTargetHost") is not False or negatives.get("fullScenarioAcceptance") is not False:
        raise AssertionError("Local SC005 capture overclaims target-host or complete acceptance proof")
    return {"schemaVersion": "bpc-local-bonus-path-replay/v2", "captureId": provenance["runId"],
            "localBrowserIssueClaimLedgerPath": "verified", "claims": verified,
            "transportDenials": claim_proofs + run_proofs,
            "separateDirectServiceBonusOnlyProbe": direct_proof,
            "betaGateStatus": manifest["status"], "trainingAndFull12Funding": "not_run",
            "externalGoogleAndTargetHost": "not_run"}


if __name__ == "__main__":
    print(json.dumps(verify_local_bonus_path(), ensure_ascii=False))
