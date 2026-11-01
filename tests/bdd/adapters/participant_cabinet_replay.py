"""Read-only PCU raw replay. Producer status/facts are never accepted as evidence."""
from __future__ import annotations

import json
import re
from decimal import Decimal
from pathlib import Path

from tests.bdd.adapters.ber_recovery_replay import read_reference, digest, verify_native_recovery_history
from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance


def need(value, reason):
    if not value:
        raise AssertionError("PCU: " + reason)


def one(rows, reason):
    need(isinstance(rows, list) and len(rows) == 1, reason)
    return rows[0]


def ids(rows):
    return [row["id"] for row in rows]


def money_summary(units):
    units = int(units)
    magnitude = abs(units)
    sign = "-" if units < 0 else ""
    if 0 < magnitude < 10_000:
        return sign + "<0.01"
    cents = (magnitude + 5000) // 10_000
    return f"{sign}{cents // 100}.{cents % 100:02}"


def exact_units(amount):
    negative = amount.startswith("-")
    parts = amount.lstrip("-").split(".")
    units = int(parts[0]) * 1_000_000 + int((parts[1] if len(parts) > 1 else "").ljust(6, "0") or "0")
    return -units if negative else units


def observer(snapshot, database):
    need(snapshot["observer"] == {"role": "oid_observer", "database": database, "read_only": "on"}, "independent read-only observer")


def verify_capture(root: Path, reference: dict) -> dict:
    capture = read_reference(root, reference)
    need(capture.get("schemaVersion") == "pcu-browser-boundary-capture/v1", "capture schema")
    database, _ = _verify_provenance(capture, root)
    owner = capture["ownerId"]
    before, after = capture["before"], capture["after"]
    observer(before, database); observer(after, database)
    for snapshot in (before, after):
        for kind in ("runs", "intents", "grants", "history", "reports", "images"):
            need(all(row["owner_id"] == owner for row in snapshot[kind]), "foreign durable record")
    contracts = json.loads((root / "tests/bdd/changes/participant-cabinet-ux/harness-contracts.json").read_text(encoding="utf-8"))["protected_scenarios"]
    result = {sid: {"facts": {}, "verifiedVariants": [], "missingVariants": list(row["negative_variants"])} for sid, row in contracts.items()}
    cases = capture["cases"]

    launch = cases["PCU-SC-001"]
    accepted = launch["http"]
    need(accepted["status"] in (200, 201), "actual browser launch request acceptance")
    intent = accepted["body"]["intent"]
    durable = one(launch["newIntents"], "single durable new launch request")
    need(durable["id"] == intent["id"] and durable["agent_id"] == launch["payload"]["agentId"] and
         durable["mode"] == launch["payload"]["mode"] and durable["task_ids"] == launch["payload"]["taskIds"] and
         durable["quote_price_units"] == str(int(Decimal(launch["payload"]["expectedQuotePrice"]) * 1_000_000)) and
         durable["cash_ceiling_units"] == "0", "browser pinned quote to PostgreSQL")
    need(all("bonus credit" in row["text"] and "cash 0.00" in row["text"] and row["label"] == "Start " + row["mode"].capitalize() for row in launch["choices"]), "displayed modes, price and source")
    result["PCU-SC-001"]["facts"].update(displayed_price_mode_source=True, single_launch=True)
    selections = launch.get("partialSelections", [])
    expected_prices = {("S1",): "0.08", ("M1",): "0.17", ("H1",): "0.25", ("S1", "M1", "H1"): "0.50"}
    need(len(selections) == 4 and all(expected_prices[tuple(row["taskIds"])] + " USDC" in row["text"] for row in selections), "partial Training displayed prices")
    result["PCU-SC-001"]["verifiedVariants"].append("partial_training")
    if launch.get("gesture") == "double-click": result["PCU-SC-001"]["verifiedVariants"].append("double_submit")

    money = cases["PCU-SC-002"]
    observer(money["before"], database); observer(money["after"], database)
    need(money["before"]["history"] == money["after"]["history"], "money formatting wrote ledger")
    need(money["money"], "browser exact-money disclosures")
    observed_units = []
    for rendered in money["money"]:
        match = re.fullmatch(r"(-?\d+(?:\.\d{1,6})?) USDC [·/] (-?\d+) micro-USDC", rendered["exact"])
        need(match, "exact amount disclosure format")
        units = int(match[2]); need(exact_units(match[1]) == units, "exact money units")
        need(rendered["summary"] == money_summary(units) + " USDC", "rounded summary differs from exact units")
        if rendered.get("ledger"):
            ledger = rendered["ledger"]
            original = one([row for row in money["before"]["history"] if "billing-history-entry-" + row["id"] == ledger["rowId"]], "original signed ledger entry")
            need(int(original["amount_units"]) > 0 and exact_units(ledger["rawAmount"]) == int(original["amount_units"]), "signed presentation changed raw positive magnitude")
            display_type = "grant" if original["entry_type"] == "bonus_grant" else original["entry_type"]
            need(ledger["type"] == display_type and units == int(original["amount_units"]) * (-1 if original["entry_type"] == "debit" else 1), "economic direction differs from authoritative type")
            need(ledger["rawAmount"] in rendered["rawDisclosure"] and display_type in rendered["rawDisclosure"], "raw magnitude and authoritative type not accessible")
        observed_units.append(units)
    result["PCU-SC-002"]["facts"].update(two_decimal_and_subcent_render=True, exact_detail_units=True, before_after_ledger_fingerprint=True)
    if any(0 < abs(units) < 10_000 for units in observed_units): result["PCU-SC-002"]["verifiedVariants"].append("subcent_nonzero")
    signed_types = {row["ledger"]["type"] for row in money["money"] if row.get("ledger")}
    if any(units < 0 for units in observed_units) and {"debit", "refund"}.issubset(signed_types): result["PCU-SC-002"]["verifiedVariants"].append("negative_refund_display")
    if {4999, 5000}.issubset({abs(units) % 10000 for units in observed_units}): result["PCU-SC-002"]["verifiedVariants"].append("half_rounding_edges")

    history = cases["PCU-SC-003"]
    for kind, traversal in history["histories"].items():
        expected = traversal.get("expected", before[kind])
        need(all(row["owner_id"] == owner for row in expected), "history expected owner")
        need(traversal["initial"] == min(5, len(expected)), "history initial bound")
        need(traversal["renderedIds"] == ids(expected), "history browser omissions, duplicates or ordering")
        received = [item["id"] for page in traversal["pages"] for item in page["records"]]
        need(received == ids(expected), "history cursor response differs from independent database")
        need(len(received) == len(set(received)), "duplicate history identities")
        if expected: need(traversal["expanded"] is True, "technical history disclosure did not open")
        if traversal.get("concurrent") is not None:
            current = traversal["concurrent"]
            need(len(current) > len(expected) and set(ids(expected)).issubset(ids(current)), "concurrent fixture removed old history")
            need(traversal["refreshedFirstIds"] == ids(current)[:5] and set(ids(current)) == set(received) | set(traversal["refreshedFirstIds"]), "new records are not reachable on refresh")
    need(all(response["status"] in (400, 403) for response in history["cursorDenials"].values()), "foreign cursor accepted")
    result["PCU-SC-003"]["facts"].update(initial_five_and_order=True, complete_cursor_traversal=True, compact_and_expanded_fields=True,
        foreign_cursor_denial=len(history["cursorDenials"]) == 4)
    if all(len(before[kind]) > 5 for kind in history["histories"]):
        result["PCU-SC-003"]["verifiedVariants"].append("stale_or_foreign_cursor")
    if all(len({row.get("created_at", row.get("queued_at")) for row in before[kind]}) < len(before[kind]) for kind in history["histories"]):
        result["PCU-SC-003"]["verifiedVariants"].append("same_timestamp")
    if history.get("emptyHistory"):
        empty = history["emptyHistory"]
        observer(empty["database"], database)
        need(all(not empty["database"][kind] and empty["histories"][kind]["initial"] == 0 and not empty["histories"][kind]["renderedIds"] for kind in history["histories"]), "empty history leaked a record")
        result["PCU-SC-003"]["verifiedVariants"].append("empty_history")
    if all(row.get("concurrent") is not None for row in history["histories"].values()):
        result["PCU-SC-003"]["verifiedVariants"].append("concurrent_new_record")

    help_case = cases["PCU-SC-004"]
    need(help_case["keyboardExpanded"] is True and help_case["pointerExpanded"] is True, "accessible help")
    need(help_case["unknown"]["status"] == 400, "unknown cursor rejection")
    need(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", help_case["unknown"]["requestId"] or ""), "server support correlation missing")
    result["PCU-SC-004"]["facts"].update(accessible_help_interaction=True, correlation_id_binding=True)
    rendered = help_case["renderedPageText"]
    need(isinstance(rendered, str) and not re.search(r"PCU_SECRET_CANARY|aap1_[A-Za-z0-9_-]{43}|Bearer\s+\S+", rendered), "credential/canary rendered")
    result["PCU-SC-004"]["facts"]["no_secret_render"] = True
    result["PCU-SC-004"]["verifiedVariants"].append("screen_keyboard_only")

    feedback = cases["PCU-SC-005"]
    run = one(feedback["database"]["run"], "diagnostic owner run")
    need(run["owner_id"] == owner and run["mode"] == "training", "diagnostic projection owner/mode")
    need(feedback["diagnostics"], "no actual task drilldown")
    for row in feedback["diagnostics"]:
        need(row["http"]["status"] == 200, "actual browser diagnostic response")
        detail = row["http"]["body"]["diagnostics"]
        grade = one([grade for grade in feedback["database"]["evaluations"] if grade["task_id"] == row["taskId"]], "durable evaluation")
        evaluation = grade["result_json"]
        if isinstance(evaluation, str): evaluation = json.loads(evaluation)
        need(digest(evaluation) == grade["result_hash"], "retained result hash mismatch")
        need(detail["runId"] == run["id"] and detail["taskId"] == row["taskId"] and detail["credit"] == evaluation["credit"] and
             detail["status"] == evaluation["status"] and detail["outcome"] == evaluation["outcome"], "diagnostics differ from durable sealed result")
        actions = [action for action in feedback["database"]["actions"] if action["task_index"] == grade["task_index"]]
        need([(action["actionId"], action["sequence"], action["status"]) for action in detail["actions"]] ==
             [(action["id"], action["action_sequence"], action["receipt_status"]) for action in actions], "timeline differs from durable receipts")
        need(all(re.fullmatch(r"sha256:[a-f0-9]{64}", ref) for ref in detail["evidenceRefs"]), "unsafe diagnostic reference")
    need(feedback["foreign"]["status"] in (403, 404), "foreign diagnostics disclosed")
    if feedback["ranked"]: need(feedback["ranked"]["status"] in (403, 404), "Ranked diagnostic disclosed")
    need(feedback["publicTrace"]["status"] == 404, "public trace disclosure")
    sealed_source_verified = False
    if capture.get("trainingSource") and capture.get("trainingHistory"):
        training_source = read_reference(root, capture["trainingSource"])
        need(training_source["mode"] == "training" and training_source["run"]["runId"] == run["id"], "actual worker capture scope")
        history_report = verify_native_recovery_history(capture["trainingHistory"], repository_root=root, required_modes=["training"])
        need(one(history_report["runs"], "actual sealed Training history")["runId"] == run["id"], "sealed source belongs to another Training run")
        raw_history = read_reference(root, capture["trainingHistory"])
        need(raw_history["databaseName"] == database, "sealed source database differs")
        source_grades = one(raw_history["runs"], "raw source run")["rows"]["evaluations"]
        need({row["task_id"]: row["result_hash"] for row in source_grades} == {row["task_id"]: row["result_hash"] for row in feedback["database"]["evaluations"]}, "feedback is not the source-sealed worker result")
        sealed_source_verified = True
    result["PCU-SC-005"]["facts"].update(actual_feedback_click=True, timeline_matches_receipts=True, safe_goal_diagnostics=sealed_source_verified,
        ranked_and_foreign_projection=bool(feedback["ranked"]), completed_training_only_action_detail=False,
        no_ranked_or_public_trace_viewer=bool(feedback["ranked"]))
    result["PCU-SC-005"]["verifiedVariants"].append("foreign_run")
    result["PCU-SC-005"]["verifiedVariants"].append("ranked_or_public_trace_request")
    for negative in feedback.get("negativeTasks", []):
        need(negative["http"]["status"] == 404, "unfinished/unissued task disclosed diagnostics")
        state = one(negative["database"]["run"], "negative diagnostic fixture run")
        need(state["owner_id"] == owner, "negative fixture foreign owner")
        need(negative["taskId"] in ("S1", "M1", "H1"), "negative fixture requested an invalid Training family")
        if negative["variant"] == "active_ranked_request": need(state["mode"] == "ranked" and state["status"] not in ("completed", "failed", "cancelled"), "active Ranked fixture was terminal")
        if negative["variant"] == "active_training_unreleased_detail":
            need(state["mode"] == "training" and state["status"] not in ("completed", "failed", "cancelled"), "active Training fixture was terminal")
            task = one([row for row in negative["database"]["tasks"] if row["task_id"] == negative["taskId"]], "active Training task")
            need(task["closure_status"] not in ("closed", "unknown") and task["status"] not in ("completed", "failed", "unknown"), "active task was already closed")
            result["PCU-SC-005"]["facts"]["completed_training_only_action_detail"] = sealed_source_verified
        if negative["variant"] == "unissued_task": need(not any(row["task_id"] == negative["taskId"] for row in negative["database"]["evaluations"]), "unissued fixture had a retained evaluation")
        result["PCU-SC-005"]["verifiedVariants"].append(negative["variant"])
    if feedback.get("forgedHash"):
        forged = feedback["forgedHash"]
        need(forged["original"] == forged["restored"], "forged hash fixture did not restore exact original records")
        need(forged["fault"]["http"]["status"] == 409, "forged retained result hash was accepted")
        mismatches = [row for row in forged["fault"]["database"]["evaluations"] if digest(row["result_json"]) != row["result_hash"]]
        need(mismatches, "forged hash variant did not actually corrupt the retained hash")
        result["PCU-SC-005"]["verifiedVariants"].append("forged_result_hash")

    report = cases["PCU-SC-006"]
    need(report["http"]["status"] in (200, 201), "browser report receipt")
    report_id = report["http"]["body"]["report"]["id"]
    stored = one([row for row in report["reportRows"]["reports"] if row["id"] == report_id], "durable report")
    need(stored["run_id"] == report["autofilledRunId"] == run["id"] and stored["operation_id"] == report["payload"]["operationId"], "report context binding")
    need(stored["safe_context"]["clientVersionSource"] == ("owner_declared_unverified" if stored["client_version"] else "unavailable"), "client version provenance")
    image = one([row for row in report["reportRows"]["images"] if row["report_id"] == report_id], "durable report image")
    screenshot_bytes = read_reference(root, report["screenshot"], json_body=False)
    need(image["expected_sha256"] == report["screenshot"]["sha256"] and image["expected_input_bytes"] == len(screenshot_bytes) and
         image["id"] in report["payload"]["imageUploadIds"], "actual page PNG not bound to uploaded/attached image")
    need(image["status"] == "attached" and image["output_mime"] == "image/webp" and report["normalizedImage"] and
         image["output_sha256"] == report["normalizedImage"]["sha256"], "normalized image readback hash")
    need(report["adminRead"]["status"] == 200 and report["adminRead"]["body"]["report"]["id"] == report_id, "admin report visibility")
    need(report["financialBefore"] == report["financialAfter"], "report changed finances")
    need(report["taskBefore"] == report["taskAfter"], "report changed original task/evaluation/receipt state")
    result["PCU-SC-006"]["facts"].update(browser_submit_receipt=True, validated_context_and_client_source=True,
        normalized_image_hash=True, admin_visibility=True, financial_task_fingerprint=True)
    if stored["client_version"] is None: result["PCU-SC-006"]["verifiedVariants"].append("missing_client_version")
    need(report["reportReplay"]["status"] == 200 and report["reportReplay"]["body"]["report"]["id"] == report_id and report["reportReplay"]["body"]["replayed"] is True, "report idempotent replay")
    result["PCU-SC-006"]["verifiedVariants"].append("duplicate_submit")
    need(len(report["linkDenials"]) == 3, "foreign run/task/action matrix")
    for denial in report["linkDenials"]:
        need(denial["response"]["status"] in (400, 403, 404), "foreign report context accepted")
        for kind in ("history", "runs", "reports", "reportAudits"):
            need(denial["before"][kind] == denial["after"][kind], "rejected context caused durable effect")
    result["PCU-SC-006"]["verifiedVariants"].append("foreign_run_task_action")
    forged_metadata = report["forgedMetadata"]
    need(forged_metadata["response"]["status"] == 400, "forged observed client provenance accepted")
    for kind in ("reports", "reportAudits", "history", "runs"):
        need(forged_metadata["before"][kind] == forged_metadata["after"][kind], "rejected metadata changed durable records")
    unlinked = report["unlinked"]
    need(unlinked["http"]["status"] in (200, 201), "unlinked connection report browser receipt")
    unlinked_id = unlinked["http"]["body"]["report"]["id"]
    unlinked_row = one([row for row in unlinked["database"]["reports"] if row["id"] == unlinked_id], "unlinked report durable row")
    need(unlinked_row["run_id"] is None and unlinked_row["task_id"] is None and unlinked_row["action_id"] is None, "unlinked report invented context")
    need(unlinked_row["client_version"] is None and unlinked_row["safe_context"]["clientVersionSource"] == "unavailable", "missing client metadata invented observed source")
    result["PCU-SC-006"]["verifiedVariants"].append("no_run")
    result["PCU-SC-006"]["verifiedVariants"].append("missing_client_version")
    images = report["unsafeImages"]
    need(images["corruptHttp"]["status"] in (400, 413, 415, 422), "corrupt screenshot was not rejected by actual decoder")
    need(images["oversize"]["bytes"] > 5 * 1024 * 1024 and images["oversize"]["uploadRequests"] == 0 and "5 MiB" in images["oversize"]["alert"], "oversize screenshot UI boundary")
    for kind in ("reports", "history", "runs", "reportAudits"):
        need(images["corruptBefore"][kind] == images["corruptAfter"][kind] == images["oversize"]["after"][kind], "unsafe image changed reports/tasks/finances")
    result["PCU-SC-006"]["verifiedVariants"].append("corrupt_or_oversize_image")
    if report.get("flood"):
        flood = report["flood"]
        need(1 <= len(flood["attempts"]) <= 8 and flood["attempts"][-1]["status"] == 429, "bounded report quota denial")
        created = [row["body"]["report"]["id"] for row in flood["attempts"] if row["status"] in (200, 201)]
        need(set(ids(flood["after"]["reports"])) - set(ids(flood["before"]["reports"])) == set(created), "quota denial persisted an extra report")
        need(flood["before"]["history"] == flood["after"]["history"] and flood["before"]["runs"] == flood["after"]["runs"], "quota probe affected task/finance state")
        result["PCU-SC-006"]["verifiedVariants"].append("flood")

    admin = cases["PCU-SC-007"]
    need(len(admin["pages"]) == 10 and all(row["status"] == 404 and "no-store" in (row["cacheControl"] or "") and "private" in row["cacheControl"] for row in admin["pages"]), "admin page concealment/cache")
    need(admin["ownerNav"] == 0 and admin["adminNav"] == 1, "role-bound nav")
    need(admin["ownerApi"]["status"] == 403 and admin["anonymousApi"]["status"] == 401, "API status authority")
    result["PCU-SC-007"]["facts"].update(http_status_and_headers=True, role_bound_nav_and_hydration=True)
    need(admin["deniedMutation"]["status"] == 403 and admin["csrfMutation"]["status"] == 403, "admin role/origin mutation denial")
    need(admin["adminBefore"]["reports"] == admin["deniedAfter"]["reports"] and admin["adminBefore"]["reportAudits"] == admin["deniedAfter"]["reportAudits"], "unauthorized admin write")
    need(admin["authorizedMutation"]["status"] == 200, "actual administrator UI mutation")
    triaged = one([row for row in admin["authorizedAfter"]["reports"] if row["id"] == report_id], "admin triage durable row")
    need(triaged["status"] == "in_progress" and triaged["revision"] == stored["revision"] + 1 and
         len(admin["authorizedAfter"]["reportAudits"]) == len(admin["deniedAfter"]["reportAudits"]) + 1, "once-only authorized admin audit")
    result["PCU-SC-007"]["facts"].update(api_role_csrf_denials=True, unchanged_admin_records=True)
    result["PCU-SC-007"]["verifiedVariants"].extend(["direct_url", "subroute", "prefetch", "spoofed_email_role"])

    connection = cases["PCU-SC-008"]
    need(connection["status"]["status"] == 200 and connection["legacyInitiallyClosed"] is True, "normal/advanced connections")
    result["PCU-SC-008"]["facts"]["main_vs_advanced_fields"] = True
    if capture.get("nativeConnectionCaptureRef"):
        from tests.bdd.adapters.agent_client_installer import physical, verify_preflight, verify_launch
        proof = physical(capture["nativeConnectionCaptureRef"], root=root)
        identity = verify_preflight(proof)
        verify_launch(proof)
        need(identity["ownerId"] == owner and identity["agentId"] == connection["agentId"] and
             proof["beforePreflight"]["database"]["databaseName"] == database, "native connection proof belongs to another owner/agent/database")
        grant = one([row for row in connection["status"]["body"]["connections"] if row["id"] == identity["connectionId"]], "browser status stable native grant")
        need(grant["lastPreflightAt"] is not None and grant["protocolVersion"] in ("2025-06-18", "2026-07-28"), "native preflight absent from actual owner status")
        result["PCU-SC-008"]["facts"]["actual_connection_observation"] = True

    for sid, row in result.items():
        row["missingVariants"] = [name for name in contracts[sid]["negative_variants"] if name not in row["verifiedVariants"]]
        row["missingObservations"] = [name for name in contracts[sid]["required_observations"] if not row["facts"].get(name)]
        row["status"] = "passed" if not row["missingVariants"] and not row["missingObservations"] else "blocked"
    return {"schemaVersion": "pcu-independent-replay/v1", "database": database, "scenarios": result}
