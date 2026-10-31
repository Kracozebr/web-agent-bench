"""Independent raw H1 cutoff replay; producer checks and claims are not evidence."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from tests.bdd.adapters.ber_recovery_replay import digest, read_reference

VARIANTS = {
    "before_cutoff_dispatch_after", "at_cutoff_new_denied", "after_cutoff_new_denied",
    "admission_reply_lost_before_dispatch", "worker_restart_pending", "revoked_agent_pending",
    "tool_reply_lost_after_dispatch", "worker_restart_delivered",
}
FACTS = (
    "accepted_cutoff_order", "outbox_and_receipt_history", "effect_count", "closure_progress",
    "exact_generation_fence", "before_at_after_deadline", "response_loss_before_and_after_dispatch",
    "worker_restart", "late_duplicate", "revoked_agent", "immutable_action_and_cutoff",
    "bounded_pending_resolution", "no_duplicate_effect_or_charge",
)
UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def one(rows, label):
    require(isinstance(rows, list) and len(rows) == 1, label + " must have exactly one row")
    return rows[0]


def epoch(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "H1 timestamp lacks timezone")
    return parsed.timestamp()


def iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _checkpoint(packet, database, run):
    identity, rows = packet["identity"], packet["result"]
    require(identity["role"] == "oid_observer" and identity["readonly"] == "on"
            and identity["database_name"] == database, "H1 checkpoint observer scope differs")
    require(all(rows["run"][key] == run[key] for key in
                ("id", "owner_id", "agent_id", "access_generation", "release_identity", "manifest_hash", "quote_price_units")),
            "H1 checkpoint changed the original run identity/policy")
    task = one(rows["tasks"], "H1 checkpoint task")
    require(task["run_id"] == run["id"] and task["task_id"] == "H1" and task["task_index"] == 0,
            "H1 checkpoint task scope differs")
    return rows, task


def _original_action(rows, target):
    original = one([a for a in rows["actions"] if a["id"] == target["id"]], "H1 checkpoint original action")
    require(all(original[key] == target[key] for key in
                ("id", "run_id", "owner_id", "agent_id", "access_generation", "environment_id", "grant_id",
                 "task_id", "task_index", "operation_id", "payload_hash", "command_json", "accepted_at", "action_sequence")),
            "H1 interrupted action identity or payload changed")
    return original


def _restart(receipt, enabled=True):
    require(receipt["schemaVersion"] == "beta-local-api-restart-receipt/v1"
            and type(receipt["previousPid"]) is int and type(receipt["currentPid"]) is int
            and receipt["previousPid"] > 0 and receipt["currentPid"] > 0
            and receipt["previousPid"] != receipt["currentPid"] and receipt["healthHttpStatus"] == 200
            and receipt["coordinatorEnabled"] is enabled
            and epoch(receipt["finishedAt"]) >= epoch(receipt["startedAt"]), "H1 worker restart/pause was not observed")


def _issued_funding(genuine, owner_id, database):
    """Bind spendable grants to actual code redemption and observer ledger rows."""
    funding = genuine["bonusGrant"]
    db = funding["database"]
    observer, grant, entry = db["observer"], db["grant"], db["grantEntry"]
    code, redemption = db["code"], db["redemption"]
    grant_id, operation = funding["grantId"], funding["operationId"]
    require(observer["role"] == "oid_observer" and observer["database"] == database
            and observer["transaction_read_only"] == observer["default_transaction_read_only"] == "on",
            "H1 funding observer scope differs")
    require(UUID.fullmatch(grant_id) and grant["id"] == entry["bonus_grant_id"] == redemption["bonus_grant_id"] == grant_id
            and grant["owner_id"] == entry["owner_id"] == redemption["owner_id"] == owner_id
            and grant["operation_id"] == entry["operation_id"] == redemption["financial_operation_id"] == operation
            and code["id"] == redemption["code_id"] == funding["codeId"]
            and code["issuer_owner_id"] == grant["issued_by_owner_id"] == entry["actor_owner_id"],
            "H1 funding grant/code/redemption lineage differs")
    require(funding["sourceKind"] == entry["source_kind"] == "tester_bonus"
            and entry["entry_type"] == "bonus_grant"
            and funding["amountUnits"] == grant["amount_units"] == entry["amount_units"] == code["amount_units"] == "250000"
            and entry["available_delta_units"] == "250000"
            and entry["reserved_delta_units"] == entry["expired_delta_units"] == "0"
            and grant["expires_at"] is None and code["used_count"] == 1
            and any(s["name"] == "owner_bonus_code_issue_redeem_and_readonly_database"
                    and s.get("status") == "verified" and s.get("grantId") == grant_id
                    and s.get("redemptionId") == redemption["id"] for s in genuine["stages"]),
            "H1 funding issuance was not observed")
    return grant_id, {"ownerId": owner_id, "availableUnits": 250000,
                      "availableAt": max(epoch(row["created_at"]) for row in (grant, entry, redemption))}


def _ledger_authority(owner):
    """Reconstruct the quoted debit rather than trusting its amount alone."""
    rows, run = owner["ledger"], owner["run"]
    require(isinstance(rows, list) and len(rows) in {2, 3}, "H1 unexpected financial entry")
    require(all(UUID.fullmatch(r["id"]) for r in rows)
            and len({r["id"] for r in rows}) == len(rows), "H1 duplicate ledger identity")
    require(all(r["entry_type"] in {"reserve", "debit", "refund"}
                and r["source_kind"] == "tester_bonus" and UUID.fullmatch(r["bonus_grant_id"])
                for r in rows), "H1 unsupported financial source or entry")
    def units(row, field):
        value = row[field]
        require(isinstance(value, str) and re.fullmatch(r"0|-?[1-9][0-9]*", value), "H1 noncanonical ledger units")
        return int(value)
    quote = int(run["quote_price_units"])
    require(quote == 250000, "H1 unexpected quoted price")
    reserve = one([r for r in rows if r["entry_type"] == "reserve"], "H1 original reservation")
    debit = one([r for r in rows if r["entry_type"] == "debit"], "H1 original debit")
    run_key = run["id"].replace("-", "")
    grant = reserve["bonus_grant_id"]
    require(reserve["operation_id"] == "runacc_" + run_key
            and debit["operation_id"] == "rundeb_" + run_key
            and debit["bonus_grant_id"] == grant, "H1 debit/reservation relinked to another run or grant")
    for row, deltas in ((reserve, (-quote, quote, 0)), (debit, (0, -quote, 0))):
        require(units(row, "amount_units") == quote
                and tuple(units(row, key) for key in ("available_delta_units", "reserved_delta_units", "expired_delta_units")) == deltas,
                "H1 reserve/debit balance deltas differ from the original quote")
    refunds = [r for r in rows if r["entry_type"] == "refund"]
    require(len(refunds) == len(owner["refunds"]) <= 1, "H1 extra or missing source refund entry")
    for row in refunds:
        available, reserved, expired = (units(row, key) for key in
                                       ("available_delta_units", "reserved_delta_units", "expired_delta_units"))
        require(row["bonus_grant_id"] == grant
                and row["operation_id"] == "runref_" + run_key + "_" + grant.replace("-", "")
                and units(row, "amount_units") == quote and reserved == 0
                and available >= 0 and expired >= 0 and available + expired == quote,
                "H1 refund balance or original funding source differs")


def _refund_authority(owner, bef, prep, target):
    refunds = owner["refunds"]
    ledger = [row for row in owner["ledger"] if row["entry_type"] == "refund"]
    if not refunds:
        require(not ledger, "H1 refund ledger exists without official source authority")
        return
    refund = one(refunds, "H1 official refund")
    require(refund["run_id"] == owner["run"]["id"]
            and refund["operation_id"] == "runref_" + owner["run"]["id"].replace("-", ""),
            "H1 official refund belongs to another run")
    require(target is not None and owner["run"]["terminal_reason"] == "platform_failure_recovery_exhausted"
            and owner["run"]["cancellation_reason"] == "coordinator_platform_failure", "H1 refund has unrelated terminal authority")
    recovery = one([r for r in owner["recovery"] if r["action_id"] == target["id"]], "H1 refund recovery")
    generation, source_prep = one(bef["generation"], "H1 generation"), one(bef["preparations"], "H1 BEF preparation")
    fence_set = [{"preparationId": prep["preparation_id"], "leaseId": prep["lease_id"],
                  "environmentId": prep["environment_id"], "generationId": prep["generation_id"],
                  "manifestSha256": prep["environment_manifest_sha256"], "applicationSourceSha256": prep["application_source_hash"],
                  "generationFencedAt": iso(generation["fenced_at"]),
                  "preparationFenceConfirmedAt": iso(source_prep["fence_confirmed_at"]),
                  "publicPinsSha256": source_prep["public_pins_sha256"],
                  "preparationManifestSha256": source_prep["manifest_sha256"],
                  "environmentManifestSha256": prep["environment_manifest_sha256"]}]
    authority = {"schema": "bpc-platform-recovery-exhaustion/v1", "runId": owner["run"]["id"],
                 "actionId": target["id"], "ownerId": owner["run"]["owner_id"], "agentId": owner["run"]["agent_id"],
                 "taskIndex": 0, "environmentId": prep["environment_id"], "ownerOperationId": target["operation_id"],
                 "payloadHash": target["payload_hash"], "preparationId": prep["preparation_id"], "leaseId": prep["lease_id"],
                 "generationId": prep["generation_id"], "manifestSha256": prep["environment_manifest_sha256"],
                 "applicationSourceSha256": prep["application_source_hash"], "incidentEvidenceHash": recovery["incident_evidence_hash"],
                 "startedAt": iso(recovery["started_at"]), "deadlineAt": iso(recovery["deadline_at"]),
                 "clockExcludedMs": recovery["clock_excluded_ms"],
                 "cancellationEvidenceHash": owner["run"]["cancellation_evidence_hash"], "fenceSetHash": digest(fence_set)}
    require(digest(authority) == refund["evidence_hash"] == recovery["latest_evidence_hash"]
            and recovery["status"] == "refunded", "H1 refund is not bound to exact original source/fence/deadline")
    require(sum(int(r["available_delta_units"]) + int(r["expired_delta_units"]) for r in ledger)
            == int(refund["bonus_refunded_units"]) == int(owner["run"]["quote_price_units"]), "H1 refund amount differs from original debit")
    debit = one([r for r in owner["ledger"] if r["entry_type"] == "debit"], "H1 original refund source")
    require(all(r["source_kind"] == "tester_bonus" and r["bonus_grant_id"] == debit["bonus_grant_id"]
                and int(r["amount_units"]) == int(r["available_delta_units"]) + int(r["expired_delta_units"])
                for r in ledger), "H1 refund was credited to a different funding source")
    event = one([e for e in owner["events"] if e["event_type"] == "run.failed.platform_recovery_exhausted"], "H1 official refund event")
    require(event["payload_json"]["evidenceHash"] == refund["evidence_hash"]
            and event["payload_json"]["cashRefundedUnits"] == "0", "H1 refund event/source differs")


def _case(entry, database, root, funding_sources=None):
    variant = entry.get("variant")
    require(variant in VARIANTS, "unapproved H1 variant")
    genuine = read_reference(root, entry["genuineAttempt"])
    if not entry.get("fault", {}).get("target"):
        remaining = entry["remaining"]
        require(remaining["identity"]["role"] == "oid_observer" and remaining["identity"]["readonly"] == "on"
                and all(value == 0 for value in remaining["result"].values()), "unexercised H1 case leaked resources")
        return {"variant": variant, "complete": False, "missing": ["third_payment_not_reached"]}
    body = read_reference(root, entry["reference"])
    require(body == {k: v for k, v in entry.items() if k not in {"reference", "proxyReusable"}}, "H1 immutable case differs from matrix")
    require(body["schemaVersion"] == "ber-h1-cutoff-case/v1" and body["taskIndex"] == 0, "H1 case schema/index differs")
    packet, bef, fault = body["owner"], body["bef"], body["fault"]
    identity, owner = packet["identity"], packet["result"]
    require(identity["role"] == "oid_observer" and identity["readonly"] == "on" and identity["database_name"] == database
            and bef["identity"] == {"role": "bef_observer", "readonly": "on"}, "H1 observer role/scope differs")
    run, task, prep = owner["run"], one(owner["tasks"], "H1 task"), one(owner["preparation"], "H1 preparation")
    run_id = body["runId"]
    require(UUID.fullmatch(run_id) and UUID.fullmatch(body["captureId"])
            and body["captureId"] == genuine["captureId"], "H1 run/capture identity is invalid")
    require(run["id"] == run_id == fault["target"]["runId"] and run["mode"] == "training"
            and task["task_id"] == "H1" and task["task_index"] == 0 and prep["task_id"] == "H1"
            and prep["run_id"] == run_id and prep["manifest_hash"] == run["manifest_hash"]
            and prep["release_identity"] == run["release_identity"], "H1 immutable run/task/preparation scope differs")
    launch = genuine["launchIntent"]
    require(genuine["mode"] == "training" and genuine["taskIds"] == ["H1"]
            and genuine["run"]["runId"] == run_id and launch["browserHttpStatus"] in {200, 201}
            and launch["database"]["status"] == "pending" and launch["database"]["run_id"] is None
            and launch["operationId"] == genuine["run"]["createIntentOperationId"]
            and any(s["name"] == "owner_run_intent_ui_and_readonly_database" and s.get("intentId") == launch["intentId"]
                    for s in genuine["stages"]), "H1 browser-to-durable-admission proof missing")
    require(run["status"] in {"completed", "cancelled", "failed"} and owner["slots"] == []
            and one(owner["claim"], "H1 claim")["status"] == "released", "H1 run/slot/claim still live")
    generation, source_prep = one(bef["generation"], "H1 generation"), one(bef["preparations"], "H1 source preparation")
    require(generation["generation_id"] == prep["generation_id"] == source_prep["generation_id"]
            and generation["env_id"] == prep["environment_id"] == source_prep["env_id"]
            and generation["status"] == source_prep["status"] == "fenced"
            and prep["lease_state"] == prep["observation_status"] == "fenced"
            and source_prep["preparation_id"] == prep["preparation_id"], "H1 exact generation was not fenced")
    require(source_prep["manifest_sha256"].strip() == prep["environment_manifest_sha256"]
            and generation["manifest_sha256"].strip() == prep["environment_manifest_sha256"], "H1 source manifest differs")
    fence = prep["fence_evidence"]
    raw_fence = read_reference(root, fence["evidence"])
    require(fence["confirmed"] is True and fence["environmentId"] == prep["environment_id"]
            and fence["preparationId"] == prep["preparation_id"]
            and fence["leaseId"] == prep["lease_id"] and fence["generationId"] == prep["generation_id"]
            and raw_fence["preparationId"] == prep["preparation_id"]
            and raw_fence["evidence"]["fenceConfirmed"] is True
            and raw_fence["evidence"]["actualBefGenerationId"] == prep["generation_id"], "H1 raw fence identity differs")
    require(sorted(int(e["sequence"]) for e in owner["events"]) == list(range(1, len(owner["events"]) + 1)), "H1 event sequence has gaps")
    for event in owner["events"]:
        require(digest(event["payload_json"]) == event["payload_hash"], "H1 event payload hash differs")
    actions = owner["actions"]
    require([int(a["action_sequence"]) for a in actions] == list(range(1, len(actions) + 1)), "H1 action sequence has gaps")
    require(len([e for e in owner["events"] if e["event_type"] == "task.action.admitted"]) == len(actions)
            and len([e for e in owner["events"] if e["event_type"] == "task.action.dispatch_claimed"])
            == len([a for a in actions if a["outbox_status"] == "delivered"]), "H1 action/outbox journal contains orphan events")
    indexed = {ref["path"]: ref["sha256"] for ref in body["evidenceRefs"]}
    require(len(indexed) == len(body["evidenceRefs"]), "H1 raw artifact index has duplicates")
    for ref in body["evidenceRefs"]:
        read_reference(root, ref, json_body=False)
    receipt_documents = {}
    for action in actions:
        require(action["run_id"] == run_id and action["owner_id"] == run["owner_id"] and action["agent_id"] == run["agent_id"]
                and action["access_generation"] == run["access_generation"] and action["environment_id"] == prep["environment_id"]
                and action["task_id"] == "H1" and action["task_index"] == 0
                and action["receipt_status"] in {"observed", "unknown", "rejected_before_execution"}
                and digest({"runId": run_id, "taskIndex": 0, "command": action["command_json"]}) == action["payload_hash"], "H1 action/cutoff/receipt identity differs")
        require(indexed.get(action["evidence_path"]) == action["evidence_hash"], "H1 receipt raw file omitted")
        evidence = read_reference(root, {"path": action["evidence_path"], "sha256": action["evidence_hash"]})
        receipt_documents[action["id"]] = evidence
        require(evidence["actionId"] == action["id"] and evidence["runId"] == run_id and evidence["taskIndex"] == 0
                and evidence["ownerOperationId"] == action["operation_id"] and evidence["commandSha256"] == action["payload_hash"]
                and evidence["environmentId"] == prep["environment_id"] and evidence["generationId"] == prep["generation_id"]
                and evidence["manifestSha256"] == prep["environment_manifest_sha256"]
                and evidence["applicationSourceSha256"] == prep["application_source_hash"]
                and evidence["status"] == action["receipt_status"], "H1 receipt evidence scope differs")
        require(action["outbox_status"] == "delivered" or
                (action["outbox_status"] == "pending" and action["receipt_status"] == "rejected_before_execution"
                 and evidence["reasonCode"] == "cancelled_before_dispatch_after_exact_fence"), "H1 outbox has unresolved ambiguity")
        admitted = one([e for e in owner["events"] if e["event_type"] == "task.action.admitted"
                        and e["payload_json"].get("actionId") == action["id"]], "H1 admitted event")
        require(admitted["source"] == "agent" and admitted["payload_json"] == {
            "taskId": "H1", "taskIndex": 0, "actionId": action["id"], "actionKind": action["action_kind"],
            "operationId": action["operation_id"], "payloadHash": action["payload_hash"],
            "actionSequence": action["action_sequence"]}, "H1 admitted event does not bind the original action")
        if action["outbox_status"] == "delivered":
            dispatch_event = one([e for e in owner["events"] if e["event_type"] == "task.action.dispatch_claimed"
                                  and e["payload_json"].get("actionId") == action["id"]], "H1 dispatch event")
            payload = dispatch_event["payload_json"]
            require(dispatch_event["source"] == "executor" and int(dispatch_event["sequence"]) > int(admitted["sequence"])
                    and all(payload[key] == value for key, value in {
                        "actionId": action["id"], "taskIndex": 0, "taskId": "H1", "actionKind": action["action_kind"],
                        "actionSequence": action["action_sequence"], "ownerOperationId": action["operation_id"],
                        "payloadHash": action["payload_hash"], "idempotencyKey": "task-action-" + action["id"],
                        "environmentId": prep["environment_id"], "generationId": prep["generation_id"],
                        "manifestSha256": prep["environment_manifest_sha256"], "applicationSourceSha256": prep["application_source_hash"],
                    }.items()) and payload["payerAddress"].lower() == generation["payer_address"].lower(),
                    "H1 dispatch event changed the original execution binding")
    closure = one(owner["closures"], "H1 committed cutoff")
    has_unknown = any(a["receipt_status"] == "unknown" for a in actions)
    require(task["closure_id"] == closure["id"] and task["closure_status"] == ("unknown" if has_unknown else "closed")
            and task["closure_reason"] == closure["reason"] and int(task["accepted_action_sequence"]) == len(actions)
            and int(task["action_cutoff_sequence"]) == int(task["reconciled_action_sequence"])
            == int(closure["action_cutoff_sequence"]) == len(actions), "H1 cutoff is incomplete or mutable")
    require(task["closed_at"] is not None and epoch(closure["requested_at"]) <= epoch(task["closed_at"]), "H1 closure time precedes the cutoff")
    if has_unknown:
        require(not owner["evaluations"], "H1 unknown receipt was turned into an official grade")
    cutoff_event = one([e for e in owner["events"] if e["event_type"] == "task.cutoff.established"], "H1 cutoff event")
    require(cutoff_event["payload_json"] == {"reason": closure["reason"], "taskId": "H1", "taskIndex": 0,
            "closureId": closure["id"], "actionCutoffSequence": closure["action_cutoff_sequence"]}
            and cutoff_event["source"] == "coordinator" and closure["reason"] == "task_deadline"
            and all(int(e["sequence"]) < int(cutoff_event["sequence"]) for e in owner["events"] if e["event_type"] == "task.action.admitted"),
            "H1 cutoff event is not bound to all original admissions")
    target = [a for a in actions if a["operation_id"] == fault["target"]["operationId"]]
    denied = variant in {"at_cutoff_new_denied", "after_cutoff_new_denied"}
    require(len(target) == (0 if denied else 1), "H1 target admission duplicated or unexpectedly accepted")
    target = target[0] if target else None
    require(fault["target"]["taskId"] == "H1" and fault["target"]["command"]["kind"] == "pay", "H1 third payment shape missing")
    pay_route = "/tools/" + prep["environment_id"] + "/pay"
    require(fault["target"]["environmentId"] == prep["environment_id"] and fault["target"]["payRoute"] == pay_route,
            "H1 fault route does not match the original bound environment")
    if target:
        require(target["id"] == fault["admission"]["actionId"] and target["command_json"] == fault["target"]["command"]
                and epoch(target["accepted_at"]) < epoch(fault["target"]["initialDeadline"]), "H1 action not admitted before original cutoff")
    pays, payments = [a for a in actions if a["action_kind"] == "pay"], bef["payments"]
    require(len(pays) == (2 if denied else 3) and 2 <= len(payments) <= len(pays)
            and len({p["operation_id"] for p in payments}) == len(payments)
            and all(p["receipt_status"] == "success" and int(p["amount_units"]) == int(p["token_delta_units"]) for p in payments), "H1 payment count/delta differs")
    for payment in payments:
        require(payment["env_id"] == prep["environment_id"] and payment["generation_id"] == prep["generation_id"]
                and payment["payer_address"].lower() == generation["payer_address"].lower()
                and len(payment["authorization_sha256"]) == 64
                and int(payment["payer_balance_before"]) - int(payment["payer_balance_after"]) == int(payment["amount_units"])
                and int(payment["facilitator_balance_after"]) - int(payment["facilitator_balance_before"]) == int(payment["amount_units"]),
                "H1 payment generation/payer/balance source differs")
    chain = body["chain"]
    require(len(chain["receipts"]) == len(payments), "H1 chain receipt count differs")
    for payment, receipt in zip(payments, chain["receipts"]):
        require(receipt["transactionHash"] == payment["transaction_hash"] and receipt["status"] == "0x1", "H1 payment chain receipt differs")
    transfer = chain["generationTransfers"]
    require(len(transfer["logs"]) == len(payments) and len({log["transactionHash"] for log in transfer["logs"]}) == len(payments), "H1 duplicate/missing transfer log")
    for log in transfer["logs"]:
        payment = one([p for p in payments if p["transaction_hash"] == log["transactionHash"]], "H1 transfer payment")
        require(log["address"].lower() == payment["asset_address"].lower()
                and log["topics"][0].lower() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                and log["topics"][1].lower() == "0x" + payment["payer_address"][2:].lower().rjust(64, "0")
                and log["topics"][2].lower() == "0x" + payment["facilitator_address"][2:].lower().rjust(64, "0")
                and int(log["data"], 16) == int(payment["amount_units"]), "H1 transfer amount/recipient differs")
    operations = bef["operations"]
    require(len(operations) <= 1, "H1 source operation duplicated")
    if operations:
        operation = operations[0]
        require(target is not None and operation["env_id"] == prep["environment_id"] and operation["generation_id"] == prep["generation_id"]
                and operation["operation_kind"] == "purchase" and operation["payment_response_mode"] == "deferred_delivery"
                and operation["status"] == "settled" and operation["receipt_status"] == "success"
                and operation["idempotency_key_sha256"] == hashlib.sha256(("task-action-" + target["id"]).encode()).hexdigest(), "H1 original source operation binding differs")
        payment = one([p for p in payments if p["operation_id"] == operation["operation_id"]], "H1 original source payment")
        require(operation["transaction_hash"] == payment["transaction_hash"]
                and operation["authorization_sha256"] == payment["authorization_sha256"]
                and operation["generation_manifest_sha256"] == prep["environment_manifest_sha256"]
                and operation["environment_manifest_sha256"] == prep["environment_manifest_sha256"], "H1 source transaction/authority differs")
        target_dispatch = one([e for e in owner["events"] if e["event_type"] == "task.action.dispatch_claimed"
                               and e["payload_json"].get("actionId") == target["id"]], "H1 paid dispatch")
        require(operation["participant_id"] == target_dispatch["payload_json"]["participantId"], "H1 payment belongs to another participant")
        command = target["command_json"]
        offer_action = one([a for a in actions if a["id"] == command["offerReadActionId"]], "H1 original offer inspection")
        offer = receipt_documents[offer_action["id"]]["participantToolResponse"]
        terms = one([o for o in offer["offers"] if o["id"] == command["offerId"]], "H1 selected public offer")["payment"]
        require(offer_action["action_kind"] == "inspect_offer" and int(offer_action["action_sequence"]) < int(target["action_sequence"])
                and command["resourceId"] == offer["resourceId"] == operation["selected_resource_id"]
                and command["offerId"] == operation["selected_offer_id"]
                and offer["resourceSha256"] == operation["selected_resource_sha256"]
                and int(terms["amount"]) == int(operation["selected_amount_units"]) == int(payment["amount_units"])
                and terms["network"] == payment["network"] and terms["asset"].lower() == payment["asset_address"].lower()
                and terms["payTo"].lower() == payment["facilitator_address"].lower(), "H1 paid a different resource/offer/amount")
    wire = [r for r in body["proxy"]["submissions"] if target and r["actionId"] == target["id"]]
    traces = [r for r in body["proxy"]["actionRequests"] if target and r["actionId"] == target["id"]]
    require(body["proxy"]["omittedActionRequests"] == 0 and len(wire) <= 1
            and (wire[0]["count"] if wire else 0) == len(traces), "H1 action wire trace is incomplete")
    if operations:
        require(len(traces) == 2 and [r["ordinal"] for r in traces] == [1, 2]
                and all(r["method"] == "POST" and r["path"] == pay_route and r["upstreamResponseComplete"] is True for r in traces)
                and traces[0]["paymentProofPresent"] is False and traces[0]["upstreamStatus"] == 402
                and traces[0]["downstreamResponseFinished"] is True
                and traces[1]["paymentProofPresent"] is True and 200 <= traces[1]["upstreamStatus"] < 300
                and traces[1]["upstreamResponseSha256"] == operations[0]["response_sha256"]
                and epoch(traces[0]["requestStartedAt"]) <= epoch(traces[0]["upstreamResponseFinishedAt"])
                <= epoch(traces[1]["requestStartedAt"]) <= epoch(traces[1]["upstreamResponseFinishedAt"]),
                "H1 requires one unsigned x402 challenge and exactly one signed settlement wire")
    else:
        require(not traces, "H1 rejected action was dispatched")
    _ledger_authority(owner)
    if funding_sources is None:
        grant_id, funding = _issued_funding(genuine, run["owner_id"], database)
        funding_sources = {grant_id: funding}
    debit = one([r for r in owner["ledger"] if r["entry_type"] == "debit"], "H1 funded debit")
    source = funding_sources.get(debit["bonus_grant_id"])
    require(source is not None and source["ownerId"] == run["owner_id"]
            and source["availableUnits"] >= int(debit["amount_units"])
            and source["availableAt"] <= epoch(one([e for e in owner["events"]
                if e["event_type"] == "run.accepted"], "H1 funding admission")["created_at"]),
            "H1 debit is not backed by observed available original funding")
    for recovery in owner["recovery"]:
        require(abs(epoch(recovery["deadline_at"]) - epoch(recovery["started_at"]) - 180) < .0001
                and 0 <= int(recovery["clock_excluded_ms"]) <= 180000, "H1 recovery deadline was renewed")
    clock_excluded = 0
    for event in [e for e in owner["events"] if e["event_type"] == "run.platform_recovery_clock_excluded"]:
        payload = event["payload_json"]
        require(target is not None and payload["actionId"] == target["id"]
                and payload["operationId"] == target["operation_id"] and event["source"] == "worker"
                and type(payload["clockExcludedMs"]) is int and 0 < payload["clockExcludedMs"] <= 180000
                and re.fullmatch(r"[a-f0-9]{64}", payload["evidenceHash"]), "H1 clock change lacks original recovery authority")
        clock_excluded += payload["clockExcludedMs"]
    require(clock_excluded <= sum(int(r["clock_excluded_ms"]) for r in owner["recovery"])
            and round(epoch(task["deadline_at"]) * 1000) == round(epoch(fault["target"]["initialDeadline"]) * 1000) + clock_excluded,
            "H1 deadline changed without the source-linked clock exclusion")
    _refund_authority(owner, bef, prep, target)
    missing = []
    if denied:
        require(not operations and len(payments) == 2 and not fault["admission"]["actionId"]
                and epoch(task["deadline_at"]) == epoch(fault["target"]["initialDeadline"])
                and epoch(closure["requested_at"]) >= epoch(task["deadline_at"]), "H1 post-deadline action created an effect")
        before_rows, before_task = _checkpoint(fault["preRequestBoundarySnapshot"], database, run)
        require(epoch(fault["preRequestBoundarySnapshot"]["identity"]["observed_at"]) <= epoch(fault["admissionRequestStartedAt"])
                <= epoch(fault["admissionResponseObservedAt"])
                and not any(a["operation_id"] == fault["target"]["operationId"] for a in before_rows["actions"]),
                "H1 new-request boundary timing/action absence differs")
        if variant == "at_cutoff_new_denied":
            if not (before_task["closure_status"] == "open" and before_task["closure_id"] is None
                    and fault["admission"]["httpStatus"] == 200 and fault["admission"]["admitted"] is False
                    and fault["admission"]["reason"] == "task_deadline" and fault["admission"]["closureId"] == closure["id"]
                    and epoch(fault["admissionRequestStartedAt"]) <= epoch(closure["requested_at"]) <= epoch(fault["admissionResponseObservedAt"])):
                missing.append("fresh_request_did_not_establish_the_deadline_cutoff")
        else:
            require(before_task["closure_status"] == "closed" and before_task["closure_id"] == closure["id"]
                    and fault["admission"]["httpStatus"] == 409 and fault["admission"]["errorCode"] in {"TASK_CLOSED", "TASK_NOT_ACTIVE"},
                    "H1 after-cutoff denial was not preceded by its durable closure")
    elif variant in {"before_cutoff_dispatch_after", "admission_reply_lost_before_dispatch",
                     "tool_reply_lost_after_dispatch", "worker_restart_delivered"}:
        locked = fault.get("pendingLock")
        if not locked or locked.get("outbox_status") != "pending" or locked.get("receipt_status") != "pending":
            missing.append("original_pending_outbox_lock_not_exercised")
        else:
            require(locked["id"] == target["id"] and locked["operation_id"] == target["operation_id"]
                    and locked["payload_hash"] == target["payload_hash"]
                    and epoch(fault["releaseClock"]["released_at"]) >= epoch(fault["target"]["initialDeadline"]), "H1 original lock/cutoff binding differs")
        if variant in {"before_cutoff_dispatch_after", "admission_reply_lost_before_dispatch"}:
            dispatched = one([e for e in owner["events"] if e["event_type"] == "task.action.dispatch_claimed"
                              and e["payload_json"].get("actionId") == target["id"]], "H1 original dispatch")
            require(epoch(target["delivered_at"]) >= epoch(fault["target"]["initialDeadline"])
                    and len(traces) == 2 and epoch(traces[0]["requestStartedAt"]) >= epoch(target["delivered_at"])
                    and int(dispatched["sequence"]) > int(one([e for e in owner["events"]
                        if e["event_type"] == "task.action.admitted" and e["payload_json"].get("actionId") == target["id"]], "H1 original admission")["sequence"])
                    and fault["duplicate"]["actionId"] == target["id"] and fault["ownerAdmissionCalls"] == 2
                    and len(payments) == 3 and len(operations) == 1, "H1 late duplicate or post-cutoff dispatch differs")
        if variant == "admission_reply_lost_before_dispatch":
            held_rows, _ = _checkpoint(fault["admissionReplyWithheldBeforeDispatch"], database, run)
            held_action = _original_action(held_rows, target)
            require(held_action["receipt_status"] == held_action["outbox_status"] == "pending"
                    and epoch(fault["admissionResponseObservedAt"]) <= epoch(fault["admissionReplyWithheldBeforeDispatch"]["identity"]["observed_at"])
                    <= epoch(fault["admissionReplyWithheldAt"]) <= epoch(fault["releaseClock"]["released_at"])
                    <= epoch(target["delivered_at"]) <= epoch(traces[0]["requestStartedAt"]),
                    "H1 admission reply loss was not observed before dispatch")
            require(any(a["operationId"] == target["operation_id"] and a["transportUnknown"] is True
                        for a in genuine["participantActions"]), "H1 admission response loss not observed by client")
    if variant in {"worker_restart_pending", "revoked_agent_pending"}:
        paused_rows, paused_task = _checkpoint(fault["workerPauseBefore"], database, run)
        require(paused_task["closure_status"] == "open" and paused_task["closure_id"] is None
                and len([a for a in paused_rows["actions"] if a["action_kind"] == "pay"]) == 2
                and all(a["receipt_status"] == "observed" and a["outbox_status"] == "delivered" for a in paused_rows["actions"]),
                "H1 worker pause did not begin with a resolved original prefix")
        pause, restart = fault["workerPauseReceipt"], fault["restartReceipt"]
        _restart(pause, False)
        _restart(restart)
        pending_rows, pending_task = _checkpoint(fault["pendingCheckpoint"], database, run)
        pending = _original_action(pending_rows, target)
        require(pending["receipt_status"] == pending["outbox_status"] == "pending"
                and epoch(fault["workerPauseBefore"]["identity"]["observed_at"]) <= epoch(pause["startedAt"])
                <= epoch(pause["finishedAt"]) <= epoch(fault["admissionRequestStartedAt"])
                <= epoch(target["accepted_at"]) <= epoch(fault["admissionResponseObservedAt"])
                <= epoch(fault["pendingCheckpoint"]["identity"]["observed_at"])
                and epoch(pending_task["deadline_at"]) == epoch(fault["target"]["initialDeadline"]),
                "H1 pending admission did not preserve the paused worker/original clock")
        prior = fault["committedCutoffBeforeInterruption"]
        prior_rows, prior_task = _checkpoint(prior, database, run)
        prior_action = _original_action(prior_rows, target)
        restart_rows, restart_task = _checkpoint(fault["restartBefore"], database, run)
        restart_action = _original_action(restart_rows, target)
        require(prior_task["closure_id"] == restart_task["closure_id"] == task["closure_id"]
                and prior_task["action_cutoff_sequence"] == target["action_sequence"]
                and prior_action["receipt_status"] == prior_action["outbox_status"] == "pending"
                and restart_action["receipt_status"] == restart_action["outbox_status"] == "pending"
                and epoch(fault["target"]["initialDeadline"]) <= epoch(prior["identity"]["observed_at"])
                <= epoch(fault["restartBefore"]["identity"]["observed_at"]) <= epoch(restart["startedAt"])
                and pause["currentPid"] == restart["previousPid"] and not operations and len(payments) == 2,
                "H1 restart/revoke did not interrupt the original committed cutoff")
        if variant == "revoked_agent_pending":
            require(fault["revoke"]["httpStatus"] == 200 and fault["revoke"]["accessStatus"] == "revoked"
                    and owner["currentAccess"]["id"] == run["agent_id"] and owner["currentAccess"]["access_revoked_at"]
                    and owner["currentAccess"]["access_generation"] > run["access_generation"]
                    and target["receipt_status"] == "rejected_before_execution"
                    and run["cancellation_reason"] == "owner_global_revoke"
                    and epoch(prior["identity"]["observed_at"]) <= epoch(owner["currentAccess"]["access_revoked_at"])
                    <= epoch(fault["restartBefore"]["identity"]["observed_at"]), "H1 revocation dispatched the pending payment")
    if variant in {"tool_reply_lost_after_dispatch", "worker_restart_delivered"}:
        dropped = body["proxy"]["fault"]
        require(dropped["actionId"] == target["id"] and dropped["method"] == "POST" and dropped["path"] == pay_route
                and 200 <= dropped["upstreamStatus"] < 300 and dropped["upstreamResponseComplete"] is True
                and dropped["downstreamResponseDelivered"] is False and dropped["responseBytes"] > 0
                and len(traces) == 2 and traces[1]["downstreamResponseFinished"] is False
                and traces[1]["upstreamResponseSha256"] == dropped["upstreamResponseSha256"]
                and len(operations) == 1 and len(payments) == 3,
                "H1 committed reply-loss fault is not bound to one original payment")
        rows, unknown_task = _checkpoint(fault["committedCutoffAfterReplyLoss"], database, run)
        unknown_action = _original_action(rows, target)
        require(unknown_task["closure_id"] == closure["id"] and unknown_task["closure_status"] == "unknown"
                and unknown_task["action_cutoff_sequence"] == unknown_task["reconciled_action_sequence"] == target["action_sequence"]
                and unknown_action["receipt_status"] == "unknown" and not rows["evaluations"]
                and epoch(traces[1]["requestStartedAt"]) >= epoch(fault["target"]["initialDeadline"])
                and epoch(traces[1]["upstreamResponseFinishedAt"]) <= epoch(dropped["observedAt"])
                <= epoch(fault["committedCutoffAfterReplyLoss"]["identity"]["observed_at"]),
                "H1 reply loss did not precede an actual unknown cutoff")
        if variant == "worker_restart_delivered":
            restart = fault["restartReceipt"]
            _restart(restart)
            before_rows, before_task = _checkpoint(fault["restartBefore"], database, run)
            before_action = _original_action(before_rows, target)
            require(before_task["closure_id"] == closure["id"] and before_action["receipt_status"] == "unknown"
                    and epoch(fault["committedCutoffAfterReplyLoss"]["identity"]["observed_at"])
                    <= epoch(fault["restartBefore"]["identity"]["observed_at"]) <= epoch(restart["startedAt"]),
                    "H1 restart was not after the original third-payment reply loss/cutoff")
    return {"variant": variant, "runId": run_id, "complete": not missing, "missing": missing,
            "actions": len(actions), "payments": len(payments), "liveSlots": 0,
            "restart_at_cutoff": variant == "worker_restart_pending" and not missing}


def _parent_cases(capture, database, root):
    """Validate every supplied case using only its own database funding history."""
    matrix = capture["result"]
    require(matrix.get("schemaVersion") == "ber-h1-cutoff-matrix/v1", "unsupported H1 matrix")
    require(isinstance(matrix.get("cases"), list) and 0 < len(matrix["cases"]) <= len(VARIANTS),
            "H1 parent case inventory invalid")
    transport = read_reference(root, matrix["transportDiagnostics"])
    require(transport.get("schemaVersion") == "ber-h1-cutoff-final-transport/v1"
            and transport.get("captureId") == capture["captureId"]
            and transport.get("cases") == [{"variant": e["variant"], "status": e.get("status"),
                                            "reference": e.get("reference")} for e in matrix["cases"]],
            "H1 parent omitted or changed its hash-pinned physical case inventory")
    cases, funding_sources = [], {}
    for entry in matrix["cases"]:
        genuine = read_reference(root, entry["genuineAttempt"])
        if not entry.get("fault", {}).get("target"):
            cases.append(_case(entry, database, root))
            continue
        owner = entry["owner"]["result"]
        grant_id, funding = _issued_funding(genuine, owner["run"]["owner_id"], database)
        require(grant_id not in funding_sources, "H1 funding issuance reused")
        funding_sources[grant_id] = funding
        result = _case(entry, database, root, funding_sources)
        cases.append(result)
        debit = one([r for r in owner["ledger"] if r["entry_type"] == "debit"], "H1 funded debit")
        funding_sources[debit["bonus_grant_id"]]["availableUnits"] -= int(debit["amount_units"])
        if result["complete"]:
            if owner["refunds"]:
                funding_sources[debit["bonus_grant_id"]]["availableAt"] = epoch(owner["run"]["finished_at"])
            funding_sources[debit["bonus_grant_id"]]["availableUnits"] += sum(
                int(r["available_delta_units"]) for r in owner["ledger"] if r["entry_type"] == "refund")
    require(len({r["variant"] for r in cases}) == len(cases), "H1 variants duplicated")
    exercised = [entry for entry in matrix["cases"] if entry.get("fault", {}).get("target")]
    require(len({entry["runId"] for entry in exercised}) == len(exercised)
            and len({entry["captureId"] for entry in exercised}) == len(exercised), "H1 variants reused a physical run/capture")
    return cases


def _capture_parts(reference, root):
    document = read_reference(root, reference)
    assembly = document.get("schemaVersion") == "ber-h1-cutoff-matrix-assembly/v1"
    refs = document.get("captures") if assembly else [reference]
    require(isinstance(refs, list) and 0 < len(refs) <= 8, "H1 assembly capture inventory invalid")
    require(all(isinstance(p, dict) and isinstance(p.get("sha256"), str) for p in refs)
            and len({p["sha256"] for p in refs}) == len(refs), "H1 assembly duplicated capture selection")
    selections = document.get("selections") if assembly else None
    if assembly:
        require(isinstance(selections, dict) and set(selections) == {p["sha256"] for p in refs},
                "H1 assembly needs explicit selections for every capture hash")
        for names in selections.values():
            require(isinstance(names, list) and names and all(isinstance(n, str) and n in VARIANTS for n in names)
                    and len(set(names)) == len(names), "H1 assembly duplicated or invalid variant selection")
    from tests.bdd.adapters.beta_poc_recovery_verifier import _verify_provenance
    parts = []
    for pointer in refs:
        parent = read_reference(root, pointer)
        require(parent.get("schemaVersion") == "ber-h1-cutoff-matrix-capture/v1", "unsupported or nested H1 capture")
        require(isinstance(parent.get("captureId"), str) and UUID.fullmatch(parent["captureId"]), "invalid H1 parent capture identity")
        require(parent.get("boundary") == "isolated_local_browser_backend_postgres_bef_files"
                and parent.get("result", {}).get("boundary") == "actual_owner_browser_admission_worker_bef_postgres_local_rpc",
                "H1 parent boundary profile differs")
        database, _ = _verify_provenance(parent, root)
        results = _parent_cases(parent, database, root)
        parts.append((pointer, parent, database, results))
    require(len({p[1]["captureId"] for p in parts}) == len(parts)
            and len({p[2] for p in parts}) == len(parts), "H1 assembly reused capture or database")
    require(all(p[1]["provenance"]["inputHashesBefore"] == parts[0][1]["provenance"]["inputHashesBefore"]
                and p[1].get("boundary") == parts[0][1].get("boundary")
                and p[1]["result"].get("boundary") == parts[0][1]["result"].get("boundary") for p in parts),
            "H1 assembly mixed source inventories or boundary profiles")
    profiles = []
    for _, parent, _, _ in parts:
        for entry in parent["result"]["cases"]:
            if not entry.get("fault", {}).get("target"):
                continue
            owner = entry["owner"]["result"]
            run, prep = owner["run"], one(owner["preparation"], "H1 execution profile preparation")
            profile = (run["release_identity"], run["manifest_hash"], prep["case_id"], prep["case_hash"],
                       prep["execution_identity_hash"], prep["environment_manifest_sha256"], prep["application_source_hash"])
            require(all(isinstance(v, str) and v for v in profile), "H1 execution profile is incomplete")
            profiles.append(profile)
    require(not profiles or all(p == profiles[0] for p in profiles),
            "H1 captures mixed pinned release or execution profiles")
    return document, parts, selections


def verify_h1_matrix(reference, *, repository_root: Path | None = None):
    root = repository_root or Path(__file__).resolve().parents[3]
    document, parts, selections = _capture_parts(reference, root)
    selected, excluded = [], []
    for pointer, parent, database, results in parts:
        if selections is not None:
            require(set(selections[pointer["sha256"]]) <= {r["variant"] for r in results},
                    "selected H1 observation was not supplied")
        for entry, result in zip(parent["result"]["cases"], results):
            observation = {"captureId": parent["captureId"], "captureSha256": pointer["sha256"],
                           "databaseName": database, "parentReference": pointer, "observation": result}
            if selections is None or result["variant"] in selections[pointer["sha256"]]:
                require(selections is None or result["complete"], "selected H1 observation is incomplete")
                selected.append(observation)
            else:
                require(not result["complete"], "H1 assembly excluded a completed observation")
                excluded.append(observation)
    if selections is not None:
        declared = document.get("excludedIncomplete")
        require(isinstance(declared, list) and all(isinstance(e, dict) and set(e) == {"captureSha256", "variant"}
                and isinstance(e["captureSha256"], str) and isinstance(e["variant"], str) for e in declared),
                "H1 assembly must declare excluded incomplete observations")
        keys = [(e["captureSha256"], e["variant"]) for e in declared]
        require(len(set(keys)) == len(keys) and set(keys) == {
                (e["captureSha256"], e["observation"]["variant"]) for e in excluded},
                "H1 assembly omitted or invented an excluded incomplete observation")
        names = [e["observation"]["variant"] for e in selected]
        require(len(names) == len(set(names)) == len(VARIANTS) and set(names) == VARIANTS,
                "H1 assembly must select exactly eight unique complete variants")
        exercised = [(entry["runId"], entry["captureId"]) for _, parent, _, _ in parts
                     for entry in parent["result"]["cases"] if entry.get("fault", {}).get("target")]
        require(len({e[0] for e in exercised}) == len(exercised) and len({e[1] for e in exercised}) == len(exercised),
                "H1 assembly reused a physical run or case capture")
    cases = [e["observation"] for e in selected]
    complete = {r["variant"] for r in cases if r["complete"]}
    facts = {name: complete == VARIANTS for name in FACTS}
    return {"facts": facts, "cases": cases, "databaseName": parts[0][2] if len(parts) == 1 else None,
            "databaseNames": [p[2] for p in parts],
            "selectedObservations": selected, "excludedIncompleteObservations": excluded,
            "missingVariants": sorted(VARIANTS - complete),
            "restart_at_cutoff": "worker_restart_pending" in complete,
            "fullScenarioAcceptance": "passed" if complete == VARIANTS else "blocked"}
