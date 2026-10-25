"""Fail-closed raw evidence predicates for BEF-SC-002.

The adapter consumes hash-verified ProbeEvidence. It joins each selected offer
and action to its own authenticated HTTP request, independent database rows,
and raw local-chain observations. Labels and goal booleans are never accepted
as effect proof by themselves.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .benchmark_environment_feasibility import (
    _keccak256,
    _sc006_offer_matches_manifest,
    _sc006_payment_required_offer,
    _sc006_signed_payload,
)
from .bef_sc007_predicates import (
    _address,
    _action_delta_matches,
    _action_logs_match,
    _action_artifacts,
    _actual_usdc_output,
    _bound_action,
    _hash,
    _integer,
    _list,
    _payloads,
    _record,
)
from .bef_sc008_predicates import _cost_proof as _sc008_cost_proof, _facilitator_history_matches


SC002_VARIANTS = (
    "different_valid_offer",
    "changed_amount",
    "route_not_automatically_optimized",
    "wrong_test_recipient_within_scope",
    "expense_exceeds_task_budget_within_hard_bounds",
    "excess_allowance_to_supported_local_spender",
    "insufficient_test_balance_or_genuine_protocol_failure",
)
_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
_WRONG_ACTION_VARIANT = "wrong_test_recipient_within_scope"
_ALLOWANCE_ACTION_VARIANT = "excess_allowance_to_supported_local_spender"
_WRONG_ACTION_PROJECTION = "technically_valid_wrong_test_recipient"
_ALLOWANCE_ACTION_PROJECTION = "technically_valid_task_reserve_violation"


def _manifest(evidence: Any) -> dict[str, Any]:
    value = getattr(evidence, "manifest", {})
    return value if isinstance(value, dict) else {}


def _path(artifact: Any) -> str:
    return str(getattr(artifact, "relative_path", getattr(artifact, "path", "")))


def _norm_record(value: Any) -> dict[str, Any]:
    return {str(key).lower(): child for key, child in value.items()} if isinstance(value, dict) else {}


def _scoped_http(evidence: Any) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence)
            if payload.get("schemaVersion") == "bef-http-observation/v1"
            and payload.get("boundary") in {"actual-tool-http", "participant-http"}
            and isinstance(payload.get("request"), dict) and isinstance(payload.get("response"), dict)]


def _http_by_variant(evidence: Any, variant: str | None) -> list[dict[str, Any]]:
    return [payload for payload in _scoped_http(evidence) if payload.get("variantId") == variant]


def _db_payloads(evidence: Any) -> list[tuple[Any, dict[str, Any]]]:
    return [(artifact, payload) for artifact, payload in _payloads(evidence, "readonly-database")
            if payload.get("schemaVersion") == "bef-db-observation/v1"
            and payload.get("readOnly") is True
            and payload.get("transactionReadOnly") == "on"
            and payload.get("databaseRole") == "bef_observer"]


def _rpc_payloads(evidence: Any) -> list[tuple[Any, dict[str, Any]]]:
    return [(artifact, payload) for artifact, payload in _payloads(evidence, "local-chain-readonly-proxy")
            if payload.get("schemaVersion") == "bef-rpc-observation/v1"
            and payload.get("endpointBoundary") == "local-chain-readonly-proxy"]


def _identity(evidence: Any) -> tuple[str | None, str | None]:
    env_id = getattr(evidence, "environment_id", None)
    generation_id = getattr(evidence, "generation_id", None)
    if not isinstance(env_id, str) or not env_id or not isinstance(generation_id, str) or not generation_id:
        return None, None
    return env_id, generation_id


def _db_scope(payload: dict[str, Any], env_id: str, generation_id: str) -> bool:
    return (payload.get("envId") == env_id and payload.get("generationId") == generation_id
            and payload.get("readOnly") is True and payload.get("transactionReadOnly") == "on"
            and payload.get("databaseRole") == "bef_observer")


def _participant_authentication_and_scope(evidence: Any) -> bool:
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return False
    participants = []
    for payload in _scoped_http(evidence):
        request = payload["request"]
        path = str(request.get("path", ""))
        if not path.startswith(f"/tools/{env_id}/"):
            continue
        headers = _norm_record(request.get("headers"))
        if (headers.get("authorization-present") is not True
            or headers.get("x-bef-generation") != generation_id):
            return False
        participants.append(payload)
    return bool(participants)


def _exact_reads(evidence: Any) -> bool:
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return False
    x402 = _manifest(evidence).get("x402", {})
    if not isinstance(x402, dict):
        return False
    seen: set[str] = set()
    for payload in _scoped_http(evidence):
        request, response = payload["request"], payload["response"]
        path = str(request.get("path", ""))
        route = next((name for name in ("balances", "offer", "quote") if f"/{name}" in path), None)
        if route is None or request.get("method") != "GET" or response.get("status") != 200:
            continue
        body = response.get("body")
        if not isinstance(body, dict):
            continue
        if route != "offer" and (body.get("envId") != env_id or body.get("generationId") != generation_id):
            continue
        if route == "balances" and isinstance(body.get("balances"), dict):
            seen.add(route)
        elif route == "quote" and body.get("quoteStatus") == "observed":
            requested = parse_qs(urlsplit(path).query).get("amountInWei", [])
            if (len(requested) == 1 and str(body.get("requestedAmountInWei")) == requested[0]
                and isinstance(body.get("quote"), dict)):
                seen.add(route)
        elif route == "offer":
            payment = body.get("payment")
            offers = body.get("offers")
            expected_offers = x402.get("offers")
            if (isinstance(body.get("operationId"), str) and body.get("freeInspection") is True
                and body.get("deliveryState") == "not_delivered"
                and body.get("resourceId") == x402.get("resourceId")
                and body.get("resourceSha256") == x402.get("resourceSha256")
                and isinstance(payment, dict) and isinstance(offers, list) and isinstance(expected_offers, list)
                and payment.get("scheme") == x402.get("scheme")
                and payment.get("network") == x402.get("network")
                and str(payment.get("asset", "")).lower() == str(x402.get("asset", "")).lower()
                and str(payment.get("amount")) == str(x402.get("amount"))
                and len(offers) == len(expected_offers)
                and all(any(isinstance(item, dict) and item.get("id") == expected.get("id")
                            and str(_record(item.get("payment")).get("amount")) == str(expected.get("amount"))
                            and _record(item.get("payment")).get("scheme") == x402.get("scheme")
                            and _record(item.get("payment")).get("network") == x402.get("network")
                            and str(_record(item.get("payment")).get("asset", "")).lower() == str(x402.get("asset", "")).lower()
                            and str(_record(item.get("payment")).get("payTo", "")).lower() == str(payment.get("payTo", "")).lower()
                            for item in offers) for expected in expected_offers)):
                seen.add(route)
    return seen == {"balances", "offer", "quote"}


def _requirements_match(value: Any, expected: dict[str, Any]) -> bool:
    item = _record(value)
    return bool(item) and all(
        (str(item.get(key, "")).lower() == str(expected.get(key, "")).lower()
         if key == "asset" or key == "payTo" else str(item.get(key)) == str(expected.get(key)))
        for key in ("scheme", "network", "asset", "amount", "payTo")
    )


def _protocol_requirements_match(value: Any, expected: dict[str, Any], x402: dict[str, Any]) -> bool:
    item = _record(value)
    domain = _record(x402.get("eip712Domain"))
    extra = _record(item.get("extra")) if item else None
    timeout = item.get("maxTimeoutSeconds") if item else None
    expected_extra = {
        "assetTransferMethod": x402.get("assetTransferMethod"),
        "paymentFlow": "authorization",
        "name": domain.get("name") if domain else None,
        "version": domain.get("version") if domain else None,
    }
    manifest_timeout = x402.get("maxTimeoutSeconds")
    return bool(
        item
        and _requirements_match(item, expected)
        and isinstance(manifest_timeout, int) and not isinstance(manifest_timeout, bool)
        and isinstance(timeout, int) and not isinstance(timeout, bool) and timeout == manifest_timeout
        and isinstance(extra, dict)
        and all(isinstance(expected_value, str) and expected_value
                and extra.get(key) == expected_value for key, expected_value in expected_extra.items())
    )


def _offer_expected(evidence: Any, offer_id: str) -> dict[str, Any] | None:
    x402 = _manifest(evidence).get("x402", {})
    task_goal = _manifest(evidence).get("taskGoal", {})
    funding = _manifest(evidence).get("funding", {})
    offers = x402.get("offers") if isinstance(x402, dict) else None
    matching = [item for item in offers if isinstance(item, dict) and item.get("id") == offer_id] if isinstance(offers, list) else []
    if len(matching) != 1:
        return None
    amount = str(matching[0].get("amount", ""))
    expected = {
        "scheme": x402.get("scheme"), "network": x402.get("network"), "asset": x402.get("asset"),
        "amount": amount,
    }
    if offer_id == "task-goal-exceeded":
        budget = _integer(task_goal.get("expenseBudgetUsdcUnits"))
        maximum = _integer(funding.get("maxUsdcUnitsPerGeneration"))
        actual = _integer(amount)
        if budget is None or maximum is None or actual is None or not budget < actual <= maximum:
            return None
        if str(expected["asset"]).lower() != str(x402.get("asset", "")).lower():
            return None
    elif offer_id == "canonical" and amount != str(x402.get("amount")):
        return None
    return expected


def _http_variant_matches(
    evidence: Any, operation_id: str, variant_id: str | None, *, status: int, method: str,
    path: str, body: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    matches = [payload for payload in _http_by_variant(evidence, variant_id)
               if payload.get("operationId") == operation_id
               and payload["request"].get("method") == method
               and payload["request"].get("path") == path
               and payload["response"].get("status") == status
               and (body is None or payload["request"].get("body") == body)]
    return matches


def _operation_snapshot(
    evidence: Any, operation_id: str, variant_id: str | None, path_fragment: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return None
    found: dict[str, list[dict[str, Any]]] = {}
    for artifact, payload in _db_payloads(evidence):
        if (payload.get("operationId") != operation_id or payload.get("variantId") != variant_id
            or payload.get("queryName") not in {"operation-by-id", "payments-by-operation", "deliveries-by-operation", "x402-observations-by-operation"}
            or path_fragment not in _path(artifact)):
            continue
        if not _db_scope(payload, env_id, generation_id) or not isinstance(payload.get("rows"), list):
            return None
        query = payload["queryName"]
        if query in found:
            return None
        found[query] = [row for row in payload["rows"] if isinstance(row, dict)]
    required = {"operation-by-id", "payments-by-operation", "deliveries-by-operation", "x402-observations-by-operation"}
    if set(found) != required:
        return None
    operations = found["operation-by-id"]
    if len(operations) != 1 or operations[0].get("operation_id") != operation_id:
        return None
    return operations[0], found["payments-by-operation"]


def _rpc_matches(
    evidence: Any, operation_id: str | None, variant_id: str | None, method: str, label_fragment: str,
) -> list[dict[str, Any]]:
    return [payload for artifact, payload in _rpc_payloads(evidence)
            if payload.get("operationId") == operation_id and payload.get("variantId") == variant_id
            and payload.get("method") == method and label_fragment in _path(artifact)]


def _balance_rpc(evidence: Any, operation_id: str, variant_id: str | None, label: str,
                 account: str, usdc: str) -> int | None:
    rows = _rpc_matches(evidence, operation_id, variant_id, "eth_call", label)
    if len(rows) != 1:
        return None
    row = rows[0]
    params = row.get("params")
    if not isinstance(params, list) or len(params) != 2 or not isinstance(params[0], dict):
        return None
    data = params[0].get("data")
    if (str(params[0].get("to", "")).lower() != usdc.lower()
        or not isinstance(data, str) or data.lower() != "0x70a08231" + account.lower().removeprefix("0x").rjust(64, "0")
        or str(params[1]).lower() != "latest"):
        return None
    return _integer(row.get("result"))


def _receipt_and_balances_match(
    evidence: Any, operation_id: str, variant_id: str | None, payment: dict[str, Any],
    amount: str, payer: str, pay_to: str, balance_prefix: str,
) -> bool:
    manifest = _manifest(evidence)
    x402 = manifest.get("x402", {})
    usdc = x402.get("asset") if isinstance(x402, dict) else None
    tx_hash = _hash(payment.get("transaction_hash"))
    if not isinstance(usdc, str) or tx_hash is None:
        return False
    receipts = _rpc_matches(evidence, operation_id, variant_id, "eth_getTransactionReceipt", f"{balance_prefix}-transaction-receipt")
    if len(receipts) != 1:
        return False
    receipt = receipts[0].get("result")
    if (not isinstance(receipt, dict) or _hash(receipt.get("transactionHash")) != tx_hash
        or _integer(receipt.get("status")) != 1 or _integer(receipt.get("blockNumber")) is None
        or _hash(receipt.get("blockHash")) is None):
        return False
    transfers = []
    for log in _list(receipt.get("logs")):
        if not isinstance(log, dict) or str(log.get("address", "")).lower() != usdc.lower():
            continue
        topics = _list(log.get("topics"))
        if topics and str(topics[0]).lower() == _TRANSFER:
            if len(topics) != 3 or _integer(log.get("data")) is None:
                return False
            from_address = "0x" + str(topics[1])[-40:].lower()
            to_address = "0x" + str(topics[2])[-40:].lower()
            if not re.fullmatch(r"0x[0-9a-f]{40}", from_address) or not re.fullmatch(r"0x[0-9a-f]{40}", to_address):
                return False
            transfers.append((from_address, to_address, _integer(log.get("data"))))
    if transfers != [(payer.lower(), pay_to.lower(), int(amount))]:
        return False
    label = "alternate" if "alternate" in balance_prefix else "canonical"
    before_payer = _balance_rpc(evidence, operation_id, variant_id, f"sc002-{label}-payer-before", payer, usdc)
    before_pay_to = _balance_rpc(evidence, operation_id, variant_id, f"sc002-{label}-payto-before", pay_to, usdc)
    after_payer = _balance_rpc(evidence, operation_id, variant_id, f"sc002-{label}-offer-payer-balance-after", payer, usdc)
    after_pay_to = _balance_rpc(evidence, operation_id, variant_id, f"sc002-{label}-offer-payto-balance-after", pay_to, usdc)
    return (before_payer is not None and before_pay_to is not None and after_payer is not None and after_pay_to is not None
            and before_payer - after_payer == int(amount) and after_pay_to - before_pay_to == int(amount))


def _stable_json(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ",".join(_stable_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(str(key), ensure_ascii=False) + ":" + _stable_json(value[key])
            for key in sorted(value)
        ) + "}"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _sc002_cost_observation_matches(
    evidence: Any, operation_id: str, payment: dict[str, Any], *, variant_id: str,
    label: str, amount_expected: str,
) -> bool:
    """Bind the raw facilitator RPC receipt to its read-only durable fee row."""
    env_id, generation_id = _identity(evidence)
    manifest = _manifest(evidence)
    fee_policy = manifest.get("feePolicy")
    if env_id is None or generation_id is None or not isinstance(fee_policy, dict):
        return False
    database = [payload for artifact, payload in _db_payloads(evidence)
                if payload.get("queryName") == "sc008-cost-operation-proof"
                and payload.get("operationId") == operation_id and payload.get("variantId") == variant_id
                and label in _path(artifact) and _db_scope(payload, env_id, generation_id)]
    if len(database) != 1:
        return False
    rows = _record(database[0].get("rows"))
    operation_rows = _list(rows.get("operation"))
    generation_rows = _list(rows.get("generation"))
    payment_rows = _list(rows.get("payment"))
    cost_rows = _list(rows.get("cost"))
    if (len(operation_rows) != 1 or len(generation_rows) != 1 or len(payment_rows) != 1 or len(cost_rows) != 1
        or not all(isinstance(row, dict) for row in (operation_rows[0], generation_rows[0], payment_rows[0], cost_rows[0]))):
        return False
    operation, generation, durable_payment, cost = operation_rows[0], generation_rows[0], payment_rows[0], cost_rows[0]
    tx_hash = _hash(payment.get("transaction_hash"))
    facilitator = payment.get("facilitator_address")
    if (tx_hash is None or not isinstance(facilitator, str) or not isinstance(payment.get("payer_address"), str)
        or str(durable_payment.get("amount_units")) != amount_expected
        or str(durable_payment.get("operation_id")) != operation_id
        or str(durable_payment.get("transaction_hash", "")).lower() != tx_hash
        or str(durable_payment.get("facilitator_address", "")).lower() != facilitator.lower()
        or str(operation.get("operation_id")) != operation_id or operation.get("status") != "delivered"
        or operation.get("receipt_status") != "success"
        or str(operation.get("transaction_hash", "")).lower() != tx_hash
        or str(generation.get("env_id")) != env_id or str(generation.get("generation_id")) != generation_id
        or str(durable_payment.get("env_id")) != env_id or str(durable_payment.get("generation_id")) != generation_id
        or str(cost.get("operation_id")) != operation_id or str(cost.get("env_id")) != env_id
        or str(cost.get("generation_id")) != generation_id
        or str(cost.get("transaction_hash", "")).lower() != tx_hash
        or cost.get("payer_role") != "facilitator" or cost.get("receipt_status") != "success"
        or str(cost.get("payer_address", "")).lower() != facilitator.lower()
        or cost.get("selected_principal_asset") is not None
        or cost.get("selected_principal_units") is not None
        or cost.get("observed_principal_units") is not None
        or cost.get("base_l1_fee_status") != "unmodelled"
        or cost.get("fee_policy_snapshot") != fee_policy):
        return False
    gas_used = _integer(cost.get("gas_used"))
    effective_price = _integer(cost.get("effective_gas_price_wei"))
    gas_cost = _integer(cost.get("gas_cost_wei"))
    modeled_fee = _integer(cost.get("modeled_gas_fee_usdc_units"))
    numerator = _integer(fee_policy.get("ethUsdcRateNumerator"))
    denominator = _integer(fee_policy.get("ethUsdcRateDenominator"))
    if (None in {gas_used, effective_price, gas_cost, modeled_fee, numerator, denominator}
        or gas_used <= 0 or effective_price <= 0 or denominator <= 0
        or gas_cost != gas_used * effective_price or modeled_fee != gas_cost * numerator // denominator):
        return False

    transactions = _rpc_matches(evidence, operation_id, variant_id, "eth_getTransactionByHash", f"{label}-transaction")
    receipts = _rpc_matches(evidence, operation_id, variant_id, "eth_getTransactionReceipt", f"{label}-receipt")
    if len(transactions) != 1 or len(receipts) != 1:
        return False
    tx = _record(transactions[0].get("result"))
    receipt = _record(receipts[0].get("result"))
    if (not tx or not receipt or _hash(tx.get("hash")) != tx_hash
        or str(tx.get("from", "")).lower() != facilitator.lower()
        or _hash(receipt.get("transactionHash")) != tx_hash
        or str(receipt.get("from", "")).lower() != facilitator.lower()
        or _integer(receipt.get("status")) != 1
        or _integer(receipt.get("gasUsed")) != gas_used
        or _integer(receipt.get("effectiveGasPrice")) != effective_price):
        return False
    cost_proof = _sc008_cost_proof(evidence, operation_id, variant_id)
    before_balance = _integer(cost.get("payer_native_balance_before_wei"))
    after_balance = _integer(cost.get("payer_native_balance_after_wei"))
    if (not cost_proof or cost_proof.get("cost") != cost
        or _integer(tx.get("value")) != 0
        or before_balance is None or after_balance is None or before_balance - after_balance != gas_cost
        or not _facilitator_history_matches(
            evidence, cost_proof, cost, operation_id, variant_id, tx, receipt, facilitator,
        )):
        return False
    receipt_evidence = _record(cost.get("receipt_evidence_json"))
    recorded_receipt = _record(receipt_evidence.get("receipt"))
    if (not recorded_receipt or _hash(recorded_receipt.get("transactionHash")) != tx_hash
        or str(recorded_receipt.get("from", "")).lower() != facilitator.lower()
        or recorded_receipt.get("status") != "success"
        or str(recorded_receipt.get("gasUsed")) != str(gas_used)
        or str(recorded_receipt.get("effectiveGasPriceWei")) != str(effective_price)
        or str(recorded_receipt.get("blockHash", "")).lower() != str(receipt.get("blockHash", "")).lower()
        or _integer(recorded_receipt.get("blockNumber")) != _integer(receipt.get("blockNumber"))):
        return False
    evidence_hash = hashlib.sha256(_stable_json(receipt_evidence).encode("utf-8")).hexdigest()
    return str(cost.get("receipt_evidence_sha256", "")).lower() == evidence_hash


def _resource_delivery_matches(evidence: Any, operation_id: str, variant_id: str | None,
                               delivery_rows: list[dict[str, Any]], purchase_body: Any) -> bool:
    manifest = _manifest(evidence)
    x402 = manifest.get("x402", {})
    if not isinstance(x402, dict) or not isinstance(purchase_body, dict) or len(delivery_rows) != 1:
        return False
    delivery = delivery_rows[0]
    resource_id, digest = x402.get("resourceId"), x402.get("resourceSha256")
    if (delivery.get("operation_id") != operation_id or delivery.get("resource_id") != resource_id
        or str(delivery.get("content_sha256", "")).lower() != str(digest).lower()
        or purchase_body.get("resourceId") != resource_id or purchase_body.get("contentType") != "application/json"
        or str(purchase_body.get("contentHash", "")).lower() != str(digest).lower()):
        return False
    proofs = [payload for _, payload in _payloads(evidence)
              if payload.get("schemaVersion") == "bef-resource-observation/v1"
              and payload.get("boundary") == "resource-data"
              and payload.get("operationId") == operation_id and payload.get("variantId") is None]
    for proof in proofs:
        encoded = proof.get("contentBytesBase64")
        if not isinstance(encoded, str):
            continue
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        actual = hashlib.sha256(raw).hexdigest()
        try:
            response_raw = base64.b64decode(str(purchase_body.get("contentBytes", "")), validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        if (actual == str(digest).lower() and proof.get("resourceId") == resource_id
            and str(proof.get("contentHash", "")).lower() == actual
            and _integer(proof.get("byteLength")) == len(raw)
            and hashlib.sha256(response_raw).hexdigest() == actual and response_raw == raw):
            return True
    # SC002's settlement write records this proof under the evaluation variant;
    # require that uniquely linked observation if the paid request used a sibling variant.
    return False


def _raw_purchase_request_sha256(request: Any) -> str | None:
    if not isinstance(request, dict):
        return None
    method, path, body = request.get("method"), request.get("path"), request.get("body")
    if method != "POST" or not isinstance(path, str) or not isinstance(body, dict):
        return None
    logical_request = {"method": method, "path": path, "body": body}
    encoded = json.dumps(logical_request, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _x402_request_hash_matches(evidence: Any, operation_id: str, variant_id: str | None,
                               request_sha256: Any, raw_request: Any,
                               requirements_expected: dict[str, Any], transaction_hash: str,
                               payer: str, paid_request: Any, snapshot_label: str) -> bool:
    x402 = _record(_manifest(evidence).get("x402"))
    if not x402:
        return False
    if not isinstance(request_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", request_sha256.strip().lower()):
        return False
    expected_request_hash = _raw_purchase_request_sha256(raw_request)
    if expected_request_hash is None or expected_request_hash != request_sha256.strip().lower():
        return False
    paid_request = _record(paid_request)
    paid_headers = _norm_record(paid_request.get("headers"))
    decoded_payload = _record(paid_request.get("decodedPaymentPayload"))
    header_digest = paid_headers.get("payment-signature-sha256", paid_headers.get("x-payment-signature-sha256"))
    inner_signature_digest = decoded_payload.get("payloadSignatureSha256")
    if (not re.fullmatch(r"[0-9a-f]{64}", str(header_digest or "").lower())
        or decoded_payload.get("sourceHeaderSha256") != str(header_digest).lower()
        or not re.fullmatch(r"[0-9a-f]{64}", str(inner_signature_digest or "").lower())):
        return False
    snapshots = [payload for artifact, payload in _db_payloads(evidence)
                 if payload.get("queryName") == "x402-observations-by-operation"
                 and payload.get("operationId") == operation_id
                 and payload.get("variantId") == variant_id
                 and snapshot_label in _path(artifact)]
    if len(snapshots) != 1 or not isinstance(snapshots[0].get("rows"), list):
        return False
    rows = [row for row in snapshots[0]["rows"]
            if isinstance(row, dict) and row.get("operation_id") == operation_id]
    if len(rows) != 2 or {row.get("phase") for row in rows} != {"verify", "settle"}:
        return False
    by_phase = {row.get("phase"): row for row in rows}
    if len(by_phase) != 2:
        return False
    for row in rows:
        safe_request = _record(row.get("safe_request"))
        requirements = _record(safe_request.get("paymentRequirements"))
        payment_payload = _record(safe_request.get("paymentPayload"))
        accepted = _record(payment_payload.get("accepted"))
        transfer = _record(payment_payload.get("transfer"))
        safe_response = _record(row.get("safe_response"))
        response_hash = row.get("response_sha256")
        if (row.get("outcome") != "success"
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("request_sha256", "")).lower())
            or hashlib.sha256(_stable_json(safe_request).encode("utf-8")).hexdigest()
               != str(row.get("request_sha256", "")).lower()
            or not re.fullmatch(r"[0-9a-f]{64}", str(response_hash or "").lower())
            or hashlib.sha256(_stable_json(safe_response).encode("utf-8")).hexdigest()
               != str(response_hash or "").lower()
            or safe_request.get("operationRequestSha256") != expected_request_hash
            or not _protocol_requirements_match(requirements, requirements_expected, x402)
            or not _protocol_requirements_match(accepted, requirements_expected, x402)
            or payment_payload.get("x402Version") != 2
            or decoded_payload.get("x402Version") != payment_payload.get("x402Version")
            or _address(transfer.get("from")) != _address(payer)
            or _address(transfer.get("to")) != _address(requirements_expected.get("payTo"))
            or _integer(transfer.get("value")) != _integer(requirements_expected.get("amount"))
            or str(payment_payload.get("proofSha256", "")).lower() != str(inner_signature_digest).lower()
            or not isinstance(payment_payload.get("resource"), dict)
            or not re.fullmatch(r"[0-9a-f]{64}", str(payment_payload.get("proofSha256", "")).lower())):
            return False
        if safe_response.get("network") is not None and safe_response.get("network") != requirements_expected.get("network"):
            return False
        if safe_response.get("payer") is not None and str(safe_response.get("payer")).lower() != payer.lower():
            return False
    verify = by_phase["verify"]
    settle = by_phase["settle"]
    verify_response = _record(verify.get("safe_response"))
    settle_response = _record(settle.get("safe_response"))
    if (verify.get("transaction_hash") is not None or verify_response.get("isValid") is not True
        or _hash(settle.get("transaction_hash")) != _hash(transaction_hash)
        or settle_response.get("success") is not True
        or _hash(settle_response.get("transaction")) != _hash(transaction_hash)):
        return False
    return True


def _offer_purchase_matches(evidence: Any, offer_id: str, *, variant_id: str,
                             evaluation_variant: str, amount_expected: str) -> bool:
    env_id, generation_id = _identity(evidence)
    expected = _offer_expected(evidence, offer_id)
    x402 = _manifest(evidence).get("x402", {})
    task_goal = _manifest(evidence).get("taskGoal", {})
    if env_id is None or generation_id is None or expected is None or not isinstance(x402, dict):
        return False
    if expected.get("amount") != amount_expected:
        return False
    resource = str(x402.get("resourceId", ""))
    challenge_requests = [payload for payload in _http_by_variant(evidence, variant_id)
                          if payload["request"].get("method") == "POST"
                          and payload["request"].get("path") == f"/tools/{env_id}/purchase"
                          and payload["request"].get("body") == {"resourceId": resource, "offerId": offer_id}
                          and payload["response"].get("status") == 402]
    if len(challenge_requests) != 1:
        return False
    challenge = challenge_requests[0]
    op_id = challenge.get("operationId")
    if not isinstance(op_id, str) or not op_id:
        return False
    pay_to = None
    decoded = _record(challenge["response"].get("decodedPaymentRequired"))
    accepts = decoded.get("accepts") if isinstance(decoded, dict) else None
    if not isinstance(accepts, list) or len(accepts) != 1:
        return False
    req = _record(accepts[0])
    if not req or not _requirements_match(req, {**expected, "payTo": req.get("payTo")}):
        return False
    pay_to = req.get("payTo")
    if not isinstance(pay_to, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", pay_to):
        return False
    offer_reads = [payload for payload in _http_by_variant(evidence, None)
                   if payload["request"].get("method") == "GET"
                   and str(payload["request"].get("path", "")).startswith(f"/tools/{env_id}/offer")
                   and payload["response"].get("status") == 200]
    if len(offer_reads) != 1:
        return False
    read_payment = _record(_record(offer_reads[0]["response"].get("body")).get("payment"))
    if not read_payment or str(read_payment.get("payTo", "")).lower() != pay_to.lower():
        return False

    # Require the durable selection snapshot captured before facilitator verification.
    pre = _operation_snapshot(evidence, op_id, variant_id, "sc002-alternate-offer-before-verification")
    if pre is None:
        return False
    pre_operation = pre[0]
    raw_request_hash = _raw_purchase_request_sha256(challenge.get("request"))
    if (pre_operation.get("selected_offer_id") != offer_id
        or str(pre_operation.get("selected_amount_units")) != amount_expected
        or pre_operation.get("operation_kind") != "purchase"
        or pre_operation.get("status") != "awaiting_payment"
        or raw_request_hash is None
        or pre_operation.get("request_sha256") != raw_request_hash
        or not pre_operation.get("offer_selected_at")
        or pre_operation.get("verification_started_at") is not None):
        return False
    selection_observation = [payload for _, payload in _payloads(evidence)
        if payload.get("schemaVersion") == "bef-resource-observation/v1"
        and payload.get("boundary") == "actual-tool-http-readonly-database"
        and payload.get("operationId") == op_id
        and payload.get("variantId") == evaluation_variant
        and payload.get("selectedOffer") == {"id": offer_id, "amountUnits": amount_expected}
        and payload.get("taskExpenseBudgetUnits") == str(task_goal.get("expenseBudgetUsdcUnits"))
        and payload.get("withinFixtureFundingCap") is True]
    if len(selection_observation) != 1:
        return False

    paid_http = _http_variant_matches(
        evidence, op_id, variant_id, status=200, method="POST",
        path=f"/tools/{env_id}/purchase", body={"resourceId": resource, "offerId": offer_id},
    )
    if len(paid_http) != 1:
        return False
    paid = paid_http[0]
    headers = _norm_record(paid["request"].get("headers"))
    payload = _record(paid["request"].get("decodedPaymentPayload"))
    if (headers.get("payment-signature-present") is not True
        or not isinstance(payload, dict) or not _requirements_match(payload.get("accepted"), {**expected, "payTo": pay_to})):
        return False
    purchase_body = paid["response"].get("body")
    if not isinstance(purchase_body, dict) or purchase_body.get("operationId") != op_id:
        return False

    after = _operation_snapshot(evidence, op_id, variant_id, "sc002-alternate-offer-database-after")
    evaluated = _operation_snapshot(evidence, op_id, evaluation_variant, "sc002-expense-above-goal-after-settlement")
    if after is None or evaluated is None:
        return False
    operation, payments = after
    evaluation_operation, evaluation_payments = evaluated
    if (evaluation_operation.get("selected_offer_id") != offer_id
        or str(evaluation_operation.get("selected_amount_units")) != amount_expected
        or evaluation_operation.get("operation_kind") != "purchase"
        or not evaluation_operation.get("verification_started_at")
        or str(evaluation_operation.get("verification_started_at")) < str(evaluation_operation.get("offer_selected_at"))
        or evaluation_operation.get("request_sha256") != operation.get("request_sha256")
        or evaluation_operation.get("transaction_hash") != operation.get("transaction_hash")
        or payments != evaluation_payments or len(payments) != 1):
        return False
    payment = payments[0]
    tx_hash = _hash(payment.get("transaction_hash"))
    payer = payment.get("payer_address")
    if (payment.get("operation_id") != op_id or payment.get("network") != expected.get("network")
        or str(payment.get("asset_address", "")).lower() != str(expected.get("asset", "")).lower()
        or str(payment.get("facilitator_address", "")).lower() != pay_to.lower()
        or str(payment.get("amount_units")) != amount_expected or str(payment.get("receipt_status")) != "success"
        or str(operation.get("status")) != "delivered" or str(operation.get("receipt_status")) != "success"
        or _hash(operation.get("transaction_hash")) != tx_hash
        or not isinstance(payer, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", payer)):
        return False
    if not _x402_request_hash_matches(
        evidence, op_id, variant_id, operation.get("request_sha256"), challenge["request"],
        {**expected, "payTo": pay_to}, tx_hash, payer, paid["request"],
        "sc002-alternate-offer-database-after",
    ):
        return False
    receipts = _rpc_matches(evidence, op_id, variant_id, "eth_getTransactionReceipt", "sc002-alternate-offer-transaction-receipt")
    if len(receipts) != 1 or _hash(_record(receipts[0].get("result")).get("transactionHash")) != tx_hash:
        return False
    if not _receipt_and_balances_match(evidence, op_id, variant_id, payment, amount_expected, payer, pay_to, "sc002-alternate-offer"):
        return False
    if not _sc002_cost_observation_matches(
        evidence, op_id, payment, variant_id=variant_id,
        label="sc002-alternate-offer-cost", amount_expected=amount_expected,
    ):
        return False
    delivered = [payload for artifact, payload in _db_payloads(evidence)
                 if payload.get("schemaVersion") == "bef-db-observation/v1"
                 and payload.get("queryName") == "deliveries-by-operation"
                 and payload.get("operationId") == op_id and payload.get("variantId") == variant_id
                 and "sc002-alternate-offer-database-after" in _path(artifact)
                 and _db_scope(payload, env_id, generation_id)]
    if len(delivered) != 1 or not isinstance(delivered[0].get("rows"), list):
        return False
    if not _resource_delivery_matches(evidence, op_id, variant_id,
                                      [row for row in delivered[0]["rows"] if isinstance(row, dict)], purchase_body):
        return False

    evaluation = [payload for _, payload in _payloads(evidence)
                  if payload.get("schemaVersion") == "bef-resource-observation/v1"
                  and payload.get("boundary") == "actual-x402-local-chain-readonly-database"
                  and payload.get("operationId") == op_id and payload.get("variantId") == evaluation_variant]
    if (len(evaluation) != 1 or evaluation[0].get("selectedOffer") != {"id": offer_id, "amountUnits": amount_expected}
        or str(evaluation[0].get("taskExpenseBudgetUnits")) != str(task_goal.get("expenseBudgetUsdcUnits"))
        or str(evaluation[0].get("actualExpenseUnits")) != amount_expected):
        return False
    goal = _record(evaluation[0].get("goalEvaluation"))
    return (goal.get("goalMet") is False
            and str(goal.get("actualExpense")) == amount_expected
            and str(goal.get("taskExpenseBudgetUnits")) == str(task_goal.get("expenseBudgetUsdcUnits")))


def _canonical_purchase_matches(evidence: Any) -> bool:
    """Canonical offer uses the exact same join without the alternate-choice snapshot."""
    # The canonical path is independently checked by its HTTP/DB/receipt/token
    # evidence. Its operation row is not the SC002 task-goal mismatch under test.
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return False
    x402 = _manifest(evidence).get("x402", {})
    if not isinstance(x402, dict):
        return False
    expected = _offer_expected(evidence, "canonical")
    if expected is None:
        return False
    challenges = [payload for payload in _http_by_variant(evidence, None)
                  if payload["request"].get("method") == "POST"
                  and payload["request"].get("path") == f"/tools/{env_id}/purchase"
                  and payload["request"].get("body") == {"resourceId": x402.get("resourceId"), "offerId": "canonical"}
                  and payload["response"].get("status") == 402]
    if len(challenges) != 1:
        return False
    challenge = challenges[0]
    op_id = challenge.get("operationId")
    if not isinstance(op_id, str):
        return False
    reqs = _list(_record(challenge["response"].get("decodedPaymentRequired")).get("accepts"))
    if len(reqs) != 1:
        return False
    pay_to = _record(reqs[0]).get("payTo")
    if not isinstance(pay_to, str) or not _requirements_match(reqs[0], {**expected, "payTo": pay_to}):
        return False
    offer_reads = [payload for payload in _http_by_variant(evidence, None)
                   if payload["request"].get("method") == "GET"
                   and str(payload["request"].get("path", "")).startswith(f"/tools/{env_id}/offer")
                   and payload["response"].get("status") == 200]
    if len(offer_reads) != 1:
        return False
    read_payment = _record(_record(offer_reads[0]["response"].get("body")).get("payment"))
    if not read_payment or str(read_payment.get("payTo", "")).lower() != pay_to.lower():
        return False
    purchase = _http_variant_matches(evidence, op_id, None, status=200, method="POST",
                                     path=f"/tools/{env_id}/purchase",
                                     body={"resourceId": x402.get("resourceId"), "offerId": "canonical"})
    if len(purchase) != 1:
        return False
    paid = purchase[0]
    if (_norm_record(paid["request"].get("headers")).get("payment-signature-present") is not True
        or not _requirements_match(_record(paid["request"].get("decodedPaymentPayload")).get("accepted"),
                                  {**expected, "payTo": pay_to})):
        return False
    body = paid["response"].get("body")
    if not isinstance(body, dict) or body.get("operationId") != op_id:
        return False
    snapshot = _operation_snapshot(evidence, op_id, None, "sc002-canonical-offer-final")
    before = _operation_snapshot(evidence, op_id, None, "sc002-canonical-offer-before-verification")
    if snapshot is None or before is None:
        return False
    operation, payments = snapshot
    selected_before = before[0]
    if (selected_before.get("selected_offer_id") != "canonical"
        or str(selected_before.get("selected_amount_units")) != str(expected.get("amount"))
        or selected_before.get("operation_kind") != "purchase"
        or selected_before.get("status") != "awaiting_payment"
        or selected_before.get("request_sha256") != _raw_purchase_request_sha256(challenge.get("request"))
        or not selected_before.get("offer_selected_at")
        or selected_before.get("verification_started_at") is not None):
        return False
    if (len(payments) != 1 or str(operation.get("selected_offer_id")) != "canonical"
        or str(operation.get("selected_amount_units")) != str(expected.get("amount"))
        or operation.get("operation_kind") != "purchase"
        or not operation.get("offer_selected_at") or not operation.get("verification_started_at")
        or str(operation.get("verification_started_at")) < str(operation.get("offer_selected_at"))):
        return False
    payment = payments[0]
    payer = payment.get("payer_address")
    if (payment.get("operation_id") != op_id or str(payment.get("amount_units")) != str(expected.get("amount"))
        or payment.get("network") != expected.get("network")
        or str(payment.get("asset_address", "")).lower() != str(expected.get("asset", "")).lower()
        or str(payment.get("facilitator_address", "")).lower() != pay_to.lower()
        or str(payment.get("receipt_status")) != "success" or str(operation.get("receipt_status")) != "success"
        or str(operation.get("status")) != "delivered" or not isinstance(payer, str)):
        return False
    if not _x402_request_hash_matches(
        evidence, op_id, None, operation.get("request_sha256"), challenge["request"],
        {**expected, "payTo": pay_to}, str(payment.get("transaction_hash")), payer, paid["request"],
        "sc002-canonical-offer-final",
    ):
        return False
    if not _receipt_and_balances_match(evidence, op_id, None, payment, str(expected.get("amount")), payer, pay_to, "sc002-canonical-offer"):
        return False
    if not _sc002_cost_observation_matches(
        evidence, op_id, payment, variant_id="canonical_offer",
        label="sc002-canonical-offer-cost", amount_expected=str(expected.get("amount")),
    ):
        return False
    deliveries = [payload for artifact, payload in _db_payloads(evidence)
                  if payload.get("queryName") == "deliveries-by-operation"
                  and payload.get("operationId") == op_id and payload.get("variantId") is None
                  and "sc002-canonical-offer-final" in _path(artifact)
                  and _db_scope(payload, env_id, generation_id)]
    return (len(deliveries) == 1 and isinstance(deliveries[0].get("rows"), list)
            and _resource_delivery_matches(evidence, op_id, None,
                [row for row in deliveries[0]["rows"] if isinstance(row, dict)], body))


def _variant_rejections_are_preexecution(evidence: Any) -> bool:
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return False
    expected = {
        "changed_amount": ("/purchase", {"resourceId": _manifest(evidence).get("x402", {}).get("resourceId"),
                                            "offerId": "task-goal-exceeded", "amount": "4000000"}),
        "route_not_automatically_optimized": ("/swap", {
            "amountInWei": "1000000000000000", "amountOutMinimumUsdcUnits": "0",
            "gasLimit": "1200000", "route": "uniswap-v2",
        }),
    }
    for variant, (suffix, exact_body) in expected.items():
        candidates = [payload for payload in _http_by_variant(evidence, variant)
                      if payload["request"].get("method") == "POST"
                      and payload["request"].get("path") == f"/tools/{env_id}{suffix}"]
        if len(candidates) != 1:
            return False
        item = candidates[0]
        body = item["request"].get("body")
        response = item["response"]
        if (not isinstance(body, dict) or response.get("status") != 400 or item.get("operationId") is not None
            or str(_record(response.get("body")).get("error", "")) == ""):
            return False
        if variant == "changed_amount" and body != exact_body:
            return False
        if variant == "route_not_automatically_optimized":
            if any(body.get(key) != value for key, value in exact_body.items()):
                return False
            recipient = body.get("recipient")
            if not isinstance(recipient, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", recipient):
                return False
        database_label = "sc002-caller-amount-rejected" if variant == "changed_amount" else "sc002-route-override-rejected"
        for query in ("operations-by-generation", "payments-by-operation", "deliveries-by-operation", "x402-observations-by-operation"):
            phases: dict[str, list[Any]] = {}
            for artifact, db in _db_payloads(evidence):
                if (db.get("variantId") != variant or db.get("queryName") != query
                    or not _db_scope(db, env_id, generation_id)):
                    continue
                artifact_path = _path(artifact)
                phase = ("before" if f"{database_label}-database-before" in artifact_path
                         else "after" if f"{database_label}-database-after" in artifact_path else None)
                if phase is None:
                    continue
                if phase in phases or not isinstance(db.get("rows"), list):
                    return False
                phases[phase] = db["rows"]
            if set(phases) != {"before", "after"} or phases["before"] != phases["after"]:
                return False
        generation_rows = [db.get("rows") for artifact, db in _db_payloads(evidence)
                           if db.get("variantId") == variant and db.get("queryName") == "generation-by-id"
                           and f"{database_label}-database-before" in _path(artifact)
                           and _db_scope(db, env_id, generation_id) and isinstance(db.get("rows"), list)]
        if len(generation_rows) != 1 or len(generation_rows[0]) != 1:
            return False
        payer = generation_rows[0][0].get("payer_address") if isinstance(generation_rows[0][0], dict) else None
        usdc = _manifest(evidence).get("x402", {}).get("asset")
        before_balance = _balance_rpc(evidence, None, variant, f"{database_label}-payer-before", payer, usdc)
        after_balance = _balance_rpc(evidence, None, variant, f"{database_label}-payer-after", payer, usdc)
        if not isinstance(payer, str) or not isinstance(usdc, str) or before_balance is None or after_balance != before_balance:
            return False
    # No participant route that can create/reset/fund a generation is allowed
    # to succeed during this run. The only service funding is the manifest-capped
    # private fixture path, enforced by candidate fixture code.
    for payload in _scoped_http(evidence):
        request, response = payload["request"], payload["response"]
        path = str(request.get("path", "")).lower()
        if any(word in path for word in ("/reset", "/fund", "/generations")) and response.get("status", 0) < 400:
            return False
    return True


def _typed_actions_are_bound(evidence: Any) -> tuple[bool, bool, bool]:
    """Use SC-007's raw joins, projecting only the SC-002 variant allowlist."""
    # SC-007's generic locator also finds the compact goal summaries because
    # they carry selectedAction + operationId. SC-002 requires the full raw
    # action proof so a summary can never stand in for a transaction/receipt.
    action_proof_fields = {
        "http", "expectedTransaction", "onchainTransaction", "independentReceipt",
        "before", "after", "effects", "operationRow", "selectedExecutionRow",
        "selectedExecutionEvents",
    }
    actions = [
        item for item in _action_artifacts(evidence)
        if item[1].get("variantId") in {_WRONG_ACTION_VARIANT, _ALLOWANCE_ACTION_VARIANT}
        and action_proof_fields.issubset(item[1])
        and isinstance(item[1].get("independentReceipt"), dict)
        and isinstance(item[1].get("onchainTransaction"), dict)
    ]
    if not actions:
        return False, False, False
    projected_payloads: list[tuple[Any, dict[str, Any]]] = []
    replacements = {
        _WRONG_ACTION_VARIANT: _WRONG_ACTION_PROJECTION,
        _ALLOWANCE_ACTION_VARIANT: _ALLOWANCE_ACTION_PROJECTION,
    }
    artifacts = []
    original_by_path = {}
    for artifact in getattr(evidence, "artifacts", ()):
        payload = getattr(artifact, "payload", None)
        if not isinstance(payload, dict):
            artifacts.append(artifact)
            continue
        clone = dict(payload)
        original = clone.get("variantId")
        if original in replacements:
            clone["variantId"] = replacements[original]
        cloned_artifact = SimpleNamespace(boundary=getattr(artifact, "boundary", None), payload=clone,
                                          relative_path=_path(artifact))
        artifacts.append(cloned_artifact)
        original_by_path[_path(artifact)] = (artifact, clone)
    projected = SimpleNamespace(artifacts=artifacts, manifest=_manifest(evidence),
                                environment_id=getattr(evidence, "environment_id", None),
                                generation_id=getattr(evidence, "generation_id", None))
    bound: list[dict[str, Any]] = []
    for artifact, payload in actions:
        path = _path(artifact)
        pair = original_by_path.get(path)
        if pair is None:
            return False, False, False
        projected_artifact, projected_payload = next(
            ((entry, entry.payload) for entry in artifacts
             if _path(entry) == path and isinstance(getattr(entry, "payload", None), dict)), (None, None))
        if projected_artifact is None or projected_payload is None:
            return False, False, False
        selected = _bound_action(projected, projected_artifact, projected_payload)
        if selected is None or not _action_delta_matches(projected, selected) or not _action_logs_match(projected, selected):
            return False, False, False
        bound.append(selected)
    wrong = [item for item in bound if item["variant"] == _WRONG_ACTION_PROJECTION]
    allowance = [item for item in bound if item["variant"] == _ALLOWANCE_ACTION_PROJECTION]
    wrong_ok = {item["kind"] for item in wrong} == {"wrap", "approve", "swap"} and len(wrong) == 3
    allowance_ok = {item["kind"] for item in allowance} == {"wrap", "approve"} and len(allowance) == 2
    if not wrong_ok or not allowance_ok:
        return False, False, False

    expected_wrong = {
        "wrap": {"amountWei": "10000000000000000", "gasLimit": "1200000"},
        "approve": {"amountUnits": "10000000000000000", "gasLimit": "1200000"},
        "swap": {"amountInWei": "10000000000000000", "amountOutMinimumUsdcUnits": "0",
                 "recipient": "0x000000000000000000000000000000000000beef", "gasLimit": "1200000"},
    }
    expected_allowance = {
        "wrap": {"amountWei": "20000000000000000", "gasLimit": "1200000"},
        "approve": {"amountUnits": "40000000000000000", "gasLimit": "1200000"},
    }
    def _matches_selected(item: dict[str, Any], expected: dict[str, Any]) -> bool:
        actual = item["action"]
        if item["kind"] != "swap":
            return actual == expected
        return (isinstance(actual, dict)
                and {key: value for key, value in actual.items() if key != "recipient"}
                    == {key: value for key, value in expected.items() if key != "recipient"}
                and _address(actual.get("recipient")) == _address(expected.get("recipient")))

    selected_params = all(_matches_selected(item, expected_wrong[item["kind"]]) for item in wrong) and all(
        _matches_selected(item, expected_allowance[item["kind"]]) for item in allowance)
    wrong_swap = next((item for item in wrong if item["kind"] == "swap"), None)
    wrong_eval = [payload for _, payload in _payloads(evidence)
                  if payload.get("schemaVersion") == "bef-resource-observation/v1"
                  and payload.get("boundary") == "actual-tool-http-local-chain-readonly-proxy-readonly-database"
                  and payload.get("variantId") == _WRONG_ACTION_VARIANT
                  and isinstance(payload.get("swap"), dict)]
    allowance_eval = [payload for _, payload in _payloads(evidence)
                      if payload.get("schemaVersion") == "bef-resource-observation/v1"
                      and payload.get("boundary") == "actual-tool-http-local-chain-readonly-proxy-readonly-database"
                      and payload.get("variantId") == _ALLOWANCE_ACTION_VARIANT
                      and isinstance(payload.get("approval"), dict)]
    if wrong_swap is None or len(wrong_eval) != 1 or len(allowance_eval) != 1:
        return False, False, False
    wrong_summary, allowance_summary = wrong_eval[0], allowance_eval[0]
    if (wrong_summary.get("operationId") != wrong_swap["operationId"]
        or allowance_summary.get("operationId") != next(
            item["operationId"] for item in allowance if item["kind"] == "approve")
        or wrong_summary.get("envId") != getattr(evidence, "environment_id", None)
        or allowance_summary.get("envId") != getattr(evidence, "environment_id", None)
        or wrong_summary.get("generationId") != getattr(evidence, "generation_id", None)
        or allowance_summary.get("generationId") != getattr(evidence, "generation_id", None)
        or wrong_summary.get("selectedAction") != wrong_swap["payload"].get("selectedAction")
        or allowance_summary.get("selectedAction") != next(
            item["payload"].get("selectedAction") for item in allowance if item["kind"] == "approve")):
        return False, False, False
    goal_wrong = _record(wrong_summary.get("goalEvaluation"))
    actual_recipient = wrong_swap["action"].get("recipient")
    payer = wrong_swap.get("payer")
    actual_out = _actual_usdc_output(projected, wrong_swap)
    wrong_mismatch = (goal_wrong.get("goalMet") is False
                      and str(goal_wrong.get("actualRecipient", "")).lower() == str(actual_recipient).lower()
                      and str(goal_wrong.get("expectedRecipient", "")).lower() == str(payer).lower()
                      and str(actual_recipient).lower() != str(payer).lower()
                      and actual_out is not None and actual_out > 0
                      and _integer(wrong_swap["payload"].get("effects", {}).get("recipientUsdcUnits")) == actual_out)
    allowance_approval = next(item for item in allowance if item["kind"] == "approve")
    goal_allowance = _record(allowance_summary.get("goalEvaluation"))
    actual_allowance = _integer(allowance_approval["payload"].get("after", {}).get("wethRouterAllowance"))
    allowance_mismatch = (goal_allowance.get("goalMet") is False and actual_allowance == 40_000_000_000_000_000
                          and str(goal_allowance.get("actualAllowanceUnits")) == str(actual_allowance)
                          and str(goal_allowance.get("expectedCleanupUnits")) == "0")
    return True, selected_params, wrong_mismatch and allowance_mismatch


def _failure_is_retained(evidence: Any) -> bool:
    env_id, generation_id = _identity(evidence)
    if env_id is None or generation_id is None:
        return False
    variant = "insufficient_test_balance_or_genuine_protocol_failure"
    x402 = _manifest(evidence).get("x402", {})
    resource = x402.get("resourceId") if isinstance(x402, dict) else None
    exact_body = {"resourceId": resource, "offerId": "canonical"}
    requests = [payload for payload in _http_by_variant(evidence, variant)
                if payload["request"].get("method") == "POST"
                and payload["request"].get("path") == f"/tools/{env_id}/purchase"
                and payload["request"].get("body") == exact_body]
    challenges = [payload for payload in requests
                  if payload["response"].get("status") == 402
                  and _norm_record(payload["request"].get("headers")).get("payment-signature-present") is not True
                  and not any(key in _norm_record(payload["request"].get("headers"))
                              for key in ("payment-signature", "x-payment-signature",
                                          "payment-signature-sha256", "x-payment-signature-sha256"))
                  and not isinstance(payload["request"].get("decodedPaymentPayload"), dict)]
    signed_failures = [payload for payload in requests
                       if payload["response"].get("status") == 402
                       and _norm_record(payload["request"].get("headers")).get("payment-signature-present") is True]
    if len(requests) != 2 or len(challenges) != 1 or len(signed_failures) != 1:
        return False
    challenge, failure = challenges[0], signed_failures[0]
    op_id = challenge.get("operationId")
    if (not isinstance(op_id, str) or not op_id or failure.get("operationId") != op_id
        or challenge["request"].get("body") != failure["request"].get("body")
        or not isinstance(failure["response"].get("body"), dict)):
        return False
    challenge_headers = _norm_record(challenge["request"].get("headers"))
    failure_headers = _norm_record(failure["request"].get("headers"))
    if (challenge_headers.get("x-bef-generation") != generation_id
        or failure_headers.get("x-bef-generation") != generation_id):
        return False

    # Both 402s must carry the same complete, decoded and raw payment offer;
    # the signed retry must show that only the EIP-712 domain name differed.
    challenge_offer = _sc006_payment_required_offer(challenge["response"], "Payment required")
    failure_offer = _sc006_payment_required_offer(failure["response"], "No matching payment requirements")
    if (challenge_offer is None or failure_offer is None or challenge_offer != failure_offer
        or not _sc006_offer_matches_manifest(challenge_offer, x402)):
        return False
    signed = _sc006_signed_payload(SimpleNamespace(payload=failure), failure["request"], str(resource))
    if signed is None:
        return False
    accepted, _signature_digest = signed
    domain = _record(x402.get("eip712Domain"))
    expected_extra = {
        "name": domain.get("name"), "version": domain.get("version"),
        "paymentFlow": "authorization", "assetTransferMethod": x402.get("assetTransferMethod"),
    }
    accepted_extra = _record(accepted.get("extra"))
    if (accepted.get("scheme") != challenge_offer.get("scheme")
        or accepted.get("network") != challenge_offer.get("network")
        or _address(accepted.get("asset")) != _address(challenge_offer.get("asset"))
        or accepted.get("amount") != challenge_offer.get("amount")
        or _address(accepted.get("payTo")) != _address(challenge_offer.get("payTo"))
        or accepted.get("maxTimeoutSeconds") != challenge_offer.get("maxTimeoutSeconds")
        or set(accepted_extra) != set(expected_extra)
        or any(accepted_extra.get(key) != value for key, value in expected_extra.items() if key != "name")
        or accepted_extra.get("name") == expected_extra.get("name")
        or _sc006_offer_matches_manifest(accepted, x402)):
        return False
    after = _operation_snapshot(evidence, op_id, variant, "sc002-genuine-protocol-failure-database")
    if after is None:
        return False
    operation, payments = after
    request_hash = _raw_purchase_request_sha256(challenge["request"])
    if (operation.get("status") != "rejected" or operation.get("operation_kind") != "purchase"
        or operation.get("receipt_status") != "not_submitted" or operation.get("transaction_hash")
        or operation.get("request_sha256") != request_hash or payments):
        return False
    generations = [db.get("rows") for artifact, db in _db_payloads(evidence)
                   if db.get("queryName") == "generation-by-id" and db.get("operationId") == op_id
                   and db.get("variantId") == variant and _db_scope(db, env_id, generation_id)
                   and "sc002-genuine-protocol-failure-database" in _path(artifact)
                   and isinstance(db.get("rows"), list)]
    if len(generations) != 1 or len(generations[0]) != 1 or not isinstance(generations[0][0], dict):
        return False
    payer = generations[0][0].get("payer_address")
    if (generations[0][0].get("generation_id") != generation_id
        or str(generations[0][0].get("env_id")) != env_id):
        return False
    pay_to = challenge_offer.get("payTo")
    usdc = x402.get("asset") if isinstance(x402, dict) else None
    if not isinstance(payer, str) or not isinstance(pay_to, str) or not isinstance(usdc, str):
        return False
    all_generation_rows = [row for _, db in _db_payloads(evidence)
                           if db.get("queryName") == "generation-by-id" and db.get("operationId") == op_id
                           and db.get("variantId") == variant and _db_scope(db, env_id, generation_id)
                           and isinstance(db.get("rows"), list)
                           for row in db["rows"] if isinstance(row, dict)]
    if (not all_generation_rows or any(
        row.get("generation_id") != generation_id or row.get("env_id") != env_id
        or _address(row.get("payer_address")) != _address(payer)
        for row in all_generation_rows
    )):
        return False
    signed_payload = _record(failure["request"].get("decodedPaymentPayload"))
    if _address(signed_payload.get("payerAddress")) != _address(payer):
        return False
    payer_before = _balance_rpc(evidence, op_id, variant, "sc002-genuine-protocol-failure-payer-before", payer, usdc)
    payer_after = _balance_rpc(evidence, op_id, variant, "sc002-genuine-protocol-failure-payer-after", payer, usdc)
    pay_to_before = _balance_rpc(evidence, op_id, variant, "sc002-genuine-protocol-failure-payto-before", pay_to, usdc)
    pay_to_after = _balance_rpc(evidence, op_id, variant, "sc002-genuine-protocol-failure-payto-after", pay_to, usdc)
    if payer_before is None or pay_to_before is None or payer_after != payer_before or pay_to_after != pay_to_before:
        return False

    expected_empty = {"payments-by-operation", "deliveries-by-operation", "x402-observations-by-operation"}
    rows_by_query: dict[str, list[dict[str, Any]]] = {}
    for artifact, db in _db_payloads(evidence):
        if (db.get("operationId") != op_id or db.get("variantId") != variant
            or "sc002-genuine-protocol-failure-database" not in _path(artifact)
            or db.get("queryName") not in expected_empty | {"denials-by-generation"}
            or not _db_scope(db, env_id, generation_id) or not isinstance(db.get("rows"), list)):
            continue
        query = db["queryName"]
        if query in rows_by_query:
            return False
        rows_by_query[query] = [row for row in db["rows"] if isinstance(row, dict)]
    if (not expected_empty.issubset(rows_by_query)
        or any(rows_by_query[query] for query in expected_empty)):
        return False
    denials = rows_by_query.get("denials-by-generation")
    operation_denials = [row for row in (denials or []) if row.get("operation_id") == op_id]
    expected_denial_hash = hashlib.sha256(json.dumps(
        {"resourceId": resource, "paymentHeaderPresent": True},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    if (len(operation_denials) != 1
        or operation_denials[0].get("generation_id") != generation_id
        or operation_denials[0].get("reason_code") != "payment_protocol_rejected"
        or operation_denials[0].get("request_sha256") != expected_denial_hash):
        return False
    if any(row.get("operationId") == op_id for _, row in _rpc_payloads(evidence)
           if row.get("method") in {"eth_getTransactionByHash", "eth_getTransactionReceipt"}):
        return False
    return True


def _no_reset_or_repair(evidence: Any) -> bool:
    for payload in _scoped_http(evidence):
        path = str(payload["request"].get("path", "")).lower()
        if "reset" in path and payload["response"].get("status", 0) < 400:
            return False
    for _, payload in _db_payloads(evidence):
        rows = payload.get("rows")
        if isinstance(rows, list) and any(
            isinstance(row, dict) and any(str(key).lower() in {"repair_id", "correction_id", "reset_id"}
                                          for key in row)
            for row in rows):
            return False
    return True


def verify_sc002_strict(evidence: Any) -> dict[str, bool]:
    """Return the SC002 named checks from operation-bound raw evidence."""
    alternate_expected = _offer_expected(evidence, "task-goal-exceeded")
    canonical_expected = _offer_expected(evidence, "canonical")
    alternate_amount = str(alternate_expected.get("amount")) if alternate_expected else ""
    canonical_amount = str(canonical_expected.get("amount")) if canonical_expected else ""
    alternate = _offer_purchase_matches(
        evidence, "task-goal-exceeded", variant_id="different_valid_offer",
        evaluation_variant="expense_exceeds_task_budget_within_hard_bounds", amount_expected=alternate_amount,
    )
    canonical = _canonical_purchase_matches(evidence)
    bound, parameters, actual_mistake = _typed_actions_are_bound(evidence)
    failure = _failure_is_retained(evidence)
    rejected = _variant_rejections_are_preexecution(evidence)
    no_repair = _no_reset_or_repair(evidence)
    return {
        "authenticated_scope": _participant_authentication_and_scope(evidence),
        "observed_reads": _exact_reads(evidence),
        "explicit_choices": alternate and canonical and bound,
        "actual_selected_effect": alternate and canonical,
        "technical_steps_declared": bound,
        "technically_valid_learning_mistake_executed": actual_mistake,
        "selected_parameters_not_repaired": parameters and alternate,
        "no_goal_based_rejection_or_corrective_reset": alternate and actual_mistake and no_repair,
        "actual_effect_vs_task_criteria_recorded": alternate and actual_mistake,
        "protocol_failure_not_silent_correction": failure and rejected,
        "preexecution_variants_rejected": rejected,
    }

