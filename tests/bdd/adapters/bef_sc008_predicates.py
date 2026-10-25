"""Strict ignored SC-008 predicates for actual receipt-cost evidence.

The candidate evidence contract is intentionally explicit: an observer query
named ``sc008-cost-operation-proof`` returns the durable operation,
generation, optional payment/selected-execution rows, and zero or one cost row
for one operation. Independent local-proxy observations carry the same
operation and variant IDs. Probe labels and aggregate booleans are never proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


SC008_REQUIRED_NEGATIVE_VARIANTS = frozenset({
    "missing_receipt",
    "sponsored_settlement",
    "embedded_fee",
    "preexecution_rejection",
})
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
_COST_QUERY = "sc008-cost-operation-proof"


def _record(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _address(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and _ADDRESS.fullmatch(value) else None


def _hash(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and _HASH.fullmatch(value) else None


def _uint(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            number = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            return None
        return number if number >= 0 else None
    return None


def _uint_text(value: Any) -> str | None:
    parsed = _uint(value)
    return str(parsed) if parsed is not None else None


def _artifacts(evidence: Any) -> list[Any]:
    artifacts = getattr(evidence, "artifacts", None)
    return list(artifacts) if isinstance(artifacts, (list, tuple)) else []


def _payloads(evidence: Any, boundary: str | None = None) -> list[tuple[Any, dict[str, Any]]]:
    result = []
    for artifact in _artifacts(evidence):
        payload = getattr(artifact, "payload", None)
        artifact_boundary = getattr(artifact, "boundary", None)
        if isinstance(payload, dict) and (boundary is None or artifact_boundary == boundary):
            result.append((artifact, payload))
    return result


def _manifest(evidence: Any) -> dict[str, Any]:
    manifest = getattr(evidence, "manifest", None)
    return manifest if isinstance(manifest, dict) else {}


def _policy_is_pinned(evidence: Any) -> bool:
    policy = _manifest(evidence).get("feePolicy")
    if not isinstance(policy, dict):
        return False
    numerator = _uint(policy.get("ethUsdcRateNumerator"))
    denominator = _uint(policy.get("ethUsdcRateDenominator"))
    return bool(
        numerator and denominator
        and _uint(policy.get("baseFeeWei")) is not None
        and _uint(policy.get("priorityFeeWei")) is not None
        and policy.get("rounding") == "floor-to-6-decimal-usdc-units"
        and policy.get("baseL1Fee") == "unmodelled"
        and policy.get("principalSeparateFromExpense") is True
    )


def _observer_role_is_readonly_sc008(evidence: Any) -> bool:
    proofs = [payload for _, payload in _payloads(evidence, "readonly-database")
              if payload.get("schemaVersion") == "bef-db-observation/v1"
              and payload.get("queryName") == "observer-role-effective-privileges"
              and payload.get("readOnly") is True
              and payload.get("databaseRole") == "bef_observer"]
    if len(proofs) != 1:
        return False
    proof = proofs[0]
    role, tables = proof.get("role"), proof.get("rows")
    if (not isinstance(role, dict) or role.get("role_name") != "bef_observer"
        or any(role.get(flag) is not False for flag in (
            "is_superuser", "can_create_db", "can_create_role", "can_replicate",
            "can_bypass_rls", "can_create_in_schema", "can_create_in_database"))
        or not isinstance(tables, list)):
        return False
    expected = {"bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery",
                "bef_denial", "bef_selected_execution", "bef_selected_execution_event", "bef_transaction_cost"}
    observed = set()
    for table in tables:
        if (not isinstance(table, dict) or table.get("can_select") is not True
            or any(table.get(flag) is not False for flag in (
                "can_insert", "can_update", "can_delete", "can_truncate", "can_references", "can_trigger"))):
            return False
        if isinstance(table.get("table_name"), str):
            observed.add(table["table_name"])
    return expected.issubset(observed)


def modeled_fee_usdc_units(gas_used: Any, effective_gas_price_wei: Any,
                           rate_numerator: Any, rate_denominator: Any) -> int | None:
    """Convert using the manifest's USDC-base-units-per-wei rational directly."""
    gas, price = _uint(gas_used), _uint(effective_gas_price_wei)
    numerator, denominator = _uint(rate_numerator), _uint(rate_denominator)
    if None in (gas, price, numerator, denominator) or numerator == 0 or denominator == 0:
        return None
    return gas * price * numerator // denominator


def _rows(payload: dict[str, Any], table: str) -> list[dict[str, Any]] | None:
    value = payload.get("rows")
    if not isinstance(value, dict) or not isinstance(value.get(table), list):
        return None
    if any(not isinstance(row, dict) for row in value[table]):
        return None
    return value[table]


def _cost_proof(evidence: Any, operation_id: str, variant_id: str) -> dict[str, Any] | None:
    matches = [payload for _, payload in _payloads(evidence, "readonly-database")
               if payload.get("schemaVersion") == "bef-db-observation/v1"
               and payload.get("queryName") == _COST_QUERY
               and payload.get("operationId") == operation_id
               and payload.get("variantId") == variant_id]
    if len(matches) != 1:
        return None
    payload = matches[0]
    if (payload.get("readOnly") is not True
        or payload.get("databaseRole") != "bef_observer"
        or payload.get("transactionReadOnly") != "on"
        or payload.get("envId") != getattr(evidence, "environment_id", None)):
        return None
    names = ("operation", "generation", "payment", "selectedExecution", "cost")
    rows = {name: _rows(payload, name) for name in names}
    if any(rows[name] is None for name in names):
        return None
    operation_rows = rows["operation"]
    generation_rows = rows["generation"]
    payment_rows = rows["payment"]
    selected_rows = rows["selectedExecution"]
    cost_rows = rows["cost"]
    assert operation_rows is not None and generation_rows is not None
    assert payment_rows is not None and selected_rows is not None and cost_rows is not None
    if len(operation_rows) != 1 or len(generation_rows) != 1 or len(payment_rows) > 1 or len(selected_rows) > 1 or len(cost_rows) > 1:
        return None
    operation = operation_rows[0]
    generation = generation_rows[0]
    operation_generation_id = operation.get("generation_id")
    if (operation.get("operation_id") != operation_id
        or operation.get("env_id") != getattr(evidence, "environment_id", None)
        or not isinstance(operation_generation_id, str) or not _UUID.fullmatch(operation_generation_id)
        or payload.get("generationId") != operation_generation_id
        or generation.get("env_id") != operation.get("env_id")
        or generation.get("generation_id") != operation_generation_id):
        return None
    for name, optional_rows in (("payment", payment_rows), ("selectedExecution", selected_rows), ("cost", cost_rows)):
        if optional_rows and any(
            row.get("operation_id") != operation_id
            or row.get("env_id") != operation.get("env_id")
            or row.get("generation_id") != operation_generation_id
            for row in optional_rows
        ):
            return None
    if not _operation_generation_matches_http(evidence, operation_id, operation_generation_id):
        return None
    return {
        "payload": payload,
        "operation": operation,
        "generation": generation,
        "payment": payment_rows[0] if payment_rows else None,
        "selectedExecution": selected_rows[0] if selected_rows else None,
        "cost": cost_rows[0] if cost_rows else None,
    }


def _http(evidence: Any, operation_id: str, variant_id: str) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence)
            if payload.get("boundary") in {"actual-tool-http", "participant-http"}
            and payload.get("schemaVersion") == "bef-http-observation/v1"
            and payload.get("operationId") == operation_id
            and payload.get("variantId") == variant_id
            and isinstance(payload.get("request"), dict)
            and isinstance(payload.get("response"), dict)]


def _operation_generation_matches_http(evidence: Any, operation_id: str, generation_id: str) -> bool:
    requests = [payload for _, payload in _payloads(evidence)
                if payload.get("boundary") in {"actual-tool-http", "participant-http"}
                and payload.get("schemaVersion") == "bef-http-observation/v1"
                and payload.get("operationId") == operation_id
                and isinstance(payload.get("request"), dict)
                and isinstance(payload.get("response"), dict)]
    if not requests:
        return False
    for payload in requests:
        request = payload.get("request")
        headers = request.get("headers") if isinstance(request, dict) else None
        if not isinstance(headers, dict):
            return False
        generation_headers = [value for key, value in headers.items()
                              if isinstance(key, str) and key.lower() == "x-bef-generation"]
        if len(generation_headers) != 1 or generation_headers[0] != generation_id:
            return False
    return True


def _rpc(evidence: Any, operation_id: str, variant_id: str, method: str) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence, "local-chain-readonly-proxy")
            if payload.get("endpointBoundary") == "local-chain-readonly-proxy"
            and payload.get("operationId") == operation_id
            and payload.get("variantId") == variant_id
            and payload.get("method") == method]


def _rpc_with_null_operation(evidence: Any, variant_id: str, method: str) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence, "local-chain-readonly-proxy")
            if payload.get("endpointBoundary") == "local-chain-readonly-proxy"
            and payload.get("operationId") is None
            and payload.get("variantId") == variant_id
            and payload.get("method") == method]


def _status(receipt: dict[str, Any]) -> str | None:
    value = receipt.get("status")
    if value in (1, "1", "success", "0x1", "0x01"):
        return "success"
    if value in (0, "0", "reverted", "0x0", "0x00"):
        return "reverted"
    return None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _receipt_evidence_matches(row: dict[str, Any], tx: dict[str, Any], receipt: dict[str, Any], status: str,
                              gas_used: str, price: str, block_base_fee: str) -> bool:
    evidence = _record(row.get("receipt_evidence_json"))
    tx_hash, tx_from = _hash(tx.get("hash")), _address(tx.get("from"))
    block_hash, block_number = _hash(receipt.get("blockHash")), _uint_text(receipt.get("blockNumber"))
    if not evidence or not tx_hash or not tx_from or not block_hash or block_number is None:
        return False
    expected = {
        "transaction": {"hash": tx_hash, "from": tx_from,
                        "blockHash": _hash(tx.get("blockHash")),
                        "blockNumber": _uint_text(tx.get("blockNumber")),
                        "valueWei": _uint_text(tx.get("value")),
                        "maxFeePerGasWei": _uint_text(tx.get("maxFeePerGas")),
                        "maxPriorityFeePerGasWei": _uint_text(tx.get("maxPriorityFeePerGas"))},
        "receipt": {"transactionHash": _hash(receipt.get("transactionHash")), "from": _address(receipt.get("from")),
                    "status": status, "blockHash": block_hash, "blockNumber": block_number,
                    "gasUsed": gas_used, "effectiveGasPriceWei": price,
                    "blockBaseFeePerGasWei": block_base_fee},
    }
    # A facilitator receipt includes additional block and historical-balance evidence;
    # those fields are checked independently by _facilitator_history_matches.
    if any(evidence.get(key) != expected[key] for key in expected):
        return False
    digest = hashlib.sha256(_canonical_json(evidence)).hexdigest()
    return digest == str(row.get("receipt_evidence_sha256", "")).lower()


def _selected_principal(proof: dict[str, Any]) -> tuple[str | None, str | None]:
    execution = proof.get("selectedExecution")
    if not isinstance(execution, dict):
        return None, None
    action = _record(execution.get("selected_action_json"))
    if not action:
        return None, None
    kind = action.get("kind", execution.get("action_kind"))
    if kind in {"wrap", "unwrap"}:
        return ("ETH" if kind == "wrap" else "WETH", _uint_text(action.get("amountWei")))
    if kind == "swap":
        return "WETH", _uint_text(action.get("amountInWei"))
    if kind == "approve":
        return None, "0"
    return None, None


def _request_params(payload: dict[str, Any]) -> list[Any]:
    request = payload.get("request")
    if isinstance(request, dict) and isinstance(request.get("params"), list):
        return request["params"]
    params = payload.get("params")
    return params if isinstance(params, list) else []


def _block_for(evidence: Any, operation_id: str, variant_id: str, number: str) -> dict[str, Any] | None:
    wanted = int(number)
    found = []
    for payload in _rpc(evidence, operation_id, variant_id, "eth_getBlockByNumber"):
        params = _request_params(payload)
        result = _record(payload.get("result"))
        if not params or _uint(params[0]) != wanted or result is None:
            continue
        found.append(result)
    if len(found) == 1:
        return found[0]
    if len(found) < 2:
        return None
    identities = {
        (_hash(item.get("hash")), _uint_text(item.get("number")), _hash(item.get("parentHash")),
         _uint_text(item.get("baseFeePerGas"))) for item in found
    }
    expanded = [item for item in found
                if isinstance(item.get("transactions"), list)
                and all(isinstance(_record(tx), dict) and _hash(_record(tx).get("hash"))
                        and _address(_record(tx).get("from")) for tx in item["transactions"])]
    return expanded[0] if len(identities) == 1 and len(expanded) == 1 else None


def _balance_for(evidence: Any, operation_id: str, variant_id: str, payer: str, number: str) -> int | None:
    wanted = int(number)
    matches = []
    for payload in _rpc(evidence, operation_id, variant_id, "eth_getBalance"):
        params = _request_params(payload)
        if len(params) < 2 or _address(params[0]) != payer or _uint(params[1]) != wanted:
            continue
        result = _uint(payload.get("result"))
        if result is not None:
            matches.append(result)
    return matches[0] if len(matches) == 1 else None


def _facilitator_history_matches(evidence: Any, proof: dict[str, Any], row: dict[str, Any],
                                 operation_id: str, variant_id: str,
                                 tx: dict[str, Any], receipt: dict[str, Any], payer: str) -> bool:
    receipt_number = _uint_text(receipt.get("blockNumber"))
    receipt_hash = _hash(receipt.get("blockHash"))
    if receipt_number is None or int(receipt_number) == 0 or receipt_hash is None:
        return False
    before_number = str(int(receipt_number) - 1)
    before_block = _block_for(evidence, operation_id, variant_id, before_number)
    receipt_block = _block_for(evidence, operation_id, variant_id, receipt_number)
    if not before_block or not receipt_block:
        return False
    before_hash = _hash(before_block.get("hash"))
    if (_hash(receipt_block.get("hash")) != receipt_hash
        or _uint_text(receipt_block.get("number")) != receipt_number
        or _hash(receipt_block.get("parentHash")) != before_hash
        or _uint_text(before_block.get("number")) != before_number):
        return False
    transactions = receipt_block.get("transactions")
    if not isinstance(transactions, list):
        return False
    matching = []
    projected = []
    for item in transactions:
        tx_row = _record(item)
        if tx_row is None:
            # Hash-only transaction lists do not establish a sender.
            return False
        item_hash, item_from = _hash(tx_row.get("hash")), _address(tx_row.get("from"))
        if item_hash is None or item_from is None:
            return False
        projected.append({"hash": item_hash, "from": item_from})
        if item_hash == _hash(tx.get("hash")):
            matching.append(item_from)
    if len(matching) != 1 or matching[0] != payer or len({item["hash"] for item in projected}) != len(projected):
        return False
    before_balance = _balance_for(evidence, operation_id, variant_id, payer, before_number)
    after_balance = _balance_for(evidence, operation_id, variant_id, payer, receipt_number)
    if before_balance is None or after_balance is None:
        return False
    expected_proof = {
        "payerBlock": {"hash": receipt_hash, "number": receipt_number, "parentHash": before_hash,
                       "transactions": projected},
        "payerNativeBalanceBefore": {"blockHash": before_hash, "blockNumber": before_number,
                                      "balanceWei": str(before_balance)},
        "payerNativeBalanceAfter": {"blockHash": receipt_hash, "blockNumber": receipt_number,
                                     "balanceWei": str(after_balance)},
    }
    stored = _record(row.get("receipt_evidence_json"))
    if not stored or any(stored.get(key) != value for key, value in expected_proof.items()):
        return False
    return (
        _uint_text(row.get("receipt_block_number")) == receipt_number
        and _hash(row.get("receipt_block_hash")) == receipt_hash
        and _hash(row.get("receipt_block_parent_hash")) == before_hash
        and _uint_text(row.get("payer_native_balance_before_block_number")) == before_number
        and _hash(row.get("payer_native_balance_before_block_hash")) == before_hash
        and _uint(row.get("payer_native_balance_before_wei")) == before_balance
        and _uint_text(row.get("payer_native_balance_after_block_number")) == receipt_number
        and _hash(row.get("payer_native_balance_after_block_hash")) == receipt_hash
        and _uint(row.get("payer_native_balance_after_wei")) == after_balance
    )


def _embedded_fee_component_allocation_matches(evidence: Any, proof: dict[str, Any],
                                                operation_id: str, variant_id: str,
                                                row: dict[str, Any], tx: dict[str, Any],
                                                receipt: dict[str, Any]) -> bool:
    """Recompute service and gas components from payment, receipt, and cost rows.

    The participant pays the token service amount once. The facilitator is the
    native-gas payer, so that gas is an operating expense and is not added to
    the participant's service expense a second time.
    """
    payment = proof.get("payment")
    if not isinstance(payment, dict) or row.get("payer_role") != "facilitator":
        return False
    service_amount = _uint_text(payment.get("amount_units"))
    gas_fee = _uint_text(row.get("modeled_gas_fee_usdc_units"))
    service_payer = _address(payment.get("payer_address"))
    service_recipient = _address(payment.get("facilitator_address"))
    gas_payer = _address(row.get("payer_address"))
    generation = proof.get("generation")
    participant_payer = _address(generation.get("payer_address")) if isinstance(generation, dict) else None
    asset = _address(payment.get("asset_address"))
    tx_hash = _hash(row.get("transaction_hash"))
    if (service_amount is None or int(service_amount) <= 0 or gas_fee is None
        or service_payer is None or service_recipient is None or gas_payer is None
        or participant_payer is None or service_payer != participant_payer
        or asset is None or tx_hash is None or gas_payer != service_recipient
        or _address(tx.get("from")) != gas_payer
        or _hash(receipt.get("transactionHash")) != tx_hash):
        return False

    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    from_topic = "0x" + "0" * 24 + service_payer[2:]
    to_topic = "0x" + "0" * 24 + service_recipient[2:]
    matching_transfers = []
    logs = receipt.get("logs")
    if not isinstance(logs, list):
        return False
    for log_value in logs:
        log = _record(log_value)
        if log is None:
            continue
        topics = log.get("topics")
        if _address(log.get("address")) != asset or not isinstance(topics, list) or len(topics) < 3:
            continue
        if (str(topics[0]).lower() != transfer_topic
            or str(topics[1]).lower() != from_topic
            or str(topics[2]).lower() != to_topic):
            continue
        amount = _uint(log.get("data"))
        if amount is None:
            return False
        matching_transfers.append(str(amount))
    if matching_transfers != [service_amount]:
        return False
    receipt_number = _uint_text(receipt.get("blockNumber"))
    receipt_block_hash = _hash(receipt.get("blockHash"))
    if receipt_number is None or receipt_block_hash is None or int(receipt_number) == 0:
        return False
    before_number = str(int(receipt_number) - 1)
    participant_before = _balance_for(evidence, operation_id, variant_id, participant_payer, before_number)
    participant_after = _balance_for(evidence, operation_id, variant_id, participant_payer, receipt_number)
    receipt_block = _block_for(evidence, operation_id, variant_id, receipt_number)
    before_block = _block_for(evidence, operation_id, variant_id, before_number)
    if (participant_before is None or participant_after is None or participant_before != participant_after
        or receipt_block is None or before_block is None
        or _hash(receipt_block.get("hash")) != receipt_block_hash
        or _hash(before_block.get("hash")) != _hash(receipt_block.get("parentHash"))):
        return False

    expected_allocation = {
        "serviceComponent": {
            "assetAddress": asset,
            "amountUsdcUnits": service_amount,
            "payerAddress": service_payer,
            "recipientAddress": service_recipient,
            "transactionHash": tx_hash,
            "receiptTransferCount": 1,
        },
        "gasComponent": {
            "asset": "ETH",
            "modeledUsdcUnits": gas_fee,
            "payerAddress": gas_payer,
            "payerRole": "facilitator",
            "transactionHash": tx_hash,
            "receiptStatus": row.get("receipt_status"),
        },
        "participantExpenseUsdcUnits": service_amount,
        "participantGasFeeUsdcUnits": "0",
        "participantNativeBalanceProof": {
            "payerAddress": participant_payer,
            "beforeBalanceWei": str(participant_before),
            "beforeBlockHash": _hash(before_block.get("hash")),
            "beforeBlockNumber": before_number,
            "afterBalanceWei": str(participant_after),
            "afterBlockHash": receipt_block_hash,
            "afterBlockNumber": receipt_number,
            "deltaWei": "0",
        },
        "facilitatorOperatingGasFeeUsdcUnits": gas_fee,
        "countedServiceComponents": 1,
        "countedGasComponents": 1,
    }
    matches = [payload for _, payload in _payloads(evidence, "benchmark-environment-transaction-costs")
               if payload.get("schemaVersion") == "bef-resource-observation/v1"
               and payload.get("queryName") == "sc008-cost-component-allocation"
               and payload.get("operationId") == operation_id
               and payload.get("variantId") == variant_id]
    return (len(matches) == 1 and matches[0].get("costAllocation") == expected_allocation
            and str(matches[0].get("serviceAmountUnits")) == service_amount
            and str(matches[0].get("modeledGasFeeUsdcUnits")) == gas_fee
            and matches[0].get("rawReceiptCapturedBySettlementProof") is True)


def _artifact_position(evidence: Any, predicate: Any) -> int | None:
    matches = []
    for index, artifact in enumerate(_artifacts(evidence)):
        payload = getattr(artifact, "payload", None)
        boundary = getattr(artifact, "boundary", None)
        if isinstance(payload, dict) and predicate(boundary, payload):
            matches.append(index)
    return matches[0] if len(matches) == 1 else None


def _cost_observation_precedes_next_reset(evidence: Any, operation_id: str,
                                          variant_id: str, env_id: str) -> bool:
    operation_positions = []
    for index, artifact in enumerate(_artifacts(evidence)):
        payload = getattr(artifact, "payload", None)
        if (isinstance(payload, dict) and payload.get("operationId") == operation_id
            and payload.get("variantId") == variant_id
            and getattr(artifact, "boundary", None) in {
                "actual-tool-http", "facilitator-http", "readonly-database", "local-chain-readonly-proxy",
            }):
            operation_positions.append(index)
    if not operation_positions:
        return False
    reset_path = f"/internal/admin/environments/{env_id}/reset"
    later_resets = []
    for index, artifact in enumerate(_artifacts(evidence)):
        payload = getattr(artifact, "payload", None)
        request = payload.get("request") if isinstance(payload, dict) else None
        if (isinstance(payload, dict) and getattr(artifact, "boundary", None) == "private-admin-http"
            and isinstance(request, dict) and request.get("method") == "POST"
            and request.get("path") == reset_path and index > min(operation_positions)):
            later_resets.append(index)
    return not later_resets or max(operation_positions) < min(later_resets)


def _receipt_fault_http_matches(evidence: Any, operation_id: str,
                                generation_id: str, transaction_hash: str) -> bool:
    relevant = []
    for index, artifact in enumerate(_artifacts(evidence)):
        payload = getattr(artifact, "payload", None)
        if (not isinstance(payload, dict) or getattr(artifact, "boundary", None) != "facilitator-http"
            or payload.get("schemaVersion") != "bef-http-observation/v1"
            or payload.get("operationId") != operation_id or payload.get("variantId") != "missing_receipt"):
            continue
        request, response = payload.get("request"), payload.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        relevant.append((index, request, response))
    arm = [(i, req, resp) for i, req, resp in relevant
           if req.get("method") == "POST" and isinstance(req.get("path"), str)
           and req["path"].endswith("/internal/admin/sc006/receipt-read-fault/arm")]
    status = [(i, req, resp) for i, req, resp in relevant
              if req.get("method") == "GET" and isinstance(req.get("path"), str)
              and req["path"].endswith(f"/internal/admin/sc006/receipt-read-fault/status/{operation_id}")]
    restore = [(i, req, resp) for i, req, resp in relevant
               if req.get("method") == "POST" and isinstance(req.get("path"), str)
               and req["path"].endswith("/internal/admin/sc006/receipt-read-fault/restore")]
    if len(arm) != 1 or len(status) != 1 or len(restore) != 1:
        return False
    arm_index, arm_request, arm_response = arm[0]
    status_index, _, status_response = status[0]
    restore_index, restore_request, restore_response = restore[0]
    failure_index = _artifact_position(
        evidence, lambda boundary, payload: boundary == "actual-tool-http"
        and payload.get("schemaVersion") == "bef-http-observation/v1"
        and payload.get("operationId") == operation_id and payload.get("variantId") == "missing_receipt"
        and isinstance(payload.get("response"), dict)
        and _uint(payload["response"].get("status")) == 502)
    unknown_index = _artifact_position(
        evidence, lambda boundary, payload: boundary == "readonly-database"
        and payload.get("queryName") == _COST_QUERY
        and payload.get("operationId") == operation_id and payload.get("variantId") == "missing_receipt")
    reconciled_receipt_index = _artifact_position(
        evidence, lambda boundary, payload: boundary == "local-chain-readonly-proxy"
        and payload.get("operationId") == operation_id
        and payload.get("variantId") == "missing_receipt_reconciled"
        and payload.get("method") == "eth_getTransactionReceipt")
    arm_body = arm_request.get("body")
    armed = arm_response.get("body")
    status_body = status_response.get("body")
    restore_body = restore_request.get("body")
    restored = restore_response.get("body")
    if not (isinstance(arm_body, dict) and arm_body.get("operationId") == operation_id
        and arm_body.get("generationId") == generation_id and arm_body.get("ttlMs") == 10_000
        and _uint(arm_response.get("status")) == 200 and isinstance(armed, dict)
        and armed.get("operationId") == operation_id and armed.get("generationId") == generation_id
        and isinstance(status_body, dict) and _uint(status_response.get("status")) == 200
        and status_body.get("operationId") == operation_id and status_body.get("generationId") == generation_id
        and status_body.get("applied") is True and status_body.get("faultedReads") == 1
        and _hash(status_body.get("transactionHash")) == transaction_hash
        and isinstance(status_body.get("broadcastHashes"), list)
        and status_body["broadcastHashes"] == [transaction_hash]
        and isinstance(restore_body, dict) and restore_body.get("operationId") == operation_id
        and restore_body.get("generationId") == generation_id
        and _uint(restore_response.get("status")) == 200 and isinstance(restored, dict)
        and restored.get("operationId") == operation_id and restored.get("generationId") == generation_id
        and restored.get("restored") is True and restored.get("applied") is True
        and _hash(restored.get("transactionHash")) == transaction_hash
        and failure_index is not None and unknown_index is not None and reconciled_receipt_index is not None
        and arm_index < failure_index < unknown_index < status_index < restore_index < reconciled_receipt_index):
        return False
    return True


def _facilitator_reconciliation_matches(evidence: Any, operation_id: str,
                                        transaction_hash: str) -> bool:
    participant_failures = _http(evidence, operation_id, "missing_receipt")
    if len(participant_failures) != 1:
        return False
    failure_response = participant_failures[0].get("response")
    failure_status = _uint(failure_response.get("status")) if isinstance(failure_response, dict) else None
    if failure_status != 502:
        return False
    matches = []
    for _, payload in _payloads(evidence, "facilitator-http"):
        request, response = payload.get("request"), payload.get("response")
        body = request.get("body") if isinstance(request, dict) else None
        result = response.get("body") if isinstance(response, dict) else None
        path = request.get("path") if isinstance(request, dict) else None
        if (payload.get("schemaVersion") == "bef-http-observation/v1"
            and payload.get("operationId") == operation_id
            and payload.get("variantId") == "missing_receipt_reconciled"
            and isinstance(request, dict) and request.get("method") == "POST"
            and isinstance(path, str) and path.endswith("/internal/admin/reconcile-original-settlement")
            and isinstance(body, dict) and body.get("operationId") == operation_id
            and isinstance(response, dict) and _uint(response.get("status")) == 200
            and isinstance(result, dict) and result.get("accepted") is True
            and result.get("reasonCode") == "original_settlement_reconciled"):
            matches.append(payload)
    if len(matches) != 1:
        return False
    return str(transaction_hash).lower() == _hash(transaction_hash)


def _cost_row_matches(evidence: Any, proof: dict[str, Any], operation_id: str,
                      variant_id: str) -> tuple[bool, bool, bool]:
    """Return (receipt math, payer attribution, principal separation)."""
    row, operation, generation, payment = (
        proof.get("cost"), proof["operation"], proof["generation"], proof.get("payment"))
    if not isinstance(row, dict):
        return False, False, False
    tx_hash = _hash(row.get("transaction_hash"))
    payer = _address(row.get("payer_address"))
    manifest_hash = str(getattr(evidence, "manifest_sha256", "")).lower()
    policy = _manifest(evidence).get("feePolicy")
    if (not isinstance(policy, dict) or tx_hash is None or payer is None or row.get("operation_id") != operation_id
        or row.get("env_id") != getattr(evidence, "environment_id", None)
        or row.get("generation_id") != operation.get("generation_id")
        or not isinstance(row.get("manifest_sha256"), str)
        or row.get("manifest_sha256", "").strip().lower() != manifest_hash
        or row.get("fee_policy_snapshot") != policy
        or row.get("fee_rate_numerator") is None
        or str(row.get("fee_rate_numerator")) != str(policy.get("ethUsdcRateNumerator"))
        or str(row.get("fee_rate_denominator")) != str(policy.get("ethUsdcRateDenominator"))
        or row.get("base_l1_fee_status") != "unmodelled"):
        return False, False, False
    if variant_id == "missing_receipt_reconciled":
        if not _facilitator_reconciliation_matches(evidence, operation_id, tx_hash):
            return False, False, False
    else:
        http = _http(evidence, operation_id, variant_id)
        if len(http) != 1:
            return False, False, False
        http_response = http[0].get("response")
        http_status = _uint(http_response.get("status")) if isinstance(http_response, dict) else None
        if http_status is None or not 200 <= http_status < 300:
            return False, False, False
    tx_artifacts = _rpc(evidence, operation_id, variant_id, "eth_getTransactionByHash")
    receipt_artifacts = _rpc(evidence, operation_id, variant_id, "eth_getTransactionReceipt")
    if len(tx_artifacts) != 1 or len(receipt_artifacts) != 1:
        return False, False, False
    if any(_hash(_request_params(item)[0]) != tx_hash for item in (tx_artifacts[0], receipt_artifacts[0])
           if _request_params(item)) or any(not _request_params(item) for item in (tx_artifacts[0], receipt_artifacts[0])):
        return False, False, False
    tx = _record(tx_artifacts[0].get("result"))
    receipt = _record(receipt_artifacts[0].get("result"))
    if tx is None or receipt is None:
        return False, False, False
    status, gas, price = _status(receipt), _uint_text(receipt.get("gasUsed")), _uint_text(receipt.get("effectiveGasPrice"))
    tx_from = _address(tx.get("from"))
    if (status is None or gas is None or price is None or int(gas) <= 0 or int(price) <= 0 or tx_from is None
        or _hash(tx.get("hash")) != tx_hash or _hash(receipt.get("transactionHash")) != tx_hash
        or _address(receipt.get("from")) != tx_from or tx_from != payer
        or _hash(tx.get("blockHash")) != _hash(receipt.get("blockHash"))
        or _uint_text(tx.get("blockNumber")) != _uint_text(receipt.get("blockNumber"))
        or _uint_text(row.get("gas_used")) != gas
        or _uint_text(row.get("effective_gas_price_wei")) != price):
        return False, False, False
    gas_cost = int(gas) * int(price)
    expected_fee = modeled_fee_usdc_units(gas, price, policy.get("ethUsdcRateNumerator"), policy.get("ethUsdcRateDenominator"))
    if (expected_fee is None or _uint(row.get("gas_cost_wei")) != gas_cost
        or _uint(row.get("modeled_gas_fee_usdc_units")) != expected_fee
        or row.get("receipt_status") != status
        or str(operation.get("transaction_hash", "")).lower() != tx_hash):
        return False, False, False
    receipt_number = _uint_text(receipt.get("blockNumber"))
    receipt_block = _block_for(evidence, operation_id, variant_id, receipt_number) if receipt_number is not None else None
    block_base_fee = _uint_text(receipt_block.get("baseFeePerGas")) if receipt_block else None
    tx_max_fee = _uint_text(tx.get("maxFeePerGas"))
    tx_priority_fee = _uint_text(tx.get("maxPriorityFeePerGas"))
    tx_value = _uint_text(tx.get("value"))
    policy_base_fee = _uint(policy.get("baseFeeWei"))
    policy_priority_fee = _uint(policy.get("priorityFeeWei"))
    expected_tx_value = 0
    if row.get("payer_role") == "participant":
        selected_asset, selected_units = _selected_principal(proof)
        if selected_asset == "ETH" and selected_units is not None:
            expected_tx_value = int(selected_units)
    if (block_base_fee is None or policy_base_fee is None or policy_priority_fee is None
        or tx_max_fee is None or tx_priority_fee is None or tx_value is None
        or str(tx.get("type", "")).lower() not in {"0x2", "2"}
        or int(block_base_fee) > policy_base_fee
        or int(tx_priority_fee) != policy_priority_fee
        or int(tx_max_fee) != policy_base_fee + policy_priority_fee
        or int(tx_priority_fee) > int(tx_max_fee)
        or int(tx_value) != expected_tx_value
        or int(price) != min(int(tx_max_fee), int(block_base_fee) + int(tx_priority_fee))):
        return False, False, False
    if not _receipt_evidence_matches(row, tx, receipt, status, gas, price, block_base_fee):
        return False, False, False

    role = row.get("payer_role")
    if role == "participant":
        if (operation.get("receipt_status") != status
            or operation.get("status") != ("settled" if status == "success" else "reverted")):
            return True, False, False
        expected_payer = _address(generation.get("payer_address"))
        payer_ok = expected_payer == payer and not payment
        asset, principal = _selected_principal(proof)
        principal_ok = (
            _uint_text(row.get("selected_principal_units")) == principal
            and row.get("selected_principal_asset") == asset
            and _uint_text(row.get("observed_principal_units")) == (principal if status == "success" else "0")
            and principal is not None
        )
    elif role == "facilitator":
        expected_status = "settled" if variant_id == "missing_receipt_reconciled" else "delivered"
        if (operation.get("status") != expected_status or operation.get("receipt_status") != status):
            return True, False, False
        payer_ok = bool(
            isinstance(payment, dict)
            and _address(payment.get("facilitator_address")) == payer
            and str(payment.get("transaction_hash", "")).lower() == tx_hash
            and _address(payment.get("payer_address")) == _address(generation.get("payer_address"))
            and str(payment.get("network")) == str(_manifest(evidence).get("x402", {}).get("network"))
            and _address(payment.get("asset_address")) == _address(_manifest(evidence).get("x402", {}).get("asset"))
            and _facilitator_history_matches(evidence, proof, row, operation_id, variant_id, tx, receipt, payer)
        )
        expected_service_units = _uint(_manifest(evidence).get("x402", {}).get("amount"))
        principal_ok = (
            row.get("selected_principal_asset") is None
            and row.get("selected_principal_units") is None
            and row.get("observed_principal_units") is None
            and isinstance(payment, dict)
            and expected_service_units is not None
            and _uint(payment.get("amount_units")) == expected_service_units
        )
        if variant_id == "embedded_fee":
            principal_ok = principal_ok and _embedded_fee_component_allocation_matches(
                evidence, proof, operation_id, variant_id, row, tx, receipt,
            )
    else:
        payer_ok = principal_ok = False
    return True, payer_ok, principal_ok


def _unknown_is_null(evidence: Any) -> bool:
    proof = _proof_for_variant(evidence, "missing_receipt")
    if not proof:
        return False
    row, operation = proof.get("cost"), proof["operation"]
    if not isinstance(row, dict):
        return False
    tx_hash = _hash(row.get("transaction_hash"))
    policy = _manifest(evidence).get("feePolicy")
    null_fields = ("gas_used", "effective_gas_price_wei", "gas_cost_wei", "modeled_gas_fee_usdc_units",
                   "transaction_from", "receipt_from", "receipt_block_number", "receipt_block_hash",
                   "receipt_block_parent_hash", "block_transaction_senders",
                   "payer_native_balance_before_wei", "payer_native_balance_before_block_number",
                   "payer_native_balance_before_block_hash", "payer_native_balance_after_wei",
                   "payer_native_balance_after_block_number", "payer_native_balance_after_block_hash",
                   "receipt_evidence_json", "receipt_evidence_sha256")
    if not (isinstance(policy, dict) and tx_hash and row.get("receipt_status") == "unknown"
        and operation.get("status") == "settlement_unknown"
        and operation.get("receipt_status") == "unknown"
        and str(operation.get("transaction_hash", "")).lower() == tx_hash
        and all(row.get(field) is None for field in null_fields)
        and row.get("observed_principal_units") is None
        and row.get("base_l1_fee_status") == "unmodelled"
        and str(row.get("fee_rate_numerator")) == str(_manifest(evidence).get("feePolicy", {}).get("ethUsdcRateNumerator"))
        and str(row.get("fee_rate_denominator")) == str(_manifest(evidence).get("feePolicy", {}).get("ethUsdcRateDenominator"))
        and isinstance(row.get("manifest_sha256"), str)
        and row.get("manifest_sha256", "").strip().lower() == str(getattr(evidence, "manifest_sha256", "")).lower()
        and row.get("fee_policy_snapshot") == policy):
        return False
    operation_id = operation.get("operation_id")
    payment = proof.get("payment")
    if (not isinstance(operation_id, str) or row.get("payer_role") != "facilitator"
        or not isinstance(payment, dict)
        or _address(payment.get("facilitator_address")) != _address(row.get("payer_address"))
        or str(payment.get("transaction_hash", "")).lower() != tx_hash):
        return False
    transactions = _rpc(evidence, operation_id, "missing_receipt", "eth_getTransactionByHash")
    receipts = _rpc(evidence, operation_id, "missing_receipt", "eth_getTransactionReceipt")
    if len(transactions) != 1 or receipts:
        return False
    tx = _record(transactions[0].get("result"))
    if (tx is None or _hash(tx.get("hash")) != tx_hash
        or _hash(_request_params(transactions[0])[0]) != tx_hash
        or _address(tx.get("from")) != _address(row.get("payer_address"))):
        return False
    http = _http(evidence, operation_id, "missing_receipt")
    if len(http) != 1:
        return False
    response = http[0].get("response")
    http_status = _uint(response.get("status")) if isinstance(response, dict) else None
    if http_status != 502:
        return False
    if len(http) != 1:
        return False
    faults = [payload for _, payload in _payloads(evidence, "facilitator-original-receipt-read-fault")
              if payload.get("schemaVersion") == "bef-resource-observation/v1"
              and payload.get("queryName") == "sc008-original-receipt-read-fault-proof"
              and payload.get("operationId") == operation_id
              and payload.get("variantId") == "missing_receipt"]
    if len(faults) != 1:
        return False
    fault = faults[0]
    broadcast_hashes = fault.get("broadcastHashes")
    if not (fault.get("responseStatus") == 200 and fault.get("applied") is True
        and fault.get("faultedReads") == 1
        and _hash(fault.get("transactionHash")) == tx_hash
        and isinstance(broadcast_hashes, list) and len(broadcast_hashes) == 1
        and _hash(broadcast_hashes[0]) == tx_hash):
        return False
    final = _proof_for_variant(evidence, "missing_receipt_reconciled")
    if not final or not isinstance(final.get("cost"), dict):
        return False
    generation_id = str(proof["generation"].get("generation_id", ""))
    if not _receipt_fault_http_matches(evidence, operation_id, generation_id, tx_hash):
        return False
    final_row = final["cost"]
    final_payment = final.get("payment")
    final_generation = final.get("generation")
    if (final_row.get("receipt_status") != "success"
        or _hash(final_row.get("transaction_hash")) != tx_hash
        or _address(final_row.get("payer_address")) != _address(row.get("payer_address"))
        or final_row.get("payer_role") != row.get("payer_role")
        or not isinstance(final_payment, dict)
        or final_payment != payment
        or not isinstance(final_generation, dict)
        or _address(final_generation.get("payer_address")) != _address(proof["generation"].get("payer_address"))
        or final["operation"].get("status") != "settled"
        or final["operation"].get("receipt_status") != "success"):
        return False
    final_receipts = _rpc(evidence, operation_id, "missing_receipt_reconciled", "eth_getTransactionReceipt")
    if len(final_receipts) != 1:
        return False
    final_receipt = _record(final_receipts[0].get("result"))
    if (final_receipt is None or _hash(final_receipt.get("transactionHash")) != tx_hash
        or _status(final_receipt) != "success"):
        return False
    unknown_position = _artifact_position(
        evidence, lambda boundary, payload: boundary == "readonly-database"
        and payload.get("queryName") == _COST_QUERY and payload.get("operationId") == operation_id
        and payload.get("variantId") == "missing_receipt")
    fault_position = _artifact_position(
        evidence, lambda boundary, payload: boundary == "facilitator-original-receipt-read-fault"
        and payload.get("queryName") == "sc008-original-receipt-read-fault-proof"
        and payload.get("operationId") == operation_id)
    receipt_position = _artifact_position(
        evidence, lambda boundary, payload: boundary == "local-chain-readonly-proxy"
        and payload.get("operationId") == operation_id and payload.get("variantId") == "missing_receipt_reconciled"
        and payload.get("method") == "eth_getTransactionReceipt")
    final_position = _artifact_position(
        evidence, lambda boundary, payload: boundary == "readonly-database"
        and payload.get("queryName") == _COST_QUERY and payload.get("operationId") == operation_id
        and payload.get("variantId") == "missing_receipt_reconciled")
    return bool(unknown_position is not None and fault_position is not None and receipt_position is not None
                and final_position is not None
                and unknown_position < fault_position < receipt_position < final_position
                and _cost_observation_precedes_next_reset(evidence, operation_id, "missing_receipt", str(proof["payload"].get("envId", "")))
                and _cost_observation_precedes_next_reset(evidence, operation_id, "missing_receipt_reconciled", str(final["payload"].get("envId", ""))))


def _proof_for_variant(evidence: Any, variant_id: str) -> dict[str, Any] | None:
    candidates = [payload for _, payload in _payloads(evidence, "readonly-database")
                  if payload.get("schemaVersion") == "bef-db-observation/v1"
                  and payload.get("queryName") == _COST_QUERY and payload.get("variantId") == variant_id]
    if len(candidates) != 1:
        return None
    operation_id = candidates[0].get("operationId")
    if not isinstance(operation_id, str):
        return None
    return _cost_proof(evidence, operation_id, variant_id)


def _rejection_has_no_cost(evidence: Any) -> bool:
    proofs = [payload for _, payload in _payloads(evidence, "readonly-database")
              if payload.get("schemaVersion") == "bef-db-observation/v1"
              and payload.get("queryName") == "sc008-preexecution-rejection-cost-proof"
              and payload.get("variantId") == "preexecution_rejection"]
    if len(proofs) != 1:
        return False
    proof = proofs[0]
    rows = proof.get("rows")
    summary_candidates = [payload for _, payload in _payloads(evidence, "benchmark-environment-transaction-costs")
                          if payload.get("schemaVersion") == "bef-resource-observation/v1"
                          and payload.get("scenarioId") == "BEF-SC-008"
                          and payload.get("boundary") == "benchmark-environment-transaction-costs"]
    if (proof.get("readOnly") is not True or proof.get("databaseRole") != "bef_observer"
        or proof.get("transactionReadOnly") != "on"
        or proof.get("envId") != getattr(evidence, "environment_id", None)
        or not isinstance(proof.get("generationId"), str) or not _UUID.fullmatch(proof.get("generationId", ""))
        or proof.get("operationId") is not None
        or not isinstance(proof.get("idempotencyKeySha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", proof.get("idempotencyKeySha256", ""))
        or not isinstance(rows, dict) or rows.get("operation") != [] or rows.get("cost") != []):
        return False
    summary_payloads = [payload for payload in summary_candidates
                        if isinstance(payload.get("rejectedRequest"), dict)
                        and payload["rejectedRequest"].get("variantId") == "preexecution_rejection"]
    if len(summary_payloads) != 1:
        return False
    summary = summary_payloads[0]
    rejection = summary.get("rejectedRequest")
    if (summary.get("envId") != proof.get("envId")
        or summary.get("generationId") != proof.get("generationId")
        or not isinstance(rejection, dict)
        or rejection.get("variantId") != "preexecution_rejection"
        or rejection.get("status") != 400
        or rejection.get("idempotencyKeySha256") != proof.get("idempotencyKeySha256")):
        return False
    http = [payload for _, payload in _payloads(evidence, "actual-tool-http")
            if payload.get("schemaVersion") == "bef-http-observation/v1"
            and payload.get("operationId") is None
            and payload.get("variantId") == "preexecution_rejection"
            and isinstance(payload.get("request"), dict) and isinstance(payload.get("response"), dict)]
    if len(http) != 1:
        return False
    request, response = http[0]["request"], http[0]["response"]
    headers = request.get("headers")
    key = headers.get("Idempotency-Key") if isinstance(headers, dict) else None
    generation_headers = [value for name, value in headers.items()
                          if isinstance(name, str) and name.lower() == "x-bef-generation"] if isinstance(headers, dict) else []
    if (request.get("method") != "POST" or not isinstance(request.get("path"), str)
        or not request["path"].endswith("/wrap") or not isinstance(key, str)
        or len(generation_headers) != 1 or generation_headers[0] != proof.get("generationId")
        or hashlib.sha256(key.encode("utf-8")).hexdigest() != proof.get("idempotencyKeySha256")
        or _uint(response.get("status")) != 400):
        return False
    boundaries = [payload for _, payload in _payloads(evidence, "actual-tool-http-readonly-database-local-chain-readonly-proxy")
                  if payload.get("schemaVersion") == "bef-resource-observation/v1"
                  and payload.get("variantId") == "preexecution_rejection"
                  and payload.get("operationId") is None
                  and payload.get("boundary") == "actual-tool-http-readonly-database-local-chain-readonly-proxy"]
    if len(boundaries) != 1:
        return False
    boundary = boundaries[0]
    return bool(boundary.get("httpStatus") == 400
                and boundary.get("envId") == proof.get("envId")
                and boundary.get("generationId") == proof.get("generationId")
                and boundary.get("beforeState") == boundary.get("afterState")
                and boundary.get("beforeDatabase") == boundary.get("afterDatabase")
                and boundary.get("beforeSelectedExecutionState") == boundary.get("afterSelectedExecutionState")
                and not _rpc_with_null_operation(evidence, "preexecution_rejection", "eth_getTransactionByHash")
                and not _rpc_with_null_operation(evidence, "preexecution_rejection", "eth_getTransactionReceipt"))


def verify_sc008_strict(evidence: Any) -> dict[str, bool]:
    """Recompute SC-008 fee/payer/unknown/rejection gates from raw evidence."""
    variant_ids = {payload.get("variantId") for _, payload in _payloads(evidence)
                   if isinstance(payload.get("variantId"), str)}
    inventory = SC008_REQUIRED_NEGATIVE_VARIANTS.issubset(variant_ids)
    all_final_rows_match = True
    final_row_count = 0
    participant_seen = facilitator_seen = False
    participant_payer_ok = facilitator_payer_ok = True
    participant_principal_ok = facilitator_principal_ok = True
    sponsor_ok = embedded_fee_ok = False
    final_cost_refs: list[tuple[str, str]] = []
    unknown_cost_refs: list[tuple[str, str]] = []
    statuses: set[str] = set()
    proof_artifacts = [payload for _, payload in _payloads(evidence, "readonly-database")
                       if payload.get("schemaVersion") == "bef-db-observation/v1"
                       and payload.get("queryName") == _COST_QUERY]
    unique_operation_variants = {
        (payload.get("operationId"), payload.get("variantId")) for payload in proof_artifacts
    }
    if len(unique_operation_variants) != len(proof_artifacts):
        return {
            "required_negative_inventory": False, "pinned_fee_and_raw_receipts": False,
            "readonly_observer_role": False,
            "actual_payer_roles": False, "principal_and_service_separate": False,
            "missing_receipt_is_unknown": False, "rejection_has_no_fee": False,
            "base_l1_unmodelled": False, "complete": False,
        }
    for db_payload in proof_artifacts:
        op_id, variant_id = db_payload.get("operationId"), db_payload.get("variantId")
        if not isinstance(op_id, str) or not isinstance(variant_id, str):
            all_final_rows_match = False
            break
        proof = _cost_proof(evidence, op_id, variant_id)
        if not proof:
            all_final_rows_match = False
            break
        if not _cost_observation_precedes_next_reset(evidence, op_id, variant_id,
                                                      str(db_payload.get("envId", ""))):
            all_final_rows_match = False
            break
        row = proof.get("cost")
        if row is None:
            continue
        if row.get("receipt_status") == "unknown":
            if variant_id != "missing_receipt":
                all_final_rows_match = False
            unknown_cost_refs.append((op_id, str(row.get("transaction_hash", "")).lower()))
            continue
        if isinstance(row, dict):
            final_cost_refs.append((op_id, str(row.get("transaction_hash", "")).lower()))
        final_row_count += 1
        matched_math, matched_payer, matched_principal = _cost_row_matches(evidence, proof, op_id, variant_id)
        all_final_rows_match = all_final_rows_match and matched_math
        if row.get("payer_role") == "participant":
            participant_seen = True
            participant_payer_ok = participant_payer_ok and matched_payer
            participant_principal_ok = participant_principal_ok and matched_principal
        elif row.get("payer_role") == "facilitator":
            facilitator_seen = True
            facilitator_payer_ok = facilitator_payer_ok and matched_payer
            facilitator_principal_ok = facilitator_principal_ok and matched_principal
        sponsor_ok = sponsor_ok or (variant_id == "sponsored_settlement"
                                    and matched_math and matched_payer and row.get("payer_role") == "facilitator")
        embedded_fee_ok = embedded_fee_ok or (variant_id == "embedded_fee"
                                              and matched_math and matched_payer and matched_principal
                                              and row.get("payer_role") == "facilitator")
        if matched_math:
            status = str(row.get("receipt_status"))
            statuses.add(status)
    final_identities = set(final_cost_refs)
    unique_final_costs = bool(final_cost_refs) and all(_hash(tx_hash) for _, tx_hash in final_cost_refs) \
        and len(final_cost_refs) == len(final_identities) and len({h for _, h in final_cost_refs}) == len(final_cost_refs)
    unknown_transition = len(unknown_cost_refs) == 1 and unknown_cost_refs[0] in final_identities
    unique_cost_identity = unique_final_costs and unknown_transition
    math_ok = final_row_count > 0 and all_final_rows_match
    receipt_statuses = {"success", "reverted"}.issubset(statuses)
    unknown = _unknown_is_null(evidence)
    rejection = _rejection_has_no_cost(evidence)
    payer_ok = participant_seen and participant_payer_ok and facilitator_seen and facilitator_payer_ok
    principal_ok = participant_seen and facilitator_seen and participant_principal_ok \
        and facilitator_principal_ok and embedded_fee_ok
    policy = _manifest(evidence).get("feePolicy")
    has_unmodelled_cost = False
    for db_payload in proof_artifacts:
        op_id, variant_id = db_payload.get("operationId"), db_payload.get("variantId")
        proof = _cost_proof(evidence, op_id, variant_id) if isinstance(op_id, str) and isinstance(variant_id, str) else None
        cost = proof.get("cost") if isinstance(proof, dict) else None
        has_unmodelled_cost = has_unmodelled_cost or (
            isinstance(cost, dict) and cost.get("base_l1_fee_status") == "unmodelled")
    l1 = bool(_policy_is_pinned(evidence) and isinstance(policy, dict)
              and policy.get("baseL1Fee") == "unmodelled" and has_unmodelled_cost)
    observer_role = _observer_role_is_readonly_sc008(evidence)
    complete = bool(inventory and observer_role and _policy_is_pinned(evidence) and math_ok and payer_ok and principal_ok
                    and unique_cost_identity and receipt_statuses and sponsor_ok and embedded_fee_ok
                    and unknown and rejection and l1)
    return {
        "required_negative_inventory": inventory,
        "readonly_observer_role": observer_role,
        "pinned_fee_and_raw_receipts": bool(_policy_is_pinned(evidence) and math_ok and unique_cost_identity and receipt_statuses),
        "actual_payer_roles": payer_ok,
        "principal_and_service_separate": principal_ok,
        "missing_receipt_is_unknown": unknown,
        "rejection_has_no_fee": rejection,
        "base_l1_unmodelled": l1,
        "complete": complete,
    }
