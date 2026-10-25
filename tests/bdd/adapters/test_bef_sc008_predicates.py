from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

MODULE_PATH = Path(__file__).with_name("bef_sc008_predicates.py")
SPEC = importlib.util.spec_from_file_location("bef_sc008_candidate_predicates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PREDICATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREDICATES)

RATE_NUM = "15020514483295716381154243967034954650524622599204"
RATE_DEN = "6277101735386680763835789423207666416102355444464034512896"
POLICY = {
    "baseFeeWei": "1003980019", "priorityFeeWei": "1000000",
    "ethUsdcRateNumerator": RATE_NUM, "ethUsdcRateDenominator": RATE_DEN,
    "rounding": "floor-to-6-decimal-usdc-units", "baseL1Fee": "unmodelled",
    "principalSeparateFromExpense": True,
}
MANIFEST_SHA = "d" * 64
ENV_ID = "bef-a"
GENERATION_ID = "22222222-2222-4222-8222-222222222222"
PARTICIPANT = "0x" + "1" * 40
FACILITATOR = "0x" + "3" * 40
USDC = "0x" + "6" * 40
BLOCK_HASH = "0x" + "b" * 64
PARENT_HASH = "0x" + "c" * 64
OTHER_HASH = "0x" + "e" * 64
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _artifact(payload: dict[str, Any], boundary: str | None = None) -> Any:
    return SimpleNamespace(payload=payload, boundary=boundary or payload.get("boundary"))


def _digest_json(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def _cost_row(operation_id: str, tx_hash: str, payer: str, role: str, status: str,
              *, variant_id: str, selected_asset: str | None, selected_units: str | None,
              observed_units: str | None, payment_amount: str | None = None,
              generation_id: str = GENERATION_ID) -> dict[str, Any]:
    gas, price = 102832, 1004980019
    base_fee, priority_fee = 1003980019, 1000000
    common: dict[str, Any] = {
        "operation_id": operation_id, "env_id": ENV_ID, "generation_id": generation_id,
        "transaction_hash": tx_hash, "payer_address": payer, "payer_role": role,
        "receipt_status": status, "manifest_sha256": MANIFEST_SHA,
        "fee_policy_snapshot": dict(POLICY), "fee_rate_numerator": RATE_NUM,
        "fee_rate_denominator": RATE_DEN, "base_l1_fee_status": "unmodelled",
        "selected_principal_asset": selected_asset, "selected_principal_units": selected_units,
        "observed_principal_units": observed_units,
    }
    if status == "unknown":
        common.update({field: None for field in (
            "transaction_from", "receipt_from", "receipt_block_number", "receipt_block_hash",
            "receipt_block_parent_hash", "block_transaction_senders", "gas_used",
            "effective_gas_price_wei", "gas_cost_wei", "modeled_gas_fee_usdc_units",
            "payer_native_balance_before_wei", "payer_native_balance_before_block_number",
            "payer_native_balance_before_block_hash", "payer_native_balance_after_wei",
            "payer_native_balance_after_block_number", "payer_native_balance_after_block_hash",
            "receipt_evidence_json", "receipt_evidence_sha256",
        )})
        return common
    reverted = status == "reverted"
    value = int(selected_units or "0") if role == "participant" and selected_asset == "ETH" else 0
    tx = {"hash": tx_hash, "from": payer, "blockHash": BLOCK_HASH, "blockNumber": "0x32871b7",
          "type": "0x2", "value": hex(value), "maxFeePerGas": hex(base_fee + priority_fee),
          "maxPriorityFeePerGas": hex(priority_fee)}
    receipt = {
        "transactionHash": tx_hash, "from": payer, "status": "reverted" if reverted else "success",
        "blockHash": BLOCK_HASH, "blockNumber": "0x32871b7", "gasUsed": hex(gas),
        "effectiveGasPrice": hex(price),
    }
    evidence: dict[str, Any] = {
        "transaction": {"hash": tx_hash, "from": payer, "blockHash": BLOCK_HASH, "blockNumber": "52982199",
                        "valueWei": str(value), "maxFeePerGasWei": str(base_fee + priority_fee),
                        "maxPriorityFeePerGasWei": str(priority_fee)},
        "receipt": {"transactionHash": tx_hash, "from": payer,
                    "status": "reverted" if reverted else "success", "blockHash": BLOCK_HASH,
                    "blockNumber": "52982199", "gasUsed": str(gas), "effectiveGasPriceWei": str(price),
                    "blockBaseFeePerGasWei": str(base_fee)},
    }
    senders = [{"hash": tx_hash, "from": payer}]
    evidence["payerBlock"] = {"hash": BLOCK_HASH, "number": "52982199", "parentHash": PARENT_HASH,
                              "transactions": senders}
    evidence["payerNativeBalanceBefore"] = {"blockHash": None, "blockNumber": None, "balanceWei": None}
    evidence["payerNativeBalanceAfter"] = {"blockHash": None, "blockNumber": None, "balanceWei": None}
    common.update({"receipt_block_parent_hash": PARENT_HASH, "block_transaction_senders": senders,
                   "payer_native_balance_before_wei": None, "payer_native_balance_before_block_number": None,
                   "payer_native_balance_before_block_hash": None, "payer_native_balance_after_wei": None,
                   "payer_native_balance_after_block_number": None, "payer_native_balance_after_block_hash": None})
    if role == "facilitator":
        balance_before = 1000000000000000000
        balance_after = balance_before - gas * price
        evidence.update({
            "payerBlock": {"hash": BLOCK_HASH, "number": "52982199", "parentHash": PARENT_HASH, "transactions": senders},
            "payerNativeBalanceBefore": {"blockHash": PARENT_HASH, "blockNumber": "52982198", "balanceWei": str(balance_before)},
            "payerNativeBalanceAfter": {"blockHash": BLOCK_HASH, "blockNumber": "52982199", "balanceWei": str(balance_after)},
        })
        common.update({
            "payer_native_balance_before_wei": str(balance_before),
            "payer_native_balance_before_block_number": "52982198",
            "payer_native_balance_before_block_hash": PARENT_HASH,
            "payer_native_balance_after_wei": str(balance_after),
            "payer_native_balance_after_block_number": "52982199",
            "payer_native_balance_after_block_hash": BLOCK_HASH,
        })
    common.update({
        "transaction_from": payer, "receipt_from": payer, "receipt_block_number": "52982199",
        "receipt_block_hash": BLOCK_HASH, "gas_used": str(gas), "effective_gas_price_wei": str(price),
        "gas_cost_wei": str(gas * price),
        "modeled_gas_fee_usdc_units": str(PREDICATES.modeled_fee_usdc_units(gas, price, RATE_NUM, RATE_DEN)),
        "receipt_evidence_json": evidence, "receipt_evidence_sha256": _digest_json(evidence),
    })
    return common


def _db_payload(operation_id: str, variant_id: str, *, status: str,
                receipt_status: str, tx_hash: str | None, cost: dict[str, Any] | None,
                role: str = "participant", selected_action: dict[str, Any] | None = None,
                payment: dict[str, Any] | None = None,
                generation_id: str = GENERATION_ID) -> dict[str, Any]:
    action_rows = [] if selected_action is None else [{
        "operation_id": operation_id, "env_id": ENV_ID, "generation_id": generation_id,
        "action_kind": selected_action["kind"], "selected_action_json": selected_action,
        "measurement_json": None,
    }]
    return {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
        "queryName": "sc008-cost-operation-proof", "operationId": operation_id,
        "variantId": variant_id, "envId": ENV_ID, "generationId": generation_id,
        "readOnly": True, "databaseRole": "bef_observer", "transactionReadOnly": "on",
        "rows": {
            "operation": [{"operation_id": operation_id, "env_id": ENV_ID,
                           "generation_id": generation_id, "status": status,
                           "receipt_status": receipt_status, "transaction_hash": tx_hash}],
            "generation": [{"env_id": ENV_ID, "generation_id": generation_id,
                            "payer_address": PARTICIPANT}],
            "payment": [] if payment is None else [payment],
            "selectedExecution": action_rows,
            "cost": [] if cost is None else [cost],
        },
    }


def _http(operation_id: str, variant_id: str, status: int) -> dict[str, Any]:
    return {
        "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
        "operationId": operation_id, "variantId": variant_id,
        "request": {"method": "POST", "url": "/tools/selected-execution",
                    "headers": {"X-BEF-Generation": GENERATION_ID}},
        "response": {"status": status},
    }


def _rpc(operation_id: str, variant_id: str, method: str, params: list[Any], result: Any) -> dict[str, Any]:
    return {
        "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
        "operationId": operation_id, "variantId": variant_id, "method": method,
        "request": {"params": params}, "result": result,
    }


def _executed(op_no: int, variant_id: str, role: str = "participant", status: str = "success") -> list[Any]:
    operation_id = f"00000000-0000-4000-8000-{op_no:012d}"
    tx_hash = "0x" + f"{op_no:064x}"
    payer = PARTICIPANT if role == "participant" else FACILITATOR
    action = {"kind": "wrap", "amountWei": "10000000000000000"} if role == "participant" else None
    selected_asset = "ETH" if role == "participant" else None
    selected_units = "10000000000000000" if role == "participant" else None
    observed = selected_units if status == "success" else "0" if role == "participant" else None
    cost = _cost_row(operation_id, tx_hash, payer, role, status, variant_id=variant_id,
                     selected_asset=selected_asset, selected_units=selected_units,
                     observed_units=observed)
    payment = ({"operation_id": operation_id, "env_id": ENV_ID, "generation_id": GENERATION_ID,
                "facilitator_address": FACILITATOR, "transaction_hash": tx_hash, "amount_units": "1000000",
                "payer_address": PARTICIPANT, "network": "eip155:8453", "asset_address": USDC}
               if role == "facilitator" else None)
    payloads: list[Any] = [
        _artifact(_db_payload(operation_id, variant_id,
                              status=("delivered" if role == "facilitator" else "settled") if status == "success" else "reverted",
                              receipt_status=status, tx_hash=tx_hash, cost=cost,
                              role=role, selected_action=action, payment=payment)),
        _artifact(_http(operation_id, variant_id, 200)),
    ]
    value = int(selected_units or "0") if role == "participant" and selected_asset == "ETH" else 0
    tx_to = USDC if role == "facilitator" else "0x" + "4" * 40
    tx = {"hash": tx_hash, "from": payer, "to": tx_to,
          "blockHash": BLOCK_HASH, "blockNumber": "0x32871b7", "input": "0x", "type": "0x2",
          "value": hex(value), "maxFeePerGas": hex(1004980019), "maxPriorityFeePerGas": hex(1000000)}
    service_logs = ([{
        "address": USDC,
        "topics": [TRANSFER_TOPIC, "0x" + "0" * 24 + PARTICIPANT[2:],
                   "0x" + "0" * 24 + FACILITATOR[2:]],
        "data": hex(1000000),
    }] if role == "facilitator" else [])
    receipt = {
        "transactionHash": tx_hash, "from": payer, "to": tx["to"], "blockHash": BLOCK_HASH,
        "blockNumber": "0x32871b7", "status": "0x1" if status == "success" else "0x0",
        "gasUsed": hex(102832), "effectiveGasPrice": hex(1004980019), "logs": service_logs,
    }
    payloads += [
        _artifact(_rpc(operation_id, variant_id, "eth_getTransactionByHash", [tx_hash], tx)),
        _artifact(_rpc(operation_id, variant_id, "eth_getTransactionReceipt", [tx_hash], receipt)),
    ]
    parent_number = "0x32871b6"
    receipt_number = "0x32871b7"
    txs = [tx]
    payloads += [
        _artifact(_rpc(operation_id, variant_id, "eth_getBlockByNumber", [parent_number, False], {
            "hash": PARENT_HASH, "number": parent_number, "parentHash": "0x" + "9" * 64,
            "transactions": [],
        })),
        _artifact(_rpc(operation_id, variant_id, "eth_getBlockByNumber", [receipt_number, True], {
            "hash": BLOCK_HASH, "number": receipt_number, "parentHash": PARENT_HASH,
            "baseFeePerGas": hex(1003980019), "transactions": txs,
        })),
    ]
    if role == "facilitator":
        balance_before = 1000000000000000000
        balance_after = balance_before - 102832 * 1004980019
        participant_native_balance = 500000000000000000
        payloads += [
            _artifact(_rpc(operation_id, variant_id, "eth_getBalance", [FACILITATOR, parent_number], hex(balance_before))),
            _artifact(_rpc(operation_id, variant_id, "eth_getBalance", [FACILITATOR, receipt_number], hex(balance_after))),
            _artifact(_rpc(operation_id, variant_id, "eth_getBalance", [PARTICIPANT, parent_number], hex(participant_native_balance))),
            _artifact(_rpc(operation_id, variant_id, "eth_getBalance", [PARTICIPANT, receipt_number], hex(participant_native_balance))),
        ]
        gas_fee = str(cost["modeled_gas_fee_usdc_units"])
        allocation = {
            "serviceComponent": {
                "assetAddress": USDC, "amountUsdcUnits": "1000000",
                "payerAddress": PARTICIPANT, "recipientAddress": FACILITATOR,
                "transactionHash": tx_hash, "receiptTransferCount": 1,
            },
            "gasComponent": {
                "asset": "ETH", "modeledUsdcUnits": gas_fee,
                "payerAddress": FACILITATOR, "payerRole": "facilitator",
                "transactionHash": tx_hash, "receiptStatus": status,
            },
            "participantExpenseUsdcUnits": "1000000",
            "participantGasFeeUsdcUnits": "0",
            "participantNativeBalanceProof": {
                "payerAddress": PARTICIPANT,
                "beforeBalanceWei": str(participant_native_balance),
                "beforeBlockHash": PARENT_HASH,
                "beforeBlockNumber": "52982198",
                "afterBalanceWei": str(participant_native_balance),
                "afterBlockHash": BLOCK_HASH,
                "afterBlockNumber": "52982199",
                "deltaWei": "0",
            },
            "facilitatorOperatingGasFeeUsdcUnits": gas_fee,
            "countedServiceComponents": 1, "countedGasComponents": 1,
        }
        payloads.append(_artifact({
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "benchmark-environment-transaction-costs",
            "queryName": "sc008-cost-component-allocation",
            "operationId": operation_id, "variantId": variant_id,
            "serviceAmountUnits": "1000000", "modeledGasFeeUsdcUnits": gas_fee,
            "rawReceiptCapturedBySettlementProof": True, "costAllocation": allocation,
        }))
    return payloads


def make_evidence() -> Any:
    artifacts: list[Any] = []
    expected_tables = (
        "bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery",
        "bef_denial", "bef_selected_execution", "bef_selected_execution_event", "bef_transaction_cost",
    )
    artifacts.append(_artifact({
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
        "queryName": "observer-role-effective-privileges", "readOnly": True,
        "databaseRole": "bef_observer",
        "role": {"role_name": "bef_observer", "is_superuser": False, "can_create_db": False,
                 "can_create_role": False, "can_replicate": False, "can_bypass_rls": False,
                 "can_create_in_schema": False, "can_create_in_database": False},
        "rows": [{"table_name": table, "can_select": True, "can_insert": False, "can_update": False,
                  "can_delete": False, "can_truncate": False, "can_references": False, "can_trigger": False}
                 for table in expected_tables],
    }))
    artifacts.extend(_executed(1, "successful_transaction", status="success"))
    artifacts.extend(_executed(2, "reverted_transaction", status="reverted"))
    artifacts.extend(_executed(3, "sponsored_settlement", role="facilitator", status="success"))
    artifacts.extend(_executed(4, "embedded_fee", role="facilitator", status="success"))

    unknown_id = "00000000-0000-4000-8000-000000000005"
    unknown_hash = "0x" + f"{5:064x}"
    unknown_cost = _cost_row(unknown_id, unknown_hash, FACILITATOR, "facilitator", "unknown",
                             variant_id="missing_receipt", selected_asset=None,
                             selected_units=None, observed_units=None)
    unknown_payment = {"operation_id": unknown_id, "env_id": ENV_ID, "generation_id": GENERATION_ID,
                       "facilitator_address": FACILITATOR, "transaction_hash": unknown_hash,
                       "amount_units": "1000000", "payer_address": PARTICIPANT,
                       "network": "eip155:8453", "asset_address": USDC}
    artifacts += [
        _artifact({
            "schemaVersion": "bef-http-observation/v1", "boundary": "facilitator-http",
            "operationId": unknown_id, "variantId": "missing_receipt",
            "request": {"method": "POST", "path": "/internal/admin/sc006/receipt-read-fault/arm",
                        "body": {"operationId": unknown_id, "generationId": GENERATION_ID, "ttlMs": 10_000}},
            "response": {"status": 200, "body": {"operationId": unknown_id,
                        "generationId": GENERATION_ID, "armed": True}},
        }),
        _artifact(_http(unknown_id, "missing_receipt", 502)),
        _artifact(_db_payload(unknown_id, "missing_receipt", status="settlement_unknown",
                              receipt_status="unknown", tx_hash=unknown_hash, cost=unknown_cost,
                              role="facilitator", payment=unknown_payment)),
        _artifact(_rpc(unknown_id, "missing_receipt", "eth_getTransactionByHash", [unknown_hash], {
            "hash": unknown_hash, "from": FACILITATOR, "to": "0x" + "4" * 40,
            "blockHash": BLOCK_HASH, "blockNumber": "0x32871b8", "input": "0xd0e30db0",
        })),
        _artifact({
            "schemaVersion": "bef-http-observation/v1", "boundary": "facilitator-http",
            "operationId": unknown_id, "variantId": "missing_receipt",
            "request": {"method": "GET", "path": f"/internal/admin/sc006/receipt-read-fault/status/{unknown_id}"},
            "response": {"status": 200, "body": {
                "operationId": unknown_id, "generationId": GENERATION_ID, "applied": True,
                "faultedReads": 1, "transactionHash": unknown_hash, "broadcastHashes": [unknown_hash],
            }},
        }),
        _artifact({
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "facilitator-original-receipt-read-fault",
            "queryName": "sc008-original-receipt-read-fault-proof",
            "operationId": unknown_id, "variantId": "missing_receipt",
            "responseStatus": 200, "transactionHash": unknown_hash,
            "applied": True, "faultedReads": 1, "broadcastHashes": [unknown_hash],
        }),
        _artifact({
            "schemaVersion": "bef-http-observation/v1", "boundary": "facilitator-http",
            "operationId": unknown_id, "variantId": "missing_receipt",
            "request": {"method": "POST", "path": "/internal/admin/sc006/receipt-read-fault/restore",
                        "body": {"operationId": unknown_id, "generationId": GENERATION_ID}},
            "response": {"status": 200, "body": {
                "operationId": unknown_id, "generationId": GENERATION_ID, "restored": True,
                "applied": True, "transactionHash": unknown_hash,
            }},
        }),
    ]

    # The same durable cost identity moves from an unknown marker to a
    # receipt-backed final row only after the scoped read fault is restored.
    final_unknown_cost = _cost_row(unknown_id, unknown_hash, FACILITATOR, "facilitator", "success",
                                   variant_id="missing_receipt_reconciled", selected_asset=None,
                                   selected_units=None, observed_units=None, payment_amount="1000000")
    final_unknown_payment = dict(unknown_payment)
    final_proof = _db_payload(unknown_id, "missing_receipt_reconciled", status="settled",
                              receipt_status="success", tx_hash=unknown_hash, cost=final_unknown_cost,
                              role="facilitator", payment=final_unknown_payment)
    final_tx = {"hash": unknown_hash, "from": FACILITATOR, "to": USDC,
                "blockHash": BLOCK_HASH, "blockNumber": "0x32871b7", "input": "0x", "type": "0x2",
                "value": "0x0", "maxFeePerGas": hex(1004980019), "maxPriorityFeePerGas": hex(1000000)}
    final_receipt = {
        "transactionHash": unknown_hash, "from": FACILITATOR, "to": final_tx["to"],
        "blockHash": BLOCK_HASH, "blockNumber": "0x32871b7", "status": "0x1",
        "gasUsed": hex(102832), "effectiveGasPrice": hex(1004980019),
        "logs": [{
            "address": USDC,
            "topics": [TRANSFER_TOPIC, "0x" + "0" * 24 + PARTICIPANT[2:],
                       "0x" + "0" * 24 + FACILITATOR[2:]],
            "data": hex(1000000),
        }],
    }
    final_block = {
        "hash": BLOCK_HASH, "number": "0x32871b7", "parentHash": PARENT_HASH,
        "baseFeePerGas": hex(1003980019), "transactions": [final_tx],
    }
    final_parent = {"hash": PARENT_HASH, "number": "0x32871b6", "parentHash": "0x" + "9" * 64, "transactions": []}
    artifacts += [
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getTransactionByHash", [unknown_hash], final_tx)),
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getTransactionReceipt", [unknown_hash], final_receipt)),
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getBlockByNumber", ["0x32871b7", True], final_block)),
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getBlockByNumber", ["0x32871b6", False], final_parent)),
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getBalance", [FACILITATOR, "0x32871b6"], hex(1000000000000000000))),
        _artifact(_rpc(unknown_id, "missing_receipt_reconciled", "eth_getBalance", [FACILITATOR, "0x32871b7"], hex(1000000000000000000 - 102832 * 1004980019))),
        _artifact({
            "schemaVersion": "bef-http-observation/v1", "boundary": "facilitator-http",
            "operationId": unknown_id, "variantId": "missing_receipt_reconciled",
            "request": {"method": "POST", "path": "/internal/admin/reconcile-original-settlement",
                        "body": {"operationId": unknown_id}},
            "response": {"status": 200, "body": {"accepted": True, "reasonCode": "original_settlement_reconciled"}},
        }),
        _artifact(final_proof),
    ]

    rejected_id = "00000000-0000-4000-8000-000000000006"
    rejection_key = "safe-random-idempotency-key"
    rejection_hash = hashlib.sha256(rejection_key.encode()).hexdigest()
    artifacts += [
        _artifact({
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
            "queryName": "sc008-preexecution-rejection-cost-proof", "operationId": None,
            "variantId": "preexecution_rejection", "envId": ENV_ID, "generationId": GENERATION_ID,
            "idempotencyKeySha256": rejection_hash, "readOnly": True,
            "databaseRole": "bef_observer", "transactionReadOnly": "on",
            "rows": {"operation": [], "cost": []},
        }),
        _artifact({
            "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
            "operationId": None, "variantId": "preexecution_rejection",
            "request": {"method": "POST", "path": f"/tools/{ENV_ID}/wrap",
                        "headers": {"Idempotency-Key": rejection_key, "X-BEF-Generation": GENERATION_ID},
                        "body": {"gasLimit": "1200000"}},
            "response": {"status": 400, "body": {"error": "invalid_request"}},
        }),
        _artifact({
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "actual-tool-http-readonly-database-local-chain-readonly-proxy",
            "operationId": None, "variantId": "preexecution_rejection", "envId": ENV_ID,
            "generationId": GENERATION_ID,
            "httpStatus": 400, "beforeState": {"balance": "0x1"}, "afterState": {"balance": "0x1"},
            "beforeDatabase": {"operations": [], "payments": []}, "afterDatabase": {"operations": [], "payments": []},
            "beforeSelectedExecutionState": [], "afterSelectedExecutionState": [],
        }),
        _artifact({
            "schemaVersion": "bef-resource-observation/v1", "boundary": "benchmark-environment-transaction-costs",
            "scenarioId": "BEF-SC-008", "envId": ENV_ID, "generationId": GENERATION_ID,
            "rejectedRequest": {"variantId": "preexecution_rejection", "idempotencyKeySha256": rejection_hash, "status": 400},
        }),
    ]
    return SimpleNamespace(
        artifacts=tuple(artifacts), environment_id=ENV_ID, generation_id=GENERATION_ID,
        manifest_sha256=MANIFEST_SHA,
        manifest={"feePolicy": dict(POLICY),
                  "x402": {"network": "eip155:8453", "asset": USDC, "amount": "1000000"}},
    )


def test_exact_rational_uses_no_additional_wei_divisor() -> None:
    actual = PREDICATES.modeled_fee_usdc_units("102832", "1004980019", RATE_NUM, RATE_DEN)
    assert actual == 247292
    assert 102832 * 1004980019 * int(RATE_NUM) // (10**18 * int(RATE_DEN)) == 0


def test_strict_join_covers_success_revert_sponsor_unknown_rejection_and_fee_split() -> None:
    result = PREDICATES.verify_sc008_strict(make_evidence())
    assert result == {
        "required_negative_inventory": True,
        "readonly_observer_role": True,
        "pinned_fee_and_raw_receipts": True,
        "actual_payer_roles": True,
        "principal_and_service_separate": True,
        "missing_receipt_is_unknown": True,
        "rejection_has_no_fee": True,
        "base_l1_unmodelled": True,
        "complete": True,
    }


def test_cost_proof_joins_each_operation_generation_to_its_http_header() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    operation_generation = "33333333-3333-4333-8333-333333333333"
    final_probe_generation = "44444444-4444-4444-8444-444444444444"
    evidence.generation_id = final_probe_generation
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-cost-operation-proof"
                 and item.payload.get("operationId") == operation_id)
    proof["generationId"] = operation_generation
    for table in ("operation", "generation", "selectedExecution", "cost"):
        for row in proof["rows"][table]:
            row["generation_id"] = operation_generation
    http = next(item.payload for item in evidence.artifacts
                if item.payload.get("operationId") == operation_id
                and item.payload.get("variantId") == "successful_transaction"
                and item.payload.get("boundary") == "actual-tool-http")
    http["request"]["headers"]["X-BEF-Generation"] = operation_generation

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is True
    assert result["complete"] is True


def test_cost_proof_rejects_coordinated_database_generation_that_conflicts_with_http() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    foreign_generation = "33333333-3333-4333-8333-333333333333"
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-cost-operation-proof"
                 and item.payload.get("operationId") == operation_id)
    proof["generationId"] = foreign_generation
    for table in ("operation", "generation", "selectedExecution", "cost"):
        for row in proof["rows"][table]:
            row["generation_id"] = foreign_generation

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["complete"] is False


def test_cost_proof_rejects_cost_row_generation_mismatch() -> None:
    evidence = make_evidence()
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-cost-operation-proof"
                 and item.payload.get("variantId") == "successful_transaction")
    proof["rows"]["cost"][0]["generation_id"] = "33333333-3333-4333-8333-333333333333"

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["complete"] is False


def test_operation_generation_accepts_multiple_http_requests_when_all_headers_match() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    original = next(item.payload for item in evidence.artifacts
                    if item.payload.get("operationId") == operation_id
                    and item.payload.get("variantId") == "successful_transaction"
                    and item.payload.get("boundary") == "actual-tool-http")
    repeated = json.loads(json.dumps(original))
    repeated["variantId"] = "paid_retry"
    repeated["response"]["status"] = 402
    evidence.artifacts = (*evidence.artifacts, _artifact(repeated))

    assert PREDICATES._operation_generation_matches_http(
        evidence, operation_id, GENERATION_ID,
    ) is True


def test_operation_generation_rejects_foreign_header_among_multiple_http_requests() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    original = next(item.payload for item in evidence.artifacts
                    if item.payload.get("operationId") == operation_id
                    and item.payload.get("variantId") == "successful_transaction"
                    and item.payload.get("boundary") == "actual-tool-http")
    repeated = json.loads(json.dumps(original))
    repeated["variantId"] = "paid_retry"
    repeated["request"]["headers"]["X-BEF-Generation"] = "33333333-3333-4333-8333-333333333333"
    repeated["response"]["status"] = 402
    evidence.artifacts = (*evidence.artifacts, _artifact(repeated))

    assert PREDICATES._operation_generation_matches_http(
        evidence, operation_id, GENERATION_ID,
    ) is False


def test_cost_proof_generation_binding_uses_other_variant_http_for_same_operation() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-cost-operation-proof"
                 and item.payload.get("operationId") == operation_id)
    proof["variantId"] = "canonical_offer"

    assert PREDICATES._cost_proof(evidence, operation_id, "canonical_offer") is not None


def test_cost_proof_rejects_foreign_generation_http_on_other_variant() -> None:
    evidence = make_evidence()
    operation_id = "00000000-0000-4000-8000-000000000001"
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-cost-operation-proof"
                 and item.payload.get("operationId") == operation_id)
    proof["variantId"] = "canonical_offer"
    raw_http = next(item.payload for item in evidence.artifacts
                    if item.payload.get("operationId") == operation_id
                    and item.payload.get("variantId") == "successful_transaction"
                    and item.payload.get("boundary") == "actual-tool-http")
    foreign_http = json.loads(json.dumps(raw_http))
    foreign_http["variantId"] = "paid_retry"
    foreign_http["request"]["headers"]["X-BEF-Generation"] = "33333333-3333-4333-8333-333333333333"
    evidence.artifacts = (*evidence.artifacts, _artifact(foreign_http))

    assert PREDICATES._cost_proof(evidence, operation_id, "canonical_offer") is None


def test_preexecution_rejection_requires_generation_matching_http_and_state_proof() -> None:
    evidence = make_evidence()
    proof = next(item.payload for item in evidence.artifacts
                 if item.payload.get("queryName") == "sc008-preexecution-rejection-cost-proof")
    foreign_generation = "33333333-3333-4333-8333-333333333333"
    proof["generationId"] = foreign_generation
    summary = next(item.payload for item in evidence.artifacts
                   if item.payload.get("boundary") == "benchmark-environment-transaction-costs"
                   and isinstance(item.payload.get("rejectedRequest"), dict))
    summary["generationId"] = foreign_generation
    boundary = next(item.payload for item in evidence.artifacts
                    if item.payload.get("boundary") == "actual-tool-http-readonly-database-local-chain-readonly-proxy"
                    and item.payload.get("variantId") == "preexecution_rejection")
    boundary["generationId"] = foreign_generation

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["rejection_has_no_fee"] is False
    assert result["complete"] is False


def test_preexecution_rejection_ignores_unrelated_cost_summaries() -> None:
    evidence = make_evidence()
    summary = next(item.payload for item in evidence.artifacts
                   if item.payload.get("boundary") == "benchmark-environment-transaction-costs"
                   and isinstance(item.payload.get("rejectedRequest"), dict))
    unrelated = json.loads(json.dumps(summary))
    unrelated["variantId"] = "sponsored_settlement"
    unrelated["generationId"] = "33333333-3333-4333-8333-333333333333"
    unrelated.pop("rejectedRequest")
    evidence.artifacts = (*evidence.artifacts, _artifact(unrelated))

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["rejection_has_no_fee"] is True
    assert result["complete"] is True


def test_conflicting_duplicate_preexecution_rejection_summary_fails_closed() -> None:
    evidence = make_evidence()
    summary = next(item.payload for item in evidence.artifacts
                   if item.payload.get("boundary") == "benchmark-environment-transaction-costs"
                   and isinstance(item.payload.get("rejectedRequest"), dict))
    conflicting = json.loads(json.dumps(summary))
    conflicting["rejectedRequest"]["idempotencyKeySha256"] = "0" * 64
    evidence.artifacts = (*evidence.artifacts, _artifact(conflicting))

    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["rejection_has_no_fee"] is False
    assert result["complete"] is False


def test_unknown_receipt_cost_cannot_be_replaced_with_zero() -> None:
    evidence = make_evidence()
    db = next(item.payload for item in evidence.artifacts
              if item.payload.get("queryName") == "sc008-cost-operation-proof"
              and item.payload.get("variantId") == "missing_receipt")
    db["rows"]["cost"][0]["modeled_gas_fee_usdc_units"] = "0"
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["missing_receipt_is_unknown"] is False
    assert result["complete"] is False


def test_facilitator_cost_needs_raw_same_block_sender_and_historical_balances() -> None:
    evidence = make_evidence()
    sponsor_blocks = [item.payload for item in evidence.artifacts
                      if isinstance(item.payload.get("operationId"), str)
                      and item.payload.get("operationId", "").endswith(("000000000003", "000000000004"))
                      and item.payload.get("method") == "eth_getBlockByNumber"
                      and int(item.payload["request"]["params"][0], 16) == 0x32871B7]
    assert len(sponsor_blocks) == 2
    for block in sponsor_blocks:
        block["result"]["transactions"][0]["from"] = PARTICIPANT
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["actual_payer_roles"] is False
    assert result["complete"] is False


def test_actual_eip1559_fee_fields_must_match_manifest_and_receipt_block() -> None:
    mutations = (
        ("transaction", "maxFeePerGas", hex(1004980020)),
        ("transaction", "maxPriorityFeePerGas", hex(1000001)),
        ("block", "baseFeePerGas", hex(1003980020)),
    )
    for target_kind, field, value in mutations:
        evidence = make_evidence()
        artifacts = list(evidence.artifacts)
        matched = False
        for artifact in artifacts:
            payload = artifact.payload
            if (payload.get("variantId") != "successful_transaction"
                or payload.get("operationId") != "00000000-0000-4000-8000-000000000001"):
                continue
            if target_kind == "transaction" and payload.get("method") == "eth_getTransactionByHash":
                payload["result"][field] = value
                matched = True
            elif target_kind == "block" and payload.get("method") == "eth_getBlockByNumber":
                result_block = payload.get("result", {})
                if result_block.get("number") == "0x32871b7":
                    result_block[field] = value
                    matched = True
        assert matched
        result = PREDICATES.verify_sc008_strict(evidence)
        assert result["pinned_fee_and_raw_receipts"] is False
        assert result["complete"] is False


def test_declining_receipt_block_base_fee_uses_observed_price_and_rejects_tampering() -> None:
    operation_id = "00000000-0000-4000-8000-000000000002"
    variant_id = "reverted_transaction"
    block_base_fee = int(POLICY["baseFeeWei"]) - 100000
    expected_price = block_base_fee + int(POLICY["priorityFeeWei"])

    def apply_observation(evidence: Any, effective_price: int) -> None:
        cost_proof = next(item.payload for item in evidence.artifacts
                          if item.payload.get("queryName") == "sc008-cost-operation-proof"
                          and item.payload.get("operationId") == operation_id)
        cost = cost_proof["rows"]["cost"][0]
        for artifact in evidence.artifacts:
            payload = artifact.payload
            if payload.get("operationId") != operation_id or payload.get("variantId") != variant_id:
                continue
            if payload.get("method") == "eth_getTransactionReceipt":
                payload["result"]["effectiveGasPrice"] = hex(effective_price)
            elif payload.get("method") == "eth_getBlockByNumber":
                block = payload.get("result", {})
                if block.get("number") == "0x32871b7":
                    block["baseFeePerGas"] = hex(block_base_fee)
        gas_used = int(cost["gas_used"])
        receipt_evidence = cost["receipt_evidence_json"]
        cost["effective_gas_price_wei"] = str(effective_price)
        cost["gas_cost_wei"] = str(gas_used * effective_price)
        cost["modeled_gas_fee_usdc_units"] = str(PREDICATES.modeled_fee_usdc_units(
            gas_used, effective_price, RATE_NUM, RATE_DEN,
        ))
        receipt_evidence["receipt"]["effectiveGasPriceWei"] = str(effective_price)
        receipt_evidence["receipt"]["blockBaseFeePerGasWei"] = str(block_base_fee)
        cost["receipt_evidence_sha256"] = _digest_json(receipt_evidence)

    accepted = make_evidence()
    apply_observation(accepted, expected_price)
    result = PREDICATES.verify_sc008_strict(accepted)
    assert result["pinned_fee_and_raw_receipts"] is True
    assert result["complete"] is True

    tampered = make_evidence()
    apply_observation(tampered, expected_price + 1)
    result = PREDICATES.verify_sc008_strict(tampered)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["complete"] is False


def test_duplicate_operation_cost_observation_fails_closed() -> None:
    evidence = make_evidence()
    original = next(item for item in evidence.artifacts
                    if item.payload.get("queryName") == "sc008-cost-operation-proof"
                    and item.payload.get("variantId") == "successful_transaction")
    evidence.artifacts = (*evidence.artifacts, _artifact(dict(original.payload)))
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["complete"] is False


def test_one_conflicting_final_row_is_not_masked_by_other_valid_receipts() -> None:
    evidence = make_evidence()
    db = next(item.payload for item in evidence.artifacts
              if item.payload.get("queryName") == "sc008-cost-operation-proof"
              and item.payload.get("variantId") == "successful_transaction")
    row = db["rows"]["cost"][0]
    row["gas_cost_wei"] = str(int(row["gas_cost_wei"]) + 1)
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["complete"] is False


def test_facilitator_service_amount_cannot_be_folded_into_receipt_gas_cost() -> None:
    evidence = make_evidence()
    db = next(item.payload for item in evidence.artifacts
              if item.payload.get("queryName") == "sc008-cost-operation-proof"
              and item.payload.get("variantId") == "embedded_fee")
    row = db["rows"]["cost"][0]
    row["gas_cost_wei"] = str(int(row["gas_cost_wei"]) + int(db["rows"]["payment"][0]["amount_units"]))
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["pinned_fee_and_raw_receipts"] is False
    assert result["principal_and_service_separate"] is False
    assert result["complete"] is False


def test_embedded_fee_allocation_does_not_charge_facilitator_gas_to_participant_again() -> None:
    evidence = make_evidence()
    allocation = next(item.payload for item in evidence.artifacts
                      if item.payload.get("queryName") == "sc008-cost-component-allocation"
                      and item.payload.get("variantId") == "embedded_fee")
    allocation["costAllocation"]["participantExpenseUsdcUnits"] = str(
        int(allocation["costAllocation"]["serviceComponent"]["amountUsdcUnits"])
        + int(allocation["costAllocation"]["gasComponent"]["modeledUsdcUnits"])
    )
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["principal_and_service_separate"] is False
    assert result["complete"] is False


def test_embedded_fee_zero_participant_gas_requires_unchanged_native_balance() -> None:
    evidence = make_evidence()
    participant_balance = next(item.payload for item in evidence.artifacts
                               if item.payload.get("variantId") == "embedded_fee"
                               and item.payload.get("method") == "eth_getBalance"
                               and item.payload.get("request", {}).get("params", [None])[0] == PARTICIPANT
                               and item.payload.get("request", {}).get("params", [None, None])[1] == "0x32871b7")
    participant_balance["result"] = hex(500000000000000001)
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["principal_and_service_separate"] is False
    assert result["complete"] is False


def test_preexecution_rejection_cannot_be_linked_to_a_receipt_or_cost_row() -> None:
    evidence = make_evidence()
    rejected = next(item.payload for item in evidence.artifacts
                    if item.payload.get("variantId") == "preexecution_rejection"
                    and item.payload.get("queryName") == "sc008-preexecution-rejection-cost-proof")
    rejected["rows"]["cost"].append({"receipt_status": "unknown", "gas_cost_wei": None})
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["rejection_has_no_fee"] is False
    assert result["complete"] is False


def test_unknown_cost_requires_scoped_fault_and_later_original_receipt_reconciliation() -> None:
    evidence = make_evidence()
    evidence.artifacts = tuple(item for item in evidence.artifacts
                               if item.payload.get("queryName") != "sc008-original-receipt-read-fault-proof")
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["missing_receipt_is_unknown"] is False
    assert result["complete"] is False


def test_raw_receipt_is_not_collected_until_unknown_marker_and_fault_proof() -> None:
    evidence = make_evidence()
    unknown = next(item for item in evidence.artifacts
                   if item.payload.get("variantId") == "missing_receipt"
                   and item.payload.get("queryName") == "sc008-cost-operation-proof")
    operation_id = unknown.payload["operationId"]
    raw_receipt = _artifact(_rpc(operation_id, "missing_receipt", "eth_getTransactionReceipt",
                                 [unknown.payload["rows"]["cost"][0]["transaction_hash"]], None))
    evidence.artifacts = evidence.artifacts[:2] + (raw_receipt,) + evidence.artifacts[2:]
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["missing_receipt_is_unknown"] is False
    assert result["complete"] is False


def test_unknown_and_reconciled_rows_must_keep_the_same_payment_and_payer_binding() -> None:
    evidence = make_evidence()
    unknown = next(item.payload for item in evidence.artifacts
                   if item.payload.get("queryName") == "sc008-cost-operation-proof"
                   and item.payload.get("variantId") == "missing_receipt")
    unknown["rows"]["payment"][0]["amount_units"] = "999"
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["missing_receipt_is_unknown"] is False
    assert result["complete"] is False


def test_preexecution_rejection_binds_empty_cost_query_to_hashed_http_key() -> None:
    evidence = make_evidence()
    rejection = next(item.payload for item in evidence.artifacts
                     if item.payload.get("queryName") == "sc008-preexecution-rejection-cost-proof")
    rejection["idempotencyKeySha256"] = "0" * 64
    result = PREDICATES.verify_sc008_strict(evidence)
    assert result["rejection_has_no_fee"] is False
    assert result["complete"] is False
