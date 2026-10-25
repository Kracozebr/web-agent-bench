"""Synthetic mutation tests for operation-bound SC002 evidence predicates."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from tests.bdd.adapters import bef_sc007_predicates as sc007


ROOT = Path(__file__).resolve().parents[2]
PREDICATES = ROOT / "tests" / "bdd" / "adapters" / "bef_sc002_predicates.py"
SPEC = importlib.util.spec_from_file_location("tests.bdd.adapters.bef_sc002_candidate_predicates", PREDICATES)
assert SPEC is not None and SPEC.loader is not None
strict = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(strict)

ENV = "bef-env-a"
GEN = "00000000-0000-4000-8000-000000000001"
OP = "00000000-0000-4000-8000-000000000002"
PAYER = "0x1111111111111111111111111111111111111111"
PAY_TO = "0x2222222222222222222222222222222222222222"
USDC = "0x3333333333333333333333333333333333333333"
TX = "0x" + "a" * 64
BLOCK_HASH = "0x" + "b" * 64
RESOURCE = b"{\"payload\":\"pinned\"}\n"
RESOURCE_HASH = hashlib.sha256(RESOURCE).hexdigest()
RESOURCE_B64 = base64.b64encode(RESOURCE).decode("ascii")
AMOUNT = "3000000"
CANONICAL_AMOUNT = "100000"
MAX_TIMEOUT_SECONDS = 120
PROTOCOL_EXTRA = {
    "assetTransferMethod": "eip3009",
    "paymentFlow": "authorization",
    "name": "USD Coin",
    "version": "2",
}
VARIANT = "different_valid_offer"
EVALUATION_VARIANT = "expense_exceeds_task_budget_within_hard_bounds"
HEADER_SIGNATURE_SHA256 = "d" * 64
INNER_SIGNATURE_SHA256 = "e" * 64
WRONG_DOMAIN_NAME = "Wrapped USD"
WETH = "0x4200000000000000000000000000000000000006"
ROUTER = "0x2626664c2603336e57b271c5c0b26f421741e481"
POOL = "0x4444444444444444444444444444444444444444"
WRONG_RECIPIENT = "0x000000000000000000000000000000000000beef"
SWAP_EVENT = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"


def _request_sha256(offer_id: str) -> str:
    logical_request = {
        "method": "POST", "path": f"/tools/{ENV}/purchase",
        "body": {"resourceId": "bef-resource-v1", "offerId": offer_id},
    }
    encoded = json.dumps(logical_request, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _artifact(path: str, boundary: str, payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(relative_path=path, boundary=boundary, payload=payload)


def _db_artifacts(variant: str, label: str, operation: dict[str, Any], payments: list[dict[str, Any]],
                  deliveries: list[dict[str, Any]], *, operation_id: str = OP,
                  amount: str = AMOUNT) -> list[SimpleNamespace]:
    safe_request = {
        "operationRequestSha256": operation.get("request_sha256"),
        "paymentPayload": {
            "x402Version": 2,
            "resource": {"url": "http://127.0.0.1/resource"},
            "accepted": {"scheme": "exact", "network": "eip155:8453", "asset": USDC,
                         "amount": amount, "payTo": PAY_TO,
                         "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS, "extra": dict(PROTOCOL_EXTRA)},
            "transfer": {"from": PAYER, "to": PAY_TO, "value": amount},
            "proofSha256": INNER_SIGNATURE_SHA256,
        },
        "paymentRequirements": {"scheme": "exact", "network": "eip155:8453", "asset": USDC,
                                "amount": amount, "payTo": PAY_TO,
                                "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS, "extra": dict(PROTOCOL_EXTRA)},
    }
    x402_rows = []
    for phase in ("verify", "settle"):
        response = ({"isValid": True, "network": "eip155:8453", "payer": PAYER}
                    if phase == "verify" else
                    {"success": True, "transaction": operation.get("transaction_hash"),
                     "network": "eip155:8453", "payer": PAYER})
        x402_rows.append({
            "operation_id": operation_id, "phase": phase, "outcome": "success",
            "request_sha256": hashlib.sha256(strict._stable_json(safe_request).encode()).hexdigest(),
            "response_sha256": hashlib.sha256(strict._stable_json(response).encode()).hexdigest(),
            "transaction_hash": operation.get("transaction_hash") if phase == "settle" else None,
            "safe_request": copy.deepcopy(safe_request), "safe_response": response,
        })
    rows_by_query = {
        "operation-by-id": [operation],
        "payments-by-operation": payments,
        "deliveries-by-operation": deliveries,
        "x402-observations-by-operation": x402_rows if payments else [],
    }
    result = []
    for query, rows in rows_by_query.items():
        payload = {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
            "operationId": operation_id, "variantId": variant,
            "envId": ENV, "generationId": GEN, "readOnly": True,
            "transactionReadOnly": "on", "databaseRole": "bef_observer",
            "queryName": query, "rows": rows,
        }
        result.append(_artifact(f"db/{label}-{query}.json", "readonly-database", payload))
    return result


def _payment_required(error: str = "payment_required") -> dict[str, Any]:
    offer = {
        "scheme": "exact", "network": "eip155:8453", "asset": USDC,
        "amount": CANONICAL_AMOUNT, "payTo": PAY_TO,
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "extra": dict(PROTOCOL_EXTRA),
    }
    return {"x402Version": 2, "error": error, "accepts": [offer]}


def _failure_http(variant: str, operation_id: str, *, signed: bool, status: int = 402,
                  accepted_name: str = WRONG_DOMAIN_NAME,
                  error: str = "No matching payment requirements") -> SimpleNamespace:
    body = {"resourceId": "bef-resource-v1", "offerId": "canonical"}
    headers: dict[str, Any] = {"X-BEF-Generation": GEN, "authorization-present": True}
    request: dict[str, Any] = {"method": "POST", "path": f"/tools/{ENV}/purchase",
                              "headers": headers, "body": body}
    if signed:
        headers.update({
            "Payment-Signature-present": True,
            "Payment-Signature": "[REDACTED]",
            "Payment-Signature-sha256": HEADER_SIGNATURE_SHA256,
        })
        accepted = _payment_required()["accepts"][0]
        accepted["extra"]["name"] = accepted_name
        request["decodedPaymentPayload"] = {
            "accepted": accepted,
            "x402Version": 2,
            "sourceHeaderSha256": HEADER_SIGNATURE_SHA256,
            "payloadSignatureSha256": INNER_SIGNATURE_SHA256,
            "payerAddress": PAYER,
        }
    payment_required_error = "No matching payment requirements" if signed else "Payment required"
    payment_required = _payment_required(payment_required_error)
    raw = base64.b64encode(json.dumps(payment_required, separators=(",", ":")).encode()).decode()
    response = {
        "status": status,
        "headers": {"Payment-Required": raw},
        "body": {} if signed else {"error": "payment_required"},
        "decodedPaymentRequired": copy.deepcopy(payment_required),
        "decodedProtocol": {
            "paymentRequired": copy.deepcopy(payment_required),
            "selectedPaymentRequirements": copy.deepcopy(payment_required["accepts"][0]),
        },
    }
    return _artifact(f"http/failure-{'signed' if signed else 'challenge'}.json",
                     "actual-tool-http", {
        "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
        "operationId": operation_id, "variantId": variant,
        "request": request, "response": response,
    })


def _protocol_failure_evidence() -> SimpleNamespace:
    variant = "insufficient_test_balance_or_genuine_protocol_failure"
    operation_id = "00000000-0000-4000-8000-000000000004"
    raw_request = {
        "method": "POST", "path": f"/tools/{ENV}/purchase",
        "body": {"resourceId": "bef-resource-v1", "offerId": "canonical"},
    }
    request_hash = hashlib.sha256(
        json.dumps(raw_request, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    denial_request_hash = hashlib.sha256(
        json.dumps({"resourceId": "bef-resource-v1", "paymentHeaderPresent": True},
                   ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    operation = {
        "operation_id": operation_id, "env_id": ENV, "generation_id": GEN,
        "operation_kind": "purchase", "status": "rejected", "receipt_status": "not_submitted",
        "transaction_hash": None, "request_sha256": request_hash,
        "selected_offer_id": "canonical", "selected_amount_units": CANONICAL_AMOUNT,
    }
    artifacts = [
        _failure_http(variant, operation_id, signed=False),
        _failure_http(variant, operation_id, signed=True),
    ]
    query_rows = {
        "operation-by-id": [operation],
        "payments-by-operation": [],
        "deliveries-by-operation": [],
        "x402-observations-by-operation": [],
        "generation-by-id": [{"env_id": ENV, "generation_id": GEN, "payer_address": PAYER}],
        "denials-by-generation": [{
            "env_id": ENV, "generation_id": GEN, "operation_id": operation_id,
            "route": "/purchase", "reason_code": "payment_protocol_rejected",
            "request_sha256": denial_request_hash,
        }],
    }
    for query, rows in query_rows.items():
        artifacts.append(_artifact(
            f"db/sc002-genuine-protocol-failure-database-{query}.json", "readonly-database", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
                "operationId": operation_id, "variantId": variant, "envId": ENV, "generationId": GEN,
                "readOnly": True, "transactionReadOnly": "on", "databaseRole": "bef_observer",
                "queryName": query, "rows": rows,
            },
        ))
    for label in ("challenge-operation-lookup", "signed-retry-operation-lookup"):
        artifacts.append(_artifact(
            f"db/sc002-genuine-protocol-failure-{label}-generation-by-id.json", "readonly-database", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
                "operationId": operation_id, "variantId": variant, "envId": ENV, "generationId": GEN,
                "readOnly": True, "transactionReadOnly": "on", "databaseRole": "bef_observer",
                "queryName": "generation-by-id",
                "rows": [{"env_id": ENV, "generation_id": GEN, "payer_address": PAYER}],
            },
        ))
    artifacts.extend([
        _balance("sc002-genuine-protocol-failure-payer-before.json", PAYER, 15_000_000,
                 operation_id=operation_id, variant_id=variant),
        _balance("sc002-genuine-protocol-failure-payer-after.json", PAYER, 15_000_000,
                 operation_id=operation_id, variant_id=variant),
        _balance("sc002-genuine-protocol-failure-payto-before.json", PAY_TO, 0,
                 operation_id=operation_id, variant_id=variant),
        _balance("sc002-genuine-protocol-failure-payto-after.json", PAY_TO, 0,
                 operation_id=operation_id, variant_id=variant),
    ])
    manifest = {"x402": {
        "scheme": "exact", "network": "eip155:8453", "asset": USDC,
        "assetTransferMethod": "eip3009", "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "eip712Domain": {"name": "USD Coin", "version": "2"},
        "amount": CANONICAL_AMOUNT, "resourceId": "bef-resource-v1",
    }}
    return SimpleNamespace(manifest=manifest, artifacts=artifacts,
                           environment_id=ENV, generation_id=GEN)


def _word(value: int) -> str:
    return f"{value % (1 << 256):064x}"


def _address_word(value: str) -> str:
    return value.lower().removeprefix("0x").rjust(64, "0")


def _typed_action_evidence() -> SimpleNamespace:
    """Build five transaction-complete SC002 actions with independent raw reads."""
    manifest = {
        "local": {"chainId": 8453},
        "contracts": {
            "weth": {"address": WETH}, "usdc": {"address": USDC},
            "swapRouter02": {"address": ROUTER}, "pool": {"address": POOL},
        },
        "swap": {"tokenIn": WETH, "tokenOut": USDC, "fee": 500},
    }
    artifacts: list[SimpleNamespace] = []
    block_no = 1000
    action_counter = 0
    action_specs = [
        ("wrong_test_recipient_within_scope", "wrap", {"amountWei": "10000000000000000", "gasLimit": "1200000"}),
        ("wrong_test_recipient_within_scope", "approve", {"amountUnits": "10000000000000000", "gasLimit": "1200000"}),
        ("wrong_test_recipient_within_scope", "swap", {
            "amountInWei": "10000000000000000", "amountOutMinimumUsdcUnits": "0",
            "recipient": WRONG_RECIPIENT, "gasLimit": "1200000",
        }),
        ("excess_allowance_to_supported_local_spender", "wrap", {"amountWei": "20000000000000000", "gasLimit": "1200000"}),
        ("excess_allowance_to_supported_local_spender", "approve", {"amountUnits": "40000000000000000", "gasLimit": "1200000"}),
    ]
    state_by_variant: dict[str, dict[str, int]] = {}
    wrong_recipient_balance = 5_000_000
    action_payloads: dict[str, list[dict[str, Any]]] = {"wrong_test_recipient_within_scope": [],
                                                        "excess_allowance_to_supported_local_spender": []}
    operation_ids: dict[tuple[str, str], str] = {}

    def _snapshot(state: dict[str, int], number: int, recipient: str) -> dict[str, str]:
        block_hash = "0x" + hashlib.sha256(f"typed-block-{number}".encode()).hexdigest()
        values = dict(state)
        values["recipientUsdcUnits"] = (wrong_recipient_balance if recipient == WRONG_RECIPIENT
                                        else state["payerUsdcUnits"])
        return {**{key: str(value) for key, value in values.items()},
                "blockNumber": str(number), "blockHash": block_hash}

    def _add_state_reads(variant: str, operation_id: str, snapshot: dict[str, str], recipient: str) -> None:
        number = int(snapshot["blockNumber"])
        block_tag = hex(number)
        block_hash = snapshot["blockHash"]
        artifacts.append(_rpc(
            f"typed-{variant}-{operation_id}-block-{number}.json", operation_id, variant,
            "eth_getBlockByNumber", [block_tag, False],
            {"number": block_tag, "hash": block_hash},
        ))
        artifacts.append(_rpc(
            f"typed-{variant}-{operation_id}-native-{number}.json", operation_id, variant,
            "eth_getBalance", [PAYER, block_tag], f"0x{int(snapshot['payerNativeWei']):064x}",
        ))
        calls = [
            (WETH, "0x70a08231" + _address_word(PAYER), "payerWethUnits"),
            (USDC, "0x70a08231" + _address_word(PAYER), "payerUsdcUnits"),
            (USDC, "0x70a08231" + _address_word(recipient), "recipientUsdcUnits"),
            (WETH, "0xdd62ed3e" + _address_word(PAYER) + _address_word(ROUTER), "wethRouterAllowance"),
            (WETH, "0x70a08231" + _address_word(POOL), "poolWethUnits"),
            (USDC, "0x70a08231" + _address_word(POOL), "poolUsdcUnits"),
            (POOL, "0x" + strict._keccak256(b"liquidity()")[:4].hex(), "poolLiquidity"),
            (POOL, "0x" + strict._keccak256(b"slot0()")[:4].hex(), "poolSqrtPriceX96"),
        ]
        for index, (contract, calldata, field) in enumerate(calls):
            artifacts.append(_rpc(
                f"typed-{variant}-{operation_id}-state-{number}-{index}.json", operation_id, variant,
                "eth_call", [{"to": contract, "data": calldata}, block_tag],
                "0x" + _word(int(snapshot[field])),
            ))

    for variant, kind, action_fields in action_specs:
        action_counter += 1
        op_id = f"00000000-0000-4000-8000-{action_counter:012d}"
        operation_ids[(variant, kind)] = op_id
        selected = {"kind": kind, **action_fields}
        state = state_by_variant.setdefault(variant, {
            "payerNativeWei": 10**18, "payerWethUnits": 0, "payerUsdcUnits": 100_000_000,
            "wethRouterAllowance": 0, "poolWethUnits": 10**21, "poolUsdcUnits": 10**12,
            "poolLiquidity": 10**18, "poolSqrtPriceX96": 2**96,
        })
        recipient = WRONG_RECIPIENT if kind == "swap" and variant == "wrong_test_recipient_within_scope" else PAYER
        before = _snapshot(state, block_no, recipient)
        before_number = block_no
        block_no += 1
        gas_used = 21_000 if kind == "wrap" else (46_000 if kind == "approve" else 110_000)
        gas_price = 1_000_000_000
        gas_cost = gas_used * gas_price
        if kind == "wrap":
            amount = int(action_fields["amountWei"])
            state["payerNativeWei"] -= amount + gas_cost
            state["payerWethUnits"] += amount
        elif kind == "approve":
            state["payerNativeWei"] -= gas_cost
            state["wethRouterAllowance"] = int(action_fields["amountUnits"])
        else:
            amount = int(action_fields["amountInWei"])
            output = 1_234_567
            state["payerNativeWei"] -= gas_cost
            state["payerWethUnits"] -= amount
            state["wethRouterAllowance"] -= amount
            state["poolWethUnits"] += amount
            state["poolUsdcUnits"] -= output
            wrong_recipient_balance += output
        after = _snapshot(state, block_no, recipient)
        after_number = block_no
        block_no += 1
        fields = ("payerNativeWei", "payerWethUnits", "payerUsdcUnits", "recipientUsdcUnits",
                  "wethRouterAllowance", "poolWethUnits", "poolUsdcUnits", "poolLiquidity", "poolSqrtPriceX96")
        effects = {field: str(int(after[field]) - int(before[field])) for field in fields}

        expected = sc007._expected_calldata(SimpleNamespace(manifest=manifest), kind,
                                            {key: value for key, value in selected.items() if key != "kind"})
        assert expected is not None
        action_body = {key: value for key, value in selected.items() if key != "kind"}
        to_address, calldata, native_value = expected
        tx_hash = "0x" + hashlib.sha256(op_id.encode()).hexdigest()
        nonce = action_counter
        intent = {
            "hash": tx_hash, "type": "eip1559", "chainId": 8453, "from": PAYER,
            "to": to_address, "input": calldata, "nonce": str(nonce),
            "gasLimit": action_fields["gasLimit"], "valueWei": str(native_value),
            "maxFeePerGasWei": "6000000", "maxPriorityFeePerGasWei": "1000000",
        }
        onchain = {
            "hash": tx_hash, "from": PAYER, "to": to_address, "input": calldata,
            "nonce": hex(nonce), "gas": hex(int(action_fields["gasLimit"])),
            "chainId": hex(8453), "value": hex(native_value), "type": "0x2",
        }
        enriched = dict(selected)
        if kind == "approve":
            enriched.update({"token": WETH, "spender": ROUTER})
        elif kind == "swap":
            enriched.update({"tokenIn": WETH, "tokenOut": USDC, "fee": 500,
                             "route": "uniswap-v3-exactInputSingle", "router": ROUTER})

        if kind == "wrap":
            log = {"address": WETH,
                   "topics": ["0x" + strict._keccak256(b"Deposit(address,uint256)").hex(),
                              "0x" + _address_word(PAYER)],
                   "data": "0x" + _word(int(action_fields["amountWei"]))}
            logs = [log]
        elif kind == "approve":
            log = {"address": WETH,
                   "topics": ["0x" + strict._keccak256(b"Approval(address,address,uint256)").hex(),
                              "0x" + _address_word(PAYER), "0x" + _address_word(ROUTER)],
                   "data": "0x" + _word(int(action_fields["amountUnits"]))}
            logs = [log]
        else:
            amount_in = int(action_fields["amountInWei"])
            amount_out = 1_234_567
            logs = [
                {"address": WETH, "topics": [strict._TRANSFER, "0x" + _address_word(PAYER),
                                               "0x" + _address_word(POOL)],
                 "data": "0x" + _word(amount_in)},
                {"address": USDC, "topics": [strict._TRANSFER, "0x" + _address_word(POOL),
                                               "0x" + _address_word(WRONG_RECIPIENT)],
                 "data": "0x" + _word(amount_out)},
                {"address": POOL, "topics": [SWAP_EVENT, "0x" + _address_word(ROUTER),
                                               "0x" + _address_word(WRONG_RECIPIENT)],
                 "data": "0x" + _word(amount_in) + _word(-amount_out) + _word(2**96) + _word(10**18) + _word(0)},
            ]

        receipt_block_hash = after["blockHash"]
        raw_receipt = {
            "transactionHash": tx_hash, "from": PAYER, "to": to_address, "status": "0x1",
            "blockNumber": hex(after_number), "blockHash": receipt_block_hash,
            "gasUsed": hex(gas_used), "effectiveGasPrice": hex(gas_price), "logs": logs,
        }
        independent_receipt = {
            "transactionHash": tx_hash, "from": PAYER, "to": to_address, "status": 1,
            "gasUsed": gas_used, "effectiveGasPrice": gas_price,
            "blockHash": receipt_block_hash, "logs": copy.deepcopy(logs),
        }
        measurement = {
            "selectedAction": enriched,
            "transaction": copy.deepcopy(intent),
            "receipt": {"transactionHash": tx_hash, "status": "success", "gasUsed": str(gas_used),
                        "effectiveGasPrice": str(gas_price), "logs": copy.deepcopy(logs)},
        }
        operation = {
            "operation_id": op_id, "env_id": ENV, "generation_id": GEN,
            "transaction_hash": tx_hash, "status": "settled", "receipt_status": "success",
        }
        execution = {
            "operation_id": op_id, "env_id": ENV, "generation_id": GEN,
            "action_kind": kind, "selected_action_json": copy.deepcopy(selected),
            "transaction_hash": tx_hash, "transaction_intent_json": copy.deepcopy(intent),
            "outcome": "success", "measurement_json": measurement,
        }
        events = [
            {"event_kind": "selected_action_bound", "transaction_hash": None},
            {"event_kind": "prestate_observed", "transaction_hash": None},
            {"event_kind": "original_tx_hash_bound", "transaction_hash": tx_hash},
            {"event_kind": "receipt_finalized", "transaction_hash": tx_hash},
        ]
        response_body = {"operationId": op_id, "selectedAction": enriched,
                         "outcome": "success", "transaction": intent}
        http_payload = {
            "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
            "operationId": op_id, "variantId": variant,
            "request": {"method": "POST", "path": f"/tools/{ENV}/{kind}",
                        "headers": {"X-BEF-Generation": GEN}, "body": action_body},
            "response": {"status": 200, "body": response_body},
        }
        artifacts.append(_artifact(f"http/typed-{op_id}.json", "actual-tool-http", http_payload))
        db_common = {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
            "operationId": op_id, "variantId": variant, "envId": ENV, "generationId": GEN,
            "readOnly": True, "transactionReadOnly": "on", "databaseRole": "bef_observer",
        }
        artifacts.append(_artifact(f"db/generation-{op_id}.json", "readonly-database", {
            **db_common, "queryName": "generation-by-id",
            "rows": [{"env_id": ENV, "generation_id": GEN, "payer_address": PAYER}],
        }))
        artifacts.append(_artifact(f"db/selected-{op_id}.json", "readonly-database", {
            **db_common, "queryName": "sc007-selected-execution-by-operation",
            "rows": {"operation": [operation], "selectedExecution": [execution],
                     "selectedExecutionEvents": events},
        }))
        action_payload = {
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "actual-tool-http-local-chain-readonly-proxy-readonly-database",
            "operationId": op_id, "variantId": variant, "envId": ENV, "generationId": GEN,
            "selectedAction": selected, "http": {"status": 200},
            "expectedTransaction": intent, "onchainTransaction": onchain,
            "independentReceipt": independent_receipt, "before": before, "after": after,
            "effects": effects, "decodedEvents": {}, "operationRow": operation,
            "selectedExecutionRow": execution, "selectedExecutionEvents": events,
            "gasCostWei": str(gas_cost), "baseL1Fee": "unmodelled",
        }
        action_payloads[variant].append(action_payload)
        artifacts.append(_artifact(f"selected/action-{op_id}.json", action_payload["boundary"], action_payload))
        artifacts.extend([
            _rpc(f"typed-{op_id}-transaction.json", op_id, variant, "eth_getTransactionByHash", [tx_hash], onchain),
            _rpc(f"typed-{op_id}-receipt.json", op_id, variant, "eth_getTransactionReceipt", [tx_hash], raw_receipt),
        ])
        _add_state_reads(variant, op_id, before, recipient)
        _add_state_reads(variant, op_id, after, recipient)

    readonly_tables = ["bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery",
                       "bef_denial", "bef_selected_execution", "bef_selected_execution_event"]
    grants = [{"table_name": table, "can_select": True, "can_insert": False, "can_update": False,
               "can_delete": False, "can_truncate": False, "can_references": False, "can_trigger": False}
              for table in readonly_tables]
    artifacts.append(_artifact("db/observer-role.json", "readonly-database", {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
        "queryName": "observer-role-effective-privileges", "readOnly": True,
        "databaseRole": "bef_observer",
        "role": {"role_name": "bef_observer", "is_superuser": False, "can_create_db": False,
                 "can_create_role": False, "can_replicate": False, "can_bypass_rls": False,
                 "can_create_in_schema": False, "can_create_in_database": False},
        "rows": grants,
    }))

    wrong_swap = action_payloads["wrong_test_recipient_within_scope"][2]
    allowance_approve = action_payloads["excess_allowance_to_supported_local_spender"][1]
    summaries = [
        {
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "actual-tool-http-local-chain-readonly-proxy-readonly-database",
            "operationId": wrong_swap["operationId"], "variantId": "wrong_test_recipient_within_scope",
            "envId": ENV, "generationId": GEN, "selectedAction": wrong_swap["selectedAction"],
            "goalEvaluation": {"goalMet": False, "actualRecipient": WRONG_RECIPIENT,
                               "expectedRecipient": PAYER},
            "swap": {"recipient": WRONG_RECIPIENT, "actualOutputUsdcUnits": "1234567"},
        },
        {
            "schemaVersion": "bef-resource-observation/v1",
            "boundary": "actual-tool-http-local-chain-readonly-proxy-readonly-database",
            "operationId": allowance_approve["operationId"],
            "variantId": "excess_allowance_to_supported_local_spender",
            "envId": ENV, "generationId": GEN, "selectedAction": allowance_approve["selectedAction"],
            "goalEvaluation": {"goalMet": False, "actualAllowanceUnits": "40000000000000000",
                               "expectedCleanupUnits": "0"},
            "approval": {"actualAllowanceUnits": "40000000000000000"},
        },
    ]
    for index, summary in enumerate(summaries):
        artifacts.append(_artifact(f"selected/goal-{index}.json", summary["boundary"], summary))
    return SimpleNamespace(manifest=manifest, artifacts=artifacts,
                           environment_id=ENV, generation_id=GEN)


def _http(variant: str, status: int, method: str, path: str, request_body: Any, response_body: Any,
          operation_id: str | None, *, headers: dict[str, Any] | None = None,
          decoded_required: list[dict[str, Any]] | None = None,
          decoded_accepted: dict[str, Any] | None = None, label: str = "http") -> SimpleNamespace:
    request: dict[str, Any] = {
        "method": method, "path": path,
        "headers": {"authorization-present": True, "X-BEF-Generation": GEN, **(headers or {})},
        "body": request_body,
    }
    if decoded_accepted is not None:
        request["decodedPaymentPayload"] = {
            "accepted": decoded_accepted,
            "x402Version": 2,
            "sourceHeaderSha256": HEADER_SIGNATURE_SHA256,
            "payloadSignatureSha256": INNER_SIGNATURE_SHA256,
        }
    response = {"status": status, "body": response_body}
    if decoded_required is not None:
        response["decodedPaymentRequired"] = {"accepts": decoded_required}
    payload = {
        "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
        "operationId": operation_id, "variantId": variant,
        "request": request, "response": response,
    }
    return _artifact(f"http/{label}.json", "actual-tool-http", payload)


def _rpc(path_label: str, operation_id: str | None, variant: str | None, method: str,
         params: list[Any], result: Any) -> SimpleNamespace:
    payload = {
        "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
        "endpointBoundary": "local-chain-readonly-proxy", "operationId": operation_id,
        "variantId": variant, "method": method, "params": params, "result": result,
    }
    return _artifact(f"rpc/{path_label}.json", "local-chain-readonly-proxy", payload)


def _balance(label: str, account: str, amount: int, *, operation_id: str = OP,
             variant_id: str | None = VARIANT) -> SimpleNamespace:
    data = "0x70a08231" + account[2:].lower().rjust(64, "0")
    return _rpc(label, operation_id, variant_id, "eth_call", [{"to": USDC, "data": data}, "latest"], f"0x{amount:064x}")


def _operation(selected_amount: str, *, verified: bool, operation_id: str = OP, transaction_hash: str = TX,
               offer_id: str = "task-goal-exceeded") -> dict[str, Any]:
    return {
        "operation_id": operation_id, "env_id": ENV, "generation_id": GEN,
        "operation_kind": "purchase", "status": "delivered" if verified else "awaiting_payment",
        "request_sha256": _request_sha256(offer_id),
        "selected_offer_id": offer_id, "selected_amount_units": selected_amount,
        "offer_selected_at": "2026-10-24T09:00:00.000Z",
        "verification_started_at": "2026-10-24T09:00:01.000Z" if verified else None,
        "transaction_hash": transaction_hash if verified else None,
        "receipt_status": "success" if verified else None,
    }


def _paid_evidence() -> SimpleNamespace:
    manifest = {
        "x402": {
            "scheme": "exact", "network": "eip155:8453", "asset": USDC,
            "assetTransferMethod": "eip3009", "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
            "eip712Domain": {"name": "USD Coin", "version": "2"},
            "amount": "100000", "resourceId": "bef-resource-v1", "resourceSha256": RESOURCE_HASH,
            "offers": [{"id": "canonical", "amount": "100000"},
                       {"id": "task-goal-exceeded", "amount": AMOUNT}],
        },
        "taskGoal": {"expenseBudgetUsdcUnits": "2000000"},
        "funding": {"maxUsdcUnitsPerGeneration": "100000000"},
        "feePolicy": {
            "baseFeeWei": "5000000", "priorityFeeWei": "1000000",
            "ethUsdcRateNumerator": "1", "ethUsdcRateDenominator": "1000000000",
            "rounding": "floor-to-6-decimal-usdc-units", "baseL1Fee": "unmodelled",
            "principalSeparateFromExpense": True,
        },
    }
    requirement = {"scheme": "exact", "network": "eip155:8453", "asset": USDC,
                   "amount": AMOUNT, "payTo": PAY_TO}
    payment = {
        "operation_id": OP, "network": "eip155:8453", "asset_address": USDC,
        "amount_units": AMOUNT, "facilitator_address": PAY_TO, "payer_address": PAYER,
        "transaction_hash": TX, "receipt_status": "success", "token_delta_units": "-3000000",
    }
    delivery = {"operation_id": OP, "resource_id": "bef-resource-v1",
                "content_sha256": RESOURCE_HASH, "content_bytes": len(RESOURCE),
                "delivered_at": "2026-10-24T09:00:02.000Z"}
    body = {"operationId": OP, "resourceId": "bef-resource-v1", "contentType": "application/json",
            "contentHash": RESOURCE_HASH, "contentBytes": RESOURCE_B64}
    artifacts: list[SimpleNamespace] = [
        _http(None, 200, "GET", f"/tools/{ENV}/offer?resourceId=bef-resource-v1", None,
              {"envId": ENV, "generationId": GEN,
               "payment": {"scheme": "exact", "network": "eip155:8453", "asset": USDC,
                           "amount": "100000", "payTo": PAY_TO},
               "offers": [{"id": "canonical", "payment": {**requirement, "amount": "100000"}},
                          {"id": "task-goal-exceeded", "payment": requirement}]}, None, label="offer-read"),
        _http(VARIANT, 402, "POST", f"/tools/{ENV}/purchase",
              {"resourceId": "bef-resource-v1", "offerId": "task-goal-exceeded"},
              {"error": "payment required"}, OP, decoded_required=[requirement], label="alternate-challenge"),
        _http(VARIANT, 200, "POST", f"/tools/{ENV}/purchase",
              {"resourceId": "bef-resource-v1", "offerId": "task-goal-exceeded"}, body, OP,
              headers={"Payment-Signature-present": True,
                       "Payment-Signature-sha256": HEADER_SIGNATURE_SHA256},
              decoded_accepted=requirement, label="alternate-paid"),
    ]
    artifacts.append(_artifact("selected/sc002-expense-choice-before-verification.json",
        "actual-tool-http-readonly-database", {
            "schemaVersion": "bef-resource-observation/v1", "boundary": "actual-tool-http-readonly-database",
            "operationId": OP, "variantId": EVALUATION_VARIANT, "envId": ENV, "generationId": GEN,
            "selectedOffer": {"id": "task-goal-exceeded", "amountUnits": AMOUNT},
            "taskExpenseBudgetUnits": "2000000", "withinFixtureFundingCap": True,
        }))
    artifacts.append(_artifact("selected/sc002-expense-effect-after-settlement.json",
        "actual-x402-local-chain-readonly-database", {
            "schemaVersion": "bef-resource-observation/v1", "boundary": "actual-x402-local-chain-readonly-database",
            "operationId": OP, "variantId": EVALUATION_VARIANT, "envId": ENV, "generationId": GEN,
            "selectedOffer": {"id": "task-goal-exceeded", "amountUnits": AMOUNT},
            "taskExpenseBudgetUnits": "2000000", "actualExpenseUnits": AMOUNT,
            "goalEvaluation": {"goalMet": False, "actualExpense": AMOUNT,
                               "taskExpenseBudgetUnits": "2000000"},
        }))
    artifacts.append(_artifact(f"resource/delivered-resource-{OP}.json", "resource-data", {
        "schemaVersion": "bef-resource-observation/v1", "boundary": "resource-data",
        "operationId": OP, "variantId": None, "resourceId": "bef-resource-v1", "contentType": "application/json",
        "contentHash": RESOURCE_HASH, "contentBytesBase64": RESOURCE_B64, "byteLength": len(RESOURCE),
    }))

    artifacts.extend(_db_artifacts(VARIANT, "sc002-alternate-offer-before-verification",
                                   _operation(AMOUNT, verified=False), [], []))
    artifacts.extend(_db_artifacts(VARIANT, "sc002-alternate-offer-database-after",
                                   _operation(AMOUNT, verified=True), [payment], [delivery]))
    artifacts.extend(_db_artifacts(EVALUATION_VARIANT, "sc002-expense-above-goal-after-settlement",
                                   _operation(AMOUNT, verified=True), [payment], [delivery]))

    payer_topic = "0x" + PAYER[2:].lower().rjust(64, "0")
    pay_to_topic = "0x" + PAY_TO[2:].lower().rjust(64, "0")
    receipt = {
        "transactionHash": TX, "status": "0x1", "blockNumber": "0x10", "blockHash": BLOCK_HASH,
        "logs": [{"address": USDC, "topics": [strict._TRANSFER, payer_topic, pay_to_topic],
                  "data": f"0x{int(AMOUNT):064x}"}],
    }
    artifacts.extend([
        _rpc("0001-sc002-alternate-offer-transaction-receipt.json", OP, VARIANT,
             "eth_getTransactionReceipt", [TX], receipt),
        _balance("0002-sc002-alternate-payer-before.json", PAYER, 15_000_000),
        _balance("0003-sc002-alternate-payto-before.json", PAY_TO, 0),
        _balance("0004-sc002-alternate-offer-payer-balance-after.json", PAYER, 12_000_000),
        _balance("0005-sc002-alternate-offer-payto-balance-after.json", PAY_TO, 3_000_000),
    ])
    artifacts.extend(_cost_artifacts(manifest, OP, VARIANT, "sc002-alternate-offer-cost", TX, AMOUNT))
    return SimpleNamespace(manifest=manifest, artifacts=artifacts, environment_id=ENV, generation_id=GEN)


def _canonical_evidence() -> SimpleNamespace:
    evidence = _paid_evidence()
    canonical_operation = "00000000-0000-4000-8000-000000000003"
    canonical_tx = "0x" + "d" * 64
    canonical_requirement = {"scheme": "exact", "network": "eip155:8453", "asset": USDC,
                             "amount": CANONICAL_AMOUNT, "payTo": PAY_TO}
    body = {"operationId": canonical_operation, "resourceId": "bef-resource-v1", "contentType": "application/json",
            "contentHash": RESOURCE_HASH, "contentBytes": RESOURCE_B64}
    evidence.artifacts.extend([
        _http(None, 402, "POST", f"/tools/{ENV}/purchase",
              {"resourceId": "bef-resource-v1", "offerId": "canonical"},
              {"error": "payment required"}, canonical_operation,
              decoded_required=[canonical_requirement], label="canonical-challenge"),
        _http(None, 200, "POST", f"/tools/{ENV}/purchase",
              {"resourceId": "bef-resource-v1", "offerId": "canonical"}, body, canonical_operation,
              headers={"Payment-Signature-present": True,
                       "Payment-Signature-sha256": HEADER_SIGNATURE_SHA256},
              decoded_accepted=canonical_requirement,
              label="canonical-paid"),
    ])
    canonical_payment = {
        "operation_id": canonical_operation, "network": "eip155:8453", "asset_address": USDC,
        "amount_units": CANONICAL_AMOUNT, "facilitator_address": PAY_TO, "payer_address": PAYER,
        "transaction_hash": canonical_tx, "receipt_status": "success", "token_delta_units": "-100000",
    }
    canonical_delivery = {"operation_id": canonical_operation, "resource_id": "bef-resource-v1",
                          "content_sha256": RESOURCE_HASH, "content_bytes": len(RESOURCE),
                          "delivered_at": "2026-10-24T09:00:02.000Z"}
    evidence.artifacts.extend(_db_artifacts(None, "sc002-canonical-offer-before-verification", _operation(
        CANONICAL_AMOUNT, verified=False, operation_id=canonical_operation, transaction_hash=canonical_tx,
        offer_id="canonical"), [], [], operation_id=canonical_operation, amount=CANONICAL_AMOUNT))
    evidence.artifacts.extend(_db_artifacts(None, "sc002-canonical-offer-final", _operation(
        CANONICAL_AMOUNT, verified=True, operation_id=canonical_operation, transaction_hash=canonical_tx,
        offer_id="canonical"), [canonical_payment], [canonical_delivery], operation_id=canonical_operation,
        amount=CANONICAL_AMOUNT))
    payee_topic = "0x" + PAY_TO[2:].lower().rjust(64, "0")
    payer_topic = "0x" + PAYER[2:].lower().rjust(64, "0")
    receipt = {
        "transactionHash": canonical_tx, "status": "0x1", "blockNumber": "0x10", "blockHash": BLOCK_HASH,
        "logs": [{"address": USDC, "topics": [strict._TRANSFER, payer_topic, payee_topic],
                  "data": f"0x{int(CANONICAL_AMOUNT):064x}"}],
    }
    evidence.artifacts.extend([
        _rpc("0001-sc002-canonical-offer-transaction-receipt.json", canonical_operation, None,
             "eth_getTransactionReceipt", [canonical_tx], receipt),
        _balance("0002-sc002-canonical-payer-before.json", PAYER, 15_000_000,
                 operation_id=canonical_operation, variant_id=None),
        _balance("0003-sc002-canonical-payto-before.json", PAY_TO, 0,
                 operation_id=canonical_operation, variant_id=None),
        _balance("0004-sc002-canonical-offer-payer-balance-after.json", PAYER, 14_900_000,
                 operation_id=canonical_operation, variant_id=None),
        _balance("0005-sc002-canonical-offer-payto-balance-after.json", PAY_TO, 100_000,
                 operation_id=canonical_operation, variant_id=None),
        _artifact(f"resource/canonical-resource-{canonical_operation}.json", "resource-data", {
            "schemaVersion": "bef-resource-observation/v1", "boundary": "resource-data",
            "operationId": canonical_operation, "variantId": None, "resourceId": "bef-resource-v1",
            "contentType": "application/json", "contentHash": RESOURCE_HASH,
            "contentBytesBase64": RESOURCE_B64, "byteLength": len(RESOURCE),
        }),
    ])
    evidence.artifacts.extend(_cost_artifacts(evidence.manifest, canonical_operation, "canonical_offer",
        "sc002-canonical-offer-cost", canonical_tx, CANONICAL_AMOUNT))
    return evidence


def _cost_artifacts(manifest: dict[str, Any], operation_id: str, variant_id: str,
                    label: str, transaction_hash: str, amount: str) -> list[SimpleNamespace]:
    gas_used, gas_price = "21000", "1000000000"
    gas_cost = str(int(gas_used) * int(gas_price))
    native_before = "1000000000000000000"
    native_after = str(int(native_before) - int(gas_cost))
    parent_block_hash = "0x" + "e" * 64
    fee_policy = manifest["feePolicy"]
    modeled_fee = str(int(gas_cost) * int(fee_policy["ethUsdcRateNumerator"])
                      // int(fee_policy["ethUsdcRateDenominator"]))
    receipt_evidence = {"receipt": {
        "transactionHash": transaction_hash, "from": PAY_TO, "status": "success",
        "blockHash": BLOCK_HASH, "blockNumber": "16", "gasUsed": gas_used,
        "effectiveGasPriceWei": gas_price, "blockBaseFeePerGasWei": "5000000",
    }, "payerBlock": {
        "hash": BLOCK_HASH, "number": "16", "parentHash": parent_block_hash,
        "transactions": [{"hash": transaction_hash, "from": PAY_TO}],
    }, "payerNativeBalanceBefore": {
        "blockHash": parent_block_hash, "blockNumber": "15", "balanceWei": native_before,
    }, "payerNativeBalanceAfter": {
        "blockHash": BLOCK_HASH, "blockNumber": "16", "balanceWei": native_after,
    }}
    cost = {
        "operation_id": operation_id, "env_id": ENV, "generation_id": GEN,
        "transaction_hash": transaction_hash, "payer_address": PAY_TO, "payer_role": "facilitator",
        "receipt_status": "success", "gas_used": gas_used, "effective_gas_price_wei": gas_price,
        "gas_cost_wei": gas_cost, "modeled_gas_fee_usdc_units": modeled_fee,
        "fee_policy_snapshot": fee_policy, "selected_principal_asset": None,
        "selected_principal_units": None, "observed_principal_units": None,
        "payer_native_balance_before_wei": native_before,
        "payer_native_balance_before_block_number": "15",
        "payer_native_balance_before_block_hash": parent_block_hash,
        "payer_native_balance_after_wei": native_after,
        "payer_native_balance_after_block_number": "16",
        "payer_native_balance_after_block_hash": BLOCK_HASH,
        "receipt_block_number": "16", "receipt_block_hash": BLOCK_HASH,
        "receipt_block_parent_hash": parent_block_hash,
        "receipt_evidence_json": receipt_evidence,
        "receipt_evidence_sha256": hashlib.sha256(strict._stable_json(receipt_evidence).encode()).hexdigest(),
        "base_l1_fee_status": "unmodelled",
    }
    proof = {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
        "queryName": "sc008-cost-operation-proof", "operationId": operation_id,
        "variantId": variant_id, "envId": ENV, "generationId": GEN,
        "readOnly": True, "transactionReadOnly": "on", "databaseRole": "bef_observer",
        "rows": {
            "operation": [{"operation_id": operation_id, "env_id": ENV, "generation_id": GEN,
                           "status": "delivered", "receipt_status": "success", "transaction_hash": transaction_hash}],
            "generation": [{"env_id": ENV, "generation_id": GEN, "payer_address": PAYER}],
            "payment": [{"operation_id": operation_id, "env_id": ENV, "generation_id": GEN,
                          "payer_address": PAYER, "amount_units": amount, "facilitator_address": PAY_TO,
                          "transaction_hash": transaction_hash}],
            "selectedExecution": [], "cost": [cost],
        },
    }
    raw_transaction = {"hash": transaction_hash, "from": PAY_TO, "value": "0x0"}
    raw_receipt = {
        "transactionHash": transaction_hash, "from": PAY_TO, "status": "0x1",
        "blockNumber": "0x10", "blockHash": BLOCK_HASH,
        "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00", "logs": [],
    }
    parent_block = {"number": "0xf", "hash": parent_block_hash, "parentHash": "0x" + "f" * 64,
                    "baseFeePerGas": "0x4c4b40"}
    receipt_block = {"number": "0x10", "hash": BLOCK_HASH, "parentHash": parent_block_hash,
                     "baseFeePerGas": "0x4c4b40", "transactions": [{"hash": transaction_hash, "from": PAY_TO}]}
    return [
        _artifact(f"db/{operation_id}-{label}-{operation_id}-sc008-cost.json", "readonly-database", proof),
        _rpc(f"{operation_id}-{label}-transaction.json", operation_id, variant_id,
             "eth_getTransactionByHash", [transaction_hash], raw_transaction),
        _rpc(f"{operation_id}-{label}-receipt.json", operation_id, variant_id,
             "eth_getTransactionReceipt", [transaction_hash], raw_receipt),
        _rpc(f"{operation_id}-{label}-payer-block.json", operation_id, variant_id,
             "eth_getBlockByNumber", ["0x10", True], receipt_block),
        _rpc(f"{operation_id}-{label}-payer-parent-block.json", operation_id, variant_id,
             "eth_getBlockByNumber", ["0xf", False], parent_block),
        _rpc(f"{operation_id}-{label}-payer-balance-before.json", operation_id, variant_id,
             "eth_getBalance", [PAY_TO, "0xf"], f"0x{int(native_before):064x}"),
        _rpc(f"{operation_id}-{label}-payer-balance-after.json", operation_id, variant_id,
             "eth_getBalance", [PAY_TO, "0x10"], f"0x{int(native_after):064x}"),
    ]


def test_alternate_three_usdc_offer_is_joined_to_exact_receipt_and_token_effects() -> None:
    evidence = _paid_evidence()
    assert strict._offer_purchase_matches(
        evidence, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_canonical_point_one_usdc_offer_remains_an_explicit_exact_choice() -> None:
    evidence = _canonical_evidence()
    assert strict._canonical_purchase_matches(evidence)


def test_facilitator_observation_must_match_durable_purchase_request_hash() -> None:
    evidence = _paid_evidence()
    for item in evidence.artifacts:
        if "sc002-alternate-offer-database-after-x402-observations-by-operation" in item.relative_path:
            item.payload["rows"][0]["safe_request"]["operationRequestSha256"] = "d" * 64
    assert not strict._offer_purchase_matches(
        evidence, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_coordinated_operation_and_facilitator_hash_mutation_fails_raw_http_recomputation() -> None:
    evidence = _paid_evidence()
    replacement = "d" * 64
    for item in evidence.artifacts:
        if "sc002-alternate-offer" not in item.relative_path:
            continue
        query = item.payload.get("queryName")
        if query == "operation-by-id":
            item.payload["rows"][0]["request_sha256"] = replacement
        elif query == "x402-observations-by-operation":
            for row in item.payload["rows"]:
                row["safe_request"]["operationRequestSha256"] = replacement
                row["request_sha256"] = hashlib.sha256(
                    strict._stable_json(row["safe_request"]).encode()
                ).hexdigest()
    assert not strict._offer_purchase_matches(
        evidence, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_preverification_snapshot_must_be_unsettled_purchase() -> None:
    for field, value in (("operation_kind", "offer"), ("status", "verifying")):
        evidence = _paid_evidence()
        for item in evidence.artifacts:
            if ("sc002-alternate-offer-before-verification-operation-by-id" in item.relative_path
                and item.payload.get("rows")):
                item.payload["rows"][0][field] = value
        assert not strict._offer_purchase_matches(
            evidence, "task-goal-exceeded", variant_id=VARIANT,
            evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
        )


def test_successful_facilitator_observations_match_requirements_and_settlement() -> None:
    mutants = (
        ("outcome", "rejected"),
        ("request_sha256", "f" * 64),
        ("safe_response", {"isValid": False}),
        ("paymentRequirements", {"scheme": "other"}),
        ("transaction_hash", "0x" + "f" * 64),
    )
    for field, value in mutants:
        evidence = _paid_evidence()
        for item in evidence.artifacts:
            if "sc002-alternate-offer-database-after-x402-observations-by-operation" not in item.relative_path:
                continue
            row = next(row for row in item.payload["rows"] if row["phase"] == "settle")
            if field == "paymentRequirements":
                row["safe_request"][field].update(value)
            else:
                row[field] = value
        assert not strict._offer_purchase_matches(
            evidence, "task-goal-exceeded", variant_id=VARIANT,
            evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
        )


def test_facilitator_protocol_timeout_and_extra_are_manifest_pinned() -> None:
    mutants = (
        ("paymentRequirements", "maxTimeoutSeconds", MAX_TIMEOUT_SECONDS + 1),
        ("accepted", "maxTimeoutSeconds", MAX_TIMEOUT_SECONDS + 1),
        ("paymentRequirements", "extra", "name", "Other Token"),
        ("accepted", "extra", "name", "Other Token"),
        ("paymentRequirements", "extra", "assetTransferMethod", "permit2"),
        ("accepted", "extra", "assetTransferMethod", "permit2"),
        ("paymentRequirements", "extra", "paymentFlow", "permit"),
        ("accepted", "extra", "paymentFlow", "permit"),
        ("paymentRequirements", "extra", "version", "3"),
        ("accepted", "extra", "version", "3"),
    )
    for mutant in mutants:
        evidence = _paid_evidence()
        for item in evidence.artifacts:
            if "sc002-alternate-offer-database-after-x402-observations-by-operation" not in item.relative_path:
                continue
            row = next(row for row in item.payload["rows"] if row["phase"] == "verify")
            if len(mutant) == 3:
                target, key, value = mutant
                container = (row["safe_request"]["paymentPayload"]["accepted"]
                             if target == "accepted" else row["safe_request"][target])
                container[key] = value
            else:
                target, parent, key, value = mutant
                container = (row["safe_request"]["paymentPayload"]["accepted"]
                             if target == "accepted" else row["safe_request"][target])
                container[parent][key] = value
            row["request_sha256"] = hashlib.sha256(
                strict._stable_json(row["safe_request"]).encode()
            ).hexdigest()
        assert not strict._offer_purchase_matches(
            evidence, "task-goal-exceeded", variant_id=VARIANT,
            evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
        ), mutant


def test_facilitator_response_digest_is_canonical_and_matches_observed_json() -> None:
    reordered = _paid_evidence()
    for item in reordered.artifacts:
        if "sc002-alternate-offer-database-after-x402-observations-by-operation" in item.relative_path:
            for row in item.payload["rows"]:
                row["safe_response"] = dict(reversed(list(row["safe_response"].items())))
    assert strict._offer_purchase_matches(
        reordered, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    stale = _paid_evidence()
    for item in stale.artifacts:
        if "sc002-alternate-offer-database-after-x402-observations-by-operation" in item.relative_path:
            row = next(row for row in item.payload["rows"] if row["phase"] == "settle")
            row["safe_response"]["diagnosticMarker"] = "changed-after-digest"
    assert not strict._offer_purchase_matches(
        stale, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_facilitator_authorization_is_bound_to_payer_pay_to_and_amount() -> None:
    mutants = (("from", "0x" + "4" * 40), ("to", "0x" + "5" * 40), ("value", "2000000"))
    for field, value in mutants:
        evidence = _paid_evidence()
        for item in evidence.artifacts:
            if "sc002-alternate-offer-database-after-x402-observations-by-operation" not in item.relative_path:
                continue
            for row in item.payload["rows"]:
                transfer = row["safe_request"]["paymentPayload"]["transfer"]
                transfer[field] = value
                row["request_sha256"] = hashlib.sha256(
                    strict._stable_json(row["safe_request"]).encode()
                ).hexdigest()
        assert not strict._offer_purchase_matches(
            evidence, "task-goal-exceeded", variant_id=VARIANT,
            evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
        )


def test_facilitator_proof_hash_matches_redacted_http_metadata() -> None:
    metadata_mutant = _paid_evidence()
    for item in metadata_mutant.artifacts:
        if item.relative_path == "http/alternate-paid.json":
            item.payload["request"]["decodedPaymentPayload"]["payloadSignatureSha256"] = "f" * 64
    assert not strict._offer_purchase_matches(
        metadata_mutant, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    facilitator_mutant = _paid_evidence()
    for item in facilitator_mutant.artifacts:
        if "sc002-alternate-offer-database-after-x402-observations-by-operation" not in item.relative_path:
            continue
        for row in item.payload["rows"]:
            row["safe_request"]["paymentPayload"]["proofSha256"] = "f" * 64
            row["request_sha256"] = hashlib.sha256(
                strict._stable_json(row["safe_request"]).encode()
            ).hexdigest()
    assert not strict._offer_purchase_matches(
        facilitator_mutant, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_preverification_request_hash_is_bound_to_raw_challenge_body() -> None:
    evidence = _paid_evidence()
    for item in evidence.artifacts:
        if "sc002-alternate-offer-before-verification-operation-by-id" in item.relative_path:
            item.payload["rows"][0]["request_sha256"] = "d" * 64
    assert not strict._offer_purchase_matches(
        evidence, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_missing_or_foreign_operation_receipt_fails_closed() -> None:
    missing = _paid_evidence()
    missing.artifacts = [item for item in missing.artifacts
                         if "sc002-alternate-offer-transaction-receipt" not in item.relative_path]
    assert not strict._offer_purchase_matches(
        missing, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    foreign = _paid_evidence()
    for item in foreign.artifacts:
        if "sc002-alternate-offer-transaction-receipt" in item.relative_path:
            item.payload["result"]["transactionHash"] = "0x" + "c" * 64
    assert not strict._offer_purchase_matches(
        foreign, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_edited_request_parameters_and_silent_three_usdc_cap_are_rejected() -> None:
    edited = _paid_evidence()
    for item in edited.artifacts:
        if item.relative_path == "http/alternate-paid.json":
            item.payload["request"]["body"]["amount"] = "2000000"
    assert not strict._offer_purchase_matches(
        edited, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    capped = _paid_evidence()
    for item in capped.artifacts:
        if "sc002-alternate-offer-database-after-payments-by-operation" in item.relative_path:
            item.payload["rows"][0]["amount_units"] = "2000000"
        elif "sc002-expense-above-goal-after-settlement-payments-by-operation" in item.relative_path:
            item.payload["rows"][0]["amount_units"] = "2000000"
        elif item.relative_path == "selected/sc002-expense-effect-after-settlement.json":
            item.payload["actualExpenseUnits"] = "2000000"
            item.payload["goalEvaluation"]["actualExpense"] = "2000000"
    assert not strict._offer_purchase_matches(
        capped, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_manifest_cannot_lower_the_valid_offer_to_the_task_budget() -> None:
    evidence = _paid_evidence()
    evidence.manifest["x402"]["offers"][1]["amount"] = "2000000"
    assert strict._offer_expected(evidence, "task-goal-exceeded") is None


def test_missing_or_repaired_preverification_choice_is_rejected() -> None:
    missing = _paid_evidence()
    missing.artifacts = [item for item in missing.artifacts
                         if "sc002-alternate-offer-before-verification" not in item.relative_path]
    assert not strict._offer_purchase_matches(
        missing, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    repaired = _paid_evidence()
    for item in repaired.artifacts:
        if "sc002-alternate-offer-before-verification-operation-by-id" in item.relative_path:
            item.payload["rows"][0]["selected_amount_units"] = "2000000"
    assert not strict._offer_purchase_matches(
        repaired, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_facilitator_cost_requires_matching_raw_rpc_receipt_and_durable_row() -> None:
    missing = _paid_evidence()
    missing.artifacts = [item for item in missing.artifacts
                         if item.payload.get("queryName") != "sc008-cost-operation-proof"]
    assert not strict._offer_purchase_matches(
        missing, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    receipt_mutant = _paid_evidence()
    for item in receipt_mutant.artifacts:
        if item.payload.get("method") == "eth_getTransactionReceipt" and "sc002-alternate-offer-cost-receipt" in item.relative_path:
            item.payload["result"]["effectiveGasPrice"] = "0x3b9aca01"
    assert not strict._offer_purchase_matches(
        receipt_mutant, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    accounting_mutant = _paid_evidence()
    for item in accounting_mutant.artifacts:
        if item.payload.get("queryName") == "sc008-cost-operation-proof":
            item.payload["rows"]["cost"][0]["gas_cost_wei"] = "21000000000001"
    assert not strict._offer_purchase_matches(
        accounting_mutant, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )

    principal_mutant = _paid_evidence()
    for item in principal_mutant.artifacts:
        if item.payload.get("queryName") == "sc008-cost-operation-proof":
            item.payload["rows"]["cost"][0]["selected_principal_units"] = AMOUNT
    assert not strict._offer_purchase_matches(
        principal_mutant, "task-goal-exceeded", variant_id=VARIANT,
        evaluation_variant=EVALUATION_VARIANT, amount_expected=AMOUNT,
    )


def test_genuine_wrong_domain_402_is_retained_with_no_payment_or_chain_effects() -> None:
    evidence = _protocol_failure_evidence()
    assert strict._failure_is_retained(evidence)


def test_protocol_failure_requires_signed_402_same_generation_denial_and_zero_effects() -> None:
    mutations = ("unsigned", "502", "foreign_generation", "foreign_payer", "missing_denial",
                 "wrong_denial_hash", "paid_contamination", "raw_receipt", "correct_domain",
                 "missing_x402_observation_query")
    for mutation in mutations:
        evidence = _protocol_failure_evidence()
        if mutation in {"unsigned", "502", "foreign_generation", "correct_domain"}:
            failure = next(item for item in evidence.artifacts if item.relative_path.endswith("failure-signed.json"))
            if mutation == "unsigned":
                headers = failure.payload["request"]["headers"]
                headers["Payment-Signature-present"] = False
                headers.pop("Payment-Signature")
                headers.pop("Payment-Signature-sha256")
                failure.payload["request"].pop("decodedPaymentPayload")
            elif mutation == "502":
                failure.payload["response"]["status"] = 502
            elif mutation == "foreign_generation":
                failure.payload["request"]["headers"]["X-BEF-Generation"] = "00000000-0000-4000-8000-000000000099"
            else:
                failure.payload["request"]["decodedPaymentPayload"]["accepted"]["extra"]["name"] = "USD Coin"
        elif mutation == "foreign_payer":
            row = next(item for item in evidence.artifacts
                       if "challenge-operation-lookup-generation-by-id" in item.relative_path)
            row.payload["rows"][0]["payer_address"] = "0x" + "9" * 40
        elif mutation == "missing_denial":
            row = next(item for item in evidence.artifacts
                       if item.payload.get("queryName") == "denials-by-generation")
            row.payload["rows"] = []
        elif mutation == "wrong_denial_hash":
            denial = next(item for item in evidence.artifacts
                          if item.payload.get("queryName") == "denials-by-generation")
            operation = next(item for item in evidence.artifacts
                             if item.payload.get("queryName") == "operation-by-id")
            denial.payload["rows"][0]["request_sha256"] = operation.payload["rows"][0]["request_sha256"]
        elif mutation == "paid_contamination":
            row = next(item for item in evidence.artifacts
                       if item.payload.get("queryName") == "payments-by-operation")
            row.payload["rows"] = [{"operation_id": "00000000-0000-4000-8000-000000000004"}]
        elif mutation == "raw_receipt":
            evidence.artifacts.append(_rpc(
                "sc002-genuine-protocol-failure-foreign-receipt.json",
                "00000000-0000-4000-8000-000000000004", "insufficient_test_balance_or_genuine_protocol_failure",
                "eth_getTransactionReceipt", [TX], {"transactionHash": TX},
            ))
        elif mutation == "missing_x402_observation_query":
            evidence.artifacts = [item for item in evidence.artifacts
                                  if item.payload.get("queryName") != "x402-observations-by-operation"]
        assert not strict._failure_is_retained(evidence), mutation


def test_five_raw_typed_actions_are_joined_and_goal_summaries_are_not_actions() -> None:
    evidence = _typed_action_evidence()
    candidates = strict._action_artifacts(evidence)
    proof_fields = {
        "http", "expectedTransaction", "onchainTransaction", "independentReceipt",
        "before", "after", "effects", "operationRow", "selectedExecutionRow",
        "selectedExecutionEvents",
    }
    assert len(candidates) == 7  # Five raw actions plus two goal summaries.
    assert sum(proof_fields.issubset(payload) for _, payload in candidates) == 5
    assert strict._typed_actions_are_bound(evidence) == (True, True, True)


def test_typed_action_join_rejects_missing_raw_receipt_and_unbound_goal_summaries() -> None:
    missing_receipt = _typed_action_evidence()
    swap = next(payload for _, payload in strict._action_artifacts(missing_receipt)
                if payload.get("variantId") == "wrong_test_recipient_within_scope"
                and payload.get("selectedAction", {}).get("kind") == "swap"
                and "independentReceipt" in payload)
    missing_receipt.artifacts = [
        item for item in missing_receipt.artifacts
        if not (item.payload.get("method") == "eth_getTransactionReceipt"
                and item.payload.get("operationId") == swap.get("operationId"))
    ]
    assert strict._typed_actions_are_bound(missing_receipt) == (False, False, False)

    for field, value in (("operationId", "00000000-0000-4000-8000-000000000099"),
                         ("generationId", "00000000-0000-4000-8000-000000000099")):
        evidence = _typed_action_evidence()
        summary = next(item for item in evidence.artifacts if item.relative_path.endswith("goal-0.json"))
        summary.payload[field] = value
        assert strict._typed_actions_are_bound(evidence) == (False, False, False), field


def test_typed_action_records_actual_goal_mismatch_not_only_summary_presence() -> None:
    evidence = _typed_action_evidence()
    summary = next(item for item in evidence.artifacts if item.relative_path.endswith("goal-0.json"))
    summary.payload["goalEvaluation"]["goalMet"] = True
    assert strict._typed_actions_are_bound(evidence) == (True, True, False)

