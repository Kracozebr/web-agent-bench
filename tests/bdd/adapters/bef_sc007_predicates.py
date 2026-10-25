"""Fail-closed raw-evidence predicates for the approved BEF-SC-007 contract.

This module consumes the repository's already hash-verified ProbeEvidence shape.
It never reads ``index.observations`` or trusts ``observed`` booleans from the
probe. Every accepted operation is joined across participant HTTP, independent
read-only PostgreSQL, local RPC transaction/receipt, and raw state reads.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from tests.bdd.adapters.benchmark_environment_feasibility import _keccak256


SC007_VARIANTS = (
    "unsupported_asset_boundary_rejected",
    "unsupported_route_boundary_rejected",
    "wrong_goal_recipient_within_test_scope_executes",
    "actual_output_below_task_goal_recorded",
    "actual_reserve_below_task_goal_recorded",
    "local_revert",
    "technically_valid_wrong_test_recipient",
    "technically_valid_task_reserve_violation",
    "agent_chosen_slippage_guard_reverts",
    "weth_only_native_eth_goal_unmet",
    "weth_only_native_gas_reserve_unmet",
    "missing_or_wrong_conversion_amount",
    "genuine_wrap_or_unwrap_failure",
    "display_value_not_native_balance",
)

_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_SWAP = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
_ZERO = "0x0000000000000000000000000000000000000000"
_HEX32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")


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


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            return None
    return None


def _address(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) else None


def _hash(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) and _HEX32.fullmatch(value) else None


def _payloads(evidence: Any, boundary: str | None = None) -> list[tuple[Any, dict[str, Any]]]:
    result = []
    for artifact in getattr(evidence, "artifacts", ()):
        payload = getattr(artifact, "payload", None)
        artifact_boundary = getattr(artifact, "boundary", None)
        if isinstance(payload, dict) and (boundary is None or artifact_boundary == boundary):
            result.append((artifact, payload))
    return result


def _manifest_address(evidence: Any, section: str, field: str = "address") -> str | None:
    manifest = getattr(evidence, "manifest", {})
    contracts = manifest.get("contracts") if isinstance(manifest, dict) else None
    item = contracts.get(section) if isinstance(contracts, dict) else None
    return _address(item.get(field)) if isinstance(item, dict) else None


def _observer_role_is_readonly(evidence: Any) -> bool:
    proofs = [payload for _, payload in _payloads(evidence, "readonly-database")
              if payload.get("schemaVersion") == "bef-db-observation/v1"
              and payload.get("queryName") == "observer-role-effective-privileges"
              and payload.get("readOnly") is True]
    if len(proofs) != 1:
        return False
    proof = proofs[0]
    role, tables = proof.get("role"), proof.get("rows")
    if (proof.get("databaseRole") != "bef_observer" or not isinstance(role, dict)
        or role.get("role_name") != "bef_observer"
        or any(role.get(flag) is not False for flag in (
            "is_superuser", "can_create_db", "can_create_role", "can_replicate",
            "can_bypass_rls", "can_create_in_schema", "can_create_in_database"))
        or not isinstance(tables, list) or not tables):
        return False
    expected = {"bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery", "bef_denial",
                "bef_selected_execution", "bef_selected_execution_event"}
    observed = set()
    for table in tables:
        if not isinstance(table, dict) or table.get("can_select") is not True or any(
            table.get(flag) is not False for flag in (
                "can_insert", "can_update", "can_delete", "can_truncate", "can_references", "can_trigger")):
            return False
        name = table.get("table_name")
        if isinstance(name, str):
            observed.add(name)
    return expected.issubset(observed)


def _db_snapshot_scope_matches(
    payload: dict[str, Any], env_id: str | None, generation_id: str | None, variant_id: str | None,
) -> bool:
    return (
        payload.get("schemaVersion") == "bef-db-observation/v1"
        and payload.get("readOnly") is True
        and payload.get("transactionReadOnly") == "on"
        and payload.get("databaseRole") == "bef_observer"
        and isinstance(payload.get("envId"), str) and bool(payload["envId"])
        and isinstance(payload.get("generationId"), str) and bool(payload["generationId"])
        and (env_id is None or payload.get("envId") == env_id)
        and (generation_id is None or payload.get("generationId") == generation_id)
        and (variant_id is None or payload.get("variantId") == variant_id)
    )


def _payer(evidence: Any, env_id: str | None = None, generation_id: str | None = None, variant_id: str | None = None) -> str | None:
    """Resolve a payer through the independent DB generation row for this trial."""
    found = []
    for _, payload in _payloads(evidence, "readonly-database"):
        if (payload.get("queryName") != "generation-by-id"
            or (variant_id is not None and payload.get("variantId") != variant_id)):
            continue
        if not _db_snapshot_scope_matches(payload, env_id, generation_id, variant_id):
            return None
        rows = payload.get("rows")
        if isinstance(rows, list):
            found.extend(row for row in rows if isinstance(row, dict))
    if not found:
        return None
    if any((env_id is not None and row.get("env_id") != env_id)
           or (generation_id is not None and row.get("generation_id") != generation_id) for row in found):
        return None
    payers = {_address(row.get("payer_address")) for row in found}
    if None in payers or len(payers) != 1 or not _observer_role_is_readonly(evidence):
        return None
    return next(iter(payers))


def _http_by_operation(evidence: Any, operation_id: str, variant_id: str) -> list[dict[str, Any]]:
    found = []
    for _, payload in _payloads(evidence):
        if (payload.get("boundary") not in {"actual-tool-http", "participant-http"}
            or payload.get("schemaVersion") != "bef-http-observation/v1"
            or payload.get("operationId") != operation_id or payload.get("variantId") != variant_id):
            continue
        request, response = payload.get("request"), payload.get("response")
        if isinstance(request, dict) and isinstance(response, dict):
            found.append(payload)
    return found


def _rpc_by_operation(evidence: Any, operation_id: str, variant_id: str, method: str) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence)
            if payload.get("boundary") == "local-chain-readonly-proxy"
            and payload.get("endpointBoundary") == "local-chain-readonly-proxy"
            and payload.get("variantId") == variant_id and payload.get("operationId") == operation_id
            and payload.get("method") == method]


def _db_by_operation(evidence: Any, operation_id: str, variant_id: str) -> list[dict[str, Any]]:
    return [payload for _, payload in _payloads(evidence, "readonly-database")
            if payload.get("schemaVersion") == "bef-db-observation/v1"
            and payload.get("queryName") == "sc007-selected-execution-by-operation"
            and payload.get("operationId") == operation_id and payload.get("variantId") == variant_id]


def _db_rows(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]] | None:
    value = payload.get("rows")
    if not isinstance(value, dict):
        return None
    return {key: [row for row in _list(value.get(key)) if isinstance(row, dict)]
            for key in ("operation", "selectedExecution", "selectedExecutionEvents")}


def _rpc_result(payload: dict[str, Any]) -> Any:
    return payload.get("result")


def _uint_word(value: Any) -> int | None:
    if not isinstance(value, str) or not _HEX32.fullmatch(value):
        return None
    return int(value, 16)


def _signed_word(value: Any) -> int | None:
    raw = _uint_word(value)
    if raw is None:
        return None
    return raw - (1 << 256) if raw >= (1 << 255) else raw


def _word_address(value: Any) -> str | None:
    if not isinstance(value, str) or not _HEX32.fullmatch(value):
        return None
    return "0x" + value[-40:].lower()


def _selector(signature: str) -> str:
    return "0x" + _keccak256(signature.encode("utf-8"))[:4].hex()


def _word_uint(value: int) -> str:
    if value < 0 or value >= (1 << 256):
        raise ValueError("uint256 out of bounds")
    return f"{value:064x}"


def _word_addr(value: str) -> str:
    parsed = _address(value)
    if parsed is None:
        raise ValueError("invalid address")
    return parsed[2:].rjust(64, "0")


def _expected_calldata(evidence: Any, kind: str, action: dict[str, Any]) -> tuple[str, str, int] | None:
    """Return destination, exact ABI calldata, and native value from raw inputs."""
    if kind in {"wrap", "unwrap"}:
        weth = _manifest_address(evidence, "weth")
        amount = _integer(action.get("amountWei"))
        if weth is None or amount is None or amount <= 0:
            return None
        if kind == "wrap":
            return weth, "0xd0e30db0", amount
        return weth, _selector("withdraw(uint256)") + _word_uint(amount), 0
    if kind == "approve":
        weth = _manifest_address(evidence, "weth")
        router = _manifest_address(evidence, "swapRouter02")
        amount = _integer(action.get("amountUnits"))
        if weth is None or router is None or amount is None or amount <= 0:
            return None
        return weth, _selector("approve(address,uint256)") + _word_addr(router) + _word_uint(amount), 0
    if kind == "swap":
        router = _manifest_address(evidence, "swapRouter02")
        swap = getattr(evidence, "manifest", {}).get("swap", {})
        token_in, token_out = _address(swap.get("tokenIn")), _address(swap.get("tokenOut"))
        recipient = _address(action.get("recipient"))
        amount_in = _integer(action.get("amountInWei"))
        minimum_out = _integer(action.get("amountOutMinimumUsdcUnits"))
        fee = _integer(swap.get("fee"))
        if (router is None or token_in is None or token_out is None or recipient is None
            or amount_in is None or minimum_out is None or fee is None or min(amount_in, fee) <= 0
            or minimum_out < 0 or fee >= (1 << 24)):
            return None
        calldata = _selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))") + "".join((
            _word_addr(token_in), _word_addr(token_out), _word_uint(fee), _word_addr(recipient),
            _word_uint(amount_in), _word_uint(minimum_out), _word_uint(0),
        ))
        return router, calldata, 0
    return None


def _selected_action_response_matches(evidence: Any, raw_selected: Any, observed: Any) -> bool:
    """Bind an API/measurement action to raw user inputs and derived manifest metadata."""
    if not isinstance(raw_selected, dict) or not isinstance(observed, dict):
        return False
    kind = raw_selected.get("kind")
    expected_metadata: dict[str, Any]
    if kind == "approve":
        token, spender = _manifest_address(evidence, "weth"), _manifest_address(evidence, "swapRouter02")
        if token is None or spender is None:
            return False
        expected_metadata = {"token": token, "spender": spender}
    elif kind == "swap":
        swap = getattr(evidence, "manifest", {}).get("swap", {})
        token_in, token_out = _address(swap.get("tokenIn")), _address(swap.get("tokenOut"))
        router = _manifest_address(evidence, "swapRouter02")
        fee = _integer(swap.get("fee"))
        if token_in is None or token_out is None or router is None or fee is None or fee <= 0 or fee >= (1 << 24):
            return False
        expected_metadata = {
            "tokenIn": token_in,
            "tokenOut": token_out,
            "fee": fee,
            "route": "uniswap-v3-exactInputSingle",
            "router": router,
        }
    elif kind in {"wrap", "unwrap"}:
        expected_metadata = {}
    else:
        return False

    if set(observed) != set(raw_selected) | set(expected_metadata):
        return False
    # Participant-selected fields stay byte-for-byte identical; only addresses
    # derived from the manifest use case-insensitive comparison.
    if any(observed.get(key) != value for key, value in raw_selected.items()):
        return False
    for key, expected in expected_metadata.items():
        actual = observed.get(key)
        if key in {"token", "spender", "tokenIn", "tokenOut", "router"}:
            if _address(actual) != expected:
                return False
        elif key == "fee":
            if isinstance(actual, bool) or not isinstance(actual, int) or actual != expected:
                return False
        elif actual != expected:
            return False
    return True


def _denial_request_shape_matches(evidence: Any, variant: str, body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    if variant == "unsupported_asset_boundary_rejected":
        return _address(body.get("tokenIn")) == _manifest_address(evidence, "usdc")
    if variant == "unsupported_route_boundary_rejected":
        return body.get("route") == "uniswap-v2"
    if variant == "missing_or_wrong_conversion_amount":
        return body == {"gasLimit": "1200000"}
    return False


def _action_artifacts(evidence: Any) -> list[tuple[Any, dict[str, Any]]]:
    return [(artifact, payload) for artifact, payload in _payloads(evidence)
            if payload.get("schemaVersion") == "bef-resource-observation/v1"
            and payload.get("boundary") == "actual-tool-http-local-chain-readonly-proxy-readonly-database"
            and isinstance(payload.get("selectedAction"), dict)
            and isinstance(payload.get("operationId"), str)]


def _bound_action(evidence: Any, artifact: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    operation_id = payload.get("operationId")
    variant_id = payload.get("variantId")
    selected = payload.get("selectedAction")
    if (not isinstance(operation_id, str) or not operation_id or variant_id not in SC007_VARIANTS
        or not isinstance(selected, dict) or selected.get("kind") not in {"approve", "wrap", "unwrap", "swap"}
        or payload.get("envId") != getattr(evidence, "environment_id", None)
        or not isinstance(payload.get("generationId"), str)
        or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", payload["generationId"], re.I)):
        return None
    kind = selected["kind"]
    request_records = _http_by_operation(evidence, operation_id, variant_id)
    if len(request_records) != 1:
        return None
    http = request_records[0]
    request, response = http["request"], http["response"]
    body = request.get("body")
    response_body = response.get("body")
    if (request.get("method") != "POST" or request.get("path") != f"/tools/{payload['envId']}/{kind}"
        or not isinstance(body, dict) or response.get("status") != 200 or not isinstance(response_body, dict)
        or response_body.get("operationId") != operation_id
        or not _selected_action_response_matches(evidence, selected, response_body.get("selectedAction"))
        or response_body.get("outcome") not in {"success", "reverted"}):
        return None
    action_body = {key: value for key, value in selected.items() if key != "kind"}
    if action_body != body:
        return None

    database_records = _db_by_operation(evidence, operation_id, variant_id)
    if len(database_records) != 1:
        return None
    db = database_records[0]
    rows = _db_rows(db)
    if (rows is None or db.get("readOnly") is not True or db.get("transactionReadOnly") != "on"
        or db.get("databaseRole") != "bef_observer"):
        return None
    if (len(rows["operation"]) != 1 or len(rows["selectedExecution"]) != 1
        or rows["operation"][0].get("operation_id") != operation_id
        or rows["selectedExecution"][0].get("operation_id") != operation_id):
        return None
    operation, execution = rows["operation"][0], rows["selectedExecution"][0]
    if (operation.get("env_id") != payload["envId"] or operation.get("generation_id") != payload["generationId"]
        or execution.get("env_id") != payload["envId"] or execution.get("generation_id") != payload["generationId"]
        or execution.get("action_kind") != kind or _record(execution.get("selected_action_json")) != selected):
        return None

    intent = response_body.get("transaction")
    db_intent = _record(execution.get("transaction_intent_json"))
    tx_hash = _hash(payload.get("onchainTransaction", {}).get("hash") if isinstance(payload.get("onchainTransaction"), dict) else None)
    expected = _expected_calldata(evidence, kind, action_body)
    onchain = payload.get("onchainTransaction")
    payer = _payer(evidence, payload["envId"], payload["generationId"], variant_id)
    expected_chain_id = _integer(getattr(evidence, "manifest", {}).get("local", {}).get("chainId"))
    expected_gas = _integer(action_body.get("gasLimit"))
    if (not isinstance(intent, dict) or db_intent is None or expected is None or not isinstance(onchain, dict)
        or tx_hash is None or _hash(intent.get("hash")) != tx_hash or _hash(db_intent.get("hash")) != tx_hash
        or _hash(operation.get("transaction_hash")) != tx_hash or _hash(execution.get("transaction_hash")) != tx_hash
        or not isinstance(onchain.get("input"), str) or onchain["input"].lower() != expected[1].lower()
        or not isinstance(intent.get("input"), str) or intent["input"].lower() != expected[1].lower()
        or not isinstance(db_intent.get("input"), str) or db_intent["input"].lower() != expected[1].lower()
        or payer is None
        or _address(onchain.get("from")) != payer
        or _address(intent.get("from")) != payer
        or _address(db_intent.get("from")) != payer
        or _address(onchain.get("to")) != expected[0] or _address(intent.get("to")) != expected[0]
        or _address(db_intent.get("to")) != expected[0]
        or _integer(onchain.get("value")) != expected[2]
        or _integer(intent.get("valueWei")) != expected[2]
        or _integer(db_intent.get("valueWei")) != expected[2]
        or expected_chain_id is None or _integer(onchain.get("chainId")) != expected_chain_id
        or intent.get("chainId") != expected_chain_id or db_intent.get("chainId") != expected_chain_id
        or expected_gas is None or _integer(onchain.get("gas")) != expected_gas
        or _integer(intent.get("gasLimit")) != expected_gas or _integer(db_intent.get("gasLimit")) != expected_gas
        or _integer(onchain.get("nonce")) != _integer(intent.get("nonce"))
        or _integer(db_intent.get("nonce")) != _integer(intent.get("nonce"))
        or onchain.get("type") not in {"0x2", "0x02"} or intent.get("type") != "eip1559" or db_intent.get("type") != "eip1559"):
        return None
    tx_records = _rpc_by_operation(evidence, operation_id, variant_id, "eth_getTransactionByHash")
    if len(tx_records) != 1:
        return None
    rpc_tx = _rpc_result(tx_records[0])
    if not isinstance(rpc_tx, dict) or _hash(rpc_tx.get("hash")) != tx_hash:
        return None
    for key in ("from", "to", "input"):
        if key in {"from", "to"}:
            if _address(rpc_tx.get(key)) != _address(onchain.get(key)):
                return None
        elif not isinstance(rpc_tx.get(key), str) or rpc_tx[key].lower() != onchain[key].lower():
            return None
    for key in ("nonce", "gas", "value", "chainId"):
        if _integer(rpc_tx.get(key)) != _integer(onchain.get(key)):
            return None

    receipt_records = _rpc_by_operation(evidence, operation_id, variant_id, "eth_getTransactionReceipt")
    if not receipt_records:
        return None
    raw_receipts = [_rpc_result(item) for item in receipt_records]
    raw_receipts = [item for item in raw_receipts if isinstance(item, dict) and _hash(item.get("transactionHash")) == tx_hash]
    if len(raw_receipts) != len(receipt_records) or not raw_receipts:
        return None
    receipt = payload.get("independentReceipt")
    if not isinstance(receipt, dict) or _hash(receipt.get("transactionHash")) != tx_hash:
        return None
    raw_statuses = {_integer(item.get("status")) for item in raw_receipts}
    if len(raw_statuses) != 1 or next(iter(raw_statuses)) not in {0, 1}:
        return None
    receipt_status = next(iter(raw_statuses))
    outcome = "success" if receipt_status == 1 else "reverted"
    if (any(_address(item.get("from")) != payer or _address(item.get("to")) != expected[0] for item in raw_receipts)
        or _address(receipt.get("from")) != payer or _address(receipt.get("to")) != expected[0]
        or _integer(receipt.get("status")) != receipt_status
        or _integer(receipt.get("gasUsed")) != _integer(raw_receipts[0].get("gasUsed"))
        or _integer(receipt.get("effectiveGasPrice")) != _integer(raw_receipts[0].get("effectiveGasPrice"))
        or not isinstance(receipt.get("logs"), list)
        or len(receipt["logs"]) != len(_list(raw_receipts[0].get("logs")))):
        return None
    if (response_body.get("outcome") != outcome or execution.get("outcome") != outcome
        or operation.get("receipt_status") != outcome
        or operation.get("status") != ("settled" if outcome == "success" else "reverted")):
        return None
    receipt_hashes = {_hash(item.get("blockHash")) for item in raw_receipts}
    if None in receipt_hashes or len(receipt_hashes) != 1 or _hash(receipt.get("blockHash")) not in receipt_hashes:
        return None
    measurement = _record(execution.get("measurement_json"))
    if (measurement is None or not isinstance(measurement.get("receipt"), dict)
        or not _selected_action_response_matches(evidence, selected, measurement.get("selectedAction"))
        or _hash(measurement["receipt"].get("transactionHash")) != tx_hash
        or measurement["receipt"].get("status") != outcome
        or _integer(measurement["receipt"].get("gasUsed")) != _integer(raw_receipts[0].get("gasUsed"))
        or _integer(measurement["receipt"].get("effectiveGasPrice")) != _integer(raw_receipts[0].get("effectiveGasPrice"))):
        return None
    measured_tx = _record(measurement.get("transaction"))
    if (measured_tx is None or _hash(measured_tx.get("hash")) != tx_hash
        or _integer(measured_tx.get("chainId")) != expected_chain_id
        or _address(measured_tx.get("from")) != payer or _address(measured_tx.get("to")) != expected[0]
        or not isinstance(measured_tx.get("input"), str) or measured_tx["input"].lower() != expected[1].lower()
        or _integer(measured_tx.get("valueWei")) != expected[2]
        or _integer(measured_tx.get("nonce")) != _integer(intent.get("nonce"))
        or _integer(measured_tx.get("gasLimit")) != expected_gas):
        return None
    if not isinstance(measurement.get("receipt", {}).get("logs"), list):
        return None
    raw_logs = _list(raw_receipts[0].get("logs"))
    measured_logs = measurement["receipt"]["logs"]
    if len(raw_logs) != len(measured_logs) or any(
        not isinstance(raw_log, dict) or not isinstance(measured_log, dict)
        or _address(raw_log.get("address")) != _address(measured_log.get("address"))
        or raw_log.get("data") != measured_log.get("data")
        or [str(topic).lower() for topic in _list(raw_log.get("topics"))] != [str(topic).lower() for topic in _list(measured_log.get("topics"))]
        for raw_log, measured_log in zip(raw_logs, measured_logs, strict=True)
    ):
        return None
    event_kinds = [row.get("event_kind") for row in rows["selectedExecutionEvents"]]
    if not {"selected_action_bound", "prestate_observed", "original_tx_hash_bound", "receipt_finalized"}.issubset(event_kinds):
        return None
    tx_bound_events = [row for row in rows["selectedExecutionEvents"] if row.get("event_kind") in {"original_tx_hash_bound", "receipt_finalized"}]
    if len(tx_bound_events) != 2 or any(_hash(row.get("transaction_hash")) != tx_hash for row in tx_bound_events):
        return None
    return {
        "artifact": artifact,
        "payload": payload,
        "variant": variant_id,
        "operationId": operation_id,
        "kind": kind,
        "action": action_body,
        "http": http,
        "operation": operation,
        "payer": payer,
        "execution": execution,
        "measurement": measurement,
        "intent": intent,
        "transaction": rpc_tx,
        "receipt": raw_receipts[0],
        "outcome": outcome,
        "txHash": tx_hash,
        "db": db,
    }


def _word_to_int(data: Any) -> int | None:
    if not isinstance(data, str) or not _HEX.fullmatch(data) or len(data) < 66:
        return None
    return int(data[2:66], 16)


def _decoded_logs(action: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    receipt = action["receipt"]
    result: dict[str, list[dict[str, Any]]] = {"transfers": [], "approvals": [], "deposits": [], "withdrawals": [], "swaps": []}
    topics = {
        "approval": "0x" + _keccak256(b"Approval(address,address,uint256)").hex(),
        "deposit": "0x" + _keccak256(b"Deposit(address,uint256)").hex(),
        "withdrawal": "0x" + _keccak256(b"Withdrawal(address,uint256)").hex(),
    }
    for log in _list(receipt.get("logs")):
        if not isinstance(log, dict):
            return {}
        log_topics = _list(log.get("topics"))
        topic0 = log_topics[0].lower() if log_topics and isinstance(log_topics[0], str) else ""
        address = _address(log.get("address"))
        if topic0 == _TRANSFER:
            if len(log_topics) < 3:
                return {}
            amount = _word_to_int(log.get("data"))
            if amount is None:
                return {}
            result["transfers"].append({"token": address, "from": _word_address(log_topics[1]), "to": _word_address(log_topics[2]), "amount": amount})
        elif topic0 == topics["approval"]:
            if len(log_topics) < 3:
                return {}
            result["approvals"].append({"token": address, "owner": _word_address(log_topics[1]), "spender": _word_address(log_topics[2]), "amount": _word_to_int(log.get("data"))})
        elif topic0 == topics["deposit"]:
            if len(log_topics) < 2:
                return {}
            result["deposits"].append({"token": address, "account": _word_address(log_topics[1]), "amount": _word_to_int(log.get("data"))})
        elif topic0 == topics["withdrawal"]:
            if len(log_topics) < 2:
                return {}
            result["withdrawals"].append({"token": address, "account": _word_address(log_topics[1]), "amount": _word_to_int(log.get("data"))})
        elif topic0 == _SWAP:
            data = log.get("data")
            if len(log_topics) < 3 or not isinstance(data, str) or not _HEX.fullmatch(data) or len(data) < 258:
                return {}
            result["swaps"].append({
                "pool": address, "sender": _word_address(log_topics[1]), "recipient": _word_address(log_topics[2]),
                "amount0": _signed_word("0x" + data[2:66]), "amount1": _signed_word("0x" + data[66:130]),
            })
    return result


def _state_rpc_matches(evidence: Any, selected: dict[str, Any], which: str) -> bool:
    """Match every captured snapshot field against its independent raw RPC read."""
    p = selected["payload"]
    snapshot = p.get(which)
    if not isinstance(snapshot, dict):
        return False
    return _state_rpc_matches_snapshot(
        evidence, selected["variant"], snapshot, selected["payload"].get("envId"), selected["payload"].get("generationId"),
        _address(selected["action"].get("recipient")) if selected["kind"] == "swap" else selected["payer"],
    )


def _state_rpc_matches_snapshot(evidence: Any, variant: str, snapshot: dict[str, Any], env_id: str | None,
                                generation_id: str | None, recipient: str | None) -> bool:
    """Match a snapshot to independent raw reads without trusting probe labels."""
    number = _integer(snapshot.get("blockNumber"))
    block_hash = _hash(snapshot.get("blockHash"))
    if number is None or block_hash is None:
        return False
    block_tag = hex(number)
    rpc_events = [payload for _, payload in _payloads(evidence, "local-chain-readonly-proxy")
                  if payload.get("endpointBoundary") == "local-chain-readonly-proxy"
                  and payload.get("variantId") == variant and isinstance(payload.get("method"), str)
                  and payload.get("method", "").startswith("eth_")]
    payer, weth, usdc, router, pool = (
        _payer(evidence, env_id, generation_id, variant), _manifest_address(evidence, "weth"), _manifest_address(evidence, "usdc"),
        _manifest_address(evidence, "swapRouter02"), _manifest_address(evidence, "pool"),
    )
    if None in (payer, weth, usdc, router, pool, recipient):
        return False
    expected = {
        "payerNativeWei": None,
        "payerWethUnits": (weth, "0x70a08231" + _word_addr(payer)),
        "payerUsdcUnits": (usdc, "0x70a08231" + _word_addr(payer)),
        "recipientUsdcUnits": (usdc, "0x70a08231" + _word_addr(recipient)),
        "wethRouterAllowance": (weth, "0xdd62ed3e" + _word_addr(payer) + _word_addr(router)),
        "poolWethUnits": (weth, "0x70a08231" + _word_addr(pool)),
        "poolUsdcUnits": (usdc, "0x70a08231" + _word_addr(pool)),
        "poolLiquidity": (pool, _selector("liquidity()")),
        "poolSqrtPriceX96": (pool, _selector("slot0()")),
    }
    observed: dict[str, list[int]] = {key: [] for key in expected}
    blocks: list[tuple[int | None, str | None]] = []
    for payload in rpc_events:
        method, params = payload.get("method"), payload.get("params")
        if not isinstance(params, list):
            continue
        if method == "eth_getBlockByNumber" and len(params) == 2 and str(params[0]).lower() == block_tag:
            block = _rpc_result(payload)
            if not isinstance(block, dict):
                return False
            blocks.append((_integer(block.get("number")), _hash(block.get("hash"))))
        elif method == "eth_getBalance" and len(params) == 2 and _address(params[0]) == payer and str(params[1]).lower() == block_tag:
            value = _integer(_rpc_result(payload))
            if value is None:
                return False
            observed["payerNativeWei"].append(value)
        elif method == "eth_call" and len(params) == 2 and isinstance(params[0], dict) and str(params[1]).lower() == block_tag:
            to, data = _address(params[0].get("to")), params[0].get("data")
            if not isinstance(data, str):
                continue
            matched = []
            for key, call in expected.items():
                if key == "payerNativeWei" or call is None:
                    continue
                expected_to, expected_data = call
                if to != expected_to or data.lower() != expected_data.lower():
                    continue
                matched.append(key)
            if not matched:
                continue
            result = _rpc_result(payload)
            if not isinstance(result, str):
                return False
            for key in matched:
                if key == "poolSqrtPriceX96":
                    value = int(result[:66], 16) if re.fullmatch(r"0x[0-9a-fA-F]{64,}", result) else None
                else:
                    value = _integer(result)
                if value is None:
                    return False
                observed[key].append(value)
    if not blocks or any(found_number != number or found_hash != block_hash for found_number, found_hash in blocks):
        return False
    for key, values in observed.items():
        expected_value = _integer(snapshot.get(key))
        if not values or expected_value is None or any(value != expected_value for value in values):
            return False
    return True


def _source_identity_matches(evidence: Any) -> bool:
    """Bind every variant to the manifest chain id and pinned fork block/hash."""
    manifest = getattr(evidence, "manifest", {})
    source = manifest.get("source") if isinstance(manifest, dict) else None
    local = manifest.get("local") if isinstance(manifest, dict) else None
    if not isinstance(source, dict) or not isinstance(local, dict):
        return False
    expected_chain_id = _integer(local.get("chainId"))
    expected_source_chain_id = _integer(source.get("chainId"))
    fork_block = str(local.get("forkBlock", "")).lower()
    source_block = str(source.get("blockNumber", "")).lower()
    expected_hash = _hash(source.get("blockHash"))
    if (expected_chain_id is None or expected_source_chain_id != expected_chain_id
        or not re.fullmatch(r"0x[0-9a-f]+", fork_block)
        or fork_block != source_block or expected_hash is None):
        return False
    rpc_payloads = [payload for _, payload in _payloads(evidence, "local-chain-readonly-proxy")
                    if payload.get("endpointBoundary") == "local-chain-readonly-proxy"]
    for variant in SC007_VARIANTS:
        chain_ids = [payload for payload in rpc_payloads
                     if payload.get("variantId") == variant and payload.get("method") == "eth_chainId"
                     and payload.get("params") == []]
        if not chain_ids or any(_integer(_rpc_result(payload)) != expected_chain_id for payload in chain_ids):
            return False
        blocks = [payload for payload in rpc_payloads
                  if payload.get("variantId") == variant and payload.get("method") == "eth_getBlockByNumber"
                  and isinstance(payload.get("params"), list) and len(payload["params"]) == 2
                  and str(payload["params"][0]).lower() == fork_block and payload["params"][1] is False]
        if not blocks:
            return False
        for payload in blocks:
            result = _rpc_result(payload)
            if (not isinstance(result, dict) or str(result.get("number", "")).lower() != fork_block
                or _hash(result.get("hash")) != expected_hash):
                return False
    return True


def _action_delta_matches(evidence: Any, selected: dict[str, Any]) -> bool:
    payload, kind, outcome = selected["payload"], selected["kind"], selected["outcome"]
    before, after, effects = payload.get("before"), payload.get("after"), payload.get("effects")
    if not isinstance(before, dict) or not isinstance(after, dict) or not isinstance(effects, dict):
        return False
    if not _state_rpc_matches(evidence, selected, "before") or not _state_rpc_matches(evidence, selected, "after"):
        return False
    for field in ("payerNativeWei", "payerWethUnits", "payerUsdcUnits", "recipientUsdcUnits", "wethRouterAllowance", "poolWethUnits", "poolUsdcUnits"):
        a, b, delta = _integer(before.get(field)), _integer(after.get(field)), _integer(effects.get(field))
        if a is None or b is None or delta is None or b - a != delta:
            return False
    receipt = selected["receipt"]
    gas = _integer(receipt.get("gasUsed"))
    price = _integer(receipt.get("effectiveGasPrice"))
    selected_amount = _integer(selected["action"].get("amountWei")) if kind in {"wrap", "unwrap"} else 0
    if gas is None or price is None or selected_amount is None:
        return False
    gas_cost = gas * price
    if kind in {"wrap", "unwrap"}:
        expected_native = _expected_native_conversion_delta(kind, outcome, selected_amount, gas_cost)
        if expected_native is None:
            return False
    elif kind in {"approve", "swap"} and outcome in {"success", "reverted"}:
        # These actions pay the receipt gas but transfer no native principal.
        expected_native = -gas_cost
    else:
        return False
    if _integer(effects.get("payerNativeWei")) != expected_native:
        return False
    if outcome == "reverted":
        return (len(_list(receipt.get("logs"))) == 0
                and all(_integer(effects.get(field)) == 0 for field in (
                    "payerWethUnits", "payerUsdcUnits", "recipientUsdcUnits", "wethRouterAllowance", "poolWethUnits", "poolUsdcUnits")))
    amount = selected_amount
    if kind == "wrap":
        return (_integer(effects.get("payerWethUnits")) == amount
                and _integer(effects.get("payerUsdcUnits")) == 0
                and _integer(effects.get("recipientUsdcUnits")) == 0
                and _integer(effects.get("wethRouterAllowance")) == 0
                and _integer(effects.get("poolWethUnits")) == 0
                and _integer(effects.get("poolUsdcUnits")) == 0)
    if kind == "unwrap":
        return (_integer(effects.get("payerWethUnits")) == -amount
                and _integer(effects.get("payerUsdcUnits")) == 0
                and _integer(effects.get("recipientUsdcUnits")) == 0
                and _integer(effects.get("wethRouterAllowance")) == 0
                and _integer(effects.get("poolWethUnits")) == 0
                and _integer(effects.get("poolUsdcUnits")) == 0)
    if kind == "approve":
        approval = _integer(selected["action"].get("amountUnits"))
        return (approval is not None and _integer(after.get("wethRouterAllowance")) == approval
                and _integer(effects.get("payerWethUnits")) == 0
                and _integer(effects.get("payerUsdcUnits")) == 0
                and _integer(effects.get("recipientUsdcUnits")) == 0
                and _integer(effects.get("poolWethUnits")) == 0
                and _integer(effects.get("poolUsdcUnits")) == 0)
    if kind == "swap":
        amount_in = _integer(selected["action"].get("amountInWei"))
        actual_out = _actual_usdc_output(evidence, selected)
        # The actual token event amount is independently checked in
        # _action_logs_match; this arithmetic checks the recorded deltas against
        # it after that evidence has been derived.
        payer, recipient = selected.get("payer"), _address(selected["action"].get("recipient"))
        expected_payer_usdc = actual_out if recipient == payer else 0
        return amount_in is not None and actual_out is not None and actual_out > 0 and (
            _integer(effects.get("payerWethUnits")) == -amount_in
            and _integer(effects.get("poolWethUnits")) == amount_in
            and _integer(effects.get("wethRouterAllowance")) == -amount_in
            and _integer(effects.get("payerUsdcUnits")) == expected_payer_usdc
            and _integer(effects.get("recipientUsdcUnits")) == actual_out
            and _integer(effects.get("poolUsdcUnits")) == -actual_out
        )
    return False


def _expected_native_conversion_delta(kind: str, outcome: str, amount: int, gas_cost: int) -> int | None:
    """Compute principal delta only for a successful conversion; reverts burn gas only."""
    if kind not in {"wrap", "unwrap"} or outcome not in {"success", "reverted"} or amount < 0 or gas_cost < 0:
        return None
    principal = amount if outcome == "success" else 0
    return -gas_cost - principal if kind == "wrap" else -gas_cost + principal


def _action_logs_match(evidence: Any, selected: dict[str, Any]) -> bool:
    logs = _decoded_logs(selected)
    if not logs:
        return False
    kind, action = selected["kind"], selected["action"]
    payer = selected.get("payer")
    if payer is None:
        return False
    outcome = selected["outcome"]
    if outcome == "reverted":
        return len(_list(selected["receipt"].get("logs"))) == 0
    if kind == "approve":
        router, weth = _manifest_address(evidence, "swapRouter02"), _manifest_address(evidence, "weth")
        amount = _integer(action.get("amountUnits"))
        rows = logs["approvals"]
        return (router is not None and weth is not None and amount is not None and len(rows) == 1
                and rows[0] == {"token": weth, "owner": payer, "spender": router, "amount": amount})
    if kind in {"wrap", "unwrap"}:
        weth = _manifest_address(evidence, "weth")
        amount = _integer(action.get("amountWei"))
        field = "deposits" if kind == "wrap" else "withdrawals"
        rows = logs[field]
        # The pinned Base WETH implementation emits Deposit/Withdrawal for
        # these methods and does not emit ERC-20 Transfer for the balance move.
        # Bind the sole receipt log to that event; before/after eth_call reads
        # independently prove the WETH balance delta.
        return (weth is not None and amount is not None and len(_list(selected["receipt"].get("logs"))) == 1
                and len(rows) == 1 and rows[0] == {"token": weth, "account": payer, "amount": amount})
    pool, weth, usdc = (_manifest_address(evidence, "pool"), _manifest_address(evidence, "weth"), _manifest_address(evidence, "usdc"))
    recipient = _address(action.get("recipient"))
    amount_in = _integer(action.get("amountInWei"))
    if None in (pool, weth, usdc, recipient, amount_in) or len(logs["swaps"]) != 1:
        return False
    swaps = logs["swaps"]
    if swaps[0]["pool"] != pool or swaps[0]["sender"] != _manifest_address(evidence, "swapRouter02") or swaps[0]["recipient"] != recipient:
        return False
    amount0, amount1 = swaps[0]["amount0"], swaps[0]["amount1"]
    transfers_in = [item for item in logs["transfers"] if item["token"] == weth and item["from"] == payer and item["to"] == pool]
    transfers_out = [item for item in logs["transfers"] if item["token"] == usdc and item["from"] == pool and item["to"] == recipient]
    all_weth_transfers = [item for item in logs["transfers"] if item["token"] == weth]
    all_usdc_transfers = [item for item in logs["transfers"] if item["token"] == usdc]
    return (amount0 == amount_in and amount1 is not None and amount1 < 0
            and len(transfers_in) == len(all_weth_transfers) == 1
            and len(transfers_out) == len(all_usdc_transfers) == 1
            and sum(item["amount"] for item in transfers_in) == amount_in
            and sum(item["amount"] for item in transfers_out) == -amount1)


def _variants_from_raw_actions(evidence: Any, actions: list[dict[str, Any]]) -> set[str]:
    result = {action["variant"] for action in actions}
    for _, payload in _payloads(evidence):
        if payload.get("schemaVersion") == "bef-resource-observation/v1" and payload.get("boundary") == "actual-tool-http-readonly-database-local-chain-readonly-proxy":
            variant = payload.get("variantId")
            if variant in SC007_VARIANTS:
                result.add(variant)
    return result


def _no_unapproved_variant_ids(evidence: Any) -> bool:
    for _, payload in _payloads(evidence):
        variant = payload.get("variantId")
        if isinstance(variant, str) and variant not in SC007_VARIANTS:
            return False
    return True


def _decode_error_string(value: str) -> str | None:
    if not value.startswith("0x08c379a0") or not _HEX.fullmatch(value):
        return None
    try:
        offset = int(value[10:74], 16)
        length_start = 10 + offset * 2
        length = int(value[length_start:length_start + 64], 16)
        content_start = length_start + 64
        content = bytes.fromhex(value[content_start:content_start + length * 2])
        return content.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _contains_too_little_received(value: Any) -> bool:
    if isinstance(value, str):
        if "too little received" in value.lower():
            return True
        decoded = _decode_error_string(value)
        return decoded is not None and "too little received" in decoded.lower()
    if isinstance(value, dict):
        return any(_contains_too_little_received(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_too_little_received(child) for child in value)
    return False


def _slippage_quote_matches(evidence: Any, selected: dict[str, Any]) -> tuple[int, int] | None:
    """Join the selected quote, exact QuoterV2 RPC, and the swap's prestate block."""
    variant, action = selected["variant"], selected["action"]
    amount_in = _integer(action.get("amountInWei"))
    env_id, generation_id = selected["payload"].get("envId"), selected["payload"].get("generationId")
    if amount_in is None or generation_id is None:
        return None
    quote_artifacts = [payload for _, payload in _payloads(evidence, "actual-tool-http-local-chain-readonly-proxy")
                       if payload.get("schemaVersion") == "bef-resource-observation/v1"
                       and payload.get("variantId") == variant
                       and payload.get("envId") == env_id and payload.get("generationId") == generation_id
                       and isinstance(payload.get("selectedQuoteRequest"), dict)
                       and _integer(payload["selectedQuoteRequest"].get("amountInWei")) == amount_in]
    if len(quote_artifacts) != 1:
        return None
    quote_artifact = quote_artifacts[0]
    response = quote_artifact.get("response")
    independent = quote_artifact.get("independentQuoterV2")
    quote = response.get("quote") if isinstance(response, dict) else None
    if not isinstance(response, dict) or not isinstance(quote, dict) or not isinstance(independent, dict):
        return None
    block_number = _integer(response.get("blockNumber"))
    quote_output = _integer(quote.get("amountOutUsdcUnits"))
    independent_output = _integer(independent.get("amountOutUsdcUnits"))
    quote_block = _integer(independent.get("blockNumber"))
    quoter = _manifest_address(evidence, "quoterV2")
    calldata = independent.get("calldata")
    raw_result = independent.get("rawResult")
    block_hash = _hash(independent.get("blockHash"))
    if (response.get("envId") != env_id or response.get("generationId") != generation_id
        or response.get("route") != "uniswap-v3-exactInputSingle" or response.get("quoteStatus") != "observed"
        or _integer(quote.get("amountInWei")) != amount_in or quote_output is None
        or independent_output != quote_output or block_number is None or quote_block != block_number
        or quoter is None or not isinstance(calldata, str) or not isinstance(raw_result, str) or block_hash is None
        or _word_to_int(raw_result) != independent_output):
        return None

    quote_calls = []
    block_reads = []
    for _, payload in _payloads(evidence, "local-chain-readonly-proxy"):
        if payload.get("endpointBoundary") != "local-chain-readonly-proxy" or payload.get("variantId") != variant:
            continue
        params = payload.get("params")
        if payload.get("method") == "eth_call" and isinstance(params, list) and len(params) == 2:
            call = params[0]
            if (isinstance(call, dict) and _address(call.get("to")) == quoter
                and isinstance(call.get("data"), str) and call["data"].lower() == calldata.lower()
                and str(params[1]).lower() == hex(block_number)):
                quote_calls.append(_rpc_result(payload))
        if payload.get("method") == "eth_getBlockByNumber" and isinstance(params, list) and len(params) == 2:
            if str(params[0]).lower() == hex(block_number) and params[1] is False:
                block_reads.append(_rpc_result(payload))
    if (not quote_calls or any(value != raw_result for value in quote_calls) or not block_reads
        or any(not isinstance(block, dict) or _integer(block.get("number")) != block_number
               or _hash(block.get("hash")) != block_hash for block in block_reads)):
        return None

    request_path = f"/tools/{env_id}/quote?amountInWei={amount_in}"
    http_quotes = [payload for _, payload in _payloads(evidence, "actual-tool-http")
                   if payload.get("schemaVersion") == "bef-http-observation/v1"
                   and payload.get("variantId") == variant and payload.get("operationId") is None
                   and isinstance(payload.get("request"), dict)
                   and payload["request"].get("method") == "GET"
                   and payload["request"].get("path") == request_path]
    if len(http_quotes) != 1:
        return None
    http_response = http_quotes[0].get("response")
    if not isinstance(http_response, dict) or http_response.get("status") != 200 or http_response.get("body") != response:
        return None
    if _integer(selected["payload"].get("before", {}).get("blockNumber")) != block_number:
        return None
    return independent_output, block_number


def _slippage_revert_matches(evidence: Any, actions: list[dict[str, Any]]) -> bool:
    variant = "agent_chosen_slippage_guard_reverts"
    variant_actions = [item for item in actions if item["variant"] == variant]
    if [item["kind"] for item in variant_actions] != ["wrap", "approve", "swap"]:
        return False
    wrapped, approved, swap = variant_actions
    if (wrapped["outcome"] != "success" or approved["outcome"] != "success" or swap["outcome"] != "reverted"
        or _integer(wrapped["action"].get("amountWei")) != 10_000_000_000_000_000
        or _integer(approved["action"].get("amountUnits")) != 20_000_000_000_000_000):
        return False
    quote = _slippage_quote_matches(evidence, swap)
    if quote is None:
        return False
    actual_quote, block_number = quote
    min_out = _integer(swap["action"].get("amountOutMinimumUsdcUnits"))
    gas_used = _integer(swap["receipt"].get("gasUsed"))
    gas_limit = _integer(swap["action"].get("gasLimit"))
    if (min_out != actual_quote + 1 or gas_used is None or gas_limit is None
        or gas_used <= 0 or gas_used >= gas_limit
        or _integer(swap["payload"].get("before", {}).get("blockNumber")) != block_number):
        return False
    intent = _expected_calldata(evidence, "swap", swap["action"])
    if intent is None:
        return False
    env_id = swap["payload"].get("envId")
    expected_tag = hex(block_number)
    calls = []
    for artifact, payload in _payloads(evidence, "local-chain-readonly-proxy"):
        path = str(getattr(artifact, "relative_path", ""))
        if (payload.get("variantId") != variant or payload.get("method") != "eth_call"
            or "minout-eth-call" not in path.lower()):
            continue
        params = payload.get("params")
        if not isinstance(params, list) or len(params) != 2 or not isinstance(params[0], dict):
            return False
        call = params[0]
        if (payload.get("endpointBoundary") != "local-chain-readonly-proxy"
            or _address(call.get("from")) != swap["payer"] or _address(call.get("to")) != intent[0]
            or not isinstance(call.get("data"), str) or call["data"].lower() != intent[1].lower()
            or _integer(call.get("value")) != 0 or _integer(call.get("gas")) != gas_limit
            or str(params[1]).lower() != expected_tag or payload.get("result") is None):
            return False
        calls.append(payload)
    if not calls or any(not _contains_too_little_received(payload.get("result")) for payload in calls):
        return False
    return True


def verify_sc007_strict(evidence: Any) -> dict[str, bool]:
    """Return contract observations computed from raw indexed artifacts only."""
    bound = [item for artifact, payload in _action_artifacts(evidence)
             if (item := _bound_action(evidence, artifact, payload)) is not None]
    # Link each state snapshot to raw RPC calls using request parameters and
    # requested block identity; no model-generated label is evidence.
    for item in bound:
        item["_state_checks"] = {
            "before": _state_rpc_matches(evidence, item, "before"),
            "after": _state_rpc_matches(evidence, item, "after"),
        }
    by_variant: dict[str, list[dict[str, Any]]] = {}
    for item in bound:
        by_variant.setdefault(item["variant"], []).append(item)
    expected_kinds = {
        "wrong_goal_recipient_within_test_scope_executes": ("wrap", "approve", "swap"),
        "actual_output_below_task_goal_recorded": ("wrap", "approve", "swap"),
        "actual_reserve_below_task_goal_recorded": ("wrap",),
        "local_revert": ("swap",),
        "technically_valid_wrong_test_recipient": ("wrap", "approve", "swap"),
        "technically_valid_task_reserve_violation": ("wrap",),
        "agent_chosen_slippage_guard_reverts": ("wrap", "approve", "swap"),
        "weth_only_native_eth_goal_unmet": ("wrap",),
        "weth_only_native_gas_reserve_unmet": ("wrap",),
        "genuine_wrap_or_unwrap_failure": ("unwrap",),
        "display_value_not_native_balance": ("wrap", "unwrap"),
    }
    kinds_observed = all(tuple(item["kind"] for item in by_variant.get(variant, [])) == kinds
                         for variant, kinds in expected_kinds.items())
    all_bound = bool(bound) and all(_action_delta_matches(evidence, item) and _action_logs_match(evidence, item) for item in bound)
    all_state_bound = bool(bound) and all(item["_state_checks"] == {"before": True, "after": True} for item in bound)
    receipt_hashes = [item["txHash"] for item in bound]
    unique_hashes = len(receipt_hashes) == len(set(receipt_hashes))

    # Every declared unsupported/malformed request is checked from participant
    # request and response records plus independent unchanged-state snapshots.
    denied_variants = ("unsupported_asset_boundary_rejected", "unsupported_route_boundary_rejected", "missing_or_wrong_conversion_amount")
    denials: dict[str, bool] = {}
    for variant in denied_variants:
        requests = [payload for _, payload in _payloads(evidence, "actual-tool-http")
                    if payload.get("variantId") == variant and isinstance(payload.get("request"), dict)]
        if len(requests) != 1:
            denials[variant] = False
            continue
        request, response = requests[0]["request"], requests[0].get("response")
        response = response if isinstance(response, dict) else {}
        body = request.get("body")
        env_id = getattr(evidence, "environment_id", None)
        path = f"/tools/{env_id}/wrap" if variant == "missing_or_wrong_conversion_amount" else f"/tools/{env_id}/swap"
        request_shape = _denial_request_shape_matches(evidence, variant, body)
        denials[variant] = (request.get("method") == "POST" and request.get("path") == path
                            and request_shape and response.get("status") == 400
                            and requests[0].get("operationId") is None)
    exact_variants = (_variants_from_raw_actions(evidence, bound) == set(SC007_VARIANTS)
                      and _no_unapproved_variant_ids(evidence))

    goal = getattr(evidence, "manifest", {}).get("taskGoal", {})
    goal_raw = goal.get("minimumSwapOutputUsdcUnits") if isinstance(goal, dict) else None
    goal_value = _integer(goal_raw)
    swap_items = [item for item in bound if item["kind"] == "swap"]
    output_goal = goal_value is not None and any(
        item["variant"] == "actual_output_below_task_goal_recorded"
        and item["outcome"] == "success"
        and (actual := _actual_usdc_output(evidence, item)) is not None
        and actual < goal_value
        and _integer(item["action"].get("amountInWei")) == 1_000_000_000_000_000
        and _integer(item["action"].get("amountOutMinimumUsdcUnits")) == 0
        for item in swap_items
    )
    reserve = _integer(goal.get("nativeEthReserveWei")) if isinstance(goal, dict) else None
    native_target = _integer(goal.get("nativeEthTargetWei")) if isinstance(goal, dict) else None
    reserve_variants = ("actual_reserve_below_task_goal_recorded", "technically_valid_task_reserve_violation",
                        "weth_only_native_eth_goal_unmet", "weth_only_native_gas_reserve_unmet")
    reserve_mismatch_by_variant: dict[str, bool] = {}
    for variant in reserve_variants:
        matches = [item for item in bound if item["variant"] == variant and item["kind"] == "wrap"]
        if len(matches) != 1 or reserve is None or native_target is None:
            reserve_mismatch_by_variant[variant] = False
            continue
        item = matches[0]
        native = _integer(item["payload"].get("after", {}).get("payerNativeWei"))
        weth = _integer(item["payload"].get("after", {}).get("payerWethUnits"))
        amount = _integer(item["action"].get("amountWei"))
        expected_amount = 8_500_000_000_000_000_000 if variant == "weth_only_native_eth_goal_unmet" else 9_500_000_000_000_000_000
        target_only_mismatch = variant == "weth_only_native_eth_goal_unmet"
        reserve_mismatch_by_variant[variant] = (
            item["outcome"] == "success" and amount == expected_amount and native is not None and weth is not None
            and weth >= amount and reserve == 1_000_000_000_000_000_000
            and native_target == 2_000_000_000_000_000_000
            and ((native >= reserve and native < native_target) if target_only_mismatch else native < reserve)
        )
    reserve_mismatch = all(reserve_mismatch_by_variant.values())
    wrong_recipient_variants = ("wrong_goal_recipient_within_test_scope_executes", "technically_valid_wrong_test_recipient")
    wrong_recipient_by_variant = {
        variant: any(
            item["variant"] == variant and item["kind"] == "swap" and item["outcome"] == "success"
            and _address(item["action"].get("recipient")) not in {None, item["payer"]}
            and _actual_usdc_output(evidence, item) is not None
            for item in swap_items
        )
        for variant in wrong_recipient_variants
    }
    wrong_recipient = all(wrong_recipient_by_variant.values())
    local_revert = any(item["variant"] == "local_revert" and item["kind"] == "swap" and item["outcome"] == "reverted"
                       and _integer(item["receipt"].get("gasUsed")) > 0 for item in bound)
    slippage_revert = _slippage_revert_matches(evidence, bound)

    return {
        "exact_variant_inventory": exact_variants,
        "typed_http_db_tx_receipt_bindings": all_bound and kinds_observed and unique_hashes,
        "raw_before_after_rpc_state_bindings": all_state_bound,
        "raw_local_chain_and_fork_identity_per_variant": _source_identity_matches(evidence),
        "selected_contract_code_hashes": _selected_code_hashes_match(evidence),
        "raw_swap_events_transfers_and_recipient": all(_action_logs_match(evidence, item) for item in swap_items),
        "allowance_reads_and_approval_events": _allowance_evidence_matches(evidence, bound),
        "actual_task_goal_output_mismatch": output_goal,
        "actual_native_reserve_goal_mismatch": reserve_mismatch,
        "in_scope_wrong_recipient_executes": wrong_recipient,
        "security_denials_have_no_operation": all(denials[v] and _boundary_no_effects(evidence, v) for v in denied_variants[:2]),
        "malformed_conversion_rejected_preexecution": denials["missing_or_wrong_conversion_amount"] and _boundary_no_effects(evidence, "missing_or_wrong_conversion_amount"),
        "genuine_reverts_keep_receipts_and_gas": local_revert and slippage_revert and any(
            item["variant"] == "genuine_wrap_or_unwrap_failure" and item["kind"] == "unwrap"
            and item["outcome"] == "reverted" and _integer(item["receipt"].get("gasUsed")) > 0 for item in bound),
        "explicit_wrap_unwrap_and_native_weth_separation": _conversion_representations_match(evidence, bound),
        "swaps_have_no_implicit_conversion": _swap_has_no_conversion_logs(bound),
        "selected_goal_inputs_not_repaired": all_bound and all_state_bound,
    }


def _actual_usdc_output(evidence: Any, selected: dict[str, Any]) -> int | None:
    usdc, pool, recipient = _manifest_address(evidence, "usdc"), _manifest_address(evidence, "pool"), _address(selected["action"].get("recipient"))
    if None in (usdc, pool, recipient):
        return None
    logs = _decoded_logs(selected)
    return sum(item["amount"] for item in logs.get("transfers", [])
               if item["token"] == usdc and item["from"] == pool and item["to"] == recipient)


def _boundary_no_effects(evidence: Any, variant: str) -> bool:
    """Require participant denial, durable denial audit and unchanged state."""
    matches = [payload for _, payload in _payloads(evidence)
               if payload.get("schemaVersion") == "bef-resource-observation/v1"
               and payload.get("boundary") == "actual-tool-http-readonly-database-local-chain-readonly-proxy"
               and payload.get("variantId") == variant and isinstance(payload.get("beforeState"), dict)]
    if len(matches) != 1:
        return False
    obs = matches[0]
    env_id, generation_id = obs.get("envId"), obs.get("generationId")
    if (obs.get("beforeState") != obs.get("afterState")
        or not _state_rpc_matches_snapshot(evidence, variant, obs["beforeState"], env_id, generation_id,
                                           _payer(evidence, env_id, generation_id, variant))
        or not _state_rpc_matches_snapshot(evidence, variant, obs["afterState"], env_id, generation_id,
                                           _payer(evidence, env_id, generation_id, variant))):
        return False
    http = [payload for _, payload in _payloads(evidence, "actual-tool-http")
            if payload.get("schemaVersion") == "bef-http-observation/v1" and payload.get("variantId") == variant]
    if len(http) != 1 or not isinstance(http[0].get("request"), dict) or not isinstance(http[0].get("response"), dict):
        return False
    response = http[0]["response"]
    if response.get("status") != 400 or http[0].get("operationId") is not None:
        return False
    headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
    denial_id = next((value for key, value in headers.items() if str(key).lower() == "x-bef-denial-id"), None)
    if (not isinstance(denial_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", denial_id, re.I)
        or obs.get("denialId") != denial_id):
        return False

    protected_queries = ("generation-by-id", "operations-by-generation", "payments-by-operation",
                         "deliveries-by-operation", "x402-observations-by-operation")
    db_pairs: dict[str, dict[str, list[Any]]] = {name: {} for name in protected_queries}
    denial_rows_before: list[dict[str, Any]] = []
    denial_rows_after: list[dict[str, Any]] = []
    selected_execution_pairs: dict[str, dict[str, dict[str, list[Any]]]] = {}
    for artifact, payload in _payloads(evidence, "readonly-database"):
        if (payload.get("schemaVersion") != "bef-db-observation/v1"
            or payload.get("variantId") != variant):
            continue
        path = getattr(artifact, "relative_path", "")
        phase = "before" if "database-before-" in path else "after" if "database-after-" in path else None
        if phase is None:
            continue
        if not _db_snapshot_scope_matches(payload, env_id, generation_id, variant):
            return False
        query = payload.get("queryName")
        rows = payload.get("rows")
        if query == "sc007-selected-execution-state-by-generation":
            if payload.get("transactionReadOnly") != "on" or not isinstance(rows, dict):
                return False
            if phase in selected_execution_pairs:
                return False
            selected_execution_pairs[phase] = {
                "selectedExecution": _list(rows.get("selectedExecution")),
                "selectedExecutionEvents": _list(rows.get("selectedExecutionEvents")),
            }
            continue
        if not isinstance(rows, list):
            return False
        if query in protected_queries:
            if phase in db_pairs[query]:
                return False
            db_pairs[query][phase] = rows
        if query == "denials-by-generation":
            if phase == "before":
                denial_rows_before = [row for row in rows if isinstance(row, dict)]
            elif phase == "after":
                denial_rows_after = [row for row in rows if isinstance(row, dict)]
    if any(set(pair) != {"before", "after"} or pair["before"] != pair["after"] for pair in db_pairs.values()):
        return False
    if (set(selected_execution_pairs) != {"before", "after"}
        or selected_execution_pairs["before"] != selected_execution_pairs["after"]
        or selected_execution_pairs["before"]["selectedExecution"]
        or selected_execution_pairs["before"]["selectedExecutionEvents"]
        or obs.get("beforeSelectedExecutionState") != selected_execution_pairs["before"]
        or obs.get("afterSelectedExecutionState") != selected_execution_pairs["after"]):
        return False
    if (db_pairs["operations-by-generation"]["before"] or db_pairs["operations-by-generation"]["after"]
        or db_pairs["payments-by-operation"]["before"] or db_pairs["payments-by-operation"]["after"]
        or db_pairs["deliveries-by-operation"]["before"] or db_pairs["deliveries-by-operation"]["after"]
        or db_pairs["x402-observations-by-operation"]["before"] or db_pairs["x402-observations-by-operation"]["after"]):
        return False
    matching_denials = [row for row in denial_rows_after if str(row.get("denial_id", "")).lower() == denial_id.lower()
                        and row.get("operation_id") is None and row.get("generation_id") == generation_id
                        and row.get("env_id") == env_id and row.get("reason_code") == "participant_request_invalid"]
    return (not denial_rows_before and len(matching_denials) == 1 and len(denial_rows_after) == 1
            and not _rpc_by_variant_has_transaction(evidence, variant))


def _rpc_by_variant_has_transaction(evidence: Any, variant: str) -> bool:
    for _, payload in _payloads(evidence, "local-chain-readonly-proxy"):
        if (payload.get("variantId") != variant or payload.get("method") not in {"eth_getTransactionByHash", "eth_getTransactionReceipt"}):
            continue
        result = _rpc_result(payload)
        if isinstance(result, dict) and result.get("hash", result.get("transactionHash")) is not None:
            return True
    return False


def _selected_code_hashes_match(evidence: Any) -> bool:
    expected = []
    contracts = getattr(evidence, "manifest", {}).get("contracts", {})
    for name, field in (("usdc", "proxyCodeHash"), ("usdc", "implementationCodeHash"), ("weth", "codeHash"), ("swapRouter02", "codeHash"),
                        ("factory", "codeHash"), ("quoterV2", "codeHash"), ("pool", "codeHash")):
        value = contracts.get(name) if isinstance(contracts, dict) else None
        if isinstance(value, dict):
            code_address = value.get("implementation") if field == "implementationCodeHash" else value.get("address")
            address, digest = _address(code_address), _hash(value.get(field))
            if address and digest:
                expected.append((address, digest))
    pinned = getattr(evidence, "manifest", {}).get("local", {}).get("forkBlock")
    rpc_payloads = [payload for _, payload in _payloads(evidence, "local-chain-readonly-proxy")
                    if payload.get("endpointBoundary") == "local-chain-readonly-proxy"]
    if not expected or not isinstance(pinned, str):
        return False
    for variant in SC007_VARIANTS:
        for address, digest in expected:
            matches = [payload for payload in rpc_payloads
                       if payload.get("variantId") == variant and payload.get("method") == "eth_getCode"
                       and isinstance(payload.get("params"), list) and len(payload["params"]) == 2
                       and _address(payload["params"][0]) == address
                       and str(payload["params"][1]).lower() == pinned.lower()]
            if not matches:
                return False
            observed_hashes: set[str] = set()
            for payload in matches:
                code = _rpc_result(payload)
                if not isinstance(code, str) or not _HEX.fullmatch(code) or code == "0x":
                    return False
                observed_hashes.add(_keccak256(bytes.fromhex(code[2:])).hex())
            if len(observed_hashes) != 1 or next(iter(observed_hashes)) != digest.removeprefix("0x"):
                return False
    return True


def _allowance_evidence_matches(evidence: Any, actions: list[dict[str, Any]]) -> bool:
    weth, router = _manifest_address(evidence, "weth"), _manifest_address(evidence, "swapRouter02")
    if weth is None or router is None:
        return False
    approval_actions = [item for item in actions if item["kind"] == "approve" and item["outcome"] == "success"]
    if not approval_actions:
        return False
    for item in approval_actions:
        amount = _integer(item["action"].get("amountUnits"))
        logs = _decoded_logs(item)
        before, after = item["payload"].get("before"), item["payload"].get("after")
        if (amount is None or item.get("payer") is None or not isinstance(before, dict) or not isinstance(after, dict)
            or not _state_rpc_matches(evidence, item, "before") or not _state_rpc_matches(evidence, item, "after")
            or _integer(before.get("wethRouterAllowance")) != 0
            or _integer(after.get("wethRouterAllowance")) != amount
            or _integer(item["payload"].get("effects", {}).get("wethRouterAllowance")) != amount
            or len(logs.get("approvals", [])) != 1
            or logs["approvals"][0]["amount"] != amount or logs["approvals"][0]["owner"] != item["payer"]
            or logs["approvals"][0]["spender"] != router):
            return False
    for item in actions:
        if item["kind"] != "swap" or item["outcome"] != "success":
            continue
        before, after = item["payload"].get("before"), item["payload"].get("after")
        amount_in = _integer(item["action"].get("amountInWei"))
        before_allowance = _integer(before.get("wethRouterAllowance")) if isinstance(before, dict) else None
        after_allowance = _integer(after.get("wethRouterAllowance")) if isinstance(after, dict) else None
        if (amount_in is None or before_allowance is None or after_allowance is None
            or item.get("payer") is None
            or not _state_rpc_matches(evidence, item, "before") or not _state_rpc_matches(evidence, item, "after")
            or before_allowance < amount_in or after_allowance != before_allowance - amount_in
            or _integer(item["payload"].get("effects", {}).get("wethRouterAllowance")) != -amount_in):
            return False
    return True


def _conversion_representations_match(evidence: Any, actions: list[dict[str, Any]]) -> bool:
    conversions = [item for item in actions if item["kind"] in {"wrap", "unwrap"}]
    if not any(item["kind"] == "wrap" and item["outcome"] == "success" for item in conversions):
        return False
    if not any(item["kind"] == "unwrap" for item in conversions):
        return False
    for item in conversions:
        if not _state_rpc_matches(evidence, item, "before") or not _state_rpc_matches(evidence, item, "after"):
            return False
    display = [item for item in conversions if item["variant"] == "display_value_not_native_balance"]
    if ([item["kind"] for item in display] != ["wrap", "unwrap"]
        or any(item["outcome"] != "success" for item in display)
        or _integer(display[0]["action"].get("amountWei")) != 20_000_000_000_000_000
        or _integer(display[1]["action"].get("amountWei")) != 10_000_000_000_000_000
        or len(_decoded_logs(display[1]).get("withdrawals", [])) != 1):
        return False
    return True


def _swap_has_no_conversion_logs(actions: list[dict[str, Any]]) -> bool:
    swaps = [item for item in actions if item["kind"] == "swap"]
    if not swaps:
        return False
    for item in swaps:
        logs = _decoded_logs(item)
        if logs.get("deposits") or logs.get("withdrawals"):
            return False
        tx = item["transaction"]
        if _integer(tx.get("value")) != 0:
            return False
        effects = item["payload"].get("effects", {})
        receipt = item["receipt"]
        gas_cost = (_integer(receipt.get("gasUsed")) or 0) * (_integer(receipt.get("effectiveGasPrice")) or 0)
        if _integer(effects.get("payerNativeWei")) != -gas_cost:
            return False
    return True

