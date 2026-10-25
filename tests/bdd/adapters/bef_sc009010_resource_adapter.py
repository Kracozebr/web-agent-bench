"""Ignored SC009/010 evidence-predicate draft.

This module deliberately consumes only hash-indexed raw HTTP, RPC, and
read-only database artifacts.  The scenario report is a pointer map, never a
set of pass/fail claims.  It is not imported by the frozen BDD adapter yet.
"""

from __future__ import annotations

import json
import re
from typing import Any


SC009_VARIANTS = frozenset({
    "concurrent_operations",
    "foreign_environment_reference",
    "reset_other_instance",
})
SC010_VARIANTS = frozenset({
    "late_worker",
    "previous_payment_nonce",
    "stale_delivery_record",
    "reused_operation_namespace",
})

_CHAIN_READ_KEYS = frozenset({
    "chainId", "head",
    "payerNative", "payerNonce", "facilitatorNative", "facilitatorNonce",
    "donorNative", "donorNonce", "donorUsdc", "payerWeth", "payerUsdc",
    "facilitatorUsdc", "recipientUsdc", "poolWeth", "poolUsdc",
    "wethRouterAllowance", "usdcRouterAllowance",
    "usdcCode", "usdcImplementationCode", "wethCode", "factoryCode",
    "routerCode", "quoterCode", "poolCode", "poolLiquidity", "poolSlot0",
})
_SERVICE_QUERY_NAMES = frozenset({
    "generation-by-id", "operations-by-generation", "payments-by-operation",
    "deliveries-by-operation", "denials-by-generation",
    "x402-observations-by-operation", "selected-execution-by-generation",
    "selected-execution-events-by-generation",
})
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_DIGEST_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")


def _items(evidence: Any) -> tuple[Any, ...]:
    value = getattr(evidence, "artifacts", ())
    return tuple(value) if isinstance(value, (tuple, list)) else ()


def _payload(item: Any) -> dict[str, Any]:
    value = getattr(item, "payload", None)
    return value if isinstance(value, dict) else {}


def _path(item: Any) -> str | None:
    value = getattr(item, "relative_path", None)
    return value if isinstance(value, str) else None


def _sha(item: Any) -> str | None:
    value = getattr(item, "sha256", None)
    return value.lower() if isinstance(value, str) else None


def _boundary(item: Any) -> str | None:
    value = getattr(item, "boundary", None)
    return value if isinstance(value, str) else None


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.fullmatch(value))


def _ref_item(evidence: Any, ref: Any, boundary: str, schema: str) -> Any | None:
    if not isinstance(ref, dict):
        return None
    path, digest = ref.get("path"), ref.get("sha256")
    if not isinstance(path, str) or not _is_digest(digest):
        return None
    matches = [item for item in _items(evidence) if _path(item) == path]
    if len(matches) != 1:
        return None
    item = matches[0]
    payload = _payload(item)
    if (_sha(item) != str(digest).lower() or _boundary(item) != boundary
            or payload.get("schemaVersion") != schema or payload.get("boundary") != boundary):
        return None
    return item


def _ref(item: Any) -> dict[str, str]:
    path, digest = _path(item), _sha(item)
    if path is None or digest is None:
        return {}
    return {"path": path, "sha256": digest}


def _manifest_envs(evidence: Any) -> tuple[str, str] | None:
    manifest = getattr(evidence, "manifest", None)
    local = manifest.get("local") if isinstance(manifest, dict) else None
    raw = local.get("environments") if isinstance(local, dict) else None
    if not isinstance(raw, list):
        return None
    ids = [item.get("id") for item in raw if isinstance(item, dict)]
    if len(ids) != 2 or any(not isinstance(item, str) or not item for item in ids) or len(set(ids)) != 2:
        return None
    return ids[0], ids[1]


def _scenario_report(evidence: Any, scenario_id: str) -> dict[str, Any] | None:
    found = [
        _payload(item) for item in _items(evidence)
        if _payload(item).get("schemaVersion") == "bef-sc009010-checkpoint-index/v1"
        and _payload(item).get("scenarioId") == scenario_id
        and _boundary(item) == "scenario-report"
    ]
    if len(found) != 1 or found[0].get("boundary") != "scenario-report":
        return None
    return found[0]


def _checkpoint_map(evidence: Any, scenario_id: str) -> dict[tuple[str, str], dict[str, Any]] | None:
    report = _scenario_report(evidence, scenario_id)
    checkpoints = report.get("checkpoints") if isinstance(report, dict) else None
    if not isinstance(checkpoints, list) or not checkpoints:
        return None
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for row in checkpoints:
        if not isinstance(row, dict):
            return None
        phase, env_id, generation_id = row.get("phase"), row.get("environmentId"), row.get("generationId")
        if not all(isinstance(value, str) and value for value in (phase, env_id, generation_id)):
            return None
        if (phase == "reset") != isinstance(row.get("resetRequest"), dict):
            return None
        key = (phase, env_id)
        if key in result:
            return None
        chain = _ref_item(evidence, row.get("chainSnapshot"), "local-chain-readonly-proxy", "bef-sc009010-chain-snapshot/v1")
        service = _ref_item(evidence, row.get("serviceSnapshot"), "readonly-database", "bef-sc009010-service-snapshot/v1")
        if chain is None or service is None:
            return None
        chain_payload, service_payload = _payload(chain), _payload(service)
        for payload in (chain_payload, service_payload):
            if payload.get("environmentId") != env_id or payload.get("generationId") != generation_id or payload.get("phase") != phase:
                return None
        result[key] = {
            "generationId": generation_id,
            "chain": chain_payload,
            "service": service_payload,
            "rawCheckpoint": row,
            "chainArtifactPath": _path(chain),
            "serviceArtifactPath": _path(service),
        }
    return result


def _one_rpc(evidence: Any, snapshot: dict[str, Any], key: str, method: str,
             params_ok: Any) -> dict[str, Any] | None:
    reads = snapshot.get("reads")
    ref = reads.get(key) if isinstance(reads, dict) else None
    item = _ref_item(evidence, ref, "local-chain-readonly-proxy", "bef-rpc-observation/v1")
    if item is None:
        return None
    payload = _payload(item)
    env_id = snapshot.get("environmentId")
    envs = _manifest_envs(evidence)
    bindings = _endpoint_bindings(evidence, (env_id,)) if envs is not None and isinstance(env_id, str) else None
    binding = bindings.get(env_id) if bindings is not None and isinstance(env_id, str) else None
    if (payload.get("endpointBoundary") != "local-chain-readonly-proxy"
            or payload.get("environmentId") != env_id
            or binding is None
            or payload.get("endpointIdentityArtifact") != binding["identityArtifact"]
            or payload.get("endpointRef") != binding["endpointRef"]
            or payload.get("operationId") is not None or payload.get("variantId") is not None
            or payload.get("method") != method or not params_ok(payload.get("params"))
            or "error" in (payload.get("result") if isinstance(payload.get("result"), dict) else {})):
        return None
    return payload


def _latest_address_call(params: Any, address: Any) -> bool:
    return (isinstance(params, list) and len(params) == 2 and isinstance(params[0], str)
            and params[0].lower() == str(address).lower() and params[1] == "latest")


def _call_data(params: Any, to: Any, selector: str, args: list[str]) -> bool:
    if not isinstance(params, list) or len(params) != 2 or params[1] != "latest" or not isinstance(params[0], dict):
        return False
    call = params[0]
    data = call.get("data")
    if not isinstance(data, str) or not data.lower().startswith(selector.lower()):
        return False
    if not isinstance(call.get("to"), str) or call["to"].lower() != str(to).lower():
        return False
    expected = selector.lower() + "".join(arg.lower().removeprefix("0x").zfill(64) for arg in args)
    return data.lower() == expected


def _valid_result(value: Any) -> bool:
    return isinstance(value, str) and bool(_QUANTITY_RE.fullmatch(value))


def _valid_abi_uint_word(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", value))


def _expected_chain_reads(evidence: Any, snapshot: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    addresses = snapshot.get("addresses")
    if not isinstance(addresses, dict):
        return None
    manifest = getattr(evidence, "manifest", None)
    contracts = manifest.get("contracts") if isinstance(manifest, dict) else None
    funding = manifest.get("funding") if isinstance(manifest, dict) else None
    if not isinstance(contracts, dict) or not isinstance(funding, dict):
        return None

    roles = {key: addresses.get(key) for key in ("payer", "facilitator", "donor", "recipient")}
    if any(not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value) for value in roles.values()):
        return None
    expected_addresses = {
        "weth": contracts.get("weth", {}).get("address") if isinstance(contracts.get("weth"), dict) else None,
        "usdc": contracts.get("usdc", {}).get("address") if isinstance(contracts.get("usdc"), dict) else None,
        "usdcImplementation": contracts.get("usdc", {}).get("implementation") if isinstance(contracts.get("usdc"), dict) else None,
        "factory": contracts.get("factory", {}).get("address") if isinstance(contracts.get("factory"), dict) else None,
        "router": contracts.get("swapRouter02", {}).get("address") if isinstance(contracts.get("swapRouter02"), dict) else None,
        "quoter": contracts.get("quoterV2", {}).get("address") if isinstance(contracts.get("quoterV2"), dict) else None,
        "pool": contracts.get("pool", {}).get("address") if isinstance(contracts.get("pool"), dict) else None,
    }
    if any(not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value) for value in expected_addresses.values()):
        return None
    if roles["donor"].lower() != str(funding.get("donor", "")).lower():
        return None
    if any(addresses.get(key, expected_addresses.get(key)) is not None
           and str(addresses.get(key, expected_addresses.get(key))).lower() != str(value).lower()
           for key, value in expected_addresses.items()):
        return None
    if set(snapshot.get("reads", {})) != _CHAIN_READ_KEYS:
        return None

    params: dict[str, tuple[str, Any]] = {
        "chainId": ("eth_chainId", lambda p: isinstance(p, list) and p == []),
        "head": ("eth_getBlockByNumber", lambda p: isinstance(p, list) and p == ["latest", False]),
        "payerNative": ("eth_getBalance", lambda p: _latest_address_call(p, roles["payer"])),
        "payerNonce": ("eth_getTransactionCount", lambda p: _latest_address_call(p, roles["payer"])),
        "facilitatorNative": ("eth_getBalance", lambda p: _latest_address_call(p, roles["facilitator"])),
        "facilitatorNonce": ("eth_getTransactionCount", lambda p: _latest_address_call(p, roles["facilitator"])),
        "donorNative": ("eth_getBalance", lambda p: _latest_address_call(p, roles["donor"])),
        "donorNonce": ("eth_getTransactionCount", lambda p: _latest_address_call(p, roles["donor"])),
        "donorUsdc": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0x70a08231", [roles["donor"]])),
        "payerWeth": ("eth_call", lambda p: _call_data(p, expected_addresses["weth"], "0x70a08231", [roles["payer"]])),
        "payerUsdc": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0x70a08231", [roles["payer"]])),
        "facilitatorUsdc": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0x70a08231", [roles["facilitator"]])),
        "recipientUsdc": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0x70a08231", [roles["recipient"]])),
        "poolWeth": ("eth_call", lambda p: _call_data(p, expected_addresses["weth"], "0x70a08231", [expected_addresses["pool"]])),
        "poolUsdc": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0x70a08231", [expected_addresses["pool"]])),
        "wethRouterAllowance": ("eth_call", lambda p: _call_data(p, expected_addresses["weth"], "0xdd62ed3e", [roles["payer"], expected_addresses["router"]])),
        "usdcRouterAllowance": ("eth_call", lambda p: _call_data(p, expected_addresses["usdc"], "0xdd62ed3e", [roles["payer"], expected_addresses["router"]])),
        "usdcCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["usdc"])),
        "usdcImplementationCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["usdcImplementation"])),
        "wethCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["weth"])),
        "factoryCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["factory"])),
        "routerCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["router"])),
        "quoterCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["quoter"])),
        "poolCode": ("eth_getCode", lambda p: _latest_address_call(p, expected_addresses["pool"])),
        "poolLiquidity": ("eth_call", lambda p: _call_data(p, expected_addresses["pool"], "0x1a686502", [])),
        "poolSlot0": ("eth_call", lambda p: _call_data(p, expected_addresses["pool"], "0x3850c7bd", [])),
    }
    out: dict[str, dict[str, Any]] = {}
    for key, (method, params_ok) in params.items():
        payload = _one_rpc(evidence, snapshot, key, method, params_ok)
        if payload is None:
            return None
        result = payload.get("result")
        if key == "head":
            if not isinstance(result, dict) or not all(_valid_result(result.get(name)) for name in ("number", "timestamp", "gasLimit")):
                return None
            if not _is_digest(result.get("hash")) or result.get("baseFeePerGas") is not None and not _valid_result(result.get("baseFeePerGas")):
                return None
            out[key] = {name: result.get(name) for name in ("number", "hash", "timestamp", "baseFeePerGas", "gasLimit")}
        elif key.endswith("Code"):
            if not isinstance(result, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", result):
                return None
            out[key] = result.lower()
        elif key == "poolSlot0":
            if not isinstance(result, str) or not re.fullmatch(r"0x[0-9a-fA-F]{448}", result):
                return None
            out[key] = result.lower()
        elif key in {
            "donorUsdc", "payerWeth", "payerUsdc", "facilitatorUsdc", "recipientUsdc",
            "poolWeth", "poolUsdc", "wethRouterAllowance", "usdcRouterAllowance", "poolLiquidity",
        }:
            if not _valid_abi_uint_word(result):
                return None
            out[key] = int(result, 16)
        elif not _valid_result(result):
            return None
        else:
            out[key] = int(result, 16)
    return out


def _service_tables(evidence: Any, snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]] | None:
    raw = snapshot.get("tables")
    if not isinstance(raw, dict) or set(raw) != _SERVICE_QUERY_NAMES:
        return None
    result: dict[str, list[dict[str, Any]]] = {}
    for query_name, ref in raw.items():
        item = _ref_item(evidence, ref, "readonly-database", "bef-db-observation/v1")
        if item is None:
            return None
        payload = _payload(item)
        rows = payload.get("rows")
        role = payload.get("databaseRole")
        if (payload.get("readOnly") is not True or payload.get("transactionReadOnly") != "on"
                or role != "bef_observer" or payload.get("queryName") != query_name
                or payload.get("observationScope") != "generation"
                or payload.get("envId") != snapshot.get("environmentId")
                or payload.get("generationId") != snapshot.get("generationId")
                or not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows)):
            return None
        result[query_name] = rows

    # Recheck the identities carried by the actual result rows. The top-level
    # scope fields bind the query artifact; they do not bind each returned row.
    env_id, generation_id = snapshot.get("environmentId"), snapshot.get("generationId")
    scoped_names = (
        "generation-by-id", "operations-by-generation", "payments-by-operation",
        "denials-by-generation", "x402-observations-by-operation",
        "selected-execution-by-generation", "selected-execution-events-by-generation",
    )
    for name in scoped_names:
        for row in result[name]:
            if row.get("env_id") != env_id or str(row.get("generation_id")) != str(generation_id):
                return None
    if len(result["generation-by-id"]) != 1:
        return None

    operation_ids = _ids(result["operations-by-generation"], "operation_id")
    for name in (
        "payments-by-operation", "deliveries-by-operation", "x402-observations-by-operation",
        "selected-execution-by-generation", "selected-execution-events-by-generation",
    ):
        if any(str(row.get("operation_id")) not in operation_ids for row in result[name]):
            return None
    if any(row.get("operation_id") is not None and str(row.get("operation_id")) not in operation_ids
           for row in result["denials-by-generation"]):
        return None
    return result


def _logical_chain(state: dict[str, Any], *, keep_head_identity: bool = False) -> dict[str, Any]:
    result = dict(state)
    head = result.get("head")
    if isinstance(head, dict):
        head = dict(head)
        if not keep_head_identity:
            head.pop("number", None)
            head.pop("hash", None)
        result["head"] = head
    return result


def _logical_tables(tables: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {key: rows for key, rows in tables.items() if key != "denials-by-generation"}


def _fixture_hash(tables: dict[str, list[dict[str, Any]]]) -> str | None:
    rows = tables.get("generation-by-id", [])
    if len(rows) != 1:
        return None
    value = rows[0].get("fixture_hash")
    return value.lower() if _is_digest(value) else None


def _ids(rows: list[dict[str, Any]], key: str) -> set[str]:
    return {str(row[key]) for row in rows if row.get(key) is not None}


def _has_successful_execution(tables: dict[str, list[dict[str, Any]]]) -> bool:
    operations = tables.get("operations-by-generation", [])
    payments = tables.get("payments-by-operation", [])
    deliveries = tables.get("deliveries-by-operation", [])
    executions = tables.get("selected-execution-by-generation", [])
    op_ids = _ids(operations, "operation_id")
    paid = [row for row in payments if str(row.get("operation_id")) in op_ids
            and row.get("receipt_status") == "success" and _is_digest(row.get("transaction_hash"))]
    delivered = [row for row in deliveries if str(row.get("operation_id")) in op_ids
                 and _is_digest(row.get("content_sha256"))]
    actions = {str(row.get("action_kind")) for row in executions
               if str(row.get("operation_id")) in op_ids and row.get("outcome") == "success"}
    return bool(paid and delivered and {"wrap", "approve", "swap"}.issubset(actions))


def _receipt_payload_for_operation(evidence: Any, operation_id: str, transaction_hash: Any,
                                   environment_id: str | None) -> dict[str, Any] | None:
    if (not isinstance(transaction_hash, str) or not _is_digest(transaction_hash)
            or not isinstance(environment_id, str)):
        return None
    envs = _manifest_envs(evidence)
    bindings = _endpoint_bindings(evidence, (environment_id,)) if envs is not None else None
    binding = bindings.get(environment_id) if bindings is not None else None
    if binding is None:
        return None
    matches: list[dict[str, Any]] = []
    for item in _items(evidence):
        payload = _payload(item)
        if (_boundary(item) != "local-chain-readonly-proxy"
                or payload.get("schemaVersion") != "bef-rpc-observation/v1"
                or payload.get("method") != "eth_getTransactionReceipt"
                or payload.get("operationId") != operation_id
                or payload.get("endpointBoundary") != "local-chain-readonly-proxy"
                or payload.get("environmentId") != environment_id):
            continue
        params, receipt = payload.get("params"), payload.get("result")
        if (isinstance(params, list) and params == [transaction_hash]
                and isinstance(receipt, dict)
                and isinstance(receipt.get("transactionHash"), str)
                and receipt["transactionHash"].lower() == transaction_hash.lower()):
            matches.append(payload)
    if len(matches) != 1:
        return None
    payload = matches[0]
    receipt = payload.get("result")
    if (payload.get("endpointIdentityArtifact") != binding["identityArtifact"]
            or payload.get("endpointRef") != binding["endpointRef"]
            or not isinstance(receipt, dict)
            or str(receipt.get("status", "")).lower() not in {"0x1", "1"}):
        return None
    return payload


def _receipt_bound_to_operation(evidence: Any, operation_id: str, transaction_hash: Any,
                                environment_id: str | None = None) -> bool:
    return _receipt_payload_for_operation(evidence, operation_id, transaction_hash, environment_id) is not None


def _successful_purchase_rows(evidence: Any, tables: dict[str, list[dict[str, Any]]], env_id: str,
                              generation_id: str) -> bool:
    operations = tables.get("operations-by-generation", [])
    payments = tables.get("payments-by-operation", [])
    deliveries = tables.get("deliveries-by-operation", [])
    purchases = [row for row in operations
        if str(row.get("operation_kind", "")).lower() == "purchase"
        and row.get("env_id") == env_id and str(row.get("generation_id")) == generation_id
        and row.get("status") == "delivered" and row.get("receipt_status") == "success"
        and _is_digest(row.get("transaction_hash"))]
    if len(purchases) != 1:
        return False
    purchase = purchases[0]
    operation_id = str(purchase.get("operation_id"))
    matching_payments = [row for row in payments if str(row.get("operation_id")) == operation_id
        and row.get("env_id") == env_id and str(row.get("generation_id")) == generation_id
        and row.get("receipt_status") == "success"
        and str(row.get("transaction_hash", "")).lower() == str(purchase.get("transaction_hash", "")).lower()]
    matching_deliveries = [row for row in deliveries if str(row.get("operation_id")) == operation_id
        and _is_digest(row.get("content_sha256"))]
    manifest = getattr(evidence, "manifest", None)
    x402 = manifest.get("x402") if isinstance(manifest, dict) else None
    expected_hash = x402.get("resourceSha256") if isinstance(x402, dict) else None
    expected_resource_id = x402.get("resourceId") if isinstance(x402, dict) else None
    delivery_ok = (len(matching_deliveries) == 1
        and _is_digest(expected_hash)
        and str(matching_deliveries[0].get("content_sha256", "")).lower() == str(expected_hash).lower()
        and (expected_resource_id is None or matching_deliveries[0].get("resource_id") == expected_resource_id))
    paid_http = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if request.get("method") == "POST"
        and request.get("path") == f"/tools/{env_id}/purchase"
        and _headers_generation(request) == generation_id
        and _operation_id(item, response) == operation_id
        and response.get("status") == 200
    ]
    canonical_request_ok = (
        isinstance(expected_resource_id, str) and bool(expected_resource_id)
        and len(paid_http) == 1
        and paid_http[0][1].get("body") == {"resourceId": expected_resource_id, "offerId": "canonical"}
    )
    return (len(matching_payments) == 1 and delivery_ok
        and canonical_request_ok
        and _receipt_bound_to_operation(evidence, operation_id, purchase.get("transaction_hash"), env_id))


def _successful_selected_actions(evidence: Any, tables: dict[str, list[dict[str, Any]]], env_id: str,
                                 generation_id: str) -> bool:
    expected_actions = {"wrap", "approve", "swap"}
    selected = tables.get("selected-execution-by-generation", [])
    operations = tables.get("operations-by-generation", [])
    events = tables.get("selected-execution-events-by-generation", [])
    if len(selected) != len(expected_actions):
        return False
    action_rows = {str(row.get("action_kind")): row for row in selected}
    operation_rows = {str(row.get("operation_id")): row for row in operations}
    if set(action_rows) != expected_actions:
        return False
    required_event_kinds = {
        "selected_action_bound", "prestate_observed", "original_tx_hash_bound", "receipt_finalized",
    }
    for action in expected_actions:
        selected_row = action_rows[action]
        operation_id = selected_row.get("operation_id")
        operation = operation_rows.get(str(operation_id))
        transaction_hash = selected_row.get("transaction_hash")
        if (
            not isinstance(operation_id, str)
            or not isinstance(operation, dict)
            or selected_row.get("env_id") != env_id
            or str(selected_row.get("generation_id")) != str(generation_id)
            or selected_row.get("outcome") != "success"
            or operation.get("env_id") != env_id
            or str(operation.get("generation_id")) != str(generation_id)
            or str(operation.get("operation_kind", "")).lower() != action
            or operation.get("status") != "settled"
            or operation.get("receipt_status") != "success"
            or not _is_digest(transaction_hash)
            or str(operation.get("transaction_hash", "")).lower() != transaction_hash.lower()
            or not _receipt_bound_to_operation(evidence, operation_id, transaction_hash, env_id)
        ):
            return False
        action_events = [row for row in events if str(row.get("operation_id")) == operation_id]
        kinds = [row.get("event_kind") for row in action_events]
        sequences = [row.get("event_sequence") for row in action_events]
        try:
            numeric_sequences = [int(value) for value in sequences]
        except (TypeError, ValueError):
            return False
        if (
            len(action_events) != len(required_event_kinds)
            or set(kinds) != required_event_kinds
            or any(row.get("env_id") != env_id or str(row.get("generation_id")) != str(generation_id)
                   for row in action_events)
            or len(set(numeric_sequences)) != len(required_event_kinds)
            or any(value <= 0 for value in numeric_sequences)
            or any(not isinstance(row.get("event_id"), str) or not row["event_id"] for row in action_events)
            or any(row.get("transaction_hash") not in (None, transaction_hash)
                   for row in action_events)
        ):
            return False
    return True


def _has_empty_trial_namespace(tables: dict[str, list[dict[str, Any]]]) -> bool:
    return all(not tables.get(name, []) for name in (
        "operations-by-generation", "payments-by-operation", "deliveries-by-operation",
        "x402-observations-by-operation", "selected-execution-by-generation",
        "selected-execution-events-by-generation",
    ))


def _http_records(evidence: Any) -> list[tuple[Any, dict[str, Any], dict[str, Any]]]:
    out = []
    for item in _items(evidence):
        payload = _payload(item)
        if _boundary(item) not in {"actual-tool-http", "private-admin-http", "admin-http"}:
            continue
        request, response = payload.get("request"), payload.get("response")
        if isinstance(request, dict) and isinstance(response, dict):
            out.append((item, request, response))
    return out


def _checkpoint_reset(evidence: Any, checkpoint: dict[str, Any], env_id: str) -> Any | None:
    """Resolve the reset explicitly joined to this checkpoint, never by label or loose status."""
    raw = checkpoint.get("rawCheckpoint")
    ref = raw.get("resetRequest") if isinstance(raw, dict) else None
    item = _ref_item(evidence, ref, "private-admin-http", "bef-http-observation/v1")
    if item is None:
        return None
    payload = _payload(item)
    request, response = payload.get("request"), payload.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        return None
    request_headers = {str(key).lower(): value for key, value in (request.get("headers") or {}).items()} \
        if isinstance(request.get("headers"), dict) else {}
    body = _body(response)
    if (
        payload.get("operationId") is not None
        or payload.get("variantId") is not None
        or request.get("method") != "POST"
        or request.get("path") != f"/internal/admin/environments/{env_id}/reset"
        or request.get("body") not in (None, {})
        or request_headers.get("x-bef-admin-key-present") is not True
        or "authorization" in request_headers
        or response.get("status") != 200
        or body.get("status") != "reset"
        or body.get("envId") != env_id
    ):
        return None
    return item


def _artifact_index(evidence: Any, path: Any) -> int | None:
    if not isinstance(path, str):
        return None
    matches = [index for index, item in enumerate(_items(evidence)) if _path(item) == path]
    return matches[0] if len(matches) == 1 else None


def _reset_between_checkpoints(evidence: Any, reset_item: Any,
                               before: dict[str, Any], after: dict[str, Any]) -> bool:
    reset_index = _artifact_index(evidence, _path(reset_item))
    before_index = _artifact_index(evidence, before.get("chainArtifactPath"))
    after_index = _artifact_index(evidence, after.get("chainArtifactPath"))
    return (reset_index is not None and before_index is not None and after_index is not None
            and before_index < reset_index < after_index)


def _admin_resets_between(evidence: Any, env_id: str, before: dict[str, Any],
                          after: dict[str, Any]) -> list[Any]:
    before_index = _artifact_index(evidence, before.get("chainArtifactPath"))
    after_index = _artifact_index(evidence, after.get("chainArtifactPath"))
    if before_index is None or after_index is None or before_index >= after_index:
        return []
    matches = []
    for item, request, _response in _http_records(evidence):
        index = _artifact_index(evidence, _path(item))
        if (_boundary(item) == "private-admin-http"
                and request.get("method") == "POST"
                and request.get("path") == f"/internal/admin/environments/{env_id}/reset"
                and index is not None and before_index < index < after_index):
            matches.append(item)
    return matches


def _stale_operation_has_no_rpc_effect(evidence: Any, item: Any, response: dict[str, Any]) -> bool:
    operation_id = _operation_id(item, response)
    variant_id = _payload(item).get("variantId")
    return not any(
        _boundary(rpc) == "local-chain-readonly-proxy"
        and ((operation_id is not None and _payload(rpc).get("operationId") == operation_id)
             or (isinstance(variant_id, str) and _payload(rpc).get("variantId") == variant_id))
        for rpc in _items(evidence)
    )


def _body(response: dict[str, Any]) -> dict[str, Any]:
    value = response.get("body")
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _operation_id(item: Any, response: dict[str, Any] | None = None) -> str | None:
    value = _payload(item).get("operationId")
    if isinstance(value, str) and value:
        return value
    if response is not None:
        value = _body(response).get("operationId")
        if isinstance(value, str) and value:
            return value
    return None


def _denied(response: dict[str, Any]) -> bool:
    status = response.get("status")
    return isinstance(status, int) and 400 <= status < 500


def _generation_scope_denied(response: dict[str, Any]) -> bool:
    return response.get("status") == 403 and _body(response).get("error") == "generation_scope_denied"


def _endpoint_bindings(evidence: Any, expected_envs: tuple[str, ...]) -> dict[str, dict[str, Any]] | None:
    if not expected_envs or any(not isinstance(env, str) or not env for env in expected_envs):
        return None
    if len(set(expected_envs)) != len(expected_envs):
        return None
    binding_items: dict[str, Any] = {}
    for item in _items(evidence):
        payload = _payload(item)
        if payload.get("schemaVersion") != "bef-rpc-endpoint-binding/v1":
            continue
        if (_boundary(item) != "local-chain-readonly-proxy"
                or payload.get("boundary") != "local-chain-readonly-proxy"):
            return None
        env_id = payload.get("environmentId")
        if env_id not in expected_envs:
            configured_envs = _manifest_envs(evidence)
            if configured_envs is not None and env_id in configured_envs:
                continue
            return None
        if env_id in binding_items:
            return None
        binding_items[env_id] = item
    if set(binding_items) != set(expected_envs):
        return None

    manifest_sha = getattr(evidence, "manifest_sha256", None)
    if not _is_digest(manifest_sha):
        return None
    result: dict[str, dict[str, Any]] = {}
    endpoint_refs: list[dict[str, Any]] = []
    for env_id in expected_envs:
        item = binding_items[env_id]
        payload = _payload(item)
        identity_path = f"rpc/endpoint-binding-{env_id}.json"
        endpoint_ref = payload.get("endpointRef")
        endpoint_host = endpoint_ref.get("host") if isinstance(endpoint_ref, dict) else None
        if (_path(item) != identity_path
                or payload.get("operationId") is not None or payload.get("variantId") is not None
                or not isinstance(endpoint_ref, dict)
                or set(endpoint_ref) != {"scheme", "host", "port"}
                or endpoint_ref.get("scheme") != "http"
                or not isinstance(endpoint_host, str)
                or endpoint_host not in {"localhost", "127.0.0.1", "::1", "[::1]"}
                or not isinstance(endpoint_ref.get("port"), int)
                or isinstance(endpoint_ref.get("port"), bool)
                or not 1 <= endpoint_ref["port"] <= 65535):
            return None

        health_path = payload.get("healthArtifactPath")
        health_digest = payload.get("healthArtifactSha256")
        if (health_path != f"rpc/endpoint-health-{env_id}.json" or not _is_digest(health_digest)):
            return None
        health_matches = [candidate for candidate in _items(evidence) if _path(candidate) == health_path]
        if len(health_matches) != 1:
            return None
        health_item = health_matches[0]
        health = _payload(health_item)
        if (_boundary(health_item) != "local-chain-readonly-proxy"
                or _sha(health_item) != str(health_digest).lower()
                or health != payload.get("health")
                or set(health) != {"status", "boundary", "envId", "manifestSha256"}
                or health.get("status") != "ok"
                or health.get("boundary") != "local-chain-readonly-proxy"
                or health.get("envId") != env_id
                or not _is_digest(health.get("manifestSha256"))
                or str(health.get("manifestSha256")).lower() != str(manifest_sha).lower()):
            return None
        result[env_id] = {
            "identityArtifact": identity_path,
            "endpointRef": endpoint_ref,
            "healthArtifactPath": health_path,
            "healthArtifactSha256": str(health_digest).lower(),
        }
        endpoint_refs.append(endpoint_ref)
    endpoint_keys = {
        (ref["scheme"], "loopback", ref["port"])
        for ref in endpoint_refs
    }
    if len(endpoint_keys) != len(endpoint_refs):
        return None
    return result


def _unique_endpoint_refs(evidence: Any, expected_envs: tuple[str, str]) -> bool:
    return _endpoint_bindings(evidence, expected_envs) is not None


def _exact_variants(evidence: Any, expected: frozenset[str]) -> bool:
    observed = {
        payload.get("variantId") for item in _items(evidence)
        if isinstance((payload := _payload(item)).get("variantId"), str)
    }
    return observed == set(expected)


def _checkpoint(evidence: Any, scenario_id: str, phase: str, env_id: str,
                checkpoints: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any] | None:
    return checkpoints.get((phase, env_id))


def _sc009(evidence: Any) -> dict[str, bool]:
    envs = _manifest_envs(evidence)
    checkpoints = _checkpoint_map(evidence, "BEF-SC-009")
    if envs is None or checkpoints is None:
        return {"independent_chain_state": False, "independent_service_state": False,
                "reset_not_crossing_boundary": False, "foreign_access_denied": False}
    env_a, env_b = envs
    required_checkpoints = {
        ("baseline", envs[0]), ("mutated", envs[0]), ("reset", envs[0]),
        ("baseline", envs[1]), ("mutated", envs[1]), ("after_reset", envs[1]),
    }
    if set(checkpoints) != required_checkpoints:
        return {"independent_chain_state": False, "independent_service_state": False,
                "reset_not_crossing_boundary": False, "foreign_access_denied": False}
    parsed_chain: dict[tuple[str, str], dict[str, Any]] = {}
    parsed_service: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = {}
    for key, row in checkpoints.items():
        chain = _expected_chain_reads(evidence, row["chain"])
        tables = _service_tables(evidence, row["service"])
        if chain is None or tables is None:
            return {"independent_chain_state": False, "independent_service_state": False,
                    "reset_not_crossing_boundary": False, "foreign_access_denied": False}
        parsed_chain[key], parsed_service[key] = chain, tables

    base_a, base_b = parsed_chain[("baseline", env_a)], parsed_chain[("baseline", env_b)]
    mut_a, mut_b = parsed_chain[("mutated", env_a)], parsed_chain[("mutated", env_b)]
    reset_a, post_b = parsed_chain[("reset", env_a)], parsed_chain[("after_reset", env_b)]
    base_changed = (_logical_chain(base_a) != _logical_chain(mut_a)
                    and _logical_chain(base_b) != _logical_chain(mut_b))
    identities_ok = (_unique_endpoint_refs(evidence, envs)
                     and checkpoints[("baseline", env_a)]["generationId"] != checkpoints[("baseline", env_b)]["generationId"]
                     and checkpoints[("baseline", env_a)]["generationId"] != checkpoints[("reset", env_a)]["generationId"]
                     and checkpoints[("mutated", env_b)]["generationId"] == checkpoints[("after_reset", env_b)]["generationId"]
                     and parsed_service[("mutated", env_a)]["generation-by-id"][0].get("env_id") == env_a
                     and parsed_service[("mutated", env_b)]["generation-by-id"][0].get("env_id") == env_b
                     and not (_ids(parsed_service[("mutated", env_a)]["operations-by-generation"], "operation_id")
                              & _ids(parsed_service[("mutated", env_b)]["operations-by-generation"], "operation_id")))
    equivalent_start = _logical_chain(base_a) == _logical_chain(base_b)
    independent_chain = base_changed and identities_ok and equivalent_start and all(
        _has_successful_execution(parsed_service[("mutated", env_id)])
        and _successful_purchase_rows(evidence, parsed_service[("mutated", env_id)], env_id,
                                     checkpoints[("mutated", env_id)]["generationId"])
        and _successful_selected_actions(evidence, parsed_service[("mutated", env_id)], env_id,
                                         checkpoints[("mutated", env_id)]["generationId"])
        for env_id in envs
    )

    fixture_ok = (_fixture_hash(parsed_service[("baseline", env_a)]) is not None
                  and _fixture_hash(parsed_service[("baseline", env_a)]) == _fixture_hash(parsed_service[("mutated", env_a)])
                  and _fixture_hash(parsed_service[("baseline", env_a)]) == _fixture_hash(parsed_service[("reset", env_a)])
                  and _fixture_hash(parsed_service[("baseline", env_b)]) == _fixture_hash(parsed_service[("mutated", env_b)])
                  and _fixture_hash(parsed_service[("baseline", env_a)]) == _fixture_hash(parsed_service[("baseline", env_b)]))
    independent_service = (fixture_ok
        and _has_empty_trial_namespace(parsed_service[("baseline", env_a)])
        and _has_empty_trial_namespace(parsed_service[("baseline", env_b)])
        and all(_has_successful_execution(parsed_service[("mutated", env_id)])
                and _successful_purchase_rows(evidence, parsed_service[("mutated", env_id)], env_id,
                                             checkpoints[("mutated", env_id)]["generationId"])
                and _successful_selected_actions(evidence, parsed_service[("mutated", env_id)], env_id,
                                                 checkpoints[("mutated", env_id)]["generationId"])
                for env_id in envs)
        and _logical_tables(parsed_service[("mutated", env_b)]) == _logical_tables(parsed_service[("after_reset", env_b)]))

    reset_a_baseline = (_logical_chain(base_a) == _logical_chain(reset_a)
                        and _has_empty_trial_namespace(parsed_service[("reset", env_a)]))
    b_unchanged = (mut_b == post_b and _logical_tables(parsed_service[("mutated", env_b)])
                   == _logical_tables(parsed_service[("after_reset", env_b)]))
    reset_checkpoint = checkpoints[("reset", env_a)]
    reset_item = _checkpoint_reset(evidence, reset_checkpoint, env_a)
    reset_calls = _admin_resets_between(evidence, env_a, checkpoints[("mutated", env_a)], reset_checkpoint)
    reset_other_denied = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if _payload(item).get("variantId") == "reset_other_instance"
        and request.get("method") == "POST" and request.get("path") == f"/internal/admin/environments/{env_b}/reset"
        and _denied(response) and _operation_id(item, response) is None
        and _headers_generation(request) == checkpoints[("baseline", env_a)]["generationId"]
        and "x-bef-admin-key" not in _headers(request)
    ]
    foreign_denied = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if _payload(item).get("variantId") == "foreign_environment_reference"
        and request.get("method") == "GET" and request.get("path") == f"/tools/{env_b}/balances"
        and _denied(response) and _operation_id(item, response) is None
        and _headers_generation(request) == checkpoints[("baseline", env_a)]["generationId"]
    ]
    concurrent = []
    for item, request, response in _http_records(evidence):
        path = request.get("path")
        segments = path.split("/") if isinstance(path, str) else []
        if (_payload(item).get("variantId") == "concurrent_operations"
                and request.get("method") == "POST"
                and len(segments) == 4 and segments[1] == "tools"
                and segments[2] in envs and segments[3] in {"wrap", "approve", "swap"}
                and response.get("status") == 200 and _operation_id(item, response) is not None):
            concurrent.append((item, request, response, segments[2], segments[3]))
    expected_action_pairs = {(env_id, action) for env_id in envs for action in ("wrap", "approve", "swap")}
    observed_action_pairs = [(env_id, action) for _, _, _, env_id, action in concurrent]
    selected_ids = {
        (env_id, str(row.get("action_kind"))): str(row.get("operation_id"))
        for env_id in envs for row in parsed_service[("mutated", env_id)]["selected-execution-by-generation"]
    }
    action_binding = (
        len(concurrent) == len(expected_action_pairs)
        and set(observed_action_pairs) == expected_action_pairs
        and len(set(observed_action_pairs)) == len(observed_action_pairs)
        and all(_operation_id(item, response) == selected_ids.get((env_id, action))
                for item, _, response, env_id, action in concurrent)
        and all(_successful_selected_actions(evidence, parsed_service[("mutated", env_id)], env_id,
                                             checkpoints[("mutated", env_id)]["generationId"])
                for env_id in envs)
    )
    concurrent_envs = {env_id for _, _, _, env_id, _ in concurrent}
    variant_ok = _exact_variants(evidence, SC009_VARIANTS)
    reset_linked = (reset_item is not None and len(reset_calls) == 1 and reset_calls[0] is reset_item
        and _reset_between_checkpoints(evidence, reset_item, checkpoints[("mutated", env_a)], reset_checkpoint))
    foreign_access = (variant_ok and reset_linked
        and len(reset_other_denied) == 1 and len(foreign_denied) == 1 and concurrent_envs == set(envs)
        and action_binding)
    return {
        "independent_chain_state": bool(independent_chain),
        "independent_service_state": bool(independent_service),
        "reset_not_crossing_boundary": bool(reset_a_baseline and b_unchanged and reset_linked),
        "foreign_access_denied": bool(foreign_access),
    }


def _fee_uint(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _fee_record(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
        return decoded if isinstance(decoded, dict) else None
    return None


def _fee_policy(evidence: Any) -> tuple[int, int] | None:
    manifest = getattr(evidence, "manifest", None)
    policy = manifest.get("feePolicy") if isinstance(manifest, dict) else None
    if not isinstance(policy, dict):
        return None
    base_fee = _fee_uint(policy.get("baseFeeWei"))
    priority_fee = _fee_uint(policy.get("priorityFeeWei"))
    numerator = _fee_uint(policy.get("ethUsdcRateNumerator"))
    denominator = _fee_uint(policy.get("ethUsdcRateDenominator"))
    if (base_fee is None or priority_fee is None or numerator is None or denominator is None
            or base_fee <= 0 or priority_fee <= 0 or numerator <= 0 or denominator <= 0
            or policy.get("rounding") != "floor-to-6-decimal-usdc-units"
            or policy.get("baseL1Fee") != "unmodelled"
            or policy.get("principalSeparateFromExpense") is not True):
        return None
    return base_fee + priority_fee, priority_fee


def _fee_operation_set(tables: dict[str, list[dict[str, Any]]], env_id: str,
                       generation_id: str, snapshot: dict[str, Any]) -> dict[str, Any] | None:
    addresses = snapshot.get("addresses")
    if not isinstance(addresses, dict):
        return None
    payer, facilitator = addresses.get("payer"), addresses.get("facilitator")
    if (not isinstance(payer, str) or not _ADDRESS_RE.fullmatch(payer)
            or not isinstance(facilitator, str) or not _ADDRESS_RE.fullmatch(facilitator)):
        return None

    generation_rows = tables.get("generation-by-id")
    operations = tables.get("operations-by-generation")
    payments = tables.get("payments-by-operation")
    selected_rows = tables.get("selected-execution-by-generation")
    if not all(isinstance(rows, list) for rows in (generation_rows, operations, payments, selected_rows)):
        return None
    if len(generation_rows) != 1 or not isinstance(generation_rows[0], dict):
        return None
    generation = generation_rows[0]
    if (generation.get("env_id") != env_id or str(generation.get("generation_id")) != generation_id
            or str(generation.get("payer_address", "")).lower() != payer.lower()):
        return None

    if len(operations) != 4 or not all(isinstance(row, dict) for row in operations):
        return None
    by_kind: dict[str, dict[str, Any]] = {}
    op_ids: set[str] = set()
    for row in operations:
        kind = str(row.get("operation_kind", "")).lower()
        operation_id, tx_hash = row.get("operation_id"), row.get("transaction_hash")
        expected_status = "delivered" if kind == "purchase" else "settled"
        if (kind not in {"purchase", "wrap", "approve", "swap"} or kind in by_kind
                or not isinstance(operation_id, str) or not operation_id or operation_id in op_ids
                or row.get("env_id") != env_id or str(row.get("generation_id")) != generation_id
                or row.get("status") != expected_status or row.get("receipt_status") != "success"
                or not isinstance(tx_hash, str) or not _DIGEST_RE.fullmatch(tx_hash)):
            return None
        by_kind[kind] = row
        op_ids.add(operation_id)
    if set(by_kind) != {"purchase", "wrap", "approve", "swap"}:
        return None

    purchase = by_kind["purchase"]
    purchase_id, purchase_hash = purchase["operation_id"], purchase["transaction_hash"]
    if len(payments) != 1 or not isinstance(payments[0], dict):
        return None
    payment = payments[0]
    if (payment.get("operation_id") != purchase_id or payment.get("env_id") != env_id
            or str(payment.get("generation_id")) != generation_id or payment.get("receipt_status") != "success"
            or str(payment.get("transaction_hash", "")).lower() != purchase_hash.lower()
            or str(payment.get("payer_address", "")).lower() != payer.lower()
            or str(payment.get("facilitator_address", "")).lower() != facilitator.lower()):
        return None

    if len(selected_rows) != 3 or not all(isinstance(row, dict) for row in selected_rows):
        return None
    selected_by_kind: dict[str, dict[str, Any]] = {}
    for row in selected_rows:
        kind = str(row.get("action_kind", "")).lower()
        operation_id = row.get("operation_id")
        if (kind not in {"wrap", "approve", "swap"} or kind in selected_by_kind
                or row.get("outcome") != "success" or row.get("env_id") != env_id
                or str(row.get("generation_id")) != generation_id
                or operation_id != by_kind[kind].get("operation_id")
                or str(row.get("transaction_hash", "")).lower()
                    != str(by_kind[kind].get("transaction_hash", "")).lower()):
            return None
        action = _fee_record(row.get("selected_action_json"))
        if not isinstance(action, dict) or action.get("kind") != kind:
            return None
        gas_limit = _fee_uint(action.get("gasLimit"))
        if gas_limit is None or gas_limit <= 0:
            return None
        selected_by_kind[kind] = {"row": row, "gasLimit": gas_limit}
    if set(selected_by_kind) != {"wrap", "approve", "swap"}:
        return None
    return {
        "payer": payer,
        "facilitator": facilitator,
        "byKind": by_kind,
        "selectedByKind": selected_by_kind,
    }


def _fee_receipt_cost(evidence: Any, operation: dict[str, Any], expected_sender: str,
                      env_id: str, fee_cap: int, priority_fee: int,
                      gas_limit: int | None) -> int | None:
    operation_id, transaction_hash = operation.get("operation_id"), operation.get("transaction_hash")
    payload = _receipt_payload_for_operation(evidence, operation_id, transaction_hash, env_id)
    if (not isinstance(payload, dict) or payload.get("operationId") != operation_id
            or payload.get("environmentId") != env_id or payload.get("method") != "eth_getTransactionReceipt"):
        return None
    receipt = payload.get("result")
    if not isinstance(receipt, dict):
        return None
    gas_used = _fee_uint(receipt.get("gasUsed"))
    effective_price = _fee_uint(receipt.get("effectiveGasPrice"))
    status = _fee_uint(receipt.get("status"))
    if status is None and receipt.get("status") == "success":
        status = 1
    if (str(receipt.get("transactionHash", "")).lower() != str(transaction_hash).lower()
            or str(receipt.get("from", "")).lower() != expected_sender.lower()
            or status != 1 or gas_used is None or gas_used <= 0
            or effective_price is None or effective_price < priority_fee or effective_price > fee_cap
            or gas_limit is not None and gas_used > gas_limit):
        return None
    return gas_used * effective_price


def _fee_costs_for_generation(evidence: Any, tables: dict[str, list[dict[str, Any]]],
                              chain_snapshot: dict[str, Any], env_id: str,
                              generation_id: str, fee_cap: int,
                              priority_fee: int) -> dict[str, Any] | None:
    if (chain_snapshot.get("environmentId") != env_id
            or str(chain_snapshot.get("generationId")) != generation_id):
        return None
    parsed_chain = _expected_chain_reads(evidence, chain_snapshot)
    operation_set = _fee_operation_set(tables, env_id, generation_id, chain_snapshot)
    if not isinstance(parsed_chain, dict) or operation_set is None:
        return None

    costs = {"payer": 0, "facilitator": 0}
    seen_transactions: set[str] = set()
    for kind, operation in operation_set["byKind"].items():
        role = "facilitator" if kind == "purchase" else "payer"
        gas_limit = operation_set["selectedByKind"][kind]["gasLimit"] if kind != "purchase" else None
        fee = _fee_receipt_cost(
            evidence, operation, operation_set[role], env_id, fee_cap, priority_fee, gas_limit,
        )
        tx_hash = str(operation["transaction_hash"]).lower()
        if fee is None:
            return None
        if tx_hash in seen_transactions:
            return None
        seen_transactions.add(tx_hash)
        costs[role] += fee
    return {**costs, "parsedChain": parsed_chain}


def _fee_post_trial_signature(parsed_chain: dict[str, Any], costs: dict[str, Any]) -> dict[str, Any] | None:
    result = dict(parsed_chain)
    payer_native, facilitator_native = _fee_uint(result.get("payerNative")), _fee_uint(result.get("facilitatorNative"))
    head = result.get("head")
    if not isinstance(head, dict):
        return None
    gas_limit = _fee_uint(head.get("gasLimit"))
    if payer_native is None or facilitator_native is None or gas_limit is None or gas_limit <= 0:
        return None
    result["payerNative"] = payer_native + int(costs["payer"])
    result["facilitatorNative"] = facilitator_native + int(costs["facilitator"])
    normalized_head = dict(head)
    for field in ("number", "hash", "timestamp", "baseFeePerGas"):
        normalized_head.pop(field, None)
    normalized_head["gasLimit"] = gas_limit
    result["head"] = normalized_head
    return result


def sc010_fee_normalized_equivalent(
    evidence: Any,
    trial_tables: dict[str, list[dict[str, Any]]],
    fresh_tables: dict[str, list[dict[str, Any]]],
    trial_chain_snapshot: dict[str, Any],
    fresh_chain_snapshot: dict[str, Any],
    env_id: str,
    trial_generation_id: str,
    fresh_generation_id: str,
) -> bool:
    """Compare SC010 post-trial state after exact receipt gas is added back.

    Every purchase, wrap, approve, and swap operation needs one successful
    endpoint-bound receipt. Receipt gas fees normalize payer/facilitator native
    balances; transaction hash and gas price are counted once per transaction.
    Only post-trial block identity, timestamp and base fee are execution-dependent.
    """
    if (not isinstance(env_id, str) or not env_id
            or not isinstance(trial_generation_id, str) or not trial_generation_id
            or not isinstance(fresh_generation_id, str) or not fresh_generation_id
            or trial_generation_id == fresh_generation_id
            or not isinstance(trial_chain_snapshot, dict) or not isinstance(fresh_chain_snapshot, dict)):
        return False
    policy = _fee_policy(evidence)
    if policy is None:
        return False
    fee_cap, priority_fee = policy
    trial_costs = _fee_costs_for_generation(
        evidence, trial_tables, trial_chain_snapshot, env_id, trial_generation_id, fee_cap, priority_fee,
    )
    fresh_costs = _fee_costs_for_generation(
        evidence, fresh_tables, fresh_chain_snapshot, env_id, fresh_generation_id, fee_cap, priority_fee,
    )
    if trial_costs is None or fresh_costs is None:
        return False
    trial_signature = _fee_post_trial_signature(trial_costs["parsedChain"], trial_costs)
    fresh_signature = _fee_post_trial_signature(fresh_costs["parsedChain"], fresh_costs)
    return trial_signature is not None and trial_signature == fresh_signature


def _sc010(evidence: Any) -> dict[str, bool]:
    envs = _manifest_envs(evidence)
    checkpoints = _checkpoint_map(evidence, "BEF-SC-010")
    names = ("baseline", "trial", "reset", "after_stale", "fresh_trial")
    if envs is None or checkpoints is None:
        return {"stale_generation_fenced": False, "chain_baseline": False, "service_baseline": False,
                "fixture_hash": False, "equivalent_probe_outcome": False}
    env_id = envs[0]
    if set(checkpoints) != {(phase, env_id) for phase in names}:
        return {"stale_generation_fenced": False, "chain_baseline": False, "service_baseline": False,
                "fixture_hash": False, "equivalent_probe_outcome": False}
    chains: dict[str, dict[str, Any]] = {}
    tables: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for phase in names:
        row = checkpoints[(phase, env_id)]
        chain, service = _expected_chain_reads(evidence, row["chain"]), _service_tables(evidence, row["service"])
        if chain is None or service is None:
            return {"stale_generation_fenced": False, "chain_baseline": False, "service_baseline": False,
                    "fixture_hash": False, "equivalent_probe_outcome": False}
        chains[phase], tables[phase] = chain, service

    report = _scenario_report(evidence, "BEF-SC-010")
    old_after_ref = report.get("oldGenerationAfterStaleServiceSnapshot") if isinstance(report, dict) else None
    old_after_item = _ref_item(evidence, old_after_ref, "readonly-database", "bef-sc009010-service-snapshot/v1")
    old_after_payload = _payload(old_after_item) if old_after_item is not None else {}
    old_after = _service_tables(evidence, old_after_payload) if old_after_item is not None else None
    old_generation = checkpoints[("trial", env_id)]["generationId"]
    old_after_service_valid = (
        old_after is not None
        and old_after_payload.get("environmentId") == env_id
        and old_after_payload.get("generationId") == old_generation
        and old_after_payload.get("phase") == "old_generation_after_stale"
        and checkpoints[("baseline", env_id)]["generationId"] == old_generation
    )

    baseline_chain = _logical_chain(chains["baseline"])
    reset_chain = _logical_chain(chains["reset"])
    reset_checkpoint = checkpoints[("reset", env_id)]
    reset_item = _checkpoint_reset(evidence, reset_checkpoint, env_id)
    reset_calls = _admin_resets_between(evidence, env_id, checkpoints[("trial", env_id)], reset_checkpoint)
    reset_linked = (reset_item is not None and len(reset_calls) == 1 and reset_calls[0] is reset_item
        and _reset_between_checkpoints(evidence, reset_item, checkpoints[("trial", env_id)], reset_checkpoint))
    chain_baseline = (baseline_chain == reset_chain
        and _logical_chain(chains["reset"]) == _logical_chain(chains["after_stale"])
        and reset_linked
        and checkpoints[("trial", env_id)]["generationId"] != checkpoints[("reset", env_id)]["generationId"]
        and checkpoints[("reset", env_id)]["generationId"] == checkpoints[("fresh_trial", env_id)]["generationId"])
    base_fixture = _fixture_hash(tables["baseline"])
    fixture_hash = (base_fixture is not None and base_fixture == _fixture_hash(tables["reset"])
                    and base_fixture == _fixture_hash(tables["fresh_trial"]))
    service_baseline = (_has_empty_trial_namespace(tables["baseline"])
        and _has_empty_trial_namespace(tables["reset"])
        and _logical_tables(tables["reset"]) == _logical_tables(tables["after_stale"]))
    old_trial_generation = tables["trial"]["generation-by-id"]
    old_after_generation = old_after["generation-by-id"] if old_after is not None else []
    immutable_old_tables = (
        "operations-by-generation", "payments-by-operation", "deliveries-by-operation",
        "x402-observations-by-operation", "selected-execution-by-generation",
        "selected-execution-events-by-generation",
    )
    old_work_unchanged = (old_after_service_valid and len(old_trial_generation) == len(old_after_generation) == 1
        and old_trial_generation[0].get("env_id") == env_id
        and str(old_trial_generation[0].get("generation_id")) == old_generation
        and old_trial_generation[0].get("status") == "active"
        and old_after_generation[0].get("env_id") == env_id
        and str(old_after_generation[0].get("generation_id")) == old_generation
        and old_after_generation[0].get("status") == "fenced"
        and _fixture_hash(tables["trial"]) == _fixture_hash(old_after)
        and all(tables["trial"][name] == old_after[name] for name in immutable_old_tables))
    service_baseline = service_baseline and old_work_unchanged
    trial_ok = (_has_successful_execution(tables["trial"])
        and _successful_purchase_rows(evidence, tables["trial"], env_id,
                                     checkpoints[("trial", env_id)]["generationId"])
        and _successful_selected_actions(evidence, tables["trial"], env_id,
                                         checkpoints[("trial", env_id)]["generationId"]))
    fresh_ok = (_has_successful_execution(tables["fresh_trial"])
        and _successful_purchase_rows(evidence, tables["fresh_trial"], env_id,
                                     checkpoints[("fresh_trial", env_id)]["generationId"])
        and _successful_selected_actions(evidence, tables["fresh_trial"], env_id,
                                         checkpoints[("fresh_trial", env_id)]["generationId"]))
    trial_ops = _ids(tables["trial"]["operations-by-generation"], "operation_id")
    fresh_ops = _ids(tables["fresh_trial"]["operations-by-generation"], "operation_id")
    trial_payments = _ids(tables["trial"]["payments-by-operation"], "payment_id")
    fresh_payments = _ids(tables["fresh_trial"]["payments-by-operation"], "payment_id")
    trial_deliveries = _ids(tables["trial"]["deliveries-by-operation"], "delivery_id")
    fresh_deliveries = _ids(tables["fresh_trial"]["deliveries-by-operation"], "delivery_id")
    old_hashes = {str(row.get("transaction_hash")).lower() for row in tables["trial"]["operations-by-generation"]
                  if _is_digest(row.get("transaction_hash"))}
    new_hashes = {str(row.get("transaction_hash")).lower() for row in tables["fresh_trial"]["operations-by-generation"]
                  if _is_digest(row.get("transaction_hash"))}
    content_hashes_old = {str(row.get("content_sha256")).lower() for row in tables["trial"]["deliveries-by-operation"]
                          if _is_digest(row.get("content_sha256"))}
    content_hashes_new = {str(row.get("content_sha256")).lower() for row in tables["fresh_trial"]["deliveries-by-operation"]
                          if _is_digest(row.get("content_sha256"))}
    expected_resource = None
    manifest = getattr(evidence, "manifest", None)
    x402 = manifest.get("x402") if isinstance(manifest, dict) else None
    expected_resource_id = x402.get("resourceId") if isinstance(x402, dict) else None
    if isinstance(x402, dict) and _is_digest(x402.get("resourceSha256")):
        expected_resource = str(x402["resourceSha256"]).lower()

    stale_records = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if _payload(item).get("variantId") in {"late_worker", "previous_payment_nonce", "stale_delivery_record"}
    ]
    stale_variants = {_payload(item).get("variantId") for item, _, _ in stale_records}
    late_worker_records = [(item, request, response) for item, request, response in stale_records
                           if _payload(item).get("variantId") == "late_worker"]
    stale_generation = (_exact_variants(evidence, SC010_VARIANTS)
        and len(stale_records) == 3
        and len(late_worker_records) == 1
        and late_worker_records[0][1].get("method") == "POST"
        and late_worker_records[0][1].get("path") == f"/tools/{env_id}/swap"
        and stale_variants == {"late_worker", "previous_payment_nonce", "stale_delivery_record"}
        and all(_generation_scope_denied(response) and _operation_id(item, response) is None
                and _headers_generation(request) == checkpoints[("trial", env_id)]["generationId"]
                for item, request, response in stale_records))
    old_purchase_rows = [row for row in tables["trial"]["operations-by-generation"]
                         if str(row.get("operation_kind", "")).lower() == "purchase"
                         and row.get("status") == "delivered" and row.get("receipt_status") == "success"]
    old_purchase_id = str(old_purchase_rows[0].get("operation_id")) if len(old_purchase_rows) == 1 else None
    old_purchase_http = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if request.get("method") == "POST"
        and request.get("path") == f"/tools/{env_id}/purchase"
        and _headers_generation(request) == checkpoints[("trial", env_id)]["generationId"]
        and _operation_id(item, response) == old_purchase_id
        and isinstance(request.get("decodedPaymentPayload"), dict)
        and response.get("status") == 200
    ]
    old_swap_rows = [row for row in tables["trial"]["operations-by-generation"]
                     if str(row.get("operation_kind", "")).lower() == "swap"
                     and row.get("status") == "settled" and row.get("receipt_status") == "success"]
    old_swap_id = str(old_swap_rows[0].get("operation_id")) if len(old_swap_rows) == 1 else None
    old_swap_http = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if _payload(item).get("variantId") == "reused_operation_namespace"
        and request.get("method") == "POST" and request.get("path") == f"/tools/{env_id}/swap"
        and _headers_generation(request) == checkpoints[("trial", env_id)]["generationId"]
        and _operation_id(item, response) == old_swap_id and response.get("status") == 200
    ]
    late_worker_request_ok = False
    if len(late_worker_records) == len(old_swap_http) == 1:
        late_request = late_worker_records[0][1]
        prior_swap_request = old_swap_http[0][1]
        late_worker_request_ok = (
            isinstance(prior_swap_request.get("body"), dict)
            and late_request.get("body") == prior_swap_request.get("body")
            and _headers_idempotency_key(late_request) is not None
            and _headers_idempotency_key(late_request) != _headers_idempotency_key(prior_swap_request)
        )
    previous_nonce_records = [(item, request, response) for item, request, response in stale_records
                              if _payload(item).get("variantId") == "previous_payment_nonce"]
    stale_delivery_records = [(item, request, response) for item, request, response in stale_records
                              if _payload(item).get("variantId") == "stale_delivery_record"]
    previous_matches_purchase = False
    if len(old_purchase_http) == len(previous_nonce_records) == len(stale_delivery_records) == 1:
        old_request = old_purchase_http[0][1]
        previous_request = previous_nonce_records[0][1]
        stale_delivery_request = stale_delivery_records[0][1]
        old_payment = old_request.get("decodedPaymentPayload")
        previous_payment = previous_request.get("decodedPaymentPayload")
        expected_purchase_body = {"resourceId": expected_resource_id, "offerId": "canonical"}
        previous_matches_purchase = (
            isinstance(expected_resource_id, str) and bool(expected_resource_id)
            and old_request.get("body") == expected_purchase_body
            and previous_request.get("body") == expected_purchase_body
            and stale_delivery_request.get("body") == expected_purchase_body
            and _headers_idempotency_key(previous_request) == _headers_idempotency_key(old_request)
            and _headers_idempotency_key(stale_delivery_request) == _headers_idempotency_key(old_request)
            and isinstance(old_payment, dict) and isinstance(previous_payment, dict)
            and old_payment.get("sourceHeaderSha256") == previous_payment.get("sourceHeaderSha256")
            and previous_nonce_records[0][1].get("path") == f"/tools/{env_id}/purchase"
            and stale_delivery_request.get("path") == f"/tools/{env_id}/purchase"
        )
    old_authorization_sha256 = (_headers(old_purchase_http[0][1]).get("authorization-sha256")
                                if len(old_purchase_http) == 1 else None)
    authorization_bound = (
        isinstance(old_authorization_sha256, str) and _is_digest(old_authorization_sha256)
        and _headers(old_purchase_http[0][1]).get("authorization-present") is True
        and all(_headers(request).get("authorization-present") is True
                and _headers(request).get("authorization-sha256") == old_authorization_sha256
                for _, request, _ in stale_records)
        and len(old_swap_http) == 1
        and _headers(old_swap_http[0][1]).get("authorization-sha256") == old_authorization_sha256
    )
    stale_generation = stale_generation and previous_matches_purchase
    stale_generation = stale_generation and late_worker_request_ok and authorization_bound
    stale_generation = stale_generation and all(
        _stale_operation_has_no_rpc_effect(evidence, item, response)
        for item, _, response in stale_records
    )
    reset_chain_index = _artifact_index(evidence, checkpoints[("reset", env_id)].get("chainArtifactPath"))
    after_stale_chain_index = _artifact_index(evidence, checkpoints[("after_stale", env_id)].get("chainArtifactPath"))
    old_after_index = _artifact_index(evidence, _path(old_after_item)) if old_after_item is not None else None
    stale_indices = [_artifact_index(evidence, _path(item)) for item, _, _ in stale_records]
    stale_ordered = (reset_chain_index is not None and old_after_index is not None
        and after_stale_chain_index is not None and reset_chain_index < old_after_index < after_stale_chain_index
        and all(index is not None and reset_chain_index < index < old_after_index for index in stale_indices))
    stale_generation = stale_generation and stale_ordered and old_work_unchanged

    stale_denial_rows = old_after.get("denials-by-generation", []) if old_after is not None else []
    stale_denial_records: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {}
    for item, request, response in stale_records:
        denial_id = _headers(response).get("x-bef-denial-id")
        variant = _payload(item).get("variantId")
        if isinstance(denial_id, str) and isinstance(variant, str):
            stale_denial_records[denial_id] = (variant, request, response)
    stale_denial_ids = set(stale_denial_records)
    expected_stale_routes = {
        "late_worker": f"/tools/{env_id}/swap",
        "previous_payment_nonce": f"/tools/{env_id}/purchase",
        "stale_delivery_record": f"/tools/{env_id}/purchase",
    }
    stale_denial_audit_ok = (
        old_after_service_valid
        and not tables["trial"]["denials-by-generation"]
        and len(stale_denial_rows) == 3
        and len(stale_denial_ids) == 3
        and all(
            (denial := stale_denial_records.get(str(row.get("denial_id")))) is not None
            and row.get("env_id") == env_id
            and str(row.get("generation_id")) == old_generation
            and row.get("operation_id") is None
            and row.get("route") == expected_stale_routes.get(denial[0])
            and row.get("reason_code") == "participant_generation_scope_denied"
            and _is_digest(row.get("request_sha256"))
            and _generation_scope_denied(denial[2])
            and _headers_generation(denial[1]) == old_generation
            for row in stale_denial_rows
        )
        and {row.get("denial_id") for row in stale_denial_rows} == stale_denial_ids
    )
    stale_generation = stale_generation and stale_denial_audit_ok

    namespace_pairs = []
    for item, request, response in _http_records(evidence):
        if _payload(item).get("variantId") == "reused_operation_namespace" and request.get("path", "").endswith("/purchase"):
            key = _headers_idempotency_key(request)
            op_id = _operation_id(item, response)
            if key and op_id and isinstance(response.get("status"), int) and response["status"] == 200:
                namespace_pairs.append((key, op_id))
    old_purchase_key = _headers_idempotency_key(old_purchase_http[0][1]) if len(old_purchase_http) == 1 else None
    fresh_purchase_rows = [row for row in tables["fresh_trial"]["operations-by-generation"]
                           if str(row.get("operation_kind", "")).lower() == "purchase"
                           and row.get("status") == "delivered" and row.get("receipt_status") == "success"]
    fresh_purchase_id = str(fresh_purchase_rows[0].get("operation_id")) if len(fresh_purchase_rows) == 1 else None
    fresh_namespace_http = [
        (item, request, response) for item, request, response in _http_records(evidence)
        if _payload(item).get("variantId") == "reused_operation_namespace"
        and request.get("method") == "POST" and request.get("path") == f"/tools/{env_id}/purchase"
        and _headers_generation(request) == checkpoints[("fresh_trial", env_id)]["generationId"]
        and response.get("status") == 200 and _operation_id(item, response) == fresh_purchase_id
    ]
    namespace_ok = (old_purchase_key is not None and len(fresh_namespace_http) == 1
        and _headers_idempotency_key(fresh_namespace_http[0][1]) == old_purchase_key
        and len(namespace_pairs) == 2
        and set(namespace_pairs) == {(old_purchase_key, old_purchase_id), (old_purchase_key, fresh_purchase_id)}
        and fresh_purchase_id in fresh_ops and fresh_purchase_id not in trial_ops)
    equivalent = (trial_ok and fresh_ok
        and sc010_fee_normalized_equivalent(
            evidence, tables["trial"], tables["fresh_trial"],
            checkpoints[("trial", env_id)]["chain"], checkpoints[("fresh_trial", env_id)]["chain"],
            env_id, checkpoints[("trial", env_id)]["generationId"],
            checkpoints[("fresh_trial", env_id)]["generationId"],
        )
        and bool(trial_ops) and bool(fresh_ops) and trial_ops.isdisjoint(fresh_ops)
        and bool(trial_payments) and bool(fresh_payments) and trial_payments.isdisjoint(fresh_payments)
        and bool(trial_deliveries) and bool(fresh_deliveries) and trial_deliveries.isdisjoint(fresh_deliveries)
        and bool(old_hashes) and bool(new_hashes) and old_hashes.isdisjoint(new_hashes)
        and expected_resource is not None and content_hashes_old == {expected_resource} == content_hashes_new
        and namespace_ok)
    return {
        "stale_generation_fenced": bool(stale_generation),
        "chain_baseline": bool(chain_baseline),
        "service_baseline": bool(service_baseline),
        "fixture_hash": bool(fixture_hash),
        "equivalent_probe_outcome": bool(equivalent),
    }


def _headers(request: dict[str, Any]) -> dict[str, Any]:
    raw = request.get("headers")
    return {str(key).lower(): value for key, value in raw.items()} if isinstance(raw, dict) else {}


def _headers_generation(request: dict[str, Any]) -> str | None:
    value = _headers(request).get("x-bef-generation")
    return value if isinstance(value, str) else None


def _headers_idempotency_key(request: dict[str, Any]) -> str | None:
    value = _headers(request).get("idempotency-key")
    return value if isinstance(value, str) and value else None


def evaluate_sc009010(evidence: Any, scenario_id: str) -> dict[str, bool]:
    """Recompute the approved SC009 or SC010 predicates; malformed evidence fails closed."""
    try:
        if scenario_id == "BEF-SC-009":
            return _sc009(evidence)
        if scenario_id == "BEF-SC-010":
            return _sc010(evidence)
    except (KeyError, TypeError, ValueError, IndexError):
        pass
    if scenario_id == "BEF-SC-009":
        return {"independent_chain_state": False, "independent_service_state": False,
                "reset_not_crossing_boundary": False, "foreign_access_denied": False}
    if scenario_id == "BEF-SC-010":
        return {"stale_generation_fenced": False, "chain_baseline": False, "service_baseline": False,
                "fixture_hash": False, "equivalent_probe_outcome": False}
    return {}
