from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from . import bef_sc009010_resource_adapter as adapter


@dataclass(frozen=True)
class Artifact:
    relative_path: str
    sha256: str
    boundary: str
    payload: dict[str, Any]


class Evidence:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest
        self.manifest_sha256 = "d" * 64
        self.artifacts: list[Artifact] = []

    def add(self, path: str, boundary: str, payload: dict[str, Any]) -> Artifact:
        raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        artifact = Artifact(path, hashlib.sha256(raw).hexdigest(), boundary, payload)
        self.artifacts.append(artifact)
        return artifact


@pytest.fixture
def evidence() -> Evidence:
    result = Evidence({
        "local": {"environments": [{"id": "a"}, {"id": "b"}], "chainId": 31337},
        "funding": {"donor": "0x0000000000000000000000000000000000000001"},
        "contracts": {
            "usdc": {"address": "0x0000000000000000000000000000000000000010", "implementation": "0x0000000000000000000000000000000000000011"},
            "weth": {"address": "0x0000000000000000000000000000000000000012"},
            "factory": {"address": "0x0000000000000000000000000000000000000013"},
            "swapRouter02": {"address": "0x0000000000000000000000000000000000000014"},
            "quoterV2": {"address": "0x0000000000000000000000000000000000000015"},
            "pool": {"address": "0x0000000000000000000000000000000000000016"},
        },
        "x402": {"resourceId": "fixture-resource", "resourceSha256": "a" * 64},
        "feePolicy": {
            "baseFeeWei": "5000000", "priorityFeeWei": "1000000",
            "ethUsdcRateNumerator": "1", "ethUsdcRateDenominator": "1000000000",
            "rounding": "floor-to-6-decimal-usdc-units", "baseL1Fee": "unmodelled",
            "principalSeparateFromExpense": True,
        },
    })
    _add_endpoint_bindings(result, ("a",))
    return result


def _addr(value: str) -> str:
    return value.lower().removeprefix("0x").zfill(64)


def _endpoint_binding(evidence: Evidence, env: str) -> Artifact:
    path = f"rpc/endpoint-binding-{env}.json"
    return next(item for item in evidence.artifacts if item.relative_path == path)


def _chain_snapshot(evidence: Evidence, env: str = "a", phase: str = "baseline", generation: str = "ga",
                    *, payer_native_result: str = "0xde0b6b3a7640000",
                    state_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = evidence.manifest
    state = state_overrides or {}
    contracts = manifest["contracts"]
    addresses = {
        "payer": "0x0000000000000000000000000000000000000021" if env == "a" else "0x0000000000000000000000000000000000000031",
        "facilitator": "0x0000000000000000000000000000000000000022" if env == "a" else "0x0000000000000000000000000000000000000032",
        "donor": manifest["funding"]["donor"],
        "recipient": "0x0000000000000000000000000000000000000023" if env == "a" else "0x0000000000000000000000000000000000000033",
    }
    addresses.update({
        "weth": contracts["weth"]["address"], "usdc": contracts["usdc"]["address"],
        "usdcImplementation": contracts["usdc"]["implementation"],
        "factory": contracts["factory"]["address"], "router": contracts["swapRouter02"]["address"],
        "quoter": contracts["quoterV2"]["address"], "pool": contracts["pool"]["address"],
    })
    reads: dict[str, dict[str, str]] = {}
    binding = _endpoint_binding(evidence, env)
    binding_payload = binding.payload

    def add(key: str, method: str, params: list[Any], result: Any) -> None:
        path = f"rpc/{env}-{phase}-{key}.json"
        payload = {
            "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
            "endpointBoundary": "local-chain-readonly-proxy", "environmentId": env,
            "endpointIdentityArtifact": binding.relative_path,
            "endpointRef": binding_payload["endpointRef"],
            "operationId": None, "variantId": None, "method": method, "params": params,
            "result": result,
        }
        item = evidence.add(path, "local-chain-readonly-proxy", payload)
        reads[key] = adapter._ref(item)

    add("chainId", "eth_chainId", [], state.get("chainId", "0x7a69"))
    add("head", "eth_getBlockByNumber", ["latest", False], {
        "number": "0x10", "hash": "0x" + "1" * 64,
        "timestamp": state.get("timestamp", "0x20"),
        "baseFeePerGas": state.get("baseFeePerGas", "0x1"),
        "gasLimit": state.get("gasLimit", "0x1c9c380"),
    })
    for role, address in (("payer", addresses["payer"]), ("facilitator", addresses["facilitator"]), ("donor", addresses["donor"])):
        default_native = payer_native_result if role == "payer" else "0xde0b6b3a7640000"
        add(role + "Native", "eth_getBalance", [address, "latest"], state.get(role + "Native", default_native))
        add(role + "Nonce", "eth_getTransactionCount", [address, "latest"], state.get(role + "Nonce", "0x0"))

    def balance(key: str, token: str, owner: str) -> None:
        add(key, "eth_call", [{"to": token, "data": "0x70a08231" + _addr(owner)}, "latest"],
            state.get(key, "0x" + "0" * 63 + "1"))

    balance("donorUsdc", addresses["usdc"], addresses["donor"])
    balance("payerWeth", addresses["weth"], addresses["payer"])
    balance("payerUsdc", addresses["usdc"], addresses["payer"])
    balance("facilitatorUsdc", addresses["usdc"], addresses["facilitator"])
    balance("recipientUsdc", addresses["usdc"], addresses["recipient"])
    balance("poolWeth", addresses["weth"], addresses["pool"])
    balance("poolUsdc", addresses["usdc"], addresses["pool"])
    add("wethRouterAllowance", "eth_call", [{"to": addresses["weth"], "data": "0xdd62ed3e" + _addr(addresses["payer"]) + _addr(addresses["router"])}, "latest"], state.get("wethRouterAllowance", "0x" + "0" * 64))
    add("usdcRouterAllowance", "eth_call", [{"to": addresses["usdc"], "data": "0xdd62ed3e" + _addr(addresses["payer"]) + _addr(addresses["router"])}, "latest"], state.get("usdcRouterAllowance", "0x" + "0" * 64))
    for key, role in (("usdcCode", "usdc"), ("usdcImplementationCode", "usdcImplementation"),
                      ("wethCode", "weth"), ("factoryCode", "factory"), ("routerCode", "router"),
                      ("quoterCode", "quoter"), ("poolCode", "pool")):
        add(key, "eth_getCode", [addresses[role], "latest"], state.get(key, "0x6001600055"))
    add("poolLiquidity", "eth_call", [{"to": addresses["pool"], "data": "0x1a686502"}, "latest"], state.get("poolLiquidity", "0x" + "0" * 63 + "1"))
    add("poolSlot0", "eth_call", [{"to": addresses["pool"], "data": "0x3850c7bd"}, "latest"], state.get("poolSlot0", "0x" + "0" * 448))
    return {
        "schemaVersion": "bef-sc009010-chain-snapshot/v1", "boundary": "local-chain-readonly-proxy",
        "environmentId": env, "generationId": generation, "phase": phase,
        "addresses": addresses, "reads": reads,
    }


def _service_snapshot(evidence: Evidence, env: str = "a", phase: str = "baseline", generation: str = "ga",
                      *, rows: dict[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    rows = rows or {
        "generation-by-id": [{"env_id": env, "generation_id": generation, "status": "active", "fixture_hash": "b" * 64}],
        "operations-by-generation": [], "payments-by-operation": [], "deliveries-by-operation": [],
        "denials-by-generation": [], "x402-observations-by-operation": [],
        "selected-execution-by-generation": [], "selected-execution-events-by-generation": [],
    }
    refs = {}
    for query_name, query_rows in rows.items():
        path = f"db/{env}-{phase}-{query_name}.json"
        payload = {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database",
            "readOnly": True, "transactionReadOnly": "on", "databaseRole": "bef_observer", "queryName": query_name,
            "observationScope": "generation", "envId": env, "generationId": generation,
            "rows": query_rows,
        }
        item = evidence.add(path, "readonly-database", payload)
        refs[query_name] = adapter._ref(item)
    return {
        "schemaVersion": "bef-sc009010-service-snapshot/v1", "boundary": "readonly-database",
        "environmentId": env, "generationId": generation, "phase": phase, "tables": refs,
    }


def _scenario_tables(evidence: Evidence, env: str, generation: str, *, mutated: bool = False,
                     prefix: str = "") -> dict[str, list[dict[str, Any]]]:
    fixture_hash = "b" * 64
    payer_address = ("0x0000000000000000000000000000000000000021" if env == "a"
                     else "0x0000000000000000000000000000000000000031")
    facilitator_address = ("0x0000000000000000000000000000000000000022" if env == "a"
                           else "0x0000000000000000000000000000000000000032")
    rows: dict[str, list[dict[str, Any]]] = {
        "generation-by-id": [{"env_id": env, "generation_id": generation, "status": "active",
                              "fixture_hash": fixture_hash, "payer_address": payer_address}],
        "operations-by-generation": [], "payments-by-operation": [], "deliveries-by-operation": [],
        "denials-by-generation": [], "x402-observations-by-operation": [],
        "selected-execution-by-generation": [], "selected-execution-events-by-generation": [],
    }
    if not mutated:
        return rows

    tx_suffix = prefix or env
    purchase_id = f"{tx_suffix}-purchase"
    purchase_tx = "0x" + hashlib.sha256(f"{tx_suffix}-purchase-tx".encode()).hexdigest()
    rows["operations-by-generation"].append({
        "operation_id": purchase_id, "env_id": env, "generation_id": generation,
        "operation_kind": "purchase", "status": "delivered", "receipt_status": "success",
        "transaction_hash": purchase_tx,
    })
    rows["payments-by-operation"].append({
        "payment_id": f"{tx_suffix}-payment", "operation_id": purchase_id,
        "env_id": env, "generation_id": generation, "receipt_status": "success",
        "transaction_hash": purchase_tx, "payer_address": payer_address,
        "facilitator_address": facilitator_address,
    })
    rows["deliveries-by-operation"].append({
        "delivery_id": f"{tx_suffix}-delivery", "operation_id": purchase_id,
        "resource_id": evidence.manifest["x402"].get("resourceId", "fixture-resource"),
        "content_sha256": evidence.manifest["x402"]["resourceSha256"], "content_bytes": "12",
    })
    for action_index, action in enumerate(("wrap", "approve", "swap"), start=3):
        operation_id = f"{tx_suffix}-{action}"
        transaction_hash = "0x" + hashlib.sha256(f"{tx_suffix}-{action}-tx".encode()).hexdigest()
        rows["operations-by-generation"].append({
            "operation_id": operation_id, "env_id": env, "generation_id": generation,
            "operation_kind": action, "status": "settled", "receipt_status": "success",
            "transaction_hash": transaction_hash,
        })
        rows["selected-execution-by-generation"].append({
            "operation_id": operation_id, "env_id": env, "generation_id": generation,
            "action_kind": action, "transaction_hash": transaction_hash, "outcome": "success",
            "selected_action_json": {
                "wrap": {"kind": "wrap", "amountWei": "100000000000000000", "gasLimit": "1200000"},
                "approve": {"kind": "approve", "amountUnits": "200000000000000000", "gasLimit": "1200000"},
                "swap": {"kind": "swap", "amountInWei": "100000000000000000",
                         "amountOutMinimumUsdcUnits": "0", "gasLimit": "1200000"},
            }[action],
        })
        for event_sequence, event_kind in enumerate((
            "selected_action_bound", "prestate_observed", "original_tx_hash_bound", "receipt_finalized",
        ), start=1):
            rows["selected-execution-events-by-generation"].append({
                "event_sequence": str(event_sequence), "event_id": f"{operation_id}-{event_sequence}",
                "operation_id": operation_id, "env_id": env, "generation_id": generation,
                "event_kind": event_kind, "transaction_hash": transaction_hash,
            })
    return rows


def _add_checkpoint(evidence: Evidence, scenario: str, env: str, phase: str, generation: str,
                    *, payer_native_result: str, tables: dict[str, list[dict[str, Any]]],
                    reset_request: dict[str, str] | None = None,
                    state_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    chain = _chain_snapshot(evidence, env, phase, generation, payer_native_result=payer_native_result,
                            state_overrides=state_overrides)
    chain_item = evidence.add(f"state/{scenario.lower()}-{env}-{phase}-chain.json", "local-chain-readonly-proxy", chain)
    service = _service_snapshot(evidence, env, phase, generation, rows=tables)
    service_item = evidence.add(f"state/{scenario.lower()}-{env}-{phase}-service.json", "readonly-database", service)
    checkpoint = {
        "phase": phase, "environmentId": env, "generationId": generation,
        "chainSnapshot": adapter._ref(chain_item), "serviceSnapshot": adapter._ref(service_item),
    }
    if reset_request is not None:
        checkpoint["resetRequest"] = reset_request
    return checkpoint


def _add_endpoint_bindings(evidence: Evidence, envs: tuple[str, str]) -> None:
    manifest_envs = tuple(item["id"] for item in evidence.manifest["local"]["environments"])
    for env in envs:
        binding_path = f"rpc/endpoint-binding-{env}.json"
        if any(item.relative_path == binding_path for item in evidence.artifacts):
            continue
        if env not in manifest_envs:
            raise AssertionError(f"fixture endpoint environment is not in manifest: {env}")
        port = 8541 + manifest_envs.index(env)
        health = {
            "status": "ok", "boundary": "local-chain-readonly-proxy",
            "envId": env, "manifestSha256": evidence.manifest_sha256,
        }
        health_path = f"rpc/endpoint-health-{env}.json"
        health_item = evidence.add(health_path, "local-chain-readonly-proxy", health)
        evidence.add(binding_path, "local-chain-readonly-proxy", {
            "schemaVersion": "bef-rpc-endpoint-binding/v1", "boundary": "local-chain-readonly-proxy",
            "operationId": None, "variantId": None, "environmentId": env,
            "endpointRef": {"scheme": "http", "host": "127.0.0.1", "port": port},
            "healthArtifactPath": health_path, "healthArtifactSha256": health_item.sha256,
            "health": health,
        })


def _add_http(evidence: Evidence, name: str, *, boundary: str = "actual-tool-http", variant: str | None,
              method: str, path: str, status: int, operation_id: str | None = None,
              headers: dict[str, str] | None = None, request_body: Any = None, response_body: Any = None,
              response_headers: dict[str, str] | None = None,
              decoded_payment_hash: str | None = None) -> Artifact:
    request: dict[str, Any] = {"method": method, "path": path, "headers": headers or {}, "body": request_body}
    if decoded_payment_hash:
        request["decodedPaymentPayload"] = {"sourceHeaderSha256": decoded_payment_hash}
    return evidence.add(f"http/{name}.json", boundary, {
        "schemaVersion": "bef-http-observation/v1", "boundary": boundary,
        "operationId": operation_id, "variantId": variant, "request": request,
        "response": {"status": status, "headers": response_headers or {}, "body": response_body or {}},
    })


def _add_receipt(evidence: Evidence, env: str, operation_id: str, transaction_hash: str,
                 variant: str | None = None, *, sender: str | None = None,
                 gas_used: str = "0x5208", effective_gas_price: str = "0x5b8d80") -> None:
    binding = _endpoint_binding(evidence, env)
    if sender is None:
        sender = ("0x0000000000000000000000000000000000000021" if env == "a"
                  else "0x0000000000000000000000000000000000000031")
    evidence.add(f"rpc/{env}-{operation_id}-receipt.json", "local-chain-readonly-proxy", {
        "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
        "endpointBoundary": "local-chain-readonly-proxy", "environmentId": env,
        "endpointIdentityArtifact": binding.relative_path, "endpointRef": binding.payload["endpointRef"],
        "operationId": operation_id, "variantId": variant,
        "method": "eth_getTransactionReceipt", "params": [transaction_hash],
        "result": {"transactionHash": transaction_hash, "status": "0x1", "from": sender,
                   "gasUsed": gas_used, "effectiveGasPrice": effective_gas_price},
    })


def test_full_raw_chain_snapshot_checks_actual_rpc_shapes(evidence: Evidence) -> None:
    snapshot = _chain_snapshot(evidence)
    parsed = adapter._expected_chain_reads(evidence, snapshot)
    assert parsed is not None
    assert parsed["chainId"] == 31337
    assert parsed["head"]["timestamp"] == "0x20"
    assert parsed["payerNonce"] == 0
    assert parsed["poolSlot0"] == "0x" + "0" * 448


def test_chain_snapshot_rejects_missing_balance_or_wrong_rpc_target(evidence: Evidence) -> None:
    snapshot = _chain_snapshot(evidence)
    del snapshot["reads"]["payerUsdc"]
    assert adapter._expected_chain_reads(evidence, snapshot) is None

    snapshot = _chain_snapshot(evidence, phase="bad")
    ref = snapshot["reads"]["payerWeth"]
    item = next(item for item in evidence.artifacts if item.relative_path == ref["path"])
    tampered = dict(item.payload)
    tampered["params"] = [{"to": evidence.manifest["contracts"]["usdc"]["address"], "data": item.payload["params"][0]["data"]}, "latest"]
    evidence.artifacts[evidence.artifacts.index(item)] = Artifact(item.relative_path, item.sha256, item.boundary, tampered)
    assert adapter._expected_chain_reads(evidence, snapshot) is None


def test_service_snapshot_binds_each_raw_readonly_query(evidence: Evidence) -> None:
    snapshot = _service_snapshot(evidence)
    assert adapter._service_tables(evidence, snapshot) is not None
    ref = snapshot["tables"]["operations-by-generation"]
    item = next(item for item in evidence.artifacts if item.relative_path == ref["path"])
    bad_payload = {**item.payload, "databaseRole": "admin_observer"}
    evidence.artifacts[evidence.artifacts.index(item)] = Artifact(item.relative_path, item.sha256, item.boundary, bad_payload)
    assert adapter._service_tables(evidence, snapshot) is None


def test_service_snapshot_rejects_unhashed_or_missing_query_reference(evidence: Evidence) -> None:
    snapshot = _service_snapshot(evidence)
    snapshot["tables"]["payments-by-operation"] = {"path": "db/no-such-file.json", "sha256": "a" * 64}
    assert adapter._service_tables(evidence, snapshot) is None


def test_service_snapshot_uses_actual_observer_identity_and_transaction_mode(evidence: Evidence) -> None:
    snapshot = _service_snapshot(evidence)
    assert adapter._service_tables(evidence, snapshot) is not None

    artifact = next(item for item in evidence.artifacts
                    if item.relative_path == snapshot["tables"]["generation-by-id"]["path"])
    evidence.artifacts[evidence.artifacts.index(artifact)] = Artifact(
        artifact.relative_path, artifact.sha256, artifact.boundary, {**artifact.payload, "envId": "b"},
    )
    assert adapter._service_tables(evidence, snapshot) is None

    snapshot = _service_snapshot(evidence, phase="read-only-check")
    artifact = next(item for item in evidence.artifacts if item.relative_path == snapshot["tables"]["generation-by-id"]["path"])
    evidence.artifacts[evidence.artifacts.index(artifact)] = Artifact(
        artifact.relative_path, artifact.sha256, artifact.boundary,
        {**artifact.payload, "transactionReadOnly": "off"},
    )
    assert adapter._service_tables(evidence, snapshot) is None


def test_service_snapshot_rejects_generation_row_with_wrong_scope(evidence: Evidence) -> None:
    snapshot = _service_snapshot(evidence)
    ref = snapshot["tables"]["generation-by-id"]
    artifact = next(item for item in evidence.artifacts if item.relative_path == ref["path"])
    payload = {**artifact.payload, "rows": [{**artifact.payload["rows"][0], "env_id": "b"}]}
    evidence.artifacts[evidence.artifacts.index(artifact)] = Artifact(
        artifact.relative_path, artifact.sha256, artifact.boundary, payload,
    )
    assert adapter._service_tables(evidence, snapshot) is None


def test_receipt_must_bind_operation_and_transaction_hash(evidence: Evidence) -> None:
    tx = "0x" + "2" * 64
    _add_receipt(evidence, "a", "op-1", tx, "concurrent_operations")
    assert adapter._receipt_bound_to_operation(evidence, "op-1", tx, "a")
    assert not adapter._receipt_bound_to_operation(evidence, "op-2", tx, "a")
    assert not adapter._receipt_bound_to_operation(evidence, "op-1", "0x" + "3" * 64, "a")


def _replace_payload(evidence: Evidence, item: Artifact, payload: dict[str, Any]) -> Artifact:
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    replacement = Artifact(item.relative_path, hashlib.sha256(raw).hexdigest(), item.boundary, payload)
    evidence.artifacts[evidence.artifacts.index(item)] = replacement
    return replacement


def test_endpoint_binding_requires_distinct_refs_and_hashed_health_artifacts(evidence: Evidence) -> None:
    _add_endpoint_bindings(evidence, ("b",))
    assert adapter._unique_endpoint_refs(evidence, ("a", "b"))

    binding_a = _endpoint_binding(evidence, "a")
    binding_b = _endpoint_binding(evidence, "b")
    _replace_payload(evidence, binding_b, {**binding_b.payload, "endpointRef": binding_a.payload["endpointRef"]})
    assert not adapter._unique_endpoint_refs(evidence, ("a", "b"))

    evidence = Evidence(evidence.manifest)
    evidence.manifest_sha256 = "d" * 64
    _add_endpoint_bindings(evidence, ("a", "b"))
    binding_a = _endpoint_binding(evidence, "a")
    binding_b = _endpoint_binding(evidence, "b")
    alias_ref = {**binding_a.payload["endpointRef"], "scheme": "http", "host": "localhost"}
    _replace_payload(evidence, binding_b, {**binding_b.payload, "endpointRef": alias_ref})
    assert not adapter._unique_endpoint_refs(evidence, ("a", "b"))

@pytest.mark.parametrize("mutant", ["foreign_health_path", "missing_health", "wrong_health_hash", "foreign_health_payload"])
def test_endpoint_binding_rejects_foreign_or_unverifiable_health_artifacts(evidence: Evidence, mutant: str) -> None:
    binding = _endpoint_binding(evidence, "a")
    if mutant == "foreign_health_path":
        payload = {**binding.payload, "healthArtifactPath": "rpc/endpoint-health-b.json"}
        _replace_payload(evidence, binding, payload)
    elif mutant == "missing_health":
        evidence.artifacts = [item for item in evidence.artifacts
                              if item.relative_path != "rpc/endpoint-health-a.json"]
    elif mutant == "wrong_health_hash":
        _replace_payload(evidence, binding, {**binding.payload, "healthArtifactSha256": "0" * 64})
    else:
        health = next(item for item in evidence.artifacts if item.relative_path == "rpc/endpoint-health-a.json")
        _replace_payload(evidence, health, {**health.payload, "envId": "b"})
    assert not adapter._unique_endpoint_refs(evidence, ("a", "b"))


@pytest.mark.parametrize("field", ["endpointIdentityArtifact", "endpointRef"])
def test_rpc_snapshot_read_must_join_its_environment_endpoint_binding(evidence: Evidence, field: str) -> None:
    _add_endpoint_bindings(evidence, ("b",))
    snapshot = _chain_snapshot(evidence)
    ref = snapshot["reads"]["payerNative"]
    item = next(candidate for candidate in evidence.artifacts if candidate.relative_path == ref["path"])
    other = _endpoint_binding(evidence, "b")
    payload = {**item.payload, field: other.relative_path if field == "endpointIdentityArtifact"
               else other.payload["endpointRef"]}
    replacement = _replace_payload(evidence, item, payload)
    snapshot["reads"]["payerNative"]["sha256"] = replacement.sha256
    assert adapter._expected_chain_reads(evidence, snapshot) is None


def test_receipt_must_join_its_environment_endpoint_binding(evidence: Evidence) -> None:
    _add_endpoint_bindings(evidence, ("b",))
    tx = "0x" + "2" * 64
    _add_receipt(evidence, "a", "op-1", tx)
    receipt = next(item for item in evidence.artifacts if item.relative_path == "rpc/a-op-1-receipt.json")
    foreign_binding = _endpoint_binding(evidence, "b")
    _replace_payload(evidence, receipt, {**receipt.payload,
        "endpointIdentityArtifact": foreign_binding.relative_path,
        "endpointRef": foreign_binding.payload["endpointRef"]})
    assert not adapter._receipt_bound_to_operation(evidence, "op-1", tx, "a")


def test_exact_variant_sets_are_not_inferred_from_checkpoint_names(evidence: Evidence) -> None:
    for index, variant in enumerate(adapter.SC010_VARIANTS):
        evidence.add(f"http/{index}.json", "actual-tool-http", {"boundary": "actual-tool-http", "variantId": variant})
    assert not adapter._exact_variants(evidence, adapter.SC009_VARIANTS)
    assert adapter._exact_variants(evidence, adapter.SC010_VARIANTS)


def test_malformed_scenario_evidence_fails_closed(evidence: Evidence) -> None:
    assert set(adapter.evaluate_sc009010(evidence, "BEF-SC-009").values()) == {False}
    assert set(adapter.evaluate_sc009010(evidence, "BEF-SC-010").values()) == {False}
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-099") == {}


def test_empty_new_generation_namespace_requires_all_service_tables(evidence: Evidence) -> None:
    snapshot = _service_snapshot(evidence)
    parsed = adapter._service_tables(evidence, snapshot)
    assert parsed is not None
    assert adapter._has_empty_trial_namespace(parsed)
    parsed["selected-execution-events-by-generation"] = [{"event_id": "leaked"}]
    assert not adapter._has_empty_trial_namespace(parsed)


def test_stale_http_without_operation_does_not_match_unrelated_null_operation_rpcs(evidence: Evidence) -> None:
    stale = evidence.add("http/stale.json", "actual-tool-http", {
        "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
        "operationId": None, "variantId": "late_worker",
        "request": {}, "response": {"status": 403},
    })
    evidence.add("rpc/unrelated-read.json", "local-chain-readonly-proxy", {
        "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
        "operationId": None, "variantId": None, "method": "eth_chainId", "params": [], "result": "0x7a69",
    })
    assert adapter._stale_operation_has_no_rpc_effect(evidence, stale, {"status": 403})

    stale_with_operation = evidence.add("http/stale-with-operation.json", "actual-tool-http", {
        "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http",
        "operationId": "op-1", "variantId": "late_worker",
        "request": {}, "response": {"status": 409},
    })
    evidence.add("rpc/operation-effect.json", "local-chain-readonly-proxy", {
        "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy",
        "operationId": "op-1", "variantId": "late_worker", "method": "eth_getTransactionReceipt",
        "params": ["0x" + "1" * 64], "result": None,
    })
    assert not adapter._stale_operation_has_no_rpc_effect(evidence, stale_with_operation, {"status": 409})


def _add_reset_http(evidence: Evidence, name: str, env: str) -> Artifact:
    return _add_http(evidence, name, boundary="private-admin-http", variant=None,
        method="POST", path=f"/internal/admin/environments/{env}/reset", status=200,
        headers={"X-BEF-Admin-Key-present": True}, response_body={"status": "reset", "envId": env})


def _add_scenario_operations(evidence: Evidence, env: str, generation: str,
                             rows: dict[str, list[dict[str, Any]]], *,
                             action_variant: str | None = None,
                             purchase_variant: str | None = None,
                             purchase_key: str | None = None,
                             payment_hash: str | None = None) -> None:
    payer = ("0x0000000000000000000000000000000000000021" if env == "a"
             else "0x0000000000000000000000000000000000000031")
    facilitator = ("0x0000000000000000000000000000000000000022" if env == "a"
                   else "0x0000000000000000000000000000000000000032")
    for row in rows["operations-by-generation"]:
        operation_id = str(row["operation_id"])
        kind = str(row["operation_kind"])
        transaction_hash = str(row["transaction_hash"])
        _add_receipt(evidence, env, operation_id, transaction_hash,
                     purchase_variant if kind == "purchase" else action_variant,
                     sender=facilitator if kind == "purchase" else payer)
        key = purchase_key if kind == "purchase" and purchase_key else f"{operation_id}-key"
        action_body = {
            "wrap": {"amountWei": "100000000000000000", "gasLimit": "1200000"},
            "approve": {"amountUnits": "200000000000000000", "gasLimit": "1200000"},
            "swap": {"amountInWei": "100000000000000000", "amountOutMinimumUsdcUnits": "0",
                     "recipient": payer, "gasLimit": "1200000"},
        }.get(kind)
        _add_http(evidence, f"{env}-{generation}-{operation_id}",
            variant=purchase_variant if kind == "purchase" else action_variant,
            method="POST", path=f"/tools/{env}/{kind}", status=200, operation_id=operation_id,
            headers={"x-bef-generation": generation, "idempotency-key": key,
                     "authorization-present": True, "authorization-sha256": "f" * 64},
            request_body=({"resourceId": evidence.manifest["x402"]["resourceId"], "offerId": "canonical"}
                          if kind == "purchase" else action_body),
            decoded_payment_hash=payment_hash if kind == "purchase" else None)


def _add_checkpoint_index(evidence: Evidence, scenario: str,
                          checkpoints: list[dict[str, Any]],
                          extra: dict[str, Any] | None = None) -> None:
    evidence.add(f"scenario/{scenario.lower()}-checkpoint-index.json", "scenario-report", {
        "schemaVersion": "bef-sc009010-checkpoint-index/v1", "boundary": "scenario-report",
        "operationId": None, "variantId": None, "scenarioId": scenario, "checkpoints": checkpoints,
        **(extra or {}),
    })


def test_sc009_reset_selection_uses_checkpoint_hash_not_observation_label(evidence: Evidence) -> None:
    startup = _add_reset_http(evidence, "startup-reset", "a")
    baseline = _add_checkpoint(evidence, "BEF-SC-009", "a", "baseline", "ga-old",
        payer_native_result="0xde0b6b3a7640000", tables=_scenario_tables(evidence, "a", "ga-old"))
    mutated = _add_checkpoint(evidence, "BEF-SC-009", "a", "mutated", "ga-old",
        payer_native_result="0xde0b6b3a7630000",
        tables=_scenario_tables(evidence, "a", "ga-old", mutated=True, prefix="a-mut"))
    deliberate = _add_reset_http(evidence, "unlabelled-deliberate-reset", "a")
    reset = _add_checkpoint(evidence, "BEF-SC-009", "a", "reset", "ga-new",
        payer_native_result="0xde0b6b3a7640000", tables=_scenario_tables(evidence, "a", "ga-new"),
        reset_request=adapter._ref(deliberate))
    _add_checkpoint_index(evidence, "BEF-SC-009", [baseline, mutated, reset])
    checkpoints = adapter._checkpoint_map(evidence, "BEF-SC-009")
    assert checkpoints is not None
    reset_checkpoint = checkpoints[("reset", "a")]
    selected = adapter._checkpoint_reset(evidence, reset_checkpoint, "a")
    assert selected is deliberate
    assert startup is not selected
    assert adapter._admin_resets_between(evidence, "a", checkpoints[("mutated", "a")], reset_checkpoint) == [deliberate]


def _build_sc009(evidence: Evidence, *, reset_state: dict[str, Any] | None = None,
                 env_b_after_state: dict[str, Any] | None = None,
                 env_b_baseline_state: dict[str, Any] | None = None,
                 foreign_status: int = 403,
                 reset_other_status: int = 403) -> None:
    envs = ("a", "b")
    _add_endpoint_bindings(evidence, envs)
    checkpoints: list[dict[str, Any]] = []
    generation_ids = {"a": "ga-old", "b": "gb-old"}
    for env in envs:
        generation = generation_ids[env]
        baseline_rows = _scenario_tables(evidence, env, generation)
        mutated_rows = _scenario_tables(evidence, env, generation, mutated=True, prefix=f"{env}-mut")
        checkpoints.append(_add_checkpoint(evidence, "BEF-SC-009", env, "baseline", generation,
            payer_native_result="0xde0b6b3a7640000", tables=baseline_rows,
            state_overrides=env_b_baseline_state if env == "b" else None))
        _add_scenario_operations(evidence, env, generation, mutated_rows,
                                 action_variant="concurrent_operations", purchase_variant="concurrent_operations",
                                 purchase_key=f"{env}-purchase-key")
        checkpoints.append(_add_checkpoint(evidence, "BEF-SC-009", env, "mutated", generation,
            payer_native_result="0xde0b6b3a7630000", tables=mutated_rows))
    _add_http(evidence, "foreign-environment", variant="foreign_environment_reference", method="GET",
        path="/tools/b/balances", status=foreign_status, headers={"x-bef-generation": "ga-old"})
    _add_http(evidence, "reset-other-environment", variant="reset_other_instance", method="POST",
        path="/internal/admin/environments/b/reset", status=reset_other_status,
        headers={"x-bef-generation": "ga-old"})
    reset_request = _add_reset_http(evidence, "reset-request", "a")
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-009", "a", "reset", "ga-new",
        payer_native_result="0xde0b6b3a7640000", tables=_scenario_tables(evidence, "a", "ga-new"),
        reset_request=adapter._ref(reset_request), state_overrides=reset_state))
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-009", "b", "after_reset", "gb-old",
        payer_native_result="0xde0b6b3a7630000",
        tables=_scenario_tables(evidence, "b", "gb-old", mutated=True, prefix="b-mut"),
        state_overrides=env_b_after_state))
    _add_checkpoint_index(evidence, "BEF-SC-009", checkpoints)


def test_sc009_complete_raw_checkpoint_and_http_evidence_passes(evidence: Evidence) -> None:
    _build_sc009(evidence)
    predicates = adapter.evaluate_sc009010(evidence, "BEF-SC-009")
    assert predicates == {
        "independent_chain_state": True, "independent_service_state": True,
        "reset_not_crossing_boundary": True, "foreign_access_denied": True,
    }


@pytest.mark.parametrize(("key", "value"), [
    ("payerNative", "0xde0b6b3a7640001"),
    ("payerNonce", "0x1"),
    ("donorUsdc", "0x" + "0" * 63 + "2"),
    ("wethRouterAllowance", "0x" + "0" * 63 + "1"),
    ("wethCode", "0x6002600055"),
    ("timestamp", "0x21"),
    ("baseFeePerGas", "0x2"),
    ("poolSlot0", "0x" + "0" * 447 + "1"),
])
def test_sc009_reset_rejects_each_protected_state_mismatch(evidence: Evidence, key: str, value: str) -> None:
    _build_sc009(evidence, reset_state={key: value})
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-009")["reset_not_crossing_boundary"] is False


def test_sc009_detects_mutation_of_the_other_environment_after_reset(evidence: Evidence) -> None:
    _build_sc009(evidence, env_b_after_state={"poolLiquidity": "0x" + "0" * 63 + "2"})
    result = adapter.evaluate_sc009010(evidence, "BEF-SC-009")
    assert result["reset_not_crossing_boundary"] is False


def test_sc009_requires_equivalent_baselines_in_both_environments(evidence: Evidence) -> None:
    _build_sc009(evidence, env_b_baseline_state={"payerNonce": "0x1"})
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-009")["independent_chain_state"] is False


@pytest.mark.parametrize(("foreign_status", "reset_other_status"), [(200, 403), (403, 200)])
def test_sc009_foreign_mutations_must_be_denied(evidence: Evidence, foreign_status: int,
                                                reset_other_status: int) -> None:
    _build_sc009(evidence, foreign_status=foreign_status, reset_other_status=reset_other_status)
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-009")["foreign_access_denied"] is False


def _build_sc010(evidence: Evidence, *, reset_state: dict[str, Any] | None = None,
                 after_stale_state: dict[str, Any] | None = None,
                 leak_after_stale: bool = False,
                 old_work_mutated: bool = False,
                 stale_before_reset: bool = False,
                 fresh_fixture_hash: str = "b" * 64,
                 previous_payload_hash: str = "c" * 64,
                 fresh_purchase_key: str = "sc010-reused-key",
                 stale_late_status: int = 403,
                 duplicate_fresh_operation: bool = False) -> None:
    env, old_generation, new_generation = "a", "ga-old", "ga-new"
    checkpoints: list[dict[str, Any]] = []
    baseline = _scenario_tables(evidence, env, old_generation)
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-010", env, "baseline", old_generation,
        payer_native_result="0xde0b6b3a7640000", tables=baseline))

    trial = _scenario_tables(evidence, env, old_generation, mutated=True, prefix="old")
    _add_scenario_operations(evidence, env, old_generation, trial, action_variant="reused_operation_namespace",
                             purchase_variant="reused_operation_namespace", purchase_key="sc010-reused-key",
                             payment_hash="c" * 64)
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-010", env, "trial", old_generation,
        payer_native_result="0xde0b6b3a7630000", tables=trial))

    def add_stale_requests() -> None:
        purchase_body = {"resourceId": evidence.manifest["x402"]["resourceId"], "offerId": "canonical"}
        auth_headers = {"x-bef-generation": old_generation, "authorization-present": True,
                        "authorization-sha256": "f" * 64}
        _add_http(evidence, "late-worker", variant="late_worker", method="POST",
            path=f"/tools/{env}/swap", status=stale_late_status,
            headers={**auth_headers, "idempotency-key": "late-worker-key"},
            request_body={"amountInWei": "100000000000000000", "amountOutMinimumUsdcUnits": "0",
                          "recipient": "0x0000000000000000000000000000000000000021", "gasLimit": "1200000"},
            response_body={"error": "generation_scope_denied"},
            response_headers={"x-bef-denial-id": "00000000-0000-4000-8000-000000000001"})
        _add_http(evidence, "previous-payment", variant="previous_payment_nonce", method="POST",
            path=f"/tools/{env}/purchase", status=403,
            headers={**auth_headers, "idempotency-key": "sc010-reused-key"},
            request_body=purchase_body,
            response_body={"error": "generation_scope_denied"},
            response_headers={"x-bef-denial-id": "00000000-0000-4000-8000-000000000002"},
            decoded_payment_hash=previous_payload_hash)
        _add_http(evidence, "stale-delivery", variant="stale_delivery_record", method="POST",
            path=f"/tools/{env}/purchase", status=403,
            headers={**auth_headers, "idempotency-key": "sc010-reused-key"},
            request_body=purchase_body, response_body={"error": "generation_scope_denied"},
            response_headers={"x-bef-denial-id": "00000000-0000-4000-8000-000000000003"})

    if stale_before_reset:
        add_stale_requests()

    reset_request = _add_reset_http(evidence, "reset-request", env)
    reset_rows = _scenario_tables(evidence, env, new_generation)
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-010", env, "reset", new_generation,
        payer_native_result="0xde0b6b3a7640000", tables=reset_rows,
        reset_request=adapter._ref(reset_request), state_overrides=reset_state))

    if not stale_before_reset:
        add_stale_requests()

    after_rows = _scenario_tables(evidence, env, new_generation)
    if leak_after_stale:
        after_rows["operations-by-generation"].append({
            "operation_id": "stale-leak", "env_id": env, "generation_id": new_generation,
            "operation_kind": "swap", "status": "settled", "receipt_status": "success",
            "transaction_hash": "0x" + "d" * 64,
        })
    old_after_rows = {name: [dict(row) for row in rows] for name, rows in trial.items()}
    old_after_rows["generation-by-id"][0]["status"] = "fenced"
    old_after_rows["denials-by-generation"] = [
        {"denial_id": f"00000000-0000-4000-8000-{index:012d}", "env_id": env,
         "generation_id": old_generation, "operation_id": None, "route": route,
         "reason_code": "participant_generation_scope_denied",
         "request_sha256": hashlib.sha256(f"stale-denial-{variant}".encode()).hexdigest()}
        for index, (variant, route) in enumerate((
            ("late_worker", f"/tools/{env}/swap"),
            ("previous_payment_nonce", f"/tools/{env}/purchase"),
            ("stale_delivery_record", f"/tools/{env}/purchase"),
        ), start=1)
    ]
    if old_work_mutated:
        old_after_rows["deliveries-by-operation"][0]["content_sha256"] = "e" * 64
    old_after_snapshot = _service_snapshot(evidence, env, "old_generation_after_stale", old_generation,
                                           rows=old_after_rows)
    old_after_item = evidence.add("state/bef-sc-010-a-old-generation-after-stale-service.json",
                                  "readonly-database", old_after_snapshot)
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-010", env, "after_stale", new_generation,
        payer_native_result="0xde0b6b3a7640000", tables=after_rows,
        state_overrides=after_stale_state))

    fresh = _scenario_tables(evidence, env, new_generation, mutated=True, prefix="fresh")
    fresh["generation-by-id"][0]["fixture_hash"] = fresh_fixture_hash
    if duplicate_fresh_operation:
        fresh["operations-by-generation"][0]["operation_id"] = "old-purchase"
        fresh["payments-by-operation"][0]["operation_id"] = "old-purchase"
        fresh["deliveries-by-operation"][0]["operation_id"] = "old-purchase"
    _add_scenario_operations(evidence, env, new_generation, fresh, action_variant="reused_operation_namespace",
        purchase_variant="reused_operation_namespace", purchase_key=fresh_purchase_key)
    checkpoints.append(_add_checkpoint(evidence, "BEF-SC-010", env, "fresh_trial", new_generation,
        payer_native_result="0xde0b6b3a7630000", tables=fresh))
    _add_checkpoint_index(evidence, "BEF-SC-010", checkpoints,
                          {"oldGenerationAfterStaleServiceSnapshot": adapter._ref(old_after_item)})


def test_sc010_complete_raw_reset_fence_and_fresh_execution_passes(evidence: Evidence) -> None:
    _build_sc010(evidence)
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-010") == {
        "stale_generation_fenced": True, "chain_baseline": True, "service_baseline": True,
        "fixture_hash": True, "equivalent_probe_outcome": True,
    }


def _sc010_fee_inputs(evidence: Evidence) -> tuple[
    dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]], dict[str, Any], dict[str, Any],
]:
    checkpoints = adapter._checkpoint_map(evidence, "BEF-SC-010")
    assert checkpoints is not None
    trial, fresh = checkpoints[("trial", "a")], checkpoints[("fresh_trial", "a")]
    trial_tables = adapter._service_tables(evidence, trial["service"])
    fresh_tables = adapter._service_tables(evidence, fresh["service"])
    assert trial_tables is not None and fresh_tables is not None
    return trial_tables, fresh_tables, trial["chain"], fresh["chain"]


def _sc010_fee_equivalent(evidence: Evidence) -> bool:
    trial_tables, fresh_tables, trial_chain, fresh_chain = _sc010_fee_inputs(evidence)
    return adapter.sc010_fee_normalized_equivalent(
        evidence, trial_tables, fresh_tables, trial_chain, fresh_chain, "a", "ga-old", "ga-new",
    )


def _replace_checkpoint_rpc_result(evidence: Evidence, phase: str, key: str, result: Any) -> None:
    report = next(item for item in evidence.artifacts
                  if item.payload.get("schemaVersion") == "bef-sc009010-checkpoint-index/v1"
                  and item.payload.get("scenarioId") == "BEF-SC-010")
    report_payload = report.payload
    checkpoint_rows = [dict(row) for row in report_payload["checkpoints"]]
    checkpoint = next(row for row in checkpoint_rows
                      if row.get("phase") == phase and row.get("environmentId") == "a")
    chain_ref = checkpoint["chainSnapshot"]
    chain_item = next(item for item in evidence.artifacts if item.relative_path == chain_ref["path"])
    chain_payload = dict(chain_item.payload)
    reads = dict(chain_payload["reads"])
    read_ref = dict(reads[key])
    rpc_item = next(item for item in evidence.artifacts if item.relative_path == read_ref["path"])
    replacement_rpc = _replace_payload(evidence, rpc_item, {**rpc_item.payload, "result": result})
    read_ref["sha256"] = replacement_rpc.sha256
    reads[key] = read_ref
    chain_payload["reads"] = reads
    replacement_chain = _replace_payload(evidence, chain_item, chain_payload)
    checkpoint["chainSnapshot"] = {"path": replacement_chain.relative_path, "sha256": replacement_chain.sha256}
    report_payload = {**report_payload, "checkpoints": checkpoint_rows}
    _replace_payload(evidence, report, report_payload)


def _receipt_for_operation(evidence: Evidence, operation_id: str) -> Artifact:
    return next(item for item in evidence.artifacts
                if item.payload.get("operationId") == operation_id
                and item.payload.get("method") == "eth_getTransactionReceipt")


def test_sc010_receipt_gas_variance_is_normalized_by_exact_native_fee_delta(evidence: Evidence) -> None:
    _build_sc010(evidence)
    receipt = _receipt_for_operation(evidence, "fresh-swap")
    receipt_result = dict(receipt.payload["result"])
    receipt_result["gasUsed"] = "0x5209"
    _replace_payload(evidence, receipt, {**receipt.payload, "result": receipt_result})
    checkpoints = adapter._checkpoint_map(evidence, "BEF-SC-010")
    assert checkpoints is not None
    fresh_reads = checkpoints[("fresh_trial", "a")]["chain"]["reads"]
    payer_native_read = next(item for item in evidence.artifacts
                             if item.relative_path == fresh_reads["payerNative"]["path"])
    adjusted_native = int(payer_native_read.payload["result"], 16) - 6_000_000
    _replace_checkpoint_rpc_result(evidence, "fresh_trial", "payerNative", hex(adjusted_native))
    assert _sc010_fee_equivalent(evidence)
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-010")["equivalent_probe_outcome"] is True


@pytest.mark.parametrize("mutation", [
    "missing_receipt", "wrong_sender", "forged_native_delta", "native_principal",
    "fee_over_policy", "effective_price_mismatch", "gas_over_limit",
    "generation_payer_mismatch", "boolean_gas_limit", "aliased_transaction_hash",
])
def test_sc010_fee_normalization_rejects_mutations(evidence: Evidence, mutation: str) -> None:
    _build_sc010(evidence)
    trial_tables, fresh_tables, trial_chain, fresh_chain = _sc010_fee_inputs(evidence)
    if mutation == "missing_receipt":
        operation = next(row for row in fresh_tables["operations-by-generation"] if row["operation_kind"] == "swap")
        missing = _receipt_for_operation(evidence, str(operation["operation_id"]))
        evidence.artifacts.remove(missing)
    elif mutation == "wrong_sender":
        operation = next(row for row in trial_tables["operations-by-generation"] if row["operation_kind"] == "purchase")
        receipt = _receipt_for_operation(evidence, str(operation["operation_id"]))
        result = dict(receipt.payload["result"])
        result["from"] = trial_chain["addresses"]["payer"]
        _replace_payload(evidence, receipt, {**receipt.payload, "result": result})
    elif mutation == "forged_native_delta":
        payer_read = next(item for item in evidence.artifacts
                          if item.relative_path == trial_chain["reads"]["payerNative"]["path"])
        _replace_checkpoint_rpc_result(
            evidence, "trial", "payerNative", hex(int(payer_read.payload["result"], 16) + 1),
        )
    elif mutation == "native_principal":
        payer_read = next(item for item in evidence.artifacts
                          if item.relative_path == trial_chain["reads"]["payerNative"]["path"])
        _replace_checkpoint_rpc_result(
            evidence, "trial", "payerNative", hex(int(payer_read.payload["result"], 16) - 1),
        )
    elif mutation in {"fee_over_policy", "effective_price_mismatch", "gas_over_limit"}:
        operation = next(row for row in trial_tables["operations-by-generation"]
                         if row["operation_kind"] == ("swap" if mutation == "gas_over_limit" else "wrap"))
        receipt = _receipt_for_operation(evidence, str(operation["operation_id"]))
        result = dict(receipt.payload["result"])
        field = "gasUsed" if mutation == "gas_over_limit" else "effectiveGasPrice"
        value = "0x124f81" if mutation == "gas_over_limit" else (
            "0x4c4b40" if mutation == "effective_price_mismatch" else "0x6acfc0"
        )
        result[field] = value
        _replace_payload(evidence, receipt, {**receipt.payload, "result": result})
    elif mutation == "generation_payer_mismatch":
        trial_tables["generation-by-id"][0]["payer_address"] = "0x" + "9" * 40
    elif mutation == "boolean_gas_limit":
        selected = next(row for row in trial_tables["selected-execution-by-generation"]
                        if row["action_kind"] == "swap")
        selected["selected_action_json"]["gasLimit"] = True
    else:
        wrap = next(row for row in trial_tables["operations-by-generation"] if row["operation_kind"] == "wrap")
        approve = next(row for row in trial_tables["operations-by-generation"] if row["operation_kind"] == "approve")
        approve["transaction_hash"] = wrap["transaction_hash"]
        selected_approve = next(row for row in trial_tables["selected-execution-by-generation"]
                                if row["action_kind"] == "approve")
        selected_approve["transaction_hash"] = wrap["transaction_hash"]
        receipt = _receipt_for_operation(evidence, str(approve["operation_id"]))
        result = dict(receipt.payload["result"])
        result["transactionHash"] = wrap["transaction_hash"]
        _replace_payload(evidence, receipt, {
            **receipt.payload, "params": [wrap["transaction_hash"]], "result": result,
        })
    assert not adapter.sc010_fee_normalized_equivalent(
        evidence, trial_tables, fresh_tables, trial_chain, fresh_chain, "a", "ga-old", "ga-new",
    )


@pytest.mark.parametrize("mutant", ["stale_accepted", "chain_reset_mismatch", "post_stale_chain_change",
                                     "service_leak", "old_generation_work_mutated", "stale_before_reset",
                                     "fixture_drift", "previous_payment_mismatch", "previous_offer_missing",
                                     "stale_delivery_wrong_offer", "late_worker_invalid_body",
                                     "stale_wrong_reason", "stale_authorization_mismatch", "stale_denial_missing",
                                     "idempotency_key_not_reused", "operation_identity_reused"])
def test_sc010_rejects_stale_reset_and_equivalence_mutants(evidence: Evidence, mutant: str) -> None:
    options: dict[str, Any] = {}
    expected = "equivalent_probe_outcome"
    if mutant == "stale_accepted":
        options["stale_late_status"] = 200
        expected = "stale_generation_fenced"
    elif mutant == "chain_reset_mismatch":
        options["reset_state"] = {"payerNonce": "0x1"}
        expected = "chain_baseline"
    elif mutant == "post_stale_chain_change":
        options["after_stale_state"] = {"baseFeePerGas": "0x2"}
        expected = "chain_baseline"
    elif mutant == "service_leak":
        options["leak_after_stale"] = True
        expected = "service_baseline"
    elif mutant == "old_generation_work_mutated":
        options["old_work_mutated"] = True
        expected = "service_baseline"
    elif mutant == "stale_before_reset":
        options["stale_before_reset"] = True
        expected = "stale_generation_fenced"
    elif mutant == "fixture_drift":
        options["fresh_fixture_hash"] = "c" * 64
        expected = "fixture_hash"
    elif mutant == "previous_payment_mismatch":
        options["previous_payload_hash"] = "d" * 64
        expected = "stale_generation_fenced"
    elif mutant in {"late_worker_invalid_body", "stale_wrong_reason", "stale_authorization_mismatch", "stale_denial_missing"}:
        expected = "stale_generation_fenced"
    elif mutant in {"previous_offer_missing", "stale_delivery_wrong_offer"}:
        _build_sc010(evidence)
        target = "previous-payment" if mutant == "previous_offer_missing" else "stale-delivery"
        item = next(item for item in evidence.artifacts if item.relative_path == f"http/{target}.json")
        item.payload["request"]["body"] = {"resourceId": evidence.manifest["x402"]["resourceId"]}
        assert adapter.evaluate_sc009010(evidence, "BEF-SC-010")["stale_generation_fenced"] is False
        return
    elif mutant == "idempotency_key_not_reused":
        options["fresh_purchase_key"] = "new-key"
    elif mutant == "operation_identity_reused":
        options["duplicate_fresh_operation"] = True
    _build_sc010(evidence, **options)
    if mutant == "late_worker_invalid_body":
        item = next(item for item in evidence.artifacts if item.relative_path == "http/late-worker.json")
        item.payload["request"]["body"] = {}
    elif mutant == "stale_wrong_reason":
        item = next(item for item in evidence.artifacts if item.relative_path == "http/late-worker.json")
        item.payload["response"]["body"] = {"error": "participant_request_invalid"}
    elif mutant == "stale_authorization_mismatch":
        item = next(item for item in evidence.artifacts if item.relative_path == "http/late-worker.json")
        item.payload["request"]["headers"]["authorization-sha256"] = "1" * 64
    elif mutant == "stale_denial_missing":
        item = next(item for item in evidence.artifacts
                    if item.relative_path == "db/a-old_generation_after_stale-denials-by-generation.json")
        item.payload["rows"].pop()
    assert adapter.evaluate_sc009010(evidence, "BEF-SC-010")[expected] is False


@pytest.mark.parametrize("variant", ["concurrent_operations", "reused_operation_namespace"])
def test_sc010_and_sc009_paid_canonical_purchases_require_explicit_offer_id(evidence: Evidence, variant: str) -> None:
    if variant == "concurrent_operations":
        _build_sc009(evidence)
        scenario = "BEF-SC-009"
        purchase_variant = variant
    else:
        _build_sc010(evidence)
        scenario = "BEF-SC-010"
        purchase_variant = variant
    paid = [item for item in evidence.artifacts
            if item.payload.get("variantId") == purchase_variant
            and item.payload.get("request", {}).get("method") == "POST"
            and item.payload.get("request", {}).get("path", "").endswith("/purchase")
            and item.payload.get("response", {}).get("status") == 200]
    assert paid
    paid[0].payload["request"]["body"] = {"resourceId": evidence.manifest["x402"]["resourceId"]}
    key = "equivalent_probe_outcome" if scenario == "BEF-SC-010" else "independent_service_state"
    assert adapter.evaluate_sc009010(evidence, scenario)[key] is False
