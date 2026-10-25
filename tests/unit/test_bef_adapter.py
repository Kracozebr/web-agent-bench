"""Focused fail-closed tests for BEF probe evidence validation."""

from __future__ import annotations

import hashlib
import json
import base64
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.bdd.adapters import benchmark_environment_feasibility as bef_adapter
from tests.bdd.adapters.benchmark_environment_feasibility import (
    EvidenceInvalid,
    EvidenceArtifact,
    ProbeBlocked,
    ProbeEvidence,
    _keccak256,
    _contains_value,
    _delivery_row_is_durable,
    _delivered_bytes_match_pinned_hash,
    _facilitator_verified_authorization,
    _inspection_has_no_token_delta,
    _manifest_negative_variants_rejected,
    _numeric,
    _offer_identity_is_read_from_http,
    _payer_is_linked_to_receipt_and_database,
    _purchase_token_effects_match_receipt,
    _probe_timeout_seconds,
    _reject_secrets,
    _replay_is_read_only,
    _replay_local_rpc_states_match,
    _verified_original_capture,
    _source_reads_are_allowlisted,
    _x402_compatibility_matches,
    _x402_negative_variants_are_not_paid_success,
)


SC006_CONTENT = b'{"resource":"pinned"}'
SC006_CONTENT_HASH = hashlib.sha256(SC006_CONTENT).hexdigest()
SC006_PAYER = "0x" + "11" * 20
SC006_PAYTO = "0x" + "22" * 20
SC006_ASSET = "0x" + "aa" * 20


def _sc006_evidence(artifacts: list[EvidenceArtifact], *, operations: list[dict[str, Any]] | None = None) -> ProbeEvidence:
    if not any(
        artifact.payload.get("queryName") == "observer-role-effective-privileges"
        for artifact in artifacts
    ):
        role_flags = {
            "is_superuser": False,
            "can_create_db": False,
            "can_create_role": False,
            "can_replicate": False,
            "can_bypass_rls": False,
            "can_create_in_schema": False,
            "can_create_in_database": False,
        }
        write_flags = {
            "can_insert": False,
            "can_update": False,
            "can_delete": False,
            "can_truncate": False,
            "can_references": False,
            "can_trigger": False,
        }
        artifacts = [
            *artifacts,
            _sc006_artifact("db/observer-role-effective-privileges.json", "readonly-database", {
                "boundary": "readonly-database", "operationId": None, "variantId": None,
                "databaseRole": "bef_observer", "readOnly": True,
                "queryName": "observer-role-effective-privileges",
                "role": {"role_name": "bef_observer", **role_flags},
                "rows": [
                    {"table_name": table, "can_select": True, **write_flags}
                    for table in (
                        "bef_delivery", "bef_denial", "bef_environment", "bef_evidence_artifact",
                        "bef_generation", "bef_operation", "bef_payment", "bef_resource_sample",
                        "bef_rpc_observation", "bef_schema_migration", "bef_selected_execution",
                        "bef_selected_execution_event", "bef_x402_observation",
                    )
                ],
            }),
        ]
    return ProbeEvidence(
        scenario_id="BEF-SC-006",
        status="captured",
        directory=Path("."),
        index={"operations": operations or []},
        manifest={"x402": {
            "resourceId": "bef-resource-v1", "resourceSha256": SC006_CONTENT_HASH,
            "amount": "100000", "asset": SC006_ASSET, "network": "eip155:8453", "scheme": "exact",
            "maxTimeoutSeconds": 120, "assetTransferMethod": "eip3009",
            "eip712Domain": {"name": "USD Coin", "version": "2"},
        }},
        manifest_sha256="b" * 64,
        artifacts=tuple(artifacts),
        environment_id="bef-a",
        generation_id="generation-1",
    )


def _sc006_artifact(path: str, boundary: str, payload: dict[str, Any]) -> EvidenceArtifact:
    if boundary == "readonly-database":
        payload.setdefault("readOnly", True)
        payload.setdefault("databaseRole", "bef_observer")
        if payload.get("queryName") != "observer-role-effective-privileges":
            payload.setdefault("transactionReadOnly", "on")
    return EvidenceArtifact(path, "c" * 64, boundary, payload)


SCENARIO_ID = "BEF-SC-004"
MANIFEST = {
    "schemaVersion": "bef-runtime-manifest/v1",
    "change": "benchmark-environment-feasibility",
}


def _write_json(path: Path, value: Any) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    path.write_bytes(content)
    return content


def _captured_index(
    directory: Path,
    extra_artifacts: list[dict[str, Any]] | None = None,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest_bytes = _write_json(directory / "manifest.json", manifest or MANIFEST)
    artifacts = [
        {
            "path": "manifest.json",
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "contentType": "application/json",
            "boundary": "runtime-manifest",
        }
    ]
    artifacts.extend(extra_artifacts or [])
    return {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": SCENARIO_ID,
        "status": "captured",
        "manifest": {"path": "manifest.json", "sha256": hashlib.sha256(manifest_bytes).hexdigest()},
        "environment": {"envId": "bef-a", "generation": {"generationId": "generation-1", "participantId": "participant-1", "payerAddress": "0x" + "11" * 20}},
        "operations": [],
        "observations": [],
        "artifacts": artifacts,
        "applicationSourceSha256": "a" * 64,
        "probeSourceSha256": "b" * 64,
        "runtimeVersions": {"node": "24.22.1"},
        "sourceBlock": {"number": "0x32871b6", "hash": "0x" + "88" * 32},
    }


def _add_artifact(index: dict[str, Any], directory: Path, relative_path: str, payload: dict[str, Any], boundary: str) -> str:
    content = _write_json(directory / relative_path, payload)
    digest = hashlib.sha256(content).hexdigest()
    index["artifacts"].append({
        "path": relative_path,
        "sha256": digest,
        "contentType": "application/json",
        "boundary": boundary,
    })
    return digest


def _bound_source_rpc_observation(
    index: dict[str, Any],
    *,
    operation_id: str,
    method: str,
    params: list[Any],
    result: Any,
) -> dict[str, Any]:
    request_body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    response_envelope = {"jsonrpc": "2.0", "id": 1, "result": result}
    encoded_response = json.dumps(response_envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    request_bytes = len(json.dumps(request_body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    before = {"forwarded": 0, "denied": 0, "sourceCallsReserved": 0}
    after = {"forwarded": 1, "denied": 0, "sourceCallsReserved": 1}
    return {
        "schemaVersion": "bef-rpc-observation/v1",
        "boundary": "source-readonly-proxy",
        "endpointBoundary": "source-readonly-proxy",
        "operationId": operation_id,
        "variantId": None,
        "method": method,
        "params": params,
        "requestedBlock": params[1] if len(params) > 1 else None,
        "result": result,
        "forwarded": True,
        "requestBody": request_body,
        "requestBytes": request_bytes,
        "requestId": request_body["id"],
        "responseBodyBase64": base64.b64encode(encoded_response).decode("ascii"),
        "responseBodySha256": hashlib.sha256(encoded_response).hexdigest(),
        "responseBytes": len(encoded_response),
        "responseStatus": 200,
        "responseCorrelated": True,
        "sourceProxyCounterDelta": {
            "method": method,
            "sourceProxyManifestSha256": index["manifest"]["sha256"],
            "sourceCallLimit": 8,
            "before": before,
            "after": after,
            "forwarded": 1,
            "denied": 0,
            "sourceCallsReserved": 1,
        },
    }


def _purchase_evidence(
    tmp_path: Path,
    *,
    transfer_to: str | None = None,
    observed_amount: int = 100000,
    include_x402_observation: bool = True,
    x402_observation_payer: str | None = None,
    x402_observation_pay_to: str | None = None,
    x402_row_variant: str | None = None,
    payment_facilitator_address: str | None = None,
    unrelated_facilitator_verify: bool = False,
    variant_effect_snapshots: bool = False,
    duplicate_primary_payment_rows: bool = False,
    duplicate_primary_delivery_rows: bool = False,
    extra_primary_payment_row: dict[str, Any] | None = None,
    extra_primary_delivery_row: dict[str, Any] | None = None,
) -> ProbeEvidence:
    payer = "0x" + "11" * 20
    pay_to = "0x" + "22" * 20
    asset = "0x" + "aa" * 20
    tx_hash = "0x" + "33" * 32
    resource_bytes = b'{"resource":"pinned"}'
    resource_hash = hashlib.sha256(resource_bytes).hexdigest()
    manifest = {
        **MANIFEST,
        "contracts": {"usdc": {"address": asset}},
        "x402": {
            "asset": asset,
            "amount": "100000",
            "resourceId": "bef-resource-v1",
            "resourceSha256": resource_hash,
            "network": "eip155:8453",
            "scheme": "exact",
        },
    }
    index = _captured_index(tmp_path, manifest=manifest)
    index["environment"]["generation"]["payerAddress"] = payer
    index["operations"] = [{"operationId": "purchase-op", "transactionHash": tx_hash}]
    if unrelated_facilitator_verify:
        index["operations"].append({"operationId": "unrelated-operation"})
    challenge = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": "purchase-op",
        "variantId": None,
        "request": {"method": "POST", "path": "/v1/environments/bef-a/tools/purchase", "headers": {}, "body": {"resourceId": "bef-resource-v1"}},
        "response": {
            "status": 402,
            "headers": {},
            "body": {},
            "decodedProtocol": {
                "paymentRequired": {
                    "accepts": [{"scheme": "exact", "network": "eip155:8453", "asset": asset, "amount": "100000", "payTo": pay_to}]
                }
            },
        },
    }
    _add_artifact(index, tmp_path, "http/challenge.json", challenge, "actual-tool-http")
    encoded_resource = base64.b64encode(resource_bytes).decode("ascii")
    success_body = {
        "resourceId": "bef-resource-v1",
        "contentType": "application/json",
        "contentHash": resource_hash,
        "contentBytes": encoded_resource,
    }
    raw_success_body = json.dumps(success_body, separators=(",", ":")).encode("utf-8")
    success = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": "purchase-op",
        "variantId": None,
        "request": {
            "method": "POST",
            "path": "/v1/environments/bef-a/tools/purchase",
            "headers": {"payment-signature": "[REDACTED]", "payment-signature-present": True},
            "body": {"resourceId": "bef-resource-v1"},
        },
        "response": {"status": 200, "headers": {}, "body": success_body, "bodyBase64": base64.b64encode(raw_success_body).decode("ascii")},
    }
    _add_artifact(index, tmp_path, "http/purchase-success.json", success, "actual-tool-http")
    payment_row = {
        "payment_id": "payment-primary",
        "operation_id": "purchase-op",
        "transaction_hash": tx_hash,
        "payer_address": payer,
        "facilitator_address": payment_facilitator_address or pay_to,
        "asset_address": asset,
        "amount_units": str(observed_amount),
        "receipt_status": "success",
    }
    _add_artifact(index, tmp_path, "db/payment.json", {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
        "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "payments-by-operation", "rows": [payment_row],
    }, "readonly-database")
    delivery_row = {
        "delivery_id": "delivery-primary",
        "operation_id": "purchase-op",
        "content_sha256": resource_hash,
        "delivered_at": "2026-10-23T10:00:00Z",
    }
    _add_artifact(index, tmp_path, "db/delivery.json", {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
        "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "deliveries-by-operation",
        "rows": [delivery_row],
    }, "readonly-database")
    if variant_effect_snapshots:
        for name, query_name, row in (
            ("payment", "payments-by-operation", payment_row),
            ("delivery", "deliveries-by-operation", delivery_row),
        ):
            _add_artifact(index, tmp_path, f"db/variant-{name}.json", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
                "variantId": "other-variant", "readOnly": True, "databaseRole": "bef_readonly_observer",
                "queryName": query_name, "rows": [row],
            }, "readonly-database")
    if duplicate_primary_payment_rows:
        _add_artifact(index, tmp_path, "db/payment-duplicate-rows.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "payments-by-operation",
            "rows": [payment_row, {**payment_row, "payment_id": "payment-duplicate"}],
        }, "readonly-database")
    if extra_primary_payment_row is not None:
        _add_artifact(index, tmp_path, "db/payment-contradictory-row.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "payments-by-operation",
            "rows": [payment_row, {**payment_row, **extra_primary_payment_row}],
        }, "readonly-database")
    if duplicate_primary_delivery_rows:
        _add_artifact(index, tmp_path, "db/delivery-duplicate-rows.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "deliveries-by-operation",
            "rows": [delivery_row, {**delivery_row, "delivery_id": "delivery-duplicate"}],
        }, "readonly-database")
    if extra_primary_delivery_row is not None:
        _add_artifact(index, tmp_path, "db/delivery-contradictory-row.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "deliveries-by-operation",
            "rows": [delivery_row, {**delivery_row, **extra_primary_delivery_row}],
        }, "readonly-database")
    generation_id = "generation-primary"
    for query_name, rows in (
        ("operation-by-id", [{"operation_id": "purchase-op", "generation_id": generation_id}]),
        ("generation-by-id", [{"generation_id": generation_id, "payer_address": payer}]),
    ):
        _add_artifact(index, tmp_path, f"db/{query_name}.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": query_name, "rows": rows,
        }, "readonly-database")
    if include_x402_observation:
        _add_artifact(index, tmp_path, "db/x402-observations-by-operation.json", {
            "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "purchase-op",
            "variantId": None, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "x402-observations-by-operation",
            "rows": [{
                "operation_id": "purchase-op", "generation_id": generation_id,
                "variant_id": x402_row_variant, "phase": "verify", "outcome": "success",
                "transaction_hash": None,
                "safe_request": {"paymentRequirements": {
                    "scheme": "exact", "network": "eip155:8453", "asset": asset, "amount": "100000",
                    "payTo": x402_observation_pay_to or pay_to,
                }},
                "safe_response": {"isValid": True, "payer": x402_observation_payer or payer},
            }],
        }, "readonly-database")
    if unrelated_facilitator_verify:
        _add_artifact(index, tmp_path, "http/unrelated-facilitator-verify.json", {
            "schemaVersion": "bef-http-observation/v1", "boundary": "facilitator-http", "operationId": "unrelated-operation", "variantId": None,
            "request": {"method": "POST", "path": "/verify", "headers": {}, "body": {}},
            "response": {"status": 200, "headers": {}, "body": {"isValid": True, "payer": payer}},
        }, "facilitator-http")
    transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    transfer = {
        "address": asset,
        "topics": [transfer_topic, "0x" + payer[2:].rjust(64, "0"), "0x" + (transfer_to or pay_to)[2:].rjust(64, "0")],
        "data": hex(observed_amount),
    }
    _add_artifact(index, tmp_path, "rpc/receipt.json", {
        "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
        "operationId": "purchase-op", "variantId": None, "method": "eth_getTransactionReceipt", "params": [tx_hash],
        "result": {"transactionHash": tx_hash, "status": "0x1", "logs": [transfer]},
    }, "local-chain-readonly-proxy")
    for role, account in (("payer", payer), ("payto", pay_to)):
        before = 200000 if role == "payer" else 100
        after = before - observed_amount if role == "payer" else before + observed_amount
        for phase, balance in (("before", before), ("after", after)):
            path = f"rpc/purchase-{role}-{phase}.json"
            _add_artifact(index, tmp_path, path, {
                "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
                "operationId": "purchase-op", "variantId": None, "method": "eth_call",
                "params": [{"to": asset, "data": "0x70a08231" + account[2:].rjust(64, "0")}, "latest"],
                "result": hex(balance),
            }, "local-chain-readonly-proxy")
    return _load(tmp_path, index)


def _negative_purchase_evidence(
    tmp_path: Path,
    *,
    wrong_token_status: int = 402,
    wrong_token_rechallenge: bool = True,
    wrong_token_error: str = "No matching payment requirements",
    wrong_token_header_error: str | None = None,
    wrong_token_accepted_asset: str | None = None,
    wrong_token_reoffer_asset: str | None = None,
    wrong_token_header_reoffer_asset: str | None = None,
    wrong_token_signature_digest: str | None = "c" * 64,
    wrong_token_source_header_digest: str | None = None,
    wrong_token_database_rejection: bool = True,
    verify_generation_payer: str | None = None,
    verify_observation_payer: str | None = None,
) -> ProbeEvidence:
    payer = "0x" + "11" * 20
    payer_by_variant = {
        "wrong_token_representation": "0x" + "33" * 20,
        "verification_without_receipt": "0x" + "44" * 20,
        "mismatched_data": "0x" + "55" * 20,
    }
    pay_to = "0x" + "22" * 20
    asset = "0x" + "aa" * 20
    wrong_asset = wrong_token_accepted_asset or ("0x" + "bb" * 20)
    reoffer_asset = wrong_token_reoffer_asset or asset
    pinned_bytes = b'{"resource":"pinned"}'
    pinned_hash = hashlib.sha256(pinned_bytes).hexdigest()
    wrong_bytes = b'{"resource":"changed"}'
    wrong_hash = hashlib.sha256(wrong_bytes).hexdigest()
    manifest = {
        **MANIFEST,
        "contracts": {"usdc": {"address": asset}},
        "x402": {"asset": asset, "amount": "100000", "resourceId": "bef-resource-v1", "resourceSha256": pinned_hash, "network": "eip155:8453", "scheme": "exact"},
    }
    index = _captured_index(tmp_path, manifest=manifest)
    index["environment"]["generation"]["payerAddress"] = payer
    index["operations"] = [{"operationId": f"{name}-op"} for name in ("wrong-token", "verify", "mismatch")]

    def http(name: str, operation_id: str, variant: str, boundary: str, method: str, status: int, label: str, *, signed: bool = False, valid: bool = False) -> None:
        body = {"isValid": True, "payer": payer_by_variant[variant]} if valid else {}
        headers = {"payment-signature": "[REDACTED]", "payment-signature-present": True} if signed else {}
        request = {"method": method, "path": f"/v1/environments/bef-a/tools/purchase" if boundary == "actual-tool-http" else "/verify", "headers": headers, "body": {}}
        if signed and variant == "wrong_token_representation":
            if wrong_token_signature_digest is not None:
                request["headers"]["payment-signature-sha256"] = wrong_token_signature_digest
            request["decodedPaymentPayload"] = {
                "x402Version": 2,
                "sourceHeaderSha256": wrong_token_source_header_digest or wrong_token_signature_digest,
                "accepted": {
                    "scheme": "exact", "network": "eip155:8453", "asset": wrong_asset,
                    "amount": "100000", "payTo": pay_to,
                },
            }
        response_headers: dict[str, Any] = {}
        decoded_required: dict[str, Any] | None = None
        if (
            variant == "wrong_token_representation" and label == "retry" and status == 402
            and wrong_token_rechallenge
        ):
            reoffer = {
                "scheme": "exact", "network": "eip155:8453", "asset": reoffer_asset,
                "amount": "100000", "payTo": pay_to,
            }
            protocol = {"x402Version": 2, "accepts": [reoffer]}
            header_reoffer = {**reoffer, "asset": wrong_token_header_reoffer_asset or reoffer_asset}
            header_protocol = {
                "x402Version": 2,
                "accepts": [header_reoffer],
                "error": wrong_token_header_error or wrong_token_error,
            }
            response_headers["payment-required"] = base64.b64encode(
                json.dumps(header_protocol, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            decoded_required = {"error": wrong_token_error, **protocol}
        payload = {
            "schemaVersion": "bef-http-observation/v1", "boundary": boundary, "operationId": operation_id, "variantId": variant,
            "request": request,
            "response": {"status": status, "headers": response_headers, "body": body,
                          **({"decodedPaymentRequired": decoded_required} if decoded_required is not None else {})},
        }
        _add_artifact(index, tmp_path, f"http/{name}-{label}.json", payload, boundary)

    def challenge(name: str, operation_id: str, variant: str) -> None:
        payload = {
            "schemaVersion": "bef-http-observation/v1", "boundary": "actual-tool-http", "operationId": operation_id, "variantId": variant,
            "request": {"method": "POST", "path": "/v1/environments/bef-a/tools/purchase", "headers": {}, "body": {}},
            "response": {"status": 402, "headers": {}, "body": {}, "decodedProtocol": {"paymentRequired": {"accepts": [{
                "scheme": "exact", "network": "eip155:8453", "asset": asset, "amount": "100000", "payTo": pay_to,
            }]}}},
        }
        _add_artifact(index, tmp_path, f"http/{name}-challenge.json", payload, "actual-tool-http")

    challenge("wrong-token", "wrong-token-op", "wrong_token_representation")
    http("wrong-token", "wrong-token-op", "wrong_token_representation", "actual-tool-http", "POST", wrong_token_status, "retry", signed=True)
    challenge("verify", "verify-op", "verification_without_receipt")
    http("verify", "verify-op", "verification_without_receipt", "facilitator-http", "POST", 200, "verify", valid=True)
    challenge("mismatch", "mismatch-op", "mismatched_data")
    http("mismatch", "mismatch-op", "mismatched_data", "actual-tool-http", "POST", 400, "retry", signed=True)

    for variant, operation_id, prefix in (
        ("wrong_token_representation", "wrong-token-op", "wrong-token"),
        ("verification_without_receipt", "verify-op", "verify"),
        ("mismatched_data", "mismatch-op", "mismatch"),
    ):
        generation_id = f"generation-{prefix}"
        for query_name, rows in (
            ("operation-by-id", [{"operation_id": operation_id, "generation_id": generation_id,
                                  **({"status": "rejected", "transaction_hash": None} if variant == "wrong_token_representation" else {})}]),
            ("generation-by-id", [{"generation_id": generation_id, "payer_address": (
                verify_generation_payer if variant == "verification_without_receipt" and verify_generation_payer else payer_by_variant[variant]
            )}]),
        ):
            _add_artifact(index, tmp_path, f"db/{prefix}-{query_name}.json", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": operation_id,
                "variantId": variant, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": query_name, "rows": rows,
            }, "readonly-database")
        if variant == "wrong_token_representation" and wrong_token_database_rejection:
            _add_artifact(index, tmp_path, f"db/{prefix}-denials-by-generation.json", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": operation_id,
                "variantId": variant, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": "denials-by-generation",
                "rows": [{"operation_id": operation_id, "generation_id": generation_id, "reason_code": "payment_protocol_rejected"}],
            }, "readonly-database")
        for query in (("payments-by-operation", "deliveries-by-operation") if variant != "mismatched_data" else ("deliveries-by-operation",)):
            _add_artifact(index, tmp_path, f"db/{prefix}-{query}.json", {
                "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": operation_id,
                "variantId": variant, "readOnly": True, "databaseRole": "bef_readonly_observer", "queryName": query, "rows": [],
            }, "readonly-database")
    _add_artifact(index, tmp_path, "db/verify-x402-observations-by-operation.json", {
        "schemaVersion": "bef-db-observation/v1", "boundary": "readonly-database", "operationId": "verify-op",
        "variantId": "verification_without_receipt", "readOnly": True, "databaseRole": "bef_readonly_observer",
        "queryName": "x402-observations-by-operation", "rows": [{
            "operation_id": "verify-op", "generation_id": "generation-verify", "variant_id": "verification_without_receipt",
            "phase": "verify", "outcome": "success", "transaction_hash": None,
            "safe_request": {"paymentRequirements": {"scheme": "exact", "network": "eip155:8453", "asset": asset, "amount": "100000", "payTo": pay_to}},
            "safe_response": {"isValid": True, "payer": verify_observation_payer or payer_by_variant["verification_without_receipt"]},
        }],
    }, "readonly-database")
    for variant, operation_id, prefix in (
        ("wrong_token_representation", "wrong-token-op", "wrong-token"),
        ("verification_without_receipt", "verify-op", "verify"),
    ):
        for role, account in (("payer", payer_by_variant[variant]), ("payto", pay_to)):
            for phase in ("before", "after"):
                _add_artifact(index, tmp_path, f"rpc/{prefix}-{role}-{phase}.json", {
                    "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
                    "operationId": operation_id, "variantId": variant, "method": "eth_call",
                    "params": [{"to": asset, "data": "0x70a08231" + account[2:].rjust(64, "0")}, "latest"], "result": "0x64",
                }, "local-chain-readonly-proxy")
    _add_artifact(index, tmp_path, "resource/mismatch-proof.json", {
        "schemaVersion": "bef-resource-observation/v1", "boundary": "resource-data", "operationId": "mismatch-op", "variantId": "mismatched_data",
        "claimedSha256": pinned_hash, "actualDataSha256": wrong_hash, "actualContentBytesBase64": base64.b64encode(wrong_bytes).decode("ascii"),
    }, "resource-data")
    return _load(tmp_path, index)


def _load(
    directory: Path,
    index: dict[str, Any] | None = None,
    scenario_id: str = SCENARIO_ID,
) -> ProbeEvidence:
    payload = index or _captured_index(directory)
    _write_json(directory / "probe.json", payload)
    return ProbeEvidence.load(Path.cwd(), scenario_id, directory)


def test_blocked_probe_is_classified_without_fabricated_observations(tmp_path: Path) -> None:
    blocked = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": SCENARIO_ID,
        "status": "blocked",
        "reasonCode": "manifest_missing",
        "missingPrerequisites": ["infrastructure/benchmark-environment/manifest.json"],
        "manifest": None,
        "environment": None,
        "operations": [],
        "observations": [],
        "artifacts": [],
    }
    _write_json(tmp_path / "probe.json", blocked)

    with pytest.raises(ProbeBlocked, match="manifest_missing"):
        ProbeEvidence.load(Path.cwd(), SCENARIO_ID, tmp_path)


def test_artifact_path_traversal_is_rejected(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    index["artifacts"].append({
        "path": "../outside.json",
        "sha256": "c" * 64,
        "contentType": "application/json",
        "boundary": "readonly-database",
    })
    _write_json(tmp_path / "probe.json", index)

    with pytest.raises(EvidenceInvalid, match="escapes"):
        ProbeEvidence.load(Path.cwd(), SCENARIO_ID, tmp_path)


def test_artifact_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    index["artifacts"][0]["sha256"] = "c" * 64
    _write_json(tmp_path / "probe.json", index)

    with pytest.raises(EvidenceInvalid, match="SHA-256 mismatch"):
        ProbeEvidence.load(Path.cwd(), SCENARIO_ID, tmp_path)


def test_unindexed_operation_remains_rejected_for_all_artifacts(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    index["operations"] = [{"operationId": "00000000-0000-4000-8000-000000000001"}]
    _add_artifact(index, tmp_path, "db/unindexed-operation.json", {
        "schemaVersion": "bef-db-observation/v1",
        "boundary": "readonly-database",
        "operationId": "00000000-0000-4000-8000-000000000002",
        "variantId": None,
        "readOnly": True,
        "databaseRole": "bef_readonly_observer",
        "queryName": "operation-by-id",
        "rows": [],
    }, "readonly-database")

    with pytest.raises(EvidenceInvalid, match="unindexed operation"):
        _load(tmp_path, index)


def test_unredacted_payment_credential_is_rejected(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    raw = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": None,
        "request": {"method": "GET", "path": "/offer", "headers": {"authorization": "Bearer secret-value"}, "body": None},
        "response": {"status": 200, "headers": {}, "body": {}},
    }
    body = _write_json(tmp_path / "http" / "offer.json", raw)
    index["artifacts"].append({
        "path": "http/offer.json",
        "sha256": hashlib.sha256(body).hexdigest(),
        "contentType": "application/json",
        "boundary": "actual-tool-http",
    })
    _write_json(tmp_path / "probe.json", index)

    with pytest.raises(EvidenceInvalid, match="sensitive field|credential-like"):
        ProbeEvidence.load(Path.cwd(), SCENARIO_ID, tmp_path)


def test_authorization_digest_from_capture_loads_without_allowing_raw_bearer(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    raw = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": None,
        "request": {
            "method": "POST",
            "path": "/tools/bef-a/purchase",
            "headers": {"authorization-present": True, "authorization-sha256": "a" * 64},
            "body": {"resourceId": "bef-resource-v1"},
        },
        "response": {"status": 200, "headers": {}, "body": {}},
    }
    body = _write_json(tmp_path / "http" / "authorization-digest.json", raw)
    index["artifacts"].append({
        "path": "http/authorization-digest.json",
        "sha256": hashlib.sha256(body).hexdigest(),
        "contentType": "application/json",
        "boundary": "actual-tool-http",
    })

    evidence = _load(tmp_path, index)
    assert any(item.relative_path == "http/authorization-digest.json" for item in evidence.artifacts)


def test_observation_label_does_not_prove_offer_identity(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    index["observations"] = [{"id": "offer_identity", "sourceArtifact": "manifest.json"}]
    evidence = _load(tmp_path, index)

    assert evidence.index["observations"][0]["id"] == "offer_identity"
    assert not _offer_identity_is_read_from_http(evidence)


def test_keccak_uses_ethereum_legacy_padding() -> None:
    assert _keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_integer_amount_comparison_preserves_one_wei_and_booleans_are_not_numbers() -> None:
    assert not _contains_value(
        {"amount_units": "10000000000000000001"},
        {"amountUnits"},
        "10000000000000000000",
    )
    assert not _contains_value({"receiptStatus": True}, {"receiptStatus"}, 1)
    assert _numeric(float("inf")) is None
    assert _numeric(Decimal("NaN")) is None


def test_probe_timeout_uses_trial_limit_plus_bounded_margin(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, {"guardrails": {"maxTrialSeconds": 120, "maxSwapScenarioSeconds": 1800}})
    assert _probe_timeout_seconds(manifest_path) == 150
    assert _probe_timeout_seconds(manifest_path, "BEF-SC-007") == 1830
    _write_json(manifest_path, {"guardrails": {"maxTrialSeconds": 999999}})
    assert _probe_timeout_seconds(manifest_path) == 60


def test_probe_capture_launches_node_with_package_local_tsx_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    probe_source = repository / bef_adapter.PROBE_SOURCE_RELATIVE
    probe_source.parent.mkdir(parents=True)
    probe_source.write_text("// probe entry", encoding="utf-8")
    tsx_loader = repository / bef_adapter.TSX_LOADER_RELATIVE
    tsx_loader.parent.mkdir(parents=True)
    tsx_loader.write_text("// tsx loader", encoding="utf-8")
    node = r"C:\Program Files\nodejs\node.exe"
    evidence_root = tmp_path / "captures"
    monkeypatch.setenv("BEF_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setattr(bef_adapter.shutil, "which", lambda name: node if name == "node" else None)
    monkeypatch.setattr(bef_adapter, "_probe_timeout_seconds", lambda _manifest, _scenario: 17)
    captured_evidence = object()
    monkeypatch.setattr(
        bef_adapter.ProbeEvidence,
        "load",
        classmethod(lambda _cls, _root, _scenario, _directory: captured_evidence),
    )
    observed: dict[str, Any] = {}

    def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout_seconds: int) -> Any:
        observed.update(command=command, cwd=cwd, env=env, timeout_seconds=timeout_seconds)
        evidence_dir = Path(command[command.index("--evidence-dir") + 1])
        (evidence_dir / "probe.json").write_text("{}", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bef_adapter, "_run_probe_command", run)
    case = bef_adapter.BenchmarkEnvironmentCase("BEF-SC-001", object())
    case._repository_root = repository
    context = SimpleNamespace(outcome=None)

    case._capture(context)

    command = observed["command"]
    assert command[:4] == [node, "--import", tsx_loader.resolve().as_uri(), str(probe_source)]
    assert command[4:6] == ["--scenario", "BEF-SC-001"]
    assert "pnpm" not in " ".join(command).lower()
    assert observed["cwd"] == repository
    assert observed["env"]["BEF_EVIDENCE_ROOT"] == str(evidence_root)
    assert observed["timeout_seconds"] == 17
    assert context.outcome is captured_evidence


def test_real_manifest_env_reference_and_transport_secret_metadata_are_allowed(tmp_path: Path) -> None:
    manifest = json.loads(Path("infrastructure/benchmark-environment/manifest.json").read_text(encoding="utf-8"))
    _reject_secrets(manifest, "runtime manifest")
    evidence_index = _captured_index(tmp_path)
    transport_payload = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "actual-tool-http",
        "operationId": None,
        "variantId": None,
        "request": {
            "method": "GET",
            "path": "/v1/environments/bef-a/tools/offer",
            "headers": {
                "authorization": "[REDACTED]",
                "authorization-present": True,
                "payment-signature": "[REDACTED]",
                "payment-signature-present": True,
                "payment-signature-sha256": "a" * 64,
            },
            "body": None,
        },
        "response": {"status": 200, "headers": {}, "body": {}},
    }
    _add_artifact(evidence_index, tmp_path, "http/transport.json", transport_payload, "actual-tool-http")
    _load(tmp_path, evidence_index)


def test_probe_secret_checker_rejects_non_metadata_key_material() -> None:
    with pytest.raises(EvidenceInvalid, match="unredacted sensitive field"):
        _reject_secrets({"payment-signature": "0x" + "12" * 65}, "HTTP artifact")


def test_probe_secret_checker_rejects_generic_credential_fields() -> None:
    with pytest.raises(EvidenceInvalid, match="unredacted sensitive field"):
        _reject_secrets({"canaryCredential": "CANARY"}, "synthetic artifact")


def test_manifest_negative_variant_names_are_not_rejection_evidence(tmp_path: Path) -> None:
    index = _captured_index(tmp_path)
    for variant in ("wrong_block", "wrong_chain", "missing_code", "unsupported_asset_scheme", "per_trial_latest"):
        payload = {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "private-admin-http",
            "operationId": None,
            "variantId": variant,
            "request": {"method": "POST", "path": "/internal/admin/environments/bef-a/generations", "headers": {}, "body": {}},
            "response": {"status": 400, "headers": {}, "body": {"error": "rejected"}},
        }
        _add_artifact(index, tmp_path, f"http/{variant}.json", payload, "private-admin-http")
    manifest = {
        **MANIFEST,
        "source": {"blockNumber": "0x32871b4", "chainId": 8453},
        "local": {"chainId": 8453},
        "x402": {"asset": "0x" + "aa" * 20, "scheme": "exact"},
    }
    index = _captured_index(tmp_path, manifest=manifest, extra_artifacts=index["artifacts"][1:])
    evidence = _load(tmp_path, index)

    assert not _manifest_negative_variants_rejected(evidence)


def _manifest_negative_evidence(directory: Path, tamper: str | None = None) -> ProbeEvidence:
    source_block = "0x32871b4"
    block_hash = "0x" + "88" * 32
    zero_address = "0x" + "00" * 20
    asset = "0x" + "aa" * 20
    code_hash = "0x" + "bb" * 32
    manifest = {
        **MANIFEST,
        "source": {"blockNumber": source_block, "blockHash": block_hash, "chainId": 8453},
        "local": {"forkBlock": source_block, "chainId": 8453},
        "contracts": {"usdc": {"address": asset, "proxyCodeHash": code_hash}},
        "x402": {"asset": asset, "scheme": "exact"},
    }
    index = _captured_index(directory, manifest=manifest)
    index["scenarioId"] = "BEF-SC-001"
    index["environment"]["generation"]["generationId"] = "generation-primary"
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    local_block = source_block
    variants = {
        "wrong_block": (
            {"blockNumber": "0x32871b5", "blockHash": "0x" + "99" * 32},
            "source_block_mismatch",
        ),
        "wrong_chain": ({"chainId": 1}, "source_chain_mismatch"),
        "missing_code": ({"contractAddress": zero_address, "codeHash": code_hash}, "required_code_missing"),
        "per_trial_latest": ({"requestedBlock": "latest"}, "latest_block_disallowed"),
    }
    for variant, (candidate, reason) in variants.items():
        source_observations = {
            "chainId": {"method": "eth_chainId", "params": [], "result": "0x2105"},
            "block": {
                "method": "eth_getBlockByNumber",
                "params": [source_block, False],
                "result": {"number": source_block, "hash": block_hash},
            },
        }
        local_observations = {
            "chainId": {"method": "eth_chainId", "params": [], "result": "0x2105"},
            "block": {
                "method": "eth_getBlockByNumber",
                "params": [local_block, False],
                "result": {"number": local_block, "hash": block_hash},
            },
        }
        if variant == "missing_code":
            source_observations["code"] = {
                "method": "eth_getCode", "params": [zero_address, source_block], "result": "0x"
            }
        response_body = {
            "boundary": "private-admin-prerequisite-validation",
            "envId": "bef-a",
            "variantId": variant,
            "manifestSha256": manifest_digest,
            "applicationSourceSha256": index["applicationSourceSha256"],
            "candidate": candidate,
            "accepted": False,
            "reasonCode": reason,
            "observations": {"source": source_observations, "local": local_observations},
        }
        if variant == "per_trial_latest":
            response_body.update({"requestedBlock": "latest", "forwarded": False})
        if tamper == f"reason:{variant}":
            response_body["reasonCode"] = "invalid_request"
        if tamper == "latest-forwarded" and variant == "per_trial_latest":
            response_body["forwarded"] = True
        if tamper == "latest-candidate" and variant == "per_trial_latest":
            response_body["candidate"] = {"requestedBlock": source_block}
        payload = {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "private-admin-http",
            "operationId": None,
            "variantId": variant,
            "request": {
                "method": "POST",
                "path": "/internal/admin/environments/bef-a/prerequisite-validations",
                "headers": {},
                "body": {"variantId": variant, "candidate": candidate},
            },
            "response": {"status": 200, "headers": {}, "body": response_body},
        }
        _add_artifact(index, directory, f"http/{variant}-validation.json", payload, "private-admin-http")

        for boundary, chain_result, block_number in (
            ("source-readonly-proxy", "0x2105", source_block),
            ("local-chain-readonly-proxy", "0x2105", local_block),
        ):
            for phase in ("before", "after"):
                for suffix, method, params, result, requested in (
                    ("chain", "eth_chainId", [], chain_result, None),
                    (
                        "block", "eth_getBlockByNumber", [block_number, False],
                        {"number": block_number, "hash": block_hash}, block_number,
                    ),
                ):
                    rpc_payload = {
                        "schemaVersion": "bef-rpc-observation/v1",
                        "boundary": boundary,
                        "endpointBoundary": boundary,
                        "operationId": None,
                        "variantId": variant,
                        "method": method,
                        "params": params,
                        "requestedBlock": requested,
                        "result": result,
                    }
                    _add_artifact(
                        index, directory,
                        f"rpc/{variant}-{phase}-{boundary}-{suffix}.json",
                        rpc_payload, boundary,
                    )
        if variant == "missing_code":
            rpc_payload = {
                "schemaVersion": "bef-rpc-observation/v1",
                "boundary": "source-readonly-proxy",
                "endpointBoundary": "source-readonly-proxy",
                "operationId": None,
                "variantId": variant,
                "method": "eth_getCode",
                "params": [zero_address, source_block],
                "requestedBlock": source_block,
                "result": "0x" if tamper != "missing-code" else "0x6000",
            }
            _add_artifact(index, directory, f"rpc/{variant}-zero-address-code.json", rpc_payload, "source-readonly-proxy")

    unsupported_requirements = {"scheme": "unsupported-scheme", "network": "eip155:8453", "asset": asset}
    if tamper == "unsupported-actual-input":
        unsupported_requirements["scheme"] = "exact"
    unsupported = {
        "schemaVersion": "bef-http-observation/v1",
        "boundary": "facilitator-http",
        "operationId": None,
        "variantId": "unsupported_asset_scheme",
        "request": {
            "method": "POST",
            "path": "/verify",
            "headers": {"x-bef-variant-id": "unsupported_asset_scheme"},
            "body": {
                "paymentPayload": {"x402Version": 2, "payload": {"signature": "[REDACTED]"}},
                "paymentRequirements": unsupported_requirements,
            },
        },
        "response": {
            "status": 400,
            "headers": {},
            "body": {"error": "unsupported_payment_requirements", "reasonCode": "unsupported_asset_scheme"},
        },
    }
    _add_artifact(index, directory, "http/unsupported-asset-verify.json", unsupported, "facilitator-http")
    for boundary, chain_result, block_number in (
        ("source-readonly-proxy", "0x2105", source_block),
        ("local-chain-readonly-proxy", "0x2105", local_block),
    ):
        for phase in ("before", "after"):
            for suffix, method, params, result, requested in (
                ("chain", "eth_chainId", [], chain_result, None),
                ("block", "eth_getBlockByNumber", [block_number, False], {"number": block_number, "hash": block_hash}, block_number),
            ):
                rpc_payload = {
                    "schemaVersion": "bef-rpc-observation/v1",
                    "boundary": boundary,
                    "endpointBoundary": boundary,
                    "operationId": None,
                    "variantId": "unsupported_asset_scheme",
                    "method": method,
                    "params": params,
                    "requestedBlock": requested,
                    "result": result,
                }
                _add_artifact(
                    index, directory,
                    f"rpc/unsupported_asset_scheme-{phase}-{boundary}-{suffix}.json",
                    rpc_payload, boundary,
                )

    query_names = (
        "generation-by-id", "operations-by-generation", "payments-by-operation",
        "deliveries-by-operation", "denials-by-generation", "x402-observations-by-operation",
    )
    for variant in (*variants.keys(), "unsupported_asset_scheme"):
        for phase in ("before", "after"):
            for query_name in query_names:
                rows: list[dict[str, Any]] = []
                if query_name == "generation-by-id":
                    rows = [{
                        "generation_id": index["environment"]["generation"]["generationId"],
                        "env_id": index["environment"]["envId"],
                        "status": "fenced",
                    }]
                    if tamper == f"generation-missing:{variant}":
                        rows = []
                if tamper == f"database-change:{variant}" and phase == "after" and query_name == "payments-by-operation":
                    rows = [{"payment_id": "unexpected-payment"}]
                db_payload = {
                    "schemaVersion": "bef-db-observation/v1",
                    "boundary": "readonly-database",
                    "operationId": None,
                    "variantId": variant,
                    "readOnly": True,
                    "databaseRole": "bef_observer",
                    "queryName": query_name,
                    "rows": rows,
                }
                _add_artifact(index, directory, f"db/{variant}-{phase}-{query_name}.json", db_payload, "readonly-database")
    privilege_payload = {
        "schemaVersion": "bef-db-observation/v1",
        "boundary": "readonly-database",
        "operationId": None,
        "variantId": None,
        "readOnly": True,
        "databaseRole": "bef_observer",
        "queryName": "observer-role-effective-privileges",
        "role": {
            "is_superuser": False, "can_create_db": False, "can_create_role": False,
            "can_replicate": False, "can_bypass_rls": False, "can_create_in_schema": False,
            "can_create_in_database": False,
        },
        "rows": [{
            "can_select": True, "can_insert": False, "can_update": False, "can_delete": False,
            "can_truncate": False, "can_references": False, "can_trigger": False,
        }],
    }
    _add_artifact(index, directory, "db/observer-role-privileges.json", privilege_payload, "readonly-database")
    return _load(directory, index, "BEF-SC-001")


def test_manifest_negative_predicate_recomputes_bound_prerequisite_evidence(tmp_path: Path) -> None:
    evidence = _manifest_negative_evidence(tmp_path)

    assert _manifest_negative_variants_rejected(evidence)


@pytest.mark.parametrize(
    "tamper",
    [
        "reason:wrong_block",
        "reason:wrong_chain",
        "reason:missing_code",
        "reason:per_trial_latest",
        "latest-forwarded",
        "latest-candidate",
        "missing-code",
        "unsupported-actual-input",
        "database-change:wrong_chain",
        "generation-missing:wrong_chain",
    ],
)
def test_manifest_negative_predicate_rejects_unproven_or_effectful_variants(tmp_path: Path, tamper: str) -> None:
    evidence = _manifest_negative_evidence(tmp_path, tamper)

    assert not _manifest_negative_variants_rejected(evidence)


def test_x402_compatibility_pins_api_and_facilitator_node_not_probe_host(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "_payment_requirements_match_manifest",
        "_facilitator_verified_authorization",
        "_purchase_token_effects_match_receipt",
    ):
        monkeypatch.setattr(bef_adapter, name, lambda _evidence: True)

    asset = "0x" + "aa" * 20
    manifest = {
        "x402": {
            "sdk": "@x402",
            "scheme": "exact",
            "assetTransferMethod": "eip3009",
            "network": "eip155:8453",
            "version": "2.28.0",
            "asset": asset,
            "amount": "100000",
            "resourceId": "bef-resource-v1",
            "resourceSha256": "a" * 64,
        },
        "contracts": {"usdc": {"address": asset}},
        "local": {
            "nodeVersion": "24.22.1",
            "versions": {"x402Core": "2.28.0", "x402Evm": "2.28.0", "x402Fastify": "2.28.0"},
        },
    }
    evidence = SimpleNamespace(
        manifest=manifest,
        index={
            "runtimeVersions": {
                "x402Core": "2.28.0",
                "x402Evm": "2.28.0",
                "x402Fastify": "2.28.0",
                "apiNode": "v24.22.1",
                "facilitatorNode": "24.22.1",
                "probeNode": "24.14.0",
            }
        },
    )

    assert _x402_compatibility_matches(evidence)
    evidence.index["runtimeVersions"]["apiNode"] = "24.14.0"
    assert not _x402_compatibility_matches(evidence)
    evidence.index["runtimeVersions"]["apiNode"] = "24.22.1"
    evidence.index["runtimeVersions"]["facilitatorNode"] = "24.14.0"
    assert not _x402_compatibility_matches(evidence)


def test_purchase_effect_requires_exact_payee_and_before_after_token_deltas(tmp_path: Path) -> None:
    valid = _purchase_evidence(tmp_path)
    assert _purchase_token_effects_match_receipt(valid)
    assert _delivered_bytes_match_pinned_hash(valid)

    wrong_payee = _purchase_evidence(tmp_path / "wrong-payee", transfer_to="0x" + "44" * 20)
    assert not _purchase_token_effects_match_receipt(wrong_payee)

    one_unit_off = _purchase_evidence(tmp_path / "one-unit-off", observed_amount=100001)
    assert not _purchase_token_effects_match_receipt(one_unit_off)


def test_purchase_effect_uses_operation_bound_primary_db_rows_only(tmp_path: Path) -> None:
    variant_snapshots = _purchase_evidence(tmp_path / "variant-snapshots", variant_effect_snapshots=True)
    assert _purchase_token_effects_match_receipt(variant_snapshots)

    duplicate_payment = _purchase_evidence(
        tmp_path / "duplicate-payment", duplicate_primary_payment_rows=True,
    )
    assert not _purchase_token_effects_match_receipt(duplicate_payment)

    duplicate_delivery = _purchase_evidence(
        tmp_path / "duplicate-delivery", duplicate_primary_delivery_rows=True,
    )
    assert not _purchase_token_effects_match_receipt(duplicate_delivery)


@pytest.mark.parametrize(
    "extra_payment",
    [
        {"amount_units": "100001"},
        {"transaction_hash": "0x" + "44" * 32},
        {"asset_address": "0x" + "bb" * 20},
    ],
)
def test_purchase_effect_rejects_contradictory_primary_payment_rows(tmp_path: Path, extra_payment: dict[str, Any]) -> None:
    evidence = _purchase_evidence(
        tmp_path,
        extra_primary_payment_row=extra_payment,
    )

    assert not _purchase_token_effects_match_receipt(evidence)


def test_purchase_effect_rejects_contradictory_primary_delivery_hash(tmp_path: Path) -> None:
    evidence = _purchase_evidence(
        tmp_path,
        extra_primary_delivery_row={"content_sha256": "f" * 64},
    )

    assert not _purchase_token_effects_match_receipt(evidence)


def test_fixture_bytes_without_a_paid_http_delivery_do_not_prove_success(tmp_path: Path) -> None:
    raw = b'{"resource":"pinned"}'
    digest = hashlib.sha256(raw).hexdigest()
    index = _captured_index(tmp_path, manifest={
        **MANIFEST,
        "x402": {"resourceSha256": digest},
    })
    _add_artifact(index, tmp_path, "resource/fixture.json", {
        "schemaVersion": "bef-resource-observation/v1",
        "boundary": "resource-data",
        "operationId": None,
        "variantId": None,
        "contentBytesBase64": base64.b64encode(raw).decode("ascii"),
        "actualBytesSha256": digest,
    }, "resource-data")
    evidence = _load(tmp_path, index)

    assert not _delivered_bytes_match_pinned_hash(evidence)


@pytest.mark.parametrize("delivered_at", [{}, "", "not-a-timestamp", "2026-10-23T10:00:00"])
def test_delivery_timestamp_must_be_a_real_timezone_aware_timestamp(delivered_at: Any) -> None:
    assert not _delivery_row_is_durable({"delivered_at": delivered_at})
    assert not _delivery_row_is_durable({"status": "delivered", "delivered_at": delivered_at})


def test_delivery_timestamp_accepts_database_iso_datetime() -> None:
    assert _delivery_row_is_durable({"delivered_at": "2026-10-23T10:00:00Z"})


def test_wrong_token_success_response_cannot_be_counted_as_negative_denial(tmp_path: Path) -> None:
    valid_negatives = _negative_purchase_evidence(tmp_path / "valid")
    assert _x402_negative_variants_are_not_paid_success(valid_negatives)

    wrong_token_success = _negative_purchase_evidence(tmp_path / "wrong-token-success", wrong_token_status=200)
    assert not _x402_negative_variants_are_not_paid_success(wrong_token_success)


def test_wrong_token_402_requires_signed_wrong_asset_protocol_and_database_rejection(tmp_path: Path) -> None:
    valid = _negative_purchase_evidence(tmp_path / "signed-wrong-asset-rechallenged")
    assert _x402_negative_variants_are_not_paid_success(valid)

    missing_protocol_challenge = _negative_purchase_evidence(
        tmp_path / "missing-payment-required", wrong_token_rechallenge=False
    )
    assert not _x402_negative_variants_are_not_paid_success(missing_protocol_challenge)

    wrong_error = _negative_purchase_evidence(
        tmp_path / "wrong-protocol-error", wrong_token_error="Payment is required"
    )
    assert not _x402_negative_variants_are_not_paid_success(wrong_error)

    contradictory_header_error = _negative_purchase_evidence(
        tmp_path / "contradictory-header-error", wrong_token_header_error="Payment is required"
    )
    assert not _x402_negative_variants_are_not_paid_success(contradictory_header_error)

    pinned_asset_signed = _negative_purchase_evidence(
        tmp_path / "signed-pinned-asset", wrong_token_accepted_asset="0x" + "aa" * 20
    )
    assert not _x402_negative_variants_are_not_paid_success(pinned_asset_signed)

    mismatched_reoffer = _negative_purchase_evidence(
        tmp_path / "mismatched-reoffer", wrong_token_reoffer_asset="0x" + "cc" * 20
    )
    assert not _x402_negative_variants_are_not_paid_success(mismatched_reoffer)

    contradictory_header_reoffer = _negative_purchase_evidence(
        tmp_path / "contradictory-header-reoffer", wrong_token_header_reoffer_asset="0x" + "cc" * 20
    )
    assert not _x402_negative_variants_are_not_paid_success(contradictory_header_reoffer)

    missing_durable_denial = _negative_purchase_evidence(
        tmp_path / "missing-database-denial", wrong_token_database_rejection=False
    )
    assert not _x402_negative_variants_are_not_paid_success(missing_durable_denial)

    missing_signature_digest = _negative_purchase_evidence(
        tmp_path / "missing-signature-digest", wrong_token_signature_digest=None
    )
    assert not _x402_negative_variants_are_not_paid_success(missing_signature_digest)

    mismatched_signature_digest = _negative_purchase_evidence(
        tmp_path / "mismatched-signature-digest", wrong_token_source_header_digest="d" * 64
    )
    assert not _x402_negative_variants_are_not_paid_success(mismatched_signature_digest)


def test_negative_x402_variant_uses_its_own_readonly_generation_and_verification_row(tmp_path: Path) -> None:
    valid = _negative_purchase_evidence(tmp_path / "distinct-generations")
    assert _x402_negative_variants_are_not_paid_success(valid)

    generation_mismatch = _negative_purchase_evidence(
        tmp_path / "wrong-generation-payer",
        verify_generation_payer="0x" + "11" * 20,
    )
    assert not _x402_negative_variants_are_not_paid_success(generation_mismatch)

    observation_mismatch = _negative_purchase_evidence(
        tmp_path / "wrong-observation-payer",
        verify_observation_payer="0x" + "33" * 20,
    )
    assert not _x402_negative_variants_are_not_paid_success(observation_mismatch)


def test_primary_facilitator_verification_is_same_operation_readonly_db_evidence(tmp_path: Path) -> None:
    captured = _purchase_evidence(tmp_path / "actual-x402-row")
    assert _facilitator_verified_authorization(captured)
    assert _payer_is_linked_to_receipt_and_database(captured)

    # Real runtime capture labels its durable primary verification row as
    # "baseline" even though the indexed primary request has variantId=null.
    baseline_row = _purchase_evidence(tmp_path / "actual-primary-baseline-row", x402_row_variant="baseline")
    assert _facilitator_verified_authorization(baseline_row)

    # The alias is deliberately restricted to the primary row. A named
    # negative variant cannot be smuggled into primary verification evidence.
    mislabeled_negative = _purchase_evidence(
        tmp_path / "unexpected-primary-variant-row", x402_row_variant="wrong_token_representation"
    )
    assert not _facilitator_verified_authorization(mislabeled_negative)

    unrelated_http_only = _purchase_evidence(
        tmp_path / "unrelated-http-only",
        include_x402_observation=False,
        unrelated_facilitator_verify=True,
    )
    assert not _facilitator_verified_authorization(unrelated_http_only)

    wrong_requirements_payer = _purchase_evidence(
        tmp_path / "mismatched-x402-payer",
        x402_observation_payer="0x" + "44" * 20,
    )
    assert not _facilitator_verified_authorization(wrong_requirements_payer)

    wrong_challenge_requirements = _purchase_evidence(
        tmp_path / "mismatched-x402-payto",
        x402_observation_pay_to="0x" + "55" * 20,
    )
    assert not _facilitator_verified_authorization(wrong_challenge_requirements)

    wrong_database_payee = _purchase_evidence(
        tmp_path / "mismatched-database-payto",
        payment_facilitator_address="0x" + "66" * 20,
    )
    assert not _payer_is_linked_to_receipt_and_database(wrong_database_payee)
    assert not _purchase_token_effects_match_receipt(wrong_database_payee)


def test_offer_inspection_groups_distinct_token_holders_without_database_balance_rows(tmp_path: Path) -> None:
    asset = "0x" + "aa" * 20
    payer = "0x" + "11" * 20
    pay_to = "0x" + "22" * 20
    index = _captured_index(tmp_path, manifest={**MANIFEST, "contracts": {"usdc": {"address": asset}}})
    index["operations"] = [{"operationId": "offer-op"}]
    for role, account, before_path, after_path, before, after in (
        ("payer", payer, "sc004-payer-before-offer", "sc004-payer-after-offer", 1000000, 1000000),
        ("payto", pay_to, "sc004-payto-before-offer-read", "sc004-payto-after-unpaid-challenge", 17, 17),
    ):
        for label, balance in ((before_path, before), (after_path, after)):
            _add_artifact(index, tmp_path, f"rpc/{label}.json", {
                "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
                "operationId": None if role == "payer" and "before" in label else "offer-op", "variantId": None, "method": "eth_call",
                "params": [{"to": asset, "data": "0x70a08231" + account[2:].rjust(64, "0")}, "latest"], "result": "0x" + format(balance, "064x"),
            }, "local-chain-readonly-proxy")
    evidence = _load(tmp_path, index)
    assert _inspection_has_no_token_delta(evidence)

    changed = _captured_index(tmp_path, manifest={**MANIFEST, "contracts": {"usdc": {"address": asset}}})
    changed["operations"] = [{"operationId": "offer-op"}]
    for role, account, before_path, after_path, before, after in (
        ("payer", payer, "sc004-payer-before-offer", "sc004-payer-after-offer", 1000000, 1000000),
        ("payto", pay_to, "sc004-payto-before-offer-read", "sc004-payto-after-unpaid-challenge", 17, 18),
    ):
        for label, balance in ((before_path, before), (after_path, after)):
            _add_artifact(changed, tmp_path, f"rpc/{label}.json", {
                "schemaVersion": "bef-rpc-observation/v1", "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
                "operationId": None if role == "payer" and "before" in label else "offer-op", "variantId": None, "method": "eth_call",
                "params": [{"to": asset, "data": "0x70a08231" + account[2:].rjust(64, "0")}, "latest"], "result": "0x" + format(balance, "064x"),
            }, "local-chain-readonly-proxy")
    changed_evidence = _load(tmp_path, changed)
    assert not _inspection_has_no_token_delta(changed_evidence)


def test_source_read_must_use_allowlisted_method_and_pinned_block(tmp_path: Path) -> None:
    manifest = {
        **MANIFEST,
        "source": {
            "allowedMethods": ["eth_getCode"],
            "blockNumber": "0x32871b6",
            "maxRequestBytes": 4096,
        },
    }
    index = _captured_index(tmp_path, manifest=manifest)
    source_rpc = _bound_source_rpc_observation(
        index,
        operation_id="source-op",
        method="eth_getCode",
        params=["0x" + "22" * 20, "0x32871b6"],
        result="0x6000",
    )
    _add_artifact(index, tmp_path, "rpc/code.json", source_rpc, "source-readonly-proxy")
    index["operations"] = [{"operationId": "source-op"}]
    evidence = _load(tmp_path, index)

    assert _source_reads_are_allowlisted(evidence)


def test_source_read_at_latest_is_not_pinned_evidence(tmp_path: Path) -> None:
    manifest = {
        **MANIFEST,
        "source": {
            "allowedMethods": ["eth_getCode"],
            "blockNumber": "0x32871b6",
            "maxRequestBytes": 4096,
        },
    }
    index = _captured_index(tmp_path, manifest=manifest)
    source_rpc = _bound_source_rpc_observation(
        index,
        operation_id="source-op",
        method="eth_getCode",
        params=["0x" + "22" * 20, "latest"],
        result="0x6000",
    )
    _add_artifact(index, tmp_path, "rpc/code.json", source_rpc, "source-readonly-proxy")
    index["operations"] = [{"operationId": "source-op"}]
    evidence = _load(tmp_path, index)

    assert not _source_reads_are_allowlisted(evidence)


def test_source_read_without_bound_raw_response_is_rejected(tmp_path: Path) -> None:
    manifest = {
        **MANIFEST,
        "source": {
            "allowedMethods": ["eth_getCode"],
            "blockNumber": "0x32871b6",
            "maxRequestBytes": 4096,
        },
    }
    index = _captured_index(tmp_path, manifest=manifest)
    source_rpc = _bound_source_rpc_observation(
        index,
        operation_id="source-op",
        method="eth_getCode",
        params=["0x" + "22" * 20, "0x32871b6"],
        result="0x6000",
    )
    source_rpc.pop("responseBodyBase64")
    _add_artifact(index, tmp_path, "rpc/code.json", source_rpc, "source-readonly-proxy")
    index["operations"] = [{"operationId": "source-op"}]
    evidence = _load(tmp_path, index)

    assert not _source_reads_are_allowlisted(evidence)


def _offline_replay_evidence(
    tmp_path: Path,
    *,
    after_nonce: str = "0x5",
    change_database_after: bool = False,
    gate_status: str = "not_established_by_replay",
) -> tuple[ProbeEvidence, Path]:
    repository = tmp_path / "repository"
    evidence_dir = tmp_path / "sc012-evidence"
    payer = "0x" + "11" * 20
    token = "0x" + "22" * 20
    evidence_manifest = {
        **MANIFEST,
        "x402": {
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": token,
            "amount": "100000",
        },
        "contracts": {"usdc": {"address": token}},
    }
    approved_paths = {
        "proposal": "openspec/changes/benchmark-environment-feasibility/bdd-harness-proposal.json",
        "harnessContract": "tests/bdd/changes/benchmark-environment-feasibility/harness-contracts.json",
        "normativeSpec": "openspec/changes/benchmark-environment-feasibility/specs/source-readonly/spec.md",
        "predicateSource": "tests/bdd/adapters/benchmark_environment_feasibility.py",
    }
    approved_sources: dict[str, dict[str, str]] = {}
    for name, path in approved_paths.items():
        source = f"source fixture: {name}\n".encode("utf-8")
        source_path = repository / path
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(source)
        approved_sources[name] = {"path": path, "sha256": hashlib.sha256(source).hexdigest()}
    replayer_source = b"offline fixture replayer\n"
    replayer_path = repository / "tools" / "replay_bef_evidence.py"
    replayer_path.parent.mkdir(parents=True, exist_ok=True)
    replayer_path.write_bytes(replayer_source)

    index = _captured_index(evidence_dir, manifest=evidence_manifest)
    index["scenarioId"] = "BEF-SC-012"
    index["operations"] = [{"operationId": "sc012-replay-operation"}]
    index["artifacts"] = [{
        "path": "manifest.json",
        "sha256": index["manifest"]["sha256"],
        "contentType": "application/json",
        "boundary": "runtime-manifest",
    }]
    endpoint_ref = {"scheme": "http", "host": "127.0.0.1", "port": 8545}
    index_sha_by_scenario: dict[str, str] = {}
    references_by_scenario: dict[str, dict[str, Any]] = {}
    operation_ids_by_scenario: dict[str, list[str]] = {}
    generation_by_operation_by_scenario: dict[str, dict[str, str]] = {}
    replay_reports_by_scenario: dict[str, dict[str, Any]] = {}

    for scenario in ("BEF-SC-004", "BEF-SC-005"):
        scenario_suffix = scenario.lower()
        original_dir = repository / "artifacts" / "benchmark-environment-feasibility" / "probes" / f"{scenario_suffix}-fixture"
        manifest_bytes = _write_json(original_dir / "manifest.json", evidence_manifest)
        original_artifacts = [{
            "path": "manifest.json",
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "contentType": "application/json",
            "boundary": "runtime-manifest",
        }]
        operation_numbers = [100, 101] if scenario == "BEF-SC-004" else [200, 201, 202, 203]
        operation_ids = [f"00000000-0000-4000-8000-{number:012x}" for number in operation_numbers]
        generation_by_operation = {
            operation_id: f"00000000-0000-4000-8000-{(number + 1000):012x}"
            for operation_id, number in zip(operation_ids, operation_numbers, strict=True)
        }
        if scenario == "BEF-SC-004":
            generation_by_operation[operation_ids[0]] = generation_by_operation[operation_ids[1]]
        operation_ids_by_scenario[scenario] = operation_ids
        generation_by_operation_by_scenario[scenario] = generation_by_operation
        primary_generation_id = generation_by_operation[operation_ids[-1]]
        pay_to = "0x" + "33" * 20
        declaration = {
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": token,
                "amount": "100000",
                "payTo": pay_to,
            }],
        }
        for number, original_operation_id in enumerate(operation_ids):
            raw_http = {
                "schemaVersion": "bef-http-observation/v1",
                "boundary": "actual-tool-http",
                "operationId": original_operation_id,
                "variantId": None,
                "request": {"method": "POST", "path": "/tools/bef-a/purchase", "headers": {}, "body": {}},
                "response": {
                    "status": 402,
                    "headers": {
                        "payment-required": base64.b64encode(json.dumps(declaration, separators=(",", ":")).encode()).decode("ascii"),
                        "x-bef-operation-id": original_operation_id,
                    },
                    "body": {},
                },
            }
            http_path = f"http/challenge-{number}.json"
            http_bytes = _write_json(original_dir / http_path, raw_http)
            original_artifacts.append({
                "path": http_path,
                "sha256": hashlib.sha256(http_bytes).hexdigest(),
                "contentType": "application/json",
                "boundary": "actual-tool-http",
            })
        original_index = {
            "schemaVersion": "bef-runtime-probe/v1",
            "scenarioId": scenario,
            "status": "captured",
            "manifest": {"path": "manifest.json", "sha256": hashlib.sha256(manifest_bytes).hexdigest()},
            "environment": {"envId": "bef-a", "generation": {
            "generationId": primary_generation_id,
                "participantId": f"{scenario_suffix}-participant",
                "payerAddress": payer,
            }},
            "operations": [{"operationId": item, "kind": "purchase", "observedStatus": "recorded"} for item in operation_ids],
            "observations": [],
            "artifacts": original_artifacts,
            "applicationSourceSha256": "a" * 64,
            "probeSourceSha256": "b" * 64,
            "runtimeVersions": {"apiNode": "24.22.1"},
            "sourceBlock": {"number": "0x32871b6", "hash": "0x" + "88" * 32},
        }
        index_bytes = _write_json(original_dir / "probe.json", original_index)
        index_sha = hashlib.sha256(index_bytes).hexdigest()
        index_sha_by_scenario[scenario] = index_sha
        relative_root = original_dir.relative_to(repository).as_posix()
        original_reference = {
            "scenarioId": scenario,
            "status": "captured",
            "evidenceRoot": {"kind": "repository_relative", "path": relative_root},
            "externalResolutionRequired": False,
            "probeIndexPath": "probe.json",
            "probeIndexSha256": index_sha,
            "manifestPath": "manifest.json",
            "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "applicationSourceSha256": original_index["applicationSourceSha256"],
            "probeSourceSha256": original_index["probeSourceSha256"],
            "sourceBlock": original_index["sourceBlock"],
            "environmentId": "bef-a",
            "generationId": original_index["environment"]["generation"]["generationId"],
            "operationIds": operation_ids,
            "artifacts": [{
                "path": item["path"],
                "sha256": item["sha256"],
                "boundary": item["boundary"],
            } for item in original_artifacts],
        }
        replayed_reference = {
            "provenance": "replayed-original",
            "scenarioId": scenario,
            "evidenceRoot": original_reference["evidenceRoot"],
            "probeIndexPath": "probe.json",
            "probeIndexSha256": index_sha,
            "environmentId": original_reference["environmentId"],
            "generationId": primary_generation_id,
            "operationIds": operation_ids,
        }
        references_by_scenario[scenario] = replayed_reference
        replay_report = {
            "schemaVersion": "bef-evidence-replay-observation/v1",
            "boundary": "recorded-evidence-replay",
            "operationId": None,
            "variantId": None,
            "evaluatedScenarioId": scenario,
            "replayStatus": "matched",
            "gateStatus": gate_status,
            "original": original_reference,
            "replay": {
                "contractChange": "benchmark-environment-feasibility",
                "contractScenarioId": scenario,
                "approvedSources": approved_sources,
                "replayerSourcePath": "tools/replay_bef_evidence.py",
                "replayerSourceSha256": hashlib.sha256(replayer_source).hexdigest(),
                "requiredChecks": ["captured_http", "database_link"],
                "checkResults": [
                    {"name": "captured_http", "passed": True},
                    {"name": "database_link", "passed": True},
                ],
                "checksMatchContract": True,
                "missingChecks": [],
                "predicateCompleted": True,
                "predicateErrorType": None,
                "execution": {
                    "mode": "offline_recorded_observations",
                    "httpRequests": 0,
                    "rpcCalls": 0,
                    "databaseQueries": 0,
                    "broadcasts": 0,
                    "newTrials": 0,
                },
            },
            "stateComparison": {
                "databaseRowsEqual": True,
                "databaseOperationIdsMatch": True,
                "databaseGenerationBindingsEqual": True,
                "localChainReadsEqual": True,
                "environmentId": "bef-a",
                "generationIds": sorted(set(generation_by_operation.values())),
                "operationIds": operation_ids,
            },
            "replayExecutionBoundary": "offline-file-only-no-http-rpc-db-or-broadcast-by-replayer",
        }
        replay_reports_by_scenario[scenario] = replay_report
        replayed_reference = references_by_scenario[scenario]
        operation_generations = generation_by_operation_by_scenario[scenario]
        generation_operations: dict[str, list[str]] = {}
        for original_operation_id, original_generation_id in operation_generations.items():
            generation_operations.setdefault(original_generation_id, []).append(original_operation_id)
        for phase in ("before", "after"):
            binding_rows = [
                {"operation_id": original_operation_id, "env_id": "bef-a", "generation_id": original_generation_id}
                for original_operation_id, original_generation_id in operation_generations.items()
            ]
            _add_artifact(index, evidence_dir, f"db/{scenario_suffix}-{phase}-operation-generation-bindings.json", {
                "schemaVersion": "bef-db-observation/v1",
                "boundary": "readonly-database",
                "operationId": None,
                "variantId": None,
                "readOnly": True,
                "databaseRole": "bef_readonly_observer",
                "queryName": "replayed-original-operation-generation-bindings",
                "observationScope": "original-operation-bindings",
                "observationOperationId": None,
                "replayPhase": phase,
                "replayedOriginalCapture": replayed_reference,
                "envId": "bef-a",
                "operationIds": operation_ids,
                "rows": binding_rows,
            }, "readonly-database")
            for snapshot_generation_id, generation_operation_ids in generation_operations.items():
                generation_rows = [{
                    "env_id": "bef-a",
                    "generation_id": snapshot_generation_id,
                    "payer_address": payer,
                    "status": "active",
                }]
                operation_rows = [{
                    "operation_id": original_operation_id,
                    "env_id": "bef-a",
                    "generation_id": snapshot_generation_id,
                    "status": "settled" if scenario == "BEF-SC-005" and original_operation_id == operation_ids[-1] else "recorded",
                } for original_operation_id in generation_operation_ids]
                if change_database_after and phase == "after" and scenario == "BEF-SC-005" and operation_rows:
                    operation_rows[-1]["status"] = "settlement_unknown"
                payments = []
                deliveries = []
                if scenario == "BEF-SC-005" and operation_ids[-2] in generation_operation_ids:
                    payments = [{
                        "operation_id": operation_ids[-2], "env_id": "bef-a", "generation_id": snapshot_generation_id,
                        "payer_address": payer, "facilitator_address": "0x" + "33" * 20,
                    }]
                if scenario == "BEF-SC-005" and operation_ids[-1] in generation_operation_ids:
                    payments = payments + [{
                        "operation_id": operation_ids[-1], "env_id": "bef-a", "generation_id": snapshot_generation_id,
                        "payer_address": payer, "facilitator_address": "0x" + "33" * 20,
                    }]
                    deliveries = [{"operation_id": operation_ids[-1], "resource_id": "bef-resource-v1"}]
                query_rows = {
                    "generation-by-id": generation_rows,
                    "operations-by-generation": operation_rows,
                    "payments-by-operation": payments,
                    "deliveries-by-operation": deliveries,
                    "denials-by-generation": [],
                    "x402-observations-by-operation": [],
                }
                for query_name, rows in query_rows.items():
                    _add_artifact(index, evidence_dir, f"db/{scenario_suffix}-{snapshot_generation_id[-4:]}-{phase}-{query_name}.json", {
                        "schemaVersion": "bef-db-observation/v1",
                        "boundary": "readonly-database",
                        "operationId": None,
                        "variantId": None,
                        "readOnly": True,
                        "databaseRole": "bef_readonly_observer",
                        "queryName": query_name,
                        "observationScope": "generation",
                        "observationOperationId": None,
                        "generationOperationIds": sorted(generation_operation_ids),
                        "replayPhase": phase,
                        "replayedOriginalCapture": replayed_reference,
                        "envId": "bef-a",
                        "generationId": snapshot_generation_id,
                        "rows": rows,
                    }, "readonly-database")

    health = {"status": "ok", "boundary": "local-chain-readonly-proxy", "envId": "bef-a", "manifestSha256": index["manifest"]["sha256"]}
    health_path = "rpc/endpoint-health-bef-a.json"
    binding_path = "rpc/endpoint-binding-bef-a.json"
    health_hash = _add_artifact(index, evidence_dir, health_path, health, "local-chain-readonly-proxy")
    binding = {
        "schemaVersion": "bef-rpc-endpoint-binding/v1",
        "boundary": "local-chain-readonly-proxy",
        "operationId": None,
        "variantId": None,
        "environmentId": "bef-a",
        "endpointRef": endpoint_ref,
        "healthArtifactPath": health_path,
        "healthArtifactSha256": health_hash,
        "health": health,
    }
    _add_artifact(index, evidence_dir, binding_path, binding, "local-chain-readonly-proxy")
    address_call = "0x70a08231" + payer[2:].rjust(64, "0")
    methods = (
        ("eth_getBalance", [payer, "latest"], "0x100"),
        ("eth_getTransactionCount", [payer, "latest"], "0x5"),
        ("eth_call", [{"to": token, "data": address_call}, "latest"], "0x64"),
    )
    for scenario, index_sha in index_sha_by_scenario.items():
        generation_operations: dict[str, list[str]] = {}
        for original_operation_id, original_generation_id in generation_by_operation_by_scenario[scenario].items():
            generation_operations.setdefault(original_generation_id, []).append(original_operation_id)
        replayed_reference = references_by_scenario[scenario]
        for generation_id, generation_operation_ids in generation_operations.items():
            addresses = [payer, pay_to]
            for phase in ("before", "after"):
                for address in addresses:
                    address_call = "0x70a08231" + address[2:].rjust(64, "0")
                    generation_methods = (
                        ("eth_getBalance", [address, "latest"], "0x100"),
                        ("eth_getTransactionCount", [address, "latest"], "0x5"),
                        ("eth_call", [{"to": token, "data": address_call}, "latest"], "0x64"),
                    )
                    for method, params, value in generation_methods:
                        result = after_nonce if phase == "after" and method == "eth_getTransactionCount" else value
                        request_body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
                        response_body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}, separators=(",", ":")).encode()
                        _add_artifact(index, evidence_dir, f"rpc/{scenario.lower()}-{generation_id[-4:]}-{phase}-{method}-{address[2:8]}.json", {
                            "schemaVersion": "bef-rpc-observation/v1",
                            "boundary": "local-chain-readonly-proxy",
                            "endpointBoundary": "local-chain-readonly-proxy",
                            "operationId": None,
                            "variantId": None,
                            "phase": phase,
                            "replayOfProbeIndexSha256": index_sha,
                            "envId": "bef-a",
                            "environmentId": "bef-a",
                            "generationId": generation_id,
                            "operationIds": sorted(generation_operation_ids),
                            "replayedOriginalCapture": replayed_reference,
                            "forwarded": True,
                            "requestedBlock": "latest",
                            "method": method,
                            "params": params,
                            "endpointIdentityArtifact": binding_path,
                            "endpointRef": endpoint_ref,
                            "requestBody": request_body,
                            "responseBodyBase64": base64.b64encode(response_body).decode("ascii"),
                            "responseBodySha256": hashlib.sha256(response_body).hexdigest(),
                            "responseStatus": 200,
                            "responseCorrelated": True,
                            "responseBytes": len(response_body),
                            "result": result,
                        }, "local-chain-readonly-proxy")

    for scenario, replay_report in replay_reports_by_scenario.items():
        scenario_suffix = scenario.lower()
        replayed_reference = references_by_scenario[scenario]
        index_sha = index_sha_by_scenario[scenario]
        local_inventory = []
        generation_operations: dict[str, list[str]] = {}
        for operation_id, generation_id in generation_by_operation_by_scenario[scenario].items():
            generation_operations.setdefault(generation_id, []).append(operation_id)
        for generation_id, operation_ids in sorted(generation_operations.items()):
            local_inventory.append({
                "generationId": generation_id,
                "operationIds": sorted(operation_ids),
                "addresses": sorted([payer.lower(), pay_to.lower()]),
            })
        replay_report["stateComparison"]["localRpcExpectedAccounts"] = local_inventory
        identity = {
            "schemaVersion": "bef-evidence-replay/v1",
            "evaluatedScenarioId": replay_report["evaluatedScenarioId"],
            "replayStatus": replay_report["replayStatus"],
            "gateStatus": replay_report["gateStatus"],
            "original": replay_report["original"],
            "replay": replay_report["replay"],
        }
        identity_bytes = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        identity_sha = hashlib.sha256(identity_bytes).hexdigest()
        events = []
        for ordinal, kind, phase, boundary in (
            (1, "before_database_snapshot", "before", "readonly-database"),
            (2, "before_local_rpc_snapshot", "before", None),
            (4, "after_database_snapshot", "after", "readonly-database"),
            (5, "after_local_rpc_snapshot", "after", None),
        ):
            refs = []
            for entry in index["artifacts"]:
                if entry["boundary"] not in ({boundary} if boundary else {"local-chain-readonly-proxy", "replay-local-state"}):
                    continue
                payload = json.loads((evidence_dir / entry["path"]).read_text())
                if entry["boundary"] == "readonly-database":
                    matches = payload.get("replayedOriginalCapture") == replayed_reference and payload.get("replayPhase") == phase
                    matches = matches and payload.get("observationScope") in {"generation", "original-operation-bindings"}
                else:
                    matches = payload.get("replayOfProbeIndexSha256") == index_sha and payload.get("phase") == phase
                if matches:
                    refs.append({"path": entry["path"], "sha256": entry["sha256"], "boundary": entry["boundary"]})
            events.append({"ordinal": ordinal, "kind": kind, "artifacts": refs})
        events.insert(2, {
            "ordinal": 3,
            "kind": "offline_evidence_replay",
            "scenarioId": scenario,
            "originalProbeIndexSha256": index_sha,
            "replayIdentitySha256": identity_sha,
        })
        replay_report["replayBracket"] = {
            "sequence": [event["kind"] for event in events],
            "preflightIdentitySha256": identity_sha,
            "replayIdentitySha256": identity_sha,
            "events": events,
        }
        _add_artifact(index, evidence_dir, f"replay/{scenario_suffix}.json", replay_report, "recorded-evidence-replay")

    index["replayedOriginalCaptures"] = [references_by_scenario[scenario] for scenario in ("BEF-SC-004", "BEF-SC-005")]

    return _load(evidence_dir, index, scenario_id="BEF-SC-012"), repository


def test_replay_validates_offline_file_report_and_independent_unchanged_db_rpc_state(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path)

    assert _replay_is_read_only(evidence, repository)


def test_replay_fails_when_independent_chain_state_changes(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path, after_nonce="0x6")

    assert not _replay_is_read_only(evidence, repository)


def test_replay_fails_when_independent_database_state_changes(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path, change_database_after=True)

    assert not _replay_is_read_only(evidence, repository)


def test_replay_rejects_changed_original_operation_generation_binding(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path)
    binding = next(item for item in evidence.database_artifacts()
                   if item.payload.get("queryName") == "replayed-original-operation-generation-bindings"
                   and item.payload.get("replayPhase") == "after")
    binding.payload["rows"][0]["generation_id"] = "00000000-0000-4000-8000-00000000ffff"

    assert not _replay_is_read_only(evidence, repository)


def test_replay_rejects_tampered_original_capture_index_reference(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path)
    evidence.index["replayedOriginalCaptures"][0]["probeIndexSha256"] = "c" * 64

    assert not _replay_is_read_only(evidence, repository)


def test_replay_rejects_missing_rpc_inventory_for_an_entire_generation(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path)
    report_artifact = next(item for item in evidence.boundary_artifacts("recorded-evidence-replay")
                           if item.payload.get("original", {}).get("scenarioId") == "BEF-SC-005")
    original = report_artifact.payload["original"]
    capture = _verified_original_capture(repository, original, "BEF-SC-005")
    assert capture is not None
    local_rpc = [item for item in evidence.boundary_artifacts("local-chain-readonly-proxy")
                 if item.payload.get("replayOfProbeIndexSha256") == capture["indexSha256"]]
    generation_ids = sorted({item.payload["generationId"] for item in local_rpc})
    assert len(generation_ids) > 1
    missing_generation = generation_ids[0]
    evidence_missing_generation = replace(evidence, artifacts=tuple(
        item for item in evidence.artifacts
        if not (item.boundary == "local-chain-readonly-proxy"
                and item.payload.get("replayOfProbeIndexSha256") == capture["indexSha256"]
                and item.payload.get("generationId") == missing_generation)
    ))

    assert not _replay_local_rpc_states_match(evidence_missing_generation, original, capture)


def test_replay_rejects_offline_replay_outside_snapshot_bracket(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path)
    report = next(item.payload for item in evidence.boundary_artifacts("recorded-evidence-replay")
                  if item.payload.get("original", {}).get("scenarioId") == "BEF-SC-005")
    events = report["replayBracket"]["events"]
    events[0], events[2] = events[2], events[0]

    assert not _replay_is_read_only(evidence, repository)


def test_replay_does_not_establish_scenario_gate_pass(tmp_path: Path) -> None:
    evidence, repository = _offline_replay_evidence(tmp_path, gate_status="passed")

    assert not _replay_is_read_only(evidence, repository)


def _sc012_fault_evidence(
    directory: Path,
    *,
    repository_root: Path | None = None,
    fault_overrides: dict[str, dict[str, Any]] | None = None,
    include_secret_fault: bool = True,
    include_missing_hash_fault: bool = True,
    duplicate_secret_fault: bool = False,
) -> ProbeEvidence:
    index = _captured_index(directory)
    index["scenarioId"] = "BEF-SC-012"
    repository = repository_root or (directory / "repository")
    capture_relative = "artifacts/benchmark-environment-feasibility/probes/bef-sc-004-fixture"
    original_root = repository / capture_relative
    original_root.mkdir(parents=True, exist_ok=True)
    original_index = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": "BEF-SC-004",
        "status": "captured",
    }
    original_index_bytes = json.dumps(original_index, separators=(",", ":"), sort_keys=True).encode("utf-8")
    (original_root / "probe.json").write_bytes(original_index_bytes)
    original_index_digest = hashlib.sha256(original_index_bytes).hexdigest()
    reference = {
        "provenance": "replayed-original",
        "scenarioId": "BEF-SC-004",
        "evidenceRoot": {"kind": "repository_relative", "path": capture_relative},
        "probeIndexPath": "probe.json",
        "probeIndexSha256": original_index_digest,
    }
    index["replayedOriginalCaptures"] = [reference]
    validator_path = repository / "tools" / "replay_bef_evidence.py"
    validator_path.parent.mkdir(parents=True, exist_ok=True)
    validator_path.write_bytes((Path.cwd() / "tools" / "replay_bef_evidence.py").read_bytes())
    validator_digest = hashlib.sha256(validator_path.read_bytes()).hexdigest()
    original_tree_digest = bef_adapter._sc012_evidence_tree_digest(original_root)
    assert original_tree_digest is not None
    expected_faults = {
        "secret_in_artifact": {
            "schemaVersion": "bef-source-validation-fault-observation/v1",
            "boundary": "recorded-evidence-validation",
            "operationId": None,
            "variantId": "secret_in_artifact",
            "inputScenario": "BEF-SC-004",
            "originalEvidenceRootPath": capture_relative,
            "originalProbeIndexSha256": original_index_digest,
            "originalEvidenceTreeSha256Before": original_tree_digest,
            "originalEvidenceTreeSha256After": original_tree_digest,
            "inputFault": "synthetic_secret_key_in_artifact",
            "validator": "tools/replay_bef_evidence.py -> ProbeEvidence.load",
            "validatorSourcePath": "tools/replay_bef_evidence.py",
            "validatorSourceSha256": validator_digest,
            "replayerExitCode": 1,
            "replayerTimedOut": False,
            "replayerProcessClosed": True,
            "rejected": True,
            "reportCreated": False,
            "originalEvidenceUnchanged": True,
            "syntheticCopyRemoved": True,
            "recordingBoundary": "hashed_probe_evidence_artifact",
        },
        "missing_hash": {
            "schemaVersion": "bef-source-validation-fault-observation/v1",
            "boundary": "recorded-evidence-validation",
            "operationId": None,
            "variantId": "missing_hash",
            "inputScenario": "BEF-SC-004",
            "originalEvidenceRootPath": capture_relative,
            "originalProbeIndexSha256": original_index_digest,
            "originalEvidenceTreeSha256Before": original_tree_digest,
            "originalEvidenceTreeSha256After": original_tree_digest,
            "inputFault": "artifact_sha256_field_removed",
            "validator": "tools/replay_bef_evidence.py -> ProbeEvidence.load",
            "validatorSourcePath": "tools/replay_bef_evidence.py",
            "validatorSourceSha256": validator_digest,
            "replayerExitCode": 1,
            "replayerTimedOut": False,
            "replayerProcessClosed": True,
            "rejected": True,
            "reportCreated": False,
            "originalEvidenceUnchanged": True,
            "syntheticCopyRemoved": True,
            "recordingBoundary": "hashed_probe_evidence_artifact",
        },
    }
    for variant, path in (
        ("secret_in_artifact", "replay/secret_in_artifact-validator-rejection.json"),
        ("missing_hash", "replay/missing_hash-validator-rejection.json"),
    ):
        if variant == "secret_in_artifact" and not include_secret_fault:
            continue
        if variant == "missing_hash" and not include_missing_hash_fault:
            continue
        payload = {**expected_faults[variant], **(fault_overrides or {}).get(variant, {})}
        _add_artifact(index, directory, path, payload, "recorded-evidence-validation")
        if variant == "secret_in_artifact" and duplicate_secret_fault:
            _add_artifact(
                index,
                directory,
                "replay/duplicate-secret-fault.json",
                payload,
                "recorded-evidence-validation",
            )
    for variant in ("wrong_source_identity", "send_raw_transaction", "admin_method", "sign_method"):
        _add_artifact(index, directory, f"source-rpc/{variant}.json", {
            "schemaVersion": "bef-rpc-observation/v1",
            "boundary": "source-readonly-proxy",
            "operationId": None,
            "variantId": variant,
        }, "source-readonly-proxy")
    return _load(directory, index, scenario_id="BEF-SC-012")


def test_sc012_synthetic_validation_faults_require_both_exact_hashed_rejections(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    evidence = _sc012_fault_evidence(tmp_path, repository_root=repository)

    assert bef_adapter._synthetic_validation_faults_are_rejected(evidence, repository)


@pytest.mark.parametrize(
    ("fault_overrides", "include_secret_fault", "include_missing_hash_fault", "duplicate_secret_fault"),
    [
        ({}, False, True, False),
        ({}, True, False, False),
        ({"secret_in_artifact": {"rejected": False}}, True, True, False),
        ({"missing_hash": {"inputFault": "hash_removed_but_not_indexed"}}, True, True, False),
        ({}, True, True, True),
    ],
)
def test_sc012_synthetic_validation_fault_predicate_fails_closed(
    tmp_path: Path,
    fault_overrides: dict[str, dict[str, Any]],
    include_secret_fault: bool,
    include_missing_hash_fault: bool,
    duplicate_secret_fault: bool,
) -> None:
    repository = tmp_path / "repository"
    evidence = _sc012_fault_evidence(
        tmp_path,
        repository_root=repository,
        fault_overrides=fault_overrides,
        include_secret_fault=include_secret_fault,
        include_missing_hash_fault=include_missing_hash_fault,
        duplicate_secret_fault=duplicate_secret_fault,
    )

    assert not bef_adapter._synthetic_validation_faults_are_rejected(evidence, repository)


def test_sc012_complete_verifier_records_fault_predicate_without_asserting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repository = tmp_path / "repository"
    evidence = _sc012_fault_evidence(tmp_path, repository_root=repository)
    module_path = repository / "tests" / "bdd" / "adapters" / "benchmark_environment_feasibility.py"
    module_path.parent.mkdir(parents=True, exist_ok=True)
    module_path.write_text("# fixture module path for root resolution\n", encoding="utf-8")
    monkeypatch.setattr(bef_adapter, "__file__", str(module_path))
    for name in (
        "_source_block_matches",
        "_contract_code_hashes_match",
        "_sc012_required_source_reads_are_bound",
        "_source_reads_are_allowlisted",
        "_prohibited_source_methods_are_not_forwarded",
        "_all_evidence_paths_are_verified",
        "_replay_is_read_only",
    ):
        monkeypatch.setattr(bef_adapter, name, lambda *_args, **_kwargs: True)

    expected_variants = (
        "wrong_source_identity",
        "send_raw_transaction",
        "admin_method",
        "sign_method",
        "secret_in_artifact",
        "missing_hash",
    )
    case = bef_adapter.BenchmarkEnvironmentCase(
        "BEF-SC-012",
        SimpleNamespace(negative_variants=expected_variants),
    )

    class CollectingContext:
        scenario_id = "BEF-SC-012"

        def __init__(self, outcome: ProbeEvidence) -> None:
            self.outcome = outcome
            self.checks: dict[str, bool] = {}

        def check(self, name: str, condition: bool) -> None:
            self.checks[name] = condition

    context = CollectingContext(evidence)
    case._verify_BEF_SC_012(context)

    assert context.checks["secrets_absent"] is True


def test_sc006_duplicate_recovery_requires_failed_original_and_two_same_operation_retries() -> None:
    operation_id = "operation-1"
    key = "same-generated-idempotency-key"
    request = {"method": "POST", "path": "/tools/bef-a/purchase", "headers": {"idempotency-key": key, "authorization-sha256": "d" * 64}, "body": {"resourceId": "bef-resource-v1"}}
    response_body = {
        "operationId": operation_id,
        "resourceId": "bef-resource-v1",
        "contentHash": "a" * 64,
        "contentBytes": "eyJyZXNvdXJjZSI6InBpbm5lZCJ9",
    }
    artifacts = [
        _sc006_artifact("http/001-response-loss.json", "actual-tool-http", {
            "boundary": "actual-tool-http", "operationId": operation_id, "variantId": "response_loss",
            "request": {**request, "headers": {**request["headers"], "payment-signature-present": True}},
            "response": {"status": 502, "body": {"error": "settlement_observation_unknown"}},
        }),
        *[
            _sc006_artifact(f"http/00{index}-concurrent-duplicate.json", "actual-tool-http", {
                "boundary": "actual-tool-http", "operationId": operation_id, "variantId": "concurrent_duplicate",
                "request": request, "response": {"status": 200, "body": response_body},
            })
            for index in (2, 3)
        ],
    ]
    evidence = _sc006_evidence(artifacts, operations=[{
        "operationId": operation_id,
        "idempotencyKeyHash": hashlib.sha256(key.encode()).hexdigest(),
        "observedStatus": "delivered",
        "receiptStatus": "success",
        "transactionHash": "0x" + "1" * 64,
    }])
    assert bef_adapter._duplicate_retries_keep_identity(evidence)

    changed_request = {**request, "headers": {"idempotency-key": "different-key"}}
    tampered = replace(artifacts[2], payload={**artifacts[2].payload, "request": changed_request})
    assert not bef_adapter._duplicate_retries_keep_identity(_sc006_evidence([artifacts[0], artifacts[1], tampered], operations=evidence.index["operations"]))


def test_sc006_unknown_receipt_requires_same_hash_and_ordered_original_reconciliation() -> None:
    operation_id = "operation-1"
    generation_id = "generation-1"
    transaction_hash = "0x" + "2" * 64
    key = "sc006-shared-operation-key"
    content_hash = SC006_CONTENT_HASH
    reconciled_payment = {
        "payment_id": "payment-1", "operation_id": operation_id, "generation_id": generation_id,
        "transaction_hash": transaction_hash, "receipt_status": "success", "amount_units": "100000",
        "token_delta_units": "100000", "payer_address": SC006_PAYER, "asset_address": SC006_ASSET,
        "network": "eip155:8453", "facilitator_address": SC006_PAYTO,
    }
    settle_observation = {
        "observation_id": "settle-observation-1", "phase": "settle", "outcome": "unknown",
        "operation_id": operation_id, "variant_id": "response_loss",
        "request_sha256": "d" * 64,
        "transaction_hash": transaction_hash,
        "safe_request": {"paymentRequirements": {
            "scheme": "exact", "network": "eip155:8453", "asset": SC006_ASSET,
            "amount": "100000", "payTo": SC006_PAYTO,
        }},
    }
    settle_retry_observation = {
        **settle_observation,
        "observation_id": "settle-observation-2",
        "transaction_hash": None,
    }

    def database(path: str, variant: str, query_name: str, rows: list[dict[str, Any]]) -> EvidenceArtifact:
        return _sc006_artifact(path, "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": variant,
            "readOnly": True, "databaseRole": "bef_observer", "transactionReadOnly": "on",
            "queryName": query_name, "rows": rows,
        })

    def http(path: str, boundary: str, variant: str, request: dict[str, Any], response: dict[str, Any]) -> EvidenceArtifact:
        return _sc006_artifact(path, boundary, {
            "boundary": boundary, "operationId": operation_id, "variantId": variant,
            "request": request, "response": response,
        })

    artifacts = [
        http("http/001-missing-receipt-original-purchase.json", "actual-tool-http", "missing_receipt", {
            "method": "POST", "path": "/tools/bef-a/purchase", "headers": {"idempotency-key": key},
            "body": {"resourceId": "bef-resource-v1"},
        }, {"status": 502, "body": {"error": "settlement_outcome_unknown", "operationId": operation_id}}),
        database("db/002-missing-receipt-after-unavailable-operation-by-id.json", "missing_receipt", "operation-by-id", [
            {"operation_id": operation_id, "status": "settlement_unknown", "receipt_status": "unknown", "transaction_hash": transaction_hash},
        ]),
        database("db/003-missing-receipt-after-unavailable-payments-by-operation.json", "missing_receipt", "payments-by-operation", [
            {"payment_id": "payment-1", "operation_id": operation_id, "transaction_hash": transaction_hash, "receipt_status": "unknown"},
        ]),
        database("db/004-missing-receipt-after-unavailable-deliveries-by-operation.json", "missing_receipt", "deliveries-by-operation", []),
        http("http/005-missing-receipt-unverified-same-operation-retry.json", "actual-tool-http", "missing_receipt", {
            "method": "POST", "path": "/tools/bef-a/purchase", "headers": {"idempotency-key": key},
            "body": {"resourceId": "bef-resource-v1"},
        }, {"status": 409, "body": {"error": "settlement_outcome_unknown", "operationId": operation_id}}),
        database("db/006-after-unknown-retry-operation-by-id.json", "missing_receipt", "operation-by-id", [
            {"operation_id": operation_id, "status": "settlement_unknown", "receipt_status": "unknown", "transaction_hash": transaction_hash},
        ]),
        database("db/007-after-unknown-retry-payments-by-operation.json", "missing_receipt", "payments-by-operation", [
            {"payment_id": "payment-1", "operation_id": operation_id, "transaction_hash": transaction_hash, "receipt_status": "unknown"},
        ]),
        database("db/008-after-unknown-retry-deliveries-by-operation.json", "missing_receipt", "deliveries-by-operation", []),
        http("http/009-receipt-fault-status.json", "facilitator-http", "missing_receipt", {
            "method": "GET", "path": f"/internal/admin/sc006/receipt-read-fault/status/{operation_id}", "headers": {},
        }, {"status": 200, "body": {
            "applied": True, "faultedReads": 1, "transactionHash": transaction_hash,
            "broadcastHashes": [transaction_hash],
        }}),
        _sc006_artifact("rpc/010-original-receipt-independent-success.json", "local-chain-readonly-proxy", {
            "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
            "operationId": operation_id, "variantId": "missing_receipt", "method": "eth_getTransactionReceipt",
            "params": [transaction_hash], "result": {"transactionHash": transaction_hash, "status": "0x1", "logs": []},
        }),
        http("http/011-receipt-fault-restore.json", "facilitator-http", "missing_receipt", {
            "method": "POST", "path": "/internal/admin/sc006/receipt-read-fault/restore", "headers": {},
            "body": {"operationId": operation_id, "generationId": "generation-1"},
        }, {"status": 200, "body": {"restored": True, "applied": True, "transactionHash": transaction_hash}}),
        http("http/012-original-reconciliation.json", "facilitator-http", "missing_receipt", {
            "method": "POST", "path": "/internal/admin/reconcile-original-settlement", "headers": {},
            "body": {"operationId": operation_id},
        }, {"status": 200, "body": {"accepted": True, "reasonCode": "original_settlement_reconciled"}}),
        database("db/013-after-original-reconciliation-operation-by-id.json", "response_loss", "operation-by-id", [
            {"operation_id": operation_id, "generation_id": generation_id, "status": "settled", "receipt_status": "success", "transaction_hash": transaction_hash},
        ]),
        database("db/014-after-original-reconciliation-payments-by-operation.json", "response_loss", "payments-by-operation", [
            reconciled_payment,
        ]),
        database("db/015-after-original-reconciliation-deliveries-by-operation.json", "response_loss", "deliveries-by-operation", []),
        database("db/015a-after-original-reconciliation-generation-by-id.json", "response_loss", "generation-by-id", [
            {"generation_id": generation_id, "payer_address": SC006_PAYER},
        ]),
        database("db/015b-after-original-reconciliation-x402-observations-by-operation.json", "response_loss", "x402-observations-by-operation", [
            settle_observation, settle_retry_observation,
        ]),
        http("http/016-response-loss-client.json", "actual-tool-http", "response_loss", {
            "method": "POST", "path": "/tools/bef-a/purchase",
            "monotonicStartMs": 100,
            "headers": {"idempotency-key": key, "authorization-sha256": "d" * 64},
            "body": {"resourceId": "bef-resource-v1"},
        }, {"transportError": "connection_closed", "relayUpstreamStatus": 200, "monotonicObservedMs": 220}),
        _sc006_artifact("http/017-response-loss-relay.json", "probe-owned-response-loss-relay", {
            "boundary": "probe-owned-response-loss-relay", "schemaVersion": "bef-sc006-response-loss-relay/v1",
            "operationId": operation_id, "variantId": "response_loss", "upstreamStatus": 200,
            "upstreamMonotonicStartMs": 110, "upstreamMonotonicObservedMs": 200,
            "deliveredOperationId": operation_id, "deliveredResourceId": "bef-resource-v1",
            "deliveredContentSha256": content_hash, "deliveredContentBytes": len(SC006_CONTENT),
            "downstreamClosedWithoutResponse": True,
            "idempotencyKeySha256": hashlib.sha256(key.encode()).hexdigest(),
        }),
        *[
            http(f"http/{index}-concurrent-duplicate.json", "actual-tool-http", "concurrent_duplicate", {
                "method": "POST", "path": "/tools/bef-a/purchase",
                "monotonicStartMs": start,
                "headers": {"idempotency-key": key, "authorization-sha256": "d" * 64},
                "body": {"resourceId": "bef-resource-v1"},
            }, {"status": 200, "body": {
                "operationId": operation_id, "resourceId": "bef-resource-v1", "contentHash": content_hash,
                "contentBytes": base64.b64encode(SC006_CONTENT).decode("ascii"),
            }, "monotonicObservedMs": finish})
            for index, start, finish in (("018", 120, 180), ("019", 130, 190))
        ],
        database("db/020-after-concurrent-duplicate-operation-by-id.json", "concurrent_duplicate", "operation-by-id", [
            {"operation_id": operation_id, "generation_id": generation_id, "status": "delivered", "receipt_status": "success", "transaction_hash": transaction_hash},
        ]),
        database("db/020a-after-concurrent-duplicate-payments-by-operation.json", "concurrent_duplicate", "payments-by-operation", [
            reconciled_payment,
        ]),
        database("db/020b-after-concurrent-duplicate-x402-observations-by-operation.json", "concurrent_duplicate", "x402-observations-by-operation", [
            settle_observation, settle_retry_observation,
        ]),
        database("db/021-after-concurrent-duplicate-deliveries-by-operation.json", "concurrent_duplicate", "deliveries-by-operation", [
            {"delivery_id": "delivery-1", "operation_id": operation_id, "resource_id": "bef-resource-v1", "content_sha256": content_hash, "content_bytes": len(SC006_CONTENT)},
        ]),
    ]
    evidence = _sc006_evidence(artifacts, operations=[{
        "operationId": operation_id, "idempotencyKeyHash": hashlib.sha256(key.encode()).hexdigest(),
        "observedStatus": "delivered", "receiptStatus": "success", "transactionHash": transaction_hash,
    }])
    assert bef_adapter._unknown_receipt_is_not_success(evidence)
    assert bef_adapter._duplicate_retries_keep_identity(evidence)
    assert bef_adapter._one_durable_settlement(evidence)
    assert bef_adapter._one_durable_delivery(evidence)

    observations_artifact = next(item for item in artifacts if item.relative_path.endswith("after-concurrent-duplicate-x402-observations-by-operation.json"))
    divergent_observations = replace(observations_artifact, payload={
        **observations_artifact.payload,
        "rows": [settle_observation, {**settle_retry_observation, "transaction_hash": "0x" + "4" * 64}],
    })
    assert not bef_adapter._one_durable_settlement(_sc006_evidence(
        [divergent_observations if item is observations_artifact else item for item in artifacts],
        operations=evidence.index["operations"],
    ))
    too_many_observations = replace(observations_artifact, payload={
        **observations_artifact.payload,
        "rows": [settle_observation, settle_retry_observation, {**settle_retry_observation, "observation_id": "settle-observation-3"}],
    })
    assert not bef_adapter._one_durable_settlement(_sc006_evidence(
        [too_many_observations if item is observations_artifact else item for item in artifacts],
        operations=evidence.index["operations"],
    ))
    changed_request_hash = replace(observations_artifact, payload={
        **observations_artifact.payload,
        "rows": [settle_observation, {**settle_retry_observation, "request_sha256": "e" * 64}],
    })
    assert not bef_adapter._one_durable_settlement(_sc006_evidence(
        [changed_request_hash if item is observations_artifact else item for item in artifacts],
        operations=evidence.index["operations"],
    ))
    duplicate_id_observation = replace(observations_artifact, payload={
        **observations_artifact.payload,
        "rows": [settle_observation, {**settle_retry_observation, "observation_id": "settle-observation-1"}],
    })
    assert not bef_adapter._one_durable_settlement(_sc006_evidence(
        [duplicate_id_observation if item is observations_artifact else item for item in artifacts],
        operations=evidence.index["operations"],
    ))
    changed_requirements = replace(observations_artifact, payload={
        **observations_artifact.payload,
        "rows": [settle_observation, {**settle_retry_observation, "safe_request": {"paymentRequirements": {
            "scheme": "exact", "network": "eip155:8453", "asset": SC006_ASSET,
            "amount": "200000", "payTo": SC006_PAYTO,
        }}}],
    })
    assert not bef_adapter._one_durable_settlement(_sc006_evidence(
        [changed_requirements if item is observations_artifact else item for item in artifacts],
        operations=evidence.index["operations"],
    ))

    reordered = [*artifacts[:8], artifacts[9], artifacts[8], *artifacts[10:]]
    assert not bef_adapter._unknown_receipt_is_not_success(_sc006_evidence(reordered))

    nonoverlapping = list(artifacts)
    duplicate = next(index for index, artifact in enumerate(nonoverlapping) if artifact.relative_path == "http/018-concurrent-duplicate.json")
    duplicate_artifact = nonoverlapping[duplicate]
    duplicate_payload = {**duplicate_artifact.payload,
                         "request": {**duplicate_artifact.payload["request"], "monotonicStartMs": 201},
                         "response": {**duplicate_artifact.payload["response"], "monotonicObservedMs": 240}}
    nonoverlapping[duplicate] = replace(duplicate_artifact, payload=duplicate_payload)
    assert not bef_adapter._duplicate_retries_keep_identity(_sc006_evidence(nonoverlapping, operations=evidence.index["operations"]))


def test_sc006_settlement_and_delivery_predicates_deduplicate_repeat_snapshots() -> None:
    operation_id = "operation-1"
    transaction_hash = "0x" + "3" * 64
    payment = {
        "payment_id": "payment-1", "operation_id": operation_id, "transaction_hash": transaction_hash,
        "receipt_status": "success", "amount_units": "100000", "token_delta_units": "100000",
        "payer_address": SC006_PAYER, "asset_address": SC006_ASSET, "network": "eip155:8453",
        "facilitator_address": SC006_PAYTO,
    }
    x402 = {
        "observation_id": "settle-observation-1", "phase": "settle", "outcome": "success", "request_sha256": "d" * 64,
        "operation_id": operation_id, "variant_id": "response_loss",
        "transaction_hash": transaction_hash,
        "safe_request": {"paymentRequirements": {
            "scheme": "exact", "network": "eip155:8453", "asset": SC006_ASSET,
            "amount": "100000", "payTo": SC006_PAYTO,
        }},
    }
    artifacts = [
            _sc006_artifact("http/001-original-response-loss.json", "actual-tool-http", {
                "boundary": "actual-tool-http", "operationId": operation_id, "variantId": "response_loss",
                "request": {"method": "POST", "path": "/tools/bef-a/purchase", "headers": {"Idempotency-Key": "idem-001"}, "body": {"resourceId": "bef-resource-v1"}},
                "response": {"status": 503, "body": {"error": "payment outcome unknown"}},
            }),
        _sc006_artifact("db/after-original-reconciliation-payments-by-operation.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "response_loss",
            "queryName": "payments-by-operation", "readOnly": True, "rows": [payment],
        }),
        _sc006_artifact("db/after-concurrent-duplicate-payments-by-operation.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "concurrent_duplicate",
            "queryName": "payments-by-operation", "readOnly": True, "rows": [payment],
        }),
        _sc006_artifact("db/after-original-reconciliation-x402-observations-by-operation.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "response_loss",
            "queryName": "x402-observations-by-operation", "readOnly": True, "rows": [x402],
        }),
        _sc006_artifact("db/after-concurrent-duplicate-x402-observations-by-operation.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "concurrent_duplicate",
            "queryName": "x402-observations-by-operation", "readOnly": True, "rows": [x402],
        }),
        _sc006_artifact("db/001-operation-by-id.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "response_loss",
            "queryName": "operation-by-id", "readOnly": True, "rows": [{"operation_id": operation_id, "generation_id": "generation-1"}],
        }),
        _sc006_artifact("db/002-generation-by-id.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "response_loss",
            "queryName": "generation-by-id", "readOnly": True, "rows": [{"generation_id": "generation-1", "payer_address": SC006_PAYER}],
        }),
        _sc006_artifact("rpc/005-original-success-receipt.json", "local-chain-readonly-proxy", {
            "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
            "operationId": operation_id, "method": "eth_getTransactionReceipt", "params": [transaction_hash],
            "result": {"transactionHash": transaction_hash, "status": "0x1", "logs": []},
        }),
        _sc006_artifact("http/007-concurrent-duplicate-1.json", "actual-tool-http", {
            "boundary": "actual-tool-http", "operationId": operation_id, "variantId": "concurrent_duplicate",
            "request": {"method": "POST", "path": "/tools/bef-a/purchase", "headers": {}, "body": {"resourceId": "bef-resource-v1"}},
            "response": {"status": 200, "body": {
                "operationId": operation_id, "resourceId": "bef-resource-v1", "contentHash": SC006_CONTENT_HASH,
                "contentBytes": base64.b64encode(SC006_CONTENT).decode("ascii"),
            }},
        }),
        _sc006_artifact("http/008-concurrent-duplicate-2.json", "actual-tool-http", {
            "boundary": "actual-tool-http", "operationId": operation_id, "variantId": "concurrent_duplicate",
            "request": {"method": "POST", "path": "/tools/bef-a/purchase", "headers": {}, "body": {"resourceId": "bef-resource-v1"}},
            "response": {"status": 200, "body": {
                "operationId": operation_id, "resourceId": "bef-resource-v1", "contentHash": SC006_CONTENT_HASH,
                "contentBytes": base64.b64encode(SC006_CONTENT).decode("ascii"),
            }},
        }),
        _sc006_artifact("db/after-concurrent-duplicate-deliveries-by-operation.json", "readonly-database", {
            "boundary": "readonly-database", "operationId": operation_id, "variantId": "concurrent_duplicate",
            "queryName": "deliveries-by-operation", "readOnly": True,
            "rows": [{"delivery_id": "delivery-1", "operation_id": operation_id, "resource_id": "bef-resource-v1", "content_sha256": SC006_CONTENT_HASH, "content_bytes": len(SC006_CONTENT)}],
        }),
    ]
    evidence = _sc006_evidence(artifacts, operations=[{
        "operationId": operation_id, "observedStatus": "delivered", "receiptStatus": "success",
    }])
    assert bef_adapter._one_durable_settlement(evidence)
    assert bef_adapter._one_durable_delivery(evidence)

    response_artifact = next(item for item in artifacts if item.relative_path == "http/007-concurrent-duplicate-1.json")
    bad_resource_body = {
        **response_artifact.payload["response"]["body"],
        "resourceId": "different-resource",
    }
    wrong_resource = replace(response_artifact, payload={
        **response_artifact.payload,
        "response": {**response_artifact.payload["response"], "body": bad_resource_body},
    })
    wrong_resource_evidence = [wrong_resource if item is response_artifact else item for item in artifacts]
    assert not bef_adapter._one_durable_delivery(_sc006_evidence(wrong_resource_evidence, operations=evidence.index["operations"]))

    bad_hash_body = {
        **response_artifact.payload["response"]["body"],
        "contentHash": "f" * 64,
    }
    wrong_content_hash = replace(response_artifact, payload={
        **response_artifact.payload,
        "response": {**response_artifact.payload["response"], "body": bad_hash_body},
    })
    wrong_hash_evidence = [wrong_content_hash if item is response_artifact else item for item in artifacts]
    assert not bef_adapter._one_durable_delivery(_sc006_evidence(wrong_hash_evidence, operations=evidence.index["operations"]))

    conflicting = replace(artifacts[1], payload={**artifacts[1].payload, "rows": [{**payment, "transaction_hash": "0x" + "4" * 64}]})
    assert not bef_adapter._one_durable_settlement(_sc006_evidence([*artifacts[:1], conflicting, *artifacts[2:]], operations=evidence.index["operations"]))


def _sc006_invalid_payment_capture() -> ProbeEvidence:
    canonical = {
        "scheme": "exact", "network": "eip155:8453", "asset": SC006_ASSET,
        "amount": "100000", "payTo": SC006_PAYTO, "maxTimeoutSeconds": 120,
        "extra": {
            "name": "USD Coin", "version": "2", "paymentFlow": "authorization",
            "assetTransferMethod": "eip3009",
        },
    }
    variants = {
        "wrong_domain": ("No matching payment requirements", {
            **canonical, "extra": {**canonical["extra"], "name": "USD Coin BEF Wrong Domain"},
        }, "1" * 64),
        "amount_mismatch": ("No matching payment requirements", {**canonical, "amount": "100001"}, "2" * 64),
        "reused_authorization": ("verification_rejected", canonical, "3" * 64),
    }
    artifacts: list[EvidenceArtifact] = []

    def required_response(error: str) -> dict[str, Any]:
        protocol = {"x402Version": 2, "error": error, "accepts": [canonical]}
        raw = base64.b64encode(json.dumps(protocol, separators=(",", ":")).encode("utf-8")).decode("ascii")
        return {
            "status": 402,
            "headers": {"payment-required": raw},
            "decodedPaymentRequired": protocol,
            "decodedProtocol": {"paymentRequired": protocol, "selectedPaymentRequirements": canonical},
            "body": {},
        }

    for variant, (error, selected, digest) in variants.items():
        operation_id = f"operation-{variant}"
        challenge = _sc006_artifact(f"http/{variant}-challenge.json", "actual-tool-http", {
            "boundary": "actual-tool-http", "operationId": operation_id, "variantId": variant,
            "request": {
                "method": "POST", "path": "/tools/bef-a/purchase",
                "headers": {"authorization": "[REDACTED]", "authorization-present": True, "authorization-sha256": "a" * 64},
                "body": {"resourceId": "bef-resource-v1"},
            },
            "response": required_response("Payment required"),
        })
        signed_headers = {
            "authorization": "[REDACTED]", "authorization-present": True,
            "authorization-sha256": "a" * 64, "payment-signature": "[REDACTED]",
            "payment-signature-present": True, "payment-signature-sha256": digest,
        }
        signed = _sc006_artifact(f"http/{variant}-signed.json", "actual-tool-http", {
            "boundary": "actual-tool-http", "operationId": operation_id, "variantId": variant,
            "request": {
                "method": "POST", "path": "/tools/bef-a/purchase", "headers": signed_headers,
                "decodedPaymentPayload": {"x402Version": 2, "sourceHeaderSha256": digest, "accepted": selected},
                "body": {"resourceId": "bef-resource-v1"},
            },
            "response": required_response(error),
        })
        artifacts.extend((challenge, signed))

        generation_id = "generation-1"
        db_rows = {
            "operation-by-id": [{
                "operation_id": operation_id, "generation_id": generation_id, "status": "rejected",
                "receipt_status": "not_submitted", "transaction_hash": None,
                "operation_kind": "purchase", "env_id": "bef-a",
            }],
            "generation-by-id": [{"generation_id": generation_id, "payer_address": SC006_PAYER}],
            "denials-by-generation": [{
                "denial_id": f"denial-{variant}", "operation_id": operation_id,
                "generation_id": generation_id, "env_id": "bef-a", "reason_code": "payment_protocol_rejected",
            }],
            "payments-by-operation": [],
            "deliveries-by-operation": [],
        }
        for query_name, rows in db_rows.items():
            artifacts.append(_sc006_artifact(f"db/{variant}-{query_name}.json", "readonly-database", {
                "boundary": "readonly-database", "operationId": operation_id, "variantId": variant,
                "queryName": query_name, "rows": rows,
            }))
        if variant == "reused_authorization":
            artifacts.append(_sc006_artifact(f"db/{variant}-x402-observations-by-operation.json", "readonly-database", {
                "boundary": "readonly-database", "operationId": operation_id, "variantId": variant,
                "queryName": "x402-observations-by-operation", "rows": [{
                    "operation_id": operation_id, "generation_id": generation_id, "variant_id": "baseline",
                    "phase": "verify", "outcome": "rejected", "transaction_hash": None,
                    "safe_request": {"paymentPayload": {"accepted": canonical}, "paymentRequirements": canonical},
                    "safe_response": {
                        "isValid": False, "invalidReason": "verification_rejected",
                        "invalidMessage": "verification_rejected", "payer": SC006_PAYER,
                    },
                }],
            }))
        else:
            artifacts.append(_sc006_artifact(f"db/{variant}-x402-observations-by-operation.json", "readonly-database", {
                "boundary": "readonly-database", "operationId": operation_id, "variantId": variant,
                "queryName": "x402-observations-by-operation", "rows": [],
            }))

        for role, account in (("payer", SC006_PAYER), ("payto", SC006_PAYTO)):
            account_word = account[2:].lower().rjust(64, "0")
            for phase, balance in (("before", 200000 if role == "payer" else 10),
                                   ("after", 200000 if role == "payer" else 10)):
                artifacts.append(_sc006_artifact(f"rpc/{variant}-{role}-{phase}.json", "local-chain-readonly-proxy", {
                    "boundary": "local-chain-readonly-proxy", "endpointBoundary": "local-chain-readonly-proxy",
                    "operationId": operation_id, "variantId": variant, "method": "eth_call",
                    "params": [{"to": SC006_ASSET, "data": "0x70a08231" + account_word}, "latest"],
                    "result": hex(balance),
                }))

    original_digest = variants["reused_authorization"][2]
    artifacts.append(_sc006_artifact("http/missing-receipt-original-signed.json", "actual-tool-http", {
        "boundary": "actual-tool-http", "operationId": "operation-missing-receipt", "variantId": "missing_receipt",
        "request": {
            "method": "POST", "path": "/tools/bef-a/purchase",
            "headers": {
                "payment-signature": "[REDACTED]", "payment-signature-present": True,
                "payment-signature-sha256": original_digest,
            },
            "decodedPaymentPayload": {
                "x402Version": 2, "sourceHeaderSha256": original_digest, "accepted": canonical,
            },
            "body": {"resourceId": "bef-resource-v1"},
        },
        "response": {"status": 502, "body": {"error": "settlement_outcome_unknown"}},
    }))
    return _sc006_evidence(artifacts)


def test_sc006_invalid_payment_requires_validated_signed_402_and_durable_no_effect_rejection() -> None:
    evidence = _sc006_invalid_payment_capture()

    assert bef_adapter._invalid_payment_variants_are_denied(evidence)

    signed = next(
        item for item in evidence.artifacts
        if item.payload.get("variantId") == "wrong_domain"
        and item.payload.get("request", {}).get("decodedPaymentPayload") is not None
    )
    missing_decoded_error = replace(signed, payload={
        **signed.payload,
        "response": {
            **signed.payload["response"],
            "decodedPaymentRequired": {
                key: value for key, value in signed.payload["response"]["decodedPaymentRequired"].items()
                if key != "error"
            },
        },
    })
    assert not bef_adapter._invalid_payment_variants_are_denied(_sc006_evidence([
        missing_decoded_error if item is signed else item for item in evidence.artifacts
    ]))

    unknown_502 = replace(signed, payload={
        **signed.payload,
        "response": {**signed.payload["response"], "status": 502},
    })
    assert not bef_adapter._invalid_payment_variants_are_denied(_sc006_evidence([
        unknown_502 if item is signed else item for item in evidence.artifacts
    ]))


def test_sc006_invalid_payment_requires_transaction_read_only_and_privilege_proof() -> None:
    evidence = _sc006_invalid_payment_capture()
    assert bef_adapter._invalid_payment_variants_are_denied(evidence)

    query = next(
        item for item in evidence.artifacts
        if item.payload.get("queryName") == "operation-by-id"
    )
    transaction_writable = replace(query, payload={**query.payload, "transactionReadOnly": "off"})
    assert not bef_adapter._invalid_payment_variants_are_denied(_sc006_evidence([
        transaction_writable if item is query else item for item in evidence.artifacts
    ]))

    proof = next(
        item for item in evidence.artifacts
        if item.payload.get("queryName") == "observer-role-effective-privileges"
    )
    writable_privilege = replace(proof, payload={
        **proof.payload,
        "rows": [
            {**row, "can_update": True} if row.get("table_name") == "bef_operation" else row
            for row in proof.payload["rows"]
        ],
    })
    assert not bef_adapter._invalid_payment_variants_are_denied(_sc006_evidence([
        writable_privilege if item is proof else item for item in evidence.artifacts
    ]))


def test_sc006_invalid_payment_requires_a_durable_denial_row() -> None:
    evidence = _sc006_invalid_payment_capture()
    denial = next(
        item for item in evidence.artifacts
        if item.payload.get("variantId") == "amount_mismatch"
        and item.payload.get("queryName") == "denials-by-generation"
    )
    absent_denial = replace(denial, payload={**denial.payload, "rows": []})
    assert not bef_adapter._invalid_payment_variants_are_denied(_sc006_evidence([
        absent_denial if item is denial else item for item in evidence.artifacts
    ]))
