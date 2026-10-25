"""Focused fail-closed tests for SC003 denial and endpoint evidence predicates."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from tests.bdd.adapters.benchmark_environment_feasibility import (
    EvidenceArtifact,
    ProbeEvidence,
    _denied_state_is_unchanged,
    _foreign_and_stale_requests_are_denied,
    _sc003_denial_rows_match_http,
    _sc003_endpoint_identity_matches,
    _sc003_state_reads_unchanged,
    _keccak256,
)


ENV_A = "bef-env-a"
ENV_B = "bef-env-b"
CURRENT_GENERATION = str(uuid.UUID("00000000-0000-4000-8000-000000000001"))
STALE_GENERATION = str(uuid.UUID("00000000-0000-4000-8000-000000000002"))
FOREIGN_GENERATION = str(uuid.UUID("00000000-0000-4000-8000-000000000003"))
FOREIGN_DENIAL = str(uuid.UUID("00000000-0000-4000-8000-000000000004"))
STALE_DENIAL = str(uuid.UUID("00000000-0000-4000-8000-000000000005"))
MANIFEST_HASH = "a" * 64


def _artifact(path: str, boundary: str, payload: dict[str, Any], sha256: str = "b" * 64) -> EvidenceArtifact:
    return EvidenceArtifact(path, sha256, boundary, payload)


def _generation(generation_id: str, env_id: str, status: str) -> dict[str, Any]:
    return {"generation_id": generation_id, "env_id": env_id, "status": status}


def _denial(
    denial_id: str,
    env_id: str,
    generation_id: str,
    route: str,
    reason_code: str = "participant_generation_scope_denied",
) -> dict[str, Any]:
    return {
        "denial_id": denial_id,
        "env_id": env_id,
        "generation_id": generation_id,
        "operation_id": None,
        "route": route,
        "reason_code": reason_code,
        "request_sha256": "c" * 64,
    }


def _db_payload(query_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schemaVersion": "bef-db-observation/v1",
        "boundary": "readonly-database",
        "operationId": None,
        "variantId": None,
        "readOnly": True,
        "databaseRole": "bef_observer",
        "queryName": query_name,
        "rows": rows,
    }


def _http_attempt(variant: str, generation_id: str, denial_id: str) -> EvidenceArtifact:
    return _artifact(
        f"http/sc003-{variant}.json",
        "actual-tool-http",
        {
            "schemaVersion": "bef-http-observation/v1",
            "boundary": "actual-tool-http",
            "operationId": None,
            "variantId": variant,
            "request": {
                "method": "GET",
                "path": f"/tools/{ENV_A}/offer?resourceId=bef-resource-v1",
                "headers": {
                    "x-bef-generation": generation_id,
                    "authorization-present": True,
                    "idempotency-key": f"sc003-{variant}",
                },
                "body": None,
            },
            "response": {
                "status": 403,
                "headers": {"x-bef-denial-id": denial_id},
                "body": {"error": "participant_generation_scope_denied"},
            },
        },
    )


def _scope_evidence(
    tmp_path: Path,
    *,
    include_denials: bool = True,
    foreign_denial_env: str = ENV_A,
    foreign_denial_generation: str = FOREIGN_GENERATION,
) -> ProbeEvidence:
    manifest = {
        "local": {"environments": [{"id": ENV_A}, {"id": ENV_B}]},
    }
    artifacts: list[EvidenceArtifact] = [
        _http_attempt("foreign_environment", FOREIGN_GENERATION, FOREIGN_DENIAL),
        _http_attempt("stale_generation", STALE_GENERATION, STALE_DENIAL),
    ]
    generations = {
        "stale-a": [_generation(STALE_GENERATION, ENV_A, "fenced")],
        "current-a": [_generation(CURRENT_GENERATION, ENV_A, "active")],
        "foreign-b-owner": [_generation(FOREIGN_GENERATION, ENV_B, "active")],
        "foreign-b-at-target-a": [],
    }
    denial_rows: dict[str, list[dict[str, Any]]] = {name: [] for name in generations}
    if include_denials:
        denial_rows["foreign-b-at-target-a"] = [
            _denial(FOREIGN_DENIAL, foreign_denial_env, foreign_denial_generation, f"/tools/{ENV_A}/offer")
        ]
        denial_rows["stale-a"] = [
            _denial(STALE_DENIAL, ENV_A, STALE_GENERATION, f"/tools/{ENV_A}/offer")
        ]

    state_queries = (
        "generation-by-id",
        "operations-by-generation",
        "payments-by-operation",
        "deliveries-by-operation",
        "x402-observations-by-operation",
        "denials-by-generation",
    )
    for phase in ("before", "after"):
        for selector, rows in generations.items():
            for query_name in state_queries:
                selected_rows = rows if query_name == "generation-by-id" else []
                if phase == "after" and query_name == "denials-by-generation":
                    selected_rows = denial_rows[selector]
                artifacts.append(
                    _artifact(
                        f"db/sc003-{phase}-{selector}-{query_name}.json",
                        "readonly-database",
                        _db_payload(query_name, selected_rows),
                    )
                )
    index = {
        "schemaVersion": "bef-runtime-probe/v1",
        "scenarioId": "BEF-SC-003",
        "status": "captured",
        "operations": [],
    }
    return ProbeEvidence(
        scenario_id="BEF-SC-003",
        status="captured",
        directory=tmp_path,
        index=index,
        manifest=manifest,
        manifest_sha256=MANIFEST_HASH,
        artifacts=tuple(artifacts),
        environment_id=ENV_A,
        generation_id=CURRENT_GENERATION,
    )


def _endpoint_evidence(
    tmp_path: Path,
    *,
    health_env: str = ENV_A,
    health_manifest: str = MANIFEST_HASH,
) -> ProbeEvidence:
    health = {
        "status": "ok",
        "boundary": "local-chain-readonly-proxy",
        "envId": health_env,
        "manifestSha256": health_manifest,
    }
    health_bytes = json.dumps(health, separators=(",", ":"), sort_keys=True).encode("utf-8")
    health_hash = hashlib.sha256(health_bytes).hexdigest()
    health_path = f"rpc/endpoint-health-{ENV_A}.json"
    artifacts = (
        _artifact(health_path, "local-chain-readonly-proxy", health, health_hash),
        _artifact(
            f"rpc/endpoint-binding-{ENV_A}.json",
            "local-chain-readonly-proxy",
            {
                "schemaVersion": "bef-rpc-endpoint-binding/v1",
                "boundary": "local-chain-readonly-proxy",
                "operationId": None,
                "variantId": None,
                "environmentId": ENV_A,
                "endpointRef": {"scheme": "http", "host": "127.0.0.1", "port": 18545},
                "healthArtifactPath": health_path,
                "healthArtifactSha256": health_hash,
                "health": health,
            },
        ),
    )
    return ProbeEvidence(
        scenario_id="BEF-SC-003",
        status="captured",
        directory=tmp_path,
        index={"schemaVersion": "bef-runtime-probe/v1", "scenarioId": "BEF-SC-003", "status": "captured"},
        manifest={"local": {"environments": [{"id": ENV_A}, {"id": ENV_B}]}},
        manifest_sha256=MANIFEST_HASH,
        artifacts=artifacts,
        environment_id=ENV_A,
        generation_id=CURRENT_GENERATION,
    )


def _state_read_evidence(
    tmp_path: Path,
    *,
    extra_rpc: tuple[str, list[Any], Any] | None = None,
) -> ProbeEvidence:
    payer_a = "0x" + "21" * 20
    payer_b = "0x" + "22" * 20
    payer_c = "0x" + "23" * 20
    donor = "0x" + "24" * 20
    usdc = "0x" + "11" * 20
    implementation = "0x" + "12" * 20
    weth = "0x" + "13" * 20
    factory = "0x" + "14" * 20
    router = "0x" + "15" * 20
    quoter = "0x" + "16" * 20
    pool = "0x" + "17" * 20
    code = "0x6000"
    code_hash = "0x" + _keccak256(bytes.fromhex(code[2:])).hex()
    manifest = {
        "local": {"chainId": 8453, "environments": [{"id": ENV_A}, {"id": ENV_B}]},
        "contracts": {
            "usdc": {"address": usdc, "proxyCodeHash": code_hash, "implementation": implementation, "implementationCodeHash": code_hash},
            "weth": {"address": weth, "codeHash": code_hash},
            "factory": {"address": factory, "codeHash": code_hash},
            "swapRouter02": {"address": router, "codeHash": code_hash},
            "quoterV2": {"address": quoter, "codeHash": code_hash},
            "pool": {"address": pool, "codeHash": code_hash},
        },
        "funding": {"donor": donor},
    }
    artifacts: list[EvidenceArtifact] = []

    for env_id, port in ((ENV_A, 18545), (ENV_B, 28545)):
        health = {
            "status": "ok",
            "boundary": "local-chain-readonly-proxy",
            "envId": env_id,
            "manifestSha256": MANIFEST_HASH,
        }
        health_bytes = json.dumps(health, separators=(",", ":"), sort_keys=True).encode("utf-8")
        health_hash = hashlib.sha256(health_bytes).hexdigest()
        health_path = f"rpc/endpoint-health-{env_id}.json"
        binding_path = f"rpc/endpoint-binding-{env_id}.json"
        artifacts.append(_artifact(health_path, "local-chain-readonly-proxy", health, health_hash))
        artifacts.append(_artifact(binding_path, "local-chain-readonly-proxy", {
            "schemaVersion": "bef-rpc-endpoint-binding/v1",
            "boundary": "local-chain-readonly-proxy",
            "operationId": None,
            "variantId": None,
            "environmentId": env_id,
            "endpointRef": {"scheme": "http", "host": "127.0.0.1", "port": port},
            "healthArtifactPath": health_path,
            "healthArtifactSha256": health_hash,
            "health": health,
        }))

    selectors = {
        "stale-a": (ENV_A, payer_a, "fenced"),
        "current-a": (ENV_A, payer_b, "active"),
        "foreign-b-owner": (ENV_B, payer_c, "active"),
        "foreign-b-at-target-a": (ENV_A, payer_c, "active"),
    }
    for phase in ("before", "after"):
        for selector, (env_id, payer, status) in selectors.items():
            for query_name in (
                "generation-by-id", "operations-by-generation", "payments-by-operation",
                "deliveries-by-operation", "x402-observations-by-operation", "denials-by-generation",
            ):
                rows = [{"generation_id": selector, "env_id": env_id, "payer_address": payer, "status": status}] \
                    if query_name == "generation-by-id" and selector != "foreign-b-at-target-a" else []
                artifacts.append(_artifact(f"db/sc003-{phase}-{selector}-{query_name}.json", "readonly-database", {
                    "schemaVersion": "bef-db-observation/v1",
                    "boundary": "readonly-database",
                    "operationId": None,
                    "variantId": None,
                    "readOnly": True,
                    "databaseRole": "bef_observer",
                    "queryName": query_name,
                    "rows": rows,
                }))

    code_contracts = (usdc, implementation, weth, factory, router, quoter, pool)
    payer_addresses = (payer_a, payer_b, payer_c, donor)
    for env_id, _port in ((ENV_A, 18545), (ENV_B, 28545)):
        binding_path = f"rpc/endpoint-binding-{env_id}.json"
        for phase in ("before", "after"):
            reads: list[tuple[str, list[Any], Any]] = [
                ("eth_chainId", [], "0x2105"),
                ("eth_getBlockByNumber", ["latest", False], {"number": "0x32871b4", "hash": "0x" + "ab" * 32}),
            ]
            for address in payer_addresses:
                reads.extend((
                    ("eth_getBalance", [address, "latest"], "0x1234"),
                    ("eth_getTransactionCount", [address, "latest"], "0x3"),
                    ("eth_call", [{"to": usdc, "data": "0x70a08231" + address[2:].zfill(64)}, "latest"], "0x" + "0" * 62 + "64"),
                    ("eth_call", [{"to": usdc, "data": "0xdd62ed3e" + address[2:].zfill(64) + router[2:].zfill(64)}, "latest"], "0x" + "0" * 64),
                ))
            reads.extend(("eth_getCode", [address, "latest"], code) for address in code_contracts)
            if extra_rpc is not None and env_id == ENV_A and phase == "before":
                reads.append(extra_rpc)
            for index, (method, params, result) in enumerate(reads):
                payload = {
                    "schemaVersion": "bef-rpc-observation/v1",
                    "boundary": "local-chain-readonly-proxy",
                    "endpointBoundary": "local-chain-readonly-proxy",
                    "operationId": None,
                    "variantId": None,
                    "environmentId": env_id,
                    "endpointIdentityArtifact": binding_path,
                    "method": method,
                    "params": params,
                    "requestedBlock": params[1] if len(params) > 1 else None,
                    "result": result,
                }
                artifacts.append(_artifact(
                    f"rpc/sc003-{phase}-{env_id}-{index:03d}-{method}.json",
                    "local-chain-readonly-proxy",
                    payload,
                ))

    return ProbeEvidence(
        scenario_id="BEF-SC-003",
        status="captured",
        directory=tmp_path,
        index={"schemaVersion": "bef-runtime-probe/v1", "scenarioId": "BEF-SC-003", "status": "captured"},
        manifest=manifest,
        manifest_sha256=MANIFEST_HASH,
        artifacts=tuple(artifacts),
        environment_id=ENV_A,
        generation_id=CURRENT_GENERATION,
    )


def test_sc003_foreign_and_stale_scope_requires_new_independent_denial_rows() -> None:
    root = Path(".")
    assert _foreign_and_stale_requests_are_denied(_scope_evidence(root))
    assert not _foreign_and_stale_requests_are_denied(_scope_evidence(root, include_denials=False))


def test_sc003_denial_cannot_be_rebound_to_wrong_environment_or_generation() -> None:
    root = Path(".")
    assert not _sc003_denial_rows_match_http(
        _scope_evidence(root, foreign_denial_env=ENV_B),
        ("foreign_environment", "stale_generation"),
    )
    assert not _sc003_denial_rows_match_http(
        _scope_evidence(root, foreign_denial_generation=CURRENT_GENERATION),
        ("foreign_environment", "stale_generation"),
    )


def test_sc003_database_only_unchanged_claim_is_insufficient_without_two_chain_bindings() -> None:
    assert not _denied_state_is_unchanged(_scope_evidence(Path(".")))


def test_sc003_local_rpc_identity_requires_hash_linked_health_response() -> None:
    root = Path(".")
    assert _sc003_endpoint_identity_matches(_endpoint_evidence(root), ENV_A)
    assert not _sc003_endpoint_identity_matches(_endpoint_evidence(root, health_env=ENV_B), ENV_A)
    assert not _sc003_endpoint_identity_matches(_endpoint_evidence(root, health_manifest="d" * 64), ENV_A)


def test_sc003_allows_bound_chain_identity_and_head_reads_but_rejects_extra_rpc_methods(tmp_path: Path) -> None:
    assert _sc003_state_reads_unchanged(_state_read_evidence(tmp_path / "valid"))
    assert not _sc003_state_reads_unchanged(_state_read_evidence(
        tmp_path / "extra-method",
        extra_rpc=("eth_getTransactionByHash", ["0x" + "cc" * 32], {"hash": "0x" + "cc" * 32}),
    ))
    assert not _sc003_state_reads_unchanged(_state_read_evidence(
        tmp_path / "wrong-chain-read",
        extra_rpc=("eth_chainId", ["unexpected"], "0x2105"),
    ))
