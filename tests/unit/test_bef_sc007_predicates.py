from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "bdd" / "adapters" / "bef_sc007_predicates.py"
SPEC = importlib.util.spec_from_file_location("bef_sc007_predicates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PREDICATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREDICATES)


def rpc_artifact(path: str, variant: str, method: str, params: list[object], result: object) -> SimpleNamespace:
    return SimpleNamespace(
        boundary="local-chain-readonly-proxy",
        relative_path=path,
        payload={
            "schemaVersion": "bef-rpc-observation/v1",
            "boundary": "local-chain-readonly-proxy",
            "endpointBoundary": "local-chain-readonly-proxy",
            "variantId": variant,
            "method": method,
            "params": params,
            "result": result,
        },
    )


def source_identity_evidence() -> SimpleNamespace:
    block = 12345
    block_hash = "0x" + "a" * 64
    artifacts = []
    for variant in PREDICATES.SC007_VARIANTS:
        artifacts.append(rpc_artifact(f"rpc/{variant}-chain.json", variant, "eth_chainId", [], "0x2105"))
        artifacts.append(rpc_artifact(
            f"rpc/{variant}-fork.json", variant, "eth_getBlockByNumber", [hex(block), False],
            {"number": hex(block), "hash": block_hash},
        ))
    return SimpleNamespace(
        manifest={
            "source": {"chainId": 8453, "blockNumber": hex(block), "blockHash": block_hash},
            "local": {"chainId": 8453, "forkBlock": hex(block)},
        },
        artifacts=artifacts,
    )


def state_evidence() -> tuple[SimpleNamespace, dict[str, str], str, str, str, str]:
    env_id, generation_id = "e" * 36, "a" * 36
    payer, recipient = "0x" + "1" * 40, "0x" + "2" * 40
    weth, usdc = "0x" + "3" * 40, "0x" + "4" * 40
    router, pool = "0x" + "5" * 40, "0x" + "6" * 40
    block_number, block_hash = 123, "0x" + "b" * 64
    row = lambda name: {
        "table_name": name, "can_select": True, "can_insert": False, "can_update": False,
        "can_delete": False, "can_truncate": False, "can_references": False, "can_trigger": False,
    }
    readonly = SimpleNamespace(boundary="readonly-database", payload={
        "schemaVersion": "bef-db-observation/v1", "queryName": "observer-role-effective-privileges",
        "readOnly": True, "databaseRole": "bef_observer",
        "role": {
            "role_name": "bef_observer", "is_superuser": False, "can_create_db": False,
            "can_create_role": False, "can_replicate": False, "can_bypass_rls": False,
            "can_create_in_schema": False, "can_create_in_database": False,
        },
        "rows": [row(name) for name in (
            "bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery", "bef_denial",
            "bef_selected_execution", "bef_selected_execution_event",
        )],
    })
    payer_row = SimpleNamespace(boundary="readonly-database", payload={
        "schemaVersion": "bef-db-observation/v1", "queryName": "generation-by-id", "readOnly": True,
        "databaseRole": "bef_observer", "transactionReadOnly": "on", "envId": env_id, "generationId": generation_id,
        "variantId": "actual_output_below_task_goal_recorded",
        "rows": [{"env_id": env_id, "generation_id": generation_id, "payer_address": payer}],
    })
    manifest = {"contracts": {
        "weth": {"address": weth}, "usdc": {"address": usdc},
        "swapRouter02": {"address": router}, "pool": {"address": pool},
    }}
    snapshot = {
        "blockNumber": str(block_number), "blockHash": block_hash,
        "payerNativeWei": "101", "payerWethUnits": "102", "payerUsdcUnits": "103",
        "recipientUsdcUnits": "104", "wethRouterAllowance": "105", "poolWethUnits": "106",
        "poolUsdcUnits": "107", "poolLiquidity": "108", "poolSqrtPriceX96": "109",
    }
    tag = hex(block_number)
    word = lambda value: f"0x{value:064x}"
    calls = [
        (weth, "0x70a08231" + PREDICATES._word_addr(payer), 102),
        (usdc, "0x70a08231" + PREDICATES._word_addr(payer), 103),
        (usdc, "0x70a08231" + PREDICATES._word_addr(recipient), 104),
        (weth, "0xdd62ed3e" + PREDICATES._word_addr(payer) + PREDICATES._word_addr(router), 105),
        (weth, "0x70a08231" + PREDICATES._word_addr(pool), 106),
        (usdc, "0x70a08231" + PREDICATES._word_addr(pool), 107),
        (pool, PREDICATES._selector("liquidity()"), 108),
        (pool, PREDICATES._selector("slot0()"), 109),
    ]
    artifacts = [readonly, payer_row, rpc_artifact("rpc/state-block.json", "actual_output_below_task_goal_recorded",
        "eth_getBlockByNumber", [tag, False], {"number": tag, "hash": block_hash}),
        rpc_artifact("rpc/state-balance.json", "actual_output_below_task_goal_recorded",
        "eth_getBalance", [payer, tag], word(101))]
    for index, (address, data, value) in enumerate(calls):
        result = word(value)
        if data == PREDICATES._selector("slot0()"):
            result += "0" * 64 * 6
        artifacts.append(rpc_artifact(f"rpc/state-call-{index}.json", "actual_output_below_task_goal_recorded",
            "eth_call", [{"to": address, "data": data}, tag], result))
    evidence = SimpleNamespace(manifest=manifest, artifacts=artifacts)
    return evidence, snapshot, env_id, generation_id, recipient, block_hash


def slippage_evidence() -> tuple[SimpleNamespace, dict[str, object], list[dict[str, object]], str]:
    variant = "agent_chosen_slippage_guard_reverts"
    env_id, generation_id = "e" * 36, "11111111-1111-4111-8111-111111111111"
    payer, recipient = "0x" + "1" * 40, "0x" + "2" * 40
    weth, usdc, router, quoter = ("0x" + str(digit) * 40 for digit in ("3", "4", "5", "6"))
    block_number, block_hash, amount_in, quote_out = 123, "0x" + "c" * 64, 10_000_000_000_000_000, 50_000
    calldata = "0x" + "ab" * 132
    raw_quote = "0x" + f"{quote_out:064x}" + "0" * 64 * 3
    response = {
        "envId": env_id, "generationId": generation_id, "route": "uniswap-v3-exactInputSingle",
        "quoteStatus": "observed", "blockNumber": str(block_number),
        "quote": {"amountInWei": str(amount_in), "amountOutUsdcUnits": str(quote_out)},
    }
    observation = SimpleNamespace(boundary="actual-tool-http-local-chain-readonly-proxy", payload={
        "schemaVersion": "bef-resource-observation/v1", "variantId": variant, "envId": env_id,
        "generationId": generation_id, "selectedQuoteRequest": {"amountInWei": str(amount_in)},
        "response": response,
        "independentQuoterV2": {"amountOutUsdcUnits": str(quote_out), "blockNumber": str(block_number),
            "blockHash": block_hash, "address": quoter, "calldata": calldata, "rawResult": raw_quote},
    })
    http_quote = SimpleNamespace(boundary="actual-tool-http", payload={
        "schemaVersion": "bef-http-observation/v1", "variantId": variant, "operationId": None,
        "request": {"method": "GET", "path": f"/tools/{env_id}/quote?amountInWei={amount_in}"},
        "response": {"status": 200, "body": response},
    })
    manifest = {"contracts": {"weth": {"address": weth}, "usdc": {"address": usdc},
        "swapRouter02": {"address": router}, "quoterV2": {"address": quoter}},
        "swap": {"tokenIn": weth, "tokenOut": usdc, "fee": 500}}
    artifacts = [observation, http_quote,
        rpc_artifact("rpc/quote-call.json", variant, "eth_call", [{"to": quoter, "data": calldata}, hex(block_number)], raw_quote),
        rpc_artifact("rpc/quote-block.json", variant, "eth_getBlockByNumber", [hex(block_number), False],
            {"number": hex(block_number), "hash": block_hash})]
    evidence = SimpleNamespace(manifest=manifest, environment_id=env_id, artifacts=artifacts)
    selected = {"variant": variant, "action": {"amountInWei": str(amount_in), "amountOutMinimumUsdcUnits": str(quote_out + 1),
        "recipient": recipient, "gasLimit": "1200000"}, "payload": {"envId": env_id, "generationId": generation_id,
        "before": {"blockNumber": str(block_number)}}}
    wrap = {"variant": variant, "kind": "wrap", "outcome": "success", "action": {"amountWei": "10000000000000000"}}
    approve = {"variant": variant, "kind": "approve", "outcome": "success", "action": {"amountUnits": "20000000000000000"}}
    swap_action = selected["action"]
    intent = PREDICATES._expected_calldata(evidence, "swap", swap_action)
    assert intent is not None
    revert_text = b"Too little received"
    revert_data = "0x08c379a0" + f"{32:064x}" + f"{len(revert_text):064x}" + revert_text.hex().ljust(((len(revert_text) + 31) // 32) * 64, "0")
    evidence.artifacts.append(rpc_artifact("rpc/minout-eth-call.json", variant, "eth_call", [
        {"from": payer, "to": intent[0], "data": intent[1], "value": "0x0", "gas": hex(1_200_000)},
        hex(block_number),
    ], {"error": {"data": revert_data}}))
    swap = {**selected, "kind": "swap", "payer": payer, "outcome": "reverted",
        "receipt": {"gasUsed": "150000"}}
    return evidence, selected, [wrap, approve, swap], revert_data


class NativeConversionDeltaTests(unittest.TestCase):
    def test_successful_wrap_and_unwrap_include_selected_principal(self) -> None:
        amount = 1_000_000_000_000_000_000
        gas_cost = 21_000_000_000_000_000
        self.assertEqual(
            PREDICATES._expected_native_conversion_delta("wrap", "success", amount, gas_cost),
            -(amount + gas_cost),
        )
        self.assertEqual(
            PREDICATES._expected_native_conversion_delta("unwrap", "success", amount, gas_cost),
            amount - gas_cost,
        )

    def test_reverted_wrap_and_unwrap_burn_only_receipt_gas(self) -> None:
        amount = 1_000_000_000_000_000_000
        gas_cost = 21_000_000_000_000_000
        for kind in ("wrap", "unwrap"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    PREDICATES._expected_native_conversion_delta(kind, "reverted", amount, gas_cost),
                    -gas_cost,
                )

    def test_invalid_action_or_outcome_has_no_expected_delta(self) -> None:
        self.assertIsNone(PREDICATES._expected_native_conversion_delta("swap", "success", 1, 1))
        self.assertIsNone(PREDICATES._expected_native_conversion_delta("wrap", "unknown", 1, 1))


class PerGenerationPayerTests(unittest.TestCase):
    @staticmethod
    def readonly_role_proof() -> SimpleNamespace:
        required = (
            "bef_environment", "bef_generation", "bef_operation", "bef_payment", "bef_delivery", "bef_denial",
            "bef_selected_execution", "bef_selected_execution_event",
        )
        row = lambda name: {
            "table_name": name, "can_select": True, "can_insert": False, "can_update": False,
            "can_delete": False, "can_truncate": False, "can_references": False, "can_trigger": False,
        }
        return SimpleNamespace(boundary="readonly-database", payload={
            "schemaVersion": "bef-db-observation/v1", "queryName": "observer-role-effective-privileges",
            "readOnly": True, "databaseRole": "bef_observer",
            "role": {
                "role_name": "bef_observer", "is_superuser": False, "can_create_db": False,
                "can_create_role": False, "can_replicate": False, "can_bypass_rls": False,
                "can_create_in_schema": False, "can_create_in_database": False,
            },
            "rows": [row(name) for name in required],
        })

    def test_distinct_variant_generations_resolve_their_own_payer(self) -> None:
        env = "e" * 36
        generation_a = "a" * 36
        generation_b = "b" * 36
        payer_a = "0x" + "1" * 40
        payer_b = "0x" + "2" * 40

        def artifact(generation_id: str, variant_id: str, payer: str) -> SimpleNamespace:
            return SimpleNamespace(
                boundary="readonly-database",
                payload={
                    "schemaVersion": "bef-db-observation/v1",
                    "queryName": "generation-by-id",
                    "readOnly": True,
                    "databaseRole": "bef_observer",
                    "transactionReadOnly": "on",
                    "envId": env,
                    "generationId": generation_id,
                    "variantId": variant_id,
                    "rows": [{
                        "env_id": env,
                        "generation_id": generation_id,
                        "payer_address": payer,
                    }],
                },
            )

        evidence = SimpleNamespace(artifacts=[
            self.readonly_role_proof(),
            artifact(generation_a, "variant_a", payer_a),
            artifact(generation_b, "variant_b", payer_b),
        ])
        self.assertEqual(PREDICATES._payer(evidence, env, generation_a, "variant_a"), payer_a)
        self.assertEqual(PREDICATES._payer(evidence, env, generation_b, "variant_b"), payer_b)

    def test_conflicting_envelope_identity_fails_closed(self) -> None:
        env = "e" * 36
        generation = "a" * 36
        evidence = SimpleNamespace(artifacts=[
            self.readonly_role_proof(),
            SimpleNamespace(boundary="readonly-database", payload={
                "schemaVersion": "bef-db-observation/v1", "queryName": "generation-by-id",
                "readOnly": True, "databaseRole": "bef_observer", "transactionReadOnly": "on",
                "envId": "f" * 36,
                "generationId": generation, "variantId": "variant_a",
                "rows": [{"env_id": env, "generation_id": generation, "payer_address": "0x" + "1" * 40}],
            }),
        ])
        self.assertIsNone(PREDICATES._payer(evidence, env, generation, "variant_a"))

    def test_missing_envelope_identity_or_actual_readonly_mode_fails_closed(self) -> None:
        env, generation, payer = "e" * 36, "a" * 36, "0x" + "1" * 40
        base = {
            "schemaVersion": "bef-db-observation/v1", "queryName": "generation-by-id",
            "readOnly": True, "databaseRole": "bef_observer", "variantId": "variant_a",
            "rows": [{"env_id": env, "generation_id": generation, "payer_address": payer}],
        }
        role = self.readonly_role_proof()
        for omitted in ({**base}, {**base, "envId": env, "generationId": generation, "transactionReadOnly": "off"}):
            with self.subTest(fields=sorted(omitted)):
                evidence = SimpleNamespace(artifacts=[role, SimpleNamespace(boundary="readonly-database", payload=omitted)])
                self.assertIsNone(PREDICATES._payer(evidence, env, generation, "variant_a"))

    def test_conflicting_generation_rows_fail_closed(self) -> None:
        env = "e" * 36
        generation = "a" * 36
        payload = {
            "schemaVersion": "bef-db-observation/v1",
            "queryName": "generation-by-id",
            "readOnly": True,
            "databaseRole": "bef_observer",
            "transactionReadOnly": "on",
            "envId": env,
            "generationId": generation,
            "variantId": "variant_a",
            "rows": [
                {"env_id": env, "generation_id": generation, "payer_address": "0x" + "1" * 40},
                {"env_id": env, "generation_id": generation, "payer_address": "0x" + "2" * 40},
            ],
        }
        evidence = SimpleNamespace(artifacts=[self.readonly_role_proof(), SimpleNamespace(boundary="readonly-database", payload=payload)])
        self.assertIsNone(PREDICATES._payer(evidence, env, generation, "variant_a"))

    def test_effective_write_privilege_invalidates_observer_identity(self) -> None:
        proof = self.readonly_role_proof()
        proof.payload["rows"][0]["can_update"] = True
        evidence = SimpleNamespace(artifacts=[proof])
        self.assertFalse(PREDICATES._observer_role_is_readonly(evidence))


class SelectedActionDerivedMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.weth = "0x" + "1" * 40
        self.usdc = "0x" + "2" * 40
        self.router = "0x" + "3" * 40
        self.evidence = SimpleNamespace(manifest={
            "contracts": {
                "weth": {"address": self.weth},
                "usdc": {"address": self.usdc},
                "swapRouter02": {"address": self.router},
            },
            "swap": {"tokenIn": self.weth, "tokenOut": self.usdc, "fee": 500},
        })

    def test_approve_enrichment_is_manifest_bound_and_rejects_extra_fields(self) -> None:
        raw = {"kind": "approve", "amountUnits": "200", "gasLimit": "1200000"}
        observed = {**raw, "token": self.weth.upper().replace("0X", "0x"), "spender": self.router}
        self.assertTrue(PREDICATES._selected_action_response_matches(self.evidence, raw, observed))

        wrong = {**observed, "spender": "0x" + "4" * 40}
        self.assertFalse(PREDICATES._selected_action_response_matches(self.evidence, raw, wrong))
        extra = {**observed, "untrustedMetadata": "ignored?"}
        self.assertFalse(PREDICATES._selected_action_response_matches(self.evidence, raw, extra))

    def test_swap_enrichment_is_manifest_bound_and_raw_inputs_stay_exact(self) -> None:
        raw = {
            "kind": "swap", "amountInWei": "1000", "amountOutMinimumUsdcUnits": "0",
            "gasLimit": "1200000", "recipient": "0x" + "4" * 40,
        }
        observed = {
            **raw, "tokenIn": self.weth, "tokenOut": self.usdc, "fee": 500,
            "route": "uniswap-v3-exactInputSingle", "router": self.router,
        }
        self.assertTrue(PREDICATES._selected_action_response_matches(self.evidence, raw, observed))

        wrong_token = {**observed, "tokenOut": "0x" + "5" * 40}
        self.assertFalse(PREDICATES._selected_action_response_matches(self.evidence, raw, wrong_token))
        wrong_input = {**observed, "amountInWei": "1001"}
        self.assertFalse(PREDICATES._selected_action_response_matches(self.evidence, raw, wrong_input))

    def test_wrap_does_not_accept_unexpected_enrichment(self) -> None:
        raw = {"kind": "wrap", "amountWei": "100", "gasLimit": "1200000"}
        self.assertTrue(PREDICATES._selected_action_response_matches(self.evidence, raw, dict(raw)))
        self.assertFalse(PREDICATES._selected_action_response_matches(
            self.evidence, raw, {**raw, "token": self.weth}))


class DenialRequestShapeTests(unittest.TestCase):
    def test_unsupported_asset_matches_manifest_address_case_insensitively(self) -> None:
        usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        evidence = SimpleNamespace(manifest={"contracts": {"usdc": {"address": usdc}}})
        self.assertTrue(PREDICATES._denial_request_shape_matches(
            evidence, "unsupported_asset_boundary_rejected", {"tokenIn": usdc.lower()}))
        self.assertFalse(PREDICATES._denial_request_shape_matches(
            evidence, "unsupported_asset_boundary_rejected", {"tokenIn": "0x" + "1" * 40}))


class DatabaseSnapshotIdentityTests(unittest.TestCase):
    def test_snapshot_scope_requires_selected_env_generation_and_readonly_transaction(self) -> None:
        payload = {
            "schemaVersion": "bef-db-observation/v1", "readOnly": True,
            "transactionReadOnly": "on", "databaseRole": "bef_observer",
            "envId": "bef-env-a", "generationId": "11111111-1111-4111-8111-111111111111",
            "variantId": "unsupported_asset_boundary_rejected",
        }
        self.assertTrue(PREDICATES._db_snapshot_scope_matches(
            payload, "bef-env-a", "11111111-1111-4111-8111-111111111111",
            "unsupported_asset_boundary_rejected"))
        for field in ("envId", "generationId", "transactionReadOnly"):
            without_scope = dict(payload)
            del without_scope[field]
            self.assertFalse(PREDICATES._db_snapshot_scope_matches(
                without_scope, "bef-env-a", "11111111-1111-4111-8111-111111111111",
                "unsupported_asset_boundary_rejected"))


class ActionGasAndConversionEventTests(unittest.TestCase):
    @staticmethod
    def snapshot(**updates: int) -> dict[str, str]:
        values = {
            "payerNativeWei": 100, "payerWethUnits": 100, "payerUsdcUnits": 100,
            "recipientUsdcUnits": 200, "wethRouterAllowance": 20,
            "poolWethUnits": 1000, "poolUsdcUnits": 500,
        }
        values.update(updates)
        return {key: str(value) for key, value in values.items()}

    def test_approve_and_swap_native_effects_are_receipt_gas_only(self) -> None:
        before = self.snapshot()
        approve_after = self.snapshot(payerNativeWei=94, wethRouterAllowance=50)
        approve_effects = {key: str(int(approve_after[key]) - int(before[key])) for key in before}
        approve = {
            "payload": {"before": before, "after": approve_after, "effects": approve_effects},
            "kind": "approve", "outcome": "success", "action": {"amountUnits": "50"},
            "receipt": {"gasUsed": "2", "effectiveGasPrice": "3", "logs": []},
        }
        with patch.object(PREDICATES, "_state_rpc_matches", return_value=True):
            self.assertTrue(PREDICATES._action_delta_matches(SimpleNamespace(), approve))

            swap_after = self.snapshot(
                payerNativeWei=94, payerWethUnits=90, recipientUsdcUnits=205,
                wethRouterAllowance=10, poolWethUnits=1010, poolUsdcUnits=495,
            )
            swap_effects = {key: str(int(swap_after[key]) - int(before[key])) for key in before}
            swap = {
                "payload": {"before": before, "after": swap_after, "effects": swap_effects},
                "kind": "swap", "outcome": "success", "action": {
                    "amountInWei": "10", "recipient": "0x" + "2" * 40,
                }, "payer": "0x" + "1" * 40,
                "receipt": {"gasUsed": "2", "effectiveGasPrice": "3", "logs": []},
            }
            with patch.object(PREDICATES, "_actual_usdc_output", return_value=5):
                self.assertTrue(PREDICATES._action_delta_matches(SimpleNamespace(), swap))

    def test_wrap_and_unwrap_receipts_bind_deposit_or_withdrawal_without_transfer(self) -> None:
        weth, payer, amount = "0x" + "3" * 40, "0x" + "1" * 40, 100
        evidence = SimpleNamespace(manifest={"contracts": {"weth": {"address": weth}}})
        address_word = "0x" + PREDICATES._word_addr(payer)
        cases = (
            ("wrap", "Deposit(address,uint256)", "deposits"),
            ("unwrap", "Withdrawal(address,uint256)", "withdrawals"),
        )
        for kind, signature, _ in cases:
            topic = "0x" + PREDICATES._keccak256(signature.encode()).hex()
            log = {"address": weth, "topics": [topic, address_word], "data": "0x" + f"{amount:064x}"}
            selected = {
                "kind": kind, "action": {"amountWei": str(amount)}, "payer": payer,
                "outcome": "success", "receipt": {"logs": [log]},
            }
            with self.subTest(kind=kind):
                self.assertTrue(PREDICATES._action_logs_match(evidence, selected))


class StrictRawEvidenceJoinTests(unittest.TestCase):
    def test_chain_and_fork_identity_join_all_variants(self) -> None:
        evidence = source_identity_evidence()
        self.assertTrue(PREDICATES._source_identity_matches(evidence))

        contradictory = rpc_artifact("rpc/conflicting-chain.json", PREDICATES.SC007_VARIANTS[0],
            "eth_chainId", [], "0x1")
        evidence.artifacts.append(contradictory)
        self.assertFalse(PREDICATES._source_identity_matches(evidence))

    def test_unapproved_variant_ids_fail_closed(self) -> None:
        evidence = source_identity_evidence()
        evidence.artifacts.append(rpc_artifact("rpc/unapproved-variant.json", "extra_variant",
            "eth_chainId", [], "0x2105"))
        self.assertFalse(PREDICATES._no_unapproved_variant_ids(evidence))

    def test_snapshot_join_accepts_all_matching_reads_and_rejects_conflicting_duplicate(self) -> None:
        evidence, snapshot, env_id, generation_id, recipient, _ = state_evidence()
        variant = "actual_output_below_task_goal_recorded"
        self.assertTrue(PREDICATES._state_rpc_matches_snapshot(
            evidence, variant, snapshot, env_id, generation_id, recipient))

        # A second exact query with a conflicting value invalidates the sample;
        # one matching response cannot hide a contradictory duplicate.
        matching = next(item for item in evidence.artifacts
            if item.payload.get("method") == "eth_call"
            and item.payload["params"][0]["data"].lower() == ("0x70a08231" + PREDICATES._word_addr("0x" + "1" * 40)).lower())
        evidence.artifacts.append(rpc_artifact("rpc/conflicting-state.json", variant, "eth_call",
            matching.payload["params"], "0x" + f"{999:064x}"))
        self.assertFalse(PREDICATES._state_rpc_matches_snapshot(
            evidence, variant, snapshot, env_id, generation_id, recipient))

    def test_code_hash_join_requires_each_variant_and_rejects_duplicate_conflict(self) -> None:
        contracts = {
            "usdc": {"address": "0x" + "1" * 40, "proxyCodeHash": "", "implementation": "0x" + "2" * 40, "implementationCodeHash": ""},
            "weth": {"address": "0x" + "3" * 40, "codeHash": ""},
            "swapRouter02": {"address": "0x" + "4" * 40, "codeHash": ""},
            "factory": {"address": "0x" + "5" * 40, "codeHash": ""},
            "quoterV2": {"address": "0x" + "6" * 40, "codeHash": ""},
            "pool": {"address": "0x" + "7" * 40, "codeHash": ""},
        }
        code_by_address = {
            "0x" + "1" * 40: "0x60016001",
            "0x" + "2" * 40: "0x60026002",
            "0x" + "3" * 40: "0x60036003",
            "0x" + "4" * 40: "0x60046004",
            "0x" + "5" * 40: "0x60056005",
            "0x" + "6" * 40: "0x60066006",
            "0x" + "7" * 40: "0x60076007",
        }
        code_hash = lambda code: "0x" + PREDICATES._keccak256(bytes.fromhex(code[2:])).hex()
        contracts["usdc"]["proxyCodeHash"] = code_hash(code_by_address[contracts["usdc"]["address"]])
        contracts["usdc"]["implementationCodeHash"] = code_hash(code_by_address[contracts["usdc"]["implementation"]])
        for name in ("weth", "swapRouter02", "factory", "quoterV2", "pool"):
            contracts[name]["codeHash"] = code_hash(code_by_address[contracts[name]["address"]])
        pinned = "0x3039"
        artifacts = []
        for variant in PREDICATES.SC007_VARIANTS:
            for address, code in code_by_address.items():
                artifacts.append(rpc_artifact(f"rpc/{variant}-code-{address[-2:]}.json", variant,
                    "eth_getCode", [address, pinned], code))
        evidence = SimpleNamespace(manifest={"contracts": contracts, "local": {"forkBlock": pinned}}, artifacts=artifacts)
        self.assertTrue(PREDICATES._selected_code_hashes_match(evidence))
        evidence.artifacts.append(rpc_artifact("rpc/conflicting-code.json", PREDICATES.SC007_VARIANTS[0],
            "eth_getCode", [next(iter(code_by_address)), pinned], "0x60086008"))
        self.assertFalse(PREDICATES._selected_code_hashes_match(evidence))

    def test_slippage_revert_joins_quote_quoter_prestate_and_exact_revert_reason(self) -> None:
        evidence, selected, actions, revert_data = slippage_evidence()
        self.assertTrue(PREDICATES._slippage_revert_matches(evidence, actions))

        conflicting_quote = evidence.artifacts[0]
        conflicting_quote.payload["independentQuoterV2"]["amountOutUsdcUnits"] = "50001"
        self.assertFalse(PREDICATES._slippage_revert_matches(evidence, actions))
        conflicting_quote.payload["independentQuoterV2"]["amountOutUsdcUnits"] = "50000"

        unrelated = "0x08c379a0" + f"{32:064x}" + f"{9:064x}" + b"Not a swap".hex().ljust(64, "0")
        minout = next(item for item in evidence.artifacts
            if "minout-eth-call" in getattr(item, "relative_path", ""))
        minout.payload["result"] = {"error": {"data": unrelated}}
        self.assertFalse(PREDICATES._slippage_revert_matches(evidence, actions))
        minout.payload["result"] = {"error": {"data": revert_data}}
        self.assertTrue(PREDICATES._slippage_revert_matches(evidence, actions))

        # Evidence from an exact duplicate call is part of the join too.
        evidence.artifacts.append(rpc_artifact("rpc/minout-eth-call-duplicate.json", selected["variant"], "eth_call",
            minout.payload["params"], {"error": {"data": unrelated}}))
        self.assertFalse(PREDICATES._slippage_revert_matches(evidence, actions))


if __name__ == "__main__":
    unittest.main()
