from __future__ import annotations

import copy
import hashlib
import unittest

from tools.replay_bpc_bonus_local import (
    _verify_browser_http_probe,
    _verify_ui_request,
    verify_bonus_only_cash_substitution,
    verify_code_claim_denial,
    verify_run_denial,
)


DB = "oid_acceptance_0123456789abcdef0123456789abcdef"
IDENTITY = {"role": "oid_observer", "database": DB, "transaction_read_only": "on"}


def empty_run_snapshot(**overrides):
    snapshot = {
        "identity": IDENTITY.copy(),
        "intent": None,
        "agentIntents": [],
        "runs": [],
        "reservations": [],
        "budgetHolds": [],
        "tasks": [],
        "ledgerEntries": [],
        "ledgerOperations": [],
        "runOperations": [],
        "ledgerAudits": [],
        "agentPolicy": {"training": True, "ranked": True, "revision": 1},
        "bonusGrants": [],
        "bonusAvailableUnits": "0",
        "financialPolicy": {"allow_cash_shortfall": False, "operation_limit_units": None},
    }
    snapshot.update(overrides)
    return snapshot


def pending_intent(intent_id="intent-1", operation_id="intent-op", quote="1000000", tasks=None):
    return {
        "id": intent_id,
        "operation_id": operation_id,
        "mode": "training",
        "task_ids": tasks or ["S1"],
        "status": "pending",
        "run_id": None,
        "quote_price_units": quote,
        "cash_ceiling_units": "0",
    }


class BonusReplayTests(unittest.TestCase):
    def test_browser_http_probe_is_not_mistaken_for_a_ui_click(self):
        path = "/api/owner/runs/intents"
        capture = {
            "actions": [{"action": "http-probe", "selector": "mode-permission"}],
            "requests": [{"method": "POST", "path": path, "operationId": "mode-op"}],
            "responses": [{"method": "POST", "path": path, "status": 403}],
        }
        with self.assertRaises(AssertionError):
            _verify_ui_request(capture, operation_id="mode-op", path=path, status=403, action="mode-permission")
        outcome = {"method": "POST", "path": path, "status": 403, "operationId": "mode-op",
            "response": {"method": "POST", "path": path, "status": 403, "operationId": "mode-op"}}
        _verify_browser_http_probe(capture, outcome, operation_id="mode-op", path=path,
            status=403, probe="mode-permission")
        outcome["response"]["operationId"] = "different-op"
        with self.assertRaises(AssertionError):
            _verify_browser_http_probe(capture, outcome, operation_id="mode-op", path=path,
                status=403, probe="mode-permission")

    def test_claim_denial_replays_raw_rows_and_ignores_producer_boolean(self):
        code = {"id": "code-1", "issue_operation_id": "issue-op", "used_count": 0, "maximum_uses": 1}
        snapshot = {
            "observer": IDENTITY.copy(), "codes": [code], "redemptions": [], "claimOperations": [],
            "grants": [], "entries": [], "operations": [], "audits": [], "ownerBalances": [],
            "cashEffectCount": 0,
        }
        case = {
            "boundary": "valid_agent_bearer_without_owner_cookie",
            "outcome": {"method": "POST", "path": "/api/owner/bonus-codes/redeem", "status": 401,
                        "errorCode": "UNAUTHORIZED", "operationId": "claim-op"},
            "cookieCountBefore": 0, "cookieCountAfter": 0, "agentId": "agent-1", "claimOwnerId": "owner-1",
            "preflight": {"status": 200, "allowed": True, "agentId": "agent-1", "cookieCount": 0},
            "codeId": "code-1", "issueOperationId": "issue-op", "before": copy.deepcopy(snapshot),
            "after": copy.deepcopy(snapshot), "verified": False, "durableStateUnchanged": False,
        }
        self.assertTrue(verify_code_claim_denial(case, DB)["denialWithoutMutation"])
        case["after"]["claimOperations"].append({"operation_id": "claim-op"})
        case["verified"] = True
        with self.assertRaises(AssertionError):
            verify_code_claim_denial(case, DB)

    def test_mode_denial_uses_persisted_permission_and_no_intent(self):
        before = empty_run_snapshot(agentPolicy={"training": False, "ranked": True, "revision": 2})
        case = {
            "ownerOperationId": "mode-op", "request": {"method": "POST", "path": "/api/owner/runs/intents",
                "status": 403, "errorCode": "MODE_NOT_AUTHORIZED", "operationId": "mode-op"},
            "before": copy.deepcopy(before), "after": copy.deepcopy(before),
            "permissionBeforeDenial": False, "verified": False,
        }
        self.assertTrue(verify_run_denial(case, expected_database=DB, expected_status=403,
            expected_error="MODE_NOT_AUTHORIZED", kind="missing_mode_permission")["denialWithoutMutation"])
        case["after"]["intent"] = pending_intent()
        with self.assertRaises(AssertionError):
            verify_run_denial(case, expected_database=DB, expected_status=403,
                expected_error="MODE_NOT_AUTHORIZED", kind="missing_mode_permission")
        case["after"] = copy.deepcopy(before)
        del case["after"]["ledgerEntries"]
        with self.assertRaises(AssertionError):
            verify_run_denial(case, expected_database=DB, expected_status=403,
                expected_error="MODE_NOT_AUTHORIZED", kind="missing_mode_permission")

    def test_cap_and_bonus_shortfall_denials_bind_raw_policy_and_pending_intent(self):
        intent = pending_intent(quote="83334")
        before = empty_run_snapshot(intent=intent.copy(), agentIntents=[intent.copy()],
            financialPolicy={"allow_cash_shortfall": False, "operation_limit_units": "83333"})
        cap = {"intent": {"intentId": "intent-1", "operationId": "intent-op", "mode": "training", "taskIds": ["S1"]}, "accept": {
            "method": "POST", "path": "/api/agent/run-intents/intent-1/accept", "status": 409,
            "errorCode": "AGENT_BUDGET_EXCEEDED", "operationId": "accept-op"},
            "operationQuoteUnits": "83334", "operationLimitUnits": "83333",
            "before": copy.deepcopy(before), "after": copy.deepcopy(before), "cleanup": {"status": 200,
                "statusAfterCleanup": "cancelled"}, "verified": False,
        }
        self.assertTrue(verify_run_denial(cap, expected_database=DB, expected_status=409,
            expected_error="AGENT_BUDGET_EXCEEDED", kind="nominal_cap_exceeded")["denialWithoutMutation"])
        for wrong_mode, wrong_tasks in (("ranked", ["S1"]), ("training", ["S2"])):
            altered = copy.deepcopy(cap)
            altered["intent"].update(mode=wrong_mode, taskIds=wrong_tasks)
            for phase in ("before", "after"):
                altered[phase]["intent"].update(mode=wrong_mode, task_ids=wrong_tasks)
                altered[phase]["agentIntents"][0].update(mode=wrong_mode, task_ids=wrong_tasks)
            with self.assertRaises(AssertionError):
                verify_run_denial(altered, expected_database=DB, expected_status=409,
                    expected_error="AGENT_BUDGET_EXCEEDED", kind="nominal_cap_exceeded")
        cap["after"]["runs"].append({"id": "partial-run"})
        with self.assertRaises(AssertionError):
            verify_run_denial(cap, expected_database=DB, expected_status=409,
                expected_error="AGENT_BUDGET_EXCEEDED", kind="nominal_cap_exceeded")
        cap["after"] = copy.deepcopy(before)
        cap["after"]["ledgerEntries"].append({"operation_id": "accept-op", "entry_type": "reserve"})
        with self.assertRaises(AssertionError):
            verify_run_denial(cap, expected_database=DB, expected_status=409,
                expected_error="AGENT_BUDGET_EXCEEDED", kind="nominal_cap_exceeded")

        tasks = ["S1", "M1", "H1"]
        full_intent = pending_intent(tasks=tasks, quote="500000")
        shortfall_snapshot = empty_run_snapshot(intent=full_intent.copy(), agentIntents=[full_intent.copy()],
            bonusAvailableUnits="0", financialPolicy={"allow_cash_shortfall": False, "operation_limit_units": None})
        shortfall = {"intent": {"intentId": "intent-1", "operationId": "intent-op", "mode": "training", "taskIds": tasks},
            "accept": {"method": "POST", "path": "/api/agent/run-intents/intent-1/accept", "status": 409,
                "errorCode": "CASH_PERMISSION_REQUIRED", "operationId": "shortfall-op"},
            "quoteUnits": "500000", "bonusAvailableUnits": "0", "shortfallUnits": "500000",
            "before": copy.deepcopy(shortfall_snapshot), "after": copy.deepcopy(shortfall_snapshot),
            "cleanup": {"status": 200, "statusAfterCleanup": "cancelled"}, "verified": False,
        }
        self.assertTrue(verify_run_denial(shortfall, expected_database=DB, expected_status=409,
            expected_error="CASH_PERMISSION_REQUIRED", kind="insufficient_bonus")["denialWithoutMutation"])
        for phase in ("before", "after"):
            shortfall[phase]["intent"]["task_ids"] = ["S1"]
            shortfall[phase]["agentIntents"][0]["task_ids"] = ["S1"]
        shortfall["intent"]["taskIds"] = ["S1"]
        with self.assertRaises(AssertionError):
            verify_run_denial(shortfall, expected_database=DB, expected_status=409,
                expected_error="CASH_PERMISSION_REQUIRED", kind="insufficient_bonus")

    def test_bonus_only_cash_substitution_uses_raw_grant_to_ledger_lineage(self):
        owner, issuer, code_id, grant_id = "owner-1", "issuer-1", "code-1", "grant-1"
        grant_op = "bcg_" + hashlib.sha256(f"{code_id}\0{owner}".encode()).hexdigest()
        claim_op = "redeem-op"
        base = {
            "observer": {"role": "oid_observer", "database_name": DB, "transaction_read_only": "on"},
            "code": {"id": code_id, "issuer_owner_id": issuer, "issue_operation_id": "issue-op",
                "used_count": 1, "maximum_uses": 1, "amount_units": "250000"},
            "redemption": {"id": "redemption-1", "code_id": code_id, "owner_id": owner,
                "bonus_grant_id": grant_id, "financial_operation_id": grant_op},
            "grant": {"id": grant_id, "owner_id": owner, "issued_by_owner_id": issuer,
                "operation_id": grant_op, "amount_units": "250000", "expires_at": None},
            "claimOperations": [{"owner_id": owner, "operation_id": claim_op, "code_id": code_id,
                "redemption_id": "redemption-1"}],
            "ledgerOperations": [{"operation_id": grant_op, "action": "bonus_grant",
                "actor_owner_id": issuer, "subject_owner_id": owner}],
            "audits": [{"operation_id": grant_op, "event_type": "bonus_grant_issued",
                "metadata": {"grantId": grant_id}}, {"operation_id": claim_op,
                "event_type": "bonus_code_redeemed"}],
            "ledgerEntries": [{"owner_id": owner, "actor_owner_id": issuer, "bonus_grant_id": grant_id,
                "operation_id": grant_op, "entry_type": "bonus_grant", "source_kind": "tester_bonus",
                "available_delta_units": "250000", "reserved_delta_units": "0"}],
            "totals": [{"source_kind": "tester_bonus", "available_units": "250000", "reserved_units": "0"},
                {"source_kind": "cash_usdc", "available_units": "2000000", "reserved_units": "0"}],
            "policy": {"allow_cash_shortfall": True},
            "intent": {"status": "pending", "run_id": None, "quote_price_units": "416667",
                "cash_ceiling_units": "416667"},
            "runs": [], "runOperations": [], "reservations": [], "budgetHolds": [],
        }
        case = {"boundary": "local_isolated_direct_service_with_independent_read_only_postgres",
            "status": "failed", "codeGrantLineageVerified": False, "noCashFallbackEffects": False,
            "rejection": {"status": 409, "code": "BETA_BONUS_BALANCE_REQUIRED"},
            "funding": {"codeId": code_id, "issueOperationId": "issue-op", "issuerOwnerId": issuer,
                "redemptionId": "redemption-1", "redemptionOperationId": claim_op, "ownerId": owner,
                "grantId": grant_id, "acceptOperationId": "accept-op"},
            "syntheticRelease": {"selectedQuoteUnits": "416667"},
            "before": copy.deepcopy(base), "after": copy.deepcopy(base),
        }
        self.assertTrue(verify_bonus_only_cash_substitution(case, DB)["bonusOnlyCashSubstitutionRejected"])
        case["after"]["ledgerEntries"][0]["available_delta_units"] = "150000"
        with self.assertRaises(AssertionError):
            verify_bonus_only_cash_substitution(case, DB)


if __name__ == "__main__":
    unittest.main()
