from __future__ import annotations

import hashlib
import json
import unittest

from .benchmark_run_lifecycle_codex_verifier import derive_observations


INTENT_ID = "11111111-1111-4111-8111-111111111111"
RUN_ID = "22222222-2222-4222-8222-222222222222"
OPERATION_ID = "33333333-3333-4333-8333-333333333333"
OWNER_ID = "44444444-4444-4444-8444-444444444444"
AGENT_ID = "55555555-5555-4555-8555-555555555555"
_OBSERVER = {"role": "oid_observer", "transaction_read_only": "on", "database_name": "acceptance_fixture"}


def _pending_snapshot():
    return {"observer": dict(_OBSERVER), "database": {"observedAt": "2026-10-28T09:00:00Z",
        "intents": [{"id": INTENT_ID, "owner_id": OWNER_ID, "agent_id": AGENT_ID,
            "status": "pending", "run_id": None}],
        "runs": [], "reservations": [], "budgetHolds": [], "slots": [], "taskSlots": []}}


def _accepted_snapshot():
    return {"observer": dict(_OBSERVER), "database": {"observedAt": "2026-10-28T09:00:03Z",
        "intents": [{"id": INTENT_ID, "owner_id": OWNER_ID, "agent_id": AGENT_ID,
            "status": "accepted", "run_id": RUN_ID}],
        "runs": [{"id": RUN_ID, "intent_id": INTENT_ID, "owner_id": OWNER_ID,
            "agent_id": AGENT_ID, "status": "queued", "started_at": None}],
        "reservations": [{"run_id": RUN_ID}], "budgetHolds": [{"run_id": RUN_ID}],
        "slots": [], "taskSlots": []}}


def _codex_receipt():
    argument_text = json.dumps({"intentId": INTENT_ID, "operationId": OPERATION_ID}, separators=(",", ":"))
    argument_hash = hashlib.sha256(argument_text.encode()).hexdigest()
    event = {"event": "item.completed", "name": "runs_accept_launch_intent", "serverLabel": "owner_agent",
        "status": "completed", "isError": False, "argumentsSha256": argument_hash,
        "itemKeys": ["type", "tool_name", "arguments", "result"], "result": {"runId": RUN_ID, "status": "queued"}}
    return {"schemaVersion": "brl-codex-owner-mcp-observation/v1", "outcome": "accepted_result_observed",
        "client": {"name": "Codex CLI", "package": "@openai/codex", "version": "0.165.0",
            "isolatedCodexHome": True, "ephemeralTurn": True, "workspaceWritable": False,
            "repoRootDirectoryAvailable": True},
        "model": {"providerId": "oid_local_fixture", "model": "fixture-model",
            "providerClass": "deterministic_local_responses_fixture", "providerAuthConfigured": False,
            "externalModelCalls": 0, "llmBenchmarkInvocation": False},
        "mcp": {"configured": True, "serverId": "owner_agent", "allowlistedTools": ["runs.accept_launch_intent"],
            "approvalMode": "approve", "nativeApprovalPromptCount": 0, "ownerMcpServerUsed": True,
            "toolCallCount": 1, "acceptanceCallAttemptCount": 1, "ownerActionAttemptCount": 1,
            "confirmedAcceptanceResultCount": 1, "toolResult": {"toolName": "runs.accept_launch_intent",
                "operationId": OPERATION_ID, "runId": RUN_ID, "status": "queued",
                "argumentsSha256": argument_hash, "isError": False}},
        "turn": {"exitCode": 0, "completed": True, "eventTypes": ["item.completed", "turn.completed"],
            "terminalTurnEventSeen": True, "terminalEventKeys": ["type", "turn_id"], "expectedMessageSeen": True,
            "mcpToolEventCount": 1, "mcpToolNames": ["runs_accept_launch_intent"], "mcpTools": [event]},
        "responsesFixture": {"schemaVersion": "brl-codex-responses-fixture/v1",
            "transport": "local_http_responses_sse_or_json", "baseUrlOrigin": "http://127.0.0.1:43123",
            "model": "fixture-model", "requests": [{"method": "POST", "path": "/v1/responses",
                "model": "fixture-model", "requestSha256": "a" * 64, "authorizationHeaderPresent": False,
                "credentialLikeInputRejected": False}]},
        "handoff": {"ownerPageProvided": True, "nativeClient": "codex-cli",
            "manualCopyFallbackUsed": False, "clientApprovalPromptCount": 0},
        "executionBoundary": "docker_codex_cli_local_owner_mcp_single_allowlisted_acceptance"}


def _launch_capture_023():
    pending = _pending_snapshot()
    accepted = _accepted_snapshot()
    intent = {"id": INTENT_ID, "owner_id": OWNER_ID, "agent_id": AGENT_ID, "status": "pending",
        "run_id": None, "expires_at": "2026-10-28T09:15:00Z", "operation_id": "intent-create-op",
        "release_identity": "release-r1", "manifest_hash": "b" * 64, "quote_price_units": "1000000",
        "cash_ceiling_units": "0", "task_ids": ["S1"]}
    acceptance_record = {"operationId": OPERATION_ID, "clientBoundary": "codex_native_mcp_agent_case",
        "toolName": "runs.accept_launch_intent", "isError": False, "status": 200,
        "body": {"run": {"id": RUN_ID, "status": "queued"}},
        "clientModel": {"externalModelCalls": 0, "llmBenchmarkInvocation": False}}
    accepted["database"]["ledgerEntries"] = [{"operation_id": "runacc_22222222222242228222222222222222",
        "entry_type": "reserve", "amount_units": "1000000"}]
    accepted["database"]["events"] = [{"run_id": RUN_ID, "event_type": "run.accepted"}]
    accepted["database"]["outbox"] = [{"run_id": RUN_ID, "event_type": "run.accepted"}]
    accepted["database"]["tasks"] = [{"run_id": RUN_ID, "status": "queued", "started_at": None}]
    accepted["database"]["actions"] = []
    accepted["database"]["publicActionMarkers"] = []
    accepted["database"]["rankedBestResults"] = []
    return {"schemaVersion": "benchmark-run-lifecycle-runtime-evidence/v1", "scenarioId": "BRL-SC-023",
        "ownerId": OWNER_ID, "agentId": AGENT_ID, "database": {"observer": dict(_OBSERVER)},
        "cases": {"seed": {"intent": intent, "release": {"releaseIdentity": "release-r1", "manifestHash": "b" * 64}},
            "duplicateCreate": {"status": 200, "body": {"intent": {"id": INTENT_ID, "expiresAt": intent["expires_at"]}}},
            "preAcceptance": {"before": pending, "after": pending},
            "acceptance": {"before": pending, "after": accepted,
                "attempts": {"primaryMcp": acceptance_record}}}}


def _evidence():
    browser = {"pendingBeforeAcceptance": {"url": "http://127.0.0.1:3000/runs", "intentId": INTENT_ID,
            "statusText": "pending", "admissionCopy": "No run admitted and no funds or queue slot reserved",
            "databaseSnapshot": _pending_snapshot()},
        "acceptedAfterMcp": {"url": "http://127.0.0.1:3000/runs", "intentId": INTENT_ID,
            "statusText": "accepted and queued", "linkedRunId": RUN_ID,
            "databaseSnapshot": _accepted_snapshot()},
        "afterReload": {"url": "http://127.0.0.1:3000/runs", "intentId": INTENT_ID,
            "statusText": "accepted and queued", "linkedRunId": RUN_ID,
            "databaseSnapshot": _accepted_snapshot()}}
    return {"schemaVersion": "benchmark-run-lifecycle-codex-runtime-evidence/v1", "scenarioId": "BRL-SC-025",
        "status": "passed", "client": _codex_receipt(),
        "launchCaptures": {"BRL-SC-023": _launch_capture_023(), "BRL-SC-024": {
            "schemaVersion": "benchmark-run-lifecycle-runtime-evidence/v1", "scenarioId": "BRL-SC-024",
            "database": {"observer": dict(_OBSERVER)}, "cases": {}}},
        "observations": {"browser": browser, "browserWitness": {"classification": "safe_metadata_only"},
            "browserActionManifest": [{"label": "owner_run_intent_create", "operationId": "intent-create-op"}]}}


class BenchmarkRunLifecycleCodexVerifierTests(unittest.TestCase):
    def test_native_tool_event_is_hash_only_and_cross_bound_to_readonly_sql_and_ui(self):
        facts = derive_observations("BRL-SC-025", _evidence())
        self.assertIsNotNone(facts)
        self.assertTrue(facts["real_owner_ui_waiting_before_admission"])
        self.assertTrue(facts["linked_run_only_after_commit"])
        self.assertTrue(facts["reload_same_handoff_identity"])
        self.assertTrue(facts["native_selected_client_action_evidence"])
        self.assertTrue(facts["no_secret_in_link_or_prompt"])
        self.assertTrue(facts["no_hosted_model_invocation"])
        self.assertFalse(facts["fallback_setup_approvals_counted_separately"])
        self.assertNotIn("arguments", _codex_receipt()["turn"]["mcpTools"][0])

    def test_mismatched_codex_result_cannot_prove_sql_link_or_reload_identity(self):
        evidence = _evidence()
        evidence["client"]["turn"]["mcpTools"][0]["result"]["runId"] = "66666666-6666-4666-8666-666666666666"
        facts = derive_observations("BRL-SC-025", evidence)
        self.assertFalse(facts["linked_run_only_after_commit"])
        self.assertFalse(facts["reload_same_handoff_identity"])
        self.assertFalse(facts["native_selected_client_action_evidence"])

    def test_secret_in_browser_link_blocks_secret_free_claim(self):
        evidence = _evidence()
        evidence["observations"]["browser"]["acceptedAfterMcp"]["url"] += "?access_token=not-public"
        facts = derive_observations("BRL-SC-025", evidence)
        self.assertFalse(facts["no_secret_in_link_or_prompt"])

    def test_absent_adversarial_paths_and_raw_cli_arguments_remain_unproven(self):
        evidence = _evidence()
        evidence["client"]["turn"]["mcpTools"][0]["arguments"] = "{\"secret\":\"never-store\"}"
        facts = derive_observations("BRL-SC-025", evidence)
        self.assertFalse(facts["no_secret_in_link_or_prompt"])
        for key in ("fallback_setup_approvals_counted_separately", "client_never_responds", "copy_request_fallback",
            "extra_native_approval", "reload_back_double_click", "stale_review_required",
            "unsupported_client_without_short_path_claim"):
            self.assertFalse(facts[key], key)

    def test_tool_result_summary_without_a_native_event_is_not_an_action_receipt(self):
        evidence = _evidence()
        evidence["client"]["turn"]["mcpTools"] = []
        evidence["client"]["turn"]["mcpToolEventCount"] = 0
        facts = derive_observations("BRL-SC-025", evidence)
        self.assertFalse(facts["native_selected_client_action_evidence"])
        self.assertFalse(facts["linked_run_only_after_commit"])

    def test_rejects_wrong_envelope_identity(self):
        evidence = _evidence()
        self.assertIsNone(derive_observations("BRL-SC-024", evidence))
        evidence["scenarioId"] = "BRL-SC-024"
        self.assertIsNone(derive_observations("BRL-SC-025", evidence))


if __name__ == "__main__":
    unittest.main()
