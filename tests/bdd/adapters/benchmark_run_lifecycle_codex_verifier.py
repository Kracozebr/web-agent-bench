"""Independent BRL-025 derivation from the native Codex receipt and BRL-023/024 captures.

The adapter intentionally treats the producer's status and claimed observations as
untrusted. Positive facts must be reconstructed from a native Codex MCP event,
its arguments hash, the existing read-only BRL SQL verifier, and raw browser/DB
snapshots. Uncaptured fallback and negative paths remain false.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

try:
    from .benchmark_run_lifecycle_verifier import derive_observations as _derive_launch_observations
except ImportError:  # pragma: no cover - supports direct adapter import in local tooling
    from benchmark_run_lifecycle_verifier import derive_observations as _derive_launch_observations


SCENARIO_ID = "BRL-SC-025"
EVIDENCE_SCHEMA = "benchmark-run-lifecycle-codex-runtime-evidence/v1"
CODEX_RECEIPT_SCHEMA = "brl-codex-owner-mcp-observation/v1"
PINNED_CODEX_PACKAGE = "@openai/codex"
PINNED_CODEX_VERSION = "0.165.0"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)
_SECRET_TEXT = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+|"
    r"\b(?:aap1|oid1|oat1)_[A-Za-z0-9_-]{32,}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"\bsk-[A-Za-z0-9_-]{12,}\b",
    re.I,
)
_SECRET_KEYS = {
    "accesstoken", "authtoken", "bearer", "cookie", "cookies", "password", "secret",
    "clientsecret", "manualtoken", "tokenvalue", "authorization", "privatekey",
    "mnemonic", "seedphrase", "rawsignature", "signature", "walletmaterial",
    "databaseurl", "rpcurl", "oauthcode", "oauthstate",
}
_RAW_CLIENT_FIELDS = {"argv", "args", "arguments", "prompt", "rawprompt", "rawarguments"}

OBSERVATIONS = (
    "real_owner_ui_waiting_before_admission",
    "linked_run_only_after_commit",
    "reload_same_handoff_identity",
    "native_selected_client_action_evidence",
    "fallback_setup_approvals_counted_separately",
    "no_secret_in_link_or_prompt",
    "no_hosted_model_invocation",
)
NEGATIVES = (
    "client_never_responds",
    "copy_request_fallback",
    "extra_native_approval",
    "reload_back_double_click",
    "stale_review_required",
    "unsupported_client_without_short_path_claim",
)


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _rows(snapshot: Any, name: str) -> list[dict[str, Any]]:
    values = _object(_object(snapshot).get("database")).get(name)
    return [row for row in values if isinstance(row, dict)] if isinstance(values, list) else []


def _observer_ok(snapshot: Any) -> bool:
    observer = _object(_object(snapshot).get("observer"))
    return observer.get("role") == "oid_observer" and observer.get("transaction_read_only") == "on"


def _uuid(value: Any) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def _secret_free(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.I)
            if normalized in _SECRET_KEYS or not _secret_free(child):
                return False
        return True
    if isinstance(value, list):
        return all(_secret_free(item) for item in value)
    return not (isinstance(value, str) and _SECRET_TEXT.search(value))


def _client_has_no_raw_invocation(client: dict[str, Any]) -> bool:
    """Ensure sanitized CLI evidence never grows raw prompt/argv/argument fields."""
    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            if any(re.sub(r"[^a-z]", "", str(key), flags=re.I) in _RAW_CLIENT_FIELDS for key in value):
                return False
            return all(walk(child) for child in value.values())
        if isinstance(value, list):
            return all(walk(child) for child in value)
        return True
    return walk(client)


def _argument_hash(intent_id: str, operation_id: str) -> str:
    encoded = json.dumps({"intentId": intent_id, "operationId": operation_id}, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _tool_is_accept(name: Any) -> bool:
    if not isinstance(name, str):
        return False
    return name.lower().replace("_", ".").endswith("runs.accept.launch.intent")


def _native_event(client: dict[str, Any], intent_id: str, operation_id: str) -> dict[str, Any] | None:
    turn = _object(client.get("turn"))
    mcp = _object(client.get("mcp"))
    events = _list(turn.get("mcpTools"))
    if not (
        client.get("schemaVersion") == CODEX_RECEIPT_SCHEMA
        and turn.get("exitCode") == 0
        and turn.get("completed") is True
        and turn.get("terminalTurnEventSeen") is True
        and turn.get("expectedMessageSeen") is True
        and "turn.completed" in _list(turn.get("eventTypes"))
        and turn.get("mcpToolEventCount") == 1
        and len(events) == 1
        and mcp.get("configured") is True
        and mcp.get("serverId") == "owner_agent"
        and mcp.get("allowlistedTools") == ["runs.accept_launch_intent"]
        and mcp.get("ownerMcpServerUsed") is True
        and mcp.get("toolCallCount") == 1
        and mcp.get("acceptanceCallAttemptCount") == 1
        and mcp.get("ownerActionAttemptCount") == 1
        and mcp.get("confirmedAcceptanceResultCount") == 1
    ):
        return None
    event = _object(events[0])
    expected_hash = _argument_hash(intent_id, operation_id)
    event_result = _object(event.get("result"))
    client_result = _object(mcp.get("toolResult"))
    if not (
        event.get("event") == "item.completed"
        and _tool_is_accept(event.get("name"))
        and event.get("serverLabel") == "owner_agent"
        and event.get("status") == "completed"
        and event.get("isError") is False
        and event.get("argumentsSha256") == expected_hash
        and _uuid(event_result.get("runId"))
        and event_result.get("runId") == client_result.get("runId")
        and client_result.get("operationId") == operation_id
        and client_result.get("argumentsSha256") == expected_hash
        and client_result.get("isError") is False
    ):
        return None
    return event


def _capture_parts(capture: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = _object(capture)
    cases = _object(root.get("cases"))
    seed = _object(cases.get("seed"))
    acceptance = _object(cases.get("acceptance"))
    attempts = _object(acceptance.get("attempts"))
    primary = _object(attempts.get("primaryMcp"))
    return seed, acceptance, primary


def _pending_ui_state(snapshot: Any, intent_id: str) -> bool:
    if not _observer_ok(snapshot):
        return False
    intent = next((row for row in _rows(snapshot, "intents") if row.get("id") == intent_id), None)
    if not intent or intent.get("status") != "pending" or intent.get("run_id") is not None:
        return False
    return not any(_rows(snapshot, name) for name in ("runs", "reservations", "budgetHolds", "taskSlots", "slots"))


def _accepted_ui_state(snapshot: Any, intent_id: str, run_id: str) -> bool:
    if not _observer_ok(snapshot):
        return False
    intent = next((row for row in _rows(snapshot, "intents") if row.get("id") == intent_id), None)
    run = next((row for row in _rows(snapshot, "runs") if row.get("id") == run_id), None)
    return bool(intent and run and intent.get("status") == "accepted" and intent.get("run_id") == run_id
        and run.get("id") == run_id and run.get("intent_id") == intent_id)


def _browser_text_state(state: dict[str, Any], expected: str) -> bool:
    text = " ".join(value for value in (state.get("statusText"), state.get("admissionCopy")) if isinstance(value, str)).lower()
    if expected == "pending":
        return ("pending" in str(state.get("statusText", "")).lower()
            or "waiting" in str(state.get("statusText", "")).lower()) and "no run admitted" in text
    return expected in str(state.get("statusText", "")).lower() or (
        expected == "accepted" and "queued" in str(state.get("statusText", "")).lower())


def _loopback_origin(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith("http://127.0.0.1:") or value.startswith("http://localhost:")


def _local_fixture_no_hosted_model(client: dict[str, Any]) -> bool:
    model = _object(client.get("model"))
    fixture = _object(client.get("responsesFixture"))
    client_meta = _object(client.get("client"))
    turn = _object(client.get("turn"))
    requests = _list(fixture.get("requests"))
    return bool(
        client.get("schemaVersion") == CODEX_RECEIPT_SCHEMA
        and client_meta.get("package") == PINNED_CODEX_PACKAGE
        and client_meta.get("version") == PINNED_CODEX_VERSION
        and turn.get("completed") is True
        and model.get("providerClass") == "deterministic_local_responses_fixture"
        and model.get("providerAuthConfigured") is False
        and model.get("externalModelCalls") == 0
        and model.get("llmBenchmarkInvocation") is False
        and fixture.get("schemaVersion") == "brl-codex-responses-fixture/v1"
        and fixture.get("model") == "fixture-model"
        and _loopback_origin(fixture.get("baseUrlOrigin"))
        and len(requests) >= 1
        and all(isinstance(row, dict)
            and row.get("model") == fixture.get("model")
            and row.get("authorizationHeaderPresent") is False
            and row.get("credentialLikeInputRejected") is False
            and _SHA256.fullmatch(str(row.get("requestSha256", "")))
            for row in requests)
    )


def derive_observations(scenario_id: str, evidence: Any) -> dict[str, bool] | None:
    """Return BRL-SC-025 facts recomputed from the wrapper's raw child captures."""
    if scenario_id != SCENARIO_ID:
        return None
    if not isinstance(evidence, dict) or evidence.get("schemaVersion") != EVIDENCE_SCHEMA or evidence.get("scenarioId") != SCENARIO_ID:
        return None

    result = {key: False for key in (*OBSERVATIONS, *NEGATIVES)}
    client = _object(evidence.get("client"))
    observations = _object(evidence.get("observations"))
    browser = _object(observations.get("browser"))
    pending = _object(browser.get("pendingBeforeAcceptance"))
    accepted_ui = _object(browser.get("acceptedAfterMcp"))
    reloaded = _object(browser.get("afterReload"))
    captures = _object(evidence.get("launchCaptures"))
    capture023 = _object(captures.get("BRL-SC-023"))
    capture024 = _object(captures.get("BRL-SC-024"))

    sql023 = _derive_launch_observations("BRL-SC-023", capture023)
    sql024 = _derive_launch_observations("BRL-SC-024", capture024)
    seed, acceptance, primary_mcp = _capture_parts(capture023)
    intent = _object(seed.get("intent"))
    intent_id = intent.get("id")
    operation_id = primary_mcp.get("operationId")
    event = _native_event(client, intent_id, operation_id) if _uuid(intent_id) and isinstance(operation_id, str) else None
    run_id = _object(_object(event).get("result")).get("runId")
    after = _object(acceptance.get("after"))
    accepted_intent = next((row for row in _rows(after, "intents") if row.get("id") == intent_id), None)
    accepted_run_id = accepted_intent.get("run_id") if isinstance(accepted_intent, dict) else None
    accepted_run = next((row for row in _rows(after, "runs") if row.get("id") == accepted_run_id), None)
    sql_acceptance_ok = bool(
        isinstance(sql023, dict)
        and sql023.get("atomic_intent_run_reservation_link") is True
        and sql023.get("pending_no_run_hold_slot_or_timer") is True
        and primary_mcp.get("clientBoundary") == "codex_native_mcp_agent_case"
        and primary_mcp.get("toolName") == "runs.accept_launch_intent"
        and primary_mcp.get("isError") is False
        and primary_mcp.get("status") == 200
        and _object(_object(primary_mcp.get("body")).get("run")).get("id") == run_id
        and accepted_intent is not None
        and accepted_intent.get("status") == "accepted"
        and accepted_intent.get("run_id") == run_id
        and accepted_run is not None
        and accepted_run.get("intent_id") == intent_id
        and _observer_ok(after)
    )
    pending_db = _object(pending.get("databaseSnapshot"))
    accepted_db = _object(accepted_ui.get("databaseSnapshot"))
    reload_db = _object(reloaded.get("databaseSnapshot"))
    pending_ui_id = pending.get("intentId")
    accepted_ui_id = accepted_ui.get("intentId")
    reload_ui_id = reloaded.get("intentId")
    accepted_ui_run_id = accepted_ui.get("linkedRunId")
    reload_ui_run_id = reloaded.get("linkedRunId")
    waiting_ui = bool(
        _uuid(intent_id)
        and pending_ui_id == intent_id
        and _browser_text_state(pending, "pending")
        and _pending_ui_state(pending_db, intent_id)
        and isinstance(sql023, dict)
        and sql023.get("pending_no_run_hold_slot_or_timer") is True
    )
    linked_after_commit = bool(
        event is not None
        and sql_acceptance_ok
        and waiting_ui
        and accepted_ui_id == intent_id
        and accepted_ui_run_id == run_id
        and _browser_text_state(accepted_ui, "accepted")
        and _accepted_ui_state(accepted_db, intent_id, run_id)
    )
    reload_same = bool(
        linked_after_commit
        and reload_ui_id == intent_id
        and reload_ui_run_id == run_id
        and _browser_text_state(reloaded, "accepted")
        and _accepted_ui_state(reload_db, intent_id, run_id)
        and isinstance(accepted_ui.get("url"), str)
        and accepted_ui.get("url") == reloaded.get("url")
    )

    turn = _object(client.get("turn"))
    client_meta = _object(client.get("client"))
    handoff = _object(client.get("handoff"))
    native_action = bool(
        event is not None
        and client_meta.get("name") == "Codex CLI"
        and client_meta.get("package") == PINNED_CODEX_PACKAGE
        and client_meta.get("version") == PINNED_CODEX_VERSION
        and client_meta.get("isolatedCodexHome") is True
        and client_meta.get("ephemeralTurn") is True
        and client_meta.get("workspaceWritable") is False
        and handoff.get("nativeClient") == "codex-cli"
        and handoff.get("ownerPageProvided") is True
        and handoff.get("manualCopyFallbackUsed") is False
        and turn.get("mcpToolEventCount") == 1
        and operation_id == _object(_object(client.get("mcp")).get("toolResult")).get("operationId")
        and isinstance(sql023, dict)
        and sql023.get("atomic_intent_run_reservation_link") is True
    )

    result["real_owner_ui_waiting_before_admission"] = waiting_ui
    result["linked_run_only_after_commit"] = linked_after_commit
    result["reload_same_handoff_identity"] = reload_same
    result["native_selected_client_action_evidence"] = native_action
    # The current runner has no raw client-selection/copy action log, so separate
    # setup/fallback counts cannot be independently reconstructed yet.
    result["fallback_setup_approvals_counted_separately"] = False
    result["no_secret_in_link_or_prompt"] = _secret_free(evidence) and _client_has_no_raw_invocation(client)
    result["no_hosted_model_invocation"] = _local_fixture_no_hosted_model(client)

    # No raw evidence currently exercises these variants. In particular, do not
    # promote absent action records or producer self-assertions into passing negatives.
    del sql024
    return result
