"""Evidence consumer for the approved active AAP delta.

The browser runner owns mutations and writes immutable, secret-safe captures.
This adapter only verifies those artifacts and recomputes the partial card facts
from browser/API captures plus independent read-only PostgreSQL rows. A blocked
domain or client boundary remains blocked even when those setup facts exist.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest

from .registry import ScenarioContext, ScenarioRegistry


CHANGE_NAME = "agent-access-and-permissions"
SCENARIO_IDS = tuple(f"AAP-SC-{number:03d}" for number in range(1, 17))
PARTIAL_CARD_SCENARIOS = frozenset({"AAP-SC-001", "AAP-SC-006", "AAP-SC-014"})
PASSABLE_SCENARIOS = frozenset({"AAP-SC-002", "AAP-SC-003", "AAP-SC-004"})
SC002_OBSERVATIONS = (
    "consent_owner_agent_bound",
    "effective_scopes_displayed",
    "approved_grant_identity",
    "denied_consent_no_grant",
)
SC002_NEGATIVES = (
    "consent_denied",
    "foreign_card_selection",
    "scope_escalation_in_request",
    "agent_selection_changed_after_consent",
)
SC003_OBSERVATIONS = (
    "binding_validation",
    "code_consumed_once",
    "invalid_exchange_denied",
    "no_scope_escalation",
)
SC003_NEGATIVES = (
    "wrong_redirect",
    "wrong_resource_or_issuer",
    "wrong_pkce",
    "expired_or_replayed_code",
)
SC004_OBSERVATIONS = (
    "owner_issuance",
    "token_agent_binding",
    "header_authentication",
    "unauthorized_issuance_denied",
)
SC004_NEGATIVES = (
    "foreign_issuance",
    "agent_self_issuance",
    "token_for_other_agent",
    "forged_withdrawal_scope",
)
PASSABLE_FACTS = {
    "AAP-SC-002": (SC002_OBSERVATIONS, SC002_NEGATIVES),
    "AAP-SC-003": (SC003_OBSERVATIONS, SC003_NEGATIVES),
    "AAP-SC-004": (SC004_OBSERVATIONS, SC004_NEGATIVES),
}
ADAPTER_PROFILES = frozenset(
    {
        "agent_access_http_mcp_adapter",
        "agent_access_browser_mcp_adapter",
        "agent_actual_clients_adapter",
    }
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_ROOT = REPOSITORY_ROOT / "artifacts" / "runs" / "acceptance"
CONTRACT_PATH = (
    REPOSITORY_ROOT / "tests" / "bdd" / "changes" / CHANGE_NAME / "harness-contracts.json"
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARTIFACT_RE = re.compile(r"^[a-z][a-z0-9-]*\.json$")
SECRET_KEY_RE = re.compile(
    r"^(?:accesstoken|authtoken|bearer|cookie|cookies|password|"
    r"secret|clientsecret|manualtoken|tokenvalue|authorization|privatekey|"
    r"mnemonic|seedphrase|rawsignature|signature|walletmaterial|databaseurl|"
    r"oauthcode|oauthstate)$",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|"
    r"(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)"
    r"(?!<redacted>|\[redacted\])[^&#\s]+|\baap1_[A-Za-z0-9_-]{43}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    re.IGNORECASE,
)


def _assert_secret_free(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z]", "", str(key), flags=re.IGNORECASE)
            if SECRET_KEY_RE.fullmatch(normalized):
                raise AssertionError(f"credential-bearing evidence field at {path}.{key}")
            _assert_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _assert_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_TEXT_RE.search(value):
        raise AssertionError(f"unredacted credential-like text at {path}")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"AAP evidence object expected at {path.name}")
    _assert_secret_free(payload, path.name)
    return payload


def _load_run(scenario_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    scenario_root = EVIDENCE_ROOT / scenario_id
    index_path = scenario_root / "manifest.json"
    if not index_path.is_file():
        return None
    index = _read_json(index_path)
    if (
        index.get("schemaVersion") != "agent-access-evidence-index/v1"
        or index.get("scenarioId") != scenario_id
        or index.get("status") not in {"blocked", "passed"}
    ):
        raise AssertionError(f"{scenario_id} evidence index identity or schema is invalid")
    run_id = index.get("latestRunId")
    if not isinstance(run_id, str) or not UUID_RE.fullmatch(run_id):
        raise AssertionError(f"{scenario_id} evidence index has an invalid latest run ID")
    if not isinstance(index.get("runs"), list) or run_id not in index["runs"]:
        raise AssertionError(f"{scenario_id} evidence index does not inventory its latest run")
    run_root = (scenario_root / "runs" / run_id).resolve(strict=True)
    if scenario_root.resolve(strict=True) not in run_root.parents:
        raise AssertionError(f"{scenario_id} evidence run escapes its scenario directory")
    manifest = _read_json(run_root / "manifest.json")
    if (
        manifest.get("schemaVersion") != "agent-access-acceptance/v1"
        or manifest.get("scenarioId") != scenario_id
        or manifest.get("runId") != run_id
        or manifest.get("specProfile") != "active-delta"
        or manifest.get("status") not in {"blocked", "failed", "passed"}
        or index.get("status") != manifest.get("status")
    ):
        raise AssertionError(f"{scenario_id} run manifest identity or schema is invalid")

    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    contract_row = contract.get("protected_scenarios", {}).get(scenario_id)
    if not isinstance(contract_row, dict):
        raise AssertionError(f"{scenario_id} is missing from its active runtime contract")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise AssertionError(f"{scenario_id} run has no artifact inventory")
    if {item.get("path") for item in artifacts if isinstance(item, dict)} != {
        "browser.json",
        "database.json",
        "provenance.json",
    } or len(artifacts) != 3:
        raise AssertionError(f"{scenario_id} must inventory exactly its three safe artifacts")

    loaded: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        relative = item.get("path")
        digest = item.get("sha256")
        if not isinstance(relative, str) or not SAFE_ARTIFACT_RE.fullmatch(relative):
            raise AssertionError(f"{scenario_id} has an unsafe artifact path")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise AssertionError(f"{scenario_id} has an invalid artifact digest")
        if item.get("contentType") != "application/json" or not isinstance(item.get("boundary"), str):
            raise AssertionError(f"{scenario_id} artifact metadata is invalid")
        artifact_path = (run_root / relative).resolve(strict=True)
        if run_root not in artifact_path.parents:
            raise AssertionError(f"{scenario_id} artifact escapes its immutable run")
        content = artifact_path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise AssertionError(f"{scenario_id} artifact hash mismatch for {relative}")
        payload = json.loads(content.decode("utf-8"))
        if not isinstance(payload, dict):
            raise AssertionError(f"{scenario_id} artifact {relative} is not an object")
        _assert_secret_free(payload, relative)
        loaded[relative] = payload

    provenance = loaded["provenance.json"]
    if provenance.get("contractSha256") != hashlib.sha256(contract_bytes).hexdigest():
        raise AssertionError(f"{scenario_id} evidence was captured against another runtime contract")
    if manifest.get("status") == "passed" and (
        provenance.get("sourceStableDuringRun") is not True
        or not provenance.get("inputHashesBefore")
        or provenance.get("inputHashesBefore") != provenance.get("inputHashesAfter")
    ):
        raise AssertionError(f"{scenario_id} cannot pass with unstable or absent source provenance")
    database = loaded["database.json"]
    observer = database.get("observer")
    if not isinstance(observer, dict) or observer.get("role") != "oid_observer":
        raise AssertionError(f"{scenario_id} lacks independent oid_observer evidence")
    if observer.get("transaction_read_only") != "on":
        raise AssertionError(f"{scenario_id} observer transaction was not read-only")

    expected_observations = set(contract_row["required_observations"])
    expected_negatives = set(contract_row["negative_variants"])
    observations = manifest.get("observations")
    negatives = manifest.get("negativeVariants")
    if not isinstance(observations, dict) or set(observations) != expected_observations:
        raise AssertionError(f"{scenario_id} observation inventory drifted")
    if not isinstance(negatives, dict) or set(negatives) != expected_negatives:
        raise AssertionError(f"{scenario_id} negative-variant inventory drifted")
    if manifest.get("status") == "blocked":
        if not manifest.get("blockedReasonCode"):
            raise AssertionError(f"{scenario_id} blocked evidence needs a reason code")
        if manifest.get("observationStatus") != "not_run" or manifest.get("negativeVariantStatus") != "not_run":
            raise AssertionError(f"{scenario_id} blocked capture must retain not_run aggregate statuses")
        for collection in (observations, negatives):
            if any(
                not isinstance(item, dict)
                or item.get("status") != "not_run"
                or not isinstance(item.get("reasonCode"), str)
                or not item["reasonCode"]
                for item in collection.values()
            ):
                raise AssertionError(f"{scenario_id} blocked capture must keep every claim at not_run")
    return manifest, loaded


def _all_false(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    return all(row.get(key) is False for key in ("training", "ranked", "forum_messages", "custom_topics"))


def _derive_sc004_facts(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    """Recompute SC004's four observations and four negatives from browser and SQL facts."""

    browser = artifacts["browser.json"]
    database = artifacts["database.json"]
    owner_id = browser.get("ownerId")
    agent_id = browser.get("primaryAgentId")
    resource = browser.get("resource")
    preflight = browser.get("preflight", {})
    initial = browser.get("initialIssue", {})
    negatives = browser.get("directHttpNegatives", {})
    attempts = negatives.get("attempts", []) if isinstance(negatives, dict) else []
    attempt_by_variant = {
        row.get("variant"): row for row in attempts if isinstance(row, dict)
    }
    capture = browser.get("capture", {})
    actions = capture.get("actions", []) if isinstance(capture, dict) else []
    requests = capture.get("requests", []) if isinstance(capture, dict) else []
    responses = capture.get("responses", []) if isinstance(capture, dict) else []
    issuance_checkpoint = database.get("initialIssuanceCheckpoint", {})
    issuance_credentials = issuance_checkpoint.get("credentials", [])
    issuance_grants = issuance_checkpoint.get("grants", [])
    issuance_operations = issuance_checkpoint.get("operations", [])
    issuance_audits = issuance_checkpoint.get("audits", [])
    credential = next(
        (row for row in issuance_credentials if isinstance(row, dict) and row.get("id") == initial.get("credentialId")),
        None,
    )
    grant = next(
        (row for row in issuance_grants if isinstance(row, dict) and row.get("id") == initial.get("grantId")),
        None,
    )
    operation_id = initial.get("operationId")
    issue_path = f"/api/owner/agents/{agent_id}/manual-credential"
    clicked_issue = any(
        isinstance(row, dict) and row.get("action") == "click" and row.get("selector") == f"credential-issue-{agent_id}"
        for row in actions
    )
    issue_request = any(
        isinstance(row, dict) and row.get("method") == "POST" and row.get("path") == issue_path
        and row.get("operationId") == operation_id
        for row in requests
    )
    issue_response = any(
        isinstance(row, dict) and row.get("method") == "POST" and row.get("path") == issue_path and row.get("status") == 201
        for row in responses
    )
    initial_preflight = preflight.get("initial", {}) if isinstance(preflight, dict) else {}
    cookie_only = preflight.get("cookieOnly", {}) if isinstance(preflight, dict) else {}
    checkpoint = database.get("negativePersistenceCheckpoint", {})
    no_unauthorized_insert = (
        checkpoint.get("credentialsBefore") == checkpoint.get("credentialsAfter")
        and checkpoint.get("grantsBefore") == checkpoint.get("grantsAfter")
        and isinstance(checkpoint.get("credentialsBefore"), list)
        and isinstance(checkpoint.get("grantsBefore"), list)
    )
    verifier_safe = (
        isinstance(credential, dict) and credential.get("verifier_present") is True
        and issuance_checkpoint.get("noPlaintextCredentialColumn") is True
        and issuance_checkpoint.get("secretAbsentFromOperations") is True
        and issuance_checkpoint.get("secretAbsentFromAudit") is True
    )
    grant_bound = (
        isinstance(credential, dict) and isinstance(grant, dict)
        and credential.get("grant_id") == grant.get("id")
        and credential.get("owner_id") == owner_id and credential.get("agent_id") == agent_id
        and grant.get("owner_id") == owner_id and grant.get("agent_id") == agent_id
        and grant.get("source") == "manual" and grant.get("role") == "agent"
        and grant.get("resource") == resource and grant.get("status") == "active"
    )
    operation_recorded = any(
        isinstance(row, dict) and row.get("operationId") == operation_id
        and row.get("action") == "agent.manual_credential.issue" and row.get("responseHasSecret") is False
        for row in issuance_operations
    )
    audit_recorded = any(
        isinstance(row, dict) and row.get("operationId") == operation_id
        and row.get("eventType") == "agent.manual_credential.issued"
        and row.get("actorOwnerId") == owner_id and row.get("subjectOwnerId") == owner_id
        and row.get("metadataHasSecret") is False
        for row in issuance_audits
    )

    foreign = attempt_by_variant.get("foreign_issuance", {})
    self_issue = attempt_by_variant.get("agent_self_issuance", {})
    other_agent = attempt_by_variant.get("token_for_other_agent", {})
    forged_scope = attempt_by_variant.get("forged_withdrawal_scope", {})
    foreign_isolation = (
        foreign.get("method") == "POST" and foreign.get("path") == issue_path
        and foreign.get("status") == 404 and foreign.get("actorOwnerId") != owner_id
        and negatives.get("foreignOwnerId") == foreign.get("actorOwnerId")
    )
    self_issue_denied = (
        self_issue.get("method") == "POST" and self_issue.get("path") == issue_path
        and self_issue.get("status") == 401 and self_issue.get("actorAgentId") == agent_id
    )
    other_agent_denied = (
        other_agent.get("method") == "GET" and other_agent.get("path") == "/api/agent/preflight"
        and other_agent.get("status") == 403 and other_agent.get("requestedAgentId") != agent_id
        and initial_preflight.get("agentId") == agent_id
    )
    forged_scope_denied = (
        forged_scope.get("method") == "PUT" and forged_scope.get("path") == f"/api/owner/agents/{agent_id}/permissions"
        and forged_scope.get("status") == 401 and forged_scope.get("attemptedScope") == "wallet.withdraw"
    )
    header_authenticated = (
        initial_preflight.get("status") == 200 and initial_preflight.get("allowed") is True
        and initial_preflight.get("agentId") == agent_id and initial_preflight.get("resource") == resource
        and initial_preflight.get("role") == "agent"
        and cookie_only.get("hasOwnerSessionCookie") is True and cookie_only.get("status") == 401
    )
    return {
        "owner_issuance": bool(clicked_issue and issue_request and issue_response and initial.get("oneTimeSecretDisplayed") is True
            and initial.get("oneTimeSecretDismissed") is True and initial.get("responseStatus") == 201
            and operation_recorded and audit_recorded and verifier_safe),
        "token_agent_binding": bool(grant_bound and initial_preflight.get("agentId") == agent_id
            and initial_preflight.get("resource") == resource and initial_preflight.get("role") == "agent"),
        "header_authentication": bool(header_authenticated and verifier_safe),
        "unauthorized_issuance_denied": bool(foreign_isolation and self_issue_denied and no_unauthorized_insert),
        "foreign_issuance": bool(foreign_isolation and no_unauthorized_insert),
        "agent_self_issuance": bool(self_issue_denied and no_unauthorized_insert),
        "token_for_other_agent": bool(other_agent_denied),
        "forged_withdrawal_scope": bool(forged_scope_denied),
    }


def _derive_credential_partial_facts(scenario_id: str, browser: dict[str, Any], database: dict[str, Any]) -> dict[str, bool]:
    """Derive credential lifecycle observations without closing unavailable full gates."""

    if scenario_id == "AAP-SC-004":
        return _derive_sc004_facts({"browser.json": browser, "database.json": database})
    credential_browser = browser["credentials"] if isinstance(browser.get("credentials"), dict) else browser
    credential_database = database["credentials"] if isinstance(database.get("credentials"), dict) else database
    if not isinstance(credential_browser, dict) or not isinstance(credential_database, dict):
        return {}
    lost = credential_browser.get("lostResponse", {})
    revoke = credential_browser.get("globalRevoke", {})
    expiry = credential_browser.get("expiry", {})
    credentials = credential_database.get("credentials", [])
    grants = credential_database.get("grants", [])
    primary_id = credential_browser.get("primaryAgentId")
    primary_credentials = [row for row in credentials if isinstance(row, dict) and row.get("agent_id") == primary_id]
    old = next((row for row in primary_credentials if row.get("id") == lost.get("predecessorCredentialId")), None)
    facts: dict[str, bool] = {}
    if scenario_id in {"AAP-SC-005", "AAP-SC-014"}:
        facts.update({
            "issuance_response_lost_after_commit": lost.get("committed") is True and lost.get("upstreamCommitStatus") in {200, 201}
                and lost.get("browserSawResponse") is False,
            "safe_status_recovered": lost.get("safeStatusRecovered") is True and bool(lost.get("activeCredentialId")),
            "explicit_replacement_committed": lost.get("explicitReplacementStatus") == 200
                and lost.get("explicitReplacementHeaderPreflightStatus") == 200,
            "predecessor_fenced": isinstance(old, dict) and old.get("status") == "replaced"
                and lost.get("predecessorDeniedStatus") == 401,
            "verifier_only_storage": credential_database.get("noPlaintextCredentialColumn") is True
                and credential_database.get("secretAbsentFromOperations") is True
                and credential_database.get("secretAbsentFromAudit") is True
                and all(row.get("verifier_present") is True for row in primary_credentials),
        })
    if scenario_id == "AAP-SC-007":
        preflight = credential_browser.get("preflight", {})
        facts.update({
            "existing_token_observes_current_policy": preflight.get("policyAppliedWithoutReplacement") is True
                and preflight.get("sameTokenAfterPolicy", {}).get("status") == 200,
            "fixed_credential_resource_role": all(row.get("resource") == credential_browser.get("resource") and row.get("role") == "agent"
                for row in primary_credentials),
        })
    if scenario_id in {"AAP-SC-009", "AAP-SC-014"}:
        negatives = credential_browser.get("directHttpNegatives", {})
        attempts = {row.get("variant"): row for row in negatives.get("attempts", []) if isinstance(row, dict)}
        facts["agent_owner_management_denied"] = attempts.get("agent_self_issuance", {}).get("status") == 401
        facts["forged_withdrawal_scope_denied"] = attempts.get("forged_withdrawal_scope", {}).get("status") == 401
    if scenario_id in {"AAP-SC-010", "AAP-SC-014"}:
        outbox = next((row for row in credential_database.get("outbox", []) if isinstance(row, dict) and row.get("agent_id") == primary_id), None)
        final_agent = next((row for row in credential_database.get("agents", []) if isinstance(row, dict) and row.get("id") == primary_id), None)
        facts.update({
            "credential_fence_survives_restart": revoke.get("oldTokenDeniedAfterRestart") is True
                and isinstance(final_agent, dict) and final_agent.get("access_revoked_at") is not None,
            "other_agent_unaffected": revoke.get("otherAgentStillWorksAfterRestart") is True,
            "pending_outbox_observed": isinstance(outbox, dict) and outbox.get("status") == "pending"
                and outbox.get("event_type") == "agent.access.revoked" and outbox.get("scope") == "all",
            "coordinator_delivery_observed": False,
            "cancelled_runs_observed": False,
        })
    if scenario_id in {"AAP-SC-011", "AAP-SC-014"}:
        expired = expiry.get("fixture", {})
        expired_row = next((row for row in credentials if isinstance(row, dict) and row.get("id") == expired.get("credentialId")), None)
        facts.update({
            "expiry_fixture_isolated_and_labelled": expired.get("method") == "dedicated acceptance DB expiry fixture"
                and expired.get("updatedRows") == 1,
            "expired_credential_denied": expiry.get("preflightStatus") == 401
                and isinstance(expired_row, dict) and expired_row.get("status") == "expired",
            "run_deadline_preservation_observed": False,
        })
    return facts


def _token_exchange_rejected(attempt: Any) -> bool:
    if not isinstance(attempt, dict) or attempt.get("result") not in {"rejected", "state_mismatch"}:
        return False
    if attempt.get("tokenPresent") is True:
        return False
    requests = attempt.get("tokenRequests", [])
    if attempt.get("result") == "state_mismatch":
        return attempt.get("tokenRequests") == []
    return bool(requests) and all(
        isinstance(row, dict) and row.get("status") in {400, 401, 403} and row.get("accessTokenPresent") is False
        for row in requests
    )


def _derive_oauth_facts(artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    """Recompute OAuth consent/exchange facts from safe browser and observer rows."""

    browser = artifacts["browser.json"]
    database = artifacts["database.json"]
    owner_id = browser.get("ownerId")
    agent_id = browser.get("agentId")
    client_id = browser.get("clientId")
    resource = browser.get("resource")
    approved = browser.get("consentAndExchange", {})
    denied = browser.get("deniedConsent", {})
    challenge = browser.get("mcpAuthorizationChallenge", {})
    approved_consent = approved.get("consent", {}) if isinstance(approved, dict) else {}
    approved_sdk = approved.get("sdkAuthorization", {}) if isinstance(approved, dict) else {}
    approved_request = approved_sdk.get("request", {}) if isinstance(approved_sdk, dict) else {}
    approved_discovery = approved_sdk.get("discovery", {}) if isinstance(approved_sdk, dict) else {}
    issuer_binding = approved_sdk.get("issuerBinding", {}) if isinstance(approved_sdk, dict) else {}
    approved_callback = approved.get("callback", {}) if isinstance(approved, dict) else {}
    approved_exchange = approved.get("exchange", {}) if isinstance(approved, dict) else {}
    denied_consent = denied.get("consent", {}) if isinstance(denied, dict) else {}
    denied_callback = denied.get("callback", {}) if isinstance(denied, dict) else {}
    before = database.get("beforeRevoke", {}) if isinstance(database, dict) else {}
    after = database.get("afterRevoke", {}) if isinstance(database, dict) else {}
    authorizations = before.get("authorizations", []) if isinstance(before, dict) else []
    grants = before.get("grants", []) if isinstance(before, dict) else []
    provider_access = before.get("providerAccess", []) if isinstance(before, dict) else []
    authorization_codes = before.get("authorizationCodes", []) if isinstance(before, dict) else []
    authorizations_by_operation = before.get("authorizationsByOperation", []) if isinstance(before, dict) else []
    exchange_audits = before.get("exchangeAudits", []) if isinstance(before, dict) else []
    approved_flow_id = approved_consent.get("flowId") if isinstance(approved_consent, dict) else None
    denied_flow_id = denied_consent.get("flowId") if isinstance(denied_consent, dict) else None
    approved_flow = next((row for row in authorizations if isinstance(row, dict) and row.get("id") == approved_flow_id), None)
    denied_flow = next((row for row in authorizations if isinstance(row, dict) and row.get("id") == denied_flow_id), None)
    approved_grant = next((row for row in grants if isinstance(row, dict) and approved_flow and row.get("id") == approved_flow.get("grant_id")), None)
    denied_grant = next((row for row in grants if isinstance(row, dict) and denied_flow and row.get("id") == denied_flow.get("grant_id")), None)
    approved_code_row = next((row for row in authorization_codes if isinstance(row, dict)
        and row.get("authorization_id") == approved_flow_id), None)
    expected_scope = approved.get("scope") == "agent:operate" if isinstance(approved, dict) else False
    request_bound = bool(
        approved_request.get("clientIdMatches") is True
        and approved_request.get("redirectUriMatches") is True
        and approved_request.get("responseTypeCode") is True
        and approved_request.get("codeChallengePresent") is True
        and approved_request.get("codeChallengeMethodS256") is True
        and approved_request.get("statePresent") is True
        and approved_request.get("resourceMatches") is True
        and approved_request.get("expectedScopeRequested") is True
        and approved_request.get("extraScopeRequested") is False
        and approved_request.get("requestedScopeCount") == 1
    )
    challenged_discovery_bound = bool(
        challenge.get("method") == "unauthenticated MCP initialize POST"
        and challenge.get("status") == 401
        and challenge.get("challengePresent") is True
        and challenge.get("resourceMetadataPath") == "/.well-known/oauth-protected-resource/api/agent"
        and challenge.get("resourceMetadataOriginMatches") is True
        and challenge.get("expectedResource") == resource
        and approved_discovery.get("resourceMetadataPathMatchesChallenge") is True
        and approved_discovery.get("resourceMatchesPinned") is True
        and approved_discovery.get("issuerLoopback") is True
        and issuer_binding.get("clientInformationIssuerBound") is True
        and issuer_binding.get("tokenIssuerBound") is True
    )
    expected_permission_values = {"training": False, "ranked": False, "forumMessages": False, "customTopics": False}
    permission_display = approved_consent.get("permissionValues") == expected_permission_values
    approved_binding = bool(
        approved_consent.get("consentPageLoaded") is True
        and approved_consent.get("selectedAgentMatches") is True
        and approved_consent.get("decision") == "approve"
        and approved_consent.get("decisionStatus") == 200
        and approved_consent.get("submittedFlowMatchesContext") is True
        and approved_consent.get("consentAgentId") == agent_id
        and approved_consent.get("displayed", {}).get("clientId") is True
        and approved_consent.get("displayed", {}).get("resource") is True
        and approved_consent.get("displayed", {}).get("role") is True
        and approved_consent.get("displayed", {}).get("scope") is True
        and approved_consent.get("displayed", {}).get("agent") is True
        and approved_consent.get("displayed", {}).get("permissions") is True
        and approved_consent.get("displayed", {}).get("policyRevision") is True
        and approved_flow is not None
        and approved_flow.get("owner_id") == owner_id
        and approved_flow.get("agent_id") == agent_id
        and approved_flow.get("client_id") == client_id
        and approved_flow.get("resource") == resource
        and approved_flow.get("redirect_uri") == "http://127.0.0.1:38765/oauth/callback"
        and approved_flow.get("scopes") == ["agent:operate"]
        and approved_flow.get("status") == "approved"
    )
    grant_bound = bool(
        approved_grant is not None
        and approved_grant.get("owner_id") == owner_id
        and approved_grant.get("agent_id") == agent_id
        and approved_grant.get("source") == "oauth"
        and approved_grant.get("oauth_client_id") == client_id
        and approved_grant.get("resource") == resource
        and approved_grant.get("role") == "agent"
        and approved_grant.get("access_generation") == approved_flow.get("access_generation")
        and approved_grant.get("revoked_at") is None
    ) if approved_flow else False
    denied_is_safe = bool(
        denied_consent.get("decision") == "deny"
        and denied_consent.get("decisionStatus") == 200
        and denied_callback.get("errorPresent") is True
        and denied_callback.get("codePresent") is False
        and denied_callback.get("stateMatches") is True
        and denied_flow is not None
        and denied_flow.get("owner_id") == owner_id
        and denied_flow.get("agent_id") == agent_id
        and denied_flow.get("client_id") == client_id
        and denied_flow.get("resource") == resource
        and denied_flow.get("status") == "denied"
        and denied_grant is None
    )
    token_requests = approved_exchange.get("tokenRequests", []) if isinstance(approved_exchange, dict) else []
    token_request = token_requests[0] if token_requests and isinstance(token_requests[0], dict) else {}
    provider_access_bound = any(
        isinstance(row, dict)
        and approved_flow is not None
        and row.get("reference_id") == approved_flow.get("grant_id")
        and row.get("client_id") == client_id
        and row.get("resources") == [resource]
        and row.get("scopes") == ["agent:operate"]
        for row in provider_access
    )
    exchange_audit_bound = any(
        isinstance(row, dict)
        and row.get("event_type") == "agent.oauth.code_exchanged"
        and row.get("actor_owner_id") == owner_id
        and row.get("subject_owner_id") == owner_id
        and row.get("agent_id") == agent_id
        and approved_flow is not None
        and row.get("grant_id") == approved_flow.get("grant_id")
        and row.get("client_id") == client_id
        and row.get("resource") == resource
        and row.get("authorization_id") == approved_flow.get("id")
        for row in exchange_audits
    )
    successful_binding = bool(
        request_bound
        and challenged_discovery_bound
        and approved_callback.get("stateMatches") is True
        and approved_callback.get("issuerMatches") is True
        and approved_callback.get("codePresent") is True
        and approved_exchange.get("tokenEndpointStatus") == 200
        and approved_exchange.get("tokenPresent") is True
        and token_request.get("clientIdMatches") is True
        and token_request.get("redirectUriMatches") is True
        and token_request.get("resourceMatches") is True
        and token_request.get("pkceVerifierPresent") is True
        and token_request.get("status") == 200
        and token_request.get("accessTokenPresent") is True
        and expected_scope
        and approved_flow is not None
        and approved_flow.get("scopes") == ["agent:operate"]
    )
    exchange_negatives = browser.get("exchangeNegatives", {}) if isinstance(browser, dict) else {}
    wrong_redirect = exchange_negatives.get("wrongRedirect", {}) if isinstance(exchange_negatives, dict) else {}
    wrong_resource = exchange_negatives.get("wrongResource", {}) if isinstance(exchange_negatives, dict) else {}
    wrong_pkce = exchange_negatives.get("wrongPkce", {}) if isinstance(exchange_negatives, dict) else {}
    wrong_issuer = exchange_negatives.get("wrongIssuer", {}) if isinstance(exchange_negatives, dict) else {}
    wrong_issuer_rejected = bool(
        isinstance(wrong_issuer, dict)
        and wrong_issuer.get("result") == "rejected"
        and wrong_issuer.get("issuerMismatch") is True
        and wrong_issuer.get("errorName") == "IssuerMismatchError"
        and wrong_issuer.get("tokenPresent") is False
        and wrong_issuer.get("tokenEndpointStatus") is None
        and wrong_issuer.get("tokenRequests") == []
    )
    replay = browser.get("codeReplay", {}) if isinstance(browser, dict) else {}
    expiry = browser.get("codeExpiry", {}) if isinstance(browser, dict) else {}
    expiry_fixture = expiry.get("fixture", {}) if isinstance(expiry, dict) else {}
    expiry_attempt = expiry.get("exchange", {}) if isinstance(expiry, dict) else {}
    expiry_flow = expiry.get("flow", {}) if isinstance(expiry, dict) else {}
    expiry_flow_id = expiry_flow.get("consent", {}).get("flowId") if isinstance(expiry_flow, dict) else None
    expiry_row = next((row for row in authorization_codes if isinstance(row, dict)
        and row.get("authorization_id") == expiry_flow_id), None)

    foreign_selection = browser.get("foreignSelection", {}) if isinstance(browser, dict) else {}
    foreign_consent = foreign_selection.get("consent", {}) if isinstance(foreign_selection, dict) else {}
    foreign_selection_operation = foreign_consent.get("continueOperationId")
    foreign_owner_id = browser.get("foreignOwnerId") if isinstance(browser, dict) else None
    foreign_agent_id = browser.get("foreignAgentId") if isinstance(browser, dict) else None
    foreign_selection_authorization = next((row for row in authorizations_by_operation if isinstance(row, dict)
        and row.get("operation_id") == foreign_selection_operation), None)
    scope_flow = browser.get("scopeEscalation", {}) if isinstance(browser, dict) else {}
    scope_request = scope_flow.get("sdkAuthorization", {}).get("request", {}) if isinstance(scope_flow, dict) else {}
    scope_consent = scope_flow.get("consent", {}) if isinstance(scope_flow, dict) else {}
    scope_callback = scope_flow.get("callback", {}) if isinstance(scope_flow, dict) else {}
    scope_operation = scope_consent.get("continueOperationId")
    scope_authorization = next((row for row in authorizations_by_operation if isinstance(row, dict)
        and row.get("operation_id") == scope_operation), None)
    agent_change = browser.get("agentSelectionChange", {}) if isinstance(browser, dict) else {}
    agent_change_consent = agent_change.get("consent", {}) if isinstance(agent_change, dict) else {}
    agent_change_flow_id = agent_change_consent.get("flowId")
    agent_change_flow = next((row for row in authorizations if isinstance(row, dict)
        and row.get("id") == agent_change_flow_id), None)
    agent_change_grant = next((row for row in grants if isinstance(row, dict) and agent_change_flow
        and row.get("id") == agent_change_flow.get("grant_id")), None)
    substitution = browser.get("selectionSubstitution", {}) if isinstance(browser, dict) else {}
    substitution_consent = substitution.get("consent", {}) if isinstance(substitution, dict) else {}
    substitution_flow_id = substitution_consent.get("flowId")
    substitution_flow = next((row for row in authorizations if isinstance(row, dict)
        and row.get("id") == substitution_flow_id), None)
    substitution_grant = next((row for row in grants if isinstance(row, dict) and substitution_flow
        and row.get("id") == substitution_flow.get("grant_id")), None)
    foreign_grants = [row for row in grants if isinstance(row, dict) and row.get("agent_id") == foreign_agent_id]
    foreign_selection_safe = bool(
        foreign_consent.get("foreignAgentOptionAbsent") is True
        and foreign_consent.get("attemptedForeignAgent") is True
        and foreign_consent.get("continueStatus") == 404
        and foreign_selection_authorization is None
        and not foreign_grants
    )
    scope_escalation_safe = bool(
        scope_request.get("expectedScopeRequested") is True
        and scope_request.get("extraScopeRequested") is True
        and scope_request.get("requestedScopeCount", 0) > 1
        and (scope_consent.get("continueStatus") == 400
            or (scope_consent.get("providerRejectedBeforeSelection") is True
                and scope_callback.get("errorPresent") is True
                and scope_callback.get("codePresent") is False
                and scope_callback.get("stateMatches") is True
                and scope_callback.get("issuerMatches") is True
                and scope_callback.get("errorCode") == "invalid_scope"))
        and scope_authorization is None
    )
    agent_selection_change_safe = bool(
        agent_change_consent.get("attemptedAgentIdChange") is True
        and agent_change_consent.get("decisionStatus") == 400
        and agent_change_flow is not None
        and agent_change_flow.get("owner_id") == owner_id
        and agent_change_flow.get("agent_id") == agent_id
        and agent_change_flow.get("status") == "selected"
        and agent_change_grant is None
    )
    selection_substitution_safe = bool(
        substitution_consent.get("consentPageLoaded") is True
        and substitution_consent.get("consentAgentId") == foreign_agent_id
        and substitution_consent.get("decisionStatus") == 403
        and substitution_consent.get("submittedFlowMatchesContext") is False
        and substitution_flow is not None
        and substitution_flow.get("owner_id") == foreign_owner_id
        and substitution_flow.get("agent_id") == foreign_agent_id
        and substitution_flow.get("status") == "selected"
        and substitution_grant is None
    )
    expiry_fixture_observed = bool(
        expiry_fixture.get("method") == "dedicated acceptance DB expiry fixture"
        and expiry_fixture.get("flowBound") is True
        and expiry_fixture.get("updatedRows") == 1
        and expiry_fixture.get("expiryApplied") is True
        and isinstance(expiry_row, dict)
        and expiry_row.get("provider_verification_present") is True
        and expiry_row.get("provider_verification_expired") is True
        and _token_exchange_rejected(expiry_attempt)
    )

    facts = {
        "consent_owner_agent_bound": approved_binding and grant_bound,
        "effective_scopes_displayed": bool(approved_binding and permission_display and expected_scope
            and approved_flow is not None and approved_flow.get("policy_revision") == approved_consent.get("consentPolicyRevision")),
        "approved_grant_identity": grant_bound,
        "denied_consent_no_grant": denied_is_safe,
        "consent_denied": denied_is_safe,
        "foreign_card_selection": foreign_selection_safe,
        "scope_escalation_in_request": scope_escalation_safe,
        "binding_validation": successful_binding and grant_bound,
        "code_consumed_once": False,
        "invalid_exchange_denied": False,
        "no_scope_escalation": bool(successful_binding and expected_scope and not approved_request.get("extraScopeRequested")),
        "wrong_redirect": _token_exchange_rejected(wrong_redirect),
        "wrong_resource_or_issuer": _token_exchange_rejected(wrong_resource) and wrong_issuer_rejected,
        "wrong_issuer_rejected_before_token_request": wrong_issuer_rejected,
        "wrong_pkce": _token_exchange_rejected(wrong_pkce),
        "expired_or_replayed_code": bool((_token_exchange_rejected(replay) and exchange_audit_bound) or expiry_fixture_observed),
        "exchange_audit_observed": exchange_audit_bound,
        "provider_access_record_observed": provider_access_bound,
        "approved_code_verification_consumed": bool(isinstance(approved_code_row, dict)
            and approved_code_row.get("provider_verification_present") is False),
        "cross_owner_flow_substitution": selection_substitution_safe,
        "agent_selection_changed_after_consent": agent_selection_change_safe,
    }
    invalid_attempts = [wrong_redirect, wrong_resource, wrong_pkce, expiry_attempt]
    facts["invalid_exchange_denied"] = bool(all(_token_exchange_rejected(row) for row in invalid_attempts)
        and wrong_issuer_rejected)
    facts["code_consumed_once"] = bool(_token_exchange_rejected(replay) and exchange_audit_bound
        and facts["approved_code_verification_consumed"])
    facts["no_scope_escalation"] = bool(facts["no_scope_escalation"] and scope_escalation_safe)

    mcp = browser.get("mcp", {}) if isinstance(browser, dict) else {}
    preflight = mcp.get("preflight", {}) if isinstance(mcp, dict) else {}
    protocol_ok = bool(
        mcp.get("protocolPinned") is True
        and mcp.get("protocolVersion") == "2026-07-28"
        and mcp.get("protocolEra") == "modern"
    ) if isinstance(mcp, dict) else False
    post_revoke = browser.get("postRevokeMcp", {}) if isinstance(browser, dict) else {}
    revoked_preflight = post_revoke.get("preflight", {}) if isinstance(post_revoke, dict) else {}
    denied_status = any(
        isinstance(row, dict) and row.get("status") in {401, 403}
        for row in post_revoke.get("requests", [])
    ) if isinstance(post_revoke, dict) else False
    final_grant = next((row for row in after.get("grants", []) if isinstance(row, dict)
        and approved_flow is not None and row.get("id") == approved_flow.get("grant_id")), None) if isinstance(after, dict) else None
    final_fence = next((row for row in after.get("agentFence", []) if isinstance(row, dict) and row.get("id") == agent_id), None) if isinstance(after, dict) else None
    revoke = browser.get("globalRevoke", {}) if isinstance(browser, dict) else {}
    local_label = browser.get("scopeLabel", "") if isinstance(browser, dict) else ""
    paired_manual = browser.get("pairedManualCredential", {}) if isinstance(browser, dict) else {}
    if not isinstance(paired_manual, dict):
        paired_manual = {}
    manual_mcp = paired_manual.get("mcpPreflight", {}) if isinstance(paired_manual, dict) else {}
    manual_preflight = manual_mcp.get("preflight", {}) if isinstance(manual_mcp, dict) else {}
    manual_rows = before.get("manualCredentials", []) if isinstance(before, dict) else []
    manual_row = next((row for row in manual_rows if isinstance(row, dict)
        and row.get("id") == paired_manual.get("credentialId")), None)
    manual_mcp_protocol_ok = bool(manual_mcp.get("protocolPinned") is True
        and manual_mcp.get("protocolVersion") == "2026-07-28"
        and manual_mcp.get("protocolEra") == "modern") if isinstance(manual_mcp, dict) else False
    oauth_mcp_allowed = bool(protocol_ok and preflight.get("status") == "allowed"
        and preflight.get("operationIdMatches") is True) if isinstance(preflight, dict) else False
    manual_mcp_allowed = bool(manual_mcp_protocol_ok and manual_preflight.get("status") == "allowed"
        and manual_preflight.get("operationIdMatches") is True) if isinstance(manual_preflight, dict) else False
    manual_identity_parity = bool(
        paired_manual.get("status") == 201
        and paired_manual.get("secretShownOnce") is True
        and paired_manual.get("secretDismissed") is True
        and paired_manual.get("secretAvailableAtIssue") is True
        and isinstance(manual_row, dict)
        and manual_row.get("grant_id") == paired_manual.get("grantId")
        and manual_row.get("owner_id") == owner_id
        and manual_row.get("agent_id") == agent_id
        and manual_row.get("source") == "manual"
        and manual_row.get("resource") == resource
        and manual_row.get("role") == "agent"
        and manual_row.get("grant_revoked_at") is None
        and approved_grant is not None
        and manual_row.get("access_generation") == approved_grant.get("access_generation")
        and manual_mcp_allowed and oauth_mcp_allowed
        and manual_preflight.get("policyVersion") == preflight.get("policyVersion")
        and manual_preflight.get("accessGeneration") == preflight.get("accessGeneration")
    )
    def mcp_denied(result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        preflight_result = result.get("preflight")
        if not isinstance(preflight_result, dict):
            preflight_result = {}
        return bool(preflight_result.get("status") == "denied"
            or any(isinstance(row, dict) and row.get("status") in {401, 403}
                for row in result.get("requests", [])))

    manual_post_revoke = browser.get("manualPostRevokeMcp", {}) if isinstance(browser, dict) else {}
    post_restart_oauth = browser.get("postRestartMcp", {}) if isinstance(browser, dict) else {}
    manual_post_restart = browser.get("manualPostRestartMcp", {}) if isinstance(browser, dict) else {}
    api_restart = browser.get("apiRestart", {}) if isinstance(browser, dict) else {}
    final_manual_row = next((row for row in after.get("manualCredentials", []) if isinstance(row, dict)
        and row.get("id") == paired_manual.get("credentialId")
        and row.get("grant_id") == paired_manual.get("grantId")), None) if isinstance(after, dict) else None
    durable_both_revoked = bool(
        revoke.get("accessStatus") == "revoked"
        and mcp_denied(post_revoke)
        and mcp_denied(manual_post_revoke)
        and api_restart.get("completed") is True
        and mcp_denied(post_restart_oauth)
        and mcp_denied(manual_post_restart)
        and isinstance(final_manual_row, dict)
        and final_manual_row.get("grant_revoked_at") is not None
        and final_grant is not None and final_grant.get("revoked_at") is not None
        and isinstance(final_fence, dict) and final_fence.get("access_revoked_at") is not None
    )
    facts.update({
        "discovery_and_browser_flow": bool(successful_binding and challenged_discovery_bound),
        "resource_bound_access": bool(grant_bound and approved_flow is not None and approved_flow.get("resource") == resource),
        "tool_catalog_and_preflight": bool(protocol_ok and mcp.get("toolListSucceeded") is True
            and "identity.preflight" in mcp.get("toolNames", []) and preflight.get("status") == "allowed"
            and preflight.get("operationIdMatches") is True and isinstance(preflight.get("policyVersion"), int)
            and isinstance(preflight.get("accessGeneration"), int)),
        "actual_operation_receipt": False,
        "revoked_call_denied": bool(revoke.get("accessStatus") == "revoked"
            and ((revoked_preflight.get("status") == "denied") or denied_status)
            and final_grant is not None and final_grant.get("revoked_at") is not None
            and isinstance(final_fence, dict) and final_fence.get("access_revoked_at") is not None),
        "local_scope_label": "local" in local_label.lower() and "not google" in local_label.lower()
            and "third-party-client" in local_label.lower(),
        "call_after_global_revoke": bool(revoke.get("accessStatus") == "revoked"
            and ((revoked_preflight.get("status") == "denied") or denied_status)
            and final_grant is not None and final_grant.get("revoked_at") is not None),
        "consent_denied_for_mcp_flow": denied_is_safe,
        # Supplemental identity-parity evidence; these do not expand SC002/SC003 gates.
        "manual_connection_identity_parity": manual_identity_parity,
        "oauth_and_manual_revocation_survives_restart": durable_both_revoked,
        "unsupported_profile": False,
        "expired_credential": False,
    })
    return facts


def _derive_partial_facts(scenario_id: str, artifacts: dict[str, dict[str, Any]]) -> dict[str, bool]:
    """Derive observed setup facts; never infer unsupported domain acceptance."""

    if scenario_id in {"AAP-SC-002", "AAP-SC-003", "AAP-SC-015"}:
        oauth_facts = _derive_oauth_facts(artifacts)
        if scenario_id in {"AAP-SC-002", "AAP-SC-003"}:
            return oauth_facts
        return {name: value for name, value in oauth_facts.items() if name in {
            "discovery_and_browser_flow", "resource_bound_access", "tool_catalog_and_preflight",
            "actual_operation_receipt", "revoked_call_denied", "local_scope_label",
            "call_after_global_revoke", "consent_denied_for_mcp_flow", "unsupported_profile", "expired_credential",
        }}
    if scenario_id == "AAP-SC-004":
        return _derive_credential_partial_facts(scenario_id, artifacts["browser.json"], artifacts["database.json"])
    if scenario_id not in PARTIAL_CARD_SCENARIOS:
        return _derive_credential_partial_facts(scenario_id, artifacts["browser.json"], artifacts["database.json"])
    browser = artifacts["browser.json"]
    database = artifacts["database.json"]
    capture = browser.get("capture")
    if not isinstance(capture, dict):
        return {"owner_card_persisted": False, "initial_policy_all_false": False, "policy_edit_committed": False}
    actions = capture.get("actions", [])
    requests = capture.get("requests", [])
    responses = capture.get("responses", [])
    operation_ids = browser.get("operationIds", [])
    final = database.get("final", {})
    initial = database.get("initial", {})
    if not all(isinstance(value, list) for value in (actions, requests, responses, operation_ids)):
        return {"owner_card_persisted": False, "initial_policy_all_false": False, "policy_edit_committed": False}
    agent_id = browser.get("agentId")
    owner_id = browser.get("ownerId")
    create_operation = operation_ids[0] if operation_ids else None
    policy_operation = operation_ids[2] if len(operation_ids) > 2 else None
    create_clicked = any(item.get("action") == "click" and item.get("selector") == "agent-create" for item in actions if isinstance(item, dict))
    create_requested = any(
        item.get("method") == "POST" and item.get("path") == "/api/owner/agents" and item.get("operationId") == create_operation
        for item in requests if isinstance(item, dict)
    )
    create_succeeded = any(
        item.get("method") == "POST" and item.get("path") == "/api/owner/agents" and item.get("status") == 201
        for item in responses if isinstance(item, dict)
    )
    final_agents = final.get("agents", []) if isinstance(final, dict) else []
    final_policies = final.get("policies", []) if isinstance(final, dict) else []
    final_operations = final.get("operations", []) if isinstance(final, dict) else []
    final_audits = final.get("audits", []) if isinstance(final, dict) else []
    initial_policies = initial.get("policies", []) if isinstance(initial, dict) else []
    agent = next((row for row in final_agents if isinstance(row, dict) and row.get("id") == agent_id and row.get("owner_id") == owner_id), None)
    create_operation_row = any(isinstance(row, dict) and row.get("operation_id") == create_operation and row.get("agent_id") == agent_id for row in final_operations)
    create_audit = any(
        isinstance(row, dict) and row.get("operation_id") == create_operation
        and row.get("event_type") == "agent.created" and row.get("actor_owner_id") == owner_id
        for row in final_audits
    )
    card_persisted = bool(create_clicked and create_requested and create_succeeded and agent and create_operation_row and create_audit)
    initial_defaults = bool(initial_policies and _all_false(initial_policies[0]))
    policy_clicked = any(item.get("action") == "click" and item.get("selector") == "agent-permissions-save" for item in actions if isinstance(item, dict))
    policy_requested = any(
        isinstance(item, dict) and item.get("operationId") == policy_operation
        and item.get("method") == "PUT" and item.get("path") == f"/api/owner/agents/{agent_id}/permissions"
        for item in requests
    )
    policy = next((row for row in final_policies if isinstance(row, dict) and row.get("agent_id") == agent_id), None)
    policy_operation_row = any(isinstance(row, dict) and row.get("operation_id") == policy_operation and row.get("agent_id") == agent_id for row in final_operations)
    policy_audit = any(
        isinstance(row, dict) and row.get("operation_id") == policy_operation
        and row.get("event_type") == "agent.permissions_updated" and row.get("actor_owner_id") == owner_id
        for row in final_audits
    )
    policy_committed = bool(policy_clicked and policy_requested and policy and policy_operation_row and policy_audit)
    created = browser.get("created", {})
    edited = browser.get("edited", {})
    policy_result = browser.get("policy", {})
    negatives = browser.get("protocolNegatives", {})
    metadata = agent.get("client_metadata") if isinstance(agent, dict) else None
    declared_metadata = bool(
        isinstance(created, dict)
        and created.get("metadataTrust") == "owner-declared-unverified"
        and isinstance(metadata, dict)
        and metadata.get("clientName")
        and metadata.get("modelName")
    )
    edited_persisted = bool(
        isinstance(edited, dict)
        and isinstance(agent, dict)
        and agent.get("revision") == edited.get("revision")
        and agent.get("declared_version") == edited.get("declaredVersion")
        and any(
            isinstance(row, dict) and row.get("operation_id") == (operation_ids[1] if len(operation_ids) > 1 else None)
            and row.get("event_type") == "agent.profile_updated" and row.get("actor_owner_id") == owner_id
            for row in final_audits
        )
    )
    policy_matches_response = bool(
        isinstance(policy_result, dict)
        and isinstance(policy, dict)
        and policy.get("policy_revision") == policy_result.get("policyRevision")
        and policy_result.get("permissions") == {
            "training": policy.get("training"),
            "ranked": policy.get("ranked"),
            "forumMessages": policy.get("forum_messages"),
            "customTopics": policy.get("custom_topics"),
        }
    )
    foreign_denials = bool(
        isinstance(negatives, dict)
        and negatives.get("foreignReadStatus") == 404
        and negatives.get("foreignEditStatus") == 404
        and edited_persisted
        and policy_matches_response
    )
    caller_visibility_denied = bool(
        isinstance(negatives, dict)
        and negatives.get("forgedPublicationStatus") == 400
        and edited_persisted
        and policy_matches_response
        and isinstance(agent, dict)
        and "is_public" not in agent
    )
    facts = {
        "owner_card_persisted": card_persisted,
        "declared_metadata_labelled": declared_metadata,
        "foreign_owner_denied": foreign_denials,
        "caller_visibility_change_cannot_publish": caller_visibility_denied,
        "profile_edit_correlated_to_postgres": edited_persisted,
        "initial_policy_all_false": initial_defaults,
        "policy_edit_committed": bool(policy_committed and policy_matches_response),
    }
    if scenario_id == "AAP-SC-014":
        facts.update(_derive_credential_partial_facts(scenario_id, browser, database))
    return facts


class AgentAccessEvidenceCase:
    def setup(self, context: ScenarioContext) -> None:
        context.state["aap_evidence_root"] = EVIDENCE_ROOT.as_posix()

    def execute(self, context: ScenarioContext, when_text: str) -> None:
        del when_text
        method = getattr(self, "_execute_" + context.scenario_id.replace("-", "_"), None)
        if not callable(method):
            raise AssertionError(f"no AAP executor for {context.scenario_id}")
        method(context)

    def _execute_evidence(self, context: ScenarioContext, scenario_id: str) -> None:
        loaded = _load_run(scenario_id)
        if loaded is None:
            pytest.skip(f"BLOCKED: no immutable AAP acceptance run exists for {scenario_id}")
        manifest, artifacts = loaded
        derived = _derive_partial_facts(scenario_id, artifacts)
        context.state["aap_manifest"] = manifest
        context.state["aap_artifacts"] = artifacts
        context.state["aap_partial_facts"] = derived
        context.state["aap_derived_observations"] = derived
        if manifest["status"] == "failed":
            raise AssertionError(f"{scenario_id} latest AAP browser/database run failed")
        if manifest["status"] == "passed":
            if scenario_id not in PASSABLE_SCENARIOS:
                raise AssertionError(f"{scenario_id} cannot pass through the available partial AAP evidence")
            required_observations, required_negatives = PASSABLE_FACTS[scenario_id]
            if any(derived.get(name) is not True for name in (*required_observations, *required_negatives)):
                raise AssertionError(f"{scenario_id} passed evidence does not derive every approved observation and negative from raw artifacts")
            observations = manifest.get("observations", {})
            negatives = manifest.get("negativeVariants", {})
            if any(observations.get(name, {}).get("status") != "observed" for name in required_observations):
                raise AssertionError(f"{scenario_id} passed manifest has an unobserved required observation")
            if any(negatives.get(name, {}).get("status") != "observed" for name in required_negatives):
                raise AssertionError(f"{scenario_id} passed manifest has an unobserved approved negative variant")
            return
        pytest.skip(f"BLOCKED: {scenario_id} remains {manifest['blockedReasonCode']}; card facts are partial only")

    def _execute_AAP_SC_001(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-001")

    def _execute_AAP_SC_002(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-002")

    def _execute_AAP_SC_003(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-003")

    def _execute_AAP_SC_004(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-004")

    def _execute_AAP_SC_005(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-005")

    def _execute_AAP_SC_006(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-006")

    def _execute_AAP_SC_007(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-007")

    def _execute_AAP_SC_008(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-008")

    def _execute_AAP_SC_009(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-009")

    def _execute_AAP_SC_010(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-010")

    def _execute_AAP_SC_011(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-011")

    def _execute_AAP_SC_012(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-012")

    def _execute_AAP_SC_013(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-013")

    def _execute_AAP_SC_014(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-014")

    def _execute_AAP_SC_015(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-015")

    def _execute_AAP_SC_016(self, context: ScenarioContext) -> None:
        self._execute_evidence(context, "AAP-SC-016")

    def verify(self, context: ScenarioContext, then_text: str) -> None:
        del then_text
        method = getattr(self, "_verify_" + context.scenario_id.replace("-", "_"), None)
        if not callable(method):
            raise AssertionError(f"no AAP verifier for {context.scenario_id}")
        method(context)

    def _verify_AAP_SC_001(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("owner_card_persisted", facts.get("owner_card_persisted") is True)
        context.check("foreign_owner_denied", facts.get("foreign_owner_denied") is True)
        context.check("agent_owner_mutation_denied", facts.get("agent_owner_mutation_denied") is True)
        context.check("declared_metadata_labelled", facts.get("declared_metadata_labelled") is True)
        context.check("run_snapshot_unchanged", facts.get("run_snapshot_unchanged") is True)
        context.check("new_card_no_public_marker", facts.get("new_card_no_public_marker") is True)
        context.check("caller_visibility_change_cannot_publish", facts.get("caller_visibility_change_cannot_publish") is True)

    def _verify_AAP_SC_002(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("consent_owner_agent_bound", facts.get("consent_owner_agent_bound") is True)
        context.check("effective_scopes_displayed", facts.get("effective_scopes_displayed") is True)
        context.check("approved_grant_identity", facts.get("approved_grant_identity") is True)
        context.check("denied_consent_no_grant", facts.get("denied_consent_no_grant") is True)

    def _verify_AAP_SC_003(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("binding_validation", facts.get("binding_validation") is True)
        context.check("code_consumed_once", facts.get("code_consumed_once") is True)
        context.check("invalid_exchange_denied", facts.get("invalid_exchange_denied") is True)
        context.check("no_scope_escalation", facts.get("no_scope_escalation") is True)

    def _verify_AAP_SC_004(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("owner_issuance", facts.get("owner_issuance") is True)
        context.check("token_agent_binding", facts.get("token_agent_binding") is True)
        context.check("header_authentication", facts.get("header_authentication") is True)
        context.check("unauthorized_issuance_denied", facts.get("unauthorized_issuance_denied") is True)
        if any(facts.get(name) is not True for name in SC004_NEGATIVES):
            raise AssertionError("AAP-SC-004 negative variants did not all derive from raw evidence")

    def _verify_AAP_SC_005(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("show_once_response", facts.get("show_once_response") is True)
        context.check("stored_verifier_not_plaintext", facts.get("stored_verifier_not_plaintext") is True)
        context.check("safe_replacement_identity", facts.get("safe_replacement_identity") is True)
        context.check("old_credential_denied", facts.get("old_credential_denied") is True)
        context.check("secret_absent_from_audit", facts.get("secret_absent_from_audit") is True)

    def _verify_AAP_SC_006(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("four_action_permissions_independent", facts.get("four_action_permissions_independent") is True)
        context.check("topic_first_post_included", facts.get("topic_first_post_included") is True)
        context.check("standalone_message_permission_checked", facts.get("standalone_message_permission_checked") is True)
        context.check("denied_actions_no_effect", facts.get("denied_actions_no_effect") is True)
        context.check("omitted_owner_selections_default_all_false", facts.get("omitted_owner_selections_default_all_false") is True)
        context.check("free_preflight_without_action_flags", facts.get("free_preflight_without_action_flags") is True)
        context.check("explicit_owner_selection_required", facts.get("explicit_owner_selection_required") is True)

    def _verify_AAP_SC_007(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("current_revision_loaded", facts.get("current_revision_loaded") is True)
        context.check("fixed_credential_identity_resource_role", facts.get("fixed_credential_identity_resource_role") is True)
        context.check("owner_increase_works_without_reconnect", facts.get("owner_increase_works_without_reconnect") is True)
        context.check("same_oauth_and_manual_credentials_used", facts.get("same_oauth_and_manual_credentials_used") is True)
        context.check("disabled_and_foreign_authority_denied", facts.get("disabled_and_foreign_authority_denied") is True)
        context.check("agent_cannot_change_permissions", facts.get("agent_cannot_change_permissions") is True)
        context.check("re_enable_does_not_reopen_cancelled_runs", facts.get("re_enable_does_not_reopen_cancelled_runs") is True)

    def _verify_AAP_SC_008(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("shared_owner_funds", facts.get("shared_owner_funds") is True)
        context.check("same_agent_utc_caps", facts.get("same_agent_utc_caps") is True)
        context.check("bonus_first_sources", facts.get("bonus_first_sources") is True)
        context.check("separate_cash_permission", facts.get("separate_cash_permission") is True)
        context.check("no_duplicate_or_partial_charge", facts.get("no_duplicate_or_partial_charge") is True)

    def _verify_AAP_SC_009(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("agent_withdrawal_denied", facts.get("agent_withdrawal_denied") is True)
        context.check("recovery_authority_denied", facts.get("recovery_authority_denied") is True)
        context.check("owner_controls_denied", facts.get("owner_controls_denied") is True)
        context.check("human_session_post_denied", facts.get("human_session_post_denied") is True)
        context.check("no_signing_intent", facts.get("no_signing_intent") is True)

    def _verify_AAP_SC_010(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("revocation_admission_fence", facts.get("revocation_admission_fence") is True)
        context.check("queue_release_once", facts.get("queue_release_once") is True)
        context.check("started_cancel_no_voluntary_refund", facts.get("started_cancel_no_voluntary_refund") is True)
        context.check("mode_scope_preserved", facts.get("mode_scope_preserved") is True)
        context.check("other_agents_unchanged", facts.get("other_agents_unchanged") is True)
        context.check("regrant_no_reopen", facts.get("regrant_no_reopen") is True)
        context.check("re_enable_mode_no_reopen", facts.get("re_enable_mode_no_reopen") is True)

    def _verify_AAP_SC_011(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("expiry_denies_calls", facts.get("expiry_denies_calls") is True)
        context.check("no_disconnect_revoke_event", facts.get("no_disconnect_revoke_event") is True)
        context.check("same_run_deadline", facts.get("same_run_deadline") is True)
        context.check("refresh_scope_preserved", facts.get("refresh_scope_preserved") is True)
        context.check("revoked_refresh_denied", facts.get("revoked_refresh_denied") is True)

    def _verify_AAP_SC_012(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("same_operation_across_transports", facts.get("same_operation_across_transports") is True)
        context.check("original_receipt_recovered", facts.get("original_receipt_recovered") is True)
        context.check("conflict_rejected", facts.get("conflict_rejected") is True)
        context.check("foreign_reuse_denied", facts.get("foreign_reuse_denied") is True)

    def _verify_AAP_SC_013(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("pinned_profile_validation", facts.get("pinned_profile_validation") is True)
        context.check("resource_token_rejection", facts.get("resource_token_rejection") is True)
        context.check("origin_policy", facts.get("origin_policy") is True)
        context.check("metadata_fetch_constrained", facts.get("metadata_fetch_constrained") is True)
        context.check("no_private_projection", facts.get("no_private_projection") is True)

    def _verify_AAP_SC_014(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("actual_owner_pages", facts.get("actual_owner_pages") is True)
        context.check("four_flags_and_separate_limits", facts.get("four_flags_and_separate_limits") is True)
        context.check("safe_token_display", facts.get("safe_token_display") is True)
        context.check("changes_affect_admission", facts.get("changes_affect_admission") is True)
        context.check("foreign_control_denied", facts.get("foreign_control_denied") is True)

    def _verify_AAP_SC_015(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("discovery_and_browser_flow", facts.get("discovery_and_browser_flow") is True)
        context.check("resource_bound_access", facts.get("resource_bound_access") is True)
        context.check("tool_catalog_and_preflight", facts.get("tool_catalog_and_preflight") is True)
        context.check("actual_operation_receipt", facts.get("actual_operation_receipt") is True)
        context.check("revoked_call_denied", facts.get("revoked_call_denied") is True)
        context.check("local_scope_label", facts.get("local_scope_label") is True)

    def _verify_AAP_SC_016(self, context: ScenarioContext) -> None:
        facts = context.state.get("aap_derived_observations", {})
        context.check("four_selected_editions_pinned", facts.get("four_selected_editions_pinned") is True)
        context.check("no_platform_connector_install", facts.get("no_platform_connector_install") is True)
        context.check("chosen_auth_route_recorded", facts.get("chosen_auth_route_recorded") is True)
        context.check("actual_preflight_and_operation", facts.get("actual_preflight_and_operation") is True)
        context.check("post_revoke_denial_per_client", facts.get("post_revoke_denial_per_client") is True)
        context.check("unsupported_alternatives_disclosed", facts.get("unsupported_alternatives_disclosed") is True)


def _profile_for(scenario_id: str) -> str:
    if scenario_id in {"AAP-SC-002", "AAP-SC-014", "AAP-SC-015"}:
        return "agent_access_browser_mcp_adapter"
    if scenario_id == "AAP-SC-016":
        return "agent_actual_clients_adapter"
    return "agent_access_http_mcp_adapter"


def register(registry: ScenarioRegistry) -> None:
    for scenario_id in SCENARIO_IDS:
        registry.register(scenario_id, AgentAccessEvidenceCase(), adapter_profile=_profile_for(scenario_id))
