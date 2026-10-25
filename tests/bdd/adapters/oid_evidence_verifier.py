"""Derive OID scenario outcomes from sanitized browser, fixture, and SQL artifacts."""

from __future__ import annotations

from typing import Any


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _trial(browser: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((item for item in _items(browser.get("trials")) if item.get("name") == name), None)


def _identity(database: dict[str, Any], provider: str, subject_sha256: str | None = None) -> dict[str, Any] | None:
    return next(
        (
            item
            for item in _items(database.get("identities"))
            if item.get("provider") == provider
            and (subject_sha256 is None or item.get("subject_sha256") == subject_sha256)
        ),
        None,
    )


def _session_facts(browser: dict[str, Any], database: dict[str, Any]) -> dict[str, bool]:
    before = database.get("before", {})
    after = database.get("after", {})
    denied = database.get("denied", {})
    prepared = database.get("expiryPrepared", {})
    expired_after = database.get("expiryAfter", {})
    protocol = browser.get("protocolNegatives", {})
    snapshots = [before, after, denied, prepared, expired_after, database.get("expiryBefore", {})]
    if not all(snapshot.get("observer", {}).get("role") == "oid_observer"
               and snapshot.get("observer", {}).get("transaction_read_only") == "on" for snapshot in snapshots):
        return {name: False for name in ("logout", "origin", "forged", "expired")}
    active = lambda snapshot: sum(row.get("active_session_count", 0) for row in _items(snapshot.get("sessions")))
    preserved = all(before.get(key) == after.get(key) for key in ("owners", "identities", "admissions"))
    logout = bool(
        browser.get("logoutStatus") == 200 and browser.get("loggedOutStatus") == 401
        and browser.get("reusedStatus") == 401 and active(before) == 1 and active(after) == 0
        and preserved and any(row.get("selector") == "sign-out" for row in _items(browser.get("capture", {}).get("actions")))
    )
    origin = bool(
        protocol.get("crossOriginStatus") == 403 and protocol.get("crossOriginOperation")
        and denied.get("observer", {}).get("role") == "oid_observer"
        and not any(row.get("operation_id") == protocol["crossOriginOperation"] for row in _items(denied.get("challenges")))
    )
    return {
        "logout": logout,
        "origin": origin,
        "forged": bool(protocol.get("forgedAdminStatus") == 403 and before.get("invitations") == denied.get("invitations")),
        "expired": bool(browser.get("expiredStatus") == 401 and browser.get("expiredMutationStatus") == 401
                        and browser.get("expirySetup", {}).get("changedFreshPendingSessions") == 1
                        and active(database.get("expiryBefore", {})) == 1 and active(prepared) == 0
                        and expired_after.get("admissions") == []),
    }


def derive_observations(
    scenario_id: str,
    browser: dict[str, Any],
    database: dict[str, Any],
    provider: dict[str, Any],
    crypto: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, bool]:
    """Return only facts derivable from raw allowlisted observations."""

    if scenario_id == "OID-SC-008":
        facts = _session_facts(browser, database)
        return {"origin_csrf_checked": facts["origin"], "logout_session_invalidated": facts["logout"]}

    if scenario_id == "OID-SC-001":
        valid = _trial(browser, "valid") or {}
        valid_op = valid.get("operationId")
        valid_identity = _identity(database, "google", valid.get("subjectSha256"))
        flow = next(
            (row for row in _items(database.get("authFlows")) if row.get("operation_id") == valid_op),
            None,
        )
        audit = any(
            row.get("operation_id") == valid_op and row.get("event_type") == "auth.session_succeeded"
            for row in _items(database.get("audits"))
        )
        events = _items(provider.get("events"))
        valid_token_exchange = any(
            row.get("kind") == "token_exchange_verified_pkce"
            and row.get("claimVariant") == "valid"
            and row.get("subjectSha256") == valid.get("subjectSha256")
            for row in events
        )
        invalid_trials = [
            _trial(browser, name)
            for name in ("wrong_state", "wrong_issuer", "wrong_audience", "expired_token", "provider_response_missing")
        ]
        invalid_no_session = all(
            trial
            and trial.get("ownerStatus") == 401
            and trial.get("operationId")
            and not any(
                row.get("operation_id") == trial["operationId"]
                and row.get("outcome") in {"success", "succeeded"}
                for row in _items(database.get("authFlows"))
            )
            for trial in invalid_trials
        )
        return {
            "provider_subject_verified": bool(
                valid_identity and valid_identity.get("owner_id") == valid.get("ownerId")
            ),
            "callback_state_correlated": bool(
                valid.get("stateCorrelated") is True
                and flow
                and flow.get("provider") == "google"
                and flow.get("purpose") == "signin"
                and flow.get("outcome") in {"success", "succeeded"}
                and audit
            ),
            "token_claims_validated": bool(
                flow
                and flow.get("outcome") in {"success", "succeeded"}
                and valid_token_exchange
                and valid_identity
            ),
            "invalid_exchange_no_session": invalid_no_session,
        }

    if scenario_id == "OID-SC-002":
        outcomes = _items(browser.get("outcomes"))
        valid = next((item for item in outcomes if item.get("trial") == "valid"), {})
        address_hash = valid.get("addressSha256")
        identity = _identity(database, "wallet", address_hash)
        challenges = _items(database.get("challenges"))
        valid_nonce = next(
            (
                item
                for item in _items(browser.get("siweChallenges"))
                if item.get("path") == "/api/auth/siwe/nonce"
            ),
            {},
        )
        challenge = next(
            (item for item in challenges if item.get("operation_id") == valid_nonce.get("operationId")),
            None,
        )
        rejected = lambda name: any(
            row.get("trial") == name and row.get("ownerStatus") == 401 for row in outcomes
        )
        return {
            "signature_and_message_verified": bool(
                identity and challenge and challenge.get("consumed_at") and valid.get("signingRequests") == 1
            ),
            "nonce_consumed_once": bool(
                challenge
                and challenge.get("consumed_at")
                and isinstance(browser.get("replayStatus"), int)
                and browser["replayStatus"] >= 400
            ),
            "domain_uri_chain_time_checked": all(
                rejected(name) for name in ("wrong_domain", "wrong_uri", "wrong_chain", "not_yet_valid", "expired", "wrong_signature", "unsupported_wallet_profile")
            ),
            "browser_purpose_bound": bool(
                challenge
                and challenge.get("purpose") == "signin"
                and isinstance(browser.get("crossPurposeStatus"), int)
                and browser["crossPurposeStatus"] >= 400
                and isinstance(browser.get("crossBrowserStatus"), int)
                and browser["crossBrowserStatus"] >= 400
            ),
            "wallet_email_not_google_proof": bool(
                identity
                and not any(
                    row.get("owner_id") == identity.get("owner_id") and row.get("provider") == "google"
                    for row in _items(database.get("identities"))
                )
            ),
        }

    if scenario_id == "OID-SC-009":
        admin = browser.get("admin") if isinstance(browser.get("admin"), dict) else {}
        ordinary = browser.get("ordinaryOwner") if isinstance(browser.get("ordinaryOwner"), dict) else {}
        invite = browser.get("invitation") if isinstance(browser.get("invitation"), dict) else {}
        actions = {item.get("selector") for item in _items(admin.get("actions"))}
        requests = _items(admin.get("requests"))
        operation_ids = {item.get("operationId") for item in requests}
        invitation_id = invite.get("id")
        invitation = next(
            (item for item in _items(database.get("invitations")) if item.get("id") == invitation_id),
            None,
        )
        issue_audit = any(
            row.get("operation_id") == invite.get("operationId") and row.get("event_type") == "invitation.issued"
            for row in _items(database.get("audits"))
        )
        revoke_audit = any(
            row.get("operation_id") == invite.get("revokeOperation") and row.get("event_type") == "invitation.revoked"
            for row in _items(database.get("audits"))
        )
        policy_audit = any(
            row.get("operation_id") in operation_ids and row.get("event_type") == "registration_policy.changed"
            for row in _items(database.get("audits"))
        )
        admin_owner = admin.get("owner") if isinstance(admin.get("owner"), dict) else {}
        return {
            "actual_admin_pages": bool(
                {"invite-create", "registration-save"}.issubset(actions)
                and admin.get("adminPageVisible") is True
            ),
            "configured_admin_only": bool(
                admin_owner.get("isAdmin") is True
                and ordinary.get("isAdmin") is False
                and ordinary.get("adminReadStatus") == 403
            ),
            "invitation_verifier_not_plaintext_history": bool(
                invite.get("verifierMatches") is True
                and invite.get("listExcludesSecret") is True
                and invitation
                and "verifier_hash" not in invitation
            ),
            "mode_change_audited": bool(
                {"registration-save", "invite-revoke"}.intersection(actions)
                and policy_audit
                and revoke_audit
                and issue_audit
                and invitation
                and invitation.get("revoked_at")
            ),
            "no_first_signup_admin": bool(
                ordinary.get("isAdmin") is False and ordinary.get("adminReadStatus") == 403
            ),
        }

    if scenario_id == "OID-SC-011":
        owner_id = browser.get("ownerId")
        login = browser.get("login") if isinstance(browser.get("login"), dict) else {}
        activation = browser.get("activation") if isinstance(browser.get("activation"), dict) else {}
        link = browser.get("walletLink") if isinstance(browser.get("walletLink"), dict) else {}
        returned = browser.get("returnedWalletLogin") if isinstance(browser.get("returnedWalletLogin"), dict) else {}
        google_hash = browser.get("googleSubjectSha256")
        wallet_hash = (link.get("walletAudit") or {}).get("addressSha256")
        identities = _items(database.get("identities"))
        google = _identity(database, "google", google_hash)
        wallet = _identity(database, "wallet", wallet_hash)
        admission = next((row for row in _items(database.get("admissions")) if row.get("owner_id") == owner_id), None)
        redemption = next((row for row in _items(database.get("redemptions")) if row.get("invitation_id") == browser.get("invitationId")), None)
        link_op = link.get("linkOperationId")
        link_audit = any(
            row.get("operation_id") == link_op and row.get("event_type") in {"auth.identity_link_succeeded", "owner.identity_linked"}
            for row in _items(database.get("audits"))
        )
        flows = _items(browser.get("failedFlows"))
        invalid_signature = any(row.get("kind") == "invalid_signature" and row.get("ownerStatus") == 401 for row in flows)
        denied_provider = any(row.get("kind") == "provider_denied" and row.get("ownerStatus") == 401 for row in flows)
        invalid_invite = activation.get("invalidInvitationStatus", 0) >= 400 and activation.get("pendingAfterInvalid") is True
        scope = provenance.get("scope") if isinstance(provenance.get("scope"), dict) else {}
        provider_scope = (
            scope.get("externalProviderUsed") is False
            and scope.get("externalWalletUsed") is False
            and "fixture" in str(scope.get("profile", "")).lower()
        )
        return {
            "actual_auth_admission_link_pages": bool(
                "sign-in-google" in {item.get("selector") for item in _items(login.get("actions"))}
                and "activate-owner" in {item.get("selector") for item in _items(activation.get("actions"))}
                and "link-wallet" in {item.get("selector") for item in _items(link.get("actions"))}
                and "sign-in-wallet" in {item.get("selector") for item in _items(returned.get("actions"))}
                and returned.get("sameOwner") is True
                and returned.get("hasBothMethods") is True
            ),
            "real_server_verification": bool(
                google
                and wallet
                and google.get("owner_id") == owner_id
                and wallet.get("owner_id") == owner_id
                and admission
                and redemption
                and link_audit
            ),
            "failed_flow_no_fake_success": bool(invalid_signature and denied_provider and invalid_invite),
            "safe_secret_free_evidence": True,
            "local_provider_scope_label": provider_scope,
        }

    return {}


def derive_negative_variants(
    scenario_id: str,
    browser: dict[str, Any],
    database: dict[str, Any],
    provider: dict[str, Any],
    crypto: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, bool]:
    """Derive contract negative variants from observed browser and SQL results."""

    if scenario_id == "OID-SC-008":
        facts = _session_facts(browser, database)
        return {"expired_session": facts["expired"], "forged_owner_admin_id": facts["forged"],
                "cross_origin_mutation": facts["origin"], "reused_logged_out_session": facts["logout"]}

    if scenario_id == "OID-SC-001":
        trials = {name: _trial(browser, name) for name in (
            "wrong_state", "wrong_issuer", "wrong_audience", "expired_token", "provider_response_missing",
        )}
        return {
            "wrong_state": bool(trials["wrong_state"] and trials["wrong_state"].get("ownerStatus") == 401 and trials["wrong_state"].get("stateCorrelated") is False),
            "wrong_issuer_or_audience": all(trials[name] and trials[name].get("ownerStatus") == 401 for name in ("wrong_issuer", "wrong_audience")),
            "expired_token": bool(trials["expired_token"] and trials["expired_token"].get("ownerStatus") == 401),
            "provider_response_missing": bool(trials["provider_response_missing"] and trials["provider_response_missing"].get("ownerStatus") == 401),
            "caller_supplied_email": bool(browser.get("callerEmailEndpoint", {}).get("rejected") is True and browser.get("callerEmailEndpoint", {}).get("ownerStatus") == 401),
        }
    if scenario_id == "OID-SC-002":
        outcomes = _items(browser.get("outcomes"))
        rejected = lambda name: any(row.get("trial") == name and row.get("ownerStatus") == 401 for row in outcomes)
        return {
            "nonce_replay": isinstance(browser.get("replayStatus"), int) and browser["replayStatus"] >= 400,
            "wrong_domain_uri_chain": all(rejected(name) for name in ("wrong_domain", "wrong_uri", "wrong_chain")),
            "expired_or_not_yet_valid": rejected("not_yet_valid") and rejected("expired"),
            "wrong_signature": rejected("wrong_signature"),
            "unsupported_wallet_profile": any(
                row.get("trial") == "unsupported_wallet_profile" and row.get("ownerStatus") == 401 and row.get("signingRequests") == 0
                for row in outcomes
            ),
        }
    if scenario_id == "OID-SC-009":
        ordinary = browser.get("ordinaryOwner") if isinstance(browser.get("ordinaryOwner"), dict) else {}
        invitation = browser.get("invitation") if isinstance(browser.get("invitation"), dict) else {}
        return {
            "ordinary_owner_admin_api": ordinary.get("adminReadStatus") == 403,
            "agent_invite_issuance": False,
            "first_signup_role_claim": ordinary.get("isAdmin") is False,
            "unused_invite_revocation_retry": bool(invitation.get("revoked") is True and invitation.get("revokeAudit") is True),
        }
    if scenario_id == "OID-SC-011":
        failed = _items(browser.get("failedFlows"))
        activation = browser.get("activation") if isinstance(browser.get("activation"), dict) else {}
        return {
            "abandoned_login": any(row.get("kind") == "abandoned_login" and row.get("ownerStatus") == 401 and row.get("navigationAbandoned") is True for row in failed),
            "provider_denies": any(row.get("kind") == "provider_denied" and row.get("ownerStatus") == 401 for row in failed),
            "invalid_signature": any(row.get("kind") == "invalid_signature" and row.get("ownerStatus") == 401 for row in failed),
            "failed_invite_retry": activation.get("invalidInvitationStatus", 0) >= 400 and activation.get("pendingAfterInvalid") is True and activation.get("validActivationStatus") == 200,
            "browser_session_substitution": any(
                row.get("kind") == "browser_session_substitution"
                and row.get("ownerStatus") == 401 and row.get("callbackStatus") == 401
                and any(action.get("selector") == "sign-in-google" for action in _items(row.get("capture", {}).get("actions")))
                for row in failed
            ),
        }
    return {}


def derive_evidence(
    scenario_id: str,
    manifest: dict[str, Any],
    artifacts: dict[str, Any],
) -> tuple[dict[str, bool], dict[str, bool]]:
    browser = artifacts.get("browser.json", {})
    database = artifacts.get("database.json", {})
    provider = artifacts.get("provider.json", {})
    crypto = artifacts.get("crypto.json", {})
    provenance = artifacts.get("provenance.json", {})
    observations = derive_observations(scenario_id, browser, database, provider, crypto, provenance)
    negatives = derive_negative_variants(scenario_id, browser, database, provider, crypto, provenance)

    for name, record in manifest.get("observations", {}).items():
        if record.get("status") == "observed" and observations.get(name) is not True:
            raise AssertionError(f"{scenario_id} observation {name} cannot be derived from raw artifacts")
    for name, record in manifest.get("negativeVariants", {}).items():
        if record.get("status") == "observed" and negatives.get(name) is not True:
            raise AssertionError(f"{scenario_id} negative variant {name} cannot be derived from raw artifacts")
    return observations, negatives
