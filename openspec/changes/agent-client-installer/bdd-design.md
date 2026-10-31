# BDD design packet: agent-client-installer

Workflow: [docs/task-design.md](../../../docs/task-design.md)

**Status:** Revised planning proposal; awaiting explicit approval of the changed assertions. The 2026-10-31 approval applies to the earlier installer scope only. All eight revised runtime gates remain not_run.
**Normative proposed delta:** [spec](specs/agent-client-installer/spec.md)
**Target main source after eventual approved sync:** openspec/specs/agent-client-installer/spec.md
**Proposed contracts:** [bdd-harness-proposal.json](bdd-harness-proposal.json). No executable registry, Gherkin, mapper, adapter, runtime profile, or runtime capture is installed by this revision.

## Intent

**Goal:** Connect a participant-owned agent through one remote MCP endpoint without local platform software; preserve scoped authorization and hand off Training or Ranked starts with capability-based compatibility.

**Non-goals:**

- Hosted model execution or provider-key custody.
- Automatic permission or spending-cap increases.
- Exact client application version allowlists.
- Claiming every client has a native add link or that first-time setup always takes two clicks.
- Changes to benchmark scoring, PvP fairness, settlement, or BRL billing authority.

## Scenario design

All rows are mandatory environment gates for the claims they cover. In ACI-SC-008, every client included in the beta support claim needs native evidence; unavailable or unselected named targets remain visibly unverified and do not block beta with a verified subset. Mapper module proposed for later implementation: tests/bdd/mappers/test_agent_client_installer_bdd.py. Adapter name: agent_client_installer. The existing eight scenario IDs are retained for traceability, but their assertions have changed and therefore await renewed approval.

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
|---|---|---|---|---|---|---|---|---|---|---|
| ACI-REQ-001 | ACI-SC-001 | Add the canonical remote MCP endpoint without local platform software | Given a signed-in owner and a named, generic, or unsupported client / When the owner uses an official add link, a URL fallback, or an invalid/substituted endpoint / Then only the canonical endpoint is offered, platform code is not downloaded or run, credentials are absent from links/prompts, and unsupported clients are reported honestly | environment | yes | test_aci_sc_001 | agent_client_installer | canonical_endpoint; official_link_or_url_fallback; no_platform_package_or_process; expected_client_owned_config_delta; no_credential_in_link_or_prompt | Actual owner browser and actual selected client configuration/process observation with independent replay | Protects the no-download remote entry boundary and truthful fallback behavior. |
| ACI-REQ-002 | ACI-SC-002 | Consent creates only the selected owner-agent connection grant | Given a canonical remote endpoint and a verified owner with an agent / When OAuth consent is accepted or denied and callback, resource, state, code, or agent bindings are attacked / Then only valid consent creates the one scoped grant and denials leave no usable credential or business effect | environment | yes | test_aci_sc_002 | agent_client_installer | pkce_state_resource_binding; owner_agent_client_grant; displayed_permissions; credential_absence_from_url_prompt_logs; denial_no_authority | Actual browser-to-OAuth-to-MCP flow, owner database rows, sanitized client callback evidence | Protects identity, consent, and least privilege across remote clients. |
| ACI-REQ-003 | ACI-SC-003 | Refresh remains bounded and recovers safely | Given an authorized remote MCP grant / When access expires, the client reconnects after offline time, or concurrent retries occur around response loss or restart / Then the same grant renews under bounded rotation and replay outside that policy revokes its token family without changing scope or creating business effects | environment | yes | test_aci_sc_003 | agent_client_installer | access_expiry_and_rotation; scope_and_cap_fingerprint; restart_recovery; bounded_response_loss_retry; refresh_replay_rejection | Actual authorization service and PostgreSQL state with independent read-only replay | Prevents fragile manual renewal while preserving revocation and once-only effects. |
| ACI-REQ-004 | ACI-SC-004 | Revoke the intended scope and never revive restored credentials | Given two connections for one agent, active/queued work, and an older checkpoint / When one connection is disconnected, replaced, revoked, or the whole agent is revoked during refresh and the old checkpoint is restored / Then only the requested scope is fenced, other authorized work follows AAP rules, and stale restored credentials remain denied before write-enable | environment | yes | test_aci_sc_004 | agent_client_installer | scoped_vs_agent_wide_revocation; native_401_and_authenticate_header; zero_revoked_scope_admission; other_connection_and_run_preserved; restore_invalidation_barrier | Actual owner revoke controls, native MCP requests, AAP/BRL/PostgreSQL/BEF observations | Protects connection-level controls and restore safety without duplicating AAP authority. |
| ACI-REQ-005 | ACI-SC-005 | Compatible versions connect and missing capabilities fail closed | Given two client releases with the same required MCP behavior and a deliberately incapable client / When they negotiate a declared protocol and perform schema-valid preflight, including spoofed client metadata / Then compatible clients connect independent of release number and missing capabilities fail before domain effects | environment | yes | test_aci_sc_005 | agent_client_installer | negotiated_protocol; required_transport_and_tool_schema; client_version_is_metadata; incompatibility_reason; no_auth_or_domain_bypass | Actual native MCP handshake and preflight for declared protocol profiles with raw request/response hashes | Protects protocol compatibility while removing package-version allowlists and metadata trust. |
| ACI-REQ-006 | ACI-SC-006 | Preflight proves native access without benchmark effects | Given a native authorized remote MCP client and healthy, missing, revoked, or unavailable tools / When the owner connects or checks status / Then only a real client preflight establishes a timestamped state and no run, slot, task action, reservation, charge, or public card is created | environment | yes | test_aci_sc_006 | agent_client_installer | authenticated_self_identity; real_preflight_timestamp; permission_readiness_separation; zero_benchmark_effects | Actual client tool call plus independently correlated owner/BEF/PostgreSQL reads | Separates connectivity from permissions and executor readiness. |
| ACI-REQ-007 | ACI-SC-007 | One launch intent reaches only its selected agent and admits once | Given a connected agent with mode permission and a valid displayed quote / When the owner starts Training or Ranked, opens and sends the ready request, or encounters duplicate, stale, offline, foreign, cancelled, or lost-response handoff / Then the selected agent accepts one unchanged intent or it remains visibly pending and no stale/foreign path creates a run or charge | environment | yes | test_aci_sc_007 | agent_client_installer | browser_launch_identity; authenticated_delivery_binding; native_send_action_count; pending_no_reservation; reservation_and_charge_count; idempotent_run_binding | Actual browser, selected client, BRL admission, PostgreSQL, and independent financial observer | Protects the one-site-action plus optional native Send/Run repeat path and existing admission rules. |
| ACI-REQ-008 | ACI-SC-008 | Qualify claimed clients once and keep new compatible versions eligible | Given a beta support subset from the ten target surfaces, other targets that are unavailable or unselected, and an additional MCP client / When each claimed surface performs native connect, preflight, and launch smoke at one representative release and a new or unlisted client passes the same capability check / Then evidence qualifies only exercised surfaces, other targets remain visibly unverified and outside the support claim, compatible new versions remain eligible, and no client is labelled qualified without native evidence | environment | yes | test_aci_sc_008 | agent_client_installer | per_surface_native_connect_preflight_handoff; version_metadata_only; unknown_compatible_client; missing_client_unverified; no_sdk_substitution; beta_subset_scope_disclosed | Actual native smoke for every surface claimed as supported from Codex Desktop/CLI, Claude Desktop/Code, OpenClaw, OpenCode, Hermes, KiloCode, Cline, and Goose; independent browser/API/PostgreSQL/BEF evidence | Demonstrates broad standards-based entry without requiring every target to block beta or requiring a regression run for every client patch. |

## Semantic harness contract

The proposed JSON declares each real boundary, required observations, negative variants, durable effects, evidence mode, and narrow private setup/read-only exceptions. It remains a planning artifact. Install the approved entries into tests/bdd/harness-contracts.json only after renewed assertion approval and during a later apply. Producer labels, SDK-only probes, and inventory checks are not evidence of native client behavior.

## Execution design

- Reuse AAP owner consent, auth, permission, and revocation boundaries and BRL intent/admission/billing authority; add no second authority.
- Start business actions through actual browser controls and follow the running API/worker to independently correlated PostgreSQL/BEF effects.
- Exercise each native client surface included in the beta support claim at one representative available release. Keep other named targets visibly unverified and outside that claim. Record the reported release and negotiated protocol as evidence only; do not create a per-patch release gate.
- Use actual native client flows for client qualification. Reference clients may probe protocol components but cannot qualify a named surface or a participant benchmark result.
- Preserve raw paths and hashes for private evidence. Replays are read-only and do not repeat business actions.
- Missing apps, accounts, host, observers, or required variants remain blocked or not_run. A missing prerequisite is not a pass.

## Approval boundary

The owner approved the earlier installer plan and its assertions on 2026-10-31. The owner later directed this remote-MCP/no-local-package revision and authorized updating its planning artifacts. That direction does not approve the changed scenario assertions or authorize code implementation. Any new or changed assertion requires explicit approval under docs/task-design.md.

**Decision:** revised assertions pending approval.
**Decision reference:** owner direction in this conversation on 2026-10-31; see [approval.md](approval.md).
