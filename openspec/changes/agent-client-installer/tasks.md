# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Runtime gates remain `not_run`.

## 1. Review and freeze the boundary

- [ ] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [ ] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement install only selected client configuration safely at native_installer_actual_client_filesystem; exercise all listed negative variants and independently inspect recoverable_scoped_config, no_unrelated_setting_or_provider_key_change; gate: ACI-SC-001 (environment).
- [ ] 2.3 Implement authorize the actual owner and selected agent at installer_browser_oauth_server_postgres_secure_store; exercise all listed negative variants and independently inspect one_scoped_grant, no_provider_secret_custody, denial_no_credential; gate: ACI-SC-002 (environment).
- [ ] 2.4 Implement refresh until revocation with bounded access tokens at native_client_refresh_service_postgres_secure_store; exercise all listed negative variants and independently inspect rotated_refresh_family, unchanged_permissions_and_caps, no_new_run_or_charge; gate: ACI-SC-003 (environment).
- [ ] 2.5 Implement separate connection revocation from agent-wide revocation and restore at owner_browser_revoke_native_mcp_refresh_bef_postgres; exercise all listed negative variants and independently inspect selected_or_agent_wide_revoked_families_only, existing_agent_wide_cleanup_authority, restored_write_barrier, no_permission_revival; gate: ACI-SC-004 (environment).
- [ ] 2.6 Implement negotiate protocol and required capabilities at installer_native_mcp_initialization_owner_api; exercise all listed negative variants and independently inspect verified_connection_metadata, no_bypass_profile_or_credential; gate: ACI-SC-005 (environment).
- [ ] 2.7 Implement discover self identity and show real connection health at native_client_preflight_owner_browser_postgres; exercise all listed negative variants and independently inspect connection_observation_only, unchanged_action_and_financial_rows; gate: ACI-SC-006 (environment).
- [ ] 2.8 Implement launch without copying identifiers at owner_browser_native_handoff_acceptance_postgres; exercise all listed negative variants and independently inspect one_owner_bound_intent_run, existing_reservation_rules, no_uuid_clipboard_dependency; gate: ACI-SC-007 (environment).
- [ ] 2.9 Implement qualify every required native execution path at five_native_clients_browser_target_postgres_bef; exercise all listed negative variants and independently inspect source_bound_edition_acceptance, no_aggregate_masking_of_blocker; gate: ACI-SC-008 (environment).

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.

