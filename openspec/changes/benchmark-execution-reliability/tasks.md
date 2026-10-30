# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Runtime gates remain `not_run`.

## 1. Review and freeze the boundary

- [ ] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [ ] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement represent every valid action and finish answer through mcp at native_mcp_owner_api_postgres; exercise all listed negative variants and independently inspect one_admission_per_operation, unchanged_ledger_on_rejection; gate: BER-SC-001 (environment).
- [ ] 2.3 Implement disclose answer contracts without teaching a solution at native_mcp_issuance_closure_postgres; exercise all listed negative variants and independently inspect one_valid_closure, invalid_answer_no_task_or_action_mutation; gate: BER-SC-002 (environment).
- [ ] 2.4 Implement resolve admitted actions across the task cutoff at owner_worker_action_outbox_bef_postgres; exercise all listed negative variants and independently inspect immutable_action_and_cutoff, bounded_pending_resolution, no_duplicate_effect_or_charge; gate: BER-SC-003 (environment).
- [ ] 2.5 Implement preserve unknown grading and terminate safely at coordinator_observation_recovery_bef_postgres; exercise all listed negative variants and independently inspect one_recovery_terminal_transition, at_most_one_authorized_source_refund, retained_unknown; gate: BER-SC-004 (environment).
- [ ] 2.6 Implement diagnose and prevent successor preparation regression at coordinator_successor_preparation_bef_postgres_rpc; exercise all listed negative variants and independently inspect one_successor_binding, unchanged_original_charge, no_active_generation_leak; gate: BER-SC-005 (environment).
- [ ] 2.7 Implement complete catalog rejection evidence at release_validator_producer_independent_replay_postgres; exercise all listed negative variants and independently inspect no_invalid_release_activation, no_reservation_or_grant_mutation; gate: BER-SC-006 (environment).
- [ ] 2.8 Implement recover and replay without rewriting business history at real_worker_restart_postgres_bef_independent_replay; exercise all listed negative variants and independently inspect idempotent_authorized_recovery_completion, readonly_replay_zero_business_writes, exact_resource_release; gate: BER-SC-007 (environment).
- [ ] 2.9 Implement attribute failures with bounded diagnostic evidence at owner_browser_feedback_api_independent_postgres; exercise all listed negative variants and independently inspect read_only_historical_feedback, no_regrading_or_refund_from_display; gate: BER-SC-008 (environment).

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.

