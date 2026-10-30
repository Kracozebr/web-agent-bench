# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Runtime gates remain `not_run`.

## 1. Review and freeze the boundary

- [ ] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [ ] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement measure separate non-overlapping timing phases at worker_monotonic_events_postgres_native_trace; exercise all listed negative variants and independently inspect append_only_timing_evidence, unchanged_score_and_billing; gate: BTB-SC-001 (environment).
- [ ] 2.3 Implement calibrate task budgets before choosing numeric defaults at native_client_serial_benchmark_resource_capture; exercise all listed negative variants and independently inspect measurement_only_until_numeric_approval, no_active_timer_change; gate: BTB-SC-002 (environment).
- [ ] 2.4 Implement pin clocks at admission and survive restart at admission_coordinator_clock_postgres_bef; exercise all listed negative variants and independently inspect immutable_run_clock_policy, no_timer_revival_or_extra_charge; gate: BTB-SC-003 (environment).
- [ ] 2.5 Implement apply deadlines without abandoning cutoff or recovery at real_deadline_action_recovery_coordinator_postgres_bef; exercise all listed negative variants and independently inspect one_cutoff_and_terminal_path, source_preserving_finances, explicit_unissued_status; gate: BTB-SC-004 (environment).
- [ ] 2.6 Implement show task timing and progress without misleading completion claims at owner_browser_timing_projection_independent_postgres; exercise all listed negative variants and independently inspect read_only_owner_timing_projection, unchanged_official_scores; gate: BTB-SC-005 (environment).
- [ ] 2.7 Implement measure a serial resource baseline without requiring deferred prefetch at serial_target_bef_resource_observers_and_disabled_feature_state; exercise all listed negative variants and independently inspect read_only_serial_measurement_report, no_prefetch_implementation_or_enablement, unchanged_grade_and_financial_state; gate: BTB-SC-006 (environment).

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.

