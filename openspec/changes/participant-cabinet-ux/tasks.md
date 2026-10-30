# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Runtime gates remain `not_run`.

## 1. Review and freeze the boundary

- [ ] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [ ] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement expose honest priced launch actions at owner_browser_quote_admission_postgres; exercise all listed negative variants and independently inspect existing_exact_holds_debits, no_cash_substitution_or_silent_reprice; gate: PCU-SC-001 (environment).
- [ ] 2.3 Implement format money without losing exact accounting at owner_browser_billing_api_independent_postgres; exercise all listed negative variants and independently inspect unchanged_integer_arithmetic, no_financial_write_from_formatting; gate: PCU-SC-002 (environment).
- [ ] 2.4 Implement keep complete histories compact and private at owner_browser_cursor_api_postgres; exercise all listed negative variants and independently inspect read_only_complete_owner_history, no_cross_owner_cache; gate: PCU-SC-003 (environment).
- [ ] 2.5 Implement explain readiness and support through accessible help at owner_browser_accessibility_actual_status_api; exercise all listed negative variants and independently inspect read_only_diagnostics, no_automatic_paid_retry; gate: PCU-SC-004 (environment).
- [ ] 2.6 Implement show detailed owner training feedback safely at owner_browser_feedback_service_postgres_bef; exercise all listed negative variants and independently inspect read_only_result_projection, no_score_or_refund_change; gate: PCU-SC-005 (environment).
- [ ] 2.7 Implement create contextual reports with optional private screenshots at owner_browser_report_upload_admin_independent_postgres_files; exercise all listed negative variants and independently inspect one_report_image_audit, unchanged_benchmark_and_finances, existing_beta_ended_at_plus_30_utc_day_cleanup; gate: PCU-SC-006 (environment).
- [ ] 2.8 Implement hide and reject non-admin administration pages at real_http_browser_admin_server_api_postgres; exercise all listed negative variants and independently inspect authorized_admin_writes_only, no_unauthorized_page_data_or_mutation; gate: PCU-SC-007 (environment).
- [ ] 2.9 Implement present connection management without manual credential clutter at owner_browser_installer_status_native_mcp_postgres; exercise all listed negative variants and independently inspect scoped_grant_changes_only, unchanged_caps_and_other_connections; gate: PCU-SC-008 (environment).

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.

