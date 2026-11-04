# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Current runtime results and remaining blocks are recorded below.

## 1. Review and freeze the boundary

- [x] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [x] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement expose honest priced launch actions at owner_browser_quote_admission_postgres; exercise all listed negative variants and independently inspect existing_exact_holds_debits, no_cash_substitution_or_silent_reprice; gate: PCU-SC-001 (environment).
- [ ] 2.3 Implement format money without losing exact accounting at owner_browser_billing_api_independent_postgres; exercise all listed negative variants and independently inspect unchanged_integer_arithmetic, no_financial_write_from_formatting; gate: PCU-SC-002 (environment).
- [x] 2.4 Implement keep complete histories compact and private at owner_browser_cursor_api_postgres; exercise all listed negative variants and independently inspect read_only_complete_owner_history, no_cross_owner_cache; gate: PCU-SC-003 (environment).
- [ ] 2.5 Implement explain readiness and support through accessible help at owner_browser_accessibility_actual_status_api; exercise all listed negative variants and independently inspect read_only_diagnostics, no_automatic_paid_retry; gate: PCU-SC-004 (environment).
- [ ] 2.6 Implement show detailed owner training feedback safely at owner_browser_feedback_service_postgres_bef; exercise all listed negative variants and independently inspect read_only_result_projection, no_score_or_refund_change; gate: PCU-SC-005 (environment).
- [ ] 2.7 Implement create contextual reports with optional private screenshots at owner_browser_report_upload_admin_independent_postgres_files; exercise all listed negative variants and independently inspect one_report_image_audit, unchanged_benchmark_and_finances, existing_beta_ended_at_plus_30_utc_day_cleanup; gate: PCU-SC-006 (environment).
- [ ] 2.8 Implement hide and reject non-admin administration pages at real_http_browser_admin_server_api_postgres; exercise all listed negative variants and independently inspect authorized_admin_writes_only, no_unauthorized_page_data_or_mutation; gate: PCU-SC-007 (environment).
- [ ] 2.9 Implement present connection management without manual credential clutter at owner_browser_remote_mcp_status_native_client_postgres; exercise all listed negative variants and independently inspect scoped_grant_changes_only, unchanged_caps_and_other_connections; gate: PCU-SC-008 (environment).
- [x] 2.10 Add visible-page five-second polling for launch requests/admitted runs and remove inline handoff-prompt rendering. The updated Runs UI was checked on the Docker preview; its BDD replay remains open in 3.1.
- [x] 2.11 Move Diagnostics into Reports/Support and explain its evidence/import purpose and limits. The Reports / Support link and explanation were checked on the Docker preview; its BDD replay remains open in 3.1.
- [x] 2.12 Give the active primary-navigation route and an inactive hovered route distinct background colors. PCU-SC-004 captures and independently replays the computed colors in 3.1.

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions. This includes recapturing PCU-SC-003 and PCU-SC-004 after the Runs and Diagnostics updates; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.


## Implementation checkpoint (2026-10-31)

Current owner authorization is recorded in approval.md. The cross-change index retains AAP owner/admin API authority, BRL pricing/admission, BTS issuance/secrecy, BPC report/image retention and BLP-REQ-007/SC-011/014's narrow completed-Training diagnostic amendment. ACI owns Remote MCP URL/OAuth/refresh and stable connection grants. No price, weight, cap, timer, grade, refund, publication or existing ledger arithmetic is changed by the cabinet.

Implemented source: exact-money presentation and disclosure, five-entry cursor UI for four histories, readable Training/Ranked launch actions with zero cash, accessible help/readiness mapping, contextual reports, completed Training task diagnostics, pre-render admin HTTP concealment and server-verified admin navigation, Remote MCP connection status/revoke with legacy credentials under Advanced.

Installed spec-derived Gherkin, named mapper and semantic contracts. Structural audit protects all eight approved scenarios. The actual collector now uses real browser controls, API responses and independent read-only PostgreSQL snapshots. Its offline reader checks hashes, exact monetary units, complete history IDs, persisted receipt timelines, reports/images and role/cache boundaries. It consumes source-sealed worker history for positive Training diagnostics and delegates native proof to ACI. All eight environment gates remain blocked pending execution and the full approved negative matrix. Task 2.1 is structurally complete; scenario tasks remain unchecked because implementation alone does not complete their exercise/readback clauses.

Validation: actual Docker runtime `pnpm --filter @web-agent-bench/owner-web check` passed; exact-money edge tests passed using the runtime tsx loader. Builds and browser E2E are coordinated by the root agent after source freeze. No migrations, user-database writes, stand restart or beta activation were performed by this UI work. Target host/native editions, backup/restore qualification and full runtime acceptance remain open.

The collector entry is `runParticipantCabinetCases` in `packages/owner-acceptance/src/participant-cabinet-cases.mjs`. Optional private fixture callbacks are explicit caller dependencies and never substitute mocked responses. The read-only `participant_cabinet_replay` reader rejects producer pass labels and tampered captures; its three scoped tests passed. Native editions and unobserved variants remain non-passing.

## Local runtime checkpoint (2026-11-01)

Frozen-source actual browser/backend/PostgreSQL/BEF capture: `artifacts/runs/participant-cabinet/1333879d-73d9-44d1-b001-71fb0190033f/participant-cabinet-capture.json`, SHA-256 `f0298bbfe5e0356f573851915cab0cff3ad6738a3b303e900c2ea650fefe1027`. Independent replay succeeded. Actual BDD mappers: **1 passed, 7 blocked/skipped**, no failed cases; `bdd-runtime.xml` in that directory records the result. The reader was not weakened to accept producer flags.

The reference executor completed Training S1/M1/H1 with three known full-credit results and Ranked with twelve known full-credit results, including S2/H3/U1. Each run retained one exact debit (500000/1000000 micro-USDC), released its dispatch claim and had no remaining execution slots. Runs: `042795d1-7ed0-4e26-acf0-cc171ed06d11` and `3ad451df-d237-41da-82aa-d323642e6788`; corresponding genuine worker captures/history are referenced from the cabinet owner capture. These are real local reference-executor flows, not twelve tasks solved by a participant model.

The browser capture independently confirms exact money disclosure, all four private cursor histories, accessible help/correlation, actual Training result/receipt diagnostics, contextual report submission with a real page PNG and normalized image hash, malformed/oversize image rejection, admin visibility and non-admin HTTP denial. PCU-SC-003 passed its complete same-timestamp, concurrent-insert, empty-history and foreign-cursor matrix. A collector race was fixed by waiting for actual refresh-response IDs to appear in the DOM after the shared refresh control completes; a unique report error marker avoids the route-announcer ambiguity.

Remaining full-gate controls: zero/stale/insufficient quotes and exact admission linkage; one-micro-unit overcap allocation; unknown/offline/executor/malicious error states; unknown, unissued, active and forged-result diagnostics; retention-deadline restore; agent-bearer/cross-session cache denial; same-boundary native connection observation, revoke/replacement/other-client/cancelled-confirmation controls. The native OAuth positive capture exists on the same fixture database, but PCU-SC-008 does not yet bind that later evidence and must not be promoted. No external beta activation or sync/archive is claimed.
