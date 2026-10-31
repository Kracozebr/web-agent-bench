# Scenario map: `agent-failure-reporting`

Workflow: [`docs/task-design.md`](../../../../docs/task-design.md)

**Lifecycle phase:** `active-delta`
**Normative source:** `openspec/changes/agent-failure-reporting/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/changes/agent-failure-reporting/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `AFR-REQ-001` | `AFR-SC-001` | Confirm one private platform failure report | `@scn_afr_sc_001` | `test_afr_sc_001` | `agent_failure_reporting` | `environment` | yes | `environment`; observations: same_handoff_terminal_report, one_private_report_and_receipt, admin_ui_pg_binding, benchmark_finance_unchanged; negatives: uncertain_unchanged_retry, foreign_run_task_action; effects: one_private_report, one_creation_audit, no_benchmark_or_financial_mutation; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `AFR-REQ-002` | `AFR-SC-002` | Preserve benchmark state when reporting is unnecessary or fails | `@scn_afr_sc_002` | `test_afr_sc_002` | `agent_failure_reporting` | `environment` | yes | `environment`; observations: ordinary_outcomes_do_not_trigger, report_failure_preserves_run, safe_report_content; negatives: ordinary_failed_partial, nonterminal_null, unconfirmed_transport, report_or_receipt_denied, hidden_payload_excluded; effects: no_ordinary_bug_report, no_relaunch_payment_or_grade_change; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `AFR-REQ-003` | `AFR-SC-003` | Preserve report authorization and profile scope | `@scn_afr_sc_003` | `test_afr_sc_003` | `agent_failure_reporting` | `environment` | yes | `environment`; observations: eight_tool_scope, terminal_reporting_available, revoked_expired_foreign_denied, private_config_backup; negatives: already_patched, concurrent_config_edit, forged_principal, foreign_link, expired_grant, revoked_grant; effects: two_tool_addition_only, no_unauthorized_report_writes; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |

## Active-delta review

- [x] Normative behavior resolves to the selected active OpenSpec delta.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] The approved proposal is review metadata; the separate manifest supplies runtime contracts.
