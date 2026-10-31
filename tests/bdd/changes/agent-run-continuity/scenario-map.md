# Scenario map: `agent-run-continuity`

Workflow: [`docs/task-design.md`](../../../../docs/task-design.md)

**Lifecycle phase:** `active-delta`
**Normative source:** `openspec/changes/agent-run-continuity/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/changes/agent-run-continuity/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `ARC-REQ-001` | `ARC-SC-001` | Execute the complete handoff continuously | `@scn_arc_sc_001` | `test_arc_sc_001` | `agent_run_continuity` | `environment` | yes | `environment`; observations: clipboard_selection_binding, continuous_native_run, historical_run_unchanged; negatives: wrong_card_or_intent, clipboard_fallback, stale_selection; effects: one_admission, one_platform_debit; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `ARC-REQ-002` | `ARC-SC-002` | Expose authorized run progression through MCP | `@scn_arc_sc_002` | `test_arc_sc_002` | `agent_run_continuity` | `environment` | yes | `environment`; observations: raw_waiting_and_terminal_responses, readonly_projection, authorization_rechecked; negatives: queued_or_preparing_null, closed_grading_null, foreign_owner_or_card, revoked_expired_or_mode_disabled; effects: zero_projection_business_writes, no_cross_owner_disclosure; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `ARC-REQ-003` | `ARC-SC-003` | Grade proven unrequested retrieval without fabricating absence | `@scn_arc_sc_003` | `test_arc_sc_003` | `agent_run_continuity` | `environment` | yes | `environment`; observations: closed_admission_census, confirmed_payment_and_source_absence, known_m1_then_h1_completion, exact_fences_and_finance; negatives: missing_census, contradictory_source, admitted_pending_or_unknown_retrieve, tampered_or_foreign_proof; effects: no_duplicate_effect_or_refund, historical_grade_unchanged; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |

## Active-delta review

- [x] Normative behavior resolves to the selected active OpenSpec delta.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] The approved proposal is review metadata; the separate manifest supplies runtime contracts.
