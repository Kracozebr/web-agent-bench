# Scenario map: `paid-delivery-cutoff-consistency`

Workflow: [`docs/task-design.md`](../../../../docs/task-design.md)

**Lifecycle phase:** `active-delta`
**Normative source:** `openspec/changes/paid-delivery-cutoff-consistency/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/changes/paid-delivery-cutoff-consistency/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `PDC-REQ-001` | `PDC-SC-001` | Preserve known grades through no-retrieval cutoff | `@scn_pdc_sc_001` | `test_pdc_sc_001` | `paid_delivery_cutoff_consistency` | `environment` | yes | `environment`; observations: training_h1_known, ranked_all_twelve_known, all_five_paid_absences, exact_finance_and_fences; negatives: source_missing, duplicate_action_or_refund, foreign_capture; effects: one_admission_per_run, one_quoted_debit_no_refund; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `PDC-REQ-002` | `PDC-SC-002` | Reject incomplete contradictory or admitted retrieval exemptions | `@scn_pdc_sc_002` | `test_pdc_sc_002` | `paid_delivery_cutoff_consistency` | `unit` | yes | `reference_model`; observations: five_paid_families_verified, same_payment_retrieval_blocks_exemption, unrelated_retrieval_preserves_absence; negatives: missing_census, contradictory_census, admitted_rejected_pending_unknown_retrieve, foreign_payment_cutoff_generation_source; effects: no_fabricated_delivery_or_score; evidence: source_pinned_executed_junit_contract_checks | source_pinned_executed_junit_contract_checks | `passed` |
| `PDC-REQ-003` | `PDC-SC-003` | Preserve exact sealed and composite source identity | `@scn_pdc_sc_003` | `test_pdc_sc_003` | `paid_delivery_cutoff_consistency` | `environment` | yes | `environment`; observations: actual_h3_u1_child_authority, preflight_matches_sealed_replay, legacy_hashes_unchanged; negatives: child_reference_substitution, foreign_root_execution, legacy_absence_suppressed; effects: historical_inputs_unchanged; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |
| `PDC-REQ-004` | `PDC-SC-004` | Retain task-specific outcomes and evidence safety | `@scn_pdc_sc_004` | `test_pdc_sc_004` | `paid_delivery_cutoff_consistency` | `unit` | yes | `reference_model`; observations: all_twelve_rubrics_audited, ordinary_fractional_credit, seven_nonpurchase_safety_retained; negatives: blanket_unknown_to_zero, missing_final_state_or_chain_observation; effects: no_goal_weight_price_or_deadline_change; evidence: source_pinned_executed_junit_contract_checks | source_pinned_executed_junit_contract_checks | `passed` |

## Active-delta review

- [x] Normative behavior resolves to the selected active OpenSpec delta.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] The approved proposal is review metadata; the separate manifest supplies runtime contracts.
