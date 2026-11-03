# Scenario map: `s2-answer-review-h1-cutoff-evaluation`

Workflow: [`docs/task-design.md`](../../../../docs/task-design.md)

**Lifecycle phase:** `active-delta`
**Normative source:** `openspec/changes/s2-answer-review-h1-cutoff-evaluation/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/changes/s2-answer-review-h1-cutoff-evaluation/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `WB-REQ-002` | `WB-SC-002` | A scorecard separates outcome cost latency safety and evidence | `@scn_wb_sc_002` | `test_wb_sc_002` | `benchmarking_core` | `unit` | yes | `reference_model`; observations: dimensions_separate, chain_evidence_unknown, task_outcome_preserved; negatives: partial_chain_evidence_not_converted_to_success; effects: no_score_dimension_collapse; evidence: source_pinned_executed_junit_contract_checks | source_pinned_executed_junit_contract_checks | `not_run` |
| `WB-REQ-002` | `WB-SC-006` | H1 grades a validated paid-child absence proof | `@scn_wb_sc_006` | `test_wb_sc_006` | `s2_answer_review_h1_cutoff_evaluation` | `environment` | yes | `environment`; observations: complete_action_cutoff, exact_payment_linkage, paid_child_proof_hash, no_same_payment_retrieve, validated_child_source, existing_h1_partial_grade, single_ordinary_handoff; negatives: unrelated_payment_retrieve, duplicate_handoff; effects: one_existing_payment, at_most_one_evaluation_and_handoff, no_refund_or_fabricated_delivery; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `not_run` |
| `WB-REQ-002` | `WB-SC-007` | Ambiguous H1 retrieval evidence stays unknown | `@scn_wb_sc_007` | `test_wb_sc_007` | `s2_answer_review_h1_cutoff_evaluation` | `environment` | yes | `environment`; observations: proof_predicate_failure, unknown_without_score, no_new_terminal_cause, payment_identity_unchanged; negatives: missing_or_incomplete_census, contradictory_proof, foreign_or_hash_mismatched_source, admitted_same_payment_retrieve; effects: no_fabricated_delivery_or_score, unchanged_payment_identity; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `not_run` |
| `OAR-REQ-001` | `OAR-SC-001` | Owner inspects a terminal S2 submission | `@scn_oar_sc_001` | `test_oar_sc_001` | `s2_answer_review_h1_cutoff_evaluation` | `environment` | yes | `environment`; observations: owner_identity, terminal_gate, retained_input_hash, exact_answer_equality, response_dom_allowlist, read_only_rows; negatives: foreign_owner, active_run_or_task, missing_input, mismatched_input_hash, hidden_field_injection; effects: no_answer_duplication, unchanged_evaluation_rows; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `not_run` |
| `OAR-REQ-001` | `OAR-SC-002` | Missing or unauthorized answer remains unavailable | `@scn_oar_sc_002` | `test_oar_sc_002` | `s2_answer_review_h1_cutoff_evaluation` | `environment` | yes | `environment`; observations: foreign_owner_denied, nonterminal_answer_hidden, missing_or_bad_hash_hidden, no_response_answer_content, no_durable_mutation; negatives: foreign_owner, active_run_or_task, missing_input, mismatched_input_hash; effects: unchanged_owner_and_evaluation_rows; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `not_run` |

## Active-delta review

- [x] Normative behavior resolves to the selected active OpenSpec delta.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] The approved proposal is review metadata; the separate manifest supplies runtime contracts.
