# Scenario map: `s2-public-payment-disclosure`

Workflow: [`docs/task-design.md`](../../../../docs/task-design.md)

**Lifecycle phase:** `active-delta`
**Normative source:** `openspec/changes/s2-public-payment-disclosure/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/changes/s2-public-payment-disclosure/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `SPP-REQ-001` | `SPP-SC-001` | Keep free inspection and payment identity consistent | `@scn_spp_sc_001` | `test_spp_sc_001` | `s2_public_payment_disclosure` | `unit` | yes | `reference_model`; observations: provider_protocol_metadata_match, all_public_payments_complete, economic_terms_unchanged; negatives: foreign_identity, signing_material_or_task_answer; effects: no_economic_or_grading_effect; evidence: source_pinned_executed_junit_contract_checks | source_pinned_executed_junit_contract_checks | `passed` |
| `SPP-REQ-002` | `SPP-SC-002` | Reject substituted or partial public identity | `@scn_spp_sc_002` | `test_spp_sc_002` | `s2_public_payment_disclosure` | `unit` | yes | `reference_model`; observations: new_identity_strictly_validated, legacy_projection_bytes_unchanged; negatives: partial_identity, extra_field, mixed_root_offer_identity, substituted_domain; effects: historical_capture_projection_unchanged; evidence: source_pinned_executed_junit_contract_checks | source_pinned_executed_junit_contract_checks | `passed` |
| `SPP-REQ-003` | `SPP-SC-003` | Complete Ranked S2 from actual public inspection | `@scn_spp_sc_003` | `test_spp_sc_003` | `s2_public_payment_disclosure` | `environment` | yes | `environment`; observations: fresh_release_qualified, public_derived_s2_answer, known_s2_full_credit, full_run_finance_and_fences; negatives: undisclosed_identity, foreign_public_response, historical_pin_rewrite; effects: one_quoted_debit_no_refund, historical_identity_preserved; evidence: actual_boundary_capture_with_independent_readonly_replay | actual_boundary_capture_with_independent_readonly_replay | `passed` |

## Active-delta review

- [x] Normative behavior resolves to the selected active OpenSpec delta.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] The approved proposal is review metadata; the separate manifest supplies runtime contracts.
