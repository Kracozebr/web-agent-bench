# Scenario map: `web3-agent-bench-baseline`

Workflow: [`docs/task-design.md`](../../docs/task-design.md)

**Lifecycle phase:** `synced-main`
**Normative source:** `openspec/specs/*/spec.md`
**Acceptance evidence:** `tests/bdd/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `WB-REQ-001` | `WB-SC-001` | A benchmark run records reproducible identity and trace | `@scn_wb_sc_001` | `test_wb_sc_001` | `benchmarking_core_adapter` | `local` | yes | `reference_model`; observations: run_identity_present, event_sequence_ordered, event_payloads_hashed; negatives: missing_run_identity, unordered_event_sequence; effects: run_record, normalized_event_trace; evidence: deterministic reference run record | deterministic reference run record | `not_run` |
| `WB-REQ-002` | `WB-SC-002` | A scorecard separates outcome cost latency safety and evidence | `@scn_wb_sc_002` | `test_wb_sc_002` | `benchmarking_core_adapter` | `local` | yes | `reference_model`; observations: dimensions_separate, chain_evidence_unknown, task_outcome_preserved; negatives: unknown_collapsed_to_failure, unknown_collapsed_to_success; effects: scorecard, evidence_status; evidence: reference scorecard with partial chain evidence | reference scorecard with partial chain evidence | `not_run` |
| `WB-REQ-003` | `WB-SC-003` | The same seed produces a comparable replay | `@scn_wb_sc_003` | `test_wb_sc_003` | `benchmarking_core_adapter` | `local` | yes | `reference_model`; observations: same_canonical_inputs, original_evidence_retained, replay_marked_separately; negatives: different_seed_replay, original_trace_overwritten; effects: original_run, replay_run; evidence: reference replay comparison | reference replay comparison | `not_run` |
| `WB-REQ-004` | `WB-SC-004` | Incomplete chain evidence remains explicitly unknown | `@scn_wb_sc_004` | `test_wb_sc_004` | `benchmarking_core_adapter` | `local` | yes | `chain_observation`; observations: raw_evidence_reference_preserved, chain_effect_unknown, unknown_not_success; negatives: missing_receipt_classified_success, provider_ambiguity_hidden; effects: transaction_intent, reconciliation_candidate; evidence: reference fixture representing an unverified chain observation | reference fixture representing an unverified chain observation | `not_run` |
| `PV-REQ-001` | `PV-SC-001` | A PvP match starts only after both agents are ready | `@scn_pv_sc_001` | `test_pv_sc_001` | `realtime_pvp_adapter` | `local` | yes | `match_authority`; observations: one_sided_rejected, match_started_after_both_ready, rules_snapshot_immutable; negatives: one_agent_not_ready, rules_mutated_after_start; effects: match_identity, rules_snapshot; evidence: reference match authority state and immutable snapshot | reference match authority state and immutable snapshot | `not_run` |
| `PV-REQ-002` | `PV-SC-002` | Accepted PvP actions have authoritative monotonic order | `@scn_pv_sc_002` | `test_pv_sc_002` | `realtime_pvp_adapter` | `local` | yes | `match_authority`; observations: monotonic_sequence, authority_timestamped, deadline_decisions_recorded; negatives: client_timestamp_reordering, missing_deadline_decision; effects: accepted_event_log, deadline_outcomes; evidence: reference authority event log | reference authority event log | `not_run` |
| `PV-REQ-003` | `PV-SC-003` | A late action cannot mutate a terminal match | `@scn_pv_sc_003` | `test_pv_sc_003` | `realtime_pvp_adapter` | `local` | yes | `match_authority`; observations: terminal_result_stable, late_action_recorded, accepted_history_preserved; negatives: reconnect_resets_clock, late_action_changes_winner; effects: terminal_result, rejection_event; evidence: reference terminal match state and post-terminal event | reference terminal match state and post-terminal event | `not_run` |
| `PV-REQ-004` | `PV-SC-004` | Retrying settlement produces one durable outcome | `@scn_pv_sc_004` | `test_pv_sc_004` | `realtime_pvp_adapter` | `local` | yes | `settlement`; observations: stable_outcome, single_effect, dedup_key_recorded; negatives: duplicate_retry_effect, ambiguous_provider_result; effects: settlement_intent, deduplication_record; evidence: reference settlement record with duplicate submission | reference settlement record with duplicate submission | `not_run` |

## Source transition

- [x] Normative behavior resolves to synchronized main capability specs.
- [x] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [x] No executable reference targets an active change path in this baseline.
