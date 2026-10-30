# Proposed implementation tasks

Implementation approved on 2026-10-31; uncompleted tasks remain unchecked. [Approval](approval.md), [design](design.md), [BDD packet](bdd-design.md). Runtime gates remain `not_run`.

## 1. Review and freeze the boundary

- [ ] 1.1 Reconcile this packet against the cross-change index and active legacy deltas, record exact requirement/scenario amendments and obtain implementation/assertion approval; gate: artifact review, not runtime acceptance.
- [ ] 1.2 Resolve the technical prerequisites named in design.md, freeze target/profile, finite limits, migration/rollback and required native client access; gate: reviewed profile with explicit blockers.
- [ ] 1.3 Preserve a unified pre-migration checkpoint of bonuses, results, reports, screenshots and official evidence; verify migration preserves existing data and restore remains write-disabled until authorized; gate: existing backup/restore environment controls.

## 2. Add approved real adapters and implement incrementally

- [ ] 2.1 After approval only, install spec-derived Gherkin mirrors, named mapper entries and per-scenario semantic harness contracts; gate: local traceability/semantic audit, runtime still not_run.
- [ ] 2.2 Implement explain the product before sign-in at anonymous_browser_web_api; exercise all listed negative variants and independently inspect public_read_only, no_owner_or_run_creation_from_get; gate: PBD-SC-001 (environment).
- [ ] 2.3 Implement publish descriptions and grading rules for twelve task families at public_browser_validated_release_projection; exercise all listed negative variants and independently inspect read_only_public_catalog, unchanged_catalog_admission_and_grading; gate: PBD-SC-002 (environment).
- [ ] 2.4 Implement keep sealed ranked cases outside every public projection at public_http_build_artifacts_cache_private_issuance; exercise all listed negative variants and independently inspect no_sealed_material_publication, unchanged_current_task_authority; gate: PBD-SC-003 (environment).
- [ ] 2.5 Implement publish only authoritative complete ranked results at coordinator_public_readmodel_anonymous_browser_postgres; exercise all listed negative variants and independently inspect existing_idempotent_public_marker_and_best_result, no_new_scoring_formula; gate: PBD-SC-004 (environment).
- [ ] 2.6 Implement distinguish empty publication from restricted or unavailable service at anonymous_browser_public_api_manifest_cache; exercise all listed negative variants and independently inspect read_only_public_state, no_automatic_manifest_or_guard_change; gate: PBD-SC-005 (environment).
- [ ] 2.7 Implement keep public rollout separate from target beta acceptance at target_release_manifest_runtime_gate_public_http; exercise all listed negative variants and independently inspect no_unapproved_cohort_activation, unchanged_existing_beta_gates; gate: PBD-SC-006 (environment).

## 3. Prove integration before release

- [ ] 3.1 Capture all scenario observations/variants on frozen source and independently replay raw paths/hashes, then rerun affected existing BRL/BTS/BPC/AAP/BLP regressions; gate: complete environment report, missing variants non-passing.
- [ ] 3.2 Prove real browser-to-backend-to-database journeys and each applicable native client edition on the selected target; gate: source-bound target acceptance, no reference-worker substitution.
- [ ] 3.3 Exercise interruption/rollback and existing unified backup/restore for any new durable records or private files, preserving auth revocation, original identities and once-only business effects; gate: restore/restart integration evidence.
- [ ] 3.4 Review all mandatory results and unresolved external prerequisites, approve activation deliberately, then sync/archive only after all required gates pass; gate: strict validation, semantic audit, runtime closeout. No sync/archive in planning.

