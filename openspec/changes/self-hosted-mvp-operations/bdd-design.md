# BDD design packet: `self-hosted-mvp-operations`

Workflow: [docs/task-design.md](../../../docs/task-design.md)

**Status:** Awaiting review and explicit scope approval.
**Normative delta source:** `specs/self-hosted-mvp-operations/spec.md`.
**Target main source after sync:** `openspec/specs/self-hosted-mvp-operations/spec.md`.
**Execution status:** all 12 mandatory scenarios are `not_run`; no executable test,
service, cleanup, backup, restore or host connection has been created by this packet.

## Intent

Verify actual single-host deployment, bounded storage/worker behavior, selected
thirty-day detailed-run-log retention and isolated local backup/restore. External
storage and total-host-loss recovery remain deferred. No five-minute target,
mainnet transfer, full task grading or automated production reactivation is claimed.

## Scenario design

All gates are mandatory `environment`. OPS-SC-001–011 require actual local Compose,
application/domain integrations, PostgreSQL and filesystem/network observations.
OPS-SC-012 separately requires the actual selected Linux host and HTTPS route.
A filesystem model, mocked container listing or local-only restore cannot replace
their named real boundaries.

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OPS-REQ-001 | OPS-SC-001 | Pinned Compose startup preserves the actual persistent service graph | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / the reviewed local Compose profile starts against dedicated synthetic persistent volumes and application/database services restart / actual services SHALL retain the declared database and artifact identities, expose only the configured application routes and report their pinned image/schema/profile identities without replacing persisted state with an empty installation | environment | yes | test_ops_sc_001 | mvp_compose_operations_adapter; actual_compose_http_postgres_volumes | bdd-harness-proposal.json#OPS-SC-001 | artifacts/runs/acceptance/OPS-SC-001/manifest.json; actual service/domain/store/filesystem/network observations | Protects the actual selected deployment and persistent data through process restarts. |
| OPS-REQ-001 | OPS-SC-002 | Participant and test roles cannot reach privileged operational surfaces | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / public or agent routes and a test worker attempt database/admin Anvil, cleanup, backup, container-engine or real-payment control access / actual network/service/mount policies SHALL reject the prohibited access without protected effects and without granting an unrestricted engine socket or real-signing credentials to the public/test role | environment | yes | test_ops_sc_002 | mvp_compose_operations_adapter; actual_compose_network_mount_role_boundary | bdd-harness-proposal.json#OPS-SC-002 | artifacts/runs/acceptance/OPS-SC-002/manifest.json; actual service/domain/store/filesystem/network observations | Prevents public/test roles from gaining administrative, container or real-funds authority. |
| OPS-REQ-002 | OPS-SC-003 | Invalid configuration or unavailable dependencies cannot pass readiness | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / required settings, schema identity, storage roots or role/network bindings are missing or invalid, a dependency fails or an optional provider remains unconfigured / readiness SHALL describe the actual profile's blocked/degraded/disabled boundary rather than fabricate provider success or full health, while public liveness SHALL remain minimal and failed startup SHALL not activate charge or execution work | environment | yes | test_ops_sc_003 | mvp_compose_operations_adapter; actual_config_startup_http_dependency_checks | bdd-harness-proposal.json#OPS-SC-003 | artifacts/runs/acceptance/OPS-SC-003/manifest.json; actual service/domain/store/filesystem/network observations | Prevents configuration and dependency failures being misrepresented as operational readiness. |
| OPS-REQ-003 | OPS-SC-004 | Container restart fences old workers and recovers durable operations | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / actual API/worker/database processes restart around accepted synthetic domain operations and queue deliveries while a predecessor executor is delayed / the deployment SHALL retain original reservation/charge/run/slot identities and recover through existing domain contracts without duplicate effects, and successor work SHALL wait for the predecessor to stop or be fenced | environment | yes | test_ops_sc_004 | mvp_compose_operations_adapter; actual_compose_worker_postgres_domain_restart | bdd-harness-proposal.json#OPS-SC-004 | artifacts/runs/acceptance/OPS-SC-004/manifest.json; actual service/domain/store/filesystem/network observations | Tests domain durability and executor fencing across actual deployment restarts. |
| OPS-REQ-003 | OPS-SC-005 | Resource pressure applies backpressure without destructive shortcuts | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / declared worker, memory, evidence/cache or backup/disk-reserve thresholds are reached during a bounded actual workload / new affected work SHALL remain unstarted/uncharged or be rejected through its real admission contract, existing recovery state SHALL remain explicit and no protected or younger-than-window log data SHALL be deleted to manufacture capacity | environment | yes | test_ops_sc_005 | mvp_compose_operations_adapter; actual_limits_filesystem_admission_boundary | bdd-harness-proposal.json#OPS-SC-005 | artifacts/runs/acceptance/OPS-SC-005/manifest.json; actual service/domain/store/filesystem/network observations | Protects admission/accounting and required evidence when finite server resources are exhausted. |
| OPS-REQ-004 | OPS-SC-006 | Thirty-day cleanup protects ongoing work holds and durable proof | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / actual trace artifacts have declared terminal timestamps just before and at the proposed thirty-day cutoff while active/recovering runs, held investigations and protected result/financial/proof records are present / only correctly classified expired unheld detailed traces SHALL be purged, protected or uncertain material SHALL remain and historical paths/hashes SHALL retain truthful availability without changing outcomes or money; backup sets SHALL exclude disposable trace bodies | environment | yes | test_ops_sc_006 | mvp_storage_restore_adapter; actual_retention_http_postgres_filesystem | bdd-harness-proposal.json#OPS-SC-006 | artifacts/runs/acceptance/OPS-SC-006/manifest.json; actual service/domain/store/filesystem/network observations | Protects the selected thirty-day window and its explicit evidence/financial/investigation exemptions. |
| OPS-REQ-004 | OPS-SC-007 | Cleanup races crashes and unsafe paths preserve authoritative ordering | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / cleanup races a committed investigation hold, retries after an interrupted unlink/metadata update or receives traversal, symlink-escape, foreign-root or generation-mismatched artifact references / the cleaner SHALL honor hold ordering at the irreversible boundary, reject unsafe or stale targets without deleting foreign/protected files and reconcile original purge intent idempotently with actual availability rather than claiming removed bytes remain retained | environment | yes | test_ops_sc_007 | mvp_storage_restore_adapter; actual_retention_concurrency_filesystem_identity | bdd-harness-proposal.json#OPS-SC-007 | artifacts/runs/acceptance/OPS-SC-007/manifest.json; actual service/domain/store/filesystem/network observations | Protects actual files and truthful audit under concurrency, crash recovery and malicious references. |
| OPS-REQ-005 | OPS-SC-008 | Local backup commits only a coherent verified set | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / the actual local backup workflow captures a consistent database/evidence manifest while cleanup or writes run and a dump/file/hash/staging failure interrupts another set / only a coherent validated snapshot/file set SHALL become complete, disposable trace bodies SHALL be absent, incomplete work SHALL not replace the last verified set and bounded rotation SHALL retain required coverage within its declared roots | environment | yes | test_ops_sc_008 | mvp_storage_restore_adapter; actual_postgres_dump_filesystem_backup_manifest | bdd-harness-proposal.json#OPS-SC-008 | artifacts/runs/acceptance/OPS-SC-008/manifest.json; actual service/domain/store/filesystem/network observations | Prevents a partial or inconsistent local copy being labelled a usable backup. |
| OPS-REQ-006 | OPS-SC-009 | Isolated local restore verifies application state and file coverage | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / a selected verified local set is restored into a separate actual acceptance database/file project and a corrupt or incomplete set is also attempted / the real restored application SHALL match pinned account/agent/ledger/bonus/forum/result invariants and required hashes or explicit expired availability, preserve the source deployment and reject missing required recovery inputs without claiming total-host-loss coverage | environment | yes | test_ops_sc_009 | mvp_storage_restore_adapter; actual_separate_compose_postgres_file_restore | bdd-harness-proposal.json#OPS-SC-009 | artifacts/runs/acceptance/OPS-SC-009/manifest.json; actual service/domain/store/filesystem/network observations | Proves the actual local database/file/application restore while preserving its source. |
| OPS-REQ-006 | OPS-SC-010 | Restore mode fences stale authority and uncertain monetary effects | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / restored jobs include a previously submitted payment and stale permission state while a participant or automatic worker requests mutation or signing before reconciliation / the actual restored service SHALL deny mutations/broadcast and fence stale jobs, preserve the original external-operation identity for reconciliation and report unknown post-snapshot effects without retry or invented credit, with production reactivation remaining a separate documented decision | environment | yes | test_ops_sc_010 | mvp_storage_restore_adapter; actual_restore_mode_http_worker_egress_fence | bdd-harness-proposal.json#OPS-SC-010 | artifacts/runs/acceptance/OPS-SC-010/manifest.json; actual service/domain/store/filesystem/network observations | Prevents a database rollback from replaying external effects or reviving stale mutation authority. |
| OPS-REQ-007 | OPS-SC-011 | Operator status is private truthful and secret-safe | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / operator, owner, agent and public roles inspect real health/status while observations are stale or missing and acceptance canaries exercise redaction / only operator authority SHALL obtain private diagnostics, public health SHALL remain minimal, missing/stale values SHALL remain unknown/degraded and emitted evidence SHALL contain no credentials reusable authorizations or actual user data | environment | yes | test_ops_sc_011 | mvp_compose_operations_adapter; actual_operator_http_cli_logs_store | bdd-harness-proposal.json#OPS-SC-011 | artifacts/runs/acceptance/OPS-SC-011/manifest.json; actual service/domain/store/filesystem/network observations | Protects operator-only observability and honest secret-safe diagnostic evidence. |
| OPS-REQ-008 | OPS-SC-012 | Actual Linux host proves its own bounded deployment boundary | Reviewed dedicated synthetic acceptance deployment and task-owned persistent resources / the reviewed profile is deployed with synthetic data to the actual selected Linux server and its configured HTTPS route for a bounded readiness restart retention and local-restore smoke workload / the mandatory host gate SHALL record actual OS/runtime/profile/route and measured free-resource/disk observations with separate local/host evidence, and missing host access domain runtime or observations SHALL block it rather than infer capacity or external recovery from local success | environment | yes | test_ops_sc_012 | mvp_actual_linux_host_adapter; actual_selected_linux_host_https_compose | bdd-harness-proposal.json#OPS-SC-012 | artifacts/runs/acceptance/OPS-SC-012/manifest.json; actual service/domain/store/filesystem/network observations | Prevents local-container observations being sold as validation of the user's actual server. |

## Semantic harness contract

[bdd-harness-proposal.json](bdd-harness-proposal.json) is a review-only inventory.
Each scenario declares boundary, named observations, negative variants and durable
effects. Add matching runtime contracts only during approved implementation;
inventory presence is not execution evidence. No private-call exceptions apply.

## Execution design

- Reuse traceability, semantic audit, pytest-bdd and evidence conventions. Reuse/
  implement active-delta harness selection from benchmark-run-lifecycle before
  claiming these gates executable; do not sync unverified deltas to bypass tooling.
- Proposed mirror: `tests/bdd/features/self_hosted_mvp_operations.feature`.
- Proposed mapper: `tests/bdd/mappers/test_self_hosted_mvp_operations_bdd.py`.
- Proposed module: `tests/bdd/adapters/self_hosted_mvp_operations.py`, with the
  three named adapter profiles from the table. Actual I/O belongs in adapters.
- Pin actual Compose/runtime/image/schema identities, selected service dependencies,
  volumes/roots, resource/disk thresholds, backup snapshot/manifest/tool/cadence/
  rotation, retention classes and hold ordering before execution. The accepted
  duration is thirty days; terminal-time clock and mechanics remain proposed.
- Use declared synthetic historical run timestamps and real stored classifications/
  files for age boundaries, not thirty days of claimed live operation. Acceptance
  may control clocks/faults privately; participant-provided dates grant no authority.
- Controlled actual domain and payment-observation fixtures support restart/restore
  checks. They do not establish CDP or Base transfer safety. Real external broadcast
  is disarmed; restored egress controls are observed without moving actual funds.
- All cleanup/backup/restore drills use verified task-owned disposable paths and
  new volumes, with preserved source manifests and explicit containment/symlink
  negative cases. They never delete user/shared roots or overwrite a source database.
- Record deployment/profile/version hashes, operation/generation IDs, actual file/
  dump/set/hash observations, purge ordering/availability and restore checks.
  Evidence contains no credentials, reusable payment payloads or real user data.
- Restore/replay compares original identities and observations without replaying
  task or monetary actions. Missing data stays unknown/incomplete; no hidden score
  or financial rewrite can make a restore pass.
- Missing local runtime/dependency or actual host/domain/access -> `blocked`.
  Violated observed assertions -> `failed`. All mandatory not_run/blocked/skipped
  gates prevent sync/archive of this scope; none implies an off-host gate was run.

## Approval boundary

Approval covers these twelve scenarios and their named actual services, file/
database cleanup/backup/restore jobs, network/role controls and target-host check.
Review proposed quotas, terminal-time aging, rotation and restore reactivation.
A changed assertion/new scenario returns for review. Actual remote work requires
the selected host/profile and approved access/configuration before execution.
No external bucket, paid service, real transfer, source-data destruction or
automatic production deployment/reactivation is included by writing this proposal.

**Decision:** pending.
**Decision reference:** no scenario/implementation approval received.
