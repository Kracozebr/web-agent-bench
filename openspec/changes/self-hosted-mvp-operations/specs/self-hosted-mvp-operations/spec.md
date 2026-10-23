# Self-hosted MVP operations

Status: proposed. Retention duration/exemptions and external-storage deferral are user decisions; implementation mechanics in ../../design.md await scope review. All gates not_run.

## ADDED Requirements

### Requirement: OPS-REQ-001 Deploy pinned services with protected boundaries
The deployment SHALL use versioned Docker Compose profiles for the accepted application stack, pinned runtime/image/schema identities and explicit persistent volumes, networks, published ports and role/resource configuration. Participant routes SHALL NOT expose database administration, Anvil setup, backup/cleanup controls, unrestricted container-engine access or real-payment authority through test roles.

#### Scenario: OPS-SC-001 Pinned Compose startup preserves the actual persistent service graph
- **WHEN** the reviewed local Compose profile starts against dedicated synthetic persistent volumes and application/database services restart
- **THEN** actual services SHALL retain the declared database and artifact identities, expose only the configured application routes and report their pinned image/schema/profile identities without replacing persisted state with an empty installation

#### Scenario: OPS-SC-002 Participant and test roles cannot reach privileged operational surfaces
- **WHEN** public or agent routes and a test worker attempt database/admin Anvil, cleanup, backup, container-engine or real-payment control access
- **THEN** actual network/service/mount policies SHALL reject the prohibited access without protected effects and without granting an unrestricted engine socket or real-signing credentials to the public/test role

### Requirement: OPS-REQ-002 Report configuration and readiness honestly
Startup and readiness SHALL validate required configuration, actual dependency/schema state, storage roots and network/role bindings for the declared profile. Missing, stale, unsafe or contradictory prerequisites SHALL be blocked/degraded rather than reported healthy. Minimal public liveness SHALL NOT certify full dependency, provider, financial or production readiness.

#### Scenario: OPS-SC-003 Invalid configuration or unavailable dependencies cannot pass readiness
- **WHEN** required settings, schema identity, storage roots or role/network bindings are missing or invalid, a dependency fails or an optional provider remains unconfigured
- **THEN** readiness SHALL describe the actual profile's blocked/degraded/disabled boundary rather than fabricate provider success or full health, while public liveness SHALL remain minimal and failed startup SHALL not activate charge or execution work

### Requirement: OPS-REQ-003 Bound resource admission and preserve durable restart semantics
The deployment SHALL enforce reviewed worker/resource/storage limits and reserve headroom for durable application state. Actual capacity/readiness failures SHALL defer or reject affected new work before its charge/start boundary. Restart SHALL preserve existing operation/reservation/slot identities and require old executors to stop or be fenced before successor effects. Disk pressure SHALL NOT authorize early trace expiry, protected-evidence deletion or blind action/payment retries.

#### Scenario: OPS-SC-004 Container restart fences old workers and recovers durable operations
- **WHEN** actual API/worker/database processes restart around accepted synthetic domain operations and queue deliveries while a predecessor executor is delayed
- **THEN** the deployment SHALL retain original reservation/charge/run/slot identities and recover through existing domain contracts without duplicate effects, and successor work SHALL wait for the predecessor to stop or be fenced

#### Scenario: OPS-SC-005 Resource pressure applies backpressure without destructive shortcuts
- **WHEN** declared worker, memory, evidence/cache or backup/disk-reserve thresholds are reached during a bounded actual workload
- **THEN** new affected work SHALL remain unstarted/uncharged or be rejected through its real admission contract, existing recovery state SHALL remain explicit and no protected or younger-than-window log data SHALL be deleted to manufacture capacity

### Requirement: OPS-REQ-004 Expire detailed run logs safely after thirty days
Detailed internal run logs SHALL have a 30-day retention window. Under the proposed clock they SHALL become eligible only after final terminal time plus 30 * 24 hours in UTC. Active/recovering or uncertain-state runs, committed unresolved investigation holds, scores, versions, error reasons, financial/bonus history and compact evidence required for grading/provenance SHALL remain protected from this rule. Cleanup SHALL validate artifact classification, exact path containment/link safety and current hold/state ordering, persist idempotent intent/completion and preserve historical hashes with explicit availability. It SHALL NOT change scores, money or claims of evidence availability, and disposable trace bodies SHALL NOT survive beyond this rule merely through backup copies.

#### Scenario: OPS-SC-006 Thirty-day cleanup protects ongoing work holds and durable proof
- **WHEN** actual trace artifacts have declared terminal timestamps just before and at the proposed thirty-day cutoff while active/recovering runs, held investigations and protected result/financial/proof records are present
- **THEN** only correctly classified expired unheld detailed traces SHALL be purged, protected or uncertain material SHALL remain and historical paths/hashes SHALL retain truthful availability without changing outcomes or money; backup sets SHALL exclude disposable trace bodies

#### Scenario: OPS-SC-007 Cleanup races crashes and unsafe paths preserve authoritative ordering
- **WHEN** cleanup races a committed investigation hold, retries after an interrupted unlink/metadata update or receives traversal, symlink-escape, foreign-root or generation-mismatched artifact references
- **THEN** the cleaner SHALL honor hold ordering at the irreversible boundary, reject unsafe or stale targets without deleting foreign/protected files and reconcile original purge intent idempotently with actual availability rather than claiming removed bytes remain retained

### Requirement: OPS-REQ-005 Create bounded consistent local backup sets
The proposed local backup workflow SHALL bind a consistent database snapshot and required immutable files/configuration to a versioned verified manifest, excluding disposable detailed trace bodies. Missing/corrupt required files or dump failure SHALL leave the new set incomplete and preserve previously verified sets. Reviewed quota/rotation SHALL affect only declared backup resources. A local set SHALL NOT claim off-host survival or an accepted five-minute recovery point.

#### Scenario: OPS-SC-008 Local backup commits only a coherent verified set
- **WHEN** the actual local backup workflow captures a consistent database/evidence manifest while cleanup or writes run and a dump/file/hash/staging failure interrupts another set
- **THEN** only a coherent validated snapshot/file set SHALL become complete, disposable trace bodies SHALL be absent, incomplete work SHALL not replace the last verified set and bounded rotation SHALL retain required coverage within its declared roots

### Requirement: OPS-REQ-006 Restore locally without replaying external effects
An actual restore rehearsal SHALL use separate database/file volumes and verify application/ledger identities, invariant checks, required hashes and explicit availability against a selected complete local set without overwriting its source. The proposed restore entry mode SHALL fence participant mutations, signing/broadcast, automatic withdrawals and stale jobs until required state/authority/external-effect reconciliation and documented reactivation. Unknown effects SHALL NOT be blindly retried or converted into credit. Normal fresh-owner-confirmed automatic withdrawal policy SHALL remain unchanged outside restore mode.

#### Scenario: OPS-SC-009 Isolated local restore verifies application state and file coverage
- **WHEN** a selected verified local set is restored into a separate actual acceptance database/file project and a corrupt or incomplete set is also attempted
- **THEN** the real restored application SHALL match pinned account/agent/ledger/bonus/forum/result invariants and required hashes or explicit expired availability, preserve the source deployment and reject missing required recovery inputs without claiming total-host-loss coverage

#### Scenario: OPS-SC-010 Restore mode fences stale authority and uncertain monetary effects
- **WHEN** restored jobs include a previously submitted payment and stale permission state while a participant or automatic worker requests mutation or signing before reconciliation
- **THEN** the actual restored service SHALL deny mutations/broadcast and fence stale jobs, preserve the original external-operation identity for reconciliation and report unknown post-snapshot effects without retry or invented credit, with production reactivation remaining a separate documented decision

### Requirement: OPS-REQ-007 Expose private attributable operator state
Private operator status SHALL expose timestamped readiness, queue/worker/resource/storage, retention/hold/cleanup, verified-backup/restore and reconciliation observations with explicit unknown/degraded states. Owner/agent/public roles SHALL NOT obtain operator authority or private diagnostics. Logs and acceptance artifacts SHALL exclude credentials, reusable payment payloads and actual unredacted user data.

#### Scenario: OPS-SC-011 Operator status is private truthful and secret-safe
- **WHEN** operator, owner, agent and public roles inspect real health/status while observations are stale or missing and acceptance canaries exercise redaction
- **THEN** only operator authority SHALL obtain private diagnostics, public health SHALL remain minimal, missing/stale values SHALL remain unknown/degraded and emitted evidence SHALL contain no credentials reusable authorizations or actual user data

### Requirement: OPS-REQ-008 Distinguish local and actual target-host acceptance
Acceptance SHALL separately exercise actual local Compose/application/database/filesystem boundaries and the selected actual Linux deployment host with its pinned HTTPS/runtime/configuration and bounded synthetic workload. It SHALL record measured host/profile/resource provenance and secret-safe raw paths/hashes. Missing real prerequisites SHALL block their mandatory gate; local/model evidence SHALL NOT replace target-host evidence or establish capacity, off-host recovery, chain safety or whole-MVP readiness.

#### Scenario: OPS-SC-012 Actual Linux host proves its own bounded deployment boundary
- **WHEN** the reviewed profile is deployed with synthetic data to the actual selected Linux server and its configured HTTPS route for a bounded readiness restart retention and local-restore smoke workload
- **THEN** the mandatory host gate SHALL record actual OS/runtime/profile/route and measured free-resource/disk observations with separate local/host evidence, and missing host access domain runtime or observations SHALL block it rather than infer capacity or external recovery from local success
