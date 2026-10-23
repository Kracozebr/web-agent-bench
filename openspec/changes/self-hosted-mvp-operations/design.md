## Context

Status: proposed; no executable test, Compose service or server connection has
been created. The accepted stack is TypeScript/Next/Fastify/PostgreSQL/pg-boss,
controlled x402 and Anvil, Caddy and Docker Compose on Ubuntu 24.04 LTS by default
or Debian 13. The reported server has 16 CPU/32 GB RAM; actual free resources,
disk behavior, domains and container readiness remain unverified.

The user deferred external backup storage and selected 30 days for detailed
internal run logs, excluding scores, versions, error reasons, financial history,
compact grading evidence and unresolved investigation materials from that expiry.
Other planning packets own domain behavior; this packet verifies deployment,
retention and local recovery without redefining those authorities.

## Goals / Non-Goals

**Goals:** actual reproducible service boundaries, honest readiness, bounded
resource use, safe selected retention, consistent local copies/restore and an
actual target-host check with secret-safe evidence.

**Non-Goals:** external storage/provider selection, total-host-loss coverage,
high availability, a five-minute recovery guarantee, full task grading, new
financial rules, real-funds execution during drills or automatic disaster reactivation.

## Decisions

### 1. Pin profiles and protect service boundaries

Use one versioned Compose definition with explicit local acceptance and server
configuration. Pin image/runtime references, migration/schema identity, persistent
volumes, published ports, resource budgets and environment/tool policy. Test and
real-payment service identities, networks, credentials and volumes stay distinct.
Expose Caddy/application routes; PostgreSQL, Anvil administration, backup/cleanup
controls and the container-engine socket are not participant interfaces.

The public API must not gain unrestricted container orchestration through a
Docker socket. Start with a reviewed bounded private executor service/pool whose
actual isolation is checked, not assumed from its process name. Persistent mounts
are explicit; ordinary process restart must not recreate an empty database.
Only task-owned disposable acceptance resources may be removed during a drill.

Configuration checks reject missing required secrets, wrong network/role bindings,
schema mismatch, unsafe published administrative ports or invalid storage roots.
Readiness distinguishes required local dependencies from unconfigured optional
features and actual external integration status. A local provider fixture is not
CDP/Google readiness evidence. Liveness alone cannot certify healthy accounting.
Actual HTTPS/domain configuration is required for the target-host gate; no domain
or certificate is registered by this plan. Local tests use a declared test profile.

### 2. Resource limits, restart and migration handling

Begin with one admitted benchmark environment as the proposed operating default;
increase only after measurement. Pin CPU/RAM/process/task limits, evidence and
cache quotas, backup staging space, disk reserve and admission thresholds before
execution. Numeric thresholds must fit observed headroom, not all reported RAM.
Use backpressure when required storage/worker capacity is unavailable; do not
charge/start an unready run, delete protected evidence or fabricate a successful
operation to make health green. Evidence failures follow lifecycle reconciliation.

Restart actual API/worker/database containers during bounded synthetic workloads.
Verify durable reservations/charges, completion identities, per-agent slots and
executor generations through the existing modules. A restarted queue delivery
does not authorize replay of an uncertain chain or financial action. Recovered
old workers must be stopped/fenced before successors obtain effect authority.

The runbook pins migration compatibility and backup/preflight steps. A failed
schema/image change cannot be labelled ready. Rollback uses compatible images
or isolated restore/reconciliation; do not assume destructive down migrations
or database rollback can reverse external side effects. This packet adds no
automatic production upgrade, cloud provisioning or mainnet deployment action.

### 3. Selected thirty-day log scope

Separate disposable detailed run traces from durable compact domain evidence at
write time. Proposed aging rule: eligible only after a final terminal run timestamp
plus 30 * 24 hours, compared in UTC. Queued/active/evaluating/recovering runs are
not eligible. Missing or contradictory terminal time blocks cleanup, not retention.
This clock and the batch/race mechanics are engineering proposals; the 30-day
duration and named exemptions are user-selected.

Preserve scores, achieving/configuration versions, error reasons, financial and
bonus history, exact scoring inputs, required receipts/state proofs and compact
provenance manifests. Preserve materials under a committed unresolved review or
incident hold. Releasing a hold makes already aged material eligible under the
same original clock; no extra 30 days is implied by this proposed rule. Unknown
classification is protected pending review, not assumed disposable. Do not evade
the window by labelling every full trace a compact grading record.

Compact evidence must remain sufficient for its declared grade/provenance claim;
a hash alone cannot replace an observation needed to verify it. If that boundary
has not been designed or verified, preserve the needed source material. Detailed
tool logs never become the participant journal/public replay deferred by the user.

### 4. Safe idempotent cleanup and evidence availability

Track run/artifact identity, class, final timestamp, hold revision, exact configured
storage root, digest, availability and purge intent/completion. Cleanup uses only
allowlisted task-owned trace paths after containment and link/alias validation;
caller-supplied paths and mounted foreign roots are not deletion authority.
Reject traversal, symlink escape and protected-file references before mutation.

Serialize cleanup authorization with hold/state changes and recheck protection
at the irreversible boundary. A committed hold before that boundary wins. If a
hold request arrives after an already committed purge boundary, report actual
availability and the established ordering; never claim missing files are retained.
Retain durable purge intent so a crash between unlink and metadata completion
can reconcile actual file presence/digest and mark completion without deleting
another generation. Repeated cleanup is idempotent. Mismatch or unknown path/state
stops that item's deletion and is visible to the operator.

Keep original evidence paths/hashes as historical identity with explicit
`expired_by_policy`/missing status and purge timestamp/reason, not as live links
or proof that the bytes remain available. Cleanup changes neither score nor
eligibility, money nor original evaluation records. Active recovery/review material
must not be purged merely because disk is full. Pause new affected work instead.

Backups must not secretly extend the detailed-log window: exclude disposable raw
trace bodies from local backup sets, keep them outside backed-up DB payloads and
preserve only protected compact evidence/availability metadata. Audit the actual
backup contents. Old copies containing such traces require an explicit migration/
retention plan rather than silently preserving them beyond the selected window.

### 5. Bounded local backup sets

Proposed minimal local tool is a PostgreSQL-native consistent logical dump plus
required immutable files and a manifest; this tool/cadence choice is not approved
by accepting 30-day log retention. Propose daily sets and a pre-migration set,
retaining at most seven complete daily sets subject to a reviewed quota; exact
cadence/count/space behavior must be pinned before acceptance. Preserve the last
verified usable set if a new attempt fails, and report stale coverage/space pressure.
No automatic deletion of unrelated data is part of backup rotation.

Use one database snapshot identity for the dump and selected evidence references,
protecting required files from cleanup until the set is validated. Write immutable
evidence before making its database reference authoritative. Record schema/image
versions, roles/restore prerequisites, backup timestamp, hashes and file coverage.
An artifact already explicitly expired at that snapshot is recorded as such;
missing required compact evidence makes the set incomplete. A file-copy exit code
or an existing dump filename is not a verified complete backup.

Exclude raw live database-directory copying while PostgreSQL is running. Source
data/config credentials and decryption-key recovery are separate protected operator
material, never public evidence. Real backups contain private application data;
access/storage protection and secret recovery must be pinned and reviewed. Tests
use synthetic identities only. The external B2/R2/pgBackRest/WAL design stays deferred.

### 6. Actual isolated local restore and financial fencing

Restore a selected verified set to new named database/file volumes in a separate
acceptance project. Verify ledger/reservation/bonus invariants, owner/agent/forum
and versioned score records, required file digests and availability markers through
the actual application. Do not overwrite the source deployment during the drill.
Record set ID, snapshot/manifest hashes, image/schema versions and restore duration.
Missing/corrupt inputs fail or block that restore; preserve other usable sets.

Proposed restore mode starts with participant mutations, payment signing/broadcast,
automatic withdrawals and old jobs/workers fenced. Verify an already submitted
operation is not submitted again by restored queued state. Consult canonical
external/signer observations through existing reconciliation contracts before
enabling monetary operations; a wallet balance alone cannot reconstruct internal
spends, grants or lost revocations. Check recovered authority freshness before
allowing mutations. Unresolved post-snapshot effects stay explicit.

This changes the restore entry mode, not ordinary automatic withdrawals after a
fresh owner proof. No arbitrary per-withdrawal admin approval is introduced.
Production reactivation needs a documented operator decision after the required
checks; this packet does not automatically reactivate mainnet. The acceptance
drill uses controlled payment observations and denies actual external broadcast.

The database/file backup point may be hours old; no accepted loss window or
recovery-time guarantee exists. Local restore proves only that retained local
bytes can be used while the server/disk remains available. It is not a substitute
for the explicitly deferred off-host/total-host-loss gate.

### 7. Private operator status and actual target-host evidence

Provide a private operator CLI/status surface with dependency/readiness state,
queue/worker age, resource/disk/trace/backup usage, last verified set/restore,
retention holds/purge failures and financial reconciliation backlog. Preserve
timestamped provenance; absent/stale observations are unknown or degraded rather
than green/zero. Public health returns minimal liveness only; owners/agents cannot
read private operator details. Logs/evidence omit credentials, reusable payment
payloads and real unredacted user data. No paid monitoring or messaging channel
is selected by this packet.

All twelve scenarios are mandatory environment gates. OPS-SC-001–011 require
actual local Compose/application/database/filesystem boundaries, not model-only
adapters. OPS-SC-012 separately requires the real selected Linux server, HTTPS
route/configuration and bounded synthetic workload with measured available
resources. No user data or actual funds are necessary. Missing host access,
required runtime or domain blocks the target gate; local success cannot replace it.
Record actual OS/runtime/profile/image/config identities and observations without
publishing server credentials/IP access details. No capacity, money safety or
whole-MVP readiness claim follows merely from this operations gate.

## Risks / Trade-offs

- [Local copies are mistaken for host-loss recovery] -> label the exact same-host
  boundary and preserve external storage as deferred.
- [Cleanup destroys grading/recovery evidence] -> separate classes, protect holds
  and needed proofs, record availability and test actual filesystem races.
- [Restore replays already executed transfers or stale grants] -> restore fencing
  and reconciliation before reactivation, with explicit unresolved effects.
- [Backups retain expired full traces] -> exclude disposable bodies and inspect
  actual set contents; retain only the separately protected proof set.

## Migration Plan

After explicit scope approval, pin configuration and add acceptance profiles,
retention/backup metadata and bounded jobs. Classify existing artifacts and preview
eligibility before enabling cleanup; protect unknown classes. Test restore into
new volumes and keep source data intact. Rollback disables new cleanup/backup jobs,
fences workers and retains manifests/evidence; already deleted trace bytes cannot
be recreated by rolling back metadata. Actual host deployment is a separate
observed step within the approved scope, not performed by writing these files.

## Open Questions

Pin domain/host/runtime access, storage roots/quotas, service resource limits,
backup protection/cadence/count, snapshot/file consistency mechanism and operator
reactivation evidence. Review the proposed terminal-time clock and purge ordering.
External storage and exact recovery targets remain deferred/open, respectively;
all current gates are not_run.
