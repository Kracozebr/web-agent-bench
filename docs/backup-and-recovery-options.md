# Backup and recovery options for the single-server MVP

Date checked: 2026-10-22. Status: external storage explicitly deferred and thirty-day
detailed-run-log retention selected by the user. Other comparison/operating mechanics
remain proposals, not an accepted provider, purchase or implementation approval. Only the main server
is currently available. No storage account, bucket, credentials, backup job or
restore test has been created.

## Current decision and local planning scope

The user chose to postpone external storage. B2, R2 and other external destinations
are not selected requirements or current provisioning work. Keep their comparison
as dated research for a later decision; defer the external restore/integration gate.
Continue local MVP/operations planning without treating this as a request to stop.

For now propose bounded same-server copies of a consistent database backup and
required files/configuration, plus an isolated restore rehearsal into separate
task-owned volumes. This helps recover from some application/operator errors
while the source disk remains available; it does not establish recovery after
loss of the server or disk. Schedule, tools, backup-set rotation and disk quota still need
review. No automatic cleanup or actual backup job is authorized by this note.

The five-minute off-host database target and external transfer cadence below
remain conditional future proposals, not achieved or accepted current targets.
Local restore evidence must identify the local boundary and cannot pass an
external-storage or total-host-loss recovery gate. No substitute computer/storage
or automatic periodic download is assumed available.

## Deferred external-storage recommendation and alternatives

The earlier recommendation was a small encrypted off-host object-storage repository,
initially Backblaze B2 through its S3-compatible API, with R2 Standard as an alternative.
The user deferred this destination decision; it is not the current deployment baseline.
This adds storage rather than another application VPS. Keep a short local recovery
copy if disk permits; it does not cover loss of that server or its disks.

| Destination | Recurring storage illustration | Fit and limitation |
| --- | --- | --- |
| Same-server directory/volume | No additional storage subscription; uses the existing disk | Useful for quick rollback. Does not survive losing the server/disk and is not the off-host recovery destination. |
| Existing personal computer with space | No new storage subscription if suitable equipment already exists; bandwidth/electricity not priced | Encrypted scheduled downloads are possible, but availability/freshness depends on that computer being online. User has not confirmed spare storage. Temporary development option rather than the proposed unattended money-service baseline. |
| Backblaze B2 pay-as-you-go | Published $6.95/TB-month, first 10 GB free; illustrative 50/100 GB retained averages cost about $0.28/$0.63 per month for storage | Recommended low-volume candidate. Egress free up to 3x average stored amount, then $0.01/GB on the published route; restoration/check reads count toward that budget. |
| Cloudflare R2 Standard | Published $0.015/GB-month, first 10 GB-month free; illustrative 50/100 GB retained averages cost about $0.60/$1.35 per month for storage | Alternative with free Internet egress. Operations have separate pricing/free allowances; stay with Standard for this comparison. |

Price sources: [Backblaze B2 pricing](https://www.backblaze.com/cloud-storage/pricing),
[Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/).
Calculations assume decimal units, steady retained usage over the billing period
and an unused account free allowance. They exclude taxes, currency conversion,
possible paid operations and the server provider's outgoing traffic charges.
Free allowance is shared with other usage, not multiplied per repository. R2
also rounds billable usage to its documented units. These are storage examples,
not a prediction that this MVP's backup set will fit 50 or 100 GB.

The billed volume includes retained backup generations, WAL, encrypted file
packs, noncurrent object versions and any protected copies. It is not merely
the current live database size. Measure actual compressed size and change rate.

Hetzner Storage Box was also considered: the official page lists a 1 TB entry
capacity, SSH/SFTP and backup-tool access. The rendered page did not expose a
reliable price for the selected currency/tax location, so no price is invented.
For this small proposed footprint it is a capacity alternative rather than the
first recommendation. [Official Storage Box page](https://www.hetzner.com/storage/storage-box/).

## What to preserve

| Data | Proposed treatment |
| --- | --- |
| PostgreSQL | Preserve the full application database: owner/agent identities, rights/revocations, ledger, reserves, bonus lots/terms, payment/withdrawal identities, forum/moderation, run states, outcomes and publication inputs. This is the shared source of application accounting. |
| Required evidence and fixture artifacts | Preserve immutable referenced files and a manifest of hashes/paths/versions and backup coverage. Compact grade/provenance evidence must support retained results. Non-reconstructible fixture inputs belong here. |
| Deployment | Preserve versioned Compose/config templates, migrations, exact image/runtime references and a rebuild/restore runbook. Backups are not just a container image. |
| Secrets and recovery access | Maintain owner-controlled encrypted recovery material outside the failed server: backup decryption keys, provider account recovery and necessary application secret recovery/rotation references. Never write them into Git, test evidence or public artifacts. Separate access/recovery handling must be reviewed. |
| Disposable files | Exclude build outputs and proven-reconstructible caches/test-node scratch state. A pinned fork cache is expendable only when the required historical source/fixture can actually be reconstructed; do not assume future RPC availability. |

The user selected thirty days for detailed internal run logs. Scores, versions,
error reasons, financial history and compact grading evidence are excluded from
that expiry, and unresolved investigation materials remain protected. This does
not create a participant tool journal or a public replay surface.

The [operations proposal](../openspec/changes/self-hosted-mvp-operations/proposal.md)
proposes aging from final termination, UTC cutoff/hold ordering, safe idempotent
cleanup and availability markers. It also proposes excluding disposable trace
bodies from backups so old copies do not silently extend retention. Required
proofs remain separate and sufficient for their declared claims. These mechanics
await scope review; no files have been deleted and no cleanup job exists.

## Conditional future off-host backup mechanics

1. PostgreSQL: use pgBackRest base/incremental backups plus continuous WAL
   archiving to encrypted off-host storage. Proposed initial cadence: weekly
   full, daily incremental and retention of four full backup chains with their
   required dependent backups/WAL. Pin exact versions, retention and configuration
   after compatibility and size measurements.
2. Aim initially for no more than five minutes of database changes outside the
   verified off-host recovery point while archiving is healthy. This is a proposed
   recovery-point target, not zero-loss or an achieved guarantee. Segment switching,
   transfer time and archive errors determine actual recoverability. Observe
   archived LSN/timeline coverage and backlog; a scheduled command is not proof.
3. Immutable evidence/config files: encrypted restic backups with a proposed
   15-minute cadence and a consistent manifest. Record the latest mutually
   recoverable database/file boundary. Database recovery may be newer than file
   coverage; missing referenced evidence stays explicit, never fabricated.
4. Keep local staging/cache bounded. Upload/backup failure must surface freshness,
   failed chain coverage and disk pressure. A cost limit that stops uploads also
   stops improving recoverability; a billing alert alone is not a hard spending cap.
5. Before money use, restore into a clean isolated Compose deployment and verify
   database/ledger consistency, file hashes and service behavior. Repeat after
   material backup/schema changes and periodically; measure restore duration.

PostgreSQL PITR depends on a valid base backup and the required WAL sequence;
archiving only completed segments needs explicit low-traffic handling. Configuration
files are outside WAL recovery. [PostgreSQL 18 continuous archiving](https://www.postgresql.org/docs/18/continuous-archiving.html).
pgBackRest documents S3-compatible repositories, incremental backups, client-side
encryption and restore checks; actual provider/PG18 integration remains untested.
[pgBackRest guide](https://pgbackrest.org/user-guide.html).

For a disposable bonus-only development stage, scheduled logical dumps and file
backups are a simpler alternative. A daily dump recovers its snapshot, potentially
losing the changes since then; it is not continuous WAL/PITR recovery. Do not
present it as the proposed five-minute target for monetary operation.
[PostgreSQL SQL dump](https://www.postgresql.org/docs/18/backup-dump.html).

restic supports S3-compatible storage; its B2 guidance currently recommends the
S3 path. Test pruning/noncurrent object behavior to prevent hidden-version growth.
An integrity check and an application restore are different checks; the default
restic check does not read all stored data. [Repository setup](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html),
[repository verification](https://restic.readthedocs.io/en/stable/045_working_with_repos.html).

## Recovery and failure boundary

Proposed disaster recovery starts isolated, with outgoing signing/broadcast,
withdrawals, charged writes and old queued/executor actions fenced. A database
rollback cannot undo an already broadcast transfer, restore a lost off-chain
service debit from the blockchain, or establish that old permissions remain valid.
Do not infer a user's ledger balance from a custody-wallet balance alone.

Reconcile original deposit/withdrawal operations with canonical chain observations
and the actual signer/provider evidence before enabling money operations. Missing
post-backup internal charges/bonus changes remain an explicit discrepancy; no
blind retry or invented credit. Review recovered sessions/revocation freshness
before granting mutation authority. This is a proposed restore policy to specify,
not a change to normal automatic owner-confirmed withdrawals or the already
selected per-account reorg/recovery rules.

Restore required files against their manifest, rebuild public projections from
original exact inputs and keep missing evidence visible. In-flight runs do not
automatically resume stale workers; lifecycle recovery/refund rules still apply.
The runbook must distinguish a successful isolated restore from production
reactivation. Replacement-host availability, download speed, data size and
reconciliation time remain unknown; no recovery-time promise is made.

Encryption protects content but does not prevent an attacker holding deletion
authority from removing copies. Use separate narrowly scoped storage/recovery
authority and evaluate protected copies/retention against actual tool cleanup.
B2 Object Lock and R2 bucket locks are documented options, not configurations
enabled here. Blanket locks on mutable backup repositories can obstruct retention
or maintenance, so test the exact layout rather than assuming compatibility.
[B2 Object Lock](https://www.backblaze.com/docs/cloud-storage-object-lock),
[R2 bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/).

## Decisions still needed

For the current local scope, review consistent-copy/restore mechanics, cadence,
backup-set rotation, quotas and recovery/reactivation rules in the operations packet.
Revisit the external destination only when that deferred work resumes, then review
decryption-key custody, cost limits and real off-host archive/file recovery gates.
Account/payment availability and server connectivity to the destination need
checking; no successful integration is inferred from published S3 support.

An independent local restore rehearsal can be developed in task-owned directories;
it does not replace the actual external-storage recovery gate. This document
is now linked to the ninth planning packet, with no executable backup workflow yet.
