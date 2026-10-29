# Beta backup inventory verification

Implementation note for BPC-SC-022/026. This file describes the v1 file verifier,
the v2 combined checkpoint provider and local report-aware rehearsals. The results
below are bounded local evidence, not a passed target-host backup or restore gate.
Combined attempt R33 (`39cb93bd-8d5b-4ecd-9297-19080e876b69`) created a sealed
checkpoint and two fresh clones. The normal clone passed owner/admin report and
screenshot reads and original-operation retries. The expired clone was purged,
but its UI check failed before a complete combined result could be recorded.
The cause of that UI failure is still under investigation; the final independent
replay and physical-file verification remain pending. The callable daily rotation
implementation has focused local checks, but installation under a selected host
scheduler, unattended daily operation, off-host recovery and target-host acceptance
remain unverified.

## Current combined v2 provider

`infrastructure/owner-identity/beta-backup-local.mjs` exposes
`createLocalCombinedBackup(...)` and `runLocalCombinedBackupSchedule(...)`. The
schedule entry accepts `requestedKind: 'daily'` or `'pre_migration'`, calls the
same consistent-checkpoint provider, verifies the published source evidence, and
applies the journaled local rotation policy (seven daily/retention-sanitized
checkpoints plus the latest pre-migration checkpoint). It is a callable API, not
a standalone scheduler command: the caller must provide the source and observer
database URLs, private-data and closure paths, official evidence references,
source-build hash, runtime-secret callback, and supervised API stop/restart
callbacks. No OS timer or service registration is installed by this module.

For a restore rehearsal, `resumeSourceAfterCheckpoint: false` keeps the original
source API stopped after sealing and throughout clone verification. This prevents
source maintenance or browser polling from changing the source while it is being
compared with the checkpoint. Ordinary checkpoint callers default this option to
`true` and resume their API through the supervised callback.

Restored clones also retain `official-evidence/<original-relative-path>` after
temporary unseal cleanup. The provider verifies the complete file set, sizes and
SHA-256 values against the authenticated official-evidence manifest and its
checkpoint/build/run bindings. It copies the manifest to
`operator/official-evidence-manifest.json` and records the verified inventory in
`operator/official-evidence-restore.json`. These files have private filesystem
permissions; they are operator artifacts, not a new public evidence endpoint.
The raw reader checks both clone inventories, while the separate live replay
reads actual clone files, manifest bytes and receipt bytes under an explicitly
supplied restore root. Focused tests pass; the full combined runtime must still
prove this materialization in both real restored clones.

The runner-side call shape is:

```js
await runLocalCombinedBackupSchedule(providerOptions, { requestedKind: 'daily' });
```

`providerOptions` must be created by a supervised caller that already owns the
source API lifecycle and secret provider; this snippet is not a ready-to-run CLI.
Initialize the operator key once, then run exactly one broker process for the
shared job root:

```powershell
$repoRoot = (Resolve-Path '.').Path
$operatorRoot = Join-Path $repoRoot '.local/beta-backup-operator'
$recoveryPrivate = Join-Path $operatorRoot 'operator/operator-recovery-private.dpapi'
$recoveryPublic = Join-Path $operatorRoot 'operator/operator-recovery-public.pem'
$hostBroker = Join-Path $repoRoot 'infrastructure/owner-identity/beta-backup-host.ps1'
$composeFile = Join-Path $repoRoot 'infrastructure/owner-identity/compose.yaml'

pwsh -NoLogo -NoProfile -File $hostBroker `
  -InitializeRecoveryKey -BackupRoot $operatorRoot `
  -RecoveryPrivateKeyPath $recoveryPrivate -RecoveryPublicKeyPath $recoveryPublic

$jobRoot = Join-Path $repoRoot '.local/beta-backup-jobs'
pwsh -NoLogo -NoProfile -File $hostBroker `
  -RunJobBroker -JobRoot $jobRoot -BackupRoot $operatorRoot `
  -RecoveryPrivateKeyPath $recoveryPrivate -ComposeFile $composeFile
```

The v2 bundle contains one authenticated encrypted `checkpoint.bundle.enc`; its
payload includes the custom-format PostgreSQL dump, committed private screenshots,
official evidence files, read-only source snapshots, reconciliation record, and a
copy of the authoritative closure sidecar. The external `inventory.json` binds
the sealed payload, source snapshot, report/bonus/run operation counts and hashes,
and checkpoint kind. The separate recovery envelope contains the random bundle
key and the runtime recovery settings needed by the restored API, encrypted to the
operator RSA public key. It is stored outside the bundle. The operator private
RSA key is protected with Windows DPAPI `CurrentUser` in
`.local/beta-backup-operator/operator/operator-recovery-private.dpapi`; the public
key is at the sibling `operator-recovery-public.pem` path. This design was
interop-checked under the same Windows user profile. It does not establish
cross-user or off-host key recovery.

The runtime submits fixed job records beneath the workspace-shared
`.local/beta-backup-jobs/<checkpoint-id>/` bridge root. A single supervised host
process runs `infrastructure/owner-identity/beta-backup-host.ps1 -RunJobBroker`
with absolute `-JobRoot`, `-BackupRoot` (the operator root),
`-RecoveryPrivateKeyPath`, and `-ComposeFile` paths. The broker accepts only the
fixed `pg_dump`, fresh restore-database creation, `pg_restore`, database-existence,
and recovery-material operations; it does not run caller-provided shell commands.
Its restore path creates only a new guarded `oid_restore_<32 hex>` database and
grants the independent observer read access there. The bundle, screenshot data,
and runtime staging live on the named Docker volume mounted at
`/local-report-captures`; the Windows host bridge carries bounded job inputs and
outputs and a temporary private plaintext database dump while it is streamed
into the sealed bundle. The provider removes that dump after sealing; it does
not export a plaintext screenshot directory. Do not start a second
broker for the same job root.

The combined browser/restore flow is still pending. No result currently proves
that a bonus-funded worker run, linked report and screenshot, grade/ledger state,
restored owner/admin UI, same-ID operation retries, or expiry-only clone cleanup
all survive one combined checkpoint and two restored instances. Earlier report
and expiry rehearsals below remain separate evidence and are not combined-gate
acceptance.

The operator can verify an existing private bundle without sending mutations:

```text
node infrastructure/owner-identity/verify-beta-backup.mjs BUNDLE_ROOT INVENTORY_JSON AUTHORITATIVE_CLOSURE_JSON
```

Run with the pinned Linux Node runtime. All three arguments are operator-selected
local paths. The command reads files, emits a small JSON verification result, and
returns exit 1 on malformed inventory, missing/corrupt referenced bytes, unsafe
paths or expired unsanitized report content. It never enables restored writes.
The closure state must come from the current operator state outside the restored
database; using a pre-closure backup's state would defeat the retention check.

Legacy unsealed bundles use `beta-backup-inventory/v1` and contain a checkpoint UUID,
UTC `capturedAt`, kind (`daily`, `pre_migration`, `retention_sanitized`),
`failureDomain: same_host`, source build SHA-256, reconciliation-evidence and
database-total SHA-256 references, `betaEndedAt` (UTC or null), deletion receipts,
and a file list. Each file has a bundle-relative path, `database`, `evidence` or
`screenshot` kind, exact byte count and SHA-256. Exactly one nonempty database
dump is required. Credentials and secret-recovery material belong outside this
bundle and its inventory.

The current closure file uses `beta-report-closure-state/v1` under `schemaVersion`,
`betaEndedAt` (UTC or null) and `sourceEvidenceSha256`. This hash identifies the
operator's closure evidence; the file verifier does not independently establish
the audit event or the contents of a database dump. Expired copies require a
sanitized inventory, no screenshots, completed deletion receipts and a
`sanitizationEvidenceSha256`. A matching hash reference is not proof that SQL
content was sanitized: the isolated database restore must still verify that.

The pure `planBackupRotation` helper returns identifiers to retain/retire without
deleting files. The `runLocalCombinedBackupSchedule` entry journals checkpoint creation,
verification, retirement, and restart reconciliation; it bounds daily/sanitized
checkpoints to seven plus the latest pre-migration checkpoint and excludes
unsanitized copies past an authoritative report deadline. Its behavior has
focused unit coverage, but no host timer is installed or unattended daily run
measured. Same-host copies do not protect against loss of the host or disk.

Reproducible file-integrity tests:

```powershell
./infrastructure/owner-identity/tool.ps1 node --test infrastructure/owner-identity/beta-backup-inventory.test.mjs
```

Six tests passed in the pinned Docker runtime. Their synthetic dump/image bytes
test file integrity, containment, retention and rotation only. They establish no
database consistency, recovered ledger totals, operation idempotency, measured
restore duration or RPO.

## Local PostgreSQL rehearsal

`rehearse-local-bonus-restore.ps1 -SourceDatabase oid_acceptance_<32 lowercase hex>`
adds a narrow local rehearsal using the existing Docker PostgreSQL service. It
rejects primary database names and any fixture containing reports or uploads,
creates a custom-format `pg_dump`, restores into a newly named `oid_restore_*`
database, and compares counts and SHA-256 fingerprints of complete rows in every
public table. It also checks that the source stayed unchanged. Dumps stay under
the ignored private `.local/owner-identity/restore-rehearsals/` directory; row
contents and credentials are not diagnostic output. The source and restored DBs
are retained. No restored application is enabled.

On 28 October 2026 at 23:33 MSK, checkpoint
`1b7f5241c76c4c19956c00bc9ab9e2a0` completed with exit 0 against the retained
bonus acceptance fixture `oid_acceptance_97e0f8c3054642b9849794a5b68523dc`.
All 83 public-table fingerprints matched, including 17 codes, 10 redemptions,
11 ledger entries, 11 ledger operations and 43 ledger audit rows. The dump was
356,992 bytes; the entire rehearsal including source/restored comparisons took
222.77 seconds. This is a measured fixture rehearsal duration, not a beta RTO.
That 83-table bonus-fixture rehearsal had no reports or screenshots and therefore
does not establish report evidence restoration. Interrupted-run reconciliation,
consistent multi-store checkpoints and the daily scheduler remain unverified;
BPC-SC-022 remains blocked.

## Report-aware offline rehearsal

`rehearse-report-backup-restore.ps1` performs a local, offline report backup and
restore using the existing Docker PostgreSQL service and pinned runtime. It accepts
only `oid_acceptance_1cd165376c254469960b85ef058ab3ca`, whose local capture ID is
`1cd16537-6c25-4469-960b-85ef058ab3ca`. The source capture is unserved and its
private screenshots and authoritative closure sidecar live under
`/local-report-captures/<source-database>/`. The wrapper checks Compose identity
and permits only named offline release tools/checks; live server commands fail
closed. Owner and observer identities are verified, source snapshots run in
read-only transactions, and the exact source database must have no other client
sessions, active transactions, or long transactions.

The source is dumped without mutation. Each restore uses a newly generated
`oid_restore_<32 lowercase hex>` database; retention is exercised only in a second
fresh clone with a synthetic backdated closure sidecar. The original closure and
image set are compared with the original source-before snapshot before and after
cleanup. The source DB and its screenshot files are never used as a restore target.
Plaintext dumps exist temporarily in the PostgreSQL container and host temp space;
the saved bundle contains an authenticated encrypted dump and copied report
evidence. Its DPAPI-wrapped key is stored outside the bundle and is recovered from
that saved file using `DataProtectionScope.CurrentUser`. This demonstrates key
recovery for the same Windows user profile on this host; it is not an off-host
recovery or key-portability claim.

The two-step command is:

```powershell
pwsh -NoLogo -NoProfile -File infrastructure/owner-identity/rehearse-report-backup-restore.ps1 `
  -PreflightOnly -CheckpointId <32 lowercase hex>
pwsh -NoLogo -NoProfile -File infrastructure/owner-identity/rehearse-report-backup-restore.ps1 `
  -ContinueCheckpoint -CheckpointId <same 32 lowercase hex>
```

Checkpoint `f05253e8809d4b889d4d4dd972a850e7` completed on 28 October 2026 with
exit 0. Its append-only journal is in
`.local/owner-identity/report-restore-rehearsals/f05253e8809d4b889d4d4dd972a850e7/journal/`.
The recorded interval from `000-started.json` to `025-complete.json` is 48.86
seconds; this is one fixture run's elapsed time, not an RTO. Root's independent
read-only replay found all 88 public-table row hashes equal across the source,
restore and checkpoint; the retained source had four reports, one upload and one
24,786-byte screenshot. The restored screenshot hash and bytes matched. The
synthetic expiry clone ended with zero reports/uploads and four complete deletion
receipts while non-support tables/sequences and the source DB, closure and images
remained unchanged. The original and retention-sanitized inventories verified.

The checkpoint's capture-input map SHA-256 describes the 384-path source map from
the original local acceptance capture; it is not a Docker image or current helper
digest. Its implementation hash map covered five selected files. Review then
added raw image-chunk rejection, original-checkpoint source binding during expiry,
strict same-report retry checks, and expanded code-input hashing to all
`packages/owner-identity/src` files plus the helper, wrapper, inventory module,
package manifest and lockfile. The historical checkpoint predates those changes;
its artifact and the stale `prepared` terminal label are preserved. The corrected
guarded replay is recorded below.

Corrected checkpoint `5d1e4d201d484ed1b9839c9b9afbfa2b` completed on 28 October
2026. Its journal and evidence are under
`.local/owner-identity/report-restore-rehearsals/5d1e4d201d484ed1b9839c9b9afbfa2b/`.
The source was `oid_acceptance_1cd165376c254469960b85ef058ab3ca`; the restore
clone was `oid_restore_754bf3568e584a5096e5d5a4ec41d5ae`; retention ran only in
synthetic-expiry clone `oid_restore_b788628abcb14b2ca76b81da4b8fe626`. Source
before/after evidence matches across all 88 public-table fingerprints, the
database totals digest, and 152 helper/source implementation pins. The journal
interval was 51.94 seconds; this is one local rehearsal duration, not an RTO.

The restored clone's table and sequence fingerprints match the source. Its one
restored screenshot is 24,786 bytes with SHA-256
`b21455ad59dcec1c7f6c386917d9209c52e7961377680ca89bb564918842332f`; both the
original and retention-sanitized inventories passed file-integrity verification.
The bundle inventory SHA-256 is
`4adb4424a99ba8949936b910f7ef778301c6305d4c0ef2df1f16240c8fac6d39`; the
retention-clone inventory SHA-256 is
`9a1f9838e51449fc701fb9c3f1143d5cbfb04fb23ee7526d46c0b37790ab6056`.
The saved DPAPI `CurrentUser` key was recovered and the encrypted dump decrypted.
A tampered ciphertext was rejected without creating plaintext, and the original
ciphertext remained unchanged. The closure sidecars contain only
`schemaVersion`, `betaEndedAt`, and `sourceEvidenceSha256`.

In the disposable expiry clone, the synthetic backdated closure produced zero
reports, uploads, and image files, with four complete deletion receipts and no
failed report receipts or pending upload-GC receipts. Non-report table and
sequence fingerprints, the source database, closure, and source images remained
unchanged. The source fixture has no grade/ledger restoration proof, and the
restore verifier did not start the application. The run also does not test exact
HTTP deadline behavior or target-host enforcement against old-backup resurrection.

This fixture has no benchmark-run/bonus ledger rows, so it proves no bonus restore
or official grade/ledger preservation. The retention closure was synthetic and
clone-only. The run does not establish a daily scheduler, off-host backup,
cross-user key recovery, production RPO/RTO, or the full BPC-SC-022/026 gate.

## Independent combined-restore replay

`tools/replay_bpc_combined_restore_live.mjs` independently checks a completed
combined-restore capture against read-only PostgreSQL snapshots and the physical
source, normal-clone and expired-clone files. Run it in the pinned Docker runtime
with the report-capture volume mounted; replace the two identifiers with the
capture ID and source database recorded in `capture.json`:

```powershell
$captureId = '<capture-id>'
$sourceDatabase = 'oid_acceptance_<32 lowercase hex>'
docker compose -f infrastructure/owner-identity/compose.yaml `
  -f infrastructure/owner-identity/compose.reports-acceptance.yaml `
  run --rm --no-deps runtime `
  node /workspace/tools/replay_bpc_combined_restore_live.mjs `
  "/workspace/artifacts/runs/beta-combined-restore/$captureId/capture.json" `
  --source-private-dir "/local-report-captures/$sourceDatabase/private-data" `
  --restore-private-base /local-report-captures/beta-restores
```

The helper requires explicit private roots and uses the runtime's read-only
observer connection. A verified result is local replay evidence for that capture;
it does not promote the BDD gate or establish target-host, off-host, or production
recovery acceptance.
