# Approved bounded backup capacity amendments

## Current approved count: 16,384 (2026-11-03)

The owner approved increasing only the official source-file cap to 16,384 and
checking 16,384 accepted / 16,385 rejected, followed by a fresh complete cold
restore without enabling writes. Full read-only discovery of the original DB
found 9,616 required source files (9,612 hash-verified official/provenance files
plus four required metadata files), exceeding the former 8,192 cap. This is a
complete selected inventory for 18 runs, including the later native run, rather
than a count of global disposable artifacts.

Proof: `.local/mcd-current-original-discovery-a9c93309-4d5a-4ec6-a731-8b226581b157/inventory.json`,
SHA-256 `56289540464c66ed927419e5900913ee6f0e95dbf849cb312dbf9a20decd1e92`.
Selected hash-verified bytes are 50,160,947; largest file 721,702 bytes. Actual
fresh freeze metadata and generated manifest size still require measurement.

Only the count changes. The 64 MiB per-file, 2 GiB total and 16 MiB manifest caps,
exact file-set/hash/path/symlink protections, encryption, source quiescence,
write-disabled clone, diagnostic helper-authority policy and external native
revocation journal are preserved. The six scoped implementation/test/verifier
files now use the approved count. Canonical Linux tests passed 16/16, including
actual materialization and byte verification of 16,384 files and rejection of
16,385 before materialization. Windows passed the count boundary but could not
create symlinks in three other test fixtures (EPERM); those failures were not
suppressed, and the same symlink cases passed in Linux. Operator summary:
`.local/ber-backup-16384-boundary-summary-20261103.json`, SHA-256
`0729b62ccbf9a986801562f40b32676ca2d5bb2f9d3f7fe75d8ad01cbd5f3ef5`.
The fresh complete original-DB checkpoint and cold restore now passed independent
byte-preservation verification: capture `c5e4ad00-5182-40c4-82d7-bbc5935c56f4`
preserved 18 runs, 45 ledger entries, seven reports, one 33,102-byte screenshot
and 9,617 official payload files including the generated manifest (55,052,641
bytes). The 98-table source fingerprints remained unchanged; the clone matched
the exact approved helper-authority exclusion policy, preserving all other
business/native/diagnostic state. The external native revocation journal matched
before/after and at independent verification. Fresh clone connections received
SQLSTATE `25006`; no app or worker was served, no BEF call or original DB write
was performed. Restore elapsed 134,775 ms is a local observation, not target RTO.

Proof: `.local/aci-pre-migration-c5e4ad00-5182-40c4-82d7-bbc5935c56f4/proof.json`,
SHA-256 `d2833ee2b199b3d43e11ecdd5b4b9fad25e334bfa25f907797933cdc96d8276f`.
[Independent verification](../../../artifacts/runs/aci-pre-migration-preservation/c5e4ad00-5182-40c4-82d7-bbc5935c56f4/independent-verification.json),
SHA-256 `5df99bf93d472d822bbd9f11e7fd1f191881340402e0347d1ade9de7f2d87d43`.
Scope remains complete stopped-source byte preservation; original runtime
activation, native client E2E and broader benchmark gates remain separate.
Historical 8,192-limit proofs below remain historical and are not relabelled.

## Historical approved count: 8,192 (2026-10-31)

Status: approved by the owner in this chat on 2026-10-31. The exact 8,192-file count amendment, retained byte limits, boundary assertions and fresh write-disabled full cold restore are authorized. Implemented after H1 qualification was committed as `2566b7d`. Nineteen focused tests and fresh complete local cold restore passed; target and restored-runtime activation remain unapproved.

The latest local source contains 13 runs, 35 ledger rows, two reports and one upload.
Its complete official evidence closure exceeds the current 4,096-file limit. Capture
`b415089a-593d-4a85-b143-57d21ac42c7e` rejected discovery at file 4,097, preserving
all original data. That is a lower bound, not a complete inventory. Older cold restore
`16f62e49-7e92-48c0-bc3f-5bf3620d3d7d` covers only the earlier eleven runs.

Approved exact scope: increase the official evidence file-count limit from 4,096 to
8,192 consistently in checkpoint creation, restore and their independent verifiers.
Retain the existing 64 MiB per-file, 2 GiB total official evidence and 16 MiB manifest
limits, exact file-set/hash checks, containment/symlink guards, encryption/key custody,
source pause and write-disabled clone. Do not omit files, repack to evade limits or
change retention, financial authority, auth revocation or publication rules.

After implementation, exercise the 8,192 accepted/8,193 rejected boundary, current size/hash
negative controls, and a fresh actual complete checkpoint/cold restore with independent
PostgreSQL/results/bonuses/reports/screenshot/official-file verification. Measure the
actual complete count and duration; if another bound is exceeded, retain explicit
blocked status. Preserve the earlier rejection and the older restore as separate proof.
Apply only after the current physical H1 capture finishes; changing infrastructure
source during that capture would invalidate its source inventory. This amendment does
not authorize writes in the restored clone or production/target activation.

## Executed verification

Production checkpoint and restore now both admit at most 8,192 official evidence
files. The independent live verifiers already used 8,192; their unrelated expired-image
scan limits were retained. Four changed files only: the two modules and their tests.
The four-file Node suite returned 19 passed, zero failed/skipped (37.39 seconds),
including actual 8,192-file materialization/receipt/every-output-byte checking and
8,193-file rejection before materialization. Size, hash, path, symlink and sealed-bundle
negative controls also passed.

Fresh checkpoint `5550a5f7-086e-459f-a3f9-bf97df38a064` preserved 13 runs, 35 ledger
entries, two reports, one upload/screenshot, and 4,426 official evidence files
(26,627,354 bytes). All 88 source and clone table fingerprints matched before/after
dump, restore and independent verification. Original data stayed unchanged. Restore
elapsed 61,932 ms; this is a local measurement, not target RPO/RTO. Restored writes
remain disabled; independent fresh owner connections received SQLSTATE 25006. The
final verifier used source and restore-volume mounts `:ro`, rehashed all files and
matched the screenshot to SQL/authenticated manifest/original and restored bytes.

[Observation](../../../artifacts/runs/ber-latest-google-preservation/5550a5f7-086e-459f-a3f9-bf97df38a064/observation.json),
SHA-256 `0aee5900d737ac047f7b1f4b7892e62feea39a0984faf9bb6de5edac91556f0c`;
[independent verification](../../../artifacts/runs/ber-latest-google-preservation/5550a5f7-086e-459f-a3f9-bf97df38a064/independent-verification.json),
SHA-256 `5eebff9be382eeeae52cd2b9430850124af30256da7ac59e07a1b0e617dd1ef1`.
The original Google runtime was subsequently restarted, with all 88 fingerprints
still equal at the independent post-start snapshot. The restored clone was not started.
Full safe-business-retry, target deployment, unattended backup and target RPO/RTO
acceptance remain separate open gates.
