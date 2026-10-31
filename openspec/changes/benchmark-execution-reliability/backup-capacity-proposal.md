# Approved bounded backup capacity amendment

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
