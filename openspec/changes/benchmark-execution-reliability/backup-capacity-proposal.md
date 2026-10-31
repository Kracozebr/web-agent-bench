# Approved bounded backup capacity amendment

Status: approved by the owner in this chat on 2026-10-31. The exact 8,192-file count amendment, retained byte limits, boundary assertions and fresh write-disabled full cold restore are authorized. Implementation is queued after the current H1 physical capture; no backup/restore code is changed yet.

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
