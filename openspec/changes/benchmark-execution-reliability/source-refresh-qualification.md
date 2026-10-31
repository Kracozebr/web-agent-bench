# Source refresh prerequisite for BER-005/007

This implementation note records tooling and evidence boundaries. It does not change task goals,
grading, prices, deadlines, or the approved BDD contract. Runtime acceptance remains blocked until
fresh evidence passes the production verifiers and independent replay.

The initial diagnostic BEF changes produced application identity
`8f18173b7e86304d6dbe0c974c76b8064dad399a5c9ed674bb8028ff94d13f15`.
The previous cases bind `b9b0ff9e251ce1f423b543409a3567029c1d4e703644a3b15c8e89f5fe6bc3f9`.
The coordinator and preparation health checks intentionally reject that mismatch. Updating only
minimum-review or release references cannot make the old raw proof describe the new application.

## Immutable refresh inputs

The new offline `assemble-source-refresh-candidates.mjs` accepts
`--refresh-profile <artifact-path> --sha256 <artifact-hash>`. Its profile has exactly these fields:

```json
{
  "schemaVersion": "bts-source-refresh-profile/v1",
  "classification": "explicit_new_source_profile_not_release_acceptance",
  "reason": "ber_diagnostic_source_refresh",
  "approvedBaseline": { "path": "<approved baseline path>", "sha256": "<approved baseline hash>" },
  "feasibilityVerification": { "path": "<fresh verification path>", "sha256": "<fresh hash>" },
  "rawIntegrity": { "path": "<fresh fifteen-reference integrity verification path>", "sha256": "<fresh hash>" },
  "expectedApplicationSourceSha256": "<explicit current application hash>",
  "expectedProbeSourceSha256": "<explicit current probe hash>",
  "expectedManifestSha256": "<unchanged manifest hash>"
}
```

The approved semantic baseline is fixed to
`artifacts/runs/bts-difficulty-v2-case-candidates/0b68e103-c296-45f9-a97a-b6b8f14a44e5/candidate-cases.json`,
SHA-256 `4c66c32fb00de697b46317ad6a90dd0e0ed5b63812f9545a0fc5b03d94fc5356`.
Profiles cannot substitute another baseline. A profile must be saved as a new immutable artifact;
historical profiles, cases, witnesses, references, and failures are preserved byte-for-byte.

The initial application-`8f1817…` feasibility verification was
`artifacts/runs/bts-runtime-feasibility-verification/d0068280-2fac-41db-b573-ed8b1625212d/verification.json`,
SHA-256 `01dce56be9a5ceb9f2411a087230f440511b2e25472b2aa95fc2cf1ecc59fd72`.
Its witness is
`artifacts/runs/bts-release-feasibility-witness/12df576c-4025-4339-88ee-2faf4a50970f/witness.json`,
SHA-256 `f3946dee5e957cd633f818f7ffe5a61ff54d1335f48f6e9cc3e4781a7c64c683`.
These prove retained local feasibility, not owner execution or a resolved cause of the earlier 503.

## Exact preservation boundary

The canonical TaskCase comparison excludes only these six exact JSON paths:

- `caseHash`
- `executionIdentityHash`
- `initialStateEvidence.path`
- `initialStateEvidence.sha256`
- `referencePath.evidence.path`
- `referencePath.evidence.sha256`

Every other TaskCase field remains exact, including evidence boundaries, objectives, initial state,
final-state hash, action count, rubric, rules, weight, route, and deadline. Exclusions use explicit
property access; no recursive key-name pruning is permitted. The whole case hash is independently
recomputed before comparison.

Execution identity may differ only at `x402ServiceSha256` and `applicationSchemaVersion`. The latter
is recomputed through the existing production schema-lineage derivation. The complete sorted
migration inventory must equal the approved baseline; added, removed, or modified migrations block
this refresh. Policy bytes, including prices and expense policy, must match the approved pin.

All fifteen captures must bind one explicit current application, probe source, and manifest cohort.
Each new case must name its actual fresh capture. Production feasibility and reference verifiers
read the hash-pinned raw bytes, capability source identity, HTTP/RPC observations, receipts, and
independent generation fences. Integrity labels and producer booleans cannot replace those checks.

## Commands and remaining gates

Commands run in the existing isolated owner-identity tools container with the TS loader:

```text
node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/assemble-source-refresh-candidates.mjs --refresh-profile <new-profile.json> --sha256 <hash>
node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/verify-difficulty-v2-references.mjs --cases <new-candidate-cases.json> --sha256 <hash>
node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/review-difficulty-v2-minima.mjs --cases <new-candidate-cases.json> --sha256 <hash>
node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/assemble-difficulty-v2-release.mjs --cases <new-candidate-cases.json> --sha256 <hash>
```

After updating the explicit current input references, run the existing offline validator,
`release-bdd-runner.mjs`, and independent BTS/BER acceptance readers. Release assembly deliberately
produces an unvalidated candidate; its nonzero candidate-only exit does not authorize activation.
The historical assembler's existing `--integrity` path and frozen-baseline equality remain intact.

Focused tooling regressions: **9 passed, 0 failed, 0 skipped**. They cover semantic changes,
unknown/unsafe profile inputs, mixed or missing capture cohorts, migration changes, hash mismatch,
and symlink escape. This is offline unit proof only. Fresh fifteen-reference assembly, independent
release validation, current-source catalog21 replay, owner Training3/Ranked execution, and the
remaining BER negative matrices are separate gates.

An additional offline negative used the actual fresh feasibility verification with the actual old
fifteen-reference inventory. The loader rejected it with `refresh_mixed_or_old_capture_source`.
The new profile and rejection remain at
`artifacts/runs/bts-source-refresh-negative/9555e63f-d642-491e-9c5f-4b935e5ee8de/`;
`receipt.json` SHA-256 is `9cfb6924dd00694e959ccd9bbb06ea84cb0f3f4e1c0dc82899bb0935d1a3bcc2`.
This proves that retained old raw observations cannot be promoted through a new source identity;
it does not complete the new runtime cohort or BER environment gate.

## Decision after the historical fifteen-case inventory

The attempted application-`8f1817…` refresh stopped on Ranked S1 with
`refresh_semantic_case_changed`. Its immutable profile is
`artifacts/runs/bts-source-refresh-profile/a6f71a65-4f6b-4b71-a14c-67e778ff4ebf/profile.json`,
SHA-256 `69a0fd3d612fe89899510b2316e2b073a7e9e9bc3e1ac4ade26ffa8e865bdc6a`.
The failed composition remains under
`artifacts/runs/bts-difficulty-v2-case-candidates/cc467e9a-ea01-46e3-ae27-2a72e1b8af80/`.
No candidate release, minimum-review result, activation, or current-source acceptance follows.

A subsequent read-only historical inventory verified 1,601 indexed raw-file hashes across all
fifteen retained application-`8f1817…` references. Thirteen case cores matched exactly. Only S1
Ranked and Training differed: each reference driver generated a new ephemeral recipient, changing
`objective.recipient`, the two recipient balance-account rows, and the dependent initial/final state
hashes. Quantities, assets, rules, rubric, weights, deadlines, action counts, routes, and budgets
matched. These observations describe historical references; the later proxy source changes require
a fresh application/probe cohort and feasibility witness.

The technical decision is to retain the strict six-path comparator above. No beneficiary-role
alpha-renaming, state-hash exclusion, or BDD assertion amendment is authorized. The reference-only
S1 capture will accept an optional validated **public recipient address**, taken from the exact
approved baseline case for its mode. Its default continues to generate a fresh random recipient.
The pinned path requires no recipient private key, signer restoration, or change to participant
tools, runtime goals, grading, or prices. New reference captures must prove the original literal
recipient and exact state hashes through the existing production verifiers.

The bounded proxy changes already require all fifteen references to be captured against their new
application and probe identities. Pinning S1's approved recipient therefore fits that required
recapture; it does not substitute an amended comparison policy for missing proof. The new full
application/probe hashes, witness, and fifteen-reference inventory must be recorded before another
qualification attempt. Failed attempts and the historical fifteen-case existence inventory remain
visible; neither a later successful reference nor its reuse proves zero preparation failures.

## Final source qualification evidence

The completed refresh uses application
`426c7e4c587807f4f0fa0bbb28c7cf08a048b312cc6f1194e30f141e3805a771` and probe
`483b241f3b7c8ab2e45eeea05d9cbf635252f599254035ba9978dca0192a57ec`.
All fifteen references were captured anew for that cohort. Both S1 modes used their exact approved
public recipients. No historical application-`8f1817…` reference was mixed into this qualification.
The original strict comparator and BDD assertions remained unchanged.

| Artifact | Path under `artifacts/runs/` | SHA-256 |
| --- | --- | --- |
| Feasibility witness | `bts-release-feasibility-witness/b939eb1e-af2b-48ee-92c0-7e178c0e0f1d/witness.json` | `4fa67f88f91c3378d6b0cfe3a086b8d363a23d0962ce6bf5fdb851080c1f0e85` |
| Feasibility verification | `bts-runtime-feasibility-verification/0e027059-4b5e-4b27-8fd4-04d785d4d196/verification.json` | `29dc9356110d7a4fe1ac8c9297fb85fa006341f2fef760edb74ad764c0119ac6` |
| Fifteen-reference input index | `ber-final-reference-inputs/185479a8-3f09-4fdb-bac6-b365670dbc9e/source-index.json` | `8845157a7b9e593b1885ff9f1700286a903bc1fcac59f7722333e68efaa602c6` |
| Raw integrity verification | `bts-difficulty-v2-artifact-verification/73d430a3-a254-47d2-987c-614175365c2c/verification.json` | `da1c3bb061d0da53ffcd764fae51114249f78c11dafe6d5c3847c4d8cde3d15f` |
| Immutable source profile | `bts-source-refresh-profile/624fbbbf-4fbc-4cce-9874-8a8ecd15ea87/profile.json` | `6a2fc115def5c6ccd820498d40ab42481276508b7b738403e9c5892c75fc122e` |
| New fifteen cases | `bts-difficulty-v2-case-candidates/4786d2b5-3a98-4d94-b495-77803ecaae44/candidate-cases.json` | `d9c4fc7093fd0c96fee4de27c398502ffab18c4368aeb4e0ff76fbc2511640a0` |
| Independent semantic references | `bts-v2-reference-verification/d78447e7-21c7-41d8-ad61-74afc871d8a2/verification.json` | `5ae573ccc87c087638a7ca638c2c688016c0624035aff26f6c228558913c0540` |
| Minimum-action review | `bts-v2-minimum-action-review/fed77779-1e92-48c7-b6ae-962deb56808d/review.json` | `5057f031f5f6fd122768369630e268d02a68f98797367e9b1698ba8d4b8ffdd1` |
| New release candidate | `bts-difficulty-v2-release-candidates/ac9f9e15-76c7-4cc2-a54b-5a3b17b5ae4a/candidate-release.json` | `331d799ca8152bb0953ba0a269b92a62f360a9ea1e1c4b905ef0f3ee1b467597` |
| Offline release validation | `bts-difficulty-v2-release-validation/7b5fa924-d06f-430c-b833-397c658fcd46/validation.json` | `1c52a87c8f801c24afc4ac923f569489707ce23c0453534c11ffc91477ebe2d6` |

Case assembly, independent semantic verification, and minimum-action review each passed fifteen
cases. Offline validation returned `validated_candidate`, `sourceUnchanged=true`, 1,701 checked
source inputs, and no blockers. The tracked current input references and ignored validated pointer
were updated. This is validation of a local candidate; no original Google database activation was
performed by this qualification.

The actual release-negative producer capture `06069166-9bbe-4f13-a0c6-34e0b0381e23` used a fresh
isolated database, verified **21/21** controls, and recorded `sourceStableDuringRun=true` with zero
failed or missing probes. Its source-bound raw capture is
`acceptance/BTS-SC-001/runs/206e40b0-b025-4e03-b49f-d9e7f22229fe/runtime-capture.json`,
SHA-256 `d213cc825c67b5d8616c45d3e76edf5ff345611a6acc2e7c32ad272d8f8dd631`.
Independent BDD replay passed **BTS-SC-001**, **BTS-SC-002**, and **BER-SC-006**.
The complete BTS package still has 32 blocked scenarios, and BER has seven blocked scenarios;
both aggregate acceptance gates remain incomplete despite zero pytest failures.

A fresh authenticated HTTP/MCP/PostgreSQL check also passed nine exchanges in an isolated database:
`ber-mcp-postgres/371c9b48-6623-4629-8433-8bf86f8ffa4b/capture.json`, SHA-256
`1fb47dae077a88eb6eb46e101cae08fa5b51d37595ae9e0f80286a35e13e9f43`.
It uses synthetic tasks and proves neither participant-model execution nor a complete BER matrix.

Before claiming the same compiled source after an application restart, compare all 171 file hashes
in the ignored receipt `.local/ber-catalog-final-dist-06069166.json`, SHA-256
`46e8ac5e73d7e4a9cd96c460862dbbff4008baffd587adedb464bd3672b6f096`.
Any changed captured source requires requalification. Historical failures remain visible; these
passes do not establish zero transient failures, beta readiness, or production execution.

## Owner handoff fix: subsequent qualification

The later owner-only ranked-handoff fix required a fresh owner build and source-bound capture.
BEF application `426c7e4c…`, probe `483b241f…`, the physical fifteen-reference cohort, immutable source
profile, and case candidate `4786d2b5…` remained unchanged. The changed handoff source/tests were
absent from the existing case/reference/minimum/offline-validation pin inventories. Physical BEF
recapture was therefore unnecessary; the production readers reverified all fifteen existing cases.
The owner API was built before the new frozen-source producer capture.

Fresh artifacts under `artifacts/runs/`:

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| Semantic references, 15 verified | `bts-v2-reference-verification/66d1f016-c97d-4de2-9828-d77fd7e1076a/verification.json` | `f8496a5c519de71fc235775152ecfe089481fcc6d512568ed2b2663a556eb33b` |
| Minimum actions, 15 compatible | `bts-v2-minimum-action-review/6abf17fe-de48-4d8c-a0e4-bda7edb0fe6f/review.json` | `0ec6d40450664892370a71a818ce35fe18a695d5cca41a8b8df9898bc9e1cbad` |
| Fresh release candidate | `bts-difficulty-v2-release-candidates/5537f9d4-8581-4aef-840a-6dc6bf895ff6/candidate-release.json` | `b881088ac02df3e7bca26c3dbf82f7ca0b5113eecf0df638332ac9bef22e767e` |
| Validated candidate, 1,701 pins | `bts-difficulty-v2-release-validation/5b16c894-9d46-43d0-830b-a53879a46157/validation.json` | `55bef25ddd4e481d684989a519fafd1a2b8ec3281af3b8daa9e2c3b472ae1d32` |
| Actual release-negative raw capture | `acceptance/BTS-SC-001/runs/889687c5-d5d0-4360-95d4-c71245ede8a8/runtime-capture.json` | `40928619b744e86d70f9a461d66c8ea314e52fcc202139fc864c5a168fe2079a` |

The current input references and ignored validated pointer now select the new candidate; its bound
manifest hash is `d6bde27972a2e3c65ee45ec5d6b841b47db3f6f241e0e4bd5facab9f29954a81`.
Old admitted release artifacts, including `ac9f9e15…`, were preserved unchanged for authoritative
completion of their existing runs. No original Google database activation or startup was performed
by this qualification.

The actual isolated producer capture `3774c80e-7624-497c-927d-9013823cd1b1` passed **21/21** controls,
with zero failed/missing probes and unchanged before/after source inventories. Independent replay
again passed **BTS-SC-001**, **BTS-SC-002**, and **BER-SC-006**. Aggregate gates remain incomplete:
BTS has 32 blocked scenarios and BER has seven; neither suite reported pytest failures.

The post-handoff compiled-source receipt is `.local/ber-catalog-post-handoff-dist-3774c80e.json`,
171 files, SHA-256 `ba1122d5c18b72f0bdec90c74fad50364445c8953eb19b022392aa6d2391d12a`.
Use this newer receipt when checking a subsequent Google startup. Runtime handoff completion,
preservation of the prior personal best, and second-restart idempotency remain separate operational
checks; a catalog/source-qualification pass does not claim those effects.
