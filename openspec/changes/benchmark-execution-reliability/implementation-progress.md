# Reliability implementation progress

Date: 2026-10-31 (Europe/Moscow). Implementation is approved; acceptance is incomplete.
Planning approval was committed and pushed as `f9614a8`. This note records measured
observations, not a replacement for approved scenarios or permission to sync/archive.

## Implemented boundary

- MCP accepts bounded full swap commands and maximum S2 answers: 512 KiB HTTP,
  512 recursive elements, depth 8. Authenticated malformed arguments consume their
  credential rate limit. Invalid answers allow a corrected retry of the same operation;
  issued contracts expose shape, not reference values.
- An immutable action admitted before cutoff can drain after deadline under its exact
  original run/grant/environment/generation/lease binding. Admission stays closed.
  Exact-fence cancellation resolves pre-dispatch receipts as rejected and delivered
  ambiguity as unknown, without dispatching another command or authorizing a refund.
- Closed, reconciled unknown grading is bounded to 180 seconds from durable closure;
  restart does not reset that origin. Unknown evidence remains unknown.
- Initial preparation PUT has a separate 45-second default budget and is sent once.
  Losing its response does not reconstruct credentials or repeat funding.
- Source-pinned reads can retry one known pre-response network failure within the
  original total 15-second budget. Each actual wire attempt consumes source quota.
  Economic commands, preparation PUT, HTTP/RPC errors and ambiguous responses are excluded.
- Terminal feedback preserves every persisted task, including absent grades, without
  inventing zeros, blame, regrading or refunding historical runs.

## Executed evidence

These are separate observations, not interchangeable acceptance claims. Source changes
invalidate captured-source assertions until the declared qualification is rerun.

| Observation | Result and boundary | Evidence under `artifacts/runs/` |
| --- | --- | --- |
| Targeted regressions | 113 distinct tests passed, zero failed/skipped: owner 72 with all five optional PG flags; BEF/probe/tool 34; completion/handoff/aggregate seven with both PG flags enabled. Both TypeScript checks passed. | Reproduction commands below |
| Final BEF source qualification | New application `426c7e4c...`, probe `483b241f...`; all 15 physical references, strict original case comparison, 1,701 offline source checks | [Full paths and hashes](source-refresh-qualification.md) |
| Authenticated MCP/PG | Nine actual HTTP exchanges and independent PG checks; synthetic tasks, no model/executor claim | `ber-mcp-postgres/371c9b48-6623-4629-8433-8bf86f8ffa4b/capture.json` |
| Catalog negative matrix | 21/21 actual controls; independent BTS001/002 and BER006 passed at captured source | `acceptance/BTS-SC-001/runs/889687c5-d5d0-4360-95d4-c71245ede8a8/runtime-capture.json` |
| Actual H1 cutoff | Third pay admitted 177 ms before deadline, dispatched 159 ms after; original receipt, three payments/transfers, one platform debit, all fences and no slots; 19/19 subset checks | `ber-h1-cutoff/9a1cdc66-08e0-4996-b90f-7dc7c60a3ff0/independent-observer.json` |
| Native Google Training | Actual Chrome launch, Codex CLI 0.165.0, S1/M1/H1 all known passed 1/1; 41 MCP calls, zero tool errors/local tools, once 0.5 bonus debit, all fences/no slots | `ber-native-google-training/c3effe2e-3418-4a6f-8222-c090e11d24ed/browser-model-witness.json` |
| Native Google Ranked | All 12 grades known: 11 passed 1/1, S2 partial 7/10; 179 MCP calls, no economic retries, once 1 bonus debit, all 12 fences; immutable completion recovered after the owner fix as described below | `ber-native-google-ranked/b04802cb-53d8-49f2-9974-5f32a610b3cc/` |
| Original data preservation | Verified prechange dump restored to isolated clone; exact full-row equality across ten selections for original runs/tasks/evaluations/actions/receipts/outboxes/reconciliations/closures/reports/image metadata; rechecked after native Training | `ber-original-preservation/3498f50c-bc94-4f3d-b677-f4d83b7cf63c/prechange-comparison.json` |

Native Training CLI duration was 138,369 ms including client startup; the server run
lasted approximately 92 seconds. Native Ranked CLI duration was 871,649 ms, including
read-only polling of the stuck finalization. That duration is not twelve-task execution
latency. The CLI summary conservatively says `taskOutcome: unknown`; server grades come
from the independent database observer and actual results UI.

The native Training screenshot is retained alongside its witness as
`chrome-training-results.png`. All these runs used local private-fork infrastructure
and bonus balances. They do not prove mainnet behavior or other native clients.

## Finalization incident and recovery

Native Ranked run `6f97299a-3618-437e-a96c-d8d48ea497c5` has all twelve immutable known
results, closed actions and fenced generations, but its original normal completion rolled back on
`RANKED_BENCHMARK_IDENTITY_CONFLICT`. The prior best result for this agent uses another
manifest under the same benchmark version. The rollback retained the final task as active,
the run as running and its execution slot, despite physical generations already fenced.

Read-only diagnosis:
`ber-native-ranked-completion-conflict/6f97299a-3618-437e-a96c-d8d48ea497c5.json`, SHA-256
`3d6baa40fdba1d6aebaa821ef7131ea2de881a706e531534d3bdba253e60bb15`.
The immutable observer at 01:12:59 UTC retained the unresolved state before repair.

The bounded correction allows verified immutable per-run completion while preserving
the incompatible old best pointer and never comparing different-manifest scores. Old
results, deadlines, charges and grades were not edited. Replay remains fail-closed
on inconsistent completion/result evidence. The separate discovery package owns future
cohort-aware best-result projection. Regression tests cover a higher new score, an
incompatible prior manifest, repeated completion, and corrupt or incomplete proofs.

After source qualification and normal Google-runtime restart, the original run completed
at **01:30:33.761 UTC**, retaining its original admitted release and persisted cutoffs.
The wall-clock deadline had elapsed; existing policy validates the already committed
closures/evaluations/fences before completion, without reopening task admission.
Independent before/after observation proves exact unchanged hashes for all twelve
evaluations, 45 actions, 45 receipts, one ledger debit and the old best. All twelve task
stable fields and eleven complete predecessor rows match; only U1's intended final
status/timestamp transition occurred. There is exactly one completion event, eligibility
event, handoff and result, with all twelve fences and zero live slots. The original
first-public-action marker is preserved.

Evidence root: `ber-native-google-ranked-postfix/b04802cb-53d8-49f2-9974-5f32a610b3cc/`:

- `before.json`, SHA-256 `5bc93cd301e3ca7025d4bbaa8a811b8cd111aeece309eb640bf20dcfcac974f3`.
- `after.json`, SHA-256 `4559c432939ab8293f63c99c969ac7426a026de3961c163de97ecb9743c682bc`.
- `independent-owner-final-state.json`, ten linkage checks passed, SHA-256
  `3f628fd1481aa2222715c1849d7386652a64c773c979e397b4d095bd95f43d5f`.
- `dist-first-restart.json`, all 171 compiled files match the new qualified inventory,
  SHA-256 `7d31e0ecc8485777cf48c60fdedfc0d92bc95f131c26f45a46125c5d0cec2e66`.
- `chrome-ranked-results.png`: actual Chrome refresh and View results show this run
  completed and all twelve grades, including S2 partial 7/10.

This proves native-model execution followed by normal durable completion recovery after
an owner-finalizer fix. It is not a fresh entire run on the post-fix build or full BER007.

A second controlled normal runtime restart preserved all fourteen complete row/count
sets exactly, including the same run completion timestamp, twelve evaluations, 45 actions,
45 receipts, one ledger debit, one handoff/result and 186 events; the claim stays released
and live slots stay zero. `restart-idempotency-second-restarted.json`, SHA-256
`a7dcb14f48b3641da0abe5960727d078c18038327b18a89e01b07e16e8677489`.
Both restarts matched all 171 compiled files; the second receipt is
`dist-second-restart.json`, SHA-256
`cc90abd901c0c1c10a360307ade5f3d2796412a7ec23928a541a89ec1bd87efd`.
Original participant history was independently compared again with the actual restored
prechange dump clone: all ten selections match, including both failed runs, reports and
image upload metadata. `original-preservation-after-second-restart.json`, SHA-256
`957165fcd7e81d3594b5f6f387494a3b42cffd49fa8df4d9acd9f5724d79b4b9`.
This is normal-runtime restart idempotency, not manual finalizer replay or cold image restore.
The joined browser/model/recovery receipt is
`joined-browser-model-recovery-witness-v2.json`, SHA-256
`910dac3eda268ef38afd0648fe5c9f1e9e5b43b0ee61de48a9b0810e8fe126f6`;
all fifteen referenced artifact paths and hashes were independently checked. It retains
the CLI's conservative outcome separately from durable server completion. The earlier
invalid witness assembly is preserved and superseded, not relabelled as valid proof.

The Google-local stand uses the explicit local-BEF queue policy (900 seconds). The beta
profile still requires 86,400 seconds; selected-target beta-policy acceptance is separate
from these local journeys. Neither old deadlines nor past admissions were changed.

## Retained failures and limits

- Earlier H1 preparation returned 503 at `set_payer_balance` in 9,818 ms, below the
  45-second PUT budget. Its precise historical cause remains unknown. A later final-source
  cutoff test actually exercised the intended boundary; it does not erase that failure.
- A bounded read-only source diagnosis observed a pre-response network exception against
  the former source endpoint. The current public source passed pinned-read checks.
  This does not establish a unique cause for historical H1/M4 failures or zero future faults.
- Final-source reference Full12 capture `da631c3e-094c-4c3a-ba0a-d1e3ab72e10c` stopped at
  H2 on `execution_observation_unknown` after about 15 seconds. Independent BEF evidence
  says REJECTED/NOT_SUBMITTED before signing or broadcast, but the owner API lacks that
  specific durable rejection proof. Owner therefore retained unknown conservatively.
  Ten generations were fenced; run cancelled, slot released, no cash/refund or retry.
  See its `independent-h2-failure-diagnostic.json`.
- An older Full12 worker capture `228221fd-5b4a-4f26-affb-b05cf16eead4` completed with
  11 passed and S2 partial. It uses earlier source and a reference actor; it is historical
  integration evidence, not current-source or native-model acceptance.
- Original two participant failed runs were not retried, regraded or refunded. The clone
  comparison proves DB rows and screenshot metadata, not cold screenshot-byte restoration.
  A sealed combined prechange checkpoint is retained privately.

## Mandatory remaining work

1. Extend the proven finalization restart to the complete approved recovery/replay matrix.
   Retain the owner qualification and once-only result/charge/resource invariants; do not
   treat a normal restart as proof of every interrupted durable transition.
2. Complete actual negative matrices for BER001/002 (native payloads and answer contracts),
   BER003/004 (cutoff, response loss, restart, revoke/cancel races and bounded unknown),
   BER005 (successor failures), BER007 (crash transitions/read-only/tampered replay), and
   BER008 (historical browser feedback and evidence-backed attribution).
3. Run affected legacy BDD/recovery/combined-restore gates. The H1 subset and unit/PG
   regressions do not substitute for the full mandatory scenario contracts.
4. Complete required client/target acceptance. Only Codex CLI is demonstrated here;
   Codex Desktop, Claude Code/Desktop and Hermes remain unproven.

At the latest post-finalizer qualification, BER has **one passed, seven blocked**, and BTS
has **two passed, 32 blocked**. Both aggregate acceptance wrappers exit nonzero. Later
source changes require refreshed producer capture and independent replay. Installer,
renewable authorization, cabinet/discovery and calibrated time budgets remain queued.
No sync/archive or beta-readiness claim is authorized by these partial results.

## Reproduction

Owner tests, from repository root, with isolated Docker tool profile:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml --profile tools run --rm --no-deps -e OID_COORDINATOR_DEADLINE_CLEANUP_PG_TEST=1 -e OID_TASK_ACTION_FENCE_PG_TEST=1 -e OID_COORDINATOR_LEASE_INTEGRATION=true -e OID_TASK_TRAINING_LIFECYCLE_PG_TEST=1 -e OID_RUN_CANCELLATION_BETWEEN_TASKS_PG_TEST=1 runtime sh -c 'pnpm --filter @web-agent-bench/owner-identity build && cd packages/owner-identity && node --import tsx --test src/mcp-input-bounds.test.ts src/ber-mcp-handler.test.ts src/task-feedback.test.ts src/task-execution-binding.test.ts src/bef-task-coordinator.test.ts src/bef-task-preparation.test.ts src/task-training-observation-lifecycle.test.ts src/task-action-fence-finalization.test.ts src/run-service-cancellation-between-tasks.test.ts'
```

BEF/probe/tool tests must run from `/workspace` so manifest paths resolve:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml --profile tools run --rm --no-deps runtime node --import /workspace/packages/benchmark-environment/node_modules/tsx/dist/loader.mjs --test --test-timeout=30000 packages/benchmark-environment/src/chain.test.ts packages/benchmark-environment/src/fixtures.test.ts packages/benchmark-environment/src/proxy-read-forwarding.test.ts packages/benchmark-environment/src/proxy-read-recovery.test.ts packages/benchmark-environment/src/probe/task-transfer-recipient.test.ts packages/benchmark-environment/src/probe/task-difficulty-v2-basic-capture.test.ts packages/benchmark-environment/src/probe/task-difficulty-v2-capture.test.ts infrastructure/benchmark-environment/run-difficulty-v2.test.mjs infrastructure/owner-identity/task-release-source-refresh.test.mjs
```

BDD: `.venv/Scripts/python.exe tools/run_bdd_acceptance.py --change benchmark-execution-reliability`.
Structural/semantic audits, targeted tests and full runtime acceptance remain separate.

Additional completion regression batch (seven tests, both PG gates enabled):

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml --profile tools run --rm --no-deps -e OID_TASK_RUN_COMPLETION_PG_TEST=1 -e OID_RANKED_HANDOFF_PG_TEST=1 runtime sh -c 'cd packages/owner-identity && node --import tsx --test src/task-run-completion.test.ts src/task-ranked-handoff.test.ts src/task-ranked-aggregate.test.ts'
```

The next environment acceptance slice is to extract the first two S1 cases from
`runBetaRecoveryCases` as a core-only runner: committed-response loss/recovery and
bounded exhaustion with once-only authorized compensation. The legacy collector later
requests S4/M3 as Training, which conflicts with the closed Training3 catalog; invoking
that entire helper cannot establish a green BPC gate. Preserve those legacy blockers.
Then add missing/tampered copied-artifact denial and two strictly read-only replays;
actual pending/delivered worker restart, revoke, and new admission at/after cutoff;
unknown grading across its original 180-second bound; both cancel/recovery orderings;
and interruption before the first authorized refund commit. The native finalization
restart is one subset of BER007, not evidence for these other transition faults.
