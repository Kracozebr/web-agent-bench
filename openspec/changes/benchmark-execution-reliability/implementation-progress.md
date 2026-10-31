# Reliability implementation progress

Date: 2026-10-31 (Europe/Moscow). Implementation is approved; acceptance is incomplete.
Planning approval was committed and pushed as `f9614a8`. This note records measured
observations, not a replacement for approved scenarios or permission to sync/archive.

## Current continuation status (2026-10-31)

Local recovery qualification is complete for BER-SC-003/004/006/007 at the source
qualified below. The aggregate wrapper records **4 passed / 4 blocked / 0 failed
assertions**, unchanged harness sources, and exits nonzero because mandatory gates
001/002/005/008 remain blocked. Tasks 2.4, 2.5, 2.7 and 2.8 are checked; total 6/16.
Native negative matrices, successor preparation negatives, historical feedback and
source-bound target/client acceptance remain open. No sync/archive or beta activation.

H1 covers all eight physical variants and all thirteen independent facts, with one
incomplete transport-failure attempt explicitly retained. Twenty-seven independent
raw-copy/assembly tests pass without skips. Original producer inputs are identical
across both H1 captures (469/469). Source-linked funding includes actual grant/code/
redemption rows, owner, balance availability and chronology; a prior authorized refund
can fund a later run without permitting foreign or future grants.

The approved backup-capacity amendment is now implemented and verified in a separate
post-`2566b7d` tooling profile: 8,192-file bound, unchanged byte guards, 19 passing tests,
and fresh complete local cold preservation of 13 runs/35 ledger entries/two reports/
one screenshot/4,426 official files. All 88 source/clone tables match; clone writes are
disabled. This is not full target, safe-business-retry or restored-runtime acceptance;
tasks 1.3 and 3.3 stay open for their broader required boundaries. Original Google
runtime has been restarted and its post-start 88-table fingerprint remains identical.
See [capacity amendment and evidence](backup-capacity-proposal.md). Qualification at
`2566b7d` remains source-bound; the capacity change creates a new inventory, so final
combined acceptance must be repeated on the eventual frozen release, without old-source
hash exemptions.
Historical entries below preserve earlier captures; their source-qualified scope and
explicit non-passing states are not superseded by a green aggregate claim.

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

## Recovery follow-up on 2026-10-31

The additional actual fault experiments found an owner coordinator defect, rather
than an RPC explanation inferred from an old failure. Capture `dab219e7-0d69-45db-83c9-95d9315ddda4`
closed H1 with a missing receipt, restarted the API and cancelled the run after
7.190 seconds as `coordinator_executor_session_lost`, before the original 180-second
observation deadline. Its failed raw evidence is retained. The fix qualifies the
original closed task, current access/claim/slot, fully reconciled action cutoff,
closure journal and validated execution binding before preserving only the
remaining observation window. It does not restore an economic executor or extend
the original deadline.

Fresh actual capture `8c0b1537-f943-45f6-8943-9f6f532d9b6b` then retained unknown
after restart and cancelled as `coordinator_evaluation_unknown` after the original
deadline, without an H1 grade, publication or refund. All nine generations were
fenced and the execution slot released. Independent replay verifies this case;
it remains one of five required unknown-grading variants, not a complete BER004.
The coordinator/binding regression batch passed 25 tests with both PG gates enabled.

S1 committed-response loss recovered the original action without economic replay.
An exhaustion experiment also reached the original recovery deadline and one
official refund. Its outer capture failed a fixture assumption: a residual bonus
made the second reservation span two sources, correctly producing two refund
ledger rows for one official refund. The new core-only fixture funds the exact
validated quote; the failed original is retained. First-refund interruption still
requires a fresh complete physical capture.

The first extended H1 experiment, `ee5bf660-fec8-430a-89d3-99d48bfa2fee`, again
proved unknown survived a cold restart, but the extra first-grade interruption
probe failed before its after-stop checkpoint. Isolated clone diagnostic
`d506529e-fb22-4675-8979-ee7eaef0dd91` reproduced the cause without business writes:
with PostgreSQL `client_connection_check_interval=0`, a backend awaiting a table
lock can outlive its killed client until the lock is released. A 100 ms setting
on that client session detects the disconnect while the barrier remains held.
The acceptance runner now awaits actual process exit and applies that setting
only to isolated BER fault API connections. Product defaults and deadlines are
unchanged; the fault experiments must be rerun against these final sources.

Two independently executed read-only replays reconstruct the retained Training3
and Ranked12 history, with 132 filesystem inputs and the scoped PostgreSQL rows
unchanged. Missing, tampered and wrong-generation artifact copies are rejected.
Seven actual completion/late-callback probes on a disposable completed-run clone
preserve all 19 business sets and make no executor call. These are historical
replay and current-service callback evidence, not a new native-client benchmark
or proof of every interrupted transition. Final reader self-hashes, physical
matrices and the BDD report must be refreshed before closing any additional task.

The next fresh experiment, `528a929a-9599-49f3-b468-ed525e98fb8e`, independently
passed the actual first-grade interruption: capture
`f680d782-17f5-45fe-9914-cb8bf9846688` records the blocked first H1 evaluation,
actual process death, PostgreSQL rollback while the barrier remained held and
normal restart committing exactly one original grade. It subsequently graded
H2/H3, but its Full12 tail failed at U1 `approve` action
`b4055978-1313-440f-8b86-1468f9072dfa`: empty HTTP 502 after 5.004 seconds.
Independent BEF inspection found no operation or selected-execution row for that
exact generation/idempotency hash. That absence does not prove the historical
network cause or authorize economic retransmission. The original run was not
resurrected and is not a complete BER004 or fresh Full12 baseline.

The acceptance transport proxy now retains bounded, secret-free error codes and
lookup/connect/response timing for future proxy-generated failures. Three actual
loopback tests pass, including one upstream socket reset producing one request,
empty 502 and a matching `ECONNRESET` witness without headers, query strings or
bodies in evidence. This diagnostic addition does not establish the earlier
502's cause. The final unknown matrix also adds a first-owed Ranked handoff
interruption; retained normal-restart narrative alone is not causal proof of
that specific crash boundary.

The next frozen Full12 attempt, `19a246ee-091f-4459-ac8a-d45aa40fd042`, did not
reach H1: M2 `inspect_catalog` was rejected before execution because BEF health
was unavailable. The original 502 and this health failure remain unexplained;
no DNS, gateway or public RPC cause is asserted. Three hundred sequential GET
`/healthz` requests through the same three-overlay transport profile then passed.
That idle diagnostic does not prove availability under task load. Generic proxy
diagnostics are now retained on both unknown-matrix success and failure.

Fresh core capture `77be0277-9158-4214-b795-2579f90f6577` passed both S1 experiments
on 469 stable producer inputs: original committed-response recovery without a
new command, and original-deadline exhaustion with a crash before the first owed
refund commit. The latter observed an actually blocked refund writer with zero
official/ledger refunds, stopped the API, observed writer rollback before releasing
the barrier, and restarted normally to exactly one official and one source-ledger
refund. All original source effects remained unchanged. Independent verification
passed eight applicable core facts and the first-refund interruption fact:
`artifacts/runs/ber-fault-recovery-core/77be0277-9158-4214-b795-2579f90f6577/independent-verification.json`,
SHA-256 `dfc76dfd51f66713bda59fe1db1f2241eeb0259fd296af9c320c1660f14fac8a`.
Three copied evidence attacks—an early committed refund, a surviving writer and
changed refund units—were rejected. Twenty Python tests passed without skips.
This closes the core/first-refund subset only; complete BER003/004/007 still
require their remaining actual variants and a fresh Training3/Full12 baseline.

The H1 qualification instrumentation required additional corrections before a
final-source gate. A split x402 payment uses an unsigned HTTP 402 challenge and
one signed settlement request; two POSTs do not mean two payments. The proxy now
records their separate response status/hash, ordered timestamps and a boolean
payment-proof presence, retaining no proof value. The fault targets the exact
bound `/tools/:environment/pay` route. Four loopback tests pass, including a
signed settlement response withheld only after the complete upstream response.
The old H1 collectors `0b9e0e0f-ce1b-4eb5-8c77-f88f61e33da7` and
`cfd13565-133a-40ca-b8ae-f98082d57288` remain aborted diagnostics with individual
raw cases; they have no complete after-source inventory or full acceptance claim.
These harness changes also require a final-source core/refund recapture; the
successful `77be` experiment remains historical positive evidence.

Stopping `cfd` exposed an operator race: another fixture run entered after a
point-in-time idle check but before container termination. Its original history
was retained. A narrowly scoped normal cold coordinator, without restored actor
credentials or direct business SQL, observed the original pending payment,
preserved its newly persisted 180-second recovery window, and performed the
normal exhaustion/fence/refund/resource-release path. The cleanup proof is
`artifacts/runs/ber-orphan-normal-worker-cleanup/3dfa3d20-4b45-4a50-8f2a-3bcb0703310d/cleanup.json`,
SHA-256 `0295c1df2ecd99945ace54fddf69f7e7c0a879a9c245f515dc8bd826629a09cc`.
Independent post-cleanup observation found zero active generations, preparations,
runs, slots or unfenced leases. This is cleanup evidence, not a completed H1
benchmark or a substitute for the named third-payment scenario. Do not stop a
collector based only on an earlier idle observation; let its resource-checked
case boundaries and final cleanup complete.

The corrected cutoff matrix uses observable transaction boundaries: before the
original deadline, the third action is admitted; at the boundary, a fresh request
itself commits the deadline cutoff and is denied; after an independently observed
committed cutoff, another fresh request is denied. Identical wall-clock
milliseconds were an implementation-added overconstraint, not an approved
requirement. No timestamps are backdated. Pending/revoke tests pause only the
isolated local coordinator through its existing configuration, preserving the
API auth environment and real deadline maintenance, then resume the normal cold
worker. This avoids a test-created outbox-lock/worker-lock cycle. Delivered-loss
tests hold the original pending action until after the original deadline, release
the gate, and independently observe an actual unknown cutoff before restart.
Verified recovery clock exclusion remains separate from the immutable recovery
deadline; an unknown action can legitimately produce an unknown closure and no
grade. Two independent complete static reviews passed before starting the fresh
matrix `0bc4b3b6-038a-4d2f-8599-ed64b729d5ea`; runtime acceptance remains pending.

That collector independently passed the before/at/after transaction-boundary
cases, then stopped safely before the next admission for a production review fix.
Unlike the earlier operator race, the actual runner process was first suspended;
two independent idle observations 18.7 seconds apart and a post-kill observation
confirmed zero live resources. Its three raw positives remain historical subsets.

The additional production review identified a cross-query expiry race: the normal
expiry scan could run just before `closed_at + 180 seconds`, while the subsequent
lost-RAM scan ran just after it and incorrectly used the session-loss reason.
`classifyClosedObservationRecovery` now separates valid retry, valid expired and
invalid-authority states. Both valid paths recheck the execution binding and
validated release/case. Expired state delegates to the existing normal expiry
selector and never falls back to session loss solely because the clock crossed.
No actor credentials, deadlines, grades or refund authority are reconstructed.
Build and 26 coordinator/binding tests passed with the PostgreSQL gates enabled,
including grading/overall boundary crossings and expired invalid-authority cases.
An independent production diff review found no further actionable issue.

The historical H1 collector is
`8794eeb9-156b-4911-982b-623e1f21c221`, with hard variants first. Its pending-action
restart and revoked-pending cases have each passed independent raw replay; the
full source-after inventory and all eight variants are still required before
BER003 passes. Sixteen targeted Node fault-tool checks and eight adversarial H1
reader unit checks passed without skips. The latter use an exact historical raw
case and copied mutations; they do not promote that older producer to a current
environment gate.

That H1 collector subsequently completed all eight physical variants. Independent
raw replay passed all thirteen applicable facts. The producer nevertheless exited
with two false diagnostic assertions: PostgreSQL event `created_at` is the start
of its transaction and can precede the deadline while the transaction waits on
the outbox gate. Actual dispatch is established by `delivered_at` and the physical
HTTP trace. Those two diagnostics were corrected without changing product clocks
or event rows. Because this changed the producer, the historical capture is not
qualified as the final current-source gate; a new complete capture is required.

Unknown-matrix capture `3b97ca71-69d9-42af-8b9d-369c662db4c4` completed a fresh
Full12 after missing-receipt recovery and interruption before the first owed grade.
Its twelve terminal evaluations, twelve generation fences, once-only completion,
debit, handoff and verified result were independently reconstructed. Two actual
read-only replays agreed on 112 raw files; copied missing, tampered and foreign-
generation evidence was rejected, and selected PostgreSQL business fingerprints
remained unchanged. This uses the reference actor and does not prove native-model
or target-host acceptance.

The second case recovered its conflicting receipt and independently passed the
interruption before successor dispatch. Its completion-handoff test then stopped
before U1 on a harness assertion: the test incorrectly expected no version
snapshot, although original admission already creates exactly one. Read-only
inspection established that this snapshot predated run start and remained
unchanged. The correction must preserve that original snapshot at every crash
checkpoint and require zero handoffs/results before the first owed commit. The
failed run and raw evidence remain retained; no failed run is resurrected. The
matrix is incomplete and will be repeated after the helper and independent
reader agree on the actual admission contract.

A separate cold restore of the authenticated pre-migration unified checkpoint
completed without starting its restored API or enabling writes. Eighty-eight
table/sequence fingerprints matched the checkpoint, including eleven runs,
thirty-one ledger entries, two reports and one uploaded screenshot. The screenshot
bytes matched its SQL hash, manifest and original read-only file; 2,620 official
evidence files were rehashed twice. Two new owner connections rejected even a
zero-row update with PostgreSQL `25006`. Original Google database fingerprints
were unchanged. Existing restore execution took 58,812 ms on the local native
volume profile. The independent report is
`artifacts/runs/ber-cold-sealed-restore/16f62e49-7e92-48c0-bc3f-5bf3620d3d7d/independent-verification.json`,
SHA-256 `93077c2812dfde854bd74e1fcb6fe4d30aa2b84aa1721f02c166ea436335328f`.
This proves cold byte preservation of that older checkpoint, not a latest-data
backup, authorized activation, native-client journey or target-host restore gate.

Remaining BER005/008 evidence was separately audited while the physical recovery
matrix held its source freeze. Original `f54674d5` proves a preparation PUT
`request_failed` after a generation was allocated/funded; it does not establish
wrong origin or a preparation timeout. Fresh Full12 success can establish the
normal M2-fence to M3-preparation/activation chain, original charge and final fence
tail, but cannot substitute for wrong-origin, case/facilitator-pin mismatch,
preparation-timeout, restart-before-ready or unavailable-evidence experiments.
BER005 remains blocked on that actual negative matrix. BER008 also remains blocked
on its complete historical-feedback and attribution-negative browser matrix.
Neither scenario is promoted from successful recovery or unit-test results.

The corrected hard-first matrix `a89e8349-74b1-44b3-a511-4a79d576775c` then
completed its conflicting-receipt Full12. Both the original H2 successor-dispatch
interruption and the first owed completion-handoff interruption independently
passed. For the latter, twelve known grades and exact fences existed while the
first handoff INSERT was actually blocked; process death and PostgreSQL rollback
were observed before unlocking. Normal restart created one handoff and one
verified result, preserving the admission snapshot, actions and original debit.
The independent completion report is
`artifacts/runs/ber-completion-handoff-interruption/f6eddfcb-d93b-4922-ab71-90302eecc50e/independent-verification.json`,
SHA-256 `06ff664ee82fe9039f7aee89cb5e624c4cd888ae96c0c6e43dbdac2460ed2d98`.
This is a current local fault-boundary Full12 using the reference actor; remaining
matrix cases, source-after inventory and final BDD integration are still pending.

That matrix later stopped before its second H1 experiment: S4 preparation failed
while a proxied health GET recorded fast DNS but no observed TCP connect, followed
by `ECONNRESET` at five seconds. Its failed run reached normal cancellation with
all four created preparations fenced. The aggregate matrix remains blocked; the
successful conflicting-receipt case is retained separately. No DNS, RPC, gateway
overload or peer-reset cause is inferred from this error code.

Two isolated transport experiments separated competing explanations. Cancelling
a fully sent GET did not trigger the proxy's incoming-request error handler.
An actual local TCP listener with a deliberately full accept queue did reproduce
the five-second failure: Node 24's global Agent installed a 5,000 ms socket timeout
before connection, and the callback registered by `setTimeout(45_000)` destroyed
the still-connecting request at that earlier timeout. A diagnostic Agent with an
explicit 45,000 ms timeout remained pending past seven seconds without the reset.
The raw comparison is
`artifacts/runs/ber-proxy-connect-timeout-audit/ee381041-8c03-40e7-a526-f5ac290044a1/capture.json`,
SHA-256 `8c32241d2935d77dc1eafb47895086c0c63c5b9aa02a8693da665dc92fd69a13`.
The acceptance proxy now explicitly supplies its already-declared 45-second
timeout in the request constructor as well. Product health deadlines, retries,
economic dispatch and gateway code are unchanged. This fixes a demonstrated
harness timeout mismatch, not the unknown cause of the original delayed connect.
The producer change makes `a89e` historical rather than final-current-source;
strict source checks are not relaxed, and final qualification must be repeated.

Read-only replay of the exact failed S3 in the proxy process completed in 175 ms
with maximum measured event-loop delay 31.49 ms; 56 accompanying health reads
passed and business fingerprints were unchanged. This did not reproduce a
five-second CPU stall and does not disprove one at the earlier incident.

The failed S4 preparation was independently bound to the post-intent adapter
health phase: intent `95e2acbd-e73b-42de-8b1d-30742d2669f1` existed before the GET,
and its immutable diagnostic records `api_health/response_unavailable` after the
non-200 response. The adapter uses its unchanged 15-second health budget; this
was not the separate five-second environment selector before intent creation.
The read-only binding report is
`artifacts/runs/ber-h1-diagnostic/failed-s4-preparation-82261df3-ad85-4d7c-b9c5-8fe5909fd378.json`,
SHA-256 `5943aa33e451efd0a8d6c98c757cd1380f7f994338fe5bfc62cbac46603c47de`.
No physical generation was created for that failed S4. The proxy's premature
five-second timeout is therefore material to this adapter request, while the
underlying delayed TCP connection still has no uniquely established cause.

The regression uses a private child process, a real stalled loopback TCP connect
and a shorter isolated Agent default. The exact same test bytes failed against
the archived old proxy and passed against the fixed proxy: the request remained
pending beyond the shorter timeout, then completed with one upstream connection
and one HTTP 200 after the listener drained. Both source copies and outputs are
retained in
`artifacts/runs/ber-proxy-preconnect-regression/ed284fc1-4ac7-49bd-bbc2-f346767fa9e8/capture-forward-paths.json`,
SHA-256 `c9f72c7116f59b84b3554cc7426f28472fbc92024b069352eec316de244dea89`.
The combined targeted Node suite passed 19 tests, zero failures/skips, including
this real-connect regression. Twenty paired runtime published-port reads and
twenty internal gateway/API reads all passed with matching response hashes; all
used fresh sockets. These probes did not reproduce the original network stall.
No provider, gateway, Docker network profile, production timeout or retry policy
was changed. Final physical qualification resumes on proxy source
`0e907a85b6d9cfe8314c9ffe0506a851d9810d64a8e52f7cc1d7d1a6e02aa5d1`.

On that fixed proxy, capture `b23e3b5b-2fe4-4a16-88ce-27d0c50145f6`
independently completed both conflicting- and missing-receipt recovery Full12s.
The actual first-grade, successor-dispatch and first-completion interruptions all
passed independent replay, as did the seven completed/late callback probes.
The fresh Ranked history was replayed twice over 112 immutable files with three
copied-artifact attacks rejected and unchanged surrounding PostgreSQL fingerprints.
The outer capture remains partial:
`artifacts/runs/ber-unknown-grading/b23e3b5b-2fe4-4a16-88ce-27d0c50145f6/capture.json`,
SHA-256 `4e0cc76241b91e973664f5210b1e984083a04431919492169a3015363be3221a`.
Its third case stopped before H1 on S4 preparation HTTP 503. The immutable
diagnostic identifies `preparation_put/http_503`, not timeout; proxy transport
failure records were empty, no physical generation was created, and all four
created leases were fenced through normal cancellation. This distinct failure
does not invalidate the two complete cases and does not establish a provider
cause. Remaining three variants require fresh runs; successful variants must not
be silently duplicated or failed histories discarded when assembling the matrix.

Final current-source core capture `1c756aa5-8556-4ad0-b17a-b744821e609b`
completed with exit 0 and all 469 producer inputs unchanged. Independent replay
passed the eight applicable S1 facts and actual first-refund interruption:
`artifacts/runs/ber-fault-recovery-core/1c756aa5-8556-4ad0-b17a-b744821e609b/independent-verification.json`,
SHA-256 `d6f61fdd6e2e89201412542e674eac642817ecbdc9afeddd82f78927e20b8d22`.
The original 180-second bound was retained. A first refund writer was actually
blocked with zero committed refunds, the API was killed, PostgreSQL rollback was
observed before releasing the barrier, and normal restart committed exactly one
official refund and one original-source ledger refund. Original source effects
remained unchanged. Four current-capture reader regressions passed, including
copied early-refund, surviving-writer and altered-amount attacks. Independent
post-capture inspection found no active generations, preparations, runs, slots
or unfenced leases. This proves that named subset; remaining full H1/unknown and
fresh Training3 integration gates still require their final captures.

A fresh latest-Google checkpoint attempt, `b415089a-593d-4a85-b143-57d21ac42c7e`,
stopped safely before creating the checkpoint, recovery envelope or restore clone:
official-evidence discovery exceeded the existing 4,096-file limit. Both the
checkpoint and restore implementations enforce this finite bound; it was not
raised and no official evidence was omitted. The source remained stopped and
write-disabled inspection before/after its read-only dump matched all 88 table
fingerprints. The dump is private and is not a completed verified backup.

The old sealed checkpoint's database fingerprint is `0943e6b7...`, whereas the
current original source is `76e981b5...`. The earlier cold restore's unchanged
`76e981b5...` observation proved preservation of the original source during that
restore, not equality between the old checkpoint and latest data. Its eleven-run
inventory excludes the two later native Training/Ranked runs. At the discovery
limit, 2,600 references matched the old closure byte-for-byte and 1,497 additional
references had been found, mostly newer task-reference evidence. No historical
file-hash change was observed. Latest full-backup capacity therefore remains an
explicit blocker requiring a separately reviewed bounded profile/design; the
successful cold restore of the older checkpoint retains only its stated scope.

The subsequent same-source capture `510d75da-1a13-464f-8ef5-8d6314427101`
independently passed `missing_exhaust_restart`: original closure plus 180 seconds
survived restart, no H1 grade was invented, and normal exhaustion fenced/released
resources. Its cancel-before-recovery attempt reached H1 but stopped before the
unknown-grading injection. The last retrieve was admitted, then durably rejected
before execution with `task_x402_local_bef_unavailable`; its actual health read
failed to establish TCP and exhausted the corrected 45-second proxy budget.
There was no additional economic effect or replay of that action. Normal owner
cancellation retained the failed history and released resources. This establishes
continued transport instability separately from the fixed premature timeout.
Only the two missing cancel orderings are scheduled in the next fresh capture.

Independent H1 replay was further hardened after review found that a copied
debit amount could remain correct while its available-balance delta was altered.
The reader now reconstructs original reserve/debit/refund operation and grant
identities, unique ledger rows and exact available/reserved/expired deltas.
Twenty actual-row/copy regression checks pass without skips. Existing historical
raw cases still reconstruct, but their older parent inventories are not promoted
to current-source environment acceptance.

The tracked runtime-input manifest now binds the current core, partial unknown
matrix and actual two-replay database window. An interim adapter run independently
verified those supplied proofs and correctly kept BER003/004/007 blocked on their
missing variants and fresh baseline. No malformed supplied proof was hidden by a
skip. Final acceptance must replace the partial references with complete current
captures and rerun the acceptance wrapper; this interim mapper run is not closeout.

BER004 now passes its actual BDD adapter against the complete same-source matrix:
`artifacts/runs/ber-unknown-grading-assembly/202f6ab5-a3cf-4b3e-9f63-7bb5d67f1ce9/assembly.json`,
SHA-256 `e348ad02967e24684eae5169b45f21dc80569b706a274109ec9ab026fe03d6a8`.
Independent reconstruction passed all thirteen facts for five unique complete
variants. Two earlier incomplete attempts remain validated and explicitly listed
as excluded observations. The final two-case capture exited 0 on 472 stable
inputs, and an independent global idle check confirmed resource release.
Reproduction: project Python pytest mapper, `--change benchmark-execution-reliability
-k test_ber_sc_004`; one passed. Task 2.5 is complete for its named local
environment boundary. Target-host and native-client acceptance remain separate.

The complete independent recovery-reader regression suite then passed **37 tests,
zero failures/skips** against exact current core, full unknown assembly and
completion-interruption pins, plus the retained combined native-history fixture.
The H1 ledger/copy regression suite separately passed **20 tests, zero skips**.
The combined Node fault-tool suite passed 19 tests. These reader/tool regressions
do not replace the pending final current-source H1 matrix and fresh Training3
environment baseline.

The fresh baseline now independently passes too:
`artifacts/runs/ber-fresh-current-source-baseline/b8d594f9-b6e2-4e9a-adf0-c7b2cc0d1d4f/manifest.json`,
SHA-256 `8931b5f6c57b9f062fb6e4afe3931b70c48c79a106a64daf816cd7f81a3030fa`.
Fresh browser-launched Training3 run `67ae4aa6-ea6a-415a-bcce-f04d3731649d`
has S1/M1/H1 known passed 1/1, one 500,000-unit bonus debit, three fenced leases
and zero slots. Its 465 source inputs match the Ranked capture's shared inputs;
the seven Ranked-only BER collection inputs are explicitly declared. Independent
three-/twelve-task histories, two actual offline passes per mode and surrounding
read-only database fingerprints all agree; missing, tampered and foreign-generation
copies are rejected. The baseline verification report SHA-256 is
`a5054b916814defd55a3b3c617e2ec9bc443f0d17614dc37871e5b86a661f114`.
Training admission-to-completion was 55,726 ms for the reference actor, excluding
build/catalog setup; this is not participant-native-agent timing. Final H1 cutoff
acceptance is still pending at this observation.

## Frozen-reader catalog refresh and legacy regression snapshot

After the H1 funding-lineage/chronology fix was frozen, actual release validation
`99a6c7df-5079-4751-8341-01b6235b0005` completed all 21 controls, zero failed/not-run,
with identical source inventories. Fresh BTS-SC-001 manifest:
`artifacts/runs/acceptance/BTS-SC-001/runs/2e395fa8-2bdc-460d-b69d-56fdee08e68e/manifest.json`,
SHA-256 `e24f487abf00a3517e822c7596325e587fe0682131b9b9887b703287527f3444`;
BTS-SC-002 manifest:
`artifacts/runs/acceptance/BTS-SC-002/runs/0c22b088-fa25-4847-b67a-d8516c7b81c4/manifest.json`,
SHA-256 `aecf72fb35eabc9aee586aec5a84d3f8d9fff0aa3e4071de2939ba8ea470dbca`.
Earlier refresh `db5e114b-0187-407e-bdad-d0c1eb7cd12a` observed 21 valid controls but
correctly remains blocked because the last reader fix changed its source inventory.
No stale-source exemption is used.

Actual legacy wrappers: BRL 0 passed/25 blocked, BPC 0 passed/26 blocked,
AAP 3 passed (002/003/004)/13 blocked, zero executed assertion failures.
All three reports have unchanged harness sources. Missing scenario-specific runtime
captures, full native negative matrices and target/domain/client prerequisites remain
non-passing. BLP (`benchmark-leaderboard-and-agent-pages`) refused execution because
its existing proposal review status is pending; no assertion was weakened or approval
inferred. These aggregate results do not erase the separately recorded physical local
recovery, native positive runs or older cold-restore evidence, and do not qualify the
whole beta. Reproduce with `.venv/Scripts/python.exe tools/run_bdd_acceptance.py --change <change>`;
see each corresponding `tests/bdd/changes/<change>/acceptance-evidence.json`.

## First complete BER-SC-007 recovery/replay gate

The actual mapper passed on 2026-10-31 after the strict source-bound H1 parent
`67071ce5-86d6-42e9-9282-50a824fb97a4` supplied the missing restart-at-cutoff proof:
`.venv/Scripts/python.exe -m pytest tests/bdd/mappers/test_benchmark_execution_reliability_bdd.py --change benchmark-execution-reliability -q -p no:cacheprovider -k test_ber_sc_007`
returned one passed, seven deselected, no failed/skipped selected scenarios (26.43 s).
The full required transition/refund/callback/read-only replay matrix is now observed;
task 2.8 is checked. This reference-actor local gate is separate from native target
acceptance and unified backup capacity. The parent SHA-256 is
`0f659fc153016349353bd44f7831ad8ccb245119d67bbb2c4322507c98d8996f`.

The same strict parent reader verifies seven complete H1 variants and retains one
incomplete `before_cutoff_dispatch_after` attempt: its client transport failed before
the third payment, no targeted cutoff was exercised, the original run was cancelled
and all resources fenced. Independent global idle at 12:34:48.701 UTC confirmed zero
active generations/preparations/runs/slots/unfenced leases; report
`artifacts/runs/ber-h1-diagnostic/idle-bfc0c906-d7bb-438e-94d4-9b8e08920523.json`,
SHA-256 `9f38ff6cbc43908956cbc84f754ccf84300d4a6d1dfe549c71293d65ba10395b`.
Only that missing variant is queued for a fresh physical attempt. Its evidence must
be assembled with explicit retained incomplete observations and identical current
producer inputs; the old attempt is never deleted or called passing.

## Final local recovery source qualification

Aggregate command `.venv/Scripts/python.exe tools/run_bdd_acceptance.py --change benchmark-execution-reliability`
returned pytest 4 passed/4 skipped (42.29 s), converted by the wrapper to BER003/004/006/007
passed and BER001/002/005/008 blocked. No executed assertion failed; harness sources
were unchanged. The wrapper nonzero exit is the mandatory blocked gate, not success
for the entire package. The final BTS wrapper records two passed/32 blocked, no failed
assertions, source unchanged. Strict OpenSpec validation and the eight-scenario
semantic audit passed; no sync/archive is performed.

H1 assembly:
`artifacts/runs/ber-h1-cutoff-assembly/c6b1b44c-2748-4e37-8412-e895e3eef7fc/assembly.json`,
SHA-256 `fb89b3c6164eda66061bc8d2868bdd469f5561afbbc98f96b1d98366f4450070`;
independent report in the same directory, SHA-256
`0b5e59c791b74b527ff312e1fcb867b04c949e2ee565cb9583d3b3c8ba1f7af1`.
Parent `67071ce5-86d6-42e9-9282-50a824fb97a4` retained seven complete and one
incomplete before-third-payment transport failure. Only the missing variant was
recaptured in `0ab29f2f-ca51-4ebe-b66c-d0cea925e263` (SHA-256
`49b00a4b6eb48521dee96ae948dde580297ff648303eb5ba9dc31d5ca1087c46`).
Both parents are source-stable with identical 469-file producer inventories, same
release/case/execution/BEF pins and independent physical identities. The explicit
assembly binds every original case to hash-pinned final transport inventory, validates
all raw cases, selects exactly eight complete unique variants and retains the excluded
incomplete observation. Rehashed deletion, foreign execution profile, source divergence,
duplicate selection and missing exclusion all fail the actual-copy tests.

Actual H1 test command uses `BER_H1_MATRIX_PATH`/`BER_H1_MATRIX_SHA256` set to that
assembly and `.venv/Scripts/python.exe -m pytest tests/bdd/adapters/test_ber_h1_replay.py -q -p no:cacheprovider`:
27 passed in 4.41 s, no skips. Final idle observation at 12:44:05.063 UTC:
`artifacts/runs/ber-h1-diagnostic/idle-870f130a-00df-4751-919a-2219179bc8a4.json`,
SHA-256 `9c667eafa55d67a04514a260ab7956b4c349295eac2c8316a85cb82acc0554c9`;
both owner databases and BEF have zero active runs/generations/preparations/slots/unfenced
leases. Final catalog capture `56bd5fc9-c145-4925-90c1-28d15ca91002` independently
re-exercised 21/21 controls on the final H1 reader with stable source; latest BTS
manifests are `ea2fc8dc-7536-4b9d-8093-2cb3a0bc9fc3` and
`12853652-dc50-4189-94f6-7a06317b76e7` under their scenario directories.

This checkpoint qualifies local reference-actor recovery, not a fresh participant-model
negative matrix, live mainnet or external target. The intermittent HTTP transport stall
remains causally unresolved even though unknown/fencing/recovery behavior is verified.
The separately approved backup-capacity infrastructure edit will create a new source
profile: preserve this pre-amendment qualification rather than rewriting hashes or
claiming it as a later unchanged-source beta gate.

## Approved capacity amendment and latest complete local cold restore

After `2566b7d` was committed/pushed, the approved count-only edit changed
`beta-backup-checkpoint.mjs` and `beta-backup-restore.mjs` to 8,192 and updated their
boundary tests. Per-file 64 MiB, official total 2 GiB and manifest 16 MiB remain fixed.
The base Compose Node suite for checkpoint/restore/local/sealed-bundle returned
19 passed, zero failed/skipped in 37.39 seconds. The actual 8,192-file restore test
checks every output byte and receipt; 8,193 is rejected before official materialization.

All intermediate failures were retained, never promoted:
- `b415089a`: old 4,096-file bound rejected discovery at 4,097; no sealed checkpoint.
- `f6913ddf`: correct rejection of unknown per-job relative origins in a known fifteen-
  reference inventory, before sealing. The narrow operator fix verifies each actual
  probe SHA/schema/task/mode and exact artifact list, then resolves paths under that
  probe directory. Root independently checked all 15 probes and 1,601 artifact rows.
- `8df5a68b`: complete 4,425-file discovery/staging succeeded, but a missing empty
  broker factory directory prevented broker startup; the unchanged freshness guard
  correctly rejected sealing. Provider requests/results and sealed/restore files were
  absent, and source fingerprints remained unchanged. A fresh operator now creates
  the contained empty directory and checks process liveness plus two increasing fresh
  source heartbeats within the same 15-second startup and 10-second freshness bounds.
These are private operator profile fixes, not relaxed evidence/path/timeout policies.

Fresh successful capture `5550a5f7-086e-459f-a3f9-bf97df38a064` has tooling profile
19 sources, SHA-256 `1b591f6ae40b974f35dd6a565bdaffb1527a876bcab12fcbc62800ef70d01706`.
This is current checkpoint tooling identity, not historical serving-build or target
qualification. The authenticated checkpoint and cold clone preserve 13 original runs,
35 ledger entries, two reports, one uploaded screenshot and 4,426 official files
(26,627,354 bytes; 4,425 discovered source files plus verified staging provenance).
Encrypted bundle: 31,354,497 bytes, SHA-256
`97107cb09b4f52eac9ef584aee22d48b70f965e279573f99389fc8fee0a3d906`.
The clone is `oid_restore_867f4ead0d2d4e87a612042161f18051`; restore elapsed 61,932 ms,
whole private cold phase 73.264 seconds. Source pause/staging/encryption are separate
from that restore time; no target RPO/RTO is inferred.

Primary observation:
`artifacts/runs/ber-latest-google-preservation/5550a5f7-086e-459f-a3f9-bf97df38a064/observation.json`,
SHA-256 `0aee5900d737ac047f7b1f4b7892e62feea39a0984faf9bb6de5edac91556f0c`.
Independent verification in the same directory, SHA-256
`5eebff9be382eeeae52cd2b9430850124af30256da7ac59e07a1b0e617dd1ef1`.
Root repeated the verifier with only a new output directory, source and native mounts
`:ro`; new report
`root-second-verification-c390741f-1067-42a1-91e1-1c5a7e84075e/independent-verification.json`,
SHA-256 `ad3625f106779072878d3cb47d2abe3b56cafbc3367e97385bb5e213ccd81f8d`.
All 88 original and clone table fingerprints matched
`76e981b5cddd6d3230f142a313fb9ae122cf0d2a3cadf20e3a9577f087324857`.
The screenshot is 33,102 bytes, SHA-256
`c54c6b5620a2f388eab3384bdc42999bff6e5b95ed099dc719e80a4188044e1b`;
SQL, authenticated manifest, original source and restored file match. Fresh independent
owner connections reject UPDATE WHERE false with 25006, default/transaction read-only
on. Actual restored permissions: 4,430 files 0400, 584 directories 0500. No restored
API, worker, credential renewal, economic action, regrading or business retry occurred.
This covers complete latest local bytes, not all BER1.3/3.3 or BPC022/026 variants.

The original source was then restarted with `google-local.ps1 -Action Start -EnableExecutor`.
Ready at 13:11:58.323 UTC; adminConfigured/executorEnabled true. Independent observer
at 13:14:02.137 UTC matched every one of the 88 original tables to the checkpoint,
zero changed tables, report/image counts unchanged. Report
`post-google-start-69aab02c-bd78-4c2f-80f4-c4d45e152dca.json` in the same capture directory,
SHA-256 `97402bd523b18d8a8cbadeef80eee962d6dc74f3c1d92f5a9c2086d68b27f7ab`.
API health and sign-in returned 200 inside the source container; public host
`http://127.0.0.1:3000/sign-in` and `/api/auth/get-session` returned 200 through the
normal web proxy. Direct host port 8784 is not this fixture's public API boundary;
its API binds container loopback. No new OAuth sign-in or browser-admin journey is
claimed by these health checks.
