# Run admission and task-release implementation checkpoint

Date: 2026-10-26. Scope is the unchanged, approved BRL/TBB/BTS packet in
[the execution entry review](run-execution-entry-review.md). This checkpoint
separates implemented code, direct-service integration, browser observations,
and actual executor evidence. It is not full scenario acceptance or a release.

## 2026-10-27 continuation: complete local reference inventory

This section supersedes older partial-inventory statements below. It does not
supersede their evidence boundaries or promote any OpenSpec/BDD gate.

All twelve ranked and eight training difficulty-v2 reference captures completed
against the pinned local BEF/Anvil fork. Each actual generation was fenced.
The immutable inventory is
`artifacts/runs/bts-reference-input-index/2026-10-27-difficulty-v2-twenty.json`
(SHA-256 `ddca597009c564326f6aafd08da28c4efe8b49f3c1fd53f45423b85ddc6dbf7a`).
Independent integrity/trace verification checked all 2067 raw artifacts:
`artifacts/runs/bts-difficulty-v2-artifact-verification/d9aefeb1-0cc7-424b-a507-11f788eb054d/verification.json`
(SHA-256 `21844cf4c79fcbc3f71a23a5b947c6ee242915cd0f15a04f7e887ad8abb17df8`).
This verifies retained bytes and trace links, not task solvability.

The twenty typed case candidates are retained at
`artifacts/runs/bts-difficulty-v2-case-candidates/8f478f5f-edda-47f8-85b2-35fa2f455a4c/candidate-cases.json`
(SHA-256 `b50836aa76611fe826e4c31e3fcc20f3cedb6e2e05485c0c59d11c79c0462156`).
They share BEF manifest
`e18e51cc85255d78c31262acecb0a556b51624f4b007cad77e870cceae361810`,
application source
`214ea87c270687329303c2cdcb4ccda22d9b24204159868992aaa374a1d2392e`
and migrations 001–010. Historical probe revisions differ and are explicitly
recorded; no uniform probe-build replay is claimed.

The full inventory release candidate is
`artifacts/runs/bts-difficulty-v2-release-candidates/6e63f0a7-6bc8-4512-a544-d57ef4f8bb63/candidate-release.json`
(SHA-256 `c7ad713ad931b1ec2cf623912230a07776a4da8fea06c3b53443dc64a2f8e8b5`).
Its schema, inventory and retained feasibility checks pass. Every declared
reference count falls in the original difficulty band. At composition time,
validation was blocked on independent semantic reference verification and minimum
necessary action review; compatible counts alone do not approve difficulty. No release
was activated, no owner run was graded and no browser-to-database acceptance
was established.

The stricter raw-context preflight passed twenty cases at
`artifacts/runs/bts-v2-reference-context-preflight/2d3612b5-2d45-4777-b4fc-7aa0dde95db6/verification.json`
(SHA-256 `c588ad5e727fd6ac3b4f6d916bf24bd6cf3ab12b936c130d9f05605161fd08f6`).
It independently binds endpoint identity, actual generation, read-only observer
privileges, source/profile pins, HTTP actions and the post-fence database row.
Every initial/final numeric state has matching block-tagged raw RPC reads within
the actual generation phase. Planning-generation observations are excluded.
This is a context/data-availability check, not semantic goal verification.

The opt-in retained-reader integration command is:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml --profile tools run --rm --no-deps runtime node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs --test tests/integration/task-reference-evidence-v2.test.mjs
```

It passed five Node test entries (one parent and four subtests), with zero skips.
Rehashed fixtures with elevated observer privileges, another HTTP generation,
or another generation's fence row are rejected. A rehashed raw ERC20 balance
changes the reconstructed amount despite the unchanged claimed state. Original
captures remain untouched; generated fixture copies are removed after checking
their resolved paths.

The basic semantic reader subsequently passed the common verification wrapper
for all nine basic captures: ranked S1/S2/S3/S4/M3 and training S1/S2/S4/M3.
The opt-in run passed 13 Node test entries, including unsupported-task,
missing-action and missing-HTTP-witness rejection checks. The common wrapper
also reconstructs both numeric states and checks their canonical hashes;
returning a goal proof alone is insufficient. Run it with:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml --profile tools run --rm --no-deps -e BEF_V2_BASIC_CAPTURE_TEST=1 runtime node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs --test packages/owner-identity/src/task-reference-evidence-v2-basic.test.ts
```

The default unit invocation does not require ignored capture artifacts: it
passes three rejection tests and explicitly skips the opt-in retained suite.
This basic subset does not establish the remaining advanced goals or full
release acceptance.

Subsequently, the common semantic verifier passed **all twenty** retained cases,
including canonical initial/final state reconstruction, at
`artifacts/runs/bts-v2-reference-verification/34182407-1f19-4d9c-9dc1-1a4e31a466a7/verification.json`
(SHA-256 `18bb2a9dc5b81b6e163223e2842d01e828c32bbb1623c00a419f1be6fba594d8`).
Source inputs were unchanged. The opt-in advanced focused suite passed 13/13
entries, covering eleven advanced captures; the default invocation passes its
rejection test and explicitly skips the retained suite. Payment proof covers
successful independent USDC receipt Transfer facts, exact public terms and
durable BEF operation/payment/delivery joins. Unretained intermediate payment
calldata or block headers are not claimed as checked.

The independent engineering minimum-action review passed twenty cases at
`artifacts/runs/bts-v2-minimum-action-review/3c5906a0-7376-404c-acec-a3acb5d03117/review.json`
(SHA-256 `11b7eb9191b91054daf4a2267811246f6530490e4c398bc21c370a437e175259`).
Command: `node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/review-difficulty-v2-minima.mjs --cases artifacts/runs/bts-difficulty-v2-case-candidates/8f478f5f-edda-47f8-85b2-35fa2f455a4c/candidate-cases.json --sha256 b50836aa76611fe826e4c31e3fcc20f3cedb6e2e05485c0c59d11c79c0462156`
inside the owner Docker tools runtime. It rechecks each semantic reference and
derives necessary dependencies, rather than accepting the trace count alone.
U1 uses the entire 470000-unit expense budget to bound all budget-valid offer
choices conservatively; 99230000 USDC units still exceed the 41-bps allocation
upper bound before conversion. Source inputs remained unchanged. The artifact
does not itself approve or activate a release. The subsequent trusted offline
validator result is recorded below; mandatory BDD gates and actual owner
execution remain separate.

The complete local-reference release candidate subsequently passed
`validateTaskReleaseCandidate` using actual retained feasibility, all twenty
semantic references and independently recomputed minimum-action evidence.
The authoritative artifact is
`artifacts/runs/bts-difficulty-v2-release-validation/fccaa85d-a450-4766-8b96-c2f03d233682/validation.json`
(SHA-256 `202642dec8d8da83105db69a0a9bcddb5c055abd4b7bf023ca04d29a890fa6d2`).
It retains all 2177 source/artifact pins checked before and after validation,
including the new verifier and CLI build hashes. Source inputs were unchanged;
semantic wrapper results matched; difficulty returned `approved`; release
validation returned `validated`. The bound manifest hash is
`0caa29f8d61553e79d05185aaab06ae5076197ccc0e728910fcb71495e0c9f42`.
This is a local-reference-validated candidate, with twelve ranked and eight
training cases. No product registry pointer, owner-run acceptance, grade or BDD
lifecycle gate was changed. The preceding capture `890df07c-d1ba-4962-8e43-1d12c26576bf`
is retained, but the authoritative rerun additionally preserves every source pin.

The private first-task worker is implemented in
`packages/owner-identity/src/bef-task-coordinator.ts`, with config, compose and
server maintenance wiring. It is disabled by default and rejects production
mode or a non-loopback API bind. Enabling requires a bounded private config,
a separate private admin-key file, pinned local-fork policies and the singleton
PostgreSQL lease. Unix config/key permissions must exclude group/other access;
Windows bind-mount modes may require Linux-managed private storage. No
permission-check bypass was added.

The worker claims, prepares once, atomically starts and attaches the RAM-only
session, then dispatches only the first task. It processes cancellation before
dispatch and recovers dispatched/prepared intents and running bindings without
RAM through exact cancellation/fencing. A dedicated one-connection pool owns
the session advisory lock; backend PID and lock ownership are checked before
work. Returning a reserved connection to a pool does not release session locks,
so denial, loss and shutdown end that dedicated pool. Five focused config/lease
tests passed; the opt-in real-PostgreSQL run passed four lease-test entries,
including actual contention and reacquisition after the owning pool closed.
No worker was enabled and no live BEF request was made by those tests.
S4 preparation support was subsequently added and exercised separately below.
Task advancement, run-bound observation/grading and the complete twelve-task worker
path remain unavailable. This wiring is not a genuine-run acceptance capture.
The browser admission route and worker now share the frozen local-v1 queue policy
only when the private coordinator is enabled; previously only the worker had
those limits, so the browser catalog remained `intentCreationReady:false`.
Default-off startup remains unconfigured. This does not add a readiness-success
stub: debit/start still require the actual per-run prepared session.

The private observation store now seals one final immutable bundle per task
closure, using a separate observation cutoff and admitted action cutoff. The
normal schema migration invokes it after preparation migrations. Its isolated
PostgreSQL contract test passed in retained synthetic database
`oid_acceptance_f1ded95db2664fbaa729d03c4c0a447c`: concurrent identical replay,
conflicting content rejection, closure/preparation/generation binding, declared
incomplete/contradictory coverage preservation and mutation/delete/truncate
guards. Nonzero action sequences must exist in the admitted action journal;
duplicate observation IDs within a domain reject, while sequence ties remain
valid. This is not a revision journal: callers must reconcile before the final
seal if they expect later evidence. It does not collect or independently verify
chain facts, derive coverage, grade, or expose a public endpoint. The concrete
S1 collector is still being connected; no production evaluation source is enabled.

`TaskSealedEvidenceSource` now reads S1 bundles inside the evaluator's supplied
transaction, verifies release/case/closure/execution bindings and bounded raw
file hashes, and preserves the sealed coverage unchanged. Historically ready
original-generation bundles can be read after fencing. The latest focused suite
and opt-in isolated PostgreSQL case passed 10/10 entries, including transitive
preparation/action-file tampering and missing-child rejection. The reader
does not independently establish chain semantics from a file hash: that remains
the concrete collector's responsibility. It is not wired into the product
server, and no grade was written by those contract tests.

S4's private pre-task setup now uses the existing scoped USDC approve endpoint,
with a deterministic public-request idempotency identity and gas limit 100000.
The adapter verifies raw read-only RPC transaction/receipt/block/Approval facts,
the gas-only native debit, unchanged unrelated principal/allowances and the
exact sealed post-setup state hash. Unknown outcomes retain the original
operation/transaction/digest lineage and are not resubmitted. Sixteen focused
mocked tests and the full owner TypeScript check passed before actor capture.

Actual preparation proofs, with explicitly synthetic isolated release providers:

| Mode | Artifact | Result and boundary |
| --- | --- | --- |
| ranked | `artifacts/runs/owner-bef-task-preparation-capture/9af85c6c-9a7f-4de2-a3ce-44b7124e229f/capture.json` | One PUT and one approve; prepared; exact case baseline matched; finally fenced. Capture remains incomplete because the capture SQL incorrectly queried delivery generation columns. |
| ranked reconciliation | `artifacts/runs/owner-bef-s4-preparation-reconciliation/7be143ea-3063-4639-ae1c-6e501bba6e8d/verification.json` | Read-only verification of the original operation, selected execution, events, costs and fenced generation. No actor call or approve replay. SHA-256 `29e32b901363971498cb044c68116e33c8294bfa625599adb027e86ecb0b0951`. |
| training | `artifacts/runs/owner-bef-task-preparation-capture/244a10ae-f8bf-4054-b83d-0c52839461cd/capture.json` | Complete capture after correcting the delivery-to-operation join. One PUT/approve, same-instance replay of the original generation, exact baseline, independent read-only PostgreSQL joins, late adapter zero PUT, finally fenced. SHA-256 `d09c2a4c3d490ade89dcecc0bc7a0027503625ec71c14c7cfcec2c1dc1fb1864`. |

All ten adapter evidence files across the two actor captures were independently
rehashed. The original ranked capture SHA-256 is
`21ab61db3bc6f0fd0f614cf306261a561164e79b9b66e036eecdbc12cc3e7837`;
it was preserved unchanged. Both case baselines matched without modifying BEF
application or manifest pins, so the twenty reference cases remain applicable.
These proofs establish the local S4 preparation adapter, not an admitted S4
task, a task grade or a twelve-task owner run.

The first genuine-S1 browser capture activated the fully verifier-backed release
in a fresh retained acceptance database, then stopped before agent/run creation:
`artifacts/runs/genuine-s1-owner-run/194d87eb-903c-4781-8305-f097f49d956b/capture.json`
(SHA-256 `1ed4487fe4bc0fa4594cb448e3b2c3bd5689783f472cc465a859fe48eb002496`).
The harness incorrectly expected HTTP 201 from the existing bonus-grant route,
which returns 200. Its browser witness retains the original operation ID and
successful response. The separate read-only `grant-reconciliation.json` in the
same directory (SHA-256
`d905e711702071083d4bb9d11772cf56cd3e8d3fe478a8325de92db96b44ee37`)
confirms exactly one 100000-unit synthetic bonus and ledger entry, with zero
runs. It made no actor calls or repeated grant. The original blocked capture
is unchanged; the corrected harness uses another fresh database.

The next capture reached real browser bonus/card/permission/financial-policy
updates and created the S1 launch intent at 33334 micro-USDC, then failed agent
acceptance before a run existed:
`artifacts/runs/genuine-s1-owner-run/e3a63aba-c829-4170-8218-4df4ea2ada86/capture.json`
(SHA-256 `02e380a59d2b1d98b02e60f9f3bedcdc447bcdb455a78ce29a7715e3bdd55b66`).
Its separate read-only `admission-reconciliation.json` (SHA-256
`74fa1500a93629ff4dd8a2d26ded35e175e183a58abb0a128fa96748ba6da8e1`)
confirms zero runs, reservations, budget holds and preparation intents. No chain
action had been dispatched. The capture did not retain the acceptance HTTP error
and is not retrospective proof of a particular status code. Local Next proxy
source shows `changeOrigin: true`, while run routes accepted only the public Host;
the MCP route already allowed the explicit configured backend hosts. This
identifies an ingress compatibility defect. The harness now retains a bounded
acceptance error projection and probes unauthenticated proxy ingress before
release replay; it never treats that probe as an authenticated admission.

Run-agent ingress now shares MCP's config-derived request-host allowlist. The
server passes public and explicit API-listener hosts; an omitted optional host
dependency preserves the public-only default. Forwarded hosts are not trusted,
wildcard bind addresses are not request hosts, and Origin/bearer checks remain.
Five focused Fastify test entries passed across accept, current-task,
action-status, action-admission and finish: allowed backend/public hosts reach
authentication, unknown/spoofed hosts reject, and a wrong Origin rejects.

The historical-evidence slice now uses each task's immutable preparation and
execution environment for observation sealing, sealed reload, result binding
and S1 collection. The run's current environment pointer is no longer a grading
authority for older tasks. The bundle format and prior artifacts are unchanged.
Thirteen opt-in PostgreSQL test entries and seventeen offline tests passed,
covering seal/reload while the run points to a successor environment and rejection
of task/environment/preparation/generation mismatches. This does not implement
successor preparation, activation or automatic advancement; action admission,
task issuance and executor dispatch still need that separate integration.
The pre-existing synthetic evaluator integration fixture was updated with its
own explicit task preparation and execution binding; there is no product
fallback for missing bindings. Its 19 observations passed in separate retained
database `oid_acceptance_44e23352681e4171900a7289e3235611`, using actual PostgreSQL
with declared synthetic release/observation ports. Both genuine-capture databases
were left unchanged.

The third capture passed the real Next-to-API authentication boundary, actual
matching-agent acceptance, queue/strict preparation/debit/start, S1 disclosure,
one 200000-unit USDC transfer and explicit finish with action cutoff 1:
`artifacts/runs/genuine-s1-owner-run/b969c47e-b91a-49c1-a9cc-899743dcea84/capture.json`
(SHA-256 `b662d1db9e6ca0cd04537f6d710a1c38404bea08e9f9b168ec4d3e8ee74b624b`).
Run `83bdb7f2-340f-419e-9105-79fe19853559` retained observed transaction
`0xf43243d04189c8cb3976cfccb4f8d6f6b038501a87a00aab01d509b8548cbbfe`.
The collector then returned `action_evidence_unavailable`, so no observation
bundle or grade was accepted. Actual owner-UI cancellation reached `cancelled`
with cancellation evidence and its one preparation lease fenced. Source inputs
remained unchanged. This is partial real execution evidence, not a passing S1
grade/completion. The original capture and action evidence remain unchanged.

The collector had compared the canonical command hash with the admission
envelope hash (`{runId,taskIndex,command}`), and its secret-field guard rejected
the public ERC20 contract address at the selected-action token field. These are
reader contract defects; they do not justify replaying the original transaction
or changing its retained effect. The next collector revision must preserve exact
envelope binding and permit only the known public contract-address field while
continuing to reject credential material.
The corrected reader passed 9/9 focused tests and the owner TypeScript check.
Regressions use the actual admission-envelope and selected-action response
shapes, reject the bare-command digest, and reject credential-shaped or foreign
token fields. This test result does not upgrade the third capture to a passing
grade; its cancelled run and retained observations remain the original result.

Independent read-only reconciliation of that original effect subsequently passed
at `artifacts/runs/genuine-s1-owner-run/b969c47e-b91a-49c1-a9cc-899743dcea84/effect-reconciliation.json`
(SHA-256 `248c9e02854df5d5126c6ea091c9eab74e365952a446c5e005c6d639b7a370ee`).
Its retained `reconcile-effect.mjs` source hashes to
`c12de2bf8823e7b38c0be278447a9801a7f28c6306cb9290a51b60d9c0bc599c`.
Owner and BEF observers confirmed the exact admitted action/history, closed
cutoff, scoped settled operation/selected events, one cost row and original
generation/preparation fence. Independent RPC confirmed pinned USDC code, tx
calldata and Transfer log, payer/recipient token deltas -200000/+200000, and
native debit 334116746005 wei = 62159 × 5375195. No actor or DB-write operation
ran, and the cancelled run was not graded, reopened or completed. The initial
overstrict diagnostic is retained separately as `effect-reconciliation-attempt-1.json`.

The actual compact BEF transfer selection stores kind/amount/recipient/gas but
omits the manifest-pinned token; its final measurement includes the token.
`bef_operation.response_sha256` is NULL for this selected transfer. These fields
must not be invented in the census or required to equal the action witness's raw
response digest. Token identity is checked through the pinned release and
independent RPC target/code/calldata/logs; recorded raw and semantic hash
contracts remain distinct.
The subsequent reader revision uses this observed compact/measurement shape and
nullable response hash in its positive fixture. Ten focused tests and the owner
TypeScript check passed, including foreign-token and malformed optional-hash
rejection. It is being checked in another fresh genuine run; the original
cancelled run is not reopened.

The fourth genuine capture reached a complete run-bound S1 observation candidate
and a known rubric preflight:
`artifacts/runs/genuine-s1-owner-run/482c9311-6868-4f2b-b83a-019130120855/capture.json`
(SHA-256 `69a330e4c0201db78ecd104cf116d5b883e89df778081324b27c16136a2fe750`).
Its 39428-byte `s1-observer-packet.json` hashes to
`7be1ad783aa89ab2f4aaa465f60eb7e2233281ceaaf80447a24f3e92b489ba5f`.
The harness used its own capture directory for the packet, while the production
reader deliberately permits only the coordinator's private observation namespace.
That reader rejected `TASK_EVIDENCE_PATH_INVALID`; no grade or completion was
accepted. The run was cancelled/fenced through the real owner UI, and source
inputs were stable. The harness sink now writes new packets to
`artifacts/runs/owner-identity-bef-task-coordinator/observation/`; the reader's
path boundary and original capture/bundle remain unchanged.

The fifth genuine S1 capture passed the whole local path:
`artifacts/runs/genuine-s1-owner-run/4da36fdd-3894-41f1-9405-7920d3150c13/capture.json`
(SHA-256 `0d9f45b846dd0ff9efa0cd326a7c97e0a435e1b3164dfccf75b3289ef7c232f7`).
Run `98315e23-7070-4062-a220-af3c6de148fe` reached known `passed`, credit 1/1,
with immutable bundle `d1d3e3e2889e3e190c9af7ec162c4d886d22f4db295ddce1be3a6f9a82283a96`
and result `f22f324657f2c0661b8fff88941611520f0b57712b1476bf339de0ddc9ccd847`.
Original-input reconstruction did not diverge. The real owner-auth results API
returned the same known outcome and credit. The exact original generation was
fenced before normal training completion, one `run.completed` event was retained,
the dispatch claim was released, the execution slot removed, and replay left
money state unchanged: one 33334-unit debit and no refund.

After the runtime stopped, separate read-only owner/BEF PostgreSQL inspection
confirmed those durable rows and the exact generation/preparation fence:
`durable-completion-reconciliation.json` in the same capture directory
(SHA-256 `0ed7666d01af1e6504a1aecb60289568d2d925462aa00ae2d99f57a9496453e6`).
The capture retains operation-correlated real browser requests/responses for
bonus grant, admission, agent creation/permissions/financial policy/credential
and intent creation. All source inputs stayed unchanged during this run.

This proves the local first-task path with actual worker action dispatch and a
private harness bridge for observation sealing, evaluation, fencing and training
completion. Automatic worker evaluation/advancement, full twelve-task execution,
an external model client, public ranked publication and full mandatory scenario
acceptance remain unproved. The release was activated only in the fresh retained
acceptance database; the normal product registry was not activated. No OpenSpec
checkbox, BDD gate, sync or archive status was promoted by this capture.

Subsequently, the private run card gained an explicit result-read button. It
requests only the existing allowlisted owner result DTO, renders exact per-task
credit and safe reason categories, preserves unknown as unknown, and honors the
ranked-withholding response. The production frontend build passed. The next
genuine capture must click that button and match the rendered result to the
persisted evaluation; the fifth capture predates this UI addition and proves
only API feedback visibility.

The private `finalizeKnownTrainingTask` service now terminalizes a non-final
selected training task only after known immutable evaluation, exact evidence
reload, reconciled cutoff and original-generation fencing. It revalidates prior
known terminal tasks and records one replay-bound `task.terminalized` event,
preserving the run's charge, claim, slot and clock. Its expanded isolated
PostgreSQL contract test passed, including known failed outcomes, replay and
unknown/unfenced/cancellation/predecessor rejection. It is not wired to the
coordinator and does not prepare or activate a successor. Between-task preparation
still needs a persisted clock interval that satisfies BRL-REQ-006 without
resetting the remaining execution budget.

The BEF PostgreSQL regression passed 113/113 tests with zero skips at
`artifacts/runs/bef-package-postgres/cce28b09-897f-4533-9a12-e34eeaf6f29f/capture.json`.
The owner aggregate captured 121 passing observations at
`artifacts/runs/launch-boundary/99466b82-592a-4853-be99-1d27900975a5/capture.json`
(SHA-256 `e5d607f5771c3ae563a7238ed1cd9eb01301c30ac17b658a37c00324b6054e1a`),
using synthetic ports rather than full scenario acceptance. The subsequent
preparing-run expiry fix passed 28 focused PostgreSQL start observations;
the earlier aggregate does not cover that later fix.

## 2026-10-28 continuation: task-scoped environments and new readers

Active action admission, task issuance, execution binding and dispatch now resolve
environment identity from each task's exact preparation and execution binding.
The run's compatibility environment pointer cannot retarget a task. The focused
executor suite passed 15/15; synthetic fixtures explicitly retain their
preparation/binding identities rather than using a production fallback.

The refreshed engineering review is
`artifacts/runs/bts-v2-minimum-action-review/1a25da07-3301-400c-ab6d-c6e96f81da2d/review.json`
(SHA-256 `e67cbc3a81c96491edfbdc7cea15dd47aa0498c4dcdd75c2374b8ffc5e06a77d`).
All twenty results, assumptions, case hashes and execution identity match the
earlier review exactly; only the executor and action-service source pins changed.
The validator retains a single explicit review pin; no arbitrary CLI override
was added. The new full offline validation passed 20/20 with 2177 retained pins:
`artifacts/runs/bts-difficulty-v2-release-validation/382d65b5-fd03-4ba1-95e5-ccde5e35d737/validation.json`
(SHA-256 `5b12c392d4f1db240c5bc5fae2fc0a74d0359f521e271eb9fb529c18b2e94943`).
Its bound manifest hash is
`1be1fc3ed3db09f5fbf763b18d5c1f9cd7f396facba608b7fd7011b4cb582b7f`.
The earlier S1 runtime capture remains proof of its original `0caa...` manifest;
it is not relabelled as execution of this new package.

The S2 collector now covers free offer reads or zero-action closure, immutable
answers and independently checked no-effect intervals. Its focused tests passed
3/3. The S4 collector separates the verified pre-task fixture approval from the
task interval, retains unrelated WETH/router allowance changes even after
restoration, and returns an unsealed candidate. Its focused tests passed 7/7;
the separate packet-link validator passed 6/6. These are synthetic contract
tests, not actual S2/S4 runtime acceptance. Unsupported or unverified effects
remain unavailable rather than receiving invented complete coverage.

The combined S1/S2/S4 sealed-reader and packet suites passed 25/25 with zero
skips, including the isolated PostgreSQL historical-load case. Source readers
hash the full bounded private child-reference graph and retain declared
coverage. At that checkpoint the new live S1 result-button and S2/S4 captures
were pending; their subsequent outcomes are retained below. Automatic worker
grading and actual sequential execution remain separate work;
the successor-preparation policy is recorded in
[the policy review](successor-preparation-policy-review.md).

The subsequent successor foundations add a separately versioned local 180-second
default (subsequently confirmed by the owner), nullable immutable intent/run
snapshots with no legacy backfill, explicit training successor preparation, and a separate atomic
activation service. The original first-task start remains the charge path.
Successor activation preserves charge/claim/slot identities, verifies the known
predecessor and original fences, and records one preparation-clock adjustment
and public binding. It remains unwired to the worker. Exact task-index
cancellation retains legacy missing-index task-zero compatibility.

The combined Docker command enabled `OID_TASK_SEALED_EVIDENCE_SOURCE_PG_TEST`,
`OID_TASK_RUN_COMPLETION_PG_TEST`, `OID_TASK_SUCCESSOR_PREPARATION_PG_TEST` and
`OID_TASK_SUCCESSOR_ACTIVATION_PG_TEST`, and ran those suites together with the
three collectors and S4 packet tests: **58/58 passed, zero skips**, exit 0.
The successor integration uses the real preparation port with a synthetic
adapter, not an actual successor BEF executor. No BDD gate, sync/archive status,
automatic grading or full twelve-task execution is promoted by these checks.

The 2026-10-28 continuation added the post-start cancellation gap check: when a
known predecessor is already fenced and no successor lease exists, cancellation
reuses that exact stored proof, keeps the original charge, releases the claim and
slot, and prevents successor preparation. An orphaned preparation fails closed.
The Docker PostgreSQL/evidence/completion/successor/cancellation suites passed
30/30 with all five PostgreSQL opt-ins enabled; the three actual
`bef-s1/s2/s4-observation-collector.test.ts` suites separately passed 29/29.
Both commands exited 0 with zero skips: 59 checks total. This does not establish
actual worker advancement or full scenario acceptance. The owner also explicitly
confirmed the saved local successor bound as 180 seconds.

The coordinator's subsequent phase-aware lost-RAM check passed 12/12 focused
checks with `OID_COORDINATOR_LEASE_INTEGRATION=true`, zero skips. It exempts
only an exact fenced, closed, reconciled and known task awaiting terminalization;
it neither restores RAM nor finalizes the task. A read-only query of the retained
S4 database checked the SQL projection aliases only, not a positive recovery
classification: that historical task is already completed and has a
terminalization event. The actual waiting-finalizer branch still needs runtime
exercise. There is still no overall-expiry terminalization handler.

The new sequence writer was separately exercised without runtime or actors at
`artifacts/runs/genuine-training-sequence-owner-run/9844e78e-c592-4661-be43-f6d1f0cf43dd/capture.json`
(SHA-256 `e678cba3a5cdc115ce4870e1daae6591eec7ee83376d3b4257e49ae806da9a7b`).
Its explicit `writer_smoke_no_runtime` blocker is test input, not an attempted
S1/S2 execution or evidence of a runtime failure.

After worker wiring and the cancellation-gap fix, owner-identity `check` and
`build` passed. The first transaction aggregate stopped at a legacy synthetic
mixed-cancellation fixture that started a multi-task run without a preparation
record. The strict cancellation path correctly refused to invent a fence.
Its retained database is `oid_acceptance_ac5a83637989407b84e121290c417968`;
`artifacts/runs/launch-boundary-failure/ac5a8363-7989-407b-84e1-21290c417968/failure-diagnostic.json`
has SHA-256 `8a4db3398684619de54ecccce4a4f6a7e42dbac2a521cd85a073313fa21c4537`.
Its 248-input source checkpoint has SHA-256
`2acac4c2d2cf66342d2e6873e2509f92df35b7ee93234922a91c6f5083491d7b`.
Only the fixture was repaired to seed and assert an exact task-zero preparation,
lease and generation; the product's fail-closed rule was retained.

The fresh transaction-only aggregate then exited 0:
`artifacts/runs/launch-boundary/d640b0b3-2a38-4929-8c60-828ee43db5a5/capture.json`,
SHA-256 `36c0d29c7edeb2f849e4aadd8108ea913f21e35ab3059dd4bb979b06c4715b77`.
Provenance run `cf56e593-fdfd-42d2-b1c4-4ef92a582dd7` retained database
`oid_acceptance_cf56e593fdfd42d2b1c44ef92a582dd7` and 248 unchanged source
inputs. Coordinator transactions (15), atomic start (31), release store (7),
evaluation store (19), task actions (32), execution bindings (9), and task
preparation (15) all passed. This is still synthetic transaction integration:
the wrapper remains `partial_blocked`, `fullScenarioAcceptance=false`; there
were no actors or claimed full lifecycle gates.

Read-only follow-up identified two remaining lifecycle gaps beyond that aggregate.
The worker still has no production collector/seal/evaluation/finalizer call path;
the genuine harness provides that private bridge. Also, the conservative successor
guards currently reject a predecessor with a non-null `mandatoryViolation`.
BRL-REQ-005 requires that task's zero outcome and continuation of later independent
tasks, so those guards still need reconciliation with the approved requirement.
The forthcoming S1/S2 positive path cannot establish this adversarial branch.

The first real S1/S2 sequence attempt is retained at
`artifacts/runs/genuine-training-sequence-owner-run/c06e1171-6185-45e2-a798-4b9fbcdee10c/capture.json`
(SHA-256 `e74d40772a47324f34f790d7729d041ee2558adf9879b1b0daad5c99865a169d`),
run `a9d4f469-f46e-4d43-a852-15475efa6f57`, isolated database
`oid_acceptance_c06e1171618545e2a7984b9fbcdee10c`. Source inputs stayed unchanged.
S1's actual transfer was observed, evaluated as known/pass and terminalized with
its exact original generation fenced. The attempt then stopped before S2's action
at `successor_activation_event_or_deadline_readback_mismatch`; owner UI cancellation
returned 200, with both task preparation leases reported fenced. The original
capture remains blocked, not a completed sequence. Inspection found a concrete
verifier shape bug: `projectEvaluation` exposes `taskIndex`, but the new successor
predicate read `task_index`. Independent read-only reconciliation of the stopped
database is required before attributing the entire failure to that condition.

The stopped-run read-only diagnosis is now retained beside that original capture
as `activation-reconciliation.json`, SHA-256
`5d0b00bf0f6f1fb2d72e57518c3fe72f47ba3680a5ed2eb67d6bef0e7a75f554`.
All 19 diagnostic checks passed under `oid_observer` and `bef_observer`, with
read-only transactions. The actual activation event and persisted task binding
agree: S1 finished at `2026-10-27T23:54:51.352Z`, S2 activated at
`2026-10-27T23:54:54.953Z`; preparation was 3601 ms. The original overall deadline
`2026-10-28T00:02:47.993Z` became `2026-10-28T00:02:51.594Z`, exactly +3601 ms,
and S2's deadline was activation +60 seconds. There was one activation, one
66667-unit tester-bonus reservation/debit, a charged hold, zero refunds, one
released claim and zero slots after cleanup. Both exact owner/BEF generations
were fenced; eight referenced artifact hashes matched. There was one S1 action
and no S2 action, evaluation or terminalization. The verifier field mismatch is
confirmed; the run remains cancelled and is not retroactively completed. The
narrow `task_index` to `taskIndex` verifier correction passed Docker `node --check`
before a separate fresh isolated attempt.

That second attempt also remained blocked at the successor verifier:
`artifacts/runs/genuine-training-sequence-owner-run/f5337cec-285d-4604-9c90-f2b4805c3c55/capture.json`,
SHA-256 `7ada0a55e83579dde27610e81f91dac1b8d6f5b5be922dcd1992f980b57d64a6`,
run `8671898f-20f6-4e26-9469-5cc3b858dcd1`, database
`oid_acceptance_f5337cec285d46049c90f2b4805c3c55`. S1 was known/pass and fenced;
cleanup cancelled the run and reported both task leases fenced. It was incorrect
to attribute the whole first rejection to the camelCase mismatch before checking
the exact runtime value types. A Docker-only reproduction confirmed that
`Date.parse(new Date('2026-10-28T00:02:47.993Z'))` loses 993 milliseconds,
whereas `getTime()` preserves them. PostgreSQL Date objects and ISO event strings
must be compared with a type-aware millisecond conversion before serialization.
The verifier now retains its 93 original static conditions, reports the exact
failed conditions, and uses `getTime()` for Date inputs; syntax validation passed.
The stopped second run still requires its own typed read-only diagnosis before
any new execution attempt.

The second attempt's typed read-only diagnosis is retained alongside its capture
as `activation-verifier-terms-corrected.json`, SHA-256
`16085cb20e80fe89f9091f06fed60d30fa610fbe74900944bc4de9cdf0b28046`.
It evaluates the 93 exact original conjuncts before JSON serialization: six
comparisons fail because `Date.parse(Date)` truncates milliseconds; all other
evaluated terms pass. Run status at the earlier verifier read and the unretained
S2 task DTO case hash are explicitly `unknown_historical`, not reconstructed as
observed facts. Both immutable activation event and persisted clocks agree on
the 4318-ms preparation interval. The typed conversion fix preserves every
condition and reports individual failures. No old run was reopened or regraded.

The third attempt passed actual worker activation and both task executions, but
the capture remained blocked at its final completion readback:
`artifacts/runs/genuine-training-sequence-owner-run/b34b2285-51cb-4ef0-a93d-05ceea85d8ab/capture.json`,
SHA-256 `5b4446b11eca03f1db345cf2e72750596f7d485ea1ea8291107c971dd72e018a`.
Run `c9850662-5019-4900-8d55-291fe4e164af` in database
`oid_acceptance_b34b228551cb4ef0a93d05ceea85d8ab` reached backend `completed`;
S1 and S2 each have known/pass 1/1 evaluations, both original generations are
fenced, and the independently verified preparation interval was 2757 ms.
The owner results button had not yet been exercised when readback failed.
Inspection found another harness assumption to verify: it expects one standalone
`task.terminalized` event per selected task, whereas the existing completion service
emits that event only for nonfinal tasks and atomically terminalizes the final
task with `run.completed`, whose payload binds all selected task proofs. The
original capture stays blocked pending independent stopped-run diagnosis.

The third run's stopped-state diagnosis is now complete under read-only owner/BEF
observers. `postcompletion-offline-reconciliation-v3.json` beside its capture has
SHA-256 `994bfae7ab52f2efdd6c366e134d21f9cebe3361eba86f044273b681180b032e`;
all 14 independent checks pass. Earlier diagnostic versions remain retained.
The corrected verifier's exact completion terms also pass offline in
`corrected-completion-verifier-terms.json`, SHA-256
`748daa524cd7603efcc4487f2adf2ef0106af00a6aec4e6867e4851e56237773`.
There is one intermediate task terminalization and one final completion event
whose hash, run/mode/task IDs/time and both task proof tuples match persisted
closures, evaluation hashes, and exact preparation/lease/generation fences.
Both tasks are completed, the original claim is released, no slot remains,
the sole 66667-unit charge is unchanged, and there is no refund. This is
backend-completion evidence, not the unobserved UI results-button gate or a
retroactive passing capture. The harness now checks the existing final-event
contract and its full payload without changing the completion service.

The fresh fourth sequence completed through the actual owner results button:
`artifacts/runs/genuine-training-sequence-owner-run/200e82e5-0616-48dd-813c-5f7271aa42d5/capture.json`,
SHA-256 `bb2460b4a2c4baed93b5f51bc6d2522e55e9e0d4f33562a787efa76985800042`.
The Docker command exited 0. Run `44d6e669-2e35-4950-a002-3397d5795e92` used
isolated database `oid_acceptance_200e82e5061648dd813c5f7271aa42d5`; all 248
source inputs remained unchanged. Both actual task actions and immutable
evaluations were known/pass 1/1. The server worker, without manual successor
preparation/activation or RAM injection, prepared and activated S2 after S1.
The v1/180 snapshot was preserved; the preparation interval was 3462 ms, extending
the overall deadline from `2026-10-28T00:34:18.331Z` to
`2026-10-28T00:34:21.793Z` once. S2's deadline was activation +60 seconds.
Normal completion and its replay retained one charge, released the same claim
and slot, and produced one completion event. The actual owner button returned
HTTP 200 and rendered both persisted 1/1 evaluations.

After runtime shutdown, independent `oid_observer` and `bef_observer` read-only
transactions passed all 16 durable checks. The additive
`durable-completion-reconciliation.json` beside that capture has SHA-256
`a7dbf2224df597c98b7ab3d61e41af6078b8a3752c98fd4f3f23aad35dfe4a6c`.
It verifies both task bindings and original owner/BEF fences, one nonfinal
terminalization and one hashed final completion payload, exact activation clock
arithmetic, one independently recomputed 66667-unit quote/reserve/debit, charged
hold, zero refunds, released claim/no slot, and capture/raw evidence hashes.
This closes this private S1/S2 sequence capture only: grading/fencing/completion
still use the internal bridge; automatic worker grading, ranked eligibility,
full twelve-task execution and all mandatory BDD gates remain separate work.

The following implementation slice adds an explicitly optional
`observationPipeline` local configuration. Absence retains the manual-bridge
profile; the default coordinator remains disabled. The optional worker path uses
verified `bef_observer` repeatable-read/read-only transactions, bounded read RPC
methods, immutable content-addressed S1/S2/S4 observation packets, known-only
rubric preflight before sealing, retained-input replay, exact-generation fencing
plus independent fence observation, and the existing training finalizers. It
runs closed-task recovery before lost-RAM cancellation. Existing collectors
still own their internal snapshot/row-lock transactions; the lifecycle adds no
enclosing transaction around their external reads. Overall-expiry terminalization,
bounded platform recovery/refunds and ranked eligibility remain open.

Port tests passed 8/8 including the unchanged retained S1/S2/S4 packet bytes.
The initial orchestration PG test passed 2/2 with explicitly synthetic evidence,
observer and fencer ports; it tests service ordering/replay rather than raw BEF
proof. Live read-only smoke verified role/read-only mode, chain ID 8453, and an
old exact fence; the new lifecycle fence validator matched the real retained
owner/BEF proof with zero actor calls. Canonical mandatory-violation successor
checks now use real rubric-derived zero-credit failed results, allowing the next
independent task; contradictory passed/partial violation claims are blocked.
Focused successor and shared completion/cancellation PG tests passed.

The first combined run was 79/81, zero skips. Its two test-fixture failures were
a workspace/package-cwd-dependent retained-packet path and an upfront short
crossing-deadline fixture that expired before predecessor terminalization under
parallel load. The packet path now derives from `import.meta.url`; the crossing
fixture is created at its case, proves predecessor completion before expiry and
waits until the old deadline +250 ms. Product deadline checks were not relaxed.
An additional review found a sealed-ranked resume guard gap in the new lifecycle;
the common training-only guard is being verified before automatic runtime use.
No automatic-worker or BDD acceptance claim follows from these implementation
checks alone.

After those fixes, the combined Docker focused suite passed **81/81, zero skips**,
exit 0, including every PostgreSQL opt-in, actual retained packet smoke and the
coordinator advisory-lock integration. The common lifecycle guard now rejects
sealed ranked/cancelled targets before observer/source/fence/finalizer work and
retains valid training completion replay. Read-only wiring review found no
concrete blocker. Source-level pipeline checks remain distinct from automatic
worker runtime acceptance.

The automatic capture startup writer was smoke-tested without runtime or actors:
`artifacts/runs/genuine-training-sequence-owner-run/8b8f37dc-02b0-44b1-8540-d824a3a54087/capture.json`,
SHA-256 `1993d223759aa71b34004e7d63963364822edf7d35303a08696315ae3813e2ce`.
Its explicit `automatic_writer_smoke_no_runtime` blocker is test input, not an
execution failure. The new opt-in is `--genuine-training-sequence-worker-owner-run`;
that branch sends public participant action/finish requests and then reads
worker-created sealed inputs, grades, fences and completion. It does not invoke
harness seal/evaluation/fence/finalizer writes. Its acceptance predicates now
explicitly compare authoritative event order, the original held claim/slot at S2
activation, exact run-specific reserve/debit ledger rows and charged hold amount,
then the owner results button with both persisted evaluations.

The final frozen-tree transaction aggregate passed after owner-identity `check`
and `build`: `artifacts/runs/launch-boundary/bfc1657a-7b29-4cf3-bb6c-62ef155428a1/capture.json`,
SHA-256 `0ec90e418322f0df6f31ace8597cfe57f6b544622c0ad6ffc9d5411036096b90`.
Provenance run `c7f49b46-c6ed-43ec-b0f7-2b520a3a9902` retained database
`oid_acceptance_c7f49b46c6ed43ecb0f72b520a3a9902` and 252 identical before/after
inputs; all 252 current hashes and byte counts matched that snapshot. Its before
checkpoint has SHA-256 `dd6537653a2fc6e3ffd4e9ba121d77485aa0f867f639350585eb27a491549b39`.
All seven transaction groups passed, exit 0, with `fullScenarioAcceptance=false`.
The earlier passing aggregate `1a527644-3eee-4932-86ec-3800dbf6a2fb` (SHA-256
`28e1a4bbf6ba3a541ce9b507e31af02f1f53c42596825dc44f65739fb7a80696`) retains its
own stable snapshot and predates the packet-smoke test-path correction; it is not
relabeled as validation of those later edits. No actor ran in either aggregate.

The first actual automatic-worker S1/S2 run then exited 0:
`artifacts/runs/genuine-training-sequence-owner-run/93a9597a-c8d4-411b-9204-332aaa79912b/capture.json`,
SHA-256 `1456e432a3c7ebf21eba7842a63f59fd45e8dd40015fcf36a9af4c2eb780c174`.
Run `e49fd4ac-f43e-4cdf-b389-6713761b34ca` used isolated database
`oid_acceptance_93a9597ac8d4411b9204332aaa79912b`. Its 252 source inputs stayed
unchanged. Both automatic-worker flags are true, both task evaluations and fences
identify `server_worker` as producer, and the harness records no seal/evaluation/
fence/completion writes. The backend created content-addressed observation packets
and lifecycle progress artifacts. Both known/pass 1/1 results were read through
the actual owner button/API with HTTP 200. Preparation took 3509 ms, extending
the overall deadline from `2026-10-28T01:11:48.135Z` to
`2026-10-28T01:11:51.644Z` once; terminalization sequence 9 preceded activation
sequence 10. One exact `rundeb_e49fd4acf43e4cdfb3896713761b34ca` ledger debit was
66667, with zero refund, the original claim released and no slot remaining.
Completion replay was not invoked by the read-only worker harness.

Before another actor/reset, root independently read owner/BEF snapshots under
their observer roles in repeatable-read/read-only transactions. Both tasks were
known/pass 1/1, the one debit used `tester_bonus` funding, the original claim was
released, there were zero slots, and both exact generations/preparations were
fenced with confirmation timestamps. The additive `root-prereset-readonly-snapshot.json`
beside that capture has SHA-256
`812540d8d2a6d38383281b101da974de6a285a33ae07ce148fd5fc28f33d6b09`.
Funding source kind is distinct from the benchmark spending category. A captured
live held-slot witness and a post-stop released-claim/no-slot observation are
different evidence boundaries; the deleted active slot cannot be re-read later.
Full twelve-task/ranked execution and all mandatory BDD gates remain unproven.

The automatic S1/S2 post-stop reconciliation subsequently passed 19/19 checks:
`durable-completion-reconciliation-v4.json` beside capture `93a9597a`, SHA-256
`c67962305c99e3410b1c354abc09570cb6c29648ef5e419ed5bf666b52f03486`.
It verifies historical source stability, both worker packet content addresses and
lifecycle records, all task/bundle/evaluation/binding/fence identities, event/clock
ordering, exact bonus funding and debit, final resources and the captured UI/API
witness. Earlier blocked reconciliation files remain diagnostics for incorrect
source-kind and nonexistent event-field predicates, not run failures.

An independent automatic S4 run also exited 0:
`artifacts/runs/genuine-s4-owner-run/e58fe6af-1903-4328-b8a7-482b5ae62cb8/capture.json`,
SHA-256 `9115ff286e94de0d19eec4e42e3facbefbbc6e0b3210465cf9b66fa6d332c593`.
Run `ce7f31c9-7802-4054-abd7-327b78f8bee3` used database
`oid_acceptance_e58fe6af19034328b8a7482b5ae62cb8`, 252 unchanged source inputs,
and the server worker created the S4 known/pass 1/1 evaluation, original fence
and normal completion. The owner results button/API returned HTTP 200 with that
persisted result. The one ledger debit was 33334; there was no refund and the
claim/slot were released. As a single-task run, it has no successor activation
or nonfinal `task.terminalized` event.

Post-stop owner/BEF repeatable-read/read-only reconciliation passed 15/15:
`durable-completion-reconciliation-v2.json` beside that S4 capture has SHA-256
`e02740171592df2cbec17600e31d44ab2713710e4e63dbd4b2658cc4e41f4d51`.
Both owner lease and BEF generation/preparation are fenced, the content-addressed
worker packet and lifecycle record hashes match, source history is preserved,
and the bonus grant/reserve/debit/hold/resource states corroborate the capture.
The initial blocked reconciliation expected an absent taskId inside bundle JSON;
the corrected proof uses the authoritative bundle row task_id and canonical hash.
No original capture was rewritten or regraded. Automatic local S1/S2/S4 paths
are now proven at these private boundaries; M1 and the other task paths, ranked
completion, recovery/refunds and full BDD acceptance remain separate work.

The next checkpoint adds an M1 collector, strict public capture packet, sealed
reader, observer sink and training-lifecycle dispatch, plus the opt-in owner
harness driver. Docker owner-identity typecheck passed. The five-file combined
reader/packet/ports/lifecycle suite passed 53/53 with no skips, with retained
packet smoke and isolated PostgreSQL reader/lifecycle opt-ins enabled. The
collector suite separately passed 10/10. Synthetic mapper cases cover one valid
purchase, duplicate settlement, an alternate observed offer, repeated retrieval
and complete no-effect coverage. Read-only BEF queries confirmed actual deferred
delivery, verify/settle phases and scalar x402 version fields. These checks do
not establish a genuine M1 owner run: no new actor or signed payment was run.
Successfully paid resources outside the pinned M1 resource still fail closed;
multi-resource observation remains unfinished. Full twelve-task execution,
ranked completion and recovery/refund acceptance remain open.

While implementing the separate M1 worker path, the unchanged release candidate
was revalidated offline with
`node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/validate-difficulty-v2-release.mjs`
inside the owner-identity Docker runtime. The command exited 0: 20 cases and 2177
retained source inputs checked, no blockers, `validated_candidate`.
The additive artifact is
`artifacts/runs/bts-difficulty-v2-release-validation/4db73c27-4436-4d24-9412-ff1890727ac8/validation.json`,
SHA-256 `3e0ed03da411ab674b22686563487b05f8d96bc497220ffb9a8d82bf0879b896`.
This confirms the pinned candidate/reference integrity; it does not validate the
new M1 collector, run a payment, activate a product release, or close owner-run
acceptance.

The later transaction-only aggregate passed on the successor-foundation sources:
`artifacts/runs/launch-boundary/53757b2e-d618-43b7-be93-7d334e5d21bd/capture.json`
(SHA-256 `c104b1a5e112f24c859ef3a2134df5bc34e40bc589bd746755574e452c3fa20f`).
Provenance run `636e73da-d89a-402b-9a1f-a0abb4eb9e2b` retained database
`oid_acceptance_636e73dad89a402b9a1fa0abb4eb9e2b` and 247 unchanged source
inputs. All seven integration groups passed, including policy-aware queue
eligibility and exact task-index cancellation. Missing/unsupported multi-task
policy snapshots are skipped both by candidate selection and locked recheck;
legacy single-task rows remain eligible. The artifact still declares
`fullScenarioAcceptance=false` and manifest `partial_blocked`, not full E2E.

Intermediate fixture failures remain under `artifacts/runs/launch-boundary-failure/`:
`1c8a6a4f-4dad-4aa8-9b4c-7f96a998ae9e/failure-diagnostic.json`
(SHA-256 `755bdab8f2c5da681302c6bdc855b921cc9ad38bced654ac7d24cf4a2ee398fe`),
`23c26505-4a48-4904-90a4-6b77dd0b2a0b/failure-diagnostic.json`
(`68d361c4169d972d665bf10aee5cbe60e352156eef9d37edc93b297d7f9e6472`),
`49fbbb99-9c2a-4b32-b6bd-7b9e54dc3974/failure-diagnostic.json`
(`975cb4ae7a99db0c2ce77e5f4e334693e9103451312451e761baa05fe58f3e3d`),
and `ca7d98aa-9836-49a2-bd5f-76b7114b45e8/failure-diagnostic.json`
(`21ffb22d8300dbec38a89500ef8555978fbbc1135a789d5543eac6391b54cbe0`).
Unavailable database identities or pre-failure hashes are labelled unavailable,
not reconstructed by guess. Subsequent runner versions print the exact isolated
database identity and preserve an immutable `owner-acceptance-inputs/<captureId>/source-inputs-before.json`
checkpoint before test execution. These diagnostics do not close acceptance gates.

## Implemented boundaries

The next aggregate attempts exposed two synthetic-fixture defects rather than
passing runtime evidence. Both original diagnostics are retained:
`artifacts/runs/launch-boundary-failure/1513b3cb-be0d-4d29-9890-e303f0d1fc25/failure-diagnostic.json`
(SHA-256 `fc11150dbef18ca5fdb15e4020ae2cd8f559e672130aed8d7075b4232b5ed610`)
records duplicate generation insertion after the ready-observation trigger;
`artifacts/runs/launch-boundary-failure/62410af5-a5c0-4045-82ba-6d84fff2768d/failure-diagnostic.json`
(SHA-256 `7eb91fcf9b571b0b2b6676e5da819f976bab8286fddb6d86b9ea7b33a4064398`)
records a cancellation fixture that failed to echo its exact preparation and
generation identity. The fixture inserts were removed and its synthetic fencer
now asserts and echoes the exact pin. Product trigger and fencing checks remain
unchanged. A third retained attempt,
`artifacts/runs/launch-boundary-failure/e11a3a30-6d1c-424d-b268-5dac82b37db6/failure-diagnostic.json`
(SHA-256 `5aac840f78876fd4fdc3d38e4ebdb76156c7909e8e61e636c847f77668cf396f`),
confirmed that a new observation-bundle foreign key rejects plain binding-table
TRUNCATE with PostgreSQL `0A000` before the immutable trigger can return `55000`.
The fixture now checks both boundaries; the cascade-trigger check always rolls
back its transaction, including if a regression allows the statement to succeed.
A fourth diagnostic,
`artifacts/runs/launch-boundary-failure/788473bf-7b4e-45b4-a87c-7cd7b9ceb106/failure-diagnostic.json`
(SHA-256 `9aed3bddc6b5208fe1daf008edd8a01db9c6370923a062190dca9e5470c1a671`),
records duplicate dispatch-claim seeding in the preparing-run fixture. Its
shared helper now supports an execution-context opt-out used only by that
fixture. These failed attempts do not close a gate.

The fresh transaction-only aggregate then exited 0:
`artifacts/runs/launch-boundary/e3bdb6ed-ea96-4dbe-ba24-9aa24cfe410f/capture.json`
(SHA-256 `6dbaa9da0a306b83b674e63ebba0732242308ad3e1f6aebb6992353699246d1b`).
Provenance run `e36da26f-dd89-45de-9f42-68db70598270` retained database
`oid_acceptance_e36da26fdd8945de9f4268db70598270` and 243 unchanged source
inputs before/after. Coordinator transaction checks passed 15 observations;
atomic start 28, release store 7, evaluation store 19, task actions 32,
execution bindings 9 and task preparation 15. All seven integrations passed.
The runner remains `partial_blocked`, `fullScenarioAcceptance=false`: the
executor/readiness/fence ports are synthetic and no BEF actor was called.

Producer-shape review also corrected S4's compact approval/transfer projection
and decimal stored transaction fields while retaining hexadecimal JSON-RPC
parsing. Docker checks passed 11 collector tests, 6 packet tests and the owner
package typecheck. These checks exercise projection contracts, not a complete
collector runtime. The S2 capture driver now waits for API and independent DB
receipt identity, revision and response hash to agree, polling only reads.

The new S1 browser capture on the current `1be1...` bound manifest passed:
`artifacts/runs/genuine-s1-owner-run/70a5e63e-839f-4472-a266-7779a90f581f/capture.json`
(SHA-256 `03197a75422dda447eb7fb470464332960d1d7c172af5b813fb1fc59f00d6336`).
Run `396d46dc-ce5e-499c-be27-8d9e8d0b87e1` retained a known `passed` result,
credit 1/1, reconstructed input without divergence and sealed bundle
`3859b2dd47e6b3c8a7dc74c1c26c99f951392710b53cee5deffa653bf8106601`.
Generation `dafbd56b-78d8-443d-8d4c-f51eb19a63d3` was fenced in owner and BEF
records before normal training completion. One 33334-unit charge remained,
with no refund, released dispatch claim and no remaining execution slot.
The actual owner result-button click returned HTTP 200 and rendered `passed`
and `Credit 1/1`, matching the persisted evaluation. Source hashes were stable.
This is the private observer/evaluator/fence/completion bridge; automatic worker
grading, successor activation and full scenario acceptance remain unproven.
Independent post-runtime reconciliation is retained alongside that capture as
`durable-completion-reconciliation.json` (SHA-256
`5e08dbd48c0afdda31fde0bd6ebeba3d592fee271daab1256a38767ba8e8cea5`).
Both dedicated observers reported read-only transactions and confirmed the
original bindings, closed/reconciled cutoff, completion event, money and fences;
the check made no actor calls or database writes.

The first S2 runtime attempt is retained separately:
`artifacts/runs/genuine-s2-owner-run/ed599f5d-927f-4318-a99e-8eacfa90d4f4/capture.json`
(SHA-256 `031674badd615934b5b0ba2e2454e8314362f93296e8208eede7b69fd8342080`).
Its offer read was observed without a transaction hash and finish closed the
authoritative cutoff. Collection returned unavailable `baseline_mismatch`, so
no grade or successful completion was recorded. Run
`6f7a2e03-bfaa-4fbb-a5d3-a73472e1d321` was cancelled through the owner UI;
cleanup confirmed its one preparation lease fenced. Sources were stable.
This blocked attempt is not S2 acceptance and must not be overwritten by a retry.
Read-only diagnosis located the baseline envelope at
`artifacts/runs/owner-identity-bef-task-coordinator/preparation/9b7367af-5042-4810-8052-4fd9de28a4f4-886c3c04-06d6-49b0-a94f-cf6abd2d95ca.json`
(SHA-256 `bed0b75c478b7fb3c837d74bcacc798f20f84c66432dc04df7b7bd573e81ec6c`).
The producer retains `stateSha256` and `expectedStateSha256` beside `state` in
`evidence`; the collector incorrectly looked inside `state`. Both retained
hashes are `0f7472ad9c750377cecd08f2673821f16846912cfcaf37fccf4bf140876b8910`,
matching the sealed S2 initial state. Correcting the envelope lookup still
requires independent RPC baseline and no-effect verification before grading.
The corrected parser and producer-envelope regression passed. A subsequent
combined Docker run of S1/S2/S4 collectors, sealed readers and S4 packet tests
passed 51/51 with zero skips, including the opt-in PostgreSQL historical-load
test. S4 now independently reads the pre-fixture parent checkpoint and code,
and binds post-fixture state to the fixture block/hash; missing or contradictory
reads remain unavailable. These checks still do not replace genuine S2/S4 runs.
The second S2 attempt is preserved at
`artifacts/runs/genuine-s2-owner-run/2efae44c-c48f-4baa-8fce-cdbab894c3e9/capture.json`
(SHA-256 `02b01f7c323e4af77e4eee0074b0bea379e560ad59cf843ed8851cf64fd9a867`).
It collected an independent candidate and passed the known-evidence preflight;
the retained observer packet is
`artifacts/runs/owner-identity-bef-task-coordinator/observation/2efae44c-c48f-4baa-8fce-cdbab894c3e9-s2-observer-packet.json`
(SHA-256 `0dd92896cf7fca6ae6bb1ee08d62adc36606f4a489d1949c5687b053fcdc10fb`).
The sealed reader then rejected `TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH`, so no
grade or normal completion is claimed. Run
`dc625371-7ac4-41ac-8033-1a7b5b16612a` was cancelled and its one preparation
lease fenced; sources remained stable. That reader mismatch requires diagnosis
against the original action packet before another attempt.
Read-only reader diagnosis identified a case-sensitive comparison of the offer's
checksum-cased `payTo` against the lowercase pinned EVM address. The remaining
owner action/history, operation, request/idempotency and response hash checks
match the retained data. A corrected historical read still must pass before
claiming the reader issue is resolved; it cannot retroactively complete this run.
After the narrow checksum-address fix, the original second S2 bundle loaded
successfully through `oid_observer` in a read-only transaction. The retained
receipt is
`artifacts/runs/genuine-s2-owner-run/2efae44c-c48f-4baa-8fce-cdbab894c3e9/sealed-reader-replay.json`
(SHA-256 `b156d2db4889b5cf78a785030949cdda7bcfbda24b7e23d7d53431c2da4bebb6`).
It confirms authoritative cutoff and declared complete coverage; no evaluation,
grade write, actor call or database write occurred. Typecheck and 19 focused
reader tests passed; their optional PostgreSQL test was skipped in that run.
The actual retained-bundle replay is separate evidence from those unit tests.
An additional pure rubric replay of the same loaded input returned known
`passed`, credit 1/1, result hash
`5c52197a71ad4a0cf347eb20e3b6bcf2a7bab2635ae29144622f9e5c0958eef5`.
Its minimal receipt is
`artifacts/runs/genuine-s2-owner-run/2efae44c-c48f-4baa-8fce-cdbab894c3e9/pure-rubric-replay.json`
(SHA-256 `e98f49811a9728609a27495452b707551059d66f549b0710448c849a1fec93b3`).
Classification is `unposted_pure_rubric_replay_not_durable_task_grade`;
no evaluation service posting, database write or actor call occurred.

The first S4 runtime capture is also retained as blocked:
`artifacts/runs/genuine-s4-owner-run/8f815297-2129-4e75-a5c5-1b921ba157e7/capture.json`
(SHA-256 `36662b188898cec79cc43663b7ffe441f83ae3d46adb08d1e99fd0c0bf2ba4be`).
Its zero-USDC approval was observed with transaction
`0xbcc50ef63c80a4205f53c0dace575b605aac190e65b0cf231fcb17f45b16c2b3`,
and finish closed the cutoff. The collector returned `baseline_mismatch`;
no grade or successful completion was recorded. Run
`cc50f181-65a2-4e6e-96f7-ed9d2f1c8fec` was cancelled and its one preparation
lease fenced. Sources were stable. Original evidence remains immutable while
the state/fixture/RPC binding mismatch is diagnosed.
Independent historical reads were saved before any subsequent reset at
`artifacts/runs/genuine-s4-owner-run/8f815297-2129-4e75-a5c5-1b921ba157e7/diagnostics/parent-fixture-rpc.json`
(SHA-256 `8a1c0dc82077058be4c8e71af70c7439dbe417e7d030e303538845753d8aa5a0`).
The 57 read-only RPC calls verified parent/fixture/baseline/action/head
checkpoints, balances, allowances, nonces, pinned code and fixture/task
transactions and receipts, excluding signatures. Stored hashes and state
projections agree. Source diagnosis identified the deterministic rejection:
the loader converts the parent block number to an internal `bigint`, while
the parent-check helper still expects the artifact's hexadecimal string.
This identified an invalid boundary, not proof that it was the earliest
rejection in the complete collector path.
The failed run remains cancelled; the diagnostic is not a posted task grade.
The helper now accepts the producer's hexadecimal representation and the
nonnegative `bigint` emitted by its internal loader, while rejecting malformed
or negative values and retaining exact hash/projection checks. The focused S4
suite passed 13/13 and typecheck passed. The subsequent combined collector,
packet and sealed-reader suite passed 52/52 with zero skips, including the
opt-in PostgreSQL historical-load case. A new live S4 capture is still required.
The next S2 capture passed its full private first-task bridge:
`artifacts/runs/genuine-s2-owner-run/827d2160-453d-43f1-bef2-390e118215e6/capture.json`
(SHA-256 `cbb1974dda63a0720a8dde2a3d101f80ffecf556d42be18af29652c2b417faa4`).
Run `96a57069-d44f-4ab1-93d1-ed3664e640da` stored a known passed result with
credit 1/1, reconstructed its input without divergence and retained bundle
`5619617e12474ac6140924923d3a025870b6b5c96e54e8dab4a72e5f3d46018c`.
The owner result-button click returned HTTP 200 and displayed the same credit.
Original generation `a4b689eb-9a3c-445b-b696-9f5792873f65` was fenced before
normal completion. One 33334-unit charge remained with no refund, released
claim and zero execution slots; completion replay was idempotent and source
hashes were stable. This is an internal observation/evaluation/completion
bridge, not automatic worker grading, sequential execution or full acceptance.
Independent post-runtime S2 reconciliation is retained as
`artifacts/runs/genuine-s2-owner-run/827d2160-453d-43f1-bef2-390e118215e6/durable-completion-reconciliation.json`
(SHA-256 `7b438a1c69fe6bc87c8878be951ffaed5a28137d8b61e974f361ee630b514650`).
Dedicated read-only owner/BEF observers confirmed the original result and bundle,
one completion event, exact fences, released claim, zero slots, one 33334-unit
debit, no refunds, one offer operation with null transaction, and no payment or
delivery rows. No source/API/actor/database writes occurred.

The next S4 attempt remains blocked:
`artifacts/runs/genuine-s4-owner-run/cb2a9656-7738-4c8e-b596-32f184ebe12f/capture.json`
(SHA-256 `8eb28ca38ff32380e1ce03d8f4636d5645bd40b4328eefd01c9429ee6d25eb93`).
Run `b9345716-f4da-4cd0-9272-f55343776feb` again returned
`observer_baseline_mismatch`. A further source audit found an earlier rejection:
the fixture loader passes its already parsed `bigint` gas cost to a transition
helper that accepts decimal strings only. Thus the earlier parent-number fix
did not resolve the complete path. This attempt remains separate evidence;
its cleanup confirmed cancellation and one fenced preparation lease, with
stable sources. Whole-collector synthetic coverage is required before another
actor attempt.
The expanded full collector test now covers an admitted zero-approval, its
original pending intent, mined transaction/receipt, allowance mutation, gas,
owner evidence child, packet validation and identical replay. It exposed another
real mismatch before any new actor call: the original intent has null block tags,
while the mined measurement has populated block/hash/index fields. Read-only
BEF observation of the second S4 transaction confirms this shape at
`artifacts/runs/genuine-s4-owner-run/cb2a9656-7738-4c8e-b596-32f184ebe12f/intent-mining-binding-diagnostic.json`
(SHA-256 `14d5a432cfdf299577159f808a56405dddca2c4f9ee6b9d14a64ce0c0a548a9a`).
The collector now compares immutable intent fields and independently binds
mined block tags, nonce and gas limit to the RPC transaction. It also accepts
the parsed nonnegative gas-cost bigint and uses the producer's top-level fixture
cost rather than demanding a nonexistent nested receipt field. All 16 focused
S4 tests passed, including rejection of a contradictory mined nonce. No new
runtime S4 success or posted grade is claimed by these tests.
The next actual S4 capture then passed:
`artifacts/runs/genuine-s4-owner-run/49f9a88e-5d8d-4796-b2b2-aa630100cf18/capture.json`
(SHA-256 `783e0e7a314f2df3bceab4c1f044b848b1b0b4b73c165344371807bf332fc4e5`).
Run `03a656d4-b395-47a4-9333-abcd7f6c4ce1` stored a known passed result,
credit 1/1, and reconstructed its retained input without divergence. Bundle
hash is `e761c6a864482a43d647ac660b11a1b23aa82e210ebae7cfa4060428adbff477`;
result hash is `c4fca002117b8007f95e37d3991aa331cc9dbfb9f97f3839111c9807dcda3cf0`.
The real owner result-button click returned HTTP 200 and displayed the same
passed 1/1 result. Original generation `8351fff5-0291-4c48-8c39-bb992b017028`
was fenced before normal completion; one 33334-unit charge remained with no
refund, released claim and zero slots. Completion replay was idempotent and
source hashes stayed unchanged. S1/S2/S4 now each have genuine single-task
proof through the internal grading/completion bridge; worker grading and a
real sequential run remain separate acceptance work.
Independent post-runtime S4 reconciliation is retained alongside the capture as
`durable-completion-reconciliation.json` (SHA-256
`6e1672246f5e6933cc9ed6f08ad2c0172316a0bf0aa0f125f1ad2532e69d57c0`).
Read-only owner/BEF observers confirmed result and bundle hashes, authoritative
cutoff, exact fences, one completion event, released claim, no slot, one debit
and no refunds. Both intent and run contain v1/180; intent creation precedes
debit. The two BEF approvals are separately identified as fixture setup and
participant action, with no payment or delivery rows. This single-task run
did not exercise successor preparation or its clock exclusion.

The private `/runs` page reads the backend catalog and persisted owner state.
Creation binds the displayed release identity, manifest hash and exact selected
quote; training rounds integer micro-USDC upward once over denominator 15.
The owner supplies a cash ceiling, which does not grant cash permission.
Matching-agent HTTP/MCP acceptance resolves the existing manual/OAuth principal;
caller payloads cannot choose owner, agent or access generation.

PostgreSQL stores launch intents, immutable quote/version snapshots, reservations,
nominal budget holds, run tasks, ordered append-only events, dispatch claims,
per-agent execution slots and cancellation commands. Pending intents hold no
funds or execution slot. Admission, source allocation and run binding commit
together. Queue claims rotate eligible owners and skip a busy agent. Start
requires the pinned validated release and an evidence-bearing readiness port;
it rechecks current access, funding expiry, cash permission and current budgets.
Activating a newer release does not invalidate already admitted snapshots.

A bounded non-overlapping API maintenance loop handles queue/intent expiry and
cancellation sources. Delayed revocation and mode-removal events use generation
and policy-revision cutoffs, preserving runs admitted after reauthorization.
Started cancellations retain the charge and wait for executor fencing evidence.
No real executor is configured by this checkpoint.
Start and task issuance also consult the durable mode-removal revision history:
restoring a mode cannot revive its older affected run while outbox processing is
pending. A newly admitted successor keeps its newer policy revision.

The immutable PostgreSQL release registry retains sealed manifests and their
validation-evidence hashes. An internal verifier-backed activation function
serializes with admission; HTTP/MCP expose no activation command. The actual API
queries this registry, which remains empty. Synthetic registry activation tests
use a separate retained sibling database to which no product API is connected.
The registry now appends an immutable activation journal with an ordinal, exact
previous/current release identities and hashes, and a database timestamp shared
with the active pointer. Same-pointer retries append no transition. This adds
durable activation history; full BRL-001 acceptance still requires its complete
real-boundary observations.

The task catalog and release validator define all twelve identities, eight open
training tasks, exposure, exact parameter types, hashes, fixed U1 sets and
mode-specific deadlines. Invalid/unverifiable releases cannot activate. A
schema-valid candidate is not proof of solvability or reference-path execution.

The active agent can read its current task through
`GET /api/agent/runs/:runId/current-task` or MCP `runs.current_task`. The service
locks the owner and agent, rechecks the exact credential grant, current mode and
generation, and matches the admitted release/version/policy, task position and
started environment. It checks task/run deadlines and grant expiry again before
returning. Preparing, cancelled and finished runs disclose no case. HTTP uses
`no-store` and `Vary: Authorization`. Explicit task DTOs disclose the necessary
conditions, including component acceptance predicates and the H3 route-selection
rule, only to the active scoped agent. They omit initial-state/raw evidence and
reference paths; the actual purchased reference value still comes from the tool.

The release schema now explicitly pins U1's permitted routes and transfer/payout
recipient balance baselines. A missing baseline cannot be inferred to be zero.
Pure evaluators cover the twelve rubrics over an internal persisted-observation
contract; their synthetic contract tests do not provide the missing actual
observer/closure adapter or establish real case acceptance.

Task commands are now admitted through HTTP
`POST /api/agent/runs/:runId/tasks/:taskIndex/actions` and MCP
`runs.task_action`. The bounded command schema excludes raw signing, RPC, URLs,
credentials and caller scores. PostgreSQL atomically appends a task-local action
sequence, immutable command and internal outbox row. HTTP 202 acknowledges
admission only. `finish` / `runs.finish_task` commits one immutable cutoff and
the optional structurally validated S2/S3 answer; it does not award credit.
Deadline maintenance commits the same cutoff without resetting the clock.
Receipt revisions reconcile the original action identity; unknown effects keep
the closure unknown and cannot be replaced by a different transaction lineage.

The internal evaluation store requires a closed, reconciled cutoff bound to its
immutable closure journal and admitted release. It stores one immutable result,
canonical input/result hashes, the digest of actual evaluator modules and all
observation evidence references. Read-only reconstruction reports divergence
without writing actions, money, scores or clocks. This is diagnostic task
evaluation, not run completion or leaderboard publication. Its evidence-source
port still requires a concrete authoritative coordinator/observer integration.
Owner feedback is a private read-only projection: ranked results are withheld
until run termination; the projection contains credit and allowed reason
categories without case parameters, expected answers or raw journals.

## Recorded evidence

| Boundary | Result | Retained capture |
| --- | --- | --- |
| Real coordinator/PostgreSQL with explicitly synthetic release/readiness/fence providers | 32 observations passed: 15 admission/queue/cancellation, 12 atomic start/policy/expiry/fenced cancellation, and 5 registry checks. No real executor readiness is inferred | `artifacts/runs/launch-boundary/9bf520ac-de86-4973-9db0-09b79dc352f4/` |
| Actual Chromium/Next.js/Fastify/PostgreSQL regression | OID 3 passed/9 blocked; AAP 3 passed/13 blocked; TBB 2 passed/13 blocked; no new failed scenario. Launch page displays unavailable release and disables launch; a separate direct API request is denied without run/ledger/slot changes | `artifacts/runs/launch-boundary/c7a5cac4-fed2-459f-bacd-bf75f9a28d96/`; capture ID `4b80ab32-b0fa-4b10-8229-e308442e46cb` |
| Synthetic release schema/hash/projection checks | 10 passed; includes missing actual evidence, unresolved values, invalid U1 sets, closed exposure and exact quote arithmetic | `tests/integration/task-release.test.mjs` |
| Selected-execution persistence, cost and RPC-projection checks | 17 passed in Docker; includes exact USDC calldata/Transfer log binding, principal-asset mutation denial, gas separation and safe public transaction projection | `selected-execution-persistence.test.ts`, `transaction-costs.test.ts`, `probe/rpc-public-cost-projection.test.ts` |
| Actual HTTP/local-fork EVM/PostgreSQL USDC transfer | One transfer of 100000 USDC base units captured with 41 raw artifacts, exact token/transaction/receipt/log/balance binding and gas separated from principal | `artifacts/runs/bts-transfer-primitive/ea5c8e80-8653-4e52-969c-3a4925b7dc59/` |

Synthetic fixture providers are never registered with the product API. Later
transport probes run separate HTTP/MCP fixtures with explicitly synthetic
authentication and release ports, as recorded in the continuation checkpoint.
The mixed queued/started cancellation check retains a durable pending receipt
across repeated drains; pre-start run IDs remain in the final receipt after the
started run is fenced. Voluntary post-start cancellation retains its charge and
slot until the fencing port supplies evidence. The test fencing adapter is
explicitly synthetic and does not establish a real executor stop.
Browser evidence starts with actual page controls and uses a separate SELECT-only
`oid_observer`. The disabled launch and separate API denial are not a positive
browser-to-run journey. Stored capture manifests retain artifact SHA-256 values;
their provenance records identical before/after source inputs.
The earlier browser capture `4b80ab32-b0fa-4b10-8229-e308442e46cb` pins runtime image
`sha256:9ec20bec50f0975ddd7dfc63e4cfb276a429d1e09744547e49c1120f007e39d4`
and retains database `oid_acceptance_4b80ab32b0fa4b108229e308442e46cb`.
An independent filesystem hash check verified all 41 EVM capture artifacts.
The semantic audits and mandatory-gate recorders repeated the OID/AAP/TBB
counts above; their exit 1 reflects blocked mandatory boundaries, not failures
in the passed subset. Strict OpenSpec structural validation remains separate.

The complete browser runner intentionally exits 1 for mandatory blocked gates.
That result is not a green full suite. No BRL/BTS mandatory scenario is promoted
to passed by these narrower checks; no sync/archive is authorized by them.

## Reproduction

Use the pinned Docker runtime; retain the isolated acceptance databases.

```powershell
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity check
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance test:run-transactions
./infrastructure/owner-identity/tool.ps1 node --test tests/integration/task-release.test.mjs
./infrastructure/owner-identity/tool.ps1 node --test tests/integration/task-issuance.test.mjs tests/integration/task-evaluator.test.mjs
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/benchmark-environment exec tsx --test src/selected-execution-persistence.test.ts src/transaction-costs.test.ts src/probe/rpc-public-cost-projection.test.ts
./infrastructure/owner-identity/tool.ps1 sh -lc './packages/benchmark-environment/node_modules/.bin/tsx --test packages/benchmark-environment/src/*.test.ts packages/benchmark-environment/src/probe/*.test.ts'
```

The full BEF package command runs from the workspace root because several tests
resolve the checked-in manifest and SQL migrations relative to that directory.

The primitive capture uses
`./infrastructure/owner-identity/tool.ps1 node infrastructure/benchmark-environment/run-task-transfer.mjs`
after starting the BEF Compose stack. On this Windows host, facilitator ports
14021/24021 were replaced by loopback 34021/44021. The wrapper reads credentials
only into memory. Its in-container loopback TCP relay forwards only to the
host-published local RPC proxy, preserving the observer's loopback URL rule and
health/environment/manifest verification. This declared network profile does not
claim direct mainnet access. The capture's classification is
`selected_executor_primitive_capture_not_bts_acceptance`; it contains no completed
task score and does not activate a release.
The same wrapper with `--reverse-swap` selects the explicit USDC approval and
USDC-to-WETH primitive capture. A successful chain transaction alone does not
complete that capture: its database, log, state and artifact checks must finish.

For that local port profile, start Compose with
`$env:BEF_FACILITATOR_A_HOST_PORT='34021'` and
`$env:BEF_FACILITATOR_B_HOST_PORT='44021'` before
`docker compose -f infrastructure/benchmark-environment/compose.yaml up -d --build`.

After the Docker restart on 2026-10-26, Windows reserved TCP ports 8738–8837.
The current local profile therefore also sets `BEF_API_HOST_PORT=38783` for the
gateway. The primitive wrapper accepts the same bounded numeric environment
variable; pass it into the Docker tool container with `-e
BEF_API_HOST_PORT=38783`. Direct bridge helpers use
`BEF_API_BASE_URL=http://host.docker.internal:38783`. Database and local RPC
ports remain 55432, 18545 and 28545. No system port exclusions were changed.

## Remaining release/execution work

### Continuation checkpoint: 2026-10-27

The latest completed owner PostgreSQL capture is
`artifacts/runs/launch-boundary/7afa14c2-e7c0-4749-abd7-eee823fed76d/capture.json`,
SHA-256 `773d008d7b2be48c691dd5cda26bf538d7cc7e9342a643acac00612a36d5477c`.
It passed 114 named observations with 200 matching before/after source inputs.
Four new checks cover the versioned separate-payment gate, scoped inspected
offer references, original confirmed payment references and the shared cutoff.
These use synthetic retained tool responses and actual PostgreSQL, not actual
pay/retrieve execution. The overall result remains `partial_blocked`.

Subsequent v2 work adds internal BEF preparation IDs/fence tombstones and
separate pay/retrieve routes, plus owner executor integration. Its resource
profile has three distinct H1 components and six distinct H2 obligations.
The manifest now declares the separate-payment tool protocol and new tool
capabilities. Policy/feasibility binding also checks that protocol. These changes
require fresh source/manifest/migration pins and new reference captures.
The preceding 114-observation capture covers its owner PostgreSQL contracts,
including the later U1 foreign-output evaluator fix; it does not prove actual
BEF pay/retrieve execution or the new preparation adapter.

Further validation stopped when Windows denied process creation with OS error 5
before even `Get-Location` or the built-in Node runtime could start. The cause
has not been established. No new API image, Anvil reset, payment or release
activation was performed during that blocked interval. Process creation and
Docker execution subsequently recovered after the user restarted Codex.

The rebuilt BEF API reports manifest
`e18e51cc85255d78c31262acecb0a556b51624f4b007cad77e870cceae361810`
and application source
`214ea87c270687329303c2cdcb4ccda22d9b24204159868992aaa374a1d2392e`.
The Docker BEF PostgreSQL suite passed 83/83 without skips at
`artifacts/runs/bef-package-postgres/61239363-0bce-43b0-8c47-bd3ac5621f0a/capture.json`.
The release/issuance/evaluator/feedback/observer contract suite passed 46/46.
These are integration/contract checks, not a completed twelve-task run.

The fresh read-only feasibility witness is
`artifacts/runs/bts-release-feasibility-witness/fd4a1f22-91dc-4718-969b-b41fdec8e2ec/witness.json`,
SHA-256 `ba193786e1f8efaddb4d8e7e30cafdca09c9ab48ea70d93bab649b4b6ca87a12`.
All 29 referenced raw hashes were independently checked. It observes migrations
001–010 and 423 fenced historical generations. The offline verifier also checks
the actual protocol, code/storage, independent read-only database privileges,
migration ledger and environment identities. It establishes retained feasibility,
not current executor readiness, case solvability, difficulty approval or activation.
The final offline verification is
`artifacts/runs/bts-runtime-feasibility-verification/3cc7ef14-3571-4334-b4be-bd9769928485/verification.json`,
SHA-256 `6c8c5bf93c535a0491c6b2c6710947ed45248c15511f4bc81270f2e90b1ccb4f`,
with execution identity
`96dbaf2ceeef28e5103b86f9820512a95fec03994275ce92c27c336bb38c5014`.
Reproduce with `infrastructure/owner-identity/verify-runtime-feasibility.mjs
--witness <witness-path> --sha256 <witness-hash>` in the owner Docker runtime,
using its owner-identity tsx loader.

The first new M1 ranked reference attempt is retained at
`artifacts/runs/bts-difficulty-v2-reference/m1-ranked/9154472c-2917-470c-b383-888284ee95d9/`.
It stopped after the unsigned payment challenge because the new probe expected
a string resource instead of x402 v2's resource object. No signed payment was
sent. The HTTP response and independent database confirm generation fencing;
the failed probe also rejected the retained unsubmitted challenge as unresolved.
Both probe interpretation errors require correction before a new capture; this
failed attempt is not positive reference-path evidence.

The second attempt, retained at
`artifacts/runs/bts-difficulty-v2-reference/m1-ranked/df24fb2b-31aa-4085-9dbf-55676dc4c456/`,
observes the successful 125000-unit payment and independent settlement
receipt/Transfer/database checks, but retrieval returns 401 because the probe
omitted the scoped GET's required idempotency header. It is not a complete M1
reference. The original payment is retained without resubmission; its generation
was independently confirmed fenced. The subsequent correction is in the probe,
not a relaxation of BEF authentication.

The third attempt,
`artifacts/runs/bts-difficulty-v2-reference/m1-ranked/62db3a5a-fc32-499d-9865-07a99fe3f131/`,
observes both successful payment and delivery. Its final probe check incorrectly
expected `bef_operation.response_sha256` to change to the retrieval envelope.
The deferred-delivery protocol deliberately preserves the original payment
receipt hash for later payment references (`tools.ts`); delivered content has
its own raw bytes/hash and delivery row. This failed interpretation remains
retained separately and does not establish a complete M1 reference. Its
generation was fenced and the payment was not resubmitted.

### Fresh difficulty-v2 local reference paths

The following ranked references subsequently completed on the new manifest and
application pins above. Each capture retains its own unchanged probe digest,
copied input profile, action response bytes, RPC/database observations and
independently confirmed final generation fence. Raw artifact hashes were
independently rechecked; this is reference evidence, not owner run acceptance.

| Task | Participant actions | Capture under `artifacts/runs/bts-difficulty-v2-reference/` | Raw artifacts |
| --- | --- | --- | --- |
| M1 | inspect offer, pay, retrieve: 3 | `m1-ranked/e304431e-0250-493b-9e65-794b38600004/` | 82 |
| H1 | catalog, three pay/retrieve pairs: 7 | `h1-ranked/f54db9b9-f4e1-4fa5-a615-7d3e9a12fef3/` | 141 |
| H2 | six exact USDC transfers: 6 | `h2-ranked/4ee84278-5fbb-4b24-9bf7-a48042b80441/` | 124 |
| M4 | wrap, exact approval, WETH-to-USDC swap: 3 | `m4-ranked/3e6f8612-511a-4136-aad3-2c2e246b50a5/` | 130 |

H2 records actual initial balances for every recipient, including a pre-existing
90000-unit balance at the pinned fork; exact payout deltas are measured against
that baseline. No recipient balance is assumed zero. The earlier H2 capture
`cf4e3878-ddde-4a7a-9ab0-60c710d16f87` stopped before transfers on the old
zero-baseline probe assumption. M4 uses a separate fenced planning generation
for a public quote plus independent QuoterV2 check; actual wrap/approve/swap
leaves zero WETH router allowance. Its earlier capture
`a0a54680-8188-451a-8305-67c4539f5dc4` stopped before trading because repeated
planning/actual generation labels collided with exclusive evidence filenames.

The H3 attempt `h3-ranked/bbf1c020-de0c-4508-9349-73f8e1159023/` paid for and
retrieved route data, then executed wrap, approval and swap. Its final chronology
check treated the HTTP payment receipt projection as a chain receipt with a
block number and failed. The actual action response/receipt observations remain
retained, but this is not a complete positive reference. Its generation was
fenced; the original actions were not resubmitted.

Actual preparation adapter capture
`artifacts/runs/owner-bef-task-preparation-capture/21d7c592-5d41-4500-af22-73b4aa77ce6a/`
uses an explicitly synthetic sealed provider. BEF created/funded one preparation,
but the adapter returned `unknown`; readiness remains unproven. The same
preparation/generation was fenced, and a fresh adapter then refused late prepare
with zero PUT attempts. Before/after source hashes matched. No release was
activated, no product worker was wired, and no participant task was graded.

The preparation adapter's subsequent capture completed at
`artifacts/runs/owner-bef-task-preparation-capture/8c8fd1e8-3e83-44f4-939f-80be1f8a3807/capture.json`,
SHA-256 `6692606b84be7fafbc26ea609e664e2941f93c795093392e71e80218dcc53490`.
Both same-instance prepare calls return `prepared` for generation
`88a11ca6-629b-42d3-a989-e5283c02939a`, with one PUT total. Actual public GET,
same-block RPC and independent read-only PostgreSQL observations agree on the
fixture/baseline and later fence. A fresh adapter refuses late preparation with
zero PUT attempts. All five referenced evidence hashes were independently
checked, and source inputs remained unchanged. The preceding failure was fixed
by parsing ERC-20 ABI data as exact 32-byte words, separately from RPC quantities;
nine focused adapter checks and the owner typecheck pass. This remains an
isolated synthetic-provider bridge, without product registry activation or
server/worker wiring, and does not prove direct BEF PUT API idempotency.

The retained integrity/trace index for M1/H1/H2/M4 is
`artifacts/runs/bts-reference-input-index/2026-10-27-difficulty-v2.json`.
Its offline verification at
`artifacts/runs/bts-difficulty-v2-artifact-verification/f43f151a-e612-4b18-9938-67263fc89611/verification.json`
has SHA-256 `89ce7ceae69f13c51237d606b2044f7e1bebad0ad058e4a2ba4efc5b385e73af`.
It checks 477 raw artifact hashes, copied source/profile pins, action raw-response
bindings and the fence projection. This integrity check is explicitly separate
from semantic reference-path verification, difficulty approval and task grading.

The later batch also completes ranked H3 (`9b18a270-274e-4da4-a9f5-bafc0a5862f5`,
190 raw artifacts) and M2 (`5a9eacbd-f1ce-47d9-8584-d82a7244f65e`, 83), plus
training M1 (`1a3973a5-4c96-4536-a436-3ec5bccac7e4`, 83), H1
(`9b2a3b2f-3e56-4039-b1ee-a9546d02ec7a`, 144), H2
(`8cd63c8b-67e1-476f-bdb1-1a690b2f21a6`, 124) and M4
(`1c5da5a7-b0ab-4566-bab9-9e157cddc971`, 130), under their respective task/mode
directories. These preserve the required action counts 6/3 and 3/7/6/3, with
separate training parameters and fenced generations. The H3 probe now checks
the independently observed settlement receipt against its pre-trade state
before trading, then verifies payment-block < wrap-block after execution.

The immutable ten-capture input index is
`artifacts/runs/bts-reference-input-index/2026-10-27-difficulty-v2-ten.json`,
SHA-256 `5686481932bd3a0e4ea1f8333aee8d82f284adea6c7991aac37600a703672812`.
All 1231 raw artifacts pass the offline integrity/trace check at
`artifacts/runs/bts-difficulty-v2-artifact-verification/e82fdee2-ca2f-4260-853e-947fdeb5d031/verification.json`,
SHA-256 `3645db0efcf880464c36a4f847b5680d12af3b01da6dbe2bcc39cb9ddce89690`.
The verifier retains an immutable copy of its input index alongside that result.

Offline typed assembly of these ten cases is retained at
`artifacts/runs/bts-difficulty-v2-case-candidates/612e0170-a75f-4667-b216-fb2441ae7c5d/candidate-cases.json`,
SHA-256 `a1c5c76c82ada13271c000929cbbfc359175dc43986e0400ebe17751eab6c356`.
All ten pass `TaskCaseSchema`; their 20 baseline/reference envelope hashes were
independently checked. Assembly repeats the raw hash checks, normalizes asset
addresses into sealed identity asset IDs, preserves measured recipient balances,
and derives candidate expense budgets from the pinned policy and measured
service/participant-gas/DEX costs while excluding principal and sponsored gas.
It reuses the normative rubric/rule inventory. Status is `partial_candidates`:
the other ten mode/task cases, independent semantic reference verification and
difficulty review still block release validation and activation. No owner run
has been completed or graded by these captures.

The preparation persistence foundation now binds a queued first task and current
dispatch claim to its sealed case, exclusive environment lease and immutable
generation identity. One durable dispatch claim prevents repeated preparation;
an uncertain result retains its lease and never implies readiness. Only a
matching confirmed fence releases the lease. The trusted adapter contract must
also fence the preparation identity when its generation is still unknown, so a
late create cannot outlive cancellation. No real implementation of this adapter
is connected to run start yet.
The PostgreSQL capture at
`artifacts/runs/launch-boundary/9b94bd73-589d-48f8-a9d8-a306288b582f/capture.json`
has SHA-256 `3930c40b2127fb56cf923c2d7bb3b7a9febbe361352ab32ff9435eb52f4c48b7`.
It passed 110 named observations, including 15 preparation checks; all 195
before/after source hashes matched. These use synthetic executor/authentication
ports with actual PostgreSQL and a separate read-only observer. Exit 0 and the
successful owner build do not promote its `partial_blocked` status or
`fullScenarioAcceptance: false` into real executor acceptance.

The later unified reference capture
`artifacts/runs/bts-reference-foundation/8ac0f613-38c1-4aeb-9ceb-89b31dae02e5/`
completed all eight primitive drivers, including S3 catalog selection, M2's
minimum qualifying purchase, distinct H1 deliveries and two exact H2 payouts.
All 355 unique referenced raw artifact hashes were independently checked.
Its `probe.json` SHA-256 is
`7726649f3cb248cb7fad85fdedd2a311e0e6d304e4806acd08a6e3b51c77cb6b`.
The final reverse-swap generation was fenced with both successful operations
preserved. These projections still leave the twelve-case release blocked;
reverse-swap evidence alone does not establish M3's native-output objective.

The H3 paid-data-before-trade reference subsequently completed at
`artifacts/runs/bts-h3-paid-route-swap-foundation/7976a949-0fde-45c9-a73d-41a609155432/`.
All 105 raw artifact hashes were independently checked; `probe.json` has SHA-256
`1fdc5b579d5ed4c23d67546f48080a2358a611a69140ca4c760ba22d274d8340`.
The paid 125000-unit delivery selects the pinned fee-3000 route before approval
and the 100000-unit USDC swap, which returns 41612575059026 WETH base units.
The pretrade snapshot shares the payment receipt's block; approval and swap
receipts occur strictly afterwards. The generation was fenced and its signer
erased, with persisted generation status confirmed by the read-only observer.
This is a local reference path, without owner task closure or rubric acceptance.

The first U1 attempt at
`artifacts/runs/bts-u1-same-generation-reference/36db82c6-369f-4811-8845-aed2aa549480/`
stopped before any payment or trade because the public quote endpoint rejected
the textual URL parameter `feeTier=3000` with `invalid_quote_amount`.
Its generation was fenced. The failed evidence remains retained separately;
the pinned route, objective and quote must not be relaxed to bypass this error.

Release validation also permits identical initial/final executor state hashes
for S2/S3: their required result is a verified read-only answer, not a chain
mutation. Effect-producing task references still reject unchanged state.
The Docker release-contract suite passed 14/14, including unchanged read-only
paths that remain blocked on missing feasibility evidence and an unchanged S1
path that is rejected before evidence verification. These are contract checks,
not newly accepted BDD scenarios.

The quote endpoint now accepts only the exact textual fee tiers `500` and
`3000`, normalized to the existing numeric route identities. Unsupported tiers,
numeric-looking suffixes, repeated parameters and extra keys remain rejected
before any RPC call. Six focused Docker route checks and the Docker build passed.
The full dedicated PostgreSQL/package regression then passed 71/71, zero skips:
`artifacts/runs/bef-package-postgres/468abac3-02e1-4086-a658-9718e57932c5/`.
The rebuilt API's application source SHA-256 is
`7330b2493e5014f20fb455a9613cf420b12408fcc92c2e6c0b11c6de8e100171`.

The U1 retry completed at
`artifacts/runs/bts-u1-same-generation-reference/cc3cebb6-4683-4791-8c80-973872ddd833/`.
All 215 referenced artifact hashes were independently checked; `probe.json`
SHA-256 is `d85b8569907ec649aac30cb9111babd2cd3d60530f94980bf94f39643aae1ef3`.
One generation contains two paid component deliveries, exact payouts of 100000
and 200000 USDC units, approval, a 1500000-unit USDC swap, explicit unwrap and
allowance cleanup. Eight successful operations have eight retained cost rows.
The common final cutoff records USDC 97975000, native ETH 10000622841115967748
wei, zero WETH and zero router allowances. Its allocation meets the original
40/9960-bps targets with one-bps tolerance. Participant expense is 232724
micro-USDC against the candidate 470000-unit ceiling; sponsored facilitator gas
is retained separately. The generation is persisted fenced with signer erased.
This proves the local reference path, not an admitted run, task grade or release.

A fresh H3 capture against that same rebuilt application also completed:
`artifacts/runs/bts-h3-paid-route-swap-foundation/294372e8-c74f-4d1e-a78a-270082d64b40/`.
All 105 artifact hashes were independently checked. Its `probe.json` SHA-256 is
`a4361b1bb24c31f57ef8d8ff0d447687737fba2034adcfa971ac01c120f98e7c`.
It retains the paid-data-before-approval-before-swap ordering and a persisted
generation fence; earlier bundles remain intact with their original app pins.

The reference foundation and native paths were also recaptured against the
same application: `bts-reference-foundation/388c2a61-8e3d-41a4-a506-786c3ec9a211`
and `bts-native-task-primitives/fee7511a-9c6e-4cab-a917-20cbf63e94b6`, under
`artifacts/runs/`. Their 355 and 215 original raw artifact hashes respectively
passed independent checks. Final reverse-swap and S4 generations are fenced
with successful operations preserved. Their separate fence sidecars retain
read-only database confirmation; the reference sidecar explicitly distinguishes
the original inspected-but-unretained fence response from its retained
idempotent confirmation. Original probe files were not rewritten.

The new offline inventory verifier checks contained paths, symlink boundaries,
raw hashes, exact supported capture profiles, source/manifest identity and
cross-capture compatibility. Five Docker integration tests exercised actual
captures plus tampered temporary copies. An older native capture with a
different application digest does not count toward compatible task coverage.
The owner Docker TypeScript build passed after the final narrowing fix.

The four compatible bundles were then verified together at
`artifacts/runs/bts-verified-reference-inventory/3da42455-a824-483f-8082-ae0ce442f267/`.
Its `inventory.json` SHA-256 is
`e7b74c942160f484cd73b740f84f0f817241c0e95677b7bfdb2adbcfd07da9be`.
It verifies 890 in-capture artifacts plus the two external pinned U1 planning
files and records primitive reference coverage for all twelve task IDs.
All activation, grade, difficulty-approval and task-acceptance claims remain
false. One earlier inventory attempt detected a concurrent verifier source edit
and aborted without emitting a verified inventory; the retained successful run
has matching before/after verifier hashes.

Reproduce the offline check in the owner Docker runtime with its installed
tsx loader and command
`node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/verify-task-reference-inventory.mjs artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249.json`.
The index pins each probe hash; output goes to a fresh capture directory.
The subsequent isolated owner PostgreSQL regression passed 95 checks with
stable sources and exit 0 at
`artifacts/runs/launch-boundary/a14241a6-6bc5-4934-81f3-b25a31f78cc8/`.
Its capture SHA-256 is
`dc2e23904d56a5fbb6f5fff75673bb58e22c42d8953b0ee8fc91f78125e72698`.
Its release/authentication/observer fixtures remain explicitly synthetic.
The release/issuance/evaluator/feedback/retained-observer Docker contract suite
also passed 40/40 after the read-only-state correction. This includes the
original retained S1 primitive and its tamper/binding/path-escape variants;
the rubric observations remain synthetic where explicitly declared.

Separate open-training paths subsequently completed at
`artifacts/runs/bts-open-training-reference-profile/10fff3fa-2aa4-474b-a084-240e31e2b879/`.
All 512 artifact hashes were independently verified. `probe.json` SHA-256 is
`7bc0c7fc24d4e09eecd0da35768355d12c838e67f9d11e2d5399ea4d61a6a1e8`.
Each of the eight tasks uses a distinct generation, persisted fenced with its
signer erased. The API/manifest pins match the ranked reference inventory;
the separately pinned probe version adds the training drivers.
Training changes actual exercise parameters: S1 transfer 200000; S2 market
brief at 125000; S4 initial allowance 20000; M1 canonical resource at 100000;
M3/M4 swap input 200000; H2 payouts 200000/300000. Both training swaps use a
fresh exact-input public quote, independently verified by QuoterV2 at its
reported block: output 83225150113771 WETH base units. The 100000-unit quote
is not reused. Two focused quote checks and the Docker package check passed.
H1 retains two components and uses canonical 100000 plus extended 250000,
yielding 350000 service spend and a candidate ceiling of 700000. H1's wider
ceiling also permits the cheaper offer; there is no invented exact-offer or
minimum-spend grading condition. These are distinct reference exercises,
not yet twenty validated immutable release cases.
After the training-driver changes, the complete BEF package/PostgreSQL suite
passed 73/73 with zero skips at
`artifacts/runs/bef-package-postgres/5c76fad8-eefb-479b-ae48-f951bc36bdbc/`.
The inventory verifier now supports the exact training profile separately from
generic reference evidence. Its combined five-source capture is
`artifacts/runs/bts-verified-reference-inventory/62eccf62-d8d5-4597-9e0d-9fa4138a0f8e/`,
with inventory SHA-256
`d7d993a2d33b1c9f744971e0391da3aff9e865b9370e5180099109a38aa55e2d`.
All five sources match the application/manifest/source-block pins; the training
source retains its own probe digest. Persistent Docker integration tests passed
11/11, including changed generation identity, missing fence, wrong public quote
and false baseline mutations against retained raw evidence. No mutation counts
as a verified training primitive. Acceptance and activation claims remain false.

The explicit local case-assembly policy is now recorded in
`infrastructure/owner-identity/task-release-local-policy.json`: 60-second tasks,
480/720-second training/ranked limits, once-applied 2x expense headroom rounded
up to 10000 units, and a 0.01 ETH reserve for applicable simple/native/payout
tasks. U1 retains the reserve already fixed by its pre-execution plan.
Budgets are resolved once from reference evidence before release activation;
participant outcomes never recalibrate them. This selects a finite engineering
profile within the approved local implementation scope, without asserting
difficulty approval, production capacity or release activation.

The offline ranked case assembly at
`artifacts/runs/bts-task-case-candidates/182275ce-2c74-4bee-a0eb-96f6094f8196/candidate-cases.json`
has SHA-256 `16e8797bacb50c88f80483240a5109958e0de5187de925cce210d44e66c0ca18`.
It contains twelve schema-valid ranked candidates and 24 retained baseline/trace
envelopes. Their file hashes, canonical case hashes and state hashes were
independently checked; the assembly source snapshot remained unchanged.
The envelopes preserve the original HTTP/EVM/store boundaries and paid versus
read-only observations. Candidate budgets apply the local policy once; they do
not alter historical capture bytes. This is candidate assembly, not a validated
release, difficulty approval or a run-bound task grade. Reproduce in the owner
Docker tool runtime with
`node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/assemble-ranked-task-candidates.mjs`.

The first combined release validation exposed address-valued asset references
that individual TaskCase schema checks did not reject. The assembler now
resolves typed asset references strictly through the pinned same-chain asset
inventory, preserving all raw capture bytes. Six focused assembler tests passed.
Regenerated ranked/training candidates are
`artifacts/runs/bts-task-case-candidates/af9aa307-efbd-4ee7-bc2b-dceadc8747e1/`
and `artifacts/runs/bts-task-case-candidates/57910e7b-7cb9-4057-b14a-ea55ad3323a1/`.
The combined twenty-case candidate at
`artifacts/runs/bts-task-release-candidates/01a908d8-bebc-4d00-8d77-d2cdd0708927/candidate-release.json`
has SHA-256 `63532c2cfabdb8c6fe7e27177143866d5002e9b8eb6762bee9826631cba6a5ad`.
Its static manifest checks and retained feasibility verification pass; validation
then blocks at the unavailable independent reference-path verifier. Difficulty,
mandatory BDD gates, product execution and activation remain unproven. The
nonzero Docker command exit retains this blocked result. This candidate records
the pre-redesign baseline, not approval of its provisional difficulty.

The read-only feasibility witness at
`artifacts/runs/bts-release-feasibility-witness/9a306c79-614b-4027-9129-33f68ffa3a75/witness.json`
has SHA-256 `39c7340d7e438c6da232dcb39e6130ee56d4de0ae3507d533851f2844e148ded`.
All 29 indexed raw artifacts were independently hash-verified using their
workspace-relative paths. Both environments match the pinned block and chain,
eight contract code hashes and USDC implementation storage slot. A real
`bef_observer` transaction confirms all eight applied migration filenames and
checksums match the checked-out files. All 423 observed generations were fenced;
none was active at this observation. The collector used only read-only chain
methods, health/capability GETs and read-only SQL. This supplies independent
schema/identity facts; it does not approve difficulty or close the BTS gates.
Reproduce with the Docker-only helper
`infrastructure/owner-identity/capture-release-feasibility.mjs`.

The retained-feasibility verifier in
`packages/owner-identity/src/task-feasibility-evidence.ts` independently checks
the witness's 29 raw hashes, RPC methods/parameters/results, contract bytecode,
USDC implementation slot, observer privileges and applied migration checksums.
It derives the schema lineage and compares the complete asset/contract and
execution pins with the ranked candidate and pinned local policy. Seven Docker
tests passed, including rehashed wrong-chain, observer-write-privilege,
fabricated-migration, wrong-proxy and active-generation inputs. The exact
artifact inventory and read-only scope are required; a same-count replacement
cannot substitute an unrelated file. Files are read through bounded handles.
Passing this point-in-time feasibility check does not approve reference paths,
difficulty, current executor availability or release activation.
The source-stable offline verification at
`artifacts/runs/bts-retained-feasibility-verification/4af3fc99-917a-4002-b96b-2925781c29e1/verification.json`
has SHA-256 `866ec19a4f9be34dac099d212d184a4848d280d3078d164e9e4cf844b155ff26`.
It verifies execution identity
`8e56784cf3a35d2a8b8f763bff1339aceb4a57b93381b89a4a39ac0ffd63119b`.
Reproduce with the owner Docker tool runtime and
`node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/verify-release-feasibility.mjs`.

Difficulty remains a separate release gate. The ranked candidates declare
reference action counts S1/S2/S3/S4 = 1, M1/M2 = 1, M3/M4 = 3,
H1/H2 = 2, H3 = 3 and U1 = 8. The accepted provisional ranges in
[MVP discovery](mvp-discovery.md) are simple 1–2, medium 3–5, hard 6–9
and ultra 10+. These capture counters omit some public discovery/selection
steps and do not by themselves establish the complete reference action
granularity. Reconcile the actual necessary public actions before approving
the concrete cases. A mismatch requires review; adding meaningless calls or
silently changing goals, levels or weights cannot resolve it.
The owner subsequently chose «Доработать кейсы под прежние диапазоны».
The resulting [concrete redesign review](task-release-difficulty-redesign-review.md)
preserves the goals/weights and separates necessary participant actions from
mechanical HTTP and observer work. New captures and identities are required.

The active-delta BDD preflight now records the exact missing real adapter as
`blocked`, exits 2 before scenario execution, and retains unchanged source
digests. The retained BRL and BTS acceptance files respectively list all 25
and 34 scenarios as `not_run`; these reference captures do not promote them.
Nested import failures are still errors rather than misclassified prerequisites.

The actual owner-command x402 purchase bridge is now observed in
`artifacts/runs/bts-x402-task-action-executor-bridge/bd2804be-1f6f-4411-a435-c617838cd2c5/`.
It settled exactly 125000 synthetic USDC base units for the standard market
brief and retained the matching 850-byte delivery. Owner receipt and BEF
operation bind transaction
`0x6cf2d72a9675de48e8223beb7105385dac2aa803efc0531d5a4fe47042efff33`.
All four raw artifact hashes were independently checked. Reusing the payment
operation key for a different resource returned 409 without another delivery;
the generation was fenced. The summary SHA-256 is
`c511d7130ee9b738a5781cfe83f2023f300da4df0eb15506997965d851a5fc9b`.
This uses a synthetic isolated owner/run/release-source fixture, not an
activated product release or a graded task. The earlier failed pin check is
retained separately and had stopped before reset or payment. BEF pins the raw
manifest file hash; canonical JSON hashing is a different identity.

An independent read-only witness was then added without rewriting that summary:
`independent-observer-witness.json`, SHA-256
`2cd8f1c14807c4ffd5f26ff8f52ab7a268456c380bbf4c3f59053ab93bef6842`.
It confirms the public generation binding, owner receipt/outbox and BEF
payment/delivery rows. A direct local receipt records one 125000-unit USDC
transfer and facilitator gas of 552785053800 wei. The modeled facilitator gas
is 1322 micro-USDC, recorded separately from the participant's service charge.
The witness and its retained raw receipt file hashes were independently checked.

The coordinator now writes one `task.evaluated` event in the same transaction
as the immutable result. Its payload binds task, closure, release, input,
result and evaluator hashes. Concurrent evaluation emits it once; conflicting
evidence and read-only reconstruction do not republish it. The isolated
PostgreSQL capture `1c4c7cec-f4b1-4af5-98ed-01076ee710e7` passed 95 checks
with stable source inputs and process exit 0. Its `capture.json` SHA-256 is
`39eb5aa34c122b6599c14eb9848baf00f85d1c72b02c2131ac3cb68d2e5b376e`.
The release/observer inputs remain synthetic and full scenario acceptance is
false; no run completion or ranking handoff follows from this event alone.

The original selected swap, operation `3310915a-617e-4335-b460-696f500cc0b1`,
was subsequently reconciled through the authenticated admin observer endpoint.
Recovery retained transaction
`0xace3726134f80a8f9d346b6e7d970fdd6a91bdb2ac00fab7639e8891c4365521`
and all four original events, including the earlier unknown measurement. The
same transaction's receipt and effects now verify as successful. The observer
record pins the current application source separately from the original
execution source. Terminal replay returned the same hash without another
participant action or a pre-recovery reset.

The retained bundle is
`artifacts/runs/bef-selected-execution-reconciliation/3310915a-617e-4335-b460-696f500cc0b1/`.
All five listed file hashes were independently checked; `capture.json` has
SHA-256 `c5bb967a7c0f7bd9f9162b26a9643c30cb6c303611d830b90a77ae56660cfe04`.
The independent database read used `bef_observer` with
`transaction_read_only=on`. This establishes local recovery of the original
effect, not a full M3 task acceptance.

Fresh M3/M4/S4 reference captures completed in
`artifacts/runs/bts-native-task-primitives/2ca3cc87-8df5-4f64-862a-20e6987f0c2f/`.
All 215 raw artifact hashes were independently checked. M3 records approval,
USDC-to-WETH swap and explicit unwrap with a net native increase of
40530135731795 wei. M4 records the achieved swap followed by removal of its
residual router allowance. S4 records its declared fixture allowance setup
separately from the task's revocation; the final target allowance is zero.
All eight operations have successful receipts and retained measurements.
Each task uses its own generation; all three generations were fenced, with
the final S4 fence preserving operation/event counts and all transaction hashes.
These are same-tool local reference paths, without owner task closure/grade.

The complete BEF package suite then passed 66/66 checks, zero failures or skips,
in a dedicated retained PostgreSQL database. Capture:
`artifacts/runs/bef-package-postgres/8839c165-d5b1-4cb7-9894-b4578dbb17bb/`.
The `tests.log` SHA-256 is
`b6100b82bdc5c41dcacc23159cee04200e28f45091e23fd3af213f8090730efc`.
This includes the five previously skipped database checks and the migration
008 inventory correction. Reproduce inside the owner Docker tool runtime with
`node infrastructure/benchmark-environment/run-postgres-checks.mjs`.
The helper creates a new `bef_migration_test_<uuid>` database on the local owner
PostgreSQL service and retains it for inspection; tests never target either
runtime database and submit no fork action.

U1 allocation planning is now pinned before its execution, using a read-only
local public quote for exactly 1500000 USDC base units on the fee-3000 route.
The quote returns 624188625435803 WETH base units, with the declared 10% output
guard yielding 561769762892222. The local allocation plan fixes USDC at 40 bps
and native ETH at 9960 bps, each with one-bps tolerance, and verifies that the
initial portfolio does not satisfy that target. Planned paid services, two
payouts, gas ceilings and explicit unwrap are included in its projected bounds;
achieved balances do not choose the target afterwards.

The reproducible command inside the owner Docker tool runtime is
`node infrastructure/benchmark-environment/run-u1-planning.mjs`.
Its retained output is
`artifacts/runs/bts-u1-planning/00a9bf05-5661-4105-8def-dfe8795ab1fe/`.
Three synthetic arithmetic tests passed, covering exact boundaries, initially
solved rejection and infeasible plans. This is a local pre-execution objective
plan, not a completed U1 reference path or release feasibility approval.

The release validator also rejects a training/ranked exercise copied under a
different mode, case name, evidence path or array ordering. Distinctness now
compares goals and actual initial-state contents rather than `caseHash`, which
already changes when metadata changes. The synthetic fixtures deliberately
use different training funding. The release/issuance/evaluator/feedback/reader
contract suite passed 38/38; the isolated PostgreSQL regression passed 95 checks
with stable sources at
`artifacts/runs/launch-boundary/58f1a77b-35e2-42fa-bf5b-7349c62e6a96/`.
Its `capture.json` SHA-256 is
`533e6fd3d8d9450314b30c57627f2886120cdc97fc15e75c9b6256e93e9bfb0a`.

The newer BEF package/PostgreSQL regression passed 70/70 with zero skips in
`artifacts/runs/bef-package-postgres/239600d2-9f05-471a-bc34-541ca9e8ed17/`.
It includes receipt deduplication, aggregate gas rounding, sponsored-gas
exclusion and fee/payer snapshot tamper checks for H1/H2.

### Retained evaluation inputs and execution identity

The isolated PostgreSQL capture
`artifacts/runs/launch-boundary/2bf26e68-f00e-4cf0-ba9a-d7bd51e5ee63/`
passed 90 observations with stable before/after sources. Nine observations
exercise the immutable public task execution binding: concurrent creation,
restart replay, generation uniqueness across tasks, closed-deadline denial,
identity-change denial, SQL mutation denial and absence of secrets or ledger
effects. The binding retains public generation/manifest/application identities;
it does not restore a signing session after restart.

The later capture
`artifacts/runs/launch-boundary/d888fed0-8029-4ce9-b7c6-c909b7b60c06/`
passed 92 observations with stable sources; its `capture.json` SHA-256 is
`599a41d4d2886646d15d98dd0ec6cae8555d755774c4884f4e32f75795310a2e`.
It additionally verifies retention of the complete canonical evaluator input
and its original hash, without replacement by later observer responses. These
are actual service/PostgreSQL checks with synthetic release/observer inputs,
not real task completion or release acceptance. Legacy evaluation rows lacking
the original input remain explicitly unavailable; the migration invents none.

The next capture, `daa589d6-eefe-4b17-b3fa-d5e9d6f71c01`, passed 93
observations with stable sources and process exit 0. Its `capture.json` hash is
`45e0a0075283d6212389102b0c3cf39d3cac2d97c0a791778dce1162456fd4a5`.
The additional check reconstructs the original result directly from retained
input after the synthetic observer response changes. It requires no live
observer, executor call or result update. This audit path stays internal and
does not expose sealed inputs through owner/agent feedback.

### Continuation checkpoint: 2026-10-26

Backend build passed again after Docker was restored. The combined release,
issuance, evaluator, feedback and retained-artifact reader contract suite passed
37/37 without skips. Evaluator observations in this suite remain synthetic;
these are not twelve real task acceptances. OpenSpec strict validation passed
12/12 structurally; that does not establish runtime acceptance.

The actual reverse-swap capture completed at
`artifacts/runs/bts-reverse-swap-primitive/eadb7e07-0158-4ae4-80e5-ec66b7812709/`.
All 64 artifact hashes were independently checked with zero mismatches. The
100000-base-unit USDC input produced 41769296111030 WETH base units. Approval
plus swap gas was 950515633279 wei; their separately rounded modeled costs sum
to 2274 micro-USDC, excluding principal. This is a local executor primitive
capture, not a product run or BTS scenario acceptance.

The corrected PostgreSQL capture passed 42 observations at
`artifacts/runs/launch-boundary/c4b38779-6a16-454f-b3e4-3aa25f9fba57/`
with identical before/after source inputs. It includes 15 admission/queue/cancel,
20 atomic-start/issuance/credential-race observations and 7 registry observations.
The latter cover the durable activation ordinal and exact previous/current
identities, idempotent same-pointer replay after reconnect, and serialization
with admission. The HTTP/MCP issuance test uses an explicitly synthetic auth
resolver and release provider alongside actual transport and PostgreSQL; it
does not establish actual-client or complete scenario acceptance.

The later combined PostgreSQL capture at
`artifacts/runs/launch-boundary/5b5dcf2e-a1c2-4ba1-ac2c-d709cb6a7360/`
passed 72 observations (15 admission, 20 start/issuance, 7 registry, 14 immutable
evaluation/feedback and 16 action/cutoff). Before/after source hashes matched.
The new command transport checks use real HTTP sockets and registered MCP
handlers with synthetic authentication/observer ports, not an external client.

The newer PostgreSQL capture at
`artifacts/runs/launch-boundary/1e87dd42-82bd-422a-b0be-501dd960b39d/`
passed 76 observations (15 admission, 20 start/issuance, 7 registry, 14 immutable
evaluation/feedback and 20 action/cutoff). Before/after source hashes matched.
It adds scoped HTTP/MCP action status, hash-checked retained tool responses,
denial of new commands while an effect is unknown, and denial of reconciliation
that erases the original transaction identity. Both substitution and omission
leave the original unknown receipt/revision untouched. These observations use
synthetic trusted receipt/authentication ports with real PostgreSQL and transport;
the capture retains `fullScenarioAcceptance: false`.

The same 76 observations passed again at
`artifacts/runs/launch-boundary/f907f937-faf6-428e-8d61-808bab5d380c/`
after the original-transaction guard was also enforced by a PostgreSQL trigger.
The probe verifies that direct SQL attempts to clear or substitute that hash fail
without changing the receipt revision. Source hashes remained stable.

The expanded capture
`artifacts/runs/launch-boundary/4cf61985-def7-442b-aefa-db46ab162d1a/`
passed 81 observations, including 25 action/cutoff checks. It adds bounded
catalog/offer read commands, foreign-grant denial, retained raw evidence paths
in current receipts and immutable history, and unknown receipt enrichment from
no transaction hash to the original observed transaction. Identical receipt
retries do not add revisions. Source hashes matched; full scenario acceptance
remains false.

The browser regression run `6a469aa8-4631-4347-b497-f3f62437ec40` retained
OID 3 passed / 9 blocked, AAP 3 passed / 13 blocked and TBB 2 passed / 13 blocked,
with no failed scenarios. Its launch capture is
`artifacts/runs/launch-boundary/ccb68c43-4dff-45c1-884d-249c58fc074e/`;
before/after source hashes matched. Exit status 1 reflects the mandatory blocked
gates, not successful full acceptance.

Multi-resource x402 now has pinned catalog entries, content hashes and exact
resource/offer selection through settlement and delivery. The actual local-fork
capture at
`artifacts/runs/bts-resource-catalog-primitive/ab4980b4-59ea-4e92-9432-5433e1bc92ab/`
completed two distinct paid deliveries and rejected same-key cross-resource
replay with 409, preserving the original payment and delivery. All 56 raw hashes
were independently checked. The BEF build and 55 package tests passed; five
PostgreSQL-only checks were skipped when their database URL was absent. This
capture is a primitive, not BTS acceptance. The read-only S1 primitive reader
also cross-checks retained DB/RPC/calldata/log/state evidence but explicitly
produces no run-bound evaluator observations without an authoritative action
mapping. No genuine release was activated.

The later Docker BEF package regression passed 57 tests with zero failures;
five PostgreSQL-specific tests were skipped because their dedicated migration
database URL was not configured. It includes the legacy fee-500 idempotency
replay regression and pinned fee-3000 route selection. These package checks do
not replace an actual execution capture.

The fee-3000 local execution capture subsequently completed at
`artifacts/runs/bts-route-fee3000/3e5556b2-c41a-4617-9d95-09d8a55038af/`.
All 64 raw artifact hashes were independently verified. Transaction
`0x07aa033cb43c13aa2b89994480dcaa6d94b803e26e33d0eff2e5fc3c7b0a0c0c`
used the pinned fee-3000 pool
`0x6c561b446416e1a00e8e93e221854d6ea4171372`. The successful swap spent
100000 USDC base units and delivered 41612575059026 WETH base units. Swap gas
was 135081 at a total of 652231584288 wei; approval gas remains a separate
receipt and cost. Actual payer/recipient/pool deltas and zero final router
allowance agree with persisted measurements. This is an alternative-route
primitive capture, not a graded M/H/U task or a complete release.

There is no genuine activated twelve-task release. Actual open/ranked case
captures, same-public-tool reference paths, difficulty validation, all task
observer integrations and authoritative cutoff/action/evidence reconciliation
remain required. Executor capabilities now include scoped USDC transfer and
both directions of the pinned USDC/WETH swap, with explicit token approval and
unwrap, and pinned multi-resource paid delivery. Complete typed training/ranked
case bundles and the run-bound executor/observer integration remain missing;
later H/U reference-path progress is recorded in the continuation checkpoint above.
No completed/graded benchmark, external-client compatibility, ranking handoff,
mainnet operation or production capacity is claimed.

### Selected executor bridge

On 2026-10-26 the owner explicitly authorized implementing the x402 purchase
bridge and signed test payments only in the isolated local BEF/Anvil fork with
synthetic USDC and ephemeral test keys: «Да, разрешаю только локальный BEF fork».
This resolved the automatic approval review's rejection of the dispatch patch;
it does not authorize a mainnet payment. The bridge remains unavailable without
the pinned private-fork identity/policy and a matching RAM-only generation signer.

The fresh isolated owner-command to BEF transfer capture completed with
`outcome: observed` at
`artifacts/runs/bts-task-action-executor-bridge/a3a3c6aa-cc8b-4c52-a9d6-858971c97718/`.
The admitted owner action, retained tool measurement, BEF operation and owner
receipt refer to transaction
`0x80baa64b6e49c1a50cdb7e7248b40c7d3cca17f8e7ec6f1bb747a311ab19c3b4`.
USDC balances changed from 100000000 to 99900000 for the payer and 0 to 100000
for the recipient. The successful receipt reports gas 62159 and effective gas
price 5375195 wei with one transfer log. All three referenced artifact hashes
were independently checked. The ephemeral generation was fenced afterwards.
The owner/run/release provider fixture is explicitly synthetic and isolated;
no product release was activated and no task grade was posted.

The earlier unknown action in capture
`33313494-5f35-43ad-95ad-eb42c21ee7f5` was independently reconciled from its
original retained tool response and read-only owner/BEF database observations.
It now has an observed receipt at revision 2, retaining its original transaction.
`reconciliation-confirmation.json` has SHA-256
`df9d39d3ef4a8470ff87a9409298b516d14d40eae92b8e13bca2238912937b8c`.
The second reconciliation returned the same evidence/revision as an idempotent
replay. No participant command was resent. Failed pre-dispatch fixture attempts
remain retained separately; they are not positive bridge captures.

The read-only facade capture at
`artifacts/runs/bts-read-action-executor-bridge/4be08408-bad2-42a1-afb7-93df5cd1ec47/`
observed `inspect_catalog` then `inspect_offer` for the distinct market brief
resource. Both scoped owner receipts retain response hashes and evidence paths,
with no transaction hash. The BEF offer operation is accepted/not_submitted.
All four referenced raw evidence hashes were independently verified and the
generation was fenced. The synthetic owner fixture remains separate from a
full S2 task acceptance.

### Reference-path foundation

The retained reference bundle
`artifacts/runs/bts-reference-foundation/ea5e40c7-62e2-440d-b76f-0a6ab1039ccc/`
contains five observed primitive paths: transfer, read-only offer, exactly one
paid delivery, resource catalog purchases and reverse swap. All 233 referenced
artifact hashes were independently checked. Derived per-primitive records bind
the actual HTTP/RPC/database facts to their raw source references.
S2 checks the same block identity before/after the GET and at interval end, with
unchanged participant balances/allowances and zero payment/delivery/effect rows.
M1 records exactly one 125000-unit market-brief settlement and delivery; the
facilitator pays gas while the participant has no native gas debit. The M1
budget is still unresolved and all twelve release cases remain blocked.
Ten reference projection/validator tests passed in Docker. These observations
do not supply the missing complete case manifests or difficulty review.
