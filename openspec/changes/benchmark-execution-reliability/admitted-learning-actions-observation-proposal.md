# Observe every admitted learning action before grading

Status: **approved for implementation and BER-SC-009–012 assertions by the owner on 2026-11-02; physical acceptance remains incomplete**. See [recorded approval](approval.md).
This packet is a correctness repair within `benchmark-execution-reliability`, not an
authorization to change task goals or to restrict participant strategy. All gates below
remain `not_run`/blocked for the approved repair until their complete physical matrices pass. Existing reference qualifications do not prove it.

## Confirmed failure and evidence boundary

On 2026-11-02 a real Codex used the current native OAuth connection and accepted Training
intent `38d4a301-8925-4441-a124-0e5811336bd2` as run
`9192245e-76b5-49aa-9986-2fac63e6df81`. Its S1 actions were independently retained as
`inspect_catalog`, `inspect_offer`, then `pay`, each with an observed revision and evidence
reference. The S1 collector rejected the third action's kind before its effect could be
independently evaluated. This was not proof that the payment itself was wrong, missing,
or entitled to zero credit.

The run eventually became `cancelled/coordinator_evaluation_unknown`; no task evaluations
were retained, and M1/H1 were not issued. The diagnostic helper did automatically deliver
canonical report `f3fc5064-f65f-4a59-b8bd-a4067dd23ec3` for case
`5da85e64-81c1-4ab8-8bb6-b2d8cde8f685`. The helper report and the native agent's separate
support report are different report kinds. Working diagnostics do not establish working
benchmark evaluation.

Immutable operator-private proofs, relative to the repository root:

| Proof | SHA-256 | What it establishes |
| --- | --- | --- |
| `.local/mcd-training-postrun-proof-3ef5015b-f7ca-4572-89dc-5ce29b974b7a.json` | `d499fc5b03cb4fbe69d66abda2aa83f14b7511e5c023d602c26039b0b887ebdb` | Read-only independent PostgreSQL run, admission, ledger, evaluation, case/report and contiguous batch state. SQL watermarks alone are not HTTP receipt acknowledgement. |
| `.local/mcd-training-lifecycle-proof-111045ea-35a5-4a37-9507-366805cd7304.json` | `d7a87d5f33c54d264c0a4793b734b9011d98da75ab4de72020cdb60b548d1380` | Retained exact-run coordinator progress: `blocked/observe/action_evidence_unavailable`. |
| `.local/mcd-s1-action-validator-proof-d28a8d9e-8231-40cc-b957-0b0d017c4ebc.json` | `7e875e7b03e79a6fd6313123caa5ad25a1a17f84683862031a62435eb1893e01` | Unchanged deployed collector validator accepts actual action prefixes 1 and 2, rejects prefix 3. The read-only reproduction exposes the existing function in RAM; it performs no chain action, evidence write, regrade or DB mutation. |

These are local evidence references, not public attachments or permission to publish raw
conditions, answers, native output, Ranked state or credentials. Preserve original failures.

## Existing normative contract and source mismatch

The active `benchmark-task-suite/specs/benchmark-task-suite/spec.md` is normative:

- **BTS-REQ-006 / BTS-SC-010**, lines 59–64: technically valid, supported learning mistakes
  inside task scope execute and retain their chosen effects; no goal-based rejection or repair.
- **BTS-REQ-007 / BTS-SC-011–012**, lines 66–75: S1 credit follows independently proven exact
  transfer/reserve predicates. Gas is separate from recipient principal. A command name is
  insufficient to assign either zero or one.
- **BTS-REQ-008 / BTS-SC-013–014**, lines 77–86: S2 actual payment, delivery or mutation
  requires known zero; absence of effects requires complete authoritative proof.
- **BTS-REQ-009 / BTS-SC-015–016**, lines 88–97: S3 paid/mutating effects require zero;
  selection predicates come from the pinned catalog, not caller assertions.
- **BTS-REQ-010 / BTS-SC-017–018**, starting line 99: S4 unrelated mutation/principal movement
  remains a violation even if later restored. Final-state equality cannot erase history.
- **BTS-REQ-003 / BTS-SC-006**: missing or contradictory evidence remains unknown. See also
  `docs/benchmark-protocol.md:13–26` for separate outcome, tool, cost, chain and evidence dimensions.

Source references below describe the reviewed baseline; implementation must pin its actual
source hashes rather than treating line numbers as an immutable release identifier:

| Source | Relevant boundary |
| --- | --- |
| `packages/owner-identity/src/task-action-service.ts:25–41,406–479` | Bounded common command schema and actual admission. No task-goal kind allowlist. |
| `packages/owner-identity/src/task-payment-references.ts:28,95` | Same-task observed reference resolution; release payment-protocol checks. Split-payment v2 rejects combined `purchase`, not learning mistakes based on task goals. |
| `packages/owner-identity/src/task-issuance.ts:23–28,242` | S1 conditions and release-level participant tool protocol. |
| `packages/owner-identity/src/bef-s1-observation-collector.ts:609–665` | Strict action identity/evidence checks, but kind filter at 624 accepts only transfer/catalog/offer. Actual admitted pay fails this filter. |
| `packages/owner-identity/src/bef-s2-observation-collector.ts:370–384` | Read-only kinds and objective-specific offer identity filter; an independently valid nonobjective read is rejected as unavailable. |
| `packages/owner-identity/src/bef-s3-observation-collector.ts:365–380` | Catalog-membership filter similarly conflates observed read validity with task objective membership. |
| `packages/owner-identity/src/bef-m1-observation-collector.ts:435` | Training M1 limits observation to catalog/offer/pay/retrieve despite the common admission surface. |
| `packages/owner-identity/src/bef-s4-observation-collector.ts:988–993` | S4 limits observation to approve/transfer/catalog/offer. |
| `packages/owner-identity/src/bef-chain-observation-collector.ts:417–423` | Noncomposite tasks reject admitted paid actions; H3/U1 use the wider external-action union. |
| `packages/owner-identity/src/bef-paid-data-observation-collector.ts:271,331,687–703` | Non-paid kinds are skipped while owner action count includes them; payment-only census can still produce observed coverage. |
| `packages/owner-identity/src/task-paid-data-capture-packet.ts:295–302` | Projection derives transfer/state-mutation/expense completeness from that coverage, initially with empty chain arrays. These four paid-only paths are not established as safe by the existing references. |
| `packages/owner-identity/src/task-training-observation-lifecycle.ts:364–382,468–470` | Collector dispatch and unavailable-observation propagation; no evaluation should be fabricated. |
| `packages/owner-identity/src/task-evaluator.ts:240,841,1472` | Existing known/unknown result structure and S1 predicates; preserve evaluator semantics. |

## Approved observation contract

Use a shared, strict run/task-bound action observation layer for every admitted kind, then
project verified facts into the existing task-specific evaluation. Do not fix this by simply
accepting more kinds in a validator, silently skipping unsupported rows, suppressing failures,
or marking coverage complete from row counts. Do not introduce a task-goal admission allowlist.

| Command family | Required independent observation, for every applicable task variant |
| --- | --- |
| `inspect_catalog`, `inspect_offer` | Exact request/response identity, actual scoped read evidence and verified absence of mutation. A nonobjective but valid scoped offer is still an observable read; it earns no objective membership by being read. |
| `pay` | Owner/action/BEF operation linkage, immutable offer/read reference and accepted terms; independent payment row, receipt, transaction/logs, balances and cost. A confirmed payment does not imply resource delivery. |
| `retrieve` | Same-task confirmed payment reference and delivery operation; exact returned resource identity, content hash/bytes/schema and independent delivery evidence. Retrieval failure cannot undo an already confirmed payment. |
| `approve`, `transfer`, `wrap`, `unwrap`, `swap` | Exact chosen parameters, operation and receipt linkage; independent actual state/log/balance/allowance changes and gas, including off-goal side effects and reverted attempts. No automatic route/amount/asset/recipient correction. |
| `purchase` | Under the current split-payment protocol, retain verified pre-execution protocol denial and no economic effect; do not enable it. If an actually supported pinned legacy protocol admits it, require full payment and delivery observation rather than assuming equivalence. |

Schema, identity, authorization, scope, immutable-reference, resource/billing limits and deadline
fences remain authoritative. No foreign environment, admin/setup, raw-signing or real-fund
authority is added. An admitted terminal rejection requires independent no-execution proof;
an ambiguous dispatch/receipt remains unknown until reconciliation, never a fresh payment retry.

For each closed cutoff, account for every admitted sequence exactly once, including rejected,
reverted and nonobjective actions. Preserve revision/history consistency, evidence hashes,
generation/release pins, independent read-only observer privileges, chain identity and receipt
integrity. A complete census must reconcile paid and chain effects together. Skipping chain
actions in a paid task or treating an empty query as absence must prevent a known grade.
Shared child observations may be reused by a composite only after exact binding/cutoff
agreement and deduplication; no duplicate gas, payment, delivery or action count.

## All fifteen variants are mandatory

| Mode / task | Current collector | Reviewed gap / required qualification scope |
| --- | --- | --- |
| Training S1; Ranked S1 | S1 | Hard kind gap: pay/retrieve and chain kinds beyond transfer; actual Training pay failure proven above. |
| Training M1 | M1 training | Hard coverage gap outside its paid/read command family. |
| Ranked S2 | S2 | Hard kind gap plus nonobjective valid scoped offer read. Observe paid/mutating violations for existing mandatory zero. |
| Ranked S3 | S3 | Hard kind gap plus valid noncatalog/objective offer read; prove scope validity independently. Paid/mutating effects remain mandatory zero. |
| Ranked S4 | S4 | Hard gap outside its chain/read observation surface. Preserve unrelated changes, even restored changes. |
| Ranked M3; Ranked M4; Ranked H2 | Chain | Hard noncomposite paid-action gap. Include payment/delivery and chain cost/history together. |
| Training H1; Ranked M1; Ranked M2; Ranked H1 | Paid data | Chain rows can be skipped while completeness is asserted. Require independent chain coverage, not a label or payment-only census. This is a confirmed source gap, not a demonstrated runtime exploit. |
| Ranked H3; Ranked U1 | Composite | Existing child union is broader; not a waiver or proof of passing. Require exact shared coverage, cross-child integrity and no double counting. |

This is nine variant paths with hard coverage gaps, four paid-only paths with completeness
risks, and two composite paths that must regress the same contract. No path is marked passed.
The matrix describes observation coverage, not a newly permitted strategy or a proposed goal change.

## Approved BDD boundary and assertions

Mapper for the approved existing BTS learning-effects boundary:
`admitted_learning_action_observation`; real adapter: participant MCP admission → actual
BEF execution → independent PostgreSQL/RPC observer → sealed evidence → unchanged evaluator →
coordinator → persisted task/run result. The following approved stable scenario IDs are installed
in the reliability change, tracing to BTS-SC-010 and the task-specific scenarios above.
These assertions were explicitly approved and are installed in the normative delta, semantic harness contract and executable mirrors. Their runtime gates remain non-passing until actual independent proof is complete.
All four are mandatory `environment` gates with native-agent acceptance additionally required
by the final Training/Ranked gate below; unit/integration coverage cannot substitute for them.

| Assertion group | Positive and adversarial variants | Durable effects / named observations |
| --- | --- | --- |
| BER-SC-009 Complete admitted-action census | Every current allowed family on each of 15 paths; objective and off-goal scoped reads; valid wrong recipient/amount/route/allowance; no-op and reverted actions. Protocol-disabled purchase, foreign/invalid references and late actions remain rejected. | Preserve exact admitted command hash, sequence, revision, cutoff and actual effects; `all_admitted_sequences_accounted`, `scope_denials_unchanged`, `no_automatic_repair`. |
| BER-SC-010 Known violation versus missing evidence | S1 exact/wrong/extra transfer and reserve cases; S2/S3 observed payment/delivery/mutation; S4 mutate-then-restore; paid-only task with unrelated chain action. Remove/alter a receipt, row, hash, generation, read proof or block observation; test contradictory and truncated census. | Unchanged task-specific known grades only with complete facts; `known_effects_reach_existing_rubric`, `missing_or_contradictory_stays_unknown`, no evaluation row with fabricated zero/success. |
| BER-SC-011 Separate payment and delivery | Confirmed pay with no retrieve, rejected/late retrieve, wrong scoped resource read, lost action response, repeated status/finish; chain gas alongside payments. | `payment_not_delivery`, immutable action/status evidence, separate principal/gas/service cost; one actual economic effect per idempotent action, no double count or replacement ambiguous payment. |
| BER-SC-012 Closure, recovery and handoff | Deadline at dispatch/receipt; restart after confirmation but before observation/seal/evaluation; duplicate reconciliation/finalize and composite child replay; unreconciled action at cutoff. | Stable closure/cutoff, append-only evidence, one evaluation/settlement per task; next task issued after known finalization, terminal state explicit, unknown retained if reconstruction fails. No admission, debit, aggregate or report duplication. |

Fixtures may deliberately choose learning mistakes through the same participant interface,
but may not seed authoritative success, receipts, outcomes or coverage. Observer access is
read-only. Source/evidence hashes and actual initial/final state establish the outcome; a
unit mock, reference adapter or replay alone cannot satisfy a chain/native gate.

## Approved implementation and required acceptance

1. Reconcile this packet into the active design/spec/tasks and existing BDD mirrors, mapper and
   semantic contract; enumerate the concrete family/status combinations and independent proof
   required for all fifteen paths before product implementation.
2. Add strict shared observation/projection and meaningful regression checks; leave task goals,
   evaluator predicates, deadlines, prices, quotas, scores and safety fences unchanged. Preserve
   existing evidence validators and add equivalent independent checks for newly covered actions.
3. Run all fifteen fresh real sandbox qualifications with pinned source/release identity and raw
   evidence verification, plus the approved adversarial observation variants. Preserve failed
   campaigns. A happy-path reference run alone does not exercise learning mistakes.
4. Execute a fresh browser-created Training intent and a fresh browser-created 12-task Ranked
   intent using actual Codex through the current native OAuth connection. Inspect UI and
   independently query PostgreSQL for every task result, known/unknown grade, terminal status,
   charge/settlement and diagnostic report/receipt. No hidden solver, direct mutation of the
   business result or replacement native fixture may satisfy these gates.
5. Include an intentional controlled off-goal action campaign through real tools and a missing-
   evidence negative campaign, separately labelled from normal native benchmark performance.
   Check automatic error reporting without confusing a report acknowledgement with evaluation.
6. Release only after mandatory gates pass with a coherent immutable evidence closure. Keep
   historical run `9192245e-76b5-49aa-9986-2fac63e6df81` and its grades absent as recorded;
   do not regrade, repair, delete or retrospectively relabel it.

Per `docs/task-design.md:29–30`, “A new scenario or changed assertion requires renewed
approval.” The owner approved the strict all-fifteen admitted-action observation and negative
assertion scope above on 2026-11-02. That approval authorizes the stated implementation
and checks; it changes no task rubric. Until successful physical gates, the confirmed
runtime reliability blocker remains open even though automatic diagnostics worked.
