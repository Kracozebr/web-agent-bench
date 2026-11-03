# BER admitted learning-action replay implementation contract

This implements the owner-approved BER-SC-009–012 extension. It is not a physical capture or runtime acceptance. Existing eight scenario results remain historical; new four gates remain not_run until their actual independent boundaries pass.

## Current partial boundary: immutable identity census

The independently replayed partial document has schemaVersion `ber-admitted-learning-identity-capture/v1`, a nonempty exact sourceInputs before/after inventory, and `cells`. Cells enumerate exactly Training S1/M1/H1 plus all twelve Ranked tasks, crossed with the nine current scope-valid kinds inspect_catalog/inspect_offer/pay/retrieve/approve/transfer/wrap/unwrap/swap (135 unique cells). Each cell contains mode/taskId/kind, censusRef and ownerSnapshotRef. All references bind original bytes by path/SHA-256. Disabled current-protocol purchase is a rejection control, never a tenth admitted kind.

`ownerSnapshotRef` is actual read-only PostgreSQL output `{source:postgresql_observer,observer:{role:oid_observer,readOnly:true,databaseName},mode,binding,taskIndex,execution,closure,rows}`. The rows are the original snake_case action/receipt/history projections selected under one snapshot; receipt revision, status, evidence path/hash and transaction must agree with the retained history. Do not construct authoritative rows from a census, mutate snapshots or preseed outcomes.

`censusRef` is the actual `bts-admitted-action-census/v1`, classification `identity_and_evidence_census_not_effect_proof`, with binding/taskIndex/execution/closure and entries. Replay independently validates each original sequence through cutoff, normalized schema-bounded chosen command hash, immutable action file bytes, receipt/history and generation/source identity. It does not call the application census validator. The current Python reader derives no economic facts from census counts or copied proof entries.

Even a complete 135-cell identity capture remains blocked: its schema deliberately cannot qualify complete paid/chain effect coverage, unchanged-rubric grades, fault recovery or native acceptance. Producer `passed` flags are ignored. Pure reader fixtures test integrity only; synthetic observed rows are never physical action/receipt/effect evidence.

## Required actual full boundary before acceptance

The full producer must separately preserve real family proofs: owner census plus read-only BEF operations/payment/delivery/cost rows, original HTTP response/evidence bytes, independently retrieved transaction/receipt/log/block and state snapshots, then original sealed projection/evaluator rows. Every current sequence must reconcile exactly once across paid and chain families; skipped chain rows in paid-only tasks are not complete coverage. Scope-valid wrong actions must retain chosen parameters and reach existing rubric predicates; missing/contradictory facts remain unknown.

BER-SC-009 additionally requires all approved scoped-read, wrong-action, no-op/revert and unchanged denial variants. BER-SC-010 requires known violations and evidence-removal/corruption matrices. BER-SC-011 requires confirmed payment without inferred delivery, actual same-operation loss/retry and separately reconciled principal/gas/service cost. BER-SC-012 requires actual deadline/restart/seal/evaluate/finalize/composite/handoff proof and durable once-only identities. Wire DTOs for these independent family/evaluator/fault proofs must be reconciled with their actual producer before implementing a positive full-gate reader; neither the identity-only schema nor a local reference adapter may substitute.

Fresh physical fifteen-case qualifications, controlled learning-mistake/missing-proof campaigns and real Codex Training/Ranked from browser-created intents through current OAuth are distinct mandatory acceptance evidence. Preserve failed historical runs and proofs. No independent replay dispatches actions, rewrites grades, creates refunds, resets authorization or changes benchmark rules.

### Original-hash read recovery within BER-SC-009–012

A bounded postmine observation retry is a read of the same already-bound original
transaction, not another economic attempt. Retain the original owner action and
operation, BEF operation, generation, command/intent hash, transaction hash,
prestate block and quote throughout. Actual transport/visibility failure may
trigger the bounded read; a mismatched hash, transaction intent, generation,
receipt/block/prestate binding, semantic measurement or effects cannot be retried
into agreement. An EVM revert remains the actual reverted result.

Proof must correlate the retry/status reads to those original identities and
retain receipt revisions/history, actual RPC receipt/log/block/state and gas
evidence. Compare original admission, execution and ledger rows before/after:
there is no second sign/broadcast, owner admission, principal movement or charge.
Read/status polling consumes the original bounded observation/recovery authority;
it does not reset task/run deadlines, a trial budget or closure cutoff. A timeout
with insufficient remaining authority, an exhausted retry, or missing/conflicting
evidence stays unknown with the original hash and no fabricated evaluation.
Successful later read-only reconstruction is separate evidence and does not
rewrite a historical unknown receipt or regrade a cancelled run.

These are existing original-effect, unknown, cutoff and single-count obligations
of BER-REQ-009–012, not a new scenario or a relaxed positive matrix assertion.
Unit retry controls alone cannot establish the actual worker/MCP/database gate.


## Full producer design under unchanged deadlines (2026-11-03)

This is implementation design within the approved four matrices, not a claim that a
campaign has executed. The selected release currently exposes 60 seconds per task,
480 seconds per Training run and 720 seconds per Ranked run. With the current SDK
reference pacing of 2.1 seconds per MCP call, nine admissions plus one status each
and preflight/current/finish require at least 44.1 seconds; one extra status per
action already reaches 63 seconds before network/worker time. Keep task/run deadlines
unchanged and split controlled learning strategies into separate fresh intents.

The promoted controller defines three finite strategy IDs, each intended to execute once through full
Training S1/M1/H1 and once through immutable Ranked12 (six intents/45 task executions).
A missing task/kind remains non-passing; duplicate bootstrap kinds are preserved in
raw history but must not create duplicate matrix cells.

- Profile A (paid/read): actual catalog, candidate first offer, independent actual offer read,
  pay with its original read action ID, retrieve with its original pay action ID.
  Catalog resources have no root payment. Only the actual offer's root payment and
  first offer, resource hash/type and read-handle identity establish matching terms.
- Profile B (conversion): fixed small positive wrap of 2W, approve W WETH, swap W WETH to USDC
  on the published supported fee tier with minimum output 1, unwrap the remaining W.
  Recipient is derived from the actual successful wrap response's transaction.from.
  This uses newly wrapped stock, not hidden initial balances. The fixed W=10^12 wei,
  simple gas=100000 and swap gas=300000 fit the public technical caps; live funds,
  pool/output and deadline feasibility still require actual observation. No fallback
  amount, route or asset repair is permitted after an unsuccessful command.
- Profile C (transfer): the uniform fixed sequence is catalog, wrap 2W, approve W
  WETH, swap W WETH to USDC with minimum output 1 and the actual wrap transaction's
  sender as recipient, then transfer exactly 1 USDC base unit to the selected
  published offer's payTo. The controller verifies the original successful swap
  receipt and actual USDC increase of at least 1 before the transfer. This declared
  bootstrap runs for every task; it does not depend on hidden initial USDC stock.
  There is no conditional approve-zero balance probe, implicit funding, fallback
  route or repair after an unsuccessful command. Preserve every bootstrap effect.

Repeated wrap/approve/swap bootstrap kinds in profile C do not add matrix cells.
No-op approval remains a separate unrun adversarial control; these positive
profiles do not prove it. Zero wrap/unwrap is a technical pre-execution denial,
not a valid balance probe. The earlier conditional-stock transfer draft is
superseded by this uniform profile and is not the promoted controller's behavior.

These strategies require actual deadline telemetry before campaign activation.
Readiness of one S1 case does not establish worst-case timing for every task. The
controller must stop an ambiguous economic operation under its original identity,
query its status and retain unresolved proof; it cannot resubmit a new payment.
S2/S3 must finish with a shape allowed by their actual issued answerContract; an
explicit empty object is permitted by the current published optional-field schemas
and represents a deliberate missing answer, not a reference solution. Other tasks
retain the explicit no-answer contract. No hidden Ranked answer/state/route may be
read to construct a strategy.

### Required immutable full-proof DTO

A future full physical assembly must point to original bytes, not success flags:

- `sourceInputs:{before,after}`: exact current normative, owner/worker, BEF, strategy,
  reader and schema inventory; plus immutable qualification/validation/input refs.
- `campaigns[]`: fixed strategy ID and mode; actual browser intent action/request/
  response reference; scoped SDK/MCP transport transcript; actual worker runtime
  identity; selected task sequence and timings. Credentials stay in RAM.
- `tasks[]`: issued task/answer contract ref, original owner read-only SQL snapshot,
  actual root `bts-admitted-actions-observation-capture/v1` ref and sealed bundle/
  evaluation refs. Root fields are binding/taskIndex/execution/closure/closureAnswer,
  census entries and children.paid/chain evidence plus common RPC boundary. The
  census remains identity-only; independently verify the actual raw owner rows.
- Each child retains its real `bts-paid-family-observation-capture/v1` or
  `bts-chain-family-observation-capture/v1`, BEF repeatable-read role/session/census,
  immutable operations/payment/delivery/cost/selected-state rows, RPC blocks,
  transactions/receipts/logs and actual call response evidence. Capture RPC raw
  receipts and independently parse event identities/amounts, balances/allowances,
  gas and principal; transaction signatures/input material are excluded or hashed.
  Stable before/after census and binding alone cannot prove economic effects.
- `cells[]`: exactly 135 distinct mode/task/kind keys referencing original task,
  admission/receipt and family proof; observed/reverted/pre-execution-denied status
  remains explicit. A denied/no-funds attempt cannot masquerade as the required
  successful positive effect; approved no-op/revert negatives are separate.
- `negatives`: original per-variant request/effect/result captures for all approved
  009–012 adversarial controls. Rejected input retains no-effect/unchanged-finance
  proof; missing/corrupt/contradictory evidence retains unknown and absent fabricated
  evaluation. Recovery includes actual stop/restart boundaries, immutable cutoff,
  duplicate-call responses and durable once-only terminalization/settlement/handoff.
- Grading proof retains existing source/rubric/release pins, original sealed inputs,
  exact rational known/unknown result, evaluation/input hashes and independent UI/
  PostgreSQL consistency. Never supply an expected score to the execution endpoint.

The final positive Python replay path must independently derive these effects and
existing-rubric facts from the original raw references. The current identity-only
reader intentionally cannot qualify this full schema yet. Merely adding JSON
fields, copied projections or producer verified flags must not unblock it. Actual
native Codex Training/Ranked remains a separate required campaign, with its own
browser/UI/database proof and diagnostic receipt; SDK-reference runs are labelled
as such throughout.


### S4 conversion representation boundary

Retain actual conversion/native-value/state history for every task; never invent a
WETH burn Transfer event for an unwrap. Contextual S1/S4 successful wrapping may
expose the independently proven native principal transfer to the pinned WETH
contract when applying the existing wrong/extra-principal rubric; conversion-goal
tasks preserve their verified conversion representation, including M4 behavior.

For a future S4 case funded with pre-existing WETH, a successful unwrap without
independently proven outgoing-principal representation cannot be promoted to
S4 success. The implemented guard reports
`ADMITTED_ACTION_GOAL_EFFECT_UNREPRESENTED`/unknown; a reverted unwrap is not
blocked by that successful-effect guard. This is an explicit projection-completeness
boundary, not a new mandatory-zero rubric. Current qualification case-state proof
remains private and source-pinned; it does not qualify all possible future initial
states. No private Ranked variant amounts are disclosed here.


## Final assembly interface (acceptance implementation, 2026-11-03)

`ber-admitted-learning-full-capture/v1` is the full, offline assembly selector.
Its nonempty `sourceInputs.before` and `.after` maps must be equal and every byte
must still match the current repository. Original captures are immutable. An old
source cohort may remain historical evidence but cannot be repinned into this gate.
The legacy identity-only capture retains its always-blocked authority.

The selector contains references, never `passed`/`facts` assertions:

| Field | Actual producer and independent replay |
| --- | --- |
| `positiveReports` | Exactly six current A/B/C Training/Ranked reports. `ber_matrix_replay` reruns owner/current/history, paid and chain raw effects, direct supporting reads, sealed input/result and immutable evaluator linkage. Cell order is canonicalized as a set; all other report fields remain exact. The union is exactly 135 identities. |
| `controls.trainingD` / `controls.rankedD` | Finite D4 actual successful wrap, two approvals including a true no-op, then a mined revert. Four original IDs, raw receipt/log/gas and direct state facts are required on all fifteen variants. No positive cells. |
| `controls.compositeMixed` | Full Ranked; H3/U1 contain actual A4+B4 under one cutoff with five unique economic transactions. Other ten tasks remain A4. Raw payer-role gas is reconciled separately, never charged twice. |
| `controls.nonEoa` | Full Training with S1 deterministic contract-recipient no-broadcast rejection. The provisional marker is not authority: exact historical code/header, original request and both source events, null transaction and no finance/effects are independently replayed. |
| `controls.mcpGuards` | `--ber-mcp-guards-training`: actual disabled purchase, fabricated references, real prior-task references, original payment status replay, same-operation finish replay and postclosure denial. The latter is not deadline proof. Only original A4 may appear in each owner/family census. |
| `genericFaults` | Nine `{faultRef,actorRef}` selectors: paid_s1, chain_s1, composite_u1 crossed only with missing_child, corrupt_child, restart_blocked_seal. Exact unavailable-window bytes, fresh worker reason, no evaluation while bad, restored bytes, original closure/effects/finance and known normal commit are required. Chain/mixed recovery uses strict log-derived history, explicitly distinct from the direct-state support required by positive135. |
| `s4PreparationFaults` | Two `{faultRef,actorRef}` selectors for missing_fixture and corrupt_fixture. `ber_s4_preparation_replay` verifies original preparation/source, actual fresh unavailable observation and modifiedAt, no evaluation/successor while bad, identical restore, both mutation/restore entries, unchanged rubric/input/result and one fence/handoff. |
| `sourceNegatives` | Seven current generic-source observation faults: receipt_row_missing, receipt_hash_conflict, receipt_generation_conflict, read_missing, block_missing, census_contradictory, census_truncated. Original read results are retained; only a scoped acceptance read-return is changed. No authoritative DB deletion is claimed. Original owner command/history/closure/finance remain unchanged, actual worker unknown has no evaluation, and normal passthrough recovery must independently replay the original family raw proof. |
| `recovery` | Typed existing `h1CutoffRef`, `unknownRef`, `faultCoreRef`, `completedCallbacksRef`, `pendingTransitionRef`, `completionHandoffRef`. Existing raw readers retain deadline/cutoff, response loss, original unknown identities, restart, cancellation ordering and once-only callback/publication assertions. New universal packets need the actual generic dispatcher, not the legacy paid-only assumption. |
| `qualification` | `{validationRef}` for the selected immutable validation/candidate/minimum/semantic-reference cohort. Every qualified source byte and all fifteen raw reference variants must verify. This preserves the unchanged semantic baseline; it does not claim new owner/runtime acceptance. |
| `native` | Separate Training and Ranked `{nativeRef,diagnosticsRef,historyRef,uiRef,clientOutboxRef,receiptRef,connectionRef}` selectors. Actual native process/local-tool census, diagnostic case intent-to-run link, callIdHash+traceId+operationIdHash+admission actionId, raw durable history and actual browser launch/results are required. SDK reference captures never qualify this field. |

Missing components or named raw predicates remain `blocked`; a schema-complete
JSON document is not proof. Full runtime gates are not activated by this contract.

### Actual observation-completion witness

Each chain-support SQL snapshot retains `observationCompletedAt` read from the
same observer connection after target/action/commit/evaluation and cross-connection
waiter/coordinator reads, before COMMIT. The proof's witness equals the blocked
snapshot witness. Every witness must follow its actual target/waiter observations;
ordered snapshot completions and all RPC reads must fit the original grading,
overall and inherited statement bounds. A 1 ms later waiter is valid only when the
actual final DB witness follows it. Never synthesize max(target,waiter), introduce
a numeric tolerance, or substitute the earlier target clock. Historical captures
without this field remain incomplete under the current support schema.

### Native UI selector

`uiRef` points to actual browser observations with `source:actual_browser_observer`,
runId/mode/runUrl, screenshotRef, domSnapshotRef, renderedTasks and intentActionRef.
The bounded DOM projection contains observed runId/runStatus/taskRows; it is
compared with original persisted evaluator rows. The intent action records the
actual click and hash-bound before/after DOM selections/created intent ID, which
must equal the run's accepted intent and agent. A network GET body may be retained
when genuinely captured but is not mandatory. A toast or producer verified flag
cannot replace browser action plus durable identity. Credentials and unrelated DOM
or account data are not persisted.


Native tool-call IDs and MCP JSON-RPC IDs belong to different domains. Their
`callIdHash` values must not be equated. The actual server response's `traceId`
links a native call to the server SDK event; that event's original operation hash
then joins the same trace's admission action ID and the original owner action.
Retain both hashes separately. Never infer this chain from temporal proximity.

The S1 reserve assertion retains distinct evidence boundaries: current raw native
balance/principal/gas arithmetic and its sealed evaluator input; actual wrong/extra
principal results; the fresh fifteen-reference baseline; and the canonical
semantic test capture for R-1/R/R+1/missing balance. The last boundary executes
synthetic persisted observations against the existing evaluator, not a live
below-reserve owner task. Wrapping below reserve cannot be advertised as an
isolated reserve-caused zero when the earlier wrong/extra-principal rule fires.


The final native selectors also retain the already-emitted own readonly client
outbox and the actual own-helper HTTP receipt. Recompute original batch hashes,
contiguous sequence/watermark and uploaded client event bytes against SQL. A clean
complete capture with zero actual errors and no collection gap has an acknowledged
receipt with reportId null/reportCreated false and zero SQL reports. An actual
error or partial capture requires exactly one canonical report with the same
pointer. Never inject an error merely to obtain a report.

`connectionRef` retains only actual safe oid_agent_access_grant metadata columns
(id, owner_id, agent_id, source, role, resource, oauth_client_id, access_generation,
created_at, expires_at, revoked_at), readonly observer identity and database name.
Every original action grant/generation must match the diagnostic case connection,
source OAuth/agent role/current MCP audience and valid admission times. No token,
credential store or secret column is read for this proof.

The actual application route is `/runs`, optionally selected by agentId; it has no
`/runs/<runId>` route. Native UI replay uses the observed specific run ID and grades
from the bounded DOM snapshot against durable history. It must not demand an
unavailable run-ID URL or invent a network response body.


## Required negative-to-producer inventory

Every row is mandatory in the final applicable gate. This inventory describes
executable capture/replay paths; it is not a claim that the final physical cohort
has run. No denial Cartesian across all fifteen tasks is introduced.

| Scenario / named negative | Actual producer | Strict independent reader |
| --- | --- | --- |
| 009 all_fifteen_paths_all_nine_kinds | Six finite Training/Ranked A/B/C owner/MCP campaigns | matrix current-source raw replay plus exact135 union |
| 009 objective_and_off_goal_scoped_reads | Original A/C offer reads and immutable actual task objectives | goal replay joins verified census/offer data; no objective lookup drives actor actions |
| 009 wrong_recipient_amount_route_allowance | Original C S1 USDC effects, B/C permitted-route mismatches and S4 allowance history | goal/raw chain replay and persisted violation/input linkage; no rescore |
| 009 noop_and_reverted_actions | Training D + Ranked D | exact D4 pattern, successful Approval audit even for no-op, state-mutation absence, mined revert/log/gas proof |
| 009 protocol_disabled_purchase | MCP_GUARDS S1 | actual precise SDK denial plus original A4-only owner/BEF census |
| 009 foreign_or_invalid_reference | MCP_GUARDS S1 fabricated handles and M1 real S1 handles | exact actual arguments/codes, real preceding-task IDs, no admitted denied operation |
| 009 late_action_rejected | Existing H1 cutoff at/after deadline variants | ber_h1_replay; postclosure MCP_GUARDS is explicitly not its substitute |
| 010 s1_exact_wrong_extra_and_reserve | Fresh15 exact reference, actual A/B/C S1 effects/input arithmetic, actual canonical semantic TAP R-1/R/R+1/missing | qualification + goal/semantic replay; no isolated live below-reserve claim |
| 010 s2_s3_paid_delivery_mutation | Ranked A paid/delivery and Ranked B/C chain mutations | actual raw effect/state joins plus existing no_payment known-zero assertion for both tasks |
| 010 s4_mutate_then_restore | Fixed S4 three-approval history and both preparation-fault recoveries | S4 setup/participant partition, both unrelated history IDs, original mandatory rule and known result |
| 010 paid_only_unrelated_chain_action | All fifteen B/C paths, including paid-only task types | full independent chain/state/gas census reaches persisted unchanged evaluator |
| 010 missing_or_changed_receipt_row_hash_generation | Source7 receipt_row_missing/receipt_hash_conflict/receipt_generation_conflict | exact original/delivered registered source read preimages; fresh precise unknown/noeval, same-source recovery |
| 010 missing_read_or_block_observation | Source7 read_missing/block_missing | actual forwarded upstream historical read retained, only result null, exact target block/source, unknown then normal known |
| 010 contradictory_or_truncated_census | Source7 census_contradictory/census_truncated | exact count+1 or exact original_tx_hash_bound event removal, no other returned-data change |
| 011 confirmed_pay_without_retrieve | Three paid_s1 file/seal faults after original confirmed pay | generic paid source/payment/absence and unchanged S1 result; payment never supplies delivery |
| 011 rejected_or_late_retrieve | MCP_GUARDS invalid/foreign payment reference; existing PDC late retrieval is additional available coverage | actual rejection/no admitted retrieve; PDC reader is not required to substitute for the current guarded rejection |
| 011 wrong_scoped_resource_read | Actual objective/off-goal A/C reads, independently selected after the run | original issued scope, offer/census and unchanged goal-input linkage |
| 011 lost_action_response | Existing H1 admission/tool reply loss variants | raw transport loss plus original operation/action/status and no duplicate effect/charge |
| 011 repeated_status_and_finish | MCP_GUARDS each original payment status and exact same finish operation | original SQL receipt/evidence/transaction and one actual closure; replay flag alone insufficient |
| 011 chain_gas_with_payment | COMPOSITE_MIXED H3/U1 A4+B4 | separate payer roles, original transaction union and once-only participant cost projection |
| 012 deadline_at_dispatch_and_receipt | Existing eight H1 cutoff variants | original DB deadline, accepted sequence/cutoff, raw dispatch/receipt and no clock reset |
| 012 restart_after_confirmation_before_observe_seal_evaluate | Existing recovery core/H1/unknown races; generic paid/chain/composite restart; S4/source evidence recovery | typed actual restart/lock/unknown/known checkpoints and original bounded authority |
| 012 duplicate_reconcile_finalize | Completed-callback producer original seven probes plus two original recordTaskActionReceipt replays | original receipt bytes/revision/latest history and unchanged all before/after business fingerprints; completion alone is insufficient |
| 012 composite_child_replay | Three composite_u1 child-file/seal faults and MIXED actual root | both original children, same cutoff, restored bytes and verified mixed derived history; not strong-direct135 support |
| 012 unreconciled_action_at_cutoff | Existing pending H1 dispatch/receipt variants | actual outbox/receipt history and original cutoff; no fake missing action or fabricated grade |
| 012 known_handoff_next_task_and_explicit_terminal | Actual SDK known campaigns + separate actual native Training/Ranked | owner/BEF fences, one successor/handoff, original MCP terminal, actual native/UI/database linkage |
| 012 one_evaluation_and_settlement/no duplication | All current known campaigns, unknown races, duplicate receipt/finalize and pending/handoff interruption probes | original identities, append-only events and exact ledger/source deltas; no duplicate admission/debit/aggregate/report |

Unknown recovery with the universal collector may fail at `observe` before a
complete root exists. Its actual specific failure, original receipt-wire
intervention, confirmed source payments and rich readonly owner snapshot prove
the unknown boundary. Do not manufacture an incomplete generic root or pass the
legacy paid-only parser a new family. Known recovery dispatches the real generic
root/children against that original SQL context. Legacy captures retain their
original exact parser.
