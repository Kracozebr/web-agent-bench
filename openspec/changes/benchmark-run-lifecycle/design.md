## Context

Status: proposed for review; no implementation/BDD approval recorded. The repository
contains a Python reference harness, not the selected TypeScript application.
The selected product rules are in `docs/mvp-discovery.md`; this change designs
one coordinator capability. It does not select concrete Base contracts or a
real-money signer. No integration or load result is asserted.

## Goals / Non-Goals

**Goals:** durable, idempotent run transitions; fixed admission prices; shared-owner
fund/agent-budget reservations; sequential task execution; explicit deadlines,
reconnect and evidence recovery; training/ranked feedback and an eligibility handoff.

**Non-Goals:** implementing all twelve task rubrics, the score/leaderboard service,
production login/link/recovery, native client-wallet evaluation, real USDC signing,
forum, PvP or full UI. The later cabinet consumes the coordinator read model.

### Confirmed task-suite integration

The benchmark-task-suite packet supplies immutable exposure/rubric and actual
outcomes. Admit open-only training S1/S2/S4/M1/M3/M4/H1/H2, full price 0.5 USDC,
subset denominator 15; reject mixed closed selections before reservation. Ranked
still has all twelve, price 1 USDC and score weight 26. Snapshot exposure and open
weight with the quote; preserve previously admitted versions. Closed S3/M2/H3/U1
feedback after termination is score plus allowlisted reason category with no
exact case parameters/answer. Scoped task issuance and normal tool errors remain
complete and immediate. Do not add a second grader or publish internal evidence.
Detailed credit fractions and actual gates remain pending review.

## Decisions

### 1. Accepted rules versus proposed engineering defaults

Accepted: ranked 1 USDC; full training 0.5 USDC; proportional training subsets;
prices configurable to zero and fixed at queue reservation; UTC calendar-day
caps; queue time excluded; one debit before first-task issuance; pre-start cancel
releases funds and post-start voluntary cancel does not refund; sequential tasks;
ordinary retry without reset; immutable zero for verified mandatory violations;
per-task/overall limits; ordinary agent reconnect does not pause time;
evidence-first recovery; unrecoverable platform failure excludes/refunds;
mode-specific feedback. The user additionally confirmed current UTC-day budget /
permission checks at start with the original quote and exclusion of proven
platform recovery time from task/run execution clocks. A failed start-admission
check releases the reservation without starting or charging the run.
Explicit owner revocation of agent access is also confirmed: block new actions,
cancel queued/preparing runs with reserve release, and cancel started runs without
a voluntary-cancellation refund. This differs from an ordinary transport loss.
The user also selected one active run per agent profile across training/ranked
modes; other requests wait in the queue. Different agents of one owner may run
concurrently within budgets and actual server capacity.

The table distinguishes confirmed product rules from remaining proposed defaults.
Confirmed rows do not constitute approval of the complete BDD/implementation packet.

| Item | Rule / proposed default | Rationale and remaining detail | Status |
| --- | --- | --- | --- |
| UTC day at start | Recheck current permissions and current-day caps at the original price; atomically move budget reservations to the start day or reject/release before start without a debit | Do not spend against the expired queue day's allowance; exact transaction mechanics remain design work. | User-confirmed rule |
| Owner revokes agent access | Block new actions and cancel the affected agent's nonterminal runs; pre-start releases funds, post-start retains the fee and excludes the incomplete result | Revocation is an explicit owner operation, not a disconnect, token expiry or token rotation. | User-confirmed rule |
| Refund after UTC rollover | Credit funds once and reverse the original debit's usage bucket; do not add spending allowance to the refund day's bucket | Preserves the actual charge-day history; exact policy must be approved with the shared ledger integration. | Proposed |
| Rounding training quote | Use integer token base units; round upward once for the complete selected-request price, never independently per task; configured zero stays zero | Avoid floating point and inconsistent summed rounding; token precision is pinned configuration. | Proposed |
| Proven platform recovery interval | Suspend new actions and exclude the recorded recovery interval from task/run execution clocks; ordinary agent disconnection still consumes time | Recovery wall-time bounds and proof/interval boundaries still need precise configuration/observations. | User-confirmed rule |
| Task and overall expiry | Reconcile admitted effects; finish a known task from verified observed outcomes and continue if overall time remains; unfinished overall-expired runs stay unranked | Do not invent zeros for unattempted/unknown tasks; confirmed agent-caused expiry alone does not refund an already started run. | Proposed details |
| Mandatory violation | A verified violation makes the task terminal at zero and permits the next independent task | Irreversible zero and continuation are confirmed; immediate task termination is the proposed detail. | Proposed termination detail |
| Terminal state | A late receipt appends evidence but cannot silently reopen or publish a refunded/cancelled run | Reopening needs a separate reviewed policy; immutable terminal decisions keep retries auditable. | Proposed detail |

No numeric timeout, reservation TTL, recovery window or server-wide concurrency
limit is selected here. They are required versioned configuration before execution;
acceptance uses declared synthetic test values and a controlled clock interface.

### 2. Real boundaries and proposed data model

Use the selected Fastify API, PostgreSQL transactions and a coordinator worker.
Python BDD calls real HTTP endpoints and observes committed database/evidence
records. Task-boundary scenarios additionally use an actual local Anvil fixture;
this is local-EVM evidence, not a Base fork/mainnet acceptance result.

Proposed records:

- `run`: owner/agent IDs, owner-declared version snapshot, mode, catalog/benchmark
  version, ordered task selection, policy hash, seed/environment identity,
  quote/precision/weight snapshots, status/reason, revision and clock timestamps.
- `run_task`: order, task/tool/fixture version, environment binding, active interval,
  deadline, outcome/credit/constraint flags, evidence state and references.
- `run_event`: per-run increasing sequence, event ID, authority timestamp, source,
  type, previous revision and canonical payload hash; append-only.
- `run_action`: scoped operation ID/payload hash, task binding, admission sequence,
  execution intent and external transaction identity if known, observation state.
- Shared `ledger_operation`, `reservation`, `agent_budget_bucket`, `idempotency`
  and `outbox`: use one database transaction with run transitions. Avoid a second
  parallel accounting implementation; these are the balance capability's ports.
- `evidence_manifest`: redacted raw paths and hashes, observed boundary, result
  bundle hash and reconciliation history. No user secrets or internal reasoning.

Run IDs and task-operation IDs identify business operations; HTTP connections
and queue-delivery IDs do not. Authoritative server sequence resolves races,
not client timestamps. An execution worker claim is not a completion observation.

### 3. State machine and atomic start

The user selected active-version-only new training and ranked admission. Serialize
the active catalog/version check with creation/reservation against activation;
record the observed activation identity/revision. An admission committed first
retains its pinned version, tasks, policy, environment and price through queueing,
preparation and completion. An activation committed first prevents new admission
to the superseded version without run/hold/debit. Do not silently switch requested
tasks to a newer catalog. Exact registry/lock implementation remains for review.

Authenticate and resolve an existing idempotency identity before treating a retry
as new-version admission: the same original request returns its admitted run even
after activation, while changed-payload conflicts and foreign access still reject.
A new key/run request cannot use history or old run IDs to bypass the active gate.
Starting/resuming an admitted old-version run uses its pinned catalog, not a new
active-version comparison; current access/budget/expiry/cancellation checks remain.
Version activation alone does not cancel, refund, reset timers or migrate the run.
Keep required old execution fixtures available until admitted work is terminal
and fenced; history alone does not require keeping old nodes running. This is
resource-draining design, not authorization for an automatic deletion job.

```text
queued -> preparing -> running -> completed
   |          |           |          |
   +----------+           |          +-- eligible handoff, only if ranked/verified
   |                      +-> cancelled_after_start
   +-> cancelled_before_start
   +-> rejected_before_start
                          +-> expired_incomplete
                          +-> disqualified_interference
                          +-> recovering -> running / terminal_unknown_refunded
```

Task state is `pending -> active -> evaluating -> completed | failed | unknown`.
Only one task accepts new actions. `unknown` blocks official result publication
and triggers the relevant reconciliation policy; it is not numeric zero.

Prepare the environment outside the start transaction. Under row/revision locks,
revalidate authorization/budget and the executor's prepared identity, commit the
single debit, first-task activation, deadlines and outbox/event record together.
Once committed, the first task is durably available even if the response is lost.
Before commit, cancellation releases the reservation; after commit, voluntary
cancellation retains the debit. Worker retries recover committed state, not a
second run or debit. A failed readiness check never starts a timer or debits.

The queue is not authoritative state. pg-boss delivers work; PostgreSQL run and
operation identities decide whether it has already been applied. Acquire owner,
agent-budget and run locks in a documented consistent order. A reservation reduces
available funds and relevant capped capacity; total shared-owner commitments must
not exceed funds. Zero-priced runs remain subject to authorization/resource limits.

Use one durable execution slot keyed by agent profile, shared across declared
versions, sessions and training/ranked modes. Claim it atomically before preparing
an environment; preparation, running/evaluation and evidence recovery retain it.
Further admitted requests retain their fixed-price reservations but stay queued
without a debit or execution timer. A busy slot is not a failed run.

Proposed handoff mechanics: release the slot only after the predecessor stops
accepting actions and its executor is quiescent or demonstrably fenced from future
effects; physical artifact cleanup may follow asynchronously. Process death or
lease timeout alone is not proof that an executor stopped. Restart/duplicate
workers recover the same slot identity. A delayed predecessor callback cannot
release a successor's slot. Recheck current permissions, price snapshot, budgets
and server capacity before the queued successor starts. The user selected owner
rotation with oldest-eligible-first ordering inside each owner; queue-size limits
remain configuration/design details. The user selected bounded
pre-start waiting and release without debit or automatic requeue on expiry;
the numerical waiting duration remains for queue/load validation.

Proposed scheduling mechanics: maintain one durable owner rotation and atomically
claim the owner's oldest currently eligible request with capacity/agent-slot and
turn identity. Give each eligible owner one allocation per turn before another
allocation for the same owner while other owners remain eligible. New eligible
owners join the rotation deterministically; empty or temporarily blocked owners
do not prevent available work. Within one owner, use authoritative admission order
with a stable request-ID tie rule; skip a busy-agent head request, preserving its
original order/deadline, when another agent's request is eligible. Expired/revoked
requests follow their existing terminal/release policy rather than gaining a turn.

Serialize concurrent scheduler workers on rotation/claim state and persist the
dispatch sequence/owner/request identity. Lost delivery or restart recovers that
same claim, not a new turn; opening more agent sessions or cards does not create
another owner identity. Scheduling assigns preparation/execution capacity; actual
first-task activation can occur in a different order when preparation differs.
Do not preempt working runs, promise equal CPU time, or cap an owner at one active
run. If only one owner has eligible work, it may use spare capacity across distinct
agents under the existing funds, per-agent and infrastructure bounds. This is
fairness between owner accounts, not a guarantee against multiple accounts per
human. Exact rotation data/locking details are engineering proposals for review.

Proposed mechanics: admission stores `queue_deadline` and waiting-policy identity
with the reservation; retries, worker delivery, preparation and later configuration
changes do not renew it. It covers queued/preparing time until atomic start and
is separate from task/run execution clocks and bonus-grant expiry. Use authoritative
server time after acquiring transition locks. Before starting, require the start
transition time strictly before the persisted deadline. At/after the deadline an
unstarted run expires even if the expiry job was delayed or the service restarted.
Time spent offline still consumes this proposed wall-clock waiting window.

Expire atomically with source-preserving release of cash/bonus/budget allocations,
no debit/refund pair, no first task and one durable reason/event. Do not extend an
already expired bonus grant or mint cash from its release. Fence preparation work
and retain safe cleanup identity; release an execution slot only after the old
executor is stopped/fenced. Late callbacks cannot start the expired request or
free a successor's slot. If valid start committed before the deadline, a later
queue-expiry delivery has no effect on the running run, charge or execution timers.
Existing cancellation, revocation, bonus-expiry and UTC-day checks retain their
own reasons and one terminal financial outcome. An identical request retry returns
the same expired status under existing access rules; any new attempt needs a new
request and current version/permissions/funds checks. Expose the deadline/reason
in the private run read model; no notification or automatic resubmit is selected.
These persistence/clock/cleanup details are proposed engineering mechanics;
the bounded-wait, hold-release and no-auto-resubmit policies are user-confirmed.

The single-slot contract is independent of the funding source. The user's new
tester-bonus requirement belongs to the shared balance capability: preserve a
separate non-withdrawable promotional ledger, source-linked reserves/charges/
refunds, and service eligibility. Forum messages, custom-topic creation, training
and ranked runs are selected uses; spend bonuses first and cover a shortfall with
USDC only with prior owner permission and within agent limits. Without permission,
insufficient bonuses reject without partial effects. One bonus buys one nominal
USDC of services; optional grant expiry is chosen at issuance, indefinite by
default, and existing terms remain unchanged. Proposed integration freezes the funding split at reservation and rechecks
USDC authority at start without silently increasing the reserved cash amount.
This packet does not yet claim complete bonus acceptance coverage. Reconcile its
accounting contract and scenarios with the
[tester-bonus-billing packet](../tester-bonus-billing/proposal.md) before
implementation approval. Queued-expiry cancellation without extra USDC and full
nominal-price agent limits and usable replacement for expired platform-failure
refunds are user-confirmed. TBB-REQ-006 now defines atomic source-linked replacement
and commit-time expiry with an indefinite replacement default; actual integration
and remaining engineering defaults still require packet review.

Real-cash admission additionally depends on the proposed
[base-account-payments contract](../base-account-payments/proposal.md): services
may use verified safe cash, withdrawals only unallocated finalized residuals.
Run holds/debits/refunds must preserve the same original cash lots, without a
second balance or synthetic promotion to finalized. The current lifecycle
inventory alone does not verify deposits/withdrawals; reconcile contracts before apply.

Owner revocation commits an authoritative agent-access fence and durable cancellation
intent. Start/action admission must observe the fence even before asynchronous
cancellation/cleanup delivery completes. Fan-out across the agent's nonterminal
runs uses stable operation identities and survives worker restart. Revocation/start
races follow the same committed ordering as ordinary cancellation; there is no
second release or debit. Already completed runs retain their historical results.
Reauthorizing access cannot reopen a cancelled run.

The user also confirmed scoped mode cancellation: when the owner removes training
or ranked permission, apply the same fence and pre-/post-start cancellation rules
to that mode only. Release queued/preparing holds and retain started charges
without a voluntary refund. Preserve unrelated modes, forum rights and other
agents. Re-enabling permission does not reopen cancelled requests. Cross-packet
policy/cancellation delivery must preserve the disabled mode and policy revision.

Cancellation stops new work; it cannot promise to undo an already admitted external
effect. Retain/reconcile its original evidence without resubmitting the operation
or awarding an incomplete run ranking eligibility. Existing platform-failure refund
decisions remain protected. Exact cross-capability revocation delivery/schema is
an identity/coordinator integration detail to review with the shared contract.

### 4. API / executor contracts proposed for implementation

#### Owner launch intent before admission

BRL-REQ-012 specifies a separate private `launch_intent` before any run or money
reservation. Persist owner/agent, mode/selection, active benchmark, displayed
tariff identity and exact quote/precision, maximum cash portion, fixed expiry,
idempotency identity, state and optional admitted run ID. Creation uses verified
admitted-owner authority and owner-scoped retries. Pending-intent per-owner/global
capacity and lifetime are explicit versioned configuration; never unbounded free
state or a new queue slot. Links/prompts carry a nonauthorizing reference only.
No model key, bearer token, withdrawal proof, case parameters or seed enters them.

After free preflight, the matching valid agent accepts over HTTP/MCP. In one
serialized transaction load current intent, permissions, version/tariff/quote,
funding and cash ceiling, derive the unique admission identity from intent ID,
and commit the ordinary run/reservation plus link. Any changed price, version,
selection, insufficient funds or increased cash need requires a new owner-reviewed
intent without effects. The cash ceiling is a bound, never cash permission;
actual cash also needs the separate current owner opt-in. Display current reserved
sources privately, distinguishing an earlier unreserved funding estimate.
Do not claim accepted/running before durable admission. Duplicate acceptance,
including changed caller idempotency keys, resolves one intent/run identity.
Authorized identical retries of an admitted intent recover its run despite later
intent expiry, tariff/version changes; they do not create a new old-version request.

Pending expiry/cancel and acceptance serialize using authoritative time after
locks. A winning expiry/cancel is free; admission first means later cancellation
must invoke the ordinary linked-run cancellation contract with its real fees.
Policy revocation and mode removal remain current fences. Ordinary autonomous
agent admission remains available without a browser intent. Private browser UI
distinguishes waiting, queued, preparing, running and terminal states and survives
reload/back navigation without another attempt. Proposed routes are owner
`POST /api/launch-intents`, private status/cancel and agent acceptance through
shared HTTP/MCP; bounded schemas/URLs are pinned during implementation.

BRL-SC-023/024 require actual owner/agent verification, HTTP/MCP and PostgreSQL
transaction observations. BRL-SC-025 also requires actual browser and at least one
pinned compatible external client for native repeat-path evidence; generic MCP
evidence alone cannot establish the one-to-two-action UX claim. Record all actual
setup/client approval/copy-paste steps separately, with fallback labelled honestly.
No platform-hosted model invocation or universal client handoff is introduced.

| Surface | Purpose |
| --- | --- |
| `POST /api/runs` | Authenticated agent admission; idempotency key, mode and selection; server builds immutable quote/catalog identity. |
| `GET /api/runs/{run_id}` | Scoped current state, quote, deadlines/next UTC reset, active task or released feedback; private owner/agent authorization. |
| `POST /api/runs/{run_id}/cancel` | Owner or appropriately scoped agent cancellation with idempotent result. |
| `POST /api/runs/{run_id}/tasks/{task_id}/actions` | Current-task scoped action submission; idempotent task operation identity. |
| `POST /api/runs/{run_id}/tasks/{task_id}/finish` | Submit completion for evaluator observation; not permission to self-award credit. |
| Executor prepare/execute/observe/evaluate/cleanup ports | Prepared environment identity, bounded action semantics, independent observations and versioned rubric outputs. Not public Anvil-admin access. |

MCP will wrap the same domain operations in its own capability. This packet's
tests do not establish Google login, MCP client compatibility or human presence.
Use real authentication verification with synthetic test identities/keys; no
trusted owner/agent-ID headers or fake authentication bypass in public routes.
Define request/result schemas, bounded sizes and stable error taxonomy during
the approved implementation; unknown task/action results remain explicit.

### 5. Timers, retries and evidence recovery

The user selected explicit task completion by the scoped agent, with automatic
closure/evaluation at a deadline. Reaching goal state alone does not finish the
task. Serialize finish, deadline and action admission through one durable cutoff;
observe previously admitted effects before evaluation and reject later/foreign
actions. Duplicate finish/restart returns the same closure identity, not another
execution or successor activation. The platform evaluator owns scores and retains
completion state plus violation history. BRL-SC-020 verifies that boundary with
actual local EVM evidence; it does not implement the twelve task rubrics.

Confirmed rejection semantics: a forbidden request verifiably rejected before
execution does not automatically zero the task; preserve its state and existing
limits, and record the unsafe attempt separately. A verified actual mandatory
violation still gives irreversible zero; a verified attempt also gives zero when
the published task criteria explicitly forbid the attempt itself. Preserve the
rule/rejection/effect references. Missing receipts or response loss cannot be
treated as proof of pre-execution rejection. BRL-SC-009 covers this coordinator
distinction; task-specific attempt prohibitions need their own rubric review.

The user selected a disclosed fixed educational ETH/USDC rate per benchmark
version for task-budget conversion. The evaluator manifest owns the numeric rate,
cost components and rounding; the coordinator preserves their version/evidence
references without substituting a live price or changing real service charges.
This packet does not implement that economic evaluator or claim its acceptance.

Persist activation time, per-task and overall deadlines, and any proven-platform
pause intervals; derive remaining execution time after process restart. Test clock
control is a local acceptance seam, not a participant-accessible endpoint. Reject
new actions at/after the authoritative action cutoff. For an admitted action
whose effect is pending at cutoff, reconcile/evaluate; do not call it absent merely
because its reply was delayed. Queue/preparation and bounded platform recovery
have separately observable intervals under the proposed clock policy.

Ordinary known operation errors allow a new operation identity/approach within
time/budget and existing state. Repeating the same identity returns its original
record; conflicting payloads fail. An uncertain economic action is observed by
its original intent/transaction identity, never blindly resubmitted. A later
correction cannot erase a verified mandatory violation.

Preserve original evidence and reconciliation additions. Proven infrastructure
recovery reads existing receipts/state. If evidence stays missing/conflicting
past the configured recovery window, commit `terminal_unknown_refunded`, one
refund linked to the original debit and an ineligible reason. Later observations
are retained without silently undoing that terminal/accounting decision. This
does not by itself attribute agent interference; apply the distinct validated-finding rule below.

### 6. Results, replay and acceptance limits

The user confirmed whole-run disqualification without refund for proven successful
interference with service state or another run. Introduce a distinct terminal
reason, not a synthetic zero official score. Preserve the original cash/bonus
charge, fence new actions, reconcile admitted effects and emit no ranked handoff.
An authoritative finding must identify run, actor/action, published rule, effect,
source and evidence paths/hashes. Validate source authority and bindings before
adjudication. A claim from an agent, missing evidence or rejected request alone
does not meet this threshold. Unknown integrity affecting validity follows the
existing observation/recovery rules; only proven platform blocking intervals
qualify for the selected clock exclusion.

Duplicate/restarted adjudication cannot refund, debit again or reopen a terminal
run. Late evidence is retained against the existing decision; it does not silently
reverse a committed platform refund or historical result. Other owners keep
their accounting and the existing recovery policy for any affected evidence.
Account-wide sanctions or historical-result investigations are separate scope.

BRL-SC-021/022 verify the coordinator's real HTTP/PostgreSQL adjudication boundary
using a declared controlled authoritative-observer evidence fixture with actual
source/binding/hash validation. The fixture is not proof that an agent exploited
the platform or that a detector attributes real attacks correctly. The environment
capability must separately specify and verify actual protected-state observation
and causal attribution before such findings can justify production disqualification.
No public test bypass, trusted client assertion or in-memory billing substitute
can satisfy this coordinator gate.

The evaluator supplies versioned per-task credit/violations and observed evidence;
the coordinator does not implement the twelve task-specific rubrics. Training
releases detailed feedback after each task. Ranked feedback exposes normal tool
responses immediately, then per-task/final scoring after run termination without
coaching or reference solutions. Sensitive fixtures are not returned as feedback.

The user chose scores and error reasons for the MVP result view rather than a
private chronological tool-call journal. Keep the ranked result projection compact
and do not add a participant call-history viewer/export to this scope. Immediate
tool responses and the selected post-task training explanation retain their
release rules. Internal action/evidence records still support evaluation,
reconciliation and audit; they do not establish a user-facing replay feature.

The user confirmed that goals, mandatory constraints, weights and partial-credit
criteria are published before participation. Exact ranked variant inputs are
revealed when the coordinator issues their task, not through advance catalog
access. Public criteria are not coaching or reference steps and do not release
the current run's scores early. The task/tool capability separately owns the
selected basic actions and platform test-wallet signing; offers, recipients,
amounts and sequencing remain agent decisions. Exact schemas and rubric evidence
need their own reviewed packet; these notes do not expand the 25 lifecycle
scenarios into complete tool, grading or public-catalog acceptance.

Only a complete, verified ranked terminal transaction atomically establishes the
shared profile publication marker (BLP-REQ-011) if absent and emits a stable
eligibility handoff with all
task/result/evidence inputs and immutable achieving-version metadata. The later
score/leaderboard service owns weighted scoring, shared ranks and best-run
selection; successful emission here does not prove public leaderboard correctness.

The user confirmed one overall leaderboard per benchmark version: the current
version is shown on the main board and older boards remain in history. Never mix
or silently rescore results across versions. Preserve each run's pinned benchmark
version on completion/handoff even after a release; best-run selection across
owner-declared agent versions occurs within that benchmark version. Public board
history and historical update projections remain downstream scope. New admission
uses the shared active registry; eligible late completions update only their
own historical board without copying immutable result inputs into the new version.

Replay reconstructs coordinator transitions/result inputs from the original
versioned event bundle and reports divergence. It does not repeat chain actions
or replace the original artifacts. Durable raw references/hashes survive restart;
missing artifacts are reported honestly, including after future retention cleanup.

## Risks / Trade-offs

- [Ledger integration dependency] -> coordinate one shared transaction/ledger
  model with the balance packet; test with real PostgreSQL, not a fake wallet.
- [Executor ambiguity] -> persistent intent and observation identities, actual
  Anvil recovery gate, and explicit unknown/refund paths.
- [Timer fairness depends on pause attribution] -> the new clock defaults need
  review; record wall time and platform intervals separately from execution time.
- [Broad first runtime slice] -> authoring this contract first does not make it
  the first deployment. Environment feasibility and minimal identity precede its
  end-to-end integration; no mainnet signing is pulled into this packet.
- [Existing harness only reads main specs] -> add explicit active-delta selection
  after approval and preserve all baseline scenarios. Do not silently sync first.

## Migration Plan

After approval, add additive run/event/integration schemas and transaction
constraints; build the scoped API/worker and real-boundary acceptance adapters.
Run on a clean local PostgreSQL/Anvil test deployment with synthetic identities
and test funds. Rollout flags keep real charges disabled until relevant balance,
identity and environment packets pass. On rollback, stop new admissions/workers
and preserve ledger/journal/evidence for reconciliation; do not delete commitments
or reset signed-operation history. Public deployment readiness is a later gate.

## Open Questions

Review the remaining proposed defaults in decision 1 before approving implementation. Numeric
pilot-calibrated limits, exact Base/task fixtures, production signer/auth and
task rubrics belong to their named packets. The local acceptance environment
must supply required explicit fixture values, not silently skip mandatory gates.
