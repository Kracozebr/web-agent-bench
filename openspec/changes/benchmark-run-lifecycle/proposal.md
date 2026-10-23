## Why

The MVP's run, fee and recovery rules are now selected, but the repository only
has a reference benchmarking contract. A durable run coordinator needs a
reviewable contract before queue retries, reconnects and uncertain task effects
can influence charges or leaderboard eligibility.

Status: **proposed, awaiting review and explicit implementation/BDD approval**.
Product discovery decisions do not constitute that approval.

## What Changes

- Add private owner launch intents with no reservation until matching-agent
  acceptance, one atomic run binding, stale-price/version/cash-ceiling rejection,
  bounded expiry/cancellation and honest browser/selected-client handoff evidence.
- Establish the shared first-public-action marker atomically with an eligible
  ranked terminal decision; other run states cannot publish a card.

- Add durable authenticated run admission with immutable agent/version,
  benchmark/task/policy and price snapshots, shared-owner balance reservation
  and UTC-day spending-budget attribution.
- Admit new training/ranked requests only for the active benchmark version;
  preserve already admitted queued/active requests across version activation,
  including authenticated same-request retries, without migration or repricing.
  New old-version requests must fail without a run/reservation.
- Define idempotent queue/start/cancel operations and one atomic transition
  publishing the first task and charging its reserved run price. Queue wait is
  outside execution timers; voluntary post-start cancellation is non-refundable.
- Bound pre-start queue waiting and expire a request that has not started by its
  deadline, releasing cash and bonus holds without a charge or automatic resubmit.
  Persist the deadline across retry/restart and serialize expiry with start; the
  duration remains unselected pending queue/load observations.
- Treat explicit owner revocation of agent access as cancellation of its queued
  and active runs: release pre-start reservations and retain started-run fees.
  Reject new agent actions at the committed revocation boundary;
  ordinary transport disconnection retains the existing reconnect policy.
- Coordinate sequential independent tasks, in-task retries without resets,
  per-task/overall deadlines and state-preserving reconnects.
- Allow only one active run per agent profile across ranked/training modes and
  declared versions; keep other admitted requests queued, uncharged and untimed.
  Different agent profiles may execute concurrently within shared budgets and capacity.
- Assign free execution capacity by alternating eligible owners, then choosing
  each owner's oldest currently eligible request. Preserve running work and
  per-agent slots; make rotation/claim recovery durable without equating dispatch
  order to equal CPU time or imposing one active run per owner.
- Recover missing infrastructure evidence without repeating agent actions;
  exclude/refund unrecoverable infrastructure failures with durable deduplication.
- Expose training/ranked feedback and a versioned eligibility/result handoff;
  retain raw evidence references and hashes. Detailed grading and leaderboard
  persistence are separate capabilities.
- Keep MVP participant results to scores/error reasons and the selected training
  explanation, without a private tool-call-history viewer. Internal evidence
  remains part of evaluation/recovery; public replay is later scope.
- Close tasks on explicit scoped-agent finish or deadline through one action
  cutoff and evidence-based evaluation; duplicate closure cannot repeat effects
  or successor activation. Preserve the pinned benchmark version for downstream
  version-separated leaderboards even if a new version is published mid-run.
- Apply owner removal of training/ranked permission as confirmed cancellation of
  only that mode's submitted runs, preserving unrelated modes/agents and the
  existing pre-/post-start source-accounting rules.
- Disqualify the current started run on validated evidence of successful agent
  interference with service state or another run, excluding ranking without a
  refund or extra debit. Keep claims, blocked attempts and unknown observations
  distinct; retain original source/evidence identities.
- Record the user-confirmed rules: recheck current UTC-day caps/permissions at
  start without changing the quote, and exclude proven platform recovery time
  from execution clocks while ordinary agent disconnection still consumes time.
- Propose remaining defaults for refund-bucket attribution, rounding, expiry and
  terminal transitions. These remain review items, not prior product approvals.
- Preserve the confirmed distinction between a forbidden request verifiably
  blocked before execution and a mandatory violation: continue after the former
  with separate safety evidence unless published rules forbid the attempt itself.
  Unknown execution is not a verified safe rejection. Task-specific rules remain
  outside the coordinator's grading scope.

Non-goals: real USDC deposit/withdrawal signing, production custody, Google/SIWE
implementation, a general agent host, complete task fixtures/evaluators, live
Base execution, PvP, forum, full UI or public replay. The scope includes the
coordinator's API/read model, shared database ledger/budget integration and
test-only external-boundary adapters; it does not select production wallet keys.

## Capabilities

### New Capabilities

- `benchmark-run-lifecycle`: durable run admission, queue/start/task/terminal
  transitions, timers, reconnect, fee accounting, recovery and feedback.

### Modified Capabilities

None. Preserve `benchmarking-core` and `realtime-pvp` main requirements unchanged.
The new capability consumes their identity/evidence principles and does not
reinterpret reference evidence as actual environment execution.

## Impact

Future changes affect the TypeScript API/coordinator, worker integration,
PostgreSQL run/event/ledger/budget records and Python pytest-bdd HTTP/environment
adapter. Exact named observations and mandatory gates are in `bdd-design.md`.
The existing mirror tooling currently targets synchronized main specs; active
delta support must be added after approval, preserving existing inventories.

This affects benchmark validity, internal accounting/settlement and externally
visible run results. It does not change PvP fairness or prove mainnet settlement.
Acceptance requires real API/PostgreSQL observations and a narrowly declared
local execution boundary for uncertain-effect recovery; an in-memory runner is
insufficient. No new tests, product code or main-spec edits are part of proposal
generation. Authoring this packet first does not change the proposed delivery
order: environment feasibility remains the first implementation slice.

Task-suite refinement: confirmed open training S1/S2/S4/M1/M3/M4/H1/H2 costs
0.5 USDC full or selected weight over 15; closed S3/M2/H3/U1 is ranked-only.
Ranked remains twelve tasks for 1 USDC, score weight sum 26. Closed post-ranked
feedback is score plus reason category without exact case parameters/solution.
The benchmark-task-suite packet owns the detailed real-evidence rubrics; this
coordinator keeps admission/quote/clock/eligibility authority. Earlier admitted
snapshots are preserved. These planning revisions remain pending for execution.
