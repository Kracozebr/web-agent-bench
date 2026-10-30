## Why

The MVP's run, fee and recovery rules are now selected, but the repository only
has a reference benchmarking contract. A durable run coordinator needs a
reviewable contract before queue retries, reconnects and uncertain task effects
can influence charges or leaderboard eligibility.

Status: approved for incremental implementation on 2026-10-25, with the bounded
local Codex profile addendum dated 2026-10-28; see [approval](approval.md).
Runtime acceptance remains separate. The 2026-10-30 Training amendment below
changes the single current catalog's Training availability and quote inputs.

## What Changes

- Add private owner launch intents with no reservation until matching-agent
  acceptance, one atomic run binding, stale-price/version/cash-ceiling rejection,
  bounded expiry/cancellation and honest browser/selected-client handoff evidence.
- Use the separately approved local Codex CLI 0.165.0 / MCP 2025-06-18
  manual-bearer profile for actual local launch acceptance only; preserve the
  strict 2026-07-28 default and all existing admission authority and accounting.
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

Task-suite refinement, amended 2026-10-30: the single current catalog offers
Training only for S1/M1/H1, weights 1/2/3, full price 0.5 USDC and subset
denominator 6. The other nine tasks are ranked-only. Training eligibility is
independent of task exposure. Ranked remains twelve tasks for 1 USDC, score
weight sum 26. Closed post-ranked feedback remains score plus reason category
without exact case parameters/solution. The benchmark-task-suite packet owns
rubrics; this coordinator keeps admission/quote/clock/eligibility authority.

The owner's latest override removes the parallel catalog-version and legacy
migration requirements for this amendment: old local test runs/results may be
deleted by the separately assigned cleanup. Preserve accounts, agents, auth,
codes, ledger and reports. This packet performs no deletion. Fresh immutable
manifest hashes and validation proof remain required for the current catalog.
The generic immutable admitted-snapshot and retry rules remain for future runs;
this amendment requires no old-test compatibility or replay gate. UI selection,
quote and intent snapshots must agree on the current three-task selection and
exact quote. Bounded implementation, matching tests/BDD and fresh release proof
are human-approved; staged team review precedes apply. No additional real-user
fees, grants, model runs or credential operations are authorized beyond the
explicit budget. This revision itself edits planning only.
