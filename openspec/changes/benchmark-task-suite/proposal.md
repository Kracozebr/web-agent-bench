## Why

The lifecycle can complete twelve tasks and the leaderboard can aggregate supplied
credits, but neither defines how observed x402/EVM actions earn those credits.
The agreed closed subset also changes training admission and feedback. This packet
connects actual task evidence to reproducible grading before implementation.

Status: approved for incremental implementation on 2026-10-25, with the 2026-10-30
current-catalog amendment recorded in [approval](approval.md). Runtime acceptance
remains separate; no runtime gate is promoted by this planning update.

## What Changes

- Define one current twelve-task ranked inventory and per-task parameter
  contracts, mandatory conditions, exact credit functions and evidence provenance.
- Admit training only for S1/M1/H1; keep the other nine tasks training-closed and
  embargo their conditions/solutions until retirement. Ranked retains all twelve.
- Keep ranked weights 1/2/3/5, total 26, and price 1 USDC. Keep the full training
  bundle at 0.5 USDC and round selected training weight once over denominator 6.
  Use the single current catalog without a parallel legacy catalog contract.
- Define task-local evidence collection, authoritative finish cutoffs, exact
  read-only answers, known failure versus unknown, and verified outcome handoff.
- Pin U1's nonempty unique component, allocation-asset, payout-obligation and
  temporary-spender sets in the release; reject invalid sets before task admission
  or charge and compute component/payout fractions from release-fixed denominators.
- Protect closed materials and compact post-ranked reasons without withholding
  required conditions or normal tool responses from the active scoped agent.
- **Catalog exposure change:** the current training inventory is S1/M1/H1 only.
  Prior local test runs may be cleaned separately; this proposal does not delete
  database rows or files or overwrite historical validation artifacts. New
  current-catalog evidence uses new artifact paths and a new immutable release
  identity/hash. Retain the present schemaVersion string if it cleanly represents
  the single current inventory; no parallel catalog parser or admission contract
  is proposed.

## Capabilities

### New Capabilities

- `benchmark-task-suite`: the twelve task rubrics, fixture/manifest validation,
  actual evidence-backed grading, exposure and verified result integration.

### Modified Capabilities

None of the existing main capabilities is changed here. Related active proposals
`benchmark-run-lifecycle`, `agent-forum`,
`benchmark-leaderboard-and-agent-pages` and `benchmark-environment-feasibility`
are coordinated planning dependencies, not copied or prematurely synced main specs.

## Impact

Future task-catalog API, selected tools, evaluator, coordinator outcome schema,
ledger quote selection, forum policy, release-aware private feedback and real
acceptance adapters.
This affects benchmark validity and disclosure, not PvP fairness/settlement.
No product code, executable tests, real wallets, inference or chain broadcast is
authorized by this proposal. Numeric market-dependent fixture values and actual
contract identities must be pinned after feasibility, not guessed in this packet.

Non-goals: new task goals/weights, additional leaderboards, hosted agents, model
keys/token billing, human-noninterference guarantees, rotating ranked variants,
stress-injection suites, public replay, automatic leak detection or score sanctions.
