## Why

The lifecycle can complete twelve tasks and the leaderboard can aggregate supplied
credits, but neither defines how observed x402/EVM actions earn those credits.
The agreed closed subset also changes training admission and feedback. This packet
connects actual task evidence to reproducible grading before implementation.

Status: planning proposal, awaiting scenario/implementation approval; every new
gate is `not_run`. Product selections come from `docs/closed-benchmark-design.md`.

## What Changes

- Define a versioned twelve-task inventory, per-task parameter contracts,
  mandatory conditions, exact credit functions and evidence provenance.
- Admit training only for S1/S2/S4/M1/M3/M4/H1/H2; reserve closed S3/M2/H3/U1
  for ranked execution and embargo their conditions/solutions until retirement.
- Keep ranked weights 1/2/3/5, total 26, and price 1 USDC; full open training
  remains 0.5 USDC with subset denominator 15 and existing quote snapshots.
- Define task-local evidence collection, authoritative finish cutoffs, exact
  read-only answers, known failure versus unknown, and verified outcome handoff.
- Pin U1's nonempty unique component, allocation-asset, payout-obligation and
  temporary-spender sets in the release; reject invalid sets before task admission
  or charge and compute component/payout fractions from release-fixed denominators.
- Protect closed materials and compact post-ranked reasons without withholding
  required conditions or normal tool responses from the active scoped agent.
- **BREAKING relative to earlier unimplemented drafts:** training is not all
  twelve, and new training pricing does not use denominator 26. Existing admitted
  runs retain their pinned contracts; related pending packets are reconciled.

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
ledger quote selection, forum policy, private feedback and real acceptance adapters.
This affects benchmark validity and disclosure, not PvP fairness/settlement.
No product code, executable tests, real wallets, inference or chain broadcast is
authorized by this proposal. Numeric market-dependent fixture values and actual
contract identities must be pinned after feasibility, not guessed in this packet.

Non-goals: new task goals/weights, additional leaderboards, hosted agents, model
keys/token billing, human-noninterference guarantees, rotating ranked variants,
stress-injection suites, public replay, automatic leak detection or score sanctions.
