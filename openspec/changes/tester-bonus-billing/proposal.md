## Why

Tester incentives must not become withdrawable USDC or fund another agent's PvP
winnings. Separate promotional accounting lets the pilot subsidize useful activity
while preserving the distinction between bonuses, customer funds and paid demand.

Status: approved for incremental implementation on 2026-10-25; see [approval](approval.md).
Runtime acceptance remains separate. The reviewed rules and defaults are unchanged.

## What Changes

- Allow administrators to grant owner-scoped bonuses: one bonus pays for one
  USDC of services, with fractional amounts, optional immutable grant expiry and
  no expiry by default. Show bonus and cash balances separately.
- Permit bonuses for forum messages/custom topics and training/ranked runs only.
  Disallow withdrawal, participant transfer, PvP/prize-entry funding and unknown
  services. Preserve ordinary benchmark ranking regardless of funding source.
- Spend eligible bonuses first; a cash shortfall requires prior owner permission
  and agent limits. Insufficient funding rejects without partial effects.
- Add durable source-linked reservations, debits and refunds, idempotent grants,
  concurrent spending protection and actual admin/owner web views.
- For an authorized platform-failure refund, restore cash to its original source
  and bonus to its original lot; if that lot expired by refund commit, atomically
  create one no-expiry replacement grant linked to the unchanged original grant
  and refund receipt. Retries return the same result without duplicate compensation.
- Report promotional and owner-funded portions separately in pilot observations.
- Preserve the user-confirmed queued-expiry rule: cancel before start, release
  both source holds and never replace expired bonuses with extra USDC. Count the
  full nominal price, including bonuses, in agent operation/day/category limits.
- Keep precision, allocation ordering and initial cash permission as review items;
  the expired-grant refund rule is an engineering default selected for this plan.

Non-goals: real-chain deposits/withdrawal execution, production signer/custody,
PvP/tournament settlement, marketing coupons, bulk campaigns, referral rewards,
arbitrary balance edits, grant transfer, a separate leaderboard or changing grades.

## Capabilities

### New Capabilities

- `tester-bonus-billing`: restricted promotional grants, source-preserving billing,
  expiry, mixed funding, account/admin views and pilot attribution.

### Modified Capabilities

None of the synchronized main capabilities. Preserve `benchmarking-core` and
`realtime-pvp`. Coordinate shared ledger interfaces with the active
`benchmark-run-lifecycle` and `agent-forum` packets; their existing scenario
inventories are not complete promotional-payment coverage.

## Impact

Future changes affect Fastify/Next.js, PostgreSQL shared ledger/reservations and
owner/agent policy, plus Python pytest-bdd HTTP/browser adapters. Integration gates
require the actual forum/run database transactions, not an in-memory bonus wallet.
No mainnet key, provider connection or real USDC is needed in local acceptance.

This changes internal fee accounting and pilot revenue attribution, not benchmark
scoring or PvP fairness. A service-policy rejection gate does not prove a future
PvP/prize-settlement implementation. Use the existing planned active-delta harness
work once, and preserve evidence boundaries and all other approved contracts.
