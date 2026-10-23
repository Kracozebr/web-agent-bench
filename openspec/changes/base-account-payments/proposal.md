## Why

The MVP needs automatic USDC funding and owner-authorized withdrawals without
confusing safe service credit, finalized withdrawable funds, bonuses and uncertain
external sends. A durable payment contract must precede actual asset handling.

Status: proposed, awaiting complete scenario/scope approval. Individual discovery
choices do not approve implementation or live transactions.

## What Changes

- Provision one permanent platform-controlled EOA per owner through selected CDP
  API-key wallets, only expose initial funding after a withdrawal method is set up,
  and support wallet-button and ordinary/exchange-origin transfers.
- Observe the pinned USDC contract on Base, credit service use at verified `safe`
  state, and make remaining corresponding cash withdrawable only at `finalized`.
  Expose these availability views separately; elapsed time alone never confirms funds.
- Require a fresh account-linked wallet signature or Google-only passkey proof
  bound to each withdrawal; execute automatically to the confirmed Base destination
  without per-withdrawal administrator approval. Platform pays network gas.
- Enforce the user-selected initial 1-USDC withdrawal minimum, configurable by an
  administrator, with an exception for the entire positive withdrawable remainder
  below the threshold; no partial below-threshold exit or bonus/nonfinalized/held
  funding. Check eligibility with the exact confirmed amount when reserving cash.
- Persist source-linked cash allocations, holds, nonce/transaction identities,
  external submission and reconciliation across retries/restarts and sweep operations.
  Release submitted holds only for a finalized canonical revert proven in the
  original signer/nonce/transaction lineage under the configured provider/head
  evidence policy; a pre-submission cancellation requires proof that signed bytes
  could not have escaped. Ambiguous, replaced or dropped execution retains its hold.
- Support pre-enrolled backup confirmation and manual recovery review if all
  methods are lost; ordinary Google login cannot automatically reset withdrawal proof.
- Add real account/admin payment views, source-aware audit and declared local plus
  external CDP/Base Sepolia acceptance gates.

Confirmed incident policies: proven loss of a credited deposit's canonicality
pauses new cash spending and withdrawals for that owner until reconciliation;
pending manual method recovery pauses new withdrawals while leaving ordinary
services and bonuses available subject to their existing conditions. RPC outage
alone does not establish canonicality loss. Neither policy authorizes another payout.

Proposed defaults still for review: oldest-deposit-first cash allocation,
withdrawal terminal accounting and sign-only CDP with durable raw-transaction broadcasting.
The withdrawal minimum and full-remainder exception are confirmed. Other numeric
limits, challenge TTLs, liquidity/sweep thresholds and RPC supplier are open.

Non-goals: mainnet launch or live production testing, other chains/assets, bridges,
prize/PvP payouts, a dedicated internal owner-to-owner transfer API, bonus issuance redesign,
full identity/Google onboarding implementation or guarantees of biological humanity.

## Capabilities

### New Capabilities

- `base-account-payments`: owner funding addresses, evidence-based cash availability,
  owner-authorized withdrawals, signing/submission reconciliation, gas/sweeps and
  recovery/audit views.

### Modified Capabilities

None of the synchronized main capabilities. Preserve `benchmarking-core` and
`realtime-pvp`. Coordinate this shared cash contract with the proposed run, forum
and bonus capabilities; do not create another account ledger or sync them early.

## Impact

Future changes touch Fastify/Next.js, PostgreSQL shared cash/deposit/withdrawal
records, observer/payment workers, CDP signing and real RPC adapters, plus Python
pytest-bdd HTTP/browser/chain adapters. The declared test boundary includes local
Anvil execution with explicitly controlled finality and a separate mandatory
CDP/Base Sepolia integration gate. Local provider fixtures never prove live CDP
or Base finality; a testnet pass never proves mainnet custody or production readiness.

This changes real-account settlement/availability and service admission inputs,
not scoring or PvP fairness. Shared active-delta harness support and actual
auth/ledger/run/forum dependencies must be reused. No new product code, executable
test, provider account or wallet is created by proposal generation.
