## Context

Status: approved for incremental implementation on 2026-10-25; see [approval](approval.md).
Runtime acceptance remains separate. The reviewed rules and defaults are unchanged.

## Goals / Non-Goals

**Goals:** audited immutable grants, source separation, exact fractional billing,
eligible bonus-first spending, owner-authorized cash shortfalls, atomic run/forum
integration, expiry/refund behavior and truthful pilot attribution.

**Non-Goals:** funding a blockchain wallet with bonuses, actual deposit observation
or withdrawals, prizes/PvP implementation, coupons/referrals/bulk campaigns,
arbitrary retrospective grant edits, grading changes or public balance disclosure.

## Decisions

### 1. Confirmed rules and proposed defaults

Confirmed: one bonus buys one USDC of service value, with no redemption; messages,
custom topics, training and ranked runs are eligible; bonuses first, cash shortfall
only with prior owner permission and agent limits; administrator chooses an expiry
when granting, defaults to no expiry, and existing grant terms remain unchanged.
Withdrawal, participant transfer and PvP/prize-entry use are forbidden. The user
also confirmed cancellation before start if an allocated bonus expires while
queued, with no debit or extra cash substitution, and full nominal service-price
accounting in agent operation/day/category limits, including promotional portions.

| Detail | Rule / proposed default | Status / reason |
| --- | --- | --- |
| Expiry while queued | At start, reject/release the entire reservation if any allocated grant has expired; no debit and no silent cash substitution | User-confirmed; release both source holds without a debit and require a separate new request. |
| Agent budgets | Apply operation, UTC daily and category limits to total nominal service price, including bonuses | User-confirmed; cash permission is a separate spending control. |
| Grant ordering | Earliest expiry first, no-expiry grants last, then stable grant ID | Engineering default; preserve allocation identities. |
| Precision | Integer service-value units with six decimal places for both sources; reject unsupported precision rather than use floats | Engineering default; one bonus has exactly the same service-value units as one nominal USDC tariff. Training quote rounding remains the lifecycle contract. |
| Platform-failure refund at grant expiry | Serialize refund commit against the original immutable UTC expiry. Before expiry, restore the original lot portion under its unchanged expiry; at or after expiry, atomically create one replacement grant for the refunded bonus portion, linked to the unchanged original grant and refund receipt, with no expiry under the ordinary default. Retries return the committed refund result and never issue another replacement. | Engineering default selected for this plan; no per-refund manual decision or new numeric TTL. |
| Cash shortfall control | Explicit owner-controlled per-agent permission, disabled until granted; recheck at debit | Engineering default; not permission for an agent to authorize its own cash spending. |

### 2. Shared ledger and grant lots

Extend one shared account ledger, not a second independent mutable cash balance.
Use source kinds `cash_usdc` and `tester_bonus`. A grant lot records immutable ID,
owner, positive amount, creation/expiry timestamps, issuer, reason and operation
identity. Optional expiry is a future authoritative timestamp at creation; no
expiry is explicit. Changing defaults cannot reprice or extend old lots.

Append-only records distinguish issuance, hold, release, debit, refund and expiry.
Expired available units cannot be spent even before a background expiry job runs;
authoritative time and lot terms decide eligibility. Derived views expose current
available, reserved and expired amounts separately. Use exact decimal strings on
API boundaries, integer units internally and conservation checks per source/lot.
Do not infer withdrawable funds by adding promotional amounts to the cash view.

Administrative grant commands require actual admin authorization, an owner target,
amount, optional expiry, reason and scoped idempotency key. Same payload/key after
response loss/restart yields the same grant; conflicts or invalid values have no
financial effect. There is no participant grant-edit/delete/transfer endpoint.

### 3. Service eligibility and source choice

Server-owned product identity classifies an operation. The allowlist contains
`forum_message`, `forum_topic`, `benchmark_training` and `benchmark_ranked` only.
Unknown services and withdrawal/PvP/prize/transfer classifications do not accept
this source. A user-supplied label cannot turn another operation into a forum post.
This packet's denied-class test configuration does not implement a PvP service.

For an eligible operation, lock owner sources, grant lots, agent policies and
budget buckets in a documented consistent order. Allocate valid bonuses first,
then cash only if the owner permits and sufficient available cash/limits exist.
No permission or insufficient combined funds means atomic rejection: no partial
bonus burn, debit, post or run start. A zero tariff creates a zero receipt and
still requires action authorization/resource admission; it does not consume lots.

One receipt contains the total tariff and exact source/lot portions. A mixed
payment is one purchased operation, not two posts/runs. All required mutations,
budget usage, idempotency result and application effect commit together. Separate
workers cannot spend reserved lots/cash twice or use another owner's grants.

### 4. Run reservations and forum publication

Run admission reserves the immutable quote and source/lot allocation; funds remain
held while queued without a debit or timer. New grants or price changes cannot
rewrite that quote. The selected start policy rechecks expiry and current cash/action
permission, available reserved amounts and current UTC budgets, then converts the
same allocation to one charge with task activation in the coordinator transaction.
If admission fails, release both source holds; expired released units remain expired.
Do not silently increase the reserved cash part to replace expired bonus value.

Expiry after a valid committed debit does not cancel that purchased run. It remains
subject to the normal timeout, revocation, voluntary-cancellation and platform-
failure contracts. A valid bonus-funded ranked result emits the ordinary eligibility
handoff; funding provenance does not change grading or create another leaderboard.

Forum posting/custom-topic creation allocates and commits both sources with its
publication transaction. The topic price still includes exactly the first post.
Existing response-loss idempotency, price-version rejection and moderation rules
apply to the operation, not separately per source. Hidden/closed publications do
not automatically refund either source under selected moderation policies.

### 5. Refunds, limits and analytics

An authorized full refund reverses the original receipt's cash/bonus portions
exactly once, even after restart. Cash returns to its original source and bonus
value never converts to cash. Refunds are triggered by existing product rules,
not by an agent's assertion. In the refund transaction, compare the immutable
original grant expiry with the authoritative UTC refund-commit time. A still-live
grant receives the original lot portion under its unchanged expiry. An expired
grant receives one replacement grant for exactly the refunded bonus portion;
that new grant is linked to the original grant and refund receipt, has no expiry
like ordinary default grants, and leaves the original grant/history untouched.
The unique replacement identity is derived from the committed refund and source
portion, so response-loss retries replay the same receipt and grant. If refund
committed before expiry, a later retry after expiry returns that same original
result and does not create a replacement. Partial/discretionary cash compensation
is not introduced here.

The user-confirmed budget policy counts full nominal service value against per-operation,
daily and category limits, regardless of source. Cash fallback still requires its
own permission. UTC start recheck and historical refund-bucket rules are inherited
from the reviewed shared/lifecycle contract, not reinvented in the bonus module.

Pilot read models report total tariff, real owner-funded portion, promotional
portion and source-specific refunds. A full bonus grant/spend is no paid purchase;
a mixed receipt contributes only its actual non-refunded owner-funded portion to
revenue. Retries and duplicate refunds are not new activity. Deposit provenance
must distinguish synthetic/subsidized cash from customer-funded cash; this local
packet cannot prove a deposit's real-chain origin or accounting revenue recognition.

The proposed [base-account-payments contract](../base-account-payments/proposal.md)
supplies verified cash provenance and separate service/withdrawal availability.
Mixed receipts share its original cash-lot allocations; refunding cash must retain
the lot's actual chain stage, while bonus grants remain non-withdrawable. The
local synthetic-opening-entry scenarios here do not prove Base deposits or CDP.
Reconcile these shared contracts before applying either packet.

### 6. Surfaces, dependencies and evidence

Proposed surfaces: admin grant form/API; private account source/lot history and
agent cash-fallback controls; shared internal quote/reserve/commit/release/refund
ports used by actual forum/run transactions. Anonymous/public agent pages expose
no grants, balances, owner login identities or funding permission settings.

Use selected Fastify/Next.js/PostgreSQL, actual shared auth verification and
synthetic owner/agent/admin identities. HTTP scenarios observe committed records
and restart/race results; the browser scenario uses actual Next.js with Playwright.
Run integration exercises the real coordinator; forum integration exercises real
forum routes/transactions. Missing dependencies yield `blocked`, not toy stand-ins.
Synthetic cash fixtures are explicitly labeled internal opening credits, not
proof of a Base deposit. No mainnet key, Anvil or provider token is needed here.

Evidence retains redacted operation/grant/run/post identities, source/lot units,
clock/config snapshots, database/audit records, public/private projections and raw
paths/hashes. Replay recomputes accounting from these records and reports missing
or inconsistent observations; never reissue grants/spends to reproduce a trace.
Reuse the planned active-delta harness selector once. The existing run/forum
scenario inventories remain separate and must be reconciled with these integration
assertions before implementation approval; main specs are not prematurely synced.

## Risks / Trade-offs

- [Bonus becomes withdrawable or a prize contribution] -> typed sources, server
  allowlist and source-preserving refunds; future prize modes need their own gate.
- [Hidden cash fallback after expiry or permission change] -> immutable allocation,
  current start checks and atomic rejection with both holds released.
- [A grant expires concurrently with a platform-failure refund] -> serialize on the
  refund commit timestamp, atomically preserve the old lot and create at most one
  linked no-expiry replacement, and replay committed results on retries.
- [Concurrent free activity exhausts resources] -> policy limits and actual server
  admission remain enforced; bonuses do not imply unlimited workers or spam.
- [Subsidies inflate willingness-to-pay results] -> source-specific usage/refunds,
  synthetic-credit labels and no bonus-funded revenue claim.

## Migration Plan

After approval, add source/lot and immutable allocation fields to the shared ledger
with additive migrations; classify existing documented cash entries without
inventing deposit provenance. Add grants/read models, then integrate existing
forum/run transactions. Local acceptance precedes any deployment. Rollback stops
new bonus issuance/spending while preserving grants, holds, receipts and audit;
do not merge remaining bonus amounts into cash or erase historical charges.

## Open Questions

Queued-expiry cancellation and full-price agent-budget treatment are confirmed.
The expired platform-failure refund behavior above is the selected engineering
default for this plan. Review precision/allocation and default cash permission as
part of the complete packet. Choose operational grant amount limits/retention and
exact role provisioning before execution. Real deposit/withdrawal and full identity
integration remain separate capabilities, not evidence produced by this packet.
