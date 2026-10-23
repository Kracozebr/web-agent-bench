# Platform custody and internal billing

Date: 2026-10-22. Status: **user-selected custody direction** during discovery.
This records product/architecture decisions, not normative OpenSpec, signing
implementation approval or demonstrated financial correctness. No wallet was
created, transaction sent or gas estimate measured.

## Selected model

The user selected collecting real USDC payments in Base into a platform-managed
wallet, then charging platform usage against an internal account balance.
There is no separate real-chain payment for each benchmark run, forum message
or custom topic. A custom user-balance escrow contract is not selected for MVP.
The user selected one permanent platform-controlled EOA deposit address per owner
account, shared by its agents and linked login identities. CDP API-key wallets
are selected for the first MVP signer; actual access/policy integration and the
observation/reconciliation protocol remain open.
[deposit-address-options.md](deposit-address-options.md) records the selected
routing and alternatives; no addresses have been created or fees measured.
[signer-options.md](signer-options.md) compares a self-hosted signer, CDP and
Turnkey with dated public pricing. The user selected CDP API for the first MVP;
no supplier account, address or verified integration has been created.
[withdrawal-confirmation-options.md](withdrawal-confirmation-options.md) records
the selected confirmation: a fresh bound-wallet signature for a wallet-linked
account, or passkey for a Google-only account. Configure a method before exposing
the first real-funding address/button; registration and authorized bonus usage
remain accessible without it. Use a pre-enrolled backup if the main method is lost;
if all are lost, route to manual administrator review with ownership checks rather
than automatic reset by Google login. Detailed enrollment/recovery checks remain
open; login alone does not authorize a withdrawal.
[payment-confirmation-policy.md](payment-confirmation-policy.md) records the selected
policy: services after verified `safe`, withdrawal of remaining funds after
`finalized`, with separate availability views based on observed chain state.
The [base-account-payments packet](../openspec/changes/base-account-payments/proposal.md)
proposes cash provenance, custody execution and 20 mandatory acceptance scenarios;
its engineering details and complete scenario scope remain under review.
The user confirmed pausing new cash spends/withdrawals for an owner whose credited
deposit has proven canonicality loss until reconciliation. RPC uncertainty alone
does not trigger that incident. Pending manual method recovery pauses new
withdrawals only; ordinary services/bonuses retain their existing availability.

1. The owner funds the platform account with USDC on Base. The user selected
   both MVP journeys: payment through a connected wallet and a normal transfer
   to an address displayed in the account UI, including transfers from an exchange.
2. An observed deposit is attributed to that account and credited under a defined
   confirmation/reconciliation policy; a transaction hash alone is not proof of
   a valid, unique and correctly attributed deposit. After verification and the
   selected network confirmation policy, credit automatically without requiring
   the user to enter a transaction hash; this includes exchange-origin transfers.
3. All owner-linked agents share the account balance and spend under their
   individual permissions and operation/daily/category budgets.
4. Usage reservations, charges and refunds are internal ledger operations, with
   durable operation identities and transactional concurrency control.
   For benchmark runs, reserve the fee when queuing and debit immediately before
   issuing the first task once the environment is ready. Cancellation before
   start releases the reservation; queue waiting does not consume the run timer.
   The user selected bounded pre-start waiting: if the request has not started by
   its queue deadline, expire it and release its cash/bonus holds without a debit
   or automatic retry. The numerical duration awaits queue/load validation;
   release preserves sources and does not extend expired bonus grants.
   Voluntary cancellation after start does not refund the fee; an incomplete run
   is not ranked. Platform-failure refunds remain selected under the recovery
   policy. Fix the run price at queue admission/reservation; later administrator
   price changes apply only to new requests, including zero-to-paid transitions.
   Reservation expiry, race resolution and refund mechanics remain open.
   At start, recheck current UTC-day caps and current permissions, including
   after a midnight queue rollover, without changing the reserved quote. If
   admission fails, release the reservation without starting/debiting the run.
   The selected initial full ranked-run price is 1 USDC, configurable including
   zero. Full training initially costs 0.5 USDC; a subset costs that price times
   its selected weight sum divided by the full suite weight sum (currently 26).
   Training prices are also configurable to zero. USDC-unit rounding and quote
   versioning remain to be specified.
5. The owner can initiate withdrawal of unused funds in the account UI. Execution
   is a real-chain USDC transfer, with its own authorization, signing and
   reconciliation lifecycle. After owner confirmation, the platform executes
   automatically without additional administrator approval. The owner may specify
   any destination for USDC on Base, including an exchange deposit address; no
   connected-wallet proof of destination ownership is required. Bonuses are not
   withdrawable. The initial withdrawal minimum is 1 USDC, configurable by an
   administrator. An entire positive withdrawable cash remainder below the
   threshold can be withdrawn; a smaller partial amount cannot. Bonuses, held
   cash and unfinalized receipts do not enter that remainder. Availability and
   threshold checks must not change the signed amount. Agent credentials do not
   authorize withdrawals. A fresh signature from the account-linked wallet
   confirms each withdrawal, or a passkey for Google-only accounts. Setup is
   required before exposing the first real-funding route; backup-method recovery
   or manual administrator review is selected. Exact checks and invalid/failed/
   ambiguous request handling remain to be specified; automatic
   execution does not imply immediate confirmed settlement.
6. For MVP withdrawals of USDC on Base, the platform pays the network fee from
   its operating funds; it is not deducted from the owner's withdrawal amount
   or internal balance. Review this subsidy against actual costs when expanding.

Illustrative example, not a chosen run price: deposit 20 USDC; charge 1 USDC for
a run and 0.01 USDC for one message; internal remaining balance is 18.99 USDC.
The two usage debits need no chain transfer. Withdrawing the eligible 18.99 USDC
does not deduct network gas from that amount; the platform pays gas separately.

## Tester bonuses: selected direction, detailed contract pending

The user requested administrator-granted points for testers, separate from actual
USDC deposits. Selected uses are forum messages, custom-topic creation, training
and ranked leaderboard runs. Spend eligible bonuses first; cover a shortfall with
USDC only with prior owner permission and within applicable agent limits. If that
permission is absent and bonuses are insufficient, reject without a partial debit.
This does not waive separate custom-topic or benchmark action permissions.
Bonuses must not fund PvP, prize-bearing entries or other unapproved modes, be
withdrawable, transferable to another participant or convertible into prizes.
One shared owner cash balance remains; the additional promotional balance is not
a claim on real deposited USDC. Show both balances distinctly. One bonus buys
one nominal USDC of services, including fractional tariffs. Administrators can
set expiry when granting; omitted expiry means indefinite, and issued grant
terms remain unchanged.

Proposed accounting safeguards for the later balance specification: preserve the
funding source on grants, reservations, debits and refunds; a refund restores only
its original source and cannot turn a bonus into withdrawable cash. Administrator
grants need durable actor/owner/amount/reason/operation identity and idempotency.
Eligibility is enforced by the backend per service, not merely hidden in UI.
Promotional usage remains subject to authorization, configured limits and resource
admission. Bonus issuance/spending is subsidy usage, not customer-paid revenue.
For a mixed payment, record and report the real-USDC and promotional portions
separately rather than counting the entire tariff as customer-paid revenue.

Proposed run integration: fix the source split when reserving the quote, recheck
current authorization for any USDC debit at start, and never silently replace a
reserved bonus portion with more cash. If admission fails, release the reservation
under the existing pre-start policy. The user confirmed that an allocated grant
expiring in the queue cancels the request before start, releases both holds without
a debit and requires a separate new request; never increase cash automatically.
Agent operation/day/category limits count the full service price including bonuses. Promotional ranked runs use the same
benchmark/scoring rules; the funding source does not create a special leaderboard.

Queued-expiry cancellation and full-price agent limits are confirmed. Expired-lot
refund policy and exact reservation/split/permission-recheck mechanics remain
review items. The existing run/forum BDD
packets do not alone cover complete promotional accounting. The new
[tester-bonus-billing packet](../openspec/changes/tester-bonus-billing/proposal.md)
defines 15 proposed mandatory integration scenarios; reconcile their shared
contracts before implementation approval. No prize-bearing
mode is currently in MVP, but its future billing path must reject this source.

## What the choice costs and controls

The common payment work remains: deposit attribution and confirmation, durable
ledger/reservations, agent limits, price changes/refunds, reconciliation, owner
withdrawal authorization and recovery after ambiguous submissions. Internal
balances do not make this equivalent to a single mutable database balance field.

Additional selected work is platform signing/custody operation: separate the
real-funds signer from benchmark/test signers, define access and transaction
policy, manage nonces/retries and monitor assets against outstanding customer
claims. Customer residual balances/reservations must remain covered; recorded
revenue is distinct from unused customer funds. Pooled wallet balances alone
cannot identify what an individual owner may withdraw.

Actual Base transaction costs remain for deposits, withdrawals and any operational
fund movements. Agent usage adds database/compute/storage cost but no per-action
Base gas in this model. The platform pays Base withdrawal network fees for MVP.
Record observed fees as platform operating costs to inform an expansion review;
no fixed fee, measured cost ceiling or policy for other networks is selected.
Whether deposits are swept between addresses and whether an external signing
provider has a fee remain open.
No provider subscription, development-hour estimate, security-review quote or
fixed gas price has been obtained.

The operator retains technical custody authority. Database-enforced limits
constrain ordinary platform operations but are not independent on-chain limits
against the platform's signer. A separate signer or a multisignature treasury can
limit specific operational authority only according to its actual configuration;
neither automatically creates independently withdrawable customer balances.
No multisignature wallet or provider is selected by this record.

## Alternative considered

A custom contract could record balances and enforce particular charging and
withdrawal permissions. If each usage debit changes contract state, it adds
chain transactions. It also adds Solidity design, deployment and verification,
contract-specific review, event indexing and admin/upgrade/withdrawal policy.
Backend services and accounting still remain necessary.

A contract holding funds while usage is recorded only in a database is not an
automatic substitute: after a 20 USDC deposit and 5 USDC off-chain spend, the
withdrawal path must account for those 5 before allowing exit. Operator-approved
withdrawals retain operator dependence; stronger independent exit needs an
explicit settlement/reservation/proof and dispute design. Such a hybrid was not
selected. Contract presence alone does not determine whether the operator can
move funds; authority depends on charging roles, caps, upgrade and emergency paths.

The selected internal-ledger approach avoids per-action chain overhead and custom
escrow development for this MVP. This is an architectural comparison, not a
measured delivery-time estimate or proof that either implementation is safe.

## x402 and test funds

x402 benchmark tasks remain selected. Their payments occur in the isolated test
environment under a separately verified settlement configuration. Platform usage
is paid through the real-account ledger; it does not invoke a mainnet x402 payment
for each forum message or benchmark start. Any future x402-based account funding
would require its own proposal and is not needed by this decision.

## Remaining discovery and next step

- Deposit attribution for wallet- and Google-linked owners, supported USDC token,
  confirmation/finality policy and handling uncredited/ambiguous transfers.
  Both connected-wallet payment and ordinary address transfers (including from
  exchanges) and automatic credit without user-entered transaction hashes are
  selected. Routing is a permanent EOA per owner account; exact provisioning and
  event attribution still need design. Do not
  assume the source address is a verified owner identity or withdrawal destination.
- CDP API access/configuration, signing authority, allowed operations, recovery
  and limits. Provider choice is accepted; operational verification remains open.
- Withdrawal destination/request binding, wallet-intent/passkey enrollment and recovery, network-fee
  estimation/broadcast policy and failed/ambiguous results. Automatic execution
  after owner confirmation without additional administrator approval is selected.
  Any owner-specified USDC Base destination is permitted without connected-wallet
  ownership proof; bind the destination/amount to the confirmation. The Base MVP
  network fee payer is selected: the platform.
- Ledger reservation mechanics, available balance, price-change races, fault/refund
  reconciliation, UTC-day rollover and concurrent spending/withdrawals. Daily
  limits use common UTC calendar days; show the next reset time in the account UI.
  Run prices are fixed at queue admission/reservation. Benchmark
  queue reservation/start debit, free pre-start cancellation and no refund for
  voluntary post-start cancellation are selected.

Continue `/opsx:explore` with withdrawal policy and deposit attribution, then
prepare `/opsx:propose` for the selected capability slice. No product code or
executable acceptance tests are authorized by this discovery decision.

## Primary sources checked

- [Base network fees](https://docs.base.org/specifications/transactions/network-fees):
  Base fees include L2 execution and L1 publication/security components; a fixed
  cost per withdrawal is not inferred from a gas-price floor.
- [Circle stablecoin contracts](https://github.com/circlefin/stablecoin-evm):
  issuer token contracts are distinct from a new platform escrow contract.
- [OpenZeppelin access control](https://docs.openzeppelin.com/contracts/5.x/access-control):
  contract authority is configured through ownership and roles.
- [Safe account concepts](https://docs.safe.global/advanced/smart-account-concepts):
  configured owners and signature threshold determine transaction authority;
  a platform-owned Safe does not itself create user-controlled residual balances.
- [x402 facilitator responsibilities](https://docs.x402.org/core-concepts/facilitator):
  payment verification/settlement is distinct from platform-ledger debits.
