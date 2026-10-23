## Context

Status: proposed; complete BDD/implementation approval is pending. There is no
working TypeScript payment application, CDP project or real wallet in this task.
The selected stack is Fastify/Next.js/PostgreSQL with shared internal billing.
Real account money remains separate from benchmark execution funds and bonuses.

## Goals / Non-Goals

**Goals:** stable funding addresses, evidence-based deposit credit, safe/finalized
availability, fresh owner confirmation, durable cash allocations/withdrawals,
CDP signing boundaries, gas/sweeps, account recovery and operator reconciliation.

**Non-Goals:** production activation, other assets/networks, bridging, prize/PvP
settlement, arbitrary raw signing, custody guarantees, full Google/MCP onboarding,
changing task grades or issuing bonus grants in this capability.

## Decisions

### 1. Confirmed rules and remaining defaults

Confirmed: permanent platform-controlled EOA per owner; CDP API-key signing;
wallet-button and ordinary/exchange-origin deposits credited automatically without
user-entered hashes; verified `safe` deposits fund services, corresponding remaining
cash is withdrawable only at `finalized`; private UI shows the distinction.

Each withdrawal requires fresh account-linked wallet proof or Google-only passkey,
bound to its amount, asset/network, destination and operation. Any validated Base
destination is permitted without proving ownership of that destination. Send is
automatic after authorization; operator approval is not a normal withdrawal step.
Platform pays network gas. Bonuses cannot fund withdrawals or network payouts.

The user selected an initial 1-USDC minimum, administrator-configurable, with an
exception for the entire positive withdrawable cash remainder below the threshold.
This remainder excludes existing holds, bonuses and funds not verified finalized.
A smaller partial withdrawal below the threshold is rejected; zero is not a payout.

Configure a confirmation method before exposing initial funding details. Free
registration and authorized bonus actions remain available without it. Recovery
uses a pre-enrolled backup, otherwise manual ownership review; Google login alone
cannot reset withdrawal proof. Manual method recovery is not an administrator
issuing a transfer on the owner's behalf.

| Detail | Rule / proposed default | Status and review boundary |
| --- | --- | --- |
| Cash lot allocation | Oldest credited eligible deposit first for cash service spends/reserves; withdrawals select only finalized residual lots | Explains residual withdrawable amounts without counting funds twice. Source-linked refunds restore the same lot state. |
| Credited deposit loses canonicality | Preserve evidence, remove unsupported unspent availability, record any consumed deficit and pause new cash spends/withdrawals for the affected owner until reconciliation | User-confirmed; no bonus-to-cash conversion, cross-owner recovery charge, erased history or automatic new payment. Missing/stale RPC alone is uncertainty, not proof of reorg. |
| Manual owner recovery is pending | Pause new withdrawals until manual recovery is resolved; ordinary service/bonus usage remains available under its existing rules | User-confirmed; separate from a forum restriction or per-withdrawal admin approval. Exact case initiation/resolution authority still needs design. |
| Signing path | CDP sign-only for a persistently constructed transaction; persist signed bytes/hash before broadcasting through RPC | Engineering proposal; exact SDK capabilities, permission policies and nonce handling require a feasibility gate. Managed send is not silently substituted if it weakens recovery identity. |
| Withdrawal accounting | Hold finalized cash before submission. A pre-submission cancellation releases only when durable signer/broadcast-boundary evidence proves the signed payload could not have escaped. After escape is possible, settle on matching finalized canonical success or release once on a finalized canonical revert in the original signer/nonce/transaction lineage under the predeclared provider/head evidence policy; otherwise keep the hold. | Engineering default selected for this plan. Gas is platform expense even for a proven reverted transaction; stale, missing or conflicting evidence remains unknown. |

Maximum withdrawal, operational gas limits, liquidity/sweep
thresholds, RPC supplier, challenge/reservation/recovery TTLs and rate limits are
required configuration before execution, not chosen amounts here.

### 2. One shared cash ledger with deposit provenance

Add records for `deposit_address`, `deposit_observation`, `cash_lot`,
`cash_allocation`, `withdrawal_intent`, `withdrawal_authorization`, `payment_tx`,
`signing_request`, `recovery_case` and reconciliation/evidence checkpoints to the
shared ledger. Reuse owner/agent identity, operations, holds/outbox and source-
specific receipts from the billing packets; do not maintain an independent wallet
balance field that bypasses reservations or promotional source restrictions.

A deposit address binds one owner to network, provider account and provisioning
operation. Persist successful control/mapping before displaying it; linked Google
and wallet logins and all agents share it. Concurrent/retried provisioning exposes
one stable mapping. If provider creation is ambiguous, reconcile the same request
before exposing any address; unused remote accounts, if discovered, are inventoried
and never silently reassigned. A public address is not a private signing credential.

Pin network and exact USDC contract; do not trust symbol or request parameters.
Identify a transfer occurrence by network, token, transaction/event index and
observed block hash; group reorg/reinclusion history under its original business
identity with explicit reconciliation. One transaction may contain multiple
transfers. The token event sender and transaction sender may differ, and neither
is assumed to be the authenticated owner. Internal sweep events do not create
customer deposits. Zero/failed/foreign-token/unknown-recipient events do not credit.

### 3. Safe credit and finalized withdrawal availability

Validate successful receipt, exact event/recipient/amount and canonical block,
then compare the observed block with fresh `safe`/`finalized` heads and ancestry.
An event is initially pending; credit a cash lot once at verified `safe`, and
promote only its remaining residual eligibility at verified `finalized`. No second
credit occurs at promotion. No time threshold substitutes for RPC evidence.

Available-for-services cash is the sum of supported safe-or-finalized residual
lots minus assigned holds; withdrawable cash is the finalized unallocated subset.
Both are views of one cash balance. Bonus amounts are separate. Each cash debit
or hold records the exact lot portions; a unit held for a run cannot also be held
for withdrawal. Proposed FIFO allocation applies consistently to service charges
and queue reservations; withdrawals allocate finalized lots only. For example,
with 10 finalized units plus 5 safe units and a FIFO service spend of 3, remaining
service availability is 12 and withdrawable availability is 7. This is a synthetic
accounting example, not a measured payment or economic guarantee.

Source-preserving cash refunds restore the original allocations and their actual
current chain support, not an invented finalized deposit. Bonus refunds follow
their separate grant/expiry policy. A cancelled hold releases its original lots.
Finality promotion of already spent/held units cannot increase available cash.

Persist scan cursor plus block identities; use bounded overlap to recover missed
logs after restart. A webhook may trigger observation but cannot alone mint cash.
Unsupported tags, missing receipts, stale/conflicting RPC or provider outages
remain explicit unknown/reconciliation states; no silent downgrade to `latest`.
An out-of-order stale notification cannot demote evidence without verification.
A proven canonicality loss follows the confirmed owner-scoped rule above, with
append-only corrections and explicit consumed deficit. Incident resolution must
not charge other owners, manufacture evidence or trigger another external send.

### 4. Enrollment, authorization and recovery

Require actual owner authentication to set up funding/confirmation. Initial
method enrollment needs fresh owner proof and binding of the new credential;
the exact Google reauthentication mechanism must be verified in the identity
integration, not guessed from an old session cookie. Changes while an existing
method is usable require its purpose-specific authorization and new-method proof.
Prevent removing the last usable method through an ordinary session alone.

For a withdrawal, display and persist immutable owner, chain/token, exact amount,
destination, challenge/expiry and intent hash. Wallet proof is an EIP-712 withdrawal
intent from an already linked wallet, not SIWE login, token approval or the
recipient wallet. Passkey uses a server-held challenge bound to the same intent,
credential ownership, RP/origin and required user verification; an ordinary login
assertion is not a withdrawal proof. Browser tests use a declared virtual WebAuthn
authenticator and actual verification, not evidence of a biological human/device.

In one database transition, check current method/policy, unused valid proof and
available finalized cash; consume the proof, reserve exact lots and emit one
authorized execution intent. Changed data, expired/replayed proof, foreign keys,
agent grants and bonus/nonfinalized funding reject without a send or cash hold.
An active financial/recovery restriction has explicit reason and scope; a forum
ban alone does not deny cash withdrawal. Provider policy rejection is distinct
from owner authentication and does not automatically retry another provider.

Backup recovery verifies an enrolled credential. Manual recovery is a scoped
admin review of synthetic evidence in acceptance: case identity, requester,
ownership findings, decision, replacement credential proof, revisions and audit.
A pending case cannot grant signing authority or waive per-withdrawal confirmation.
The user confirmed pausing new withdrawals during pending manual recovery while
keeping ordinary services and bonuses available under their existing rules.
Exact case initiation/resolution authority and ownership checks still require design;
an unverified third-party allegation must not establish an authorized recovery case.
Do not collect real identity documents or user wallet material in test evidence.

### 5. Durable external execution

Withdrawal admission additionally enforces the selected minimum. Proposed atomic
check: let A be positive exact requested amount, W the current finalized unallocated
cash, and M the configured minimum. Require A <= W and (A >= M or A == W).
Use exact token base units rather than rounded display amounts. Thus with W=0.70
and M=1, A=0.70 is allowed but A=0.50 is rejected; with W=2, A=0.70 is rejected.
All owner-proof, finality and financial-restriction checks still apply.

Evaluate this with lot allocation under the same serialization boundary as other
cash consumers. If availability changed since display, do not increase/decrease
the signed amount to manufacture a full-remainder exception. Preserve the proof
and avoid a partial hold/outbox when admission fails; a different amount needs a
new intent/proof. Proposed policy timing: read/version the minimum in this atomic
admission, retain its value and exception basis on the admitted intent, and do not
retroactively invalidate an already-reserved operation on later minimum changes.
The owner page displays the current threshold and exception; scoped admin changes
record actor, previous/new value, version and audit without granting payout authority.
These concurrency/versioning mechanics are engineering proposals for review;
the 1-USDC initial minimum, configurability and full-remainder exception are confirmed.

CDP is selected, but its exact SDK methods and request/recovery behavior are not
yet integrated. Proposed flow: persist a normalized authorized payment transaction
with signer, chain, token/recipient/amount, reserved nonce, bounded fee fields and
intent identity; request sign-only; persist protected signed payload/hash; broadcast
those exact bytes. Store secrets outside evidence and keep signing interfaces off
participant routes. Signed transactions are sensitive operational payloads, not
public test fixtures. Log redacted identities/hashes, not raw wallet credentials.

Use a persistent per-signer nonce fence and documented lock order. Duplicate
workers or a lost response recover the same operation; repeat broadcasting only
the same known transaction is not a new withdrawal. If nonce/provider state is
ambiguous, preserve holds and reconcile; never construct a fresh-nonce replacement
as a blind retry. Fee replacements, if later allowed, need explicit lineage and
the same economic destination/value, not another authorized payout.

States distinguish draft/awaiting confirmation, authorized/reserved, signed,
submitted, observed included, finalized settled, finalized reverted, cancelled
before payload escape and reconciliation-required. A verified success receipt
must match chain, sender, destination, token/value and operation lineage. A
release-qualifying revert must match the original economic intent's signer, nonce
and persisted transaction/attempt lineage, be canonical and finalized, and satisfy
the provider/head agreement rule pinned for the deployment. That rule checks fresh
provider observations for receipt identity/status, canonical block ancestry and a
finalized head containing the receipt; missing, stale or contradictory evidence
is unknown and retains the hold. Before submission, cancellation may release only
when durable signer/broadcast-boundary records prove the signed payload could not
have escaped to a broadcast-capable boundary. Once escape is possible, local
cancellation, timeout, missing transaction, replacement or dropped claims do not
prove nonpayment. A nonfinal included revert also retains the hold until finality.
No new admin approval path is introduced. Terminal histories retain late evidence
without issuing another payout.

### 6. Sweeps, gas and operational views

Platform funds ETH for selected owned deposit addresses when needed and may batch
USDC collection by configurable policy. It pays withdrawal gas from operating
funds; the user receives the confirmed amount without a deducted network fee.
ETH top-ups, sweeps, customer deposits and withdrawals have different purposes.
Sweeping does not change an owner's ledger balance or finality lot identity.
Insufficient gas/liquidity queues the same authorized operation with an honest
status; it does not consume its proof twice or lower its amount silently.

Owner UI exposes stable deposit address, pending/safe/finalized availability,
source-specific history, withdrawal details/status and method/recovery controls.
Admin views expose observation/submission/reconciliation and recovery decisions
under scoped roles, not a raw-sign or arbitrary cash-credit button. Reconcile
observed supported assets across controlled addresses against cash liabilities,
holds, in-flight transfers and recorded platform expenses without double-counting
assets moved by sweeps. Replay compares journal/observation hashes and reports
missing evidence; never sign or send while replaying.

### 7. Acceptance boundaries and prerequisites

Local gates use actual HTTP/Next.js/PostgreSQL and Anvil token transfers. A clearly
labeled acceptance-only RPC gateway controls safe/finalized-head observations,
delays, reorg fixtures and missing/conflicting evidence while actual EVM execution
and receipt/log identity are observed. This proves our reaction to declared
finality inputs, not that a local chain achieved Ethereum/Base finality.
Local CDP test transport is explicitly a contract fixture for faults, not live CDP.

A separate mandatory external gate uses actual CDP API-key signing and actual
Base Sepolia RPC/test funds, obtains an address, signs/submits a bounded test-token
transfer, verifies the observed receipt and available finality tags and recovers
the same intent. Use a dedicated test project/accounts with no production assets;
pin actual methods, policies, token and test configuration before execution.
No real mainnet credentials, keys or customer data enter fixtures/prompts/logs.
Missing provider access/RPC/test funds yields `blocked`, never a fixture pass.
Sign-only capability and request recovery must pass this feasibility gate before
the payment implementation is treated as integrated. A provider SDK example alone
is not acceptance or proof of policy availability for this account.

Reuse one approved active-delta harness selector and preserve other contracts.
Shared auth/ledger/bonus/run/forum integrations are real dependencies. Acceptance
scenarios must name which observations are local controlled versus actual external
CDP/testnet and retain redacted raw paths/hashes plus source/config identities.

## Risks / Trade-offs

- [Safe service credit precedes full finality] -> per-deposit evidence and residual
  allocations, proposed scoped reconciliation restrictions and explicit deficit.
- [Provider send ambiguity or stale/conflicting finality evidence] -> stable
  intent/nonce/hash lineage, pinned provider/head agreement, retained holds while
  unknown and no fresh-payment retry.
- [Recovery lowers the confirmation boundary] -> method-bound proofs, scoped
  review/audit and fresh confirmation after replacement; no Google-session reset.
- [Self-hosted app plus external signer still needs authority controls] -> limited
  payment credentials, approved operation schema, policy probe and no agent signing.
- [Broad real-money integration] -> test-only local then mandatory external
  testnet evidence, with no implied authorization to activate mainnet.

## Migration Plan

After approval, add provenance/allocation/payment schemas to the shared ledger;
do not fabricate source evidence for old synthetic balances. Build observer and
controlled acceptance environment, authorization/UI, then signing probe/integration.
Provider-account creation and external tests require declared test configuration.
Roll back by stopping new funding exposure, confirmations and signing while
continuing observation/reconciliation of known operations. Preserve cash holds,
raw evidence, signed-intent identities and provider mapping; do not reset nonces,
erase history or remap old deposit addresses to another owner.

## Open Questions

Canonicality-loss and manual-recovery pauses are user-confirmed. Review FIFO allocation,
sign-only feasibility, provider/head configuration and other operational values.
The finalized terminal/release rule above is the selected engineering default for
this plan. Pin the
actual production token/RPC only in the approved integration; local/testnet
fixtures do not establish mainnet readiness. Identity/bootstrap and manual-review
evidence rules need explicit ownership criteria before acceptance can pass.
