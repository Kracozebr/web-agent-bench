# Base account payments

Status: proposed; complete scenario/scope approval is pending. Confirmed product
choices, including incident/recovery restrictions, and proposed FIFO/signing defaults are distinguished in
`../../design.md`. All acceptance gates remain `not_run`.

## ADDED Requirements

### Requirement: BAP-REQ-001 Expose permanent owner funding addresses after confirmation setup
The platform SHALL configure a verified owner withdrawal method before exposing initial real-funding details, while allowing free registration and permitted bonus usage. It SHALL provision through selected CDP API-key wallets and persist one permanent controlled EOA per owner shared by linked identities/agents before display. Retries, provider ambiguity and linking SHALL preserve this mapping without reassignment or foreign access.

#### Scenario: BAP-SC-001 Initial funding requires a configured withdrawal method
- **WHEN** an authenticated owner without a confirmation method requests first funding details, then enrolls a linked wallet or passkey with fresh owner proof
- **THEN** funding details SHALL remain unavailable until valid enrollment, while free registration and authorized bonus actions remain available, and a stale session or agent grant SHALL not enroll a withdrawal credential

#### Scenario: BAP-SC-002 Address provisioning exposes one permanent owner mapping across retries
- **WHEN** concurrent requests provision a CDP-backed address, a provider response is lost and the worker restarts before linked login identities request the address
- **THEN** the platform SHALL expose one permanent controlled EOA mapping only after durable reconciliation, share it across the owner's agents and linked logins, and prevent another owner's access or address reassignment

### Requirement: BAP-REQ-002 Attribute verified token transfer events automatically
The observer SHALL validate exact configured chain/token, successful receipt, mapped recipient, positive event amount and observed block identity. It SHALL automatically attribute each valid event once without user-entered hashes or sender-login assumptions, including multiple transfers in one transaction. Wrong/failed/unsupported evidence and callbacks alone SHALL NOT create cash. Raw event/block evidence SHALL be preserved.

#### Scenario: BAP-SC-003 Verified transfer events credit the correct owner once
- **WHEN** actual local EVM token transfers produce multiple eligible events in one transaction to mapped addresses and the observer rescans after restart
- **THEN** each valid event SHALL be attributed by its mapped recipient and exact network/token/event identity once, preserve raw receipt and block evidence, and require no user-entered transaction hash or sender-login match

#### Scenario: BAP-SC-004 Wrong or unsupported deposit evidence cannot create cash
- **WHEN** the observer encounters a wrong token or network, failed transfer, zero amount, unknown recipient or unauthenticated callback claiming a successful deposit
- **THEN** the platform SHALL create no customer cash credit from invalid evidence or callbacks alone and SHALL preserve an auditable rejection or unresolved observation rather than trusting token names or supplied hashes

### Requirement: BAP-REQ-003 Gate service and withdrawal availability by observed chain stage
A pending deposit SHALL NOT be spendable. A verified canonical safe deposit SHALL create one cash credit usable for services; verified finalized support SHALL promote only remaining residual withdrawal eligibility without another credit. Missing/stale/conflicting head or ancestry evidence SHALL remain unresolved, not be inferred from elapsed time or a weaker RPC stage. Private views SHALL distinguish pending, service-available and withdrawable amounts.

#### Scenario: BAP-SC-005 Safe and finalized heads control distinct availability without a second credit
- **WHEN** a valid deposit progresses through pending, verified safe and verified finalized observations while timers advance and RPC tags become stale or unavailable
- **THEN** service availability SHALL begin only at verified safe state, withdrawal eligibility SHALL promote only remaining finalized cash without another credit, and elapsed time or missing tags SHALL not manufacture confirmation

### Requirement: BAP-REQ-004 Allocate shared cash holds and refunds by original provenance
All services, queued runs and withdrawals SHALL share one source-aware cash ledger. Under the proposed FIFO rule, service allocations SHALL select oldest eligible credited lots; withdrawal allocations SHALL select finalized residual lots only. A unit SHALL NOT be spent or held twice across concurrent operations. Refunds/releases SHALL restore original allocations once at their actual current support level, without inventing finalized cash or converting bonuses.

#### Scenario: BAP-SC-006 Cash allocation prevents overlap between services runs and withdrawals
- **WHEN** service purchases, queued runs and withdrawals compete for one owner's mixture of safe and finalized cash lots
- **THEN** the proposed oldest-credit-first service allocation and finalized-only withdrawal allocation SHALL preserve source conservation and holds so no cash unit is spent or reserved twice, while another owner's lots remain untouched

#### Scenario: BAP-SC-007 Refund and cancellation preserve the original cash provenance
- **WHEN** an eligible cash service refund or a cancelled pre-start reservation restores amounts from deposit lots at different current confirmation stages and a duplicate delivery follows
- **THEN** the operation SHALL restore or release its original lot portions once without inventing a finalized deposit, converting bonuses into cash or increasing another lot's funds

### Requirement: BAP-REQ-005 Recover observations and isolate canonicality incidents
The observer SHALL persist checkpoints and block identities, recover with overlap and deduplicate across restart. Uncertain provider observations SHALL remain reconciliation-required without false credit or payment replay. Under the user-confirmed canonicality-loss policy, proven unsupported credits SHALL receive append-only corrections, unsupported unspent availability removal and explicit consumed deficits, with an affected-owner pause on new cash spends/withdrawals until reconciliation, without charging other owners.

#### Scenario: BAP-SC-008 Observer restart and conflicting providers preserve explicit uncertainty
- **WHEN** the observer restarts after a partial scan and receives missing, stale or contradictory receipt/head observations
- **THEN** it SHALL resume from durable checkpoint with bounded overlap, retain original evidence and mark unresolved funding or execution as reconciliation-required without duplicate credit or weaker confirmation fallback

#### Scenario: BAP-SC-009 Canonicality loss preserves history and isolates the affected owner
- **WHEN** a previously safe credited deposit is proven noncanonical after some of its value was held or consumed
- **THEN** under the user-confirmed incident policy the system SHALL remove unsupported unspent availability, retain original effects and explicit deficit evidence, pause new cash spending and withdrawals for that owner pending reconciliation, and not charge another owner or blindly resend money

### Requirement: BAP-REQ-006 Authorize each withdrawal with current owner-bound proof
A withdrawal SHALL require fresh purpose-specific account-linked wallet proof or Google-only passkey confirmation bound to immutable owner, amount, chain/token, destination, challenge and expiry. Passkey verification SHALL require correct credential ownership, origin/RP and user verification. Login-only, agent, foreign, tampered, expired or replayed proofs SHALL NOT authorize payout. A valid destination SHALL NOT require matching the login wallet. Confirmation SHALL be consumed once under server-side enforcement.

#### Scenario: BAP-SC-010 Wallet confirmation authorizes one immutable withdrawal intent
- **WHEN** a wallet-linked owner signs a withdrawal to a different Base recipient and callers alter its amount or address, replay proof, use login proof or supply another wallet signature
- **THEN** only the current valid account-linked purpose-specific proof SHALL authorize that exact withdrawal once, while tampered, expired, replayed, foreign or login-only proofs SHALL create no payout

#### Scenario: BAP-SC-011 Passkey confirmation is bound to a Google-only owner's withdrawal
- **WHEN** a Google-only owner confirms using a virtual WebAuthn authenticator and stale login assertions, wrong credentials or missing user verification are submitted
- **THEN** actual passkey verification SHALL require the owner-bound withdrawal challenge, expected origin and RP, expiry and user verification, consume the proof once and reject ordinary login assertions as payout authorization

### Requirement: BAP-REQ-007 Reserve finalized money atomically with owner authorization
Accepted owner confirmation, exact finalized cash-lot holds and one execution intent SHALL commit atomically. Concurrent withdrawals/services/runs SHALL NOT overcommit funds. The initial withdrawal minimum SHALL be 1 USDC and administrator-configurable. A positive exact amount below the current minimum SHALL be admissible only if it equals the entire currently withdrawable cash remainder, excluding existing holds, bonuses and nonfinalized funds. Amount eligibility SHALL be checked with reservation atomically; a changed remainder SHALL NOT silently change the owner-confirmed amount. Rejection SHALL create no partial hold, consume no proof and emit no signing intent. Under the proposed policy-timing rule, admission SHALL retain the minimum version/value and full-remainder basis; later minimum changes SHALL NOT invalidate already-reserved intents. Bonus or nonfinalized value SHALL NOT fund withdrawal; a forum restriction alone SHALL NOT become a financial restriction. Ordinary authorized withdrawals SHALL proceed automatically without administrator approval, subject to explicit payment/recovery policies.

#### Scenario: BAP-SC-012 Withdrawal authorization and finalized cash reservation commit together
- **WHEN** valid owner withdrawal requests at the minimum, below it for a whole or partial remainder, or for zero race with service spending, another withdrawal or a minimum change, and an agent or bonus-only account requests payout
- **THEN** only admissible positive owner-confirmed requests at or above the configured initial 1-USDC minimum or for the entire smaller withdrawable cash remainder SHALL consume proof and reserve finalized cash atomically once; zero, smaller subminimum partial, agent, bonus or nonfinalized funding attempts SHALL fail without consuming proof, a signing intent or partial hold, while exact signed amounts and admitted policy versions remain preserved

### Requirement: BAP-REQ-008 Submit and settle one economic withdrawal with platform gas
The payment boundary SHALL preserve intent, signer, nonce, transaction/hash and attempt lineage across signing/submission/restart. Unknown execution SHALL keep holds and require reconciliation, never a blind fresh-nonce payout or automatic refund. Matching successful execution SHALL settle one debit only after canonical inclusion is finalized under the configured provider/head evidence policy. After signing or submission may have allowed a signed payload to escape, cancellation, timeout, missing transaction, replacement or dropped-transaction claim SHALL NOT prove nonpayment and SHALL NOT release the hold. A pre-submission cancellation SHALL release the hold only when durable signer/broadcast-boundary evidence proves the signed payload could not have escaped. Otherwise, a submitted payment hold SHALL be released once only after a failed/reverted transaction in the original signer/nonce/transaction lineage is canonically included and finalized under the same configured provider/head evidence policy, with the required provider observations agreeing on receipt identity/status, canonical block ancestry and a finalized head containing the receipt; missing, stale or contradictory observations SHALL remain unknown. Gas/liquidity shortage SHALL retain honest state and the same authorized amount. Network gas SHALL be platform expense without an added owner/bonus debit.

#### Scenario: BAP-SC-013 Ambiguous signing or broadcast cannot create a fresh payment
- **WHEN** the payment worker loses a signing or broadcast response, restarts while retries or another worker compete for its nonce, and receives a cancellation request before or after the signed-payload boundary
- **THEN** it SHALL release a pre-submission hold only when durable boundary evidence proves the signed payload could not have escaped; otherwise it SHALL recover the same intent and signer/nonce/transaction lineage, retain the cash hold while execution is unknown, and never allocate a fresh payment or nonce as a blind retry

#### Scenario: BAP-SC-014 Observed withdrawal settlement and proven failure have different terminal effects
- **WHEN** submitted transactions are observed as included, successfully finalized, reverted, replaced, dropped or unresolved and terminal processing is retried against the original signer/nonce/transaction lineage
- **THEN** only matching canonical success finalized under the configured provider/head evidence policy SHALL settle the customer debit once, and a canonical reverted transaction in that same lineage SHALL release the hold once only after the required providers agree on receipt identity/status, canonical block ancestry and a finalized head containing the receipt; included but nonfinal reverts, replaced or dropped claims, missing/stale/conflicting provider or head evidence, and all other unresolved execution SHALL retain the hold and original evidence without a replacement payout

#### Scenario: BAP-SC-015 Platform gas never silently reduces the owner's withdrawal
- **WHEN** an authorized withdrawal encounters insufficient operating gas or liquidity and later executes with a verified fee
- **THEN** the system SHALL retain the same authorized amount and honest pending state until admissible execution, pay network gas from platform operating funds and record it separately without debiting bonus or extra owner cash

### Requirement: BAP-REQ-009 Keep gas and sweeps separate from customer funding
Gas top-ups and sweeps SHALL use typed authorized operational routes and stable transaction identities. Internal asset collection SHALL NOT create a new customer deposit, change cash-lot provenance or alter customer liability. Repeated delivery/observation SHALL preserve one economic operation and reject operational route misuse.

#### Scenario: BAP-SC-016 Internal sweeps change custody location without creating customer deposits
- **WHEN** actual local gas top-ups and token sweeps move assets between platform-controlled deposit and operating addresses with duplicate worker and observer delivery
- **THEN** they SHALL retain typed operational identities, leave customer lot balances and finality provenance unchanged, create no duplicate customer credit and restrict operational signing to configured owned routes

### Requirement: BAP-REQ-010 Recover methods without bypassing withdrawal proof
Recovery SHALL use a verified pre-enrolled backup, otherwise scoped manual administrator review with recorded ownership findings and replacement-credential proof. Google login alone SHALL NOT automatically reset withdrawal authority. Method changes/recovery SHALL preserve audit and require fresh owner proof for later withdrawals. During pending manual recovery new withdrawals SHALL pause, while ordinary services and bonuses SHALL remain available under their existing rules.

#### Scenario: BAP-SC-017 Backup and manual recovery never authorize a payout by themselves
- **WHEN** an owner loses the primary method, uses an enrolled backup or opens an all-methods-lost review, and an administrator resolves a case after recorded ownership checks and replacement-method proof
- **THEN** recovery SHALL preserve audit and require a new valid owner proof for any later withdrawal; Google login alone or an unverified review SHALL not reset authority, and under the user-confirmed policy pending manual recovery SHALL pause new withdrawals while ordinary services and bonuses remain available under their existing rules

### Requirement: BAP-REQ-011 Expose role-scoped payment and recovery interfaces
Actual account pages SHALL show the permanent address only after setup, source-separated cash availability/bonus history, the current withdrawal minimum/full-remainder exception and immutable withdrawal details/status. Payment/recovery admin views SHALL enforce scoped roles, including audited changes of the withdrawal minimum without payout authority. Direct API calls SHALL enforce the same authorization; public, agent and foreign-owner projections SHALL NOT expose private finances, arbitrary signing authority or provider credentials.

#### Scenario: BAP-SC-018 Account and admin pages expose actual payment state under scoped roles
- **WHEN** an owner uses the actual funding and withdrawal pages while an administrator inspects observations/recovery and a foreign owner or agent directly requests private operations
- **THEN** the interface SHALL expose the stable address only after setup, separate pending/service/withdrawable cash and bonuses, show the current minimum/full-remainder rule and immutable withdrawal details and real status, and enforce roles including audited authorized minimum changes without exposing signing credentials or another owner's finances

### Requirement: BAP-REQ-012 Preserve reconciliation evidence and verify the external integration separately
The platform SHALL retain original operation/event/block/provider identities and raw evidence paths/hashes. Reconciliation SHALL distinguish observed supported assets, customer cash claims, holds, in-flight transfers and expenses without double-counting sweeps. Replay SHALL report divergence/missing evidence without signing/sending or overwriting history. Acceptance SHALL separately require actual CDP API and Base Sepolia test-only evidence; local fixtures SHALL NOT satisfy that mandatory external gate, and absent prerequisites SHALL produce blocked results without mainnet-readiness claims.

#### Scenario: BAP-SC-019 Reconciliation and replay retain asset liability and evidence identities
- **WHEN** payment observations, source allocations, sweeps and in-flight withdrawals are reconciled and replayed after restart with a missing artifact or conflicting event
- **THEN** the system SHALL preserve original event/block/provider identities and hashes, distinguish supported assets from cash liabilities and platform expenses without double-counting sweeps, and report discrepancies without signing, sending or overwriting evidence

#### Scenario: BAP-SC-020 Actual CDP and Base Sepolia integration records its own external evidence
- **WHEN** a dedicated test configuration provisions an actual CDP EOA and signs and broadcasts a bounded Base Sepolia test-token transfer then reconciles the same intent against actual RPC receipt and available finality heads
- **THEN** the external gate SHALL record real provider and testnet evidence with the pinned method and policy identities and no duplicate economic transfer; missing credentials, test funds or required observations SHALL block rather than pass through local fixtures
