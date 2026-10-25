# Benchmark environment feasibility

## Purpose

Define reproducible acceptance of isolated local fork execution, scoped tools, x402 settlement, resource bounds and replayable evidence without claiming live-chain or production readiness.

## Requirements

### Requirement: BEF-REQ-001 Pin and validate the execution manifest
The acceptance deployment SHALL bind every probe to a reviewed immutable manifest of source network/block/hash, local execution identity, runtime/SDK versions, contract/code/asset/route identities, test funding, resource data, allowed tools, educational fee/valuation policy and numeric resource guardrails. The manifest SHALL distinguish task evaluation criteria from always-enforced authentication, scope, service/admin/foreign-run, real-fund/external-write, technical and hard resource boundaries. It SHALL verify actual observations against that manifest before accepting results; unavailable or incompatible prerequisites SHALL be blocked rather than replaced silently.

#### Scenario: BEF-SC-001 Pinned manifest matches actual source and execution
- **WHEN** an actual acceptance environment is initialized with the reviewed manifest and source block, contract, local identity or scheme support is missing or mismatched
- **THEN** the gate SHALL verify actual source/runtime/code observations, accept only a matching supported environment and otherwise report the missing or contradictory prerequisite without substituting another block, contract or asset

### Requirement: BEF-REQ-002 Expose scoped explicit-choice tools
The tool boundary SHALL bind authenticated private acceptance principals to one environment/task and expose bounded basic reads, offers, quotes and selected execution. The reference driver SHALL make explicit choices through that same boundary. Participant routes SHALL NOT expose goal-solving shortcuts, administrative setup, raw arbitrary transactions/signing, foreign environment access or caller-selected external endpoints.

Technically valid learning mistakes within that isolated test scope SHALL execute without silent correction, goal-based pre-execution rejection or corrective reset. Wrong test recipients, spending above a task expense budget and excess test allowances SHALL retain selected parameters and observed consequences for evaluation. Hard boundaries SHALL remain enforced; malformed requests and actual protocol/contract failures SHALL retain their observed outcomes. Task evaluation criteria SHALL NOT waive real service-spending caps or manufacture test funds. This feasibility capability SHALL provide attributable effect evidence without claiming to implement the full task grading/lifecycle.

#### Scenario: BEF-SC-002 Basic tools preserve the reference driver's explicit choices
- **WHEN** the declared driver reads balances and offers, requests a quote and explicitly chooses technically valid in-scope operations including task-goal mistakes through authenticated scoped tools
- **THEN** the service SHALL return actual observations and execute the selected operations without goal-based rejection, silent correction or corrective reset, preserve chosen parameters and attributable effects or genuine protocol failures for evaluation, and record technical signing/approval and explicitly selected conversions without claiming agent reasoning or full task grading

#### Scenario: BEF-SC-003 Participant requests cannot reach setup or foreign execution
- **WHEN** the caller submits a foreign environment or generation, arbitrary URL, raw signing or transaction payload, or administrative method through participant routes
- **THEN** the service SHALL reject the unauthorized request before signing or setup/execution and record the denial and unchanged protected state without treating caller-supplied identifiers as authority

### Requirement: BEF-REQ-003 Observe actual local x402 purchase and recovery
The selected x402 path SHALL use the pinned implementation, actual selected asset/scheme and local verification/settlement path. It SHALL distinguish offer inspection, authorization verification, observed settlement and data delivery. Paid success SHALL require correlated actual local payment effects and verified resource delivery, with idempotent recovery of the original operation under response loss or duplicate requests. Unknown payment observations SHALL NOT become success or trigger blind replacement payment.

#### Scenario: BEF-SC-004 Offer inspection neither pays nor delivers purchased data
- **WHEN** the driver inspects the selected controlled x402 resource and its payment requirements without authorizing a purchase
- **THEN** the service SHALL expose the declared offer and payment requirements while observed token balances, settlement records and purchased-data delivery remain unchanged

#### Scenario: BEF-SC-005 Selected x402 purchase settles locally and delivers verified data
- **WHEN** the driver selects a valid offer and authorizes the pinned asset and scheme through the actual local verification and settlement implementation
- **THEN** paid success SHALL require correlated requirements, operation identity, actual local receipt and exact token effects plus the declared data hash, with successful delivery withheld until the declared settlement check succeeds

#### Scenario: BEF-SC-006 Payment recovery preserves one effect under duplicates and uncertainty
- **WHEN** invalid or mismatched payment is submitted, an accepted response is lost, concurrent duplicates retry, or the original local settlement observation becomes temporarily unavailable
- **THEN** the service SHALL deny invalid payment without paid delivery, recover accepted requests by their original identity, preserve one settlement and one logical delivery and leave unresolved evidence unknown without a replacement debit

### Requirement: BEF-REQ-004 Execute the selected forked-pool exchange
The swap probe SHALL execute a driver-selected bounded exchange through an actual selected contract in the pinned local Base fork and verify receipts, events, assets, amounts, recipient, allowance and remaining reserve. Native ETH and pinned WETH SHALL have distinct asset identities. Separate wrap/unwrap actions SHALL preserve driver-selected direction/amount and actual execution evidence; swap tools SHALL NOT convert representations automatically. WETH alone SHALL NOT satisfy an ETH target or native-ETH gas reserve. The probe SHALL observe actual conversion receipts and separate native/token balances with gas attribution, not infer conversion from a ticker or equivalent valuation. Representation mismatch SHALL be retained for the task-specific evaluator rather than create an unselected blanket zero. A toy exchange model or quote alone SHALL NOT satisfy actual execution.

#### Scenario: BEF-SC-007 Selected forked-pool swap proves actual constrained effects
- **WHEN** the driver chooses a declared exchange and explicit wrap/unwrap actions through the selected actual forked contracts, with valid and invalid asset, route, recipient, output, reserve or unconverted-WETH variants
- **THEN** successful constrained exchange SHALL require local receipts/events and actual input/output/recipient/allowance/reserve observations plus selected conversion parameters and distinct native ETH/WETH balances; tools SHALL perform no automatic conversion or count WETH as an ETH target or gas reserve, technically valid task-goal mistakes SHALL retain their observed mismatches, security-boundary violations SHALL reject before execution and genuine contract failures SHALL retain actual reverted effects without treating a quote or toy market as completed exchange

### Requirement: BEF-REQ-005 Account for educational local gas without invented Base fees
The educational model SHALL calculate observed gas costs of successful and reverted executed local transactions using the version-pinned fee policy and educational ETH/USDC rate. It SHALL identify the actual payer and attribute each expense once, separating service fees and exchange/payout principal. Missing cost observations SHALL remain unknown. Unmodelled Base L1 fees SHALL be labelled unmodelled rather than measured zero or complete Base cost.

#### Scenario: BEF-SC-008 Observed successful and reverted gas uses the pinned educational model
- **WHEN** successful transactions, actually executed reverted transactions and unexecuted rejected requests are evaluated under the manifest fee and valuation policy
- **THEN** the model SHALL count observed executed costs once with actual payer attribution, invent no fee for an uncharged unexecuted request, keep missing costs unknown, separate principal/service components and label Base L1 fees unmodelled

### Requirement: BEF-REQ-006 Isolate and reset complete environments
Independent active environments SHALL have separate mutable chain and off-chain operation/payment/delivery state. Reset/reuse SHALL fence stale workers and restore the declared logical baseline including relevant balances, nonces, allowances, code, time/fee state and service namespaces. Equivalent starts SHALL be demonstrated by observed state and fixture hashes rather than labels alone.

#### Scenario: BEF-SC-009 Two active environments cannot mutate or reset one another
- **WHEN** two independent actual environments execute and one is reset while the other retains admitted operations and changed state
- **THEN** each SHALL preserve its own chain and service/payment/delivery state and reject cross-environment access, with observed balances/nonces/allowances and operation records proving no shared mutable reset effect

#### Scenario: BEF-SC-010 Reset restores equivalent starts and fences stale work
- **WHEN** a completed trial is reset or recreated, stale-generation work arrives and a new separately identified trial repeats the declared probes
- **THEN** the service SHALL reject stale work, restore actual relevant chain and off-chain baseline observations and logical fixture hash and permit the new trial without leaking prior payment/delivery state, while labelling repeated execution separately from replay

### Requirement: BEF-REQ-007 Measure bounded cold and warm resource use
The acceptance deployment SHALL run declared cold/warm trials within reviewed time, memory, disk and upstream-call guardrails and record actual host/container limits, elapsed intervals, CPU, peak RAM, cache/artifact bytes and source request counts. Unobservable provider CU SHALL remain unknown. Missing required measurements or exceeded bounds SHALL prevent a successful feasibility claim; development-host measurements SHALL NOT establish production-host capacity.

#### Scenario: BEF-SC-011 Cold and warm trials produce bounded actual resource evidence
- **WHEN** declared cold and warm actual probe trials run with dedicated cache state, resource sampling and numeric guardrails, including a bounded over-limit variant
- **THEN** the gate SHALL record actual host/limits, elapsed time, CPU, peak RAM, cache/artifact sizes and source requests, report unavailable CU as unknown, stop safely on exceeded bounds and block success on missing required observations without claiming production capacity

### Requirement: BEF-REQ-008 Protect source access and preserve replayable evidence
External source access SHALL validate actual chain/block provenance and allow only declared read-only RPC methods. Transaction submission, administration and signing methods SHALL be rejected at the proxy without forwarding them externally. Each probe SHALL retain redacted raw evidence paths/hashes and manifest/environment/operation/transaction/delivery identity. Evidence replay SHALL be read-only and distinct from new execution after reset; secrets and reusable payment authorizations SHALL NOT enter artifacts.

#### Scenario: BEF-SC-012 Source proxy and evidence keep execution local and replay read-only
- **WHEN** the actual source RPC is checked for pinned chain/block/code provenance, prohibited outbound methods are submitted to the proxy and original redacted evidence is replayed
- **THEN** the proxy SHALL forward only declared reads, reject submission/admin/signing without external forwarding and retain attributable sanitized paths/hashes; replay SHALL compare original observations without broadcast, with missing provenance or evidence remaining blocked or unknown
