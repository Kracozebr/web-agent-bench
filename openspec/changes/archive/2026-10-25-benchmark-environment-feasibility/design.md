## Context

Status: scenario/implementation scope authorized; see [approval.md](approval.md).
Concrete execution prerequisites remain outstanding. The user selected
an Anvil execution layer with controlled x402 endpoints and a narrow pinned Base
fork. Existing planning does not prove a working node, settlement path or budget.
The user's reported server is 16 CPU/32 GB RAM; available headroom/disk IOPS and
local container-engine readiness are unverified.

## Goals / Non-Goals

**Goals:** actual x402 purchase and forked-pool swap probes through basic scoped
tools; reproducible isolated starts; observed local gas; measured cold/warm cost
and safe source-RPC/evidence boundaries.

**Non-Goals:** full task suite or scoring rubrics, real user accounts/billing,
mainnet broadcast/finality, full Base fee fidelity, real attack attribution,
public replay, automatic LLM execution or server-capacity promises.

## Decisions

### 1. Manifest before execution

Use a versioned manifest containing source network/block number/hash, observed
source provenance, local endpoint/chain identity, Anvil/SDK versions, contract
addresses/code hashes and ABIs, pool/route/token representations, fixture funding,
resource data/offer hashes, allowed tools, fee/valuation policy and guardrails.
Classify always-enforced security/technical/resource rules separately from task
evaluation criteria (recipient objective, expense budget, reserve and allowance
cleanup). Both are pinned; a task goal must not silently become a signer guard.
Exact values are intentionally not invented during planning. Pin/review them
before executing a probe; never select `latest` independently for each trial.

Keep source Base identity distinct from local execution identity even if numeric
chain IDs coincide. Inspect the actual runtime/contract state against the manifest.
Missing contracts, inconsistent block/code or unsupported scheme/asset is blocked,
not permission to swap in a toy market or call a different network successful.

Test wallet material is ephemeral and isolated; no real owner/signer credentials,
CDP integration or customer balance participates. Fixture funding changes are
declared private setup operations. They do not prove real acquisition of funds.

### 2. Basic tools and reference probes

The tool worker accepts authenticated private acceptance principals, binds each
request to one environment/task and exposes bounded read/offer/quote/selected-
execution responsibilities. A reference driver makes explicit choices through
the same tool boundary; it is not an external agent compatibility or reasoning test.
There is no goal-solving tool that automatically picks a winning offer/route.

| Probe | Required actual effects | Scope limit |
| --- | --- | --- |
| Controlled x402 purchase | Real offer, valid chosen payment, local verification/settlement, observed token effect and verifiable data delivery | Selected SDK/scheme/asset/chain path only; no real customer funds |
| Selected forked-pool swap | Actual allowed contract execution, receipt/events, input/output/reserve and allowance observations | One narrow route/profile, not all DEXs or the twelve rubrics |

Anvil admin/raw RPC, arbitrary signing/transactions and environment setup must be
unreachable through participant tool routes or arbitrary target URLs. Validate
authenticated scope, supported local assets/routes/operation surface and payload
before signing; preserve rejected-request and observed-effect evidence.
Caller-provided environment IDs do not grant access.

The user selected technically valid learning mistakes to execute in isolated test
state. Do not replace a wrong test recipient with the expected one, cap the task
expense budget, trim an excess local allowance, choose a better offer or pre-reject
the action solely for a task-goal mismatch. Preserve the selected parameters,
actual receipt/effects and comparison against the pinned criteria. Once proven,
a mandatory violation is handled by the existing lifecycle zero/termination rule;
this probe does not implement the full task evaluator or reverse the mistake.

Always reject unauthorized foreign/stale environment access, service/admin/setup
operations, raw signing/transactions, arbitrary external endpoints and real-fund
or external-write paths before effects. Enforce hard resource bounds, supported
schemas and actual protocol/contract preconditions. Insufficient test balance or
an agent-chosen on-chain slippage guard can genuinely fail/revert: do not invent
funding, force a revert to succeed or mislabel it as an infrastructure denial.
Task expense ceilings and gas reserves are evaluated goals, distinct from hard
transaction gas/resource bounds and real service-balance/bonus spending caps.

### 3. Actual local x402 settlement

Use the pinned official x402 implementation and an explicitly local self-hosted
or in-resource settlement path. A read of the offer produces no payment/delivery.
Verification alone is not observed settlement; correlate payment requirements,
operation/authorization identity, local transaction/receipt, exact token effects
and delivery hash. The selected probe withholds successful delivery until its
declared local settlement check succeeds. Invalid or uncertain evidence must
not produce a false paid-success result.

The official protocol distinguishes network expression, runtime registration
and an operational facilitator path. Self-hosted/self-facilitating operation is
documented; it still needs validation against this private chain and asset.
[x402 network support](https://docs.x402.org/core-concepts/network-and-token-support),
[x402 facilitator](https://docs.x402.org/core-concepts/facilitator).

Pin the token's actual signature/authorization/allowance and chain-domain behavior
with the selected scheme. Do not assume a public facilitator can settle a private
fork or that a matching symbol makes a local token equivalent to forked USDC.
If a controlled test-token fallback is needed, state the changed boundary and
return that choice for scope review; it cannot satisfy a selected fork-USDC path
by relabelling the asset. The complete later combined data/swap task asset model
is a separate integration requirement, not proven by these two narrow probes.

Duplicate request/response-loss recovery preserves business payment/delivery
identity; unknown settlement is observed by its original identity rather than
blindly paid again. These are integration negative cases, not new stress tasks
added to the participant's retained twelve-task inventory.

### 4. Fork swap and local gas accounting

Choose one actual forked pool/router and bounded amount within a pinned liquidity
snapshot. Record quote inputs, supported spender and selected test recipient, approvals, execution
receipts/events, actual token deltas and final reserve. Native ETH and pinned
WETH are distinct assets. The user selected explicit wrap/unwrap actions; the
driver/agent chooses direction and amount, and swap tools must not automatically
convert. WETH alone does not satisfy an ETH target, payout or native gas reserve.
Pin actual WETH contract/code and typed native/token asset identities. Record
selected conversion parameters, actual receipts, separate native/token balances
and observed gas; an equivalent displayed valuation is not asset equivalence.
The probe must include actual selected conversion execution, not only a label.
Reference counts include necessary explicit conversions; hidden convenience work
cannot inflate agent step counts. Unsupported asset/route or an isolation-boundary
violation rejects. A technically valid wrong goal recipient, excess allowance or
insufficient final task reserve executes unchanged within the pinned test surface
and records the mismatch. A local EVM revert records its actual receipt/effects
rather than imaginary success; agent-supplied contract guards remain effective.
Native-asset goal mismatches are evaluation evidence, not a new universal
zero-credit rule; the later task rubric decides their scoring consequence.

The user selected the educational local-EVM gas model. Use actual receipt gas
costs under version-pinned fee policy, including executed reverted transactions.
Convert ETH-denominated costs at the selected version-fixed educational rate.
Pre-execution rejection without a charge does not create gas spending. Missing
receipts/cost observations are unknown. Base L1 fees are explicitly unmodelled,
not reported as measured zero or as part of a claimed complete Base fee.

Record payer and cost attribution, especially when a local facilitator sponsors
settlement gas; do not charge the same fee once through service price and again
through a gas line. Operating expenses remain separate from exchanged/payout
principal and final reserve. Exact payer/fee formulas, precision and gas settings
are required manifest configuration before acceptance.

### 5. Isolation and reset

Proposed execution uses exclusive environment ownership, initially one active
worker, with independent instances for the two-environment isolation gate. Do not
concurrently revert a shared mutable node for unrelated tasks. Fence stale worker
actions before reset/reuse; tie references to instance/generation identities.

Restore or recreate the pinned baseline and reset all relevant components:
chain balances/nonces/allowances/code and declared time/fee state, payment nonces,
offers, delivery records and operation IDs. Compare actual initialized observations
and logical fixture hash; a matching manifest label alone is insufficient. Raw
trial IDs or isolated address bindings may differ without changing the logical task.

Anvil documents state save/restore/reset facilities. Their availability does not
prove isolation or exact restoration in this setup; verify the selected version
and complete fixture semantics. [Foundry state management](https://github.com/foundry-rs/book/blob/master/src/pages/anvil/state-management.mdx).

### 6. Source network and measurement boundary

Route upstream access through a declared read-only RPC boundary with no customer
secrets and no forwarding of transaction submission/admin/signing methods.
Validate actual source chain/block identity and record read counts/provenance.
Local signing/settlement endpoints cannot be supplied by the participant. Probe
denied outbound methods at the proxy boundary without sending a real transaction
to an external network. Record rejected forwarding, not a claim of mainnet execution.

Use actual controlled-service, node and receipt observations in the real acceptance
deployment. PostgreSQL or an equivalent durable selected application store records
operations/evidence; a pure Python balance model or canned settlement response
cannot replace execution. Pin storage/runtime choices to the accepted stack.

Record actual development host/container limits and trial conditions. Measure
wall intervals, process/container CPU and peak RAM, cache/artifact bytes and
upstream requests for defined cold and warm trials. A cold trial uses a dedicated
empty task cache, never deletes a shared or user cache. Warm uses recorded prepared
state; neither implies offline coverage. Report provider CU only if observable,
otherwise unknown with request counts; no inferred zero bill or concurrency claim.

Guardrails for trial time, memory/storage and upstream calls are required before
execution. If exceeded, stop safely and report the actual failed/blocked boundary,
not successful capacity. Development measurements do not establish the user's
server capacity; production-host validation belongs to operations acceptance.

### 7. Evidence, replay and prerequisite status

Every probe records manifest/source/code/version hashes, environment generation,
scoped operation and transaction/delivery identities, actual observations, raw
redacted paths/hashes and resource samples. No private keys, source RPC secrets,
raw reusable payment authorizations or production wallet material enter evidence.
Replay compares the original trace/outcome inputs without broadcasting again.
New execution after reset is a separately labelled trial, not evidence replay.

All twelve proposed scenarios are mandatory environment gates, including actual
source-RPC validation. Missing Docker/runtime, reachable approved source RPC,
pinned block/contracts, scheme/asset support or measurements is blocked. No
Anvil, facilitator, fork, contract or test has been started by this planning work.

## Risks / Trade-offs

- [A local success is mistaken for Base execution] -> record local/source identities
  separately and exclude mainnet/finality/full-fee claims.
- [Fork token and x402 scheme are incompatible] -> pin actual validation and block
  or review a changed asset path; never use a canned facilitator success.
- [Reset leaves off-chain payment state] -> compare chain and service baselines
  and exercise fresh purchases after reset under scoped operation identity.
- [Resource measurement overpromises deployment] -> report actual host/conditions
  and unknowns; production-host capacity requires its own gate.

## Migration Plan

After explicit scope approval, pin configuration, create the isolated acceptance
deployment and collect probes before generalizing to all tasks. Retain existing
main specs/harness inventories. Rollback stops new admissions, fences the worker
and retains evidence before removing only its task-owned disposable environments.
No real platform balance or source-chain contract is modified.

## Open Questions

Pin block/pool/route/assets, local x402 scheme/domain compatibility, precise tool
schemas, fee/payer attribution, reset policy and numeric guardrails before running.
Decide any required fallback through reviewed scope. Full rubrics, combined
economic workflows, actual attack attribution and production-host deployment
remain separate work; this slice is the first feasibility evidence, not the MVP.

### Downstream task-suite boundary

benchmark-task-suite depends on observed feasibility evidence, not the reverse.
Pin the first probe's concrete environment configuration before its execution;
then resolve and validate all complete task cases/rubrics before task-suite
activation. The twelve-rubric gate cannot be satisfied by this one purchase/swap,
and rubric drafting cannot manufacture missing block/contract/fee observations.
Closed S3/M2/H3/U1 payloads belong to access-controlled task bundles, not public
probe examples/images. Preserve reusable manifest/receipt identities and evidence
provenance without adding a second grader or weakening these twelve probe gates.
