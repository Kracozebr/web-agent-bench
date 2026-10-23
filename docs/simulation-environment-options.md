# Simulation environment: development and infrastructure comparison

Research date: 2026-10-22. The user selected the combined environment direction
described below. Detailed architecture and implementation are not approved or
measured. Sources are official tool/protocol/provider documentation.
No simulator was started, provider key used, transaction sent, or resource
benchmark performed.

## Accepted context and user-reported resources

- Agent receives a goal with constraints and available tools, not a recipe.
- Tasks are independent at the environment-state boundary; complex workflows
  remain possible inside an individual task.
- Ranked starting conditions are identical for all participants and repeated
  attempts within a benchmark version, separate from training. State/offer/input
  fixtures must be pinned and independently initialized; equal conditions do not
  mean sharing mutable chain state. Actual equivalence/isolation is untested.
- Twelve tasks across x402 payments and basic Web3, with one shared toolset.
- Agent tools expose separate basic actions. Offer/recipient/amount/sequence
  choices remain with the agent; the platform signs with isolated test wallets.
  Exact schemas and step counting remain to be designed, not measured behavior.
- Native ETH and WETH are distinct. The user selected explicit agent-chosen
  wrap/unwrap actions with direction/amount; no automatic conversion by swap tools.
  WETH alone does not fulfill an ETH goal or native gas reserve. Pin the actual
  WETH contract and observe native/token balances and conversion receipts separately;
  exact fixture contracts and reference action counts remain to be verified.
- Goals, mandatory constraints, weights and partial-credit criteria are public
  beforehand; ranked variant inputs are revealed at task issuance and reference
  solutions are not disclosed. See [task-catalog-draft.md](task-catalog-draft.md).
- Task funds are isolated test funds. Real platform deposits/withdrawals remain
  a separate production boundary and common cost under every simulation option.
- Task-budget valuation uses a disclosed fixed educational ETH/USDC rate per
  benchmark version, not a live rate per run. The user selected observed local-EVM
  gas with version-pinned settings and no modelled Base L1 component for MVP.
  Numeric rate, exact fee/payer formulas and rounding remain open; this does not
  override the actual pinned pool's quote or swap result.
- Operating expenses include paid data, observed gas of successful/failed executed
  transactions and exchange fees counted once. Exchanged principal, payouts and
  required reserves are checked separately. Exact fee evidence/gas formulas remain
  design work. Final task evaluation uses completion state and violation history,
  not a temporary goal state the agent subsequently undid.
- A forbidden request proven rejected before execution permits further work and
  is logged separately for safety, unless published rules forbid the attempt
  itself. Unknown effects require reconciliation. Exact per-task constraints and
  evaluator evidence still require design.
- The user selected actual execution of technically valid learning mistakes in
  the caller's isolated test state: wrong test recipient, exceeded task budget or
  excess test allowance. Evaluate the consequences without silently correcting
  the choice. Always enforce environment/admin/foreign-run/real-fund boundaries
  and hard infrastructure limits; real service spending caps remain separate.
  Genuine malformed requests, protocol errors and contract reverts are not forced
  into successful execution. Pin evaluator rules separately from enforced boundaries.
- The user reports 16 CPU and 32 GB RAM on the intended server. HDD capacity can
  be expanded to 500 GB–1 TB, but large storage is undesirable. CPU characteristics,
  free RAM, current disk capacity/IOPS, and other workloads are unknown.

## Clarify the alternatives

"Controlled environment" can mean two different implementations:

1. **Behavioral model:** our backend computes balances, quotes, fees and outcomes.
   This is a reference-model boundary, not EVM execution. Cheapest fidelity level
   for simple tasks, but cannot prove contract execution or realistic DeFi pricing.
2. **Controlled local EVM:** a development chain with deployed test tokens and
   deliberately selected contracts/pools. It provides execution evidence for those
   contracts; it still does not prove the state or economics of Base Mainnet.

**Pinned Base fork:** a local EVM execution environment initialized against a
chosen Base block and selected deployed contracts. This is not running a full Base
node or continuously mirroring the live market. It provides fork execution evidence,
not mainnet inclusion, market competition, finality, or profitability evidence.

## Officially documented building blocks

- [Anvil overview](https://www.getfoundry.sh/anvil/index.html): local development
  chain, fixed-block forks, state save/load, and execution traces.
- [Anvil fork documentation source](https://github.com/foundry-rs/book/blob/master/src/pages/anvil/forking.mdx):
  RPC-backed forks, block selection, provider rate-limit settings, and disk cache.
  Cached state is not a guarantee of complete offline coverage of future actions.
- [Anvil state documentation source](https://github.com/foundry-rs/book/blob/master/src/pages/anvil/state-management.mdx):
  dump/load/reset and history pruning. Save/restore support alone does not prove
  isolation between simultaneous participants; orchestration must enforce it.
- [Alchemy pricing](https://www.alchemy.com/pricing): the fetched page advertises
  30 million CU/month on Free, archive data, and PAYG compute at USD 0.525/million CU.
  CU are method-dependent billing units, not a count of HTTP calls. PAYG treatment
  must be checked when selecting a plan; do not assume it subtracts Free's allowance.
- [Base fees](https://docs.base.org/specifications/transactions/network-fees):
  execution and L1 data/security components need an explicit simulation policy.
- [x402 network support](https://docs.x402.org/core-concepts/network-and-token-support):
  a protocol network identifier is distinct from an operational settlement path.
  An isolated fork requires a verified local/self-hosted settlement arrangement;
  a public mainnet facilitator must not be assumed to settle against it.

Some Foundry web pages were returned as unsupported Markdown by the web tool;
their official repository documentation sources were read instead.

## Development work

| Work area | Behavioral model | Controlled local EVM | Pinned Base fork |
| --- | --- | --- | --- |
| Market/token behavior | Implement simplified rules ourselves | Deploy/configure test tokens and chosen contracts; seed liquidity | Select supported tokens, pools, routers and block; verify compatibility |
| Execution verification | Verify our own model's durable state | Check local receipts/events/balances and constraints | Same, plus named fork state and protocol-specific assertions |
| Reproducible setup | Seed and reset our model | Deployment fixture and state reset | Pin block/hash, setup fixture, cache/provider strategy and reset |
| Integration burden | Few external dependencies; custom logic grows with realism | Contract setup and funding; avoid creating an unnecessary custom DEX | RPC reads/rate limits, ABI/router dependencies, token funding and fork/version compatibility |
| Isolation | Separate model state per task/participant | Isolated chain state or one exclusive task per worker | Same; a shared mutable fork cannot be reverted concurrently across unrelated runs |
| Maintenance | Maintain our invented market rules | Maintain local fixtures and contracts | Maintain supported pinned configurations and invalidate/version updates explicitly |

All options also need task design, tools, evaluator, evidence, queue/resource
limits, billing integration, and operational recovery. Those common platform
costs should not be attributed only to the fork option.

Inference: the behavioral model is likely the shortest route if its limited
evidence is sufficient. A realistic controlled EVM and a narrow fork can have
comparable integration effort; implementing realistic AMM behavior ourselves may
cost more than using an existing contract in a fork. No measured hours, delivery
dates, multipliers, or full-project estimates are available yet.

## Infrastructure and money

| Cost | Controlled local environment | Narrow pinned fork |
| --- | --- | --- |
| Existing server | CPU/RAM/disk and competing workloads | Same classes of resources, plus fork state cache and remote-read latency |
| External blockchain RPC during tasks | Not needed for a self-contained model/local chain | Required for uncached source state; usage depends on supported actions and cache reuse |
| Gas for task transactions | Test funds only | Test funds only; operations execute locally |
| Paid simulator subscription | Not inherently required by the local approach | Not inherently required to run local Anvil |
| Database, artifacts, monitoring, backups | Common platform cost | Common platform cost plus cache/fixture retention |
| Real USDC account deposits/withdrawals | Real network/settlement costs, separately designed | Same; a fork does not remove real platform payment costs |

An RPC bill could remain zero on a small pilot within provider Free limits, but
that has not been demonstrated for this workload. For scale illustration only,
10 million paid CU at the stated PAYG compute rate is USD 5.25; 100 million is
USD 52.50, before any other plan charges. Neither figure is an estimate of our
monthly consumption. Upstream request volume must be measured on cold and warm
fixtures; cache reuse does not imply no future upstream calls.

## Implications for the reported server

The reported CPU/RAM makes a bounded pilot on existing hardware plausible; it
does not establish a concurrency number. Begin capacity validation with one
active worker and increase only after measurements. Agent LLM inference remains
on the owner's side; the server runs tools, test execution, evaluation and storage.

The proposed narrow-fork architecture does not require reserving 500 GB–1 TB
for a full Base chain database. Retained blocks, cached source state, evidence,
traces and backups still need explicit quotas/retention. Cache size and HDD
latency are not measured. Cold and warm cache conditions can affect observed
task latency, so prepare fixtures and define timing before ranking speed.

## Selected direction and next evidence

### Selected task-budget fee model

The user selected the local-EVM educational gas model for MVP, with settings
pinned to the benchmark version. Base documents both L2 execution and L1 data/security
fees; an EVM execution cost alone must not be labelled the full Base fee.
Source checked 2026-10-22:
[Base network fees](https://docs.base.org/specifications/transactions/network-fees).

| Option | Task accounting | Work and measurement boundary |
| --- | --- | --- |
| Selected: local EVM gas model for MVP | Use observed local receipt gas costs, with fee-policy configuration pinned to the benchmark version; convert ETH cost using the selected educational rate | Requires actual execution/receipt and reserve checks. Explicitly exclude unmodelled L1 fees rather than report them as measured zero; label the result simulated task expense, not total Base cost |
| Deferred alternative: add a pinned Base L1 component | Separately derive and verify a data-fee estimate against the selected Base snapshot and incorporate it consistently into task spending/reserve checks | Requires serialized-transaction/fee-source evidence and coherent test-fund accounting in addition to local execution. It remains a snapshot model, not a prediction of future mainnet fees |

The first option is confirmed by the user, with published limitations and no
claim of full-network fee fidelity. This choice is not a measured development-
cost estimate. Both options keep
paid-data and exchange-fee components separate and count executed failed
transactions under the selected operating-expense rule. Neither changes real
customer deposits, withdrawal gas paid by the platform, or service tariffs.

Pin exact policy/rounding and verify receipt/balance consistency before a version
can be accepted. Do not select a numerical gas rate from a live documentation
example or silently change the model between ranked runs.

User-selected direction: one Anvil-based execution layer, controlled x402 service endpoints
and a compatible test settlement path, plus a narrow pinned Base fork for selected
Web3 tasks. Avoid implementing a realistic DEX from scratch or supporting every
public router/aggregator in the first release. The user accepted combining these
parts; exact contracts, block, tools and settlement implementation remain open.

The proposed [feasibility packet](../openspec/changes/benchmark-environment-feasibility/proposal.md)
and [BDD design](../openspec/changes/benchmark-environment-feasibility/bdd-design.md) cover
one x402 purchase and one swap against a selected forked pool, reset and repeated
with cold/warm caches. Measure CPU, RAM, cache/artifact bytes, provider CU/requests,
latency, receipts and outcome verification. Required observations also include
blocked administrative methods and no effect on real platform funds. The slice
has 8 requirements and 12 mandatory planned environment scenarios, all not_run.
It requires explicit scope approval before executable tests or code.

Next discovery command: `/opsx:explore benchmark-environment-feasibility` — review
the concrete execution boundary and pin its remaining configuration. No full-chain
node, paid RPC plan, executable test or running settlement path is established by this note.
