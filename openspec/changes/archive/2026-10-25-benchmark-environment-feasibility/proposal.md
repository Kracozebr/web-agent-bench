## Why

The MVP needs observed proof that its selected controlled x402 service and narrow
Base fork can execute, reset and remain isolated within bounded infrastructure.
Identity/billing designs alone do not establish task execution or resource cost.

Status: implementation scope authorized on 2026-10-23; see [approval.md](approval.md).
Concrete configuration prerequisites and runtime acceptance remain outstanding.

## What Changes

- Pin one reviewed versioned environment manifest with source block/hash, local
  chain/asset/contract identities, test funding, fee model and tool policy.
- Provide scoped basic test tools and a declared reference driver for one x402
  purchase and one exchange through an actual selected forked pool.
- Distinguish native ETH from pinned WETH and expose explicit driver-selected
  wrap/unwrap actions with chosen amounts. Do not automatically convert in swap
  tools or count WETH as an ETH target/native gas reserve; retain asset-specific
  conversion evidence without claiming all task rubrics are implemented.
- Execute technically valid learning mistakes within isolated test state and
  retain their consequences without goal-based rejection or silent repair. Pin
  task evaluation criteria separately from always-enforced scope, admin/foreign-run,
  real-fund/external-write and hard infrastructure boundaries.
- Verify actual local x402 payment settlement and resource delivery, plus local
  EVM swap receipts/token effects; no canned facilitator success or toy AMM.
- Apply the user-selected local-EVM gas model at pinned settings, recording gas
  from successful/failed executed transactions and excluding unmodelled Base L1
  fees explicitly rather than calling them measured zero.
- Verify independent environments, reset/equivalent starts, protected admin RPC
  boundaries and no transaction forwarding to the external source network.
- Measure bounded cold/warm execution, cache/artifact footprint and upstream reads
  with explicit unknowns, safe raw evidence and replay comparison.

Non-goals: all twelve task rubrics, production agents/auth/billing, full leaderboard,
mainnet effects/finality, complete Base gas fidelity, native client-wallet scoring,
attack attribution, concurrency promises or full-node replication.

Exact source block, contracts/pool, local payment scheme/asset, supported SDK/runtime
versions and guardrail values must be pinned before execution. A successful probe
does not validate the later combined data/swap workflows or the whole MVP.

## Capabilities

### New Capabilities

- `benchmark-environment-feasibility`: pinned scoped local execution, actual x402/
  fork probes, observed gas, isolation/reset, external-read boundary and measured
  evidence for the first delivery slice.

### Modified Capabilities

None. Preserve synchronized `benchmarking-core` and `realtime-pvp`, plus all other
proposed capabilities. Reuse their identity/evidence contracts without implementing
another run coordinator, owner ledger or agent-auth system.

## Impact

Future changes add an isolated Anvil/TypeScript tool-worker acceptance deployment,
controlled resource server and local settlement path, test-only funding/setup,
read-only source-RPC proxy, resource recording and Python environment adapters.

This affects benchmark execution validity and simulated economic measurements,
not real customer settlement or PvP fairness. No node, RPC transaction, fixture
contract, executable test or benchmark action is created/run by this proposal.

Dependency clarification: benchmark-task-suite consumes this packet's actual
manifest/receipt evidence before resolving complete case quantities. The first
feasibility purchase/swap remains independently executable after its own approval;
it does not require all twelve task fixtures first and does not prove their
rubrics. Reuse environment identities in the later task release, keep sealed
materials outside public artifacts and preserve original raw evidence.
