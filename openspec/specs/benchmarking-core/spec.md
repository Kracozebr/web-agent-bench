# Benchmarking core

## Purpose

Define reproducible, evidence-first benchmark runs for web3-capable agents without collapsing
outcome, cost, latency, safety, and chain evidence into an opaque score.

## Requirements

### Requirement: WB-REQ-001 Normalize benchmark run identity and trace
The benchmark harness SHALL record a stable run identity containing the agent, task, benchmark
version, policy hash, seed, execution interval, and an append-only normalized event trace. The trace
MUST preserve event sequence, source, type, and payload hash so a result can be replayed and audited.

#### Scenario: WB-SC-001 A benchmark run records reproducible identity and trace
- **WHEN** the reference runner executes one task for an agent with a pinned benchmark version, policy, and seed
- **THEN** the run record SHALL contain the reproducible identity fields and a sequence-ordered normalized event trace

### Requirement: WB-REQ-002 Keep score dimensions and evidence status separate
The benchmark harness SHALL expose task outcome, latency, resource/cost, tool-safety, chain-effect,
and evidence-quality dimensions separately. Missing, delayed, contradictory, or unverifiable chain
evidence MUST be represented as `unknown` or `inconclusive` and MUST NOT be silently converted into
a successful outcome.

#### Scenario: WB-SC-002 A scorecard separates outcome cost latency safety and evidence
- **WHEN** a completed run is converted into a scorecard with partial chain evidence
- **THEN** the scorecard SHALL retain separate dimensions and mark the chain evidence status as `unknown` without changing the task outcome

### Requirement: WB-REQ-003 Make deterministic replay explicit
The benchmark harness SHALL support replaying a run from the same task input, benchmark version,
policy hash, seed, and declared environment. A replay MUST report divergence in the normalized event
trace or score inputs instead of overwriting the original run evidence.

#### Scenario: WB-SC-003 The same seed produces a comparable replay
- **WHEN** the reference runner replays a run with the same input bundle, version, policy, seed, and environment
- **THEN** the replay SHALL produce the same canonical event and score inputs and SHALL retain the original evidence separately

### Requirement: WB-REQ-004 Preserve evidence provenance at the benchmark boundary
Every benchmark result SHALL identify the execution boundary and evidence bundle used to derive it.
The harness MUST distinguish local reference, sandbox, testnet, and mainnet observations, and MUST
not label a lower-trust boundary as proof of a higher-trust boundary.

#### Scenario: WB-SC-004 Incomplete chain evidence remains explicitly unknown
- **WHEN** a run has a submitted transaction intent but no verified receipt or finality observation
- **THEN** the benchmark result SHALL preserve the raw evidence reference and classify the chain effect as `unknown` rather than `success`

