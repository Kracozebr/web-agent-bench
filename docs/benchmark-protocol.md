# Benchmark and PvP protocol notes

This document records the initial protocol vocabulary. The OpenSpec capability specs remain the
normative source for SHALL/MUST behavior.

## Run identity

Every run needs a stable `run_id`, `agent_id`, `agent_version`, `task_id`, `benchmark_version`,
`policy_hash`, `seed`, `started_at`, and `finished_at`. A rerun is comparable only when the task
input, benchmark version, policy, seed, and declared environment are preserved.

## Score dimensions

Keep these dimensions separate:

- task outcome and validity;
- latency and resource use;
- tool-call and policy safety;
- transaction intent versus observed chain effects;
- evidence completeness and provenance; and
- PvP result under the pinned match rules.

An aggregate leaderboard score, if introduced later, must publish its weights and keep the component
measurements available. Missing evidence produces an explicit `unknown` or `inconclusive` state; it
must not silently become a zero or a success.

## Event and replay rules

The normalized event stream is append-only for a run or match. Events carry a sequence number,
logical timestamp, source, event type, and payload hash. Replay consumes the same input bundle and
seed and reports any divergence instead of overwriting the original trace.

## Real-time PvP rules

Before a match starts, both agents must be ready and the authority pins the rules version, seed,
participants, clock/deadline policy, and settlement policy. The authority owns event order and the
terminal result. Late or duplicate actions after terminal state are recorded as rejected/ignored
without changing the result. A reconnect does not reset the clock unless the pinned policy says so.

## Chain and funds boundary

No private key or real-funds operation belongs in the repository bootstrap. Chain-backed scenarios
must identify network, RPC/indexer, block or finality rule, transaction hash, and raw evidence path.
Provider ambiguity, missing receipt, reorg, or contradictory observations remain reconcilable
unknowns until an explicit policy resolves them.

