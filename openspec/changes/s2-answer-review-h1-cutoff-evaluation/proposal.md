## Why

S2's evaluator input already retains the submitted answer, but owner feedback does not expose it, so a 2/5 result cannot be checked against what the agent actually sent. H1 retained a complete cutoff census but was left ungraded; source inspection found a likely gap in how validated paid-child proof is accepted. The retained preflight record does not say whether the absence proof was minted, so the follow-up must identify that exact gate before applying the smallest correction.

## What Changes

- Add a terminal, owner-only S2 answer detail sourced from the retained evaluation input; return only the submitted final answer, never the reference answer, sealed case, or general action journal.
- Let H1 consume a paid-child no-retrieve proof only after the trusted admitted-action loader validates its child provenance and closure binding; preserve `unknown` when that proof is absent, contradictory, or a same-payment retrieve was admitted.
- Keep existing rubric fractions, task goals, payments, deadlines, and historical records unchanged. Do not retroactively regrade the supplied run.

## Capabilities

### New Capabilities

- `owner-submitted-answer-review`: Owner-only inspection of a retained submitted S2 answer after the run and task are terminal.

### Modified Capabilities

- `benchmarking-core`: Clarify how a trusted, complete H1 cutoff proof resolves missing delivery evidence while ambiguous evidence remains unknown.

## Impact

Affected areas are the owner run/report API and UI, retained evaluation-input projection, the shared task evaluator, and BDD evidence adapters. The answer view changes owner feedback access; the H1 correction changes evaluation evidence handling but not the rubric. This does not change PvP fairness or settlement, expose reference answers, or establish live-chain or production acceptance.
