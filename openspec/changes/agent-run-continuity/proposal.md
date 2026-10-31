## Why

Native Training run a6e58ea5-11a2-4476-8619-3bfab98e22d3 lost S1 while an acceptance-only handoff waited for a second prompt. M1 then paid before cutoff but did not admit retrieve before cutoff; grading stayed unknown and cancelled H1. MCP task:null hid the intermediate state.

## What Changes

- Copy one complete, scoped handoff containing the actual agent/intent and continuous execution through explicit terminal run status.
- Extend current_task additively with authorized run status, explicit waiting state and retry hint; task:null alone never asserts completion.
- Permit ordinary rubric evaluation of M1 only when authoritative closed/census/payment/source evidence proves no retrieve was admitted at cutoff. Missing/ambiguous delivery proof remains unknown.
- Add source-bound BDD, negative controls and actual browser/API/worker/PG/BEF E2E; preserve historical runs and existing financial authority.

## Capabilities

### New Capabilities

- `agent-run-continuity`: Complete handoff, observable run progression and evidence-backed paid-without-request grading.

### Modified Capabilities

None of the synchronized main capabilities is replaced. This approved correction integrates active BER003/004/007/008 and BRL025; it does not replace their outstanding target/native matrices.

## Impact

owner-web handoff; owner-identity scoped issuance/MCP, M1 capture projection and evaluator; observation loaders and acceptance/BDD adapters. No pricing, refund, task goal/weight, deadline, historical regrading, live-mainnet or PvP settlement change.

Approval: owner explicitly requested all three fixes, subagents, BDD, real end-to-end, commit and push in this chat on 2026-10-31. This authorizes the bounded fix and adversarial assertions below; no further product decision is inferred.
