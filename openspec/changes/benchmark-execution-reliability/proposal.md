## Why

The participant Training run left an admitted H1 payment pending at task cutoff; the Ranked run rejected all valid swaps through a recursive eight-element MCP limit and stopped before H2/H3/U1. These are validity and recovery issues, not evidence that the participant agent failed every task.

Status: implementation and listed BDD assertions approved on 2026-10-31 after independent review. Planning validation and approval are separate from runtime acceptance. See [approval](approval.md) and the [cross-change index](../../../docs/beta-usability-spec-plan.md).

## What Changes

- Make every declared bounded action and finish-answer shape representable through MCP, with useful schemas and safe errors.
- Reconcile every admitted action at cutoff without resubmitting an ambiguous payment; finish tasks with an explicit known or unknown result.
- Diagnose the two H1 failures and the earlier pre-M3 successor-preparation failure using original source-bound evidence.
- Complete the four missing catalog negative controls and independent restart/replay tails; preserve existing financial and fence contracts.

Non-goals and evidence boundary: New task goals, weights, pricing/refund policy, hosted solvers, parallel task execution, new publication eligibility, timing recalibration, prefetch implementation, PvP or real-money settlement. A local reference adapter is not a participant-owned model run or target-host acceptance. No PvP fairness or settlement change is included.

## Capabilities

### New Capabilities

- `benchmark-execution-reliability`: Benchmark execution reliability.

### Modified Capabilities

None of the three synchronized main capabilities is replaced in this planning packet. Integration with active deltas is recorded explicitly below and in design.md; existing active approval scopes are not silently amended.

## Impact

owner-identity MCP registration, action/closure/executor/coordinator, observation and recovery services; owner-acceptance producers and independent BDD adapters. Task goals, weights, prices, model execution ownership and PvP settlement stay unchanged.

Owns correctness of existing execution and evidence contracts. Integrates active benchmark-run-lifecycle (BRL), benchmark-task-suite (BTS), beta-poc-delivery (BPC) and benchmark-environment-feasibility (BEF); does not redefine their score or refund policies.

Dependencies: First implementation stream. Cabinet errors consume its safe classifications; time-budget calibration and prefetch qualification require its successful serial baseline.

