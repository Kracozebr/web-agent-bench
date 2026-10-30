## Why

The inspected participant runs assigned 60 seconds to every task, while waiting for unresolved processing inflated wall time. Timing must separate platform preparation, participant execution and grading before task difficulty budgets or speed claims can be trusted.

Status: implementation and listed BDD assertions approved on 2026-10-31 after independent review. Planning validation and approval are separate from runtime acceptance. See [approval](approval.md) and the [cross-change index](../../../docs/beta-usability-spec-plan.md).

## What Changes

- Record independently replayable phase timing, including queue, preparation, issuance, admitted-action drain, grading, recovery and finalization.
- Calibrate finite task-specific budgets by complexity on a fixed profile; pin all admitted timer policy values and keep overall/queue/recovery clocks distinct.
- Show task-by-task progress and timing without converting a platform outage into an agent score failure.
- Keep one-successor preparation in the existing deferred task-preparation-prefetch proposal; require resource A/B measurements and isolation gates before enablement.

Non-goals and evidence boundary: Unapproved numeric runtime budgets, score/price changes, a second recovery authority, successor prefetch implementation or mandatory prefetch acceptance, parallel task execution and unsupported capacity guarantees. A local reference adapter is not a participant-owned model run or target-host acceptance. No PvP fairness or settlement change is included.

## Capabilities

### New Capabilities

- `benchmark-time-budgets`: Benchmark timing, budgets and measured optimization.

### Modified Capabilities

None of the three synchronized main capabilities is replaced in this planning packet. Integration with active deltas is recorded explicitly below and in design.md; existing active approval scopes are not silently amended.

## Impact

release policy snapshots, run/task clocks, worker phase evidence, owner timing projection and read-only performance capture. Changing durations changes comparability and must use a new immutable admitted policy identity; no parallel legacy catalog product is required.

Owns timing measurement and future calibrated budget policy, not action recovery or prefetch implementation. BRL/BEF clocks remain authoritative until approved reconciliation; existing task-preparation-prefetch (TPP) owns all staging/activation/cleanup scenarios.

Dependencies: Measure only after BER serial correctness and preserved evidence. Numerical budgets and performance thresholds are an explicit later calibration approval gate, not invented defaults in this proposal.

