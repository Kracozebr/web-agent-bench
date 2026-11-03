## Why

Users need a way to check their own agents against goals they choose, rather than infer reliability from one run of the fixed benchmark suite. Repeating a task from equivalent starting conditions exposes whether the agent consistently reaches the requested state while staying within the user's spending, gas-price, and time limits.

## What Changes

- Add a private task authoring flow for supported sandbox operations. A task describes the requested state transition, its observable preconditions and target conditions, and hard execution limits.
- Let the user select an agent and a repetition count. Each repetition starts from an equivalent, reset sandbox state under the same pinned task, agent, policy, and environment versions.
- Report each run separately, including verified goal result, constraint violations, latency/cost, evidence status, and normalized action/final-state comparison.
- Show repeat success rate and determinism as separate measurements. A task receives the strict “passed every run” result only when every requested repetition is evaluable and no run contains a verified agent error. Platform or evidence uncertainty remains inconclusive and never counts as a pass.
- Keep these private user-authored trials outside the fixed official task catalog, public leaderboard, PvP, and settlement flows.

This is a candidate for further development **after the MVP**. It is not in the current MVP/PoC delivery sequence, is not scheduled for the current stage, and is not authorization to implement it now.

## Capabilities

### New Capabilities

- `user-authored-agent-task-lab`: Private authoring and repeated evaluation of bounded user-defined agent tasks in the supported local sandbox.

### Modified Capabilities

None. The proposal reuses existing benchmark identity, evidence, and environment-reset contracts; it does not change the official benchmark or PvP requirements.

## Impact

- A future owner-facing task builder, task-definition API, versioned task storage, and run-group/result views.
- The benchmark coordinator and local sandbox reset path, including enforcement of per-run and aggregate spend ceilings, gas-price ceilings, and time limits.
- The evaluator and result projection for per-run outcomes, strict all-repetitions pass status, pass rate, and separate outcome/action-trace determinism.
- Browser/API/PostgreSQL/worker/sandbox acceptance. No real-fund path, arbitrary user code, public task publishing, leaderboard qualification, PvP, or settlement changes are proposed.
