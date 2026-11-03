## Context

The official benchmark uses a fixed, versioned task suite and has separate evidence, replay, and sandbox-reset contracts. This post-MVP proposal adds a private lab for owners who want to test their own agents against goals they define. The first version is limited to state changes and observations already supported by the local sandbox; it does not add an arbitrary-code task runner.

The real boundary is owner browser → owner API/PostgreSQL → coordinator/worker → isolated local sandbox. A reference model may test grading logic, but it cannot prove that the browser-created task ran or that the sandbox enforced its limits.

## Goals / Non-Goals

**Goals:**

- Let an owner describe a supported “from state X to state Y” task with machine-checkable preconditions and goal conditions.
- Allow selection of a connected agent, repetition count, maximum spend, gas-price ceiling, and execution-time limit.
- Run each repetition from an independently reset, equivalent sandbox baseline and retain its own identity and evidence.
- Show individual outcomes, pass rate, strict all-repetitions pass/fail, constraint violations, and repeatability measurements.

**Non-Goals:**

- Changing the fixed official task suite, Ranked results, public leaderboard, PvP, or settlement.
- Publishing or sharing user-authored tasks, arbitrary user code/contracts, mainnet execution, or real-fund operations.
- Selecting the best run, hiding failures, or treating missing evidence as a pass or an agent error.

## Decisions

1. **Use a bounded, declarative task definition.** Store the owner instruction together with a supported sandbox profile, observable initial conditions, target predicates, and hard constraints. Validate it before creating any run. A changed task creates a new immutable revision and hash; old trial groups keep their original revision.

2. **Let user limits tighten platform limits.** Capture per-run and trial-group spend caps, maximum transaction gas price, and execution timeout. Enforce platform-wide ceilings as well as the user's limits in the sandbox. Reject an action before execution when its known parameters would exceed a cap. Attribute a violation to the agent only when the admitted-action and effect evidence supports that conclusion; otherwise keep the result unknown.

3. **Model repetitions as independent runs, not replay.** A trial group pins task revision/hash, agent identity/version and available configuration metadata, policy, environment manifest, seed, and baseline hash. Each repetition has a distinct run ID and starts only after reset/recreation verifies an equivalent baseline. If reset or identity verification fails, block or mark the affected repetition inconclusive; do not reuse prior state or call it an agent mistake. Replays remain read-only reconstructions and are labelled separately.

4. **Make the strict result literal.** The group is `passed_every_run` only when all requested repetitions have verified passing outcomes and no rubric or constraint error. One verified agent error makes the strict result not passed even if the other repetitions succeed. Any unknown repetition prevents a strict pass. Show passed/attempted/evaluable counts so a rate never hides its denominator; do not pick a best run.

5. **Report outcome consistency separately from action-trace consistency.** Compare goal results, canonical final-state digests, and normalized action traces as separate fields. Different valid action paths may satisfy the task; they can lower trace consistency without turning a valid run into a task failure. Any trace normalization must be versioned and evidence-linked.

6. **Preserve owner scope and provenance.** Each run retains the task-group ID, repetition index, task revision, agent/config identity available from the client, environment and baseline hashes, policy/seed, event cutoff, result, and raw evidence references/hashes. User tasks and results are private to their owner and the selected agent execution; they do not enter official benchmark scorecards or public leaderboard data.

## Risks / Trade-offs

- **A vague goal cannot be graded consistently** → require supported, machine-checkable target predicates and reject unsupported definitions before launch.
- **Repeats consume sandbox time and test funds** → enforce per-run and aggregate caps and derive platform maxima from measured capacity before release.
- **A failed reset can contaminate later repeats** → require fresh environment identity and observed baseline equivalence for every repetition.
- **Provider or platform faults can look like agent errors** → preserve `unknown`/`inconclusive` and require attributable evidence before assigning an error.
- **Exact trace equality can punish valid alternate strategies** → report trace consistency separately from goal and final-state consistency.
- **The external agent/model may change during the group** → pin the agent version and configuration when supplied; otherwise label comparisons as not fully controlled.

## Migration Plan

No data or runtime migration is part of this planning change. After MVP completion and separate owner approval, implement the private task and trial-group records alongside the existing fixed benchmark. Start in the local sandbox with a narrow supported-operation profile, then enable the browser-created environment acceptance path. Rollback disables new task creation and starts while retaining historical trial evidence read-only.

## Open Questions

- Which sandbox operations and state fields belong in the first supported task builder?
- Should a harmless failed tool call count as a mistake, or only a rubric/constraint violation with verified evidence?
- What are the measured upper bounds for repetitions, spend, gas price, and execution time?
- Which agent/model/configuration fields can each supported client provide and keep stable across repetitions?
- Should a first release execute repetitions sequentially only, or allow bounded parallel runs after reset isolation is proven?
