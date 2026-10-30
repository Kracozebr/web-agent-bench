## Why

The measured current Full12 run spends 111.282 seconds on initial preparation and inter-task transitions out of 513.101 seconds. Preparing one isolated successor while the current task executes could hide part of the 100.386 seconds between tasks without removing grading, baseline verification or fencing.

Status: deferred planning, saved at the owner's request on 30 October 2026. Implementation and executable acceptance assertions are not approved by this request. See [research](../../../docs/task-preparation-optimization-research.md) and [approval boundary](approval.md).

## What Changes

- Introduce optional, bounded preparation of exactly one immediate successor in a different compatible environment; task issuance and execution remain sequential.
- Add a durable staged lifecycle with private future-task state, activation-only execution authority, capacity accounting, expiry and confirmed cleanup.
- Preserve admitted case/payment/environment pins, grading, original charge, active task identity, clock boundaries, cancellation and recovery behavior.
- Evaluate parallel independent read-only preflight checks and immutable hash-keyed metadata caching separately from speculative environment preparation.
- Compare latency, CPU, memory and verification quality against an unchanged serial baseline before enabling the feature.

Non-goals: parallel task execution for one run, a warm pool of all twelve tasks, reuse of participant-mutated state, skipped verification, benchmark price/weight/rubric changes, PvP changes, real-money settlement changes, or a promised beta/production capacity. Existing M3 preparation failure remains a separate prerequisite. This affects benchmark validity and isolation if implemented incorrectly; it does not change task success criteria or settlement.

## Capabilities

### New Capabilities

- `task-preparation-prefetch`: bounded isolated successor staging, private activation, cleanup and evidence-backed performance qualification.

### Modified Capabilities

None of the synchronized main capabilities are changed by this planning commit. Integration must preserve `benchmark-environment-feasibility` and reconcile the active `benchmark-run-lifecycle`, `benchmark-task-suite` and `beta-poc-delivery` contracts before implementation approval; this proposal does not edit or supersede their current artifacts.

## Impact

Expected implementation areas: owner coordinator/preparation/activation and cancellation services; BEF preparation/generation authority and environment leases; environment-specific case qualification; resource accounting and profiling. Public task order, current-task-only access and billing remain authoritative.

Planning artifacts only are delivered now: research, proposed spec, design, BDD packet and unchecked tasks. No migrations, runtime flags, tests, harness registry changes or deployment are included.
