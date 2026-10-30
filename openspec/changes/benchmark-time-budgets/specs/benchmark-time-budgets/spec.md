# Benchmark timing, budgets and measured optimization

Status: approved for implementation on 2026-10-31. Runtime for all 6 scenarios: `not_run`. [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: BTB-REQ-001 Measure separate non-overlapping timing phases
Timing evidence SHALL retain authoritative start/end events for queue, initial preparation, each task issue-to-cutoff interval, admitted-action drain, grading, successor wait, recovery and finalization. Agent-tool waiting inside an active task SHALL remain separately attributable, not silently subtracted. Wall-time decomposition SHALL use disjoint intervals or an explicit overlap map and preserve unobserved intervals as unknown.

#### Scenario: BTB-SC-001 Measure separate non-overlapping timing phases
- **GIVEN** Frozen serial Training3/Full12 with independent worker/database observers
- **WHEN** normal, stalled, cancelled and interrupted runs are measured and replayed
- **THEN** per-task and whole-run durations SHALL reconcile with authoritative wall time within declared capture resolution, without double counting or calling platform waiting pure model latency

### Requirement: BTB-REQ-002 Calibrate task budgets before choosing numeric defaults
A finite budget policy SHALL specify each task's duration by measured workload/complexity, including distinctions among simple, medium, hard and ultra when supported. The exact seconds and total limit SHALL be frozen only after source-bound serial measurements, reviewed explicit values and renewed assertion approval. No runtime fallback to a uniform 60 seconds or silently invented durations is permitted for the new policy.

#### Scenario: BTB-SC-002 Calibrate task budgets before choosing numeric defaults
- **GIVEN** Repaired serial runtime and all required actual-client access
- **WHEN** a fixed benchmark/profile cohort measures per-task execution, tool waits and platform phase overhead then proposes budgets
- **THEN** the report SHALL publish sample count, spread, client/model/source/hardware identity and fairness limitations; insufficient samples or absent clients SHALL remain blocked and a concrete table SHALL require approval before activation

### Requirement: BTB-REQ-003 Pin clocks at admission and survive restart
Each newly admitted run under the approved policy SHALL snapshot task budgets, overall duration rule and preparation/recovery bounds with a validated immutable policy/release identity. Queue expiry remains 24 hours. Task timing SHALL begin only after ready issuance/activation, and client reconnect/retry SHALL not reset it. Existing runs SHALL retain their original snapshots. Execution clock accounting SHALL continue to exclude recorded proven-platform recovery intervals under BRL-REQ-008/BPC-REQ-009, with no subtraction from actual wall-time reporting.

#### Scenario: BTB-SC-003 Pin clocks at admission and survive restart
- **GIVEN** Two policy revisions and queued/running runs admitted on opposite sides of activation
- **WHEN** activation races admission, worker restart or repeated ready/start events at before/at/after deadline
- **THEN** each run SHALL use exactly one policy, preserve original start and authorized deadline adjustments and integer price, reject unknown policy inputs, exclude queue/preparation and recorded proven-platform recovery intervals under the existing policy, and never reset time for ordinary disconnect

### Requirement: BTB-REQ-004 Apply deadlines without abandoning cutoff or recovery
A task budget expiring SHALL close new admission once and preserve all previously admitted actions, finite drain/observation recovery and existing platform failure compensation authority. Overall run, queue, preparation, action drain and recovery deadlines SHALL remain distinct and replayable. Unissued tasks SHALL not become agent failures.

#### Scenario: BTB-SC-004 Apply deadlines without abandoning cutoff or recovery
- **GIVEN** H1 action admitted just before cutoff and other tasks requiring grading
- **WHEN** task and overall deadlines race dispatch, grading, recovery, cancel or successor readiness
- **THEN** committed order SHALL choose one valid closure/recovery/terminal path; no late new action, lost pending receipt, invented zero or leaked active/staged generation SHALL result

### Requirement: BTB-REQ-005 Show task timing and progress without misleading completion claims
The owner run view SHALL show current stage, task-level budget/elapsed time, actual phase breakdown and final measured wall duration where observed. Estimates SHALL be labeled separately and waiting for queue/preparation/observation SHALL not be presented as agent reasoning. Ranked visibility SHALL not disclose future case content.

#### Scenario: BTB-SC-005 Show task timing and progress without misleading completion claims
- **GIVEN** Live and terminal Training/Ranked runs with phase evidence and unknown gaps
- **WHEN** the owner opens progress and per-task details while events arrive late, browser reconnects or a run stalls
- **THEN** displayed intervals SHALL match durable timing policy/events, unknowns SHALL remain explicit and skipped/unissued tasks SHALL not show fabricated durations or failed score

### Requirement: BTB-REQ-006 Measure a serial resource baseline without requiring deferred prefetch
BTB SHALL capture a reproducible serial Training3/Full12 phase and resource baseline with raw CPU core-seconds, simultaneous memory, IO and RPC observations, sample resolution and evidence gaps. BTB SHALL define a future paired comparison protocol referencing existing TPP-SC-001–008, but its own acceptance SHALL NOT require prefetch implementation, actual serial/prefetch A/B or passing TPP gates. Prefetch remains disabled until its separate approved implementation and qualification; no saving or capacity guarantee SHALL be inferred from a baseline or old limited probes.

#### Scenario: BTB-SC-006 Measure a serial resource baseline without requiring deferred prefetch
- **GIVEN** BER repaired serial Training3/Full12 and frozen source, target hardware, resource limits and cache profile with deferred TPP
- **WHEN** operators capture serial phase/resource samples under normal and pressure variants, inspect the disabled prefetch state and review the future comparison protocol
- **THEN** the report SHALL bind raw serial CPU/memory/IO/RPC data to task phases, publish sampling/attribution limits and unknown gaps, state that no prefetch benefit is measured and preserve disabled prefetch; future candidate A/B and isolation acceptance SHALL remain owned by TPP

