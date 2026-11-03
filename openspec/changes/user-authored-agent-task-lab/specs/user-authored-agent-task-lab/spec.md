## ADDED Requirements

### Requirement: UATL-REQ-001 Author private, versioned, machine-checkable tasks

The system SHALL let an authenticated owner define a task instruction, supported sandbox profile, observable initial conditions, machine-checkable target conditions, and execution constraints. The system SHALL validate a task before launch, reject unsupported operations or predicates without starting a run, and SHALL NOT execute arbitrary author-provided code as task logic. Editing a task SHALL create a new immutable revision so existing trial groups retain their original task definition.

#### Scenario: UATL-SC-001 Save a supported state-transition task

- **WHEN** an owner defines a supported change from a declared starting state to a machine-checkable target state and saves it
- **THEN** the system SHALL store a new task revision bound to that owner and make it available only to that owner and an agent execution explicitly selected by the owner

#### Scenario: UATL-SC-002 Reject an unsupported task before launch

- **WHEN** an owner submits a task containing an unsupported operation, unobservable goal, or executable custom checker
- **THEN** the system SHALL reject the definition before creating a trial group or sandbox action and SHALL identify the unsupported field without exposing another owner's tasks

### Requirement: UATL-REQ-002 Enforce owner and platform execution limits

Each trial SHALL enforce the owner's per-run spend limit, trial-group aggregate spend limit, maximum transaction gas price, and execution-time limit together with stricter platform hard ceilings. These values SHALL be pinned to the trial group and repetitions. An action known to exceed a cap SHALL NOT be submitted to the sandbox. Missing or contradictory cost, gas-price, or timing evidence SHALL remain `unknown` and SHALL NOT be treated as compliant or as an agent error without attributable evidence.

#### Scenario: UATL-SC-003 A task cannot exceed a declared hard limit

- **WHEN** the agent requests an action whose declared spend or gas price exceeds the task limit, or the repetition reaches its execution deadline
- **THEN** the runner SHALL prevent further over-limit execution, retain the denied action and relevant evidence, and mark the repetition as a verified constraint failure only when the action and policy evidence are correlated

### Requirement: UATL-REQ-003 Repeat a task from equivalent isolated baselines

The owner SHALL be able to select a bounded repetition count supported by platform capacity. Each repetition SHALL have a unique run identity and SHALL use the same immutable task revision, pinned sandbox manifest, policy, seed, and declared agent configuration while starting from a separately reset or recreated equivalent baseline. The system SHALL verify baseline identity/equivalence before admitting each repetition. A reset or identity failure SHALL block or mark that repetition inconclusive; it SHALL NOT reuse contaminated state or be attributed to the agent.

#### Scenario: UATL-SC-004 Each repetition starts from the pinned baseline

- **WHEN** an owner starts a trial group with multiple repetitions
- **THEN** the runner SHALL record each run ID and repetition index, verify the expected baseline and environment hashes before each start, and preserve each run's events and evidence independently

### Requirement: UATL-REQ-004 Require every repetition for strict task credit

The trial group SHALL expose every repetition's outcome and the number passed, attempted, and evaluable. The strict `passed_every_run` result SHALL be awarded only when every requested repetition has a verified passing result and no verified rubric or constraint error. A single verified agent error SHALL prevent strict pass regardless of other successful repetitions. The system SHALL NOT select a best run or hide a failed repetition.

#### Scenario: UATL-SC-005 One failed repetition prevents strict pass

- **WHEN** two repetitions pass and one repetition contains a verified task or constraint error
- **THEN** the system SHALL report the individual results and denominator, show the measured pass rate, and withhold `passed_every_run`

### Requirement: UATL-REQ-005 Keep unknown trials inconclusive

If any repetition lacks a valid reset, required observation, attributable outcome, or trustworthy evidence, the system SHALL label that repetition and the group `unknown` or `inconclusive` as appropriate. Such a repetition SHALL NOT count as a pass or as an agent mistake, and SHALL prevent strict all-repetitions pass. The system SHALL preserve any separate verified failures in the same group.

#### Scenario: UATL-SC-006 A platform failure is not converted to an agent error or pass

- **WHEN** a repetition ends without sufficient evidence because of a sandbox, worker, provider, or observation failure
- **THEN** the system SHALL report the repetition as unknown/inconclusive, exclude it from verified agent-error attribution, and SHALL NOT award strict group pass

### Requirement: UATL-REQ-006 Report repeatability without collapsing measurements

The owner report SHALL keep task outcome, spend, gas price, execution time, constraint behavior, evidence quality, final-state consistency, and normalized action-trace consistency distinct. A verified valid action path SHALL satisfy the task even if it differs from another valid path; any difference SHALL be visible in trace-consistency reporting and SHALL NOT be silently converted into task failure. Repetition and read-only replay SHALL be identified separately, and original evidence SHALL NOT be overwritten.

#### Scenario: UATL-SC-007 Valid alternate action paths remain distinguishable from task failure

- **WHEN** two repetitions reach the same verified target state through different valid normalized action traces
- **THEN** both repetitions SHALL retain their goal result, while final-state and trace consistency are reported separately and the original evidence remains available
