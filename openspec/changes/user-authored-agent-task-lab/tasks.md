## 1. Authoring and validation

- [ ] 1.1 Define the versioned task schema for agent instruction, supported initial state, target predicates, sandbox profile, and owner limits; add unit cases for unsupported fields and unobservable goals.
- [ ] 1.2 Add owner-scoped task create/read/update APIs and UI; edits create immutable revisions and the browser/API/PostgreSQL check proves private ownership and no run starts on save.

## 2. Bounded repeated execution

- [ ] 2.1 Bind each trial group to a task revision, agent/config metadata, policy, seed, environment manifest, and owner limits; enforce per-run and aggregate spend, gas-price, and execution-time ceilings against platform hard caps.
- [ ] 2.2 Execute N distinct runs through the worker and isolated local sandbox; verify reset equivalence and baseline hashes before each run, and block or mark failed resets inconclusive without reusing state.

## 3. Evaluation and owner results

- [ ] 3.1 Preserve every run result and implement the strict all-repetitions rule, explicit pass-rate denominators, verified agent-error attribution, and unknown/inconclusive propagation.
- [ ] 3.2 Add separate outcome, final-state, and normalized action-trace repeatability fields to the owner report; test that valid alternate paths can pass the goal while trace variation remains visible.

## 4. Acceptance and release boundary

- [ ] 4.1 Implement only the approved BDD scenarios and semantic contracts, then verify owner browser → API/PostgreSQL → worker → local sandbox effects with independent read-only observations.
- [ ] 4.2 Qualify reset, capacity, hard ceilings, evidence retention, and rollback before enabling private task creation; keep official benchmark, Ranked, PvP, and settlement state unchanged.
