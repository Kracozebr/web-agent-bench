# OpenSpec BDD closeout: `<change-name>`

Workflow: [`docs/task-design.md`](../../docs/task-design.md)

## Apply and acceptance

- [ ] OpenSpec reports every required artifact complete.
- [ ] Every implementation task is checked only after its acceptance condition is satisfied.
- [ ] Every mandatory local, artifact, and environment gate passed.
- [ ] No mandatory gate is `not_run`, `failed`, `skipped`, or `blocked`.
- [ ] The semantic harness audit passed before pytest.
- [ ] Every protected scenario recorded all observations from its harness contract.
- [ ] Acceptance evidence is complete and records Git commit, main-spec SHA-256, harness-contract
      SHA-256, harness-source SHA-256, and passing mandatory results.

## Sync

- [ ] `/opsx:sync <change-name>` merged every delta into main specs, or the change has no delta specs.
- [ ] Existing main-spec content outside the delta is preserved.
- [ ] Main-spec validation and generated mirror checks pass.
- [ ] OpenSpec, Gherkin, and named-mapper IDs and titles match.
- [ ] Rerunning sync would make no further changes.

## Archive

- [ ] `/opsx:archive <change-name>` completed.
- [ ] The change is absent from the active list and the dated archive exists.
- [ ] Main-spec and BDD checks still pass after the move.
- [ ] The handoff reports the archive path and final gate results.

