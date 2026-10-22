# Scenario map: `<change-name>`

Workflow: [`docs/task-design.md`](../../docs/task-design.md)

**Lifecycle phase:** `<active-delta | synced-main | archived>`  
**Normative source:** `<resolved spec path>`  
**Acceptance evidence:** `tests/bdd/acceptance-evidence.json`

| Requirement ID | Scenario ID | Mirrored title | Feature tag | Named mapper | Adapter | Gate | Mandatory | Harness contract | Evidence | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| `REQ-001` | `SC-001` | `<exact title>` | `@scn_<id>` | `test_<behavior>` | `<real boundary>` | `local` | yes | `<observations; negatives; effects>` | `<assertion or evidence path>` | `not_run` |

Gate values: `local`, `artifact`, `environment`. Result values: `not_run`, `passed`, `failed`,
`skipped`, `blocked`.

## Source transition

- [ ] While active, `Normative source` resolves to the change delta returned by OpenSpec status.
- [ ] After `/opsx:sync`, `Normative source` resolves to the main capability spec.
- [ ] OpenSpec scenario IDs and titles equal the Gherkin and named-mapper inventories.
- [ ] No executable reference remains to the active change path before archive.

