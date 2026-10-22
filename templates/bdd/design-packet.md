# BDD design packet: `<change-name>`

Workflow: [`docs/task-design.md`](../../docs/task-design.md)

**Status:** Awaiting approval  
**Normative delta source:** `<resolved delta-spec path>`  
**Target main source after sync:** `<resolved main-spec path>`

## Intent

**Goal:** `<observable behavior to add or correct>`

**Non-goals:**

- `<explicitly excluded behavior>`

## Scenario design

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
|---|---|---|---|---|---|---|---|---|---|---|
| `<req>` | `<scn>` | `<domain title>` | `<precondition> / <action> / <observable result>` | `local` | yes | `test_<behavior>` | `<real boundary>` | `<observations; negatives; effects>` | `<assertions or evidence file>` | `<requirement protected>` |

Allowed gates: `local`, `artifact`, `environment`. Mark a gate optional only when its omission
cannot weaken the approved behavior or release decision.

## Semantic harness contract

For every reviewed boundary scenario, declare the machine-readable contract in
`tests/bdd/harness-contracts.json`: boundary, required named observations, negative/adversarial
variants, durable effects, evidence mode, and any narrow private-call exception. An inventory check
alone is not semantic coverage; the adapter must record every required observation during verification.

## Execution design

- Existing checks to reuse: `<paths or commands>`
- New step bindings or adapters: `<minimal additions>`
- External prerequisites: `<environment, artifact, credentials, or none>`
- Expected unavailable-gate behavior: `<skipped or blocked, with reason>`

## Approval boundary

Approval authorizes only the scenarios, tests, adapters, and production scope listed above. Any new
scenario or changed assertion returns this packet to review.

**Decision:** `<approved | revisions requested>`  
**Decision reference:** `<task message, issue, or review record>`

