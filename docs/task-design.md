# Designing behavior-changing tasks

Use this workflow for changes that alter benchmark semantics, agent execution boundaries, score
interpretation, evidence, match behavior, or settlement:

`/opsx:explore` (optional) -> `/opsx:propose` -> approval -> `/opsx:apply` -> mandatory BDD gates ->
`/opsx:sync` -> `/opsx:archive`

Do not impose it on behavior-preserving refactors, chores, or documentation-only changes unless the
user explicitly asks for BDD.

## Bootstrap

Before the first BDD task, follow [`bootstrap.md`](bootstrap.md) if OpenSpec is unavailable, the
repository is not initialized, or the project interpreter cannot import `pytest_bdd`. A healthy
setup proceeds directly to explore or propose without reinstalling.

## Contract

- The active OpenSpec delta is normative while a change is active. After sync, the main capability
  spec is normative. Gherkin is an executable mirror, not a second source of truth.
- Every scenario has stable requirement and scenario IDs, one named mapper, an adapter, a gate class,
  a mandatory flag, and defined evidence.
- Reviewed boundary scenarios have a checked-in semantic harness contract declaring boundary,
  negative/adversarial variants, durable effects, and named observations.
- A local reference model does not prove a sandbox, chain, artifact, or external environment gate.
- Valid results are `not_run`, `passed`, `failed`, `skipped`, and `blocked`. A skipped or blocked
  mandatory gate prevents sync and archive.
- Approval authorizes only the listed tests and implementation scope. A new scenario or changed
  assertion requires renewed approval.

## Explore

`/opsx:explore` is read-only. Inspect the actual architecture, current adapters, evidence, and
environment constraints. Do not create tests or implementation. End with remaining decisions and
the exact next `/opsx:*` command.

## Propose and approve

`/opsx:propose <change>` creates proposal, design, specs, and tasks. Add a BDD design packet using
[`templates/bdd/design-packet.md`](../templates/bdd/design-packet.md). For each scenario, name the
real boundary, observations, adversarial variants, durable effects, and evidence. Stop for explicit
approval before editing executable tests or product code.

## Apply

After approval, add the Gherkin mirror, named mapper, reusable step bindings, and real adapter before
or alongside production changes. Do not replace a missing chain or agent environment with a false
proxy. Report implementation and acceptance separately.

## Sync and archive

Run `/opsx:sync` only when tasks and mandatory gates pass. Preserve unaffected main-spec content,
validate the merged specs, and rerun traceability. Use
[`templates/bdd/closeout-checklist.md`](../templates/bdd/closeout-checklist.md) before archive; do
not archive while an executable reference still points to an active change path.

## Reference profile

With OpenSpec, Gherkin, and `pytest-bdd`:

- mirror IDs and titles from normative specs;
- keep Given/When/Then bindings reusable and put system-specific work in adapters;
- fail when OpenSpec, Gherkin, mapper, registry, or contract inventories drift;
- run the semantic harness audit before pytest; and
- keep evidence shaped like [`templates/bdd/evidence.example.json`](../templates/bdd/evidence.example.json).

