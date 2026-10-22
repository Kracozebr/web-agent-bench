# Agent prompts for the OpenSpec BDD lifecycle

Replace angle-bracket placeholders before use.

## Bootstrap

```text
Bootstrap this repository for the OpenSpec BDD workflow using docs/bootstrap.md. Audit Node,
OpenSpec, Python, dependency-manager, and Git state first. Show exact global and repository-local
changes and wait for one approval before installing. Preserve AGENTS.md. Do not create scenarios or
tests during bootstrap.
```

## Explore

```text
/opsx:explore <change-or-idea>

Explore this benchmark/PvP behavior read-only. Inspect actual adapters, evidence, and environment
constraints. Do not create tests or implementation. End with remaining decisions and the exact next
command if the idea is ready for proposal.
```

## Propose and review

```text
/opsx:propose <change-name>

Create the OpenSpec artifacts and BDD design packet. Give each normative scenario stable IDs and map
it to Gherkin, a named mapper, a real boundary adapter, gate class, mandatory status, semantic
contract, and evidence. Stop for explicit approval before implementation.
```

## Apply after approval

```text
/opsx:apply <change-name>

Implement only the approved design packet. Add mirrors, mappings, adapters, and executable checks.
Do not treat a reference model as chain or production evidence. If behavior or test design changes,
pause and return it for approval. Report implementation and acceptance separately.
```

## Sync and archive

```text
/opsx:sync <change-name>

Only after tasks and mandatory gates pass, merge the delta into main specs, preserve unaffected
content, validate, and rerun traceability.

/opsx:archive <change-name>

Use the closeout checklist. Archive only after mandatory acceptance, sync, and main-spec checks pass.
```

