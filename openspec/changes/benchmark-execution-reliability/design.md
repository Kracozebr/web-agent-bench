## Context

Proposed 2026-10-30 from the owner-approved direction and local inspection. The participant Training run left an admitted H1 payment pending at task cutoff; the Ranked run rejected all valid swaps through a recursive eight-element MCP limit and stopped before H2/H3/U1. These are validity and recovery issues, not evidence that the participant agent failed every task. Implementation and listed assertions were approved on 2026-10-31; evidence status changes only after actual verification.

## Goals / Non-Goals

**Goals:** Make every declared bounded action and finish-answer shape representable through MCP, with useful schemas and safe errors. Reconcile every admitted action at cutoff without resubmitting an ambiguous payment; finish tasks with an explicit known or unknown result. Diagnose the two H1 failures and the earlier pre-M3 successor-preparation failure using original source-bound evidence. Complete the four missing catalog negative controls and independent restart/replay tails; preserve existing financial and fence contracts.

**Non-Goals:** New task goals, weights, pricing/refund policy, hosted solvers, parallel task execution, new publication eligibility, timing recalibration, prefetch implementation, PvP or real-money settlement. All original beta target-host, Google, bonus, source-bound restore/recovery and native-client gates remain. No new code, Gherkin, mappers, registry entries, runtime profile or real-money actions are delivered by this draft.

## Decisions

### Execution and evidence

Use the existing immutable operation/action/cutoff journals. The action worker must drain admitted work through the cutoff even after new-action admission closes; dispatch authorization still rechecks identity, grant, mode, generation and lease. A dispatched response loss is an observation/recovery operation, never permission to send another payment. Pre-dispatch denial requires proof of non-execution. A bounded dispatch/reconciliation policy must name its persisted timeout and recovery authority before assertions are installed; reuse existing qualified policy bounds where applicable.

The eight-element bug is confirmed by the installed SDK recursively counting object keys: request wrapper has four keys, minimum swap command seven, total eleven. Select finite byte/depth/collection limits from the actual allowed schema maxima (including S2 authFields), not an arbitrary global key count. Preserve boundedness and rejection before side effects.

H1 requires two separate investigations: Training action 48723f89-9b3b-4137-bf23-3b2a1fee7b33 is admitted/pending with cutoff 8/reconciled 7; Ranked task index 8 has observed actions, closed cutoff and candidate_evaluation_unknown but no durable grade. These states prove incompleteness, not the underlying cause or any on-chain effect of the pending action. Preserve originals; fault injection and repair qualification use fresh isolated runs.

### Existing gates carried forward

BER-SC-006 augments producer/replay evidence for BTS-SC-001/002; do not add substitute catalog scenario IDs to the executable registry or rename those four variants. BER-SC-005/007 close the pre-M3 failure/restart tail under current BRL/BTS/BPC proof chains. Run independent replay on a frozen source before calling a fresh successful producer capture accepted. Preserve original evidence files, path/hash bindings, private screenshots and backup/restore coverage. Existing BPC recovery/restore/flood/bonus matrices remain required and are not reset to passed by this packet.

Crash recovery and independent artifact replay have different write authority. A recovering worker may complete the first legitimate pending grade/completion/refund under existing idempotency and proof rules; it cannot duplicate an already committed effect. Independent replay performs no business writes at all. BER-SC-007 observes these separately, including a crash before the first owed refund commits.

### Cross-change authority

Owns correctness of existing execution and evidence contracts. Integrates active benchmark-run-lifecycle (BRL), benchmark-task-suite (BTS), beta-poc-delivery (BPC) and benchmark-environment-feasibility (BEF); does not redefine their score or refund policies.

First implementation stream. Cabinet errors consume its safe classifications; time-budget calibration and prefetch qualification require its successful serial baseline.

The [integration index](../../../docs/beta-usability-spec-plan.md) lists active-delta overlap and the approval-time reconciliation. These new drafts do not supersede approved active requirements merely because they are newer. Before implementation, record exact affected legacy requirement/scenario mappings and approve coherent amendments to those active deltas; keep IDs and prior evidence history. No sync/archive is authorized here.

### Evidence and replay

Every scenario uses its real boundary in [bdd-harness-proposal.json](bdd-harness-proposal.json), with named observations, negative variants and durable effects. Runtime evidence carries frozen source/build/profile, sanitized principal/run/operation identifiers, authoritative event order, raw artifact paths and hashes, and independent observer identity. User journeys start through actual browser controls, follow running API/worker and persist in PostgreSQL; independently inspect final database/BEF/filesystem effects. Installer scenarios require actual native configuration and model client boundaries, not browser mocks. Private setup/fault injection and read-only inspection are permitted only for their named roles. Never retain credentials, sensitive provider data or raw personal identities in checked-in evidence.

Replays are read-only and never repeat economic commands. A missing external client, host, observer or unexecuted negative is `blocked` or `not_run`, not a green reference-model substitute. Planning validation checks structure, not runtime acceptance.

## Risks / Trade-offs

- Active-delta overlap can create two authorities: use the integration index and approval-time reconciliation before any apply.
- Local success can hide target/client gaps: retain separate per-edition and target-host mandatory gates.
- Readable UX can overstate certainty: display only durable known facts and preserve unknown attribution.
- New adapters can expose secrets: use secret references, protected stores and synthetic canaries, with no raw secret evidence.

## Migration Plan

1. Review this packet and all cross-change mappings; obtain explicit scenario/assertion and implementation approval.
2. Add only approved mirrors, mappers and real adapters in a later apply; keep all current runtime gates unchanged until rerun.
3. Prepare compatible migrations/config changes with an existing unified pre-migration backup of bonuses, results, reports, screenshots and evidence. Rehearse restore with writes disabled, original identities and retries preserved.
4. Qualify locally on frozen source, independently replay, then repeat required target/client gates before release. Missing host/domain or client access blocks that gate, not documentation work.
5. Roll back via disabled feature/profile and scoped configuration restoration without erasing journals, original evidence, account/ledger/report data or unobserved effects. Preserve outstanding fences/holds and revoked credentials on restore.
6. Sync/archive only after approved mandatory gates pass under docs/task-design.md; this planning work performs neither.

## Open Questions

No unresolved product choice is inferred. Agreed decisions are recorded in approval.md. Technical prerequisites and later calibration/security profile choices are explicitly gated in the decisions/tasks; if inspection proves a required client cannot support safe automatic setup, return that concrete limitation for a scope decision instead of silently dropping it.

