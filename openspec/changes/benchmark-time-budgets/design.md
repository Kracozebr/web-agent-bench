## Context

Proposed 2026-10-30 from the owner-approved direction and local inspection. The inspected participant runs assigned 60 seconds to every task, while waiting for unresolved processing inflated wall time. Timing must separate platform preparation, participant execution and grading before task difficulty budgets or speed claims can be trusted. Implementation and listed assertions were approved on 2026-10-31; evidence status changes only after actual verification.

## Goals / Non-Goals

**Goals:** Record independently replayable phase timing, including queue, preparation, issuance, admitted-action drain, grading, recovery and finalization. Calibrate finite task-specific budgets by complexity on a fixed profile; pin all admitted timer policy values and keep overall/queue/recovery clocks distinct. Show task-by-task progress and timing without converting a platform outage into an agent score failure. Keep one-successor preparation in the existing deferred task-preparation-prefetch proposal; require resource A/B measurements and isolation gates before enablement.

**Non-Goals:** Unapproved numeric runtime budgets, score/price changes, a second recovery authority, successor prefetch implementation or mandatory prefetch acceptance, parallel task execution and unsupported capacity guarantees. All original beta target-host, Google, bonus, source-bound restore/recovery and native-client gates remain. No new code, Gherkin, mappers, registry entries, runtime profile or real-money actions are delivered by this draft.

## Decisions

### Phase model and clock authority

Capture queue; initial ready preparation; task issue-to-cutoff elapsed; admitted-action drain; observation/grading; successor readiness wait; bounded platform recovery; finalization. Use authoritative persisted events and monotonic duration capture when available with clock-source/resolution metadata. A task's elapsed interval includes native-client thinking and tool roundtrips; without client instrumentation label it participant-task elapsed, not pure model compute. Record tool/worker waits separately only where causal timestamps exist. Wall-time sum must use disjoint intervals; parallel suboperations require an overlap map and never add their elapsed times twice.

Preserve current BRL exclusion of queue/preparation from execution budget and all original admission timestamps. Do not subtract ordinary client disconnect, polling or model delay. Task cutoff stops new actions, not reconciliation. Grade/recovery clocks are finite and separately pinned; later platform recovery can continue after task time without reopening the task. Actual total wall time includes all waiting even where budget accounting excludes preparation. BER owns resolution/fencing/compensation; BTB only classifies clock intervals and prevents silent uniform fallback.

Preserve the existing BRL-REQ-008/BPC-REQ-009 exclusion of recorded proven-platform recovery intervals from execution clocks, including once-only authoritative clock adjustments. Recovery wall time remains bounded and visible in actual total duration. No unproven failure report or repeated recovery event can extend clocks. Original deadline identity means original policy plus only these authorized recorded adjustments, not a prohibition on existing recovery accounting.

### Calibration and activation barrier

Uniform 60 seconds is an observed implementation limitation, not the future difficulty policy. Collect real-client per-task distributions after BER repairs plus a successful complete serial baseline; record source, model, client edition/version, host, configuration, sample count and uncertainty. Select finite explicit seconds for all twelve tasks, overall rule and drain/preparation/recovery bounds in a follow-up numerical policy table. Approval of this planning packet can authorize measurement infrastructure, not arbitrary runtime durations: freeze the table, tests and fairness/comparability consequences for owner approval before activating a new policy. Until then keep all active policies unchanged. This is a technical calibration gate, not an open product preference.

Activation/admission serialize on policy identity. New runs pin a new immutable policy/release identity; no requirement for parallel legacy catalogs or historical local-test migration is added. Do not delete old user data as part of timing work. Existing admitted runs retain original timers and price. The 24-hour pre-start queue timeout and source-preserving bonus/cash accounting remain unchanged.

### Resource and optimization boundary

Existing research reports a successful serial Full12 wall duration 513.101 seconds and preparation/transition 111.282 seconds, but those historical values are not target capacity acceptance. The suggested 60–90 second saving is an estimate, not a measured result. Original limited S1/S4 preparation probes are inadequate for cold/warm, process attribution, full load or multi-environment capacity.

TPP remains the sole owner of staged preparation/activation/privacy/cleanup. Do not implement prefetch in this change. A later TPP qualification must freeze CPU/memory/cgroup limits, cache state, sampling resolution, simultaneous peak memory and source/case controls; record raw CPU core-seconds, wall duration, RSS/container memory, disk/RPC and grade invariants. Report independent serial/preflight-cache/prefetch A/B results and negative benefit honestly; approve performance thresholds before enablement. No 4-vCPU/8-GiB recommendation is established by these drafts.

BTB-SC-006 itself requires only the serial resource baseline, honest sampling limits, a reviewed future comparison protocol and proof prefetch remains disabled. Actual candidate A/B execution and passing TPP gates are outside BTB acceptance, so deferred TPP cannot block closing an otherwise accepted timing/measurement packet.

### Cross-change authority

Owns timing measurement and future calibrated budget policy, not action recovery or prefetch implementation. BRL/BEF clocks remain authoritative until approved reconciliation; existing task-preparation-prefetch (TPP) owns all staging/activation/cleanup scenarios.

Measure only after BER serial correctness and preserved evidence. Numerical budgets and performance thresholds are an explicit later calibration approval gate, not invented defaults in this proposal.

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

