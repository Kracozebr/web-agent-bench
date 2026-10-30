## Context

Deferred proposal, not implemented or approved for implementation. The [research](../../../docs/task-preparation-optimization-research.md) retains measured baselines, local probe results, sampling limits and raw paths/hashes. Full12 inter-task gaps total 100.386 seconds; no optimized run exists.

Current successor preparation validates a known predecessor and its sealed evaluation/bundle/fence before allocating an environment. BEF reset and funding hold a per-environment lock. A/B have different payment facilitators; cases cannot be moved between them by changing a URL. The owner coordinator uses a non-overlapping maintenance tick. This design must integrate with the active BRL/BTS/BPC contracts without weakening their task, billing, timing or queue assertions.

## Goals / Non-Goals

**Goals:** overlap one successor preparation with current-task execution, retain all independent verification, bound additional resources, and prove both speed and verification equivalence on a declared profile.

**Non-Goals:** multiple executing tasks for a run, speculative agent actions, all-case warm pools, chain-state reuse without verification, automatic retrial of ambiguous effects, local LLM hosting, changed scores/prices/refunds or beta-capacity claims.

## Decisions

### Separate staging from activation

Proposed internal states are `staging -> ready-private -> activated`, with `expired/failed/unknown -> fence-pending -> fenced` cleanup paths. Names are design vocabulary, not existing schema or public API. Persist the original run/claim, exact next index, admitted release/case/profile, environment/generation, stage operation, lease, expiry and evidence hashes. Use one durable stage identity with idempotent delivery. Keep the current execution slot unchanged; account for a distinct bounded preparation reservation.

The stage path can prepare the immediate successor while its predecessor is active; it cannot use the ordinary start API or bypass it. Atomic activation still verifies the predecessor's exact known evaluation, closure/cutoff/reconciliation, sealed evidence, terminal event and confirmed fence. A known ordinary failed task can advance; an unknown predecessor cannot. Recheck run status, access generation, permission revision, cancellation and stage validity under the appropriate locks. A prefetch flag never authorizes two active task rows.

### Use distinct compatible environments

Hold separate environment leases and isolate mutable chain state, caches, generation tokens and facilitator state. Read-only pinned upstream data can be shared under bounded resource admission. Qualify each case's immutable payment tuple and execution profile for its chosen environment before admission; existing A-pinned cases cannot silently become B-pinned cases. Treat missing compatible capacity as a serial-fallback decision, not permission to reset A or alter case hashes.

A hidden token is not sufficient isolation: staged BEF generations must reject participant effects until an activation authority is committed. Agent current-task APIs must not reveal future task data or credentials. The design review must specify the BEF/owner activation handshake, including lost acknowledgements; a partial commit remains non-executable/unknown until reconciled. No premature participant capability can be published to resolve a race.

### Keep lifetimes and clocks distinct

Persist finite standby limits and a profile defining bounded active-generation lifetime. Current diagnostic funding sets a 120-second lifetime during preparation; blindly spending that lifetime while the predecessor runs could leave too little time for the next task. At valid activation, establish the declared active-generation expiry exactly once under the qualified policy; an expired or fenced stage cannot be revived. Do not silently extend existing generation limits or reuse expired secrets.

Task execution starts at activation, not stage creation. The accepted-run pre-start deadline remains 24 hours where the beta profile applies. The 180-second local successor policy and bounded recovery clock stay distinct. Exclude only the actual post-predecessor waiting interval from the overall execution clock, once; never add back speculative preparation time that overlapped execution. Staging does not create another run fee, hold, owner bonus grant or charge.

### Bound contention and fail safely

Initial candidate is one immediate standby per active run, subject to a separate globally bounded preparation budget; the beta's one active global execution slot remains unchanged. Numeric standby TTL/global budget and fairness policy must be reviewed and pinned before execution. Stop scheduling new standby work under pressure; retain serial execution when compatible capacity is unavailable and the existing run policy permits it. Do not charge again or reset the current task on speculative failure.

Cancellation/revoke cleans both current and staged generations through their exact evidence-backed fences. Cleanup uncertainty retains the corresponding lease/reservation and blocks reuse. On restart, lost in-memory credentials are not restored from logs or resent through a new economic PUT: reconcile public facts and fence an unusable stage before replacement. Source timeouts, contradictory baseline evidence or lost setup replies stay unknown.

### Keep independent preflight optimization separable

Evaluate concurrency of independent read-only health/source/local checks, retaining all validation results and bounded upstream limits. Existing RPC batching is preserved. Immutable release metadata can be cached by complete content/policy/source identity with invalidation on activation or corruption. Live permissions, receipts, generation identity and mutable baseline state cannot be replaced by cached success.

### Evidence, measurement and replay

Boundary: actual owner/web/API/PostgreSQL coordinator plus two BEF environments, real local EVM reset/funding, private evidence store and independent read-only DB/RPC observers. Every capture binds source/build/case/policy identities, stage/activation/fence operations, authoritative event order, environment/generation leases and raw-file hashes. Secrets remain private; no token/hash-of-token or key material in evidence.

Use unchanged serial and proposed-prefetch profiles with matching case/rubric/seed/source/model/client declarations and controlled resource/cache conditions. Report wall time, each phase, sampling cadence, CPU delta, simultaneous sampled memory, throttling, RPC/storage load and interrupted/unknown runs separately. Compare deterministic platform/evidence behavior first; independently label actual model runs and their naturally variable outcomes. One S1/S4 serial measurement is not a two-environment or twelve-case acceptance result.

Replay derives required positive and negative observations from raw effects rather than trusting producer labels. Missing data is `blocked`/`not_run`, contradicting assertions are `failed`; retain original failed/partial attempts. The 60–90-second Full12 saving and 4 vCPU/8 GiB experiment budget are hypotheses, not acceptance thresholds. Freeze measurable regression/benefit bounds before the performance trial.

## Risks / Trade-offs

- Resetting a live fork -> require a distinct compatible lease and prove current-generation state/evidence unaffected.
- Standby consumes the environment another queued run could use -> separate global budget, fairness/backpressure and serial fallback.
- Extra work increases RPC/DB/storage contention -> measure simultaneous execution/preparation; do not infer capacity from low serial CPU.
- Future-task disclosure or usable early token -> enforce private stage authority at both owner and BEF boundaries.
- Expired stage or two-worker activation race -> immutable stage identity, finite lifetime, atomic current-task publication and reconciliation.
- Existing M3 preparation failure obscures performance -> diagnose and obtain a serial Full12 baseline before prefetch qualification.

## Migration Plan

After separate approval, add disabled-by-default additive state and profile support, then qualify compatible environments and run the proposed gates. Old admitted runs retain their serial policy. Enable only for newly admitted runs with an explicit qualified profile. Rollback stops new staging, fences existing standby reservations, and preserves active task/charge/result identities; it must not orphan a generation or silently retarget an admitted run. No migration or rollout occurs in this planning change.

## Open Questions

Resolve during design review: compatible A/B payment profiles and immutable case strategy; exact owner/BEF activation handshake and recovery ordering; finite standby/active TTLs; separate global preparation limit and fairness; profiling cadence/overhead and approved performance bounds. Do not substitute the current 120-second diagnostic lifetime, 180-second successor bound or 24-hour queue deadline for one another. No answer is inferred from the request to save this research.
