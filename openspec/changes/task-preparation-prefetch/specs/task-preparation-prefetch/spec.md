# Task preparation prefetch

Status: proposed, deferred; implementation approval pending. These requirements define future behavior only. Current runtime remains serial, and all TPP acceptance scenarios are `not_run`. Existing active BRL/BTS/BPC contracts must be reconciled before implementation. No current gate or main spec is promoted by this document.

## ADDED Requirements

### Requirement: TPP-REQ-001 Bound preparation separately from execution
An enabled prefetch profile SHALL permit at most one staged immediate successor per active run, with a persisted finite global preparation budget and separate preparation reservation. It SHALL preserve the admitted run, charge, claim, selected task order and existing execution-slot limits. Competing workers SHALL NOT exceed either budget. Disabled, unsupported or capacity-exhausted profiles SHALL preserve the serial path when existing run rules permit it; queued runs SHALL NOT consume speculative environment capacity without an eligible active predecessor.

#### Scenario: TPP-SC-001 Concurrent staging obeys budgets without another charge
- **WHEN** workers race to stage successors while the preparation budget is available or exhausted and a run uses a disabled or unsupported profile
- **THEN** at most the allowed immediate stages SHALL commit with one reservation each, no additional financial effect or active task, and eligible non-staged work SHALL follow the existing serial rules without resetting its current task

### Requirement: TPP-REQ-002 Preserve independent compatible environment state
A staged successor SHALL use a distinct exclusively leased environment and generation whose immutable execution, source, case, initial-state and payment/facilitator pins are compatible with the admitted run. Reset, funding, cache mutation or cleanup of the staged environment SHALL NOT mutate the current environment. All original baseline, receipt, evidence and exact-generation fence checks SHALL remain required. Equal source fork state SHALL NOT authorize an incompatible facilitator or an unverified snapshot.

#### Scenario: TPP-SC-002 Preparing another environment preserves the current task
- **WHEN** the successor is prepared in a compatible second environment and a stale generation, mismatched payment tuple, mutated baseline or attempt to reset the active environment is presented
- **THEN** valid preparation SHALL retain independently verified unchanged current-task balances, nonces, allowances, operations and evidence, and every mismatched or active-environment request SHALL fail without an unverified ready stage

### Requirement: TPP-REQ-003 Keep staged content and participant authority private
Staging SHALL NOT issue the next task, publish its credentials or admit participant effects before authoritative activation. Owner/agent current-task APIs and BEF participant tools SHALL enforce the staged versus active distinction, including direct requests with a future-generation credential. Secrets SHALL remain outside logs, fixtures and evidence. Stage readiness SHALL NOT start task clocks, publish grades or reveal hidden task answers.

#### Scenario: TPP-SC-003 Future-generation access remains denied until activation
- **WHEN** an agent requests future-task details, submits a participant action using staged credentials or retries a stale or foreign generation while its predecessor is active
- **THEN** disclosure and effects SHALL be denied without new task actions, receipts, financial effects, grades or execution clocks, while authorized current-task operations continue

### Requirement: TPP-REQ-004 Activate once after the exact predecessor proof
Successor activation SHALL revalidate the original predecessor's known evaluation, reconciled cutoff, sealed observation evidence, terminal event and exact confirmed fence, and SHALL atomically publish only the immediate next task after rechecking live run/access/cancellation and valid stage bindings. A known ordinary failure SHALL remain eligible to advance under the existing task rules; unknown effects or missing proof SHALL block advancement. Duplicate workers, callbacks and lost acknowledgements SHALL NOT activate twice or create simultaneous task execution. An incomplete owner/BEF activation handshake SHALL remain non-executable or unknown until safely reconciled.

#### Scenario: TPP-SC-004 Activation replay preserves one task and its proof chain
- **WHEN** workers race activation and retry after lost acknowledgement or restart with valid, failed-known, unknown or contradictory predecessor evidence
- **THEN** only a valid next activation SHALL commit once with the original run and charge identities, unknown or contradictory proof SHALL prevent activation, and independent DB/event/BEF observations SHALL establish one active task and no duplicated effects

### Requirement: TPP-REQ-005 Preserve execution clocks and bounded generation lifetimes
The admitted profile SHALL pin finite stage expiry, supported active-generation lifetime and clock policy. A task clock SHALL start only at authoritative activation. Overall execution-clock exclusion SHALL count only the actual post-predecessor waiting interval once, excluding time already overlapped with execution. Stage expiry, the accepted-run pre-start deadline, successor waiting bound and platform recovery clock SHALL remain distinct. Activation SHALL establish a bounded active-generation lifetime under the qualified policy without reviving an expired/fenced stage or silently extending unsupported guardrails.

#### Scenario: TPP-SC-005 Early readiness and expiry do not inflate execution time
- **WHEN** staging finishes before or after predecessor terminalization or its expiry races activation and the activation request is replayed
- **THEN** the next task SHALL receive its declared execution budget from the single valid activation, only actual non-overlapped waiting SHALL be excluded once, and expired or unsupported generations SHALL remain unusable without extra charge or deadline inflation

### Requirement: TPP-REQ-006 Clean speculative resources safely across failures
Cancellation, access revoke, stage failure, expiry and process restart SHALL identify and fence every affected current/staged generation before releasing its corresponding lease or preparation reservation. Unknown setup/effects or lost private in-memory credentials SHALL NOT be treated as success, blindly retried or restored from evidence. A failed stage SHALL NOT reset an otherwise valid current task; serial fallback SHALL require safe cleanup and the original run's continued eligibility. Rollback SHALL stop new stages and drain existing ones without orphaned generations or altered billing/results.

#### Scenario: TPP-SC-006 Failure and revocation retain resources until confirmed cleanup
- **WHEN** cancellation, revoke or restart races stage setup/activation, or the original setup reply or fence confirmation is lost
- **THEN** durable reconciliation SHALL preserve unknown states and the existing charge/results, reject further unauthorized effects, release only exactly fenced resources once and permit fallback only after safe cleanup and eligibility checks

### Requirement: TPP-REQ-007 Optimize read-only checks without stale verification
Independent read-only preflight operations SHALL be concurrency-bounded and retain all required results and upstream limits. Cached metadata SHALL bind the complete immutable release/case/source/policy identity and be invalidated on mismatch or corruption. Current permissions, mutable generation baselines, action receipts, capacity and activation checks SHALL NOT be replaced by cached success. A partial or contradictory check SHALL prevent ready/active publication under the existing unknown policy.

#### Scenario: TPP-SC-007 Concurrent preflight and caches reject stale or partial facts
- **WHEN** independent checks finish out of order, one times out, a release/cache object changes or current permission/baseline state differs from a cached result
- **THEN** only a complete correctly bound verification SHALL permit progression, stale/partial facts SHALL remain denied or unknown, and no extra setup PUT or participant effect SHALL be introduced by retries

### Requirement: TPP-REQ-008 Qualify performance and verification quality independently
Prefetch SHALL remain disabled by default until source/profile-bound serial versus overlapped trials verify all preceding requirements on compatible environments and an explicitly reviewed resource/performance policy. Evidence SHALL separate startup, preparation, activation waiting, execution, grading, cleanup, interrupted runs, CPU, sampled memory, RPC/storage and quality outcomes. It SHALL retain sample cadence, simultaneous rather than summed independent memory peaks, cache condition, background/observer attribution limits and raw hashes. Deterministic/reference and actual model runs SHALL be labelled separately. Missing data SHALL remain blocked/not_run; producer labels, the two serial diagnostics or planning estimates SHALL NOT establish a passing gate or production capacity.

#### Scenario: TPP-SC-008 Paired workload captures establish only measured improvements
- **WHEN** matched serial and overlapped workloads exercise Training3 and Full12 with declared cache/resource conditions, including a partial capture or resource-pressure regression
- **THEN** independent replay SHALL derive phase/resource deltas and unchanged isolation/verification invariants from raw evidence, fail breached approved bounds, retain unavailable observations as blocked/not_run and publish no unsupported speed or concurrent-capacity claim
