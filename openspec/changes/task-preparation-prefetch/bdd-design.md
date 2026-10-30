# BDD design packet: task-preparation-prefetch

Workflow: [task-design](../../../docs/task-design.md). Status: **proposed, awaiting implementation/assertion approval**. Runtime acceptance for every scenario: `not_run`.

Normative delta: [specs/task-preparation-prefetch/spec.md](specs/task-preparation-prefetch/spec.md). Target after eventual approved sync: `openspec/specs/task-preparation-prefetch/spec.md`. Proposed machine-readable contracts are [bdd-harness-proposal.json](bdd-harness-proposal.json); they are not installed in the executable registry or harness. No tests are created in this planning commit.

## Intent

Protect sequential benchmark execution while one immediate successor is prepared in an independent compatible environment. Preserve original validation, grading, billing, timers and cleanup, and separately measure the performance effect. Exclude multiple executing tasks per run, grading shortcuts, all-task warm pools, real-funds settlement changes and unsupported production-capacity claims.

## Scenario design

All gates are mandatory `environment` gates. Proposed mapper module: `tests/bdd/mappers/test_task_preparation_prefetch_bdd.py`; proposed adapter: `task_preparation_prefetch`. These paths/names are future design, not existing executables. Boundary: actual owner coordinator/PostgreSQL plus two private BEF/EVM environments with independent read-only DB/RPC observers. Source-bound artifact replay derives the named observations; a producer `verified` label does not satisfy them.

| Requirement | Scenario | Title | Given / When / Then | Named mapper | Evidence and purpose |
| --- | --- | --- | --- | --- | --- |
| TPP-REQ-001 | TPP-SC-001 | Concurrent staging obeys budgets without another charge | Active run and finite budgets / concurrent stage deliveries and exhausted or disabled profiles / bounded unique stage reservation, unchanged run charge and serial fallback | `test_tpp_sc_001` | DB stage/lease/claim/slot/ledger snapshots and authoritative operation order protect capacity and original billing. |
| TPP-REQ-002 | TPP-SC-002 | Preparing another environment preserves the current task | Current A and compatible spare B / reset, fund and verify B plus mismatched variants / unchanged A and only correctly pinned B ready | `test_tpp_sc_002` | Correlated A/B RPC balances/nonces/allowances, DB operation/generation rows, baseline hashes and fences protect isolation. |
| TPP-REQ-003 | TPP-SC-003 | Future-generation access remains denied until activation | Active predecessor and private stage / future detail/tool requests with staged, stale or foreign credentials / no future disclosure or participant effects | `test_tpp_sc_003` | Actual HTTP/tool denials, current-task continuity and unchanged action/receipt/timer/ledger rows protect authority and task secrecy. |
| TPP-REQ-004 | TPP-SC-004 | Activation replay preserves one task and its proof chain | Exact predecessor proof and valid stage / two workers, response loss, restart and unknown/tampered proof / one eligible activation or safe block | `test_tpp_sc_004` | Independent evaluation/bundle/closure/event/fence/active-task readbacks protect task ordering and idempotency. |
| TPP-REQ-005 | TPP-SC-005 | Early readiness and expiry do not inflate execution time | Pinned stage/active TTL and clock policy / early or late readiness, expiry boundary and replay / single task start, only actual post-terminal wait excluded | `test_tpp_sc_005` | Authoritative timestamps, generation lifetime and exactly-once clock events protect timing/fairness. |
| TPP-REQ-006 | TPP-SC-006 | Failure and revocation retain resources until confirmed cleanup | Current plus staged generations / cancel/revoke/expiry/restart/lost setup or fence replies / unknown retained, exact cleanup before lease release and safe fallback | `test_tpp_sc_006` | Durable lease/fence/reconciliation/rejection rows and original ledger/results protect cleanup and recovery. |
| TPP-REQ-007 | TPP-SC-007 | Concurrent preflight and caches reject stale or partial facts | Immutable metadata and live generation / out-of-order checks, timeout, changed pins/cache or permission / complete bound verification only, no extra economic dispatch | `test_tpp_sc_007` | Raw RPC/health results, cache identity, current DB policy/baseline and dispatch counts protect verification quality. |
| TPP-REQ-008 | TPP-SC-008 | Paired workload captures establish only measured improvements | Frozen serial/prefetch profiles and approved bounds / matched Training3/Full12 plus pressure and incomplete captures / measured deltas, invariants preserved, honest non-passing gaps | `test_tpp_sc_008` | Raw phase events, CPU deltas, sampled simultaneous memory, RPC/storage and independent replay protect performance claims. |

Each contract's required observations, adversarial variants and durable effects are enumerated in the adjacent JSON. No scenario is an inventory-only or nominal health test. Variants must be exercised at their named actual boundary; mocked success is insufficient.

## Execution design

- Reuse existing preparation/fence probes, resource sampler, current-task authority checks and observer-only replay patterns; their serial results are baseline evidence only.
- Introduce the minimal proposed bindings/adapter and reviewed harness contracts only after approval, then generate mirrors from the spec. Keep source/contract hashes and explicit missing-observation reasons.
- Owner admission/start/cancel journeys must begin through actual browser controls and correlate to backend/PostgreSQL effects. Narrow private calls are limited to isolated diagnostic setup/fault injection, internal worker delivery and read-only observation; they do not substitute for user-facing E2E.
- Prerequisites: resolved serial M3 failure, qualified compatible A/B execution/payment profiles, reviewed activation handshake, finite budgets/lifetimes/fairness, private source-RPC and observer access, declared hardware/cache/model/client conditions.
- If a prerequisite or raw observation is missing, emit `blocked` or `not_run`; if a tested assertion contradicts the contract, emit `failed`. Do not infer passing from cleanup command exit, CPU headroom, artifact presence or a producer label.
- Keep all source pins, failed/partial captures, raw paths and hashes. Never retain secrets, authorization headers or token digests.

## Approval boundary

See [approval.md](approval.md). The user authorized saving, structural validation, commit and push of this planning packet. No executable assertion or prefetch implementation is approved. Before `/opsx:apply`, review the exact eight scenarios/variants, concrete open decisions and affected integration scope. Changes to assertions or inventory require review under task-design. All TPP gates remain `not_run`; no sync/archive is authorized now.
