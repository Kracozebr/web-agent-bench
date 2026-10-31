# Recovery implementation checkpoint

Date: 2026-10-31. Scope: BER-SC-003/004/005/007 implementation and bounded regression evidence.
This note is not a passing BER environment-gate report or target/native-client acceptance.

## Concrete causes and preserved originals

- Training run `1faa495d-b412-405e-8a93-454d4194ca0e` admitted H1 action
  `48723f89-9b3b-4137-bf23-3b2a1fee7b33` immediately before task deadline. The
  executor reused the live/open admission binding check while claiming and
  dispatching an already admitted action. Once deadline/closure advanced, that
  check could throw before marking outbox delivery; recovery selected only
  delivered outboxes. This establishes a code-level starvation path. A fresh
  actual-worker cutoff capture must still establish repaired runtime acceptance.
- Ranked run `6adddaa9-d1fc-4dc4-b8f9-0973e4866315`, H1 index 8, has complete
  receipt reconciliation for offer inspection plus one payment but no delivery.
  The existing evaluator intentionally returns `paid_resource_delivery_unobserved`.
  The action recovery monitor cannot recover this as an ambiguous action because
  its receipts are already observed. Preserve this unknown rubric result: absence
  of retrieve is not proof of a platform incident and cannot authorize its refund.
- Original reference capture `f54674d5-178f-4ad4-8f1d-5c04e86d3fc0`, run
  `bc8ac4e1-b8fe-49b4-b41d-40c3bd55c2ea`, stopped at preparation
  `ca5cf1fa-074a-4c18-ba87-3b261a87f5b9`. Exact diagnostic
  `artifacts/runs/owner-identity-bef-task-coordinator/lifecycle/ca5cf1fa-074a-4c18-ba87-3b261a87f5b9-6aea180d-ad1a-452a-907f-cc3e2e9e164a.json`
  has SHA-256 `321d2365b7fa0031991e3f351439369d96d6050c93af246a9b30b9f6567a4c7d`
  and records `preparation_put/request_failed`, not an earlier health-origin
  failure. Independent owner/BEF observers show an actually created and funded
  generation `72dac492-58d5-4598-8493-aa670ab10003`, followed by confirmed fence.
  The old diagnostic did not retain transport exception class; a timeout is
  consistent with the old 15-second PUT limit, but is not proven as the unique
  cause. Neither original database nor original artifact is rewritten.

## Technical profile

- New admission retains live/open deadline checks. Internal drain accepts only
  an exact immutable admitted action UUID whose scope/generation/environment,
  pre-deadline acceptance and cutoff sequence match the active task. It still
  requires the running run, exactly one active task, ready leased generation,
  live matching claim/slot, and executor grant/mode/revocation checks. This is
  not a new late-admission API or authority to restore lost actor credentials.
- Closed reconciled tasks get a finite evaluation retry window of 180 seconds
  from durable `closed_at`, matching the existing recovery duration. Retry and
  restart cannot reset the origin. If unresolved before overall expiry, normal
  cancel/fence uses `coordinator_evaluation_unknown`, retaining unknown with no
  platform refund. Existing proven-platform recovery has priority and retains
  its own clock adjustment and original-source refund authority. Ordinary overall
  expiry keeps its existing distinct reason.
- Initial BEF preparation PUT has a default 45-second HTTP budget; ordinary
  health/RPC requests retain their default 15 seconds. Explicit PUT overrides
  are integer 1–120 seconds, within the existing 180-second successor window.
  Start remains subject to the original persisted preparation/deadline policy;
  this change does not extend benchmark task clocks or retry a PUT.
- Future failed PUT diagnostics add only a static transport class, monotonic
  elapsed milliseconds and configured timeout. No raw exception messages, URLs,
  admin key, payer key or run token enter evidence. A lost successful reply stays
  unknown and uses GET observation/fencing without a second PUT or reconstructing
  unavailable credentials.

## Executed regression checks

- Actual Node/TypeScript tests in the existing runtime container: coordinator,
  preparation, execution binding and observation lifecycle, 58 tests total,
  55 passed, 3 explicitly disabled PostgreSQL tests skipped, 0 failures.
- A real ephemeral loopback HTTP test commits a synthetic preparation result
  before delaying the reply. With read timeout 1 second and PUT timeout 2 seconds,
  the one-shot preparation succeeds after 1.1 seconds. With PUT timeout 1 second,
  it records timeout/elapsed, retains unknown and observes via GET; repeat prepare
  does not issue another PUT. This proves the HTTP orchestration boundary only,
  not BEF reset/funding or native model execution.
- Separately enabled `OID_COORDINATOR_DEADLINE_CLEANUP_PG_TEST=1` creates/migrates
  its own `oid_deadline_cleanup_*` database. The selector cancels a closed task
  older than 180 seconds while its overall deadline is still future, retains
  pending/unknown-action tasks for their recovery authority, confirms stored
  generation fences, releases claims/slots and proves zero refund/evaluation
  writes. 20 passed, 1 unrelated PostgreSQL lease test skipped, 0 failures.
- The first isolated-PG attempt lacked the migration auth-secret environment and
  failed before exercising the new selector; the corrected invocation supplies
  the existing secret internally without printing it and passes.

Root integration owns source freeze, BDD semantic registry/mirrors, actual
browser/native-client-to-worker runs, independent replay and final gate status.

## Post-fence receipt completion

A corner review found cancellation/session loss/revoke could fence a generation
and finalize a run while its individual admitted receipts remained pending. The
action monitor selects only running, delivered actions, so run-level fencing alone
did not satisfy per-action reconciliation.

The cancellation bridge now calls `finalizeFencedTaskActionReceipts` after a
verified stored exact preparation/lease/generation fence and before declaring run
cleanup complete. It locks owner, agent, run, task and action records in the normal
order, validates original immutable grant/action/release/environment scope, and
reuses the authoritative receipt/reconciliation/cutoff writer in the same database
transaction. Pre-dispatch pending outboxes become evidence-backed rejected receipts;
the pending outbox itself remains the historical no-dispatch marker. Delivered
pending ambiguity becomes unknown. Existing observed/rejected/unknown receipts and
transaction identity remain unchanged. No actor dispatch, payment replay or refund
is introduced; original failed-user records are not backfilled automatically.

Each changed receipt points to a new raw safe action artifact containing the
original action identity, prior outbox status and exact immutable fence reference.
An absent/foreign/unproven fence or unavailable evidence store blocks cancellation
completion rather than inventing a receipt. Restart/duplicate callbacks reuse the
stored fence and leave already terminal receipts untouched.

`OID_TASK_ACTION_FENCE_PG_TEST=1` runs in a fresh `oid_postfence_*` database and
checks owner cancellation, a revoked-agent snapshot, lost-session cancellation,
unproven fence, retained transaction hash, duplicate callback, exact receipt/revision
counts and zero refund/evaluation changes. Its one executed integration test passed.
This isolated PostgreSQL/file regression is not a native-client or real-BEF E2E gate.
