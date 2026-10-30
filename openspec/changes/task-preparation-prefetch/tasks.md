# Deferred implementation tasks

Status: planning saved; implementation approval pending. All tasks are intentionally unchecked. Read [approval](approval.md), [research](../../../docs/task-preparation-optimization-research.md) and [BDD packet](bdd-design.md) before resuming.

## 1. Resolve prerequisites and approve a concrete profile

- [ ] 1.1 Verify the separate M3 preparation issue is resolved and retain a successful source-bound serial Full12 baseline; gate: environment baseline, no prefetch claim.
- [ ] 1.2 Reconcile active BRL/BTS/BPC integration and qualify compatible per-environment case/payment/execution pins; gate: reviewed design plus actual A/B pin checks.
- [ ] 1.3 Specify owner/BEF staged activation authority, finite standby/active TTLs, preparation budgets/fairness and rollback; freeze hardware/cache/sampling and measurable performance bounds; gate: artifact review.
- [ ] 1.4 Obtain explicit implementation and TPP-SC-001–008 assertion approval; gate: dated approval record covering the concrete scope.

## 2. Install reviewed BDD contracts and minimal bindings

- [ ] 2.1 Install approved machine-readable harness contracts, mapper names and spec-derived mirrors; gate: semantic/traceability audit, runtime still not_run.
- [ ] 2.2 Implement source-bound raw evidence capture and independent observer replay with explicit blocked/not_run/failed handling; gate: artifact integrity and adversarial replay regressions.

## 3. Add bounded private staging and activation

- [ ] 3.1 Add disabled-by-default durable immediate-successor staging with separate preparation reservations and concurrent admission limits; gate: TPP-SC-001.
- [ ] 3.2 Prepare a distinct compatible generation with all original reset/funding/baseline/receipt checks; gate: TPP-SC-002.
- [ ] 3.3 Enforce future-content secrecy and inactive participant authority at owner and BEF boundaries; gate: TPP-SC-003.
- [ ] 3.4 Atomically activate after exact known predecessor proof, live access recheck and idempotent cross-service authority reconciliation; gate: TPP-SC-004.
- [ ] 3.5 Preserve clock exclusion, finite standby expiry and once-only active-generation lifetime without revival or hidden extensions; gate: TPP-SC-005.
- [ ] 3.6 Handle revoke/cancel/expiry/restart/unknown setup and rollback with exact fences and safe serial fallback; gate: TPP-SC-006.

## 4. Evaluate independent read-only optimizations

- [ ] 4.1 Measure bounded concurrent health/source/local checks and immutable hash-keyed metadata caching, retaining all live verification; gate: TPP-SC-007.
- [ ] 4.2 Measure each optimization separately against the unchanged serial path before combining it with staging; gate: source-bound phase/resource captures.

## 5. Qualify, review and release deliberately

- [ ] 5.1 Run paired Training3/Full12 serial versus one-successor-prefetch trials, including resource pressure, interrupted runs and original verification negatives; gate: TPP-SC-008 and TPP-SC-001–007.
- [ ] 5.2 Independently replay all mandatory observations and report CPU, memory, latency, billing/timing invariants and verification quality separately; gate: complete eight-scenario runtime report, no missing variants.
- [ ] 5.3 Review measured benefit and contention on the intended deployment profile; enable only for newly admitted qualified runs after approval and prove safe disable/drain; gate: target environment review.
- [ ] 5.4 Sync and archive only after approved tasks and mandatory gates pass; gate: strict OpenSpec, semantic traceability and source-bound runtime evidence.
