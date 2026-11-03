# BDD design packet: `user-authored-agent-task-lab`

Workflow: [`docs/task-design.md`](../../../docs/task-design.md)

**Status:** Future post-MVP candidate; implementation and executable acceptance await a separate owner approval  
**Normative delta source:** `openspec/changes/user-authored-agent-task-lab/specs/user-authored-agent-task-lab/spec.md`  
**Target main source after sync:** `openspec/specs/user-authored-agent-task-lab/spec.md`

## Intent

**Goal:** After MVP, let an owner define a bounded state-transition task, run a selected agent repeatedly from equivalent local sandbox state, and see strict reliability and determinism evidence.

**Non-goals:**

- Changing the fixed official benchmark, Ranked eligibility, public leaderboard, PvP, or settlement.
- Running arbitrary user code, publishing tasks, or using real funds/mainnet.
- Counting a platform failure or unverifiable result as an agent mistake or successful run.

## Scenario design

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
|---|---|---|---|---|---|---|---|---|---|---|
| UATL-REQ-001 | UATL-SC-001 | Save a supported state-transition task | Owner session and supported local profile / owner defines from-state, target, and constraints in the browser / a private immutable revision is stored and selectable only by its owner | environment | yes | `test_uatl_sc_001` | Actual owner browser → API → PostgreSQL | Observe owner binding, validated profile, task revision/hash, privacy, and no sandbox action at definition time; negative unsupported-field and foreign-owner variants | Browser capture, response field allowlist, independent read-only task-row/hash check | Proves task authoring is a real owner workflow and does not start work early |
| UATL-REQ-001 | UATL-SC-002 | Reject an unsupported task before launch | Owner submits an unsupported action, unobservable target, or custom executable checker / validate definition / reject it with no trial group or sandbox action | environment | yes | `test_uatl_sc_002` | Actual task validator/API/PostgreSQL and sandbox action ledger | Observe validation reason and absence of trial/action rows; negative arbitrary-code, unknown-effect, and over-scope variants | Request/response, before/after row fingerprint, action-ledger query | Protects the sandbox and ensures every custom task has a real evaluator |
| UATL-REQ-002 | UATL-SC-003 | Enforce spend, gas-price, and time ceilings | Valid task, test funds, and owner/platform limits / agent approaches or exceeds a configured ceiling / over-limit action is not executed and attributable evidence is retained | environment | yes | `test_uatl_sc_003` | Actual worker → local sandbox/fork → evidence store | Observe per-run and group spend, gas price, deadline, attempted/denied action, final state, and fault attribution; negative boundary and unavailable-observation variants | Raw action, receipt/balance and clock evidence paths/hashes plus independent state reads | Proves requested limits are enforced, not display-only settings |
| UATL-REQ-003 | UATL-SC-004 | Repeat from equivalent isolated baselines | Versioned task, selected agent/config, manifest, seed, and count N / start a trial group / each run has a distinct identity and verified equivalent initial state | environment | yes | `test_uatl_sc_004` | Actual browser → API/coordinator/worker → isolated local sandbox/PostgreSQL | Observe N, task/agent/policy/environment pins, baseline hashes, reset fences, run IDs, and action cutoffs; negative reset mismatch, stale worker, or changed agent version | Per-run manifest, baseline observations/hash, lifecycle events, read-only final row inspection | Makes success rate and trace comparisons reproducible |
| UATL-REQ-004 | UATL-SC-005 | A single agent error prevents strict all-runs pass | Three completed, evaluable repetitions / one has a verified goal or constraint error / report all results and pass rate without `passed_every_run` | environment | yes | `test_uatl_sc_005` | Pure aggregation contract plus actual owner result view | Observe all individual results, passed/attempted/evaluable denominator, no best-run selection, and strict status; negative one-failure variants | Unit/JUnit contract evidence plus browser/API/result rows | Directly implements the owner's “not once mistaken” acceptance rule |
| UATL-REQ-005 | UATL-SC-006 | Unknown sandbox evidence stays inconclusive | A repeated run has a verified platform/observer fault or missing reset evidence / aggregate / report unknown without agent blame or strict pass | environment | yes | `test_uatl_sc_006` | Fault-injected worker/sandbox boundary and actual result store | Observe fault source, unknown result, absence of fabricated error/pass, and preservation of other verified runs; negative ambiguous-provider and missing-cutoff variants | Fault record, result, event cutoff, and independent persisted-row snapshot | Prevents unreliable infrastructure from distorting agent reliability |
| UATL-REQ-006 | UATL-SC-007 | Outcome and trace determinism are separate | Two valid runs reach the same target through different supported paths / view repeated-run result / both goals pass while trace consistency remains separately visible | environment | yes | `test_uatl_sc_007` | Normalized trace evaluator plus actual owner result view | Observe goal results, final-state hashes, normalized traces, normalization version, and unchanged source evidence; negative same-goal/different-state and invalid-path variants | Replayable run identities, trace/final-state hashes, rendered result, independent read-only rows | Measures repeatability without treating legitimate strategies as errors |

## Semantic harness contract

The machine-readable proposal is `bdd-harness-proposal.json`. Runtime contracts, named mappers, and adapters are created only after approval. For every boundary scenario, observe owner/task/run identity, task revision and environment hashes, action cutoff, per-run and group budgets, verified reset, evaluator result, and immutable evidence references. Negative variants include unsupported objectives, foreign ownership, attempted limit overruns, baseline mismatch, one erroneous repetition, and platform uncertainty. Durable effects include no run on invalid task, no over-limit sandbox effect, N distinct run records, one read-only result projection per trial group, and no mutation of the official task catalog or leaderboard.

## Execution design

- Reuse the existing local sandbox manifest/reset and evidence identity contracts; do not replace them with a toy reference runner for environment gates.
- Add one owner-facing task API/UI path, one bounded task-definition schema/validator, and a repeated-run coordinator contract after approval.
- External prerequisites: authenticated owner/agent, qualified isolated sandbox, verified reset, local chain/state observer, worker, and read-only PostgreSQL observer.
- Keep local grading tests distinct from browser→API→worker→sandbox acceptance. If reset, worker, evidence, or agent identity is unavailable, mark the affected gate blocked/inconclusive.

## Approval boundary

This packet is a post-MVP proposal only. It authorizes no implementation, executable test, new agent run, or change to the current MVP/PoC. After MVP, approval must cover these seven scenarios and this private local-lab scope; any new action family or public/ranked behavior returns the packet to review.

**Decision:** Awaiting owner approval  
**Decision reference:** User request on 2026-11-03 to record the self-authored repeated-agent-task capability in the plans.
