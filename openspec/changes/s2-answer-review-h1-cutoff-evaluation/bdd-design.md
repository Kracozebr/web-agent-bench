# BDD design packet: `s2-answer-review-h1-cutoff-evaluation`

Workflow: [`docs/task-design.md`](../../../docs/task-design.md)

**Status:** Approved for implementation  
**Normative delta source:** `openspec/changes/s2-answer-review-h1-cutoff-evaluation/specs/`  
**Target main source after sync:** `openspec/specs/benchmarking-core/spec.md` plus the new `owner-submitted-answer-review` capability

## Intent

**Goal:** Make the submitted S2 value reviewable by its owner and identify/fix the exact H1 no-retrieve proof gate so a fully validated cutoff proof reaches the existing rubric.

**Non-goals:**

- Expose a reference answer, sealed case, raw transcript, or live-task hint.
- Change scores, task goals, deadlines, payment policy, coordinator retry windows, or historical grades.
- Treat local BEF evidence as live-chain evidence.

## Scenario design

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
|---|---|---|---|---|---|---|---|---|---|---|
| OAR-REQ-001 | OAR-SC-001 | Owner inspects a terminal S2 submission | Owned terminal run and task with hash-valid retained evaluation input / owner opens S2 report / exact submitted answer is shown without reference or unrelated data | `environment` | yes | `test_oar_sc_001` | Actual browser → owner API → PostgreSQL retained evaluation input | Observe owner identity, terminal gate, input hash, answer equality, and response/DOM field allowlist; adversarial hidden-field injection; read-only durable effect | Browser/API capture, independent input hash read, rendered report and persisted-row fingerprint | Directly enables manual review of the observed S2 score |
| OAR-REQ-001 | OAR-SC-002 | Missing or unauthorized answer remains unavailable | Foreign owner, active run/task, missing evaluation, or invalid input hash / request answer detail / no answer content or mutation is returned | `environment` | yes | `test_oar_sc_002` | Actual browser/API with owner and non-owner sessions plus read-only PostgreSQL inspection | Observe auth, terminal/evaluation gates, hash validation, empty answer response, and unchanged rows; adversarial foreign owner/hash tamper; no durable effect | HTTP responses, independent owner binding/input hash checks, before/after row fingerprints | Protects sealed and owner-scoped data while adding the review field |
| WB-REQ-002 | WB-SC-002 | A scorecard separates outcome cost latency safety and evidence | Completed run with partial chain evidence / produce scorecard / retain separate dimensions and mark chain evidence `unknown` without changing task outcome | `local` | yes | `test_wb_sc_002` | Existing deterministic `ReferenceBenchmark` model | Preserve the unchanged main-spec observations for separate dimensions, unknown chain evidence, and unchanged task outcome | Existing reference-model unit evidence | Carried unchanged from the main spec because the active modified requirement retains its existing scenario |
| WB-REQ-002 | WB-SC-006 | H1 grades a validated paid-child absence proof | Fresh bounded Training H1 run through browser and native agent with a confirmed required payment, full admitted-action census and no retrieve linked to that payment / coordinator reaches evaluation / existing H1 partial grade and ordinary handoff are persisted once | `environment` | yes | `test_wb_sc_006` | Actual browser → API/worker → local BEF app store/PostgreSQL/RPC and native MCP action path | Observe whether projection minted the proof, exact preflight predicate, payment, closure/cutoff, complete census, child evidence hash, no same-payment retrieve, evaluator input, grade and next-task handoff; adversarial unrelated retrieve for another payment; one evaluation, no new payment/refund | Raw paid/chain/census evidence refs and hashes, independent projection/evaluator result, task/run/evaluation rows, cleanup fences | Reproduces the user's coordinator-evaluation-unknown symptom and distinguishes proof-generation failure from source-authority failure |
| WB-REQ-002 | WB-SC-007 | Ambiguous H1 retrieval evidence stays unknown | Fresh H1 candidate with missing/contradictory/foreign proof or same-payment retrieve admitted / coordinator evaluates / no grade is fabricated and existing bounded recovery remains authoritative | `environment` | yes | `test_wb_sc_007` | Actual worker/evaluator plus local BEF evidence and PostgreSQL observer | Observe the exact failing proof predicate, retained `unknown`, absence of evaluation/score, and unchanged payment identity; adversarial census omission, hash mismatch, and admitted rejected/pending retrieve; no durable score mutation | Source-linked packet hashes, evaluator result, task/run state and original receipts | Prevents fixing H1 by converting ambiguous delivery into agent failure or success |

Allowed gates: `local`, `artifact`, `environment`. Mark a gate optional only when its omission cannot weaken the approved behavior or release decision.

## Semantic harness contract

For OAR-SC-001/002, the machine-readable contract SHALL observe authenticated owner identity, run/task terminal state, retained-input hash validation, exact answer equality, absence of reference/case/action fields, and unchanged evaluation rows. Negative variants are foreign owner, nonterminal run/task, missing input, and mismatched hash. The boundary is the real browser/API/PostgreSQL path; evidence is the response, rendered report, and independent read-only row/hash check.

For WB-SC-006/007, the machine-readable contract SHALL observe the full accepted-action cutoff, exact payment/action linkage, paid-child evidence hash, retrieve-to-payment linkage, validated source handoff, evaluator status, persisted result, and ordinary handoff. Negative variants are missing/incomplete/contradictory/foreign/hash-mismatched proof and any same-payment retrieve admitted before cutoff. The boundary is the browser-started local run through the actual worker and BEF app store/PostgreSQL/RPC with native MCP actions. Durable effects are one existing payment, at most one evaluation and handoff, and no fabricated delivery or refund. The environment must be labelled local BEF; no higher-trust claim is allowed.

## Execution design

- Existing checks to reuse: `packages/owner-identity/src/task-evaluator.ts`, `task-admitted-actions-capture-packet.test.ts`, `task-paid-data-capture-packet.test.ts`, `tests/bdd/features/benchmarking_core.feature`, `tests/bdd/features/paid_delivery_cutoff_consistency.feature`, and the current owner report API/UI.
- New step bindings or adapters: extend the paid-delivery evaluator adapter and add an owner S2 answer-review browser/API adapter; keep one named mapper per scenario family.
- External prerequisites: current local UI/API/worker/BEF stack, authenticated owner and non-owner sessions, the native MCP agent path, and read-only PostgreSQL/RPC observers.
- Expected unavailable-gate behavior: mark the mandatory environment gate `blocked` with the exact missing service/client/evidence; never substitute a local unit test for browser/database acceptance.

## Approval boundary

Approval authorizes only the four new scenarios, tests, adapters, and production scope listed above. WB-SC-002 is carried unchanged from the main spec because the active modified requirement retains that existing scenario; it adds no behavior or assertion. Any other new scenario or changed assertion returns this packet to review.

**Decision:** Approved  
**Decision reference:** User message on 2026-11-03: «ок, давай выполняй» after review of this proposal
