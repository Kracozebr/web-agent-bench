## 1. Review and contracts

- [x] 1.1 Review remaining defaults for refund-bucket attribution, quote rounding, expiry and terminal transitions; retain confirmed current-day start checks and platform-recovery clock exclusion; record explicit approval of this packet before test/product edits. Gate: artifact review of design and all BRL scenarios.
- [ ] 1.2 Pin local acceptance fixture/config values, token precision, catalog/evaluator contract and dependency versions; document environment feasibility/identity dependencies without claiming they have passed. Gate: artifact fixture/contract review.
- [ ] 1.3 Define bounded HTTP schemas, authentication claims, stable errors, executor/evaluator ports and ledger transaction integration for the listed operations. Gate: artifact trace from BRL requirements to schemas.
- [ ] 1.4 Reconcile the lifecycle delta, BDD design and protected contracts with shared bonus accounting: training/ranked eligibility, bonus-first spending, owner-authorized USDC shortfall, source-linked reservations/debits/refunds and current start authorization. Retain the confirmed tester-bonus-billing queued-expiry/full-price-budget rules; review remaining refund defaults and cross-packet integration first; existing 25 scenarios are not complete bonus acceptance coverage. Gate: artifact cross-capability contract/scenario review before implementation approval.

## 2. Active-delta BDD support after approval

- [ ] 2.1 Add explicit change-source selection to mirror generation and semantic inventory/snapshot validation, preserving existing main-source behavior and the eight baseline scenarios. Gate: artifact source/ID/title/WHEN/THEN correspondence.
- [ ] 2.2 Merge the reviewed draft observation contracts into the runtime harness manifest, generate the 25 named mappers and feature mirror, and register the real-boundary adapter. Gate: artifact semantic harness audit; missing adapters fail closed.
- [ ] 2.3 Extend acceptance recording for active delta plus baseline source hashes and all mandatory environment gates, with explicit blocked prerequisites. Gate: artifact evidence inventory and provenance.

## 3. Local runtime and durable primitives

- [ ] 3.1 Add the minimal selected TypeScript API/coordinator workspace and local PostgreSQL/Anvil acceptance deployment, with ephemeral test auth and no real wallet/provider secrets. Gate: environment declared process/health/secret-redaction observations.
- [ ] 3.2 Add additive run/task/action/event/idempotency/outbox and shared reservation/budget integration schemas with uniqueness/revision constraints. Gate: environment transaction and restart observations in BRL-SC-003/004/005/018.
- [ ] 3.3 Implement canonical event/result hashing, raw reference storage and immutable version/quote/task snapshots. Gate: environment BRL-SC-001/017/018.

## 4. Admission and charging

- [ ] 4.1 Implement authenticated active-version-only new training/ranked admission serialized with activation and current Training admission (S1/M1/H1 weights 1/2/3, denominator 6) and integer fixed-price quotes, including zero-price authorization; preserve queued old-version snapshots/start eligibility and distinguish same-request retries from new archived-version requests without retargeting or effects on rejection. Gate: environment BRL-SC-001/002.
- [ ] 4.2 Implement same-key replay/conflict handling and serialized shared-owner/agent-cap reservations. Gate: environment BRL-SC-003/004.
- [ ] 4.3 Implement prepared-environment admission and atomic debit/first-task/deadline/outbox transition, requiring an unexpired persisted queue deadline; serialize start, cancellation and expiry under duplicate delivery/restart and retain one financial outcome. Gate: environment BRL-SC-005/006.
- [ ] 4.4 Implement approved UTC rollover, pre-start budget/permission recheck, original-quote preservation, refund-bucket linkage and next-reset read model. Gate: environment BRL-SC-007.
- [ ] 4.5 Implement one durable agent execution slot across modes/versions, uncharged queued waiters, restart-safe fenced handoff and concurrency for different agents within funds/capacity. Persist the proposed waiting deadline/policy at admission, expose deadline/expiry reason privately and expire queued/preparing requests once with cash/bonus/budget release, no debit or automatic requeue and no late-start/successor-slot effects; select the numerical duration after load validation. Gate: environment BRL-SC-005/006/012/019.

- [ ] 4.6 Implement owner-account rotation and oldest-currently-eligible ordering inside each owner with durable serialized dispatch/claim identity across workers/restart, busy-agent head skipping, no preemption and spare-capacity use for a sole eligible owner; preserve original waiting deadlines, per-agent slots and current budget/expiry/access rules. Gate: environment BRL-SC-019.

- [ ] 4.7 Add bounded private owner launch-intent creation/status/cancellation with immutable current eligible selection/weights/denominator/quote, active benchmark, cash ceiling and expiry; no holds, queue slot, timer or publication before matching-agent acceptance. Gate: BRL-SC-023/024.
- [ ] 4.8 Integrate atomic matching-agent HTTP/MCP acceptance with one server-derived admission identity/run binding; serialize stale-policy/price/version/cash checks, expiry/cancel and authorized admitted retries. Gate: BRL-SC-023/024.
- [ ] 4.9 Add current private browser quote/selection/handoff/status flow (three Training options), actual backend/PostgreSQL quote observations and actual pinned compatible-client repeat/fallback evidence, with safe nonauthorizing links/prompts and honest action counts. Gate: BRL-SC-025.

## 5. Task lifecycle and time


- [ ] 5.1 Implement ordered current-task action authorization and independent executor environment bindings. Gate: environment BRL-SC-008 with actual local Anvil state observations.
- [ ] 5.2 Implement ordinary-error and verified pre-execution rejection continuation without reset, separate unsafe-attempt evidence, and irreversible mandatory-violation zero/termination, including published attempt prohibitions; do not invent task-specific rubrics. Gate: environment BRL-SC-009.
- [ ] 5.3 Implement persisted task/overall timers, reconnect state and cutoff enforcement across restart. Gate: environment BRL-SC-010/011.
- [ ] 5.4 Reconcile pre-cutoff in-flight effects at expiry and retain verified partial outcomes versus unknowns; prevent incomplete overall-expired eligibility. Gate: environment BRL-SC-011.
- [ ] 5.5 Implement authenticated explicit finish and shared finish/deadline/action ordering, reconcile already admitted effects without resubmission, preserve violation history and reject agent-supplied scoring authority; ensure one evaluation posting and next-task activation across retry/restart. Gate: environment BRL-SC-020.

## 6. Cancellation and recovery

- [ ] 6.1 Implement idempotent pre-/post-start cancellation, including explicit agent-wide owner revocation and removal of a run-mode permission scoped to that mode, an immediate access fence, durable cancellation delivery across affected nonterminal runs, task-action cutoff, cleanup intent and retained evidence. Distinguish ordinary disconnect/token refresh from owner revocation; reauthorization cannot reopen cancelled runs. Gate: environment BRL-SC-006/012/013.
- [ ] 6.2 Implement bounded infrastructure observation recovery by original action/transaction identity, explicit approved clock adjustments and no action resubmission. Gate: environment BRL-SC-014 with actual local EVM effect.
- [ ] 6.3 Implement unknown terminal exclusion and exactly-one internal refund on failed recovery, including restart, contradictory and late evidence. Gate: environment BRL-SC-007/015.
- [ ] 6.4 Define the reviewed authoritative integrity-finding source/schema and evidence bindings, integrate real validation and implement idempotent run disqualification without refund/extra debit; preserve ordinary blocked-attempt, unknown/recovery and existing-terminal rules. Gate: environment BRL-SC-021/022; actual attack observation/attribution remains an explicit environment-capability dependency.

## 7. Feedback and handoff

- [ ] 7.1 Implement scoped run/feedback read models with closed S3/M2/H3/U1 reason-category allowlists and no exact case parameters/solution, compact ranked scores/error reasons without a participant tool-call journal, and training-versus-ranked release points without reference-solution leakage. Gate: environment BRL-SC-016.
- [ ] 7.2 Atomically establish/preserve the shared BLP-REQ-011 marker with complete-verified-ranked terminal state and idempotent eligibility handoff including immutable achieving-version metadata; other outcomes cannot publish a card. Gate: environment BRL-SC-017 and BLP-SC-017.
- [ ] 7.3 Implement coordinator event replay comparison and missing-artifact reporting without replaying external actions or overwriting original bundles. Gate: environment BRL-SC-018.

## 8. Acceptance and lifecycle closeout

- [ ] 8.1 Run the semantic audit before pytest, execute all 25 mandatory real-boundary scenarios plus preserved baseline gates, and review every named observation/negative variant/durable effect. Gate: environment and artifact complete passing evidence; no skips substitute.
- [ ] 8.2 Record limitations explicitly: no mainnet signing, Base fixture fidelity, full rubrics, Google/MCP client, public leaderboard or full UI acceptance is claimed. Gate: artifact boundary/provenance review.
- [ ] 8.3 After all required work/gates pass, sync only the new capability to main, preserve existing specs, retarget mirrors/contracts and repeat required source/acceptance checks. Gate: artifact/main-source coherence and mandatory environment evidence.
- [ ] 8.4 Archive only after sync and closeout verify no executable references to the active change path. Gate: artifact archive and post-move traceability.

## 9. Approved 2026-10-30 current Training amendment (pending implementation)

- [ ] 9.1 Update the single current catalog to Training S1/M1/H1 weights 1/2/3, full 0.5 USDC, denominator 6; ranked twelve/1 USDC/26 stays unchanged. Produce fresh immutable manifest hashes and validation proof without parallel catalog versions. Gate: artifact review plus BRL-SC-001/002/018 current-catalog evidence.
- [ ] 9.2 Update admission/quote/intent/run snapshots and UI projections together; retain generic future immutable snapshots/idempotency and normal stale-quote/selection checks. Do not add legacy test-catalog migration/history gates. Root separately owns permitted old local test-run/result cleanup, preserving accounts/agents/auth/codes/ledger/reports. Gate: BRL-SC-001/003/008/018/023/024 and independently observed DB/evidence inputs.
- [ ] 9.3 Update existing mirrors, named observations and isolated adapters for whole-request six-decimal quotes (singles 83334/166667/250000, S1+M1 250000, full 500000, zero), all excluded/mixed/forged selections and stale quote conflicts; preserve 25 stable IDs and existing gate status. Gate: semantic audit then mandatory isolated BDD, amendment variants initially not_run.
- [ ] 9.4 Exercise actual browser current quote/selection and stale-intent handling through the real backend with independent PostgreSQL reads; separately retain actual selected-client requirements and blocked states. Gate: BRL-SC-016/025. No additional real-user fees/grants/model runs/credential operations beyond the explicit budget.

Existing checkbox and gate results above remain unchanged. Human approval covers
bounded implementation and matching tests/BDD; await root's team review and apply
assignment. This planning revision performs no code/test/source-artifact write,
DB mutation or deletion.
