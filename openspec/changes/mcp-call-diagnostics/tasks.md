## 1. Freeze the approved diagnostic contract

- [x] 1.1 Approve the revised six-scenario packet including helper-owned OAuth consent/scope, canonical intent/session/report identities, positive attribution matrix, global quotas and separate server/client retention; gate: reviewed proposal/spec/design/BDD packet. Owner implementation/subagent authorization recorded in approval.md, 2026-11-02; runtime gates unchanged.
- [x] 1.2 Verify SDK/native event interception and source impacts; implementability-spike the selected helper public OAuth/PKCE client, diagnostic-only resource/scope/OS credential store and deterministic API, fixed outbox policy and bounded batches; reconcile active AFR/ACI/remote-MCP revocation/consent contracts without weakening platform-failure rules; gate: architecture review, not runtime acceptance. Real SDK/PG validation and scoped OAuth, native CLI metadata, Windows own-entry credential roundtrip, durable subprocess recovery and bounded delivery reviewed. Actual native consent/report acceptance remains required by 2.3 and 3.2.
- [x] 1.3 Preserve a unified pre-migration checkpoint and historical aggregate-only failure evidence; gate: existing backup verifier, unchanged business hashes. Independent verification: artifacts/runs/aci-pre-migration-preservation/b1170b3e-30c9-49ea-8fda-debb188c9a25/independent-verification.json; original 88-table business fingerprint unchanged.
- [x] 1.4 Install approved Gherkin mirrors, named mappers, semantic contracts and fail-closed independent readers; gate: traceability/semantic audit, runtime not_run. Strict OpenSpec, six-scenario semantic/mirror audit and 14 reader-integrity controls passed 2026-11-02; physical runtime gates remain open.

## 2. Implement collection and private diagnosis

- [ ] 2.1 Add compatible append-only diagnostic storage/completeness, actor-independent case/report uniqueness, batch/watermark receipts and shared quota reservations; add helper OAuth resource/scope/consent/revocation bindings through compatible migrations; gate: PostgreSQL preservation and concurrency checks.
- [ ] 2.2 Instrument real ingress/auth/SDK-validation/handler/admission/dispatch/receipt boundaries with validated trace links and no raw values; gate: MCD-SC-001.
- [ ] 2.3 Implement helper-owned OAuth authorization/refresh and deterministic case/batch/report delivery, crash-tolerant native capture/outbox and fallback owner import; prove stable case identity across admission/lost response/active-run client crash, late batches and cross-actor races; authorized delivery gets one receipt, revoked delivery gets zero report writes/pending_auth; gate: MCD-SC-002.
- [ ] 2.4 Implement the exact positive evidence-to-category table and unknown/conflict rules; reject all-unknown classification on complete positive evidence; gate: MCD-SC-003.
- [ ] 2.5 Add owner/admin private views, diagnostic report kind/references and foreign/agent access denials; verify completed runs with client errors report automatically and ordinary failed grades/error-free runs do not; gate: MCD-SC-004 with actual browser/backend/PostgreSQL proof.
- [ ] 2.6 Verify allowlists/canaries, per-event/canonical-case/bundle limits and owner/deployment/anonymous/local-spool quotas including in-flight reservations, rotating sessions, fixed anonymous buckets and concurrent replicas; gate: MCD-SC-005 with visible partial/unavailable coverage and no retained evidence eviction.
- [ ] 2.7 Add only server-owned received diagnostics/mappings/receipts to unified backup/retention; separately test remote-client outbox restore, 30-day creation-based local expiry and post-ack GC on next launcher start, without server backup/purge claims for offline client files; gate: MCD-SC-006, preserved canonical identities/revocation.

## 3. Qualify and deliver

- [ ] 3.1 Freeze source, run all six mandatory gates and independently replay every required observation/negative; gate: complete environment report, no substitute flags or skipped acceptance.
- [ ] 3.2 Requalify affected source pins, execute fresh actual native OAuth Training/Ranked and verify diagnostic completeness, actual automatic report/receipt in admin UI/PostgreSQL, exactly-once retry after connection recovery, zero duplicate economic effects and unchanged official grading rules; gate: source-bound native/browser acceptance.
- [ ] 3.3 Publish the safe failure breakdown, completeness/attribution limits and operator procedure; preserve old 27-error history as aggregate-only; gate: artifact review.
- [ ] 3.4 Review mandatory results, commit/push only the approved completed scope and sync/archive only when all required gates pass; gate: closeout review.

## Current physical acceptance status — 2026-11-02

The owner's real Chrome click created Training intent
`38d4a301-8925-4441-a124-0e5811336bd2`. The pinned native Codex, current
OAuth connection and separately owner-authorized diagnostic helper executed
run `9192245e-76b5-49aa-9986-2fac63e6df81`. Native collection took 311 seconds;
the model made 151 MCP calls and no local tool calls. All 139 `current_task`
intervals were at least 1001 ms after the preceding response. Source inventories
before/after this attempt matched (620 inputs); subsequent acceptance tooling
changes do not retroactively qualify that inventory as the current release.

This is **not successful benchmark acceptance**: the server cancelled the run
with `coordinator_evaluation_unknown`. Independent deployed-validator replay
accepted the first two actual S1 inspection observations, then rejected the
third, already observed `pay`, as `action_evidence_unavailable`. The original
run and its unknown grades remain unchanged. Repairing admitted learning-action
observation needs a separate approved reliability assertion packet; do not
silently forbid learning mistakes or manufacture a zero score.

Diagnostic delivery for this failed attempt is physically demonstrated:
case `5da85e64-81c1-4ab8-8bb6-b2d8cde8f685`, canonical diagnostic report
`f3fc5064-f65f-4a59-b8bd-a4067dd23ec3`, segment
`417615ac-067e-4590-8664-b16534180cbc`; automatic delivery used one attempt.
An independent actual helper HTTP receipt returned 200, contiguous batch 1,
`reportCreated=true`, `diagnosticsSynced=true`, `completion=complete`;
read-only PostgreSQL and the real owner diagnostics UI matched the identifiers.
The UI displayed 927 source events and four error observations; observations
from different sources are not four independently established causes. The
`TASK_CLOSED` denial has verified policy evidence; two native configuration
items retain unknown exact causes. This does not prove administrator visibility
or all fourteen SC002 fault variants.

A separate actual native free-preflight/invalid-preflight capture also reached
one canonical report and synchronized receipt, with unchanged seven business
hashes. It is a physical SC002 fragment, not the full mandatory gate. Private
operator evidence is under `.local/mcd-native-training-38d4a301/` and
`.local/mcd-native-validation-9363a59e-728a-4bd1-8265-f40621d8bd95/`.
Fresh complete Training/Ranked, administrator UI, remaining fault variants and
the final source-bound six-gate cohort remain open. No commit, push, sync or
archive is claimed.
