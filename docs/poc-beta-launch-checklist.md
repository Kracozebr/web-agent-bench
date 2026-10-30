# Beta PoC launch checklist

Status: readiness checklist. The operations rehearsal baseline is R37 runtime commit `e0b5932`, independently verified 29 October 2026; current native-run and screenshot qualification is recorded below for 30 October. This checklist does not change the approved scope, OpenSpec task checkboxes, or target gate statuses. It is a launch-readiness summary, not a target acceptance record.

30 October local update: real Google sign-in/admin access and the current
three-task Training have browser-to-PostgreSQL proof. Native Codex completed
S1/M1/H1 with three known passed 1/1 results, a single 0.5 bonus-USDC fee,
verified evidence and released claim/slot. Admission to completion took 125.2
seconds, including initial preparation. The current catalog has only those three
Training tasks, denominator 6, and the unchanged twelve Ranked cases at 1 USDC.

The current native Full12 now also completed normally: run
`a9f5c4fa-551a-4c8d-b657-eb9b89dac640` has twelve known grades (six passed,
four failed, two partial), independently verified input/result/bundle hashes,
92 runtime files, two manifest-pinned source leaves, one bonus-USDC fee and
all twelve generations fenced with claim/slot released. Execution took 502.2
seconds; admission to completion took 513.1 seconds. The earlier H3 inspection
and H2 rejected-child loader defects have bounded fixes and regressions. The
closed-but-ungraded deadline cleanup also ran on the earlier actual H2 stall,
without fabricating a grade or extra debit.
The native-agent report now has an owner-attached private screenshot, loaded in
the actual Chrome owner and admin views. Independent observer verification matches
its normalized WebP bytes/hash, uploader and attachment audit; ledger, grades,
actions and stored timers are unchanged. The existing owner report remains a
zero-image control. This closes the local attachment gap, not the target-host or
four-client screenshot matrix. See the dated
[qualification record](poc-implementation-progress.md#30-october-real-google-and-native-codex-local-qualification).
These loopback observations do not satisfy the target-host or four-client gates.

## Readiness decision

**Not ready for an external 3–5-person beta or 20–30-person release.** The current three-task Training and Full12 have real Google and participant-owned model proof on loopback. Historical eight-task/reference-worker captures belong to their original builds. Target deployment, other clients and mandatory beta acceptance gates remain open.

Latest 30 October acceptance replay: BTS has two failed and 32 blocked scenarios;
BRL has 25 blocked; BPC has 26 blocked. The failures expose four missing current
release-negative controls. A separate fresh full-worker attempt stopped before
M3 on `coordinator_preparation_failed`; the actual native Codex completion above
is preserved as its own bounded proof. Fresh local bonus/report independent
replays pass, including screenshot storage and the local negative matrix.

The approved task file marks 1.1, 1.3, and 8.2 checked. Those boxes track their named artifact/implementation outputs; the mix of implementation, external setup, and acceptance work in the rest of the list is not a code-completion percentage.

## Already implemented, with bounded local evidence

- Bonus-code [migration](../packages/owner-identity/src/bonus-code-migrate.ts), [service](../packages/owner-identity/src/bonus-code-service.ts), routes, admin/owner UI, code claim, and source-linked ledger handling are present. Capture `97e0f8c3` and its independent replay cover local issue/claim. The separate shortfall probe `9589f738` proves a `BETA_BONUS_BALANCE_REQUIRED` denial with synthetic cash available and no partial run/debit effect. Captures `f519ab49` and `a3387be8` show code-derived funding through local all-eight training and full12 worker completion. The ranked capture records twelve evaluations and the internally bound handoff/result; it is not a real model run or public page acceptance. See [implementation progress](poc-implementation-progress.md) and the approved [bonus scenarios](../openspec/changes/beta-poc-delivery/tasks.md).
- Report/image routes, owner/admin UI, MCP report wiring, private image storage, and closure handling are present. Historical R14 capture `50103cbf-ee58-446d-b460-79658d220bce` independently replays eleven owner/admin observations and all thirteen SC018/020 negatives, including flood and four valid-agent admin denials. Live PostgreSQL and private-file checks pass. Historical bonus restriction capture `c75b3094-345f-4794-9a6b-5530af1b92fe` passes five HTTP denial paths plus a separately labelled cash-sufficient direct-service bonusOnly probe. These two captures share the frozen R14 source; they are a historical baseline rather than current-source acceptance. See the [local closeout record](poc-implementation-progress.md#29-october-requested-local-restriction-checks-closed).
- The beta runtime manifest/profile is implemented. Production [config](../packages/owner-identity/src/config.ts) selects it separately from the loopback-only, development/test local coordinator; it checks manifest, source/build pins, HTTPS origin, Google settings, secret references, and client profile constraints. [Server wiring](../packages/owner-identity/src/server.ts) constructs the beta coordinator/readiness path from this manifest. No target host has been configured or accepted.
- The beta [run policy](../packages/owner-identity/src/bef-task-coordinator.ts) pins one execution slot, two accepted queued runs per owner, eight globally, and an 86,400-second pre-start deadline. The [run service](../packages/owner-identity/src/run-service.ts) checks the deadline before claim/start and exposes pending-fence state; the [owner run UI](../packages/owner-web/components/run-launch-panel.tsx) shows the deadline and explains that holds release only after cleanup confirmation. These are implementation facts, not proof of the 24-hour boundary/race/restart matrix on the target.
- Public list/detail API routes in [public-ranked.ts](../packages/owner-identity/src/public-ranked.ts) and the `/public/agents` [list page](../packages/owner-web/app/public/agents/page.tsx) and [detail page](../packages/owner-web/app/public/agents/%5BagentId%5D/page.tsx) exist. The full12 replay validates internal completion, version snapshot, first-action marker, eligibility event, and best-result pointer bindings. The progress record explicitly leaves anonymous public HTTP/UI/cache rendering unrun.
- Operations pause/resume and usage/support export code exist; local database/HTTP regressions are recorded. Export regression 5/5 closes implementation task 8.2 only, not SC023 release acceptance.

## Prioritized work before a participant beta

### P0 — Complete the local safety and recovery slice

- [ ] **Complete the updated release-negative evidence matrix.** Independent replay rejects BTS-SC-001/002: the producer's seventeen variants omit the four current controls `training_set_mismatch`, `training_weight_or_sum_mismatch`, `ranked_or_training_case_count_mismatch`, and `release_identity_reuse`. Add actual producer probes and independent raw replay for them; a producer `verified` label is insufficient. Keep the current two failures visible until evidence exists.
- [ ] **Resolve and reproduce the latest local successor-preparation failure.** Fresh reference-worker capture `f54674d5` passed native MCP admission and six known evaluations/fences, then cancelled with `coordinator_preparation_failed` before M3 was issued. Overall deadline had not expired. Establish the underlying cause and obtain a successful current-source full replay/restart tail; the fixed wrong-origin health probe currently has regression proof only. Preserve this separately from the completed actual Codex Full12.
- [x] **Close actual Google/native-report screenshot attachment locally.** The owner attached one image to the existing native-agent report through Chrome; owner/admin previews, normalized private bytes/hash, attachment audit and unchanged benchmark/billing/timer fingerprints were independently verified. Full target screenshot abuse/retry/client gates remain open.
- [x] **Close the requested local recovery slice.** The wired durable-source monitor passes S1/S4/M3 lost-response recovery and a real 180-second observer outage with API restart, retained unknown, exactly one original-source refund, fencing and resource release. R37 raw replay confirms five core observations. Target-host recovery and the complete cancel/revoke/forgery race matrix remain open below.
- [x] **Close the local combined backup/restore rehearsal.** R37 passed with exit 0, stable source and eight independently replayed observations. Live read-only verification matched all 88 source tables, financial/results/report state, two screenshot files, and 21 official-evidence files plus manifest/receipt in each clone. Expired content is inaccessible and purged, five deletion receipts are complete, and original retries create no new business effects. Restored writes remain disabled. Daily/pre-migration operations and rotation are callable, but an unattended host scheduler and target RPO/RTO are still unverified. See [backup inventory](poc-backup-inventory.md) and [current evidence](poc-implementation-progress.md#current-verified-local-result).
- [ ] **Preserve existing production database state through migration.** A local migration rerun seeded an existing grant/ledger row and verified it remained preserved. Before migrating the selected beta database, take the approved pre-migration checkpoint and verify the existing production data and operations remain intact; the local seeded rerun does not prove an upgrade on the eventual production database.
- [x] **Close the requested local flood, agent-admin and bonus restrictions.** The final same-source captures and independent raw/live database checks above close this local slice. Full beta gates remain blocked.
- [ ] **Complete independent bonus-race replay and target acceptance.** Prior local producer captures cover SC003/004/006 code-claim races, disable behavior, rollback and response/restart replay. Scenario-specific independent raw replay for those three scenarios and actual-target integration remain open. SC005 now independently replays its local issue/claim and restriction paths; the linked worker positives remain the separately bounded training/full12 captures.

### P1 — Configure and prove the actual target profile

- [ ] Select the host and domain, provision HTTPS and trusted origins, configure the production Google OAuth callback and verify the founder subject on that target. The Google project and local sign-in/admin bootstrap now work; server/domain and production callback remain unselected.
- [ ] Prepare the pinned production qualification manifest and secret references; deploy web/API/worker, persistent PostgreSQL and private evidence storage. Keep PostgreSQL, BEF admin, and raw RPC private. Prove readiness and an actual task start against the pinned target without fixture authentication or a local model provider.
- [ ] Run target-host SC021 operations evidence: health/readiness, pause and drain, reads/reports while paused, queue/disk/resource admission, bounded load, and restart with queued/running/completed work. Verify identities, holds, claims, slots, fences, and no duplicate effects. The implemented pause and queue status UI do not substitute for this workload/restart capture.
- [ ] Run the approved SC016/017 timing and recovery cases on the target: caps under concurrency, duplicate dispatch/start, original 24-hour queue deadline at/before/after start, cancellation/restart, expiry cleanup, and preserved holds until confirmed fence. Keep deadline, successor preparation, and platform recovery clocks separate.
- [ ] Verify anonymous public list/detail pages and API/cache behavior on the cohort-release manifest, including eligible completion, partial/zero/tied result, private/unpublished agent, missing/corrupt binding, and cache/rebuild. The pages and routes exist; public rendering remains unverified.
- [ ] Repeat the SC022/026 restore gate on the selected target, install and exercise unattended daily/pre-migration backup with separate key custody, and record target RPO/RTO and write-enable decision. The R37 local combined rehearsal is verified; synthetic historical expiry does not establish an actual 30-day wait or external-host disaster recovery. Complete the remaining missing/corrupt-artifact, missing-key and interrupted-run runtime negatives.
- [ ] Complete the 26-scenario BPC runtime gate run on the frozen target source and replay its source-bound evidence. The semantic audit covers 26 contracts; consult the dated current-source runtime results in the [progress record](poc-implementation-progress.md) for passed, failed and blocked evidence. Structural audit success does not promote a beta gate.

### P1 — Obtain external client coverage

- [ ] Arrange real pinned editions and model access for Claude Code, Claude Desktop, and Hermes; only Codex access is currently available. Pin and verify all four client profiles and exact callback/transport declarations.
- [ ] For each of Codex, Claude Code, Claude Desktop, and Hermes, capture actual participant-owned model training and full12 use on the target, including preflight, accept, ordinary failure/reconnect, report, credential revoke/replacement, and independent result readback. Reference workers and scripted actors do not count. The approved decision waits for all four families before release.

### P2 — Run and review the 3–5-person pilot, then decide on expansion

- [ ] After the target safety, auth, recovery, restore, and client paths are ready, run the initial 3–5-person pilot and record actual owner counts separately from agent counts, onboarding failures, completed training/full runs, reports, and operational cost. Set pilot bonus amounts and dates before issuing codes; the plan defers those values.
- [ ] Reconcile the frozen source/build inventory and all mandatory gates, retaining `passed`, `failed`, `blocked`, `skipped`, and `not_run` separately. Publish a readiness decision and restrictions before considering the 20–30-person cohort. Do not promote old MVP gates or infer readiness from elapsed time or a green build.

## External inputs and boundaries

The remaining external prerequisites are host/domain selection, HTTPS and production Google callback/secret configuration with the founder subject verified on that target, and three missing client/model sessions. The Google project and local founder sign-in already work. Their waiting time is not an engineering estimate. No duration or percentage is assigned here. If an effort estimate is added later, state the assumption of up to three parallel agents plus one integrating/reviewing root, identify shared-source/build serialization, and report external dependency wait separately.

This checklist follows the approved boundary in [approval](../openspec/changes/beta-poc-delivery/approval.md), [spec](../openspec/changes/beta-poc-delivery/specs/beta-poc-delivery/spec.md), and [tasks](../openspec/changes/beta-poc-delivery/tasks.md). Existing implementation and evidence status remain recorded in [progress](poc-implementation-progress.md); this checklist does not change them.
