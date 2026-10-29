# PoC implementation progress

Checkpoint: 29 October 2026, Europe/Moscow. Approved planning baseline:
`2db5f5f`, pushed to `origin/dev`. This document reports implementation and
verification separately; agent reports are not accepted as runtime proof.

## 29 October: recovery and combined-restore continuation

The R28 capture (`64b720a6-a3ca-4901-9305-4a6f966ff94f`, frozen code
`78c38c8`) completed S1 lost-response recovery, the real 180-second observer
outage with API restart and exactly one source-linked refund, and passing S4
and M3 recovery without resubmitting the original action. The full recovery
stage is preserved at
`artifacts/runs/beta-platform-recovery-complete-stage/64b720a6-a3ca-4901-9305-4a6f966ff94f/capture.json`
(SHA-256 `b1e43aba2757825c38c689d284f96f098eb8072854300e189888e2f210cfe60e`).
The linked owner report with its real run/task/action context also completed.
The combined attempt then stopped before checkpoint creation; its failed
wrapper and isolated database remain available for inspection.

Two acceptance-helper assumptions were corrected: redemption operation IDs
come from the actual UI as dashed UUIDs, and the pause audit actor must match
the authenticated administrator rather than the participant. Genuine worker
failure classification is now checked before secondary request-capture checks.
The raw recovery reader now accepts the normal deletion of a completed run's
slot only with exact generation-fence evidence and released same-run claims;
it rejects active or foreign slot/claim state. A restart can finish before the
restarted monitor persists its incident row (24 ms earlier in R28); response
loss, process/health evidence and the fixed deadline remain required.

Focused Node acceptance-helper checks pass 13/13. The recovery and combined
restore raw-reader regressions pass 37/37. These corrections require a fresh
source-frozen combined capture; R28 is not relabelled as a successful backup,
and no target-host gate is promoted. Earlier tables below are historical
checkpoints, not a current process or completion inventory.

## Active work

The first three implementation processes stopped with a usage-limit error. On
the user's instruction to continue, three Luna/max continuations resumed from
the existing files: `bonus_continue`, `reports_continue`, `runtime_continue`.
On the next continuation, the active processes are `bonus_resume`,
`reports_resume` and `runtime_resume`, again Luna/max. The original owner names
below identify the work slices, not live process names.

| Owner | Slice | Observed progress | Verification |
| --- | --- | --- | --- |
| implement_bonus_codes (Luna/max) | Codes, atomic redemption, UI and BDD/E2E | Schema/migration/service/routes, admin and owner UI, browser producer and evidence writer added | Final c75b3094 independently replays UI issue/claim and all requested mode/cap/balance/anonymous-agent denials; root live PG confirms both HTTP fixture intents cancelled and no denied run/financial effects. The separate direct-service beta-only cash-sufficient probe also passes. Current-lock release activation passes. Captures f519ab49 and a3387be8 now prove code-funded all-eight training and full12 completion, with root live PG/ledger/fence-file replay; native models and target gates remain open |
| implement_reports (Luna/max) | Reports, images, triage, retention and BDD/E2E | HTTP/MCP routes, multipart upload, UI, private normalization/storage, closure state and browser/PG producer added | Final 50103cbf passes with stable 392-input inventory; root verifies all 11 owner/admin observations, all 13 SC018/020 negatives and live rate-counter/credential/file effects. Lifecycle 3/3 and authenticated local MCP smoke pass with independent live PG/file replay. Corrected report-aware restore/expiry rehearsal 5d1e4d20 passes with root replay; four native clients and combined restore remain open |
| implement_beta_runtime (Luna/max) | Qualification/runtime, clients, queue and central integration | Beta coordinator/readiness, queue policy, MCP registry/parser, central report wiring, partial recovery library and operations pause added | Identity/web checks pass; real PG recovery and pause lock regressions pass. Current-lock feasibility verifies and all 20 fresh reference captures pass raw integrity verification. Candidate validation and isolated release activation pass; code-funded all-eight training and full12 worker completion now pass locally. Trusted production recovery authority remains missing |
| Main agent | Coordination, source review, common BDD wiring and acceptance review | Approved 26 semantic contracts installed and mirrors generated; module ownership assigned | Semantic harness audit passes 26 contracts; latest raw-verifier regressions pass 14/14 and Node guard/intent tests 4/4; official target runtime mappers remain blocked/skipped. Usage/support export regression independently passes 5/5 (task 8.2 complete). Bonus-only dump/restore matches all 83 tables. No mandatory beta gate accepted |

## Coordination rules in use

- Subagents report each coherent slice with changed files, actual commands/results,
  blockers and next action. The main agent reviews source and evidence.
- Runtime agent owns shared server/config/migration/schema/MCP integration.
  Domain agents provide exports and independent adapter/capture modules directly.
  During BEF-only recovery, bonus_resume has the narrow server registration and
  operations-panel export-button slot; root and runtime do not edit those slots.
- Reports agent alone updates the package/lock files for the necessary pinned
  image decoder. Build/install/capture operations on the shared stand are serialized.
- Escalated read-only Docker inspection found only the existing healthy OID
  PostgreSQL container. No app runtime was active at that checkpoint. No existing
  DB/evidence reset is authorized by these inspections.
- User-facing E2E must initiate through real browser controls and independently
  inspect PostgreSQL/backend effects. Unit checks, synthetic provider tests and
  source existence do not close external Google/client/target-host gates.

## Current review items

- Reports: align ORM schema and migration on conditional uploader identity,
  source/reporter consistency and image-output constraints. Preserve deletion
  receipts before cascade removes report/image metadata.
- Codes: inspect concurrency/lock order, exact replay and source-linked credit;
  require actual isolated PostgreSQL race tests before accepting the service.
- Beta runtime: preserve local-profile restrictions and distinguish qualification
  from four-client cohort release; queue expiry must expose pending safe fencing.
- Qualification: the raw peer behind an HTTPS proxy identifies the proxy, not the
  end user. Allowlisting that peer alone cannot prove a restricted external
  qualification audience. Require enforced ingress restrictions and negative proof.

No complete PoC runtime acceptance or external deployment is claimed here.

## Executed checks (intermediate source; not a release build)

- `python -B tools/generate_bdd_mirrors.py --change beta-poc-delivery --check`:
  passed; 26 approved scenarios match structurally.
- `./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web check`:
  passed, exit 0.
- Identity `check` in the same pinned Docker runtime: failed on optional beta
  config-path typing and the sharp output-info type. Findings assigned to their
  module owners; a later passing run must explicitly supersede this result.
- `pnpm --filter @web-agent-bench/owner-identity exec node --import tsx --test
  src/config.test.ts src/beta-profile.test.ts` through the wrapper: 7 tests,
  5 passed, 2 failed. The two production negative fixtures hit unrelated new
  path validation first; fixes must preserve the intended production guards.
- Reports agent reported a successful pinned runtime image build and frozen
  dependency install; root reviewed the limited lockfile diff. This is dependency
  setup evidence, not report normalization or browser acceptance evidence.
- Follow-up after the assigned fixes: identity `check` passed, exit 0; the same
  config/profile command passed all 7 tests with no skips. These results supersede
  the two failures above for that intermediate source state. Later integration
  edits still require their own affected checks.
- After central schema/route integration, identity `check` found a new optional
  `codeVerifierSecret` argument typing error in server wiring; assigned to runtime.
- Affected MCP/run-route/cancellation regressions: 8 tests, 7 passed, 1 skipped,
  exit 0. The skipped between-task cancellation case is not runtime proof.
- Latest follow-up after central integration fixes: both identity and owner-web
  `check` passed, exit 0. The bonus continuation now owns the isolated browser/DB
  capture window; no bonus/report browser acceptance has yet been reported.
- Operations inventory core added in `infrastructure/owner-identity/beta-backup-inventory.mjs`
  with read-only `verify-beta-backup.mjs`. Four Docker file-integrity tests passed:
  valid byte inventory, corrupt/missing/symlink/escaping paths, authoritative
  closure preventing old-dump report resurrection, bounded checkpoint rotation
  including expiry retirement. Synthetic test bytes are not a database dump or
  screenshot acceptance capture. Daily backup, consistent DB checkpoint and
  isolated restore/retry rehearsal remain not_run; file verification never
  authorizes restored writes.
- Central BPC reader tests also ran in the pinned Docker runtime: 7 passed.
  The first bonus opt-in capture (`9d38741b-3b7e-463f-9192-ca22b18f03c9`)
  stopped at the API build, before migration/browser actions. Three new report
  type errors were assigned and repaired. Its isolated acceptance database was
  retained; the primary database was not reset or migrated. A new capture is
  required after the fix; this attempt proves no bonus acceptance.
- Subsequent attempts found stale web output and a native Next worker-thread
  abort before bonus actions. Explicit production builds with a two-worker Next
  CPU cap pass; the runner now builds web before starting the API. These fixes
  are harness/build results, not a successful bonus journey.
- Latest agent checkpoint at 22:31 MSK: identity/web checks and production web
  build passed; pure report image/closure tests 9/9; central reader/report replay
  tests 13/13. All 26 BPC mappers skip without target captures. None of the 26
  mandatory gates is accepted. Report browser/PG capture is not yet implemented.
- Root review at 22:48 MSK verified the first narrow local browser journey from
  capture `0654bcb8-636d-4d88-811d-b74c2290edbb`: real admin issue and owner claim
  for a group code (2.125001 bonus USDC) and single-use code (3.000007), visible
  balance deltas, independent read-only PostgreSQL redemption/grant/ledger/
  operation/audit lineage, and unchanged cash. Reproduce with
  `./infrastructure/owner-identity/tool.ps1 python -B -m tools.replay_bpc_bonus_local`.
  This verifies only local issuance/redemption. The capture's broader negative
  matrix had producer Origin-header defects, now being corrected and rerun.
  BPC-SC-005 remains blocked: code-funded training/full12 and the external target
  boundary are not proven. No mandatory BPC gate is closed by this local replay.
- Corrected bonus capture `97e0f8c3-0546-42b9-8497-94a5b68523dc` completed
  with exit 0 at 22:51 MSK. Root independently replayed issue/claim lineage and
  verified stable source inventories. SC-003/004/006 local matrices complete;
  SC-005 partial. Every official target gate remains blocked.
- On the next continuation, existing project containers were found stopped.
  PostgreSQL restart hit a Windows bind prohibition at loopback port 55433.
  Root checked port 65433, recreated only the PostgreSQL container with the
  same persistent volume and `OID_DATABASE_HOST_PORT=65433`, and verified health.
  Internal `postgres:5432` and retained acceptance DBs were preserved.
- Root local PostgreSQL dump/restore rehearsal completed at 23:33 MSK, exit 0:
  checkpoint `1b7f5241c76c4c19956c00bc9ab9e2a0`, all 83 public-table counts and
  full-row SHA-256 fingerprints match; source unchanged. This bonus-only fixture
  had no reports/images. See [backup inventory note](poc-backup-inventory.md).
  No screenshot/worker reconciliation or safe-retry acceptance is claimed.
- Report capture `82176614-e6e6-4d9e-8ddd-c54d13ee581a` stopped with exit 1
  awaiting the first report POST response. Its unique DB is retained; the failure
  does not establish a successful browser report path or final source stability.
- Root review found report replay omitted action-row invariance and platform
  refund replay rejected its already-finalized run. Assigned fixes were applied:
  report verifier tests 5/5 and runtime config/recovery tests 11/11 pass. Recovery
  tests use a queued test DB abstraction; they do not prove SQL or concurrency.
- Root semantic harness audit initially failed because the generic evidence
  case exposed no scenario-specific execute/verify methods or literal observation
  names. The adapter now dispatches explicit approved scenario methods with
  unchanged raw facts, negative checks and fail-closed missing evidence. Audit
  `python -B tools/check_bdd_harness.py --change beta-poc-delivery --json` passes
  all 26 contracts; reader/report unit tests pass 14/14; all 26 environment mapper
  tests explicitly skip pending target evidence. Artifact task 1.3 is complete;
  no mandatory runtime gate is thereby accepted.
- Second report attempt `e7524da8-5616-4387-a35f-62b177b76555` identified real
  HTTP 507 `REPORT_IMAGE_STORAGE_LOW` before any upload/report row: the project
  filesystem has roughly 12.7% free space, below the approved 20% floor. That
  guard remains unchanged. The opt-in `compose.reports-acceptance.yaml` moves
  local capture storage to a persistent native Docker volume with sufficient
  space; existing host captures are retained. The next browser capture must
  independently verify this path. This is local infrastructure, not a target
  host capacity acceptance result.
- The native volume capacity precheck passed (roughly 998 GB free of 1.081 TB).
  Third report attempt `ab8b901f-aae9-4ba6-a2df-d772e67981ee` uploaded a real
  screenshot with HTTP 201 and left one ready upload, then report creation
  returned HTTP 500. Root independently confirmed these rows. Forced-rollback
  service probes traced PostgreSQL `22P02` to raw UUID array binding and then
  `ERR_INVALID_ARG_TYPE` to raw JSON object binding. All affected report/image
  bindings were repaired; rollback probes exercise creation/attachment/audit
  and nonempty/empty retention arrays without committing. Fresh UI acceptance
  remains required after these fixes.
- Actual PostgreSQL recovery regression passed in unique retained databases
  `oid_acceptance_f2a2a568e40f4ce4b3fa56de6544d9bf` and
  `oid_acceptance_181a2805abad483685edd77056f4b05d`: wrong environment rejected,
  two concurrent finalizations yield one settlement and one replay, reconnect
  replay preserves one refund. Root independently read the first DB through
  `oid_observer` with read-only enabled: run failed, recovery refunded, one refund
  receipt/ledger entry, 250 minimum units. The second test also denies observer
  writes. Authority is explicitly injected test evidence; no production monitor
  or connected recovery acceptance is claimed.
- Report capture four `8896ee55-a0ab-43c2-8ab5-a6a9c0cce46b` committed real
  owner UI reports and an attached private screenshot, then stopped on an
  asynchronous lost-response assertion. Capture five
  `b4858122-0fa0-4e46-aff9-97b91c6e32d6` passed the corrected response-loss retry
  but stopped on an unsupported `min(uuid)` aggregate in its observer query.
  Read-only PostgreSQL independently showed exactly one report/operation for
  that retry. The observer query now uses `min(id::text)`.
- Capture six `0628d3e3-ea1b-413a-adb6-b4b1001d1430` stopped with exit 1 at the
  over-5-MiB multipart negative request timeout. Diagnosis must distinguish
  bounded rejection latency from a stuck handler; no timeout relaxation or
  negative-matrix acceptance is inferred. These failed attempts have no complete
  source-after/evidence bundle and do not establish the whole report/admin E2E.
  Positive code-funded training/full12 captures are next while this is diagnosed.
- Follow-up HTTP diagnosis confirmed two separate multipart defects: partial
  durable staging before complete input validation, and an unconsumed
  `preParsing` Transform that backpressured the raw request also consumed by
  `@fastify/multipart`. The same isolated parser returned 413 without that second
  pipe and stalled with it. The fix must preserve the total envelope bound for
  both Content-Length and chunked requests, validate all parts before durable
  staging, and prove bounded rejection with unchanged PostgreSQL state.
- The focused real-loopback HTTP/PostgreSQL regressions subsequently passed
  2/2: 5 MiB+1 known-length file returns 413, a trailing extra field returns 400,
  and chunked envelope overflow returns 413. Independent read-only counts for
  reports/audits/uploads/chunks/deletion receipts/rate/ledger/runs/tasks/actions
  remain unchanged. The existing partial upload in capture six is retained;
  the regression added no rows. This is a local rejection regression, not a
  replacement for the still-missing complete owner/admin browser capture.
- Review also found inconsistent owner/global-advisory/control lock ordering
  across create, accept and queued claim. The ordering is aligned; isolated PG
  regression work is still in progress. A queued pause request is not itself a
  committed pause, and no claim that the old order demonstrably deadlocked is
  made without a reproduced PostgreSQL cycle. The required behavior is denial
  after pause has linearized, with original deadlines and financial state intact.
- The lock regression subsequently passed 1/1 in retained DB
  `oid_acceptance_fa8c3c16477040eda652858087dcfd22` (5.97 seconds wall time).
  Root independently read `oid_observer`, read-only `on`, final pause revision 3,
  three control events and zero intents created after that pause timestamp.
  PostgreSQL allowed create/accept before the pause acquired its control row;
  the test accepts this valid pre-pause branch and checks paused claim/start
  effects and preserved queue deadlines separately. Identity/web typechecks pass.
- Training startup `306fbd90-9ed7-4841-b932-6a0061b5943e` rejected an extra CLI
  separator before any build or DB action. The corrected direct-node invocation
  `af39e11a-810a-4943-9f14-96352ab23e5f` then stopped before positive release
  activation. A supplemental negative-probe serializer masked the original
  blocker; it now saves that probe separately and preserves primary failures.
  Root's independent historical-pin audit found all five artifact hashes match,
  but their source inputs pin the old `pnpm-lock.yaml`. The approved multipart/
  sharp additions changed that file. Current-lock feasibility and 20 fresh
  local-fork case probes are required before refreshing release evidence and
  exact PIN references; no old artifact or SHA guard is rewritten or weakened.
- Reports capture seven reached the inert-text assertion but read stale detail
  state immediately after a different report was clicked. Capture eight
  `a4e3922b-9dbe-4ec5-a13c-fb422f84bee5` passed the corrected inert-text check,
  then failed at browser evidence serialization: the capture wrapper exposes
  arrays under `.capture`. Root independently read four reports, four distinct
  operations, four creation audits, one attached image and zero ledger/task/
  action rows; the single linked-run fixture remains. Admin triage was not
  reached. A wrapper-contract regression and a new full capture remain required.
- Complete local report capture `e3155475-4e32-4b35-a51a-c0d780559ab7` exited 0:
  no local failures, all 377 source inputs stable. Root ran
  `python -B -m tools.replay_bpc_reports_local` in pinned Docker, exit 0. All six
  owner and five admin raw observations verify, including duplicate-free retry,
  independent private image hashes, list filters and audited close/reopen.
  Official SC018/020 manifests remain blocked. Four native clients, external
  Google/host, complete negative matrix and retention purge/restore are not_run.
- Separate local shortfall capture `9589f738-1795-4569-a88d-2aefd58669b0`
  stores before/helper-result/after artifacts under
  `artifacts/runs/bpc-bonus-shortfall-helper/`. Root checked every indexed file
  hash/size and independently read the exact synthetic owner through the
  read-only observer: 250000 bonus units, 2000000 cash units, zero reserves or
  debits, zero runs; before/after ledger and totals match. Service returned 409
  `BETA_BONUS_BALANCE_REQUIRED`. This is direct-service/local evidence only,
  using synthetic cash and the real code-derived lot; no central gate promoted.
- Current-lock feasibility witness `f28df42b-6341-467a-9be9-380e63ab4325`
  passed verifier `5da32b24-3bbe-4e23-8969-ee954d7acf72`; root checked both
  file hashes. Execution identity is
  `72aeadc411180708f4498a03619a1708b88eb053753c60b3fb35fcb3eb5609e2`.
  Fresh S1 training/ranked probes captured and fenced, with matching source pins.
  S2 training `bf50be68-5646-45e5-b5e2-314b5e71a320` returned reset HTTP 503:
  response says generation fenced, environment unknown. It is not counted as a
  successful reference; exact generation/lease state must be reconciled before
  another start. Existing evidence, primary DBs and volumes remain preserved.
- SC023 usage/support aggregation passed its deterministic and isolated read-only
  PostgreSQL regressions (2/2). It uses one repeatable-read snapshot, persisted
  action/grant bindings and a supplied pinned registry; preflight connections,
  manual support time and paid conversion remain explicitly unmeasured. Report
  history is incomplete after retention deletion. Admin route/download wiring
  is in progress; this does not close task 8.2 or the target acceptance gate.
- Root corrected the operations pending-intent count to exclude expired intents,
  matching admission capacity semantics. A rolled-back transaction in isolated
  `oid_acceptance_fa8c3c16477040eda652858087dcfd22` presented one live and one
  expired pending intent: the actual operations snapshot returned one, and a
  full before/after intent read matched after rollback. No durable fixture or
  primary database change was made.
- The guarded env-A recovery subsequently succeeded. A single journaled reset
  returned JSON-RPC null; independent `bef_observer`/Anvil readback showed all
  483 generations and 150 preparations fenced, zero unresolved operations and
  latest exactly equal to the pinned block/hash. Root checked after-artifact
  SHA-256 `4ad850aae06e66bdac6f54ff4cc85c6500f5dd2597ca54d05c090edc9bbf0d79`
  under `artifacts/runs/bef-env-a-reset-step-execution/db91f2ec-53bb-47a2-a502-90d1de8dd011/`.
  An intermittent source-proxy 502 delayed preflight; no mutation was sent while
  that prerequisite failed. New reference capture resumes with a new S2 UUID.
- Admin usage/support JSON route and operations-panel download are implemented.
  Registry SHA-256 is explicitly derived from the startup-validated deployment
  client projection, separately from benchmark release hashes. Without a beta
  manifest the strict local fixture returns 503 rather than inventing a registry.
  Identity/web typechecks pass. Focused route HTTP/read-only PG regression passes
  3/3, using injected authorization; real-session browser validation remains next.
- Fresh browser capture `1cd16537-6c25-4469-960b-85ef058ab3ca` exited 0 with
  all 384 source inputs stable and no local failures. Root's report replay again
  verifies all six owner and five admin observations. Supplementary SC021
  pause/resume, report reads while paused, real-session non-admin denial and
  missing-registry export denial also pass. Root's independent operations replay
  verifies raw SHA-256 `4b7573992e63d84c43909ce0a6d9c097ef0f9eeb37e2b278648bc4a17c4b973f`
  and live read-only PostgreSQL: revision 2, two new audit events, preserved
  report/run/action/ledger counts. This is partial local coverage; target
  health/load/restart and native-client gates remain blocked/not_run.
- The first isolated lifecycle regression `9e82ad6f-c517-4456-ae1c-e3c3756bc100`
  stopped on a test pre-race count error: two images were already attached,
  whereas the test expected one. Actual observer state showed three attached
  and one ready/unlinked after exactly one race winner. The old DB/artifact are
  retained. The corrected test is being rerun on a new database; no whole
  quota/retention acceptance is inferred from the first partial attempt.
- Corrected lifecycle capture `50bc8604-ef2a-4f96-ac53-7542399e785b` passes
  3/3 tests. Local HTTP/PG checks cover seeded rolling quota, three staged images,
  chunk ordering/replay/conflict, foreign principal denial, orphan cleanup and
  concurrent cap enforcement. The synthetic historical closure preserves the
  exact 2592000-second interval, with real HTTP reads before and denials after
  an independently observed database deadline. Root checked artifact SHA-256
  `bed8c3fa54489fcb648656f00af4fa8b02c41b4f7b423836813cf444fcb0be8e`
  and independently read the retained DB/files: zero reports/uploads/chunks/files,
  one complete deletion receipt and unchanged grade/run/bonus/ledger sentinel
  digest `4d3ce497994e815920f5528ec1679550ea909144f08845a6950ea2042d4e1113`.
  This does not establish old-backup sanitization or four native-client acceptance.
- Root independently reran both usage-export suites with both PostgreSQL opt-ins
  enabled against the isolated `af39` fixture: 5 passed, 0 failed/skipped. This
  completes implementation task 8.2; central SC023 release acceptance, cohort
  measurement and task 8.3 remain open. The local real-session browser also
  verifies non-admin export denial and missing-manifest failure, not a fabricated
  positive deployment-registry download.
- Authenticated local MCP smoke `33941ef0-833f-44a7-9634-3c81fd264da3`
  completes through the production database-backed bearer resolver and HTTP MCP
  transport. Root independently verifies artifact SHA-256
  `8dd4e626aed233ecfe695057cc4b4c384c8b0e1993ee306560fbe48e3d68c281`,
  live observer-role PostgreSQL and normalized private image bytes: one report,
  audit and attached upload, zero retained raw chunks, five usage receipts.
  Nonempty ledger/run/task/action/timer state retains digest
  `703d32fe4f3d27908639fb6fbb5a60b7d4ed7c2695cc2efce4aa44f9cb28ab9c`.
  Ordered chunks, exact replay, conflict, foreign access and revoked bearer
  checks are local synthetic-credential evidence; UI token issuance, native
  clients, model execution and SC019 release acceptance remain unproven.
- Offline report-aware backup rehearsal checkpoint
  `f05253e8809d4b889d4d4dd972a850e7` finishes successfully. The saved operator
  DPAPI-wrapped key is read back to decrypt the database dump; a tampered copy
  is rejected. Root independently compares all 88 table row hashes in the
  untouched source and isolated restored database, verifies every inventoried
  file and the restored 24786-byte screenshot (SHA-256
  `b21455ad59dcec1c7f6c386917d9209c52e7961377680ca89bb564918842332f`).
  A second clone uses a synthetic expired closure: zero reports/uploads/images,
  four complete deletion receipts and unchanged non-support table hashes.
  Original inventory SHA-256 is
  `6d32a2bac3411cad5e39420ce86422b069486780134916a0da4f521de0b7b06a`;
  sanitized inventory SHA-256 is
  `db0d298f3b537b933918a75c6f960cab8382ae53f65e3f193f9078799bad9fc9`.
  Journal `025-complete.json` incorrectly labels the expired stage `prepared`;
  actual cleanup/finalization journals and independent live readback establish
  the result. The summary mapping was corrected without rewriting capture
  evidence. Independent follow-up review required guards for leftover raw
  chunks, original-checkpoint invariance through clone cleanup, receipt identity
  on retry and a complete helper dependency source map. The corrected guarded
  replay is recorded below; this earlier artifact remains preserved as historical
  evidence only. This report-only fixture does not prove combined bonus/run
  restore, application restart, daily scheduling, target-host recovery or full
  SC022/026.
- Fresh current-lock release candidate validation passes in
  `artifacts/runs/bts-difficulty-v2-release-validation/a8755b14-6868-42d4-977b-39314c067cd4/validation.json`,
  SHA-256 `e63308ed99100555f1f29b51b37269fdb3ead580a34367431d17adc177aa6bea`:
  `validated_candidate`, 20 semantic reference results, approved difficulty proof.
  Root checks the artifact identity/hash. Retained reference and minimum reviews
  both pass 20/20. Semantic comparison
  `62365f4f-e48b-4d9e-822f-94b2cbf54df5` preserves task/rubric/weight/rule/deadline
  and price semantics; changed synthetic addresses bind to actual probe records,
  and remaining native-balance differences follow observed gas costs.
  Earlier blocked validator artifact `f0a29a7b-3054-4ec2-b971-2532454d8f1e`
  retains the stale candidate-binding failure. The production verifier now pins
  the new candidate with unchanged verification logic. Isolated activation and
  positive bonus-funded owner training/full12 runs remain next, not established
  by offline validation.
- Corrected report-aware backup/restore rehearsal `5d1e4d201d484ed1b9839c9b9afbfa2b`
  completed with source `oid_acceptance_1cd165376c254469960b85ef058ab3ca`, restore
  clone `oid_restore_754bf3568e584a5096e5d5a4ec41d5ae`, and synthetic-expiry clone
  `oid_restore_b788628abcb14b2ca76b81da4b8fe626`. The journal/evidence under
  `.local/owner-identity/report-restore-rehearsals/5d1e4d201d484ed1b9839c9b9afbfa2b/`
  shows all 88 table fingerprints and 152 implementation pins stable, source
  and restored tables/sequences matching, DPAPI current-user key recovery, and
  tampered-ciphertext rejection. The restored screenshot is 24,786 bytes with
  SHA-256 `b21455ad59dcec1c7f6c386917d9209c52e7961377680ca89bb564918842332f`;
  the journal interval was 51.94 seconds, not an RTO. The expiry clone ended with
  zero reports/uploads/images, four complete deletion receipts, no pending or
  failed receipts, and unchanged non-report tables/sequences plus source DB,
  closure and images. Expiry used synthetic closure state in the clone only;
  grades/ledger restoration was not proven, the restored application was not
  started, and this does not close full SC022/026, off-host, target-host, or
  production RPO/RTO requirements.
- Release BDD capture `f3e9a531-9e3a-4768-9ffa-fbad32354c3d` passed local
  `BTS-SC-001` and `BTS-SC-002` activation observations. Each persisted runtime
  capture reports 17/17 observations, zero not-run/failed, validated activation,
  and unchanged PostgreSQL state with no run or ledger rows:
  `artifacts/runs/acceptance/BTS-SC-001/runs/96c0e3de-9318-4470-8ddc-0c4940a0bbc3/runtime-capture.json`
  and
  `artifacts/runs/acceptance/BTS-SC-002/runs/6712c9d0-d82b-455b-8f9a-d2de8968e1d8/runtime-capture.json`.
  Root's independent PostgreSQL activation replay agrees. This is release
  activation evidence without task execution; no central gate is promoted.
- Positive browser training-sequence capture
  `90714c34-be23-4924-9178-4288e08c578d` remains blocked and explicitly has
  `fullScenarioAcceptance=false`; its evidence is under
  `artifacts/runs/genuine-training-sequence-owner-run/90714c34-be23-4924-9178-4288e08c578d/`.
  The browser-issued bonus-code path produced a 100,000-unit grant. A separate
  post-capture read-only PostgreSQL observation in
  `.tmp/check-bonus-preparation-block.mjs` found a 66,667-unit held
  `tester_bonus` reservation with no cash effect; the capture's earlier embedded
  owner-balance snapshot reports zero reserved bonus, so these are distinct
  observation times. The run did not start (`started_at` is null), had zero
  participant actions, no recorded internal evaluation or grade, and an
  unverified worker-evaluation request. It remains `cancellation_requested`
  after `coordinator_preparation_failed`; cancellation evidence and task-lease
  fencing are absent from the capture, so the final fence is unproven.
- The positive capture records blocker code
  `strict_preparation_or_task_issue_timeout`. Follow-up found a coordinator
  evidence-path bug for its exact nested local default; the writer in
  `packages/owner-identity/src/bef-task-coordinator.ts` now enforces canonical
  containment while allowing that default and safe single-component overrides. Its filesystem regression
  reports 14 passed and one existing skip; identity typecheck and build passed.
  The blocked capture predates that fix and has not been rerun, so the fix does
  not change its acceptance status or prove a unique cause for the timeout.
- After the fix, a guarded one-shot standard coordinator recovery against the
  same isolated `90714c34` database completed its cancellation tick in 176 ms.
  Before/after journals are preserved in `.tmp/recover-bonus-cancellation-90714/`;
  SHA-256 values are `8a9f9f1ece0fc7098db2e22d53a131029f54b7ea8f2ee1b5786c980bb33086e6`
  and `4bd02e138f89c44f8606cebce363dfd2b41312028712cb2c82a14951e712906b`.
  Root independently ran `.tmp/check-bonus-cancellation-recovery.mjs` with the
  read-only observer role: the run is cancelled, its lease is fenced with a
  verified evidence-file hash, claim/slot are released, reservation/budget hold
  are released, and the original bonus balance is 100,000 available / zero
  reserved. Exactly one 66,667-unit release offsets the original reserve; no
  start debit, task action, or evaluation exists. No manual ledger edits or BEF
  reset were used. This is cancellation recovery evidence, not successful
  training completion; the original failed capture remains unchanged.
- Fresh post-fix capture `93d332b8-b216-45cd-b7e8-7642c976b7a7` retained
  stable 387-input provenance but stopped before task issue. Capture SHA-256 is
  `c55c2c86cec276c711aa886c1a6d70bb406d67822b095cb7e4603cbe6af63497`.
  Run `b0a47cd0-429d-4d8c-80a1-d477a8f8d20a` recorded
  `preparation_identity_mismatch` with no BEF generation. Its cancellation now
  completes automatically. Root independently verifies the durable fence file,
  released slot/claim/holds, 100,000 available / zero reserved bonus, and no start
  debit, task action, or evaluation. The exact adapter health replay currently
  succeeds and source/local RPC batches match the pinned block; this does not
  identify the predicate that failed during the original attempt. Safe internal
  preparation diagnostics are being added before another capture. The failed
  artifact remains blocked; training/full12 completion is still unproven.
- Internal pre-PUT refusal diagnostics now persist one event per preparation
  attempt with exactly `preparationId`, `environmentId`, `phase`, and static
  `reasonCode`. No request/header/payer/credential or raw exception data is
  recorded. Diagnostic sink failure preserves the existing unknown outcome and
  zero-PUT guard. Focused adapter tests pass 16/16, identity typecheck and build
  pass; a new runtime capture is required to prove its observation boundary.
- Diagnostic capture `87a79e57-be75-4662-a4aa-4411431b2e12` kept stable
  provenance and stopped before task issue. Capture SHA-256 is
  `025a553fa53103fce85a97d6387abc8de4f239990d6d4b5bb068290596cf04f6`.
  Its four-field lifecycle event records `source_rpc_response/response_invalid`
  (event SHA-256 `e915de91a52b73e15f0b4a622ea13b8c3dac95cd85227b7f1cac0874dec3f305`).
  No BEF generation was created. Root's read-only replay confirms automatic
  cancellation and full original-source reservation release, no debit/actions/
  evaluations, and a verified fence evidence file. A later health replay with
  the same Google transport preload succeeds; source call usage is below its
  10,000-item limit. Source metrics have ten cumulative upstream errors, without
  per-request attribution. HTTP/protocol classification and one bounded
  transient-HTTP preflight read retry are being implemented; successful task
  execution remains unproven.
- The acceptance harness now supports the fixed bonus-funded all-open opt-in
  `--genuine-bonus-funded-training-all-open-worker-owner-run`. It preserves the
  S1/S2 mode, verifies each adjacent predecessor/activation/deadline/fence binding,
  and derives one-ceiling training quote and sufficient bonus funding from the
  pinned release. Root's focused sequence and existing bonus-capture contract
  tests pass 9/9; runner syntax check passes. This is harness verification, not
  observed all-eight task completion or SC014 acceptance. The additional report
  negative-test draft remains unapplied pending fixture/evidence corrections.
- The source/local initial pre-PUT identity RPC batches now permit one 250 ms
  delayed retry for HTTP 502/503/504 only. Logical pin mismatch, malformed/RPC
  errors, ordinary baseline reads and cached reconciliation are not retried;
  admin preparation PUT remains exactly once. Final refusal diagnostics classify
  HTTP/protocol failures without recording raw responses. The adapter suite
  passes 24/24, including retry recovery/exhaustion, no-PUT wrong pins, redaction,
  and one-shot cached reconciliation. Identity typecheck/build pass. Root also
  restored the indexed task-0 predecessor record in the legacy non-worker
  sequence bridge; no new legacy non-worker runtime acceptance is claimed.
- All-eight capture `f64d4135-3060-4052-890c-99199f5aff66` (SHA-256
  `3d015572ca2b52585d911e731abed6d54a486cbd98a8c6911fdee472450acef2`)
  proves the first actual code-funded task: S1 completed with an independently
  reconstructed known `passed` evaluation and credit 1/1, and the server
  activated S2. The harness then rejected a correct deadline because
  `Date.parse(Date)` lost milliseconds; persisted run-start and activation
  deadline values both retain `.332Z`. This was a harness comparison error,
  not a demonstrated product deadline mismatch. The failed capture is preserved.
  Root independently verified the code/redemption/grant linkage, one 500,000-unit
  reserve and one debit, no refund/cash substitution, zero remaining reserve,
  released claim/slot, delivered cancellation outbox and both fence file hashes.
  The run was voluntarily cancelled by harness cleanup after starting; S2 has no
  evaluation and full-run completion remains unproven. The old capture's false
  `allTaskLeasesFenced` combined fencing with incomplete transition proof; live
  owner and BEF readbacks prove both exact generations fenced. Date precision
  and truthful selected-prefix cleanup are corrected; focused tests now pass
  12/12, including stale/malformed deadlines and a prepared but unverified
  successor. The next frozen-source captures below supersede this blocker.
- All-eight training capture `f519ab49-7ab9-46ff-a1b5-ecdd215e15c1`
  (SHA-256 `f10bc0f3ca1a4052ae7ab007305a709d6d6573efd4523214c9c125e572c1bbfb`)
  completed through browser code issue/redemption, actual server-worker actions,
  independent observations/evaluations, seven successor activations and owner
  results UI. S1/S4/M1/M3/M4/H1/H2 passed 1/1; S2 was partial 7/10. Root's
  separate read-only PostgreSQL replay verifies the grant/redemption/reservation
  linkage, exactly one 500,000-unit reserve and start debit, no cash substitution,
  zero remaining balance/reserve, eight evaluations, one completion, released
  dispatch claim, zero slots and all eight fence-file hashes.
- Full12 ranked capture `a3387be8-053a-495b-a7da-33561c0d3e6c`
  (SHA-256 `fae995ccf7d08f4d4db522301793ad093c5d6d3d73fa21f6efc3e3baab1aabce`)
  completed with automatic server-worker lifecycle, owner results UI and internal
  ranked handoff verification. Root independently verifies code-derived funding,
  exactly one 1,000,000-unit reserve/debit, no cash substitution, twelve
  evaluations, one completion, released claim, zero slots and twelve fence-file
  hashes. Both captures retained identical before/after 388-input capture
  inventories; root also checked the broader 683-path R7 freeze unchanged.
  These are local reference-participant/fixture-Google captures; native model,
  external Google, public leaderboard UI and target-host acceptance remain open.
- Applied reviewed report negative-test extensions and the narrow Fastify
  `FST_ERR_CTP_BODY_TOO_LARGE` mapping to HTTP 413 `REQUEST_BODY_TOO_LARGE`.
  The previous generic fallback could map parser rejection to 500 (source
  diagnosis, not a captured pre-fix response). Actual report-route `app.inject`
  now verifies bounded 413 before auth/rate-limit/service entry; the separate
  PostgreSQL multipart test was skipped in this focused invocation. Identity
  typecheck passes, report producer/evidence tests pass 3/3 and independent
  verifier tests pass 7/7. New browser assertions cover separate foreign run and
  action IDs, field and HTTP-envelope bounds, conflicting retry, denied admin
  status/foreign screenshot reads and admin inert-text rendering. A fresh
  browser capture below supplies local runtime evidence; SC018/020 remain open.
- Fresh report capture `850e258a-1352-411f-a0dd-e0e46dfc5d70` exited 0 with
  no local failures, stable 389-input capture inventory and independently checked
  684-path R8 source freeze. `python -B -m tools.replay_bpc_reports_local`
  independently replays all eleven owner/admin positive observations. Additional
  raw-verifier replay confirms SC018 foreign run **and** foreign action denial,
  forbidden fields, actual oversized HTTP envelope 413, inert HTML text,
  response-loss retry and conflicting retry. SC020 replay confirms stale
  revision, foreign owner read, unauthorized status, inert admin text and
  foreign screenshot denial. The remaining local negatives are SC018
  `report_flood` and SC020 `agent_admin_attempt`; no complete negative matrix
  or external gate is claimed. Authenticated negative probes use actual HTTP
  requests from browser contexts, explicitly distinct from UI clicks.
  Local operations artifact SHA-256
  `e94cf5cd4e48e50bc1678ba1b49677143e3813a689caa3f8d4cb67067f67cac1`
  passes separate live read-only PG replay: control revision 2, two new audit
  events, no domain changes. Actual target and all-four-native-client gates
  remain blocked. Existing restore rehearsals retain their original source
  databases; this capture has not undergone a new backup/restore rehearsal.
  Separate live observer transactions confirm five reports, seven audits, two
  attached normalized images, zero chunks and zero ledger entries. Two runs,
  one task and one immutable action are the retained synthetic authorization
  fixtures, not executed benchmark work. Admin close/reopen persists revisions
  2/3 and exactly two status audits. A read-only native-volume inspection finds
  exactly two private WebP files, mode 0600, each 24,786 bytes and SHA-256
  `b21455ad59dcec1c7f6c386917d9209c52e7961377680ca89bb564918842332f`,
  matching the attached database rows. Both happen to contain the same
  screenshot bytes; authorization was tested against their distinct owner IDs.
- Ranked terminal readback independently confirms twelve known evaluations:
  eleven passed 1/1 and S2 partial 7/10. The exact weighted overall is `1285/13`
  out of 100; simple tier `185/2`, other tiers `100/1`. Aggregate/handoff,
  version snapshot, completion/eligibility event hashes, first-action marker and
  best-result pointer bind to the completed run. This verifies persisted
  internal/public-eligibility records; public HTTP/UI rendering remains unrun.

## 29 October: requested local restriction checks closed

Implementation checkpoint `b3c8549` committed the previous approved work. The
three Luna/max continuations then implemented/reviewed report negatives, bonus
restriction evidence and a [launch checklist](poc-beta-launch-checklist.md).
The final runtime captures below share one unchanged 689-path R14 root inventory
(SHA-256 `798da5fd63e32579fe9ccb934cb5e7350987e3c561fd6a1df57eb24e061439fa`);
each producer also retained identical before/after 392-input inventories.

- Reports: capture `50103cbf-ee58-446d-b460-79658d220bce` exited 0 with no
  local failures. Root independently replays all eleven owner/admin positive
  observations and all thirteen SC018/020 negative variants, including flood
  and four cookie-free agent attempts against admin list/detail/status/image.
  SC018 runtime SHA-256 is
  `0496a7b5ee0dfb657dad2cb22cd9f056290bb7ceb0a07bfeb2cbd1c599bee187`.
  Separate live observer reads confirm counter 12 -> 122: 108 invalid requests,
  one threshold-crossing 429, then a valid-shaped 429; the intended limiter
  counter changes while report/domain projections remain equal. Both private
  WebP files match their two attached DB rows (24,786 bytes, mode 0600); final
  counts are five reports, seven audits, two uploads and zero ledger entries.
  The four malformed staging rows naturally disappeared before the foreign
  upload baseline; the isolated aggregate failed-upload receipt count changed
  0 -> 4. No per-upload receipt-ID binding is claimed.
- Bonuses: capture `c75b3094-345f-4794-9a6b-5530af1b92fe` exited 0 with no
  local failures. Its SC005 runtime SHA-256 is
  `f0b7c6a3865a1e82afdbce0115d0d5dafd045fee282c16a8cac26e8c56be33cf`.
  `python -B -m tools.replay_bpc_bonus_local` independently verifies UI
  issue/claim/ledger lineage plus anonymous and preflighted-agent claim denials
  (401), owner intent creation with training disabled (403), per-operation cap
  denial (409) and zero-bonus admission without cash permission (409).
  The permission negative is explicitly an authenticated browser HTTP probe;
  actual intent creation/cancellation and code issuance/redemption use UI clicks.
  Separate live PG readback confirms both denied-claim codes remain unused,
  all denied operation IDs are absent, both HTTP fixture intents are cancelled
  with exact training selections (S1 and canonical open8), and there are zero
  runs, reservations, budget holds or reserve/debit entries.
- The cash-sufficient `bonusOnly` proof remains a separate synthetic direct-service
  boundary: a code-derived 250,000-unit bonus lot, 1,000,000-unit quote,
  2,000,000 cash units and cash permission still produce
  `BETA_BONUS_BALANCE_REQUIRED`, with unchanged source balances and no acceptance.
  It is not a beta-manifest HTTP or model proof. Its fixture intent stays pending
  in the stopped isolated instance; no executor environment or hold exists.
- Focused regressions pass: four Node intent/secret-guard tests and fourteen
  Python raw-verifier tests. Syntax checks, strict OpenSpec validation, 26/26
  semantic harness audit and 26-scenario mirror validation pass. These structural
  checks do not change mandatory environment gate states.

The retained intermediate attempts explain the harness fixes: `f719b1d6` lacked
the explicit local run policy; `0898a27b` exposed the nested API quote contract
and left one pending fixture intent; `28fb5162` hit a secret-text false positive
on an internal schema label whose suffix was exactly 43 characters; `33490f9e`
captured the flows but its direct-service projection omitted ledger owner/actor
columns, so offline replay failed. Those columns are now observed explicitly;
the secret guard was not weakened. `dc66fa2f` passed before the final report
fixture adjustment. Report attempt `e5c29241` failed while concurrent natural GC
removed four malformed staging rows; exact failed attempt counters were not
persisted, so the causal diagnosis is supported by receipt timing and source,
not a recovered request snapshot. A bounded read-only wait now separates that
known setup cleanup from authorization measurements. All failed/predecessor DBs
and artifacts remain retained; no previous failure is relabelled passed.

The requested local flood/admin/bonus checks are closed. Actual target Google,
four native model/client families, trusted recovery integration, combined restore,
load/queue/public-page acceptance and pilot/release remain open in the checklist.
Official BPC manifests stay `blocked`; no sync/archive or beta release is claimed.

## 29 October: recovery and combined-backup implementation checkpoint

Commit `2ccac73` records the trusted bounded recovery monitor/authority,
source-backed S1 evidence, fixed 180-second recovery/refund boundary, and the
sealed combined checkpoint/restore provider, Windows operator broker, separate
key recovery and bounded daily/pre-migration rotation. It is an implementation
checkpoint, not successful combined runtime acceptance.

Capture `1f375cdc-b843-4512-92bb-f709dd0a98f1` independently observed the S1
run `54e79893-cd1e-4a50-a1c9-1e9d559d4638` complete after the proxy consumed
the real upstream response and dropped it. The receipt became `observed`, the
recovery row became `recovered`, and the original environment lease was fenced.
No response wire hash was invented from the durable BEF measurement. The earlier
attempt `01abb409-11ac-445e-9a04-fd4ed74feb14` recovered its receipt but blocked
grading; it remains failed evidence rather than being relabelled successful.

The combined capture then stopped before the exhaustion run: the worker-funding
fixture required the owner's total bonus balance to equal the newly issued lot.
The first run left 66,666 units; a second 100,000-unit redemption correctly made
the total 166,666. This exposed an incorrect fixture assertion, not a missing
grant or an exercised recovery timeout. Its recorded wrapper reason is
`recovery_exhaustion_terminal_not_captured`. No combined backup was produced by
that attempt. The corrected fixture verifies the exact before/after delta and
the new grant's own ledger lineage.

Separately, the concrete dump/restore provider copied 88 tables / 124 rows from
the stopped earlier source to fresh database
`oid_restore_bfc5ce74491f40529dc880dc05ebbb72`. Independent source-before,
restored and source-after fingerprints and sequences matched, with totals hash
`9d6d0a8bde61ae459d4d303cc46889dfa2f4444481e75601c61bae78f0a3317f`.
That source contained no reports/screenshots, so this remains database-provider
evidence only. The full combined screenshot/application/retry rehearsal and
the remaining chain-collector recovery paths are being checked separately.

### Subsequent recovery attempts (29 October)

Capture `02a9e632-6993-43a7-a902-c022c9d686d5` retained a complete core recovery
stage under `artifacts/runs/beta-platform-recovery-stage/`. Independent raw replay
verifies the original settled S1 action, fixed recovery window, ungraded exhausted
run, one original-source bonus refund, exact fence/claim/slot release, and actual
API restart. The S4 collector then reconstructed its lost response from the
selected BEF operation/measurement and matching RPC receipt/cost. Automatic
grading and fencing completed, but the capture stopped at an invalid harness
assumption that the owner had no historical refunds. The corrected assertion
preserves the entire owner-money fingerprint, compares the refund count with
the admission baseline, and additionally rejects any refund linked to this run.
The S4 source evidence has no invented raw HTTP response hash or status.

The raw reader also now checks the cancellation event's actual fence hash instead
of requiring that field on a separate failure event. A restart may begin after
the committed-response loss and overlap incident persistence; its health check
must complete within the original recovery window. Negative tests reject a
restart before the fault, wholly before recovery, or after the fixed deadline.

Fresh capture `dee69b82-f980-45d2-a7ad-091f9d7393ba` independently completed its
first S1 recovery, but the exhausted case did not finalize after API restart.
It remains failed: receipt/recovery stayed unknown, no refund/fence was claimed,
and bounded harness cleanup requested owner cancellation. Its database and
original environment bindings are retained. Code inspection found a separate
startup defect: the server ignored a false coordinator advisory-lock acquisition,
although that lease object could never become active afterward. That defect is
being repaired with bounded fresh-instance retries and fail-closed startup;
the historical capture alone does not prove lock contention caused its failure.
Neither attempt reached a combined checkpoint or passed the full target gate.

The R23 database records six recovery-observation events after restart; therefore
startup lock contention is not established as its cause. The observer driver used
the default exponential reconnect delay, capped at 20 seconds per attempt.
Its reconnect backoff is now 500 ms;
an actual TCP-proxy regression resets twelve PostgreSQL connections twice, then
verifies a real `bef_observer` read-only repeatable-read transaction in each
cycle. Separately, the monitor now returns expired run IDs for fencing before
performing another source read; the isolated PostgreSQL regression verifies zero
observer calls, no inferred receipt, no grade and no refund at that transition.

A guarded production-coordinator resume of the exact R23 database, run and
preparation completed the pre-existing owner cancellation in one tick. The
original preparation is fenced, claim released and active slot count zero.
The original action remains unknown, with no new action, intent, run, charge,
grade or platform refund; owner-voluntary cancellation is preserved. Capture
and attempt file hashes remain unchanged. This cleanup does not promote R23.

Capture `a4df1bb2-5be3-4554-9284-53863ec1c21f` then exposed an acceptance-only
race: the first post-restart snapshot preceded the monitor's asynchronous
recovery-row insert. The waiter now polls within its existing bound and verifies
the observer/database/run/action identities on every snapshot; missing forever,
foreign and unrelated terminal states fail closed (17/17 focused tests pass).
Independent R24 readback confirms its ordinary cancellation fenced both retained
preparations; no refund or grade was claimed for the failed exhausted case.
The reader now proves the entire persisted recovery window is contained in the
actual outage interval instead of incorrectly demanding another full 180-second
callback wait after API restart (25/25 raw-reader tests pass).

Capture `5dda14a3-81c7-4cd9-9400-97f606b667c9` on commit `07428dc` passed the
core recovery/exhaustion stage and full S4 worker completion/UI/funding checks.
The retained core artifact SHA-256 is
`4ba48dcd2f682d37b12fd8b4246e13e7f3bd2f4da9ad432a4f82b0c13f66d5e4`.
Raw replay and independent file review verify one original submission, exactly
180,000 ms recovery/exclusion, one 33,334-unit bonus refund and no exhausted-run
grade. S4 evidence SHA-256 is
`60d504672293d37a4d0e01e97a6bf3b255b453a30b060a03f10b21006919f14b`.
Its newest issued lot remains unused; the run correctly consumes an earlier
code-derived lot. The worker-funding proof now verifies all consumed lots against
their own code/redemption/claim records and exact reserve/debit totals.

M3 reconciled the original approve and observed the subsequent swap/unwrap, but
could not publish its observation packet (`capture_evidence_unavailable`), so
the full capture remains blocked. An initial token/spender-shape hypothesis was
rejected: the collector already projects resolved public-address responses into
logical selections. The reproduced defect is the selected-event contract: the
collector emits the original event's `eventJsonSha256`, while the writer's exact
packet validator and fixture omitted that key. The fixture now reproduces the
emitted shape and the validator requires a valid SHA-256. Real-writer tests cover
acceptance/replay and malformed hashes; negative cases recompute the surrounding
census hashes so rejection cannot be attributed merely to stale outer hashes.
The focused suite passes 22 tests with one existing retained-fixture skip; the
owner-identity typecheck passes. Token/credential guards remain unchanged.
Normal cancellation fenced the M3 preparation;
the failed capture and database are retained and no M3 grade is claimed. The
earlier all-eight/full12 captures remain historical proofs for their own builds.

Capture `3529bb1e-1ef8-4797-a846-7b090f626cab` exercised the delayed recovery-row
path successfully, then exposed another waiter race at the cutoff: the production
coordinator had already fenced/cancelled the run for platform failure while the
observer was still intentionally blocked. The waiter incorrectly rejected that
intermediate `cancelled` state before allowing source reconciliation/refund.
Independent readback confirms the original fence and platform cancellation, no
grade and no claimed refund. The transition matrix now accepts only the expected
platform `cancellation_requested`/fenced `cancelled`/unresolved `unknown`/final
`failed` states after the persisted cutoff, still waits through the observation
margin, and retains the separate final proof (19/19 tests). Owner/revocation,
foreign, success and premature terminal states remain rejected. This attempt
remains failed evidence rather than being relabelled successful.

On commit `87d287f`, capture `a8dd2394-0b24-4a60-9780-023c2cfe0248` completed
the core recovery/exhaustion, S4 and M3 worker paths. M3 genuine artifact SHA-256
is `18d02b6b2b86e7fc7602a009ad2d475ce7ad255ad56911ac5e948cb00cce854e`;
its known grade is 1/1, with zero original-action resubmissions. Its two code-derived
bonus lots total 66,667 units, with two reserve/debit pairs and no cash or run refund.
Root independently compared all 12 event JSON hashes from observation packet
`69a29c243c0033805c886fe140956054fe2f02e3f92bebbe529f4e5081284b55`
with the actual BEF rows under `bef_observer`; every hash matches. The complete
combined run then stopped because the browser report helper populated only Run ID,
although the combined case requires the real Task ID and Action ID too. Those
existing UI controls are now filled and the accepted request bindings checked
(23/23 focused report/recovery tests). The complete recovery stage is now saved
separately before report/backup work, preserving its independent replay boundary.

Separately, the exact pending R26 refund was resumed by normal coordinator ticks
after its API had stopped. A subsequent independent read-only verifier confirms
original receipt `observed`, run `failed`, recovery `refunded`, exactly 180,000 ms
exclusion, one 33,334-unit refund to the original bonus grant, and zero grade/cash
refund. Its observed-receipt hash binds to the observed recovery row; the separate
exhaustion hash binds to recovery latest/refund/audit/failure event. Original
capture files and run/intent/action/claim counts remain unchanged. The failed R26
wrapper is retained as failed evidence; this is a separate resume/readback proof.
