# Implementation review and runtime evidence

This is a local implementation review, not an acceptance decision. The active
spec and approved BDD contract remain normative. Browser-to-database product E2E
belongs to delivery stage 2; these BEF checks exercise the environment boundary.

## Observed results

- Synchronized-main acceptance passed 20 mandatory scenarios and six traceability
  tests in 260.21 seconds, exit 0, without skipped/blocked scenarios. The semantic
  audit passed 20/20 and the accepted harness-source hash remained unchanged.
  Report SHA-256: `2439b5c93a56acc42ce31fe0a7009c1c60878063b6f9ef0b1c7f3f7bdb400c51`.
  Python regressions passed 332 tests with four platform skips and six subtests;
  package TypeScript type checking passed. Parent offline replay of real saved
  SC004/005 captures matched synchronized-main predicates and preserved all
  original tree hashes. Main profile selection is explicit/versioned; mixed
  active/main bindings and downgrade attempts fail closed.
- Main synchronization added the BEF capability without changing either original
  main spec's bytes. The main harness now retains eight baseline scenarios and
  the twelve BEF scenarios with their original environment gate classes and
  adapter profiles. Strict OpenSpec validation passed 13/13, the semantic audit
  passed 20/20, and focused source-selection/traceability tests passed 21/21.
  Main runtime acceptance and post-archive checks remain separate closeout work.
- Harness-source integrity now also covers the offline replay tool, resource
  orchestrator and resource sampler. Parameterized regressions verify that
  changes to each existing helper change the main harness fingerprint; the
  focused source-selection suite passed 18/18 after this addition.
- Final active-delta acceptance on 2026-10-25 passed all twelve mandatory
  environment gates in 436.94 seconds. The semantic audit passed 12/12, exit
  code was 0, and `source_unchanged` was true. Preserved report:
  `artifacts/runs/acceptance/acceptance-twelve-gates-20261025-v4.json`
  (SHA-256 `9424ac4db4d8dcea2948ada7c153b6687045204119507671458b961f108f806c`);
  log: `artifacts/runs/bef-final-twelve-gate-acceptance-v4.log`.
  This supersedes the aggregate status of the earlier attempts below; their
  failed captures remain unchanged. Main-mode sync/replay acceptance is a
  separate closeout check.
- Private reset/generation setup now uses the manifest's 120-second setup
  budget, capped by the remaining overall trial deadline. Participant and
  facilitator calls retain their existing bounds; no HTTP retry was added.
  Safe transport-failure observations retain only method, pathname, boundary,
  operation/variant, elapsed time, timeout and an allowlisted error class.
  Focused transport tests passed 4/4. Earlier generic fetch failures do not
  establish their cause; the new diagnostics avoid guessing it.
- After the final suite, an independent database read found zero unresolved
  operations. The remaining active A generation was protectively fenced,
  with independent database/RPC verification and no reset or new payment:
  `artifacts/runs/bef-v4-passed-fence-A/fence-active/fence/fence-verification.json`
  (SHA-256 `a0e17427fdc677d392b4428565af474f6467703aae258b934a94017ee60a0537`).
- Deterministic fixture preparation now requires the pristine pinned source
  head, pins the funding transaction to source timestamp +1, retains the actual
  funding receipt/token effects, then restores/verifies the donor's declared
  private fixture native balance without another mined block. Strict SC009/010
  baseline oracles are unchanged. Parent TypeScript and three helper tests pass;
  fresh SC009 passes in 25.32 seconds and SC010 in 20.56 seconds, including
  post-verification cleanup. The full 51-test Node/PostgreSQL run passes without
  skips (`artifacts/runs/bef-pinned-fixture-node-postgres-ready.log`). Its initial
  invocation coincided with gateway startup and got ECONNREFUSED; the failed log
  is retained separately. A fresh SC001 then passes in 33.84 seconds. New full
  acceptance remains required; no sync/archive has been performed.
- The second complete run finished with 8 passed and 4 non-passing gates in
  281.17 seconds; preserved report:
  `artifacts/runs/acceptance/acceptance-eight-gates-20261025-v2.json`, log:
  `artifacts/runs/bef-final-twelve-gate-acceptance-v2.log`. SC001's reset request
  failed at transport; existing evidence cannot distinguish timeout from other
  fetch rejection. A same-source focused SC001 passed in 22.09 seconds.
  SC009/010 exposed true fixture baseline drift, not an oracle defect: donor
  native balances differed by variable funding gas (99999627118000000 versus
  99999627046000000 wei), and initial funded block timestamps differed by one
  or two seconds. Complete-baseline predicates remain strict; private fixture
  preparation must pin these before another acceptance run. SC011 correctly
  blocked because preceding failed isolation/reset gates left active work.
  Both environments were protectively fenced with independent DB/RPC proof;
  no unresolved operation remained. SC006 passed after its wire-body correction.
  A separate evidence-tool fix excludes generated result maps from the source
  digest, hashes the final map separately and rejects actual source changes
  during acceptance. Its fifteen tests passed; prepatch backups are under
  `artifacts/runs/bef-source-fingerprint-prepatch`. No earlier report is rewritten
  into a pass. Final regression checks before this tooling fix passed 311 Python
  tests (four skips, six subtests) and all 48 Node/PostgreSQL tests (no skips).
- The first complete final-source acceptance run finished with 9 passed and
  3 failed in 252.20 seconds. Its raw report is preserved at
  `artifacts/runs/acceptance/acceptance-nine-gates-20261025-first.json` and log
  `artifacts/runs/bef-final-twelve-gate-acceptance.log`. Failures are not passing
  results: SC001 omitted two observed Anvil profile fields from runtime metadata
  despite correct ethereum/Prague capability responses; SC006's response-loss
  wire body omitted offerId while its evidence record included it; SC011's raw
  cold/warm/overrun orchestration completed, but its index secret filter did not
  recognize the new payloadSignatureSha256 digest metadata. All original
  captures remain unchanged. Corrections preserve the profile assertions,
  forward/record one canonical body, and permit only the exact hex64 digest key.
  A fresh complete suite is required after these corrections.
  SC009/010 post-verification cleanup succeeded with separate evidence under
  `artifacts/runs/bef-generation-cleanup`; it closed both declared environments
  and allowed SC011's strict preflight to proceed. Further reviewed cleanup
  hardening binds the workload's fence-report path/hash/status and rejects extra
  or unsubmitted payment rows. Exact promotion hashes/backups are recorded in
  `artifacts/runs/bef-cleanup-hardening-promotion.json`; its eleven tests pass.
  Parent checks passed 303 Python tests (four platform skips, six subtests) and
  all 48 Node tests with PostgreSQL (no skips). Private verification-only SC005
  subsequently passed fresh in 11.36 seconds; SC004 replay setup passed in 5.70.
- Final replay-reference preparation exposed a SC005 regression after immutable
  offer selection was introduced. Capture `bef-sc-005-2c961a5b79a34bbdabd283808740298b`
  stopped at private facilitator verification with 403: the direct verify probe
  omitted the required operation request hash. The corrected probe reads that
  exact hash from its scoped observer snapshot. Capture
  `bef-sc-005-ca56b683266c4e33900100bef3fdecf0` then reached the stricter offer
  check and received 409 because the no-settlement verification fixture remains
  awaiting_payment. A narrowly scoped private-variant verification timestamp
  path is being implemented; it must retain awaiting_payment, immutable choice,
  active-generation authorization and unchanged settlement rules. Neither
  failed capture is a pass. Both environments were fenced; the post-fence DB
  independently reports zero active generations and zero unresolved operations.
  The original raw logs and API cleanup responses remain preserved.
  Full-suite lifecycle review also found SC011 requires no active generation
  from preceding probes; successful per-scenario cleanup is being added with
  separate fence evidence, without relaxing SC011 preflight or resetting state.
- Fresh SC010 passed in 14.17 seconds: `bef-sc-010-9b3b1943baba4b04826305cc03b96ed2`,
  8 operations, 324 artifacts; index SHA256
  `606024b16c0cf668a261bcf3f5589e33d728d90bf15607314b75ecd54d40d747`. Baseline/reset and post-stale chain/service state
  are exact; old paid state is unchanged, stale generation requests are denied,
  and fresh separately identified purchases/swaps succeed with receipt-backed
  gas normalization only for post-trial native balance equivalence.
  Summary: `artifacts/runs/bef-sc010-passed-observation.json`. Tasks 5.2/5.3 are
  closed (22/25 total). The earlier error capture
  `bef-sc-010-d89e7485b8dd4035b7e0896d6b70ebe7` remains unchanged: its second
  generation reused an evidence filename after successful wrap. Probe labels now
  include generation/operation identity; TypeScript passed. Both failed and
  passed generations were protectively fenced after independent DB/RPC checks.
  The reviewed Python follow-up and backups are recorded in
  `artifacts/runs/bef-sc010-fee-equivalence-promotion.json`; parent checks pass
  63 adapter tests and 298 full regression tests (four platform skips and six
  subtests). Logs: `artifacts/runs/bef-sc010-receipt-fee-runtime.log` and
  `artifacts/runs/bef-sc010-receipt-fee-regression-python.log`.
  All twelve scenarios now have separate real passing runs, but final combined
  acceptance on the same final code is still pending; no sync/archive yet.
- Fresh SC009 passed in 21.30 seconds: `bef-sc-009-fb2a38164a594921bdb2bdfa313c1b95`
  with 8 operations and 369 artifacts. Probe index SHA256:
  `dafbaaff2a61e80437c0d616ff440e5848854a259c2addb0fc939f6a245550c4`. Both environments executed canonical purchases,
  wrap/approve/swap, foreign requests were denied, and resetting A preserved B's
  complete observed state. Every snapshot/receipt is bound to its environment's
  endpoint and hashed health proof. Summary:
  `artifacts/runs/bef-sc009-passed-observation.json`. Both active generations
  were protectively fenced with independent DB/RPC proof. The first B cleanup
  command stopped at an import error before any action; the module invocation
  succeeded and both logs remain preserved. Task 5.1 is closed (20/25 tasks).
  The seven-file reviewed promotion, backups and exact hashes are recorded in
  `artifacts/runs/bef-sc009010-reviewed-promotion.json`; parent TypeScript and
  all 52 adapter tests passed. SC010's post-trial gas-equivalence correction is
  still pending; this does not close SC010 or the combined twelve-gate report.
- Independent Luna/xhigh review blocks SC009/010 promotion on two concrete
  candidate defects. Snapshot reads and receipts must join their own endpoint
  binding and hashed health artifact; two unrelated binding records do not
  establish independent chains. SC010 post-trial equivalence must reconstruct
  exact observed gas effects rather than equating native balances across fresh
  signatures. Actual SC002 alternate-payment receipts used 0x19198 versus
  0x191b0 gas at the same 0x318202 effective price in captures 352346... and
  993b9f..., demonstrating the legitimate difference. Baseline-to-reset chain
  restoration remains strict. Candidate fixes and negative tests are underway;
  SC009/010 gates and tasks remain open.
- Fresh SC002 passed in 10.75 seconds with nine operations and 357 artifacts:
  `bef-sc-002-993b9f6e745845eeac6e2bc4598feeb0`, index SHA256
  `9fb0c1af22d79dc0bcf3509dce03fc1572cb6aca2405dbe0b0cc17e719226e82`.
  All eleven named strict checks pass, including both explicit paid offers,
  receipt-backed wrong-recipient/excess-allowance execution, observed goal
  mismatches and same-payer wrong-domain protocol rejection without effects.
  Summary: `artifacts/runs/bef-sc002-passed-observation.json`; mapper log:
  `artifacts/runs/bef-sc002-strict-final-runtime.log`. Protective fencing passed
  independent DB/RPC verification. Prior failed captures remain unchanged.
  This closes task 3.1 and completes the remaining task 1.3 pins: funding,
  canonical/alternate offers, tool schemas, fee conversion/payer attribution,
  precision, numerical guardrails and the task-goal versus hard-boundary split
  are explicit in the manifest and observed across SC002/007/008/011.
  Final regression checks pass: 235 Python tests, four platform skips and six
  subtests (`artifacts/runs/bef-sc002-passed-regression-python.log`), including
  21 SC002 tests with five-action proof and negative mutations.
  Progress is 19/25 tasks; the complete twelve-gate suite is still pending.
- The latest SC002 runtime completed its purchases and five selected actions,
  but the strict mapper is still failing; task 3.1 remains open. Capture
  `bef-sc-002-352346aea3cb4c8cacb5a9bf9364569b` preserves the actual unsigned
  challenge and signed same-payer wrong-domain rejection, with the payer public
  address projected safely from the SDK payload. All five action transaction,
  receipt, database and event joins pass the reused SC007 action validator.
  Remaining review findings concern summary-boundary naming, selecting the final
  generation snapshot among three actual reads, and the distinct audit-denial
  hash versus operation-request hash. They must be fixed without relaxing the
  underlying proof. The generation was protectively fenced with independent
  DB/RPC verification; no failed capture was rewritten.
  Parent checks passed all 47 Node tests against the separate migration database
  with zero skips (`artifacts/runs/bef-sc002-protocol-oracle-node-postgres.log`),
  plus 189 unit tests, four platform skips and six subtests
  (`artifacts/runs/bef-sc002-oracle-review-python-host.log`). The initial sandbox
  unit invocation could not create pytest's temporary directory; the ordinary
  host rerun passed. Strict OpenSpec validation and the active-delta semantic
  audit pass; explicit SC002 check names preserve static traceability.
  SC009/010's seven-file candidate has been rebased to the current shared source
  and passes its 44 adapter tests and TypeScript check; it remains unpromoted
  pending independent review and actual execution.
- SC002's reviewed 23-file overlay is promoted with exact byte hashes and backups
  in `artifacts/runs/bef-sc002-reviewed-promotion.json`. The public facilitator
  request projection preserves transfer fields and a signature digest through
  the actual evidence sanitizer, while omitting signing material. Parent checks
  passed TypeScript, all 44 Node tests with PostgreSQL (no skips), and 228 Python
  tests (four platform skips, six subtests). A module-level predicate import
  caused a collection-time cycle; a narrow lazy import fixed it.
  The deployed SC002 application source is
  `11577c0ab6e97c40057246271f18728f6ac3bbfd5aa6a668988ad125ec38084f`.
  Two actual failed captures remain preserved: `bef-sc-002-b0742c4ba0504942ac8522521325b7f1`
  stopped because the new RPC reader lacked endpoint binding; the binding is
  now initialized. `bef-sc-002-0ca74135fd1f4fe2a2061e5db293c2a0` then reached
  selected execution but rejected before broadcast because the payment-only
  generation setup did not register its ephemeral signer for execution.
  Both generations were protectively fenced with independent DB/RPC evidence;
  no unresolved transaction remained. SC002 runtime acceptance is still pending.
- Fresh SC008 passed in 15.60 seconds with six operations and 284 artifacts:
  `bef-sc-008-ceac18cb8e404e5ab1e49beefb683fda`, probe index SHA256
  `dc08d4c3b2cadc237a1abaf4f091fed6c2cabee1b9771a8a8c2b4e8cef7e5c54`.
  App source is `d88fd585a6969b4d10e31e011912b504894c3de0767f224917fe2fb5ec4d91bd`;
  probe source is `9be8b7358180d71b08164fe7fd239de78d81b9d256e0388fe68130757b9c2277`.
  This closes tasks 4.3/4.4 (17/25 total). The mapper confirms receipt-backed
  successful/reverted gas, pinned conversion, actual payer, principal/service
  separation, no invented rejection fee, unknown-to-original-hash recovery and
  explicitly unmodelled Base L1 fees. The generation was protectively fenced
  with independent database/RPC verification, without reset or replacement.
  Summary: `artifacts/runs/bef-sc008-passed-observation.json`; mapper log:
  `artifacts/runs/bef-sc008-operation-generation-runtime.log`.
  Earlier failed captures remain unchanged. The combined twelve-gate acceptance
  report still requires a fresh run on the final implementation.
- Corrective migration 004 preserves every receipt-shape predicate from 003
  except the reviewed base-fee comparison; 003's checksum remains unchanged.
  Actual PostgreSQL migration and persistence-finalizer regressions passed.
  It was applied to the acceptance schema without resetting either node.
  The original reverted unwrap is now terminal in operation, selected execution
  and cost rows, with 23707 gas at 5375195 wei (127429747865 wei total), zero
  observed principal, and its generation still fenced. Independent verification:
  `artifacts/runs/bef-sc008-original-unwrap-final-verification.json`.
  The reconciler's post-commit check incorrectly expected a `0x` prefix on a
  plain SHA256 digest; that failed log is preserved and the database result was
  independently checked rather than blindly retried.
- Fresh SC008 capture `bef-sc-008-80ca4e57621647c29581ad94d1e8bc73`
  completed its runtime flow with 284 artifacts, but the mapper failed: its
  validator compared earlier operations to the final generation ID after resets.
  This is not a gate pass. The remaining active generation was protectively
  fenced without reset; no unresolved operation remained. Per-operation
  generation binding must be fixed and a fresh gate rerun is required.
- SC002's renumbered migration 005 passed both tests with no skips in the fresh
  `bef_migration_test_sc002_v2_20261024` database, including corrected migration
  004. Log: `artifacts/runs/bef-sc002-candidate005-postgres-reviewed.log`.
  Its candidate remains under review; it has not been promoted.
- The SC008 fee correction accepts an observed declining block base fee under
  the pinned ceiling and recomputes the exact EIP-1559 effective price. Parent
  checks passed TypeScript compilation, eight cost tests, sixteen strict-oracle
  tests and one real PostgreSQL test (zero skips); logs are
  `artifacts/runs/bef-sc008-observed-basefee-{tests,predicates,postgres}.log`.
  This does not yet establish a fresh SC008 gate pass.
- The separate SC002 candidate migration 004 passed both migration tests against
  `bef_migration_test_sc002_20261024`, including real SQL offer/timestamp
  immutability, NULL rejection, and legacy terminal rows remaining unselected.
  Evidence: `artifacts/runs/bef-sc002-candidate-postgres-reviewed-uri.log`.
  This is candidate validation, not SC002 promotion or runtime acceptance.
- The resumed SC008 deployment built successfully as image
  `sha256:2402ca421cdc94909acf378d0d1a7c426819172251ab19fc4182f08e6753ec49`;
  migrations 001–003 match their recorded hashes. A stale external pnpm shim
  prevented the first probe from starting; the adapter now uses the installed
  package-local tsx loader with Node directly (68 adapter unit tests passed).
  The next real capture, `bef-sc-008-81289bc39a9d48a6935015b7ecc02765`, failed
  after an actual reverted unwrap: cost validation incorrectly required the
  receipt block's EIP-1559 base fee to equal the initial manifest base fee.
  Original receipt evidence is preserved in
  `artifacts/runs/bef-sc008-reverted-original-receipt.json` (SHA256
  `25b1bb8dd40f677dd8da53ca97723fd2a7594826f63adf5cfb71b387fffa8e03`).
  The generation was fenced without reset or replacement transaction; at that
  point its original operation remained unknown pending reviewed reconciliation.
- SC008's reviewed 22-file candidate was promoted; the exact file hashes and
  pre-promotion backups are recorded in
  `artifacts/runs/bef-sc008-reviewed-promotion.json`. After restoring Docker,
  all 38 Node tests passed with the dedicated real PostgreSQL database, with no
  skips: `artifacts/runs/bef-sc008-promoted-node-postgres-restored-tests.log`.
  The earlier attempt is retained separately and failed because PostgreSQL was
  unavailable. Runtime SC008 acceptance remains pending. Review also found that
  the new secret-safe RPC projection removed selected-execution calldata needed
  by SC007; the fix must preserve exact ABI evidence without exposing payment
  authorization calldata. Windows now reserves port 14021; this resumed local
  deployment uses `BEF_FACILITATOR_A_HOST_PORT=34021`, recorded in
  `artifacts/runs/bef-resumed-local-runtime-20261024.json`.
- Fresh SC011 passed in 140.40 seconds:
  `bef-sc011-d8bf6a020d3748a689b54dc757109992`, two purchase operations and
  268 indexed artifacts. Probe index SHA256:
  `a7667d0e4a05423730adae0b8588fe3c00a8fa5abbd96f5b28f4db54a86248f4`.
  App source remains `9660df8e3ba697f8efbce9769eb73223aa0df22284dd1ebc03f022a37e6b091b`;
  probe source is `34c062cc3ad83ed20879f52123cd1ffc8bc5c4234915e60b8adca08beb465d47`.
  This closes tasks 6.1/6.2 (15/25 total). The raw orchestration took 137.125 s;
  cold/warm workload windows took 20.891/11.640 s. The prepared cache contained
  24376 bytes and survived the same-bind restart. The read workload was stopped
  after an observed 2890 ms against a 2000 ms bound, with confirmed process-tree
  exit and independent no-effect/fence evidence. Post-run observer counts are
  active=0, unresolved=0. Summary: `artifacts/runs/bef-sc011-passed-observation.json`.
- SC011 records source-proxy window deltas of 59 cold and 16 warm forwarded
  requests. Their precise attribution remains unknown; they are conservative
  aggregate-window observations, not exact per-operation counts. Provider CU
  remains unknown. Sampled current RAM is separate from reused-container lifetime
  peaks, and startup CPU/RAM is not sampled. These development-host measurements
  establish no production-capacity claim. Parent regressions passed 187 Python
  tests (four platform skips, six subtests), plus TypeScript and seven probe tests.
- The final SC011 validator fixes preserve raw sampler statuses and derive
  unresolved collector metadata from independent orchestration evidence. Only
  the declared metadata codes are permitted; actual missing metrics still block.
  Terminal purchase DB groups are joined to their own request, generation,
  capability-derived facilitator, receipt, token effects and delivered bytes.
  Extra diagnostic `primary` reads are restricted to the two actual cleanup
  fences. All ten predicates were first recomputed on the immutable earlier
  indexed capture; the fresh full pass above is separate execution evidence.
- SC008 migration `003_transaction_costs.sql`, SHA256
  `5384ebbe9aec4e39b23036e6918e9c065dbf8ba63b047be0f0773be6d00f3623`,
  passed a real PostgreSQL regression in the separately created
  `bef_migration_test_sc008_20261024` database: one test, zero skips.
  Missing/extra/type-invalid fee-policy fields reject, null unknown markers
  finalize by original identity, and final rows are immutable. Evidence:
  `artifacts/runs/bef-sc008-candidate-postgres-reviewed-final.log`.
  This was a migration check in an ignored candidate. Promotion and the broader
  PostgreSQL checks are recorded above; SC008 runtime acceptance remains pending.
- SC011 `bef-sc011-1bac21f3abcc45f2af1dac1bc0113b54` completed actual cold,
  warm and overrun workloads, produced a captured orchestration and loaded a
  complete hash-indexed probe. Its 114.19-second mapper failed independent
  validation. Offline review found integration assumptions in the validator:
  individual samplers intentionally retain unresolved orchestration metadata,
  canonical snapshots use the `primary` variant, and repeated pre/post DB
  snapshots need exact phase/operation joins. Guardrail DB selection also
  collided with cold/warm fence filenames. These remain acceptance defects;
  the original indexed run is preserved and SC011 tasks stay open.
- The preceding SC011 `bef-sc011-b7bf683ab5de41a4b284270f1ba64e85` completed
  all workloads but failed indexing because the fence summary embedded raw
  copies of paid-generation protocol rows. Fence reports now use the existing
  sanitizer for exported DB copies while raw snapshots still drive equality.
  Parent TypeScript check and all seven focused tests passed. The secret
  validator was not broadened; the subsequent indexed capture above confirms
  the report fix.
- SC011 `bef-sc011-28680bbf840d4f9482d3cbf74fc02ee9` reached actual guardrail
  stopping after both purchases: 2469 ms against a 2000 ms bound, confirmed
  process-tree exit, observed first-read readiness and a captured generation
  fence. The 119.21-second mapper remained blocked because the report builder
  looked for the direct fence under an extra `fence/` directory. Its independent
  validator also compared millisecond observations to a seconds limit. These
  evidence-integration defects do not turn the failed capture into a pass.
- SC011 `bef-sc011-92998c02cc88451b856b974495b0153e` completed both actual
  purchases, their cleanup fences and exact warm-cache retention after restart.
  Anvil stopped with exit code 0, no OOM and no engine error; the prepared cache
  contained 24436 bytes. The gate still blocked after 114.69 seconds: its guardrail
  workload incorrectly expected the actual balances response to be an array.
  The actual HTTP 200 response contains a scoped object of decimal balance fields.
  Readiness also compared a checksummed address to lowercase with string equality.
  These collector defects are being corrected; no guardrail pass is claimed.
  Protective fencing succeeded, and independent DB reads confirm active=0 and
  unresolved=0. Both original successful payment observations remain preserved.
- Fresh SC006 passed in 17.98 seconds:
  `bef-sc-006-6edbb23297124edcab1a4b85a387916a`, four operations and 141
  hash-indexed artifacts. Wrong-domain/amount and reused authorization reject;
  the original uncertain payment is reconciled by the same hash, and real
  response loss plus overlapping retries retain one payment and one logical
  delivery. This closes task 3.4 (13/25 total). The earlier all-variant capture
  `bef-sc-006-b4527c1b6a09482eac6cec74ffbc7bfe` failed adapter predicates because
  they expected a nonexistent observer role and omitted signed protocol 402
  rejections. The fix checks actual SELECT-only privileges and read-only
  transactions, exact signed error/offer metadata, durable rejection and unchanged
  balances; an unpaid challenge or unknown 502 remains insufficient. Parent
  regression: 67 passed. Historical failed captures were not edited.
- SC011 cold purchases now execute with accepted resource metrics. The
  `bef-sc011-1b7bcb23d9594d59baa9c32fb984aa2b` capture exposed a missing host
  observation status; the collector now emits observed only after validating
  all required Docker host fields. The next capture,
  `bef-sc011-cb15493a6b5340ceb373ea7a8dbed6a0`, stopped at warm preparation:
  its RPC cache has one retained 420-byte file, while its state cache is empty.
  The predicate incorrectly required each root to be nonempty. No historical
  cache churn is established: the failed prewarm inventory was not saved.
  `artifacts/runs/bef-sc011-warm-cache-diagnostic.json` hashes the original
  orchestration and independently records the unchanged RPC file. Review calls
  for a combined nonempty prepared cache, inventories after cleanup and graceful
  stop, exact retention across the same-bind restart, and observed mutations
  during the warm workload. SC011 remains open pending a fresh full trial.
- The direct Node TSX loader avoids a hidden loader child in resource workloads.
  Protective fencing now uses a distinct `protective_only` purpose and a
  `protected` outcome, which never establishes resource acceptance. The fresh
  SC006 generation was fenced without resetting its paid state; independent
  DB/RPC proof is in `artifacts/runs/bef-sc006-complete-protective-fence.log`.
- The next SC006 capture `bef-sc-006-854e9150dadf4ee18b262b99a95b2608`
  reached reconciliation, actual response loss and overlapping same-key retries.
  Independent DB observation confirms one successful payment and one delivery,
  with zero unresolved operations. Its driver stopped on diagnostic-row
  cardinality; two x402 observations are not two payment effects. The same
  deployment's SC011 run `bef-sc011-ad16879820ed4d9fada0c4333e82ca6b`
  verified writable cache bindings and empty cold caches, then stopped on a 502
  despite the actual canonical payment succeeding.
- The concrete cause was a PostgreSQL parameter inference error in the new
  terminal-state guards: nullable `$3 IS NULL` was untyped. Exact error times
  and protocol outcomes are retained in
  `artifacts/runs/bef-settlement-postgres-type-errors.log` and
  `bef-settlement-protocol-vs-db-observations.json`. In the cold trial, the SDK
  recorded success before this SQL failure produced a second unknown record.
  Explicit text casts now preserve the original status/hash guards; the actual
  production SQL passed a dedicated PostgreSQL regression with null, original,
  conflicting and terminal hashes, no skips. No speculative receipt retry was
  added to the facilitator to conceal this database failure.
- Original cold-purchase operation `082d3e24-a015-4da9-95c1-abe898f0486b`
  was reconciled by original transaction
  `0x93a4d9816c7a1d9d1ad6c12abb37d56614721dfd5d50d850655b33b7d2a2526b`.
  `artifacts/runs/bef-sc011-cold-original-reconciliation.json` retains exact
  historical 100000-unit token effects. Independent DB-after evidence confirms
  settled/success, zero delivery, active generations=0 and unresolved=0. Failed
  trial artifacts remain unchanged. These observations do not close SC006/011.
- SC007 passed its fresh actual mapper in 54.31 seconds:
  `bef-sc-007-428b28d9a48f4efbaa0e14cc49360f59`, all 14 variants, 20 operations,
  1211 hash-indexed artifacts. Aggregate variant execution took 44670 ms.
  Image `sha256:657b81d9d7c0bb5f36855cd667d4e476f4f8d05a286071ed5d3e24a6e0c03036`;
  app source `9fccc6e59cd67ab28ab5c6caa6a22deeb9d517cae4dc0a99ea46257ef63ce206`;
  probe source `e298af10ba41d2a27c45157fea7c2c393c14da5444602bbbccf39d53f42d851f`.
  This closes tasks 4.1/4.2 (12/25 total), not cost accounting or product E2E.
  The earlier all-variant capture `bef-sc-007-96b7d828235d48218de8e612b125ce49`
  failed strict acceptance and remains unchanged: metadata joins and WETH-event
  assumptions were corrected, and the producer now records verified transaction
  read-only mode plus env/generation even for empty DB selections. Missing scoped
  denial evidence is still rejected. The new pass uses a fresh complete capture.
- SC006's first actual capture `bef-sc-006-e3707edd0acd4aa8bdc7df1467d3e1db`
  reached the real original settlement after wrong-domain/amount rejection and
  one scoped injected receipt failure. It correctly retained unknown/no delivery,
  then stopped on a transient independent receipt lookup. Original operation
  `86c5d9c5-c98f-4bcd-9c5d-4385d9737613`, transaction
  `0x1d824d81667edd3ce255d8a3295bf3362899a594f82a38917a8d274c8806583f`.
  Parent restored the one-shot read fault and reconciled this original identity;
  `artifacts/runs/bef-sc006-original-payment-reconciliation.json` retains receipt
  and historical exact 100000-unit USDC effects. Independent DB-after evidence
  confirms settled/success, zero delivery and zero unresolved operations; chain
  head stayed `0x32871b6`. This is not a passed SC006 result.
- SC011's first live trial blocked on the actual unusable RPC cache: Anvil UID
  1000 (`foundry`) could not traverse `/root` (mode 700). Both nodes now use the
  verified `/home/foundry` home/cache mount. Post-deploy actual write-access
  checks passed for both state and RPC caches on both nodes; see
  `artifacts/runs/bef-foundry-cache-permissions-observation.json`. Recovery JSON
  Path serialization and durable binding diagnostics were fixed. The subsequent
  protective-fence preflight exposed an incompatible guardrail marker phase;
  later typed-purpose fixes and the protective observation above resolve it.
  Parent fenced the completed SC007 generation by the
  existing private API; independent DB evidence shows active=0, unresolved=0.
- Combined preflight checks passed 152 Python tests (3 platform skips, 6 subtests)
  and 13 focused TypeScript tests; a separate actual PostgreSQL lock run passed
  all 3 tests without skips. At that checkpoint SC006 implementation was promoted
  but its live gate remained open; the later pass above closes it. SC011 resource
  acceptance remains open.
- Fresh SC001 passed in 22.10 seconds on the explicit Ethereum/Prague profile:
  `bef-sc-001-0ce459836fca4894ac26d25e23e335d5`. Image:
  `sha256:2ec0c83f61d04bbe8a4680838e206325c0d286baea2ed1e6a53e31eb369ab9eb`;
  manifest remains `9b822315814d9dbe39ac37c70906c12686e6a1f0ea6e0fbd03a41ca428c2b030`.
  The subsequent SC007 capture `bef-sc-007-1e689e7603024e86b54dd2cf2a916b5f`
  successfully executes wrap and approve, then stops before swap broadcast on
  `recipient_code_observation_unavailable`. Investigation is in progress; no
  unresolved operation remains. This is a failed capture, not swap acceptance.
- The earlier unknown approve was reconciled after read-only verification,
  preserving its original hash and event prefix. Final evidence:
  `artifacts/runs/bef-sc007-original-approve-reconciliation-1792843828129-25456-finalized.json`,
  SHA `d5b6d605dd5fe5bf8dfbac79e4495d0f3059ad5d3b96e7b43f325ab04a3f01ee`.
  Independent `bef-sc007-original-approve-db-after.json` confirms settled/success,
  one final event, one prior unknown event, unchanged expired generation and zero
  unresolved operations. `bef-sc007-original-approve-chain-after.json` retains
  head `0x32871b7`; no replacement transaction was submitted. Fixes distinguish
  raw selected inputs from manifest-derived observation metadata and normalize
  only hex casing when binding observed transactions to persisted intent.
- SC011 process cleanup has passed three isolated Linux process regressions,
  including a child spawned from a non-leader thread and an exited runner with
  surviving child/grandchild. Script, exact Docker command, stdout and exit code
  are preserved under `artifacts/runs/drafts/posix_sc011_cleanup_regression.*`.
  Python checks passed 135 tests with 3 Linux-only skips on Windows; TypeScript
  persistence/reset checks passed 6. These do not establish SC011 live acceptance.
- Both recreated nodes were independently observed with execution network
  `ethereum`, hardfork `Prague`, chain ID 8453 and the unchanged pinned source
  block/hash. Image:
  `sha256:f0fd2572d2313b957ae39f814481e5ac7a1a4d074847ccad067b421fe0701cf2`.
  The fresh SC007 capture `bef-sc-007-962bd59e35ab41529d5db05351ea66e6`
  binds manifest `9b822315814d9dbe39ac37c70906c12686e6a1f0ea6e0fbd03a41ca428c2b030`
  and app source `1a68fa5d060dd8b2e074289b299a87e966f838ec333b3b7f72928c50b5398c14`.
  Its wrap succeeds with the exact principal plus receipt-gas native debit.
  The following approve was mined successfully, but the API retained unknown
  and the collector stopped. This observation led to the metadata/casing fixes
  and original-hash reconciliation recorded above. Original operation
  `31b0b927-79f7-4e07-87e3-f5ed2f9c97e6`, transaction
  `0x9926a7c10bdd696bd43fccf3968f4df0121a4ac90bac7aa18b47b999f0d4e728`.
  This remains a failed capture. Prior five-gate acceptance is historical;
  the changed profile requires fresh acceptance evidence.
- SC007 implementation was deployed for its first real capture as image
  `sha256:0317ce754fbba339a136deaa4865a39b85518850e78a70039d30557cb6e07ec4`.
  Observed manifest SHA is
  `323f9b2ba8bc4cbbb75e9177bedec54c155ced0c1f8217c9d2e5675ec1673fbb`;
  application source SHA is
  `db96f44aa1449e6abe230523fc7eea4168d85294182efd1a70af02425a44a5f5`.
  See `artifacts/runs/bef-sc007-deployment-observation.json`.
  The manifest pins separate 2 ETH target/1 ETH gas-reserve criteria, a 100 USDC
  feasibility output criterion, and 1800/900-second swap/resource scenario caps
  while normal trials remain 120 seconds. Unit/tooling checks passed 122 tests.
  The first capture (`bef-sc-007-e51fea184efe48d284984fb04850bd82`) failed before
  any participant operation: the driver sent an absent JSON reset body instead
  of the API's required empty object. The strict API returned 400; a probe-only
  correction was followed by a fresh capture.
- The second SC007 capture, `bef-sc-007-7a2a89a31d754104a052f0dcfa0e3e61`,
  collected the two security-denial variants and then stopped after its first
  real wrap. The probe queried nonexistent `bef_operation.created_at` instead
  of `started_at`; that query is corrected. Independently, the API correctly
  withheld a verified-effects result because native debit exceeded value plus
  receipt L2 gas. Original operation `46d79b46-c8ab-47f3-8772-4a22c1eec807`
  was initially recorded as `settlement_unknown`; original transaction
  `0xe471853593e802f261d431b500d6c694872361fc1691864766fec87709437c99`
  has a successful receipt and exact 0.1 ETH WETH deposit effects.
  Receipt gas costs `268299532454` wei, while actual native debit beyond
  principal is `268854862706` wei. The extra `555330252` wei exactly equals
  the historical L1 Fee Vault increase in that one-transaction block. Evidence:
  `artifacts/runs/bef-sc007-original-wrap-receipt.json`,
  `bef-sc007-original-wrap-state.json` and
  `bef-sc007-original-wrap-fee-vaults.json` in the same directory.
  Actual `anvil_nodeInfo` reports network `base`, hardfork `Beryl`.
  [Anvil 1.8.6 source](https://raw.githubusercontent.com/foundry-rs/foundry/v1.8.6/crates/anvil/src/config.rs)
  confirms Base family inference; the
  [OP predeploy specification](https://specs.optimism.io/protocol/predeploys.html)
  identifies the fee vault. This exposes an unpinned execution-family assumption,
  rather than a fee-cap mismatch. The subsequent original-hash reconciliation
  and explicit educational local-EVM profile are recorded separately above/below;
  the exact source block, assets and contracts remain pinned. The original
  failed capture must not be rewritten.
- The original wrap was subsequently reconciled by an operation/hash-specific
  CLI after a successful read-only verification. It uses the existing persistence
  finalizer and preserves the expired generation and earlier unknown event.
  Evidence is
  `artifacts/runs/bef-sc007-original-wrap-reconciliation-1792840862577-42456.json`
  (SHA `058455a08d61c72aa846f7b682b26c68708f2f980837396c059f94475f4dc619`).
  Independent `bef-sc007-original-wrap-db-after.json` confirms settled/success,
  one finalized receipt event, one prior unknown event and zero unresolved
  operations. `bef-sc007-original-wrap-chain-after.json` confirms the head stayed
  `0x32871b6`; no replacement transaction was sent. The observed L1 vault charge
  is separate and remains unmodelled in the educational L2 fee calculation.
  This closes that uncertain execution, not SC007 acceptance.
- The SC006 lock fix has separately passed an actual dedicated PostgreSQL
  regression: 20 same-environment contenders complete with nested pool reads;
  uncertain-query and late-checkout cases also pass, three tests with no skips.
  Log: `artifacts/runs/bef-sc006-lock-pg-test.log`. These isolated checks do not
  establish SC006 payment-recovery acceptance.
- The full acceptance run finished on 2026-10-24 at 10:26:22 UTC: SC001,
  SC003, SC004, SC005 and SC012 passed; the remaining seven mandatory gates
  remain blocked. Pytest reported five passed and seven skipped in 154.44 seconds;
  the acceptance wrapper correctly exited 1. This closes tasks 5.4 and 6.3,
  without establishing resource-trial acceptance or product browser E2E.
  The persisted report is
  `tests/bdd/changes/benchmark-environment-feasibility/acceptance-evidence.json`.
  This run's successful captures under
  `artifacts/benchmark-environment-feasibility/probes/` are:
  SC001 `bef-sc-001-2953e46ce8644056ae315ce8a1f66d3f`,
  SC003 `bef-sc-003-542423b113a84c40856138fec94ab8fd`,
  SC004 `bef-sc-004-1d26dab488464aef94e40f4ffd45d679`,
  SC005 `bef-sc-005-e0bd780c8a694640860093dd8c13930a`, and
  SC012 `bef-sc-012-24201eec317f4716a30a35cb22254f2f`.
  SC012 replays the explicitly selected earlier SC004/005 captures; it does not
  silently select the newest capture. Its standalone rerun also passed in
  28.28 seconds (`bef-sc-012-e1c0e8e0096743a489aeea3e33bf3a17`).
  The source/probe fixes passed TypeScript and 94 unit tests before execution.
- On 2026-10-24 the selected-action runtime was built and deployed as image
  `sha256:8d2f6c6b271b631ace09110805ea0508f6f82b3ec3f515656481958513e34e5d`.
  The observed API manifest hash is
  `ba8e33961a80f123951a52b2270e0943038be9ef417f78754851696379046af1`;
  application source hash is
  `311d66ac028199a4b11a61c3032fa73fe33e4b18c8e59f30e74555da985db9d7`.
  See `artifacts/runs/bef-selected-deployment-observation.json`.
  No unresolved operation existed before the private nodes were recreated.
- Actual migration tests passed on the separate local `bef_migration_test`
  database, then passed again with its migrations already installed: two tests,
  zero failures and zero skips. They cover source checksums, atomic rollback,
  new-generation manifest pinning and rejection of changes or invented legacy
  bindings. The rerun log is `artifacts/runs/bef-migration-rerun-test.log`.
- Fresh SC004 and SC005 passed on that deployment, respectively in
  `bef-sc-004-2ac371492e71495f8719b965e0a4ac3f` and
  `bef-sc-005-2fc2c8bc198c4c3abb876acd6baae895`. Typed selected-action routes are
  connected, but their full SC002/SC007/SC008 acceptance remains pending.
  Dedicated state/RPC cache mounts are configured; this is not SC011 trial proof.
- The first live SC012 attempt exposed a real credential-key filter omission.
  It was fixed and tested against a modified copy of actual SC004 evidence;
  invalid input produces no replay report and leaves the original unchanged.
  A subsequent runtime capture completed, but loading failed because replayed
  original operation references were absent from the top-level inventory.
  That attempt remained failed until the later fixes and successful reruns above.
- Further SC012 review found that SC005's four original operations span four
  generations. Replay must observe all those bindings and generations rather
  than compare only its primary generation. The actual offline replay must run
  between independent before/after DB and RPC observations; paired snapshots
  taken after replay do not establish that boundary. These fixes and exact
  per-generation/account RPC coverage are now covered by the successful fresh
  SC012 runs above.
- The next actual SC012 capture, `bef-sc-012-9fe5f805f9dd49c288cf73efda124f5b`,
  completed in 29.30 seconds but failed the forwarding-provenance assertion.
  Independent proxy counters show prohibited methods were denied with zero
  forwarding; the collector had recorded its expectation-match boolean as
  `forwarded`. Review of the same capture also exposed missing generation/env
  metadata on DB observations, redaction of a public boolean predicate result
  after its identity hash was calculated, and a missing fault-verifier function.
  The later successful runs above include fixes for these collection and
  validation defects; the failed capture remains preserved.
- Structural verification on 2026-10-24 passed: all 12 active-delta scenarios
  remain protected and strict OpenSpec validation has no issues. The separate
  tooling suite passed 17 tests. These checks do not establish runtime gates.
- The full acceptance command completed on 2026-10-23 at 19:22:33 UTC:
  SC001, SC003, SC004 and SC005 passed; the other eight mandatory gates are
  blocked by missing implementation/capabilities. The wrapper exited 1 because
  mandatory blocked gates prevent acceptance, despite pytest exiting 0 with
  four passed and eight skipped. The persisted report is
  `tests/bdd/changes/benchmark-environment-feasibility/acceptance-evidence.json`.
  Original all-blocked evidence is preserved separately in
  `artifacts/runs/acceptance/acceptance-before-live-four-gates.json`.
- The 2026-10-23 full-run captures are SC001 `bef-sc-001-dfa203e388e74db88482fb0cdfa3870c`,
  SC003 `bef-sc-003-3111a550cda540198e504afd310b0f35`,
  SC004 `bef-sc-004-5d900efbe8ef466db7be7436cc8a6df2`, and
  SC005 `bef-sc-005-5655311f794748f59358ae8603beedfa` under
  `artifacts/benchmark-environment-feasibility/probes/`.
- The isolated Compose project runs both Anvil environments, PostgreSQL, API,
  controlled facilitators and read-only proxies. The local deployment observation
  is `artifacts/runs/bef-deployment-observation.json`.
- SC004 passed against the actual services. Original evidence:
  `artifacts/benchmark-environment-feasibility/probes/bef-sc-004-0e5b869abfc644dc9b67d52f8bc7b498/`.
  The offer and unpaid purchase operation have no transaction hash; the independent
  observations contain no settlement, delivery or token-balance change.
- Its offline replay matched:
  `artifacts/runs/acceptance/BEF-SC-004/replay-first-real.json`. Replay evaluates
  recorded bytes and does not establish a new execution result.
- A fresh SC005 passed after the receipt and protocol-evidence fixes:
  `artifacts/benchmark-environment-feasibility/probes/bef-sc-005-9de84ef4337f46529a1a5c071509db6b/`.
  The live mapper completed in 33.48 seconds, with 126 indexed artifacts and four
  operations. Verification-only has no debit/delivery; wrong-token rejection
  binds the actual signed request's public requirement metadata and the raw
  PAYMENT-REQUIRED error to its rejected DB operation; mismatched content is
  withheld despite settlement. The canonical purchase has the expected receipt,
  exact token effects, resource hash and independent payment/delivery rows.
  This closes task 3.3, while payment recovery under concurrency remains SC006.
- A focused SC005 run verified authorization without payment or delivery, rejected
  the wrong-token request at the service, and confirmed payment while withholding
  mismatched resource data. Its canonical purchase then returned `unknown` because
  the SDK queried the receipt before Anvil exposed it locally. A later independent
  read found the original transaction successful; see
  `artifacts/runs/bef-canonical-failure-state.json` and
  `artifacts/runs/bef-canonical-original-receipt.json`. Independent historical
  balance reads in `artifacts/runs/bef-canonical-original-balances.json` show
  payer `100000000 -> 99900000` and original payTo `0 -> 100000` USDC units.
  This is a recovery input,
  not a passed SC005 result or permission to submit a replacement payment.
- The original payment was subsequently reconciled by its original identity:
  `artifacts/runs/bef-original-reconciliation.json`. Independent observer evidence
  in `artifacts/runs/bef-original-reconciliation-db-after.json` confirms one
  successful settled payment, zero delivery records and zero unresolved operations
  in that environment. `artifacts/runs/bef-original-reconciliation-chain-after.json`
  confirms the chain head still equals the original receipt block. This closes
  that uncertain payment observation; the later fresh SC005 pass above and
  complete SC006 acceptance are separate results.
- The short resource sample is an observation window, not SC011 trial evidence:
  `artifacts/runs/acceptance/BEF-SC-011/resource-sample-39def64ada984da9b1cf4f8490e89ec9.json`.
  Cold/warm cache provenance and per-trial attribution remain unknown.

## Findings to close before the corresponding gates

1. **SC006:** closed by the fresh focused run above. Receipt observation retries
   retain the original hash and cannot trigger a replacement payment.
2. **SC006 locking:** closed by the dedicated actual PostgreSQL regression and
   fresh concurrent recovery capture. Waiting contenders no longer exhaust the
   pool needed by the current advisory-lock owner.
3. **SC002/008:** typed selected-execution routes and SC007 actual variants are
   accepted; complete the combined driver and cost persistence. Keep ephemeral acceptance signing material in process memory,
   scoped to the generation, and outside participant routes, DB, logs and evidence.
   SC008 review also found an extra `10**18` divisor in the adapter's conversion
   oracle: the pinned rational is already USDC base units per wei. Bind its units
   explicitly before acceptance, and distinguish selected principal from executed
   principal when a transaction reverts; reverted execution still consumes gas.
   Arithmetic against the fresh SC005 receipt produces `247292` USDC base units,
   whereas the adapter's extra divisor produces `0`; see
   `artifacts/runs/bef-fee-arithmetic-review.json`. That facilitator receipt also
   uses an effective gas price of `1004980019` wei, inconsistent with treating
   the manifest's `1000000` wei priority fee as a uniform SDK execution policy.
   Pin and apply the facilitator policy explicitly before SC008 acceptance.
4. **SC009–010:** immutable generation manifest bindings and restart fencing are
   implemented and migration-tested. Complete actual two-environment isolation,
   complete-baseline equivalence and stale-work acceptance. Existing historical
   rows must not acquire an inferred manifest binding by backfill.
5. **SC011:** closed by the fresh full mapper above. Dedicated state/RPC-cache
   preparation, both purchases and overrun stopping have independent evidence.
   Preserve the declared measurement limits; Anvil reset or an arbitrary empty
   folder alone does not establish a cold cache, and startup CPU/RAM is outside
   the sampled window.
6. **SC012:** closed by the fresh complete acceptance run. The negative
   secret/hash checks retain actual validator process outcomes and unchanged
   original-tree hashes; replay preserves all original generation/operation
   bindings and runs between independent DB/RPC snapshots.

SC001/SC003 review findings are closed by the full acceptance run. The fixes
normalize observed dependency-version names and chain-id representations, scope
payment/delivery cardinality to the original operation's primary DB query, and
accept only the explicitly validated chain/head reads when comparing protected
state. Regression tests still reject contradictory extra DB rows, malformed
chain requests, unbound endpoints and unexpected RPC methods.

The complete mandatory suite must be recorded using
`infrastructure/benchmark-environment/run-bdd.ps1 -Acceptance`. Its persisted report
and the checked task list determine closeout; partial results do not permit sync
or archive.

Configuration pinning (task 1.2) is complete in the versioned runtime manifest,
source-intake artifacts and startup observations. Actual local EIP-3009 payment
effects demonstrate the selected scheme/asset path. The later focused SC006/007
passes are separate evidence; the complete mandatory suite still needs a fresh
run after the remaining implementations.
