# Restart/payment-recipient successor regression

Implementation continuation authorized by the owner on 2026-11-01: “давай
исправляй с саб агентами”, following the three-part diagnosis. This is a repair
under BER-REQ-005/007/008 and AFR-REQ-001/002, not timing recalibration or a
change to task goals, prices, scores, compensation or publication rules.

## Reproduced boundary

The retained Training run has a known failed, fully reconciled and fenced S1,
and two queued successors. The exact coordinator candidate query selects it.
Runtime exception tracing identifies `local_bef_coordinator_no_free_compatible_environment`
for M1: the sealed payment recipient differs from the facilitator's newly
generated signer address after service restart. All other inspected manifest,
application, fork, generation and claim identities agree.

Environment selection occurs before the database-time successor-window guard.
Its plain error is retried without a preparation intent or terminal transition.
The existing overall-gap cleanup covers predecessors completed after the
overall deadline, leaving this pre-deadline predecessor stuck indefinitely.

The same agent did not create a support report. Current AFR correctly requires
an authoritative terminal platform-failure response; the stuck coordinator
never supplies one. A local client timeout alone must not become a fabricated
platform-failure attribution.

## Repair constraints

- Keep the sealed recipient authoritative across service restart. Distinguish
  the public payment recipient from the ephemeral transaction-signing account;
  never persist private wallet material or accept an arbitrary recipient merely
  to make a stale catalog runnable. Preserve old evidence decoding/replay.
- Check compatibility before admission and preserve runtime identity checks.
  A live HTTP endpoint alone is insufficient readiness evidence.
- Enforce the already snapshotted successor-preparation window using database
  time even when environment selection fails before an intent can be created.
  Retain strict predecessor evaluation/fence/claim checks. A bounded platform
  preparation failure must terminate through existing cancellation authority,
  not manufacture an agent zero or leave claims/slots active indefinitely.
- Once the server confirms the terminal platform reason, the native agent
  reports once and confirms the receipt. A final status refresh at the bounded
  client-wait boundary must still process a newly terminal failure. Ordinary
  task deadlines, partial grades and unexplained null tasks do not independently
  authorize automatic bug reports.

## Required verification

1. Focused unit and PostgreSQL regressions protect valid/invalid predecessor
   proof, original funding, strict payment recipient checks, expiry boundaries,
   retry/restart and exact resource release. Existing BDD scenario IDs remain
   authoritative; focused checks are not a replacement for environment gates.
2. Freeze changed sources. If BEF application/probe identity changes, regenerate
   all fifteen current qualification references and use the strict independent
   source-refresh comparators. Never repin old captures to new code.
3. After qualification, restart the actual payment services again while
   retaining that same catalog. Run real browser-admitted Training S1/M1/H1
   and Ranked twelve through the actual API/worker/BEF/PostgreSQL boundary.
   Retain pre/post public payment identity, service start and source hashes.
4. Exercise an unavailable/incompatible successor environment through the
   pinned bound, verify one terminal platform reason and cleanup, then prove
   native MCP report/receipt, administrator UI and independent report/audit rows.
   Label native-model and reference-executor evidence separately.
5. Independently compare retained historical evaluation, action, receipt, bonus,
   report and screenshot fingerprints. Normal authorized completion of a pending
   cancellation is distinct from rewriting an existing grade or ledger entry.

Historical checkpoint before the subsequent qualification: implementation and fresh runtime verification in progress. The
prior successful captures remain historical evidence; they do not establish
that this restart regression is repaired. No sync/archive is authorized by an
unexecuted or skipped mandatory gate.

## Historical verification checkpoint, 2026-11-01

- Focused coordinator, successor-expiry, handoff, failure-classification and
  negative health-proxy regressions: 38 passed, no skips, with the PostgreSQL
  integration flags enabled. Capture/replay regressions: 69 passed, no skips.
  Startup payment-readiness checks: 2 passed.
- Fresh authenticated MCP/report PostgreSQL and handoff-policy test reports:
  `artifacts/runs/restart-fix-validation/dcfb0794-830b-4d4e-aacd-1376e8c74c69/`.
  The independent AFR negative reader verified all thirteen declared variants,
  current source pins and JUnit hashes. These are supplementary tests, not a
  native-agent reporting acceptance claim.
- Qualification `a2fc2828-e89e-4894-9b2b-e9cbe9986859` is **blocked** after
  successful S1–S4 Ranked references: M1 payment settled, but resource retrieval
  returned HTTP 409 `delivery_unavailable_or_unverified`. Its immutable capture
  is `artifacts/runs/bts-difficulty-v2-reference/m1-ranked/b0393cdb-0914-4aa6-86b3-f6438e56427f/probe.json`.
  The durable delivery verifier retained a signer-equals-payee assumption; the
  corresponding recovery path needs the same identity separation. A fresh full
  qualification is required after that repair. No release pointer was promoted.
- The original Google stand remains stopped, with its database, OAuth
  invalidation authority and private storage preserved. Physical restart,
  Training/Ranked acceptance, native automatic reporting and historical-data
  comparison remain pending. No successful local component test removes these
  pending gates.

## Fresh qualification and acceptance, 2026-11-02

The later successful evidence supersedes the blockers above; failed captures are
retained unchanged. The three approved qualification amendments are documented in
[payment-schema-qualification-proposal.md](payment-schema-qualification-proposal.md),
[u1-fee-reconciliation-qualification-proposal.md](u1-fee-reconciliation-qualification-proposal.md)
and [native-gas-qualification-extension.md](native-gas-qualification-extension.md).
They preserve the old profiles, task goals and limits. Profile v4 permits only
receipt-backed exact native-balance plus gas equality, without a tolerance.

All paths below are relative to `artifacts/runs/` unless marked private.

| Boundary | Evidence | Result |
| --- | --- | --- |
| Fifteen fresh physical references and independent release validation | `bts-source-refresh-qualification/28e1dc93-ef3a-41f4-ac2f-e020207b7d71/qualification.json`, SHA-256 `6b8879b4b6ea1cb041bab4fff67badd437e181492c50b0367242f4f2c1a92826` | All fifteen references verified; validated candidate subsequently promoted locally. The offline campaign itself does not activate a release. |
| Actual payment-service restart retaining the promoted catalog | private `.local/restart-fix-preservation/restart-b339277a-fb2c-4b12-9578-1de2f2e4b550.json`, SHA-256 `97d091d5552f364909f25c784c8c2db010fc909891399c8e630b848b9ff5302a` | Both ephemeral gas signers changed; public recipients, catalog and application pins stayed fixed. |
| Browser-admitted Training through reference executor | `genuine-training-sequence-owner-run/bdd42d54-c762-4c5c-9892-7b3950066d24/capture.json`, SHA-256 `7eb624395409f4546e8ff0b60eea10bef424a92f27b544ffc2b9991b3e88cf8f` | S1/M1/H1 passed, Credit 1/1; run completed. |
| Browser-admitted Ranked through reference executor | `genuine-ranked-worker-owner-run/652c59c4-d65a-417b-87e1-1f80cea5ad92/capture.json`, SHA-256 `a1da3543c4c58f856f6784ddfaacfa5cad9ccedd40d6adae24408f96d002eb7c` | All twelve tasks passed, Credit 1/1; run completed. This is not native-model Ranked proof. |
| Paid-without-retrieval continuity | `agent-run-continuity-controlled/8cd569dd-2113-4d68-8e9b-ac187d8081f7/capture.json`, SHA-256 `97438f846ac8b365cc5bec0c566e87faa2cb3cc24c99e3371bd17aa5bcdb00b3` | M1 known failed with Credit 0/1, H1 known passed, run completed; no invented unknown evaluation or successor stall. |
| Actual Codex CLI 0.165.0, production clipboard handoff and MCP-only Training | `agent-run-continuity-native/8cd569dd-2113-4d68-8e9b-ac187d8081f7/capture.json`, SHA-256 `c70f73e039da4e6931318d8e5ede5324bb521f3a0535f16045c4347e4a0a6a10` | S1/M1/H1 passed, Credit 1/1; completed; 40 MCP calls, zero local calls. One recoverable tool error occurred; its exact error enum was not retained in the safe projection. |
| Actual Codex terminal preparation failure and automatic support report | `agent-failure-reporting/ad69a1a9-741f-442c-972c-2d0d2b2c63bd/capture.json`, SHA-256 `da2a3d651493d2d1ce5e0d3053afb1b48290acbde62db490d9c299fe1127776e` | Known/fenced S1, actual health 503 before M1 preparation; saved 180-second bound produced one cancelled run with `coordinator_preparation_failed`. Same native agent reported and confirmed receipt; actual administrator UI and independent PostgreSQL verified it. 171 MCP calls, zero local calls/errors. |

Independent physical readers verified both continuity captures and the reporting
capture. AFR semantic audit and all three mandatory BDD gates passed against the
fresh reporting capture and thirteen source-bound negative variants. The JUnit
report is beside that capture as `bdd-runtime.xml`. Qualification tests passed
21/21; owner preparation/readiness/collector/PostgreSQL checks passed 90/90 and
the subsequent paid-data projection checks 23/23, without skips.

The original 237 actions, 237 receipts, 79 evaluations, 81 observation bundles,
41 ledger entries, five bonus grants, two reports and one screenshot row remain
byte-hash identical in PostgreSQL. Private after-check:
`.local/restart-fix-preservation/owner-row-hashes-5c6976e1-9ff5-423e-a831-d80f1f117828.json`,
SHA-256 `4c4afeb3f9c515280d74d100e3eff09fba059200679febe3f8fdcddb8c5ad2dc`.
Normal cancellation cleanup is permitted to change pending run state, never an
existing evaluation or original financial record. No retrospective report is
fabricated for the old disconnected agent.

These are local acceptance boundaries. Native Ranked twelve, other client
editions, deployment acceptance and the remaining BER fault matrix are separate
gates. Do not infer complete BER acceptance or sync/archive from these passes.

Supplementary terminal cleanup passed 12/12 owner-PG checks and 4/4 direct
BEF-PG checks, both through read-only observer roles. Evidence:
`restart-fix-validation/f7f2fa8e-742f-44f4-8eb0-f1837ada7ede/afr-cleanup.json`
(SHA-256 `aff875b076f4c9285b0c5525bdffb9efb856246f8b8f432daebe1612768e13ec`)
and `restart-fix-validation/a6a1f82f-4354-40a2-9c1d-6fd5d1eec1de/afr-bef-fence.json`
(SHA-256 `6cb7983a3884b3260ca932d9404de60b7e88d301b6f33860707711d5feb7fece`).
Exactly one original reserve/debit remains; claim released, slots absent and the
exact BEF generation fenced. Cancellation outbox delivery is confirmed once;
queued/started notification rows remaining pending are not pending cancellation.
The earlier supplementary probe that incorrectly required every notification to
be delivered remains retained unchanged, along with matching database hashes.

ARC semantic audit and all three mandatory BDD gates also passed against the
fresh controlled/native captures. Its newly executed identity and handoff suites
passed 75/75 and 4/4 checks, respectively, without skips; independent replay
verified eleven negative variants. JUnit: beside the native continuity capture,
`bdd-runtime.xml`. No historical test report was repinned to changed source.
