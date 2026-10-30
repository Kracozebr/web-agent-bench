# Planning review: beta-poc-delivery

Initial review date: 28 October 2026. Source baseline: `4e84d0e`. The original
scope was approved for implementation on 28 October; the 30 October limited
training-release amendment is approved and awaits root review before code/BDD
implementation. Beta runtime acceptance remains `not_run`.

## Inventory and checks

- One new capability: `beta-poc-delivery`; no modified synchronized main spec.
- 15 proposed requirements, 26 stable scenario IDs, 25 mandatory environment
  gates and one mandatory artifact/release-bundle gate.
- 45 implementation/verification tasks detail the delivery plan's 16 work
  packages. Current status remains 3 checked / 42 unchecked; checkbox count is
  not a remaining-time or readiness metric.
- `openspec validate beta-poc-delivery --strict --json`: valid, no issues.
- `openspec validate --all --strict --json`: 13/13 valid (ten changes and three
  main specs); existing informational long-text notices remain in BEF main only.
- `openspec status --change beta-poc-delivery`: all four planning artifacts
  complete. This is artifact completion, not approval to implement or release.
- Independent static extraction of the spec compared requirement/scenario
  IDs, titles, complete WHEN/THEN, named mappers/adapters and evidence modes
  against both BDD table and JSON inventory: 26/26 aligned. Every contract has
  required observations, negatives and durable effects, is mandatory, and has
  an empty private-mutation exception list.
- At the initial review, local Markdown links resolved, JSON parsed, task IDs
  were unique and three artifact-gate tasks were checked. Runtime
  contracts/mappers/mirrors remain planned.
- No product code, executable tests, live provider/client/chain calls or
  deployment changed during proposal preparation. No new runtime gate was run.

## Review conclusions

The scope follows the owner's explicit decisions: open Google signup, internal
bonus codes, four selected real clients, existing training/full12, human/agent
reports and administrator triage for a 20–30-person beta. Owner answers now confirm group-code per-owner rules, fixed/no-expiry bonus
behavior, 24-hour queue waiting, screenshot inclusion, waiting for all four clients
and daily same-host backups. Detailed screenshot bounds, remote protocol/auth,
recovery and measured restore targets remain engineering proposals in the revised
package. Product choices do not by themselves mark executable scope approved.

The largest critical-path risk is a new external executor/readiness plus client
profile: the completed local Codex profile cannot be made remote merely by
reusing its acceptance flag or removing loopback guards. Real inference evidence
is required separately from the deterministic native-client transport fixture.
Shared training coverage and the four client journeys are separate gates.

Included owner/bonus/run/evidence invariants remain mandatory for beta even
when their old whole-MVP packages are deferred. Existing blocked gates retain
their states; this package does not mark them passed or archive them. New beta
protocol/auth assertions outside the reviewed matrix require renewed review.

## Remaining external inputs

Host/domain are not selected; Google OAuth project must be created/configured
and the owner-selected administrator's Google subject verified. Only Codex is
available; arrange Claude Code/Desktop/Hermes test sessions and pin the exact
client/model profiles. Target BEF/source RPC and tester availability remain
prerequisites. These are manifest/acceptance prerequisites;
missing access yields blocked gates rather than invented values.

## Clarification delta, 28 October

- Queue policy is 86400 seconds with no retry renewal or local one-hour clamp.
- Screenshot upload/normalization/private attachment/read/cleanup is included;
  BPC-SC-024 adds its own negative/effect contract. Existing report/admin/restore
  assertions and JSON/table entries include screenshot references/bytes/hashes.
- Screenshot, public result and retention tasks now total 45, all unchecked.
- Mandatory client families remain four; missing application access is recorded
  as a prerequisite, not an omitted gate. All runtime results remain `not_run`.
- Confirmed product answers and pending implementation scope are recorded
  separately in approval.md. No product code/tests/deployment changed.

## Review resolution delta

The owner selected public cards/results for everyone and retention of reports /
screenshots for 30 days after beta ends. BPC-REQ-014/015 and BPC-SC-025/026 protect
those additions. The public view composes existing marker/best-result rules;
private feedback/account/report fields are explicitly excluded.

Engineering resolutions are recorded in design/spec/BDD: qualification before
verified release manifests, principal-authenticated bounded MCP image chunks
and browser multipart with owner attachment fallback, aggregate upload quotas,
24-hour expiry eligibility separated from safe-fence completion, and retention
purge/deletion receipts with backup sanitization. This records planning corrections,
not runtime proof. Pending-intent and restore-time engineering targets are no
longer presented as owner-confirmed product values. Existing BPC IDs remain stable; SC-025/026 extend the reviewed inventory for public summaries and retention.

## Next step

The 30 October amendment is recorded in [approval.md](approval.md). Root review
the updated proposal/spec/design/tasks and BDD packet, then continue with
`/opsx:apply beta-poc-delivery` for this exact training-release change; no further
human approval is needed for the approved scope. Keep runtime gates `not_run` and
the task count at 3/45 until evidence exists.

## Latest Training override — 30 October 2026

The user's latest explicit decision supersedes the interim versioned-catalog
amendment recorded earlier in the planning history. Training uses one current
roster: S1/M1/H1 with weights 1/2/3, denominator 6 and a 0.5-USDC bundle
(500,000 micro-USDC), priced once per selection with the ceiling formula.
Ranked12 remains unchanged. No versioned catalog or backward-compatibility
branch is required.

The user also confirmed old qualification runs are disposable test data. Root
owns deleting exactly five local qualification runs and dependent results;
this planning pass performs no deletion and leaves accounts, agents, auth,
codes, ledger and reports retained. Frozen repository proof artifacts remain
unchanged, and new validation evidence uses fresh paths.

The normative BPC-SC-014 spec, BDD design row and JSON proposal are reconciled.
The executable BDD work for `/opsx:apply` must retain `test_bpc_sc_014`, its
adapter, gate and mandatory status while updating the scenario map, semantic
contract, Gherkin mirror and evidence schema to cover current S1/M1/H1 order,
single/multi/full-bundle rounding, real UI start and bound agent actions,
direct-API and stale/cross-selection quote negatives, invalid-selection
no-effect evidence and fresh non-overwriting evidence paths. Do not add a
scenario or change the 26-scenario inventory. No executable BDD file, code,
test or runtime gate was changed in this planning pass.

Implementation and executable BDD changes are authorized after root review,
without another human approval. No additional real model runs, credit
grants/spend or credential operations are authorized beyond the previously
consumed 3.1 attempt. Existing gates and progress remain 3/45; runtime
acceptance is `not_run`.
