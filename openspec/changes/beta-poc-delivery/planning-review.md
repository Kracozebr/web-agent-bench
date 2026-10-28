# Planning review: beta-poc-delivery

Date: 28 October 2026. Source baseline: `4e84d0e`. Status: planning complete,
implementation approval pending; beta runtime acceptance `not_run`.

## Inventory and checks

- One new capability: `beta-poc-delivery`; no modified synchronized main spec.
- 15 proposed requirements, 26 stable scenario IDs, 25 mandatory environment
  gates and one mandatory artifact/release-bundle gate.
- 45 unchecked implementation/verification tasks detail the delivery plan's
  16 work packages; checkbox count is not a remaining-time or readiness metric.
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
- Local Markdown document links resolve; JSON parses; task IDs are unique and
  all tasks are unchecked. Runtime contracts/mappers/mirrors remain planned.
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

Review [approval.md](approval.md) and its linked spec/BDD/defaults. After explicit
scope approval, run `/opsx:apply beta-poc-delivery`. The repository's
[task-design](../../../docs/task-design.md) requires that approval before changes
to product code or executable tests. Proposal preparation alone does not supply it.
