# Beta PoC approval boundary

Date: 28 October 2026 (Europe/Moscow). Decision: **approved for implementation and acceptance**.

The owner's request `/opsx:propose beta-poc-delivery` authorizes creation of this
planning package. It is not an approval of implementation, executable tests,
external deployment, or new assertions. No prior local Codex/MVP approval is
extended to the remote beta by this record.

## Concrete scope presented for approval

- BPC-REQ-001–015 and exactly BPC-SC-001–026, with titles/WHEN/THEN in
  [delta spec](specs/beta-poc-delivery/spec.md) and matched observations,
  negative variants, durable effects and evidence in [BDD packet](bdd-design.md)
  and [harness proposal](bdd-harness-proposal.json).
- [Design](design.md) and [tasks](tasks.md): additive Google open beta, private
  agent controls, distinct external execution/MCP profile, four actual clients,
  code-issued internal credits, existing training/full12, minimal public verified result/card views and private owner controls,
  private reports/screenshots and administrator triage, bounded target-host operations.
- User-confirmed code behavior: one claim per owner per group; fixed amount/maximum;
  first eligible claimant for single-use; immutable terms; no-expiry credits;
  disable only future claims; exact atomic existing-ledger grants.
- User-confirmed queue behavior: one global execution slot and one per agent; accepted
  unstarted queue two per owner/eight global; original
  queue deadline 86400 seconds (24 hours); successor preparation and bounded platform recovery
  180 seconds remain engineering proposals, each with its distinct clock policy. Existing task timers, weights,
  exposure, nominal pricing/limits and source-refund rules remain authoritative.
- Proposed pending-intent bound is two per owner/thirty globally; it is an engineering choice, not an owner-confirmed accepted-run cap.
- Report text limit/status/minimum workflow and screenshot support are accepted; screenshots are optional per report. Proposed
  image policy: up to three PNG/JPEG/WebP images per report, at most 5 MiB each,
  bounded decoded dimensions, private normalized storage/preview, no URL fetch,
  no automatic desktop capture; bounded MCP begin/chunk/finish or audited owner attachment, quotas, orphan cleanup and backup/restore are included.
  Exact validation/access/negative assertions are in BPC-SC-024 and the revised
  report/admin/restore cases. Free reporting has no task/billing/timer effects.
- Proposed remote protocol allowlist `2025-06-18` / `2026-07-28`, exact registered
  callbacks and real client/profile pins; local restrictions are preserved.
- User-confirmed backup policy: daily same-host copies and disclosed up-to-24-hour loss window. Pre-migration backup and operator-assisted RTO 4h are engineering targets, measured in rehearsal; four hours is not an owner-promised SLA. No off-host loss guarantee.

All new runtime gates remain **not_run**. A complete proposal or strict structural
validation is not runtime acceptance or automatic permission to deploy. Secrets
and external host/client values must be supplied and pinned before their gates.

Changes to scenario inventory/assertions, newly supported protocol/auth mechanisms,
task semantics or excluded product scope return to review under
[task-design](../../../docs/task-design.md). Existing unrelated pending gates
are preserved; included path invariants cannot be waived to meet the date.

- User-confirmed public visibility: everyone can see published cards and verified
  score summaries, following existing marker/best-result/privacy rules. Reports,
  screenshots, private task reasons and financial/account controls stay private.
- User-confirmed retention: reports/screenshots expire 30 days after beta ends.
  The revised scope includes audited closure, access denial, purge and safe backup
  rotation/restore; official grades and original bonus receipts are retained.
- Engineering review resolutions: qualification vs cohort-release manifests;
  24-hour start cutoff vs delayed safe-fence release; bounded image transport and
  storage; precise ownership/approval labels. Assertions are in the revised BDD.

## Owner answers recorded on 28 October

1. Accepted group/individual code behavior, fixed credit and indefinite bonus
   validity, and disabling only future claims.
2. Changed queue expiry from one hour to **24 hours**; retained the initial
   one active / eight globally waiting / two per-owner waiting plan.
3. Required support for screenshots, optional on an individual report. Detailed upload bounds above are engineering
   proposals, not numbers the owner independently specified.
4. Chose to wait for all four clients before release.
5. Accepted daily same-host backup and its disclosed limitations.
6. Google OAuth project does not exist. Intended administrator is
   `evgavrilovev@gmail.com`; verify the real Google subject before bootstrap.
7. Only Codex is available; real Claude Code, Claude Desktop and Hermes access
   must be arranged for their mandatory gates.
8. Follow-up: target server and domain are **not selected**; selection is an
   explicit preparation task, not an available deployment prerequisite.

9. Follow-up after review: cards/results are visible to everyone; reports and screenshots are retained 30 days after beta closure.

These answers confirm the listed product decisions and authorize revising the
planning artifacts. The screenshot assertion/adapter revision and remaining
implementation scope are presented concretely here; no product code, test,
account provisioning or deployment is authorized by silently reclassifying the
answers as a blanket approval. Already confirmed choices need not be asked again.

## Decision record

- Product decision/reference: numbered owner replies and host/domain follow-up in this conversation, 28 October 2026.
- Implementation scope approved by the owner on 28 October 2026: commit/push this package and launch three subagents to implement these specs with BDD and end-to-end tests. Approval covers BPC-REQ-001–015 / BPC-SC-001–026 and their currently declared variants/defaults. It is not runtime acceptance or permission to fabricate missing external access.
- Reviewed source/spec/harness proposal hashes: pin at the approval checkpoint.
- Runtime evidence: not_run; no release decision has been made.

## Implementation approval checkpoint

The latest explicit owner instruction supersedes the earlier pending implementation status. Proceed with the reviewed domain implementation, BDD and real browser/backend/database E2E. Missing host/domain, Google project or actual client/model access remain explicit external acceptance prerequisites; they do not block independent local implementation. No unrelated MVP scope or real-money operation is included.

Approved artifact SHA-256 pins:

- `proposal.md`: `870cfcfa4ac2243796685236dba3c6d626c2a79e7fe65497a6d4ad811a4192c5`.
- `design.md`: `bb171e7a4d192cbd47c0f46e9788666d30bad4308485eafd918a14f39f295750`.
- `specs/beta-poc-delivery/spec.md`: `28552811f4464186a8ce8e9e70fd8c62a980b290a56417c2114fe1da039e40be`.
- `bdd-harness-proposal.json`: `9446fbfc18410aa7eaece81ac685556f7853798d54b8e7448579f11a4f77cc92`.
- `bdd-design.md`: `54765801ffc1002e992e1bffcccc2e3357130a36e00b7c0caf55657258d9276f`.
