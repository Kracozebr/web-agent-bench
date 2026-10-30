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

Original 28 October approved artifact SHA-256 pins (historical; these identify the pre-amendment package):

- `proposal.md`: `870cfcfa4ac2243796685236dba3c6d626c2a79e7fe65497a6d4ad811a4192c5`.
- `design.md`: `bb171e7a4d192cbd47c0f46e9788666d30bad4308485eafd918a14f39f295750`.
- `specs/beta-poc-delivery/spec.md`: `28552811f4464186a8ce8e9e70fd8c62a980b290a56417c2114fe1da039e40be`.
- `bdd-harness-proposal.json`: `9446fbfc18410aa7eaece81ac685556f7853798d54b8e7448579f11a4f77cc92`.
- `bdd-design.md`: `54765801ffc1002e992e1bffcccc2e3357130a36e00b7c0caf55657258d9276f`.

## Superseded interim training amendment — 30 October 2026

**Historical record only.** The user later replaced this interim versioned-catalog
decision with the single-current-roster override recorded below. The scope and
pins in this section do not define the current implementation contract.

**Decision:** approved for the bounded training-release change, with root review before implementation. This amendment preserves the 28 October approval for the rest of the beta and changes only BPC-SC-014's training-release contract.

### Approved scope

- Add immutable task-release schema v2 for new training admissions, pinned to current task catalog version 3 containing exactly S1/M1/H1 in order, weights 1/2/3 and fixed denominator 6.
- Preserve the 0.5 internal-USDC training bundle (500,000 micro-USDC). Price each request once as `ceil(500000 × selected-weight-sum / 6)`; single-task selections cost 83,334 / 166,667 / 250,000 micro-USDC for S1 / M1 / H1, and the full trio costs exactly 500,000.
- Preserve the v1 eight-open-task profile and denominator 15, every historical v1 run snapshot and source capture, for version-selected read-only replay. Do not rewrite or re-evaluate v1 records under v2; reject v1 releases/quotes for new v2 admissions.
- Keep Ranked12 unchanged: twelve task IDs/order, weights 1/2/3/5 and total 26, 1-USDC price, rubric, grading, unknown and settlement rules.
- Keep BPC-SC-014's ID, mapper, adapter, mandatory gate and environment boundary. Within that scenario, add real-UI start/agent action evidence, direct-API/quote/version/old-release negatives, legacy replay hash checks and durable no-effect evidence. Add no scenario ID or gate.

### Limits and status

The bounded implementation and executable BDD changes are authorized after root review; this planning update does not authorize additional real model runs, credit grants/spend, or credential operations beyond the previously consumed 3.1 single attempt. Existing BPC gate results and the 3/45 task progress remain unchanged; runtime acceptance remains `not_run`. The amendment does not change or promote any official gate.

The approval is limited to this exact current training roster/pricing/versioning change and its SC-014 variants. Any further catalog, task, price, denominator, Ranked12, protocol or scenario-inventory change returns to review. No additional human approval is needed to implement this approved amendment after root review.

### BDD and artifact pinning

The planning packet updates `spec.md`, `bdd-design.md` and `bdd-harness-proposal.json` under the same BPC-SC-014 ID. The next implementation phase must update the executable scenario map, semantic harness contract and Gherkin/mapper evidence together; no executable tests or code were changed in this planning pass. Current amendments supersede the historical artifact pins above; updated planning snapshot hashes are recorded after this packet is reconciled.

30 October 2026 superseded-interim planning snapshot SHA-256 pins:

- `proposal.md`: `a249103c934b67fd4d30f5a97da8ef7795bec6cd404d199904fa640b5a591f12`.
- `design.md`: `a3b8f102fcb494b2f1ce5585713b99c005f453737ba87a33b3f5e70c1b2d4f50`.
- `specs/beta-poc-delivery/spec.md`: `ebccdef08059090440624924907ddaff1de7e89919291eed04990e1b5014a00c`.
- `tasks.md`: `8e1d8e34dbdee9770452ac3e7468227a3a22ef43ec0af2861c5759a679961d5d`.
- `bdd-design.md`: `c186f549cf5214286adcf0c18bade36fbf7044431bc4db0ff37105ee2f2379fc`.
- `bdd-harness-proposal.json`: `6b3b7b8744e3eedb501359801627fb8c0071649334f0fb2954c31233eb156779`.
- `planning-review.md`: `2d41e2d07996cd8b6247431e34dc2bd9b6595fee4c896037ffc99376a6cd44f9`.

## Current Training override — 30 October 2026

**Decision:** the user's latest explicit override replaces the interim
versioned-catalog amendment above. It authorizes implementation and executable
BDD work after root review; no additional human approval is needed for this
bounded scope.

### Current scope

- Use one current Training roster: S1/M1/H1 in that order, weights 1/2/3,
  fixed denominator 6 and 0.5 internal-USDC bundle (500,000 micro-USDC).
  Charge a selection once as `ceil(500000 × selected-weight-sum / 6)`; single
  selections are 83,334 / 166,667 / 250,000 micro-USDC and the full trio is
  500,000 micro-USDC.
- Do not create a versioned catalog or backward-compatibility branch. Keep
  Ranked12 unchanged: its twelve task IDs/order, weights 1/2/3/5 and total 26,
  1-USDC price, rubric, grading, unknown and settlement rules remain as they
  are.
- Keep BPC-SC-014's ID, mapper, adapter, mandatory gate and environment
  boundary. Cover actual UI start and bound agent actions; direct API, invalid
  selection and stale/cross-selection quote negatives; and durable no-effect
  evidence. Add no scenario ID or gate.
- New validation evidence uses fresh paths. Frozen repository proof artifacts
  are unchanged. Root separately owns deletion of exactly five local
  qualification runs and dependent results. Retain accounts, agents, auth,
  codes, ledger and reports. This planning change performs no deletion.

### Limits and status

The bounded implementation and executable BDD changes may proceed after root
review. This override authorizes no additional real model runs, credit
grants/spend or credential operations beyond the previously consumed 3.1
single attempt. Existing BPC gate results and progress (3/45 tasks) remain
unchanged; runtime acceptance remains `not_run`. No official gate is changed
or promoted.

The approval is limited to this exact current Training roster/pricing and its
BPC-SC-014 variants. Ranked12, other product scope and the 26-scenario
inventory are unchanged.

### BDD and artifact pinning

The planning packet updates `spec.md`, `bdd-design.md` and
`bdd-harness-proposal.json` under the existing BPC-SC-014 ID. The next
implementation phase must update the executable scenario map, semantic
harness contract, Gherkin mirror and evidence paths together. No executable
BDD files, code, tests or runtime gates were changed in this planning pass.

Current override planning snapshot SHA-256 pins:

- `proposal.md`: `2cd899cb4d7d02ce7435bad4f589ce83577e957266b4e6924c9b3e357a9a1482`.
- `design.md`: `6e091f81b6340663c612aeeb2c69beefb9445654b12e323d57f9b79743d5a0d5`.
- `specs/beta-poc-delivery/spec.md`: `e46c35341f740b14dcfb8a267e06799fb9fd8b9547a58438f61b51d510e5cedb`.
- `tasks.md`: `cb02b08322c8e21e0646642b3156625115acd06a3d330fea2348557a39b926f3`.
- `bdd-design.md`: `087001523e516477119a69367394b90fa3c58c6d96b78c242ec7b006033c5d52`.
- `bdd-harness-proposal.json`: `c3f2b62e4feae47759bef93dfa112dddee011c6a61bb515871763fe4b2122768`.
- `planning-review.md`: `5f53ec560ca5b6f4acca41172fd5c0deb49b6b1dbd51cb30454997fbd9060ab4`.
