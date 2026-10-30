## Context

Baseline: `4e84d0e`, 28 October 2026. See [proposal](proposal.md) and
[delivery plan](../../../docs/poc-delivery-plan.md). Local Codex transport/auth
has 17/17 scoped observations; post-stop reconciliation has 16/16. The reference
actor, not a model in Codex, executed full12. Existing BTS acceptance is 2 passed,
32 blocked; BRL has 25 blocked. Historical reports remain evidence of their own
sources/boundary and are never relabelled as beta acceptance.

The current `config.ts` forbids the local coordinator in production, requires
loopback for it, and restricts Codex compatibility to HTTP loopback/dev/test.
Without a real coordinator/readiness provider, server start is fail-closed.
The training harness currently covers individual tasks and S1→S2, not arbitrary
training selections. Direct admin bonus grants exist; redeemable bonus codes
and support reports do not. Google protocol tests used an isolated provider;
actual target-host Google login is an external prerequisite.

Owner clarification, 28 October: bonus-code behavior is accepted; queue expiry
is **24 hours**, not one hour; reports include screenshots; release waits for
all four client families; daily same-host backup is accepted. No Google OAuth
project exists yet. Intended administrator contact is `evgavrilovev@gmail.com`;
its verified Google issuer/subject must be established before admin authority
is configured. Only Codex is currently available; Claude Code, Claude Desktop
and Hermes need participant/tester access. Host/domain are not selected; selection is a preparation task.
The owner additionally selected public cards/results for everyone and removal of
reports/screenshots 30 days after the beta ends. Product decisions are confirmed; implementation approval and runtime evidence
remain separate from these answers.

## Goals / Non-Goals

**Goals:** reusable, bounded external beta with participant-owned models, exact
internal bonus accounting, public eligible-result summaries and private owner controls/reports and enough operational
evidence to run a 20–30-person cohort. Target first 3–5 people by day 7 and
expanded beta by days 10–14; verify external feasibility by day 2.

**Non-Goals:** all items excluded in the proposal, including the full multi-version leaderboard product and real-money operations. Wallet code is retained without requiring
wallet onboarding. A free bonus cohort measures use/interest, not actual paid
conversion or a mainnet/production-capacity guarantee.

## Decisions

### 1. One additive beta capability and explicit obligation ownership

`specs/beta-poc-delivery/spec.md` owns the new beta boundary and its release
matrix. Reuse the domain services and existing rules; do not fork a second
ledger, grader, agent identity system or task suite. Alternatives of finishing
every MVP package before beta, or cloning all their requirements, would expand
scope without adding a needed user journey.

| Existing capability | Included obligation / PoC scenarios | Deferred product area |
| --- | --- | --- |
| OID | verified Google identity, open admission, admin subject, session/owner isolation; BPC-SC-001/002 | invitation-only recruitment, wallet linking/recovery |
| AAP | private agent card, permissions, credential replacement/revoke, scoped authorization; BPC-SC-007–012 | general OAuth clients or every historic client edition |
| TBB | immutable source lots, exact units, permissions/limits, conservation and source-linked refunds; BPC-SC-003–006/014–017 | cash shortfalls, forum billing, paid conversion |
| BRL | intent/admission, queue/start/debit, per-agent slot, deadlines, independent tasks, finish/recovery/fencing, private feedback; BPC-SC-005/008–017/021/025 | full historic handoff UX matrix |
| BTS | one current Training roster S1/M1/H1, unchanged twelve-task Ranked12 definitions, validators/rubrics, sealed independent effects and unknowns; BPC-SC-013–015 | changing Ranked12 order/weights/price/rubric, redesigning difficulty, adding tasks |
| BEF main | pinned read-only source fork, synthetic assets, chosen actions, observation and reset/isolation; BPC-SC-013/021/022 | live user funds and mainnet execution |
| OPS active | bounded admission, process/data persistence and verified recovery; BPC-SC-016/021/022 | full high availability, off-host disaster recovery/SLA |
| BLP active | shared publication marker, coherent exact best/tiers and public allowlist; BPC-SC-025 | full historical boards and forum links |
| New beta | redeemable codes; private reports; minimal public result views; retention; target-host/client release record; BPC-SC-003–006/018–026 | public support forum and error analytics/rankings |

The current local-only AAP addendum remains exact. This proposal adds a distinct
remote beta profile only; it does not authorize its use by toggling existing
local flags or deleting their guards. Reconcile affected AAP/BRL design/config
notes during implementation under this new reviewed scope, without changing
their scenario assertions, task rules or acceptance reports. Sync of this
capability cannot promote old blocked gates. Included invariants that fail in a
beta journey block beta even when the old whole-package gate stays deferred.
Trusted-integrity intake/adjudication is not introduced here: isolation/access
rejection must be proven, uncertainty remains unknown, and a reported allegation
cannot become disqualification, charge forfeiture or an administrator score edit.

### 2. Validated non-secret beta manifest before any external gate

Proposed profile IDs: execution `beta-bef-v1`, transport `beta-remote-v1`.
The manifest pins the current Training roster and its selection/pricing contract;
source commit/build hashes; HTTPS origin, proxy trust and private listeners; Google issuer/client ID/callback and
configured founder subject; exact task release/manifest/rubric/asset/source-block
hashes; worker/queue/timer policy; artifact paths/retention; and a declared
entry per enabled client family (edition/version/platform/protocol/auth/redirect).
Secrets are supplied by secret files/runtime settings and excluded from it.

Two manifest states break the qualification bootstrap cycle: `qualification`
and `cohort_release`. Qualification is an operator-restricted, source-pinned beta
instance with no public cohort admission; enabled profiles have complete declared
auth/protocol/origin inputs but carry `unverified` status. It may start to collect
actual Google, client and model evidence, including the first Codex task. A missing
family is disabled/unverified here, never silently labelled supported. The frozen
cohort-release manifest requires all four verified profiles and their complete
BPC gates. Only that state enables unrestricted public cohort admission/results. Qualification network allowlists permit controlled anonymous application reads of the same public handlers for BPC-SC-025, without opening the cohort or bypassing application auth on private routes. Same domain
security, synthetic isolation, bonus conservation and safe reporting apply in both
states; qualification is not a fixture or an authorization bypass.

Exact DNS names, client versions other than the observed Codex baseline and
Google values are not invented in planning. Missing/unsupported inputs for an
ENABLED profile block its qualification startup; missing verified families block
cohort release, not evidence collection for other declared profiles. Changing rules, protocols outside the supported
allowlist, auth mechanisms or scenario assertions returns to scope review;
pinning a concrete host or observed supported client edition does not.

Proposed initial bounds to approve: one active global run, one active run per
agent, at most two unstarted accepted runs per owner and eight globally, pending
intents capped separately at two per owner/thirty globally. Snapshot an 86400-second
queue deadline, preserving original expiry on retry/restart, and a 180-second
successor-preparation bound. Preserve published task timers and initial prices
(Ranked12 remains 1 internal USDC; the current S1/M1/H1 training bundle is
0.5 internal USDC) and existing agent UTC limits. Training uses the single
current S1/M1/H1 roster, weights 1/2/3 and denominator 6.
These are beta configuration bounds, not measured capacity. Host tests
must validate them; increasing concurrency requires a new pinned measured policy.
Report defaults: title 160 characters, body 4000, request body 16 KiB maximum,
five new reports per minute per principal and fifty per hour per owner; retrying
a committed idempotent submission does not consume another creation allowance.
Bounds are validated as positive finite values in the manifest, not bypassed by
client fields or a free operation.

The accepted queue values are one execution slot, eight globally queued runs,
two per owner, with cancellation after 24 hours. This waiting bound does not
change task execution timers, extend pending owner-intent TTL or renew on retry.
The separate beta policy must allow 86400 seconds rather than clamping it to
the existing local profile's 3600-second queue maximum. Local behavior stays
pinned. Report/screenshot caps below are proposed implementation bounds.

### 3. External beta runtime with retained isolation

Use existing coordinator/observers/executor behind the new explicit beta entry,
with a dedicated beta DB/environment/config and validated readiness provider.
Web/API may run as production builds behind HTTPS; the BEF admin, chain RPC,
source proxy, DB, signer and private evidence stay on private interfaces. The
public worker accepts domain operations only; it exposes no raw signer/admin
or arbitrary upstream forwarding. Readiness requires the pinned release and
actual environment observation; a local fixture flag cannot establish it.
Keep the existing local dev/test profile unchanged for historical replay.

One generation-scoped isolated environment/session per current task, durable
action cutoffs and receipt binding, observation→seal→evaluate→fence→terminal
sequence, source-aware atomic start and exclusive dispatch claims remain shared
domain services. Restart reloads durable run/action/evidence identities; missing
ephemeral sessions cannot be fabricated from a new environment. Reconcile or
fence them and use bounded platform-failure recovery. Replay reads retained bytes
and their hashes; it never retransmits a task transaction or issues credits.

Alternative rejected: reverse-proxy a dev acceptance runner and disable its
loopback checks. That mixes test credentials and local assumptions with users,
does not supply production readiness and cannot establish the beta boundary.

### 4. Client connection and real model evidence

Reuse manual bearer credentials where a real selected client can configure them.
For clients needing browser OAuth, use the existing owner consent/code/PKCE path
with explicitly registered client IDs and exact callback URIs; extend the
loopback-only configuration only for a verified required callback in the beta
allowlist. No arbitrary dynamic registration, redirect wildcard, SSRF metadata
fetch, resource substitution or identity trust from `clientInfo` is allowed.

The remote manifest initially permits only the two protocol generations already
represented in this repository, `2025-06-18` and `2026-07-28`, with the actual SDK
transport for each. Real initialization/call behavior and auth determine the
supported matrix; neither rewriting a version label nor faking a newer client
constitutes compatibility. A client needing another protocol/mechanism is a day-2
blocker requiring explicit review, not a silently weakened default. Preserve
modern and local-profile tests, current identity, mode permissions, limits,
resource audience and revoke enforcement across both remote transports.

Provide a short per-client setup recipe: origin, secure credential/consent setup,
preflight, owner-created intent, agent acceptance/current-task/action/finish,
read result, report and reconnect/revoke. Credentials are never copied into URLs,
prompts or reports. Setup may be manual; no one-click claim is made.

One real model session in EACH family must perform a training selection and a
full12 run. Retain private protocol/effect evidence and versions, not provider
tokens or full model transcripts. Model solution failures/partial credits are
valid benchmark outcomes and do not block release when the protocol and verified
grading complete correctly. Infrastructure-caused unknown/failure blocks that
positive journey until resolved; a deterministic reference actor remains useful
for shared boundary negatives and all-task coverage, not the four model gates.

For these controlled acceptance sessions, record actual client configuration and
safe provider-invocation metadata sufficient to distinguish live inference from
the deterministic fixture. This is evidence about those sessions only, not an
attestation of every participant's model identity or absence of human help.
HTTP request provenance alone cannot establish who solved a task.

### 5. Google open registration and internal credits

Reuse Better Auth Google verification and owner admission in `open` mode.
Code possession does not assign identity, admission privileges or admin. Admin
is one configured verified Google provider subject; no email auto-promotion.
Create/configure the real Google OAuth project and verify the owner's intended
administrator account in an operator-controlled bootstrap, then pin issuer/sub.
The email is an account-selection instruction, not authentication evidence;
keep it out of public fixtures and diagnostics.
Creating cards, enabling training/ranked permissions and setting nominal spending
limits remain explicit owner controls, with short instructions/presets to avoid
unexplained initial zero caps. Bonus credit itself grants no permissions.
PoC requests allocate only valid bonus lots; no cash/deposit/withdrawal capability
is exposed or inferred from a synthetic balance. Existing unused wallet endpoints
are not part of new required onboarding and need not be removed.

### 6. Codes and atomic redemption

Proposed tables: code (UUID, issuer, title, kind, positive six-decimal amount,
maximum uses, used count, verifier, issued/disabled timestamps), redemption
(code/owner/grant/operation/receipt IDs), plus existing grant/ledger/audit tables.
Single-use codes fix maximum uses to one; group codes fix a positive maximum.
Amount/max/kind are immutable after issue; a new offer gets a new code. Default
credit has no expiry, following the existing grant default. Amount/maximum and
bounded label are entered by the admin. Expiring campaigns are deferred.

Generate at least 128 random bits; persist only a keyed verifier with a secret
outside the DB snapshot. Show plaintext once to the authorized issuer. Issuance
retries return the same code ID/terms without minting another code; if its first
response is lost, the UI lists it and offers disabling/reissuing, not recovery of
plaintext from logs. Never log codes. Treat a group code as intentionally shared
and a single-use code as transferable until first valid redemption.

In one transaction acquire the code lock then owner-ledger lock in the shared
lock order; recheck existing owner/code redemption before treating disable/full
as a failed retry. For a new claim validate active state/capacity, write one
redemption and existing immutable tester-bonus grant/entry/audit/receipt, increment
usage and commit together. Refactor the existing grant writer to accept the same
transaction rather than calling an admin HTTP grant route after capacity commit.
Unique code/owner and stable redemption financial-operation keys deduplicate
same-owner claims with either identical or different retry keys. Changed payload
under an existing operation key conflicts. Different owners racing the last use
get exactly one winner. Anonymous, agent and foreign-owner claims cannot choose
the recipient. Insufficient bonus at run admission leaves no partial effect.

Admin disable serializes on the same code row: a committed earlier redemption
keeps its grant, a later new redemption fails. Owner/private balance exposes exact
available/reserved values and code redemption receipt. No bonus-to-cash conversion.

### 7. Queue, lifecycle and failure policy

Bound pending intents separately from accepted unstarted runs, using serialized
count/admission decisions to prevent overshoot. Reject over-capacity before a new
run/hold is committed. Preserve owner turn rotation, one active slot per agent,
snapshot prices/mode/task order/release/deadlines, UTC rechecks and current access.
Training rejects any closed task rather than silently filtering it. Charge only
at ready atomic start. Task failures do not stop later independent tasks; known
mandatory violations irreversibly zero that task. Unknown actions suspend relevant
progress and reconcile the ORIGINAL operation/receipt, without blind write retry.

At 86400 seconds the authoritative deadline makes an unstarted run permanently
ineligible to start; this is not a promise that an unreachable executor is already
fenced. For queued work without an allocated environment, expiry releases holds
once immediately. For preparing work with a live lease, commit
`cancellation_requested` / `queue_expiry_fence_pending`, deny late start/actions,
retain the original claim/slot and any holds that cannot safely be released,
then release them once the exact generation fence is confirmed. Show this state
and reserved amount to the owner; retry/restart never renews the deadline.
A failed fence stays pending/unknown with operator-visible retry status; do not
manufacture a fence, refund or safe outcome merely because another timeout elapsed.
Test before/at/after cutoff, BEF outage during preparation, restart and eventual
fence confirmation. This reconciles 24-hour cancellation with the existing safe
lease-release contract. It does not change the selected wait or charge policy.

Pre-start cancellation completes with one release after this safe boundary and no debit. Post-start
voluntary cancel/revoke retains the original charge under BRL; fence/clean up
before releasing the slot. Bounded platform-attributed recovery uses at most
180 seconds wall time with recorded clock exclusion, then leaves unresolvable
evidence unknown, closes the run unranked and refunds the original bonus debit
exactly once under existing source/expiry rules. Never turn a timeout alone into
proof that an operation had no effect. Refunds use trusted server outcomes and
source links; neither a participant report nor a generic admin button triggers
one. Test platform failure after an actual committed action and lost-response
retry; frozen evidence is not rewritten and a refunded run cannot reopen.

### 8. Reports, authority and safe context

Proposed APIs: owner `POST/GET /api/owner/reports`, agent `POST /api/agent/reports`
and MCP `support.report`, admin `GET /api/admin/reports`,
`GET/PATCH /api/admin/reports/:id`. Final route names are implementation details
within these boundaries. Browser routes require owner session/origin checks;
agent routes require current agent principal/resource/permission checks without
pretending a remote agent has a browser Origin. No anonymous intake in PoC.
Reporting is a free support capability for an authenticated connected agent;
it does not enable training/ranked or consume benchmark action budget, change
timers, finish tasks, grant credit or expose private evaluation internals.

Persist UUID receipt, authenticated owner/optional agent, server time, source,
title/body, private screenshot references, optional run/task/action locator, deployment/client version when
known and status. Validate each provided link, including run-agent association;
derive principals from auth and never accept an arbitrary owner ID. Reports
without a run are valid for connection failures; a failed credential may report
through its owner's web session. Same principal+operation key+payload returns
the same receipt across restart; conflicting payload fails. Similar text with
different keys is not silently merged; rate limits bound duplicate spam.

Automatically attach only allowlisted correlation IDs, safe error category,
timestamps, approved version identifiers and validated public-safe state. Missing
context is marked unavailable. Do not store raw cookies, codes, bearer/provider
tokens, signatures, private keys, model transcripts or hidden-case answers in
automatic context. Reject disallowed structured fields, bound/sanitize free text
for known credential material, and treat all participant text as private untrusted
content with no execution/rendered HTML or automatic causality/scoring verdict.
Avoid promising that arbitrary user prose can be proven free of all sensitive data;
the UI tells submitters not to paste secrets, and no report is publicly published.

Admin list filters source/status/agent/run and uses bounded pagination; detail
shows private safe context. Status is `new → in_progress → closed`, with reopening
to `in_progress` allowed and audited; concurrent stale status updates conflict.
Owners see only their receipts/status/text and own screenshots, agents only their own receipt; neither
sees other reports or admin actions. No general-purpose attachments, chat, email notifications,
automatic error leaderboard or task-step disclosure is added.

#### Screenshots included in the minimum

Support optional screenshots for both owner-form and agent-created reports. The
owner can choose local images; an agent can upload image bytes it already has.
Never auto-capture the participant's desktop or retrieve a caller-supplied URL.
Proposed initial caps: three images per report, 5 MiB input per image, PNG/JPEG/WebP
only, at most 16 million decoded pixels per image. Text/metadata retains its own
16 KiB limit. The owner browser streams multipart bytes to an authenticated
upload route. Native agents use MCP `support.screenshot.begin`,
`support.screenshot.chunk` and `support.screenshot.finish`: begin returns a
principal-bound opaque upload ID; each chunk carries at most 24 KiB decoded
base64 bytes, sequence index and hash; finish checks declared total/hash and
normalizes the image. JSON envelopes stay below the existing 64 KiB MCP limit.
Exact chunk retries are idempotent, conflicting/out-of-order chunks fail, and
unfinished uploads expire. These data are tool payloads from actual image bytes,
not a model-generated reconstruction of an image or credentials in a prompt.
The MCP server authenticates with the existing configured connection; no model
needs to retrieve its bearer for a second HTTP request. Both browser and MCP
converge on the same upload service and receipt consumed by `support.report`.
If a selected client cannot supply original image bytes, its agent still creates
the report and its owner adds the screenshot through the authenticated report
page; explicitly test/document this path for that client, not a claimed automatic
capture. Show a preview and advise the submitter to remove secrets.

Authenticate upload first; stream-limit bytes, verify decoded image format and
pixel bounds, re-encode to an allowed inert image and strip EXIF/other metadata.
Reject SVG/GIF/PDF, disguised HTML, corrupt/oversized images, external URLs and
path traversal. Store normalized bytes under an opaque server-chosen ID in a
private persistent attachment volume, with content hash, dimensions, size,
uploader principal and upload/attachment state in PostgreSQL. Do not retain raw
input or put image bytes in application logs. No OCR/automatic content judgment
is required; treat pixels as private user-supplied content, not proven facts.

Use a short-lived upload receipt followed by transactional attachment to the
report. Same upload key/payload retry recovers its original object; conflicting
bytes conflict. An agent may bind only its own upload to its own report. An owner session
may bind its own upload to its own report or an existing report from its own
agent, with an audited owner-authored attachment event. This is not agent
impersonation or permission to rewrite agent report text. Foreign owners and
agents cannot bind it; owners may view screenshots on their own agents' reports. An image cannot be rebound to a foreign or second report. Enforce the
three-image limit atomically; a failed attach cannot create a dangling visible
report or debit. Delete unlinked uploads after 24 hours through an idempotent
cleanup job; committed attachments follow the report retention deadline defined below. Reference-count/transaction guards prevent cleanup from deleting
an attachment being committed. Disk/upload admission bounds also apply before
report attachment and when benchmark admission is paused.

Initial upload budgets (engineering policy, validated before enablement): 5 MiB
normalized output per image, three pending images/15 MiB staging per owner,
75 MiB new image input per owner per rolling 24 hours, and 1 GiB total live plus
staged normalized image storage. Reserve worst-case bytes before admission and
count in-flight/orphan bytes; exact retries do not multiply quota. Throttle chunk
requests separately from report creates. Normalize through one bounded image
worker so image decoding cannot exhaust the task worker. Pause new uploads at
less than max(2 GiB, 20 percent of the attachment volume) free space or insufficient
space for a consistent backup. Text-only reports remain available if their own
DB/health bounds permit. Validate these limits and the backup-space budget on
the chosen host; lowering limits under insufficient capacity is disclosed, never
silently accepted as the tested manifest. No infinite staging or uncapped decoded
output is allowed.

Download/preview checks current owner/admin authority at every request, uses
private cache headers and fixed validated image Content-Type, never a public
static path or fetch proxy. Agents receive their attachment/report receipts;
private attachment read access is for the report owner and administrator.
Automatic context still omits hidden answers and credentials; screenshots are
explicitly submitted, never generated from internal evaluator/hidden-case state.

Include committed normalized screenshot bytes and hashes in backup/restore,
with missing/corrupt attachments blocking a claim of complete report restore.
BPC-SC-024 is the dedicated upload/privacy/failure gate; owner, agent, triage and
restore scenarios also exercise their screenshot surfaces.

### 9. Persistence, release and learning loop

Persistent DB/evidence/screenshot volumes are separate from source/module/test mounts.
Supervise web/API/worker, validate health/readiness, monitor queue age, disk
space, failed/unknown runs and support counts. Provide administrator pause of
new admissions while allowing read/report/reconciliation and orderly drain.
Freeze run release/profile snapshots; no destructive DB reseed during beta.

Take a consistent backup with DB, referenced evidence/screenshots, manifest/hash inventory
and required secret-recovery references stored separately under operator control.
Initial procedure pauses/drains admission and fences or reconciles unfinished
effects before checkpoint. Restore into an isolated instance and validate original
ledger totals, code counts, reports/screenshots, result/evidence hashes and no repeated effects
on retry. Retain same-host daily copies for the beta plus before migrations;
this does not protect against loss of the host. Proposed RPO is the last verified
daily checkpoint (up to 24 hours), target operator-assisted restore within 4 hours;
measure it in rehearsal and disclose if unmet. Separate report retention from immutable run/ledger evidence. The owner-selected
rule is report text/context and screenshots until 30 days after the beta ends,
not 30 days after each submission. The administrator records one audited
`beta_ended_at`; expiry is that timestamp plus 30 UTC days, not extended by
report status changes, retries or restore. Stop new report intake at that expiry.
At expiry, deny reads immediately and idempotently purge report text/context and
committed image bytes/links with retries on failure, retaining only non-content deletion
receipts and already aggregated cohort counts. Keep run scores, original financial
receipts and official evaluation evidence under their separate retention; report
images never become official grading evidence.

After daily consistent backup, rotate to a bounded seven-checkpoint set plus the
latest pre-migration checkpoint. At the report deadline create/verify a sanitized
checkpoint and retire report-containing snapshots at the retention deadline; failed deletion is access-denied and operator-visible until retry completes. Restore
checks the retention timestamp/tombstones before enabling reads/writes and purges
expired report data so an old backup cannot republish it. A completed restore
compares active, nonexpired report/image hashes or expected deletion receipts,
not a requirement to resurrect expired screenshots. No off-host copies are added.

Release bundle records source/profile/client hashes, per-scenario outcomes,
sanitized raw paths/hashes, and independent DB/BEF observations. All 26 mandatory
beta gates must pass on the declared target boundary; missing provider/client,
unknown observations or a skipped mandatory gate blocks beta release.
Replaying a bundle verifies integrity/semantics without sending effects again.
Capture small counts: distinct owners signed up/connected, training/full completed,
repeat use, failures/unknown by client, reports and manual support time. Derive
counts from stable IDs; bonus usage is not paid revenue. No new analytics service.

### 10. Minimal public cards and eligible results

The owner chose visibility for everyone, including anonymous visitors. Reuse the
existing first-public-action marker written by a complete eligible ranked run;
profile edits, preflight/training and incomplete/unknown runs still do not publish
a new card. Add a small English public results list and agent page with the
versioned best complete result, overall/four difficulty indicators from that same
run and its declared agent-version snapshot. Preserve exact best selection and
tie semantics already described by BLP; do not assemble tier maxima from different
runs or claim a new ranking model. A verified zero result is a result, not no data.
This minimal public projection is now in PoC; full historical boards/forum remain
out of scope. Owner management/history and detailed task reasons stay authorized
private surfaces. The public allowlist contains card metadata, declared/unverified
client/model labels if supplied, benchmark/version and verified score summary;
never owner email, bonus balance, credentials, reports/screenshots, private reasons,
sealed cases or task journals. Use the shared marker and persisted selected result,
not a second public flag or a raw private API response. Test anonymous/foreign API,
HTML/hydration/cache reads before and after marker commit, retries, ties, partial
scores and unknown/incomplete exclusions. BPC-SC-025 owns this small read surface.

### 11. Current Training selection and pricing

The latest 30 October user decision selects one current Training roster:
S1, M1 and H1 in canonical order with weights 1/2/3, a fixed denominator of 6
and a bundle price of 0.5 internal USDC (500,000 micro-USDC). Price each valid
selection once as `ceil(500000 × selected-weight-sum / 6)` micro-USDC. A
single-task selection costs 83,334 / 166,667 / 250,000 for S1 / M1 / H1
respectively, and the full trio costs exactly 500,000. Do not add individually
rounded single-task prices to compute a multi-task request.

Quotes and admitted run snapshots SHALL bind the current roster, exact selected
IDs/order, weights, denominator, rounding policy, quote and charge, rubric pins,
and source/evidence hashes. UI and API admissions reject closed or non-current
IDs, mixed/duplicate/empty selections, stale or cross-selection quotes and
caller-supplied grades. Rejected requests produce no run, preparation,
reservation/debit, task action or BEF effect. The catalog is not split into
versioned current/legacy branches. Ranked12 keeps the existing twelve IDs and
order, 1/2/3/5 weights and total 26, 1-USDC price, rubric, grading and unknown
rules unchanged.

BPC-SC-014 retains its stable ID, mapper and adapter. It covers current Training
selection and price through a real UI start and bound agent actions, plus
direct-API, stale/cross-selection quote, invalid-ID and invalid-selection
rejection with durable no-effect evidence. New validation evidence uses fresh
paths; frozen repository proof artifacts remain unchanged. The separate
root-owned cleanup targets exactly five local qualification runs and their
dependent results while retaining accounts, agents, auth, codes, ledger and
reports. This amendment authorizes bounded implementation and executable BDD
changes after root review, but no additional real model runs, credit
grants/spend or credential operations beyond the previously consumed 3.1
single attempt.

## Risks / Trade-offs

- External transport or worker requires more than the current local reuse → day-2
  go/no-go after genuine external Google login and one model-executed task; all
  four client connection paths diagnosed. Missing families are not silently dropped.
- The four selected editions need different auth or unsupported protocols → pin
  actual profiles; exact redirect allowlists; block and review incompatibilities.
- Single slot limits throughput → visible bounded queue/deadline and measured
  load, not a promise of 20–30 simultaneous runs or automatic capacity increases.
- Open Google registration does not establish one account per person → one group
  redemption per owner limits accounts, not human identities; fixed code caps
  bound total subsidy. Do not claim Sybil resistance.
- Free-text reports are untrusted and privacy-sensitive → bounded private storage,
  allowlisted auto-context, escaped rendering, no commands/model instructions run.
- Live-model latency and user availability vary → actual client/model acceptance
  and days 11–14 buffer; elapsed agent time is not an evidence-based delivery SLA.
- Shared file/infrastructure changes conflict between agents → one integrator,
  up to three scoped workers, serialized migrations/build/capture on one stand.
- A stale quote or changed selection could alter training charges → quotes bind
  the submitted current selection and one per-request rounding result; invalid
  requests have no effects, and Ranked12 pins remain identical.

## Migration Plan

1. Preserve the 28 October BPC approval and apply the latest 30 October
   single-roster Training amendment. At root review, confirm the S1/M1/H1
   roster, weights, denominator, pricing and amended BPC-SC-014 boundary before
   implementation. Keep existing gate and task statuses unchanged; no
   additional real model run or credit spend is authorized.
2. Add code/report schemas and uniqueness/audit/indexes with additive migrations;
   retain accounts, agents, auth, codes, ledger, reports and unrelated records.
   Root separately owns deletion of exactly five local qualification runs and
   their dependent results. Deploy flags off and rehearse backup.
3. Implement isolated beta runtime and one external journey before code/report
   work is considered releasable. No fixture identity or response provider in beta.
4. Implement codes, reports and client matrix in parallel; serialize shared seams.
5. Run scoped gates, freeze evidence, restore rehearsal, then 3–5-person trial;
   only the reviewed green target build is admitted to the expanded cohort.
6. Rollback pauses admissions and new writes as appropriate, drains/fences workers,
   and restores a compatible application over retained additive data. Do not
   introduce a legacy Training catalog branch, reverse financial/evidence
   migrations destructively or reset the user DB.
   Reconciliation precedes any restored write enablement.
7. Sync/archive only the completed beta capability after its own mandatory gates;
   old active packages remain open. Existing local evidence paths stay readable.

## Open Questions

Host/domain are not selected; selection and operator access are preparation tasks. Google OAuth project does not
exist: add its creation/configuration before real login acceptance. The owner
selected the administrator email recorded above; the verified subject remains
to be obtained securely. Only Codex access exists today. Arrange real Claude
Code, Claude Desktop and Hermes sessions with willing testers, or obtain the
required application/model access before acceptance. Availability is not consent
to send invitations or buy accounts; no accounts need be shared in chat.
Source RPC/BEF availability, exact editions and cohort test slots must also be
pinned. Record non-secret references in the beta manifest.

All four families remain mandatory: the owner chose waiting for them rather
than a partial-family release. The 10–14-day target therefore depends on getting
these accesses early; screenshots consume some integration/acceptance buffer.
Missing clients do not become a successful or optional gate.

Code behavior, queue caps with 24-hour wait, screenshot inclusion, all-client
release and same-host backup are user-confirmed product decisions. The latest
30 October user override approves one current Training roster, S1/M1/H1 at
weights 1/2/3, denominator 6 and the 0.5-USDC bundle, with no versioned catalog
or backward-compatibility branch; Ranked12 remains unchanged. Root owns deletion
of exactly five local qualification runs and dependent results, retaining
accounts, agents, auth, codes, ledger and reports. This planning change leaves
frozen repository proof artifacts untouched and uses fresh paths for new
validation evidence. Bounded implementation and executable BDD changes may
proceed after root review. No additional real model runs, credit grants/spend
or credential operations are authorized beyond the previously consumed 3.1
single attempt. The original broader implementation approval remains as
recorded on 28 October. No unanswered external value is treated as a successful
check.

## Acceptance design and approval

See [BDD packet](bdd-design.md), [review-only harness proposal](bdd-harness-proposal.json),
[tasks](tasks.md) and [approval boundary](approval.md). All beta runtime gates
are `not_run`; document validation cannot change them.
