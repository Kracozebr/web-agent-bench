## Context

The source-bound native summary for intent `428f6726-5bc2-463d-adcf-fc904dc62eb2`
contains 238 MCP calls, 27 failed calls and two client error items. `EventSummary`
deduplicates failed call IDs but discards per-call names, times and error detail.
The private launcher set `--ephemeral` and `RUST_LOG=off`; a read-only search of
the exact 11:33:37–11:45:15 UTC interval found no native thread in local state.
Existing application logs also contain no relevant backend records. Other Codex
Desktop log activity is not evidence for this native process.

The original evaluations and money remain authoritative. Do not manufacture a
27-row historical breakdown from counters, action timings, or later reproductions.

## Goals / Non-Goals

**Goals:** durable bounded evidence for individual failures, readable private
diagnosis, explicit completeness and source trust, and preservation across
restart/backup. Support the existing native participant-owned execution model.

**Non-goals:** raw argument/result/message collection, native Codex credential access or raw token exposure, altered
grades or deadlines, automatic compensation, new solver tools, or changes to the
confirmed-platform-failure report allowlist. This change cannot make a third-party client expose an error it never
reports; an uninstrumented client remains explicitly only server-observed.

## Decisions

### Server and client evidence are complementary

Instrument real MCP ingress and the actual SDK schema rejection path, not only
`runs.task_action` handlers. Distinguish ingress, authentication, schema validation,
handler/admission, executor dispatch, receipt observation and client transport.
Success timings are needed to distinguish model gaps from executor time.
An HTTP response alone is not proof of a successful JSON-RPC/MCP operation.

The native launcher projects each JSONL event in memory to an allowlisted event
and durably writes it before discarding raw content. A local private bundle and
delivery outbox work even if the server is unreachable. Automatic authenticated
delivery of safe diagnostics and a support report is the normal path; an
owner-session-authorized UI import is a fallback, not required for ordinary
delivery. Validate owner/run/connection binding and deduplicate both paths.
The chosen transport is an installer-managed diagnostic helper using its own
public OAuth client `w3bench-diagnostics-helper-v1`, authorization code + PKCE S256,
resource `/api/diagnostics`, and scopes `diagnostics:write offline_access`. The
installer opens one explicit browser consent for the already signed-in owner to
bind this helper to the selected agent/native connection. This is additional
diagnostic consent; it is not reuse of Codex's cached refresh token. The helper's
OAuth library manages its own tokens in the OS credential store and refreshes
them normally. Neither helper nor installer reads/copies Codex credential files.
Use the qualified loopback callback profile, with a separate exact registered
callback `http://127.0.0.1:38766/diagnostics/callback` in the local profile; a busy
callback port fails setup explicitly. Production resources require HTTPS under
the existing development-origin exception rules.

The helper deterministically calls a bounded authenticated diagnostics API to
register a case, append batches and obtain delivery receipts. Server ingestion
creates the diagnostic report; model inference or a second model turn is not the
delivery mechanism. Diagnostic OAuth permits only those writes and own receipt
metadata, not task operations, diagnostic reads, arbitrary reports or admin APIs.
Revoke the helper grant with its linked connection through the existing external
revocation journal. Reauthorization requires owner consent and cannot reactivate
the old task grant. Existing installations remain visibly unconfigured until this
new consent/setup completes; manual-only delivery does not pass qualification.
The new client/resource/scope/consent and receipt endpoint are implementation
work in this packet, not claims that the current server already exposes them.

### Automatic diagnostic reports and delivery authority

Owner decision, 2026-11-02: client errors must also arrive automatically as an
administrator-visible report. Use the separate kind `client_diagnostics`. Submit
one aggregate report when a run reaches terminal state or client execution fails,
including a crash/disconnect after admission while the known run is still active.
For that active-run case record `client_execution_failed`, the last observed run
status/time, and unresolved server outcome; do not cancel, finish or relaunch the
run to send diagnostics. If the helper also dies, its next start recovers the
outbox before launching a new solver. A recoverable tool error is included even
when the final run completed; no error means no diagnostic report. Collection or
transport failure is represented by safe incomplete-coverage evidence, not an
empty all-clear. Reporting must not consume an active task's deadline.

The report contains known run/session identity, error counts by tool/code/stage,
safe timing summaries, available attribution evidence, capture completeness and
diagnostic references. Unknown reasons remain unknown. Use bounded summaries and
links for a large capture instead of unmarked truncation or larger report/upload
limits. An unadmitted session has no invented runId. The existing admin Reports
section must expose the diagnostic kind and receipt. The recipient is the platform
administrator; no email/Telegram delivery is added.

### Canonical case, report and append identities

Before starting the solver, atomically persist a diagnostic session UUID and the
known intent reference locally. When an intent is known, the server's canonical
case uniqueness is `(owner_id, intent_id, client_diagnostics)`; otherwise it is
`(owner_id, diagnostic_session_id, client_diagnostics)` for an intent-free setup
session. The server assigns one `diagnostic_case_id`. Run admission enriches the
intent case with a verified run link and never changes case/report identity.
An intent-free setup case is never converted into a later benchmark case: choosing
an intent starts its intent case. No additional report for the same case is made
when runId becomes known, a process restarts, another uploader submits, or the
owner uses fallback import. A verified run has at most one intent-case diagnostic
report. A genuine earlier intent-free setup report stays explicitly unlinked.

Server ingestion/fallback import share a unique `(owner_id, diagnostic_case_id,
report_kind)` report mapping and a transaction covering its creation, creation
audit and receipt identity. This is independent of uploader/reporter actor; the
existing actor-scoped generic `support.report` idempotency key is not sufficient.
Only the ingestion service creates the reserved diagnostic report kind. Fallback
owner import verifies owner/agent/intent ownership and uses the same case mapping;
it cannot impersonate an agent or obtain an agent-only receipt.

The immutable report submission contains its case reference and safe fixed title/
body. Mutable counts, run links and completeness are read projections of the
append-only case journal, not rewritten submission arguments. Each batch has a
persisted `(case_id, segment_id, batch_sequence)` key and canonical sanitized
payload hash; identical repeats return the original receipt, changed content at
the same key conflicts. Segment identity and sequence survive client restart.
The receipt exposes case/report IDs, the highest contiguous accepted sequence and
its hash, plus segment completion state. Distinguish `report_created` from
`diagnostics_synced`; the helper cannot mark a segment synced until its final
watermark and report receipt are confirmed. Late evidence appends under new batch
keys, updates the diagnostic view and never makes another report or mutates an
old batch. Report-delivery failures remain on the same outbox; no recursive
reports about failed reports are generated.
Retry automatically after connection recovery while the authorized client is
running, or on its next launch; no always-on background service is implied.
Use at most five attempts per launcher lifetime, with backoffs 5/30/120/600 seconds
between attempts when that launcher is still running. Refreshable token expiry
uses normal helper OAuth refresh; revoked/reauthorization-required grants wait
for explicit owner consent instead of polling. Quota/retention expiry and payload
conflict have distinct terminal/blocked states. Stop the helper within 30 seconds
after the solver exits unless the user keeps the launcher open; unsent work stays
durable for the next launch. There is no implied always-on service. A missing
receipt is pending/unresolved, never delivery success. With valid authorization,
open intake and capacity, retry qualification must prove one report/receipt; with
revoked authorization it must prove zero new report writes and pending_auth.

The current authorized identity may submit only its own validated diagnostics;
revoked/expired authorization must be renewed normally, never bypassed for
delivery. A blocked outbox stays pending and cannot claim receipt. Scope any
report-only transport to diagnostics/report/receipt, not economic or admin tools.
Client-supplied logs remain untrusted observations after import or reporting.

This is an explicit new reporting trigger. Reconcile the active AFR instructions
so `client_diagnostics` can be submitted without a terminal platform-failure
reason; the existing `Platform run failure` branch retains its exact allowlist,
same-operation retry and receipt rules. A diagnostic report alone proves neither
platform fault nor entitlement to regrading/compensation.

### Allowlisted diagnostic envelope

Versioned envelopes contain generated diagnostic/session/call/trace identities,
source and observation stage, start/end/duration, known tool enum, safe error code,
HTTP/JSON-RPC status where actually observed, and optional validated operation,
action, run, task and connection references. Include client edition/version,
model/reasoning identifiers, schema/issued-contract hashes and capture completeness.
Hash canonical sanitized envelopes for integrity; never hash and archive a raw
credential-bearing message as a substitute for redaction.

The launcher injects the non-secret canonical case reference into this native
process's MCP HTTP metadata (`X-W3Bench-Diagnostic-Case`), without modifying its
server URL, OAuth audience or global config. The server validates that reference
against the authenticated native principal; the header grants no authority.
Server responses expose their generated trace ID in safe MCP metadata, including
the structured SDK-error path. The qualified parser extracts only registered
locations/enums. If a client version hides that metadata, mark correlation coverage
partial rather than joining by timestamp alone. Actual native qualification must
prove the case/trace carrier and reject a foreign/spoofed case link.

Server trace IDs are generated independently of caller data. Bind a run/action
only after current principal ownership and actual durable links are checked.
Anonymous failures have no owner/run link. A client-supplied correlation or report
is labelled untrusted until independently matched, and cannot prove admission.
If RPC IDs are arbitrary strings, correlate using bounded hashes instead of
copying their content. Distinguish retries from unique economic operations.

Do not retain raw messages, arguments, results, headers, URLs with queries,
addresses, provider data, signatures, hidden Ranked state or reference answers.
Store only registered codes and schema-known field-path segments; unknown codes,
tool names and user-controlled field names map to fixed unknown enums. Keep
missing facts null rather than inferring them from a keyword.

### Classification is an evidence projection

Record the observed failure stage separately from responsibility. Responsibility
is one of `client_contract`, `client_runtime`, `platform_contract`,
`platform_runtime`, `external_dependency`, `expected_policy_denial`, `unknown`.
Each non-unknown classification requires an explicit reason and evidence links.
An invalid argument is client-contract responsibility only when compatibility of
the published schema and issued task contract is verified. A platform schema
that cannot represent a valid issued operation is platform-contract responsibility.
A timeout with no authoritative outcome stays unknown until reconciliation.
Do not subtract client/server clocks to claim causality; retain source-local
durations and use authoritative operation order to correlate them.

The following decision table is normative in the spec and must be independently
replayed. An implementation returning `unknown` for every positive control fails.

| Complete verified evidence | Required responsibility |
| --- | --- |
| Server validation rejected a request; published schema and issued contract are compatible; safe violation/field identity matches both pins | `client_contract` |
| A pinned valid issued operation cannot be represented by the advertised schema | `platform_contract` |
| Independently reproduced qualified client exception/parse failure after a matching valid server response, with no contradictory server failure | `client_runtime` |
| Trusted server invariant/handler/dispatch failure under valid authority, not an external dependency failure | `platform_runtime` |
| Matched trusted dependency observation confirms a dependency failure rather than a schema/policy/handler defect | `external_dependency` |
| Trusted policy/grant/revocation evidence and the actual rejection agree | `expected_policy_denial` |
| Missing/contradictory evidence, only an unverified client claim, or ambiguous transport timeout | `unknown` |

Do not infer any of these solely from HTTP 4xx/5xx, a failed model tool item,
keywords or the absence of a server row. Conflicting sufficient categories resolve
to `unknown` with a conflict marker, not a priority guess. Every positive table
row must produce its named category in tests; incomplete/contradictory controls
must produce unknown. Evidence references and source trust remain visible.

### Bounds, failure handling and privacy

Proposed limits for approval: at most 2 KiB per sanitized envelope, 4096 detailed
envelopes per canonical case across all segments/uploads, and 8 MiB total per native import
bundle including metadata. Reject oversized imports before storing them. Reuse
the existing authenticated flood limits and bounded upload primitives; an import
must not raise global HTTP/body limits or bypass them.

Add shared hard storage/admission budgets; changing caller session IDs cannot
reset them. Account for reserved in-flight bytes as well as committed data, under
transactional quota locks before allocation. Server budgets cover diagnostic
envelopes, uploaded objects and delivery metadata; existing report storage keeps
its own bounds. No diagnostics quota can evict an existing retained record.

| Scope | Detailed bytes / rows / case registrations |
| --- | --- |
| Per owner, across all cases | 32 MiB / 16384 / 128 |
| Whole server deployment, shared by all API replicas | 256 MiB / 131072 / 4096 |
| Unauthenticated detail, included in deployment total | 4 MiB / 2048 / no case registration |
| Local managed helper spool, across all cases | 64 MiB / 32768 / 128 |

The first limit reached stops new detailed allocation. Anonymous/rate-rejected
requests after the anonymous budget is full update only a fixed registry of at
most 128 aggregate code/stage buckets with saturating counters; never allocate
one row/key/file per request, caller ID or network address. Reserve at most 8 MiB
of deployment capacity for those buckets and quota/completeness control metadata.
Reject unknown keys rather than expanding that registry. Existing rate limits
are evaluated before expensive parsing/import work, but rejected requests also
obey these diagnostic budgets. Low-disk reserve retains its existing protection.
Quota exhaustion is visible as `partial_quota` or unavailable with aggregate loss
counts; it is not permission to bypass limits, silently drop data or change a
task's admitted economic operation. New case registration/import can return a
safe quota denial while already admitted task effects retain their original
execution/reconciliation authority. Local spool exhaustion similarly marks
incomplete capture without overwriting older undelivered files.

The 2026-11-02 approved verification interpretation preserves all ceilings when
stricter constraints make a ceiling unreachable. Replay derives the maximum
safe envelope from pinned current schema and registry fields, verifies that
actual maximal envelope at the boundary, and rejects strict 2048/2049-byte
overlong/unknown-field probes. It does not add a padding field. For other
dominated byte ceilings, independent PostgreSQL/SQLite allocation aggregates and
physical page/file observations must establish the earlier row/case/storage
blocker and unchanged retained evidence under the pinned charging rules. Real
exact/over probes remain mandatory for reachable bounds. Application usage
counters or seeded quota totals cannot prove this boundary. See
`envelope-bound-reachability.md` and the physical reader contract.

An explicit capture state and counters distinguish complete, partial, unavailable
and unsupported-client coverage. Overflow, parser failure, storage failure,
interrupted flush or sequence gaps must never appear as a complete zero-error
capture. Retain the earliest usable evidence and a bounded gap/overflow marker.
Diagnostics cannot replay a payment, alter result/ledger authority, or claim that
an economic request failed solely because its diagnostic persistence failed.
Logging degradation cannot authorize duplicate execution; unknown outcomes still
use the original action-status/reconciliation path.

Owner and admin views show safe rows, timings, causes, evidence source and missing
coverage. Foreign owners and agents receive no diagnostic read access. Import is
an owner action; the task-solving agent gets no new administrative capability.
An ordinary failed grade remains separate from a platform error and does not by
itself trigger a client diagnostic report. The diagnostic trigger requires actual
client/tool/collection failures; confirmed-platform-failure triggers remain unchanged.

### Retention and backup

Server-owned diagnostic rows, received objects, report mappings, receipts and
server delivery metadata use the existing audited beta retention boundary: until
30 UTC days after `beta_ended_at`; run completion does not trigger their purge.
They join the server unified checkpoint with hashes and source/completeness
metadata. Existing report retention also covers the automatic report. Backup
manifests explicitly distinguish `server_received` evidence from known registered
`client_pending_not_received` coverage; never-observed remote sessions remain
`client_coverage_unknown`. Missing remote client files are not
listed as backed up and cannot make server-only restore evidence look complete.

Remote client spool files remain client-owned. They are not promised by the
server backup or remotely deleted while the device/helper is offline. The helper
has its own documented local lifecycle: retain undelivered managed captures for
at most 30 UTC days from local capture creation, with expiry/GC evaluated before
upload on the next launcher start; once every batch and the report receipt are
confirmed, payload files are eligible for GC. A stopped/uninstalled helper cannot
promise timely local deletion. Expiry marks a local loss/expired state rather than
claiming delivered or recreating the original events. This applies only to the
new managed diagnostic spool, not old artifacts, arbitrary files or credentials.
No server restore restores a helper's OAuth tokens or local private files. A
separate client-spool restore probe tests retained keys, local expiry and current
authorization; it is not labelled a server cold restore of remote files.

On server retention closure, intake/receipt policy returns its existing safe
expiry denial; the helper marks pending work `retention_expired` and does not
retry indefinitely or emit a report about the expired report. Restoring either
store preserves case/batch/report identity and cannot duplicate reports, execute
tasks, change original grades/funding or roll back external revocation authority.

### Instrumentation isolation and framing

The implementation uses a separate two-connection diagnostic SQL pool with
one-second statement and half-second lock timeouts. Request observations share
one 100 ms budget; post-commit action observations use 25 ms and at most 128
pending writes. Failure or timeout discloses unavailable capture and cannot
retry a business action. Cleanup is single-flight and does not block coordinator
maintenance. Authorization and task state remain on the business database pool.

The actual SDK can return tool validation failures as HTTP 200 SSE even when
JSON response mode was requested. Decode bounded JSON/SSE framing in memory,
classify the actual MCP result, and attach safe metadata only to a matching
JSON-RPC response. Unknown framing stays unknown; transport success cannot
stand in for tool success. Do not retain the original payload.

Unified backup preserves diagnostic evidence but excludes data from the three
helper OAuth request/grant/token tables. Their schema remains restorable.
Independent restore fingerprints account for exactly those exclusions; all
other tables retain strict checks. Existing native authority rows and the
external revocation journal keep their existing policy. A read-only cold restore
proves effective write denial rather than claiming those preserved rows vanished.

## Migration Plan

1. Approve this exact six-scenario packet, automatic-report trigger, limits and retention scope. Preserve a
   unified checkpoint before an additive diagnostic migration; never rewrite old
   migration bytes or previous captures.
2. Install approved mirrors/adapters; instrument server and native boundaries;
   add private read views, automatic authenticated diagnostic delivery/reporting,
   persistent outbox/receipt checks and fallback import with no raw-data persistence.
3. Exercise deterministic failures, interruptions, redaction canaries and actual
   native report/receipt → actual admin UI → independent PostgreSQL verification,
   plus browser fallback import. Demonstrate one report across retries/restart,
   zero duplicate action/funding effects and visible incomplete capture on failure.
4. Rehearse full backup/cold restore with writes disabled, then qualify fresh
   actual native MCP Training/Ranked and correlate captured errors if any. New
   malformed probes are isolated and cannot mutate the user's original run.
5. Rollback disables new collection/import without dropping evidence or changing
   original business rows. Sync/archive only when all six mandatory gates pass.

## Risks / Trade-offs

- Client errors may never reach the server → durable native-side collection and
  automatic delivery outbox; provenance remains client-observed and incomplete
  when absent or pending, never falsely server-confirmed.
- Sanitization can lose essential distinctions → registered safe templates and
  field paths, canary tests and explicit unknown rather than arbitrary excerpts.
- Logging can add latency → bounded append/projection, measure actual overhead
  separately, do not recalibrate existing task timers under this change.
- Caller spoofing can misattribute failures → verified ownership/bindings and
  evidence-derived responsibility; client assertions never change a score.
- Historic causes are unavailable → retain the original 27 aggregate count and
  mark detailed recovery unavailable, never synthesize historical events.

## Open Questions

The limits, retention extension and six assertions were approved; the exact
schema-dominated boundary adjustment is recorded in approval.md. New assertions
still require approval under `docs/task-design.md`. Runtime acceptance must verify
interception of SDK validation, safe registered error extraction, actual
import/body limits and backup inventory before implementation activation.
Transport, identity, attribution and storage policies are selected above; their
full acceptance remains unproven. Qualify the new helper OAuth client/resource/
scope/consent, five-attempt outbox policy, canonical actor-independent report
mapping and AFR-kind integration before activation. This is not permission to
read Codex tokens, install an always-on service or claim support for clients that
have not installed/authorized the helper.
