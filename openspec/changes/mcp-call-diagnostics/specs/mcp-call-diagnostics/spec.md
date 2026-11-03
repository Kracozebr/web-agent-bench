## ADDED Requirements

### Requirement: MCD-REQ-001 Preserve server-observed call evidence
The platform SHALL persist bounded sanitized call evidence for successful and
failed MCP operations, including ingress/authentication, SDK schema validation,
handler/admission, dispatch and receipt failures. It SHALL distinguish HTTP,
JSON-RPC and tool outcomes and generate trusted trace identity. Operation/run
links SHALL be derived from verified ownership and durable bindings; failure
before action admission SHALL NOT require or fabricate an action row.
The qualified launcher SHALL carry its non-secret case reference in per-process
MCP HTTP metadata without changing the native OAuth audience/global config. The
server SHALL validate ownership independently and expose generated trace IDs in
safe success/SDK-error metadata. A hidden/unavailable carrier SHALL be explicit
partial correlation, not a timestamp-based or caller-authorized causal link.

Scenario setup: An isolated authenticated MCP connection, real SDK ingress and
independent PostgreSQL observer with immutable business snapshots.

#### Scenario: MCD-SC-001 Retain failures before and after action admission
- **WHEN** valid calls, malformed/schema-invalid calls, policy denials and handler/dispatch failures cross their actual boundaries
- **THEN** their safe stage/code/timing and evidence identity SHALL survive API restart, known links SHALL match the original operation, and rejected calls SHALL create no unauthorized action, charge or reservation

### Requirement: MCD-REQ-002 Retain native-side failures without credential access
The installed diagnostic helper SHALL use its own public OAuth client
`w3bench-diagnostics-helper-v1`, authorization-code/PKCE-S256 flow, resource
`/api/diagnostics` and `diagnostics:write offline_access` scopes. Setup SHALL obtain
explicit owner browser consent linking the selected agent/native connection.
The helper's OAuth library SHALL use its own OS credential store and SHALL NOT
read/copy Codex credential files. Its authority SHALL permit only diagnostic
case registration, bounded batch writes and own receipt metadata, not task,
diagnostic-read, arbitrary report or administrator operations. Connection
revocation SHALL invalidate the linked helper grant. Unsupported/unconfigured
installations SHALL be explicit; manual import SHALL NOT qualify normal delivery.

The qualified native launcher SHALL durably capture safe per-call events before
discarding raw CLI output, including client validation, client runtime and
transport failures with no server observation. It SHALL automatically deliver
bounded safe diagnostics and one aggregated `client_diagnostics` support report
per run or pre-admission session with actual errors, after task execution ends
or client execution fails. It SHALL persist delivery identity and outbox state,
retry without duplicate reports after reconnection/restart, and confirm receipt
before claiming delivery. A completed run SHALL NOT suppress actual client errors.
The platform SHALL retain owner-authorized bounded import as a fallback, validate
private links and deduplicate it against automatic delivery. Revoked/expired
authorization SHALL NOT be bypassed; undelivered evidence SHALL remain visibly
pending. No manual import SHALL be required for the qualified normal path.
Report-delivery failures SHALL remain on the same outbox/report identity and
SHALL NOT recursively create additional diagnostic reports.
Client-provided events SHALL remain source-labelled and SHALL NOT become trusted
admission, grading or compensation evidence merely by being imported.

A client crash/disconnect after admission SHALL trigger diagnostic delivery even
if the last known run status is still running. The report SHALL preserve that
last observed status/time and unresolved outcome, without cancelling, finishing
or replacing the run. A crashed helper SHALL recover its pending outbox on the
next start before launching another solver; absent current authorization SHALL
remain pending_auth, never falsely delivered.

The server SHALL identify intent-associated cases uniquely by
`(owner_id, intent_id, client_diagnostics)` and intent-free setup cases by
`(owner_id, diagnostic_session_id, client_diagnostics)`. Diagnostic session
identity SHALL be persisted before solver startup. Admission/runId enrichment
SHALL NOT change case identity. Intent-free setup cases SHALL remain unlinked;
selecting a later benchmark intent SHALL start its own intent case, not convert
the earlier setup case. Automatic delivery, fallback owner import and restart
SHALL use one canonical `(owner_id, diagnostic_case_id, report_kind)` report
mapping, independent of uploader/reporter actor. One verified run SHALL have at
most one intent-case diagnostic report; actor-scoped generic report idempotency
alone SHALL NOT satisfy this requirement.

Immutable report submission SHALL reference the case; changing run links, error
counts and completeness SHALL be derived from its append-only diagnostic journal.
Each batch SHALL use durable `(case_id, segment_id, batch_sequence)` identity and
sanitized payload hash. Identical repeats SHALL return their prior receipt;
changed payload at the same key SHALL conflict. Late evidence SHALL append with
new batch keys and SHALL NOT create another report. Receipts SHALL expose
case/report IDs, highest contiguous accepted sequence/hash and completion state.
`report_created` SHALL be distinct from `diagnostics_synced`; syncing requires
acknowledgement of the segment's final watermark as well as the report receipt.

Retry SHALL be bounded to five attempts per launcher lifetime with 5/30/120/600
second backoffs when it remains running. The helper SHALL stop within 30 seconds
after solver exit unless the launcher is kept open; pending work SHALL resume on
the next launch, not through an implicitly installed background service. Revoked
authorization SHALL wait for explicit reauthorization; conflicts and closed
retention SHALL have explicit blocked/terminal states rather than infinite retry.

Scenario setup: Actual qualified Codex CLI, private launcher output, an isolated
fault-controlled MCP connection, automatic diagnostic reporting/receipt, actual
administrator report UI, and real owner fallback import controls.

#### Scenario: MCD-SC-002 Retain client failures and report them automatically
- **WHEN** native calls encounter input rejection, an unavailable endpoint or a lost response and automatic delivery retries after reconnection/restart or fallback import repeats the same capture
- **THEN** with valid authorization, capacity and open intake, exactly one canonical report/receipt and acknowledged diagnostic watermarks SHALL appear in admin UI/PostgreSQL across automatic delivery and fallback import; denied authorization SHALL instead create zero new report writes and visible pending_auth, missing correlation SHALL remain unknown, and no additional run, payment or task closure SHALL occur

### Requirement: MCD-REQ-003 Separate observed stage from responsibility
Diagnostic projections SHALL distinguish source, observed failure stage and
responsibility. A non-unknown responsibility SHALL require independently
verifiable supporting evidence. Invalid input SHALL NOT alone prove client fault
when the published schema and issued task contract are incompatible. Timeout or
unobserved transport failure SHALL remain unknown pending authoritative
reconciliation. Diagnostic views SHALL NOT rewrite grades or authorize refunds.

Responsibility SHALL use exactly the following evidence-to-result rules. Every
fully verified positive control SHALL produce its named non-unknown category;
an always-unknown classifier SHALL fail acceptance. Contradictory categories or
unverified client claims SHALL resolve to unknown with an explicit gap/conflict.

| Verified evidence | Required responsibility |
| --- | --- |
| Actual server validation rejection, compatible published schema/issued contract and matching safe violation identity | `client_contract` |
| A valid pinned issued operation is not representable by the advertised schema | `platform_contract` |
| Independently reproduced qualified client exception/parse failure after its matching valid server response, without contradictory server failure | `client_runtime` |
| Trusted server invariant/handler/dispatch failure under valid authority, with external-dependency cause excluded | `platform_runtime` |
| Matched trusted dependency observation confirms the dependency failure and excludes schema/policy/handler causes | `external_dependency` |
| Authoritative policy/grant/revocation evidence matches the actual denial | `expected_policy_denial` |
| Missing/contradictory evidence, unverified client claim or ambiguous transport timeout | `unknown` |

An HTTP status, model failed-tool item, keyword or missing server row alone SHALL
NOT establish responsibility. Source-local duration SHALL remain separate from
cross-source clock differences; authoritative operation order SHALL establish links.

Scenario setup: Matched compatible and incompatible schema/contract evidence,
actual accepted/denied operations and a transport response-loss capture.

#### Scenario: MCD-SC-003 Attribute only failures supported by causal evidence
- **WHEN** the projection compares schema violations, platform contract defects, server/external failures, expected denials and ambiguous transport outcomes
- **THEN** every complete positive evidence row SHALL produce its required category and links, incomplete/contradictory evidence SHALL produce unknown with its reason, an always-unknown projection SHALL fail, and existing scores, receipts and ledger entries SHALL remain unchanged

### Requirement: MCD-REQ-004 Expose only authorized private diagnostics
Owners SHALL be able to inspect their own diagnostic events and completeness in
the run/connection UI; administrators SHALL have a server-authorized view. Foreign
owners and task agents SHALL NOT read these records. Anonymous and unbound client
claims SHALL NOT be associated with an arbitrary owner's run. Reports SHALL
reference safe diagnostic identity. The `client_diagnostics` automatic trigger
SHALL be separate from the existing confirmed-platform-failure allowlist and
SHALL NOT assert platform responsibility. An ordinary failed/partial grade alone
SHALL NOT trigger it, and an error-free capture SHALL NOT create a diagnostic
report. Anonymous/pre-admission errors SHALL NOT invent a run link.

Scenario setup: Two owners, an administrator, an ordinary task agent and an
anonymous caller, with real UI and independent PostgreSQL access observations.

#### Scenario: MCD-SC-004 Verify private diagnostic views and ownership checks
- **WHEN** owners/admins open diagnostics and foreign, anonymous or agent callers attempt reads or forged imports
- **THEN** only authorized rows SHALL be visible, invalid links SHALL not create foreign records, and diagnostic viewing/report references SHALL not mutate benchmark or financial history

### Requirement: MCD-REQ-005 Bound collection and make missing evidence explicit
Persisted diagnostics SHALL use a registered field/code allowlist and SHALL NOT
contain credentials, raw messages/arguments/results, hidden Ranked variants,
answers, signatures or provider data. Each envelope SHALL be at most 2 KiB,
each canonical case across all segments/uploads at most 4096 detailed envelopes, and each imported bundle
at most 8 MiB including metadata. Collection SHALL expose complete, partial,
unavailable or unsupported-client coverage; overflow or persistence/parser failure
SHALL NOT become an apparently complete zero-error capture. Loss of diagnostic
storage SHALL NOT authorize duplicate economic execution or fabricated outcomes.

Shared diagnostic quotas SHALL account transactionally for committed and reserved
in-flight bytes/rows/case registrations across all upload actors and API replicas:

| Scope | Maximum detailed bytes | Maximum detailed rows | Maximum case registrations |
| --- | --- | --- | --- |
| Per owner, across cases | 32 MiB | 16384 | 128 |
| Deployment, shared by all replicas | 256 MiB | 131072 | 4096 |
| Anonymous detail, included in deployment total | 4 MiB | 2048 | 0 |
| Local helper spool, across cases | 64 MiB | 32768 | 128 |

The earliest exhausted bound SHALL stop new detailed allocation without evicting
retained evidence or changing business execution authority. New caller IDs,
sessions, import actors and unauthenticated/rate-denied traffic SHALL NOT reset
quotas. Anonymous overflow SHALL update only a fixed registry of at most 128
code/stage aggregate buckets with saturating counters; no per-request/key/address
allocation SHALL occur. At most 8 MiB of deployment capacity SHALL be reserved for
quota/completeness control metadata and fixed buckets. Existing rate/body limits
and low-disk reserve SHALL remain enforced. Exhaustion SHALL be visible as partial
quota/unavailable coverage with bounded loss counts; it SHALL NOT appear as an
error-free complete capture or overwrite an older undelivered local file.

Scenario setup: Real collector/import boundaries with redaction canaries,
exact-limit and over-limit inputs, interrupted writes and storage/parser faults.
For a ceiling dominated by stricter approved schema, row/case or physical storage
bounds, verification SHALL independently derive the unreachable ceiling from the
pinned current schema/allocation rules and actual PostgreSQL/SQLite observations,
verify the reachable maximum and the actual earlier blocker, and preserve every
configured ceiling. Envelope verification SHALL recompute its largest safe
representable value and reject exact 2048/2049-byte overlong or unsupported
envelopes rather than adding padding fields to make a 2048-byte acceptance
witness possible. Reachable ceilings SHALL retain real exact/over probes.
Application usage counters, artificially seeded quota totals and producer pass
flags SHALL NOT establish either reachability or dominance.

#### Scenario: MCD-SC-005 Preserve privacy and explicit incomplete coverage
- **WHEN** secret-bearing error text, adversarial fields, reachable exact/over-limit input or independently proven schema/storage-dominated ceilings, rotating-session anonymous floods, concurrent replica/import allocations or storage/parser faults reach collection/import
- **THEN** durable stores and exports SHALL contain only bounded allowlisted data, gaps SHALL be explicit, oversized imports SHALL be rejected before durable import, all configured ceilings SHALL remain enforced with independently replayable reachability or dominance proof, and business effects SHALL remain once-only or explicitly unresolved

### Requirement: MCD-REQ-006 Preserve diagnostics through retention and restore
Server-owned diagnostic records, received bundles, canonical report mappings,
receipts and server delivery metadata SHALL join the existing unified backup
inventory with hashes and audited beta retention until 30 UTC days after
`beta_ended_at`. Coverage SHALL distinguish server_received from
client_pending_not_received for known registered cases; unobserved client coverage
SHALL remain unknown. Remote client files SHALL NOT be claimed as present
in a server checkpoint. A restore SHALL retain evidence and completeness
without reopening task execution, changing original business history or rolling
back external revocation authority. Missing historical detail SHALL remain
unavailable; new captures SHALL NOT be attached as reconstructed original events.
Remote helper spool/outbox files SHALL remain client-owned with a separate local
lifecycle, not a server backup/purge guarantee. On the next launcher start the
helper SHALL expire undelivered managed captures older than 30 UTC days from local
capture creation before uploading; acknowledged payloads SHALL be eligible for
local GC only after all batch watermarks and the report receipt are confirmed.
Stopped/uninstalled helpers SHALL NOT claim timely remote deletion. Expiry SHALL
remain explicit loss/expired coverage, not delivered success. This local policy
SHALL apply only to the new managed spool, not historical artifacts or credentials.
Server intake closure SHALL produce retention_expired locally rather than an
infinite retry. Server restore SHALL NOT restore helper OAuth tokens or remote
client files. A separate client-spool restore probe SHALL preserve original case,
batch, report and payload identities, enforce current local expiry and require
current authorization before delivery; it SHALL NOT duplicate a report/receipt.

Scenario setup: A server checkpoint of received diagnostics and existing business
data, a separate client-spool fixture, a cold write-disabled server restore and
audited server retention plus local capture creation times.

#### Scenario: MCD-SC-006 Restore diagnostic evidence without execution authority
- **WHEN** server collection is interrupted and its checkpoint is cold-restored, and separately an offline helper/spool is resumed around local expiry and server retention closure
- **THEN** received server evidence/hashes and original business records SHALL reconcile, remote pending data SHALL remain explicitly outside server backup, local expiry and current authorization SHALL govern client delivery, partial coverage SHALL remain partial and no restored record SHALL duplicate a report, re-execute a task or restore revoked access
