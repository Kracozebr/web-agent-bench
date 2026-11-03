# MCD physical capture replay input

This is the implementation input contract for the approved six MCD boundaries,
not runtime acceptance evidence. An empty `runtime-inputs.json` leaves every gate
`not_run`/blocked. Synthetic reader tests must never be installed as captures.
The producer records actual native, HTTP, browser and independent read-only
PostgreSQL/SQLite observations; the offline reader has no write client.

Each reference is `{path,sha256}`: a bounded file inside this checkout, with the
hash of its original bytes. No real credentials, user content, hidden task
arguments or Ranked variants may appear. Use synthetic probe inputs/canaries.

## Common envelope

```json
{
  "schemaVersion":"mcd-physical-capture/v1",
  "scenarioId":"MCD-SC-001",
  "observer":{"role":"oid_observer","readOnly":true,"databaseName":"probe"},
  "sourceInputs":{"before":{"relative/source.ts":"sha256"},"after":{"relative/source.ts":"sha256"}},
  "raw":{"protocol":{"path":"capture/protocol.json","sha256":"sha256"}},
  "variants":[{
    "name":"malformed_json_rpc",
    "requestRef":{},"responseRef":{},"beforeBusinessRef":{},"afterBusinessRef":{},
    "beforeDiagnosticRef":{},"afterDiagnosticRef":{}
  }]
}
```

`sourceInputs` must contain the same nonempty inventory before and after, and
every hash must still match the checkout. `variants` must contain exactly the
scenario's approved `negative_variants` from `harness-contracts.json`.
MCD producer selection excludes only these exact lifecycle/output paths:
`tests/bdd/changes/mcp-call-diagnostics/runtime-inputs.json`,
`tests/bdd/changes/mcp-call-diagnostics/acceptance-evidence.json`,
`tests/bdd/changes/mcp-call-diagnostics/scenario-map.md`,
`openspec/changes/mcp-call-diagnostics/tasks.md` and
`openspec/changes/mcp-call-diagnostics/approval.md`. This allows activating a
selector, recording lifecycle decisions and writing official acceptance results
without invalidating the capture that is being evaluated. The official runner
rewrites acceptance evidence before/after execution and regenerates the
result-bearing scenario map from pinned normative and executable inputs. These
two exact generated outputs are not alternative gate expectations; their
generator/checker, OpenSpec, contracts, feature, mapper and readers remain pinned.
The normative spec/design, harness contracts, actual code, mappers/readers and
the source-selection policy itself remain hash-pinned. Other changes' similarly
named files are unaffected by this MCD-specific exclusion.

Business snapshots contain `source:"postgresql_observer"` and `domainHashes`
with all of `runs,tasks,actions,receipts,evaluations,ledger,bonuses`. Hashes are
computed from independently selected canonical rows, including identities and
amounts. Snapshots surround the diagnostic operation, not the benchmark execution
that the diagnostic operation describes. Each pair must be identical.

Diagnostic snapshots contain `source:"postgresql_observer"` and arrays
`cases,events,reports,batches,audits`. Use the safe case/event view field names;
events additionally include their durable `caseId`. Reports have
`id,ownerId,caseId,kind`; batches have
`caseId,segmentId,batchSequence,payloadHash,completion`.
Requests contain safe `method,path` and optional owned `binding` references.
Responses contain actual `httpStatus`, safe `errorCode`, optional `rpcErrorCode`,
`traceId` and the actual receipt, not a producer's assertion of success.

## Scenario raw documents

The executable field contract is in
`tests/bdd/adapters/mcd_physical_replay.py`; the following describes the source
boundaries that must populate it.

- **001 `raw.protocol`:** `beforeRestartRef,afterRestartRef` diagnostic snapshots.
  Every failure response must correlate to exactly one newly persisted event by
  trace ID. Stage, code and source-local timing come from the event, not aggregate
  counts. A rejected unbound request must not invent an owned case.
- **002 `raw.native,oauth,carrier,delivery`:** native implementation/version,
  normalized actual MCP calls and an empty actual local-tool call inventory;
  separate helper grant, PKCE request and explicit consent click; native/helper
  case identity and server trace carrier; deterministic-helper delivery trigger
  plus actual admin browser click/URL/case/report observation. Denied capability
  probes include individual `attempts` and `outboxState:"pending_auth"`.
  Successful variant responses carry durable `receipt`. The reader reconstructs
  contiguous watermark/hash from batch rows and verifies one canonical report.
  A synchronized final `partial` receipt requires contiguous acknowledged bytes,
  the canonical report receipt and a case explicitly marked `partial` or
  `partial_quota`; synchronized delivery does not mean complete capture.
  Crash events retain paired `clientRunStatus`/`clientRunObservedAt`, only on
  `source:client`, `stage:client_runtime`, `outcome:error`. They remain unverified
  client observations and cannot override authoritative server status or grades.
  Active-crash replay additionally requires the qualified native client's last
  matching actual run observation and unchanged business snapshots; a producer
  summary alone does not prove the source observation or absence of relaunch.
  `raw.clientOutbox.runObservation` is the read-only SQLite control row:
  `{runId,status,observedAt,sourceCallIdHash,sourceTool,traceId?,terminal?}`.
  Uploaded envelopes never carry its `runId`. Replay correlates its call hash to
  actual native calls and its run to the PostgreSQL case's intent/run join.
  A separate interrupted native run may be supplied by the crash variant's
  `response.nativeRef` and `response.clientOutboxRef`, instead of the main
  normally completed capture.
  Report response loss, owner-import races and restart use the original keys.
  SC002 callbacks must supply actual boundary evidence for every named variant;
  an exact list of variant names is not proof of the corresponding operation.
  Each successful final receipt must explicitly have `diagnosticsSynced:true`.
  `refused_endpoint_and_recovery.response.attempts` includes the real socket
  refusal projection (loopback reserved then closed, zero credential bytes).
  `lost_report_response` includes the successful HTTP 200 receipt actually lost
  and a subsequent successful identical-hash receipt with the same report ID.
  `lost_admission_response.response.transportRef` points to the actual proxy
  document (`boundary:actual_origin_preserving_loopback_proxy`, zero overflow).
  Its `observations` include exactly one `admission_response_dropped` and one
  `admission_retry_response` with `replayed:true`, equal `runId,taskIndex,
  operationIdHash,actionId`, HTTP 200 and ordered `droppedAt,enteredAt`. The
  armed command is only `inspect_catalog`; raw operation arguments never leave
  memory. `response.nativeRef` must retain the actual successful native
  `runs.task_action` call and empty local-tool inventory.
  `failed_report_retry_no_recursion` retains actual `attempts`: initial 429
  `REPORT_RATE_LIMITED`, or HTTP 200 with no report/no synced receipt and
  `rateFailureRef` containing independent PostgreSQL exhausted-window rows.
  Rate limits are independently read from the pinned report-service source.
  `actualWaitMs` respects the observed wait; `identicalPayloadHash` and the final
  HTTP receipt match the unchanged batch and exactly one canonical report.

  Three callback responses additionally carry `evidenceRef` (an immutable safe
  path/hash, preserved by the assembler's finite projection):
  - `owner_import_races_helper`: `{attempts:[...]}`, exactly one `actor:owner`
    and one `actor:helper`. Each actual request/response capture has
    `startedAt,completedAt` from the same local clock, overlapping intervals,
    `request:{caseId,segmentId,batchSequence,payloadHash}` and
    `response:{httpStatus,receipt}`. Both final receipts acknowledge the same
    original batch/report. Capture the actual owner import and helper request;
    do not manufacture their success from a later lookup.
  - `late_run_binding_and_batches`: `beforeBindingRef,afterBindingRef,
    beforeAppendRef,afterAppendRef` are independent diagnostic snapshots.
    The same owned intent case initially has no run, subsequently joins the
    real run, then gains new event and batch keys. Existing reports, batches,
    events and report audit rows must be preserved, without another report.
  - `restart_and_restore`: `beforeOutboxRef,afterOutboxRef,restoredOutboxRef`
    are read-only actual SQLite projections shaped like `raw.clientOutbox`;
    `beforeDiagnosticRef,afterDiagnosticRef,restoredDiagnosticRef` are actual
    independent PostgreSQL diagnostic snapshots. Reopen and actual restore
    retain original local/canonical/session/report IDs and batch payloads.
    Restored diagnostic rows remain identical and the final receipt is synced.

  Root must prepare native actions before the diagnostic business snapshots:
  executing an intent/action inside the snapshot pair would correctly fail
  noninterference. The native driver automatically delivers before returning;
  use its `after_native_before_delivery` boundary for the original pending
  segment, and distinct actual launcher lifetimes for additional fault probes.
  Do not reset the same launcher's five-attempt lifetime budget between variants.
  The no-consent builtin intentionally lacks distinct wrong-scope/audience
  grants and remains incomplete until actual authorization probes are supplied.
  Its replacement supplies `response.evidenceRef` containing
  `missing_consent,wrong_scope,wrong_audience`, each `{requestRef,responseRef}`.
  Requests are actual safe HTTP transport captures with
  `{source:http_transport,origin,method,path,...}`. Missing consent is POST
  `/api/diagnostics/cases` with only `headers:{content-type:application/json}`
  and no bearer, producing the source-defined 401 code. The other two requests
  are GET `/api/diagnostics/oauth/authorize` with complete public synthetic
  `query`: client `w3bench-diagnostics-helper-v1`, callback
  `http://127.0.0.1:38766/diagnostics/callback`, `response_type:code`,
  `code_challenge_method:S256`, the public canary challenge `A` repeated 43 times,
  and public canary state `mcd_diagnostic_negative_probe_20261102`.
  Scope/audience otherwise match the actual helper grant; wrong scope changes
  only scope to `diagnostics:read`, wrong audience changes only resource to the
  same origin's `/api/agent/mcp`. Both must actually return the source-defined
  400 authorization error. No real verifier, state, token or grant is exported.
  The final admin click may use `/admin/diagnostics?caseId=...`; replay checks
  its pathname and canonical observed PostgreSQL report ID.
- **003 `raw.classification`:** `controls` for all six positive categories and
  one contradictory/missing control. Each has `name,facts,projection`, bounded
  `evidenceReferences`, and the contract cases additionally have
  `issuedSchemaRef,issuedContractRef`. Facts are qualified causal observations
  produced independently of the application's classifier, with retained evidence
  IDs. `projection` is the actual database output. `allUnknownMutation` is a
  copy of the six positive projections changed to unknown; the independent
  matrix must detect the contradiction. Raw schema/contract files retain the
  issued tool shape without hidden task arguments. Evidence references carry
  `observer:{role:"oid_observer"|"qualified_client_reproducer",readOnly:true}`.
  Issued contract has `tool,requiredOperation` (safe synthetic control arguments);
  client-contract controls additionally carry `clientArguments`. The independent
  reader validates these operations against the issued schema itself and fails
  closed on unsupported JSON Schema validation keywords.
  The controlled reference producer uses the actual MCP SDK client/server over
  loopback HTTP and a separately declared trusted verifier worker. Its profile
  is `mcd_controlled_reference_sdk`, SDK 2.4.0, `nativeClient:false`. This qualifies
  only the controlled reference profile; it does not attribute a native Codex
  failure. Retain actual initialize/listTools/callTool wire observations,
  hashed call IDs, server handler-entry/throw/policy traces, client result and
  exception class, dependency HTTP observations and the verifier source ref.
  Reader derives causal facts from these raw observations before comparing the
  actual database projection; producer cause/pass flags cannot qualify it.
- **004 `raw.browser`:** `owner,admin` each contain actual `action:"click"`,
  URL, HTTP status, actor owner reference, case IDs, safe DOM text and
  `databaseRef`. Reader compares visible case IDs with independent rows. Actual
  source trust and unknown responsibility text must be visible. Foreign,
  anonymous, task-agent and forged reference attempts return no case IDs and
  change neither diagnostics nor business history. Grade-only/zero-error probes
  create no report; completed run with client errors creates exactly one.
- **005 `raw.quotas`:** synthetic canaries and all retained surface references;
  `envelopeBound:{schemaSourceRef,schemaRef,maximumEnvelopeRef,maximumResponseRef}`:
  the actual contract source, Zod-exported JSON Schema, maximum safe envelope and
  actual accepted response. Reader independently parses the pinned finite Zod
  source vocabulary, derives the bound and compares the exported schema. Do not
  freeze a historical maximum or add a padding property.
  `sizeProbes` retain exact actual inputs/bytes/status at 2048/2049 (both strict
  schema rejection) and 8 MiB/over (real accepted/rejected bundle boundary).
  `allocationSources:{server,local}` pin actual service.ts and client.mjs refs.
  `capacityProbes` name every owner/deployment/anonymous/local limit and contain
  `mode:"exact_over"|"dominated",observationRef,afterObservationRef,
  blockingResponseRef`; exact probes also require `acceptedResponseRef`.
  Each observation is an independent SQL allocation aggregate result with
  `source:"postgresql_observer"|"sqlite_observer"`,
  `queryKind:"diagnostic_allocation_aggregates"`,
  `observer:{role:"oid_observer"|"client_sqlite_observer",readOnly:true}`,
  `groups,reservedGroups` (the latter may be explicitly empty). Groups have
  `kind:"event"|"batch"|"segment"|"case",count,sumBytes,maxBytes,rowsSha256`.
  PostgreSQL aggregates select actual event envelope bytes and apply the pinned
  512-byte batch/case and 256-byte segment charging rules to actual row counts;
  they never select diagnostic quota usage counters or seed aggregate totals.
  SQLite aggregates select actual event/batch payload bytes and actual case
  registrations. Reader derives exact occupancy or a conservative global
  byte upper bound from the approved row/case ceilings plus schema maximum.
  Local byte dominance also requires actual `sqlite:{pageSize,maxPageCount,
  pageCount,journalMode:"delete"}` and `files:[{name,bytes}]` demonstrating the
  earlier physical page/journal reserve, with actual storage rejection.
  In every mode committed plus reserved allocation and retained group hashes
  must survive rejection unchanged. Also retain
  `canonicalCaseCounts`, `anonymousBuckets`, `concurrentReservations` for all
  helper/import/replica actors and preserved evidence hashes. Parser/storage/
  quota gaps must persist explicit partial/unavailable coverage. Aggregate values
  must be SQL/SQLite observer results, never application usage counters.
- **006 `raw.restore`:** independent before/after database references, server
  manifest and actual received file references; remote pending references that
  are absent from the server manifest; cold restore write mode, access-grant and
  execution-lease inventories; before/after revocation rows; separate SQLite
  expiry observation on helper resume after 30 days, server intake-closed status,
  and stopped-helper observation that makes no remote-purge claim. Missing or
  tampered server evidence and revoked helper probes must be rejected.
  `readOnlyFenceRef` contains actual read-only restored-database observations:
  `observer:{role:"oid_observer",readOnly:true,databaseName:"oid_restore_..."}`,
  `databaseSettings:[{databaseName,setconfig:["default_transaction_read_only=on"]}]`,
  `ownerWriteProbe:{role:"oid_owner",databaseName,defaultTransactionReadOnly:"on",
  transactionReadOnly:"on",sqlState:"25006"}`, and exactly the three excluded
  `helperAuthorityTables:[{name,count:0}]`. Raw native `rawAccessGrants` and
  `rawExecutionLeases` must remain identical to actual source arrays in
  `rawAuthorityBeforeRef`; effective arrays must be empty under the independently
  proven fence. The restored diagnostic snapshot carries the same observer DB
  identity. `servedApi:false` needs an actual configured-API network observation
  `apiProbe:{url:"http://127.0.0.1:8784/healthz",outcome:"connection_refused",
  errorCode:"ECONNREFUSED"}`; zero rows or a producer flag alone cannot pass.
  The tamper variant is an operator restore-verifier boundary, not an HTTP
  endpoint: response `{boundary:"unified_backup_restore_verifier",
  outcome:"rejected",errorCode:"beta_backup_file_integrity"|
  "beta_backup_bundle_ciphertext_integrity",checkpointInventoryRef,
  beforeBundleRef,afterTamperRef}`. Reader streams actual encrypted file hashes,
  verifies unchanged original inventory binding and a same-sized changed copy,
  and never invents an HTTP status or decrypts key material. Cipher references
  have a finite 2 GiB payload plus 32 MiB manifest/framing bound and use 1 MiB
  read chunks; ordinary JSON evidence keeps its existing smaller bound.

Missing fields or missing variants fail closed. Producer `passed` flags,
`observations`, safe aggregate error counts, mocks and application-only counters
cannot establish acceptance. The independent reader and its mutation tests are
necessary checks; only the real producer can supply the runtime boundary proof.

The SC006 server-intake closure boundary additionally retains
`serverIntakeOutboxObservation` from a separate still-authorized helper:
`source:sqlite_observer`, read-only observer identity, `localCaseId`, actual
`state:retention_expired`, helper `httpResponses` containing `/api/diagnostics/*`
HTTP 410, and `identityRef` with the actual reopened SQLite case row. An owner
import HTTP 410 alone cannot prove the helper stopped its pending retries.

SC005 supplemental execution occurs before deployment quota fill. The exact
8 MiB UTF-8 JSON export crosses actual file selection, button click, backend
response and PostgreSQL receipt. Its 8 MiB + 1 byte counterpart is rejected by
the existing browser size guard before any upload: `boundary` is
`owner_browser_file_size_guard`, `browser` records the actual selected byte
count, exact validation text, disabled import control and empty upload request
inventory. It has no fabricated HTTP status. This preserves the configured
8 MiB ceiling at its actual enforcement boundary.

The replica race launches the same built server against the same disposable
acceptance database on loopback port 8785. It records the build hash/reference,
owned PID and actual HTTP socket ports. Helper, owner browser import and replica
submit three distinct one-event/new-segment batches while a controlled case row
lock is held. Actual HTTP allocations first fill the real owner budget to
16381 rows; each competing batch requires three rows (event, batch, segment). A separate
`oid_observer` read-only `pg_locks` observation must show at least three waiting
connections before release. Independent before/after rows must retain every old
event, produce exactly one new event/batch and preserve the canonical report;
exactly one real request succeeds and two return quota rejection. Independent
owner allocation groups must change from 16381 to 16384 rows; the accepted
receipt and new event/batch must match the winning request. Three duplicate
idempotency keys alone cannot qualify shared quota reservation. The owned
replica is stopped in `finally` and by runner cleanup before unified checkpoint.
Synthetic helper authorization used by this capacity race does not establish
native OAuth consent or client qualification.

SC005 local capacity runs the same `runMcdLocalCapacityRestore` function on
actual Windows Node24, preserving its FULL sync, physical reserve and all row,
byte and case ceilings. This avoids Docker's Windows bind-mount latency without
substituting a different filesystem or relaxed limits. The fixed job contains
only capture/job UUIDs and pinned source hashes; it cannot request shell commands,
credentials or custom thresholds. The private probe ID is exactly
`<captureId>-host-<jobId>` and its output directory is derived from the capture.

`hostCapacityEvidenceRef` binds original job/result bytes and two distinct
request/response pairs. Each fresh request has sequence 0 or 1 and the same
capture/job UUID; the runtime executes only the fixed read-only server counts
query. The independent reader binds `observer.databaseName` to the actual
`oid_acceptance_<captureUUIDWithoutDashes>`, verifies original reference hashes,
Windows/Node24 and unchanged source pins, and checks that both counts correspond
to the host helper's actual expiry callbacks. Quota assertions still derive from
read-only SQLite row/byte groups and physical-page observations, never local
allocation-counter projections. A status heartbeat or Windows label alone is
insufficient evidence.

Anonymous-detail quota exhaustion uses a further valid authorized `tools/list`,
not malformed JSON. It must retain HTTP 200 and a verified JSON/SSE tools result,
while explicitly reporting unavailable diagnostic capture. Independent allocation
rows remain exactly 2048 and unchanged; the actual 128 fixed SQL buckets retain
all identifiers and their bounded dropped-detail counts increase. An HTTP 500
from malformed input is a separate parser observation and cannot establish a
quota cause. The previously captured malformed-input 500 evidence is retained;
this packet does not change parser response normalization.

SC006 retains both a byte-identical legitimate original owned export and a fresh
owned export. The original is actually accepted before expiry, bound to its saved
case/session/connection and original batch/hash. After restart, the producer waits
for independently observed cases/events zero and a committed retention receipt
whose counts reconcile the full source fingerprints, before either request.
Both actual responses must be 410 `REPORT_RETENTION_EXPIRED`; a fabricated or
mismatching session is insufficient. The still-authorized helper must independently
reach HTTP 410 and durable SQLite `retention_expired` as well. Safe phase/status/
registered-code and source-relative frame projections are retained before assertions.
