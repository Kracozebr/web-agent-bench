# Native diagnostic launcher — implementation and qualification

This is the reproducible entry point for the approved safe native collector. The
OpenSpec spec remains normative. Unit/subprocess tests below prove the projection
and outbox boundary; they do not prove browser consent, the actual OS credential
store, a Codex model run, or a report visible in the running UI/PostgreSQL.
Those physical gates remain `not_run` until separately recorded.

## Connection and execution

From the repository root in PowerShell, retain the existing native MCP/OAuth
connection. The diagnostics helper is a separate OAuth client and asks for its own
owner consent; its refresh token goes only into its own Windows Credential Manager
entry. It never reads the native Codex credential file.

The helper's exact public client ID is `w3bench-diagnostics-helper-v1`; scopes are
`diagnostics:write offline_access`, and its resource is `<Origin>/api/diagnostics`.
Its own callback is `http://127.0.0.1:38766/diagnostics/callback`. This is separate
from the existing native Codex MCP OAuth callback on port 38765. No native token
is copied into the helper's authorization or credential entry.

```powershell
$bench = Join-Path (Get-Location) 'infrastructure/owner-identity/codex-bench.ps1'
& $bench -Action DiagnosticsLogin
& $bench -Action DiagnosticsStatus
```

Use the same owner/card in the consent screen as the intended benchmark. The owner chooses the owned card and native OAuth connection in the consent
screen. For another deployed origin, pass the same `-Origin 'https://…'` on
all commands. HTTP is accepted only for explicit localhost development.

In the current `/runs` flow, create and review a fresh Training or Ranked launch
intent. Copy its complete execution instructions (the existing handoff text, not
only the intent UUID). Save the exact clipboard text into a private UTF-8 plain
text file under `.local`, for example `.local/training-handoff.txt`. Do not add
other instructions, edit identifiers, copy a credential, or place this file in
Git. The launcher checks exact equality against the current production handoff
builder, including its owner-reviewed JSON selection line:

```text
Owner-reviewed selection (IDs are references, not credentials or permission):
{"agentId":"<UUID>","intentId":"<UUID>","mode":"training","taskIds":["S1","M1","H1"],"quote":{"price":"0.500000","token":"USDC"},"cashCeiling":"0.000000"}
```

That example only illustrates the line's shape; save the complete instructions
from the actual reviewed intent. Launch once:

```powershell
& $bench -Action Run -HandoffFile .local/training-handoff.txt
```

`Start -HandoffFile` is an alias for this instrumented path. For Ranked create a
new reviewed Ranked intent and save its complete instructions to another file;
then use `Run -HandoffFile .local/ranked-handoff.txt`. Do not reuse a consumed
intent to request an additional run.

The instrumented path uses the pinned Codex `exec --json` build, preserves its
model/reasoning settings and native OAuth, disables unrelated tools/MCP servers
only for that process, and passes a public diagnostic case reference only when
registration succeeded. It retains safe per-call projections before discarding
raw JSONL. It prints no raw model text, arguments, task payloads or credentials.
The final launcher summary is diagnostic delivery evidence, **not** a benchmark
grade; verify the actual terminal run and task results in the platform.

Interactive `Start` without a handoff file remains a TUI. That surface has no
qualified per-call client stream: the launcher explicitly says client diagnostics
are unsupported there. It must not be described as equivalent coverage.

## Pending evidence and owner fallback

Automatic delivery needs no model reporting turn. For captured errors or gaps,
report creation and diagnostic watermarks must both be acknowledged. An error-free
complete capture legitimately has no report ID and creates no bug report. Lost responses replay the same canonical
batch. Authorization failure remains `pending_auth`; a later report/rate-limit
failure keeps final evidence pending. Diagnostic setup/storage failure is shown
as partial/unavailable and does not cancel or suppress the authorized benchmark.
A native failure does not itself prove a platform fault.

```powershell
& $bench -Action DiagnosticsStatus
& $bench -Action DiagnosticsRetry
# For a pending capture use localCaseId from DiagnosticsStatus.
# For an already synced capture use localCaseId from the earlier Run summary:
& $bench -Action DiagnosticsExport -LocalCaseId '<local case UUID>'
```

Export writes a new, non-overwriting safe bundle under
`.local/diagnostics-helper/` and prints its path. Import it through the owner's
Diagnostics page; do not upload raw Codex transcripts. The same case/segment IDs
and batch hashes are preserved so owner import and automatic retry converge.
Only a verified receipt permits acknowledged-payload collection. Undelivered
managed payloads expire before network delivery once their local age exceeds
30 UTC days. No always-running background process is installed.

## Reproduction boundary

```powershell
node --test tools/mcp-diagnostics-client.test.mjs tools/mcp-diagnostics-oauth.test.mjs tools/mcp-diagnostics-launcher.test.mjs tools/run-mcd-client-capture.test.mjs tools/mcd-local-capacity-restore.test.mjs tools/mcp-diagnostics-recovery.test.mjs tools/mcp-diagnostics-allocation.test.mjs
```

These tests include a real Node subprocess emitting synthetic JSONL and exiting
mid-call, safe allowlist projection with secret canaries, durable SQLite reopen,
binding isolation, identical retry bytes, fake-watermark rejection, finite retry
budget, authorization/expiry failures, and native-launch argument validation.
OAuth exchange/store tests use injected transports/store commands. They do not
read or mutate any user's native OAuth cache or the real OS credential store.

## Physical spool capacity

The 64 MiB cap includes SQLite control/schema pages and its transient journal,
not only event JSON. The helper uses `journal_mode=DELETE`, `synchronous=FULL`,
`cache_spill=OFF` and `temp_store=MEMORY`. A WAL is deliberately not used: another
reader can otherwise prevent checkpoint reuse and permit unbounded WAL growth.
All instances share one database; `BEGIN IMMEDIATE` serializes allocations.

Before creating schema or inserting rows, each connection sets SQLite's hard
`max_page_count` to `floor((budget - framingReserve) / (2*pageSize + 8))`.
The default framing reserve is 1 MiB. Thus the database plus one rollback image
of each page, journal record framing and reserve fit inside 64 MiB, including
control metadata. No cache spill, nested/savepoint transactions or attached
additional databases are used by the helper. This conservative internal reserve
can exhaust detailed capacity before the logical JSON/row limits. Allocation
then stops; retained rows are not evicted. Diagnostic coverage becomes
partial/unavailable without changing benchmark authority.

`DiagnosticsStatus` exposes logical usage and physical file bytes separately.
A pre-existing nonempty legacy WAL is preserved and rejected as unsupported
storage until separately checkpointed; the helper does not risk growing an old
WAL during implicit recovery. Unexpected files/links or an already oversized
managed store also fail closed for diagnostics.

Reduced-budget tests use real SQLite files, two open connections and two actual
competing helper subprocesses. They reach `SQLITE_FULL`, verify unchanged
retained row counts across reopen, inspect database/journal sizes, and assert
that no WAL/SHM is created. These tests cover the same page-budget arithmetic at
256 KiB; they are not a claim about disk allocation granularity or filesystem
compression. SQLite's [page limit and rollback journal controls](https://sqlite.org/pragma.html)
and [journal file format](https://sqlite.org/fileformat.html) define the storage
mechanism used here.

## Physical client capture producer (operator gate)

`tools/run-mcd-client-capture.mjs` performs an **actual** pinned native model run
when invoked. Metadata inspection alone cannot populate this evidence. Prepare a
private job file only after the owner has reviewed a fresh UI intent and the
helper's explicit OAuth consent has been completed:

```json
{
  "schemaVersion": "mcd-native-client-job/v1",
  "origin": "http://127.0.0.1:3000",
  "handoffFile": ".local/training-handoff.txt",
  "outputDirectory": ".local/mcd-client-capture-unique-id"
}
```

```powershell
node tools/run-mcd-client-capture.mjs --job .local/mcd-client-capture-job.json
```

Use a fresh output directory: files are created without overwrite. The producer
runs the real launcher, independently opens its SQLite spool read-only, and
writes only safe native-call/outbox/delivery fragments with original-byte hashes.
Setup envelopes are not relabelled as native MCP calls. It records source hashes
before/after execution and rejects a changed implementation. It does not save raw
model text, prompts, native credentials or task arguments.

Its fragment manifest deliberately remains `runtimeStatus: incomplete`. Root
qualification must attach real browser consent/click records, all SC002 negative
variants with independent business/diagnostic snapshots, actual HTTP receipt
watermarks and PostgreSQL report rows, and the run/intent audit. The producer
neither writes `runtime-inputs.json` nor claims a complete SC002 capture. Its
read-only projection unit tests use synthetic local rows; those tests are not
native model evidence and are never installed as captures.

## Interrupted capture recovery

Safe last-observed run state is durably written to a local SQLite control row
before its native result is discarded. The local row contains the validated run
UUID, status, client observation time, actual source call hash/tool and optional
trace/terminal flag. The run UUID is not added to uploaded diagnostic envelopes;
only the paired client status/time fields appear on runtime error evidence.
The qualified capture producer exposes this local observation independently of
its uploaded events and matches its source call hash before projecting the safe
server result into native evidence.

Each open segment has a process PID, random spool-instance UUID and release
marker. Startup recovery claims only a released segment or one whose PID is
provably dead. Live and unknown processes are skipped. Normal close releases
only that instance's open leases. Recovery preserves the case, existing event
IDs, staged batch hashes and sequence, adds one runtime interruption reason, and
stages the remaining segment as partial. No benchmark cancellation or new run is
performed by recovery.

Run and retry attempt old delivery before a new solver. When resuming the same
known nonterminal intent, startup permits one initial 25 ms attempt without
waiting for retry backoff, then continues with explicitly pending delivery. The
pre/post phases share the five-attempt budget. Export performs local recovery
without requiring network or helper consent. A successful native process exit
that last explicitly observed `terminal: false` records
`CLIENT_EXECUTION_FAILED`; an unknown terminal flag is not guessed.

The recovery test starts and kills an actual Node helper subprocess (no model),
checks that its live lease was skipped beforehand, and verifies original batch
identity, durable observation, recovery-before-execute and one canonical report
in a deterministic transport fixture. That client-side regression does not
replace the separate native/browser/PostgreSQL acceptance gates.

## Exact quota accounting performance

The former per-call allocator scanned all retained event payloads twice: once
for a case count and again for global byte totals. An actual read-only plan on
the stopped 2116-row capacity spool showed `SCAN events` for the byte query and
`SCAN e` plus segment lookup for the case query. Repeating those scans while
filling N events requires quadratic total row visits. Full filesystem syncs and
directory observations add separate costs; the scan diagnosis does not attribute
all observed wall time to SQL.

The allocator now bootstraps fixed counters from actual rows under
`BEGIN IMMEDIATE`, then uses SQLite triggers to update global row/byte/case/
segment counts and per-case row counts in the same transaction as each allocation
or release. Rollback rolls back both the detail and its counters. Reopening an
existing spool does not reset usage. The normal guard reads a single primary-key
counter row; detail insertion and indexes retain normal B-tree costs. The
independent acceptance observer still counts and sums actual payload rows, never
these application counters. Logical limits, the physical page/journal reserve,
per-call `FULL` sync and no-eviction behavior are unchanged. There is no
`appendMany`, asynchronous buffering or relaxed durability.

A disposable 2116-row real-file probe in this workspace measured the legacy byte
SUM at 1.156 ms median versus 0.113 ms for the fixed counter lookup on the same
retained database (100 cached reads each). New durable appends averaged 3.44 ms
for the first 512 and 3.43 ms for the last 512; all 2116 appends took 7.28 seconds.
These are local filesystem measurements, not a deployment throughput guarantee.
Safe exact output and probe source are `.local/mcd-allocation-perf-probe.json`
and `.local/mcd-allocation-perf-probe.mjs`. Existing-spool bootstrap, two real
competing helper processes, forced storage rollback, expiry/acknowledged GC and
physical `SQLITE_FULL` are compared with independent row/UTF-8 byte sums by the
allocation tests in the full command above.

## Native bootstrap configuration and observed setup

The pinned Codex CLI can list dynamically supplied MCP servers whose transports
are absent during configuration deserialization. Adding only an
`mcp_servers.<name>.enabled=false` override for such a server creates an invalid
transport record before the model or MCP initialization starts. The original
failure was reproduced without a model: `codex_app`, then `cua_repl` failed as
the preceding incomplete overrides were removed. This was a launcher
configuration defect, not a failed benchmark action or an OAuth denial.

For other STDIO servers the launcher supplies complete disabled entries with
the verified executable as an inert command. It copies no environment,
arguments or credentials from server metadata. The selected `w3bench_user`
HTTP transport and current native OAuth authorization remain unchanged. Native
metadata validation and regression tests protect both transport validity and
the disabled state; removing isolation is not a fallback.

A real first-setup probe subsequently completed exactly one authorized
`identity.preflight`, with zero MCP errors and zero local tool calls. The
observed identity matched the owner's current client connection, with Training
and Ranked allowed. Its immutable private projection is
`.local/mcd-native-first-setup-skeleton-c27ae89a-6cdd-4e69-bd2a-f4b12be09152.json`.
This probe accepted no intent and started no benchmark. Two native error items
preceded its successful MCP call; their exact causes were not retained and
remain unknown. They must not be relabelled as the transport defect or as
platform MCP failures.

Subsequent bootstrap and native error items retain only bounded fixed-class,
known configuration-field and fixed-vocabulary projections in the safe native
summary. Raw messages, paths, quoted values and credential configuration stay
out of persisted evidence. This adds no envelope fields and changes no schema
or byte limits. A successful first-setup probe and helper consent are setup
evidence only; the full native Training/Ranked, automatic-report, fault/recovery
and independent browser/PostgreSQL gates remain separate.
