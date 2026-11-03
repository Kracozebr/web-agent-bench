## Why

The actual OAuth Ranked run `681411ae-8772-4649-acdc-98daa71a6d33` completed
with twelve known evaluations and 27 failed native MCP calls, but its sanitizer
retained only aggregate counters. The ephemeral client history and server logs
cannot recover their per-call causes. A completed run therefore does not establish
a usable, diagnosable client path.

## What Changes

- Persist bounded, sanitized per-call diagnostics at the server ingress, MCP
  schema/handler, dispatch and receipt boundaries, including failures before a
  valid task action exists. Retain successful-call timings for causal comparison.
- Extend the qualified native launcher to durably retain per-call outcomes and
  safe error codes/field paths before discarding raw CLI events. Client-only
  validation and transport failures remain observable even when no request reaches
  the server. Automatically deliver bounded diagnostics and one aggregated
  `client_diagnostics` support report to the platform administrator for each run
  or pre-admission client session with errors. Persist a delivery outbox and
  verify the report receipt; retain owner-authorized import as a fallback. Do not
  extract native OAuth tokens to upload it.
- Use an installer-managed diagnostics helper with its own public OAuth/PKCE
  client, write-only diagnostic scope and OS credential store. Its one-time browser
  consent is additional to native Codex authorization. No read of Codex tokens,
  model-driven upload or manual key is required by the selected design.
- Correlate server-generated trace IDs with existing operation/action/run IDs
  only after authoritative ownership/binding checks. Separate observed failure
  stage, evidence source, and responsibility; insufficient evidence stays unknown.
- Define mandatory positive attribution cases and one actor-independent canonical
  diagnostic case/report across admission, retries, owner import and late batches.
  A client crash with a still-running accepted run reports without changing that run.
- Add owner-private and administrator diagnostic views, completeness markers,
  and safe diagnostic references in reports. The new diagnostic-report trigger
  is independent of terminal platform-failure reporting; it does not assert
  platform responsibility. Preserve existing grade, funding, refund and confirmed
  platform-failure report authority.
- Bound owner/deployment/anonymous/local spool totals as well as each event/case.
  Include server-received evidence in unified backup and audited beta retention;
  distinguish remote pending client files and their next-launch local expiry.
  Verify access control, redaction and persistence after restart.

Non-goals: raw transcript collection, hidden Ranked payload retention in diagnostic
records, reading native credential stores, changing task goals/timers/prices or
scores, granting new task authority, hosted solving, PvP or settlement changes.
Historical missing causes are not backfilled with guesses.

## Capabilities

### New Capabilities

- `mcp-call-diagnostics`: durable private call-level evidence, automatic diagnostic
  delivery/reporting, fallback import, evidence-based classification and explicit
  capture completeness.

### Modified Capabilities

None of the synchronized main capabilities is replaced. This supplements active BER-REQ-008 and cabinet/report projections without
replacing their existing scenario IDs or changing task evaluation semantics.
The implementation must reconcile existing backup/retention and access contracts
and the active AFR delta: its confirmed-platform-failure allowlist still governs
platform-failure reports, while this explicitly authorized diagnostic kind can
report client errors without a confirmed platform failure.

## Impact

Owner API/MCP transport and registration, diagnostic PostgreSQL migration and
read projections, native launcher/parser and persistent delivery outbox, owner/admin
UI, automatic diagnostic report/receipt and fallback import, unified backup/restore
readers and BDD adapters; a new diagnostic helper OAuth client/resource/scope and
consent/revocation binding. These new permissions are explicitly part of this
pending packet, not a claim that existing OAuth grants already permit delivery.
No existing business record is rewritten. Implementation and the revised six
scenario/assertion inventory were approved on 2026-11-02; see approval.md.
Planning validation and approval do not establish runtime acceptance.
