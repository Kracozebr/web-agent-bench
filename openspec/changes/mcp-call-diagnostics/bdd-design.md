# BDD design packet: mcp-call-diagnostics

**Status:** awaiting approval of new assertions; no executable mirrors installed.
**Normative delta:** `specs/mcp-call-diagnostics/spec.md`.
**Target main capability:** `openspec/specs/mcp-call-diagnostics/spec.md` after
successful mandatory gates and explicit lifecycle closeout.

## Intent

Protect durable bounded error evidence and evidence-based attribution without
rewriting benchmark outcomes. All six gates use real boundaries and independent
read-only replay; source-bound component checks supplement these gates.

| Requirement | Scenario / named mapper | Boundary | Required observations | Negative/adversarial variants | Durable effects / evidence |
| --- | --- | --- | --- | --- | --- |
| MCD-REQ-001 | MCD-SC-001 / `test_mcd_sc_001` | Real MCP ingress, SDK validation, handler, executor and PostgreSQL | `stage_and_error_identity`; `source_local_timings`; `validated_links`; `survives_restart` | malformed JSON/RPC; SDK-rejected fields; expired/revoked auth; handler fault; dispatch fault; duplicate operation | Safe records exist; no action/funding on rejection. Trace hashes, actual responses/statuses projected safely, independent diagnostic/action/ledger rows and restart receipts. |
| MCD-REQ-002 | MCD-SC-002 / `test_mcd_sc_002` | Actual Codex → helper-owned OAuth/PKCE consent → deterministic private outbox delivery → admin UI/PostgreSQL; owner fallback import | `native_call_events`; `helper_oauth_scope_and_revocation`; `canonical_case_identity`; `automatic_report_and_watermark_receipt`; `admin_report_visible`; `deduplicated_delivery`; `blocked_delivery_zero_report_writes` | client-only validation; refused endpoint/recovery; lost admission/report response; crash with active known run; owner import racing helper; late run binding/batches; same-key different payload; missing consent/wrong scope/audience; revoked auth; restart/restore; delivery failure without recursion | Authorized/open-capacity intake creates one case/report and verified watermarks across actors/restarts; denied authorization instead creates zero new report writes with pending_auth. No replacement admission/payment. OAuth consent/revocation observations, native/outbox hashes, UI, receipts and independent case/report/ledger rows. |
| MCD-REQ-003 | MCD-SC-003 / `test_mcd_sc_003` | Issued schema/contract, trusted server observations, qualified client reproducer and read-only projection | `schema_contract_compatibility`; `positive_matrix_categories`; `classification_evidence`; `reject_all_unknown_projection`; `unknown_preserved`; `business_hashes_unchanged` | complete positive controls for client_contract/platform_contract/client_runtime/platform_runtime/external_dependency/expected_policy_denial; incomplete/contradictory controls; all-unknown mutation | Every complete positive returns the exact normative table category; unknown-only mutation rejected. Original grades/receipts/ledger unchanged; no refund. Source-bound observations, schema/contract hashes and independent classification replay. |
| MCD-REQ-004 | MCD-SC-004 / `test_mcd_sc_004` | Actual owner/admin UI and authenticated diagnostic/report API/PostgreSQL | `own_rows_visible`; `admin_authorized`; `foreign_denied`; `source_trust_visible`; `diagnostic_trigger_distinct` | foreign owner; anonymous; task agent read; forged run/action reference; client claim of server authority; completed run with client errors; ordinary failed grade only; error-free capture | No foreign import/view side effect; diagnostic errors report without fabricated platform attribution; no report for grade-only/error-free capture and no business write. Real UI, authorization and independent audit/domain snapshots. |
| MCD-REQ-005 | MCD-SC-005 / `test_mcd_sc_005` | Actual collectors, shared quota transactions across API replicas, importer and local spool | `canaries_absent`; `exact_finite_bounds`; `shared_quota_reservations`; `anonymous_fixed_buckets`; `gap_markers`; `no_duplicate_effect` | canaries in messages/keys/codes/identifiers; exact/over event/case/bundle and owner/deployment/anonymous/local quotas; rotating session IDs; concurrent helper/import/replica reservations; parser/storage faults | Quotas count reservations and all actors; anonymous overflow allocates no per-request rows; older evidence not evicted. Only allowlisted bounded records persist; quota exhaustion visibly incomplete. Independent byte/row/case counts, actual faults and business snapshots. |
| MCD-REQ-006 | MCD-SC-006 / `test_mcd_sc_006` | Server-received unified checkpoint/cold restore plus separate offline client-spool resume/expiry fixture | `server_received_inventory_and_hashes`; `remote_pending_excluded`; `partial_retained`; `write_disabled`; `revocation_retained`; `separate_retention_boundaries`; `case_batch_report_identity_retained` | interrupted upload/checkpoint; missing/tampered received evidence; pending remote file absent from server; stopped/uninstalled helper; local 30-day expiry; server intake closed; revoked helper; client/server restore independently | Server restore reconciles only received evidence; client backup is not claimed. Local expiry/reconsent/receipt govern later delivery without duplicates; no task/grade/financial write or revoked access restoration. Two separately labelled restore proofs and original business hashes. |

All scenarios are **environment**, **mandatory**, adapter
`mcp_call_diagnostics`, evidence mode
`actual_boundary_capture_with_independent_readonly_replay`. Private setup and
fault injection are isolated fixtures, never substitutes for native execution or
browser-initiated fallback import/view and actual native automatic report/receipt.
Missing external native access, authenticated reporting transport, observer or restore
prerequisites is `blocked`; untouched gates are `not_run`. No skipped gate permits
sync/archive or an all-clear claim.

## Execution design and integration

- Reuse the actual SDK, `EventSummary`/`AciEventSummary`, owner-acceptance runner,
  authenticated MCP negatives, BPC flood/privacy and combined backup/restore
  controls, and BER receipts/action/evaluation replay where their boundaries match.
- Prove the selected new helper OAuth client/resource/scope, explicit browser
  consent, own credential-store/refresh and linked revocation using real runtime
  boundaries. Wrong scope/audience and attempts at task/admin/diagnostic-read APIs
  must be denied. No model turn or access to Codex token files substitutes for
  deterministic automatic delivery qualification.
- MCD-SC-002 additionally requires `native_case_trace_carrier`: prove the exact
  native process's non-secret case header and safe server trace metadata on
  success/SDK errors; deny a foreign case association and explicitly mark partial
  correlation if the client hides the carrier. A timestamp-only join cannot pass.
- Install Gherkin, named mappers and semantic contracts only after approval.
  Independent readers recompute records, hashes, classifications and effects;
  producer flags/counters alone cannot satisfy a gate.
- Use fresh isolated fault probes for validation/client/transport cases. A fresh
  native Training and Ranked run validates collection on the qualified client;
  it does not require or invent 27 new failures, and cannot recover old detail.
- Preserve all old captures and current release pins. Refresh changed owner-source
  qualification/activation through existing verifiers before runtime acceptance;
  changes to sealed BEF source require its established qualification workflow.
- Protect existing BER-REQ-008, AFR platform-failure reporting privacy/allowlist, cabinet access,
  bonus/once-only authority and revocation/retention/restore rules. No existing
  scenario is renamed or silently redefined.
- Reconcile the new explicitly authorized `client_diagnostics` trigger with AFR:
  completed runs with actual client errors report automatically; ordinary failed
  grades alone do not. Assert exactly one report/receipt across lost responses,
  restarts, fallback import and pending-outbox restore. Report-delivery failures
  cannot generate a recursive chain of new reports or bypass revoked access.
- Use separate expected branches for delivered versus denied/pending variants;
  a revoked grant must create zero reports, not satisfy the positive receipt
  observation. Test crash after admission with run still active and no run-state
  mutation. Race owner import with helper delivery, then append late batches/run
  binding and verify one canonical report with fresh diagnostic projection.
- Recompute every classification table row independently; explicitly reject an
  all-unknown projection on complete positive evidence. Both global and per-owner
  quotas must resist caller-session rotation and concurrent replica reservations.
- Server backup qualification excludes remote pending spools and helper tokens.
  A separate client fixture checks next-launch local expiry/GC and durable
  outbox keys; neither fixture may claim timely purge on a stopped remote host.

## Approval boundary

The proposed production scope, six scenarios, exact privacy/limit assertions and
automatic diagnostic-report trigger/outbox, retention and fallback import extension are new and require approval under
`docs/task-design.md`. General approval of the older BER scenarios does not
retroactively approve these new assertions. This packet changes no executable
tests, production code, client configuration, grants or original run data.
