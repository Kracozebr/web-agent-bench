# Beta PoC implementation tasks

Status: approved for implementation/acceptance on 28 October 2026; runtime gates remain separate.
The 10–14-day target and parallel work map are in [delivery plan](../../../docs/poc-delivery-plan.md).
Gate IDs below refer to the exact [BDD packet](bdd-design.md); environment gates
must use real UI/client/backend/database/BEF boundaries. Keep all boxes unchecked
until their named result exists, and implementation separate from gate completion.

## 1. Scope, manifest and first external slice (P0–P3; days 1–2)

- [x] 1.1 Obtain approval of BPC-REQ-001–015, BPC-SC-001–026, their negative variants/defaults and external beta extension; record the decision in approval.md (artifact gate).
- [ ] 1.2 Select the not-yet-chosen server/domain and arrange access; create/configure the absent Google OAuth project, verify the owner-selected admin account subject; arrange missing Claude Code/Desktop/Hermes access and pin all four editions/model access and qualification/release manifest states and schema/secret references; validate missing/invalid profile inputs fail closed (BPC-SC-001/008/013).
- [x] 1.3 Add review-approved BPC runtime contracts, named mappers/adapters and Gherkin mirrors using existing active-delta tooling; missing producer/observation must be blocked (artifact traceability; BPC-SC-023).
- [ ] 1.4 Factor reusable local worker/readiness dependencies into an explicit beta entry/profile without relaxing local-mode guards; validate release/environment and exclude fixtures (BPC-SC-013).
- [ ] 1.5 Configure target-host web/API/worker, HTTPS/trusted origins and private DB/BEF admin/RPC interfaces with persistent DB/evidence paths (BPC-SC-013/021).
- [ ] 1.6 Implement/validate the remote allowlisted transport and exact OAuth callback/client registry where required; retain strict/default/local regression behavior (BPC-SC-008).
- [ ] 1.7 Record day-2 checkpoint: real external Google owner, real client preflight and model-executed first task with independent result; diagnose all four client paths and explicitly report blockers/schedule impact (partial BPC-SC-001/009–013, not whole gates).

## 2. Open onboarding and explicit agent policy (P4/P7)

- [ ] 2.1 Configure real Google open signup and founder bootstrap, return-owner session and no-code/no-bonus admission; verify callback failures (BPC-SC-001).
- [ ] 2.2 Verify private owner/agent UI and direct API roles/origin/CSRF enforcement with distinct real sessions (BPC-SC-002).
- [ ] 2.3 Integrate client setup instructions, preflight, explicit training/ranked permissions and nominal caps, credential replacement/revoke without insecure token copying (BPC-SC-007).
- [ ] 2.4 Capture all four remote client preflight/accept/revoke and HTTP/MCP replay/denial matrices across restart (BPC-SC-007/008).

## 3. Bonus codes and source-aware funding (P5–P6)

- [ ] 3.1 Add code/redemption migration, verifier/uniqueness/indexes and transaction-scoped existing grant writer; verify migration preserves old grants/data and wrong precision/kind/limits fail (BPC-SC-003/006).
- [ ] 3.2 Add authorized idempotent issue/list/disable handlers, immutable terms and one-time plaintext delivery with lost-issuance recovery UX (BPC-SC-003/004).
- [ ] 3.3 Add atomic owner claim with code/owner locking, stable financial receipt and grant/entry/audit/counter conservation (BPC-SC-005/006).
- [ ] 3.4 Add admin code UI and owner redemption/balance UI; verify real browser-to-PostgreSQL final effects (BPC-SC-003–005).
- [ ] 3.5 Capture different-owner last-use race, same-owner different-key race, disable race, rollback, lost-response/restart/conflict and unauthorized variants (BPC-SC-004/006).
- [ ] 3.6 Prove code-derived bonus lot → authorized training/full12 reserve/start debit, no cash substitution, exact balance and denial without partial effects (BPC-SC-005).

## 4. Training, full12 and real models (P8–P9)

- [ ] 4.1 Extend real training capture coverage to single, multi and all-eight open selections; keep closed/mixed/duplicate rejection and exact denominator/rounding/quote (BPC-SC-014).
- [ ] 4.2 Verify beta task actions, independent observations/sealing/grading, mandatory zeroing, continuation and full12 aggregate against the pinned release with no recipe/grade substitution (BPC-SC-013/015).
- [ ] 4.3 Integrate private run history and authorized mode-specific feedback; verify ranked withholding and closed-category-only disclosure (BPC-SC-015).
- [ ] 4.4 Capture actual Codex model training/full12, solution failures, reconnect and final independent readback (BPC-SC-009).
- [ ] 4.5 Capture actual Claude Code model training/full12, solution failures, reconnect and final independent readback (BPC-SC-010).
- [ ] 4.6 Capture actual Claude Desktop model training/full12, solution failures, reconnect and final independent readback (BPC-SC-011).
- [ ] 4.7 Capture actual Hermes model training/full12, solution failures, reconnect and final independent readback (BPC-SC-012).

- [ ] 4.8 Add minimal anonymous public list/card and coherent versioned best-result views using the existing marker, allowlisted fields and exact best/tie behavior; capture real browser/API/cache/rebuild cases (BPC-SC-025).

## 5. Durable queue and platform failure (P12)

- [ ] 5.1 Add separately serialized accepted-queue caps and pending-intent caps with validated beta policy, preserved owner rotation/slots and original 86400-second queue deadline and visible expiry-fence-pending state during failed preparation cleanup, with a separate beta maximum supporting 24 hours instead of the local 3600-second ceiling (BPC-SC-016).
- [ ] 5.2 Verify concurrent cap fill, duplicate dispatch/start, busy-agent head, 24-hour deadline/start/cancel boundary race, expiry/retry and UTC/current-permission rechecks without extra holds/debits (BPC-SC-016/017).
- [ ] 5.3 Implement trusted bounded platform-evidence recovery and exactly-once original-source bonus refund for exhausted recovery; unknown never becomes inferred safe failure (BPC-SC-017).
- [ ] 5.4 Capture cancel/revoke before/after start, actual committed action with lost response, restart/recovery success/exhaustion and stale callbacks; verify original fencing/claim/slot and source outcomes (BPC-SC-017).

## 6. Human and agent reports with admin triage (P10–P11)

- [ ] 6.1 Add report/status/audit schema, idempotent create/read service, per-principal authorization, optional validated links and private screenshot references, safe auto-context and independent size/rate bounds (BPC-SC-018/019).
- [ ] 6.2 Add website report form, screenshot upload/preview and own receipt/status/image views; cover no-run connection problems and lost-response retries (BPC-SC-018).
- [ ] 6.3 Add authenticated agent report API/MCP tool with bounded MCP screenshot begin/chunk/finish and principal-bound upload references or audited owner attachment and all-four-client captures; prove zero billing/task/action/timer effects and no bypass via revoked/forged/foreign credentials (BPC-SC-019).
- [ ] 6.4 Add admin list/detail/filter/pagination with private screenshot previews/downloads and audited revisioned status close/reopen controls with escaped rendering (BPC-SC-020).
- [ ] 6.5 Capture real UI and native-client report paths plus forbidden context, foreign IDs, duplicate/conflict, payload/flood and stale-status and foreign-image variants; independently read reports/audits/image hashes and unchanged run/ledger state (BPC-SC-018–020/024).

- [ ] 6.6 Add bounded authenticated PNG/JPEG/WebP upload/normalization/private storage, atomic image binding, owner/total/staging quotas and normalized byte/disk thresholds, retry/conflict chunk receipts, orphan cleanup and real negative/upload/read tests (BPC-SC-024).

## 7. Beta operations and restore (P13)

- [ ] 7.1 Add supervised health/readiness, admission pause/drain, queue/disk/failure observations and stable private service isolation on the target host (BPC-SC-021).
- [ ] 7.2 Capture bounded load, pause, healthy read/report access, resource exhaustion and restart with queued/running/completed work, checking original identities and no leaks (BPC-SC-021).
- [ ] 7.3 Implement consistent daily/pre-migration DB+evidence+committed-screenshot backup with separate operator secret recovery and immutable inventory; document same-host limitation (BPC-SC-022).
- [ ] 7.4 Restore into an isolated instance; verify code/bonus/report/result totals and screenshot bytes, required hashes, interrupted-run reconciliation and safe retry before enabling writes; record actual RPO/RTO (BPC-SC-022).

- [ ] 7.5 Add audited beta closure and 30-day report/screenshot expiry, access denial, idempotent purge/deletion receipts and backup sanitization; verify late attachment, failed delete and old-backup restore without erasing grades/ledger (BPC-SC-026).

## 8. Acceptance, cohort and closeout (P14–P15; days 6–14)

- [ ] 8.1 Run initial 3–5-person test after included paths are ready; retain stable source/client/profile evidence and receive real human/agent reports; fix observed blockers and repeat affected gates (BPC-SC-001–022/024–026).
- [x] 8.2 Produce deduplicated owner/client usage and support export excluding bonus usage from paid conversion; verify missing/duplicate/conflicting records (BPC-SC-023).
- [ ] 8.3 Run all mandatory beta gates on the frozen target build, semantic/traceability audit and read-only evidence replay; record passed/failed/blocked/not_run distinctly, preserve old MVP states (BPC-SC-023).
- [ ] 8.4 Record explicit beta readiness decision and expanded-cohort conditions using complete evidence, setup/known limits and operator recovery guide; do not infer release from elapsed time or a green source build (BPC-SC-023).
- [ ] 8.5 Sync/archive only this capability after all beta tasks/gates pass, rerun synchronized traceability/replay and update PoC/MVP status without closing unrelated changes (artifact closeout).
