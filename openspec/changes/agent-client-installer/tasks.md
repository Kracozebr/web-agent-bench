# Proposed implementation tasks

Revision direction: remote MCP connection, no local installer, and capability-based client compatibility. The owner renewed implementation and BDD approval on 2026-10-31; see approval.md. Implementation is in progress and all mandatory environment gates remain not_run until actual native/browser evidence and independent replay pass.

## 1. Reconcile scope and freeze the contract

- [x] 1.1 Reconcile the revised ACI capability matrix with active AAP owner/consent/client-qualification requirements and BRL launch-intent authority; preserve existing IDs/evidence and obtain approval for the revised assertions before apply.
- [x] 1.2 Freeze the canonical HTTPS MCP endpoint profile, supported protocol revisions, required tool schemas, OAuth registration modes, and safe incompatibility behavior; gate: reviewed profile, no exact app-version allowlist.
- [x] 1.3 Freeze the non-exclusive named target set and native add-link/fallback behavior; allow beta with the actually verified subset and identify remaining targets as unverified and outside its support claim.
- [ ] 1.4 Preserve the unified pre-migration checkpoint for bonuses, results, reports, screenshots, and evidence; verify migration and write-disabled restore before any new durable writes.

## 2. Add approved remote MCP and owner handoff

- [x] 2.1 After approval only, add the approved Gherkin mirrors, named mappers, and semantic contracts; gate: traceability and semantic audit, runtime still not_run.
- [ ] 2.2 Implement the canonical remote MCP onboarding flow with official native add links where verified and a clear URL fallback; inspect actual client state and prove no platform package, process, credential-bearing link, or hidden configuration write.
- [ ] 2.3 Implement browser OAuth consent bound to the verified owner, selected agent, remote MCP resource, and displayed permissions; capture denial and substitution negatives with no usable grant.
- [x] 2.4 Implement bounded access-token expiry, rotating refresh, response-loss retry, and replay denial without permission/cap changes or new business effects.
- [ ] 2.5 Implement selected-connection revoke, agent-wide revoke, disconnect distinction, and restore invalidation using existing AAP authority.
- [ ] 2.6 Implement declared MCP protocol negotiation and actual capability/schema preflight without exact client-version checks or client metadata trust.
- [ ] 2.7 Implement free authenticated native preflight and timestamped health/readiness states with independently verified zero run/financial effects.
- [ ] 2.8 Implement owner-bound launch intent delivery to the selected connected client; use existing BRL acceptance, quote, reservation, queue, and idempotency rules.
- [ ] 2.9 Qualify one real connection, preflight, and handoff smoke for every client included in the beta support claim; retain version as evidence metadata and label other named targets unverified, without a per-patch gate.

## 3. Prove the integration before release

- [ ] 3.1 Capture every approved scenario and negative variant on frozen source; independently replay raw paths/hashes and rerun affected AAP/BRL/BPC/BTS regressions.
- [ ] 3.2 Prove real browser-to-backend-to-database handoff and actual native client boundaries; no SDK/reference worker substitutes for a named client or participant model.
- [ ] 3.3 Exercise interruption, refresh/revocation races, rollback, and unified backup/restore for new durable records, preserving revoked access and once-only business effects.
- [ ] 3.4 Review each client’s qualified/unverified state and all mandatory gates; sync/archive only after renewed approval and required environment gates pass.

## Local implementation checkpoint (2026-11-01)

Implemented the remote OAuth profile, exact endpoint resource/audience, browser owner/agent consent with authoritative financial limits, rotating refresh, scoped connection management, authenticated preflight and selected-connection launch binding. Native clients own their configuration and credential stores. Other client families and external HTTPS deployment remain unverified.

Actual local Codex CLI 0.165.0 completed native OAuth, one free preflight and the browser-delivered S1 handoff on frozen source. Independent setup/authorization/preflight/launch replay passed all four checks, including exact UI/context/read-only PostgreSQL limits, once-only reservation/debit and terminal run status. Source: `artifacts/runs/agent-client-connection/1333879d-73d9-44d1-b001-71fb0190033f/capture-final.json`, SHA-256 `d0a1e931c8e915109f8678cab2d56246a3826a810953ede1c2e4d4c0b54a0fb6`. Replay: `positive-independent-replay.json` in that directory. This qualifies the documented local native profile only, not all eight environment gates or all Codex editions.

An external invalidation journal/floor is mandatory before remote API startup and remains outside restored private data. Missing, damaged or regressed authority fails closed. The consistent filesystem lock passed sixteen independent concurrent writers and controlled read/publication races; orphan locks time out without automatic deletion. Real provider PostgreSQL checks preserve bounded refresh retry and reject revoked/consumed refresh before read-only transaction locks.

Actual fresh PostgreSQL dump/restore independently compared all 88 tables, reconciled only security state on a maintenance connection, kept the ordinary database read-only, rejected old JWTs with HTTP 401 plus WWW-Authenticate and consumed refresh with HTTP 400, and preserved another connection with HTTP 200. Source and business fingerprints remained unchanged; no workers or BEF execution started. Private component capture: `.local/aci-cold-auth-e1d207b2-f44f-4a2e-8394-4e43db5cd22e/capture.json`, SHA-256 `16087042117a555820940cc16945bede62a5f1cfcd356963324150f7d6d04626`. This is separate from the sealed combined pre-migration checkpoint and is not native-client restore acceptance.

All eight full ACI gates remain open: the approved independently replayable negative matrices, refresh/restart and scoped/agent-wide native revocation controls, unified restore/operator handoff, same-boundary qualification inventory and external target activation are incomplete. Component tests and the native positive path do not replace those gates. No sync/archive or external beta activation is authorized by this checkpoint.
