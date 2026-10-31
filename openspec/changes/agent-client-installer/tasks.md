# Proposed implementation tasks

Revision direction: remote MCP connection, no local installer, and capability-based client compatibility. All revised BDD assertions await explicit approval. No task is complete and all runtime gates remain not_run.

## 1. Reconcile scope and freeze the contract

- [ ] 1.1 Reconcile the revised ACI capability matrix with active AAP owner/consent/client-qualification requirements and BRL launch-intent authority; preserve existing IDs/evidence and obtain approval for the revised assertions before apply.
- [ ] 1.2 Freeze the canonical HTTPS MCP endpoint profile, supported protocol revisions, required tool schemas, OAuth registration modes, and safe incompatibility behavior; gate: reviewed profile, no exact app-version allowlist.
- [ ] 1.3 Freeze the non-exclusive named target set and native add-link/fallback behavior; allow beta with the actually verified subset and identify remaining targets as unverified and outside its support claim.
- [ ] 1.4 Preserve the unified pre-migration checkpoint for bonuses, results, reports, screenshots, and evidence; verify migration and write-disabled restore before any new durable writes.

## 2. Add approved remote MCP and owner handoff

- [ ] 2.1 After approval only, add the approved Gherkin mirrors, named mappers, and semantic contracts; gate: traceability and semantic audit, runtime still not_run.
- [ ] 2.2 Implement the canonical remote MCP onboarding flow with official native add links where verified and a clear URL fallback; inspect actual client state and prove no platform package, process, credential-bearing link, or hidden configuration write.
- [ ] 2.3 Implement browser OAuth consent bound to the verified owner, selected agent, remote MCP resource, and displayed permissions; capture denial and substitution negatives with no usable grant.
- [ ] 2.4 Implement bounded access-token expiry, rotating refresh, response-loss retry, and replay denial without permission/cap changes or new business effects.
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
