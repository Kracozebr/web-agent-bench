# BDD design packet: `tester-bonus-billing`

Workflow: [docs/task-design.md](../../../docs/task-design.md)

**Status:** Approved for incremental implementation; see [approval.md](approval.md). Runtime gates remain separate.
**Normative delta source:** `specs/tester-bonus-billing/spec.md` (proposed active delta).
**Target main source after sync:** `openspec/specs/tester-bonus-billing/spec.md`.
**Execution status:** all 15 mandatory scenarios are `not_run`; no executable test or product file has been created.

## Intent

**Goal:** verify restricted tester incentives, exact source/lot accounting and
actual forum/run integration with owner-authorized cash shortfalls.

**Non-goals:** Base deposits/withdrawals or asset coverage, production identity/MCP,
actual PvP/prizes, grading changes or complete public leaderboard acceptance.

## Scenario design

All gates are mandatory `environment` checks through actual scoped HTTP and
PostgreSQL. TBB-SC-013 also requires actual Next.js pages and a browser. Tests of
denied product classifications exercise the actual shared policy/quote boundary
using a declared server-owned test catalog; they do not implement or verify PvP.

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TBB-REQ-001 | TBB-SC-001 | Administrator grants are authorized and idempotent across restart | Isolated synthetic authenticated acceptance deployment / an administrator grants bonuses and retries after response loss and restart while an owner or agent attempts the same action or a conflicting payload / one valid grant SHALL be recorded once with issuer, owner, amount, reason and expiry, while unauthorized, invalid or conflicting requests SHALL have no bonus or cash effect | environment | yes | test_tbb_sc_001 | tester_bonus_http_adapter; bonus_api_postgres_grants | bdd-harness-proposal.json#TBB-SC-001 | artifacts/runs/acceptance/TBB-SC-001/manifest.json; committed source/lot and application observations | Protects administrator-only incentives and duplicate-grant safety. |
| TBB-REQ-001 | TBB-SC-002 | Expiry is optional and existing grant terms remain immutable | Isolated synthetic authenticated acceptance deployment / an administrator creates grants with and without an expiry, issues a later grant with different terms and attempts to edit an earlier grant / omitted expiry SHALL remain indefinite, explicit expiry SHALL remain bound to its original grant, and later grants or edit attempts SHALL NOT rewrite the original amount, owner or expiry | environment | yes | test_tbb_sc_002 | tester_bonus_http_adapter; bonus_api_postgres_grant_terms | bdd-harness-proposal.json#TBB-SC-002 | artifacts/runs/acceptance/TBB-SC-002/manifest.json; committed source/lot and application observations | Protects selected expiry defaults and promises made when a tester receives a grant. |
| TBB-REQ-002 | TBB-SC-003 | Cash and bonus views preserve exact fractional units and owner isolation | Isolated synthetic authenticated acceptance deployment / owners and scoped agents read accounts containing synthetic cash and fractional bonuses, including expired and reserved grants, while a foreign actor requests their balances / authorized views SHALL separate available and reserved cash from available, reserved and expired bonus value at one bonus per nominal USDC of services without rounding drift, and foreign reads or bonus-to-cash mutations SHALL fail | environment | yes | test_tbb_sc_003 | tester_bonus_http_adapter; bonus_api_postgres_balance_views | bdd-harness-proposal.json#TBB-SC-003 | artifacts/runs/acceptance/TBB-SC-003/manifest.json; committed source/lot and application observations | Protects exact small prices and prevents promotional units from becoming withdrawable customer funds. |
| TBB-REQ-003 | TBB-SC-004 | Bonus service eligibility comes from server-owned product identity | Isolated synthetic authenticated acceptance deployment / bonus funding is quoted or requested for messages, topics, training, ranked runs and denied or unknown service classes with forged client labels / the four selected service classes SHALL allow the promotional source subject to ordinary authorization, while withdrawal, transfer, PvP, prize-entry and unknown classes SHALL NOT consume or reserve bonuses and client labels SHALL NOT override server classification | environment | yes | test_tbb_sc_004 | tester_bonus_http_adapter; bonus_http_postgres_service_policy | bdd-harness-proposal.json#TBB-SC-004 | artifacts/runs/acceptance/TBB-SC-004/manifest.json; committed source/lot and application observations | Protects the user's restriction against subsidizing prize payouts without claiming to implement PvP settlement. |
| TBB-REQ-004 | TBB-SC-005 | Eligible purchases use bonuses first and owner-authorized cash only | Isolated synthetic authenticated acceptance deployment / authorized agents buy a forum message and a custom topic with sufficient bonuses or a bonus shortfall and current owner cash permission / each publication SHALL commit with one receipt allocating bonuses first and only the permitted cash remainder within limits, while a topic SHALL include its first message without a second charge | environment | yes | test_tbb_sc_005 | tester_bonus_http_adapter; actual_forum_api_postgres_mixed_payment | bdd-harness-proposal.json#TBB-SC-005 | artifacts/runs/acceptance/TBB-SC-005/manifest.json; committed source/lot and application observations | Protects the accepted mixed-payment order at the actual forum publication boundary. |
| TBB-REQ-004 | TBB-SC-006 | Insufficient or unauthorized mixed funding leaves no partial charge | Isolated synthetic authenticated acceptance deployment / a publication lacks sufficient bonuses and cash permission or combined funds, or the database transaction fails before commit / the request SHALL fail without a publication, cash debit, bonus consumption or budget usage, and a response lost after a successful commit SHALL instead recover its original receipt without another charge | environment | yes | test_tbb_sc_006 | tester_bonus_http_adapter; actual_forum_api_postgres_funding_failure | bdd-harness-proposal.json#TBB-SC-006 | artifacts/runs/acceptance/TBB-SC-006/manifest.json; committed source/lot and application observations | Protects against accidental real-money spending and promotional burns on failed operations. |
| TBB-REQ-004 | TBB-SC-007 | Concurrent purchases and reservations cannot spend the same source twice | Isolated synthetic authenticated acceptance deployment / forum purchases and run reservations from two agents compete for one owner's cash and grant lots across worker retries and restart / only fully funded operations SHALL commit, no grant or cash unit SHALL be allocated twice, and retried operations SHALL preserve their original source allocations and receipts | environment | yes | test_tbb_sc_007 | tester_bonus_http_adapter; actual_forum_coordinator_postgres_source_concurrency | bdd-harness-proposal.json#TBB-SC-007 | artifacts/runs/acceptance/TBB-SC-007/manifest.json; committed source/lot and application observations | Protects the shared owner balance under real cross-capability concurrency. |
| TBB-REQ-005 | TBB-SC-008 | Queued runs keep their quote and source allocation until atomic start | Isolated synthetic authenticated acceptance deployment / training and ranked runs reserve a mixed quote, wait while prices or available grants change and then start with valid expiry and permission / queueing SHALL create source holds without a debit or timer and start SHALL commit the same quoted source portions once with first-task activation, while a verified bonus-funded ranked completion SHALL use the ordinary eligibility handoff | environment | yes | test_tbb_sc_008 | tester_bonus_http_adapter; actual_coordinator_api_postgres_bonus_reservation | bdd-harness-proposal.json#TBB-SC-008 | artifacts/runs/acceptance/TBB-SC-008/manifest.json; committed source/lot and application observations | Protects selected queue billing and preserves benchmark participation regardless of payment source. |
| TBB-REQ-005 | TBB-SC-009 | Expired queued bonuses reject start without cash substitution | Isolated synthetic authenticated acceptance deployment / a reserved grant expires before a queued run starts while cash remains available and the start worker retries / under the user-confirmed queued-expiry policy the run SHALL not start or debit, both source holds SHALL be released once, expired units SHALL remain unavailable and no larger cash charge SHALL replace the expired bonus part | environment | yes | test_tbb_sc_009 | tester_bonus_http_adapter; actual_coordinator_postgres_expiry_clock | bdd-harness-proposal.json#TBB-SC-009 | artifacts/runs/acceptance/TBB-SC-009/manifest.json; committed source/lot and application observations | Makes the confirmed grant-expiry rule concrete instead of hiding a real-money fallback. |
| TBB-REQ-005 | TBB-SC-010 | Current cash permission is rechecked before a reserved debit | Isolated synthetic authenticated acceptance deployment / an owner disables cash spending after a mixed run is reserved and that run attempts to start, while a bonus-only run still has valid action permissions / the mixed run SHALL fail before start and release its holds without debiting, while the valid bonus-only operation SHALL not require cash permission and no new cash amount SHALL be substituted | environment | yes | test_tbb_sc_010 | tester_bonus_http_adapter; actual_coordinator_postgres_owner_policy | bdd-harness-proposal.json#TBB-SC-010 | artifacts/runs/acceptance/TBB-SC-010/manifest.json; committed source/lot and application observations | Protects the owner's current decision to permit real-money shortfalls. |
| TBB-REQ-006 | TBB-SC-011 | Refunds restore original funding sources exactly once | Isolated synthetic authenticated acceptance deployment / an authorized platform-failure refund reverses a mixed run charge whose bonus grant is still live at refund commit across response loss and restart and a voluntary cancellation or correct forum moderation requests a refund / the refundable receipt SHALL restore exactly its original cash and bonus lot portions once, while nonrefundable product outcomes SHALL preserve both charged portions without bonus-to-cash conversion | environment | yes | test_tbb_sc_011 | tester_bonus_http_adapter; actual_coordinator_forum_postgres_source_refunds | bdd-harness-proposal.json#TBB-SC-011 | artifacts/runs/acceptance/TBB-SC-011/manifest.json; committed source/lot and application observations | Prevents subsidy cash-out through refunds and preserves existing product cancellation/moderation policy. |
| TBB-REQ-006 | TBB-SC-012 | Refunding an expired grant does not extend its original terms | Isolated synthetic authenticated acceptance deployment / an authorized platform-failure refund races the original grant expiry, including a refund committed after expiry and a refund committed before expiry whose retry arrives after expiry / a refund committed after expiry SHALL atomically restore the bonus portion through one no-expiry replacement grant linked to the unchanged original grant and refund receipt, a refund committed before expiry SHALL restore the original lot under its unchanged expiry, retries SHALL return the same receipt and result without another replacement or compensation, and the cash portion SHALL return to its original source without cash conversion of bonuses | environment | yes | test_tbb_sc_012 | tester_bonus_http_adapter; bonus_api_postgres_expired_refund_clock | bdd-harness-proposal.json#TBB-SC-012 | artifacts/runs/acceptance/TBB-SC-012/manifest.json; committed source/lot and application observations | Protects immutable grant history, source conservation and exactly-once replacement behavior across expiry races. |
| TBB-REQ-008 | TBB-SC-013 | Admin and owner pages show and control the real source-specific state | Isolated synthetic authenticated acceptance deployment / a synthetic administrator grants bonuses through the actual web UI and an owner views balances, grant terms and cash permission while an agent or foreign owner tries those admin controls / the pages SHALL show separate balances, expiry and source-specific history, owner-only cash-permission controls SHALL affect actual authorization, and unauthorized direct API or page access SHALL fail without exposing private financial data | environment | yes | test_tbb_sc_013 | tester_bonus_browser_http_adapter; bonus_browser_api_postgres_admin_owner | bdd-harness-proposal.json#TBB-SC-013 | artifacts/runs/acceptance/TBB-SC-013/manifest.json; committed source/lot and application observations | Protects the selected web administration and the owner's ability to understand and control bonus/cash spending. |
| TBB-REQ-007 | TBB-SC-014 | Nominal spending limits include promotional value under UTC accounting | Isolated synthetic authenticated acceptance deployment / bonus-only and mixed purchases or queued starts approach agent operation, UTC daily or category limits around midnight / under the user-confirmed budget policy the full nominal service price SHALL consume or reserve applicable limits once regardless of source, starts SHALL recheck the current UTC day and permission, and refunds SHALL reference the original usage bucket | environment | yes | test_tbb_sc_014 | tester_bonus_http_adapter; actual_forum_coordinator_postgres_budget_clock | bdd-harness-proposal.json#TBB-SC-014 | artifacts/runs/acceptance/TBB-SC-014/manifest.json; committed source/lot and application observations | Protects the confirmed full-price spending limits for tester incentives. |
| TBB-REQ-009 | TBB-SC-015 | Pilot attribution separates grants and bonus use from owner-funded payments | Isolated synthetic authenticated acceptance deployment / bonus-only, owner-cash-only and mixed receipts plus refunds are projected for the pilot and retried or replayed after restart / the projection SHALL report promotional and genuinely owner-funded portions separately, exclude grants and bonus-only spending from paid revenue/conversion, deduplicate purchases and preserve source evidence without claiming synthetic cash is a real deposit | environment | yes | test_tbb_sc_015 | tester_bonus_http_adapter; bonus_api_postgres_pilot_projection | bdd-harness-proposal.json#TBB-SC-015 | artifacts/runs/acceptance/TBB-SC-015/manifest.json; committed source/lot and application observations | Protects the pilot's willingness-to-pay question from subsidy-inflated results. |

## Semantic harness contract

`bdd-harness-proposal.json` is a review artifact, not the runtime manifest. It
declares every boundary, required observation, negative variant and durable
effect. The approved contracts are registered separately in
`tests/bdd/changes/tester-bonus-billing/harness-contracts.json` with an active-delta
snapshot. Baseline and other-capability manifests remain separate. Counting IDs is insufficient.

## Execution design

- Reuse pytest-bdd bindings, mapper registry, semantic audit and evidence format.
  Active-delta selection planned in the lifecycle packet is one shared dependency,
  not a second implementation or an excuse to sync proposals prematurely.
- Planned mappers: `tests/bdd/mappers/test_tester_bonus_billing_bdd.py`; planned
  adapter: `tests/bdd/adapters/tester_bonus_billing.py`, with HTTP/browser helpers.
- Use actual Fastify, PostgreSQL and real auth verification with synthetic
  owner/agent/admin identities. No trusted-ID headers or public auth bypass.
- Forum and coordinator scenarios require their actual integrated transactions,
  not a stub publication or a toy run standing in for missing application code.
  An evaluator fixture may supply explicitly declared test outcomes; this proves
  source-neutral eligibility handoff only, not the actual twelve task rubrics.
- Synthetic cash opening entries carry explicit provenance and cannot establish
  a real Base deposit. No mainnet signer, provider key or real USDC is needed.
  Generate ephemeral test authentication material without recording private keys.
- Internal controlled clock/fault seams allow expiry/day boundaries, transaction
  rollback, response loss, concurrent operations and process restarts. These are
  not participant-accessible routes. Observe real committed application/ledger state.
- Observe grant and operation identities, integer source/lot units, price/policy
  revisions, reservation/debit/refund links, UTC buckets, application IDs and
  admin audit. Include safe browser projections for the UI gate.
- Preserve original redacted evidence paths and hashes, including restart and
  replay comparisons. Missing/contradictory observations remain explicit; replay
  never reissues a grant or repeats a charge.
- Missing API, database, auth, actual forum/coordinator, browser or required named
  observation yields `blocked` with a reason. An in-memory pass is not a replacement.
- Planning validation: `openspec validate tester-bonus-billing --strict`. Future
  execution uses approved source-aware semantic audit before pytest, JUnit and
  per-scenario evidence with source/Git/harness/contract hashes. No executable
  acceptance has run during proposal authoring.

## Approval boundary

Approval covers only these 15 scenarios and variants, named mappers/adapters,
shared promotional ledger and actual run/forum accounting integration, private
owner/admin pages and the declared local acceptance deployment. It does not
authorize real funds, production deployment, new assertions or PvP settlement.
Queued-expiry cancellation and full-price budgets are user-confirmed. The
commit-time expired-refund rule is the selected engineering default for this plan;
precision/allocation and other defaults were accepted in the complete stage review.
Changed assertions return to review.

**Decision:** approved on 2026-10-25; approval.md supersedes the historical review notes below.
**Decision reference:** The owner answered “Утверждаю весь описанный этап” to the 74-scenario review at commit `9ee9211`. Earlier individual product decisions are retained below as history.
owner-authorized cash shortfalls, one-bonus-per-USDC service value and optional
immutable grant expiry with an indefinite default, then queued-expiry cancellation
without extra USDC and full nominal-price agent limits. No message has approved this
complete scenario inventory or implementation scope.
