# Ledger grants: first implementation slice

Date: 2026-10-25. Approved scope: [stage review](run-execution-entry-review.md),
review commit `9ee9211`, and the owner's explicit approval of all 74 BRL/TBB/BTS
scenarios. This document records local runtime evidence, not production readiness.

## Implemented boundary

The actual admin form commits immutable tester-bonus lots, source entries,
idempotency receipts and safe audits through Fastify into PostgreSQL. It retains
the original operation key after an uncertain response. Private owner pages show
separate cash/bonus balances and grant terms; agent financial policy persists
cash-shortfall opt-in and operation, UTC-day and category caps. All caps start at
zero and cash permission starts off. Amounts use integer six-decimal units.

No product cash-mint endpoint, spending coordinator, payment or task execution
is included in this slice. Stored financial policy does not yet prove enforcement
at a real purchase or run start. Runtime changes are additive to existing auth.

## Verified runtime evidence

The browser capture used Chromium, the production Next.js build, actual Fastify
and PostgreSQL in Docker. Synthetic identities passed through the real local
authentication verifier. Independent SQL inspection used SELECT-only
`oid_observer`, with read-only transactions.

Capture ID: `e4d00c48-df29-41db-81e3-01f3b21ac7d8`.
Retained isolated database: `oid_acceptance_e4d00c48df2941db81e301f3b21ac7d8`.
Runtime image: `sha256:9ec20bec50f0975ddd7dfc63e4cfb276a429d1e09744547e49c1120f007e39d4`.
Provenance confirms source inputs stayed unchanged during capture; marking task
3.2 complete afterward changes only workflow bookkeeping.

| Gate | Result | Evidence |
|---|---|---|
| TBB-SC-001 | passed | Admin UI grant; lost committed response; same-key retry after API restart; one lot/entry/receipt/audit; invalid/conflicting and unauthorized attempts have no financial effect. |
| TBB-SC-002 | passed | Default no-expiry and pinned explicit expiry; three denied edits with rejection audits; independent later grant preserves original terms. |
| TBB-SC-013 | blocked, partial controls observed | `/billing` balances and every displayed lot match the owner API projection. Browser policy save/reload matches independently observed policy, receipt and audit. Actual spending enforcement and the complete access matrix remain unproven. |
| Other 12 TBB gates | blocked | Required spending, reservation, forum, refund or pilot projection boundaries are absent. |

Raw sanitized evidence and SHA-256 inventories are retained under
`artifacts/runs/acceptance/<scenario>/runs/<run UUID>/`:

- TBB-SC-001: `bc52b09d-560c-4622-93a3-d5876db92ff9`.
- TBB-SC-002: `466a58f4-4817-40b9-b068-d7f347f10504`.
- TBB-SC-013: `9537b6c8-e72d-4c7a-ba89-20dde3738575`.

The filesystem-only replay independently derives every SC-001/002 observation
and negative from the browser/API captures and SQL rows. It verifies artifact
and contract hashes and performs no network requests or product mutations.

## Checks and reproduction

All runtime commands run through the repository Docker wrapper:

```powershell
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity check
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance check
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/replay_tbb_acceptance.py all
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change tester-bonus-billing
```

Stop the development container before production build/capture, then restart it.
Identity typecheck, web production build, acceptance syntax, ledger migration,
OpenSpec structural validation (12/12), and TBB semantic audit (15/15) passed.
BDD results: TBB 2 passed/13 blocked, OID 3 passed/9 blocked, AAP 3 passed/13
blocked. Pytest reports blocked boundaries as skips; the mandatory-gate recorder
returns exit 1 because they prevent whole-change acceptance. These are not full
green suites. Existing pytest-bdd compatibility deprecation warnings remain.

The next implementation slice adds durable launch intent/admission/cancellation
and coordinator primitives. A positive launch-to-run gate also requires a genuine
validated complete 12-task release and prepared execution environment. A partial
catalog, fabricated run or selected-action BEF adapter cannot satisfy that gate.
No sync or archive is allowed while mandatory gates remain blocked.
