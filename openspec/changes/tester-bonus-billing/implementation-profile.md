# Initial ledger implementation profile

Approved scope: [approval.md](approval.md), review commit `9ee9211`.
This pins the first engineering slice; runtime evidence is recorded separately.

The existing Fastify/Better Auth/PostgreSQL/Next.js/Docker versions are reused.
No new runtime dependency or product cash-credit endpoint is introduced.
Identity, access fences and ledger tables share one PostgreSQL transaction boundary.
Execution-service commands remain a separate later integration.

Amounts use integer six-decimal units internally and fixed-six decimal strings
in responses. No floating point monetary arithmetic or exponent inputs.
Positive bonus amounts and nonempty bounded reasons are required. Expiry is
optional, explicit omission means no expiry, and a supplied expiry must be future.
One amount is bounded by PostgreSQL signed bigint units: `9223372036854.775807`.
Reasons contain 1-500 safe text characters; operation keys contain 12-128 ASCII
letters, digits, underscores or hyphens. No automatic audit/history deletion is
implemented. Initial private views include all owner lots and ledger entries.
Lots are immutable; rejected edits are audited without storing arbitrary bodies.
Transaction advisory locks serialize each actor's operation key before owner
row locks. Financial mutations use `FOR NO KEY UPDATE` to serialize balances
without cross-grant deadlocks from issuer foreign-key checks. Grant, source
entry, operation receipt and issuance audit commit together.

Private owner financial policy defaults to cash shortfall disabled and all caps
`0.000000`. An owner can explicitly select a positive cap or `null` for no cap.
Categories are `benchmark` and `forum`; both benchmark modes share the former.
These are separate from the four existing business permission flags.

## HTTP surface

- `POST /api/admin/bonus-grants`: `{operationId,ownerId,amount,reason,expiresAt?}`.
  Returns `{grant:{id,ownerId,amount,reason,createdAt,expiresAt},replayed,operationId}`.
  Same authorized key/payload recovers the same grant, conflicting reuse rejects.
- `PUT|PATCH /api/admin/bonus-grants/:grantId`: explicit immutable-edit rejection;
  no update capability. Authenticated invalid grant commands write a safe rejection
  audit with IDs/reason code, never raw invalid request text.
- `GET /api/owner/billing`: `{cash:{available,reserved},bonus:{available,reserved,expired},grants,history,observedAt,nextUtcResetAt}`.
  Totals cover all applicable lots; history/lot display may be bounded separately.
- `GET /api/owner/agents/:agentId/financial-policy`: direct policy DTO
  `{revision,allowCashShortfall,operationLimit,utcDayLimit,categoryLimits:{benchmark,forum}}`.
- `PUT` on the same policy path: policy fields plus `operationId,expectedRevision`;
  current verified owner only, optimistic revision, immutable safe audit.

Session/admin identities come from the existing verifier, never caller owner or
admin headers. Mutations keep same-origin checks. Agent credentials cannot use
owner/admin mutation routes. Bonus source is `tester_bonus`, cash is `cash_usdc`;
grants are not withdrawable cash or paid customer revenue.

The first full target gates are TBB-SC-001/002. Real browser controls initiate
commands, actual API/PostgreSQL commit them, and the separate `oid_observer`
reads persisted lots, idempotent receipts and audits. Other whole gates remain
blocked until their actual domain/cash/reservation/client observations exist.
