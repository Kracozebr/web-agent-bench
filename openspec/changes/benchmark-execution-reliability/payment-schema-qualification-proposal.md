# Qualification of the additive public-payee schema

Status: approved by the owner on 2026-11-01: “Да, допустить только точную
миграцию 011 и продолжить проверки.” No task goals, timing, prices,
scores, historical artifacts or semantic case comparator may change.

All fifteen fresh references in qualification
`63b0dd71-3cfa-48e6-bd1d-a9c1742b3e8f` completed, and raw integrity passed.
Case assembly correctly stopped at `refresh_migrations_changed`: existing
source-refresh profiles require an exactly unchanged migration inventory.
The repair adds `011_public_payment_recipient.sql`, so those existing profiles
cannot authorize its release.

## Proposed narrow admission

Add a separate `restart_payment_identity` qualification reason. Keep the old
source-refresh reasons and their exact-inventory requirement unchanged. For the
new reason, require exactly the ten approved baseline migration files, with
their existing hashes unchanged, plus precisely:

- Path: `infrastructure/benchmark-environment/migrations/011_public_payment_recipient.sql`
- SHA-256: `5596a70231924c55999ae8a631a8dc8fc9ce1372acfd852ba95455651b6418bb`

The migration adds one nullable public-address column and a nonzero address
constraint. It contains no data update and no private wallet storage. Existing
rows remain NULL. All ten previous files currently match the approved baseline;
all 647 pre-migration payment row fingerprints were independently unchanged,
and a private backup was restored and checked read-only.

Protect this admission with negative tests: reject an edited, missing or
duplicate old migration; wrong hash/path for 011; any additional migration;
attempts to use this exception under either old qualification reason; and
unknown qualification reasons. Existing task/identity semantic comparators,
all-fifteen fresh source bindings and independent reference verification remain
mandatory. A schema admission alone must never activate a release.

After approval, run the new qualification profile, independent candidate
validation, actual service-restart regression, browser-admitted Training and
Ranked, and native failure/report E2E. Retain failed campaigns unchanged.

Approval is requested because `docs/task-design.md` states: “A new scenario or
changed assertion requires renewed approval.” This changes only the schema
admission assertion for the named new profile, not benchmark task assertions.
