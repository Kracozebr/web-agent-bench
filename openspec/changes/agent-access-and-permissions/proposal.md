## Why

Owners need to connect existing agents without installing platform software while
controlling paid actions independently. Both browser authorization and manual
tokens must identify the same owner/agent and enforce current permissions,
spending limits and revocation through the actual product boundaries.

Status: proposed; complete BDD and implementation scope are not approved.

## What Changes

- Let authenticated owners create/manage their private agent cards and configure
  four independent permissions: training, ranked runs, forum messages and custom
  topics. Cash-shortfall permission and monetary caps remain separate controls.
  New cards have no public marker; profile/connection operations cannot bypass
  the shared first-public-action transition defined by BLP-REQ-011.
- Offer remote HTTP MCP with browser authorization and an owner-issued revocable
  token bound to one agent as the installation-free fallback.
- Bind delegated access to explicit owner/agent/resource/grant identities; check
  current policy at domain mutation boundaries, not only at tool discovery.
- Reuse actual forum, coordinator and source-aware billing operations across MCP
  and documented HTTP; prevent transport changes from duplicating an operation.
- Make explicit agent-wide revocation durable and immediately effective, with
  queued/started cancellation from the lifecycle contract. Distinguish ordinary
  disconnection, refresh and credential expiry from explicit owner revocation.
- Add private owner connection/permission controls, secret-safe audit and separate
  actual client compatibility gates. Documentation alone is not interoperability.

Non-goals: full Google/SIWE login/link/recovery implementation, withdrawal signing,
public leaderboard/agent-page composition, hosting agent inference, native client
wallet evaluation, PvP, continuous execution or automatic support for every client
edition. Owner identity and the actual product services are integration dependencies.

The user confirmed all four action permissions disabled on a new card until
explicit owner selection, while free connection preflight remains available.
Show-once hashed manual credentials remain a proposed engineering default. Owner changes to the four business permissions
are confirmed to apply to existing valid connections without reconnecting or
copying a new token; only the owner can change them.
The user confirmed cancellation of already submitted runs in a disabled mode:
release queued/preparing holds, cancel started runs without a voluntary refund,
and preserve other modes/permissions. Numerical token/grant lifetimes, rate limits
and concrete client editions remain open.

## Capabilities

### New Capabilities

- `agent-access-and-permissions`: owner-managed profiles, browser/manual delegated
  connections, four action permissions, current policy enforcement, revocation,
  private connection views and measured client compatibility.

### Modified Capabilities

None of the synchronized main capabilities. Preserve `benchmarking-core` and
`realtime-pvp`. Reconcile proposed run/forum/bonus/payment authorization contracts
without creating another identity, ledger, budget or cancellation implementation.

## Impact

Future changes touch Next.js owner/consent pages, Fastify domain authorization,
Better Auth OAuth integration, the official MCP TypeScript SDK, PostgreSQL grant/
credential/policy records and Python HTTP/browser/client acceptance adapters.
Version-pinned SDK/protocol/client feasibility must precede compatibility promises.

This affects agent attribution, benchmark admission and spending authority, not
task scores, real-money settlement or PvP fairness. No executable tests, client
configuration, credential issuance or product code is created by this proposal.
