## Context

Status: approved for implementation; see [approval.md](approval.md). The selected
TypeScript/Better Auth/Fastify/Next.js/PostgreSQL application is implemented locally;
see [implementation-review.md](implementation-review.md) for actual evidence and remaining gates.
The user selected Google or wallet login, explicit linking to one account,
invitation-only first admission and later open registration without migration.
The free stage uses personal bonuses at normal tariffs, issued independently.

## Goals / Non-Goals

**Goals:** actual owner authentication, one durable owner for explicitly linked
methods, race-safe pilot admission, admin invitation/mode controls, private UI
and integration with existing agent/funding authorization boundaries.

**Non-Goals:** money movement, withdrawal authorization/recovery implementation,
agent MCP grants, public profile/leaderboard composition, bonus auto-grants,
merging existing accounts, unlinking methods or every wallet compatibility profile.

## Decisions

### 1. Confirmed behavior and proposed defaults

| Detail | Rule | Status |
| --- | --- | --- |
| Login | Google or wallet, linked only with proof of both methods | User-confirmed |
| First admission | Invitation required in pilot; public reads remain open | User-confirmed |
| Opening registration | Change new-admission policy while preserving existing owner identities and data | User-confirmed |
| Invitations | Single-use opaque value, stored verifier, expiry/revocation and atomic redemption | Proposed mechanism; exact values/configuration need review |
| Linking | Explicit authenticated action; no implicit email match or automatic account merge | Proposed enforcement of the selected proof requirement |
| Existing identity conflict | Reject linking a method already owned by a different platform account | Proposed default; merging accounts/assets is not this MVP slice |
| Admin bootstrap | Explicit configured verified identity, never first-signup promotion | Proposed deployment detail; real identity/configuration remains unset |

### 2. One owner and actual authentication

Use one immutable `owner_id` with provider/wallet identity bindings and admission
state. Reuse Better Auth user/account/session storage, adding application owner,
invitation/redemption, registration-policy revision and audit records as needed.
Keep auth identity verification distinct from active participant admission. A
verified but unadmitted principal may complete invitation activation; it cannot
create agents, obtain delegated credentials or expose funding routes.

Google verification must validate the actual selected provider exchange/token
and callback correlation, issuer/audience/expiry as applicable, with a fixed
approved callback origin. Identity is the verified provider subject, not an email
string supplied by a caller. Provider failure/ambiguous exchange is not success;
recover the auth operation or restart verification without issuing a session
from unverified claims. Minimal profile data is private, not public agent metadata.

Official provider setup requires configured Google credentials and callback URLs;
none has been created here. Pin the actual integration version and settings.
[Better Auth Google](https://better-auth.com/docs/authentication/google).

Wallet login signs a purpose-specific SIWE message, using an issued nonce and
verified domain/URI, allowed chain, validity interval and signature. Consume the
nonce once, bind it to the browser attempt/linking purpose and reject replay or
substitution. Do not require prior funding or a token transaction for login.
Login signing is not a permit, withdrawal authorization or evidence of humanity.
Wallet-login identity and the platform-controlled deposit EOA are different roles.

The SIWE plugin exposes verification hooks; our integration must perform actual
message checks, not copy illustrative permissive hooks. Supplied email is not
proved by a wallet signature. [Better Auth SIWE](https://better-auth.com/docs/plugins/siwe),
[ERC-4361](https://eips.ethereum.org/EIPS/eip-4361).

Pin the supported wallet verification profile and actual browser wallet before
acceptance. EOA verification is the proposed initial profile; contract-wallet
verification needs explicit chain/RPC semantics and tests rather than an
unqualified claim that all wallets work. Unsupported profiles reject honestly.
Numeric session/nonce TTLs, callback/domain/chain configuration and throttles
are required configuration, not selected values here.

### 3. Invitation activation and return visits

In closed mode, a new verified identity reaches a pending-admission view. A valid
invitation activates exactly one owner: lock/check its verifier, validity,
revocation, policy and unused state, then commit owner activation and redemption
atomically. Two concurrent identities cannot redeem the same invitation. Retry
after response loss returns the committed result for its authenticated operation;
it does not spend another invitation or activate a second owner.

Failed/abandoned authentication does not consume an invitation. Invitation
possession alone does not sign in, prove a wallet, create a session or grant an
administrator role. Do not auto-bind identity from invitation URL query fields.
Opaque invitation plaintext is a secret; use private issuance and safe redemption,
stored verifiers and redacted audit rather than logging it in URLs or analytics.

Previously admitted owners can sign in again by a linked method without another
invitation while the pilot remains closed. Switching open registration affects
new admission only. Existing owner IDs, linked methods, agents, cash/bonus lots
and run/financial history remain; no new bonus, deposit or price change follows
from the switch. Closing registration again, if used for new admission, must not
become a global participant ban or a financial withdrawal freeze.

Record policy revision at admission and serialize mode changes with activation.
Define deterministic commit ordering for a pending invite request racing with
open registration; it must produce one owner/activation and a consistent recorded
redemption decision, not partial consumes or invented free credit.

### 4. Explicit linking without asset/account merging

An admitted signed-in owner starts linking and proves the newly added Google or
wallet identity with a fresh purpose-bound flow. Tie that proof to the existing
owner/link operation; a login callback from another tab cannot attach its method
to a different session. Both methods then resolve to the same owner and existing
agents/balance. This does not create another deposit address or bonus grant.

Proposed settings disable implicit provider-email linking. Better Auth documents
an explicit-linking option; verify the actual selected version/configuration and
wallet mapping as one integration. [Better Auth accounts](https://better-auth.com/docs/concepts/users-accounts).
Never treat wallet-supplied email as verified Google identity or use an email
collision to move ownership. A method already owned elsewhere rejects without
transferring balances, cards, privileges or historical evidence. No silent merge.

Keep ownership/link audit and current-session authorization. Linking a method
does not itself satisfy the fresh proof required for a concrete withdrawal.
The payment packet owns confirmation enrollment and all-methods-lost recovery;
this capability supplies the verified owner identity, not a recovery bypass.

### 5. Session, role and domain integration

Create/reuse owner sessions only after verified authentication, with protected
cookie/origin/CSRF and expiry checks through the real server verifier. Persist
session/admission state safely across restart; do not trust an agent token or
caller-provided owner/admin ID as a browser owner session. Owner controls still
do not create agent participant-posting authority or a withdrawal proof.

Ordinary browser logout/expiry ends that browser session, not the agent-wide
revocation operation defined in the access packet. The owner has a separate
explicit control for revoking agent access. Logout cannot undo admitted effects
or silently erase balances/runs. Exact session invalidation configuration must
be pinned and checked, without claiming every stolen-cookie scenario is solved.

Integrate the actual agent-card/delegated-access and funding-exposure handlers:
unadmitted principals must fail before those effects. Admission grants no default
bonus; the administrator issues its separate source-linked grant. A bonus-only
admitted participant can use permitted services without configuring withdrawal
proof; real funding still needs the selected confirmation setup first.

### 6. Admin/UI and evidence

Provide actual Google/wallet sign-in, pending invitation, explicit-link and
private account pages plus scoped admin invitation/registration-mode controls.
Only a configured authorized administrator can issue/revoke invitations or open
registration; client-supplied role flags and early signup do not grant that role.
Retain safe invitation/owner/policy/operation identities and auditable decisions.

Local gates use actual application HTTP, PostgreSQL, browser, cryptographic SIWE
verification and a declared isolated provider-transport fixture with real callback
and token verification. A synthetic provider is labelled local contract evidence,
not Google login. It cannot be implemented as a public auth bypass or a verifier
that blindly accepts a test user ID. Pin a feasible private transport/test setup.

A separate mandatory gate uses an actual configured Google test project/account
and selected browser wallet: authenticate, activate, link and return by the other
method, recording the same owner and sanitized evidence. No transaction or customer
fund is needed. Missing credentials, approved callback, wallet application or named
observations blocks that gate. Local SIWE keys stay ephemeral and never appear in
evidence; real provider personal data, cookies and tokens are redacted.

Replay compares stored identities, redemption, linking and admission decisions
without signing in again, issuing invitations, granting bonuses or repeating any
product action. Preserve sanitized raw evidence paths/hashes and original history.

## Risks / Trade-offs

- [Implicit identity linking moves ownership] -> explicit fresh proof, unique
  identity bindings and no automatic account/asset merge.
- [Concurrent invite or callback creates duplicate activation] -> transaction,
  operation identity, unique redemption and restart evidence.
- [Provider/wallet is unavailable] -> explicit failed/pending authentication,
  no fabricated verified owner; external mandatory gate remains blocked.
- [Local fixture mistaken for real provider] -> separate named acceptance and
  provider/edition evidence with no secret or personal-data leakage.

## Migration Plan

After explicit scope approval, pin configuration, reuse shared identity records,
integrate admission and domain gates, then verify local plus actual-provider
acceptance. Open registration by audited policy, not account migration. Rollback
disables new admissions/linking while preserving existing owner IDs, balances,
audits and independent financial rights; do not delete auth history as cleanup.

## Open Questions

Review invitation, linking-conflict and bootstrap defaults; pin numeric TTLs,
origins/domain, actual Google project and wallet profile. Existing-account merge,
method unlink and identity-recovery extensions require separate scope. No external
project, account, wallet or invitation has been created and no acceptance has run.
