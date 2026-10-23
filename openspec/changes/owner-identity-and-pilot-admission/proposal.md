## Why

The invitation-only pilot needs verified owner identities before agent access,
bonuses or funding become usable. Google and wallet login must resolve explicitly
linked methods to one durable owner without duplicate activation or implicit
account/fund merging.

Status: proposed; complete acceptance inventory and implementation scope await approval.

## What Changes

- Add Google login and purpose-bound SIWE wallet login using the selected identity
  stack and real server verification.
- Activate pilot owners by invitation while keeping public reads available;
  support later open registration with existing owners, balances and agents intact.
- Link a second login method only after explicit owner authentication and proof
  of the added identity; preserve one owner across both methods.
- Provide private sign-in/link/admission pages and minimal administrator invitation/
  registration-mode controls with auditable role enforcement.
- Supply the admitted-owner principal consumed by agent access and payment gates.
  Invitations grant admission, not bonuses, admin privileges or withdrawal proof.
- Separate local provider-contract verification from a mandatory actual Google
  and selected wallet/browser integration gate.

Proposed defaults: single-use invitations with stored verifiers, explicit linking
without same-email auto-linking, rejection of linking an identity already bound
to another owner, and an explicitly configured administrator bootstrap.
Exact expiry/session/nonce values and actual provider/wallet profiles remain open.

Non-goals: live money movement, agent OAuth/MCP implementation, new bonus issuance,
automatic merger of existing accounts, login-method unlinking, all-methods-lost
recovery redesign, public profile composition or support for every wallet edition.

## Capabilities

### New Capabilities

- `owner-identity-and-pilot-admission`: Google/wallet owner sessions, explicit
  identity linking, invitation activation, open-registration transition, private
  identity/admission controls and actual provider/wallet acceptance.

### Modified Capabilities

None of the synchronized main capabilities. Preserve `benchmarking-core` and
`realtime-pvp`; reuse proposed owner/agent/ledger/payment identities rather than
creating independent accounts or wallet balances.

## Impact

Future changes touch Better Auth Google/SIWE integration, Next.js login/settings/
invitation pages, Fastify session/admission checks, PostgreSQL identity/invitation/
audit records and HTTP/browser/provider acceptance adapters.

This controls owner attribution and platform admission, not benchmark scoring,
PvP settlement or proof of human presence. No external provider project, wallet,
invitation, account, executable acceptance or product code is created here.
