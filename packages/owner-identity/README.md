# Owner identity and pilot admission API

This package owns the Fastify API, Better Auth session/provider integration, owner identity projection, invite redemption, registration policy, SIWE wallet linking, private agent cards and permission settings, delegated credentials/preflight and durable audit records. All application state is in the configured PostgreSQL database. The local browser OAuth/MCP profile is pinned in [oauth-profile.md](../../openspec/changes/agent-access-and-permissions/oauth-profile.md). Paid domain operations, actual pilot-client compatibility, funding and ledger posting remain separate acceptance gates.

## Local start

Use the repository's Docker runtime for dependency installation, migration, build, and execution. The parent runtime supplies `OID_DATABASE_URL` and `OID_AUTH_SECRET` from ignored local secret files. Do not run package commands from the Windows host.

```powershell
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity migrate
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity dev
```

The API defaults to `127.0.0.1:8784`. Set `OID_API_HOST=0.0.0.0` only when the API must accept connections from another container. The browser-facing origin defaults to `http://127.0.0.1:3000`; use this same hostname for the web app and Better Auth OAuth callback. The Google redirect URI is `{OID_PUBLIC_ORIGIN}/api/auth/callback/google` and should be registered with the provider.

## Environment

| Variable | Meaning |
| --- | --- |
| `OID_DATABASE_URL` | PostgreSQL connection string for the owner identity database. |
| `OID_AUTH_SECRET` | Required Better Auth secret, at least 32 characters. |
| `OID_PUBLIC_ORIGIN` | Trusted browser origin and Better Auth base URL; defaults to `http://127.0.0.1:3000`. |
| `OID_API_HOST` / `OID_API_PORT` | Fastify bind address and port; defaults to `127.0.0.1:8784`. |
| `OID_GOOGLE_CLIENT_ID` / `OID_GOOGLE_CLIENT_SECRET` | Configure together to enable the actual Better Auth Google provider. |
| `OID_GOOGLE_FIXTURE_ORIGIN` | Optional local contract-fixture marker; forbidden in production. It does not replace or bypass Google adapter token/JWKS verification. |
| `OID_ADMIN_PROVIDER` / `OID_ADMIN_SUBJECT` | Configure together with the exact verified identity that receives admin controls. Supported provider names are `google` and `wallet` (`siwe` is normalized to `wallet`). |
| `OID_REGISTRATION_MODE` | Initial policy used only when the singleton policy row is first migrated: `closed` (default) or `open`. |
| `OID_SESSION_TTL_SECONDS` | Session lifetime; default 604800, range 300–31536000. |
| `OID_INVITATION_TTL_SECONDS` | Default invitation lifetime; default 604800, range 60–2592000. |
| `OID_MANUAL_CREDENTIAL_TTL_SECONDS` | Default manual credential lifetime; default 86400, range 300–2592000. |
| `OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX` | Owner manual credential requests per IP and configured window; default 30. |
| `OID_AGENT_PREFLIGHT_RATE_LIMIT_MAX` | Agent preflight requests per IP and per credential/IP and configured window; default 60. |
| `OID_MCP_CLIENT_ID` | Preregistered public OAuth client; local default `oid-local-mcp-client`, explicit in production. |
| `OID_MCP_CLIENT_REDIRECT_URI` | Exact preregistered loopback callback; local default `http://127.0.0.1:38765/oauth/callback`, explicit in production. |
| `OID_AUTH_RATE_LIMIT_MAX` | Requests per IP and configured window for auth/admin/admission groups; default 10. |
| `OID_SIWE_RATE_LIMIT_MAX` | SIWE requests per IP and configured window; default 6. |
| `OID_RATE_LIMIT_WINDOW_SECONDS` | Rate limit bucket size; default 60 seconds. |

`OID_GOOGLE_FIXTURE_ORIGIN` is only used with the isolated local provider transport in acceptance. `googleMode` reports `provider-fixture`; this is contract evidence, not proof of real Google credentials or production provider behavior. With no Google credentials, Google sign-in is disabled. Real Google validation requires credentials configured by the operator and an actual provider callback.

## API contract

Better Auth owns the allowlisted `/api/auth/*` endpoints: Google `sign-in/social`, explicit `link-social`, Google callback, SIWE `POST /siwe/nonce`, SIWE `POST /siwe/verify`, session lookup, sign-out, and the provider error callback. Unrelated Better Auth mutations such as account unlink and user deletion are not exposed. Implicit account linking is disabled; identities are never merged by matching email. SIWE verifies an EOA signature, the configured origin/domain, chain ID 8453, a short-lived nonce, browser context, and signed message time bounds. Google identity linking stores an OAuth state digest bound to the initiating admitted owner and live session, then checks that same session before Better Auth can attach the callback identity. Wallet linking uses the owner/session-bound routes below and creates a Better Auth wallet association only after signature verification.

| Method and path | Result |
| --- | --- |
| `GET /healthz` | `{status:"ok"}` after a PostgreSQL read. |
| `GET /api/identity/config` | Non-secret Google mode and SIWE origin/chain/statement/nonce configuration. |
| `GET /api/identity/connection-profile` | Public protocol/resource/client/discovery configuration, without credentials or account state. |
| `POST /api/owner/agents/oauth-select` | Selects an existing owned agent for a signed provider authorization request; stores a pending session-bound flow. |
| `POST /api/owner/agents/oauth-consent-context` | Returns the selected client/resource/scopes and current agent permissions for review. |
| `POST /api/owner/agents/oauth-consent` | Records the explicit owner decision and returns the validated provider redirect. |
| `GET /api/owner` | Verified owner, admission status, admin display hint, identities, and policy revision. Returns `401` without a session. |
| `POST /api/admission/activate` | Body `{invitation?,operationId}`; consumes an invite atomically in closed mode, or admits under current open policy. |
| `POST /api/owner/links/siwe/nonce` | Body `{operationId}`; issues a 15-minute owner/session-bound linking nonce. |
| `POST /api/owner/links/siwe/verify` | Body `{operationId,message,signature}`; verifies the EOA proof and commits the identity association. |
| `GET /api/owner/agents/:agentId/manual-credential` | Returns safe access revision, resource/preflight URL, and manual credential status metadata; never returns token plaintext. |
| `POST /api/owner/agents/:agentId/manual-credential` | Body `{operationId,expectedAccessRevision,intent:"issue"|"replace",expiresInSeconds?}`; returns a 256-bit opaque token once. `replace` fences any current predecessor and also recovers an uncertain issuance whose first response was lost. Replays return a safe receipt without the token. |
| `POST /api/owner/agents/:agentId/access-revoke` | Body `{operationId,expectedAccessRevision}`; globally fences current agent credentials/grants and writes a pending cancellation intent. Coordinator delivery is not implemented by this package. |
| `GET /api/agent/preflight` | Requires `Authorization: Bearer ...`, `X-Agent-Id`, and `X-Agent-Resource`; validates the fixed agent/resource binding and returns current policy. Preflight is free but grants no action permission. |
| `POST /api/agent/mcp` | Official SDK stateless HTTP handler, protocol `2026-07-28`, legacy rejected. The bounded `identity.preflight` tool accepts `{agentId,operationId}`; both manual and OAuth credentials resolve through the same current grant/policy verifier. |
| `GET /api/admin/invitations` | Lists invitations issued by the configured administrator, without verifier material. |
| `POST /api/admin/invitations` | Body `{operationId,expiresAt?}`; returns a new one-time `secret`. Only its SHA-256 verifier is persisted. |
| `POST /api/admin/invitations/:id/revoke` | Body `{operationId}`; revokes an unused invitation. |
| `GET /api/admin/registration-policy` | Returns `{mode,revision,updatedAt}`. |
| `PUT /api/admin/registration-policy` | Body `{mode,expectedRevision,operationId?}`; optimistic revision update, returning `{mode,revision,updatedAt}`. |

Application mutations require a same-origin `Origin` matching `OID_PUBLIC_ORIGIN`; Better Auth separately enforces trusted origin and OAuth state. Session cookies are HttpOnly, SameSite=Lax, Secure in production. There are no owner/admin headers or public test-auth routes. Errors use `{error:{code,message}}`; known conflict codes include `INVITATION_INVALID`, `INVITATION_EXPIRED`, `INVITATION_REVOKED`, `INVITATION_CONSUMED`, `IDENTITY_ALREADY_LINKED`, `POLICY_REVISION_CONFLICT`, `UNAUTHORIZED`, `FORBIDDEN`, and `RATE_LIMITED`.

## Persistence and boundary

The MCP endpoint accepts header credentials without a browser Origin; when an
Origin is present it must match the configured public origin. Exact host and
JSON content-type checks apply, with a 64 KiB request limit. Other application
mutations retain their owner-origin requirement. The OAuth provider's internal
continue/consent endpoints are closed to direct public calls; the owner-bound
wrappers validate the signed request, selected agent, session and policy revision.

OAuth selection stores a pending authorization without an access grant. Explicit
approval creates the grant and decision audit together; denial creates no grant.
The provider owns code/PKCE consumption and signed access-token issuance. Safe
code fingerprints correlate exchange audits; raw codes and tokens are omitted.
Protected requests verify the JWT and then load the current database grant,
owner admission, agent access generation and policy, so a token's remaining
lifetime cannot bypass a committed revoke. Client registration and resource
records are deployment-managed; no remote metadata fetch or dynamic client
registration is enabled in this local profile.

`migrate` creates Better Auth's user/session/account/verification/wallet-address tables plus `oid_owner`, `oid_identity`, `oid_invitation`, `oid_admission`, `oid_invitation_redemption`, `oid_registration_policy`, `oid_siwe_challenge`, `oid_auth_flow`, `oid_google_link_state`, `oid_rate_limit`, `oid_agent_access_grant`, `oid_agent_manual_credential`, `oid_agent_cancellation_outbox`, and `oid_audit`. Manual credentials store only a SHA-256 verifier for a 256-bit random token; operation receipts and audit metadata retain safe IDs and status, never token plaintext or verifier hashes. Credential replacement increments the optimistic access revision and revokes its predecessor. Global revoke increments the generation, revokes every current grant, and creates a cancellation outbox item constrained to `pending`; it does not claim coordinator delivery or run cancellation. A globally revoked agent needs a separate future owner reauthorization flow before a new credential can be issued. The acceptance observer should use a separate read-only database role.

This package is an identity/admission reference implementation. A green local provider fixture or SIWE test proves the declared local contract only. It does not prove production Google configuration, mainnet behavior, funding/ledger effects, or production readiness.
