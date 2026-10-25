# Owner identity and pilot admission API

This package owns the Fastify API, Better Auth session/provider integration, owner identity projection, invite redemption, registration policy, SIWE wallet linking, and durable audit records. All application state is in the configured PostgreSQL database. It does not implement pilot funding, ledger posting, or agent handlers; those remain separate acceptance gates.

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
| `GET /api/owner` | Verified owner, admission status, admin display hint, identities, and policy revision. Returns `401` without a session. |
| `POST /api/admission/activate` | Body `{invitation?,operationId}`; consumes an invite atomically in closed mode, or admits under current open policy. |
| `POST /api/owner/links/siwe/nonce` | Body `{operationId}`; issues a 15-minute owner/session-bound linking nonce. |
| `POST /api/owner/links/siwe/verify` | Body `{operationId,message,signature}`; verifies the EOA proof and commits the identity association. |
| `GET /api/admin/invitations` | Lists invitations issued by the configured administrator, without verifier material. |
| `POST /api/admin/invitations` | Body `{operationId,expiresAt?}`; returns a new one-time `secret`. Only its SHA-256 verifier is persisted. |
| `POST /api/admin/invitations/:id/revoke` | Body `{operationId}`; revokes an unused invitation. |
| `GET /api/admin/registration-policy` | Returns `{mode,revision,updatedAt}`. |
| `PUT /api/admin/registration-policy` | Body `{mode,expectedRevision,operationId?}`; optimistic revision update, returning `{mode,revision,updatedAt}`. |

Application mutations require a same-origin `Origin` matching `OID_PUBLIC_ORIGIN`; Better Auth separately enforces trusted origin and OAuth state. Session cookies are HttpOnly, SameSite=Lax, Secure in production. There are no owner/admin headers or public test-auth routes. Errors use `{error:{code,message}}`; known conflict codes include `INVITATION_INVALID`, `INVITATION_EXPIRED`, `INVITATION_REVOKED`, `INVITATION_CONSUMED`, `IDENTITY_ALREADY_LINKED`, `POLICY_REVISION_CONFLICT`, `UNAUTHORIZED`, `FORBIDDEN`, and `RATE_LIMITED`.

## Persistence and boundary

`migrate` creates Better Auth's user/session/account/verification/wallet-address tables plus `oid_owner`, `oid_identity`, `oid_invitation`, `oid_admission`, `oid_invitation_redemption`, `oid_registration_policy`, `oid_siwe_challenge`, `oid_auth_flow`, `oid_google_link_state`, `oid_rate_limit`, and `oid_audit`. Invitation verifier values and OAuth state/flow values are one-way digests; SIWE nonce values are hashed. Auth flows expose a random `operationId` in provider initiation responses, retain only purpose/provider/session and opaque HMAC context, and record succeeded/failed audit events. Audit rows omit invitation secrets, OAuth state/code, provider tokens, signatures, and cookies. The acceptance observer should use a separate read-only database role.

This package is an identity/admission reference implementation. A green local provider fixture or SIWE test proves the declared local contract only. It does not prove production Google configuration, mainnet behavior, funding/ledger effects, or production readiness.
