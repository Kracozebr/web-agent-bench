# Isolated OID PostgreSQL

This local acceptance database is separate from BEF and contains no real provider
credentials or customer funds. PostgreSQL 18.6 uses the same pinned image digest
as the reviewed BEF stack. It binds only to `127.0.0.1:55433` by default.

From the repository root in PowerShell:

```powershell
./infrastructure/owner-identity/bootstrap.ps1
docker compose -f infrastructure/owner-identity/compose.yaml up -d --wait
```

Bootstrap retains or generates random secrets under ignored
`.local/owner-identity/secrets/`; it prints no secret values. Set
`OID_DATABASE_HOST_PORT` for Compose and pass the same `-DatabasePort` to
bootstrap when changing the port. The generated URL files support local
application migration and independent outcome inspection.

The `oid_owner` role owns the local application schema. The separate
`oid_observer` role has SELECT on future public tables created by that owner,
no table-write grants, and `default_transaction_read_only=on`. The acceptance
observer must use that separate role, rather than read application responses as
proof of a commit. These grants are installed only on a fresh Compose volume;
existing volumes are retained across restart.

Stop without deleting evidence or database state:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml down
```

All application tooling runs in Docker, as requested by the owner on 2026-10-25.
Do not use the quarantined Windows pnpm launcher or create antivirus exclusions.
Build the pinned Node 24 / pnpm 11.25.0 image with Chromium and Python BDD:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml build runtime
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity migrate
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-identity check
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
```

`tool.ps1` only forwards arguments to Docker. The source checkout is bind-mounted
at `/workspace`; each package and the workspace root use separate Linux dependency
volumes. Secrets are read inside the container and are not stored in the image.
Rebuild the image and run container `pnpm install --frozen-lockfile` if dependency
manifests or the lockfile change while volumes already exist.

Start API and UI together after migration:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml run --rm --service-ports -e OID_API_HOST=0.0.0.0 runtime node infrastructure/owner-identity/dev-stack.mjs
```

Open `http://127.0.0.1:3000`. Google is disabled until configured. The public
origin and callback host must match; an external provider is not simulated by
the development startup. The actual API verifies configured EOA wallet proofs.
Closed admission still needs an invitation; first signup does not grant admin.

The acceptance runner owns its isolated local provider transport and browser/API/web
children inside a single container. It uses the production Next build:

```powershell
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change owner-identity-and-pilot-admission
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance replay -- all
```

Keep the acceptance database for synthetic identities only. The runner may seed
private fixtures and expiry/recovery state; initiating business actions must go
through real browser controls. Read-only replay must not reissue sign-in,
invitations or admission. Missing downstream services and the separate actual
Google/browser-wallet gate remain blocked, preventing sync/archive. See the
owner-acceptance package for the evidence boundary. Database startup alone is
not authentication or browser E2E evidence.

The manual agent-credential profile uses `OID_MANUAL_CREDENTIAL_TTL_SECONDS`
(default 86400; supported 300–2592000 seconds),
`OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX` (30 requests/IP/window), and
`OID_AGENT_PREFLIGHT_RATE_LIMIT_MAX` (60 requests/IP/window, also enforced per
resolved credential/IP). The existing rate window defaults to 60 seconds.
The Compose runtime passes these nonsecret configuration variables through.
Credentials are bound to the configured public origin plus `/api/agent`.
Issuance plaintext is never part of the image, secret files or evidence.
See the approved change's [configuration profile](../../openspec/changes/agent-access-and-permissions/configuration.md).

The browser OAuth/MCP slice pins Better Auth plugins 1.7.12 and official MCP SDK
2.4.0 with modern protocol `2026-07-28`. Compose passes
`OID_MCP_CLIENT_ID` and `OID_MCP_CLIENT_REDIRECT_URI`; its local defaults are
`oid-local-mcp-client` and `http://127.0.0.1:38765/oauth/callback`.
That callback belongs to a separate client listener, not the Next.js app.
Only the configured preregistered public client is enabled; dynamic registration
and remote client metadata are disabled. The connection endpoint is
`http://127.0.0.1:3000/api/agent/mcp`. The acceptance runner owns the isolated
loopback client listener and never writes its code, PKCE verifier or token to
evidence. See [the pinned OAuth profile](../../openspec/changes/agent-access-and-permissions/oauth-profile.md)
for the exact resource, scope, lifetimes and compatibility boundary.
