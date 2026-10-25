# Owner web

Next.js owner identity, pilot admission and private agent-card UI. All sign-in, activation, identity-linking,
invitation, registration-policy, card and permission-setting mutations go to the Fastify API. There is no demo auth or
browser-persisted success state.

## Local development

Use the repository's [Docker runtime](../../infrastructure/owner-identity/README.md)
from the repository root. Application tooling runs inside the container:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml run --rm --service-ports -e OID_API_HOST=0.0.0.0 runtime node infrastructure/owner-identity/dev-stack.mjs
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). Keep this hostname for sign-in and callback URLs. Next.js proxies browser requests under
`/api/*` to the configured API origin, so browser cookies and OAuth redirects remain same-origin.
`OID_API_URL` is server-only and must be an origin such as `http://127.0.0.1:8784`.
Configure the API's `OID_PUBLIC_ORIGIN` as `http://127.0.0.1:3000` for the local browser flow.

The Google flow uses Better Auth's provider callback. Wallet authentication asks the selected
injected EIP-1193 provider to sign a purpose-bound SIWE message; the API verifies the signed
message and nonce. Only the server's owner projection determines admission and administrator
access. An invitation value is held in the page only while the activation form is open, and an
issued invitation secret is displayed once in memory after the API confirms issuance.

The page labels local provider fixtures as local evidence when the API provides that environment
label. A local fixture does not establish actual Google compatibility or universal wallet support.

## Commands

- `./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web check` checks TypeScript inside Docker.
- `./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build` creates the production Next.js build inside Docker.
