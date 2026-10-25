# Local browser OAuth and MCP profile

Pinned on 2026-10-25 for the approved AAP implementation. This profile covers
one preregistered local public client; it is not actual pilot-client compatibility.

| Parameter | Profile |
| --- | --- |
| Better Auth | Existing 1.7.12 plus `@better-auth/mcp` 1.7.12 and `@better-auth/oauth-provider` 1.7.12 |
| MCP SDK | Official split packages `@modelcontextprotocol/server` and `@modelcontextprotocol/client`, both 2.4.0 |
| Tool schema | Direct `zod` 4.6.7; exact transitive resolutions in `pnpm-lock.yaml` |
| Transport | Stateless HTTP POST, protocol `2026-07-28`, legacy profile rejected |
| SDK negotiation | Client `versionNegotiation.mode.pin = "2026-07-28"`; verify actual negotiated protocol/era, do not accept default legacy fallback |
| Local public client | `oid-local-mcp-client`, exact redirect `http://127.0.0.1:38765/oauth/callback`; an actual separate loopback client listener receives it |
| Client configuration | `OID_MCP_CLIENT_ID` and `OID_MCP_CLIENT_REDIRECT_URI`; explicit values required in production; this slice accepts only the pinned loopback callback shape |
| Registration | Deployment-managed preregistration; DCR disabled, CIMD/remote metadata fetching disabled |
| Grant | Authorization code with PKCE S256, explicit browser consent, fixed `agent:operate` delegation |
| Resource | Configured public origin plus `/api/agent`, shared with manual credentials |
| MCP endpoint | `/api/agent/mcp`; application protected-resource metadata points to the provider's authorization-server metadata |
| Owner UI | `/owner/agents/oauth-select` and `/owner/agents/oauth-consent`, existing admitted owner verifier, explicit selection of one existing owned agent |
| Lifetime | Authorization code 600 seconds; access token 3600 seconds; this slice does not request offline access/refresh grants |

Better Auth owns protocol code generation/consumption, PKCE, redirect/resource/
issuer verification and token issuance. The application owns the durable
consent-operation-to-owner/agent binding and checks current grant/access fence
and policy on protected operations. Selection must not use one mutable global
session agent value that can be overwritten by another browser tab.

The provider is composed once using `jwt()` and `mcp()`; a separate
`oauthProvider()` instance is not registered. Actual extension API choices are
recorded with the implementation before execution. Browser
and SDK acceptance keep authorization code, state, PKCE verifier, access token
and session cookies in process memory and omit them from evidence.

The released MCP tool in this slice is bounded free preflight. No fake paid
operation, run result or ledger receipt is added to satisfy SC015; that full
gate remains blocked until an actual permitted domain operation exists. All
actual Claude/Codex/OpenClaw/Hermes edition gates remain separate.

Primary references checked for this profile:
[Better Auth MCP](https://better-auth.com/docs/plugins/mcp),
[OAuth Provider](https://better-auth.com/docs/plugins/oauth-provider),
[official SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/), and
[MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
These describe library capabilities; local runtime evidence is recorded separately.
