# Manual credential implementation profile

Pinned for the approved manual-credential slice on 2026-10-25. These are
engineering configuration choices within the approved scope, separate from
actual OAuth/MCP/client compatibility. Existing AAP assertions are unchanged.

| Parameter | Pinned profile |
| --- | --- |
| Runtime | Existing Docker Node 24.22.1, Fastify 5.12.7, Better Auth 1.7.12 and PostgreSQL stack; no new auth SDK |
| Credential | Opaque `aap1_` prefix plus 32 cryptographically random bytes encoded base64url; only verifier persists |
| Lifetime | 86400 seconds by default; configurable/requested lifetime constrained to 300–2592000 seconds |
| Resource | Exact configured `OID_PUBLIC_ORIGIN` plus `/api/agent`; local acceptance uses `http://127.0.0.1:3000/api/agent` |
| Header preflight | `GET /api/agent/preflight`, Bearer header, matching `X-Agent-Id` and `X-Agent-Resource`; browser cookies alone confer no agent authority |
| Role | Fixed `agent`; no owner, withdrawal, recovery or arbitrary caller-scope delegation |
| Revision | Owner issue/replace/revoke requires expected access revision; mutations serialize on immutable agent row |
| Retry | Same issuance operation returns safe receipt without plaintext; a lost response is recovered by safe status and explicit replacement |
| Replacement | Creates new manual authority and fences predecessor; cannot replace after global revoke |
| Global revoke | Fences all current grants/credentials and records durable pending cancellation intent; actual coordinator delivery is unavailable |
| Owner credential throttle | `OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX=30` per IP per configured rate window, including status/issue/replace/revoke |
| Preflight throttle | `OID_AGENT_PREFLIGHT_RATE_LIMIT_MAX=60` per IP before authentication and per resolved credential/IP after authentication |
| Rate window | Existing `OID_RATE_LIMIT_WINDOW_SECONDS=60` by default; changing it changes the above window lengths |

Reauthorization after global revoke requires a later explicit authorization
path; the current slice returns `REAUTHORIZATION_REQUIRED` and does not revive
old authority. Natural expiry is not a global revoke or a run cancellation.
An idempotent replay describes the original operation; its safe status fields
may be historical after a later replacement/revoke. Current state comes from
the canonical status endpoint, which the owner UI refreshes before allowing
another mutation. An old receipt never creates new bearer authority.
Numerical throttles are bounded in server configuration. No price, source balance or paid action
authority is introduced by the free preflight.

This profile does not select a public MCP edition, SDK protocol negotiation,
OAuth discovery/registration strategy or actual Claude/Codex/OpenClaw/Hermes
edition. Those require their own feasibility and compatibility evidence before
their implementation/acceptance claims. Missing domain/lifecycle/client
boundaries remain blocked.
