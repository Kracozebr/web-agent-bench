## Context

The current proposal requires a user-launched Windows installer, selected local client configuration writes, and an optional local credential bridge. The owner’s current direction is a platform-hosted remote MCP endpoint, without a downloaded SDK, installer, or platform-run local process. The participant keeps the model and inference subscription in their existing harness. ACI owns connection onboarding, grant renewal, client capability negotiation, health, and handoff. AAP continues to own owner identity, permissions, credential authority, and revocation; BRL owns launch-intent admission and billing.

The ACI change identifier is retained for continuity, but its capability no longer includes an installer.

## Goals / Non-Goals

**Goals:**

- Connect through one public HTTPS Streamable HTTP MCP service.
- Avoid requiring local executable downloads or platform-written client configuration.
- Use explicit owner consent and renewable, agent-scoped authorization.
- Accept compatible MCP clients by protocol and capabilities, not an exact client application version.
- Offer an official native add/import link when a client has one, with an honest URL-based fallback.
- Keep connection status separate from permissions, executor readiness, and benchmark results.
- Let a connected agent accept one browser-started Training or Ranked intent without copying identifiers or creating a second run.

**Non-Goals:**

- Running or hosting the participant’s model.
- Collecting model-provider credentials or bypassing client approvals.
- Supporting clients that cannot connect to a remote MCP endpoint under the approved OAuth or advanced manual-credential route.
- Promising two actions for first-time account setup, client configuration without a native add link, or client-native approvals.
- Changing task, score, evidence, PvP, settlement, or existing quote and reservation rules.

## Decisions

### 1. One remote MCP service, no platform installer

The platform SHALL expose one canonical HTTPS MCP endpoint backed by the existing authorized domain operations. The ordinary path SHALL NOT ask a participant to download or execute a platform package, SDK, bridge, or shell command. The website SHALL NOT edit local client files.

Where a client publishes a native server-add link or import mechanism, the website may open that official client flow with the canonical endpoint prefilled. The link SHALL contain no bearer or refresh token, authorization code, model key, private task data, or withdrawal material. If no native link is verified, show the endpoint and concise instructions for adding a remote server in that client. That fallback is not a two-action setup.

A client that only supports local stdio and has no remote MCP option is outside this no-local-software path. Do not substitute an unreviewed helper.

**Alternative considered:** a signed installer or generated SDK could edit different client configurations, but would create a local code trust and update channel and preserve a client-by-client configuration/version matrix. It is rejected as the normal PoC entry path.

### 2. Browser authorization and scoped grants

Remote MCP authorization SHALL use the approved MCP OAuth authorization-code flow with PKCE, resource binding, exact callback validation, and the existing owner/agent consent boundary. Consent selects an existing owner-bound agent and shows the requested business permissions and limits. All business permissions remain disabled until the owner explicitly enables them. A connection or successful preflight does not enable Training or Ranked.

The client stores its own OAuth credentials through its supported credential handling. The platform does not install a local credential store. The platform SHALL NOT collect model-provider credentials or put its access/refresh token or authorization code in a URL, prompt, clipboard launch text, log, screenshot, or checked-in evidence.

The existing owner-issued manual credential route remains an advanced AAP route only where explicitly enabled. It is not the default and is excluded from the two-action claim because setup requires manual client configuration.

### 3. Capability-based compatibility

The client package name, edition, and reported version are observational metadata, not authentication or authorization. A change to a client version alone SHALL NOT reject a connection. Authentication is established by the scoped grant; protocol negotiation and actual preflight establish transport and required capability.

The compatibility profile SHALL publish a finite tested set of MCP protocol revisions and negotiate the revision offered by the client. The initial target includes the existing 2025-06-18 and 2026-07-28 handshake profiles so the observed Codex legacy transport and the current strict profile can be exercised without a Codex-version allowlist. A profile mismatch or unsupported required capability returns a safe, actionable incompatibility result before domain effects. Do not rewrite client metadata or protocol labels to make an unsupported request pass.

Required baseline behavior is remote Streamable HTTP, MCP initialization, tool discovery, and schema-valid tool calls for the declared benchmark tools. Any additional transport, auth-registration mode, or optional MCP capability must be named in the profile and verified at its actual boundary. Client-reported identity fields never replace OAuth authority.

Every run continues to retain agent/client/version and protocol observations required for comparison. These values describe the run; they are not version gates.

### 4. One-time connection and repeat launch

For an already signed-in owner and client with a native add link, the connection target is: website Connect, then client/authorization confirmation. Other clients show their extra native configuration steps. Owner login, agent creation, permission selection, model-provider login, client-native approval, and manual URL fallback are shown separately and excluded from the repeat-launch count.

After connection and explicit Training or Ranked permission, the repeat path is:

1. The owner selects the agent and mode on the site and sees the current benchmark version, price, funding source, task count, and result visibility.
2. Start creates a short-lived owner-bound launch intent. A pending intent is not a run, queue slot, reserve, or charge.
3. The site opens the selected client with a ready request containing only the service reference and non-authorizing launch ID. Where no app handoff exists, show Copy request and count the extra paste/send actions.
4. If required by the client, the owner presses Send/Run. The agent calls the authenticated MCP acceptance tool.
5. The server checks current owner/agent grant, permissions, unchanged quote/version, expiry, and idempotency, then uses the existing BRL admission path. Duplicate or lost-response retries recover the same intent/run. Stale quotes and mismatched clients remain pending or require review without a second run or charge.
6. The participant’s client executes the benchmark. The site shows pending, queued, preparing, running, and final state separately. Training feedback and Ranked evaluation retain their existing visibility and publication rules.

MCP does not make a browser click start a model turn in every harness. The native client remains in control of sending and any required tool approval.

### 5. Open client ecosystem and qualification

The first named compatibility targets are Codex Desktop, Codex CLI, Claude Desktop, Claude Code, OpenClaw, OpenCode, Hermes, KiloCode, Cline, and Goose. This list is non-exclusive. Any other client that authenticates and passes the declared live capability preflight may connect without being added to a fixed package-version allowlist.

Each named surface receives one actual connection, preflight, and launch-handoff smoke check at an available representative edition/version before being labelled client-family-qualified. Record the version and protocol in evidence; do not require requalification for every patch release unless the observed capabilities or behavior change. Beta may launch with a verified subset; unavailable or unselected target surfaces remain visibly unverified and outside the supported-client claim. A client with no real test remains unverified, not falsely qualified. Full Training/Ranked outcomes are evidence from actual participant runs and are not simulated by a client SDK test.

The site distinguishes connected and protocol-preflight-verified from client-family-qualified. Unknown client names or versions may pass if the authenticated native MCP behavior passes. A missing required capability gives a safe reason; version novelty alone does not.

### 6. Health, revocation, and recovery

Preflight derives owner and agent identity from the authenticated grant, optionally checks but never trusts a client-supplied identity hint, and proves remote tool access without starting or charging a run. Health distinguishes configured, authorized, last successful native preflight, offline, revoked, and executor-unready.

Keep disconnect, selected-connection revoke/replacement, and agent-wide revoke separate. A selected connection revoke invalidates only that grant and refresh family; agent-wide revoke follows existing AAP cancellation/fencing authority. Refresh preserves identity, permissions, and caps. A restored checkpoint cannot revive stale credentials: keep writes disabled until trusted invalidation state is reconciled, or invalidate restored grants and require reauthorization.

### Cross-change authority

- AAP owns verified owner, agent, consent, permission, credential, and revocation policy. Its approved local Codex 0.165.0 profile remains a local acceptance configuration; it is not the production client allowlist.
- BRL owns launch intent, quote, reservation, queue, billing, deadlines, and idempotent admission. ACI must not add a second admission or refund authority.
- PCU owns wording and page layout; ACI supplies connection and handoff state.
- Before implementation, reconcile the expanded named-client smoke set and the production MCP capability policy with active AAP/BRL deltas. Preserve their stable IDs and historical evidence; a changed assertion needs explicit reapproval.

### Evidence and replay

Capture actual browser initiation, actual selected client/harness, authenticated native MCP request, OAuth profile, negotiated protocol/capabilities, client version as metadata, and independently correlated PostgreSQL/BEF effects. A preflight producer counter alone is insufficient. A reference MCP client, synthetic model, or SDK-level probe may test a component but cannot establish a named native client’s compatibility or a participant benchmark result.

Store raw evidence paths and hashes and replay read-only. Do not retain tokens, model-provider secrets, private task inputs, or unredacted user data. Unknown or missing observations stay unknown, blocked, or not_run. Never repeat a business command to recreate evidence.

### Risks / Trade-offs

- A shared protocol removes per-client server implementations, but native add links, OAuth behavior, and approval surfaces still differ by harness. Use small link/instruction adapters and a clear URL fallback.
- A version-neutral policy can expose regressions after an upstream client update. Fail on actual missing protocol/capability behavior, keep versions as evidence, and repair the shared MCP profile instead of adding a new exact-version gate.
- A client may proxy remote MCP calls through its provider infrastructure. Do not claim the connection is local; show the known route or mark it unknown where the client does not disclose it.
- Open compatibility does not mean every MCP client is qualified. Keep connected, preflight-verified, and client-family-qualified states separate.

### Migration Plan

1. Reconcile the revised ACI requirements with AAP consent and the AAP-SC-016 actual-client evidence boundary, plus BRL launch handoff. Obtain explicit approval for the revised BDD assertions.
2. Freeze the server capability profile, supported protocol revisions, OAuth registration modes, and named native client smoke set based on available real clients. Do not add application-version allowlists.
3. Keep the current local Codex profile confined to its approved local acceptance boundary; it does not satisfy or define the remote production profile.
4. After approval, implement the remote endpoint and client onboarding, then add only the approved mirrors, mappers, contracts, and real adapters.
5. Preserve the unified backup/restore boundary for any new durable grant or launch-intent records. Rehearse restore with writes disabled and preserve revocation and once-only effects.
6. Qualify the shared MCP contract, named client smoke paths, and real browser-to-backend-to-database journeys separately. Missing client access remains blocked/unverified and does not become a passing SDK substitute.
7. Sync/archive only after the approved mandatory gates pass under docs/task-design.md. This planning revision does neither.

## Open Questions

The owner has decided that the ten named clients are targets, not a requirement to block beta until all ten are qualified. Beta may launch with the actually verified subset, while the remaining named surfaces stay visibly unverified and outside its support claim. Technical prerequisites remain: exact current client editions, availability and verified targets of native add links, OAuth registration behavior, finite protocol profile, and access to each client included in the beta support claim. If a client lacks remote MCP or the approved authorization path, report that specific limitation for an explicit scope decision rather than downloading an unreviewed bridge.
