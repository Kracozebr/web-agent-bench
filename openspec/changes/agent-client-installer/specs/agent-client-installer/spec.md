# Agent client remote MCP connection and durable handoff

Status: revised planning proposal; updated BDD assertions await explicit approval. Runtime for all 8 scenarios: not_run. [Design](../../design.md), [BDD packet](../../bdd-design.md), [revision record](../../approval.md).

## ADDED Requirements

### Requirement: ACI-REQ-001 Connect through remote MCP without a platform installer
The platform SHALL expose one canonical HTTPS remote MCP endpoint for its released agent tools. The ordinary participant connection SHALL NOT require downloading or executing a platform installer, SDK, bridge, or local process, and the platform SHALL NOT write to client configuration files. When a selected client provides an official add/import link, the platform MAY open that client’s native setup with the canonical endpoint prefilled. Otherwise it SHALL show the remote endpoint and concise client-native setup instructions. The link and setup text SHALL contain no bearer/refresh token, authorization code, provider key, private benchmark input, or withdrawal material. A client without remote MCP support SHALL receive a clear unsupported reason, not an unreviewed helper download.

Scenario setup: An owner has a supported remote MCP client or another MCP client and is signed into the benchmark account

#### Scenario: ACI-SC-001 Add the canonical remote MCP endpoint without local platform software
- **WHEN** the owner connects a named client with a native add link, a client requiring manual URL setup, or a client with no remote MCP capability, including an invalid or substituted endpoint attempt
- **THEN** the selected client SHALL receive only the canonical HTTPS endpoint through its official native flow or clear URL instructions; the platform SHALL download or execute no local code, write no client files, expose no credential in links/prompts, and SHALL report unsupported clients honestly without claiming a connection

### Requirement: ACI-REQ-002 Authorize the verified owner and selected agent
Remote MCP authorization SHALL use the approved browser-mediated OAuth authorization-code flow with PKCE, state, exact callback and resource binding, and a grant scoped to the verified owner, selected agent, and client connection. The consent surface SHALL show selected business permissions and limits; no business permission SHALL be enabled by connection alone. The platform SHALL NOT collect model-provider credentials or expose platform credentials in URLs, prompts, config plaintext, logs, screenshots, or evidence. An explicitly enabled AAP manual credential route remains an advanced alternative and is not the default onboarding path.

Scenario setup: A client has the canonical endpoint and a verified owner with an existing agent

#### Scenario: ACI-SC-002 Consent creates only the selected owner-agent connection grant
- **WHEN** the owner authorizes or denies the client and callback substitution, wrong resource, wrong state, replayed code, foreign agent, or an unapproved redirect is attempted
- **THEN** only valid consent SHALL create one grant bound to that owner, agent, client, and MCP resource with the displayed permissions; denied or mismatched flows SHALL create no usable credential or domain effect, and no provider secret or platform credential SHALL appear in a URL, prompt, client setup text, or retained evidence

### Requirement: ACI-REQ-003 Refresh a connection until revocation
The ordinary OAuth connection SHALL use bounded short-lived access tokens and rotated refresh credentials and SHALL renew without scheduled user-facing 24-hour reauthorization while the grant remains valid. Refresh SHALL preserve owner, agent, client, resource, permission, and cap bindings and SHALL NOT mint an owner session or increase authorization.

Scenario setup: An authorized persisted remote MCP grant with short-lived access and refresh credentials

#### Scenario: ACI-SC-003 Refresh remains bounded and recovers safely
- **WHEN** access expires, the client reconnects after offline time, or concurrent refresh retries occur around response loss or server/client restart
- **THEN** the same connection SHALL renew through a bounded idempotent retry and rotation policy; replay outside that policy SHALL revoke the affected token family and require explicit reauthorization without changing permissions, caps, runs, or charges

### Requirement: ACI-REQ-004 Separate connection revocation from agent-wide revocation and restore
Revoking or replacing one client connection SHALL invalidate only that grant and refresh family without revoking another connection or cancelling the agent’s already-admitted work. Ordinary disconnect SHALL change connectivity only. Explicit agent-wide owner revocation SHALL follow AAP cancellation and generation-fencing authority. Restored checkpoints predating revocation or rotation SHALL remain write-disabled until trusted invalidation state is reconciled; if it cannot be proven, restored connection grants SHALL be invalidated and require owner reauthorization.

Scenario setup: Two client connections on one agent, active/queued work, and a checkpoint predating revocation or refresh rotation

#### Scenario: ACI-SC-004 Revoke the intended scope and never revive restored credentials
- **WHEN** the owner disconnects, replaces one connection, revokes that connection, or revokes the whole agent during refresh/tool use and then an old checkpoint is restored
- **THEN** only the selected grant SHALL be denied after connection revocation while the other connection and admitted run remain authorized; agent-wide revocation SHALL fence only that agent under AAP rules; and restored stale credentials SHALL remain denied before write-enable without duplicate business effects

### Requirement: ACI-REQ-005 Negotiate protocol and required capabilities without exact client-version gates
The server SHALL negotiate only declared MCP protocol revisions and SHALL check the actual remote transport, authorization, and required tool/schema capabilities. The initial compatibility profile SHALL cover MCP revisions 2025-06-18 and 2026-07-28. A reported client name, edition, or version SHALL be observational metadata, never authentication or an exact-version allowlist. A client SHALL NOT be rejected only because its application version is new or differs from a recorded version. Unsupported protocol or missing required capability SHALL produce a safe actionable reason before domain effects; metadata or protocol labels SHALL NOT be rewritten to bypass checks.

Scenario setup: Two application versions that provide the same required MCP capabilities and a client profile missing a required capability

#### Scenario: ACI-SC-005 Compatible versions connect and missing capabilities fail closed
- **WHEN** clients initialize using either declared protocol revision, change their application version while retaining required capabilities, omit a required transport/tool/schema behavior, or spoof client metadata
- **THEN** capable clients SHALL complete schema-valid preflight without exact application-version equality; incapable clients SHALL receive a specific incompatibility reason before any grant expansion, run, or financial effect; and spoofed metadata SHALL NOT change authority

### Requirement: ACI-REQ-006 Derive identity and show actual connection health
A free preflight SHALL derive owner and agent identity from the authenticated grant and prove actual native remote MCP access without starting or charging a run. Health SHALL distinguish configured, authorized, last successful preflight, offline, revoked, and executor-unready. Client-supplied identity hints and a server-only self-test SHALL NOT establish a native connection.

Scenario setup: An owner-authorized native remote MCP client with available, missing, revoked, or unreachable tools

#### Scenario: ACI-SC-006 Preflight proves native access without benchmark effects
- **WHEN** the owner connects or checks status while tools are absent, authorization is revoked, the backend is unreachable, or the executor is unready
- **THEN** only an actual authenticated client preflight SHALL establish the timestamped connection state and safe identity; the UI SHALL distinguish the observed failure/readiness state, and preflight SHALL create no run, queue slot, task action, reservation, charge, or public card

### Requirement: ACI-REQ-007 Launch Training or Ranked without copying identifiers
After setup and explicit mode permission, a browser Training or Ranked start SHALL create one owner-bound launch intent and open or otherwise deliver a ready request to the selected connected client without requiring the owner to copy an intent identifier. Pending intent creation, waiting, and free preflight SHALL NOT create a run, queue slot, reservation, charge, or execution timer. The repeat path target is one site start action plus one native Send/Run action when the client requires it; setup, manual URL fallback, and native approval steps SHALL be counted separately. The agent SHALL accept through its authenticated MCP grant and the existing BRL admission path.

Scenario setup: A connected agent with mode permission, a valid displayed quote, and an owner-started browser handoff

#### Scenario: ACI-SC-007 One launch intent reaches only its selected agent and admits once
- **WHEN** the owner starts Training or Ranked, opens the selected client, and sends the ready request, including double-click, stale quote, sleeping client, wrong account, response loss, or owner cancellation
- **THEN** the matching authorized agent SHALL accept one unchanged intent or leave it visibly pending; stale, foreign, cancelled, expired, or unapproved requests SHALL create no admission effect; and retries SHALL recover at most one normally admitted run and charge under BRL rules

### Requirement: ACI-REQ-008 Support an open MCP client set and qualify versions as metadata
The service SHALL accept any client that authenticates and passes the declared remote MCP capability preflight, without an exact application-version allowlist. The named target surfaces are Codex Desktop, Codex CLI, Claude Desktop, Claude Code, OpenClaw, OpenCode, Hermes, KiloCode, Cline, and Goose; this list is non-exclusive. Before a named surface is labelled client-family-qualified, one actual native connection, preflight, and launch-handoff smoke SHALL be evidenced at an available representative edition/version. Beta MAY launch with a verified subset of the named targets; every unverified target SHALL be identified as unverified and excluded from the supported-client claim until its smoke is complete. Client versions and protocols SHALL be retained as evidence metadata; a new client version SHALL remain eligible when it passes the same live capability contract. Missing client access or unobserved paths SHALL be unverified/blocked for that surface, never passed by an SDK-only client or reference worker. This requirement does not demand rerunning full Training and Ranked benchmarks for every client patch.

Scenario setup: A frozen beta support subset drawn from the named target surfaces, with some target surfaces available and others unavailable, plus at least one additional MCP client not in the list

#### Scenario: ACI-SC-008 Named clients qualify once and new compatible versions remain eligible
- **WHEN** each surface in the claimed beta support subset performs native connect, free preflight, and launch handoff at a representative version, other named surfaces are unavailable or not selected for beta, an unlisted MCP client performs the same capability check, or a new version arrives with unchanged or changed required capabilities
- **THEN** actual observations SHALL qualify only exercised client surfaces; beta MAY launch with that verified subset if all other named targets are visibly marked unverified and excluded from its support claim; the unlisted client and new versions SHALL connect when they pass the same authenticated capability contract; missing capabilities SHALL fail with a specific reason; and no client SHALL be blocked solely by a version change or counted as qualified without native evidence
