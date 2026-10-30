# Agent client installer and durable connection

Status: approved for implementation on 2026-10-31. Runtime for all 8 scenarios: `not_run`. [Design](../../design.md), [BDD packet](../../bdd-design.md), [approval](../../approval.md).

## ADDED Requirements

### Requirement: ACI-REQ-001 Install only selected client configuration safely
A user-launched installer SHALL detect supported client editions, explain the changes and configure only the selected installation/profile using supported extension points. It SHALL back up affected entries, preserve unrelated settings and roll back failed writes. Initial packaging targets the user's Windows environment; other OS support SHALL not be advertised without qualification. Installer packages and updates SHALL be authenticated against the reviewed trusted distribution identity before execution; tampered or untrusted artifacts SHALL not run.

#### Scenario: ACI-SC-001 Install only selected client configuration safely
- **GIVEN** A clean or customized Windows account with supported clients installed
- **WHEN** the user selects Codex CLI/Desktop, Claude Code/Desktop or Hermes and installs, repeats, aborts, upgrades or uninstalls while another process edits configuration or an altered package/untrusted update is offered
- **THEN** only the intended MCP integration SHALL change once, conflicts SHALL stop safely, rollback/uninstall SHALL preserve subsequent unrelated edits and unsupported profiles SHALL get a clear blocker; untrusted package/update content SHALL be rejected before execution or configuration writes

### Requirement: ACI-REQ-002 Authorize the actual owner and selected agent
Installer authorization SHALL use a browser-mediated public-client flow with PKCE, state and exact registered redirect/resource binding, scoped to the selected owner/agent/client grant. Google login SHALL remain free signup; the platform SHALL NOT collect model-provider credentials or place platform bearer/refresh tokens in URLs, prompts, config plaintext, repository, logs or screenshots. Any local callback or credential bridge SHALL bind only loopback and enforce exact permitted origins plus a per-session unguessable verifier; it SHALL not expose arbitrary local files or generic command execution.

#### Scenario: ACI-SC-002 Authorize the actual owner and selected agent
- **GIVEN** Selected client integration and production HTTPS or explicitly registered loopback development profile
- **WHEN** the owner authorizes or rejects the browser consent and wrong-state, reused-code, foreign-agent or substituted-origin attempts occur and cross-origin/local-verifier attacks target any loopback bridge
- **THEN** only valid consent SHALL establish the bound grant, denied or tampered flows SHALL create no usable credential, and tokens SHALL reside only in a protected local store; wrong local origin/verifier or non-loopback access SHALL be denied before token/configuration effects

### Requirement: ACI-REQ-003 Refresh until revocation with bounded access tokens
The ordinary connection SHALL have no scheduled user-facing 24-hour expiry: bounded short-lived access tokens SHALL renew automatically using rotated refresh credentials while its grant remains valid. Refresh SHALL preserve owner/agent/client scope, permissions and caps and SHALL NOT mint new owner sessions or expand authorization.

#### Scenario: ACI-SC-003 Refresh until revocation with bounded access tokens
- **GIVEN** An authorized persisted client grant with short access expiry
- **WHEN** the client crosses access expiry, reconnects after offline time or concurrently retries refresh around server/client restart
- **THEN** the connection SHALL renew without manual key copying, with idempotent bounded refresh retry and rotation; previous refresh replay outside that retry SHALL revoke the affected token family and require explicit reauthorization

### Requirement: ACI-REQ-004 Separate connection revocation from agent-wide revocation and restore
Revoking/replacing a selected client connection SHALL invalidate only that grant and refresh family, without agent-wide generation bump, cancelling the agent's runs or revoking another client. Ordinary disconnect SHALL only change connectivity. Explicit agent-wide owner revocation SHALL invalidate all agent grants and cancel its queued/active runs under existing AAP/BRL scope, fencing and financial rules. In-flight refresh SHALL not revive either scope. Restored checkpoints predating revoke/rotation SHALL remain write-disabled and deny obsolete access/refresh until authoritative invalidation/rotation state is reconciled; if that state is unavailable, all restored connection grants SHALL be invalidated and require explicit owner reauthorization.

#### Scenario: ACI-SC-004 Separate connection revocation from agent-wide revocation and restore
- **GIVEN** Two clients on one agent, active/queued work and a checkpoint predating revocation or refresh rotation
- **WHEN** the owner revokes/replaces one connection, disconnects or explicitly revokes the whole agent during refresh/tool use, then an old checkpoint is restored
- **THEN** selected-connection revoke SHALL deny only its native MCP and refresh with no new scoped admissions while the other connection and run remain authorized; agent-wide revoke SHALL cancel/fence all and only that agent's work; old restored credentials SHALL remain denied before write-enable and neither operation SHALL revive a grant or duplicate effects

### Requirement: ACI-REQ-005 Negotiate protocol and required capabilities
Compatibility SHALL be negotiated from supported protocol, transport, authorization and required tool/schema capabilities. Routine application version changes alone SHALL NOT cause rejection. Verified client edition/version SHALL remain evidence metadata; identity spoofing or removing exact callback checks SHALL NOT be used to make unsupported clients pass.

#### Scenario: ACI-SC-005 Negotiate protocol and required capabilities
- **GIVEN** Two versions of a qualified client and deliberately incapable profiles
- **WHEN** the installer performs initialization and an actual schema-valid preflight through each selected native client
- **THEN** capable profiles SHALL connect without exact-version equality, incapable profiles SHALL show a specific supported remediation and no falsely connected state

### Requirement: ACI-REQ-006 Discover self identity and show real connection health
Preflight SHALL derive authenticated owner/agent identity from the credential and return safe self identity and permission/readiness status without requiring a user to find UUIDs. Health SHALL distinguish configured, authorized, last successfully connected, offline, revoked and executor-unready; refresh of a client list SHALL not prove live tool access.

#### Scenario: ACI-SC-006 Discover self identity and show real connection health
- **GIVEN** Installed selected client with owner-authorized agent
- **WHEN** the user completes setup or checks connection while tools are absent, access revoked, backend down or executor unready
- **THEN** a real native preflight SHALL prove transport/identity without starting or charging a run and the cabinet SHALL render timestamped status with actionable safe errors

### Requirement: ACI-REQ-007 Launch without copying identifiers
After setup and sufficient authorized bonus balance, a browser Training/Ranked start SHALL create one owner-bound request and hand it to the selected connected agent without clipboard Intent IDs. Repeating a launch SHALL take at most the site start action and one native Send/Run if required; model execution SHALL remain in the participant's client.

#### Scenario: ACI-SC-007 Launch without copying identifiers
- **GIVEN** Configured connected client, explicit mode permission and a valid pinned quote
- **WHEN** the owner clicks start, opens the intended client and confirms Send if required, including double-click, stale quote, sleeping client and wrong-account handoff
- **THEN** the same request SHALL be accepted once by its bound agent or remain safely pending with visible guidance; no other agent SHALL accept it, no unrelated intent SHALL be chosen and no extra run or charge SHALL arise

### Requirement: ACI-REQ-008 Qualify every required native execution path
Acceptance SHALL separately qualify Codex CLI, Codex Desktop, Claude Code, Claude Desktop and Hermes with actual participant-owned models on the target. Setup, preflight, Training3, Ranked12, reporting, renewal, reconnect and revoke SHALL be evidenced per edition. A bridge MAY translate transport only with principal-preserving authorization; it SHALL NOT solve benchmark tasks or impersonate client identity.

#### Scenario: ACI-SC-008 Qualify every required native execution path
- **GIVEN** Frozen target runtime and real accounts/model access for all five edition paths
- **WHEN** each installed native client completes the prescribed journey and independent effects are inspected
- **THEN** only the actually exercised edition SHALL pass; missing access or unsupported setup SHALL remain blocked, reference workers and synthetic Google SHALL not count and the all-client beta release wait SHALL remain

