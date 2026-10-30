## Context

Proposed 2026-10-30 from the owner-approved direction and local inspection. Participants currently copy credentials, identifiers and client commands across a long setup guide. The approved product direction is automatic client setup, participant-owned model execution, and a renewable connection until explicit revocation. Implementation and listed assertions were approved on 2026-10-31; evidence status changes only after actual verification.

## Goals / Non-Goals

**Goals:** Provide a user-launched installer that detects and configures the selected supported native client, with recoverable configuration edits. Use browser authorization, scoped renewable grants and secure local token storage; remove the manual 24-hour key from the ordinary path. Negotiate protocol and capabilities rather than matching an exact application version; qualify actual client paths. Deliver owner-authorized launch requests to the connected agent without copying Intent IDs and expose real connection status.

**Non-Goals:** Hosted model execution, model-provider credential custody, bypassing native consent, identity/version spoofing, silently changing unrelated client settings, automatic cap/permission increases, unqualified OS support and real-money authorization. All original beta target-host, Google, bonus, source-bound restore/recovery and native-client gates remain. No new code, Gherkin, mappers, registry entries, runtime profile or real-money actions are delivered by this draft.

## Decisions

### Installer and transport architecture

The deliverable is an actual user-launched installer, not another long copy/paste guide. Initial qualification targets Windows; supported editions are Codex CLI, Codex Desktop, Claude Code, Claude Desktop and Hermes. Detect actual supported integration points before choosing an implementation. Support may be native remote HTTP MCP+OAuth or a narrowly scoped local stdio/HTTP credential bridge when the host cannot store/refresh platform tokens itself. A bridge proxies authenticated tools only; the user's native model remains the solver. No client-name/version spoofing, platform reference solver or third-party provider-key collection is allowed.

For each edition, first record OS/config discovery, supported write surface or official import/deep-link, native authorization/refresh facilities, model access and restart requirement. If the host exposes no safe automatic setup path, mark that edition blocked and bring the concrete constraint to review; do not silently redefine automatic setup as manual instructions or remove that edition from beta prerequisites. Installer package/update authenticity and publisher verification must be selected before distribution; test tampered/truncated packages and untrusted update source refusal. Do not require system-wide elevated install by default. Bind any local callback/bridge to loopback, a per-session unguessable verifier and exact trusted origins; no broad local filesystem/API service.

### Authorization and storage

The installer requests browser owner consent for one selected agent and client connection. Existing selected-agent consent creates or reuses no unrelated profile; if there is no agent, the verified owner approves creating one through the existing owner-management boundary before delegation. Use PKCE, state, issuer/resource checks, exact redirect registration and least privilege. Automatic setup must not auto-opt-in Ranked permissions or increase bonus caps. Save opaque short-lived access and rotating refresh credentials in an OS-protected user store; config contains only a reference or bridge command, never plaintext secrets. Redact source paths or account identifiers in review evidence.

Connections remain renewable until explicit revoke or security invalidation, including long offline periods; refresh must revalidate the same principal, resource and permissions. No scheduled absolute grant expiry may force periodic normal-user re-login. Existing manual 24-hour grants are not silently extended: the owner explicitly migrates the selected connection through browser consent; old tokens remain scoped until replaced/revoked. Define rotation/retry grace and access-token duration in the profile before implementation assertion approval. Refresh response-loss recovery may use a bounded encrypted token response keyed to the same client operation, not an unlimited replay window. Do not store bearer/refresh/code material in chat, URL query, analytics, logs, screenshots or Git. A URI carrying a non-secret handoff reference must still be redeemed only by the bound principal.

### Handoff and health

Prefer an authenticated pending-request inbox for a listening native client or supported native open-composer/import link. Actual delivery choice is edition-specific, but payload/acceptance owner binding is common. Never poll by launching a second model or send without the client's required consent. Backend accepts only the matching agent and idempotent operation, with current permissions and unchanged existing quote/queue/debit rules. ACI owns delivery/consumption; PCU owns wording/layout. Preflight derives the principal and accepts an optional legacy agentId only as an equality-checked hint; old API behavior needs an explicit compatibility migration, not a guessed UUID.

Record separate configured, browser-authorized, native-preflight-success and executor-ready observations. A successful server self-test is not a native connection. Revocation checks must prove actual upstream 401 plus WWW-Authenticate and zero admitted tool invocations, including reconnect and refresh races.

Connection disconnect, selected-connection revoke/replacement and explicit agent-wide revoke are distinct commands. The first preserves grant and task deadlines; the second invalidates only that connection's grant/refresh family and leaves other connections and admitted runs intact; the third follows AAP-REQ-006 cancellation and generation-fencing for all and only this agent. Prove the distinction with two clients sharing one agent. Revoked grant effects remain inaccessible even if another legitimate connection may continue that agent's run.

A restored older checkpoint cannot authorize current traffic from stale grants or rotated refresh families. Keep restored writes disabled and reconcile a trustworthy revocation/rotation watermark before serving credentials; if post-checkpoint invalidation state cannot be proven, invalidate all restored connection grants and require owner reauthorization. This is a restore-only security fallback, not scheduled normal-user expiry. The ACI-SC-004 negative explicitly proves old access/refresh denial before write-enable. Package/update verification and local bridge origin/verifier denial are mandatory in ACI-SC-001/002, not design-only assertions.

### Cross-change authority

Owns installer, refresh lifecycle, native client handoff and connection health. Existing agent-access-and-permissions (AAP), owner-identity-and-pilot-admission (OID), BRL and BPC remain authoritative for owner/agent binding, permission checks and run admission.

Can be designed in parallel with execution repair; its real-client acceptance requires BER correctness. The cabinet consumes connection and launch status; public pages link to the installer.

The [integration index](../../../docs/beta-usability-spec-plan.md) lists active-delta overlap and the approval-time reconciliation. These new drafts do not supersede approved active requirements merely because they are newer. Before implementation, record exact affected legacy requirement/scenario mappings and approve coherent amendments to those active deltas; keep IDs and prior evidence history. No sync/archive is authorized here.

### Evidence and replay

Every scenario uses its real boundary in [bdd-harness-proposal.json](bdd-harness-proposal.json), with named observations, negative variants and durable effects. Runtime evidence carries frozen source/build/profile, sanitized principal/run/operation identifiers, authoritative event order, raw artifact paths and hashes, and independent observer identity. User journeys start through actual browser controls, follow running API/worker and persist in PostgreSQL; independently inspect final database/BEF/filesystem effects. Installer scenarios require actual native configuration and model client boundaries, not browser mocks. Private setup/fault injection and read-only inspection are permitted only for their named roles. Never retain credentials, sensitive provider data or raw personal identities in checked-in evidence.

Replays are read-only and never repeat economic commands. A missing external client, host, observer or unexecuted negative is `blocked` or `not_run`, not a green reference-model substitute. Planning validation checks structure, not runtime acceptance.

## Risks / Trade-offs

- Active-delta overlap can create two authorities: use the integration index and approval-time reconciliation before any apply.
- Local success can hide target/client gaps: retain separate per-edition and target-host mandatory gates.
- Readable UX can overstate certainty: display only durable known facts and preserve unknown attribution.
- New adapters can expose secrets: use secret references, protected stores and synthetic canaries, with no raw secret evidence.

## Migration Plan

1. Review this packet and all cross-change mappings; obtain explicit scenario/assertion and implementation approval.
2. Add only approved mirrors, mappers and real adapters in a later apply; keep all current runtime gates unchanged until rerun.
3. Prepare compatible migrations/config changes with an existing unified pre-migration backup of bonuses, results, reports, screenshots and evidence. Rehearse restore with writes disabled, original identities and retries preserved.
4. Qualify locally on frozen source, independently replay, then repeat required target/client gates before release. Missing host/domain or client access blocks that gate, not documentation work.
5. Roll back via disabled feature/profile and scoped configuration restoration without erasing journals, original evidence, account/ledger/report data or unobserved effects. Preserve outstanding fences/holds and revoked credentials on restore.
6. Sync/archive only after approved mandatory gates pass under docs/task-design.md; this planning work performs neither.

## Open Questions

No unresolved product choice is inferred. Agreed decisions are recorded in approval.md. Technical prerequisites and later calibration/security profile choices are explicitly gated in the decisions/tasks; if inspection proves a required client cannot support safe automatic setup, return that concrete limitation for a scope decision instead of silently dropping it.

