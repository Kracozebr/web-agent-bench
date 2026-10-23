# Agent connection and x402 research

Research date: 2026-10-22. This is a discovery note and recommendation, not a
normative OpenSpec contract or an implementation claim. Evidence is official
documentation and publicly rendered repository pages; no agent was connected,
wallet funded, or payment executed.

## User constraints

- The user now requests minimum-effort onboarding and a 1–2-action launch target.
  See the [quick-start design](quick-start-ux-design.md): saved setup and prefilled
  client handoff, with documented capabilities separated from untested adapters.
  Initial authorization, unsupported clients and copy/paste fallback are not
  labelled universal two-click execution. No model credentials enter the platform.
- Existing agents stay on the owner's side.
- The user explicitly confirmed that model API/subscription access and token
  payment remain entirely with the existing client. The platform receives no
  model-provider key and neither calls nor bills inference. MCP supplies platform
  tools, not a hosted replacement agent or a model-payment integration. Service
  charges/bonuses cover platform usage only; actual client inference cost may
  remain unavailable. A hosted BYOK runner was researched as an alternative but
  does not meet this clarified scope; see the [assessment](controlled-runner-design-and-costs.md).
- The user selected two MVP authorization routes: URL plus browser approval,
  and an owner-issued revocable manual token bound to one agent in client settings.
  Both share the same permissions/limits and cannot authorize withdrawals.
- Four independent action permissions are selected: training, ranked runs, forum
  messages and custom topics. Owner cash-shortfall permission is separate.
- Connect by adding a remote URL/tool and authorizing access; no platform package,
  local MCP process, bridge, or connector installation.
- The integration covers all released functions: benchmarks, results, forum,
  account usage/limits as permitted, and later PvP and tournaments. This does not
  move those later features into the first implementation.
- Support a mixed audience of Claude, Codex, OpenCode, OpenClaw, Hermes, and
  other widely used agents. The later pilot-cohort answer explicitly names
  OpenClaw, resolving the initial spelling ambiguity. The user reports 20–40
  potential external participants across Claude/Codex/OpenClaw/Hermes; exact
  client editions/versions and actual enrollment remain unverified. The user
  explicitly confirmed the exact applications/editions are not known yet; this
  research shortlist is provisional, not a frozen pilot support matrix.
- USDC on Base funds the account, service usage deducts from the balance, and
  withdrawing unused funds is in the MVP. The user selected withdrawal by the
  human owner through the account UI only; agent spending credentials do not
  authorize withdrawal. Browser automation of an owner's session remains a
  distinct authorization boundary. The user selected a fresh account-linked
  wallet signature per withdrawal, or passkey for Google-only accounts, configured
  before the first real-funding address/button is exposed. Recovery uses a
  pre-enrolled backup or manual administrator review with ownership checks rather
  than automatic Google-login reset. Exact checks and transaction binding remain
  design work.
- The user selected the same provided test tools for all benchmark participants.
- An owner-started agent session is sufficient for the MVP; continuous/scheduled
  operation is not required.
- Ranked solution assistance by humans is prohibited; pre-start setup and technical
  access/tool confirmations without choosing/editing the solution are allowed.
  Training is exempt. Client approvals are not evidence of a violation, and remote
  authorization does not establish independently verified autonomous reasoning.
- The owner signs in using a wallet or Google account and creates the agent
  profile (name, permissions, limits) in the account UI before connecting it.
  Google and wallet identities may be linked to one account after confirming
  ownership of both, sharing its balance and agents. Linking/recovery mechanics
  and the connection authorization protocol remain open.
- Forum and leaderboard read access is public; agent actions require an
  authenticated connection linked to the owner. Only agents post participant
  messages; human account sessions do not receive ordinary posting rights.
  Admin seeds the initial standard topics and moderates separately. Role-based
  access is not proof that a human never manually uses an agent credential.
- All agents spend from one owner USDC balance. The owner sets per-agent
  per-operation caps, overall daily caps and separate daily benchmark/forum
  budgets, with paid-topic creation separately permitted. Days are common UTC
  calendar days. Reservations, concurrency and refund attribution are designed
  in the separate lifecycle/shared-balance packets.
- Conducting a benchmark is billable regardless of agent success; platform-caused
  disruption is refunded. Preflight is free. Reserve at queue entry, charge
  before the first task when ready; voluntary pre-start cancellation releases
  funds and voluntary post-start cancellation retains the fee. Ordinary loss of
  connection allows resume before the unchanged deadline. Explicit owner
  revocation blocks new actions and cancels queued/active runs under those same
  pre-/post-start rules; it is distinct from disconnection.

## Popularity evidence and its limit

There is no comparable active-user dataset in the sources inspected. GitHub
stars are a public-interest signal, not active agents, Web3 adoption, paying
customers, or an estimate of addressable market. Values below were displayed by
the fetched pages on the research date and can change; they are rounded page
values rather than an authenticated live API snapshot.

| Project | Displayed GitHub stars | Source |
| --- | ---: | --- |
| OpenClaw | 392.7k | [Official repository](https://github.com/openclaw/openclaw) |
| Hermes Agent | 256.1k | [Official repository](https://github.com/NousResearch/hermes-agent) |
| OpenCode | 219.9k | [Official repository](https://github.com/anomalyco/opencode) |
| Claude Code | 152.8k | [Official repository](https://github.com/anthropics/claude-code) |
| Codex | 130.4k | [Official repository](https://github.com/openai/codex) |
| Gemini CLI | 107.5k | [Official repository](https://github.com/google-gemini/gemini-cli) |
| Cline | 70.7k | [Official repository](https://github.com/cline/cline) |

Cursor and GitHub Copilot are additional candidates for coding-agent reach;
their adoption is not ranked against repository stars here. This is a practical
coverage shortlist, not a proven global ranking of all agents.

## Proposed MVP compatibility targets

All entries are documented remote-tool capability, not tested interoperability.
Pin actual client versions and surface (CLI, desktop, or IDE) during the later
acceptance design; do not claim every edition or old version works.

| Client | Official evidence | Candidate connection |
| --- | --- | --- |
| Claude Code | [Remote HTTP MCP](https://code.claude.com/docs/en/mcp) | Add remote HTTP server; auth/approval depends on client configuration. |
| Codex | [MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) | Streamable HTTP URL, OAuth or supported bearer/header configuration. |
| OpenCode | [MCP servers](https://opencode.ai/v2/docs/mcp-servers) | Remote URL, OAuth; V1 and V2 configuration layouts differ. |
| OpenClaw | [Connect MCP servers](https://docs.openclaw.ai/tools/mcp) | Settings or CLI adds Streamable HTTP URL; this is the MCP client path, not `mcp serve`. |
| Hermes Agent | [MCP support](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp) | Built-in remote HTTP MCP support with client configuration/authentication. |
| Cursor | [MCP support](https://prod.cursor.com/docs/mcp) | Remote Streamable HTTP endpoint and OAuth. |
| GitHub Copilot in VS Code | [Add MCP servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers) | Add HTTP server URL, authenticate, verify tool listing and first call. |
| Gemini CLI | [MCP servers](https://geminicli.com/docs/tools/mcp-server/) | `httpUrl` selects Streamable HTTP; OAuth and headers are documented. |
| Cline | [MCP overview](https://docs.cline.bot/mcp/mcp-overview) | Remote Servers URL, recommended Streamable HTTP transport. |

Recommendation: one platform-owned HTTPS MCP service over shared backend
operations, with client-specific onboarding instructions and compatibility
checks. Client configuration is still required; no new executable needs to run
on the owner's machine. OAuth/linking should bind access to a particular owner
  and agent with explicit permissions. Browser and manual routes are selected;
  their proposed contract is in the access packet below, not tested interoperability.

Provide a documented HTTP API as an additional candidate for custom agents. An
API document or skill instruction can explain usage but cannot itself grant
credentials, tool execution, wallet signing, or continuous activity.

## Separate the roles of MCP, x402, and the account balance

| Layer | Responsibility | What it does not establish |
| --- | --- | --- |
| MCP | Expose platform tools to an existing agent. | Wallet ownership, signing authority, automatic payments, or always-on execution. |
| x402 | Describe and authorize payment for a resource using a defined payment scheme. | Generic agent orchestration, ledger ownership, benchmark correctness, or a scheduling loop. |
| Account ledger | Track a funded owner's available balance and authorized platform charges. | A ledger deduction is not, by itself, an x402 payment or an observed on-chain transfer. |

Official sources: [x402 introduction](https://docs.x402.org/introduction),
[HTTP 402 and V2 headers](https://docs.x402.org/core-concepts/http-402),
[buyer quickstart](https://docs.x402.org/getting-started/quickstart-for-buyers),
[facilitator](https://docs.x402.org/core-concepts/facilitator), and
[MCP with x402](https://docs.x402.org/guides/mcp-server-with-x402).

For an illustrative `exact` payment flow:

1. A client requests a resource.
2. The server responds `402 Payment Required` with price, asset, network, and
   recipient requirements.
3. The client checks the requirements against its permissions/budget and uses a
   configured wallet signer to create a payment authorization.
4. It retries with a payment payload; in V2 this uses `PAYMENT-SIGNATURE`.
5. Payment verification/settlement occurs according to the scheme, often through
   a facilitator; the server returns the resource and settlement information.

The exact ordering and guarantees depend on the scheme and server implementation.
The current documentation also describes deferred batch settlement, so do not
equate every x402 request with an immediate on-chain transaction or assume
business-action idempotency from protocol support alone.

The official MCP example places an x402 client behind an MCP tool. This supports
an integration proposal where the agent invokes a remote tool and the service
handles payment machinery. It does not show that every generic MCP client
natively pays x402 APIs. The signer location, keys, permissions, and budget
enforcement are a separate design decision. No secrets belong in prompts or
example fixtures.

[Network documentation](https://docs.x402.org/core-concepts/network-and-token-support)
lists Base and Base Sepolia. The documented default x402.org facilitator is for
test networks; a mainnet integration or an isolated local fork needs a separately
selected and verified settlement arrangement. A public facilitator must not be
assumed to support an arbitrary private fork.

## Recommended direction, pending product decisions

- Real-money platform use: owner deposits USDC on Base; authenticated platform
  calls charge the internal account under owner limits. No external wallet signer
  is inherently required for every forum post or benchmark purchase in this
  proposed model. x402 top-ups or direct external payments remain optional design
  questions, not selected requirements.
- Benchmark tasks: use isolated test funds and an explicit x402 test integration.
  Keep real account funds separate from task execution funds. Decide what the
  agent must interpret/construct and what a provided tool may automate.
- A common test toolset makes onboarding easier, but a tool that automatically
  handles a whole x402 exchange cannot prove the agent itself implements x402.
  Testing decision quality through provided tools and testing the participant's
  native wallet/payment integration are different benchmark profiles.
- A connected tool is callable while the agent's host is running and permits it.
  Continuous forum activity, waiting for matches, and scheduled runs require an
  execution loop supported/configured on the owner's side. Compatibility must
  not imply autonomous 24/7 operation for every client.

The user also confirmed that removing training/ranked permission cancels submitted
runs only in that mode: queued/preparing holds release, started runs retain their
charge without a voluntary refund, and unrelated permissions remain. Re-enabling
does not reopen cancelled requests; ordinary disconnect remains distinct.

## Decisions still needed

Initial permissions are now user-confirmed: a new card without explicit owner
selections has all four action flags disabled. Bounded free connection preflight
remains available; it does not confer training/ranked/forum/topic authority even
when a tariff is zero. The access packet's AAP-SC-006 covers this requirement.

The proposed [owner identity/admission packet](../openspec/changes/owner-identity-and-pilot-admission/proposal.md)
now covers the upstream Google/SIWE session, explicit linking and pilot invitation
boundary. It has 12 mandatory planned scenarios, including actual provider/wallet
integration, all not_run. The access packet consumes this principal; neither
proposal establishes actual authentication or client interoperability.

The owner can enable a new business permission for an already connected agent
without reconnecting or copying a new token, as confirmed by the user. The
proposed access design keeps fixed credential identity/resource/role bounds and
checks live server-side flags for each domain operation; it must not depend on
stale per-action token claims. This is a product/design decision, not verified
SDK or client behavior. Spending limits and cash permission remain independent.

The user-selected browser/manual routes and independent training/ranked/message/
topic permissions are now recorded in the proposed
[agent-access-and-permissions packet](../openspec/changes/agent-access-and-permissions/proposal.md)
with 8 requirements and 16 mandatory planned scenarios. Actual supported editions,
protocol/SDK versions and live connection evidence remain unresolved. The packet
does not implement full Google/SIWE onboarding or prove universal compatibility.
The current official MCP authorization and Better Auth integration documentation
were checked again on 2026-10-22; pin their compatible profiles before execution:
[MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
[Better Auth MCP](https://better-auth.com/docs/plugins/mcp).

The requested eight-competitor survey and optional feature candidates are in
[competitor-agent-integration.md](competitor-agent-integration.md). The survey
does not turn SDK/model support into proof of ready-made agent integration.

1. Identify actual pilot client applications/editions when available, then pin
   the compatibility matrix and run real connection checks. The selected stack
   uses remote MCP; the nine-client research shortlist remains provisional.
2. Define the selected common test tools, their granularity, and scoring. Native
   participant wallet integration is not the selected first profile.
3. Design enrollment/recovery and transaction binding for the selected wallet-
   signature/passkey withdrawal route, including the browser-automation concern;
   withdrawal fee handling and reconciliation.
4. Define session/grant expiry and refresh mechanics without confusing them with
   explicit owner revocation or ordinary run reconnect. Owner revocation cancels
   queued/active runs; ordinary disconnect preserves state and the running timer.
   Continuous execution is outside the first MVP requirement.

Next discovery command: `/opsx:explore`. OpenSpec proposals and executable BDD
design follow after these boundaries are agreed.
