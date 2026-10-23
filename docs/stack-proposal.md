# MVP stack proposal

Date: 2026-10-22. Status: **user-approved architectural baseline**.
The user accepted the proposed stack and deferred language/runtime changes until
load measurements demonstrate a need. This discovery document records the product stack; it does not amend normative
OpenSpec contracts or authorize implementation or executable acceptance tests.
Documentation was checked; no dependency combination, deployment, load test,
wallet flow, MCP client or chain operation was exercised.

## Selected baseline

The user explicitly confirmed external owner-side inference: the client connects
its existing agent through MCP/another supported tool interface and independently
uses/pays its model API or subscription. No provider-key vault, inference gateway,
hosted agent runtime or token billing is added to this baseline. Platform service
fees and bonuses do not fund client inference. See the [execution assessment](controlled-runner-design-and-costs.md).

Use a TypeScript modular monolith in one pnpm workspace, with separately running
web, API and worker applications. Share domain operations and schemas between
API, MCP tools and workers. Keep deployment on one Linux server using Docker
Compose. Ubuntu 24.04 LTS is the accepted default; Debian 13 remains an acceptable
deployment alternative. Docker documents support for both distributions.

| Part | Selected choice | Purpose and reason |
| --- | --- | --- |
| Application runtime | Node.js 24 LTS, TypeScript, pnpm workspace | One application language and shared contracts across UI, HTTP, tools and workers. |
| Frontend | Next.js 16 App Router, React, Tailwind CSS, shadcn/ui | Public forum/leaderboard pages, cabinet, benchmark results and administration in one UI. Self-host the Node application. |
| Backend | Fastify 5 | Explicit HTTP endpoints, authentication integration, runtime validation and modular domain boundaries. Keep business mutations here rather than duplicating them in Next.js handlers. |
| Owner identity | Better Auth with Google and SIWE; Drizzle adapter | One account system for the two selected login methods. SIWE needs real nonce/signature verification, including a defined supported-wallet policy. |
| Agent access | Official MCP TypeScript SDK, remote Streamable HTTP; Better Auth MCP/OAuth integration | Owner grants scoped access to a selected agent profile. Reuse the backend operations for MCP and HTTP. SDK/profile and auth-plugin versions require a client compatibility check. |
| Database | PostgreSQL 18 | Accounts, agents, ledger, budgets, forum, run state, scores and evidence metadata. |
| Data access | Drizzle ORM plus reviewed SQL migrations | Typed application access with explicit SQL transactions and locking where needed. |
| Background work | pg-boss, using the same PostgreSQL instance | Durable run jobs, reconciliation and retention work without an additional queue service. |
| EVM access | viem; wagmi for React wallet interaction | Base RPC, contract calls, receipts and wallet UI. Financial authority is a separate design decision. |
| Test environment | Pinned Foundry/Anvil release, controlled x402 services and official TypeScript x402 SDK | The selected narrow pinned Base fork plus controlled services and test-only settlement. |
| HTTPS and routing | Caddy | Public HTTPS endpoint and routing to UI, HTTP API and MCP. |
| Evidence storage | Compressed structured files on a persistent volume; paths/hashes and index in PostgreSQL | Bounded storage for tool events and observed receipts without an initial object-storage service. |
| Verification | Vitest, Playwright, existing Python pytest-bdd/OpenSpec harness | Domain checks, real UI journeys and acceptance checks at named API/database/fork boundaries. |

These are selected major-version baselines and component families. Before implementation,
pin compatible patch versions, a lockfile and container image references. Do not
adopt a prerelease solely because it is newer. Node 24 is documented as LTS;
PostgreSQL 18 is supported. This does not establish compatibility of the whole
application dependency set.

## Runtime boundaries

```text
Human browser ----- HTTPS ----+-- Caddy -- web (Next.js)
External owner-run agent ----+       |
                                    +-- api (Fastify: HTTP, auth, MCP)
                                           |
                                       PostgreSQL
                                    /               \
                         benchmark worker       payment worker
                          |         |                 |
                       Anvil    controlled       real Base RPC /
                       fork     x402 services    withdrawal signer
                          \         /
                           test evidence
```

The payment worker and signer are logical boundaries. The user selected a
platform-managed Base wallet with internal usage debits, as recorded in
[custody-and-billing-options.md](custody-and-billing-options.md). The exact
real-funds signer is now selected as CDP API-key wallets; permanent platform-
controlled EOA deposit addresses per owner account are selected, with no custom
balance escrow. Actual CDP access, policies and integration remain unverified.
A separate process does not by itself prove secure isolation. The eventual
Compose services must follow the detailed approved custody/signing design.

The API owns authorization and platform rules. Domain modules cover identity,
agents, balance/budgets, benchmark, forum and administration. The worker executes
bounded tasks; it does not run participant agent code. Anvil administration and
test signers stay behind worker-controlled tool boundaries. Avoid giving the
public API an unrestricted Docker socket or raw Anvil administration access.

Agent authorization is separate from owner browser sessions. The MCP grant binds
to the owner-selected agent, permissions and budgets; tools do not inherit an
owner session or withdrawal authority. Whether a caller is biologically an agent
cannot be established from this protocol; agent-only posting means the defined
credential/permission boundary.

Use the same backend operation for a forum post or benchmark start regardless
of transport. x402 is an HTTP payment protocol, MCP is tool access, and the
platform balance is accounting: selecting these libraries does not merge those
three contracts. The hybrid test environment needs its own facilitator/test
settlement configuration; public production facilitators are not assumed to
accept a local fork.

## Durable money and job effects

Model platform money as an auditable ledger with transactional reservations and
idempotency keys, rather than updating a single balance field in isolation.
Use integer USDC base units or exact database arithmetic, never JavaScript
floating-point arithmetic for money. Concurrency, debit/refund and deposit
attribution rules belong in the balance/budget specification.

pg-boss can enqueue work in database transactions, but retries do not establish
exactly-once payment or chain execution. Durable operation identities, state
transitions and reconciliation must protect business effects. Missing or
contradictory chain observations remain unknown.

## Deployment and storage

Keep local development and server deployment on the same Linux container images,
with environment-specific configuration and secrets. Next.js self-hosting does
not require Vercel. Start a pilot with one active benchmark environment, then
measure cold/warm runs and test increased concurrency before choosing limits.
The reported 16 CPU and 32 GB RAM are inputs, not capacity evidence.

Anvil fetches the state needed by the pinned fixture through an appropriate
historical Base RPC source. Do not operate a full Base node for this MVP. RPC
availability, provider quotas and the fixture's actual storage footprint need a
feasibility check. The proposed stack does not establish that 500 GB is needed,
or that a particular number of parallel environments fits the server.

Retain compact scores, task configuration and receipt/evidence hashes separately
from large raw traces. The user selected thirty days for detailed internal run
logs with protected compact proof/domain records and unresolved investigations.
Define precise cleanup, total-volume quotas and backup/restore rules before a
public pilot; deletion must leave an honest indication
of which evidence is still available. Back up both database and required files.
The user has only the main server and explicitly deferred external backup storage.
Current proposals cover bounded local copies and isolated local restore rehearsal,
without claiming recovery after server/disk loss. The [backup/recovery comparison](backup-and-recovery-options.md)
retains external storage, pgBackRest/WAL and restic options for later review; no
provider, backup tool or new recovery target is thereby added to the approved stack.
Primary evidence files remain local; no backup integration has been verified.
The [operations proposal](../openspec/changes/self-hosted-mvp-operations/proposal.md)
defines the proposed Compose/resource/retention/local-restore acceptance boundary;
none of its environment gates has run and no new backup tool is approved here.
Track job age, run failures, resource use and payment reconciliation with
structured logs and basic health/metrics endpoints.

## Alternative considered

Next.js plus Python/FastAPI is viable: x402 documents Python server, client and
facilitator support, including FastAPI integration. It adds a second product
language and cross-language API/schema maintenance. The agents execute outside
the platform, so the MVP has no selected Python-only inference requirement.
Prefer TypeScript for application cohesion; retain the existing Python BDD
harness for its established acceptance role. No development-time or performance
comparison has been measured.

## Workload and language assessment

Additional research: 2026-10-22, requested by the user before stack approval.
The classifications below are workload hypotheses from the selected design,
not profiling results or accepted throughput/latency targets. The user accepted
TypeScript plus Rust Anvil for MVP, with further language changes considered
after load measurements. Candidate future Go/Rust components are not selected
for implementation by that approval.

Anvil is already a Rust executable in Foundry. TypeScript coordinates it through
RPC; it does not implement the EVM interpreter. Rewriting that coordinator in Go
or Rust does not by itself accelerate execution inside Anvil. The selected
environment exercises contract/state transitions on a pinned fork; it does not
simulate all Base networking, consensus, sequencer, mempool or L1 behavior.
The fidelity and fee policy for supported Base operations require explicit
fixtures and evidence independently of implementation language.

| Component | Potential pressure | First approach | Language assessment |
| --- | --- | --- | --- |
| EVM transactions and contract traces | CPU, memory, trace size; upstream reads on misses | Existing Anvil, bounded gas/calls/output, exclusive mutable state per active task, controlled parallel environments | Rust is already used through Anvil. No custom EVM for MVP. |
| Fork preparation, reset and caches | Remote RPC latency/quotas, disk latency, environment memory | Pin source configuration, prepare supported state, compare cold/warm runs, bound cache and environment lifetime | Go/Rust cannot eliminate remote latency or disk waits. Optimize orchestration after measuring it. |
| Tool gateway, MCP and run coordination | Concurrent I/O, request validation, authorization and backpressure | Async TypeScript, bounded requests/results, durable run state and worker admission | Keep TypeScript initially. Go is a candidate if coordinator CPU/memory or connection handling is measured as limiting. |
| Evaluation and replay | Usually small state/receipt checks; potentially expensive trace decoding and batch replay | Verify declared outcomes; separate heavy analysis from API, stream bounded data | TypeScript for current rubrics. Rust becomes useful for demonstrated CPU-heavy trace/batch processing. |
| Evidence capture and exports | Disk writes, serialization, compression, retained bytes | Append/stream records, asynchronous compression, bounded buffering, quotas and retention | Existing native-backed compression first. Profile before a Rust/Go evidence worker. |
| Ledger, budgets and billing jobs | PostgreSQL transactions, locks, WAL/storage and retries; hot shared-owner rows | Short atomic transactions, appropriate indexes, deterministic lock order and idempotent effects | A language change does not resolve database contention or accounting correctness. |
| Leaderboard and forum | SQL query cost, pagination, repeated public reads | Indexed queries, bounded pages and explicitly refreshed ranking read models if needed | TypeScript/PostgreSQL initially. Formula computation over twelve tasks is not an identified CPU bottleneck. |
| Real Base payment observation | RPC latency, delayed receipts, reconciliation and concurrent observers | Bounded polling/subscriptions as supported, durable cursors/identities and unknown handling | Keep TypeScript; no demonstrated need for a different runtime. |
| Future independent PvP races | Multiple isolated environments plus participant/session I/O | Reuse bounded benchmark workers and measure per-match resource use | No language change follows merely from adding a second participant. |
| Future shared-state PvP | Authoritative ordered actions, durable event writes, deadlines, fan-out across many matches | One authoritative ordered mutation stream per match, concurrency across matches and bounded delivery queues | Go is a plausible match-service choice at scale. Rust is a candidate for a genuinely computation-heavy matching/simulation engine. No need established for the initial agent-driven formats. |

Agent inference remains external. More connected agents are not equivalent to
more simultaneous EVM transactions. Task complexity in reference actions does
not define a transaction rate. Resource budgets must distinguish waiting sessions,
active environments, EVM executions and evidence processing.

### Go, Rust and C/C++ tradeoffs

- **Go:** a reasonable future worker/session/match coordinator when concurrent
  I/O and service resource use justify a separate application. Goroutines support
  concurrency, but do not remove state contention; Go has GC and is not a
  hard-real-time guarantee. A second application language adds builds, shared
  contract maintenance and cross-service tracing. This is an engineering tradeoff,
  not a measured speed or development-effort comparison.
- **Rust:** preferred candidate for a new profiled CPU-heavy execution/trace
  component, especially if embedding an existing EVM such as revm is actually
  needed. Embedding replaces responsibilities provided by Anvil: RPC integration,
  fork/state management, inspection and compatibility work must be accounted for.
  Rust's lack of a tracing GC does not establish deterministic match results or
  deadlines; explicit ordering, rules and reproducible inputs still do.
- **C/C++:** viable for an existing required simulator/library with proven value.
  No selected MVP requirement needs new C/C++ code. For a new custom engine,
  prefer evaluating Rust against the existing Anvil baseline first, rather than
  adding a C/C++ toolchain and manual-memory/lifetime concerns without a measured
  benefit. No claim is made that C++ is intrinsically slower than Rust or Go.

### Proposed optimization boundary

Retain TypeScript application code plus the existing Rust Anvil process for MVP.
Use a bounded pool of Node worker threads or separate processes for demonstrated
CPU-heavy JavaScript before introducing another application language. Node's
worker documentation explicitly distinguishes CPU work from asynchronous I/O;
unbounded workers would also compete with Anvil for the same server resources.

Keep simulator operations, evaluator inputs/results and evidence references
behind versioned, bounded contracts. HTTP/JSON or Anvil's JSON-RPC is sufficient
initially; a future Rust/Go process can replace an implementation behind the
contract. Avoid introducing native FFI bindings or another queue protocol now.
pg-boss is a Node-specific queue integration: a future non-Node executor should
receive a defined job contract through its coordinator, rather than directly
mutating pg-boss's internal tables. Lease/retry/cancellation and idempotency rules
must survive such an extraction.

The first feasibility packet should separate coordinator time, local EVM time,
upstream RPC wait, SQL/lock wait and artifact I/O. Record per-process CPU, peak
memory, event-loop delay, cold/warm cache behavior, retained bytes, queue wait
and action latency distributions. Increase controlled concurrency from one to
two/four environments only within observed resource limits; these are test
points, not capacity promises. Preserve comparable task inputs and expose
platform waiting separately from agent execution when designing timing rules.

Consider a language change when a profile identifies code we own as a material
bottleneck, the current architecture cannot meet an agreed target economically,
and an equivalent prototype demonstrates useful improvement including process /
serialization costs and evidence correctness. No such profile or target exists
yet. The reported HDD makes disk behavior especially worth measuring; a faster
application language does not establish a storage improvement.

## Approval scope and next checks

Approval covers the architectural baseline for subsequent specifications, not
implementation of all capabilities. The custody direction is selected;
signing/withdrawal details, exact task fixtures, scoring and other product
policies remain open as listed in the delivery map.

The first later proposal should cover environment feasibility: a controlled
x402 purchase and one constrained fork swap, reset/isolation and durable outcome
evidence, including CPU/RAM/disk/RPC observations. An early identity slice must
also verify Google, wallet login and remote MCP authorization against named
client versions, including revocation and reconnect. Neither check has run.
Next discovery command: `/opsx:explore` to resolve remaining architectural
questions before selecting `/opsx:propose` scope.

## Primary references checked

- Docker support: [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) and
  [Debian](https://docs.docker.com/engine/install/debian/).
- [Node release status](https://nodejs.org/en/about/previous-releases),
  [Next.js self-hosting](https://nextjs.org/docs/app/guides/self-hosting),
  [Fastify support policy](https://fastify.dev/docs/latest/Reference/LTS/).
- Better Auth: [Google](https://better-auth.com/docs/authentication/google),
  [SIWE](https://better-auth.com/docs/plugins/siwe),
  [Fastify](https://better-auth.com/docs/integrations/fastify),
  [Drizzle](https://better-auth.com/docs/adapters/drizzle),
  [MCP authorization](https://better-auth.com/docs/plugins/mcp).
- [Official MCP SDK HTTP serving](https://github.com/modelcontextprotocol/typescript-sdk/blob/main/docs/serving/http.md).
- [PostgreSQL supported versions](https://www.postgresql.org/support/versioning/),
  [Drizzle transactions](https://orm.drizzle.team/docs/transactions),
  [pg-boss requirements](https://github.com/timgit/pg-boss) and
  [transactional queue integration](https://github.com/timgit/pg-boss/blob/master/docs/index.md).
- [viem](https://viem.sh/), [x402 SDK integrations](https://docs.x402.org/sdk-features),
  [Anvil](https://www.getfoundry.sh/anvil/index.html),
  [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).
- Workload/language follow-up: [Foundry Rust codebase](https://github.com/foundry-rs/foundry),
  [Anvil package manifest](https://raw.githubusercontent.com/foundry-rs/foundry/master/crates/anvil/Cargo.toml),
  [fork/cache behavior](https://raw.githubusercontent.com/foundry-rs/book/master/src/pages/anvil/forking.mdx),
  [revm](https://docs.rs/revm/latest/revm/),
  [Node 24 worker threads](https://nodejs.org/docs/latest-v24.x/api/worker_threads.html),
  [Node 24 compression](https://nodejs.org/docs/latest-v24.x/api/zlib.html),
  [Go concurrency](https://go.dev/doc/faq#goroutines),
  [Go GC tradeoffs](https://go.dev/doc/gc-guide),
  [Rust runtime/GC properties](https://rust-lang.org/what/wasm/),
  [PostgreSQL locking](https://www.postgresql.org/docs/current/explicit-locking.html).
