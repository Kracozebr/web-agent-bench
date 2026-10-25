# Web3 Agent Bench

An evidence-first starting point for benchmarking web3 agents and running real-time PvP matches
between them.

The repository contains OpenSpec contracts, generated pytest-bdd mirrors, deterministic baseline
adapters, a controlled benchmark environment and local owner-product packages. Each acceptance
report declares its boundary; local results do not establish public-chain or production behavior.

The MVP planning snapshot and accepted delivery sequence are in
[`docs/mvp-execution-plan.md`](docs/mvp-execution-plan.md). It links the ten
proposed OpenSpec packets, remaining preparation work and the parallel
[`UI layout brief`](docs/ui-layout-brief.md). Planning and mock UI do not establish
runtime acceptance or approval of every implementation packet.

The local [MVP UI prototype](prototypes/mvp-ui/README.md) revises the latest Stitch
export with synthetic data and explicit simulated interactions. It is a design
artifact for later integration, not the Next.js application, authentication,
ledger, MCP server or chain execution layer.

## What is in the first slice

The first real owner product journey now runs through Next.js, Fastify and
PostgreSQL. Use the [Docker-only local setup](infrastructure/owner-identity/README.md)
and read the [OID implementation review](openspec/changes/owner-identity-and-pilot-admission/implementation-review.md).
Its local Google/SIWE/browser gates are separate from actual Google/wallet
compatibility and the remaining agent/funding integrations; the change stays active.

- `openspec/specs/benchmarking-core/spec.md` defines reproducible run identity, score/evidence
  separation, replay, and explicit `unknown` outcomes.
- `openspec/specs/realtime-pvp/spec.md` defines match readiness, authoritative event order, late
  actions/disconnects, and idempotent settlement.
- `tools/` contains the copied fail-closed BDD mirror generator, semantic harness audit, contract
  snapshot logic, and acceptance-evidence runner.
- `tests/bdd/adapters/` separates reference models from controlled-environment and real-product
  evidence verifiers. A passing local model does not establish an external boundary.
- `docs/benchmark-protocol.md` and `docs/architecture.md` describe the current measurement and
  evidence boundaries.

## Local setup

Use PowerShell only to launch Docker and prepare ignored local secret files:

```powershell
./infrastructure/owner-identity/bootstrap.ps1
docker compose -f infrastructure/owner-identity/compose.yaml up -d --wait postgres
docker compose -f infrastructure/owner-identity/compose.yaml build runtime
```

The image contains pinned Node/pnpm, OpenSpec, Chromium and a Python BDD environment.
See [`docs/bootstrap.md`](docs/bootstrap.md) for the original portable harness bootstrap.

## Checks

```powershell
./infrastructure/owner-identity/tool.ps1 python tools/generate_bdd_mirrors.py --check
./infrastructure/owner-identity/tool.ps1 python tools/check_bdd_harness.py
./infrastructure/owner-identity/tool.ps1 openspec validate --all --strict
```

Runtime acceptance additionally requires its declared services and fixtures; use the
specific BEF or OID infrastructure instructions instead of treating these structural checks
as runtime proof.

`tools/run_bdd_acceptance.py` records per-scenario evidence in
`tests/bdd/acceptance-evidence.json` and writes transient JUnit output under
`artifacts/bdd-evidence/`.

## Change lifecycle

For behavior changes, use `/opsx:explore`, `/opsx:propose`, explicit approval, `/opsx:apply`, the
mandatory BDD gates, `/opsx:sync`, and `/opsx:archive`. The detailed contract is in
[`docs/task-design.md`](docs/task-design.md); reusable prompts are in
[`templates/bdd/agent-prompts.md`](templates/bdd/agent-prompts.md).

The local Git repository is initialized for this project. No remote is configured by this
bootstrap; add one only when the destination is known.
