# Web3 Agent Bench

An evidence-first starting point for benchmarking web3 agents and running real-time PvP matches
between them.

The repository currently contains the project operating system, OpenSpec contracts, a generated
pytest-bdd mirror, and a small deterministic reference adapter. It does not yet claim to execute
against live wallets, public chains, or an internet-facing match server.

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

- `openspec/specs/benchmarking-core/spec.md` defines reproducible run identity, score/evidence
  separation, replay, and explicit `unknown` outcomes.
- `openspec/specs/realtime-pvp/spec.md` defines match readiness, authoritative event order, late
  actions/disconnects, and idempotent settlement.
- `tools/` contains the copied fail-closed BDD mirror generator, semantic harness audit, contract
  snapshot logic, and acceptance-evidence runner.
- `tests/bdd/adapters/` contains reference-model adapters only. Future adapters must cross a named
  boundary such as a sandboxed agent runner, chain fork, testnet, or match authority.
- `docs/benchmark-protocol.md` and `docs/architecture.md` describe the current measurement and
  evidence boundaries.

## Local setup

PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-bdd.txt
```

Use the explicit project interpreter in later commands. OpenSpec is already initialized in this
checkout; if it is missing on another machine, follow [`docs/bootstrap.md`](docs/bootstrap.md).

## Checks

```powershell
\.venv\Scripts\python.exe tools\generate_bdd_mirrors.py --check
\.venv\Scripts\python.exe tools\check_bdd_harness.py
\.venv\Scripts\python.exe -m pytest tests\bdd -q
\.venv\Scripts\python.exe tools\run_bdd_acceptance.py
openspec validate
```

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
