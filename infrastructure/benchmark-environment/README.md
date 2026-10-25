# Local BEF acceptance deployment

This Compose project is a disposable, two-environment acceptance stack. It pins the reviewed
manifest and container images, forks Base at the declared block through the read-only source proxy,
and keeps Anvil administration on the private Compose network. API, observer PostgreSQL, read-only
RPC proxies, and controlled facilitators bind to loopback only. The source RPC URL and generated
local credentials live under the ignored `.local/secrets/` directory.

Run these commands from the repository root in PowerShell:

```powershell
.\infrastructure\benchmark-environment\bootstrap.ps1
docker compose -f infrastructure/benchmark-environment/compose.yaml up -d --build
.\infrastructure\benchmark-environment\run-bdd.ps1 -SyncedMain -ScenarioId BEF-SC-004
.\infrastructure\benchmark-environment\run-bdd.ps1 -SyncedMain -Acceptance
docker compose -f infrastructure/benchmark-environment/compose.yaml down
```

The bootstrap creates local random admin, service, owner, API-role, and observer-role credentials
without displaying them. It prompts for no provider value. Add the approved read-only Base RPC URL
to `infrastructure/benchmark-environment/.local/secrets/source-rpc-url` using a local editor, then
rerun bootstrap. Keep that file out of Git and do not pass the URL as a command-line argument.
`run-bdd.ps1` reads the needed values into its process memory, invokes the project BDD interpreter,
and restores the caller's previous environment values without echoing secrets.

The Compose port defaults avoid common local development ports: API `127.0.0.1:8783`, observer DB
`127.0.0.1:55432`, source proxy `127.0.0.1:18544`, local RPC proxies `127.0.0.1:18545` and
`127.0.0.1:28545`, and facilitators `127.0.0.1:14021` and `127.0.0.1:24021`. Set the corresponding
`BEF_*_HOST_PORT` variable in the shell for both Compose and `run-bdd.ps1` if a port is occupied.
No Anvil RPC port is published. The declared per-service memory limits total 5.125 GiB, below the
reported 7.56 GiB Docker host limit; this is a configured cap, not a measured workload result.

Use `run-bdd.ps1 -SyncedMain -Acceptance` for the complete synchronized-main gate report (the
eight baseline scenarios plus twelve BEF environment scenarios) and its persisted acceptance
evidence. A blocked/skipped mandatory gate makes this command fail even when pytest itself exits
zero. Without `-Acceptance`, the script runs the mapper tests, optionally filtered by `-ScenarioId`;
that mode does not update the complete acceptance report. `-Acceptance` and `-ScenarioId` cannot
be combined. `-SyncedMain` selects the main contracts and replay source profile explicitly;
omitting it selects the historical active-delta workflow, which requires an active approved
BEF change and is unavailable after that change is archived.

Standalone read-only replay also selects its source profile explicitly:

```powershell
.venv/Scripts/python.exe tools/replay_bef_evidence.py --source-profile synced-main --evidence-dir artifacts/benchmark-environment-feasibility/probes/<capture-id> --report artifacts/runs/<new-replay-report>.json
```

The report binds current main specs, main harness contracts and verifier sources while retaining
the original capture hashes. Replay does not rerun the workload or establish a new environment gate.

Scenario probes whose real driver/evidence is not yet available remain blocked. The Anvil services
now bind separate task-owned state and Foundry RPC cache directories under
`artifacts/runs/bef-ethereum-prague-cache/`. Both nodes explicitly use
`--network ethereum --hardfork prague`; the source remains the pinned Base fork and the
numeric local chain ID remains 8453. Startup and reset verify the actual execution profile.
This implements the educational local-EVM fee model and does not reproduce Base L1 fees.
The pinned Anvil image runs as `foundry`; both services explicitly use
`HOME=/home/foundry` and mount RPC caches at `/home/foundry/.foundry/cache`.
The sampler checks the actual HOME, mount sources and write access as that user.
Those bindings alone do not establish SC011: cold/warm
preparation, actual workloads, resource measurements and guardrail stopping still need recorded
trial evidence. Resource-window sampling and the bounded child-command collector alone are
insufficient.
The SC011 orchestration CLI defaults to a plan-only report; its execution preflight requires
explicit manifest guardrails and the promoted workload driver. Its current sampler observes the
workload window after container startup, reports reused-service cgroup lifetime peaks separately,
and does not measure startup CPU or memory. A nonempty post-start cache prevents a cold-workload
claim under that measurement profile.
Warm preparation observes the cache after cold cleanup and a verified Anvil-A stop.
The combined state/RPC inventory must contain actual nonzero data; an individual
root may be empty. The exact prepared entries must survive recreation with the same
bind sources. Later workload cache updates or eviction are measured as inventory
deltas, because the cache is mutable working state. Failed preparation inventories
and stop outcomes remain in the original orchestration evidence.
Do not interpret service health, a structural audit or an offline evidence replay as a newly
executed environment gate.
