# Task preparation: measurements and deferred optimization

Date: 30 October 2026, Europe/Moscow. Status: measured serial baseline plus proposed optimization; no prefetch implementation or parallel-capacity proof. Saved at the owner's request. The proposed behavior lives in [task-preparation-prefetch](../openspec/changes/task-preparation-prefetch/proposal.md).

## Measured complete-run baseline

Source: read-only PostgreSQL timestamps from the actual participant-owned Codex Training3 and Full12 runs, not the later reference-worker captures. The full run completed with six passed, four failed and two partial task grades; completion is not twelve solved tasks. Training completed with three passed 1/1 grades.

| Phase, seconds | Full12 | Training S1/M1/H1 |
| --- | ---: | ---: |
| Initial queue/preparation/activation | 10.896 | 10.565 |
| Eleven/two subsequent preparation and activation gaps | 100.386 | 9.060 |
| Task activation to agent finish request | 357.916 | 97.422 |
| Finish request to persisted evaluation | 28.291 | 7.259 |
| Evaluation to terminalization | 15.612 | 0.934 |
| Total admission to terminalization | **513.101** | **125.240** |

These are wall-clock intervals, not CPU-only measurements. Preparation gaps include coordinator scheduling and activation. Execution includes model thinking, MCP calls and response waiting. Evaluation includes reconciliation and evidence checks; terminalization includes fencing/finalization. Build/startup of the whole stack is outside these run totals. The current trace does not assign every preparation second to RPC, DB, hashing or storage.

Full12 per-task decomposition (seconds; preparation is the gap before that task):

| Task | Preparation/gap | Execution | Evaluation | Finalization |
| --- | ---: | ---: | ---: | ---: |
| S1 | 10.896 | 22.864 | 2.970 | 0.334 |
| S2 | 5.373 | 36.023 | 1.914 | 0.477 |
| S3 | 6.848 | 21.583 | 1.771 | 0.594 |
| S4 | 6.878 | 13.470 | 2.176 | 0.769 |
| M1 | 7.900 | 35.192 | 1.195 | 0.881 |
| M2 | 10.959 | 39.410 | 2.069 | 1.239 |
| M3 | 10.588 | 37.235 | 2.946 | 1.349 |
| M4 | 10.344 | 18.057 | 1.970 | 1.471 |
| H1 | 9.508 | 43.872 | 2.658 | 1.837 |
| H2 | 9.744 | 24.471 | 2.602 | 2.101 |
| H3 | 11.416 | 21.639 | 3.369 | 2.082 |
| U1 | 10.828 | 44.100 | 2.651 | 2.478 |

Training decomposition:

| Task | Preparation/gap | Execution | Evaluation | Finalization |
| --- | ---: | ---: | ---: | ---: |
| S1 | 10.565 | 25.542 | 1.662 | 0.205 |
| M1 | 4.523 | 33.636 | 3.618 | 0.220 |
| H1 | 4.537 | 38.244 | 1.979 | 0.509 |

## Two new environment-preparation measurements

Existing `capture-bef-task-preparation.mjs` was run on the already running local BEF stack, once for its synthetic S1 preparation and once for ranked S4 with an actual case-pinned allowance fixture. This is an environment diagnostic, not an owner-admitted benchmark, native-agent task-solving run, cold-container startup or all-case capacity test. No new instrumentation or application code was written. Both probes returned exit 0, one original preparation PUT, confirmed fence, unchanged source and zero remaining active generations in environment A. A separate observer readback confirmed unchanged actual-owner ledger/run/task/action/evaluation/timing fingerprints and the private report image.

| Measurement | S1 | S4 |
| --- | ---: | ---: |
| CLI interval, UTC | 17:03:10.087–17:03:22.648 | 17:05:35.541–17:05:51.746 |
| Full diagnostic command seconds | 12.549 | 16.198 |
| BEF persisted preparation creation to reset completion, seconds | 2.830 | 2.195 |
| Reset completion to funding recorded, seconds | 1.945 | 2.301 |
| Creation to funding recorded, seconds | **4.776** | **4.495** |
| BEF mean CPU cores during overlapping command intervals | 0.480 | 0.246 |
| BEF observed maximum interval-averaged CPU cores | 0.840 | 0.308 |
| BEF maximum sampled simultaneous total cgroup memory, MiB | 908.4 | 920.8 |
| BEF samples / actual mean spacing, seconds | 16 / 2.57 | 19 / 2.48 |

The funding timestamp is reconstructed from the persisted generation expiry minus the manifest's 120-second lifetime; `recordPreparationFixture` sets that expiry using database time. It is not the completion timestamp of the owner adapter's subsequent baseline/evidence checks. S4 also performs its allowance fixture after initial funding. Full command duration additionally includes module/pin loading, original prepare, replay/readback checks, fencing and late-prepare denial. Do not label either the 4.5–4.8-second segment or the whole CLI duration as pure production successor-preparation latency.

The BEF measurements aggregate ten running containers, including environment B's background activity. CPU is derived from cgroup usage deltas divided by interval duration; one core means 100% of one logical CPU, not 100% of the twenty-CPU host. Intervals overlapping command start/end are included. Memory uses `memory.current`, not Docker's cache-adjusted working-set display. Summed per-container peaks are not used as a simultaneous aggregate peak. Kernel lifetime `memory.peak` is not treated as a trial-window peak.

For S4, a separate approximately 0.5-second sampler covered the web/API container plus the diagnostic process: average 0.135 cores, observed interval peak 1.054 cores, baseline 361.2 MiB and sampled peak 534.8 MiB. These include source-module loading and background web/API work; they are not an incremental per-environment production-worker requirement. BEF and web/API maxima have different sample spacing and must not be added as a proven simultaneous CPU peak. Some service CPU throttling counters increased; causation of preparation latency is unproven.

The existing BEF sampler reported `blocked` for both windows; the terminal commands returned nonzero. Source-call attribution, artifact-byte scope and cold/warm cache provenance were unavailable. CPU/memory observations were present. Preserve that non-acceptance status: neither window proves cold/warm classification, isolated per-generation resource causality, the SC011 gate or production capacity.

Host at measurement: i7-13650HX, 14 physical cores/20 logical CPUs, 15.63 GiB OS-visible RAM; Docker VM exposes 20 CPUs and about 7.56 GiB RAM. A subsequent VM snapshot had about 4.94 GiB MemAvailable; Windows had about 1.9 GiB free. These are transient local-machine observations.

## Architecture findings and safe optimization candidates

- `packages/benchmark-environment/src/preparation-routes.ts` holds an environment advisory lock across fork reset, facilitator recovery and funding. A reset in the currently executing environment would destroy that task's state.
- `packages/owner-identity/src/task-preparation.ts` currently requires a known, sealed, terminalized predecessor with confirmed fencing before beginning successor preparation. Early staging needs a distinct state/authority path; removing those guards is not an optimization.
- `packages/owner-identity/src/bef-task-preparation.ts` binds case payment recipients to the selected environment's facilitator. Equal fork baselines do not make environment B compatible with an A-pinned case. Qualify compatible per-environment cases/execution profiles before alternating.
- Prefetch at most one immediate successor in another leased environment. Keep future content and credentials private, reject participant effects until activation, and switch only after the original predecessor proof and live access checks pass.
- Current BEF generation authority/lifetime begins during preparation. A future staged/active distinction must prevent early tool use and handle expiry explicitly; hidden UI alone is insufficient. The measured 120-second generation lifetime is not a safe universal standby or active-task TTL.
- Independent health/source/local read-only checks are currently sequential and could overlap. RPC batching already exists. Cache only immutable content-addressed release/schema data; preserve current-generation baseline, receipt, permission, capacity and activation checks.
- Warm compatible infrastructure and source-cache reuse could help, but reusing a participant-mutated chain or unverified snapshot cannot replace reset/baseline proof. Windows bind-mount I/O and network waits are hypotheses requiring phase measurements, not established bottlenecks.

## Estimated benefit and resources — unverified projections

Perfectly hiding only the measured inter-task gaps would reduce Full12 from 513.101 to 412.715 seconds (6m53s), and Training from 125.240 to 116.180 seconds (1m56s). This is an arithmetic upper bound assuming unchanged execution, grading and cleanup time and no extra contention. It does not remove the first preparation or predict actual prefetch latency.

Planning range: save about 60–90 seconds on Full12 (roughly 12–18%, 7m03s–7m33s), or 4–7 seconds on Training (about 1m58s–2m01s). No parallel run or optimized implementation has established these gains. Paired same-profile experiments must replace these estimates.

An Anvil/facilitator/local-proxy trio sampled roughly 300 MiB on the active side; configured individual caps total 1.5 GiB per environment (1 GiB + 384 MiB + 128 MiB). Shared API, databases, source proxy, web and evidence buffers are additional. Caps are ceilings, not reserved or measured consumption. A starting experiment budget of 4 vCPU / 8 GiB RAM for one executing and one preparing environment, without a local LLM, is an engineering hypothesis. Measurements were on a twenty-logical-CPU host, not a verified four-vCPU deployment. Neither linear scaling nor 20–30 simultaneous agents is established; the cohort can still use the approved queue.

## Reproduction and retained raw evidence

Run from the repository root, with the existing local stack ready, reviewed pins/secrets available and no active owner run. Do not reset a busy environment. The existing probe rejects non-clear state and fences its own generation in cleanup. Supply secret values only through existing private files. Run a separate sampler before each probe; keep its terminal session active while the probe executes.

```powershell
.venv/Scripts/python.exe tools/bef_resource_sampler.py --duration-seconds 45 --interval-seconds 0.5 --output artifacts/runs/<fresh-resource-output>.json

docker exec -e BEF_API_HOST_PORT=38783 -w /workspace oid-google-local node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/capture-bef-task-preparation.mjs --capture-synthetic-local-bef-env-a

docker exec -e BEF_API_HOST_PORT=38783 -w /workspace oid-google-local node --import ./packages/owner-identity/node_modules/tsx/dist/loader.mjs infrastructure/owner-identity/capture-bef-task-preparation.mjs --capture-synthetic-local-bef-env-a --task-id S4 --mode ranked
```

Record command UTC start/end and exit status independently. The second command selects S1; run S4 separately with a fresh resource window. Never run these two commands concurrently against their hard-coded environment A. Check compatibility against the current checkout before reusing this historical recipe. No account bonus grant, owner run intent, model-provider call or production target is required.

Raw files are ignored local evidence, not committed runtime proof. The tables above preserve the useful summary in Git; a fresh clone needs new measurements or separately restored raw files.

| Retained path (repository-relative) | SHA-256 |
| --- | --- |
| `.local/owner-identity/google-local/qualification-phase-breakdown.json` | `b3035ad601603c5b12eeecf88b9465722e056e48442eaeef97653c8a8ce75d6c` |
| `artifacts/runs/preparation-profile-20261030-s1-01.json` | `bb17f2cff9c11523e0220bc509bc2c0d5de48e116cf6beff3972fc2073d07cb3` |
| `artifacts/runs/preparation-profile-20261030-s4-02.json` | `8deb8439e326e6a8f2fa583719a4a24b72747d89fa2345d6aa33feda9d2a827b` |
| `artifacts/runs/preparation-profile-20261030-s4-02-google-cgroup.txt` | `8ebd17019b714eef432383abd21cb81c18c995d83fc436179f355d65ab40d96d` |
| `artifacts/runs/owner-bef-task-preparation-capture/264a4c47-2298-4139-a142-729d1659291b/capture.json` | `c3cddd7fdbc7c377f33524db8c8af0b6c39307030a221634dff6e0858c768727` |
| `artifacts/runs/owner-bef-task-preparation-capture/fedd6732-35a4-415c-a3a3-2bae920d665d/capture.json` | `0b6f79fd4cb4e9a866c9b6e4ac8031e19217a4a2847fc5e0eb16529b85d2e7a5` |

Existing failure to revisit first: reference-worker capture `f54674d5-178f-4ad4-8f1d-5c04e86d3fc0` cancelled before M3 with `coordinator_preparation_failed`; the underlying cause is unresolved. These successful S1/S4 diagnostics do not close it. See [beta checklist](poc-beta-launch-checklist.md).

Resume by reviewing the [proposed spec](../openspec/changes/task-preparation-prefetch/specs/task-preparation-prefetch/spec.md), [design](../openspec/changes/task-preparation-prefetch/design.md), [BDD packet](../openspec/changes/task-preparation-prefetch/bdd-design.md) and [tasks](../openspec/changes/task-preparation-prefetch/tasks.md), then obtain explicit implementation approval. All proposed prefetch acceptance gates remain `not_run`.
