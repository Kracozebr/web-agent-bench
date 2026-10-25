# BEF feasibility handoff

**Scope:** evidence handoff for change task 7.2, dated 2026-10-25. The active
delta and approved BDD contract remain normative. This report records the final
combined acceptance and its boundaries; it does not make a production-readiness
claim.

## Combined acceptance

The final active-delta run completed with all 12 mandatory environment scenarios
passed, exit code 0, and semantic audit coverage complete (12 approved and 12
protected scenarios, no errors or warnings). The JUnit suite time was 436.856 s;
SC-011's mapper took 109.436 s. Acceptance ran from commit
`8091238a693dcddbb7c4f2560ec5c948ad337714` with a dirty worktree. The harness
source fingerprint was unchanged during the run; that does not mean the whole
worktree was clean.

Acceptance record:
[`acceptance-evidence.json`](../../../../tests/bdd/changes/benchmark-environment-feasibility/acceptance-evidence.json),
SHA-256 `9424ac4db4d8dcea2948ada7c153b6687045204119507671458b961f108f806c`.
The preserved v4 copy under `artifacts/runs/acceptance/` has the same hash.
JUnit:
[`benchmark-environment-feasibility-pytest.xml`](../../../../artifacts/bdd-evidence/benchmark-environment-feasibility-pytest.xml),
SHA-256 `f9497964b8c158450e5552e10324d66840464aa33fb28cfab9ae0c45f62c9533`.
Recorded command:

```text
.venv/Scripts/python.exe -m pytest tests/bdd/mappers/test_benchmark_environment_feasibility_bdd.py --change benchmark-environment-feasibility -q -p no:cacheprovider --junitxml=artifacts/bdd-evidence/benchmark-environment-feasibility-pytest.xml
```

The run bound the following source fingerprints:

| Evidence scope | SHA-256 |
|---|---|
| Active delta | `5abebd1a7189396735d2800808d73b6d0fa0f3abaacbebdbad455a76987415fe` |
| Harness sources, before and after | `0acc92af67991c2154b45aea45a6e95a465c1b3198959aeb42e8c26af9cab283` |
| Harness contracts | `9fdb57dcfe72cd28dd34a3846066ae848d33ceb3baa6fee59d6f43f7d242133d` |
| Scenario map | `f59f07778096f90ad39ee259ec0113dc2bc756632f0b989a33af94609a63f131` |
| Main specs at acceptance time | `bd94686684e0dfbea3bb74cbb186a1b340f69212fe2fd0cd44857ed763f4eb31` |

## Pinned environment and boundary

The versioned
[`manifest.json`](../../../../infrastructure/benchmark-environment/manifest.json)
and SC-011 run copy have SHA-256
`1a3cc1a9843a76317fddd084615b4638afe85723e3f1e4e58535a8b26a7a426c`. It pins
Base source chain 8453 at block `0x32871b4` with hash
`0x8884b44376e007d7e298126e56b88f5b93ad202993ba099938689affc5eda966`, then
executes against two isolated private Anvil environments using Prague. The
selected local payment path is x402 2.28.0 `exact` / EIP-3009 on Base USDC;
Base L1 fees are unmodelled.

The SC-011 runtime capture records Anvil 1.8.6, API and facilitator Node
24.22.1, probe Node 24.14.1, PostgreSQL 18.6, Fastify 5.12.7, viem 2.47.4 and
x402 core/EVM/Fastify 2.28.0. The Node versions refer to separate processes.
The sampled host is containerized Linux x86_64 with cgroup v2, 20 CPUs and
8,120,688,640 bytes of host memory. Manifest limits include 120 seconds per
trial, 900 seconds for SC-011, 1 GiB per Anvil, 768 MiB each for API and
PostgreSQL, 10,000 source calls and 64 MiB evidence per trial, 256 MiB cache
per Anvil, and a 2,000 ms read-overrun bound.
This is a local fork integration result. It does not establish Base mainnet
execution or finality, live-funds safety, production-host capacity, profitability,
or complete Base transaction cost.

## SC-011 observations

The indexed v4 capture is
[`probe.json`](../../../../artifacts/runs/bef-sc011-adapter/bef-sc011-d67d0d3387af4927ae4f19c8f321c2b7/probe.json),
SHA-256 `2cefca27cdca94d85c0029eb815c5edd52676cd7a04623e5fa11b502ae98e1d`. It
binds application source SHA-256
`ece89acb5074057b3ed9f6c2c2b433e97189cafd4380228e49d1fac99b302510`, probe
source SHA-256
`04b1219bf9d7d47f5bc2f18ce5378090af125889c6d9d692129bcefa64ec671d`, and the
manifest above. The orchestration record is
[`orchestration.json`](../../../../artifacts/runs/bef-sc011-adapter/bef-sc011-d67d0d3387af4927ae4f19c8f321c2b7/orchestration.json),
SHA-256 `a4e64bd352757a03952f63e36a6bf94fa23a358ab0895777a94c5e101069bce0`.

Cold and warm sampler windows recorded these values:

| Window | Elapsed | Forwarded source calls | Max RPC cache bytes | CPU seconds (Postgres / Anvil A / Anvil B / API) | Current-window RAM max MiB (same order) |
|---|---:|---:|---:|---:|---:|
| Cold purchase | 19.390 s | 59 | 420 | 0.378 / 0.380 / 0.287 / 0.517 | 187.6 / 20.0 / 60.6 / 97.5 |
| Warm purchase | 10.968 s | 12 | 24,497 | 0.275 / 0.241 / 0.190 / 0.306 | 186.2 / 14.7 / 60.8 / 97.9 |

The sampled cache state directory remained 0 bytes; the observed RPC cache
maxima were below the 256 MiB per-Anvil cache guardrail. The raw sampler's
generic cache-condition field is `unknown`; the SC-011 adapter independently
checks the dedicated cold/warm restart and inventory evidence. CPU and RAM
values are container-window observations, with container activity attribution
unknown; they are not isolated per-operation costs. Source counts are measured
proxy-window totals, not individual-operation attribution. Provider compute
units are unobservable and remain `unknown`.
Sampling begins after Anvil startup, so startup CPU and RAM remain unmeasured.

The read-overrun variant observed 2,172 ms against the 2,000 ms bound; the
process tree was stopped and its exit confirmed. This proves the bounded stop
path, not that the read completed within the limit. The raw collector reports
some metadata as unavailable (`not_established_by_resource_trial_collector`);
that descriptor is not the gate verdict. The SC-011 adapter recomputes the
required predicates from hash-indexed observations, cache/restart evidence,
source counters, stop/fence evidence and the explicit unknown CU observation.
The v4 BEF-SC-011 mapper passed those checks as part of the 12/12 suite.

Raw sampler files and hashes:

- [Cold](../../../../artifacts/runs/bef-sc011-adapter/bef-sc011-d67d0d3387af4927ae4f19c8f321c2b7/cold-purchase/resource-sampler.json) — `b07fc2bf12511a21f0733f1558a24996e030929131e41a07e1c2373ce695d5ae`
- [Warm](../../../../artifacts/runs/bef-sc011-adapter/bef-sc011-d67d0d3387af4927ae4f19c8f321c2b7/warm-purchase/resource-sampler.json) — `05e13363ae56f5a8c9d50309d895f1bb23a232f54b88f3c006cd030eecf7c27d`
- [Read overrun](../../../../artifacts/runs/bef-sc011-adapter/bef-sc011-d67d0d3387af4927ae4f19c8f321c2b7/guardrail-read/resource-sampler.json) — `ff0d1a0f62ab29bab9d2950a2f1e519b5d3df19cc7e600cb75087bc1d7c6073a`

The probe index preserves hashes for the rest of the capture; raw observations
remain under the same run directory.

## Handoff limits

These are mandatory environment/integration gates. They do not exercise a
user-started browser journey through the frontend, backend and durable store;
stage-2 browser-to-database E2E remains a separate delivery gate. BEF's reference
driver also does not prove agent reasoning or score the twelve benchmark-task
rubrics. The benchmark-task-suite still requires its own approved case set,
same-tool reference paths, rubric validation and coordinator/leaderboard
integration; a BEF pass does not authorize publishing closed cases.

This report records acceptance and feasibility evidence for task 7.2. Main-mode
sync/replay traceability and the remaining closeout checks under task 7.3 are
separate evidence and must be completed under the approved OpenSpec lifecycle.

## Synchronized-main acceptance

After synchronization and replay-profile migration, the full main run passed
20 mandatory scenarios (eight baseline local and twelve BEF environment gates)
plus six traceability tests in 260.21 seconds. No scenario was skipped or blocked;
exit code was 0 and the before/after harness-source hashes matched.
Main acceptance: [`acceptance-evidence.json`](../../../../tests/bdd/acceptance-evidence.json),
SHA-256 `2439b5c93a56acc42ce31fe0a7009c1c60878063b6f9ef0b1c7f3f7bdb400c51`.
Harness-source SHA-256:
`801ea1637c80afc8baad1404bc6429812b423964abfc373f135f38b834b099ae`.
Log: `artifacts/runs/bef-main-twenty-gate-acceptance.log`.
The v4 resource table above remains the explicitly identified v4 observation;
the subsequent main run has its own fresh raw captures.

The main replay profile is `synced-main/v1` and binds the synchronized spec,
merged main contract and current verifier sources. Parent replay of the saved
SC004/005 captures matched main predicates without altering any original file.
Python regression checks passed 332 tests (four platform-specific skips, six
subtests passed); TypeScript type checking passed. These are separate from the
mandatory environment acceptance, which had no skips.

The change was archived to
`openspec/changes/archive/2026-10-25-benchmark-environment-feasibility`.
After the move, main mirrors and the 20/20 semantic audit passed, all 332 Python
regressions passed again (the same four platform skips), and both saved real
captures replayed successfully with unchanged original trees. The active BEF
directory was absent during these checks. Current main sources still match the
accepted harness fingerprint. Incoming documentation links were updated and all
archive Markdown links resolve.
