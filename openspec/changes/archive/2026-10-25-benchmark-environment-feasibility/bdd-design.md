# BDD design packet: `benchmark-environment-feasibility`

Workflow: [docs/task-design.md](../../../../docs/task-design.md)

**Status:** Existing twelve-scenario implementation scope authorized on 2026-10-23; see [approval.md](approval.md). Concrete execution configuration remains a prerequisite.
**Normative delta source:** `specs/benchmark-environment-feasibility/spec.md`.
**Target main source after sync:** `openspec/specs/benchmark-environment-feasibility/spec.md`.
**Execution status:** the full acceptance run finished on 2026-10-24 at 10:26:22 UTC with SC001, SC003, SC004, SC005 and SC012 passed and seven mandatory gates blocked by missing implementation/capabilities. See [acceptance evidence](../../../../tests/bdd/changes/benchmark-environment-feasibility/acceptance-evidence.json) and [implementation review](implementation-review.md) for original capture paths, prior failures and recovery evidence. The isolated Compose deployment runs both Anvil environments, PostgreSQL, API, facilitators and read-only proxies. The complete mandatory suite has not passed; blocked gates prevent sync/archive. These are environment gates; browser-to-database product E2E remains delivery stage 2.

## Intent

Later focused execution: SC007 passed all fourteen approved variants in 54.31
seconds (`bef-sc-007-428b28d9a48f4efbaa0e14cc49360f59`), closing tasks 4.1/4.2.
SC006 then passed in 17.98 seconds (`bef-sc-006-6edbb23297124edcab1a4b85a387916a`),
with four operations and 141 indexed artifacts, closing task 3.4.
SC011 passed a fresh full mapper in 140.40 seconds
(`bef-sc011-d8bf6a020d3748a689b54dc757109992`), with two purchase operations and
268 indexed artifacts, closing tasks 6.1/6.2. Source counts
remain aggregate proxy-window observations; provider CU is unknown and startup
CPU/RAM is outside the measurement window.
SC008 then passed in 15.60 seconds
(`bef-sc-008-ceac18cb8e404e5ab1e49beefb683fda`), with six operations and
284 artifacts, closing tasks 4.3/4.4 (17/25 tasks total). It observes actual
successful/reverted gas, original-hash recovery, rejection without a fee and
separate principal/service components; Base L1 fees remain unmodelled.
The complete report above remains historical until the next full acceptance run;
focused execution does not establish the remaining mandatory gates.

Prove the narrow selected environment boundary with actual local settlement and
forked-contract execution, complete reset/isolation, educational gas and bounded
resource observations. This is the first proposed delivery slice, not the full
twelve-task benchmark, user onboarding/billing, a model reasoning test or mainnet
execution/finality evidence.

## Scenario design

All gates are mandatory `environment`. Use actual tool HTTP, pinned x402 services,
durable application operation storage, isolated Anvil execution and receipts.
BEF-SC-009 requires two actual independent environments. BEF-SC-011 requires real
resource sampling; BEF-SC-012 additionally requires actual source RPC reads and
the proxy. A pure Python model, canned settlement response, source fixture or
counter-only mock cannot replace these boundaries.

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BEF-REQ-001 | BEF-SC-001 | Pinned manifest matches actual source and execution | Reviewed private acceptance deployment and manifest / an actual acceptance environment is initialized with the reviewed manifest and source block, contract, local identity or scheme support is missing or mismatched / the gate SHALL verify actual source/runtime/code observations, accept only a matching supported environment and otherwise report the missing or contradictory prerequisite without substituting another block, contract or asset | environment | yes | test_bef_sc_001 | benchmark_environment_http_evm_adapter; manifest_actual_rpc_runtime_code | bdd-harness-proposal.json#BEF-SC-001 | artifacts/runs/acceptance/BEF-SC-001/manifest.json; actual receipts/state/service/resource/source observations as applicable | Prevents incomparable or incompatible environments from being passed by a matching label. |
| BEF-REQ-002 | BEF-SC-002 | Basic tools preserve the reference driver's explicit choices | Reviewed private acceptance deployment and manifest / the declared driver reads balances and offers, requests a quote and explicitly chooses technically valid in-scope operations including task-goal mistakes through authenticated scoped tools / the service SHALL return actual observations and execute the selected operations without goal-based rejection, silent correction or corrective reset, preserve chosen parameters and attributable effects or genuine protocol failures for evaluation, and record technical signing/approval and explicitly selected conversions without claiming agent reasoning or full task grading | environment | yes | test_bef_sc_002 | benchmark_environment_http_evm_adapter; actual_tool_http_evm_services | bdd-harness-proposal.json#BEF-SC-002 | artifacts/runs/acceptance/BEF-SC-002/manifest.json; actual receipts/state/service/resource/source observations as applicable | Protects the benchmark's assessment of participant decisions rather than a hidden platform solver. |
| BEF-REQ-002 | BEF-SC-003 | Participant requests cannot reach setup or foreign execution | Reviewed private acceptance deployment and manifest / the caller submits a foreign environment or generation, arbitrary URL, raw signing or transaction payload, or administrative method through participant routes / the service SHALL reject the unauthorized request before signing or setup/execution and record the denial and unchanged protected state without treating caller-supplied identifiers as authority | environment | yes | test_bef_sc_003 | benchmark_environment_http_evm_adapter; actual_tool_scope_admin_boundary | bdd-harness-proposal.json#BEF-SC-003 | artifacts/runs/acceptance/BEF-SC-003/manifest.json; actual receipts/state/service/resource/source observations as applicable | Prevents a participant tool from changing another task or the private setup boundary. |
| BEF-REQ-003 | BEF-SC-004 | Offer inspection neither pays nor delivers purchased data | Reviewed private acceptance deployment and manifest / the driver inspects the selected controlled x402 resource and its payment requirements without authorizing a purchase / the service SHALL expose the declared offer and payment requirements while observed token balances, settlement records and purchased-data delivery remain unchanged | environment | yes | test_bef_sc_004 | benchmark_environment_http_evm_adapter; actual_resource_http_local_evm | bdd-harness-proposal.json#BEF-SC-004 | artifacts/runs/acceptance/BEF-SC-004/manifest.json; actual receipts/state/service/resource/source observations as applicable | Distinguishes unpaid discovery from paid access and avoids charging harmless offer inspection. |
| BEF-REQ-003 | BEF-SC-005 | Selected x402 purchase settles locally and delivers verified data | Reviewed private acceptance deployment and manifest / the driver selects a valid offer and authorizes the pinned asset and scheme through the actual local verification and settlement implementation / paid success SHALL require correlated requirements, operation identity, actual local receipt and exact token effects plus the declared data hash, with successful delivery withheld until the declared settlement check succeeds | environment | yes | test_bef_sc_005 | benchmark_environment_http_evm_adapter; actual_x402_local_settlement_delivery | bdd-harness-proposal.json#BEF-SC-005 | artifacts/runs/acceptance/BEF-SC-005/manifest.json; actual receipts/state/service/resource/source observations as applicable | Proves the selected x402 integration settles and delivers instead of returning a verification stub. |
| BEF-REQ-003 | BEF-SC-006 | Payment recovery preserves one effect under duplicates and uncertainty | Reviewed private acceptance deployment and manifest / invalid or mismatched payment is submitted, an accepted response is lost, concurrent duplicates retry, or the original local settlement observation becomes temporarily unavailable / the service SHALL deny invalid payment without paid delivery, recover accepted requests by their original identity, preserve one settlement and one logical delivery and leave unresolved evidence unknown without a replacement debit | environment | yes | test_bef_sc_006 | benchmark_environment_http_evm_adapter; actual_x402_http_evm_durable_recovery | bdd-harness-proposal.json#BEF-SC-006 | artifacts/runs/acceptance/BEF-SC-006/manifest.json; actual receipts/state/service/resource/source observations as applicable | Protects against duplicate simulated spending and false success after ambiguous network responses. |
| BEF-REQ-004 | BEF-SC-007 | Selected forked-pool swap proves actual constrained effects | Reviewed private acceptance deployment and manifest / the driver chooses a declared exchange and explicit wrap/unwrap actions through the selected actual forked contracts, with valid and invalid asset, route, recipient, output, reserve or unconverted-WETH variants / successful constrained exchange SHALL require local receipts/events and actual input/output/recipient/allowance/reserve observations plus selected conversion parameters and distinct native ETH/WETH balances; tools SHALL perform no automatic conversion or count WETH as an ETH target or gas reserve, technically valid task-goal mistakes SHALL retain their observed mismatches, security-boundary violations SHALL reject before execution and genuine contract failures SHALL retain actual reverted effects without treating a quote or toy market as completed exchange | environment | yes | test_bef_sc_007 | benchmark_environment_http_evm_adapter; actual_tool_http_fork_contract | bdd-harness-proposal.json#BEF-SC-007 | artifacts/runs/acceptance/BEF-SC-007/manifest.json; actual receipts/state/service/resource/source observations as applicable | Proves an actual forked exchange meets declared constraints rather than merely obtaining a quote. |
| BEF-REQ-005 | BEF-SC-008 | Observed successful and reverted gas uses the pinned educational model | Reviewed private acceptance deployment and manifest / successful transactions, actually executed reverted transactions and unexecuted rejected requests are evaluated under the manifest fee and valuation policy / the model SHALL count observed executed costs once with actual payer attribution, invent no fee for an uncharged unexecuted request, keep missing costs unknown, separate principal/service components and label Base L1 fees unmodelled | environment | yes | test_bef_sc_008 | benchmark_environment_http_evm_adapter; actual_receipts_balances_cost_evaluator | bdd-harness-proposal.json#BEF-SC-008 | artifacts/runs/acceptance/BEF-SC-008/manifest.json; actual receipts/state/service/resource/source observations as applicable | Protects consistent educational budgets and prevents invented or double-counted expenses. |
| BEF-REQ-006 | BEF-SC-009 | Two active environments cannot mutate or reset one another | Reviewed private acceptance deployment and manifest / two independent actual environments execute and one is reset while the other retains admitted operations and changed state / each SHALL preserve its own chain and service/payment/delivery state and reject cross-environment access, with observed balances/nonces/allowances and operation records proving no shared mutable reset effect | environment | yes | test_bef_sc_009 | benchmark_environment_http_evm_adapter; two_actual_nodes_services_isolation | bdd-harness-proposal.json#BEF-SC-009 | artifacts/runs/acceptance/BEF-SC-009/manifest.json; actual receipts/state/service/resource/source observations as applicable | Tests the independence needed for fair simultaneous task environments. |
| BEF-REQ-006 | BEF-SC-010 | Reset restores equivalent starts and fences stale work | Reviewed private acceptance deployment and manifest / a completed trial is reset or recreated, stale-generation work arrives and a new separately identified trial repeats the declared probes / the service SHALL reject stale work, restore actual relevant chain and off-chain baseline observations and logical fixture hash and permit the new trial without leaking prior payment/delivery state, while labelling repeated execution separately from replay | environment | yes | test_bef_sc_010 | benchmark_environment_http_evm_adapter; actual_chain_service_reset_generation | bdd-harness-proposal.json#BEF-SC-010 | artifacts/runs/acceptance/BEF-SC-010/manifest.json; actual receipts/state/service/resource/source observations as applicable | Protects identical logical starts and prevents stale work from altering a new trial. |
| BEF-REQ-007 | BEF-SC-011 | Cold and warm trials produce bounded actual resource evidence | Reviewed private acceptance deployment and manifest / declared cold and warm actual probe trials run with dedicated cache state, resource sampling and numeric guardrails, including a bounded over-limit variant / the gate SHALL record actual host/limits, elapsed time, CPU, peak RAM, cache/artifact sizes and source requests, report unavailable CU as unknown, stop safely on exceeded bounds and block success on missing required observations without claiming production capacity | environment | yes | test_bef_sc_011 | benchmark_environment_resource_adapter; actual_process_container_cache_source_measurement | bdd-harness-proposal.json#BEF-SC-011 | artifacts/runs/acceptance/BEF-SC-011/manifest.json; actual receipts/state/service/resource/source observations as applicable | Produces bounded resource evidence before estimating infrastructure cost or capacity. |
| BEF-REQ-008 | BEF-SC-012 | Source proxy and evidence keep execution local and replay read-only | Reviewed private acceptance deployment and manifest / the actual source RPC is checked for pinned chain/block/code provenance, prohibited outbound methods are submitted to the proxy and original redacted evidence is replayed / the proxy SHALL forward only declared reads, reject submission/admin/signing without external forwarding and retain attributable sanitized paths/hashes; replay SHALL compare original observations without broadcast, with missing provenance or evidence remaining blocked or unknown | environment | yes | test_bef_sc_012 | benchmark_source_rpc_evidence_adapter; actual_source_rpc_proxy_evidence_replay | bdd-harness-proposal.json#BEF-SC-012 | artifacts/runs/acceptance/BEF-SC-012/manifest.json; actual receipts/state/service/resource/source observations as applicable | Prevents real-network writes and preserves the exact provenance and safe replay scope of evidence. |

## Semantic harness contract

[bdd-harness-proposal.json](bdd-harness-proposal.json) is the review inventory.
Each scenario declares named observations, negative/adversarial variants and
durable effects. On approved implementation, add those contracts to the runtime
registry alongside the executable mirror, mapper and adapters; inventory presence
alone is not semantic evidence. No private production call exceptions are proposed.

## Execution design

- Reuse the repository's Python pytest-bdd, traceability, semantic audit and
  evidence conventions. Active-delta selection must be implemented/reused as
  described in the run-lifecycle packet before claiming these gates executable;
  do not sync an unverified delta merely to satisfy existing main-only tooling.
- Proposed new mirror: `tests/bdd/features/benchmark_environment_feasibility.feature`.
- Proposed mapper: `tests/bdd/mappers/test_benchmark_environment_feasibility_bdd.py`.
- Proposed adapter module: `tests/bdd/adapters/benchmark_environment_feasibility.py`,
  exposing the three named adapter profiles in the table. Keep reusable step
  bindings declarative; actual I/O and observations belong in the adapters.
- Actual prerequisites: selected container/runtime deployment, source RPC,
  reviewed pinned block/contracts/assets/scheme/SDK/tool schemas, numeric
  guardrails, educational gas/rate/payer policy, isolated test keys, local
  settlement/resource services, durable application store and resource sampling.
- Private setup/fault controls remain acceptance-admin-only and record their
  provenance; participant routes cannot invoke them. Fault injection may delay
  an actual receipt or response; it cannot fabricate a passing payment effect.
- Cold trials use dedicated disposable caches. Guardrails stop admissions/work
  safely, fence workers and retain evidence before task-owned cleanup.
- Replay reads recorded observations only. A repeated probe after reset is a new
  trial with its own manifest/identity; it is not replay.
- Missing prerequisites/observations produce `blocked`; actual violated assertions
  produce `failed`. Mandatory blocked/skipped/not-run gates prevent sync/archive.
  The current per-scenario result is recorded in the linked acceptance evidence;
  no passing runtime result is asserted by this design document.

## Learning-error observations

For BEF-SC-002/007, submit technically valid wrong-test-recipient, task-expense-budget and excess-test-allowance variants within the pinned local surface. Observe unchanged selected parameters, actual effects/costs and mismatch evidence without goal-based pre-rejection, automatic repair or corrective reset. These probes report consequences, not a full twelve-task scoring implementation. Contrast with actual schema/protocol failures, contract reverts and BEF-SC-003 protected-boundary denials; retain no-effect evidence for denied protected operations. No real service balance cap is waived.

## Explicit ETH/WETH observations

BEF-SC-007 uses actual pinned WETH code, separately identified native/token balances and driver-selected wrap/unwrap direction and amount. Exercise actual wrap and unwrap in separately identified variants, missing/incorrect conversion, WETH-only holdings against a native-ETH goal/reserve, genuine conversion failure and no automatic correction by the swap/signer. Retain conversion receipts/parameters, final native/token balances, observed gas and goal-mismatch evidence. This adds no full-rubric claim or blanket zero penalty, and reference action lengths remain unverified.

## Approval boundary

Approval covers only the reviewed twelve scenarios, named real boundaries,
negative variants, minimal acceptance deployment and corresponding proposed code
scope. Pin the listed exact environment/guardrail configuration before execution.
A changed payment asset/scheme boundary, new scenario or changed assertion returns
for review. No real source-network transaction, customer wallet, CDP operation or
production deployment is within this packet.

**Decision:** implementation authorized for the existing twelve scenarios; mandatory runtime gates have not passed. See [approval.md](approval.md).
**Decision reference:** the user confirmed distinct ETH/WETH assets and explicit agent-selected wrap/unwrap without automatic swap conversion; WETH alone cannot satisfy an ETH target or native gas reserve. Technically valid learning mistakes execute within isolated test state and their observed consequences are evaluated, while service/admin/foreign-run/real-fund and hard infrastructure boundaries remain enforced. The later implementation authorization for the existing twelve-scenario scope is recorded in [approval.md](approval.md).

## Downstream scope clarification

The twelve existing feasibility scenarios remain unchanged. benchmark-task-suite consumes their actual manifest/effect evidence; this purchase/swap probe cannot establish twelve-rubric grading or replace BTS gates. Mandatory blocked gates prevent sync and archive.
