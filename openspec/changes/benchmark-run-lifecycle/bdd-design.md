# BDD design packet: `benchmark-run-lifecycle`

Workflow: [docs/task-design.md](../../../docs/task-design.md)

**Status:** Approved for incremental implementation; see [approval.md](approval.md). Runtime gates remain separate.
**Normative delta source:** `specs/benchmark-run-lifecycle/spec.md` (proposed active delta).
**Target main source after sync:** `openspec/specs/benchmark-run-lifecycle/spec.md`.
**Execution status:** all 25 mandatory scenarios are `not_run`; no new test/adapter/implementation file exists.

The user confirmed current UTC-day budget/permission checks at start with the
unchanged quote and exclusion of proven platform recovery intervals from task/run
clocks, explicit owner revocation as cancellation, and one active run per agent
across ranked/training modes. These are product decisions, not approval of the
complete scenario/assertion inventory. BRL-SC-019 adds the slot/restart/handoff
boundary; prior IDs remain stable.

## Intent

**Goal:** verify durable run transitions, fee/budget effects, sequential tasks, clocks,
reconnect, evidence recovery and mode-specific feedback at their real boundaries.

**Non-goals:** production Google integration, universal client compatibility, complete task rubrics, public leaderboard
selection, mainnet custody/withdrawals, forum, PvP and full UI beyond the scoped launch/status flow. Local Anvil observations
prove only the declared local EVM fixture. Eligibility output is not a published ranking.

## Approved client-profile selection

The existing BRL launch/client boundaries may use Codex CLI 0.165.0 with MCP
2025-06-18 through the existing owner-issued manual bearer route, but only under
the explicitly selected local BEF/loopback profile. The 2026-07-28 strict profile
remains the default. This records the selected client configuration within the
existing scenarios; it adds no scenario ID, assertion, negative variant or
contract change. The configuration and this documentation do not mark a runtime
gate as passed.

## Scenario design

All gates below are mandatory `environment` gates. The semantic boundary enum is
`environment`; the boundary detail names the actual API/database/executor combination.
The shared adapter is a planned HTTP/real-boundary adapter, not an in-memory model.

| Requirement ID | Scenario ID | Scenario title | Given / When / Then | Gate | Mandatory | Named mapper | Adapter | Harness contract | Evidence | Why this test is required |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BRL-REQ-001 | BRL-SC-001 | Queue admission preserves the quoted price and run identity | Isolated declared acceptance deployment / an authorized agent queues ranked and training requests against the active catalog and an administrator later changes prices including zero to paid or activates a new benchmark version before queued start or same-request retry / each admitted run SHALL retain its original price selection exposure open-weight denominator pinned benchmark/environment declared version policy and UTC reservation identity without queued charging or execution time; new training quotes SHALL use only open IDs and denominator 15 while activation alone neither cancels nor retargets admitted work and identical authorized retries recover original snapshots | environment | yes | test_brl_sc_001 | benchmark_run_lifecycle_http_adapter; admission_api_postgres | bdd-harness-proposal.json#BRL-SC-001 | artifacts/runs/acceptance/BRL-SC-001/manifest.json; committed state/observations | Protects the selected fixed-price and reproducible-identity contract. |
| BRL-REQ-001 | BRL-SC-002 | Admission rejects an unauthorized agent or invalid task selection | Isolated declared acceptance deployment / a caller uses missing foreign or insufficient-scope credentials requests an invalid selection including any closed training ID alone or mixed with open IDs or requests a new nonactive-version run while admission races activation / admission SHALL reject the request without creating a run, reservation or readable foreign run data | environment | yes | test_brl_sc_002 | benchmark_run_lifecycle_http_adapter; admission_api_postgres | bdd-harness-proposal.json#BRL-SC-002 | artifacts/runs/acceptance/BRL-SC-002/manifest.json; committed state/observations | Protects owner isolation and complete ranked inventory. |
| BRL-REQ-002 | BRL-SC-003 | Admission retries preserve one operation and reject conflicting payloads | Isolated declared acceptance deployment / the same admission key is retried after a lost response and process restart and is then reused with a different selection or mode / the original request SHALL return the same run and reservation while the conflicting request is rejected without another financial effect | environment | yes | test_brl_sc_003 | benchmark_run_lifecycle_http_adapter; admission_api_postgres | bdd-harness-proposal.json#BRL-SC-003 | artifacts/runs/acceptance/BRL-SC-003/manifest.json; committed state/observations | Protects retry safety for chargeable agent commands. |
| BRL-REQ-002 | BRL-SC-004 | Concurrent admissions cannot overdraw shared funds or agent caps | Isolated declared acceptance deployment / two agent requests race for the same owner funds or an operation, UTC daily or benchmark category limit is exhausted / only admissible reservations SHALL commit and no committed combination may exceed shared available funds or the applicable agent limits | environment | yes | test_brl_sc_004 | benchmark_run_lifecycle_http_adapter; admission_api_postgres | bdd-harness-proposal.json#BRL-SC-004 | artifacts/runs/acceptance/BRL-SC-004/manifest.json; committed state/observations | Protects the selected shared balance and individual budget limits. |
| BRL-REQ-003 | BRL-SC-005 | Start atomically charges once and activates the first task | Isolated declared acceptance deployment / a queued run has a prepared execution environment and duplicate start deliveries occur before, at or after its persisted queue deadline around a coordinator restart / only a ready run with an unexpired queue deadline SHALL commit one debit and one first-task activation with the execution start time; unready preparation SHALL remain uncharged and untimed, and an unstarted request at or after its queue deadline SHALL expire with source-preserving cash/bonus hold release and no first task or automatic resubmit even if the expiry job was delayed | environment | yes | test_brl_sc_005 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_executor | bdd-harness-proposal.json#BRL-SC-005 | artifacts/runs/acceptance/BRL-SC-005/manifest.json; committed state/observations | Protects the selected charge-at-start boundary. |
| BRL-REQ-003 | BRL-SC-006 | Concurrent start and cancellation choose one durable outcome | Isolated declared acceptance deployment / start, queue expiry and cancellation including explicit owner revocation race on a queued or preparing run and responses are retried / the authoritative transition/deadline check SHALL select one pre-start terminal release with no task or a valid before-deadline start with one charge subject to later cancellation rules, never both financial outcomes; a queue-expiry delivery after valid start SHALL NOT cancel the run, release its charge or reset execution clocks | environment | yes | test_brl_sc_006 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_executor | bdd-harness-proposal.json#BRL-SC-006 | artifacts/runs/acceptance/BRL-SC-006/manifest.json; committed state/observations | Protects the pre-start versus post-start refund rule under concurrency. |
| BRL-REQ-003 | BRL-SC-019 | One agent execution slot serializes ranked and training runs across restart | Isolated declared acceptance deployment / ranked/training requests across multiple owners and agents compete for free capacity across scheduler workers and restart while predecessors run, recover or cancel, including an owner's busy-agent head request and another eligible request / only one run per agent SHALL own its slot and waiters SHALL remain uncharged and untimed; free capacity SHALL alternate eligible owners and choose each owner's oldest eligible request without head blocking or preempting working runs, preserve durable turn/claim identity across retry/restart, allow spare capacity for the sole eligible owner within existing bounds, and require stopped/fenced predecessors without letting stale callbacks release successor slots | environment | yes | test_brl_sc_019 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_executor_slot | bdd-harness-proposal.json#BRL-SC-019 | artifacts/runs/acceptance/BRL-SC-019/manifest.json; committed state/observations | Protects the selected one-active-run rule without charging waiters or allowing stale-worker overlap. |
| BRL-REQ-004 | BRL-SC-007 | UTC rollover rechecks budgets without changing the quote | Isolated declared acceptance deployment / a queued run crosses midnight UTC before start or its earlier charge is later refunded on another UTC day / the coordinator SHALL re-admit the start against the current UTC day's caps at the original quote or reject before start without charge, and a refund SHALL reference the original charge bucket without adding allowance to the new day | environment | yes | test_brl_sc_007 | benchmark_run_lifecycle_http_adapter; budget_postgres_clock | bdd-harness-proposal.json#BRL-SC-007 | artifacts/runs/acceptance/BRL-SC-007/manifest.json; committed state/observations | Makes the selected UTC-day caps concrete across queued starts and refunds. |
| BRL-REQ-005 | BRL-SC-008 | Only the current task accepts actions in the pinned order | Isolated declared acceptance deployment / ranked and selected training runs advance through their task inventory and a caller tries a future, completed or foreign run task / the coordinator SHALL issue only the next configured task on independent executor state and reject out-of-order or foreign task actions without changing another task | environment | yes | test_brl_sc_008 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil | bdd-harness-proposal.json#BRL-SC-008 | artifacts/runs/acceptance/BRL-SC-008/manifest.json; committed state/observations | Protects sequential task delivery and independent task state. |
| BRL-REQ-005 | BRL-SC-009 | Ordinary operation errors allow recovery but mandatory violations retain zero credit | Isolated declared acceptance deployment / an active task reports an ordinary error or a forbidden request verifiably rejected before execution and the agent retries without reset, while another task produces a verified actual mandatory violation or an attempt explicitly forbidden by published criteria / the coordinator SHALL preserve the first task state for further permitted work and record the rejected unsafe attempt separately without automatic outcome zero, retain zero credit for the violated task without allowing a corrective reset, and continue the remaining independent tasks | environment | yes | test_brl_sc_009 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil | bdd-harness-proposal.json#BRL-SC-009 | artifacts/runs/acceptance/BRL-SC-009/manifest.json; committed state/observations | Protects ordinary retry and mandatory-constraint semantics without changing task rubrics. |
| BRL-REQ-006 | BRL-SC-010 | Reconnect preserves deadlines and rejects late or foreign actions | Isolated declared acceptance deployment / an agent reconnects after transport loss or coordinator restart before or after its persisted deadline and a different agent requests the run / the original agent SHALL receive the same run state and remaining time without deadline reset while expired or unauthorized mutation is rejected and ordinary disconnection does not pause time | environment | yes | test_brl_sc_010 | benchmark_run_lifecycle_http_adapter; coordinator_api_postgres_clock | bdd-harness-proposal.json#BRL-SC-010 | artifacts/runs/acceptance/BRL-SC-010/manifest.json; committed state/observations | Protects the selected reconnect/time policy and access boundary. |
| BRL-REQ-006 | BRL-SC-011 | Task expiry evaluates observed effects while overall expiry remains incomplete | Isolated declared acceptance deployment / a per-task deadline or overall run deadline expires with verified, pending or missing task evidence / the coordinator SHALL stop new actions, request evaluation or evidence reconciliation for admitted effects, continue after a known per-task outcome when overall time remains, and mark an unfinished overall-expired run unranked without inventing zero outcomes | environment | yes | test_brl_sc_011 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil_clock | bdd-harness-proposal.json#BRL-SC-011 | artifacts/runs/acceptance/BRL-SC-011/manifest.json; committed state/observations | Protects both selected time-limit levels without conflating missing evidence and task failure. |
| BRL-REQ-007 | BRL-SC-012 | Pre-start cancellation releases one reservation and executes no task | Isolated declared acceptance deployment / a queued or preparing run reaches its waiting deadline or is cancelled directly, by agent-wide owner revocation or by owner removal of its run-mode permission, and delivery, request retry or cleanup repeats after restart / the coordinator SHALL record the matching pre-start expiry or cancellation reason without a debit, release original cash/bonus/budget holds once without extending grant expiry, and prevent task execution, duplicate release or automatic resubmit; revocation SHALL fence affected actions before cleanup, mode removal SHALL preserve unrelated modes, and retry or re-enabling SHALL not reopen terminal requests or release a successor's slot | environment | yes | test_brl_sc_012 | benchmark_run_lifecycle_http_adapter; coordinator_api_postgres_executor | bdd-harness-proposal.json#BRL-SC-012 | artifacts/runs/acceptance/BRL-SC-012/manifest.json; committed state/observations | Protects free cancellation before the first task. |
| BRL-REQ-007 | BRL-SC-013 | Voluntary post-start cancellation retains the charge and excludes ranking | Isolated declared acceptance deployment / an owner or scoped agent cancels an already started run directly, or the owner revokes agent access or removes its run-mode permission, and late actions, reauthorization or duplicate cancellation delivery follow / the coordinator SHALL retain the single charge, reject new affected task actions, preserve evidence of admitted effects and mark the incomplete run unranked without a voluntary-cancellation refund; mode removal SHALL preserve unrelated modes and reauthorization SHALL NOT reopen the cancelled run | environment | yes | test_brl_sc_013 | benchmark_run_lifecycle_http_adapter; coordinator_api_postgres_executor | bdd-harness-proposal.json#BRL-SC-013 | artifacts/runs/acceptance/BRL-SC-013/manifest.json; committed state/observations | Protects the selected post-start cancellation payment rule. |
| BRL-REQ-008 | BRL-SC-014 | Evidence recovery observes an existing effect without executing it again | Isolated declared acceptance deployment / an action has an uncertain response after an actual local EVM effect and infrastructure recovery obtains its original receipt and state / the coordinator SHALL reconcile that same action and transaction into the run without resubmitting it, retain the original evidence and record any platform-recovery clock adjustment explicitly | environment | yes | test_brl_sc_014 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil_recovery | bdd-harness-proposal.json#BRL-SC-014 | artifacts/runs/acceptance/BRL-SC-014/manifest.json; committed state/observations | Protects recovery without accidental replay of economic actions. |
| BRL-REQ-008 | BRL-SC-015 | Unrecoverable infrastructure evidence excludes the run and refunds once | Isolated declared acceptance deployment / a platform-attributed evidence failure cannot be resolved within the pinned recovery window and terminal recovery is retried / the coordinator SHALL retain explicit unknown evidence, exclude the run from ranking and issue one internal refund linked to its debit, without turning later observations into a new official result automatically | environment | yes | test_brl_sc_015 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil_recovery | bdd-harness-proposal.json#BRL-SC-015 | artifacts/runs/acceptance/BRL-SC-015/manifest.json; committed state/observations | Protects the selected unrecoverable-platform-failure refund and ranking policy. |
| BRL-REQ-009 | BRL-SC-016 | Training and ranked feedback use different release points | Isolated declared acceptance deployment / an open training subset and ranked run with closed tasks complete tasks while clients request feedback before and after termination / open training SHALL expose post-task explanations while ranked scores and reasons wait until termination and closed feedback contains only score and allowed reason category without exact case parameters solution coaching or journal while normal scoped tool responses remain immediate | environment | yes | test_brl_sc_016 | benchmark_run_lifecycle_http_adapter; coordinator_api_postgres_feedback | bdd-harness-proposal.json#BRL-SC-016 | artifacts/runs/acceptance/BRL-SC-016/manifest.json; committed state/observations | Protects the selected training/ranked feedback distinction. |
| BRL-REQ-009 | BRL-SC-017 | Only complete verified ranked runs produce an immutable eligibility handoff | Isolated declared acceptance deployment / ranked or training runs finish with complete verified, incomplete or unknown outcomes and the owner later edits the public agent version metadata / only the complete verified ranked terminal transaction SHALL atomically preserve or establish the shared first-public-action marker and emit one eligibility handoff containing all task outcomes and immutable run-version identity, while excluded runs retain explicit reasons and later profile edits do not rewrite its achieved version | environment | yes | test_brl_sc_017 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_result_handoff | bdd-harness-proposal.json#BRL-SC-017 | artifacts/runs/acceptance/BRL-SC-017/manifest.json; committed state/observations | Protects complete-run eligibility and best-result version provenance; leaderboard selection is downstream. |
| BRL-REQ-010 | BRL-SC-018 | Audit records retain ordered transitions and original evidence across restart | Isolated declared acceptance deployment / a run is retried, restarted and reconciled and its recorded bundle is reconstructed with a changed event or missing evidence artifact / the audit output SHALL preserve ordered event identities, source and payload hashes, raw evidence references and the declared execution boundary, and report divergence or missing evidence without rewriting the original bundle | environment | yes | test_brl_sc_018 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_artifact_store | bdd-harness-proposal.json#BRL-SC-018 | artifacts/runs/acceptance/BRL-SC-018/manifest.json; committed state/observations | Extends the existing evidence-first identity/replay contract to the durable coordinator. |
| BRL-REQ-005 | BRL-SC-020 | Explicit finish and deadline share one evidence-based task closure | Isolated declared acceptance deployment / the scoped agent explicitly finishes an active task while new actions, duplicate finish requests and its deadline race, with an already admitted local EVM action still awaiting observation and a foreign agent requesting finish / the coordinator SHALL establish one durable action cutoff, reject later and foreign actions, reconcile the originally admitted effects without resubmission and evaluate once from the supported completion state and retained violations; agent-supplied scores SHALL have no authority and duplicate closure SHALL not activate another task twice | environment | yes | test_brl_sc_020 | benchmark_run_lifecycle_http_adapter; coordinator_postgres_anvil_finish | bdd-harness-proposal.json#BRL-SC-020 | artifacts/runs/acceptance/BRL-SC-020/manifest.json; committed state/observations | Protects explicit completion, deadline races, evidence reconciliation and independent scoring. |
| BRL-REQ-011 | BRL-SC-021 | Verified interference disqualifies the current run without another financial effect | Isolated declared acceptance deployment with a controlled validated integrity-observer fixture / an authenticated integrity observer supplies a validated run-bound finding of successful service-state or cross-run interference during a started run and duplicate findings, actions and worker restart follow / the coordinator SHALL persist one disqualified terminal outcome, fence new run actions and exclude ranking while retaining the original source-linked charge without refund or extra debit, preserve finding and admitted-effect evidence, and leave other owners' accounting untouched | environment | yes | test_brl_sc_021 | benchmark_run_lifecycle_http_adapter; coordinator_http_postgres_validated_integrity_finding | bdd-harness-proposal.json#BRL-SC-021 | artifacts/runs/acceptance/BRL-SC-021/manifest.json; real coordinator/database and declared observer-fixture evidence | Protects evidence-based whole-run disqualification and prevents unproven punitive effects. |
| BRL-REQ-011 | BRL-SC-022 | Claims blocked attempts and unknown evidence do not establish disqualification | Isolated declared acceptance deployment with a controlled validated integrity-observer fixture / agent claims, forged or incomplete observer findings, a verified pre-execution rejection and conflicting integrity observations reach the coordinator / unverified or foreign findings SHALL not establish interference or change billing, an ordinary blocked attempt SHALL follow its published task rule, and unresolved observations affecting result validity SHALL enter reconciliation without false success, fabricated task zero or blind action replay | environment | yes | test_brl_sc_022 | benchmark_run_lifecycle_http_adapter; coordinator_http_postgres_integrity_validation_recovery | bdd-harness-proposal.json#BRL-SC-022 | artifacts/runs/acceptance/BRL-SC-022/manifest.json; real coordinator/database and declared observer-fixture evidence | Protects evidence-based whole-run disqualification and prevents unproven punitive effects. |
| BRL-REQ-012 | BRL-SC-023 | Agent acceptance creates one run from one private launch intent | Dedicated actual application with synthetic verified identities and pinned dependencies / an owner creates a launch intent and its matching authorized agent accepts after preflight with duplicate caller keys over HTTP and MCP around response loss restart later expiry price changes and version activation / pending intent and preflight SHALL remain free unqueued and private, the first valid acceptance SHALL atomically link one normally reserved run at the reviewed quote and cash ceiling, and authorized matching retries SHALL recover that run without a second reservation repricing deadline renewal or model execution | environment | yes | test_brl_sc_023 | benchmark_run_lifecycle_http_adapter; actual_owner_agent_http_mcp_postgres_launch_admission | bdd-harness-proposal.json#BRL-SC-023 | artifacts/runs/acceptance/BRL-SC-023/manifest.json; actual declared boundary observations | Protects one reviewed financial admission from duplicate launch handoffs across transports and restart. |
| BRL-REQ-012 | BRL-SC-024 | Stale foreign expired or cancelled launch intents cannot admit work | Dedicated actual application with synthetic verified identities and pinned dependencies / an intent is accepted with foreign owner or agent authority changed selection tariff benchmark quote cash need or permissions at or after expiry while owner cancellation and acceptance race / only an unchanged currently authorized before-expiry pending intent SHALL admit one run; rejection or a winning pending cancellation SHALL create no run or holds and expose no foreign data, while a winning admission SHALL retain its run identity and subsequent cancellation SHALL follow ordinary run billing rather than undo admission for free | environment | yes | test_brl_sc_024 | benchmark_run_lifecycle_http_adapter; actual_launch_authorization_deadline_quote_and_cancel_transactions | bdd-harness-proposal.json#BRL-SC-024 | artifacts/runs/acceptance/BRL-SC-024/manifest.json; actual declared boundary observations | Protects authorization quote cash bounds and cancellation/expiry ordering before any launch financial effects. |
| BRL-REQ-012 | BRL-SC-025 | Actual browser and selected client distinguish handoff from execution | Dedicated actual application with synthetic verified identities and pinned dependencies / the actual owner browser starts a repeat launch through a pinned compatible external client or copy-request fallback and the agent preflights accepts or never responds while pages reload and navigate back / real private pages SHALL show waiting without queue reservation before admission and the actual linked run afterward, preserve one handoff identity across retries, keep secrets out of links and prompts, count fallback setup and client approvals honestly and claim a one-to-two-action repeat path only with actual selected-client evidence | environment | yes | test_brl_sc_025 | benchmark_launch_browser_client_adapter; actual_owner_browser_pinned_external_client_mcp_and_store | bdd-harness-proposal.json#BRL-SC-025 | artifacts/runs/acceptance/BRL-SC-025/manifest.json; actual declared boundary observations | Protects honest actual-client handoff/status and action-count claims without secrets or a hosted model. |

## Semantic harness contract

`bdd-harness-proposal.json` is a review artifact, not the runtime manifest and not
executed tests. Each scenario names boundary detail, required observations,
negative/adversarial variants, durable effects and evidence mode. No private-call
exceptions are proposed. Approved contracts are registered separately in
`tests/bdd/changes/benchmark-run-lifecycle/harness-contracts.json`, preserving baseline
contracts and pinning the snapshot from the selected normative source. Inventory-only
coverage does not satisfy a gate: real adapter observations must be present.

## Execution design

- Existing reusable bindings: `tests/bdd/conftest.py`, adapter registry and
  `tools/check_bdd_harness.py`; current generation/evidence tools read main specs.
- Approved implementation must add an explicit active-delta source selector across
  generation, semantic audit and acceptance evidence, retain baseline requirements,
  and migrate source references during sync. Do not sync first to bypass this work.
- Planned mapper module: `tests/bdd/mappers/test_benchmark_run_lifecycle_bdd.py`;
  planned adapter: `tests/bdd/adapters/benchmark_run_lifecycle.py`; each named
  mapper in the table binds exactly the matching delta title/WHEN/THEN.
- Real deployment: selected Fastify application, PostgreSQL with actual transactions,
  coordinator worker and durable artifact volume. Actual local Anvil plus a tiny
  counter/constraint test contract is mandatory for SC-008, SC-009, SC-011, SC-014
  and SC-015. This is not a Base fork fixture or a financial/mainnet gate.
- Known evaluator results in pure lifecycle scenarios are controlled versioned
  evaluator-port inputs, not evidence that all twelve rubrics work. Anvil-specific
  scenarios independently observe receipts and contract state. Implementing the
  production task evaluators is outside approval scope.
- Use authenticated synthetic owner/agent identities. Generate any test signing
  material ephemerally outside stored fixtures; never print/commit keys. Local
  Anvil unlocked test accounts stay behind the test executor; redact its startup
  output. No provider token or real wallet is required by these local scenarios.
- For actual Codex launch observations, use only the approved local manual-bearer
  profile and retain the strict 2026-07-28 default. The profile does not substitute
  for BRL-SC-023/024 durable intent/run/charge observations or the complete browser,
  reload/back, retry and client-action accounting required by BRL-SC-025.
- Clock control is an internal test seam with explicit advancement observations,
  unavailable to participant routes. Use real processes/restarts/transactions for
  durability and race checks; do not substitute a Python reference state machine.
- Evidence contains run/operation identities, API outcomes, committed ledger/budget
  records, event sequence and payload hashes, declared fixture/environment identity,
  redacted receipt/state references, resource/process identity and artifact hashes.
  Store only generated test data, never user prompts/internal reasoning or secrets.
- Missing required runtime, database, execution fixture or observation yields
  `blocked` with a reason. A skipped/blocked mandatory gate prevents sync/archive.
  No green baseline test can substitute for these 25 new gates.
- Planning-only validation now: `openspec validate benchmark-run-lifecycle --strict`.
  Acceptance commands with a change selector are future tooling work, not commands
  claimed to work today. After apply, run semantic audit before pytest, preserve
  JUnit/raw evidence and record Git/source/contract/harness hashes.

## Approval boundary

Approval authorizes only the 25 scenarios, their listed negative variants, the
shared adapter/mappers, source-selection tooling changes and coordinator/API/
database/local-test-executor scope in proposal/design/tasks. It does not authorize
real funds, production signing, mainnet deployment or additional test assertions.
The 2026-10-28 addendum selects one local Codex manual-bearer client profile within
the existing launch/client scenarios without changing any scenario or assertion.
New scenarios/changed assertions return this packet to review.

**Decision:** approved on 2026-10-25; approval.md supersedes the historical review notes below.
**Decision reference:** The owner answered “Утверждаю весь описанный этап” to the 74-scenario review at commit `9ee9211`. Earlier individual product decisions are retained below as history.
approved this concrete BDD packet or its new engineering defaults. The user has
confirmed explicit owner revocation as cancellation, including queue release and
no voluntary refund after start; BRL-SC-006/012/013 now include this trigger.
The user also confirmed continuation after a forbidden request verifiably
rejected before execution, separate safety reporting and the exception for
published prohibitions on the attempt itself. BRL-SC-009 and its review contract
now distinguish these cases from actual violations and unknown effects. This
does not approve the complete packet or numeric task rubrics. The version-fixed
educational valuation rate is a confirmed evaluator dependency, not implemented
economic acceptance in this coordinator packet.


The user confirmed explicit agent-requested completion and automatic deadline evaluation; BRL-SC-020 adds their shared cutoff, duplicate/race and admitted-effect boundary. The full 20-scenario packet still awaits explicit implementation approval. Separate benchmark-version boards and historical views are downstream leaderboard scope, not verified by this coordinator gate.

The user confirmed cancellation of submitted runs when its specific training/ranked permission is removed: BRL-SC-012/013 now include the affected-mode fence, unrelated-mode preservation and no reopening on re-enable. This confirms that policy, not the complete implementation/scenario packet.

The user selected scores/error reasons instead of a private tool-call journal for MVP results. BRL-SC-016 now checks this compact ranked projection and its release timing; internal evidence remains protected by the existing audit/recovery contract. No frontend journal or executable acceptance was added.

The user confirmed current-run disqualification without refund on proven successful interference with service state or another run. BRL-SC-021/022 cover validated-finding adjudication and unproven/blocked/unknown distinctions. The observer fixture proves coordinator behavior only; real protected-state observation and attribution require their own environment gate before production use. The complete 25-scenario scope remains unapproved.

## Confirmed version admission policy

New training and ranked requests target only the active benchmark version. Already admitted requests, including queue waiters, preserve pinned rules/environment/price and may finish after activation under existing authorization, expiry and cancellation rules. Identical authenticated retries resolve the existing request; new old-version requests create no run/reservation. Test authoritative activation/admission ordering, no retargeting/repricing and late results updating only their historical projection without changing original result snapshots. History reads are not execution authority and must not start an old node. This confirms the product policy, not the full scenario/implementation scope; all gates remain not_run.

## Confirmed bounded queue waiting

The user selected expiry of not-yet-started requests after bounded waiting, source-preserving cash/bonus hold release without charge and no automatic resubmit. Numerical duration awaits queue/load validation. Proposed persisted deadline/policy spans queued/preparing time and survives retry/restart without renewal. Exercise before/at/after deadline admission to start, a delayed expiry worker, mixed-source/budget release, expired bonus grants, competing cancellation/revocation, a valid earlier start, terminal retry and late preparation callbacks. Observe no first task/debit on pre-start expiry, one terminal reason, no renewed grant or cash conversion and fenced safe slot handoff. A queue deadline is not an execution timer or a reason to cancel a valid started run. These observations remain review material; all 25 gates are not_run.

## Confirmed owner-rotation scheduling

The user selected alternating eligible owner accounts for free slot assignment, then the oldest eligible request inside that owner without preempting running work. BRL-SC-019 additionally exercises multiple owners/agents, busy-agent head skipping, sole-owner spare capacity, duplicate scheduler delivery and restart. Observe actual durable dispatch/turn/claim identities and original request order/deadline under existing funds, expiry and per-agent slot bounds. Scheduling orders capacity assignment, not simultaneous task activation or equal CPU time. Exact persistent rotation/locking mechanics remain proposed; all 25 gates remain not_run.

## Launch and first-public-action review correction

BRL-SC-023/024 cross real owner/agent verification, shared HTTP/MCP and PostgreSQL
intent/admission transactions with a controlled clock; private read/status/cancel
routes use the same owner/agent bindings. BRL-SC-025 additionally requires actual
browser and a pinned compatible external client, including native handoff and
copy-request fallback observations. Missing actual client/native observations
blocks that mandatory gate rather than substituting a generic SDK or claiming
a universal short path. Record edition/OS/auth/protocol and actual action counts;
platform receives no model credentials and invokes no model. Versioned pending
intent lifetime/per-owner/global caps are required before execution.

BRL-SC-017 now observes the shared first-public-action marker in the same commit
as eligible ranked terminal state/handoff; other outcomes do not create it.
BLP-SC-016/017 separately exercise actual forum/lifecycle/profile transactions and
public-route/cache projections. Planning correction authorization does not mark
any task complete or grant full executable scenario/implementation approval.
