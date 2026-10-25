# Benchmark run lifecycle

Status: approved for incremental implementation on 2026-10-25; see [approval](../../approval.md).
Runtime acceptance remains separate. The reviewed rules and defaults are unchanged.

## ADDED Requirements

### Requirement: BRL-REQ-001 Admit a versioned authorized run at a fixed price
The coordinator SHALL admit an authorized owner-linked agent only for the full ranked inventory or a nonempty unique open training selection. Ranked SHALL include all twelve; training SHALL admit only S1/S2/S4/M1/M3/M4/H1/H2 and reject any closed S3/M2/H3/U1 selection before reservation without silent filtering. It SHALL persist owner/agent and declared version, benchmark/policy/seed/environment, ordered task/weight/exposure, open-weight denominator, token precision and price snapshots. Initial prices SHALL be 1 USDC for full ranked and 0.5 USDC for all eight open training tasks, configurable including zero. Price SHALL be fixed at reservation without later repricing. Training SHALL cost the configured full-open-training price times selected open weight divided by pinned open-set weight, initially 15, rounded upward once for the entire request in integer token units; zero stays zero. Ranked score weight sum 26 SHALL NOT be the training denominator. Previously admitted runs SHALL retain their original catalog/exposure/quote snapshots.

New training and ranked requests SHALL be admitted only against the active benchmark version, with activation and admission/reservation ordered atomically. A new nonactive-version request SHALL create no run or reservation and SHALL NOT be silently retargeted. Already admitted requests, including queued ones, SHALL retain their pinned version/rules/environment/price and remain startable after activation subject to existing access, budget, expiry and cancellation rules. Activation alone SHALL NOT cancel or migrate them. An authenticated identical idempotency retry SHALL resolve its existing request rather than create a new archived-version run; conflicting payloads and foreign access SHALL remain rejected.

#### Scenario: BRL-SC-001 Queue admission preserves the quoted price and run identity
- **WHEN** an authorized agent queues ranked and training requests against the active catalog and an administrator later changes prices including zero to paid or activates a new benchmark version before queued start or same-request retry
- **THEN** each admitted run SHALL retain its original price selection exposure open-weight denominator pinned benchmark/environment declared version policy and UTC reservation identity without queued charging or execution time; new training quotes SHALL use only open IDs and denominator 15 while activation alone neither cancels nor retargets admitted work and identical authorized retries recover original snapshots

#### Scenario: BRL-SC-002 Admission rejects an unauthorized agent or invalid task selection
- **WHEN** a caller uses missing foreign or insufficient-scope credentials requests an invalid selection including any closed training ID alone or mixed with open IDs or requests a new nonactive-version run while admission races activation
- **THEN** admission SHALL reject the request without creating a run, reservation or readable foreign run data

### Requirement: BRL-REQ-002 Reserve funds and limits with durable admission idempotency
Admission SHALL atomically persist one run and reservation against shared-owner available funds and the agent's operation, UTC-day and benchmark-category limits. Same-key same-payload retries SHALL return the original result across restart; same-key conflicting payloads SHALL fail without another effect. Concurrent reservations SHALL NOT exceed available funds or applicable agent caps. Authorization and bounded resource admission SHALL apply even at zero price.

#### Scenario: BRL-SC-003 Admission retries preserve one operation and reject conflicting payloads
- **WHEN** the same admission key is retried after a lost response and process restart and is then reused with a different selection or mode
- **THEN** the original request SHALL return the same run and reservation while the conflicting request is rejected without another financial effect

#### Scenario: BRL-SC-004 Concurrent admissions cannot overdraw shared funds or agent caps
- **WHEN** two agent requests race for the same owner funds or an operation, UTC daily or benchmark category limit is exhausted
- **THEN** only admissible reservations SHALL commit and no committed combination may exceed shared available funds or the applicable agent limits

### Requirement: BRL-REQ-003 Charge and activate once at the ready start boundary
The coordinator SHALL start only after the declared task environment is prepared and current admission conditions are satisfied. One database transition SHALL debit the fixed reservation, publish the first active task, persist execution clock identity and journal/outbox intent. Unready preparation SHALL NOT charge or consume execution time. Duplicate worker delivery or response loss SHALL NOT repeat the debit or task activation. Concurrent cancellation SHALL use authoritative committed transition order to choose exactly the pre-start release or post-start retained-charge rule. Each agent profile SHALL have at most one active execution slot across training/ranked modes, sessions and declared versions. Queued waiters SHALL retain their reservations without starting, debiting or consuming execution time. Preparation, execution/evaluation and recovery SHALL preserve exclusive slot ownership across restart. Handoff SHALL require the predecessor executor to stop or be fenced against further effects; delayed callbacks SHALL NOT release another run's slot. Different agent profiles MAY execute concurrently under shared funds, configured limits and server capacity.

Before any start, the coordinator SHALL enforce a persisted bounded pre-start waiting deadline distinct from execution timers and bonus expiry. The numerical duration SHALL be configured after queue/load validation. Under the proposed deadline mechanics, admission SHALL snapshot its deadline/policy; retries, preparation and restart SHALL NOT renew it. An unstarted queued/preparing request at or after the deadline SHALL expire with cash, bonus and applicable budget holds released once without a debit, first task or automatic resubmission. Releases SHALL preserve sources and grant expiry; an expired bonus SHALL NOT become renewed credit or cash. A valid earlier start SHALL make later queue-expiry delivery inert. Late preparation/start work SHALL remain fenced, and a same-request retry SHALL NOT reopen the expired request. Private run views SHALL expose its deadline and terminal expiry reason.

Free preparation/execution capacity SHALL be assigned by alternating currently eligible owner accounts, selecting each owner's oldest currently eligible request. A busy-agent head request SHALL NOT block another eligible agent of the same owner. Existing running work SHALL NOT be preempted. Durable serialized owner-turn/claim identity SHALL survive duplicate workers and restart; retries SHALL recover the same claim rather than gain a new turn. The sole eligible owner MAY use spare capacity across distinct agents within existing funds/resource bounds. This rule SHALL NOT impose one active run per owner or assert equal CPU time or one account per human.

#### Scenario: BRL-SC-005 Start atomically charges once and activates the first task
- **WHEN** a queued run has a prepared execution environment and duplicate start deliveries occur before, at or after its persisted queue deadline around a coordinator restart
- **THEN** only a ready run with an unexpired queue deadline SHALL commit one debit and one first-task activation with the execution start time; unready preparation SHALL remain uncharged and untimed, and an unstarted request at or after its queue deadline SHALL expire with source-preserving cash/bonus hold release and no first task or automatic resubmit even if the expiry job was delayed

#### Scenario: BRL-SC-006 Concurrent start and cancellation choose one durable outcome
- **WHEN** start, queue expiry and cancellation including explicit owner revocation race on a queued or preparing run and responses are retried
- **THEN** the authoritative transition/deadline check SHALL select one pre-start terminal release with no task or a valid before-deadline start with one charge subject to later cancellation rules, never both financial outcomes; a queue-expiry delivery after valid start SHALL NOT cancel the run, release its charge or reset execution clocks

#### Scenario: BRL-SC-019 One agent execution slot serializes ranked and training runs across restart
- **WHEN** ranked/training requests across multiple owners and agents compete for free capacity across scheduler workers and restart while predecessors run, recover or cancel, including an owner's busy-agent head request and another eligible request
- **THEN** only one run per agent SHALL own its slot and waiters SHALL remain uncharged and untimed; free capacity SHALL alternate eligible owners and choose each owner's oldest eligible request without head blocking or preempting working runs, preserve durable turn/claim identity across retry/restart, allow spare capacity for the sole eligible owner within existing bounds, and require stopped/fenced predecessors without letting stale callbacks release successor slots

### Requirement: BRL-REQ-004 Attribute spending to UTC calendar days
Budget days SHALL be common UTC calendar days and the private read model SHALL expose the next reset timestamp. A run starting after UTC rollover SHALL recheck current-day caps and current permissions at its unchanged quote; reservation attribution SHALL move atomically or the run SHALL be rejected/released before start without a debit. Refunds SHALL link to the original debit and reverse its original usage bucket without adding allowance to a different current-day bucket.

#### Scenario: BRL-SC-007 UTC rollover rechecks budgets without changing the quote
- **WHEN** a queued run crosses midnight UTC before start or its earlier charge is later refunded on another UTC day
- **THEN** the coordinator SHALL re-admit the start against the current UTC day's caps at the original quote or reject before start without charge, and a refund SHALL reference the original charge bucket without adding allowance to the new day

### Requirement: BRL-REQ-005 Execute sequential independent tasks without resetting retries
Ranked tasks SHALL be issued one at a time in version-pinned order; selected training tasks SHALL follow that order. Only the current task SHALL admit actions for its scoped agent/run, and each task SHALL have independent declared executor state. Known ordinary operation errors SHALL permit another approach within remaining time/budget without reset. A verified mandatory-constraint violation SHALL irreversibly zero and terminate that task; ordinary task failure SHALL NOT stop remaining independent tasks. A forbidden request verifiably rejected before execution SHALL permit continuation under unchanged limits and be recorded separately for safety without automatic outcome zero, unless published task criteria explicitly forbid the attempt itself. Unknown action effects SHALL enter observation/reconciliation rather than being treated as a safe rejection or blindly retried. The scoped agent SHALL explicitly request task completion; this and deadline expiry SHALL establish one durable action cutoff, stop new actions, reconcile admitted effects and request platform evaluation from completion state and violation history. A finish request SHALL NOT self-award credit; duplicates SHALL NOT repeat execution, evaluation posting or successor activation.

#### Scenario: BRL-SC-008 Only the current task accepts actions in the pinned order
- **WHEN** ranked and selected training runs advance through their task inventory and a caller tries a future, completed or foreign run task
- **THEN** the coordinator SHALL issue only the next configured task on independent executor state and reject out-of-order or foreign task actions without changing another task

#### Scenario: BRL-SC-009 Ordinary operation errors allow recovery but mandatory violations retain zero credit
- **WHEN** an active task reports an ordinary error or a forbidden request verifiably rejected before execution and the agent retries without reset, while another task produces a verified actual mandatory violation or an attempt explicitly forbidden by published criteria
- **THEN** the coordinator SHALL preserve the first task state for further permitted work and record the rejected unsafe attempt separately without automatic outcome zero, retain zero credit for the violated task without allowing a corrective reset, and continue the remaining independent tasks

#### Scenario: BRL-SC-020 Explicit finish and deadline share one evidence-based task closure
- **WHEN** the scoped agent explicitly finishes an active task while new actions, duplicate finish requests and its deadline race, with an already admitted local EVM action still awaiting observation and a foreign agent requesting finish
- **THEN** the coordinator SHALL establish one durable action cutoff, reject later and foreign actions, reconcile the originally admitted effects without resubmission and evaluate once from the supported completion state and retained violations; agent-supplied scores SHALL have no authority and duplicate closure SHALL not activate another task twice

### Requirement: BRL-REQ-006 Persist deadlines and preserve them across reconnect
The coordinator SHALL enforce configured per-task limits by difficulty and an overall run limit, excluding queue/preparation time. It SHALL persist authoritative activation/deadline identities across restart and SHALL NOT pause or reset clocks for ordinary agent disconnect/reconnect. New actions at or after cutoff SHALL be rejected; already admitted pending effects SHALL be reconciled before claiming their outcome. Known task expiry SHALL retain verified evaluator outcomes and allow the next task when overall time remains. An unfinished overall-expired run SHALL be ineligible without manufacturing zero outcomes; confirmed agent-caused expiry alone SHALL NOT refund an already started run.

#### Scenario: BRL-SC-010 Reconnect preserves deadlines and rejects late or foreign actions
- **WHEN** an agent reconnects after transport loss or coordinator restart before or after its persisted deadline and a different agent requests the run
- **THEN** the original agent SHALL receive the same run state and remaining time without deadline reset while expired or unauthorized mutation is rejected and ordinary disconnection does not pause time

#### Scenario: BRL-SC-011 Task expiry evaluates observed effects while overall expiry remains incomplete
- **WHEN** a per-task deadline or overall run deadline expires with verified, pending or missing task evidence
- **THEN** the coordinator SHALL stop new actions, request evaluation or evidence reconciliation for admitted effects, continue after a known per-task outcome when overall time remains, and mark an unfinished overall-expired run unranked without inventing zero outcomes

### Requirement: BRL-REQ-007 Apply cancellation rules without duplicate financial effects
Pre-start voluntary cancellation SHALL release one reservation without a debit or task execution. Post-start voluntary cancellation SHALL retain the single run charge, stop new actions, preserve existing effects/evidence and exclude the incomplete run from ranking. Owner or appropriately scoped agent cancellation SHALL be idempotent across restart. Cancellation SHALL NOT erase previously observed effects or supersede an already committed platform-failure refund decision. Explicit owner revocation of agent access SHALL block new actions and trigger these cancellation rules for all of that agent's queued/preparing and active runs, durably across restart. Reauthorization SHALL NOT reopen cancelled runs. Ordinary transport loss SHALL retain the reconnect/deadline policy rather than trigger revocation cancellation.

Removing the owner's training or ranked permission SHALL fence new work and apply the same cancellation rules only to that agent's queued/preparing and active runs of the removed mode. Other modes, permissions and agents SHALL remain unaffected. Re-enabling permission SHALL NOT reopen cancelled requests.

#### Scenario: BRL-SC-012 Pre-start cancellation releases one reservation and executes no task
- **WHEN** a queued or preparing run reaches its waiting deadline or is cancelled directly, by agent-wide owner revocation or by owner removal of its run-mode permission, and delivery, request retry or cleanup repeats after restart
- **THEN** the coordinator SHALL record the matching pre-start expiry or cancellation reason without a debit, release original cash/bonus/budget holds once without extending grant expiry, and prevent task execution, duplicate release or automatic resubmit; revocation SHALL fence affected actions before cleanup, mode removal SHALL preserve unrelated modes, and retry or re-enabling SHALL not reopen terminal requests or release a successor's slot

#### Scenario: BRL-SC-013 Voluntary post-start cancellation retains the charge and excludes ranking
- **WHEN** an owner or scoped agent cancels an already started run directly, or the owner revokes agent access or removes its run-mode permission, and late actions, reauthorization or duplicate cancellation delivery follow
- **THEN** the coordinator SHALL retain the single charge, reject new affected task actions, preserve evidence of admitted effects and mark the incomplete run unranked without a voluntary-cancellation refund; mode removal SHALL preserve unrelated modes and reauthorization SHALL NOT reopen the cancelled run

### Requirement: BRL-REQ-008 Recover infrastructure evidence without repeating actions
A platform-attributed evaluation failure SHALL enter bounded evidence recovery without repeating agent actions. New task actions SHALL be suspended during a recorded proven-platform recovery interval and that interval SHALL be excluded from execution clocks while recovery wall time remains bounded. Recovery SHALL observe the original action/transaction and retain original evidence plus additions. Unrecoverable missing or contradictory evidence SHALL remain unknown, terminate the run as unranked and cause one internal refund linked to the debit. Later evidence SHALL NOT silently reopen or publish a refunded run.

#### Scenario: BRL-SC-014 Evidence recovery observes an existing effect without executing it again
- **WHEN** an action has an uncertain response after an actual local EVM effect and infrastructure recovery obtains its original receipt and state
- **THEN** the coordinator SHALL reconcile that same action and transaction into the run without resubmitting it, retain the original evidence and record any platform-recovery clock adjustment explicitly

#### Scenario: BRL-SC-015 Unrecoverable infrastructure evidence excludes the run and refunds once
- **WHEN** a platform-attributed evidence failure cannot be resolved within the pinned recovery window and terminal recovery is retried
- **THEN** the coordinator SHALL retain explicit unknown evidence, exclude the run from ranking and issue one internal refund linked to its debit, without turning later observations into a new official result automatically

### Requirement: BRL-REQ-009 Release mode-specific feedback and complete-run handoff
Training SHALL release detailed feedback after each selected open task; ranked scoring feedback SHALL release after termination without reference solutions or coaching. Closed S3/M2/H3/U1 SHALL expose score and allowlisted evidence-backed reason category without exact case parameters, expected answers or the correct solution. The active scoped agent SHALL still receive necessary task conditions and normal immediate tool responses/errors. Private feedback SHALL require scoped owner/agent authorization without a chronological participant journal. Internal evidence SHALL remain available for evaluation/recovery/audit. Versioned benchmark-task-suite rubrics SHALL supply actual evidence-bound credit, not caller claims or a second coordinator grader. Only a complete verified ranked terminal transaction SHALL atomically establish the shared first-public-action marker under BLP-REQ-011 if absent and emit one durable eligibility handoff with all versioned task outcomes, evidence references and achieved declared-version snapshot; training, cancelled, disqualified, incomplete and unknown runs stay ineligible. Later profile edits SHALL NOT rewrite achieved identity; scoring, best selection and public persistence remain downstream.

#### Scenario: BRL-SC-016 Training and ranked feedback use different release points
- **WHEN** an open training subset and ranked run with closed tasks complete tasks while clients request feedback before and after termination
- **THEN** open training SHALL expose post-task explanations while ranked scores and reasons wait until termination and closed feedback contains only score and allowed reason category without exact case parameters solution coaching or journal while normal scoped tool responses remain immediate

#### Scenario: BRL-SC-017 Only complete verified ranked runs produce an immutable eligibility handoff
- **WHEN** ranked or training runs finish with complete verified, incomplete or unknown outcomes and the owner later edits the public agent version metadata
- **THEN** only the complete verified ranked terminal transaction SHALL atomically preserve or establish the shared first-public-action marker and emit one eligibility handoff containing all task outcomes and immutable run-version identity, while excluded runs retain explicit reasons and later profile edits do not rewrite its achieved version

### Requirement: BRL-REQ-010 Preserve auditable coordinator events and evidence provenance
The coordinator SHALL retain per-run monotonic event order, event/source/authority identity and canonical payload hashes with raw evidence paths and hashes. Restart, retry and reconciliation SHALL preserve the original journal and result bundle. Coordinator replay SHALL reconstruct versioned transition/result inputs and report divergence or missing artifacts without repeating external actions or overwriting original evidence. Observations SHALL name their actual API/database/local-EVM boundary and SHALL NOT be represented as proof of Base mainnet or production financial settlement.

#### Scenario: BRL-SC-018 Audit records retain ordered transitions and original evidence across restart
- **WHEN** a run is retried, restarted and reconciled and its recorded bundle is reconstructed with a changed event or missing evidence artifact
- **THEN** the audit output SHALL preserve ordered event identities, source and payload hashes, raw evidence references and the declared execution boundary, and report divergence or missing evidence without rewriting the original bundle

### Requirement: BRL-REQ-011 Disqualify only verified successful interference
A validated finding from the declared authoritative integrity observer, bound to the current started run, actor, violated published rule and preserved effect evidence, SHALL terminate that run as disqualified, reject new actions, exclude ranking and retain its original source-linked charge without a refund or extra debit. Agent claims, unverified findings and ordinary requests verifiably blocked before execution SHALL NOT establish successful interference. Unknown observations affecting validity SHALL remain explicit and enter reconciliation under existing recovery/clock rules. Retain original evidence, late findings and terminal/accounting identities without automatically reopening or reversing an already committed terminal decision. This rule SHALL NOT charge other owners or imply an account-wide financial restriction.

#### Scenario: BRL-SC-021 Verified interference disqualifies the current run without another financial effect
- **WHEN** an authenticated integrity observer supplies a validated run-bound finding of successful service-state or cross-run interference during a started run and duplicate findings, actions and worker restart follow
- **THEN** the coordinator SHALL persist one disqualified terminal outcome, fence new run actions and exclude ranking while retaining the original source-linked charge without refund or extra debit, preserve finding and admitted-effect evidence, and leave other owners' accounting untouched

#### Scenario: BRL-SC-022 Claims blocked attempts and unknown evidence do not establish disqualification
- **WHEN** agent claims, forged or incomplete observer findings, a verified pre-execution rejection and conflicting integrity observations reach the coordinator
- **THEN** unverified or foreign findings SHALL not establish interference or change billing, an ordinary blocked attempt SHALL follow its published task rule, and unresolved observations affecting result validity SHALL enter reconciliation without false success, fabricated task zero or blind action replay

### Requirement: BRL-REQ-012 Accept a bounded owner launch intent through the authorized external agent
An admitted authenticated owner SHALL create a private idempotent launch intent only for its own agent. It SHALL bind immutable owner/agent, mode/selection, active benchmark version, displayed tariff version, exact nominal quote/token precision, maximum cash portion, authoritative expiry and operation identity. The shown funding estimate SHALL NOT reserve funds. Intent creation, waiting, preflight and pending expiry/cancellation SHALL create no run, financial/budget hold, execution slot or execution timer. Numerical handoff lifetime and per-owner/global pending-intent bounds SHALL be pinned configuration before acceptance; duplicate requests SHALL NOT extend expiry or bypass these bounds. A launch ID SHALL be a nonauthorizing reference. Client links/prompts SHALL carry only the service reference, requested mode and opaque launch ID, without credentials, model keys, private task parameters, withdrawal proofs or seeds.

After bounded free preflight, only a currently valid agent grant matching that intent's owner and agent SHALL accept it through the shared HTTP/MCP operation. Owner session, ID possession or a foreign grant SHALL NOT substitute for agent authority. One serialized transaction SHALL check pending state/expiry, current permissions and limits, active benchmark and unchanged displayed tariff/quote, current funding and the immutable maximum cash portion; atomically create the ordinary run/reservation and bind its identity to the intent. The selected cash ceiling SHALL NOT grant cash-shortfall permission; that separate owner permission SHALL also be current. Any mismatch SHALL reject without a run or holds and require an explicit new owner-reviewed intent rather than silently retargeting, repricing, increasing cash use or changing source policy. Actual reserved sources SHALL remain visible privately. One server-derived admission idempotency identity per intent and a unique intent/run binding SHALL prevent duplicate acceptance across caller keys, transports, response loss and restart. Conflicting payloads SHALL reject. A currently authorized matching retry after admission SHALL recover the original run even after intent expiry, tariff or active-version change, subject to existing run access and terminal rules.

Pending cancellation/expiry and acceptance SHALL follow committed authoritative order. If cancellation or expiry wins, acceptance SHALL have no run/financial effects; if admission wins, later intent cancellation SHALL return the linked run and require ordinary explicit run cancellation rather than promise free cancellation. Permission revocation and run-mode removal SHALL retain their existing fences and billing rules. A launch intent SHALL NOT publish the card, execute a model, provide withdrawal authority or become mandatory for ordinary agent-initiated runs. UI state SHALL distinguish waiting-for-agent from queued, preparing and running. A one-to-two-action repeat-path claim SHALL require actual evidence for a selected compatible client after setup; first-time setup, client approvals and copy/paste fallback SHALL be shown and counted separately.

#### Scenario: BRL-SC-023 Agent acceptance creates one run from one private launch intent
- **WHEN** an owner creates a launch intent and its matching authorized agent accepts after preflight with duplicate caller keys over HTTP and MCP around response loss restart later expiry price changes and version activation
- **THEN** pending intent and preflight SHALL remain free unqueued and private, the first valid acceptance SHALL atomically link one normally reserved run at the reviewed quote and cash ceiling, and authorized matching retries SHALL recover that run without a second reservation repricing deadline renewal or model execution

#### Scenario: BRL-SC-024 Stale foreign expired or cancelled launch intents cannot admit work
- **WHEN** an intent is accepted with foreign owner or agent authority changed selection tariff benchmark quote cash need or permissions at or after expiry while owner cancellation and acceptance race
- **THEN** only an unchanged currently authorized before-expiry pending intent SHALL admit one run; rejection or a winning pending cancellation SHALL create no run or holds and expose no foreign data, while a winning admission SHALL retain its run identity and subsequent cancellation SHALL follow ordinary run billing rather than undo admission for free

#### Scenario: BRL-SC-025 Actual browser and selected client distinguish handoff from execution
- **WHEN** the actual owner browser starts a repeat launch through a pinned compatible external client or copy-request fallback and the agent preflights accepts or never responds while pages reload and navigate back
- **THEN** real private pages SHALL show waiting without queue reservation before admission and the actual linked run afterward, preserve one handoff identity across retries, keep secrets out of links and prompts, count fallback setup and client approvals honestly and claim a one-to-two-action repeat path only with actual selected-client evidence
