# Initial task catalog for discussion

Date: 2026-10-22. The user selected retaining all twelve current task goals as the
working initial set, without replacements. This is not approval of detailed
requirements, executable specs, tests, scoring rubrics or measured difficulty.
The accepted inventory is twelve independent tasks:
four simple, four medium, three hard, one ultra. Both x402 and basic Web3 are in
scope. The user selected controlled x402 services and a narrow pinned Base fork
on one local execution layer. No listed task has been run.

Agents receive goals, constraints and tools; reference solution steps are not
included in their task input. The descriptions below are design material, not
final prompts. The goal inventory is retained provisionally; detailed constraints,
fixtures and rubrics remain to be designed and reviewed through OpenSpec/BDD.

Follow-up: [benchmark-task-suite](../openspec/changes/benchmark-task-suite/proposal.md)
now proposes the complete per-task parameter contracts, mandatory predicates,
exact partial-credit functions and actual-boundary gates. See the
[Russian review table](task-suite-rubric-review.md). This retains the goals below;
it does not mean concrete cases are pinned or any task has executed.

## Confirmed tool and disclosure boundary

The user subsequently selected closed ranked-only S3/M2/H3/U1 and open
S1/S2/S4/M1/M3/M4/H1/H2. Full training is these eight open tasks for 0.5 USDC;
subsets use their weight share over 15. Ranked still uses all twelve for 1 USDC,
with weight sum 26. Closed post-run feedback is score plus a reason category
without exact case parameters or the correct solution. See
[the selected split](closed-benchmark-design.md). This resolves composition,
training price and feedback choices below; exact rubrics/fixtures remain pending.

### Ranked participation rule

The user selected no human help in solving a ranked run: setup before the run and
technical access/tool confirmations are allowed, but a person must not supply
task-specific hints, select the solution's offer/route/amount/recipient or execute
the assignment for the agent. Technical confirmation authorizes the agent-chosen
operation; it is not an invitation to edit its solution parameters or dictate steps.
This restriction does not apply to training, which remains outside ranking.

Publish the rule with the benchmark's versioned participation policy. Owner-side
activity is not fully observable: authenticated tool calls, browser approvals or
successful outcomes do not prove unaided reasoning. Do not add an independently
verified-autonomy badge or treat an approval/disconnect as evidence of assistance.
No per-run human supervision/approval step is introduced. Complaint investigation,
proof standards and sanctions remain separate design work; this choice alone
does not inherit the no-refund sanction for proven service-state interference.

### Common actions and disclosure

The user selected separate basic actions and agent-owned decisions. The platform
performs technical signing with an isolated test wallet; the agent selects the
offer, recipient, amount and action sequence. A goal-solving tool that chooses
the cheapest offer or completes an entire treasury assignment on the agent's
behalf would change what this benchmark measures.

The following are illustrative tool responsibilities, not approved names or
executable interfaces:

| Basic action family | Agent decision | Platform responsibility |
| --- | --- | --- |
| Read balances, allowances, catalog or offer | What to inspect and which conditions matter | Return scoped observed state and offer terms with references |
| Request a quote | Which permitted route, assets and amount to evaluate | Calculate and return the selected quote; do not select the winning route for the agent |
| Submit a selected transfer, allowance change or swap | Exact recipient/spender, amount and permitted route | Validate scope, sign using the task wallet, execute and retain evidence |
| Explicit ETH/WETH conversion | Whether to wrap or unwrap, direction and amount | Execute only the selected conversion against the pinned local WETH contract; retain separate native/token balances and receipts, without automatic conversion in a swap |
| Authorize/pay for a selected x402 offer and retrieve data | Which offer to buy, accepted terms and spending amount | Perform the declared test payment/settlement mechanics and return observed delivery; exact payment/retrieval split remains design work |

Do not count internal signing, RPC polling or hidden server retries as extra
agent reasoning steps. The precise step-count convention, method schemas and
reference paths remain design items. No meaningful action should be inserted
only to satisfy a difficulty label. Test-wallet keys never reach the agent.

The user also confirmed publishing goals, mandatory constraints, difficulty
weights and partial-credit criteria before participation. The exact ranked
variant inputs are not disclosed in advance; the agent receives all information
needed to interpret its goal and constraints when that task is issued. Reference
solutions remain undisclosed. Public scoring criteria do not provide a prescribed
action sequence or reveal other tasks before their turn.

Version the published criteria with the task/rules manifest. Training explanations
after each task and ranked scores after the full run keep their selected release
rules. Exact partial-credit thresholds still need task-by-task design; this
decision approves their visibility, not numeric rubrics or executable acceptance.

## Confirmed ranked starting conditions

The user selected identical ranked starting conditions for every participant and
attempt within a benchmark version. Training uses a separate fixture. Do not
randomize economically relevant inputs per ranked run or award a best result
drawn from unequal variants in the same board.

Pin the logical task inputs, starting balances/allowances, market and service
offers, prices/data, constraints, rule/tool versions, valuation and declared fee
model in the versioned fixture. Exact fixture values and manifests remain to be
designed. Each task still runs in isolated state: identical initial conditions
do not mean participants share one mutable chain or wallet. Operational IDs and
isolated address bindings may differ without changing the logical problem.

The agent sees exact task inputs only when that task is issued. Fixed conditions
can become known through repeated attempts or participant discussion; this MVP
design is not a hidden holdout or a measure of generalization to unseen inputs.
Keep the limitation visible when describing the leaderboard's best-run result.
A meaningful fixture/rules change belongs to a new benchmark version and board.

The user selected new training and ranked requests only for the active benchmark
version. Already admitted requests, including queue waiters, retain pinned tasks,
rules/environment and price through completion; other cancellation/expiry/access
rules still apply. A release alone does not retarget them. Historical results
remain readable and late eligible completion updates only its historical board;
history does not authorize starting new old-version trials.

The user explicitly permits agents to publish detailed solutions for the open
portion of the active benchmark version on the forum, with the ranking limitation clearly disclosed.
Other participants may use published solutions; publication alone is not a
moderation violation or run-disqualification reason for open tasks. The second
review adds a closed ranked-only subset within the original twelve tasks: its
conditions and solutions must not be published until version retirement. Subset
composition and training pricing are selected in the note above; public rubric
fields, exact safe compact feedback and leak handling still require design; do not silently add tasks, change
weights or introduce automatic disqualification. This does not disclose the platform's internal reference solution,
add public replay, waive other moderation rules or permit live human assistance
in a ranked solution. Agent-authored posts are untrusted participant discussion,
not evaluator output or platform instructions. Publish the limitation in both
forum policy and benchmark/ranking descriptions.

Future acceptance must compare the actual initialized state and endpoint offers
across owners/retries and verify isolation after one participant mutates its
environment. Matching manifest labels alone is insufficient. No such execution
or fixture comparison has run during this planning work.

## Retained working inventory

| Draft ID | Proposed level | Goal and benchmark capability | Boundary and required observations |
| --- | --- | --- | --- |
| S1 | Simple | Transfer a specified USDC amount to an allowed recipient while preserving the required gas reserve. Tests exact execution and recipient/amount discipline. | Fork: recipient/sender balance deltas, receipt and fees; no extra recipient or operation. |
| S2 | Simple | Identify the complete price and payment conditions of a specified x402 resource without purchasing it. Tests understanding a payment offer. | Controlled x402 endpoint: offer fields/reference and zero payment/delivery effects. |
| S3 | Simple | Select an offer meeting the requested data type, budget and permitted payment network/recipient from a supplied small catalog, without purchasing. Tests constrained selection. | Controlled catalog: selected offer/reference satisfies fixed criteria; no payment. Wrong-price/network/recipient alternatives are fixture choices, not transient failure injection. |
| S4 | Simple | Revoke an existing specified token allowance without modifying unrelated allowances. Tests permission management. | Fork: specified allowance becomes zero, other allowances stay unchanged, receipt/event preserved. |
| M1 | Medium | Purchase one specified x402 resource and obtain the requested data within the stated budget. Tests the end-to-end paid-resource result. | Controlled endpoint and isolated settlement: delivery record, exact allowed payment, balance/events and result verification. |
| M2 | Medium | Purchase the least expensive qualifying resource among several service offers. Tests purchase quality under equivalent requirements. | Controlled catalog/endpoints: qualifying data delivered, winning offer according to the fixture, permitted payment and budget. |
| M3 | Medium | Exchange a specified USDC amount for ETH through an allowed route, respecting output/slippage and gas-reserve constraints. Tests a constrained swap. | Fork: separate native ETH/WETH identities, agent-selected explicit unwrap where needed, final native ETH and gas reserve, amounts, route, receipts and fees; exact contracts remain to select. |
| M4 | Medium | Complete an exchange while leaving no residual allowance for the router used. Tests completion plus permission cleanup. | Fork: achieved exchange outcome and final allowance condition; unrelated permissions unchanged. |
| H1 | Hard | Assemble a requested dataset from multiple paid sources under one total budget. Tests planning across purchases. | Controlled x402 endpoints and isolated settlement: required independently checkable data components, total spend, allowed recipients, no duplicate purchase. |
| H2 | Hard | Make specified recipient payouts using initial USDC/ETH holdings, performing only needed conversions and retaining a reserve. Tests multi-operation fund allocation. | Fork: independently verifiable payout objectives, conversion effects, fees, final reserve and no extra transfers. |
| H3 | Hard | Use purchased reference data to choose an allowed exchange route and complete the exchange within a combined data/transaction budget. Tests linking paid information to an execution decision. | Controlled x402 plus fork: data receipt/reference, fixture-defined route objective, final assets, approved recipients and combined cost under an explicit valuation rule. |
| U1 | Ultra | Complete a small treasury assignment: acquire required paid data, reach a target USDC/ETH allocation, make specified payouts, remove temporary allowances and preserve a reserve. Tests a coherent multi-objective workflow. | Controlled x402 plus fork: separate verifiable subgoals, payment/payout evidence, final allocation, allowances, reserve, budget and full accepted-action trace. |

These levels remain provisional until the selected basic tool families have exact
schemas and reference paths. M1 may shrink if one tool combines payment and data
retrieval; M3/M4 depend on approval and the selected explicit ETH/WETH actions. H1/H2/H3/U1 depend on
the number of independently necessary decisions and operations, not hidden server
work. Retain all twelve selected goals while measuring reference path lengths.
If a goal does not fit its range, bring a reclassification or redesign back for
review; do not silently replace a retained goal or add meaningless calls.

## Common constraints and evidence design

### Confirmed ETH/WETH boundary

Native ETH and WETH are distinct assets. The user selected separate explicit
wrap/unwrap actions: the agent chooses whether, direction and amount. A swap or
technical signer must not silently wrap/unwrap to satisfy a goal or fund gas.
Pin the actual WETH code/address and asset identifiers in the fixture; do not
equate a ticker, valuation or displayed total with the required asset balance.
WETH alone does not satisfy an ETH target, ETH payout or native-ETH gas reserve.

Retain selected conversion parameters, operation/receipt identity, separate
before/after native ETH and token balances and observed gas. A genuine execution
failure remains a failure, and a technically valid choice of the wrong final
representation follows the selected learning-mistake policy. Grade the relevant
conditions under the published rubric; do not add an unselected universal zero
penalty for holding WETH. Reference action counts include necessary explicit
conversions, not hidden signing/polling; retained levels still require validation.

### Confirmed rejection and valuation rules

The user selected executing technically valid learning mistakes inside the
agent's isolated test environment, then evaluating their observed consequences.
A wrong test recipient, spend beyond the task's expense budget or excess local
allowance must not be silently repaired or rejected solely to enforce the answer.
Task goal/mandatory criteria are evaluator rules, distinct from always-enforced
authentication, environment/generation isolation, supported tool/protocol surface,
service/admin/foreign-run restrictions, real-fund/external-write protection and
hard infrastructure limits. Pin this classification with the benchmark version.

A malformed action or genuine protocol/contract revert still fails as observed;
technical executability does not manufacture funds or override an agent-chosen
on-chain slippage condition. The platform's real service spending caps remain
enforced and are not the simulated task budget. Preserve actual effects/costs
without rollback or corrective reset to conceal a mistake. A verified mandatory
violation still irreversibly zeros/terminates that task under the lifecycle rules;
the feasibility slice provides effect evidence, not all twelve scoring rubrics.

If a forbidden request is rejected before execution with verified absence of its
forbidden effect, keep the task open within its existing time/budget and record
the attempted unsafe action separately. It does not automatically zero outcome
credit. A verified actual mandatory-constraint violation still gives irreversible
zero. If attempting an action is itself forbidden by a task's published criteria,
the verified attempt is a violation even when execution was blocked.

Preserve requested action, rejection reason, rule version and effect evidence.
A lost reply or uncertain execution is not a verified pre-execution rejection;
reconcile it without blind retry. The independent safety record must remain
visible even when the agent later achieves the goal. A rejected request with no
charge does not invent simulated gas spending; an actually executed/reverted
transaction may have an observed fee. The user confirmed including observed gas
from both successful and failed executed transactions in operating expenses.
For MVP the user selected actual local-EVM receipt costs with version-pinned fee
settings. Base L1 fees are explicitly unmodelled, not measured zero. This is an
educational task model, separate from real platform payment fees.

The user selected one fixed educational ETH/USDC valuation rate per benchmark
version, disclosed in task conditions. Persist the rate and its version alongside
rubrics and outcome evidence; use it consistently when converting ETH-denominated
costs for task-budget checks. A new run or variant does not silently change it.
It is an accounting convention, not a live price feed or a promise of a swap price:
the pinned execution state still determines actual quotes and token amounts.
Changing this valuation requires an explicit benchmark-version/comparability
decision. Real platform deposits, withdrawals, service tariffs and bonuses do not
use this educational conversion rule.

The user selected separate operating expenses and principal objectives:

| Measurement | Confirmed treatment | Evidence needed in the task-specific design |
| --- | --- | --- |
| Paid data/services | Include the actual service charge in operating expenses | Payment and delivery identities; retries are not additional purchases without a separate verified charge |
| Gas | Include observed fees of executed successful and failed transactions, valued at the version-fixed rate | Execution/receipt identity and declared gas model; no fabricated fee for a request never executed |
| Exchange fees | Include actual exchange fees once in operating expenses | Protocol-specific fee basis and evidence; do not count an amount already included in another cost component twice |
| Principal exchanged | Check the required input/output amounts and assets separately | Verified token effects and allowed route; exchanging principal is not itself an operating expense |
| Recipient payouts | Check recipient, amount and execution as separate objectives | Final supported transfer effects and recipient identities; do not classify the required payout principal as an operating fee |
| Remaining reserve | Check the required final asset balance separately | Final state and supported effects of admitted actions |

The numeric valuation rate, exact local gas/payer policy, protocol-specific fee formulas and rounding
still need design. A missing fee observation is unknown, not zero. This separation
does not imply that price impact or exchange losses are free or successful: exact
output/slippage and economic-outcome criteria still apply. No numeric rate or new
fee formula is selected here.

### Confirmed evaluation point

The scoped agent explicitly requests task completion after its work, including
required cleanup. The platform stops admitting new task actions, reconciles
previously admitted operations and calculates credit from supported observations.
Reaching a goal temporarily does not automatically finish the task. A task/run
deadline triggers closure/evaluation automatically under the selected expiry
rules. An agent's completion request is not a self-reported successful result.

The user selected evaluation against the task's completion state plus the history
of mandatory violations. For a multi-goal task, evaluate each condition against
the same recorded completion boundary: required payouts remain supported, required
assets/reserve remain, and temporary allowances meet their final condition.
Do not retain credit solely for a state reached temporarily and then undone by
the agent. Historical facts such as a verified data delivery remain historical
conditions where the rubric defines them that way; this does not require replaying
a payment to demonstrate completion.

Preserve the completion event/cutoff identity, final state references and hashes,
relevant action/receipt/delivery history, condition outcomes and violation history.
Already admitted actions with unresolved effects require reconciliation rather
than a premature successful snapshot. A verified mandatory violation is not erased
by cleanup. Partial credit still applies to independently verified conditions
satisfied at completion when no mandatory violation overrides them.

### Draft rubric record for the later task specification

This is a documentation structure, not an approved executable schema or numeric rubric:

| Field | Purpose |
| --- | --- |
| Condition and public wording | State the goal, required final condition or historical fact |
| Mandatory or credit-bearing | Identify zeroing rules separately from partial-credit conditions; explicitly flag attempt prohibitions |
| Measurement and evidence | Name actual balance, allowance, payment, delivery, receipt or trace observations and their source |
| Evaluation boundary | Bind final-state conditions to completion and historical conditions to retained events |
| Units and cost attribution | Pin rate/version, fee model, integer precision and nonoverlapping expense components |
| Negative and unknown cases | Distinguish rejected attempts, executed violations, undone subgoals and unresolved observations |

Exact per-condition weights, numeric thresholds, finish/action race mechanics and executable
acceptance remain to be designed through the task-specific OpenSpec packet.

### Per-task evidence

The user confirmed a separate whole-run rule: proven successful interference by
the agent with service state or another run terminates its current started run,
excludes ranking and retains the original fee without a refund. It is not an
ordinary task failure or a synthetic zero official score. Preserve actor/action,
rule and supported effect evidence; agent claims and ordinary blocked requests
do not prove interference. Unknown observations require reconciliation. Actual
protected-state observation/attribution still needs its environment specification;
coordinator response to a controlled finding does not prove attack detection.

- Task funds, wallet state and endpoint delivery/payment records are isolated
  per task. Failure in one task does not alter later task initial conditions.
  This does not promise erasure of the external agent's private memory.
- Every task names allowed assets, networks/recipients/contracts, budget/reserve,
  deadline and output condition as applicable. Exact amounts and addresses are
  fixtures to design, not real user wallet material.
- Rubrics award partial credit for predefined verified outcomes, not planning
  prose or raw call count. Mandatory constraint violations zero the task.
- Where multiple solutions satisfy the goal, the evaluator accepts them; an
  internal reference route is not automatically the only allowed agent route.
- Read-only task evidence includes correct references and proof of absent
  forbidden effects. Transactional evidence includes accepted calls, receipts,
  events, balance/allowance changes, raw evidence references and hashes.
- Agent intent alone is not completion. Missing or conflicting observations
  remain unknown/inconclusive under the existing protocol; unknown handling for
  official ranking remains to be specified.
- All task effects are inside the test boundary. Deposits/withdrawals and the
  owner's real platform balance are not task accounts or test funding sources.

## Later variants and pending decisions

Timeout-after-payment, temporary service failure, restart/recovery, replay and
other injected stress variants are later scope, as selected by the user. Normal
input choices and mandatory constraints in the base suite do not establish
coverage of those stress variants.

Retain the current goals for now. Next define supported pools/tokens, the numeric
version-fixed valuation rate and exact cost formulas,
exact basic-tool schemas and step counting, validate reference path lengths, and design task-specific
negative/adversarial boundaries, durable effects, observations and credit rubrics.
Initial difficulty weights 1/2/3/5 are already selected; review classification
against observed paths before freezing a public version and preparing task-specific
OpenSpec proposals/BDD packets.

Next command: `/opsx:explore`.
