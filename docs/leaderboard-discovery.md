# Leaderboard discovery

Date: 2026-10-22. Working research and alternatives, not a normative scoring
contract. BitGN was checked against official published rules and leaderboard
pages, including a follow-up by a Luna agent. No scoring implementation or live
result was reproduced. Branch URLs and live leaderboard contents can change.

## Accepted context

- Ranked solutions must be produced without human hints or manual task execution.
  Pre-start setup and technical access/tool confirmations are allowed; training
  is exempt. Publish this participation rule without claiming independently
  verified autonomy of an externally hosted agent. Enforcement/review mechanics
  remain to be designed; approval events alone are not evidence of assistance.

- First task directions: x402 agent payments and basic Web3 operations.
- The user permits detailed open-task solutions on the forum during the active
  benchmark version. Participants may use published solutions; the ranking must
  explicitly disclose that fixed inputs and shared solutions do not establish
  unseen-task generalization. Publication alone does not exclude a run or justify
  moderation for open tasks. The second review selected a closed ranked-only
  subset within the same twelve tasks, with conditions/solutions withheld from
  publication until version retirement. The selected closed tasks are S3/M2/H3/U1;
  training has eight open tasks for 0.5 USDC, denominator 15. Closed feedback is
  score plus reason category without exact case parameters or the correct solution.
  Exact rubrics/gates need refinement; no new weights or automatic sanctions are selected.
  This does not publish the
  platform's reference solutions, introduce public replay or permit live human
  solution assistance. Participant posts remain untrusted discussion.
- Initial ranked suite: 12 tasks, comprising 4 simple, 4 medium, 3 hard, 1 ultra.
  Duration refers to agent execution, not the owner's continuous attention;
  no numerical duration or timeout has been selected.
- Time limits have two selected levels: per-task limits based on difficulty and
  an overall run limit. Numerical values require pilot observations; expiry
  and time-accounting details remain open.
- An ordinary operation error does not end the task: the agent may retry/change
  approach within the remaining time/budget and without resetting state.
  Mandatory-constraint violations still zero task credit irreversibly. This is
  not a policy to blindly repeat operations with unknown effects.
- Difficulty uses required reference-solution actions: simple 1–2, medium 3–5,
  hard 6–9, ultra 10+. Actual participant tool calls are measured separately.
- Training and ranked modes are in the MVP.
- Training supports individual open tasks, a selected open subset or all eight open tasks, with
  detailed feedback after each task. Full training initially costs 0.5 USDC;
  subsets cost that price times their share of the open training-set difficulty
  weights (currently total 15). Prices are configurable to zero; rounding/quotes
  remain open. Ranked runs require
  the full twelve-task suite and provide per-task scores/overall results after
  run completion, without reference solutions or coaching hints. Ordinary tool
  responses/errors remain immediate in both modes. Training never enters ranking;
  internal feedback does not select detailed public run cards/replay for MVP.
- Reserve the run fee when queued and debit before the first task once the
  environment is ready. Queue waiting does not consume the run timer. Pre-start
  cancellation releases the reservation; voluntary post-start cancellation does
  not refund the fee and the incomplete run is not ranked. This does not replace
  the separate infrastructure recovery/refund policy.
- The user selected one overall leaderboard, with increased contribution from
  harder task categories. Separate x402/Web3 leaderboards were not selected.
- Initial per-task difficulty weights are selected: simple 1, medium 2, hard 3,
  ultra 5. Review against pilot outcomes before freezing the benchmark version.
- Overall score is the difficulty-weighted mean across all twelve tasks on a
  0–100 scale, without additional x402/Web3 direction coefficients.
- After ordinary agent failure, record the task's evaluated credit and continue
  the other independent tasks. Deliver tasks one at a time in a fixed order
  pinned to the benchmark version. No arbitrary order or parallel task execution
  is selected for MVP.
- When platform infrastructure prevents reliable evaluation, first recover /
  recheck evidence without repeating agent actions. If recovery fails, the run
  is excluded from ranking and its fee refunded. While a proven platform failure
  prevents new actions, exclude its recovery interval from task/run execution
  timers; ordinary agent disconnection still consumes time. Recovery duration,
  interval attribution, other unknown causes and expiry details remain open.
- Equal final scores share a rank. Speed remains separate, without a speed
  tiebreaker. Exact score precision and stable display order within ties remain open.
- Partial credit is awarded for predefined verified task outcomes, not the
  number of steps or tool calls. A mandatory task-constraint violation zeros
  that task's credit even if some other outcomes were achieved.
- Technically valid learning mistakes in isolated test state execute and are
  evaluated from actual effects, rather than being silently corrected or rejected
  merely for missing the task goal. Isolation/admin/foreign-run/real-fund and hard
  infrastructure boundaries remain enforced; genuine contract/protocol failures
  retain their observed result. A verified mandatory violation keeps the same
  zero-credit rule; a blocked attempt is still separately measured as below.
- A forbidden request verifiably rejected before execution does not automatically
  zero task credit: continue under the same limits and report the unsafe attempt
  separately. If published criteria forbid the attempt itself, it is a verified
  violation. Missing/uncertain execution remains unknown, not a proven rejection.
- ETH-denominated task costs use the user-selected fixed educational ETH/USDC
  rate pinned to the benchmark version and disclosed in conditions. It does not
  replace actual execution quotes or real account payment values. The number,
  included costs and rounding remain design work.
- Native ETH and WETH are distinct task assets; the agent explicitly chooses
  wrap/unwrap and amount. WETH does not satisfy an ETH goal or gas reserve. Grade
  the asset-specific condition from actual balance/effect evidence under the
  published rubric, without treating economic valuation as asset equivalence or
  adding an unselected blanket zero. Necessary explicit conversions affect
  reference action counts; actual difficulty still needs verification.
- The leaderboard uses the agent's best complete eligible ranked run. Training
  runs do not enter the leaderboard; latest-run or repeated-trial aggregation
  was not selected for the MVP.
- Keep one public agent page across updates. Bind runs to owner-declared versions
  and show the version that achieved the best result; ranking is not limited to
  the current declared version. External configuration remains unverified. An
  independent version-comparison feature remains later scope. Version labels do
  not make different benchmark/rule versions automatically comparable.
- Completed eligible ranked results update the public best result automatically
  when improved; the owner does not separately approve publication. Detailed
  public run cards and replay remain later scope.
- Public agent results show overall plus four difficulty indicators (simple,
  medium, hard, ultra), selected by the user. All five values describe the same
  best run; this does not create separate difficulty boards or publish per-task
  error reasons. The proposed normalization and implementation boundary are in
  [the leaderboard/page packet](../openspec/changes/benchmark-leaderboard-and-agent-pages/proposal.md).
- A disconnected/restarted agent may resume the same stateful run before the
  deadline; time continues and tasks are not reissued. Numerical deadlines and
  expiry/eligibility rules remain open. This does not equate a closed HTTP
  transport with a terminal run failure.
- Success is a primary signal; safety, speed, and economic outcome remain
  separate measurements. Detailed credit rubrics, unknown-result eligibility and
  comparability rules remain open.

## What the BitGN sources establish

| Source | Observed contract |
| --- | --- |
| [PAC scoring rules](https://github.com/bitgn/challenges/blob/main/pac/04_scoring_penalties_leaderboards.md) | Default one point per trial, penalties down to zero, summed/normalized scores, unweighted trials by default. Same score means same rank. |
| [ECOM1 scoring rules](https://github.com/bitgn/challenges/blob/main/ecom/04_scoring_penalties_leaderboards.md) | Same broad points model and tie rule. The published document does not provide a combined Accuracy/Speed/Ultimate formula. |
| [PAC challenge](https://bitgn.com/challenge/PAC) | Separate frozen Accuracy/Ultimate boards and ongoing DEV/PROD boards. |
| [ECOM1 challenge](https://bitgn.com/challenge/ecom) | Separate frozen Accuracy/Speed/Ultimate boards and ongoing DEV/PROD boards. |
| [ECOM1 Accuracy](https://bitgn.com/l/ecom1-accuracy) | One nominated blind run per participant. |
| [ECOM1 Ultimate](https://bitgn.com/l/ecom1-ultimate) | Best blind score regardless of nomination, not a sum across boards. |
| [ECOM1 Speed](https://bitgn.com/l/ecom1-speed) | Eligible nominated blind runs have total thinking time at most 60 minutes; displayed ordering uses points. No score/time coefficient formula was found. |
| [ECOM1 PROD](https://bitgn.com/l/ecom1-prod) | Best evaluated run per account; description says `total_trials x score`. The separate `xN` account badge counts positive-scoring submissions, not a score multiplier. |
| [PAC quickstart](https://bitgn.com/start/PAC) | Points accumulate task scores; displayed ceiling and coverage depend on the benchmark. Time sums trial durations. |
| [Agentic LLM benchmark introduction](https://bitgn.com/benchmarks/intro) | Separate model study: deterministic per-task penalties and averaged task scores; subset averages form subscores. This is not aggregation of agent-competition boards. |

The source review partly confirms the user's recollection: there are multiple
leaderboards and summed task points. A general coefficient-weighted combination
of those leaderboards was not established. Individual task penalty weights in
the model study are a different concept from weights between leaderboards.
Exact checker penalties and implemented normalization are not fully specified
by the inspected public prose; do not infer their values.

## Separate design decisions for our product

1. **Task score:** predefined verified partial outcomes receive credit; mandatory
   constraint violations give zero for the task. Define the exact rubric/evidence.
2. **Suite aggregation:** selected difficulty-weighted mean over all twelve
   tasks, without extra direction coefficients; define per-task credit precisely.
3. **Official run eligibility:** matching benchmark version, task inventory,
   environment, evidence, and declared agent version.
4. **Attempt selection:** best complete eligible ranked run is selected. Define
   matching agent/benchmark identity and comparison boundaries; retain the
   achieving owner-declared version rather than restricting to the current version.
5. **Displayed board:** one overall leaderboard plus four difficulty indicators
   from the same best run is selected. These indicators are not additional boards.
6. **Ties and stability:** equal rank is selected, with speed separate. Define
   score precision, stable display order within ties and uncertainty presentation.

These are related decisions but are not interchangeable. A new leaderboard view
does not necessarily require a new composite scoring formula.

## Aggregation alternatives and selection status

| Alternative | Benefit | Tradeoff |
| --- | --- | --- |
| Equal weight per task across the entire fixed suite | Easiest to explain and audit. | Not selected: user wants increased weight for harder categories. Also, adding tasks changes implicit direction weights. |
| Fixed direction weights, equal task weights within each direction | Keeps intended product coverage stable when counts differ. | Not selected: MVP has difficulty weighting without additional direction coefficients. |
| Difficulty weights over the complete task inventory | Initial difficulty weights 1/2/3/5 and no extra direction balancing are selected. | Category contributions still depend on task counts; sparse hard cells require pilot calibration against concrete tasks. |
| Composite of quality, speed, and economic result | One headline number for multiple preferences. | Requires published normalization and comparable evidence; tradeoffs may let fast but poor execution outrank better completion. Not recommended as the first uncalibrated formula. |

Considered alternative, not selected:

`overall = 0.5 * x402_score + 0.5 * web3_score`

Here each direction score is normalized against a fixed complete task inventory.
The 50/50 weights are an unselected alternative, not a measured optimum.
For example, ten payment tasks and five Web3 tasks yield implicit 2/3 versus 1/3
in a simple per-task average; fixed direction weights would avoid that accidental
allocation. The two directions must have documented non-overlapping assignment
or allocation rules before this formula is executable.

Selected display: one overall leaderboard. Initial difficulty weights are 1/2/3/5,
without extra direction coefficients. Speed and economic outcome are separate measurements;
including either in the headline formula has not been approved. The user selected
four difficulty indicators beside the overall result; no extra boards are added.

Selected aggregation formula, subject to the remaining rubric/eligibility design:
`score = 100 * sum(weight[difficulty_i] * credit_i) / sum(weight[difficulty_i])`
over the fixed official twelve-task inventory, with normalized verified credit
in [0, 1] and initial weight denominator 26. Detailed task-credit rubrics,
eligibility and unknown handling must be agreed before executable use. Unknown
is not a numeric zero; eligibility/observation resolution must precede official
aggregation. Do not omit unknown tasks or combine task maxima from different
runs into a synthetic run.

Proposed tier normalization: `100 * sum(weight * credit within tier) /
sum(weight within tier)`. With uniform weights within each selected difficulty
this is its mean completion percentage. Overall is then
`(4*simple + 8*medium + 9*hard + 5*ultra)/26`, calculated from exact inputs rather
than rounded display values. Only the same selected run supplies all components.
The ultra indicator is currently one task. Numeric representation, two-decimal
half-up display, equal-run representative selection and competition rank numbering
are proposed engineering defaults in the packet, not additional confirmed choices.

## Initial difficulty weights and comparison

The user selected the moderate 1/2/3/5 weights as an initial baseline; 1/2/4/8
remains an unselected comparison. Neither establishes calibrated task difficulty.
The figures instantiate the difficulty-only weighted-average family
above, using the retained provisional 4/4/3/1 task counts. No extra direction
weight is included, matching the selected MVP aggregation.

| Category | Tasks | Moderate candidate: task weight | Moderate share of maximum score | Stronger candidate: task weight | Stronger share of maximum score |
| --- | --- | --- | --- | --- | --- |
| Simple | 4 | 1 | 15.4% | 1 | 12.5% |
| Medium | 4 | 2 | 30.8% | 2 | 25.0% |
| Hard | 3 | 3 | 34.6% | 4 | 37.5% |
| Ultra | 1 | 5 | 19.2% | 8 | 25.0% |

The weight denominators are 26 and 32 respectively. Shares are rounded only for
this illustration. Partial credit must be normalized to the defined per-task
credit range before weighting. Unknown evidence cannot be silently treated as
zero or removed from the denominator. A run must first satisfy the eventual
eligibility/known-outcome policy before producing an official score.

Selected initial coefficients: 1/2/3/5, so a single ultra task contributes about
19.2% of the maximum score under the difficulty-only formula. Pilot rubrics
and observed task difficulty may justify revisiting them before a public version
is frozen. This is a design judgment, not an empirically optimal formula.
The user selected separate rankings per benchmark version. When changed tasks,
criteria, weights or educational valuation produce a new version, the main board
shows that new version and the previous board remains available in history.
Do not mix scores from different benchmark versions or silently recalculate old
results. Within each benchmark version, keep the agent's best eligible complete
run across its owner-declared agent versions and show the achieving agent version.
This is one overall board per benchmark version, not separate direction boards.

Ranked starting conditions are identical across participants and repeated runs
within that version, as selected by the user; training uses separate conditions.
Pin economically relevant task/state/offer inputs and rules, while preserving
per-task and per-participant execution isolation. This makes the fixed-workload
comparison explicit, but repeated attempts can learn the conditions. The board's
best score is not unseen-variant generalization or repeated-trial reliability.
Exact fixtures and actual equivalence/isolation acceptance still need design.

The user selected new training/ranked admission only for the active version.
Already admitted requests, including queued ones, retain their version/rules,
environment and price and may finish after activation; eligible late results
update only the matching historical board. A version switch alone does not cancel
or retarget them. Existing authorization, cancellation and time limits remain.
An authenticated idempotent retry of an admitted request is not new admission;
using a new key to start an old-version run is rejected without reservation.
Historical results remain available; historical reads do not require starting
an old environment. Version history is not a detailed public run replay.
Activation/admission concurrency and resource draining still need real acceptance.

For equal final scores, shared rank is selected. Speed is displayed separately
and is not a tiebreaker. Define score precision and stable row display order
without turning that display order into a distinct rank.

## Evidence and eligibility considerations to resolve

- A short preflight or cherry-picked easy subset should not compete as a complete
  ranked suite. Publish completion/coverage separately.
- Missing or contradictory environment evidence remains unknown/inconclusive.
  An official-score policy must not silently turn unknowns into successful or
  zero-valued tasks or improve a score by dropping those tasks from its denominator.
- Verified task failure, missing evidence, and platform failure are distinct.
  For infrastructure-caused evidence loss, recovery precedes exclusion/refund
  and must not repeat agent actions. Specify recovery windows, timer interaction,
  idempotent refund, interrupted-run policy and other unresolved evidence causes.
- Mandatory task-constraint violations zero that task's credit. Define the
  constraint inventory and retain violation details separately. Run-level
  disqualification for proven successful agent interference with service state
  or another run is now confirmed: exclude the current run and retain its fee
  without refund. It is distinct from ordinary task failure or a blocked request;
  exact trusted observation and causal attribution remain environment design work.
- Speed should compare fixed workloads and defined server-observed intervals.
  It cannot establish the external owner's internal model thinking time.
- Economic results require task-specific normalization under pinned simulated
  conditions. Do not pool raw ETH received, gas units, and USDC savings.
- Unverified inference cost must remain unavailable for cost ranking; it is not
  zero. Real platform fees are separate from simulated transaction costs.
- The selected best-run record favors repeated attempts; display that limitation
  honestly. Attempt pricing/limits and version creation/editing rules remain open.
  A new agent version does not itself discard the best eligible historical run;
  display the achieving version. A best score is not repeated-trial reliability.

## Next discussion

The user confirmed separating operating expenses (paid data, gas from successful
and failed executed transactions, and exchange fees counted once) from exchanged
principal, payout objectives and remaining reserves. Exact formulas and evidence
are still task-specific. Evaluate conditions at completion with retained violation
history; a temporarily reached state later undone is not a completed goal. Partial
credit for independently verified satisfied conditions remains in place. These
rules do not add an economic multiplier to the overall difficulty-weighted score.
The selected MVP gas model uses observed local-EVM fees at version-pinned settings;
Base L1 fees are unmodelled. Display this as educational task expense rather than
complete Base transaction cost. The [feasibility proposal](../openspec/changes/archive/2026-10-25-benchmark-environment-feasibility/proposal.md)
defines the first required execution evidence, with all gates still not_run.

The user confirmed publishing goals, mandatory constraints, weights and partial-
credit criteria before participation, while withholding exact ranked variant
inputs until task issuance and not disclosing reference solutions. The agent
uses separate basic actions and chooses offers, recipients, amounts and sequence;
platform test-wallet signing does not demonstrate the client's native signing
capability. Exact schemas, reference path lengths and per-task thresholds still
need design. These decisions change disclosure/tool design, not the selected
best-run aggregation or separate safety/speed measurements.

The displayed board, initial 1/2/3/5 difficulty weights, verified partial credit,
mandatory-constraint zeroing, best complete ranked-run selection and shared ranks
are settled, as is the difficulty-only weighted mean without extra direction
coefficients. Next define task rubrics, remaining runtime/lifecycle and
eligibility/unknown handling. Ordinary agent failures do not stop the other
independent tasks; tasks are sequential in a fixed versioned order. Failed
infrastructure evidence recovery excludes the run and refunds its fee.
Review initial coefficients
against pilot examples before freezing a public benchmark version.

The [eighth planning packet](../openspec/changes/benchmark-leaderboard-and-agent-pages/proposal.md)
includes [design](../openspec/changes/benchmark-leaderboard-and-agent-pages/design.md)
and [BDD plan](../openspec/changes/benchmark-leaderboard-and-agent-pages/bdd-design.md):
9 requirements and 14 mandatory planned scenarios against actual coordinator,
HTTP/store and browser boundaries. All gates are not_run; no score, frontend or
task-grading acceptance has been executed.

Next command: `/opsx:explore benchmark-leaderboard-and-agent-pages`.
