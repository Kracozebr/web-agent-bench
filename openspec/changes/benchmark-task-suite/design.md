## Context

Status: approved for incremental implementation on 2026-10-25; see [approval](approval.md).
Runtime acceptance remains separate. The reviewed rules and defaults are unchanged.

The reference harness does not run a product, chain or agent. Environment
feasibility must first bind actual controlled x402 and forked EVM identities.
This packet then grades observations from those boundaries; leaderboard fixtures
alone cannot prove task grading. No participant model is hosted or billed here.

## Goals / Non-Goals

**Goals:** a complete evaluable rule for every retained goal; immutable fixture
parameters; actual evidence attribution; training/ranked exposure and price;
compact closed feedback; verified coordinator-to-leaderboard integration.

**Non-Goals:** inventing market/block/contract values, reference-solution steps
for participants, new goals, secret penalties, stress injection, rotating ranked
variants, model compatibility tests, replay UI, autonomy guarantees or PvP.

## Decisions

### 1. Inventory and ownership

Fixed order: S1,S2,S3,S4,M1,M2,M3,M4,H1,H2,H3,U1. Training is the ordered
intersection of a nonempty unique request with open IDs. Closed IDs are
S3/M2/H3/U1; open IDs S1/S2/S4/M1/M3/M4/H1/H2. Weights are 1/2/3/5 by level;
ranked denominator 26 and open-training denominator 15. Training cannot silently
drop a requested closed ID and charge for a different subset.

This module owns rubrics/evidence/credit/exposure. Lifecycle owns admission,
timers/closure/cancellation/refunds; shared billing owns source allocation;
environment owns actual execution/isolation; leaderboard owns aggregation/best
selection. One graded-outcome schema crosses these ports. It must not introduce
a second timer, ledger, eligibility authority or public agent visibility policy.

### 2. Parameter-complete manifests, not invented market data

Each immutable benchmark release binds public metadata plus access-controlled
case bundles: benchmark/policy/rubric/environment versions and hashes; mode;
task ID/weight; actual asset/address/code identities; initial balances/allowances;
offers/data/route inputs; all objective quantities/tolerances; mandatory rules;
operating-cost definition; finite task/run deadlines; reference-path evidence.
Every symbolic quantity in a rubric below is a required typed manifest field.
Amounts are integer native/token base units, rates exact rationals, indicators
boolean, lists finite and unique. An unresolved placeholder is invalid, not zero.

Release construction is two-phase: obtain actual feasibility evidence, then
resolve/persist all concrete case values and validate them before activation.
No runtime lookup of latest prices or per-participant threshold recalibration.
For a DEX minimum/output/allocation threshold, pin the measured quote/state and
the resulting exact integer threshold before release; do not choose a guessed
ETH amount here. The educational rate and actual fee/payer observations are pinned
likewise. This is a release prerequisite, not a hidden choice of live market rate.

Required fields by task:

| ID | Additional required parameters |
| --- | --- |
| S1 | token, sender, recipient, exact principal A, native reserve G, unrelated-effect baseline |
| S2 | resource/offer identity, complete supported payment-requirements tuple, structured answer fields |
| S3 | scoped catalog, required data type, price ceiling, network/asset/recipient constraints, eligible-set computation |
| S4 | token, owner/spender pair, positive initial allowance, unrelated-allowance baseline |
| M1 | required resource/data schema/hash, selected permitted payer/payee/asset/network, operating ceiling B |
| M2 | finite qualifying catalog, complete advertised price per offer, equality/tie policy, required delivery, B |
| M3 | input token/principal, native ETH output minimum Q, permitted routes, declared slippage bounds, G and B |
| M4 | input/principal and output minimum, permitted routes/spenders, initial allowance map, G and B |
| H1 | finite nonempty unique required data-component set with one complete deterministic validator per component, supported sources, B, duplicate-purchase identity |
| H2 | at least two unique recipient/asset/exact-amount obligations, initial assets, permitted conversions, G and B |
| H3 | paid reference dataset/validator, fixture route objective and permitted set, input, output bound, G and combined B |
| U1 | finite nonempty unique paid-component set with complete validators, nonempty unique final-allocation asset set and target/tolerance after payouts, at least two unique payout obligations, nonempty unique declared temporary-spender set, G and B |

Validate solvability through a real reference driver using the same public tools,
not a participant-visible recipe. Initial state must not already satisfy a paid,
payout or conversion objective; an explicit allowance-removal objective must
start with an allowance to remove. U1's cleanup predicate checks its nonempty
release-declared spender set and may include unused or initially zero allowances;
zero allowances alone do not satisfy the required core-progress guard. M2 has at least two qualifying
offers with a distinct cheaper choice; all tied minima are valid if present.
S3 has feasible and nonqualifying catalog choices; H3 data distinguish allowed
routes. These are fixed base conditions, not injected transient-failure tests.
Reference path length validates the provisional difficulty; a mismatch returns
for redesign/review, never adds meaningless calls or silently reclassifies a task.
For H1/H2/U1, fractional-score denominators are the unique required identities
bound in the immutable release. H1/U1 data validators are complete and
deterministic per component; repeated purchases or caller claims cannot create
components. H2/U1 payout fractions count distinct fully fulfilled obligations,
not payout amounts. A release cannot defer, shrink, extend or recompute these
sets after admission; duplicate obligation entries are invalid rather than extra
denominator rows.
Each component validator pins its version, required payload schema/fields, exact
acceptance predicate and permitted source/provenance; the grader evaluates the
authenticated delivered payload and evidence, never a caller-supplied valid flag.
U1's cleanup scope is a nonempty set of unique owner/token/spender allowance
keys. Its entries may be unused or initially zero; no approval is required just
to create cleanup credit. A zero result across the configured scope earns the
cleanup portion only when the same cutoff also proves core data, allocation or
payout progress.

### 3. Evidence, common mandatory conditions and result arithmetic

Store task/run/environment identity, accepted-action sequence and cutoff,
operation/authorization/transaction IDs, receipts/status, observed state deltas,
data deliveries/hashes, answer payload if applicable, costs and observer
provenance with raw evidence paths/hashes. Agent assertions are not chain effects.
Read-only tasks require an authoritative complete no-effect interval, not merely
an empty receipt query. S2/S3 submit structured answers at finish; malformed
answers are rejected before finish and can be corrected within existing limits.
A valid but wrong/missing final answer is an ordinary scored failure.

Use lifecycle's finish/deadline closure. Stop new actions, reconcile already
admitted effects, evaluate final conditions and retained historical violations.
Post-cutoff and foreign observations cannot improve a result. A timeout with
complete evidence grades achieved conditions; overall incomplete-run eligibility
remains lifecycle-owned. Unknown receipt/delivery/history/state is not a zero or
success: preserve unknown and use existing recovery/refund rules without replaying
an economic action. Known agent-caused reverts are observed failures with actual
gas, not automatically a platform fault.

Notation: I(P) is 1 only when predicate P is verifiably true, otherwise 0 for a
verifiably false predicate; unknown never enters arithmetic. Each task credit
c is an exact rational in [0,1]. A proven mandatory violation makes c=0
irreversibly and follows lifecycle task termination. An ordinary rejected unsafe
attempt alone does not zero credit; none of these rubrics newly forbids the
attempt itself. No outcome points for speed, tool count, reasoning prose or
unobserved model cost. A task need not have partial credit if its goal is atomic.

Common mandatory conditions, where applicable and disclosed to the active
agent: effect scope/asset/network/recipient constraints; exact no-extra/no-overpay
rules for requested principal; final native reserve G; operating ceiling B;
historical no-unrelated-permission mutation. Do not treat every goal as mandatory:
the task table below selects which rules apply. Technically valid test mistakes
within infrastructure bounds execute and are then evaluated, not repaired by tools.

Operating expense is paid data/service charges plus actual executed gas (including
reverts) converted at the pinned educational rate plus verified DEX fees, each
once. Principal exchange/payouts/reserves are separate conditions. Fee embedded
in an amount or quote is not added twice; missing fee evidence is unknown, not
an invented zero. ETH and WETH remain distinct; wrap/unwrap are explicit and
their actual gas counts. Base L1 cost remains unmodelled as already selected.

### 4. Complete per-task rubric proposals

All predicates use the pinned case plus authenticated observations. "Allowed"
below is an evaluation constraint inside the isolated world, not permission to
reject a supported learning mistake solely because it will score badly.

| ID | Credit when no mandatory rule has been violated | Mandatory task rules and evidence |
| --- | --- | --- |
| S1 | Binary: 1 iff exactly A of the specified USDC reaches the recipient and final native reserve is at least G; otherwise 0 | No wrong/extra principal transfer or overpayment; reserve G. Actual successful receipt, principal deltas and native gas; fees are not extra recipient principal. No points for merely retaining the initial reserve. |
| S2 | 0.4 times I(correct complete amount) + 0.3 times I(correct network/asset/recipient tuple) + 0.3 times I(correct scheme/resource/offer identity); absent/wrong groups earn 0 | No payment, delivered paid resource or other state mutation. Compare structured answer with the actual observed immutable requirements; complete no-effect evidence. Technical auth/version fields required by the pinned scheme are part of the identity group, not invented universal headers. |
| S3 | Binary: 1 iff final selected scoped offer satisfies all required type/price/network/asset/recipient predicates; otherwise 0 | No payment/delivery/state mutation. Derive qualifying set from the fixed catalog, not a caller-supplied eligible flag; no requirement to select the cheapest unless the case explicitly says so (M2 tests that). |
| S4 | Binary: 1 iff the specified initially positive allowance is zero at finish; otherwise 0 | No unrelated allowance mutation or principal movement. Observe actual allowance before/after plus receipt/history; restoring an unrelated changed allowance does not erase the violation. |
| M1 | Binary: 1 iff permitted exact payment is settled and required data are verifiably delivered within B; otherwise 0 for known ordinary failure | Resource/asset/network/payee scope, no duplicate charge/extra purchase, B. Correlate offer, authorization, actual token effect and delivery hash; settlement verification alone is not delivery. Missing platform delivery evidence is unknown, not a partial fabricated purchase. |
| M2 | 0.4 times I(qualifying required delivery) + 0.6 times I(qualifying delivery at a minimum advertised qualifying total price) | Permitted scope, no extra/duplicate purchase, B. Minimum includes all advertised service charges; actual gas also counts in B but is not silently added to the advertised-price ordering. All equal minima are valid. More expensive qualifying purchase can earn 0.4. |
| M3 | Binary: 1 iff exactly the input principal is exchanged through an allowed route to at least Q native ETH with the specified slippage rules; otherwise 0 | No wrong/extra principal operation, G, B. Receipts, route and separate ETH/WETH observations. WETH-only output cannot meet Q; absent unwrap is not repaired automatically. Reverted execution still consumes observed gas. |
| M4 | 0.7 times I(required exchange outcome) + 0.3 times I(required exchange outcome AND all used temporary router allowances zero at finish) | Permitted assets/routes/principal, no unrelated allowance mutation, G, B. Exchange with residual permitted allowance earns 0.7; doing nothing or merely clearing pre-existing state earns no cleanup points. Preserve intermediate approvals/history. |
| H1 | Number of distinct required component identities whose pinned validators pass on authenticated delivery evidence, divided by the number of required identities fixed in the release | Permitted sources/payment scope, no duplicate purchase, B. Count each component once by validator/hash/provenance, never each purchase/caller claim or amount paid. Incomplete but known valid subset earns its exact fraction. |
| H2 | Number of distinct payout obligations exactly fulfilled, divided by the number of unique obligations fixed in the release | No wrong/extra recipient/asset/overpayment, only permitted conversions, G, B. Actual recipient deltas identify each obligation; payout amounts do not weight the fraction and principal is not operating expense. A supported failed conversion is not automatically a platform failure; unmet obligations remain unmet. |
| H3 | 0.3 times I(required paid reference delivered) + 0.7 times I(required reference delivered before the relevant trade AND route objective and exchange outcome achieved) | Permitted scope/principal/routes, G, combined B. Derive route objective from authenticated purchased data and pin its rule; retain delivery-before-action order and actual execution. A self-reported reference ID or correct route guessed before delivery cannot earn the dependent 0.7. This proves observable dependency/order, not the model's internal reasoning. |
| U1 | 0.20 × (distinct required components with passing pinned validators / N_data) + 0.25 × I(final post-payout allocation is within the pinned target/tolerance) + 0.35 × (distinct exactly fulfilled obligations / N_payout) + 0.20 × I(all allowances in the nonempty declared spender set are zero AND a core data/allocation/payout objective was verifiably achieved), where positive N_data and N_payout are fixed by the release | The release binds a finite nonempty unique component set with one complete deterministic validator per component, at least two unique recipient/asset/exact-amount payout obligations, a nonempty unique allocation-asset set with its complete target/tolerance, and a nonempty unique declared temporary-spender set. No wrong/extra principal effect or overpayment, permitted routes/sources/conversions, no unrelated permission mutation, G, B. Repeated purchases, payout amounts and caller claims cannot change the exact fractions or release-pinned denominators. Evaluate allocation on remaining assets after payouts with pinned rational valuation/tolerance; paid-data/gas/DEX expense counted once. Initial state is not a solved allocation. Cleanup alone is not free credit; the set may include unused or initially zero allowances, and U1 does not require creating an allowance solely to earn cleanup credit. All final predicates use one cutoff. |

The specific 40/30/30, 40/60, 70/30, 30/70 and 20/25/35/20
splits are proposed visible rubric policy and require review before execution.
No task's mandatory rule is inferred from a vague goal or added after issuance.
Before activation the manifest enumerates exact mandatory predicates/quantities
from the relevant row, all exposed to the active agent before it can act.

### 5. Exposure, pricing, feedback and forum boundary

Public metadata shows skill, difficulty/weight, scoring policy and availability;
it does not ship full closed cases, parameters or reference solutions. The active
scoped agent receives every necessary condition at task issuance. Training uses
distinct open cases. No closed ID via training API/direct URL/cache; no mixed
selection silently reduced to an open subset. No raw journal or public replay.

Full ranked price 1 USDC; full open training 0.5. A new training quote uses
ceil(P_micro * selected_open_weight / 15) once for the whole request; configured
zero stays zero. More generally use the version's open weight sum, validated
against inventory. Existing admitted snapshots are not repriced. Bonus/cash
source policy, current permissions and budget reservations stay shared.

Training explanations after each open task can show its achieved/missed
conditions and observed training values. Ranked feedback only after termination:
open score/reasons without coaching; closed score plus allowlisted reason
category (goal unmet, budget/reserve/permission/scope violation, time exhausted,
evidence unknown) with no exact case parameters, expected answer or solution.
Each reason has a deterministic evidence-bound rule and release projection.
Public agent/board retains overall plus four difficulty indicators, not new
open/closed boards. Private response bodies, HTML/hydration and caches must
enforce the same projection; required normal task tool responses remain immediate.

Forum policy permits open solutions during the active version and closed
solutions after retirement. Proposed MVP enforcement is existing authorized
manual moderation with reason/audit and existing author-violation fee policy.
No automatic leak classifier, score disqualification or account freeze. A third
party allegation alone is not proof. Storing forensic evidence does not make it
participant/public content; retired versions do not automatically publish logs.

### 6. Verification and replay boundary

The real task gate uses actual authenticated tool HTTP, controlled x402/local
settlement, fork-backed EVM receipts and durable application stores. A scripted
reference driver proves execution/evaluation mechanics, not agent intelligence,
native x402 implementation, mainnet or human independence. Each task has success
and targeted negative/partial cases, plus shared unknown/cutoff/isolation cases.
No Python in-memory grader or fabricated credit fixture can replace these gates.

Read-only reconstruction reuses preserved manifest, cutoff and original raw
observations to recompute rational credit and detect divergence, without executing
actions, rewriting scores or triggering refunds. Signed/scoped graded outcomes
are consumed exactly once by actual lifecycle and leaderboard services. Their
own rules still decide complete-run eligibility and best-result publication.

## Risks / Trade-offs

- Fixed cases and repeated best scores can be learned; external agents expose
  inputs locally. Compact feedback and embargo reduce disclosure, not guarantee secrecy.
- Closed U1 means no full ultra training; selected intentionally, components
  remain open. Closed weight is 11/26, not an extra coefficient.
- Exact fee evidence and realistic route thresholds depend on feasibility.
  Missing prerequisites block release/task gates, not justify a toy-market pass.
- Short deadlines can penalize clients/approvals. Measure before pinning finite
  values; preserve platform-failure clock exclusions and speed as a separate metric.
- Public source/images must not contain closed bundles; keep actual case storage
  separate from public artifacts and retain controlled compact scoring evidence.

## Migration Plan

Add manifest/evaluator ports and the graded-outcome store after scoped approval.
Register active-delta harness support before executing new gates; preserve main
WB/PV baseline. Bind real environment evidence, construct/validate sealed cases,
run every mandatory task/integration/projection gate, then activate one pinned
version. Rollback stops new admissions, preserves admitted snapshots/evidence and
uses existing reconciliation; do not recalculate old results under new rubrics.

## Open Questions

Rubric credit splits and the exact mandatory-predicate lists require review.
Runtime block/contracts, concrete case values, educational rate, fees, timeouts
and reference path lengths must be resolved/measured before release. None are
claimed verified here. Founder-only admin/bootstrap, general recovery/ledger and
quick-start/privacy contracts remain in their respective planning work, not
silently implemented by this task suite.
