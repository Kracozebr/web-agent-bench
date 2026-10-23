# Benchmark task suite

Status: proposed; scenario and implementation approval is pending. Every new gate is not_run. Product scope is confirmed; detailed rubric credit splits require review. No mainnet or agent-autonomy claim.

## ADDED Requirements

### Requirement: BTS-REQ-001 Validate a parameter-complete immutable task release
The service SHALL validate an immutable manifest for ordered S1,S2,S3,S4,M1,M2,M3,M4,H1,H2,H3,U1, levels/weights 1/2/3/5, ranked weight sum 26, exposure, mode-specific case/rubric hashes, actual execution/asset/contract identities, initial state, complete objective quantities, mandatory rules, cost/valuation policy and finite deadlines. Every quantity referenced below SHALL resolve to typed case data before activation; unresolved placeholders and per-run latest quotes SHALL be invalid. Closed cases SHALL stay access-controlled. Actual feasibility and same-tool reference-path evidence SHALL bind the release; missing prerequisites SHALL block activation rather than substitute a model. Training and ranked cases SHALL differ. Solvability, nontrivial initial state and provisional difficulty SHALL be validated before release without silent goal/weight changes. H1 and U1 component sets SHALL be finite, nonempty and unique, with a complete deterministic validator pinned for every required component. Each component validator SHALL pin its version, required payload schema/fields, exact acceptance predicate and permitted source/provenance; a caller-supplied validity flag SHALL NOT satisfy it. H2 and U1 payout sets SHALL contain at least two unique recipient/asset/exact-amount obligations and SHALL reject duplicate entries. U1 SHALL also bind a nonempty allocation-asset set and a finite, unique declared temporary-spender allowance scope. Set identities, validators and cardinalities SHALL be immutable parts of the release case; invalid or incomplete sets SHALL prevent activation, task admission and charge.

#### Scenario: BTS-SC-001 Actual manifests bind the fixed inventory and source evidence
- **WHEN** a release candidate is constructed from actual feasibility and same-tool reference-path evidence and its complete case manifest is validated
- **THEN** the accepted manifest SHALL bind immutable inventory case rubric and execution identities before task admission without claiming measured difficulty from labels alone

#### Scenario: BTS-SC-002 Incomplete substituted or unsolvable releases cannot activate
- **WHEN** validation receives unresolved amounts, wrong block/code identities, missing or incomplete data validators, no qualifying offer, an initially solved paid/payout case or initially satisfied U1 final-allocation objective, empty/duplicate U1 component/allocation-asset/spender sets, fewer than two unique U1 payout obligations or duplicate payout entries
- **THEN** activation SHALL fail before task admission or any charge and preserve invalid-field or missing-prerequisite evidence instead of inventing defaults

### Requirement: BTS-REQ-002 Enforce the selected open training set and price
Training SHALL allow a nonempty unique selection only from S1,S2,S4,M1,M3,M4,H1,H2 in fixed release order. S3,M2,H3,U1 SHALL be ranked-only; ranked SHALL contain all twelve. Any closed/invalid requested training ID SHALL reject before reservation without silent filtering. Initial full open training SHALL cost 0.5 USDC and full ranked 1 USDC, configurable including zero. New training quotes SHALL use ceil(P_micro * selected_open_weight / open_weight_sum) once per request, initially denominator 15. Actual source allocation, limits and immutable admitted price/version snapshots SHALL remain lifecycle/billing-owned; later changes SHALL NOT reprice admitted work.

#### Scenario: BTS-SC-003 Open selections quote one whole-request price with denominator fifteen
- **WHEN** agents quote full open training weighted subsets and full ranked then retry admitted reservations after price or version changes
- **THEN** quotes SHALL use eight open tasks at 0.5 USDC subsets rounded once over weight fifteen and twelve ranked tasks at 1 USDC while admitted reservations retain their pinned price and source identities

#### Scenario: BTS-SC-004 Closed training IDs are denied before financial effects
- **WHEN** a scoped caller requests a closed ID alone or mixed with open IDs through tools direct HTTP or a stale training link
- **THEN** the entire request SHALL reject without a case payload run or reservation rather than filter the selection or expose closed parameters

### Requirement: BTS-REQ-003 Grade authoritative cutoff evidence and preserve unknown
Evaluation SHALL bind owner/agent/run/task/environment, release/rubric, accepted-action sequence/cutoff, original receipts/delivery/state and raw paths/hashes. It SHALL reconcile admitted effects and reject post-cutoff/foreign attribution. Known failures SHALL follow the rubric; missing/contradictory/unverifiable evidence SHALL remain unknown under lifecycle recovery without economic replay. Proven mandatory violation SHALL irreversibly zero the task under existing termination rules; a rejected attempt alone SHALL NOT invent a violation. Credit SHALL be exact rational [0,1]; speed/tool count/safety/unobserved inference cost SHALL remain separate. Operating expense SHALL count actual paid charges, successful/reverted gas at the pinned educational rate and verified DEX fees once, separately from principal/payout/reserve. ETH and WETH SHALL remain distinct. Missing fee evidence SHALL NOT become zero.

#### Scenario: BTS-SC-005 Cutoff evaluation uses observed final state and historical violations
- **WHEN** selected operations finish around the lifecycle cutoff and a known mandatory violation is followed by an attempted repair
- **THEN** grading SHALL reconcile admitted effects evaluate one final snapshot retain the proven violation as zero and ignore late or foreign effects without another economic action

#### Scenario: BTS-SC-006 Unknown observations never become success or a fabricated zero
- **WHEN** evidence has a missing receipt contradictory state or unverified delivery and recovery or read-only reconstruction is attempted
- **THEN** the task SHALL remain unknown until original evidence resolves it and reconstruction SHALL detect divergence without action replay score overwrite fabricated zero or duplicate refund

### Requirement: BTS-REQ-004 Project release-correct compact closed feedback
The active scoped agent SHALL receive all task conditions/constraints and normal tool responses; no undisclosed mandatory penalty is allowed. Public metadata SHALL expose skill/level/weight/scoring policy/availability without full closed cases. Training explanations SHALL release after each open task. Ranked feedback SHALL release after run termination: closed tasks SHALL expose score and allowlisted evidence-backed reason categories without exact case parameters, expected answers or reference solutions. Owner pages SHALL require owner authority; agent feedback SHALL remain a separate scoped lifecycle surface. Anonymous/foreign HTML/API/hydration/cache SHALL NOT expose private/sealed material. Existing overall/four-tier public results SHALL remain unchanged. Retirement SHALL end the forum embargo without automatically publishing internal logs/solutions.

#### Scenario: BTS-SC-007 Issuance and post-run projections disclose only authorized fields
- **WHEN** an actual scoped run receives open and closed tasks and its owner reads training post-task and ranked post-run results
- **THEN** the agent SHALL receive necessary conditions while owner feedback follows release timing and closed results expose only score and allowed reason category without exact case solution or journal

#### Scenario: BTS-SC-008 Public foreign and cache surfaces do not leak closed cases
- **WHEN** anonymous foreign-owner and delegated credentials request owner results closed task data and cached or rendered bodies outside their scope
- **THEN** unauthorized surfaces SHALL deny private case access and public metadata SHALL remain safe without treating a normal scoped tool response as public content

### Requirement: BTS-REQ-005 Integrate actual graded outcomes without a second score authority
Actual grading SHALL emit one immutable provenance-bound outcome per lifecycle task/cutoff to the real coordinator and leaderboard. Complete eligible ranked runs SHALL use all twelve exact credits and pinned weights. Training/incomplete/unknown or caller-forged outcomes SHALL NOT gain official eligibility. Duplicate handoff/reconstruction SHALL NOT duplicate outcomes, actions, charges or scored results. Mandatory integration acceptance SHALL grade actual x402/EVM observations rather than supplied leaderboard credit fixtures.

#### Scenario: BTS-SC-009 Real twelve-task execution reaches the versioned leaderboard once
- **WHEN** a reference driver completes the actual ranked suite through real tools and duplicate graded-outcome handoffs or restart reach lifecycle and scoring services
- **THEN** the services SHALL preserve twelve evidence-bound credits one eligible versioned aggregate and one best-result update while rejecting forged or unknown outcomes without another action charge or result

### Requirement: BTS-REQ-006 Preserve basic decision tools and isolated learning effects
Participants SHALL choose offer/recipient/asset/amount/route/sequence through common basic tools including explicit ETH/WETH conversion. Supported technically valid learning mistakes inside task scope SHALL execute and be evaluated without automatic repair or goal-based rejection. Foreign/admin/setup/raw-signing/real-fund access SHALL remain blocked by environment policy. Task expense/reserve goals SHALL remain separate from hard resource and real service billing limits. Reference drivers SHALL use the same participant surface; private solver/grader calls SHALL NOT prove actual acceptance.

#### Scenario: BTS-SC-010 Basic tools execute isolated mistakes while blocking foreign authority
- **WHEN** a scoped driver chooses a wrong supported test recipient or excess local allowance then attempts foreign task setup raw signing and real-fund access
- **THEN** supported learning mistakes SHALL preserve chosen parameters and observed effects for grading while boundary attacks are rejected without foreign or real-fund effects or automatic route and asset repair

### Requirement: BTS-REQ-007 Grade the exact requested USDC transfer
S1 case data SHALL bind token/sender/recipient, exact principal A and native reserve G. Binary credit one SHALL require exactly A delivered and final reserve at least G. Wrong/extra principal transfer, overpayment or G breach SHALL be mandatory zero; retaining initial reserve alone SHALL earn no credit. Actual successful receipt and recipient/native deltas SHALL prove effects; gas SHALL NOT count as extra recipient principal.

#### Scenario: BTS-SC-011 S1 observed goal earns full credit
- **WHEN** the driver transfers exact A to the specified recipient and retains native reserve G
- **THEN** S1 SHALL receive exact credit one from the actual receipt principal deltas and reserve observations

#### Scenario: BTS-SC-012 S1 wrong transfers and reserve violations remain failures
- **WHEN** the driver sends a wrong amount or recipient adds a principal transfer or breaches G
- **THEN** S1 SHALL receive known zero without silent transfer repair or gas being misclassified as extra recipient principal

### Requirement: BTS-REQ-008 Grade the complete read-only x402 offer
S2 SHALL bind the actual immutable resource and supported scheme requirements. Structured final answers SHALL earn 0.4 for correct complete amount, 0.3 for the complete correct network/asset/recipient tuple and 0.3 for correct scheme/resource/offer identity including required version/auth fields. Wrong/absent groups SHALL earn zero per group. Any actual payment, paid-resource delivery or state mutation SHALL be mandatory zero. Complete authoritative absence-of-effect evidence SHALL be required, not merely an empty receipt query.

#### Scenario: BTS-SC-013 S2 complete observed requirements earn full credit
- **WHEN** the driver reads an actual offer and submits its complete correct structured requirements without paying
- **THEN** S2 SHALL receive exact credit one from observed amount tuple identity and complete no-effect evidence

#### Scenario: BTS-SC-014 S2 wrong groups lose defined credit and payment zeros the task
- **WHEN** final answers omit or change price tuple or scheme fields and an actual purchase variant is exercised
- **THEN** known wrong groups SHALL lose exactly their defined credit while a proven paid or mutating effect zeros S2 and missing effect evidence remains unknown

### Requirement: BTS-REQ-009 Grade constrained read-only offer selection
S3 SHALL bind catalog plus required type/price/network/asset/recipient predicates. Binary credit one SHALL require a final selected scoped offer satisfying all predicates, without an unstated cheapest-choice criterion. Qualifying membership SHALL be derived from the pinned catalog, not caller eligibility flags. Actual payment/delivery/state mutation SHALL be mandatory zero, with complete no-effect evidence required for a valid read-only result.

#### Scenario: BTS-SC-015 S3 constrained selection earns full credit
- **WHEN** the driver selects an offer meeting every pinned predicate without a purchase
- **THEN** S3 SHALL receive exact credit one from the actual catalog selected offer predicates and complete no-effect interval

#### Scenario: BTS-SC-016 S3 nonqualifying selection and paid effects cannot succeed
- **WHEN** the driver selects a nonqualifying offer forges eligibility or actually pays for a resource
- **THEN** caller eligibility SHALL confer no credit a known wrong selection scores zero and a proven forbidden paid effect irreversibly zeros S3

### Requirement: BTS-REQ-010 Grade allowance removal without unrelated changes
S4 SHALL start with a positive specified token/owner/spender allowance and bind unrelated baselines. Binary credit one SHALL require target allowance zero at finish. Any unrelated allowance mutation or principal movement SHALL be mandatory zero even if restored. Actual allowance observations, receipt and retained action history SHALL prove the result.

#### Scenario: BTS-SC-017 S4 target revocation earns full credit
- **WHEN** the driver revokes the specified positive allowance and leaves unrelated state unchanged
- **THEN** S4 SHALL receive exact credit one from target allowance receipt and unrelated-state history

#### Scenario: BTS-SC-018 S4 residual and repaired unrelated mutations cannot pass
- **WHEN** the driver leaves a residual allowance mutates and restores unrelated permission or moves principal
- **THEN** a known residual SHALL fail the goal and proven unrelated mutation or principal movement keeps mandatory zero despite repair

### Requirement: BTS-REQ-011 Grade one settled resource and verified delivery
M1 SHALL bind required resource/data validator, exact permitted payment requirements and expense ceiling B. Binary credit one SHALL require actual settlement and validated requested delivery. Resource/asset/network/payee violations, extra/duplicate purchase or B breach SHALL be mandatory zero. Verification without token effect SHALL NOT prove settlement; unobserved platform delivery SHALL remain unknown rather than fabricated partial purchase credit.

#### Scenario: BTS-SC-019 M1 actual payment and delivery earn full credit
- **WHEN** the driver buys the specified controlled x402 resource and receives validated data within B
- **THEN** M1 SHALL receive exact credit one after correlating offer authorization token effects delivery and expenses

#### Scenario: BTS-SC-020 M1 known violations and unresolved delivery stay distinct
- **WHEN** the driver buys a wrong resource duplicates purchase or exceeds B and incomplete settlement or delivery evidence is separately exercised
- **THEN** known violations SHALL zero M1 while unverifiable payment or delivery stays unknown rather than paid success or fabricated partial credit

### Requirement: BTS-REQ-012 Grade the cheapest qualifying resource
M2 SHALL bind a finite qualifying catalog with at least two choices, complete advertised prices, delivery validators and B. Credit SHALL be 0.4 for qualifying delivery plus 0.6 for that delivery at any minimum advertised qualifying total price; all tied minima SHALL qualify. Advertised price includes all stated service charges; actual gas SHALL count in B separately without silently changing the price ordering or double counting. Scope violation, extra/duplicate purchase or B breach SHALL be mandatory zero.

#### Scenario: BTS-SC-021 M2 minimum qualifying purchase earns full credit
- **WHEN** the driver purchases and receives a minimum-price qualifying resource within B
- **THEN** M2 SHALL receive exact credit one using complete advertised prices minimum membership and actual payment delivery evidence

#### Scenario: BTS-SC-022 M2 valid expensive purchase earns only its defined partial credit
- **WHEN** the driver receives a more expensive qualifying offer or a cheaper nonqualifying resource or exceeds B
- **THEN** a more expensive qualifying delivery SHALL earn exactly 0.4 nonqualifying delivery earns no purchase credit and proven mandatory scope or budget violation yields zero

### Requirement: BTS-REQ-013 Grade an explicit swap to native ETH
M3 SHALL bind exact input principal, permitted routes, native ETH minimum Q, declared slippage policy, G and B. Binary credit one SHALL require requested actual exchange outcome in native ETH. Wrong/extra principal, disallowed scope/route or G/B breach SHALL be mandatory zero. WETH SHALL NOT satisfy native output/reserve and tools SHALL NOT auto-unwrap. Actual reverted gas SHALL still count; Q and fee rules SHALL be pinned before activation rather than guessed per run.

#### Scenario: BTS-SC-023 M3 actual native output earns full credit
- **WHEN** the driver exchanges the specified principal through an allowed route and explicitly unwraps where needed to reach Q native ETH within G and B
- **THEN** M3 SHALL receive exact credit one from actual input route receipts native balances and cost observations

#### Scenario: BTS-SC-024 M3 WETH and insufficient output do not satisfy native goals
- **WHEN** the driver ends with WETH only or insufficient output uses a wrong route or breaches G or B
- **THEN** a known missed native output SHALL fail without automatic conversion and proven mandatory violations yield zero with actual successful or reverted gas retained

### Requirement: BTS-REQ-014 Grade exchange completion and allowance cleanup
M4 SHALL bind required exchange output, input/routes/spenders, initial allowance map, G and B. Credit SHALL be 0.7 for the required exchange plus 0.3 only when that exchange is achieved and all used temporary router allowances are zero at finish. Cleanup without exchange SHALL earn nothing. Unrelated allowance mutation, wrong scope/principal or G/B breach SHALL be mandatory zero. Residual otherwise permitted temporary allowance SHALL lose cleanup credit rather than add an unselected universal zero penalty.

#### Scenario: BTS-SC-025 M4 exchange plus cleanup earns full credit
- **WHEN** the driver completes the required exchange then removes used router allowances
- **THEN** M4 SHALL receive exact credit one from exchange final allowances and unchanged unrelated permissions

#### Scenario: BTS-SC-026 M4 cleanup credit requires actual exchange progress
- **WHEN** the driver completes exchange but leaves permitted allowance only cleans up without exchange or mutates unrelated allowance
- **THEN** M4 SHALL award exactly 0.7 for exchange with residual allowance zero for cleanup-only and mandatory zero for unrelated mutation

### Requirement: BTS-REQ-015 Grade independently delivered data components
H1 SHALL bind a finite, nonempty set of unique required component identities, a complete deterministic validator for each, permitted sources and B. Credit SHALL equal the number of distinct required components whose pinned validators pass on authenticated delivery evidence by cutoff divided by the number of required component identities fixed in the release. Denominator and identities SHALL remain release-pinned; purchases, amount paid and caller claims SHALL NOT change either count. Each component SHALL count once by actual hash/validator/provenance. Duplicate purchase, disallowed scope or B breach SHALL be mandatory zero. Known valid subsets SHALL earn exact fractions; unobserved platform delivery remains unknown.

#### Scenario: BTS-SC-027 H1 complete validated components earn full credit
- **WHEN** the driver obtains all required paid components from permitted sources within B
- **THEN** H1 SHALL receive exact credit one from independently validated deliveries and actual expenses

#### Scenario: BTS-SC-028 H1 partial data and duplicate purchases have distinct outcomes
- **WHEN** the driver obtains a known subset submits duplicate component claims buys duplicates or exceeds B
- **THEN** valid subsets SHALL earn exact component fractions without duplicate credit while proven duplicate purchase or budget violation yields zero

### Requirement: BTS-REQ-016 Grade payout obligations with conversions and reserve
H2 SHALL bind at least two unique recipient/asset/exact-amount obligations, initial assets, permitted conversions, G and B. Credit SHALL equal the number of distinct obligations exactly fulfilled by cutoff divided by the number of unique obligations fixed in the release; payout amounts SHALL NOT weight the fraction. Wrong/extra recipient or asset, overpayment, disallowed conversion or G/B breach SHALL be mandatory zero. Actual recipient deltas and receipts SHALL prove payouts; principal SHALL stay separate from operating costs. A known agent-caused conversion failure SHALL not automatically imply platform fault.

#### Scenario: BTS-SC-029 H2 all verified payouts earn full credit
- **WHEN** the driver makes every specified payout using explicit permitted conversions and retains G within B
- **THEN** H2 SHALL receive exact credit one from recipient deltas conversion receipts reserve and operating costs

#### Scenario: BTS-SC-030 H2 payout fractions cannot erase mandatory violations
- **WHEN** the driver fulfills a known subset uses a wrong recipient overpays or breaches G
- **THEN** the exact verified subset fraction SHALL apply absent mandatory violations while wrong recipient overpayment or reserve violation yields irreversible zero

### Requirement: BTS-REQ-017 Grade paid information before dependent execution
H3 SHALL bind paid reference data/validator, explicit route objective, input/output limits, permitted scope, G and combined B. Credit SHALL be 0.3 for required reference delivery plus 0.7 only when delivery precedes the relevant actual trade and the route objective and exchange outcome are achieved. A self-reported reference ID or trade before delivery SHALL not satisfy dependency. Scope/principal/route or G/B violations SHALL be mandatory zero. Observed dependency/order SHALL NOT claim proof of internal reasoning.

#### Scenario: BTS-SC-031 H3 paid data before the satisfying route earns full credit
- **WHEN** the driver receives required paid data then chooses a satisfying allowed route and executes the exchange within combined limits
- **THEN** H3 SHALL receive exact credit one from authenticated delivery-before-action order derived route objective actual effects and combined expenses

#### Scenario: BTS-SC-032 H3 dependent credit requires observed prior data and execution
- **WHEN** the driver receives data but chooses an allowed suboptimal route trades before delivery or only claims a reference identity
- **THEN** verified data alone SHALL earn 0.3 absent mandatory violation and the dependent 0.7 SHALL require actual prior delivery and the satisfying observed route outcome

### Requirement: BTS-REQ-018 Grade a coherent treasury result without idle cleanup points
U1 SHALL bind a finite, nonempty set of unique required paid-component identities with one complete deterministic validator per component; each validator SHALL pin its version, required payload schema/fields, exact acceptance predicate and permitted source/provenance; a finite set of at least two unique recipient/asset/exact-amount payout obligations; a nonempty unique allocation-asset set with a fully specified post-payout target and tolerance at a pinned rational rate; and a finite, nonempty unique declared temporary-spender allowance scope, plus G and B. The sets, validators and their cardinalities SHALL be fixed in the immutable release case. Let N_data and N_payout be the respective positive release-pinned set sizes. The delivered-component fraction SHALL be the exact count of distinct components whose pinned validators pass on authenticated delivery evidence by cutoff divided by N_data. The fulfilled-payout fraction SHALL be the exact count of distinct obligations exactly fulfilled by cutoff divided by N_payout. Purchases, payout amounts, caller claims or run-time list changes SHALL NOT alter either numerator or denominator; no amount-weighted policy is selected. Credit SHALL be 0.20 times delivered-component fraction plus 0.25 times the final-allocation indicator plus 0.35 times fulfilled-payout fraction plus 0.20 times the cleanup indicator. The final-allocation indicator SHALL be evaluated only against the nonempty pinned asset set and target/tolerance after payouts; the release SHALL be rejected if this objective is unspecified, initially solved, or cannot be evaluated on the validated reference path. Cleanup SHALL require zero temporary allowances for every owner/token/spender key in the nonempty pinned set at the common cutoff and at least one verifiably achieved core data/allocation/payout objective. The declared set MAY include unused or initially zero allowances; U1 SHALL NOT require an allowance to be created solely to earn cleanup credit. Cleanup alone SHALL earn nothing, including when no core objective was achieved. Wrong/extra principal or overpayment, disallowed scope/conversion, unrelated permission mutation or G/B breach SHALL be mandatory zero. All final predicates SHALL share one cutoff; retained historical violations and single-count costs SHALL apply.

#### Scenario: BTS-SC-033 U1 coherent final treasury state earns full credit
- **WHEN** a release with nonempty unique U1 component, allocation-asset, payout-obligation and declared-spender sets has one complete pinned validator per component and the driver validates every required delivery, reaches final allocation, completes every payout, has zero allowances in the declared set and preserves G within B
- **THEN** U1 SHALL receive exact credit one as 0.20*(N_data/N_data) + 0.25 + 0.35*(N_payout/N_payout) + 0.20 from the same cutoff, where positive N_data and N_payout are fixed by the release and all component, allocation, payout, cleanup and expense evidence is independently observed

#### Scenario: BTS-SC-034 U1 partial subgoals do not reward idle or undone outcomes
- **WHEN** a valid release is evaluated after only a known subset of unique components or payout obligations is fulfilled, duplicate purchases/claims occur, an allocation is undone before cutoff, a caller attempts to change a release-pinned set or denominator, or only zero allowances remain without any core objective
- **THEN** only exact fractions count distinct validated components over release-pinned N_data and distinct fulfilled obligations over release-pinned N_payout, with no purchase-count or amount weighting; attempted set or denominator changes SHALL NOT alter those counts, cleanup SHALL require the nonempty configured spender set and a verified core objective, and any proven mandatory violation irreversibly zeros U1
