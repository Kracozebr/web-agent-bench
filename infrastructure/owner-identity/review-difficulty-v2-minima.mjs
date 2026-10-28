// Offline engineering review. Semantic proofs precede lower-bound derivation.
// No registry, participant actions, grades or acceptance-gate mutation.
import { createHash, randomUUID } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { TaskCaseSchema, canonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';
import { PUBLIC_TASK_CATALOG } from '../../packages/owner-identity/src/task-catalog.ts';
import { loadV2ReferenceContext, verifyTaskReferenceEvidenceV2 } from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const demand = (condition, reason) => { if (!condition) throw new Error(reason); };
const positive = (value) => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
const unique = (values) => new Set(values).size === values.length;
const sourcePaths = ['pnpm-lock.yaml', 'infrastructure/owner-identity/review-difficulty-v2-minima.mjs',
  'infrastructure/owner-identity/task-release-local-policy.json',
  ...['task-release', 'task-catalog', 'task-action-service', 'task-payment-references', 'bef-task-executor',
    'task-reference-evidence-v2', 'task-reference-evidence-v2-types', 'task-reference-evidence-v2-basic',
    'task-reference-evidence-v2-advanced'].map((name) => `packages/owner-identity/src/${name}.ts`),
  ...['tools', 'selected-execution', 'pay-retrieve'].map((name) => `packages/benchmark-environment/src/${name}.ts`)];

function derive(context) {
  const task = context.taskCase, goal = task.objective;
  const balance = (assetId) => {
    const matches = task.initialState.balances.filter((row) => row.account === 'participant' && row.assetId === assetId);
    demand(matches.length === 1, 'initial_balance_not_unique'); return BigInt(matches[0].amountUnits);
  };
  const routers = () => goal.permittedRoutes.map((route) => {
    const found = context.identity.contracts.find((contract) => contract.contractId === route.routerContractId);
    demand(found, 'route_router_unbound'); return found.address.toLowerCase();
  });
  const zeroAllowance = (assetId) => {
    for (const router of new Set(routers())) {
      const found = task.initialState.allowances.filter((row) => row.owner === 'participant'
        && row.tokenAssetId === assetId && row.spender.toLowerCase() === router);
      demand(found.length === 1 && found[0].amountUnits === '0', 'initial_allowance_does_not_require_approval');
    }
  };
  const components = (rows) => {
    demand(rows.length > 0 && unique(rows.map((row) => row.componentId))
      && unique(rows.map((row) => row.resourceId)), 'components_not_distinct_resources');
    return rows.length;
  };
  const payouts = (rows) => {
    demand(rows.length > 0 && unique(rows.map((row) => row.obligationId))
      && unique(rows.map((row) => row.recipient.toLowerCase()))
      && rows.every((row) => row.assetId === 'USDC' && positive(row.exactAmountUnits)), 'payouts_not_distinct_positive_usdc');
    return rows.length;
  };
  const wethInputTrade = () => {
    demand(goal.inputAssetId === 'WETH' && positive(goal.exactInputUnits) && balance('WETH') === 0n
      && goal.permittedRoutes.length > 0 && goal.permittedRoutes.every((route) => route.tokenInAssetId === 'WETH'
        && route.tokenOutAssetId === 'USDC'), 'wrap_not_proven_necessary');
    zeroAllowance('WETH');
  };
  switch (task.taskId) {
    case 'S1': demand(positive(goal.exactPrincipalUnits), 'transfer_not_positive');
      return { minimum: 1, dependencies: ['one exact positive scoped transfer'] };
    case 'S2': case 'S3': return { minimum: 1,
      dependencies: ['one scoped public inspection supplies the required offer/catalog answer'] };
    case 'S4': demand(positive(goal.initialAllowanceUnits), 'revoke_already_satisfied');
      return { minimum: 1, dependencies: ['one revoke from the positive post-fixture task baseline; setup excluded'] };
    case 'M1': case 'M2': return { minimum: 3,
      dependencies: ['one same-task observed inspection', 'one resource payment', 'one separately confirmed delivery'] };
    case 'H1': return { minimum: 1 + 2 * components(goal.requiredComponents),
      dependencies: ['one shared catalog', 'one pay and one retrieve per distinct required resource'] };
    case 'H2': demand(goal.permittedConversions.length === 0, 'alternate_payout_conversion_not_reviewed');
      return { minimum: payouts(goal.obligations), dependencies: ['one exact transfer per distinct recipient; no batch primitive'] };
    case 'M3': demand(goal.inputAssetId === 'USDC' && goal.outputAssetId === 'ETH'
      && positive(goal.exactInputUnits) && positive(goal.minimumNativeOutputWei) && balance('WETH') === 0n
      && goal.permittedRoutes.length > 0 && goal.permittedRoutes.every((route) => route.tokenInAssetId === 'USDC'
        && route.tokenOutAssetId === 'WETH'), 'native_conversion_dependencies_not_proven');
      zeroAllowance('USDC'); return { minimum: 3, dependencies: ['zero allowance requires approve',
        'exact-input USDC-to-WETH swap', 'distinct native output requires unwrap'] };
    case 'M4': wethInputTrade(); return { minimum: 3,
      dependencies: ['zero WETH requires wrap', 'zero allowance requires approve', 'exact-input swap'] };
    case 'H3': wethInputTrade(); return { minimum: 6,
      dependencies: ['one inspection/pay/retrieve for the required reference', 'necessary wrap/approve/swap'] };
    case 'U1': {
      const paidCount = components(goal.requiredComponents), payoutCount = payouts(goal.payoutObligations);
      demand(balance('WETH') === 0n && goal.permittedRoutes.length > 0
        && goal.permittedRoutes.every((route) => route.tokenInAssetId === 'USDC' && route.tokenOutAssetId === 'WETH'),
      'allocation_alternative_routes_not_reviewed');
      zeroAllowance('USDC');
      const allocation = new Map(goal.allocationAssets.map((row) => [row.assetId, row]));
      demand(allocation.size === 3 && allocation.get('WETH')?.targetShareBps === 0
        && allocation.get('WETH')?.toleranceBps === 0 && allocation.get('USDC') && allocation.get('ETH'),
      'allocation_zero_weth_not_required');
      const paid = context.actions.filter((action) => action.kind === 'pay').map((action) => context.action(action).payment);
      const usdc = context.identity.assets.find((row) => row.assetId === 'USDC').address.toLowerCase();
      const payoutRecipients = new Set(goal.payoutObligations.map((row) => row.recipient.toLowerCase()));
      demand(paid.length === paidCount && paid.every((row) => positive(row.amount) && row.asset.toLowerCase() === usdc),
        'mandatory_payment_units_missing');
      demand(paid.every((row) => !payoutRecipients.has(row.payTo.toLowerCase()))
        && !payoutRecipients.has(context.generation.payerAddress.toLowerCase()), 'payments_could_overlap_payouts');
      // AICODE-NOTE: cheaper reference spending cannot prove a lower bound for
      // every valid solver. Conservatively let ALL allowed expense reduce USDC,
      // including budget-valid higher offer tiers and gas. This overestimates
      // possible non-conversion USDC loss and therefore strengthens necessity.
      demand(positive(goal.expenseBudgetUsdcUnits), 'expense_budget_missing');
      const payoutTotal = goal.payoutObligations.reduce((sum, row) => sum + BigInt(row.exactAmountUnits), 0n);
      const capturedPaymentTotal = paid.reduce((sum, row) => sum + BigInt(row.amount), 0n);
      demand(capturedPaymentTotal <= BigInt(goal.expenseBudgetUsdcUnits), 'reference_payment_budget_exceeded');
      const remaining = balance('USDC') - BigInt(goal.expenseBudgetUsdcUnits) - payoutTotal;
      const usdcRate = allocation.get('USDC').usdcBaseUnitsPerAssetBaseUnit;
      demand(usdcRate.numerator === '1' && usdcRate.denominator === '1', 'usdc_valuation_not_identity');
      const rate = allocation.get('ETH').usdcBaseUnitsPerAssetBaseUnit;
      const numerator = BigInt(rate.numerator), denominator = BigInt(rate.denominator);
      const upperBps = allocation.get('USDC').targetShareBps + allocation.get('USDC').toleranceBps;
      demand(remaining > 0n && numerator > 0n && denominator > 0n
        && remaining * denominator * 10000n > BigInt(upperBps)
          * (remaining * denominator + balance('ETH') * numerator), 'allocation_swap_not_proven_necessary');
      return { minimum: 1 + 2 * paidCount + payoutCount + 3,
        dependencies: ['one shared catalog', 'pay/retrieve per distinct component', 'one transfer per distinct payout',
          'even the full allowed expense budget cannot remove the required USDC allocation excess', 'zero allowance requires approve',
          'permitted conversion requires swap', 'zero WETH target requires unwrap; exact approve needs no extra revoke'],
        allocationWitness: { minimumUsdcBeforeConversionEvenAtFullExpenseBudget: remaining.toString(),
          expenseBudgetUsdcUnits: goal.expenseBudgetUsdcUnits, payoutTotalUsdcUnits: payoutTotal.toString(),
          capturedServicePaymentsUsdcUnits: capturedPaymentTotal.toString(), upperBps,
          comparison: 'remaining*rateDenominator*10000 > upperBps*(remaining*rateDenominator+initialNative*rateNumerator)' } };
    }
    default: throw new Error('task_minimum_not_reviewed');
  }
}

async function main() {
  const args = process.argv.slice(2);
  demand(process.platform === 'linux' && process.cwd() === '/workspace' && args.length === 4
    && args[0] === '--cases' && args[2] === '--sha256' && /^[0-9a-f]{64}$/.test(args[3])
    && /^artifacts\/runs\/[A-Za-z0-9_./-]+\/candidate-cases\.json$/.test(args[1])
    && !args[1].split('/').some((part) => part === '..' || part === '.' || !part), 'usage');
  const inputBytes = await readFile(args[1]); demand(sha(inputBytes) === args[3], 'candidate_pin_mismatch');
  const candidate = JSON.parse(inputBytes);
  demand(candidate.cases.length === 20 && candidate.participantToolProtocol === 'separate_payment_delivery_v2', 'inventory_or_protocol_mismatch');
  const expected = PUBLIC_TASK_CATALOG.flatMap((row) => [`${row.taskId}:ranked`,
    ...(row.trainingAvailable ? [`${row.taskId}:training`] : [])]).sort();
  demand(canonicalTaskJson(candidate.cases.map((row) => `${row.taskId}:${row.mode}`).sort())
    === canonicalTaskJson(expected), 'case_inventory_mismatch');
  const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
  const policyHash = sha(await readFile(policyPath));
  const snapshot = () => Promise.all([...sourcePaths, args[1]].toSorted().map(async (path) => ({ path, sha256: sha(await readFile(path)) })));
  const before = await snapshot(), results = [];
  for (const raw of candidate.cases) {
    const taskCase = TaskCaseSchema.parse(raw), input = { repositoryRoot: '/workspace', identity: candidate.executionIdentity,
      executionIdentityHash: candidate.executionIdentityHash, taskCase, evidence: taskCase.referencePath.evidence,
      profilePolicy: { path: policyPath, sha256: policyHash } };
    const semantic = await verifyTaskReferenceEvidenceV2(input);
    if (semantic.status !== 'verified') { results.push({ taskId: taskCase.taskId, mode: taskCase.mode,
      caseHash: taskCase.caseHash, status: 'blocked', semantic }); continue; }
    try {
      const proof = derive(await loadV2ReferenceContext(input));
      const metadata = PUBLIC_TASK_CATALOG.find((row) => row.taskId === taskCase.taskId);
      const band = { simple: [1, 2], medium: [3, 5], hard: [6, 9], ultra: [10, null] }[metadata.level];
      const compatible = proof.minimum === semantic.actionCount && proof.minimum >= band[0]
        && (band[1] === null || proof.minimum <= band[1]);
      results.push({ taskId: taskCase.taskId, mode: taskCase.mode, caseHash: taskCase.caseHash,
        status: compatible ? 'compatible_minimum' : 'incompatible', band, referenceActionCount: semantic.actionCount, ...proof });
    } catch (error) { results.push({ taskId: taskCase.taskId, mode: taskCase.mode, caseHash: taskCase.caseHash,
      status: 'blocked', reason: /^[a-z_]+$/.test(error?.message) ? error.message : 'minimum_derivation_unavailable' }); }
  }
  const after = await snapshot(); demand(canonicalTaskJson(before) === canonicalTaskJson(after), 'review_source_changed');
  const success = results.every((row) => row.status === 'compatible_minimum');
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-v2-minimum-action-review/${captureId}`;
  await mkdir(outputPrefix, { recursive: true });
  const content = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-v2-minimum-action-review/v1', captureId,
    classification: 'offline_engineering_review_of_semantically_verified_local_references',
    status: success ? 'compatible_minima' : 'blocked', executionIdentityHash: candidate.executionIdentityHash,
    candidate: { path: args[1], sha256: args[3] }, sourceInputs: before, sourceUnchanged: true, results,
    assumptions: ['sealed split-payment protocol; combined purchase rejected', 'no raw signing, multicall or batch command',
      'no extra principal, duplicate purchase or overpayment allowed', 'reference trace proves achievability; dependency lower bounds establish necessity'],
    claims: { difficultyApproval: false, releaseValidation: false, releaseActivation: false, ownerRunAcceptance: false,
      taskGrade: false, mainnetExecution: false } }, null, 2)}\n`);
  await writeFile(`${outputPrefix}/review.json`, content, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(content), success, cases: results.length,
    blockers: results.filter((row) => row.status !== 'compatible_minimum') })}\n`);
  if (!success) process.exitCode = 2;
}
void main().catch(() => { process.stderr.write('difficulty_minimum_review_failed\n'); process.exitCode = 2; });
