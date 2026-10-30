import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { PUBLIC_TASK_CATALOG, TASK_IDS } from './task-catalog.js';
import { canonicalTaskJson, TaskCaseSchema, type DifficultyVerification, type EvidenceReference, type ReferencePathVerification,
  type TaskCase, type TaskReleaseManifest } from './task-release.js';
import { loadV2ReferenceContext, verifyTaskReferenceEvidenceV2, type V2ReferenceVerifierInput } from './task-reference-evidence-v2.js';
import { V2ReferenceError, v2Require, type V2Document, type V2ReferenceContext } from './task-reference-evidence-v2-types.js';

const HASH = /^[0-9a-f]{64}$/;
const CURRENT_CASE_COUNT = 15;
const REVIEW_SCHEMA = 'bts-v2-minimum-action-review/v1';
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const EXPECTED_ACTIONS: Record<string, readonly string[]> = {
  S1: ['transfer'], S2: ['inspect_offer'], S3: ['inspect_catalog'], S4: ['revoke'],
  M1: ['inspect_offer', 'pay', 'retrieve'], M2: ['inspect_catalog', 'pay', 'retrieve'],
  M3: ['approve', 'swap', 'unwrap'], M4: ['wrap', 'approve', 'swap'],
  H1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'],
  H2: ['transfer', 'transfer', 'transfer', 'transfer', 'transfer', 'transfer'],
  H3: ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'],
  U1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'],
};
const sha = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const lower = (value: unknown) => String(value ?? '').toLowerCase();
const positive = (value: unknown): value is string => typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
const same = (left: unknown, right: unknown) => canonicalTaskJson(left) === canonicalTaskJson(right);

type MinimumProof = {
  minimum: number;
  dependencies: string[];
  allocationWitness?: {
    minimumUsdcBeforeConversionEvenAtFullExpenseBudget: string;
    expenseBudgetUsdcUnits: string;
    payoutTotalUsdcUnits: string;
    upperBps: number;
    comparison: string;
  };
};

export type DifficultyEvidenceV2Input = {
  repositoryRoot: string;
  evidence: EvidenceReference;
  cases: readonly TaskCase[];
  executionIdentityHash: string;
  identity: TaskReleaseManifest['executionIdentity'];
  profilePolicy: { path: string; sha256: string };
  /** The current release-input pin identifies the case set reviewed by this artifact. */
  caseCandidate: { path: string; sha256: string };
  /** The independent wrapper results produced earlier in this same candidate validation. */
  verifiedReferences: readonly { taskCase: TaskCase; result: ReferencePathVerification }[];
  costPolicy: TaskReleaseManifest['costPolicy'];
};

function demand(condition: unknown, code: string): asserts condition {
  if (!condition) throw new Error(code);
}

function asObject(value: unknown, code: string): V2Document {
  demand(value && typeof value === 'object' && !Array.isArray(value), code);
  return value as V2Document;
}

async function pinnedBytes(root: string, path: string, expectedHash: string, maxBytes = 8 * 1024 * 1024): Promise<Buffer> {
  demand(typeof path === 'string' && path.length > 0 && path.length <= 512 && path.trim() === path
    && !isAbsolute(path) && !path.includes('\\') && !path.includes(':')
    && path.split('/').every((part) => part && part !== '.' && part !== '..') && HASH.test(expectedHash),
  'difficulty_review_path_or_hash_invalid');
  const absoluteRoot = await realpath(root), actual = await realpath(resolve(absoluteRoot, path));
  const rel = relative(absoluteRoot, actual);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'difficulty_review_path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= maxBytes, 'difficulty_review_file_invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    demand(offset === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs, 'difficulty_review_file_changed');
    const content = bytes.subarray(0, offset);
    demand(sha(content) === expectedHash, 'difficulty_review_artifact_hash_mismatch');
    return content;
  } finally { await handle.close(); }
}

function initialBalance(taskCase: TaskCase, assetId: string): bigint {
  const rows = taskCase.initialState.balances.filter((row) => row.account === 'participant' && row.assetId === assetId);
  demand(rows.length === 1, 'minimum_initial_balance_not_unique');
  return BigInt(rows[0]!.amountUnits);
}

function distinctComponents(rows: readonly { componentId: string; resourceId: string }[]): number {
  demand(rows.length > 0 && new Set(rows.map((row) => row.componentId)).size === rows.length
    && new Set(rows.map((row) => row.resourceId)).size === rows.length, 'minimum_components_not_distinct_resources');
  return rows.length;
}

function distinctPayouts(rows: readonly { obligationId: string; recipient: string; assetId: string; exactAmountUnits: string }[]): number {
  demand(rows.length > 0 && new Set(rows.map((row) => row.obligationId)).size === rows.length
    && new Set(rows.map((row) => row.recipient.toLowerCase())).size === rows.length
    && rows.every((row) => row.assetId === 'USDC' && positive(row.exactAmountUnits)), 'minimum_payouts_not_distinct_positive_usdc');
  return rows.length;
}

function routeContractAddresses(ctx: V2ReferenceContext, routes: readonly V2Document[]): string[] {
  demand(routes.length > 0, 'minimum_routes_missing');
  return routes.map((route) => {
    const contract = ctx.identity.contracts.find((item) => item.contractId === route.routerContractId);
    demand(contract && typeof route.routerContractId === 'string', 'minimum_route_router_unbound');
    return contract.address.toLowerCase();
  });
}

function requireZeroAllowanceForRoutes(ctx: V2ReferenceContext, taskCase: TaskCase, assetId: string,
  routes: readonly V2Document[]): void {
  for (const spender of new Set(routeContractAddresses(ctx, routes))) {
    const matches = taskCase.initialState.allowances.filter((row) => row.owner === 'participant'
      && row.tokenAssetId === assetId && row.spender.toLowerCase() === spender);
    demand(matches.length === 1 && matches[0]!.amountUnits === '0', 'minimum_zero_allowance_not_proven');
  }
}

function assertToolProtocol(ctx: V2ReferenceContext): void {
  const tools = asObject(ctx.manifest.tools, 'minimum_tool_surface_missing');
  const reads = tools.reads, writes = tools.writes;
  demand(ctx.probe.participantToolProtocol === 'separate_payment_delivery_v2'
    && tools.participantProtocol === 'separate_payment_delivery_v2'
    && Array.isArray(reads) && reads.includes('offer') && reads.includes('catalog') && reads.includes('retrieve')
    && Array.isArray(writes) && writes.includes('pay') && writes.includes('transfer')
    && !writes.includes('batch') && !writes.includes('multicall') && !writes.includes('arbitrary_transaction'),
  'minimum_participant_protocol_not_sealed');
  const plan = EXPECTED_ACTIONS[ctx.taskCase.taskId];
  demand(plan && ctx.actions.length === plan.length && ctx.actions.every((action, index) => action.kind === plan[index]),
    'minimum_verified_action_plan_mismatch');
}

/**
 * Recompute a task's shortest necessary action lower bound from its pinned goal
 * and task-start state. The caller must first verify the retained raw reference.
 */
export function deriveMinimumActionProof(ctx: V2ReferenceContext,
  releaseCostPolicy?: TaskReleaseManifest['costPolicy']): MinimumProof {
  const taskCase = ctx.taskCase;
  const objective = taskCase.objective as Record<string, any>;
  assertToolProtocol(ctx);
  switch (taskCase.taskId) {
    case 'S1':
      demand(positive(objective.exactPrincipalUnits), 'minimum_transfer_not_positive');
      return { minimum: 1, dependencies: ['one exact positive scoped transfer'] };
    case 'S2': case 'S3':
      return { minimum: 1, dependencies: ['one scoped public inspection supplies the required offer or catalog answer'] };
    case 'S4': {
      const matches = taskCase.initialState.allowances.filter((row) => row.owner === 'participant'
        && row.tokenAssetId === objective.tokenAssetId && row.spender.toLowerCase() === objective.spender.toLowerCase());
      demand(positive(objective.initialAllowanceUnits) && matches.length === 1
        && matches[0]!.amountUnits === objective.initialAllowanceUnits, 'minimum_positive_task_start_allowance_not_proven');
      return { minimum: 1, dependencies: ['one revoke from a positive task-start allowance; fixture setup is before the baseline'] };
    }
    case 'M1': case 'M2':
      return { minimum: 3, dependencies: ['one same-task observed inspection', 'one resource payment', 'one separately confirmed retrieval'] };
    case 'H1': {
      const count = distinctComponents(objective.requiredComponents);
      return { minimum: 1 + 2 * count, dependencies: ['one shared catalog', 'one pay and one retrieve per distinct required resource'] };
    }
    case 'H2': {
      demand(objective.permittedConversions.length === 0, 'minimum_h2_conversion_alternative_not_reviewed');
      const count = distinctPayouts(objective.obligations);
      return { minimum: count, dependencies: ['one exact transfer per distinct recipient; the sealed tool surface has no batch command'] };
    }
    case 'M3': {
      const routes = objective.permittedRoutes as V2Document[];
      demand(objective.inputAssetId === 'USDC' && positive(objective.exactInputUnits) && objective.outputAssetId === 'ETH'
        && positive(objective.minimumNativeOutputWei) && initialBalance(taskCase, 'WETH') === 0n
        && routes.every((route) => route.tokenInAssetId === 'USDC' && route.tokenOutAssetId === 'WETH'),
      'minimum_m3_native_conversion_not_required');
      requireZeroAllowanceForRoutes(ctx, taskCase, 'USDC', routes);
      return { minimum: 3, dependencies: ['zero allowance requires approve', 'exact-input USDC-to-WETH swap', 'native output requires unwrap'] };
    }
    case 'M4': case 'H3': {
      const routes = objective.permittedRoutes as V2Document[];
      demand(objective.inputAssetId === 'WETH' && positive(objective.exactInputUnits)
        && initialBalance(taskCase, 'WETH') === 0n
        && routes.every((route) => route.tokenInAssetId === 'WETH' && route.tokenOutAssetId === 'USDC'),
      'minimum_weth_wrap_not_required');
      requireZeroAllowanceForRoutes(ctx, taskCase, 'WETH', routes);
      if (taskCase.taskId === 'M4') {
        demand(objective.outputAssetId === 'USDC' && positive(objective.minimumOutputUnits), 'minimum_m4_output_goal_invalid');
        return { minimum: 3, dependencies: ['zero WETH requires wrap', 'zero allowance requires approve', 'exact-input swap'] };
      }
      demand(objective.routeObjective && objective.routeObjective.allowedRouteIds.length > 0
        && positive(objective.minimumOutputUnits) && positive(objective.combinedExpenseBudgetUsdcUnits),
      'minimum_h3_paid_route_goal_invalid');
      return { minimum: 6, dependencies: ['one offer inspection, payment, and retrieval for the required route reference',
        'zero WETH requires wrap, zero allowance requires approve, and the exact-input route requires swap'] };
    }
    case 'U1': {
      const componentCount = distinctComponents(objective.requiredComponents);
      const payoutCount = distinctPayouts(objective.payoutObligations);
      const routes = objective.permittedRoutes as V2Document[];
      demand(initialBalance(taskCase, 'WETH') === 0n && routes.length > 0
        && routes.every((route) => route.tokenInAssetId === 'USDC' && route.tokenOutAssetId === 'WETH'),
      'minimum_u1_conversion_route_not_required');
      requireZeroAllowanceForRoutes(ctx, taskCase, 'USDC', routes);
      const allocationRows = objective.allocationAssets as V2Document[];
      const allocation = new Map(allocationRows.map((row) => [row.assetId, row]));
      const wethAllocation = allocation.get('WETH'), usdcAllocation = allocation.get('USDC'), ethAllocation = allocation.get('ETH');
      demand(allocation.size === 3 && wethAllocation && usdcAllocation && ethAllocation
        && wethAllocation.targetShareBps === 0 && wethAllocation.toleranceBps === 0
        && usdcAllocation.usdcBaseUnitsPerAssetBaseUnit.numerator === '1'
        && usdcAllocation.usdcBaseUnitsPerAssetBaseUnit.denominator === '1'
        && allocationRows.reduce((sum, row) => sum + row.targetShareBps, 0) === 10000,
      'minimum_u1_allocation_scope_invalid');
      const spenderScope = objective.temporarySpenderScope as V2Document[];
      demand(spenderScope.length > 0 && routes.every((route) => spenderScope.some((row) => row.owner === 'participant'
        && row.tokenAssetId === 'USDC' && row.spender.toLowerCase() === routeContractAddresses(ctx, [route])[0])),
      'minimum_u1_guarded_spender_scope_missing');
      const expenseBudget = BigInt(objective.expenseBudgetUsdcUnits);
      // AICODE-NOTE: the release candidate's U1 budget is pinned at 470000 USDC
      // units. Use all of B against USDC so a cheaper captured offer cannot prove
      // a false lower bound when a solver may choose another allowed offer tier.
      demand(expenseBudget === 470000n && releaseCostPolicy !== undefined
        && releaseCostPolicy.usdcAssetId === 'USDC' && releaseCostPolicy.usdcPrecision === 6
        && releaseCostPolicy.principalSeparateFromExpense && releaseCostPolicy.missingFeeEvidence === 'unknown',
      'minimum_u1_full_expense_budget_not_pinned');
      const payoutTotal = objective.payoutObligations.reduce((sum: bigint, row: V2Document) => sum + BigInt(row.exactAmountUnits), 0n);
      const initialUsdc = initialBalance(taskCase, 'USDC'), initialEth = initialBalance(taskCase, 'ETH');
      const remaining = initialUsdc - expenseBudget - payoutTotal;
      const upperBps = usdcAllocation.targetShareBps + usdcAllocation.toleranceBps;
      const rate = ethAllocation.usdcBaseUnitsPerAssetBaseUnit;
      const numerator = BigInt(rate.numerator), denominator = BigInt(rate.denominator);
      demand(remaining > 0n && numerator > 0n && denominator > 0n
        && remaining * denominator * 10000n > BigInt(upperBps)
          * (remaining * denominator + initialEth * numerator), 'minimum_u1_swap_not_proven_at_full_budget');
      const expectedUsdcRate = releaseCostPolicy.ethValuation;
      demand(expectedUsdcRate.numerator === rate.numerator && expectedUsdcRate.denominator === rate.denominator,
        'minimum_u1_release_valuation_mismatch');
      return { minimum: 1 + 2 * componentCount + payoutCount + 3,
        dependencies: ['one shared catalog', 'pay and retrieve per distinct component', 'one transfer per distinct payout',
          'even the full allowed expense budget cannot remove the USDC allocation excess', 'zero allowance requires approve',
          'permitted conversion requires swap', 'zero WETH target requires unwrap; exact approve needs no extra revoke'],
        allocationWitness: { minimumUsdcBeforeConversionEvenAtFullExpenseBudget: remaining.toString(),
          expenseBudgetUsdcUnits: expenseBudget.toString(), payoutTotalUsdcUnits: payoutTotal.toString(), upperBps,
          comparison: 'remaining*rateDenominator*10000 > upperBps*(remaining*rateDenominator+initialNative*rateNumerator)' } };
    }
  }
}

export function currentDifficultyCaseKeys(cases: readonly Pick<TaskCase, 'taskId' | 'mode'>[]): string[] {
  const keys = cases.map((taskCase) => `${taskCase.taskId}:${taskCase.mode}`);
  demand(keys.length === CURRENT_CASE_COUNT && new Set(keys).size === CURRENT_CASE_COUNT,
    'difficulty_case_inventory_invalid');
  const expected = PUBLIC_TASK_CATALOG.flatMap((item) => [`${item.taskId}:ranked`,
    ...(item.trainingAvailable ? [`${item.taskId}:training`] : [])]).sort();
  demand(same(keys.sort(), expected), 'difficulty_case_inventory_mismatch');
  return keys;
}

function expectedCaseKeys(cases: readonly TaskCase[]): string[] {
  return currentDifficultyCaseKeys(cases);
}

export async function verifyCurrentDifficultyCaseCandidate(
  repositoryRoot: string,
  caseCandidate: DifficultyEvidenceV2Input['caseCandidate'],
  cases: readonly TaskCase[],
): Promise<readonly TaskCase[]> {
  const bytes = await pinnedBytes(repositoryRoot, caseCandidate.path, caseCandidate.sha256);
  const candidate = asObject(JSON.parse(bytes.toString('utf8')), 'difficulty_case_candidate_invalid');
  demand(candidate.schemaVersion === 'bts-difficulty-v2-case-candidates/v1'
    && candidate.participantToolProtocol === 'separate_payment_delivery_v2'
    && Array.isArray(candidate.cases) && candidate.cases.length === CURRENT_CASE_COUNT,
  'difficulty_case_candidate_inventory_invalid');
  const candidateRows = candidate.cases.map((value) => asObject(value, 'difficulty_case_candidate_invalid'));
  currentDifficultyCaseKeys(candidateRows as unknown as Array<Pick<TaskCase, 'taskId' | 'mode'>>);
  const expectedKeys = expectedCaseKeys(cases);
  const keyOf = (taskCase: Record<string, unknown>) => `${taskCase.taskId}:${taskCase.mode}`;
  const sortedCandidate = [...candidateRows].sort((left, right) => keyOf(left).localeCompare(keyOf(right)));
  const sortedInput = [...cases].sort((left, right) => keyOf(left).localeCompare(keyOf(right)));
  demand(same(sortedCandidate, sortedInput), 'difficulty_case_candidate_binding_mismatch');
  const candidateCases = candidateRows.map((value) => TaskCaseSchema.parse(value));
  demand(same(expectedCaseKeys(candidateCases), expectedKeys), 'difficulty_case_candidate_inventory_mismatch');
  return candidateCases;
}

export function indexCurrentDifficultyReviewResults(reviewRows: unknown,
  expectedKeys: readonly string[]): Map<string, V2Document> {
  demand(Array.isArray(reviewRows) && reviewRows.length === CURRENT_CASE_COUNT,
    'difficulty_review_result_inventory_invalid');
  const reviewByKey = new Map<string, V2Document>();
  for (const raw of reviewRows) {
    const row = asObject(raw, 'difficulty_review_result_invalid'), key = `${row.taskId}:${row.mode}`;
    demand(!reviewByKey.has(key) && HASH.test(String(row.caseHash)), 'difficulty_review_result_identity_invalid');
    reviewByKey.set(key, row);
  }
  demand(reviewByKey.size === CURRENT_CASE_COUNT && expectedKeys.every((key) => reviewByKey.has(key)),
    'difficulty_review_result_inventory_mismatch');
  return reviewByKey;
}

function sourcePins(review: V2Document): Array<{ path: string; sha256: string }> {
  demand(Array.isArray(review.sourceInputs) && review.sourceInputs.length > 0 && review.sourceInputs.length <= 128,
    'difficulty_review_source_inventory_invalid');
  const byPath = new Map<string, string>();
  for (const raw of review.sourceInputs) {
    const row = asObject(raw, 'difficulty_review_source_entry_invalid');
    demand(typeof row.path === 'string' && HASH.test(String(row.sha256)), 'difficulty_review_source_entry_invalid');
    const old = byPath.get(row.path);
    demand(old === undefined || old === row.sha256, 'difficulty_review_source_pin_conflict');
    byPath.set(row.path, row.sha256);
  }
  return [...byPath.entries()].map(([path, sha256]) => ({ path, sha256 })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

async function verifySourcePins(root: string, pins: readonly { path: string; sha256: string }[]): Promise<void> {
  for (const row of pins) await pinnedBytes(root, row.path, row.sha256);
}

function refResultMatches(taskCase: TaskCase, result: ReferencePathVerification, executionIdentityHash: string): result is Extract<ReferencePathVerification, { status: 'verified' }> {
  return result.status === 'verified' && result.actualBoundary === true && result.solvable === true
    && result.initiallySolved === false && result.caseHash === taskCase.caseHash
    && result.executionIdentityHash === executionIdentityHash
    && result.toolSurfaceSha256 === taskCase.referencePath.toolSurfaceSha256
    && result.actionCount === taskCase.referencePath.actionCount
    && result.initialStateSha256 === taskCase.initialState.stateSha256
    && result.finalStateSha256 === taskCase.referencePath.finalStateSha256;
}

/**
 * Evidence-verifier adapter for `validateTaskReleaseCandidate`. It reopens and
 * verifies every raw reference, recomputes each lower bound, and only then
 * returns `approved`; copied review status/claims never authorize this result.
 */
export async function verifyDifficultyEvidenceV2(input: DifficultyEvidenceV2Input): Promise<DifficultyVerification> {
  try {
    demand(input.evidence.boundary === BOUNDARY && HASH.test(input.evidence.sha256),
    'difficulty_review_binding_invalid');
    await verifyCurrentDifficultyCaseCandidate(input.repositoryRoot, input.caseCandidate, input.cases);
    const bytes = await pinnedBytes(input.repositoryRoot, input.evidence.path, input.evidence.sha256);
    const review = asObject(JSON.parse(bytes.toString('utf8')), 'difficulty_review_document_invalid');
    demand(review.schemaVersion === REVIEW_SCHEMA
      && review.classification === 'offline_engineering_review_of_semantically_verified_local_references'
      && review.executionIdentityHash === input.executionIdentityHash,
    'difficulty_review_contract_mismatch');
    const reviewCandidate = asObject(review.candidate, 'difficulty_review_candidate_missing');
    demand(reviewCandidate.path === input.caseCandidate.path && reviewCandidate.sha256 === input.caseCandidate.sha256,
      'difficulty_review_case_candidate_mismatch');
    const reportPins = sourcePins(review);
    demand(reportPins.some((row) => row.path === input.caseCandidate.path && row.sha256 === input.caseCandidate.sha256),
      'difficulty_review_case_candidate_source_missing');
    await verifySourcePins(input.repositoryRoot, reportPins);

    const keys = expectedCaseKeys(input.cases);
    const caseByKey = new Map(input.cases.map((taskCase) => [`${taskCase.taskId}:${taskCase.mode}`, taskCase]));
    const reviewByKey = indexCurrentDifficultyReviewResults(review.results, keys);

    const referenceByKey = new Map(input.verifiedReferences.map((item) => [`${item.taskCase.taskId}:${item.taskCase.mode}`, item]));
    demand(referenceByKey.size === CURRENT_CASE_COUNT, 'difficulty_semantic_result_inventory_invalid');
    const findings: string[] = [];
    for (const key of keys) {
      const taskCase = caseByKey.get(key)!;
      const reported = reviewByKey.get(key)!;
      const retained = referenceByKey.get(key);
      if (!retained || retained.taskCase.caseHash !== taskCase.caseHash
        || !refResultMatches(taskCase, retained.result, input.executionIdentityHash)) {
        findings.push(`${key}:semantic_reference_not_verified`);
        continue;
      }
      const rawInput: V2ReferenceVerifierInput = { repositoryRoot: input.repositoryRoot, identity: input.identity,
        profilePolicy: input.profilePolicy, evidence: taskCase.referencePath.evidence, taskCase,
        executionIdentityHash: input.executionIdentityHash };
      const rawSemantic = await verifyTaskReferenceEvidenceV2(rawInput);
      if (!refResultMatches(taskCase, rawSemantic, input.executionIdentityHash)) {
        findings.push(`${key}:raw_semantic_reference_not_verified`);
        continue;
      }
      const context = await loadV2ReferenceContext(rawInput);
      const proof = deriveMinimumActionProof(context, input.costPolicy);
      const metadata = PUBLIC_TASK_CATALOG.find((row) => row.taskId === taskCase.taskId)!;
      const band = ({ simple: [1, 2], medium: [3, 5], hard: [6, 9], ultra: [10, null] } as const)[metadata.level];
      const inBand = proof.minimum >= band[0] && (band[1] === null || proof.minimum <= band[1]);
      if (proof.minimum !== rawSemantic.actionCount || !inBand) findings.push(`${key}:recomputed_minimum_outside_band_or_trace`);
      // The pinned engineering report is corroboration only: compare its row to
      // this fresh derivation, never use its status/approval flag as the proof.
      if (reported.caseHash !== taskCase.caseHash || reported.status !== 'compatible_minimum'
        || reported.referenceActionCount !== rawSemantic.actionCount || reported.minimum !== proof.minimum
        || !Array.isArray(reported.band) || reported.band[0] !== band[0] || reported.band[1] !== band[1]) {
        findings.push(`${key}:pinned_minimum_report_disagrees_with_recomputation`);
      }
    }
    if (findings.length) return { status: 'incompatible', findings };
    return { status: 'approved', executionIdentityHash: input.executionIdentityHash, actualBoundary: true };
  } catch (error) {
    const reason = error instanceof Error && /^difficulty_[a-z0-9_]+$/.test(error.message)
      ? error.message : error instanceof V2ReferenceError ? error.code : 'difficulty_evidence_unavailable';
    return { status: 'unavailable', reason };
  }
}
