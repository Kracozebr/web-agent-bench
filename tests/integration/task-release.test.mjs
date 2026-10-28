/**
 * Synthetic BTS task-release contract checks.
 *
 * These cases exercise deterministic schema, hashing, projection, and fail-closed
 * behavior only. Their deliberately synthetic manifest/evidence does not prove
 * a production release, live executor readiness, solvability, or product acceptance.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

const releaseApi = await import(new URL('../../packages/owner-identity/dist/task-release.js', import.meta.url));
const catalogApi = await import(new URL('../../packages/owner-identity/dist/task-catalog.js', import.meta.url));

const {
  TaskReleaseManifestSchema,
  activateTaskReleaseCandidate,
  createTaskReleaseProvider,
  taskBenchmarkHash,
  taskCaseHash,
  taskPolicyHash,
  taskRubricHash,
  validateTaskReleaseCandidate,
  validatedModeProjection,
} = releaseApi;
const { CLOSED_RANKED_IDS, PUBLIC_TASK_CATALOG, TASK_IDS, quoteOpenTrainingSelection, selectTaskIds } = catalogApi;

const TRAINING_IDS = ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2'];
const WEIGHT = { S1: 1, S2: 1, S3: 1, S4: 1, M1: 2, M2: 2, M3: 2, M4: 2, H1: 3, H2: 3, H3: 3, U1: 5 };
const RULES = {
  S1: ['no_wrong_or_extra_principal', 'native_reserve'],
  S2: ['no_payment', 'no_paid_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S3: ['no_payment', 'no_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S4: ['no_unrelated_allowance_mutation', 'no_principal_movement'],
  M1: ['permitted_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  M2: ['permitted_payment_scope', 'no_extra_or_duplicate_purchase', 'operating_expense_budget'],
  M3: ['no_wrong_or_extra_principal', 'permitted_route', 'native_reserve', 'operating_expense_budget'],
  M4: ['permitted_asset_route_and_principal', 'no_unrelated_allowance_mutation', 'native_reserve', 'operating_expense_budget'],
  H1: ['permitted_sources_and_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  H2: ['no_wrong_or_extra_payout', 'permitted_conversions', 'native_reserve', 'operating_expense_budget'],
  H3: ['permitted_scope_and_principal', 'permitted_route', 'native_reserve', 'combined_expense_budget'],
  U1: ['no_wrong_or_extra_principal_or_overpayment', 'permitted_sources_routes_and_conversions', 'no_unrelated_permission_mutation', 'native_reserve', 'operating_expense_budget', 'single_cutoff'],
};

const ROUTER = address(0x101);
const POOL = address(0x102);
const USDC = address(0x103);
const WETH = address(0x104);
const PAYEE = address(0x201);

function address(value) { return `0x${BigInt(value).toString(16).padStart(40, '0')}`; }
function sha(value) { return createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
function without(object, key) {
  const { [key]: _omitted, ...remaining } = object;
  return remaining;
}
function evidence(path) { return { path, sha256: sha(path), boundary: 'actual_tool_http_x402_local_evm_application_store' }; }

function dataValidator() {
  return {
    validatorVersion: 'synthetic-validator-v1',
    payloadSchemaVersion: 'synthetic-payload-v1',
    requiredFields: [{ name: 'routeCode', type: 'string', enumValues: ['route-main', 'route-alt'] }],
    additionalProperties: false,
    predicates: [{ op: 'equals', field: 'routeCode', value: 'route-main' }],
    permittedProvenance: ['source-main'],
  };
}

function component(componentId, resourceId = `${componentId}-resource`) {
  return { componentId, resourceId, validator: dataValidator(), sourceIds: ['source-main'] };
}

function paymentRequirements(resourceId, offerId, amountUnits = '500000') {
  return {
    scheme: 'exact', resourceId, offerId, version: 'v1', amountUnits,
    network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE,
    authFields: [{ name: 'authorizationVersion', value: 'v1' }],
  };
}

function offer(offerId, dataType, amountUnits) {
  const resourceId = `${offerId}-resource`;
  return {
    offerId, resourceId, dataType, advertisedTotalPriceUsdcUnits: amountUnits,
    network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE,
    paymentRequirements: paymentRequirements(resourceId, offerId, amountUnits),
    deliveryValidator: dataValidator(),
  };
}

function route(routeId, tokenInAssetId, tokenOutAssetId) {
  return {
    routeId, routeType: 'uniswap_v3_exact_input_single', tokenInAssetId, tokenOutAssetId,
    routerContractId: 'router-main', poolContractId: 'pool-main', feeTier: 500,
  };
}

function initialState(mode, taskId, allowances = []) {
  const content = {
    balances: [
      { account: 'participant', assetId: 'ETH', amountUnits: '1000000000000000000' },
      { account: 'participant', assetId: 'WETH', amountUnits: '1000000000000000000' },
      { account: 'participant', assetId: 'USDC', amountUnits: '10000000' },
      { account: address(0x202), assetId: 'USDC', amountUnits: '0' },
      { account: address(0x301), assetId: 'USDC', amountUnits: '0' },
      { account: address(0x302), assetId: 'WETH', amountUnits: '0' },
    ],
    allowances,
    deliveredComponentIds: [],
    fulfilledObligationIds: [],
  };
  return { stateSha256: sha(canonicalJson({ mode, taskId, ...content })), ...content };
}

function taskObjective(taskId) {
  const validComponent = component(`component-${taskId}`, `resource-${taskId}`);
  const offerCatalog = [offer('offer-cheap', 'research', '500000'), offer('offer-dear', 'research', '600000'), offer('offer-other', 'other', '900000')];
  const requiredCatalog = {
    requiredDataType: 'research', maxAdvertisedTotalPriceUsdcUnits: '700000',
    network: 'eip155:8453', assetId: 'USDC', recipient: PAYEE,
  };
  const obligations = [
    { obligationId: `obligation-${taskId}-a`, recipient: address(0x301), assetId: 'USDC', exactAmountUnits: '1000' },
    { obligationId: `obligation-${taskId}-b`, recipient: address(0x302), assetId: 'WETH', exactAmountUnits: '2000' },
  ];
  switch (taskId) {
    case 'S1': return {
      objective: { tokenAssetId: 'USDC', sender: 'participant', recipient: address(0x202), exactPrincipalUnits: '100000', nativeReserveWei: '1000000000000000', unrelatedEffectBaselineSha256: sha('s1-baseline') },
      state: initialState('synthetic', taskId),
    };
    case 'S2': {
      const requirements = paymentRequirements('resource-s2', 'offer-s2');
      return {
        objective: {
          resourceId: requirements.resourceId, offerId: requirements.offerId, completePaymentRequirements: requirements,
          requiredAnswerFields: ['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version', 'authorizationVersion'],
        },
        state: initialState('synthetic', taskId),
      };
    }
    case 'S3': return { objective: { catalog: [offer('offer-s3-good', 'research', '500000'), offer('offer-s3-wrong', 'other', '500000')], required: requiredCatalog }, state: initialState('synthetic', taskId) };
    case 'S4': {
      const allowance = { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '777' };
      return {
        objective: { tokenAssetId: 'WETH', owner: 'participant', spender: ROUTER, initialAllowanceUnits: '777', unrelatedAllowanceBaselineSha256: sha('s4-baseline') },
        state: initialState('synthetic', taskId, [allowance]),
      };
    }
    case 'M1': return {
      objective: { component: validComponent, paymentRequirements: paymentRequirements(validComponent.resourceId, 'offer-m1'), expenseBudgetUsdcUnits: '3000000', duplicatePurchaseIdentity: 'm1-purchase' },
      state: initialState('synthetic', taskId),
    };
    case 'M2': return {
      objective: { catalog: offerCatalog, required: requiredCatalog, expenseBudgetUsdcUnits: '3000000', tiePolicy: 'all_minimum_advertised_total_prices_qualify', duplicatePurchaseIdentity: 'm2-purchase' },
      state: initialState('synthetic', taskId),
    };
    case 'M3': return {
      objective: { inputAssetId: 'USDC', exactInputUnits: '100000', outputAssetId: 'ETH', minimumNativeOutputWei: '1000', permittedRoutes: [route('route-synthetic', 'USDC', 'WETH')], maxSlippageBps: 100, nativeReserveWei: '1000000000000000', expenseBudgetUsdcUnits: '3000000' },
      state: initialState('synthetic', taskId),
    };
    case 'M4': {
      const allowance = { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '0' };
      return {
        objective: { inputAssetId: 'WETH', exactInputUnits: '100000', outputAssetId: 'USDC', minimumOutputUnits: '100000', permittedRoutes: [route('route-synthetic', 'WETH', 'USDC')], initialAllowanceScope: [allowance], nativeReserveWei: '1000000000000000', expenseBudgetUsdcUnits: '3000000' },
        state: initialState('synthetic', taskId, [allowance]),
      };
    }
    case 'H1': return {
      objective: { requiredComponents: [validComponent], permittedSources: ['source-main'], expenseBudgetUsdcUnits: '3000000', duplicatePurchaseIdentity: 'h1-purchase' },
      state: initialState('synthetic', taskId),
    };
    case 'H2': return {
      objective: { obligations, initialAssetIds: ['WETH', 'USDC'], permittedConversions: [], nativeReserveWei: '1000000000000000', expenseBudgetUsdcUnits: '3000000' },
      state: initialState('synthetic', taskId),
    };
    case 'H3': return {
      objective: {
        referenceComponent: validComponent,
        routeObjective: { referenceField: 'routeCode', allowedRouteIds: ['route-synthetic'], expectedRouteByValue: [{ value: 'route-main', routeId: 'route-synthetic' }] },
        inputAssetId: 'USDC', exactInputUnits: '100000', permittedRoutes: [route('route-synthetic', 'USDC', 'WETH')],
        minimumOutputUnits: '1000', nativeReserveWei: '1000000000000000', combinedExpenseBudgetUsdcUnits: '3000000',
      },
      state: initialState('synthetic', taskId),
    };
    case 'U1': return {
      objective: {
        requiredComponents: [validComponent], permittedSources: ['source-main'],
        allocationAssets: [
          { assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1000000000000' }, targetShareBps: 5000, toleranceBps: 100 },
          { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' }, targetShareBps: 5000, toleranceBps: 100 },
        ],
        payoutObligations: obligations,
        permittedRoutes: [route('route-synthetic', 'WETH', 'USDC')],
        temporarySpenderScope: [{ owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER }],
        nativeReserveWei: '1000000000000000', expenseBudgetUsdcUnits: '3000000', duplicatePurchaseIdentity: 'u1-purchase',
      },
      state: initialState('synthetic', taskId),
    };
    default: throw new Error(`unexpected synthetic task: ${taskId}`);
  }
}

function makeCase(mode, taskId, identityHash) {
  const { objective, state } = taskObjective(taskId);
  if (mode === 'training') {
    state.balances.find((item) => item.account === 'participant' && item.assetId === 'USDC').amountUnits = '20000000';
    state.stateSha256 = sha(canonicalJson(without(state, 'stateSha256')));
  }
  const base = {
    caseId: `synthetic-${mode}-${taskId}`,
    caseHash: '0'.repeat(64),
    taskId,
    mode,
    rubricVersion: 'bts-rubric/v1',
    rubricHash: taskRubricHash(taskId),
    taskWeight: WEIGHT[taskId],
    mandatoryRules: RULES[taskId],
    executionIdentityHash: identityHash,
    taskDeadlineSeconds: 120,
    initialState: state,
    initialStateEvidence: evidence(`evidence/${mode}/${taskId}-initial-state.json`),
    referencePath: {
      evidence: evidence(`evidence/${mode}/${taskId}-reference.json`),
      actionCount: 2,
      initialStateSha256: state.stateSha256,
      finalStateSha256: sha(`final-${mode}-${taskId}`),
      toolSurfaceSha256: sha('synthetic-tool-surface'),
    },
    objective,
  };
  base.referencePath.toolSurfaceSha256 = sha('synthetic-tool-surface');
  base.caseHash = taskCaseHash(without(base, 'caseHash'));
  return base;
}

function makeManifest() {
  const sourceBlockHash = sha('synthetic-source-block');
  const executionIdentity = {
    profileId: 'synthetic-base-fork-profile-v1',
    environmentManifestSha256: sha('synthetic-environment-manifest'),
    toolSurfaceSha256: sha('synthetic-tool-surface'),
    x402ServiceSha256: sha('synthetic-x402-service'),
    applicationSchemaVersion: 'synthetic-app-schema-v1',
    sourceNetwork: 'base', sourceChainId: 8453, sourceBlockNumber: '100', sourceBlockHash,
    localNetwork: 'base-anvil-fork', localChainId: 8453, localForkBlockNumber: '100',
    assets: [
      { assetId: 'ETH', kind: 'native', chainId: 8453, address: null, codeHash: null, decimals: 18 },
      { assetId: 'WETH', kind: 'erc20', chainId: 8453, address: WETH, codeHash: sha('synthetic-weth-code'), decimals: 18 },
      { assetId: 'USDC', kind: 'erc20', chainId: 8453, address: USDC, codeHash: sha('synthetic-usdc-code'), decimals: 6 },
    ],
    contracts: [
      { contractId: 'router-main', address: ROUTER, codeHash: sha('synthetic-router-code'), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
      { contractId: 'pool-main', address: POOL, codeHash: sha('synthetic-pool-code'), chainId: 8453, blockNumber: '100', blockHash: sourceBlockHash },
    ],
  };
  const executionIdentityHash = sha(canonicalJson(executionIdentity));
  const manifest = {
    schemaVersion: 'bts-task-release/v1',
    releaseIdentity: 'synthetic-bts-release-v1',
    benchmarkVersion: 'synthetic-bts-v1',
    manifestHash: '0'.repeat(64), benchmarkHash: '0'.repeat(64), policyHash: '0'.repeat(64),
    inventory: {
      orderedTaskIds: TASK_IDS,
      rankedWeightSum: 26,
      openTrainingTaskIds: TRAINING_IDS,
      openTrainingWeightSum: 15,
      closedRankedOnlyTaskIds: CLOSED_RANKED_IDS,
    },
    pricing: { precision: 6, openTrainingPriceUnits: '500000', rankedPriceUnits: '1000000', trainingRounding: 'ceil_once_per_request' },
    deadlines: { taskTimeoutSeconds: 180, trainingRunTimeoutSeconds: 1800, rankedRunTimeoutSeconds: 3600 },
    executionIdentity, executionIdentityHash,
    costPolicy: {
      policyVersion: 'synthetic-cost-policy-v1', usdcAssetId: 'USDC', usdcPrecision: 6,
      ethValuation: { numerator: '1', denominator: '1000000000000' },
      expenseComponents: ['paid_service_charge', 'participant_gas_success_or_revert', 'verified_dex_fee'],
      rounding: 'floor_to_usdc_base_units', principalSeparateFromExpense: true,
      ethAndWethDistinct: true, missingFeeEvidence: 'unknown',
    },
    feasibilityEvidence: evidence('evidence/synthetic/feasibility.json'),
    difficultyReviewEvidence: evidence('evidence/synthetic/difficulty-review.json'),
    cases: {
      training: TRAINING_IDS.map((taskId) => makeCase('training', taskId, executionIdentityHash)),
      ranked: TASK_IDS.map((taskId) => makeCase('ranked', taskId, executionIdentityHash)),
    },
  };
  manifest.policyHash = taskPolicyHash(manifest);
  manifest.benchmarkHash = taskBenchmarkHash(manifest);
  manifest.manifestHash = sha(canonicalJson(without(manifest, 'manifestHash')));
  return manifest;
}

function resealCaseAndManifest(manifest, mode, taskId) {
  const taskCase = manifest.cases[mode].find((entry) => entry.taskId === taskId);
  taskCase.caseHash = taskCaseHash(without(taskCase, 'caseHash'));
  manifest.benchmarkHash = taskBenchmarkHash(manifest);
  manifest.manifestHash = sha(canonicalJson(without(manifest, 'manifestHash')));
  return manifest;
}

function unavailableVerifier() {
  const calls = { feasibility: 0, references: 0, difficulty: 0 };
  const verifier = {
    async verifyFeasibility() { calls.feasibility += 1; return { status: 'unavailable', reason: 'synthetic evidence is not live evidence' }; },
    async verifyReferencePath() { calls.references += 1; return { status: 'unavailable', reason: 'synthetic reference is not live evidence' }; },
    async verifyDifficultyReview() { calls.difficulty += 1; return { status: 'unavailable', reason: 'synthetic review is not live evidence' }; },
  };
  return { verifier, calls };
}

function assertHasBlocker(result, code) {
  assert.equal(result.status, 'blocked');
  assert.ok(result.blockers.some((blocker) => blocker.code === code), `expected blocker ${code}; saw ${result.blockers.map(({ code: item }) => item).join(', ')}`);
}

test('tool protocol is a release policy pin while omitted legacy protocol preserves its policy hash', () => {
  const candidate = makeManifest();
  assert.equal(taskPolicyHash(candidate), candidate.policyHash);
  const split = { ...candidate, participantToolProtocol: 'separate_payment_delivery_v2' };
  const explicitLegacy = { ...candidate, participantToolProtocol: 'combined_purchase_v1' };
  assert.equal(TaskReleaseManifestSchema.safeParse(split).success, true);
  assert.notEqual(taskPolicyHash(split), candidate.policyHash);
  assert.notEqual(taskPolicyHash(split), taskPolicyHash(explicitLegacy));
});

test('synthetic contract: pinned inventory and mode exposure preserve the approved order', () => {
  assert.deepEqual(TASK_IDS, ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1']);
  assert.deepEqual(CLOSED_RANKED_IDS, ['S3', 'M2', 'H3', 'U1']);
  assert.deepEqual(selectTaskIds('training', [...TRAINING_IDS].reverse()), { ok: true, mode: 'training', taskIds: TRAINING_IDS, weightSum: 15 });
  assert.deepEqual(selectTaskIds('ranked', [...TASK_IDS].reverse()), { ok: true, mode: 'ranked', taskIds: TASK_IDS, weightSum: 26 });
  assert.deepEqual(selectTaskIds('training', ['S3']), { ok: false, reason: 'closed_training_task' });
  assert.deepEqual(selectTaskIds('ranked', TASK_IDS.slice(0, 11)), { ok: false, reason: 'ranked_selection_must_be_complete' });
  assert.deepEqual(PUBLIC_TASK_CATALOG.filter((task) => !task.trainingAvailable).map((task) => task.taskId), CLOSED_RANKED_IDS);
});

test('synthetic contract: open training price uses one integer ceiling and preserves zero', () => {
  assert.equal(quoteOpenTrainingSelection(['S1'], '0').priceUnits, '0');
  assert.equal(quoteOpenTrainingSelection(['S1'], '500000').priceUnits, '33334');
  assert.equal(quoteOpenTrainingSelection(['S1', 'S2'], '500000').priceUnits, '66667');
  assert.equal(quoteOpenTrainingSelection(['M1', 'S1'], '1').priceUnits, '1');
  assert.deepEqual(quoteOpenTrainingSelection(['S3'], '500000'), { ok: false, reason: 'closed_training_task' });
  assert.deepEqual(quoteOpenTrainingSelection(['S1'], '0001'), { ok: false, reason: 'invalid_price' });
});

test('synthetic contract: renamed or reordered copies do not establish distinct training cases', async () => {
  const candidate = makeManifest();
  const training = candidate.cases.training.find((item) => item.taskId === 'S1');
  const ranked = candidate.cases.ranked.find((item) => item.taskId === 'S1');
  training.objective = structuredClone(ranked.objective);
  training.initialState = structuredClone(ranked.initialState);
  training.initialState.balances.reverse();
  training.initialState.stateSha256 = sha('different-evidence-identity-only');
  training.referencePath.initialStateSha256 = training.initialState.stateSha256;
  resealCaseAndManifest(candidate, 'training', 'S1');
  const { verifier } = unavailableVerifier();
  assertHasBlocker(await validateTaskReleaseCandidate(candidate, verifier), 'training_ranked_cases_not_distinct');
});

test('synthetic contract: full shaped case inventory parses but remains unverifiable without actual evidence', async () => {
  const candidate = makeManifest();
  assert.equal(TaskReleaseManifestSchema.safeParse(candidate).success, true);
  assert.deepEqual(candidate.cases.ranked.map((taskCase) => taskCase.taskId), TASK_IDS);
  assert.deepEqual(candidate.cases.training.map((taskCase) => taskCase.taskId), TRAINING_IDS);

  const { verifier, calls } = unavailableVerifier();
  const result = await validateTaskReleaseCandidate(candidate, verifier);
  assertHasBlocker(result, 'feasibility_evidence_unavailable');
  assert.deepEqual(calls, { feasibility: 1, references: 0, difficulty: 0 });
});

test('synthetic contract: read-only reference paths may preserve state but still require actual feasibility', async () => {
  const candidate = makeManifest();
  for (const mode of ['training', 'ranked']) {
    for (const taskId of ['S2', 'S3']) {
      const taskCase = candidate.cases[mode].find((item) => item.taskId === taskId);
      if (!taskCase) continue;
      taskCase.referencePath.finalStateSha256 = taskCase.referencePath.initialStateSha256;
      resealCaseAndManifest(candidate, mode, taskId);
    }
  }
  const { verifier, calls } = unavailableVerifier();
  const result = await validateTaskReleaseCandidate(candidate, verifier);
  assertHasBlocker(result, 'feasibility_evidence_unavailable');
  assert.deepEqual(calls, { feasibility: 1, references: 0, difficulty: 0 });
});

test('synthetic contract: unchanged state still blocks a transfer reference before evidence verification', async () => {
  const candidate = makeManifest();
  const taskCase = candidate.cases.ranked.find((item) => item.taskId === 'S1');
  taskCase.referencePath.finalStateSha256 = taskCase.referencePath.initialStateSha256;
  resealCaseAndManifest(candidate, 'ranked', 'S1');
  const { verifier, calls } = unavailableVerifier();
  assertHasBlocker(await validateTaskReleaseCandidate(candidate, verifier), 'case_identity_or_initial_state_mismatch');
  assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
});

test('synthetic contract: namespaced data versions retain their actual identities', async () => {
  const candidate = makeManifest();
  const component = candidate.cases.ranked.find((item) => item.taskId === 'M1').objective.component;
  component.validator.validatorVersion = 'bef-delivery-envelope-validator/v1';
  component.validator.payloadSchemaVersion = 'bef-delivery-envelope/v1';
  resealCaseAndManifest(candidate, 'ranked', 'M1');
  assert.equal(TaskReleaseManifestSchema.safeParse(candidate).success, true);
  const { verifier, calls } = unavailableVerifier();
  assertHasBlocker(await validateTaskReleaseCandidate(candidate, verifier), 'feasibility_evidence_unavailable');
  assert.deepEqual(calls, { feasibility: 1, references: 0, difficulty: 0 });
});

test('synthetic contract: data version support does not relax resource identities or accept whitespace', () => {
  for (const mutate of [
    (item) => { item.validator.validatorVersion = 'invalid version/v1'; },
    (item) => { item.validator.payloadSchemaVersion = 'schema/v1\n'; },
    (item) => { item.resourceId = 'resource/with-path'; },
  ]) {
    const candidate = makeManifest();
    mutate(candidate.cases.ranked.find((item) => item.taskId === 'M1').objective.component);
    resealCaseAndManifest(candidate, 'ranked', 'M1');
    assert.equal(TaskReleaseManifestSchema.safeParse(candidate).success, false);
  }
});

test('synthetic contract: unresolved unknown values remain placeholders outside the required fee-policy enum', async () => {
  const candidate = makeManifest();
  const unresolvedCase = candidate.cases.ranked.find((taskCase) => taskCase.taskId === 'S1');
  unresolvedCase.caseId = 'unknown';
  resealCaseAndManifest(candidate, 'ranked', 'S1');
  const { verifier, calls } = unavailableVerifier();

  const result = await validateTaskReleaseCandidate(candidate, verifier);
  assertHasBlocker(result, 'placeholder_or_latest_value');
  assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
});

test('synthetic contract: incomplete inventory and wrong release/case hashes reject before evidence verification', async () => {
  const { verifier, calls } = unavailableVerifier();

  const incomplete = makeManifest();
  incomplete.cases.ranked.pop();
  const incompleteResult = await validateTaskReleaseCandidate(incomplete, verifier);
  assertHasBlocker(incompleteResult, 'manifest_schema_invalid');

  const wrongManifestHash = makeManifest();
  wrongManifestHash.manifestHash = 'f'.repeat(64);
  const manifestResult = await validateTaskReleaseCandidate(wrongManifestHash, verifier);
  assertHasBlocker(manifestResult, 'manifest_hash_mismatch');

  const wrongCaseHash = makeManifest();
  wrongCaseHash.cases.training[0].caseHash = 'e'.repeat(64);
  const caseResult = await validateTaskReleaseCandidate(wrongCaseHash, verifier);
  assertHasBlocker(caseResult, 'case_hash_mismatch');
  assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
});

test('synthetic contract: absent evidence cannot activate even a well-shaped release', async () => {
  const candidate = makeManifest();
  delete candidate.feasibilityEvidence;
  const { verifier, calls } = unavailableVerifier();
  let activations = 0;
  const store = {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord() { return null; },
    async activateValidatedRelease() { activations += 1; },
  };

  const result = await activateTaskReleaseCandidate(candidate, verifier, store, {});
  assertHasBlocker(result, 'manifest_schema_invalid');
  assert.equal(activations, 0);
  assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
});

test('synthetic contract: missing verifier evidence blocks activation before storage', async () => {
  const candidate = makeManifest();
  const { verifier, calls } = unavailableVerifier();
  let activations = 0;
  const store = {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord() { return null; },
    async activateValidatedRelease() { activations += 1; },
  };

  const result = await activateTaskReleaseCandidate(candidate, verifier, store, {});
  assertHasBlocker(result, 'feasibility_evidence_unavailable');
  assert.equal(activations, 0);
  assert.deepEqual(calls, { feasibility: 1, references: 0, difficulty: 0 });
});

test('synthetic contract: empty U1 fixed sets and validator fields fail the schema', () => {
  for (const mutate of [
    (manifest) => { manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1').objective.requiredComponents = []; },
    (manifest) => { manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1').objective.allocationAssets = []; },
    (manifest) => { manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1').objective.payoutObligations = []; },
    (manifest) => { manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1').objective.temporarySpenderScope = []; },
    (manifest) => { manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1').objective.requiredComponents[0].validator.requiredFields = []; },
  ]) {
    const candidate = mutateAndReseal(makeManifest(), mutate);
    assert.equal(TaskReleaseManifestSchema.safeParse(candidate).success, false);
  }
});

test('synthetic contract: duplicate U1 components, validator fields, and payout obligations are semantic blockers', async () => {
  const mutations = [
    (manifest) => {
      const taskCase = manifest.cases.ranked.find((entry) => entry.taskId === 'U1');
      taskCase.objective.requiredComponents.push(structuredClone(taskCase.objective.requiredComponents[0]));
      resealCaseAndManifest(manifest, 'ranked', 'U1');
    },
    (manifest) => {
      const taskCase = manifest.cases.ranked.find((entry) => entry.taskId === 'U1');
      taskCase.objective.requiredComponents[0].validator.requiredFields.push(structuredClone(taskCase.objective.requiredComponents[0].validator.requiredFields[0]));
      resealCaseAndManifest(manifest, 'ranked', 'U1');
    },
    (manifest) => {
      const taskCase = manifest.cases.ranked.find((entry) => entry.taskId === 'U1');
      taskCase.objective.payoutObligations[1] = structuredClone(taskCase.objective.payoutObligations[0]);
      resealCaseAndManifest(manifest, 'ranked', 'U1');
    },
  ];

  const expectedCodes = ['invalid_u1_fixed_sets', 'missing_component_validator_field', 'invalid_u1_fixed_sets'];
  for (let index = 0; index < mutations.length; index += 1) {
    const candidate = makeManifest();
    mutations[index](candidate);
    assert.equal(TaskReleaseManifestSchema.safeParse(candidate).success, true);
    const { verifier, calls } = unavailableVerifier();
    const result = await validateTaskReleaseCandidate(candidate, verifier);
    assertHasBlocker(result, expectedCodes[index]);
    assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
  }
});

test('synthetic contract: validated mode projection and provider return no case payloads', async () => {
  const manifest = makeManifest();
  const rankedSecret = manifest.cases.ranked.find((taskCase) => taskCase.taskId === 'U1');
  rankedSecret.caseId = 'synthetic-ranked-case-sentinel';
  resealCaseAndManifest(manifest, 'ranked', 'U1');
  const record = {
    releaseIdentity: manifest.releaseIdentity,
    manifestHash: manifest.manifestHash,
    benchmarkVersion: manifest.benchmarkVersion,
    benchmarkHash: manifest.benchmarkHash,
    policyHash: manifest.policyHash,
    manifest,
  };
  const projection = validatedModeProjection(record, 'training');
  assert.deepEqual(projection.taskIds, TRAINING_IDS);
  assert.equal('cases' in projection, false);
  assert.equal('manifest' in projection, false);
  assert.equal(JSON.stringify(projection).includes('synthetic-ranked-case-sentinel'), false);

  const provider = createTaskReleaseProvider({
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord(releaseIdentity, manifestHash) {
      return releaseIdentity === record.releaseIdentity && manifestHash === record.manifestHash ? record : null;
    },
  });
  assert.equal(await provider.getActiveAdmissionRelease('ranked'), null);
  const provided = await provider.getValidatedRelease(record.releaseIdentity, record.manifestHash, 'training');
  assert.deepEqual(provided.taskIds, TRAINING_IDS);
  assert.equal('cases' in provided, false);
  assert.equal(JSON.stringify(provider.getPublicCatalog()).includes('synthetic-ranked-case-sentinel'), false);
});

test('synthetic contract: transfer and payout cases require explicit recipient balance baselines', async () => {
  for (const taskId of ['S1', 'H2', 'U1']) {
    const manifest = makeManifest();
    const task = manifest.cases.ranked.find((entry) => entry.taskId === taskId);
    task.initialState.balances = task.initialState.balances.filter((entry) => entry.account === 'participant');
    resealCaseAndManifest(manifest, 'ranked', taskId);
    const { verifier, calls } = unavailableVerifier();
    const result = await validateTaskReleaseCandidate(manifest, verifier);
    assertHasBlocker(result, 'invalid_task_reference');
    assert.deepEqual(calls, { feasibility: 0, references: 0, difficulty: 0 });
  }
});

function mutateAndReseal(manifest, mutate) {
  mutate(manifest);
  return manifest;
}
