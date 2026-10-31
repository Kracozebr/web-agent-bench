// Offline partial TaskCase assembly. No registry, actor, chain or database writes.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { TaskCaseSchema, canonicalTaskJson, sha256CanonicalTaskJson, taskCaseHash,
  taskRubricHash, taskMandatoryRules } from '../../packages/owner-identity/src/task-release.ts';
import { CURRENT_TRAINING_TASK_IDS, PUBLIC_TASK_CATALOG, TASK_IDS } from '../../packages/owner-identity/src/task-catalog.ts';
import { calculateParticipantExpenseBudget } from '../../packages/owner-identity/src/task-case-assembler.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';
import { projectDeliveryEnvelope } from '../../packages/benchmark-environment/src/probe/task-reference-cases.ts';
import { projectRouteDelivery } from '../../packages/benchmark-environment/src/probe/task-route-reference.ts';
import { sourceDigests } from '../../packages/benchmark-environment/src/probe/environment.ts';
import { projectBasicV2Candidate } from './project-basic-v2-candidates.mjs';
import { projectU1V2Candidate } from './project-u1-v2-candidate.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hashPattern = /^[0-9a-f]{64}$/;
const boundary = 'actual_tool_http_x402_local_evm_application_store';
const frozenCandidatePath = 'artifacts/runs/bts-difficulty-v2-case-candidates/00f47005-8951-4003-b6b3-4540172e15d9/candidate-cases.json';
const frozenCandidateSha256 = '7ddc9b1181041933aad76c056ffa3288a65265e3d9e6725381343412ce05e82b';
function must(condition, code) { if (!condition) throw new Error(code); }
function uint(value) { must(typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value), 'uint_invalid'); return value; }
function safePath(path) {
  must(typeof path === 'string' && path.length <= 512 && !path.includes('\\') && !path.includes(':')
    && path.split('/').every((part) => part && part !== '.' && part !== '..'), 'path_invalid');
  return path;
}
async function pinned(path, expected, parse = true) {
  must(hashPattern.test(expected), 'hash_invalid');
  const bytes = await readFile(resolve('/workspace', safePath(path)));
  must(bytes.length <= 8 * 1024 * 1024 && sha(bytes) === expected, 'input_hash_mismatch');
  return { bytes, value: parse ? JSON.parse(bytes.toString('utf8')) : null };
}
function state(balances, allowances = [], deliveredComponentIds = [], fulfilledObligationIds = []) {
  const balanceKey = (item) => `${item.account.toLowerCase()}|${item.assetId}`;
  const allowanceKey = (item) => `${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`;
  const sort = (key) => (left, right) => key(left) < key(right) ? -1 : key(left) > key(right) ? 1 : 0;
  return { balances: balances.toSorted(sort(balanceKey)), allowances: allowances.toSorted(sort(allowanceKey)),
    deliveredComponentIds: [...deliveredComponentIds].sort(), fulfilledObligationIds: [...fulfilledObligationIds].sort() };
}
function participantState(raw, router, delivered = []) {
  must(raw && typeof raw === 'object', 'state_missing');
  return state([
    { account: 'participant', assetId: 'ETH', amountUnits: uint(raw.payerNativeEthWei) },
    { account: 'participant', assetId: 'USDC', amountUnits: uint(raw.payerUsdcUnits) },
    { account: 'participant', assetId: 'WETH', amountUnits: uint(raw.payerWethUnits) },
  ], ['USDC', 'WETH'].map((tokenAssetId) => ({ owner: 'participant', tokenAssetId, spender: router,
    amountUnits: uint(raw[tokenAssetId === 'USDC' ? 'usdcRouterAllowanceUnits' : 'wethRouterAllowanceUnits']) })), delivered);
}
function component(value) {
  const item = value.dataComponent ?? value;
  return { componentId: item.componentId, resourceId: item.resourceId, validator: item.validator, sourceIds: item.sourceIds };
}
function assetId(identity, raw) {
  const found = identity.assets.filter((asset) => asset.assetId === raw
    || asset.address?.toLowerCase() === String(raw).toLowerCase());
  must(found.length === 1, 'asset_identity_ambiguous'); return found[0].assetId;
}
function catalog(identity, offers) {
  return offers.map((offer) => ({ ...offer, assetId: assetId(identity, offer.assetId),
    paymentRequirements: { ...offer.paymentRequirements, assetId: assetId(identity, offer.paymentRequirements.assetId) } }));
}
function route(manifest, fee, direction = 'reverse') {
  must(fee === 500 || fee === 3000, 'route_fee_invalid');
  must(manifest.contracts[fee === 500 ? 'pool' : 'pool3000'].fee === fee, 'route_manifest_mismatch');
  return { routeId: fee === 500 ? 'fee500' : 'fee3000', routeType: 'uniswap_v3_exact_input_single',
    tokenInAssetId: direction === 'reverse' ? 'WETH' : 'USDC', tokenOutAssetId: direction === 'reverse' ? 'USDC' : 'WETH',
    routerContractId: 'swapRouter02', poolContractId: fee === 500 ? 'pool' : 'pool3000', feeTier: fee };
}
function budget(manifest, policy, service, gas, dex = '0') {
  return calculateParticipantExpenseBudget({ serviceChargesUsdcUnits: uint(service), participantGasWei: uint(gas),
    verifiedDexFeeUsdcUnits: uint(dex), ethUsdcRateNumerator: manifest.feePolicy.ethUsdcRateNumerator,
    ethUsdcRateDenominator: manifest.feePolicy.ethUsdcRateDenominator,
    ...Object.fromEntries(['headroomMultiplierNumerator', 'headroomMultiplierDenominator', 'roundUpToUsdcUnits']
      .map((key) => [key, policy.expenseBudget[key]])) });
}
export async function buildProjection(probe, manifest, identity, policy, rawArtifact) {
  const capture = probe.capture, task = probe.taskId, router = manifest.contracts.swapRouter02.address.toLowerCase();
  const resourceInputs = [];
  const helpers = { state, participantState, assetId, budget, route, component, projectDeliveryEnvelope,
    readPinnedResource: async (path, sha256) => { const value = await pinned(path, sha256);
      resourceInputs.push({ path, sha256 }); return value; } };
  if (['S1', 'S2', 'S3', 'S4', 'M3', 'U1'].includes(task)) {
    const project = task === 'U1' ? projectU1V2Candidate : projectBasicV2Candidate;
    return { ...await project({ probe, manifest, identity, policy, rawArtifact, helpers }), resourceInputs };
  }
  let initial, final, objective, expense;
  const delivery = async (resourceId, routeDelivery = false) => {
    const action = probe.captureReferences.participantActions.find((action) => action.kind === 'retrieve');
    must(action, 'delivery_action_missing');
    const envelope = (await rawArtifact(action.rawResponsePath)).value;
    const definition = manifest.x402.catalog.find((resource) => resource.resourceId === resourceId);
    must(definition, 'resource_not_pinned');
    const input = { envelope, expectedResourceId: resourceId, expectedContentHash: definition.resourceSha256,
      provenanceId: definition.provenance.classification };
    return routeDelivery ? projectRouteDelivery({ ...input,
      routes: [{ value: 'baseline', routeId: 'fee500' }, { value: 'alternative', routeId: 'fee3000' }] }) : projectDeliveryEnvelope(input);
  };
  if (task === 'M1') {
    const reference = capture.reference;
    const projected = await delivery(reference.resourceId);
    const data = component(projected.component);
    initial = participantState(capture.initialState, router);
    final = participantState(capture.finalState, router, [data.componentId]);
    expense = budget(manifest, policy, reference.amountUsdcUnits, '0');
    objective = { component: data, paymentRequirements: {
      scheme: manifest.x402.scheme, resourceId: reference.resourceId, offerId: reference.offerId,
      version: manifest.x402.eip712Domain.version, amountUnits: reference.amountUsdcUnits,
      network: manifest.x402.network, assetId: assetId(identity, manifest.x402.asset), recipient: reference.facilitatorAddress,
      authFields: [{ name: 'assetTransferMethod', value: manifest.x402.assetTransferMethod },
        { name: 'paymentFlow', value: 'authorization' }, { name: 'name', value: manifest.x402.eip712Domain.name },
        { name: 'version', value: manifest.x402.eip712Domain.version }],
    }, expenseBudgetUsdcUnits: expense.budgetUsdcUnits, duplicatePurchaseIdentity: policy.duplicatePurchaseIdentity };
  } else if (task === 'M2') {
    const candidate = capture.objectiveCandidate;
    initial = participantState(capture.initialState, router);
    final = participantState(capture.finalState, router, [capture.delivery.component.componentId]);
    expense = budget(manifest, policy, capture.selectedOffer.amountUsdcUnits, '0');
    objective = { catalog: catalog(identity, candidate.catalog), required: { ...candidate.required,
      assetId: assetId(identity, candidate.required.assetId) }, expenseBudgetUsdcUnits: expense.budgetUsdcUnits,
      tiePolicy: 'all_minimum_advertised_total_prices_qualify', duplicatePurchaseIdentity: policy.duplicatePurchaseIdentity };
  } else if (task === 'H1') {
    const components = capture.components.map(component);
    initial = participantState(capture.initialState, router);
    final = participantState(capture.finalState, router, components.map((item) => item.componentId));
    const service = capture.components.reduce((sum, item) => sum + BigInt(uint(item.amountUsdcUnits)), 0n).toString();
    expense = budget(manifest, policy, service, '0');
    objective = { requiredComponents: components, permittedSources: policy.permittedProvenanceIds,
      expenseBudgetUsdcUnits: expense.budgetUsdcUnits, duplicatePurchaseIdentity: policy.duplicatePurchaseIdentity };
  } else if (task === 'H2') {
    const obligations = capture.obligations;
    const balances = (raw) => [
      { account: 'participant', assetId: 'USDC', amountUnits: uint(raw.payerUsdcUnits) },
      { account: 'participant', assetId: 'ETH', amountUnits: uint(raw.payerNativeWei) },
      ...obligations.map((item) => ({ account: item.recipient, assetId: 'USDC', amountUnits: uint(raw.recipientUsdcUnits[item.recipient]) })),
    ];
    initial = state(balances(capture.initialAssets));
    must(obligations.every((item) => item.fulfilledAtCommonCutoff === true), 'payout_not_fulfilled');
    final = state(balances(capture.finalCutoff), [], [], obligations.map((item) => item.obligationId));
    expense = budget(manifest, policy, '0', capture.observedExpense.participantGasCostWei);
    objective = { obligations: obligations.map((item) => ({ obligationId: item.obligationId,
      recipient: item.recipient, assetId: assetId(identity, item.assetId), exactAmountUnits: item.amountUnits })),
      initialAssetIds: ['USDC', 'ETH'], permittedConversions: [], nativeReserveWei: policy.nativeReserveWei.H2,
      expenseBudgetUsdcUnits: expense.budgetUsdcUnits };
  } else if (task === 'M4' || task === 'H3') {
    const cost = capture.measuredCost;
    expense = budget(manifest, policy, cost.serviceChargeUsdcUnits, cost.participantGasCostWei, cost.dexFeeUsdcUnits);
    initial = participantState(task === 'M4' ? capture.initial : capture.initialCaseState, router);
    if (task === 'M4') {
      final = participantState(capture.final, router);
      objective = { inputAssetId: 'WETH', exactInputUnits: capture.amountInUnits, outputAssetId: 'USDC',
        minimumOutputUnits: capture.quote.minimumOutputUnits, permittedRoutes: [route(manifest, capture.route.feeTier)],
        initialAllowanceScope: initial.allowances.filter((item) => item.tokenAssetId === 'WETH'),
        nativeReserveWei: policy.nativeReserveWei.M4, expenseBudgetUsdcUnits: expense.budgetUsdcUnits };
    } else {
      const projected = await delivery(capture.paidReference.resourceId, true), data = component(projected.component);
      final = participantState(capture.final, router, [data.componentId]);
      const selectedQuote = capture.quotePlanning[capture.route.feeTier === 500 ? 'fee500' : 'fee3000'];
      objective = { referenceComponent: data, routeObjective: projected.routeObjective, inputAssetId: 'WETH',
        exactInputUnits: capture.amountInUnits, permittedRoutes: [route(manifest, 500), route(manifest, 3000)],
        minimumOutputUnits: selectedQuote.minimumOutputUnits, nativeReserveWei: policy.nativeReserveWei.H3,
        combinedExpenseBudgetUsdcUnits: expense.budgetUsdcUnits };
    }
  } else throw new Error('task_projection_not_implemented');
  return { initial, final, objective, expense };
}
async function main() {
  must(process.platform === 'linux' && process.cwd() === '/workspace', 'docker_required');
  const args = process.argv.slice(2);
  must(args.length === 4 && args[0] === '--integrity' && args[2] === '--sha256', 'usage');
  const integrityInput = await pinned(args[1], args[3]), integrity = integrityInput.value;
  must(integrity.status === 'verified' && integrity.classification === 'raw_artifact_integrity_and_trace_binding_not_semantic_task_acceptance',
    'integrity_contract_invalid');
  await pinned(integrity.retainedInputIndex.path, integrity.retainedInputIndex.sha256);
  const frozenCasesInput = await pinned(frozenCandidatePath, frozenCandidateSha256), frozenCandidate = frozenCasesInput.value;
  must(frozenCandidate.schemaVersion === 'bts-difficulty-v2-case-candidates/v1'
    && frozenCandidate.captureId === frozenCandidatePath.split('/')[3] && Array.isArray(frozenCandidate.cases)
    && frozenCandidate.cases.length === 20 && Array.isArray(frozenCandidate.sourceInputs), 'frozen_candidate_inventory_invalid');
  const frozenCases = frozenCandidate.cases.map((value) => TaskCaseSchema.parse(value));
  const frozenByKey = new Map(frozenCases.map((taskCase) => [`${taskCase.taskId}:${taskCase.mode}`, taskCase]));
  must(frozenByKey.size === frozenCases.length, 'frozen_candidate_keys_invalid');
  const identityPath = 'artifacts/runs/bts-runtime-feasibility-verification/5da32b24-3bbe-4e23-8969-ee954d7acf72/verification.json';
  const identityInput = await pinned(identityPath, '0d0032dd24f5a9e8c4bcccf9e80088287f719ec1299a4649ba9de0300825feb0');
  const identity = identityInput.value.executionIdentity, identityHash = sha256CanonicalTaskJson(identity);
  must(identityHash === identityInput.value.executionIdentityHash, 'identity_hash_mismatch');
  const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
  const policyBytes = await readFile(policyPath), policy = JSON.parse(policyBytes);
  must(policy.schemaVersion === 'bts-local-case-assembly-policy/v1' && policy.profileId === identity.profileId
    && policy.difficultyApproval === false && policy.releaseActivation === false, 'policy_invalid');
  const appSource = await sourceDigests('/workspace');
  must(appSource.appSourceSha256 === identity.x402ServiceSha256, 'current_application_source_mismatch');
  const feasibility = await verifyRetainedTaskFeasibility({ repositoryRoot: '/workspace',
    evidence: { ...identityInput.value.witness, boundary }, executionIdentity: identity,
    expectedIdentityHash: identityHash, profilePolicy: { path: policyPath, sha256: sha(policyBytes) },
    participantToolProtocol: 'separate_payment_delivery_v2' });
  must(feasibility.status === 'verified', 'current_retained_feasibility_not_verified');
  const expectedCaseKeys = [
    ...TASK_IDS.map((taskId) => `${taskId}:ranked`),
    ...CURRENT_TRAINING_TASK_IDS.map((taskId) => `${taskId}:training`),
  ].sort();
  const expectedCaseKeySet = new Set(expectedCaseKeys);
  const integrityCaseKeys = integrity.captures.map((capture) => `${capture.taskId}:${capture.mode}`).sort();
  const frozenProbePins = new Set(frozenCandidate.sourceInputs
    .filter((row) => typeof row.path === 'string' && row.path.endsWith('/probe.json') && hashPattern.test(row.sha256))
    .map((row) => `${row.path}\0${row.sha256}`));
  must(integrityCaseKeys.length === expectedCaseKeys.length && new Set(integrityCaseKeys).size === expectedCaseKeys.length
    && integrityCaseKeys.every((key, index) => key === expectedCaseKeys[index])
    && integrity.captures.every((capture) => expectedCaseKeySet.has(`${capture.taskId}:${capture.mode}`)
      && frozenProbePins.has(`${capture.probe.path}\0${capture.probe.sha256}`)),
  'current_raw_probes_do_not_match_frozen_case_sources');
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-difficulty-v2-case-candidates/${captureId}`;
  await mkdir(outputPrefix, { recursive: true });
  const cases = expectedCaseKeys.map((key) => frozenByKey.get(key));
  must(cases.every(Boolean), 'current_cases_missing_from_frozen_candidate');
  const evidenceFiles = new Map();
  const sourceInputs = [{ path: args[1], sha256: args[3] },
    { path: frozenCandidatePath, sha256: frozenCandidateSha256 },
    integrity.verifierSource,
    { ...integrity.retainedInputIndex }, { ...identityInput.value.witness },
    { path: identityPath, sha256: sha(identityInput.bytes) }, { path: policyPath, sha256: sha(policyBytes) },
    ...identityInput.value.applicationSchemaLineage.migrationFiles];
  for (const path of ['infrastructure/owner-identity/assemble-difficulty-v2-candidates.mjs', 'pnpm-lock.yaml',
    'infrastructure/owner-identity/project-basic-v2-candidates.mjs', 'infrastructure/owner-identity/project-u1-v2-candidate.mjs',
    ...['task-release', 'task-catalog', 'task-case-assembler', 'task-reference-inventory', 'task-feasibility-evidence']
      .map((name) => `packages/owner-identity/src/${name}.ts`),
    'infrastructure/owner-identity/verify-runtime-feasibility.mjs',
    'packages/benchmark-environment/src/probe/environment.ts',
    'packages/benchmark-environment/src/probe/task-reference-cases.ts', 'packages/benchmark-environment/src/probe/task-route-reference.ts']) {
    sourceInputs.push({ path, sha256: sha(await readFile(path)) });
  }
  let projectedCaseCount = 0;
  for (const source of integrity.captures) {
    const probeInput = await pinned(source.probe.path, source.probe.sha256), probe = probeInput.value;
    const captureRoot = dirname(source.probe.path);
    must(probe.status === 'captured' && probe.participantToolProtocol === 'separate_payment_delivery_v2'
      && probe.sourceDigests.matches && probe.sourceDigests.before.appSourceSha256 === identity.x402ServiceSha256
      && probe.manifest.sha256 === identity.environmentManifestSha256, 'probe_identity_mismatch');
    const artifacts = new Map(probe.artifacts.map((artifact) => [artifact.path, artifact]));
    const rawArtifact = async (path) => { const ref = artifacts.get(path); must(ref, 'artifact_not_indexed');
      return pinned(`${captureRoot}/${safePath(path)}`, ref.sha256); };
    // Integrity is checked again during assembly; previous green summaries never substitute for raw bytes.
    for (const ref of artifacts.values()) await rawArtifact(ref.path);
    const manifest = (await rawArtifact(probe.manifest.path)).value;
    const projected = await buildProjection(probe, manifest, identity, policy, rawArtifact);
    sourceInputs.push(...(projected.resourceInputs ?? []));
    const taskKey = `${probe.taskId}:${probe.mode}`;
    const frozen = frozenByKey.get(taskKey);
    must(frozen && expectedCaseKeySet.has(taskKey), 'projection_case_not_in_current_frozen_inventory');
    const caseId = `bts-${probe.mode}-${probe.taskId.toLowerCase()}-local-v2`;
    must(frozen.caseId === caseId, 'frozen_case_identity_mismatch');
    const initialHash = sha256CanonicalTaskJson(projected.initial), finalHash = sha256CanonicalTaskJson(projected.final);
    const rawReferences = [...artifacts.values()].map((ref) => ({ path: `${captureRoot}/${ref.path}`, sha256: ref.sha256, boundary: ref.boundary }));
    sourceInputs.push(...rawReferences.map(({ path, sha256 }) => ({ path, sha256 })));
    const initialEvidence = (await pinned(frozen.initialStateEvidence.path, frozen.initialStateEvidence.sha256)).value;
    const referenceEvidence = (await pinned(frozen.referencePath.evidence.path, frozen.referencePath.evidence.sha256)).value;
    const { stateSha256: _initialStateSha256, ...frozenInitialCore } = frozen.initialState;
    const evidenceMatchesProjection = [initialEvidence, referenceEvidence].every((evidence) =>
      evidence.schemaVersion === 'bts-task-case-evidence-composition/v2'
      && evidence.taskId === probe.taskId && evidence.mode === probe.mode && evidence.caseId === caseId
      && evidence.executionIdentityHash === identityHash
      && canonicalTaskJson(evidence.probe) === canonicalTaskJson(source.probe)
      && canonicalTaskJson(evidence.inputProfile) === canonicalTaskJson(probe.difficultyProfile)
      && canonicalTaskJson(evidence.policyInput) === canonicalTaskJson({ path: policyPath, sha256: sha(policyBytes) })
      && canonicalTaskJson(evidence.rawReferences) === canonicalTaskJson(rawReferences)
      && canonicalTaskJson(evidence.initialState) === canonicalTaskJson(projected.initial)
      && canonicalTaskJson(evidence.finalState) === canonicalTaskJson(projected.final)
      && canonicalTaskJson(evidence.measuredExpenseAndCandidateBudget) === canonicalTaskJson(projected.expense)
      && canonicalTaskJson(evidence.projectionEvidence) === canonicalTaskJson(projected.extraEvidence ?? null)
      && canonicalTaskJson(evidence.participantActions) === canonicalTaskJson(probe.captureReferences.participantActions));
    const expectedBase = { caseId, mode: probe.mode, taskId: probe.taskId, rubricVersion: 'bts-rubric/v1',
      rubricHash: taskRubricHash(probe.taskId), taskWeight: PUBLIC_TASK_CATALOG.find((task) => task.taskId === probe.taskId).weight,
      mandatoryRules: taskMandatoryRules(probe.taskId), executionIdentityHash: identityHash,
      taskDeadlineSeconds: policy.taskDeadlineSeconds, initialState: { stateSha256: initialHash, ...projected.initial },
      initialStateEvidence: frozen.initialStateEvidence,
      referencePath: { evidence: frozen.referencePath.evidence, actionCount: probe.participantActionCount,
        initialStateSha256: initialHash, finalStateSha256: finalHash, toolSurfaceSha256: identity.toolSurfaceSha256 },
      objective: projected.objective };
    const reconstructed = TaskCaseSchema.parse({ ...expectedBase, caseHash: taskCaseHash(expectedBase) });
    const { caseHash: frozenCaseHash, ...frozenWithoutHash } = frozen;
    must(evidenceMatchesProjection && initialHash === frozen.initialState.stateSha256
      && canonicalTaskJson(projected.initial) === canonicalTaskJson(frozenInitialCore)
      && canonicalTaskJson(reconstructed) === canonicalTaskJson(frozen)
      && taskCaseHash(frozenWithoutHash) === frozenCaseHash,
    'frozen_case_projection_or_evidence_mismatch');
    projectedCaseCount++;
    for (const ref of [frozen.initialStateEvidence, frozen.referencePath.evidence]) {
      sourceInputs.push({ path: ref.path, sha256: ref.sha256 });
      evidenceFiles.set(ref.path, ref);
    }
    sourceInputs.push(source.probe);
  }
  for (const input of sourceInputs) await pinned(input.path, input.sha256, false);
  must((await sourceDigests('/workspace')).appSourceSha256 === appSource.appSourceSha256, 'application_source_changed');
  const completeInventory = cases.length === expectedCaseKeys.length;
  const preservedRankedCount = cases.filter((taskCase) => taskCase.mode === 'ranked').length;
  const preservedTrainingCount = cases.filter((taskCase) => taskCase.mode === 'training').length;
  const casesPreserved = completeInventory && projectedCaseCount === expectedCaseKeys.length
    && preservedRankedCount === TASK_IDS.length
    && preservedTrainingCount === CURRENT_TRAINING_TASK_IDS.length;
  const status = completeInventory && casesPreserved ? 'complete_inventory_candidates' : 'partial_candidates';
  const output = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-difficulty-v2-case-candidates/v1',
    classification: 'typed_case_candidates_not_validated_release', status,
    captureId, executionIdentity: identity, executionIdentityHash: identityHash,
    participantToolProtocol: 'separate_payment_delivery_v2', sourceInputs, sourceUnchanged: true,
    frozenCandidateBaseline: { path: frozenCandidatePath, sha256: frozenCandidateSha256,
      caseCount: frozenCases.length, rankedCaseCount: frozenCases.filter((taskCase) => taskCase.mode === 'ranked').length,
      trainingCaseCount: frozenCases.filter((taskCase) => taskCase.mode === 'training').length },
    projectedCandidate: { caseCount: cases.length, rankedCaseCount: cases.filter((taskCase) => taskCase.mode === 'ranked').length,
      trainingTaskIds: CURRENT_TRAINING_TASK_IDS },
    preservedFrozenCases: { rankedCaseCount: preservedRankedCount, selectedTrainingCaseCount: preservedTrainingCount,
      projectedCaseCount, allCurrentCasesDeepEqualFrozenBaseline: casesPreserved },
    feasibilityRevalidated: feasibility,
    probeBuildCohort: { policy: 'individual_capture_source_pins_with_uniform_runtime_identity',
      distinctProbeSourceSha256: [...new Set(integrity.captures.map((capture) => capture.probeSourceSha256))],
      historicalProbeSourceTreeReplay: 'not_claimed' },
    cases, evidenceFiles: [...evidenceFiles.values()], blockers: [...(completeInventory ? [] : ['current_fifteen_case_inventory_missing']),
      ...(casesPreserved ? [] : ['frozen_ranked_and_selected_training_cases_not_preserved']), 'semantic_reference_verifier_missing',
      'difficulty_review_missing', 'release_not_validated'], claims: { releaseValidated: false,
      releaseActivated: false, taskGrade: false, difficultyApproved: false } }, null, 2)}\n`);
  await writeFile(`${outputPrefix}/candidate-cases.json`, output, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(output), cases: cases.length,
    status, releaseValidated: false })}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) void main().catch((error) => {
  const code = error?.name === 'ZodError' ? 'task_case_schema_invalid'
    : error instanceof Error && /^[a-z_][a-z0-9_]{1,159}$/.test(error.message) ? error.message : 'v2_assembly_failed';
  const type = ['TypeError', 'RangeError', 'ReferenceError', 'SyntaxError', 'ZodError'].includes(error?.name) ? error.name : 'Error';
  const locations = typeof error?.stack === 'string'
    ? error.stack.match(/\/workspace\/(?:infrastructure\/owner-identity\/[^ :()]+\.mjs|packages\/[^ :()]+\.ts):[0-9]+:[0-9]+/g)?.slice(0, 3) ?? [] : [];
  process.stderr.write(`${JSON.stringify({ status: 'error', code, type, sourceLocations: locations })}\n`); process.exitCode = 2;
});
