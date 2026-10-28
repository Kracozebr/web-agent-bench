import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assembleRankedTaskCaseCandidates,
  assembleTrainingTaskCaseCandidates,
  calculateParticipantExpenseBudget,
} from './task-case-assembler.js';
import { TaskCaseSchema, taskCaseHash, type TaskCase } from './task-release.js';
import type { TaskId } from './task-catalog.js';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const runsRoot = resolve(repositoryRoot, 'artifacts/runs');
const sourceIndexRelative = 'artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249.json';
const trainingSourceIndexRelative = 'artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249-training.json';
const policyRelative = 'infrastructure/owner-identity/task-release-local-policy.json';
const outputPrefix = 'artifacts/runs/bts-task-case-candidates/test-fixture';
const trainingOutputPrefix = 'artifacts/runs/bts-task-case-candidates/test-training-fixture';
const assemblyPromise = assembleRankedTaskCaseCandidates({ repositoryRoot, evidencePathPrefix: outputPrefix });
const trainingAssemblyPromise = assembleTrainingTaskCaseCandidates({ repositoryRoot, evidencePathPrefix: trainingOutputPrefix });

function getTaskCase<T extends TaskId>(cases: readonly TaskCase[], taskId: T): Extract<TaskCase, { taskId: T }> {
  const found = cases.find((item) => item.taskId === taskId);
  assert.ok(found, `${taskId} candidate missing`);
  return found as Extract<TaskCase, { taskId: T }>;
}

function assertCanonicalCaseAssetIds(cases: readonly TaskCase[]): void {
  const usdc = (value: string, label: string) => assert.equal(value, 'USDC', label);
  for (const taskCase of cases) {
    switch (taskCase.taskId) {
      case 'S1':
      case 'S4':
        usdc(taskCase.objective.tokenAssetId, `${taskCase.taskId}.tokenAssetId`);
        break;
      case 'S2':
        usdc(taskCase.objective.completePaymentRequirements.assetId, 'S2.completePaymentRequirements.assetId');
        break;
      case 'S3':
      case 'M2':
        usdc(taskCase.objective.required.assetId, `${taskCase.taskId}.required.assetId`);
        for (const offer of taskCase.objective.catalog) {
          usdc(offer.assetId, `${taskCase.taskId}.${offer.offerId}.assetId`);
          usdc(offer.paymentRequirements.assetId, `${taskCase.taskId}.${offer.offerId}.paymentRequirements.assetId`);
        }
        break;
      case 'M1':
        usdc(taskCase.objective.paymentRequirements.assetId, 'M1.paymentRequirements.assetId');
        break;
      case 'M3':
        usdc(taskCase.objective.inputAssetId, 'M3.inputAssetId');
        for (const route of taskCase.objective.permittedRoutes) {
          usdc(route.tokenInAssetId, 'M3.route.tokenInAssetId');
          assert.equal(route.tokenOutAssetId, 'WETH', 'M3.route.tokenOutAssetId');
        }
        break;
      case 'M4':
        usdc(taskCase.objective.inputAssetId, 'M4.inputAssetId');
        assert.equal(taskCase.objective.outputAssetId, 'WETH');
        for (const route of taskCase.objective.permittedRoutes) {
          usdc(route.tokenInAssetId, 'M4.route.tokenInAssetId');
          assert.equal(route.tokenOutAssetId, 'WETH', 'M4.route.tokenOutAssetId');
        }
        for (const item of taskCase.objective.initialAllowanceScope) usdc(item.tokenAssetId, 'M4.initialAllowanceScope.tokenAssetId');
        break;
      case 'H1':
        break;
      case 'H2':
        for (const item of taskCase.objective.obligations) usdc(item.assetId, 'H2.obligation.assetId');
        for (const item of taskCase.initialState.balances.filter((balance) => balance.account !== 'participant')) {
          usdc(item.assetId, 'H2.recipientBalance.assetId');
        }
        break;
      case 'H3':
        usdc(taskCase.objective.inputAssetId, 'H3.inputAssetId');
        for (const route of taskCase.objective.permittedRoutes) {
          usdc(route.tokenInAssetId, 'H3.route.tokenInAssetId');
          assert.equal(route.tokenOutAssetId, 'WETH', 'H3.route.tokenOutAssetId');
        }
        break;
      case 'U1':
        for (const item of taskCase.objective.payoutObligations) usdc(item.assetId, 'U1.payoutObligation.assetId');
        for (const item of taskCase.objective.allocationAssets) assert.ok(['USDC', 'ETH'].includes(item.assetId));
        for (const route of taskCase.objective.permittedRoutes) {
          usdc(route.tokenInAssetId, 'U1.route.tokenInAssetId');
          assert.equal(route.tokenOutAssetId, 'WETH', 'U1.route.tokenOutAssetId');
        }
        for (const item of taskCase.objective.temporarySpenderScope) usdc(item.tokenAssetId, 'U1.temporarySpenderScope.tokenAssetId');
        break;
    }
  }
}

test('assembles all twelve pinned ranked cases as schema-valid, unactivated candidates', async () => {
  const result = await assemblyPromise;
  assert.equal(result.status, 'candidates_only', result.taskResults.map((item) => `${item.taskId}:${item.blockers.join(',')}`).join(';'));
  assert.equal(result.inventory?.status, 'verified');
  assert.equal(result.inventory?.taskCoverage.length, 12);
  assert.equal(result.cases.length, 12);
  assert.deepEqual(result.cases.map((item) => item.taskId), ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1']);
  assert.equal(result.evidenceFiles.length, 24);
  assert.equal(result.claims.taskAcceptance, false);
  assert.equal(result.claims.taskGrade, false);
  assert.equal(result.claims.validatedRelease, false);
  assert.equal(result.claims.difficultyApproval, false);
  assert.equal(result.claims.releaseActivation, false);
  assert.ok(result.blockers.includes('training_cases_not_assembled_by_this_scope'));
  assert.ok(result.blockers.includes('difficulty_approval_not_performed'));
  assert.ok(result.blockers.includes('release_activation_not_performed'));
  assertCanonicalCaseAssetIds(result.cases);

  for (const taskCase of result.cases) {
    const parsed = TaskCaseSchema.safeParse(taskCase);
    assert.equal(parsed.success, true, taskCase.taskId);
    assert.equal(taskCase.caseHash, taskCaseHash(Object.fromEntries(Object.entries(taskCase).filter(([key]) => key !== 'caseHash'))));
    assert.equal(taskCase.referencePath.evidence.path.startsWith(`${outputPrefix}/ranked/${taskCase.taskId}/`), true);
    const file = result.evidenceFiles.find((entry) => entry.path === taskCase.referencePath.evidence.path);
    assert.ok(file, `${taskCase.taskId} trace envelope missing`);
    assert.equal(createHash('sha256').update(file.content).digest('hex'), file.sha256);
    assert.equal(file.sha256, taskCase.referencePath.evidence.sha256);
    assert.equal(file.content.includes(taskCase.caseHash), false, `${taskCase.taskId} evidence envelope must not self-bind caseHash`);
  }

  const s1 = getTaskCase(result.cases, 'S1');
  const s2 = getTaskCase(result.cases, 'S2');
  const s3 = getTaskCase(result.cases, 'S3');
  const m1 = getTaskCase(result.cases, 'M1');
  const m2 = getTaskCase(result.cases, 'M2');
  const m3 = getTaskCase(result.cases, 'M3');
  const m4 = getTaskCase(result.cases, 'M4');
  const h1 = getTaskCase(result.cases, 'H1');
  const h2 = getTaskCase(result.cases, 'H2');
  const h3 = getTaskCase(result.cases, 'H3');
  const u1 = getTaskCase(result.cases, 'U1');
  assert.equal(s1.objective.nativeReserveWei, '10000000000000000');
  assert.equal(s2.referencePath.initialStateSha256, s2.referencePath.finalStateSha256);
  assert.equal(s3.referencePath.initialStateSha256, s3.referencePath.finalStateSha256);
  assert.deepEqual(s2.objective.requiredAnswerFields, [...new Set(s2.objective.requiredAnswerFields)]);
  assert.equal(m1.objective.expenseBudgetUsdcUnits, '250000');
  assert.equal(m2.objective.expenseBudgetUsdcUnits, '250000');
  assert.equal(m1.objective.duplicatePurchaseIdentity, 'one_public_purchase_operation_per_resource');
  assert.equal(m2.objective.duplicatePurchaseIdentity, 'one_public_purchase_operation_per_resource');
  assert.ok(m3.referencePath.evidence.path.includes('/M3/'));
  assert.ok(m4.referencePath.evidence.path.includes('/M4/'));
  assert.equal(h1.objective.expenseBudgetUsdcUnits, '450000');
  assert.equal(h2.objective.expenseBudgetUsdcUnits, '10000');
  assert.equal(h3.objective.combinedExpenseBudgetUsdcUnits, '260000');
  assert.equal(u1.objective.expenseBudgetUsdcUnits, '470000');
  assert.equal(u1.objective.nativeReserveWei, '9999994000000000000');
  assert.deepEqual(h3.initialState.deliveredComponentIds, []);
  assert.ok(h3.initialStateEvidence.path.includes('/H3/initial-state-evidence.json'));

  const s2Trace = JSON.parse(result.evidenceFiles.find((item) => item.path === s2.referencePath.evidence.path)!.content);
  const s3Trace = JSON.parse(result.evidenceFiles.find((item) => item.path === s3.referencePath.evidence.path)!.content);
  assert.equal(s2Trace.paidSettlementObserved, false);
  assert.equal(s3Trace.paidSettlementObserved, false);
  assert.equal(s2Trace.rawReferenceRoot, 'artifacts/runs');
  assert.ok(s2Trace.rawReferences.some((item: { path: string }) => item.path.includes('public-offer-read')));
  assert.ok(s3Trace.rawReferences.some((item: { path: string }) => item.path.includes('public-catalog-read')));
  const h3Baseline = JSON.parse(result.evidenceFiles.find((item) => item.path === h3.initialStateEvidence.path)!.content);
  assert.ok(h3Baseline.rawReferences.some((item: { path: string }) => item.path.endsWith('rpc/0007-task-h3-market-brief-payer-usdc-before.json')));
});

test('assembles the eight open training candidates from their retained training captures', async () => {
  const [result, ranked] = await Promise.all([trainingAssemblyPromise, assemblyPromise]);
  assert.equal(result.status, 'candidates_only', result.taskResults.map((item) => `${item.taskId}:${item.blockers.join(',')}`).join(';'));
  assert.equal(result.profile?.inputIndexPath, trainingSourceIndexRelative);
  assert.equal(result.inventory?.status, 'verified');
  const trainingCapture = result.inventory?.captures.find((item) => item.kind === 'training_reference');
  assert.equal(trainingCapture?.probeSha256, '7bc0c7fc24d4e09eecd0da35768355d12c838e67f9d11e2d5399ea4d61a6a1e8');
  assert.equal(trainingCapture?.rawArtifactCount, 512);
  assert.deepEqual(trainingCapture?.primitives.map((item) => item.taskId), ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']);
  assert.equal(result.cases.length, 8);
  assert.deepEqual(result.cases.map((item) => item.taskId), ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']);
  assert.equal(result.evidenceFiles.length, 16);
  assert.equal(result.taskResults.length, 8);
  assert.ok(result.taskResults.every((item) => item.status === 'assembled'));
  assert.equal(result.claims.taskAcceptance, false);
  assert.equal(result.claims.taskGrade, false);
  assert.equal(result.claims.validatedRelease, false);
  assert.equal(result.claims.difficultyApproval, false);
  assert.equal(result.claims.releaseActivation, false);
  assert.ok(result.blockers.includes('same_tool_reference_path_verification_not_run'));
  assert.ok(result.blockers.includes('release_validation_not_run'));
  assert.ok(result.blockers.includes('release_activation_not_performed'));
  assertCanonicalCaseAssetIds(result.cases);

  for (const taskCase of result.cases) {
    const parsed = TaskCaseSchema.safeParse(taskCase);
    assert.equal(parsed.success, true, taskCase.taskId);
    assert.equal(taskCase.mode, 'training');
    assert.ok(taskCase.caseId.startsWith('bts-training-'));
    assert.equal(taskCase.caseHash, taskCaseHash(Object.fromEntries(Object.entries(taskCase).filter(([key]) => key !== 'caseHash'))));
    const rankedCase = getTaskCase(ranked.cases, taskCase.taskId);
    assert.notEqual(taskCase.caseHash, rankedCase.caseHash, `${taskCase.taskId} must be assembled as a distinct training case`);
    assert.ok(taskCase.referencePath.evidence.path.startsWith(`${trainingOutputPrefix}/training/${taskCase.taskId}/`));
    const file = result.evidenceFiles.find((entry) => entry.path === taskCase.referencePath.evidence.path);
    assert.ok(file, `${taskCase.taskId} training trace envelope missing`);
    assert.equal(createHash('sha256').update(file.content).digest('hex'), file.sha256);
    assert.equal(file.sha256, taskCase.referencePath.evidence.sha256);
    const envelope = JSON.parse(file.content);
    assert.equal(envelope.mode, 'training');
    assert.equal(envelope.trainingCaptureInput.probeSha256, trainingCapture?.probeSha256);
    assert.equal(envelope.trainingCaptureInput.relativeDirectory, trainingCapture?.relativeDirectory);
    assert.ok(envelope.rawReferences.length > 0);
    assert.ok(envelope.rawReferences.every((item: { path: string }) => item.path.startsWith('bts-open-training-reference-profile/10fff3fa-2aa4-474b-a084-240e31e2b879/')));
  }

  const s1 = getTaskCase(result.cases, 'S1');
  const s2 = getTaskCase(result.cases, 'S2');
  const s4 = getTaskCase(result.cases, 'S4');
  const m1 = getTaskCase(result.cases, 'M1');
  const m3 = getTaskCase(result.cases, 'M3');
  const m4 = getTaskCase(result.cases, 'M4');
  const h1 = getTaskCase(result.cases, 'H1');
  const h2 = getTaskCase(result.cases, 'H2');
  assert.equal(s1.objective.exactPrincipalUnits, '200000');
  assert.equal(s2.objective.completePaymentRequirements.amountUnits, '125000');
  assert.equal(new Set(s2.objective.requiredAnswerFields).size, s2.objective.requiredAnswerFields.length);
  assert.equal(s4.objective.initialAllowanceUnits, '20000');
  assert.equal(m1.objective.paymentRequirements.amountUnits, '100000');
  assert.equal(m3.objective.exactInputUnits, '200000');
  assert.equal(m3.objective.minimumNativeOutputWei, '74902635102393');
  assert.equal(m4.objective.exactInputUnits, '200000');
  assert.equal(m4.objective.initialAllowanceScope[0]?.amountUnits, '0');
  assert.equal(h1.objective.requiredComponents.length, 2);
  assert.equal(h1.objective.expenseBudgetUsdcUnits, '700000');
  assert.deepEqual(h2.objective.obligations.map((item) => item.exactAmountUnits), ['200000', '300000']);
  assert.equal(h2.objective.expenseBudgetUsdcUnits, '10000');
});

test('blocks training candidate assembly when the retained training probe pin changes', async () => {
  const tempName = `.case-assembler-training-tampered-index-${randomUUID()}.json`;
  const tempPath = resolve(runsRoot, tempName);
  try {
    const sourceIndex = JSON.parse(await readFile(resolve(repositoryRoot, trainingSourceIndexRelative), 'utf8')) as Array<Record<string, unknown>>;
    const trainingSource = sourceIndex.find((item) => item.kind === 'training_reference');
    assert.ok(trainingSource);
    trainingSource.expectedProbeSha256 = '0'.repeat(64);
    await writeFile(tempPath, JSON.stringify(sourceIndex), { flag: 'wx' });
    const result = await assembleTrainingTaskCaseCandidates({
      repositoryRoot,
      sourceIndexPath: `artifacts/runs/${tempName}`,
      evidencePathPrefix: `${trainingOutputPrefix}/tampered`,
    });
    assert.equal(result.status, 'blocked');
    assert.equal(result.cases.length, 0);
    assert.ok(result.blockers.some((item) => item.includes('capture_inventory_not_fully_verified')));
  } finally {
    await rm(tempPath, { force: true });
  }
});

test('blocks when a source-index probe pin is changed', async () => {
  const tempPath = `.case-assembler-tampered-index-${randomUUID()}.json`;
  const absolute = resolve(runsRoot, tempPath);
  try {
    const sourceIndex = JSON.parse(await readFile(resolve(repositoryRoot, sourceIndexRelative), 'utf8')) as Array<Record<string, unknown>>;
    sourceIndex[0] = { ...sourceIndex[0], expectedProbeSha256: '0'.repeat(64) };
    await writeFile(absolute, JSON.stringify(sourceIndex), { flag: 'wx' });
    const result = await assembleRankedTaskCaseCandidates({
      repositoryRoot,
      sourceIndexPath: `artifacts/runs/${tempPath}`,
      evidencePathPrefix: `${outputPrefix}/tampered`,
    });
    assert.equal(result.status, 'blocked');
    assert.equal(result.cases.length, 0);
    assert.ok(result.blockers.some((item) => item.includes('capture_inventory_not_fully_verified')));
  } finally {
    await rm(absolute, { force: true });
  }
});

test('binds raw policy bytes into case reference envelopes and case hashes', async () => {
  const tempName = `.case-assembler-policy-${randomUUID()}.json`;
  const tempPath = resolve(runsRoot, tempName);
  try {
    await mkdir(runsRoot, { recursive: true });
    const original = await readFile(resolve(repositoryRoot, policyRelative));
    await writeFile(tempPath, Buffer.concat([original, Buffer.from('\n')]), { flag: 'wx' });
    const result = await assembleRankedTaskCaseCandidates({
      repositoryRoot,
      localPolicyPath: `artifacts/runs/${tempName}`,
      evidencePathPrefix: `${outputPrefix}/policy-byte-binding`,
    });
    const baseline = await assemblyPromise;
    assert.equal(result.status, 'candidates_only');
    assert.notEqual(result.profile?.policySha256, baseline.profile?.policySha256);
    assert.notEqual(result.cases[0]?.caseHash, baseline.cases[0]?.caseHash);
    const envelope = JSON.parse(result.evidenceFiles.find((item) => item.path === result.cases[0]?.referencePath.evidence.path)!.content);
    assert.equal(envelope.policyInput.sha256, result.profile?.policySha256);
  } finally {
    await rm(tempPath, { force: true });
  }
});

test('floors aggregate participant gas once, adds DEX fee, then applies headroom and rounding once', () => {
  const result = calculateParticipantExpenseBudget({
    serviceChargesUsdcUnits: '225000',
    participantGasWei: '2',
    ethUsdcRateNumerator: '1',
    ethUsdcRateDenominator: '2',
    verifiedDexFeeUsdcUnits: '4500',
    headroomMultiplierNumerator: '2',
    headroomMultiplierDenominator: '1',
    roundUpToUsdcUnits: '10000',
  });
  assert.deepEqual(result, { measuredExpenseUsdcUnits: '229501', gasUsdcUnits: '1', budgetUsdcUnits: '460000' });
});

