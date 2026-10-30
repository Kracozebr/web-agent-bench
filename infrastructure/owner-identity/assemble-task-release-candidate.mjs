// Offline composition only. Missing reference/difficulty verification blocks activation.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { TaskCaseSchema, TaskReleaseManifestSchema, sha256CanonicalTaskJson,
  taskBenchmarkHash, taskCaseHash, taskPolicyHash, validateTaskReleaseCandidate } from '../../packages/owner-identity/src/task-release.ts';
import { CURRENT_TRAINING_TASK_IDS, TASK_IDS } from '../../packages/owner-identity/src/task-catalog.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';

if (process.platform !== 'linux' || process.cwd() !== '/workspace' || process.argv.length !== 4) {
  throw new Error('Run in owner Docker runtime with ranked and training candidate-cases.json paths');
}
const root = '/workspace';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
const manifestPath = 'infrastructure/benchmark-environment/manifest.json';
const witnessPath = 'artifacts/runs/bts-release-feasibility-witness/9a306c79-614b-4027-9129-33f68ffa3a75/witness.json';
const [rankedPath, trainingPath] = process.argv.slice(2);
for (const path of [rankedPath, trainingPath]) {
  if (!/^artifacts\/runs\/bts-task-case-candidates\/[0-9a-f-]{36}\/candidate-cases\.json$/.test(path)) {
    throw new Error('Candidate path must name a retained case-candidate capture');
  }
}
async function bytesAt(path) {
  if (typeof path !== 'string' || isAbsolute(path) || path.includes('\\') || path.includes(':') ||
      path.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error('Invalid input path');
  const absolute = await realpath(resolve(root, path));
  const rel = relative(root, absolute);
  if (!rel || isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('Input escapes workspace');
  return readFile(absolute);
}
const sources = [rankedPath, trainingPath, policyPath, manifestPath, witnessPath, 'pnpm-lock.yaml',
  'infrastructure/owner-identity/assemble-task-release-candidate.mjs',
  ...['task-release', 'task-catalog', 'task-feasibility-evidence'].map((name) => `packages/owner-identity/src/${name}.ts`)];
const snapshot = async () => Promise.all(sources.toSorted().map(async (path) => ({ path, sha256: hash(await bytesAt(path)) })));
const before = await snapshot();
const policyBytes = await bytesAt(policyPath);
const policy = JSON.parse(policyBytes);
const befManifestBytes = await bytesAt(manifestPath);
const bef = JSON.parse(befManifestBytes);
const ranked = JSON.parse(await bytesAt(rankedPath));
const training = JSON.parse(await bytesAt(trainingPath));
if (ranked.schemaVersion !== 'bts-offline-ranked-case-candidate-capture/v1' ||
    training.schemaVersion !== 'bts-offline-training-case-candidate-capture/v1' ||
    !ranked.sourceUnchanged || !training.sourceUnchanged ||
    ranked.assembly.status !== 'candidates_only' || training.assembly.status !== 'candidates_only') {
  throw new Error('Both inputs must be complete source-stable candidate captures');
}
const a = ranked.assembly, b = training.assembly;
if (!Array.isArray(a.cases) || !Array.isArray(b.cases)) throw new Error('current_fifteen_case_inputs_required');
const expectedRankedKeys = TASK_IDS.map((taskId) => `${taskId}:ranked`).sort();
const expectedTrainingKeys = CURRENT_TRAINING_TASK_IDS.map((taskId) => `${taskId}:training`).sort();
const rankedKeys = a.cases.map((taskCase) => `${taskCase.taskId}:${taskCase.mode}`).sort();
const trainingKeys = b.cases.map((taskCase) => `${taskCase.taskId}:${taskCase.mode}`).sort();
if (rankedKeys.length !== expectedRankedKeys.length || new Set(rankedKeys).size !== expectedRankedKeys.length
    || rankedKeys.some((key, index) => key !== expectedRankedKeys[index])
    || trainingKeys.length !== expectedTrainingKeys.length || new Set(trainingKeys).size !== expectedTrainingKeys.length
    || trainingKeys.some((key, index) => key !== expectedTrainingKeys[index])) {
  throw new Error('current_fifteen_case_inputs_required');
}
if (a.executionIdentityHash !== b.executionIdentityHash ||
    sha256CanonicalTaskJson(a.executionIdentity) !== a.executionIdentityHash ||
    sha256CanonicalTaskJson(b.executionIdentity) !== b.executionIdentityHash ||
    a.profile.policySha256 !== hash(policyBytes) || b.profile.policySha256 !== hash(policyBytes) ||
    a.executionIdentity.environmentManifestSha256 !== hash(befManifestBytes)) {
  throw new Error('Candidate identity, policy or BEF manifest disagreement');
}
const envelopePins = new Map();
for (const assembly of [a, b]) {
  for (const raw of assembly.cases) {
    const taskCase = TaskCaseSchema.parse(raw);
    const { caseHash, ...unhashed } = taskCase;
    if (taskCaseHash(unhashed) !== caseHash) throw new Error('Candidate case hash mismatch');
    for (const evidence of [taskCase.initialStateEvidence, taskCase.referencePath.evidence]) {
      if (hash(await bytesAt(evidence.path)) !== evidence.sha256) throw new Error('Case evidence hash mismatch');
      if (envelopePins.has(evidence.path) && envelopePins.get(evidence.path) !== evidence.sha256) {
        throw new Error('Conflicting evidence pins');
      }
      envelopePins.set(evidence.path, evidence.sha256);
      sources.push(evidence.path);
    }
  }
}
// Include evidence envelopes in the before/after guard after their initial reads.
const envelopeBefore = await snapshot();
if (envelopeBefore.some((row) => envelopePins.has(row.path) && envelopePins.get(row.path) !== row.sha256)) {
  throw new Error('Case evidence changed before composition');
}
const captureId = randomUUID();
const outputPrefix = `artifacts/runs/bts-task-release-candidates/${captureId}`;
const review = {
  schemaVersion: 'bts-difficulty-readiness-review/v1', decision: 'review_required',
  executionIdentityHash: a.executionIdentityHash,
  boundary: 'retained_reference_action_counts_not_complete_task_acceptance',
  acceptedProvisionalBands: { simple: [1, 2], medium: [3, 5], hard: [6, 9], ultra: [10, null] },
  granularityStatus: 'declared_reference_counts_require_reconciliation_with_necessary_public_actions',
  casePins: [...b.cases, ...a.cases].map((taskCase) => ({ taskId: taskCase.taskId, mode: taskCase.mode,
    caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, declaredReferenceActionCount: taskCase.referencePath.actionCount })),
  findings: ['Reference action granularity and provisional difficulty require review before release validation.',
    'Do not add meaningless calls or silently change goals, levels or weights.'],
  difficultyApproval: false, releaseActivation: false,
};
const reviewBytes = Buffer.from(`${JSON.stringify(review, null, 2)}\n`);
const manifest = {
  schemaVersion: 'bts-task-release/v1', releaseIdentity: `${policy.profileId}-current-${captureId}`, benchmarkVersion: 'bts-local-v1',
  manifestHash: '0'.repeat(64), benchmarkHash: '0'.repeat(64), policyHash: '0'.repeat(64),
  inventory: { orderedTaskIds: [...TASK_IDS],
    rankedWeightSum: 26, openTrainingTaskIds: [...CURRENT_TRAINING_TASK_IDS],
    openTrainingWeightSum: 6, closedRankedOnlyTaskIds: TASK_IDS.filter((taskId) => !CURRENT_TRAINING_TASK_IDS.includes(taskId)) },
  pricing: { precision: 6, openTrainingPriceUnits: '500000', rankedPriceUnits: '1000000', trainingRounding: 'ceil_once_per_request' },
  deadlines: { taskTimeoutSeconds: policy.taskDeadlineSeconds, trainingRunTimeoutSeconds: policy.trainingRunTimeoutSeconds,
    rankedRunTimeoutSeconds: policy.rankedRunTimeoutSeconds },
  executionIdentity: a.executionIdentity, executionIdentityHash: a.executionIdentityHash,
  ...(bef.tools.participantProtocol === undefined ? {} : { participantToolProtocol: bef.tools.participantProtocol }),
  costPolicy: { policyVersion: policy.profileId, usdcAssetId: 'USDC', usdcPrecision: 6,
    ethValuation: { numerator: bef.feePolicy.ethUsdcRateNumerator, denominator: bef.feePolicy.ethUsdcRateDenominator },
    expenseComponents: ['paid_service_charge', 'participant_gas_success_or_revert', 'verified_dex_fee'],
    rounding: 'floor_to_usdc_base_units', principalSeparateFromExpense: true, ethAndWethDistinct: true, missingFeeEvidence: 'unknown' },
  feasibilityEvidence: { path: witnessPath, sha256: '39c7340d7e438c6da232dcb39e6130ee56d4de0ae3507d533851f2844e148ded',
    boundary: 'actual_tool_http_x402_local_evm_application_store' },
  difficultyReviewEvidence: { path: `${outputPrefix}/difficulty-readiness.json`, sha256: hash(reviewBytes),
    boundary: 'actual_tool_http_x402_local_evm_application_store' },
  cases: { training: b.cases, ranked: a.cases },
};
manifest.policyHash = taskPolicyHash(manifest);
manifest.benchmarkHash = taskBenchmarkHash(manifest);
const { manifestHash: omitted, ...unhashedManifest } = manifest;
manifest.manifestHash = sha256CanonicalTaskJson(unhashedManifest);
TaskReleaseManifestSchema.parse(manifest);
const validation = await validateTaskReleaseCandidate(manifest, {
  verifyFeasibility: (evidence, executionIdentity, expectedIdentityHash, participantToolProtocol) => verifyRetainedTaskFeasibility({
    repositoryRoot: root, evidence, executionIdentity, expectedIdentityHash,
    participantToolProtocol,
    profilePolicy: { path: policyPath, sha256: hash(policyBytes) } }),
  verifyReferencePath: async () => ({ status: 'unavailable', reason: 'Independent same-tool reference verifier is not connected' }),
  verifyDifficultyReview: async () => ({ status: 'unavailable', reason: 'Concrete difficulty has not been approved' }),
});
if (validation.status !== 'blocked') throw new Error('Offline composition must never validate or activate a release');
const after = await snapshot();
if (JSON.stringify(before) !== JSON.stringify(after.filter((row) => before.some((input) => input.path === row.path))) ||
    JSON.stringify(envelopeBefore) !== JSON.stringify(after)) throw new Error('Release composition inputs changed');
await mkdir(resolve(root, outputPrefix), { recursive: true });
await writeFile(resolve(root, outputPrefix, 'difficulty-readiness.json'), reviewBytes, { flag: 'wx' });
const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-task-release-candidate-capture/v1', captureId,
  sourceUnchanged: true, sourceInputs: after, manifest, validation,
  remainingGates: ['same_tool_reference_verification', 'difficulty_review', 'mandatory_bdd_acceptance', 'actual_executor_integration'],
  claims: { validatedRelease: false, releaseActivation: false, taskGrade: false } }, null, 2)}\n`);
await writeFile(resolve(root, outputPrefix, 'candidate-release.json'), bytes, { flag: 'wx' });
process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: hash(bytes), caseCount: a.cases.length + b.cases.length,
  manifestHash: manifest.manifestHash, validation })}\n`);
process.exitCode = 2;
