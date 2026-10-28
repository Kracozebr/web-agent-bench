// Offline full-inventory composition. Verification gates remain fail closed.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { TaskReleaseManifestSchema, TaskCaseSchema, sha256CanonicalTaskJson,
  taskPolicyHash, taskBenchmarkHash, validateTaskReleaseCandidate } from '../../packages/owner-identity/src/task-release.ts';
import { TASK_IDS, PUBLIC_TASK_CATALOG } from '../../packages/owner-identity/src/task-catalog.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const boundary = 'actual_tool_http_x402_local_evm_application_store';
function must(condition, code) { if (!condition) throw new Error(code); }
function pathValid(path) {
  return typeof path === 'string' && path.length <= 512 && !path.includes('\\') && !path.includes(':')
    && path.split('/').every((part) => part && part !== '.' && part !== '..');
}
async function pinned(path, expected, parse = true) {
  must(pathValid(path) && /^[0-9a-f]{64}$/.test(expected), 'input_reference_invalid');
  const bytes = await readFile(resolve('/workspace', path));
  must(bytes.length <= 16 * 1024 * 1024 && sha(bytes) === expected, 'input_hash_mismatch');
  return { bytes, value: parse ? JSON.parse(bytes.toString('utf8')) : null };
}
async function main() {
  must(process.platform === 'linux' && process.cwd() === '/workspace', 'docker_required');
  const args = process.argv.slice(2);
  must(args.length === 4 && args[0] === '--cases' && args[2] === '--sha256', 'usage');
  const input = await pinned(args[1], args[3]), candidate = input.value;
  must(candidate.schemaVersion === 'bts-difficulty-v2-case-candidates/v1'
    && ['typed_partial_case_candidates_not_validated_release', 'typed_case_candidates_not_validated_release'].includes(candidate.classification)
    && candidate.sourceUnchanged === true && candidate.claims.releaseValidated === false
    && candidate.claims.releaseActivated === false && candidate.cases.length === 20, 'complete_candidate_inventory_required');
  const cases = candidate.cases.map((value) => TaskCaseSchema.parse(value));
  const openIds = PUBLIC_TASK_CATALOG.filter((task) => task.trainingAvailable).map((task) => task.taskId);
  const collect = (mode, ids) => ids.map((taskId) => {
    const matches = cases.filter((taskCase) => taskCase.taskId === taskId && taskCase.mode === mode);
    must(matches.length === 1, 'mode_inventory_mismatch'); return matches[0];
  });
  const training = collect('training', openIds), ranked = collect('ranked', TASK_IDS);
  const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
  const policyBytes = await readFile(policyPath), policy = JSON.parse(policyBytes);
  const manifestBytes = await readFile('infrastructure/benchmark-environment/manifest.json');
  const bef = JSON.parse(manifestBytes);
  must(sha(manifestBytes) === candidate.executionIdentity.environmentManifestSha256
    && sha256CanonicalTaskJson(candidate.executionIdentity) === candidate.executionIdentityHash
    && bef.tools.participantProtocol === candidate.participantToolProtocol, 'runtime_identity_mismatch');
  const witnessPath = 'artifacts/runs/bts-release-feasibility-witness/fd4a1f22-91dc-4718-969b-b41fdec8e2ec/witness.json';
  const witnessSha256 = 'ba193786e1f8efaddb4d8e7e30cafdca09c9ab48ea70d93bab649b4b6ca87a12';
  await pinned(witnessPath, witnessSha256);
  const sourceInputs = [{ path: args[1], sha256: args[3] }, { path: policyPath, sha256: sha(policyBytes) },
    { path: 'infrastructure/benchmark-environment/manifest.json', sha256: sha(manifestBytes) },
    { path: witnessPath, sha256: witnessSha256 }, ...candidate.evidenceFiles,
    ...candidate.sourceInputs];
  for (const path of ['infrastructure/owner-identity/assemble-difficulty-v2-release.mjs',
    'packages/owner-identity/src/task-release.ts', 'packages/owner-identity/src/task-catalog.ts',
    'packages/owner-identity/src/task-feasibility-evidence.ts']) sourceInputs.push({ path, sha256: sha(await readFile(path)) });
  for (const ref of sourceInputs) await pinned(ref.path, ref.sha256, false);
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-difficulty-v2-release-candidates/${captureId}`;
  const bands = { simple: [1, 2], medium: [3, 5], hard: [6, 9], ultra: [10, null] };
  const reviewCases = [...training, ...ranked].map((taskCase) => {
    const metadata = PUBLIC_TASK_CATALOG.find((task) => task.taskId === taskCase.taskId);
    const [minimum, maximum] = bands[metadata.level], count = taskCase.referencePath.actionCount;
    return { taskId: taskCase.taskId, mode: taskCase.mode, caseHash: taskCase.caseHash,
      weight: metadata.weight, level: metadata.level, declaredReferenceActionCount: count,
      inBand: count >= minimum && (maximum === null || count <= maximum),
      referenceEvidence: taskCase.referencePath.evidence };
  });
  const review = { schemaVersion: 'bts-difficulty-readiness-review/v2',
    decision: 'compatible_counts_require_independent_minimum_action_and_solvability_review',
    executionIdentityHash: candidate.executionIdentityHash, acceptedBands: bands,
    allDeclaredCountsInBand: reviewCases.every((task) => task.inBand), cases: reviewCases,
    difficultyApproval: false, releaseActivation: false };
  const reviewBytes = Buffer.from(`${JSON.stringify(review, null, 2)}\n`);
  const manifest = {
    schemaVersion: 'bts-task-release/v1', releaseIdentity: `${policy.profileId}-difficulty-v2-candidate`, benchmarkVersion: 'bts-local-v2',
    manifestHash: '0'.repeat(64), benchmarkHash: '0'.repeat(64), policyHash: '0'.repeat(64),
    inventory: { orderedTaskIds: [...TASK_IDS], rankedWeightSum: 26, openTrainingTaskIds: openIds,
      openTrainingWeightSum: 15, closedRankedOnlyTaskIds: PUBLIC_TASK_CATALOG.filter((task) => !task.trainingAvailable).map((task) => task.taskId) },
    // Existing local candidate pricing; unrelated to task operating expense budgets.
    pricing: { precision: 6, openTrainingPriceUnits: '500000', rankedPriceUnits: '1000000', trainingRounding: 'ceil_once_per_request' },
    deadlines: { taskTimeoutSeconds: policy.taskDeadlineSeconds, trainingRunTimeoutSeconds: policy.trainingRunTimeoutSeconds,
      rankedRunTimeoutSeconds: policy.rankedRunTimeoutSeconds },
    executionIdentity: candidate.executionIdentity, executionIdentityHash: candidate.executionIdentityHash,
    participantToolProtocol: candidate.participantToolProtocol,
    costPolicy: { policyVersion: policy.profileId, usdcAssetId: 'USDC', usdcPrecision: 6,
      ethValuation: { numerator: bef.feePolicy.ethUsdcRateNumerator, denominator: bef.feePolicy.ethUsdcRateDenominator },
      expenseComponents: ['paid_service_charge', 'participant_gas_success_or_revert', 'verified_dex_fee'],
      rounding: 'floor_to_usdc_base_units', principalSeparateFromExpense: true, ethAndWethDistinct: true, missingFeeEvidence: 'unknown' },
    feasibilityEvidence: { path: witnessPath, sha256: witnessSha256, boundary },
    difficultyReviewEvidence: { path: `${outputPrefix}/difficulty-readiness.json`, sha256: sha(reviewBytes), boundary },
    cases: { training, ranked },
  };
  manifest.policyHash = taskPolicyHash(manifest); manifest.benchmarkHash = taskBenchmarkHash(manifest);
  const { manifestHash: _omitted, ...unhashed } = manifest;
  manifest.manifestHash = sha256CanonicalTaskJson(unhashed);
  TaskReleaseManifestSchema.parse(manifest);
  const validation = await validateTaskReleaseCandidate(manifest, {
    verifyFeasibility: (evidence, executionIdentity, expectedIdentityHash, participantToolProtocol) =>
      verifyRetainedTaskFeasibility({ repositoryRoot: '/workspace', evidence, executionIdentity, expectedIdentityHash,
        participantToolProtocol, profilePolicy: { path: policyPath, sha256: sha(policyBytes) } }),
    verifyReferencePath: async () => ({ status: 'unavailable', reason: 'Independent raw semantic reference verifier is not connected' }),
    verifyDifficultyReview: async () => ({ status: 'unavailable', reason: 'Minimum necessary public actions and solvability require independent review' }),
  });
  must(validation.status === 'blocked', 'offline_composition_cannot_validate_release');
  for (const ref of sourceInputs) await pinned(ref.path, ref.sha256, false);
  await mkdir(outputPrefix, { recursive: true });
  await writeFile(`${outputPrefix}/difficulty-readiness.json`, reviewBytes, { flag: 'wx' });
  const output = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-task-release-candidate-capture/v2', captureId,
    classification: 'full_inventory_candidate_not_validated_or_activated_release', sourceUnchanged: true, sourceInputs,
    manifest, validation, review: { allDeclaredCountsInBand: review.allDeclaredCountsInBand, difficultyApproval: false },
    remainingGates: ['semantic_reference_verification', 'minimum_action_difficulty_review', 'mandatory_bdd_acceptance', 'actual_executor_integration'],
    claims: { validatedRelease: false, releaseActivation: false, taskGrade: false } }, null, 2)}\n`);
  await writeFile(`${outputPrefix}/candidate-release.json`, output, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(output), cases: cases.length,
    manifestHash: manifest.manifestHash, allDeclaredCountsInBand: review.allDeclaredCountsInBand, validation })}\n`);
  process.exitCode = 2;
}
void main().catch((error) => { const code = error?.name === 'ZodError' ? 'release_schema_invalid'
  : error instanceof Error && /^[a-z_][a-z0-9_]{1,159}$/.test(error.message) ? error.message : 'v2_release_composition_failed';
  process.stderr.write(`status=error code=${code}\n`); process.exitCode = 2; });
