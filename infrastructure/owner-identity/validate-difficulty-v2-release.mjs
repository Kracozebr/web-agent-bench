// Offline release-candidate validation only. Never activates, grades, or writes a registry.
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { CURRENT_TRAINING_TASK_IDS, TASK_IDS } from '../../packages/owner-identity/src/task-catalog.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';
import { verifyDifficultyEvidenceV2 } from '../../packages/owner-identity/src/task-difficulty-evidence-v2.ts';
import { verifyTaskReferenceEvidenceV2 } from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';
import { TaskCaseSchema, TaskReleaseManifestSchema, canonicalTaskJson, sha256CanonicalTaskJson,
  taskBenchmarkHash, taskPolicyHash, validateTaskReleaseCandidate } from '../../packages/owner-identity/src/task-release.ts';
import { CURRENT_TASK_RELEASE_INPUTS_PATH, loadCurrentTaskReleaseInputPins }
  from './current-task-release-pins.mjs';

const root = '/workspace';
const POLICY_PATH = 'infrastructure/owner-identity/task-release-local-policy.json';
const FROZEN_CANDIDATE = { path: 'artifacts/runs/bts-difficulty-v2-case-candidates/00f47005-8951-4003-b6b3-4540172e15d9/candidate-cases.json',
  sha256: '7ddc9b1181041933aad76c056ffa3288a65265e3d9e6725381343412ce05e82b' };
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const HASH = /^[0-9a-f]{64}$/;
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const demand = (condition, code) => { if (!condition) throw new Error(code); };
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

function validRelative(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 512 && path.trim() === path
    && !isAbsolute(path) && !path.includes('\\') && !path.includes(':')
    && path.split('/').every((part) => part && part !== '.' && part !== '..');
}

async function safeBytes(path, expectedHash = null, maxBytes = 8 * 1024 * 1024) {
  demand(validRelative(path) && (expectedHash === null || HASH.test(expectedHash)), 'source_path_or_hash_invalid');
  const actualRoot = await realpath(root), actualPath = await realpath(resolve(actualRoot, path));
  const rel = relative(actualRoot, actualPath);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'source_path_escape');
  const handle = await open(actualPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= maxBytes, 'source_file_invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    demand(offset === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs, 'source_file_changed_during_read');
    const content = bytes.subarray(0, offset), actualHash = sha(content);
    demand(expectedHash === null || actualHash === expectedHash, 'source_hash_mismatch');
    return { bytes: content, sha256: actualHash };
  } finally { await handle.close(); }
}

function readPinRows(value, code) {
  demand(Array.isArray(value) && value.length > 0 && value.length <= 4096, code);
  const rows = new Map();
  for (const row of value) {
    demand(row && validRelative(row.path) && HASH.test(String(row.sha256)), code);
    const previous = rows.get(row.path);
    demand(previous === undefined || previous === row.sha256, 'source_pin_conflict');
    rows.set(row.path, row.sha256);
  }
  return [...rows.entries()].map(([path, sha256]) => ({ path, sha256 })).sort((a, b) => compare(a.path, b.path));
}

async function snapshot(paths) {
  const sorted = [...new Set(paths)].sort(compare);
  return Promise.all(sorted.map(async (path) => ({ path, sha256: (await safeBytes(path)).sha256 })));
}

function currentCaseKeys() {
  return [...TASK_IDS.map((taskId) => `${taskId}:ranked`),
    ...CURRENT_TRAINING_TASK_IDS.map((taskId) => `${taskId}:training`)].sort(compare);
}

function caseInventory(candidateCases, manifest, frozenCandidate) {
  demand(candidateCases.schemaVersion === 'bts-difficulty-v2-case-candidates/v1'
    && candidateCases.participantToolProtocol === 'separate_payment_delivery_v2'
    && Array.isArray(candidateCases.cases), 'case_candidate_contract_invalid');
  const parsedCases = candidateCases.cases.map((value) => TaskCaseSchema.parse(value));
  const keys = parsedCases.map((taskCase) => `${taskCase.taskId}:${taskCase.mode}`);
  const expectedKeys = currentCaseKeys();
  demand(keys.length === expectedKeys.length && new Set(keys).size === expectedKeys.length,
    'current_fifteen_case_inventory_invalid');
  demand(canonicalTaskJson([...keys].sort(compare)) === canonicalTaskJson(expectedKeys), 'case_candidate_inventory_mismatch');
  const frozenByKey = new Map(frozenCandidate.cases.map((taskCase) => [`${taskCase.taskId}:${taskCase.mode}`, taskCase]));
  demand(candidateCases.frozenCandidateBaseline?.path === FROZEN_CANDIDATE.path
    && candidateCases.frozenCandidateBaseline?.sha256 === FROZEN_CANDIDATE.sha256
    && candidateCases.frozenCandidateBaseline?.caseCount === frozenCandidate.cases.length
    && candidateCases.frozenCandidateBaseline?.rankedCaseCount === frozenCandidate.cases.filter((taskCase) => taskCase.mode === 'ranked').length
    && candidateCases.frozenCandidateBaseline?.trainingCaseCount === frozenCandidate.cases.filter((taskCase) => taskCase.mode === 'training').length
    && candidateCases.preservedFrozenCases?.allCurrentCasesDeepEqualFrozenBaseline === true,
  'frozen_candidate_preservation_claim_missing');
  demand(parsedCases.every((taskCase) => {
    const frozen = frozenByKey.get(`${taskCase.taskId}:${taskCase.mode}`);
    return frozen !== undefined && canonicalTaskJson(taskCase) === canonicalTaskJson(frozen);
  }), 'current_cases_differ_from_frozen_baseline');
  const candidateSourcePins = readPinRows(candidateCases.sourceInputs, 'case_candidate_source_inventory_invalid');
  demand(candidateSourcePins.some((row) => row.path === FROZEN_CANDIDATE.path && row.sha256 === FROZEN_CANDIDATE.sha256),
    'frozen_candidate_source_pin_missing');
  const manifestCases = [...manifest.cases.training, ...manifest.cases.ranked];
  const keyOf = (taskCase) => `${taskCase.taskId}:${taskCase.mode}`;
  const byKey = new Map(parsedCases.map((taskCase) => [keyOf(taskCase), taskCase]));
  demand(byKey.size === expectedKeys.length && manifestCases.length === expectedKeys.length && manifestCases.every((taskCase) => {
    const candidate = byKey.get(keyOf(taskCase));
    return candidate && canonicalTaskJson(candidate) === canonicalTaskJson(taskCase);
  }), 'release_case_set_differs_from_pinned_case_candidate');
  return parsedCases;
}

function referenceArtifactIndex(document, casesPin) {
  demand(document.schemaVersion === 'bts-v2-reference-verification/v1'
    && document.status === 'verified_references' && document.contextOnly === false
    && document.candidate?.path === casesPin.path && document.candidate?.sha256 === casesPin.sha256
    && HASH.test(String(document.executionIdentityHash)) && Array.isArray(document.results)
    && document.results.length === currentCaseKeys().length, 'semantic_reference_artifact_contract_invalid');
  const index = new Map();
  for (const row of document.results) {
    const key = `${row.taskId}:${row.mode}`;
    demand(!index.has(key) && HASH.test(String(row.caseHash)) && row.result?.status === 'verified'
      && row.result.caseHash === row.caseHash && row.result.executionIdentityHash === document.executionIdentityHash
      && row.result.actualBoundary === true && row.result.solvable === true && row.result.initiallySolved === false,
    'semantic_reference_artifact_result_invalid');
    index.set(key, row);
  }
  demand(index.size === currentCaseKeys().length, 'semantic_reference_artifact_inventory_invalid');
  return index;
}

function bindMinimumReview(manifest, minimumEvidence) {
  const bound = structuredClone(manifest);
  bound.difficultyReviewEvidence = { ...minimumEvidence, boundary: BOUNDARY };
  bound.policyHash = taskPolicyHash(bound);
  bound.benchmarkHash = taskBenchmarkHash(bound);
  const { manifestHash: _previousHash, ...unhashed } = bound;
  bound.manifestHash = sha256CanonicalTaskJson(unhashed);
  return TaskReleaseManifestSchema.parse(bound);
}

async function main() {
  demand(process.platform === 'linux' && process.cwd() === root && process.argv.length === 2, 'usage');
  const pins = await loadCurrentTaskReleaseInputPins(root);
  const { cases: CASES, release: RELEASE, minimum: MINIMA, references: REFERENCES } = pins;
  const caseBytes = (await safeBytes(CASES.path, CASES.sha256)).bytes;
  const frozenCaseBytes = (await safeBytes(FROZEN_CANDIDATE.path, FROZEN_CANDIDATE.sha256)).bytes;
  const releaseBytes = (await safeBytes(RELEASE.path, RELEASE.sha256)).bytes;
  const minimumBytes = (await safeBytes(MINIMA.path, MINIMA.sha256)).bytes;
  const referenceBytes = (await safeBytes(REFERENCES.path, REFERENCES.sha256)).bytes;
  const casesCandidate = JSON.parse(caseBytes.toString('utf8'));
  const frozenCaseCandidate = JSON.parse(frozenCaseBytes.toString('utf8'));
  const capturedCandidate = JSON.parse(releaseBytes.toString('utf8'));
  const minimumReview = JSON.parse(minimumBytes.toString('utf8'));
  const referenceReview = JSON.parse(referenceBytes.toString('utf8'));
  demand(frozenCaseCandidate.schemaVersion === 'bts-difficulty-v2-case-candidates/v1'
    && frozenCaseCandidate.captureId === FROZEN_CANDIDATE.path.split('/')[3]
    && Array.isArray(frozenCaseCandidate.cases) && frozenCaseCandidate.cases.length === 20,
  'frozen_candidate_baseline_invalid');
  frozenCaseCandidate.cases = frozenCaseCandidate.cases.map((value) => TaskCaseSchema.parse(value));
  demand(capturedCandidate.schemaVersion === 'bts-task-release-candidate-capture/v2'
    && capturedCandidate.captureId === RELEASE.path.split('/')[3]
    && capturedCandidate.classification === 'full_inventory_candidate_not_validated_or_activated_release',
  'release_candidate_capture_contract_invalid');
  demand(casesCandidate.captureId === CASES.path.split('/')[3]
    && minimumReview.captureId === MINIMA.path.split('/')[3]
    && referenceReview.captureId === REFERENCES.path.split('/')[3], 'release_artifact_capture_identity_mismatch');
  const caseSourceRows = readPinRows(casesCandidate.sourceInputs, 'case_candidate_source_inventory_invalid');
  const sourceRows = readPinRows(capturedCandidate.sourceInputs, 'release_candidate_source_inventory_invalid');
  const minimumSourceRows = readPinRows(minimumReview.sourceInputs, 'minimum_review_source_inventory_invalid');
  const referenceSourceRows = readPinRows(referenceReview.sourceInputs, 'semantic_review_source_inventory_invalid');
  const releaseSourceIndex = new Map(sourceRows.map((row) => [row.path, row.sha256]));
  demand(caseSourceRows.every((row) => releaseSourceIndex.get(row.path) === row.sha256),
    'release_candidate_omits_case_candidate_source_pins');
  const referenceIndex = referenceArtifactIndex(referenceReview, CASES);
  const originalManifest = TaskReleaseManifestSchema.parse(capturedCandidate.manifest);
  const { manifestHash: _omitted, ...originalUnhashed } = originalManifest;
  demand(sha256CanonicalTaskJson(originalUnhashed) === originalManifest.manifestHash
    && taskPolicyHash(originalManifest) === originalManifest.policyHash
    && taskBenchmarkHash(originalManifest) === originalManifest.benchmarkHash,
  'original_release_manifest_hash_mismatch');
  const parsedCases = caseInventory(casesCandidate, originalManifest, frozenCaseCandidate);
  demand(minimumReview.candidate?.path === CASES.path && minimumReview.candidate?.sha256 === CASES.sha256
    && minimumReview.executionIdentityHash === originalManifest.executionIdentityHash,
  'minimum_review_candidate_or_identity_mismatch');
  demand(referenceReview.executionIdentityHash === originalManifest.executionIdentityHash,
    'semantic_review_identity_mismatch');
  demand(canonicalTaskJson([...referenceIndex.keys()].sort(compare))
    === canonicalTaskJson(parsedCases.map((taskCase) => `${taskCase.taskId}:${taskCase.mode}`).sort(compare)),
  'semantic_review_inventory_mismatch');
  for (const taskCase of parsedCases) {
    const row = referenceIndex.get(`${taskCase.taskId}:${taskCase.mode}`);
    demand(row?.caseHash === taskCase.caseHash && row.result.actionCount === taskCase.referencePath.actionCount
      && row.result.initialStateSha256 === taskCase.initialState.stateSha256
      && row.result.finalStateSha256 === taskCase.referencePath.finalStateSha256
      && row.result.toolSurfaceSha256 === originalManifest.executionIdentity.toolSurfaceSha256,
    'semantic_review_case_binding_mismatch');
  }

  const allPins = new Map();
  for (const row of [...caseSourceRows, ...sourceRows, ...minimumSourceRows, ...referenceSourceRows]) {
    const previous = allPins.get(row.path);
    demand(previous === undefined || previous === row.sha256, 'release_source_pin_conflict');
    allPins.set(row.path, row.sha256);
  }
  for (const pin of [CASES, RELEASE, MINIMA, REFERENCES, FROZEN_CANDIDATE]) {
    const { path, sha256 } = pin;
    const previous = allPins.get(path);
    demand(previous === undefined || previous === sha256, 'release_artifact_pin_conflict');
    allPins.set(path, sha256);
  }
  const previousInputsConfigHash = allPins.get(pins.inputsConfig.path);
  demand(previousInputsConfigHash === undefined || previousInputsConfigHash === pins.inputsConfig.sha256,
    'release_inputs_config_pin_conflict');
  allPins.set(pins.inputsConfig.path, pins.inputsConfig.sha256);
  const localSources = [
    'pnpm-lock.yaml', POLICY_PATH, 'infrastructure/owner-identity/validate-difficulty-v2-release.mjs',
    'infrastructure/owner-identity/current-task-release-pins.mjs', CURRENT_TASK_RELEASE_INPUTS_PATH,
    'infrastructure/owner-identity/review-difficulty-v2-minima.mjs',
    'infrastructure/owner-identity/verify-difficulty-v2-references.mjs',
    'infrastructure/owner-identity/assemble-difficulty-v2-release.mjs',
    'packages/owner-identity/src/task-release.ts', 'packages/owner-identity/src/task-catalog.ts',
    'packages/owner-identity/src/task-case-assembler.ts', 'packages/owner-identity/src/task-reference-inventory.ts',
    'packages/owner-identity/src/task-feasibility-evidence.ts',
    'packages/owner-identity/src/task-reference-evidence-v2.ts',
    'packages/owner-identity/src/task-reference-evidence-v2-types.ts',
    'packages/owner-identity/src/task-reference-evidence-v2-basic.ts',
    'packages/owner-identity/src/task-reference-evidence-v2-advanced.ts',
    'packages/owner-identity/src/task-difficulty-evidence-v2.ts',
  ];
  const guardedPaths = [...new Set([...allPins.keys(), ...localSources])].sort(compare);
  const before = await snapshot(guardedPaths);
  for (const row of allPins.entries()) await safeBytes(row[0], row[1]);
  const policyBytes = (await safeBytes(POLICY_PATH)).bytes;
  const policyHash = sha(policyBytes);
  const boundManifest = bindMinimumReview(originalManifest, { path: MINIMA.path, sha256: MINIMA.sha256, boundary: BOUNDARY });
  demand(boundManifest.participantToolProtocol === 'separate_payment_delivery_v2', 'release_split_payment_protocol_required');

  const verifiedReferences = [];
  let difficultyVerification = null;
  const verifier = {
    verifyFeasibility: (evidence, executionIdentity, expectedIdentityHash, participantToolProtocol) =>
      verifyRetainedTaskFeasibility({ repositoryRoot: root, evidence, executionIdentity, expectedIdentityHash,
        participantToolProtocol, profilePolicy: { path: POLICY_PATH, sha256: policyHash } }),
    verifyReferencePath: async ({ evidence, taskCase, executionIdentityHash }) => {
      const result = await verifyTaskReferenceEvidenceV2({ repositoryRoot: root,
        identity: boundManifest.executionIdentity, profilePolicy: { path: POLICY_PATH, sha256: policyHash },
        evidence, taskCase, executionIdentityHash });
      verifiedReferences.push({ taskCase, result });
      return result;
    },
    verifyDifficultyReview: async (evidence, cases, executionIdentityHash) => {
      difficultyVerification = await verifyDifficultyEvidenceV2({ repositoryRoot: root, evidence, cases,
        executionIdentityHash, identity: boundManifest.executionIdentity,
        profilePolicy: { path: POLICY_PATH, sha256: policyHash }, caseCandidate: CASES,
        verifiedReferences, costPolicy: boundManifest.costPolicy });
      return difficultyVerification;
    },
  };
  const validation = await validateTaskReleaseCandidate(boundManifest, verifier);
  const after = await snapshot(guardedPaths);
  const sourceUnchanged = canonicalTaskJson(before) === canonicalTaskJson(after);
  demand(sourceUnchanged, 'release_validation_source_changed');

  const actualReferenceIndex = new Map(verifiedReferences.map((row) => [`${row.taskCase.taskId}:${row.taskCase.mode}`, row]));
  const wrapperMatches = actualReferenceIndex.size === currentCaseKeys().length && parsedCases.every((taskCase) => {
    const actual = actualReferenceIndex.get(`${taskCase.taskId}:${taskCase.mode}`);
    const recorded = referenceIndex.get(`${taskCase.taskId}:${taskCase.mode}`);
    return actual && recorded && actual.taskCase.caseHash === taskCase.caseHash
      && canonicalTaskJson(actual.result) === canonicalTaskJson(recorded.result);
  });
  const success = validation.status === 'validated' && difficultyVerification?.status === 'approved' && wrapperMatches;
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-difficulty-v2-release-validation/${captureId}`;
  const output = { schemaVersion: 'bts-difficulty-v2-offline-release-validation/v1', captureId,
    classification: success ? 'local_reference_validated_candidate_not_product_activation_or_owner_acceptance'
      : 'blocked_offline_release_candidate_validation', status: success ? 'validated_candidate' : 'blocked',
    sourceUnchanged, sources: { caseCandidate: { ...CASES }, releaseCandidate: { ...RELEASE },
      minimumActionReview: { ...MINIMA }, semanticReferenceReview: { ...REFERENCES },
      sourceInputsChecked: before.length },
    sourceInputs: before,
    manifestBinding: { originalManifestHash: originalManifest.manifestHash, boundManifestHash: boundManifest.manifestHash,
      difficultyReviewEvidence: boundManifest.difficultyReviewEvidence,
      participantToolProtocol: boundManifest.participantToolProtocol },
    caseInventory: parsedCases.map((taskCase) => ({ taskId: taskCase.taskId, mode: taskCase.mode, caseHash: taskCase.caseHash }))
      .sort((a, b) => compare(`${a.taskId}:${a.mode}`, `${b.taskId}:${b.mode}`)),
    validation, difficultyVerification, semanticWrapperMatches: wrapperMatches,
    semanticResults: verifiedReferences.map(({ taskCase, result }) => ({ taskId: taskCase.taskId,
      mode: taskCase.mode, caseHash: taskCase.caseHash, result })),
    claims: { releaseCandidateValidated: success, productReleaseActivated: false, ownerRunAcceptance: false,
      taskGrade: false, mainnetExecution: false, bddLifecycleChanged: false } };
  await mkdir(outputPrefix, { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify(output, null, 2)}\n`);
  await writeFile(`${outputPrefix}/validation.json`, bytes, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(bytes), status: output.status,
    validationStatus: validation.status, casesChecked: verifiedReferences.length, sourceInputsChecked: before.length,
    blockers: validation.status === 'blocked' ? validation.blockers : difficultyVerification?.status === 'incompatible'
      ? difficultyVerification.findings : wrapperMatches ? [] : ['semantic_wrapper_result_mismatch'] })}\n`);
  if (!success) process.exitCode = 2;
}

void main().catch((error) => {
  const code = error instanceof Error && /^[a-z0-9_]+$/.test(error.message) ? error.message : 'offline_release_validation_failed';
  process.stderr.write(`difficulty_v2_release_validation_blocked:${code}\n`);
  process.exitCode = 2;
});
