import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, mkdir, open, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import pg from 'pg';
import { assertSecretFree, sha256 } from './evidence.mjs';
import { createCard, issueThroughUi } from './credential-cases.mjs';
import { runReleaseBddCases } from './release-bdd-cases.mjs';
import { runRankedBddCases } from './ranked-bdd-cases.mjs';
import { runCodexNativeOwnerAcceptance } from './codex-client-cases.mjs';
import { runCodexOwnerProfileCases } from './codex-owner-profile-cases.mjs';
import { runBrlLaunchAdmissionPreAcceptCases, runBrlLaunchAdmissionPrimaryOnlyCase, captureBrlPrimaryMcpAcceptance,
  runBrlLaunchAdmissionPostCompletionCases } from './benchmark-run-lifecycle-launch-probe.mjs';

const { Pool } = pg;
const ROOT = '/workspace';
const EVIDENCE_ROOT = 'artifacts/runs/genuine-s1-owner-run';
const SEQUENCE_EVIDENCE_ROOT = 'artifacts/runs/genuine-training-sequence-owner-run';
const RANKED_EVIDENCE_ROOT = 'artifacts/runs/genuine-ranked-worker-owner-run';
export const OPEN_TASK_IDS = Object.freeze(['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']);
const RANKED_TASK_IDS = ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1'];
const SUPPORTED_TASKS = new Set(OPEN_TASK_IDS);
const evidenceRootForTask = (taskId = 'S1') => {
  demand(SUPPORTED_TASKS.has(taskId), 'unsupported_genuine_task');
  return taskId === 'S1' ? EVIDENCE_ROOT : 'artifacts/runs/genuine-' + taskId.toLowerCase() + '-owner-run';
};
const POLICY_PATH = 'infrastructure/owner-identity/task-release-local-policy.json';
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const PIN = Object.freeze({
  validation: { path: 'artifacts/runs/bts-difficulty-v2-release-validation/368c4bf6-defb-4205-87d7-a242576732c0/validation.json', sha256: '36fd0bb7154f4639a25acd4daf5a4384b557cb22466f27be622fd47c43558594' },
  cases: { path: 'artifacts/runs/bts-difficulty-v2-case-candidates/00f47005-8951-4003-b6b3-4540172e15d9/candidate-cases.json', sha256: '7ddc9b1181041933aad76c056ffa3288a65265e3d9e6725381343412ce05e82b' },
  release: { path: 'artifacts/runs/bts-difficulty-v2-release-candidates/9cdbaf6a-2c75-47ac-b4c4-2a1dfd997979/candidate-release.json', sha256: '32e71ec759ccd0d3b612e5d87db969ad13e1d9d5213ab77f9a8eadc9e4f6a67f' },
  minimum: { path: 'artifacts/runs/bts-v2-minimum-action-review/40c1a8d1-5697-490f-93d9-3d57442a0688/review.json', sha256: '8fcf1bbfdd7b7f4e8a9bc146a20484c683e207a5ea523863669edec520a20cb0' },
  references: { path: 'artifacts/runs/bts-v2-reference-verification/6be1a286-111c-40bf-a320-1fd8e4b99426/verification.json', sha256: 'f77ef62de268c41295f6b23665cbb4a4f9b41083eaba78826de06a091dac981b' },
});
const HEX_HASH = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const delay = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code) => Object.assign(new Error(code), { code });

function demand(condition, code) {
  if (!condition) throw fail(code);
}

export function normalizeTrainingSequenceTaskIds(requested) {
  // This limits the owner-capture harness to the already-used S1/S2 sequence or
  // the complete canonical open inventory. It does not change service selection policy.
  const validIds = Array.isArray(requested) && requested.every((id) => typeof id === 'string' && SUPPORTED_TASKS.has(id)) &&
    new Set(requested).size === requested.length;
  const s1s2 = validIds && requested.length === 2 && requested.includes('S1') && requested.includes('S2');
  const allOpen = validIds && JSON.stringify(requested) === JSON.stringify(OPEN_TASK_IDS);
  demand(s1s2 || allOpen, 'unsupported_genuine_task_selection');
  return s1s2 ? ['S1', 'S2'] : [...OPEN_TASK_IDS];
}

export function trainingSequenceTransitions(taskIds) {
  const selected = normalizeTrainingSequenceTaskIds(taskIds);
  return selected.slice(1).map((toTaskId, transitionIndex) => ({
    fromTaskIndex: transitionIndex,
    fromTaskId: selected[transitionIndex],
    toTaskIndex: transitionIndex + 1,
    toTaskId,
  }));
}

export function trainingSequenceTransitionBasis({ taskIds, transition, runStartedEvents, activationEvents, terminalizationEvents,
  initialOverallDeadline }) {
  const timestampMillis = (value) => value instanceof Date ? value.getTime() : Date.parse(value ?? '');
  const selected = normalizeTrainingSequenceTaskIds(taskIds);
  const expectedTransition = trainingSequenceTransitions(selected).find((entry) =>
    entry.toTaskIndex === transition?.toTaskIndex);
  demand(expectedTransition && transition?.fromTaskIndex === expectedTransition.fromTaskIndex &&
    transition?.fromTaskId === expectedTransition.fromTaskId && transition?.toTaskId === expectedTransition.toTaskId,
  'successor_public_task_binding_mismatch');

  const currentActivations = activationEvents.filter((event) => event.payload?.toTaskIndex === expectedTransition.toTaskIndex);
  const predecessorTerminalizations = terminalizationEvents.filter((event) =>
    event.payload?.taskIndex === expectedTransition.fromTaskIndex);
  demand(currentActivations.length === 1 && currentActivations[0].payload?.fromTaskIndex === expectedTransition.fromTaskIndex &&
    currentActivations[0].payload?.fromTaskId === expectedTransition.fromTaskId &&
    currentActivations[0].payload?.toTaskId === expectedTransition.toTaskId,
  'successor_activation_event_binding_invalid');
  demand(predecessorTerminalizations.length === 1 &&
    predecessorTerminalizations[0].payload?.taskId === expectedTransition.fromTaskId,
  'successor_predecessor_terminalization_missing_or_stale');
  demand(runStartedEvents.length === 1, 'successor_run_start_event_invalid');

  const priorActivations = activationEvents.filter((event) => event.payload?.toTaskIndex === expectedTransition.fromTaskIndex);
  const priorActivationEvent = expectedTransition.fromTaskIndex === 0 ? null : priorActivations[0];
  demand(expectedTransition.fromTaskIndex === 0 ? priorActivations.length === 0 : priorActivations.length === 1,
    'successor_prior_activation_missing_or_ambiguous');
  const previousTransitionEvent = priorActivationEvent ?? runStartedEvents[0];
  const deadlineValue = priorActivationEvent
    ? priorActivationEvent.payload?.overallDeadline : runStartedEvents[0]?.payload?.overallDeadline;
  const previousDeadline = timestampMillis(deadlineValue);
  const initialDeadlineIsProvided = initialOverallDeadline !== null && initialOverallDeadline !== undefined;
  const initialDeadline = timestampMillis(initialOverallDeadline);
  const sequenceValue = (event) => {
    const sequence = typeof event?.sequence === 'string' && /^\d+$/.test(event.sequence)
      ? BigInt(event.sequence)
      : Number.isSafeInteger(event?.sequence) && event.sequence > 0 ? BigInt(event.sequence) : null;
    return sequence !== null && sequence > 0n ? sequence : null;
  };
  const previousSequence = sequenceValue(previousTransitionEvent);
  const predecessorSequence = sequenceValue(predecessorTerminalizations[0]);
  const activationSequence = sequenceValue(currentActivations[0]);
  demand(Number.isFinite(previousDeadline) &&
    (expectedTransition.fromTaskIndex !== 0 || !initialDeadlineIsProvided ||
      (Number.isFinite(initialDeadline) && initialDeadline === previousDeadline)) &&
    timestampMillis(currentActivations[0].payload?.previousOverallDeadline) === previousDeadline,
  'successor_previous_deadline_missing_or_stale');
  demand(previousSequence !== null && predecessorSequence !== null && activationSequence !== null &&
    previousSequence < predecessorSequence && predecessorSequence < activationSequence,
  'successor_transition_event_order_invalid');
  return {
    activationEvent: currentActivations[0],
    predecessorTerminalizationEvent: predecessorTerminalizations[0],
    priorActivationEvent,
    previousTransitionEvent,
    previousDeadlineValue: deadlineValue,
    previousDeadline,
  };
}

export function trainingSuccessorActivationResult({ transition, proof }) {
  const taskIndex = transition?.toTaskIndex;
  const taskId = transition?.toTaskId;
  demand(Number.isSafeInteger(taskIndex) && taskIndex > 0 && typeof taskId === 'string' &&
    proof?.taskIndex === taskIndex && proof?.taskId === taskId,
  'successor_activation_result_binding_invalid');
  return { ...proof, fromTaskIndex: transition.fromTaskIndex, fromTaskId: transition.fromTaskId,
    toTaskIndex: taskIndex, toTaskId: taskId, taskIndex, taskId };
}

export function trainingSuccessorActivationChainMatches(taskIds, activations) {
  const transitions = trainingSequenceTransitions(taskIds);
  return Array.isArray(activations) && activations.length === transitions.length &&
    transitions.every((transition, index) => {
      const entry = activations[index];
      return entry?.fromTaskIndex === transition.fromTaskIndex && entry?.fromTaskId === transition.fromTaskId &&
        entry?.toTaskIndex === transition.toTaskIndex && entry?.toTaskId === transition.toTaskId &&
        entry?.taskIndex === transition.toTaskIndex && entry?.taskId === transition.toTaskId;
    });
}

export function trainingCleanupLeasePrefixIsFenced({ mode, preparations, taskIds }) {
  if (!Array.isArray(preparations)) return false;
  if (mode === 'ranked') {
    return preparations.every((entry, index) => entry.lease_state === 'fenced' && entry.task_index === index);
  }
  return mode === 'training' && Array.isArray(taskIds) && preparations.length <= taskIds.length &&
    preparations.every((entry, index) => entry.lease_state === 'fenced' && entry.task_index === index &&
      entry.task_id === taskIds[index]);
}

export function quoteTrainingSelectionUnits(release, taskIds) {
  const tasks = release.trainingTasks;
  const inventory = tasks.map((task) => task.taskId);
  const totalWeight = tasks.reduce((sum, task) => sum + task.taskWeight, 0);
  const selectedWeight = tasks.filter((task) => taskIds.includes(task.taskId))
    .reduce((sum, task) => sum + task.taskWeight, 0);
  demand(JSON.stringify(inventory) === JSON.stringify(OPEN_TASK_IDS) && totalWeight === 15 &&
    selectedWeight > 0 && Number.isSafeInteger(selectedWeight), 'training_quote_release_inventory_invalid');
  return (BigInt(release.trainingPriceUnits) * BigInt(selectedWeight) + BigInt(totalWeight) - 1n) / BigInt(totalWeight);
}

export function trainingSequenceGrantAmountUnits(quoteUnits) {
  demand(typeof quoteUnits === 'bigint' && quoteUnits > 0n, 'training_sequence_quote_invalid');
  return quoteUnits > 100_000n ? quoteUnits : 100_000n;
}

function safeErrorCode(error, fallback = 'genuine_s1_case_failed') {
  const code = typeof error?.code === 'string' ? error.code
    : typeof error?.message === 'string' ? error.message : '';
  return /^[A-Za-z0-9_]{1,96}$/.test(code) ? code : fallback;
}

function validRelative(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 512 && path.trim() === path &&
    !isAbsolute(path) && !path.includes('\\') && !path.includes(':') &&
    path.split('/').every((part) => part && part !== '.' && part !== '..');
}

async function safeBytes(repositoryRoot, path, expectedHash = null, maxBytes = 16 * 1024 * 1024) {
  demand(validRelative(path) && (expectedHash === null || HEX_HASH.test(expectedHash)), 'release_source_path_invalid');
  const root = await realpath(repositoryRoot);
  const actual = await realpath(resolve(root, path));
  const rel = relative(root, actual);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + sep), 'release_source_path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= maxBytes, 'release_source_file_invalid');
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (!result.bytesRead) break;
      offset += result.bytesRead;
    }
    const after = await handle.stat();
    demand(offset === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs,
      'release_source_changed_during_read');
    const content = bytes.subarray(0, offset);
    const actualHash = digest(content);
    demand(expectedHash === null || actualHash.toLowerCase() === expectedHash.toLowerCase(), 'release_source_hash_mismatch');
    return { bytes: content, sha256: actualHash };
  } finally { await handle.close(); }
}

function pinRows(value, code) {
  demand(Array.isArray(value) && value.length > 0 && value.length <= 4096, code);
  const byPath = new Map();
  for (const row of value) {
    demand(row && validRelative(row.path) && HEX_HASH.test(String(row.sha256)), code);
    const previous = byPath.get(row.path);
    demand(previous === undefined || previous === row.sha256.toLowerCase(), 'release_source_pin_conflict');
    byPath.set(row.path, row.sha256.toLowerCase());
  }
  return Array.from(byPath, ([path, sha256Value]) => ({ path, sha256: sha256Value })).sort((a, b) => a.path.localeCompare(b.path));
}

async function verifyPinRows(repositoryRoot, rows) {
  for (const row of rows) await safeBytes(repositoryRoot, row.path, row.sha256);
  return digest(Buffer.from(JSON.stringify(rows)));
}

function bindMinimumReview(manifest, minimum, taskRelease) {
  const bound = structuredClone(manifest);
  bound.difficultyReviewEvidence = { path: minimum.path, sha256: minimum.sha256, boundary: BOUNDARY };
  bound.policyHash = taskRelease.taskPolicyHash(bound);
  bound.benchmarkHash = taskRelease.taskBenchmarkHash(bound);
  const { manifestHash: omitted, ...unhashed } = bound;
  void omitted;
  bound.manifestHash = taskRelease.sha256CanonicalTaskJson(unhashed);
  return taskRelease.TaskReleaseManifestSchema.parse(bound);
}

export async function validateAndActivatePinnedRelease({ repositoryRoot, databaseUrl, observerDatabaseUrl, bddContext = null }) {
  const pinnedDocuments = {};
  for (const [name, row] of Object.entries(PIN)) {
    const read = await safeBytes(repositoryRoot, row.path, row.sha256);
    pinnedDocuments[name] = JSON.parse(read.bytes.toString('utf8'));
  }
  const validation = pinnedDocuments.validation;
  const candidateCases = pinnedDocuments.cases;
  const capturedRelease = pinnedDocuments.release;
  const minimumReview = pinnedDocuments.minimum;
  const referenceReview = pinnedDocuments.references;
  demand(validation.schemaVersion === 'bts-difficulty-v2-offline-release-validation/v1' &&
    validation.status === 'validated_candidate' && validation.sourceUnchanged === true &&
    validation.manifestBinding?.boundManifestHash && validation.claims?.productReleaseActivated === false &&
    validation.claims?.ownerRunAcceptance === false && validation.claims?.taskGrade === false,
  'pinned_release_validation_not_authoritative');
  demand(capturedRelease.schemaVersion === 'bts-task-release-candidate-capture/v2' &&
    capturedRelease.captureId === '9cdbaf6a-2c75-47ac-b4c4-2a1dfd997979' &&
    capturedRelease.classification === 'full_inventory_candidate_not_validated_or_activated_release',
  'pinned_release_candidate_invalid');
  demand(candidateCases.schemaVersion === 'bts-difficulty-v2-case-candidates/v1' &&
    candidateCases.participantToolProtocol === 'separate_payment_delivery_v2' && Array.isArray(candidateCases.cases) &&
    candidateCases.cases.length === 20, 'pinned_case_candidate_invalid');
  const sourceRows = pinRows(validation.sourceInputs, 'validation_source_inventory_invalid');
  const releaseRows = pinRows(capturedRelease.sourceInputs, 'release_source_inventory_invalid');
  const minimumRows = pinRows(minimumReview.sourceInputs, 'minimum_source_inventory_invalid');
  const referenceRows = pinRows(referenceReview.sourceInputs, 'reference_source_inventory_invalid');
  const mergedPins = new Map();
  for (const row of [...sourceRows, ...releaseRows, ...minimumRows, ...referenceRows]) {
    const prior = mergedPins.get(row.path);
    demand(prior === undefined || prior === row.sha256, 'release_source_pin_conflict');
    mergedPins.set(row.path, row.sha256);
  }
  for (const row of Object.values(PIN)) {
    const prior = mergedPins.get(row.path);
    demand(prior === undefined || prior === row.sha256, 'release_artifact_pin_conflict');
    mergedPins.set(row.path, row.sha256);
  }
  const currentPins = Array.from(mergedPins, ([path, sha256Value]) => ({ path, sha256: sha256Value })).sort((a, b) => a.path.localeCompare(b.path));
  const sourceInputPinSetSha256 = await verifyPinRows(repositoryRoot, currentPins);
  const localPolicy = await safeBytes(repositoryRoot, POLICY_PATH);
  const { TaskCaseSchema, TaskReleaseManifestSchema, canonicalTaskJson, sha256CanonicalTaskJson,
    taskPolicyHash, taskBenchmarkHash, validateTaskReleaseCandidate } = await import('../../owner-identity/dist/task-release.js');
  const { verifyRetainedTaskFeasibility } = await import('../../owner-identity/dist/task-feasibility-evidence.js');
  const { verifyTaskReferenceEvidenceV2 } = await import('../../owner-identity/dist/task-reference-evidence-v2.js');
  const { verifyDifficultyEvidenceV2 } = await import('../../owner-identity/dist/task-difficulty-evidence-v2.js');
  const { createDatabase } = await import('../../owner-identity/dist/db.js');
  const { loadConfig } = await import('../../owner-identity/dist/config.js');
  const { activatePostgresTaskReleaseCandidate, createPostgresTaskReleaseQuerySource } = await import('../../owner-identity/dist/task-store.js');

  const original = TaskReleaseManifestSchema.parse(capturedRelease.manifest);
  const { manifestHash: originalHashOmitted, ...originalWithoutHash } = original;
  void originalHashOmitted;
  demand(sha256CanonicalTaskJson(originalWithoutHash) === original.manifestHash &&
    original.manifestHash === validation.manifestBinding.originalManifestHash, 'original_manifest_hash_mismatch');
  demand(minimumReview.candidate?.path === PIN.cases.path && minimumReview.candidate?.sha256 === PIN.cases.sha256 &&
    minimumReview.executionIdentityHash === original.executionIdentityHash && referenceReview.executionIdentityHash === original.executionIdentityHash,
  'review_case_or_identity_binding_mismatch');
  const parsedCases = candidateCases.cases.map((value) => TaskCaseSchema.parse(value));
  demand(parsedCases.length === 20 && OPEN_TASK_IDS.every((taskId) =>
    parsedCases.filter((taskCase) => taskCase.taskId === taskId && taskCase.mode === 'training').length === 1),
    'case_inventory_invalid');
  const byKey = new Map(parsedCases.map((taskCase) => [taskCase.taskId + ':' + taskCase.mode, taskCase]));
  demand([...original.cases.training, ...original.cases.ranked].length === 20 &&
    [...original.cases.training, ...original.cases.ranked].every((taskCase) => {
      const candidate = byKey.get(taskCase.taskId + ':' + taskCase.mode);
      return candidate && canonicalTaskJson(candidate) === canonicalTaskJson(taskCase);
    }), 'release_case_binding_mismatch');
  const bound = bindMinimumReview(original, PIN.minimum, { taskPolicyHash, taskBenchmarkHash,
    sha256CanonicalTaskJson, TaskReleaseManifestSchema });
  demand(bound.participantToolProtocol === 'separate_payment_delivery_v2' &&
    bound.manifestHash === validation.manifestBinding.boundManifestHash &&
    bound.difficultyReviewEvidence.path === PIN.minimum.path && bound.difficultyReviewEvidence.sha256 === PIN.minimum.sha256,
  'bound_manifest_pin_mismatch');
  const policyHash = localPolicy.sha256;
  const dbConfig = loadConfig({ ...process.env, OID_DATABASE_URL: databaseUrl });
  const { db, client } = createDatabase(dbConfig);
  const taskReleaseSource = createPostgresTaskReleaseQuerySource(db);
  const verifiedReferences = [];
  let difficultyEvidence = null;
  const verifier = {
    verifyFeasibility: (evidence, identity, expectedIdentityHash, participantToolProtocol) =>
      verifyRetainedTaskFeasibility({ repositoryRoot, evidence, executionIdentity: identity, expectedIdentityHash,
        participantToolProtocol, profilePolicy: { path: POLICY_PATH, sha256: policyHash } }),
    verifyReferencePath: async ({ evidence, taskCase, executionIdentityHash }) => {
      const result = await verifyTaskReferenceEvidenceV2({ repositoryRoot, identity: bound.executionIdentity,
        profilePolicy: { path: POLICY_PATH, sha256: policyHash }, evidence, taskCase, executionIdentityHash });
      verifiedReferences.push({ taskCase, result });
      return result;
    },
    verifyDifficultyReview: async (evidence, cases, executionIdentityHash) => {
      difficultyEvidence = await verifyDifficultyEvidenceV2({ repositoryRoot, evidence, cases, executionIdentityHash,
        identity: bound.executionIdentity, profilePolicy: { path: POLICY_PATH, sha256: policyHash },
        caseCandidate: PIN.cases, verifiedReferences, costPolicy: bound.costPolicy });
      return difficultyEvidence;
    },
  };
  try {
    const activation = await activatePostgresTaskReleaseCandidate(db, bound, verifier);
    demand(activation.status === 'validated' && activation.release.manifest.manifestHash === bound.manifestHash &&
      verifiedReferences.length === 20 && difficultyEvidence?.status === 'approved', 'full_release_verifier_blocked');
    const active = await taskReleaseSource.getActiveAdmissionRelease('training');
    demand(active?.releaseIdentity === bound.releaseIdentity && active.manifestHash === bound.manifestHash,
      'active_release_database_binding_mismatch');
    const positiveReferenceCount = verifiedReferences.length;
    const positiveDifficultyStatus = difficultyEvidence.status;
    if (bddContext) {
      const observerPool = new Pool({connectionString: observerDatabaseUrl, max: 1,
        application_name: 'bdd-release-readonly-observer'});
      try {
        bddContext.releaseProbe = await runReleaseBddCases({db, observerPool, manifest: bound, verifier,
          positiveActivation: activation, referenceResults: [...verifiedReferences], difficultyEvidence});
      } finally { await observerPool.end(); }
      const { LOCAL_BEF_RUN_SERVICE_POLICY } = await import('../../owner-identity/dist/bef-task-coordinator.js');
      bddContext.ownerPendingLimit = LOCAL_BEF_RUN_SERVICE_POLICY?.maxPendingIntentsPerOwner;
      const activate = async (candidate) => {
        const created = createDatabase(dbConfig);
        verifiedReferences.length = 0;
        difficultyEvidence = null;
        try {
          const result = await activatePostgresTaskReleaseCandidate(created.db, candidate, verifier);
          demand(result.status === 'validated', 'bdd_release_callback_validation_failed');
          return {status: result.status, releaseIdentity: candidate.releaseIdentity,
            benchmarkVersion: candidate.benchmarkVersion, manifestHash: candidate.manifestHash,
            rankedPriceUnits: candidate.pricing.rankedPriceUnits};
        } finally { await created.client.end({timeout: 5}); }
      };
      const next = structuredClone(bound);
      next.releaseIdentity += '-bdd-next';
      next.benchmarkVersion += '-bdd-next';
      next.pricing.rankedPriceUnits = (BigInt(next.pricing.rankedPriceUnits) + 1n).toString();
      next.policyHash = taskPolicyHash(next);
      next.benchmarkHash = taskBenchmarkHash(next);
      const {manifestHash: _prior, ...withoutHash} = next;
      next.manifestHash = sha256CanonicalTaskJson(withoutHash);
      bddContext.activateNextRelease = () => activate(TaskReleaseManifestSchema.parse(next));
      bddContext.restoreRelease = () => activate(bound);
    }
    return {
      status: 'activated_in_isolated_acceptance_database', releaseIdentity: bound.releaseIdentity,
      manifestHash: bound.manifestHash, candidatePath: PIN.release.path, candidateSha256: PIN.release.sha256,
      environmentManifestSha256: bound.executionIdentity.environmentManifestSha256,
      validationPath: PIN.validation.path, validationSha256: PIN.validation.sha256,
      sourceInputCount: currentPins.length, sourceInputPinSetSha256, feasibilityStatus: 'verified',
      benchmarkVersion: bound.benchmarkVersion, benchmarkHash: bound.benchmarkHash, policyHash: bound.policyHash,
      semanticReferenceCount: positiveReferenceCount, difficultyStatus: positiveDifficultyStatus,
      participantToolProtocol: bound.participantToolProtocol, precision: bound.pricing.precision,
      trainingPriceUnits: bound.pricing.openTrainingPriceUnits,
      rankedPriceUnits: bound.pricing.rankedPriceUnits,
      trainingTasks: bound.cases.training.map((taskCase) => ({ taskId: taskCase.taskId, taskWeight: taskCase.taskWeight,
        taskDeadlineSeconds: taskCase.taskDeadlineSeconds })),
      rankedTasks: bound.cases.ranked.map((taskCase) => ({ taskId: taskCase.taskId, taskWeight: taskCase.taskWeight, caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash,
        taskDeadlineSeconds: taskCase.taskDeadlineSeconds })),
    };
  } finally { await client.end({ timeout: 5 }); }
}

function pgRows(result) {
  if (Array.isArray(result)) return result;
  if (result && Array.isArray(result.rows)) return result.rows;
  return [];
}

function sortedJsonValue(value) {
  if (Array.isArray(value)) return value.map(sortedJsonValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, child]) => [key, sortedJsonValue(child)]));
}

function eventPayloadHash(value) {
  return digest(Buffer.from(JSON.stringify(sortedJsonValue(value))));
}

function formatUsdcUnits(value) {
  const units = typeof value === 'bigint' ? value : BigInt(value);
  demand(units >= 0n, 'usdc_units_negative');
  return (units / 1_000_000n).toString() + '.' + (units % 1_000_000n).toString().padStart(6, '0');
}
function exactUsdcUnits(value) {
  if (typeof value !== 'string') return null;
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/.exec(value);
  if (!match) return null;
  return BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? '').padEnd(6, '0') || '0');
}

function projectAcceptedEvent(row) {
  let payload = row.payload_json;
  try { if (typeof payload === 'string') payload = JSON.parse(payload); } catch { payload = null; }
  return { eventId: row.event_id, runId: row.run_id, sequence: row.sequence, source: row.source,
    eventType: row.event_type, payloadHash: row.payload_hash, payload,
    intentId: row.intent_id, ownerId: row.owner_id, agentId: row.agent_id, manifestHash: row.manifest_hash,
    mode: row.run_mode, taskIds: row.run_task_ids };
}

function acceptedEventMatches(snapshot, expected) {
  const events = snapshot.acceptanceEvents;
  if (!Array.isArray(events) || events.length !== 1) return false;
  const event = events[0];
  const payload = event.payload;
  const expectedTaskIds = expected.taskIds ?? [expected.taskId ?? 'S1'];
  const expectedMode = expected.mode ?? 'training';
  return Boolean(payload && typeof payload === 'object' && !Array.isArray(payload) &&
    event.source === 'agent' && event.eventType === 'run.accepted' && event.runId === expected.runId &&
    event.intentId === expected.intentId && event.ownerId === expected.ownerId && event.agentId === expected.agentId &&
    event.manifestHash === expected.manifestHash && event.mode === expectedMode &&
    Array.isArray(event.taskIds) && JSON.stringify(event.taskIds) === JSON.stringify(expectedTaskIds) &&
    payload.intentId === expected.intentId && payload.operationId === expected.acceptOperationId &&
    payload.mode === expectedMode && Array.isArray(payload.taskIds) && JSON.stringify(payload.taskIds) === JSON.stringify(expectedTaskIds) &&
    typeof event.payloadHash === 'string' && event.payloadHash.toLowerCase() === eventPayloadHash(payload).toLowerCase());
}

async function readonlyTransaction(pool, callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity = await client.query('SELECT current_user AS role,current_database() AS database_name,current_setting(\'transaction_read_only\') AS readonly');
    if (identity.rows[0]?.role !== 'oid_observer' || identity.rows[0]?.readonly !== 'on') throw fail('identity_observer_role_invalid');
    const value = await callback((statement, parameters = []) => client.query(statement, parameters));
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function readRunSnapshot(pool, target) {
  return readonlyTransaction(pool, async (query) => {
    const run = await query(`SELECT r.id::text,r.intent_id::text,r.owner_id::text,r.agent_id::text,r.mode,r.task_ids,
        r.release_identity,r.manifest_hash,r.benchmark_hash,r.policy_hash,r.quote_price_units::text,r.cash_ceiling_units::text,
        r.status,r.environment_id,r.started_at,r.finished_at,r.overall_deadline,r.cancellation_reason,r.cancellation_evidence_hash,
        r.successor_preparation_policy_version,r.successor_preparation_timeout_seconds,
        i.status AS intent_status,i.operation_id AS intent_operation_id,i.cash_ceiling_units::text AS intent_cash_ceiling_units,
        i.successor_preparation_policy_version AS intent_successor_preparation_policy_version,
        i.successor_preparation_timeout_seconds AS intent_successor_preparation_timeout_seconds
      FROM oid_benchmark_run r JOIN oid_run_launch_intent i ON i.id=r.intent_id WHERE r.id=$1`, [target.runId]);
    const tasks = await query(`SELECT task_index,task_id,status,started_at,finished_at,deadline_at,accepted_action_sequence::text,
        action_cutoff_sequence::text,reconciled_action_sequence::text,closure_status,closure_id::text,closure_reason,closed_at
      FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`, [target.runId]);
    const actions = await query(`SELECT a.id::text,a.task_index,a.action_sequence::text,a.operation_id,a.action_kind,a.command_json,a.payload_hash,
        a.accepted_at,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,r.tool_response_hash,
        r.tool_response_json
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.run_id=$1 ORDER BY a.action_sequence`, [target.runId]);
    const execution = await query(`SELECT b.task_index,b.env_id,b.generation_id::text,b.manifest_hash,b.application_source_hash,
        b.participant_id,b.payer_address,
        i.preparation_id::text,i.lease_id::text,i.case_id,i.case_hash,i.initial_state_sha256,l.state AS lease_state
      FROM oid_task_execution_binding b
      LEFT JOIN oid_task_preparation_intent i ON i.run_id=b.run_id AND i.task_index=b.task_index
      LEFT JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      WHERE b.run_id=$1 ORDER BY b.task_index`, [target.runId]);
    const preparations = await query(`SELECT i.task_index,i.preparation_id::text,i.lease_id::text,i.environment_id,i.task_id,
        i.case_id,i.case_hash,i.initial_state_sha256,i.environment_manifest_sha256,i.application_source_hash,
        l.state AS lease_state,o.status AS preparation_status,o.generation_id::text AS observed_generation_id,
        o.baseline_state_sha256
      FROM oid_task_preparation_intent i LEFT JOIN oid_task_environment_lease l
        ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
      LEFT JOIN LATERAL (SELECT status,generation_id,baseline_state_sha256 FROM oid_task_preparation_observation
        WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
      WHERE i.run_id=$1 ORDER BY i.task_index`, [target.runId]);
    const evaluation = await query(`SELECT task_index,task_id,manifest_hash,case_hash,input_hash,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index`, [target.runId]);
    const runEvents = await query(`SELECT e.id::text AS event_id,e.run_id::text,e.sequence::text,e.source,e.event_type,
        e.payload_hash,e.payload_json,r.intent_id::text,r.owner_id::text,r.agent_id::text,r.manifest_hash,r.mode AS run_mode,r.task_ids AS run_task_ids
      FROM oid_run_event e JOIN oid_benchmark_run r ON r.id=e.run_id
      WHERE e.run_id=$1 AND e.event_type IN ('run.accepted','run.started','task.activated','task.terminalized','run.completed') ORDER BY e.sequence`, [target.runId]);
    const projectedEvents = pgRows(runEvents).map(projectAcceptedEvent);
    return { identity: identityless(await query('SELECT current_user AS role,current_setting(\'transaction_read_only\') AS readonly')),
      run: pgRows(run).map(projectRun), tasks: pgRows(tasks), actions: pgRows(actions).map(projectAction),
      execution: pgRows(execution), preparations: pgRows(preparations), evaluation: pgRows(evaluation).map(projectEvaluation),
      runEvents: projectedEvents, acceptanceEvents: projectedEvents.filter((event) => event.eventType === 'run.accepted') };
  });
}

function identityless(rowsValue) {
  const row = pgRows(rowsValue)[0] ?? {};
  return { role: row.role, readOnly: row.readonly };
}

function projectRun(row) {
  return { ...row, runId: row.id, intentId: row.intent_id };
}

function projectAction(row) {
  let response = null;
  try { response = typeof row.tool_response_json === 'string' ? JSON.parse(row.tool_response_json) : row.tool_response_json; } catch { /* No body projection. */ }
  return { actionId: row.id, taskIndex: row.task_index, actionSequence: row.action_sequence, operationId: row.operation_id, kind: row.action_kind,
    command: row.command_json, commandSha256: row.payload_hash, acceptedAt: row.accepted_at,
    receiptRevision: row.receipt_revision, receiptStatus: row.receipt_status, evidenceHash: row.evidence_hash,
    evidencePath: row.evidence_path, transactionHash: row.transaction_hash, toolResponseHash: row.tool_response_hash,
    toolResponseStatus: response && typeof response === 'object' ? response.status ?? null : null };
}

function projectEvaluation(row) {
  let result = null;
  try { result = typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json; } catch { /* Hash facts remain. */ }
  return { taskIndex: row.task_index, taskId: row.task_id, manifestHash: row.manifest_hash, caseHash: row.case_hash,
    inputHash: row.input_hash, resultHash: row.result_hash, evaluatorSourceHash: row.evaluator_source_hash,
    resultStatus: result?.status ?? null, resultCredit: result?.credit ?? null };
}

async function checkBonusGrant(pool, grantId, ownerId, operationId) {
  return readonlyTransaction(pool, async (query) => {
    const grant = await query(`SELECT id::text,owner_id::text,amount_units::text,issued_by_owner_id::text,reason,operation_id,created_at,expires_at
      FROM oid_bonus_grant WHERE id=$1 AND owner_id=$2 AND operation_id=$3`, [grantId, ownerId, operationId]);
    const ledger = await query(`SELECT id::text,entry_type,source_kind,amount_units::text,available_delta_units::text,
        reserved_delta_units::text,bonus_grant_id::text,operation_id FROM oid_ledger_entry
      WHERE owner_id=$1 AND bonus_grant_id=$2 ORDER BY created_at,id`, [ownerId, grantId]);
    return { role: 'oid_observer', grant: pgRows(grant), ledgerEntries: pgRows(ledger) };
  });
}

function createMinimumIntervalPacer(intervalMs, now = () => performance.now(), sleep = delay) {
  demand(Number.isFinite(intervalMs) && intervalMs >= 0 && typeof now === 'function' && typeof sleep === 'function',
    'agent_request_pacer_configuration_invalid');
  let queue = Promise.resolve();
  let nextStartAt = 0;
  return () => {
    const slot = queue.then(async () => {
      const waitMs = Math.max(0, nextStartAt - now());
      if (waitMs > 0) await sleep(waitMs);
      nextStartAt = now() + intervalMs;
    });
    queue = slot.catch(() => undefined);
    return slot;
  };
}

const paceAgentRequest = createMinimumIntervalPacer(1100);

async function agentRequest({ publicOrigin, path, method = 'GET', bearer, body }) {
  await paceAgentRequest();
  let response;
  try {
    response = await fetch(new URL(path, publicOrigin), {
      method, redirect: 'error', signal: AbortSignal.timeout(15_000),
      headers: { authorization: 'Bearer ' + bearer, origin: publicOrigin, ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch { throw fail('agent_http_transport_unknown'); }
  let payload = {};
  try { payload = await response.json(); } catch { /* Retain status only. */ }
  return { status: response.status, payload };
}

async function waitForActiveTask({ publicOrigin, bearer, runId, observerPool, taskId = 'S1', taskIndex = 0,
  mode = 'training', timeoutMs = 180_000 }) {
  const end = Date.now() + timeoutMs;
  let latestRun = null;
  while (Date.now() < end) {
    const response = await agentRequest({ publicOrigin, path: '/api/agent/runs/' + runId + '/current-task', bearer });
    if (response.status === 200 && response.payload?.task) {
      const task = response.payload.task;
      demand(task.runId === runId && task.taskIndex === taskIndex && task.taskId === taskId && task.mode === mode,
        'issued_task_binding_mismatch');
      return task;
    }
    if (response.status >= 400 && response.status !== 404 && response.status !== 409 && response.status !== 503) {
      throw fail(typeof response.payload?.error?.code === 'string' ? response.payload.error.code : 'current_task_http_denied');
    }
    const snapshot = await readRunSnapshot(observerPool, { runId });
    latestRun = snapshot.run[0] ?? null;
    if (latestRun && ['cancelled', 'failed', 'expired', 'unknown', 'disqualified'].includes(latestRun.status)) throw fail('run_terminal_before_task_issue');
    await delay(1000);
  }
  const error = fail('strict_preparation_or_task_issue_timeout');
  error.safeDiagnostic = { lastObservedRunStatus: latestRun?.status ?? null };
  throw error;
}

async function waitForActionResolution({ publicOrigin, bearer, runId, actionId, observerPool, timeoutMs = 180_000,
  waitForPlatformRecovery = false, onInitialUnknown = undefined, finishWhenUnknown = undefined }) {
  demand(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1_000 && timeoutMs <= 240_000,
    'action_resolution_timeout_invalid');
  const end = Date.now() + timeoutMs;
  let initialUnknown = null;
  let initialUnknownNotified = false;
  while (Date.now() < end) {
    let api;
    try {
      api = await agentRequest({ publicOrigin, path: '/api/agent/runs/' + runId + '/actions/' + actionId, bearer });
    } catch (error) {
      if (!waitForPlatformRecovery) throw error;
      api = { status: 0, payload: { error: { code: safeErrorCode(error) } } };
    }
    const snapshot = await readRunSnapshot(observerPool, { runId });
    const action = snapshot.actions.find((row) => row.actionId === actionId);
    if (waitForPlatformRecovery && initialUnknown && action && typeof finishWhenUnknown === 'function' &&
        await finishWhenUnknown({ apiStatus: api.status, apiPayload: api.payload, action, snapshot })) {
      return { apiStatus: api.status, apiPayload: api.payload, action, snapshot, initialUnknown, finalTerminal: true };
    }
    if (action && ['observed', 'rejected_before_execution', 'unknown'].includes(action.receiptStatus)) {
      // The GET can precede the receipt commit seen by the independent observer.
      // Poll reads until both surfaces agree; never resend the participant action.
      const apiMatches = api.status === 200 && api.payload?.actionId === actionId &&
        api.payload?.runId === runId && api.payload?.status === action.receiptStatus &&
        api.payload?.receiptRevision === action.receiptRevision &&
        (api.payload?.toolResponse == null ? action.toolResponseHash === null
          : eventPayloadHash(api.payload.toolResponse) === action.toolResponseHash);
      if (action.receiptStatus === 'unknown') {
        initialUnknown ??= { apiStatus: api.status, action, snapshot };
        if (!initialUnknownNotified && typeof onInitialUnknown === 'function') {
          initialUnknownNotified = true;
          await onInitialUnknown(initialUnknown);
        }
        if (!waitForPlatformRecovery) return { apiStatus: api.status, apiPayload: api.payload, action, snapshot };
      } else if (apiMatches) {
        return { apiStatus: api.status, apiPayload: api.payload, action, snapshot, initialUnknown };
      }
    }
    await delay(750);
  }
  const snapshot = await readRunSnapshot(observerPool, { runId });
  return { apiStatus: null, action: snapshot.actions.find((row) => row.actionId === actionId) ?? null,
    snapshot, initialUnknown, timedOut: true };
}

async function waitForClosedTask(pool, runId, taskIndex = 0, timeoutMs = 90_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const snapshot = await readRunSnapshot(pool, { runId });
    const task = snapshot.tasks.find((row) => row.task_index === taskIndex);
    if (task?.closure_status === 'closed' && task.action_cutoff_sequence !== null &&
      BigInt(task.reconciled_action_sequence ?? 0) >= BigInt(task.action_cutoff_sequence)) return snapshot;
    await delay(750);
  }
  return readRunSnapshot(pool, { runId });
}

function answerFromPublicS2Read(task, body) {
  demand(task.participantToolProtocol === 'separate_payment_delivery_v2' && body?.resourceId === task.conditions.resourceId &&
    body?.readHandle?.kind === 'offer' && Array.isArray(body.offers), 's2_public_offer_unavailable');
  const offer = body.offers.find((entry) => entry?.id === task.conditions.offerId);
  const payment = offer?.payment;
  const assetId = task.execution.assets.find((asset) => typeof asset.address === 'string' && typeof payment?.asset === 'string' &&
    asset.address.toLowerCase() === payment.asset.toLowerCase() && payment.network === 'eip155:' + asset.chainId)?.assetId;
  demand(payment?.network === 'eip155:8453' && typeof assetId === 'string' && payment?.transferMethod === 'eip3009' &&
    /^\d+$/.test(payment.amount) && /^0x[0-9a-f]{40}$/i.test(payment.payTo ?? ''), 's2_public_payment_profile_unsupported');
  const paymentFields = { assetTransferMethod: payment.transferMethod, paymentFlow: payment.paymentFlow,
    name: payment.name ?? offer?.assetName ?? body.assetName, version: payment.version ?? body.version };
  const authFields = task.conditions.requiredAnswerFields.flatMap((name) =>
    Object.prototype.hasOwnProperty.call(paymentFields, name) && typeof paymentFields[name] === 'string'
      ? [{ name, value: paymentFields[name] }] : []);
  return { amountUnits: payment.amount, network: payment.network, assetId,
    recipient: payment.payTo, scheme: payment.scheme, resourceId: body.resourceId,
    offerId: offer.id, ...(typeof payment.version === 'string' ? { version: payment.version } : {}),
    authFields };
}
function taskObject(value, code) {
  demand(value !== null && typeof value === 'object' && !Array.isArray(value), code);
  return value;
}

function taskUnits(value, code, { allowZero = true } = {}) {
  const normalized = typeof value === 'string' ? value : typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : '';
  demand((allowZero ? /^(?:0|[1-9][0-9]{0,77})$/ : /^[1-9][0-9]{0,77}$/).test(normalized), code);
  return BigInt(normalized);
}

function publicTaskBody(result, code) {
  demand(result?.action?.receiptStatus === 'observed' && result.action.kind === result.action.command?.kind,
    code + '_action_not_observed');
  return taskObject(result.apiPayload?.toolResponse, code + '_public_response_unavailable');
}

function paymentAmount(offer) {
  const payment = offer?.payment;
  const candidate = offer?.advertisedTotalPriceUsdcUnits ?? offer?.fullCostUsdcUnits ?? payment?.amount;
  if (typeof candidate !== 'string' || !/^(?:0|[1-9][0-9]{0,77})$/.test(candidate)) return null;
  return BigInt(candidate);
}

function offerTermsMatch(offer, constraints = {}) {
  const payment = offer?.payment;
  if (!payment || typeof payment !== 'object' || Array.isArray(payment) || paymentAmount(offer) === null) return false;
  const resource = constraints.resource ?? {};
  const dataType = offer.dataType ?? resource.dataType;
  const disclosedAsset = constraints.assets?.find((asset) => typeof asset.address === 'string' && typeof payment.asset === 'string' &&
    asset.address.toLowerCase() === payment.asset.toLowerCase() && payment.network === 'eip155:' + asset.chainId);
  const assetId = Array.isArray(constraints.assets) ? disclosedAsset?.assetId : offer.assetId ?? resource.assetId;
  const network = offer.network ?? payment.network;
  const recipient = offer.recipient ?? payment.payTo;
  return (!constraints.dataType || dataType === constraints.dataType) &&
    (!constraints.assetId || assetId === constraints.assetId) &&
    (!constraints.scheme || payment.scheme === constraints.scheme) &&
    (!constraints.network || network === constraints.network) &&
    (!constraints.recipient || typeof recipient === 'string' && recipient.toLowerCase() === constraints.recipient.toLowerCase()) &&
    (!constraints.sourceIds?.length || !Array.isArray(offer.sourceIds) && typeof offer.sourceId !== 'string' ||
      constraints.sourceIds.some((id) => id === offer.sourceId || offer.sourceIds?.includes?.(id))) &&
    (!constraints.maxAmount || paymentAmount(offer) <= constraints.maxAmount);
}

function selectPublicOffer(body, constraints = {}) {
  const offers = Array.isArray(body?.offers) ? body.offers : [];
  const matching = offers.filter((offer) => offerTermsMatch(offer, constraints));
  matching.sort((left, right) => {
    const delta = paymentAmount(left) - paymentAmount(right);
    return delta < 0n ? -1 : delta > 0n ? 1 : String(left.id).localeCompare(String(right.id));
  });
  return matching[0] ?? null;
}

function selectCatalogOffer(body, required, assets) {
  const catalog = Array.isArray(body?.catalog) ? body.catalog : [];
  const maxAmount = taskUnits(required?.maxAdvertisedTotalPriceUsdcUnits, 'catalog_budget_invalid', { allowZero: false });
  const candidates = [];
  for (const resource of catalog) {
    if (resource?.dataType !== required.requiredDataType || !Array.isArray(resource.offers)) continue;
    for (const offer of resource.offers) {
      if (offerTermsMatch(offer, { resource, dataType: required.requiredDataType, assetId: required.assetId,
        network: required.network, recipient: required.recipient, maxAmount, assets })) {
        candidates.push({ resourceId: resource.resourceId, offerId: offer.id, fullCostUsdcUnits: paymentAmount(offer).toString() });
      }
    }
  }
  candidates.sort((left, right) => {
    const delta = BigInt(left.fullCostUsdcUnits) - BigInt(right.fullCostUsdcUnits);
    return delta < 0n ? -1 : delta > 0n ? 1 : (left.resourceId + '\0' + left.offerId).localeCompare(right.resourceId + '\0' + right.offerId);
  });
  return candidates[0] ?? null;
}

async function performPublicPaidComponent(context, task, component, constraints = {}) {
  constraints = { ...constraints, assets: task.execution.assets };
  const resourceId = component?.resourceId;
  demand(typeof resourceId === 'string' && resourceId.length > 0, 'paid_component_resource_id_unavailable');
  const inspected = constraints.inspectionResult ?? await submitLinkedTrainingAction(context, { kind: 'inspect_offer', resourceId,
    ...(constraints.offerId ? { offerId: constraints.offerId } : {}) }, false);
  const body = publicTaskBody(inspected, 'paid_component_inspect');
  demand(body.freeInspection === true && body.deliveryState === 'not_delivered' && body.resourceId === resourceId &&
    body.readHandle?.kind === 'offer' && body.readHandle.operationId === body.operationId && HEX_HASH.test(body.resourceSha256 ?? ''),
  'paid_component_inspection_binding_mismatch');
  const offer = constraints.offerId
    ? body.offers?.find((item) => item?.id === constraints.offerId && offerTermsMatch(item, { resource: body, ...constraints }))
    : selectPublicOffer(body, { resource: body, ...constraints });
  demand(offer && typeof offer.id === 'string' && offerTermsMatch(offer, { resource: body, ...constraints }),
    'paid_component_offer_not_selected_from_public_read');
  const cost = paymentAmount(offer);
  demand(cost !== null && cost > 0n, 'paid_component_cost_unavailable');
  const paidTotal = context.paidDataSpendUsdcUnits ?? 0n;
  if (constraints.remainingBudget !== undefined) {
    demand(paidTotal + cost <= constraints.remainingBudget, 'paid_component_budget_exceeded');
  }
  const paid = await submitLinkedTrainingAction(context, { kind: 'pay', resourceId, offerId: offer.id,
    offerReadActionId: inspected.action.actionId }, true);
  const receipt = publicTaskBody(paid, 'paid_component_payment');
  demand(receipt.status === 'payment_confirmed' && UUID.test(receipt.operationId ?? '') && receipt.deliveryHandle === receipt.operationId &&
    receipt.payment?.transactionHash?.toLowerCase() === paid.action.transactionHash?.toLowerCase() &&
    receipt.payment.receiptStatus === 'success' && receipt.payment.amount === offer.payment.amount &&
    receipt.payment.network === offer.payment.network && receipt.payment.payTo?.toLowerCase() === offer.payment.payTo?.toLowerCase() &&
    receipt.payment.asset?.toLowerCase() === offer.payment.asset?.toLowerCase(), 'paid_component_settlement_mismatch');
  const retrieved = await submitLinkedTrainingAction(context, { kind: 'retrieve', payActionId: paid.action.actionId }, false);
  const delivery = publicTaskBody(retrieved, 'paid_component_retrieval');
  demand(delivery.operationId === receipt.operationId && delivery.resourceId === resourceId &&
    delivery.contentType === body.contentType && delivery.contentHash === body.resourceSha256 && typeof delivery.contentBytes === 'string',
  'paid_component_delivery_binding_mismatch');
  const bytes = Buffer.from(delivery.contentBytes, 'base64');
  demand(bytes.length > 0 && bytes.length <= 1024 * 1024 && bytes.toString('base64') === delivery.contentBytes &&
    sha256(bytes) === body.resourceSha256 && eventPayloadHash(JSON.parse(bytes.toString('utf8'))) === eventPayloadHash(delivery.content),
  'paid_component_delivery_content_mismatch');
  context.paidDataSpendUsdcUnits = paidTotal + cost;
  const fact = { componentId: component.componentId ?? null, resourceId, offerId: offer.id, inspectActionId: inspected.action.actionId,
    payActionId: paid.action.actionId, retrieveActionId: retrieved.action.actionId, amountUnits: offer.payment.amount,
    contentSha256: body.resourceSha256, decodedBytes: bytes.length };
  context.output.paidDataActions ??= [];
  context.output.paidDataActions.push(fact);
  return { inspected, paid, retrieved, offer, content: delivery.content, contentBytes: bytes, resource: body, fact };
}

function participantAddressFromToolResponse(value) {
  const address = value?.receipt?.from ?? value?.transaction?.from ?? value?.selectedAction?.receipt?.from;
  return typeof address === 'string' && /^0x[0-9a-f]{40}$/i.test(address) ? address : null;
}

function readH3PublicReferenceField(reference, component, field) {
  const resource = taskObject(reference?.resource, 'h3_public_reference_resource_unavailable');
  const envelope = taskObject(reference?.content, 'h3_public_reference_envelope_unavailable');
  demand(typeof component?.resourceId === 'string' && resource.resourceId === component.resourceId &&
    envelope.resourceId === resource.resourceId && typeof resource.schema === 'string' && resource.schema.length > 0 &&
    envelope.schema === resource.schema, 'h3_public_reference_envelope_binding_mismatch');
  demand(typeof field === 'string' && field.length > 0, 'h3_public_reference_field_invalid');
  const path = field.split('.');
  demand(path.every((key) => key.length > 0), 'h3_public_reference_field_invalid');
  const content = taskObject(envelope.content, 'h3_public_reference_content_unavailable');
  return path.reduce((current, key) => current && typeof current === 'object' && !Array.isArray(current)
    ? current[key] : undefined, content);
}

function routeFor(conditions, inputAssetId, outputAssetId, routeId) {
  const routes = Array.isArray(conditions?.permittedRoutes) ? conditions.permittedRoutes : [];
  return routes.find((route) => route && route.tokenInAssetId === inputAssetId &&
    (!outputAssetId || route.tokenOutAssetId === outputAssetId) &&
    (!routeId || route.routeId === routeId)) ?? null;
}

async function performM3Actions(context, task) {
  const conditions = task.conditions;
  const route = routeFor(conditions, conditions.inputAssetId, 'WETH');
  demand(conditions.inputAssetId === 'USDC' && route && route.tokenOutAssetId === 'WETH', 'm3_permitted_route_unavailable');
  const approval = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: 'USDC',
    amountUnits: String(conditions.exactInputUnits), gasLimit: '100000' }, true);
  const recipient = participantAddressFromToolResponse(approval.apiPayload?.toolResponse);
  demand(recipient, 'm3_participant_receipt_address_unavailable');
  const swapped = await submitLinkedTrainingAction(context, { kind: 'swap', inputAssetId: 'USDC', outputAssetId: 'WETH',
    feeTier: route.feeTier, amountInUnits: String(conditions.exactInputUnits),
    amountOutMinimumUnits: String(conditions.minimumNativeOutputWei), recipient, gasLimit: '300000' }, true);
  const state = taskObject(swapped.apiPayload?.toolResponse?.after, 'm3_swap_after_state_unavailable');
  const before = taskObject(swapped.apiPayload?.toolResponse?.before, 'm3_swap_before_state_unavailable');
  const amountWei = taskUnits(state.payerWethUnits, 'm3_after_weth_balance_invalid') -
    taskUnits(before.payerWethUnits, 'm3_before_weth_balance_invalid');
  demand(amountWei > 0n, 'm3_observed_weth_delta_not_positive');
  const unwrapped = await submitLinkedTrainingAction(context, { kind: 'unwrap', amountWei: amountWei.toString(), gasLimit: '100000' }, true);
  return { actions: [approval, swapped, unwrapped] };
}

async function performM4Actions(context, task) {
  const conditions = task.conditions;
  const route = routeFor(conditions, conditions.inputAssetId, conditions.outputAssetId);
  const allowance = Array.isArray(conditions.initialAllowanceScope)
    ? conditions.initialAllowanceScope.find((item) => item?.tokenAssetId === conditions.inputAssetId && typeof item.spender === 'string') : null;
  const exactInput = taskUnits(conditions.exactInputUnits, 'm4_exact_input_invalid', { allowZero: false });
  demand(route && allowance, 'm4_permitted_route_or_cleanup_scope_unavailable');
  const wrapped = await submitLinkedTrainingAction(context, { kind: 'wrap', amountWei: exactInput.toString(), gasLimit: '100000' }, true);
  const recipient = participantAddressFromToolResponse(wrapped.apiPayload?.toolResponse);
  demand(recipient, 'm4_participant_receipt_address_unavailable');
  const overInput = (exactInput + 1n).toString();
  const approval = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: conditions.inputAssetId,
    amountUnits: overInput, gasLimit: '100000' }, true);
  const swapped = await submitLinkedTrainingAction(context, { kind: 'swap', inputAssetId: conditions.inputAssetId,
    outputAssetId: conditions.outputAssetId, feeTier: route.feeTier, amountInUnits: exactInput.toString(),
    amountOutMinimumUnits: String(conditions.minimumOutputUnits), recipient, gasLimit: '300000' }, true);
  const cleanup = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: conditions.inputAssetId,
    amountUnits: '0', gasLimit: '100000' }, true);
  return { actions: [wrapped, approval, swapped, cleanup] };
}

function stateBalance(state, assetId) {
  const key = assetId === 'USDC' ? 'payerUsdcUnits' : assetId === 'WETH' ? 'payerWethUnits'
    : assetId === 'ETH' ? 'payerNativeWei' : null;
  if (!key) return null;
  try { return taskUnits(state?.[key], 'u1_balance_invalid'); } catch { return null; }
}

async function performU1Actions(context, task) {
  const conditions = task.conditions;
  demand(Array.isArray(conditions.requiredComponents) && conditions.requiredComponents.length > 0 &&
    Array.isArray(conditions.payoutObligations) && conditions.payoutObligations.length > 0 &&
    Array.isArray(conditions.allocationAssets) && conditions.allocationAssets.length >= 2 &&
    Array.isArray(conditions.temporarySpenderScope) && conditions.temporarySpenderScope.length > 0,
  'u1_disclosed_plan_incomplete');
  const budget = taskUnits(conditions.expenseBudgetUsdcUnits, 'u1_budget_invalid', { allowZero: false });
  for (const component of conditions.requiredComponents) await performPublicPaidComponent(context, task, component,
    { sourceIds: component.sourceIds, remainingBudget: budget });
  let stateResponse = null;
  for (const scope of conditions.temporarySpenderScope) {
    demand(scope?.owner === 'participant' && ['USDC', 'WETH'].includes(scope.tokenAssetId) && /^0x[0-9a-f]{40}$/i.test(scope.spender ?? ''),
      'u1_cleanup_scope_invalid');
    const cleared = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: scope.tokenAssetId,
      amountUnits: '0', gasLimit: '100000' }, true);
    stateResponse = cleared.apiPayload?.toolResponse;
  }
  let state = taskObject(stateResponse?.after, 'u1_initial_public_state_unavailable');
  for (const obligation of conditions.payoutObligations) {
    demand(obligation.assetId === 'USDC' && /^0x[0-9a-f]{40}$/i.test(obligation.recipient ?? ''), 'u1_payout_asset_or_recipient_unsupported');
    taskUnits(obligation.exactAmountUnits, 'u1_payout_amount_invalid', { allowZero: false });
    const paid = await submitLinkedTrainingAction(context, { kind: 'transfer', amountUnits: String(obligation.exactAmountUnits),
      recipient: obligation.recipient, gasLimit: '100000' }, true);
    stateResponse = paid.apiPayload?.toolResponse;
    state = taskObject(stateResponse?.after, 'u1_post_payout_public_state_unavailable');
  }
  const allocations = conditions.allocationAssets;
  demand(allocations.every((asset) => ['USDC', 'ETH', 'WETH'].includes(asset.assetId) &&
    asset.usdcBaseUnitsPerAssetBaseUnit && /^(0|[1-9][0-9]*)$/.test(String(asset.usdcBaseUnitsPerAssetBaseUnit.numerator)) &&
    /^[1-9][0-9]*$/.test(String(asset.usdcBaseUnitsPerAssetBaseUnit.denominator)) &&
    Number.isInteger(asset.targetShareBps) && asset.targetShareBps >= 0 && asset.targetShareBps <= 10000 &&
    Number.isInteger(asset.toleranceBps) && asset.toleranceBps >= 0 && asset.toleranceBps <= 10000), 'u1_allocation_terms_invalid');
  const totalShare = allocations.reduce((sum, item) => sum + item.targetShareBps, 0);
  demand(totalShare === 10000, 'u1_allocation_share_total_invalid');
  const valued = allocations.map((item) => {
    const units = stateBalance(state, item.assetId);
    demand(units !== null, 'u1_allocation_state_unavailable');
    const numerator = BigInt(item.usdcBaseUnitsPerAssetBaseUnit.numerator);
    const denominator = BigInt(item.usdcBaseUnitsPerAssetBaseUnit.denominator);
    return { ...item, units, value: units * numerator / denominator, numerator, denominator };
  });
  const totalValue = valued.reduce((sum, item) => sum + item.value, 0n);
  demand(totalValue > 0n, 'u1_allocation_value_empty');
  let over = null, under = null;
  for (const item of valued) {
    const targetValue = totalValue * BigInt(item.targetShareBps) / 10000n;
    const difference = item.value - targetValue;
    const within = item.value === 0n ? targetValue === 0n :
      (difference >= 0n ? difference : -difference) * 10000n <= totalValue * BigInt(item.toleranceBps);
    if (!within && difference > 0n) over = { item, targetValue, difference };
    if (!within && difference < 0n) under = { item, targetValue, difference: -difference };
  }
  if (over && under) {
    // The public action protocol swaps ERC-20 assets; native ETH is reached through WETH.
    const routeOutputAssetId = under.item.assetId === 'ETH' ? 'WETH' : under.item.assetId;
    const route = routeFor(conditions, over.item.assetId, routeOutputAssetId);
    demand(route, 'u1_allocation_conversion_route_unavailable');
    const unwrapToEth = under.item.assetId === 'ETH' && route.tokenOutAssetId === 'WETH';
    demand(under.item.assetId !== 'ETH' || unwrapToEth, 'u1_native_allocation_requires_weth_bridge');
    const inputUnits = (over.difference * over.item.denominator + over.item.numerator - 1n) / over.item.numerator;
    demand(inputUnits > 0n && inputUnits <= over.item.units, 'u1_allocation_input_unavailable');
    const scope = conditions.temporarySpenderScope.find((item) => item.tokenAssetId === over.item.assetId);
    demand(scope, 'u1_conversion_allowance_scope_unavailable');
    const approval = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: over.item.assetId,
      amountUnits: inputUnits.toString(), gasLimit: '100000' }, true);
    const recipient = participantAddressFromToolResponse(approval.apiPayload?.toolResponse);
    demand(recipient, 'u1_participant_receipt_address_unavailable');
    const expectedOutput = inputUnits * over.item.numerator * under.item.denominator /
      (over.item.denominator * under.item.numerator);
    // Allocation tolerance is a final portfolio predicate, not a swap slippage setting.
    // The local reference actor budgets the disclosed route fee and 1% price movement.
    const afterFee = expectedOutput * (1000000n - BigInt(route.feeTier)) / 1000000n;
    const minimumOutput = afterFee * 9900n / 10000n;
    const swapped = await submitLinkedTrainingAction(context, { kind: 'swap', inputAssetId: over.item.assetId,
      outputAssetId: route.tokenOutAssetId, feeTier: route.feeTier, amountInUnits: inputUnits.toString(),
      amountOutMinimumUnits: minimumOutput.toString(), recipient, gasLimit: '300000' }, true);
    stateResponse = swapped.apiPayload?.toolResponse;
    state = taskObject(stateResponse?.after, 'u1_post_conversion_public_state_unavailable');
    if (unwrapToEth) {
      const before = taskObject(stateResponse?.before, 'u1_weth_bridge_before_state_unavailable');
      const beforeWeth = stateBalance(before, 'WETH');
      const afterWeth = stateBalance(state, 'WETH');
      demand(beforeWeth !== null && afterWeth !== null, 'u1_weth_bridge_balance_unavailable');
      const wethDelta = afterWeth - beforeWeth;
      demand(wethDelta > 0n, 'u1_weth_bridge_delta_not_positive');
      const unwrapped = await submitLinkedTrainingAction(context, { kind: 'unwrap', amountWei: wethDelta.toString(),
        gasLimit: '100000' }, true);
      stateResponse = unwrapped.apiPayload?.toolResponse;
      state = taskObject(stateResponse?.after, 'u1_post_unwrap_public_state_unavailable');
    }
  }
  for (const tokenAssetId of new Set(conditions.temporarySpenderScope.map((item) => item.tokenAssetId))) {
    const cleared = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId, amountUnits: '0', gasLimit: '100000' }, true);
    stateResponse = cleared.apiPayload?.toolResponse;
    state = taskObject(stateResponse?.after, 'u1_post_cleanup_public_state_unavailable');
  }
  const finalValued = allocations.map((item) => {
    const units = stateBalance(state, item.assetId);
    demand(units !== null, 'u1_final_allocation_state_unavailable');
    const ratio = item.usdcBaseUnitsPerAssetBaseUnit;
    const value = units * BigInt(ratio.numerator) / BigInt(ratio.denominator);
    return { assetId: item.assetId, value, targetShareBps: item.targetShareBps, toleranceBps: item.toleranceBps };
  });
  const finalTotalValue = finalValued.reduce((sum, item) => sum + item.value, 0n);
  const allocationWithinTolerance = finalTotalValue > 0n && finalValued.every((item) => {
    const target = finalTotalValue * BigInt(item.targetShareBps) / 10000n;
    const delta = item.value - target;
    const absoluteDelta = delta >= 0n ? delta : -delta;
    return absoluteDelta * 10000n <= finalTotalValue * BigInt(item.toleranceBps);
  });
  context.output.u1PublicPlan = { paidComponentCount: conditions.requiredComponents.length,
    payoutCount: conditions.payoutObligations.length, allocationAssetIds: allocations.map((item) => item.assetId),
    conversionObserved: Boolean(over && under), allocationWithinTolerance,
    cleanupScopes: conditions.temporarySpenderScope.map((item) => ({ tokenAssetId: item.tokenAssetId, spender: item.spender })) };
}
async function performGenuineActorActions(context, task) {
  const { taskId, output, record } = context;
  const conditions = task.conditions;
  const disclosure = { runId: context.runId, taskIndex: context.taskIndex, taskId, caseHash: task.caseHash,
    environmentId: task.environmentId, conditions };
  output.taskDisclosures ??= [];
  output.taskDisclosures.push(disclosure);
  if (output.taskIds.length === 1) output.taskDisclosure = disclosure;
  record('strict_preparation_start_and_agent_task_disclosure', 'verified', { taskIndex: context.taskIndex, taskId,
    environmentId: task.environmentId, mode: task.mode });
  let answer;
  if (taskId === 'S1') {
    demand(conditions?.tokenAssetId === 'USDC' && conditions?.sender === 'participant' && /^0x[0-9a-f]{40}$/i.test(conditions.recipient ?? ''),
      'issued_s1_conditions_malformed');
    taskUnits(conditions.exactPrincipalUnits, 'issued_s1_amount_malformed', { allowZero: false });
    taskUnits(conditions.nativeReserveWei, 'issued_s1_reserve_malformed', { allowZero: false });
    await submitLinkedTrainingAction(context, { kind: 'transfer', amountUnits: String(conditions.exactPrincipalUnits),
      recipient: conditions.recipient, gasLimit: '100000' }, true);
  } else if (taskId === 'S2') {
    demand(typeof conditions?.resourceId === 'string' && typeof conditions?.offerId === 'string', 'issued_s2_conditions_malformed');
    const inspected = await submitLinkedTrainingAction(context, { kind: 'inspect_offer', resourceId: conditions.resourceId }, false);
    answer = answerFromPublicS2Read(task, publicTaskBody(inspected, 's2_public_offer'));

  } else if (taskId === 'S3') {
    const inspected = await submitLinkedTrainingAction(context, { kind: 'inspect_catalog' }, false);
    const body = publicTaskBody(inspected, 's3_public_catalog');
    const selected = selectCatalogOffer(body, conditions.required, task.execution.assets);
    demand(selected, 's3_required_offer_not_in_public_catalog');
    answer = { offerId: selected.offerId };
    output.s3PublicSelection = { inspectActionId: inspected.action.actionId, resourceId: selected.resourceId,
      offerId: selected.offerId, selectedFromPublicCatalog: true };
  } else if (taskId === 'S4') {
    demand(conditions?.tokenAssetId === 'USDC' && conditions?.owner === 'participant' && /^0x[0-9a-f]{40}$/i.test(conditions.spender ?? ''),
      'issued_s4_conditions_unsupported');
    await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: conditions.tokenAssetId,
      amountUnits: '0', gasLimit: '100000' }, true);
  } else if (taskId === 'M1') {
    demand(task.participantToolProtocol === 'separate_payment_delivery_v2' && conditions?.component && conditions?.paymentScope &&
      typeof conditions.paymentScope.offerId === 'string', 'issued_m1_conditions_unsupported');
    await performPublicPaidComponent(context, task, conditions.component, { offerId: conditions.paymentScope.offerId,
      network: conditions.paymentScope.network, recipient: conditions.paymentScope.recipient,
      assetId: conditions.paymentScope.assetId, scheme: conditions.paymentScope.scheme,
      remainingBudget: taskUnits(conditions.expenseBudgetUsdcUnits, 'm1_budget_invalid', { allowZero: false }) });
  } else if (taskId === 'M2') {
    const inspected = await submitLinkedTrainingAction(context, { kind: 'inspect_catalog' }, false);
    const selected = selectCatalogOffer(publicTaskBody(inspected, 'm2_public_catalog'), conditions.required, task.execution.assets);
    demand(selected, 'm2_no_public_offer_matches_conditions');
    const paid = await performPublicPaidComponent(context, task, { resourceId: selected.resourceId }, { offerId: selected.offerId,
      dataType: conditions.required.requiredDataType, assetId: conditions.required.assetId,
      network: conditions.required.network, recipient: conditions.required.recipient,
      remainingBudget: taskUnits(conditions.expenseBudgetUsdcUnits, 'm2_budget_invalid', { allowZero: false }) });
    output.m2PublicSelection = { catalogActionId: inspected.action.actionId, resourceId: selected.resourceId, offerId: selected.offerId,
      fullCostUsdcUnits: selected.fullCostUsdcUnits, retrievedContentSha256: paid.fact.contentSha256 };
  } else if (taskId === 'M3') {
    await performM3Actions(context, task);
  } else if (taskId === 'M4') {
    await performM4Actions(context, task);
  } else if (taskId === 'H1') {
    demand(Array.isArray(conditions.requiredComponents) && conditions.requiredComponents.length > 0, 'h1_components_unavailable');
    const budget = taskUnits(conditions.expenseBudgetUsdcUnits, 'h1_budget_invalid', { allowZero: false });
    for (const component of conditions.requiredComponents) await performPublicPaidComponent(context, task, component,
      { sourceIds: component.sourceIds, remainingBudget: budget });
  } else if (taskId === 'H2') {
    demand(Array.isArray(conditions.obligations) && conditions.obligations.length === 6, 'h2_six_disclosed_payouts_unavailable');
    for (const obligation of conditions.obligations) {
      demand(obligation.assetId === 'USDC' && /^0x[0-9a-f]{40}$/i.test(obligation.recipient ?? ''), 'h2_payout_scope_unsupported');
      taskUnits(obligation.exactAmountUnits, 'h2_payout_amount_invalid', { allowZero: false });
      await submitLinkedTrainingAction(context, { kind: 'transfer', amountUnits: obligation.exactAmountUnits,
        recipient: obligation.recipient, gasLimit: '100000' }, true);
    }
  } else if (taskId === 'H3') {
    const component = conditions.referenceComponent;
    const budget = taskUnits(conditions.combinedExpenseBudgetUsdcUnits, 'h3_budget_invalid', { allowZero: false });
    const reference = await performPublicPaidComponent(context, task, component,
      { sourceIds: component?.sourceIds, remainingBudget: budget });
    const field = String(conditions.routeObjective?.referenceField ?? '');
    const value = readH3PublicReferenceField(reference, component, field);
    const mapped = conditions.routeObjective?.expectedRouteByValue?.find((item) => item?.value === value);
    demand(mapped && conditions.routeObjective.allowedRouteIds?.includes(mapped.routeId), 'h3_public_reference_route_unmapped');
    const route = routeFor(conditions, conditions.inputAssetId, undefined, mapped.routeId);
    demand(route, 'h3_reference_selected_route_unavailable');
    const exactInput = taskUnits(conditions.exactInputUnits, 'h3_exact_input_invalid', { allowZero: false });
    if (conditions.inputAssetId === 'WETH') await submitLinkedTrainingAction(context, { kind: 'wrap', amountWei: exactInput.toString(), gasLimit: '100000' }, true);
    const approval = await submitLinkedTrainingAction(context, { kind: 'approve', tokenAssetId: conditions.inputAssetId,
      amountUnits: exactInput.toString(), gasLimit: '100000' }, true);
    const recipient = participantAddressFromToolResponse(approval.apiPayload?.toolResponse);
    demand(recipient, 'h3_participant_receipt_address_unavailable');
    await submitLinkedTrainingAction(context, { kind: 'swap', inputAssetId: conditions.inputAssetId,
      outputAssetId: route.tokenOutAssetId, feeTier: route.feeTier, amountInUnits: exactInput.toString(),
      amountOutMinimumUnits: String(conditions.minimumOutputUnits), recipient, gasLimit: '300000' }, true);
    output.h3PublicRouteChoice = { componentId: component.componentId, resourceId: component.resourceId,
      contentField: field, routeId: route.routeId, selectedFromRetrievedContent: true };
  } else if (taskId === 'U1') {
    await performU1Actions(context, task);
  } else {
    throw fail('unsupported_genuine_task');
  }
  return { answer };
}

async function createObserverPorts({ repositoryRoot, runId, environmentId, taskId = 'S1', taskIndex = 0 }) {
  let password = (await readFile('/run/secrets/bef_database_observer_password', 'utf8')).trim();
  demand(password.length >= 16 && !/[\r\n\u0000]/.test(password), 'bef_observer_credential_unavailable');
  const databaseUrl = new URL('postgres://bef_observer@host.docker.internal:' + (process.env.BEF_DATABASE_HOST_PORT || '55432') + '/bef');
  databaseUrl.password = password;
  const befPool = new Pool({ connectionString: databaseUrl.href, max: 2, application_name: 'genuine-s1-bef-observer' });
  password = '';
  const postgresPort = {
    environmentId,
    async withRepeatableRead(callback) {
      const client = await befPool.connect();
      try {
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        const rows = await client.query('SELECT current_user AS role,current_setting(\'transaction_read_only\') AS readonly');
        if (rows.rows[0]?.role !== 'bef_observer' || rows.rows[0]?.readonly !== 'on') throw fail('bef_observer_role_invalid');
        const result = await callback(async (statement, parameters = []) => {
          const value = await client.query(statement, parameters);
          return value.rows;
        });
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      } finally { client.release(); }
    },
    async readFenceProof({ preparationId, generationId }) {
      return postgresPort.withRepeatableRead(async (query) => {
        const rows = await query(`SELECT g.generation_id::text,g.env_id,g.status AS generation_status,g.fenced_at::text,
            p.preparation_id::text,p.status AS preparation_status,p.fence_confirmed_at::text,
            p.generation_id::text AS preparation_generation_id,p.public_pins_sha256,p.manifest_sha256,
            trim(e.manifest_sha256) AS environment_manifest_sha256
          FROM public.bef_generation g
          JOIN public.bef_preparation p ON p.env_id=g.env_id AND p.generation_id=g.generation_id
          JOIN public.bef_environment e ON e.env_id=g.env_id
          WHERE g.env_id=$1 AND g.generation_id=$2::uuid AND p.preparation_id=$3::uuid`,
        [environmentId, generationId, preparationId]);
        return pgRows(rows);
      });
    },
    async readPreparedProof({ preparationId, generationId }) {
      return postgresPort.withRepeatableRead(async (query) => {
        const rows = await query(`SELECT g.generation_id::text,g.env_id,g.status AS generation_status,
            p.preparation_id::text,p.status AS preparation_status,p.generation_id::text AS preparation_generation_id,
            p.public_pins_sha256,p.manifest_sha256,trim(e.manifest_sha256) AS environment_manifest_sha256
          FROM public.bef_generation g
          JOIN public.bef_preparation p ON p.env_id=g.env_id AND p.generation_id=g.generation_id
          JOIN public.bef_environment e ON e.env_id=g.env_id
          WHERE g.env_id=$1 AND g.generation_id=$2::uuid AND p.preparation_id=$3::uuid`,
        [environmentId, generationId, preparationId]);
        return pgRows(rows);
      });
    },
  };
  const rpcUrl = 'http://host.docker.internal:' + (process.env.BEF_LOCAL_RPC_A_HOST_PORT || '18545');
  let rpcId = 0;
  const rpcPort = {
    environmentId,
    async request(method, params) {
      if (!new Set(['eth_blockNumber', 'eth_call', 'eth_chainId', 'eth_getBalance', 'eth_getBlockByNumber',
        'eth_getCode', 'eth_getLogs', 'eth_getTransactionByHash', 'eth_getTransactionCount', 'eth_getTransactionReceipt']).has(method)) {
        throw fail('rpc_method_not_allowlisted');
      }
      let response;
      try {
        response = await fetch(rpcUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(20_000),
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
      } catch { throw fail('rpc_observation_transport_unavailable'); }
      if (!response.ok) throw fail('rpc_observation_http_unavailable');
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.length > 4 * 1024 * 1024) throw fail('rpc_observation_response_oversized');
      let payload;
      try { payload = JSON.parse(bytes.toString('utf8')); } catch { throw fail('rpc_observation_response_invalid'); }
      if (payload?.jsonrpc !== '2.0' || payload.id !== rpcId || payload.error || !Object.prototype.hasOwnProperty.call(payload, 'result')) {
        throw fail('rpc_observation_result_unavailable');
      }
      return payload.result;
    },
  };
  const evidenceSink = {
    async write(packet) {
      const bytes = Buffer.from(JSON.stringify(packet));
      demand(bytes.length <= 8 * 1024 * 1024, 'observation_packet_oversized');
      assertSecretFree(packet, 'genuine-s1-observation-packet');
      const observationRoot = 'artifacts/runs/owner-identity-bef-task-coordinator/observation';
      const directory = resolve(repositoryRoot, observationRoot);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const name = runId + '-' + taskId.toLowerCase() + '-' + taskIndex + '-observer-packet.json';
      const path = resolve(directory, name);
      await writeFile(path, Buffer.concat([bytes, Buffer.from('\n')]), { flag: 'wx', mode: 0o600 });
      return { path: observationRoot + '/' + name, sha256: sha256(Buffer.concat([bytes, Buffer.from('\n')])), boundary: BOUNDARY };
    },
  };
  return { postgresByEnvironment: { [environmentId]: postgresPort }, rpcByEnvironment: { [environmentId]: rpcPort }, evidenceSink,
    close: () => befPool.end() };
}

async function readOwnerRunCompletionState(observerPool, { runId, ownerId, includeRanked = false }) {
  return readonlyTransaction(observerPool, async (query) => {
    const run = pgRows(await query(`SELECT id::text,owner_id::text,agent_id::text,mode,status,started_at::text,finished_at::text,quote_price_units::text,manifest_hash,benchmark_version,release_identity,benchmark_hash,policy_hash
      FROM oid_benchmark_run WHERE id=$1 AND owner_id=$2`, [runId, ownerId]));
    const tasks = pgRows(await query(`SELECT task_index,task_id,status,finished_at FROM oid_run_task
      WHERE run_id=$1 ORDER BY task_index`, [runId]));
    const completionEvents = pgRows(await query(`SELECT id::text,sequence::text,source,event_type,payload_hash,payload_json,created_at::text
      FROM oid_run_event WHERE run_id=$1 AND event_type='run.completed' ORDER BY sequence`, [runId]));
    const terminalizationEvents = pgRows(await query(`SELECT id::text,sequence::text,source,event_type,payload_hash,payload_json
      FROM oid_run_event WHERE run_id=$1 AND event_type='task.terminalized' ORDER BY sequence`, [runId]));
    const evaluations = pgRows(await query(`SELECT task_index,task_id,input_hash,result_hash,evaluator_source_hash,result_json
      FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index`, [runId])).map((row) => {
      let result = null;
      try { result = typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json; } catch { /* Hashes remain usable. */ }
      return { task_index: row.task_index, task_id: row.task_id, input_hash: row.input_hash, result_hash: row.result_hash,
        evaluator_source_hash: row.evaluator_source_hash, result_status: result?.status ?? null, outcome: result?.outcome ?? null,
        credit: result?.credit ?? null };
    });
    const claims = pgRows(await query(`SELECT claim_id::text,status,released_at::text FROM oid_run_dispatch_claim WHERE run_id=$1`, [runId]));
    const slots = pgRows(await query(`SELECT run_id::text,agent_id::text,claim_id::text,state,released_at::text
      FROM oid_run_execution_slot WHERE run_id=$1`, [runId]));
    const reservations = pgRows(await query(`SELECT id::text,source_kind,bonus_grant_id::text,cash_provenance,amount_units::text,state
      FROM oid_run_reservation WHERE run_id=$1 ORDER BY id`, [runId]));
    const budgetHolds = pgRows(await query(`SELECT run_id::text,mode,utc_day,amount_units::text,state
      FROM oid_run_budget_hold WHERE run_id=$1 ORDER BY run_id`, [runId]));
    const operationIds = ['runacc_' + runId.replaceAll('-', ''), 'rundeb_' + runId.replaceAll('-', ''),
      'runrel_' + runId.replaceAll('-', '')];
    const ledger = pgRows(await query(`SELECT id::text,entry_type,source_kind,operation_id,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,bonus_grant_id::text,cash_provenance,reason
      FROM oid_ledger_entry WHERE owner_id=$1 AND operation_id=ANY($2::text[]) ORDER BY operation_id,id`, [ownerId, operationIds]));
    const bonusSourceGrants = pgRows(await query(`SELECT g.id::text AS grant_id,g.owner_id::text AS grant_owner_id,
        g.amount_units::text AS grant_amount_units,g.issued_by_owner_id::text AS grant_issuer_owner_id,
        g.operation_id AS grant_operation_id,redemption.id::text AS redemption_id,
        redemption.owner_id::text AS redemption_owner_id,redemption.code_id::text AS redemption_code_id,
        redemption.financial_operation_id AS redemption_financial_operation_id,
        code.id::text AS code_id,code.issuer_owner_id::text AS code_issuer_owner_id,code.kind AS code_kind,
        code.amount_units::text AS code_amount_units,code.maximum_uses AS code_maximum_uses,
        code.used_count AS code_used_count,code.issue_operation_id AS code_issue_operation_id,
        claims.operation_ids AS claim_operation_ids,claims.payload_hashes AS claim_payload_hashes,
        claims.operation_count AS claim_operation_count
      FROM oid_run_reservation reservation
      JOIN oid_bonus_grant g ON g.id=reservation.bonus_grant_id AND g.owner_id=reservation.owner_id
      LEFT JOIN oid_bonus_code_redemption redemption ON redemption.bonus_grant_id=g.id AND redemption.owner_id=g.owner_id
      LEFT JOIN oid_bonus_code code ON code.id=redemption.code_id
      LEFT JOIN LATERAL (
        SELECT array_agg(claim.operation_id ORDER BY claim.created_at,claim.operation_id) AS operation_ids,
          array_agg(claim.payload_hash ORDER BY claim.created_at,claim.operation_id) AS payload_hashes,
          count(*)::int AS operation_count
        FROM oid_bonus_code_claim_operation claim
        WHERE claim.redemption_id=redemption.id AND claim.owner_id=redemption.owner_id AND claim.code_id=redemption.code_id
      ) claims ON TRUE
      WHERE reservation.run_id=$1 AND reservation.owner_id=$2 AND reservation.source_kind='tester_bonus'
      ORDER BY g.id`, [runId, ownerId]));
    const runRefundOperationId = 'runref_' + runId.replaceAll('-', '');
    const runRefundPrefix = runRefundOperationId + '_';
    const runRefundLedger = pgRows(await query(`SELECT id::text,entry_type,source_kind,operation_id,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,reason
      FROM oid_ledger_entry WHERE owner_id=$1 AND entry_type='refund' AND
        (operation_id=$2 OR left(operation_id,length($3))=$3) ORDER BY operation_id,id`,
    [ownerId, runRefundOperationId, runRefundPrefix]));
    const ownerLedger = pgRows(await query(`SELECT id::text,entry_type,source_kind,operation_id,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,bonus_grant_id::text,reason
      FROM oid_ledger_entry WHERE owner_id=$1 ORDER BY created_at,id`, [ownerId]));
    const rankedEligibilityEvents = includeRanked ? pgRows(await query(`SELECT id::text,sequence::text,source,event_type,payload_hash,payload_json,created_at::text
      FROM oid_run_event WHERE run_id=$1 AND event_type='run.ranked_eligible' ORDER BY sequence`, [runId])) : [];
    const rankedVersionSnapshots = includeRanked ? pgRows(await query(`SELECT run_id::text,owner_id::text,agent_id::text,snapshot_hash,snapshot_json,created_at::text
      FROM oid_ranked_run_version_snapshot WHERE run_id=$1`, [runId])) : [];
    const rankedHandoffs = includeRanked ? pgRows(await query(`SELECT run_id::text,owner_id::text,agent_id::text,benchmark_version,manifest_hash,
        version_snapshot_hash,aggregate_hash,completion_event_hash,handoff_hash,handoff_json
      FROM oid_ranked_run_handoff WHERE run_id=$1`, [runId])) : [];
    const rankedResults = includeRanked ? pgRows(await query(`SELECT run_id::text,owner_id::text,agent_id::text,benchmark_version,aggregate_hash,
        aggregate_json,version_snapshot_hash,version_snapshot_json
      FROM oid_ranked_verified_result WHERE run_id=$1`, [runId])) : [];
    const rankedBestResults = includeRanked ? pgRows(await query(`SELECT benchmark_version,agent_id::text,run_id::text
      FROM oid_ranked_best_result WHERE run_id=$1`, [runId])) : [];
    const rankedFirstActionMarkers = includeRanked ? pgRows(await query(`SELECT agent_id::text,owner_id::text,source_kind,source_id,source_hash
      FROM oid_agent_first_public_action WHERE source_kind='ranked_run' AND source_id=$1`, [runId])) : [];
    const parseJson = (value) => {
      if (typeof value !== 'string') return value;
      try { return JSON.parse(value); } catch { return null; }
    };
    for (const row of rankedVersionSnapshots) row.snapshot_json = parseJson(row.snapshot_json);
    for (const row of rankedHandoffs) row.handoff_json = parseJson(row.handoff_json);
    for (const row of rankedResults) {
      row.aggregate_json = parseJson(row.aggregate_json);
      row.version_snapshot_json = parseJson(row.version_snapshot_json);
    }
    const projection = { run: run[0] ?? null, tasks, evaluations, terminalizationEvents, completionEvents, rankedEligibilityEvents,
      rankedVersionSnapshots, rankedHandoffs, rankedResults, rankedBestResults, rankedFirstActionMarkers, claims, slots, reservations, budgetHolds, ledger,
      bonusSourceGrants,
      runRefundLedger, runRefundCount: runRefundLedger.length,
      ownerLedgerSha256: digest(Buffer.from(JSON.stringify(ownerLedger))), ownerLedgerCount: ownerLedger.length,
      ownerRefundCount: ownerLedger.filter((row) => row.entry_type === 'refund').length };
    const runMoney = { reservations, budgetHolds, ledger, runRefundLedger };
    const money = { ...runMoney, ownerLedger };
    return { ...projection, runMoneySha256: digest(Buffer.from(JSON.stringify(runMoney))),
      moneySha256: digest(Buffer.from(JSON.stringify(money))),
      stateSha256: digest(Buffer.from(JSON.stringify(projection))) };
  });
}

const POSITIVE_UNITS = /^[1-9]\d*$/;
const NONNEGATIVE_UNITS = /^(?:0|[1-9]\d*)$/;
const OPERATION_ID = /^[A-Za-z0-9_-]{12,128}$/;

function sourceKey(sourceKind, grantId, cashProvenance) {
  return JSON.stringify([sourceKind, grantId ?? null, cashProvenance ?? null]);
}

function verifyFundingLedgerRow(row, reservation, expectedOperationId, entryType) {
  const amount = BigInt(reservation.amount_units);
  const expectedAvailable = entryType === 'reserve' ? (-amount).toString() : '0';
  const expectedReserved = entryType === 'reserve' ? amount.toString() : (-amount).toString();
  return row.entry_type === entryType && row.operation_id === expectedOperationId &&
    row.source_kind === reservation.source_kind &&
    (row.bonus_grant_id ?? null) === (reservation.bonus_grant_id ?? null) &&
    (row.cash_provenance ?? null) === (reservation.cash_provenance ?? null) &&
    row.amount_units === reservation.amount_units && row.available_delta_units === expectedAvailable &&
    row.reserved_delta_units === expectedReserved && row.expired_delta_units === '0';
}

/** Verify all per-run reservation lots and their reserve/debit ledger rows against the exact quote. */
export function verifyRunFundingConservation({ runId, quoteUnits, reservations, ledger }) {
  demand(UUID.test(runId ?? '') && POSITIVE_UNITS.test(String(quoteUnits ?? '')) &&
    Array.isArray(reservations) && reservations.length > 0 && Array.isArray(ledger),
  'worker_run_funding_observation_invalid');
  const reserveOperationId = 'runacc_' + runId.replaceAll('-', '');
  const debitOperationId = 'rundeb_' + runId.replaceAll('-', '');
  const seenSources = new Set();
  let reservedUnits = 0n;
  for (const reservation of reservations) {
    const amountText = String(reservation?.amount_units ?? '');
    demand(reservation?.state === 'debited' && POSITIVE_UNITS.test(amountText) &&
      ((reservation.source_kind === 'tester_bonus' && UUID.test(reservation.bonus_grant_id ?? '') &&
        (reservation.cash_provenance ?? null) === null) ||
       (reservation.source_kind === 'cash_usdc' && reservation.bonus_grant_id == null &&
        typeof reservation.cash_provenance === 'string' && reservation.cash_provenance.length > 0)),
    'worker_run_reservation_source_invalid');
    const key = sourceKey(reservation.source_kind, reservation.bonus_grant_id, reservation.cash_provenance);
    demand(!seenSources.has(key), 'worker_run_reservation_source_duplicate');
    seenSources.add(key);
    reservedUnits += BigInt(amountText);
    const reserveRows = ledger.filter((row) => sourceKey(row.source_kind, row.bonus_grant_id, row.cash_provenance) === key &&
      row.entry_type === 'reserve');
    const debitRows = ledger.filter((row) => sourceKey(row.source_kind, row.bonus_grant_id, row.cash_provenance) === key &&
      row.entry_type === 'debit');
    demand(reserveRows.length === 1 && debitRows.length === 1 &&
      verifyFundingLedgerRow(reserveRows[0], reservation, reserveOperationId, 'reserve') &&
      verifyFundingLedgerRow(debitRows[0], reservation, debitOperationId, 'debit'),
    'worker_run_reservation_ledger_binding_invalid');
  }
  demand(reservedUnits === BigInt(quoteUnits) && ledger.length === reservations.length * 2 &&
    ledger.every((row) => row.entry_type === 'reserve' || row.entry_type === 'debit'),
  'worker_run_funding_quote_or_ledger_total_mismatch');
  return {
    status: 'verified', runId, quoteUnits: String(quoteUnits), reservationUnits: reservedUnits.toString(),
    reservationCount: reservations.length, reserveEntryCount: reservations.length, debitEntryCount: reservations.length,
    bonusReservationCount: reservations.filter((row) => row.source_kind === 'tester_bonus').length,
    cashReservationCount: reservations.filter((row) => row.source_kind === 'cash_usdc').length,
    allSourcesAreBonus: reservations.every((row) => row.source_kind === 'tester_bonus'),
  };
}

/** Verify each FIFO-consumed bonus lot against its immutable issued-code and redemption records. */
export function verifyCodeDerivedBonusFunding({ ownerId, reservations, sourceGrants, issuedGrant }) {
  demand(UUID.test(ownerId ?? '') && Array.isArray(reservations) && reservations.length > 0 &&
    reservations.every((row) => row.source_kind === 'tester_bonus') && Array.isArray(sourceGrants) && issuedGrant,
  'worker_run_bonus_code_funding_input_invalid');
  const issuedCode = issuedGrant.database?.code;
  const issuedRedemption = issuedGrant.database?.redemption;
  const issuedGrantRow = issuedGrant.database?.grant;
  const balanceDelta = issuedGrant.database?.fundingBalanceDelta;
  const issuedGrantId = issuedGrant.grantId;
  const issuedCodeId = issuedGrant.issue?.codeId;
  const issuedRedemptionId = issuedGrant.redemption?.redemptionId;
  const issuedGrantOperationId = issuedGrant.grantOperationId;
  const issuedCodeOperationId = issuedGrant.issue?.operationId;
  const issuedRedemptionOperationId = issuedGrant.redemption?.operationId;
  const issuedAmountUnits = String(issuedGrant.amountUnits ?? '');
  const previousBalanceUnits = String(balanceDelta?.beforeUnits ?? '');
  demand(UUID.test(issuedGrantId ?? '') && UUID.test(issuedCodeId ?? '') && UUID.test(issuedRedemptionId ?? '') &&
    OPERATION_ID.test(issuedGrantOperationId ?? '') && OPERATION_ID.test(issuedCodeOperationId ?? '') &&
    OPERATION_ID.test(issuedRedemptionOperationId ?? '') && POSITIVE_UNITS.test(issuedAmountUnits) &&
    issuedGrant.database?.ledgerConserved === true && balanceDelta?.verified === true &&
    NONNEGATIVE_UNITS.test(previousBalanceUnits),
  'worker_run_new_code_grant_balance_baseline_invalid');
  demand(POSITIVE_UNITS.test(String(balanceDelta.afterUnits ?? '')) &&
    BigInt(balanceDelta.afterUnits) - BigInt(balanceDelta.beforeUnits) === BigInt(issuedAmountUnits) &&
    balanceDelta.deltaUnits === issuedAmountUnits && issuedGrant.database?.cashEffectCount === 0 &&
    issuedCode?.id === issuedCodeId && issuedCode.kind === 'single_use' && issuedCode.maximum_uses === 1 &&
    issuedCode.issue_operation_id === issuedCodeOperationId && issuedCode.amount_units === issuedAmountUnits &&
    issuedCode.used_count === 1 && issuedGrant.issue?.status === 201 &&
    issuedRedemption?.id === issuedRedemptionId && issuedGrant.redemption?.redemptionId === issuedRedemptionId &&
    issuedGrant.redemption?.grantId === issuedGrantId &&
    issuedGrant.redemption?.operationId === issuedRedemptionOperationId &&
    UUID.test(issuedCode.issuer_owner_id ?? '') && UUID.test(issuedGrantRow?.issued_by_owner_id ?? '') &&
    issuedRedemption.owner_id === ownerId && issuedRedemption.code_id === issuedCodeId &&
    issuedRedemption.bonus_grant_id === issuedGrantId && issuedRedemption.financial_operation_id === issuedGrantOperationId &&
    issuedGrantRow?.id === issuedGrantId && issuedGrantRow.owner_id === ownerId &&
    issuedGrantRow.issued_by_owner_id === issuedCode.issuer_owner_id &&
    issuedGrantRow.operation_id === issuedGrantOperationId && issuedGrantRow.amount_units === issuedAmountUnits &&
    issuedGrant.database?.grantEntry?.bonus_grant_id === issuedGrantId &&
    issuedGrant.database?.grantEntry?.source_kind === 'tester_bonus' &&
    issuedGrant.database?.grantEntry?.available_delta_units === issuedAmountUnits,
  'worker_run_new_code_grant_delta_or_lineage_invalid');

  const reservationsByGrant = new Map();
  for (const reservation of reservations) {
    const grantId = reservation.bonus_grant_id;
    demand(UUID.test(grantId ?? '') && POSITIVE_UNITS.test(String(reservation.amount_units ?? '')),
      'worker_run_bonus_reservation_invalid');
    reservationsByGrant.set(grantId, (reservationsByGrant.get(grantId) ?? 0n) + BigInt(reservation.amount_units));
  }
  const grantRowsById = new Map();
  for (const row of sourceGrants) {
    demand(row && UUID.test(row.grant_id ?? '') && !grantRowsById.has(row.grant_id),
      'worker_run_bonus_grant_observation_duplicate');
    grantRowsById.set(row.grant_id, row);
  }
  demand(grantRowsById.size === reservationsByGrant.size && [...reservationsByGrant.keys()].every((id) => grantRowsById.has(id)),
    'worker_run_bonus_grant_observation_incomplete');

  const codeDerivedSourceGrants = [];
  for (const [grantId, reservationUnits] of reservationsByGrant) {
    const row = grantRowsById.get(grantId);
    const claimOperationIds = Array.isArray(row.claim_operation_ids) ? row.claim_operation_ids : [];
    const claimPayloadHashes = Array.isArray(row.claim_payload_hashes) ? row.claim_payload_hashes : [];
    const grantAmount = String(row.grant_amount_units ?? '');
    const codeAmount = String(row.code_amount_units ?? '');
    demand(row.grant_owner_id === ownerId && row.redemption_owner_id === ownerId &&
      UUID.test(row.grant_issuer_owner_id ?? '') && UUID.test(row.code_issuer_owner_id ?? '') &&
      row.grant_issuer_owner_id === row.code_issuer_owner_id && UUID.test(row.redemption_id ?? '') &&
      UUID.test(row.code_id ?? '') &&
      row.redemption_code_id === row.code_id && row.redemption_financial_operation_id === row.grant_operation_id &&
      (row.code_kind === 'single_use' || row.code_kind === 'group'),
    'worker_run_bonus_grant_code_binding_invalid');
    demand(POSITIVE_UNITS.test(grantAmount) && grantAmount === codeAmount &&
      POSITIVE_UNITS.test(String(reservationUnits)) && reservationUnits <= BigInt(grantAmount) &&
      Number.isSafeInteger(row.code_maximum_uses) && row.code_maximum_uses > 0 &&
      Number.isSafeInteger(row.code_used_count) && row.code_used_count > 0 && row.code_used_count <= row.code_maximum_uses &&
      OPERATION_ID.test(row.grant_operation_id ?? '') && OPERATION_ID.test(row.code_issue_operation_id ?? '') &&
      claimOperationIds.length > 0 && claimOperationIds.length === claimPayloadHashes.length &&
      claimOperationIds.every((id) => OPERATION_ID.test(id)) && new Set(claimOperationIds).size === claimOperationIds.length &&
      claimPayloadHashes.every((hash) => HEX_HASH.test(hash ?? '')),
    'worker_run_bonus_grant_redemption_lineage_invalid');
    codeDerivedSourceGrants.push({ grantId, ownerId, grantAmountUnits: grantAmount,
      reservationUnits: reservationUnits.toString(), codeId: row.code_id, codeKind: row.code_kind,
      codeAmountUnits: codeAmount, codeIssueOperationIdSha256: digest(Buffer.from(row.code_issue_operation_id)),
      redemptionId: row.redemption_id,
      redemptionFinancialOperationIdSha256: digest(Buffer.from(row.redemption_financial_operation_id)),
      claimOperationCount: claimOperationIds.length,
      claimOperationIdSha256s: claimOperationIds.map((id) => digest(Buffer.from(id))),
      claimPayloadHashes: claimPayloadHashes });
  }
  const latestIssuedRow = grantRowsById.get(issuedGrantId);
  const consumedLatestIssuedGrant = reservationsByGrant.has(issuedGrantId);
  if (consumedLatestIssuedGrant) {
    const claimOperationIds = latestIssuedRow.claim_operation_ids ?? [];
    demand(latestIssuedRow.code_id === issuedCodeId && latestIssuedRow.redemption_id === issuedRedemptionId &&
      latestIssuedRow.grant_operation_id === issuedGrantOperationId &&
      latestIssuedRow.code_issue_operation_id === issuedCodeOperationId &&
      claimOperationIds.includes(issuedRedemptionOperationId) &&
      reservationsByGrant.get(issuedGrantId) <= BigInt(issuedAmountUnits),
    'worker_run_latest_code_grant_receipt_mismatch');
  }
  return {
    status: 'verified', codeDerivedSourceGrants, consumedLatestIssuedGrant,
    newlyIssuedGrantConsumedUnits: (reservationsByGrant.get(issuedGrantId) ?? 0n).toString(),
    newlyIssuedGrantAvailableDeltaUnits: balanceDelta.deltaUnits,
    newlyIssuedGrant: { grantId: issuedGrantId, codeId: issuedCodeId, redemptionId: issuedRedemptionId,
      amountUnits: issuedAmountUnits, grantOperationIdSha256: digest(Buffer.from(issuedGrantOperationId)),
      codeIssueOperationIdSha256: digest(Buffer.from(issuedCodeOperationId)),
      redemptionOperationIdSha256: digest(Buffer.from(issuedRedemptionOperationId)),
      availableDeltaUnits: balanceDelta.deltaUnits,
      consumedUnits: (reservationsByGrant.get(issuedGrantId) ?? 0n).toString(), consumedLatestIssuedGrant },
    bonusGrantIdMatchesCodeReceipt: consumedLatestIssuedGrant,
  };
}

export function automaticWorkerChargeUnchanged(initial, current) {
  const currentRunId = current?.run?.id ?? current?.runId;
  return Boolean(initial && current && UUID.test(initial.runId ?? '') && initial.runId === currentRunId &&
    HEX_HASH.test(initial.moneySha256 ?? '') && current.moneySha256 === initial.moneySha256 &&
    Number.isSafeInteger(initial.ownerRefundCount) && initial.ownerRefundCount >= 0 &&
    current.ownerRefundCount === initial.ownerRefundCount &&
    initial.runRefundCount === 0 && current.runRefundCount === 0);
}

export function automaticWorkerCallbackFinancialBoundaryUnchanged(before, after, { runId, callbackName } = {}) {
  if (callbackName !== 'onGenuineFirstTaskActive' || !UUID.test(runId ?? '') || !before || !after) return false;
  const validHash = (value) => HEX_HASH.test(value ?? '');
  const activeBinding = (state) => {
    const run = state?.run;
    const claims = state?.claims;
    const slots = state?.slots;
    if (run?.id !== runId || run.status !== 'running' || !UUID.test(run.owner_id ?? '') ||
        !UUID.test(run.agent_id ?? '') || !Array.isArray(claims) || claims.length !== 1 ||
        !Array.isArray(slots) || slots.length !== 1) return null;
    const claim = claims[0];
    const slot = slots[0];
    if (!UUID.test(claim?.claim_id ?? '') || claim.status !== 'claimed' || claim.released_at != null ||
        slot?.run_id !== runId || slot.agent_id !== run.agent_id || slot.claim_id !== claim.claim_id ||
        slot.state !== 'running' || slot.released_at != null) return null;
    return { ownerId: run.owner_id, agentId: run.agent_id, claimId: claim.claim_id,
      claimStatus: claim.status, slotRunId: slot.run_id, slotAgentId: slot.agent_id,
      slotClaimId: slot.claim_id, slotState: slot.state };
  };
  const beforeBinding = activeBinding(before);
  const afterBinding = activeBinding(after);
  return Boolean(beforeBinding && afterBinding &&
    before.runMoneySha256 && validHash(before.runMoneySha256) &&
    after.runMoneySha256 === before.runMoneySha256 &&
    validHash(before.moneySha256) && validHash(after.moneySha256) &&
    validHash(before.ownerLedgerSha256) && validHash(after.ownerLedgerSha256) &&
    Number.isSafeInteger(before.ownerLedgerCount) && before.ownerLedgerCount >= 0 &&
    Number.isSafeInteger(after.ownerLedgerCount) && after.ownerLedgerCount >= 0 &&
    Number.isSafeInteger(before.ownerRefundCount) && before.ownerRefundCount >= 0 &&
    after.ownerRefundCount === before.ownerRefundCount &&
    before.runRefundCount === 0 && after.runRefundCount === 0 &&
    JSON.stringify(beforeBinding) === JSON.stringify(afterBinding));
}

async function readOwnerTrainingFeedback(ownerPage, runId, expectedResult) {
  try {
    const response = await ownerPage.request.get('/api/owner/runs/' + encodeURIComponent(runId) + '/results', { timeout: 15_000 });
    if (response.status() !== 200) return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_http_unavailable' };
    let body;
    try { body = await response.json(); } catch { return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_body_invalid' }; }
    if (!body || body.status !== 'available' || !Array.isArray(body.tasks)) {
      return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_projection_unavailable' };
    }
    const matching = body.tasks.filter((item) => item && item.taskId === expectedResult.taskId);
    if (matching.length !== 1) return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_task_missing_or_ambiguous' };
    const actual = matching[0];
    const actualCredit = actual.credit ?? null;
    const expectedCredit = expectedResult.credit ?? null;
    return { status: 'observed', httpStatus: response.status(), taskId: expectedResult.taskId, taskStatus: actual.status,
      outcome: actual.outcome, credit: actualCredit,
      consistentWithInternalEvaluation: actual.status === expectedResult.status && actual.outcome === expectedResult.outcome &&
        JSON.stringify(actualCredit) === JSON.stringify(expectedCredit) };
  } catch (error) {
    return { status: 'unknown', reasonCode: safeErrorCode(error, 'owner_feedback_unavailable') };
  }
}

async function readOwnerTrainingFeedbackTasks(ownerPage, runId, expectedResults) {
  try {
    const response = await ownerPage.request.get('/api/owner/runs/' + encodeURIComponent(runId) + '/results', { timeout: 15_000 });
    if (response.status() !== 200) return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_http_unavailable' };
    const body = await response.json().catch(() => null);
    if (!body || body.status !== 'available' || !Array.isArray(body.tasks)) {
      return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_projection_unavailable' };
    }
    const taskIds = expectedResults.map((item) => item.taskId);
    if (new Set(taskIds).size !== taskIds.length || body.tasks.length !== expectedResults.length) {
      return { status: 'unknown', httpStatus: response.status(), reasonCode: 'owner_feedback_task_set_mismatch' };
    }
    const tasks = expectedResults.map((expected) => {
      const matches = body.tasks.filter((item) => item && item.taskId === expected.taskId);
      if (matches.length !== 1) return { taskId: expected.taskId, consistentWithInternalEvaluation: false };
      const actual = matches[0];
      return { taskId: expected.taskId, status: actual.status, outcome: actual.outcome, credit: actual.credit ?? null,
        consistentWithInternalEvaluation: actual.status === expected.status && actual.outcome === expected.outcome &&
          JSON.stringify(actual.credit ?? null) === JSON.stringify(expected.credit ?? null) };
    });
    return { status: 'observed', httpStatus: response.status(), tasks,
      consistentWithInternalEvaluation: tasks.every((item) => item.consistentWithInternalEvaluation) };
  } catch (error) {
    return { status: 'unknown', reasonCode: safeErrorCode(error, 'owner_feedback_unavailable') };
  }
}

async function verifyTrainingSuccessorActivation({ input, record, observerPool, runId, task, taskIds, transition,
  oldOverallDeadline, release, priorTaskResult, predecessorTerminalization, dispatchIdentity }) {
  const timestampMillis = (value) => value instanceof Date ? value.getTime() : Date.parse(value ?? '');
  const taskIndex = transition?.toTaskIndex;
  const predecessorIndex = transition?.fromTaskIndex;
  const predecessorTaskId = transition?.fromTaskId;
  const taskId = transition?.toTaskId;
  demand(Number.isSafeInteger(taskIndex) && taskIndex > 0 && predecessorIndex === taskIndex - 1 &&
    taskIds?.[predecessorIndex] === predecessorTaskId && taskIds?.[taskIndex] === taskId &&
    task.taskIndex === taskIndex && task.taskId === taskId && task.mode === 'training',
  'successor_public_task_binding_mismatch');
  const snapshot = await readRunSnapshot(observerPool, { runId });
  const run = snapshot.run[0];
  const successor = snapshot.tasks.find((item) => item.task_index === taskIndex);
  const predecessor = snapshot.tasks.find((item) => item.task_index === predecessorIndex);
  const execution = snapshot.execution.find((item) => item.task_index === taskIndex);
  const preparation = snapshot.preparations.find((item) => item.task_index === taskIndex);
  const activatedEvents = snapshot.runEvents.filter((event) => event.eventType === 'task.activated');
  const activationMatches = activatedEvents.filter((event) => event.payload?.toTaskIndex === taskIndex);
  const startedEvents = snapshot.runEvents.filter((event) => event.eventType === 'run.started');
  const allTerminalizationEvents = snapshot.runEvents.filter((event) => event.eventType === 'task.terminalized');
  const terminalizationEvents = allTerminalizationEvents.filter((event) => event.payload?.taskIndex === predecessorIndex);
  const transitionBasis = trainingSequenceTransitionBasis({ taskIds, transition, runStartedEvents: startedEvents,
    activationEvents: activatedEvents, terminalizationEvents: allTerminalizationEvents, initialOverallDeadline: oldOverallDeadline });
  const activationEvent = transitionBasis.activationEvent;
  const payload = activationEvent?.payload;
  const priorActivation = transitionBasis.priorActivationEvent;
  const taskCase = release.trainingTasks.find((entry) => entry.taskId === taskId);
  const finishedAt = timestampMillis(predecessorTerminalization?.finishedAt ?? '');
  const activatedAt = timestampMillis(payload?.activatedAt ?? '');
  const previousDeadlineValue = transitionBasis.previousDeadlineValue;
  const previousDeadline = transitionBasis.previousDeadline;
  const currentDeadline = timestampMillis(run?.overall_deadline ?? '');
  const interval = activatedAt - finishedAt;
  const expectedDeadline = previousDeadline + interval;
  const expectedTaskDeadline = Math.min(activatedAt + Number(taskCase?.taskDeadlineSeconds) * 1000, expectedDeadline);
  const previousTransitionEvent = transitionBasis.previousTransitionEvent;
  const activationConditions = [
    ['running training run', () => Boolean(run?.mode === 'training' && run?.status === 'running' && run.finished_at == null)],
    ['one authoritative run start', () => Boolean(startedEvents.length === 1 && run.started_at)],
    ['selected task rows retain pinned order', () => JSON.stringify(run.task_ids) === JSON.stringify(taskIds) &&
      snapshot.tasks.length === taskIds.length && snapshot.tasks.every((item, index) =>
        item.task_index === index && item.task_id === taskIds[index])],
    ['preparation rows cover only the reached task prefix', () => snapshot.preparations.length === taskIndex + 1 &&
      snapshot.preparations.every((item, index) => item.task_index === index)],
    ['execution rows cover only the reached task prefix', () => snapshot.execution.length === taskIndex + 1 &&
      snapshot.execution.every((item, index) => item.task_index === index)],
    ['evaluations cover every completed predecessor', () => snapshot.evaluation.length === taskIndex &&
      snapshot.evaluation.every((item, index) => item.taskIndex === index)],
    ['one terminalization per completed predecessor', () => allTerminalizationEvents.length === taskIndex &&
      allTerminalizationEvents.every((event, index) => event.payload?.taskIndex === index)],
    ['activation events cover the reached successor prefix', () => activatedEvents.length === taskIndex &&
      activatedEvents.every((event, index) => event.payload?.toTaskIndex === index + 1) && activationMatches.length === 1],
    ['predecessor terminalization agrees with reconstructed result and row', () =>
      predecessorTerminalization?.taskIndex === predecessorIndex && predecessorTerminalization?.taskId === predecessorTaskId &&
      predecessorTerminalization?.outcome === priorTaskResult?.outcome &&
      predecessorTerminalization?.closureId === predecessor?.closure_id],
    ['run start, predecessor terminalization and current activation are ordered', () =>
      BigInt(previousTransitionEvent.sequence) < BigInt(terminalizationEvents[0].sequence) &&
      BigInt(terminalizationEvents[0].sequence) < BigInt(activationEvent.sequence)],
    ['start identity and initial deadline are stable', () => startedEvents[0].source === 'coordinator' &&
      startedEvents[0].runId === runId && startedEvents[0].payload?.taskId === taskIds[0] &&
      (taskIndex !== 1 || (startedEvents[0].payload?.environmentId === predecessorTerminalization.environmentId &&
        timestampMillis(startedEvents[0].payload?.overallDeadline ?? '') === timestampMillis(oldOverallDeadline)))],
    ['predecessor was terminalized with its reconstructed outcome', () =>
      predecessor?.task_id === predecessorTaskId &&
      predecessor?.status === (priorTaskResult.outcome === 'failed' ? 'failed' : 'completed') &&
      predecessor?.finished_at && timestampMillis(predecessor.finished_at) === finishedAt &&
      terminalizationEvents.length === 1],
    ['current selected task is active', () => successor?.task_id === taskId && successor.status === 'active' && successor.started_at],
    ['current preparation and execution share a leased generation', () => Boolean(execution && preparation &&
      preparation.task_id === taskId && preparation.preparation_status === 'ready' && preparation.lease_state === 'leased' &&
      preparation.observed_generation_id === execution.generation_id && preparation.environment_id === execution.env_id &&
      preparation.case_id === execution.case_id && preparation.case_hash === execution.case_hash &&
      task.caseHash === execution.case_hash && preparation.initial_state_sha256 === execution.initial_state_sha256 &&
      run.environment_id === preparation.environment_id && execution.preparation_id === preparation.preparation_id &&
      execution.lease_id === preparation.lease_id && execution.lease_state === 'leased' &&
      UUID.test(preparation.preparation_id) && UUID.test(preparation.lease_id) && UUID.test(execution.generation_id))],
    ['current activation event binds this exact adjacent transition', () => activationEvent.source === 'coordinator' &&
      activationEvent.payloadHash === eventPayloadHash(payload) && payload?.runId === runId &&
      payload.fromTaskIndex === predecessorIndex && payload.toTaskIndex === taskIndex &&
      payload.fromTaskId === predecessorTaskId && payload.toTaskId === taskId],
    ['pinned training successor policy is retained', () =>
      payload.successorPreparationPolicyVersion === 'local-bef-successor-preparation/v1' &&
      payload.successorPreparationTimeoutSeconds === 180 &&
      run.successor_preparation_policy_version === payload.successorPreparationPolicyVersion &&
      Number(run.successor_preparation_timeout_seconds) === payload.successorPreparationTimeoutSeconds &&
      run.intent_successor_preparation_policy_version === payload.successorPreparationPolicyVersion &&
      Number(run.intent_successor_preparation_timeout_seconds) === payload.successorPreparationTimeoutSeconds],
    ['bounded preparation interval extends the correct prior deadline', () =>
      Number.isFinite(finishedAt) && Number.isFinite(activatedAt) && Number.isFinite(previousDeadline) &&
      interval >= 0 && interval <= 180_000 && payload.preparationIntervalMilliseconds === interval &&
      timestampMillis(payload.predecessorFinishedAt) === finishedAt &&
      timestampMillis(payload.previousOverallDeadline) === previousDeadline &&
      timestampMillis(payload.overallDeadline) === expectedDeadline && currentDeadline === expectedDeadline &&
      Number.isSafeInteger(Number(taskCase?.taskDeadlineSeconds)) &&
      timestampMillis(payload.taskDeadline) === expectedTaskDeadline &&
      timestampMillis(successor.deadline_at) === expectedTaskDeadline],
    ['activation receipt binds the independently observed predecessor terminalization', () =>
      payload.predecessorReceipt?.inputHash === predecessorTerminalization.inputHash &&
      payload.predecessorReceipt?.resultHash === predecessorTerminalization.resultHash &&
      payload.predecessorReceipt?.closureId === predecessorTerminalization.closureId &&
      payload.predecessorReceipt?.outcome === predecessorTerminalization.outcome &&
      payload.predecessorReceipt?.preparationId === predecessorTerminalization.preparationId &&
      payload.predecessorReceipt?.leaseId === predecessorTerminalization.leaseId &&
      payload.predecessorReceipt?.generationId === predecessorTerminalization.generationId &&
      payload.predecessorReceipt?.fenceEvidenceHash === predecessorTerminalization.fenceEvidenceHash],
    ['activation preparation and execution binding match persisted owner rows', () =>
      payload.preparation?.preparationId === preparation.preparation_id &&
      payload.preparation?.leaseId === preparation.lease_id &&
      payload.preparation?.environmentId === preparation.environment_id &&
      payload.preparation?.generationId === execution.generation_id &&
      payload.preparation?.environmentManifestSha256 === preparation.environment_manifest_sha256 &&
      payload.preparation?.applicationSourceHash === preparation.application_source_hash &&
      payload.binding?.runId === runId && payload.binding?.taskIndex === taskIndex &&
      payload.binding?.generationId === execution.generation_id && payload.binding?.envId === execution.env_id &&
      payload.binding?.manifestHash === preparation.environment_manifest_sha256 &&
      payload.binding?.applicationSourceHash === preparation.application_source_hash &&
      payload.binding?.participantId === (execution.participant_id ?? null) &&
      payload.binding?.payerAddress === (execution.payer_address?.toLowerCase() ?? null)],
  ];
  const failedConditions = activationConditions.filter(([, check]) => {
    try { return !check(); } catch { return true; }
  }).map(([condition]) => condition);
  if (failedConditions.length) {
    const error = fail('successor_activation_event_or_deadline_readback_mismatch');
    error.safeDiagnostic = { failedConditions };
    throw error;
  }
  const dispatch = await readOwnerRunCompletionState(observerPool, { runId, ownerId: run.owner_id });
  demand(dispatch.claims.length === 1 && dispatch.claims[0].status === 'claimed' &&
    dispatch.claims[0].claim_id === dispatchIdentity?.claimId && dispatch.slots.length === 1 &&
    dispatch.slots[0].state === 'running' && dispatch.slots[0].run_id === dispatchIdentity.slotRunId &&
    dispatch.slots[0].agent_id === dispatchIdentity.slotAgentId && dispatch.slots[0].claim_id === dispatchIdentity.slotClaimId,
  'successor_dispatch_claim_or_slot_changed');

  const { postgresByEnvironment, close } = await createObserverPorts({ repositoryRoot: input.repoRoot, runId,
    environmentId: preparation.environment_id, taskId, taskIndex });
  try {
    const rows = await postgresByEnvironment[preparation.environment_id].readPreparedProof({
      preparationId: preparation.preparation_id, generationId: execution.generation_id });
    const bef = rows[0];
    demand(rows.length === 1 && bef.preparation_id === preparation.preparation_id &&
      bef.generation_id === execution.generation_id && bef.env_id === preparation.environment_id &&
      bef.preparation_status === 'ready' && bef.generation_status === 'active' &&
      bef.environment_manifest_sha256 === release.environmentManifestSha256,
    'successor_bef_preparation_readback_mismatch');
    const originalFence = predecessorTerminalization;
    const oldObserver = await createObserverPorts({ repositoryRoot: input.repoRoot, runId,
      environmentId: originalFence.environmentId, taskId: predecessorTaskId, taskIndex: predecessorIndex });
    let oldFence;
    try {
      const oldRows = await oldObserver.postgresByEnvironment[originalFence.environmentId].readFenceProof({
        preparationId: originalFence.preparationId, generationId: originalFence.generationId });
      oldFence = oldRows[0];
      demand(oldRows.length === 1 && oldFence.generation_status === 'fenced' && oldFence.preparation_status === 'fenced' &&
        oldFence.preparation_generation_id === originalFence.generationId,
      'predecessor_generation_fence_changed_after_successor_activation');
    } finally { await oldObserver.close(); }
    const verified = { fromTaskIndex: predecessorIndex, fromTaskId: predecessorTaskId,
      taskIndex, taskId, preparationId: preparation.preparation_id, leaseId: preparation.lease_id,
      environmentId: preparation.environment_id, generationId: execution.generation_id,
      binding: { manifestHash: execution.manifest_hash, applicationSourceHash: execution.application_source_hash },
      predecessorFinishedAt: new Date(finishedAt).toISOString(), activatedAt: new Date(activatedAt).toISOString(),
      preparationIntervalMilliseconds: interval, previousOverallDeadline: new Date(previousDeadline).toISOString(),
      overallDeadline: new Date(expectedDeadline).toISOString(), taskDeadline: new Date(expectedTaskDeadline).toISOString(),
      policyVersion: payload.successorPreparationPolicyVersion, policyTimeoutSeconds: payload.successorPreparationTimeoutSeconds,
      activationEventSequence: activationEvent.sequence, predecessorTerminalizationEventSequence: terminalizationEvents[0].sequence,
      dispatchClaimId: dispatch.claims[0].claim_id, slotRunId: dispatch.slots[0].run_id,
      slotAgentId: dispatch.slots[0].agent_id, slotClaimId: dispatch.slots[0].claim_id,
      runStartedEvents: startedEvents.length, activationEvents: activatedEvents.length,
      ownerPreparationStatus: preparation.preparation_status, ownerLeaseStatus: preparation.lease_state,
      befPreparationStatus: bef.preparation_status, befGenerationStatus: bef.generation_status,
      predecessorGenerationStatus: oldFence.generation_status,
      oldGenerationFenceStillAuthoritative: predecessorTerminalization.generationId !== execution.generation_id };
    const activationResult = trainingSuccessorActivationResult({ transition, proof: verified });
    record('server_successor_activation_and_independent_owner_bef_readback', 'verified', activationResult);
    return activationResult;
  } finally { await close(); }
}
async function verifyRankedSuccessorActivation({ input, record, observerPool, runId, task,
  release, predecessorTerminalization, priorTaskResult, dispatchIdentity }) {
  const timestampMillis = (value) => value instanceof Date ? value.getTime() : Date.parse(value ?? '');
  const taskIndex = task.taskIndex;
  demand(Number.isSafeInteger(taskIndex) && taskIndex > 0 && task.mode === 'ranked' &&
    task.taskId === RANKED_TASK_IDS[taskIndex], 'ranked_successor_public_task_binding_mismatch');
  const snapshot = await readRunSnapshot(observerPool, { runId });
  const run = snapshot.run[0];
  const predecessorIndex = taskIndex - 1;
  const predecessorTaskId = RANKED_TASK_IDS[predecessorIndex];
  const predecessor = snapshot.tasks.find((item) => item.task_index === predecessorIndex);
  const successor = snapshot.tasks.find((item) => item.task_index === taskIndex);
  const predecessorExecution = snapshot.execution.find((item) => item.task_index === predecessorIndex);
  const predecessorPreparation = snapshot.preparations.find((item) => item.task_index === predecessorIndex);
  const execution = snapshot.execution.find((item) => item.task_index === taskIndex);
  const preparation = snapshot.preparations.find((item) => item.task_index === taskIndex);
  const activatedEvents = snapshot.runEvents.filter((event) => event.eventType === 'task.activated');
  const activationMatches = activatedEvents.filter((event) => event.payload?.toTaskIndex === taskIndex);
  const activationEvent = activationMatches[0];
  const payload = activationEvent?.payload;
  const taskCase = release.rankedTasks?.[taskIndex];
  const startedEvents = snapshot.runEvents.filter((event) => event.eventType === 'run.started');
  const terminalizationEvents = snapshot.runEvents.filter((event) => event.eventType === 'task.terminalized');
  const predecessorEvents = terminalizationEvents.filter((event) => event.payload?.taskIndex === predecessorIndex);
  const predecessorEvent = predecessorEvents[0];
  const finishedAt = timestampMillis(predecessorTerminalization?.finishedAt ?? '');
  const activatedAt = timestampMillis(payload?.activatedAt ?? '');
  const priorActivation = taskIndex === 1 ? null : activatedEvents.find((event) =>
    event.payload?.toTaskIndex === predecessorIndex);
  const startedDeadline = startedEvents[0]?.payload?.overallDeadline;
  const previousDeadlineValue = taskIndex === 1 ? startedDeadline : priorActivation?.payload?.overallDeadline;
  const previousDeadline = timestampMillis(previousDeadlineValue ?? '');
  const currentDeadline = timestampMillis(run?.overall_deadline ?? '');
  const interval = activatedAt - finishedAt;
  const timeoutSeconds = Number(run?.successor_preparation_timeout_seconds);
  const expectedDeadline = previousDeadline + interval;
  const expectedTaskDeadline = Math.min(activatedAt + Number(taskCase?.taskDeadlineSeconds) * 1000, expectedDeadline);
  const conditions = [
    ['ranked running run with no cancellation', () => run?.mode === 'ranked' && run.status === 'running' &&
      run.cancellation_reason === null && run.finished_at == null],
    ['immutable ordered task list', () => JSON.stringify(run.task_ids) === JSON.stringify(RANKED_TASK_IDS) &&
      snapshot.tasks.length === RANKED_TASK_IDS.length && snapshot.tasks.every((row, index) =>
        row.task_index === index && row.task_id === RANKED_TASK_IDS[index])],
    ['one start event and one activation per reached successor', () => startedEvents.length === 1 &&
      activatedEvents.length === taskIndex && activationMatches.length === 1 &&
      activatedEvents.every((event, index) => event.payload?.toTaskIndex === index + 1)],
    ['one indexed terminalization per predecessor', () => terminalizationEvents.length === taskIndex &&
      predecessorEvents.length === 1 && terminalizationEvents.every((event, index) => event.payload?.taskIndex === index)],
    ['predecessor terminalization agrees with worker and persisted result', () =>
      predecessorTerminalization?.status === 'verified' && predecessorTerminalization.taskIndex === predecessorIndex &&
      predecessorTerminalization.taskId === predecessorTaskId && priorTaskResult?.taskIndex === predecessorIndex &&
      priorTaskResult?.taskId === predecessorTaskId && predecessorTerminalization.outcome === priorTaskResult.result?.outcome &&
      predecessorTerminalization.inputHash === priorTaskResult.inputHash && predecessorTerminalization.resultHash === priorTaskResult.resultHash &&
      predecessorTerminalization.closureId === predecessor?.closure_id && predecessorTerminalization.finishedAt != null],
    ['predecessor owner preparation and execution rows retain the fenced identity', () =>
      Boolean(predecessorPreparation && predecessorExecution) && predecessorPreparation.task_id === predecessorTaskId &&
      predecessorPreparation.preparation_id === predecessorTerminalization.preparationId &&
      predecessorPreparation.lease_id === predecessorTerminalization.leaseId &&
      predecessorPreparation.environment_id === predecessorTerminalization.environmentId &&
      predecessorPreparation.observed_generation_id === predecessorTerminalization.generationId &&
      predecessorPreparation.preparation_status === 'fenced' && predecessorPreparation.lease_state === 'fenced' &&
      predecessorExecution.generation_id === predecessorTerminalization.generationId &&
      predecessorExecution.lease_state === 'fenced'],
    ['event order is start, predecessor activation, predecessor terminalization, successor activation', () =>
      BigInt(startedEvents[0]?.sequence ?? 0) < BigInt(predecessorEvent?.sequence ?? 0) &&
      (taskIndex === 1 || BigInt(priorActivation?.sequence ?? 0) < BigInt(predecessorEvent?.sequence ?? 0)) &&
      BigInt(predecessorEvent?.sequence ?? 0) < BigInt(activationEvent?.sequence ?? 0)],
    ['start event binds the first task and initial deadline', () => startedEvents[0]?.source === 'coordinator' &&
      startedEvents[0]?.runId === runId &&
      timestampMillis(startedEvents[0]?.payload?.startedAt ?? '') === timestampMillis(run.started_at ?? '') &&
      startedEvents[0]?.payload?.taskId === RANKED_TASK_IDS[0] &&
      Number.isFinite(timestampMillis(startedEvents[0]?.payload?.overallDeadline ?? '')) &&
      startedEvents[0]?.payloadHash === eventPayloadHash(startedEvents[0]?.payload)],
    ['predecessor task is terminal with the verified closure', () =>
      ['completed', 'failed'].includes(predecessor?.status) && predecessor.finished_at != null &&
      timestampMillis(predecessor.finished_at) === finishedAt && predecessorEvent?.source === 'coordinator' &&
      predecessorEvent?.payloadHash === eventPayloadHash(predecessorEvent.payload) &&
      predecessorEvent?.payload?.runId === runId && predecessorEvent?.payload?.taskId === predecessorTaskId &&
      predecessorEvent?.payload?.inputHash === predecessorTerminalization.inputHash &&
      predecessorEvent?.payload?.resultHash === predecessorTerminalization.resultHash &&
      predecessorEvent?.payload?.outcome === predecessorTerminalization.outcome &&
      predecessorEvent?.payload?.status === predecessor.status &&
      predecessorEvent?.payload?.closureId === predecessorTerminalization.closureId &&
      predecessorEvent?.payload?.finishedAt === predecessorTerminalization.finishedAt &&
      predecessorEvent?.payload?.preparationId === predecessorTerminalization.preparationId &&
      predecessorEvent?.payload?.leaseId === predecessorTerminalization.leaseId &&
      predecessorEvent?.payload?.generationId === predecessorTerminalization.generationId &&
      predecessorEvent?.payload?.fenceEvidenceHash === predecessorTerminalization.fenceEvidenceHash],
    ['successor row is the currently issued active task', () => successor?.task_id === task.taskId &&
      successor.status === 'active' && successor.started_at != null && taskCase?.taskId === task.taskId &&
      taskCase?.caseHash === execution?.case_hash &&
      timestampMillis(successor.started_at) === activatedAt && task.caseHash === execution?.case_hash],
    ['current owner preparation, lease and execution binding agree', () => Boolean(execution && preparation) &&
      preparation.task_id === task.taskId && preparation.preparation_status === 'ready' && preparation.lease_state === 'leased' &&
      preparation.observed_generation_id === execution.generation_id && preparation.environment_id === execution.env_id &&
      preparation.case_id === execution.case_id && preparation.case_hash === execution.case_hash &&
      preparation.initial_state_sha256 === execution.initial_state_sha256 && execution.preparation_id === preparation.preparation_id &&
      execution.lease_id === preparation.lease_id && execution.lease_state === 'leased' &&
      UUID.test(preparation.preparation_id) && UUID.test(preparation.lease_id) && UUID.test(execution.generation_id)],
    ['activation event binds adjacent task identities and canonical payload', () => activationEvent?.source === 'coordinator' &&
      activationEvent.payloadHash === eventPayloadHash(payload) && payload?.runId === runId &&
      payload.fromTaskIndex === predecessorIndex && payload.toTaskIndex === taskIndex &&
      payload.fromTaskId === predecessorTaskId && payload.toTaskId === task.taskId],
    ['predecessor receipt binds terminalization proof', () => {
      const receipt = payload?.predecessorReceipt;
      return receipt?.inputHash === predecessorTerminalization.inputHash && receipt?.resultHash === predecessorTerminalization.resultHash &&
        receipt?.closureId === predecessorTerminalization.closureId && receipt?.outcome === predecessorTerminalization.outcome &&
        receipt?.preparationId === predecessorTerminalization.preparationId && receipt?.leaseId === predecessorTerminalization.leaseId &&
        receipt?.generationId === predecessorTerminalization.generationId && receipt?.fenceEvidenceHash === predecessorTerminalization.fenceEvidenceHash;
    }],
    ['event preparation and execution binding match the owner rows', () => {
      const prepared = payload?.preparation, binding = payload?.binding;
      return prepared?.preparationId === preparation?.preparation_id && prepared?.leaseId === preparation?.lease_id &&
        prepared?.environmentId === preparation?.environment_id && prepared?.generationId === execution?.generation_id &&
        prepared?.environmentManifestSha256 === preparation?.environment_manifest_sha256 &&
        prepared?.applicationSourceHash === preparation?.application_source_hash &&
        binding?.runId === runId && binding?.taskIndex === taskIndex && binding?.generationId === execution?.generation_id &&
        binding?.envId === execution?.env_id && binding?.manifestHash === preparation?.environment_manifest_sha256 &&
        binding?.applicationSourceHash === preparation?.application_source_hash &&
        binding?.participantId === (execution?.participant_id ?? null) &&
        binding?.payerAddress === (execution?.payer_address?.toLowerCase() ?? null);
    }],
    ['pinned successor preparation policy is preserved', () =>
      run.successor_preparation_policy_version === 'local-bef-successor-preparation/v1' &&
      run.intent_successor_preparation_policy_version === run.successor_preparation_policy_version &&
      Number.isSafeInteger(timeoutSeconds) && timeoutSeconds > 0 &&
      Number(payload?.successorPreparationTimeoutSeconds) === timeoutSeconds &&
      payload?.successorPreparationPolicyVersion === run.successor_preparation_policy_version],
    ['successor preparation interval and run/task deadlines are exact', () =>
      Number.isFinite(finishedAt) && Number.isFinite(activatedAt) && Number.isFinite(previousDeadline) &&
      finishedAt < previousDeadline && interval >= 0 && interval <= timeoutSeconds * 1000 &&
      payload?.preparationIntervalMilliseconds === interval &&
      timestampMillis(payload?.predecessorFinishedAt ?? '') === finishedAt &&
      timestampMillis(payload?.previousOverallDeadline ?? '') === previousDeadline &&
      timestampMillis(payload?.overallDeadline ?? '') === expectedDeadline && currentDeadline === expectedDeadline &&
      Number.isSafeInteger(Number(taskCase?.taskDeadlineSeconds)) &&
      timestampMillis(payload?.taskDeadline ?? '') === expectedTaskDeadline &&
      timestampMillis(successor?.deadline_at ?? '') === expectedTaskDeadline],
  ];
  const failedConditions = conditions.filter(([, check]) => {
    try { return !check(); } catch { return true; }
  }).map(([condition]) => condition);
  if (failedConditions.length) {
    const error = fail('ranked_successor_activation_event_or_deadline_readback_mismatch');
    error.safeDiagnostic = { taskIndex, failedConditions };
    throw error;
  }

  const dispatch = await readOwnerRunCompletionState(observerPool, { runId, ownerId: run.owner_id });
  demand(dispatch.claims.length === 1 && dispatch.claims[0].status === 'claimed' &&
    dispatch.claims[0].claim_id === dispatchIdentity?.claimId && dispatch.slots.length === 1 &&
    dispatch.slots[0].state === 'running' && dispatch.slots[0].run_id === dispatchIdentity.slotRunId &&
    dispatch.slots[0].agent_id === dispatchIdentity.slotAgentId && dispatch.slots[0].claim_id === dispatchIdentity.slotClaimId,
  'ranked_successor_dispatch_claim_or_slot_changed');

  const { postgresByEnvironment, close } = await createObserverPorts({ repositoryRoot: input.repoRoot, runId,
    environmentId: preparation.environment_id, taskId: task.taskId, taskIndex });
  try {
    const rows = await postgresByEnvironment[preparation.environment_id].readPreparedProof({
      preparationId: preparation.preparation_id, generationId: execution.generation_id });
    const bef = rows[0];
    demand(rows.length === 1 && bef.preparation_id === preparation.preparation_id &&
      bef.generation_id === execution.generation_id && bef.env_id === preparation.environment_id &&
      bef.preparation_status === 'ready' && bef.generation_status === 'active' &&
      bef.environment_manifest_sha256 === release.environmentManifestSha256 &&
      preparation.environment_manifest_sha256 === release.environmentManifestSha256,
    'ranked_successor_bef_preparation_readback_mismatch');
    const oldObserver = await createObserverPorts({ repositoryRoot: input.repoRoot, runId,
      environmentId: predecessorPreparation.environment_id, taskId: predecessorTaskId, taskIndex: predecessorIndex });
    let oldFence;
    try {
      const oldRows = await oldObserver.postgresByEnvironment[predecessorPreparation.environment_id].readFenceProof({
        preparationId: predecessorPreparation.preparation_id, generationId: predecessorExecution.generation_id });
      oldFence = oldRows[0];
      demand(oldRows.length === 1 && oldFence.generation_status === 'fenced' && oldFence.preparation_status === 'fenced' &&
        oldFence.preparation_generation_id === predecessorExecution.generation_id && oldFence.env_id === predecessorPreparation.environment_id,
      'ranked_predecessor_generation_fence_changed_after_successor_activation');
    } finally { await oldObserver.close(); }
    const verified = { taskIndex, taskId: task.taskId, predecessorTaskIndex: predecessorIndex, predecessorTaskId,
      preparationId: preparation.preparation_id, leaseId: preparation.lease_id,
      environmentId: preparation.environment_id, generationId: execution.generation_id,
      binding: { manifestHash: execution.manifest_hash, applicationSourceHash: execution.application_source_hash },
      predecessorFinishedAt: new Date(finishedAt).toISOString(), activatedAt: new Date(activatedAt).toISOString(),
      preparationIntervalMilliseconds: interval, previousOverallDeadline: new Date(previousDeadline).toISOString(),
      overallDeadline: new Date(expectedDeadline).toISOString(), taskDeadline: new Date(expectedTaskDeadline).toISOString(),
      activationEventSequence: activationEvent.sequence, predecessorTerminalizationEventSequence: predecessorEvent.sequence,
      ownerPreparationStatus: preparation.preparation_status, ownerLeaseStatus: preparation.lease_state,
      befPreparationStatus: bef.preparation_status, befGenerationStatus: bef.generation_status,
      predecessorGenerationStatus: oldFence.generation_status };
    record('ranked_successor_activation_and_independent_owner_bef_readback', 'verified', verified);
    return verified;
  } finally { await close(); }
}

async function observeWorkerTask(context, issuedTask) {
  const { input, output, record, observerPool, runId, taskIndex, taskId, created, taskReleaseSource, evidenceSource, mode = 'training' } = context;
  const until = Date.now() + 180_000;
  let snapshot;
  let terminalTask;
  while (Date.now() < until) {
    snapshot = await readRunSnapshot(observerPool, { runId });
    terminalTask = snapshot.tasks.find((entry) => entry.task_index === taskIndex);
    const evaluation = snapshot.evaluation.find((entry) => entry.taskIndex === taskIndex);
    const preparation = snapshot.preparations.find((entry) => entry.task_index === taskIndex);
    if (['completed', 'failed'].includes(terminalTask?.status) && evaluation?.resultStatus === 'known' &&
        preparation?.lease_state === 'fenced' && preparation.preparation_status === 'fenced') break;
    demand(!['cancelled', 'expired', 'unknown', 'disqualified'].includes(snapshot.run[0]?.status),
      'worker_training_run_terminal_without_known_task');
    await delay(500);
  }
  demand(['completed', 'failed'].includes(terminalTask?.status), 'automatic_worker_task_completion_timeout');
  const rawRows = await readonlyTransaction(observerPool, async (query) => pgRows(await query(`
    SELECT e.input_hash,e.result_hash,e.result_json,b.bundle_hash,b.bundle_json,l.fence_evidence
    FROM oid_run_task_evaluation e JOIN oid_run_task_observation_bundle b ON b.run_id=e.run_id AND b.task_index=e.task_index
    JOIN oid_task_preparation_intent i ON i.run_id=e.run_id AND i.task_index=e.task_index
    JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
    WHERE e.run_id=$1 AND e.task_index=$2`, [runId, taskIndex])));
  demand(rawRows.length === 1, 'automatic_worker_durable_result_missing');
  const raw = rawRows[0];
  const parse = (value) => typeof value === 'string' ? JSON.parse(value) : value;
  const result = parse(raw.result_json);
  const bundle = parse(raw.bundle_json);
  const fence = parse(raw.fence_evidence);
  const execution = snapshot.execution.find((entry) => entry.task_index === taskIndex);
  demand(result?.status === 'known' && result.taskId === taskId && raw.result_hash === eventPayloadHash(result) &&
    raw.bundle_hash === eventPayloadHash(bundle) && bundle.binding.runId === runId && bundle.binding.taskId === taskId &&
    bundle.binding.environmentId === issuedTask.environmentId && execution?.env_id === issuedTask.environmentId &&
    bundle.execution.generationId === execution.generation_id && fence?.confirmed === true &&
    fence.preparationId === execution.preparation_id && fence.leaseId === execution.lease_id &&
    fence.generationId === execution.generation_id && fence.environmentId === execution.env_id,
  'automatic_worker_result_binding_mismatch');
  await safeBytes(input.repoRoot, fence.evidence.path, fence.evidence.sha256);
  const { reconstructTaskEvaluation, getTaskEvaluatorBuildHash } = await import('../../owner-identity/dist/task-result-service.js');
  const reconstruction = await reconstructTaskEvaluation({ db: created.db, taskReleaseSource, evidenceSource,
    evaluatorSourceHash: await getTaskEvaluatorBuildHash() }, { runId, taskIndex });
  demand(reconstruction.diverged === false && reconstruction.original.inputHash === raw.input_hash &&
    reconstruction.original.resultHash === raw.result_hash, 'automatic_worker_retained_evidence_reconstruction_mismatch');
  const observers = await createObserverPorts({ repositoryRoot: input.repoRoot, runId, environmentId: execution.env_id, taskId, taskIndex });
  try {
    const proof = await observers.postgresByEnvironment[execution.env_id].readFenceProof({
      preparationId: execution.preparation_id, generationId: execution.generation_id });
    demand(proof.length === 1 && proof[0].generation_status === 'fenced' && proof[0].preparation_status === 'fenced' &&
      proof[0].preparation_generation_id === execution.generation_id && proof[0].env_id === execution.env_id,
    'automatic_worker_independent_fence_readback_mismatch');
  } finally { await observers.close(); }
  output.taskEvaluations ??= [];
  output.taskEvaluations.push({ taskIndex, taskId, result, inputHash: raw.input_hash, resultHash: raw.result_hash,
    sealedBundleHash: raw.bundle_hash, producer: 'server_worker' });
  output.taskGenerationFences ??= [];
  output.taskGenerationFences.push({ status: 'verified', taskIndex, taskId, preparationId: fence.preparationId,
    leaseId: fence.leaseId, generationId: fence.generationId, environmentId: fence.environmentId,
    fenceEvidence: fence.evidence, producer: 'server_worker', independentObserverRole: 'bef_observer' });
  output.internalTaskEvaluationRecorded = true;
  record('automatic_worker_evaluation_fence_and_readonly_reconstruction', 'verified', {
    taskIndex, taskId, resultHash: raw.result_hash, sealedBundleHash: raw.bundle_hash, resultStatus: result.status,
    harnessEvaluationWrites: false, harnessFenceWrites: false });
  const state = await readOwnerRunCompletionState(observerPool, { runId, ownerId: snapshot.run[0].owner_id, includeRanked: mode === 'ranked' });
  demand(automaticWorkerChargeUnchanged({ runId, moneySha256: output.automaticInitialMoneySha256,
    ownerRefundCount: output.automaticInitialOwnerRefundCount, runRefundCount: output.automaticInitialRunRefundCount }, state),
    'automatic_worker_changed_single_run_charge');
  if (taskIndex < snapshot.run[0].task_ids.length - 1) {
    const events = snapshot.runEvents.filter((event) => event.eventType === 'task.terminalized' && event.payload?.taskIndex === taskIndex);
    const payload = events[0]?.payload;
    const finishedMilliseconds = terminalTask.finished_at instanceof Date ? terminalTask.finished_at.getTime() : Date.parse(terminalTask.finished_at ?? '');
    const finish = output.participantActions.find((entry) => entry.taskIndex === taskIndex && entry.kind === 'finish');
    demand(events.length === 1 && events[0].source === 'coordinator' && events[0].payloadHash === eventPayloadHash(payload) && payload?.runId === runId &&
      payload.taskId === taskId && payload.inputHash === raw.input_hash && payload.resultHash === raw.result_hash &&
      payload.outcome === result.outcome && payload.status === terminalTask.status &&
      payload.closureId === terminalTask.closure_id && payload.closureId === finish?.closureId &&
      payload.closureId === reconstruction.original.closureId && Number.isFinite(finishedMilliseconds) &&
      Date.parse(payload.finishedAt ?? '') === finishedMilliseconds &&
      payload.preparationId === fence.preparationId && payload.leaseId === fence.leaseId &&
      payload.generationId === fence.generationId && payload.fenceEvidenceHash === fence.evidence.sha256,
    'automatic_worker_nonfinal_terminalization_mismatch');
    output.predecessorTerminalization = { status: 'verified', taskIndex, taskId, finishedAt: payload.finishedAt,
      terminalStatus: terminalTask.status, terminalizationEventId: events[0].eventId,
      terminalizationEventHash: events[0].payloadHash, closureId: payload.closureId, outcome: payload.outcome,
      inputHash: raw.input_hash, resultHash: raw.result_hash, preparationId: fence.preparationId, leaseId: fence.leaseId,
      generationId: fence.generationId, environmentId: fence.environmentId, fenceEvidenceHash: fence.evidence.sha256,
      moneyStateSha256: state.moneySha256, observedFromWorker: true };
    output.predecessorTerminalizations ??= [];
    output.predecessorTerminalizations[taskIndex] = output.predecessorTerminalization;
    return { terminalization: { observedFromWorker: true } };
  }
  await verifyWorkerRunCompletionUi({ input, output, record, state, snapshot, mode });
  return { terminalization: null };
}

async function verifyWorkerRunCompletionUi({ input, output, record, state, snapshot, mode = 'training' }) {
  const run = snapshot.run[0];
  const expected = output.taskEvaluations;
  const debitOperation = 'rundeb_' + run.id.replaceAll('-', '');
  const reserveOperation = 'runacc_' + run.id.replaceAll('-', '');
  const debitRows = state.ledger.filter((entry) => entry.entry_type === 'debit' && entry.operation_id === debitOperation);
  const reserveRows = state.ledger.filter((entry) => entry.entry_type === 'reserve' && entry.operation_id === reserveOperation);
  const runFunding = verifyRunFundingConservation({ runId: run.id, quoteUnits: run.quote_price_units,
    reservations: state.reservations, ledger: state.ledger });
  demand(run.status === 'completed' && state.tasks.length === expected.length && state.evaluations.length === expected.length &&
    state.tasks.every((task, index) => task.task_index === index && task.task_id === expected[index].taskId &&
      task.status === (expected[index].result.outcome === 'failed' ? 'failed' : 'completed')) &&
    state.completionEvents.length === 1 && state.terminalizationEvents.length === expected.length - 1 &&
    state.claims.length === 1 && state.claims[0].status === 'released' && state.claims[0].claim_id === output.dispatchIdentity.claimId &&
    state.slots.length === 0 && runFunding.reservationUnits === run.quote_price_units && state.budgetHolds.length === 1 &&
    state.budgetHolds[0].state === 'charged' && state.budgetHolds[0].amount_units === run.quote_price_units &&
    debitRows.length === state.reservations.length && reserveRows.length === state.reservations.length &&
    runFunding.reservationCount > 0 &&
    automaticWorkerChargeUnchanged({ runId: run.id, moneySha256: output.automaticInitialMoneySha256,
      ownerRefundCount: output.automaticInitialOwnerRefundCount, runRefundCount: output.automaticInitialRunRefundCount }, state),
  'automatic_worker_completion_state_mismatch');
  if (input.bonusCodeFunding === true) {
    const codeFunding = verifyCodeDerivedBonusFunding({ ownerId: run.owner_id,
      reservations: state.reservations, sourceGrants: state.bonusSourceGrants, issuedGrant: output.bonusFunding });
    demand(runFunding.allSourcesAreBonus && runFunding.cashReservationCount === 0 &&
      state.ledger.every((entry) => entry.source_kind === 'tester_bonus') && state.runRefundCount === 0,
    'bonus_code_worker_run_used_cash_or_refund');
    const reserveAndDebit = state.ledger.filter((entry) => entry.entry_type === 'reserve' || entry.entry_type === 'debit');
    output.bonusFunding.workerRunFunding = {
      status: 'verified',
      runId: run.id,
      mode: run.mode,
      taskIds: run.task_ids,
      quoteUnits: run.quote_price_units,
      reservation: state.reservations.length === 1 ? state.reservations[0] : null,
      reservations: state.reservations,
      reserveEntries: reserveAndDebit.filter((entry) => entry.entry_type === 'reserve'),
      startDebitEntries: reserveAndDebit.filter((entry) => entry.entry_type === 'debit'),
      cashReservationCount: state.reservations.filter((row) => row.source_kind === 'cash_usdc').length,
      cashLedgerEntryCount: state.ledger.filter((row) => row.source_kind === 'cash_usdc').length,
      runRefundCount: state.runRefundCount,
      ownerRefundCountAtRunStart: output.automaticInitialOwnerRefundCount,
      ownerRefundCountUnchangedDuringRun: state.ownerRefundCount === output.automaticInitialOwnerRefundCount,
      ...runFunding,
      ...codeFunding,
    };
  }
  const completed = state.completionEvents[0];
  const payload = typeof completed.payload_json === 'string' ? JSON.parse(completed.payload_json) : completed.payload_json;
  const finalTrainingActivation = output.trainingSuccessorActivations?.at(-1) ?? output.successorActivation;
  const finishedMilliseconds = state.run.finished_at instanceof Date ? state.run.finished_at.getTime() : Date.parse(state.run.finished_at ?? '');
  demand(completed.source === 'coordinator' && completed.payload_hash === eventPayloadHash(payload) && payload?.runId === run.id &&
    (mode === 'training' && expected.length > 1 ? BigInt(completed.sequence) > BigInt(finalTrainingActivation?.activationEventSequence ?? 0) : state.terminalizationEvents.every((event) => BigInt(event.sequence) < BigInt(completed.sequence))) &&
    payload.mode === mode && JSON.stringify(payload.taskIds) === JSON.stringify(run.task_ids) &&
    Number.isFinite(finishedMilliseconds) && Date.parse(payload.finishedAt ?? '') === finishedMilliseconds &&
    Array.isArray(payload.tasks) && payload.tasks.length === expected.length && payload.tasks.every((proof, index) => {
      const evaluation = expected[index];
      const fence = output.taskGenerationFences.find((entry) => entry.taskIndex === index);
      const finish = output.participantActions.find((entry) => entry.taskIndex === index && entry.kind === 'finish');
      return proof.taskIndex === index && proof.taskId === evaluation.taskId && proof.closureId === finish?.closureId &&
        proof.inputHash === evaluation.inputHash && proof.resultHash === evaluation.resultHash &&
        proof.preparationId === fence?.preparationId && proof.leaseId === fence?.leaseId &&
        proof.generationId === fence?.generationId && proof.fenceEvidenceHash === fence?.fenceEvidence.sha256;
    }), 'automatic_worker_completion_payload_mismatch');
  await input.ownerPage.goto('/runs', { waitUntil: 'domcontentloaded' });
  const card = input.ownerPage.getByTestId('owner-run-' + run.id);
  await card.waitFor({ state: 'visible', timeout: 15_000 });
  demand((await card.getByTestId('owner-run-status-' + run.id).innerText()).trim() === 'completed', 'automatic_worker_completed_run_ui_missing');
  const responsePromise = input.ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/owner/runs/' + run.id + '/results' && response.request().method() === 'GET', { timeout: 15_000 });
  await card.getByTestId('run-feedback-load-' + run.id).click();
  const response = await responsePromise;
  const uiTasks = [];
  for (const evaluation of expected) {
    const result = evaluation.result;
    const row = card.getByTestId('run-feedback-task-' + run.id + '-' + evaluation.taskId);
    await row.waitFor({ state: 'visible', timeout: 15_000 });
    const text = (await row.innerText()).replace(/\s+/g, ' ').trim();
    demand(response.status() === 200 && text.includes(result.outcome) &&
      text.includes('Credit ' + result.credit.numerator + '/' + result.credit.denominator), 'automatic_worker_result_ui_mismatch');
    uiTasks.push({ taskId: evaluation.taskId, outcome: result.outcome, credit: result.credit });
  }
  const resultsApi = await readOwnerTrainingFeedbackTasks(input.ownerPage, run.id, expected.map((entry) => entry.result));
  demand(resultsApi.status === 'observed' && resultsApi.consistentWithInternalEvaluation, 'automatic_worker_results_api_mismatch');
  output.ownerRunResultsUi = { status: 'verified', browserHttpStatus: response.status(), runStatus: 'completed', tasks: uiTasks,
    resultsApi, classification: 'owner_button_to_results_api_and_worker_persisted_evaluation' };
  output.trainingRunCompletion = { status: 'verified', mode, runStatus: 'completed', finishedAt: payload.finishedAt,
    completionEventId: completed.id, completionEventPayloadHash: completed.payload_hash, dispatchClaimStatus: 'released',
    remainingExecutionSlots: 0, chargeQuoteUnits: run.quote_price_units, reservationCount: state.reservations.length,
    reservationUnits: runFunding.reservationUnits, reserveEntryCount: reserveRows.length, reserveEntryIds: reserveRows.map((entry) => entry.id),
    ownerRefundCount: state.ownerRefundCount,
    runRefundCount: state.runRefundCount, ownerRefundCountAtRunStart: output.automaticInitialOwnerRefundCount,
    ownerRefundCountUnchangedDuringRun: state.ownerRefundCount === output.automaticInitialOwnerRefundCount,
    debitEntryId: debitRows.length === 1 ? debitRows[0].id : null, debitEntryIds: debitRows.map((entry) => entry.id),
    debitOperationId: debitOperation, debitEntryCount: debitRows.length,
    moneyStateUnchangedByCompletion: true, completionReplayVerified: false, completionReplayScope: 'not_run_readonly_worker_capture' };
  output.runCompletion = output.trainingRunCompletion;
  if (mode === 'ranked') verifyRankedHandoffState({ output, state, run, expected, completed, payload });
  if (mode === 'training') output.ownerTrainingFeedbackUi = output.ownerRunResultsUi;
  output.completionBridge = { classification: mode === 'ranked' ? 'automatic_server_worker_ranked_completion_with_readonly_handoff_verification' : 'automatic_server_worker_lifecycle_with_readonly_harness_verification',
    automaticWorkerEvaluation: true, actualServerWorkerSuccessorAdvancement: mode === 'training' && expected.length > 1 &&
      output.trainingSuccessorActivations?.length === expected.length - 1,
    harnessObservationSealWrites: false, harnessEvaluationWrites: false, harnessFenceWrites: false, harnessCompletionWrites: false };
  output.automaticWorkerEvaluationVerified = true;
  record('automatic_worker_completion_and_owner_results_ui', 'verified', output.ownerRunResultsUi);
}

function verifyRankedHandoffState({ output, state, run, expected, completed, payload }) {
  const parse = (value) => typeof value === 'string' ? JSON.parse(value) : value;
  const snapshots = state.rankedVersionSnapshots, handoffs = state.rankedHandoffs, results = state.rankedResults;
  const bestResults = state.rankedBestResults, markers = state.rankedFirstActionMarkers, eligibleEvents = state.rankedEligibilityEvents;
  demand(run.mode === 'ranked' && expected.length === 12 && snapshots.length === 1 && handoffs.length === 1 &&
    results.length === 1 && bestResults.length === 1 && markers.length === 1 && eligibleEvents.length === 1,
  'ranked_handoff_rows_missing_or_ambiguous');
  const snapshot = snapshots[0], handoff = handoffs[0], result = results[0], marker = markers[0], best = bestResults[0], eligible = eligibleEvents[0];
  const aggregate = parse(result.aggregate_json), versionSnapshot = parse(snapshot.snapshot_json);
  const retainedVersionSnapshot = parse(result.version_snapshot_json), handoffBody = parse(handoff.handoff_json), eligibleBody = parse(eligible.payload_json);
  demand(versionSnapshot && retainedVersionSnapshot && aggregate && handoffBody && eligibleBody, 'ranked_handoff_json_invalid');
  const { aggregateHash, ...aggregateBody } = aggregate;
  const scoreValid = (fraction) => fraction && /^(0|[1-9][0-9]*)$/.test(String(fraction.numerator)) &&
    /^[1-9][0-9]*$/.test(String(fraction.denominator)) &&
    BigInt(fraction.numerator) <= 100n * BigInt(fraction.denominator);
  const taskCases = output.release?.rankedTasks ?? [];
  const sameJson = (left, right) => JSON.stringify(sortedJsonValue(left)) === JSON.stringify(sortedJsonValue(right));
  const expectedProofs = expected.map((entry, index) => {
    const taskCase = taskCases[index], fence = output.taskGenerationFences.find((item) => item.taskIndex === index);
    return { taskIndex: index, taskId: entry.taskId, caseHash: taskCase?.caseHash, rubricHash: taskCase?.rubricHash,
      inputHash: entry.inputHash, resultHash: entry.resultHash, fenceEvidenceHash: fence?.fenceEvidence?.sha256, result: entry.result };
  });
  const expectedHandoff = { schemaVersion: 'ranked-run-handoff/v1', runId: run.id, ownerId: run.owner_id, agentId: output.agent.agentId,
    releaseIdentity: output.release.releaseIdentity, benchmarkVersion: output.release.benchmarkVersion,
    benchmarkHash: output.release.benchmarkHash, policyHash: output.release.policyHash, manifestHash: output.release.manifestHash,
    versionSnapshotHash: snapshot.snapshot_hash, aggregateHash, completionEventHash: completed.payload_hash, finishedAt: payload.finishedAt,
    taskProofs: aggregate.taskProofs?.map(({ result: omitted, ...proof }) => proof) };
  demand(snapshot.run_id === run.id && snapshot.owner_id === run.owner_id && snapshot.agent_id === output.agent.agentId &&
    HEX_HASH.test(snapshot.snapshot_hash) && eventPayloadHash(versionSnapshot) === snapshot.snapshot_hash &&
    versionSnapshot.schemaVersion === 'ranked-agent-version-snapshot/v1' && versionSnapshot.runId === run.id &&
    versionSnapshot.ownerId === run.owner_id && versionSnapshot.agentId === output.agent.agentId &&
    versionSnapshot.name === output.agent.profileSnapshotCandidate?.name &&
    versionSnapshot.declaredVersion === output.agent.profileSnapshotCandidate?.declaredVersion &&
    versionSnapshot.profileRevision === output.agent.profileSnapshotCandidate?.profileRevision &&
    Date.parse(snapshot.created_at) <= Date.parse(run.started_at) &&
    result.run_id === run.id && result.owner_id === run.owner_id && result.agent_id === output.agent.agentId &&
    handoff.run_id === run.id && handoff.owner_id === run.owner_id && handoff.agent_id === output.agent.agentId &&
    result.benchmark_version === output.release.benchmarkVersion && handoff.benchmark_version === output.release.benchmarkVersion &&
    result.aggregate_hash === aggregateHash && handoff.aggregate_hash === aggregateHash &&
    eventPayloadHash(aggregateBody) === aggregateHash && aggregate.schemaVersion === 'ranked-outcome-aggregate/v1' &&
    aggregate.releaseIdentity === output.release.releaseIdentity && aggregate.manifestHash === output.release.manifestHash &&
    aggregate.benchmarkVersion === output.release.benchmarkVersion && aggregate.benchmarkHash === output.release.benchmarkHash &&
    aggregate.policyHash === output.release.policyHash && aggregate.taskProofs?.length === 12 &&
    scoreValid(aggregate.overall) && ['simple','medium','hard','ultra'].every((tier) => scoreValid(aggregate.tiers?.[tier])) &&
    sameJson(aggregate.taskProofs, expectedProofs) &&
    result.version_snapshot_hash === snapshot.snapshot_hash && handoff.version_snapshot_hash === snapshot.snapshot_hash &&
    sameJson(retainedVersionSnapshot, versionSnapshot) &&
    handoff.completion_event_hash === completed.payload_hash &&
    handoff.handoff_hash === eventPayloadHash(handoffBody) && sameJson(handoffBody, expectedHandoff) &&
    sameJson(eligibleBody, handoffBody) && eligible.source === 'coordinator' && eligible.payload_hash === handoff.handoff_hash &&
    BigInt(eligible.sequence) > BigInt(completed.sequence) &&
    marker.owner_id === run.owner_id && marker.agent_id === output.agent.agentId && marker.source_kind === 'ranked_run' &&
    marker.source_id === run.id && marker.source_hash === handoff.handoff_hash &&
    best.agent_id === output.agent.agentId && best.benchmark_version === output.release.benchmarkVersion && best.run_id === run.id,
  'ranked_handoff_binding_mismatch');
  output.rankedHandoff = { status: 'verified', handoffHash: handoff.handoff_hash, aggregateHash,
    completionEventHash: handoff.completion_event_hash, versionSnapshotHash: snapshot.snapshot_hash, taskProofCount: aggregate.taskProofs.length,
    eligibilityEventSequence: eligible.sequence, firstPublicActionMarker: { sourceKind: marker.source_kind, sourceId: marker.source_id,
      sourceHash: marker.source_hash }, bestResultRunId: best.run_id, publicLeaderboardPublication: false };
}
async function submitLinkedTrainingAction(context, command, expectsTransaction) {
  const { input, output, record, observerPool, bearer, runId, taskIndex, taskId } = context;
  const operationId = randomUUID();
  const recoveryFault = input.platformRecoveryFault;
  if (recoveryFault && !output.platformRecovery?.faultArmOperationId) {
    demand(typeof recoveryFault.beforeFirstAction === 'function', 'platform_recovery_fault_arm_callback_required');
    await recoveryFault.beforeFirstAction({ runId, taskIndex, taskId, operationId, command });
    output.platformRecovery ??= { schemaVersion: 'bpc-platform-recovery-worker-hook/v1',
      boundary: 'local_real_bef_response_drop_fault_injection', firstActionOperationId: operationId,
      faultArmOperationId: operationId };
  }
  let admitted;
  let transportUnknown = false;
  try {
    admitted = await agentRequest({ publicOrigin: input.publicOrigin,
      path: '/api/agent/runs/' + runId + '/tasks/' + taskIndex + '/actions', method: 'POST', bearer,
      body: { operationId, command } });
  } catch (error) {
    if (safeErrorCode(error) !== 'agent_http_transport_unknown') throw error;
    transportUnknown = true;
    admitted = { status: 0, payload: {} };
  }
  const fact = { taskIndex, taskId, kind: command.kind, operationId, command, httpStatus: admitted.status, transportUnknown };
  output.participantActions.push(fact);
  let actionId = admitted.payload?.actionId;
  if (!UUID.test(actionId)) {
    const rows = await readonlyTransaction(observerPool, async (query) => pgRows(await query(
      'SELECT id::text FROM oid_run_task_action WHERE run_id=$1 AND task_index=$2 AND operation_id=$3', [runId, taskIndex, operationId])));
    actionId = rows[0]?.id ?? null;
  }
  demand(UUID.test(actionId), 'linked_action_admission_unknown_do_not_retry');
  fact.actionId = actionId;
  const recoveryWaitMs = recoveryFault?.waitTimeoutMs ?? 180_000;
  const resolved = await waitForActionResolution({ publicOrigin: input.publicOrigin, bearer, runId, actionId, observerPool,
    timeoutMs: recoveryFault ? recoveryWaitMs : 180_000, waitForPlatformRecovery: Boolean(recoveryFault),
    onInitialUnknown: recoveryFault?.onInitialUnknown ? async ({ apiStatus, action, snapshot }) => {
      output.platformRecovery.initialUnknown = { actionId, runId, ownerOperationId: operationId,
        receiptStatus: action?.receiptStatus ?? 'unknown', apiStatus, observedActionCount: snapshot.actions.filter((row) =>
          row.operationId === operationId).length, retrySubmitted: false };
      await recoveryFault.onInitialUnknown({ runId, actionId, ownerOperationId: operationId,
        taskIndex, taskId, apiStatus, action, snapshot });
    } : undefined,
    finishWhenUnknown: recoveryFault?.finishWhenUnknown ? async ({ apiStatus, apiPayload, action, snapshot }) =>
      recoveryFault.finishWhenUnknown({ runId, actionId, ownerOperationId: operationId, taskIndex, taskId,
        apiStatus, apiPayload, action, snapshot }) : undefined });
  fact.receiptStatus = resolved.action?.receiptStatus ?? 'unknown';
  fact.transactionHash = resolved.action?.transactionHash ?? null;
  fact.evidence = resolved.action?.evidencePath && resolved.action?.evidenceHash
    ? { path: resolved.action.evidencePath, sha256: resolved.action.evidenceHash } : null;
  const exhaustedTerminal = recoveryFault?.terminalAfterRecovery === true && resolved.finalTerminal === true;
  const exhaustedUnknown = exhaustedTerminal &&
    resolved.action.receiptStatus === 'unknown';
  demand(resolved.action?.receiptStatus === 'observed' || exhaustedUnknown,
    resolved.action?.receiptStatus === 'unknown' ? 'linked_action_effect_unknown_do_not_retry' : 'linked_action_not_observed');
  demand(resolved.action.kind === command.kind && eventPayloadHash(resolved.action.command) === eventPayloadHash(command) &&
    (exhaustedUnknown ? resolved.action.transactionHash === null :
      expectsTransaction ? /^0x[0-9a-f]{64}$/i.test(resolved.action.transactionHash ?? '') : resolved.action.transactionHash === null),
  'linked_action_receipt_binding_mismatch');
  if (recoveryFault && resolved.initialUnknown) {
    const originalOnly = resolved.snapshot.actions.filter((row) => row.operationId === operationId);
    demand(originalOnly.length === 1 && (resolved.action.receiptStatus === 'observed' || exhaustedUnknown),
      'platform_recovery_original_operation_not_reconciled');
    output.platformRecovery.reconciledOriginalAction = { actionId, runId, ownerOperationId: operationId,
      initialReceiptStatus: 'unknown', finalReceiptStatus: resolved.action.receiptStatus, actionRowCount: originalOnly.length,
      resubmissionCount: 0, evidence: resolved.action.evidence ?? null };
    if (recoveryFault.terminalAfterRecovery === true) {
      demand(typeof recoveryFault.afterOriginalActionReconciled === 'function',
        'platform_recovery_terminal_verifier_required');
      const terminal = await recoveryFault.afterOriginalActionReconciled({ runId, actionId, ownerOperationId: operationId,
        taskIndex, taskId, action: resolved.action, snapshot: resolved.snapshot, originalReceiptRemainsUnknown: exhaustedUnknown });
      demand(terminal?.verified === true && terminal.terminalReason === 'platform_failure_recovery_exhausted' &&
        terminal.cashRefundedUnits === '0' && typeof terminal.bonusRefundedUnits === 'string' &&
        /^\d+$/.test(terminal.bonusRefundedUnits) && terminal.refundEntryCount >= 1 &&
        terminal.fenceVerified === true && terminal.runStatus === 'failed' &&
        ['unknown', 'observed'].includes(terminal.originalReceiptStatus),
      'platform_recovery_exhaustion_terminal_not_verified');
      output.platformRecovery.exhaustion = terminal;
      output.platformRecovery.terminalCapturedWithoutGrade = true;
      throw fail('beta_platform_recovery_terminal_captured');
    }
  }
  record('linked_participant_action_and_durable_receipt', 'observed', { taskIndex, taskId, kind: command.kind,
    actionId, transactionHash: fact.transactionHash, evidence: fact.evidence });
  return resolved;
}

async function captureAndEvaluateTrainingTask(context) {
  const { input, output, record, observerPool, bearer, runId, taskIndex, taskId, intentId,
    createIntentOperationId, acceptOperationId, selectedTaskIds, agentId, created, taskReleaseSource,
    evidenceSource, sequenceMode, beforeAction, mode = 'training', intentCreatePayload } = context;
  const task = await waitForActiveTask({ publicOrigin: input.publicOrigin, bearer, runId, observerPool, taskId, taskIndex, mode });
  const activeSnapshot = await readRunSnapshot(observerPool, { runId });
  demand(activeSnapshot.run.length === 1 && activeSnapshot.run[0].status === 'running' && activeSnapshot.run[0].overall_deadline,
    'training_run_start_clock_unavailable');
  if (taskIndex === 0) output.runInitial.overallDeadline = activeSnapshot.run[0].overall_deadline;
  let automaticPreCallbackState = null;
  if (input.automaticWorkerEvaluation && taskIndex === 0) {
    const initial = await readOwnerRunCompletionState(observerPool, { runId, ownerId: activeSnapshot.run[0].owner_id });
    demand(initial.claims.length === 1 && initial.claims[0].status === 'claimed' && initial.slots.length === 1 &&
      initial.slots[0].claim_id === initial.claims[0].claim_id && initial.run.status === 'running', 'automatic_worker_initial_dispatch_missing');
    automaticPreCallbackState = initial;
    output.dispatchIdentity = { runId, claimId: initial.claims[0].claim_id, slotRunId: initial.slots[0].run_id,
      slotAgentId: initial.slots[0].agent_id, slotClaimId: initial.slots[0].claim_id };
    demand(initial.runRefundCount === 0, 'automatic_worker_initial_run_refund_present');
    output.automaticInitialMoneySha256 = initial.moneySha256;
    output.automaticInitialOwnerRefundCount = initial.ownerRefundCount;
    output.automaticInitialRunRefundCount = initial.runRefundCount;
  }
  if (taskIndex === 0 && typeof input.onGenuineFirstTaskActive === 'function' &&
      output.genuineFirstTaskActiveCallbackInvoked !== true) {
    // The callback is an acceptance orchestration seam, not part of the task result.
    // Its bearer and browser handles remain in memory and never enter output.
    await input.onGenuineFirstTaskActive({ runId, ownerId: input.ownerId, agentId, mode,
      taskIds: [...selectedTaskIds], task, agentBearer: bearer, ownerPage: input.ownerPage,
      publicOrigin: input.publicOrigin, databaseUrl: input.databaseUrl,
      observerDatabaseUrl: input.observerDatabaseUrl, release: output.release, intentId,
      createIntentOperationId, acceptOperationId,
      // These exact owner-create bytes are exposed only to the synchronous in-memory
      // acceptance callback so a restored clone can retry the original operation.
      intentCreatePayload: intentCreatePayload ? structuredClone(intentCreatePayload) : null });
    output.genuineFirstTaskActiveCallbackInvoked = true;
    if (automaticPreCallbackState) {
      const afterCallback = await readOwnerRunCompletionState(observerPool, {
        runId, ownerId: automaticPreCallbackState.run.owner_id,
      });
      demand(automaticWorkerCallbackFinancialBoundaryUnchanged(automaticPreCallbackState, afterCallback, {
        runId, callbackName: 'onGenuineFirstTaskActive',
      }), 'automatic_worker_callback_financial_boundary_invalid');
      output.automaticWorkerCallbackFinancialBoundary = {
        status: 'verified',
        scope: 'after_onGenuineFirstTaskActive_before_first_participant_action',
        callbackName: 'onGenuineFirstTaskActive',
        runId,
        runScopedMoneySha256Before: automaticPreCallbackState.runMoneySha256,
        runScopedMoneySha256After: afterCallback.runMoneySha256,
        runScopedMoneyUnchanged: true,
        ownerMoneySha256Before: automaticPreCallbackState.moneySha256,
        ownerMoneySha256After: afterCallback.moneySha256,
        ownerLedgerSha256Before: automaticPreCallbackState.ownerLedgerSha256,
        ownerLedgerSha256After: afterCallback.ownerLedgerSha256,
        ownerLedgerCountBefore: automaticPreCallbackState.ownerLedgerCount,
        ownerLedgerCountAfter: afterCallback.ownerLedgerCount,
        ownerRefundCountBefore: automaticPreCallbackState.ownerRefundCount,
        ownerRefundCountAfter: afterCallback.ownerRefundCount,
        runRefundCountBefore: automaticPreCallbackState.runRefundCount,
        runRefundCountAfter: afterCallback.runRefundCount,
        activeClaimId: afterCallback.claims[0].claim_id,
        activeSlot: { runId: afterCallback.slots[0].run_id, agentId: afterCallback.slots[0].agent_id,
          claimId: afterCallback.slots[0].claim_id, state: afterCallback.slots[0].state },
        workerBaselineMoneySha256: afterCallback.moneySha256,
      };
      output.automaticInitialMoneySha256 = afterCallback.moneySha256;
      output.automaticInitialOwnerRefundCount = afterCallback.ownerRefundCount;
      output.automaticInitialRunRefundCount = afterCallback.runRefundCount;
    }
  }
  if (beforeAction) await beforeAction(task);
  const { answer } = await performGenuineActorActions({ ...context, mode }, task);
  const finishOperationId = randomUUID();
  const finish = await agentRequest({ publicOrigin: input.publicOrigin,
    path: '/api/agent/runs/' + runId + '/tasks/' + taskIndex + '/finish', method: 'POST', bearer,
    body: { operationId: finishOperationId, ...(answer ? { answer } : {}) } });
  const finishFact = { taskIndex, taskId, kind: 'finish', operationId: finishOperationId, httpStatus: finish.status };
  output.participantActions.push(finishFact);
  const closed = await waitForClosedTask(observerPool, runId, taskIndex);
  const closedTask = closed.tasks.find((row) => row.task_index === taskIndex);
  demand(closedTask?.closure_status === 'closed' && BigInt(closedTask.reconciled_action_sequence ?? 0) >= BigInt(closedTask.action_cutoff_sequence ?? -1),
    'finish_cutoff_or_reconciliation_unconfirmed');
  finishFact.closureId = closedTask.closure_id;
  finishFact.closureStatus = closedTask.closure_status;
  record('agent_finish_and_authoritative_cutoff', 'verified', { taskIndex, taskId, closureId: closedTask.closure_id,
    actionCutoffSequence: closedTask.action_cutoff_sequence, reconciledActionSequence: closedTask.reconciled_action_sequence });

  if (input.automaticWorkerEvaluation) return observeWorkerTask({ ...context, mode }, task);

  const environmentId = closed.run[0]?.environment_id;
  demand(environmentId === task.environmentId && environmentId === 'bef-env-a', 'execution_environment_binding_mismatch');
  const { postgresByEnvironment, rpcByEnvironment, evidenceSink, close } = await createObserverPorts({
    repositoryRoot: input.repoRoot, runId: output.captureId, environmentId, taskId, taskIndex });
  try {
    const collectorModule = await import('../../owner-identity/dist/bef-' + taskId.toLowerCase() + '-observation-collector.js');
    const collect = collectorModule['collectBef' + taskId + 'TaskObservationCandidate'];
    demand(typeof collect === 'function', 'task_observer_not_connected');
    const { sealTaskObservationBundle } = await import('../../owner-identity/dist/task-observation-store.js');
    const { recordTaskEvaluation, getTaskEvaluatorBuildHash, reconstructTaskEvaluation } = await import('../../owner-identity/dist/task-result-service.js');
    const deps = { db: created.db, taskReleaseSource, repositoryRoot: input.repoRoot,
      postgresByEnvironment, rpcByEnvironment, evidenceSink };
    const collection = await collect(deps, { runId, taskIndex });
    const collectionFact = collection.status === 'candidate'
      ? { status: collection.status, classification: collection.classification, evidence: collection.evidence }
      : { status: collection.status, reasonCode: collection.reasonCode };
    if (!Array.isArray(output.taskObservationCollections)) output.taskObservationCollections = [];
    output.taskObservationCollections.push({ taskIndex, taskId, ...collectionFact });
    if (!sequenceMode) output.observationCollection = collectionFact;
    demand(collection.status === 'candidate' && collection.classification === 'run_bound_observations_candidate_not_grade',
      collection.status === 'unavailable' ? 'observer_' + collection.reasonCode : 'observer_candidate_unavailable');
    const requiredCoverage = taskId === 'S2' ? ['transfers', 'payments', 'stateMutations', 'allowances', 'deliveries', 'answers']
      : taskId === 'S4' ? ['transfers', 'balances', 'allowances'] : ['transfers', 'balances'];
    demand(requiredCoverage.every((domain) => collection.candidate.observations?.coverage?.[domain] === 'complete'),
      'observer_required_task_coverage_incomplete');
    const latestClosed = await readRunSnapshot(observerPool, { runId });
    const latestRun = latestClosed.run[0];
    const latestTask = latestClosed.tasks.find((row) => row.task_index === taskIndex);
    const validatedRelease = latestRun && await taskReleaseSource.getValidatedReleaseRecord(latestRun.release_identity, latestRun.manifest_hash);
    const taskCase = validatedRelease?.manifest?.cases?.training?.find((entry) => entry.taskId === taskId);
    const observationCutoff = collection.candidate.observationCutoffSequence;
    const acceptedCutoff = Number(latestTask?.action_cutoff_sequence);
    const reconciledCutoff = Number(latestTask?.reconciled_action_sequence);
    demand(['running', 'completed'].includes(latestRun?.status) && latestRun.manifest_hash === output.release.manifestHash &&
      latestRun.intent_status === 'accepted' && latestRun.intent_operation_id === createIntentOperationId &&
      acceptedEventMatches(latestClosed, { runId, intentId, taskIds: selectedTaskIds, ownerId: input.ownerId, agentId,
        manifestHash: output.release.manifestHash, acceptOperationId }) &&
      latestTask?.closure_status === 'closed' && latestTask.closure_id === closedTask.closure_id &&
      Number.isSafeInteger(acceptedCutoff) && acceptedCutoff >= 0 && Number.isSafeInteger(reconciledCutoff) &&
      reconciledCutoff >= acceptedCutoff && Number.isSafeInteger(observationCutoff) && observationCutoff >= 0 &&
      validatedRelease?.manifestHash === latestRun.manifest_hash && taskCase && latestRun.owner_id === input.ownerId &&
      latestRun.agent_id === agentId && latestRun.environment_id === task.environmentId,
    'authoritative_task_evaluation_preflight_unavailable');
    const { evaluateTaskRubric } = await import('../../owner-identity/dist/task-evaluator.js');
    const preflight = evaluateTaskRubric({ taskCase, release: validatedRelease.manifest, run: {
      ownerId: latestRun.owner_id, agentId: latestRun.agent_id, runId,
      environmentId: latestRun.environment_id, releaseIdentity: latestRun.release_identity,
      manifestHash: latestRun.manifest_hash, caseId: taskCase.caseId, caseHash: taskCase.caseHash,
      rubricHash: taskCase.rubricHash, taskId, acceptedActionCutoffSequence: acceptedCutoff,
      reconciledThroughActionSequence: reconciledCutoff, observationCutoffSequence: observationCutoff,
      cutoffStatus: 'authoritative', cutoffEvidence: collection.candidate.cutoffEvidence,
    }, observations: collection.candidate.observations });
    const preflightFact = preflight.status === 'known'
      ? { status: 'known', evidenceComplete: true }
      : { status: 'blocked', reasonCodes: preflight.unknownReasons };
    if (!Array.isArray(output.taskEvaluationPreflights)) output.taskEvaluationPreflights = [];
    output.taskEvaluationPreflights.push({ taskIndex, taskId, ...preflightFact });
    if (!sequenceMode) output.evaluationPreflight = preflightFact;
    demand(preflight.status === 'known', 'authoritative_task_evaluation_inputs_incomplete');
    const sealed = await sealTaskObservationBundle({ db: created.db, taskReleaseSource }, { runId, taskIndex }, collection.candidate);
    demand(sealed.status === 'sealed', sealed.status === 'unavailable' ? 'observation_bundle_' + sealed.reasonCode : 'observation_bundle_not_sealed');
    const evaluationDeps = { db: created.db, taskReleaseSource, evidenceSource,
      evaluatorSourceHash: await getTaskEvaluatorBuildHash() };
    const recorded = await recordTaskEvaluation(evaluationDeps, { runId, taskIndex });
    const reconstructed = await reconstructTaskEvaluation(evaluationDeps, { runId, taskIndex });
    demand(recorded.evaluation.result.status === 'known' && reconstructed.diverged === false &&
      reconstructed.original.resultHash === recorded.evaluation.resultHash, 'internal_evaluation_readback_mismatch');
    output.internalTaskEvaluationRecorded = true;
    const feedback = await readOwnerTrainingFeedback(input.ownerPage, runId, recorded.evaluation.result);
    const evaluationFact = { taskIndex, taskId, resultHash: recorded.evaluation.resultHash,
      inputHash: recorded.evaluation.inputHash, sealedBundleHash: sealed.bundleHash, replayed: recorded.replayed,
      status: recorded.evaluation.result.status, outcome: recorded.evaluation.result.outcome,
      credit: recorded.evaluation.result.credit, retainedInputReconstructed: true,
      evaluatorReadbackMatches: true, ownerFeedback: feedback };
    if (!Array.isArray(output.taskEvaluations)) output.taskEvaluations = [];
    output.taskEvaluations.push({ taskId, taskIndex, result: recorded.evaluation.result, resultHash: recorded.evaluation.resultHash,
      inputHash: recorded.evaluation.inputHash, sealedBundleHash: sealed.bundleHash });
    if (!sequenceMode) {
      output.internalEvaluationBridge = { classification: 'internal_observation_seal_and_evaluator_bridge',
        ownerFeedbackVisibility: feedback.status === 'observed' ? 'observed_through_owner_auth_api' : 'unknown',
        sealedBundleHash: sealed.bundleHash, replayed: recorded.replayed, resultHash: recorded.evaluation.resultHash,
        resultStatus: recorded.evaluation.result.status, resultCredit: recorded.evaluation.result.credit,
        retainedInputReconstructed: true, evaluatorReadbackMatches: true };
      output.ownerTrainingFeedback = feedback;
    } else {
      output.internalEvaluationBridge = { classification: 'internal_observation_seal_and_evaluator_bridge',
        ownerFeedbackVisibility: feedback.status === 'observed' ? 'observed_through_owner_auth_api' : 'unknown',
        sealedBundleHash: sealed.bundleHash, replayed: recorded.replayed, resultHash: recorded.evaluation.resultHash,
        resultStatus: recorded.evaluation.result.status, resultCredit: recorded.evaluation.result.credit,
        retainedInputReconstructed: true, evaluatorReadbackMatches: true };
      if (!Array.isArray(output.internalEvaluationBridges)) output.internalEvaluationBridges = [];
      output.internalEvaluationBridges.push({ ...evaluationFact, classification: 'internal_observation_seal_and_evaluator_bridge' });
    }
    record('independent_bef_postgres_rpc_observation_and_internal_evaluation_bridge', 'verified', {
      taskIndex, taskId, classification: 'internal_observation_seal_and_evaluator_bridge',
      sealedBundleHash: sealed.bundleHash, resultHash: recorded.evaluation.resultHash,
      resultStatus: recorded.evaluation.result.status,
    });
    if (sequenceMode) {
      if (!Array.isArray(output.ownerTrainingFeedbackTasks)) output.ownerTrainingFeedbackTasks = [];
      output.ownerTrainingFeedbackTasks.push({ taskIndex, taskId, ...feedback });
    }
    record('owner_training_feedback_api_read', feedback.status, { taskIndex, taskId,
      httpStatus: feedback.httpStatus ?? null, consistentWithInternalEvaluation: feedback.consistentWithInternalEvaluation ?? null,
      reasonCode: feedback.reasonCode ?? null });
    const fenceAndComplete = await fenceAndCompleteKnownS1({ input, output, record, observerPool, postgresByEnvironment,
      created, taskReleaseSource, evidenceSource, sealed, collection, run: latestRun,
      execution: latestClosed.execution.find((row) => row.task_index === taskIndex), recorded, taskIndex, sequenceMode });
    return { task, closedTask, latestClosed, latestRun, collection, sealed, recorded, reconstructed, feedback,
      terminalization: fenceAndComplete?.terminalization ?? null };
  } finally { await close(); }
}

async function fenceAndCompleteKnownS1({ input, output, record, observerPool, postgresByEnvironment, created, taskReleaseSource,
  evidenceSource, sealed, collection, run, execution, recorded, taskIndex = 0, sequenceMode = false }) {
  const taskId = recorded.evaluation.result.taskId;
  demand(SUPPORTED_TASKS.has(taskId) && run.task_ids[taskIndex] === taskId && taskIndex < run.task_ids.length,
    'completion_task_identity_mismatch');
  const preparationId = sealed.bundle.execution.preparationId;
  const leaseId = sealed.bundle.execution.leaseId;
  const generationId = sealed.bundle.execution.generationId;
  const environmentId = run.environment_id;
  demand(UUID.test(preparationId) && UUID.test(leaseId) && UUID.test(generationId) &&
    environmentId === execution?.env_id && environmentId === 'bef-env-a', 'sealed_preparation_identity_invalid');
  demand(collection.evidence?.path && HEX_HASH.test(collection.evidence.sha256), 'sealed_capture_reference_missing');
  const packetBytes = await safeBytes(input.repoRoot, collection.evidence.path, collection.evidence.sha256, 8 * 1024 * 1024);
  let packet;
  try { packet = JSON.parse(packetBytes.bytes.toString('utf8')); } catch { throw fail('sealed_capture_packet_invalid'); }
  const binding = sealed.bundle.binding;
  demand(execution && packet?.schemaVersion === 'bts-' + taskId.toLowerCase() + '-run-observation-capture/v1' &&
    packet.binding?.runId === run.id && packet.binding?.ownerId === run.owner_id && packet.binding?.agentId === run.agent_id &&
    packet.binding?.taskId === taskId && packet.execution?.preparationId === preparationId &&
    packet.execution?.leaseId === leaseId && packet.execution?.generationId === generationId &&
    packet.execution?.environmentId === environmentId && packet.closure?.closureId === sealed.bundle.closure.closureId &&
    binding?.runId === run.id && binding?.ownerId === run.owner_id && binding?.agentId === run.agent_id &&
    binding?.taskId === taskId && binding?.environmentId === environmentId &&
    binding?.releaseIdentity === run.release_identity && binding?.manifestHash === run.manifest_hash &&
    binding?.caseId === execution.case_id && binding?.caseHash === execution.case_hash &&
    execution.preparation_id === preparationId && execution.lease_id === leaseId &&
    execution.generation_id === generationId && execution.lease_state === 'leased' &&
    execution.initial_state_sha256 === sealed.bundle.execution.initialStateSha256,
  'sealed_original_generation_binding_mismatch');

  const { getTaskPreparation, fenceTaskPreparationWithEvidence } = await import('../../owner-identity/dist/task-preparation.js');
  const preparation = await getTaskPreparation(created.db, preparationId);
  demand(preparation && preparation.intent.preparationId === preparationId && preparation.intent.leaseId === leaseId &&
    preparation.intent.runId === run.id && preparation.intent.taskIndex === taskIndex && preparation.intent.taskId === taskId &&
    preparation.intent.environmentId === environmentId && preparation.intent.releaseIdentity === run.release_identity &&
    preparation.intent.manifestHash === run.manifest_hash && preparation.intent.caseId === binding.caseId &&
    preparation.intent.caseHash === binding.caseHash && preparation.intent.initialStateSha256 === sealed.bundle.execution.initialStateSha256 &&
    preparation.observation.status === 'ready' && preparation.observation.generationId === generationId &&
    preparation.leaseStatus === 'leased', 'owner_preparation_original_generation_mismatch');

  const config = (await import('../../owner-identity/dist/config.js')).loadConfig({
    ...process.env, OID_DATABASE_URL: input.databaseUrl,
  });
  demand(typeof config.localBefTaskCoordinatorConfigPath === 'string' && config.localBefTaskCoordinatorConfigPath.length > 0,
    'private_coordinator_config_path_missing');
  const fileConfig = await (await import('../../owner-identity/dist/bef-task-coordinator.js'))
    .loadLocalBefTaskCoordinatorConfig(config.localBefTaskCoordinatorConfigPath, input.repoRoot);
  demand(Array.isArray(fileConfig.environments) && fileConfig.environments.length > 0 &&
    fileConfig.environments.every((item) => item && typeof item.envId === 'string' && item.x402Policy?.localAnvil),
  'private_coordinator_environment_map_invalid');
  const apiBaseByEnvironment = {};
  const observerRpcByEnvironment = {};
  const anvilManifestPinByEnvironment = {};
  for (const item of fileConfig.environments) {
    apiBaseByEnvironment[item.envId] = item.apiBaseUrl;
    observerRpcByEnvironment[item.envId] = item.observerRpcUrl;
    anvilManifestPinByEnvironment[item.envId] = {
      manifestSha256: item.x402Policy.manifestSha256.toLowerCase(),
      executionNetwork: item.x402Policy.localAnvil.executionNetwork,
      hardFork: item.x402Policy.localAnvil.hardFork,
      anvilVersion: item.x402Policy.localAnvil.anvilVersion,
    };
  }
  demand(Object.hasOwn(apiBaseByEnvironment, environmentId) && Object.hasOwn(observerRpcByEnvironment, environmentId) &&
    Object.hasOwn(anvilManifestPinByEnvironment, environmentId), 'original_bef_environment_not_configured');

  let fenceArtifact = null;
  const { mkdir: makeDirectory, realpath: resolveRealPath, writeFile: writeEvidenceFile } = await import('node:fs/promises');
  const { resolve: resolvePath, relative: relativePath, sep: pathSeparator, isAbsolute: isPathAbsolute } = await import('node:path');
  const evidenceSink = {
    async write(value) {
      demand(value?.kind === 'fence' && value.preparationId === preparationId && value.environmentId === environmentId,
        'fence_evidence_identity_mismatch');
      assertSecretFree(value, 'genuine-s1-fence-evidence');
      const evidenceRoot = resolvePath(input.repoRoot, 'artifacts/runs/owner-identity-bef-task-coordinator/preparation');
      await makeDirectory(evidenceRoot, { recursive: true, mode: 0o700 });
      const realRoot = await resolveRealPath(evidenceRoot);
      const repositoryReal = await realpath(input.repoRoot);
      const relRoot = relativePath(repositoryReal, realRoot);
      demand(relRoot && !isPathAbsolute(relRoot) && relRoot !== '..' && !relRoot.startsWith('..' + pathSeparator),
        'fence_evidence_directory_escape');
      const bytes = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
      demand(bytes.length <= 4 * 1024 * 1024, 'fence_evidence_oversized');
      const name = preparationId + '-' + randomUUID() + '.json';
      await writeEvidenceFile(resolvePath(realRoot, name), bytes, { flag: 'wx', mode: 0o600 });
      fenceArtifact = { path: 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/' + name,
        sha256: digest(bytes), boundary: BOUNDARY };
      return fenceArtifact;
    },
  };
  let adminKey = fileConfig.adminKey;
  const { BefTaskPreparationAdapter } = await import('../../owner-identity/dist/bef-task-preparation.js');
  const preparationAdapter = new BefTaskPreparationAdapter({ apiBaseByEnvironment, observerRpcByEnvironment,
    sourceRpcUrl: fileConfig.sourceRpcUrl, adminKey, anvilManifestPinByEnvironment,
    releaseSource: taskReleaseSource, evidenceSink });
  adminKey = '';
  fileConfig.adminKey = '';
  let fence;
  try {
    fence = await fenceTaskPreparationWithEvidence({ db: created.db, preparationAdapter }, preparationId, generationId);
  } finally {
    preparationAdapter.clearCredentials?.(preparationId);
    adminKey = '';
  }
  demand(fence?.released === true && fence.evidenceHash === fenceArtifact?.sha256, 'original_generation_fence_unconfirmed');
  const fencedPreparation = await getTaskPreparation(created.db, preparationId);
  demand(fencedPreparation?.leaseStatus === 'fenced' && fencedPreparation.observation.status === 'fenced' &&
    fencedPreparation.observation.generationId === generationId, 'owner_database_fence_readback_mismatch');
  const befFenceRows = await postgresByEnvironment[environmentId].readFenceProof({ preparationId, generationId });
  const befFence = befFenceRows[0];
  demand(befFenceRows.length === 1 && befFence.generation_id === generationId && befFence.env_id === environmentId &&
    befFence.generation_status === 'fenced' && befFence.fenced_at && befFence.preparation_id === preparationId &&
    befFence.preparation_status === 'fenced' && befFence.fence_confirmed_at &&
    befFence.preparation_generation_id === generationId &&
    befFence.environment_manifest_sha256 === sealed.bundle.execution.environmentManifestHash,
  'independent_bef_generation_fence_readback_mismatch');
  const fenceFact = { status: 'verified', taskIndex, taskId, preparationId, leaseId, generationId, environmentId,
    ownerLeaseStatus: fencedPreparation.leaseStatus, ownerPreparationStatus: fencedPreparation.observation.status,
    generationStatus: befFence.generation_status, preparationStatus: befFence.preparation_status,
    fenceEvidence: fenceArtifact, replayed: fence.replayed };
  if (!Array.isArray(output.taskGenerationFences)) output.taskGenerationFences = [];
  output.taskGenerationFences.push(fenceFact);
  if (!sequenceMode) output.originalGenerationFence = fenceFact;
  else if (taskIndex === 0) output.originalGenerationFence = fenceFact;
  output.internalEvaluationBridge.ownerFeedbackVisibility = output.ownerTrainingFeedback?.status === 'observed'
    ? 'observed_through_owner_auth_api' : 'unknown';
  record('original_bef_generation_fence_and_independent_readback', 'verified', {
    taskIndex, taskId, generationId, fenceEvidenceSha256: fenceArtifact.sha256, independentObserverRole: 'bef_observer',
  });

  const beforeCompletion = await readOwnerRunCompletionState(observerPool, { runId: run.id, ownerId: run.owner_id });
  const expectedTaskStatus = recorded.evaluation.result.outcome === 'failed' ? 'failed' : 'completed';
  demand(beforeCompletion.run?.mode === 'training' && beforeCompletion.run.status === 'running' &&
    beforeCompletion.run.owner_id === run.owner_id && beforeCompletion.run.quote_price_units &&
    beforeCompletion.completionEvents.length === 0 && beforeCompletion.claims.length === 1 && beforeCompletion.claims[0].status === 'claimed' &&
    beforeCompletion.slots.length === 1 && beforeCompletion.slots[0].run_id === run.id &&
    beforeCompletion.slots[0].agent_id === run.agent_id && beforeCompletion.slots[0].claim_id === beforeCompletion.claims[0].claim_id &&
    beforeCompletion.reservations.length === 1 &&
    beforeCompletion.reservations.every((row) => row.state === 'debited') && beforeCompletion.budgetHolds.length === 1 &&
    beforeCompletion.budgetHolds[0].state === 'charged' && beforeCompletion.ownerRefundCount === 0 &&
    beforeCompletion.ledger.every((row) => row.entry_type !== 'refund' && row.entry_type !== 'release'),
  'training_run_precompletion_money_or_claim_state_mismatch');
  const reservedUnits = beforeCompletion.reservations.reduce((sum, row) => sum + BigInt(row.amount_units), 0n);
  demand(reservedUnits === BigInt(beforeCompletion.run.quote_price_units), 'training_run_charge_does_not_match_quote');
  if (taskIndex === 0) {
    output.dispatchIdentity = { runId: run.id, claimId: beforeCompletion.claims[0].claim_id,
      slotRunId: beforeCompletion.slots[0].run_id, slotAgentId: beforeCompletion.slots[0].agent_id,
      slotClaimId: beforeCompletion.slots[0].claim_id };
  } else if (sequenceMode) {
    demand(output.dispatchIdentity?.runId === run.id && beforeCompletion.claims[0]?.claim_id === output.dispatchIdentity.claimId &&
      beforeCompletion.slots[0]?.run_id === output.dispatchIdentity.slotRunId &&
      beforeCompletion.slots[0]?.agent_id === output.dispatchIdentity.slotAgentId &&
      beforeCompletion.slots[0]?.claim_id === output.dispatchIdentity.slotClaimId,
    'training_sequence_dispatch_identity_changed_between_tasks');
  }

  const terminalizeSuccessorPredecessor = sequenceMode && taskIndex === 0 && taskIndex < run.task_ids.length - 1;
  if (terminalizeSuccessorPredecessor) {
    demand(recorded.evaluation.result.status === 'known' && recorded.evaluation.result.mandatoryViolation === null,
      'successor_predecessor_has_mandatory_violation');
    const { finalizeKnownTrainingTask } = await import('../../owner-identity/dist/task-run-completion.js');
    const finalized = await finalizeKnownTrainingTask({ db: created.db, taskReleaseSource, evidenceSource },
      { runId: run.id, taskIndex });
    demand(finalized.runId === run.id && finalized.taskIndex === taskIndex && finalized.taskId === taskId &&
      finalized.status === expectedTaskStatus && finalized.replayed === false, 'known_training_predecessor_not_terminalized');
    const afterTerminalization = await readOwnerRunCompletionState(observerPool, { runId: run.id, ownerId: run.owner_id });
    const task = afterTerminalization.tasks.find((row) => row.task_index === taskIndex);
    const terminalizationEvents = afterTerminalization.terminalizationEvents.filter((event) => {
      const payload = typeof event.payload_json === 'string' ? JSON.parse(event.payload_json) : event.payload_json;
      return payload?.taskIndex === taskIndex;
    });
    const terminalizationPayload = terminalizationEvents.length === 1
      ? (typeof terminalizationEvents[0].payload_json === 'string'
        ? JSON.parse(terminalizationEvents[0].payload_json) : terminalizationEvents[0].payload_json) : null;
    demand(afterTerminalization.run?.status === 'running' && task?.task_id === taskId && task.status === expectedTaskStatus &&
      task.finished_at && terminalizationEvents.length === 1 && terminalizationEvents[0].source === 'coordinator' &&
      terminalizationEvents[0].payload_hash === eventPayloadHash(terminalizationPayload) &&
      terminalizationPayload?.runId === run.id && terminalizationPayload.taskIndex === taskIndex &&
      terminalizationPayload.taskId === taskId && terminalizationPayload.closureId === sealed.bundle.closure.closureId &&
      terminalizationPayload.inputHash === recorded.evaluation.inputHash && terminalizationPayload.resultHash === recorded.evaluation.resultHash &&
      terminalizationPayload.preparationId === preparationId && terminalizationPayload.leaseId === leaseId &&
      terminalizationPayload.generationId === generationId && terminalizationPayload.fenceEvidenceHash === fenceArtifact.sha256 &&
      afterTerminalization.completionEvents.length === 0 && afterTerminalization.claims.length === 1 &&
      afterTerminalization.claims[0].status === 'claimed' && afterTerminalization.claims[0].claim_id === output.dispatchIdentity.claimId &&
      afterTerminalization.slots.length === 1 && afterTerminalization.slots[0].run_id === output.dispatchIdentity.slotRunId &&
      afterTerminalization.slots[0].agent_id === output.dispatchIdentity.slotAgentId &&
      afterTerminalization.slots[0].claim_id === output.dispatchIdentity.slotClaimId &&
      afterTerminalization.moneySha256 === beforeCompletion.moneySha256 && afterTerminalization.ownerRefundCount === 0,
    'known_training_predecessor_terminalization_readback_mismatch');
    output.predecessorTerminalization = { status: 'verified', taskIndex, taskId, terminalStatus: finalized.status,
      finishedAt: finalized.finishedAt, terminalizationEventId: terminalizationEvents[0].id,
      terminalizationEventHash: terminalizationEvents[0].payload_hash,
      closureId: terminalizationPayload.closureId, outcome: terminalizationPayload.outcome,
      inputHash: recorded.evaluation.inputHash, resultHash: recorded.evaluation.resultHash,
      preparationId, leaseId, generationId, environmentId, fenceEvidenceHash: fenceArtifact.sha256,
      runStatus: afterTerminalization.run.status, dispatchClaimStatus: afterTerminalization.claims[0].status,
      remainingExecutionSlots: afterTerminalization.slots.length, moneyStateUnchanged: true,
      moneyStateSha256: afterTerminalization.moneySha256,
      originalGenerationFenceStatus: 'verified' };
    output.predecessorTerminalizations ??= [];
    output.predecessorTerminalizations[taskIndex] = output.predecessorTerminalization;
    record('known_training_predecessor_terminalization_and_readonly_owner_database', 'verified', {
      taskIndex, taskId, terminalizationEvents: terminalizationEvents.length,
      claimStatus: afterTerminalization.claims[0].status, slotsRemaining: afterTerminalization.slots.length,
      moneyStateUnchanged: true,
    });
    return { terminalization: finalized, before: beforeCompletion, after: afterTerminalization };
  }

  const { completeKnownTrainingRun } = await import('../../owner-identity/dist/task-run-completion.js');
  const completionDeps = { db: created.db, taskReleaseSource, evidenceSource };
  const completion = await completeKnownTrainingRun(completionDeps, { runId: run.id });
  demand(completion.status === 'completed' && completion.replayed === false, 'known_training_completion_not_committed');
  const afterCompletion = await readOwnerRunCompletionState(observerPool, { runId: run.id, ownerId: run.owner_id });
  const expectedResults = output.taskEvaluations?.length
    ? output.taskEvaluations.map((item) => item.result)
    : [{ taskId, status: recorded.evaluation.result.status, outcome: recorded.evaluation.result.outcome,
      credit: recorded.evaluation.result.credit }];
  const expectedTasks = run.task_ids.map((selectedTaskId, index) => {
    const result = expectedResults.find((item) => item.taskId === selectedTaskId);
    return { taskId: selectedTaskId, status: result?.outcome === 'failed' ? 'failed' : 'completed' };
  });
  if (sequenceMode) {
    demand(output.predecessorTerminalization?.moneyStateSha256 === beforeCompletion.moneySha256 &&
      beforeCompletion.reservations.length === 1 && beforeCompletion.reservations[0].amount_units === beforeCompletion.run.quote_price_units,
    'training_sequence_charge_or_ledger_changed_between_tasks');
  }
  demand(afterCompletion.run?.status === 'completed' && afterCompletion.run.finished_at &&
    afterCompletion.tasks.length === run.task_ids.length && afterCompletion.tasks.every((task, index) =>
      task.task_index === index && task.task_id === expectedTasks[index]?.taskId && task.status === expectedTasks[index]?.status) &&
    afterCompletion.evaluations.length === run.task_ids.length && afterCompletion.evaluations.every((evaluation, index) =>
      evaluation.task_index === index && evaluation.task_id === run.task_ids[index] && evaluation.result_status === 'known') &&
    afterCompletion.terminalizationEvents.length === run.task_ids.length - 1 && afterCompletion.terminalizationEvents.every((event, index) => {
      const payload = typeof event.payload_json === 'string' ? JSON.parse(event.payload_json) : event.payload_json;
      return event.source === 'coordinator' && payload?.runId === run.id && payload.taskIndex === index &&
        payload.taskId === run.task_ids[index] && event.payload_hash === eventPayloadHash(payload);
    }) && afterCompletion.completionEvents.length === 1 &&
    afterCompletion.completionEvents[0].source === 'coordinator' && afterCompletion.claims.length === 1 &&
    afterCompletion.claims[0].status === 'released' && afterCompletion.claims[0].released_at &&
    afterCompletion.claims[0].claim_id === output.dispatchIdentity.claimId && afterCompletion.slots.length === 0 &&
    afterCompletion.reservations.every((row) => row.state === 'debited') && afterCompletion.budgetHolds.length === 1 &&
    afterCompletion.budgetHolds[0].state === 'charged' && afterCompletion.ownerRefundCount === 0 &&
    afterCompletion.moneySha256 === beforeCompletion.moneySha256,
  'known_training_completion_readback_mismatch');
  const completedEvent = afterCompletion.completionEvents[0];
  const completedPayload = typeof completedEvent.payload_json === 'string'
    ? JSON.parse(completedEvent.payload_json) : completedEvent.payload_json;
  demand(completedPayload?.runId === run.id && completedPayload.mode === 'training' &&
    JSON.stringify(completedPayload.taskIds) === JSON.stringify(run.task_ids) &&
    completedPayload.finishedAt === completion.finishedAt &&
    completedEvent.payload_hash === eventPayloadHash(completedPayload) &&
    Array.isArray(completedPayload.tasks) && completedPayload.tasks.length === run.task_ids.length &&
    completedPayload.tasks.every((proof, index) => {
      const evaluation = output.taskEvaluations.find((entry) => entry.taskIndex === index);
      const originalFence = output.taskGenerationFences.find((entry) => entry.taskIndex === index);
      const finish = output.participantActions.find((entry) => entry.taskIndex === index && entry.kind === 'finish');
      return proof.taskIndex === index && proof.taskId === run.task_ids[index] &&
        proof.closureId === finish?.closureId && proof.inputHash === evaluation?.inputHash &&
        proof.resultHash === evaluation?.resultHash && proof.preparationId === originalFence?.preparationId &&
        proof.leaseId === originalFence?.leaseId && proof.generationId === originalFence?.generationId &&
        proof.fenceEvidenceHash === originalFence?.fenceEvidence?.sha256;
    }), 'known_training_completion_payload_readback_mismatch');
  const replay = await completeKnownTrainingRun(completionDeps, { runId: run.id });
  const afterReplay = await readOwnerRunCompletionState(observerPool, { runId: run.id, ownerId: run.owner_id });
  demand(replay.status === 'completed' && replay.replayed === true && replay.finishedAt === completion.finishedAt &&
    afterReplay.stateSha256 === afterCompletion.stateSha256 && afterReplay.moneySha256 === afterCompletion.moneySha256 &&
    afterReplay.completionEvents.length === 1, 'known_training_completion_replay_mismatch');
  output.trainingRunCompletion = { status: 'verified', runStatus: afterReplay.run.status, finishedAt: completion.finishedAt,
    completionEventId: afterReplay.completionEvents[0].id, completionEventPayloadHash: afterReplay.completionEvents[0].payload_hash,
    taskStatus: afterReplay.tasks[taskIndex].status, taskStatuses: afterReplay.tasks.map((task) => ({ taskIndex: task.task_index,
      taskId: task.task_id, status: task.status })), dispatchClaimStatus: afterReplay.claims[0].status,
    dispatchClaimReleasedAt: afterReplay.claims[0].released_at, remainingExecutionSlots: afterReplay.slots.length,
    reservationStates: afterReplay.reservations.map((row) => row.state), budgetHoldStates: afterReplay.budgetHolds.map((row) => row.state),
    chargeQuoteUnits: beforeCompletion.run.quote_price_units, reservationUnits: reservedUnits.toString(),
    ownerLedgerRowCount: afterReplay.ownerLedgerCount, ownerLedgerSha256: afterReplay.ownerLedgerSha256,
    ownerRefundCount: afterReplay.ownerRefundCount,
    moneyStateUnchangedByCompletion: beforeCompletion.moneySha256 === afterReplay.moneySha256,
    completionReplayVerified: replay.replayed };
  output.completionBridge = { classification: sequenceMode
      ? 'internal_evaluation_fence_completion_bridge_with_real_worker_successor_advancement'
      : 'internal_observer_evaluation_fence_and_training_completion_bridge_not_worker_action_dispatch',
    status: 'completed', automaticWorkerEvaluation: false,
    ...(!sequenceMode ? { automaticWorkerEvaluationOrAdvance: false } : {}),
    actualServerWorkerSuccessorAdvancement: sequenceMode &&
      output.trainingSuccessorActivations?.length === taskIds.length - 1,
    taskGradePublished: false,
    taskGradePublicationScope: 'public_ranked_or_leaderboard_surface',
    ownerFeedbackVisibility: output.internalEvaluationBridge.ownerFeedbackVisibility,
    runCompletionService: 'completeKnownTrainingRun' };
  record('known_training_completion_and_readonly_owner_database', 'verified', {
    runStatus: afterReplay.run.status, completionEvents: afterReplay.completionEvents.length,
    claimStatus: afterReplay.claims[0].status, slotsRemaining: afterReplay.slots.length,
    moneyStateUnchanged: beforeCompletion.moneySha256 === afterReplay.moneySha256, replayed: replay.replayed,
  });
  await input.ownerPage.goto('/runs', { waitUntil: 'domcontentloaded' });
  const runCard = input.ownerPage.getByTestId('owner-run-' + run.id);
  await runCard.waitFor({ state: 'visible', timeout: 15_000 });
  demand((await runCard.getByTestId('owner-run-status-' + run.id).innerText()).trim() === 'completed',
    'completed_run_not_visible_in_owner_ui');
  const feedbackResponse = input.ownerPage.waitForResponse((response) =>
    new URL(response.url()).pathname === '/api/owner/runs/' + run.id + '/results' &&
    response.request().method() === 'GET', { timeout: 15_000 });
  await runCard.getByTestId('run-feedback-load-' + run.id).click();
  const feedbackHttp = await feedbackResponse;
  const uiTaskResults = [];
  for (const expected of expectedResults) {
    const taskFeedback = runCard.getByTestId('run-feedback-task-' + run.id + '-' + expected.taskId);
    await taskFeedback.waitFor({ state: 'visible', timeout: 15_000 });
    const feedbackText = (await taskFeedback.innerText()).replace(/\s+/g, ' ').trim();
    const expectedCredit = expected.credit;
    const matches = expected.status === 'known' && expectedCredit && feedbackText.includes(expected.outcome) &&
      feedbackText.includes('Credit ' + expectedCredit.numerator + '/' + expectedCredit.denominator);
    demand(feedbackHttp.status() === 200 && matches, 'owner_result_ui_does_not_match_persisted_evaluation');
    uiTaskResults.push({ taskId: expected.taskId, outcome: expected.outcome, credit: expectedCredit });
  }
  const feedbackApi = await readOwnerTrainingFeedbackTasks(input.ownerPage, run.id, expectedResults);
  demand(feedbackApi.status === 'observed' && feedbackApi.consistentWithInternalEvaluation &&
    feedbackApi.tasks.length === run.task_ids.length, 'owner_results_api_does_not_match_all_persisted_evaluations');
  output.ownerTrainingFeedbackUi = sequenceMode
    ? { status: 'verified', browserHttpStatus: feedbackHttp.status(), runStatus: 'completed',
      tasks: uiTaskResults, resultsApi: feedbackApi, classification: 'owner_button_to_results_api_and_persisted_evaluation' }
    : { status: 'verified', browserHttpStatus: feedbackHttp.status(), runStatus: 'completed', taskId,
      outcome: recorded.evaluation.result.outcome, credit: recorded.evaluation.result.credit,
      resultsApi: feedbackApi, classification: 'owner_button_to_results_api_and_persisted_evaluation' };
  record('owner_training_result_ui_readback', 'verified', output.ownerTrainingFeedbackUi);
}

async function requestOwnerSnapshot(pool, ownerId, agentId) {
  return readonlyTransaction(pool, async (query) => {
    const owner = await query('SELECT id::text,admission_status FROM oid_owner WHERE id=$1', [ownerId]);
    const agent = await query(`SELECT a.id::text,a.owner_id::text,a.name,a.declared_version,a.revision,p.training,p.ranked,p.revision AS policy_revision
      FROM oid_agent a JOIN oid_agent_policy p ON p.agent_id=a.id WHERE a.id=$1 AND a.owner_id=$2`, [agentId, ownerId]);
    return { owner: pgRows(owner), agent: pgRows(agent) };
  });
}

async function setS1FinancialPolicyThroughOwnerUi({ ownerPage, observerPool, ownerId, agentId, limitUnits = 100_000n }) {
  const form = ownerPage.getByTestId('financial-policy-form-' + agentId);
  await form.waitFor({ state: 'visible', timeout: 15_000 });
  const cap = async (name) => ({
    amount: await ownerPage.getByTestId('financial-policy-' + name + '-limit-' + agentId).inputValue(),
    unlimited: await ownerPage.getByTestId('financial-policy-' + name + '-unlimited-' + agentId).isChecked(),
  });
  const initial = {
    allowCashShortfall: await ownerPage.getByTestId('financial-policy-cash-' + agentId).isChecked(),
    operation: await cap('operation'), utcDay: await cap('utc-day'),
    benchmark: await cap('benchmark'), forum: await cap('forum'),
  };
  demand(initial.allowCashShortfall === false &&
    ['operation', 'utcDay', 'benchmark', 'forum'].every((key) => initial[key].amount === '0.000000' && !initial[key].unlimited),
  'new_agent_financial_policy_default_mismatch');

  const amount = formatUsdcUnits(limitUnits);
  const forumAmount = '0.000000';
  const cashSwitch = ownerPage.getByTestId('financial-policy-cash-' + agentId);
  if (await cashSwitch.isChecked()) await cashSwitch.uncheck();
  await ownerPage.getByTestId('financial-policy-operation-limit-' + agentId).fill(amount);
  await ownerPage.getByTestId('financial-policy-utc-day-limit-' + agentId).fill(amount);
  await ownerPage.getByTestId('financial-policy-benchmark-limit-' + agentId).fill(amount);
  await ownerPage.getByTestId('financial-policy-forum-limit-' + agentId).fill(forumAmount);

  const endpoint = '/api/owner/agents/' + encodeURIComponent(agentId) + '/financial-policy';
  const requestPromise = ownerPage.waitForRequest((request) => new URL(request.url()).pathname === endpoint && request.method() === 'PUT',
    { timeout: 15_000 }).catch(() => null);
  const responsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === endpoint &&
    response.request().method() === 'PUT', { timeout: 15_000 }).catch(() => null);
  await ownerPage.getByTestId('financial-policy-save-' + agentId).click();
  const [request, response] = await Promise.all([requestPromise, responsePromise]);
  demand(request, 'financial_policy_ui_request_unavailable');
  let body;
  try { body = request.postDataJSON(); } catch { throw fail('financial_policy_ui_request_invalid'); }
  demand(typeof body?.operationId === 'string' && /^[A-Za-z0-9_-]{12,128}$/.test(body.operationId) &&
    body.expectedRevision === 0 && body.allowCashShortfall === false &&
    exactUsdcUnits(body.operationLimit) === limitUnits && exactUsdcUnits(body.utcDayLimit) === limitUnits &&
    exactUsdcUnits(body.categoryLimits?.benchmark) === limitUnits && exactUsdcUnits(body.categoryLimits?.forum) === 0n,
  'financial_policy_ui_request_binding_mismatch');

  const persisted = await readonlyTransaction(observerPool, async (query) => {
    const policy = await query(`SELECT owner_id::text,agent_id::text,revision,allow_cash_shortfall,
        operation_limit_units::text,utc_day_limit_units::text,category_limits
      FROM oid_agent_financial_policy WHERE owner_id=$1::uuid AND agent_id=$2::uuid`, [ownerId, agentId]);
    const operation = await query(`SELECT id::text,actor_owner_id::text,subject_owner_id::text,operation_id,action,payload_hash,response_json
      FROM oid_ledger_operation WHERE actor_owner_id=$1::uuid AND operation_id=$2 ORDER BY created_at,id`, [ownerId, body.operationId]);
    const audit = await query(`SELECT id::text,event_type,operation_id,actor_owner_id::text,subject_owner_id::text,metadata
      FROM oid_ledger_audit WHERE actor_owner_id=$1::uuid AND operation_id=$2
        AND event_type='agent_financial_policy_updated' ORDER BY created_at,id`, [ownerId, body.operationId]);
    return { policy: pgRows(policy), operation: pgRows(operation), audit: pgRows(audit) };
  });
  const policy = persisted.policy[0];
  const operation = persisted.operation[0];
  const audit = persisted.audit[0];
  let categoryLimits = policy?.category_limits;
  let responseJson = operation?.response_json;
  let auditMetadata = audit?.metadata;
  try { if (typeof categoryLimits === 'string') categoryLimits = JSON.parse(categoryLimits); } catch { categoryLimits = null; }
  try { if (typeof responseJson === 'string') responseJson = JSON.parse(responseJson); } catch { responseJson = null; }
  try { if (typeof auditMetadata === 'string') auditMetadata = JSON.parse(auditMetadata); } catch { auditMetadata = null; }
  demand(persisted.policy.length === 1 && policy.owner_id === ownerId && policy.agent_id === agentId && policy.revision === 1 &&
    policy.allow_cash_shortfall === false && BigInt(policy.operation_limit_units) === limitUnits &&
    BigInt(policy.utc_day_limit_units) === limitUnits && categoryLimits?.benchmark === amount && categoryLimits?.forum === forumAmount,
  'financial_policy_readonly_database_mismatch');
  demand(persisted.operation.length === 1 && operation.actor_owner_id === ownerId && operation.subject_owner_id === ownerId &&
    operation.operation_id === body.operationId && operation.action === 'agent_financial_policy_update' && HEX_HASH.test(operation.payload_hash) &&
    responseJson?.revision === 1 && responseJson.allowCashShortfall === false && responseJson.operationLimit === amount &&
    responseJson.utcDayLimit === amount && responseJson.categoryLimits?.benchmark === amount && responseJson.categoryLimits?.forum === forumAmount,
  'financial_policy_operation_receipt_mismatch');
  demand(persisted.audit.length === 1 && audit.event_type === 'agent_financial_policy_updated' &&
    audit.operation_id === body.operationId && audit.actor_owner_id === ownerId && audit.subject_owner_id === ownerId &&
    auditMetadata?.agentId === agentId && auditMetadata.revision === 1 && auditMetadata.allowCashShortfall === false &&
    auditMetadata.operationLimit === amount && auditMetadata.utcDayLimit === amount &&
    auditMetadata.categoryLimits?.benchmark === amount && auditMetadata.categoryLimits?.forum === forumAmount,
  'financial_policy_audit_binding_mismatch');

  const responseBody = response ? await response.json().catch(() => ({})) : {};
  let uiConfirmedSaved = false;
  if (response?.status() === 200) {
    demand(responseBody.revision === 1 && responseBody.allowCashShortfall === false && responseBody.operationLimit === amount &&
      responseBody.utcDayLimit === amount && responseBody.categoryLimits?.benchmark === amount &&
      responseBody.categoryLimits?.forum === forumAmount, 'financial_policy_ui_response_mismatch');
    await ownerPage.waitForFunction((id) => /saved.*revision 1/i.test(
      document.querySelector(`[data-testid="financial-policy-status-${id}"]`)?.textContent ?? ''), agentId, { timeout: 15_000 });
    uiConfirmedSaved = /saved.*revision 1/i.test(await ownerPage.getByTestId('financial-policy-status-' + agentId).innerText());
  }
  await ownerPage.reload({ waitUntil: 'domcontentloaded' });
  await ownerPage.getByTestId('agent-card-' + agentId).waitFor({ state: 'visible' });
  await form.waitFor({ state: 'visible', timeout: 15_000 });
  const saved = {
    allowCashShortfall: await cashSwitch.isChecked(),
    operation: await cap('operation'), utcDay: await cap('utc-day'),
    benchmark: await cap('benchmark'), forum: await cap('forum'),
  };
  demand(saved.allowCashShortfall === false && saved.operation.amount === amount && !saved.operation.unlimited &&
    saved.utcDay.amount === amount && !saved.utcDay.unlimited && saved.benchmark.amount === amount && !saved.benchmark.unlimited &&
    saved.forum.amount === forumAmount && !saved.forum.unlimited, 'financial_policy_reload_ui_mismatch');
  return {
    operationId: body.operationId, expectedRevision: body.expectedRevision, revision: policy.revision,
    allowCashShortfall: policy.allow_cash_shortfall, operationLimitUnits: policy.operation_limit_units,
    utcDayLimitUnits: policy.utc_day_limit_units, categoryLimits,
    browserHttpStatus: response?.status() ?? null, responseReconciledFromDatabase: response === null || response.status() !== 200,
    uiConfirmedSaved, databaseReadback: {
      role: 'oid_observer', policyRevision: policy.revision, operationReceiptId: operation.id, operationPayloadHash: operation.payload_hash,
      auditId: audit.id, auditEventType: audit.event_type,
    },
  };
}

async function requestOwnerCancellation({ ownerPage, runId, observerPool, output }) {
  if (!runId) return;
  try {
    await ownerPage.goto('/runs', { waitUntil: 'domcontentloaded' });
    const runCard = ownerPage.getByTestId('owner-run-' + runId);
    await runCard.waitFor({ state: 'visible', timeout: 12_000 });
    const cancel = ownerPage.getByTestId('run-cancel-' + runId);
    if (await cancel.count() === 1 && await cancel.isVisible()) {
      const responsePromise = ownerPage.waitForResponse((response) => new URL(response.url()).pathname === '/api/owner/runs/' + runId + '/cancel'
        && response.request().method() === 'POST', { timeout: 15_000 });
      await cancel.click();
      const response = await responsePromise;
      output.stages.push({ name: 'owner_cancel_ui', status: response.ok() ? 'requested' : 'blocked', httpStatus: response.status() });
    } else {
      output.stages.push({ name: 'owner_cancel_ui', status: 'not_available_run_already_terminal' });
    }
  } catch (error) {
    output.stages.push({ name: 'owner_cancel_ui', status: 'unknown', reasonCode: safeErrorCode(error, 'owner_cancel_ui_unavailable') });
  }
  try {
    const end = Date.now() + 60_000;
    let latest = null;
    while (Date.now() < end) {
      latest = await readRunSnapshot(observerPool, { runId });
      const row = latest.run[0];
      if (row && ['cancelled', 'failed', 'expired', 'completed', 'disqualified', 'unknown'].includes(row.status)) {
        output.runAfterCleanup = row;
        const preparationIndexes = latest.preparations.map((entry) => entry.task_index);
        const trainingSequenceObserved = output.mode === 'training' && output.taskIds?.length > 1;
        const sequenceObservedS2 = trainingSequenceObserved && output.taskIds?.[1] === 'S2' &&
          output.trainingSuccessorActivations?.some((entry) => entry.toTaskIndex === 1) === true;
        const transitionCount = output.trainingSuccessorActivations?.length ?? 0;
        const trainingSequenceTransitionsObserved = trainingSequenceObserved && transitionCount === output.taskIds.length - 1;
        output.cleanupEvidence = { terminalStatus: row.status,
          cancellationEvidencePresent: typeof row.cancellation_evidence_hash === 'string' && HEX_HASH.test(row.cancellation_evidence_hash),
          ...(output.mode === 'training' ? { sequenceObservedS2, trainingSequenceTransitionsObserved,
            successorActivationCount: transitionCount } : {}),
          preparationLeaseCount: latest.preparations.length,
          preparationTaskIndexes: preparationIndexes,
          allTaskLeasesFenced: trainingCleanupLeasePrefixIsFenced({ mode: output.mode,
            preparations: latest.preparations, taskIds: output.taskIds }) };
        return;
      }
      await delay(750);
    }
    output.runAfterCleanup = latest?.run?.[0] ?? null;
    output.cleanupEvidence = { terminalStatus: output.runAfterCleanup?.status ?? null,
      cancellationEvidencePresent: false, allTaskLeasesFenced: false };
  } catch (error) {
    output.cleanupEvidence = { terminalStatus: 'unknown', cancellationEvidencePresent: false, allTaskLeasesFenced: false,
      reasonCode: safeErrorCode(error, 'cleanup_observation_unavailable') };
  }
}

/**
 * AICODE-NOTE: This opt-in harness uses the real owner UI and agent API plus read-only owner/BEF observers.
 * Training sequences observe each real server successor preparation and activation after private known-result terminalization.
 * Evaluation and completion remain a private harness bridge; the worker does not grade or dispatch participant actions, and this is not full acceptance.
 */
async function runGenuineOwnerRunCase(input) {
  const sequenceMode = input.sequenceMode === true;
  const mode = input.mode ?? 'training';
  demand(mode === 'training' || mode === 'ranked', 'genuine_run_mode_invalid');
  const rankedMode = mode === 'ranked';
  demand(!input.primaryClientOnly || (input.bddProbes === true && rankedMode && input.automaticWorkerEvaluation === true),
    'primary_client_profile_requires_ranked_bdd_worker');
  const trainingSequenceMode = sequenceMode && mode === 'training';
  const taskIds = sequenceMode
    ? rankedMode ? input.taskIds : normalizeTrainingSequenceTaskIds(input.taskIds ?? ['S1', 'S2'])
    : [input.taskId ?? 'S1'];
  demand(Array.isArray(taskIds) && taskIds.length >= 1 &&
    (rankedMode ? sequenceMode && JSON.stringify(taskIds) === JSON.stringify(RANKED_TASK_IDS) && input.automaticWorkerEvaluation === true
      : taskIds.every((id) => SUPPORTED_TASKS.has(id)) &&
        (sequenceMode ? JSON.stringify(taskIds) === JSON.stringify(normalizeTrainingSequenceTaskIds(taskIds)) : taskIds.length === 1)),
  'unsupported_genuine_task_selection');
  const taskTransitions = trainingSequenceMode ? trainingSequenceTransitions(taskIds) : [];
  const taskId = taskIds[0];
  demand(rankedMode || !taskIds.some((id) => ['M1', 'M3', 'M4', 'H1', 'H2'].includes(id)) ||
    input.automaticWorkerEvaluation === true, 'open_task_capture_requires_server_worker');
  const output = {
    schemaVersion: rankedMode ? 'genuine-ranked-worker-owner-run-capture/v1'
      : sequenceMode ? 'genuine-training-sequence-owner-run-capture/v1' : 'genuine-' + taskId.toLowerCase() + '-owner-run-capture/v1',
    classification: input.automaticWorkerEvaluation
      ? (rankedMode ? 'local_full_ranked_run_with_server_worker_observation_evaluation_fence_completion_not_full_scenario_or_product_acceptance'
        : sequenceMode ? 'local_' + taskIds.length + '_task_training_sequence_with_server_worker_observation_evaluation_fence_completion_not_full_scenario_or_product_acceptance'
        : 'local_first_task_with_server_worker_observation_evaluation_fence_completion_not_full_scenario_or_product_acceptance')
      : sequenceMode
      ? 'local_' + taskIds.length + '_task_training_sequence_with_internal_grade_fence_completion_bridge_and_real_worker_advancement_not_full_scenario_or_product_acceptance'
      : 'local_first_task_capture_not_full_scenario_acceptance_or_product_release_acceptance',
    captureId: input.captureId ?? randomUUID(),
    fullScenarioAcceptance: false,
    bddProfile: !input.bddProbes ? 'not_selected'
      : input.primaryClientOnly ? 'primary_native_client_full12_negative_matrix_not_run' : 'full_launch_negative_probe_profile',
    productReleaseActivation: 'isolated_acceptance_database_only',
    externalModelUsed: false,
    internalTaskEvaluationRecorded: false,
    automaticWorkerEvaluationRequested: input.automaticWorkerEvaluation === true,
    automaticWorkerEvaluationVerified: false,
    taskGradePublished: false,
    taskId, taskIds, mode,
    setup: input.setup ?? null,
    stages: [],
    participantActions: [],
    identity: { ownerId: input.ownerId, adminProviderFixture: true },
  };
  let observerPool;
  let ownerDbClient;
  let actorCredential = '';
  const bddContext = input.bddProbes ? {} : null;
  let launchProbeInput, launchPreCapture, primaryMcpAcceptance;
  let runId = null;
  const environmentId = 'bef-env-a';
  const record = (name, status, facts = {}) => {
    output.stages.push({name, status, ...facts});
    if (input.bddProbes) process.stdout.write(JSON.stringify({event: 'local_bdd_stage',
      captureId: output.captureId, stage: name, status}) + '\n');
  };
  try {
    // This unauthenticated request must stop at bearer authentication. It creates
    // no admission identity and catches a proxy/Host mismatch before costly replay.
    const ingressProbe = await agentRequest({ publicOrigin: input.publicOrigin,
      path: '/api/agent/run-intents/' + randomUUID() + '/accept', method: 'POST', bearer: '',
      body: { operationId: randomUUID() } });
    const ingressError = ingressProbe.payload?.error?.code;
    output.agentIngressPreflight = { httpStatus: ingressProbe.status,
      errorCode: typeof ingressError === 'string' && /^[A-Za-z0-9_]{1,96}$/.test(ingressError) ? ingressError : null,
      classification: 'unauthenticated_proxy_probe_no_admission_or_actor_execution' };
    record('agent_proxy_ingress_authentication_boundary', ingressProbe.status === 401 ? 'verified' : 'blocked',
      output.agentIngressPreflight);
    demand(ingressProbe.status === 401 && ingressError === 'UNAUTHORIZED', 'agent_proxy_ingress_not_reaching_authentication');
    record('pinned_full_release_validation_and_isolated_activation', 'started');
    const release = await validateAndActivatePinnedRelease({ repositoryRoot: input.repoRoot,
      databaseUrl: input.databaseUrl, observerDatabaseUrl: input.observerDatabaseUrl, bddContext });
    if (bddContext) {
      output.bdd = {release: bddContext.releaseProbe};
      const debugDirectory = resolve(input.repoRoot, 'artifacts/runs/local-bdd-diagnostics', output.captureId);
      await mkdir(debugDirectory, {recursive: true});
      assertSecretFree(bddContext.releaseProbe);
      await writeFile(resolve(debugDirectory, 'release-probe.json'),
        JSON.stringify(bddContext.releaseProbe, null, 2) + '\n', {flag: 'wx'});
    }
    output.release = release;
    record('pinned_full_release_validation_and_isolated_activation', 'verified', {
      manifestHash: release.manifestHash, caseCount: 20, sourceInputCount: release.sourceInputCount,
      activatedInFreshDatabase: true,
    });

    observerPool = new Pool({ connectionString: input.observerDatabaseUrl, max: 2, application_name: 'genuine-s1-owner-observer' });
    const observerIdentity = await readonlyTransaction(observerPool, async (query) => pgRows(await query(
      'SELECT current_user AS role,current_database() AS database_name,current_setting(\'transaction_read_only\') AS readonly'))[0]);
    demand(observerIdentity?.role === 'oid_observer' && observerIdentity.readonly === 'on', 'owner_observer_role_invalid');
    output.database = { databaseName: observerIdentity.database_name, observerRole: observerIdentity.role, readOnly: true };

    record(input.bonusCodeFunding ? 'owner_bonus_code_issue_redeem_and_readonly_database' : 'owner_bonus_fixture_ui_and_readonly_database', 'started');
    const selectedTrainingQuoteUnits = trainingSequenceMode ? quoteTrainingSelectionUnits(release, taskIds) : null;
    const grantAmountUnits = rankedMode
      ? BigInt(release.rankedPriceUnits) * (bddContext && !input.primaryClientOnly ? 3n : 1n)
      : trainingSequenceMode ? trainingSequenceGrantAmountUnits(selectedTrainingQuoteUnits) : 100_000n;
    demand(grantAmountUnits > 0n, 'synthetic_run_budget_invalid');
    const grantAmount = formatUsdcUnits(grantAmountUnits);
    let grantId;
    if (input.bonusCodeFunding === true) {
      const { issueAndRedeemBonusCodeForWorker } = await import('./bonus-code-cases.mjs');
      const funding = await issueAndRedeemBonusCodeForWorker({
        adminPage: input.adminPage,
        ownerPage: input.ownerPage,
        adminCapture: input.adminCapture,
        ownerCapture: input.ownerCapture,
        ownerId: input.ownerId,
        observerDatabaseUrl: input.observerDatabaseUrl,
        label: 'Worker funding ' + input.captureId.slice(0, 8),
        amount: grantAmount,
        amountUnits: grantAmountUnits.toString(),
      });
      grantId = funding.grantId;
      output.bonusFunding = funding;
      output.bonusGrant = { grantId, operationId: funding.grantOperationId, amountUnits: funding.amountUnits,
        sourceKind: 'tester_bonus', codeId: funding.issue.codeId, database: funding.database };
      record('owner_bonus_code_issue_redeem_and_readonly_database', 'verified', {
        codeId: funding.issue.codeId, redemptionId: funding.redemption.redemptionId,
        grantId, amountUnits: grantAmountUnits.toString(), sourceKind: 'tester_bonus',
      });
    } else {
      const grantForm = input.adminPage.getByTestId('bonus-grant-form');
      await grantForm.waitFor({ state: 'visible', timeout: 15_000 });
      const grantReason = rankedMode ? 'Synthetic local full ranked worker acceptance fixture'
        : trainingSequenceMode ? 'Synthetic local ' + taskIds.join(' to ') + ' training-sequence acceptance fixture'
        : 'Synthetic local ' + taskId + ' first-task acceptance fixture';
      await grantForm.getByTestId('bonus-grant-owner-id').fill(input.ownerId);
      await grantForm.getByTestId('bonus-grant-amount').fill(grantAmount);
      await grantForm.getByTestId('bonus-grant-reason').fill(grantReason);
      await grantForm.getByTestId('bonus-grant-expiry').fill('');
      const grantPromise = input.adminPage.waitForResponse((response) => new URL(response.url()).pathname === '/api/admin/bonus-grants'
        && response.request().method() === 'POST', { timeout: 15_000 });
      await grantForm.getByTestId('bonus-grant-submit').click();
      const grantHttp = await grantPromise;
      let grantBody = {};
      try { grantBody = await grantHttp.json(); } catch { /* HTTP status is retained below. */ }
      grantId = grantBody?.grant?.id;
      const grantOperationId = grantBody?.operationId;
      demand(grantHttp.status() === 200 && UUID.test(grantId) && typeof grantOperationId === 'string', 'bonus_grant_ui_failed');
      const grantDb = await checkBonusGrant(observerPool, grantId, input.ownerId, grantOperationId);
      demand(grantDb.grant.length === 1 && BigInt(grantDb.grant[0].amount_units) === grantAmountUnits &&
        grantDb.ledgerEntries.some((entry) => BigInt(entry.available_delta_units) === grantAmountUnits), 'bonus_grant_database_binding_mismatch');
      output.bonusGrant = { grantId, operationId: grantOperationId, amountUnits: grantAmountUnits.toString(), browserHttpStatus: grantHttp.status(),
        database: grantDb };
      record('owner_bonus_fixture_ui_and_readonly_database', 'verified', { grantId, amountUnits: grantAmountUnits.toString() });
    }

    await input.ownerPage.goto('/agents', { waitUntil: 'domcontentloaded' });
    const captureTaskLabel = trainingSequenceMode ? taskIds.join('-') : taskId;
    const card = await createCard(input.ownerPage, 'Genuine ' + captureTaskLabel + ' local capture ' + input.captureId.slice(0, 8));
    const agentId = card.id;
    const agentCard = input.ownerPage.getByTestId('agent-card-' + agentId);
    await agentCard.waitFor({ state: 'visible', timeout: 12_000 });
    const modePermission = agentCard.getByTestId('agent-permission-' + mode);
    if (!await modePermission.isChecked()) await modePermission.check();
    const permissionPromise = input.ownerPage.waitForResponse((response) => new URL(response.url()).pathname === '/api/owner/agents/' + agentId + '/permissions'
      && response.request().method() === 'PUT', { timeout: 15_000 });
    const permissionButton = agentCard.getByTestId('agent-permissions-save');
    await permissionButton.click();
    const permissionHttp = await permissionPromise;
    const permissionBody = await permissionHttp.json().catch(() => ({}));
    demand(permissionHttp.status() === 200 && permissionBody?.agent?.permissions?.[mode] === true,
      'agent_mode_permission_ui_failed');
    const financialPolicy = await setS1FinancialPolicyThroughOwnerUi({ ownerPage: input.ownerPage, observerPool,
      ownerId: input.ownerId, agentId, limitUnits: rankedMode ? BigInt(release.rankedPriceUnits) : grantAmountUnits });
    record('owner_agent_financial_policy_ui_and_readonly_database', 'verified', {
      agentId, operationId: financialPolicy.operationId, revision: financialPolicy.revision,
      operationLimitUnits: financialPolicy.operationLimitUnits, utcDayLimitUnits: financialPolicy.utcDayLimitUnits,
      benchmarkLimit: financialPolicy.categoryLimits.benchmark, forumLimit: financialPolicy.categoryLimits.forum,
      allowCashShortfall: financialPolicy.allowCashShortfall,
    });
    const credential = await issueThroughUi(input.ownerPage, agentId, 'issue');
    actorCredential = credential.secret;
    credential.secret = '';
    const accountSnapshot = await requestOwnerSnapshot(observerPool, input.ownerId, agentId);
    demand(accountSnapshot.owner[0]?.admission_status === 'admitted' && accountSnapshot.agent[0]?.[mode] === true,
      'agent_permission_database_mismatch');
    output.agent = { agentId, createdOperationId: card.operationId, permissionRevision: permissionBody.agent.policyRevision,
      financialPolicy,
      credentialIssuedThroughOwnerUi: true, credentialOperationId: credential.operationId,
      credentialId: credential.credential.id, accessGrantId: credential.credential.grantId,
      profileSnapshotCandidate: { name: accountSnapshot.agent[0]?.name, declaredVersion: accountSnapshot.agent[0]?.declared_version,
        profileRevision: accountSnapshot.agent[0]?.revision }, database: accountSnapshot };
    record('owner_agent_card_permission_and_credential_ui', 'verified', { agentId, modePermission: mode });

    if (bddContext) {
      bddContext.extraAgents = [];
      output.bdd.fixtureAgents = [];
      for (const label of (input.primaryClientOnly ? [] : ['race', 'post-cancel'])) {
        const card = await createCard(input.ownerPage, 'BDD ' + label + ' ' + input.captureId.slice(0, 8));
        const panel = input.ownerPage.getByTestId('agent-card-' + card.id);
        const permission = panel.getByTestId('agent-permission-ranked');
        if (!await permission.isChecked()) await permission.check();
        const saved = input.ownerPage.waitForResponse(response =>
          new URL(response.url()).pathname === '/api/owner/agents/' + card.id + '/permissions'
          && response.request().method() === 'PUT');
        await panel.getByTestId('agent-permissions-save').click();
        demand((await saved).status() === 200, 'bdd_fixture_agent_permission_failed');
        await setS1FinancialPolicyThroughOwnerUi({ownerPage: input.ownerPage, observerPool,
          ownerId: input.ownerId, agentId: card.id, limitUnits: BigInt(release.rankedPriceUnits)});
        const issued = await issueThroughUi(input.ownerPage, card.id, 'issue');
        bddContext.extraAgents.push({agentId: card.id, bearer: issued.secret});
        issued.secret = '';
        output.bdd.fixtureAgents.push({agentId: card.id, label, createdOperationId: card.operationId,
          credentialOperationId: issued.operationId});
      }
    }
    await input.ownerPage.goto('/runs?agentId=' + encodeURIComponent(agentId), { waitUntil: 'domcontentloaded' });
    await input.ownerPage.getByTestId('run-intent-form').waitFor({ state: 'visible', timeout: 15_000 });
    await input.ownerPage.getByTestId('run-agent-select').selectOption(agentId);
    await input.ownerPage.getByTestId('run-mode-select').selectOption(mode);
    const catalog = await input.ownerPage.request.get('/api/owner/runs/catalog').then((response) => response.json());
    demand(catalog?.intentCreationReady === true && catalog?.activeRelease?.manifestHash === output.release.manifestHash &&
      catalog?.activeRelease?.completeRankedRelease === true && Array.isArray(catalog.activeRelease.openTaskIds) &&
      JSON.stringify(catalog.activeRelease.taskIds) === JSON.stringify(RANKED_TASK_IDS) &&
      JSON.stringify(catalog.activeRelease.openTaskIds) === JSON.stringify(OPEN_TASK_IDS) &&
      (rankedMode ? JSON.stringify(taskIds) === JSON.stringify(catalog.activeRelease.taskIds)
        : sequenceMode ? JSON.stringify(catalog.activeRelease.openTaskIds.slice(0, taskIds.length)) === JSON.stringify(taskIds)
        : taskIds.every((id) => catalog.activeRelease.openTaskIds.includes(id))),
    'owner_run_catalog_not_bound_to_full_release');
    if (!rankedMode) {
      for (const id of catalog.activeRelease.openTaskIds) {
        const checkbox = input.ownerPage.getByTestId('run-task-checkbox-' + id);
        if (taskIds.includes(id) && !await checkbox.isChecked()) await checkbox.check();
        if (!taskIds.includes(id) && await checkbox.isChecked()) await checkbox.uncheck();
      }
    }
    const currentTasks = input.ownerPage.locator('[data-testid^="run-task-checkbox-"]:checked');
    const checkedCount = await currentTasks.count();
    demand(rankedMode ? checkedCount === 0 &&
      (await input.ownerPage.getByTestId('run-ranked-task-selection').innerText()).includes(RANKED_TASK_IDS.join(', '))
      : checkedCount === taskIds.length, 'run_intent_task_selection_mismatch');
    const cashCeiling = input.ownerPage.getByTestId('run-cash-ceiling');
    await cashCeiling.fill('0');
    const quoteText = (await input.ownerPage.getByTestId('run-selected-quote').innerText()).trim();
    const selectedTasksForQuote = rankedMode ? output.release.rankedTasks : output.release.trainingTasks;
    const selectedWeight = selectedTasksForQuote.filter((entry) => taskIds.includes(entry.taskId))
      .reduce((sum, entry) => sum + entry.taskWeight, 0);
    const totalWeight = selectedTasksForQuote.reduce((sum, entry) => sum + entry.taskWeight, 0);
    const fullPrice = BigInt(rankedMode ? output.release.rankedPriceUnits : output.release.trainingPriceUnits);
    demand(output.release.precision === 6 &&
      (rankedMode ? output.release.rankedTasks.length === RANKED_TASK_IDS.length &&
        output.release.rankedTasks.every((entry, index) => entry.taskId === RANKED_TASK_IDS[index]) && totalWeight === 26
        : output.release.trainingTasks.length === catalog.activeRelease.openTaskIds.length &&
          output.release.trainingTasks.every((entry, index) => entry.taskId === catalog.activeRelease.openTaskIds[index]) && totalWeight === 15) &&
      selectedWeight > 0, 'validated_release_pricing_projection_invalid');
    const quoteUnits = rankedMode ? fullPrice : ((fullPrice * BigInt(selectedWeight)) + BigInt(totalWeight) - 1n) / BigInt(totalWeight);
    demand(!trainingSequenceMode || (quoteUnits === selectedTrainingQuoteUnits && grantAmountUnits >= quoteUnits),
      'training_sequence_release_quote_or_funding_mismatch');
    const quoteMatch = /Server quote for this selection:\s*([0-9]+(?:\.[0-9]+)?)\s+USDC/i.exec(quoteText);
    demand(quoteMatch && exactUsdcUnits(quoteMatch[1]) === quoteUnits, 'owner_quote_does_not_match_validated_release_weights');
    const intentPromise = input.ownerPage.waitForResponse((response) => new URL(response.url()).pathname === '/api/owner/runs/intents'
      && response.request().method() === 'POST', { timeout: 20_000 });
    await input.ownerPage.getByTestId('run-intent-create').click();
    const intentHttp = await intentPromise;
    // Retained only in this function's RAM for optional same-operation restore probes.
    const intentCreatePayload = intentHttp.request().postDataJSON();
    let intentBody = {};
    try { intentBody = await intentHttp.json(); } catch { /* Reconcile from independent PostgreSQL if the body is absent. */ }
    const intentId = intentBody?.intent?.id;
    demand([200, 201].includes(intentHttp.status()) && UUID.test(intentId), 'owner_run_intent_ui_failed');
    const intentSnapshot = await readonlyTransaction(observerPool, async (query) => {
      const result = await query(`SELECT id::text,owner_id::text,agent_id::text,operation_id,mode,task_ids,release_identity,manifest_hash,benchmark_hash,policy_hash,benchmark_version,expires_at::text,
          quote_price_units::text,cash_ceiling_units::text,status,run_id::text,
          successor_preparation_policy_version,successor_preparation_timeout_seconds
        FROM oid_run_launch_intent WHERE id=$1`, [intentId]);
      return pgRows(result);
    });
    demand(intentSnapshot.length === 1 && intentSnapshot[0].owner_id === input.ownerId && intentSnapshot[0].agent_id === agentId &&
      intentSnapshot[0].status === 'pending' && intentSnapshot[0].mode === mode &&
      JSON.stringify(intentSnapshot[0].task_ids) === JSON.stringify(taskIds) && intentSnapshot[0].manifest_hash === output.release.manifestHash &&
      BigInt(intentSnapshot[0].quote_price_units) === quoteUnits && BigInt(intentSnapshot[0].cash_ceiling_units) === 0n &&
      (trainingSequenceMode ? intentSnapshot[0].successor_preparation_policy_version === 'local-bef-successor-preparation/v1' &&
        Number(intentSnapshot[0].successor_preparation_timeout_seconds) === 180
        : true),
    'owner_intent_database_binding_mismatch');
    demand(intentCreatePayload && intentCreatePayload.operationId === intentSnapshot[0].operation_id &&
      intentCreatePayload.agentId === agentId && intentCreatePayload.mode === mode &&
      JSON.stringify(intentCreatePayload.taskIds) === JSON.stringify(taskIds),
    'owner_intent_request_body_database_binding_mismatch');
    output.launchIntent = { intentId, operationId: intentSnapshot[0].operation_id, browserHttpStatus: intentHttp.status(),
      selectedTasks: taskIds, mode, cashCeilingUnits: '0', quoteDisplay: quoteText, quotePriceUnits: quoteUnits.toString(),
      successorPreparationPolicyVersion: intentSnapshot[0].successor_preparation_policy_version,
      successorPreparationTimeoutSeconds: intentSnapshot[0].successor_preparation_timeout_seconds,
      database: intentSnapshot[0] };
    record('owner_run_intent_ui_and_readonly_database', 'verified', { intentId, runUiAction: 'Create private intent' });

    const acceptOperationId = randomUUID();
    if (bddContext) {
      const pendingText = await input.ownerPage.getByTestId('run-intent-' + intentId).innerText();
      output.bdd.browser = {pendingBeforeAcceptance: {intentId,
        statusText: await input.ownerPage.getByTestId('run-intent-status-' + intentId).innerText(),
        admissionCopy: pendingText.includes('No run admitted and no funds or queue slot reserved')
          ? 'No run admitted and no funds or queue slot reserved' : null,
        linkedRunId: null, url: input.ownerPage.url(), database: output.launchIntent.database}};
      launchProbeInput = {publicOrigin: input.publicOrigin, ownerPage: input.ownerPage,
        ownerId: input.ownerId, agentId, agentBearer: actorCredential,
        observerDatabaseUrl: input.observerDatabaseUrl, intent: output.launchIntent,
        liveValidatedRelease: output.release, ownerPendingLimit: bddContext.ownerPendingLimit,
        activateNextRelease: bddContext.activateNextRelease, restoreRelease: bddContext.restoreRelease,
        restartApi: input.restartApi, foreignOwnerPage: input.foreignOwnerPage,
        raceProbeAgent: bddContext.extraAgents[0], foreignAgent: bddContext.extraAgents[0],
        postCancelProbeAgent: bddContext.extraAgents[1]};
      record('bdd_launch_pre_accept_negatives', 'started');
      launchPreCapture = input.primaryClientOnly
        ? await runBrlLaunchAdmissionPrimaryOnlyCase(launchProbeInput)
        : await runBrlLaunchAdmissionPreAcceptCases(launchProbeInput);
      output.bdd.launch = launchPreCapture;
      output.bdd.browser.pendingBeforeAcceptance.databaseSnapshot = launchPreCapture['BRL-SC-023'].cases.preAcceptance.after;
      record('codex_native_mcp_primary_acceptance', 'started');
      let nativeClient;
      try {
        nativeClient = await runCodexNativeOwnerAcceptance({publicOrigin: input.publicOrigin,
          agentBearer: actorCredential, agentId, intentId, acceptOperationId, ownerPage: input.ownerPage, repoRoot: input.repoRoot});
      } finally {
        const admitted = await readonlyTransaction(observerPool, async query => pgRows(await query(
          'SELECT run_id::text FROM oid_run_launch_intent WHERE id=$1 AND owner_id=$2 AND agent_id=$3 AND status=\'accepted\'',
          [intentId, input.ownerId, agentId])));
        if (UUID.test(admitted[0]?.run_id ?? '')) runId = admitted[0].run_id;
      }
      output.bdd.client = nativeClient;
      const result = nativeClient.mcp?.toolResult;
      demand(nativeClient.outcome === 'accepted_result_observed' && UUID.test(result?.runId ?? ''),
        'codex_native_primary_acceptance_not_observed');
      runId = result.runId;
      primaryMcpAcceptance = await captureBrlPrimaryMcpAcceptance(launchProbeInput, launchPreCapture,
        {toolName: 'runs.accept_launch_intent', clientBoundary: 'codex_native_mcp_agent_case',
          operationId: acceptOperationId, isError: false, status: 200,
          body: {run: {id: result.runId, status: result.status}}},
{externalModelCalls: nativeClient.model.externalModelCalls, llmBenchmarkInvocation: nativeClient.model.llmBenchmarkInvocation});
      await input.ownerPage.getByTestId('run-intents-refresh').click();
      await input.ownerPage.getByTestId('owner-run-' + runId).waitFor({state: 'visible', timeout: 15000});
      const acceptedText = await input.ownerPage.getByTestId('run-intent-' + intentId).innerText();
      output.bdd.browser.acceptedAfterMcp = {intentId, runId,
        statusText: await input.ownerPage.getByTestId('run-intent-status-' + intentId).innerText(),
        linkedRunId: acceptedText.includes(runId) ? runId : null, url: input.ownerPage.url(),
        databaseSnapshot: primaryMcpAcceptance.cases.acceptance.after};
      await input.ownerPage.reload({waitUntil: 'domcontentloaded'});
      await input.ownerPage.getByTestId('owner-run-' + runId).waitFor({state: 'visible', timeout: 15000});
      output.bdd.browser.afterReload = {intentId, runId,
        statusText: await input.ownerPage.getByTestId('run-intent-status-' + intentId).innerText(),
        linkedRunId: (await input.ownerPage.getByTestId('run-intent-' + intentId).innerText()).includes(runId) ? runId : null,
        url: input.ownerPage.url()};
      const reloadObserved = await captureBrlPrimaryMcpAcceptance(launchProbeInput, launchPreCapture,
        {toolName: 'runs.accept_launch_intent', clientBoundary: 'codex_native_mcp_agent_case',
          operationId: acceptOperationId, isError: false, status: 200,
          body: {run: {id: result.runId, status: result.status}}},
        {externalModelCalls: nativeClient.model.externalModelCalls, llmBenchmarkInvocation: nativeClient.model.llmBenchmarkInvocation});
      output.bdd.browser.afterReload.databaseSnapshot = reloadObserved.cases.acceptance.after;
      record('codex_native_mcp_primary_acceptance', 'verified', {clientVersion: nativeClient.client.version, runId});
    }
    record('agent_accept_http_and_readonly_database', 'started', { operationId: acceptOperationId });
    let accept = { status: null, payload: {} };
    let acceptTransportUnknown = false;
    try {
      accept = await agentRequest({ publicOrigin: input.publicOrigin,
        path: '/api/agent/run-intents/' + intentId + '/accept', method: 'POST', bearer: actorCredential,
        body: { operationId: acceptOperationId } });
    } catch { acceptTransportUnknown = true; }
    const acceptErrorCode = accept.payload?.error?.code;
    output.acceptanceAttempt = { operationId: acceptOperationId, intentId, httpStatus: accept.status,
      transportUnknown: acceptTransportUnknown,
      errorCode: typeof acceptErrorCode === 'string' && /^[A-Za-z0-9_]{1,96}$/.test(acceptErrorCode) ? acceptErrorCode : null };
    const createIntentOperationId = intentSnapshot[0].operation_id;
    let acceptedRunId = !acceptTransportUnknown && [200, 201].includes(accept.status)
      ? accept.payload?.run?.id ?? accept.payload?.run?.runId ?? null : null;
    let reconciledAcceptanceFromDatabase = false;
    if (!UUID.test(acceptedRunId ?? '')) {
      const acceptedIntent = await readonlyTransaction(observerPool, async (query) => pgRows(await query(
        `SELECT id::text,owner_id::text,agent_id::text,operation_id,status,run_id::text,manifest_hash
          FROM oid_run_launch_intent WHERE id=$1`, [intentId])));
      if (acceptedIntent.length === 1 && acceptedIntent[0].owner_id === input.ownerId && acceptedIntent[0].agent_id === agentId &&
          acceptedIntent[0].operation_id === createIntentOperationId && acceptedIntent[0].manifest_hash === output.release.manifestHash &&
          acceptedIntent[0].status === 'accepted' && UUID.test(acceptedIntent[0].run_id ?? '')) {
        acceptedRunId = acceptedIntent[0].run_id;
        reconciledAcceptanceFromDatabase = true;
      }
    }
    demand(UUID.test(acceptedRunId ?? '') &&
      (([200, 201].includes(accept.status) && !acceptTransportUnknown) || reconciledAcceptanceFromDatabase),
    'agent_accept_http_or_response_unknown');
    runId = acceptedRunId;
    const acceptedSnapshot = await readRunSnapshot(observerPool, { runId });
    demand(acceptedSnapshot.run.length === 1 && acceptedSnapshot.run[0].intent_status === 'accepted' &&
      acceptedSnapshot.run[0].intent_operation_id === createIntentOperationId && acceptedSnapshot.run[0].manifest_hash === output.release.manifestHash,
    'agent_accept_database_binding_mismatch');
    demand(acceptedSnapshot.run[0].owner_id === input.ownerId && acceptedSnapshot.run[0].agent_id === agentId &&
      acceptedSnapshot.run[0].intentId === intentId && acceptedSnapshot.run[0].mode === mode &&
      Array.isArray(acceptedSnapshot.run[0].task_ids) && JSON.stringify(acceptedSnapshot.run[0].task_ids) === JSON.stringify(taskIds) &&
      BigInt(acceptedSnapshot.run[0].quote_price_units) === quoteUnits &&
      (trainingSequenceMode ? acceptedSnapshot.run[0].successor_preparation_policy_version === 'local-bef-successor-preparation/v1' &&
        Number(acceptedSnapshot.run[0].successor_preparation_timeout_seconds) === 180 &&
        acceptedSnapshot.run[0].intent_successor_preparation_policy_version === 'local-bef-successor-preparation/v1' &&
        Number(acceptedSnapshot.run[0].intent_successor_preparation_timeout_seconds) === 180
        : true) &&
      acceptedEventMatches(acceptedSnapshot, { runId, intentId, taskIds, mode,
        ownerId: input.ownerId, agentId, manifestHash: output.release.manifestHash, acceptOperationId }),
    'agent_accept_event_or_owner_binding_mismatch');
    output.runInitial = { overallDeadline: acceptedSnapshot.run[0].overall_deadline,
      successorPreparationPolicyVersion: acceptedSnapshot.run[0].successor_preparation_policy_version,
      successorPreparationTimeoutSeconds: acceptedSnapshot.run[0].successor_preparation_timeout_seconds };
    const acceptanceEvent = acceptedSnapshot.acceptanceEvents[0];
    output.run = { runId, createIntentOperationId, acceptOperationId, acceptanceHttpStatus: accept.status,
      acceptanceReconciledFromDatabase: reconciledAcceptanceFromDatabase, acceptTransportUnknown,
      acceptanceEvent: { eventId: acceptanceEvent.eventId, sequence: acceptanceEvent.sequence,
        payloadHash: acceptanceEvent.payloadHash, operationId: acceptanceEvent.payload.operationId,
        intentId: acceptanceEvent.intentId, runId: acceptanceEvent.runId, ownerId: acceptanceEvent.ownerId,
        agentId: acceptanceEvent.agentId }, database: acceptedSnapshot.run[0] };
    record('agent_accept_http_and_readonly_database', 'verified', { runId, operationId: acceptOperationId });

    const { TaskSealedEvidenceSource } = await import('../../owner-identity/dist/task-sealed-evidence-source.js');
    const { createDatabase } = await import('../../owner-identity/dist/db.js');
    const { loadConfig } = await import('../../owner-identity/dist/config.js');
    const { createPostgresTaskReleaseQuerySource } = await import('../../owner-identity/dist/task-store.js');
    const created = createDatabase(loadConfig({ ...process.env, OID_DATABASE_URL: input.databaseUrl }));
    ownerDbClient = created.client;
    const taskReleaseSource = createPostgresTaskReleaseQuerySource(created.db);
    const evidenceSource = new TaskSealedEvidenceSource({ taskReleaseSource, evidenceRoot: input.repoRoot });
    for (let taskIndex = 0; taskIndex < taskIds.length; taskIndex += 1) {
      const currentTaskId = taskIds[taskIndex];
      const trainingTransition = taskTransitions.find((transition) => transition.toTaskIndex === taskIndex) ?? null;
      let successorActivation = null;
      const captured = await captureAndEvaluateTrainingTask({ input, output, record, observerPool, bearer: actorCredential,
        runId, taskIndex, taskId: currentTaskId, intentId, createIntentOperationId, acceptOperationId,
        selectedTaskIds: taskIds, agentId, created, taskReleaseSource, evidenceSource, sequenceMode, mode, intentCreatePayload,
        beforeAction: rankedMode && taskIndex > 0 ? async (task) => {
          successorActivation = await verifyRankedSuccessorActivation({ input, record, observerPool, runId, task,
            release: output.release, predecessorTerminalization: output.predecessorTerminalizations?.[taskIndex - 1],
            priorTaskResult: output.taskEvaluations?.find((entry) => entry.taskIndex === taskIndex - 1),
            dispatchIdentity: output.dispatchIdentity });
          output.rankedSuccessorActivations ??= [];
          output.rankedSuccessorActivations.push(successorActivation);
        } : trainingTransition ? async (task) => {
          successorActivation = await verifyTrainingSuccessorActivation({ input, record, observerPool, runId, task,
            taskIds, transition: trainingTransition, oldOverallDeadline: output.runInitial.overallDeadline,
            release: output.release, priorTaskResult: output.taskEvaluations[trainingTransition.fromTaskIndex].result,
            predecessorTerminalization: output.predecessorTerminalizations?.[trainingTransition.fromTaskIndex],
            dispatchIdentity: output.dispatchIdentity });
          output.trainingSuccessorActivations ??= [];
          output.trainingSuccessorActivations.push(successorActivation);
          output.successorActivation = successorActivation;
        } : null });
      if (rankedMode && taskIndex < taskIds.length - 1) {
        demand(captured.terminalization?.observedFromWorker === true &&
          output.predecessorTerminalizations?.[taskIndex]?.status === 'verified',
          'ranked_successor_worker_waited_before_known_predecessor_terminalization');
        output.rankedWorkerAdvancements ??= [];
        output.rankedWorkerAdvancements.push({ status: 'awaited_from_real_server_worker',
          terminalizedTaskIndex: taskIndex, nextTaskIndex: taskIndex + 1,
          trigger: 'known_terminalization_after_exact_generation_fence', manualPreparationOrActivation: false });
      }
      if (trainingSequenceMode && taskIndex < taskIds.length - 1) {
        demand((input.automaticWorkerEvaluation ? captured.terminalization?.observedFromWorker === true
          : captured.terminalization?.replayed === false) && output.predecessorTerminalizations?.[taskIndex]?.status === 'verified',
          'successor_worker_waited_before_known_predecessor_terminalization');
        const advancement = { status: 'awaited_from_real_server_worker', predecessorTaskIndex: taskIndex,
          predecessorTaskId: currentTaskId, nextTaskIndex: taskIndex + 1, nextTaskId: taskIds[taskIndex + 1],
          trigger: 'known_terminalization_after_exact_generation_fence', manualPreparationOrActivation: false };
        output.workerAdvancements ??= [];
        output.workerAdvancements.push(advancement);
        if (taskIndex === 0) output.workerAdvancement = advancement;
      }
      if (trainingSequenceMode && taskIndex > 0) demand(successorActivation?.taskIndex === taskIndex &&
        successorActivation.taskId === currentTaskId, 'successor_activation_not_independently_verified');
    }
    if (trainingSequenceMode) demand(trainingSuccessorActivationChainMatches(taskIds, output.trainingSuccessorActivations),
    'training_successor_transition_chain_incomplete');
    if (rankedMode) demand(output.rankedSuccessorActivations?.length === RANKED_TASK_IDS.length - 1 &&
      output.rankedSuccessorActivations.every((entry, index) => entry.taskIndex === index + 1 &&
        entry.predecessorTaskIndex === index && entry.taskId === RANKED_TASK_IDS[index + 1] &&
        entry.predecessorTaskId === RANKED_TASK_IDS[index]) &&
      output.rankedWorkerAdvancements?.length === RANKED_TASK_IDS.length - 1,
    'ranked_successor_transition_chain_incomplete');
    if (bddContext && !input.primaryClientOnly && rankedMode && output.runCompletion?.status === 'verified') {
      record('bdd_ranked_replay_forgery_restart', 'started');
      output.bdd.ranked = await runRankedBddCases({runId, ownerId: input.ownerId, agentId,
        publicOrigin: input.publicOrigin, agentBearer: actorCredential, ownerPage: input.ownerPage,
        observerPool, db: created.db, taskReleaseSource, evidenceSource, evidenceRoot: input.repoRoot,
        restartApi: input.restartApi});
      record('bdd_ranked_replay_forgery_restart', output.bdd.ranked.status);
      record('bdd_launch_post_completion_retries_and_expiry', 'started');
      output.bdd.launch = await runBrlLaunchAdmissionPostCompletionCases(launchProbeInput,
        {preCapture: launchPreCapture, primaryAcceptance: primaryMcpAcceptance,
          httpReplay: {method: 'POST', status: accept.status, body: accept.payload,
            request: {operationId: acceptOperationId}}});
      record('bdd_launch_post_completion_retries_and_expiry', 'observed');
    }
    if (bddContext && input.primaryClientOnly && primaryMcpAcceptance) {
      output.bdd.launch['BRL-SC-023'] = {...primaryMcpAcceptance, status: 'blocked',
        missingFixtures: ['post_acceptance_transport_version_expiry_negative_matrix_not_selected']};
      demand(output.runCompletion?.status === 'verified', 'codex_profile_run_completion_required');
      record('codex_local_profile_compatibility_and_revocation', 'started');
      output.bdd.codexProfile = await runCodexOwnerProfileCases({ownerPage: input.ownerPage,
        observerPool, publicOrigin: input.publicOrigin, agentBearer: actorCredential, agentId,
        runId, intentId, acceptOperationId, repoRoot: input.repoRoot, nativeClient: output.bdd.client});
      demand(output.bdd.codexProfile.status === 'verified', 'codex_local_profile_acceptance_incomplete');
      record('codex_local_profile_compatibility_and_revocation', 'verified');
      record('primary_native_client_profile_boundary', 'verified', {negativeMatrixAcceptance: false});
    }
    if (output.trainingRunCompletion?.status === 'verified' && typeof input.onGenuineRunCompleted === 'function') {
      // The credential is deliberately passed only through this in-memory callback.
      // It is never copied into output, an artifact, or a log.
      await input.onGenuineRunCompleted({ runId, ownerId: input.ownerId, agentId: output.agent?.agentId,
        mode, taskIds: [...taskIds], agentBearer: actorCredential, intentId,
        createIntentOperationId, acceptOperationId,
        intentCreatePayload: structuredClone(intentCreatePayload),
        releaseIdentity: output.release.releaseIdentity, manifestHash: output.release.manifestHash });
      output.postCompletionCallbackInvoked = true;
    }
  } catch (error) {
    if (safeErrorCode(error) === 'beta_platform_recovery_terminal_captured' &&
        output.platformRecovery?.terminalCapturedWithoutGrade === true && output.platformRecovery?.exhaustion?.verified === true) {
      output.status = 'captured_platform_recovery_exhausted_without_grade';
      record('platform_recovery_exhaustion_terminal', 'observed', {
        runId, actionId: output.platformRecovery.reconciledOriginalAction?.actionId,
        runStatus: output.platformRecovery.exhaustion.runStatus,
        terminalReason: output.platformRecovery.exhaustion.terminalReason,
        gradeRecorded: false,
      });
    } else {
      output.status = 'blocked';
      output.blocker = { stage: output.stages.at(-1)?.name ?? 'genuine_s1_setup', reasonCode: safeErrorCode(error) };
      if (error?.safeDiagnostic && typeof error.safeDiagnostic === 'object') output.safeDiagnostic = error.safeDiagnostic;
      record(output.blocker.stage, 'blocked', { reasonCode: output.blocker.reasonCode });
    }
  } finally {
    actorCredential = '';
    if (bddContext?.extraAgents) for (const agent of bddContext.extraAgents) agent.bearer = '';
    if (runId && observerPool && output.runCompletion?.status !== 'verified' &&
        output.platformRecovery?.terminalCapturedWithoutGrade !== true) {
      await requestOwnerCancellation({ ownerPage: input.ownerPage, runId, observerPool, output });
    }
    if (ownerDbClient) await ownerDbClient.end({ timeout: 5 }).catch(() => undefined);
    if (observerPool) await observerPool.end().catch(() => undefined);
  }
  output.runCompletion ??= output.trainingRunCompletion;
  if (!output.status) output.status = output.runCompletion?.status === 'verified'
    ? (rankedMode ? 'captured_full_ranked_run_completed_by_server_worker_with_internal_handoff'
      : input.automaticWorkerEvaluation ? (sequenceMode ? 'captured_s1_s2_training_sequence_completed_by_server_worker'
      : 'captured_' + taskId.toLowerCase() + '_training_run_completed_by_server_worker')
      : sequenceMode ? 'captured_s1_s2_training_sequence_completed_by_internal_bridge_and_real_worker_advancement'
      : 'captured_' + taskId.toLowerCase() + '_training_run_completed_by_internal_bridge')
    : (rankedMode ? 'captured_partial_ranked_run' : sequenceMode ? 'captured_partial_training_sequence' : 'captured_first_task_only');
  output.runId = runId;
  output.fullScenarioAcceptance = false;
  output.productReleaseActivated = false;
  output.taskGradePublished = false;
  assertSecretFree(output, 'genuine-s1-owner-run');
  return output;
}

export async function runGenuineS1OwnerCase(input) {
  return runGenuineOwnerRunCase({ ...input, sequenceMode: false });
}

export async function runGenuineTrainingSequenceOwnerCase(input) {
  return runGenuineOwnerRunCase({ ...input, sequenceMode: true, taskIds: input.taskIds ?? ['S1', 'S2'] });
}

export async function runGenuineRankedOwnerCase(input) {
  return runGenuineOwnerRunCase({ ...input, mode: 'ranked', sequenceMode: true, taskIds: RANKED_TASK_IDS });
}
export async function writeGenuineS1Capture({ repositoryRoot, capture, provenance }) {
  const captureId = capture.captureId;
  demand(UUID.test(captureId), 'capture_id_invalid');
  const directory = resolve(repositoryRoot, evidenceRootForTask(capture.taskId ?? 'S1'), captureId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const payload = { ...capture, provenance, fullScenarioAcceptance: false,
    claims: { productReleaseActivation: false, internalTaskEvaluationRecorded: capture.internalTaskEvaluationRecorded === true,
      taskGradePublished: false, ownerAcceptance: false, bddLifecycleChanged: false,
      automaticWorkerEvaluation: capture.automaticWorkerEvaluationVerified === true } };
  assertSecretFree(payload, 'genuine-s1-capture');
  const bytes = Buffer.from(JSON.stringify(payload, null, 2) + '\n');
  await writeFile(resolve(directory, 'capture.json'), bytes, { flag: 'wx', mode: 0o600 });
  const manifest = { schemaVersion: 'genuine-' + (capture.taskId ?? 'S1').toLowerCase() + '-owner-run-artifact/v1', captureId,
    classification: payload.classification, status: capture.status, fullScenarioAcceptance: false,
    artifacts: [{ path: 'capture.json', sha256: sha256(bytes), boundary: 'local first-task harness and independent observers' }] };
  await writeFile(resolve(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { directory: relative(repositoryRoot, directory).split(sep).join('/'), manifest, sha256: sha256(bytes) };
}

export async function writeGenuineS1StartupBlock({ repositoryRoot, captureId, phase, reasonCode, taskId = 'S1', automaticWorkerEvaluation = false }) {
  return writeGenuineS1Capture({ repositoryRoot, capture: {
    schemaVersion: 'genuine-' + taskId.toLowerCase() + '-owner-run-capture/v1', captureId, taskId, status: 'blocked',
    classification: automaticWorkerEvaluation
      ? 'local_first_task_server_worker_lifecycle_requested_not_full_scenario_or_product_acceptance'
      : 'local_first_task_capture_not_full_scenario_acceptance_or_product_release_acceptance',
    automaticWorkerEvaluationRequested: automaticWorkerEvaluation, automaticWorkerEvaluationVerified: false,
    fullScenarioAcceptance: false, productReleaseActivation: false, internalTaskEvaluationRecorded: false, taskGradePublished: false,
    stages: [{ name: phase, status: 'blocked', reasonCode }], participantActions: [],
  }, provenance: { startupFailure: true, sourceStableDuringRun: false } });
}

export async function writeGenuineTrainingSequenceCapture({ repositoryRoot, capture, provenance }) {
  const taskIds = normalizeTrainingSequenceTaskIds(capture.taskIds);
  demand(UUID.test(capture.captureId) && capture.schemaVersion === 'genuine-training-sequence-owner-run-capture/v1' &&
    JSON.stringify(capture.taskIds) === JSON.stringify(taskIds), 'training_sequence_capture_identity_invalid');
  const directory = resolve(repositoryRoot, SEQUENCE_EVIDENCE_ROOT, capture.captureId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const payload = { ...capture, provenance, fullScenarioAcceptance: false,
    claims: { productReleaseActivation: false, internalTaskEvaluationRecorded: capture.internalTaskEvaluationRecorded === true,
      taskGradePublished: false, ownerAcceptance: false, bddLifecycleChanged: false,
      realWorkerSuccessorAdvancement: capture.trainingSuccessorActivations?.length === capture.taskIds.length - 1,
      automaticWorkerEvaluation: capture.automaticWorkerEvaluationVerified === true } };
  assertSecretFree(payload, 'genuine-training-sequence-capture');
  const bytes = Buffer.from(JSON.stringify(payload, null, 2) + '\n');
  await writeFile(resolve(directory, 'capture.json'), bytes, { flag: 'wx', mode: 0o600 });
  const manifest = { schemaVersion: 'genuine-training-sequence-owner-run-artifact/v1', captureId: capture.captureId,
    classification: payload.classification, status: capture.status, fullScenarioAcceptance: false,
    artifacts: [{ path: 'capture.json', sha256: sha256(bytes),
      boundary: capture.automaticWorkerEvaluationRequested
        ? 'local ' + capture.taskIds.length + '-task training sequence with server worker lifecycle and readonly harness verification; not full scenario acceptance'
        : 'local ' + capture.taskIds.length + '-task training sequence with internal grading and completion bridge plus real worker advancement; not full scenario acceptance' }] };
  await writeFile(resolve(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { directory: relative(repositoryRoot, directory).split(sep).join('/'), manifest, sha256: sha256(bytes) };
}

export async function writeGenuineTrainingSequenceStartupBlock({ repositoryRoot, captureId, phase, reasonCode,
  automaticWorkerEvaluation = false, taskIds = ['S1', 'S2'] }) {
  const selectedTaskIds = normalizeTrainingSequenceTaskIds(taskIds);
  return writeGenuineTrainingSequenceCapture({ repositoryRoot, capture: {
    schemaVersion: 'genuine-training-sequence-owner-run-capture/v1', captureId, taskIds: selectedTaskIds, mode: 'training',
    status: 'blocked', classification: automaticWorkerEvaluation
      ? 'local_training_sequence_server_worker_lifecycle_requested_not_full_scenario_or_product_acceptance'
      : 'local_training_sequence_with_internal_grade_fence_completion_bridge_and_real_worker_advancement_not_full_scenario_or_product_acceptance',
    automaticWorkerEvaluationRequested: automaticWorkerEvaluation, automaticWorkerEvaluationVerified: false,
    fullScenarioAcceptance: false, productReleaseActivation: false, internalTaskEvaluationRecorded: false, taskGradePublished: false,
    stages: [{ name: phase, status: 'blocked', reasonCode }], participantActions: [],
  }, provenance: { startupFailure: true, sourceStableDuringRun: false } });
}

export async function writeGenuineRankedCapture({ repositoryRoot, capture, provenance }) {
  demand(UUID.test(capture.captureId) && capture.schemaVersion === 'genuine-ranked-worker-owner-run-capture/v1' &&
    capture.mode === 'ranked' && JSON.stringify(capture.taskIds) === JSON.stringify(RANKED_TASK_IDS),
  'ranked_capture_identity_invalid');
  const directory = resolve(repositoryRoot, RANKED_EVIDENCE_ROOT, capture.captureId);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const payload = { ...capture, provenance, fullScenarioAcceptance: false,
    claims: { productReleaseActivation: false, internalTaskEvaluationRecorded: capture.internalTaskEvaluationRecorded === true,
      internalRankedHandoffVerified: capture.rankedHandoff?.status === 'verified', publicLeaderboardPublication: false,
      taskGradePublished: false, ownerAcceptance: false, bddLifecycleChanged: false,
      automaticWorkerEvaluation: capture.automaticWorkerEvaluationVerified === true } };
  assertSecretFree(payload, 'genuine-ranked-owner-run-capture');
  const bytes = Buffer.from(JSON.stringify(payload, null, 2) + '\n');
  await writeFile(resolve(directory, 'capture.json'), bytes, { flag: 'wx', mode: 0o600 });
  const manifest = { schemaVersion: 'genuine-ranked-worker-owner-run-artifact/v1', captureId: capture.captureId,
    classification: payload.classification, status: capture.status, fullScenarioAcceptance: false,
    artifacts: [{ path: 'capture.json', sha256: sha256(bytes),
      boundary: 'local full ranked server-worker run and internal handoff proof; not public leaderboard or full scenario acceptance' }] };
  await writeFile(resolve(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { directory: relative(repositoryRoot, directory).split(sep).join('/'), manifest, sha256: sha256(bytes) };
}

export async function writeGenuineRankedStartupBlock({ repositoryRoot, captureId, phase, reasonCode }) {
  return writeGenuineRankedCapture({ repositoryRoot, capture: {
    schemaVersion: 'genuine-ranked-worker-owner-run-capture/v1', captureId, mode: 'ranked', taskId: RANKED_TASK_IDS[0],
    taskIds: RANKED_TASK_IDS, status: 'blocked',
    classification: 'local_full_ranked_server_worker_run_requested_not_public_leaderboard_or_full_scenario_acceptance',
    automaticWorkerEvaluationRequested: true, automaticWorkerEvaluationVerified: false,
    fullScenarioAcceptance: false, productReleaseActivation: false, internalTaskEvaluationRecorded: false,
    taskGradePublished: false, stages: [{ name: phase, status: 'blocked', reasonCode }], participantActions: [],
  }, provenance: { startupFailure: true, sourceStableDuringRun: false } });
}
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function normalizedLoopbackHost(hostname) {
  return String(hostname).replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
}

export function validateGenuineRecoveryProxySettings({ apiBaseUrl = undefined, observerDatabase = undefined,
  automaticWorkerEvaluation = false } = {}) {
  if (apiBaseUrl === undefined && observerDatabase === undefined) return null;
  demand(automaticWorkerEvaluation === true, 'platform_recovery_proxy_requires_server_worker');
  let participantApiOrigin;
  if (apiBaseUrl !== undefined) {
    let parsed;
    try { parsed = new URL(apiBaseUrl); } catch { throw fail('platform_recovery_proxy_api_origin_invalid'); }
    demand(parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(normalizedLoopbackHost(parsed.hostname)) &&
      parsed.username === '' && parsed.password === '' && parsed.pathname === '/' && parsed.search === '' && parsed.hash === '' &&
      /^\d{1,5}$/.test(parsed.port) && Number(parsed.port) >= 1 && Number(parsed.port) <= 65535,
    'platform_recovery_proxy_api_origin_must_be_loopback');
    participantApiOrigin = parsed.origin;
  }
  let observer = undefined;
  if (observerDatabase !== undefined) {
    demand(observerDatabase && typeof observerDatabase === 'object' &&
      LOOPBACK_HOSTS.has(normalizedLoopbackHost(observerDatabase.host)) &&
      Number.isSafeInteger(observerDatabase.port) && observerDatabase.port >= 1 && observerDatabase.port <= 65535,
    'platform_recovery_observer_proxy_must_be_loopback');
    observer = { host: normalizedLoopbackHost(observerDatabase.host), port: observerDatabase.port, database: 'bef' };
  }
  return { ...(participantApiOrigin ? { participantApiOrigin } : {}), ...(observer ? { observerDatabase: observer } : {}) };
}

/** Provision coordinator credentials only inside the compose tmpfs mount. */
export async function provisionGenuineS1CoordinatorConfig({ repositoryRoot, automaticWorkerEvaluation = false,
  apiBaseUrl = undefined, observerDatabase = undefined }) {
  demand(process.platform === 'linux' && repositoryRoot === ROOT, 'genuine_s1_requires_pinned_docker_runtime');
  demand(process.env.OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED === 'true', 'explicit_private_coordinator_override_required');
  const recoveryProxySettings = validateGenuineRecoveryProxySettings({ apiBaseUrl, observerDatabase, automaticWorkerEvaluation });
  const configPath = process.env.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG || '.local/owner-identity/bef-task-coordinator.json';
  demand(configPath === '.local/owner-identity/bef-task-coordinator.json', 'coordinator_config_path_not_pinned');
  const manifestBytes = await safeBytes(repositoryRoot, 'infrastructure/benchmark-environment/manifest.json');
  const manifest = JSON.parse(manifestBytes.bytes.toString('utf8'));
  const release = JSON.parse((await safeBytes(repositoryRoot, PIN.release.path, PIN.release.sha256)).bytes.toString('utf8'));
  const releaseManifest = release.manifest;
  demand(releaseManifest?.executionIdentity?.environmentManifestSha256 === manifestBytes.sha256 &&
    manifest.local?.identity === 'private-anvil-fork' && manifest.local?.chainId === 8453 && Array.isArray(manifest.x402?.catalog),
  'coordinator_manifest_pin_mismatch');
  const target = resolve(repositoryRoot, '.local/owner-identity');
  await mkdir(target, { recursive: true, mode: 0o700 });
  await chmod(target, 0o700);
  const targetInfo = await stat(target);
  demand(targetInfo.isDirectory() && (targetInfo.mode & 0o077) === 0, 'coordinator_tmpfs_permissions_invalid');
  const secretsDir = resolve(target, 'secrets');
  await mkdir(secretsDir, { recursive: true, mode: 0o700 });
  await chmod(secretsDir, 0o700);
  let adminKey = (await readFile('/run/secrets/bef_admin_key', 'utf8')).trim();
  demand(adminKey.length >= 16 && adminKey.length <= 4096 && !/[\r\n\u0000]/.test(adminKey), 'coordinator_admin_key_unavailable');
  const keyPath = resolve(secretsDir, 'bef-admin-key');
  await writeFile(keyPath, adminKey + '\n', { flag: 'wx', mode: 0o600 });
  await chmod(keyPath, 0o600);
  adminKey = '';
  const local = manifest.local;
  const x402Policy = {
    manifestSha256: manifestBytes.sha256,
    scheme: manifest.x402.scheme,
    network: manifest.x402.network,
    asset: manifest.x402.asset,
    assetTransferMethod: manifest.x402.assetTransferMethod,
    eip712Domain: manifest.x402.eip712Domain,
    maxTimeoutSeconds: manifest.x402.maxTimeoutSeconds ?? 300,
    sdkVersions: { core: manifest.x402.version, evm: local.versions.x402Evm, viem: local.versions.viem },
    localAnvil: { identity: local.identity, chainId: local.chainId, anvilVersion: local.anvilVersion,
      executionNetwork: local.executionNetwork, hardFork: local.hardfork,
      forkBlockNumber: local.forkBlock, forkBlockHash: manifest.source.blockHash },
    resources: manifest.x402.catalog.map((item) => ({ resourceId: item.resourceId, resourceSha256: item.resourceSha256,
      contentType: item.contentType, ...(item.dataType ? { dataType: item.dataType } : {}),
      ...(item.schema ? { schema: item.schema } : {}), ...(item.provenance ? { provenance: item.provenance } : {}),
      offers: item.offers })),
  };
  const apiPort = process.env.BEF_API_HOST_PORT || '8783';
  const sourcePort = process.env.BEF_SOURCE_PROXY_HOST_PORT || '18544';
  const rpcPort = process.env.BEF_LOCAL_RPC_A_HOST_PORT || '18545';
  const config = { schemaVersion: 'local-bef-task-coordinator-config/v1', adminKeyFile: 'secrets/bef-admin-key',
    sourceRpcUrl: 'http://host.docker.internal:' + sourcePort,
    ...(automaticWorkerEvaluation ? { observationPipeline: {
      schemaVersion: 'local-bef-training-observation/v1',
      database: recoveryProxySettings?.observerDatabase ?? { host: 'host.docker.internal', port: Number(process.env.BEF_DATABASE_HOST_PORT || '55432'), database: 'bef' },
      passwordFile: '/run/secrets/bef_database_observer_password',
    } } : {}),
    environments: [{ envId: 'bef-env-a', apiBaseUrl: recoveryProxySettings?.participantApiOrigin ?? 'http://host.docker.internal:' + apiPort,
      observerRpcUrl: 'http://host.docker.internal:' + rpcPort, x402Policy }] };
  const configAbsolute = resolve(repositoryRoot, configPath);
  await writeFile(configAbsolute, JSON.stringify(config) + '\n', { flag: 'wx', mode: 0o600 });
  await chmod(configAbsolute, 0o600);
  process.env.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG = configPath;
  return { configPath, environmentId: 'bef-env-a', manifestSha256: manifestBytes.sha256, secretMaterialRetained: false,
    ...(recoveryProxySettings ? { platformRecoveryFaultProxy: true,
      observerDatabaseProxy: Boolean(recoveryProxySettings.observerDatabase) } : {}) };
}

export { offerTermsMatch as matchGenuinePublicOffer, selectCatalogOffer as selectGenuinePublicCatalogOffer,
  readH3PublicReferenceField as readGenuineH3PublicReferenceField,
  createMinimumIntervalPacer as createGenuineAgentRequestPacer };
