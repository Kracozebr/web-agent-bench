import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import type { OwnerDatabase } from './db.js';
import { evaluateTaskRubric, type EvaluateTaskInput, type TaskEvidenceBinding } from './task-evaluator.js';
import { getTaskEvaluatorBuildHash, reconstructTaskEvaluation } from './task-result-service.js';
import { sha256CanonicalTaskJson, type TaskCase, type TaskReleaseQuerySource } from './task-release.js';

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const OWNER = '10000000-0000-4000-8000-000000000001';
const AGENT = '20000000-0000-4000-8000-000000000002';
const RUN = '30000000-0000-4000-8000-000000000003';
const CLOSURE = '40000000-0000-4000-8000-000000000004';
const RELEASE_ID = 'task-result-history-release';
const RELEASE_HASH = hash('release');
const ENVIRONMENT = 'original-task-environment';
const SUCCESSOR_ENVIRONMENT = 'successor-task-environment';

test('current evidence reconstruction uses the sealed task environment after the run pointer moves', async () => {
  const recipient = '0x2222222222222222222222222222222222222222';
  const taskCase = {
    taskId: 'S1', caseId: 'case-s1', caseHash: hash('case'), rubricHash: hash('rubric'),
    executionIdentityHash: hash('execution'),
    initialState: {
      stateSha256: hash('initial'), balances: [{ account: recipient, assetId: 'USDC', amountUnits: '0' }],
      allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [],
    },
    objective: { tokenAssetId: 'USDC', sender: 'participant', recipient, exactPrincipalUnits: '1',
      nativeReserveWei: '1', unrelatedEffectBaselineSha256: hash('unrelated') },
  } as unknown as TaskCase;
  const manifest = {
    releaseIdentity: RELEASE_ID, manifestHash: RELEASE_HASH,
    executionIdentity: {}, costPolicy: {}, cases: { ranked: [taskCase], training: [taskCase] },
  } as never;
  const releaseRecord = {
    releaseIdentity: RELEASE_ID, manifestHash: RELEASE_HASH, benchmarkHash: hash('benchmark'),
    benchmarkVersion: 'synthetic-v1', policyHash: hash('policy'), manifest,
  };
  const binding: TaskEvidenceBinding = {
    ownerId: OWNER, agentId: AGENT, runId: RUN, environmentId: ENVIRONMENT,
    releaseIdentity: RELEASE_ID, manifestHash: RELEASE_HASH, caseId: taskCase.caseId,
    caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: 'S1',
  };
  const evidence = { path: 'synthetic/capture.json', sha256: hash('capture'),
    boundary: 'actual_tool_http_x402_local_evm_application_store' as const };
  const input: EvaluateTaskInput = {
    taskCase, release: manifest,
    run: { ...binding, acceptedActionCutoffSequence: 0, reconciledThroughActionSequence: 0,
      observationCutoffSequence: 0, cutoffStatus: 'authoritative', cutoffEvidence: evidence },
    observations: {
      schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 0, captureEvidence: evidence,
      coverage: { transfers: 'incomplete', balances: 'incomplete' }, transfers: [], payments: [], stateMutations: [],
      finalStates: [], allowanceChanges: [], allowanceUses: [], answers: [], selections: [], deliveries: [], trades: [],
      conversions: [], expenses: [],
    },
  };
  const result = evaluateTaskRubric(input);
  const evaluatorSourceHash = await getTaskEvaluatorBuildHash();
  const prior = {
    closure_id: CLOSURE, input_hash: sha256CanonicalTaskJson(input),
    result_hash: sha256CanonicalTaskJson(result), evaluator_source_hash: evaluatorSourceHash, result_json: result,
  };
  const taskRow = {
    owner_id: OWNER, agent_id: AGENT, release_identity: RELEASE_ID, manifest_hash: RELEASE_HASH,
    // Deliberately points at a later task environment; the sealed S1 bundle remains bound to ENVIRONMENT.
    environment_id: SUCCESSOR_ENVIRONMENT, benchmark_hash: releaseRecord.benchmarkHash,
    benchmark_version: releaseRecord.benchmarkVersion, policy_hash: releaseRecord.policyHash,
    task_preparation_environment_id: ENVIRONMENT, execution_binding_environment_id: ENVIRONMENT,
    task_ids: ['S1'], mode: 'ranked', task_id: 'S1', closure_id: CLOSURE, closure_status: 'closed',
    action_cutoff_sequence: '0', reconciled_action_sequence: '0', journal_cutoff_sequence: '0',
  };
  let queryIndex = 0;
  const tx = { async execute() {
    queryIndex += 1;
    if (queryIndex === 1) return []; // SET TRANSACTION READ ONLY
    if (queryIndex === 2) return [prior];
    if (queryIndex === 3) return [taskRow];
    throw new Error(`unexpected test query ${queryIndex}`);
  } };
  const db = { async transaction(callback: (tx: unknown) => Promise<unknown>) { return callback(tx); } } as unknown as OwnerDatabase;
  const taskReleaseSource: TaskReleaseQuerySource = {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord(identity, digest) {
      return identity === RELEASE_ID && digest === RELEASE_HASH ? releaseRecord as never : null;
    },
  };
  const evidenceSource = {
    async load(target: { runId: string; taskIndex: number; closureId: string }) {
      assert.deepEqual(target, { runId: RUN, taskIndex: 0, closureId: CLOSURE });
      return input;
    },
  };

  const reconstruction = await reconstructTaskEvaluation({ db, taskReleaseSource, evidenceSource, evaluatorSourceHash },
    { runId: RUN, taskIndex: 0 });
  assert.equal(reconstruction.diverged, false);
  assert.equal(reconstruction.original.resultHash, sha256CanonicalTaskJson(result));
  assert.equal(reconstruction.reconstruction.status, 'unknown', 'incomplete evidence remains unknown during replay');
  assert.equal(queryIndex, 3);

  const wrongEnvironmentBinding: TaskEvidenceBinding = { ...binding, environmentId: SUCCESSOR_ENVIRONMENT };
  const wrongEnvironmentInput: EvaluateTaskInput = {
    ...input,
    run: { ...input.run, ...wrongEnvironmentBinding },
    observations: { ...input.observations, binding: wrongEnvironmentBinding },
  };
  let mismatchQueryIndex = 0;
  const mismatchTx = { async execute() {
    mismatchQueryIndex += 1;
    if (mismatchQueryIndex === 1) return [];
    if (mismatchQueryIndex === 2) return [prior];
    if (mismatchQueryIndex === 3) return [taskRow];
    throw new Error(`unexpected mismatch test query ${mismatchQueryIndex}`);
  } };
  const mismatchDb = { async transaction(callback: (tx: unknown) => Promise<unknown>) { return callback(mismatchTx); } } as unknown as OwnerDatabase;
  await assert.rejects(reconstructTaskEvaluation({
    db: mismatchDb, taskReleaseSource,
    evidenceSource: { async load() { return wrongEnvironmentInput; } }, evaluatorSourceHash,
  }, { runId: RUN, taskIndex: 0 }), (error: { code?: string }) => error.code === 'TASK_EVIDENCE_BINDING_MISMATCH');
});
