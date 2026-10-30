import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import type { EvidenceReference, TaskCase, TaskReleaseQuerySource } from './task-release.js';
import { canonicalTaskJson, sha256CanonicalTaskJson } from './task-release.js';
import type { M1CaptureAction } from './task-m1-capture-packet.js';
import { createS3CapturePacketFixture } from './task-s3-capture-packet.fixture.js';
import { TaskSealedEvidenceSource } from './task-sealed-evidence-source.js';

const HASH = (label: string) => createHash('sha256').update(label).digest('hex');
const OWNER = '10000000-0000-4000-8000-000000000001';
const AGENT = '20000000-0000-4000-8000-000000000002';
const RUN = '30000000-0000-4000-8000-000000000003';
const CLOSURE = '40000000-0000-4000-8000-000000000004';
const PREPARATION = '50000000-0000-4000-8000-000000000005';
const LEASE = '60000000-0000-4000-8000-000000000006';
const GENERATION = '70000000-0000-4000-8000-000000000007';
const RELEASE_ID = 'synthetic-evidence-release';
const MANIFEST_HASH = HASH('manifest');
const CASE_ID = 'synthetic-S1-case';
const CASE_HASH = HASH('case');
const RUBRIC_HASH = HASH('rubric');
const ENVIRONMENT = 'synthetic-local-env';
const ENV_MANIFEST_HASH = HASH('environment-manifest');
const SOURCE_HASH = HASH('application-source');
const EXECUTION_HASH = HASH('execution-identity');
const INITIAL_STATE_HASH = HASH('initial-state');
const S2_ASSET = `0x${'a'.repeat(40)}`;
const S2_RECIPIENT = '0x24e0ff92900f2963a54a463116f730e567f1ee89';
const S2_CHECKSUM_RECIPIENT = '0x24e0FF92900f2963A54A463116f730E567F1Ee89';
const S2_FOREIGN_RECIPIENT = '0x3000000000000000000000000000000000000003';
const COORDINATOR_EVIDENCE_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';

type Fixture = {
  root: string;
  bundle: Record<string, any>;
  row: Record<string, any>;
  taskCase: TaskCase;
  record: any;
  files: Map<string, Buffer>;
};

async function makeFixture(root: string): Promise<Fixture> {
  const taskCase = {
    taskId: 'S1', caseId: CASE_ID, caseHash: CASE_HASH, rubricHash: RUBRIC_HASH,
    executionIdentityHash: EXECUTION_HASH, initialState: { stateSha256: INITIAL_STATE_HASH },
    objective: {},
  } as unknown as TaskCase;
  const binding = {
    ownerId: OWNER, agentId: AGENT, runId: RUN, environmentId: ENVIRONMENT,
    releaseIdentity: RELEASE_ID, manifestHash: MANIFEST_HASH, caseId: CASE_ID,
    caseHash: CASE_HASH, rubricHash: RUBRIC_HASH, taskId: 'S1',
  };
  const files = new Map<string, Buffer>();
  const evidence = async (label: string, category: 'observation' | 'preparation' | 'action', payload: unknown = { proof: label }) => {
    const path = `artifacts/runs/owner-identity-bef-task-coordinator/${category}/${label}.json`;
    const bytes = Buffer.from(JSON.stringify(payload) + '\n');
    files.set(path, bytes);
    await mkdir(dirname(resolve(root, ...path.split('/'))), { recursive: true });
    await writeFile(resolve(root, ...path.split('/')), bytes, { flag: 'wx', mode: 0o600 });
    return { path, sha256: createHash('sha256').update(bytes).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  };
  const closure = {
    closureId: CLOSURE, operationId: 'synthetic-close-operation', payloadHash: HASH('closure-payload'),
    reason: 'agent_finish', actionCutoffSequence: 1, reconciledActionSequence: 1,
  };
  const execution = {
    preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION, environmentId: ENVIRONMENT,
    environmentManifestHash: ENV_MANIFEST_HASH, applicationSourceHash: SOURCE_HASH,
    executionIdentityHash: EXECUTION_HASH, initialStateSha256: INITIAL_STATE_HASH,
  };
  const fixtureEvidence = await evidence('fixture', 'preparation');
  const baselineEvidence = await evidence('baseline', 'preparation');
  const transferEvidence = await evidence('transfer', 'action');
  const transactionHash = `0x${'1'.repeat(64)}`;
  const actionId = '80000000-0000-4000-8000-000000000008';
  const packet = {
    schemaVersion: 'bts-s1-run-observation-capture/v1',
    classification: 'run_bound_observations_candidate_not_grade',
    binding,
    closure: { closureId: CLOSURE, actionCutoffSequence: 1, reconciledActionSequence: 1 },
    execution,
    preparation: { fixtureEvidence, baselineEvidence, baselineBlockNumber: '0', baselineBlockHash: `0x${'2'.repeat(64)}` },
    ownerActions: [{ actionId, actionSequence: 1, ownerOperationId: 'synthetic-owner-operation', actionKind: 'transfer',
      commandSha256: HASH('action-command'), receiptStatus: 'observed', actionEvidence: transferEvidence,
      befOperationId: '90000000-0000-4000-8000-000000000009', transactionHash }],
    bef: { session: { currentUser: 'bef_observer', sessionUser: 'bef_observer' }, before: {}, after: {}, censusSha256: HASH('census') },
    rpc: { localChainId: '8453', intervalBlocks: [], receipts: [], transferLogs: [], responseHashes: [] },
  };
  const captureEvidence = await evidence('capture', 'observation', packet);
  const cutoffEvidence = captureEvidence;
  const bundle = {
    schemaVersion: 'bts-task-observation-bundle/v1',
    binding,
    closure: { ...closure, operationId: 'synthetic-close-operation' },
    execution: {
      preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION,
      environmentManifestHash: ENV_MANIFEST_HASH, applicationSourceHash: SOURCE_HASH,
      executionIdentityHash: EXECUTION_HASH, initialStateSha256: INITIAL_STATE_HASH,
    },
    cutoff: { observationSequence: 7, status: 'authoritative', evidence: cutoffEvidence },
    observations: {
      schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 7,
      captureEvidence, coverage: { transfers: 'incomplete', balances: 'contradictory' },
      transfers: [{ kind: 'transfer', observationId: `s1-transfer-${actionId}`, sequence: 7, actionSequence: 1,
        source: 'persisted_observer', binding, evidence: captureEvidence, from: 'participant', to: 'synthetic-recipient',
        assetId: 'USDC', amountUnits: '1', receiptStatus: 'success', transactionHash, operation: 'principal' }],
      payments: [], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [], answers: [],
      selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
    },
  };
  const release = {
    releaseIdentity: RELEASE_ID,
    manifestHash: MANIFEST_HASH,
    manifest: {
      releaseIdentity: RELEASE_ID,
      manifestHash: MANIFEST_HASH,
      executionIdentity: { environmentManifestSha256: ENV_MANIFEST_HASH },
      costPolicy: { ethValuation: { numerator: '1', denominator: '1' } },
      cases: { training: [taskCase], ranked: [taskCase] },
    },
  };
  const row = {
    run_id: RUN, owner_id: OWNER, agent_id: AGENT, mode: 'ranked', task_ids: ['S1'], release_identity: RELEASE_ID,
    manifest_hash: MANIFEST_HASH, environment_id: ENVIRONMENT, task_id: 'S1', closure_id: CLOSURE,
    task_index: 0, closure_answer_json: null,
    closure_status: 'closed', action_cutoff_sequence: '1', reconciled_action_sequence: '1',
    closure_operation_id: 'synthetic-close-operation', closure_payload_hash: HASH('closure-payload'),
    closure_reason: 'agent_finish', closure_action_cutoff_sequence: '1',
    bundle_owner_id: OWNER, bundle_agent_id: AGENT, bundle_closure_id: CLOSURE,
    bundle_closure_operation_id: 'synthetic-close-operation', bundle_closure_payload_hash: HASH('closure-payload'),
    bundle_closure_reason: 'agent_finish', bundle_task_id: 'S1', bundle_release_identity: RELEASE_ID,
    bundle_manifest_hash: MANIFEST_HASH, bundle_case_id: CASE_ID, bundle_case_hash: CASE_HASH,
    bundle_rubric_hash: RUBRIC_HASH, bundle_environment_id: ENVIRONMENT, preparation_id: PREPARATION, lease_id: LEASE,
    generation_id: GENERATION, environment_manifest_hash: ENV_MANIFEST_HASH, application_source_hash: SOURCE_HASH,
    execution_identity_hash: EXECUTION_HASH, initial_state_sha256: INITIAL_STATE_HASH,
    bundle_action_cutoff_sequence: '1', bundle_reconciled_action_sequence: '1', observation_cutoff_sequence: '7',
    cutoff_evidence: cutoffEvidence, bundle_hash: sha256CanonicalTaskJson(bundle), bundle_json: bundle,
    prepared_preparation_id: PREPARATION, prepared_lease_id: LEASE, prepared_environment_id: ENVIRONMENT,
    prepared_release_identity: RELEASE_ID, prepared_manifest_hash: MANIFEST_HASH, prepared_task_id: 'S1',
    prepared_case_id: CASE_ID, prepared_case_hash: CASE_HASH, prepared_initial_state_sha256: INITIAL_STATE_HASH,
    prepared_environment_manifest_hash: ENV_MANIFEST_HASH, prepared_application_source_hash: SOURCE_HASH,
    prepared_execution_identity_hash: EXECUTION_HASH, lease_state: 'fenced',
    execution_environment_id: ENVIRONMENT, execution_generation_id: GENERATION,
    execution_manifest_hash: ENV_MANIFEST_HASH, execution_application_source_hash: SOURCE_HASH,
    has_ready_generation: true,
  };
  return { root, bundle, row, taskCase, record: release, files };
}

async function makeS2Fixture(root: string, options: { action?: boolean; answer?: boolean; coverage?: Record<string, string>; payTo?: string } = {}) {
  const actionEnabled = options.action ?? false;
  const answer = options.answer ? { amountUnits: '200000', network: 'eip155:8453', resourceId: 'market-brief', offerId: 'standard' } : null;
  const taskCase = {
    taskId: 'S2', caseId: 'synthetic-S2-case', caseHash: HASH('S2-case'), rubricHash: HASH('S2-rubric'),
    executionIdentityHash: EXECUTION_HASH,
    initialState: { stateSha256: INITIAL_STATE_HASH,
      balances: [{ account: 'participant', assetId: 'USDC', amountUnits: '10' }], allowances: [], deliveredComponentIds: [], fulfilledObligationIds: [] },
    objective: { resourceId: 'market-brief', offerId: 'standard',
      completePaymentRequirements: { scheme: 'exact', resourceId: 'market-brief', offerId: 'standard', version: '1',
        amountUnits: '200000', network: 'eip155:8453', assetId: 'USDC', recipient: S2_RECIPIENT,
        authFields: [{ name: 'assetTransferMethod', value: 'eip3009' }] }, requiredAnswerFields: ['amountUnits', 'network'] },
  } as unknown as Extract<TaskCase, { taskId: 'S2' }>;
  const binding = { ownerId: OWNER, agentId: AGENT, runId: RUN, environmentId: ENVIRONMENT, releaseIdentity: RELEASE_ID,
    manifestHash: MANIFEST_HASH, caseId: taskCase.caseId, caseHash: taskCase.caseHash, rubricHash: taskCase.rubricHash, taskId: 'S2' };
  const files = new Map<string, Buffer>();
  const writeEvidence = async (label: string, category: 'observation' | 'preparation' | 'action', payload: unknown) => {
    const path = `${COORDINATOR_EVIDENCE_ROOT}${category}/${label}.json`;
    const bytes = Buffer.from(`${JSON.stringify(payload)}\n`);
    files.set(path, bytes);
    await mkdir(dirname(resolve(root, ...path.split('/'))), { recursive: true });
    await writeFile(resolve(root, ...path.split('/')), bytes, { flag: 'wx', mode: 0o600 });
    return { path, sha256: createHash('sha256').update(bytes).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  };
  const actionId = '80000000-0000-4000-8000-000000000008';
  const befOperationId = '90000000-0000-4000-8000-000000000009';
  const command = { kind: 'inspect_offer' as const, resourceId: 'market-brief', offerId: 'standard' };
  const commandSha256 = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command });
  const payment = { scheme: 'exact', network: 'eip155:8453', amount: '200000', asset: S2_ASSET,
    payTo: options.payTo ?? S2_RECIPIENT, transferMethod: 'eip3009' };
  const body = { operationId: befOperationId, readHandle: { kind: 'offer', operationId: befOperationId },
    resourceId: 'market-brief', resourceSha256: HASH('resource'), contentType: 'application/json', freeInspection: true,
    deliveryState: 'not_delivered', payment, offers: [{ id: 'standard', payment }] };
  const expectedBefResponse = { operationId: body.operationId, readHandle: body.readHandle, resourceId: body.resourceId,
    resourceSha256: body.resourceSha256, contentType: body.contentType, payment: body.payment, offers: body.offers,
    freeInspection: body.freeInspection, deliveryState: body.deliveryState };
  const actionEvidence = actionEnabled ? await writeEvidence('s2-inspect', 'action', {
    schema: 'bef-task-action-observation-v1', actionId, runId: RUN, taskIndex: 0, actionSequence: '1',
    ownerOperationId: 'synthetic-owner-op-s2', actionKind: 'inspect_offer', commandSha256, environmentId: ENVIRONMENT,
    generationId: GENERATION, manifestSha256: ENV_MANIFEST_HASH, applicationSourceSha256: SOURCE_HASH,
    idempotencyKey: `task-action-${actionId}`, status: 'observed', httpStatus: 200, befOperationId,
    rawResponseSha256: HASH('offer-response'), participantToolResponse: body,
  }) : null;
  const fixtureEvidence = await writeEvidence('s2-fixture', 'preparation', { proof: 'fixture' });
  const baselineBlockHash = `0x${'1'.repeat(64)}`;
  const baselineEvidence = await writeEvidence('s2-baseline', 'preparation', { blockNumber: '10', blockHash: baselineBlockHash });
  const closureOperationId = 'synthetic-finish-operation';
  const closurePayloadHash = sha256CanonicalTaskJson({ action: 'task_finish', runId: RUN, taskIndex: 0, answer: answer ?? null });
  const closure = { closureId: CLOSURE, operationId: closureOperationId, payloadHash: closurePayloadHash, reason: 'agent_finish',
    actionCutoffSequence: actionEnabled ? 1 : 0, reconciledActionSequence: actionEnabled ? 1 : 0 };
  const balances = [{ account: 'participant', assetId: 'USDC', amountUnits: '10' }];
  const census = {
    generation: { generation_id: GENERATION, env_id: ENVIRONMENT, participant_id: 'synthetic-participant', payer_address: S2_RECIPIENT,
      manifest_sha256: ENV_MANIFEST_HASH, status: 'active', resource_variant: 'canonical', fixture_transaction_hash: null,
      fixture_block_hash: null, fixture_token_delta_units: null, fixture_native_balance_wei: null, expires_at: null, fenced_at: null,
      chain_id: 8453, node_identity: 'synthetic-node', environment_manifest_sha256: ENV_MANIFEST_HASH },
    operations: actionEnabled ? [{ operation_id: befOperationId, env_id: ENVIRONMENT, generation_id: GENERATION,
      participant_id: 'synthetic-participant', idempotency_key_sha256: createHash('sha256').update(`task-action-${actionId}`).digest('hex'),
      request_sha256: createHash('sha256').update(JSON.stringify({ method: 'GET', path: '/offer', resourceId: 'market-brief' })).digest('hex'),
      operation_kind: 'offer', status: 'accepted', receipt_status: 'not_submitted', transaction_hash: null,
      response_sha256: createHash('sha256').update(JSON.stringify(expectedBefResponse)).digest('hex'),
      started_at: '2026-01-01T00:00:00.000Z', completed_at: '2026-01-01T00:00:00.001Z' }] : [],
    selectedExecutions: [], selectedEvents: [], payments: [], deliveries: [], costs: [], denials: [], x402Observations: [],
    rpcObservations: [], evidenceArtifacts: [],
  };
  const rpcCheckpoint = { blockNumber: '10', blockHash: baselineBlockHash, parentHash: `0x${'2'.repeat(64)}`,
    balances, allowances: [], participantTransactionCount: '0' };
  const packet = {
    schemaVersion: 'bts-s2-run-observation-capture/v1', classification: 'run_bound_observations_candidate_not_grade', binding,
    closure: { closureId: CLOSURE, actionCutoffSequence: closure.actionCutoffSequence,
      reconciledActionSequence: closure.reconciledActionSequence, reason: 'agent_finish', operationId: closureOperationId,
      payloadHash: closurePayloadHash, answer },
    execution: { preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION, environmentId: ENVIRONMENT,
      environmentManifestHash: ENV_MANIFEST_HASH, applicationSourceHash: SOURCE_HASH, executionIdentityHash: EXECUTION_HASH,
      initialStateSha256: INITIAL_STATE_HASH },
    preparation: { fixtureEvidence, baselineEvidence, baselineBlockNumber: '10', baselineBlockHash },
    ownerActions: actionEnabled ? [{ actionId, actionSequence: 1, ownerOperationId: 'synthetic-owner-op-s2', actionKind: 'inspect_offer',
      commandSha256, receiptStatus: 'observed', actionEvidence, befOperationId }] : [],
    bef: { session: { currentUser: 'bef_observer', sessionUser: 'bef_observer', databaseName: 'synthetic_test', transactionReadOnly: 'on',
      superuser: false, bypassRls: false }, before: census, after: census, censusSha256: sha256CanonicalTaskJson(census) },
    rpc: { localChainId: '8453', baseline: rpcCheckpoint, final: rpcCheckpoint, intervalBlocks: [], participantLogQueryCount: 0, responseHashes: [] },
  };
  const captureEvidence = await writeEvidence('s2-capture', 'observation', packet);
  const observationSequence = answer ? 2 : 1;
  const coverage = options.coverage ?? { transfers: 'complete', payments: 'complete', stateMutations: 'complete', balances: 'complete',
    allowances: 'complete', deliveries: 'complete', answers: 'complete' };
  const observations = { schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: observationSequence,
    captureEvidence, coverage, transfers: [], payments: [], stateMutations: [],
    finalStates: [{ kind: 'final_state', observationId: `s2-final-${RUN}-0`, sequence: observationSequence, actionSequence: closure.actionCutoffSequence,
      source: 'persisted_observer', binding, evidence: captureEvidence, balances, allowances: [] }],
    allowanceChanges: [], allowanceUses: [], answers: answer ? [{ kind: 'final_answer', observationId: `s2-answer-${CLOSURE}`,
      sequence: 1, actionSequence: closure.actionCutoffSequence, source: 'persisted_observer', binding, evidence: captureEvidence, answer }] : [],
    selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
  };
  const bundle = { schemaVersion: 'bts-task-observation-bundle/v1', binding, closure, execution: {
    preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION, environmentManifestHash: ENV_MANIFEST_HASH,
    applicationSourceHash: SOURCE_HASH, executionIdentityHash: EXECUTION_HASH, initialStateSha256: INITIAL_STATE_HASH,
  }, cutoff: { observationSequence, status: 'authoritative', evidence: captureEvidence }, observations };
  const record: any = { releaseIdentity: RELEASE_ID, manifestHash: MANIFEST_HASH, manifest: { releaseIdentity: RELEASE_ID, manifestHash: MANIFEST_HASH,
    costPolicy: { ethValuation: { numerator: '1', denominator: '1' } },
    executionIdentity: { environmentManifestSha256: ENV_MANIFEST_HASH, localChainId: 8453,
      assets: [{ assetId: 'USDC', kind: 'erc20', chainId: 8453, address: S2_ASSET }] },
    cases: { training: [taskCase], ranked: [taskCase] } } };
  const row: Record<string, any> = {
    run_id: RUN, owner_id: OWNER, agent_id: AGENT, mode: 'ranked', task_ids: ['S2'], release_identity: RELEASE_ID,
    manifest_hash: MANIFEST_HASH, environment_id: ENVIRONMENT, task_id: 'S2', task_index: 0, closure_id: CLOSURE,
    closure_status: 'closed', action_cutoff_sequence: String(closure.actionCutoffSequence),
    reconciled_action_sequence: String(closure.reconciledActionSequence), closure_operation_id: closureOperationId,
    closure_payload_hash: closurePayloadHash, closure_reason: 'agent_finish', closure_answer_json: answer,
    closure_action_cutoff_sequence: String(closure.actionCutoffSequence), bundle_owner_id: OWNER, bundle_agent_id: AGENT,
    bundle_closure_id: CLOSURE, bundle_closure_operation_id: closureOperationId, bundle_closure_payload_hash: closurePayloadHash,
    bundle_closure_reason: 'agent_finish', bundle_task_id: 'S2', bundle_release_identity: RELEASE_ID, bundle_manifest_hash: MANIFEST_HASH,
    bundle_case_id: taskCase.caseId, bundle_case_hash: taskCase.caseHash, bundle_rubric_hash: taskCase.rubricHash,
    bundle_environment_id: ENVIRONMENT, preparation_id: PREPARATION, lease_id: LEASE, generation_id: GENERATION,
    environment_manifest_hash: ENV_MANIFEST_HASH, application_source_hash: SOURCE_HASH, execution_identity_hash: EXECUTION_HASH,
    initial_state_sha256: INITIAL_STATE_HASH, bundle_action_cutoff_sequence: String(closure.actionCutoffSequence),
    bundle_reconciled_action_sequence: String(closure.reconciledActionSequence), observation_cutoff_sequence: observationSequence,
    cutoff_evidence: captureEvidence, bundle_hash: sha256CanonicalTaskJson(bundle), bundle_json: bundle,
    prepared_preparation_id: PREPARATION, prepared_lease_id: LEASE, prepared_environment_id: ENVIRONMENT,
    prepared_release_identity: RELEASE_ID, prepared_manifest_hash: MANIFEST_HASH, prepared_task_id: 'S2',
    prepared_case_id: taskCase.caseId, prepared_case_hash: taskCase.caseHash, prepared_initial_state_sha256: INITIAL_STATE_HASH,
    prepared_environment_manifest_hash: ENV_MANIFEST_HASH, prepared_application_source_hash: SOURCE_HASH,
    prepared_execution_identity_hash: EXECUTION_HASH, lease_state: 'fenced', execution_environment_id: ENVIRONMENT,
    execution_generation_id: GENERATION, execution_manifest_hash: ENV_MANIFEST_HASH, execution_application_source_hash: SOURCE_HASH,
    has_ready_generation: true,
  };
  const actionRows = actionEnabled ? [{ id: actionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S2',
    environment_id: ENVIRONMENT, action_sequence: '1', operation_id: 'synthetic-owner-op-s2', payload_hash: commandSha256,
    action_kind: 'inspect_offer', command_json: command, receipt_revision: 1, receipt_status: 'observed', evidence_hash: actionEvidence!.sha256,
    evidence_path: actionEvidence!.path, transaction_hash: null, history_revision: 1, history_status: 'observed',
    history_evidence_hash: actionEvidence!.sha256, history_evidence_path: actionEvidence!.path, history_transaction_hash: null }] : [];
  return { root, bundle, row, taskCase, record, files, actionRows };
}

async function withPrivateRoot<T>(callback: (root: string) => Promise<T>): Promise<T> {
  const parent = await mkdtemp(join(tmpdir(), 'task-sealed-source-test-'));
  const root = join(parent, 'private-evidence');
  await mkdir(root, { mode: 0o700 });
  try { return await callback(root); }
  finally {
    const actualParent = await realpath(parent);
    const actualTemp = await realpath(tmpdir());
    assert.equal(dirname(actualParent), actualTemp, 'test cleanup remains inside the temp directory');
    assert.match(basename(actualParent), /^task-sealed-source-test-/);
    await rm(actualParent, { recursive: true, force: false });
  }
}

function makeSource(fixture: Fixture) {
  const taskReleaseSource: TaskReleaseQuerySource = {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord(identity, digest) {
      return identity === RELEASE_ID && digest === MANIFEST_HASH ? fixture.record : null;
    },
  };
  let queryCount = 0;
  const transaction = {
    async execute() {
      queryCount += 1;
      return [fixture.row];
    },
  };
  const source = new TaskSealedEvidenceSource({ taskReleaseSource, evidenceRoot: fixture.root });
  return { source, transaction, queryCount: () => queryCount };
}

function makeS2Source(fixture: Awaited<ReturnType<typeof makeS2Fixture>>) {
  let transaction: { execute(): Promise<unknown> };
  const taskReleaseSource: TaskReleaseQuerySource = {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord(identity, digest, tx) {
      assert.equal(tx, transaction, 'S2 release lookup stays inside the caller transaction');
      return identity === RELEASE_ID && digest === MANIFEST_HASH ? fixture.record : null;
    },
  };
  let queryCount = 0;
  transaction = {
    async execute() {
      queryCount += 1;
      return queryCount === 1 ? [fixture.row] : fixture.actionRows;
    },
  };
  const source = new TaskSealedEvidenceSource({ taskReleaseSource, evidenceRoot: fixture.root });
  return { source, transaction, queryCount: () => queryCount };
}

test('sealed source binds S1 to the caller transaction and preserves incomplete coverage after fencing', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    let queryCount = 0;
    const tx = { async execute() { queryCount += 1; return [fixture.row]; } };
    const source = new TaskSealedEvidenceSource({
      taskReleaseSource: {
        async getActiveAdmissionRelease() { return null; },
        async getValidatedReleaseRecord(identity, digest, passedTx) {
          assert.equal(passedTx, tx, 'release lookup receives the same transaction');
          return identity === RELEASE_ID && digest === MANIFEST_HASH ? fixture.record : null;
        },
      }, evidenceRoot: root,
    });
    const result = await source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, tx as never);
    assert.ok(result);
    assert.equal(result.taskCase.taskId, 'S1');
    assert.equal(result.run.cutoffStatus, 'authoritative');
    assert.equal(result.run.acceptedActionCutoffSequence, 1);
    assert.equal(result.run.observationCutoffSequence, 7);
    assert.equal(result.run.environmentId, ENVIRONMENT, 'historical run input remains bound to the sealed task environment');
    assert.deepEqual(result.observations.coverage, { transfers: 'incomplete', balances: 'contradictory' });
    assert.equal(result.observations.transfers.length, 1);
    assert.equal(queryCount, 1);
  });
});

test('S1 sealed capture retains a neutral catalog prefix and rejects effectful read operations', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    const packet = JSON.parse(fixture.files.get(`${COORDINATOR_EVIDENCE_ROOT}observation/capture.json`)!.toString('utf8')) as Record<string, any>;
    const readActionId = '81000000-0000-4000-8000-000000000018';
    const readOperationId = '91000000-0000-4000-8000-000000000019';
    const readOwnerOperationId = 'neutral-read-owner-op-01';
    const readCommand = { kind: 'inspect_catalog' as const };
    const readCommandHash = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command: readCommand });
    const readEvidence: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/s1-catalog-read.json`,
      sha256: HASH('s1-catalog-read'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
    const transfer = { kind: 'transfer' as const, amountUnits: '1', recipient: S2_RECIPIENT, gasLimit: '50000' };
    const transferCommandHash = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command: transfer });
    packet.closure.actionCutoffSequence = 2;
    packet.closure.reconciledActionSequence = 2;
    packet.ownerActions = [
      { actionId: readActionId, actionSequence: 1, ownerOperationId: readOwnerOperationId, actionKind: 'inspect_catalog',
        commandSha256: readCommandHash, receiptStatus: 'observed', actionEvidence: readEvidence,
        befOperationId: readOperationId, transactionHash: null },
      { ...packet.ownerActions[0], actionSequence: 2, commandSha256: transferCommandHash },
    ];
    const readResponseHash = HASH('s1-catalog-response');
    const readOperation = { operation_id: readOperationId, env_id: ENVIRONMENT, generation_id: GENERATION,
      participant_id: 'synthetic-bef-participant', idempotency_key_sha256: HASH(`task-action-${readActionId}`),
      request_sha256: HASH(JSON.stringify({ method: 'GET', path: '/catalog' })), response_sha256: readResponseHash,
      operation_kind: 'catalog', status: 'accepted', receipt_status: 'not_submitted', transaction_hash: null };
    packet.bef.after = { generation: { participant_id: 'synthetic-bef-participant' }, operations: [readOperation],
      costs: [], selectedExecutions: [], selectedEvents: [], payments: [], deliveries: [] };
    const bundle = { binding: fixture.bundle.binding,
      closure: { ...fixture.bundle.closure, actionCutoffSequence: 2, reconciledActionSequence: 2 },
      execution: { ...fixture.bundle.execution, environmentId: ENVIRONMENT },
      observations: fixture.bundle.observations };
    bundle.observations.transfers[0].actionSequence = 2;
    const row = { ...fixture.row, action_cutoff_sequence: '2', reconciled_action_sequence: '2' };
    const durableRows = [
      { id: readActionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S1', environment_id: ENVIRONMENT,
        action_sequence: '1', operation_id: readOwnerOperationId, payload_hash: readCommandHash, action_kind: 'inspect_catalog',
        command_json: readCommand, receipt_revision: 1, receipt_status: 'observed', evidence_hash: readEvidence.sha256,
        evidence_path: readEvidence.path, transaction_hash: null, history_revision: 1, history_status: 'observed',
        history_evidence_hash: readEvidence.sha256, history_evidence_path: readEvidence.path, history_transaction_hash: null },
      { id: '80000000-0000-4000-8000-000000000008', run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S1', environment_id: ENVIRONMENT,
        action_sequence: '2', operation_id: 'synthetic-owner-operation', payload_hash: transferCommandHash, action_kind: 'transfer',
        command_json: transfer, receipt_revision: 1, receipt_status: 'observed', evidence_hash: packet.ownerActions[1].actionEvidence.sha256,
        evidence_path: packet.ownerActions[1].actionEvidence.path, transaction_hash: packet.ownerActions[1].transactionHash,
        history_revision: 1, history_status: 'observed', history_evidence_hash: packet.ownerActions[1].actionEvidence.sha256,
        history_evidence_path: packet.ownerActions[1].actionEvidence.path, history_transaction_hash: packet.ownerActions[1].transactionHash },
    ];
    const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
      async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
    }, evidenceRoot: root });
    const readPacket = source as unknown as { readS1CapturePacketChildren(bytes: Buffer, bundle: unknown, tx: unknown, row: unknown): Promise<unknown> };
    const tx = { async execute() { return durableRows; } };
    const parsed = await readPacket.readS1CapturePacketChildren(Buffer.from(JSON.stringify(packet)), bundle, tx, row);
    assert.equal((parsed as { actions: Array<{ command: { kind: string } }> }).actions[0]?.command.kind, 'inspect_catalog');

    const effectful = structuredClone(packet);
    effectful.bef.after.operations[0].transaction_hash = `0x${'9'.repeat(64)}`;
    await assert.rejects(readPacket.readS1CapturePacketChildren(Buffer.from(JSON.stringify(effectful)), bundle, tx, row),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  });
});

test('sealed S1 read verification accepts producer health metadata and rejects identity or optional-shape drift', () => {
  const actionId = '81000000-0000-4000-8000-000000000028';
  const ownerOperationId = '82000000-0000-4000-8000-000000000028';
  const operationId = '83000000-0000-4000-8000-000000000028';
  const command = { kind: 'inspect_catalog' as const };
  const commandSha256 = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command });
  const rawResponseSha256 = HASH('s1-sealed-health-response');
  const payment = { scheme: 'exact', network: 'eip155:8453', asset: S2_ASSET, amount: '125000',
    payTo: S2_RECIPIENT, transferMethod: 'eip3009' };
  const response = { operationId, readHandle: { kind: 'catalog', operationId }, freeInspection: true, deliveryState: 'not_delivered',
    catalog: [{ resourceId: 'resource-a', resourceSha256: HASH('resource-a'), contentType: 'application/json', offers: [{ id: 'standard', payment }] }] };
  const environmentHealth = { boundary: 'benchmark-environment-api', envId: ENVIRONMENT, manifestSha256: ENV_MANIFEST_HASH,
    applicationSourceSha256: SOURCE_HASH, facilitatorAddress: S2_RECIPIENT,
    anvil: { clientVersion: 'anvil/v1.2.3', chainId: '8453', executionNetwork: 'base', hardFork: 'cancun',
      forkBlockNumber: '100', forkBlockHash: `0x${'a'.repeat(64)}` },
    sdkVersions: { core: '2.28.0', evm: '2.28.0', viem: '2.56.9' } };
  const row = { run_id: RUN, task_index: 0, environment_id: ENVIRONMENT, generation_id: GENERATION,
    environment_manifest_hash: ENV_MANIFEST_HASH, application_source_hash: SOURCE_HASH };
  const operation = { operation_id: operationId, operation_kind: 'catalog', status: 'accepted', receipt_status: 'not_submitted',
    transaction_hash: null, response_sha256: rawResponseSha256, request_sha256: HASH(JSON.stringify({ method: 'GET', path: '/catalog' })) };
  const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
    async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
  }, evidenceRoot: process.cwd() });
  const validate = source as unknown as { validateSealedInspectionAction(bytes: Buffer, reference: EvidenceReference,
    proof: unknown, row: unknown, taskId: 'S1'): void };
  const invoke = (health: unknown) => {
    const document = { schema: 'bef-task-action-observation-v1', actionId, runId: RUN, taskIndex: 0, actionSequence: '1',
      ownerOperationId, actionKind: 'inspect_catalog', commandSha256, environmentId: ENVIRONMENT, generationId: GENERATION,
      manifestSha256: ENV_MANIFEST_HASH, applicationSourceSha256: SOURCE_HASH, idempotencyKey: `task-action-${actionId}`,
      status: 'observed', requestStartedAt: '2026-10-30T00:00:00.000Z', requestFinishedAt: '2026-10-30T00:00:01.000Z',
      httpStatus: 200, befOperationId: operationId, rawResponseSha256, participantToolResponse: response, environmentHealth: health };
    const bytes = Buffer.from(JSON.stringify(document));
    const reference: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/s1-health.json`,
      sha256: createHash('sha256').update(bytes).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
    const action = { actionId, actionSequence: 1, ownerOperationId, actionKind: 'inspect_catalog', commandSha256,
      actionEvidence: reference, befOperationId: operationId };
    validate.validateSealedInspectionAction(bytes, reference, { action, command, operation }, row, 'S1');
  };

  assert.doesNotThrow(() => invoke(environmentHealth));
  assert.throws(() => invoke({ ...environmentHealth, envId: 'foreign-environment' }),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  assert.throws(() => invoke({ ...environmentHealth,
    sdkVersions: { ...environmentHealth.sdkVersions, unsupported: 'unexpected' } }),
  (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
});

test('S4 sealed source retains a catalog prefix before a mutable approval', async () => {
  const participantId = '90000000-0000-4000-8000-000000000009';
  const fixtureOperationId = '90000000-0000-4000-8000-000000000010';
  const readOperationId = '90000000-0000-4000-8000-000000000011';
  const approveOperationId = '90000000-0000-4000-8000-000000000012';
  const readActionId = '90000000-0000-4000-8000-000000000013';
  const approveActionId = '90000000-0000-4000-8000-000000000014';
  const readOwnerOperationId = '90000000-0000-4000-8000-000000000015';
  const approveOwnerOperationId = '90000000-0000-4000-8000-000000000016';
  const fixtureTx = `0x${'1'.repeat(64)}`;
  const approveTx = `0x${'2'.repeat(64)}`;
  const fixtureBlock = `0x${'3'.repeat(64)}`;
  const baselineBlock = `0x${'4'.repeat(64)}`;
  const approveBlock = `0x${'5'.repeat(64)}`;
  const fixtureParent = `0x${'6'.repeat(64)}`;
  const payer = S2_RECIPIENT;
  const token = S2_ASSET;
  const router = '0x0000000000000000000000000000000000000003';
  const approveAmount = '50';
  const requestHash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const approveCommand = { kind: 'approve' as const, tokenAssetId: 'USDC', amountUnits: approveAmount, gasLimit: '100000' };
  const readCommand = { kind: 'inspect_catalog' as const };
  const readCommandSha = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command: readCommand });
  const approveCommandSha = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command: approveCommand });
  const readEvidence: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/s4-catalog-read.json`,
    sha256: HASH('s4-catalog-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  const approveEvidence: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/s4-approve.json`,
    sha256: HASH('s4-approve-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  const readResponseHash = HASH('s4-catalog-response');
  const mutableSelected = { kind: 'approve', tokenAssetId: 'USDC', spender: router, amountUnits: approveAmount, gasLimit: '100000' };
  const fixtureSelected = { kind: 'approve', tokenAssetId: 'USDC', spender: router, amountUnits: '25', gasLimit: '100000' };
  const prestate = { balances: [], allowances: [] };
  const intent = (tx: string, block: string, blockNumber: string, nonce: string) => ({ hash: tx, type: 'eip1559', chainId: 8453,
    blockHash: block, blockNumber, transactionIndex: '0', from: payer, to: token, nonce, input: '0x095ea7b3', valueWei: '0',
    gasLimit: '100000', maxFeePerGasWei: '3', maxPriorityFeePerGasWei: '1' });
  const fixtureIntent = intent(fixtureTx, fixtureBlock, '9', '4');
  const approveIntent = intent(approveTx, approveBlock, '11', '7');
  const event = (operationId: string, kind: string, sequence: number, transactionHash: string | null, eventPayload: unknown) => ({
    eventId: `90000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`, eventSequence: String(sequence), operationId,
    eventKind: kind, transactionHash, eventJsonSha256: HASH(`s4-event-${sequence}`), eventPayload,
  });
  const operation = (operationId: string, idempotencyKey: string, requestSha: string, kind: string, tx: string,
    startedAt: string, completedAt: string) => ({ operation_id: operationId, env_id: ENVIRONMENT, generation_id: GENERATION,
    participant_id: participantId, idempotency_key_sha256: HASH(idempotencyKey), request_sha256: requestSha, operation_kind: kind,
    status: 'settled', receipt_status: 'success', transaction_hash: tx, response_sha256: null, started_at: startedAt, completed_at: completedAt });
  const fixtureOperation = operation(fixtureOperationId, 'fixture-operation', HASH('fixture-request'), 'approve', fixtureTx,
    '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:01.000Z');
  const readOperation = { operation_id: readOperationId, env_id: ENVIRONMENT, generation_id: GENERATION, participant_id: participantId,
    idempotency_key_sha256: HASH(`task-action-${readActionId}`), request_sha256: requestHash({ method: 'GET', path: '/catalog' }),
    operation_kind: 'catalog', status: 'accepted', receipt_status: 'not_submitted', transaction_hash: null,
    response_sha256: readResponseHash, started_at: '2026-01-01T00:00:02.000Z', completed_at: '2026-01-01T00:00:03.000Z' };
  const approveOperation = operation(approveOperationId, `task-action-${approveActionId}`,
    requestHash({ method: 'POST', path: '/approve', command: approveCommand }), 'approve', approveTx,
    '2026-01-01T00:00:04.000Z', '2026-01-01T00:00:05.000Z');
  const mutableCost = (operationId: string, tx: string, blockNumber: string, blockHash: string, parentHash: string,
    price: string, createdAt: string) => ({ operation_id: operationId, env_id: ENVIRONMENT, generation_id: GENERATION,
    transaction_hash: tx, payer_address: payer, payer_role: 'participant', receipt_status: 'success', transaction_from: payer,
    receipt_from: payer, receipt_block_number: blockNumber, receipt_block_hash: blockHash, receipt_block_parent_hash: parentHash,
    gas_used: '10', effective_gas_price_wei: price, gas_cost_wei: String(BigInt(10) * BigInt(price)), modeled_gas_fee_usdc_units: '0',
    manifest_sha256: ENV_MANIFEST_HASH, selected_principal_asset: null, selected_principal_units: null,
    observed_principal_units: null, created_at: createdAt });
  const fixtureCost = mutableCost(fixtureOperationId, fixtureTx, '9', fixtureBlock, fixtureParent, '2', '2026-01-01T00:00:01.000Z');
  const approveCost = mutableCost(approveOperationId, approveTx, '11', approveBlock, baselineBlock, '3', '2026-01-01T00:00:05.000Z');
  const fixtureExec = { operation_id: fixtureOperationId, env_id: ENVIRONMENT, generation_id: GENERATION, action_kind: 'approve',
    selected_action: fixtureSelected, prestate, transaction_intent: fixtureIntent, measurement: { measurementSha256: HASH('fixture-measurement') },
    transaction_hash: fixtureTx, outcome: 'success', reason_code: null, completed_at: '2026-01-01T00:00:01.000Z' };
  const approveExec = { operation_id: approveOperationId, env_id: ENVIRONMENT, generation_id: GENERATION, action_kind: 'approve',
    selected_action: mutableSelected, prestate, transaction_intent: approveIntent, measurement: { measurementSha256: HASH('approve-measurement') },
    transaction_hash: approveTx, outcome: 'success', reason_code: null, completed_at: '2026-01-01T00:00:05.000Z' };
  const events = [
    event(fixtureOperationId, 'selected_action_bound', 1, null, { actionKind: 'approve', requestSha256: fixtureOperation.request_sha256, selectedAction: fixtureSelected }),
    event(fixtureOperationId, 'prestate_observed', 2, null, { prestate }),
    event(fixtureOperationId, 'original_tx_hash_bound', 3, fixtureTx, { requestSha256: fixtureOperation.request_sha256, transactionHash: fixtureTx, transactionIntent: fixtureIntent }),
    event(fixtureOperationId, 'receipt_finalized', 4, fixtureTx, { outcome: 'success', measurementSha256: HASH('fixture-measurement') }),
    event(approveOperationId, 'selected_action_bound', 5, null, { actionKind: 'approve', requestSha256: approveOperation.request_sha256, selectedAction: mutableSelected }),
    event(approveOperationId, 'prestate_observed', 6, null, { prestate }),
    event(approveOperationId, 'original_tx_hash_bound', 7, approveTx, { requestSha256: approveOperation.request_sha256, transactionHash: approveTx, transactionIntent: approveIntent }),
    event(approveOperationId, 'receipt_finalized', 8, approveTx, { outcome: 'success', measurementSha256: HASH('approve-measurement') }),
  ];
  const generation = { generation_id: GENERATION, env_id: ENVIRONMENT, participant_id: participantId, payer_address: payer,
    manifest_sha256: ENV_MANIFEST_HASH, status: 'active', chain_id: '8453', environment_manifest_sha256: ENV_MANIFEST_HASH };
  const census = { generation, operations: [fixtureOperation, readOperation, approveOperation],
    selectedExecutions: [fixtureExec, approveExec], selectedEvents: events, costs: [fixtureCost, approveCost],
    paymentsCount: '0', deliveriesCount: '0', counts: { operations: '3', selectedExecutions: '2', selectedEvents: '8', costs: '2' } };
  const binding = { ownerId: OWNER, agentId: AGENT, runId: RUN, environmentId: ENVIRONMENT, releaseIdentity: RELEASE_ID,
    manifestHash: MANIFEST_HASH, caseId: 's4-sealed-case', caseHash: HASH('s4-case'), rubricHash: HASH('s4-rubric'), taskId: 'S4' };
  const closure = { closureId: CLOSURE, operationId: null, payloadHash: HASH('s4-closure'), reason: 'agent_finish',
    actionCutoffSequence: 2, reconciledActionSequence: 2 };
  const execution = { preparationId: PREPARATION, leaseId: LEASE, generationId: GENERATION, environmentManifestHash: ENV_MANIFEST_HASH,
    applicationSourceHash: SOURCE_HASH, executionIdentityHash: EXECUTION_HASH, initialStateSha256: INITIAL_STATE_HASH };
  const preparation = { fixtureEvidence: { path: `${COORDINATOR_EVIDENCE_ROOT}preparation/s4-fixture.json`, sha256: HASH('fixture-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' },
    baselineEvidence: { path: `${COORDINATOR_EVIDENCE_ROOT}preparation/s4-baseline.json`, sha256: HASH('baseline-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' },
    baselineBlockNumber: '10', baselineBlockHash: baselineBlock, fixtureOperationId, fixtureTransactionHash: fixtureTx,
    fixtureBlockNumber: '9', fixtureBlockHash: fixtureBlock, fixtureProofSha256: HASH('fixture-proof') };
  const baselineBalances = [{ account: 'participant', assetId: 'ETH', amountUnits: '1000000' }, { account: 'participant', assetId: 'USDC', amountUnits: '1000' }];
  const finalBalances = [{ account: 'participant', assetId: 'ETH', amountUnits: '999970' }, { account: 'participant', assetId: 'USDC', amountUnits: '1000' }];
  const baselineAllowances = [{ owner: 'participant', tokenAssetId: 'USDC', spender: router, amountUnits: '0' }];
  const finalAllowances = [{ owner: 'participant', tokenAssetId: 'USDC', spender: router, amountUnits: approveAmount }];
  const rpc = { localChainId: '8453', baseline: { blockNumber: '10', blockHash: baselineBlock, parentHash: fixtureParent,
      balances: baselineBalances, allowances: baselineAllowances, participantTransactionCount: '7' },
    final: { blockNumber: '11', blockHash: approveBlock, parentHash: baselineBlock, balances: finalBalances,
      allowances: finalAllowances, participantTransactionCount: '8' },
    intervalBlocks: [{ number: '11', hash: approveBlock, parentHash: baselineBlock, transactionCount: 1,
      participantTransactions: [{ hash: approveTx, from: payer, to: token, nonce: '7', input: '0x095ea7b3', valueWei: '0', gasLimit: '100000',
        blockNumber: '11', blockHash: approveBlock, transactionIndex: '0', chainId: '8453' }] }],
    approvals: [{ tokenAddress: token, owner: payer, spender: router, amountUnits: approveAmount, transactionHash: approveTx,
      blockNumber: '11', blockHash: approveBlock, transactionIndex: '0', logIndex: '0' }], transfers: [],
    receipts: [{ transactionHash: approveTx, from: payer, to: token, blockNumber: '11', blockHash: approveBlock, transactionIndex: '0',
      status: 'success', gasUsed: '10', effectiveGasPriceWei: '3', gasCostWei: '30', logsSha256: HASH('approve-logs') }], responseHashes: [] };
  const packet = { schemaVersion: 'bts-s4-run-observation-capture/v1', classification: 'run_bound_observations_candidate_not_grade',
    binding, closure: { closureId: CLOSURE, actionCutoffSequence: 2, reconciledActionSequence: 2 },
    execution: { ...execution, environmentId: ENVIRONMENT }, preparation,
    ownerActions: [
      { actionId: readActionId, actionSequence: 1, ownerOperationId: readOwnerOperationId, actionKind: 'inspect_catalog',
        commandSha256: readCommandSha, actionEvidence: readEvidence, befOperationId: readOperationId, transactionHash: null },
      { actionId: approveActionId, actionSequence: 2, ownerOperationId: approveOwnerOperationId, actionKind: 'approve',
        commandSha256: approveCommandSha, actionEvidence: approveEvidence, befOperationId: approveOperationId, transactionHash: approveTx },
    ], bef: { session: { currentUser: 'bef_observer', sessionUser: 'bef_observer', transactionReadOnly: 'on',
        transactionIsolation: 'repeatable read', superuser: false, bypassRls: false }, before: census, after: structuredClone(census),
      censusSha256: createHash('sha256').update(canonicalTaskJson(census)).digest('hex') }, rpc };
  const packetBytes = Buffer.from(canonicalTaskJson(packet));
  const captureEvidence = { path: `${COORDINATOR_EVIDENCE_ROOT}observation/s4-sealed-packet.json`,
    sha256: createHash('sha256').update(packetBytes).digest('hex'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  const meta = (sequence: number, actionSequence: number, observationId: string) => ({ observationId, sequence, actionSequence,
    source: 'persisted_observer', binding, evidence: captureEvidence });
  const observations = { schemaVersion: 'bts-task-observations/v1', binding, coveredThroughSequence: 3, captureEvidence,
    coverage: { transfers: 'complete', payments: 'complete', stateMutations: 'complete', balances: 'complete', allowances: 'complete',
      answers: 'complete', selections: 'complete', deliveries: 'complete', trades: 'complete', conversions: 'complete', expenses: 'complete' },
    transfers: [], payments: [], stateMutations: [],
    finalStates: [{ kind: 'final_state', ...meta(3, 2, 's4-final'), balances: finalBalances, allowances: finalAllowances }],
    allowanceChanges: [{ kind: 'allowance_change', ...meta(1, 2, 's4-allowance'), owner: 'participant', tokenAssetId: 'USDC',
      spender: router, amountBeforeUnits: '0', amountAfterUnits: approveAmount, transactionHash: approveTx }],
    allowanceUses: [], answers: [], selections: [], deliveries: [], trades: [], conversions: [],
    expenses: [{ kind: 'expense', ...meta(2, 2, 's4-gas'), component: 'participant_gas', sourceEffectId: `bef-operation:${approveOperationId}`,
      gasUsed: '10', effectiveGasPriceWei: '3', receiptStatus: 'success', transactionHash: approveTx }] };
  const bundle = { binding, closure, execution, observations };
  const actionRows = [
    { id: readActionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S4', environment_id: ENVIRONMENT,
      action_sequence: '1', operation_id: readOwnerOperationId, payload_hash: readCommandSha, action_kind: 'inspect_catalog', command_json: readCommand,
      receipt_revision: 1, receipt_status: 'observed', evidence_hash: readEvidence.sha256, evidence_path: readEvidence.path, transaction_hash: null,
      history_revision: 1, history_status: 'observed', history_evidence_hash: readEvidence.sha256, history_evidence_path: readEvidence.path,
      history_transaction_hash: null },
    { id: approveActionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S4', environment_id: ENVIRONMENT,
      action_sequence: '2', operation_id: approveOwnerOperationId, payload_hash: approveCommandSha, action_kind: 'approve', command_json: approveCommand,
      receipt_revision: 1, receipt_status: 'observed', evidence_hash: approveEvidence.sha256, evidence_path: approveEvidence.path, transaction_hash: approveTx,
      history_revision: 1, history_status: 'observed', history_evidence_hash: approveEvidence.sha256, history_evidence_path: approveEvidence.path,
      history_transaction_hash: approveTx },
  ];
  const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
    async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
  }, evidenceRoot: process.cwd() });
  const tx = { async execute() { return actionRows; } };
  const parseS4 = source as unknown as { readS4CapturePacketChildren(bytes: Buffer, bundle: unknown, tx: unknown, row: unknown): Promise<unknown> };
  const parsed = await parseS4.readS4CapturePacketChildren(packetBytes, bundle, tx, { run_id: RUN, task_index: 0, owner_id: OWNER,
    agent_id: AGENT, task_id: 'S4', environment_id: ENVIRONMENT, generation_id: GENERATION,
    environment_manifest_hash: ENV_MANIFEST_HASH, application_source_hash: SOURCE_HASH, action_cutoff_sequence: '2' });
  assert.equal((parsed as { actions: Array<{ action: { actionKind: string } }> }).actions.length, 1);
  assert.equal((parsed as { actions: Array<{ action: { actionKind: string } }> }).actions[0]?.action.actionKind, 'inspect_catalog');
});

test('sealed source rejects changed raw bytes even when the DB bundle hash is valid', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    await writeFile(resolve(root, ...fixture.bundle.cutoff.evidence.path.split('/')), '{"changed":true}\n');
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_HASH_MISMATCH');
  });
});

test('sealed source rehashes the database bundle JSON before reading raw files', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.bundle.observations.coverage.transfers = 'complete';
    fixture.row.bundle_json = fixture.bundle;
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_BUNDLE_HASH_MISMATCH');
  });
});

test('sealed source rejects a changed nested owner-action evidence file', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    const actionPath = [...fixture.files.keys()].find((path) => path.includes('/action/'))!;
    await writeFile(resolve(root, ...actionPath.split('/')), '{"changed":true}\n');
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_HASH_MISMATCH');
  });
});

test('sealed source rejects a missing nested preparation evidence file', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    const preparationPath = [...fixture.files.keys()].find((path) => path.endsWith('/preparation/fixture.json'))!;
    await rm(resolve(root, ...preparationPath.split('/')));
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_UNAVAILABLE');
  });
});

test('sealed source rejects conflicting hashes for one retained path', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.bundle.observations.transfers.push({
      ...fixture.bundle.observations.transfers[0], observationId: 'second-transfer',
      evidence: { ...fixture.bundle.observations.transfers[0].evidence, sha256: HASH('conflicting') },
    });
    fixture.row.bundle_json = fixture.bundle;
    fixture.row.bundle_hash = sha256CanonicalTaskJson(fixture.bundle);
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_REFERENCE_CONFLICT');
  });
});

test('sealed source rejects a symlink that resolves outside the private evidence root', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    const captureRef = fixture.bundle.cutoff.evidence;
    const capturePath = resolve(root, ...captureRef.path.split('/'));
    const external = join(dirname(root), 'outside-capture.json');
    const bytes = fixture.files.get(captureRef.path)!;
    await writeFile(external, bytes, { flag: 'wx' });
    await rm(capturePath);
    await symlink(external, capturePath);
    const sourceBundle = makeSource(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_PATH_ESCAPE');
  });
});

test('sealed source enforces per-file evidence bounds', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    const source = new TaskSealedEvidenceSource({
      taskReleaseSource: {
        async getActiveAdmissionRelease() { return null; },
        async getValidatedReleaseRecord(identity, digest) {
          return identity === RELEASE_ID && digest === MANIFEST_HASH ? fixture.record : null;
        },
      }, evidenceRoot: root, maxEvidenceFileBytes: 4, maxEvidenceTotalBytes: 64,
    });
    const transaction = { async execute() { return [fixture.row]; } };
    await assert.rejects(source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_SIZE_INVALID');
  });
});

test('sealed source rejects a preparation or execution generation that differs from the sealed task binding', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.row.prepared_environment_id = 'synthetic-wrong-env';
    const source = makeSource(fixture);
    await assert.rejects(source.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, source.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_EXECUTION_MISMATCH');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.row.execution_generation_id = '70000000-0000-4000-8000-000000000099';
    const source = makeSource(fixture);
    await assert.rejects(source.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, source.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_EXECUTION_MISMATCH');
  });
});

test('sealed source rejects a rehashed bundle with a foreign task environment or task identity', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.bundle.binding.environmentId = 'synthetic-foreign-env';
    fixture.row.bundle_json = fixture.bundle;
    fixture.row.bundle_hash = sha256CanonicalTaskJson(fixture.bundle);
    const source = makeSource(fixture);
    await assert.rejects(source.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, source.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_BINDING_MISMATCH');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.bundle.binding.taskId = 'S2';
    fixture.row.bundle_json = fixture.bundle;
    fixture.row.bundle_hash = sha256CanonicalTaskJson(fixture.bundle);
    const source = makeSource(fixture);
    await assert.rejects(source.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, source.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_BINDING_MISMATCH');
  });
});

test('sealed source routes M1 through immutable release validation', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeFixture(root);
    fixture.row.task_id = 'M1';
    let releaseReads = 0;
    const taskReleaseSource: TaskReleaseQuerySource = {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord() { releaseReads += 1; return fixture.record; },
    };
    const source = new TaskSealedEvidenceSource({ taskReleaseSource, evidenceRoot: root });
    const result = await source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, {
      async execute() { return [fixture.row]; },
    } as never);
    assert.equal(result, null);
    assert.equal(releaseReads, 1, 'M1 is admitted to the release/case validation path');
  });
});

test('sealed source accepts zero-action S2 with no answer, preserves coverage, and loads fenced history in one transaction', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root);
    const sourceBundle = makeS2Source(fixture);
    const result = await sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never);
    assert.ok(result);
    assert.equal(result.taskCase.taskId, 'S2');
    assert.equal(result.run.cutoffStatus, 'authoritative');
    assert.deepEqual(result.observations.coverage, fixture.bundle.observations.coverage);
    assert.equal(result.observations.answers.length, 0);
    assert.equal(sourceBundle.queryCount(), 2, 'the owner action join runs in the caller transaction');
  });
});

test('sealed source validates an S2 free offer handle, owner action row, and immutable finish answer', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { action: true, answer: true });
    const sourceBundle = makeS2Source(fixture);
    const result = await sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never);
    assert.ok(result);
    assert.equal(result.observations.answers.length, 1);
    assert.deepEqual(result.observations.answers[0]?.answer, fixture.row.closure_answer_json);
    assert.equal(sourceBundle.queryCount(), 2);
  });
});

test('sealed S2 accepts checksum address casing and rejects a foreign payTo address', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { action: true, payTo: S2_CHECKSUM_RECIPIENT });
    const sourceBundle = makeS2Source(fixture);
    const result = await sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never);
    assert.ok(result);
    assert.equal(result.observations.coverage.transfers, 'complete');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { action: true, payTo: S2_FOREIGN_RECIPIENT });
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  });
});

test('sealed S2 preserves incomplete coverage instead of upgrading it', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { coverage: { answers: 'incomplete', balances: 'contradictory' } });
    fixture.bundle.observations.coverage = { answers: 'incomplete', balances: 'contradictory' };
    fixture.row.bundle_json = fixture.bundle;
    fixture.row.bundle_hash = sha256CanonicalTaskJson(fixture.bundle);
    const sourceBundle = makeS2Source(fixture);
    const result = await sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never);
    assert.ok(result);
    assert.deepEqual(result.observations.coverage, { answers: 'incomplete', balances: 'contradictory' });
  });
});

test('sealed S2 rejects a closure answer that differs from immutable PostgreSQL', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { answer: true });
    fixture.row.closure_answer_json = { amountUnits: '999', network: 'eip155:8453', resourceId: 'market-brief', offerId: 'standard' };
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH');
  });
});

test('sealed S2 rejects a foreign task, environment, or generation binding', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root);
    fixture.bundle.binding.taskId = 'S1';
    fixture.row.bundle_json = fixture.bundle;
    fixture.row.bundle_hash = sha256CanonicalTaskJson(fixture.bundle);
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_BINDING_MISMATCH');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root);
    fixture.row.prepared_environment_id = 'synthetic-foreign-env';
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_EXECUTION_MISMATCH');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root);
    fixture.row.execution_generation_id = '70000000-0000-4000-8000-000000000099';
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_EXECUTION_MISMATCH');
  });
});

test('sealed S2 rejects tampered or missing action evidence children', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { action: true });
    const actionPath = fixture.bundle.observations.captureEvidence.path.replace('/observation/', '/action/').replace('s2-capture', 's2-inspect');
    await writeFile(resolve(root, ...actionPath.split('/')), '{"tampered":true}\n');
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_HASH_MISMATCH');
  });
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root, { action: true });
    const actionPath = fixture.actionRows[0]!.evidence_path as string;
    await rm(resolve(root, ...actionPath.split('/')));
    const sourceBundle = makeS2Source(fixture);
    await assert.rejects(sourceBundle.source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, sourceBundle.transaction as never),
      (error: { code?: string }) => error.code === 'TASK_EVIDENCE_FILE_UNAVAILABLE');
  });
});

test('sealed source routes M1 through release validation and resolves newly supported IDs against the release', async () => {
  await withPrivateRoot(async (root) => {
    const fixture = await makeS2Fixture(root);
    fixture.row.task_id = 'M1';
    fixture.row.task_ids = ['M1'];
    let releaseReads = 0;
    const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
      async getActiveAdmissionRelease() { return null; },
      async getValidatedReleaseRecord() { releaseReads += 1; return fixture.record; },
    }, evidenceRoot: root });
    const result = await source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, { async execute() { return [fixture.row]; } } as never);
    assert.equal(result, null);
    assert.equal(releaseReads, 1, 'M1 is admitted to the release/case validation path');

    fixture.row.task_id = 'S3';
    fixture.row.task_ids = ['S3'];
    const unsupportedResult = await source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE },
      { async execute() { return [fixture.row]; } } as never);
    assert.equal(unsupportedResult, null);
    assert.equal(releaseReads, 2, 'newly supported task IDs reach release validation and remain unavailable without an admitted case');
  });
});

test('sealed M1 reader accepts string action sequences and an explicitly known no-request rejection', () => {
  const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
    async getActiveAdmissionRelease() { return null; },
    async getValidatedReleaseRecord() { return null; },
  }, evidenceRoot: process.cwd() });
  const reference: EvidenceReference = {
    path: `${COORDINATOR_EVIDENCE_ROOT}action/m1-rejected-action.json`, sha256: HASH('m1-action-child'),
    boundary: 'actual_tool_http_x402_local_evm_application_store',
  };
  const actionId = '80000000-0000-4000-8000-000000000008';
  const protocol = {
    schema: 'bef-x402-split-payment-observation-v1', resourceId: 'market-brief', offerId: 'standard',
    resourceSha256: HASH('resource'), amountUnits: '200000', network: 'eip155:8453', asset: S2_ASSET,
    readHandle: { kind: 'offer', operationId: '90000000-0000-4000-8000-000000000009' },
    acceptedTerms: { scheme: 'exact', network: 'eip155:8453', asset: S2_ASSET, amount: '200000',
      payTo: S2_RECIPIENT, transferMethod: 'eip3009' },
  };
  const action = {
    actionId, actionSequence: 1, ownerOperationId: 'synthetic-m1-owner-operation', actionKind: 'pay',
    commandSha256: HASH('m1-command'), receiptStatus: 'rejected_before_execution', actionEvidence: reference,
    befOperationId: null, transactionHash: null, rawResponseSha256: null, participantToolResponse: null, paymentProtocol: protocol,
  } as unknown as M1CaptureAction;
  const bundle = { binding: { environmentId: ENVIRONMENT }, execution: {
    generationId: GENERATION, environmentManifestHash: ENV_MANIFEST_HASH, applicationSourceHash: SOURCE_HASH,
  } };
  const row = { run_id: RUN, task_index: 0 };
  const evidence = (reasonCode: string, extra: Record<string, unknown> = {}) => Buffer.from(JSON.stringify({
    schema: 'bef-task-action-observation-v1', actionId, runId: RUN, taskIndex: 0, actionSequence: '1',
    ownerOperationId: action.ownerOperationId, actionKind: action.actionKind, commandSha256: action.commandSha256,
    environmentId: ENVIRONMENT, generationId: GENERATION, manifestSha256: ENV_MANIFEST_HASH,
    applicationSourceSha256: SOURCE_HASH, idempotencyKey: `task-action-${actionId}`, status: action.receiptStatus,
    reasonCode, paymentProtocol: action.paymentProtocol, ...extra,
  }));
  const validate = (bytes: Buffer) => (source as unknown as { validateM1ActionEvidence: (
    bytes: Buffer, reference: EvidenceReference, action: M1CaptureAction,
    bundle: { binding: Record<string, unknown>; execution: Record<string, unknown> }, row: { run_id: string; task_index: number },
  ) => Record<string, unknown> }).validateM1ActionEvidence.call(source, bytes, reference, action, bundle, row);

  assert.equal(validate(evidence('task_split_pay_pinned_context_unavailable')).actionSequence, '1');
  assert.throws(() => validate(evidence('task_split_pay_challenge_unavailable')), (error: { code?: string }) =>
    error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  assert.throws(() => validate(evidence('task_split_pay_pinned_context_unavailable', { rawResponseSha256: HASH('unexpected-response') })),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');

  const operationId = '90000000-0000-4000-8000-000000000010';
  const challengeHash = HASH('challenge-response');
  action.befOperationId = operationId;
  action.rawResponseSha256 = challengeHash;
  action.paymentProtocol = { ...protocol, befOperationId: operationId, challengeResponseSha256: challengeHash,
    challengeHeaderSha256: HASH('challenge-header') };
  assert.equal(validate(evidence('task_split_pay_challenge_scope_mismatch', {
    httpStatus: 402, befOperationId: operationId, rawResponseSha256: challengeHash,
  })).actionSequence, '1');
});

test('paid sealed replay binds owner command, durable receipt history, actual response and BEF request hash', async () => {
  const actionId = '81000000-0000-4000-8000-000000000008';
  const ownerOperationId = '82000000-0000-4000-8000-000000000008';
  const befOperationId = '83000000-0000-4000-8000-000000000008';
  const participantId = '84000000-0000-4000-8000-000000000008';
  const command = { kind: 'inspect_offer' as const, resourceId: 'resource-market-snapshot', offerId: 'stream' };
  const commandSha256 = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command });
  const responseHash = HASH('paid-owner-raw-response');
  const payment = { scheme: 'exact', network: 'eip155:8453', asset: S2_ASSET, amount: '125000',
    payTo: S2_RECIPIENT, transferMethod: 'eip3009' };
  const response = { operationId: befOperationId, readHandle: { kind: 'offer', operationId: befOperationId },
    freeInspection: true, deliveryState: 'not_delivered', resourceId: command.resourceId, resourceSha256: HASH('resource'),
    contentType: 'application/json', payment, offers: [{ id: 'stream', payment }] };
  const requestHash = HASH(JSON.stringify({ method: 'GET', path: '/offer', resourceId: command.resourceId }));
  const actionEvidence: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/paid-owner-read.json`,
    sha256: HASH('paid-owner-action-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  const action = { actionId, actionSequence: 1, ownerOperationId, actionKind: 'inspect_offer', commandSha256,
    receiptStatus: 'observed', actionEvidence, befOperationId, transactionHash: null, rawResponseSha256: responseHash,
    safeResponse: {}, paymentProtocol: null, retrievedContent: null };
  const actionEvidenceValue = { schema: 'bef-task-action-observation-v1', actionId, runId: RUN, taskIndex: 0, actionSequence: '1',
    ownerOperationId, actionKind: 'inspect_offer', commandSha256, environmentId: ENVIRONMENT, generationId: GENERATION,
    manifestSha256: ENV_MANIFEST_HASH, applicationSourceSha256: SOURCE_HASH, idempotencyKey: `task-action-${actionId}`,
    status: 'observed', befOperationId, transactionHash: null, rawResponseSha256: responseHash, participantToolResponse: response,
    paymentProtocol: null };
  const censusOperation = { operation_id: befOperationId, env_id: ENVIRONMENT, generation_id: GENERATION, participant_id: participantId,
    idempotency_key_sha256: createHash('sha256').update(`task-action-${actionId}`).digest('hex'), request_sha256: requestHash,
    operation_kind: 'offer', status: 'accepted', receipt_status: 'not_submitted', transaction_hash: null, response_sha256: responseHash };
  const packet = { ownerActions: [action], bef: { after: { generation: { participant_id: participantId }, operations: [censusOperation], payments: [], deliveries: [] } } };
  const row: Record<string, unknown> = { run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'H1',
    environment_id: ENVIRONMENT, generation_id: GENERATION, environment_manifest_hash: ENV_MANIFEST_HASH,
    application_source_hash: SOURCE_HASH, action_cutoff_sequence: '1' };
  const dbAction = { id: actionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'H1', environment_id: ENVIRONMENT,
    action_sequence: '1', operation_id: ownerOperationId, payload_hash: commandSha256, action_kind: 'inspect_offer', command_json: command,
    receipt_revision: 1, receipt_status: 'observed', evidence_hash: actionEvidence.sha256, evidence_path: actionEvidence.path, transaction_hash: null,
    tool_response_json: response, tool_response_hash: sha256CanonicalTaskJson(response), history_revision: 1, history_status: 'observed',
    history_evidence_hash: actionEvidence.sha256, history_evidence_path: actionEvidence.path, history_transaction_hash: null,
    history_tool_response_json: response, history_tool_response_hash: sha256CanonicalTaskJson(response) };
  const callVerifier = async (candidateRow = row, candidatePacket = packet, candidateDbActions = [dbAction], composite = false) => {
    const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
      async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
    }, evidenceRoot: process.cwd() });
    const tx = { async execute() { return candidateDbActions; } };
    await (source as unknown as { verifyPaidOwnerActions(tx: unknown, row: unknown, packet: unknown,
      evidence: ReadonlyMap<string, Record<string, unknown>>, composite: boolean): Promise<void> })
      .verifyPaidOwnerActions(tx, candidateRow, candidatePacket, new Map([[actionEvidence.path, actionEvidenceValue]]), composite);
  };
  await callVerifier();
  await assert.rejects(callVerifier(row, packet, [{ ...dbAction, history_tool_response_json: { ...response, resourceId: 'tampered-resource' } }]),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier(row, { ...packet, bef: { after: { ...packet.bef.after,
    operations: [{ ...censusOperation, request_sha256: HASH('wrong-request') }] } } }),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier(row, packet, [{ ...dbAction, command_json: { ...command, resourceId: 'tampered-resource' } }]),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier(row, { ...packet, ownerActions: [] }, [dbAction], true),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier({ ...row, action_cutoff_sequence: '2' }),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier(row, packet, [{ ...dbAction, action_sequence: '2' }]),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(callVerifier(row, packet, [{ ...dbAction, tool_response_json: { ...response, resourceId: 'tampered-current-response' } }]),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
});

test('S3 sealed replay binds catalog and offer reads to durable owner receipts and BEF hashes', async () => {
  for (const kind of ['inspect_catalog', 'inspect_offer'] as const) {
  const { packet } = createS3CapturePacketFixture(kind);
  const action = packet.ownerActions[0]!;
  assert.equal(action.receiptStatus, 'observed');
  assert.ok(action.response);
  assert.ok(action.befOperationId);
  const response = action.response!;
  const rawResponseSha256 = packet.bef.before.operations[0]!.response_sha256!;
  const actionEvidenceValue: Record<string, unknown> = {
    schema: 'bef-task-action-observation-v1', actionId: action.actionId, runId: packet.binding.runId, taskIndex: 0, actionSequence: '1',
    ownerOperationId: action.ownerOperationId, actionKind: action.command.kind, commandSha256: action.commandSha256,
    environmentId: packet.binding.environmentId, generationId: packet.execution.generationId,
    manifestSha256: packet.execution.environmentManifestHash, applicationSourceSha256: packet.execution.applicationSourceHash,
    idempotencyKey: `task-action-${action.actionId}`, status: 'observed', httpStatus: 200,
    befOperationId: action.befOperationId, rawResponseSha256, participantToolResponse: response,
  };
  const dbAction: Record<string, unknown> = {
    id: action.actionId, run_id: packet.binding.runId, task_index: 0, owner_id: packet.binding.ownerId, agent_id: packet.binding.agentId, task_id: 'S3',
    environment_id: packet.binding.environmentId, action_sequence: '1', operation_id: action.ownerOperationId,
    payload_hash: action.commandSha256, action_kind: action.command.kind, command_json: action.command,
    receipt_revision: 1, receipt_status: 'observed', evidence_hash: action.actionEvidence.sha256,
    evidence_path: action.actionEvidence.path, transaction_hash: null, tool_response_json: response,
    tool_response_hash: sha256CanonicalTaskJson(response), history_revision: 1, history_status: 'observed',
    history_evidence_hash: action.actionEvidence.sha256, history_evidence_path: action.actionEvidence.path,
    history_transaction_hash: null, history_tool_response_json: response, history_tool_response_hash: sha256CanonicalTaskJson(response),
  };
  const row: Record<string, unknown> = {
    run_id: packet.binding.runId, task_index: 0, owner_id: packet.binding.ownerId, agent_id: packet.binding.agentId, task_id: 'S3', environment_id: packet.binding.environmentId,
    generation_id: packet.execution.generationId, environment_manifest_hash: packet.execution.environmentManifestHash,
    application_source_hash: packet.execution.applicationSourceHash, action_cutoff_sequence: '1',
  };
  const invoke = async (candidatePacket = packet, candidateEvidence = actionEvidenceValue, candidateAction = dbAction) => {
    const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
      async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
    }, evidenceRoot: process.cwd() });
    const tx = { async execute() { return [candidateAction]; } };
    await (source as unknown as { verifyS3OwnerActions(tx: unknown, row: unknown, packet: unknown,
      evidence: ReadonlyMap<string, Record<string, unknown>>): Promise<void> })
      .verifyS3OwnerActions(tx, row, candidatePacket, new Map([[action.actionEvidence.path, candidateEvidence]]));
  };

  await invoke();
  await assert.rejects(invoke(packet, { ...actionEvidenceValue, rawResponseSha256: HASH('different-raw-response') }),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  const changedPublicResponse = structuredClone(packet);
  changedPublicResponse.ownerActions[0]!.response!.freeInspection = false;
  await assert.rejects(invoke(changedPublicResponse),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await assert.rejects(invoke(packet, actionEvidenceValue, { ...dbAction, operation_id: 'different-owner-operation' }),
    (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  }
});

test('sealed chain read binds the complete packet offer command to the durable owner command', async () => {
  const actionId = '85000000-0000-4000-8000-000000000008';
  const ownerOperationId = '86000000-0000-4000-8000-000000000008';
  const befOperationId = '87000000-0000-4000-8000-000000000008';
  const durableCommand = { kind: 'inspect_offer' as const, resourceId: 'resource-market-snapshot', offerId: 'premium' };
  const packetCommand = { ...durableCommand, offerId: 'standard' };
  const commandSha256 = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command: durableCommand });
  const rawResponseSha256 = HASH('chain-owner-read-response');
  const payment = { scheme: 'exact', network: 'eip155:8453', asset: S2_ASSET, amount: '125000',
    payTo: S2_RECIPIENT, transferMethod: 'eip3009' };
  const response = { operationId: befOperationId, readHandle: { kind: 'offer', operationId: befOperationId },
    freeInspection: true, deliveryState: 'not_delivered', resourceId: durableCommand.resourceId, resourceSha256: HASH('resource'),
    contentType: 'application/json', payment, offers: [{ id: 'standard', payment }, { id: 'premium', payment }] };
  const actionEvidence: EvidenceReference = { path: `${COORDINATOR_EVIDENCE_ROOT}action/chain-owner-read.json`,
    sha256: HASH('chain-owner-read-evidence'), boundary: 'actual_tool_http_x402_local_evm_application_store' };
  const packetAction = { actionId, actionSequence: 1, ownerOperationId, actionKind: 'inspect_offer', commandSha256,
    receiptStatus: 'observed', actionEvidence, befOperationId, transactionHash: null,
    inspection: { command: packetCommand, rawResponseSha256 } };
  const evidenceValue = { schema: 'bef-task-action-observation-v1', actionId, runId: RUN, taskIndex: 0, actionSequence: '1',
    ownerOperationId, actionKind: 'inspect_offer', commandSha256, environmentId: ENVIRONMENT, generationId: GENERATION,
    manifestSha256: ENV_MANIFEST_HASH, applicationSourceSha256: SOURCE_HASH, idempotencyKey: `task-action-${actionId}`,
    status: 'observed', befOperationId, rawResponseSha256, participantToolResponse: response };
  const row: Record<string, unknown> = { run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'M3',
    environment_id: ENVIRONMENT, generation_id: GENERATION, environment_manifest_hash: ENV_MANIFEST_HASH,
    application_source_hash: SOURCE_HASH, action_cutoff_sequence: '1' };
  const dbAction = { id: actionId, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'M3', environment_id: ENVIRONMENT,
    action_sequence: '1', operation_id: ownerOperationId, payload_hash: commandSha256, action_kind: 'inspect_offer', command_json: durableCommand,
    receipt_revision: 1, receipt_status: 'observed', evidence_hash: actionEvidence.sha256, evidence_path: actionEvidence.path,
    transaction_hash: null, tool_response_json: response, tool_response_hash: sha256CanonicalTaskJson(response), history_revision: 1,
    history_status: 'observed', history_evidence_hash: actionEvidence.sha256, history_evidence_path: actionEvidence.path,
    history_transaction_hash: null, history_tool_response_json: response, history_tool_response_hash: sha256CanonicalTaskJson(response) };
  const packet = { ownerActions: [], externalActions: [packetAction] };
  const invoke = async (candidatePacket: unknown) => {
    const source = new TaskSealedEvidenceSource({ taskReleaseSource: {
      async getActiveAdmissionRelease() { return null; }, async getValidatedReleaseRecord() { return null; },
    }, evidenceRoot: process.cwd() });
    const tx = { async execute() { return [dbAction]; } };
    await (source as unknown as { verifyChainOwnerActions(tx: unknown, row: unknown, packet: unknown,
      chainEvidence: ReadonlyMap<string, Record<string, unknown>>, paidEvidence: ReadonlyMap<string, Record<string, unknown>>): Promise<void> })
      .verifyChainOwnerActions(tx, row, candidatePacket, new Map([[actionEvidence.path, evidenceValue]]), new Map());
  };

  await assert.rejects(invoke(packet), (error: { code?: string }) => error.code === 'TASK_EVIDENCE_CAPTURE_ACTION_MISMATCH');
  await invoke({ ownerActions: [], externalActions: [{ ...packetAction,
    inspection: { ...packetAction.inspection, command: durableCommand } }] });
});

const pgEnabled = process.env.OID_TASK_SEALED_EVIDENCE_SOURCE_PG_TEST === '1';

test('isolated PostgreSQL source reads original S1 evidence from a fenced generation without nesting transactions', { skip: !pgEnabled }, async () => {
  const databaseUrl = process.env.OID_DATABASE_URL;
  assert.ok(databaseUrl, 'The Docker owner runtime must provide its private local database URL');
  const sourceUrl = new URL(databaseUrl);
  assert.equal(sourceUrl.hostname, 'postgres', 'PostgreSQL proof must run inside the owner-identity Docker network');
  assert.equal(sourceUrl.username, 'oid_owner');
  assert.equal(sourceUrl.pathname, '/owner_identity');
  const databaseName = `oid_evidence_${randomUUID().replaceAll('-', '')}`;
  const admin = postgres(databaseUrl, { max: 1, connect_timeout: 10 });
  const isolatedUrl = new URL(databaseUrl);
  isolatedUrl.pathname = `/${databaseName}`;
  const client = postgres(isolatedUrl.toString(), { max: 2, connect_timeout: 10 });
  const db = drizzle(client) as unknown as OwnerDatabase;
  let databaseCreated = false;
  try {
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);
    databaseCreated = true;
    await withPrivateRoot(async (root) => {
      const fixture = await makeFixture(root);
      const releaseSource: TaskReleaseQuerySource = {
        async getActiveAdmissionRelease() { return null; },
        async getValidatedReleaseRecord(identity, digest, tx) {
          assert.ok(tx, 'release lookup stays inside the caller transaction');
          return identity === RELEASE_ID && digest === MANIFEST_HASH ? fixture.record : null;
        },
      };
      const source = new TaskSealedEvidenceSource({ taskReleaseSource: releaseSource, evidenceRoot: root });
      const queryResult = await db.transaction(async (tx) => {
        await tx.execute(sql`CREATE TEMP TABLE oid_benchmark_run(
          id uuid,owner_id uuid,agent_id uuid,mode text,task_ids text[],release_identity text,manifest_hash text,environment_id text)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_run_task(
          run_id uuid,task_index integer,task_id text,closure_id uuid,closure_status text,action_cutoff_sequence bigint,reconciled_action_sequence bigint)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_run_task_closure(
          id uuid,run_id uuid,task_index integer,operation_id text,payload_hash text,reason text,action_cutoff_sequence bigint,answer_json jsonb)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_run_task_observation_bundle(
          run_id uuid,task_index integer,owner_id uuid,agent_id uuid,closure_id uuid,closure_operation_id text,closure_payload_hash text,
          closure_reason text,task_id text,release_identity text,release_manifest_hash text,case_id text,case_hash text,rubric_hash text,
          environment_id text,preparation_id uuid,lease_id uuid,generation_id uuid,environment_manifest_hash text,application_source_hash text,
          execution_identity_hash text,initial_state_sha256 text,action_cutoff_sequence bigint,reconciled_action_sequence bigint,
          observation_cutoff_sequence bigint,cutoff_evidence jsonb,bundle_hash text,bundle_json jsonb)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_task_preparation_intent(
          preparation_id uuid,run_id uuid,task_index integer,lease_id uuid,environment_id text,release_identity text,manifest_hash text,
          task_id text,case_id text,case_hash text,initial_state_sha256 text,environment_manifest_sha256 text,application_source_hash text,
          execution_identity_hash text)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_task_environment_lease(preparation_id uuid,lease_id uuid,state text)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_task_execution_binding(
          run_id uuid,task_index integer,env_id text,generation_id uuid,manifest_hash text,application_source_hash text)`);
        await tx.execute(sql`CREATE TEMP TABLE oid_task_preparation_observation(
          preparation_id uuid,status text,generation_id uuid,baseline_state_sha256 text)`);
        const row = fixture.row;
        await tx.execute(sql`INSERT INTO oid_benchmark_run VALUES(${row.run_id},${row.owner_id},${row.agent_id},${row.mode},ARRAY['S1']::text[],
          ${row.release_identity},${row.manifest_hash},'synthetic-successor-env')`);
        await tx.execute(sql`INSERT INTO oid_run_task VALUES(${row.run_id},0,${row.task_id},${row.closure_id},${row.closure_status},
          ${row.action_cutoff_sequence},${row.reconciled_action_sequence})`);
        await tx.execute(sql`INSERT INTO oid_run_task_closure VALUES(${row.closure_id},${row.run_id},0,${row.closure_operation_id},
          ${row.closure_payload_hash},${row.closure_reason},${row.closure_action_cutoff_sequence},${JSON.stringify(row.closure_answer_json)}::jsonb)`);
        await tx.execute(sql`INSERT INTO oid_run_task_observation_bundle VALUES(
          ${row.run_id},0,${row.bundle_owner_id},${row.bundle_agent_id},${row.bundle_closure_id},${row.bundle_closure_operation_id},
          ${row.bundle_closure_payload_hash},${row.bundle_closure_reason},${row.bundle_task_id},${row.bundle_release_identity},${row.bundle_manifest_hash},
          ${row.bundle_case_id},${row.bundle_case_hash},${row.bundle_rubric_hash},${row.bundle_environment_id},${row.preparation_id},${row.lease_id},
          ${row.generation_id},${row.environment_manifest_hash},${row.application_source_hash},${row.execution_identity_hash},${row.initial_state_sha256},
          ${row.bundle_action_cutoff_sequence},${row.bundle_reconciled_action_sequence},${row.observation_cutoff_sequence},
          ${JSON.stringify(row.cutoff_evidence)}::jsonb,${row.bundle_hash},${JSON.stringify(row.bundle_json)}::jsonb)`);
        await tx.execute(sql`INSERT INTO oid_task_preparation_intent VALUES(
          ${row.preparation_id},${row.run_id},0,${row.lease_id},${row.prepared_environment_id},${row.prepared_release_identity},
          ${row.prepared_manifest_hash},${row.prepared_task_id},${row.prepared_case_id},${row.prepared_case_hash},${row.prepared_initial_state_sha256},
          ${row.prepared_environment_manifest_hash},${row.prepared_application_source_hash},${row.prepared_execution_identity_hash})`);
        await tx.execute(sql`INSERT INTO oid_task_environment_lease VALUES(${row.preparation_id},${row.lease_id},'fenced')`);
        await tx.execute(sql`INSERT INTO oid_task_execution_binding VALUES(${row.run_id},0,${row.execution_environment_id},${row.execution_generation_id},
          ${row.execution_manifest_hash},${row.execution_application_source_hash})`);
        await tx.execute(sql`INSERT INTO oid_task_preparation_observation VALUES(${row.preparation_id},'ready',${row.generation_id},${row.initial_state_sha256})`);
        return source.load({ runId: RUN, taskIndex: 0, closureId: CLOSURE }, tx as never);
      });
      assert.ok(queryResult);
      assert.equal(queryResult.run.taskId, 'S1');
      assert.equal(queryResult.run.environmentId, ENVIRONMENT, 'current run pointer may identify the successor environment');
      assert.equal(queryResult.observations.coverage.transfers, 'incomplete');
      assert.equal(queryResult.run.observationCutoffSequence, 7);
    });
  } finally {
    await client.end();
    if (databaseCreated) await admin.unsafe(`DROP DATABASE ${databaseName}`);
    await admin.end();
  }
});
