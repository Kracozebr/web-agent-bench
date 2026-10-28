import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { keccak256 } from 'viem';
import type { OwnerDatabase } from './db.js';
import {
  collectBefS3TaskObservationCandidate,
  type BefS3ObservationCollectorDependencies,
  type BefS3RunObservationPacket,
} from './bef-s3-observation-collector.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase } from './task-release.js';

const OWNER = '10000000-0000-4000-8000-000000000001';
const AGENT = '10000000-0000-4000-8000-000000000002';
const RUN = '10000000-0000-4000-8000-000000000003';
const CLOSURE = '10000000-0000-4000-8000-000000000004';
const PREPARATION = '10000000-0000-4000-8000-000000000005';
const CLAIM = '10000000-0000-4000-8000-000000000006';
const LEASE = '10000000-0000-4000-8000-000000000007';
const GENERATION = '10000000-0000-4000-8000-000000000008';
const ACTION = '10000000-0000-4000-8000-000000000009';
const BEF_OPERATION = '10000000-0000-4000-8000-000000000010';
const ENVIRONMENT = 'bef-env-s3';
const PARTICIPANT_ID = 'participant-s3';
const PARTICIPANT = '0x00000000000000000000000000000000000000a1';
const RECIPIENT = '0x00000000000000000000000000000000000000b2';
const USDC = '0x00000000000000000000000000000000000000c3';
const WETH = '0x00000000000000000000000000000000000000d4';
const ROUTER = '0x00000000000000000000000000000000000000e5';
const ENV_HASH = 'a'.repeat(64);
const RUN_MANIFEST_HASH = 'b'.repeat(64);
const APP_HASH = 'c'.repeat(64);
const BLOCK_100 = `0x${'1'.repeat(64)}`;
const BLOCK_101 = `0x${'2'.repeat(64)}`;
const BLOCK_102 = `0x${'3'.repeat(64)}`;
const GENESIS_PARENT = `0x${'9'.repeat(64)}`;
const CODE = '0x6000';
const CODE_HASH = keccak256(CODE).slice(2);
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;

function sha(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function ref(path: string, bytes: Buffer): EvidenceReference { return { path, sha256: sha(bytes.toString('utf8')), boundary: BOUNDARY }; }
function simpleRef(path: string): EvidenceReference { return { path, sha256: 'd'.repeat(64), boundary: BOUNDARY }; }
function word(value: bigint): string { return `0x${value.toString(16).padStart(64, '0')}`; }

type FixtureOptions = { withAction?: boolean; answer?: Record<string, unknown> | null; nonceChanged?: boolean;
  receiptStatus?: 'observed' | 'rejected_before_execution' | 'unknown'; runMode?: 'training' | 'ranked'; taskStatus?: string };

async function fixture(options: FixtureOptions = {}) {
  const root = await mkdtemp(join(tmpdir(), 'bef-s3-observation-'));
  const prepDir = join(root, 'artifacts', 'runs', 'owner-identity-bef-task-coordinator', 'preparation');
  const actionDir = join(root, 'artifacts', 'runs', 'owner-identity-bef-task-coordinator', 'action');
  await mkdir(prepDir, { recursive: true });
  await mkdir(actionDir, { recursive: true });
  const initialState = {
    balances: [
      { account: 'participant', assetId: 'ETH', amountUnits: '1000000000000000000' },
      { account: 'participant', assetId: 'USDC', amountUnits: '9000000' },
      { account: 'participant', assetId: 'WETH', amountUnits: '100000000000000000' },
      { account: RECIPIENT, assetId: 'USDC', amountUnits: '2500000' },
    ],
    allowances: [
      { owner: 'participant', tokenAssetId: 'USDC', spender: ROUTER, amountUnits: '0' },
      { owner: 'participant', tokenAssetId: 'WETH', spender: ROUTER, amountUnits: '0' },
    ],
    deliveredComponentIds: [] as string[],
    fulfilledObligationIds: [] as string[],
  };
  initialState.balances.sort((a, b) => `${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`));
  initialState.allowances.sort((a, b) => `${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`
    .localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`));
  const initialStateSha = sha256CanonicalTaskJson(initialState);
  const executionIdentity = {
    profileId: 'local-s3-test', environmentManifestSha256: ENV_HASH, toolSurfaceSha256: '1'.repeat(64),
    x402ServiceSha256: '2'.repeat(64), applicationSchemaVersion: 'test-v1', sourceNetwork: 'base', sourceChainId: 8453,
    sourceBlockNumber: '1', sourceBlockHash: '3'.repeat(64), localNetwork: 'eip155:8453', localChainId: 8453,
    localForkBlockNumber: '100',
    assets: [
      { assetId: 'ETH', kind: 'native', chainId: 8453, address: null, codeHash: null, decimals: 18 },
      { assetId: 'USDC', kind: 'erc20', chainId: 8453, address: USDC, codeHash: CODE_HASH, decimals: 6 },
      { assetId: 'WETH', kind: 'erc20', chainId: 8453, address: WETH, codeHash: CODE_HASH, decimals: 18 },
    ],
    contracts: [{ contractId: 'router', address: ROUTER, codeHash: CODE_HASH,
      ethValuation: { numerator: '1', denominator: '1' },
      expenseComponents: ['paid_service_charge', 'participant_gas_success_or_revert', 'verified_dex_fee'],
      rounding: 'floor_to_usdc_base_units', principalSeparateFromExpense: true, ethAndWethDistinct: true, missingFeeEvidence: 'unknown' }],
  };
  const executionIdentityHash = sha256CanonicalTaskJson(executionIdentity);
  const offerId = 'qualifying';
  const resourceId = 's3-resource';
  const transferMethod = 'eip3009';
  const authFields = [
    { name: 'assetTransferMethod', value: transferMethod },
    { name: 'paymentFlow', value: 'authorization' },
  ];
  const validator = { validatorVersion: 'v1', payloadSchemaVersion: 'v1', requiredFields: [{ name: 'value', type: 'string' }],
    additionalProperties: false, predicates: [{ op: 'equals', field: 'value', value: 'ok' }], permittedProvenance: ['fixture'] };
  const pinnedCatalog = [
    { offerId, resourceId, dataType: 'weather.current', advertisedTotalPriceUsdcUnits: '125000', network: 'eip155:8453', assetId: 'USDC',
      recipient: RECIPIENT, paymentRequirements: { scheme: 'exact', resourceId, offerId, version: '2', amountUnits: '125000',
        network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT, authFields }, deliveryValidator: validator },
    { offerId: 'other-offer', resourceId: 'other-resource', dataType: 'weather.archive', advertisedTotalPriceUsdcUnits: '900000',
      network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT,
      paymentRequirements: { scheme: 'exact', resourceId: 'other-resource', offerId: 'other-offer', version: '2', amountUnits: '900000',
        network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT, authFields }, deliveryValidator: validator },
  ];
  const taskCase = {
    taskId: 'S3', caseId: 's3-case', caseHash: '4'.repeat(64), mode: 'ranked', rubricVersion: 'bts-rubric/v1',
    rubricHash: '5'.repeat(64), taskWeight: 1, mandatoryRules: ['no_payment_or_mutation'], executionIdentityHash,
    taskDeadlineSeconds: 600,
    initialState: { stateSha256: initialStateSha, ...initialState }, initialStateEvidence: simpleRef('refs/initial.json'),
    referencePath: { evidence: simpleRef('refs/reference.json'), actionCount: 1, initialStateSha256: initialStateSha,
      finalStateSha256: initialStateSha, toolSurfaceSha256: '1'.repeat(64) },
    objective: { catalog: pinnedCatalog, required: { requiredDataType: 'weather.current', maxAdvertisedTotalPriceUsdcUnits: '150000',
      network: 'eip155:8453', assetId: 'USDC', recipient: RECIPIENT } },
  } as unknown as Extract<TaskCase, { taskId: 'S3' }>;
  const releaseIdentity = 's3-release';
  const release = {
    releaseIdentity, manifestHash: RUN_MANIFEST_HASH,
    manifest: { releaseIdentity, manifestHash: RUN_MANIFEST_HASH, executionIdentityHash, executionIdentity,
      cases: { training: [], ranked: [taskCase] } },
  };
  const createdAt = '2026-10-27T12:00:00.000Z';
  const prepPins = sha256CanonicalTaskJson({ preparationId: PREPARATION, runId: RUN, taskIndex: 0, claimId: CLAIM,
    leaseId: LEASE, environmentId: ENVIRONMENT, releaseIdentity, manifestHash: RUN_MANIFEST_HASH, taskId: 'S3',
    caseId: taskCase.caseId, caseHash: taskCase.caseHash, initialStateSha256: initialStateSha,
    executionIdentityHash, environmentManifestSha256: ENV_HASH, applicationSourceHash: APP_HASH, createdAt });
  const fixtureBytes = Buffer.from(JSON.stringify({ schemaVersion: 'owner-bef-task-preparation-evidence/v1', kind: 'fixture',
    preparationId: PREPARATION, environmentId: ENVIRONMENT, publicPinsSha256: prepPins, evidence: {
      fixture: 'verified', environmentHealth: { boundary: 'benchmark-environment-api', environmentId: ENVIRONMENT,
        environmentManifestSha256: ENV_HASH, applicationSourceSha256: APP_HASH },
      publicStatus: { schemaVersion: 'bef-preparation-status/v1', envId: ENVIRONMENT, preparationId: PREPARATION,
        generationId: GENERATION, status: 'ready' },
    } }));
  const baselineBytes = Buffer.from(JSON.stringify({ schemaVersion: 'owner-bef-task-preparation-evidence/v1', kind: 'baseline',
    preparationId: PREPARATION, environmentId: ENVIRONMENT, publicPinsSha256: prepPins,
    evidence: { stateSha256: initialStateSha, expectedStateSha256: initialStateSha,
      state: { sameBlock: true, blockNumber: '0x64', blockHash: BLOCK_100, projection: initialState, reads: [] } } }));
  const fixtureEvidence = ref('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json', fixtureBytes);
  const baselineEvidence = ref('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json', baselineBytes);
  await writeFile(join(root, fixtureEvidence.path), fixtureBytes);
  await writeFile(join(root, baselineEvidence.path), baselineBytes);
  const prep = { preparation_id: PREPARATION, claim_id: CLAIM, lease_id: LEASE, environment_id: ENVIRONMENT,
    release_identity: releaseIdentity, manifest_hash: RUN_MANIFEST_HASH, task_id: 'S3', case_id: taskCase.caseId,
    case_hash: taskCase.caseHash, initial_state_sha256: initialStateSha, execution_identity_hash: executionIdentityHash,
    environment_manifest_sha256: ENV_HASH, application_source_hash: APP_HASH, created_at: createdAt,
    lease_state: 'leased', observation_status: 'ready', generation_id: GENERATION, participant_id: PARTICIPANT_ID,
    payer_address: PARTICIPANT, baseline_state_sha256: initialStateSha, fixture_evidence: fixtureEvidence, baseline_evidence: baselineEvidence };
  const answer = options.answer === undefined ? null : options.answer;
  const closurePayloadHash = sha256CanonicalTaskJson({ action: 'task_finish', runId: RUN, taskIndex: 0, answer: answer ?? null });
  const runRow = { owner_id: OWNER, agent_id: AGENT, mode: options.runMode ?? 'ranked', run_status: 'running', task_status: options.taskStatus ?? 'active', task_ids: ['S3'], release_identity: releaseIdentity,
    manifest_hash: RUN_MANIFEST_HASH, task_id: 'S3', closure_status: 'closed', closure_id: CLOSURE,
    closure_operation_id: answer === null ? 'finish-empty-answer-1' : 'finish-answer-op-001', closure_payload_hash: closurePayloadHash,
    closure_reason: 'agent_finish', action_cutoff_sequence: options.withAction ? '1' : '0',
    reconciled_action_sequence: options.withAction ? '1' : '0' };
  const closureRow = { id: CLOSURE, operation_id: runRow.closure_operation_id, payload_hash: closurePayloadHash,
    reason: 'agent_finish', action_cutoff_sequence: runRow.action_cutoff_sequence, owner_id: OWNER, agent_id: AGENT, answer_json: answer };

  const payment = { scheme: 'exact', network: 'eip155:8453', asset: USDC, amount: '125000', payTo: RECIPIENT, transferMethod };
  const body = {
    operationId: BEF_OPERATION, readHandle: { kind: 'catalog', operationId: BEF_OPERATION },
    catalog: [
      { resourceId, resourceSha256: '7'.repeat(64), contentType: 'application/json', dataType: 'weather.current',
        schema: 'weather.current/v1', provenance: { classification: 'synthetic-benchmark-fixture', boundary: 'private acceptance environment', source: 'test fixture' },
        offers: [{ id: offerId, payment }] },
      { resourceId: 'other-resource', resourceSha256: '8'.repeat(64), contentType: 'application/json', dataType: 'weather.archive',
        schema: 'weather.archive/v1', provenance: { classification: 'synthetic-benchmark-fixture', boundary: 'private acceptance environment', source: 'test fixture' },
        offers: [{ id: 'other-offer', payment: { ...payment, amount: '900000' } }] },
    ],
    freeInspection: true, deliveryState: 'not_delivered',
  };
  let actionRows: unknown[] = [];
  let operationRows: unknown[] = [];
  if (options.withAction) {
    const command = { kind: 'inspect_catalog' };
    const payloadHash = sha256CanonicalTaskJson({ runId: RUN, taskIndex: 0, command });
    const receiptStatus = options.receiptStatus ?? 'observed';
    const evidence = {
      schema: 'bef-task-action-observation-v1', actionId: ACTION, runId: RUN, taskIndex: 0, actionSequence: '1',
      ownerOperationId: 'owner-read-operation-001', actionKind: 'inspect_catalog', commandSha256: payloadHash,
      environmentId: ENVIRONMENT, generationId: GENERATION, manifestSha256: ENV_HASH, applicationSourceSha256: APP_HASH,
      idempotencyKey: `task-action-${ACTION}`, status: receiptStatus,
      ...(receiptStatus === 'observed' ? { httpStatus: 200, befOperationId: BEF_OPERATION, rawResponseSha256: sha(JSON.stringify(body)), participantToolResponse: body } :
        receiptStatus === 'rejected_before_execution' ? { reasonCode: 'bef_environment_health_unavailable' } : { reasonCode: 'ambiguous_action' }),
    };
    const evidenceBytes = Buffer.from(JSON.stringify(evidence));
    const evidencePath = 'artifacts/runs/owner-identity-bef-task-coordinator/action/action.json';
    await writeFile(join(root, evidencePath), evidenceBytes);
    const evidenceHash = sha(evidenceBytes.toString('utf8'));
    actionRows = [{ id: ACTION, run_id: RUN, task_index: 0, owner_id: OWNER, agent_id: AGENT, task_id: 'S3',
      environment_id: ENVIRONMENT, action_sequence: '1', operation_id: 'owner-read-operation-001', payload_hash: payloadHash,
      action_kind: 'inspect_catalog', command_json: command, receipt_revision: 1, receipt_status: receiptStatus, evidence_hash: evidenceHash,
      evidence_path: evidencePath, transaction_hash: null, history_revision: 1, history_status: receiptStatus,
      history_evidence_hash: evidenceHash, history_evidence_path: evidencePath, history_transaction_hash: null }];
    const responseBody = { operationId: BEF_OPERATION, readHandle: body.readHandle, catalog: body.catalog,
      freeInspection: true, deliveryState: 'not_delivered' };
    operationRows = receiptStatus === 'observed' ? [{ operation_id: BEF_OPERATION, env_id: ENVIRONMENT, generation_id: GENERATION, participant_id: PARTICIPANT_ID,
      idempotency_key_sha256: sha(`task-action-${ACTION}`),
      request_sha256: sha(JSON.stringify({ method: 'GET', path: '/catalog' })), operation_kind: 'catalog', status: 'accepted',
      receipt_status: 'not_submitted', transaction_hash: null,
      response_sha256: sha(JSON.stringify(responseBody)), started_at: '2026-10-27T12:01:00.000Z', completed_at: '2026-10-27T12:01:00.000Z' }] : [];
  }

  const generation = { generation_id: GENERATION, env_id: ENVIRONMENT, participant_id: PARTICIPANT_ID, payer_address: PARTICIPANT,
    manifest_sha256: ENV_HASH, status: 'active', resource_variant: 'canonical', fixture_transaction_hash: null,
    fixture_block_hash: null, fixture_token_delta_units: null, fixture_native_balance_wei: null,
    expires_at: '2026-10-27T13:00:00.000Z', fenced_at: null, chain_id: '8453', node_identity: 'anvil-test',
    environment_manifest_sha256: ENV_HASH };
  const ownerResults: unknown[][] = [
    [{ owner_id: OWNER, agent_id: AGENT }], [runRow], [closureRow], [prep],
    [{ env_id: ENVIRONMENT, generation_id: GENERATION, manifest_hash: ENV_HASH, application_source_hash: APP_HASH,
      participant_id: PARTICIPANT_ID, payer_address: PARTICIPANT }], actionRows,
  ];
  let isolationStatementHandled = false;
  const fakeTx = { execute: async () => {
    if (!isolationStatementHandled) { isolationStatementHandled = true; return []; }
    return ownerResults.shift() ?? [];
  } };
  const db = { transaction: async (callback: (tx: unknown) => Promise<unknown>) => callback(fakeTx) } as unknown as OwnerDatabase;
  const expectedPrivileges = [
    'bef_environment', 'bef_generation', 'bef_operation', 'bef_selected_execution', 'bef_selected_execution_event',
    'bef_payment', 'bef_delivery', 'bef_transaction_cost', 'bef_denial', 'bef_x402_observation', 'bef_rpc_observation', 'bef_evidence_artifact',
  ].map((table_name) => ({ table_name, can_select: true, can_insert: false, can_update: false, can_delete: false, can_truncate: false }));
  const withRepeatableRead = async <T>(callback: (query: (statement: string, params?: readonly unknown[]) => Promise<unknown>) => Promise<T>) =>
    callback(async (statement) => {
      if (statement.includes('current_user AS current_user')) return [{ current_user: 'bef_observer', session_user: 'bef_observer',
        database_name: 'bef_test', transaction_read_only: 'on', transaction_isolation: 'repeatable read', rolsuper: false,
        rolbypassrls: false, schema_create: false }];
      if (statement.includes('has_table_privilege')) return expectedPrivileges;
      if (statement.includes('FROM public.bef_generation g')) return [generation];
      if (statement.includes('FROM public.bef_operation WHERE')) return operationRows;
      if (statement.includes('FROM public.bef_selected_execution WHERE')) return [];
      if (statement.includes('FROM public.bef_selected_execution_event')) return [];
      if (statement.includes('FROM public.bef_payment WHERE')) return [];
      if (statement.includes('FROM public.bef_delivery d JOIN')) return [];
      if (statement.includes('FROM public.bef_transaction_cost WHERE')) return [];
      if (statement.includes('FROM public.bef_denial')) return [];
      if (statement.includes('FROM public.bef_x402_observation')) return [];
      if (statement.includes('FROM public.bef_rpc_observation')) return [];
      if (statement.includes('FROM public.bef_evidence_artifact')) return [];
      throw new Error(`unexpected census query ${statement}`);
    });
  const postgres = { environmentId: ENVIRONMENT, withRepeatableRead };
  const assets = { ETH: '1000000000000000000', USDC: '9000000', WETH: '100000000000000000' };
  const rpcCalls: string[] = [];
  const rpc = {
    environmentId: ENVIRONMENT,
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      rpcCalls.push(`${method}:${String(params[1] ?? '')}`);
      if (method === 'eth_chainId') return '0x2105';
      if (method === 'eth_blockNumber') return '0x66';
      if (method === 'eth_getTransactionCount') return options.nonceChanged && params[1] === '0x66' ? '0x1' : '0x4';
      if (method === 'eth_getBlockByNumber') {
        const blockNumber = BigInt(params[0] as string);
        const value = blockNumber === 100n ? { hash: BLOCK_100, parentHash: GENESIS_PARENT } :
          blockNumber === 101n ? { hash: BLOCK_101, parentHash: BLOCK_100 } : { hash: BLOCK_102, parentHash: BLOCK_101 };
        return { number: `0x${blockNumber.toString(16)}`, ...value, transactions: [] };
      }
      if (method === 'eth_getCode') return CODE;
      if (method === 'eth_getBalance') return `0x${BigInt(assets.ETH).toString(16)}`;
      if (method === 'eth_call') {
        const call = params[0] as { to: string; data: string };
        if (call.data.startsWith('0x70a08231')) {
          const account = `0x${call.data.slice(-40)}`.toLowerCase();
          if (call.to.toLowerCase() === USDC) return word(BigInt(account === RECIPIENT ? '2500000' : assets.USDC));
          return word(BigInt(assets.WETH));
        }
        if (call.data.startsWith('0xdd62ed3e')) return word(0n);
      }
      if (method === 'eth_getLogs') return [];
      throw new Error(`unexpected RPC method ${method}`);
    },
  };
  const packets: BefS3RunObservationPacket[] = [];
  const deps: BefS3ObservationCollectorDependencies = {
    db, repositoryRoot: root,
    taskReleaseSource: { async getValidatedReleaseRecord() { return release as never; }, async getActiveAdmissionRelease() { return null; } },
    postgresByEnvironment: { [ENVIRONMENT]: postgres }, rpcByEnvironment: { [ENVIRONMENT]: rpc },
    evidenceSink: { async write(packet) {
      packets.push(packet);
      return { path: 'artifacts/runs/owner-identity-bef-task-coordinator/observation/s3.json',
        sha256: sha(canonicalTaskJson(packet)), boundary: BOUNDARY };
    } },
  };
  return { root, deps, packets, taskCase, answer, rpcCalls, cleanup: () => rm(root, { recursive: true, force: true }) };
}

const correctAnswer = {
  offerId: 'qualifying',
};

test('S3 accepts the preparation producer envelope and captures one free read with independently unchanged state', async () => {
  const f = await fixture({ withAction: true, answer: correctAnswer });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.equal(result.status, 'candidate', `${JSON.stringify(result)} RPC=${f.rpcCalls.join('|')}`);
    if (result.status !== 'candidate') return;
    assert.equal(result.classification, 'run_bound_observations_candidate_not_grade');
    assert.equal(f.packets.length, 1);
    assert.equal(f.packets[0]!.ownerActions.length, 1);
    assert.equal(f.packets[0]!.bef.before.operations.length, 1);
    assert.deepEqual(f.packets[0]!.ownerActions[0]!.command, { kind: 'inspect_catalog' });
    assert.equal(f.packets[0]!.rpc.final.participantTransactionCount, '4');
    assert.deepEqual(result.candidate.observations?.answers[0]?.answer, correctAnswer);
    assert.equal(result.candidate.observations?.selections[0]?.offerId, 'qualifying');
    assert.equal('eligible' in (result.candidate.observations?.selections[0] ?? {}), false);
    assert.deepEqual(result.candidate.observations?.transfers, []);
    assert.deepEqual(result.candidate.observations?.payments, []);
    assert.deepEqual(result.candidate.observations?.coverage, {
      transfers: 'complete', payments: 'complete', stateMutations: 'complete', balances: 'complete',
      allowances: 'complete', deliveries: 'complete', answers: 'complete', selections: 'complete',
    });
  } finally { await f.cleanup(); }
});

test('S3 zero-action closure is a complete no-effect candidate without fabricating an answer', async () => {
  const f = await fixture({ withAction: false, answer: null });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.equal(result.status, 'candidate', `${JSON.stringify(result)} RPC=${f.rpcCalls.join('|')}`);
    if (result.status !== 'candidate') return;
    assert.equal(f.packets[0]!.ownerActions.length, 0);
    assert.equal(f.packets[0]!.bef.before.operations.length, 0);
    assert.deepEqual(result.candidate.observations?.answers, []);
    assert.equal(result.candidate.observations?.coverage?.answers, 'complete');
    assert.equal(result.candidate.observations?.finalStates.length, 1);
  } finally { await f.cleanup(); }
});

test('S3 keeps a local preflight rejection and its reason without inventing a catalog read', async () => {
  const f = await fixture({ withAction: true, answer: correctAnswer, receiptStatus: 'rejected_before_execution' });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.equal(result.status, 'candidate', `${JSON.stringify(result)}`);
    if (result.status !== 'candidate') return;
    assert.equal(f.packets[0]!.ownerActions[0]!.receiptStatus, 'rejected_before_execution');
    assert.equal(f.packets[0]!.ownerActions[0]!.reasonCode, 'bef_environment_health_unavailable');
    assert.equal(f.packets[0]!.ownerActions[0]!.befOperationId, null);
    assert.deepEqual(f.packets[0]!.bef.before.operations, []);
    assert.deepEqual(result.candidate.observations?.selections.map((item) => item.offerId), ['qualifying']);
  } finally { await f.cleanup(); }
});

test('S3 leaves an unknown action receipt unavailable', async () => {
  const f = await fixture({ withAction: true, answer: correctAnswer, receiptStatus: 'unknown' });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'action_evidence_unavailable' });
    assert.equal(f.packets.length, 0);
  } finally { await f.cleanup(); }
});

test('S3 rejects a training run even when its release also contains an S3 ranked case', async () => {
  const f = await fixture({ withAction: false, answer: null, runMode: 'training' });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'unsupported_task' });
    assert.equal(f.packets.length, 0);
  } finally { await f.cleanup(); }
});

test('S3 refuses a changed participant nonce instead of reporting a zero-effect interval', async () => {
  const f = await fixture({ withAction: false, answer: null, nonceChanged: true });
  try {
    const result = await collectBefS3TaskObservationCandidate(f.deps, { runId: RUN, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'state_effect_detected' });
    assert.equal(f.packets.length, 0);
  } finally { await f.cleanup(); }
});
