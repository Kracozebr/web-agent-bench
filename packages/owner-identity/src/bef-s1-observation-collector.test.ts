import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { keccak256 } from 'viem';
import type { OwnerDatabase } from './db.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import { collectBefS1TaskObservationCandidate, type BefS1ObservationCollectorDependencies, type BefS1RunObservationPacket } from './bef-s1-observation-collector.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase } from './task-release.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const OWNER_ID = '10000000-0000-4000-8000-000000000001';
const AGENT_ID = '10000000-0000-4000-8000-000000000002';
const RUN_ID = '10000000-0000-4000-8000-000000000003';
const CLOSURE_ID = '10000000-0000-4000-8000-000000000004';
const PREPARATION_ID = '10000000-0000-4000-8000-000000000005';
const CLAIM_ID = '10000000-0000-4000-8000-000000000006';
const LEASE_ID = '10000000-0000-4000-8000-000000000007';
const GENERATION_ID = '10000000-0000-4000-8000-000000000008';
const PARTICIPANT_ID = '10000000-0000-4000-8000-000000000009';
const ENVIRONMENT_ID = 'bef-env-a';
const PARTICIPANT = '0x00000000000000000000000000000000000000a1';
const RECIPIENT = '0x00000000000000000000000000000000000000b2';
const TOKEN = '0x00000000000000000000000000000000000000c3';
const BLOCK_HASH = `0x${'d'.repeat(64)}`;
const PARENT_HASH = `0x${'e'.repeat(64)}`;
const EXTRA_BLOCK_HASH = `0x${'9'.repeat(64)}`;
const EXTRA_TX_HASH = `0x${'8'.repeat(64)}`;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const CODE = '0x6000';
const CODE_HASH = keccak256(CODE).slice(2);
const EVIDENCE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;

function ref(path: string, bytes: Buffer): EvidenceReference {
  return { path, sha256: createHash('sha256').update(bytes).digest('hex'), boundary: EVIDENCE_BOUNDARY };
}

function simpleRef(path: string): EvidenceReference {
  return { path, sha256: HASH_A, boundary: EVIDENCE_BOUNDARY };
}

function queryName(statement: string): string {
  if (statement.includes('current_user AS current_user')) return 'session';
  if (statement.includes('has_table_privilege')) return 'privileges';
  if (statement.includes('FROM public.bef_generation g')) return 'generation';
  if (statement.includes('(SELECT count(*)::text FROM public.bef_operation')) return 'counts';
  if (statement.includes('FROM public.bef_operation')) return 'operations';
  if (statement.includes('FROM public.bef_selected_execution_event')) return 'events';
  if (statement.includes('FROM public.bef_selected_execution')) return 'executions';
  if (statement.includes('FROM public.bef_payment')) return 'payments';
  if (statement.includes('FROM public.bef_delivery d JOIN')) return 'deliveries';
  if (statement.includes('FROM public.bef_transaction_cost')) return 'costs';
  if (statement.includes('FROM public.bef_generation')) return 'generation';
  throw new Error(`unexpected observer query: ${statement}`);
}

async function createZeroActionFixture(options: {
  writableObserver?: boolean; extraTransfer?: boolean; admittedAction?: boolean; bareCommandHash?: boolean;
  selectedActionToken?: unknown; selectedActionApiToken?: unknown; measurementToken?: unknown;
  operationResponseHash?: string | null;
} = {}) {
  const repositoryRoot = await mkdtemp(join(tmpdir(), 'bef-s1-zero-action-'));
  const evidenceDirectory = join(repositoryRoot, 'artifacts', 'runs', 'owner-identity-bef-task-coordinator', 'preparation');
  await mkdir(evidenceDirectory, { recursive: true });
  const actionEvidenceDirectory = join(repositoryRoot, 'artifacts', 'runs', 'owner-identity-bef-task-coordinator', 'action');
  await mkdir(actionEvidenceDirectory, { recursive: true });

  const balances = [
    { account: RECIPIENT, assetId: 'USDC', amountUnits: '2500000' },
    { account: 'participant', assetId: 'ETH', amountUnits: '1000000000000000000' },
    { account: 'participant', assetId: 'USDC', amountUnits: '9000000' },
  ];
  const pinnedProjection = {
    balances,
    allowances: [] as Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>,
    deliveredComponentIds: [] as string[],
    fulfilledObligationIds: [] as string[],
  };
  const initialStateSha256 = sha256CanonicalTaskJson(pinnedProjection).toLowerCase();
  const environmentManifestHash = HASH_A;
  const applicationSourceHash = HASH_B;
  const executionIdentityHash = 'c'.repeat(64);
  const manifestHash = 'f'.repeat(64);
  const releaseIdentity = 'synthetic-s1-zero-action';
  const createdAt = '2026-10-27T12:00:00.000Z';
  const taskCase = {
    taskId: 'S1',
    caseId: 's1-zero-action-synthetic',
    caseHash: '1'.repeat(64),
    mode: 'training',
    rubricVersion: 'bts-rubric/v1',
    rubricHash: '2'.repeat(64),
    taskWeight: 1,
    mandatoryRules: ['S1'],
    executionIdentityHash,
    taskDeadlineSeconds: 600,
    initialState: { ...pinnedProjection, stateSha256: initialStateSha256 },
    initialStateEvidence: simpleRef('artifacts/synthetic/initial.json'),
    referencePath: {
      evidence: simpleRef('artifacts/synthetic/reference.json'),
      actionCount: 1,
      initialStateSha256,
      finalStateSha256: '3'.repeat(64),
      toolSurfaceSha256: '4'.repeat(64),
    },
    objective: {
      tokenAssetId: 'USDC',
      sender: 'participant',
      recipient: RECIPIENT,
      exactPrincipalUnits: '1000000',
      nativeReserveWei: '100000000000000000',
      unrelatedEffectBaselineSha256: '5'.repeat(64),
    },
  } as unknown as Extract<TaskCase, { taskId: 'S1' }>;
  const executionIdentity = {
    profileId: 'synthetic-local-fork',
    environmentManifestSha256: environmentManifestHash,
    toolSurfaceSha256: '4'.repeat(64),
    x402ServiceSha256: '6'.repeat(64),
    applicationSchemaVersion: 'synthetic-v1',
    sourceNetwork: 'synthetic',
    sourceChainId: 1,
    sourceBlockNumber: '1',
    sourceBlockHash: HASH_B,
    localNetwork: 'synthetic-local',
    localChainId: 31337,
    localForkBlockNumber: '0',
    assets: [
      { assetId: 'ETH', kind: 'native', chainId: 31337, address: null, codeHash: null, decimals: 18 },
      { assetId: 'USDC', kind: 'erc20', chainId: 31337, address: TOKEN, codeHash: CODE_HASH, decimals: 6 },
    ],
    contracts: [{ contractId: 'USDC', address: TOKEN, codeHash: CODE_HASH, chainId: 31337, blockNumber: '0', blockHash: BLOCK_HASH }],
  };
  const release = {
    releaseIdentity,
    manifestHash,
    manifest: {
      releaseIdentity,
      manifestHash,
      executionIdentity,
      cases: { training: [taskCase], ranked: [taskCase] },
    },
  };

  const publicPinsSha256 = sha256CanonicalTaskJson({
    preparationId: PREPARATION_ID, runId: RUN_ID, taskIndex: 0, claimId: CLAIM_ID, leaseId: LEASE_ID,
    environmentId: ENVIRONMENT_ID, releaseIdentity, manifestHash, taskId: 'S1', caseId: taskCase.caseId,
    caseHash: taskCase.caseHash, initialStateSha256, executionIdentityHash, environmentManifestSha256: environmentManifestHash,
    applicationSourceHash, createdAt,
  }).toLowerCase();
  const fixtureDocument = {
    schemaVersion: 'owner-bef-task-preparation-evidence/v1', kind: 'fixture', preparationId: PREPARATION_ID,
    environmentId: ENVIRONMENT_ID, publicPinsSha256, evidence: { fixture: 'synthetic fixture contract only' },
  };
  const baselineDocument = {
    schemaVersion: 'owner-bef-task-preparation-evidence/v1', kind: 'baseline', preparationId: PREPARATION_ID,
    environmentId: ENVIRONMENT_ID, publicPinsSha256,
    evidence: {
      stateSha256: initialStateSha256, expectedStateSha256: initialStateSha256,
      state: {
        blockNumber: '0x0', blockHash: BLOCK_HASH, sameBlock: true, projection: pinnedProjection, reads: [],
      },
    },
  };
  const fixtureBytes = Buffer.from(JSON.stringify(fixtureDocument));
  const baselineBytes = Buffer.from(JSON.stringify(baselineDocument));
  await writeFile(join(evidenceDirectory, 'fixture.json'), fixtureBytes);
  await writeFile(join(evidenceDirectory, 'baseline.json'), baselineBytes);

  const prep = {
    preparation_id: PREPARATION_ID, claim_id: CLAIM_ID, lease_id: LEASE_ID, environment_id: ENVIRONMENT_ID,
    release_identity: releaseIdentity, manifest_hash: manifestHash, task_id: 'S1', case_id: taskCase.caseId,
    case_hash: taskCase.caseHash, initial_state_sha256: initialStateSha256, execution_identity_hash: executionIdentityHash,
    environment_manifest_sha256: environmentManifestHash, application_source_hash: applicationSourceHash, created_at: createdAt,
    lease_state: 'leased', observation_status: 'ready', generation_id: GENERATION_ID, participant_id: PARTICIPANT_ID,
    payer_address: PARTICIPANT, baseline_state_sha256: initialStateSha256,
    fixture_evidence: ref('artifacts/runs/owner-identity-bef-task-coordinator/preparation/fixture.json', fixtureBytes),
    baseline_evidence: ref('artifacts/runs/owner-identity-bef-task-coordinator/preparation/baseline.json', baselineBytes),
  };
  const actionCutoff = '0';
  const runRow = {
    owner_id: OWNER_ID, agent_id: AGENT_ID, mode: 'training', task_ids: ['S1'], release_identity: releaseIdentity,
    manifest_hash: manifestHash, environment_id: 'synthetic-successor-env', task_id: 'S1', closure_status: 'closed',
    closure_id: CLOSURE_ID, closure_operation_id: null, closure_payload_hash: HASH_B, closure_reason: 'agent_finish',
    action_cutoff_sequence: actionCutoff, reconciled_action_sequence: '0',
  };
  const closureRow = {
    id: CLOSURE_ID, operation_id: null, payload_hash: HASH_B, reason: 'agent_finish', action_cutoff_sequence: actionCutoff,
    owner_id: OWNER_ID, agent_id: AGENT_ID,
  };
  const executionRow = {
    env_id: ENVIRONMENT_ID, generation_id: GENERATION_ID, manifest_hash: environmentManifestHash,
    application_source_hash: applicationSourceHash, participant_id: PARTICIPANT_ID, payer_address: PARTICIPANT,
  };
  const extraAmount = '500000';
  const extraTransferInput = `0xa9059cbb${RECIPIENT.slice(2).padStart(64, '0')}${BigInt(extraAmount).toString(16).padStart(64, '0')}`;
  const extraCommand = { kind: 'transfer', amountUnits: extraAmount, recipient: RECIPIENT, gasLimit: '80000' };
  const actionId = '20000000-0000-4000-8000-000000000011';
  const ownerOperationId = 'owner-op-s1-0001';
  const transferLog = {
    address: TOKEN, topics: [TRANSFER_TOPIC, `0x${PARTICIPANT.slice(2).padStart(64, '0')}`, `0x${RECIPIENT.slice(2).padStart(64, '0')}`],
    data: `0x${BigInt(extraAmount).toString(16).padStart(64, '0')}`, transactionHash: EXTRA_TX_HASH,
    blockHash: EXTRA_BLOCK_HASH, blockNumber: '0x1', transactionIndex: '0x0', logIndex: '0x0', removed: false,
  };
  const requestSha256 = '6'.repeat(64);
  const selectedAction = { kind: 'transfer', amountUnits: extraAmount, recipient: RECIPIENT, gasLimit: '80000' };
  const measurementSelectedAction = { ...selectedAction, token: options.measurementToken ?? TOKEN };
  const prestate = {
    blockNumber: '0', payerNativeWei: '1000000000000000000', payerWethUnits: '0', payerUsdcUnits: '9000000',
    recipientWethUnits: '0', recipientUsdcUnits: '2500000', wethRouterAllowance: '0', usdcRouterAllowance: '0',
    poolWethUnits: '0', poolUsdcUnits: '0', poolLiquidity: '1', poolSqrtPriceX96: '1',
  };
  const poststate = {
    blockNumber: '1', payerNativeWei: '999999999997900000', payerWethUnits: '0', payerUsdcUnits: '8500000',
    recipientWethUnits: '0', recipientUsdcUnits: '3000000', wethRouterAllowance: '0', usdcRouterAllowance: '0',
    poolWethUnits: '0', poolUsdcUnits: '0', poolLiquidity: '1', poolSqrtPriceX96: '1',
  };
  const transactionIntent = {
    hash: EXTRA_TX_HASH, type: 'eip1559', chainId: 31337, blockHash: null, blockNumber: null, transactionIndex: null,
    from: PARTICIPANT, to: TOKEN, nonce: '0', input: extraTransferInput, valueWei: '0', gasLimit: '80000',
    maxFeePerGasWei: '100', maxPriorityFeePerGasWei: '10',
  };
  const transaction = { ...transactionIntent, blockHash: EXTRA_BLOCK_HASH, blockNumber: '1', transactionIndex: '0' };
  const measurement = {
    receipt: {
      transactionHash: EXTRA_TX_HASH, from: PARTICIPANT, to: TOKEN, status: 'success', blockHash: EXTRA_BLOCK_HASH,
      blockNumber: '1', gasUsed: '21000', effectiveGasPrice: '100', gasCostWei: '2100000', logs: [transferLog],
    },
    transaction,
    payerBlock: { hash: EXTRA_BLOCK_HASH, number: '1', parentHash: BLOCK_HASH, baseFeePerGasWei: '100',
      transactions: [{ hash: EXTRA_TX_HASH, from: PARTICIPANT }] },
    selectedAction: measurementSelectedAction, before: prestate, after: poststate,
    effects: { payerNativeWei: '-2100000', payerUsdcUnits: '-500000', recipientUsdcUnits: '500000' },
    quote: null,
    fee: { modeledGasFeeUsdcUnits: '1', baseL1Fee: 'unmodelled', principalAsset: 'USDC', selectedPrincipalUnits: extraAmount, principalUnits: extraAmount },
    taskEvaluationInputs: {
      expenseBudgetUsdcUnits: '100000', recipient: RECIPIENT, allowanceAssetId: 'WETH', allowanceAfterUnits: '0',
      nativeEthReserveWei: '100000000000000000', allowanceCleanupExpected: true, selectedMinimumOutputUnits: null,
    },
  };
  const extraOperation = {
    operation_id: '10000000-0000-4000-8000-000000000010', env_id: ENVIRONMENT_ID, generation_id: GENERATION_ID,
    participant_id: PARTICIPANT_ID, idempotency_key_sha256: createHash('sha256').update(options.admittedAction
      ? `task-action-${actionId}` : 'unadmitted-transfer').digest('hex'),
    request_sha256: requestSha256,
    operation_kind: 'transfer', status: 'settled', receipt_status: 'success', transaction_hash: EXTRA_TX_HASH,
    response_sha256: options.operationResponseHash === undefined ? null : options.operationResponseHash,
  };
  const extraSelectedExecution = {
    operation_id: extraOperation.operation_id, env_id: ENVIRONMENT_ID, generation_id: GENERATION_ID,
    action_kind: 'transfer', selected_action_json: selectedAction, prestate_json: prestate,
    transaction_intent_json: transactionIntent, measurement_json: measurement,
    transaction_hash: EXTRA_TX_HASH, outcome: 'success', reason_code: null, completed_at: createdAt,
  };
  const extraEvents = ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'].map((event_kind, index) => ({
    event_sequence: String(index + 1), event_id: `10000000-0000-4000-8000-00000000001${index + 1}`,
    operation_id: extraOperation.operation_id, env_id: ENVIRONMENT_ID, generation_id: GENERATION_ID, event_kind,
    transaction_hash: ['original_tx_hash_bound', 'receipt_finalized'].includes(event_kind) ? EXTRA_TX_HASH : null,
    event_json: structuredClone(event_kind === 'selected_action_bound'
      ? { actionKind: 'transfer', selectedAction, requestSha256 }
      : event_kind === 'prestate_observed'
        ? { prestate }
        : event_kind === 'original_tx_hash_bound'
          ? { transactionHash: EXTRA_TX_HASH, transactionIntent, requestSha256 }
          : { outcome: 'success', measurement }),
    created_at: createdAt,
  }));
  const extraCost = {
    operation_id: extraOperation.operation_id, env_id: ENVIRONMENT_ID, generation_id: GENERATION_ID,
    transaction_hash: EXTRA_TX_HASH, payer_address: PARTICIPANT, payer_role: 'participant', receipt_status: 'success',
    transaction_from: PARTICIPANT, receipt_from: PARTICIPANT, receipt_block_number: '1', receipt_block_hash: EXTRA_BLOCK_HASH,
    receipt_block_parent_hash: BLOCK_HASH, gas_used: '21000', effective_gas_price_wei: '100', gas_cost_wei: '2100000',
    modeled_gas_fee_usdc_units: null, manifest_sha256: environmentManifestHash, selected_principal_asset: 'USDC',
    selected_principal_units: extraAmount, observed_principal_units: extraAmount, created_at: createdAt,
  };
  const operations = options.extraTransfer ? [extraOperation] : [];
  const selectedExecutions = options.extraTransfer ? [extraSelectedExecution] : [];
  const selectedEvents = options.extraTransfer ? extraEvents : [];
  const costs = options.extraTransfer ? [extraCost] : [];
  const cutoff = options.admittedAction ? '1' : '0';
  const actionEvidencePath = `artifacts/runs/owner-identity-bef-task-coordinator/action/${actionId}.json`;
  const actionPayloadHash = sha256CanonicalTaskJson({ runId: RUN_ID, taskIndex: 0, command: extraCommand });
  const actionSelected = { ...selectedAction, token: options.selectedActionToken ?? TOKEN,
    ...(options.selectedActionApiToken === undefined ? {} : { apiToken: options.selectedActionApiToken }) };
  const actionEvidenceBytes = Buffer.from(JSON.stringify({
    schema: 'bef-task-action-observation-v1', actionId, runId: RUN_ID, taskIndex: 0, actionSequence: '1',
    ownerOperationId, actionKind: 'transfer', commandSha256: options.bareCommandHash ? sha256CanonicalTaskJson(extraCommand) : actionPayloadHash,
    environmentId: ENVIRONMENT_ID, generationId: GENERATION_ID, manifestSha256: environmentManifestHash,
    applicationSourceSha256: applicationSourceHash, idempotencyKey: `task-action-${actionId}`, status: 'observed',
    requestStartedAt: createdAt, requestFinishedAt: createdAt, httpStatus: 200,
    befOperationId: extraOperation.operation_id, transactionHash: EXTRA_TX_HASH, outcome: 'success', receiptStatus: 'success',
    rawResponseSha256: '7'.repeat(64), receiptGasUsed: '21000', receiptEffectiveGasPriceWei: '100',
    participantToolResponse: {
      operationId: extraOperation.operation_id, outcome: 'success',
      selectedAction: actionSelected,
      transaction: { hash: EXTRA_TX_HASH, from: PARTICIPANT, to: TOKEN, input: extraTransferInput },
      receipt: { transactionHash: EXTRA_TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '100' },
    },
  }));
  if (options.admittedAction) await writeFile(join(actionEvidenceDirectory, `${actionId}.json`), actionEvidenceBytes);
  const admittedActionRow = options.admittedAction ? {
    id: actionId, run_id: RUN_ID, task_index: 0, owner_id: OWNER_ID, agent_id: AGENT_ID, task_id: 'S1',
    environment_id: ENVIRONMENT_ID, action_sequence: '1', operation_id: ownerOperationId,
    payload_hash: options.bareCommandHash ? sha256CanonicalTaskJson(extraCommand) : actionPayloadHash,
    action_kind: 'transfer', command_json: extraCommand,
    receipt_revision: 1, receipt_status: 'observed', evidence_hash: createHash('sha256').update(actionEvidenceBytes).digest('hex'),
    evidence_path: actionEvidencePath, transaction_hash: EXTRA_TX_HASH, history_revision: 1, history_status: 'observed',
    history_evidence_hash: createHash('sha256').update(actionEvidenceBytes).digest('hex'), history_evidence_path: actionEvidencePath,
    history_transaction_hash: EXTRA_TX_HASH,
  } : null;
  const ownerResults: unknown[][] = [
    [{ owner_id: OWNER_ID, agent_id: AGENT_ID }], [], [], [runRow], [closureRow], [prep], [executionRow], [],
  ];
  if (admittedActionRow) {
    runRow.action_cutoff_sequence = cutoff;
    runRow.reconciled_action_sequence = cutoff;
    closureRow.action_cutoff_sequence = cutoff;
    ownerResults[ownerResults.length - 1] = [admittedActionRow];
  }
  const fakeTx = { execute: async () => ownerResults.shift() ?? [] };
  const db = { transaction: async (callback: (tx: unknown) => Promise<unknown>) => callback(fakeTx) } as unknown as OwnerDatabase;

  const postgres = {
    environmentId: ENVIRONMENT_ID,
    withRepeatableRead: async <T>(callback: (query: (statement: string) => Promise<unknown>) => Promise<T>) => callback(async (statement) => {
      switch (queryName(statement)) {
        case 'session': return [{ current_user: 'bef_observer', session_user: 'bef_observer', database_name: 'bef_synthetic',
          transaction_read_only: 'on', transaction_isolation: 'repeatable read', rolsuper: false, rolbypassrls: false, schema_create: false }];
        case 'privileges': return ['bef_generation', 'bef_operation', 'bef_selected_execution', 'bef_selected_execution_event',
          'bef_payment', 'bef_delivery', 'bef_transaction_cost'].map((table_name) => ({
          table_name, can_select: true, can_insert: options.writableObserver ? table_name === 'bef_operation' : false,
          can_update: false, can_delete: false, can_truncate: false,
        }));
        case 'generation': return [{
          generation_id: GENERATION_ID, env_id: ENVIRONMENT_ID, participant_id: PARTICIPANT_ID, payer_address: PARTICIPANT,
          manifest_sha256: environmentManifestHash, status: 'active', resource_variant: null, fixture_transaction_hash: null,
          fixture_block_hash: null, fixture_token_delta_units: null, fixture_native_balance_wei: null,
          expires_at: null, fenced_at: null, chain_id: '31337', node_identity: 'synthetic-local',
          environment_manifest_sha256: environmentManifestHash,
        }];
        case 'operations': return operations;
        case 'executions': return selectedExecutions;
        case 'events': return selectedEvents;
        case 'payments': case 'deliveries': return [];
        case 'costs': return costs;
        case 'counts': return [{ operations: String(operations.length), selected_executions: String(selectedExecutions.length),
          selected_events: String(selectedEvents.length), payments: '0', deliveries: '0', costs: String(costs.length) }];
        default: return [];
      }
    }),
  };
  const rpc = {
    environmentId: ENVIRONMENT_ID,
    request: async (method: string, params: readonly unknown[]) => {
      if (method === 'eth_chainId') return '0x7a69';
      if (method === 'eth_blockNumber') return options.extraTransfer ? '0x1' : '0x0';
      if (method === 'eth_getTransactionCount') return options.extraTransfer && params[1] === '0x1' ? '0x1' : '0x0';
      if (method === 'eth_getBlockByNumber') {
        const tag = params[0];
        if (tag === '0x1' && options.extraTransfer) return {
          number: '0x1', hash: EXTRA_BLOCK_HASH, parentHash: BLOCK_HASH, baseFeePerGas: '0x64',
          transactions: [{ hash: EXTRA_TX_HASH, type: '0x2', chainId: '0x7a69', from: PARTICIPANT, to: TOKEN, nonce: '0x0', value: '0x0',
            gas: '0x13880', maxFeePerGas: '0x64', maxPriorityFeePerGas: '0xa', input: extraTransferInput,
            blockNumber: '0x1', blockHash: EXTRA_BLOCK_HASH, transactionIndex: '0x0' }],
        };
        return { number: '0x0', hash: BLOCK_HASH, parentHash: PARENT_HASH, transactions: [] };
      }
      if (method === 'eth_getBalance') {
        return `0x${(10n ** 18n - (options.extraTransfer && params[1] === '0x1' ? 2100000n : 0n)).toString(16)}`;
      }
      if (method === 'eth_getCode') return CODE;
      if (method === 'eth_getLogs') return options.extraTransfer ? [transferLog] : [];
      if (method === 'eth_getTransactionByHash' && options.extraTransfer) return {
        hash: EXTRA_TX_HASH, type: '0x2', chainId: '0x7a69', from: PARTICIPANT, to: TOKEN, nonce: '0x0', value: '0x0',
        gas: '0x13880', maxFeePerGas: '0x64', maxPriorityFeePerGas: '0xa', input: extraTransferInput,
        blockNumber: '0x1', blockHash: EXTRA_BLOCK_HASH, transactionIndex: '0x0',
      };
      if (method === 'eth_getTransactionReceipt' && options.extraTransfer) return {
        transactionHash: EXTRA_TX_HASH, blockNumber: '0x1', blockHash: EXTRA_BLOCK_HASH, transactionIndex: '0x0',
        status: '0x1', gasUsed: '0x5208', effectiveGasPrice: '0x64', from: PARTICIPANT, to: TOKEN, logs: [transferLog],
      };
      if (method === 'eth_call') {
        const call = params[0] as { data: string };
        const address = `0x${call.data.slice(-40)}`.toLowerCase();
        const isFinal = params[1] === '0x1' && options.extraTransfer;
        const amount = address === RECIPIENT ? isFinal ? 3000000n : 2500000n
          : address === PARTICIPANT ? isFinal ? 8500000n : 9000000n : 0n;
        return `0x${amount.toString(16).padStart(64, '0')}`;
      }
      throw new Error(`unexpected RPC method: ${method}`);
    },
  };
  let savedPacket: BefS1RunObservationPacket | null = null;
  const evidenceSink = {
    write: async (packet: BefS1RunObservationPacket): Promise<EvidenceReference> => {
      savedPacket = packet;
      const bytes = Buffer.from(canonicalTaskJson(packet));
      return ref('artifacts/runs/owner-identity-bef-task-coordinator/observation/synthetic-zero-action.json', bytes);
    },
  };
  const dependencies: BefS1ObservationCollectorDependencies = {
    db,
    taskReleaseSource: { getValidatedReleaseRecord: async () => release } as never,
    repositoryRoot,
    postgresByEnvironment: { [ENVIRONMENT_ID]: postgres },
    rpcByEnvironment: { [ENVIRONMENT_ID]: rpc },
    evidenceSink,
  };

  return {
    dependencies,
    close: () => rm(repositoryRoot, { recursive: true, force: true }),
    getPacket: () => savedPacket,
    tamperEvent: (eventKind: string, update: (eventJson: Record<string, unknown>) => void) => {
      const event = selectedEvents.find((row) => row.event_kind === eventKind);
      if (!event || typeof event.event_json !== 'object' || event.event_json === null || Array.isArray(event.event_json)) {
        throw new Error(`missing synthetic ${eventKind} event`);
      }
      update(event.event_json as Record<string, unknown>);
    },
  };
}

test('synthetic S1 zero-action closure yields a complete no-effect candidate without grading', async () => {
  const fixture = await createZeroActionFixture();
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.equal(result.status, 'candidate', JSON.stringify(result));
    if (result.status !== 'candidate') return;
    const candidate: TaskObservationBundleCandidate = result.candidate;
    assert.equal(candidate.observationCutoffSequence, 1);
    assert.equal(candidate.cutoffStatus, 'authoritative');
    assert.deepEqual(candidate.observations?.coverage, { transfers: 'complete', balances: 'complete', expenses: 'complete' });
    assert.deepEqual(candidate.observations?.transfers, []);
    assert.deepEqual(candidate.observations?.expenses, []);
    assert.equal(candidate.observations?.finalStates.length, 1);
    assert.equal(candidate.observations?.finalStates[0]?.actionSequence, 0);
    assert.equal(candidate.observations?.finalStates[0]?.kind, 'final_state');
    assert.equal(fixture.getPacket()?.closure.actionCutoffSequence, 0);
    assert.deepEqual(fixture.getPacket()?.ownerActions, []);
    assert.deepEqual(fixture.getPacket()?.bef.before.operations, []);
    assert.deepEqual(fixture.getPacket()?.rpc.intervalBlocks, []);
    assert.equal(fixture.getPacket()?.rpc.baseline.blockHash, fixture.getPacket()?.rpc.final.blockHash);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 collector leaves evidence unavailable when observer write privileges are present', async () => {
  const fixture = await createZeroActionFixture({ writableObserver: true });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'observer_role_invalid' });
    assert.equal(fixture.getPacket(), null);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 preserves a successful unadmitted transfer as an actionSequence-zero chain fact', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.equal(result.status, 'candidate', JSON.stringify(result));
    if (result.status !== 'candidate') return;
    const candidate = result.candidate;
    assert.equal(candidate.observations?.transfers.length, 1);
    assert.equal(candidate.observations?.transfers[0]?.amountUnits, '500000');
    assert.equal(candidate.observations?.transfers[0]?.to, RECIPIENT);
    assert.equal(candidate.observations?.transfers[0]?.actionSequence, 0);
    assert.equal(candidate.observations?.expenses.length, 1);
    assert.equal(candidate.observations?.expenses[0]?.actionSequence, 0);
    assert.equal(fixture.getPacket()?.closure.actionCutoffSequence, 0);
    assert.equal(fixture.getPacket()?.ownerActions.length, 0);
    assert.equal(fixture.getPacket()?.bef.before.operations.length, 1);
    assert.equal(fixture.getPacket()?.rpc.receipts[0]?.transactionHash, EXTRA_TX_HASH);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 joins an admitted owner action to a distinct BEF operation and preserves its wrong amount', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.equal(result.status, 'candidate', JSON.stringify(result));
    if (result.status !== 'candidate') return;
    assert.equal(result.candidate.observations?.transfers.length, 1);
    assert.equal(result.candidate.observations?.transfers[0]?.amountUnits, '500000');
    assert.equal(result.candidate.observations?.transfers[0]?.actionSequence, 1);
    const action = fixture.getPacket()?.ownerActions[0];
    assert.ok(action);
    assert.notEqual(action.actionId, action.ownerOperationId);
    assert.notEqual(action.ownerOperationId, action.befOperationId);
    assert.equal(action.befOperationId, '10000000-0000-4000-8000-000000000010');
    assert.notEqual(result.candidate.observations?.binding.manifestHash, fixture.getPacket()?.execution.environmentManifestHash);
    assert.equal(fixture.getPacket()?.bef.before.operations[0]?.response_sha256, null);
    assert.equal((fixture.getPacket()?.ownerActions[0]?.actionEvidence.sha256 ?? '').length, 64);
    const selectedEvent = fixture.getPacket()?.bef.before.selectedEvents.find((event) => event.event_kind === 'selected_action_bound');
    assert.ok(selectedEvent && typeof selectedEvent.event_json_sha256 === 'string');
    assert.equal(Object.hasOwn(selectedEvent, 'event_json'), false);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 admits only the public selectedAction.token address and binds it to the BEF selected execution', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.equal(result.status, 'candidate', JSON.stringify(result));
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 rejects credential-shaped or non-address selectedAction.token values', async () => {
  for (const variant of [
    { options: { selectedActionToken: 'api-token-secret' }, reasonCode: 'action_evidence_unavailable' },
    { options: { selectedActionToken: RECIPIENT }, reasonCode: 'rpc_mapping_incomplete' },
    { options: { measurementToken: RECIPIENT }, reasonCode: 'rpc_mapping_incomplete' },
  ]) {
    const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true, ...variant.options });
    try {
      const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
      assert.equal(result.status, 'unavailable');
      if (result.status === 'unavailable') {
        assert.equal(result.reasonCode, variant.reasonCode);
      }
      assert.equal(fixture.getPacket(), null);
    } finally {
      await fixture.close();
    }
  }
});

test('synthetic S1 rejects a malformed optional BEF response digest while retaining null unchanged', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true, operationResponseHash: 'not-a-digest' });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'rpc_mapping_incomplete' });
    assert.equal(fixture.getPacket(), null);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 rejects API-token fields in retained participant action evidence', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true, selectedActionApiToken: 'credential' });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'action_evidence_unavailable' });
    assert.equal(fixture.getPacket(), null);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 rejects the obsolete bare-command action digest', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true, admittedAction: true, bareCommandHash: true });
  try {
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'action_evidence_unavailable' });
    assert.equal(fixture.getPacket(), null);
  } finally {
    await fixture.close();
  }
});

test('synthetic S1 rejects an immutable event payload that contradicts the selected execution row', async () => {
  const fixture = await createZeroActionFixture({ extraTransfer: true });
  try {
    fixture.tamperEvent('selected_action_bound', (eventJson) => {
      const action = eventJson.selectedAction as Record<string, unknown>;
      action.amountUnits = '500001';
    });
    const result = await collectBefS1TaskObservationCandidate(fixture.dependencies, { runId: RUN_ID, taskIndex: 0 });
    assert.deepEqual(result, { status: 'unavailable', reasonCode: 'rpc_mapping_incomplete' });
    assert.equal(fixture.getPacket(), null);
  } finally {
    await fixture.close();
  }
});
