/**
 * PostgreSQL adapter for participant-selected local-chain actions. Callers
 * hold the environment advisory lock and wrap every mutation in a transaction.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { Address, Hex } from 'viem';
import {
  parseSelectedAction,
  type ExecutionMeasurement,
  type ExecutionPersistence,
  type ExecutionSnapshot,
  type ExecutionTransactionObservation,
  type OperationRecord,
  type ParticipantAuth,
  type SelectedAction,
} from './selected-execution.js';
import {
  finalizeTransactionCost,
  insertUnknownTransactionCost,
  type CostIdentity,
  type FeePolicySnapshot,
} from './transaction-costs.js';

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const HEX_BYTES = /^0x(?:[0-9a-f]{2})*$/i;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const SIGNED_DECIMAL = /^-?(?:0|[1-9][0-9]{0,77})$/;
const ACTION_KINDS = new Set(['approve', 'wrap', 'unwrap', 'swap']);

type OperationRow = {
  operation_id: string;
  env_id: string;
  generation_id: string;
  participant_id: string;
  operation_kind: string;
  status: string;
  request_sha256: string;
  transaction_hash: string | null;
  receipt_status: string;
};

type SelectedExecutionRow = {
  operation_id: string;
  env_id: string;
  generation_id: string;
  action_kind: string;
  selected_action_json: unknown;
  prestate_json: unknown;
  transaction_intent_json: unknown;
  transaction_hash: string | null;
  outcome: string;
  reason_code: string | null;
  measurement_json: unknown;
};

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function fail(reason: string): never {
  throw new Error(reason);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function decodeJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try { return JSON.parse(value) as unknown; } catch { return fail('execution_persistence_json_invalid'); }
}

function asObject(value: unknown, reason: string): Record<string, unknown> {
  const decoded = decodeJson(value);
  if (!isRecord(decoded)) return fail(reason);
  return decoded;
}

function decimal(value: unknown, reason: string): string {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return fail(reason);
  return value;
}

function address(value: unknown, reason: string): Address {
  if (typeof value !== 'string' || !ADDRESS.test(value)) return fail(reason);
  return value as Address;
}

function transactionHash(value: unknown, reason: string): Hex {
  if (typeof value !== 'string' || !HASH.test(value)) return fail(reason);
  return value as Hex;
}

export function parsePersistedAction(value: unknown, expectedKind?: string): SelectedAction {
  const object = asObject(value, 'execution_persistence_action_invalid');
  const kind = object.kind;
  if (typeof kind !== 'string' || !ACTION_KINDS.has(kind) || (expectedKind && kind !== expectedKind)) {
    return fail('execution_persistence_action_invalid');
  }
  const { kind: _kind, ...payload } = object;
  const parsed = parseSelectedAction(kind as SelectedAction['kind'], payload);
  if (!parsed) return fail('execution_persistence_action_invalid');
  return parsed;
}

const selectedAction = parsePersistedAction;

function snapshot(value: unknown): ExecutionSnapshot {
  const object = asObject(value, 'execution_persistence_prestate_invalid');
  const names = [
    'blockNumber', 'payerNativeWei', 'payerWethUnits', 'payerUsdcUnits',
    'recipientUsdcUnits', 'wethRouterAllowance', 'poolWethUnits', 'poolUsdcUnits',
    'poolLiquidity', 'poolSqrtPriceX96',
  ] as const;
  if (Object.keys(object).length !== names.length || names.some((name) => !(name in object))) {
    return fail('execution_persistence_prestate_invalid');
  }
  const result = Object.fromEntries(names.map((name) => [name, decimal(object[name], 'execution_persistence_prestate_invalid')])) as ExecutionSnapshot;
  return result;
}

function transactionIntent(value: unknown): ExecutionTransactionObservation {
  const object = asObject(value, 'execution_persistence_intent_invalid');
  const hash = transactionHash(object.hash, 'execution_persistence_intent_invalid');
  if (object.type !== 'eip1559' || !Number.isSafeInteger(object.chainId) || (object.chainId as number) <= 0 ||
      (object.blockHash !== null && (typeof object.blockHash !== 'string' || !HASH.test(object.blockHash))) ||
      (object.blockNumber !== null && (typeof object.blockNumber !== 'string' || !DECIMAL.test(object.blockNumber))) ||
      (object.transactionIndex !== null && (typeof object.transactionIndex !== 'string' || !DECIMAL.test(object.transactionIndex))) ||
      typeof object.input !== 'string' || !HEX_BYTES.test(object.input)) {
    return fail('execution_persistence_intent_invalid');
  }
  const maxFeePerGasWei = object.maxFeePerGasWei === null
    ? null : decimal(object.maxFeePerGasWei, 'execution_persistence_intent_invalid');
  const maxPriorityFeePerGasWei = object.maxPriorityFeePerGasWei === null
    ? null : decimal(object.maxPriorityFeePerGasWei, 'execution_persistence_intent_invalid');
  return {
    hash,
    type: 'eip1559',
    chainId: object.chainId as number,
    blockHash: object.blockHash as Hex | null,
    blockNumber: object.blockNumber as string | null,
    transactionIndex: object.transactionIndex as string | null,
    from: address(object.from, 'execution_persistence_intent_invalid'),
    to: object.to === null ? null : address(object.to, 'execution_persistence_intent_invalid'),
    nonce: decimal(object.nonce, 'execution_persistence_intent_invalid'),
    input: object.input as Hex,
    valueWei: decimal(object.valueWei, 'execution_persistence_intent_invalid'),
    gasLimit: decimal(object.gasLimit, 'execution_persistence_intent_invalid'),
    maxFeePerGasWei,
    maxPriorityFeePerGasWei,
  };
}

function exactKeys(object: Record<string, unknown>, keys: readonly string[], reason: string): void {
  const actual = Object.keys(object).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(reason);
}

function encodedAddressWord(value: unknown, reason: string): string {
  return address(value, reason).slice(2).toLowerCase().padStart(64, '0');
}

function encodedUintWord(value: bigint, reason: string): string {
  if (value < 0n || value >= (1n << 256n)) fail(reason);
  return value.toString(16).padStart(64, '0');
}

function calldataWords(transaction: ExecutionTransactionObservation, selector: string, count: number): string[] {
  const data = transaction.input.toLowerCase();
  if (!data.startsWith(selector) || data.length !== selector.length + count * 64) {
    return fail('execution_persistence_measurement_action_calldata_invalid');
  }
  return Array.from({ length: count }, (_, index) => data.slice(selector.length + index * 64, selector.length + (index + 1) * 64));
}

function actionFromMeasurement(
  value: unknown,
  transaction: ExecutionTransactionObservation,
  receipt: Record<string, unknown>,
): SelectedAction {
  const object = asObject(value, 'execution_persistence_measurement_invalid');
  const kind = object.kind;
  if (typeof kind !== 'string' || !ACTION_KINDS.has(kind)) return fail('execution_persistence_measurement_invalid');

  if (kind === 'approve') {
    exactKeys(object, ['kind', 'token', 'spender', 'amountUnits', 'gasLimit'], 'execution_persistence_measurement_action_invalid');
    const token = address(object.token, 'execution_persistence_measurement_action_invalid');
    const spender = address(object.spender, 'execution_persistence_measurement_action_invalid');
    const action = selectedAction({ kind, amountUnits: object.amountUnits, gasLimit: object.gasLimit }, kind);
    if (action.kind !== 'approve') return fail('execution_persistence_measurement_action_invalid');
    if (transaction.to?.toLowerCase() !== token.toLowerCase() || transaction.valueWei !== '0') {
      return fail('execution_persistence_measurement_action_binding_conflict');
    }
    const amount = BigInt(action.amountUnits);
    const expectedInput = `0x095ea7b3${encodedAddressWord(spender, 'execution_persistence_measurement_action_invalid')}${encodedUintWord(amount, 'execution_persistence_measurement_action_invalid')}`;
    if (transaction.input.toLowerCase() !== expectedInput) return fail('execution_persistence_measurement_action_binding_conflict');

    if (receipt.status === 'success') {
      const ownerTopic = `0x${address(receipt.from, 'execution_persistence_measurement_invalid').slice(2).toLowerCase().padStart(64, '0')}`;
      const spenderTopic = `0x${spender.slice(2).toLowerCase().padStart(64, '0')}`;
      const hasApproval = (receipt.logs as unknown[]).some((value) => {
        if (!isRecord(value)) return false;
        const topics = value.topics;
        return typeof value.address === 'string' && value.address.toLowerCase() === token.toLowerCase() &&
          Array.isArray(topics) && topics.length >= 3 &&
          typeof topics[0] === 'string' && topics[0].toLowerCase() === '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925' &&
          typeof topics[1] === 'string' && topics[1].toLowerCase() === ownerTopic &&
          typeof topics[2] === 'string' && topics[2].toLowerCase() === spenderTopic &&
          typeof value.data === 'string' && value.data.toLowerCase() === `0x${encodedUintWord(amount, 'execution_persistence_measurement_action_invalid')}`;
      });
      if (!hasApproval) return fail('execution_persistence_measurement_action_receipt_conflict');
    }
    return action;
  }

  if (kind === 'wrap' || kind === 'unwrap') {
    exactKeys(object, ['kind', 'amountWei', 'gasLimit'], 'execution_persistence_measurement_action_invalid');
    return selectedAction({ kind, amountWei: object.amountWei, gasLimit: object.gasLimit }, kind);
  }

  exactKeys(object, [
    'kind', 'route', 'router', 'tokenIn', 'tokenOut', 'fee', 'amountInWei',
    'amountOutMinimumUsdcUnits', 'recipient', 'gasLimit',
  ], 'execution_persistence_measurement_action_invalid');
  const router = address(object.router, 'execution_persistence_measurement_action_invalid');
  const tokenIn = address(object.tokenIn, 'execution_persistence_measurement_action_invalid');
  const tokenOut = address(object.tokenOut, 'execution_persistence_measurement_action_invalid');
  const fee = object.fee;
  if (object.route !== 'uniswap-v3-exactInputSingle' || !Number.isSafeInteger(fee) || (fee as number) <= 0 || (fee as number) > 0xffffff) {
    return fail('execution_persistence_measurement_action_invalid');
  }
  const action = selectedAction({
    kind,
    amountInWei: object.amountInWei,
    amountOutMinimumUsdcUnits: object.amountOutMinimumUsdcUnits,
    recipient: object.recipient,
    gasLimit: object.gasLimit,
  }, kind);
  if (action.kind !== 'swap') return fail('execution_persistence_measurement_action_invalid');
  if (transaction.to?.toLowerCase() !== router.toLowerCase() || transaction.valueWei !== '0') {
    return fail('execution_persistence_measurement_action_binding_conflict');
  }
  const words = calldataWords(transaction, '0x04e45aaf', 7);
  const expectedWords = [
    encodedAddressWord(tokenIn, 'execution_persistence_measurement_action_invalid'),
    encodedAddressWord(tokenOut, 'execution_persistence_measurement_action_invalid'),
    encodedUintWord(BigInt(fee as number), 'execution_persistence_measurement_action_invalid'),
    encodedAddressWord(action.recipient, 'execution_persistence_measurement_action_invalid'),
    encodedUintWord(BigInt(action.amountInWei), 'execution_persistence_measurement_action_invalid'),
    encodedUintWord(BigInt(action.amountOutMinimumUsdcUnits), 'execution_persistence_measurement_action_invalid'),
    encodedUintWord(0n, 'execution_persistence_measurement_action_invalid'),
  ];
  if (words.some((word, index) => word !== expectedWords[index])) {
    return fail('execution_persistence_measurement_action_binding_conflict');
  }
  return action;
}

function transactionMatchesPersistedIntent(
  measured: ExecutionTransactionObservation,
  intent: ExecutionTransactionObservation,
): boolean {
  if (intent.blockHash !== null || intent.blockNumber !== null || intent.transactionIndex !== null) return false;
  const normalize = (value: ExecutionTransactionObservation) => ({
    ...value,
    hash: value.hash.toLowerCase(),
    blockHash: null,
    blockNumber: null,
    transactionIndex: null,
    from: value.from.toLowerCase(),
    to: value.to?.toLowerCase() ?? null,
    input: value.input.toLowerCase(),
  });
  return canonicalJson(normalize(measured)) === canonicalJson(normalize(intent));
}

function selectedActionInputsFromMeasurement(value: unknown): SelectedAction {
  const object = asObject(value, 'execution_persistence_measurement_invalid');
  const kind = object.kind;
  if (kind === 'approve') return selectedAction({ kind, amountUnits: object.amountUnits, gasLimit: object.gasLimit }, kind);
  if (kind === 'wrap' || kind === 'unwrap') return selectedAction({ kind, amountWei: object.amountWei, gasLimit: object.gasLimit }, kind);
  if (kind === 'swap') return selectedAction({
    kind,
    amountInWei: object.amountInWei,
    amountOutMinimumUsdcUnits: object.amountOutMinimumUsdcUnits,
    recipient: object.recipient,
    gasLimit: object.gasLimit,
  }, kind);
  return fail('execution_persistence_measurement_invalid');
}

function assertMeasurementActionBinding(measured: ExecutionMeasurement, action: SelectedAction): void {
  const persisted = selectedActionInputsFromMeasurement(measured.selectedAction);
  if (canonicalJson(persisted) !== canonicalJson(action)) fail('execution_persistence_terminal_binding_conflict');
}

function measurement(value: unknown, expectedHash: Hex, expectedStatus?: 'success' | 'reverted'): ExecutionMeasurement {
  const object = asObject(value, 'execution_persistence_measurement_invalid');
  const receipt = asObject(object.receipt, 'execution_persistence_measurement_invalid');
  const transaction = transactionIntent(object.transaction);
  const payerBlock = asObject(object.payerBlock, 'execution_persistence_measurement_invalid');
  exactKeys(payerBlock, ['hash', 'number', 'parentHash', 'baseFeePerGasWei', 'transactions'], 'execution_persistence_measurement_invalid');
  const payerBlockHash = transactionHash(payerBlock.hash, 'execution_persistence_measurement_invalid');
  const payerBlockNumber = decimal(payerBlock.number, 'execution_persistence_measurement_invalid');
  transactionHash(payerBlock.parentHash, 'execution_persistence_measurement_invalid');
  decimal(payerBlock.baseFeePerGasWei, 'execution_persistence_measurement_invalid');
  if (transaction.maxFeePerGasWei === null || transaction.maxPriorityFeePerGasWei === null ||
      !Array.isArray(payerBlock.transactions) || payerBlock.transactions.length !== 1) {
    return fail('execution_persistence_measurement_invalid');
  }
  const payerBlockTransactions = payerBlock.transactions.map((entry) => {
    const sender = asObject(entry, 'execution_persistence_measurement_invalid');
    exactKeys(sender, ['hash', 'from'], 'execution_persistence_measurement_invalid');
    return {
      hash: transactionHash(sender.hash, 'execution_persistence_measurement_invalid'),
      from: address(sender.from, 'execution_persistence_measurement_invalid'),
    };
  });
  const status = receipt.status;
  if (status !== 'success' && status !== 'reverted') return fail('execution_persistence_measurement_invalid');
  if (expectedStatus && status !== expectedStatus) return fail('execution_persistence_measurement_invalid');
  if (transaction.hash.toLowerCase() !== expectedHash.toLowerCase() ||
      transactionHash(receipt.transactionHash, 'execution_persistence_measurement_invalid').toLowerCase() !== expectedHash.toLowerCase() ||
      transaction.from.toLowerCase() !== address(receipt.from, 'execution_persistence_measurement_invalid').toLowerCase() ||
      transaction.to?.toLowerCase() !== (receipt.to === null ? null : address(receipt.to, 'execution_persistence_measurement_invalid').toLowerCase()) ||
      typeof receipt.blockHash !== 'string' || !HASH.test(receipt.blockHash) ||
      typeof receipt.logs === 'undefined' || !Array.isArray(receipt.logs)) {
    return fail('execution_persistence_measurement_invalid');
  }
  decimal(receipt.blockNumber, 'execution_persistence_measurement_invalid');
  if (payerBlockHash.toLowerCase() !== receipt.blockHash.toLowerCase() || payerBlockNumber !== receipt.blockNumber ||
      payerBlockTransactions[0]!.hash.toLowerCase() !== expectedHash.toLowerCase() ||
      payerBlockTransactions[0]!.from.toLowerCase() !== transaction.from.toLowerCase()) {
    return fail('execution_persistence_measurement_invalid');
  }
  decimal(receipt.gasUsed, 'execution_persistence_measurement_invalid');
  decimal(receipt.effectiveGasPrice, 'execution_persistence_measurement_invalid');
  decimal(receipt.gasCostWei, 'execution_persistence_measurement_invalid');
  const before = snapshot(object.before);
  const after = snapshot(object.after);
  if (!isRecord(object.selectedAction) || typeof object.selectedAction.kind !== 'string' || !ACTION_KINDS.has(object.selectedAction.kind)) {
    return fail('execution_persistence_measurement_invalid');
  }
  if (!isRecord(object.effects) || Object.values(object.effects).some((entry) => typeof entry !== 'string' || !SIGNED_DECIMAL.test(entry))) {
    return fail('execution_persistence_measurement_invalid');
  }
  const fee = asObject(object.fee, 'execution_persistence_measurement_invalid');
  decimal(fee.modeledGasFeeUsdcUnits, 'execution_persistence_measurement_invalid');
  const selectedPrincipalUnits = decimal(fee.selectedPrincipalUnits, 'execution_persistence_measurement_invalid');
  const principalUnits = decimal(fee.principalUnits, 'execution_persistence_measurement_invalid');
  if (fee.baseL1Fee !== 'unmodelled' ||
      (fee.principalAsset !== null && fee.principalAsset !== 'ETH' && fee.principalAsset !== 'WETH')) {
    return fail('execution_persistence_measurement_invalid');
  }
  const parsedAction = actionFromMeasurement(object.selectedAction, transaction, receipt);
  const expectedSelectedPrincipalUnits = parsedAction.kind === 'wrap' || parsedAction.kind === 'unwrap' ? parsedAction.amountWei
    : parsedAction.kind === 'swap' ? parsedAction.amountInWei : '0';
  if (selectedPrincipalUnits !== expectedSelectedPrincipalUnits ||
      principalUnits !== (status === 'success' ? selectedPrincipalUnits : '0')) {
    return fail('execution_persistence_measurement_invalid');
  }
  const task = asObject(object.taskEvaluationInputs, 'execution_persistence_measurement_invalid');
  decimal(task.expenseBudgetUsdcUnits, 'execution_persistence_measurement_invalid');
  decimal(task.allowanceAfterUnits, 'execution_persistence_measurement_invalid');
  decimal(task.nativeEthReserveWei, 'execution_persistence_measurement_invalid');
  if (typeof task.allowanceCleanupExpected !== 'boolean' ||
      (task.recipient !== null && (typeof task.recipient !== 'string' || !ADDRESS.test(task.recipient))) ||
      (task.selectedMinimumOutputUnits !== null && (typeof task.selectedMinimumOutputUnits !== 'string' || !DECIMAL.test(task.selectedMinimumOutputUnits)))) {
    return fail('execution_persistence_measurement_invalid');
  }
  for (const logValue of receipt.logs) {
    const log = asObject(logValue, 'execution_persistence_measurement_invalid');
    address(log.address, 'execution_persistence_measurement_invalid');
    if (!Array.isArray(log.topics) || log.topics.some((topic) => typeof topic !== 'string' || !HASH.test(topic)) ||
        typeof log.data !== 'string' || !HEX_BYTES.test(log.data)) {
      return fail('execution_persistence_measurement_invalid');
    }
  }
  snapshot(before);
  snapshot(after);
  return object as unknown as ExecutionMeasurement;
}

function operationRecord(row: OperationRow, isNew: boolean): OperationRecord {
  if (!/^[0-9a-f-]{36}$/i.test(row.operation_id) || typeof row.status !== 'string' ||
      typeof row.request_sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(row.request_sha256) ||
      (row.transaction_hash !== null && !HASH.test(row.transaction_hash))) {
    return fail('execution_persistence_operation_invalid');
  }
  return {
    operationId: row.operation_id,
    status: row.status,
    requestHash: row.request_sha256.trim().toLowerCase(),
    transactionHash: row.transaction_hash as Hex | null,
    isNew,
  };
}

function requireRows(rowCount: number | null, reason: string): void {
  if (!rowCount) fail(reason);
}

async function storedExecutionBinding(
  client: PoolClient,
  operationId: string,
  hash: Hex,
): Promise<{ action: SelectedAction; intent: ExecutionTransactionObservation }> {
  const result = await client.query<Pick<SelectedExecutionRow,
    'action_kind' | 'selected_action_json' | 'transaction_intent_json' | 'transaction_hash'>>(
    `SELECT action_kind,selected_action_json,transaction_intent_json,transaction_hash
       FROM bef_selected_execution
      WHERE operation_id=$1 AND transaction_hash=$2
      FOR UPDATE`,
    [operationId, hash],
  );
  const row = result.rows[0];
  if (!row || row.transaction_hash?.toLowerCase() !== hash.toLowerCase() || row.transaction_intent_json === null) {
    return fail('execution_persistence_terminal_binding_conflict');
  }
  const action = selectedAction(row.selected_action_json, row.action_kind);
  const intent = transactionIntent(row.transaction_intent_json);
  if (intent.hash.toLowerCase() !== hash.toLowerCase()) fail('execution_persistence_hash_binding_conflict');
  return { action, intent };
}

type ExecutionEventKind =
  | 'selected_action_bound'
  | 'prestate_observed'
  | 'original_tx_hash_bound'
  | 'settlement_unknown'
  | 'receipt_finalized'
  | 'rejected_before_broadcast';

async function appendEvent(
  client: PoolClient,
  input: {
    operationId: string;
    envId: string;
    generationId: string;
    eventKind: ExecutionEventKind;
    transactionHash: Hex | null;
    event: Record<string, unknown>;
  },
): Promise<void> {
  await client.query(
    `INSERT INTO bef_selected_execution_event(
       event_id,operation_id,env_id,generation_id,event_kind,transaction_hash,event_json
     ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`,
    [randomUUID(), input.operationId, input.envId, input.generationId, input.eventKind, input.transactionHash, JSON.stringify(input.event)],
  );
}

/**
 * Every method uses the supplied transaction client and refuses to repair a
 * contradictory operation/hash binding. SQL exceptions are allowed to reach
 * the caller, which maps them to fixed public error codes without logging SQL
 * parameters or transaction payloads.
 */
export class PostgresExecutionPersistence implements ExecutionPersistence {
  constructor(private readonly costContext?: { manifestSha256: string; feePolicy: FeePolicySnapshot }) {}

  private costIdentity(input: Omit<CostIdentity, 'manifestSha256' | 'feePolicy'>): CostIdentity {
    if (!this.costContext) fail('transaction_cost_context_not_pinned');
    return {
      ...input,
      manifestSha256: this.costContext.manifestSha256,
      feePolicy: this.costContext.feePolicy,
    };
  }

  async createOrGet(
    client: PoolClient,
    auth: ParticipantAuth,
    kind: SelectedAction['kind'],
    requestHash: string,
    action: SelectedAction,
  ): Promise<OperationRecord> {
    if (action.kind !== kind || !/^[0-9a-f]{64}$/i.test(requestHash)) fail('execution_persistence_input_invalid');
    const idempotencyHash = sha256(auth.idempotencyKey);
    const operationId = randomUUID();
    const inserted = await client.query<OperationRow>(
      `INSERT INTO bef_operation(
         operation_id,env_id,generation_id,participant_id,idempotency_key_sha256,
         request_sha256,operation_kind,status,receipt_status
       ) VALUES($1,$2,$3,$4,$5,$6,$7,'accepted','not_submitted')
       ON CONFLICT (env_id,generation_id,participant_id,idempotency_key_sha256) DO NOTHING
       RETURNING operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status`,
      [operationId, auth.envId, auth.generationId, auth.participantId, idempotencyHash, requestHash.toLowerCase(), kind],
    );
    if (inserted.rowCount) {
      const row = inserted.rows[0]!;
      await client.query(
        `INSERT INTO bef_selected_execution(
           operation_id,env_id,generation_id,action_kind,selected_action_json,outcome
         ) VALUES($1,$2,$3,$4,$5::jsonb,'prepared')`,
        [row.operation_id, row.env_id, row.generation_id, kind, JSON.stringify(action)],
      );
      await appendEvent(client, {
        operationId: row.operation_id,
        envId: row.env_id,
        generationId: row.generation_id,
        eventKind: 'selected_action_bound',
        transactionHash: null,
        event: { actionKind: kind, selectedAction: action, requestSha256: requestHash.toLowerCase() },
      });
      return operationRecord(row, true);
    }

    const existing = await client.query<OperationRow>(
      `SELECT operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status
         FROM bef_operation
        WHERE env_id=$1 AND generation_id=$2 AND participant_id=$3 AND idempotency_key_sha256=$4`,
      [auth.envId, auth.generationId, auth.participantId, idempotencyHash],
    );
    const row = existing.rows[0];
    if (!row || row.operation_kind !== kind || row.request_sha256.trim().toLowerCase() !== requestHash.toLowerCase()) {
      return fail('idempotency_key_reused_for_different_request');
    }
    const selected = await client.query<Pick<SelectedExecutionRow, 'action_kind' | 'selected_action_json'>>(
      `SELECT action_kind,selected_action_json FROM bef_selected_execution
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3`,
      [row.operation_id, auth.envId, auth.generationId],
    );
    const savedActionRow = selected.rows[0];
    if (!savedActionRow || savedActionRow.action_kind !== kind ||
        canonicalJson(selectedAction(savedActionRow.selected_action_json, kind)) !== canonicalJson(action)) {
      return fail('execution_persistence_action_binding_conflict');
    }
    return operationRecord(row, false);
  }

  async saveSelectedInputAndPrestate(
    client: PoolClient,
    operationId: string,
    action: SelectedAction,
    before: ExecutionSnapshot,
  ): Promise<void> {
    const checkedBefore = snapshot(before);
    const selected = await client.query(
      `UPDATE bef_selected_execution e
          SET prestate_json=$4::jsonb,updated_at=clock_timestamp()
         FROM bef_operation o
        WHERE e.operation_id=$1 AND e.action_kind=$2 AND e.selected_action_json=$3::jsonb
          AND e.outcome='prepared' AND e.transaction_hash IS NULL AND e.prestate_json IS NULL
          AND o.operation_id=e.operation_id AND o.env_id=e.env_id AND o.generation_id=e.generation_id
          AND o.status='accepted' AND o.transaction_hash IS NULL
        RETURNING e.operation_id`,
      [operationId, action.kind, JSON.stringify(action), JSON.stringify(checkedBefore)],
    );
    if (selected.rowCount) {
      const scope = await client.query<{ env_id: string; generation_id: string }>(
        `SELECT env_id,generation_id FROM bef_selected_execution WHERE operation_id=$1`, [operationId],
      );
      const row = scope.rows[0];
      if (!row) fail('execution_persistence_prestate_binding_conflict');
      await appendEvent(client, {
        operationId,
        envId: row!.env_id,
        generationId: row!.generation_id,
        eventKind: 'prestate_observed',
        transactionHash: null,
        event: { prestate: checkedBefore },
      });
      return;
    }
    const existing = await client.query<Pick<SelectedExecutionRow, 'prestate_json' | 'outcome' | 'transaction_hash' | 'selected_action_json' | 'action_kind'>>(
      `SELECT e.prestate_json,e.outcome,e.transaction_hash,e.selected_action_json,e.action_kind
         FROM bef_selected_execution e JOIN bef_operation o USING(operation_id,env_id,generation_id)
        WHERE e.operation_id=$1 AND o.status='accepted' AND o.transaction_hash IS NULL`,
      [operationId],
    );
    const row = existing.rows[0];
    if (row && row.outcome === 'prepared' && row.transaction_hash === null && row.action_kind === action.kind &&
        canonicalJson(selectedAction(row.selected_action_json, action.kind)) === canonicalJson(action) && row.prestate_json !== null &&
        canonicalJson(snapshot(row.prestate_json)) === canonicalJson(checkedBefore)) {
      const scope = await client.query<{ env_id: string; generation_id: string }>(
        `SELECT env_id,generation_id FROM bef_selected_execution WHERE operation_id=$1`, [operationId],
      );
      const savedScope = scope.rows[0];
      if (!savedScope) fail('execution_persistence_prestate_binding_conflict');
      await appendEvent(client, {
        operationId,
        envId: savedScope!.env_id,
        generationId: savedScope!.generation_id,
        eventKind: 'prestate_observed',
        transactionHash: null,
        event: { prestate: checkedBefore, idempotentReplay: true },
      });
      return;
    }
    fail('execution_persistence_prestate_binding_conflict');
  }

  async bindHashBeforeBroadcast(
    client: PoolClient,
    operationId: string,
    txHash: Hex,
    requestHash: string,
    intent: ExecutionTransactionObservation,
  ): Promise<void> {
    const checkedHash = transactionHash(txHash, 'execution_persistence_hash_invalid');
    const checkedIntent = transactionIntent(intent);
    if (checkedIntent.hash.toLowerCase() !== checkedHash.toLowerCase() || checkedIntent.type !== 'eip1559' ||
        checkedIntent.blockHash !== null || checkedIntent.blockNumber !== null || checkedIntent.transactionIndex !== null ||
        !/^[0-9a-f]{64}$/i.test(requestHash)) fail('execution_persistence_intent_binding_conflict');
    const operation = await client.query<OperationRow>(
      `UPDATE bef_operation
          SET status='settling',transaction_hash=$3,receipt_status='unknown',completed_at=NULL
        WHERE operation_id=$1 AND request_sha256=$2 AND status='accepted' AND transaction_hash IS NULL
        RETURNING operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status`,
      [operationId, requestHash.toLowerCase(), checkedHash],
    );
    const row = operation.rows[0];
    if (!row) fail('execution_persistence_hash_binding_conflict');
    const selected = await client.query(
      `UPDATE bef_selected_execution
          SET transaction_hash=$4,transaction_intent_json=$5::jsonb,outcome='settling',updated_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND outcome='prepared'
          AND transaction_hash IS NULL AND transaction_intent_json IS NULL AND prestate_json IS NOT NULL
        RETURNING operation_id`,
      [operationId, row!.env_id, row!.generation_id, checkedHash, JSON.stringify(checkedIntent)],
    );
    requireRows(selected.rowCount, 'execution_persistence_hash_binding_conflict');
    if (this.costContext) {
      const selectedResult = await client.query<Pick<SelectedExecutionRow, 'action_kind' | 'selected_action_json'>>(
        `SELECT action_kind,selected_action_json FROM bef_selected_execution
          WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$4`,
        [operationId, row!.env_id, row!.generation_id, checkedHash],
      );
      const selectedActionRow = selectedResult.rows[0];
      if (!selectedActionRow) fail('transaction_cost_selected_action_missing');
      const action = selectedAction(selectedActionRow.selected_action_json, selectedActionRow.action_kind);
      const selectedPrincipalUnits = action.kind === 'wrap' || action.kind === 'unwrap' ? action.amountWei
        : action.kind === 'swap' ? action.amountInWei : '0';
      const selectedPrincipalAsset = action.kind === 'wrap' ? 'ETH'
        : action.kind === 'unwrap' || action.kind === 'swap' ? 'WETH' : null;
      await insertUnknownTransactionCost(client, this.costIdentity({
        operationId,
        envId: row!.env_id,
        generationId: row!.generation_id,
        transactionHash: checkedHash,
        payerAddress: checkedIntent.from,
        payerRole: 'participant',
        selectedPrincipalAsset,
        selectedPrincipalUnits,
      }));
    }
    await appendEvent(client, {
      operationId,
      envId: row!.env_id,
      generationId: row!.generation_id,
      eventKind: 'original_tx_hash_bound',
      transactionHash: checkedHash,
      event: { transactionHash: checkedHash, transactionIntent: checkedIntent, requestSha256: requestHash.toLowerCase() },
    });
  }

  async readPending(
    client: PoolClient,
    operationId: string,
  ): Promise<{ action: SelectedAction; before: ExecutionSnapshot; intent: ExecutionTransactionObservation | null } | null> {
    const result = await client.query<SelectedExecutionRow & Pick<OperationRow, 'status'>>(
      `SELECT e.operation_id,e.env_id,e.generation_id,e.action_kind,e.selected_action_json,e.prestate_json,
              e.transaction_intent_json,e.transaction_hash,e.outcome,e.reason_code,e.measurement_json,o.status
         FROM bef_selected_execution e JOIN bef_operation o USING(operation_id,env_id,generation_id)
        WHERE e.operation_id=$1`,
      [operationId],
    );
    const row = result.rows[0];
    if (!row || !['settling', 'settlement_unknown'].includes(row.status) ||
        !['settling', 'settlement_unknown'].includes(row.outcome) || row.transaction_hash === null ||
        row.transaction_intent_json === null || row.prestate_json === null) return null;
    const action = selectedAction(row.selected_action_json, row.action_kind);
    const before = snapshot(row.prestate_json);
    const intent = transactionIntent(row.transaction_intent_json);
    if (intent.hash.toLowerCase() !== row.transaction_hash.toLowerCase()) fail('execution_persistence_hash_binding_conflict');
    return { action, before, intent };
  }

  async readCompleted(
    client: PoolClient,
    operationId: string,
  ): Promise<{ outcome: 'success' | 'reverted'; transactionHash: Hex; measurement: ExecutionMeasurement } | null> {
    const result = await client.query<SelectedExecutionRow & Pick<OperationRow, 'status' | 'receipt_status'>>(
      `SELECT e.operation_id,e.env_id,e.generation_id,e.action_kind,e.selected_action_json,e.prestate_json,
              e.transaction_intent_json,e.transaction_hash,e.outcome,e.reason_code,e.measurement_json,
              o.status,o.receipt_status
         FROM bef_selected_execution e JOIN bef_operation o USING(operation_id,env_id,generation_id)
        WHERE e.operation_id=$1`,
      [operationId],
    );
    const row = result.rows[0];
    if (!row) return null;
    if ((row.outcome !== 'success' && row.outcome !== 'reverted') || row.transaction_hash === null ||
        row.measurement_json === null || row.status !== (row.outcome === 'success' ? 'settled' : 'reverted') ||
        row.receipt_status !== row.outcome) fail('execution_persistence_terminal_binding_conflict');
    const hash = transactionHash(row.transaction_hash, 'execution_persistence_hash_invalid');
    const action = selectedAction(row.selected_action_json, row.action_kind);
    const measured = measurement(row.measurement_json, hash, row.outcome);
    const intent = transactionIntent(row.transaction_intent_json);
    assertMeasurementActionBinding(measured, action);
    if (!transactionMatchesPersistedIntent(measured.transaction, intent)) fail('execution_persistence_terminal_binding_conflict');
    return { outcome: row.outcome, transactionHash: hash, measurement: measured };
  }

  async rejectBeforeBroadcast(client: PoolClient, operationId: string, reasonCode: string): Promise<void> {
    const safeReason = /^[a-z0-9_]{1,80}$/.test(reasonCode) ? reasonCode : 'execution_rejected';
    const updated = await client.query<OperationRow>(
      `UPDATE bef_operation SET status='rejected',receipt_status='not_submitted',completed_at=clock_timestamp()
        WHERE operation_id=$1 AND status IN ('accepted','awaiting_payment') AND transaction_hash IS NULL
        RETURNING operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status`,
      [operationId],
    );
    const operation = updated.rows[0];
    if (!operation) {
      const existing = await client.query<{ status: string; transaction_hash: string | null }>(
        `SELECT status,transaction_hash FROM bef_operation WHERE operation_id=$1`, [operationId],
      );
      if (existing.rows[0]?.status === 'rejected' && existing.rows[0].transaction_hash === null) return;
      fail('execution_persistence_rejection_conflict');
    }
    const selected = await client.query(
      `UPDATE bef_selected_execution
          SET outcome='rejected',reason_code=$4,updated_at=clock_timestamp(),completed_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND outcome='prepared'
          AND transaction_hash IS NULL AND transaction_intent_json IS NULL
        RETURNING operation_id`,
      [operationId, operation!.env_id, operation!.generation_id, safeReason],
    );
    requireRows(selected.rowCount, 'execution_persistence_rejection_conflict');
    await appendEvent(client, {
      operationId,
      envId: operation!.env_id,
      generationId: operation!.generation_id,
      eventKind: 'rejected_before_broadcast',
      transactionHash: null,
      event: { reasonCode: safeReason },
    });
  }

  async markUnknown(
    client: PoolClient,
    operationId: string,
    txHash: Hex,
    measuredValue?: ExecutionMeasurement | null,
  ): Promise<void> {
    const hash = transactionHash(txHash, 'execution_persistence_hash_invalid');
    const measured = measuredValue == null ? null : measurement(measuredValue, hash);
    if (measured) {
      const binding = await storedExecutionBinding(client, operationId, hash);
      assertMeasurementActionBinding(measured, binding.action);
      if (!transactionMatchesPersistedIntent(measured.transaction, binding.intent)) {
        fail('execution_persistence_terminal_binding_conflict');
      }
    }
    const updated = await client.query<OperationRow>(
      `UPDATE bef_operation SET status='settlement_unknown',receipt_status='unknown'
        WHERE operation_id=$1 AND transaction_hash=$2 AND status IN ('settling','settlement_unknown')
        RETURNING operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status`,
      [operationId, hash],
    );
    const operation = updated.rows[0];
    if (!operation) {
      const terminal = await client.query<{ status: string; transaction_hash: string | null }>(
        `SELECT status,transaction_hash FROM bef_operation WHERE operation_id=$1`, [operationId],
      );
      const terminalRow = terminal.rows[0];
      if (terminalRow && terminalRow.transaction_hash?.toLowerCase() === hash.toLowerCase() &&
          ['settled', 'reverted'].includes(terminalRow.status)) return;
      fail('execution_persistence_unknown_binding_conflict');
    }
    const selected = await client.query(
      `UPDATE bef_selected_execution
          SET outcome='settlement_unknown',measurement_json=COALESCE($4::jsonb,measurement_json),updated_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$5
          AND outcome IN ('settling','settlement_unknown')
        RETURNING operation_id`,
      [operationId, operation!.env_id, operation!.generation_id, measured ? JSON.stringify(measured) : null, hash],
    );
    requireRows(selected.rowCount, 'execution_persistence_unknown_binding_conflict');
    await appendEvent(client, {
      operationId,
      envId: operation!.env_id,
      generationId: operation!.generation_id,
      eventKind: 'settlement_unknown',
      transactionHash: hash,
      event: { transactionHash: hash, measurement: measured },
    });
  }

  async finish(
    client: PoolClient,
    operationId: string,
    txHash: Hex,
    outcome: 'success' | 'reverted',
    measuredValue: ExecutionMeasurement | null,
  ): Promise<void> {
    const hash = transactionHash(txHash, 'execution_persistence_hash_invalid');
    if (!measuredValue) fail('execution_persistence_measurement_required');
    const measured = measurement(measuredValue, hash, outcome);
    const binding = await storedExecutionBinding(client, operationId, hash);
    assertMeasurementActionBinding(measured, binding.action);
    if (!transactionMatchesPersistedIntent(measured.transaction, binding.intent)) {
      fail('execution_persistence_terminal_binding_conflict');
    }
    const operationStatus = outcome === 'success' ? 'settled' : 'reverted';
    const updated = await client.query<OperationRow>(
      `UPDATE bef_operation SET status=$3,receipt_status=$4,completed_at=clock_timestamp()
        WHERE operation_id=$1 AND transaction_hash=$2 AND status IN ('settling','settlement_unknown')
        RETURNING operation_id,env_id,generation_id,participant_id,operation_kind,status,request_sha256,transaction_hash,receipt_status`,
      [operationId, hash, operationStatus, outcome],
    );
    const operation = updated.rows[0];
    if (!operation) fail('execution_persistence_terminal_binding_conflict');
    const selected = await client.query(
      `UPDATE bef_selected_execution
          SET outcome=$4,measurement_json=$5::jsonb,reason_code=NULL,updated_at=clock_timestamp(),completed_at=clock_timestamp()
        WHERE operation_id=$1 AND env_id=$2 AND generation_id=$3 AND transaction_hash=$6
          AND outcome IN ('settling','settlement_unknown')
        RETURNING operation_id`,
      [operationId, operation!.env_id, operation!.generation_id, outcome, JSON.stringify(measured), hash],
    );
    requireRows(selected.rowCount, 'execution_persistence_terminal_binding_conflict');
    if (this.costContext) {
      await finalizeTransactionCost(client, this.costIdentity({
        operationId,
        envId: operation!.env_id,
        generationId: operation!.generation_id,
        transactionHash: hash,
        payerAddress: measured.transaction.from,
        payerRole: 'participant',
        selectedPrincipalAsset: measured.fee.principalAsset,
        selectedPrincipalUnits: measured.fee.selectedPrincipalUnits,
      }), {
        transaction: {
          hash: measured.transaction.hash,
          from: measured.transaction.from,
          blockHash: measured.transaction.blockHash,
          blockNumber: measured.transaction.blockNumber,
          value: measured.transaction.valueWei,
          maxFeePerGas: measured.transaction.maxFeePerGasWei,
          maxPriorityFeePerGas: measured.transaction.maxPriorityFeePerGasWei,
        },
        receipt: {
          transactionHash: measured.receipt.transactionHash,
          from: measured.receipt.from,
          status: measured.receipt.status,
          blockHash: measured.receipt.blockHash,
          blockNumber: measured.receipt.blockNumber,
          gasUsed: measured.receipt.gasUsed,
          effectiveGasPrice: measured.receipt.effectiveGasPrice,
        },
        receiptBlockBaseFeePerGas: measured.payerBlock.baseFeePerGasWei,
        payerBlock: {
          hash: measured.payerBlock.hash,
          number: measured.payerBlock.number,
          parentHash: measured.payerBlock.parentHash,
          baseFeePerGas: measured.payerBlock.baseFeePerGasWei,
          transactions: measured.payerBlock.transactions,
        },
      });
    }
    await appendEvent(client, {
      operationId,
      envId: operation!.env_id,
      generationId: operation!.generation_id,
      eventKind: 'receipt_finalized',
      transactionHash: hash,
      event: { outcome, measurement: measured },
    });
  }
}
