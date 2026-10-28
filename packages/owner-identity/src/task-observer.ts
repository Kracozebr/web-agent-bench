import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const SHA256 = /^[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

type JsonRecord = Record<string, unknown>;

export type TrustedBefCaptureIdentity = {
  /** Values loaded from the trusted environment/generation store, never an agent request. */
  envId: string;
  generationId: string;
  operationId: string;
  participantId: string;
};

export type RawTaskArtifactReference = {
  path: string;
  sha256: string;
  boundary: string;
};

/**
 * A verified primitive result from the selected-execution fixture. This is deliberately not an
 * evaluator observation: the BEF capture has no owner/run/task/case/action-sequence authority.
 */
export type S1TransferPrimitiveCandidate = {
  schemaVersion: 'bts-s1-transfer-primitive-candidate/v1';
  status: 'verified_primitive_only';
  classification: 'selected_executor_primitive_capture_not_bts_acceptance';
  taskActionBinding: 'unavailable';
  unavailableReasons: ['task_action_binding_unavailable', 'authoritative_run_cutoff_unavailable'];
  evaluatorObservations: null;
  identity: {
    envId: string;
    generationId: string;
    participantId: string;
    operationId: string;
    transactionHash: string;
  };
  transfer: {
    fromAddress: string;
    recipientAddress: string;
    assetAddress: string;
    amountUnits: string;
    receiptStatus: 'success';
  };
  finalState: {
    blockNumber: string;
    blockHash: string;
    participantNativeWei: string;
    participantUsdcUnits: string;
    recipientUsdcUnits: string;
  };
  receiptCost: {
    gasUsed: string;
    effectiveGasPriceWei: string;
    gasCostWei: string;
    modeledGasFeeUsdcUnits: string;
    transactionCostRow: 'unavailable_in_capture';
  };
  relatedRows: {
    paymentRows: 0;
    deliveryRows: 0;
    transactionCostRows: 'not_captured';
  };
  evidence: RawTaskArtifactReference[];
};

type ArtifactIndexEntry = RawTaskArtifactReference & { contentType: string };

function fail(code: string): never {
  throw new Error(code);
}

function record(value: unknown, code: string): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(code);
  return value as JsonRecord;
}

function string(value: unknown, code: string): string {
  return typeof value === 'string' ? value : fail(code);
}

function same(left: unknown, right: unknown): boolean {
  if (typeof left === 'string' && typeof right === 'string') return left.toLowerCase() === right.toLowerCase();
  return left === right;
}

function uint(value: unknown, code: string): bigint {
  if (typeof value === 'string' && UINT.test(value)) return BigInt(value);
  if (typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value)) return BigInt(value);
  return fail(code);
}

function hexQuantity(value: unknown, code: string): bigint {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value)) return fail(code);
  return BigInt(value);
}

function hexWord(value: unknown, code: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value)) return fail(code);
  return BigInt(value);
}

function address(value: unknown, code: string): string {
  if (typeof value !== 'string' || !ADDRESS.test(value)) return fail(code);
  return value.toLowerCase();
}

function hash(value: unknown, code: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) return fail(code);
  return value.toLowerCase();
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as JsonRecord).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

async function readContained(root: string, relativePath: string): Promise<Buffer> {
  if (!relativePath || relativePath.includes('\\') || relativePath.includes('\0') || isAbsolute(relativePath) ||
      relativePath.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    return fail('task_observer_artifact_path_invalid');
  }
  const candidate = resolve(root, ...relativePath.split('/'));
  const resolved = await realpath(candidate).catch(() => fail('task_observer_artifact_missing'));
  const rel = relative(root, resolved);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return fail('task_observer_artifact_path_escape');
  const info = await lstat(resolved);
  if (!info.isFile()) return fail('task_observer_artifact_not_file');
  return readFile(resolved);
}

function parseJson(bytes: Buffer, code: string): JsonRecord {
  try {
    return record(JSON.parse(bytes.toString('utf8')) as unknown, code);
  } catch {
    return fail(code);
  }
}

function verifiedArtifactReference(entry: ArtifactIndexEntry): RawTaskArtifactReference {
  if (!entry || typeof entry.path !== 'string' || !SHA256.test(entry.sha256) || typeof entry.boundary !== 'string') {
    return fail('task_observer_artifact_index_invalid');
  }
  return { path: entry.path, sha256: entry.sha256.toLowerCase(), boundary: entry.boundary };
}

function expectedRpcObservation(
  value: unknown,
  expected: { envId: string; operationId: string | null; method: string; boundary: string },
): JsonRecord {
  const observation = record(value, 'task_observer_rpc_artifact_invalid');
  const endpoint = record(observation.endpointRef, 'task_observer_rpc_endpoint_invalid');
  if (observation.schemaVersion !== 'bef-rpc-observation/v1' || observation.boundary !== expected.boundary ||
      observation.endpointBoundary !== expected.boundary || observation.environmentId !== expected.envId ||
      observation.operationId !== expected.operationId || observation.method !== expected.method ||
      endpoint.scheme !== 'http' || !['127.0.0.1', '::1', 'localhost'].includes(String(endpoint.host))) {
    return fail('task_observer_rpc_artifact_binding_mismatch');
  }
  return observation;
}

function expectedDbObservation(value: unknown, identity: TrustedBefCaptureIdentity): JsonRecord {
  const observation = record(value, 'task_observer_database_artifact_invalid');
  if (observation.schemaVersion !== 'bef-db-observation/v1' || observation.boundary !== 'readonly-database' ||
      observation.operationId !== identity.operationId || observation.envId !== identity.envId ||
      observation.generationId !== identity.generationId || observation.readOnly !== true ||
      observation.databaseRole !== 'bef_observer' || observation.transactionReadOnly !== 'on' ||
      observation.queryName !== 'task-transfer-operation-selected-execution-and-events') {
    return fail('task_observer_database_artifact_binding_mismatch');
  }
  return observation;
}

function observationPath(probe: JsonRecord, id: string): string {
  if (!Array.isArray(probe.observations)) return fail('task_observer_observation_index_invalid');
  const matches = probe.observations.map((item) => record(item, 'task_observer_observation_index_invalid'))
    .filter((item) => item.id === id);
  if (matches.length !== 1) return fail('task_observer_required_observation_missing');
  return string(matches[0]!.sourceArtifact, 'task_observer_required_observation_missing');
}

function indexArtifacts(probe: JsonRecord): Map<string, ArtifactIndexEntry> {
  if (!Array.isArray(probe.artifacts)) return fail('task_observer_artifact_index_invalid');
  const result = new Map<string, ArtifactIndexEntry>();
  for (const raw of probe.artifacts) {
    const entry = record(raw, 'task_observer_artifact_index_invalid') as unknown as ArtifactIndexEntry;
    verifiedArtifactReference(entry);
    if (typeof entry.contentType !== 'string' || result.has(entry.path)) return fail('task_observer_artifact_index_invalid');
    result.set(entry.path, entry);
  }
  return result;
}

function transferInput(recipient: string, amount: bigint): string {
  return `0xa9059cbb${recipient.slice(2).padStart(64, '0')}${amount.toString(16).padStart(64, '0')}`;
}

function balanceCallResult(observation: JsonRecord, expected: {
  envId: string; operationId: string | null; tokenAddress: string; account: string; blockTag: string;
}): bigint {
  const rpc = expectedRpcObservation(observation, {
    envId: expected.envId, operationId: expected.operationId, method: 'eth_call', boundary: 'local-chain-readonly-proxy',
  });
  const params = rpc.params;
  if (!Array.isArray(params) || params.length !== 2) return fail('task_observer_balance_call_invalid');
  const call = record(params[0], 'task_observer_balance_call_invalid');
  const expectedData = `0x70a08231${expected.account.slice(2).padStart(64, '0')}`;
  if (!same(call.to, expected.tokenAddress) || !same(call.data, expectedData) || !same(params[1], expected.blockTag) ||
      !same(rpc.requestedBlock, expected.blockTag)) return fail('task_observer_balance_call_binding_mismatch');
  return hexWord(rpc.result, 'task_observer_balance_result_invalid');
}

function nativeBalanceResult(observation: JsonRecord, expected: {
  envId: string; operationId: string | null; account: string; blockTag: string;
}): bigint {
  const rpc = expectedRpcObservation(observation, {
    envId: expected.envId, operationId: expected.operationId, method: 'eth_getBalance', boundary: 'local-chain-readonly-proxy',
  });
  if (!Array.isArray(rpc.params) || rpc.params.length !== 2 || !same(rpc.params[0], expected.account) ||
      !same(rpc.params[1], expected.blockTag) || !same(rpc.requestedBlock, expected.blockTag)) {
    return fail('task_observer_native_balance_call_binding_mismatch');
  }
  return hexQuantity(rpc.result, 'task_observer_native_balance_invalid');
}

/**
 * Reconciles one retained BEF USDC transfer capture against hashed raw DB/RPC artifacts.
 * The expected IDs and probe hash must come from trusted coordinator/evidence-index state.
 *
 * AICODE-NOTE: BEF operation/generation identities do not bind owner/run/task/action sequence.
 * Keep this reader's result outside the rubric input contract until that authoritative mapping exists.
 */
export async function readS1TransferPrimitiveCapture(input: {
  captureDirectory: string;
  expectedProbeSha256: string;
  trustedIdentity: TrustedBefCaptureIdentity;
}): Promise<S1TransferPrimitiveCandidate> {
  if (!SHA256.test(input.expectedProbeSha256) || !input.trustedIdentity.envId || !input.trustedIdentity.generationId ||
      !input.trustedIdentity.operationId || !input.trustedIdentity.participantId) {
    return fail('task_observer_trusted_identity_invalid');
  }
  const root = await realpath(input.captureDirectory).catch(() => fail('task_observer_capture_directory_missing'));
  const probeBytes = await readContained(root, 'probe.json');
  if (sha256(probeBytes) !== input.expectedProbeSha256.toLowerCase()) return fail('task_observer_probe_hash_mismatch');
  const probe = parseJson(probeBytes, 'task_observer_probe_json_invalid');
  if (probe.schemaVersion !== 'bts-transfer-probe/v1' || probe.classification !== 'selected_executor_primitive_capture_not_bts_acceptance' ||
      probe.status !== 'captured' || probe.phase !== 'complete') return fail('task_observer_capture_not_complete_primitive');

  const artifacts = indexArtifacts(probe);
  const raw = new Map<string, Buffer>();
  for (const entry of artifacts.values()) {
    const bytes = await readContained(root, entry.path);
    if (sha256(bytes) !== entry.sha256.toLowerCase()) return fail(`task_observer_artifact_hash_mismatch:${entry.path}`);
    raw.set(entry.path, bytes);
  }
  const manifestRef = record(probe.manifest, 'task_observer_manifest_reference_invalid');
  const manifestPath = string(manifestRef.path, 'task_observer_manifest_reference_invalid');
  const manifestEntry = artifacts.get(manifestPath);
  if (!manifestEntry || manifestEntry.sha256.toLowerCase() !== string(manifestRef.sha256, 'task_observer_manifest_reference_invalid').toLowerCase()) {
    return fail('task_observer_manifest_hash_binding_mismatch');
  }
  const manifest = parseJson(raw.get(manifestPath)!, 'task_observer_manifest_json_invalid');
  const topEnvironment = record(probe.environment, 'task_observer_capture_identity_invalid');
  const capture = record(probe.capture, 'task_observer_capture_identity_invalid');
  const captureEnvironment = record(capture.environment, 'task_observer_capture_identity_invalid');
  const captureOperation = record(capture.operation, 'task_observer_capture_identity_invalid');
  const envId = input.trustedIdentity.envId;
  const generationId = input.trustedIdentity.generationId;
  const operationId = input.trustedIdentity.operationId;
  const participantId = input.trustedIdentity.participantId;
  if (topEnvironment.envId !== envId || topEnvironment.generationId !== generationId || topEnvironment.participantId !== participantId ||
      captureEnvironment.envId !== envId || captureEnvironment.generationId !== generationId || captureEnvironment.participantId !== participantId ||
      captureOperation.operationId !== operationId || manifest.local && record(manifest.local, 'task_observer_manifest_invalid').chainId !== 8453) {
    return fail('task_observer_trusted_identity_mismatch');
  }

  const endpointPath = observationPath(probe, `task-transfer-local-rpc-identity`);
  const endpointEntry = artifacts.get(endpointPath);
  if (!endpointEntry || endpointEntry.boundary !== 'local-chain-readonly-proxy') return fail('task_observer_endpoint_identity_missing');
  const endpointIdentity = record(parseJson(raw.get(endpointPath)!, 'task_observer_endpoint_identity_invalid'), 'task_observer_endpoint_identity_invalid');
  const endpointHealthPath = string(endpointIdentity.healthArtifactPath, 'task_observer_endpoint_identity_invalid');
  const endpointHealthEntry = artifacts.get(endpointHealthPath);
  const endpointHealth = endpointHealthEntry && parseJson(raw.get(endpointHealthPath)!, 'task_observer_endpoint_health_invalid');
  if (endpointIdentity.schemaVersion !== 'bef-rpc-endpoint-binding/v1' || endpointIdentity.boundary !== 'local-chain-readonly-proxy' ||
      endpointIdentity.environmentId !== envId || endpointIdentity.operationId !== null || !endpointHealthEntry ||
      endpointHealthEntry.sha256.toLowerCase() !== string(endpointIdentity.healthArtifactSha256, 'task_observer_endpoint_identity_invalid').toLowerCase() ||
      !endpointHealth || endpointHealth.status !== 'ok' || endpointHealth.boundary !== 'local-chain-readonly-proxy' ||
      endpointHealth.envId !== envId || !same(endpointHealth.manifestSha256, manifestRef.sha256)) {
    return fail('task_observer_endpoint_identity_mismatch');
  }

  const dbPath = observationPath(probe, `task-transfer-selected-execution-${operationId}`);
  const dbEntry = artifacts.get(dbPath);
  if (!dbEntry || dbEntry.boundary !== 'readonly-database') return fail('task_observer_database_artifact_missing');
  const db = expectedDbObservation(parseJson(raw.get(dbPath)!, 'task_observer_database_artifact_invalid'), input.trustedIdentity);
  const rows = record(db.rows, 'task_observer_database_rows_invalid');
  const operation = record(rows.operation, 'task_observer_operation_row_invalid');
  const selected = record(rows.selectedExecution, 'task_observer_selected_execution_row_invalid');
  const events = rows.events;
  if (!Array.isArray(events) || events.length !== 4) return fail('task_observer_selected_execution_events_incomplete');
  if (operation.operation_id !== operationId || operation.env_id !== envId || operation.generation_id !== generationId ||
      operation.participant_id !== participantId || operation.operation_kind !== 'transfer' || operation.status !== 'settled' ||
      operation.receipt_status !== 'success') return fail('task_observer_operation_row_binding_mismatch');
  if (selected.operation_id !== operationId || selected.action_kind !== 'transfer' || selected.outcome !== 'success') {
    return fail('task_observer_selected_execution_row_binding_mismatch');
  }

  const generationPath = observationPath(probe, 'task-transfer-generation-row-generation-by-id');
  const generationEntry = artifacts.get(generationPath);
  if (!generationEntry || generationEntry.boundary !== 'readonly-database') return fail('task_observer_generation_artifact_missing');
  const generationObservation = record(parseJson(raw.get(generationPath)!, 'task_observer_generation_artifact_invalid'), 'task_observer_generation_artifact_invalid');
  if (generationObservation.schemaVersion !== 'bef-db-observation/v1' || generationObservation.boundary !== 'readonly-database' ||
      generationObservation.readOnly !== true || generationObservation.databaseRole !== 'bef_observer' || generationObservation.transactionReadOnly !== 'on' ||
      generationObservation.envId !== envId || generationObservation.generationId !== generationId || generationObservation.queryName !== 'generation-by-id' ||
      !Array.isArray(generationObservation.rows) || generationObservation.rows.length !== 1) return fail('task_observer_generation_artifact_binding_mismatch');
  const generationRow = record(generationObservation.rows[0], 'task_observer_generation_row_invalid');
  if (generationRow.generation_id !== generationId || generationRow.env_id !== envId || generationRow.participant_id !== participantId ||
      !same(generationRow.payer_address, topEnvironment.payerAddress)) return fail('task_observer_generation_row_binding_mismatch');

  const action = record(selected.selected_action_json, 'task_observer_selected_action_invalid');
  const intent = record(selected.transaction_intent_json, 'task_observer_transaction_intent_invalid');
  const measurement = record(selected.measurement_json, 'task_observer_measurement_invalid');
  const receipt = record(measurement.receipt, 'task_observer_measurement_receipt_invalid');
  const transaction = record(measurement.transaction, 'task_observer_measurement_transaction_invalid');
  const measuredAction = record(measurement.selectedAction, 'task_observer_measurement_action_invalid');
  const fee = record(measurement.fee, 'task_observer_measurement_fee_invalid');
  const txHash = hash(operation.transaction_hash, 'task_observer_transaction_hash_invalid');
  const fromAddress = address(intent.from, 'task_observer_transaction_sender_invalid');
  const recipientAddress = address(action.recipient, 'task_observer_recipient_invalid');
  const assetAddress = address(measuredAction.token, 'task_observer_token_invalid');
  const amountUnits = uint(action.amountUnits, 'task_observer_transfer_amount_invalid');
  if (action.kind !== 'transfer' || measuredAction.kind !== 'transfer' || !same(operation.transaction_hash, selected.transaction_hash) ||
      !same(intent.hash, txHash) || !same(transaction.hash, txHash) || !same(receipt.transactionHash, txHash) ||
      !same(transaction.from, fromAddress) || !same(transaction.to, assetAddress) || !same(intent.to, assetAddress) ||
      !same(transaction.input, transferInput(recipientAddress, amountUnits)) || !same(intent.input, transaction.input) ||
      !same(measuredAction.recipient, recipientAddress) || !same(measuredAction.amountUnits, amountUnits.toString()) ||
      fee.principalAsset !== 'USDC' || !same(fee.principalUnits, amountUnits.toString()) ||
      !same(fee.selectedPrincipalUnits, amountUnits.toString())) return fail('task_observer_selected_transfer_binding_mismatch');

  const eventRows = events.map((rawEvent) => record(rawEvent, 'task_observer_selected_execution_event_invalid'));
  const expectedKinds = ['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'];
  if (eventRows.some((event, index) => event.event_kind !== expectedKinds[index]) ||
      eventRows.some((event, index) => index > 0 && BigInt(string(event.event_sequence, 'task_observer_event_sequence_invalid')) <=
        BigInt(string(eventRows[index - 1]!.event_sequence, 'task_observer_event_sequence_invalid')))) {
    return fail('task_observer_selected_execution_event_order_invalid');
  }
  const finalized = record(record(eventRows[3]!.event_json, 'task_observer_event_json_invalid').measurement, 'task_observer_finalized_measurement_invalid');
  const selectedActionEvent = record(eventRows[0]!.event_json, 'task_observer_event_json_invalid');
  const prestateEvent = record(eventRows[1]!.event_json, 'task_observer_event_json_invalid');
  const hashBoundEvent = record(eventRows[2]!.event_json, 'task_observer_event_json_invalid');
  if (!same(eventRows[2]!.transaction_hash, txHash) || !same(eventRows[3]!.transaction_hash, txHash) ||
      !same(record(eventRows[3]!.event_json, 'task_observer_event_json_invalid').outcome, 'success') ||
      selectedActionEvent.actionKind !== selected.action_kind || canonicalJson(selectedActionEvent.selectedAction) !== canonicalJson(action) ||
      canonicalJson(prestateEvent.prestate) !== canonicalJson(measurement.before) ||
      !same(hashBoundEvent.transactionHash, txHash) || canonicalJson(hashBoundEvent.transactionIntent) !== canonicalJson(intent) ||
      canonicalJson(finalized) !== canonicalJson(measurement)) return fail('task_observer_selected_execution_event_measurement_mismatch');

  const relatedDbSnapshot = (id: string, queryName: string): { path: string; rows: unknown[] } => {
    const path = observationPath(probe, id);
    const entry = artifacts.get(path);
    if (!entry || entry.boundary !== 'readonly-database') return fail(`task_observer_related_database_artifact_missing:${id}`);
    const observation = record(parseJson(raw.get(path)!, 'task_observer_related_database_artifact_invalid'), 'task_observer_related_database_artifact_invalid');
    if (observation.schemaVersion !== 'bef-db-observation/v1' || observation.boundary !== 'readonly-database' ||
        observation.operationId !== operationId || observation.envId !== envId || observation.generationId !== generationId ||
        observation.queryName !== queryName || observation.readOnly !== true || observation.databaseRole !== 'bef_observer' ||
        observation.transactionReadOnly !== 'on' || !Array.isArray(observation.rows)) {
      return fail('task_observer_related_database_artifact_binding_mismatch');
    }
    return { path, rows: observation.rows };
  };
  const paymentsSnapshot = relatedDbSnapshot('task-transfer-operation-snapshot-payments-by-operation', 'payments-by-operation');
  const deliveriesSnapshot = relatedDbSnapshot('task-transfer-operation-snapshot-deliveries-by-operation', 'deliveries-by-operation');
  if (paymentsSnapshot.rows.length !== 0 || deliveriesSnapshot.rows.length !== 0) {
    return fail('task_observer_primitive_has_unexpected_payment_or_delivery_rows');
  }

  const rpc = (id: string): JsonRecord => {
    const path = observationPath(probe, id);
    const entry = artifacts.get(path);
    if (!entry || entry.boundary !== 'local-chain-readonly-proxy') return fail(`task_observer_rpc_artifact_missing:${id}`);
    const observation = expectedRpcObservation(parseJson(raw.get(path)!, 'task_observer_rpc_artifact_invalid'), {
      envId, operationId: id.startsWith('task-transfer-before-') ? null : operationId,
      method: id === 'task-transfer-receipt' ? 'eth_getTransactionReceipt' :
        id === 'task-transfer-selected-calldata' ? 'eth_getTransactionByHash' :
          id.includes('block') ? 'eth_getBlockByNumber' : id.includes('native') ? 'eth_getBalance' : 'eth_call',
      boundary: 'local-chain-readonly-proxy',
    });
    if (observation.endpointIdentityArtifact !== endpointPath ||
        canonicalJson(observation.endpointRef) !== canonicalJson(endpointIdentity.endpointRef)) {
      return fail('task_observer_rpc_endpoint_binding_mismatch');
    }
    return observation;
  };
  const rpcIds = [
    'task-transfer-before-block', 'task-transfer-before-payer-native',
    'task-transfer-before-payer-usdc', 'task-transfer-before-recipient-usdc',
    'task-transfer-selected-calldata', 'task-transfer-receipt', 'task-transfer-after-block',
    'task-transfer-after-payer-usdc', 'task-transfer-after-recipient-usdc', 'task-transfer-after-payer-native',
  ];
  const rpcRows = new Map(rpcIds.map((id) => [id, rpc(id)]));
  const rawReceipt = record(rpcRows.get('task-transfer-receipt')!.result, 'task_observer_rpc_receipt_invalid');
  const rawTx = record(rpcRows.get('task-transfer-selected-calldata')!.result, 'task_observer_rpc_transaction_invalid');
  const beforeBlock = record(rpcRows.get('task-transfer-before-block')!.result, 'task_observer_rpc_block_invalid');
  const afterBlock = record(rpcRows.get('task-transfer-after-block')!.result, 'task_observer_rpc_block_invalid');
  const manifestContracts = record(manifest.contracts, 'task_observer_manifest_contracts_invalid');
  const usdc = record(manifestContracts.usdc, 'task_observer_manifest_usdc_invalid');
  const manifestToken = address(usdc.address, 'task_observer_manifest_usdc_invalid');
  if (assetAddress !== manifestToken || !same(rawTx.hash, txHash) || !same(rawTx.from, fromAddress) || !same(rawTx.to, assetAddress) ||
      !same(rawTx.input, intent.input) || !same(rawReceipt.transactionHash, txHash) || !same(rawReceipt.from, fromAddress) ||
      !same(rawReceipt.to, assetAddress) || hexQuantity(rawReceipt.status, 'task_observer_rpc_receipt_status_invalid') !== 1n ||
      !same(rawReceipt.blockHash, receipt.blockHash) || !same(rawTx.blockHash, receipt.blockHash) ||
      !same(afterBlock.hash, receipt.blockHash) || !same(afterBlock.parentHash, beforeBlock.hash) ||
      hexQuantity(rawReceipt.blockNumber, 'task_observer_rpc_receipt_block_invalid') !== uint(receipt.blockNumber, 'task_observer_measurement_block_invalid') ||
      hexQuantity(rawTx.chainId, 'task_observer_rpc_chain_invalid') !== 8453n) return fail('task_observer_rpc_transaction_receipt_conflict');
  const logs = rawReceipt.logs;
  if (!Array.isArray(logs)) return fail('task_observer_rpc_transfer_log_missing');
  const matchingLogs = logs.map((item) => record(item, 'task_observer_rpc_log_invalid')).filter((log) => {
    const topics = log.topics;
    return Array.isArray(topics) && topics.length === 3 && same(log.address, assetAddress) &&
      same(topics[0], TRANSFER_TOPIC) && same(topics[1], `0x${fromAddress.slice(2).padStart(64, '0')}`) &&
      same(topics[2], `0x${recipientAddress.slice(2).padStart(64, '0')}`) &&
      hexWord(log.data, 'task_observer_rpc_log_data_invalid') === amountUnits;
  });
  if (matchingLogs.length !== 1) return fail('task_observer_rpc_transfer_log_conflict');
  const persistedLogs = receipt.logs;
  if (!Array.isArray(persistedLogs)) return fail('task_observer_persisted_transfer_log_missing');
  const persistedMatchingLogs = persistedLogs.map((item) => record(item, 'task_observer_persisted_receipt_log_invalid')).filter((log) => {
    const topics = log.topics;
    return Array.isArray(topics) && topics.length === 3 && same(log.address, assetAddress) &&
      same(topics[0], TRANSFER_TOPIC) && same(topics[1], `0x${fromAddress.slice(2).padStart(64, '0')}`) &&
      same(topics[2], `0x${recipientAddress.slice(2).padStart(64, '0')}`) &&
      hexWord(log.data, 'task_observer_persisted_receipt_log_data_invalid') === amountUnits;
  });
  if (persistedMatchingLogs.length !== 1) return fail('task_observer_persisted_transfer_log_conflict');
  if (canonicalJson(persistedMatchingLogs[0]) !== canonicalJson(matchingLogs[0])) {
    const persistedLog = persistedMatchingLogs[0] as JsonRecord | undefined;
    const rawLog = matchingLogs[0] as JsonRecord | undefined;
    if (!persistedLog || !rawLog || !same(persistedLog.address, rawLog.address) ||
        !same(persistedLog.data, rawLog.data) || canonicalJson(persistedLog.topics) !== canonicalJson(rawLog.topics) ||
        !same(persistedLog.blockHash, rawLog.blockHash) ||
        !same(persistedLog.transactionHash, rawLog.transactionHash) || !same(persistedLog.removed, rawLog.removed) ||
        uint(persistedLog.blockNumber, 'task_observer_persisted_log_block_invalid') !== hexQuantity(rawLog.blockNumber, 'task_observer_rpc_log_block_invalid') ||
        uint(persistedLog.logIndex, 'task_observer_persisted_log_index_invalid') !== hexQuantity(rawLog.logIndex, 'task_observer_rpc_log_index_invalid') ||
        uint(persistedLog.transactionIndex, 'task_observer_persisted_log_tx_index_invalid') !== hexQuantity(rawLog.transactionIndex, 'task_observer_rpc_log_tx_index_invalid')) {
      return fail('task_observer_persisted_transfer_log_conflict');
    }
  }

  const afterBlockTag = string(rpcRows.get('task-transfer-after-block')!.requestedBlock, 'task_observer_rpc_block_tag_invalid');
  const beforeBlockTag = string(rpcRows.get('task-transfer-before-block')!.requestedBlock, 'task_observer_rpc_block_tag_invalid');
  const beforeParticipantNative = nativeBalanceResult(rpcRows.get('task-transfer-before-payer-native')!, {
    envId, operationId: null, account: fromAddress, blockTag: beforeBlockTag,
  });
  const afterParticipantNativeFromRpc = nativeBalanceResult(rpcRows.get('task-transfer-after-payer-native')!, {
    envId, operationId, account: fromAddress, blockTag: afterBlockTag,
  });
  const beforeParticipantUsdc = balanceCallResult(rpcRows.get('task-transfer-before-payer-usdc')!, {
    envId, operationId: null, tokenAddress: assetAddress, account: fromAddress, blockTag: beforeBlockTag,
  });
  const beforeRecipientUsdc = balanceCallResult(rpcRows.get('task-transfer-before-recipient-usdc')!, {
    envId, operationId: null, tokenAddress: assetAddress, account: recipientAddress, blockTag: beforeBlockTag,
  });
  const afterParticipantUsdc = balanceCallResult(rpcRows.get('task-transfer-after-payer-usdc')!, {
    envId, operationId, tokenAddress: assetAddress, account: fromAddress, blockTag: afterBlockTag,
  });
  const afterRecipientUsdc = balanceCallResult(rpcRows.get('task-transfer-after-recipient-usdc')!, {
    envId, operationId, tokenAddress: assetAddress, account: recipientAddress, blockTag: afterBlockTag,
  });
  const afterParticipantNative = afterParticipantNativeFromRpc;
  if (beforeParticipantUsdc - afterParticipantUsdc !== amountUnits || afterRecipientUsdc - beforeRecipientUsdc !== amountUnits ||
      !same(measurement.before && record(measurement.before, 'task_observer_measurement_before_invalid').payerUsdcUnits, beforeParticipantUsdc.toString()) ||
      !same(record(measurement.before, 'task_observer_measurement_before_invalid').recipientUsdcUnits, beforeRecipientUsdc.toString()) ||
      !same(record(measurement.after, 'task_observer_measurement_after_invalid').payerUsdcUnits, afterParticipantUsdc.toString()) ||
      !same(record(measurement.after, 'task_observer_measurement_after_invalid').recipientUsdcUnits, afterRecipientUsdc.toString()) ||
      beforeParticipantNative - afterParticipantNative !== hexQuantity(rawReceipt.gasUsed, 'task_observer_rpc_gas_used_invalid') *
        hexQuantity(rawReceipt.effectiveGasPrice, 'task_observer_rpc_gas_price_invalid') ||
      !same(record(measurement.after, 'task_observer_measurement_after_invalid').payerNativeWei, afterParticipantNative.toString())) {
    return fail('task_observer_rpc_balance_delta_conflict');
  }

  const gasUsed = uint(rawReceipt.gasUsed, 'task_observer_rpc_gas_used_invalid');
  const effectiveGasPriceWei = uint(rawReceipt.effectiveGasPrice, 'task_observer_rpc_gas_price_invalid');
  const gasCostWei = gasUsed * effectiveGasPriceWei;
  if (gasUsed !== uint(receipt.gasUsed, 'task_observer_measurement_gas_invalid') ||
      effectiveGasPriceWei !== uint(receipt.effectiveGasPrice, 'task_observer_measurement_gas_price_invalid') ||
      gasCostWei !== uint(receipt.gasCostWei, 'task_observer_measurement_gas_cost_invalid') ||
      afterParticipantNative !== uint(record(measurement.after, 'task_observer_measurement_after_invalid').payerNativeWei, 'task_observer_native_balance_invalid') ||
      !same(fee.modeledGasFeeUsdcUnits, record(capture.principalAndExpense, 'task_observer_capture_cost_invalid').modeledGasFeeUsdcUnits)) {
    return fail('task_observer_rpc_cost_conflict');
  }
  const feePolicy = record(manifest.feePolicy, 'task_observer_fee_policy_invalid');
  const feeNumerator = uint(feePolicy.ethUsdcRateNumerator, 'task_observer_fee_policy_invalid');
  const feeDenominator = uint(feePolicy.ethUsdcRateDenominator, 'task_observer_fee_policy_invalid');
  if (feeDenominator === 0n || gasCostWei * feeNumerator / feeDenominator !== uint(fee.modeledGasFeeUsdcUnits, 'task_observer_modeled_fee_invalid')) {
    return fail('task_observer_fee_policy_arithmetic_conflict');
  }

  const includedPaths = [generationPath, dbPath, paymentsSnapshot.path, deliveriesSnapshot.path, endpointPath, endpointHealthPath,
    ...rpcIds.map((id) => observationPath(probe, id))];
  const evidence = [...new Set(includedPaths)].map((path) => {
    const entry = artifacts.get(path)!;
    return { path, sha256: entry.sha256.toLowerCase(), boundary: entry.boundary };
  });
  return {
    schemaVersion: 'bts-s1-transfer-primitive-candidate/v1',
    status: 'verified_primitive_only',
    classification: 'selected_executor_primitive_capture_not_bts_acceptance',
    taskActionBinding: 'unavailable',
    unavailableReasons: ['task_action_binding_unavailable', 'authoritative_run_cutoff_unavailable'],
    evaluatorObservations: null,
    identity: { envId, generationId, participantId, operationId, transactionHash: txHash },
    transfer: { fromAddress, recipientAddress, assetAddress, amountUnits: amountUnits.toString(), receiptStatus: 'success' },
    finalState: {
      blockNumber: uint(receipt.blockNumber, 'task_observer_measurement_block_invalid').toString(),
      blockHash: hash(receipt.blockHash, 'task_observer_measurement_block_hash_invalid'),
      participantNativeWei: afterParticipantNative.toString(),
      participantUsdcUnits: afterParticipantUsdc.toString(),
      recipientUsdcUnits: afterRecipientUsdc.toString(),
    },
    receiptCost: {
      gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
      modeledGasFeeUsdcUnits: uint(fee.modeledGasFeeUsdcUnits, 'task_observer_modeled_fee_invalid').toString(),
      transactionCostRow: 'unavailable_in_capture',
    },
    relatedRows: { paymentRows: 0, deliveryRows: 0, transactionCostRows: 'not_captured' },
    evidence,
  };
}
