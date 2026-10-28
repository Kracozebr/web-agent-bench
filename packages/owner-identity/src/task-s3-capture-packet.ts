import { createHash } from 'node:crypto';
import {
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  type EvidenceReference,
  type TaskCase,
} from './task-release.js';
import type {
  PersistedTaskObservations,
  TaskEvidenceBinding,
} from './task-evaluator.js';

export type S3TaskCase = Extract<TaskCase, { taskId: 'S3' }>;
export type S3Json = Record<string, unknown>;
const HASH = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const ACTION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/action/';
const PREPARATION_ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/';
const ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation/';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const SECRET_KEYS = new Set(['privatekey','privkey','seedphrase','mnemonic','secret','clientsecret','bearer','bearertoken',
  'accesstoken','refreshtoken','providertoken','paymenttoken','token','apitoken','apikey','authorization','walletmaterial',
  'walletsecret','signature','signedpayload','password','credential','connectionstring','databaseurl','dsn']);

export type S3CaptureAction = {
  actionId: string;
  actionSequence: number;
  ownerOperationId: string;
  commandSha256: string;
  command: { kind: 'inspect_catalog' };
  receiptStatus: 'observed' | 'rejected_before_execution';
  reasonCode: string | null;
  actionEvidence: EvidenceReference;
  befOperationId: string | null;
  response: S3Json | null;
};

export type S3CaptureCheckpoint = {
  blockNumber: string;
  blockHash: string;
  parentHash: string;
  balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
  participantTransactionCount: string;
};
export type S3CaptureCensus = S3Json & {
  generation: S3Json;
  operations: S3Json[];
  selectedExecutions: S3Json[];
  selectedEvents: S3Json[];
  payments: S3Json[];
  deliveries: S3Json[];
  costs: S3Json[];
  denials: S3Json[];
  x402Observations: S3Json[];
  rpcObservations: S3Json[];
  evidenceArtifacts: S3Json[];
};

export type S3CaptureTransaction = { hash: string; from: string; to: string | null; nonce: string; valueWei: string;
  blockNumber: string; blockHash: string; inputSha256: string };
export type S3CaptureBlock = { number: string; hash: string; parentHash: string; transactionCount: number; transactions: S3CaptureTransaction[] };
export type S3CapturePacket = {
  schemaVersion: 'bts-s3-run-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: TaskEvidenceBinding;
  taskCase: S3TaskCase;
  closure: { closureId: string; taskIndex: number; actionCutoffSequence: number; reconciledActionSequence: number;
    reason: 'agent_finish' | 'task_deadline' | 'run_deadline'; operationId: string | null; payloadHash: string; answer: S3Json | null };
  execution: { preparationId: string; leaseId: string; generationId: string; environmentId: string;
    environmentManifestHash: string; applicationSourceHash: string; executionIdentityHash: string; initialStateSha256: string };
  preparation: { fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference; baselineBlockNumber: string; baselineBlockHash: string };
  ownerActions: S3CaptureAction[];
  bef: { session: S3Json; before: S3CaptureCensus; after: S3CaptureCensus; censusSha256: string };
  rpc: { localChainId: string; participant: string; baseline: S3CaptureCheckpoint; final: S3CaptureCheckpoint;
    intervalBlocks: S3CaptureBlock[]; trackedTokenAddresses: string[]; participantLogQueries: Array<{ address: string; fromBlock: string; toBlock: string;
      topics: Array<string | null>; logCount: number }>; responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }> };
};

export type S3PacketProjectionContext = { binding: TaskEvidenceBinding; taskCase: S3TaskCase; captureEvidence?: EvidenceReference };

export class S3CapturePacketError extends Error {
  constructor(readonly code: 'packet_invalid' | 'packet_too_large' | 'binding_mismatch') {
    super(code);
    this.name = 'S3CapturePacketError';
  }
}

function fail(code: S3CapturePacketError['code'] = 'packet_invalid'): never { throw new S3CapturePacketError(code); }
function isRecord(value: unknown): value is S3Json {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}
function exactKeys(value: S3Json, keys: readonly string[]): boolean { return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }
function same(left: unknown, right: unknown): boolean { return canonicalTaskJson(left) === canonicalTaskJson(right); }
function sha(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function validRef(value: unknown, prefix: string): value is EvidenceReference {
  return isRecord(value) && exactKeys(value, ['path','sha256','boundary']) && value.boundary === BOUNDARY &&
    typeof value.path === 'string' && value.path.startsWith(prefix) && value.path.length <= 512 &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path) &&
    !value.path.includes('\\') && value.path.split('/').every((part) => part && part !== '.' && part !== '..') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256);
}
function hasSecret(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (ancestors.has(value)) return true;
  ancestors.add(value);
  const entries = Array.isArray(value) ? value.map((item, i) => [String(i), item] as const) : Object.entries(value);
  const found = entries.some(([key, item]) => SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, '')) || hasSecret(item, ancestors));
  ancestors.delete(value);
  return found;
}
function validBinding(value: unknown): value is TaskEvidenceBinding {
  return isRecord(value) && exactKeys(value, ['ownerId','agentId','runId','environmentId','releaseIdentity','manifestHash','caseId','caseHash','rubricHash','taskId']) &&
    typeof value.ownerId === 'string' && UUID.test(value.ownerId) && typeof value.agentId === 'string' && UUID.test(value.agentId) &&
    typeof value.runId === 'string' && UUID.test(value.runId) && typeof value.environmentId === 'string' && value.environmentId.length > 0 &&
    typeof value.releaseIdentity === 'string' && value.releaseIdentity.length > 0 && typeof value.manifestHash === 'string' && HASH.test(value.manifestHash) &&
    typeof value.caseId === 'string' && value.caseId.length > 0 && typeof value.caseHash === 'string' && HASH.test(value.caseHash) &&
    typeof value.rubricHash === 'string' && HASH.test(value.rubricHash) && value.taskId === 'S3';
}
function validTaskCase(value: unknown): value is S3TaskCase {
  if (!isRecord(value) || value.taskId !== 'S3' || value.mode !== 'ranked' || typeof value.caseId !== 'string' ||
      typeof value.caseHash !== 'string' || !HASH.test(value.caseHash) || typeof value.rubricHash !== 'string' || !HASH.test(value.rubricHash) ||
      !isRecord(value.initialState) || typeof value.initialState.stateSha256 !== 'string' || !HASH.test(value.initialState.stateSha256) ||
      !Array.isArray(value.initialState.balances) || !Array.isArray(value.initialState.allowances) ||
      !Array.isArray(value.initialState.deliveredComponentIds) || !value.initialState.deliveredComponentIds.every((item) => typeof item === 'string') ||
      !Array.isArray(value.initialState.fulfilledObligationIds) || !value.initialState.fulfilledObligationIds.every((item) => typeof item === 'string') ||
      !isRecord(value.objective) || !Array.isArray(value.objective.catalog) || !isRecord(value.objective.required)) return false;
  if (!value.initialState.balances.every((item) => isRecord(item) && typeof item.account === 'string' && typeof item.assetId === 'string' &&
      typeof item.amountUnits === 'string' && /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits)) ||
      !value.initialState.allowances.every((item) => isRecord(item) && typeof item.owner === 'string' && typeof item.tokenAssetId === 'string' &&
        typeof item.spender === 'string' && typeof item.amountUnits === 'string' && /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits))) return false;
  return value.objective.catalog.every((item) => isRecord(item) && typeof item.offerId === 'string' && typeof item.resourceId === 'string' &&
    typeof item.dataType === 'string' && typeof item.advertisedTotalPriceUsdcUnits === 'string' && typeof item.assetId === 'string' &&
    typeof item.network === 'string' && typeof item.recipient === 'string' && isRecord(item.paymentRequirements) &&
    Array.isArray(item.paymentRequirements.authFields) && item.paymentRequirements.authFields.every((field) => isRecord(field) &&
      typeof field.name === 'string' && typeof field.value === 'string'));
}
function validCheckpoint(value: unknown): value is S3CaptureCheckpoint {
  return isRecord(value) && exactKeys(value, ['blockNumber','blockHash','parentHash','balances','allowances','participantTransactionCount']) &&
    typeof value.blockNumber === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value.blockNumber) &&
    typeof value.blockHash === 'string' && /^0x[0-9a-f]{64}$/i.test(value.blockHash) &&
    typeof value.parentHash === 'string' && /^0x[0-9a-f]{64}$/i.test(value.parentHash) &&
    typeof value.participantTransactionCount === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value.participantTransactionCount) &&
    Array.isArray(value.balances) && value.balances.every((item) => isRecord(item) && exactKeys(item, ['account','assetId','amountUnits']) &&
      typeof item.account === 'string' && typeof item.assetId === 'string' && typeof item.amountUnits === 'string' && /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits)) &&
    Array.isArray(value.allowances) && value.allowances.every((item) => isRecord(item) && exactKeys(item, ['owner','tokenAssetId','spender','amountUnits']) &&
      typeof item.owner === 'string' && typeof item.tokenAssetId === 'string' && typeof item.spender === 'string' && typeof item.amountUnits === 'string' &&
      /^(?:0|[1-9][0-9]*)$/.test(item.amountUnits));
}
function validCatalogResponse(taskCase: S3TaskCase, value: S3Json): boolean {
  if (!exactKeys(value, ['operationId','readHandle','catalog','freeInspection','deliveryState']) || !Array.isArray(value.catalog)) return false;
  const expected = new Map<string, typeof taskCase.objective.catalog>();
  for (const offer of taskCase.objective.catalog) expected.set(offer.resourceId, [...(expected.get(offer.resourceId) ?? []), offer]);
  if (value.catalog.length !== expected.size) return false;
  const seenResources = new Set<string>();
  const addressByAsset = new Map<string, string>();
  for (const item of value.catalog) {
    if (!isRecord(item) || !exactKeys(item, ['resourceId','resourceSha256','contentType','dataType','schema','provenance','offers']) &&
        !exactKeys(item, ['resourceId','resourceSha256','contentType','dataType','offers']) ||
        typeof item.resourceId !== 'string' || typeof item.resourceSha256 !== 'string' || !HASH.test(item.resourceSha256) ||
        typeof item.contentType !== 'string' || item.contentType.length < 1 || item.contentType.length > 128 || !Array.isArray(item.offers)) return false;
    const pinned = expected.get(item.resourceId);
    if (!pinned || seenResources.has(item.resourceId) || item.dataType !== pinned[0]!.dataType || item.offers.length !== pinned.length) return false;
    if (item.schema !== undefined && typeof item.schema !== 'string' || item.provenance !== undefined && !isRecord(item.provenance)) return false;
    const byId = new Map(pinned.map((offer) => [offer.offerId, offer]));
    const seenOffers = new Set<string>();
    for (const offerValue of item.offers) {
      if (!isRecord(offerValue) || !exactKeys(offerValue, ['id','payment']) || typeof offerValue.id !== 'string' || !isRecord(offerValue.payment)) return false;
      const pinnedOffer = byId.get(offerValue.id), payment = offerValue.payment;
      if (!pinnedOffer || seenOffers.has(offerValue.id) || !exactKeys(payment, ['scheme','network','asset','amount','payTo','transferMethod']) ||
          payment.scheme !== pinnedOffer.paymentRequirements.scheme || payment.network !== pinnedOffer.paymentRequirements.network ||
          payment.amount !== pinnedOffer.paymentRequirements.amountUnits || String(payment.payTo).toLowerCase() !== pinnedOffer.recipient.toLowerCase() ||
          payment.transferMethod !== pinnedOffer.paymentRequirements.authFields.find((field) => field.name === 'assetTransferMethod')?.value ||
          typeof payment.asset !== 'string' || !ADDRESS.test(payment.asset)) return false;
      const priorAddress = addressByAsset.get(pinnedOffer.assetId);
      if (priorAddress && priorAddress !== payment.asset.toLowerCase()) return false;
      addressByAsset.set(pinnedOffer.assetId, payment.asset.toLowerCase());
      seenOffers.add(offerValue.id);
    }
    if (seenOffers.size !== byId.size) return false;
    seenResources.add(item.resourceId);
  }
  return seenResources.size === expected.size;
}
function validAction(value: unknown, runId: string, taskIndex: number, taskCase: S3TaskCase): value is S3CaptureAction {
  if (!isRecord(value) || !exactKeys(value, ['actionId','actionSequence','ownerOperationId','commandSha256','command','receiptStatus','reasonCode','actionEvidence','befOperationId','response']) ||
      typeof value.actionId !== 'string' || !UUID.test(value.actionId) || !Number.isSafeInteger(value.actionSequence) ||
      (value.actionSequence as number) < 1 || typeof value.ownerOperationId !== 'string' || value.ownerOperationId.length < 12 ||
      typeof value.commandSha256 !== 'string' || !HASH.test(value.commandSha256) || !isRecord(value.command) || !exactKeys(value.command, ['kind']) ||
      value.command.kind !== 'inspect_catalog' || !validRef(value.actionEvidence, ACTION_ROOT)) return false;
  if (sha256CanonicalTaskJson({ runId, taskIndex, command: value.command }).toLowerCase() !== value.commandSha256.toLowerCase()) return false;
  if (value.receiptStatus === 'rejected_before_execution') {
    return typeof value.reasonCode === 'string' && value.reasonCode.length > 0 && value.reasonCode.length <= 128 &&
      value.befOperationId === null && value.response === null;
  }
  if (value.receiptStatus !== 'observed' || value.reasonCode !== null || typeof value.befOperationId !== 'string' || !UUID.test(value.befOperationId) || !isRecord(value.response)) return false;
  const body = value.response;
  return body.operationId === value.befOperationId && isRecord(body.readHandle) && body.readHandle.kind === 'catalog' &&
    body.readHandle.operationId === value.befOperationId && body.freeInspection === true && body.deliveryState === 'not_delivered' &&
    Array.isArray(body.catalog) && body.catalog.length > 0 && validCatalogResponse(taskCase, body);
}
function validCensus(value: unknown): value is S3CaptureCensus {
  if (!isRecord(value) || !exactKeys(value, ['generation','operations','selectedExecutions','selectedEvents','payments','deliveries','costs',
    'denials','x402Observations','rpcObservations','evidenceArtifacts'])) return false;
  const arrays = ['operations','selectedExecutions','selectedEvents','payments','deliveries','costs','denials','x402Observations','rpcObservations','evidenceArtifacts'];
  return isRecord(value.generation) && arrays.every((key) => Array.isArray(value[key]));
}

export function validateS3CapturePacket(value: unknown): asserts value is S3CapturePacket {
  if (!isRecord(value)) fail();
  const packetBinding = value.binding as S3Json;
  const packetClosure = value.closure as S3Json;
  const packetExecution = value.execution as S3Json;
  if (Buffer.byteLength(canonicalTaskJson(value), 'utf8') > 8 * 1024 * 1024) fail('packet_too_large');
  if (hasSecret(value) || !exactKeys(value, ['schemaVersion','classification','binding','taskCase','closure','execution','preparation','ownerActions','bef','rpc']) ||
      value.schemaVersion !== 'bts-s3-run-observation-capture/v1' || value.classification !== 'run_bound_observations_candidate_not_grade' ||
      !validBinding(value.binding) || !validTaskCase(value.taskCase) ||
      value.binding.caseId !== value.taskCase.caseId || value.binding.caseHash.toLowerCase() !== String(value.taskCase.caseHash).toLowerCase() ||
      value.binding.rubricHash.toLowerCase() !== String(value.taskCase.rubricHash).toLowerCase() ||
      !isRecord(value.closure) || !exactKeys(value.closure, ['closureId','taskIndex','actionCutoffSequence','reconciledActionSequence','reason','operationId','payloadHash','answer']) ||
      typeof value.closure.closureId !== 'string' || !UUID.test(value.closure.closureId) || !Number.isSafeInteger(value.closure.taskIndex) ||
      !Number.isSafeInteger(value.closure.actionCutoffSequence) || !Number.isSafeInteger(value.closure.reconciledActionSequence) ||
      (value.closure.reconciledActionSequence as number) < (value.closure.actionCutoffSequence as number) ||
      !['agent_finish','task_deadline','run_deadline'].includes(String(value.closure.reason)) ||
      (value.closure.reason === 'agent_finish' ? typeof value.closure.operationId !== 'string' : value.closure.operationId !== null) ||
      typeof value.closure.payloadHash !== 'string' || !HASH.test(value.closure.payloadHash) ||
      !isRecord(value.execution) || !exactKeys(value.execution, ['preparationId','leaseId','generationId','environmentId','environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256']) ||
      !UUID.test(String(value.execution.preparationId)) || !UUID.test(String(value.execution.leaseId)) || !UUID.test(String(value.execution.generationId)) ||
      value.execution.environmentId !== value.binding.environmentId ||
      ['environmentManifestHash','applicationSourceHash','executionIdentityHash','initialStateSha256'].some((key) => !HASH.test(String(packetExecution[key]))) ||
      !isRecord(value.preparation) || !exactKeys(value.preparation, ['fixtureEvidence','baselineEvidence','baselineBlockNumber','baselineBlockHash']) ||
      !validRef(value.preparation.fixtureEvidence, PREPARATION_ROOT) || !validRef(value.preparation.baselineEvidence, PREPARATION_ROOT) ||
      value.preparation.fixtureEvidence.path === value.preparation.baselineEvidence.path ||
      typeof value.preparation.baselineBlockNumber !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value.preparation.baselineBlockNumber) ||
      typeof value.preparation.baselineBlockHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(value.preparation.baselineBlockHash) ||
      !Array.isArray(value.ownerActions) || value.ownerActions.length !== value.closure.actionCutoffSequence ||
      !value.ownerActions.every((item, index) => validAction(item, String(packetBinding.runId), packetClosure.taskIndex as number,
        value.taskCase as S3TaskCase) && item.actionSequence === index + 1) ||
      !isRecord(value.bef) || !exactKeys(value.bef, ['session','before','after','censusSha256']) ||
      !isRecord(value.bef.session) || !exactKeys(value.bef.session, ['currentUser','sessionUser','databaseName','transactionReadOnly','superuser','bypassRls']) ||
      value.bef.session.currentUser !== 'bef_observer' || value.bef.session.sessionUser !== 'bef_observer' ||
      typeof value.bef.session.databaseName !== 'string' || value.bef.session.databaseName.length < 1 ||
      value.bef.session.transactionReadOnly !== 'on' || value.bef.session.superuser !== false || value.bef.session.bypassRls !== false ||
      !validCensus(value.bef.before) || !validCensus(value.bef.after) || !same(value.bef.before, value.bef.after) ||
      !same(value.bef.before, value.bef.after) || typeof value.bef.censusSha256 !== 'string' ||
      value.bef.censusSha256.toLowerCase() !== sha256CanonicalTaskJson(value.bef.before).toLowerCase() ||
      !isRecord(value.rpc) || !exactKeys(value.rpc, ['localChainId','participant','baseline','final','intervalBlocks','trackedTokenAddresses','participantLogQueries','responseHashes']) ||
      typeof value.rpc.localChainId !== 'string' || !/^[1-9][0-9]*$/.test(value.rpc.localChainId) ||
      typeof value.rpc.participant !== 'string' || !ADDRESS.test(value.rpc.participant) ||
      !validCheckpoint(value.rpc.baseline) || !validCheckpoint(value.rpc.final) || !Array.isArray(value.rpc.intervalBlocks) ||
      !Array.isArray(value.rpc.trackedTokenAddresses) || !value.rpc.trackedTokenAddresses.every((address) => typeof address === 'string' && ADDRESS.test(address)) ||
      !Array.isArray(value.rpc.participantLogQueries) || !Array.isArray(value.rpc.responseHashes)) fail();

  const census = value.bef.before as S3Json;
  const ownerActions = value.ownerActions as S3CaptureAction[];
  const observedActions = ownerActions.filter((action) => action.receiptStatus === 'observed');
  const rejectedActions = ownerActions.filter((action) => action.receiptStatus === 'rejected_before_execution');
  const expectedOps = observedActions.map((action) => action.befOperationId!.toLowerCase()).sort();
  const observedOps = (census.operations as S3Json[]).map((op) => String(op.operation_id).toLowerCase()).sort();
  if (!same(expectedOps, observedOps) || (census.selectedExecutions as unknown[]).length || (census.selectedEvents as unknown[]).length ||
      (census.payments as unknown[]).length || (census.deliveries as unknown[]).length || (census.costs as unknown[]).length ||
      (census.denials as unknown[]).length || (census.x402Observations as unknown[]).length || (census.rpcObservations as unknown[]).length ||
      (census.evidenceArtifacts as unknown[]).length) fail();
  const execution = value.execution as S3Json;
  const generation = census.generation as S3Json;
  if (!exactKeys(generation, ['generation_id','env_id','participant_id','payer_address','manifest_sha256','status','resource_variant',
      'fixture_transaction_hash','fixture_block_hash','fixture_token_delta_units','fixture_native_balance_wei','expires_at','fenced_at','chain_id','node_identity','environment_manifest_sha256']) ||
      generation.env_id !== value.binding.environmentId || generation.generation_id !== execution.generationId ||
      generation.status !== 'active' || generation.resource_variant !== 'canonical' ||
      String(generation.manifest_sha256).toLowerCase() !== String(execution.environmentManifestHash).toLowerCase() ||
      String(generation.environment_manifest_sha256).toLowerCase() !== String(execution.environmentManifestHash).toLowerCase() ||
      String(generation.payer_address).toLowerCase() !== String(value.rpc.participant).toLowerCase()) fail();
  const operations = census.operations as S3Json[];
  for (const action of rejectedActions) {
    const idempotencyHash = sha(`task-action-${action.actionId}`);
    if (operations.some((op) => String(op.idempotency_key_sha256).toLowerCase() === idempotencyHash)) fail();
  }
  for (const action of observedActions) {
    const op = operations.find((item) => String(item.operation_id).toLowerCase() === action.befOperationId!.toLowerCase());
    const expectedRequest = sha(JSON.stringify({ method: 'GET', path: '/catalog' }));
    if (!op || !exactKeys(op, ['operation_id','env_id','generation_id','participant_id','idempotency_key_sha256','request_sha256','operation_kind',
        'status','receipt_status','transaction_hash','response_sha256','started_at','completed_at']) ||
        String(op.idempotency_key_sha256).toLowerCase() !== sha(`task-action-${action.actionId}`) ||
        op.env_id !== value.binding.environmentId || op.generation_id !== execution.generationId ||
        op.participant_id !== generation.participant_id || op.operation_kind !== 'catalog' || op.status !== 'accepted' ||
        op.receipt_status !== 'not_submitted' || op.transaction_hash !== null ||
        String(op.request_sha256).toLowerCase() !== expectedRequest || typeof op.response_sha256 !== 'string' || !HASH.test(op.response_sha256)) fail();
  }
  const taskCase = value.taskCase as S3TaskCase;
  const rpc = value.rpc as S3CapturePacket['rpc'];
  const canonicalBalances = [...taskCase.initialState.balances].sort((a,b) => `${a.account.toLowerCase()}|${a.assetId}`.localeCompare(`${b.account.toLowerCase()}|${b.assetId}`));
  const canonicalAllowances = [...taskCase.initialState.allowances].sort((a,b) => `${a.owner.toLowerCase()}|${a.tokenAssetId}|${a.spender.toLowerCase()}`
    .localeCompare(`${b.owner.toLowerCase()}|${b.tokenAssetId}|${b.spender.toLowerCase()}`));
  const initialProjection = { balances: canonicalBalances, allowances: canonicalAllowances,
    deliveredComponentIds: [...taskCase.initialState.deliveredComponentIds].sort(),
    fulfilledObligationIds: [...taskCase.initialState.fulfilledObligationIds].sort() };
  if (sha256CanonicalTaskJson(initialProjection).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase() ||
      String(value.execution.initialStateSha256).toLowerCase() !== taskCase.initialState.stateSha256.toLowerCase() ||
      value.preparation.baselineBlockNumber !== value.rpc.baseline.blockNumber ||
      value.preparation.baselineBlockHash.toLowerCase() !== value.rpc.baseline.blockHash.toLowerCase() ||
      !same(value.rpc.baseline.balances, canonicalBalances) || !same(value.rpc.final.balances, canonicalBalances) ||
      !same(value.rpc.baseline.allowances, canonicalAllowances) || !same(value.rpc.final.allowances, canonicalAllowances) ||
      taskCase.initialState.deliveredComponentIds.length !== 0 || taskCase.initialState.fulfilledObligationIds.length !== 0) fail();
  const expectedAnswer = value.closure.reason === 'agent_finish' ? value.closure.answer : null;
  if (value.closure.reason === 'agent_finish') {
    if (expectedAnswer !== null && (!isRecord(expectedAnswer) || !exactKeys(expectedAnswer, Object.keys(expectedAnswer)) ||
        Object.keys(expectedAnswer).some((key) => key !== 'offerId') ||
        (expectedAnswer.offerId !== undefined && (typeof expectedAnswer.offerId !== 'string' || expectedAnswer.offerId.length > 128)))) fail();
    if (sha256CanonicalTaskJson({ action: 'task_finish', runId: value.binding.runId, taskIndex: value.closure.taskIndex, answer: expectedAnswer }).toLowerCase() !==
        value.closure.payloadHash.toLowerCase()) fail();
  } else if (value.closure.answer !== null || sha256CanonicalTaskJson({ runId: value.binding.runId, taskIndex: value.closure.taskIndex,
    reason: value.closure.reason }).toLowerCase() !== value.closure.payloadHash.toLowerCase()) fail();
  if (canonicalTaskJson(rpc.baseline.balances) !== canonicalTaskJson(rpc.final.balances) ||
      canonicalTaskJson(rpc.baseline.allowances) !== canonicalTaskJson(rpc.final.allowances) ||
      rpc.baseline.participantTransactionCount !== rpc.final.participantTransactionCount) fail();
  let previousHash = rpc.baseline.blockHash;
  let previousNumber = BigInt(rpc.baseline.blockNumber);
  for (const block of rpc.intervalBlocks) {
    if (!isRecord(block) || !Number.isSafeInteger(block.transactionCount) || !Array.isArray(block.transactions) ||
        BigInt(block.number) !== previousNumber + 1n || block.parentHash !== previousHash || block.transactions.length !== block.transactionCount ||
        block.transactions.some((tx) => !isRecord(tx) || !/^0x[0-9a-f]{64}$/i.test(tx.hash) || !ADDRESS.test(tx.from) ||
          (tx.to !== null && !ADDRESS.test(tx.to)) || tx.from.toLowerCase() === rpc.participant.toLowerCase() ||
          !/^(?:0|[1-9][0-9]*)$/.test(tx.nonce) || !/^(?:0|[1-9][0-9]*)$/.test(tx.valueWei) ||
          tx.blockNumber !== block.number || tx.blockHash !== block.hash || !HASH.test(tx.inputSha256))) fail();
    previousNumber = BigInt(block.number); previousHash = block.hash;
  }
  if (previousNumber !== BigInt(rpc.final.blockNumber) || previousHash !== rpc.final.blockHash) fail();
  const queries = rpc.participantLogQueries as S3Json[];
  const tracked = rpc.trackedTokenAddresses.map((address) => address.toLowerCase());
  if (new Set(tracked).size !== tracked.length) fail();
  const expectedQueryKeys = new Set<string>();
  if (BigInt(rpc.final.blockNumber) > BigInt(rpc.baseline.blockNumber)) {
    const participantTopic = `0x${rpc.participant.slice(2).toLowerCase().padStart(64, '0')}`;
    for (const address of tracked) {
      expectedQueryKeys.add(canonicalTaskJson({ address, topics: [TRANSFER_TOPIC, participantTopic] }));
      expectedQueryKeys.add(canonicalTaskJson({ address, topics: [TRANSFER_TOPIC, null, participantTopic] }));
      expectedQueryKeys.add(canonicalTaskJson({ address, topics: [APPROVAL_TOPIC, participantTopic] }));
    }
  }
  const actualQueryKeys = new Set<string>();
  for (const query of queries) {
    if (!isRecord(query) || !ADDRESS.test(String(query.address)) || typeof query.fromBlock !== 'string' || typeof query.toBlock !== 'string' ||
        query.logCount !== 0 || !Array.isArray(query.topics)) fail();
    const queryKey = canonicalTaskJson({ address: String(query.address).toLowerCase(), topics: query.topics });
    if (actualQueryKeys.has(queryKey) || !expectedQueryKeys.has(queryKey) ||
        query.fromBlock !== `0x${(BigInt(rpc.baseline.blockNumber) + 1n).toString(16)}` ||
        query.toBlock !== `0x${BigInt(rpc.final.blockNumber).toString(16)}`) fail();
    actualQueryKeys.add(queryKey);
    const expectedParamsHash = sha256CanonicalTaskJson([{ address: String(query.address).toLowerCase(), fromBlock: query.fromBlock,
      toBlock: query.toBlock, topics: query.topics }]).toLowerCase();
    if (!(value.rpc.responseHashes as S3Json[]).some((item) => item.method === 'eth_getLogs' &&
        String(item.paramsSha256).toLowerCase() === expectedParamsHash &&
        String(item.resultSha256).toLowerCase() === sha256CanonicalTaskJson([]).toLowerCase())) fail();
  }
  if (actualQueryKeys.size !== expectedQueryKeys.size) fail();
}

export function parseS3CapturePacket(bytes: Uint8Array | string): S3CapturePacket {
  const raw = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : Buffer.from(bytes);
  if (raw.byteLength > 8 * 1024 * 1024) fail('packet_too_large');
  let value: unknown;
  try { value = JSON.parse(raw.toString('utf8')) as unknown; } catch { fail(); }
  validateS3CapturePacket(value);
  return value;
}

export function projectS3PacketObservations(value: unknown, context: S3PacketProjectionContext): PersistedTaskObservations {
  validateS3CapturePacket(value);
  const packet = value;
  if (!same(packet.binding, context.binding) || !same(packet.taskCase, context.taskCase) ||
      packet.binding.caseHash.toLowerCase() !== context.taskCase.caseHash.toLowerCase()) fail('binding_mismatch');
  const evidence: EvidenceReference = context.captureEvidence ?? { path: `${ROOT}pending`, sha256: '0'.repeat(64), boundary: BOUNDARY };
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding: packet.binding, coveredThroughSequence: 0, captureEvidence: evidence,
    coverage: { transfers:'complete',payments:'complete',stateMutations:'complete',balances:'complete',allowances:'complete',deliveries:'complete',answers:'complete',selections:'complete' },
    transfers:[],payments:[],stateMutations:[],finalStates:[],allowanceChanges:[],allowanceUses:[],answers:[],selections:[],deliveries:[],trades:[],conversions:[],expenses:[],
  };
  let sequence = 0;
  const answer = packet.closure.answer;
  if (answer) {
    sequence += 1;
    observations.answers.push({ kind:'final_answer',observationId:`s3-answer-${packet.closure.closureId}`,sequence,
      actionSequence:packet.closure.actionCutoffSequence,source:'persisted_observer',binding:packet.binding,evidence,answer });
    if (typeof answer.offerId === 'string') {
      sequence += 1;
      observations.selections.push({ kind:'offer_selection',observationId:`s3-selection-${packet.closure.closureId}`,sequence,
        actionSequence:packet.closure.actionCutoffSequence,source:'persisted_observer',binding:packet.binding,evidence,offerId:answer.offerId });
    }
  }
  sequence += 1;
  observations.finalStates.push({ kind:'final_state',observationId:`s3-final-${packet.binding.runId}-${packet.closure.taskIndex}`,
    sequence,actionSequence:packet.closure.actionCutoffSequence,source:'persisted_observer',binding:packet.binding,evidence,
    balances:packet.rpc.final.balances,allowances:packet.rpc.final.allowances });
  observations.coveredThroughSequence = sequence;
  return observations;
}
