import { createHash } from 'node:crypto';
import { canonicalTaskJson, type DataComponentValidator, type EvidenceReference, type TaskCase } from './task-release.js';
import type {
  DataDeliveryObservation, ExpenseObservation, PaymentObservation, PersistedTaskObservations, StateMutationObservation, TaskEvidenceBinding,
  TransferObservation,
} from './task-evaluator.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/i;
const TX = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';
const PREPARATION_PREFIX = `${ROOT}preparation/`;
const ACTION_PREFIX = `${ROOT}action/`;
const CAPTURE_PREFIX = `${ROOT}observation/`;
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_ACTIONS = 256;
const MAX_ROWS = 2048;

/** BEF hashes its outer request envelope around the canonically serialized owner body. */
export function splitPayRequestSha256(environmentId:unknown,body:Record<string,unknown>):string {
  if(typeof environmentId!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(environmentId))fail('M1_CAPTURE_PACKET_INVALID');
  const parsedBody=JSON.parse(canonicalTaskJson(body)) as Record<string,unknown>;
  return createHash('sha256').update(JSON.stringify({method:'POST',path:`/tools/${environmentId}/pay`,body:parsedBody})).digest('hex');
}

type JsonRecord = Record<string, unknown>;
type M1ActionKind = 'inspect_catalog' | 'inspect_offer' | 'pay' | 'retrieve';
type M1ActionStatus = 'observed' | 'rejected_before_execution';

export type M1CaptureAction = {
  actionId: string;
  actionSequence: number;
  ownerOperationId: string;
  actionKind: M1ActionKind;
  commandSha256: string;
  receiptStatus: M1ActionStatus;
  actionEvidence: EvidenceReference;
  befOperationId: string | null;
  transactionHash: string | null;
  rawResponseSha256: string | null;
  participantToolResponse: JsonRecord | null;
  paymentProtocol: JsonRecord | null;
};

export type M1CaptureCensus = {
  generation: JsonRecord;
  operations: JsonRecord[];
  selectedExecutions: JsonRecord[];
  selectedEvents: JsonRecord[];
  payments: JsonRecord[];
  deliveries: JsonRecord[];
  costs: JsonRecord[];
  denials: JsonRecord[];
  x402Observations: JsonRecord[];
  rpcObservations: JsonRecord[];
  evidenceArtifacts: JsonRecord[];
};

export type M1CapturePacket = {
  schemaVersion: 'bts-m1-run-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: JsonRecord;
  closure: JsonRecord;
  execution: JsonRecord;
  preparation: JsonRecord;
  ownerActions: M1CaptureAction[];
  bef: {
    session: JsonRecord;
    before: M1CaptureCensus;
    after: M1CaptureCensus;
    censusSha256: string;
    resourcePin: {
      resourceId: string;
      resourceSha256: string;
      contentType: string;
      offers: Array<{ id: string; amount: string }>;
      paymentPolicy: { scheme: string; network: string; asset: string; assetTransferMethod: string; eip712Domain: { name: string; version: string } };
    };
    environmentManifest: { encoding: 'base64'; bytes: string; sha256: string };
  };
  rpc: JsonRecord;
};

export class M1CapturePacketError extends Error {
  constructor(readonly code: 'M1_CAPTURE_PACKET_INVALID' | 'M1_CAPTURE_PACKET_SECRET_FIELD' | 'M1_CAPTURE_PACKET_LIMIT_EXCEEDED') {
    super(code);
    this.name = 'M1CapturePacketError';
  }
}

function fail(code: M1CapturePacketError['code']): never { throw new M1CapturePacketError(code); }

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join('\u0000') === [...keys].sort().join('\u0000');
}

function record(value: unknown, keys: readonly string[]): JsonRecord {
  if (!isRecord(value) || !exactKeys(value, keys)) fail('M1_CAPTURE_PACKET_INVALID');
  return value;
}

function validRef(value: unknown, prefix: string): value is EvidenceReference {
  return isRecord(value) && exactKeys(value, ['path', 'sha256', 'boundary']) && value.boundary === BOUNDARY &&
    typeof value.path === 'string' && value.path.startsWith(prefix) && value.path.length <= 512 &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path) &&
    !value.path.includes('\\') && !value.path.includes('\0') && value.path.split('/').every((part) => part && part !== '.' && part !== '..') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256);
}

function safeSequence(value: unknown): number | null {
  if (typeof value !== 'number' && !(typeof value === 'string' && UINT.test(value))) return null;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : null;
  } catch { return null; }
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value));
}

function boundedString(value: unknown, max = 2048): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function nullableString(value: unknown, max = 2048): boolean {
  return value === null || boundedString(value, max);
}

function hasSecretKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasSecretKey);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, child]) => {
    const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
    const secret = /^(?:privatekey|privkey|seedphrase|mnemonic|secret|clientsecret|bearer|bearertoken|accesstoken|refreshtoken|providertoken|paymenttoken|token|apitoken|apikey|authorization|walletmaterial|walletsecret|signature|signedpayload|signedtransaction|rawsignedtransaction|paymentpayload|transferpayload|credential|password|connectionstring|databaseurl|dsn|paymentsignature|paymentauthorization|paymentauth|paymentproof|paymentresponse|xpayment|xpaymentresponse|xpaymentsignature|xpaymentpayload|xpaymentauthorization|x402authorization|x402signature|x402payload|x402proof|calldata|transactioninput|txinput)$/.test(normalized);
    return secret || hasSecretKey(child);
  });
}

function validateManifest(bytesBase64: string, expectedSha256: string): JsonRecord {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bytesBase64)) fail('M1_CAPTURE_PACKET_INVALID');
  const bytes = Buffer.from(bytesBase64, 'base64');
  if (bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES || bytes.toString('base64') !== bytesBase64 ||
      createHash('sha256').update(bytes).digest('hex') !== expectedSha256.toLowerCase()) fail('M1_CAPTURE_PACKET_INVALID');
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
  catch { fail('M1_CAPTURE_PACKET_INVALID'); }
  if (!isRecord(parsed) || parsed.schemaVersion !== 'bef-runtime-manifest/v1' || !isRecord(parsed.x402)) fail('M1_CAPTURE_PACKET_INVALID');
  const x402 = parsed.x402;
  if (x402.scheme !== 'exact' || x402.assetTransferMethod !== 'eip3009' || typeof x402.network !== 'string' ||
      !/^eip155:[1-9][0-9]*$/.test(x402.network) || typeof x402.asset !== 'string' || !ADDRESS.test(x402.asset) ||
      !Array.isArray(x402.catalog) || x402.catalog.length < 1 || x402.catalog.length > 32) fail('M1_CAPTURE_PACKET_INVALID');
  const resourceIds = new Set<string>();
  for (const candidate of x402.catalog) {
    if (!isRecord(candidate) || typeof candidate.resourceId !== 'string' || candidate.resourceId.length < 1 || candidate.resourceId.length > 128 ||
        resourceIds.has(candidate.resourceId) || typeof candidate.resourceSha256 !== 'string' || !HASH.test(candidate.resourceSha256) ||
        candidate.contentType !== 'application/json' || typeof candidate.schema !== 'string' || candidate.schema.length < 1 ||
        !Array.isArray(candidate.offers) || candidate.offers.length < 1 || candidate.offers.length > 8 || !isRecord(candidate.provenance)) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
    resourceIds.add(candidate.resourceId);
    const offerIds = new Set<string>();
    for (const offer of candidate.offers) {
      if (!isRecord(offer) || typeof offer.id !== 'string' || offer.id.length < 1 || offer.id.length > 128 || offerIds.has(offer.id) ||
          typeof offer.amount !== 'string' || !/^[1-9][0-9]{0,77}$/.test(offer.amount)) fail('M1_CAPTURE_PACKET_INVALID');
      offerIds.add(offer.id);
    }
  }
  return parsed;
}

function validateCensus(value: unknown): M1CaptureCensus {
  const censusKeys = ['generation', 'operations', 'selectedExecutions', 'selectedEvents', 'payments', 'deliveries', 'costs',
    'denials', 'x402Observations', 'rpcObservations', 'evidenceArtifacts'] as const;
  const census = record(value, censusKeys);
  const generation = record(census.generation, ['generation_id','env_id','participant_id','payer_address','manifest_sha256','status','resource_variant',
    'fixture_transaction_hash','fixture_block_hash','fixture_token_delta_units','fixture_native_balance_wei','expires_at','fenced_at','chain_id',
    'node_identity','environment_manifest_sha256']);
  if (typeof generation.generation_id !== 'string' || !UUID.test(generation.generation_id) || !boundedString(generation.env_id, 128) ||
      typeof generation.participant_id !== 'string' || !UUID.test(generation.participant_id) || typeof generation.payer_address !== 'string' ||
      !ADDRESS.test(generation.payer_address) || typeof generation.manifest_sha256 !== 'string' || !HASH.test(generation.manifest_sha256) ||
      generation.status !== 'active' || !boundedString(generation.resource_variant, 128) ||
      (generation.fixture_transaction_hash !== null && (typeof generation.fixture_transaction_hash !== 'string' || !TX.test(generation.fixture_transaction_hash))) ||
      (generation.fixture_block_hash !== null && (typeof generation.fixture_block_hash !== 'string' || !TX.test(generation.fixture_block_hash))) ||
      (generation.fixture_token_delta_units !== null && (typeof generation.fixture_token_delta_units !== 'string' || !UINT.test(generation.fixture_token_delta_units))) ||
      (generation.fixture_native_balance_wei !== null && (typeof generation.fixture_native_balance_wei !== 'string' || !UINT.test(generation.fixture_native_balance_wei))) ||
      !timestamp(generation.expires_at) || (generation.fenced_at !== null && !timestamp(generation.fenced_at)) ||
      typeof generation.chain_id !== 'string' || !DECIMAL.test(generation.chain_id) || !boundedString(generation.node_identity, 256) ||
      typeof generation.environment_manifest_sha256 !== 'string' || !HASH.test(generation.environment_manifest_sha256)) fail('M1_CAPTURE_PACKET_INVALID');
  for (const key of censusKeys.slice(1)) {
    const rows = census[key];
    if (!Array.isArray(rows) || rows.length > MAX_ROWS || rows.some((row) => !isRecord(row))) fail('M1_CAPTURE_PACKET_INVALID');
  }
  const operations = census.operations as JsonRecord[];
  const operationIds = new Set<string>();
  for (const value of operations) {
    const op = record(value, ['operation_id','env_id','generation_id','participant_id','idempotency_key_sha256','request_sha256',
      'operation_kind','status','receipt_status','transaction_hash','response_sha256','started_at','completed_at','selected_offer_id',
      'selected_amount_units','selected_resource_id','selected_resource_sha256','payment_response_mode']);
    if (typeof op.operation_id !== 'string' || !UUID.test(op.operation_id) || operationIds.has(op.operation_id) ||
        op.env_id !== generation.env_id || op.generation_id !== generation.generation_id ||
        typeof op.participant_id !== 'string' || !UUID.test(op.participant_id) || typeof op.idempotency_key_sha256 !== 'string' || !HASH.test(op.idempotency_key_sha256) ||
        typeof op.request_sha256 !== 'string' || !HASH.test(op.request_sha256) || !['catalog','offer','purchase'].includes(String(op.operation_kind)) ||
        !['accepted','awaiting_payment','verifying','settling','settlement_unknown','settled','delivered','rejected','reverted'].includes(String(op.status)) ||
        !['unknown','not_submitted','success','reverted'].includes(String(op.receipt_status)) ||
        (op.transaction_hash !== null && (typeof op.transaction_hash !== 'string' || !TX.test(op.transaction_hash))) ||
        (op.response_sha256 !== null && (typeof op.response_sha256 !== 'string' || !HASH.test(op.response_sha256))) ||
        !timestamp(op.started_at) || (op.completed_at !== null && (!timestamp(op.completed_at) || Date.parse(op.completed_at) < Date.parse(op.started_at))) ||
        (op.selected_offer_id !== null && typeof op.selected_offer_id !== 'string') ||
        (op.selected_amount_units !== null && (typeof op.selected_amount_units !== 'string' || !UINT.test(op.selected_amount_units))) ||
        (op.selected_resource_id !== null && typeof op.selected_resource_id !== 'string') ||
        (op.selected_resource_sha256 !== null && (typeof op.selected_resource_sha256 !== 'string' || !HASH.test(op.selected_resource_sha256))) ||
        (op.payment_response_mode !== null && typeof op.payment_response_mode !== 'string')) fail('M1_CAPTURE_PACKET_INVALID');
    operationIds.add(op.operation_id);
  }
  for (const value of census.selectedExecutions as JsonRecord[]) {
    const row = record(value, ['operation_id','env_id','generation_id','action_kind','transaction_hash','outcome']);
    if (typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id) || row.env_id !== generation.env_id ||
        row.generation_id !== generation.generation_id || !['catalog','offer','purchase'].includes(String(row.action_kind)) ||
        (row.transaction_hash !== null && (typeof row.transaction_hash !== 'string' || !TX.test(row.transaction_hash))) ||
        !['success','reverted'].includes(String(row.outcome))) fail('M1_CAPTURE_PACKET_INVALID');
  }
  const events = census.selectedEvents as JsonRecord[];
  const eventIds = new Set<string>(); const eventSequences = new Set<string>();
  for (const value of events) {
    const row = record(value, ['event_sequence','event_id','operation_id','env_id','generation_id','event_kind','transaction_hash','created_at']);
    if (typeof row.event_sequence !== 'string' || !DECIMAL.test(row.event_sequence) || eventSequences.has(row.event_sequence) ||
        typeof row.event_id !== 'string' || !UUID.test(row.event_id) || eventIds.has(row.event_id) || typeof row.operation_id !== 'string' ||
        !operationIds.has(row.operation_id) || row.env_id !== generation.env_id || row.generation_id !== generation.generation_id ||
        !boundedString(row.event_kind, 128) || (row.transaction_hash !== null && (typeof row.transaction_hash !== 'string' || !TX.test(row.transaction_hash))) ||
        !timestamp(row.created_at)) fail('M1_CAPTURE_PACKET_INVALID');
    eventIds.add(row.event_id); eventSequences.add(row.event_sequence);
  }
  const paymentIds = new Set<string>();
  const paymentOperationIds = new Set<string>();
  for (const value of census.payments as JsonRecord[]) {
    const row = record(value, ['payment_id','operation_id','env_id','generation_id','payer_address','network','asset_address','amount_units',
      'facilitator_address','transaction_hash','receipt_status','token_delta_units','observed_at','payer_balance_before','payer_balance_after',
      'facilitator_balance_before','facilitator_balance_after']);
    if (typeof row.payment_id !== 'string' || !UUID.test(row.payment_id) || paymentIds.has(row.payment_id) || typeof row.operation_id !== 'string' ||
        !operationIds.has(row.operation_id) || paymentOperationIds.has(row.operation_id) ||
        row.env_id !== generation.env_id || row.generation_id !== generation.generation_id || typeof row.network !== 'string' ||
        typeof row.asset_address !== 'string' || !ADDRESS.test(row.asset_address) ||
        typeof row.payer_address !== 'string' || !ADDRESS.test(row.payer_address) || typeof row.facilitator_address !== 'string' || !ADDRESS.test(row.facilitator_address) ||
        typeof row.transaction_hash !== 'string' || !TX.test(row.transaction_hash) || row.receipt_status !== 'success' ||
        ![row.amount_units,row.token_delta_units,row.payer_balance_before,row.payer_balance_after,row.facilitator_balance_before,row.facilitator_balance_after]
          .every((item) => typeof item === 'string' && UINT.test(item)) || !timestamp(row.observed_at)) fail('M1_CAPTURE_PACKET_INVALID');
    paymentIds.add(row.payment_id);
    paymentOperationIds.add(row.operation_id);
  }
  for (const value of census.deliveries as JsonRecord[]) {
    const row = record(value, ['delivery_id','operation_id','env_id','generation_id','resource_id','content_sha256','content_bytes','delivered_at']);
    if (typeof row.delivery_id !== 'string' || !UUID.test(row.delivery_id) || typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id) ||
        row.env_id !== generation.env_id || row.generation_id !== generation.generation_id || !boundedString(row.resource_id, 128) ||
        typeof row.content_sha256 !== 'string' || !HASH.test(row.content_sha256) || typeof row.content_bytes !== 'string' ||
        !DECIMAL.test(row.content_bytes) || BigInt(row.content_bytes) > 1024n * 1024n || !timestamp(row.delivered_at)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of census.costs as JsonRecord[]) {
    const row = record(value, ['operation_id','env_id','generation_id','transaction_hash','payer_address','payer_role','receipt_status','transaction_from','receipt_from',
      'receipt_block_number','receipt_block_hash','gas_used','effective_gas_price_wei','gas_cost_wei','modeled_gas_fee_usdc_units','manifest_sha256','created_at']);
    if (typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id) || row.env_id !== generation.env_id || row.generation_id !== generation.generation_id ||
        typeof row.transaction_hash !== 'string' || !TX.test(row.transaction_hash) || typeof row.payer_address !== 'string' || !ADDRESS.test(row.payer_address) ||
        !['participant','facilitator'].includes(String(row.payer_role)) ||
        !['success','reverted'].includes(String(row.receipt_status)) ||
        typeof row.transaction_from !== 'string' || !ADDRESS.test(row.transaction_from) || typeof row.receipt_from !== 'string' || !ADDRESS.test(row.receipt_from) ||
        typeof row.receipt_block_number !== 'string' || !DECIMAL.test(row.receipt_block_number) || typeof row.receipt_block_hash !== 'string' || !TX.test(row.receipt_block_hash) ||
        ![row.gas_used,row.effective_gas_price_wei,row.gas_cost_wei,row.modeled_gas_fee_usdc_units].every((item) => typeof item === 'string' && UINT.test(item)) ||
        BigInt(row.gas_used as string) * BigInt(row.effective_gas_price_wei as string) !== BigInt(row.gas_cost_wei as string) ||
        typeof row.manifest_sha256 !== 'string' || !HASH.test(row.manifest_sha256) || !timestamp(row.created_at)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of census.x402Observations as JsonRecord[]) {
    const row = record(value, ['observation_id','env_id','generation_id','operation_id','variant_id','phase','request_sha256','requirements','x402_version',
      'response_sha256','outcome','transaction_hash','observed_at']);
    const requirements = record(row.requirements, ['scheme','network','asset','amount','payTo','maxTimeoutSeconds','extra']);
    const extra = record(requirements.extra, ['assetTransferMethod','paymentFlow','name','version']);
    if (typeof row.observation_id !== 'string' || !UUID.test(row.observation_id) || typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id) ||
        row.env_id !== generation.env_id || row.generation_id !== generation.generation_id || !boundedString(row.variant_id, 128) ||
        !['supported','verify','settle'].includes(String(row.phase)) || typeof row.request_sha256 !== 'string' || !HASH.test(row.request_sha256) ||
        typeof row.x402_version !== 'string' || !/^[1-9][0-9]{0,3}$/.test(row.x402_version) ||
        typeof row.response_sha256 !== 'string' || !HASH.test(row.response_sha256) || typeof row.phase !== 'string' || typeof row.outcome !== 'string' ||
        (row.transaction_hash !== null && (typeof row.transaction_hash !== 'string' || !TX.test(row.transaction_hash))) || !timestamp(row.observed_at) ||
        !boundedString(requirements.scheme, 64) || !boundedString(requirements.network, 128) || typeof requirements.asset !== 'string' || !ADDRESS.test(requirements.asset) ||
        typeof requirements.amount !== 'string' || !/^[1-9][0-9]{0,77}$/.test(requirements.amount) || typeof requirements.payTo !== 'string' || !ADDRESS.test(requirements.payTo) ||
        typeof requirements.maxTimeoutSeconds !== 'string' || !DECIMAL.test(requirements.maxTimeoutSeconds) ||
        !boundedString(extra.assetTransferMethod, 80) || !boundedString(extra.paymentFlow, 80) || !boundedString(extra.name, 128) || !boundedString(extra.version, 128)) fail('M1_CAPTURE_PACKET_INVALID');
    // The collector allowlists only public payment requirements; reject signed/auth payload fields by key scan above.
    if (hasSecretKey(row.requirements)) fail('M1_CAPTURE_PACKET_SECRET_FIELD');
  }
  for (const value of census.denials as JsonRecord[]) {
    const row = record(value, ['denial_id','env_id','generation_id','operation_id','route','reason_code','request_sha256','protected_state_sha256','created_at']);
    if (typeof row.denial_id !== 'string' || !UUID.test(row.denial_id) || row.env_id !== generation.env_id || row.generation_id !== generation.generation_id ||
        (row.operation_id !== null && (typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id))) || !boundedString(row.route, 256) ||
        !boundedString(row.reason_code, 128) || typeof row.request_sha256 !== 'string' || !HASH.test(row.request_sha256) ||
        typeof row.protected_state_sha256 !== 'string' || !HASH.test(row.protected_state_sha256) || !timestamp(row.created_at)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of census.rpcObservations as JsonRecord[]) {
    const row = record(value, ['observation_id','operation_id','boundary','method','params_sha256','result_sha256','forwarded','response_status','source_block_hash','created_at']);
    if (typeof row.observation_id !== 'string' || !UUID.test(row.observation_id) || (row.operation_id !== null &&
        (typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id))) || !boundedString(row.boundary, 128) || !boundedString(row.method, 128) ||
        typeof row.params_sha256 !== 'string' || !HASH.test(row.params_sha256) || typeof row.result_sha256 !== 'string' || !HASH.test(row.result_sha256) ||
        typeof row.forwarded !== 'boolean' || typeof row.response_status !== 'string' || (row.source_block_hash !== null &&
        (typeof row.source_block_hash !== 'string' || !TX.test(row.source_block_hash))) || !timestamp(row.created_at)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of census.evidenceArtifacts as JsonRecord[]) {
    const row = record(value, ['artifact_id','operation_id','generation_id','relative_path','sha256','boundary','content_type','created_at']);
    if (typeof row.artifact_id !== 'string' || !UUID.test(row.artifact_id) || (row.operation_id !== null &&
        (typeof row.operation_id !== 'string' || !operationIds.has(row.operation_id))) || row.generation_id !== generation.generation_id ||
        !boundedString(row.relative_path, 512) || typeof row.sha256 !== 'string' || !HASH.test(row.sha256) || !boundedString(row.boundary, 128) ||
        !boundedString(row.content_type, 128) || !timestamp(row.created_at)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  return census as unknown as M1CaptureCensus;
}

function validateAction(value: unknown): M1CaptureAction {
  const action = record(value, ['actionId','actionSequence','ownerOperationId','actionKind','commandSha256','receiptStatus','actionEvidence',
    'befOperationId','transactionHash','rawResponseSha256','participantToolResponse','paymentProtocol']);
  const actionSequence = safeSequence(action.actionSequence);
  if (typeof action.actionId !== 'string' || !UUID.test(action.actionId) || actionSequence === null || actionSequence < 1 || actionSequence > MAX_ACTIONS ||
      typeof action.ownerOperationId !== 'string' || action.ownerOperationId.length < 12 || action.ownerOperationId.length > 128 ||
      !['inspect_catalog','inspect_offer','pay','retrieve'].includes(String(action.actionKind)) ||
      typeof action.commandSha256 !== 'string' || !HASH.test(action.commandSha256) ||
      !['observed','rejected_before_execution'].includes(String(action.receiptStatus)) || !validRef(action.actionEvidence, ACTION_PREFIX) ||
      (action.befOperationId !== null && (typeof action.befOperationId !== 'string' || !UUID.test(action.befOperationId))) ||
      (action.transactionHash !== null && (typeof action.transactionHash !== 'string' || !TX.test(action.transactionHash))) ||
      (action.rawResponseSha256 !== null && (typeof action.rawResponseSha256 !== 'string' || !HASH.test(action.rawResponseSha256))) ||
      (action.participantToolResponse !== null && !isRecord(action.participantToolResponse)) ||
      (action.paymentProtocol !== null && !isRecord(action.paymentProtocol))) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.receiptStatus === 'rejected_before_execution' && (action.transactionHash !== null || action.participantToolResponse !== null)) {
    fail('M1_CAPTURE_PACKET_INVALID');
  }
  if (action.receiptStatus === 'observed' && action.participantToolResponse === null) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.receiptStatus === 'observed' && (typeof action.rawResponseSha256 !== 'string' || !HASH.test(action.rawResponseSha256))) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.receiptStatus === 'observed' && action.actionKind !== 'inspect_catalog' && action.befOperationId === null) fail('M1_CAPTURE_PACKET_INVALID');
  if ((action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer' || action.actionKind === 'retrieve') && action.transactionHash !== null) {
    fail('M1_CAPTURE_PACKET_INVALID');
  }
  if (action.actionKind === 'inspect_catalog' && action.paymentProtocol !== null ||
      action.actionKind === 'inspect_offer' && action.paymentProtocol !== null ||
      action.receiptStatus === 'observed' && (action.actionKind === 'pay' || action.actionKind === 'retrieve') && action.paymentProtocol === null) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.receiptStatus === 'observed') {
    const response = action.participantToolResponse!;
    const operationId = response.operationId;
    if (operationId !== undefined && (typeof operationId !== 'string' || !UUID.test(operationId))) fail('M1_CAPTURE_PACKET_INVALID');
    if (action.actionKind === 'inspect_catalog') {
      if (Object.keys(response).some((key) => !['operationId','readHandle','catalog','freeInspection','deliveryState'].includes(key)) ||
          !('catalog' in response) || !('freeInspection' in response) || !('deliveryState' in response) || !Array.isArray(response.catalog) ||
          response.catalog.length < 1 || response.catalog.length > 128 || response.catalog.some((item) => !isRecord(item)) ||
          response.freeInspection !== true || response.deliveryState !== 'not_delivered') fail('M1_CAPTURE_PACKET_INVALID');
      const resourceIds = new Set<string>();
      for (const resourceValue of response.catalog as JsonRecord[]) {
        const optional = ['dataType', 'schema', 'provenance'].filter((key) => resourceValue[key] !== undefined);
        const resource = record(resourceValue, ['resourceId','resourceSha256','contentType','offers', ...optional]);
        if (!boundedString(resource.resourceId,128) || resourceIds.has(resource.resourceId) || typeof resource.resourceSha256 !== 'string' ||
            !HASH.test(resource.resourceSha256) || !boundedString(resource.contentType,128) || (resource.dataType !== undefined && !boundedString(resource.dataType,128)) ||
            (resource.schema !== undefined && !boundedString(resource.schema,256)) ||
            (resource.provenance !== undefined && !validPublicProvenance(resource.provenance)) ||
            !Array.isArray(resource.offers) || resource.offers.length < 1 || resource.offers.length > 256) fail('M1_CAPTURE_PACKET_INVALID');
        resourceIds.add(resource.resourceId);
        validateOfferList(resource.offers);
      }
      if (response.readHandle !== undefined) {
        const handle = record(response.readHandle, ['kind','operationId']);
        if (handle.kind !== 'catalog' || typeof handle.operationId !== 'string' || !UUID.test(handle.operationId) ||
            (typeof response.operationId === 'string' && response.operationId !== handle.operationId)) fail('M1_CAPTURE_PACKET_INVALID');
      }
    } else if (action.actionKind === 'inspect_offer') {
      if (!['operationId','readHandle','resourceId','resourceSha256','contentType','payment','offers','freeInspection','deliveryState'].every((key) => key in response) ||
          Object.keys(response).some((key) => !['operationId','readHandle','resourceId','resourceSha256','contentType','dataType','schema','provenance','payment','offers','freeInspection','deliveryState'].includes(key)) ||
          typeof response.operationId !== 'string' || !UUID.test(response.operationId) || !boundedString(response.resourceId,128) ||
          typeof response.resourceSha256 !== 'string' || !HASH.test(response.resourceSha256) || response.contentType !== 'application/json' ||
          !isRecord(response.payment) || !Array.isArray(response.offers) || typeof response.freeInspection !== 'boolean' || response.freeInspection !== true ||
          response.deliveryState !== 'not_delivered' || (response.dataType !== undefined && !boundedString(response.dataType,128)) ||
          (response.schema !== undefined && !boundedString(response.schema,256)) ||
          (response.provenance !== undefined && !validPublicProvenance(response.provenance))) fail('M1_CAPTURE_PACKET_INVALID');
      const handle = record(response.readHandle, ['kind','operationId']);
      if (handle.kind !== 'offer' || handle.operationId !== response.operationId) fail('M1_CAPTURE_PACKET_INVALID');
      validatePublicPaymentQuote(response.payment);
      validateOfferList(response.offers);
    } else if (action.actionKind === 'pay') {
      if (!exactKeys(response, ['operationId','status','payment','deliveryHandle']) || typeof response.operationId !== 'string' || !UUID.test(response.operationId) ||
          response.status !== 'payment_confirmed' || response.deliveryHandle !== response.operationId || !isRecord(response.payment)) fail('M1_CAPTURE_PACKET_INVALID');
      const payment = record(response.payment, ['transactionHash','receiptStatus','amount','asset','network','payTo']);
      if (!boundedString(payment.transactionHash,66) || !TX.test(payment.transactionHash) || payment.receiptStatus !== 'success' ||
          typeof payment.amount !== 'string' || !UINT.test(payment.amount) || typeof payment.asset !== 'string' || !ADDRESS.test(payment.asset) ||
          !boundedString(payment.network,128) || typeof payment.payTo !== 'string' || !ADDRESS.test(payment.payTo)) fail('M1_CAPTURE_PACKET_INVALID');
      if (action.transactionHash === null || action.transactionHash.toLowerCase() !== payment.transactionHash.toLowerCase()) fail('M1_CAPTURE_PACKET_INVALID');
    } else {
      if (!exactKeys(response, ['operationId','resourceId','contentType','contentHash','contentBytes','content']) || typeof response.operationId !== 'string' ||
          !UUID.test(response.operationId) || !boundedString(response.resourceId,128) || response.contentType !== 'application/json' ||
          typeof response.contentHash !== 'string' || !HASH.test(response.contentHash) || typeof response.contentBytes !== 'string' ||
          response.contentBytes.length > 2 * 1024 * 1024 || !isRecord(response.content) || Buffer.byteLength(canonicalTaskJson(response.content)) > 2 * 1024 * 1024) fail('M1_CAPTURE_PACKET_INVALID');
    }
    validatePaymentProtocol(action);
    if (typeof response.operationId === 'string' && response.operationId !== action.befOperationId) fail('M1_CAPTURE_PACKET_INVALID');
    if (action.actionKind !== 'inspect_catalog' && response.operationId !== action.befOperationId) fail('M1_CAPTURE_PACKET_INVALID');
  } else {
    if (action.paymentProtocol !== null) {
      validateRejectedPaymentProtocol(action);
      if (action.actionKind === 'pay') {
        const protocol = action.paymentProtocol as JsonRecord;
        const protocolOperationId = protocol.befOperationId ?? null;
        if (protocolOperationId !== action.befOperationId ||
            protocol.challengeResponseSha256 !== undefined &&
              (typeof action.rawResponseSha256 !== 'string' ||
                String(protocol.challengeResponseSha256).toLowerCase() !== action.rawResponseSha256.toLowerCase())) {
          fail('M1_CAPTURE_PACKET_INVALID');
        }
      }
    } else if (action.befOperationId !== null) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
  }
  return action as unknown as M1CaptureAction;
}

function validateRejectedPaymentProtocol(action: JsonRecord): void {
  const protocol = action.paymentProtocol;
  if (!isRecord(protocol)) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer') fail('M1_CAPTURE_PACKET_INVALID');
  if (action.actionKind === 'pay') {
    const allowed = ['schema','resourceId','offerId','resourceSha256','amountUnits','network','asset','readHandle','acceptedTerms','befServerSdkVersions',
      'ownerSignerSdkVersions','facilitatorAddress','payerAddress','challengeResponseSha256','challengeHeaderSha256','befOperationId','settlementObserved',
      'settlementMatchesPins','transactionHash','settlementHeaderSha256'];
    if (Object.keys(protocol).some((key) => !allowed.includes(key)) || protocol.schema !== 'bef-x402-split-payment-observation-v1' ||
        !boundedString(protocol.resourceId,128) || !boundedString(protocol.offerId,128) || typeof protocol.resourceSha256 !== 'string' || !HASH.test(protocol.resourceSha256) ||
        typeof protocol.amountUnits !== 'string' || !UINT.test(protocol.amountUnits) || !boundedString(protocol.network,128) || typeof protocol.asset !== 'string' ||
        !ADDRESS.test(protocol.asset) || protocol.settlementObserved === true || protocol.settlementMatchesPins === true || protocol.transactionHash !== undefined) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
    const handle = record(protocol.readHandle, ['kind','operationId']);
    const terms = record(protocol.acceptedTerms, ['scheme','network','asset','amount','payTo','transferMethod']);
    if ((handle.kind !== 'offer' && handle.kind !== 'catalog') || typeof handle.operationId !== 'string' || !UUID.test(handle.operationId) ||
        !boundedString(terms.scheme,80) || !boundedString(terms.network,128) || typeof terms.asset !== 'string' || !ADDRESS.test(terms.asset) ||
        typeof terms.amount !== 'string' || !UINT.test(terms.amount) || typeof terms.payTo !== 'string' || !ADDRESS.test(terms.payTo) ||
        !boundedString(terms.transferMethod,80)) fail('M1_CAPTURE_PACKET_INVALID');
    if (protocol.befOperationId !== undefined && (typeof protocol.befOperationId !== 'string' || !UUID.test(protocol.befOperationId))) fail('M1_CAPTURE_PACKET_INVALID');
    for (const key of ['challengeResponseSha256','challengeHeaderSha256','settlementHeaderSha256']) {
      if (protocol[key] !== undefined && (typeof protocol[key] !== 'string' || !HASH.test(protocol[key]))) fail('M1_CAPTURE_PACKET_INVALID');
    }
  } else if (action.actionKind === 'retrieve') {
    const allowed = ['schema','payOperationId','resourceId','resourceSha256','contentSha256','deliveryMatchesPinnedResource'];
    if (Object.keys(protocol).some((key) => !allowed.includes(key)) || !boundedString(protocol.resourceId,128) ||
        typeof protocol.resourceSha256 !== 'string' || !HASH.test(protocol.resourceSha256) || protocol.deliveryMatchesPinnedResource === true) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
    if (protocol.schema !== undefined && protocol.schema !== 'bef-x402-retrieve-observation-v1') fail('M1_CAPTURE_PACKET_INVALID');
    if (protocol.payOperationId !== undefined && (typeof protocol.payOperationId !== 'string' || !UUID.test(protocol.payOperationId))) fail('M1_CAPTURE_PACKET_INVALID');
    if (protocol.contentSha256 !== undefined && (typeof protocol.contentSha256 !== 'string' || !HASH.test(protocol.contentSha256))) fail('M1_CAPTURE_PACKET_INVALID');
  }
}

function validatePublicPaymentQuote(value: unknown): void {
  const payment = record(value, ['scheme','network','asset','amount','payTo','transferMethod']);
  if (!boundedString(payment.scheme,80) || !boundedString(payment.network,80) || typeof payment.asset !== 'string' || !ADDRESS.test(payment.asset) ||
      typeof payment.amount !== 'string' || !UINT.test(payment.amount) || typeof payment.payTo !== 'string' || !ADDRESS.test(payment.payTo) ||
      !boundedString(payment.transferMethod,80)) fail('M1_CAPTURE_PACKET_INVALID');
}

function validPublicProvenance(value: unknown): boolean {
  if (!isRecord(value) || !Object.keys(value).length || Object.keys(value).some((key) => !['classification','boundary','source'].includes(key))) return false;
  return Object.values(value).every((item) => boundedString(item, 256));
}

function validateOfferList(value: unknown): void {
  if (!Array.isArray(value) || value.length < 1 || value.length > 256) fail('M1_CAPTURE_PACKET_INVALID');
  const ids = new Set<string>();
  for (const offerValue of value) {
    const offer = record(offerValue, ['id','payment']);
    if (!boundedString(offer.id,128) || ids.has(offer.id)) fail('M1_CAPTURE_PACKET_INVALID');
    validatePublicPaymentQuote(offer.payment);
    ids.add(offer.id);
  }
}

function validatePaymentProtocol(action: JsonRecord): void {
  const protocol = action.paymentProtocol;
  if (action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer') return;
  if (!isRecord(protocol)) fail('M1_CAPTURE_PACKET_INVALID');
  if (action.actionKind === 'pay') {
    const allowed = ['schema','resourceId','offerId','resourceSha256','amountUnits','network','asset','readHandle','acceptedTerms','befServerSdkVersions',
      'ownerSignerSdkVersions','facilitatorAddress','payerAddress','challengeResponseSha256','challengeHeaderSha256','befOperationId','settlementObserved',
      'settlementMatchesPins','transactionHash','settlementHeaderSha256'];
    if (Object.keys(protocol).some((key) => !allowed.includes(key)) ||
        !['schema','resourceId','offerId','resourceSha256','amountUnits','network','asset','readHandle','acceptedTerms','befServerSdkVersions',
          'ownerSignerSdkVersions','facilitatorAddress','payerAddress','challengeResponseSha256','challengeHeaderSha256','befOperationId',
          'settlementObserved','settlementMatchesPins','transactionHash','settlementHeaderSha256'].every((key) => key in protocol)) fail('M1_CAPTURE_PACKET_INVALID');
    const handle = record(protocol.readHandle, ['kind','operationId']);
    const acceptedTerms = record(protocol.acceptedTerms, ['scheme','network','asset','amount','payTo','transferMethod']);
    const serverVersions = record(protocol.befServerSdkVersions, ['core','evm','viem']);
    const signerVersions = record(protocol.ownerSignerSdkVersions, ['core','evm','viem']);
    if (protocol.schema !== 'bef-x402-split-payment-observation-v1' || !boundedString(protocol.resourceId,128) || !boundedString(protocol.offerId,128) ||
        typeof protocol.resourceSha256 !== 'string' || !HASH.test(protocol.resourceSha256) || typeof protocol.amountUnits !== 'string' || !UINT.test(protocol.amountUnits) ||
        !boundedString(protocol.network,128) || typeof protocol.asset !== 'string' || !ADDRESS.test(protocol.asset) ||
        (handle.kind !== 'offer' && handle.kind !== 'catalog') ||
        typeof handle.operationId !== 'string' || !UUID.test(handle.operationId) || typeof acceptedTerms.scheme !== 'string' ||
        typeof acceptedTerms.network !== 'string' || typeof acceptedTerms.asset !== 'string' || typeof acceptedTerms.amount !== 'string' ||
        typeof acceptedTerms.payTo !== 'string' || typeof acceptedTerms.transferMethod !== 'string' ||
        !['core','evm','viem'].every((key) => boundedString(serverVersions[key],80) && boundedString(signerVersions[key],80)) ||
        typeof protocol.facilitatorAddress !== 'string' || !ADDRESS.test(protocol.facilitatorAddress) ||
        typeof protocol.payerAddress !== 'string' || !ADDRESS.test(protocol.payerAddress) || typeof protocol.befOperationId !== 'string' ||
        !UUID.test(protocol.befOperationId) || protocol.settlementObserved !== true || protocol.settlementMatchesPins !== true ||
        typeof protocol.transactionHash !== 'string' || !TX.test(protocol.transactionHash) || protocol.transactionHash.toLowerCase() !== String(action.transactionHash).toLowerCase()) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
    for (const key of ['challengeResponseSha256','challengeHeaderSha256','settlementHeaderSha256']) {
      if (typeof protocol[key] !== 'string' || !HASH.test(protocol[key])) fail('M1_CAPTURE_PACKET_INVALID');
    }
  } else {
    if (Object.keys(protocol).some((key) => !['schema','payOperationId','resourceId','resourceSha256','contentSha256','deliveryMatchesPinnedResource'].includes(key)) ||
        !['schema','payOperationId','resourceId','resourceSha256','deliveryMatchesPinnedResource'].every((key) => key in protocol) ||
        protocol.schema !== 'bef-x402-retrieve-observation-v1' || typeof protocol.payOperationId !== 'string' || !UUID.test(protocol.payOperationId) ||
        !boundedString(protocol.resourceId,128) || typeof protocol.resourceSha256 !== 'string' || !HASH.test(protocol.resourceSha256) ||
        (protocol.contentSha256 !== undefined && (typeof protocol.contentSha256 !== 'string' || !HASH.test(protocol.contentSha256))) ||
        protocol.deliveryMatchesPinnedResource !== true) fail('M1_CAPTURE_PACKET_INVALID');
  }
}

function validateRpcCheckpoint(value: unknown): JsonRecord {
  const checkpoint = record(value, ['blockNumber','blockHash','parentHash','balances','allowances','participantTransactionCount']);
  if (typeof checkpoint.blockNumber !== 'string' || !DECIMAL.test(checkpoint.blockNumber) || typeof checkpoint.blockHash !== 'string' ||
      !TX.test(checkpoint.blockHash) || typeof checkpoint.parentHash !== 'string' || !TX.test(checkpoint.parentHash) ||
      typeof checkpoint.participantTransactionCount !== 'string' || !DECIMAL.test(checkpoint.participantTransactionCount) ||
      !Array.isArray(checkpoint.balances) || checkpoint.balances.length > 256 || !Array.isArray(checkpoint.allowances) || checkpoint.allowances.length > 256) {
    fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of checkpoint.balances) {
    const row = record(value, ['account','assetId','amountUnits']);
    if (!boundedString(row.account,128) || !boundedString(row.assetId,128) || typeof row.amountUnits !== 'string' || !UINT.test(row.amountUnits)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of checkpoint.allowances) {
    const row = record(value, ['owner','tokenAssetId','spender','amountUnits']);
    if (!boundedString(row.owner,128) || !boundedString(row.tokenAssetId,128) || typeof row.spender !== 'string' || !ADDRESS.test(row.spender) ||
        typeof row.amountUnits !== 'string' || !UINT.test(row.amountUnits)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  return checkpoint;
}

function validateM1Rpc(value: unknown): JsonRecord {
  const rpc = record(value, ['localChainId','baseline','final','intervalBlocks','participantLogQueryCount','responseHashes','paymentProofs','participantTransferLogs']);
  if (typeof rpc.localChainId !== 'string' || !DECIMAL.test(rpc.localChainId) || !Number.isSafeInteger(rpc.participantLogQueryCount) ||
      (rpc.participantLogQueryCount as number) < 0 || !Array.isArray(rpc.intervalBlocks) || rpc.intervalBlocks.length > 20_000 ||
      !Array.isArray(rpc.responseHashes) || rpc.responseHashes.length > 4096 || !Array.isArray(rpc.paymentProofs) || rpc.paymentProofs.length > 128 ||
      !Array.isArray(rpc.participantTransferLogs) || rpc.participantTransferLogs.length > MAX_ROWS) fail('M1_CAPTURE_PACKET_INVALID');
  validateRpcCheckpoint(rpc.baseline); validateRpcCheckpoint(rpc.final);
  for (const value of rpc.intervalBlocks) {
    const block = record(value, ['number','hash','parentHash','transactionCount']);
    if (typeof block.number !== 'string' || !DECIMAL.test(block.number) || typeof block.hash !== 'string' || !TX.test(block.hash) ||
        typeof block.parentHash !== 'string' || !TX.test(block.parentHash) || !Number.isSafeInteger(block.transactionCount) ||
        (block.transactionCount as number) < 0) fail('M1_CAPTURE_PACKET_INVALID');
  }
  for (const value of rpc.responseHashes) {
    const row = record(value, ['method','paramsSha256','resultSha256']);
    if (!boundedString(row.method,128) || typeof row.paramsSha256 !== 'string' || !HASH.test(row.paramsSha256) ||
        typeof row.resultSha256 !== 'string' || !HASH.test(row.resultSha256)) fail('M1_CAPTURE_PACKET_INVALID');
  }
  const paymentIds = new Set<string>();
  const paymentOperationIds = new Set<string>();
  const paymentTransactionHashes = new Set<string>();
  for (const value of rpc.paymentProofs) {
    const proof = record(value, ['operationId','paymentId','transactionHash','transaction','receipt']);
    const transaction = record(proof.transaction, ['hash','from','to','value','nonce','blockNumber','blockHash','inputSha256']);
    const receipt = record(proof.receipt, ['transactionHash','transactionIndex','blockNumber','blockHash','from','to','status','gasUsed','effectiveGasPrice','logsSha256']);
    if (typeof proof.operationId !== 'string' || !UUID.test(proof.operationId) || typeof proof.paymentId !== 'string' || !UUID.test(proof.paymentId) ||
        paymentIds.has(proof.paymentId) || paymentOperationIds.has(proof.operationId) || typeof proof.transactionHash !== 'string' || !TX.test(proof.transactionHash) ||
        paymentTransactionHashes.has(proof.transactionHash.toLowerCase()) ||
        typeof transaction.hash !== 'string' || !TX.test(transaction.hash) || transaction.hash.toLowerCase() !== proof.transactionHash.toLowerCase() ||
        typeof transaction.from !== 'string' || !ADDRESS.test(transaction.from) || (transaction.to !== null && (typeof transaction.to !== 'string' || !ADDRESS.test(transaction.to))) ||
        typeof transaction.value !== 'string' || !UINT.test(transaction.value) || typeof transaction.nonce !== 'string' || !UINT.test(transaction.nonce) ||
        typeof transaction.blockNumber !== 'string' || !DECIMAL.test(transaction.blockNumber) || typeof transaction.blockHash !== 'string' || !TX.test(transaction.blockHash) ||
        typeof transaction.inputSha256 !== 'string' || !HASH.test(transaction.inputSha256) ||
        typeof receipt.transactionHash !== 'string' || !TX.test(receipt.transactionHash) || receipt.transactionHash.toLowerCase() !== proof.transactionHash.toLowerCase() ||
        typeof receipt.transactionIndex !== 'string' || !DECIMAL.test(receipt.transactionIndex) || typeof receipt.blockNumber !== 'string' ||
        !DECIMAL.test(receipt.blockNumber) || receipt.blockNumber !== transaction.blockNumber || typeof receipt.blockHash !== 'string' ||
        !TX.test(receipt.blockHash) || receipt.blockHash.toLowerCase() !== transaction.blockHash.toLowerCase() || typeof receipt.from !== 'string' ||
        !ADDRESS.test(receipt.from) || (receipt.to !== null && (typeof receipt.to !== 'string' || !ADDRESS.test(receipt.to))) ||
        !['success','reverted'].includes(String(receipt.status)) || typeof receipt.gasUsed !== 'string' || !UINT.test(receipt.gasUsed) ||
        typeof receipt.effectiveGasPrice !== 'string' || !UINT.test(receipt.effectiveGasPrice) || typeof receipt.logsSha256 !== 'string' || !HASH.test(receipt.logsSha256)) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
    paymentIds.add(proof.paymentId);
    paymentOperationIds.add(proof.operationId);
    paymentTransactionHashes.add(proof.transactionHash.toLowerCase());
  }
  const transferLogIds = new Set<string>();
  for (const value of rpc.participantTransferLogs) {
    const row = validateM1TransferLog(value);
    const identity = `${String(row.transactionHash).toLowerCase()}:${row.logIndex}`;
    if (transferLogIds.has(identity)) fail('M1_CAPTURE_PACKET_INVALID');
    transferLogIds.add(identity);
  }
  return rpc;
}

function validateM1TransferLog(value: unknown): JsonRecord {
  const row = record(value, ['assetId','tokenAddress','transactionHash','blockNumber','blockHash','logIndex','from','to','amountUnits']);
  if (!boundedString(row.assetId,128) || typeof row.tokenAddress !== 'string' || !ADDRESS.test(row.tokenAddress) ||
      typeof row.transactionHash !== 'string' || !TX.test(row.transactionHash) || typeof row.blockNumber !== 'string' || !DECIMAL.test(row.blockNumber) ||
      typeof row.blockHash !== 'string' || !TX.test(row.blockHash) || typeof row.logIndex !== 'string' || !DECIMAL.test(row.logIndex) ||
      typeof row.from !== 'string' || !ADDRESS.test(row.from) || typeof row.to !== 'string' || !ADDRESS.test(row.to) ||
      typeof row.amountUnits !== 'string' || !UINT.test(row.amountUnits)) fail('M1_CAPTURE_PACKET_INVALID');
  return row;
}

/**
 * Checks the shared, bounded M1 capture packet envelope. Database bindings and semantic joins
 * are checked by TaskSealedEvidenceSource inside its caller transaction.
 */
export function validateM1CapturePacket(value: unknown): M1CapturePacket {
  if (!isRecord(value) || hasSecretKey(value)) fail(isRecord(value) ? 'M1_CAPTURE_PACKET_SECRET_FIELD' : 'M1_CAPTURE_PACKET_INVALID');
  if (!exactKeys(value, ['schemaVersion','classification','binding','closure','execution','preparation','ownerActions','bef','rpc']) ||
      value.schemaVersion !== 'bts-m1-run-observation-capture/v1' || value.classification !== 'run_bound_observations_candidate_not_grade') {
    fail('M1_CAPTURE_PACKET_INVALID');
  }
  const binding = record(value.binding, ['ownerId','agentId','runId','environmentId','releaseIdentity','manifestHash','caseId','caseHash','rubricHash','taskId']);
  if (typeof binding.ownerId !== 'string' || !UUID.test(binding.ownerId) || typeof binding.agentId !== 'string' || !UUID.test(binding.agentId) ||
      typeof binding.runId !== 'string' || !UUID.test(binding.runId) || typeof binding.environmentId !== 'string' || binding.environmentId.length < 1 ||
      binding.environmentId.length > 128 || typeof binding.releaseIdentity !== 'string' || binding.releaseIdentity.length < 1 || binding.releaseIdentity.length > 128 ||
      typeof binding.manifestHash !== 'string' || !HASH.test(binding.manifestHash) || typeof binding.caseId !== 'string' || binding.caseId.length < 1 ||
      binding.caseId.length > 128 || typeof binding.caseHash !== 'string' || !HASH.test(binding.caseHash) || typeof binding.rubricHash !== 'string' ||
      !HASH.test(binding.rubricHash) || binding.taskId !== 'M1') fail('M1_CAPTURE_PACKET_INVALID');
  const closure = record(value.closure, ['closureId','actionCutoffSequence','reconciledActionSequence','reason','operationId','payloadHash','answer']);
  const cutoff = safeSequence(closure.actionCutoffSequence); const reconciled = safeSequence(closure.reconciledActionSequence);
  if (typeof closure.closureId !== 'string' || !UUID.test(closure.closureId) || cutoff === null || cutoff > MAX_ACTIONS || reconciled === null ||
      reconciled < cutoff || !['agent_finish','task_deadline','run_deadline'].includes(String(closure.reason)) ||
      (closure.operationId !== null && (typeof closure.operationId !== 'string' || closure.operationId.length < 12 || closure.operationId.length > 128)) ||
      typeof closure.payloadHash !== 'string' || !HASH.test(closure.payloadHash) || closure.answer !== null) fail('M1_CAPTURE_PACKET_INVALID');
  const execution = record(value.execution, ['preparationId','leaseId','generationId','environmentId','environmentManifestHash','applicationSourceHash',
    'executionIdentityHash','initialStateSha256']);
  if (typeof execution.preparationId !== 'string' || !UUID.test(execution.preparationId) || typeof execution.leaseId !== 'string' || !UUID.test(execution.leaseId) ||
      typeof execution.generationId !== 'string' || !UUID.test(execution.generationId) || execution.environmentId !== binding.environmentId ||
      typeof execution.environmentManifestHash !== 'string' || !HASH.test(execution.environmentManifestHash) ||
      typeof execution.applicationSourceHash !== 'string' || !HASH.test(execution.applicationSourceHash) ||
      typeof execution.executionIdentityHash !== 'string' || !HASH.test(execution.executionIdentityHash) ||
      typeof execution.initialStateSha256 !== 'string' || !HASH.test(execution.initialStateSha256)) fail('M1_CAPTURE_PACKET_INVALID');
  const preparation = record(value.preparation, ['fixtureEvidence','baselineEvidence','baselineBlockNumber','baselineBlockHash']);
  if (!validRef(preparation.fixtureEvidence, PREPARATION_PREFIX) || !validRef(preparation.baselineEvidence, PREPARATION_PREFIX) ||
      preparation.fixtureEvidence.path === preparation.baselineEvidence.path || typeof preparation.baselineBlockNumber !== 'string' ||
      !DECIMAL.test(preparation.baselineBlockNumber) || typeof preparation.baselineBlockHash !== 'string' || !TX.test(preparation.baselineBlockHash)) {
    fail('M1_CAPTURE_PACKET_INVALID');
  }
  if (!Array.isArray(value.ownerActions) || value.ownerActions.length > MAX_ACTIONS || value.ownerActions.length !== cutoff) fail('M1_CAPTURE_PACKET_LIMIT_EXCEEDED');
  const actions = value.ownerActions.map(validateAction);
  const actionIds = new Set<string>(); const ownerOperationIds = new Set<string>(); const sequences = new Set<number>();
  const byOperation = new Map<string, M1CaptureAction[]>();
  for (const action of actions) {
    if (actionIds.has(action.actionId) || ownerOperationIds.has(action.ownerOperationId) || sequences.has(action.actionSequence)) fail('M1_CAPTURE_PACKET_INVALID');
    actionIds.add(action.actionId); ownerOperationIds.add(action.ownerOperationId); sequences.add(action.actionSequence);
    if (action.befOperationId) {
      const rows = byOperation.get(action.befOperationId) ?? []; rows.push(action); byOperation.set(action.befOperationId, rows);
    }
  }
  if ([...sequences].some((sequence, index) => sequence !== index + 1)) fail('M1_CAPTURE_PACKET_INVALID');
  for (const rows of byOperation.values()) {
    const kinds = rows.map((action) => action.actionKind);
    if (kinds.filter((kind) => kind === 'pay').length > 1 || kinds.some((kind) => kind === 'retrieve') && kinds.filter((kind) => kind === 'pay').length !== 1) {
      fail('M1_CAPTURE_PACKET_INVALID');
    }
  }
  const bef = record(value.bef, ['session','before','after','censusSha256','resourcePin','environmentManifest']);
  if (!isRecord(bef.session) || !isRecord(bef.resourcePin) || !isRecord(bef.environmentManifest) ||
      typeof bef.censusSha256 !== 'string' || !HASH.test(bef.censusSha256)) fail('M1_CAPTURE_PACKET_INVALID');
  const session = record(bef.session, ['currentUser','sessionUser','databaseName','transactionReadOnly','superuser','bypassRls']);
  if (session.currentUser !== 'bef_observer' || session.sessionUser !== 'bef_observer' || !boundedString(session.databaseName,128) ||
      session.transactionReadOnly !== 'on' || session.superuser !== false || session.bypassRls !== false) fail('M1_CAPTURE_PACKET_INVALID');
  const manifestRef = record(bef.environmentManifest, ['encoding','bytes','sha256']);
  if (manifestRef.encoding !== 'base64' || typeof manifestRef.bytes !== 'string' || manifestRef.bytes.length > Math.ceil(MAX_MANIFEST_BYTES * 4 / 3) + 4 ||
      typeof manifestRef.sha256 !== 'string' || !HASH.test(manifestRef.sha256) ||
      manifestRef.sha256.toLowerCase() !== String(execution.environmentManifestHash).toLowerCase()) fail('M1_CAPTURE_PACKET_INVALID');
  validateManifest(manifestRef.bytes, manifestRef.sha256);
  const pin = record(bef.resourcePin, ['resourceId','resourceSha256','contentType','offers','paymentPolicy']);
  const policy = record(pin.paymentPolicy, ['scheme','network','asset','assetTransferMethod','eip712Domain']);
  const domain = record(policy.eip712Domain, ['name','version']);
  if (typeof pin.resourceId !== 'string' || pin.resourceId.length < 1 || pin.resourceId.length > 128 || typeof pin.resourceSha256 !== 'string' ||
      !HASH.test(pin.resourceSha256) || pin.contentType !== 'application/json' || !Array.isArray(pin.offers) || pin.offers.length < 1 ||
      pin.offers.length > 8 || typeof policy.scheme !== 'string' || typeof policy.network !== 'string' || !/^eip155:[1-9][0-9]*$/.test(policy.network) ||
      typeof policy.asset !== 'string' || !ADDRESS.test(policy.asset) || typeof policy.assetTransferMethod !== 'string' ||
      typeof domain.name !== 'string' || typeof domain.version !== 'string') fail('M1_CAPTURE_PACKET_INVALID');
  const offers = pin.offers.map((value) => {
    const offer = record(value, ['id','amount']);
    if (typeof offer.id !== 'string' || typeof offer.amount !== 'string' || !/^[1-9][0-9]{0,77}$/.test(offer.amount)) fail('M1_CAPTURE_PACKET_INVALID');
    return offer;
  });
  if (new Set(offers.map((offer) => offer.id)).size !== offers.length) fail('M1_CAPTURE_PACKET_INVALID');
  const environmentManifest = validateManifest(manifestRef.bytes, manifestRef.sha256);
  const x402 = environmentManifest.x402 as JsonRecord;
  const resources = (x402.catalog as JsonRecord[]).filter((candidate) => candidate.resourceId === pin.resourceId);
  if (resources.length !== 1 || resources[0]!.resourceSha256 !== pin.resourceSha256 || resources[0]!.contentType !== pin.contentType ||
      canonicalTaskJson(resources[0]!.offers) !== canonicalTaskJson(offers) || policy.scheme !== x402.scheme || policy.network !== x402.network ||
      String(policy.asset).toLowerCase() !== String(x402.asset).toLowerCase() || policy.assetTransferMethod !== x402.assetTransferMethod ||
      canonicalTaskJson(domain) !== canonicalTaskJson(x402.eip712Domain)) fail('M1_CAPTURE_PACKET_INVALID');
  const before = validateCensus(bef.before); const after = validateCensus(bef.after);
  if (canonicalTaskJson(before) !== canonicalTaskJson(after) ||
      createHash('sha256').update(canonicalTaskJson(before)).digest('hex').toLowerCase() !== bef.censusSha256.toLowerCase()) fail('M1_CAPTURE_PACKET_INVALID');
  for (const action of actions) {
    if (!action.befOperationId) continue;
    const op = before.operations.find((item) => item.operation_id === action.befOperationId);
    if (action.receiptStatus === 'observed' && !op && action.actionKind !== 'inspect_catalog') fail('M1_CAPTURE_PACKET_INVALID');
    if (op && action.actionKind === 'inspect_catalog' && op.operation_kind !== 'catalog' ||
        op && action.actionKind === 'inspect_offer' && op.operation_kind !== 'offer' ||
        op && (action.actionKind === 'pay' || action.actionKind === 'retrieve') && op.operation_kind !== 'purchase') fail('M1_CAPTURE_PACKET_INVALID');
  }
  const rpc = validateM1Rpc(value.rpc);
  if (String(rpc.localChainId) !== String(before.generation.chain_id)) fail('M1_CAPTURE_PACKET_INVALID');
  return value as unknown as M1CapturePacket;
}

export function parseM1CapturePacket(bytes: Uint8Array): M1CapturePacket {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) fail('M1_CAPTURE_PACKET_INVALID');
  if (bytes.byteLength > MAX_PACKET_BYTES) fail('M1_CAPTURE_PACKET_LIMIT_EXCEEDED');
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
  catch { fail('M1_CAPTURE_PACKET_INVALID'); }
  return validateM1CapturePacket(value);
}

export type M1PacketProjectionContext = {
  taskCase: Extract<TaskCase, { taskId: 'M1' }>;
  binding: TaskEvidenceBinding;
  taskIndex: number;
  closureId: string;
  captureEvidence: EvidenceReference;
  /** Only immutable pre-extension sealed bundles may suppress the new optional fact. */
  preserveLegacyDeliveryObservations?: boolean;
  assets: readonly { assetId: string; address: string | null; kind: 'native' | 'erc20'; chainId: number }[];
};

export type M1PacketObservationProjection = Pick<PersistedTaskObservations,
  'coverage' | 'transfers' | 'payments' | 'stateMutations' | 'deliveries' | 'expenses'>;

function demand(value: unknown): asserts value {
  if (!value) fail('M1_CAPTURE_PACKET_INVALID');
}

function addressEqual(left: unknown, right: unknown): boolean {
  return typeof left === 'string' && typeof right === 'string' && left.toLowerCase() === right.toLowerCase();
}

function parseBase64(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('M1_CAPTURE_PACKET_INVALID');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maxBytes || bytes.toString('base64') !== value) fail('M1_CAPTURE_PACKET_INVALID');
  return bytes;
}

function validateRejectedPurchaseOperation(
  packet: M1CapturePacket,
  action: M1CaptureAction,
  operationsById: ReadonlyMap<string, JsonRecord>,
): JsonRecord | null {
  const expectedIdempotencyHash = createHash('sha256').update(`task-action-${action.actionId}`).digest('hex');
  const matchingByKey = packet.bef.after.operations.filter((operation) =>
    String(operation.idempotency_key_sha256).toLowerCase() === expectedIdempotencyHash);
  demand(matchingByKey.length <= 1);

  if (action.actionKind !== 'pay' || action.paymentProtocol === null) {
    demand(matchingByKey.length === 0 && action.befOperationId === null);
    return null;
  }

  const protocol = action.paymentProtocol;
  const recordedId = action.befOperationId?.toLowerCase() ?? null;
  const protocolId = typeof protocol.befOperationId === 'string' ? protocol.befOperationId.toLowerCase() : null;
  demand(recordedId === protocolId);
  const operation = recordedId ? operationsById.get(recordedId) ?? null : matchingByKey[0] ?? null;
  demand(!recordedId || operation !== null);
  demand(!operation || matchingByKey.length === 0 || operation.operation_id === matchingByKey[0]!.operation_id);
  if (!operation) return null;

  const generation = packet.bef.after.generation;
  const expectedRequestHash = splitPayRequestSha256(packet.binding.environmentId, {
    resourceId: protocol.resourceId, offerId: protocol.offerId, readHandle: protocol.readHandle, acceptedTerms: protocol.acceptedTerms,
  });
  const operationId = String(operation.operation_id).toLowerCase();
  demand(operation.env_id === generation.env_id && operation.generation_id === generation.generation_id &&
    operation.participant_id === generation.participant_id &&
    String(operation.idempotency_key_sha256).toLowerCase() === expectedIdempotencyHash && operation.operation_kind === 'purchase' &&
    ['awaiting_payment', 'rejected'].includes(String(operation.status)) && operation.receipt_status === 'not_submitted' &&
    operation.transaction_hash === null && operation.payment_response_mode === 'deferred_delivery' &&
    operation.selected_offer_id === protocol.offerId && operation.selected_resource_id === protocol.resourceId &&
    typeof operation.selected_resource_sha256 === 'string' &&
    operation.selected_resource_sha256.toLowerCase() === String(protocol.resourceSha256).toLowerCase() &&
    operation.selected_amount_units === protocol.amountUnits && typeof operation.request_sha256 === 'string' &&
    operation.request_sha256.toLowerCase() === expectedRequestHash &&
    !packet.bef.after.payments.some((row) => String(row.operation_id).toLowerCase() === operationId) &&
    !packet.bef.after.deliveries.some((row) => String(row.operation_id).toLowerCase() === operationId) &&
    !packet.bef.after.costs.some((row) => String(row.operation_id).toLowerCase() === operationId) &&
    !packet.bef.after.x402Observations.some((row) => String(row.operation_id).toLowerCase() === operationId));
  const responseSha256 = operation.response_sha256;
  demand(responseSha256 === null || typeof responseSha256 === 'string' && HASH.test(responseSha256) &&
    typeof action.rawResponseSha256 === 'string' && responseSha256.toLowerCase() === action.rawResponseSha256.toLowerCase());
  return operation;
}

function m1RequirementsFromObserved(packet: M1CapturePacket, paymentOperation: JsonRecord, assets: M1PacketProjectionContext['assets']): {
  scheme: string; resourceId: string; offerId: string; version: string; amountUnits: string; network: string; assetId: string;
  recipient: string; authFields: Array<{ name: string; value: string }>;
} {
  const operationId = String(paymentOperation.operation_id);
  const rows = packet.bef.after.x402Observations.filter((row) => row.operation_id === operationId && row.phase === 'settle');
  demand(rows.length === 1);
  const row = rows[0]!;
  demand(row.outcome === 'success' && row.variant_id === 'baseline' &&
    typeof paymentOperation.transaction_hash === 'string' && row.transaction_hash === paymentOperation.transaction_hash);
  const req = record(row.requirements, ['scheme','network','asset','amount','payTo','maxTimeoutSeconds','extra']);
  const extra = record(req.extra, ['assetTransferMethod','paymentFlow','name','version']);
  const selectedOfferId = paymentOperation.selected_offer_id;
  const selectedResourceId = paymentOperation.selected_resource_id;
  const asset = assets.find((candidate) => candidate.kind === 'erc20' && candidate.address !== null &&
    candidate.chainId === Number(packet.rpc.localChainId) && addressEqual(candidate.address, req.asset));
  demand(typeof selectedOfferId === 'string' && typeof selectedResourceId === 'string' &&
    typeof paymentOperation.selected_amount_units === 'string' && typeof req.amount === 'string' &&
    paymentOperation.selected_amount_units === req.amount && typeof req.scheme === 'string' && boundedString(req.scheme, 64) &&
    typeof req.network === 'string' && boundedString(req.network, 128) && typeof req.asset === 'string' && ADDRESS.test(req.asset) &&
    typeof req.payTo === 'string' && ADDRESS.test(req.payTo) && asset !== undefined && typeof row.x402_version === 'string' &&
    typeof extra.assetTransferMethod === 'string' && typeof extra.paymentFlow === 'string' && typeof extra.name === 'string' && typeof extra.version === 'string');
  const authFields = Object.entries(extra).map(([name, value]) => {
    demand(typeof value === 'string');
    return { name, value };
  }).sort((left, right) => left.name.localeCompare(right.name));
  const requirements = {
    scheme: String(req.scheme), resourceId: selectedResourceId, offerId: selectedOfferId,
    version: String(row.x402_version), amountUnits: String(req.amount), network: String(req.network),
    assetId: asset!.assetId, recipient: String(req.payTo), authFields,
  };
  return requirements;
}

/**
 * Projects only the M1 payment, receipt-transfer, delivery and participant-gas facts that have
 * been independently joined to this packet. The sealed reader still reloads owner/BEF/RPC facts
 * and compares this deterministic projection with the immutable observation bundle.
 */
function projectSingleM1PacketObservations(
  packet: M1CapturePacket,
  context: M1PacketProjectionContext,
  actions: readonly M1CaptureAction[],
): M1PacketObservationProjection {
  const { taskCase, binding, taskIndex, closureId, captureEvidence, assets } = context;
  demand(taskCase.taskId === 'M1' && Number.isSafeInteger(taskIndex) && taskIndex >= 0 && taskIndex <= 11 &&
    packet.closure.closureId === closureId && canonicalTaskJson(packet.binding) === canonicalTaskJson(binding));
  demand(validRef(captureEvidence, CAPTURE_PREFIX));
  const observed = actions.filter((action) => action.receiptStatus === 'observed');
  const payActions = observed.filter((action) => action.actionKind === 'pay');
  demand(payActions.length === 1);
  const payAction = payActions[0]!;
  const payResponse = payAction.participantToolResponse!;
  const payProtocol = payAction.paymentProtocol!;
  demand(typeof payAction.befOperationId === 'string' && payAction.transactionHash !== null);
  const operation = packet.bef.after.operations.find((row) => row.operation_id === payAction.befOperationId);
  demand(operation !== undefined && operation.operation_kind === 'purchase' && ['settled', 'delivered'].includes(String(operation.status)) && operation.receipt_status === 'success' &&
    typeof operation.transaction_hash === 'string' && operation.transaction_hash.toLowerCase() === payAction.transactionHash.toLowerCase());
  const requirements = m1RequirementsFromObserved(packet, operation, context.assets);
  const observedTerms = packet.bef.after.x402Observations.find((row) => row.operation_id === operation.operation_id && row.phase === 'settle')?.requirements;
  demand(typeof payAction.rawResponseSha256 === 'string' && operation.response_sha256 === payAction.rawResponseSha256);
  demand(operation.selected_resource_id === taskCase.objective.component.resourceId && operation.selected_resource_id === packet.bef.resourcePin.resourceId &&
    operation.selected_resource_sha256 === packet.bef.resourcePin.resourceSha256 && operation.selected_offer_id === payProtocol.offerId &&
    operation.selected_amount_units === payProtocol.amountUnits && operation.payment_response_mode === 'deferred_delivery');
  demand(payProtocol.befOperationId === operation.operation_id && payProtocol.resourceId === operation.selected_resource_id &&
    payProtocol.offerId === operation.selected_offer_id && payProtocol.resourceSha256 === operation.selected_resource_sha256 &&
    payProtocol.amountUnits === operation.selected_amount_units && payProtocol.network === requirements.network &&
    isRecord(observedTerms) && addressEqual(payProtocol.asset, observedTerms.asset) &&
    addressEqual(payProtocol.facilitatorAddress, requirements.recipient));
  demand(payResponse.operationId === operation.operation_id && payResponse.status === 'payment_confirmed' &&
    isRecord(payResponse.payment) && payResponse.payment.receiptStatus === 'success' && payResponse.payment.transactionHash === operation.transaction_hash &&
    payResponse.payment.amount === operation.selected_amount_units && addressEqual(payResponse.payment.asset, payProtocol.asset) &&
    payResponse.payment.network === requirements.network && addressEqual(payResponse.payment.payTo, requirements.recipient));
  const readHandle = record(payProtocol.readHandle, ['kind','operationId']);
  const readKind: M1ActionKind = readHandle.kind === 'offer' ? 'inspect_offer' : 'inspect_catalog';
  demand((readHandle.kind === 'offer' || readHandle.kind === 'catalog') && typeof readHandle.operationId === 'string' &&
    UUID.test(readHandle.operationId) && Number.isSafeInteger(payAction.actionSequence));
  const readAction = observed.find((action) => action.actionKind === readKind && action.befOperationId === readHandle.operationId &&
    action.actionSequence < payAction.actionSequence);
  demand(readAction !== undefined && readAction.participantToolResponse !== null);
  if (readAction.befOperationId !== null) {
    const readOperation = packet.bef.after.operations.find((row) => row.operation_id === readAction.befOperationId);
    demand(readOperation !== undefined && typeof readAction.rawResponseSha256 === 'string' && readOperation.response_sha256 === readAction.rawResponseSha256);
  }
  const readResponse = readAction.participantToolResponse;
  if (readKind === 'inspect_offer') {
    demand(readResponse.resourceId === packet.bef.resourcePin.resourceId && readResponse.resourceSha256 === packet.bef.resourcePin.resourceSha256 &&
      readResponse.freeInspection === true && readResponse.deliveryState === 'not_delivered' && Array.isArray(readResponse.offers) &&
      isRecord(readResponse.payment) && readResponse.payment.scheme === requirements.scheme &&
      readResponse.offers.some((offer) => isRecord(offer) && offer.id === operation.selected_offer_id && isRecord(offer.payment) &&
        offer.payment.scheme === requirements.scheme && offer.payment.amount === operation.selected_amount_units && offer.payment.network === requirements.network &&
        addressEqual(offer.payment.asset, observedTerms?.asset) &&
        addressEqual(offer.payment.payTo, requirements.recipient)));
  } else {
    demand(Array.isArray(readResponse.catalog) && readResponse.catalog.some((resource) => isRecord(resource) &&
      resource.resourceId === packet.bef.resourcePin.resourceId && resource.resourceSha256 === packet.bef.resourcePin.resourceSha256 &&
      Array.isArray(resource.offers) && resource.offers.some((offer) => isRecord(offer) && offer.id === operation.selected_offer_id &&
        isRecord(offer.payment) && offer.payment.scheme === requirements.scheme && offer.payment.amount === operation.selected_amount_units && offer.payment.network === requirements.network &&
        addressEqual(offer.payment.asset, observedTerms?.asset) && addressEqual(offer.payment.payTo, requirements.recipient))));
  }
  const acceptedTerms = record(payProtocol.acceptedTerms, ['scheme','network','asset','amount','payTo','transferMethod']);
  demand(acceptedTerms.scheme === requirements.scheme && acceptedTerms.network === requirements.network &&
    isRecord(observedTerms) && addressEqual(acceptedTerms.asset, observedTerms.asset) && acceptedTerms.amount === requirements.amountUnits &&
    addressEqual(acceptedTerms.payTo, requirements.recipient) &&
    acceptedTerms.transferMethod === requirements.authFields.find((field) => field.name === 'assetTransferMethod')?.value);

  const payments = packet.bef.after.payments.filter((row) => row.operation_id === operation.operation_id);
  demand(payments.length === 1);
  const paymentRow = payments[0]!;
  const operationTxHash = String(operation.transaction_hash);
  const paymentTxHash = String(paymentRow.transaction_hash);
  const txHash = operationTxHash.toLowerCase();
  const proofRows = (packet.rpc.paymentProofs as JsonRecord[]).filter((row) => row.operationId === operation.operation_id && row.paymentId === paymentRow.payment_id);
  demand(proofRows.length === 1);
  const proof = proofRows[0]!;
  const transaction = record(proof.transaction, ['hash','from','to','value','nonce','blockNumber','blockHash','inputSha256']);
  const receipt = record(proof.receipt, ['transactionHash','transactionIndex','blockNumber','blockHash','from','to','status','gasUsed','effectiveGasPrice','logsSha256']);
  const asset = assets.find((item) => item.assetId === requirements.assetId);
  demand(asset !== undefined && asset.kind === 'erc20' && asset.address !== null && asset.chainId === Number(packet.rpc.localChainId));
  const payerAddress = String(packet.bef.after.generation.payer_address).toLowerCase();
  const payTo = requirements.recipient.toLowerCase();
  demand(paymentRow.receipt_status === 'success' && paymentTxHash.toLowerCase() === txHash &&
    paymentRow.amount_units === requirements.amountUnits && paymentRow.token_delta_units === requirements.amountUnits &&
    paymentRow.network === requirements.network && String(paymentRow.asset_address).toLowerCase() === asset.address.toLowerCase() &&
    String(paymentRow.payer_address).toLowerCase() === payerAddress && String(paymentRow.facilitator_address).toLowerCase() === payTo &&
    BigInt(String(paymentRow.payer_balance_before)) - BigInt(String(paymentRow.payer_balance_after)) === BigInt(requirements.amountUnits) &&
    BigInt(String(paymentRow.facilitator_balance_after)) - BigInt(String(paymentRow.facilitator_balance_before)) === BigInt(requirements.amountUnits));
  const transactionFrom = String(transaction.from);
  demand(proof.transactionHash === operationTxHash && transaction.hash === operationTxHash &&
    (transaction.to === null || addressEqual(transaction.to, asset.address)) &&
    receipt.transactionHash === operationTxHash && receipt.status === 'success' && receipt.transactionIndex !== undefined &&
    receipt.blockHash === transaction.blockHash && receipt.blockNumber === transaction.blockNumber &&
    (receipt.to === null ? transaction.to === null : addressEqual(receipt.to, transaction.to)) && addressEqual(receipt.from, transactionFrom));
  const matchingCosts = packet.bef.after.costs.filter((row) => String(row.transaction_hash).toLowerCase() === txHash && row.operation_id === operation.operation_id);
  demand(matchingCosts.length === 1);
  const cost = matchingCosts[0]!;
  demand(cost.receipt_status === 'success' && String(cost.transaction_from).toLowerCase() === transactionFrom.toLowerCase() &&
    String(cost.receipt_from).toLowerCase() === String(receipt.from).toLowerCase() && cost.receipt_block_number === receipt.blockNumber &&
    String(cost.receipt_block_hash).toLowerCase() === String(receipt.blockHash).toLowerCase() && cost.gas_used === receipt.gasUsed &&
    cost.effective_gas_price_wei === receipt.effectiveGasPrice && String(cost.manifest_sha256).toLowerCase() === String(packet.execution.environmentManifestHash).toLowerCase() &&
    addressEqual(cost.payer_address, cost.payer_role === 'participant' ? payerAddress : paymentRow.facilitator_address) &&
    addressEqual(transactionFrom, cost.payer_address) && addressEqual(payProtocol.payerAddress, payerAddress) &&
    addressEqual(payProtocol.facilitatorAddress, paymentRow.facilitator_address));
  const transactionLogs = (packet.rpc.participantTransferLogs as JsonRecord[]).filter((row) => String(row.transactionHash).toLowerCase() === txHash);
  const transactionLogIndexes = new Set<string>();
  for (const row of transactionLogs) {
    const logIndex = String(row.logIndex);
    demand(row.blockNumber === receipt.blockNumber && addressEqual(row.blockHash, receipt.blockHash) &&
      (addressEqual(row.from, payerAddress) || addressEqual(row.to, payerAddress)) && !transactionLogIndexes.has(logIndex));
    transactionLogIndexes.add(logIndex);
  }
  const settlementLogs = transactionLogs.filter((row) => row.assetId === asset.assetId &&
    String(row.tokenAddress).toLowerCase() === asset.address!.toLowerCase() && String(row.from).toLowerCase() === payerAddress &&
    String(row.to).toLowerCase() === payTo);
  demand(settlementLogs.length >= 1 && settlementLogs.reduce((sum, row) => sum + BigInt(String(row.amountUnits)), 0n) === BigInt(requirements.amountUnits));

  const retrieveActions = observed.filter((action) => action.actionKind === 'retrieve' && action.befOperationId === operation.operation_id &&
    action.actionSequence > payAction.actionSequence);
  const deliveryRows = packet.bef.after.deliveries.filter((row) => row.operation_id === operation.operation_id &&
    row.resource_id === taskCase.objective.component.resourceId);
  const meta = (observationId: string, sequence: number, actionSequence: number) => ({
    observationId, sequence, actionSequence, source: 'persisted_observer' as const, binding, evidence: captureEvidence,
  });
  const manifest = validateManifest(packet.bef.environmentManifest.bytes, packet.bef.environmentManifest.sha256);
  const resource = (manifest.x402 as JsonRecord).catalog as JsonRecord[];
  const pinnedResource = resource.find((item) => item.resourceId === taskCase.objective.component.resourceId);
  demand(pinnedResource !== undefined && pinnedResource.resourceSha256 === packet.bef.resourcePin.resourceSha256 && isRecord(pinnedResource.provenance) &&
    typeof pinnedResource.provenance.classification === 'string' && typeof pinnedResource.schema === 'string');
  let delivery: DataDeliveryObservation | null = null;
  if (operation.status === 'delivered') {
    const uniqueDeliveryIds = new Set(deliveryRows.map((row) => row.delivery_id));
    demand(deliveryRows.length === 1 && uniqueDeliveryIds.size === 1 && retrieveActions.length >= 1);
    const deliveryRow = deliveryRows[0]!;
    const deliveryContentSha256 = String(deliveryRow.content_sha256);
    const deliveryByteCount = String(deliveryRow.content_bytes);
    demand(deliveryContentSha256.toLowerCase() === packet.bef.resourcePin.resourceSha256.toLowerCase());
    const matchingRetrieve = retrieveActions.filter((action) => {
      const response = action.participantToolResponse;
      const protocol = action.paymentProtocol;
      if (response === null || protocol === null || response.operationId !== operation.operation_id ||
          response.resourceId !== taskCase.objective.component.resourceId || response.contentType !== packet.bef.resourcePin.contentType ||
          response.contentHash !== packet.bef.resourcePin.resourceSha256 || typeof response.contentBytes !== 'string' || !isRecord(response.content) ||
          protocol.payOperationId !== operation.operation_id || protocol.resourceId !== taskCase.objective.component.resourceId ||
          protocol.resourceSha256 !== packet.bef.resourcePin.resourceSha256 || protocol.deliveryMatchesPinnedResource !== true) return false;
      const bytes = parseBase64(response.contentBytes, 1024 * 1024);
      const digest = createHash('sha256').update(bytes).digest('hex');
      let decoded: unknown;
      try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
      catch { return false; }
      return BigInt(deliveryByteCount) === BigInt(bytes.length) && digest.toLowerCase() === packet.bef.resourcePin.resourceSha256.toLowerCase() &&
        canonicalTaskJson(decoded) === canonicalTaskJson(response.content) &&
        response.operationId === operation.operation_id && response.resourceId === taskCase.objective.component.resourceId &&
        response.contentType === packet.bef.resourcePin.contentType && response.contentHash === packet.bef.resourcePin.resourceSha256;
    });
    demand(matchingRetrieve.length >= 1 && retrieveActions.every((action) => action.receiptStatus === 'observed'
      ? matchingRetrieve.some((validAction) => validAction.actionId === action.actionId) : true));
    const firstRetrieve = matchingRetrieve.sort((left, right) => left.actionSequence - right.actionSequence)[0]!;
    demand(firstRetrieve.actionSequence > payAction.actionSequence && deliveryRow.resource_id === packet.bef.resourcePin.resourceId);
    const response=firstRetrieve.participantToolResponse!;
    const payload = {resourceId:response.resourceId,contentType:response.contentType,contentHash:response.contentHash,contentBytes:response.contentBytes};
    const payloadSha256 = createHash('sha256').update(canonicalTaskJson(payload)).digest('hex');
    delivery = {
      kind: 'data_delivery', ...meta(`m1-delivery-${deliveryRow.delivery_id}`, firstRetrieve.actionSequence, firstRetrieve.actionSequence),
      componentId: taskCase.objective.component.componentId, resourceId: String(deliveryRow.resource_id),
      sourceId: String(pinnedResource.provenance.classification), payloadSchemaVersion: 'bef-delivery-envelope/v1',
      payloadSha256, payload, transactionHash: String(paymentRow.transaction_hash), paymentAttemptId: String(paymentRow.payment_id),
    };
  } else {
    demand(deliveryRows.length === 0 && retrieveActions.length === 0);
  }

  const transferObservations: TransferObservation[] = transactionLogs.map((row) => {
    const logAsset = assets.find((candidate) => candidate.assetId === row.assetId && candidate.kind === 'erc20' && candidate.address !== null &&
      candidate.chainId === Number(packet.rpc.localChainId) && addressEqual(candidate.address, row.tokenAddress));
    demand(logAsset !== undefined);
    const settlement = row.assetId === asset.assetId && String(row.tokenAddress).toLowerCase() === asset.address!.toLowerCase() &&
      String(row.from).toLowerCase() === payerAddress && String(row.to).toLowerCase() === payTo;
    return { kind: 'transfer', ...meta(`m1-transfer-${paymentRow.payment_id}-${row.logIndex}`, payAction.actionSequence, payAction.actionSequence),
      from: addressEqual(row.from, payerAddress) ? 'participant' : String(row.from),
      to: addressEqual(row.to, payerAddress) ? 'participant' : String(row.to),
      assetId: logAsset.assetId, amountUnits: String(row.amountUnits), receiptStatus: 'success' as const,
      transactionHash: String(row.transactionHash), operation: settlement ? 'settlement' as const : 'other' as const,
      paymentAttemptId: String(paymentRow.payment_id) };
  });
  const paymentObservation: PaymentObservation = {
    kind: 'payment', ...meta(`m1-payment-${paymentRow.payment_id}`, payAction.actionSequence, payAction.actionSequence),
    paymentAttemptId: String(paymentRow.payment_id), status: 'settled', requirements,
    gasPayer: cost.payer_role === 'participant' ? 'participant' : 'facilitator', transactionHash: String(paymentRow.transaction_hash),
  };
  // AICODE-NOTE: A settled payment is not a delivery. Only this complete, validated
  // closed-cutoff census can distinguish a never-admitted retrieve from lost delivery evidence.
  // Even a rejected admitted retrieve remains outside this narrow absence authority.
  if (!context.preserveLegacyDeliveryObservations && operation.status === 'settled' && operation.payment_response_mode === 'deferred_delivery' &&
      !delivery && !packet.ownerActions.some((action) => action.actionKind === 'retrieve')) {
    paymentObservation.deliveryRequestAbsence = {
      schemaVersion: 'bts-delivery-request-absence/v1', status: 'not_admitted_at_cutoff',
      paymentAttemptId: paymentObservation.paymentAttemptId, paymentActionSequence: payAction.actionSequence,
      acceptedActionCutoffSequence: packet.closure.actionCutoffSequence as number,
      authority: { closureId: packet.closure.closureId as string, preparationId: packet.execution.preparationId as string,
        leaseId: packet.execution.leaseId as string, generationId: packet.execution.generationId as string },
      captureEvidence,
    };
  }
  const stateMutations: StateMutationObservation[] = [
    { kind: 'state_mutation', ...meta(`m1-state-payer-${paymentRow.payment_id}`, payAction.actionSequence, payAction.actionSequence),
      mutationType: 'balance', key: `${payerAddress}:${asset.assetId}`, beforeValue: String(paymentRow.payer_balance_before),
      afterValue: String(paymentRow.payer_balance_after), transactionHash: String(paymentRow.transaction_hash) },
    { kind: 'state_mutation', ...meta(`m1-state-recipient-${paymentRow.payment_id}`, payAction.actionSequence, payAction.actionSequence),
      mutationType: 'balance', key: `${payTo}:${asset.assetId}`, beforeValue: String(paymentRow.facilitator_balance_before),
      afterValue: String(paymentRow.facilitator_balance_after), transactionHash: String(paymentRow.transaction_hash) },
  ];
  const expenses: ExpenseObservation[] = cost.payer_role === 'participant' ? [{
    kind: 'expense', ...meta(`m1-expense-${operation.operation_id}`, payAction.actionSequence, payAction.actionSequence), component: 'participant_gas',
    sourceEffectId: `bef-operation:${operation.operation_id}`, gasUsed: String(cost.gas_used),
    effectiveGasPriceWei: String(cost.effective_gas_price_wei), receiptStatus: 'success', transactionHash: String(cost.transaction_hash),
  }] : [];
  const cutoff = safeSequence(packet.closure.actionCutoffSequence);
  demand(cutoff !== null && transferObservations.every((row) => row.sequence <= cutoff) &&
    paymentObservation.sequence <= cutoff && (!delivery || delivery.sequence <= cutoff) &&
    context.assets.some((item) => item.assetId === asset.assetId));
  return {
    coverage: { transfers: 'complete', payments: 'complete', stateMutations: 'complete', deliveries: 'complete', expenses: 'complete' },
    transfers: transferObservations, payments: [paymentObservation], stateMutations, deliveries: delivery ? [delivery] : [], expenses,
  };
}

/**
 * Projects every fully joined M1 payment attempt. A verified pre-execution rejection contributes
 * no payment facts, while complete no-effect evidence still lets the evaluator score the missed
 * objective as zero. Unknown or unexplained effects fail closed.
 */
export function projectM1PacketObservations(
  packetValue: M1CapturePacket | unknown,
  context: M1PacketProjectionContext,
): M1PacketObservationProjection {
  const packet = validateM1CapturePacket(packetValue);
  const { taskCase, binding, taskIndex, closureId, captureEvidence } = context;
  demand(taskCase.taskId === 'M1' && Number.isSafeInteger(taskIndex) && taskIndex >= 0 && taskIndex <= 11 &&
    packet.closure.closureId === closureId && canonicalTaskJson(packet.binding) === canonicalTaskJson(binding) &&
    validRef(captureEvidence, CAPTURE_PREFIX));

  const observedPays = packet.ownerActions.filter((action) => action.actionKind === 'pay' && action.receiptStatus === 'observed');
  const purchaseOperations = packet.bef.after.operations.filter((operation) => operation.operation_kind === 'purchase');
  const paymentProofs = packet.rpc.paymentProofs as JsonRecord[];
  const participantTransferLogs = packet.rpc.participantTransferLogs as JsonRecord[];
  demand(packet.bef.after.selectedExecutions.length === 0 && packet.bef.after.selectedEvents.length === 0 && packet.bef.after.denials.length === 0);
  const operationsById = new Map(packet.bef.after.operations.map((operation) => [String(operation.operation_id).toLowerCase(), operation]));
  const joinedOperationIds = new Set<string>();
  const readOperationIds = new Set<string>();
  const rejectedPurchaseOperationIds = new Set<string>();
  for (const action of packet.ownerActions) {
    if (action.receiptStatus === 'rejected_before_execution') {
      const operation = validateRejectedPurchaseOperation(packet, action, operationsById);
      if (operation) {
        const operationId = String(operation.operation_id);
        demand(!joinedOperationIds.has(operationId));
        joinedOperationIds.add(operationId);
        rejectedPurchaseOperationIds.add(operationId);
      }
      continue;
    }
    if (action.actionKind === 'inspect_catalog' && action.befOperationId === null) {
      demand(action.participantToolResponse?.operationId === undefined && action.participantToolResponse?.readHandle === undefined);
      continue;
    }
    demand(action.befOperationId !== null);
    const operationId = action.befOperationId;
    const operation = operationsById.get(operationId.toLowerCase());
    demand(operation !== undefined);
    if (action.actionKind === 'inspect_catalog' || action.actionKind === 'inspect_offer') {
      demand(!readOperationIds.has(operationId) && operation.operation_kind === (action.actionKind === 'inspect_catalog' ? 'catalog' : 'offer') &&
        operation.status === 'accepted' && operation.receipt_status === 'not_submitted' && operation.transaction_hash === null &&
        operation.response_sha256 === action.rawResponseSha256);
      readOperationIds.add(operationId);
      joinedOperationIds.add(operationId);
    } else if (action.actionKind === 'pay') {
      demand(operation.operation_kind === 'purchase' && ['settled','delivered'].includes(String(operation.status)) &&
        operation.receipt_status === 'success' && operation.transaction_hash === action.transactionHash &&
        operation.response_sha256 === action.rawResponseSha256);
      joinedOperationIds.add(operationId);
    } else {
      demand(operation.operation_kind === 'purchase' && ['settled','delivered'].includes(String(operation.status)) &&
        operation.receipt_status === 'success' && action.participantToolResponse?.operationId === operationId && joinedOperationIds.has(operationId));
    }
  }
  demand(joinedOperationIds.size === packet.bef.after.operations.length &&
    purchaseOperations.length === observedPays.length + rejectedPurchaseOperationIds.size);
  const actionOperationIds = new Set<string>();
  const operationIds = new Set<string>();
  for (const action of observedPays) {
    const operationId = action.befOperationId;
    demand(typeof operationId === 'string' && action.transactionHash !== null && !actionOperationIds.has(operationId));
    actionOperationIds.add(operationId);
  }
  for (const operation of purchaseOperations) {
    const operationId = operation.operation_id;
    demand(typeof operationId === 'string' &&
      (actionOperationIds.has(operationId) || rejectedPurchaseOperationIds.has(operationId)) && !operationIds.has(operationId));
    operationIds.add(operationId);
  }

  const observedPurchaseOperations = purchaseOperations.filter((operation) => actionOperationIds.has(String(operation.operation_id)));

  if (observedPays.length === 0) {
    const before = packet.rpc.baseline as JsonRecord;
    const after = packet.rpc.final as JsonRecord;
    demand(packet.bef.after.payments.length === 0 && packet.bef.after.deliveries.length === 0 && packet.bef.after.costs.length === 0 &&
      packet.bef.after.selectedExecutions.length === 0 && packet.bef.after.selectedEvents.length === 0 &&
      packet.bef.after.denials.length === 0 && packet.bef.after.x402Observations.length === 0 && paymentProofs.length === 0 &&
      participantTransferLogs.length === 0 &&
      before.participantTransactionCount === after.participantTransactionCount &&
      canonicalTaskJson(before.balances) === canonicalTaskJson(after.balances) &&
      canonicalTaskJson(before.allowances) === canonicalTaskJson(after.allowances));
    return {
      coverage: { transfers: 'complete', payments: 'complete', stateMutations: 'complete', deliveries: 'complete', expenses: 'complete' },
      transfers: [], payments: [], stateMutations: [], deliveries: [], expenses: [],
    };
  }

  demand(packet.bef.after.payments.length === observedPays.length && packet.bef.after.costs.length === observedPays.length &&
    packet.bef.after.deliveries.length === purchaseOperations.filter((operation) => operation.status === 'delivered').length &&
    paymentProofs.length === observedPays.length && packet.bef.after.x402Observations.length === observedPays.length * 2 &&
    packet.bef.after.x402Observations.every((observation) => typeof observation.operation_id === 'string' &&
      actionOperationIds.has(observation.operation_id)) &&
    participantTransferLogs.every((log) => observedPays.some((action) => {
      const operation = purchaseOperations.find((candidate) => candidate.operation_id === action.befOperationId);
      return typeof operation?.transaction_hash === 'string' && operation.transaction_hash.toLowerCase() === String(log.transactionHash).toLowerCase();
    })));
  for (const operation of observedPurchaseOperations) {
    const rows = packet.bef.after.x402Observations.filter((observation) => observation.operation_id === operation.operation_id);
    const verify = rows.filter((observation) => observation.phase === 'verify');
    const settle = rows.filter((observation) => observation.phase === 'settle');
    demand(rows.length === 2 && verify.length === 1 && settle.length === 1 && verify[0]!.outcome === 'success' &&
      settle[0]!.outcome === 'success' && verify[0]!.variant_id === 'baseline' && settle[0]!.variant_id === 'baseline' &&
      settle[0]!.transaction_hash === operation.transaction_hash && verify[0]!.x402_version === settle[0]!.x402_version &&
      canonicalTaskJson(verify[0]!.requirements) === canonicalTaskJson(settle[0]!.requirements));
  }

  const combined: M1PacketObservationProjection = {
    coverage: { transfers: 'complete', payments: 'complete', stateMutations: 'complete', deliveries: 'complete', expenses: 'complete' },
    transfers: [], payments: [], stateMutations: [], deliveries: [], expenses: [],
  };
  for (const payAction of observedPays) {
    const protocol = payAction.paymentProtocol;
    demand(protocol !== null && payAction.befOperationId !== null);
    const handle = record(protocol.readHandle, ['kind', 'operationId']);
    const readAction = packet.ownerActions.find((action) => action.actionSequence < payAction.actionSequence &&
      action.receiptStatus === 'observed' && action.befOperationId === handle.operationId &&
      action.actionKind === (handle.kind === 'offer' ? 'inspect_offer' : 'inspect_catalog'));
    demand(readAction !== undefined);
    const relatedActions = packet.ownerActions.filter((action) => action.actionId === readAction.actionId || action.actionId === payAction.actionId ||
      action.actionKind === 'retrieve' && action.befOperationId === payAction.befOperationId);
    const one = projectSingleM1PacketObservations(packet, context, relatedActions);
    combined.transfers.push(...one.transfers);
    combined.payments.push(...one.payments);
    combined.stateMutations.push(...one.stateMutations);
    combined.deliveries.push(...one.deliveries);
    combined.expenses.push(...one.expenses);
  }
  const uniqueDeliveryIds = new Set(packet.bef.after.deliveries.map((row) => row.delivery_id));
  demand(uniqueDeliveryIds.size === packet.bef.after.deliveries.length && combined.deliveries.length === packet.bef.after.deliveries.length &&
    new Set(combined.deliveries.map((row) => row.observationId)).size === combined.deliveries.length);
  return combined;
}
