import { createHash } from 'node:crypto';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase } from './task-release.js';
import { splitPayRequestSha256 } from './task-m1-capture-packet.js';
import type { PaymentObservation, PersistedTaskObservations } from './task-evaluator.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';

const HASH = /^[0-9a-f]{64}$/i;
const TX = /^0x[0-9a-f]{64}$/i;
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const SECRET_KEYS = new Set(['privatekey','privkey','seedphrase','mnemonic','secret','clientsecret','bearer','bearertoken','accesstoken',
  'refreshtoken','providertoken','paymenttoken','token','apitoken','apikey','authorization','walletmaterial','walletsecret','signature',
  'signedpayload','paymentpayload','paymentauthorization','paymentauth','paymentproof','xpayment','xpaymentsignature','xpaymentpayload',
  'xpaymentauthorization','x402authorization','x402signature','x402payload','x402proof','password','dsn','databaseurl']);
const SECRET_VALUE_KEYS = new Set(['input','data','calldata','rawtransaction','rawtx','v','r','s']);

export type PaidDataTaskId = 'M1' | 'M2' | 'H1' | 'H3' | 'U1';
export type PaidDataActionKind = 'inspect_catalog' | 'inspect_offer' | 'purchase' | 'pay' | 'retrieve';
export type ChainObservationBoundary = {
  actionCutoffSequence: number;
  observationCutoffSequence: number;
  baselineBlockNumber: string;
  baselineBlockHash: string;
  finalBlockNumber: string;
  finalBlockHash: string;
};
export type PaidDataAction = {
  actionId: string; actionSequence: number; ownerOperationId: string; actionKind: PaidDataActionKind; commandSha256: string;
  receiptStatus: 'observed' | 'rejected_before_execution'; actionEvidence: EvidenceReference; befOperationId: string | null;
  transactionHash: string | null; rawResponseSha256: string | null; safeResponse: Record<string, unknown> | null;
  paymentProtocol: Record<string, unknown> | null;
  retrievedContent: { payloadSchemaVersion: string; resourceSchema: string; resourceId: string; contentType: string; contentSha256: string; byteCount: number; validJson: boolean } | null;
};
export type PaidDataCapturePacket = {
  schemaVersion: 'bts-paid-data-run-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: Record<string, unknown> & { taskId: PaidDataTaskId };
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number; reason: string; operationId: string | null; payloadHash: string };
  execution: { preparationId: string; leaseId: string; generationId: string; environmentId: string; environmentManifestHash: string;
    applicationSourceHash: string; executionIdentityHash: string; initialStateSha256: string };
  preparation: { fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference; baselineBlockNumber: string; baselineBlockHash: string };
  manifest: { sha256: string; paymentPolicy: Record<string, unknown>; catalog: Array<Record<string, unknown>>;
    componentReferences: Array<{ componentId: string; resourceId: string }> };
  ownerActions: PaidDataAction[];
  bef: { session: Record<string, unknown>; before: Record<string, unknown>; after: Record<string, unknown>; censusSha256: string };
  rpc: { localChainId: string; baselineBlock: { number: string; hash: string }; finalBlock: { number: string; hash: string }; paymentEffects: Array<Record<string, unknown>> };
  coverage: { actionCutoffSequence: number; observationCutoffSequence: number; ownerActionCount: number; paidActionCount: number;
    befPaymentCount: number; deliveryCount: number; costCount: number; rpcPaymentProofCount: number; status: 'observed' | 'partial' | 'unknown' | 'contradictory' };
};
export class PaidDataCapturePacketError extends Error {
  constructor(readonly code: 'PAID_DATA_PACKET_INVALID' | 'PAID_DATA_PACKET_SECRET_FIELD' | 'PAID_DATA_PACKET_LIMIT_EXCEEDED') {
    super(code); this.name = 'PaidDataCapturePacketError';
  }
}
function fail(code: PaidDataCapturePacketError['code']): never { throw new PaidDataCapturePacketError(code); }
function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}
function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join('\u0000') === [...keys].sort().join('\u0000');
}
function hasSecret(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  const found = Array.isArray(value) ? value.some((item) => hasSecret(item, seen)) :
    Object.entries(value as Record<string, unknown>).some(([key, child]) => {
      const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
      return SECRET_KEYS.has(normalized) || SECRET_VALUE_KEYS.has(normalized) || hasSecret(child, seen);
    });
  seen.delete(value); return found;
}
function validEvidenceRef(value: unknown, prefix: string): value is EvidenceReference {
  return isRecord(value) && exactKeys(value, ['path','sha256','boundary']) && value.boundary === BOUNDARY &&
    typeof value.path === 'string' && value.path.startsWith(prefix) && value.path.length <= 512 &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path) &&
    !value.path.includes('\\') && !value.path.includes('\0') && value.path.split('/').every((part) => part && part !== '.' && part !== '..') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256);
}
function safeInteger(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0; }
function checkHash(value: unknown): value is string { return typeof value === 'string' && HASH.test(value); }
function checkBlock(value: unknown): boolean {
  return isRecord(value) && typeof value.number === 'string' && /^(?:0|[1-9][0-9]*)$/.test(value.number) &&
    typeof value.hash === 'string' && TX.test(value.hash);
}
function validatePaidAction(value: unknown): value is PaidDataAction {
  if (!isRecord(value) || !exactKeys(value, ['actionId','actionSequence','ownerOperationId','actionKind','commandSha256','receiptStatus',
    'actionEvidence','befOperationId','transactionHash','rawResponseSha256','safeResponse','paymentProtocol','retrievedContent'])) return false;
  if (typeof value.actionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.actionId) ||
      typeof value.ownerOperationId !== 'string' || value.ownerOperationId.length < 12 || value.ownerOperationId.length > 128 || !safeInteger(value.actionSequence) || value.actionSequence < 1 ||
      !['inspect_catalog','inspect_offer','purchase','pay','retrieve'].includes(String(value.actionKind)) || !checkHash(value.commandSha256) ||
      !['observed','rejected_before_execution'].includes(String(value.receiptStatus)) ||
      !validEvidenceRef(value.actionEvidence, 'artifacts/runs/owner-identity-bef-task-coordinator/action/') ||
      !(value.befOperationId === null || typeof value.befOperationId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.befOperationId)) ||
      !(value.transactionHash === null || typeof value.transactionHash === 'string' && TX.test(value.transactionHash)) ||
      !(value.rawResponseSha256 === null || checkHash(value.rawResponseSha256)) ||
      !(value.safeResponse === null || isRecord(value.safeResponse)) || !(value.paymentProtocol === null || isRecord(value.paymentProtocol))) return false;
  if (value.retrievedContent !== null) {
    const content = value.retrievedContent;
    if (!isRecord(content) || !exactKeys(content, ['payloadSchemaVersion','resourceSchema','resourceId','contentType','contentSha256','byteCount','validJson']) ||
        typeof content.payloadSchemaVersion !== 'string' || typeof content.resourceSchema !== 'string' || typeof content.resourceId !== 'string' || typeof content.contentType !== 'string' || !checkHash(content.contentSha256) ||
        !safeInteger(content.byteCount) || typeof content.validJson !== 'boolean') return false;
  }
  return true;
}
export function validatePaidDataCapturePacket(value: unknown): PaidDataCapturePacket {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion','classification','binding','closure','execution','preparation','manifest','ownerActions','bef','rpc','coverage']))
    fail('PAID_DATA_PACKET_INVALID');
  if (value.schemaVersion !== 'bts-paid-data-run-observation-capture/v1' || value.classification !== 'run_bound_observations_candidate_not_grade')
    fail('PAID_DATA_PACKET_INVALID');
  const binding = value.binding, closure = value.closure, execution = value.execution, preparation = value.preparation;
  const manifest = value.manifest, bef = value.bef, rpc = value.rpc, coverage = value.coverage;
  if (!isRecord(binding) || !['M1','M2','H1','H3','U1'].includes(String(binding.taskId)) ||
      !isRecord(closure) || !safeInteger(closure.actionCutoffSequence) || !safeInteger(closure.reconciledActionSequence) ||
      closure.reconciledActionSequence < closure.actionCutoffSequence || typeof closure.closureId !== 'string' ||
      typeof closure.reason !== 'string' || typeof closure.payloadHash !== 'string' || !checkHash(closure.payloadHash) ||
      !isRecord(execution) || typeof execution.preparationId !== 'string' || typeof execution.leaseId !== 'string' ||
      typeof execution.generationId !== 'string' || typeof execution.environmentId !== 'string' ||
      !checkHash(execution.environmentManifestHash) || !checkHash(execution.applicationSourceHash) ||
      !checkHash(execution.executionIdentityHash) || !checkHash(execution.initialStateSha256) ||
      !isRecord(preparation) || !validEvidenceRef(preparation.fixtureEvidence, 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/') ||
      !validEvidenceRef(preparation.baselineEvidence, 'artifacts/runs/owner-identity-bef-task-coordinator/preparation/') ||
      preparation.fixtureEvidence.path === preparation.baselineEvidence.path ||
      !/^(?:0|[1-9][0-9]*)$/.test(String(preparation.baselineBlockNumber)) || !TX.test(String(preparation.baselineBlockHash)) ||
      !isRecord(manifest) || !checkHash(manifest.sha256) || !isRecord(manifest.paymentPolicy) || !Array.isArray(manifest.catalog) ||
      !Array.isArray(manifest.componentReferences) || !Array.isArray(value.ownerActions) || !isRecord(bef) ||
      !isRecord(bef.session) || !isRecord(bef.before) || !isRecord(bef.after) || !checkHash(bef.censusSha256) || !isRecord(rpc) ||
      typeof rpc.localChainId !== 'string' || !checkBlock(rpc.baselineBlock) || !checkBlock(rpc.finalBlock) ||
      !Array.isArray(rpc.paymentEffects) || !isRecord(coverage) || !safeInteger(coverage.actionCutoffSequence) ||
      !safeInteger(coverage.observationCutoffSequence) || !safeInteger(coverage.ownerActionCount) || !safeInteger(coverage.paidActionCount) ||
      !safeInteger(coverage.befPaymentCount) || !safeInteger(coverage.deliveryCount) || !safeInteger(coverage.costCount) ||
      !safeInteger(coverage.rpcPaymentProofCount) || !['observed','partial','unknown','contradictory'].includes(String(coverage.status))) fail('PAID_DATA_PACKET_INVALID');
  if (value.ownerActions.some((action) => !validatePaidAction(action))) fail('PAID_DATA_PACKET_INVALID');
  const cutoff = closure.actionCutoffSequence;
  const actionIds = new Set<string>(), ownerOperations = new Set<string>(), actionSequences = new Set<number>();
  for (const action of value.ownerActions as PaidDataAction[]) {
    if (action.actionSequence > cutoff || actionIds.has(action.actionId) || ownerOperations.has(action.ownerOperationId) || actionSequences.has(action.actionSequence))
      fail('PAID_DATA_PACKET_INVALID');
    actionIds.add(action.actionId); ownerOperations.add(action.ownerOperationId); actionSequences.add(action.actionSequence);
  }
  if (manifest.catalog.some((item) => !isRecord(item))) fail('PAID_DATA_PACKET_INVALID');
  if ((manifest.componentReferences as unknown[]).some((component:unknown) => !isRecord(component) ||
      !exactKeys(component, ['componentId','resourceId']) || typeof component.componentId !== 'string' || typeof component.resourceId !== 'string'))
    fail('PAID_DATA_PACKET_INVALID');
  const after = bef.after as Record<string, unknown>;
  const censusRows = (key: string): unknown[] | null => Array.isArray(after[key]) ? after[key] as unknown[] : null;
  const censusPayments = censusRows('payments'), censusDeliveries = censusRows('deliveries'), censusCosts = censusRows('costs');
  if (coverage.actionCutoffSequence !== cutoff || coverage.ownerActionCount !== cutoff ||
      coverage.paidActionCount !== value.ownerActions.length || !censusPayments || !censusDeliveries || !censusCosts ||
      coverage.befPaymentCount !== censusPayments.length || coverage.deliveryCount !== censusDeliveries.length ||
      coverage.costCount !== censusCosts.length || coverage.rpcPaymentProofCount !== rpc.paymentEffects.filter((effect) => isRecord(effect) && effect.verification === 'observed').length ||
      !/^[1-9][0-9]*$/.test(rpc.localChainId)) fail('PAID_DATA_PACKET_INVALID');
  if (hasSecret(value)) fail('PAID_DATA_PACKET_SECRET_FIELD');
  if (Buffer.byteLength(canonicalTaskJson(value), 'utf8') > MAX_PACKET_BYTES) fail('PAID_DATA_PACKET_LIMIT_EXCEEDED');
  return value as unknown as PaidDataCapturePacket;
}
export function parsePaidDataCapturePacket(bytes: Uint8Array): PaidDataCapturePacket {
  if (bytes.byteLength > MAX_PACKET_BYTES) fail('PAID_DATA_PACKET_LIMIT_EXCEEDED');
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
  catch { fail('PAID_DATA_PACKET_INVALID'); }
  return validatePaidDataCapturePacket(parsed);
}
/** Rebinds the packet's chain and preparation baseline to the validated release and RPC interval. */
export function validatePaidDataCapturePacketPins(value: unknown, expectedLocalChainId: number): PaidDataCapturePacket {
  const packet = validatePaidDataCapturePacket(value);
  if (!Number.isSafeInteger(expectedLocalChainId) || expectedLocalChainId < 1 ||
      packet.rpc.localChainId !== String(expectedLocalChainId) ||
      packet.preparation.baselineBlockNumber !== packet.rpc.baselineBlock.number ||
      packet.preparation.baselineBlockHash.toLowerCase() !== packet.rpc.baselineBlock.hash.toLowerCase())
    fail('PAID_DATA_PACKET_INVALID');
  return packet;
}
export type PaidDataObservationCandidate = {
  schemaVersion: 'bts-paid-data-observation-candidate/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: PaidDataCapturePacket['binding'];
  boundary: ChainObservationBoundary;
  resources: Array<Record<string, unknown>>;
  componentReferences: PaidDataCapturePacket['manifest']['componentReferences'];
  actions: PaidDataAction[];
  payments: Array<Record<string, unknown>>;
  deliveries: Array<Record<string, unknown>>;
  costs: Array<Record<string, unknown>>;
  rpcPaymentEffects: Array<Record<string, unknown>>;
  coverage: PaidDataCapturePacket['coverage'];
};
/** Maps only paid-data facts and case component identifiers; validity and chain-task outcome remain evaluator inputs. */
export function projectPaidDataCaptureCandidate(packetValue: unknown, taskCase: TaskCase): PaidDataObservationCandidate {
  const packet = validatePaidDataCapturePacket(packetValue);
  if (taskCase.taskId !== packet.binding.taskId || taskCase.caseId !== packet.binding.caseId ||
      taskCase.caseHash !== packet.binding.caseHash) throw new PaidDataCapturePacketError('PAID_DATA_PACKET_INVALID');
  const expectedComponents = taskCase.taskId === 'M1' ? [taskCase.objective.component] :
    taskCase.taskId === 'H3' ? [taskCase.objective.referenceComponent] :
    taskCase.taskId === 'H1' || taskCase.taskId === 'U1' ? taskCase.objective.requiredComponents :
    taskCase.taskId === 'M2' ? taskCase.objective.catalog.map((offer) => ({ componentId: offer.offerId, resourceId: offer.resourceId })) : [];
  const componentReferences = packet.manifest.componentReferences;
  if (canonicalTaskJson(componentReferences) !== canonicalTaskJson(expectedComponents.map((component) =>
      ({ componentId: component.componentId, resourceId: component.resourceId }))) ||
      new Set(componentReferences.map((component) => component.componentId)).size !== componentReferences.length ||
      componentReferences.some((component) => !packet.manifest.catalog.some((resource) => resource.resourceId === component.resourceId)))
    throw new PaidDataCapturePacketError('PAID_DATA_PACKET_INVALID');
  const census = packet.bef.after;
  const payments = Array.isArray(census.payments) ? census.payments.filter(isRecord) : [];
  const deliveries = Array.isArray(census.deliveries) ? census.deliveries.filter(isRecord) : [];
  const costs = Array.isArray(census.costs) ? census.costs.filter(isRecord) : [];
  return {
    schemaVersion: 'bts-paid-data-observation-candidate/v1',
    classification: 'run_bound_observations_candidate_not_grade',
    binding: packet.binding,
    boundary: { actionCutoffSequence: packet.closure.actionCutoffSequence,
      observationCutoffSequence: packet.coverage.observationCutoffSequence,
      baselineBlockNumber: packet.rpc.baselineBlock.number, baselineBlockHash: packet.rpc.baselineBlock.hash,
      finalBlockNumber: packet.rpc.finalBlock.number, finalBlockHash: packet.rpc.finalBlock.hash },
    resources: packet.manifest.catalog, componentReferences: packet.manifest.componentReferences, actions: packet.ownerActions,
    payments, deliveries, costs, rpcPaymentEffects: packet.rpc.paymentEffects, coverage: packet.coverage,
  };
}

export type PaidDataObservationProjectionContext = {
  taskCase: TaskCase;
  binding: import('./task-evaluator.js').TaskEvidenceBinding;
  captureEvidence: EvidenceReference;
  assets: Array<{ assetId: string; kind: 'native' | 'erc20'; chainId: number; address: string | null }>;
  actionResponses: ReadonlyMap<string, Record<string, unknown>>;
};

/** Projects only typed evaluator facts that are joined to a real owner action and retained source evidence. */
export function projectPaidDataObservationBundle(packetValue: unknown, context: PaidDataObservationProjectionContext): TaskObservationBundleCandidate {
  const packet = validatePaidDataCapturePacket(packetValue);
  const paidCandidate = projectPaidDataCaptureCandidate(packet, context.taskCase);
  if (canonicalTaskJson(packet.binding) !== canonicalTaskJson(context.binding) ||
      context.captureEvidence.boundary !== 'actual_tool_http_x402_local_evm_application_store')
    fail('PAID_DATA_PACKET_INVALID');
  const census = packet.bef.after;
  const rows = (key: string): Array<Record<string, unknown>> => Array.isArray(census[key]) ?
    (census[key] as unknown[]).filter(isRecord) : [];
  const operations = rows('operations'), payments = rows('payments'), deliveries = rows('deliveries'), costs = rows('costs'), x402 = rows('x402Observations');
  const operationById = new Map(operations.map((row) => [String(row.operation_id).toLowerCase(), row]));
  const payActions = packet.ownerActions.filter((action) => (action.actionKind === 'pay' || action.actionKind === 'purchase') &&
    action.receiptStatus === 'observed' && action.befOperationId !== null);
  const payActionByOperation = new Map<string, PaidDataAction>();
  for (const action of payActions) if (!payActionByOperation.has(String(action.befOperationId).toLowerCase()))
    payActionByOperation.set(String(action.befOperationId).toLowerCase(), action);
  const rpcByOperation = new Map(packet.rpc.paymentEffects.filter(isRecord).map((effect) => [String(effect.operationId).toLowerCase(), effect]));
  const costByOperation = new Map<string, Record<string, unknown>>();
  for (const cost of costs) costByOperation.set(String(cost.operation_id).toLowerCase(), cost);
  const coverageStatus = (packet.coverage.status === 'contradictory' ? 'contradictory' :
    packet.coverage.status === 'observed' ? 'complete' : 'incomplete') as 'complete' | 'incomplete' | 'contradictory';
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding: context.binding, coveredThroughSequence: 0,
    captureEvidence: context.captureEvidence, coverage: { transfers: coverageStatus, payments: coverageStatus,
      stateMutations: coverageStatus, deliveries: coverageStatus, expenses: coverageStatus },
    transfers: [], payments: [], stateMutations: [], finalStates: [], allowanceChanges: [], allowanceUses: [],
    answers: [], selections: [], deliveries: [], trades: [], conversions: [], expenses: [],
  };
  const bump = (sequence: number) => { if (sequence > observations.coveredThroughSequence) observations.coveredThroughSequence = sequence; };
  const meta = (id: string, actionSequence: number) => ({ observationId: id, sequence: actionSequence, actionSequence,
    source: 'persisted_observer' as const, binding: context.binding, evidence: context.captureEvidence });
  let missingJoin = false;
  const paymentAttemptByOperation = new Map<string, Record<string, unknown>>();
  for (const payment of payments) {
    const operationId = String(payment.operation_id).toLowerCase(), action = payActionByOperation.get(operationId), operation = operationById.get(operationId);
    const effect = rpcByOperation.get(operationId), actionSequence = action?.actionSequence;
    if (!action || !operation || actionSequence === undefined) { missingJoin = true; continue; }
    const relevantX402 = x402.filter((row) => String(row.operation_id).toLowerCase() === operationId);
    const selectedX402 = relevantX402.find((row) => row.phase === 'settle') ?? relevantX402.find((row) => row.phase === 'challenge') ?? relevantX402[0];
    const requirements = selectedX402 && isRecord(selectedX402.requirements) ? selectedX402.requirements : null;
    const extra = requirements && isRecord(requirements.extra) ? requirements.extra : null;
    const asset = context.assets.find((candidate) => candidate.kind === 'erc20' && candidate.chainId === Number(packet.rpc.localChainId) &&
      candidate.address !== null && candidate.address.toLowerCase() === String(payment.asset_address).toLowerCase());
    const authFields = extra ? Object.entries(extra).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
      .map(([name, value]) => ({ name, value })).sort((left, right) => left.name.localeCompare(right.name)) : [];
    if (!requirements || !asset || typeof selectedX402?.x402_version !== 'string' || !selectedX402.x402_version ||
        typeof operation.selected_resource_id !== 'string' || typeof operation.selected_offer_id !== 'string' ||
        typeof requirements.scheme !== 'string' || typeof requirements.network !== 'string' ||
        typeof requirements.amount !== 'string' || typeof requirements.payTo !== 'string') { missingJoin = true; continue; }
    const tx = typeof payment.transaction_hash === 'string' ? payment.transaction_hash : undefined;
    const paymentId = String(payment.payment_id).toLowerCase();
    const effectStatus = effect?.verification;
    const status: PaymentObservation['status'] = payment.receipt_status !== 'success' ? 'rejected' :
      effectStatus === 'observed' || effectStatus === 'partial' ? 'settled' : 'unknown';
    const cost = costByOperation.get(operationId);
    const gasPayer = cost?.payer_role === 'participant' ? 'participant' as const : 'facilitator' as const;
    observations.payments.push({ kind: 'payment', ...meta(`paid-payment-${paymentId}`, actionSequence), paymentAttemptId: paymentId, status,
      requirements: { scheme: String(requirements.scheme), resourceId: operation.selected_resource_id, offerId: operation.selected_offer_id,
        version: selectedX402.x402_version, amountUnits: String(requirements.amount), network: String(requirements.network),
        assetId: asset.assetId, recipient: String(requirements.payTo), authFields }, gasPayer, ...(tx ? { transactionHash: tx } : {}) });
    paymentAttemptByOperation.set(operationId, payment);
    bump(actionSequence);
    if (status === 'unknown') observations.coverage.payments = 'incomplete';
    if (status === 'rejected') observations.coverage.payments = coverageStatus === 'contradictory' ? 'contradictory' : 'incomplete';

    const payer = typeof payment.payer_address === 'string' ? payment.payer_address.toLowerCase() : null;
    const facilitator = typeof payment.facilitator_address === 'string' ? payment.facilitator_address.toLowerCase() : null;
    const beforePayer = payment.payer_balance_before, afterPayer = payment.payer_balance_after;
    const beforeFacilitator = payment.facilitator_balance_before, afterFacilitator = payment.facilitator_balance_after;
    if (payer && beforePayer !== undefined && afterPayer !== undefined && facilitator && beforeFacilitator !== undefined && afterFacilitator !== undefined && tx) {
      observations.stateMutations.push({ kind: 'state_mutation', ...meta(`paid-state-payer-${paymentId}`, actionSequence),
        mutationType: 'balance', key: `${payer}:${asset.assetId}`, beforeValue: String(beforePayer), afterValue: String(afterPayer), transactionHash: tx });
      observations.stateMutations.push({ kind: 'state_mutation', ...meta(`paid-state-facilitator-${paymentId}`, actionSequence),
        mutationType: 'balance', key: `${facilitator}:${asset.assetId}`, beforeValue: String(beforeFacilitator), afterValue: String(afterFacilitator), transactionHash: tx });
    } else observations.coverage.stateMutations = 'incomplete';

    const transferRows = effect && Array.isArray(effect.decodedTransfers) ? effect.decodedTransfers.filter(isRecord) : [];
    if (effectStatus === 'observed' || effectStatus === 'partial') {
      for (const transfer of transferRows) {
        if (typeof transfer.from !== 'string' || typeof transfer.to !== 'string' || typeof transfer.assetId !== 'string' ||
            typeof transfer.amountUnits !== 'string' || typeof transfer.transactionHash !== 'string') { observations.coverage.transfers = 'incomplete'; continue; }
        const participant = payer;
        const to = transfer.to.toLowerCase(), from = transfer.from.toLowerCase();
        const settlement = from === participant && to === facilitator && String(transfer.assetId) === asset.assetId &&
          String(transfer.amountUnits) === String(payment.amount_units);
        observations.transfers.push({ kind: 'transfer', ...meta(`paid-transfer-${paymentId}-${String(transfer.logIndex ?? observations.transfers.length)}`, actionSequence),
          from: from === participant ? 'participant' : from, to: to === participant ? 'participant' : to, assetId: transfer.assetId,
          amountUnits: transfer.amountUnits, receiptStatus: 'success', transactionHash: transfer.transactionHash,
          operation: settlement ? 'settlement' : 'other', paymentAttemptId: paymentId });
        bump(actionSequence);
      }
    } else observations.coverage.transfers = effectStatus === 'contradictory' ? 'contradictory' : 'incomplete';

    if (cost && cost.payer_role === 'participant' && typeof cost.transaction_hash === 'string' && typeof cost.gas_used === 'string' &&
        typeof cost.effective_gas_price_wei === 'string' && typeof cost.receipt_status === 'string') {
      observations.expenses.push({ kind: 'expense', ...meta(`paid-expense-${operationId}`, actionSequence), component: 'participant_gas',
        sourceEffectId: `bef-operation:${operationId}`, gasUsed: cost.gas_used, effectiveGasPriceWei: cost.effective_gas_price_wei,
        receiptStatus: cost.receipt_status === 'success' ? 'success' : 'reverted', transactionHash: cost.transaction_hash });
      bump(actionSequence);
    }
  }
  const componentByResource = new Map(packet.manifest.componentReferences.map((component) => [component.resourceId, component.componentId]));
  const deliveryByOperation = new Map<string, Record<string, unknown>>();
  for (const delivery of deliveries) deliveryByOperation.set(String(delivery.operation_id).toLowerCase(), delivery);
  const emittedDeliveries = new Set<string>();
  for (const action of packet.ownerActions.filter((item) => item.actionKind === 'retrieve' && item.receiptStatus === 'observed')) {
    const operationId = String(action.befOperationId ?? '').toLowerCase(),delivery = deliveryByOperation.get(operationId),content = action.retrievedContent;
    if (!delivery || !content) { observations.coverage.deliveries = 'incomplete'; continue; }
    const componentId = componentByResource.get(content.resourceId),payment = paymentAttemptByOperation.get(operationId),response = context.actionResponses.get(action.actionId);
    if (!componentId || emittedDeliveries.has(String(delivery.delivery_id))) continue;
    if (!payment || typeof payment.transaction_hash !== 'string' || !response || typeof response.contentBytes !== 'string' ||
        !isRecord(response.content) || response.resourceId !== content.resourceId || response.contentType !== content.contentType ||
        response.contentHash !== content.contentSha256 || String(delivery.resource_id) !== content.resourceId ||
        String(delivery.content_sha256).toLowerCase() !== content.contentSha256 || String(delivery.byte_count) !== String(content.byteCount)) {
      observations.coverage.deliveries = 'incomplete';
      continue;
    }
    let bytes: Buffer; try { bytes = Buffer.from(response.contentBytes, 'base64'); } catch { observations.coverage.deliveries = 'contradictory'; continue; }
    if (!bytes.length || bytes.toString('base64') !== response.contentBytes || bytes.length !== content.byteCount ||
        createHash('sha256').update(bytes).digest('hex').toLowerCase() !== content.contentSha256.toLowerCase()) {
      observations.coverage.deliveries = 'contradictory'; continue;
    }
    let decoded: unknown; try { decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
    catch { observations.coverage.deliveries = 'contradictory'; continue; }
    if (!isRecord(decoded) || canonicalTaskJson(decoded) !== canonicalTaskJson(response.content)) { observations.coverage.deliveries = 'contradictory'; continue; }
    let payloadSchemaVersion = content.payloadSchemaVersion;
    let payload: Record<string, unknown> = { resourceId: content.resourceId, contentType: content.contentType,
      contentHash: content.contentSha256, contentBytes: response.contentBytes };
    if (context.taskCase.taskId === 'H3') {
      const component = context.taskCase.objective.referenceComponent;
      const referenceField = context.taskCase.objective.routeObjective.referenceField;
      const resource = packet.manifest.catalog.find((item) => item.resourceId === content.resourceId);
      const decodedContent = isRecord(decoded.content) ? decoded.content : null;
      const field = component.validator.requiredFields.find((item) => item.name === referenceField);
      const envelopeTypes = new Map([['resourceId', 'string'], ['contentType', 'string'], ['contentHash', 'sha256'], ['contentBytes', 'string']]);
      const requiredFields = component.validator.requiredFields;
      const envelopeMatches = component.validator.additionalProperties === false && requiredFields.length === 5 &&
        [...envelopeTypes].every(([name, type]) => requiredFields.some((item) => item.name === name && item.type === type)) &&
        requiredFields.some((item) => item.name === referenceField && item.type === 'string') &&
        new Set(requiredFields.map((item) => item.name)).size === 5;
      const routeValue = decodedContent?.[referenceField];
      if (component.resourceId !== content.resourceId || !resource || resource.schema !== content.resourceSchema ||
          resource.contentType !== content.contentType || String(resource.resourceSha256).toLowerCase() !== content.contentSha256.toLowerCase() ||
          decoded.resourceId !== content.resourceId || decoded.schema !== content.resourceSchema || !decodedContent || !field ||
          !envelopeMatches || typeof routeValue !== 'string' || Object.hasOwn(payload, referenceField)) {
        observations.coverage.deliveries = 'incomplete';
        continue;
      }
      payloadSchemaVersion = component.validator.payloadSchemaVersion;
      payload = { ...payload, [referenceField]: routeValue };
    }
    const payloadSha256 = sha256CanonicalTaskJson(payload).toLowerCase();
    const paymentId = payment ? String(payment.payment_id).toLowerCase() : undefined;
    observations.deliveries.push({ kind: 'data_delivery', ...meta(`paid-delivery-${String(delivery.delivery_id).toLowerCase()}`, action.actionSequence),
      componentId, resourceId: content.resourceId, sourceId: String(packet.manifest.catalog.find((resource) => resource.resourceId === content.resourceId)?.provenance &&
        (packet.manifest.catalog.find((resource) => resource.resourceId === content.resourceId)?.provenance as Record<string, unknown>).classification || 'unknown'),
      payloadSchemaVersion, payloadSha256, payload,
      transactionHash: String(payment?.transaction_hash ?? ''), ...(paymentId ? { paymentAttemptId: paymentId } : {}) });
    emittedDeliveries.add(String(delivery.delivery_id)); bump(action.actionSequence);
  }
  if (missingJoin) {
    for (const domain of ['payments','transfers','stateMutations','expenses'] as const)
      if (observations.coverage[domain] !== 'contradictory') observations.coverage[domain] = 'incomplete';
  }
  if (packet.binding.taskId === 'H3' || packet.binding.taskId === 'U1') {
    observations.coverage.trades = 'incomplete'; observations.coverage.conversions = 'incomplete';
  }
  const candidate: TaskObservationBundleCandidate = { schemaVersion: 'bts-task-observation-bundle-candidate/v1',
    observationCutoffSequence: observations.coveredThroughSequence, cutoffStatus: 'authoritative', cutoffEvidence: context.captureEvidence, observations };
  // Keep the paid child boundary intact; the composite caller may later use the maximum child sequence.
  void paidCandidate;
  return candidate;
}
