import { createHash } from 'node:crypto';
import { TaskActionCommandSchema } from './task-action-service.js';
import {
  canonicalTaskJson,
  type EvidenceReference,
  type TaskCase,
} from './task-release.js';
import type {
  AllowanceChangeObservation,
  AllowanceUseObservation,
  ConversionObservation,
  ExpenseObservation,
  PersistedTaskObservations,
  TaskEvidenceBinding,
  TradeObservation,
  TransferObservation,
} from './task-evaluator.js';

export type ChainTaskId = 'M3' | 'M4' | 'H2' | 'H3' | 'U1';
export type ChainTaskCase = Extract<TaskCase, { taskId: ChainTaskId }>;
export type ChainJson = Record<string, unknown>;
export type ChainEvidenceRef = EvidenceReference;

const HASH = /^[0-9a-f]{64}$/i;
const TX = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/';
const ACTION_PREFIX = ROOT + 'action/';
const PREPARATION_PREFIX = ROOT + 'preparation/';
const CAPTURE_PREFIX = ROOT + 'observation/';
const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const MAX_PACKET_BYTES = 8 * 1024 * 1024;
const MAX_ROWS = 2048;
const MAX_ACTIONS = 256;
const ZERO = '0x0000000000000000000000000000000000000000';
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const APPROVAL_TOPIC = '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925';
const SWAP_TOPIC = '0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67';
const DEPOSIT_TOPIC = '0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c';
const WITHDRAWAL_TOPIC = '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65';
const SECRET_KEYS = new Set([
  'privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer', 'bearertoken',
  'accesstoken', 'refreshtoken', 'providertoken', 'paymenttoken', 'token', 'apitoken', 'apikey',
  'authorization', 'walletmaterial', 'walletsecret', 'signature', 'signedpayload', 'password',
  'credential', 'connectionstring', 'databaseurl', 'dsn',
]);

export type ChainCaptureAction = {
  actionId: string;
  actionSequence: number;
  ownerOperationId: string;
  actionKind: 'approve' | 'transfer' | 'wrap' | 'unwrap' | 'swap';
  commandSha256: string;
  command: ChainJson;
  selectedAction: ChainJson;
  approvalSpender: string | null;
  actionEvidence: EvidenceReference;
  befOperationId: string;
  transactionHash: string;
};

/** Paid-task owner actions are bound here but are graded only by the paid-data child candidate. */
export type ChainCaptureExternalAction = {
  actionId: string;
  actionSequence: number;
  ownerOperationId: string;
  actionKind: 'inspect_catalog' | 'inspect_offer' | 'purchase' | 'pay' | 'retrieve';
  commandSha256: string;
  receiptStatus: 'observed' | 'rejected_before_execution';
  actionEvidence: EvidenceReference;
  befOperationId: string | null;
  transactionHash: string | null;
  inspection?: { command: ChainJson; rawResponseSha256: string };
};

export type ChainCaptureTransaction = {
  hash: string;
  from: string;
  to: string | null;
  nonce: string;
  input: string | null;
  inputSha256: string;
  receiptLogsSha256: string;
  valueWei: string;
  gasLimit: string;
  blockNumber: string;
  blockHash: string;
  transactionIndex: string;
  chainId: string;
  status: 'success' | 'reverted';
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  logs: ChainJson[];
};

export type ChainCaptureBlock = {
  number: string;
  hash: string;
  parentHash: string;
  transactionCount: number;
  participantTransactions: string[];
  externalTransactions: string[];
};

export type ChainCheckpoint = {
  blockNumber: string;
  blockHash: string;
  parentHash: string;
  balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
  participantTransactionCount: string;
};

export type ChainCapturePacket = {
  schemaVersion: 'bts-chain-task-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  taskId: ChainTaskId;
  binding: TaskEvidenceBinding;
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number };
  execution: {
    preparationId: string; leaseId: string; generationId: string; environmentId: string;
    environmentManifestHash: string; applicationSourceHash: string; executionIdentityHash: string; initialStateSha256: string;
  };
  preparation: {
    fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference;
    baselineBlockNumber: string; baselineBlockHash: string;
  };
  ownerActions: ChainCaptureAction[];
  externalActions: ChainCaptureExternalAction[];
  bef: {
    session: ChainJson;
    before: ChainJson;
    after: ChainJson;
    censusSha256: string;
  };
  rpc: {
    localChainId: string;
    participant: string;
    assets: Array<{ assetId: string; kind: 'native' | 'erc20'; address: string | null; codeHash: string | null }>;
    contracts: Array<{ contractId: string; address: string; codeHash: string }>;
    routes: Array<{ routeId: string; tokenInAssetId: string; tokenOutAssetId: string; router: string; pool: string; tokenIn: string; tokenOut: string; feeTier: number }>;
    identityCodeHashes: Array<{ address: string; expectedCodeHash: string; observedCodeHash: string }>;
    baseline: ChainCheckpoint;
    final: ChainCheckpoint;
    intervalBlocks: ChainCaptureBlock[];
    transactions: ChainCaptureTransaction[];
    transferLogs: ChainJson[];
    approvalLogs: ChainJson[];
    swapLogs: ChainJson[];
    wethLogs: ChainJson[];
    responseHashes: Array<{ method: string; paramsSha256: string; resultSha256: string }>;
  };
};

export type ChainCaptureBundleView = {
  binding: TaskEvidenceBinding;
  closure: { closureId: string; actionCutoffSequence: number; reconciledActionSequence: number };
  execution: ChainCapturePacket['execution'];
  observations: Record<string, unknown>;
  taskCase: ChainTaskCase;
  ethValuation: { numerator: string; denominator: string };
};

export class ChainCapturePacketError extends Error {
  constructor(readonly code: 'packet_invalid' | 'packet_too_large' | 'binding_mismatch' | 'child_reference_invalid') {
    super(code);
    this.name = 'ChainCapturePacketError';
  }
}

function fail(code: ChainCapturePacketError['code']): never { throw new ChainCapturePacketError(code); }
function isRecord(value: unknown): value is ChainJson {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null));
}
function exactKeys(value: ChainJson, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join('\u0000') === [...keys].sort().join('\u0000');
}
function same(left: unknown, right: unknown): boolean { return canonicalTaskJson(left) === canonicalTaskJson(right); }
function normAddress(value: unknown): string | null { return typeof value === 'string' && ADDRESS.test(value) ? value.toLowerCase() : null; }
function normTx(value: unknown): string | null { return typeof value === 'string' && TX.test(value) ? value.toLowerCase() : null; }
function validRef(value: unknown, prefix: string): value is EvidenceReference {
  return isRecord(value) && exactKeys(value, ['path', 'sha256', 'boundary']) && value.boundary === BOUNDARY &&
    typeof value.path === 'string' && value.path.startsWith(prefix) && value.path.length <= 512 &&
    /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/.test(value.path) &&
    !value.path.includes('\\') && !value.path.includes('\0') &&
    value.path.split('/').every((part) => part !== '' && part !== '.' && part !== '..') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256);
}
function scanSecrets(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') return false;
  if (typeof value !== 'object' || ancestors.has(value)) return true;
  ancestors.add(value);
  const entries = Array.isArray(value) ? value.map((item, index) => [String(index), item] as const) : Object.entries(value);
  for (const [key, child] of entries) {
    if (SECRET_KEYS.has(key.toLowerCase().replace(/[^a-z]/g, '')) || scanSecrets(child, ancestors)) {
      ancestors.delete(value);
      return true;
    }
  }
  ancestors.delete(value);
  return false;
}
function requireRecord(value: unknown, keys: readonly string[]): ChainJson {
  if (!isRecord(value) || !exactKeys(value, keys)) fail('packet_invalid');
  return value;
}
function uint(value: unknown): value is string { return typeof value === 'string' && UINT.test(value); }
function dec(value: unknown): value is string { return typeof value === 'string' && DECIMAL.test(value); }
function hexQuantity(value: unknown): bigint | null {
  return typeof value === 'string' && /^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value) ? BigInt(value) : null;
}
function eventAddress(topic: unknown): string | null {
  if (typeof topic !== 'string' || !/^0x[0-9a-f]{64}$/i.test(topic)) return null;
  return '0x' + topic.slice(-40).toLowerCase();
}
function eventWord(value: unknown): bigint | null {
  return typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value) ? BigInt(value) : null;
}
function logTopics(log: ChainJson): string[] { return log.topics as string[]; }
function validateLog(value: unknown): ChainJson {
  const log = requireRecord(value, ['address', 'topics', 'data', 'blockNumber', 'blockHash', 'transactionHash', 'transactionIndex', 'logIndex',
    'removed', 'rpcBlockNumber', 'rpcTransactionIndex', 'rpcLogIndex']);
  const block = hexQuantity(log.rpcBlockNumber);
  const txIndex = hexQuantity(log.rpcTransactionIndex);
  const logIndex = hexQuantity(log.rpcLogIndex);
  if (!normAddress(log.address) || !Array.isArray(log.topics) || log.topics.length < 1 || log.topics.length > 4 ||
      log.topics.some((topic) => typeof topic !== 'string' || !/^0x[0-9a-f]{64}$/i.test(topic)) ||
      typeof log.data !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(log.data) ||
      !dec(log.blockNumber) || !normTx(log.blockHash) || !normTx(log.transactionHash) ||
      !dec(log.transactionIndex) || !dec(log.logIndex) || block?.toString() !== log.blockNumber ||
      txIndex?.toString() !== log.transactionIndex || logIndex?.toString() !== log.logIndex || log.removed !== false) fail('packet_invalid');
  return { ...log, address: normAddress(log.address), blockHash: normTx(log.blockHash),
    transactionHash: normTx(log.transactionHash), topics: log.topics.map((topic) => String(topic).toLowerCase()), data: log.data.toLowerCase() };
}
function word(value: bigint): string { return value.toString(16).padStart(64, '0'); }
function addressWord(value: string): string { return value.slice(2).toLowerCase().padStart(64, '0'); }
function validCommand(action:ChainCaptureAction):boolean{
 const command=action.command;
 if(command.kind!==action.actionKind)return false;
 if(action.actionKind==='approve')return exactKeys(command,['kind','tokenAssetId','amountUnits','gasLimit'])&&
  typeof command.tokenAssetId==='string'&&typeof command.amountUnits==='string'&&uint(command.amountUnits)&&typeof command.gasLimit==='string'&&uint(command.gasLimit);
 if(action.actionKind==='transfer')return exactKeys(command,['kind','amountUnits','recipient','gasLimit'])&&
  typeof command.amountUnits==='string'&&uint(command.amountUnits)&&normAddress(command.recipient)!==null&&typeof command.gasLimit==='string'&&uint(command.gasLimit);
 if(action.actionKind==='wrap'||action.actionKind==='unwrap')return exactKeys(command,['kind','amountWei','gasLimit'])&&
  typeof command.amountWei==='string'&&uint(command.amountWei)&&typeof command.gasLimit==='string'&&uint(command.gasLimit);
 const keys=Object.hasOwn(command,'feeTier')?['kind','inputAssetId','outputAssetId','feeTier','amountInUnits','amountOutMinimumUnits','recipient','gasLimit']:
  ['kind','inputAssetId','outputAssetId','amountInUnits','amountOutMinimumUnits','recipient','gasLimit'];
 return exactKeys(command,keys)&&typeof command.amountInUnits==='string'&&uint(command.amountInUnits)&&
  typeof command.amountOutMinimumUnits==='string'&&uint(command.amountOutMinimumUnits)&&normAddress(command.recipient)!==null&&
  typeof command.gasLimit==='string'&&uint(command.gasLimit)&&(!Object.hasOwn(command,'feeTier')||Number(command.feeTier)===500||Number(command.feeTier)===3000);
}
function selectedActionMatchesCommand(action:ChainCaptureAction):boolean{
 const command=action.command;
 if(action.actionKind==='approve')return same(action.selectedAction,{kind:'approve',tokenAssetId:command.tokenAssetId,amountUnits:command.amountUnits,gasLimit:command.gasLimit});
 if(action.actionKind==='transfer')return same(action.selectedAction,{kind:'transfer',amountUnits:command.amountUnits,
  recipient:String(command.recipient).toLowerCase(),gasLimit:command.gasLimit});
 if(action.actionKind==='wrap'||action.actionKind==='unwrap')return same(action.selectedAction,{kind:action.actionKind,amountWei:command.amountWei,gasLimit:command.gasLimit});
 return same(action.selectedAction,{kind:'swap',inputAssetId:command.inputAssetId,outputAssetId:command.outputAssetId,feeTier:Number(command.feeTier??500),
  amountInUnits:command.amountInUnits,amountOutMinimumUnits:command.amountOutMinimumUnits,recipient:String(command.recipient).toLowerCase(),gasLimit:command.gasLimit});
}
function commandTransactionMatches(packet: ChainCapturePacket, action: ChainCaptureAction, tx: ChainCaptureTransaction, taskCase?: ChainTaskCase): boolean {
  const command = action.command;
  if (typeof tx.input !== 'string' || !validCommand(action) || !selectedActionMatchesCommand(action) || command.kind !== action.actionKind || String(command.gasLimit) !== tx.gasLimit) return false;
  if (action.actionKind === 'approve') {
    const tokenAssetId = String(command.tokenAssetId ?? 'WETH');
    const token = packet.rpc.assets.find((asset) => asset.assetId === tokenAssetId);
    const amount = uint(command.amountUnits) ? BigInt(command.amountUnits) : null;
    const spender = tx.input.startsWith('0x095ea7b3') && tx.input.length === 138 ? '0x' + tx.input.slice(34, 74).toLowerCase() : null;
    const scoped = Boolean(spender && taskCase?.taskId === 'U1' && taskCase.objective.temporarySpenderScope.some((item) => item.owner === 'participant' &&
      item.tokenAssetId === tokenAssetId && item.spender.toLowerCase() === spender));
    return Boolean(token?.address && amount !== null && tx.to === token.address.toLowerCase() && tx.valueWei === '0' && spender &&
      (packet.rpc.routes.some((route) => route.tokenInAssetId === tokenAssetId && route.router === spender) || scoped) &&
      action.approvalSpender === spender &&
      tx.input === `0x095ea7b3${addressWord(spender)}${word(amount)}`);
  }
  if (action.actionKind === 'transfer') {
    const amount = uint(command.amountUnits) ? BigInt(command.amountUnits) : null;
    const recipient = normAddress(command.recipient);
    const token = packet.rpc.assets.find((asset) => asset.address?.toLowerCase() === tx.to?.toLowerCase());
    return Boolean(token && amount !== null && recipient && tx.valueWei === '0' && token.assetId === 'USDC' &&
      tx.input === `0xa9059cbb${addressWord(recipient)}${word(amount)}`);
  }
  if (action.actionKind === 'wrap' || action.actionKind === 'unwrap') {
    const weth = packet.rpc.assets.find((asset) => asset.assetId === 'WETH');
    const amount = uint(command.amountWei) ? BigInt(command.amountWei) : null;
    return Boolean(weth?.address && amount !== null && tx.to === weth.address.toLowerCase() &&
      (action.actionKind === 'wrap' ? tx.input === '0xd0e30db0' && tx.valueWei === amount.toString()
        : tx.input === `0x2e1a7d4d${word(amount)}` && tx.valueWei === '0'));
  }
  const route = packet.rpc.routes.find((candidate) => candidate.tokenInAssetId === command.inputAssetId &&
    candidate.tokenOutAssetId === command.outputAssetId && candidate.feeTier === Number(command.feeTier ?? 500));
  const amountIn = uint(command.amountInUnits) ? BigInt(command.amountInUnits) : null;
  const minimum = uint(command.amountOutMinimumUnits) ? BigInt(command.amountOutMinimumUnits) : null;
  const recipient = normAddress(command.recipient);
  if (!route || amountIn === null || minimum === null || !recipient) return false;
  const expected = `0x04e45aaf${addressWord(route.tokenIn)}${addressWord(route.tokenOut)}${word(BigInt(route.feeTier))}` +
    `${addressWord(recipient)}${word(amountIn)}${word(minimum)}${word(0n)}`;
  return tx.to === route.router && tx.valueWei === '0' && tx.input === expected;
}
function expectedPrincipal(action:ChainCaptureAction):{asset:string|null;units:string}{
 const command=action.command;
 if(action.actionKind==='approve')return {asset:null,units:'0'};
 if(action.actionKind==='transfer')return {asset:'USDC',units:String(command.amountUnits)};
 if(action.actionKind==='wrap'||action.actionKind==='unwrap')return {asset:action.actionKind==='wrap'?'ETH':'WETH',units:String(command.amountWei)};
 return {asset:String(command.inputAssetId),units:String(command.amountInUnits)};
}
function validateCheckpoint(value: unknown): ChainCheckpoint {
  const checkpoint = requireRecord(value, ['blockNumber', 'blockHash', 'parentHash', 'balances', 'allowances', 'participantTransactionCount']);
  if (!dec(checkpoint.blockNumber) || !normTx(checkpoint.blockHash) || !normTx(checkpoint.parentHash) ||
      !dec(checkpoint.participantTransactionCount) || !Array.isArray(checkpoint.balances) || !Array.isArray(checkpoint.allowances) ||
      checkpoint.balances.length > MAX_ROWS || checkpoint.allowances.length > MAX_ROWS) fail('packet_invalid');
  const balances = checkpoint.balances.map((entry) => {
    const row = requireRecord(entry, ['account', 'assetId', 'amountUnits']);
    if (typeof row.account !== 'string' || (!ADDRESS.test(row.account) && row.account !== 'participant') ||
        typeof row.assetId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(row.assetId) || !uint(row.amountUnits)) fail('packet_invalid');
    return row;
  });
  const allowances = checkpoint.allowances.map((entry) => {
    const row = requireRecord(entry, ['owner', 'tokenAssetId', 'spender', 'amountUnits']);
    if ((row.owner !== 'participant' && !normAddress(row.owner)) || typeof row.tokenAssetId !== 'string' ||
        !normAddress(row.spender) || !uint(row.amountUnits)) fail('packet_invalid');
    return row;
  });
  return { ...checkpoint, blockHash: normTx(checkpoint.blockHash)!, parentHash: normTx(checkpoint.parentHash)!, balances, allowances } as ChainCheckpoint;
}
function validateCensus(value: unknown, taskId: ChainTaskId): ChainJson {
  const census = requireRecord(value, ['generation', 'operations', 'externalPaymentOperations', 'selectedExecutions', 'selectedEvents', 'costs',
    'paymentsCount', 'deliveriesCount', 'counts', ...(!['H3','U1'].includes(taskId)?['inspectionOperations']:[])]);
  const generation = requireRecord(census.generation, ['generation_id', 'env_id', 'participant_id', 'payer_address', 'manifest_sha256',
    'status', 'chain_id', 'environment_manifest_sha256']);
  if (typeof generation.generation_id !== 'string' || typeof generation.env_id !== 'string' || typeof generation.participant_id !== 'string' ||
      !normAddress(generation.payer_address) || !HASH.test(String(generation.manifest_sha256)) || generation.status !== 'active' ||
      !dec(generation.chain_id) || !HASH.test(String(generation.environment_manifest_sha256)) ||
      !Array.isArray(census.operations) || !Array.isArray(census.externalPaymentOperations) || !Array.isArray(census.selectedExecutions) ||
      !Array.isArray(census.selectedEvents) || !Array.isArray(census.costs) ||
      [census.operations, census.externalPaymentOperations, census.selectedExecutions, census.selectedEvents, census.costs].some((rows) => rows.length > MAX_ROWS) ||
      !dec(census.paymentsCount) || !dec(census.deliveriesCount) ||
      (!['H3', 'U1'].includes(taskId) && (census.paymentsCount !== '0' || census.deliveriesCount !== '0'))) fail('packet_invalid');
  const counts = requireRecord(census.counts, ['operations', 'externalPaymentOperations', 'selectedExecutions', 'selectedEvents', 'costs']);
  if (!['H3','U1'].includes(taskId) && (!Array.isArray(census.inspectionOperations) || census.inspectionOperations.length > MAX_ACTIONS)) fail('packet_invalid');
  if (counts.operations !== String(census.operations.length) || counts.selectedExecutions !== String(census.selectedExecutions.length) ||
      counts.externalPaymentOperations !== String(census.externalPaymentOperations.length) ||
      counts.selectedEvents !== String(census.selectedEvents.length) || counts.costs !== String(census.costs.length)) fail('packet_invalid');
  const operations = new Map<string, ChainJson>();
  for (const item of census.operations) {
    const op = requireRecord(item, ['operationId', 'environmentId', 'generationId', 'participantId', 'idempotencyKeySha256',
      'requestSha256', 'actionKind', 'status', 'receiptStatus', 'transactionHash', 'responseSha256', 'startedAt', 'completedAt']);
    const id = String(op.operationId);
    if (!/^[0-9a-f-]{36}$/i.test(id) || operations.has(id) || op.environmentId !== generation.env_id ||
        op.generationId !== generation.generation_id || op.participantId !== generation.participant_id ||
        !HASH.test(String(op.idempotencyKeySha256)) || !HASH.test(String(op.requestSha256)) ||
        !['approve', 'transfer', 'wrap', 'unwrap', 'swap'].includes(String(op.actionKind)) ||
        !['settled', 'delivered', 'reverted'].includes(String(op.status)) || !['success', 'reverted'].includes(String(op.receiptStatus)) ||
        !normTx(op.transactionHash) || (op.responseSha256 !== null && !HASH.test(String(op.responseSha256))) ||
        typeof op.startedAt !== 'string' || typeof op.completedAt !== 'string') fail('packet_invalid');
    operations.set(id, op);
  }
  const paymentOperationIds = new Set<string>();
  for (const item of census.externalPaymentOperations) {
    const op = requireRecord(item, ['operationId', 'status', 'receiptStatus', 'transactionHash']);
    const id = String(op.operationId);
    if (!['H3', 'U1'].includes(taskId) || !/^[0-9a-f-]{36}$/i.test(id) || paymentOperationIds.has(id) || operations.has(id) ||
        !['settled', 'delivered', 'reverted'].includes(String(op.status)) || !['success', 'reverted'].includes(String(op.receiptStatus)) ||
        !normTx(op.transactionHash)) fail('packet_invalid');
    paymentOperationIds.add(id);
  }
  const selected = new Map<string, ChainJson>();
  for (const item of census.selectedExecutions) {
    const row = requireRecord(item, ['operationId', 'environmentId', 'generationId', 'actionKind', 'selectedAction', 'prestate',
      'transactionIntent', 'measurement', 'transactionHash', 'outcome', 'reasonCode', 'completedAt']);
    const measurement = requireRecord(row.measurement, ['measurementSha256', 'receipt']);
    const receipt = requireRecord(measurement.receipt, ['transactionHash', 'status', 'gasUsed', 'effectiveGasPriceWei', 'gasCostWei']);
    const id = String(row.operationId);
    if (!operations.has(id) || selected.has(id) || row.environmentId !== generation.env_id || row.generationId !== generation.generation_id ||
        !['approve', 'transfer', 'wrap', 'unwrap', 'swap'].includes(String(row.actionKind)) || !isRecord(row.selectedAction) ||
        !isRecord(row.prestate) || !isRecord(row.transactionIntent) || !normTx(row.transactionHash) ||
        !HASH.test(String(measurement.measurementSha256)) || !normTx(receipt.transactionHash) ||
        !['success', 'reverted'].includes(String(receipt.status)) || !uint(receipt.gasUsed) ||
        !uint(receipt.effectiveGasPriceWei) || !uint(receipt.gasCostWei) ||
        BigInt(String(receipt.gasUsed)) * BigInt(String(receipt.effectiveGasPriceWei)) !== BigInt(String(receipt.gasCostWei)) ||
        receipt.transactionHash !== row.transactionHash || receipt.status !== row.outcome ||
        !['success', 'reverted'].includes(String(row.outcome)) || (row.reasonCode !== null && typeof row.reasonCode !== 'string') ||
        typeof row.completedAt !== 'string') fail('packet_invalid');
    selected.set(id, row);
  }
  const eventKinds = new Map<string, ChainJson[]>();
  const eventIds = new Set<string>();
  const eventSequences = new Set<string>();
  for (const item of census.selectedEvents) {
    const event = requireRecord(item, ['eventId', 'eventSequence', 'operationId', 'eventKind', 'eventJsonSha256', 'transactionHash', 'eventPayload']);
    const id = String(event.operationId);
    if (!operations.has(id) || !/^[0-9a-f-]{36}$/i.test(String(event.eventId)) || eventIds.has(String(event.eventId)) ||
        !dec(event.eventSequence) || eventSequences.has(String(event.eventSequence)) ||
        !['selected_action_bound', 'prestate_observed', 'original_tx_hash_bound', 'receipt_finalized'].includes(String(event.eventKind)) ||
        !HASH.test(String(event.eventJsonSha256)) || (event.transactionHash !== null && !normTx(event.transactionHash)) ||
        !isRecord(event.eventPayload)) fail('packet_invalid');
    eventIds.add(String(event.eventId));
    eventSequences.add(String(event.eventSequence));
    const list = eventKinds.get(id) ?? [];
    list.push(event);
    eventKinds.set(id, list);
  }
  const costs = new Map<string, ChainJson>();
  for (const item of census.costs) {
    const row = requireRecord(item, ['operationId', 'environmentId', 'generationId', 'transactionHash', 'payerAddress', 'payerRole',
      'receiptStatus', 'transactionFrom', 'receiptFrom', 'receiptBlockNumber', 'receiptBlockHash', 'receiptBlockParentHash',
      'gasUsed', 'effectiveGasPriceWei', 'gasCostWei', 'modeledGasFeeUsdcUnits', 'manifestSha256',
      'selectedPrincipalAsset', 'selectedPrincipalUnits', 'observedPrincipalUnits']);
    const id = String(row.operationId);
    if (!operations.has(id) || costs.has(id) || row.environmentId !== generation.env_id || row.generationId !== generation.generation_id ||
        !normTx(row.transactionHash) || !normAddress(row.payerAddress) || !['participant', 'facilitator'].includes(String(row.payerRole)) ||
        !['success', 'reverted'].includes(String(row.receiptStatus)) || !normAddress(row.transactionFrom) || !normAddress(row.receiptFrom) ||
        !dec(row.receiptBlockNumber) || !normTx(row.receiptBlockHash) || !normTx(row.receiptBlockParentHash) ||
        !uint(row.gasUsed) || !uint(row.effectiveGasPriceWei) || !uint(row.gasCostWei) ||
        BigInt(row.gasUsed) * BigInt(row.effectiveGasPriceWei) !== BigInt(row.gasCostWei) ||
        !uint(row.modeledGasFeeUsdcUnits) || !HASH.test(String(row.manifestSha256)) ||
        (row.selectedPrincipalAsset !== null && typeof row.selectedPrincipalAsset !== 'string') ||
        (row.selectedPrincipalUnits !== null && !uint(row.selectedPrincipalUnits)) ||
        (row.observedPrincipalUnits !== null && !uint(row.observedPrincipalUnits))) fail('packet_invalid');
    costs.set(id, row);
  }
  for (const [id, op] of operations) {
    const execution = selected.get(id);
    const events = (eventKinds.get(id) ?? []).sort((left, right) => BigInt(String(left.eventSequence)) < BigInt(String(right.eventSequence)) ? -1 :
      BigInt(String(left.eventSequence)) > BigInt(String(right.eventSequence)) ? 1 : 0);
    const cost = costs.get(id);
    const measurementReceipt = execution && isRecord(execution.measurement) && isRecord(execution.measurement.receipt)
      ? execution.measurement.receipt : null;
    if (!execution || !cost || events.length !== 4 ||
        events.map((event) => event.eventKind).join(',') !== 'selected_action_bound,prestate_observed,original_tx_hash_bound,receipt_finalized' ||
        execution.actionKind !== op.actionKind || execution.transactionHash !== op.transactionHash ||
        execution.outcome !== (op.receiptStatus === 'success' ? 'success' : 'reverted') ||
        cost.transactionHash !== op.transactionHash || cost.receiptStatus !== op.receiptStatus ||
        !measurementReceipt || measurementReceipt.transactionHash !== op.transactionHash ||
        measurementReceipt.status !== op.receiptStatus || measurementReceipt.gasUsed !== cost.gasUsed ||
        measurementReceipt.effectiveGasPriceWei !== cost.effectiveGasPriceWei ||
        measurementReceipt.gasCostWei !== cost.gasCostWei) fail('packet_invalid');
    const payload = events.map((event) => event.eventPayload as ChainJson);
    const measurement = execution.measurement as ChainJson;
    if (!exactKeys(payload[0]!, ['actionKind', 'requestSha256', 'selectedAction']) || payload[0]!.actionKind !== op.actionKind ||
        payload[0]!.requestSha256 !== op.requestSha256 || !same(payload[0]!.selectedAction, execution.selectedAction) ||
        !exactKeys(payload[1]!, ['prestate']) || !same(payload[1]!.prestate, execution.prestate) ||
        !exactKeys(payload[2]!, ['requestSha256', 'transactionHash', 'transactionIntent']) || payload[2]!.requestSha256 !== op.requestSha256 ||
        payload[2]!.transactionHash !== op.transactionHash || !same(payload[2]!.transactionIntent, execution.transactionIntent) ||
        !exactKeys(payload[3]!, ['outcome', 'measurementSha256']) || payload[3]!.outcome !== execution.outcome ||
        payload[3]!.measurementSha256 !== measurement.measurementSha256) fail('packet_invalid');
  }
  if (selected.size !== operations.size || costs.size !== operations.size) fail('packet_invalid');
  void taskId;
  return census;
}

function validatePacket(value: unknown, taskCase?: ChainTaskCase): ChainCapturePacket {
  const packet = requireRecord(value, ['schemaVersion', 'classification', 'taskId', 'binding', 'closure', 'execution', 'preparation',
    'ownerActions', 'externalActions', 'bef', 'rpc']);
  if (packet.schemaVersion !== 'bts-chain-task-observation-capture/v1' ||
      packet.classification !== 'run_bound_observations_candidate_not_grade' ||
      !['M3', 'M4', 'H2', 'H3', 'U1'].includes(String(packet.taskId)) || scanSecrets(packet)) fail('packet_invalid');
  const taskId = packet.taskId as ChainTaskId;
  const binding = requireRecord(packet.binding, ['ownerId', 'agentId', 'runId', 'environmentId', 'releaseIdentity', 'manifestHash',
    'caseId', 'caseHash', 'rubricHash', 'taskId']);
  if (!/^[0-9a-f-]{36}$/i.test(String(binding.ownerId)) || !/^[0-9a-f-]{36}$/i.test(String(binding.agentId)) ||
      !/^[0-9a-f-]{36}$/i.test(String(binding.runId)) || binding.taskId !== taskId ||
      typeof binding.environmentId !== 'string' || typeof binding.releaseIdentity !== 'string' ||
      !HASH.test(String(binding.manifestHash)) || typeof binding.caseId !== 'string' ||
      !HASH.test(String(binding.caseHash)) || !HASH.test(String(binding.rubricHash))) fail('packet_invalid');
  const closure = requireRecord(packet.closure, ['closureId', 'actionCutoffSequence', 'reconciledActionSequence']);
  if (!/^[0-9a-f-]{36}$/i.test(String(closure.closureId)) || !Number.isSafeInteger(closure.actionCutoffSequence) ||
      !Number.isSafeInteger(closure.reconciledActionSequence) || (closure.actionCutoffSequence as number) < 0 ||
      (closure.reconciledActionSequence as number) < (closure.actionCutoffSequence as number) ||
      (closure.actionCutoffSequence as number) > MAX_ACTIONS) fail('packet_invalid');
  const execution = requireRecord(packet.execution, ['preparationId', 'leaseId', 'generationId', 'environmentId',
    'environmentManifestHash', 'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']);
  if (!/^[0-9a-f-]{36}$/i.test(String(execution.preparationId)) || !/^[0-9a-f-]{36}$/i.test(String(execution.leaseId)) ||
      !/^[0-9a-f-]{36}$/i.test(String(execution.generationId)) || execution.environmentId !== binding.environmentId ||
      !HASH.test(String(execution.environmentManifestHash)) || !HASH.test(String(execution.applicationSourceHash)) ||
      !HASH.test(String(execution.executionIdentityHash)) || !HASH.test(String(execution.initialStateSha256))) fail('packet_invalid');
  const preparation = requireRecord(packet.preparation, ['fixtureEvidence', 'baselineEvidence', 'baselineBlockNumber', 'baselineBlockHash']);
  if (!validRef(preparation.fixtureEvidence, PREPARATION_PREFIX) || !validRef(preparation.baselineEvidence, PREPARATION_PREFIX) ||
      preparation.fixtureEvidence.path === preparation.baselineEvidence.path || !dec(preparation.baselineBlockNumber) ||
      !normTx(preparation.baselineBlockHash)) fail('packet_invalid');
  if (!Array.isArray(packet.ownerActions) || !Array.isArray(packet.externalActions) ||
      packet.ownerActions.length + packet.externalActions.length !== closure.actionCutoffSequence ||
      packet.ownerActions.length + packet.externalActions.length > MAX_ACTIONS) fail('packet_invalid');
  const actionIds = new Set<string>();
  const ownerOps = new Set<string>();
  const befOps = new Set<string>();
  const sequences = new Set<number>();
  for (const item of packet.ownerActions) {
    const action = requireRecord(item, ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind',
      'commandSha256', 'command', 'selectedAction', 'approvalSpender', 'actionEvidence', 'befOperationId', 'transactionHash']);
    if (!/^[0-9a-f-]{36}$/i.test(String(action.actionId)) || !Number.isSafeInteger(action.actionSequence) ||
        (action.actionSequence as number) < 1 || (action.actionSequence as number) > closure.actionCutoffSequence ||
        !/^[A-Za-z0-9_-]{12,128}$/.test(String(action.ownerOperationId)) ||
        !['approve', 'transfer', 'wrap', 'unwrap', 'swap'].includes(String(action.actionKind)) ||
        !HASH.test(String(action.commandSha256)) || !isRecord(action.command) || !isRecord(action.selectedAction) ||
        (action.actionKind === 'approve' ? !normAddress(action.approvalSpender) : action.approvalSpender !== null) ||
        action.command.kind !== action.actionKind || !validRef(action.actionEvidence, ACTION_PREFIX) ||
        !/^[0-9a-f-]{36}$/i.test(String(action.befOperationId)) || !normTx(action.transactionHash) ||
        actionIds.has(String(action.actionId)) || ownerOps.has(String(action.ownerOperationId)) || befOps.has(String(action.befOperationId))) fail('packet_invalid');
    actionIds.add(String(action.actionId));
    ownerOps.add(String(action.ownerOperationId));
    befOps.add(String(action.befOperationId));
    sequences.add(action.actionSequence as number);
  }
  for (const item of packet.externalActions) {
    const action = requireRecord(item, ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256', 'receiptStatus',
      'actionEvidence', 'befOperationId', 'transactionHash', ...(!['H3','U1'].includes(taskId)?['inspection']:[])]);
    const kind = String(action.actionKind);
    const tx = action.transactionHash === null ? null : normTx(action.transactionHash);
    const befId = action.befOperationId === null ? null : String(action.befOperationId);
    if (!/^[0-9a-f-]{36}$/i.test(String(action.actionId)) || !Number.isSafeInteger(action.actionSequence) ||
        (action.actionSequence as number) < 1 || (action.actionSequence as number) > closure.actionCutoffSequence ||
        !/^[A-Za-z0-9_-]{12,128}$/.test(String(action.ownerOperationId)) ||
        !['inspect_catalog', 'inspect_offer', 'purchase', 'pay', 'retrieve'].includes(kind) ||
        (!['H3', 'U1'].includes(taskId) && (!['inspect_catalog', 'inspect_offer'].includes(kind) || action.receiptStatus !== 'observed')) ||
        !HASH.test(String(action.commandSha256)) || !validRef(action.actionEvidence, ACTION_PREFIX) ||
        !['observed', 'rejected_before_execution'].includes(String(action.receiptStatus)) ||
        (befId !== null && !/^[0-9a-f-]{36}$/i.test(befId)) ||
        (kind === 'pay' && action.receiptStatus === 'observed' && (!tx || !befId)) ||
        (!['pay', 'purchase'].includes(kind) && tx !== null) ||
        (['pay', 'purchase'].includes(kind) && tx !== null && !befId) || (action.transactionHash !== null && !tx) ||
        actionIds.has(String(action.actionId)) || ownerOps.has(String(action.ownerOperationId)) || sequences.has(action.actionSequence as number)) fail('packet_invalid');
    actionIds.add(String(action.actionId));
    ownerOps.add(String(action.ownerOperationId));
    sequences.add(action.actionSequence as number);
  }
  if (sequences.size !== closure.actionCutoffSequence) fail('packet_invalid');
  for (let sequence = 1; sequence <= closure.actionCutoffSequence; sequence += 1) if (!sequences.has(sequence)) fail('packet_invalid');
  const bef = requireRecord(packet.bef, ['session', 'before', 'after', 'censusSha256']);
  if (!isRecord(bef.session) || !HASH.test(String(bef.censusSha256))) fail('packet_invalid');
  const before = validateCensus(bef.before, taskId);
  const after = validateCensus(bef.after, taskId);
  if (!same(before, after) || String(bef.censusSha256).toLowerCase() !== createHash('sha256').update(canonicalTaskJson(before)).digest('hex')) fail('packet_invalid');
  if (!['H3','U1'].includes(taskId)) {
    const sourceOperations = before.inspectionOperations as unknown[];
    const reads = packet.externalActions as ChainCaptureExternalAction[];
    if (sourceOperations.length !== reads.length) fail('packet_invalid');
    const matched = new Set<string>();
    for (const action of reads) {
      const proof = requireRecord(action.inspection, ['command','rawResponseSha256']);
      const command = TaskActionCommandSchema.safeParse(proof.command);
      if (!command.success || command.data.kind !== action.actionKind ||
          (command.data.kind !== 'inspect_catalog' && command.data.kind !== 'inspect_offer') ||
          !HASH.test(String(proof.rawResponseSha256)) || !action.befOperationId || matched.has(action.befOperationId) || befOps.has(action.befOperationId)) fail('packet_invalid');
      const op = requireRecord(sourceOperations.find((row)=>isRecord(row)&&row.operationId===action.befOperationId),
        ['operationId','environmentId','generationId','participantId','idempotencyKeySha256','requestSha256','actionKind','status','receiptStatus',
          'transactionHash','responseSha256','startedAt','completedAt','selectedExecutionsCount','selectedEventsCount','costsCount']);
      const generation = before.generation as ChainJson;
      const request = command.data.kind === 'inspect_catalog' ? {method:'GET',path:'/catalog'} :
        {method:'GET',path:'/offer',resourceId:command.data.resourceId};
      if (op.environmentId !== binding.environmentId || op.generationId !== execution.generationId || op.participantId !== generation.participant_id ||
          op.idempotencyKeySha256 !== createHash('sha256').update(`task-action-${action.actionId}`).digest('hex') ||
          op.requestSha256 !== createHash('sha256').update(JSON.stringify(request)).digest('hex') ||
          op.actionKind !== (command.data.kind === 'inspect_catalog' ? 'catalog':'offer') || op.status !== 'accepted' ||
          op.receiptStatus !== 'not_submitted' || op.transactionHash !== null || op.responseSha256 !== proof.rawResponseSha256 ||
          op.selectedExecutionsCount !== 0 || op.selectedEventsCount !== 0 || op.costsCount !== 0 ||
          typeof op.startedAt !== 'string' || typeof op.completedAt !== 'string' ||
          !Number.isFinite(Date.parse(op.startedAt)) || !Number.isFinite(Date.parse(op.completedAt)) || Date.parse(op.completedAt)<Date.parse(op.startedAt)) fail('packet_invalid');
      matched.add(action.befOperationId);
    }
  }
  const rpc = requireRecord(packet.rpc, ['localChainId', 'participant', 'assets', 'contracts', 'routes', 'identityCodeHashes', 'baseline',
    'final', 'intervalBlocks', 'transactions', 'transferLogs', 'approvalLogs', 'swapLogs', 'wethLogs', 'responseHashes']);
  if (!dec(rpc.localChainId) || !normAddress(rpc.participant) || !Array.isArray(rpc.assets) || !Array.isArray(rpc.contracts) ||
      !Array.isArray(rpc.routes) || !Array.isArray(rpc.identityCodeHashes) || !Array.isArray(rpc.intervalBlocks) ||
      !Array.isArray(rpc.transactions) || !Array.isArray(rpc.transferLogs) || !Array.isArray(rpc.approvalLogs) ||
      !Array.isArray(rpc.swapLogs) || !Array.isArray(rpc.wethLogs) || !Array.isArray(rpc.responseHashes) ||
      rpc.intervalBlocks.length > 256 || rpc.transactions.length > MAX_ACTIONS || rpc.transferLogs.length > MAX_ROWS ||
      rpc.approvalLogs.length > MAX_ROWS || rpc.swapLogs.length > MAX_ROWS || rpc.wethLogs.length > MAX_ROWS ||
      rpc.responseHashes.length > 4096 || rpc.transactions.length !== packet.ownerActions.length +
        (packet.externalActions as ChainCaptureExternalAction[]).filter((action) => ['pay', 'purchase'].includes(action.actionKind) &&
          action.receiptStatus === 'observed' && action.transactionHash !== null).length) fail('packet_invalid');
  const baseline = validateCheckpoint(rpc.baseline);
  const final = validateCheckpoint(rpc.final);
  if (baseline.blockNumber !== preparation.baselineBlockNumber || baseline.blockHash.toLowerCase() !== String(preparation.baselineBlockHash).toLowerCase() ||
      BigInt(final.blockNumber) < BigInt(baseline.blockNumber) || final.blockNumber !== String(rpc.intervalBlocks.length ? (BigInt(rpc.intervalBlocks[rpc.intervalBlocks.length - 1]!.number)) : BigInt(baseline.blockNumber))) fail('packet_invalid');
  const assets = rpc.assets.map((item) => {
    const asset = requireRecord(item, ['assetId', 'kind', 'address', 'codeHash']);
    if (typeof asset.assetId !== 'string' || !['native', 'erc20'].includes(String(asset.kind)) ||
        (asset.kind === 'native' ? asset.address !== null || asset.codeHash !== null : !normAddress(asset.address) || !HASH.test(String(asset.codeHash)))) fail('packet_invalid');
    return asset;
  });
  const contracts = rpc.contracts.map((item) => {
    const contract = requireRecord(item, ['contractId', 'address', 'codeHash']);
    if (typeof contract.contractId !== 'string' || !normAddress(contract.address) || !HASH.test(String(contract.codeHash))) fail('packet_invalid');
    return contract;
  });
  const routes = rpc.routes.map((item) => {
    const route = requireRecord(item, ['routeId', 'tokenInAssetId', 'tokenOutAssetId', 'router', 'pool', 'tokenIn', 'tokenOut', 'feeTier']);
    if (typeof route.routeId !== 'string' || typeof route.tokenInAssetId !== 'string' || typeof route.tokenOutAssetId !== 'string' ||
        !normAddress(route.router) || !normAddress(route.pool) || !normAddress(route.tokenIn) || !normAddress(route.tokenOut) ||
        !Number.isSafeInteger(route.feeTier) || (route.feeTier as number) < 1 || route.tokenInAssetId === route.tokenOutAssetId) fail('packet_invalid');
    return route;
  });
  const identityCodeHashes = rpc.identityCodeHashes.map((item) => {
    const row = requireRecord(item, ['address', 'expectedCodeHash', 'observedCodeHash']);
    if (!normAddress(row.address) || !HASH.test(String(row.expectedCodeHash)) ||
        String(row.expectedCodeHash).toLowerCase() !== String(row.observedCodeHash).toLowerCase()) fail('packet_invalid');
    return row;
  });
  const externalTransactionHashes = new Set((packet.externalActions as ChainCaptureExternalAction[])
    .filter((action) => ['pay', 'purchase'].includes(action.actionKind) && action.receiptStatus === 'observed' && action.transactionHash !== null)
    .map((action) => String(action.transactionHash).toLowerCase()));
  const transactions = rpc.transactions.map((item) => {
    const tx = requireRecord(item, ['hash', 'from', 'to', 'nonce', 'input', 'inputSha256', 'receiptLogsSha256', 'valueWei', 'gasLimit', 'blockNumber', 'blockHash',
      'transactionIndex', 'chainId', 'status', 'gasUsed', 'effectiveGasPriceWei', 'gasCostWei', 'logs']);
    const hash = typeof tx.hash === 'string' ? tx.hash.toLowerCase() : '';
    const externalPayment = externalTransactionHashes.has(hash);
    if (!normTx(tx.hash) || !normAddress(tx.from) || (tx.to !== null && !normAddress(tx.to)) || !uint(tx.nonce) ||
        (externalPayment ? tx.input !== null : typeof tx.input !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(tx.input)) ||
        !HASH.test(String(tx.inputSha256)) || (!externalPayment && createHash('sha256').update(String(tx.input), 'utf8').digest('hex') !== String(tx.inputSha256).toLowerCase()) ||
        !HASH.test(String(tx.receiptLogsSha256)) || !uint(tx.valueWei) || !uint(tx.gasLimit) ||
        !dec(tx.blockNumber) || !normTx(tx.blockHash) || !dec(tx.transactionIndex) || String(tx.chainId) !== String(rpc.localChainId) ||
        !['success', 'reverted'].includes(String(tx.status)) || !uint(tx.gasUsed) || !uint(tx.effectiveGasPriceWei) || !uint(tx.gasCostWei) ||
        BigInt(tx.gasUsed) * BigInt(tx.effectiveGasPriceWei) !== BigInt(tx.gasCostWei) || !Array.isArray(tx.logs)) fail('packet_invalid');
    tx.logs = (tx.logs as unknown[]).map(validateLog);
    return tx;
  });
  const txByHash = new Map<string, ChainJson>();
  for (const tx of transactions) {
    const hash = String(tx.hash).toLowerCase();
    if (txByHash.has(hash) || (tx.from !== String(rpc.participant).toLowerCase() && !externalTransactionHashes.has(hash))) fail('packet_invalid');
    txByHash.set(hash, tx);
  }
  const blocks = rpc.intervalBlocks.map((item) => {
    const block = requireRecord(item, ['number', 'hash', 'parentHash', 'transactionCount', 'participantTransactions', 'externalTransactions']);
    if (!dec(block.number) || !normTx(block.hash) || !normTx(block.parentHash) || !Number.isSafeInteger(block.transactionCount) ||
        (block.transactionCount as number) < 0 || !Array.isArray(block.participantTransactions) || !Array.isArray(block.externalTransactions) ||
        block.participantTransactions.length > (block.transactionCount as number) ||
        block.externalTransactions.length > (block.transactionCount as number) ||
        block.participantTransactions.some((hash) => !normTx(hash) || !txByHash.has(String(hash).toLowerCase()) ||
          txByHash.get(String(hash).toLowerCase())!.from !== String(rpc.participant).toLowerCase()) ||
        block.externalTransactions.some((hash) => !normTx(hash) || !externalTransactionHashes.has(String(hash).toLowerCase()) ||
          !txByHash.has(String(hash).toLowerCase()) || txByHash.get(String(hash).toLowerCase())!.from === String(rpc.participant).toLowerCase())) fail('packet_invalid');
    return block;
  });
  let previousNumber = BigInt(baseline.blockNumber);
  let previousHash = baseline.blockHash.toLowerCase();
  const intervalHashes = new Set<string>();
  const participantIntervalHashes = new Set<string>();
  for (const block of blocks) {
    const number = BigInt(String(block.number));
    if (number !== previousNumber + 1n || String(block.parentHash).toLowerCase() !== previousHash) fail('packet_invalid');
    for (const hash of block.participantTransactions as string[]) {
      const key = String(hash).toLowerCase();
      const tx = txByHash.get(key)!;
      if (intervalHashes.has(key) || tx.blockNumber !== block.number || tx.blockHash !== String(block.hash).toLowerCase()) fail('packet_invalid');
      intervalHashes.add(key);
      participantIntervalHashes.add(key);
    }
    for (const hash of block.externalTransactions as string[]) {
      const key = String(hash).toLowerCase();
      const tx = txByHash.get(key)!;
      if (intervalHashes.has(key) || tx.blockNumber !== block.number || tx.blockHash !== String(block.hash).toLowerCase()) fail('packet_invalid');
      intervalHashes.add(key);
    }
    previousNumber = number;
    previousHash = String(block.hash).toLowerCase();
  }
  if (previousNumber.toString() !== final.blockNumber || previousHash !== final.blockHash.toLowerCase() || intervalHashes.size !== transactions.length) fail('packet_invalid');
  const externalActions = packet.externalActions as ChainCaptureExternalAction[];
  const externalPaymentActions = externalActions.filter((action) => ['pay', 'purchase'].includes(action.actionKind) &&
    action.receiptStatus === 'observed' && action.transactionHash !== null);
  const paymentOperations = new Map((before.externalPaymentOperations as ChainJson[]).map((row) => [String(row.operationId), row]));
  if (paymentOperations.size !== externalPaymentActions.length) fail('packet_invalid');
  for (const action of externalPaymentActions) {
    const operation = paymentOperations.get(String(action.befOperationId));
    if (!operation || String(operation.transactionHash).toLowerCase() !== String(action.transactionHash).toLowerCase()) fail('packet_invalid');
  }
  if ((before.operations as ChainJson[]).length !== packet.ownerActions.length) fail('packet_invalid');
  const chainTransactionHashes = (packet.ownerActions as ChainCaptureAction[]).map((action) => action.transactionHash.toLowerCase());
  const participantExternalHashes = externalPaymentActions.map((action) => String(action.transactionHash).toLowerCase())
    .filter((hash) => txByHash.get(hash)?.from === String(rpc.participant).toLowerCase());
  const expectedParticipantHashes = new Set<string>([...chainTransactionHashes, ...participantExternalHashes]);
  const expectedTransactionHashes = new Set<string>([...chainTransactionHashes,
    ...externalPaymentActions.map((action) => String(action.transactionHash).toLowerCase())]);
  if (expectedTransactionHashes.size !== transactions.length ||
      transactions.some((transaction) => !expectedTransactionHashes.has(String(transaction.hash).toLowerCase()) ||
        (chainTransactionHashes.includes(String(transaction.hash).toLowerCase()) && String(transaction.from).toLowerCase() !== String(rpc.participant).toLowerCase())) ||
      participantIntervalHashes.size !== expectedParticipantHashes.size ||
      [...participantIntervalHashes].some((hash) => !expectedParticipantHashes.has(hash))) fail('packet_invalid');
  const actionsByTx = new Map((packet.ownerActions as ChainCaptureAction[]).map((action) => [action.transactionHash.toLowerCase(), action]));
  for (const [id, action] of befActionJoin(before, packet.ownerActions as ChainCaptureAction[])) {
    if (!actionsByTx.has(action.transactionHash.toLowerCase()) || id !== action.befOperationId) fail('packet_invalid');
  }
  for (const action of packet.ownerActions as ChainCaptureAction[]) {
    const operation = (before.operations as ChainJson[]).find((op) => op.operationId === action.befOperationId);
    const selected = (before.selectedExecutions as ChainJson[]).find((row) => row.operationId === action.befOperationId);
    const cost = (before.costs as ChainJson[]).find((row) => row.operationId === action.befOperationId);
    const tx = txByHash.get(action.transactionHash.toLowerCase());
    if (!operation || !selected || !cost || !tx || tx.from !== String(rpc.participant).toLowerCase() || operation.actionKind !== action.actionKind ||
        operation.transactionHash !== action.transactionHash.toLowerCase() || selected.actionKind !== action.actionKind ||
        !same(selected.selectedAction, action.selectedAction) ||
        !commandTransactionMatches(packet as ChainCapturePacket, action as ChainCaptureAction, tx as unknown as ChainCaptureTransaction, taskCase) ||
        selected.transactionHash !== action.transactionHash.toLowerCase() || tx.status !== operation.receiptStatus ||
        cost.selectedPrincipalAsset !== expectedPrincipal(action as ChainCaptureAction).asset ||
        cost.selectedPrincipalUnits !== expectedPrincipal(action as ChainCaptureAction).units ||
        cost.observedPrincipalUnits !== (tx.status === 'success' ? expectedPrincipal(action as ChainCaptureAction).units : '0') ||
        operation.idempotencyKeySha256 !== createHash('sha256').update('task-action-' + action.actionId).digest('hex') ||
        cost.transactionHash !== action.transactionHash.toLowerCase() || cost.gasCostWei !== tx.gasCostWei ||
        cost.gasUsed !== tx.gasUsed || cost.effectiveGasPriceWei !== tx.effectiveGasPriceWei ||
        cost.receiptBlockNumber !== tx.blockNumber || cost.receiptBlockHash !== tx.blockHash ||
        cost.receiptStatus !== tx.status || cost.payerRole !== 'participant' ||
        cost.payerAddress !== String(rpc.participant).toLowerCase() || cost.transactionFrom !== tx.from || cost.receiptFrom !== tx.from) fail('packet_invalid');
  }
  const logs = [
    ...(rpc.transferLogs as unknown[]).map(validateLog),
    ...(rpc.approvalLogs as unknown[]).map(validateLog),
    ...(rpc.swapLogs as unknown[]).map(validateLog),
    ...(rpc.wethLogs as unknown[]).map(validateLog),
  ];
  for (const log of logs) {
    const tx = txByHash.get(String(log.transactionHash).toLowerCase());
    if (!tx || tx.blockNumber !== log.blockNumber || tx.blockHash !== String(log.blockHash).toLowerCase() ||
        tx.transactionIndex !== log.transactionIndex || !(tx.logs as unknown[]).some((child) => same(child, log))) fail('packet_invalid');
  }
  const normalizedLogs=(values:unknown[])=>values.map(validateLog);
  const orderLogs=(left:ChainJson,right:ChainJson)=>BigInt(String(left.blockNumber))<BigInt(String(right.blockNumber))?-1:
    BigInt(String(left.blockNumber))>BigInt(String(right.blockNumber))?1:
    BigInt(String(left.transactionIndex))<BigInt(String(right.transactionIndex))?-1:
    BigInt(String(left.transactionIndex))>BigInt(String(right.transactionIndex))?1:
    BigInt(String(left.logIndex))<BigInt(String(right.logIndex))?-1:BigInt(String(left.logIndex))>BigInt(String(right.logIndex))?1:0;
  const participantTopic='0x'+String(rpc.participant).slice(2).toLowerCase().padStart(64,'0');
  const knownTokenAddresses=new Set((assets as Array<{address:string|null}>).filter((asset)=>asset.address).map((asset)=>asset.address!.toLowerCase()));
  const everyLog=transactions.flatMap((tx)=>tx.logs as ChainJson[]);
  const expectedCategories={
    transferLogs:everyLog.filter((log)=>logTopics(log)[0]===TRANSFER_TOPIC&&
      (knownTokenAddresses.has(String(log.address).toLowerCase())||logTopics(log).slice(1).some((topic)=>topic===participantTopic))).sort(orderLogs),
    approvalLogs:everyLog.filter((log)=>logTopics(log)[0]===APPROVAL_TOPIC&&knownTokenAddresses.has(String(log.address).toLowerCase())).sort(orderLogs),
    swapLogs:everyLog.filter((log)=>logTopics(log)[0]===SWAP_TOPIC).sort(orderLogs),
    wethLogs:everyLog.filter((log)=>logTopics(log)[0]===DEPOSIT_TOPIC||logTopics(log)[0]===WITHDRAWAL_TOPIC).sort(orderLogs),
  };
  for(const name of Object.keys(expectedCategories) as Array<keyof typeof expectedCategories>){
    const actual=normalizedLogs(rpc[name] as unknown[]).sort(orderLogs);
    if(!same(actual,expectedCategories[name]))fail('packet_invalid');
  }
  const responseHashes = (rpc.responseHashes as unknown[]).map((item) => {
    const row = requireRecord(item, ['method', 'paramsSha256', 'resultSha256']);
    if (typeof row.method !== 'string' || row.method.length < 1 || row.method.length > 80 ||
        !HASH.test(String(row.paramsSha256)) || !HASH.test(String(row.resultSha256))) fail('packet_invalid');
    return row;
  });
  if (transactions.length !== packet.ownerActions.length + externalPaymentActions.length) fail('packet_invalid');
  return { ...packet, binding, closure, execution, preparation, bef: { ...bef, before, after },
    rpc: { ...rpc, assets, contracts, routes, identityCodeHashes, baseline, final, intervalBlocks: blocks,
      transactions, transferLogs: (rpc.transferLogs as unknown[]).map(validateLog),
      approvalLogs: (rpc.approvalLogs as unknown[]).map(validateLog), swapLogs: (rpc.swapLogs as unknown[]).map(validateLog),
      wethLogs: (rpc.wethLogs as unknown[]).map(validateLog), responseHashes } } as ChainCapturePacket;
}

function befActionJoin(census: ChainJson, actions: ChainCaptureAction[]): Array<[string, ChainCaptureAction]> {
  const operations = new Set((census.operations as ChainJson[]).map((row) => String(row.operationId)));
  return actions.filter((action) => operations.has(action.befOperationId)).map((action) => [action.befOperationId, action]);
}

export function validateTaskChainCapturePacket(value: unknown, taskCase?: ChainTaskCase): ChainCapturePacket {
  const packet = validatePacket(value, taskCase);
  if (taskCase) {
    if (taskCase.taskId !== packet.taskId || taskCase.caseId !== packet.binding.caseId || taskCase.caseHash !== packet.binding.caseHash ||
        taskCase.rubricHash !== packet.binding.rubricHash || taskCase.executionIdentityHash !== packet.execution.executionIdentityHash ||
        taskCase.initialState.stateSha256 !== packet.execution.initialStateSha256) fail('binding_mismatch');
    const permitted = taskCase.taskId === 'H2' ? taskCase.objective.permittedConversions :
      taskCase.objective.permittedRoutes;
    if (permitted.length !== packet.rpc.routes.length) fail('binding_mismatch');
    for (const expected of permitted) {
      const route = packet.rpc.routes.find((candidate) => candidate.routeId === expected.routeId);
      const router = packet.rpc.contracts.find((candidate) => candidate.contractId === expected.routerContractId);
      const pool = packet.rpc.contracts.find((candidate) => candidate.contractId === expected.poolContractId);
      const tokenIn = packet.rpc.assets.find((candidate) => candidate.assetId === expected.tokenInAssetId);
      const tokenOut = packet.rpc.assets.find((candidate) => candidate.assetId === expected.tokenOutAssetId);
      if (!route || !router || !pool || !tokenIn?.address || !tokenOut?.address || route.tokenInAssetId !== expected.tokenInAssetId ||
          route.tokenOutAssetId !== expected.tokenOutAssetId || route.feeTier !== expected.feeTier || route.router !== router.address.toLowerCase() ||
          route.pool !== pool.address.toLowerCase() || route.tokenIn !== tokenIn.address.toLowerCase() || route.tokenOut !== tokenOut.address.toLowerCase()) {
        fail('binding_mismatch');
      }
    }
    for (const expected of taskCase.initialState.balances) {
      const account = expected.account === 'participant' ? 'participant' : expected.account.toLowerCase();
      if (!packet.rpc.baseline.balances.some((actual) => actual.account.toLowerCase() === account && actual.assetId === expected.assetId &&
          actual.amountUnits === expected.amountUnits)) fail('binding_mismatch');
    }
    for (const expected of taskCase.initialState.allowances) {
      const owner = expected.owner === 'participant' ? 'participant' : expected.owner.toLowerCase();
      if (!packet.rpc.baseline.allowances.some((actual) => actual.owner.toLowerCase() === owner && actual.tokenAssetId === expected.tokenAssetId &&
          actual.spender.toLowerCase() === expected.spender.toLowerCase() && actual.amountUnits === expected.amountUnits)) fail('binding_mismatch');
    }
  }
  return packet;
}

export function parseTaskChainCapturePacket(bytes: Uint8Array, taskCase?: ChainTaskCase): ChainCapturePacket {
  if (bytes.byteLength > MAX_PACKET_BYTES) fail('packet_too_large');
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown; }
  catch { fail('packet_invalid'); }
  return validateTaskChainCapturePacket(value, taskCase);
}

export function verifyTaskChainCapturePacketChildren(bytes: Uint8Array, bundle: ChainCaptureBundleView): EvidenceReference[] {
  if (bytes.byteLength > MAX_PACKET_BYTES) fail('packet_too_large');
  const packet = parseTaskChainCapturePacket(bytes, bundle.taskCase);
  if (!same(packet.binding, bundle.binding) || packet.closure.closureId !== bundle.closure.closureId ||
      packet.closure.actionCutoffSequence !== bundle.closure.actionCutoffSequence ||
      packet.closure.reconciledActionSequence !== bundle.closure.reconciledActionSequence ||
      !same(packet.execution, bundle.execution)) fail('binding_mismatch');
  const capture = bundle.observations.captureEvidence;
  if (!validRef(capture, CAPTURE_PREFIX) ||
      String(capture.sha256).toLowerCase() !== createHash('sha256').update(bytes).digest('hex')) fail('child_reference_invalid');
  const refs: EvidenceReference[] = [packet.preparation.fixtureEvidence, packet.preparation.baselineEvidence];
  const paths = new Set<string>(refs.map((ref) => ref.path));
  for (const action of [...packet.ownerActions, ...packet.externalActions]) {
    if (paths.has(action.actionEvidence.path)) fail('child_reference_invalid');
    paths.add(action.actionEvidence.path);
    refs.push(action.actionEvidence);
  }
  return refs;
}

type ProjectionContext = {
  binding: TaskEvidenceBinding;
  taskCase: ChainTaskCase;
  evidence: EvidenceReference;
  ethValuation: { numerator: string; denominator: string };
};
type OrderedEvent = { block: bigint; txIndex: bigint; logIndex: bigint; actionSequence: number; type: string;
  tx: ChainCaptureTransaction; data: ChainJson; index: number };

function wordAt(data: string, index: number): bigint | null {
  const body = data.slice(2);
  const start = index * 64;
  if (body.length < start + 64 || !/^[0-9a-f]{64}$/i.test(body.slice(start, start + 64))) return null;
  return BigInt('0x' + body.slice(start, start + 64));
}
function routeForAction(packet: ChainCapturePacket, action: ChainCaptureAction): ChainJson | null {
  const command = action.command;
  const matches = packet.rpc.routes.filter((route) =>
    route.tokenInAssetId === command.inputAssetId && route.tokenOutAssetId === command.outputAssetId &&
    Number(route.feeTier) === Number(command.feeTier ?? 500));
  return matches.length === 1 ? matches[0]! : null;
}
function buildProjection(packet: ChainCapturePacket, context: ProjectionContext): Pick<PersistedTaskObservations,
  'transfers' | 'finalStates' | 'allowanceChanges' | 'allowanceUses' | 'trades' | 'conversions' | 'expenses' | 'coverage'> {
  const participant = packet.rpc.participant.toLowerCase();
  const assetByAddress = new Map(packet.rpc.assets.filter((asset) => asset.address).map((asset) => [String(asset.address).toLowerCase(), asset.assetId]));
  const txByHash = new Map(packet.rpc.transactions.map((tx) => [tx.hash.toLowerCase(), tx]));
  const actionByHash = new Map(packet.ownerActions.map((action) => [action.transactionHash.toLowerCase(), action]));
  const events: OrderedEvent[] = [];
  let index = 0;
  const add = (event: Omit<OrderedEvent, 'index'>) => events.push({ ...event, index: index++ });
  const allTransfers = packet.rpc.transferLogs.map((log) => validateLog(log));
  const allApprovals = packet.rpc.approvalLogs.map((log) => validateLog(log));
  const allSwaps = packet.rpc.swapLogs.map((log) => validateLog(log));
  const allWeth = packet.rpc.wethLogs.map((log) => validateLog(log));
  const transferObs: TransferObservation[] = [];
  const allowanceChanges: AllowanceChangeObservation[] = [];
  const allowanceUses: AllowanceUseObservation[] = [];
  const trades: TradeObservation[] = [];
  const conversions: ConversionObservation[] = [];
  const expenses: ExpenseObservation[] = [];
  const meta = (sequence: number, actionSequence: number, observationId: string) => ({
    observationId, sequence, actionSequence, source: 'persisted_observer' as const, binding: context.binding, evidence: context.evidence,
  });
  const routeAddresses = new Set(packet.rpc.routes.flatMap((route) => [String(route.router).toLowerCase(), String(route.pool).toLowerCase()]));
  const usedSwapTxs = new Set<string>();
  for (const action of packet.ownerActions) {
    const hash = action.transactionHash.toLowerCase();
    const tx = txByHash.get(hash);
    if (!tx) fail('packet_invalid');
    const status = tx.status;
    const txLogs = allTransfers.filter((log) => log.transactionHash === hash);
    const txApprovals = allApprovals.filter((log) => log.transactionHash === hash);
    const txSwaps = allSwaps.filter((log) => log.transactionHash === hash);
    const txWeth = allWeth.filter((log) => log.transactionHash === hash);
    const command = action.command;
    if (action.actionKind === 'approve') {
      const token = packet.rpc.assets.find((asset) => asset.assetId === String(command.tokenAssetId ?? 'WETH'));
      const spender = normAddress(action.approvalSpender) ?? normAddress(action.selectedAction.spender) ?? normAddress(command.spender) ??
        normAddress(packet.rpc.routes.find((route) => route.tokenInAssetId === String(command.tokenAssetId ?? 'WETH'))?.router);
      if (!token?.address || !spender || txApprovals.length !== (status === 'success' ? 1 : 0)) fail('packet_invalid');
      if (status === 'success') {
        const log = txApprovals[0]!;
        const owner = eventAddress(logTopics(log)[1]);
        const logSpender = eventAddress(logTopics(log)[2]);
        const amount = eventWord(log.data);
        if (String(log.address).toLowerCase() !== token.address.toLowerCase() || owner !== participant || logSpender !== spender ||
            amount === null || amount.toString() !== String(command.amountUnits)) fail('packet_invalid');
        add({ block: BigInt(log.blockNumber as string), txIndex: BigInt(log.transactionIndex as string), logIndex: BigInt(log.logIndex as string),
          actionSequence: action.actionSequence, type: 'allowance_change', tx, data: { tokenAssetId: token.assetId, owner: 'participant',
            spender, amountAfterUnits: amount.toString(), log }, });
      }
    } else if (action.actionKind === 'transfer') {
      const asset = packet.rpc.assets.find((candidate) => candidate.address?.toLowerCase() === tx.to?.toLowerCase());
      if (!asset || txApprovals.length || txSwaps.length || txWeth.length) fail('packet_invalid');
      const recipient = normAddress(command.recipient);
      const matched = txLogs.filter((log) => eventAddress(logTopics(log)[1]) === participant &&
        eventAddress(logTopics(log)[2]) === recipient && eventWord(log.data)?.toString() === String(command.amountUnits));
      if (status === 'success' ? matched.length !== 1 : matched.length !== 0) fail('packet_invalid');
      for (const log of txLogs) {
        const from = eventAddress(logTopics(log)[1]);
        if (from !== participant) continue;
        const to = eventAddress(logTopics(log)[2]);
        const amount = eventWord(log.data);
        if (!to || amount === null || String(log.address).toLowerCase() !== String(asset.address).toLowerCase()) fail('packet_invalid');
        const operation = context.taskCase.taskId === 'H2' &&
          context.taskCase.objective.obligations.some((item) => item.recipient.toLowerCase() === to && item.assetId === asset.assetId)
          ? 'payout' : 'other';
        add({ block: BigInt(log.blockNumber as string), txIndex: BigInt(log.transactionIndex as string), logIndex: BigInt(log.logIndex as string),
          actionSequence: action.actionSequence, type: 'transfer', tx, data: { to, assetId: asset.assetId, amountUnits: amount.toString(), operation, log } });
      }
    } else if (action.actionKind === 'wrap' || action.actionKind === 'unwrap') {
      const weth = packet.rpc.assets.find((asset) => asset.assetId === 'WETH');
      const logTopic = action.actionKind === 'wrap' ? DEPOSIT_TOPIC : WITHDRAWAL_TOPIC;
      const matching = txWeth.filter((log) => logTopics(log)[0] === logTopic);
      const amount = String(command.amountWei);
      const address = normAddress(weth?.address);
      if (!address || tx.to?.toLowerCase() !== address || txSwaps.length || txApprovals.length ||
          status === 'success' && (matching.length !== 1 || eventAddress(logTopics(matching[0]!)[1]) !== participant ||
            eventWord(matching[0]!.data)?.toString() !== amount) ||
          status === 'reverted' && matching.length !== 0 ||
          action.actionKind === 'wrap' && tx.valueWei !== amount ||
          action.actionKind === 'unwrap' && tx.valueWei !== '0') fail('packet_invalid');
      if (status === 'success') {
        const log = matching[0]!;
        add({ block: BigInt(log.blockNumber as string), txIndex: BigInt(log.transactionIndex as string), logIndex: BigInt(log.logIndex as string),
          actionSequence: action.actionSequence, type: 'conversion', tx,
          data: { conversion: action.actionKind, amountUnits: amount, log } });
      }
    } else if (action.actionKind === 'swap') {
      const route = routeForAction(packet, action);
      if (!route || txApprovals.length || txWeth.length || status === 'success' && txSwaps.length !== 1 ||
          status === 'reverted' && txSwaps.length !== 0 || tx.to?.toLowerCase() !== String(route.router).toLowerCase() ||
          tx.valueWei !== '0') fail('packet_invalid');
      const swapLog = txSwaps[0];
      if (status === 'success' && swapLog) {
        const sender = eventAddress(logTopics(swapLog)[1]);
        const recipient = eventAddress(logTopics(swapLog)[2]);
        const a0 = signedWord(swapLog.data, 0);
        const a1 = signedWord(swapLog.data, 1);
        const amountIn = String(command.amountInUnits);
        if (String(swapLog.address).toLowerCase() !== String(route.pool).toLowerCase() ||
            sender !== String(route.router).toLowerCase() || recipient !== String(command.recipient).toLowerCase() ||
            a0 === null || a1 === null) fail('packet_invalid');
        const token0 = packet.rpc.assets.find((asset) => asset.address?.toLowerCase() === String(route.tokenIn).toLowerCase());
        const token1 = packet.rpc.assets.find((asset) => asset.address?.toLowerCase() === String(route.tokenOut).toLowerCase());
        const zeroOne = String(route.tokenIn).toLowerCase() < String(route.tokenOut).toLowerCase();
        const input = zeroOne ? a0 : a1;
        const output = zeroOne ? a1 : a0;
        if (!token0 || !token1 || input <= 0n || output >= 0n || input.toString() !== amountIn) fail('packet_invalid');
        const participantInputs = txLogs.filter((log) => eventAddress(logTopics(log)[1]) === participant &&
          routeAddresses.has(String(eventAddress(logTopics(log)[2]))) && String(log.address).toLowerCase() === String(route.tokenIn).toLowerCase());
        const inputTotal = participantInputs.reduce((sum, log) => sum + (eventWord(log.data) ?? 0n), 0n);
        const outputLogs = txLogs.filter((log) => String(log.address).toLowerCase() === String(route.tokenOut).toLowerCase() &&
          eventAddress(logTopics(log)[1]) === String(route.pool).toLowerCase() &&
          eventAddress(logTopics(log)[2]) === String(command.recipient).toLowerCase());
        const outputTotal = outputLogs.reduce((sum, log) => sum + (eventWord(log.data) ?? 0n), 0n);
        if (inputTotal !== input || outputTotal !== -output) fail('packet_invalid');
        usedSwapTxs.add(hash);
        add({ block: BigInt(swapLog.blockNumber as string), txIndex: BigInt(swapLog.transactionIndex as string),
          logIndex: BigInt(swapLog.logIndex as string), actionSequence: action.actionSequence, type: 'trade', tx,
          data: { routeId: route.routeId, inputAssetId: route.tokenInAssetId, outputAssetId: route.tokenOutAssetId,
            inputAmountUnits: input.toString(), outputAmountUnits: (-output).toString(), log: swapLog } });
        for (const log of participantInputs) {
          const value = eventWord(log.data);
          if (value === null) fail('packet_invalid');
          add({ block: BigInt(log.blockNumber as string), txIndex: BigInt(log.transactionIndex as string),
            logIndex: BigInt(log.logIndex as string), actionSequence: action.actionSequence, type: 'transfer', tx,
            data: { to: eventAddress(logTopics(log)[2]), assetId: route.tokenInAssetId, amountUnits: value.toString(), operation: 'swap_input', log } });
        }
        if (packet.taskId === 'U1') {
          for (const log of outputLogs) {
            const from = eventAddress(logTopics(log)[1]), to = eventAddress(logTopics(log)[2]), amount = eventWord(log.data);
            if (!from || !to || amount === null) fail('packet_invalid');
            add({ block: BigInt(log.blockNumber as string), txIndex: BigInt(log.transactionIndex as string),
              logIndex: BigInt(log.logIndex as string), actionSequence: action.actionSequence, type: 'transfer', tx,
              data: { from, to: to === participant ? 'participant' : to, assetId: route.tokenOutAssetId,
                amountUnits: amount.toString(), operation: 'other', log } });
          }
        }
      }
    }
    add({ block: BigInt(tx.blockNumber), txIndex: BigInt(tx.transactionIndex), logIndex: BigInt('1000000000000000000'),
      actionSequence: action.actionSequence, type: 'expense', tx,
      data: { sourceEffectId: 'bef-operation:' + action.befOperationId, gasUsed: tx.gasUsed,
        effectiveGasPriceWei: tx.effectiveGasPriceWei, receiptStatus: tx.status } });
  }
  const decimalCompare = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
  events.sort((left, right) => left.block < right.block ? -1 : left.block > right.block ? 1 :
    left.txIndex < right.txIndex ? -1 : left.txIndex > right.txIndex ? 1 :
      left.logIndex < right.logIndex ? -1 : left.logIndex > right.logIndex ? 1 :
        left.actionSequence - right.actionSequence || left.index - right.index);
  void decimalCompare;
  let sequence = packet.taskId === 'H3' || packet.taskId === 'U1' ? packet.closure.actionCutoffSequence + 1 : 1;
  for (const event of events) {
    const txHash = event.tx.hash.toLowerCase();
    const id = event.type + '-' + txHash.slice(2) + '-' + sequence;
    if (event.type === 'transfer') {
      transferObs.push({ kind: 'transfer', ...meta(sequence, event.actionSequence, id), from: String(event.data.from ?? 'participant'),
        to: String(event.data.to), assetId: String(event.data.assetId), amountUnits: String(event.data.amountUnits),
        receiptStatus: 'success', transactionHash: txHash, operation: event.data.operation as TransferObservation['operation'] });
    } else if (event.type === 'allowance_change') {
      const action = actionByHash.get(txHash)!;
      const log = event.data.log as ChainJson;
      const before = packet.rpc.baseline.allowances.find((item) => item.owner === 'participant' &&
        item.tokenAssetId === String(event.data.tokenAssetId) && item.spender.toLowerCase() === String(event.data.spender).toLowerCase());
      const previousChange = allowanceChanges.filter((item) => item.owner === 'participant' &&
        item.tokenAssetId === String(event.data.tokenAssetId) && item.spender.toLowerCase() === String(event.data.spender).toLowerCase()).at(-1);
      const amountBefore = previousChange?.amountAfterUnits ?? before?.amountUnits;
      if (amountBefore === undefined) fail('packet_invalid');
      const afterAmount = String(event.data.amountAfterUnits);
      allowanceChanges.push({ kind: 'allowance_change', ...meta(sequence, event.actionSequence, id), owner: 'participant',
        tokenAssetId: String(event.data.tokenAssetId), spender: String(event.data.spender), amountBeforeUnits: amountBefore,
        amountAfterUnits: afterAmount, transactionHash: txHash });
      void action;
      void log;
    } else if (event.type === 'conversion') {
      const conversion = event.data.conversion as 'wrap' | 'unwrap';
      conversions.push({ kind: 'conversion', ...meta(sequence, event.actionSequence, id), conversion,
        inputAssetId: conversion === 'wrap' ? 'ETH' : 'WETH', inputAmountUnits: String(event.data.amountUnits),
        outputAssetId: conversion === 'wrap' ? 'WETH' : 'ETH', outputAmountUnits: String(event.data.amountUnits),
        transactionHash: txHash, receiptStatus: 'success' });
    } else if (event.type === 'trade') {
      trades.push({ kind: 'trade', ...meta(sequence, event.actionSequence, id), routeId: String(event.data.routeId),
        inputAssetId: String(event.data.inputAssetId), inputAmountUnits: String(event.data.inputAmountUnits),
        outputAssetId: String(event.data.outputAssetId), outputAmountUnits: String(event.data.outputAmountUnits),
        transactionHash: txHash, receiptStatus: 'success' });
    } else if (event.type === 'expense') {
      expenses.push({ kind: 'expense', ...meta(sequence, event.actionSequence, id), component: 'participant_gas',
        sourceEffectId: String(event.data.sourceEffectId), gasUsed: String(event.data.gasUsed),
        effectiveGasPriceWei: String(event.data.effectiveGasPriceWei), receiptStatus: event.data.receiptStatus as 'success' | 'reverted',
        transactionHash: txHash });
    }
    sequence += 1;
  }
  for (const trade of trades) {
    const route = packet.rpc.routes.find((item) => item.routeId === trade.routeId);
    if (!route) fail('packet_invalid');
    const input = BigInt(trade.inputAmountUnits);
    const feeAssetUnits = (input * BigInt(route.feeTier) + 999999n) / 1000000n;
    const usdcUnits = route.tokenInAssetId === 'USDC'
      ? feeAssetUnits
      : (feeAssetUnits * BigInt(context.ethValuation.numerator)) / BigInt(context.ethValuation.denominator);
    if (usdcUnits < 0n) fail('packet_invalid');
    const txHash = trade.transactionHash.toLowerCase();
    const action = actionByHash.get(txHash)!;
    const tx = txByHash.get(txHash)!;
    expenses.push({ kind: 'expense', ...meta(sequence++, trade.actionSequence, 'dex-fee-' + txHash.slice(2)),
      component: 'verified_dex_fee', sourceEffectId: 'dex-fee:' + txHash, usdcUnits: usdcUnits.toString(), transactionHash: txHash });
    const routeSpender = String(route.router).toLowerCase();
    const baselineAllowance = packet.rpc.baseline.allowances.find((item) => item.owner === 'participant' &&
      item.tokenAssetId === trade.inputAssetId && item.spender.toLowerCase() === routeSpender);
    const finalAllowance = packet.rpc.final.allowances.find((item) => item.owner === 'participant' &&
      item.tokenAssetId === trade.inputAssetId && item.spender.toLowerCase() === routeSpender);
    if (!baselineAllowance || !finalAllowance) fail('packet_invalid');
    allowanceUses.push({ kind: 'allowance_use', ...meta(sequence++, action.actionSequence, 'allowance-use-' + txHash.slice(2)),
      owner: 'participant', tokenAssetId: trade.inputAssetId, spender: routeSpender, amountUnits: trade.inputAmountUnits,
      transactionHash: tx.hash });
    void tx;
  }
  const finalStateSequence = sequence;
  const finalState = {
    kind: 'final_state' as const,
    ...meta(finalStateSequence, packet.closure.actionCutoffSequence, 'chain-final-' + packet.binding.runId + '-' +
      packet.binding.taskId + '-' + packet.closure.actionCutoffSequence),
    balances: packet.rpc.final.balances,
    allowances: packet.rpc.final.allowances,
  };
  const coverage: PersistedTaskObservations['coverage'] = {
    transfers: 'complete', trades: 'complete', conversions: 'complete', balances: 'complete', expenses: 'complete',
    ...(packet.taskId === 'M4' || packet.taskId === 'U1' ? { allowances: 'complete' as const } : {}),
  };
  void usedSwapTxs;
  return { transfers: transferObs, finalStates: [finalState], allowanceChanges, allowanceUses, trades, conversions, expenses, coverage };
}

function signedWord(data: unknown, index: number): bigint | null {
  const value = wordAt(String(data), index);
  if (value === null) return null;
  const high = 1n << 255n;
  return value >= high ? value - (1n << 256n) : value;
}

export function projectTaskChainCapturePacket(packetValue: unknown, context: ProjectionContext): Pick<PersistedTaskObservations,
  'transfers' | 'finalStates' | 'allowanceChanges' | 'allowanceUses' | 'trades' | 'conversions' | 'expenses' | 'coverage'> {
  const packet = validateTaskChainCapturePacket(packetValue, context.taskCase);
  if (!same(packet.binding, context.binding) || packet.taskId !== context.taskCase.taskId) fail('binding_mismatch');
  return buildProjection(packet, context);
}

export function validateTaskChainCapturePacketContext(packetValue: unknown, context: ProjectionContext): ChainCapturePacket {
  const packet = validateTaskChainCapturePacket(packetValue, context.taskCase);
  if (!same(packet.binding, context.binding) || packet.taskId !== context.taskCase.taskId) fail('binding_mismatch');
  return packet;
}

export function chainCapturePacketSha256(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}
