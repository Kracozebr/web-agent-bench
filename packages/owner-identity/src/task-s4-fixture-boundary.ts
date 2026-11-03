import { validateS4FixtureBoundaryObservations, type S4FixtureBoundaryCapture,
  type S4PreparationFixtureProof } from './bef-s4-observation-collector.js';
import type { AdmittedActionExecution } from './bef-admitted-action-census.js';
import type { TaskEvidenceBinding } from './task-evaluator.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase, type TaskReleaseManifest } from './task-release.js';

type J = Record<string, unknown>;
type ActionIdentity = { befOperationId: string | null; transactionHash: string | null; actionId?: string };
export type S4ParticipantChainCensusInput<C extends J = J> = {
  taskId: TaskCase['taskId']; binding: TaskEvidenceBinding; execution: AdmittedActionExecution;
  ownerActions: readonly ActionIdentity[]; externalActions: readonly ActionIdentity[];
  rejectedChainActions?: readonly ActionIdentity[]; preparationFixture?: unknown;
  preparation?: { fixtureEvidence: EvidenceReference; baselineEvidence: EvidenceReference; baselineBlockNumber: string; baselineBlockHash: string };
  bef: { before: C; after: C; censusSha256?: string; session?: J };
};
const same = (a: unknown, b: unknown) => canonicalTaskJson(a) === canonicalTaskJson(b);
function fail(): never { throw new Error('S4_PREPARATION_FIXTURE_UNVERIFIED'); }
function rec(value: unknown): value is J { return !!value && typeof value === 'object' && !Array.isArray(value); }
function rows(value: unknown): J[] { if (!Array.isArray(value) || !value.every(rec)) return fail(); return value; }
function exact(value: J, names: readonly string[]): boolean { return Object.keys(value).sort().join(',') === [...names].sort().join(','); }
function uint(value: unknown): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value)) return fail(); return BigInt(value);
}
function reference(value: unknown): value is EvidenceReference {
  return rec(value) && exact(value, ['path', 'sha256', 'boundary']) && value.boundary === 'actual_tool_http_x402_local_evm_application_store' &&
    typeof value.path === 'string' && value.path.length <= 512 &&
    value.path.startsWith('artifacts/runs/owner-identity-bef-task-coordinator/preparation/') && /^[A-Za-z0-9._/-]+$/.test(value.path) &&
    !value.path.split('/').some(p => !p || p === '.' || p === '..') && /^[a-f0-9]{64}$/.test(String(value.sha256));
}
const forbidden = new Set(['privatekey', 'privkey', 'seedphrase', 'mnemonic', 'secret', 'clientsecret', 'bearer',
  'bearertoken', 'accesstoken', 'refreshtoken', 'providertoken', 'apikey', 'authorization', 'signature',
  'signedpayload', 'signedtransaction', 'rawtransaction', 'walletmaterial', 'walletsecret', 'password', 'r', 's', 'v']);
function privateFields(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => forbidden.has(key.toLowerCase().replace(/[^a-z]/g, '')) || privateFields(child));
}

/** Does not drop a setup row: validates its independent source proof before deriving a separate view. */
export function validateS4FixtureBoundaryCapture(value: unknown, input: Pick<S4ParticipantChainCensusInput,
  'taskId' | 'binding' | 'execution' | 'bef'>, taskCase: TaskCase,
  identity: TaskReleaseManifest['executionIdentity']): { capture: S4FixtureBoundaryCapture; fixture: S4PreparationFixtureProof } {
  if (taskCase.taskId !== 'S4' || input.taskId !== 'S4' || input.binding.taskId !== 'S4' || !rec(value) ||
    !exact(value, ['schemaVersion', 'preparationId', 'environmentId', 'generationId', 'manifestHash', 'sourceHash',
      'fixtureEvidence', 'baselineEvidence', 'fixture', 'bef', 'rpc']) || value.schemaVersion !== 'bts-s4-fixture-boundary-capture/v1' ||
    value.preparationId !== input.execution.preparationId || value.environmentId !== input.binding.environmentId ||
    value.environmentId !== input.execution.environmentId || value.generationId !== input.execution.generationId ||
    value.manifestHash !== input.execution.environmentManifestHash || value.sourceHash !== input.execution.applicationSourceHash ||
    !rec(value.fixture) || !rec(value.bef) || !rec(value.rpc) || privateFields(value)) fail();
  if (input.binding.caseId !== taskCase.caseId || input.binding.caseHash !== taskCase.caseHash || input.binding.rubricHash !== taskCase.rubricHash ||
    input.execution.executionIdentityHash !== taskCase.executionIdentityHash || input.execution.initialStateSha256 !== taskCase.initialState.stateSha256 ||
    input.execution.environmentManifestHash !== identity.environmentManifestSha256.toLowerCase() ||
    !reference(value.fixtureEvidence) || !reference(value.baselineEvidence) ||
    value.fixtureEvidence.path === value.baselineEvidence.path || value.fixtureEvidence.sha256 === value.baselineEvidence.sha256) fail();
  const capture = value as unknown as S4FixtureBoundaryCapture;
  const source = capture.fixture;
  if (!exact(value.fixture, ['operationId', 'transactionHash', 'blockNumber', 'blockHash', 'parentHash', 'amountUnits', 'spender',
    'tokenAddress', 'idempotencyKeySha256', 'proofSha256', 'baselineNumber', 'baselineHash', 'preState']) ||
    !rec(source.preState) || !exact(source.preState, ['blockNumber', 'blockHash', 'projection']) ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(source.operationId) ||
    !['transactionHash', 'blockHash', 'parentHash', 'baselineHash'].every(k => /^0x[a-f0-9]{64}$/.test(String(source[k as keyof typeof source]))) ||
    !['proofSha256', 'idempotencyKeySha256'].every(k => /^[a-f0-9]{64}$/.test(String(source[k as keyof typeof source]))) ||
    !/^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/i.test(source.preState.blockNumber) || !rec(source.preState.projection) ||
    !exact(value.bef, ['session', 'before', 'after']) || !rec(capture.bef.session) ||
    !exact(capture.bef.session, ['currentUser', 'sessionUser', 'databaseName', 'transactionReadOnly', 'transactionIsolation', 'superuser', 'bypassRls']) ||
    capture.bef.session.currentUser !== 'bef_observer' || capture.bef.session.sessionUser !== 'bef_observer' ||
    capture.bef.session.transactionReadOnly !== 'on' || capture.bef.session.transactionIsolation !== 'repeatable read' ||
    capture.bef.session.superuser !== false || capture.bef.session.bypassRls !== false ||
    typeof capture.bef.session.databaseName !== 'string' || !capture.bef.session.databaseName ||
    !rec(capture.bef.before) || !rec(capture.bef.after) || !same(capture.bef.before, capture.bef.after) ||
    input.bef.session !== undefined && !same(input.bef.session, capture.bef.session) ||
    !rec(input.bef.before.generation) || !same(capture.bef.before.generation, input.bef.before.generation)) fail();
  if (!rec(capture.bef.before.counts) || !exact(capture.bef.before.counts,
    ['operations', 'selectedExecutions', 'selectedEvents', 'costs']) ||
    !same(capture.bef.before.counts, { operations: '1', selectedExecutions: '1', selectedEvents: '4', costs: '1' })) fail();
  const rpc = capture.rpc;
  const txKeys = ['hash', 'from', 'to', 'nonce', 'input', 'value', 'gas', 'blockNumber', 'blockHash', 'transactionIndex', 'chainId'];
  if (!exact(value.rpc, ['localChainId', 'participant', 'fixtureTransaction', 'fixtureReceipt', 'fixtureBlock',
    'parentCheckpoint', 'baselineCheckpoint', 'responseHashes']) || !rec(rpc.fixtureTransaction) || !exact(rpc.fixtureTransaction, txKeys) ||
    !rec(rpc.fixtureReceipt) || !exact(rpc.fixtureReceipt, ['transactionHash', 'from', 'to', 'blockNumber', 'blockHash', 'transactionIndex',
      'status', 'gasUsed', 'effectiveGasPrice', 'logs']) || !rec(rpc.fixtureBlock) ||
    !exact(rpc.fixtureBlock, ['number', 'hash', 'parentHash', 'transactions']) || !Array.isArray(rpc.fixtureBlock.transactions) ||
    rpc.fixtureBlock.transactions.some(tx => !rec(tx) || !exact(tx, txKeys)) || !Array.isArray(rpc.fixtureReceipt.logs)) fail();
  for (const log of rpc.fixtureReceipt.logs) {
    const fields = ['address', 'topics', 'data', 'blockNumber', 'blockHash', 'transactionHash', 'transactionIndex', 'logIndex'];
    if (!rec(log) || !fields.every(key => Object.hasOwn(log, key)) ||
      Object.keys(log).some(key => ![...fields, 'removed'].includes(key)) ||
      Object.hasOwn(log, 'removed') && log.removed !== false) fail();
  }
  if (!Array.isArray(rpc.responseHashes) || rpc.responseHashes.length > 256 || rpc.responseHashes.some(row =>
    !rec(row) || !exact(row, ['method', 'paramsSha256', 'resultSha256']) || typeof row.method !== 'string' ||
    !/^[a-f0-9]{64}$/.test(String(row.paramsSha256)) || !/^[a-f0-9]{64}$/.test(String(row.resultSha256)))) fail();
  const generation = input.bef.before.generation;
  const fixture: S4PreparationFixtureProof = { ...source, blockNumber: uint(source.blockNumber), amountUnits: uint(source.amountUnits),
    baselineNumber: uint(source.baselineNumber), reference: capture.fixtureEvidence, baselineReference: capture.baselineEvidence,
    preState: { ...source.preState, blockNumber: BigInt(source.preState.blockNumber) } };
  validateS4FixtureBoundaryObservations({ fixture, taskCase, identity, before: capture.bef.before, after: capture.bef.after, rpc,
    preparation: { environment_id: input.execution.environmentId, generation_id: input.execution.generationId,
      participant_id: typeof generation.participant_id === 'string' ? generation.participant_id : null,
      payer_address: typeof generation.payer_address === 'string' ? generation.payer_address : null,
      environment_manifest_sha256: input.execution.environmentManifestHash, application_source_hash: input.execution.applicationSourceHash } });
  return { capture: structuredClone(capture), fixture };
}

function operation(row: J): J {
  return { operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
    participantId: row.participant_id, idempotencyKeySha256: row.idempotency_key_sha256, requestSha256: row.request_sha256,
    actionKind: row.operation_kind, status: row.status, receiptStatus: row.receipt_status, transactionHash: row.transaction_hash,
    responseSha256: row.response_sha256, startedAt: row.started_at, completedAt: row.completed_at };
}
/** Legacy S4 source projection enriches setup approval addresses; generic source stores its compact request. */
function compactFixtureApproval(value: unknown): J {
  if (!rec(value) || value.kind !== 'approve') return fail();
  return { kind: value.kind, tokenAssetId: value.tokenAssetId, amountUnits: value.amountUnits, gasLimit: value.gasLimit };
}
function execution(row: J): J {
  if (!rec(row.measurement) || !rec(row.measurement.receipt)) return fail();
  const receipt = row.measurement.receipt;
  return { operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
    actionKind: row.action_kind, selectedAction: compactFixtureApproval(row.selected_action), prestate: row.prestate, transactionIntent: row.transaction_intent,
    measurement: { measurementSha256: row.measurement.measurementSha256,
      receipt: { transactionHash: receipt.transactionHash, status: receipt.status, gasUsed: receipt.gasUsed,
        effectiveGasPriceWei: receipt.effectiveGasPrice, gasCostWei: receipt.gasCostWei } },
    transactionHash: row.transaction_hash, outcome: row.outcome, reasonCode: row.reason_code, completedAt: row.completed_at };
}
function event(row: J): J {
  if (row.eventKind !== 'selected_action_bound') return row;
  if (!rec(row.eventPayload)) return fail();
  return { ...row, eventPayload: { ...row.eventPayload, selectedAction: compactFixtureApproval(row.eventPayload.selectedAction) } };
}
function cost(row: J): J {
  const map: Record<string, string> = { operationId: 'operation_id', environmentId: 'env_id', generationId: 'generation_id',
    transactionHash: 'transaction_hash', payerAddress: 'payer_address', payerRole: 'payer_role', receiptStatus: 'receipt_status',
    transactionFrom: 'transaction_from', receiptFrom: 'receipt_from', receiptBlockNumber: 'receipt_block_number', receiptBlockHash: 'receipt_block_hash',
    receiptBlockParentHash: 'receipt_block_parent_hash', gasUsed: 'gas_used', effectiveGasPriceWei: 'effective_gas_price_wei', gasCostWei: 'gas_cost_wei',
    modeledGasFeeUsdcUnits: 'modeled_gas_fee_usdc_units', manifestSha256: 'manifest_sha256', selectedPrincipalAsset: 'selected_principal_asset',
    selectedPrincipalUnits: 'selected_principal_units', observedPrincipalUnits: 'observed_principal_units' };
  return Object.fromEntries(Object.entries(map).map(([key, source]) => [key, row[source]]));
}


function fixtureJoinIntent(value: unknown): J {
  if (!rec(value) || typeof value.from !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value.from) ||
      typeof value.to !== 'string' || !/^0x[0-9a-f]{40}$/i.test(value.to)) fail();
  return { ...value, from: value.from.toLowerCase(), to: value.to.toLowerCase() };
}
function fixtureJoinComparisonRow(kind: string, row: J): J {
  // AICODE-NOTE: The generic adapter retains original intent address spelling; the
  // legacy S4 adapter canonicalizes it. Compare only these declared EVM address
  // fields semantically, after strict source/RPC validation. Never rewrite source
  // rows, event hashes, calldata, amounts, nonces or any other string.
  if (kind === 'selectedExecutions') return { ...row, transactionIntent: fixtureJoinIntent(row.transactionIntent) };
  if (kind === 'selectedEvents' && row.eventKind === 'original_tx_hash_bound') {
    if (!rec(row.eventPayload)) fail();
    return { ...row, eventPayload: { ...row.eventPayload, transactionIntent: fixtureJoinIntent(row.eventPayload.transactionIntent) } };
  }
  return row;
}

/** The retained packet remains whole; only this independently verified participant view excludes setup. */
export function validateAndDeriveS4ParticipantChainCensus<C extends J>(input: S4ParticipantChainCensusInput<C>, taskCase: TaskCase,
  identity: TaskReleaseManifest['executionIdentity']): { before: C; after: C } {
  if (input.taskId !== 'S4' || taskCase.taskId !== 'S4') {
    if (input.preparationFixture !== undefined) fail();
    return { before: input.bef.before, after: input.bef.after };
  }
  const { capture } = validateS4FixtureBoundaryCapture(input.preparationFixture, input, taskCase, identity);
  if (input.preparation && (!same(input.preparation.fixtureEvidence, capture.fixtureEvidence) ||
    !same(input.preparation.baselineEvidence, capture.baselineEvidence) ||
    input.preparation.baselineBlockNumber !== capture.fixture.baselineNumber ||
    input.preparation.baselineBlockHash !== capture.fixture.baselineHash)) fail();
  if (!same(input.bef.before, input.bef.after) || input.bef.censusSha256 !== undefined &&
    sha256CanonicalTaskJson(input.bef.before) !== input.bef.censusSha256) fail();
  const fixtureId = capture.fixture.operationId, fixtureTx = capture.fixture.transactionHash;
  for (const action of [...input.ownerActions, ...input.externalActions, ...(input.rejectedChainActions ?? [])])
    if (action.befOperationId === fixtureId || action.transactionHash === fixtureTx || action.actionId === fixtureId) fail();
  const normalize = { operations: operation, selectedExecutions: execution, selectedEvents: event, costs: cost };
  const raw = input.bef.before;
  for (const key of ['operations', 'selectedExecutions', 'selectedEvents', 'costs'] as const) {
    const actual = rows(raw[key]).filter(row => row.operationId === fixtureId);
    const expected = rows(capture.bef.before[key]).map(normalize[key]);
    if (!same(actual.map(row => fixtureJoinComparisonRow(key, row)), expected.map(row => fixtureJoinComparisonRow(key, row))))
      throw new Error('S4_PREPARATION_FIXTURE_UNVERIFIED:' + key);
    if (rows(raw[key]).some(row => row.operationId !== fixtureId && row.transactionHash === fixtureTx)) fail();
  }
  for (const key of ['externalPaymentOperations', 'inspectionOperations', 'rejectedChainOperations']) {
    if (raw[key] === undefined) continue;
    if (rows(raw[key]).some(row => row.operationId === fixtureId || row.transactionHash === fixtureTx ||
      rec(row.operation) && (row.operation.operationId === fixtureId || row.operation.transactionHash === fixtureTx))) fail();
  }
  const counts = raw.counts;
  if (!rec(counts) || !exact(counts, ['operations', 'externalPaymentOperations', 'selectedExecutions', 'selectedEvents', 'costs']) ||
    Object.entries(counts).some(([key, value]) => String(rows(raw[key]).length) !== value)) fail();
  const participant = structuredClone(raw);
  const mutable: J = participant;
  for (const key of ['operations', 'selectedExecutions', 'selectedEvents', 'costs'])
    mutable[key] = rows(participant[key]).filter(row => row.operationId !== fixtureId);
  mutable.counts = Object.fromEntries(Object.keys(counts).map(key => [key, String(rows(participant[key]).length)]));
  return { before: participant, after: structuredClone(participant) };
}
