import { TaskActionCommandSchema, TaskFinishAnswerSchemas, type TaskActionCommand } from './task-action-service.js';
import { assertAdmittedActionCoverage, type AdmittedActionCensus, type AdmittedActionClosure,
  type AdmittedActionExecution, type AdmittedActionFamily, type AdmittedActionProof } from './bef-admitted-action-census.js';
import { validatePaidFamilyCapturePacketPins, projectPaidDataObservationBundle, type PaidDataCapturePacket,
  type ChainObservationBoundary } from './task-paid-data-capture-packet.js';
import { projectTaskChainFamilyCapturePacket, validateTaskChainFamilyCapturePacket,
  type ChainCapturePacket, type ChainFamilyValidationContext } from './task-chain-capture-packet.js';
import { verifyPaidFamilyEffectsAgainstChain } from './paid-family-effect-proof.js';
import type { PersistedObservationMeta, PersistedTaskObservations, TaskEvidenceBinding } from './task-evaluator.js';
import type { TaskObservationBundleCandidate } from './task-observation-store.js';
import { canonicalTaskJson, sha256CanonicalTaskJson, type EvidenceReference, type TaskCase } from './task-release.js';

const BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
const ROOT = 'artifacts/runs/owner-identity-bef-task-coordinator/observation/';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const TASKS = ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1'];
// Preserve the established capture-file ceiling; the sealed aggregate remains 32 MiB.
const MAX_BYTES = 8 * 1024 * 1024;
const ARRAYS = ['transfers', 'payments', 'stateMutations', 'finalStates', 'allowanceChanges', 'allowanceUses',
  'answers', 'selections', 'deliveries', 'trades', 'conversions', 'expenses'] as const;

export type AdmittedActionCensusReferenceEntry = AdmittedActionProof & {
  receiptRevision: number; family: AdmittedActionFamily; command: TaskActionCommand;
};
export type AdmittedActionsCapturePacket = {
  schemaVersion: 'bts-admitted-actions-observation-capture/v1';
  classification: 'run_bound_observations_candidate_not_grade';
  binding: TaskEvidenceBinding; taskIndex: number; execution: AdmittedActionExecution; closure: AdmittedActionClosure;
  closureAnswer: Record<string, unknown> | null;
  census: { schemaVersion: 'bts-admitted-action-census-reference/v1'; entries: AdmittedActionCensusReferenceEntry[] };
  children: { paid: { evidence: EvidenceReference; boundary: ChainObservationBoundary };
    chain: { evidence: EvidenceReference; boundary: ChainObservationBoundary } };
};
export class AdmittedActionsCaptureError extends Error {
  constructor(readonly code: 'ADMITTED_ACTION_PACKET_INVALID' | 'ADMITTED_ACTION_CHILD_MISMATCH' |
    'ADMITTED_ACTION_PROJECTION_MISMATCH' | 'ADMITTED_ACTION_GOAL_EFFECT_UNREPRESENTED') { super(code); }
}
function fail(code: AdmittedActionsCaptureError['code'] = 'ADMITTED_ACTION_PACKET_INVALID'): never {
  throw new AdmittedActionsCaptureError(code);
}
function rec(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}
const same = (a: unknown, b: unknown) => canonicalTaskJson(a) === canonicalTaskJson(b);

/** A future stock-funded unwrap must not become false S4 success through a missing rubric input. */
export function assertAdmittedGoalEffectRepresentation(taskCase: TaskCase, observations: PersistedTaskObservations,
  participantAddress: string): void {
  if (taskCase.taskId !== 'S4') return;
  const initialWeth = taskCase.initialState.balances.filter(item => item.assetId === 'WETH' &&
    (item.account === 'participant' || item.account.toLowerCase() === participantAddress.toLowerCase()));
  const positiveStock = initialWeth.some(item => /^(0|[1-9][0-9]*)$/.test(item.amountUnits) && BigInt(item.amountUnits) > 0n);
  const successfulUnwrap = observations.conversions.some(item => item.conversion === 'unwrap' &&
    item.receiptStatus === 'success' && item.inputAssetId === 'WETH' && /^(0|[1-9][0-9]*)$/.test(item.inputAmountUnits) &&
    BigInt(item.inputAmountUnits) > 0n);
  const outgoingPrincipal = observations.transfers.some(item => item.from === 'participant' && item.receiptStatus === 'success' &&
    /^(0|[1-9][0-9]*)$/.test(item.amountUnits) && BigInt(item.amountUnits) > 0n);
  // AICODE-NOTE: Existing S4 grading consumes outgoing Transfer facts, not conversion/burn facts.
  // Do not invent a WETH transfer/counterparty. Until that representation is approved, fail closed
  // when verified initial stock enables an otherwise unrepresented successful unwrap.
  if (positiveStock && successfulUnwrap && !outgoingPrincipal) fail('ADMITTED_ACTION_GOAL_EFFECT_UNREPRESENTED');
}
function ref(value: unknown, prefix = ROOT): value is EvidenceReference {
  return rec(value) && keys(value, ['path', 'sha256', 'boundary']) && value.boundary === BOUNDARY &&
    typeof value.path === 'string' && value.path.length <= 512 && value.path.startsWith(prefix) &&
    /^[A-Za-z0-9._/-]+$/.test(value.path) && !value.path.split('/').some(p => !p || p === '.' || p === '..') &&
    typeof value.sha256 === 'string' && HASH.test(value.sha256);
}
function family(kind: TaskActionCommand['kind']): AdmittedActionFamily {
  return kind === 'inspect_catalog' || kind === 'inspect_offer' ? 'read' :
    ['pay', 'retrieve', 'purchase'].includes(kind) ? 'payment' : 'chain';
}

/** Reconstruct the actual final-answer fact, never an inferred strategy or grade. */
export function validateAdmittedClosureAnswer(binding: TaskEvidenceBinding, taskIndex: number,
  closure: AdmittedActionClosure, value: unknown): Record<string, unknown> | null {
  if (value !== null) {
    if (!rec(value) || binding.taskId !== 'S2' && binding.taskId !== 'S3') fail();
    const schema = binding.taskId === 'S2' ? TaskFinishAnswerSchemas.S2 : TaskFinishAnswerSchemas.S3;
    const parsed = schema.safeParse(value);
    if (!parsed.success || !same(parsed.data, value)) fail();
  }
  if (closure.reason === 'agent_finish') {
    if (closure.operationId === null || sha256CanonicalTaskJson({ action: 'task_finish', runId: binding.runId,
      taskIndex, answer: value }) !== closure.payloadHash) fail();
  } else if (closure.operationId !== null || value !== null ||
    sha256CanonicalTaskJson({ runId: binding.runId, taskIndex, reason: closure.reason }) !== closure.payloadHash) fail();
  return structuredClone(value) as Record<string, unknown> | null;
}

export function validateAdmittedActionsCapturePacket(value: unknown): AdmittedActionsCapturePacket {
  if (!rec(value) || !keys(value, ['schemaVersion', 'classification', 'binding', 'taskIndex', 'execution', 'closure',
    'closureAnswer', 'census', 'children']) || value.schemaVersion !== 'bts-admitted-actions-observation-capture/v1' ||
    value.classification !== 'run_bound_observations_candidate_not_grade' || !rec(value.binding) || !rec(value.execution) ||
    !rec(value.closure) || !rec(value.census) || !rec(value.children)) fail();
  const b = value.binding, e = value.execution, c = value.closure;
  if (!keys(b, ['ownerId', 'agentId', 'runId', 'environmentId', 'releaseIdentity', 'manifestHash', 'caseId', 'caseHash', 'rubricHash', 'taskId']) ||
    !['ownerId', 'agentId', 'runId'].every(k => typeof b[k] === 'string' && UUID.test(b[k] as string)) ||
    !['caseHash', 'manifestHash', 'rubricHash'].every(k => typeof b[k] === 'string' && HASH.test(b[k] as string)) ||
    !['caseId', 'environmentId', 'releaseIdentity'].every(k => typeof b[k] === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(b[k] as string)) ||
    !TASKS.includes(String(b.taskId)) || !Number.isSafeInteger(value.taskIndex) || Number(value.taskIndex) < 0 || Number(value.taskIndex) > 11 ||
    !keys(e, ['preparationId', 'leaseId', 'generationId', 'environmentId', 'environmentManifestHash', 'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256']) ||
    e.environmentId !== b.environmentId || !['preparationId', 'leaseId', 'generationId'].every(k => typeof e[k] === 'string' && UUID.test(e[k] as string)) ||
    !['environmentManifestHash', 'applicationSourceHash', 'executionIdentityHash', 'initialStateSha256'].every(k => typeof e[k] === 'string' && HASH.test(e[k] as string)) ||
    !keys(c, ['closureId', 'operationId', 'payloadHash', 'reason', 'actionCutoffSequence', 'reconciledActionSequence']) ||
    !UUID.test(String(c.closureId)) || !HASH.test(String(c.payloadHash)) ||
    !(c.operationId === null || typeof c.operationId === 'string' && /^[A-Za-z0-9_-]{12,128}$/.test(c.operationId)) ||
    !['agent_finish', 'task_deadline', 'run_deadline'].includes(String(c.reason)) ||
    !Number.isSafeInteger(c.actionCutoffSequence) || Number(c.actionCutoffSequence) < 0 || Number(c.actionCutoffSequence) > 256 ||
    c.reconciledActionSequence !== c.actionCutoffSequence ||
    !keys(value.census, ['schemaVersion', 'entries']) || value.census.schemaVersion !== 'bts-admitted-action-census-reference/v1' ||
    !Array.isArray(value.census.entries) || value.census.entries.length !== c.actionCutoffSequence ||
    !keys(value.children, ['paid', 'chain'])) fail();
  const ids = new Set(), operations = new Set();
  for (let i = 0; i < value.census.entries.length; i++) {
    const a = value.census.entries[i];
    if (!rec(a) || !keys(a, ['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256', 'receiptStatus',
      'transactionHash', 'actionEvidence', 'receiptRevision', 'family', 'command']) || !UUID.test(String(a.actionId)) ||
      ids.has(a.actionId) || operations.has(a.ownerOperationId) || a.actionSequence !== i + 1 ||
      typeof a.ownerOperationId !== 'string' || !/^[A-Za-z0-9_-]{12,128}$/.test(a.ownerOperationId) ||
      !HASH.test(String(a.commandSha256)) || !Number.isSafeInteger(a.receiptRevision) || Number(a.receiptRevision) < 1 ||
      !['observed', 'rejected_before_execution'].includes(String(a.receiptStatus)) ||
      !(a.transactionHash === null || typeof a.transactionHash === 'string' && /^0x[a-f0-9]{64}$/.test(a.transactionHash)) ||
      !ref(a.actionEvidence, 'artifacts/runs/owner-identity-bef-task-coordinator/action/')) fail();
    const command = TaskActionCommandSchema.safeParse(a.command);
    if (!command.success || !same(command.data, a.command) || command.data.kind !== a.actionKind || family(command.data.kind) !== a.family ||
      sha256CanonicalTaskJson({ runId: b.runId, taskIndex: value.taskIndex, command: command.data }) !== a.commandSha256) fail();
    ids.add(a.actionId); operations.add(a.ownerOperationId);
  }
  for (const child of Object.values(value.children)) {
    if (!rec(child) || !keys(child, ['evidence', 'boundary']) || !ref(child.evidence) || !rec(child.boundary)) fail();
    const boundary = child.boundary;
    if (!keys(boundary, ['actionCutoffSequence', 'observationCutoffSequence', 'baselineBlockNumber', 'baselineBlockHash', 'finalBlockNumber', 'finalBlockHash']) ||
      boundary.actionCutoffSequence !== c.actionCutoffSequence || !Number.isSafeInteger(boundary.observationCutoffSequence) ||
      Number(boundary.observationCutoffSequence) < 0 || !['baselineBlockNumber', 'finalBlockNumber'].every(k => typeof boundary[k] === 'string' && /^(0|[1-9][0-9]*)$/.test(boundary[k] as string)) ||
      !['baselineBlockHash', 'finalBlockHash'].every(k => typeof boundary[k] === 'string' && /^0x[a-f0-9]{64}$/.test(boundary[k] as string))) fail();
  }
  const packet = value as unknown as AdmittedActionsCapturePacket;
  const paid = packet.children.paid, chain = packet.children.chain;
  if (paid.evidence.path === chain.evidence.path || !['baselineBlockNumber', 'baselineBlockHash', 'finalBlockNumber', 'finalBlockHash']
    .every(k => same(paid.boundary[k as keyof ChainObservationBoundary], chain.boundary[k as keyof ChainObservationBoundary]))) fail();
  validateAdmittedClosureAnswer(packet.binding, packet.taskIndex, packet.closure, packet.closureAnswer);
  if (Buffer.byteLength(canonicalTaskJson(packet)) > MAX_BYTES) fail();
  return structuredClone(packet);
}

export function parseAdmittedActionsCapturePacket(bytes: Uint8Array): AdmittedActionsCapturePacket {
  if (bytes.length === 0 || bytes.length > MAX_BYTES) fail();
  try { return validateAdmittedActionsCapturePacket(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); }
  catch (error) { if (error instanceof AdmittedActionsCaptureError) throw error; return fail(); }
}

/** Internal authority handoff after strict family replay; it cannot mint a missing payment fact. */
export function admittedDeliveryAbsenceSources(value: unknown, candidate: TaskObservationBundleCandidate,
  root: EvidenceReference): EvidenceReference[] {
  const observations = candidate.observations;
  if (!observations?.payments.some(payment => payment.deliveryRequestAbsence !== undefined)) return [];
  const packet = validateAdmittedActionsCapturePacket(value);
  if (!ref(root) || candidate.cutoffStatus !== 'authoritative' || !same(candidate.cutoffEvidence, root) ||
    !same(observations.captureEvidence, root) || !same(observations.binding, packet.binding) ||
    observations.coveredThroughSequence !== candidate.observationCutoffSequence) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  const paid = packet.children.paid.evidence;
  for (const payment of observations.payments) {
    const proof = payment.deliveryRequestAbsence;
    if (proof === undefined) continue;
    const action = packet.census.entries.find(entry => entry.actionSequence === proof.paymentActionSequence);
    if (!same(payment.binding, packet.binding) || payment.source !== 'persisted_observer' || payment.status !== 'settled' ||
      !same(payment.evidence, paid) || proof.schemaVersion !== 'bts-delivery-request-absence/v1' ||
      proof.status !== 'not_admitted_at_cutoff' || !same(proof.captureEvidence, paid) ||
      proof.paymentAttemptId !== payment.paymentAttemptId || payment.actionSequence !== proof.paymentActionSequence ||
      !action || !['pay', 'purchase'].includes(action.actionKind) || action.receiptStatus !== 'observed' ||
      action.transactionHash !== payment.transactionHash ||
      packet.census.entries.some(entry => entry.command.kind === 'retrieve' && entry.command.payActionId === action.actionId) ||
      !proof.authority || proof.authority.closureId !== packet.closure.closureId ||
      proof.authority.preparationId !== packet.execution.preparationId || proof.authority.leaseId !== packet.execution.leaseId ||
      proof.authority.generationId !== packet.execution.generationId ||
      proof.acceptedActionCutoffSequence !== packet.closure.actionCutoffSequence) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  }
  return [structuredClone(paid)];
}

/** Child effects must already have been independently reprojected from their retained raw packets. */
export function verifyAdmittedActionsCaptureChildren(value: unknown, paidValue: unknown, chain: ChainCapturePacket,
  census: AdmittedActionCensus, localChainId: number): { packet: AdmittedActionsCapturePacket; paid: PaidDataCapturePacket } {
  const packet = validateAdmittedActionsCapturePacket(value);
  const paid = validatePaidFamilyCapturePacketPins(paidValue, localChainId);
  if (chain.schemaVersion !== 'bts-chain-family-observation-capture/v1' ||
    !same(packet.binding, census.binding) || packet.taskIndex !== census.taskIndex ||
    !same(packet.execution, census.execution) || !same(packet.closure, census.closure) ||
    !same(packet.binding, paid.binding) || !same(packet.binding, chain.binding) ||
    !same(packet.execution, paid.execution) || !same(packet.execution, chain.execution) || !same(packet.closure, paid.closure) ||
    chain.closure.closureId !== packet.closure.closureId || chain.closure.actionCutoffSequence !== packet.closure.actionCutoffSequence ||
    chain.closure.reconciledActionSequence !== packet.closure.reconciledActionSequence) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  const censusReferences = census.entries.map(({ document: _document, ...entry }) => entry);
  if (!same(packet.census.entries, censusReferences)) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  const chainProofs: AdmittedActionProof[] = [
    ...chain.ownerActions.map(a => ({ ...a, receiptStatus: 'observed' as const })),
    ...(chain.rejectedChainActions ?? []),
  ];
  for (const action of [...chain.ownerActions, ...(chain.rejectedChainActions ?? [])]) {
    const entry = census.entries.find(e => e.actionId === action.actionId);
    if (!entry || !same(entry.command, action.command)) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  }
  assertAdmittedActionCoverage(census, [...paid.ownerActions, ...chainProofs]);
  if (chain.externalActions.length !== paid.ownerActions.length) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  for (const a of paid.ownerActions) {
    const external = chain.externalActions.find(e => e.actionId === a.actionId);
    if (!external || !['actionId', 'actionSequence', 'ownerOperationId', 'actionKind', 'commandSha256', 'receiptStatus',
      'transactionHash', 'actionEvidence', 'befOperationId'].every(k => same(a[k as keyof typeof a], external[k as keyof typeof external])))
      fail('ADMITTED_ACTION_CHILD_MISMATCH');
  }
  const p = packet.children.paid.boundary, c = packet.children.chain.boundary;
  if (p.baselineBlockNumber !== paid.rpc.baselineBlock.number || p.baselineBlockHash !== paid.rpc.baselineBlock.hash ||
    p.finalBlockNumber !== paid.rpc.finalBlock.number || p.finalBlockHash !== paid.rpc.finalBlock.hash ||
    c.baselineBlockNumber !== chain.rpc.baseline.blockNumber || c.baselineBlockHash !== chain.rpc.baseline.blockHash ||
    c.finalBlockNumber !== chain.rpc.final.blockNumber || c.finalBlockHash !== chain.rpc.final.blockHash) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  // Both independently observed children must agree about the actual payment transactions.
  const paymentHashes = new Set<string>();
  for (const effect of paid.rpc.paymentEffects) {
    if (!rec(effect.transaction) || !rec(effect.receipt)) fail('ADMITTED_ACTION_CHILD_MISMATCH');
    const found = chain.rpc.transactions.filter(t => t.hash === effect.transactionHash);
    if (found.length !== 1 || typeof effect.transactionHash !== 'string' || paymentHashes.has(effect.transactionHash)) fail('ADMITTED_ACTION_CHILD_MISMATCH');
    paymentHashes.add(effect.transactionHash);
    const tx = found[0]!, ptx = effect.transaction, receipt = effect.receipt;
    if (tx.hash !== ptx.hash || tx.from !== ptx.from || tx.to !== ptx.to || tx.nonce !== ptx.nonce ||
      tx.valueWei !== ptx.value || tx.blockNumber !== ptx.blockNumber || tx.blockHash !== ptx.blockHash ||
      tx.hash !== receipt.transactionHash || tx.transactionIndex !== receipt.transactionIndex ||
      tx.blockNumber !== receipt.blockNumber || tx.blockHash !== receipt.blockHash ||
      tx.status !== receipt.status || tx.gasUsed !== receipt.gasUsed || tx.effectiveGasPriceWei !== receipt.effectiveGasPriceWei ||
      tx.inputSha256 !== ptx.inputSha256 || tx.receiptLogsSha256 !== receipt.logsSha256 || tx.input !== null) fail('ADMITTED_ACTION_CHILD_MISMATCH');
  }
  const pays = paid.ownerActions.filter(a => ['pay', 'purchase'].includes(a.actionKind) && a.receiptStatus === 'observed');
  if (pays.some(a => !a.transactionHash || !paymentHashes.has(a.transactionHash)) || pays.length !== paymentHashes.size)
    fail('ADMITTED_ACTION_CHILD_MISMATCH');
  return { packet, paid };
}

export type AdmittedActionsProjectionOptions = ChainFamilyValidationContext & {
  taskCase: TaskCase; paidPacket: unknown; chainPacket: ChainCapturePacket; census: AdmittedActionCensus;
  localChainId: number; ethValuation: { numerator: string; denominator: string };
};

/** The same pure reconstruction is used at collection and again from retained bytes at sealing. */
export function projectAdmittedActionFamilyCandidates(packetValue: unknown,
  options: AdmittedActionsProjectionOptions): { paid: TaskObservationBundleCandidate; chain: TaskObservationBundleCandidate } {
  const { packet, paid } = verifyAdmittedActionsCaptureChildren(packetValue, options.paidPacket, options.chainPacket,
    options.census, options.localChainId);
  const chainPacket = validateTaskChainFamilyCapturePacket(options.chainPacket, options.taskCase, options);
  verifyPaidFamilyEffectsAgainstChain(paid, chainPacket, options.census);
  const responses = new Map<string, Record<string, unknown>>();
  for (const entry of options.census.entries) {
    if (rec(entry.document.participantToolResponse)) responses.set(entry.actionId, entry.document.participantToolResponse);
  }
  const paidCandidate = projectPaidDataObservationBundle(paid, { taskCase: options.taskCase, binding: packet.binding,
    captureEvidence: packet.children.paid.evidence, assets: options.executionIdentity.assets, actionResponses: responses });
  const projection = projectTaskChainFamilyCapturePacket(chainPacket, { binding: packet.binding,
    taskCase: options.taskCase, evidence: packet.children.chain.evidence, ethValuation: options.ethValuation,
    executionIdentity: options.executionIdentity, environmentManifest: options.environmentManifest });
  if (!('stateMutations' in projection) || !Array.isArray(projection.stateMutations)) fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
  const coveredThroughSequence = Math.max(0, ...Object.values(projection).flatMap(list => Array.isArray(list) ?
    list.map(item => rec(item) && typeof item.sequence === 'number' ? item.sequence : 0) : []));
  const observations: PersistedTaskObservations = { schemaVersion: 'bts-task-observations/v1', binding: packet.binding,
    coveredThroughSequence, captureEvidence: packet.children.chain.evidence, ...projection,
    payments: [], stateMutations: projection.stateMutations as PersistedTaskObservations['stateMutations'],
    answers: [], selections: [], deliveries: [] };
  return { paid: paidCandidate, chain: { schemaVersion: 'bts-task-observation-bundle-candidate/v1',
    cutoffStatus: 'authoritative', cutoffEvidence: packet.children.chain.evidence,
    observationCutoffSequence: coveredThroughSequence, observations } };
}

export function composeAdmittedActionObservationCandidates(value: unknown, paidCandidate: TaskObservationBundleCandidate,
  chainCandidate: TaskObservationBundleCandidate, root: EvidenceReference, options: AdmittedActionsProjectionOptions): TaskObservationBundleCandidate {
  const { packet, paid } = verifyAdmittedActionsCaptureChildren(value, options.paidPacket, options.chainPacket, options.census, options.localChainId);
  if (!ref(root) || !same(packet.binding.caseHash, options.taskCase.caseHash) || packet.binding.taskId !== options.taskCase.taskId) fail();
  const independentlyProjected = projectAdmittedActionFamilyCandidates(packet, options);
  if (!same(paidCandidate, independentlyProjected.paid) || !same(chainCandidate, independentlyProjected.chain))
    fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
  for (const [name, candidate] of [['paid', paidCandidate], ['chain', chainCandidate]] as const) {
    const child = packet.children[name], obs = candidate.observations;
    if (!obs || candidate.schemaVersion !== 'bts-task-observation-bundle-candidate/v1' || candidate.cutoffStatus !== 'authoritative' ||
      !same(candidate.cutoffEvidence, child.evidence) || !same(obs.captureEvidence, child.evidence) ||
      !same(obs.binding, packet.binding) || obs.coveredThroughSequence !== child.boundary.observationCutoffSequence ||
      candidate.observationCutoffSequence !== child.boundary.observationCutoffSequence) fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
  }
  const p = paidCandidate.observations!, c = chainCandidate.observations!;
  if (paid.coverage.status !== 'observed' || c.finalStates.length !== 1 || p.finalStates.length !== 0 ||
    !['transfers', 'stateMutations', 'balances', 'allowances', 'expenses', 'trades', 'conversions'].every(k => c.coverage[k as keyof typeof c.coverage] === 'complete') ||
    p.coverage.payments !== 'complete' || p.coverage.deliveries !== 'complete') fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
  const observations: PersistedTaskObservations = {
    schemaVersion: 'bts-task-observations/v1', binding: packet.binding, captureEvidence: root, coveredThroughSequence: 0,
    coverage: { transfers: 'complete', payments: 'complete', stateMutations: 'complete', balances: 'complete', allowances: 'complete',
      answers: 'complete', selections: 'complete', deliveries: 'complete', trades: 'complete', conversions: 'complete', expenses: 'complete' },
    transfers: [...p.transfers, ...c.transfers], payments: [...p.payments], stateMutations: [...p.stateMutations, ...c.stateMutations],
    finalStates: [...c.finalStates], allowanceChanges: [...c.allowanceChanges], allowanceUses: [...c.allowanceUses], answers: [], selections: [],
    deliveries: [...p.deliveries], trades: [...c.trades], conversions: [...c.conversions], expenses: [...p.expenses, ...c.expenses],
  };
  if (packet.closureAnswer !== null) {
    const meta: PersistedObservationMeta = { observationId: 'admitted-answer-' + packet.closure.closureId, sequence: 0,
      actionSequence: packet.closure.actionCutoffSequence, source: 'persisted_observer', binding: packet.binding, evidence: root };
    observations.answers.push({ ...meta, kind: 'final_answer', answer: packet.closureAnswer });
    if (packet.binding.taskId === 'S3' && typeof packet.closureAnswer.offerId === 'string')
      observations.selections.push({ ...meta, observationId: 'admitted-selection-' + packet.closure.closureId,
        kind: 'offer_selection', offerId: packet.closureAnswer.offerId });
  }
  const cloned = structuredClone(observations), ids = new Set<string>(), expenses = new Set<string>();
  const all: PersistedObservationMeta[] = [];
  for (const key of ARRAYS) for (const item of cloned[key]) {
    if (ids.has(item.observationId) || !same(item.binding, packet.binding) || item.source !== 'persisted_observer' ||
      !Number.isSafeInteger(item.actionSequence) || item.actionSequence < 0 || item.actionSequence > packet.closure.actionCutoffSequence ||
      ![root, packet.children.paid.evidence, packet.children.chain.evidence].some(r => same(item.evidence, r))) fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
    ids.add(item.observationId); all.push(item);
  }
  for (const expense of cloned.expenses) {
    const key = expense.component + ':' + expense.transactionHash;
    if (expenses.has(key)) fail('ADMITTED_ACTION_PROJECTION_MISMATCH');
    expenses.add(key);
  }
  assertAdmittedGoalEffectRepresentation(options.taskCase, cloned, options.chainPacket.rpc.participant);
  const final = cloned.finalStates[0]!;
  const ordered = all.filter(item => item !== final).sort((a, b) => a.actionSequence - b.actionSequence || a.sequence - b.sequence ||
    a.observationId.localeCompare(b.observationId));
  ordered.push(final);
  ordered.forEach((item, index) => { item.sequence = index + 1; });
  cloned.coveredThroughSequence = ordered.length;
  return { schemaVersion: 'bts-task-observation-bundle-candidate/v1', cutoffStatus: 'authoritative',
    observationCutoffSequence: ordered.length, cutoffEvidence: root, observations: cloned };
}
