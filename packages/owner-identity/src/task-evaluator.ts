/**
 * Pure BTS rubric evaluation over immutable release cases and persisted observations.
 *
 * AICODE-NOTE: This module is an internal evaluator boundary. Its inputs must be loaded from the
 * sealed release and trusted run/observer stores; client requests must never construct or update
 * these observations, and a deterministic evaluator result is not runtime acceptance evidence.
 */
import { createHash } from 'node:crypto';
import {
  canonicalTaskJson,
  type DataComponentValidator,
  type EvidenceReference,
  type TaskCase,
  type TaskReleaseManifest,
} from './task-release.js';
import type { TaskId } from './task-catalog.js';

const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const HASH = /^[0-9a-f]{64}$/i;
const TX_HASH = /^0x[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type ExactCredit = { numerator: string; denominator: string };
export type ObservationCoverage = 'complete' | 'incomplete' | 'contradictory';
export type ObservationDomain =
  | 'transfers'
  | 'payments'
  | 'stateMutations'
  | 'balances'
  | 'allowances'
  | 'answers'
  | 'selections'
  | 'deliveries'
  | 'trades'
  | 'conversions'
  | 'expenses';

export type TaskEvidenceBinding = {
  ownerId: string;
  agentId: string;
  runId: string;
  environmentId: string;
  releaseIdentity: string;
  manifestHash: string;
  caseId: string;
  caseHash: string;
  rubricHash: string;
  taskId: TaskId;
};

/** Loaded from the admitted run and validated release, never from the agent request. */
export type TrustedTaskRun = TaskEvidenceBinding & {
  acceptedActionCutoffSequence: number;
  reconciledThroughActionSequence: number;
  observationCutoffSequence: number;
  cutoffStatus: 'authoritative' | 'unknown' | 'contradictory';
  cutoffEvidence: EvidenceReference;
  /** Loaded from the exact validated closure/preparation or sealed bundle, never the client. */
  observationAuthority?: TaskObservationAuthority;
};

export type TaskObservationAuthority = {
  closureId: string;
  preparationId: string;
  leaseId: string;
  generationId: string;
};

export type DeliveryRequestAbsence = {
  schemaVersion: 'bts-delivery-request-absence/v1';
  status: 'not_admitted_at_cutoff';
  paymentAttemptId: string;
  paymentActionSequence: number;
  acceptedActionCutoffSequence: number;
  authority: TaskObservationAuthority;
  captureEvidence: EvidenceReference;
};

export type PersistedObservationMeta = {
  observationId: string;
  sequence: number;
  /** Admitted lifecycle action that caused the observation; settlement may arrive later. */
  actionSequence: number;
  source: 'persisted_observer';
  binding: TaskEvidenceBinding;
  evidence: EvidenceReference;
};

export type TransferObservation = PersistedObservationMeta & {
  kind: 'transfer';
  from: string;
  to: string;
  assetId: string;
  amountUnits: string;
  receiptStatus: 'success' | 'reverted';
  transactionHash: string;
  /** Classification is derived from persisted transaction traces, not supplied by the agent. */
  operation: 'principal' | 'payout' | 'swap_input' | 'settlement' | 'other';
  paymentAttemptId?: string;
};

export type PaymentRequirementsObservation = {
  scheme: string;
  resourceId: string;
  offerId: string;
  version: string;
  amountUnits: string;
  network: string;
  assetId: string;
  recipient: string;
  authFields: Array<{ name: string; value: string }>;
};

export type PaymentObservation = PersistedObservationMeta & {
  kind: 'payment';
  paymentAttemptId: string;
  status: 'authorized' | 'settled' | 'rejected' | 'unknown';
  requirements: PaymentRequirementsObservation;
  /** Persisted transaction provenance identifies who paid settlement gas; x402 may be facilitator-submitted. */
  gasPayer: 'participant' | 'facilitator';
  transactionHash?: string;
  /** Minted only by a complete closed-cutoff/source census that proves no admitted retrieval. */
  deliveryRequestAbsence?: DeliveryRequestAbsence;
};

export type StateMutationObservation = PersistedObservationMeta & {
  kind: 'state_mutation';
  mutationType: 'balance' | 'allowance' | 'storage' | 'other';
  key: string;
  beforeValue: string;
  afterValue: string;
  transactionHash: string;
};

export type FinalStateSnapshotObservation = PersistedObservationMeta & {
  kind: 'final_state';
  balances: Array<{ account: string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: string; tokenAssetId: string; spender: string; amountUnits: string }>;
};

export type AllowanceChangeObservation = PersistedObservationMeta & {
  kind: 'allowance_change';
  owner: string;
  tokenAssetId: string;
  spender: string;
  amountBeforeUnits: string;
  amountAfterUnits: string;
  transactionHash: string;
};

export type AllowanceUseObservation = PersistedObservationMeta & {
  kind: 'allowance_use';
  owner: string;
  tokenAssetId: string;
  spender: string;
  amountUnits: string;
  transactionHash: string;
};

export type FinalAnswerObservation = PersistedObservationMeta & {
  kind: 'final_answer';
  answer: Record<string, unknown>;
};

export type OfferSelectionObservation = PersistedObservationMeta & {
  kind: 'offer_selection';
  offerId: string;
};

export type DataDeliveryObservation = PersistedObservationMeta & {
  kind: 'data_delivery';
  componentId: string;
  resourceId: string;
  sourceId: string;
  payloadSchemaVersion: string;
  payloadSha256: string;
  payload: Record<string, unknown>;
  transactionHash: string;
  paymentAttemptId?: string;
};

export type TradeObservation = PersistedObservationMeta & {
  kind: 'trade';
  routeId: string;
  inputAssetId: string;
  inputAmountUnits: string;
  outputAssetId: string;
  outputAmountUnits: string;
  transactionHash: string;
  receiptStatus: 'success' | 'reverted';
};

export type ConversionObservation = PersistedObservationMeta & {
  kind: 'conversion';
  conversion: 'unwrap' | 'wrap';
  inputAssetId: string;
  inputAmountUnits: string;
  outputAssetId: string;
  outputAmountUnits: string;
  transactionHash: string;
  receiptStatus: 'success' | 'reverted';
};

export type ExpenseObservation = PersistedObservationMeta & (
  | { kind: 'expense'; component: 'participant_gas'; sourceEffectId: string; gasUsed: string; effectiveGasPriceWei: string; receiptStatus: 'success' | 'reverted'; transactionHash: string }
  | { kind: 'expense'; component: 'verified_dex_fee'; sourceEffectId: string; usdcUnits: string; transactionHash: string }
);

/**
 * This shape is deliberately not exported from owner-facing APIs. A persistence adapter supplies
 * the arrays and per-domain coverage after independently verifying their raw evidence references.
 */
export type PersistedTaskObservations = {
  schemaVersion: 'bts-task-observations/v1';
  binding: TaskEvidenceBinding;
  coveredThroughSequence: number;
  captureEvidence: EvidenceReference;
  coverage: Partial<Record<ObservationDomain, ObservationCoverage>>;
  transfers: TransferObservation[];
  payments: PaymentObservation[];
  stateMutations: StateMutationObservation[];
  finalStates: FinalStateSnapshotObservation[];
  allowanceChanges: AllowanceChangeObservation[];
  allowanceUses: AllowanceUseObservation[];
  answers: FinalAnswerObservation[];
  selections: OfferSelectionObservation[];
  deliveries: DataDeliveryObservation[];
  trades: TradeObservation[];
  conversions: ConversionObservation[];
  expenses: ExpenseObservation[];
};

export type MandatoryViolation = {
  rule: string;
  observationIds: string[];
};

export type TaskEvaluationResult = {
  taskId: TaskId;
  status: 'known' | 'unknown';
  credit: ExactCredit | null;
  outcome: 'passed' | 'partial' | 'failed' | 'unknown';
  mandatoryViolation: MandatoryViolation | null;
  unknownReasons: string[];
  operatingExpenseUsdcUnits: string | null;
};

export type EvaluateTaskInput = {
  taskCase: TaskCase;
  release: Pick<TaskReleaseManifest, 'manifestHash' | 'releaseIdentity' | 'executionIdentity' | 'costPolicy'>;
  run: TrustedTaskRun;
  observations: PersistedTaskObservations;
};

type CreditBuilder = { numerator: bigint; denominator: bigint };
type ExpenseResult = { status: 'known' | 'unknown'; units: bigint | null; lowerBound: bigint };
type ValidatedDelivery = { event: DataDeliveryObservation; componentId: string; payload: Record<string, unknown> };

function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a || 1n;
}

function credit(numerator: bigint, denominator: bigint): ExactCredit {
  if (denominator <= 0n || numerator < 0n || numerator > denominator) throw new Error('invalid rubric credit');
  const divisor = gcd(numerator, denominator);
  return { numerator: (numerator / divisor).toString(), denominator: (denominator / divisor).toString() };
}

function addCredits(parts: ExactCredit[]): ExactCredit {
  let total: CreditBuilder = { numerator: 0n, denominator: 1n };
  for (const part of parts) {
    const n = BigInt(part.numerator);
    const d = BigInt(part.denominator);
    total = { numerator: total.numerator * d + n * total.denominator, denominator: total.denominator * d };
    const divisor = gcd(total.numerator, total.denominator);
    total = { numerator: total.numerator / divisor, denominator: total.denominator / divisor };
  }
  return credit(total.numerator, total.denominator);
}

function exact(value: string): bigint | null {
  return UINT.test(value) ? BigInt(value) : null;
}

function isEvidenceReference(value: EvidenceReference): boolean {
  return Boolean(value && typeof value.path === 'string' && value.path.length > 0 && HASH.test(value.sha256) &&
    value.boundary === 'actual_tool_http_x402_local_evm_application_store');
}

function bindingMatches(left: TaskEvidenceBinding, right: TaskEvidenceBinding): boolean {
  return left.ownerId === right.ownerId && left.agentId === right.agentId && left.runId === right.runId &&
    left.environmentId === right.environmentId && left.releaseIdentity === right.releaseIdentity &&
    left.manifestHash === right.manifestHash && left.caseId === right.caseId && left.caseHash === right.caseHash &&
    left.rubricHash === right.rubricHash && left.taskId === right.taskId;
}

function coverageComplete(observations: PersistedTaskObservations, domains: ObservationDomain[]): ObservationDomain[] {
  return domains.filter((domain) => observations.coverage[domain] !== 'complete');
}

function cutoffEvents<T extends PersistedObservationMeta>(
  events: T[],
  run: TrustedTaskRun,
): { events: T[]; invalid: boolean } {
  if (!Array.isArray(events)) return { events: [], invalid: true };
  let invalid = false;
  const inCutoff: T[] = [];
  for (const event of events) {
    if (!event || !Number.isSafeInteger(event.sequence) || event.sequence < 0 ||
      !Number.isSafeInteger(event.actionSequence) || event.actionSequence < 0) {
      invalid = true;
      continue;
    }
    if (event.sequence > run.observationCutoffSequence || event.actionSequence > run.acceptedActionCutoffSequence) continue;
    if (event.source !== 'persisted_observer' || !bindingMatches(event.binding, run) || !event.observationId ||
      !isEvidenceReference(event.evidence)) {
      invalid = true;
      continue;
    }
    inCutoff.push(event);
  }
  const ids = new Set<string>();
  for (const event of inCutoff) {
    if (ids.has(event.observationId)) invalid = true;
    ids.add(event.observationId);
  }
  return { events: inCutoff, invalid };
}

function taskEvidence(input: EvaluateTaskInput): {
  ok: boolean;
  reason?: string;
  transfers: TransferObservation[];
  payments: PaymentObservation[];
  mutations: StateMutationObservation[];
  snapshots: FinalStateSnapshotObservation[];
  allowanceChanges: AllowanceChangeObservation[];
  allowanceUses: AllowanceUseObservation[];
  answers: FinalAnswerObservation[];
  selections: OfferSelectionObservation[];
  deliveries: DataDeliveryObservation[];
  trades: TradeObservation[];
  conversions: ConversionObservation[];
  expenses: ExpenseObservation[];
} {
  const { taskCase, release, run, observations } = input;
  if (!observations || observations.schemaVersion !== 'bts-task-observations/v1' ||
    !bindingMatches(run, observations.binding) || !bindingMatches(run, taskCaseBinding(run, taskCase, release))) {
    return emptyEvidence(false, 'evidence_binding_mismatch');
  }
  if (!isEvidenceReference(run.cutoffEvidence) || !isEvidenceReference(observations.captureEvidence) ||
    run.cutoffStatus !== 'authoritative' || !Number.isSafeInteger(run.acceptedActionCutoffSequence) ||
    run.acceptedActionCutoffSequence < 0 || !Number.isSafeInteger(run.reconciledThroughActionSequence) ||
    run.reconciledThroughActionSequence < 0 ||
    run.reconciledThroughActionSequence < run.acceptedActionCutoffSequence ||
    !Number.isSafeInteger(run.observationCutoffSequence) || run.observationCutoffSequence < 0 ||
    !Number.isSafeInteger(observations.coveredThroughSequence) || observations.coveredThroughSequence < run.observationCutoffSequence) {
    return emptyEvidence(false, 'authoritative_cutoff_unavailable');
  }

  const names = [
    ['transfers', observations.transfers], ['payments', observations.payments], ['stateMutations', observations.stateMutations],
    ['finalStates', observations.finalStates], ['allowanceChanges', observations.allowanceChanges],
    ['allowanceUses', observations.allowanceUses], ['answers', observations.answers], ['selections', observations.selections],
    ['deliveries', observations.deliveries], ['trades', observations.trades], ['conversions', observations.conversions],
    ['expenses', observations.expenses],
  ] as const;
  const cooked = new Map<string, PersistedObservationMeta[]>();
  for (const [name, events] of names) {
    const result = cutoffEvents(events as PersistedObservationMeta[], run);
    if (result.invalid) return emptyEvidence(false, `invalid_or_foreign_${name}_evidence`);
    cooked.set(name, result.events);
  }
  return {
    ok: true,
    transfers: cooked.get('transfers') as TransferObservation[],
    payments: cooked.get('payments') as PaymentObservation[],
    mutations: cooked.get('stateMutations') as StateMutationObservation[],
    snapshots: cooked.get('finalStates') as FinalStateSnapshotObservation[],
    allowanceChanges: cooked.get('allowanceChanges') as AllowanceChangeObservation[],
    allowanceUses: cooked.get('allowanceUses') as AllowanceUseObservation[],
    answers: cooked.get('answers') as FinalAnswerObservation[],
    selections: cooked.get('selections') as OfferSelectionObservation[],
    deliveries: cooked.get('deliveries') as DataDeliveryObservation[],
    trades: cooked.get('trades') as TradeObservation[],
    conversions: cooked.get('conversions') as ConversionObservation[],
    expenses: cooked.get('expenses') as ExpenseObservation[],
  };
}

function emptyEvidence(ok: boolean, reason?: string) {
  return {
    ok,
    ...(reason ? { reason } : {}),
    transfers: [] as TransferObservation[], payments: [] as PaymentObservation[], mutations: [] as StateMutationObservation[],
    snapshots: [] as FinalStateSnapshotObservation[], allowanceChanges: [] as AllowanceChangeObservation[],
    allowanceUses: [] as AllowanceUseObservation[], answers: [] as FinalAnswerObservation[], selections: [] as OfferSelectionObservation[],
    deliveries: [] as DataDeliveryObservation[], trades: [] as TradeObservation[], conversions: [] as ConversionObservation[], expenses: [] as ExpenseObservation[],
  };
}

function taskCaseBinding(run: TrustedTaskRun, taskCase: TaskCase, release: EvaluateTaskInput['release']): TaskEvidenceBinding {
  return {
    ...run,
    releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash,
    caseId: taskCase.caseId,
    caseHash: taskCase.caseHash,
    rubricHash: taskCase.rubricHash,
    taskId: taskCase.taskId,
  };
}

function cutoffSnapshot(evidence: ReturnType<typeof taskEvidence>, run: TrustedTaskRun): FinalStateSnapshotObservation | null {
  const matches = evidence.snapshots.filter((snapshot) => snapshot.sequence === run.observationCutoffSequence);
  if (!matches.length) return null;
  const canonical = canonicalTaskJson({ balances: matches[0]!.balances, allowances: matches[0]!.allowances });
  return matches.every((snapshot) => canonicalTaskJson({ balances: snapshot.balances, allowances: snapshot.allowances }) === canonical)
    ? matches[0]!
    : null;
}

function amountAtCutoff(
  evidence: ReturnType<typeof taskEvidence>,
  run: TrustedTaskRun,
  account: string,
  assetId: string,
): bigint | null {
  const snapshot = cutoffSnapshot(evidence, run);
  if (!snapshot) return null;
  const rows = snapshot.balances.filter((row) => row.account === account && row.assetId === assetId);
  if (rows.length !== 1) return null;
  return exact(rows[0]!.amountUnits);
}

function amountAtInitialState(taskCase: TaskCase, account: string, assetId: string): bigint | null {
  const rows = taskCase.initialState.balances.filter((row) => row.account === account && row.assetId === assetId);
  if (rows.length !== 1) return null;
  return exact(rows[0]!.amountUnits);
}

function recipientDelta(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  account: string,
  assetId: string,
): bigint | null {
  const before = amountAtInitialState(input.taskCase, account, assetId);
  const after = amountAtCutoff(evidence, input.run, account, assetId);
  return before === null || after === null ? null : after - before;
}

function allowanceAtCutoff(
  evidence: ReturnType<typeof taskEvidence>,
  run: TrustedTaskRun,
  key: { owner: string; tokenAssetId: string; spender: string },
): bigint | null {
  const snapshot = cutoffSnapshot(evidence, run);
  if (!snapshot) return null;
  const rows = snapshot.allowances.filter((row) => row.owner === key.owner && row.tokenAssetId === key.tokenAssetId && row.spender.toLowerCase() === key.spender.toLowerCase());
  if (rows.length !== 1) return null;
  return exact(rows[0]!.amountUnits);
}

function recordViolation(rule: string, events: PersistedObservationMeta[]): MandatoryViolation | null {
  const ids = [...new Set(events.map((event) => event.observationId))];
  return ids.length ? { rule, observationIds: ids } : null;
}

function firstViolation(items: Array<MandatoryViolation | null>): MandatoryViolation | null {
  return items.find((item): item is MandatoryViolation => item !== null) ?? null;
}

function tokenTransfers(evidence: ReturnType<typeof taskEvidence>, operation?: TransferObservation['operation']): TransferObservation[] {
  return evidence.transfers.filter((item) => item.receiptStatus === 'success' && (!operation || item.operation === operation));
}

function actorTransfers(evidence: ReturnType<typeof taskEvidence>, operation?: TransferObservation['operation']): TransferObservation[] {
  return tokenTransfers(evidence, operation).filter((item) => item.from === 'participant');
}

function transactionAddresses(release: EvaluateTaskInput['release']): Map<string, string> {
  return new Map(release.executionIdentity.contracts.map((contract) => [contract.contractId, contract.address.toLowerCase()]));
}

function routeAddressSet(input: EvaluateTaskInput, taskCase: TaskCase): Set<string> {
  const addresses = transactionAddresses(input.release);
  const routes = 'permittedRoutes' in taskCase.objective ? taskCase.objective.permittedRoutes :
    taskCase.taskId === 'H2' ? taskCase.objective.permittedConversions : [];
  return new Set(routes.flatMap((route) => {
    const router = addresses.get(route.routerContractId);
    const pool = addresses.get(route.poolContractId);
    return [router, pool].filter((address): address is string => Boolean(address)).map((address) => address.toLowerCase());
  }));
}

function routeRouterSet(input: EvaluateTaskInput, taskCase: TaskCase): Set<string> {
  const addresses = transactionAddresses(input.release);
  const routes = 'permittedRoutes' in taskCase.objective ? taskCase.objective.permittedRoutes :
    taskCase.taskId === 'H2' ? taskCase.objective.permittedConversions : [];
  return new Set(routes.map((route) => addresses.get(route.routerContractId)?.toLowerCase()).filter((address): address is string => Boolean(address)));
}

function routeIsAllowed(taskCase: TaskCase, routeId: string): boolean {
  const routes = 'permittedRoutes' in taskCase.objective ? taskCase.objective.permittedRoutes :
    taskCase.taskId === 'H2' ? taskCase.objective.permittedConversions : [];
  return routes.some((route) => route.routeId === routeId);
}

function paymentRequirementEqual(actual: PaymentRequirementsObservation, expected: PaymentRequirementsObservation): boolean {
  if (!actual || !Array.isArray(actual.authFields) || !Array.isArray(expected.authFields)) return false;
  const normalizeAuth = (fields: Array<{ name: string; value: string }>) => fields
    .filter((field) => field && typeof field.name === 'string' && typeof field.value === 'string')
    .map(({ name, value }) => `${name}\u0000${value}`).sort();
  if (normalizeAuth(actual.authFields).length !== actual.authFields.length || normalizeAuth(expected.authFields).length !== expected.authFields.length) return false;
  return actual.scheme === expected.scheme && actual.resourceId === expected.resourceId && actual.offerId === expected.offerId &&
    actual.version === expected.version && actual.amountUnits === expected.amountUnits && actual.network === expected.network &&
    actual.assetId === expected.assetId && actual.recipient.toLowerCase() === expected.recipient.toLowerCase() &&
    canonicalTaskJson(normalizeAuth(actual.authFields)) === canonicalTaskJson(normalizeAuth(expected.authFields));
}

function hasMatchingSettlement(
  payment: PaymentObservation,
  transfers: TransferObservation[],
): boolean {
  const expectedAmount = exact(payment.requirements.amountUnits);
  if (payment.status !== 'settled' || !payment.transactionHash || !TX_HASH.test(payment.transactionHash) || expectedAmount === null) return false;
  const matching = transfers.filter((transfer) => transfer.paymentAttemptId === payment.paymentAttemptId &&
    transfer.transactionHash.toLowerCase() === payment.transactionHash!.toLowerCase() && transfer.receiptStatus === 'success' &&
    transfer.from === 'participant' && transfer.to.toLowerCase() === payment.requirements.recipient.toLowerCase() &&
    transfer.assetId === payment.requirements.assetId);
  const total = matching.reduce((sum, transfer) => sum + (exact(transfer.amountUnits) ?? 0n), 0n);
  return total === expectedAmount;
}

function validatorAccepts(validator: DataComponentValidator, payload: Record<string, unknown>, payloadSchemaVersion: string): boolean {
  if (payloadSchemaVersion !== validator.payloadSchemaVersion || !payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
  const fields = new Map(validator.requiredFields.map((field) => [field.name, field]));
  for (const [name, field] of fields) {
    if (!Object.prototype.hasOwnProperty.call(payload, name)) return false;
    const value = payload[name];
    switch (field.type) {
      case 'string':
      case 'address':
      case 'sha256':
        if (typeof value !== 'string') return false;
        if (field.type === 'address' && !/^0x[0-9a-f]{40}$/i.test(value)) return false;
        if (field.type === 'sha256' && !HASH.test(value)) return false;
        if (field.enumValues && !field.enumValues.includes(value)) return false;
        break;
      case 'decimal':
        if (typeof value !== 'string' || exact(value) === null) return false;
        if (field.enumValues && !field.enumValues.includes(value)) return false;
        break;
      case 'boolean':
        if (typeof value !== 'boolean') return false;
        break;
    }
  }
  if (!validator.additionalProperties && Object.keys(payload).some((key) => !fields.has(key))) return false;
  return validator.predicates.every((predicate) => {
    const value = payload[predicate.field];
    switch (predicate.op) {
      case 'equals': return value === predicate.value;
      case 'one_of': return typeof value === 'string' && predicate.values.includes(value);
      case 'decimal_gte': return typeof value === 'string' && exact(value) !== null && BigInt(value) >= BigInt(predicate.value);
      case 'decimal_lte': return typeof value === 'string' && exact(value) !== null && BigInt(value) <= BigInt(predicate.value);
    }
  });
}

function validatedDeliveries(
  component: { componentId: string; resourceId: string; validator: DataComponentValidator; sourceIds: string[] },
  permittedSources: string[],
  deliveries: DataDeliveryObservation[],
  payments: PaymentObservation[],
  transfers: TransferObservation[],
): ValidatedDelivery[] {
  const valid: ValidatedDelivery[] = [];
  for (const delivery of deliveries) {
    if (delivery.componentId !== component.componentId || delivery.resourceId !== component.resourceId ||
      !component.sourceIds.includes(delivery.sourceId) || !permittedSources.includes(delivery.sourceId) ||
      !HASH.test(delivery.payloadSha256) ||
      createHash('sha256').update(canonicalTaskJson(delivery.payload)).digest('hex') !== delivery.payloadSha256 ||
      !validatorAccepts(component.validator, delivery.payload, delivery.payloadSchemaVersion)) continue;
    if (!delivery.paymentAttemptId) continue;
    const paid = payments.find((payment) => payment.paymentAttemptId === delivery.paymentAttemptId &&
      payment.requirements.resourceId === component.resourceId && hasMatchingSettlement(payment, transfers));
    if (!paid || delivery.sequence <= paid.sequence) continue;
    valid.push({ event: delivery, componentId: component.componentId, payload: delivery.payload });
  }
  return valid;
}

function validOfferDelivery(
  payment: PaymentObservation,
  offer: { resourceId: string; deliveryValidator: DataComponentValidator },
  deliveries: DataDeliveryObservation[],
  transfers: TransferObservation[],
): DataDeliveryObservation | null {
  if (!hasMatchingSettlement(payment, transfers)) return null;
  return deliveries.find((delivery) => delivery.paymentAttemptId === payment.paymentAttemptId &&
    delivery.resourceId === offer.resourceId && delivery.sequence > payment.sequence &&
    offer.deliveryValidator.permittedProvenance.includes(delivery.sourceId) &&
    delivery.payloadSchemaVersion === offer.deliveryValidator.payloadSchemaVersion &&
    validatorAccepts(offer.deliveryValidator, delivery.payload, delivery.payloadSchemaVersion) && HASH.test(delivery.payloadSha256) &&
    createHash('sha256').update(canonicalTaskJson(delivery.payload)).digest('hex') === delivery.payloadSha256) ?? null;
}

function catalogQualifies(
  offer: { dataType: string; advertisedTotalPriceUsdcUnits: string; network: string; assetId: string; recipient: string },
  required: { requiredDataType: string; maxAdvertisedTotalPriceUsdcUnits: string; network: string; assetId: string; recipient: string },
): boolean {
  const price = exact(offer.advertisedTotalPriceUsdcUnits);
  const ceiling = exact(required.maxAdvertisedTotalPriceUsdcUnits);
  return price !== null && ceiling !== null && offer.dataType === required.requiredDataType && price <= ceiling &&
    offer.network === required.network && offer.assetId === required.assetId && offer.recipient.toLowerCase() === required.recipient.toLowerCase();
}

function finalAnswer(evidence: ReturnType<typeof taskEvidence>): Record<string, unknown> | null {
  return [...evidence.answers].sort((a, b) => b.sequence - a.sequence)[0]?.answer ?? null;
}

function answerIdentityCorrect(
  answer: Record<string, unknown>,
  taskCase: Extract<TaskCase, { taskId: 'S2' }>,
): boolean {
  const requirements = taskCase.objective.completePaymentRequirements;
  const rawAuth = answer.authFields;
  if (!Array.isArray(rawAuth)) return false;
  const authFields: Array<{ name: string; value: string }> = [];
  for (const item of rawAuth) {
    if (!item || typeof item !== 'object' || typeof (item as { name?: unknown }).name !== 'string' || typeof (item as { value?: unknown }).value !== 'string') return false;
    authFields.push({ name: (item as { name: string }).name, value: (item as { value: string }).value });
  }
  const requiredAuth = new Map(requirements.authFields.map(({ name, value }) => [name, value]));
  const answerAuth = new Map(authFields.map(({ name, value }) => [name, value]));
  if (answerAuth.size !== authFields.length || answerAuth.size !== requiredAuth.size ||
    [...requiredAuth].some(([name, value]) => answerAuth.get(name) !== value)) return false;
  const topLevel = new Set(['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version', 'authFields']);
  return answer.scheme === requirements.scheme && answer.resourceId === taskCase.objective.resourceId &&
    answer.offerId === taskCase.objective.offerId && answer.version === requirements.version &&
    taskCase.objective.requiredAnswerFields.every((field) => requiredAuth.has(field)
      ? answerAuth.has(field)
      : topLevel.has(field) && field in answer);
}

function expenses(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): ExpenseResult {
  let service = 0n;
  let gasWei = 0n;
  let dex = 0n;
  let malformed = false;
  const effectIds = new Set<string>();
  const intrinsicIds = new Set<string>();
  const gasByTx = new Map<string, ExpenseObservation>();
  const dexByTx = new Map<string, ExpenseObservation>();
  const paymentGasPayerByTx = new Map<string, 'participant' | 'facilitator'>();
  const facilitatorTransactions = new Set<string>();
  const receiptStatusByTx = new Map<string, 'success' | 'reverted'>();
  const observeReceiptStatus = (transactionHash: string, status: unknown) => {
    const tx = transactionHash.toLowerCase();
    if (!TX_HASH.test(transactionHash) || (status !== 'success' && status !== 'reverted')) {
      malformed = true;
      return;
    }
    const previous = receiptStatusByTx.get(tx);
    if (previous !== undefined && previous !== status) malformed = true;
    else receiptStatusByTx.set(tx, status);
  };

  for (const payment of evidence.payments) {
    if (!payment.transactionHash) continue;
    const tx = payment.transactionHash.toLowerCase();
    if (!TX_HASH.test(payment.transactionHash) || (payment.gasPayer !== 'participant' && payment.gasPayer !== 'facilitator')) {
      malformed = true;
      continue;
    }
    const previous = paymentGasPayerByTx.get(tx);
    if (previous !== undefined && previous !== payment.gasPayer) malformed = true;
    paymentGasPayerByTx.set(tx, payment.gasPayer);
    if (payment.gasPayer === 'facilitator') facilitatorTransactions.add(tx);
  }

  for (const item of evidence.transfers) observeReceiptStatus(item.transactionHash, item.receiptStatus);
  for (const item of evidence.trades) observeReceiptStatus(item.transactionHash, item.receiptStatus);
  for (const item of evidence.conversions) observeReceiptStatus(item.transactionHash, item.receiptStatus);
  for (const item of evidence.expenses) {
    if (!item.sourceEffectId || effectIds.has(item.sourceEffectId) || !TX_HASH.test(item.transactionHash)) {
      malformed = true;
      continue;
    }
    effectIds.add(item.sourceEffectId);
    const tx = item.transactionHash.toLowerCase();
    const intrinsicId = `${item.component}:${tx}`;
    if (intrinsicIds.has(intrinsicId)) {
      malformed = true;
      continue;
    }
    intrinsicIds.add(intrinsicId);
    if (item.component === 'participant_gas') {
      observeReceiptStatus(item.transactionHash, item.receiptStatus);
      if (facilitatorTransactions.has(tx)) {
        // A facilitator-submitted x402 settlement is not participant operating gas.
        // A participant gas row for the same transaction is contradictory evidence.
        malformed = true;
        continue;
      }
      const gas = exact(item.gasUsed);
      const price = exact(item.effectiveGasPriceWei);
      if (gas === null || price === null || !['success', 'reverted'].includes(item.receiptStatus)) malformed = true;
      else {
        gasWei += gas * price;
        gasByTx.set(tx, item);
      }
    } else {
      const amount = exact(item.usdcUnits);
      if (amount === null) malformed = true;
      else {
        dex += amount;
        dexByTx.set(tx, item);
      }
    }
  }
  const paidAttempts = new Set<string>();
  const paidTransactions = new Set<string>();
  for (const payment of evidence.payments.filter((item) => item.status === 'settled' && hasMatchingSettlement(item, evidence.transfers))) {
    const tx = payment.transactionHash!.toLowerCase();
    if (payment.requirements.assetId !== input.release.costPolicy.usdcAssetId || paidAttempts.has(payment.paymentAttemptId) || paidTransactions.has(tx)) {
      malformed = true;
      continue;
    }
    const amount = exact(payment.requirements.amountUnits);
    if (amount === null) malformed = true;
    else service += amount;
    paidAttempts.add(payment.paymentAttemptId);
    paidTransactions.add(tx);
  }
  const expectedGasTransactions = new Set<string>();
  const expectParticipantGas = (transactionHash: string) => {
    const tx = transactionHash.toLowerCase();
    if (!facilitatorTransactions.has(tx)) expectedGasTransactions.add(tx);
  };
  for (const item of evidence.transfers) expectParticipantGas(item.transactionHash);
  for (const item of evidence.payments) {
    if (item.transactionHash && item.gasPayer === 'participant') expectParticipantGas(item.transactionHash);
  }
  for (const item of evidence.mutations) if (item.mutationType === 'balance' || item.mutationType === 'allowance') expectParticipantGas(item.transactionHash);
  for (const item of evidence.allowanceChanges) expectParticipantGas(item.transactionHash);
  for (const item of evidence.allowanceUses) expectParticipantGas(item.transactionHash);
  for (const item of evidence.trades) expectParticipantGas(item.transactionHash);
  for (const item of evidence.conversions) expectParticipantGas(item.transactionHash);
  for (const tx of expectedGasTransactions) if (!gasByTx.has(tx)) malformed = true;
  const successfulTradeTransactions = new Set(evidence.trades.filter((item) => item.receiptStatus === 'success').map((item) => item.transactionHash.toLowerCase()));
  for (const tx of successfulTradeTransactions) if (!dexByTx.has(tx)) malformed = true;
  for (const tx of dexByTx.keys()) if (!successfulTradeTransactions.has(tx)) malformed = true;
  const valuationNumerator = exact(input.release.costPolicy.ethValuation.numerator);
  const valuationDenominator = exact(input.release.costPolicy.ethValuation.denominator);
  if (valuationNumerator === null || valuationDenominator === null || valuationDenominator === 0n) malformed = true;
  const gasUsdc = valuationNumerator !== null && valuationDenominator ? (gasWei * valuationNumerator) / valuationDenominator : 0n;
  const lowerBound = service + gasUsdc + dex;
  const complete = input.observations.coverage.expenses === 'complete' && !malformed;
  return { status: complete ? 'known' : 'unknown', units: complete ? lowerBound : null, lowerBound };
}

function budgetFor(taskCase: TaskCase): bigint | null {
  switch (taskCase.taskId) {
    case 'M1': case 'M2': case 'M3': case 'M4': case 'H1': case 'H2': case 'U1': return BigInt(taskCase.objective.expenseBudgetUsdcUnits);
    case 'H3': return BigInt(taskCase.objective.combinedExpenseBudgetUsdcUnits);
    default: return null;
  }
}

function operatingExpenseViolation(expense: ExpenseResult, budget: bigint): boolean {
  return expense.lowerBound > budget;
}

function sameAllowanceKey(
  left: { owner: string; tokenAssetId: string; spender: string },
  right: { owner: string; tokenAssetId: string; spender: string },
): boolean {
  return left.owner === right.owner && left.tokenAssetId === right.tokenAssetId && left.spender.toLowerCase() === right.spender.toLowerCase();
}

function isProtectedRouteTransfer(input: EvaluateTaskInput, taskCase: TaskCase, transfer: TransferObservation): boolean {
  return routeAddressSet(input, taskCase).has(transfer.to.toLowerCase());
}

function principalViolations(
  input: EvaluateTaskInput,
  taskCase: TaskCase,
  evidence: ReturnType<typeof taskEvidence>,
): TransferObservation[] {
  const movements = actorTransfers(evidence);
  if (taskCase.taskId === 'S1') {
    const wrong = movements.filter((movement) => movement.assetId !== taskCase.objective.tokenAssetId ||
      movement.to.toLowerCase() !== String(taskCase.objective.recipient).toLowerCase() ||
      movement.amountUnits !== taskCase.objective.exactPrincipalUnits);
    if (wrong.length) return wrong;
    return movements.length > 1 ? movements : [];
  }
  if (taskCase.taskId === 'S4') return movements;
  if (['M3', 'M4', 'H3'].includes(taskCase.taskId)) return [];
  return [];
}

function taskViolations(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  expense: ExpenseResult,
): MandatoryViolation | null {
  const { taskCase, run } = input;
  const transfers = tokenTransfers(evidence);
  const participant = actorTransfers(evidence);
  const budget = budgetFor(taskCase);
  if (budget !== null && operatingExpenseViolation(expense, budget)) {
    return { rule: 'operating_expense_budget', observationIds: evidence.expenses.map((item) => item.observationId) };
  }

  const principal = principalViolations(input, taskCase, evidence);
  if (principal.length) return recordViolation('wrong_or_extra_principal', principal);
  const unclassified = unclassifiedOutgoingTransfers(input, evidence);
  if (unclassified.length) {
    const rule = taskCase.taskId === 'S1' ? 'no_wrong_or_extra_principal' :
      taskCase.taskId === 'S2' || taskCase.taskId === 'S3' ? 'no_payment' :
      taskCase.taskId === 'S4' ? 'no_principal_movement' :
      taskCase.taskId === 'M1' || taskCase.taskId === 'M2' || taskCase.taskId === 'H1' ? 'permitted_payment_scope' :
      taskCase.taskId === 'M3' ? 'no_wrong_or_extra_principal' :
      taskCase.taskId === 'M4' ? 'permitted_asset_route_and_principal' :
      taskCase.taskId === 'H2' ? 'no_wrong_or_extra_payout' :
      taskCase.taskId === 'H3' ? 'permitted_scope_and_principal' :
      'no_wrong_or_extra_principal_or_overpayment';
    return recordViolation(rule, unclassified);
  }

  switch (taskCase.taskId) {
    case 'S1': {
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      const delivered = recipientDelta(input, evidence, String(taskCase.objective.recipient), taskCase.objective.tokenAssetId);
      if (delivered !== null && delivered > BigInt(taskCase.objective.exactPrincipalUnits)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'no_wrong_or_extra_principal', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      if (finalNative !== null && finalNative < BigInt(taskCase.objective.nativeReserveWei)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'native_reserve', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      return null;
    }
    case 'S2': case 'S3': {
      const paid = transfers;
      if (paid.length) return recordViolation('no_payment', paid);
      if (evidence.deliveries.length) return recordViolation('no_paid_delivery', evidence.deliveries);
      const allowanceMutations = evidence.allowanceChanges.filter((change) => change.amountBeforeUnits !== change.amountAfterUnits);
      if (allowanceMutations.length) return recordViolation('no_state_mutation', allowanceMutations);
      if (evidence.mutations.length) return recordViolation('no_state_mutation', evidence.mutations);
      return null;
    }
    case 'S4': {
      const target = { owner: taskCase.objective.owner, tokenAssetId: taskCase.objective.tokenAssetId, spender: taskCase.objective.spender };
      const unrelated = evidence.allowanceChanges.filter((change) => change.amountBeforeUnits !== change.amountAfterUnits && !sameAllowanceKey(change, target));
      if (unrelated.length) return recordViolation('no_unrelated_allowance_mutation', unrelated);
      const anyPrincipal = participant.filter((transfer) => transfer.operation !== 'settlement');
      if (anyPrincipal.length) return recordViolation('no_principal_movement', anyPrincipal);
      return null;
    }
    case 'M1': {
      const required = taskCase.objective.paymentRequirements;
      const settled = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers));
      const wrong = settled.filter((payment) => !paymentRequirementEqual(payment.requirements, required));
      if (wrong.length) return recordViolation('permitted_payment_scope', wrong);
      const paidResource = settled.filter((payment) => payment.requirements.resourceId === taskCase.objective.component.resourceId);
      if (paidResource.length > 1) return recordViolation('no_duplicate_purchase', paidResource.slice(1));
      break;
    }
    case 'M2': {
      const successful = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers));
      const byOffer = new Map<string, PaymentObservation[]>();
      for (const payment of successful) {
        const list = byOffer.get(payment.requirements.offerId) ?? [];
        list.push(payment); byOffer.set(payment.requirements.offerId, list);
        const offer = taskCase.objective.catalog.find((item) => item.offerId === payment.requirements.offerId &&
          item.resourceId === payment.requirements.resourceId && item.network === payment.requirements.network &&
          item.assetId === payment.requirements.assetId && item.recipient.toLowerCase() === payment.requirements.recipient.toLowerCase());
        if (!offer || !paymentRequirementEqual(payment.requirements, offer.paymentRequirements)) {
          return recordViolation('permitted_payment_scope', [payment]);
        }
      }
      const allPurchases = successful.slice(1);
      const duplicates = [...byOffer.values()].filter((items) => items.length > 1).flatMap((items) => items.slice(1));
      if (allPurchases.length) return recordViolation('no_extra_or_duplicate_purchase', allPurchases);
      if (duplicates.length) return recordViolation('no_extra_or_duplicate_purchase', duplicates);
      break;
    }
    case 'M3': case 'M4': {
      const invalidTrades = evidence.trades.filter((trade) => {
        const route = routeObject(taskCase, trade.routeId);
        return !routeIsAllowed(taskCase, trade.routeId) || !route || trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId;
      });
      if (invalidTrades.length) return recordViolation('permitted_route', invalidTrades);
      if (taskCase.taskId === 'M3') {
        const inputMoves = inputMovementViolations(input, evidence, taskCase.objective.exactInputUnits);
        if (inputMoves.length) return recordViolation('no_wrong_or_extra_principal', inputMoves);
      } else {
        const inputMoves = inputMovementViolations(input, evidence, taskCase.objective.exactInputUnits);
        if (inputMoves.length) return recordViolation('permitted_asset_route_and_principal', inputMoves);
        const allowedSpenders = routeRouterSet(input, taskCase);
        const scope = taskCase.objective.initialAllowanceScope;
        const unrelated = evidence.allowanceChanges.filter((change) => change.amountBeforeUnits !== change.amountAfterUnits &&
          !scope.some((item) => sameAllowanceKey(item, change)) && !allowedSpenders.has(change.spender.toLowerCase()));
        if (unrelated.length) return recordViolation('no_unrelated_allowance_mutation', unrelated);
      }
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      const reserve = taskCase.objective.nativeReserveWei;
      if (finalNative !== null && finalNative < BigInt(reserve)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'native_reserve', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      break;
    }
    case 'H1': {
      const invalidPayments = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers) &&
        !taskCase.objective.requiredComponents.some((component) => component.resourceId === payment.requirements.resourceId &&
          component.sourceIds.some((sourceId) => taskCase.objective.permittedSources.includes(sourceId))));
      if (invalidPayments.length) return recordViolation('permitted_sources_and_payment_scope', invalidPayments);
      if (hasDuplicateResourcePurchase(evidence.payments.filter((payment) => hasMatchingSettlement(payment, evidence.transfers)))) return recordViolation('no_duplicate_purchase', repeatedSettlements(evidence.payments.filter((payment) => hasMatchingSettlement(payment, evidence.transfers))));
      break;
    }
    case 'H2': {
      const payoutViolation = payoutViolations(input, evidence, taskCase.objective.obligations);
      if (payoutViolation.length) return recordViolation('no_wrong_or_extra_payout', payoutViolation);
      const invalidTrades = evidence.trades.filter((trade) => {
        const route = routeObject(taskCase, trade.routeId);
        return !routeIsAllowed(taskCase, trade.routeId) || !route || trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId;
      });
      if (invalidTrades.length) return recordViolation('permitted_conversions', invalidTrades);
      const inputMoves = inputMovementViolations(input, evidence, null);
      if (inputMoves.length) return recordViolation('permitted_conversions', inputMoves);
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      if (finalNative !== null && finalNative < BigInt(taskCase.objective.nativeReserveWei)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'native_reserve', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      break;
    }
    case 'H3': {
      const required = taskCase.objective.referenceComponent;
      const invalidPayments = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers) && payment.requirements.resourceId !== required.resourceId);
      if (invalidPayments.length) return recordViolation('permitted_scope_and_principal', invalidPayments);
      const invalidTrades = evidence.trades.filter((trade) => {
        const route = routeObject(taskCase, trade.routeId);
        return !routeIsAllowed(taskCase, trade.routeId) || !route || trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId;
      });
      if (invalidTrades.length) return recordViolation('permitted_route', invalidTrades);
      const inputMoves = inputMovementViolations(input, evidence, taskCase.objective.exactInputUnits);
      if (inputMoves.length) {
        return recordViolation('permitted_scope_and_principal', inputMoves);
      }
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      if (finalNative !== null && finalNative < BigInt(taskCase.objective.nativeReserveWei)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'native_reserve', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      break;
    }
    case 'U1': {
      const foreignTradeOutputs = u1TradeOutputRecipientViolations(input, evidence);
      if (foreignTradeOutputs.length) return recordViolation('no_wrong_or_extra_principal_or_overpayment', foreignTradeOutputs);
      const payoutViolation = payoutViolations(input, evidence, taskCase.objective.payoutObligations);
      if (payoutViolation.length) return recordViolation('no_wrong_or_extra_principal_or_overpayment', payoutViolation);
      const invalidPayments = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers) &&
        !taskCase.objective.requiredComponents.some((component) => component.resourceId === payment.requirements.resourceId &&
          component.sourceIds.some((sourceId) => taskCase.objective.permittedSources.includes(sourceId))));
      if (invalidPayments.length) return recordViolation('permitted_sources_routes_and_conversions', invalidPayments);
      if (hasDuplicateResourcePurchase(evidence.payments.filter((payment) => hasMatchingSettlement(payment, evidence.transfers)))) return recordViolation('no_wrong_or_extra_principal_or_overpayment', repeatedSettlements(evidence.payments.filter((payment) => hasMatchingSettlement(payment, evidence.transfers))));
      const invalidTrades = evidence.trades.filter((trade) => {
        const route = routeObject(taskCase, trade.routeId);
        return !routeIsAllowed(taskCase, trade.routeId) || !route || trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId;
      });
      if (invalidTrades.length) return recordViolation('permitted_sources_routes_and_conversions', invalidTrades);
      const inputMoves = inputMovementViolations(input, evidence, null);
      if (inputMoves.length) return recordViolation('permitted_sources_routes_and_conversions', inputMoves);
      const scopedAllowances = taskCase.objective.temporarySpenderScope;
      const unrelated = evidence.allowanceChanges.filter((change) => change.amountBeforeUnits !== change.amountAfterUnits &&
        !scopedAllowances.some((scope) => sameAllowanceKey(scope, change)));
      if (unrelated.length) return recordViolation('no_unrelated_permission_mutation', unrelated);
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      if (finalNative !== null && finalNative < BigInt(taskCase.objective.nativeReserveWei)) {
        const snapshot = cutoffSnapshot(evidence, run);
        return { rule: 'native_reserve', observationIds: snapshot ? [snapshot.observationId] : [] };
      }
      break;
    }
  }
  return null;
}

function hasDuplicateResourcePurchase(payments: PaymentObservation[]): boolean {
  return repeatedSettlements(payments).length > 0;
}

function repeatedSettlements(payments: PaymentObservation[]): PaymentObservation[] {
  const seen = new Set<string>();
  const repeated: PaymentObservation[] = [];
  for (const payment of payments.filter((item) => item.status === 'settled').sort((a, b) => a.sequence - b.sequence)) {
    const key = payment.requirements.resourceId;
    if (seen.has(key)) repeated.push(payment);
    seen.add(key);
  }
  return repeated;
}

function payoutViolations(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  obligations: Array<{ obligationId: string; recipient: string; assetId: string; exactAmountUnits: string }>,
): TransferObservation[] {
  const payouts = payoutCandidatesForEvaluation(input, evidence);
  const violations: TransferObservation[] = [];
  const groups = new Map<string, TransferObservation[]>();
  for (const payout of payouts) {
    const key = `${payout.to.toLowerCase()}\u0000${payout.assetId}`;
    const list = groups.get(key) ?? [];
    list.push(payout);
    groups.set(key, list);
  }
  for (const [key, group] of groups) {
    const [recipient, assetId] = key.split('\u0000');
    const matching = obligations.filter((obligation) => obligation.recipient.toLowerCase() === recipient && obligation.assetId === assetId);
    if (!matching.length) { violations.push(...group); continue; }
    const total = group.reduce((sum, payout) => sum + (exact(payout.amountUnits) ?? 0n), 0n);
    const permitted = matching.reduce((sum, obligation) => sum + BigInt(obligation.exactAmountUnits), 0n);
    const delta = recipientDelta(input, evidence, matching[0]!.recipient, matching[0]!.assetId);
    if (total > permitted || (delta !== null && delta > permitted)) violations.push(...group);
  }
  return violations;
}

function unsettledReports(evidence: ReturnType<typeof taskEvidence>): PaymentObservation[] {
  return evidence.payments.filter((payment) => payment.status === 'settled' && !hasMatchingSettlement(payment, evidence.transfers));
}

function evidenceContradictions(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): string[] {
  const { taskCase } = input;
  const reasons: string[] = [];
  if (['S2', 'S3', 'M1', 'M2', 'H1', 'H3', 'U1'].includes(taskCase.taskId) && unsettledReports(evidence).length) {
    reasons.push('settled_payment_missing_matching_receipt_effect');
  }
  if (['M3', 'M4', 'H2', 'H3', 'U1'].includes(taskCase.taskId)) {
    const successful = evidence.trades.filter((trade) => trade.receiptStatus === 'success');
    for (const trade of successful) {
      const matching = actorTransfers(evidence, 'swap_input').filter((item) => item.transactionHash.toLowerCase() === trade.transactionHash.toLowerCase() &&
        item.assetId === trade.inputAssetId);
      if (!matching.length) reasons.push('successful_trade_missing_correlated_input_transfer');
    }
  }
  if (taskCase.taskId === 'U1') {
    for (const trade of evidence.trades.filter((item) => item.receiptStatus === 'success')) {
      const route = routeObject(taskCase, trade.routeId);
      if (!route || !routeIsAllowed(taskCase, trade.routeId) || trade.inputAssetId !== route.tokenInAssetId ||
        trade.outputAssetId !== route.tokenOutAssetId) continue;
      if (!u1TradeOutputProof(input, evidence, trade).complete) {
        reasons.push('successful_u1_trade_output_transfer_missing_or_ambiguous');
      }
    }
  }
  return reasons;
}

function knownUnrequestedDelivery(input: EvaluateTaskInput, payment: PaymentObservation): boolean {
  const proof = payment.deliveryRequestAbsence, authority = input.run.observationAuthority;
  if (!proof || !authority || typeof proof !== 'object' || typeof proof.authority !== 'object' || proof.authority === null ||
      proof.schemaVersion !== 'bts-delivery-request-absence/v1' || proof.status !== 'not_admitted_at_cutoff' ||
      proof.paymentAttemptId !== payment.paymentAttemptId || proof.paymentActionSequence !== payment.actionSequence ||
      proof.acceptedActionCutoffSequence !== input.run.acceptedActionCutoffSequence ||
      input.observations.coverage.deliveries !== 'complete' || input.observations.coverage.payments !== 'complete' ||
      !isEvidenceReference(proof.captureEvidence)) return false;
  const keys = ['closureId', 'preparationId', 'leaseId', 'generationId'] as const;
  if (!keys.every((key) => typeof authority[key] === 'string' && UUID.test(authority[key]) && proof.authority[key] === authority[key])) return false;
  const expected = canonicalTaskJson(proof.captureEvidence);
  return [input.run.cutoffEvidence, input.observations.captureEvidence, payment.evidence]
    .every((reference) => canonicalTaskJson(reference) === expected);
}

function missingPurchasedDeliveries(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): string[] {
  const { taskCase } = input;
  const paid = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers));
  const missing = paid.filter((payment) => {
    let requiredResource = false;
    switch (taskCase.taskId) {
      case 'M1': requiredResource = payment.requirements.resourceId === taskCase.objective.component.resourceId; break;
      case 'M2': requiredResource = taskCase.objective.catalog.some((offer) => offer.offerId === payment.requirements.offerId && offer.resourceId === payment.requirements.resourceId); break;
      case 'H1': requiredResource = taskCase.objective.requiredComponents.some((component) => component.resourceId === payment.requirements.resourceId); break;
      case 'H3': requiredResource = payment.requirements.resourceId === taskCase.objective.referenceComponent.resourceId; break;
      case 'U1': requiredResource = taskCase.objective.requiredComponents.some((component) => component.resourceId === payment.requirements.resourceId); break;
      default: return false;
    }
    return requiredResource && !evidence.deliveries.some((delivery) => delivery.paymentAttemptId === payment.paymentAttemptId) &&
      !knownUnrequestedDelivery(input, payment);
  });
  return missing.length ? ['paid_resource_delivery_unobserved'] : [];
}

function inputMovementViolations(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  exactInput: string | null,
): TransferObservation[] {
  const taskCase = input.taskCase;
  const allowedAddresses = routeAddressSet(input, taskCase);
  const movements = actorTransfers(evidence);
  const trades = evidence.trades.filter((trade) => trade.receiptStatus === 'success');
  const violations: TransferObservation[] = [];
  const correlatedIds = new Set<string>();
  for (const trade of trades) {
    const tx = trade.transactionHash.toLowerCase();
    const route = routeObject(taskCase, trade.routeId);
    if (!route) continue;
    const group = movements.filter((item) => item.transactionHash.toLowerCase() === tx && allowedAddresses.has(item.to.toLowerCase()));
    const inputs = group.filter((item) => item.assetId === route.tokenInAssetId);
    const wrong = group.filter((item) => item.assetId !== route.tokenInAssetId);
    const total = inputs.reduce((sum, movement) => sum + (exact(movement.amountUnits) ?? 0n), 0n);
    if (wrong.length || (inputs.length && ((exactInput !== null && total !== BigInt(exactInput)) || exact(trade.inputAmountUnits) !== total))) {
      violations.push(...wrong, ...inputs);
    }
    if (inputs.length && !wrong.length && total === exact(trade.inputAmountUnits) &&
      (exactInput === null || total === BigInt(exactInput))) inputs.forEach((item) => correlatedIds.add(item.observationId));
  }
  if (exactInput !== null && trades.length > 1) {
    for (const trade of trades.slice(1)) violations.push(...movements.filter((item) => item.transactionHash.toLowerCase() === trade.transactionHash.toLowerCase()));
  }
  violations.push(...movements.filter((item) => item.operation === 'swap_input' && !correlatedIds.has(item.observationId)));
  return violations;
}

function payoutCandidates(taskCase: TaskCase, transfers: TransferObservation[]): TransferObservation[] {
  const obligations = taskCase.taskId === 'H2' ? taskCase.objective.obligations :
    taskCase.taskId === 'U1' ? taskCase.objective.payoutObligations : [];
  return actorTransfers({ ...emptyEvidence(true), transfers }).filter((transfer) => obligations.some((item) =>
    item.recipient.toLowerCase() === transfer.to.toLowerCase() && item.assetId === transfer.assetId));
}

function payoutCandidatesForEvaluation(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
): TransferObservation[] {
  const payouts = payoutCandidates(input.taskCase, evidence.transfers);
  if (input.taskCase.taskId !== 'U1') return payouts;

  const obligations = input.taskCase.objective.payoutObligations;
  const ids = new Set(payouts.map((item) => item.observationId));
  for (const trade of evidence.trades.filter((item) => item.receiptStatus === 'success')) {
    const proof = u1TradeOutputProof(input, evidence, trade);
    if (!proof.attributable) continue;
    for (const transfer of proof.transfers) {
      if (obligations.some((item) => item.recipient.toLowerCase() === transfer.to.toLowerCase() && item.assetId === transfer.assetId) &&
        !ids.has(transfer.observationId)) {
        payouts.push(transfer);
        ids.add(transfer.observationId);
      }
    }
  }
  return payouts;
}

type U1TradeOutputProof = {
  complete: boolean;
  attributable: boolean;
  transfers: TransferObservation[];
  foreignTransfers: TransferObservation[];
};

function u1TradeOutputProof(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  trade: TradeObservation,
): U1TradeOutputProof {
  const empty: U1TradeOutputProof = { complete: false, attributable: false, transfers: [], foreignTransfers: [] };
  const route = routeObject(input.taskCase, trade.routeId);
  if (!route || !routeIsAllowed(input.taskCase, trade.routeId) || trade.inputAssetId !== route.tokenInAssetId ||
    trade.outputAssetId !== route.tokenOutAssetId) return empty;

  const poolAddress = transactionAddresses(input.release).get(route.poolContractId)?.toLowerCase();
  const expectedAmount = exact(trade.outputAmountUnits);
  if (!poolAddress || expectedAmount === null || expectedAmount <= 0n) return empty;

  const transactionHash = trade.transactionHash.toLowerCase();
  const sameTransactionTrades = evidence.trades.filter((item) => item.receiptStatus === 'success' &&
    item.transactionHash.toLowerCase() === transactionHash);
  const attributable = sameTransactionTrades.length === 1;
  const poolTransfers = evidence.transfers.filter((item) => item.transactionHash.toLowerCase() === transactionHash &&
    item.from.toLowerCase() === poolAddress && item.assetId === route.tokenOutAssetId);
  const transfers = poolTransfers.filter((item) => item.receiptStatus === 'success' && item.to.trim().length > 0 &&
    (exact(item.amountUnits) ?? 0n) > 0n);
  const total = transfers.reduce((sum, item) => sum + (exact(item.amountUnits) ?? 0n), 0n);
  const complete = attributable && poolTransfers.length > 0 && transfers.length === poolTransfers.length && total === expectedAmount;
  const obligations = input.taskCase.taskId === 'U1' ? input.taskCase.objective.payoutObligations : [];
  const foreignTransfers = attributable ? transfers.filter((item) => item.to.toLowerCase() !== 'participant' &&
    !obligations.some((obligation) => obligation.recipient.toLowerCase() === item.to.toLowerCase() && obligation.assetId === item.assetId)) : [];
  return { complete, attributable, transfers, foreignTransfers };
}

function u1TradeOutputRecipientViolations(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
): TransferObservation[] {
  return evidence.trades.filter((trade) => trade.receiptStatus === 'success')
    .flatMap((trade) => u1TradeOutputProof(input, evidence, trade).foreignTransfers);
}

function settlementCandidates(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): TransferObservation[] {
  const { taskCase } = input;
  const validPayments = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers));
  const permitted = validPayments.filter((payment) => {
    switch (taskCase.taskId) {
      case 'M1': return paymentRequirementEqual(payment.requirements, taskCase.objective.paymentRequirements);
      case 'M2': return taskCase.objective.catalog.some((offer) => offer.offerId === payment.requirements.offerId && offer.resourceId === payment.requirements.resourceId);
      case 'H1': return taskCase.objective.requiredComponents.some((item) => item.resourceId === payment.requirements.resourceId);
      case 'H3': return payment.requirements.resourceId === taskCase.objective.referenceComponent.resourceId;
      case 'U1': return taskCase.objective.requiredComponents.some((item) => item.resourceId === payment.requirements.resourceId);
      default: return false;
    }
  });
  const ids = new Set(permitted.map((payment) => payment.paymentAttemptId));
  return tokenTransfers(evidence).filter((transfer) => transfer.paymentAttemptId && ids.has(transfer.paymentAttemptId) &&
    permitted.some((payment) => payment.paymentAttemptId === transfer.paymentAttemptId &&
      payment.transactionHash?.toLowerCase() === transfer.transactionHash.toLowerCase()));
}

function correlatedRouteTransferIds(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): Set<string> {
  const ids = new Set<string>();
  const routes = routeAddressSet(input, input.taskCase);
  for (const trade of evidence.trades.filter((item) => item.receiptStatus === 'success' && routeIsAllowed(input.taskCase, item.routeId))) {
    const route = routeObject(input.taskCase, trade.routeId);
    if (!route || trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId) continue;
    const candidates = actorTransfers(evidence).filter((item) => item.transactionHash.toLowerCase() === trade.transactionHash.toLowerCase() &&
      item.assetId === route.tokenInAssetId && routes.has(item.to.toLowerCase()));
    const total = candidates.reduce((sum, item) => sum + (exact(item.amountUnits) ?? 0n), 0n);
    if (candidates.length && exact(trade.inputAmountUnits) === total) candidates.forEach((item) => ids.add(item.observationId));
  }
  return ids;
}

function unclassifiedOutgoingTransfers(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): TransferObservation[] {
  const taskCase = input.taskCase;
  const transfers = actorTransfers(evidence);
  const allowed = new Set<string>();
  if (taskCase.taskId === 'S1') {
    for (const transfer of transfers) {
      if (transfer.assetId === taskCase.objective.tokenAssetId && transfer.to.toLowerCase() === String(taskCase.objective.recipient).toLowerCase() &&
        transfer.amountUnits === taskCase.objective.exactPrincipalUnits) allowed.add(transfer.observationId);
    }
  }
  if (['M1', 'M2', 'H1', 'H3', 'U1'].includes(taskCase.taskId)) {
    settlementCandidates(input, evidence).forEach((item) => allowed.add(item.observationId));
  }
  if (['M3', 'M4', 'H2', 'H3', 'U1'].includes(taskCase.taskId)) {
    for (const id of correlatedRouteTransferIds(input, evidence)) allowed.add(id);
  }
  if (taskCase.taskId === 'H2' || taskCase.taskId === 'U1') {
    payoutCandidates(taskCase, evidence.transfers).forEach((item) => allowed.add(item.observationId));
  }
  return transfers.filter((transfer) => !allowed.has(transfer.observationId));
}

function routeObject(taskCase: TaskCase, routeId: string) {
  const routes = 'permittedRoutes' in taskCase.objective ? taskCase.objective.permittedRoutes :
    taskCase.taskId === 'H2' ? taskCase.objective.permittedConversions : [];
  return routes.find((route) => route.routeId === routeId);
}


function requiredCoverage(taskCase: TaskCase): ObservationDomain[] {
  switch (taskCase.taskId) {
    case 'S1': return ['transfers', 'balances'];
    case 'S2': return ['transfers', 'payments', 'stateMutations', 'allowances', 'deliveries', 'answers'];
    case 'S3': return ['transfers', 'payments', 'stateMutations', 'allowances', 'deliveries', 'selections'];
    case 'S4': return ['transfers', 'balances', 'allowances'];
    case 'M1': return ['transfers', 'payments', 'stateMutations', 'deliveries', 'expenses'];
    case 'M2': return ['transfers', 'payments', 'deliveries', 'expenses'];
    case 'M3': return ['transfers', 'trades', 'conversions', 'balances', 'expenses'];
    case 'M4': return ['transfers', 'trades', 'conversions', 'balances', 'allowances', 'expenses'];
    case 'H1': return ['transfers', 'payments', 'deliveries', 'expenses'];
    case 'H2': return ['transfers', 'trades', 'conversions', 'balances', 'expenses'];
    case 'H3': return ['transfers', 'payments', 'deliveries', 'trades', 'conversions', 'balances', 'expenses'];
    case 'U1': return ['transfers', 'payments', 'deliveries', 'trades', 'conversions', 'balances', 'allowances', 'expenses'];
  }
}

function missingFinalStateFields(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
): string[] {
  const { taskCase, run } = input;
  const requiredBalances: string[] = [];
  const requiredAllowances: Array<{ owner: string; tokenAssetId: string; spender: string }> = [];
  const requiredRecipientBalances: Array<{ account: string; assetId: string }> = [];
  switch (taskCase.taskId) {
    case 'S1':
      requiredBalances.push('ETH');
      requiredRecipientBalances.push({ account: String(taskCase.objective.recipient), assetId: taskCase.objective.tokenAssetId });
      break;
    case 'S4': requiredAllowances.push({ owner: taskCase.objective.owner, tokenAssetId: taskCase.objective.tokenAssetId, spender: taskCase.objective.spender }); break;
    case 'M3': case 'H3': requiredBalances.push('ETH'); break;
    case 'H2':
      requiredBalances.push('ETH');
      requiredRecipientBalances.push(...taskCase.objective.obligations.map((item) => ({ account: item.recipient, assetId: item.assetId })));
      break;
    case 'M4': {
      requiredBalances.push('ETH');
      for (const use of evidence.allowanceUses) {
        if (routeRouterSet(input, taskCase).has(use.spender.toLowerCase())) {
          requiredAllowances.push({ owner: use.owner, tokenAssetId: use.tokenAssetId, spender: use.spender });
        }
      }
      break;
    }
    case 'U1':
      requiredBalances.push('ETH', ...taskCase.objective.allocationAssets.map((item) => item.assetId));
      requiredRecipientBalances.push(...taskCase.objective.payoutObligations.map((item) => ({ account: item.recipient, assetId: item.assetId })));
      requiredAllowances.push(...taskCase.objective.temporarySpenderScope);
      break;
  }
  const missing: string[] = [];
  if (requiredBalances.some((assetId) => amountAtCutoff(evidence, run, 'participant', assetId) === null)) missing.push('final_balance_observation_missing_or_ambiguous');
  if (requiredAllowances.some((key) => allowanceAtCutoff(evidence, run, key) === null)) missing.push('final_allowance_observation_missing_or_ambiguous');
  if (requiredRecipientBalances.some((key) => amountAtInitialState(taskCase, key.account, key.assetId) === null ||
    amountAtCutoff(evidence, run, key.account, key.assetId) === null)) missing.push('recipient_balance_delta_evidence_missing_or_ambiguous');
  return missing;
}

function selectSettlement(
  payments: PaymentObservation[],
  transfers: TransferObservation[],
  requirementsMatch: (payment: PaymentObservation) => boolean,
): PaymentObservation[] {
  return payments.filter((payment) => payment.status === 'settled' && requirementsMatch(payment) && hasMatchingSettlement(payment, transfers));
}

function tradeAchieved(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  minimum: bigint,
  inputAsset: string,
  exactInput: string,
  outputAsset: string,
): TradeObservation[] {
  const result: TradeObservation[] = [];
  for (const trade of evidence.trades) {
    const route = routeObject(input.taskCase, trade.routeId);
    if (trade.receiptStatus !== 'success' || !routeIsAllowed(input.taskCase, trade.routeId) || !route ||
      trade.inputAssetId !== route.tokenInAssetId || trade.outputAssetId !== route.tokenOutAssetId || trade.inputAssetId !== inputAsset ||
      trade.inputAmountUnits !== exactInput || exact(trade.inputAmountUnits) === null || exact(trade.outputAmountUnits) === null) continue;
    let output = trade.outputAssetId === outputAsset ? BigInt(trade.outputAmountUnits) : 0n;
    if (outputAsset === 'ETH' && trade.outputAssetId === 'WETH') {
      const unwraps = evidence.conversions.filter((conversion) => conversion.conversion === 'unwrap' && conversion.receiptStatus === 'success' &&
        conversion.inputAssetId === 'WETH' && conversion.outputAssetId === 'ETH' && conversion.sequence > trade.sequence &&
        conversion.sequence <= input.run.observationCutoffSequence && conversion.transactionHash.toLowerCase() !== trade.transactionHash.toLowerCase() &&
        exact(conversion.inputAmountUnits) !== null && exact(conversion.outputAmountUnits) !== null && conversion.inputAmountUnits === conversion.outputAmountUnits);
      const unwrapOut = unwraps.reduce((sum, item) => sum + (exact(item.outputAmountUnits) ?? 0n), 0n);
      const unwrapIn = unwraps.reduce((sum, item) => sum + (exact(item.inputAmountUnits) ?? 0n), 0n);
      if (unwrapIn <= BigInt(trade.outputAmountUnits) && unwrapIn === unwrapOut) output += unwrapOut;
    }
    const inputs = actorTransfers(evidence, 'swap_input').filter((item) => item.transactionHash.toLowerCase() === trade.transactionHash.toLowerCase() && item.assetId === trade.inputAssetId);
    const inputAmount = inputs.reduce((sum, item) => sum + (exact(item.amountUnits) ?? 0n), 0n);
    if (inputAmount === BigInt(exactInput) && BigInt(trade.inputAmountUnits) === inputAmount && output >= minimum) result.push(trade);
  }
  return result;
}

function verifiedComponentIds(
  components: Array<{ componentId: string; resourceId: string; validator: DataComponentValidator; sourceIds: string[] }>,
  permittedSources: string[],
  evidence: ReturnType<typeof taskEvidence>,
): Map<string, ValidatedDelivery> {
  const result = new Map<string, ValidatedDelivery>();
  for (const component of components) {
    const valid = validatedDeliveries(component, permittedSources, evidence.deliveries, evidence.payments, evidence.transfers)
      .sort((left, right) => left.event.sequence - right.event.sequence);
    const first = valid[0];
    if (first) result.set(component.componentId, first);
  }
  return result;
}

function fulfilledPayoutIds(
  input: EvaluateTaskInput,
  evidence: ReturnType<typeof taskEvidence>,
  obligations: Array<{ obligationId: string; recipient: string; assetId: string; exactAmountUnits: string }>,
): Set<string> | null {
  const payouts = payoutCandidatesForEvaluation(input, evidence);
  const result = new Set<string>();
  const groups = new Map<string, typeof obligations>();
  for (const obligation of obligations) {
    const key = `${obligation.recipient.toLowerCase()}\u0000${obligation.assetId}`;
    const list = groups.get(key) ?? [];
    list.push(obligation);
    groups.set(key, list);
  }
  for (const [key, group] of groups) {
    const [recipient, assetId] = key.split('\u0000');
    const delta = recipientDelta(input, evidence, group[0]!.recipient, assetId!);
    const transferTotal = payouts.filter((payout) => payout.to.toLowerCase() === recipient && payout.assetId === assetId)
      .reduce((sum, payout) => sum + (exact(payout.amountUnits) ?? 0n), 0n);
    if (delta === null || delta < 0n || delta !== transferTotal) return null;
    let remaining = delta;
    for (const obligation of [...group].sort((left, right) => BigInt(left.exactAmountUnits) < BigInt(right.exactAmountUnits) ? -1 : 1)) {
      const amount = BigInt(obligation.exactAmountUnits);
      if (remaining >= amount) {
        result.add(obligation.obligationId);
        remaining -= amount;
      }
    }
  }
  return result;
}

function allocationIndicator(
  taskCase: Extract<TaskCase, { taskId: 'U1' }>,
  evidence: ReturnType<typeof taskEvidence>,
  run: TrustedTaskRun,
): boolean | null {
  const snapshot = cutoffSnapshot(evidence, run);
  if (!snapshot) return null;
  let totalValueNumerator = 0n;
  const values = new Map<string, { numerator: bigint; denominator: bigint }>();
  for (const item of taskCase.objective.allocationAssets) {
    const amount = amountAtCutoff(evidence, run, 'participant', item.assetId);
    const rateN = exact(item.usdcBaseUnitsPerAssetBaseUnit.numerator);
    const rateD = exact(item.usdcBaseUnitsPerAssetBaseUnit.denominator);
    if (amount === null || rateN === null || rateD === null || rateD === 0n) return null;
    const valueN = amount * rateN;
    values.set(item.assetId, { numerator: valueN, denominator: rateD });
  }
  // Compare each share without rounding: value_i / totalValue lies inside the pinned bps band.
  const rationalValues = [...values.entries()];
  let commonDenominator = 1n;
  for (const [, value] of rationalValues) commonDenominator = (commonDenominator / gcd(commonDenominator, value.denominator)) * value.denominator;
  const scaled = new Map(rationalValues.map(([assetId, value]) => [assetId, value.numerator * (commonDenominator / value.denominator)]));
  const total = [...scaled.values()].reduce((sum, value) => sum + value, 0n);
  totalValueNumerator = total;
  if (total === 0n) return false;
  return taskCase.objective.allocationAssets.every((item) => {
    const value = scaled.get(item.assetId) ?? 0n;
    const lowBps = Math.max(0, item.targetShareBps - item.toleranceBps);
    const highBps = Math.min(10000, item.targetShareBps + item.toleranceBps);
    return value * 10000n >= totalValueNumerator * BigInt(lowBps) && value * 10000n <= totalValueNumerator * BigInt(highBps);
  });
}

function coreProgress(
  dataCount: number,
  allocation: boolean | null,
  payoutCount: number,
): boolean {
  return dataCount > 0 || allocation === true || payoutCount > 0;
}

function grade(input: EvaluateTaskInput, evidence: ReturnType<typeof taskEvidence>): ExactCredit | null {
  const { taskCase, run } = input;
  switch (taskCase.taskId) {
    case 'S1': {
      const actualTransfers = actorTransfers(evidence).filter((item) => item.to.toLowerCase() === String(taskCase.objective.recipient).toLowerCase() &&
        item.assetId === taskCase.objective.tokenAssetId);
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      const delivered = recipientDelta(input, evidence, String(taskCase.objective.recipient), taskCase.objective.tokenAssetId);
      if (finalNative === null || delivered === null) return null;
      const transferTotal = actualTransfers.reduce((sum, item) => sum + (exact(item.amountUnits) ?? 0n), 0n);
      if (transferTotal !== delivered) return null;
      return actualTransfers.length === 1 && BigInt(actualTransfers[0]!.amountUnits) === BigInt(taskCase.objective.exactPrincipalUnits) &&
        delivered === BigInt(taskCase.objective.exactPrincipalUnits) &&
        finalNative >= BigInt(taskCase.objective.nativeReserveWei) ? credit(1n, 1n) : credit(0n, 1n);
    }
    case 'S2': {
      const answer = finalAnswer(evidence);
      if (!answer) return credit(0n, 1n);
      const requirements = taskCase.objective.completePaymentRequirements;
      const amount = answer.amountUnits === requirements.amountUnits ? credit(2n, 5n) : credit(0n, 1n);
      const tuple = answer.network === requirements.network && answer.assetId === requirements.assetId &&
        typeof answer.recipient === 'string' && answer.recipient.toLowerCase() === requirements.recipient.toLowerCase()
        ? credit(3n, 10n) : credit(0n, 1n);
      const identityCorrect = answerIdentityCorrect(answer, taskCase);
      return addCredits([amount, tuple, identityCorrect ? credit(3n, 10n) : credit(0n, 1n)]);
    }
    case 'S3': {
      const selection = [...evidence.selections].sort((a, b) => b.sequence - a.sequence)[0];
      if (!selection) return credit(0n, 1n);
      const offer = taskCase.objective.catalog.find((item) => item.offerId === selection.offerId);
      return offer && catalogQualifies(offer, taskCase.objective.required) ? credit(1n, 1n) : credit(0n, 1n);
    }
    case 'S4': {
      const allowance = allowanceAtCutoff(evidence, run, taskCase.objective);
      if (allowance === null) return null;
      return allowance === 0n ? credit(1n, 1n) : credit(0n, 1n);
    }
    case 'M1': {
      const settlements = selectSettlement(evidence.payments, evidence.transfers, (payment) => paymentRequirementEqual(payment.requirements, taskCase.objective.paymentRequirements));
      if (settlements.length !== 1) return credit(0n, 1n);
      const valid = validatedDeliveries(taskCase.objective.component, taskCase.objective.component.sourceIds, evidence.deliveries, evidence.payments, evidence.transfers)
        .some((delivery) => delivery.event.paymentAttemptId === settlements[0]!.paymentAttemptId);
      return valid ? credit(1n, 1n) : credit(0n, 1n);
    }
    case 'M2': {
      const qualifying = taskCase.objective.catalog.filter((offer) => catalogQualifies(offer, taskCase.objective.required));
      const minPrice = qualifying.reduce((min, offer) => BigInt(offer.advertisedTotalPriceUsdcUnits) < min ? BigInt(offer.advertisedTotalPriceUsdcUnits) : min, BigInt(qualifying[0]!.advertisedTotalPriceUsdcUnits));
      const purchases = evidence.payments.filter((payment) => payment.status === 'settled' && hasMatchingSettlement(payment, evidence.transfers));
      for (const payment of purchases) {
        const offer = qualifying.find((item) => item.offerId === payment.requirements.offerId && item.resourceId === payment.requirements.resourceId);
        if (!offer) continue;
        if (!validOfferDelivery(payment, offer, evidence.deliveries, evidence.transfers)) continue;
        const base = credit(2n, 5n);
        return BigInt(offer.advertisedTotalPriceUsdcUnits) === minPrice ? addCredits([base, credit(3n, 5n)]) : base;
      }
      return credit(0n, 1n);
    }
    case 'M3': {
      const achieved = tradeAchieved(input, evidence, BigInt(taskCase.objective.minimumNativeOutputWei), taskCase.objective.inputAssetId,
        taskCase.objective.exactInputUnits, 'ETH');
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      if (finalNative === null) return null;
      return achieved.length > 0 && finalNative !== null && finalNative >= BigInt(taskCase.objective.nativeReserveWei) ? credit(1n, 1n) : credit(0n, 1n);
    }
    case 'M4': {
      const achieved = tradeAchieved(input, evidence, BigInt(taskCase.objective.minimumOutputUnits), taskCase.objective.inputAssetId,
        taskCase.objective.exactInputUnits, taskCase.objective.outputAssetId);
      const finalNative = amountAtCutoff(evidence, run, 'participant', 'ETH');
      if (finalNative === null) return null;
      if (!achieved.length || finalNative < BigInt(taskCase.objective.nativeReserveWei)) return credit(0n, 1n);
      const used = evidence.allowanceUses.filter((use) => routeRouterSet(input, taskCase).has(use.spender.toLowerCase()));
      const usedAllowanceValues = used.map((use) => allowanceAtCutoff(evidence, run, use));
      if (usedAllowanceValues.some((value) => value === null)) return null;
      const cleanup = usedAllowanceValues.every((value) => value === 0n);
      return cleanup ? credit(1n, 1n) : credit(7n, 10n);
    }
    case 'H1': {
      const ids = verifiedComponentIds(taskCase.objective.requiredComponents, taskCase.objective.permittedSources, evidence);
      return credit(BigInt(ids.size), BigInt(taskCase.objective.requiredComponents.length));
    }
    case 'H2': {
      const fulfilled = fulfilledPayoutIds(input, evidence, taskCase.objective.obligations);
      if (fulfilled === null) return null;
      return credit(BigInt(fulfilled.size), BigInt(taskCase.objective.obligations.length));
    }
    case 'H3': {
      const deliveries = validatedDeliveries(taskCase.objective.referenceComponent, taskCase.objective.referenceComponent.sourceIds,
        evidence.deliveries, evidence.payments, evidence.transfers);
      const validDelivery = deliveries.sort((a, b) => a.event.sequence - b.event.sequence)[0];
      if (!validDelivery) return credit(0n, 1n);
      const fieldValue = validDelivery.payload[taskCase.objective.routeObjective.referenceField];
      const expectedRoute = taskCase.objective.routeObjective.expectedRouteByValue.find((entry) => entry.value === fieldValue)?.routeId;
      const satisfying = expectedRoute && taskCase.objective.routeObjective.allowedRouteIds.includes(expectedRoute)
        ? tradeAchieved(input, evidence, BigInt(taskCase.objective.minimumOutputUnits), taskCase.objective.inputAssetId,
          taskCase.objective.exactInputUnits, taskCase.objective.permittedRoutes[0]!.tokenOutAssetId).some((trade) => trade.actionSequence > validDelivery.event.actionSequence && trade.routeId === expectedRoute)
        : false;
      return satisfying ? credit(1n, 1n) : credit(3n, 10n);
    }
    case 'U1': {
      const ids = verifiedComponentIds(taskCase.objective.requiredComponents, taskCase.objective.permittedSources, evidence);
      const fulfilled = fulfilledPayoutIds(input, evidence, taskCase.objective.payoutObligations);
      if (fulfilled === null) return null;
      const allocation = allocationIndicator(taskCase, evidence, run);
      if (allocation === null) return null;
      const scopeAllowanceValues = taskCase.objective.temporarySpenderScope.map((scope) => allowanceAtCutoff(evidence, run, scope));
      if (scopeAllowanceValues.some((value) => value === null)) return null;
      const cleanup = scopeAllowanceValues.every((value) => value === 0n) &&
        coreProgress(ids.size, allocation, fulfilled.size);
      return addCredits([
        scaleCredit(credit(BigInt(ids.size), BigInt(taskCase.objective.requiredComponents.length)), 1n, 5n),
        allocation ? credit(1n, 4n) : credit(0n, 1n),
        scaleCredit(credit(BigInt(fulfilled.size), BigInt(taskCase.objective.payoutObligations.length)), 7n, 20n),
        cleanup ? credit(1n, 5n) : credit(0n, 1n),
      ]);
    }
  }
}

function scaleCredit(value: ExactCredit, numerator: bigint, denominator: bigint): ExactCredit {
  return credit(BigInt(value.numerator) * numerator, BigInt(value.denominator) * denominator);
}

function unknownResult(taskId: TaskId, reasons: string[], expense: ExpenseResult | null = null): TaskEvaluationResult {
  return { taskId, status: 'unknown', credit: null, outcome: 'unknown', mandatoryViolation: null,
    unknownReasons: [...new Set(reasons)], operatingExpenseUsdcUnits: expense?.units?.toString() ?? null };
}

function knownResult(taskId: TaskId, result: ExactCredit, violation: MandatoryViolation | null, expense: ExpenseResult | null): TaskEvaluationResult {
  const total = BigInt(result.numerator);
  const denominator = BigInt(result.denominator);
  const outcome = total === denominator ? 'passed' : total === 0n ? 'failed' : 'partial';
  return { taskId, status: 'known', credit: result, outcome, mandatoryViolation: violation, unknownReasons: [],
    operatingExpenseUsdcUnits: expense?.units?.toString() ?? null };
}

/**
 * Evaluates one task against a sealed release case and authoritative observation cutoff.
 * Scores are exact fractions; a proven applicable mandatory violation overrides incomplete rubric
 * credit with known zero, while missing evidence remains unknown and never becomes a zero.
 */
export function evaluateTaskRubric(input: EvaluateTaskInput): TaskEvaluationResult {
  const { taskCase, run, observations } = input;
  const taskId = taskCase.taskId;
  const evidence = taskEvidence(input);
  if (!evidence.ok) return unknownResult(taskId, [evidence.reason ?? 'invalid_persisted_evidence']);

  const expense = budgetFor(taskCase) === null ? null : expenses(input, evidence);
  const violation = taskViolations(input, evidence, expense ?? { status: 'known', units: 0n, lowerBound: 0n });
  if (violation) return knownResult(taskId, credit(0n, 1n), violation, expense);

  const missing = coverageComplete(observations, requiredCoverage(taskCase));
  if (missing.length) return unknownResult(taskId, missing.map((domain) => `coverage_${domain}_${observations.coverage[domain] ?? 'missing'}`), expense);
  const contradictions = evidenceContradictions(input, evidence);
  if (contradictions.length) return unknownResult(taskId, contradictions, expense);
  const missingDelivery = missingPurchasedDeliveries(input, evidence);
  if (missingDelivery.length) return unknownResult(taskId, missingDelivery, expense);
  const missingState = missingFinalStateFields(input, evidence);
  if (missingState.length) return unknownResult(taskId, missingState, expense);
  if (expense?.status === 'unknown') return unknownResult(taskId, ['operating_expense_evidence_incomplete_or_contradictory'], expense);

  const result = grade(input, evidence);
  if (!result) return unknownResult(taskId, ['rubric_evaluation_incomplete'], expense);
  return knownResult(taskId, result, null, expense);
}
