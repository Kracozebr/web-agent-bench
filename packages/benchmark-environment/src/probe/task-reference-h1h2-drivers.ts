/**
 * Same-generation H1 component and H2 payout reference observations.
 * These are local reference profiles, never release manifests or task scores.
 */
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { encodeFunctionData, parseAbi } from 'viem';
import type { Address } from 'viem';
import type { RuntimeManifest } from '../manifest.js';
import { apiPath } from './environment.js';
import { sanitizeValue } from './evidence.js';
import type { GenerationSession, ProbeContext } from './runner.js';
import type { SelectedExecutionTransactionEvidence } from './rpc.js';
import { transferEvents } from './rpc.js';
import {
  latestBlock,
  readCaseDatabaseFacts,
  readCaseState,
  readRpc,
  readTokenValue,
  startFreshCaseGeneration,
  type CaseDatabaseFacts,
} from './task-reference-case-drivers.js';
import { canonicalSha256, type DataComponentProjection } from './task-reference-cases.js';
import { createEphemeralSigner } from './x402.js';

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]*)$/;
const TRANSFER_ABI = parseAbi(['function transfer(address to,uint256 amount) returns (bool)']);
const COST_ROUNDING_QUANTUM_USDC_UNITS = 10_000n;
const LOCAL_H2_NATIVE_RESERVE_WEI = 10_000_000_000_000_000n;
const DIFFICULTY_PROFILE_RELATIVE_PATH = 'infrastructure/owner-identity/task-difficulty-profile-v2.json';
const DIFFICULTY_PROFILE_ID = 'bts-task-difficulty-v2';
const DIFFICULTY_PROFILE_SCHEMA = 'bts-task-case-input-profile/v2';
const H1_REQUIRED_RESOURCES = ['bef-resource-v1', 'bef-market-state-brief-v1', 'bef-treasury-risk-policy-v2'] as const;

type DifficultyProfileMode = 'ranked' | 'training';
type DifficultyProfileSource = { profile: Record<string, unknown>; path: string; sha256: string };
type H1ProfileComponent = { resourceId: string; offerId: string; amountUsdcUnits: string };
type H2ProfileObligation = { obligationId: string; recipient: string; amountUsdcUnits: string };

/** Validate observed recipient baselines without inferring absent or malformed balances as zero. */
export function h2InitialRecipientBalancesMatchPolicy(
  recipients: readonly string[], balances: Record<string, string>, requireZero: boolean,
): boolean {
  return recipients.every((recipient) => {
    if (!Object.hasOwn(balances, recipient)) return false;
    const value = balances[recipient];
    return typeof value === 'string' && UINT.test(value) && (!requireZero || value === '0');
  });
}

/** Compare final balances to the actual measured baseline for every exact obligation. */
export function h2RecipientDeltasMatchObligations(
  obligations: readonly { recipient: string; amountUnits: string }[],
  initialBalances: Record<string, string>,
  finalBalances: Record<string, string>,
): boolean {
  return obligations.every(({ recipient, amountUnits }) => {
    if (!Object.hasOwn(initialBalances, recipient) || !Object.hasOwn(finalBalances, recipient)) return false;
    const initial = initialBalances[recipient];
    const final = finalBalances[recipient];
    if (typeof initial !== 'string' || !UINT.test(initial) || typeof final !== 'string' || !UINT.test(final)
      || !UINT.test(amountUnits)) return false;
    return BigInt(final) - BigInt(initial) === BigInt(amountUnits);
  });
}

async function loadDifficultyProfileV2(ctx: ProbeContext): Promise<DifficultyProfileSource> {
  const path = resolve(ctx.runtime.root, DIFFICULTY_PROFILE_RELATIVE_PATH);
  const bytes = await readFile(path);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')) as unknown; }
  catch { throw new Error('task_reference_difficulty_profile_json_invalid'); }
  const profile = record(parsed);
  const compatibility = record(profile?.compatibility);
  const manifestPin = record(profile?.runtimeManifest);
  const measurementBoundary = record(profile?.measurementBoundary);
  if (!profile || profile.schemaVersion !== DIFFICULTY_PROFILE_SCHEMA || profile.profileId !== DIFFICULTY_PROFILE_ID
    || profile.classification !== 'candidate_case_inputs_not_capture_or_release'
    || profile.status !== 'source_profile_candidate_unactivated'
    || compatibility?.defaultProfile !== 'legacy' || compatibility.legacyCapturesAreImmutable !== true
    || compatibility.v2RequiresExplicitSelection !== true
    || manifestPin?.path !== 'infrastructure/benchmark-environment/manifest.json'
    || typeof manifestPin.sha256 !== 'string' || manifestPin.sha256.toLowerCase() !== ctx.runtime.manifestSha256.toLowerCase()
    || measurementBoundary?.approvalStatus !== 'not claimed'
    || measurementBoundary.releaseReadiness !== 'blocked_until_fresh_capture_and_release_review') {
    throw new Error('task_reference_difficulty_profile_pin_or_classification_mismatch');
  }
  return { profile, path: DIFFICULTY_PROFILE_RELATIVE_PATH, sha256 };
}

function modeRecord(profile: Record<string, unknown>, taskId: 'H1' | 'H2', mode: DifficultyProfileMode): {
  task: Record<string, unknown>;
  mode: Record<string, unknown>;
} {
  const tasks = record(profile.tasks);
  const task = record(tasks?.[taskId]);
  const modes = record(task?.modes);
  const modeValues = record(modes?.[mode]);
  if (!task || !modeValues) throw new Error(`task_reference_${taskId.toLowerCase()}_difficulty_profile_mode_missing`);
  return { task, mode: modeValues };
}

function difficultyProfileH1Components(
  ctx: ProbeContext,
  source: DifficultyProfileSource,
  mode: DifficultyProfileMode,
): H1ProfileComponent[] {
  const { task, mode: modeValues } = modeRecord(source.profile, 'H1', mode);
  const actions = Array.isArray(task.participantActionPlan) ? task.participantActionPlan : [];
  const requiredResources = Array.isArray(task.requiredResources) ? task.requiredResources : [];
  const values = Array.isArray(modeValues.components) ? modeValues.components.map(record) : [];
  const expectedActions = ['inspect_catalog', 'pay:component-1', 'retrieve:component-1', 'pay:component-2',
    'retrieve:component-2', 'pay:component-3', 'retrieve:component-3'];
  const requiredSet = new Set(requiredResources.filter((value): value is string => typeof value === 'string'));
  if (task.requiredDistinctPaidComponents !== 3 || task.countedParticipantActions !== 7
    || JSON.stringify(actions) !== JSON.stringify(expectedActions)
    || requiredSet.size !== H1_REQUIRED_RESOURCES.length || H1_REQUIRED_RESOURCES.some((id) => !requiredSet.has(id))
    || values.length !== 3 || values.some((value) => value === null)) {
    throw new Error('task_reference_h1_difficulty_profile_shape_invalid');
  }
  const components = values.map((value) => ({
    resourceId: exactString(value!.resourceId, 'h1_profile_resource_id'),
    offerId: exactString(value!.offerId, 'h1_profile_offer_id'),
    amountUsdcUnits: exactString(value!.amountUsdcUnits, 'h1_profile_amount'),
  }));
  if (new Set(components.map((value) => value.resourceId)).size !== 3
    || H1_REQUIRED_RESOURCES.some((id) => !components.some((component) => component.resourceId === id))) {
    throw new Error('task_reference_h1_difficulty_profile_resources_not_distinct');
  }
  for (const component of components) {
    if (!UINT.test(component.amountUsdcUnits) || BigInt(component.amountUsdcUnits) <= 0n) {
      throw new Error('task_reference_h1_difficulty_profile_amount_invalid');
    }
    const definition = ctx.runtime.manifest.x402.catalog?.find((item) => item.resourceId === component.resourceId);
    const offer = definition?.offers.find((item) => item.id === component.offerId);
    if (!definition || !offer || offer.amount !== component.amountUsdcUnits) {
      throw new Error('task_reference_h1_difficulty_profile_offer_pin_mismatch');
    }
  }
  return components;
}

function difficultyProfileH2Obligations(
  ctx: ProbeContext,
  source: DifficultyProfileSource,
  mode: DifficultyProfileMode,
): H2ProfileObligation[] {
  const { task, mode: modeValues } = modeRecord(source.profile, 'H2', mode);
  const actions = Array.isArray(task.participantActionPlan) ? task.participantActionPlan : [];
  const values = Array.isArray(modeValues.obligations) ? modeValues.obligations.map(record) : [];
  const expectedActions = Array.from({ length: 6 }, (_, index) => `transfer:obligation-${index + 1}`);
  const expectedObligationIds = Array.from({ length: 6 }, (_, index) => `h2-usdc-payout-${index + 1}`);
  if (task.requiredDistinctObligations !== 6 || task.countedParticipantActions !== 6 || task.assetId !== 'USDC'
    || task.recipientIdentityPolicy !== 'deterministic_synthetic_public_addresses_no_recipient_private_keys'
    || JSON.stringify(actions) !== JSON.stringify(expectedActions) || values.length !== 6 || values.some((value) => value === null)) {
    throw new Error('task_reference_h2_difficulty_profile_shape_invalid');
  }
  const obligations = values.map((value, index) => ({
    obligationId: exactString(value!.obligationId, 'h2_profile_obligation_id'),
    recipient: exactString(value!.recipient, 'h2_profile_recipient').toLowerCase(),
    amountUsdcUnits: exactString(value!.amountUsdcUnits, 'h2_profile_amount'),
  }));
  if (obligations.some((value, index) => value.obligationId !== expectedObligationIds[index]
    || !ADDRESS.test(value.recipient) || !UINT.test(value.amountUsdcUnits) || BigInt(value.amountUsdcUnits) <= 0n)
    || new Set(obligations.map((value) => value.recipient)).size !== 6) {
    throw new Error('task_reference_h2_difficulty_profile_obligations_invalid');
  }
  const services = record(ctx.capability.services);
  const facilitator = record(services?.facilitator);
  const facilitatorAddress = exactString(facilitator?.address, 'h2_facilitator_address').toLowerCase();
  if (!ADDRESS.test(facilitatorAddress)) throw new Error('task_reference_h2_facilitator_address_invalid');
  const contractAddresses = new Set<string>();
  const collectAddresses = (value: unknown): void => {
    if (typeof value === 'string' && ADDRESS.test(value)) contractAddresses.add(value.toLowerCase());
    else if (Array.isArray(value)) value.forEach(collectAddresses);
    else {
      const object = record(value);
      if (object) Object.values(object).forEach(collectAddresses);
    }
  };
  collectAddresses(ctx.runtime.manifest.contracts);
  const protectedAddresses = new Set([
    `0x${'0'.repeat(40)}`,
    ctx.runtime.manifest.funding.donor.toLowerCase(),
    facilitatorAddress,
    ...contractAddresses,
  ]);
  if (obligations.some((value) => protectedAddresses.has(value.recipient))) {
    throw new Error('task_reference_h2_difficulty_profile_recipient_collision');
  }
  return obligations;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function exactString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`task_reference_${label}_missing`);
  return value;
}

function unsigned(value: unknown, label: string): bigint {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'string' && (UINT.test(value) || /^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(value))) return BigInt(value);
  throw new Error(`task_reference_${label}_invalid`);
}

function ceilToMultiple(value: bigint, quantum: bigint): bigint {
  if (value < 0n || quantum <= 0n) throw new Error('task_reference_cost_rounding_input_invalid');
  return ((value + quantum - 1n) / quantum) * quantum;
}

export type ValidatedReferenceCost = {
  operationId: string;
  transactionHash: string;
  payerAddress: string;
  payerRole: 'participant' | 'facilitator';
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  modeledGasFeeUsdcUnitsPerReceipt: string;
  feeRateNumerator: string;
  feeRateDenominator: string;
  receiptStatus: 'success';
  baseL1FeeStatus: 'unmodelled';
};

export function validateReferenceCostRow(
  row: Record<string, unknown>,
  manifest: RuntimeManifest,
  expected: { operationId: string; transactionHash: string; payerRole: 'participant' | 'facilitator'; payerAddress?: string; manifestSha256: string },
): ValidatedReferenceCost {
  const operationId = exactString(row.operation_id, 'cost_operation_id');
  const transactionHash = exactString(row.transaction_hash, 'cost_transaction_hash');
  const payerAddress = exactString(row.payer_address, 'cost_payer_address').toLowerCase();
  const payerRole = row.payer_role;
  const receiptStatus = row.receipt_status;
  const gasUsed = unsigned(row.gas_used, 'cost_gas_used');
  const effectiveGasPriceWei = unsigned(row.effective_gas_price_wei, 'cost_effective_gas_price');
  const gasCostWei = unsigned(row.gas_cost_wei, 'cost_gas_cost');
  const modeledGasFee = unsigned(row.modeled_gas_fee_usdc_units, 'cost_modeled_gas_fee');
  const feeRateNumerator = unsigned(row.fee_rate_numerator, 'cost_fee_rate_numerator');
  const feeRateDenominator = unsigned(row.fee_rate_denominator, 'cost_fee_rate_denominator');
  const manifestNumerator = BigInt(manifest.feePolicy.ethUsdcRateNumerator);
  const manifestDenominator = BigInt(manifest.feePolicy.ethUsdcRateDenominator);
  const feePolicySnapshot = record(row.fee_policy_snapshot);
  if (payerRole !== 'participant' && payerRole !== 'facilitator') throw new Error('task_reference_cost_payer_role_invalid');
  if (!ADDRESS.test(payerAddress) || !HASH.test(transactionHash) || operationId !== expected.operationId
    || transactionHash.toLowerCase() !== expected.transactionHash.toLowerCase()
    || payerRole !== expected.payerRole || receiptStatus !== 'success'
    || (expected.payerAddress && payerAddress !== expected.payerAddress.toLowerCase())
    || String(row.transaction_from).toLowerCase() !== payerAddress || String(row.receipt_from).toLowerCase() !== payerAddress
    || gasUsed <= 0n || effectiveGasPriceWei <= 0n || gasCostWei !== gasUsed * effectiveGasPriceWei
    || feeRateNumerator !== manifestNumerator || feeRateDenominator !== manifestDenominator
    || feeRateDenominator <= 0n || modeledGasFee !== (gasCostWei * feeRateNumerator) / feeRateDenominator
    || feePolicySnapshot === null
    || feePolicySnapshot.ethUsdcRateNumerator !== manifestNumerator.toString()
    || feePolicySnapshot.ethUsdcRateDenominator !== manifestDenominator.toString()
    || feePolicySnapshot.baseFeeWei !== manifest.feePolicy.baseFeeWei
    || feePolicySnapshot.priorityFeeWei !== manifest.feePolicy.priorityFeeWei
    || feePolicySnapshot.rounding !== 'floor-to-6-decimal-usdc-units'
    || feePolicySnapshot.baseL1Fee !== 'unmodelled'
    || feePolicySnapshot.principalSeparateFromExpense !== true
    || String(row.manifest_sha256).trim() !== expected.manifestSha256
    || row.base_l1_fee_status !== 'unmodelled') {
    throw new Error('task_reference_cost_row_binding_mismatch');
  }
  return {
    operationId, transactionHash: transactionHash.toLowerCase(), payerAddress, payerRole,
    gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(), gasCostWei: gasCostWei.toString(),
    modeledGasFeeUsdcUnitsPerReceipt: modeledGasFee.toString(),
    feeRateNumerator: feeRateNumerator.toString(), feeRateDenominator: feeRateDenominator.toString(),
    receiptStatus: 'success', baseL1FeeStatus: 'unmodelled',
  };
}

export function aggregateReferenceCosts(costs: readonly ValidatedReferenceCost[]): {
  participantGasWei: bigint;
  participantReceiptRoundedGasUsdcUnits: bigint;
  facilitatorGasWei: bigint;
  facilitatorReceiptRoundedGasUsdcUnits: bigint;
  participantAggregateGasUsdcUnits: bigint;
  facilitatorAggregateGasUsdcUnits: bigint;
  rateNumerator: string;
  rateDenominator: string;
  costs: ValidatedReferenceCost[];
} {
  if (costs.length === 0) throw new Error('task_reference_cost_rows_missing');
  const transactionHashes = new Set<string>();
  const operationIds = new Set<string>();
  for (const cost of costs) {
    const transactionHash = cost.transactionHash.toLowerCase();
    const operationId = cost.operationId.toLowerCase();
    if (transactionHashes.has(transactionHash) || operationIds.has(operationId)) {
      throw new Error('task_reference_cost_duplicate_receipt');
    }
    transactionHashes.add(transactionHash);
    operationIds.add(operationId);
  }
  const rateNumerator = BigInt(costs[0]!.feeRateNumerator);
  const rateDenominator = BigInt(costs[0]!.feeRateDenominator);
  if (costs.some((cost) => cost.feeRateNumerator !== rateNumerator.toString() || cost.feeRateDenominator !== rateDenominator.toString())) {
    throw new Error('task_reference_cost_rate_changed_within_generation');
  }
  let participantGasWei = 0n;
  let participantReceiptRoundedGasUsdcUnits = 0n;
  let facilitatorGasWei = 0n;
  let facilitatorReceiptRoundedGasUsdcUnits = 0n;
  for (const cost of costs) {
    if (cost.payerRole === 'participant') {
      participantGasWei += BigInt(cost.gasCostWei);
      participantReceiptRoundedGasUsdcUnits += BigInt(cost.modeledGasFeeUsdcUnitsPerReceipt);
    } else {
      facilitatorGasWei += BigInt(cost.gasCostWei);
      facilitatorReceiptRoundedGasUsdcUnits += BigInt(cost.modeledGasFeeUsdcUnitsPerReceipt);
    }
  }
  const participantAggregateGasUsdcUnits = (participantGasWei * rateNumerator) / rateDenominator;
  const facilitatorAggregateGasUsdcUnits = (facilitatorGasWei * rateNumerator) / rateDenominator;
  return {
    participantGasWei, participantReceiptRoundedGasUsdcUnits,
    facilitatorGasWei, facilitatorReceiptRoundedGasUsdcUnits,
    participantAggregateGasUsdcUnits, facilitatorAggregateGasUsdcUnits,
    rateNumerator: rateNumerator.toString(), rateDenominator: rateDenominator.toString(),
    costs: costs.map((cost) => ({ ...cost })),
  };
}

function localBudget(measuredExpenseUsdcUnits: bigint): {
  measuredExpenseUsdcUnits: string;
  headroomPercent: 100;
  headroomMultiplier: '2/1';
  roundingQuantumUsdcUnits: string;
  budgetUsdcUnits: string;
  formula: string;
} {
  const budget = ceilToMultiple(2n * measuredExpenseUsdcUnits, COST_ROUNDING_QUANTUM_USDC_UNITS);
  return {
    measuredExpenseUsdcUnits: measuredExpenseUsdcUnits.toString(),
    headroomPercent: 100,
    headroomMultiplier: '2/1',
    roundingQuantumUsdcUnits: COST_ROUNDING_QUANTUM_USDC_UNITS.toString(),
    budgetUsdcUnits: budget.toString(),
    formula: 'ceilToMultiple(2 * (serviceChargesUsdcUnits + floor(sum(participantGasCostWei) * feeRateNumerator / feeRateDenominator) + declaredDexExpenseUsdcUnits), 10000)',
  };
}

function localDeadline(elapsedMs: number): { observedElapsedMs: number; measuredElapsedSecondsCeil: number; deadlineSeconds: number; formula: string } {
  const seconds = Math.ceil(elapsedMs / 1000);
  return {
    observedElapsedMs: Math.max(0, Math.trunc(elapsedMs)),
    measuredElapsedSecondsCeil: seconds,
    deadlineSeconds: Math.max(60, 2 * seconds),
    formula: 'max(60 seconds, 2 * ceil(measured end-to-end reference seconds))',
  };
}

type H1CandidateInput = {
  catalogCapture: unknown;
  deliveryProjections: ReadonlyArray<{
    operationId: string;
    projectionPath: string;
    rawContentPath: string;
    projection: unknown;
    component: DataComponentProjection;
    contentHash: string;
  }>;
  elapsedMs: number;
};

async function projectH1Candidate(
  ctx: ProbeContext,
  input: H1CandidateInput,
  profile: { mode: DifficultyProfileMode; source: DifficultyProfileSource; components: H1ProfileComponent[] } | null,
): Promise<Record<string, unknown>> {
  const componentCount = profile ? 3 : 2;
  const variantId = profile ? `bts_h1_${profile.mode}_difficulty_v2_reference` : 'bts_h1_two_component_reference';
  const capture = record(input.catalogCapture);
  if (profile) {
    const actions = Array.isArray(capture?.participantActions) ? capture.participantActions.map(record) : [];
    const expected = ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'];
    if (capture?.participantToolProtocol !== 'separate_payment_delivery_v2' || actions.length !== expected.length ||
      actions.some((action, index) => !action || action.kind !== expected[index] || typeof action.operationId !== 'string' ||
        typeof action.rawResponsePath !== 'string' || typeof action.rawResponseSha256 !== 'string')) {
      throw new Error('task_reference_h1_split_payment_trace_not_captured');
    }
  }
  const environment = record(capture?.environment);
  const purchases = Array.isArray(capture?.purchases) ? capture.purchases.map(record) : [];
  const envId = exactString(environment?.envId, 'h1_env_id');
  const generationId = exactString(environment?.generationId, 'h1_generation_id');
  const payerAddress = exactString(environment?.payerAddress, 'h1_payer_address').toLowerCase();
  if (!ADDRESS.test(payerAddress) || ctx.primaryGeneration?.generationId !== generationId
    || ctx.primaryGeneration.envId !== envId || purchases.length !== componentCount) {
    throw new Error('task_reference_h1_generation_or_component_count_invalid');
  }
  const purchaseIds = purchases.map((purchase) => exactString(purchase?.operationId, 'h1_operation_id'));
  const resourceIds = purchases.map((purchase) => exactString(purchase?.resourceId, 'h1_resource_id'));
  const transactionHashes = purchases.map((purchase) => exactString(purchase?.paymentTransactionHash, 'h1_payment_transaction_hash'));
  if (new Set(purchaseIds).size !== componentCount || new Set(resourceIds).size !== componentCount
    || new Set(transactionHashes.map((hash) => hash.toLowerCase())).size !== componentCount) {
    throw new Error('task_reference_h1_duplicate_purchase_or_component');
  }
  const projections = input.deliveryProjections.filter((item) => purchaseIds.includes(item.operationId));
  if (projections.length !== componentCount || new Set(projections.map((item) => item.component.resourceId)).size !== componentCount) {
    throw new Error(componentCount === 2
      ? 'task_reference_h1_two_validated_deliveries_required'
      : 'task_reference_h1_three_validated_deliveries_required');
  }
  if (profile && purchases.some((purchase, index) => {
    const expected = profile.components[index]!;
    return String(purchase?.resourceId) !== expected.resourceId || String(purchase?.offerId) !== expected.offerId
      || String(purchase?.amountUnits) !== expected.amountUsdcUnits;
  })) {
    throw new Error('task_reference_h1_difficulty_profile_purchase_binding_mismatch');
  }
  const facts = await readCaseDatabaseFacts(ctx, { envId, generationId }, 'h1-same-generation-database-facts', variantId);
  const countText = String(componentCount);
  if (facts.operations.length !== componentCount || facts.payments.length !== componentCount || facts.deliveries.length !== componentCount
    || facts.counts.purchaseOperations !== countText || facts.counts.payments !== countText || facts.counts.deliveries !== countText
    || facts.counts.transactionCosts !== countText) {
    throw new Error('task_reference_h1_same_generation_durable_rows_mismatch');
  }

  const validatedCosts: ValidatedReferenceCost[] = [];
  const components: Array<Record<string, unknown>> = [];
  let serviceCharges = 0n;
  for (let index = 0; index < purchases.length; index += 1) {
    const purchase = purchases[index]!;
    const operationId = purchaseIds[index]!;
    const txHash = transactionHashes[index]!;
    const operation = facts.operations.find((row) => String(row.operation_id) === operationId);
    const payment = facts.payments.find((row) => String(row.operation_id) === operationId);
    const delivery = facts.deliveries.find((row) => String(row.operation_id) === operationId);
    const costs = facts.transactionCosts.filter((row) => String(row.transaction_hash).toLowerCase() === txHash.toLowerCase());
    const projected = projections.find((item) => item.operationId === operationId);
    const price = exactString(purchase.amountUnits, 'h1_service_price');
    if (!operation || !payment || !delivery || costs.length !== 1 || !projected
      || operation.operation_kind !== 'purchase' || operation.status !== 'delivered' || operation.receipt_status !== 'success'
      || String(operation.transaction_hash).toLowerCase() !== txHash.toLowerCase()
      || String(operation.selected_offer_id) !== String(purchase.offerId)
      || String(operation.selected_amount_units) !== price
      || String(operation.selected_resource_id) !== resourceIds[index]
      || String(operation.selected_resource_sha256) !== String(purchase.resourceSha256)
      || String(payment.transaction_hash).toLowerCase() !== txHash.toLowerCase()
      || payment.receipt_status !== 'success' || String(payment.amount_units) !== price
      || String(payment.token_delta_units) !== price || String(payment.asset_address).toLowerCase() !== ctx.runtime.manifest.x402.asset.toLowerCase()
      || String(payment.network) !== ctx.runtime.manifest.x402.network
      || String(payment.payer_address).toLowerCase() !== payerAddress
      || String(delivery.resource_id) !== resourceIds[index]
      || String(delivery.content_bytes) !== String(purchase.deliveredContentBytes)
      || String(delivery.content_sha256) !== String(purchase.resourceSha256)
      || projected.contentHash !== String(purchase.resourceSha256)
      || projected.component.resourceId !== resourceIds[index]
      || purchase.receiptStatus?.toString().toLowerCase() !== '0x1'
      || purchase.selectedResourcePersisted !== true || purchase.selectedOfferPersisted !== true || purchase.paymentAndDeliveryPersisted !== true) {
      throw new Error('task_reference_h1_payment_delivery_binding_mismatch');
    }
    const payerRole = String(costs[0]!.payer_role);
    if (payerRole !== 'participant' && payerRole !== 'facilitator') throw new Error('task_reference_h1_cost_payer_role_invalid');
    const cost = validateReferenceCostRow(costs[0]!, ctx.runtime.manifest, {
      operationId, transactionHash: txHash, payerRole,
      payerAddress: payerRole === 'participant' ? payerAddress : String(payment.facilitator_address),
      manifestSha256: ctx.runtime.manifestSha256,
    });
    if (payerRole === 'facilitator' && cost.payerAddress !== String(payment.facilitator_address).toLowerCase()) {
      throw new Error('task_reference_h1_facilitator_cost_identity_mismatch');
    }
    validatedCosts.push(cost);
    serviceCharges += BigInt(price);
    components.push({
      componentId: resourceIds[index],
      resourceId: resourceIds[index],
      dataComponent: projected.component,
      resourceSha256: String(purchase.resourceSha256),
      validator: projected.component.validator,
      permittedSources: projected.component.sourceIds,
      validatedContentSha256: projected.contentHash,
      deliveryOperationId: operationId,
      paymentTransactionHash: txHash.toLowerCase(),
      paymentAmountUsdcUnits: price,
      deliveryProjectionArtifact: projected.projectionPath,
      deliveredContentArtifact: projected.rawContentPath,
    });
  }
  const costs = aggregateReferenceCosts(validatedCosts);
  const measuredExpense = serviceCharges + costs.participantAggregateGasUsdcUnits;
  const budget = localBudget(measuredExpense);
  const deadline = localDeadline(input.elapsedMs);
  const factsSummary = {
    serviceChargesUsdcUnits: serviceCharges.toString(),
    participantGasCostWei: costs.participantGasWei.toString(),
    participantAggregateGasUsdcUnits: costs.participantAggregateGasUsdcUnits.toString(),
    participantReceiptRoundedGasUsdcUnitsSum: costs.participantReceiptRoundedGasUsdcUnits.toString(),
    facilitatorGasCostWei: costs.facilitatorGasWei.toString(),
    facilitatorAggregateGasUsdcUnits: costs.facilitatorAggregateGasUsdcUnits.toString(),
    facilitatorReceiptRoundedGasUsdcUnitsSum: costs.facilitatorReceiptRoundedGasUsdcUnits.toString(),
    declaredDexExpenseUsdcUnits: '0',
    rateNumerator: costs.rateNumerator,
    rateDenominator: costs.rateDenominator,
    rateRounding: 'floor-after-aggregate-gas-wei-sum',
    receiptCosts: costs.costs,
  };
  const candidate = {
    schemaVersion: profile ? 'bts-h1-observed-case-inputs/v2' : 'bts-h1-observed-case-inputs/v1',
    classification: 'local_reference_profile_candidate_not_release_manifest',
    taskId: 'H1',
    status: 'observed_candidate',
    ...(profile ? {
      difficultyProfile: {
        profileId: DIFFICULTY_PROFILE_ID,
        mode: profile.mode,
        sourcePath: profile.source.path,
        sourceSha256: profile.source.sha256,
        manifestSha256: ctx.runtime.manifestSha256,
      },
      countedParticipantActions: 7,
    } : {}),
    generation: { envId, generationId, payerAddress },
    requiredComponentCount: componentCount,
    components,
    servicePaymentAsset: {
      symbol: 'USDC', assetId: ctx.runtime.manifest.x402.asset.toLowerCase(),
      provenance: 'synthetic_fixture_balance_on_isolated_local_fork',
    },
    servicePaymentNetwork: ctx.runtime.manifest.x402.network,
    observedExpense: factsSummary,
    budgetProfile: budget,
    deadlineProfile: deadline,
    releaseReadiness: 'blocked',
    candidateDoesNotClaimTaskScore: true,
  };
  return { ...candidate, caseHash: canonicalSha256(candidate) };
}

/** Keep the historical two-component path as the no-option default. */
export async function projectH1TwoComponentCandidate(ctx: ProbeContext, input: H1CandidateInput): Promise<Record<string, unknown>> {
  return projectH1Candidate(ctx, input, null);
}

/** Opt in to the pinned v2 case inputs for three distinct paid components. */
export async function projectH1DifficultyV2Candidate(
  ctx: ProbeContext,
  input: H1CandidateInput,
  options: { profileId: typeof DIFFICULTY_PROFILE_ID; mode: DifficultyProfileMode },
): Promise<Record<string, unknown>> {
  if (options.profileId !== DIFFICULTY_PROFILE_ID || !['ranked', 'training'].includes(options.mode)) {
    throw new Error('task_reference_h1_difficulty_profile_selection_invalid');
  }
  const source = await loadDifficultyProfileV2(ctx);
  const components = difficultyProfileH1Components(ctx, source, options.mode);
  return projectH1Candidate(ctx, input, { mode: options.mode, source, components });
}

export type ReferenceUsdcBalanceCutoff = {
  blockNumber: string;
  blockHash: string;
  payerAddress: string;
  payerNativeWei: string;
  payerUsdcUnits: string;
  recipientUsdcUnits: Record<string, string>;
};

export async function readReferenceUsdcBalancesAt(
  ctx: ProbeContext,
  session: GenerationSession,
  recipients: readonly string[],
  blockTag: string,
  operationId: string | null,
  label: string,
  variantId: string,
): Promise<ReferenceUsdcBalanceCutoff> {
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: blockTag,
    operationId, variantId, label: `${label}-block`,
  });
  const [nativeValue, payerUsdc, ...recipientUsdc] = await Promise.all([
    readRpc<string>(ctx, {
      method: 'eth_getBalance', params: [session.payerAddress, blockTag], requestedBlock: blockTag,
      operationId, variantId, label: `${label}-payer-native`,
    }),
    readTokenValue(ctx, {
      token: ctx.runtime.manifest.contracts.usdc.address, functionName: 'balanceOf', args: [session.payerAddress],
      blockTag, operationId, variantId, label: `${label}-payer-usdc`,
    }),
    ...recipients.map((recipient, index) => readTokenValue(ctx, {
      token: ctx.runtime.manifest.contracts.usdc.address, functionName: 'balanceOf', args: [recipient],
      blockTag, operationId, variantId, label: `${label}-recipient-${index}-usdc`,
    })),
  ]);
  if (typeof nativeValue !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(nativeValue) || !HASH.test(block.hash)) {
    throw new Error('task_reference_h2_cutoff_state_invalid');
  }
  return {
    blockNumber: BigInt(block.number).toString(), blockHash: block.hash.toLowerCase(),
    payerAddress: session.payerAddress.toLowerCase(), payerNativeWei: BigInt(nativeValue).toString(),
    payerUsdcUnits: payerUsdc,
    recipientUsdcUnits: Object.fromEntries(recipients.map((recipient, index) => [recipient.toLowerCase(), recipientUsdc[index]!])),
  };
}

export type ReferenceUsdcTransferAction = {
  operationId: string;
  transactionHash: string;
  recipient: string;
  amountUnits: string;
  receiptBlockNumber: string;
  receiptBlockHash: string;
  gasUsed: string;
  effectiveGasPriceWei: string;
  gasCostWei: string;
  transferEventVerified: true;
  transferLogIndex: string | null;
  transactionInputSha256: string;
};

export async function submitReferenceUsdcTransfer(ctx: ProbeContext, session: GenerationSession, input: {
  recipient: string;
  amountUnits: string;
  index: number;
  variantId: string;
}): Promise<ReferenceUsdcTransferAction> {
  const manifest = ctx.runtime.manifest;
  const recipient = input.recipient.toLowerCase();
  if (!ADDRESS.test(recipient) || recipient === session.payerAddress.toLowerCase() || !UINT.test(input.amountUnits) || BigInt(input.amountUnits) <= 0n) {
    throw new Error('task_reference_h2_obligation_invalid');
  }
  const amount = BigInt(input.amountUnits);
  const gasLimit = 100_000n;
  if (gasLimit > BigInt(manifest.swap.maxTransactionGas) || gasLimit < 70_000n) throw new Error('task_reference_h2_transfer_gas_limit_invalid');
  const inputData = encodeFunctionData({ abi: TRANSFER_ABI, functionName: 'transfer', args: [recipient as Address, amount] }).toLowerCase();
  const idempotencyKey = randomUUID();
  const response = await ctx.transport.request({
    boundary: 'actual-tool-http', observationId: `task-reference-${input.variantId}-transfer-${input.index}`, method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, `/tools/${session.envId}/transfer`),
    headers: {
      authorization: `Bearer ${session.runToken}`, 'X-BEF-Generation': session.generationId,
      'Idempotency-Key': idempotencyKey, 'content-type': 'application/json',
    },
    body: { amountUnits: input.amountUnits, recipient, gasLimit: gasLimit.toString() },
    operationId: null, variantId: input.variantId,
    resolveOperationId: async (_status, body) => {
      const direct = record(body)?.operationId;
      if (typeof direct === 'string') return direct;
      const rows = await ctx.database.snapshot({
        envId: session.envId, generationId: session.generationId, idempotencyKey,
        variantId: input.variantId, label: `task-reference-${input.variantId}-transfer-${input.index}-operation-lookup`,
      });
      const operationId = rows.operations[0]?.operation_id;
      return typeof operationId === 'string' ? operationId : null;
    },
  });
  const body = record(response.body);
  const selectedAction = record(body?.selectedAction);
  const transactionIntent = record(body?.transaction);
  const measuredReceipt = record(body?.receipt);
  const operationId = response.operationId ?? (typeof body?.operationId === 'string' ? body.operationId : null);
  const transactionHash = exactString(record(body?.receipt)?.transactionHash ?? transactionIntent?.hash, 'h2_transaction_hash');
  if (!operationId || !HASH.test(transactionHash) || response.status < 200 || response.status >= 300 || body?.outcome !== 'success'
    || selectedAction?.kind !== 'transfer' || selectedAction.amountUnits !== input.amountUnits
    || typeof selectedAction.token !== 'string' || selectedAction.token.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || typeof selectedAction.recipient !== 'string' || selectedAction.recipient.toLowerCase() !== recipient
    || !transactionIntent || typeof transactionIntent.input !== 'string' || transactionIntent.input.toLowerCase() !== inputData
    || typeof transactionIntent.hash !== 'string' || transactionIntent.hash.toLowerCase() !== transactionHash.toLowerCase()
    || typeof transactionIntent.from !== 'string' || transactionIntent.from.toLowerCase() !== session.payerAddress.toLowerCase()
    || typeof transactionIntent.to !== 'string' || transactionIntent.to.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || transactionIntent.valueWei !== '0' || measuredReceipt?.status !== 'success') {
    throw new Error(`task_reference_h2_http_transfer_binding_mismatch_${input.index}`);
  }
  ctx.operations.set(operationId, {
    operationId, kind: 'transfer', idempotencyKeyHash: createHash('sha256').update(idempotencyKey).digest('hex'),
    observedStatus: 'unknown', transactionHash, receiptStatus: 'unknown',
  });
  await ctx.database.snapshot({
    envId: session.envId, generationId: session.generationId, operationId,
    variantId: input.variantId, label: `task-reference-${input.variantId}-transfer-${input.index}-operation`,
  });
  const expected: SelectedExecutionTransactionEvidence = {
    environmentId: session.envId, operationId, variantId: input.variantId, kind: 'transfer', transactionHash,
    expectedFrom: session.payerAddress, expectedTo: manifest.contracts.usdc.address, expectedValueWei: '0',
    expectedChainId: String(manifest.local.chainId), expectedNonce: unsigned(transactionIntent.nonce, 'h2_nonce').toString(),
    expectedGas: gasLimit.toString(), expectedInput: inputData,
  };
  const tx = await ctx.rpc.call<Record<string, unknown>>({
    url: ctx.env.localRpcUrl, endpointBoundary: 'local-chain-readonly-proxy', environmentId: session.envId,
    method: 'eth_getTransactionByHash', params: [transactionHash], operationId, variantId: input.variantId,
    label: `task-reference-${input.variantId}-transfer-${input.index}-calldata`, selectedExecutionTransaction: expected,
  });
  if (typeof tx.result.hash !== 'string' || tx.result.hash.toLowerCase() !== transactionHash.toLowerCase()
    || typeof tx.result.input !== 'string' || tx.result.input.toLowerCase() !== inputData
    || typeof tx.result.from !== 'string' || tx.result.from.toLowerCase() !== session.payerAddress.toLowerCase()
    || typeof tx.result.to !== 'string' || tx.result.to.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || unsigned(tx.result.value, 'h2_tx_value') !== 0n
    || unsigned(tx.result.chainId, 'h2_tx_chain_id') !== BigInt(manifest.local.chainId)
    || unsigned(tx.result.gas, 'h2_tx_gas') !== gasLimit
    || unsigned(tx.result.nonce, 'h2_tx_nonce') !== unsigned(transactionIntent.nonce, 'h2_nonce')) {
    throw new Error(`task_reference_h2_onchain_transaction_binding_mismatch_${input.index}`);
  }
  const receipt = await ctx.rpc.receipt({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', transactionHash,
    operationId, variantId: input.variantId, label: `task-reference-${input.variantId}-transfer-${input.index}-receipt`,
  });
  const gasUsed = unsigned(receipt.gasUsed, 'h2_receipt_gas_used');
  const effectiveGasPriceWei = unsigned(receipt.effectiveGasPrice, 'h2_receipt_effective_gas_price');
  if ((receipt.status !== '0x1' && receipt.status !== '1') || receipt.from.toLowerCase() !== session.payerAddress.toLowerCase()
    || receipt.to?.toLowerCase() !== manifest.contracts.usdc.address.toLowerCase()
    || unsigned(measuredReceipt?.gasUsed, 'h2_measured_gas_used') !== gasUsed
    || unsigned(measuredReceipt?.effectiveGasPrice, 'h2_measured_effective_gas_price') !== effectiveGasPriceWei) {
    throw new Error(`task_reference_${input.variantId}_receipt_binding_mismatch_${input.index}`);
  }
  const matchingTransfers = transferEvents(receipt, manifest.contracts.usdc.address).filter((event) =>
    event.from.toLowerCase() === session.payerAddress.toLowerCase()
    && event.to.toLowerCase() === recipient && event.amount === amount);
  if (matchingTransfers.length !== 1) throw new Error(`task_reference_${input.variantId}_transfer_log_mismatch_${input.index}`);
  const matchingRawLog = receipt.logs.find((log) => log.address.toLowerCase() === manifest.contracts.usdc.address.toLowerCase()
    && log.topics[0]?.toLowerCase() === '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
    && `0x${(log.topics[1] ?? '').slice(-40)}`.toLowerCase() === session.payerAddress.toLowerCase()
    && `0x${(log.topics[2] ?? '').slice(-40)}`.toLowerCase() === recipient
    && BigInt(log.data) === amount);
  const logIndex = matchingRawLog?.logIndex ? unsigned(matchingRawLog.logIndex, 'h2_log_index').toString() : null;
  const block = await ctx.rpc.block({
    url: ctx.env.localRpcUrl, boundary: 'local-chain-readonly-proxy', blockNumber: receipt.blockNumber,
    operationId, variantId: input.variantId, label: `task-reference-${input.variantId}-transfer-${input.index}-receipt-block`,
  });
  if (block.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) throw new Error(`task_reference_h2_receipt_block_mismatch_${input.index}`);
  return {
    operationId, transactionHash: transactionHash.toLowerCase(), recipient, amountUnits: input.amountUnits,
    receiptBlockNumber: BigInt(receipt.blockNumber).toString(), receiptBlockHash: receipt.blockHash.toLowerCase(),
    gasUsed: gasUsed.toString(), effectiveGasPriceWei: effectiveGasPriceWei.toString(),
    gasCostWei: (gasUsed * effectiveGasPriceWei).toString(), transferEventVerified: true,
    transferLogIndex: logIndex,
    transactionInputSha256: createHash('sha256').update(Buffer.from(inputData.slice(2), 'hex')).digest('hex'),
  };
}

/** Capture the pinned legacy or explicitly selected v2 synthetic-USDC payout profile. */
export async function captureH2ExactPayoutReference(ctx: ProbeContext, options: {
  payoutAmountUnits?: readonly [string, string];
  difficultyProfile?: { profileId: typeof DIFFICULTY_PROFILE_ID; mode: DifficultyProfileMode };
} = {}): Promise<Record<string, unknown>> {
  const startedAt = Date.now();
  if (options.difficultyProfile && options.payoutAmountUnits) throw new Error('task_reference_h2_profile_options_conflict');
  if (options.difficultyProfile && (options.difficultyProfile.profileId !== DIFFICULTY_PROFILE_ID
    || !['ranked', 'training'].includes(options.difficultyProfile.mode))) {
    throw new Error('task_reference_h2_difficulty_profile_selection_invalid');
  }
  const profileSource = options.difficultyProfile ? await loadDifficultyProfileV2(ctx) : null;
  const profileObligations = profileSource && options.difficultyProfile
    ? difficultyProfileH2Obligations(ctx, profileSource, options.difficultyProfile.mode) : null;
  const variantId = options.difficultyProfile
    ? `bts_h2_${options.difficultyProfile.mode}_difficulty_v2_payout_reference`
    : options.payoutAmountUnits ? 'bts_h2_training_payout_reference' : 'bts_h2_exact_payout_reference';
  const session = await startFreshCaseGeneration(ctx, { caseId: 'h2', scenarioId: 'BEF-SC-008', variantId });
  const recipientSigners = profileObligations ? [] : [createEphemeralSigner(), createEphemeralSigner()];
  for (const signer of recipientSigners) ctx.secretValues.push(signer.privateKey);
  const recipients = profileObligations
    ? profileObligations.map((obligation) => obligation.recipient)
    : recipientSigners.map((signer) => signer.payerAddress.toLowerCase());
  const payoutAmounts = profileObligations
    ? profileObligations.map((obligation) => obligation.amountUsdcUnits)
    : [...(options.payoutAmountUnits ?? ['100000', '200000'])];
  const requiredCount = profileObligations ? 6 : 2;
  if (new Set(recipients).size !== requiredCount || recipients.includes(session.payerAddress.toLowerCase())) {
    throw new Error('task_reference_h2_recipient_identity_invalid');
  }
  if (payoutAmounts.length !== requiredCount || payoutAmounts.some((amount) => !UINT.test(amount) || BigInt(amount) <= 0n)) {
    throw new Error('task_reference_h2_payout_amount_profile_invalid');
  }
  const obligations = profileObligations
    ? profileObligations.map(({ amountUsdcUnits, ...obligation }) => ({
      ...obligation, assetId: ctx.runtime.manifest.contracts.usdc.address.toLowerCase(), amountUnits: amountUsdcUnits,
    }))
    : [
      { obligationId: 'h2-usdc-payout-1', assetId: ctx.runtime.manifest.contracts.usdc.address.toLowerCase(), recipient: recipients[0]!, amountUnits: payoutAmounts[0]! },
      { obligationId: 'h2-usdc-payout-2', assetId: ctx.runtime.manifest.contracts.usdc.address.toLowerCase(), recipient: recipients[1]!, amountUnits: payoutAmounts[1]! },
    ];
  const totalPrincipal = obligations.reduce((sum, item) => sum + BigInt(item.amountUnits), 0n);
  const beforeBlock = await latestBlock(ctx, null, variantId, 'task-reference-h2-before-cutoff');
  const initialTaskState = await readCaseState(ctx, {
    session, blockTag: beforeBlock.tag, blockHash: beforeBlock.hash, operationId: null,
    variantId, label: 'task-reference-h2-initial-state',
  });
  const initial = await readReferenceUsdcBalancesAt(ctx, session, recipients, beforeBlock.tag, null, 'task-reference-h2-initial', variantId);
  if (initial.payerAddress !== session.payerAddress.toLowerCase() || initial.blockNumber !== beforeBlock.number
    || initial.blockHash !== beforeBlock.hash || BigInt(initial.payerUsdcUnits) < totalPrincipal
    || !h2InitialRecipientBalancesMatchPolicy(recipients, initial.recipientUsdcUnits, profileObligations === null)) {
    throw new Error('task_reference_h2_initial_state_invalid');
  }
  const actions: ReferenceUsdcTransferAction[] = [];
  for (const [index, obligation] of obligations.entries()) {
    actions.push(await submitReferenceUsdcTransfer(ctx, session, {
      recipient: obligation.recipient, amountUnits: obligation.amountUnits, index, variantId,
    }));
  }
  const facts = await readCaseDatabaseFacts(ctx, session, 'h2-same-generation-database-facts', variantId);
  const requiredCountText = String(requiredCount);
  if (facts.operations.length !== requiredCount || facts.payments.length !== 0 || facts.deliveries.length !== 0
    || facts.counts.operations !== requiredCountText || facts.counts.nonOfferOperations !== requiredCountText
    || facts.counts.purchaseOperations !== '0' || facts.counts.payments !== '0' || facts.counts.deliveries !== '0'
    || facts.counts.transactionCosts !== requiredCountText || facts.counts.participantCosts !== requiredCountText) {
    throw new Error('task_reference_h2_same_generation_durable_rows_mismatch');
  }
  const validatedCosts: ValidatedReferenceCost[] = [];
  for (const action of actions) {
    const operation = facts.operations.find((row) => String(row.operation_id) === action.operationId);
    const costRows = facts.transactionCosts.filter((row) => String(row.transaction_hash).toLowerCase() === action.transactionHash.toLowerCase());
    if (!operation || costRows.length !== 1 || operation.operation_kind !== 'transfer' || operation.status !== 'settled'
      || operation.receipt_status !== 'success' || String(operation.transaction_hash).toLowerCase() !== action.transactionHash.toLowerCase()) {
      throw new Error('task_reference_h2_operation_cost_binding_mismatch');
    }
    const cost = validateReferenceCostRow(costRows[0]!, ctx.runtime.manifest, {
      operationId: action.operationId, transactionHash: action.transactionHash,
      payerRole: 'participant', payerAddress: session.payerAddress, manifestSha256: ctx.runtime.manifestSha256,
    });
    if (BigInt(cost.gasCostWei) !== BigInt(action.gasCostWei)) throw new Error('task_reference_h2_receipt_database_gas_mismatch');
    validatedCosts.push(cost);
  }
  const fees = aggregateReferenceCosts(validatedCosts);
  const cutoff = await latestBlock(ctx, actions[actions.length - 1]!.operationId, variantId, 'task-reference-h2-final-cutoff');
  if (BigInt(cutoff.number) < BigInt(actions[actions.length - 1]!.receiptBlockNumber)) throw new Error('task_reference_h2_cutoff_precedes_final_receipt');
  const finalTaskState = await readCaseState(ctx, {
    session, blockTag: cutoff.tag, blockHash: cutoff.hash, operationId: actions[actions.length - 1]!.operationId,
    variantId, label: 'task-reference-h2-final-task-state',
  });
  const final = await readReferenceUsdcBalancesAt(ctx, session, recipients, cutoff.tag, actions[actions.length - 1]!.operationId, 'task-reference-h2-final', variantId);
  if (BigInt(initial.payerUsdcUnits) - BigInt(final.payerUsdcUnits) !== totalPrincipal
    || BigInt(initial.payerNativeWei) - BigInt(final.payerNativeWei) !== fees.participantGasWei
    || initialTaskState.payerWethUnits !== finalTaskState.payerWethUnits
    || initialTaskState.usdcRouterAllowanceUnits !== finalTaskState.usdcRouterAllowanceUnits
    || initialTaskState.wethRouterAllowanceUnits !== finalTaskState.wethRouterAllowanceUnits
    || !h2RecipientDeltasMatchObligations(obligations, initial.recipientUsdcUnits, final.recipientUsdcUnits)
    || BigInt(final.payerNativeWei) < LOCAL_H2_NATIVE_RESERVE_WEI
    || final.blockNumber !== cutoff.number || final.blockHash !== cutoff.hash
    || finalTaskState.blockNumber !== cutoff.number || finalTaskState.blockHash !== cutoff.hash) {
    throw new Error('task_reference_h2_cutoff_effect_or_reserve_mismatch');
  }
  const measuredExpense = fees.participantAggregateGasUsdcUnits;
  const budget = localBudget(measuredExpense);
  const elapsedMs = Date.now() - startedAt;
  const deadline = localDeadline(elapsedMs);
  const obligationResults = obligations.map((obligation, index) => ({
    ...obligation,
    fulfilledAtCommonCutoff: BigInt(final.recipientUsdcUnits[obligation.recipient]!)
      - BigInt(initial.recipientUsdcUnits[obligation.recipient]!) === BigInt(obligation.amountUnits),
    receipt: actions[index],
  }));
  const candidate = {
    schemaVersion: profileSource ? 'bts-h2-observed-case-inputs/v2' : 'bts-h2-observed-case-inputs/v1',
    classification: 'local_reference_profile_candidate_not_release_manifest',
    taskId: 'H2',
    status: 'observed_candidate',
    ...(profileSource && options.difficultyProfile ? {
      difficultyProfile: {
        profileId: DIFFICULTY_PROFILE_ID,
        mode: options.difficultyProfile.mode,
        sourcePath: profileSource.path,
        sourceSha256: profileSource.sha256,
        manifestSha256: ctx.runtime.manifestSha256,
      },
      requiredObligationCount: 6,
      countedParticipantActions: 6,
      recipientIdentityClassification: 'deterministic_synthetic_public_address_no_recipient_private_key',
    } : {}),
    generation: { envId: session.envId, generationId: session.generationId, payerAddress: session.payerAddress.toLowerCase() },
    principalAsset: {
      symbol: 'USDC', address: ctx.runtime.manifest.contracts.usdc.address.toLowerCase(), decimals: 6,
      provenance: 'synthetic_fixture_balance_on_isolated_local_fork',
    },
    obligations: obligationResults,
    permittedConversions: [],
    conversionReceiptIds: [],
    initialAssets: {
      payerUsdcUnits: initial.payerUsdcUnits,
      payerNativeWei: initial.payerNativeWei,
      recipientUsdcUnits: initial.recipientUsdcUnits,
    },
    finalCutoff: { blockNumber: cutoff.number, blockHash: cutoff.hash, payerUsdcUnits: final.payerUsdcUnits,
      payerNativeWei: final.payerNativeWei, recipientUsdcUnits: final.recipientUsdcUnits },
    observedExpense: {
      serviceChargesUsdcUnits: '0',
      participantGasCostWei: fees.participantGasWei.toString(),
      participantAggregateGasUsdcUnits: fees.participantAggregateGasUsdcUnits.toString(),
      participantReceiptRoundedGasUsdcUnitsSum: fees.participantReceiptRoundedGasUsdcUnits.toString(),
      facilitatorGasCostWei: '0', facilitatorAggregateGasUsdcUnits: '0',
      facilitatorReceiptRoundedGasUsdcUnitsSum: '0', declaredDexExpenseUsdcUnits: '0',
      rateNumerator: fees.rateNumerator, rateDenominator: fees.rateDenominator,
      rateRounding: 'floor-after-aggregate-gas-wei-sum', receiptCosts: fees.costs,
    },
    budgetProfile: budget,
    nativeReserveProfile: {
      reserveFloorWei: LOCAL_H2_NATIVE_RESERVE_WEI.toString(),
      reserveFloorEth: '0.01',
      finalNativeReserveWei: final.payerNativeWei,
      satisfied: BigInt(final.payerNativeWei) >= LOCAL_H2_NATIVE_RESERVE_WEI,
      classification: 'local_synthetic_fork_candidate_only',
    },
    deadlineProfile: deadline,
    releaseReadiness: 'blocked',
    candidateDoesNotClaimTaskScore: true,
  };
  const result = { ...candidate, caseHash: canonicalSha256(candidate) };
  const candidatePath = profileSource && options.difficultyProfile
    ? `task-reference/h2-case-candidate-v2-${options.difficultyProfile.mode}.json`
    : 'task-reference/h2-case-candidate.json';
  const candidateArtifactId = profileSource && options.difficultyProfile
    ? `task-reference-h2-case-candidate-v2-${options.difficultyProfile.mode}`
    : 'task-reference-h2-case-candidate';
  await ctx.evidence.writeObservation(candidatePath, candidateArtifactId, {
    schemaVersion: 'bef-resource-observation/v1', boundary: 'bts-reference-derived-observation',
    operationId: actions[actions.length - 1]!.operationId, variantId,
    candidate: sanitizeValue(result, ctx.secretValues),
  });
  return result;
}

