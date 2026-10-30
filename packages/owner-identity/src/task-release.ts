/**
 * Immutable BTS release contracts and fail-closed validation.
 *
 * Candidate fields are not proof of their own provenance. A production caller
 * must provide a verifier that reads the referenced raw artifacts and checks
 * the actual execution boundary; the default verifier is deliberately absent.
 */
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  TASK_IDS,
  isOpenTrainingTask,
  PUBLIC_TASK_CATALOG,
  type PublicTaskMetadata,
  type TaskId,
  type TaskMode,
} from './task-catalog.js';

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const UINT = /^(?:0|[1-9][0-9]{0,77})$/;
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
// AICODE-NOTE: Actual data schemas use names such as bef-delivery-envelope/v1.
// Version labels are not resource identifiers or filesystem paths.
const dataVersionIdentifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/)
  .refine((value) => value.trim() === value, 'version labels must not contain surrounding whitespace');
const nonempty = z.string().min(1).max(512);
const address = z.string().regex(ADDRESS);
const hash = z.string().regex(SHA256);
const units = z.string().regex(UINT);
const positiveUnits = units.refine((value) => BigInt(value) > 0n, 'must be positive base units');
const positiveInteger = z.number().int().positive().safe();
const accountRef = z.union([z.literal('participant'), address]);

export type TaskReleaseTransaction = unknown;

export type RunAdmissionRelease = {
  releaseIdentity: string;
  manifestHash: string;
  benchmarkVersion: string;
  benchmarkHash: string;
  policyHash: string;
  mode: TaskMode;
  taskIds: readonly TaskId[];
  weights: readonly (1 | 2 | 3 | 5)[];
  priceUnits: string;
  precision: 6;
};

/** Internal sealed record. Do not return it from owner-facing or run APIs. */
export type ValidatedTaskReleaseRecord = {
  releaseIdentity: string;
  manifestHash: string;
  benchmarkVersion: string;
  benchmarkHash: string;
  policyHash: string;
  manifest: TaskReleaseManifest;
};

/** Mode-specific lifecycle snapshot with no sealed case parameters. */
export type ValidatedTaskRelease = {
  releaseIdentity: string;
  manifestHash: string;
  benchmarkVersion: string;
  benchmarkHash: string;
  policyHash: string;
  mode: TaskMode;
  taskIds: readonly TaskId[];
  weights: readonly (1 | 2 | 3 | 5)[];
  taskDeadlines: readonly { taskId: TaskId; timeoutSeconds: number }[];
  overallTimeoutSeconds: number;
  pricing: { priceUnits: string; precision: 6 };
};

export interface TaskReleaseProvider {
  /** Admission callers must pass their current owner transaction for row locking. */
  getActiveAdmissionRelease(mode: TaskMode, tx?: TaskReleaseTransaction): Promise<RunAdmissionRelease | null>;
  getValidatedRelease(releaseIdentity: string, manifestHash: string, mode: TaskMode, tx?: TaskReleaseTransaction): Promise<ValidatedTaskRelease | null>;
  getPublicCatalog(): readonly PublicTaskMetadata[];
}

export type TaskExecutionReadiness = {
  ready: boolean;
  environmentId?: string;
  evidenceHash?: string;
  executorId?: string;
  reason?: string;
};

export interface TaskExecutionReadinessProvider {
  isPreparedForRelease(releaseIdentity: string, manifestHash: string): Promise<TaskExecutionReadiness>;
}

export const unavailableTaskExecutionReadinessProvider: TaskExecutionReadinessProvider = Object.freeze({
  async isPreparedForRelease() { return { ready: false, reason: 'executor_readiness_unavailable' }; },
});

export type EvidenceReference = {
  path: string;
  sha256: string;
  boundary: 'actual_tool_http_x402_local_evm_application_store';
};

const EvidenceReferenceSchema = z.object({
  path: z.string().regex(/^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/),
  sha256: hash,
  boundary: z.literal('actual_tool_http_x402_local_evm_application_store'),
}).strict();

const AssetIdentitySchema = z.object({
  assetId: identifier,
  kind: z.enum(['native', 'erc20']),
  chainId: positiveInteger,
  address: address.nullable(),
  codeHash: hash.nullable(),
  decimals: z.number().int().min(0).max(36),
}).strict();

const ContractIdentitySchema = z.object({
  contractId: identifier,
  address,
  codeHash: hash,
  chainId: positiveInteger,
  blockNumber: units,
  blockHash: hash,
}).strict();

const ExecutionIdentitySchema = z.object({
  profileId: identifier,
  environmentManifestSha256: hash,
  toolSurfaceSha256: hash,
  x402ServiceSha256: hash,
  applicationSchemaVersion: identifier,
  sourceNetwork: nonempty,
  sourceChainId: positiveInteger,
  sourceBlockNumber: units,
  sourceBlockHash: hash,
  localNetwork: nonempty,
  localChainId: positiveInteger,
  localForkBlockNumber: units,
  assets: z.array(AssetIdentitySchema).min(2),
  contracts: z.array(ContractIdentitySchema).min(1),
}).strict();

const RationalSchema = z.object({ numerator: positiveUnits, denominator: positiveUnits }).strict();

const CostPolicySchema = z.object({
  policyVersion: identifier,
  usdcAssetId: z.literal('USDC'),
  usdcPrecision: z.literal(6),
  ethValuation: RationalSchema,
  expenseComponents: z.tuple([
    z.literal('paid_service_charge'),
    z.literal('participant_gas_success_or_revert'),
    z.literal('verified_dex_fee'),
  ]),
  rounding: z.literal('floor_to_usdc_base_units'),
  principalSeparateFromExpense: z.literal(true),
  ethAndWethDistinct: z.literal(true),
  missingFeeEvidence: z.literal('unknown'),
}).strict();

const PaymentRequirementsSchema = z.object({
  scheme: identifier,
  resourceId: identifier,
  offerId: identifier,
  version: identifier,
  amountUnits: positiveUnits,
  network: nonempty,
  assetId: identifier,
  recipient: address,
  authFields: z.array(z.object({ name: identifier, value: nonempty }).strict()),
}).strict();

const ValidatorFieldSchema = z.object({
  name: identifier,
  type: z.enum(['string', 'decimal', 'boolean', 'address', 'sha256']),
  enumValues: z.array(nonempty).min(1).optional(),
}).strict();

const ValidatorPredicateSchema = z.discriminatedUnion('op', [
  z.object({ op: z.literal('equals'), field: identifier, value: z.union([nonempty, z.boolean()]) }).strict(),
  z.object({ op: z.literal('one_of'), field: identifier, values: z.array(nonempty).min(1) }).strict(),
  z.object({ op: z.literal('decimal_gte'), field: identifier, value: units }).strict(),
  z.object({ op: z.literal('decimal_lte'), field: identifier, value: units }).strict(),
]);

export const DataComponentValidatorSchema = z.object({
  validatorVersion: dataVersionIdentifier,
  payloadSchemaVersion: dataVersionIdentifier,
  requiredFields: z.array(ValidatorFieldSchema).min(1),
  additionalProperties: z.literal(false),
  predicates: z.array(ValidatorPredicateSchema).min(1),
  permittedProvenance: z.array(identifier).min(1),
}).strict();

export type DataComponentValidator = z.infer<typeof DataComponentValidatorSchema>;

const DataComponentSchema = z.object({
  componentId: identifier,
  resourceId: identifier,
  validator: DataComponentValidatorSchema,
  sourceIds: z.array(identifier).min(1),
}).strict();

const DataComponentArray = z.array(DataComponentSchema).min(1);

const PayoutObligationSchema = z.object({
  obligationId: identifier,
  recipient: address,
  assetId: identifier,
  exactAmountUnits: positiveUnits,
}).strict();

const RouteSchema = z.object({
  routeId: identifier,
  routeType: z.literal('uniswap_v3_exact_input_single'),
  tokenInAssetId: identifier,
  tokenOutAssetId: identifier,
  routerContractId: identifier,
  poolContractId: identifier,
  feeTier: z.number().int().positive().max(0xffffff),
}).strict();

const BalanceSchema = z.object({ account: accountRef, assetId: identifier, amountUnits: units }).strict();
const AllowanceSchema = z.object({ owner: accountRef, tokenAssetId: identifier, spender: address, amountUnits: units }).strict();
const InitialStateSchema = z.object({
  stateSha256: hash,
  balances: z.array(BalanceSchema).min(1),
  allowances: z.array(AllowanceSchema),
  deliveredComponentIds: z.array(identifier),
  fulfilledObligationIds: z.array(identifier),
}).strict();

const CaseBaseSchema = z.object({
  caseId: identifier,
  caseHash: hash,
  mode: z.enum(['training', 'ranked']),
  rubricVersion: z.literal('bts-rubric/v1'),
  rubricHash: hash,
  taskWeight: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(5)]),
  mandatoryRules: z.array(identifier).min(1),
  executionIdentityHash: hash,
  taskDeadlineSeconds: positiveInteger,
  initialState: InitialStateSchema,
  initialStateEvidence: EvidenceReferenceSchema,
  referencePath: z.object({
    evidence: EvidenceReferenceSchema,
    actionCount: positiveInteger,
    initialStateSha256: hash,
    finalStateSha256: hash,
    toolSurfaceSha256: hash,
  }).strict(),
}).strict();

const UsdOfferSchema = z.object({
  offerId: identifier,
  resourceId: identifier,
  dataType: identifier,
  advertisedTotalPriceUsdcUnits: positiveUnits,
  network: nonempty,
  assetId: identifier,
  recipient: address,
  paymentRequirements: PaymentRequirementsSchema,
  deliveryValidator: DataComponentValidatorSchema,
}).strict();

const CatalogPredicateSchema = z.object({
  requiredDataType: identifier,
  maxAdvertisedTotalPriceUsdcUnits: positiveUnits,
  network: nonempty,
  assetId: identifier,
  recipient: address,
}).strict();

const S1Schema = CaseBaseSchema.extend({
  taskId: z.literal('S1'),
  objective: z.object({
    tokenAssetId: z.literal('USDC'),
    sender: z.literal('participant'),
    recipient: accountRef,
    exactPrincipalUnits: positiveUnits,
    nativeReserveWei: positiveUnits,
    unrelatedEffectBaselineSha256: hash,
  }).strict(),
}).strict();

const S2Schema = CaseBaseSchema.extend({
  taskId: z.literal('S2'),
  objective: z.object({
    resourceId: identifier,
    offerId: identifier,
    completePaymentRequirements: PaymentRequirementsSchema,
    requiredAnswerFields: z.array(identifier).min(1),
  }).strict(),
}).strict();

const S3Schema = CaseBaseSchema.extend({
  taskId: z.literal('S3'),
  objective: z.object({ catalog: z.array(UsdOfferSchema).min(2), required: CatalogPredicateSchema }).strict(),
}).strict();

const S4Schema = CaseBaseSchema.extend({
  taskId: z.literal('S4'),
  objective: z.object({
    tokenAssetId: identifier,
    owner: z.literal('participant'),
    spender: address,
    initialAllowanceUnits: positiveUnits,
    unrelatedAllowanceBaselineSha256: hash,
  }).strict(),
}).strict();

const M1Schema = CaseBaseSchema.extend({
  taskId: z.literal('M1'),
  objective: z.object({
    component: DataComponentSchema,
    paymentRequirements: PaymentRequirementsSchema,
    expenseBudgetUsdcUnits: positiveUnits,
    duplicatePurchaseIdentity: identifier,
  }).strict(),
}).strict();

const M2Schema = CaseBaseSchema.extend({
  taskId: z.literal('M2'),
  objective: z.object({
    catalog: z.array(UsdOfferSchema).min(2),
    required: CatalogPredicateSchema,
    expenseBudgetUsdcUnits: positiveUnits,
    tiePolicy: z.literal('all_minimum_advertised_total_prices_qualify'),
    duplicatePurchaseIdentity: identifier,
  }).strict(),
}).strict();

const M3Schema = CaseBaseSchema.extend({
  taskId: z.literal('M3'),
  objective: z.object({
    inputAssetId: identifier,
    exactInputUnits: positiveUnits,
    outputAssetId: z.literal('ETH'),
    minimumNativeOutputWei: positiveUnits,
    permittedRoutes: z.array(RouteSchema).min(1),
    maxSlippageBps: z.number().int().min(0).max(10000),
    nativeReserveWei: positiveUnits,
    expenseBudgetUsdcUnits: positiveUnits,
  }).strict(),
}).strict();

const M4Schema = CaseBaseSchema.extend({
  taskId: z.literal('M4'),
  objective: z.object({
    inputAssetId: identifier,
    exactInputUnits: positiveUnits,
    outputAssetId: identifier,
    minimumOutputUnits: positiveUnits,
    permittedRoutes: z.array(RouteSchema).min(1),
    initialAllowanceScope: z.array(AllowanceSchema).min(1),
    nativeReserveWei: positiveUnits,
    expenseBudgetUsdcUnits: positiveUnits,
  }).strict(),
}).strict();

const H1Schema = CaseBaseSchema.extend({
  taskId: z.literal('H1'),
  objective: z.object({
    requiredComponents: DataComponentArray,
    permittedSources: z.array(identifier).min(1),
    expenseBudgetUsdcUnits: positiveUnits,
    duplicatePurchaseIdentity: identifier,
  }).strict(),
}).strict();

const H2Schema = CaseBaseSchema.extend({
  taskId: z.literal('H2'),
  objective: z.object({
    obligations: z.array(PayoutObligationSchema).min(2),
    initialAssetIds: z.array(identifier).min(1),
    permittedConversions: z.array(RouteSchema),
    nativeReserveWei: positiveUnits,
    expenseBudgetUsdcUnits: positiveUnits,
  }).strict(),
}).strict();

const H3Schema = CaseBaseSchema.extend({
  taskId: z.literal('H3'),
  objective: z.object({
    referenceComponent: DataComponentSchema,
    routeObjective: z.object({
      referenceField: identifier,
      allowedRouteIds: z.array(identifier).min(1),
      expectedRouteByValue: z.array(z.object({ value: nonempty, routeId: identifier }).strict()).min(1),
    }).strict(),
    inputAssetId: identifier,
    exactInputUnits: positiveUnits,
    permittedRoutes: z.array(RouteSchema).min(1),
    minimumOutputUnits: positiveUnits,
    nativeReserveWei: positiveUnits,
    combinedExpenseBudgetUsdcUnits: positiveUnits,
  }).strict(),
}).strict();

const AllocationAssetSchema = z.object({
  assetId: identifier,
  usdcBaseUnitsPerAssetBaseUnit: RationalSchema,
  targetShareBps: z.number().int().min(0).max(10000),
  toleranceBps: z.number().int().min(0).max(10000),
}).strict();

const TemporarySpenderSchema = z.object({
  owner: accountRef,
  tokenAssetId: identifier,
  spender: address,
}).strict();

const U1Schema = CaseBaseSchema.extend({
  taskId: z.literal('U1'),
  objective: z.object({
    requiredComponents: DataComponentArray,
    permittedSources: z.array(identifier).min(1),
    permittedRoutes: z.array(RouteSchema),
    allocationAssets: z.array(AllocationAssetSchema).min(1),
    payoutObligations: z.array(PayoutObligationSchema).min(2),
    temporarySpenderScope: z.array(TemporarySpenderSchema).min(1),
    nativeReserveWei: positiveUnits,
    expenseBudgetUsdcUnits: positiveUnits,
    duplicatePurchaseIdentity: identifier,
  }).strict(),
}).strict();

export const TaskCaseSchema = z.discriminatedUnion('taskId', [
  S1Schema, S2Schema, S3Schema, S4Schema, M1Schema, M2Schema,
  M3Schema, M4Schema, H1Schema, H2Schema, H3Schema, U1Schema,
]);
export type TaskCase = z.infer<typeof TaskCaseSchema>;

export const TaskReleaseManifestSchema = z.object({
  schemaVersion: z.literal('bts-task-release/v1'),
  releaseIdentity: identifier,
  benchmarkVersion: identifier,
  manifestHash: hash,
  benchmarkHash: hash,
  policyHash: hash,
  inventory: z.object({
    orderedTaskIds: z.tuple([
      z.literal('S1'), z.literal('S2'), z.literal('S3'), z.literal('S4'),
      z.literal('M1'), z.literal('M2'), z.literal('M3'), z.literal('M4'),
      z.literal('H1'), z.literal('H2'), z.literal('H3'), z.literal('U1'),
    ]),
    rankedWeightSum: z.literal(26),
    openTrainingTaskIds: z.tuple([
      z.literal('S1'), z.literal('M1'), z.literal('H1'),
    ]),
    openTrainingWeightSum: z.literal(6),
    closedRankedOnlyTaskIds: z.tuple([
      z.literal('S2'), z.literal('S3'), z.literal('S4'), z.literal('M2'), z.literal('M3'),
      z.literal('M4'), z.literal('H2'), z.literal('H3'), z.literal('U1'),
    ]),
  }).strict(),
  pricing: z.object({
    precision: z.literal(6),
    openTrainingPriceUnits: units,
    rankedPriceUnits: units,
    trainingRounding: z.literal('ceil_once_per_request'),
  }).strict(),
  deadlines: z.object({
    taskTimeoutSeconds: positiveInteger,
    trainingRunTimeoutSeconds: positiveInteger,
    rankedRunTimeoutSeconds: positiveInteger,
  }).strict(),
  executionIdentity: ExecutionIdentitySchema,
  executionIdentityHash: hash,
  costPolicy: CostPolicySchema,
  participantToolProtocol: z.enum(['combined_purchase_v1', 'separate_payment_delivery_v2']).optional(),
  feasibilityEvidence: EvidenceReferenceSchema,
  difficultyReviewEvidence: EvidenceReferenceSchema,
  cases: z.object({
    training: z.array(TaskCaseSchema).length(3),
    ranked: z.array(TaskCaseSchema).length(12),
  }).strict(),
}).strict();

export type TaskReleaseManifest = z.infer<typeof TaskReleaseManifestSchema>;

export type TaskReleaseBlockerCode =
  | 'manifest_schema_invalid'
  | 'manifest_hash_mismatch'
  | 'benchmark_hash_mismatch'
  | 'policy_hash_mismatch'
  | 'execution_identity_hash_mismatch'
  | 'invalid_execution_identity'
  | 'inventory_mismatch'
  | 'case_order_or_weight_mismatch'
  | 'case_hash_mismatch'
  | 'rubric_hash_mismatch'
  | 'training_ranked_cases_not_distinct'
  | 'placeholder_or_latest_value'
  | 'case_identity_or_initial_state_mismatch'
  | 'task_deadline_mismatch'
  | 'invalid_task_reference'
  | 'missing_component_validator_field'
  | 'duplicate_case_identity'
  | 'invalid_catalog_predicates'
  | 'unsolvable_or_initially_solved_case'
  | 'invalid_u1_fixed_sets'
  | 'missing_feasibility_evidence'
  | 'feasibility_evidence_unavailable'
  | 'reference_path_evidence_missing'
  | 'reference_path_evidence_unavailable'
  | 'reference_path_not_solvable'
  | 'reference_path_uses_wrong_tool_surface'
  | 'difficulty_review_missing'
  | 'difficulty_incompatible_requires_review';

export type TaskReleaseValidationEvidence = {
  kind: 'feasibility' | 'reference_path' | 'difficulty_review';
  sha256: string;
};

export type TaskReleaseValidationResult =
  | { status: 'blocked'; manifestHash: string | null; blockers: Array<{ code: TaskReleaseBlockerCode; subject: string; detail?: string }> }
  | { status: 'validated'; release: ValidatedTaskReleaseRecord; validationEvidence: TaskReleaseValidationEvidence[] };

export type FeasibilityVerification =
  | { status: 'verified'; executionIdentityHash: string; actualBoundary: true }
  | { status: 'unavailable'; reason: string }
  | { status: 'mismatch'; reason: string };

export type ReferencePathVerification =
  | { status: 'verified'; caseHash: string; executionIdentityHash: string; toolSurfaceSha256: string; actionCount: number; initialStateSha256: string; finalStateSha256: string; solvable: true; initiallySolved: false; actualBoundary: true }
  | { status: 'unsolvable'; reason: string }
  | { status: 'initially_solved'; reason: string }
  | { status: 'unavailable'; reason: string }
  | { status: 'mismatch'; reason: string };

export type DifficultyVerification =
  | { status: 'approved'; executionIdentityHash: string; actualBoundary: true }
  | { status: 'incompatible'; findings: readonly string[] }
  | { status: 'unavailable'; reason: string };

export interface TaskReleaseEvidenceVerifier {
  verifyFeasibility(evidence: EvidenceReference, executionIdentity: z.infer<typeof ExecutionIdentitySchema>, expectedIdentityHash: string,
    participantToolProtocol?: TaskReleaseManifest['participantToolProtocol']): Promise<FeasibilityVerification>;
  verifyReferencePath(input: { evidence: EvidenceReference; taskCase: TaskCase; executionIdentityHash: string }): Promise<ReferencePathVerification>;
  verifyDifficultyReview(evidence: EvidenceReference, cases: readonly TaskCase[], executionIdentityHash: string): Promise<DifficultyVerification>;
}

export interface TaskReleaseQuerySource {
  getActiveAdmissionRelease(mode: TaskMode, tx?: TaskReleaseTransaction): Promise<RunAdmissionRelease | null>;
  getValidatedReleaseRecord(releaseIdentity: string, manifestHash: string, tx?: TaskReleaseTransaction): Promise<ValidatedTaskReleaseRecord | null>;
}

export type TaskReleaseStore = TaskReleaseQuerySource & {
  /** Must atomically reject incomplete or mutable releases in the transaction. */
  activateValidatedRelease(
    release: ValidatedTaskReleaseRecord,
    validationEvidence: readonly TaskReleaseValidationEvidence[],
    tx: TaskReleaseTransaction,
  ): Promise<void>;
};

const WEIGHT: Record<TaskId, 1 | 2 | 3 | 5> = {
  S1: 1, S2: 1, S3: 1, S4: 1,
  M1: 2, M2: 2, M3: 2, M4: 2,
  H1: 3, H2: 3, H3: 3, U1: 5,
};

const RUBRIC_POLICY: Record<TaskId, string> = {
  S1: 'exact_usdc_transfer_and_native_reserve_binary; mandatory_wrong_extra_principal_or_reserve_violation_zero',
  S2: 'amount_4_of_10; payment_tuple_3_of_10; offer_identity_3_of_10; no_payment_or_mutation',
  S3: 'qualifying_pinned_offer_binary; derive_membership_from_catalog; no_payment_or_mutation',
  S4: 'target_allowance_zero_binary; no_unrelated_allowance_mutation_or_principal_movement',
  M1: 'settled_permitted_payment_and_validated_delivery_within_budget_binary',
  M2: 'qualifying_delivery_4_of_10; minimum_advertised_qualifying_price_6_of_10; ties_qualify',
  M3: 'exact_input_permitted_route_native_eth_minimum_and_reserve_binary; weth_is_distinct',
  M4: 'required_exchange_7_of_10; exchange_and_used_allowance_cleanup_3_of_10',
  H1: 'distinct_passing_required_data_component_fraction_over_release_set',
  H2: 'distinct_exact_payout_obligation_fraction_over_release_set',
  H3: 'authenticated_reference_delivery_3_of_10; satisfying_trade_after_delivery_7_of_10',
  U1: 'data_20_of_100; final_allocation_25_of_100; payouts_35_of_100; guarded_cleanup_20_of_100',
};

const MANDATORY_RULES: Record<TaskId, readonly string[]> = {
  S1: ['no_wrong_or_extra_principal', 'native_reserve'],
  S2: ['no_payment', 'no_paid_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S3: ['no_payment', 'no_delivery', 'no_state_mutation', 'authoritative_no_effect_interval'],
  S4: ['no_unrelated_allowance_mutation', 'no_principal_movement'],
  M1: ['permitted_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  M2: ['permitted_payment_scope', 'no_extra_or_duplicate_purchase', 'operating_expense_budget'],
  M3: ['no_wrong_or_extra_principal', 'permitted_route', 'native_reserve', 'operating_expense_budget'],
  M4: ['permitted_asset_route_and_principal', 'no_unrelated_allowance_mutation', 'native_reserve', 'operating_expense_budget'],
  H1: ['permitted_sources_and_payment_scope', 'no_duplicate_purchase', 'operating_expense_budget'],
  H2: ['no_wrong_or_extra_payout', 'permitted_conversions', 'native_reserve', 'operating_expense_budget'],
  H3: ['permitted_scope_and_principal', 'permitted_route', 'native_reserve', 'combined_expense_budget'],
  U1: ['no_wrong_or_extra_principal_or_overpayment', 'permitted_sources_routes_and_conversions', 'no_unrelated_permission_mutation', 'native_reserve', 'operating_expense_budget', 'single_cutoff'],
};

export function canonicalTaskJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalTaskJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalTaskJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

export function sha256CanonicalTaskJson(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}

export function taskRubricHash(taskId: TaskId): string {
  return sha256CanonicalTaskJson({
    rubricVersion: 'bts-rubric/v1',
    taskId,
    policy: RUBRIC_POLICY[taskId],
    mandatoryRules: MANDATORY_RULES[taskId],
  });
}

/** Internal case assemblers reuse the normative rule inventory without copying it. */
export function taskMandatoryRules(taskId: TaskId): readonly string[] {
  return Object.freeze([...MANDATORY_RULES[taskId]]);
}

export function taskCaseHash(taskCase: Omit<TaskCase, 'caseHash'> | Record<string, unknown>): string {
  return sha256CanonicalTaskJson(taskCase);
}

export function taskPolicyHash(input: Pick<TaskReleaseManifest, 'inventory' | 'pricing' | 'deadlines' | 'costPolicy' | 'participantToolProtocol'>): string {
  return sha256CanonicalTaskJson({
    rubricVersion: 'bts-rubric/v1',
    inventory: input.inventory,
    pricing: input.pricing,
    deadlines: input.deadlines,
    costPolicy: input.costPolicy,
    ...(input.participantToolProtocol === undefined ? {} : { participantToolProtocol: input.participantToolProtocol }),
    rubricHashes: TASK_IDS.map((taskId) => ({ taskId, rubricHash: taskRubricHash(taskId) })),
  });
}

export function taskBenchmarkHash(input: Pick<TaskReleaseManifest, 'benchmarkVersion' | 'executionIdentityHash' | 'policyHash' | 'cases'>): string {
  return sha256CanonicalTaskJson({
    benchmarkVersion: input.benchmarkVersion,
    executionIdentityHash: input.executionIdentityHash,
    policyHash: input.policyHash,
    trainingCaseHashes: input.cases.training.map((taskCase) => ({ taskId: taskCase.taskId, caseHash: taskCase.caseHash })),
    rankedCaseHashes: input.cases.ranked.map((taskCase) => ({ taskId: taskCase.taskId, caseHash: taskCase.caseHash })),
  });
}

function withoutKey<T extends Record<string, unknown>>(object: T, key: string): Omit<T, keyof T & string> & Record<string, unknown> {
  const { [key]: _discarded, ...remaining } = object;
  return remaining;
}

function weightFor(taskId: TaskId): 1 | 2 | 3 | 5 { return WEIGHT[taskId]; }

function caseIdsForMode(mode: TaskMode): readonly TaskId[] {
  return mode === 'ranked' ? TASK_IDS : TASK_IDS.filter(isOpenTrainingTask);
}

function checkUnique<T>(values: readonly T[], key: (value: T) => string): boolean {
  const keys = values.map(key);
  return new Set(keys).size === keys.length;
}

function hasPlaceholder(value: unknown, path: readonly string[] = []): boolean {
  if (typeof value === 'string') {
    // AICODE-NOTE: `unknown` is the required cost-policy value for missing fee evidence; exempt only this exact typed field while rejecting unresolved values elsewhere.
    if (path.length === 2 && path[0] === 'costPolicy' && path[1] === 'missingFeeEvidence' && value === 'unknown') return false;
    return /\b(?:tbd|todo|placeholder|latest|unknown)\b|\{\{|\}\}/i.test(value);
  }
  if (Array.isArray(value)) return value.some((entry, index) => hasPlaceholder(entry, [...path, String(index)]));
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).some(([key, entry]) => hasPlaceholder(entry, [...path, key]));
  }
  return false;
}

function componentValidatorsComplete(components: readonly z.infer<typeof DataComponentSchema>[]): boolean {
  return components.every(({ validator }) => {
    const names = validator.requiredFields.map((field) => field.name);
    if (!checkUnique(validator.requiredFields, (field) => field.name) || !checkUnique(validator.permittedProvenance, (source) => source)) return false;
    return validator.predicates.every((predicate) => names.includes(predicate.field));
  });
}

function payoutKeysUnique(obligations: readonly z.infer<typeof PayoutObligationSchema>[]): boolean {
  return checkUnique(obligations, (item) => `${item.recipient.toLowerCase()}|${item.assetId}|${item.exactAmountUnits}`)
    && checkUnique(obligations, (item) => item.obligationId);
}

function qualifyingOffer(offer: z.infer<typeof UsdOfferSchema>, required: z.infer<typeof CatalogPredicateSchema>): boolean {
  return offer.dataType === required.requiredDataType &&
    BigInt(offer.advertisedTotalPriceUsdcUnits) <= BigInt(required.maxAdvertisedTotalPriceUsdcUnits) &&
    offer.network === required.network && offer.assetId === required.assetId &&
    offer.recipient.toLowerCase() === required.recipient.toLowerCase();
}

function paymentRequirementsValid(requirements: z.infer<typeof PaymentRequirementsSchema>, assets: ReadonlyMap<string, z.infer<typeof AssetIdentitySchema>>): boolean {
  return assets.has(requirements.assetId) && checkUnique(requirements.authFields, (field) => field.name);
}

function caseSpecificBlockers(taskCase: TaskCase, subject: string): Array<{ code: TaskReleaseBlockerCode; subject: string }> {
  const blockers: Array<{ code: TaskReleaseBlockerCode; subject: string }> = [];
  if (taskCase.taskId === 'S3') {
    const qualifying = taskCase.objective.catalog.filter((offer) => qualifyingOffer(offer, taskCase.objective.required));
    if (qualifying.length === 0 || qualifying.length === taskCase.objective.catalog.length) blockers.push({ code: 'invalid_catalog_predicates', subject });
  }
  if (taskCase.taskId === 'M2') {
    const qualifying = taskCase.objective.catalog.filter((offer) => qualifyingOffer(offer, taskCase.objective.required));
    const prices = new Set(qualifying.map((offer) => offer.advertisedTotalPriceUsdcUnits));
    if (qualifying.length < 2 || prices.size < 2) blockers.push({ code: 'invalid_catalog_predicates', subject });
  }
  if (taskCase.taskId === 'H1' || taskCase.taskId === 'U1') {
    const components = taskCase.objective.requiredComponents;
    if (!checkUnique(components, (item) => item.componentId) || !componentValidatorsComplete(components)) {
      blockers.push({ code: 'missing_component_validator_field', subject });
    }
  }
  if (taskCase.taskId === 'H2' && !payoutKeysUnique(taskCase.objective.obligations)) {
    blockers.push({ code: 'invalid_u1_fixed_sets', subject });
  }
  if (taskCase.taskId === 'U1') {
    const { objective } = taskCase;
    const allocationIds = objective.allocationAssets.map((asset) => asset.assetId);
    const spenderKeys = objective.temporarySpenderScope.map((item) => `${item.owner.toLowerCase?.() ?? item.owner}|${item.tokenAssetId}|${item.spender.toLowerCase()}`);
    const targetBps = objective.allocationAssets.reduce((sum, asset) => sum + asset.targetShareBps, 0);
    const initialComponentMatch = objective.requiredComponents.some((component) => taskCase.initialState.deliveredComponentIds.includes(component.componentId));
    if (!checkUnique(objective.requiredComponents, (item) => item.componentId) || !componentValidatorsComplete(objective.requiredComponents) ||
        !checkUnique(allocationIds, (item) => item) || targetBps !== 10000 ||
        !checkUnique(objective.payoutObligations, (item) => `${item.recipient.toLowerCase()}|${item.assetId}|${item.exactAmountUnits}`) ||
        !checkUnique(objective.payoutObligations, (item) => item.obligationId) ||
        !checkUnique(spenderKeys, (item) => item) || initialComponentMatch ||
        objective.payoutObligations.some((item) => taskCase.initialState.fulfilledObligationIds.includes(item.obligationId)) ||
        isInitialAllocationSatisfied(taskCase)) {
      blockers.push({ code: 'invalid_u1_fixed_sets', subject });
    }
  }
  if (taskCase.taskId === 'M1' && taskCase.initialState.deliveredComponentIds.includes(taskCase.objective.component.componentId)) {
    blockers.push({ code: 'unsolvable_or_initially_solved_case', subject });
  }
  if (taskCase.taskId === 'M2' && taskCase.objective.catalog.some((offer) => taskCase.initialState.deliveredComponentIds.includes(offer.offerId))) {
    blockers.push({ code: 'unsolvable_or_initially_solved_case', subject });
  }
  if (taskCase.taskId === 'H3' && taskCase.initialState.deliveredComponentIds.includes(taskCase.objective.referenceComponent.componentId)) {
    blockers.push({ code: 'unsolvable_or_initially_solved_case', subject });
  }
  return blockers;
}

function isInitialAllocationSatisfied(taskCase: z.infer<typeof U1Schema>): boolean {
  const assets = taskCase.objective.allocationAssets;
  const values = assets.map((target) => {
    const asset = taskCase.initialState.balances.filter((balance) => balance.account === 'participant' && balance.assetId === target.assetId)
      .reduce((sum, balance) => sum + BigInt(balance.amountUnits), 0n);
    const valuationNumerator = BigInt(target.usdcBaseUnitsPerAssetBaseUnit.numerator);
    const valuationDenominator = BigInt(target.usdcBaseUnitsPerAssetBaseUnit.denominator);
    return { target, numerator: asset * valuationNumerator, denominator: valuationDenominator };
  });
  if (values.every((value) => value.numerator === 0n)) return false;
  let totalNumerator = 0n;
  let totalDenominator = 1n;
  for (const value of values) {
    totalNumerator = totalNumerator * value.denominator + value.numerator * totalDenominator;
    totalDenominator *= value.denominator;
    const divisor = gcd(totalNumerator, totalDenominator);
    totalNumerator /= divisor;
    totalDenominator /= divisor;
  }
  if (totalNumerator === 0n) return false;
  return values.every(({ target, numerator, denominator }) => {
    const absoluteNumerator = numerator * totalDenominator * 10000n;
    const assetDenominator = denominator * totalNumerator;
    const targetNumerator = BigInt(target.targetShareBps) * assetDenominator;
    const delta = absoluteNumerator >= targetNumerator ? absoluteNumerator - targetNumerator : targetNumerator - absoluteNumerator;
    return delta <= BigInt(target.toleranceBps) * assetDenominator;
  });
}

function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a === 0n ? 1n : a;
}

function executionIdentityComplete(manifest: TaskReleaseManifest): boolean {
  const identity = manifest.executionIdentity;
  if (identity.sourceChainId !== identity.localChainId || identity.sourceBlockNumber !== identity.localForkBlockNumber ||
      !checkUnique(identity.assets, (asset) => asset.assetId) ||
      !checkUnique(identity.contracts, (contract) => contract.contractId) ||
      !checkUnique(identity.contracts, (contract) => `${contract.chainId}:${contract.address.toLowerCase()}`)) return false;
  const assetAddresses = new Set<string>();
  for (const asset of identity.assets) {
    if (asset.chainId !== identity.localChainId) return false;
    if (asset.kind === 'native') {
      if (asset.address !== null || asset.codeHash !== null) return false;
    } else {
      if (asset.address === null || asset.codeHash === null) return false;
      const key = `${asset.chainId}:${asset.address.toLowerCase()}`;
      if (assetAddresses.has(key)) return false;
      assetAddresses.add(key);
    }
  }
  if (!identity.assets.some((asset) => asset.assetId === 'ETH' && asset.kind === 'native' && asset.decimals === 18) ||
      !identity.assets.some((asset) => asset.assetId === 'WETH' && asset.kind === 'erc20' && asset.decimals === 18) ||
      !identity.assets.some((asset) => asset.assetId === 'USDC' && asset.kind === 'erc20' && asset.decimals === 6)) return false;
  return identity.contracts.every((contract) => contract.chainId === identity.sourceChainId &&
    contract.blockNumber === identity.sourceBlockNumber && contract.blockHash.toLowerCase() === identity.sourceBlockHash.toLowerCase());
}

function taskReferencesValid(taskCase: TaskCase, manifest: TaskReleaseManifest): boolean {
  const assets = new Map(manifest.executionIdentity.assets.map((asset) => [asset.assetId, asset]));
  const contracts = new Map(manifest.executionIdentity.contracts.map((contract) => [contract.contractId, contract]));
  const state = taskCase.initialState;
  if (!checkUnique(state.balances, (item) => `${item.account.toLowerCase()}|${item.assetId}`) ||
      !checkUnique(state.allowances, (item) => `${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`) ||
      !checkUnique(state.deliveredComponentIds, (item) => item) || !checkUnique(state.fulfilledObligationIds, (item) => item) ||
      state.balances.some((item) => !assets.has(item.assetId)) || state.allowances.some((item) => !assets.has(item.tokenAssetId))) return false;

  const routeValid = (route: z.infer<typeof RouteSchema>) =>
    route.tokenInAssetId !== route.tokenOutAssetId && assets.has(route.tokenInAssetId) && assets.has(route.tokenOutAssetId) &&
    contracts.has(route.routerContractId) && contracts.has(route.poolContractId);
  const componentValid = (component: z.infer<typeof DataComponentSchema>) =>
    component.sourceIds.some((sourceId) => component.validator.permittedProvenance.includes(sourceId)) &&
    componentValidatorsComplete([component]);
  const offerValid = (offer: z.infer<typeof UsdOfferSchema>) =>
    offer.assetId === offer.paymentRequirements.assetId && offer.network === offer.paymentRequirements.network &&
    offer.recipient.toLowerCase() === offer.paymentRequirements.recipient.toLowerCase() &&
    offer.resourceId === offer.paymentRequirements.resourceId && offer.offerId === offer.paymentRequirements.offerId &&
    offer.advertisedTotalPriceUsdcUnits === offer.paymentRequirements.amountUnits && paymentRequirementsValid(offer.paymentRequirements, assets);
  const hasBalance = (account: string, assetId: string, minimum: string) => state.balances.some((entry) =>
    entry.account.toLowerCase() === account.toLowerCase() && entry.assetId === assetId && BigInt(entry.amountUnits) >= BigInt(minimum));
  const hasRecipientBaseline = (obligation: { recipient: string; assetId: string }) => state.balances.some((entry) =>
    entry.account.toLowerCase() === obligation.recipient.toLowerCase() && entry.assetId === obligation.assetId);

  switch (taskCase.taskId) {
    case 'S1':
      return taskCase.objective.recipient !== 'participant' && assets.get('USDC')?.kind === 'erc20' &&
        state.balances.some((entry) => entry.account.toLowerCase() === taskCase.objective.recipient.toLowerCase() && entry.assetId === 'USDC') &&
        hasBalance('participant', 'USDC', taskCase.objective.exactPrincipalUnits) &&
        hasBalance('participant', 'ETH', taskCase.objective.nativeReserveWei);
    case 'S2':
      return taskCase.objective.resourceId === taskCase.objective.completePaymentRequirements.resourceId &&
        taskCase.objective.offerId === taskCase.objective.completePaymentRequirements.offerId &&
        paymentRequirementsValid(taskCase.objective.completePaymentRequirements, assets) &&
        taskCase.objective.requiredAnswerFields.length > 0 &&
        checkUnique(taskCase.objective.requiredAnswerFields, (item) => item) &&
        ['amountUnits', 'network', 'assetId', 'recipient', 'scheme', 'resourceId', 'offerId', 'version', ...taskCase.objective.completePaymentRequirements.authFields.map((field) => field.name)]
          .every((field) => taskCase.objective.requiredAnswerFields.includes(field));
    case 'S3':
      return checkUnique(taskCase.objective.catalog, (offer) => offer.offerId) && taskCase.objective.catalog.every(offerValid);
    case 'S4': {
      const allowance = state.allowances.find((entry) => entry.owner === 'participant' && entry.tokenAssetId === taskCase.objective.tokenAssetId && entry.spender.toLowerCase() === taskCase.objective.spender.toLowerCase());
      return assets.get(taskCase.objective.tokenAssetId)?.kind === 'erc20' && allowance !== undefined &&
        allowance.amountUnits === taskCase.objective.initialAllowanceUnits && BigInt(allowance.amountUnits) > 0n;
    }
    case 'M1':
      return componentValid(taskCase.objective.component) && taskCase.objective.component.resourceId === taskCase.objective.paymentRequirements.resourceId &&
        taskCase.objective.component.componentId !== '' && !state.deliveredComponentIds.includes(taskCase.objective.component.componentId) &&
        paymentRequirementsValid(taskCase.objective.paymentRequirements, assets) &&
        taskCase.objective.paymentRequirements.assetId === 'USDC' && assets.has('USDC');
    case 'M2':
      return checkUnique(taskCase.objective.catalog, (offer) => offer.offerId) && taskCase.objective.catalog.every(offerValid) &&
        taskCase.objective.catalog.every((offer) => offer.deliveryValidator.requiredFields.length > 0);
    case 'M3':
      return assets.has(taskCase.objective.inputAssetId) && taskCase.objective.permittedRoutes.some((route) =>
        routeValid(route) && route.tokenInAssetId === taskCase.objective.inputAssetId && route.tokenOutAssetId === 'WETH') &&
        hasBalance('participant', taskCase.objective.inputAssetId, taskCase.objective.exactInputUnits) &&
        hasBalance('participant', 'ETH', taskCase.objective.nativeReserveWei);
    case 'M4':
      return assets.has(taskCase.objective.inputAssetId) && assets.has(taskCase.objective.outputAssetId) &&
        taskCase.objective.permittedRoutes.length > 0 && taskCase.objective.permittedRoutes.every(routeValid) &&
        taskCase.objective.initialAllowanceScope.length > 0 &&
        checkUnique(taskCase.objective.initialAllowanceScope, (entry) => `${entry.owner.toLowerCase()}|${entry.tokenAssetId}|${entry.spender.toLowerCase()}`) &&
        taskCase.objective.initialAllowanceScope.every((entry) => assets.has(entry.tokenAssetId));
    case 'H1':
      return checkUnique(taskCase.objective.requiredComponents, (item) => item.componentId) &&
        taskCase.objective.requiredComponents.every((component) => componentValid(component) &&
          component.sourceIds.some((sourceId) => taskCase.objective.permittedSources.includes(sourceId)) &&
          !state.deliveredComponentIds.includes(component.componentId));
    case 'H2':
      return payoutKeysUnique(taskCase.objective.obligations) && taskCase.objective.obligations.every((item) => assets.has(item.assetId)) &&
        taskCase.objective.obligations.every(hasRecipientBaseline) &&
        taskCase.objective.initialAssetIds.every((assetId) => assets.has(assetId)) &&
        taskCase.objective.permittedConversions.every(routeValid) && checkUnique(taskCase.objective.initialAssetIds, (item) => item) &&
        !taskCase.objective.obligations.some((item) => state.fulfilledObligationIds.includes(item.obligationId));
    case 'H3': {
      const { routeObjective, referenceComponent, permittedRoutes } = taskCase.objective;
      const routeIds = permittedRoutes.map((route) => route.routeId);
      const valueField = referenceComponent.validator.requiredFields.find((field) => field.name === routeObjective.referenceField);
      return componentValid(referenceComponent) && checkUnique(permittedRoutes, (route) => route.routeId) && permittedRoutes.every(routeValid) &&
        checkUnique(routeObjective.allowedRouteIds, (routeId) => routeId) && routeObjective.allowedRouteIds.every((routeId) => routeIds.includes(routeId)) &&
        checkUnique(routeObjective.expectedRouteByValue, (entry) => entry.value) &&
        routeObjective.expectedRouteByValue.every((entry) => routeObjective.allowedRouteIds.includes(entry.routeId)) &&
        Boolean(valueField && valueField.type === 'string' && valueField.enumValues?.some((value) => routeObjective.expectedRouteByValue.some((entry) => entry.value === value))) &&
        !state.deliveredComponentIds.includes(referenceComponent.componentId);
    }
    case 'U1':
      return taskCase.objective.permittedRoutes.every(routeValid) &&
        checkUnique(taskCase.objective.permittedRoutes, (route) => route.routeId) &&
        taskCase.objective.requiredComponents.every((component) => componentValid(component) &&
          component.sourceIds.some((sourceId) => taskCase.objective.permittedSources.includes(sourceId))) &&
        taskCase.objective.allocationAssets.every((allocation) => assets.has(allocation.assetId)) &&
        payoutKeysUnique(taskCase.objective.payoutObligations) && taskCase.objective.payoutObligations.every((item) => assets.has(item.assetId)) &&
        taskCase.objective.payoutObligations.every(hasRecipientBaseline) &&
        taskCase.objective.temporarySpenderScope.every((item) => assets.has(item.tokenAssetId));
  }
}

function exerciseIdentity(taskCase: TaskCase): string {
  const normalize = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(normalize).sort((a, b) => {
      const left = canonicalTaskJson(a), right = canonicalTaskJson(b);
      return left < right ? -1 : left > right ? 1 : 0;
    });
    if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalize(item)]));
    return value;
  };
  return sha256CanonicalTaskJson(normalize({ objective: taskCase.objective,
    initialState: withoutKey(taskCase.initialState as unknown as Record<string, unknown>, 'stateSha256') }));
}

function staticBlockers(manifest: TaskReleaseManifest): Array<{ code: TaskReleaseBlockerCode; subject: string }> {
  const blockers: Array<{ code: TaskReleaseBlockerCode; subject: string }> = [];
  if (manifest.executionIdentityHash !== sha256CanonicalTaskJson(manifest.executionIdentity)) blockers.push({ code: 'execution_identity_hash_mismatch', subject: 'executionIdentity' });
  if (!executionIdentityComplete(manifest)) blockers.push({ code: 'invalid_execution_identity', subject: 'executionIdentity' });
  if (manifest.policyHash !== taskPolicyHash(manifest)) blockers.push({ code: 'policy_hash_mismatch', subject: 'policyHash' });
  if (manifest.benchmarkHash !== taskBenchmarkHash(manifest)) blockers.push({ code: 'benchmark_hash_mismatch', subject: 'benchmarkHash' });
  if (manifest.manifestHash !== sha256CanonicalTaskJson(withoutKey(manifest as unknown as Record<string, unknown>, 'manifestHash'))) blockers.push({ code: 'manifest_hash_mismatch', subject: 'manifestHash' });
  for (const mode of ['training', 'ranked'] as const) {
    const cases = manifest.cases[mode];
    const expected = caseIdsForMode(mode);
    if (cases.some((taskCase, index) => taskCase.taskId !== expected[index] || taskCase.mode !== mode || taskCase.taskWeight !== weightFor(taskCase.taskId))) {
      blockers.push({ code: 'case_order_or_weight_mismatch', subject: mode });
    }
    if (!checkUnique(cases, (taskCase) => taskCase.caseId)) blockers.push({ code: 'duplicate_case_identity', subject: mode });
    for (const taskCase of cases) {
      const subject = `${mode}/${taskCase.taskId}/${taskCase.caseId}`;
      const caseHash = sha256CanonicalTaskJson(withoutKey(taskCase as unknown as Record<string, unknown>, 'caseHash'));
      if (taskCase.caseHash !== caseHash) blockers.push({ code: 'case_hash_mismatch', subject });
      if (taskCase.rubricVersion !== 'bts-rubric/v1' || taskCase.rubricHash !== taskRubricHash(taskCase.taskId)) blockers.push({ code: 'rubric_hash_mismatch', subject });
      if (taskCase.mandatoryRules.length !== MANDATORY_RULES[taskCase.taskId].length ||
          taskCase.mandatoryRules.some((rule, index) => rule !== MANDATORY_RULES[taskCase.taskId][index])) {
        blockers.push({ code: 'rubric_hash_mismatch', subject });
      }
      if (taskCase.taskDeadlineSeconds > manifest.deadlines.taskTimeoutSeconds || taskCase.taskDeadlineSeconds >
          (mode === 'ranked' ? manifest.deadlines.rankedRunTimeoutSeconds : manifest.deadlines.trainingRunTimeoutSeconds)) {
        blockers.push({ code: 'task_deadline_mismatch', subject });
      }
      if (taskCase.executionIdentityHash !== manifest.executionIdentityHash || taskCase.referencePath.toolSurfaceSha256 !== manifest.executionIdentity.toolSurfaceSha256 ||
          taskCase.referencePath.initialStateSha256 !== taskCase.initialState.stateSha256 ||
          taskCase.referencePath.actionCount < 1 ||
          // AICODE-NOTE: S2/S3 must leave executor state unchanged; their answer is verified separately.
          (!['S2', 'S3'].includes(taskCase.taskId) && taskCase.referencePath.finalStateSha256 === taskCase.referencePath.initialStateSha256)) {
        blockers.push({ code: 'case_identity_or_initial_state_mismatch', subject });
      }
      if (!taskReferencesValid(taskCase, manifest)) blockers.push({ code: 'invalid_task_reference', subject });
      blockers.push(...caseSpecificBlockers(taskCase, subject));
      if (hasPlaceholder(taskCase)) blockers.push({ code: 'placeholder_or_latest_value', subject });
    }
  }
  const trainingById = new Map(manifest.cases.training.map((taskCase) => [taskCase.taskId, taskCase]));
  for (const taskCase of manifest.cases.ranked) {
    const trainingCase = trainingById.get(taskCase.taskId);
    // AICODE-NOTE: Mode, labels and evidence paths already change caseHash. They
    // cannot establish distinct exercises with identical goals and initial state.
    if (trainingCase && exerciseIdentity(trainingCase) === exerciseIdentity(taskCase)) {
      blockers.push({ code: 'training_ranked_cases_not_distinct', subject: taskCase.taskId });
    }
  }
  if (hasPlaceholder(manifest)) blockers.push({ code: 'placeholder_or_latest_value', subject: 'manifest' });
  return blockers;
}

function makeAdmissionRelease(release: ValidatedTaskReleaseRecord, mode: TaskMode): RunAdmissionRelease {
  const taskIds = mode === 'ranked' ? TASK_IDS : TASK_IDS.filter(isOpenTrainingTask);
  const weights = taskIds.map(weightFor);
  return {
    releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash,
    benchmarkVersion: release.benchmarkVersion,
    benchmarkHash: release.benchmarkHash,
    policyHash: release.policyHash,
    mode,
    taskIds,
    weights,
    priceUnits: mode === 'ranked' ? release.manifest.pricing.rankedPriceUnits : release.manifest.pricing.openTrainingPriceUnits,
    precision: 6,
  };
}

export async function validateTaskReleaseCandidate(
  candidate: unknown,
  verifier: TaskReleaseEvidenceVerifier,
): Promise<TaskReleaseValidationResult> {
  const parsed = TaskReleaseManifestSchema.safeParse(candidate);
  if (!parsed.success) {
    return {
      status: 'blocked',
      manifestHash: null,
      blockers: parsed.error.issues.map((issue) => ({ code: 'manifest_schema_invalid', subject: issue.path.join('.') || 'manifest', detail: issue.message })),
    };
  }
  const manifest = parsed.data;
  const blockers = staticBlockers(manifest);
  if (blockers.length) return { status: 'blocked', manifestHash: manifest.manifestHash, blockers };

  const feasibility = await verifier.verifyFeasibility(manifest.feasibilityEvidence, manifest.executionIdentity,
    manifest.executionIdentityHash, manifest.participantToolProtocol);
  if (feasibility.status === 'unavailable') return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'feasibility_evidence_unavailable', subject: 'feasibilityEvidence', detail: feasibility.reason }] };
  if (feasibility.status !== 'verified' || feasibility.executionIdentityHash !== manifest.executionIdentityHash || !feasibility.actualBoundary) {
    return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'missing_feasibility_evidence', subject: 'feasibilityEvidence' }] };
  }

  const allCases = [...manifest.cases.training, ...manifest.cases.ranked];
  for (const taskCase of allCases) {
    const verification = await verifier.verifyReferencePath({ evidence: taskCase.referencePath.evidence, taskCase, executionIdentityHash: manifest.executionIdentityHash });
    const subject = `${taskCase.mode}/${taskCase.taskId}/${taskCase.caseId}`;
    if (verification.status === 'unavailable') return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'reference_path_evidence_unavailable', subject, detail: verification.reason }] };
    if (verification.status === 'unsolvable' || verification.status === 'initially_solved') {
      return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'unsolvable_or_initially_solved_case', subject, detail: verification.reason }] };
    }
    if (verification.status !== 'verified' || !verification.actualBoundary || verification.caseHash !== taskCase.caseHash ||
        verification.executionIdentityHash !== manifest.executionIdentityHash || verification.toolSurfaceSha256 !== manifest.executionIdentity.toolSurfaceSha256 ||
        verification.actionCount !== taskCase.referencePath.actionCount || verification.initialStateSha256 !== taskCase.initialState.stateSha256 ||
        verification.finalStateSha256 !== taskCase.referencePath.finalStateSha256 || !verification.solvable || verification.initiallySolved) {
      return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'reference_path_not_solvable', subject }] };
    }
  }

  const difficulty = await verifier.verifyDifficultyReview(manifest.difficultyReviewEvidence, allCases, manifest.executionIdentityHash);
  if (difficulty.status === 'unavailable') return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'difficulty_review_missing', subject: 'difficultyReviewEvidence', detail: difficulty.reason }] };
  if (difficulty.status !== 'approved' || difficulty.executionIdentityHash !== manifest.executionIdentityHash || !difficulty.actualBoundary) {
    return { status: 'blocked', manifestHash: manifest.manifestHash, blockers: [{ code: 'difficulty_incompatible_requires_review', subject: 'difficultyReviewEvidence', detail: difficulty.status === 'incompatible' ? difficulty.findings.join('; ') : 'difficulty review did not approve the release' }] };
  }

  const release: ValidatedTaskReleaseRecord = {
    releaseIdentity: manifest.releaseIdentity,
    manifestHash: manifest.manifestHash,
    benchmarkVersion: manifest.benchmarkVersion,
    benchmarkHash: manifest.benchmarkHash,
    policyHash: manifest.policyHash,
    manifest,
  };
  return {
    status: 'validated',
    release,
    validationEvidence: [
      { kind: 'feasibility', sha256: manifest.feasibilityEvidence.sha256 },
      ...allCases.map((taskCase) => ({ kind: 'reference_path' as const, sha256: taskCase.referencePath.evidence.sha256 })),
      { kind: 'difficulty_review', sha256: manifest.difficultyReviewEvidence.sha256 },
    ],
  };
}

export async function activateTaskReleaseCandidate(
  candidate: unknown,
  verifier: TaskReleaseEvidenceVerifier,
  store: TaskReleaseStore,
  tx: TaskReleaseTransaction,
): Promise<TaskReleaseValidationResult> {
  const result = await validateTaskReleaseCandidate(candidate, verifier);
  if (result.status !== 'validated') return result;
  await store.activateValidatedRelease(result.release, result.validationEvidence, tx);
  return result;
}

/** Read-time projection; the sealed `manifest` is never part of this value. */
export function admissionProjection(release: ValidatedTaskReleaseRecord, mode: TaskMode): RunAdmissionRelease {
  return makeAdmissionRelease(release, mode);
}

/** Returns only lifecycle fields for the requested mode; cases remain sealed. */
export function validatedModeProjection(release: ValidatedTaskReleaseRecord, mode: TaskMode): ValidatedTaskRelease {
  const taskCases = release.manifest.cases[mode];
  return {
    releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash,
    benchmarkVersion: release.benchmarkVersion,
    benchmarkHash: release.benchmarkHash,
    policyHash: release.policyHash,
    mode,
    taskIds: taskCases.map((taskCase) => taskCase.taskId),
    weights: taskCases.map((taskCase) => taskCase.taskWeight),
    taskDeadlines: taskCases.map((taskCase) => ({ taskId: taskCase.taskId, timeoutSeconds: taskCase.taskDeadlineSeconds })),
    overallTimeoutSeconds: mode === 'ranked' ? release.manifest.deadlines.rankedRunTimeoutSeconds : release.manifest.deadlines.trainingRunTimeoutSeconds,
    pricing: {
      priceUnits: mode === 'ranked' ? release.manifest.pricing.rankedPriceUnits : release.manifest.pricing.openTrainingPriceUnits,
      precision: 6,
    },
  };
}

export function createTaskReleaseProvider(source: TaskReleaseQuerySource): TaskReleaseProvider {
  return {
    async getActiveAdmissionRelease(mode, tx) {
      const release = await source.getActiveAdmissionRelease(mode, tx);
      if (!release || !isAdmissionReleaseShape(release, mode)) return null;
      return release;
    },
    async getValidatedRelease(releaseIdentity, manifestHash, mode, tx) {
      const release = await source.getValidatedReleaseRecord(releaseIdentity, manifestHash, tx);
      if (!release || release.releaseIdentity !== releaseIdentity || release.manifestHash !== manifestHash ||
          release.manifest.manifestHash !== manifestHash || release.manifest.cases.ranked.length !== 12 || release.manifest.cases.training.length !== 3) return null;
      return validatedModeProjection(release, mode);
    },
    getPublicCatalog: () => PUBLIC_TASK_CATALOG,
  };
}

function isAdmissionReleaseShape(value: RunAdmissionRelease, mode: TaskMode): boolean {
  const expected = caseIdsForMode(mode);
  return value.mode === mode && value.precision === 6 && value.taskIds.length === expected.length &&
    value.weights.length === expected.length && value.taskIds.every((taskId, index) => taskId === expected[index] && value.weights[index] === weightFor(taskId)) &&
    /^[0-9a-f]{64}$/i.test(value.manifestHash) && /^[0-9a-f]{64}$/i.test(value.benchmarkHash) &&
    /^[0-9a-f]{64}$/i.test(value.policyHash) && UINT.test(value.priceUnits);
}

export const unavailableTaskReleaseProvider: TaskReleaseProvider = Object.freeze({
  async getActiveAdmissionRelease() { return null; },
  async getValidatedRelease() { return null; },
  getPublicCatalog() { return PUBLIC_TASK_CATALOG; },
});

export function closedFeedbackCategory(value: string): 'goal_unmet' | 'budget_reserve_permission_scope_violation' | 'time_exhausted' | 'evidence_unknown' | null {
  switch (value) {
    case 'goal_unmet':
    case 'budget_reserve_permission_scope_violation':
    case 'time_exhausted':
    case 'evidence_unknown': return value;
    default: return null;
  }
}

export function modeCaseList(release: ValidatedTaskReleaseRecord, mode: TaskMode): readonly TaskCase[] {
  return release.manifest.cases[mode];
}
