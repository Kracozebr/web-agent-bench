/**
 * Offline, fail-closed assembly of unactivated ranked BTS TaskCase candidates.
 *
 * This binds observed local-fork primitives and one versioned local policy
 * profile. It does not validate a release, approve difficulty, grade tasks, or
 * activate anything. A caller must write the returned evidence envelope bytes
 * to their returned paths before presenting the candidate cases to a verifier.
 */
import { createHash } from 'node:crypto';
import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { z } from 'zod';
import {
  TaskCaseSchema,
  canonicalTaskJson,
  sha256CanonicalTaskJson,
  taskCaseHash,
  taskRubricHash,
  type TaskCase,
} from './task-release.js';
import {
  verifyTaskCaptureInventory,
  type CapturePin,
  type TaskReferenceCaptureSource,
  type TaskReferenceInventoryResult,
  type TrainingTaskId,
  type VerifiedRawArtifact,
} from './task-reference-inventory.js';
import type { TaskId } from './task-catalog.js';

const TASK_ORDER = ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1'] as const satisfies readonly TaskId[];
const TRAINING_TASK_ORDER = ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2'] as const satisfies readonly TrainingTaskId[];
const COMPOSITE_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store' as const;
const DEFAULT_INPUT_INDEX = 'artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249.json';
const DEFAULT_TRAINING_INPUT_INDEX = 'artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249-training.json';
const DEFAULT_LOCAL_POLICY = 'infrastructure/owner-identity/task-release-local-policy.json';
const EVIDENCE_KIND = z.object({
  path: z.string().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  boundary: z.string().min(1),
  contentType: z.literal('application/json'),
}).strict();

const CaptureSourceSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('unified_reference'), relativeDirectory: z.string().min(1), expectedProbeSha256: z.string().regex(/^[0-9a-f]{64}$/i) }).strict(),
  z.object({ kind: z.literal('native_reference'), relativeDirectory: z.string().min(1), expectedProbeSha256: z.string().regex(/^[0-9a-f]{64}$/i) }).strict(),
  z.object({ kind: z.literal('h3_reference'), relativeDirectory: z.string().min(1), expectedProbeSha256: z.string().regex(/^[0-9a-f]{64}$/i) }).strict(),
  z.object({ kind: z.literal('u1_reference'), relativeDirectory: z.string().min(1), expectedProbeSha256: z.string().regex(/^[0-9a-f]{64}$/i) }).strict(),
  z.object({ kind: z.literal('training_reference'), relativeDirectory: z.string().min(1), expectedProbeSha256: z.string().regex(/^[0-9a-f]{64}$/i) }).strict(),
]);

const LocalPolicySchema = z.object({
  schemaVersion: z.literal('bts-local-case-assembly-policy/v1'),
  profileId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  boundary: z.literal('isolated_local_bef_anvil_fork'),
  taskDeadlineSeconds: z.number().int().positive(),
  trainingRunTimeoutSeconds: z.number().int().positive(),
  rankedRunTimeoutSeconds: z.number().int().positive(),
  expenseBudget: z.object({
    basis: z.tuple([z.literal('paid_service_charge'), z.literal('participant_gas_success_or_revert'), z.literal('verified_dex_fee')]),
    participantGasConversion: z.literal('floor_after_summing_receipt_gas_wei_at_pinned_rate'),
    dexFeeConversion: z.literal('ceil_exact_input_units_times_fee_tier_over_1000000'),
    headroomMultiplierNumerator: z.string().regex(/^[1-9][0-9]*$/),
    headroomMultiplierDenominator: z.string().regex(/^[1-9][0-9]*$/),
    roundUpToUsdcUnits: z.string().regex(/^[1-9][0-9]*$/),
    excludePrincipal: z.literal(true),
    excludeSponsoredFacilitatorGas: z.literal(true),
    pinOnceAfterReferenceBeforeReleaseActivation: z.literal(true),
  }).strict(),
  nativeReserveWei: z.object({
    S1: z.string().regex(/^[1-9][0-9]*$/).optional(),
    S4: z.string().regex(/^[1-9][0-9]*$/).optional(),
    M3: z.string().regex(/^[1-9][0-9]*$/).optional(),
    M4: z.string().regex(/^[1-9][0-9]*$/).optional(),
    H2: z.string().regex(/^[1-9][0-9]*$/).optional(),
    H3: z.string().regex(/^[1-9][0-9]*$/).optional(),
    U1: z.string().regex(/^[1-9][0-9]*$/).optional(),
  }).strict(),
  permittedProvenanceIds: z.array(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)).min(1),
  duplicatePurchaseIdentity: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  routeContractIds: z.object({
    fee500: z.object({ routerContractId: z.string().min(1), poolContractId: z.string().min(1) }).strict(),
    fee3000: z.object({ routerContractId: z.string().min(1), poolContractId: z.string().min(1) }).strict(),
  }).strict(),
  difficultyApproval: z.literal(false),
  releaseActivation: z.literal(false),
}).strict();

type JsonRecord = Record<string, any>;
type LocalPolicy = z.infer<typeof LocalPolicySchema>;
type EvidenceRef = { path: string; sha256: string; boundary: string; contentType: 'application/json' };
type StateProjection = {
  balances: Array<{ account: 'participant' | string; assetId: string; amountUnits: string }>;
  allowances: Array<{ owner: 'participant' | string; tokenAssetId: string; spender: string; amountUnits: string }>;
  deliveredComponentIds: string[];
  fulfilledObligationIds: string[];
};

export type TaskCaseEvidenceEnvelope = {
  schemaVersion: 'bts-task-case-evidence-composition/v1';
  classification: 'verified_local_reference_composition_not_task_acceptance';
  taskId: TaskId;
  caseId: string;
  mode?: 'training' | 'ranked';
  trainingCaptureInput?: {
    kind: 'training_reference';
    relativeDirectory: string;
    probeSha256: string;
    manifestSha256: string;
    applicationSourceSha256: string;
  };
  purpose: 'initial_state_baseline' | 'reference_execution_trace';
  boundary: typeof COMPOSITE_BOUNDARY;
  paidSettlementObserved: boolean;
  policyInput: { path: string; sha256: string; profileId: string };
  sourceIndexInput: { path: string; sha256: string };
  inventoryPins: CapturePin;
  applicationSchemaLineage: {
    classification: 'checked_in_migrations_plus_pinned_application_source_not_independent_database_migration_observation';
    applicationSourceSha256: string;
    migrationFiles: Array<{ path: string; sha256: string }>;
    derivedVersion: string;
  };
  rawReferenceRoot: 'artifacts/runs';
  taskStateSha256: string;
  rawReferences: EvidenceRef[];
};

export type TaskCaseEvidenceFile = {
  path: string;
  sha256: string;
  content: string;
};

export type RankedTaskCaseCandidateAssembly = {
  schemaVersion: 'bts-ranked-task-case-candidate-assembly/v1';
  classification: 'local_ranked_task_case_candidates_unactivated';
  status: 'candidates_only' | 'blocked';
  profile: {
    profileId: string;
    policyPath: string;
    policySha256: string;
    inputIndexPath: string;
    inputIndexSha256: string;
    difficultyApproval: false;
    releaseActivation: false;
  } | null;
  inventory: TaskReferenceInventoryResult | null;
  executionIdentity: JsonRecord | null;
  executionIdentityHash: string | null;
  applicationSchemaLineage: TaskCaseEvidenceEnvelope['applicationSchemaLineage'] | null;
  cases: TaskCase[];
  evidenceFiles: TaskCaseEvidenceFile[];
  taskResults: Array<{ taskId: TaskId; status: 'assembled' | 'blocked'; caseHash?: string; blockers: string[] }>;
  blockers: string[];
  claims: {
    taskAcceptance: false;
    taskGrade: false;
    validatedRelease: false;
    difficultyApproval: false;
    releaseActivation: false;
  };
};

export type TrainingTaskCaseCandidateAssembly = {
  schemaVersion: 'bts-training-task-case-candidate-assembly/v1';
  classification: 'local_training_task_case_candidates_unactivated';
  status: 'candidates_only' | 'blocked';
  profile: {
    profileId: string;
    policyPath: string;
    policySha256: string;
    inputIndexPath: string;
    inputIndexSha256: string;
    difficultyApproval: false;
    releaseActivation: false;
  } | null;
  inventory: TaskReferenceInventoryResult | null;
  executionIdentity: JsonRecord | null;
  executionIdentityHash: string | null;
  applicationSchemaLineage: TaskCaseEvidenceEnvelope['applicationSchemaLineage'] | null;
  cases: TaskCase[];
  evidenceFiles: TaskCaseEvidenceFile[];
  taskResults: Array<{ taskId: TrainingTaskId; status: 'assembled' | 'blocked'; caseHash?: string; blockers: string[] }>;
  blockers: string[];
  claims: {
    taskAcceptance: false;
    taskGrade: false;
    validatedRelease: false;
    difficultyApproval: false;
    releaseActivation: false;
  };
};

export type AssembleRankedTaskCaseOptions = {
  /** Absolute repository root. Capture and policy paths are resolved beneath it. */
  repositoryRoot: string;
  /** Relative path beneath repositoryRoot to the already-pinned four-capture index. */
  sourceIndexPath?: string;
  /** Relative path beneath repositoryRoot to the versioned local numeric policy. */
  localPolicyPath?: string;
  /** Safe relative output prefix under artifacts/runs, selected by the caller before assembly. */
  evidencePathPrefix: string;
};

export type AssembleTrainingTaskCaseOptions = {
  /** Absolute repository root. Capture and policy paths are resolved beneath it. */
  repositoryRoot: string;
  /** Relative path beneath repositoryRoot to the pinned five-capture index including training. */
  sourceIndexPath?: string;
  /** Relative path beneath repositoryRoot to the versioned local numeric policy. */
  localPolicyPath?: string;
  /** Safe relative output prefix under artifacts/runs, selected by the caller before assembly. */
  evidencePathPrefix: string;
};

const TASK_WEIGHT: Record<TaskId, 1 | 2 | 3 | 5> = {
  S1: 1, S2: 1, S3: 1, S4: 1, M1: 2, M2: 2, M3: 2, M4: 2, H1: 3, H2: 3, H3: 3, U1: 5,
};

// AICODE-NOTE: This copy is required because task-release.ts keeps its rubric
// rule table private. TaskCaseSchema and the full release validator remain the
// authority; keep this list synchronized if that rubric contract changes.
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

function record(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label}: expected_object`);
  return value as JsonRecord;
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label}: expected_nonempty_string`);
  return value;
}

function optionalString(value: unknown, fallback: string, label: string): string {
  return value === undefined || value === null ? fallback : string(value, label);
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label}: expected_array`);
  return value;
}

function objectAt(parent: JsonRecord, key: string): JsonRecord {
  return record(parent[key], key);
}

function arrayAt(parent: JsonRecord, key: string): unknown[] {
  return array(parent[key], key);
}

function stringAt(parent: JsonRecord, key: string): string {
  return string(parent[key], key);
}

function hashBytes(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalBytes(value: unknown): string {
  return canonicalTaskJson(value);
}

function hexToDecimal(value: unknown, label: string): string {
  const raw = string(value, label);
  if (!/^0x(?:0|[1-9a-f][0-9a-f]*)$/i.test(raw)) throw new Error(`${label}: invalid_hex_quantity`);
  return BigInt(raw).toString();
}

function stripHexPrefix(value: unknown, label: string): string {
  const raw = string(value, label);
  const normalized = raw.startsWith('0x') || raw.startsWith('0X') ? raw.slice(2) : raw;
  if (!/^[0-9a-f]{64}$/i.test(normalized)) throw new Error(`${label}: invalid_hash`);
  return normalized.toLowerCase();
}

function isContained(root: string, candidate: string): boolean {
  const remainder = relative(root, candidate);
  return remainder.length > 0 && remainder !== '..' && !remainder.startsWith(`..${sep}`) && !isAbsolute(remainder);
}

function compareStable(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function readContained(root: string, relativePath: string): Promise<Buffer> {
  if (!relativePath || relativePath.includes('\\') || relativePath.includes('\0') || isAbsolute(relativePath) ||
      relativePath.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error('assembler_artifact_path_invalid');
  }
  const candidate = resolve(root, ...relativePath.split('/'));
  const resolved = await realpath(candidate).catch(() => { throw new Error('assembler_artifact_missing'); });
  if (!isContained(root, resolved)) throw new Error('assembler_artifact_path_escape');
  const info = await lstat(resolved);
  if (!info.isFile()) throw new Error('assembler_artifact_not_file');
  return readFile(resolved);
}

async function readContainedJson(root: string, relativePath: string, label: string): Promise<{ value: JsonRecord; bytes: Buffer }> {
  const bytes = await readContained(root, relativePath);
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error(`${label}: invalid_json`); }
  return { value: record(parsed, label), bytes };
}

function safeEvidencePrefix(value: string): string {
  const normalized = value.replace(/\\/g, '/').replace(/\/$/, '');
  if (!normalized.startsWith('artifacts/runs/bts-task-case-candidates/') || normalized.length > 420 ||
      normalized.split('/').some((part) => !part || part === '.' || part === '..' || !/^[A-Za-z0-9._-]+$/.test(part))) {
    throw new Error('evidence_path_prefix_invalid');
  }
  return normalized;
}

function emptyResult(blockers: string[], inventory: TaskReferenceInventoryResult | null = null): RankedTaskCaseCandidateAssembly {
  return {
    schemaVersion: 'bts-ranked-task-case-candidate-assembly/v1',
    classification: 'local_ranked_task_case_candidates_unactivated',
    status: 'blocked', profile: null, inventory, executionIdentity: null, executionIdentityHash: null,
    applicationSchemaLineage: null, cases: [], evidenceFiles: [], taskResults: [], blockers,
    claims: { taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false },
  };
}

type LoadedContext = {
  repositoryRoot: string;
  runsRoot: string;
  sourceIndexPath: string;
  sourceIndexHash: string;
  policyPath: string;
  policyHash: string;
  policy: LocalPolicy;
  sources: TaskReferenceCaptureSource[];
  inventory: TaskReferenceInventoryResult;
  probes: Map<string, JsonRecord>;
  manifests: Map<string, JsonRecord>;
  unifiedCaseIndex: JsonRecord;
  manifest: JsonRecord;
  appLineage: TaskCaseEvidenceEnvelope['applicationSchemaLineage'];
  executionIdentity: JsonRecord;
  executionIdentityHash: string;
  evidencePrefix: string;
};

function loadSources(value: unknown, includeTrainingReference = false): TaskReferenceCaptureSource[] {
  if (!Array.isArray(value)) throw new Error('source_index_not_array');
  const sources = value.map((item) => CaptureSourceSchema.parse(item)) as TaskReferenceCaptureSource[];
  const kinds = sources.map((item) => item.kind);
  const requiredKinds: TaskReferenceCaptureSource['kind'][] = ['unified_reference', 'native_reference', 'h3_reference', 'u1_reference',
    ...(includeTrainingReference ? ['training_reference' as const] : [])];
  if (sources.length !== requiredKinds.length || new Set(kinds).size !== requiredKinds.length ||
      !requiredKinds.every((kind) => kinds.includes(kind))) {
    throw new Error(includeTrainingReference ? 'source_index_must_pin_all_five_capture_kinds' : 'source_index_must_pin_all_four_capture_kinds');
  }
  return sources;
}

export async function schemaLineage(repositoryRoot: string, applicationSourceSha256: string): Promise<TaskCaseEvidenceEnvelope['applicationSchemaLineage']> {
  const migrationFiles: Array<{ path: string; sha256: string }> = [];
  const migrationNames = (await readdir(resolve(repositoryRoot, 'infrastructure/benchmark-environment/migrations')))
    .filter((name) => /^[0-9]{3}_[a-z0-9_]+\.sql$/.test(name)).sort(compareStable);
  if (!migrationNames.length || migrationNames.length > 128 || migrationNames.some((name, index) =>
    name.slice(0, 3) !== String(index + 1).padStart(3, '0'))) throw new Error('application_migration_inventory_invalid');
  for (const name of migrationNames) {
    const path = `infrastructure/benchmark-environment/migrations/${name}`;
    const bytes = await readContained(repositoryRoot, path);
    migrationFiles.push({ path, sha256: hashBytes(bytes) });
  }
  const lineageDigest = sha256CanonicalTaskJson({ applicationSourceSha256, migrationFiles });
  return {
    classification: 'checked_in_migrations_plus_pinned_application_source_not_independent_database_migration_observation',
    applicationSourceSha256,
    migrationFiles,
    derivedVersion: `bef-db-migrations-001-${String(migrationNames.length).padStart(3, '0')}-${lineageDigest.slice(0, 16)}`,
  };
}

export function executionIdentityFromManifest(manifest: JsonRecord, manifestSha256: string, applicationSourceSha256: string,
  profileId: string, appSchemaVersion: string): JsonRecord {
  const source = objectAt(manifest, 'source');
  const local = objectAt(manifest, 'local');
  const runtimeContracts = objectAt(manifest, 'contracts');
  const chainId = Number(source.chainId);
  const localChainId = Number(local.chainId);
  if (!Number.isSafeInteger(chainId) || !Number.isSafeInteger(localChainId) || chainId !== localChainId) throw new Error('execution_identity_chain_mismatch');
  const blockNumber = hexToDecimal(source.blockNumber, 'source.blockNumber');
  const forkBlockNumber = hexToDecimal(local.forkBlock, 'local.forkBlock');
  if (blockNumber !== forkBlockNumber) throw new Error('execution_identity_block_mismatch');
  const sourceBlockHash = stripHexPrefix(source.blockHash, 'source.blockHash');
  const getContract = (id: string, codeKey = 'codeHash') => {
    const entry = objectAt(runtimeContracts, id);
    const codeHash = stripHexPrefix(entry[codeKey], `contracts.${id}.${codeKey}`);
    return {
      contractId: id,
      address: stringAt(entry, 'address'),
      codeHash,
      chainId,
      blockNumber,
      blockHash: sourceBlockHash,
    };
  };
  const usdc = objectAt(runtimeContracts, 'usdc');
  const weth = objectAt(runtimeContracts, 'weth');
  const tools = objectAt(manifest, 'tools');
  return {
    profileId,
    environmentManifestSha256: manifestSha256,
    toolSurfaceSha256: sha256CanonicalTaskJson(tools),
    x402ServiceSha256: applicationSourceSha256,
    applicationSchemaVersion: appSchemaVersion,
    sourceNetwork: stringAt(source, 'caip2'),
    sourceChainId: chainId,
    sourceBlockNumber: blockNumber,
    sourceBlockHash,
    localNetwork: `eip155:${localChainId}`,
    localChainId,
    localForkBlockNumber: forkBlockNumber,
    assets: [
      { assetId: 'ETH', kind: 'native', chainId, address: null, codeHash: null, decimals: 18 },
      { assetId: 'WETH', kind: 'erc20', chainId, address: stringAt(weth, 'address'),
        codeHash: stripHexPrefix(weth.codeHash, 'contracts.weth.codeHash'), decimals: Number(weth.decimals) },
      { assetId: 'USDC', kind: 'erc20', chainId, address: stringAt(usdc, 'address'),
        codeHash: stripHexPrefix(usdc.proxyCodeHash, 'contracts.usdc.proxyCodeHash'), decimals: Number(usdc.decimals) },
    ],
    contracts: [
      getContract('usdc', 'proxyCodeHash'), getContract('weth'), getContract('factory'), getContract('swapRouter02'),
      getContract('quoterV2'), getContract('pool'), getContract('pool3000'),
    ],
  };
}

async function loadContext(options: AssembleRankedTaskCaseOptions | AssembleTrainingTaskCaseOptions, includeTrainingReference = false): Promise<LoadedContext> {
  if (!isAbsolute(options.repositoryRoot)) throw new Error('repository_root_must_be_absolute');
  const repositoryRoot = await realpath(resolve(options.repositoryRoot));
  const runsRootCandidate = resolve(repositoryRoot, 'artifacts/runs');
  const runsRoot = await realpath(runsRootCandidate);
  if (!isContained(repositoryRoot, runsRoot)) throw new Error('runs_root_outside_repository');
  const evidencePrefix = safeEvidencePrefix(options.evidencePathPrefix);
  const sourceIndexRelative = options.sourceIndexPath ?? (includeTrainingReference ? DEFAULT_TRAINING_INPUT_INDEX : DEFAULT_INPUT_INDEX);
  const policyRelative = options.localPolicyPath ?? DEFAULT_LOCAL_POLICY;
  const sourceIndexPath = resolve(repositoryRoot, sourceIndexRelative);
  const policyPath = resolve(repositoryRoot, policyRelative);
  if (!isContained(repositoryRoot, sourceIndexPath) || !isContained(repositoryRoot, policyPath)) throw new Error('input_path_outside_repository');
  const sourceIndexBytes = await readContained(repositoryRoot, sourceIndexRelative.replace(/\\/g, '/'));
  let sourceIndexValue: unknown;
  try { sourceIndexValue = JSON.parse(sourceIndexBytes.toString('utf8')); }
  catch { throw new Error('source_index_invalid_json'); }
  const policyFile = await readContainedJson(repositoryRoot, policyRelative.replace(/\\/g, '/'), 'local_policy');
  const sources = loadSources(sourceIndexValue, includeTrainingReference);
  const policy = LocalPolicySchema.parse(policyFile.value);
  const inventory = await verifyTaskCaptureInventory({ runsRoot, captures: sources });
  if (inventory.status !== 'verified' || inventory.blockers.length !== 0 ||
      inventory.taskCoverage.length !== TASK_ORDER.length || inventory.taskCoverage.some((item) => item.status !== 'observed_primitive')) {
    throw Object.assign(new Error('capture_inventory_not_fully_verified'), { inventory });
  }
  if (!inventory.pins) throw Object.assign(new Error('capture_inventory_pins_missing'), { inventory });
  const probes = new Map<string, JsonRecord>();
  const manifests = new Map<string, JsonRecord>();
  for (const source of sources) {
    const captureRoot = resolve(runsRoot, source.relativeDirectory);
    const capturePin = inventory.captures.find((item) => item.kind === source.kind);
    if (!capturePin || capturePin.status !== 'verified_primitives' || !capturePin.probeSha256) {
      throw Object.assign(new Error(`${source.kind}.probe_not_verified`), { inventory });
    }
    const probeFile = await readContainedJson(captureRoot, 'probe.json', `${source.kind}.probe`);
    if (hashBytes(probeFile.bytes) !== source.expectedProbeSha256.toLowerCase()) throw Object.assign(new Error(`${source.kind}.probe_hash_mismatch`), { inventory });
    if (hashBytes(probeFile.bytes) !== capturePin.probeSha256) throw Object.assign(new Error(`${source.kind}.probe_inventory_hash_mismatch`), { inventory });
    const manifestRef = inventory.captures.find((item) => item.kind === source.kind)?.rawArtifacts.find((item) => item.path === 'manifest.json');
    if (!manifestRef || manifestRef.status !== 'verified') throw Object.assign(new Error(`${source.kind}.manifest_not_verified`), { inventory });
    const manifestFile = await readContainedJson(captureRoot, 'manifest.json', `${source.kind}.manifest`);
    if (hashBytes(manifestFile.bytes) !== manifestRef.sha256) throw Object.assign(new Error(`${source.kind}.manifest_hash_mismatch`), { inventory });
    probes.set(source.kind, probeFile.value);
    manifests.set(source.kind, manifestFile.value);
  }
  const manifest = manifests.get('unified_reference');
  const unifiedProbe = probes.get('unified_reference');
  if (!manifest || !unifiedProbe) throw Object.assign(new Error('unified_reference_profile_missing'), { inventory });
  const unifiedSource = sources.find((source) => source.kind === 'unified_reference');
  const caseIndexArtifact = inventory.captures.find((item) => item.kind === 'unified_reference')?.rawArtifacts
    .find((item) => item.path === 'task-reference/case-index.json');
  if (!unifiedSource || !caseIndexArtifact || caseIndexArtifact.status !== 'verified') {
    throw Object.assign(new Error('unified_reference_case_index_not_verified'), { inventory });
  }
  const caseIndexBytes = await readContained(resolve(runsRoot, unifiedSource.relativeDirectory), 'task-reference/case-index.json');
  if (hashBytes(caseIndexBytes) !== caseIndexArtifact.sha256) throw Object.assign(new Error('unified_reference_case_index_hash_mismatch'), { inventory });
  let caseIndexParsed: unknown;
  try { caseIndexParsed = JSON.parse(caseIndexBytes.toString('utf8')); }
  catch { throw Object.assign(new Error('unified_reference_case_index_invalid_json'), { inventory }); }
  const caseIndex = record(caseIndexParsed, 'unified_reference_case_index');
  for (const source of sources) {
    const candidateManifest = manifests.get(source.kind);
    const candidateProbe = probes.get(source.kind);
    if (!candidateManifest || !candidateProbe ||
        hashBytes(Buffer.from(canonicalTaskJson(candidateManifest))) !== hashBytes(Buffer.from(canonicalTaskJson(manifest))) ||
        candidateProbe.applicationSourceSha256 !== unifiedProbe.applicationSourceSha256) {
      throw Object.assign(new Error('cross_capture_manifest_or_application_mismatch'), { inventory });
    }
  }
  const appLineage = await schemaLineage(repositoryRoot, inventory.pins.applicationSourceSha256);
  const executionIdentity = executionIdentityFromManifest(
    manifest,
    inventory.pins.manifestSha256,
    inventory.pins.applicationSourceSha256,
    policy.profileId,
    appLineage.derivedVersion,
  );
  const executionIdentityHash = sha256CanonicalTaskJson(executionIdentity);
  return {
    repositoryRoot, runsRoot, sourceIndexPath, sourceIndexHash: hashBytes(sourceIndexBytes),
    policyPath, policyHash: hashBytes(policyFile.bytes), policy, sources, inventory, probes, manifests, manifest,
    unifiedCaseIndex: caseIndex, appLineage, executionIdentity, executionIdentityHash, evidencePrefix,
  };
}

function sourceFor(context: LoadedContext, kind: TaskReferenceCaptureSource['kind']): TaskReferenceCaptureSource {
  const source = context.sources.find((item) => item.kind === kind);
  if (!source) throw new Error(`capture_source_missing:${kind}`);
  return source;
}

function routerAddress(context: LoadedContext): string {
  return stringAt(objectAt(objectAt(context.manifest, 'contracts'), 'swapRouter02'), 'address');
}

function verifiedProfileArtifact(context: LoadedContext, kind: TaskReferenceCaptureSource['kind'], path: string): VerifiedRawArtifact {
  const capture = context.inventory.captures.find((item) => item.kind === kind);
  const artifact = capture?.rawArtifacts.find((item) => item.scope === 'capture' && item.path === path);
  if (!capture || capture.status !== 'verified_primitives' || !artifact || artifact.status !== 'verified') {
    throw new Error(`verified_artifact_missing:${kind}:${path}`);
  }
  return artifact;
}

async function readProfileArtifact(context: LoadedContext, kind: TaskReferenceCaptureSource['kind'], path: string): Promise<JsonRecord> {
  const source = sourceFor(context, kind);
  const artifact = verifiedProfileArtifact(context, kind, path);
  const captureRoot = resolve(context.runsRoot, source.relativeDirectory);
  if (path.includes('\\') || path.includes('\0') || isAbsolute(path) || path.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`artifact_path_invalid:${path}`);
  }
  const bytes = await readContained(captureRoot, path);
  if (hashBytes(bytes) !== artifact.sha256) throw new Error(`artifact_hash_changed:${path}`);
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error(`artifact_invalid_json:${path}`); }
  return record(parsed, path);
}

function rawRefsFromProfile(context: LoadedContext, kind: TaskReferenceCaptureSource['kind'], paths: readonly string[]): EvidenceRef[] {
  const source = sourceFor(context, kind);
  const refs = paths.map((path) => {
    const capture = context.inventory.captures.find((item) => item.kind === kind);
    const candidates = capture?.rawArtifacts.filter((item) => item.path === path && item.status === 'verified') ?? [];
    if (candidates.length !== 1) throw new Error(`verified_artifact_ambiguous:${kind}:${path}`);
    const artifact = candidates[0]!;
    return EVIDENCE_KIND.parse({
      path: artifact.scope === 'capture' ? `${source.relativeDirectory}/${artifact.path}` : artifact.path,
      sha256: artifact.sha256.toLowerCase(),
      boundary: artifact.boundary,
      contentType: artifact.contentType,
    }) as EvidenceRef;
  });
  const seen = new Map<string, EvidenceRef>();
  for (const ref of refs) {
    const old = seen.get(ref.path);
    if (old && (old.sha256 !== ref.sha256 || old.boundary !== ref.boundary)) throw new Error(`evidence_reference_conflict:${ref.path}`);
    seen.set(ref.path, ref);
  }
  return [...seen.values()].sort((a, b) => compareStable(a.path, b.path));
}

async function rehashRawReferences(context: LoadedContext, kind: TaskReferenceCaptureSource['kind'], refs: EvidenceRef[]): Promise<EvidenceRef[]> {
  const source = sourceFor(context, kind);
  const prefix = `${source.relativeDirectory}/`;
  const capture = context.inventory.captures.find((item) => item.kind === kind);
  for (const ref of refs) {
    const artifact = ref.path.startsWith(prefix)
      ? verifiedProfileArtifact(context, kind, ref.path.slice(prefix.length))
      : capture?.rawArtifacts.find((item) => item.scope === 'runs_root' && item.path === ref.path && item.status === 'verified');
    if (!artifact) throw new Error(`evidence_reference_capture_mismatch:${ref.path}`);
    if (artifact.sha256 !== ref.sha256) throw new Error(`evidence_reference_pin_mismatch:${ref.path}`);
    const bytes = await readContained(context.runsRoot, ref.path);
    if (hashBytes(bytes) !== ref.sha256) throw new Error(`evidence_reference_hash_changed:${ref.path}`);
  }
  return refs;
}

function allProfilePaths(context: LoadedContext, kind: TaskReferenceCaptureSource['kind']): string[] {
  const capture = context.inventory.captures.find((item) => item.kind === kind);
  return (capture?.rawArtifacts ?? []).filter((artifact) => artifact.status === 'verified').map((artifact) => artifact.path);
}

function unifiedTaskPaths(context: LoadedContext, taskId: TaskId, capturePath: string): string[] {
  const indexData = objectAt(context.unifiedCaseIndex, 'index');
  const cases = arrayAt(indexData, 'cases').map((item) => record(item, 'case-index-case'));
  const candidate = cases.find((item) => item.taskId === taskId);
  if (!candidate) throw new Error(`case_index_task_missing:${taskId}`);
  const evidence = arrayAt(candidate, 'evidence').map((item) => record(item, 'case-index-evidence'));
  const paths = evidence.map((item) => stringAt(item, 'path'));
  paths.push(capturePath);
  paths.push('manifest.json');
  return [...new Set(paths)];
}

async function rawReferencesForTask(context: LoadedContext, taskId: TaskId, taskCapturePath: string): Promise<EvidenceRef[]> {
  if (['S1', 'S2', 'S3', 'M1', 'M2', 'H1', 'H2'].includes(taskId)) {
    const refs = rawRefsFromProfile(context, 'unified_reference', unifiedTaskPaths(context, taskId, taskCapturePath));
    return rehashRawReferences(context, 'unified_reference', refs);
  }
  const kind = ['S4', 'M3', 'M4'].includes(taskId) ? 'native_reference' : taskId === 'H3' ? 'h3_reference' : 'u1_reference';
  if (['S4', 'M3', 'M4'].includes(taskId)) {
    const captureProfile = await readProfileArtifact(context, kind, taskCapturePath);
    const sourceArtifacts = arrayAt(captureProfile, 'sourceArtifacts').map((item) => record(item, 'native-source-artifact'));
    const paths = sourceArtifacts.map((item) => stringAt(item, 'path'));
    paths.push(taskCapturePath, 'manifest.json');
    return rehashRawReferences(context, kind, rawRefsFromProfile(context, kind, [...new Set(paths)]));
  }
  return rehashRawReferences(context, kind, rawRefsFromProfile(context, kind, allProfilePaths(context, kind)));
}

function baselineEvidencePaths(taskId: TaskId, tracePaths: readonly string[], taskCapturePath: string): string[] {
  if (taskId === 'H3') {
    return tracePaths.filter((path) => path === 'manifest.json' || path.includes('task-h3-start-one-generation') ||
      path.includes('task-h3-market-brief-payment-baseline') || path.includes('payer-usdc-before') || path.includes('payer-native-before') ||
      path === taskCapturePath);
  }
  return [...tracePaths];
}

function stateProjection(balances: StateProjection['balances'], allowances: StateProjection['allowances'] = [],
  deliveredComponentIds: string[] = [], fulfilledObligationIds: string[] = []): StateProjection {
  const balanceKey = (item: StateProjection['balances'][number]) => `${item.account.toLowerCase()}|${item.assetId}`;
  const allowanceKey = (item: StateProjection['allowances'][number]) => `${item.owner.toLowerCase()}|${item.tokenAssetId}|${item.spender.toLowerCase()}`;
  const assertUnique = (values: readonly string[], label: string) => {
    if (new Set(values).size !== values.length) throw new Error(`${label}_duplicate_identity`);
  };
  assertUnique(balances.map(balanceKey), 'state_balance');
  assertUnique(allowances.map(allowanceKey), 'state_allowance');
  assertUnique(deliveredComponentIds, 'state_delivered_component');
  assertUnique(fulfilledObligationIds, 'state_fulfilled_obligation');
  const uniqueBalances = [...balances].sort((a, b) => compareStable(balanceKey(a), balanceKey(b)));
  const uniqueAllowances = [...allowances].sort((a, b) => compareStable(allowanceKey(a), allowanceKey(b)));
  return {
    balances: uniqueBalances,
    allowances: uniqueAllowances,
    deliveredComponentIds: [...deliveredComponentIds].sort(),
    fulfilledObligationIds: [...fulfilledObligationIds].sort(),
  };
}

function hashedInitialState(projection: StateProjection): JsonRecord {
  return { stateSha256: sha256CanonicalTaskJson(projection), ...projection };
}

function balance(account: 'participant' | string, assetId: string, amountUnits: unknown, label: string) {
  return { account, assetId, amountUnits: string(amountUnits, label) };
}

function allowance(owner: 'participant' | string, tokenAssetId: string, spender: unknown, amountUnits: unknown, label: string) {
  return { owner, tokenAssetId, spender: string(spender, `${label}.spender`), amountUnits: string(amountUnits, `${label}.amountUnits`) };
}

function readOnlyState(snapshot: JsonRecord, nativeKey: string, usdcKey: string, wethKey: string,
  usdcAllowanceKey: string, wethAllowanceKey: string, router: string): StateProjection {
  return stateProjection([
    balance('participant', 'ETH', snapshot[nativeKey], `state.${nativeKey}`),
    balance('participant', 'USDC', snapshot[usdcKey], `state.${usdcKey}`),
    balance('participant', 'WETH', snapshot[wethKey], `state.${wethKey}`),
  ], [
    allowance('participant', 'USDC', router, snapshot[usdcAllowanceKey], `state.${usdcAllowanceKey}`),
    allowance('participant', 'WETH', router, snapshot[wethAllowanceKey], `state.${wethAllowanceKey}`),
  ]);
}

function route(context: LoadedContext, routeId: 'fee500' | 'fee3000'): JsonRecord {
  const mapping = context.policy.routeContractIds[routeId];
  const runtimeContracts = objectAt(context.manifest, 'contracts');
  const poolName = routeId === 'fee500' ? 'pool' : 'pool3000';
  const pool = objectAt(runtimeContracts, poolName);
  const usdc = objectAt(runtimeContracts, 'usdc');
  const weth = objectAt(runtimeContracts, 'weth');
  const expectedPoolContractId = routeId === 'fee500' ? 'pool' : 'pool3000';
  if (mapping.routerContractId !== 'swapRouter02' || mapping.poolContractId !== expectedPoolContractId ||
      !context.executionIdentity.contracts.some((contract: JsonRecord) => contract.contractId === mapping.routerContractId) ||
      !context.executionIdentity.contracts.some((contract: JsonRecord) => contract.contractId === mapping.poolContractId) ||
      Number(pool.fee) !== (routeId === 'fee500' ? 500 : 3000) ||
      ![stringAt(pool, 'token0').toLowerCase(), stringAt(pool, 'token1').toLowerCase()].includes(stringAt(usdc, 'address').toLowerCase()) ||
      ![stringAt(pool, 'token0').toLowerCase(), stringAt(pool, 'token1').toLowerCase()].includes(stringAt(weth, 'address').toLowerCase())) {
    throw new Error(`route_contract_mapping_invalid:${routeId}`);
  }
  return {
    routeId,
    routeType: 'uniswap_v3_exact_input_single',
    tokenInAssetId: 'USDC',
    tokenOutAssetId: 'WETH',
    routerContractId: mapping.routerContractId,
    poolContractId: mapping.poolContractId,
    feeTier: routeId === 'fee500' ? 500 : 3000,
  };
}

function ensureRouteMatches(context: LoadedContext, routeId: 'fee500' | 'fee3000', poolAddress: unknown, codeHash: unknown, feeTier: unknown): void {
  const poolName = routeId === 'fee500' ? 'pool' : 'pool3000';
  const pool = objectAt(objectAt(context.manifest, 'contracts'), poolName);
  if (string(poolAddress, `${routeId}.poolAddress`).toLowerCase() !== stringAt(pool, 'address').toLowerCase() ||
      stripHexPrefix(codeHash, `${routeId}.poolCodeHash`) !== stripHexPrefix(pool.codeHash, `${poolName}.codeHash`) ||
      Number(feeTier) !== (routeId === 'fee500' ? 500 : 3000)) throw new Error(`route_pin_mismatch:${routeId}`);
}

function requiredComponent(value: unknown, label: string): JsonRecord {
  const c = record(value, label);
  const component = c.dataComponent ? record(c.dataComponent, `${label}.dataComponent`) : c;
  return {
    componentId: stringAt(component, 'componentId'),
    resourceId: stringAt(component, 'resourceId'),
    validator: objectAt(component, 'validator'),
    sourceIds: arrayAt(component, 'sourceIds').map((sourceId) => string(sourceId, `${label}.sourceId`)),
  };
}

function rpcAmountFromContext(context: LoadedContext, fileName: string): Promise<string> {
  return readProfileArtifact(context, 'h3_reference', fileName).then((artifact) => {
    const result = stringAt(artifact, 'result');
    if (!/^0x[0-9a-f]+$/i.test(result)) throw new Error(`rpc_result_invalid:${fileName}`);
    return BigInt(result).toString();
  });
}

function makeReferenceFiles(context: LoadedContext, taskId: TaskId, caseId: string, rawRefs: EvidenceRef[],
  initialStateHash: string, finalStateHash: string, actionCount: number, paidSettlementObserved: boolean,
  baselineRefs: EvidenceRef[], mode: 'training' | 'ranked' = 'ranked'): { referenceFile: TaskCaseEvidenceFile; baselineFile: TaskCaseEvidenceFile } {
  const trainingCapture = mode === 'training' ? context.inventory.captures.find((item) => item.kind === 'training_reference') : undefined;
  if (mode === 'training' && (!trainingCapture?.pin || !trainingCapture.probeSha256)) throw new Error('training_reference_capture_pin_missing');
  const common = {
    classification: 'verified_local_reference_composition_not_task_acceptance' as const,
    taskId, caseId, boundary: COMPOSITE_BOUNDARY,
    ...(mode === 'training' ? { mode } : {}),
    ...(mode === 'training' ? { trainingCaptureInput: {
      kind: 'training_reference' as const,
      relativeDirectory: trainingCapture!.relativeDirectory,
      probeSha256: trainingCapture!.probeSha256!,
      manifestSha256: trainingCapture!.pin!.manifestSha256,
      applicationSourceSha256: trainingCapture!.pin!.applicationSourceSha256,
    } } : {}),
    paidSettlementObserved,
    policyInput: { path: relative(context.repositoryRoot, context.policyPath).replace(/\\/g, '/'), sha256: context.policyHash, profileId: context.policy.profileId },
    sourceIndexInput: { path: relative(context.repositoryRoot, context.sourceIndexPath).replace(/\\/g, '/'), sha256: context.sourceIndexHash },
    inventoryPins: context.inventory.pins!,
    applicationSchemaLineage: context.appLineage,
    rawReferenceRoot: 'artifacts/runs' as const,
  };
  const referenceEnvelope: TaskCaseEvidenceEnvelope = {
    schemaVersion: 'bts-task-case-evidence-composition/v1', ...common,
    purpose: 'reference_execution_trace', taskStateSha256: finalStateHash,
    rawReferences: rawRefs,
  };
  const baselineEnvelope: TaskCaseEvidenceEnvelope = {
    schemaVersion: 'bts-task-case-evidence-composition/v1', ...common,
    purpose: 'initial_state_baseline', taskStateSha256: initialStateHash,
    rawReferences: baselineRefs,
  };
  const referenceContent = canonicalBytes(referenceEnvelope);
  const baselineContent = canonicalBytes(baselineEnvelope);
  const referencePath = `${context.evidencePrefix}/${mode}/${taskId}/reference-evidence.json`;
  const baselinePath = `${context.evidencePrefix}/${mode}/${taskId}/initial-state-evidence.json`;
  return {
    referenceFile: { path: referencePath, content: referenceContent, sha256: hashBytes(Buffer.from(referenceContent)) },
    baselineFile: { path: baselinePath, content: baselineContent, sha256: hashBytes(Buffer.from(baselineContent)) },
  };
}

function referenceObject(file: TaskCaseEvidenceFile): JsonRecord {
  return { path: file.path, sha256: file.sha256, boundary: COMPOSITE_BOUNDARY };
}

function receiptGasWei(receipts: unknown[], label: string): string {
  return receipts.reduce<bigint>((sum, raw, index) => {
    const receipt = record(raw, `${label}[${index}]`);
    const role = stringAt(receipt, 'payerRole');
    const status = optionalString(receipt.receiptStatus, optionalString(receipt.status, '', `${label}.status`), `${label}.receiptStatus`);
    if (!['participant', 'participant_gas_payer'].includes(role)) return sum;
    if (status && !['success', '0x1', 'reverted', '0x0'].includes(status)) throw new Error(`${label}_receipt_status_unknown`);
    return sum + BigInt(stringAt(receipt, 'gasCostWei'));
  }, 0n).toString();
}

function calculateDexFeeUsdcUnits(exactInputUnits: string, feeTier: number): string {
  const numerator = BigInt(exactInputUnits) * BigInt(feeTier);
  return ((numerator + 999_999n) / 1_000_000n).toString();
}

export function calculateParticipantExpenseBudget(input: {
  serviceChargesUsdcUnits: string;
  participantGasWei: string;
  ethUsdcRateNumerator: string;
  ethUsdcRateDenominator: string;
  verifiedDexFeeUsdcUnits: string;
  headroomMultiplierNumerator: string;
  headroomMultiplierDenominator: string;
  roundUpToUsdcUnits: string;
}): { measuredExpenseUsdcUnits: string; budgetUsdcUnits: string; gasUsdcUnits: string } {
  const service = BigInt(input.serviceChargesUsdcUnits);
  const gasWei = BigInt(input.participantGasWei);
  const rateNum = BigInt(input.ethUsdcRateNumerator);
  const rateDen = BigInt(input.ethUsdcRateDenominator);
  const dex = BigInt(input.verifiedDexFeeUsdcUnits);
  const headroomNum = BigInt(input.headroomMultiplierNumerator);
  const headroomDen = BigInt(input.headroomMultiplierDenominator);
  const quantum = BigInt(input.roundUpToUsdcUnits);
  if ([service, gasWei, rateNum, rateDen, dex, headroomNum, headroomDen, quantum].some((value) => value < 0n) ||
      rateDen === 0n || headroomDen === 0n || quantum === 0n) throw new Error('expense_budget_input_invalid');
  const gasUsdc = (gasWei * rateNum) / rateDen;
  const measured = service + gasUsdc + dex;
  const headroom = (measured * headroomNum + headroomDen - 1n) / headroomDen;
  const budget = ((headroom + quantum - 1n) / quantum) * quantum;
  return { measuredExpenseUsdcUnits: measured.toString(), gasUsdcUnits: gasUsdc.toString(), budgetUsdcUnits: budget.toString() };
}

function profileExpenseBudget(context: LoadedContext, serviceChargesUsdcUnits: string, participantGasWei: string,
  verifiedDexFeeUsdcUnits: string): string {
  const fee = objectAt(context.manifest, 'feePolicy');
  return calculateParticipantExpenseBudget({
    serviceChargesUsdcUnits,
    participantGasWei,
    ethUsdcRateNumerator: stringAt(fee, 'ethUsdcRateNumerator'),
    ethUsdcRateDenominator: stringAt(fee, 'ethUsdcRateDenominator'),
    verifiedDexFeeUsdcUnits,
    headroomMultiplierNumerator: context.policy.expenseBudget.headroomMultiplierNumerator,
    headroomMultiplierDenominator: context.policy.expenseBudget.headroomMultiplierDenominator,
    roundUpToUsdcUnits: context.policy.expenseBudget.roundUpToUsdcUnits,
  }).budgetUsdcUnits;
}

function taskCaseBase(context: LoadedContext, taskId: TaskId, initial: StateProjection, final: StateProjection,
  evidence: { referenceFile: TaskCaseEvidenceFile; baselineFile: TaskCaseEvidenceFile }, actionCount: number,
  mode: 'training' | 'ranked' = 'ranked', caseId = `bts-${mode}-${taskId.toLowerCase()}-local-v1`): JsonRecord {
  return {
    caseId,
    mode,
    taskId,
    rubricVersion: 'bts-rubric/v1',
    rubricHash: taskRubricHash(taskId),
    taskWeight: TASK_WEIGHT[taskId],
    mandatoryRules: [...MANDATORY_RULES[taskId]],
    executionIdentityHash: context.executionIdentityHash,
    taskDeadlineSeconds: context.policy.taskDeadlineSeconds,
    initialState: hashedInitialState(initial),
    initialStateEvidence: referenceObject(evidence.baselineFile),
    referencePath: {
      evidence: referenceObject(evidence.referenceFile),
      actionCount,
      initialStateSha256: sha256CanonicalTaskJson(initial),
      finalStateSha256: sha256CanonicalTaskJson(final),
      toolSurfaceSha256: context.executionIdentity.toolSurfaceSha256,
    },
  };
}

type TaskBuild = { taskCase: TaskCase; evidenceFiles: TaskCaseEvidenceFile[] };

function unifiedCase(context: LoadedContext, taskId: TaskId): JsonRecord {
  const index = objectAt(context.unifiedCaseIndex, 'index');
  const cases = arrayAt(index, 'cases').map((item) => record(item, 'case-index-case'));
  const found = cases.find((item) => item.taskId === taskId);
  if (!found) throw new Error(`unified_case_missing:${taskId}`);
  return found;
}

function canonicalAssetId(context: LoadedContext, value: unknown, label: string): string {
  const raw = string(value, label);
  const chainId = Number(context.executionIdentity.localChainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('execution_identity_local_chain_invalid');
  const assets = arrayAt(context.executionIdentity, 'assets').map((item) => record(item, `${label}.pinnedAsset`));
  const matches = assets.filter((asset) => {
    if (Number(asset.chainId) !== chainId) return false;
    const assetId = stringAt(asset, 'assetId');
    const address = asset.address;
    return assetId.toLowerCase() === raw.toLowerCase() ||
      typeof address === 'string' && address.toLowerCase() === raw.toLowerCase();
  });
  if (matches.length !== 1) throw new Error(`asset_identity_unresolved:${label}`);
  return stringAt(matches[0]!, 'assetId');
}

function canonicalPaymentRequirements(context: LoadedContext, value: unknown, label: string): JsonRecord {
  const requirements = record(value, label);
  return { ...requirements, assetId: canonicalAssetId(context, requirements.assetId, `${label}.assetId`) };
}

function canonicalCatalogPredicate(context: LoadedContext, value: unknown, label: string): JsonRecord {
  const predicate = record(value, label);
  return { ...predicate, assetId: canonicalAssetId(context, predicate.assetId, `${label}.assetId`) };
}

function cloneOfferCatalog(context: LoadedContext, value: unknown, label: string): JsonRecord[] {
  return array(value, label).map((item, index) => {
    const offer = record(item, `${label}[${index}]`);
    return {
      offerId: stringAt(offer, 'offerId'), resourceId: stringAt(offer, 'resourceId'), dataType: stringAt(offer, 'dataType'),
      advertisedTotalPriceUsdcUnits: stringAt(offer, 'advertisedTotalPriceUsdcUnits'), network: stringAt(offer, 'network'),
      assetId: canonicalAssetId(context, offer.assetId, `${label}[${index}].assetId`), recipient: stringAt(offer, 'recipient'),
      paymentRequirements: canonicalPaymentRequirements(context, offer.paymentRequirements, `${label}[${index}].paymentRequirements`),
      deliveryValidator: objectAt(offer, 'deliveryValidator'),
    };
  });
}

function commonPolicyEnvelope(context: LoadedContext, taskId: TaskId): JsonRecord {
  return {
    profileId: context.policy.profileId,
    taskDeadlineSeconds: context.policy.taskDeadlineSeconds,
    rankedRunTimeoutSeconds: context.policy.rankedRunTimeoutSeconds,
    expenseBudgetPolicy: context.policy.expenseBudget,
    nativeReserveWei: (context.policy.nativeReserveWei as Partial<Record<TaskId, string>>)[taskId] ?? null,
    permittedProvenanceIds: context.policy.permittedProvenanceIds,
    duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    routeContractIds: context.policy.routeContractIds,
    difficultyApproval: false,
    releaseActivation: false,
  };
}

async function buildTask(context: LoadedContext, taskId: TaskId): Promise<TaskBuild> {
  let taskCapturePath = '';
  let kind: TaskReferenceCaptureSource['kind'] = 'unified_reference';
  let capture: JsonRecord;
  let objective: JsonRecord;
  let initial: StateProjection;
  let final: StateProjection;
  let actionCount: number;
  let paidSettlementObserved = false;

  if (taskId === 'S1') {
    taskCapturePath = 'task-reference/captures/s1-transfer.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath);
    capture = objectAt(wrapper, 'capture');
    const before = objectAt(capture, 'before'); const after = objectAt(capture, 'after');
    const r = routerAddress(context);
    initial = stateProjection([
      balance('participant', 'ETH', before.payerNativeWei, 'S1.before.payerNativeWei'),
      balance('participant', 'USDC', before.payerUsdcUnits, 'S1.before.payerUsdcUnits'),
      balance('participant', 'WETH', before.payerWethUnits, 'S1.before.payerWethUnits'),
      balance(stringAt(before, 'recipientAddress'), 'USDC', before.recipientUsdcUnits, 'S1.before.recipientUsdcUnits'),
      balance(stringAt(before, 'recipientAddress'), 'WETH', before.recipientWethUnits, 'S1.before.recipientWethUnits'),
    ], [
      allowance('participant', 'USDC', r, before.usdcRouterAllowanceUnits, 'S1.before.USDC allowance'),
      allowance('participant', 'WETH', r, before.wethRouterAllowanceUnits, 'S1.before.WETH allowance'),
    ]);
    final = stateProjection([
      balance('participant', 'ETH', after.payerNativeWei, 'S1.after.payerNativeWei'),
      balance('participant', 'USDC', after.payerUsdcUnits, 'S1.after.payerUsdcUnits'),
      balance('participant', 'WETH', after.payerWethUnits, 'S1.after.payerWethUnits'),
      balance(stringAt(after, 'recipientAddress'), 'USDC', after.recipientUsdcUnits, 'S1.after.recipientUsdcUnits'),
      balance(stringAt(after, 'recipientAddress'), 'WETH', after.recipientWethUnits, 'S1.after.recipientWethUnits'),
    ], [
      allowance('participant', 'USDC', r, after.usdcRouterAllowanceUnits, 'S1.after.USDC allowance'),
      allowance('participant', 'WETH', r, after.wethRouterAllowanceUnits, 'S1.after.WETH allowance'),
    ]);
    const action = objectAt(capture, 'action');
    const unrelated = {
      payerNativeWei: before.payerNativeWei, payerWethUnits: before.payerWethUnits,
      recipientWethUnits: before.recipientWethUnits, poolUsdcUnits: before.poolUsdcUnits, poolWethUnits: before.poolWethUnits,
      usdcRouterAllowanceUnits: before.usdcRouterAllowanceUnits, wethRouterAllowanceUnits: before.wethRouterAllowanceUnits,
    };
    objective = {
      tokenAssetId: 'USDC', sender: 'participant', recipient: stringAt(action, 'recipient'),
      exactPrincipalUnits: stringAt(action, 'amountUnits'),
      nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId),
      unrelatedEffectBaselineSha256: sha256CanonicalTaskJson(unrelated),
    };
    actionCount = 1;
  } else if (taskId === 'S2' || taskId === 'S3') {
    taskCapturePath = taskId === 'S2' ? 'task-reference/captures/s2-readonly-offer.json' : 'task-reference/captures/s3-readonly-catalog.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath);
    capture = objectAt(wrapper, 'capture');
    const noEffect = objectAt(capture, 'noEffectInterval');
    const router = routerAddress(context);
    initial = readOnlyState(objectAt(noEffect, 'stateBefore'), 'payerNativeEthWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcRouterAllowanceUnits', 'wethRouterAllowanceUnits', router);
    final = readOnlyState(objectAt(noEffect, 'stateAfter'), 'payerNativeEthWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcRouterAllowanceUnits', 'wethRouterAllowanceUnits', router);
    if (sha256CanonicalTaskJson(initial) !== sha256CanonicalTaskJson(final)) throw new Error(`${taskId}_observed_state_changed`);
    if (taskId === 'S2') {
      const candidate = objectAt(capture, 'objectiveCandidate');
      const reqs = objectAt(candidate, 'completePaymentRequirements');
      const requiredFields = arrayAt(candidate, 'requiredAnswerFields').map((field) => string(field, 'S2.requiredAnswerFields'));
      const deduplicated = [...new Set(requiredFields)];
      objective = {
        resourceId: stringAt(candidate, 'resourceId'), offerId: stringAt(candidate, 'offerId'),
        completePaymentRequirements: canonicalPaymentRequirements(context, reqs, 'S2.completePaymentRequirements'), requiredAnswerFields: deduplicated,
      };
    } else {
      const candidate = objectAt(capture, 'objectiveCandidate');
      objective = { catalog: cloneOfferCatalog(context, candidate.catalog, 'S3.catalog'),
        required: canonicalCatalogPredicate(context, candidate.required, 'S3.required') };
    }
    actionCount = 1;
  } else if (taskId === 'S4') {
    kind = 'native_reference'; taskCapturePath = 'task-native/captures/s4.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const candidate = objectAt(capture, 'objectiveCandidate');
    const start = objectAt(objectAt(capture, 'snapshots'), 'taskStartAfterSetup');
    const end = objectAt(objectAt(capture, 'snapshots'), 'finalAfterRevoke');
    const router = routerAddress(context);
    initial = readOnlyState(start, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    final = readOnlyState(end, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    objective = {
      tokenAssetId: stringAt(candidate, 'tokenAssetId'), owner: 'participant', spender: stringAt(candidate, 'spender'),
      initialAllowanceUnits: stringAt(candidate, 'taskStartAllowanceUnits'),
      unrelatedAllowanceBaselineSha256: sha256CanonicalTaskJson({ wethRouterAllowanceUnits: start.wethAllowanceUnits }),
    };
    actionCount = 1;
  } else if (taskId === 'M1') {
    taskCapturePath = 'task-reference/captures/m1-single-purchase.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const principal = objectAt(capture, 'observedPrincipal'); const native = objectAt(capture, 'participantNativeBalance');
    const component = objectAt(capture, 'component');
    initial = stateProjection([
      balance('participant', 'USDC', principal.payerBalanceBeforeUnits, 'M1.initial.USDC'),
      balance('participant', 'ETH', native.beforeWei, 'M1.initial.ETH'),
    ]);
    final = stateProjection([
      balance('participant', 'USDC', principal.payerBalanceAfterUnits, 'M1.final.USDC'),
      balance('participant', 'ETH', native.afterWei, 'M1.final.ETH'),
    ], [], [stringAt(component, 'componentId')]);
    const service = stringAt(objectAt(capture, 'payment'), 'amountUnits');
    const count = stringAt(objectAt(capture, 'purchaseCountFacts'), 'participantGasCostCount');
    if (count !== '0') throw new Error('M1_participant_gas_receipts_unavailable');
    objective = {
      component,
      paymentRequirements: canonicalPaymentRequirements(context, capture.paymentRequirements, 'M1.paymentRequirements'),
      expenseBudgetUsdcUnits: profileExpenseBudget(context, service, '0', '0'),
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    actionCount = 1; paidSettlementObserved = true;
  } else if (taskId === 'M2') {
    taskCapturePath = 'task-reference/captures/m2-minimum-purchase.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const payment = objectAt(capture, 'payment'); const expenses = objectAt(capture, 'expenseObservations');
    const nativeBefore = stringAt(expenses, 'participantNativeBalanceBeforeWei');
    const nativeAfter = stringAt(expenses, 'participantNativeBalanceAfterWei');
    const component = objectAt(objectAt(capture, 'delivery'), 'component');
    initial = stateProjection([
      balance('participant', 'USDC', payment.payerBalanceBeforeUnits, 'M2.initial.USDC'),
      balance('participant', 'ETH', nativeBefore, 'M2.initial.ETH'),
    ]);
    final = stateProjection([
      balance('participant', 'USDC', payment.payerBalanceAfterUnits, 'M2.final.USDC'),
      balance('participant', 'ETH', nativeAfter, 'M2.final.ETH'),
    ], [], [stringAt(component, 'componentId')]);
    const candidate = objectAt(capture, 'objectiveCandidate');
    const participantGasCount = stringAt(expenses, 'participantGasCostCount');
    const participantGas = participantGasCount === '0' ? '0' : stringAt(expenses, 'participantGasExpenseUsdcUnits');
    if (participantGasCount !== '0') throw new Error('M2_participant_gas_wei_missing');
    objective = {
      catalog: cloneOfferCatalog(context, candidate.catalog, 'M2.catalog'),
      required: canonicalCatalogPredicate(context, candidate.required, 'M2.required'),
      expenseBudgetUsdcUnits: profileExpenseBudget(context, stringAt(expenses, 'advertisedServiceChargeUsdcUnits'), participantGas, '0'),
      tiePolicy: 'all_minimum_advertised_total_prices_qualify',
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    actionCount = 1; paidSettlementObserved = true;
  } else if (taskId === 'M3' || taskId === 'M4') {
    kind = 'native_reference'; taskCapturePath = taskId === 'M3' ? 'task-native/captures/m3.json' : 'task-native/captures/m4.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const candidate = objectAt(capture, 'objectiveCandidate');
    const candidateRoute = objectAt(candidate, 'route');
    ensureRouteMatches(context, 'fee3000', candidateRoute.poolAddress, candidateRoute.poolCodeHash, candidateRoute.feeTier);
    const snapshots = objectAt(capture, 'snapshots'); const actions = objectAt(capture, 'actions');
    const before = objectAt(snapshots, 'before');
    const router = routerAddress(context);
    const end = objectAt(snapshots, taskId === 'M3' ? 'afterUnwrap' : 'afterCleanup');
    initial = readOnlyState(before, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    final = readOnlyState(end, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    const actionReceipts = Object.values(actions).map((item) => record(item, `${taskId}.action`));
    const participantGas = actionReceipts.reduce((sum, item) => sum + BigInt(stringAt(item, 'gasCostWei')), 0n).toString();
    const dexFee = calculateDexFeeUsdcUnits(stringAt(candidate, 'exactInputUnits'), 3000);
    const budget = profileExpenseBudget(context, '0', participantGas, dexFee);
    const permittedRoutes = [route(context, 'fee3000')];
    if (taskId === 'M3') {
      objective = {
        inputAssetId: stringAt(candidate, 'inputAssetId'), exactInputUnits: stringAt(candidate, 'exactInputUnits'),
        outputAssetId: 'ETH', minimumNativeOutputWei: stringAt(candidate, 'requiredNativeOutputMinimumWei'),
        permittedRoutes, maxSlippageBps: Number(candidate.maxSlippageBps),
        nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId), expenseBudgetUsdcUnits: budget,
      };
    } else {
      const allowanceCandidate = objectAt(candidate, 'requiredTemporaryAllowance');
      objective = {
        inputAssetId: stringAt(candidate, 'inputAssetId'), exactInputUnits: stringAt(candidate, 'exactInputUnits'),
        outputAssetId: stringAt(candidate, 'outputAssetId'), minimumOutputUnits: stringAt(candidate, 'minimumOutputUnits'),
        permittedRoutes,
        initialAllowanceScope: [allowance('participant', stringAt(allowanceCandidate, 'tokenAssetId'), allowanceCandidate.spender,
          allowanceCandidate.initialUnits, 'M4.initialAllowanceScope')],
        nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId), expenseBudgetUsdcUnits: budget,
      };
    }
    actionCount = actionReceipts.length;
  } else if (taskId === 'H1') {
    taskCapturePath = 'task-reference/captures/resource-catalog.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const candidate = objectAt(capture, 'h1ObjectiveCandidate');
    const purchases = arrayAt(capture, 'purchases').map((item) => record(item, 'H1.purchase'));
    if (purchases.length < 2) throw new Error('H1_required_component_purchases_missing');
    const first = purchases[0]!; const last = purchases[purchases.length - 1]!;
    const payerBefore = await readProfileArtifact(context, kind, 'rpc/0054-task-resource-catalog-0-payer-before.json');
    const payerFinal = await readProfileArtifact(context, kind, 'rpc/0062-task-resource-catalog-1-payer-after.json');
    const initialUsdc = BigInt(stringAt(payerBefore, 'result')).toString();
    const finalUsdc = BigInt(stringAt(payerFinal, 'result')).toString();
    initial = stateProjection([balance('participant', 'USDC', initialUsdc, 'H1.initial.USDC')]);
    const components = arrayAt(candidate, 'components').map((item) => requiredComponent(item, 'H1.component'));
    final = stateProjection([balance('participant', 'USDC', finalUsdc, 'H1.final.USDC')], [],
      components.map((item) => stringAt(item, 'componentId')));
    const expense = objectAt(candidate, 'observedExpense');
    objective = {
      requiredComponents: components,
      permittedSources: [...context.policy.permittedProvenanceIds],
      expenseBudgetUsdcUnits: profileExpenseBudget(context,
        stringAt(expense, 'serviceChargesUsdcUnits'), stringAt(expense, 'participantGasCostWei'), stringAt(expense, 'declaredDexExpenseUsdcUnits')),
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    actionCount = purchases.length; paidSettlementObserved = true;
    void first; void last;
  } else if (taskId === 'H2') {
    taskCapturePath = 'task-reference/captures/h2-exact-payouts.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath); capture = objectAt(wrapper, 'capture');
    const initialAssets = objectAt(capture, 'initialAssets'); const finalCutoff = objectAt(capture, 'finalCutoff');
    const obligations = arrayAt(capture, 'obligations').map((item) => record(item, 'H2.obligation'));
    const initialRecipients = record(initialAssets.recipientUsdcUnits, 'H2.initialRecipients');
    const finalRecipients = record(finalCutoff.recipientUsdcUnits, 'H2.finalRecipients');
    const obligationsWithCanonicalAssets = obligations.map((item) => ({
      ...item,
      canonicalAssetId: canonicalAssetId(context, item.assetId, 'H2.obligation.assetId'),
    }));
    const initialBalances = [
      balance('participant', 'USDC', initialAssets.payerUsdcUnits, 'H2.initial.USDC'),
      balance('participant', 'ETH', initialAssets.payerNativeWei, 'H2.initial.ETH'),
      ...obligationsWithCanonicalAssets.map((item) => balance(stringAt(item, 'recipient'), item.canonicalAssetId,
        initialRecipients[stringAt(item, 'recipient')], 'H2.initial.recipient')),
    ];
    const finalBalances = [
      balance('participant', 'USDC', finalCutoff.payerUsdcUnits, 'H2.final.USDC'),
      balance('participant', 'ETH', finalCutoff.payerNativeWei, 'H2.final.ETH'),
      ...obligationsWithCanonicalAssets.map((item) => balance(stringAt(item, 'recipient'), item.canonicalAssetId,
        finalRecipients[stringAt(item, 'recipient')], 'H2.final.recipient')),
    ];
    initial = stateProjection(initialBalances);
    const obligationIds = obligations.filter((item) => item.fulfilledAtCommonCutoff === true).map((item) => stringAt(item, 'obligationId'));
    final = stateProjection(finalBalances, [], [], obligationIds);
    const expense = objectAt(capture, 'observedExpense');
    objective = {
      obligations: obligationsWithCanonicalAssets.map((item) => ({ obligationId: stringAt(item, 'obligationId'), recipient: stringAt(item, 'recipient'),
        assetId: item.canonicalAssetId, exactAmountUnits: stringAt(item, 'amountUnits') })),
      initialAssetIds: ['USDC', 'ETH'], permittedConversions: [],
      nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId),
      expenseBudgetUsdcUnits: profileExpenseBudget(context, stringAt(expense, 'serviceChargesUsdcUnits'),
        stringAt(expense, 'participantGasCostWei'), stringAt(expense, 'declaredDexExpenseUsdcUnits')),
    };
    actionCount = obligations.length;
  } else if (taskId === 'H3') {
    kind = 'h3_reference'; taskCapturePath = 'task-h3/h3-paid-route-swap-foundation.json';
    const wrapper = await readProfileArtifact(context, kind, taskCapturePath);
    const paid = objectAt(wrapper, 'paidReference'); const trade = objectAt(wrapper, 'trade');
    const routeCandidate = objectAt(trade, 'snapshots');
    const before = objectAt(routeCandidate, 'before'); const after = objectAt(routeCandidate, 'afterSwap');
    const payerBeforeUsdc = await rpcAmountFromContext(context, 'rpc/0007-task-h3-market-brief-payer-usdc-before.json');
    const payerBeforeNative = await rpcAmountFromContext(context, 'rpc/0009-task-h3-market-brief-payer-native-before.json');
    const router = routerAddress(context);
    initial = stateProjection([
      balance('participant', 'USDC', payerBeforeUsdc, 'H3.prePurchase.USDC'),
      balance('participant', 'ETH', payerBeforeNative, 'H3.prePurchase.ETH'),
    ]);
    const component = requiredComponent(paid.component, 'H3.referenceComponent');
    final = readOnlyState(after, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    final = stateProjection(final.balances, final.allowances, [stringAt(component, 'componentId')]);
    const allowedRouteIds = arrayAt(objectAt(paid, 'routeObjective'), 'allowedRouteIds').map((value) => string(value, 'H3.allowedRouteId'));
    for (const id of allowedRouteIds) if (id !== 'fee500' && id !== 'fee3000') throw new Error(`H3_route_id_unsupported:${id}`);
    const tradeRoute = stringAt(paid, 'selectedRouteId') as 'fee500' | 'fee3000';
    ensureRouteMatches(context, tradeRoute, trade.poolAddress, trade.poolCodeHash, trade.feeTier);
    const approval = objectAt(trade, 'approval'); const swap = objectAt(trade, 'swap');
    const gasWei = (BigInt(stringAt(approval, 'gasCostWei')) + BigInt(stringAt(swap, 'gasCostWei'))).toString();
    objective = {
      referenceComponent: component,
      routeObjective: objectAt(paid, 'routeObjective'),
      inputAssetId: stringAt(trade, 'inputAssetId'), exactInputUnits: stringAt(trade, 'amountInUnits'),
      permittedRoutes: allowedRouteIds.map((id) => route(context, id as 'fee500' | 'fee3000')),
      minimumOutputUnits: stringAt(trade, 'minimumOutputUnits'),
      nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId),
      combinedExpenseBudgetUsdcUnits: profileExpenseBudget(context, stringAt(paid, 'amountUnits'), gasWei,
        calculateDexFeeUsdcUnits(stringAt(trade, 'amountInUnits'), Number(trade.feeTier))),
    };
    actionCount = 1 + Number(Boolean(trade.approval)) + Number(Boolean(trade.swap));
    paidSettlementObserved = true;
    if (stringAt(objectAt(paid, 'receipt'), 'blockNumber') !== stringAt(before, 'blockNumber')) throw new Error('H3_paid_delivery_trade_snapshot_chronology_mismatch');
  } else {
    kind = 'u1_reference'; taskCapturePath = 'task-u1/u1-same-generation-reference.json';
    capture = await readProfileArtifact(context, kind, taskCapturePath);
    const initialRaw = objectAt(capture, 'initialState'); const finalRaw = objectAt(capture, 'finalCutoff');
    const router = routerAddress(context);
    const initialRecipientMap = objectAt(initialRaw, 'recipientUsdcUnits'); const finalRecipientMap = objectAt(finalRaw, 'recipientUsdcUnits');
    const obligations = arrayAt(capture, 'obligations').map((item) => record(item, 'U1.obligation'));
    const initialBalances = [
      balance('participant', 'USDC', initialRaw.payerUsdcUnits, 'U1.initial.USDC'),
      balance('participant', 'ETH', initialRaw.payerNativeWei, 'U1.initial.ETH'),
      balance('participant', 'WETH', initialRaw.payerWethUnits, 'U1.initial.WETH'),
      ...obligations.map((item) => balance(stringAt(item, 'recipient'), 'USDC', initialRecipientMap[stringAt(item, 'recipient')], 'U1.initial.recipient')),
    ];
    const finalBalances = [
      balance('participant', 'USDC', finalRaw.payerUsdcUnits, 'U1.final.USDC'),
      balance('participant', 'ETH', finalRaw.payerNativeWei, 'U1.final.ETH'),
      balance('participant', 'WETH', finalRaw.payerWethUnits, 'U1.final.WETH'),
      ...obligations.map((item) => balance(stringAt(item, 'recipient'), 'USDC', finalRecipientMap[stringAt(item, 'recipient')], 'U1.final.recipient')),
    ];
    const initialAllowances = [
      allowance('participant', 'USDC', router, initialRaw.usdcRouterAllowanceUnits, 'U1.initial.USDC allowance'),
      allowance('participant', 'WETH', router, initialRaw.wethRouterAllowanceUnits, 'U1.initial.WETH allowance'),
    ];
    const finalAllowances = [
      allowance('participant', 'USDC', router, finalRaw.usdcRouterAllowanceUnits, 'U1.final.USDC allowance'),
      allowance('participant', 'WETH', router, finalRaw.wethRouterAllowanceUnits, 'U1.final.WETH allowance'),
    ];
    initial = stateProjection(initialBalances, initialAllowances);
    const componentsRaw = arrayAt(capture, 'dataComponents').map((item) => record(item, 'U1.component'));
    const fulfilled = obligations.filter((item) => item.fulfilledAtCommonCutoff === true).map((item) => stringAt(item, 'obligationId'));
    final = stateProjection(finalBalances, finalAllowances,
      componentsRaw.map((item) => stringAt(objectAt(item, 'dataComponent'), 'componentId')), fulfilled);
    const quote = objectAt(capture, 'currentQuote');
    const trade = objectAt(objectAt(capture, 'actions'), 'swap');
    const feeTier = Number(quote.feeTier);
    ensureRouteMatches(context, 'fee3000', quote.poolAddress, quote.poolCodeHash, feeTier);
    const approval = objectAt(objectAt(capture, 'actions'), 'approval');
    const spenderScope = [{ owner: 'participant', tokenAssetId: 'USDC', spender: router }];
    const target = objectAt(finalRaw, 'target');
    const usdcTarget = objectAt(target, 'USDC'); const ethTarget = objectAt(target, 'ETH');
    const purchaseActions = arrayAt(objectAt(capture, 'actions'), 'purchases').map((item) => record(item, 'U1.purchase'));
    const serviceAmount = purchaseActions.reduce((sum, item) => sum + BigInt(stringAt(item, 'amountUnits')), 0n).toString();
    const expense = objectAt(capture, 'observedExpense');
    const receiptRows = arrayAt(expense, 'participantReceipts').map((item) => record(item, 'U1.receipt'));
    const participantGasWei = receiptGasWei(receiptRows, 'U1.participantReceipts');
    if (participantGasWei !== stringAt(expense, 'participantGasWei')) throw new Error('U1_participant_gas_receipts_mismatch');
    const routeFee = calculateDexFeeUsdcUnits(stringAt(quote, 'inputUnits'), feeTier);
    const preExecutionPlan = objectAt(capture, 'preExecutionPlan');
    const embeddedPlan = objectAt(preExecutionPlan, 'plan');
    const savedPlan = await readProfileArtifact(context, kind, 'u1-preflight/planning-plan.json');
    const plan = objectAt(savedPlan, 'plan');
    const savedPlanSha256 = verifiedProfileArtifact(context, kind, 'u1-preflight/planning-plan.json').sha256;
    if (canonicalTaskJson(plan) !== canonicalTaskJson(embeddedPlan) || savedPlanSha256 !== stringAt(preExecutionPlan, 'planSha256')) {
      throw new Error('U1_pre_execution_plan_binding_mismatch');
    }
    if (stringAt(plan, 'nativeReserveWei') !== stringAt(context.policy.nativeReserveWei, taskId)) throw new Error('U1_preaction_native_reserve_policy_mismatch');
    objective = {
      requiredComponents: componentsRaw.map((item) => requiredComponent(item, 'U1.component')),
      permittedSources: [...context.policy.permittedProvenanceIds],
      permittedRoutes: [route(context, 'fee3000')],
      allocationAssets: [
        { assetId: 'USDC', usdcBaseUnitsPerAssetBaseUnit: { numerator: '1', denominator: '1' },
          targetShareBps: Number(usdcTarget.shareBps), toleranceBps: Number(usdcTarget.toleranceBps) },
        { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: {
          numerator: stringAt(quote, 'inputUnits'), denominator: stringAt(quote, 'quotedOutputWei'),
        }, targetShareBps: Number(ethTarget.shareBps), toleranceBps: Number(ethTarget.toleranceBps) },
      ],
      payoutObligations: obligations.map((item) => ({ obligationId: stringAt(item, 'obligationId'), recipient: stringAt(item, 'recipient'),
        assetId: canonicalAssetId(context, item.assetId, 'U1.payoutObligation.assetId'), exactAmountUnits: stringAt(item, 'amountUnits') })),
      temporarySpenderScope: spenderScope,
      nativeReserveWei: stringAt(plan, 'nativeReserveWei'),
      expenseBudgetUsdcUnits: profileExpenseBudget(context, serviceAmount, participantGasWei, routeFee),
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    const actionSet = objectAt(capture, 'actions');
    actionCount = arrayAt(actionSet, 'purchases').length + arrayAt(actionSet, 'payouts').length +
      ['approval', 'swap', 'unwrap', 'allowanceCleanup'].filter((key) => actionSet[key] !== null && actionSet[key] !== undefined).length;
    paidSettlementObserved = true;
    void trade; void approval;
  }

  const caseId = `bts-ranked-${taskId.toLowerCase()}-local-v1`;
  const stateInitialHash = sha256CanonicalTaskJson(initial);
  const stateFinalHash = sha256CanonicalTaskJson(final);
  const rawRefs = await rawReferencesForTask(context, taskId, taskCapturePath);
  const baselinePaths = baselineEvidencePaths(taskId,
    taskId === 'S1' || taskId === 'S2' || taskId === 'S3' || taskId === 'M1' || taskId === 'M2' || taskId === 'H1' || taskId === 'H2'
      ? unifiedTaskPaths(context, taskId, taskCapturePath)
      : taskId === 'S4' || taskId === 'M3' || taskId === 'M4'
        ? arrayAt(await readProfileArtifact(context, 'native_reference', taskCapturePath), 'sourceArtifacts').map((item) => stringAt(record(item, 'source-artifact'), 'path')).concat([taskCapturePath, 'manifest.json'])
        : taskId === 'H3'
          ? allProfilePaths(context, 'h3_reference')
          : allProfilePaths(context, 'u1_reference'), taskCapturePath);
  const baselineRefs = taskId === 'H3'
    ? rawRefs.filter((item) => baselinePaths.some((path) => item.path.endsWith(`/${path}`)))
    : rawRefs;
  if (baselineRefs.length === 0) throw new Error(`${taskId}_initial_state_evidence_missing`);
  const files = makeReferenceFiles(context, taskId, caseId, rawRefs, stateInitialHash, stateFinalHash, actionCount,
    paidSettlementObserved, baselineRefs);
  const base = taskCaseBase(context, taskId, initial, final, files, actionCount);
  const unchecked = { ...base, taskId, objective };
  const withHash = { ...unchecked, caseHash: taskCaseHash(unchecked) };
  const parsed = TaskCaseSchema.safeParse(withHash);
  if (!parsed.success) throw new Error(`${taskId}_task_case_schema_invalid:${parsed.error.issues.map((issue) => `${issue.path.join('.')}:${issue.code}`).join(',')}`);
  return { taskCase: parsed.data, evidenceFiles: [files.baselineFile, files.referenceFile] };
}

function trainingRowForTask(context: LoadedContext, taskId: TrainingTaskId): { row: JsonRecord; capture: JsonRecord } {
  const probe = context.probes.get('training_reference');
  if (!probe) throw new Error('training_reference_probe_missing');
  const profile = objectAt(probe, 'capture');
  const rows = arrayAt(profile, 'captures').map((item) => record(item, 'training_capture_row'));
  const row = rows.find((item) => item.taskId === taskId);
  if (!row) throw new Error(`training_capture_missing:${taskId}`);
  return { row, capture: objectAt(row, 'capture') };
}

async function trainingRawReferencesForTask(context: LoadedContext, taskId: TrainingTaskId): Promise<EvidenceRef[]> {
  const capture = context.inventory.captures.find((item) => item.kind === 'training_reference');
  const primitive = capture?.primitives.find((item) => item.taskId === taskId);
  if (!capture || capture.status !== 'verified_primitives' || !primitive || primitive.status !== 'raw_verified_primitive') {
    throw new Error(`training_task_evidence_not_verified:${taskId}`);
  }
  const paths = [...primitive.artifactReferences.map((item) => item.path), 'manifest.json'];
  const uniquePaths = [...new Set(paths)];
  const refs = rawRefsFromProfile(context, 'training_reference', uniquePaths);
  return rehashRawReferences(context, 'training_reference', refs);
}

async function trainingObservedTokenBalance(context: LoadedContext, observationId: string, expectedOwner: string): Promise<string> {
  const probe = context.probes.get('training_reference');
  if (!probe) throw new Error('training_reference_probe_missing');
  const observations = arrayAt(probe, 'observations').map((item) => record(item, 'training_observation'));
  const observation = observations.find((item) => item.id === observationId);
  if (!observation) throw new Error(`training_observation_missing:${observationId}`);
  const path = stringAt(observation, 'sourceArtifact');
  const artifact = await readProfileArtifact(context, 'training_reference', path);
  if (stringAt(artifact, 'method') !== 'eth_call') throw new Error(`training_observation_method_invalid:${observationId}`);
  const params = arrayAt(artifact, 'params');
  if (params.length !== 2) throw new Error(`training_observation_params_invalid:${observationId}`);
  const call = record(params[0], `${observationId}.call`);
  const usdc = objectAt(objectAt(context.manifest, 'contracts'), 'usdc');
  const owner = expectedOwner.toLowerCase().replace(/^0x/, '');
  if (!/^0x[0-9a-f]{40}$/i.test(expectedOwner) ||
      stringAt(call, 'to').toLowerCase() !== stringAt(usdc, 'address').toLowerCase() ||
      stringAt(call, 'data').toLowerCase() !== `0x70a08231${owner.padStart(64, '0')}` ||
      params[1] !== artifact.requestedBlock) {
    throw new Error(`training_observation_call_binding_invalid:${observationId}`);
  }
  const result = stringAt(artifact, 'result');
  if (!/^0x[0-9a-f]{64}$/i.test(result)) throw new Error(`training_observation_abi_word_invalid:${observationId}`);
  return BigInt(result).toString();
}

function trainingDeadlineSeconds(context: LoadedContext, profile: unknown, taskId: TrainingTaskId): number {
  if (profile === null || profile === undefined) return context.policy.taskDeadlineSeconds;
  const deadline = record(profile, `${taskId}.deadlineProfile`);
  const seconds = Number(deadline.deadlineSeconds);
  if (!Number.isSafeInteger(seconds) || seconds !== context.policy.taskDeadlineSeconds) {
    throw new Error(`training_deadline_policy_mismatch:${taskId}`);
  }
  return seconds;
}

function assertObservedBudget(candidate: JsonRecord, expectedBudget: string, taskId: 'H1' | 'H2'): void {
  const reported = objectAt(candidate, 'budgetProfile');
  if (stringAt(reported, 'budgetUsdcUnits') !== expectedBudget) throw new Error(`training_${taskId.toLowerCase()}_budget_profile_mismatch`);
}

async function buildTrainingTask(context: LoadedContext, taskId: TrainingTaskId): Promise<TaskBuild> {
  const { capture: taskCapture } = trainingRowForTask(context, taskId);
  const caseId = `bts-training-${taskId.toLowerCase()}-local-v1`;
  let objective: JsonRecord;
  let initial: StateProjection;
  let final: StateProjection;
  let actionCount: number;
  let paidSettlementObserved = false;
  let deadlineProfile: unknown;

  if (taskId === 'S1') {
    const before = objectAt(taskCapture, 'before');
    const after = objectAt(taskCapture, 'after');
    const router = routerAddress(context);
    initial = stateProjection([
      balance('participant', 'ETH', before.payerNativeWei, 'S1.before.payerNativeWei'),
      balance('participant', 'USDC', before.payerUsdcUnits, 'S1.before.payerUsdcUnits'),
      balance('participant', 'WETH', before.payerWethUnits, 'S1.before.payerWethUnits'),
      balance(stringAt(before, 'recipientAddress'), 'USDC', before.recipientUsdcUnits, 'S1.before.recipientUsdcUnits'),
      balance(stringAt(before, 'recipientAddress'), 'WETH', before.recipientWethUnits, 'S1.before.recipientWethUnits'),
    ], [
      allowance('participant', 'USDC', router, before.usdcRouterAllowanceUnits, 'S1.before.USDC allowance'),
      allowance('participant', 'WETH', router, before.wethRouterAllowanceUnits, 'S1.before.WETH allowance'),
    ]);
    final = stateProjection([
      balance('participant', 'ETH', after.payerNativeWei, 'S1.after.payerNativeWei'),
      balance('participant', 'USDC', after.payerUsdcUnits, 'S1.after.payerUsdcUnits'),
      balance('participant', 'WETH', after.payerWethUnits, 'S1.after.payerWethUnits'),
      balance(stringAt(after, 'recipientAddress'), 'USDC', after.recipientUsdcUnits, 'S1.after.recipientUsdcUnits'),
      balance(stringAt(after, 'recipientAddress'), 'WETH', after.recipientWethUnits, 'S1.after.recipientWethUnits'),
    ], [
      allowance('participant', 'USDC', router, after.usdcRouterAllowanceUnits, 'S1.after.USDC allowance'),
      allowance('participant', 'WETH', router, after.wethRouterAllowanceUnits, 'S1.after.WETH allowance'),
    ]);
    const action = objectAt(taskCapture, 'action');
    const unrelated = {
      payerNativeWei: before.payerNativeWei, payerWethUnits: before.payerWethUnits,
      recipientWethUnits: before.recipientWethUnits, poolUsdcUnits: before.poolUsdcUnits, poolWethUnits: before.poolWethUnits,
      usdcRouterAllowanceUnits: before.usdcRouterAllowanceUnits, wethRouterAllowanceUnits: before.wethRouterAllowanceUnits,
    };
    objective = {
      tokenAssetId: 'USDC', sender: 'participant', recipient: stringAt(action, 'recipient'),
      exactPrincipalUnits: stringAt(action, 'amountUnits'),
      nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId),
      unrelatedEffectBaselineSha256: sha256CanonicalTaskJson(unrelated),
    };
    actionCount = 1;
  } else if (taskId === 'S2') {
    const noEffect = objectAt(taskCapture, 'noEffectInterval');
    const router = routerAddress(context);
    initial = readOnlyState(objectAt(noEffect, 'stateBefore'), 'payerNativeEthWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcRouterAllowanceUnits', 'wethRouterAllowanceUnits', router);
    final = readOnlyState(objectAt(noEffect, 'stateAfter'), 'payerNativeEthWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcRouterAllowanceUnits', 'wethRouterAllowanceUnits', router);
    if (sha256CanonicalTaskJson(initial) !== sha256CanonicalTaskJson(final)) throw new Error('S2_observed_state_changed');
    const candidate = objectAt(taskCapture, 'objectiveCandidate');
    const requiredFields = arrayAt(candidate, 'requiredAnswerFields').map((field) => string(field, 'S2.requiredAnswerField'));
    objective = {
      resourceId: stringAt(candidate, 'resourceId'), offerId: stringAt(candidate, 'offerId'),
      completePaymentRequirements: canonicalPaymentRequirements(context, candidate.completePaymentRequirements, 'S2.completePaymentRequirements'),
      requiredAnswerFields: [...new Set(requiredFields)],
    };
    actionCount = 1;
  } else if (taskId === 'S4') {
    const nativeProfile = objectAt(taskCapture, 'captures');
    const capture = objectAt(nativeProfile, 'S4');
    const candidate = objectAt(capture, 'objectiveCandidate');
    const snapshots = objectAt(capture, 'snapshots');
    const start = objectAt(snapshots, 'taskStartAfterSetup');
    const end = objectAt(snapshots, 'finalAfterRevoke');
    const router = routerAddress(context);
    initial = readOnlyState(start, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    final = readOnlyState(end, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits', 'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    objective = {
      tokenAssetId: stringAt(candidate, 'tokenAssetId'), owner: 'participant', spender: stringAt(candidate, 'spender'),
      initialAllowanceUnits: stringAt(candidate, 'taskStartAllowanceUnits'),
      unrelatedAllowanceBaselineSha256: sha256CanonicalTaskJson({ wethRouterAllowanceUnits: start.wethAllowanceUnits }),
    };
    actionCount = 1;
  } else if (taskId === 'M1') {
    const payment = objectAt(taskCapture, 'payment');
    const principal = objectAt(taskCapture, 'observedPrincipal');
    const native = objectAt(taskCapture, 'participantNativeBalance');
    const component = objectAt(taskCapture, 'component');
    initial = stateProjection([
      balance('participant', 'USDC', principal.payerBalanceBeforeUnits, 'M1.initial.USDC'),
      balance('participant', 'ETH', native.beforeWei, 'M1.initial.ETH'),
    ]);
    final = stateProjection([
      balance('participant', 'USDC', principal.payerBalanceAfterUnits, 'M1.final.USDC'),
      balance('participant', 'ETH', native.afterWei, 'M1.final.ETH'),
    ], [], [stringAt(component, 'componentId')]);
    const purchaseFacts = objectAt(taskCapture, 'purchaseCountFacts');
    if (stringAt(purchaseFacts, 'purchaseCount') !== '1' || stringAt(purchaseFacts, 'paymentCount') !== '1' ||
        stringAt(purchaseFacts, 'deliveryCount') !== '1' || stringAt(purchaseFacts, 'participantGasCostCount') !== '0') {
      throw new Error('training_M1_actual_purchase_evidence_incomplete');
    }
    objective = {
      component,
      paymentRequirements: canonicalPaymentRequirements(context, taskCapture.paymentRequirements, 'M1.paymentRequirements'),
      expenseBudgetUsdcUnits: profileExpenseBudget(context, stringAt(payment, 'amountUnits'), '0', '0'),
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    actionCount = 1;
    paidSettlementObserved = true;
  } else if (taskId === 'M3' || taskId === 'M4') {
    const candidate = objectAt(taskCapture, 'objectiveCandidate');
    const candidateRoute = objectAt(candidate, 'route');
    ensureRouteMatches(context, 'fee3000', candidateRoute.poolAddress, candidateRoute.poolCodeHash, candidateRoute.feeTier);
    const publicQuote = objectAt(candidate, 'publicQuote');
    const exactInputUnits = stringAt(candidate, 'exactInputUnits');
    if (stringAt(publicQuote, 'amountInUnits') !== exactInputUnits ||
        stringAt(publicQuote, 'amountOutUnits') !== stringAt(publicQuote, 'independentQuoterV2OutputUnits') ||
        stringAt(candidate, 'quoteAtPinnedSource') !== stringAt(publicQuote, 'amountOutUnits') ||
        stringAt(publicQuote, 'minimumOutputUnits') !== (taskId === 'M3'
          ? stringAt(candidate, 'requiredNativeOutputMinimumWei') : stringAt(candidate, 'minimumOutputUnits'))) {
      throw new Error(`training_${taskId.toLowerCase()}_quote_case_binding_mismatch`);
    }
    const snapshots = objectAt(taskCapture, 'snapshots');
    const router = routerAddress(context);
    const end = objectAt(snapshots, taskId === 'M3' ? 'afterUnwrap' : 'afterCleanup');
    initial = readOnlyState(objectAt(snapshots, 'before'), 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    final = readOnlyState(end, 'payerNativeWei', 'payerUsdcUnits', 'payerWethUnits',
      'usdcAllowanceUnits', 'wethAllowanceUnits', router);
    const actions = objectAt(taskCapture, 'actions');
    const expectedActionKeys = taskId === 'M3' ? ['approval', 'swap', 'unwrap'] : ['approval', 'swap', 'cleanup'];
    if (canonicalTaskJson(Object.keys(actions).sort()) !== canonicalTaskJson([...expectedActionKeys].sort())) {
      throw new Error(`training_${taskId.toLowerCase()}_action_inventory_mismatch`);
    }
    const actionReceipts = Object.values(actions).map((item) => record(item, `${taskId}.action`));
    const participantGas = actionReceipts.reduce((sum, item) => sum + BigInt(stringAt(item, 'gasCostWei')), 0n).toString();
    const feeTier = Number(candidateRoute.feeTier);
    const budget = profileExpenseBudget(context, '0', participantGas, calculateDexFeeUsdcUnits(exactInputUnits, feeTier));
    const permittedRoutes = [route(context, 'fee3000')];
    if (taskId === 'M3') {
      objective = {
        inputAssetId: stringAt(candidate, 'inputAssetId'), exactInputUnits,
        outputAssetId: 'ETH', minimumNativeOutputWei: stringAt(candidate, 'requiredNativeOutputMinimumWei'),
        permittedRoutes, maxSlippageBps: Number(candidate.maxSlippageBps),
        nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId), expenseBudgetUsdcUnits: budget,
      };
    } else {
      const allowanceCandidate = objectAt(candidate, 'requiredTemporaryAllowance');
      objective = {
        inputAssetId: stringAt(candidate, 'inputAssetId'), exactInputUnits,
        outputAssetId: stringAt(candidate, 'outputAssetId'), minimumOutputUnits: stringAt(candidate, 'minimumOutputUnits'),
        permittedRoutes,
        initialAllowanceScope: [allowance('participant', stringAt(allowanceCandidate, 'tokenAssetId'), allowanceCandidate.spender,
          allowanceCandidate.initialUnits, 'M4.initialAllowanceScope')],
        nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId), expenseBudgetUsdcUnits: budget,
      };
    }
    actionCount = actionReceipts.length;
  } else if (taskId === 'H1') {
    const candidate = objectAt(taskCapture, 'candidate');
    const components = arrayAt(candidate, 'components').map((item) => requiredComponent(item, 'H1.component'));
    if (components.length !== 2 || Number(candidate.requiredComponentCount) !== components.length) throw new Error('training_H1_component_set_incomplete');
    const payerAddress = stringAt(objectAt(candidate, 'generation'), 'payerAddress');
    const initialUsdc = await trainingObservedTokenBalance(context, 'task-training-h1-component-1-payer-usdc-before', payerAddress);
    const finalUsdc = await trainingObservedTokenBalance(context, 'task-training-h1-component-2-payer-usdc-after', payerAddress);
    initial = stateProjection([balance('participant', 'USDC', initialUsdc, 'H1.initial.USDC')]);
    final = stateProjection([balance('participant', 'USDC', finalUsdc, 'H1.final.USDC')], [],
      components.map((item) => stringAt(item, 'componentId')));
    const expense = objectAt(candidate, 'observedExpense');
    const budget = profileExpenseBudget(context, stringAt(expense, 'serviceChargesUsdcUnits'),
      stringAt(expense, 'participantGasCostWei'), stringAt(expense, 'declaredDexExpenseUsdcUnits'));
    assertObservedBudget(candidate, budget, 'H1');
    objective = {
      requiredComponents: components,
      permittedSources: [...context.policy.permittedProvenanceIds],
      expenseBudgetUsdcUnits: budget,
      duplicatePurchaseIdentity: context.policy.duplicatePurchaseIdentity,
    };
    actionCount = arrayAt(taskCapture, 'selectedOffers').length;
    if (actionCount !== 2) throw new Error('training_H1_selected_offer_inventory_invalid');
    paidSettlementObserved = true;
    deadlineProfile = candidate.deadlineProfile;
  } else {
    const initialAssets = objectAt(taskCapture, 'initialAssets');
    const finalCutoff = objectAt(taskCapture, 'finalCutoff');
    const obligations = arrayAt(taskCapture, 'obligations').map((item) => record(item, 'H2.obligation'));
    const obligationsWithCanonicalAssets = obligations.map((item) => ({
      ...item,
      canonicalAssetId: canonicalAssetId(context, item.assetId, 'H2.obligation.assetId'),
    }));
    const initialRecipients = record(initialAssets.recipientUsdcUnits, 'H2.initialRecipients');
    const finalRecipients = record(finalCutoff.recipientUsdcUnits, 'H2.finalRecipients');
    const initialBalances = [
      balance('participant', 'USDC', initialAssets.payerUsdcUnits, 'H2.initial.USDC'),
      balance('participant', 'ETH', initialAssets.payerNativeWei, 'H2.initial.ETH'),
      ...obligationsWithCanonicalAssets.map((item) => balance(stringAt(item, 'recipient'), item.canonicalAssetId,
        initialRecipients[stringAt(item, 'recipient')], 'H2.initial.recipient')),
    ];
    const finalBalances = [
      balance('participant', 'USDC', finalCutoff.payerUsdcUnits, 'H2.final.USDC'),
      balance('participant', 'ETH', finalCutoff.payerNativeWei, 'H2.final.ETH'),
      ...obligationsWithCanonicalAssets.map((item) => balance(stringAt(item, 'recipient'), item.canonicalAssetId,
        finalRecipients[stringAt(item, 'recipient')], 'H2.final.recipient')),
    ];
    initial = stateProjection(initialBalances);
    const fulfilled = obligations.filter((item) => item.fulfilledAtCommonCutoff === true).map((item) => stringAt(item, 'obligationId'));
    final = stateProjection(finalBalances, [], [], fulfilled);
    const conversions = arrayAt(taskCapture, 'permittedConversions');
    if (conversions.length !== 0) throw new Error('training_H2_permitted_conversion_case_shape_unsupported');
    const expense = objectAt(taskCapture, 'observedExpense');
    const budget = profileExpenseBudget(context, stringAt(expense, 'serviceChargesUsdcUnits'),
      stringAt(expense, 'participantGasCostWei'), stringAt(expense, 'declaredDexExpenseUsdcUnits'));
    assertObservedBudget(taskCapture, budget, 'H2');
    objective = {
      obligations: obligationsWithCanonicalAssets.map((item) => ({ obligationId: stringAt(item, 'obligationId'), recipient: stringAt(item, 'recipient'),
        assetId: item.canonicalAssetId, exactAmountUnits: stringAt(item, 'amountUnits') })),
      initialAssetIds: ['USDC', 'ETH'], permittedConversions: [],
      nativeReserveWei: stringAt(context.policy.nativeReserveWei, taskId), expenseBudgetUsdcUnits: budget,
    };
    actionCount = obligations.length;
    deadlineProfile = taskCapture.deadlineProfile;
  }

  const taskDeadlineSeconds = trainingDeadlineSeconds(context, deadlineProfile, taskId);
  const stateInitialHash = sha256CanonicalTaskJson(initial);
  const stateFinalHash = sha256CanonicalTaskJson(final);
  const rawRefs = await trainingRawReferencesForTask(context, taskId);
  if (rawRefs.length === 0) throw new Error(`training_${taskId.toLowerCase()}_raw_evidence_missing`);
  const files = makeReferenceFiles(context, taskId, caseId, rawRefs, stateInitialHash, stateFinalHash,
    actionCount, paidSettlementObserved, rawRefs, 'training');
  const base = taskCaseBase(context, taskId, initial, final, files, actionCount, 'training', caseId);
  base.taskDeadlineSeconds = taskDeadlineSeconds;
  const unchecked = { ...base, taskId, objective };
  const withHash = { ...unchecked, caseHash: taskCaseHash(unchecked) };
  const parsed = TaskCaseSchema.safeParse(withHash);
  if (!parsed.success) throw new Error(`${taskId}_training_task_case_schema_invalid:${parsed.error.issues.map((issue) => `${issue.path.join('.')}:${issue.code}`).join(',')}`);
  return { taskCase: parsed.data, evidenceFiles: [files.baselineFile, files.referenceFile] };
}

function emptyTrainingResult(blockers: string[], inventory: TaskReferenceInventoryResult | null = null): TrainingTaskCaseCandidateAssembly {
  return {
    schemaVersion: 'bts-training-task-case-candidate-assembly/v1',
    classification: 'local_training_task_case_candidates_unactivated',
    status: 'blocked', profile: null, inventory, executionIdentity: null, executionIdentityHash: null,
    applicationSchemaLineage: null, cases: [], evidenceFiles: [], taskResults: [], blockers,
    claims: { taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false },
  };
}

export async function assembleTrainingTaskCaseCandidates(options: AssembleTrainingTaskCaseOptions): Promise<TrainingTaskCaseCandidateAssembly> {
  let context: LoadedContext;
  try { context = await loadContext(options, true); }
  catch (error) {
    const inventory = error && typeof error === 'object' && 'inventory' in error
      ? (error as { inventory?: TaskReferenceInventoryResult }).inventory ?? null : null;
    return emptyTrainingResult([error instanceof Error ? error.message : 'training_assembler_context_failed'], inventory);
  }

  const cases: TaskCase[] = [];
  const evidenceFiles: TaskCaseEvidenceFile[] = [];
  const taskResults: TrainingTaskCaseCandidateAssembly['taskResults'] = [];
  for (const taskId of TRAINING_TASK_ORDER) {
    try {
      const built = await buildTrainingTask(context, taskId);
      cases.push(built.taskCase);
      evidenceFiles.push(...built.evidenceFiles);
      taskResults.push({ taskId, status: 'assembled', caseHash: built.taskCase.caseHash, blockers: [] });
    } catch (error) {
      taskResults.push({ taskId, status: 'blocked', blockers: [error instanceof Error ? error.message : 'training_task_case_assembly_failed'] });
    }
  }
  const blockers = [
    ...(cases.length === TRAINING_TASK_ORDER.length ? [] : ['training_task_case_set_incomplete']),
    'same_tool_reference_path_verification_not_run',
    'independent_database_migration_state_not_observed',
    'feasibility_verification_not_run',
    'difficulty_approval_not_performed',
    'release_validation_not_run',
    'release_activation_not_performed',
  ];
  return {
    schemaVersion: 'bts-training-task-case-candidate-assembly/v1',
    classification: 'local_training_task_case_candidates_unactivated',
    status: cases.length === TRAINING_TASK_ORDER.length ? 'candidates_only' : 'blocked',
    profile: {
      profileId: context.policy.profileId,
      policyPath: relative(context.repositoryRoot, context.policyPath).replace(/\\/g, '/'),
      policySha256: context.policyHash,
      inputIndexPath: relative(context.repositoryRoot, context.sourceIndexPath).replace(/\\/g, '/'),
      inputIndexSha256: context.sourceIndexHash,
      difficultyApproval: false,
      releaseActivation: false,
    },
    inventory: context.inventory,
    executionIdentity: context.executionIdentity,
    executionIdentityHash: context.executionIdentityHash,
    applicationSchemaLineage: context.appLineage,
    cases,
    evidenceFiles,
    taskResults,
    blockers,
    claims: { taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false },
  };
}

export async function assembleRankedTaskCaseCandidates(options: AssembleRankedTaskCaseOptions): Promise<RankedTaskCaseCandidateAssembly> {
  let context: LoadedContext;
  try { context = await loadContext(options); }
  catch (error) {
    const inventory = error && typeof error === 'object' && 'inventory' in error
      ? (error as { inventory?: TaskReferenceInventoryResult }).inventory ?? null : null;
    return emptyResult([error instanceof Error ? error.message : 'assembler_context_failed'], inventory);
  }

  const cases: TaskCase[] = [];
  const evidenceFiles: TaskCaseEvidenceFile[] = [];
  const taskResults: RankedTaskCaseCandidateAssembly['taskResults'] = [];
  for (const taskId of TASK_ORDER) {
    try {
      const built = await buildTask(context, taskId);
      cases.push(built.taskCase);
      evidenceFiles.push(...built.evidenceFiles);
      taskResults.push({ taskId, status: 'assembled', caseHash: built.taskCase.caseHash, blockers: [] });
    } catch (error) {
      taskResults.push({ taskId, status: 'blocked', blockers: [error instanceof Error ? error.message : 'task_case_assembly_failed'] });
    }
  }
  const blockers = [
    ...(cases.length === TASK_ORDER.length ? [] : ['ranked_task_case_set_incomplete']),
    'training_cases_not_assembled_by_this_scope',
    'independent_database_migration_state_not_observed',
    'feasibility_verification_not_run',
    'difficulty_approval_not_performed',
    'release_validation_not_run',
    'release_activation_not_performed',
  ];
  return {
    schemaVersion: 'bts-ranked-task-case-candidate-assembly/v1',
    classification: 'local_ranked_task_case_candidates_unactivated',
    status: cases.length === TASK_ORDER.length ? 'candidates_only' : 'blocked',
    profile: {
      profileId: context.policy.profileId,
      policyPath: relative(context.repositoryRoot, context.policyPath).replace(/\\/g, '/'),
      policySha256: context.policyHash,
      inputIndexPath: relative(context.repositoryRoot, context.sourceIndexPath).replace(/\\/g, '/'),
      inputIndexSha256: context.sourceIndexHash,
      difficultyApproval: false,
      releaseActivation: false,
    },
    inventory: context.inventory,
    executionIdentity: context.executionIdentity,
    executionIdentityHash: context.executionIdentityHash,
    applicationSchemaLineage: context.appLineage,
    cases,
    evidenceFiles,
    taskResults,
    blockers,
    claims: { taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false },
  };
}

