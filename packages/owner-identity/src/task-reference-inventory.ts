import { createHash } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const HASH = /^[0-9a-f]{64}$/i;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/i;
const BLOCK_NUMBER = /^0x(?:0|[1-9a-f][0-9a-f]*)$/i;
const TASK_ORDER = ['S1', 'S2', 'S3', 'S4', 'M1', 'M2', 'M3', 'M4', 'H1', 'H2', 'H3', 'U1'] as const;
const CAPTURE_CLASSIFICATION = 'local_fork_public_tool_evidence_not_bts_task_acceptance';
const PRIMITIVE_CLASSIFICATION = 'verified_raw_reference_primitives_not_task_acceptance';

export type BtsTaskId = (typeof TASK_ORDER)[number];
// AICODE-NOTE: This is the immutable eight-task source-capture profile. It is
// parsed as historical evidence; current release eligibility is defined by task-catalog.ts.
const CAPTURED_TRAINING_TASK_ORDER = ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2'] as const;
export type CapturedTrainingTaskId = (typeof CAPTURED_TRAINING_TASK_ORDER)[number];
export type TaskReferenceCaptureKind = 'unified_reference' | 'native_reference' | 'h3_reference' | 'u1_reference' | 'training_reference';
export type TaskReferenceEvidenceMode = 'reference' | 'training_reference';

type CaptureSourceBase = {
  /** POSIX relative directory under `runsRoot`, for example `bts-h3/...`. */
  relativeDirectory: string;
  /** Externally pinned hash of this capture's probe.json. */
  expectedProbeSha256: string;
};

export type TaskReferenceCaptureSource =
  | (CaptureSourceBase & { kind: 'unified_reference' })
  | (CaptureSourceBase & { kind: 'native_reference' })
  | (CaptureSourceBase & { kind: 'h3_reference' })
  | (CaptureSourceBase & { kind: 'u1_reference' })
  | (CaptureSourceBase & { kind: 'training_reference' });

export type TaskReferenceInventoryInput = {
  /** Absolute path to the repository's `artifacts/runs` directory. */
  runsRoot: string;
  captures: readonly TaskReferenceCaptureSource[];
};

export type VerifiedRawArtifact = {
  scope: 'capture' | 'runs_root';
  path: string;
  sha256: string;
  boundary: string;
  contentType: 'application/json';
  status: 'verified' | 'blocked';
  blocker?: string;
};

export type CapturePin = {
  manifestSha256: string;
  applicationSourceSha256: string;
  probeSourceSha256: string;
  sourceBlock: { number: string; hash: string } | null;
};

export type VerifiedPrimitive = {
  taskId: BtsTaskId;
  captureKind: TaskReferenceCaptureKind;
  evidenceMode: TaskReferenceEvidenceMode;
  relativeDirectory: string;
  status: 'raw_verified_primitive';
  classification: typeof PRIMITIVE_CLASSIFICATION;
  releaseReadiness: 'blocked';
  artifactReferences: Array<{ path: string; sha256: string; boundary: string }>;
};

export type TaskCaptureVerification = {
  kind: TaskReferenceCaptureKind;
  evidenceMode: TaskReferenceEvidenceMode;
  relativeDirectory: string;
  status: 'verified_primitives' | 'blocked';
  compatibleWithInventoryPins: boolean;
  probeSha256: string | null;
  pin: CapturePin | null;
  rawArtifactCount: number;
  rawArtifacts: VerifiedRawArtifact[];
  primitives: VerifiedPrimitive[];
  blockers: string[];
};

export type TaskCoverage = {
  taskId: BtsTaskId;
  status: 'observed_primitive' | 'not_observed' | 'blocked';
  primitives: Array<{ captureKind: TaskReferenceCaptureKind; evidenceMode: TaskReferenceEvidenceMode; relativeDirectory: string; artifactCount: number }>;
};

export type TaskReferenceInventoryResult = {
  schemaVersion: 'bts-verified-task-reference-inventory/v1';
  classification: typeof PRIMITIVE_CLASSIFICATION;
  status: 'verified' | 'blocked';
  pins: CapturePin | null;
  captures: TaskCaptureVerification[];
  taskCoverage: TaskCoverage[];
  blockers: string[];
  claims: {
    taskAcceptance: false;
    taskGrade: false;
    validatedRelease: false;
    difficultyApproval: false;
    releaseActivation: false;
  };
};

type JsonRecord = Record<string, unknown>;
type ArtifactReference = { path: string; sha256: string; boundary?: string; contentType?: string };
type Inspection = { successful: boolean; primitives: Array<{ taskId: BtsTaskId; refs: ArtifactReference[] }>; refs: ArtifactReference[] };
type IndexedArtifact = { path: string; sha256: string; boundary: string; contentType: 'application/json' };

const TRAINING_CASES = [
  { taskId: 'S1', transferUsdcUnits: '200000' },
  { taskId: 'S2', resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-standard', amountUsdcUnits: '125000' },
  { taskId: 'S4', initialAllowanceUnits: '20000' },
  { taskId: 'M1', resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
  { taskId: 'M3', inputUsdcUnits: '200000', quote: 'public exact quote plus independent QuoterV2 at quote block' },
  { taskId: 'M4', inputUsdcUnits: '200000', approvedUsdcUnits: '400000', quote: 'public exact quote plus independent QuoterV2 at quote block' },
  { taskId: 'H1', purchases: [
    { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
    { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-extended', amountUsdcUnits: '250000' },
  ], requiredOperatingBudgetUsdcUnits: '700000' },
  { taskId: 'H2', payoutUsdcUnits: ['200000', '300000'] },
] as const;

const TRAINING_OBSERVATIONS: Record<CapturedTrainingTaskId, readonly string[]> = {
  S1: ['task-transfer-before-block', 'task-transfer-before-payer-usdc', 'task-transfer-receipt'],
  S2: ['task-reference-s2-state-before-payer-usdc', 'task-reference-s2-public-offer-read'],
  S4: ['task-native-s4-before-setup-payer-usdc', 'task-native-s4-before-setup-usdc-router-allowance'],
  M1: ['task-reference-m1-payer-usdc-before', 'task-reference-m1-single-signed-purchase'],
  M3: ['task-native-m3-before-payer-usdc', 'task-native-m3-public-exact-input-quote', 'task-native-m3-public-quote-block-identity', 'task-native-m3-independent-fee3000-quote'],
  M4: ['task-native-m4-before-payer-usdc', 'task-native-m4-public-exact-input-quote', 'task-native-m4-public-quote-block-identity', 'task-native-m4-independent-fee3000-quote'],
  H1: ['task-training-h1-component-1-payer-usdc-before', 'task-training-h1-component-1-payer-usdc-after',
    'task-training-h1-component-2-payer-usdc-before', 'task-training-h1-component-2-payer-usdc-after'],
  H2: ['task-reference-h2-initial-payer-usdc', 'task-reference-h2-initial-recipient-0-usdc', 'task-reference-h2-initial-recipient-1-usdc', 'task-reference-h2-case-candidate'],
};

class InventoryError extends Error {
  constructor(readonly code: string) { super(code); }
}

function record(value: unknown): JsonRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : null;
}

function isHash(value: unknown): value is string {
  return typeof value === 'string' && HASH.test(value);
}

function sha256(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function fail(code: string): never {
  throw new InventoryError(code);
}

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function hasKeys(value: JsonRecord, required: readonly string[]): boolean {
  return required.every((key) => Object.hasOwn(value, key));
}

function validRelativePath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.startsWith('/') || value.includes('\\') || value.includes('\0') || /^[A-Za-z]:/.test(value)) return false;
  const segments = value.split('/');
  return segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..' && /^[A-Za-z0-9._-]+$/.test(segment));
}

function isContained(root: string, target: string): boolean {
  const remainder = relative(root, target);
  return remainder.length > 0 && remainder !== '..' && !remainder.startsWith(`..${sep}`) && !isAbsolute(remainder);
}

function json(bytes: Buffer, code: string): JsonRecord {
  try {
    const parsed: unknown = JSON.parse(bytes.toString('utf8'));
    const found = record(parsed);
    return found ?? fail(code);
  } catch (error) {
    if (error instanceof InventoryError) throw error;
    return fail(code);
  }
}

function ref(value: unknown, code: string): ArtifactReference {
  const found = record(value);
  if (!found || !validRelativePath(found.path) || !isHash(found.sha256) ||
      (found.boundary !== undefined && (typeof found.boundary !== 'string' || found.boundary.length === 0)) ||
      (found.contentType !== undefined && found.contentType !== 'application/json')) return fail(code);
  return {
    path: found.path,
    sha256: found.sha256.toLowerCase(),
    ...(typeof found.boundary === 'string' ? { boundary: found.boundary } : {}),
    ...(found.contentType === 'application/json' ? { contentType: found.contentType } : {}),
  };
}

function artifactInventory(value: unknown): IndexedArtifact[] {
  if (!Array.isArray(value) || value.length === 0) return fail('artifact_inventory_missing_or_empty');
  const seen = new Map<string, IndexedArtifact>();
  for (const item of value) {
    const found = record(item);
    if (!found || !exactKeys(found, ['path', 'sha256', 'contentType', 'boundary']) ||
        !validRelativePath(found.path) || !isHash(found.sha256) || found.contentType !== 'application/json' ||
        typeof found.boundary !== 'string' || found.boundary.length === 0) return fail('artifact_inventory_entry_invalid');
    const current: IndexedArtifact = { path: found.path, sha256: found.sha256.toLowerCase(), contentType: 'application/json', boundary: found.boundary };
    const previous = seen.get(current.path);
    if (previous && (previous.sha256 !== current.sha256 || previous.boundary !== current.boundary || previous.contentType !== current.contentType)) {
      return fail(`artifact_duplicate_path_conflict:${current.path}`);
    }
    seen.set(current.path, current);
  }
  return [...seen.values()];
}

function jsonEqual(left: unknown, right: unknown): boolean {
  const canonical = (value: unknown): string => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
    if (value && typeof value === 'object') {
      const entries = Object.entries(value as JsonRecord).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
      return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`).join(',')}}`;
    }
    return JSON.stringify(value) ?? 'null';
  };
  return canonical(left) === canonical(right);
}

function taskId(value: unknown): BtsTaskId | null {
  return typeof value === 'string' && (TASK_ORDER as readonly string[]).includes(value) ? value as BtsTaskId : null;
}

function taskArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length === TASK_ORDER.length && value.every((item, index) => item === TASK_ORDER[index]);
}

function commonProfilePin(probe: JsonRecord, manifestRef: ArtifactReference, manifest: JsonRecord, blockers: string[]): CapturePin | null {
  const appSha = probe.applicationSourceSha256;
  const probeSha = probe.probeSourceSha256;
  if (!isHash(appSha)) blockers.push('application_source_hash_invalid');
  if (!isHash(probeSha)) blockers.push('probe_source_hash_invalid');
  const source = record(manifest.source);
  const local = record(manifest.local);
  if (!source || !local || source.chainId !== 8453 || local.chainId !== 8453 ||
      typeof source.blockNumber !== 'string' || !BLOCK_NUMBER.test(source.blockNumber) || !BLOCK_HASH.test(String(source.blockHash ?? '')) ||
      typeof local.forkBlock !== 'string' || !BLOCK_NUMBER.test(local.forkBlock)) {
    blockers.push('raw_manifest_source_identity_invalid');
    return null;
  }
  const topBlock = record(probe.sourceBlock);
  let sourceBlock: { number: string; hash: string } | null = null;
  if (topBlock && typeof topBlock.number === 'string' && BLOCK_NUMBER.test(topBlock.number) &&
      typeof topBlock.hash === 'string' && BLOCK_HASH.test(topBlock.hash)) {
    sourceBlock = { number: topBlock.number.toLowerCase(), hash: topBlock.hash.toLowerCase() };
    if (sourceBlock.number !== source.blockNumber.toLowerCase() || sourceBlock.number !== local.forkBlock.toLowerCase() ||
        sourceBlock.hash !== String(source.blockHash).toLowerCase()) blockers.push('probe_source_block_mismatch');
  } else {
    blockers.push('probe_source_block_missing');
  }
  const environment = record(probe.environment);
  if (environment && typeof environment.forkBlock === 'string' &&
      (!sourceBlock || environment.forkBlock.toLowerCase() !== sourceBlock.number)) blockers.push('capture_environment_fork_block_mismatch');
  const manifestSha = manifestRef.sha256.toLowerCase();
  if (!isHash(appSha) || !isHash(probeSha)) return null;
  return {
    manifestSha256: manifestSha,
    applicationSourceSha256: appSha.toLowerCase(),
    probeSourceSha256: probeSha.toLowerCase(),
    sourceBlock,
  };
}

function referenceFromProbe(probe: JsonRecord, blockers: string[]): ArtifactReference | null {
  const manifest = record(probe.manifest);
  if (!manifest || manifest.path !== 'manifest.json') {
    blockers.push('manifest_reference_invalid');
    return null;
  }
  try { return ref(manifest, 'manifest_reference_invalid'); }
  catch { blockers.push('manifest_reference_invalid'); return null; }
}

function inspectUnifiedReference(probe: JsonRecord, blockers: string[]): Inspection {
  const expectedKeys = ['schemaVersion', 'classification', 'captureStatus', 'releaseReadiness', 'manifest', 'environment',
    'applicationSourceSha256', 'probeSourceSha256', 'sourceBlock', 'referenceIndex', 'taskOrder', 'taskCases', 'captures',
    'deliveryProjectionErrors', 'observations', 'artifacts'];
  if (!exactKeys(probe, expectedKeys) || probe.schemaVersion !== 'bts-task-reference-capture/v1' ||
      probe.classification !== CAPTURE_CLASSIFICATION || probe.releaseReadiness !== 'blocked' || !taskArray(probe.taskOrder)) {
    blockers.push('unified_reference_schema_mismatch');
  }
  const successful = probe.captureStatus === 'captured';
  if (!successful) blockers.push('capture_not_successful:unified_reference');
  const taskCases = probe.taskCases;
  const captures = probe.captures;
  if (!Array.isArray(taskCases) || taskCases.length !== TASK_ORDER.length || !Array.isArray(captures)) {
    blockers.push('unified_reference_case_inventory_invalid');
    return { successful: false, primitives: [], refs: [] };
  }
  const refs: ArtifactReference[] = [];
  const captureById = new Map<string, JsonRecord>();
  for (const rawCapture of captures) {
    const capture = record(rawCapture);
    if (!capture || typeof capture.captureId !== 'string' || captureById.has(capture.captureId) ||
        !['observed', 'unavailable'].includes(String(capture.status)) || !Array.isArray(capture.artifacts)) {
      blockers.push('unified_reference_primitive_capture_invalid');
      continue;
    }
    if (capture.status === 'observed' && !isHash(capture.captureSha256)) blockers.push(`unified_reference_capture_hash_invalid:${capture.captureId}`);
    if (capture.status === 'unavailable' && capture.captureSha256 !== null) blockers.push(`unified_reference_unavailable_capture_hash_invalid:${capture.captureId}`);
    captureById.set(capture.captureId, capture);
    for (const artifact of capture.artifacts) {
      try { refs.push(ref(artifact, `unified_reference_capture_artifact_invalid:${capture.captureId}`)); }
      catch { blockers.push(`unified_reference_capture_artifact_invalid:${capture.captureId}`); }
    }
  }
  const primitives: Inspection['primitives'] = [];
  for (let index = 0; index < taskCases.length; index += 1) {
    const candidate = record(taskCases[index]);
    const expectedId = TASK_ORDER[index]!;
    if (!candidate || candidate.taskId !== expectedId || candidate.releaseReadiness !== 'blocked' ||
        !['observed', 'not_observed'].includes(String(candidate.evidenceStatus)) || !Array.isArray(candidate.primitiveCaptureIds) ||
        !Array.isArray(candidate.evidence) || !Array.isArray(candidate.blockers)) {
      blockers.push(`unified_reference_task_case_invalid:${expectedId}`);
      continue;
    }
    const taskRefs: ArtifactReference[] = [];
    for (const item of candidate.evidence) {
      try { taskRefs.push(ref(item, `unified_reference_task_evidence_invalid:${expectedId}`)); }
      catch { blockers.push(`unified_reference_task_evidence_invalid:${expectedId}`); }
    }
    refs.push(...taskRefs);
    const captureIds = candidate.primitiveCaptureIds;
    if (!captureIds.every((id) => typeof id === 'string' && captureById.get(id)?.status === 'observed')) {
      if (candidate.evidenceStatus === 'observed') blockers.push(`unified_reference_observed_case_missing_capture:${expectedId}`);
      continue;
    }
    if (candidate.evidenceStatus === 'observed') {
      if (taskRefs.length === 0 || captureIds.length === 0) blockers.push(`unified_reference_observed_case_evidence_empty:${expectedId}`);
      else primitives.push({ taskId: expectedId, refs: taskRefs });
    } else if (taskRefs.length !== 0 || captureIds.length !== 0) {
      blockers.push(`unified_reference_unobserved_case_has_evidence:${expectedId}`);
    }
  }
  const indexRefObject = record(probe.referenceIndex);
  if (!indexRefObject) blockers.push('unified_reference_index_reference_invalid');
  else {
    try { refs.push(ref(indexRefObject, 'unified_reference_index_reference_invalid')); }
    catch { blockers.push('unified_reference_index_reference_invalid'); }
  }
  validateObservations(probe.observations, blockers, 'unified_reference');
  return { successful, primitives, refs };
}

function inspectNativeReference(probe: JsonRecord, blockers: string[]): Inspection {
  const expectedKeys = ['schemaVersion', 'classification', 'status', 'phase', 'manifest', 'capture', 'applicationSourceSha256',
    'probeSourceSha256', 'sourceBlock', 'observations', 'artifacts'];
  const capture = record(probe.capture);
  if (!exactKeys(probe, expectedKeys) || probe.schemaVersion !== 'bts-native-task-probe/v1' ||
      probe.classification !== 'local_fork_public_tool_evidence_not_bts_acceptance' || probe.phase !== 'complete' ||
      !capture || capture.schemaVersion !== 'bts-native-task-reference/v1' ||
      capture.classification !== 'local_fork_public_tool_evidence_not_release_manifest' || capture.status !== 'captured') {
    blockers.push('native_reference_schema_mismatch');
  }
  const successful = probe.status === 'captured';
  if (!successful) blockers.push('capture_not_successful:native_reference');
  if (!capture) return { successful: false, primitives: [], refs: [] };
  const captureMap = record(capture.captures);
  const captureArtifactMap = record(capture.captureArtifacts);
  const nativeTasks = ['S4', 'M3', 'M4'] as const;
  if (!captureMap || !captureArtifactMap ||
      !jsonEqual(Object.keys(captureMap).sort(), [...nativeTasks].sort()) ||
      !jsonEqual(Object.keys(captureArtifactMap).sort(), [...nativeTasks].sort())) {
    blockers.push('native_reference_task_inventory_invalid');
    return { successful: false, primitives: [], refs: [] };
  }
  const schemas: Record<(typeof nativeTasks)[number], string> = {
    S4: 'bts-s4-allowance-revocation-reference/v1',
    M3: 'bts-m3-native-output-reference/v1',
    M4: 'bts-m4-exchange-cleanup-reference/v1',
  };
  const refs: ArtifactReference[] = [];
  const primitives: Inspection['primitives'] = [];
  const expectedActions: Record<(typeof nativeTasks)[number], readonly string[]> = {
    S4: [], M3: ['approval', 'swap', 'unwrap'], M4: ['approval', 'swap', 'cleanup'],
  };
  const expectedSnapshots: Record<(typeof nativeTasks)[number], readonly string[]> = {
    S4: ['beforeSetup', 'taskStartAfterSetup', 'finalAfterRevoke'],
    M3: ['before', 'afterApproval', 'afterSwap', 'afterUnwrap'],
    M4: ['before', 'afterApproval', 'afterSwapResidual', 'afterCleanup'],
  };
  for (const id of nativeTasks) {
    const profile = record(captureMap[id]);
    const artifact = captureArtifactMap[id];
    const actions = record(profile?.actions);
    const snapshots = record(profile?.snapshots);
    const actionKeys = actions ? Object.keys(actions) : [];
    const snapshotKeys = snapshots ? Object.keys(snapshots) : [];
    if (!profile || profile.schemaVersion !== schemas[id] || profile.classification !== 'actual_tool_http_reference_capture_not_bts_acceptance' ||
        profile.status !== 'captured' || profile.taskId !== id || !record(profile.environment) ||
        (id === 'S4' ? !record(profile.taskPath) : !record(profile.actions)) ||
        !jsonEqual(actionKeys.sort(), [...expectedActions[id]].sort()) ||
        !jsonEqual(snapshotKeys.sort(), [...expectedSnapshots[id]].sort())) {
      blockers.push(`native_reference_task_schema_mismatch:${id}`);
      continue;
    }
    try {
      const taskRef = ref(artifact, `native_reference_task_artifact_reference_invalid:${id}`);
      refs.push(taskRef);
      primitives.push({ taskId: id, refs: [taskRef] });
    } catch { blockers.push(`native_reference_task_artifact_reference_invalid:${id}`); }
  }
  const innerSourceBlock = record(capture.sourceBlock);
  const outerSourceBlock = record(probe.sourceBlock);
  if (!innerSourceBlock || !outerSourceBlock || !jsonEqual(innerSourceBlock, outerSourceBlock)) blockers.push('native_reference_source_block_mismatch');
  validateObservations(probe.observations, blockers, 'native_reference');
  return { successful, primitives, refs };
}

function inspectH3Reference(probe: JsonRecord, blockers: string[]): Inspection {
  const expectedKeys = ['schemaVersion', 'classification', 'status', 'releaseReadiness', 'taskId', 'manifest', 'environment',
    'applicationSourceSha256', 'probeSourceSha256', 'sourceBlock', 'caseArtifact', 'generationFence', 'capture',
    'observations', 'artifacts', 'noReleaseActivation', 'noGradePosted'];
  const capture = record(probe.capture);
  const successful = probe.status === 'captured';
  if (!exactKeys(probe, expectedKeys) || probe.schemaVersion !== 'bts-task-h3-capture/v1' ||
      probe.classification !== CAPTURE_CLASSIFICATION || probe.releaseReadiness !== 'blocked' || probe.taskId !== 'H3' ||
      probe.noReleaseActivation !== true || probe.noGradePosted !== true || !capture ||
      capture.schemaVersion !== 'bts-h3-paid-route-swap-foundation/v1' ||
      capture.classification !== 'local_fork_public_tool_reference_not_bts_acceptance' || capture.status !== 'captured' ||
      typeof capture.noAcceptanceClaim !== 'string' || capture.noAcceptanceClaim.length === 0) {
    blockers.push('h3_reference_schema_mismatch');
  }
  if (!successful) blockers.push('capture_not_successful:h3_reference');
  const refs: ArtifactReference[] = [];
  const primitives: Inspection['primitives'] = [];
  try {
    const topRef = ref(probe.caseArtifact, 'h3_case_artifact_reference_invalid');
    refs.push(topRef);
    if (!capture) return { successful: false, primitives, refs };
    const nestedRef = ref(capture.artifact, 'h3_capture_artifact_reference_invalid');
    if (!jsonEqual(topRef, nestedRef)) blockers.push('h3_case_artifact_reference_mismatch');
    refs.push(nestedRef);
    if (!Array.isArray(capture.rawArtifacts)) blockers.push('h3_raw_artifact_inventory_invalid');
    else {
      for (const item of capture.rawArtifacts) {
        try { refs.push(ref(item, 'h3_capture_raw_artifact_invalid')); }
        catch { blockers.push('h3_capture_raw_artifact_invalid'); }
      }
    }
    const fence = record(probe.generationFence);
    const fenceRow = record(fence?.databaseGeneration);
    if (!fence || fence.status !== 'fenced' || fence.signerErased !== true || !fenceRow || fenceRow.status !== 'fenced') {
      blockers.push('h3_generation_fence_missing');
    }
    if (successful) primitives.push({ taskId: 'H3', refs: [topRef] });
  } catch (error) {
    blockers.push(error instanceof InventoryError ? error.code : 'h3_case_artifact_reference_invalid');
  }
  validateObservations(probe.observations, blockers, 'h3_reference');
  return { successful, primitives, refs };
}

function inspectU1Reference(probe: JsonRecord, blockers: string[]): Inspection {
  const required = ['schemaVersion', 'classification', 'status', 'releaseReadiness', 'taskId', 'manifest', 'environment',
    'applicationSourceSha256', 'probeSourceSha256', 'sourceBlock', 'capture', 'generationFence', 'observations', 'artifacts',
    'noReleaseActivation', 'noGradePosted'];
  const allowed = new Set([...required, 'phase', 'errorCode', 'missingPrerequisites']);
  const successful = probe.status === 'captured';
  const capture = record(probe.capture);
  if (!hasKeys(probe, required) || Object.keys(probe).some((key) => !allowed.has(key)) ||
      probe.schemaVersion !== 'bts-task-u1-capture/v1' || probe.classification !== CAPTURE_CLASSIFICATION ||
      probe.releaseReadiness !== 'blocked' || probe.taskId !== 'U1' || probe.noReleaseActivation !== true || probe.noGradePosted !== true) {
    blockers.push('u1_reference_schema_mismatch');
  }
  if (!successful) blockers.push('capture_not_successful:u1_reference');
  const refs: ArtifactReference[] = [];
  const primitives: Inspection['primitives'] = [];
  if (capture && successful) {
    if (capture.schemaVersion !== 'bts-task-u1-same-generation-reference/v1' ||
        capture.classification !== 'local_fork_public_tool_reference_not_bts_acceptance' || capture.status !== 'captured' ||
        capture.taskId !== 'U1' || capture.releaseReadiness !== 'blocked' ||
        capture.noReleaseActivation !== true || capture.noGradePosted !== true ||
        !record(capture.initialState) || !record(capture.finalCutoff) || record(capture.finalCutoff)?.allocationWithinTarget !== true ||
        !Array.isArray(capture.dataComponents) || !Array.isArray(capture.obligations) || capture.obligations.length < 2 ||
        !record(capture.actions) || !record(capture.observedExpense)) blockers.push('u1_reference_case_schema_mismatch');
    try {
      const taskRef = ref(capture.artifact, 'u1_case_artifact_reference_invalid');
      refs.push(taskRef);
      const fence = record(probe.generationFence);
      const fenceRow = record(fence?.databaseGeneration);
      if (!fence || fence.status !== 'fenced' || fence.signerErased !== true || !fenceRow || fenceRow.status !== 'fenced') {
        blockers.push('u1_generation_fence_missing');
      }
      primitives.push({ taskId: 'U1', refs: [taskRef] });
    } catch (error) { blockers.push(error instanceof InventoryError ? error.code : 'u1_case_artifact_reference_invalid'); }
  }
  validateObservations(probe.observations, blockers, 'u1_reference');
  return { successful, primitives, refs };
}

function probeArtifactReference(probe: JsonRecord, path: unknown, code: string): ArtifactReference | null {
  if (typeof path !== 'string' || !Array.isArray(probe.artifacts)) return null;
  const item = probe.artifacts.map(record).find((entry) => entry?.path === path);
  if (!item) return null;
  try { return ref(item, code); }
  catch { return null; }
}

function trainingCaseValid(taskId: CapturedTrainingTaskId, value: JsonRecord): boolean {
  const capture = record(value.capture);
  if (!capture || capture.status !== (taskId === 'H2' ? 'observed_candidate' : 'captured')) return false;
  switch (taskId) {
    case 'S1':
      return capture.schemaVersion === 'bts-transfer-probe/v1' &&
        record(capture.action)?.amountUnits === '200000' &&
        record(capture.before)?.payerUsdcUnits === '100000000' && record(capture.before)?.recipientUsdcUnits === '0' &&
        record(capture.after)?.payerUsdcUnits === '99800000' && record(capture.after)?.recipientUsdcUnits === '200000' &&
        record(capture.operation)?.status === 'settled' && record(capture.receipt)?.status === '0x1';
    case 'S2': {
      const offer = record(capture.offer);
      const candidate = record(capture.objectiveCandidate);
      const requirements = record(candidate?.completePaymentRequirements);
      const interval = record(capture.noEffectInterval);
      const before = record(interval?.stateBefore);
      const after = record(interval?.stateAfter);
      return capture.schemaVersion === 'bts-s2-offer-reference/v1' &&
        offer?.resourceId === 'bef-market-state-brief-v1' && record(offer.payment)?.amount === '125000' &&
        candidate?.resourceId === 'bef-market-state-brief-v1' && candidate.offerId === 'market-brief-standard' &&
        requirements?.amountUnits === '125000' && requirements.offerId === 'market-brief-standard' &&
        before?.payerUsdcUnits === '100000000' && before.payerUsdcUnits === after?.payerUsdcUnits &&
        before.payerNativeEthWei === after?.payerNativeEthWei && before.usdcRouterAllowanceUnits === after?.usdcRouterAllowanceUnits &&
        before.wethRouterAllowanceUnits === after?.wethRouterAllowanceUnits;
    }
    case 'S4': {
      const nested = record(record(capture.captures)?.S4);
      const setup = record(nested?.fixtureSetup);
      const candidate = record(nested?.objectiveCandidate);
      const path = record(nested?.taskPath);
      const snapshots = record(nested?.snapshots);
      return capture.schemaVersion === 'bts-native-task-reference/v1' && record(capture.captures) !== null &&
        record(capture.captureArtifacts)?.S4 !== undefined && nested?.schemaVersion === 'bts-s4-allowance-revocation-reference/v1' &&
        nested.status === 'captured' && setup?.initialAllowanceUnits === '0' && setup.positiveAllowanceUnits === '20000' &&
        candidate?.taskStartAllowanceUnits === '20000' && candidate.requiredFinalAllowanceUnits === '0' &&
        path?.finalAllowanceUnits === '0' && record(snapshots?.beforeSetup)?.usdcAllowanceUnits === '0' &&
        record(snapshots?.taskStartAfterSetup)?.usdcAllowanceUnits === '20000' &&
        record(snapshots?.finalAfterRevoke)?.usdcAllowanceUnits === '0';
    }
    case 'M1': {
      const payment = record(capture.paymentRequirements);
      const delivery = record(capture.delivery);
      return capture.schemaVersion === 'bts-m1-single-purchase-reference/v1' &&
        capture.resourceId === 'bef-resource-v1' && capture.offerId === 'canonical' &&
        payment?.amountUnits === '100000' && payment.resourceId === 'bef-resource-v1' && payment.offerId === 'canonical' &&
        record(capture.objectiveCandidate)?.principalAmountUnits === '100000' &&
        typeof delivery?.rawContentPath === 'string' && isHash(delivery.rawContentSha256) &&
        typeof delivery.projectionPath === 'string' && isHash(delivery.projectionSha256);
    }
    case 'M3':
    case 'M4': {
      const candidate = record(capture.objectiveCandidate);
      const route = record(candidate?.route);
      const quote = record(candidate?.publicQuote);
      const snapshots = record(capture.snapshots);
      const before = record(snapshots?.before);
      const swap = record(record(capture.actions)?.swap);
      const isM3 = taskId === 'M3';
      const ending = record(snapshots?.[isM3 ? 'afterUnwrap' : 'afterCleanup']);
      const allowed = isM3 ? record(snapshots?.afterApproval) : record(snapshots?.afterApproval);
      const allowanceProfile = record(candidate?.requiredTemporaryAllowance);
      return capture.schemaVersion === (isM3 ? 'bts-m3-native-output-reference/v1' : 'bts-m4-exchange-cleanup-reference/v1') &&
        candidate?.exactInputUnits === '200000' && route?.feeTier === 3000 &&
        typeof route.poolAddress === 'string' && typeof route.poolCodeHash === 'string' &&
        quote?.amountInUnits === '200000' && isHashOrDecimal(quote.amountOutUnits) &&
        quote.independentQuoterV2OutputUnits === quote.amountOutUnits && quote.feeTier === 3000 &&
        quote.poolAddress === route.poolAddress && quote.poolCodeHash === route.poolCodeHash &&
        typeof quote.blockNumber === 'string' && typeof quote.blockHash === 'string' &&
        before?.payerUsdcUnits === '100000000' && before.usdcAllowanceUnits === '0' &&
        swap?.amountInUnits === '200000' && swap.amountOutMinimumUnits === quote.minimumOutputUnits &&
        record(allowed)?.usdcAllowanceUnits === (isM3 ? '200000' : '400000') &&
        ending?.payerUsdcUnits === '99800000' && ending.usdcAllowanceUnits === '0' &&
        (isM3 ? allowanceProfile === null : allowanceProfile?.approvedUnits === '400000');
    }
    case 'H1': {
      const candidate = record(capture.candidate);
      const expense = record(candidate?.observedExpense);
      const budget = record(candidate?.budgetProfile);
      const offers = capture.selectedOffers;
      return capture.schemaVersion === 'bts-h1-training-reference/v1' &&
        candidate?.taskId === 'H1' && candidate.status === 'observed_candidate' && candidate.releaseReadiness === 'blocked' &&
        candidate.candidateDoesNotClaimTaskScore === true && candidate.requiredComponentCount === 2 &&
        expense?.serviceChargesUsdcUnits === '350000' && budget?.budgetUsdcUnits === '700000' &&
        Array.isArray(offers) && offers.length === 2 &&
        jsonEqual(offers.map((entry) => {
          const offer = record(entry);
          return { resourceId: offer?.resourceId, offerId: offer?.offerId, amountUsdcUnits: offer?.amountUsdcUnits };
        }), [
          { resourceId: 'bef-resource-v1', offerId: 'canonical', amountUsdcUnits: '100000' },
          { resourceId: 'bef-market-state-brief-v1', offerId: 'market-brief-extended', amountUsdcUnits: '250000' },
        ]) && offers.every((entry) => {
          const offer = record(entry);
          return typeof offer?.contentPath === 'string' && typeof offer.projectionPath === 'string';
        });
    }
    case 'H2': {
      const obligations = capture.obligations;
      return capture.schemaVersion === 'bts-h2-observed-case-inputs/v1' && capture.taskId === 'H2' &&
        capture.releaseReadiness === 'blocked' && capture.candidateDoesNotClaimTaskScore === true &&
        Array.isArray(obligations) && jsonEqual(obligations.map((entry) => record(entry)?.amountUnits), ['200000', '300000']) &&
        record(capture.initialAssets)?.payerUsdcUnits === '100000000' &&
        record(capture.finalCutoff)?.payerUsdcUnits === '99500000';
    }
  }
}

function isHashOrDecimal(value: unknown): value is string {
  return isHash(value) || typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value);
}

function inspectTrainingReference(probe: JsonRecord, blockers: string[]): Inspection {
  const expectedKeys = ['schemaVersion', 'classification', 'status', 'phase', 'manifest', 'capture', 'applicationSourceSha256',
    'probeSourceSha256', 'sourceBlock', 'observations', 'artifacts'];
  const capture = record(probe.capture);
  const successful = probe.status === 'captured' && probe.phase === 'complete' && capture?.status === 'captured';
  if (!exactKeys(probe, expectedKeys) || probe.schemaVersion !== 'bts-open-training-profile-probe/v1' ||
      probe.classification !== 'local_fork_public_tool_evidence_not_bts_acceptance' || !successful || !capture ||
      capture.schemaVersion !== 'bts-open-training-reference-profile/v1' ||
      capture.classification !== 'local_fork_public_tool_reference_not_bts_acceptance' || capture.releaseReadiness !== 'blocked' ||
      !exactKeys(capture, ['schemaVersion', 'classification', 'cases', 'status', 'releaseReadiness', 'taskCount', 'captures'])) {
    blockers.push('training_reference_profile_schema_or_status_invalid');
  }
  if (!successful) blockers.push('capture_not_successful:training_reference');
  if (!capture || capture.taskCount !== CAPTURED_TRAINING_TASK_ORDER.length || !Array.isArray(capture.cases) ||
      !jsonEqual(capture.cases, TRAINING_CASES) || !Array.isArray(capture.captures) ||
      capture.captures.length !== CAPTURED_TRAINING_TASK_ORDER.length || !Array.isArray(probe.artifacts) || probe.artifacts.length !== 512) {
    blockers.push('training_reference_case_inventory_invalid');
    return { successful: false, primitives: [], refs: [] };
  }

  const refs: ArtifactReference[] = [];
  const primitives: Inspection['primitives'] = [];
  const observations = new Map<string, JsonRecord>();
  if (Array.isArray(probe.observations)) {
    for (const raw of probe.observations) {
      const observation = record(raw);
      if (typeof observation?.id === 'string') observations.set(observation.id, observation);
    }
  }
  const generationIds = new Set<string>();
  for (let index = 0; index < CAPTURED_TRAINING_TASK_ORDER.length; index += 1) {
    const expectedId = CAPTURED_TRAINING_TASK_ORDER[index]!;
    const row = record(capture.captures[index]);
    const generation = record(row?.generation);
    const fence = record(row?.generationFence);
    const databaseGeneration = record(fence?.databaseGeneration);
    const captureRecord = record(row?.capture);
    const generationId = generation?.generationId;
    if (!row || !exactKeys(row, ['taskId', 'generation', 'capture', 'generationFence']) || row.taskId !== expectedId ||
        typeof generationId !== 'string' || generationId.length === 0 || generationIds.has(generationId) ||
        fence?.status !== 'fenced' || fence.signerErased !== true || databaseGeneration?.status !== 'fenced' ||
        databaseGeneration.generation_id !== generationId || databaseGeneration.env_id !== generation?.envId ||
        !trainingCaseValid(expectedId, row)) {
      blockers.push(`training_reference_task_or_fence_invalid:${expectedId}`);
    }
    if (typeof generationId === 'string') generationIds.add(generationId);
    const innerEnvironment = expectedId === 'H2' ? record(captureRecord?.generation) :
      expectedId === 'S4' ? record(record(record(captureRecord?.captures)?.S4)?.environment) : record(captureRecord?.environment);
    if (!innerEnvironment || innerEnvironment.generationId !== generationId || innerEnvironment.envId !== generation?.envId) {
      blockers.push(`training_reference_generation_binding_invalid:${expectedId}`);
    }
    const taskRefs: ArtifactReference[] = [];
    for (const observationId of [...TRAINING_OBSERVATIONS[expectedId],
      `task-training-${expectedId.toLowerCase()}-generation-fence`,
      `task-training-${expectedId.toLowerCase()}-generation-after-fence-generation-by-id`]) {
      const observation = observations.get(observationId);
      const artifact = observation && probeArtifactReference(probe, observation.sourceArtifact, `training_reference_observation_invalid:${expectedId}`);
      if (!observation || !artifact) blockers.push(`training_reference_required_observation_missing:${expectedId}:${observationId}`);
      else { refs.push(artifact); taskRefs.push(artifact); }
    }
    const addPath = (path: unknown, code: string): void => {
      const artifact = probeArtifactReference(probe, path, code);
      if (!artifact) blockers.push(`${code}:${expectedId}`);
      else { refs.push(artifact); taskRefs.push(artifact); }
    };
    if (expectedId === 'S4') addPath(record(record(captureRecord?.captureArtifacts)?.S4)?.path, 'training_reference_s4_capture_artifact_missing');
    if (expectedId === 'M1') {
      const delivery = record(captureRecord?.delivery);
      addPath(delivery?.rawContentPath, 'training_reference_m1_content_artifact_missing');
      addPath(delivery?.projectionPath, 'training_reference_m1_projection_artifact_missing');
      for (const [pathKey, hashKey] of [['rawContentPath', 'rawContentSha256'], ['projectionPath', 'projectionSha256']] as const) {
        const artifact = probeArtifactReference(probe, delivery?.[pathKey], 'training_reference_m1_delivery_artifact_invalid');
        if (!artifact || artifact.sha256 !== delivery?.[hashKey]) blockers.push(`training_reference_m1_delivery_hash_mismatch:${pathKey}`);
      }
    }
    if (expectedId === 'M3' || expectedId === 'M4') addPath(record(captureRecord?.caseArtifact)?.path, `training_reference_${expectedId.toLowerCase()}_case_artifact_missing`);
    if (expectedId === 'H1') for (const offer of Array.isArray(captureRecord?.selectedOffers) ? captureRecord.selectedOffers : []) {
      const selected = record(offer);
      addPath(selected?.contentPath, 'training_reference_h1_purchase_content_missing');
      addPath(selected?.projectionPath, 'training_reference_h1_purchase_projection_missing');
    }
    if (taskRefs.length === 0) blockers.push(`training_reference_task_evidence_empty:${expectedId}`);
    primitives.push({ taskId: expectedId, refs: taskRefs });
  }
  const manifestRef = referenceFromProbe(probe, blockers);
  if (manifestRef) refs.push(manifestRef);
  validateObservations(probe.observations, blockers, 'training_reference');
  return { successful, primitives, refs };
}

function validateObservations(value: unknown, blockers: string[], prefix: string): void {
  if (!Array.isArray(value)) {
    blockers.push(`${prefix}_observation_index_invalid`);
    return;
  }
  const ids = new Set<string>();
  for (const item of value) {
    const observation = record(item);
    if (!observation || typeof observation.id !== 'string' || observation.id.length === 0 ||
        typeof observation.sourceArtifact !== 'string' || !validRelativePath(observation.sourceArtifact) || ids.has(observation.id)) {
      blockers.push(`${prefix}_observation_reference_invalid`);
      continue;
    }
    ids.add(observation.id);
  }
}

function verifyReference(refValue: ArtifactReference, inventory: Map<string, IndexedArtifact>, blockers: string[]): void {
  const indexed = inventory.get(refValue.path);
  if (!indexed || indexed.sha256 !== refValue.sha256 ||
      (refValue.boundary !== undefined && indexed.boundary !== refValue.boundary) ||
      (refValue.contentType !== undefined && indexed.contentType !== refValue.contentType)) {
    blockers.push(`raw_reference_not_in_inventory:${refValue.path}`);
  }
}

function addObservationPathChecks(probe: JsonRecord, inventory: Map<string, IndexedArtifact>, blockers: string[], kind: TaskReferenceCaptureKind): void {
  if (!Array.isArray(probe.observations)) return;
  for (const item of probe.observations) {
    const observation = record(item);
    if (typeof observation?.sourceArtifact !== 'string' || !inventory.has(observation.sourceArtifact)) {
      blockers.push(`observation_source_artifact_missing:${kind}`);
    }
  }
}

function parsedArtifact(path: string, rawBytes: Map<string, Buffer>, blockers: string[], code: string): JsonRecord | null {
  const bytes = rawBytes.get(path);
  if (!bytes) {
    blockers.push(`${code}_artifact_unavailable:${path}`);
    return null;
  }
  try { return json(bytes, `${code}_artifact_json_invalid`); }
  catch (error) { blockers.push(error instanceof InventoryError ? error.code : `${code}_artifact_json_invalid`); return null; }
}

function checkArtifactPaths(value: unknown, inventory: Map<string, IndexedArtifact>, blockers: string[], code: string): void {
  const entries = Array.isArray(value) ? value : record(value) ? [value] : null;
  if (!entries) {
    blockers.push(`${code}_path_inventory_invalid`);
    return;
  }
  for (const item of entries) {
    const entry = record(item);
    if (!entry || !exactKeys(entry, ['httpResponsePath', 'contentPath', 'projectionPath'])) {
      blockers.push(`${code}_path_reference_invalid`);
      continue;
    }
    for (const key of ['httpResponsePath', 'contentPath', 'projectionPath'] as const) {
      if (typeof entry[key] !== 'string' || !inventory.has(entry[key])) {
        blockers.push(`${code}_path_not_in_artifact_inventory:${key}`);
      }
    }
  }
}

async function verifyTypedArtifactContents(
  kind: TaskReferenceCaptureKind,
  probe: JsonRecord,
  runsRoot: string,
  inventory: Map<string, IndexedArtifact>,
  rawBytes: Map<string, Buffer>,
  rawArtifacts: VerifiedRawArtifact[],
  blockers: string[],
): Promise<void> {
  if (kind === 'training_reference') {
    const capture = record(probe.capture);
    const rows = Array.isArray(capture?.captures) ? capture.captures.map(record) : [];
    const observations = new Map<string, JsonRecord>();
    if (Array.isArray(probe.observations)) for (const item of probe.observations) {
      const observation = record(item);
      if (typeof observation?.id === 'string') observations.set(observation.id, observation);
    }
    const observedArtifact = (id: string, code: string): JsonRecord | null => {
      const observation = observations.get(id);
      if (typeof observation?.sourceArtifact !== 'string') {
        blockers.push(`${code}_observation_missing:${id}`);
        return null;
      }
      return parsedArtifact(observation.sourceArtifact, rawBytes, blockers, code);
    };
    const rpcQuantity = (id: string, expected: unknown, code: string): void => {
      const artifact = observedArtifact(id, code);
      const result = artifact?.result;
      if (typeof result !== 'string' || !/^0x[0-9a-f]+$/i.test(result) || typeof expected !== 'string') {
        blockers.push(`${code}_quantity_invalid:${id}`);
      } else if (BigInt(result).toString() !== expected) blockers.push(`${code}_quantity_mismatch:${id}`);
    };
    const nativeWrapper = (caseRef: unknown, profile: JsonRecord, taskId: string): void => {
      const artifact = record(caseRef);
      if (!artifact || typeof artifact.path !== 'string') {
        blockers.push(`training_${taskId.toLowerCase()}_derived_reference_missing`);
        return;
      }
      const wrapper = parsedArtifact(artifact.path, rawBytes, blockers, `training_${taskId.toLowerCase()}_derived_reference`);
          const expectedCapture = taskId === 'M3' || taskId === 'M4'
            ? Object.fromEntries(Object.entries(profile).filter(([key]) => key !== 'caseArtifact'))
            : profile;
          if (!wrapper || wrapper.schemaVersion !== 'bts-native-task-primitive-observation/v1' ||
          wrapper.boundary !== 'bts-reference-derived-observation' || wrapper.generationId !== record(profile.environment)?.generationId ||
          !jsonEqual(wrapper.capture, expectedCapture) || !Array.isArray(wrapper.sourceArtifacts)) {
        blockers.push(`training_${taskId.toLowerCase()}_derived_reference_binding_mismatch`);
        return;
      }
      for (const source of wrapper.sourceArtifacts) {
        try { verifyReference(ref(source, `training_${taskId.toLowerCase()}_source_reference_invalid`), inventory, blockers); }
        catch { blockers.push(`training_${taskId.toLowerCase()}_source_reference_invalid`); }
      }
    };

    for (let index = 0; index < CAPTURED_TRAINING_TASK_ORDER.length; index += 1) {
      const taskId = CAPTURED_TRAINING_TASK_ORDER[index]!;
      const row = rows[index];
      const taskCapture = record(row?.capture);
      const generation = record(row?.generation);
      const generationId = generation?.generationId;
      const envId = generation?.envId;
      if (!taskCapture || typeof generationId !== 'string' || typeof envId !== 'string') continue;

      const fenceObservation = observedArtifact(`task-training-${taskId.toLowerCase()}-generation-fence`, 'training_fence');
      const fenceBody = record(record(fenceObservation?.response)?.body);
      if (record(fenceObservation?.response)?.status !== 200 || fenceBody?.status !== 'fenced' ||
          fenceBody.generationId !== generationId || fenceBody.envId !== envId) {
        blockers.push(`training_generation_fence_evidence_mismatch:${taskId}`);
      }
      const databaseObservation = observedArtifact(`task-training-${taskId.toLowerCase()}-generation-after-fence-generation-by-id`, 'training_fenced_generation');
      const databaseRows = databaseObservation?.rows;
      const databaseRow = Array.isArray(databaseRows) && databaseRows.length === 1 ? record(databaseRows[0]) : null;
      const fence = record(row?.generationFence);
      const declaredDatabaseRow = record(fence?.databaseGeneration);
      if (!databaseRow || databaseRow.generation_id !== generationId || databaseRow.env_id !== envId || databaseRow.status !== 'fenced' ||
          !jsonEqual(databaseRow, declaredDatabaseRow)) blockers.push(`training_fenced_generation_evidence_mismatch:${taskId}`);

      switch (taskId) {
        case 'S1': {
          const captureProfile = taskCapture;
          rpcQuantity('task-transfer-before-payer-usdc', record(captureProfile.before)?.payerUsdcUnits, 'training_s1_baseline');
          break;
        }
        case 'S2': {
          const noEffect = record(taskCapture.noEffectInterval);
          rpcQuantity('task-reference-s2-state-before-payer-usdc', record(noEffect?.stateBefore)?.payerUsdcUnits, 'training_s2_baseline');
          break;
        }
        case 'S4': {
          const nestedCapture = record(record(taskCapture.captures)?.S4);
          const nested = record(nestedCapture);
          const setup = record(nested?.fixtureSetup);
          const snapshots = record(nested?.snapshots);
          rpcQuantity('task-native-s4-before-setup-payer-usdc', '100000000', 'training_s4_baseline');
          rpcQuantity('task-native-s4-before-setup-usdc-router-allowance', setup?.initialAllowanceUnits, 'training_s4_allowance_baseline');
          const artifactRef = record(record(taskCapture.captureArtifacts)?.S4);
          nativeWrapper(artifactRef, nested!, 'S4');
          break;
        }
        case 'M1': {
          rpcQuantity('task-reference-m1-payer-usdc-before', '100000000', 'training_m1_baseline');
          break;
        }
        case 'M3':
        case 'M4': {
          const taskLower = taskId.toLowerCase();
          const candidate = record(taskCapture.objectiveCandidate);
          const quote = record(candidate?.publicQuote);
          const route = record(candidate?.route);
          const snapshots = record(taskCapture.snapshots);
          rpcQuantity(`task-native-${taskLower}-before-payer-usdc`, record(snapshots?.before)?.payerUsdcUnits, `training_${taskLower}_baseline`);
          const publicObservationId = `task-native-${taskLower}-public-exact-input-quote`;
          const publicObservation = observations.get(publicObservationId);
          const publicArtifact = publicObservation && typeof publicObservation.sourceArtifact === 'string'
            ? parsedArtifact(publicObservation.sourceArtifact, rawBytes, blockers, `training_${taskLower}_public_quote`) : null;
          const requestPath = record(publicArtifact?.request)?.path;
          const response = record(publicArtifact?.response);
          const body = record(response?.body);
          const rawQuote = record(body?.quote);
          const generationHeader = record(publicArtifact?.request)?.headers && record(record(publicArtifact?.request)?.headers)?.['X-BEF-Generation'];
          if (!quote || !route || response?.status !== 200 || typeof requestPath !== 'string' ||
              !requestPath.includes('inputAssetId=USDC') || !requestPath.includes('feeTier=3000') || !requestPath.includes('amountInUnits=200000') ||
              generationHeader !== generationId || body?.generationId !== generationId || body.requestedAmountInUnits !== '200000' ||
              rawQuote?.amountInUnits !== '200000' || rawQuote.amountOutUnits !== quote.amountOutUnits ||
              rawQuote.feeTier !== quote.feeTier || rawQuote.poolAddress !== quote.poolAddress || rawQuote.poolCodeHash !== quote.poolCodeHash ||
              rawQuote.blockNumber !== quote.blockNumber || body.blockNumber !== quote.blockNumber ||
              candidate?.exactInputUnits !== '200000' || route.poolAddress !== quote.poolAddress || route.poolCodeHash !== quote.poolCodeHash) {
            blockers.push(`training_${taskLower}_public_quote_binding_mismatch`);
          }
          const blockArtifact = observedArtifact(`task-native-${taskLower}-public-quote-block-identity`, `training_${taskLower}_quote_block`);
          const blockResult = record(blockArtifact?.result);
          let blockNumberHex = '';
          try { blockNumberHex = `0x${BigInt(String(quote?.blockNumber)).toString(16)}`; } catch { /* validation below */ }
          if (!quote || blockResult?.hash !== quote.blockHash || blockArtifact?.requestedBlock !== blockNumberHex) {
            blockers.push(`training_${taskLower}_quote_block_binding_mismatch`);
          }
          const independent = observedArtifact(`task-native-${taskLower}-independent-fee3000-quote`, `training_${taskLower}_independent_quote`);
          const independentResult = independent?.result;
          const independentParams = independent?.params;
          const independentCall = Array.isArray(independentParams) ? record(independentParams[0]) : null;
          const independentBlock = Array.isArray(independentParams) ? independentParams[1] : undefined;
          const independentData = typeof independentCall?.data === 'string' ? independentCall.data.toLowerCase() : '';
          const word = (value: string): string => BigInt(value).toString(16).padStart(64, '0');
          let expectedCallData = '';
          try {
            expectedCallData = `0xc6a5026a${word('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913')}` +
              `${word('0x4200000000000000000000000000000000000006')}${word('200000')}${word('3000')}${'0'.repeat(64)}`;
          } catch { /* static quote parameters are validated below */ }
          let independentOutput: string | null = null;
          if (typeof independentResult === 'string' && /^0x[0-9a-f]{256}$/i.test(independentResult)) {
            try { independentOutput = BigInt(`0x${independentResult.slice(2, 66)}`).toString(); } catch { /* malformed ABI result */ }
          }
          if (!quote || independentOutput !== quote.independentQuoterV2OutputUnits || independentOutput !== quote.amountOutUnits ||
              independentCall?.to === undefined || independentData !== expectedCallData ||
              independentBlock !== blockNumberHex || independent?.requestedBlock !== blockNumberHex) {
            blockers.push(`training_${taskLower}_independent_quote_mismatch`);
          }
          const caseArtifact = record(taskCapture.caseArtifact);
          nativeWrapper(caseArtifact, taskCapture, taskId);
          break;
        }
        case 'H1': {
          const candidateArtifact = observedArtifact('task-training-h1-case-candidate', 'training_h1_candidate');
          const candidate = record(taskCapture.candidate);
          if (!candidateArtifact || !candidate || !jsonEqual(candidateArtifact.result, taskCapture)) {
            blockers.push('training_h1_candidate_artifact_mismatch');
          }
          rpcQuantity('task-training-h1-component-1-payer-usdc-before', '100000000', 'training_h1_component1_baseline');
          rpcQuantity('task-training-h1-component-1-payer-usdc-after', '99900000', 'training_h1_component1_final');
          rpcQuantity('task-training-h1-component-2-payer-usdc-before', '99900000', 'training_h1_component2_baseline');
          rpcQuantity('task-training-h1-component-2-payer-usdc-after', '99650000', 'training_h1_component2_final');
          break;
        }
        case 'H2': {
          const candidateArtifact = observedArtifact('task-reference-h2-case-candidate', 'training_h2_candidate');
          if (!candidateArtifact || !jsonEqual(candidateArtifact.candidate, taskCapture)) blockers.push('training_h2_candidate_artifact_mismatch');
          rpcQuantity('task-reference-h2-initial-payer-usdc', record(taskCapture.initialAssets)?.payerUsdcUnits, 'training_h2_baseline');
          break;
        }
      }
    }
    return;
  }

  if (kind === 'unified_reference') {
    const reference = record(probe.referenceIndex);
    if (!reference || typeof reference.path !== 'string') return;
    const envelope = parsedArtifact(reference.path, rawBytes, blockers, 'unified_reference_index');
    const index = record(envelope?.index);
    if (!envelope || envelope.schemaVersion !== 'bef-resource-observation/v1' || envelope.boundary !== 'actual-tool-http' ||
        !index || index.schemaVersion !== 'bts-task-reference-cases/v1' ||
        index.classification !== 'local-fork-public-tool-evidence_not_release_manifest' || index.releaseReadiness !== 'blocked' ||
        !taskArray(index.taskOrder) || !jsonEqual(index.cases, probe.taskCases) || !jsonEqual(index.captures, probe.captures) ||
        !jsonEqual(index.taskOrder, probe.taskOrder)) {
      blockers.push('unified_reference_index_schema_or_binding_mismatch');
    }
    return;
  }

  if (kind === 'native_reference') {
    const capture = record(probe.capture);
    const captures = record(capture?.captures);
    const captureArtifacts = record(capture?.captureArtifacts);
    if (!capture || !captures || !captureArtifacts) return;
    for (const id of ['S4', 'M3', 'M4'] as const) {
      const artifact = record(captureArtifacts[id]);
      const profile = record(captures[id]);
      if (!artifact || typeof artifact.path !== 'string' || !profile) continue;
      const wrapper = parsedArtifact(artifact.path, rawBytes, blockers, `native_${id.toLowerCase()}`);
      const wrapperProfile = record(wrapper?.capture);
      if (!wrapper || wrapper.schemaVersion !== 'bts-native-task-primitive-observation/v1' ||
          wrapper.classification !== 'derived_from_actual_public_tool_and_observer_evidence_not_bts_task_acceptance' ||
          wrapper.boundary !== 'bts-reference-derived-observation' || !wrapperProfile || !jsonEqual(wrapperProfile, profile)) {
        blockers.push(`native_${id.toLowerCase()}_derived_capture_binding_mismatch`);
      }
      if (!Array.isArray(wrapper?.sourceArtifacts)) {
        blockers.push(`native_${id.toLowerCase()}_source_artifact_refs_missing`);
        continue;
      }
      for (const item of wrapper.sourceArtifacts) {
        try { verifyReference(ref(item, `native_${id.toLowerCase()}_source_artifact_ref_invalid`), inventory, blockers); }
        catch { blockers.push(`native_${id.toLowerCase()}_source_artifact_ref_invalid`); }
      }
    }
    return;
  }

  if (kind === 'h3_reference') {
    const caseReference = record(probe.caseArtifact);
    const capture = record(probe.capture);
    if (!caseReference || typeof caseReference.path !== 'string' || !capture) return;
    const body = parsedArtifact(caseReference.path, rawBytes, blockers, 'h3_case');
    const mirroredKeys = ['schemaVersion', 'classification', 'status', 'environment', 'paidReference', 'trade', 'localExpenseProfile', 'noAcceptanceClaim'];
    if (!body || body.boundary !== 'actual-tool-http-and-readonly-observer' ||
        !mirroredKeys.every((key) => jsonEqual(body[key], capture[key])) || body.envId !== record(probe.environment)?.envId ||
        body.generationId !== record(probe.environment)?.generationId) blockers.push('h3_case_artifact_content_mismatch');
    checkArtifactPaths(record(capture.paidReference)?.artifacts, inventory, blockers, 'h3_paid_reference');
    return;
  }

  const capture = record(probe.capture);
  if (probe.status !== 'captured' || !capture) return;
  const caseReference = record(capture.artifact);
  if (!caseReference || typeof caseReference.path !== 'string') return;
  const body = parsedArtifact(caseReference.path, rawBytes, blockers, 'u1_case');
  const mirroredKeys = ['schemaVersion', 'classification', 'status', 'taskId', 'releaseReadiness', 'environment', 'sourceBlock',
    'preExecutionPlan', 'currentQuote', 'dataComponents', 'obligations', 'initialState', 'actions', 'finalCutoff',
    'observedExpense', 'generationDatabase', 'h1ComponentSubcheck', 'noReleaseActivation', 'noGradePosted', 'acceptanceBoundary', 'elapsedMs'];
  if (!body || body.boundary !== 'actual-tool-http-local-chain-readonly-and-readonly-database' ||
      !mirroredKeys.every((key) => jsonEqual(body[key], capture[key])) || body.envId !== record(capture.environment)?.envId ||
      body.generationId !== record(capture.environment)?.generationId) blockers.push('u1_case_artifact_content_mismatch');

  const preExecutionPlan = record(capture.preExecutionPlan);
  const currentQuote = record(capture.currentQuote);
  if (!preExecutionPlan || !currentQuote || typeof currentQuote.artifact !== 'string' || !inventory.has(currentQuote.artifact)) {
    blockers.push('u1_quote_or_plan_reference_missing');
  }
  const externalReferences = [
    { path: preExecutionPlan?.planPath, sha256: preExecutionPlan?.planSha256 },
    { path: preExecutionPlan?.quotePath, sha256: preExecutionPlan?.quoteSha256 },
  ];
  for (const external of externalReferences) {
    const externalSha = external.sha256;
    if (typeof external.path !== 'string' || !external.path.startsWith('artifacts/runs/') || !isHash(externalSha)) {
      blockers.push('u1_pre_execution_reference_invalid');
      continue;
    }
    const relativePath = external.path.slice('artifacts/runs/'.length);
    if (!validRelativePath(relativePath)) {
      blockers.push('u1_pre_execution_path_invalid');
      continue;
    }
    if (!Array.from(inventory.values()).some((artifact) => artifact.sha256 === externalSha.toLowerCase())) {
      blockers.push(`u1_pre_execution_copy_hash_mismatch:${relativePath}`);
      continue;
    }
    try {
      const loaded = await containedFile(runsRoot, relativePath);
      const digest = sha256(loaded.bytes).toLowerCase();
      if (digest !== externalSha.toLowerCase()) blockers.push(`u1_pre_execution_hash_mismatch:${relativePath}`);
      else rawArtifacts.push({ scope: 'runs_root', path: relativePath, sha256: digest, boundary: 'u1-preflight-reference',
        contentType: 'application/json', status: 'verified' });
    } catch (error) {
      const code = error instanceof InventoryError ? error.code : 'artifact_file_unavailable';
      blockers.push(`${code}:runs_root/${relativePath}`);
      rawArtifacts.push({ scope: 'runs_root', path: relativePath, sha256: externalSha.toLowerCase(), boundary: 'u1-preflight-reference',
        contentType: 'application/json', status: 'blocked', blocker: `${code}:runs_root/${relativePath}` });
    }
  }
  const actions = record(capture.actions);
  if (!Array.isArray(actions?.purchases)) blockers.push('u1_purchase_path_inventory_invalid');
  else for (const purchase of actions.purchases) checkArtifactPaths(record(purchase)?.artifacts, inventory, blockers, 'u1_purchase');
}

async function containedFile(root: string, relativePath: string): Promise<{ bytes: Buffer; realPath: string }> {
  if (!validRelativePath(relativePath)) return fail('artifact_path_invalid');
  const candidate = resolve(root, ...relativePath.split('/'));
  if (!isContained(root, candidate)) return fail('artifact_path_escape');
  let actual: string;
  try { actual = await realpath(candidate); }
  catch { return fail('artifact_file_missing'); }
  if (!isContained(root, actual)) return fail('artifact_symlink_escape');
  let info;
  try { info = await stat(actual); }
  catch { return fail('artifact_file_missing'); }
  if (!info.isFile()) return fail('artifact_not_regular_file');
  try { return { bytes: await readFile(actual), realPath: actual }; }
  catch { return fail('artifact_file_unreadable'); }
}

async function containedDirectory(root: string, relativeDirectory: string): Promise<string> {
  if (!validRelativePath(relativeDirectory)) return fail('capture_directory_path_invalid');
  const candidate = resolve(root, ...relativeDirectory.split('/'));
  if (!isContained(root, candidate)) return fail('capture_directory_path_escape');
  let actual: string;
  try { actual = await realpath(candidate); }
  catch { return fail('capture_directory_missing'); }
  if (!isContained(root, actual)) return fail('capture_directory_symlink_escape');
  let info;
  try { info = await stat(actual); }
  catch { return fail('capture_directory_missing'); }
  if (!info.isDirectory()) return fail('capture_directory_not_directory');
  return actual;
}

function profileInspection(kind: TaskReferenceCaptureKind, probe: JsonRecord, blockers: string[]): Inspection {
  switch (kind) {
    case 'unified_reference': return inspectUnifiedReference(probe, blockers);
    case 'native_reference': return inspectNativeReference(probe, blockers);
    case 'h3_reference': return inspectH3Reference(probe, blockers);
    case 'u1_reference': return inspectU1Reference(probe, blockers);
    case 'training_reference': return inspectTrainingReference(probe, blockers);
  }
}

function blockCapture(source: Partial<TaskReferenceCaptureSource>, code: string): TaskCaptureVerification {
  const kind = (source.kind ?? 'unified_reference') as TaskReferenceCaptureKind;
  return {
    kind,
    evidenceMode: kind === 'training_reference' ? 'training_reference' : 'reference',
    relativeDirectory: typeof source.relativeDirectory === 'string' ? source.relativeDirectory : '',
    status: 'blocked', compatibleWithInventoryPins: false, probeSha256: null, pin: null,
    rawArtifactCount: 0, rawArtifacts: [], primitives: [], blockers: [code],
  };
}

async function verifyOneCapture(runsRoot: string, source: TaskReferenceCaptureSource): Promise<TaskCaptureVerification> {
  const blockers: string[] = [];
  if (!HASH.test(source.expectedProbeSha256)) return blockCapture(source, 'probe_sha256_invalid');
  let directory: string;
  try { directory = await containedDirectory(runsRoot, source.relativeDirectory); }
  catch (error) { return blockCapture(source, error instanceof InventoryError ? error.code : 'capture_directory_unavailable'); }
  let probeBytes: Buffer;
  try { probeBytes = (await containedFile(directory, 'probe.json')).bytes; }
  catch (error) { return blockCapture(source, error instanceof InventoryError ? error.code.replace('artifact_', 'probe_') : 'probe_unavailable'); }
  const probeSha = sha256(probeBytes);
  if (probeSha.toLowerCase() !== source.expectedProbeSha256.toLowerCase()) return blockCapture(source, 'probe_sha256_mismatch');
  let probe: JsonRecord;
  try { probe = json(probeBytes, 'probe_json_invalid'); }
  catch (error) { return blockCapture(source, error instanceof InventoryError ? error.code : 'probe_json_invalid'); }

  const typeBlockers: string[] = [];
  const inspection = profileInspection(source.kind, probe, typeBlockers);
  blockers.push(...typeBlockers);
  let indexed: IndexedArtifact[];
  try { indexed = artifactInventory(probe.artifacts); }
  catch (error) {
    const code = error instanceof InventoryError ? error.code : 'artifact_inventory_invalid';
    return { ...blockCapture(source, code), probeSha256: probeSha, blockers: [...new Set([...blockers, code])] };
  }
  const artifacts = new Map(indexed.map((entry) => [entry.path, entry]));
  const rawArtifacts: VerifiedRawArtifact[] = [];
  const rawBytes = new Map<string, Buffer>();
  for (const artifact of indexed) {
    try {
      const read = await containedFile(directory, artifact.path);
      if (sha256(read.bytes).toLowerCase() !== artifact.sha256) {
        rawArtifacts.push({ scope: 'capture', ...artifact, status: 'blocked', blocker: `artifact_hash_mismatch:${artifact.path}` });
        blockers.push(`artifact_hash_mismatch:${artifact.path}`);
      } else {
        rawArtifacts.push({ scope: 'capture', ...artifact, status: 'verified' });
        rawBytes.set(artifact.path, read.bytes);
      }
    } catch (error) {
      const code = error instanceof InventoryError ? error.code : 'artifact_file_unavailable';
      rawArtifacts.push({ scope: 'capture', ...artifact, status: 'blocked', blocker: `${code}:${artifact.path}` });
      blockers.push(`${code}:${artifact.path}`);
    }
  }
  for (const declared of inspection.refs) verifyReference(declared, artifacts, blockers);
  addObservationPathChecks(probe, artifacts, blockers, source.kind);
  await verifyTypedArtifactContents(source.kind, probe, runsRoot, artifacts, rawBytes, rawArtifacts, blockers);

  const manifestReference = referenceFromProbe(probe, blockers);
  let pin: CapturePin | null = null;
  if (manifestReference) {
    const indexedManifest = artifacts.get(manifestReference.path);
    if (!indexedManifest || indexedManifest.sha256 !== manifestReference.sha256 || indexedManifest.boundary !== 'runtime-manifest') {
      blockers.push('manifest_artifact_binding_mismatch');
    } else {
      const bytes = rawBytes.get(manifestReference.path);
      if (!bytes) blockers.push('raw_manifest_unavailable');
      else {
        let manifest: JsonRecord;
        try { manifest = json(bytes, 'raw_manifest_json_invalid'); }
        catch (error) { blockers.push(error instanceof InventoryError ? error.code : 'raw_manifest_json_invalid'); manifest = {}; }
        pin = commonProfilePin(probe, manifestReference, manifest, blockers);
        if (pin) {
          const environment = record(probe.environment);
          if (environment && environment.chainId !== undefined && environment.chainId !== 8453) blockers.push('capture_environment_chain_mismatch');
          const manifestLocal = record(manifest.local);
          const environments = Array.isArray(manifestLocal?.environments) ? manifestLocal.environments.map(record) : [];
          if (environment && typeof environment.envId === 'string' && environments.length > 0 &&
              !environments.some((candidate) => candidate?.id === environment.envId)) blockers.push('capture_environment_not_in_manifest');
        }
      }
    }
  }
  const uniqueBlockers = [...new Set(blockers)];
  const evidenceMode = source.kind === 'training_reference' ? 'training_reference' : 'reference';
  const primitives: VerifiedPrimitive[] = uniqueBlockers.length === 0 && inspection.successful
    ? inspection.primitives.map((primitive) => ({
        taskId: primitive.taskId, captureKind: source.kind, evidenceMode, relativeDirectory: source.relativeDirectory,
        status: 'raw_verified_primitive', classification: PRIMITIVE_CLASSIFICATION, releaseReadiness: 'blocked',
        artifactReferences: primitive.refs.map((entry) => ({ path: entry.path, sha256: entry.sha256, boundary: entry.boundary ?? artifacts.get(entry.path)?.boundary ?? 'unclassified' })),
      }))
    : [];
  return {
    kind: source.kind,
    evidenceMode,
    relativeDirectory: source.relativeDirectory,
    status: uniqueBlockers.length === 0 && inspection.successful ? 'verified_primitives' : 'blocked',
    compatibleWithInventoryPins: uniqueBlockers.length === 0 && inspection.successful,
    probeSha256: probeSha,
    pin,
    rawArtifactCount: rawArtifacts.length,
    rawArtifacts,
    primitives,
    blockers: uniqueBlockers,
  };
}

function inventoryInput(value: unknown): value is TaskReferenceInventoryInput {
  const input = record(value);
  if (!input || !exactKeys(input, ['runsRoot', 'captures']) || typeof input.runsRoot !== 'string' || !isAbsolute(input.runsRoot) ||
      !Array.isArray(input.captures) || input.captures.length === 0) return false;
  return input.captures.every((item) => {
    const source = record(item);
    return source !== null && exactKeys(source, ['kind', 'relativeDirectory', 'expectedProbeSha256']) &&
      ['unified_reference', 'native_reference', 'h3_reference', 'u1_reference', 'training_reference'].includes(String(source.kind)) &&
      typeof source.relativeDirectory === 'string' && typeof source.expectedProbeSha256 === 'string';
  });
}

/**
 * Hash-verifies the four supported local capture profiles. Results are raw primitive inventories only:
 * they do not validate a BTS release, authorize activation, approve difficulty, or produce grades.
 */
export async function verifyTaskCaptureInventory(inputValue: unknown): Promise<TaskReferenceInventoryResult> {
  const claims = { taskAcceptance: false as const, taskGrade: false as const, validatedRelease: false as const,
    difficultyApproval: false as const, releaseActivation: false as const };
  if (!inventoryInput(inputValue)) {
    return { schemaVersion: 'bts-verified-task-reference-inventory/v1', classification: PRIMITIVE_CLASSIFICATION,
      status: 'blocked', pins: null, captures: [], taskCoverage: TASK_ORDER.map((id) => ({ taskId: id, status: 'not_observed', primitives: [] })),
      blockers: ['inventory_input_invalid'], claims };
  }
  const input = inputValue;
  let runsRoot: string;
  try { runsRoot = await realpath(input.runsRoot); }
  catch { return { schemaVersion: 'bts-verified-task-reference-inventory/v1', classification: PRIMITIVE_CLASSIFICATION,
    status: 'blocked', pins: null, captures: [], taskCoverage: TASK_ORDER.map((id) => ({ taskId: id, status: 'not_observed', primitives: [] })),
    blockers: ['runs_root_unavailable'], claims }; }
  try { if (!(await stat(runsRoot)).isDirectory()) throw new Error(); }
  catch { return { schemaVersion: 'bts-verified-task-reference-inventory/v1', classification: PRIMITIVE_CLASSIFICATION,
    status: 'blocked', pins: null, captures: [], taskCoverage: TASK_ORDER.map((id) => ({ taskId: id, status: 'not_observed', primitives: [] })),
    blockers: ['runs_root_not_directory'], claims }; }

  const seenSource = new Set<string>();
  const captures: TaskCaptureVerification[] = [];
  for (const source of input.captures) {
    const sourceKey = `${source.kind}\0${source.relativeDirectory}`;
    if (seenSource.has(sourceKey)) {
      captures.push(blockCapture(source, 'duplicate_capture_source'));
      continue;
    }
    seenSource.add(sourceKey);
    captures.push(await verifyOneCapture(runsRoot, source));
  }

  const inventoryBlockers: string[] = [];
  const pinnedCaptures = captures.filter((capture) => capture.status === 'verified_primitives' && capture.pin !== null);
  const baseline = pinnedCaptures[0]?.pin ?? null;
  for (const capture of pinnedCaptures) {
    if (!baseline || !capture.pin) continue;
    const mismatches: string[] = [];
    if (capture.pin.manifestSha256 !== baseline.manifestSha256) mismatches.push('cross_capture_manifest_mismatch');
    if (capture.pin.applicationSourceSha256 !== baseline.applicationSourceSha256) mismatches.push('cross_capture_application_source_mismatch');
    if (!capture.pin.sourceBlock || !baseline.sourceBlock || !jsonEqual(capture.pin.sourceBlock, baseline.sourceBlock)) mismatches.push('cross_capture_source_block_mismatch');
    if (mismatches.length) {
      capture.compatibleWithInventoryPins = false;
      capture.blockers.push(...mismatches);
      inventoryBlockers.push(...mismatches);
    }
  }
  const coverage = new Map<BtsTaskId, TaskCoverage['primitives']>(TASK_ORDER.map((id) => [id, []]));
  for (const capture of captures) {
    if (capture.status !== 'verified_primitives' || !capture.compatibleWithInventoryPins) continue;
    for (const primitive of capture.primitives) {
      coverage.get(primitive.taskId)!.push({ captureKind: capture.kind, evidenceMode: primitive.evidenceMode, relativeDirectory: capture.relativeDirectory,
        artifactCount: primitive.artifactReferences.length });
    }
  }
  const taskCoverage: TaskCoverage[] = TASK_ORDER.map((id) => {
    const sources = coverage.get(id)!;
    const hadBlockedAttempt = captures.some((capture) => (capture.status === 'blocked' || !capture.compatibleWithInventoryPins) &&
      (capture.kind === 'u1_reference' && id === 'U1' || capture.kind === 'h3_reference' && id === 'H3' ||
       capture.kind === 'native_reference' && ['S4', 'M3', 'M4'].includes(id) ||
       capture.kind === 'training_reference' && (CAPTURED_TRAINING_TASK_ORDER as readonly string[]).includes(id) ||
       capture.kind === 'unified_reference'));
    return { taskId: id, status: sources.length > 0 ? 'observed_primitive' : hadBlockedAttempt ? 'blocked' : 'not_observed', primitives: sources };
  });
  const blockers = [...new Set([...captures.flatMap((capture) => capture.blockers), ...inventoryBlockers])];
  const pins = baseline ? structuredClone(baseline) : null;
  return {
    schemaVersion: 'bts-verified-task-reference-inventory/v1', classification: PRIMITIVE_CLASSIFICATION,
    status: blockers.length === 0 ? 'verified' : 'blocked', pins, captures, taskCoverage, blockers, claims,
  };
}
