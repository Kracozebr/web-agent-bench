/** Strict, offline source refresh. Historical artifacts and semantic task data remain immutable. */
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { TaskCaseSchema, canonicalTaskJson, sha256CanonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';
import { CURRENT_TRAINING_TASK_IDS, TASK_IDS } from '../../packages/owner-identity/src/task-catalog.ts';
import { executionIdentityFromManifest, schemaLineage } from '../../packages/owner-identity/src/task-case-assembler.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';
import { verifyTaskReferenceEvidenceV2 } from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';
import { sourceDigests } from '../../packages/benchmark-environment/src/probe/environment.ts';

export const APPROVED_REFRESH_BASELINE = Object.freeze({
  path: 'artifacts/runs/bts-difficulty-v2-case-candidates/0b68e103-c296-45f9-a97a-b6b8f14a44e5/candidate-cases.json',
  sha256: '4c66c32fb00de697b46317ad6a90dd0e0ed5b63812f9545a0fc5b03d94fc5356',
});
export const REFRESH_BOUNDARY = 'actual_tool_http_x402_local_evm_application_store';
export const REFRESH_POLICY_PATH = 'infrastructure/owner-identity/task-release-local-policy.json';
export const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
export function demand(value, code) { if (!value) throw new Error(code); }
const HASH = /^[0-9a-f]{64}$/;
const equal = (a, b) => canonicalTaskJson(a) === canonicalTaskJson(b);
const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
export function currentCaseKeys() {
  return [...TASK_IDS.map((id) => `${id}:ranked`), ...CURRENT_TRAINING_TASK_IDS.map((id) => `${id}:training`)].sort();
}
export function safeRelative(path) {
  return typeof path === 'string' && path.length > 0 && path.length <= 512 && /^[A-Za-z0-9_./-]+$/.test(path)
    && !isAbsolute(path) && path.split('/').every((part) => part && part !== '.' && part !== '..');
}
export function artifactPin(ref) {
  demand(keys(ref, ['path', 'sha256']) && safeRelative(ref.path) && ref.path.startsWith('artifacts/runs/')
    && ref.path.endsWith('.json') && HASH.test(ref.sha256), 'refresh_artifact_reference_invalid');
  return ref;
}
export async function readPinned(root, path, expectedHash = null, parse = true) {
  demand(safeRelative(path) && (expectedHash === null || HASH.test(expectedHash)), 'refresh_path_or_hash_invalid');
  const actualRoot = await realpath(root), actual = await realpath(resolve(actualRoot, path));
  const rel = relative(actualRoot, actual);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'refresh_path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= 8 * 1024 * 1024, 'refresh_file_invalid');
    const bytes = await handle.readFile(), after = await handle.stat();
    demand(bytes.length === before.size && before.size === after.size && before.mtimeMs === after.mtimeMs
      && before.ctimeMs === after.ctimeMs, 'refresh_file_changed');
    const hash = sha(bytes);
    demand(expectedHash === null || hash === expectedHash, 'refresh_input_hash_mismatch');
    return { bytes, sha256: hash, value: parse ? JSON.parse(bytes.toString('utf8')) : null };
  } finally { await handle.close(); }
}
export function parseRefreshProfile(value) {
  demand(keys(value, ['schemaVersion', 'classification', 'reason', 'approvedBaseline', 'feasibilityVerification',
    'rawIntegrity', 'expectedApplicationSourceSha256', 'expectedProbeSourceSha256', 'expectedManifestSha256']),
  'refresh_profile_fields_invalid');
  demand(value.schemaVersion === 'bts-source-refresh-profile/v1'
    && value.classification === 'explicit_new_source_profile_not_release_acceptance'
    && value.reason === 'ber_diagnostic_source_refresh'
    && equal(artifactPin(value.approvedBaseline), APPROVED_REFRESH_BASELINE)
    && HASH.test(value.expectedApplicationSourceSha256) && HASH.test(value.expectedProbeSourceSha256)
    && HASH.test(value.expectedManifestSha256), 'refresh_profile_contract_invalid');
  artifactPin(value.feasibilityVerification); artifactPin(value.rawIntegrity);
  return value;
}

// AICODE-NOTE: These six exact paths are the entire exclusion list. No recursive key pruning:
// objective fields named "evidence", prices, state, final-state hash and action counts stay exact.
export function semanticCaseCore(raw) {
  const taskCase = TaskCaseSchema.parse(raw), { caseHash, ...unhashed } = taskCase;
  demand(sha256CanonicalTaskJson(unhashed) === caseHash, 'refresh_case_hash_invalid');
  const result = structuredClone(taskCase);
  delete result.caseHash;
  delete result.executionIdentityHash;
  delete result.initialStateEvidence.path;
  delete result.initialStateEvidence.sha256;
  delete result.referencePath.evidence.path;
  delete result.referencePath.evidence.sha256;
  return result;
}
export function assertSemanticCasePreserved(candidate, approved) {
  demand(equal(semanticCaseCore(candidate), semanticCaseCore(approved)), 'refresh_semantic_case_changed');
}
export function assertIdentityPreserved(identity, approved) {
  const left = structuredClone(identity), right = structuredClone(approved);
  delete left.x402ServiceSha256; delete right.x402ServiceSha256;
  delete left.applicationSchemaVersion; delete right.applicationSchemaVersion;
  demand(equal(left, right), 'refresh_non_source_execution_identity_changed');
}
export function assertMigrationInventoryPreserved(current, approvedSourceInputs) {
  const approved = approvedSourceInputs.filter((r) => /^infrastructure\/benchmark-environment\/migrations\/[0-9]{3}_[a-z0-9_]+\.sql$/.test(r.path));
  const sorted = (rows) => [...rows].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  demand(approved.length > 0 && equal(sorted(current), sorted(approved)), 'refresh_migrations_changed');
}
export function assertUniformCaptureSources(captures, profile) {
  demand(Array.isArray(captures) && captures.length === currentCaseKeys().length, 'refresh_fifteen_captures_required');
  const seen = new Set();
  for (const row of captures) {
    const key = `${row.taskId}:${row.mode}`;
    demand(currentCaseKeys().includes(key) && !seen.has(key), 'refresh_case_inventory_invalid'); seen.add(key);
    demand(row.applicationSourceSha256 === profile.expectedApplicationSourceSha256
      && row.probeSourceSha256 === profile.expectedProbeSourceSha256
      && row.manifestSha256 === profile.expectedManifestSha256, 'refresh_mixed_or_old_capture_source');
    artifactPin(row.probe);
  }
}

export async function loadSourceRefreshProfile(root, ref) {
  artifactPin(ref);
  const profile = parseRefreshProfile((await readPinned(root, ref.path, ref.sha256)).value);
  const baseline = (await readPinned(root, profile.approvedBaseline.path, profile.approvedBaseline.sha256)).value;
  demand(equal(baseline.cases.map((c) => `${c.taskId}:${c.mode}`).sort(), currentCaseKeys())
    && baseline.executionIdentity.environmentManifestSha256 === profile.expectedManifestSha256
    && baseline.executionIdentity.x402ServiceSha256 !== profile.expectedApplicationSourceSha256,
  'refresh_approved_baseline_identity_invalid');
  const digests = await sourceDigests(root);
  demand(digests.appSourceSha256 === profile.expectedApplicationSourceSha256
    && digests.probeSourceSha256 === profile.expectedProbeSourceSha256, 'refresh_current_source_mismatch');
  const verification = (await readPinned(root, profile.feasibilityVerification.path, profile.feasibilityVerification.sha256)).value;
  demand(verification.schemaVersion === 'bts-runtime-feasibility-verification/v1' && verification.result?.status === 'verified'
    && verification.sourceUnchanged === true, 'refresh_feasibility_verification_invalid');
  const witnessRef = artifactPin(verification.witness);
  const witness = (await readPinned(root, witnessRef.path, witnessRef.sha256)).value;
  demand(witness.selectedPins?.expectedApplicationSourceSha256 === profile.expectedApplicationSourceSha256
    && witness.selectedPins?.expectedManifestSha256 === profile.expectedManifestSha256, 'refresh_witness_source_mismatch');
  const manifestPath = `${dirname(witnessRef.path)}/manifest.raw.json`;
  const manifest = (await readPinned(root, manifestPath, profile.expectedManifestSha256)).value;
  const policyInput = await readPinned(root, REFRESH_POLICY_PATH), policy = policyInput.value;
  const approvedPolicy = baseline.sourceInputs.find((r) => r.path === REFRESH_POLICY_PATH);
  demand(approvedPolicy?.sha256 === policyInput.sha256, 'refresh_policy_or_prices_changed');
  const lineage = await schemaLineage(root, profile.expectedApplicationSourceSha256);
  assertMigrationInventoryPreserved(lineage.migrationFiles, baseline.sourceInputs);
  const identity = executionIdentityFromManifest(manifest, profile.expectedManifestSha256,
    profile.expectedApplicationSourceSha256, policy.profileId, lineage.derivedVersion);
  assertIdentityPreserved(identity, baseline.executionIdentity);
  const identityHash = sha256CanonicalTaskJson(identity);
  demand(equal(identity, verification.executionIdentity) && identityHash === verification.executionIdentityHash,
    'refresh_derived_identity_mismatch');
  const feasibility = await verifyRetainedTaskFeasibility({ repositoryRoot: root,
    evidence: { ...witnessRef, boundary: REFRESH_BOUNDARY }, executionIdentity: identity, expectedIdentityHash: identityHash,
    profilePolicy: { path: REFRESH_POLICY_PATH, sha256: policyInput.sha256 }, participantToolProtocol: 'separate_payment_delivery_v2' });
  demand(feasibility.status === 'verified', 'refresh_independent_feasibility_not_verified');
  const integrity = (await readPinned(root, profile.rawIntegrity.path, profile.rawIntegrity.sha256)).value;
  demand(integrity.schemaVersion === 'bts-difficulty-v2-artifact-verification/v1' && integrity.status === 'verified'
    && integrity.classification === 'raw_artifact_integrity_and_trace_binding_not_semantic_task_acceptance',
  'refresh_integrity_contract_invalid');
  assertUniformCaptureSources(integrity.captures, profile);
  const retained = artifactPin(integrity.retainedInputIndex);
  const index = (await readPinned(root, retained.path, retained.sha256)).value;
  demand(index.schemaVersion === 'bts-difficulty-v2-artifact-inputs/v1'
    && equal(index.captures.map(artifactPin), integrity.captures.map((r) => r.probe)), 'refresh_raw_index_mismatch');
  const sourceInputs = [ref, profile.approvedBaseline, profile.feasibilityVerification, witnessRef,
    profile.rawIntegrity, retained, { path: manifestPath, sha256: profile.expectedManifestSha256 },
    { path: REFRESH_POLICY_PATH, sha256: policyInput.sha256 }, ...lineage.migrationFiles];
  return { profile, baseline, identity, identityHash, feasibility, integrity, witnessRef, policy, sourceInputs };
}

/** Independent validation branch: no producer boolean can substitute for fifteen raw semantic proofs. */
export async function verifySourceRefreshCandidate(root, candidate) {
  const context = await loadSourceRefreshProfile(root, candidate.sourceRefreshProfile);
  demand(candidate.sourceRefreshClassification === 'fresh_source_immutable_baseline_preserved_semantics'
    && equal(candidate.executionIdentity, context.identity) && candidate.executionIdentityHash === context.identityHash
    && equal(candidate.cases.map((c) => `${c.taskId}:${c.mode}`).sort(), currentCaseKeys()), 'refresh_candidate_identity_invalid');
  const approved = new Map(context.baseline.cases.map((c) => [`${c.taskId}:${c.mode}`, c]));
  const captures = new Map(context.integrity.captures.map((c) => [`${c.taskId}:${c.mode}`, c]));
  for (const taskCase of candidate.cases) {
    const key = `${taskCase.taskId}:${taskCase.mode}`;
    assertSemanticCasePreserved(taskCase, approved.get(key));
    const envelope = (await readPinned(root, taskCase.referencePath.evidence.path, taskCase.referencePath.evidence.sha256)).value;
    demand(equal(envelope.probe, captures.get(key).probe), 'refresh_case_not_bound_to_fresh_capture');
    const result = await verifyTaskReferenceEvidenceV2({ repositoryRoot: root, identity: context.identity,
      executionIdentityHash: context.identityHash, taskCase, evidence: taskCase.referencePath.evidence,
      profilePolicy: { path: REFRESH_POLICY_PATH, sha256: context.sourceInputs.find((r) => r.path === REFRESH_POLICY_PATH).sha256 } });
    demand(result.status === 'verified', 'refresh_independent_reference_not_verified');
  }
  for (const ref of context.sourceInputs) demand(candidate.sourceInputs.some((r) => equal(r, ref)), 'refresh_candidate_omits_profile_source');
  return context;
}
