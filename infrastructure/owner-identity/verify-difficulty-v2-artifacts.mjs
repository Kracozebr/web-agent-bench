// Docker-only, offline integrity checks. This does not verify task solvability or grades.
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hashPattern = /^[0-9a-f]{64}$/;
const plans = { S1: ['transfer'], S2: ['inspect_offer'], S3: ['inspect_catalog'], S4: ['revoke'],
  M3: ['approve', 'swap', 'unwrap'], M1: ['inspect_offer', 'pay', 'retrieve'],
  M2: ['inspect_catalog', 'pay', 'retrieve'],
  H1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'pay', 'retrieve'],
  H2: Array(6).fill('transfer'), M4: ['wrap', 'approve', 'swap'],
  H3: ['inspect_offer', 'pay', 'retrieve', 'wrap', 'approve', 'swap'],
  U1: ['inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap'] };
function requireFact(condition, code) { if (!condition) throw new Error(code); }
async function bytesAt(root, path) {
  requireFact(typeof path === 'string' && path.length <= 512 && !isAbsolute(path)
    && !path.includes('\\') && !path.includes(':')
    && path.split('/').every((part) => part && part !== '.' && part !== '..'), 'path_invalid');
  const actual = await realpath(resolve(root, path));
  const rel = relative(root, actual);
  requireFact(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'path_escape');
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    requireFact(before.isFile() && before.size <= 8 * 1024 * 1024, 'file_invalid');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    requireFact(bytes.length === before.size && after.size === before.size
      && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs, 'file_changed');
    return bytes;
  } finally { await handle.close(); }
}
async function main() {
  requireFact(process.platform === 'linux' && process.cwd() === '/workspace', 'docker_required');
  const args = process.argv.slice(2);
  requireFact(args.length === 4 && args[0] === '--source-index' && args[2] === '--sha256'
    && hashPattern.test(args[3]), 'usage');
  const root = await realpath('/workspace');
  const verifierPath = 'infrastructure/owner-identity/verify-difficulty-v2-artifacts.mjs';
  const verifierSha256 = sha(await bytesAt(root, verifierPath));
  const indexBytes = await bytesAt(root, args[1]);
  requireFact(sha(indexBytes) === args[3], 'index_pin_mismatch');
  const index = JSON.parse(indexBytes);
  requireFact(index.schemaVersion === 'bts-difficulty-v2-artifact-inputs/v1'
    && Array.isArray(index.captures) && index.captures.length > 0 && index.captures.length <= 20, 'index_invalid');
  const records = [], seen = new Set();
  for (const source of index.captures) {
    requireFact(source.path.startsWith('artifacts/runs/') && source.path.endsWith('/probe.json')
      && hashPattern.test(source.sha256), 'probe_reference_invalid');
    const probeBytes = await bytesAt(root, source.path);
    requireFact(sha(probeBytes) === source.sha256, 'probe_hash_mismatch');
    const probe = JSON.parse(probeBytes);
    const key = `${probe.taskId}:${probe.mode}`;
    requireFact(!seen.has(key), 'duplicate_task_mode'); seen.add(key);
    requireFact(probe.schemaVersion === 'bts-difficulty-v2-reference-probe/v1'
      && probe.classification === 'local_fork_reference_evidence_not_bts_task_acceptance'
      && probe.status === 'captured' && probe.noTaskGrade === true && probe.noReleaseActivation === true
      && probe.noAcceptanceClaim === true && probe.releaseReadiness === 'blocked'
      && probe.participantToolProtocol === 'separate_payment_delivery_v2'
      && ['ranked', 'training'].includes(probe.mode) && plans[probe.taskId], 'probe_contract_invalid');
    const digests = probe.sourceDigests;
    requireFact(digests.matches === true && Object.keys(digests.before).length >= 4
      && Object.entries(digests.before).every(([key, value]) => hashPattern.test(value)
        && digests.after[key] === value), 'source_pins_not_stable');
    const captureRoot = dirname(resolve(root, source.path));
    const artifacts = new Map();
    requireFact(Array.isArray(probe.artifacts) && probe.artifacts.length > 0, 'artifact_inventory_missing');
    for (const artifact of probe.artifacts) {
      requireFact(hashPattern.test(artifact.sha256) && !artifacts.has(artifact.path), 'artifact_reference_invalid');
      const bytes = await bytesAt(captureRoot, artifact.path);
      requireFact(sha(bytes) === artifact.sha256, 'artifact_hash_mismatch');
      artifacts.set(artifact.path, { ...artifact, bytes });
    }
    const manifest = artifacts.get(probe.manifest.path);
    const profile = artifacts.get(probe.difficultyProfile.evidencePath);
    requireFact(manifest && manifest.sha256 === probe.manifest.sha256
      && manifest.sha256 === digests.before.manifestSha256
      && profile && profile.sha256 === probe.difficultyProfile.evidenceSha256
      && profile.sha256 === digests.before.profileSha256, 'manifest_profile_binding_invalid');
    const actions = probe.captureReferences.participantActions;
    requireFact(actions.length === plans[probe.taskId].length && probe.participantActionCount === actions.length
      && probe.captureReferences.participantActionCount === actions.length, 'action_count_invalid');
    for (const [position, action] of actions.entries()) {
      const raw = artifacts.get(action.rawResponsePath);
      requireFact(action.kind === plans[probe.taskId][position] && raw
        && ['actual-tool-http', 'actual-tool-http-raw-response'].includes(raw.boundary)
        && raw.sha256 === action.rawResponseSha256, 'action_raw_binding_invalid');
      const response = JSON.parse(raw.bytes.toString('utf8'));
      requireFact(response.operationId === action.operationId, 'action_operation_binding_invalid');
    }
    const fence = probe.generationFence, observed = fence.independentObserver;
    requireFact(fence.status === 'fenced' && fence.signerErased === true && observed.status === 'fenced'
      && observed.unresolvedOperationCount === 0 && fence.generationId === probe.environment.generationId
      && fence.envId === probe.environment.envId && observed.participantId === probe.environment.participantId
      && observed.payerAddress.toLowerCase() === probe.environment.payerAddress.toLowerCase(), 'fence_binding_invalid');
    requireFact(sha(await bytesAt(root, source.path)) === source.sha256, 'probe_changed');
    records.push({ taskId: probe.taskId, mode: probe.mode, probe: source, rawArtifactCount: artifacts.size,
      participantActionCount: actions.length, manifestSha256: manifest.sha256,
      applicationSourceSha256: digests.before.appSourceSha256, probeSourceSha256: digests.before.probeSourceSha256,
      generationId: fence.generationId });
  }
  requireFact(sha(await bytesAt(root, args[1])) === args[3], 'index_changed');
  requireFact(sha(await bytesAt(root, verifierPath)) === verifierSha256, 'verifier_changed');
  const captureId = randomUUID();
  const outputPrefix = `artifacts/runs/bts-difficulty-v2-artifact-verification/${captureId}`;
  await mkdir(resolve(root, outputPrefix), { recursive: true });
  await writeFile(resolve(root, outputPrefix, 'input-index.json'), indexBytes, { flag: 'wx' });
  const output = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-difficulty-v2-artifact-verification/v1',
    classification: 'raw_artifact_integrity_and_trace_binding_not_semantic_task_acceptance',
    status: 'verified', captureId, inputIndex: { path: args[1], sha256: args[3] },
    retainedInputIndex: { path: `${outputPrefix}/input-index.json`, sha256: args[3] },
    verifierSource: { path: verifierPath, sha256: verifierSha256 }, captures: records,
    claims: { taskSolvability: false, difficultyApproval: false, taskGrade: false,
      validatedRelease: false, releaseActivation: false } }, null, 2)}\n`);
  await writeFile(resolve(root, outputPrefix, 'verification.json'), output, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(output), status: 'verified', captures: records.length })}\n`);
}
void main().catch((error) => {
  const code = error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'artifact_verification_failed';
  process.stderr.write(`status=error code=${code}\n`); process.exitCode = 2;
});
