// Offline identity construction and independent retained-witness verification.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { schemaLineage, executionIdentityFromManifest } from '../../packages/owner-identity/src/task-case-assembler.ts';
import { sha256CanonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hashPattern = /^[0-9a-f]{64}$/;
async function main() {
  if (process.platform !== 'linux' || process.cwd() !== '/workspace') throw new Error('docker_required');
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--witness' || args[2] !== '--sha256'
    || !/^artifacts\/runs\/[A-Za-z0-9_./-]+\/witness\.json$/.test(args[1])
    || args[1].split('/').some((part) => !part || part === '.' || part === '..')
    || !hashPattern.test(args[3])) throw new Error('usage');
  const root = '/workspace';
  const witnessPath = args[1];
  const witnessBytes = await readFile(resolve(root, witnessPath));
  if (sha(witnessBytes) !== args[3]) throw new Error('witness_pin_mismatch');
  const witness = JSON.parse(witnessBytes);
  const appHash = witness.selectedPins.expectedApplicationSourceSha256;
  const manifestHash = witness.selectedPins.expectedManifestSha256;
  if (!hashPattern.test(appHash) || !hashPattern.test(manifestHash)) throw new Error('witness_pins_invalid');
  const manifestPath = `${witnessPath.slice(0, -'witness.json'.length)}manifest.raw.json`;
  const manifestBytes = await readFile(resolve(root, manifestPath));
  if (sha(manifestBytes) !== manifestHash) throw new Error('manifest_pin_mismatch');
  const manifest = JSON.parse(manifestBytes);
  const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
  const policyBytes = await readFile(resolve(root, policyPath));
  const policy = JSON.parse(policyBytes);
  const lineage = await schemaLineage(root, appHash);
  const inputs = [witnessPath, manifestPath, policyPath, 'pnpm-lock.yaml',
    'infrastructure/owner-identity/verify-runtime-feasibility.mjs',
    ...['task-case-assembler', 'task-release', 'task-feasibility-evidence', 'task-catalog']
      .map((name) => `packages/owner-identity/src/${name}.ts`),
    ...lineage.migrationFiles.map((file) => file.path)];
  const snapshot = () => Promise.all(inputs.toSorted().map(async (path) => ({ path,
    sha256: sha(await readFile(resolve(root, path))) })));
  const before = await snapshot();
  const pinnedInputs = new Map(before.map((item) => [item.path, item.sha256]));
  if (pinnedInputs.get(witnessPath) !== sha(witnessBytes)
    || pinnedInputs.get(manifestPath) !== sha(manifestBytes)
    || pinnedInputs.get(policyPath) !== sha(policyBytes)
    || lineage.migrationFiles.some((file) => pinnedInputs.get(file.path) !== file.sha256)) {
    throw new Error('source_changed_before_verification');
  }
  const identity = executionIdentityFromManifest(manifest, manifestHash, appHash, policy.profileId, lineage.derivedVersion);
  const identityHash = sha256CanonicalTaskJson(identity);
  const protocol = manifest.tools.participantProtocol ?? 'combined_purchase_v1';
  const result = await verifyRetainedTaskFeasibility({ repositoryRoot: root,
    evidence: { path: witnessPath, sha256: args[3], boundary: 'actual_tool_http_x402_local_evm_application_store' },
    executionIdentity: identity, expectedIdentityHash: identityHash,
    profilePolicy: { path: policyPath, sha256: sha(policyBytes) }, participantToolProtocol: protocol });
  const after = await snapshot();
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('source_changed');
  const captureId = randomUUID();
  const outputPrefix = `artifacts/runs/bts-runtime-feasibility-verification/${captureId}`;
  await mkdir(resolve(root, outputPrefix), { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-runtime-feasibility-verification/v1',
    classification: 'historical_readonly_feasibility_not_release_or_live_readiness', captureId,
    witness: { path: witnessPath, sha256: args[3] }, executionIdentity: identity,
    executionIdentityHash: identityHash, participantToolProtocol: protocol,
    applicationSchemaLineage: lineage, result, sourceUnchanged: true, sourceInputs: before,
    claims: { currentExecutorReadiness: false, difficultyApproval: false, validatedRelease: false,
      releaseActivation: false, taskGrade: false } }, null, 2)}\n`);
  await writeFile(resolve(root, outputPrefix, 'verification.json'), bytes, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(bytes), result })}\n`);
  process.exitCode = result.status === 'verified' ? 0 : 2;
}
void main().catch(() => { process.stderr.write('runtime_feasibility_verification_failed\n'); process.exitCode = 2; });
