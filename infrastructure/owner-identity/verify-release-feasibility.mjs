// Offline Docker-only verification. No API, chain or database mutation.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { verifyRetainedTaskFeasibility } from '../../packages/owner-identity/src/task-feasibility-evidence.ts';

if (process.platform !== 'linux' || process.cwd() !== '/workspace' || process.argv.length !== 2) {
  throw new Error('Run without arguments in the owner Docker tool runtime at /workspace');
}
const root = '/workspace';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const candidatePath = 'artifacts/runs/bts-task-case-candidates/182275ce-2c74-4bee-a0eb-96f6094f8196/candidate-cases.json';
const witnessPath = 'artifacts/runs/bts-release-feasibility-witness/9a306c79-614b-4027-9129-33f68ffa3a75/witness.json';
const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
const inputs = [candidatePath, witnessPath, policyPath, 'pnpm-lock.yaml',
  'infrastructure/owner-identity/verify-release-feasibility.mjs',
  'packages/owner-identity/src/task-feasibility-evidence.ts',
  'packages/owner-identity/src/task-release.ts', 'packages/owner-identity/src/task-catalog.ts',
  'packages/owner-identity/package.json', 'packages/owner-identity/tsconfig.json'];
const snapshot = async () => Promise.all(inputs.toSorted().map(async (path) => ({ path,
  sha256: sha(await readFile(resolve(root, path))) })));
const before = await snapshot();
const candidateBytes = await readFile(resolve(root, candidatePath));
if (sha(candidateBytes) !== '16e8797bacb50c88f80483240a5109958e0de5187de925cce210d44e66c0ca18') {
  throw new Error('Ranked candidate pin mismatch');
}
const candidate = JSON.parse(candidateBytes).assembly;
const result = await verifyRetainedTaskFeasibility({ repositoryRoot: root,
  evidence: { path: witnessPath, sha256: '39c7340d7e438c6da232dcb39e6130ee56d4de0ae3507d533851f2844e148ded',
    boundary: 'actual_tool_http_x402_local_evm_application_store' },
  executionIdentity: candidate.executionIdentity, expectedIdentityHash: candidate.executionIdentityHash,
  profilePolicy: { path: policyPath, sha256: '3f2e59f1b5992ed69ecea443953dd2f96c8e74fd4bc77ff0386f1039000cb0ed' },
});
const after = await snapshot();
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('Feasibility verification sources changed');
const captureId = randomUUID();
const outputPrefix = `artifacts/runs/bts-retained-feasibility-verification/${captureId}`;
await mkdir(resolve(root, outputPrefix), { recursive: true });
const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-retained-feasibility-verification/v1',
  captureId, result, boundary: 'offline_verification_of_retained_local_bef_rpc_and_sql',
  sourceUnchanged: true, sourceInputs: before, witnessPath, candidatePath,
  claims: { currentExecutorReadiness: false, difficultyApproval: false, validatedRelease: false,
    releaseActivation: false, taskGrade: false } }, null, 2)}\n`);
await writeFile(resolve(root, outputPrefix, 'verification.json'), bytes, { flag: 'wx' });
process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(bytes), result })}\n`);
process.exitCode = result.status === 'verified' ? 0 : 2;
