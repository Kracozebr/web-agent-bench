// Offline Docker entry point. Training candidates remain private, unvalidated and unactivated.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { assembleTrainingTaskCaseCandidates } from '../../packages/owner-identity/src/task-case-assembler.ts';

if (process.platform !== 'linux' || process.cwd() !== '/workspace' || process.argv.length !== 2) {
  throw new Error('Run this command without arguments in the owner Docker tool runtime at /workspace');
}
const root = '/workspace';
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const inputIndex = 'artifacts/runs/bts-reference-input-index/2026-10-27-local-7330b249-training.json';
const localPolicy = 'infrastructure/owner-identity/task-release-local-policy.json';
async function sourceSnapshot() {
  const files = [inputIndex, localPolicy, 'pnpm-lock.yaml',
    'infrastructure/owner-identity/assemble-training-task-candidates.mjs',
    'packages/owner-identity/tsconfig.json', 'packages/owner-identity/package.json',
    ...['task-case-assembler', 'task-reference-inventory', 'task-release', 'task-catalog']
      .map((name) => `packages/owner-identity/src/${name}.ts`)];
  const snapshots = [];
  for (const path of files.sort()) snapshots.push({ path, sha256: hash(await readFile(resolve(root, path))) });
  return snapshots;
}
const before = await sourceSnapshot();
const captureId = randomUUID();
const outputPrefix = `artifacts/runs/bts-task-case-candidates/${captureId}`;
const assembly = await assembleTrainingTaskCaseCandidates({ repositoryRoot: root,
  sourceIndexPath: inputIndex, localPolicyPath: localPolicy, evidencePathPrefix: outputPrefix });
const after = await sourceSnapshot();
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('Training case assembly sources changed during inspection');
const outputRoot = resolve(root, outputPrefix);
await mkdir(outputRoot, { recursive: true });
for (const file of assembly.evidenceFiles) {
  if (!file.path.startsWith(`${outputPrefix}/`) || file.path.includes('\\') ||
      file.path.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error('Training candidate evidence path escapes its new output directory');
  }
  const bytes = Buffer.from(file.content, 'utf8');
  if (hash(bytes) !== file.sha256) throw new Error('Training candidate evidence bytes differ from the case reference hash');
  const target = resolve(root, file.path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, bytes, { flag: 'wx' });
}
const document = {
  schemaVersion: 'bts-offline-training-case-candidate-capture/v1', captureId,
  boundary: 'retained local-fork training evidence and explicit local policy; no executor or database writes',
  sourceUnchanged: true, sourceInputs: before, nodeVersion: process.version,
  assembly: { ...assembly, evidenceFiles: assembly.evidenceFiles.map(({ path, sha256 }) => ({ path, sha256 })) },
};
const output = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
await writeFile(resolve(outputRoot, 'candidate-cases.json'), output, { flag: 'wx' });
process.stdout.write(`${JSON.stringify({ captureId, status: assembly.status,
  caseCount: assembly.cases.length, taskResults: assembly.taskResults, blockers: assembly.blockers,
  candidateFileSha256: hash(output), outputPrefix, validatedRelease: false })}\n`);
process.exitCode = assembly.status === 'candidates_only' ? 0 : 2;
