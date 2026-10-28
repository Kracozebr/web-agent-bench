// Offline Docker entry point. It reads retained evidence and never contacts an executor.
import { createHash, randomUUID } from 'node:crypto';
import { copyFile, link, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { verifyTaskCaptureInventory } from '../../packages/owner-identity/src/task-reference-inventory.ts';

if (process.platform !== 'linux' || process.cwd() !== '/workspace') {
  throw new Error('Run this verifier inside the owner Docker tool runtime at /workspace');
}
const args = process.argv.slice(2);
const runTrainingNegativeTests = args[0] === '--self-test-training';
const sourceIndexArgument = runTrainingNegativeTests ? args[1] : args[0];
if (!sourceIndexArgument || args.length !== (runTrainingNegativeTests ? 2 : 1)) {
  throw new Error('Usage: verify-task-reference-inventory.mjs [--self-test-training] SOURCE_INDEX.json');
}
const root = await realpath('/workspace');
const sourcePath = await realpath(resolve(root, sourceIndexArgument));
const contained = relative(root, sourcePath);
if (!contained || isAbsolute(contained) || contained === '..' || contained.startsWith(`..${sep}`)) {
  throw new Error('Source index must be a file inside the workspace');
}
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const modulePath = resolve(root, 'packages/owner-identity/src/task-reference-inventory.ts');
const before = digest(await readFile(modulePath));
const sourceBytes = await readFile(sourcePath);
const sources = JSON.parse(sourceBytes.toString('utf8'));
const inventory = await verifyTaskCaptureInventory({ runsRoot: resolve(root, 'artifacts/runs'), captures: sources });
const negativeTests = runTrainingNegativeTests
  ? await runTrainingProfileNegativeTests(root, sources)
  : undefined;
const after = digest(await readFile(modulePath));
if (before !== after) throw new Error('Verifier source changed during inspection');
const captureId = randomUUID();
const outputDirectory = resolve(root, 'artifacts/runs/bts-verified-reference-inventory', captureId);
await mkdir(outputDirectory, { recursive: true });
const document = {
  schemaVersion: 'bts-offline-reference-inventory-capture/v1',
  captureId,
  boundary: 'offline retained artifact reads; no executor, database writes, signing or grading',
  sourceIndex: { path: contained.split(sep).join('/'), sha256: digest(sourceBytes) },
  verifierSourceSha256: before,
  sourceUnchanged: true,
  inventory,
};
const output = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
await writeFile(resolve(outputDirectory, 'inventory.json'), output, { flag: 'wx' });
const coveredTasks = inventory.taskCoverage.filter((entry) => entry.status === 'observed_primitive').map((entry) => entry.taskId);
process.stdout.write(`${JSON.stringify({ captureId, status: inventory.status, coveredTasks,
  blockers: inventory.blockers, inventorySha256: digest(output),
  evidenceModes: inventory.captures.map((capture) => ({ kind: capture.kind, evidenceMode: capture.evidenceMode,
    status: capture.status, primitiveCount: capture.primitives.length })),
  ...(negativeTests ? { trainingNegativeTests: negativeTests } : {}),
  outputDirectory: relative(root, outputDirectory), validatedRelease: false })}\n`);
process.exitCode = inventory.status === 'verified' && (!negativeTests || negativeTests.every((test) => test.status === 'passed')) ? 0 : 2;

async function runTrainingProfileNegativeTests(workspaceRoot, captureSources) {
  const trainingSources = captureSources.filter((source) => source?.kind === 'training_reference');
  if (trainingSources.length !== 1) {
    return [{ name: 'training_source_unique', status: 'failed', reason: 'expected_exactly_one_training_reference_source' }];
  }
  const source = trainingSources[0];
  const captureRoot = resolve(workspaceRoot, 'artifacts/runs', ...source.relativeDirectory.split('/'));
  const originalProbe = JSON.parse((await readFile(resolve(captureRoot, 'probe.json'))).toString('utf8'));
  const cases = [
    { name: 'forged_task_count', mutate: (probe) => { probe.capture.taskCount += 1; } },
    { name: 'unfenced_generation', mutate: (probe) => {
      probe.capture.captures[0].generationFence.status = 'active';
      probe.capture.captures[0].generationFence.databaseGeneration.status = 'active';
    } },
    { name: 'missing_raw_artifact_hash', mutate: (probe) => { delete probe.artifacts[1].sha256; } },
    { name: 'error_status', mutate: (probe) => { probe.status = 'error'; } },
  ];
  const tempRoot = await mkdtemp(resolve(tmpdir(), 'bts-training-inventory-negative-'));
  const results = [];
  try {
    for (const testCase of cases) {
      const runsRoot = resolve(tempRoot, testCase.name, 'runs');
      const stagedCapture = resolve(runsRoot, ...source.relativeDirectory.split('/'));
      await mkdir(stagedCapture, { recursive: true });
      for (const artifact of originalProbe.artifacts) {
        const sourceArtifact = resolve(captureRoot, ...artifact.path.split('/'));
        const stagedArtifact = resolve(stagedCapture, ...artifact.path.split('/'));
        await mkdir(dirname(stagedArtifact), { recursive: true });
        try { await link(sourceArtifact, stagedArtifact); }
        catch { await copyFile(sourceArtifact, stagedArtifact); }
      }
      const mutated = structuredClone(originalProbe);
      testCase.mutate(mutated);
      const mutatedBytes = Buffer.from(`${JSON.stringify(mutated, null, 2)}\n`);
      await writeFile(resolve(stagedCapture, 'probe.json'), mutatedBytes, { flag: 'wx' });
      const result = await verifyTaskCaptureInventory({ runsRoot, captures: [{
        kind: 'training_reference', relativeDirectory: source.relativeDirectory,
        expectedProbeSha256: digest(mutatedBytes),
      }] });
      const capture = result.captures[0];
      const passed = result.status === 'blocked' && capture?.status === 'blocked' && capture.primitives.length === 0;
      results.push({ name: testCase.name, status: passed ? 'passed' : 'failed',
        blockedTaskPrimitiveCount: capture?.primitives.length ?? null,
        blockers: capture?.blockers ?? result.blockers });
    }
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
  return results;
}
