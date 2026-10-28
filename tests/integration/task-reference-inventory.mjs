import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, link, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { verifyTaskCaptureInventory } from '../../packages/owner-identity/src/task-reference-inventory.ts';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const runsRoot = resolve(repositoryRoot, 'artifacts/runs');
const refs = {
  currentReference: 'bts-reference-foundation/388c2a61-8e3d-41a4-a506-786c3ec9a211',
  oldNative: 'bts-native-task-primitives/2ca3cc87-8df5-4f64-862a-20e6987f0c2f',
  currentH3: 'bts-h3-paid-route-swap-foundation/294372e8-c74f-4d1e-a78a-270082d64b40',
  currentU1: 'bts-u1-same-generation-reference/cc3cebb6-4683-4791-8c80-973872ddd833',
  failedU1: 'bts-u1-same-generation-reference/36db82c6-369f-4811-8845-aed2aa549480',
  openTraining: 'bts-open-training-reference-profile/10fff3fa-2aa4-474b-a084-240e31e2b879',
};
const trustedProbeHashes = {
  currentH3: 'a4361b1bb24c31f57ef8d8ff0d447687737fba2034adcfa971ac01c120f98e7c',
  currentU1: 'd85b8569907ec649aac30cb9111babd2cd3d60530f94980bf94f39643aae1ef3',
  openTraining: '7bc0c7fc24d4e09eecd0da35768355d12c838e67f9d11e2d5399ea4d61a6a1e8',
};

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function probeSource(kind, relativeDirectory, expectedProbeSha256) {
  return { kind, relativeDirectory, expectedProbeSha256: expectedProbeSha256 ?? sha256(await readFile(join(runsRoot, relativeDirectory, 'probe.json'))) };
}

async function makeTempRuns() {
  const temporaryRoot = await mkdtemp(join(tmpdir(), 'bts-task-reference-inventory-'));
  const temporaryRuns = join(temporaryRoot, 'runs');
  await mkdir(temporaryRuns, { recursive: true });
  return { temporaryRoot, temporaryRuns };
}

async function safeCleanup(temporaryRoot) {
  const absolute = resolve(temporaryRoot);
  const expectedParent = resolve(tmpdir()) + sep;
  assert.ok(absolute.startsWith(expectedParent) && !isAbsolute(relative(expectedParent, absolute)));
  assert.ok(absolute.includes('bts-task-reference-inventory-'));
  await rm(absolute, { recursive: true, force: true });
}

async function stageTrainingProbe(temporaryRuns, relativeDirectory, probe, probeBytes) {
  const sourceCapture = resolve(runsRoot, relativeDirectory);
  const stagedCapture = resolve(temporaryRuns, 'training-candidate');
  await mkdir(stagedCapture, { recursive: true });
  assert.ok(Array.isArray(probe.artifacts) && probe.artifacts.length === 512);
  for (const artifact of probe.artifacts) {
    assert.equal(typeof artifact.path, 'string');
    assert.ok(!artifact.path.includes('\\') && !artifact.path.startsWith('/') && !artifact.path.split('/').includes('..'));
    const sourceArtifact = resolve(sourceCapture, ...artifact.path.split('/'));
    const stagedArtifact = resolve(stagedCapture, ...artifact.path.split('/'));
    const remainder = relative(stagedCapture, stagedArtifact);
    assert.ok(remainder !== '..' && !remainder.startsWith(`..${sep}`) && !isAbsolute(remainder));
    await mkdir(dirname(stagedArtifact), { recursive: true });
    try { await link(sourceArtifact, stagedArtifact); }
    catch { await copyFile(sourceArtifact, stagedArtifact); }
  }
  await writeFile(join(stagedCapture, 'probe.json'), probeBytes, { flag: 'wx' });
  return 'training-candidate';
}

test('verifies actual reference, native, H3, and U1 capture profiles without upgrading their claims', async () => {
  const [reference, native, h3, u1] = await Promise.all([
    probeSource('unified_reference', refs.currentReference),
    probeSource('native_reference', refs.oldNative),
    probeSource('h3_reference', refs.currentH3, trustedProbeHashes.currentH3),
    probeSource('u1_reference', refs.currentU1, trustedProbeHashes.currentU1),
  ]);
  assert.equal(sha256(await readFile(join(runsRoot, refs.currentH3, 'probe.json'))), trustedProbeHashes.currentH3);
  assert.equal(sha256(await readFile(join(runsRoot, refs.currentU1, 'probe.json'))), trustedProbeHashes.currentU1);

  const result = await verifyTaskCaptureInventory({ runsRoot, captures: [reference, native, h3, u1] });
  assert.equal(result.status, 'blocked');
  assert.ok(result.blockers.includes('cross_capture_application_source_mismatch'), JSON.stringify(result.captures.map(({ kind, status, compatibleWithInventoryPins, blockers }) => ({ kind, status, compatibleWithInventoryPins, blockers }))));
  assert.equal(result.pins.applicationSourceSha256, '7330b2493e5014f20fb455a9613cf420b12408fcc92c2e6c0b11c6de8e100171');
  assert.deepEqual(result.claims, {
    taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false,
  });

  const byKind = new Map(result.captures.map((capture) => [capture.kind, capture]));
  assert.equal(byKind.get('unified_reference').status, 'verified_primitives');
  assert.equal(byKind.get('native_reference').status, 'verified_primitives');
  assert.equal(byKind.get('native_reference').compatibleWithInventoryPins, false);
  assert.ok(byKind.get('native_reference').blockers.includes('cross_capture_application_source_mismatch'));
  assert.equal(byKind.get('h3_reference').status, 'verified_primitives');
  assert.equal(byKind.get('u1_reference').status, 'verified_primitives');
  assert.ok(byKind.get('unified_reference').rawArtifactCount >= 300);
  assert.ok(byKind.get('h3_reference').rawArtifactCount >= 100);
  assert.ok(byKind.get('u1_reference').rawArtifactCount >= 100);

  const coverage = new Map(result.taskCoverage.map((entry) => [entry.taskId, entry]));
  assert.equal(coverage.get('H3').status, 'observed_primitive');
  assert.equal(coverage.get('U1').status, 'observed_primitive');
  assert.equal(coverage.get('S4').status, 'blocked');
  assert.deepEqual(coverage.get('S4').primitives, []);
  assert.ok(coverage.get('M3').primitives.every((entry) => entry.captureKind !== 'native_reference'));
});

test('checks the actual open-training profile and rejects generation, fence, quote, and baseline mutations [requires actual retained training capture]', async (t) => {
  let originalBytes;
  try { originalBytes = await readFile(join(runsRoot, refs.openTraining, 'probe.json')); }
  catch (error) {
    if (error?.code === 'ENOENT') {
      t.skip('Requires the retained actual open-training reference capture');
      return;
    }
    throw error;
  }
  assert.equal(sha256(originalBytes), trustedProbeHashes.openTraining, 'retained training probe must match its pinned content hash');
  const original = JSON.parse(originalBytes.toString('utf8'));
  const source = await probeSource('training_reference', refs.openTraining, trustedProbeHashes.openTraining);

  await t.test('verifies the actual eight ordered training primitives and all retained hashes', async () => {
    const result = await verifyTaskCaptureInventory({ runsRoot, captures: [source] });
    const capture = result.captures[0];
    assert.equal(result.status, 'verified');
    assert.deepEqual(result.blockers, []);
    assert.equal(capture.kind, 'training_reference');
    assert.equal(capture.evidenceMode, 'training_reference');
    assert.equal(capture.status, 'verified_primitives');
    assert.equal(capture.rawArtifactCount, 512);
    assert.ok(capture.rawArtifacts.every((artifact) => artifact.status === 'verified'));
    assert.equal(capture.pin.manifestSha256, 'e90d876b500f2bd8d45e891295028d4b87993070a4c08b18b262fa302cde13e4');
    assert.equal(capture.pin.applicationSourceSha256, '7330b2493e5014f20fb455a9613cf420b12408fcc92c2e6c0b11c6de8e100171');
    assert.equal(capture.pin.probeSourceSha256, '95e7873cdcf1ccf7f4b5bc10b4b6f3dec56872731151cbaf4836ad1d4cb02ffe');
    assert.deepEqual(capture.pin.sourceBlock, {
      number: '0x32871b4', hash: '0x8884b44376e007d7e298126e56b88f5b93ad202993ba099938689affc5eda966',
    });
    assert.deepEqual(capture.primitives.map((primitive) => primitive.taskId), ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']);
    assert.ok(capture.primitives.every((primitive) => primitive.evidenceMode === 'training_reference'));
    assert.deepEqual(result.claims, {
      taskAcceptance: false, taskGrade: false, validatedRelease: false, difficultyApproval: false, releaseActivation: false,
    });
    for (const taskId of ['S1', 'S2', 'S4', 'M1', 'M3', 'M4', 'H1', 'H2']) {
      const coverage = result.taskCoverage.find((entry) => entry.taskId === taskId);
      assert.equal(coverage.status, 'observed_primitive');
      assert.ok(coverage.primitives.some((primitive) => primitive.captureKind === 'training_reference' &&
        primitive.evidenceMode === 'training_reference'));
    }
  });

  const mutationCases = [
    {
      name: 'duplicate generation id is blocked',
      expectedBlocker: 'training_reference_task_or_fence_invalid:S2',
      mutate(probe) {
        const firstGenerationId = probe.capture.captures[0].generation.generationId;
        const second = probe.capture.captures[1];
        second.generation.generationId = firstGenerationId;
        second.capture.environment.generationId = firstGenerationId;
        second.generationFence.databaseGeneration.generation_id = firstGenerationId;
      },
    },
    {
      name: 'unfenced generation is blocked',
      expectedBlocker: 'training_reference_task_or_fence_invalid:S1',
      mutate(probe) {
        probe.capture.captures[0].generationFence.status = 'active';
        probe.capture.captures[0].generationFence.databaseGeneration.status = 'active';
      },
    },
    {
      name: 'public quote mismatch is blocked',
      expectedBlocker: 'training_m3_public_quote_binding_mismatch',
      mutate(probe) {
        const m3 = probe.capture.captures.find((entry) => entry.taskId === 'M3').capture.objectiveCandidate.publicQuote;
        m3.amountOutUnits = '1';
        m3.independentQuoterV2OutputUnits = '1';
      },
    },
    {
      name: 'baseline mismatch against raw RPC evidence is blocked',
      expectedBlocker: 'training_m3_baseline_quantity_mismatch:task-native-m3-before-payer-usdc',
      mutate(probe) {
        probe.capture.captures.find((entry) => entry.taskId === 'M3').capture.snapshots.before.payerUsdcUnits = '99999999';
      },
    },
  ];

  for (const mutation of mutationCases) {
    await t.test(mutation.name, async () => {
      const { temporaryRoot, temporaryRuns } = await makeTempRuns();
      try {
        const mutated = structuredClone(original);
        mutation.mutate(mutated);
        const mutatedBytes = Buffer.from(`${JSON.stringify(mutated, null, 2)}\n`);
        const stagedDirectory = await stageTrainingProbe(temporaryRuns, refs.openTraining, original, mutatedBytes);
        const result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
          kind: 'training_reference', relativeDirectory: stagedDirectory, expectedProbeSha256: sha256(mutatedBytes),
        }] });
        const capture = result.captures[0];
        assert.equal(result.status, 'blocked');
        assert.equal(capture.status, 'blocked');
        assert.deepEqual(capture.primitives, []);
        assert.ok(capture.blockers.includes(mutation.expectedBlocker), JSON.stringify(capture.blockers));
        assert.equal(result.taskCoverage.find((entry) => entry.taskId === 'M3').status, 'blocked');
        assert.equal(result.claims.taskAcceptance, false);
        assert.equal(result.claims.validatedRelease, false);
      } finally { await safeCleanup(temporaryRoot); }
    });
  }
});

test('retains a failed U1 run as blocked evidence, not U1 coverage', async () => {
  const source = await probeSource('u1_reference', refs.failedU1);
  const result = await verifyTaskCaptureInventory({ runsRoot, captures: [source] });
  const capture = result.captures[0];
  assert.equal(capture.status, 'blocked');
  assert.ok(capture.blockers.includes('capture_not_successful:u1_reference'));
  assert.equal(capture.primitives.length, 0);
  assert.equal(result.taskCoverage.find((entry) => entry.taskId === 'U1').status, 'blocked');
  assert.equal(result.claims.validatedRelease, false);
});

test('rejects parent traversal before reading a capture', async () => {
  const source = await probeSource('h3_reference', refs.currentH3, trustedProbeHashes.currentH3);
  source.relativeDirectory = '../' + refs.currentH3;
  const result = await verifyTaskCaptureInventory({ runsRoot, captures: [source] });
  assert.equal(result.status, 'blocked');
  assert.ok(result.captures[0].blockers.includes('capture_directory_path_invalid'));
});

test('rejects conflicting duplicate paths and malformed artifact hashes', async () => {
  const bytes = await readFile(join(runsRoot, refs.currentReference, 'probe.json'));
  const original = JSON.parse(bytes.toString('utf8'));
  const { temporaryRoot, temporaryRuns } = await makeTempRuns();
  try {
    const captureDir = join(temporaryRuns, 'candidate');
    await mkdir(captureDir);
    const duplicate = structuredClone(original);
    duplicate.artifacts.push({ ...duplicate.artifacts[0], sha256: 'f'.repeat(64) });
    const duplicateBytes = Buffer.from(JSON.stringify(duplicate));
    await writeFile(join(captureDir, 'probe.json'), duplicateBytes);
    let result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
      kind: 'unified_reference', relativeDirectory: 'candidate', expectedProbeSha256: sha256(duplicateBytes),
    }] });
    assert.ok(result.captures[0].blockers.some((code) => code.startsWith('artifact_duplicate_path_conflict:')));

    const malformed = structuredClone(original);
    malformed.artifacts[0].sha256 = 'not-a-sha256';
    const malformedBytes = Buffer.from(JSON.stringify(malformed));
    await writeFile(join(captureDir, 'probe.json'), malformedBytes);
    result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
      kind: 'unified_reference', relativeDirectory: 'candidate', expectedProbeSha256: sha256(malformedBytes),
    }] });
    assert.ok(result.captures[0].blockers.includes('artifact_inventory_entry_invalid'));
  } finally { await safeCleanup(temporaryRoot); }
});

test('rejects missing files, byte hash mismatches, and symlink escapes', async (t) => {
  const sourceProbe = await readFile(join(runsRoot, refs.currentH3, 'probe.json'));
  const expectedProbeSha256 = sha256(sourceProbe);
  const { temporaryRoot, temporaryRuns } = await makeTempRuns();
  try {
    const captureDir = join(temporaryRuns, 'capture');
    await mkdir(captureDir);
    await writeFile(join(captureDir, 'probe.json'), sourceProbe);

    let result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
      kind: 'h3_reference', relativeDirectory: 'capture', expectedProbeSha256,
    }] });
    assert.ok(result.captures[0].blockers.some((code) => code.includes('artifact_file_missing:manifest.json')));

    const originalManifest = await readFile(join(runsRoot, refs.currentH3, 'manifest.json'));
    await writeFile(join(captureDir, 'manifest.json'), Buffer.concat([originalManifest, Buffer.from('\n') ]));
    result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
      kind: 'h3_reference', relativeDirectory: 'capture', expectedProbeSha256,
    }] });
    assert.ok(result.captures[0].blockers.includes('artifact_hash_mismatch:manifest.json'));

    const outside = join(temporaryRoot, 'outside');
    await mkdir(outside);
    await rm(join(captureDir, 'manifest.json'));
    await symlink(outside, join(captureDir, 'manifest.json'), 'junction');
    result = await verifyTaskCaptureInventory({ runsRoot: temporaryRuns, captures: [{
      kind: 'h3_reference', relativeDirectory: 'capture', expectedProbeSha256,
    }] });
    assert.ok(result.captures[0].blockers.includes('artifact_symlink_escape:manifest.json'));

    const linkRuns = join(temporaryRoot, 'link-runs');
    await mkdir(linkRuns);
    const linkedCapture = join(linkRuns, 'outside-link');
    try { await symlink(join(runsRoot, refs.currentH3), linkedCapture, 'junction'); }
    catch { t.skip('This Windows host does not permit creating a temporary directory junction'); return; }
    result = await verifyTaskCaptureInventory({ runsRoot: linkRuns, captures: [{
      kind: 'h3_reference', relativeDirectory: 'outside-link', expectedProbeSha256,
    }] });
    assert.ok(result.captures[0].blockers.includes('capture_directory_symlink_escape'));
  } catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'ENOSYS'].includes(error?.code)) {
      t.skip('This Windows host does not permit creating a temporary directory junction');
      return;
    }
    throw error;
  } finally { await safeCleanup(temporaryRoot); }
});
