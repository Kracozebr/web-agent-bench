import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {benchmarkBddCaptureDecision, saveBenchmarkBddEvidence} from './bdd-evidence.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
async function fixture(callback) {
  const root = await mkdtemp(join(tmpdir(), 'bdd-writer-'));
  try {
    const contractRoot = join(root, 'tests/bdd/changes/benchmark-task-suite');
    await mkdir(contractRoot, {recursive: true});
    const contract = {protected_scenarios: {'BTS-SC-001': {boundary: 'environment',
      required_observations: ['release_hash'], negative_variants: ['placeholder']}}};
    await writeFile(join(contractRoot, 'harness-contracts.json'), JSON.stringify(contract));
    await callback(root);
  } finally { await rm(root, {recursive: true, force: true}); }
}
test('immutable BDD bundles retain prior attempts and bind bytes to the contract', async () => fixture(async root => {
  const input = {repositoryRoot: root, changeName: 'benchmark-task-suite', scenarioId: 'BTS-SC-001',
    capture: {status: 'blocked'}, provenance: {sourceStableDuringRun: true,
      inputHashesBefore: [{path: 'source.mjs', sha256: 'a'.repeat(64), bytes: 7}],
      inputHashesAfter: [{path: 'source.mjs', sha256: 'a'.repeat(64), bytes: 7}]}};
  const first = await saveBenchmarkBddEvidence(input);
  const second = await saveBenchmarkBddEvidence(input);
  assert.notEqual(first.runId, second.runId);
  const index = JSON.parse(await readFile(join(root, 'artifacts/runs/acceptance/BTS-SC-001/manifest.json')));
  assert.deepEqual(index.runs, [first.runId, second.runId]);
  assert.equal(index.latestRunId, second.runId);
  const manifest = JSON.parse(await readFile(join(root, first.path)));
  assert.equal(manifest.status, 'blocked');
  assert.equal(manifest.observations.release_hash.status, 'not_run');
  assert.equal(manifest.negativeVariants.placeholder.status, 'not_run');
  for (const artifact of manifest.artifacts) {
    const bytes = await readFile(join(root, 'artifacts/runs/acceptance/BTS-SC-001/runs', first.runId, artifact.path));
    assert.equal(hash(bytes), artifact.sha256);
    if (artifact.path === 'provenance.json') {
      const provenance = JSON.parse(bytes);
      assert.equal(provenance.contractSha256, hash(await readFile(join(root, 'tests/bdd/changes/benchmark-task-suite/harness-contracts.json'))));
      assert.equal(provenance.localForkOnly, true);
      assert.deepEqual(provenance.inputHashesBefore, {'source.mjs': 'a'.repeat(64)});
      assert.deepEqual(provenance.inputHashesAfter, provenance.inputHashesBefore);
    }
  }
}));
test('writer rejects out-of-scope scenario IDs and secret-bearing captures', async () => fixture(async root => {
  const input = {repositoryRoot: root, changeName: 'benchmark-task-suite', scenarioId: 'BTS-SC-001', provenance: {}};
  await assert.rejects(saveBenchmarkBddEvidence({...input, scenarioId: '../BTS-SC-001', capture: {}}), /invalid_bdd_scenario/);
  await assert.rejects(saveBenchmarkBddEvidence({...input, capture: {privateKey: 'unsafe-test-value'}}));
}));
test('BRL writer uses the adapter raw evidence filename', async () => fixture(async root => {
  const directory = join(root, 'tests/bdd/changes/benchmark-run-lifecycle');
  await mkdir(directory, {recursive: true});
  await writeFile(join(directory, 'harness-contracts.json'), JSON.stringify({protected_scenarios: {
    'BRL-SC-023': {boundary: 'environment', required_observations: ['owner_bound_immutable_intent'], negative_variants: ['cross_transport_retry']}}}));
  const saved = await saveBenchmarkBddEvidence({repositoryRoot: root, changeName: 'benchmark-run-lifecycle',
    scenarioId: 'BRL-SC-023', capture: {schemaVersion: 'benchmark-run-lifecycle-runtime-evidence/v1'}, provenance: {}});
  const manifest = JSON.parse(await readFile(join(root, saved.path)));
  assert.deepEqual(manifest.artifacts.map(row => row.path), ['runtime-evidence.json', 'provenance.json']);
}));
test('runtime failures remain failed and specific missing-evidence reasons remain visible', () => {
  assert.deepEqual(benchmarkBddCaptureDecision({status:'failed', reasonCode:'unexpected_release_activation'}, true),
    {status:'failed', reasonCode:'unexpected_release_activation'});
  assert.deepEqual(benchmarkBddCaptureDecision({status:'blocked', blockedReasonCode:'persisted_unknown_outcome_variant_uncovered'}, true),
    {status:'blocked', reasonCode:'persisted_unknown_outcome_variant_uncovered'});
  assert.deepEqual(benchmarkBddCaptureDecision({status:'verified'}, false),
    {status:'blocked', reasonCode:'source_inputs_changed_during_run'});
  assert.equal(benchmarkBddCaptureDecision({status:'verified'}, true).status,'passed');
});