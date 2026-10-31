import assert from 'node:assert/strict';
import test from 'node:test';
import { qualificationArtifactPath } from './qualification-output-paths.mjs';

test('actual absolute /workspace reference output maps to the identical retained relative artifact', () => {
  const relative = 'artifacts/runs/bts-difficulty-v2-reference/s1-ranked/c572b4d9-44c2-4ed8-b370-1f59f04a7df6';
  const prefix = 'artifacts/runs/bts-difficulty-v2-reference/';
  assert.equal(qualificationArtifactPath('/workspace/' + relative, prefix), relative);
  assert.equal(qualificationArtifactPath(relative, prefix), relative);
  assert.equal(qualificationArtifactPath('/workspace/artifacts/runs/bts-release-feasibility-witness/fresh'),
    'artifacts/runs/bts-release-feasibility-witness/fresh');
});

test('output mapping rejects alternate roots, traversal, aliases, encoded paths and foreign capture families', () => {
  for (const path of ['/workspace2/artifacts/runs/fresh','/tmp/artifacts/runs/fresh','../artifacts/runs/fresh',
    '/workspace/artifacts/runs/../outside','artifacts/runs//fresh','artifacts/runs/./fresh','C:/workspace/artifacts/runs/fresh',
    'file:///workspace/artifacts/runs/fresh','artifacts/runs/%2e%2e/fresh','artifacts\\runs\\fresh']) {
    assert.throws(() => qualificationArtifactPath(path), /qualification_output_path_invalid/, path);
  }
  assert.throws(() => qualificationArtifactPath('/workspace/artifacts/runs/other-capture/id',
    'artifacts/runs/bts-difficulty-v2-reference/'), /qualification_output_path_invalid/);
});
