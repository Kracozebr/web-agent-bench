import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { hashBetaApplicationBuild, observeBetaBuildIdentity } from './beta-runtime-build-identity.js';

test('beta build observation hashes actual output and matches independent Git/evaluator pins', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'beta-build-identity-'));
  try {
    const api = resolve(root, 'packages/owner-identity/dist');
    const web = resolve(root, 'packages/owner-web/.next/server');
    await mkdir(api, { recursive: true }); await mkdir(web, { recursive: true });
    await writeFile(resolve(api, 'server.js'), 'compiled owner runtime');
    await writeFile(resolve(web, 'page.js'), 'compiled web runtime');
    const applicationBuildSha256 = await hashBetaApplicationBuild(root);
    const pins = { commit: 'a'.repeat(40), applicationBuildSha256, evaluatorSourceSha256: 'b'.repeat(64) };
    const result = await observeBetaBuildIdentity({ repositoryRoot: root, evaluatorSourceSha256: pins.evaluatorSourceSha256,
      expected: pins, dependencies: { runGit: async (args) => args[0] === 'rev-parse' ? pins.commit : '' } });
    assert.deepEqual(result, { ...pins, sourceClean: true });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('beta build observation blocks dirty checkout and stale build hash', async () => {
  const root = await mkdtemp(resolve(tmpdir(), 'beta-build-identity-'));
  try {
    await mkdir(resolve(root, 'packages/owner-identity/dist'), { recursive: true });
    await mkdir(resolve(root, 'packages/owner-web/.next'), { recursive: true });
    await writeFile(resolve(root, 'packages/owner-identity/dist/server.js'), 'compiled');
    await writeFile(resolve(root, 'packages/owner-web/.next/BUILD_ID'), 'build');
    const pins = { commit: 'a'.repeat(40), applicationBuildSha256: 'c'.repeat(64), evaluatorSourceSha256: 'b'.repeat(64) };
    await assert.rejects(observeBetaBuildIdentity({ repositoryRoot: root, evaluatorSourceSha256: pins.evaluatorSourceSha256,
      expected: pins, dependencies: { runGit: async (args) => args[0] === 'rev-parse' ? pins.commit : ' M source.ts' } }),
    /beta_build_identity_source_not_clean/);
    await assert.rejects(observeBetaBuildIdentity({ repositoryRoot: root, evaluatorSourceSha256: pins.evaluatorSourceSha256,
      expected: pins, dependencies: { runGit: async (args) => args[0] === 'rev-parse' ? pins.commit : '' } }),
    /beta_build_identity_pin_mismatch/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
