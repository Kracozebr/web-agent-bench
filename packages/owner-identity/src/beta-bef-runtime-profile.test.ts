import assert from 'node:assert/strict';
import test from 'node:test';
import type { OwnerDatabase } from './db.js';
import type { TaskReleaseQuerySource } from './task-release.js';
import { createBetaBefReadinessProvider } from './beta-bef-runtime-profile.js';
import type { BetaDeploymentManifest } from './beta-profile.js';
import type { BetaBefEnvironment } from './beta-bef-runtime-profile.js';

const hash = 'a'.repeat(64);
const sourceBlockHash = 'b'.repeat(64);
const forkBlockHash = `0x${'c'.repeat(64)}`;
const facilitatorAddress = `0x${'1'.repeat(40)}`;

function setup() {
  let activeLease = false;
  let sourceHash = sourceBlockHash;
  const manifest = {
    executionProfileId: 'beta-bef-v1',
    source: { commit: 'd'.repeat(40), applicationBuildSha256: hash, evaluatorSourceSha256: hash },
    release: { releaseIdentity: 'release-1', manifestHash: hash, benchmarkHash: 'e'.repeat(64),
      policyHash: 'f'.repeat(64), benchmarkVersion: 'beta-v1', executionIdentityHash: '1'.repeat(64),
      environmentManifestSha256: '2'.repeat(64), applicationSourceSha256: '3'.repeat(64), sourceBlockHash }
  } as unknown as BetaDeploymentManifest;
  const releaseView = { releaseIdentity: manifest.release.releaseIdentity, manifestHash: manifest.release.manifestHash,
    benchmarkHash: manifest.release.benchmarkHash, policyHash: manifest.release.policyHash,
    benchmarkVersion: manifest.release.benchmarkVersion };
  const releaseRecord = { ...releaseView, manifest: { executionIdentityHash: manifest.release.executionIdentityHash,
    executionIdentity: { environmentManifestSha256: manifest.release.environmentManifestSha256,
      x402ServiceSha256: manifest.release.applicationSourceSha256, sourceBlockHash,
      sourceChainId: 8453, sourceBlockNumber: '100' } } };
  const releaseSource = {
    async getActiveAdmissionRelease() { return releaseView; },
    async getValidatedReleaseRecord() { return releaseRecord; }
  } as unknown as TaskReleaseQuerySource;
  const db = { async execute() { return activeLease ? [{ environment_id: 'env1' }] : []; } } as unknown as OwnerDatabase;
  const localAnvil = { identity: 'private-anvil-fork', chainId: 8453, anvilVersion: '1.3.0',
    executionNetwork: 'base', hardFork: 'cancun', forkBlockNumber: '100', forkBlockHash };
  const environment: BetaBefEnvironment = { envId: 'env1', apiBaseUrl: 'https://bef.internal',
    observerRpcUrl: 'https://rpc.internal', x402Policy: { manifestSha256: manifest.release.environmentManifestSha256,
      localAnvil } as BetaBefEnvironment['x402Policy'] };
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === 'https://source.internal') {
      const request = JSON.parse(String(init?.body)) as { method: string };
      const result = request.method === 'eth_chainId' ? '0x2105' : {
        number: '0x64', hash: `0x${sourceHash}`
      };
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        headers: { 'content-type': 'application/json' }
      });
    }
    if (url === 'https://bef.internal/healthz') {
      return new Response(JSON.stringify({ status: 'ready', boundary: 'benchmark-environment-api',
        manifestSha256: manifest.release.environmentManifestSha256,
        applicationSourceSha256: manifest.release.applicationSourceSha256,
        environments: [{ envId: 'env1', anvil: { clientVersion: 'anvil/v1.3.0', chainId: 8453,
          executionNetwork: 'base', hardFork: 'cancun', forkBlockNumber: '100', forkBlockHash },
          facilitator: { address: facilitatorAddress } }] }), { headers: { 'content-type': 'application/json' } });
    }
    throw new Error('unexpected_test_fetch_url');
  }) as typeof fetch;
  const provider = createBetaBefReadinessProvider({ db, releaseSource, manifest,
    build: { sourceClean: true, commit: manifest.source.commit, applicationBuildSha256: hash, evaluatorSourceSha256: hash },
    environments: [environment], sourceRpcUrl: 'https://source.internal', fetchImpl });
  return { provider, manifest, setActiveLease(value: boolean) { activeLease = value; }, setSourceHash(value: string) { sourceHash = value; } };
}

test('beta readiness requires pinned release, source and health observations with no active lease', async () => {
  const state = setup();
  const result = await state.provider.isPreparedForRelease(state.manifest.release.releaseIdentity,
    state.manifest.release.manifestHash);
  assert.equal(result.ready, true);
  assert.equal(result.environmentId, 'env1');
  assert.match(result.evidenceHash ?? '', /^[0-9a-f]{64}$/);

  state.setActiveLease(true);
  const busy = await state.provider.isPreparedForRelease(state.manifest.release.releaseIdentity,
    state.manifest.release.manifestHash);
  assert.deepEqual(busy, { ready: false, reason: 'beta_environment_capacity_unavailable' });
  assert.equal(await state.provider.isRuntimeHealthyForRelease(state.manifest.release.releaseIdentity,
    state.manifest.release.manifestHash), true);
});

test('beta readiness fails closed when the pinned source block observation changes', async () => {
  const state = setup();
  state.setSourceHash('9'.repeat(64));
  const result = await state.provider.isPreparedForRelease(state.manifest.release.releaseIdentity,
    state.manifest.release.manifestHash);
  assert.equal(result.ready, false);
  assert.equal(result.reason, 'beta_source_block_pin_mismatch');
});
