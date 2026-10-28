import assert from 'node:assert/strict';
import test from 'node:test';
import { loadManifest, RuntimeManifestSchema } from './manifest.js';
import { loadPinnedResources } from './resource.js';

test('pinned resource catalog loads every byte-exact fixture and its legacy projection', async () => {
  const loaded = await loadManifest();
  const resources = await loadPinnedResources(loaded.manifest);
  assert.equal(resources.size, 3);
  for (const entry of loaded.manifest.x402.catalog ?? []) {
    const resource = resources.get(entry.resourceId);
    assert.ok(resource);
    assert.equal(resource.hash, entry.resourceSha256);
    assert.equal(resource.parsed.resourceId, entry.resourceId);
    assert.equal(resource.parsed.schema, entry.schema);
    assert.equal(resource.contentType, entry.contentType);
    if (resource.parsed.provenance !== undefined) assert.deepEqual(resource.parsed.provenance, entry.provenance);
  }
  assert.deepEqual(resources.get(loaded.manifest.x402.resourceId), resources.get('bef-resource-v1'));
  const treasuryPolicy = resources.get('bef-treasury-risk-policy-v2');
  assert.ok(treasuryPolicy);
  assert.equal(treasuryPolicy.parsed.schema, 'web-agent-bench/treasury-risk-policy/v2');
  const treasuryContent = treasuryPolicy.parsed.content as { riskDimensions?: Array<{ ruleId?: string }> };
  assert.deepEqual(treasuryContent.riskDimensions?.map((rule) => rule.ruleId), [
    'counterparty-concentration', 'native-gas-reserve', 'router-approval-scope',
  ]);
});

test('legacy root-only resource fields continue to load without catalog metadata', async () => {
  const loaded = await loadManifest();
  const legacy = structuredClone(loaded.manifest);
  delete legacy.x402.catalog;
  legacy.tools.reads = ['balances', 'offer', 'quote'];
  legacy.tools.writes = ['purchase', 'approve', 'swap', 'wrap', 'unwrap'];
  assert.doesNotThrow(() => RuntimeManifestSchema.parse(legacy), 'archived single-resource tool manifests remain valid');
  const resources = await loadPinnedResources(legacy);
  assert.equal(resources.size, 1);
  assert.equal(resources.get(legacy.x402.resourceId)?.hash, legacy.x402.resourceSha256);
});

test('catalog selection data types are pinned identifiers and remain optional for older catalogs', async () => {
  const { manifest } = await loadManifest();
  assert.deepEqual(manifest.x402.catalog?.map((entry) => entry.dataType), ['benchmark-resource', 'market-state-brief', 'treasury-risk-policy']);
  const older = structuredClone(manifest);
  for (const entry of older.x402.catalog ?? []) delete entry.dataType;
  assert.doesNotThrow(() => RuntimeManifestSchema.parse(older));
  for (const invalid of ['', '../private-resource', 'market\nstate', 'a'.repeat(129)]) {
    const changed = structuredClone(manifest);
    changed.x402.catalog![0]!.dataType = invalid;
    assert.equal(RuntimeManifestSchema.safeParse(changed).success, false);
  }
});
