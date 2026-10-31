/** Regression tests for the precise source-only semantic boundary; no runtime acceptance claim. */
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import { TaskCaseSchema, sha256CanonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';
import { APPROVED_REFRESH_BASELINE, assertIdentityPreserved, assertMigrationInventoryPreserved, assertSemanticCasePreserved,
  assertUniformCaptureSources, currentCaseKeys, parseRefreshProfile, readPinned, semanticCaseCore } from './task-release-source-refresh.mjs';

const baseline = JSON.parse(await readFile(new URL(`../../${APPROVED_REFRESH_BASELINE.path}`, import.meta.url)));
const rehash = (taskCase) => { const { caseHash: _old, ...core } = taskCase; return { ...core, caseHash: sha256CanonicalTaskJson(core) }; };
const approved = (id) => structuredClone(baseline.cases.find((c) => c.taskId === id && c.mode === 'ranked'));
const pin = { path: 'artifacts/runs/source-refresh-test/fixture.json', sha256: '1'.repeat(64) };
const profile = { schemaVersion: 'bts-source-refresh-profile/v1',
  classification: 'explicit_new_source_profile_not_release_acceptance', reason: 'ber_diagnostic_source_refresh',
  approvedBaseline: APPROVED_REFRESH_BASELINE, feasibilityVerification: pin, rawIntegrity: pin,
  expectedApplicationSourceSha256: '2'.repeat(64), expectedProbeSourceSha256: '3'.repeat(64), expectedManifestSha256: '4'.repeat(64) };

test('only six explicit source/provenance paths may change; final state, deadline and objective stay exact', () => {
  for (const original of baseline.cases) {
    const changed = structuredClone(original);
    changed.executionIdentityHash = '5'.repeat(64);
    changed.initialStateEvidence = { ...changed.initialStateEvidence, ...pin };
    changed.referencePath.evidence = { ...changed.referencePath.evidence, ...pin };
    assertSemanticCasePreserved(rehash(changed), original);
  }
  const changed = approved('S1'); changed.caseHash = 'f'.repeat(64);
  assert.throws(() => semanticCaseCore(changed), /refresh_case_hash_invalid/);
});

test('rubric, weights, deadline, initial state, action count and final-state hash cannot change', () => {
  const mutations = [c => { c.rubricHash = 'e'.repeat(64); }, c => { c.rubricVersion += '-changed'; },
    c => { c.taskWeight = 2; }, c => { c.taskDeadlineSeconds += 1; },
    c => { c.initialState.balances[0].amountUnits = String(BigInt(c.initialState.balances[0].amountUnits) + 1n); },
    c => { c.initialState.stateSha256 = 'e'.repeat(64); }, c => { c.referencePath.actionCount += 1; },
    c => { c.referencePath.finalStateSha256 = 'e'.repeat(64); }, c => { c.mandatoryRules.pop(); }];
  for (const mutate of mutations) { const original = approved('S1'), changed = structuredClone(original); mutate(changed);
    assert.throws(() => assertSemanticCasePreserved(rehash(changed), original)); }
});

test('goal, price or budget, and permitted route changes reject rather than hide behind source refresh', () => {
  for (const [id, mutate] of [
    ['S1', c => { c.objective.exactPrincipalUnits = String(BigInt(c.objective.exactPrincipalUnits) + 1n); }],
    ['M1', c => { c.objective.expenseBudgetUsdcUnits = String(BigInt(c.objective.expenseBudgetUsdcUnits) + 1n); }],
    ['M1', c => { c.objective.paymentRequirements.amountUnits = String(BigInt(c.objective.paymentRequirements.amountUnits) + 1n); }],
    ['M3', c => { c.objective.permittedRoutes[0].feeTier = 500; }],
  ]) { const original = approved(id), changed = structuredClone(original); mutate(changed);
    assert.throws(() => assertSemanticCasePreserved(rehash(changed), original)); }
  const original = approved('S1'), changed = structuredClone(original);
  changed.objective.evidence = { ignored: true };
  assert.throws(() => TaskCaseSchema.parse(changed));
});

test('execution identity changes only application source and its derived schema version', () => {
  const changed = structuredClone(baseline.executionIdentity);
  changed.x402ServiceSha256 = '8'.repeat(64); changed.applicationSchemaVersion += '-new-source';
  assertIdentityPreserved(changed, baseline.executionIdentity);
  changed.toolSurfaceSha256 = '7'.repeat(64);
  assert.throws(() => assertIdentityPreserved(changed, baseline.executionIdentity), /refresh_non_source_execution_identity_changed/);
});

test('profile rejects unknown fields, substituted baseline and unsafe artifact paths', () => {
  parseRefreshProfile(profile);
  assert.throws(() => parseRefreshProfile({ ...profile, skipProofs: true }), /refresh_profile_fields_invalid/);
  assert.throws(() => parseRefreshProfile({ ...profile, approvedBaseline: pin }), /refresh_profile_contract_invalid/);
  for (const path of ['../bad.json', 'artifacts/runs/../bad.json', '/absolute.json', 'C:/secret.json', 'artifacts\\runs\\x.json']) {
    assert.throws(() => parseRefreshProfile({ ...profile, rawIntegrity: { ...pin, path } }));
  }
});

test('old raw/new identity, mixed probe builds, duplicate and missing captures reject', () => {
  const rows = currentCaseKeys().map((key) => { const [taskId, mode] = key.split(':'); return { taskId, mode, probe: pin,
    applicationSourceSha256: profile.expectedApplicationSourceSha256, probeSourceSha256: profile.expectedProbeSourceSha256,
    manifestSha256: profile.expectedManifestSha256 }; });
  assertUniformCaptureSources(rows, profile);
  for (const field of ['applicationSourceSha256', 'probeSourceSha256', 'manifestSha256']) {
    const mixed = structuredClone(rows); mixed[0][field] = '9'.repeat(64);
    assert.throws(() => assertUniformCaptureSources(mixed, profile), /refresh_mixed_or_old_capture_source/);
  }
  assert.throws(() => assertUniformCaptureSources(rows.slice(1), profile), /refresh_fifteen_captures_required/);
  const duplicate = structuredClone(rows); duplicate[1] = duplicate[0];
  assert.throws(() => assertUniformCaptureSources(duplicate, profile), /refresh_case_inventory_invalid/);
});

test('pinned readers reject mismatched immutable bytes and path escape', async () => {
  await assert.rejects(readPinned(process.cwd(), APPROVED_REFRESH_BASELINE.path, 'f'.repeat(64)), /refresh_input_hash_mismatch/);
  await assert.rejects(readPinned(process.cwd(), '../outside.json', 'f'.repeat(64)), /refresh_path_or_hash_invalid/);
});

test('migration inventory rejects removed, added or modified migrations', () => {
  const rows = baseline.sourceInputs.filter((r) => /^infrastructure\/benchmark-environment\/migrations\/[0-9]{3}_[a-z0-9_]+\.sql$/.test(r.path));
  assertMigrationInventoryPreserved(rows, baseline.sourceInputs);
  assert.throws(() => assertMigrationInventoryPreserved(rows.slice(1), baseline.sourceInputs), /refresh_migrations_changed/);
  assert.throws(() => assertMigrationInventoryPreserved([...rows, {path:'infrastructure/benchmark-environment/migrations/999_added.sql',sha256:'1'.repeat(64)}], baseline.sourceInputs), /refresh_migrations_changed/);
  const modified = structuredClone(rows); modified[0].sha256 = 'f'.repeat(64);
  assert.throws(() => assertMigrationInventoryPreserved(modified, baseline.sourceInputs), /refresh_migrations_changed/);
});

test('contained pinned reader rejects a symlink resolving outside the selected root', async () => {
  await mkdir('.local', {recursive:true});
  const directory = await mkdtemp(join(process.cwd(), '.local/source-refresh-reader-test-'));
  try {
    const root = join(directory, 'root'); await mkdir(root);
    const outside = join(directory, 'outside.json'); await writeFile(outside, '{}');
    await symlink(outside, join(root, 'link.json'));
    await assert.rejects(readPinned(root, 'link.json', null), /refresh_path_escape/);
  } finally { await rm(directory, {recursive:true,force:true}); }
});
