import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import type { RuntimeManifest } from '../manifest.js';
import { findRepositoryRoot, type LoadedProbeRuntime } from './environment.js';
import type { U1DifficultyV2ParticipantAction } from './task-v2-u1-capture.js';
import {
  addU1WethZeroConstraint,
  assertU1DifficultyV2ParticipantActions,
  u1QuoteRpcBlockIdentityMatches,
  validateU1DifficultyV2ProfileTask,
} from './task-v2-u1-capture.js';
import { loadDifficultyProfileV2, type DifficultyProfileSource } from './task-difficulty-v2-capture.js';

async function fixture(): Promise<{ manifest: RuntimeManifest; source: DifficultyProfileSource }> {
  const root = findRepositoryRoot();
  const manifestBytes = await readFile(resolve(root, 'infrastructure/benchmark-environment/manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString()) as RuntimeManifest;
  const runtime = { root, manifest, manifestSha256: createHash('sha256').update(manifestBytes).digest('hex') } as LoadedProbeRuntime;
  const source = await loadDifficultyProfileV2({ runtime });
  return { manifest, source };
}

test('U1 difficulty-v2 profile binds ranked-only inputs, exact obligations, route and allocation targets', async () => {
  const { manifest, source } = await fixture();
  const validated = validateU1DifficultyV2ProfileTask(source, manifest, 'ranked');
  assert.equal(validated.components.length, 2);
  assert.deepEqual(validated.components.map((item) => item.amountUsdcUnits), ['100000', '125000']);
  assert.deepEqual(validated.obligations.map((item) => item.recipient), [
    '0x3000000000000000000000000000000000000001',
    '0x3000000000000000000000000000000000000002',
  ]);
  assert.equal(validated.planning.exactInputUsdcUnits, '1500000');
  assert.throws(() => validateU1DifficultyV2ProfileTask(source, manifest, 'training'), /task_u1_v2_ranked_only/);
});

test('U1 difficulty-v2 profile rejects changed action sequence or WETH target', async () => {
  const { manifest, source } = await fixture();
  const actionTampered = JSON.parse(JSON.stringify(source)) as DifficultyProfileSource;
  const tasks = actionTampered.profile.tasks as Record<string, unknown>;
  const u1 = tasks.U1 as Record<string, unknown>;
  (u1.participantActionPlan as unknown[])[9] = 'approve:cleanup';
  assert.throws(() => validateU1DifficultyV2ProfileTask(actionTampered, manifest), /task_u1_v2_profile_contract_invalid/);

  const targetTampered = JSON.parse(JSON.stringify(source)) as DifficultyProfileSource;
  const targetTask = (targetTampered.profile.tasks as Record<string, unknown>).U1 as Record<string, unknown>;
  (targetTask.targetSharesBps as Record<string, unknown>).WETH = 1;
  assert.throws(() => validateU1DifficultyV2ProfileTask(targetTampered, manifest), /task_u1_v2_profile_contract_invalid/);
});

test('U1 v2 allocation plan explicitly constrains WETH to zero and refuses a duplicate constraint', () => {
  const base = { allocationAssets: [
    { assetId: 'USDC', targetShareBps: 40, toleranceBps: 1 },
    { assetId: 'ETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: '25', denominator: '10000000000000000' }, targetShareBps: 9960, toleranceBps: 1 },
  ] };
  const result = addU1WethZeroConstraint(base);
  assert.deepEqual(result.allocationAssets[2], {
    assetId: 'WETH', usdcBaseUnitsPerAssetBaseUnit: { numerator: '25', denominator: '10000000000000000' }, targetShareBps: 0, toleranceBps: 0,
  });
  assert.deepEqual(result.targetSharesBps, { USDC: 40, ETH: 9960, WETH: 0 });
  assert.deepEqual(result.assetToleranceBps, { USDC: 1, ETH: 1, WETH: 0 });
  assert.throws(() => addU1WethZeroConstraint(result), /task_u1_v2_weth_constraint_already_present/);
});

test('U1 v2 participant trace requires precisely the ten approved action kinds and raw references', () => {
  const kinds: U1DifficultyV2ParticipantAction['kind'][] = [
    'inspect_catalog', 'pay', 'retrieve', 'pay', 'retrieve', 'transfer', 'transfer', 'approve', 'swap', 'unwrap',
  ];
  const actions = kinds.map((kind, index) => ({
    kind,
    operationId: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    rawResponsePath: `task-u1-v2/responses/${index}.json`, rawResponseSha256: 'a'.repeat(64),
  })) as U1DifficultyV2ParticipantAction[];
  assert.doesNotThrow(() => assertU1DifficultyV2ParticipantActions(actions));
  assert.throws(() => assertU1DifficultyV2ParticipantActions(actions.slice(1)), /task_u1_v2_participant_action_trace_invalid/);
  const reordered = [...actions];
  [reordered[8], reordered[9]] = [reordered[9]!, reordered[8]!];
  assert.throws(() => assertU1DifficultyV2ParticipantActions(reordered), /task_u1_v2_participant_action_trace_invalid/);
  const missingHash = [...actions];
  missingHash[0] = { ...missingHash[0]!, rawResponseSha256: 'no-hash' };
  assert.throws(() => assertU1DifficultyV2ParticipantActions(missingHash), /task_u1_v2_participant_action_trace_invalid/);
});

test('U1 quote block identity compares decimal public height with hex RPC block and 0x-prefixed hash', () => {
  const blockHash = `0x${'8'.repeat(64)}`;
  assert.equal(u1QuoteRpcBlockIdentityMatches('52982197', '0x32871b5', blockHash), true);
  assert.equal(u1QuoteRpcBlockIdentityMatches('52982197', '0x32871b6', blockHash), false);
  assert.equal(u1QuoteRpcBlockIdentityMatches('52982197', '0x32871b5', '8'.repeat(64)), false);
});
