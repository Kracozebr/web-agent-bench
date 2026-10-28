import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import type { RuntimeManifest } from '../manifest.js';
import { findRepositoryRoot, type LoadedProbeRuntime } from './environment.js';
import type { GenerationSession, ProbeContext } from './runner.js';
import {
  fenceDifficultyV2Generation,
  loadDifficultyProfileV2,
  validateDifficultyV2ProfileTask,
  type DifficultyProfileSource,
} from './task-difficulty-v2-capture.js';

async function fixture(): Promise<{ context: ProbeContext; source: DifficultyProfileSource }> {
  const root = findRepositoryRoot();
  const manifestBytes = await readFile(resolve(root, 'infrastructure/benchmark-environment/manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString()) as RuntimeManifest;
  const runtime = {
    root,
    manifest,
    manifestSha256: createHash('sha256').update(manifestBytes).digest('hex'),
  } as LoadedProbeRuntime;
  const source = await loadDifficultyProfileV2({ runtime });
  return { context: { runtime } as ProbeContext, source };
}

test('difficulty-v2 profile candidates bind each approved task and mode to pinned terms', async () => {
  const { context, source } = await fixture();
  for (const mode of ['ranked', 'training'] as const) {
    assert.equal(Array.isArray(validateDifficultyV2ProfileTask(context, source, 'M1', mode)), false);
    assert.equal((validateDifficultyV2ProfileTask(context, source, 'H1', mode) as unknown[]).length, 3);
    assert.equal((validateDifficultyV2ProfileTask(context, source, 'H2', mode) as unknown[]).length, 6);
  }
});

test('difficulty-v2 rejects profile terms that differ from the runtime manifest', async () => {
  const { context, source } = await fixture();
  const tampered = JSON.parse(JSON.stringify(source)) as DifficultyProfileSource;
  const tasks = tampered.profile.tasks as Record<string, unknown>;
  const m1 = tasks.M1 as Record<string, unknown>;
  const modes = m1.modes as Record<string, unknown>;
  const ranked = modes.ranked as Record<string, unknown>;
  ranked.amountUsdcUnits = '1';
  assert.throws(() => validateDifficultyV2ProfileTask(context, tampered, 'M1', 'ranked'),
    /task_difficulty_v2_m1_profile_terms_not_pinned/);
});

test('difficulty-v2 profile rejects a runtime manifest hash mismatch', async () => {
  const { context } = await fixture();
  const runtime = { ...context.runtime, manifestSha256: '0'.repeat(64) } as LoadedProbeRuntime;
  await assert.rejects(loadDifficultyProfileV2({ runtime }), /task_difficulty_v2_profile_manifest_or_classification_mismatch/);
});

test('difficulty-v2 fencing reports signer fencing independently while retaining an unsubmitted operation as unresolved', async () => {
  const generationId = '93432b71-ae46-43c8-afec-9fe60f70c45b';
  const participantId = 'BEF-SC-005-local-reference';
  const payerAddress = `0x${'2'.repeat(40)}`;
  let observerRead = false;
  const context = {
    env: { envId: 'bef-env-a', apiBaseUrl: 'http://localhost:8783', adminKey: 'a'.repeat(32) },
    transport: {
      request: async (request: { url: string }) => {
        assert.equal(request.url, `http://localhost:8783/internal/admin/environments/bef-env-a/generations/${generationId}/fence`);
        return { status: 200, body: { status: 'fenced', signerErased: true, generationId } };
      },
    },
    database: {
      snapshot: async () => {
        observerRead = true;
        return {
          generation: [{ generation_id: generationId, participant_id: participantId, payer_address: payerAddress, status: 'fenced' }],
          operations: [{ operation_id: '096187dd-e30b-4eeb-9d77-38e94fd49bc6', status: 'awaiting_payment', receipt_status: 'not_submitted' }],
          payments: [], deliveries: [], denials: [], x402Observations: [],
        };
      },
    },
  } as unknown as ProbeContext;
  const session = { envId: 'bef-env-a', generationId, participantId, payerAddress } as GenerationSession;
  const report = await fenceDifficultyV2Generation(context, session, 'bts_m1_ranked_difficulty_v2_split_reference');
  const observer = report.independentObserver as Record<string, unknown>;
  assert.equal(observerRead, true);
  assert.equal(report.status, 'fenced');
  assert.equal(observer.economicOutcome, 'unresolved');
  assert.equal(observer.unresolvedOperationCount, 1);
  assert.deepEqual(observer.unresolvedOperations, [{
    operationId: '096187dd-e30b-4eeb-9d77-38e94fd49bc6',
    status: 'awaiting_payment', receiptStatus: 'not_submitted',
  }]);
});
