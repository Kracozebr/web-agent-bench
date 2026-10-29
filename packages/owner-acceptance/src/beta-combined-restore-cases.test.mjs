import assert from 'node:assert/strict';
import test from 'node:test';
import { agentAcceptanceResponseSummary, combinedBlockerError, combinedBlockerFailureCode, combinedSourceRunIds,
  exactBonusRedemptionRequestCapture, exactKnownPassingEvaluation, pauseAuditActorsMatch, quoteUnits, runCombinedCallbackDiagnosticScope,
  verifyPostRestoreSourceStability } from './beta-combined-restore-cases.mjs';

const HASH = (character) => character.repeat(64);
const sourceDatabase = 'oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const requiredTables = ['oid_benchmark_run', 'oid_run_operation', 'oid_ledger_operation',
  'oid_bonus_code_claim_operation', 'oid_task_preparation_generation', 'oid_support_report',
  'oid_support_report_audit', 'oid_support_image_upload', 'oid_support_report_deletion_receipt',
  'oid_support_upload_gc_receipt', 'oid_support_report_rate'];

test('combined blocker diagnostics preserve only the genuine runner safe stage and reason code', () => {
  assert.equal(combinedBlockerFailureCode({ status: 'captured_s1_training_run_completed_by_server_worker' }), null);
  assert.equal(combinedBlockerFailureCode({ status: 'blocked', blocker: {
    stage: 'genuine_s1_setup', reasonCode: 'combined_pause_durable_audit_mismatch' } }),
  'combined_active_blocker_genuine_s1_setup_combined_pause_durable_audit_mismatch');
  assert.equal(combinedBlockerFailureCode({ status: 'blocked', blocker: {
    stage: 'message with secret', reasonCode: 'bad reason' } }),
  'combined_active_blocker_unknown_stage_unknown_reason');
});

test('queue acceptance receipt uses the initiating API method without assuming APIResponse.request exists', () => {
  const intentId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const operationId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const response = { status: () => 201, json: async () => ({ run: { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' } }) };
  const receipt = agentAcceptanceResponseSummary({ response, intentId, operationId, replayed: false });

  assert.equal('request' in response, false);
  assert.deepEqual(receipt, { method: 'POST', path: `/api/agent/run-intents/${intentId}/accept`,
    status: 201, operationId, replayed: false });
});

test('paused queue drain accepts the persisted exact rational grade shape and rejects absent violation proof', () => {
  const observed = { outcomeStatus: 'known', outcome: 'passed', credit: { numerator: '1', denominator: '1' },
    mandatoryViolationPresent: false };
  assert.equal(exactKnownPassingEvaluation(observed), true);
  assert.equal(exactKnownPassingEvaluation({ ...observed, credit: 1 }), false);
  assert.equal(exactKnownPassingEvaluation({ ...observed, mandatoryViolationPresent: null }), false);
  assert.equal(exactKnownPassingEvaluation({ ...observed, mandatoryViolationPresent: true }), false);
  assert.equal(exactKnownPassingEvaluation({ ...observed, outcome: 'failed' }), false);
});

test('callback failure diagnostics retain safe class, code, stage and workspace locations only', async () => {
  const credential = 'BPC-secret-credential-that-must-not-be-written';
  const error = new Error(`request failed with Bearer ${credential}`);
  error.name = 'TimeoutError';
  error.code = 'ETIMEDOUT';
  error.stack = `TimeoutError: Bearer ${credential}\n` +
    '    at createQueuedRun (file:///workspace/packages/owner-acceptance/src/beta-combined-restore-cases.mjs:173:28)\n' +
    '    at browserCall (C:\\Users\\example\\private-token.mjs:9:2)\n' +
    '    at /tmp/private-key.mjs:20:1';
  const wrapped = await runCombinedCallbackDiagnosticScope(async (setStage) => {
    setStage('queue_create_accept_and_observer_snapshot');
    throw error;
  }).catch((failure) => failure);
  const blockerError = combinedBlockerError({ status: 'blocked', blocker: {
    stage: 'genuine_s1_setup', reasonCode: wrapped.code }, safeDiagnostic: wrapped.safeDiagnostic });

  assert.equal(wrapped.code, 'ETIMEDOUT');
  assert.deepEqual(wrapped.safeDiagnostic, { schemaVersion: 'beta-combined-callback-diagnostic/v1',
    stage: 'queue_create_accept_and_observer_snapshot', errorName: 'TimeoutError', errorCode: 'ETIMEDOUT',
    topStackFrames: ['/workspace/packages/owner-acceptance/src/beta-combined-restore-cases.mjs:173:28'] });
  assert.equal(blockerError.code, combinedBlockerFailureCode({ status: 'blocked', blocker: {
    stage: 'genuine_s1_setup', reasonCode: 'ETIMEDOUT' } }));
  assert.deepEqual(blockerError.safeDiagnostic, wrapped.safeDiagnostic);
  assert.equal(JSON.stringify(blockerError.safeDiagnostic).includes(credential), false);
  assert.equal(JSON.stringify(blockerError.safeDiagnostic).includes('private-token'), false);
  assert.equal(JSON.stringify(blockerError.safeDiagnostic).includes('Bearer'), false);
});

test('combined pause audit requires the distinct authenticated admin actor identity', () => {
  const adminOwnerId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const participantOwnerId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const control = { changed_by_owner_id: adminOwnerId };
  const event = { actor_owner_id: adminOwnerId };
  assert.equal(pauseAuditActorsMatch({ adminOwnerId, control, event }), true);
  assert.equal(pauseAuditActorsMatch({ adminOwnerId: participantOwnerId, control, event }), false);
  assert.equal(pauseAuditActorsMatch({ adminOwnerId: null, control, event }), false);
});

test('combined redemption capture accepts the exact production UUID request and rejects malformed variants', () => {
  const payload = { code: `BPC-${'a'.repeat(43)}`,
    operationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
  assert.equal(exactBonusRedemptionRequestCapture({ listenerError: null, requestCount: 1, payload }), true);
  assert.equal(exactBonusRedemptionRequestCapture({ listenerError: null, requestCount: 1,
    payload: { ...payload, operationId: 'a'.repeat(32) } }), false);
  assert.equal(exactBonusRedemptionRequestCapture({ listenerError: null, requestCount: 1,
    payload: { ...payload, unexpected: true } }), false);
  assert.equal(exactBonusRedemptionRequestCapture({ listenerError: 'bonus_redemption_request_body_invalid',
    requestCount: 1, payload }), false);
  assert.equal(exactBonusRedemptionRequestCapture({ listenerError: null, requestCount: 2, payload }), false);
});

function sourceSnapshot(overrides = {}) {
  return {
    schemaVersion: 'beta-combined-source-observation/v1',
    sourceDatabase,
    observerIdentity: { databaseRole: 'oid_observer', databaseName: sourceDatabase, transactionReadOnly: 'on' },
    snapshotBoundary: 'admission_frozen_database_quiescent',
    snapshotBoundaryId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    snapshotAt: '2026-10-29T00:00:00.000Z',
    sourceBuildSha256: HASH('a'),
    tableFingerprints: Object.fromEntries(requiredTables.map((name, index) => [name,
      { rowCount: index + 1, sha256: (index + 1).toString(16).padStart(64, '0') }])),
    sequenceSha256: HASH('b'),
    databaseTotalsSha256: HASH('c'),
    financialStateSha256: HASH('d'),
    benchmarkStateSha256: HASH('e'),
    reportStateSha256: HASH('f'),
    reportRateLimitStateSha256: HASH('1'),
    controlOperationalStateSha256: HASH('2'),
    operationBindings: { bonusGrantOperationsSha256: HASH('3'), bonusGrantOperationCount: 1,
      runOperationReceiptsSha256: HASH('4'), runOperationReceiptCount: 2,
      runGenerationReceiptsSha256: HASH('5'), runGenerationReceiptCount: 2,
      reportOperationReceiptsSha256: HASH('6'), reportOperationReceiptCount: 1 },
    originalIds: { completedRunIds: ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'],
      queuedInterruptedUnknownRunIds: ['cccccccc-cccc-4ccc-8ccc-cccccccccccc'],
      operationIds: ['run-operation-1'], bonusGrantOperationIds: ['bonus-operation-1'], reportOperationIds: ['report-operation-1'] },
    imageFiles: [{ bytes: 24786, sha256: HASH('7') }],
    reportDeletionReceipts: [],
    reportCount: 1,
    uploadCount: 1,
    pendingUploadGcReceipts: 0,
    ...overrides,
  };
}

test('queued restore fixture reads the actual run-launch quote sentence without changing six-decimal units', () => {
  assert.equal(quoteUnits('Server quote for this selection: 0.2 USDC. The intent pins this value and rejects a stale release or changed quote.'), 200000n);
  assert.equal(quoteUnits('0.000001 USDC'), 1n);
  for (const value of ['unavailable USDC', '0.0000001 USDC', '-1 USDC', '1 ETH', '1 USDCx']) {
    assert.throws(() => quoteUnits(value), /combined_quote_display_invalid/);
  }
});

test('post-restore source proof compares durable source tables, sequences, business hashes and bindings', () => {
  const before = sourceSnapshot();
  const afterRestore = sourceSnapshot({ snapshotBoundaryId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    snapshotAt: '2026-10-29T00:03:00.000Z' });
  const result = verifyPostRestoreSourceStability({ checkpointSourceAfter: before, afterRestore, sourceDatabase });

  assert.equal(result.status, 'verified');
  assert.equal(Object.values(result.comparisons).every(Boolean), true);
});

test('post-restore source proof rejects any changed table fingerprint even if aggregate hashes are copied', () => {
  const before = sourceSnapshot();
  const afterRestore = sourceSnapshot({ tableFingerprints: { ...sourceSnapshot().tableFingerprints,
    oid_benchmark_run: { rowCount: 1, sha256: HASH('8') } } });

  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before, afterRestore, sourceDatabase }),
    /combined_source_database_changed_after_restores/);
});

test('post-restore source proof rejects sequence and operation-binding drift', () => {
  const before = sourceSnapshot();
  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before,
    afterRestore: sourceSnapshot({ sourceBuildSha256: HASH('9') }), sourceDatabase }),
  /combined_source_database_changed_after_restores/);
  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before,
    afterRestore: sourceSnapshot({ sequenceSha256: HASH('9') }), sourceDatabase }),
  /combined_source_database_changed_after_restores/);
  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before,
    afterRestore: sourceSnapshot({ operationBindings: { ...before.operationBindings, runOperationReceiptCount: 3 } }), sourceDatabase }),
  /combined_source_database_changed_after_restores/);
});

test('post-restore source proof fails closed for missing raw table or binding observations', () => {
  const before = sourceSnapshot();
  const missingTable = sourceSnapshot({ tableFingerprints: { oid_benchmark_run: before.tableFingerprints.oid_benchmark_run } });
  const missingBindings = sourceSnapshot({ operationBindings: null });

  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before,
    afterRestore: missingTable, sourceDatabase }), /combined_source_after_restore_snapshot_incomplete/);
  assert.throws(() => verifyPostRestoreSourceStability({ checkpointSourceAfter: before,
    afterRestore: missingBindings, sourceDatabase }), /combined_source_after_restore_bindings_missing/);
});

test('official source observation includes both S4 and M3 collector runs in addition to the combined recovery runs', () => {
  const ids = ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'ffffffff-ffff-4fff-8fff-ffffffffffff'];
  const result = combinedSourceRunIds({ completedRunId: ids[0], committedRecoveryRunId: ids[0],
    exhaustedRunId: ids[1], blockerRunId: ids[2], queuedRunId: ids[3],
    collectorCases: { S4: { binding: { runId: ids[4] } }, M3: { binding: { runId: ids[5] } } } });
  assert.deepEqual(result, ids);
  assert.throws(() => combinedSourceRunIds({ completedRunId: ids[0], committedRecoveryRunId: ids[0],
    exhaustedRunId: ids[1], blockerRunId: ids[2], queuedRunId: ids[3],
    collectorCases: { S4: { binding: { runId: ids[4] } } } }), /combined_source_run_coverage_incomplete/);
});
