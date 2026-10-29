import assert from 'node:assert/strict';
import test from 'node:test';
import {
  beginBetaPlatformRecovery,
  finalizeExhaustedBetaPlatformFailure,
  originalBonusRefundDeltas,
  platformRecoveryWindowExpired,
  platformRefundEligible,
} from './beta-platform-recovery.js';
import type { OwnerDatabase } from './db.js';

const HASH = 'a'.repeat(64);
const RUN_ID = '11111111-1111-4111-8111-111111111111';
const ACTION_ID = '22222222-2222-4222-8222-222222222222';
const OWNER_ID = '33333333-3333-4333-8333-333333333333';
const AGENT_ID = '44444444-4444-4444-8444-444444444444';
const GRANT_ID = '55555555-5555-4555-8555-555555555555';
const OPERATION_ID = 'original_operation_123';
const PAYLOAD_HASH = 'b'.repeat(64);
const EXHAUSTION_HASH = 'c'.repeat(64);

function queuedDatabase(responses: unknown[]): OwnerDatabase {
  const execute = async () => {
    const result = responses.shift();
    if (result === undefined) throw new Error('Unexpected database read in recovery replay test');
    return result;
  };
  return { transaction: async (callback: (tx: unknown) => Promise<unknown>) => callback({ execute }) } as unknown as OwnerDatabase;
}

function trustedAuthority() {
  return {
    verifyIncident: async () => ({ runId: RUN_ID, actionId: ACTION_ID, environmentId: 'bef-test', operationId: OPERATION_ID,
      payloadHash: PAYLOAD_HASH, evidenceHash: HASH, source: 'beta_platform_monitor' as const }),
    verifyOperation: async () => null,
    verifyExhaustion: async () => ({ runId: RUN_ID, actionId: ACTION_ID, environmentId: 'bef-test', operationId: OPERATION_ID,
      payloadHash: PAYLOAD_HASH, evidenceHash: EXHAUSTION_HASH, source: 'beta_platform_monitor' as const }),
  };
}

test('the 180-second recovery cutoff is inclusive and uses the supplied database timestamps', () => {
  const started = new Date('2026-10-28T10:00:00.000Z');
  const deadline = new Date(started.getTime() + 180_000);
  assert.equal(platformRecoveryWindowExpired(new Date(deadline.getTime() - 1), deadline), false);
  assert.equal(platformRecoveryWindowExpired(deadline, deadline), true);
});

test('refund restores only the original bonus lot and respects its expiry at the refund instant', () => {
  const at = new Date('2026-10-28T10:00:00.000Z');
  assert.deepEqual(originalBonusRefundDeltas(null, at), { creditTo: 'available' });
  assert.deepEqual(originalBonusRefundDeltas(new Date(at.getTime() + 1), at), { creditTo: 'available' });
  assert.deepEqual(originalBonusRefundDeltas(at, at), { creditTo: 'expired' });
  assert.deepEqual(originalBonusRefundDeltas(new Date(at.getTime() - 1), at), { creditTo: 'expired' });
});

test('platform refund requires a post-start platform cancellation, exact fence, exhausted window and fully resolved operations', () => {
  const eligible = {
    runStarted: true,
    cancellationReason: 'coordinator_platform_failure',
    fenceEvidenceHash: HASH,
    fenceEventMatches: true,
    runHasLiveLease: false,
    windowExpired: true,
    recoveryStatus: 'exhausted',
    originalReceiptStatus: 'observed',
    everyRunActionResolved: true,
  };
  assert.equal(platformRefundEligible(eligible), true);
  assert.equal(platformRefundEligible({ ...eligible, cancellationReason: 'owner_voluntary' }), false);
  assert.equal(platformRefundEligible({ ...eligible, fenceEvidenceHash: null }), false);
  assert.equal(platformRefundEligible({ ...eligible, fenceEventMatches: false }), false);
  assert.equal(platformRefundEligible({ ...eligible, runStarted: false }), false);
  assert.equal(platformRefundEligible({ ...eligible, runHasLiveLease: true }), false);
  assert.equal(platformRefundEligible({ ...eligible, windowExpired: false }), false);
  assert.equal(platformRefundEligible({ ...eligible, recoveryStatus: 'refunded' }), false);
  assert.equal(platformRefundEligible({ ...eligible, originalReceiptStatus: 'unknown' }), false);
  assert.equal(platformRefundEligible({ ...eligible, everyRunActionResolved: false }), false);
});

test('starting platform recovery replays the original record after the action receipt becomes observed', async () => {
  const startedAt = new Date('2026-10-28T10:00:00.000Z');
  const deadlineAt = new Date(startedAt.getTime() + 180_000);
  const db = queuedDatabase([
    [{ owner_id: OWNER_ID }],
    [{ id: OWNER_ID }],
    [{ run_id: RUN_ID, owner_id: OWNER_ID, agent_id: AGENT_ID, run_agent_id: AGENT_ID, task_index: 0,
      action_id: ACTION_ID, environment_id: 'bef-test', operation_id: OPERATION_ID, payload_hash: PAYLOAD_HASH,
      run_status: 'running', receipt_status: 'observed', outbox_status: 'delivered' }],
    [{ run_id: RUN_ID, owner_id: OWNER_ID, agent_id: AGENT_ID, task_index: 0, action_id: ACTION_ID,
      environment_id: 'bef-test', operation_id: OPERATION_ID, payload_hash: PAYLOAD_HASH, incident_evidence_hash: HASH,
      started_at: startedAt, deadline_at: deadlineAt, clock_excluded_ms: 0, status: 'recovered', latest_evidence_hash: 'd'.repeat(64) }],
    [{ id: 'recovery-start-event' }],
  ]);

  const result = await beginBetaPlatformRecovery({ db, authority: trustedAuthority() }, {
    runId: RUN_ID, actionId: ACTION_ID, incidentEvidence: { opaque: true },
  });
  assert.deepEqual(result, { actionId: ACTION_ID, status: 'recovered', startedAt: startedAt.toISOString(),
    deadlineAt: deadlineAt.toISOString(), replayed: true });
});

test('exhausted platform refund replays after run finalization and verifies persisted source lineage', async () => {
  const startedAt = new Date('2026-10-28T10:00:00.000Z');
  const deadlineAt = new Date(startedAt.getTime() + 180_000);
  const refundedAt = new Date(deadlineAt.getTime() + 1);
  const refundOperationId = `runref_${RUN_ID.replaceAll('-', '')}`;
  const responses = [
    [{ owner_id: OWNER_ID }],
    [{ id: OWNER_ID }],
    [{ id: RUN_ID, owner_id: OWNER_ID, status: 'failed', terminal_reason: 'platform_failure_recovery_exhausted',
      started_at: startedAt, cancellation_reason: 'coordinator_platform_failure', cancellation_evidence_hash: HASH }],
    [{ run_id: RUN_ID, owner_id: OWNER_ID, agent_id: AGENT_ID, task_index: 0, action_id: ACTION_ID,
      environment_id: 'bef-test', operation_id: OPERATION_ID, payload_hash: PAYLOAD_HASH, incident_evidence_hash: HASH,
      started_at: startedAt, deadline_at: deadlineAt, clock_excluded_ms: 0, status: 'refunded', latest_evidence_hash: EXHAUSTION_HASH }],
    [{ now: refundedAt }],
    [{ receipt_status: 'observed' }],
    [{ unresolved: false }],
    [{ live: false }],
    [{ matches: true }],
    [{ id: 'recovery-start-event' }],
    [{ evidence_hash: EXHAUSTION_HASH, operation_id: refundOperationId, bonus_refunded_units: '250' }],
    [{ bonus_grant_id: GRANT_ID, amount_units: '250', expires_at: null, reservation_state: 'debited', debit_count: 1, debited_units: '250' }],
    [{ count: 1 }],
    [{ bonus_grant_id: GRANT_ID, operation_id: `${refundOperationId}_${GRANT_ID.replaceAll('-', '')}`,
      source_kind: 'tester_bonus', amount_units: '250', available_delta_units: '250', expired_delta_units: '0', created_at: refundedAt }],
    [{ id: 'settlement-event' }],
    [{ id: 'refund-audit' }],
  ];
  const db = queuedDatabase(responses);

  const result = await finalizeExhaustedBetaPlatformFailure({ db, authority: trustedAuthority() }, {
    runId: RUN_ID, actionId: ACTION_ID, exhaustionEvidence: { opaque: true },
  });
  assert.deepEqual(result, { runId: RUN_ID, status: 'failed', bonusRefundedUnits: '250', replayed: true });
  assert.equal(responses.length, 0, 'replay verifies all persisted refund lineage before returning');
});
