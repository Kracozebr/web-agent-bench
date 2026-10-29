import assert from 'node:assert/strict';
import test from 'node:test';
import { hashRecoverySourceMeasurement, makeRecoverySourceEvidence, type RecoverySourceSnapshotInput } from './beta-platform-recovery-source-evidence.js';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function source(overrides: Partial<RecoverySourceSnapshotInput> = {}): RecoverySourceSnapshotInput {
  const measurement = { receipt: { gasUsed: '21000', effectiveGasPrice: '7' }, outcome: 'success' };
  return {
    operationId: '11111111-1111-4111-8111-111111111111', environmentId: 'bef-test',
    generationId: '22222222-2222-4222-8222-222222222222', participantId: 'participant-1',
    idempotencyKeySha256: HASH_A, requestSha256: HASH_B, operationKind: 'transfer', status: 'settled',
    transactionHash: `0x${'c'.repeat(64)}`, receiptStatus: 'success', responseSha256: null,
    generationManifestSha256: HASH_A, environmentManifestSha256: HASH_A,
    selectedActionKind: 'transfer', selectedActionEventCount: 1, selectedActionEventKind: 'transfer',
    selectedActionEventRequestSha256: HASH_B, selectedActionEventSha256: HASH_A,
    selectedOutcome: 'success', selectedTransactionHash: `0x${'c'.repeat(64)}`,
    selectedMeasurementSha256: hashRecoverySourceMeasurement(measurement),
    ...overrides,
  };
}

test('recovery source proof is stable for immutable terminal source and omits a wire response claim', () => {
  const proof = makeRecoverySourceEvidence(source());
  assert.ok(proof);
  assert.equal(proof.schema, 'bef-recovery-source/v1');
  assert.equal(proof.sourceResponseSha256, null);
  assert.equal(proof.selectedMeasurementSha256, source().selectedMeasurementSha256);
  assert.deepEqual(proof, makeRecoverySourceEvidence(source()));
  assert.equal(Object.hasOwn(proof, 'httpStatus'), false);
  assert.equal(Object.hasOwn(proof, 'rawResponseSha256'), false);
});

test('recovery source proof changes when terminal operation, bound event, or measurement changes', () => {
  const original = makeRecoverySourceEvidence(source());
  assert.ok(original);
  assert.notEqual(makeRecoverySourceEvidence(source({ responseSha256: HASH_B }))?.sourceSnapshotSha256,
    original.sourceSnapshotSha256);
  assert.notEqual(makeRecoverySourceEvidence(source({ selectedActionEventSha256: HASH_B }))?.sourceSnapshotSha256,
    original.sourceSnapshotSha256);
  assert.notEqual(makeRecoverySourceEvidence(source({ selectedMeasurementSha256: HASH_B }))?.sourceSnapshotSha256,
    original.sourceSnapshotSha256);
});

test('recovery source proof fails closed without unique event or valid pinned hashes', () => {
  assert.equal(makeRecoverySourceEvidence(source({ selectedActionEventCount: 0 })), null);
  assert.equal(makeRecoverySourceEvidence(source({ selectedActionEventCount: 2 })), null);
  assert.equal(makeRecoverySourceEvidence(source({ selectedActionEventSha256: null })), null);
  assert.equal(makeRecoverySourceEvidence(source({ requestSha256: 'invalid' })), null);
});
