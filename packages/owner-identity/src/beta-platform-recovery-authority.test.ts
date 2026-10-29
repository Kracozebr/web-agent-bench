import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  classifyBefRecoveryOperation,
  recoverySourceSnapshotHash,
  type BetaPlatformRecoveryActionBinding,
  type BefRecoveryOperationSnapshot,
} from './beta-platform-recovery-authority.js';

const RUN_ID = '11111111-1111-4111-8111-111111111111';
const ACTION_ID = '22222222-2222-4222-8222-222222222222';
const OWNER_ID = '33333333-3333-4333-8333-333333333333';
const AGENT_ID = '44444444-4444-4444-8444-444444444444';
const GRANT_ID = '55555555-5555-4555-8555-555555555555';
const OPERATION_ID = '66666666-6666-4666-8666-666666666666';
const GENERATION_ID = '77777777-7777-4777-8777-777777777777';
const TX_HASH = `0x${'a'.repeat(64)}`;
const MANIFEST_HASH = 'b'.repeat(64);
const PAYLOAD_HASH = 'c'.repeat(64);
const REQUEST_HASH = 'd'.repeat(64);
const IDEMPOTENCY_HASH = createHash('sha256').update(`task-action-${ACTION_ID}`).digest('hex');
const RECIPIENT = '0x2222222222222222222222222222222222222222';
const COMMAND = { kind: 'transfer', amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' } as const;
const SELECTED = { kind: 'transfer', amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' };
const MEASURED_SELECTED = { kind: 'transfer', token: '0x3333333333333333333333333333333333333333',
  amountUnits: '125', recipient: RECIPIENT, gasLimit: '21000' };

function actionBinding(command: Record<string, unknown> = COMMAND): BetaPlatformRecoveryActionBinding {
  return {
    actionId: ACTION_ID, runId: RUN_ID, ownerId: OWNER_ID, agentId: AGENT_ID, taskIndex: 0, taskId: 'S1',
    accessGeneration: 4, grantId: GRANT_ID, environmentId: 'bef-test', ownerOperationId: 'task-operation-123',
    payloadHash: PAYLOAD_HASH, actionSequence: '1', actionKind: 'transfer', command, acceptedAt: '2026-10-29T00:00:00.000Z',
    runStatus: 'running', runStartedAt: '2026-10-29T00:00:00.000Z', runDeadline: '2026-10-29T00:02:00.000Z',
    receiptStatus: 'pending', receiptEvidenceHash: null, receiptEvidencePath: null, receiptTransactionHash: null,
    outboxStatus: 'delivered', preparationId: '88888888-8888-4888-8888-888888888888',
    leaseId: '99999999-9999-4999-8999-999999999999', generationId: GENERATION_ID, participantId: 'participant-1',
    manifestSha256: MANIFEST_HASH, applicationSourceSha256: 'e'.repeat(64), preparationStatus: 'ready', leaseStatus: 'leased',
  };
}

function sourceSnapshot(overrides: Partial<BefRecoveryOperationSnapshot> = {}): BefRecoveryOperationSnapshot {
  return {
    operationId: OPERATION_ID, environmentId: 'bef-test', generationId: GENERATION_ID, participantId: 'participant-1',
    idempotencyKeySha256: IDEMPOTENCY_HASH, requestSha256: REQUEST_HASH, operationKind: 'transfer',
    status: 'settled', transactionHash: TX_HASH, receiptStatus: 'success', responseSha256: null,
    generationStatus: 'active', generationManifestSha256: MANIFEST_HASH, environmentManifestSha256: MANIFEST_HASH,
    selectedActionKind: 'transfer', selectedAction: SELECTED, selectedActionEventCount: 1,
    selectedActionEventKind: 'transfer', selectedActionEventAction: SELECTED,
    selectedActionEventRequestSha256: REQUEST_HASH, selectedActionEventSha256: 'f'.repeat(64),
    selectedOutcome: 'success', selectedTransactionHash: TX_HASH,
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED, before: { blockNumber: '1' },
      after: { blockNumber: '2' }, effects: { payerNativeWei: '-1' }, fee: { principalUnits: '125' },
    },
    deliveryContentSha256: null, paymentTransactionHash: null, paymentReceiptStatus: null,
    ...overrides,
  };
}

test('recovery binds a selected execution to the original command and reconstructs only its safe tool response', () => {
  const classified = classifyBefRecoveryOperation(actionBinding(), sourceSnapshot());
  assert.equal(classified.status, 'observed');
  assert.equal(classified.transactionHash, TX_HASH);
  assert.equal(classified.outcome, 'success');
  assert.equal(classified.receiptStatus, 'success');
  assert.equal(classified.receiptGasUsed, '21000');
  assert.equal(classified.receiptEffectiveGasPriceWei, '7');
  assert.equal(classified.toolResponse?.operationId, OPERATION_ID);
  assert.equal(classified.toolResponse?.outcome, 'success');
  assert.deepEqual(classified.toolResponse?.selectedAction, MEASURED_SELECTED);
  assert.deepEqual(classified.toolResponse?.receipt, {
    transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7',
  });
});

test('recovery recognizes a source-bound reverted execution without treating it as success', () => {
  const source = sourceSnapshot({
    status: 'reverted', receiptStatus: 'reverted', selectedOutcome: 'reverted',
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'reverted', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED,
    },
  });
  const classified = classifyBefRecoveryOperation(actionBinding(), source);
  assert.equal(classified.status, 'observed');
  assert.equal(classified.outcome, 'reverted');
  assert.equal(classified.receiptStatus, 'reverted');
  assert.equal(classified.toolResponse?.outcome, 'reverted');
});

test('recovery leaves unknown a changed request, duplicate binding event, or selected input mismatch', () => {
  const action = actionBinding();
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedActionEventRequestSha256: '9'.repeat(64),
  })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({ selectedActionEventCount: 2 })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedAction: { ...SELECTED, amountUnits: '126' },
    selectedActionEventAction: { ...SELECTED, amountUnits: '126' },
  })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(actionBinding({ ...COMMAND, amountUnits: '126' }), sourceSnapshot()).status, 'unknown');
});

test('recovery leaves unknown mismatched terminal receipt and measurement bindings', () => {
  const action = actionBinding();
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({ receiptStatus: 'reverted' })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(action, sourceSnapshot({
    selectedMeasurement: { receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '21000', effectiveGasPrice: '7' },
      transaction: { hash: `0x${'0'.repeat(64)}` }, selectedAction: MEASURED_SELECTED },
  })).status, 'unknown');
});

test('recovery leaves unknown a missing immutable event digest or malformed source gas', () => {
  assert.equal(classifyBefRecoveryOperation(actionBinding(), sourceSnapshot({ selectedActionEventSha256: null })).status, 'unknown');
  assert.equal(classifyBefRecoveryOperation(actionBinding(), sourceSnapshot({
    selectedMeasurement: {
      receipt: { transactionHash: TX_HASH, status: 'success', gasUsed: '1e3', effectiveGasPrice: '7' },
      transaction: { hash: TX_HASH }, selectedAction: MEASURED_SELECTED,
    },
  })).status, 'unknown');
});

test('recovery snapshot binding survives a later generation fence but changes with terminal operation evidence', () => {
  const original = sourceSnapshot({ generationStatus: 'active' });
  assert.equal(recoverySourceSnapshotHash(original), recoverySourceSnapshotHash({ ...original, generationStatus: 'fenced' }));
  assert.notEqual(recoverySourceSnapshotHash(original), recoverySourceSnapshotHash({ ...original,
    selectedMeasurement: { changedAfterCommit: true } }));
});
