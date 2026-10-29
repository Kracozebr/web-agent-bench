import { createHash } from 'node:crypto';
import { canonicalTaskJson } from './task-release.js';
import type { SafeTaskActionEvidence } from './bef-task-executor.js';

export type RecoverySourceEvidence = {
  schema: 'bef-recovery-source/v1';
  sourceSnapshotSha256: string;
  selectedMeasurementSha256: string;
  sourceResponseSha256: string | null;
};

export type RecoveryActionEvidence = SafeTaskActionEvidence & {
  recoverySource?: RecoverySourceEvidence;
};

/**
 * Immutable BEF source fields used to attest a recovered action. Current
 * generation status, fence timestamps, and live environment state are
 * deliberately excluded: fencing may legitimately change them after the
 * original operation has committed.
 *
 * AICODE-NOTE: Keep this source digest stable across the terminal run's later
 * generation fence; the S1 collector independently validates the live fence.
 */
export type RecoverySourceSnapshotInput = {
  operationId: string;
  environmentId: string;
  generationId: string;
  participantId: string;
  idempotencyKeySha256: string;
  requestSha256: string;
  operationKind: string;
  status: string;
  transactionHash: string | null;
  receiptStatus: string;
  responseSha256: string | null;
  generationManifestSha256: string;
  environmentManifestSha256: string;
  selectedActionKind: string | null;
  selectedActionEventCount: number;
  selectedActionEventKind: string | null;
  selectedActionEventRequestSha256: string | null;
  selectedActionEventSha256: string | null;
  selectedOutcome: string | null;
  selectedTransactionHash: string | null;
  selectedMeasurementSha256: string;
};

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function hashRecoverySourceMeasurement(value: unknown): string {
  return sha256(canonicalTaskJson(value));
}

export function makeRecoverySourceEvidence(input: RecoverySourceSnapshotInput): RecoverySourceEvidence | null {
  const selectedActionEventSha256 = input.selectedActionEventSha256;
  if (!HASH.test(input.idempotencyKeySha256) || !HASH.test(input.requestSha256) ||
      !HASH.test(input.generationManifestSha256) || !HASH.test(input.environmentManifestSha256) ||
      !HASH.test(input.selectedMeasurementSha256) ||
      (input.responseSha256 !== null && !HASH.test(input.responseSha256)) ||
      selectedActionEventSha256 === null || !HASH.test(selectedActionEventSha256) || input.selectedActionEventCount !== 1) return null;

  const selectedMeasurementSha256 = input.selectedMeasurementSha256.toLowerCase();
  const sourceSnapshotSha256 = sha256(canonicalTaskJson({
    schema: 'bef-recovery-source-snapshot/v1',
    operationId: input.operationId.toLowerCase(),
    environmentId: input.environmentId,
    generationId: input.generationId.toLowerCase(),
    participantId: input.participantId,
    idempotencyKeySha256: input.idempotencyKeySha256.toLowerCase(),
    requestSha256: input.requestSha256.toLowerCase(),
    operationKind: input.operationKind,
    status: input.status,
    transactionHash: input.transactionHash?.toLowerCase() ?? null,
    receiptStatus: input.receiptStatus,
    responseSha256: input.responseSha256?.toLowerCase() ?? null,
    generationManifestSha256: input.generationManifestSha256.toLowerCase(),
    environmentManifestSha256: input.environmentManifestSha256.toLowerCase(),
    selectedActionKind: input.selectedActionKind,
    selectedActionEventCount: input.selectedActionEventCount,
    selectedActionEventKind: input.selectedActionEventKind,
    selectedActionEventRequestSha256: input.selectedActionEventRequestSha256?.toLowerCase() ?? null,
    selectedActionEventSha256: selectedActionEventSha256.toLowerCase(),
    selectedOutcome: input.selectedOutcome,
    selectedTransactionHash: input.selectedTransactionHash?.toLowerCase() ?? null,
    selectedMeasurementSha256,
  }));
  return {
    schema: 'bef-recovery-source/v1',
    sourceSnapshotSha256,
    selectedMeasurementSha256,
    sourceResponseSha256: input.responseSha256?.toLowerCase() ?? null,
  };
}

const HASH = /^[0-9a-f]{64}$/i;
