import { sql } from 'drizzle-orm';
import { canonicalTaskJson } from './task-release.js';
import { makeRecoverySourceEvidence, type RecoverySourceEvidence } from './beta-platform-recovery-source-evidence.js';

const HASH = /^[0-9a-f]{64}$/i;

export type RecoverySourceFacts = {
  operation: {
    operationId: string; environmentId: string; generationId: string; participantId: string;
    idempotencyKeySha256: string; requestSha256: string; operationKind: string; status: string;
    transactionHash: string | null; receiptStatus: string; responseSha256: string | null;
  };
  generationManifestSha256: string;
  environmentManifestSha256: string;
  selectedExecution: {
    actionKind: string; selectedAction: unknown; outcome: string | null; transactionHash: string | null;
    measurementSha256: string;
  };
  selectedActionBoundEvents: Array<{
    eventKind: string; actionKind: string; requestSha256: string; selectedAction: unknown; eventJsonSha256: string;
  }>;
};

export function recoverySourceEvidenceForFacts(facts: RecoverySourceFacts): RecoverySourceEvidence | null {
  const operation = facts.operation;
  const selected = facts.selectedExecution;
  const [event] = facts.selectedActionBoundEvents;
  if (facts.selectedActionBoundEvents.length !== 1 || !event || event.eventKind !== 'selected_action_bound' ||
      event.actionKind !== selected.actionKind || event.requestSha256.toLowerCase() !== operation.requestSha256.toLowerCase() ||
      canonicalTaskJson(event.selectedAction) !== canonicalTaskJson(selected.selectedAction) ||
      !HASH.test(event.eventJsonSha256) || !HASH.test(selected.measurementSha256)) return null;
  return makeRecoverySourceEvidence({
    operationId: operation.operationId,
    environmentId: operation.environmentId,
    generationId: operation.generationId,
    participantId: operation.participantId,
    idempotencyKeySha256: operation.idempotencyKeySha256,
    requestSha256: operation.requestSha256,
    operationKind: operation.operationKind,
    status: operation.status,
    transactionHash: operation.transactionHash,
    receiptStatus: operation.receiptStatus,
    responseSha256: operation.responseSha256,
    generationManifestSha256: facts.generationManifestSha256,
    environmentManifestSha256: facts.environmentManifestSha256,
    selectedActionKind: selected.actionKind,
    selectedActionEventCount: facts.selectedActionBoundEvents.length,
    selectedActionEventKind: event.actionKind,
    selectedActionEventRequestSha256: event.requestSha256,
    selectedActionEventSha256: event.eventJsonSha256,
    selectedOutcome: selected.outcome,
    selectedTransactionHash: selected.transactionHash,
    selectedMeasurementSha256: selected.measurementSha256,
  });
}

export function recoverySourceEvidenceMatchesFacts(value: unknown, facts: RecoverySourceFacts): boolean {
  if (!isRecord(value) || Object.keys(value).sort().join(',') !==
      'schema,selectedMeasurementSha256,sourceResponseSha256,sourceSnapshotSha256' ||
      value.schema !== 'bef-recovery-source/v1' || !HASH.test(String(value.selectedMeasurementSha256 ?? '')) ||
      !HASH.test(String(value.sourceSnapshotSha256 ?? '')) ||
      (value.sourceResponseSha256 !== null && !HASH.test(String(value.sourceResponseSha256 ?? '')))) return false;
  const expected = recoverySourceEvidenceForFacts(facts);
  return expected !== null && canonicalTaskJson(expected) === canonicalTaskJson(value);
}

export function recoverySourceEvidenceEnvelope(value: unknown): boolean {
  if (!isRecord(value) || value.status !== 'observed' || value.reasonCode !== 'platform_recovery_original_operation_terminal' ||
      Object.hasOwn(value, 'httpStatus') || Object.hasOwn(value, 'rawResponseSha256') || !isRecord(value.recoverySource)) return false;
  const proof = value.recoverySource;
  return Object.keys(proof).sort().join(',') === 'schema,selectedMeasurementSha256,sourceResponseSha256,sourceSnapshotSha256' &&
    proof.schema === 'bef-recovery-source/v1' && HASH.test(String(proof.sourceSnapshotSha256 ?? '')) &&
    HASH.test(String(proof.selectedMeasurementSha256 ?? '')) &&
    (proof.sourceResponseSha256 === null || HASH.test(String(proof.sourceResponseSha256 ?? '')));
}

export function recoveredActionEvidenceIsOwnerBound(
  value: unknown,
  row: RecoveredOwnerLineageRow,
  binding: RecoveredOwnerLineageBinding,
): boolean {
  return recoverySourceEvidenceEnvelope(value) && hasExactRecoveredOwnerLineage(row, binding);
}

export type RecoveredOwnerLineageRow = {
  recovery_action_id?: string | null; recovery_run_id?: string | null; recovery_owner_id?: string | null;
  recovery_agent_id?: string | null; recovery_task_index?: number | null; recovery_environment_id?: string | null;
  recovery_operation_id?: string | null; recovery_payload_hash?: string | null; recovery_incident_evidence_hash?: string | null;
  recovery_started_at?: Date | string | null; recovery_deadline_at?: Date | string | null;
  recovery_clock_excluded_ms?: number | null; recovery_status?: string | null; recovery_latest_evidence_hash?: string | null;
  recovery_observation_count?: number | null; recovery_observation_clock_excluded_ms?: string | null;
  recovery_matching_observation_at?: Date | string | null; recovery_observed_evidence_matches?: boolean | null;
  recovery_started_event_matches?: boolean | null; recovery_observed_event_matches?: boolean | null;
};

export type RecoveredOwnerLineageBinding = {
  actionId: string; runId: string; ownerId: string; agentId: string; taskIndex: number;
  environmentId: string; operationId: string; payloadHash: string; evidenceHash: string;
};

function timestamp(value: Date | string | null | undefined): number {
  const result = value instanceof Date ? value.getTime() : typeof value === 'string' ? Date.parse(value) : Number.NaN;
  return Number.isFinite(result) ? result : Number.NaN;
}

export function hasExactRecoveredOwnerLineage(row: RecoveredOwnerLineageRow, binding: RecoveredOwnerLineageBinding): boolean {
  const startedAt = timestamp(row.recovery_started_at), deadlineAt = timestamp(row.recovery_deadline_at);
  const observationAt = timestamp(row.recovery_matching_observation_at);
  const observationCount = row.recovery_observation_count;
  const excludedMs = row.recovery_clock_excluded_ms;
  let summedExcludedMs = Number.NaN;
  try { summedExcludedMs = Number(row.recovery_observation_clock_excluded_ms); } catch { /* reject below */ }
  return row.recovery_action_id === binding.actionId && row.recovery_run_id === binding.runId &&
    row.recovery_owner_id === binding.ownerId && row.recovery_agent_id === binding.agentId &&
    row.recovery_task_index === binding.taskIndex && row.recovery_environment_id === binding.environmentId &&
    row.recovery_operation_id === binding.operationId && row.recovery_payload_hash === binding.payloadHash &&
    HASH.test(row.recovery_incident_evidence_hash ?? '') && row.recovery_status === 'recovered' &&
    row.recovery_latest_evidence_hash === binding.evidenceHash && HASH.test(binding.evidenceHash) &&
    Number.isSafeInteger(observationCount) && Number(observationCount) > 0 &&
    Number.isSafeInteger(excludedMs) && Number(excludedMs) >= 0 && Number(excludedMs) <= 180_000 &&
    Number.isSafeInteger(summedExcludedMs) && summedExcludedMs === excludedMs &&
    row.recovery_observed_evidence_matches === true && row.recovery_started_event_matches === true &&
    row.recovery_observed_event_matches === true && Number.isFinite(startedAt) && Number.isFinite(deadlineAt) &&
    deadlineAt === startedAt + 180_000 && Number.isFinite(observationAt) && observationAt >= startedAt && observationAt < deadlineAt;
}

/** Shared owner-side receipt and event projection for action queries aliased as `a`. */
export const recoveredOwnerLineageSelectSql = sql`,
  recovery.action_id::text AS recovery_action_id,recovery.run_id::text AS recovery_run_id,
  recovery.owner_id::text AS recovery_owner_id,recovery.agent_id::text AS recovery_agent_id,
  recovery.task_index AS recovery_task_index,recovery.environment_id AS recovery_environment_id,
  recovery.operation_id AS recovery_operation_id,recovery.payload_hash AS recovery_payload_hash,
  recovery.incident_evidence_hash AS recovery_incident_evidence_hash,
  recovery.started_at::text AS recovery_started_at,recovery.deadline_at::text AS recovery_deadline_at,
  recovery.clock_excluded_ms AS recovery_clock_excluded_ms,recovery.status AS recovery_status,
  recovery.latest_evidence_hash AS recovery_latest_evidence_hash,
  (SELECT COUNT(*)::int FROM oid_run_platform_recovery_observation observation
    WHERE observation.action_id=a.id) AS recovery_observation_count,
  (SELECT COALESCE(SUM(observation.clock_excluded_ms),0)::text FROM oid_run_platform_recovery_observation observation
    WHERE observation.action_id=a.id) AS recovery_observation_clock_excluded_ms,
  (SELECT MAX(observation.observed_at)::text FROM oid_run_platform_recovery_observation observation
    WHERE observation.action_id=a.id AND observation.evidence_hash=recovery.latest_evidence_hash
      AND observation.receipt_status='observed') AS recovery_matching_observation_at,
  EXISTS(SELECT 1 FROM oid_run_platform_recovery_observation observation
    WHERE observation.action_id=a.id AND observation.evidence_hash=recovery.latest_evidence_hash
      AND observation.receipt_status='observed') AS recovery_observed_evidence_matches,
  EXISTS(SELECT 1 FROM oid_run_event event
    WHERE event.run_id=a.run_id AND event.event_type='run.platform_recovery_started'
      AND event.payload_json->>'actionId'=a.id::text AND event.payload_json->>'operationId'=a.operation_id
      AND event.payload_json->>'incidentEvidenceHash'=recovery.incident_evidence_hash) AS recovery_started_event_matches,
  EXISTS(SELECT 1 FROM oid_run_event event
    WHERE event.run_id=a.run_id AND event.event_type='run.platform_recovery_observed'
      AND event.payload_json->>'actionId'=a.id::text AND event.payload_json->>'operationId'=a.operation_id
      AND event.payload_json->>'receiptStatus'='observed'
      AND event.payload_json->>'evidenceHash'=recovery.latest_evidence_hash) AS recovery_observed_event_matches`;

export const recoveredOwnerLineageJoinSql = sql`LEFT JOIN oid_run_platform_recovery recovery
  ON recovery.action_id=a.id AND recovery.run_id=a.run_id`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
