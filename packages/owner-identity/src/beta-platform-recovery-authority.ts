import { createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import type { BefReadOnlyPostgresPort } from './bef-observation-ports.js';
import { safeMeasurementProjection, selectedActionMatches, type SafeTaskActionEvidence, type TaskActionEvidenceSink } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import { canonicalTaskJson } from './task-release.js';
import { TaskActionCommandSchema, type TaskActionCommand } from './task-action-service.js';
import type { BetaPlatformRecoveryAuthority } from './beta-platform-recovery.js';
import { hashRecoverySourceMeasurement, makeRecoverySourceEvidence, type RecoveryActionEvidence, type RecoverySourceEvidence } from './beta-platform-recovery-source-evidence.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const OPERATION_ID = /^[A-Za-z0-9_-]{12,128}$/;
const ENVIRONMENT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SAFE_EVIDENCE_PATH = /^(?![A-Za-z]:)(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]{1,512}$/;
const OBSERVER_FAILURE_CODES = new Set([
  'bef_observer_connection_unavailable', 'bef_observer_transaction_unavailable', 'bef_observer_query_unavailable',
  'bef_observer_pool_unavailable', 'bef_observer_role_invalid',
]);

export interface BetaPlatformRecoveryActionBinding {
  actionId: string;
  runId: string;
  ownerId: string;
  agentId: string;
  taskIndex: number;
  taskId: string;
  accessGeneration: number;
  grantId: string;
  environmentId: string;
  ownerOperationId: string;
  payloadHash: string;
  actionSequence: string;
  actionKind: SafeTaskActionEvidence['actionKind'];
  command: Record<string, unknown>;
  acceptedAt: string;
  runStatus: string;
  runStartedAt: string | null;
  runDeadline: string | null;
  receiptStatus: 'pending' | 'observed' | 'rejected_before_execution' | 'unknown';
  receiptEvidenceHash: string | null;
  receiptEvidencePath: string | null;
  receiptTransactionHash: string | null;
  outboxStatus: 'pending' | 'delivered';
  preparationId: string;
  leaseId: string;
  generationId: string;
  participantId: string;
  manifestSha256: string;
  applicationSourceSha256: string;
  preparationStatus: string;
  leaseStatus: string;
}

export interface BefRecoveryOperationSnapshot {
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
  generationStatus: string;
  generationManifestSha256: string | null;
  environmentManifestSha256: string;
  selectedActionKind: string | null;
  selectedAction: unknown;
  selectedActionEventCount: number;
  selectedActionEventKind: string | null;
  selectedActionEventAction: unknown;
  selectedActionEventRequestSha256: string | null;
  selectedActionEventSha256?: string | null;
  selectedOutcome: string | null;
  selectedTransactionHash: string | null;
  selectedMeasurement: unknown;
  deliveryContentSha256: string | null;
  paymentTransactionHash: string | null;
  paymentReceiptStatus: string | null;
}

export type OperationClassification = {
  status: 'observed' | 'rejected_before_execution' | 'unknown';
  transactionHash?: string;
  outcome?: 'success' | 'reverted';
  receiptStatus?: 'success' | 'reverted';
  receiptGasUsed?: string;
  receiptEffectiveGasPriceWei?: string;
  toolResponse?: Record<string, unknown>;
};

function hash(value: unknown): string {
  return createHash('sha256').update(canonicalTaskJson(value)).digest('hex');
}

function asRows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('beta_platform_recovery_owner_query_unavailable');
  return value as T[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function validTimestamp(value: unknown): string | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return new Date(value).toISOString();
  return null;
}

export async function loadBetaPlatformRecoveryActionBinding(
  db: OwnerDatabase,
  actionId: string,
): Promise<BetaPlatformRecoveryActionBinding | null> {
  if (!UUID.test(actionId)) return null;
  const found = asRows<{
    action_id: string; run_id: string; owner_id: string; agent_id: string; task_index: number; task_id: string;
    access_generation: number; run_access_generation: number; grant_id: string; grant_owner_id: string | null;
    grant_agent_id: string | null; grant_access_generation: number | null; environment_id: string; owner_operation_id: string;
    payload_hash: string; action_sequence: string; action_kind: string; command_json: unknown; accepted_at: Date | string;
    run_status: string; run_started_at: Date | string | null; run_deadline: Date | string | null; run_task_id: string | null;
    run_manifest_hash: string; run_release_identity: string;
    receipt_status: string; receipt_evidence_hash: string | null; receipt_evidence_path: string | null;
    receipt_transaction_hash: string | null; outbox_status: string; preparation_id: string | null; lease_id: string | null;
    prep_environment_id: string | null; prep_task_id: string | null; prep_manifest_hash: string | null; prep_release_identity: string | null;
    prep_environment_manifest_hash: string | null; prep_application_source_hash: string | null;
    lease_status: string | null; latest_preparation_status: string | null; latest_generation_id: string | null;
    latest_participant_id: string | null;
    ready_generation_exists: boolean; registered_generation_id: string | null; registered_environment_id: string | null;
    binding_environment_id: string | null; binding_generation_id: string | null; binding_manifest_hash: string | null;
    binding_application_source_hash: string | null; binding_participant_id: string | null;
  }>(await db.execute(sql`SELECT action.id::text AS action_id,action.run_id::text AS run_id,
      action.owner_id::text AS owner_id,action.agent_id::text AS agent_id,action.task_index,action.task_id,
      action.access_generation,run.access_generation AS run_access_generation,action.grant_id::text AS grant_id,
      grant_row.owner_id::text AS grant_owner_id,grant_row.agent_id::text AS grant_agent_id,
      grant_row.access_generation AS grant_access_generation,action.environment_id,action.operation_id AS owner_operation_id,
      action.payload_hash,action.action_sequence::text AS action_sequence,action.action_kind,action.command_json,action.accepted_at,
      run.status AS run_status,run.started_at AS run_started_at,run.overall_deadline AS run_deadline,
      run.manifest_hash AS run_manifest_hash,run.release_identity AS run_release_identity,
      run.task_ids[action.task_index+1] AS run_task_id,receipt.receipt_status,receipt.evidence_hash AS receipt_evidence_hash,
      receipt.evidence_path AS receipt_evidence_path,receipt.transaction_hash AS receipt_transaction_hash,
      outbox.status AS outbox_status,intent.preparation_id::text AS preparation_id,intent.lease_id::text AS lease_id,
      intent.environment_id AS prep_environment_id,intent.task_id AS prep_task_id,intent.manifest_hash AS prep_manifest_hash,
      intent.release_identity AS prep_release_identity,
      intent.environment_manifest_sha256 AS prep_environment_manifest_hash,
      intent.application_source_hash AS prep_application_source_hash,lease.state AS lease_status,
      latest.status AS latest_preparation_status,latest.generation_id::text AS latest_generation_id,
      latest.participant_id AS latest_participant_id,
      EXISTS(SELECT 1 FROM oid_task_preparation_observation ready
        WHERE ready.preparation_id=intent.preparation_id AND ready.status='ready'
          AND ready.generation_id=registered.generation_id
          AND ready.baseline_state_sha256=intent.initial_state_sha256) AS ready_generation_exists,
      registered.generation_id::text AS registered_generation_id,registered.environment_id AS registered_environment_id,
      binding.env_id AS binding_environment_id,binding.generation_id::text AS binding_generation_id,
      binding.manifest_hash AS binding_manifest_hash,binding.application_source_hash AS binding_application_source_hash,
      binding.participant_id AS binding_participant_id
    FROM oid_run_task_action action
    JOIN oid_benchmark_run run ON run.id=action.run_id AND run.owner_id=action.owner_id AND run.agent_id=action.agent_id
    JOIN oid_run_task task ON task.run_id=action.run_id AND task.task_index=action.task_index
    JOIN oid_agent_access_grant grant_row ON grant_row.id=action.grant_id
    JOIN oid_run_task_action_receipt receipt ON receipt.action_id=action.id
    JOIN oid_run_task_action_outbox outbox ON outbox.action_id=action.id
    LEFT JOIN oid_task_preparation_intent intent ON intent.run_id=action.run_id AND intent.task_index=action.task_index
    LEFT JOIN oid_task_environment_lease lease ON lease.lease_id=intent.lease_id AND lease.preparation_id=intent.preparation_id
    LEFT JOIN oid_task_preparation_generation registered ON registered.preparation_id=intent.preparation_id
    LEFT JOIN LATERAL (SELECT status,generation_id,participant_id FROM oid_task_preparation_observation
      WHERE preparation_id=intent.preparation_id ORDER BY revision DESC LIMIT 1) latest ON true
    LEFT JOIN oid_task_execution_binding binding ON binding.run_id=action.run_id AND binding.task_index=action.task_index
    WHERE action.id=${actionId} LIMIT 2`));
  if (found.length !== 1) return null;
  const row = found[0]!;
  const command = isObject(row.command_json) ? row.command_json : null;
  const acceptedAt = validTimestamp(row.accepted_at);
  const runStartedAt = row.run_started_at === null ? null : validTimestamp(row.run_started_at);
  const runDeadline = row.run_deadline === null ? null : validTimestamp(row.run_deadline);
  const manifestSha256 = row.binding_manifest_hash?.toLowerCase();
  const applicationSourceSha256 = row.binding_application_source_hash?.toLowerCase();
  const generationId = row.binding_generation_id?.toLowerCase();
  const participantId = row.binding_participant_id;
  const validKind = ['purchase','pay','retrieve','approve','transfer','wrap','unwrap','swap','inspect_catalog','inspect_offer']
    .includes(row.action_kind);
  const validReceipt = ['pending','observed','rejected_before_execution','unknown'].includes(row.receipt_status);
  const validOutbox = row.outbox_status === 'pending' || row.outbox_status === 'delivered';
  if (!command || !validKind || !validReceipt || !validOutbox || !acceptedAt ||
      !UUID.test(row.action_id) || !UUID.test(row.run_id) || !UUID.test(row.owner_id) || !UUID.test(row.agent_id) ||
      !UUID.test(row.grant_id) || !Number.isSafeInteger(row.task_index) || row.task_index < 0 || row.task_index > 11 ||
      !Number.isSafeInteger(row.access_generation) || row.access_generation < 1 || row.access_generation !== row.run_access_generation ||
      row.grant_owner_id !== row.owner_id || row.grant_agent_id !== row.agent_id || row.grant_access_generation !== row.access_generation ||
      row.run_task_id !== row.task_id || !ENVIRONMENT_ID.test(row.environment_id) ||
      !OPERATION_ID.test(row.owner_operation_id) || !HASH.test(row.payload_hash) ||
      hash({ runId: row.run_id, taskIndex: row.task_index, command }) !== row.payload_hash ||
      !row.preparation_id || !UUID.test(row.preparation_id) || !row.lease_id || !UUID.test(row.lease_id) ||
      !generationId || !UUID.test(generationId) || !participantId || participantId.length < 1 || participantId.length > 160 ||
      row.prep_environment_id !== row.environment_id || row.prep_task_id !== row.task_id ||
      row.prep_manifest_hash?.toLowerCase() !== row.run_manifest_hash.toLowerCase() ||
      row.prep_release_identity !== row.run_release_identity ||
      !row.prep_environment_manifest_hash || !HASH.test(row.prep_environment_manifest_hash) ||
      !row.prep_application_source_hash || !HASH.test(row.prep_application_source_hash) ||
      !['leased','fenced'].includes(row.lease_status ?? '') ||
      !['ready','fenced'].includes(row.latest_preparation_status ?? '') || row.latest_generation_id?.toLowerCase() !== generationId ||
      row.latest_participant_id !== participantId ||
      row.ready_generation_exists !== true || row.registered_generation_id?.toLowerCase() !== generationId ||
      row.registered_environment_id !== row.environment_id || row.binding_environment_id !== row.environment_id ||
      row.binding_generation_id?.toLowerCase() !== generationId || !manifestSha256 || !HASH.test(manifestSha256) ||
      manifestSha256 !== row.prep_environment_manifest_hash.toLowerCase() ||
      !applicationSourceSha256 || !HASH.test(applicationSourceSha256) ||
      applicationSourceSha256 !== row.prep_application_source_hash.toLowerCase() ||
      (row.receipt_evidence_hash !== null && !HASH.test(row.receipt_evidence_hash)) ||
      (row.receipt_transaction_hash !== null && !/^0x[0-9a-f]{64}$/i.test(row.receipt_transaction_hash))) {
    return null;
  }
  return {
    actionId: row.action_id, runId: row.run_id, ownerId: row.owner_id, agentId: row.agent_id,
    taskIndex: row.task_index, taskId: row.task_id, accessGeneration: row.access_generation, grantId: row.grant_id,
    environmentId: row.environment_id, ownerOperationId: row.owner_operation_id, payloadHash: row.payload_hash,
    actionSequence: row.action_sequence, actionKind: row.action_kind as SafeTaskActionEvidence['actionKind'],
    command, acceptedAt, runStatus: row.run_status, runStartedAt, runDeadline,
    receiptStatus: row.receipt_status as BetaPlatformRecoveryActionBinding['receiptStatus'],
    receiptEvidenceHash: row.receipt_evidence_hash, receiptEvidencePath: row.receipt_evidence_path,
    receiptTransactionHash: row.receipt_transaction_hash, outboxStatus: row.outbox_status as BetaPlatformRecoveryActionBinding['outboxStatus'],
    preparationId: row.preparation_id, leaseId: row.lease_id, generationId, participantId,
    manifestSha256, applicationSourceSha256, preparationStatus: row.latest_preparation_status!, leaseStatus: row.lease_status!,
  };
}

export async function readBefRecoveryOperation(
  port: BefReadOnlyPostgresPort,
  action: BetaPlatformRecoveryActionBinding,
): Promise<BefRecoveryOperationSnapshot | null> {
  if (port.environmentId !== action.environmentId) throw new Error('beta_platform_recovery_observer_environment_mismatch');
  const idempotencyHash = createHash('sha256').update(`task-action-${action.actionId}`).digest('hex');
  return port.withRepeatableRead(async (read) => {
    const found = asRows<{
      operation_id: string; env_id: string; generation_id: string; participant_id: string; idempotency_key_sha256: string;
      request_sha256: string; operation_kind: string; status: string; transaction_hash: string | null; receipt_status: string;
      response_sha256: string | null; generation_status: string; generation_manifest_sha256: string | null;
      environment_manifest_sha256: string; selected_action_kind: string | null; selected_action_json: unknown;
      selected_action_event_count: number; selected_action_event_kind: string | null; selected_action_event_action: unknown;
      selected_action_event_request_sha256: string | null; selected_action_event_json: unknown;
      selected_outcome: string | null; selected_transaction_hash: string | null; selected_measurement_json: unknown;
      delivery_content_sha256: string | null; payment_transaction_hash: string | null; payment_receipt_status: string | null;
    }>(await read(`SELECT operation.operation_id::text,operation.env_id,operation.generation_id::text,operation.participant_id,
        trim(operation.idempotency_key_sha256) AS idempotency_key_sha256,trim(operation.request_sha256) AS request_sha256,
        operation.operation_kind,operation.status,operation.transaction_hash,operation.receipt_status,
        trim(operation.response_sha256) AS response_sha256,generation.status AS generation_status,
        trim(generation.manifest_sha256) AS generation_manifest_sha256,trim(environment.manifest_sha256) AS environment_manifest_sha256,
        selected.action_kind AS selected_action_kind,selected.selected_action_json,
        bound_event.event_count AS selected_action_event_count,bound_event.action_kind AS selected_action_event_kind,
        bound_event.selected_action AS selected_action_event_action,bound_event.request_sha256 AS selected_action_event_request_sha256,
        bound_event.event_json AS selected_action_event_json,
        selected.outcome AS selected_outcome,selected.transaction_hash AS selected_transaction_hash,
        selected.measurement_json AS selected_measurement_json,delivery.content_sha256 AS delivery_content_sha256,
        payment.transaction_hash AS payment_transaction_hash,payment.receipt_status AS payment_receipt_status
      FROM public.bef_operation operation
      JOIN public.bef_generation generation ON generation.env_id=operation.env_id AND generation.generation_id=operation.generation_id
      JOIN public.bef_environment environment ON environment.env_id=operation.env_id
      LEFT JOIN public.bef_selected_execution selected ON selected.operation_id=operation.operation_id
        AND selected.env_id=operation.env_id AND selected.generation_id=operation.generation_id
      LEFT JOIN LATERAL (
        SELECT count(*)::int AS event_count,(array_agg(event.event_json->>'actionKind'))[1] AS action_kind,
          (array_agg(event.event_json->'selectedAction'))[1] AS selected_action,
          (array_agg(event.event_json->>'requestSha256'))[1] AS request_sha256,
          (array_agg(event.event_json))[1] AS event_json
        FROM public.bef_selected_execution_event event
        WHERE event.operation_id=operation.operation_id AND event.env_id=operation.env_id
          AND event.generation_id=operation.generation_id AND event.event_kind='selected_action_bound'
      ) bound_event ON true
      LEFT JOIN public.bef_delivery delivery ON delivery.operation_id=operation.operation_id
      LEFT JOIN public.bef_payment payment ON payment.operation_id=operation.operation_id
      WHERE operation.env_id=$1 AND operation.generation_id=$2::uuid AND operation.participant_id=$3
        AND trim(operation.idempotency_key_sha256)=$4 LIMIT 2`,
    [action.environmentId, action.generationId, action.participantId, idempotencyHash]));
    if (found.length > 1) throw new Error('beta_platform_recovery_bef_operation_conflict');
    const row = found[0];
    if (!row) return null;
    const selectedActionEventSha256 = isObject(row.selected_action_event_json)
      ? hash(row.selected_action_event_json) : null;
    if (!UUID.test(row.operation_id) || row.env_id !== action.environmentId || row.generation_id.toLowerCase() !== action.generationId ||
        row.participant_id !== action.participantId || row.idempotency_key_sha256.toLowerCase() !== idempotencyHash ||
        !HASH.test(row.request_sha256) || !HASH.test(row.generation_manifest_sha256 ?? '') ||
        row.generation_manifest_sha256?.toLowerCase() !== action.manifestSha256 ||
        !HASH.test(row.environment_manifest_sha256) || row.environment_manifest_sha256.toLowerCase() !== action.manifestSha256 ||
        !['active','fenced','reset'].includes(row.generation_status) ||
        (row.response_sha256 !== null && !HASH.test(row.response_sha256)) ||
        (row.transaction_hash !== null && !/^0x[0-9a-f]{64}$/i.test(row.transaction_hash)) ||
        (row.selected_transaction_hash !== null && !/^0x[0-9a-f]{64}$/i.test(row.selected_transaction_hash)) ||
        (row.payment_transaction_hash !== null && !/^0x[0-9a-f]{64}$/i.test(row.payment_transaction_hash)) ||
        (row.delivery_content_sha256 !== null && !HASH.test(row.delivery_content_sha256))) {
      return {
        operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
        participantId: row.participant_id, idempotencyKeySha256: row.idempotency_key_sha256,
        requestSha256: row.request_sha256, operationKind: row.operation_kind, status: 'identity_conflict',
        transactionHash: row.transaction_hash, receiptStatus: row.receipt_status, responseSha256: row.response_sha256,
        generationStatus: row.generation_status, generationManifestSha256: row.generation_manifest_sha256,
        environmentManifestSha256: row.environment_manifest_sha256, selectedActionKind: row.selected_action_kind,
        selectedActionEventCount: row.selected_action_event_count, selectedActionEventKind: row.selected_action_event_kind,
        selectedActionEventAction: row.selected_action_event_action,
        selectedActionEventRequestSha256: row.selected_action_event_request_sha256,
        selectedActionEventSha256,
        selectedAction: row.selected_action_json, selectedOutcome: row.selected_outcome,
        selectedTransactionHash: row.selected_transaction_hash, selectedMeasurement: row.selected_measurement_json,
        deliveryContentSha256: row.delivery_content_sha256, paymentTransactionHash: row.payment_transaction_hash,
        paymentReceiptStatus: row.payment_receipt_status,
      };
    }
    return {
      operationId: row.operation_id, environmentId: row.env_id, generationId: row.generation_id,
      participantId: row.participant_id, idempotencyKeySha256: row.idempotency_key_sha256,
      requestSha256: row.request_sha256, operationKind: row.operation_kind, status: row.status,
      transactionHash: row.transaction_hash, receiptStatus: row.receipt_status, responseSha256: row.response_sha256,
      generationStatus: row.generation_status, generationManifestSha256: row.generation_manifest_sha256,
      environmentManifestSha256: row.environment_manifest_sha256, selectedActionKind: row.selected_action_kind,
      selectedActionEventCount: row.selected_action_event_count, selectedActionEventKind: row.selected_action_event_kind,
      selectedActionEventAction: row.selected_action_event_action,
      selectedActionEventRequestSha256: row.selected_action_event_request_sha256,
      selectedActionEventSha256,
      selectedAction: row.selected_action_json, selectedOutcome: row.selected_outcome,
      selectedTransactionHash: row.selected_transaction_hash, selectedMeasurement: row.selected_measurement_json,
      deliveryContentSha256: row.delivery_content_sha256, paymentTransactionHash: row.payment_transaction_hash,
      paymentReceiptStatus: row.payment_receipt_status,
    };
  });
}

export function classifyBefRecoveryOperation(
  action: BetaPlatformRecoveryActionBinding,
  source: BefRecoveryOperationSnapshot,
): OperationClassification {
  const expectedOperationKind = action.actionKind === 'inspect_catalog' ? 'catalog' :
    action.actionKind === 'inspect_offer' ? 'offer' : action.actionKind;
  if (source.status === 'identity_conflict' || source.environmentId !== action.environmentId ||
      source.generationId.toLowerCase() !== action.generationId || source.participantId !== action.participantId ||
      source.idempotencyKeySha256.toLowerCase() !== createHash('sha256').update(`task-action-${action.actionId}`).digest('hex') ||
      source.generationManifestSha256?.toLowerCase() !== action.manifestSha256 ||
      source.environmentManifestSha256.toLowerCase() !== action.manifestSha256 || source.operationKind !== expectedOperationKind ||
      !HASH.test(source.requestSha256)) return { status: 'unknown' };

  const parsedCommand = TaskActionCommandSchema.safeParse(action.command);
  if (!parsedCommand.success || parsedCommand.data.kind === 'purchase' ||
      parsedCommand.data.kind !== action.actionKind || source.selectedActionKind !== action.actionKind ||
      source.operationKind !== action.actionKind || source.selectedActionEventCount !== 1 ||
      source.selectedActionEventKind !== action.actionKind ||
      source.selectedActionEventRequestSha256?.toLowerCase() !== source.requestSha256.toLowerCase() ||
      !isObject(source.selectedAction) || !isObject(source.selectedActionEventAction) ||
      canonicalTaskJson(source.selectedActionEventAction) !== canonicalTaskJson(source.selectedAction) ||
      !selectedActionMatches(parsedCommand.data as Exclude<TaskActionCommand, { kind: 'purchase' }>, source.selectedAction)) {
    return { status: 'unknown' };
  }

  const txHash = source.transactionHash?.toLowerCase() ?? null;
  if (source.status === 'rejected' && source.receiptStatus === 'not_submitted' && txHash === null &&
      source.selectedOutcome === 'rejected' && source.selectedTransactionHash === null) {
    return { status: 'rejected_before_execution' };
  }

  const outcome = source.selectedOutcome;
  if (outcome !== 'success' && outcome !== 'reverted') return { status: 'unknown' };
  const terminalOperationMatches = outcome === 'success'
    ? source.status === 'settled' && source.receiptStatus === 'success'
    : source.status === 'reverted' && source.receiptStatus === 'reverted';
  if (!terminalOperationMatches || txHash === null || source.selectedMeasurement === null || source.selectedMeasurement === undefined ||
      source.selectedTransactionHash?.toLowerCase() !== txHash) return { status: 'unknown' };
  if (!recoverySourceEvidenceForOperation(source)) return { status: 'unknown' };
  const toolResponse = recoveredSelectedActionToolResponse(parsedCommand.data as Exclude<TaskActionCommand, { kind: 'purchase' }>,
    source, txHash, outcome);
  if (!toolResponse) return { status: 'unknown' };
  const receipt = isObject(toolResponse.receipt) ? toolResponse.receipt : null;
  if (typeof receipt?.gasUsed !== 'string' || typeof receipt.effectiveGasPrice !== 'string') return { status: 'unknown' };
  return { status: 'observed', transactionHash: txHash, outcome, receiptStatus: outcome,
    receiptGasUsed: receipt.gasUsed, receiptEffectiveGasPriceWei: receipt.effectiveGasPrice, toolResponse };
}

export function recoverySourceEvidenceForOperation(source: BefRecoveryOperationSnapshot): RecoverySourceEvidence | null {
  return makeRecoverySourceEvidence({
    operationId: source.operationId,
    environmentId: source.environmentId,
    generationId: source.generationId,
    participantId: source.participantId,
    idempotencyKeySha256: source.idempotencyKeySha256,
    requestSha256: source.requestSha256,
    operationKind: source.operationKind,
    status: source.status,
    transactionHash: source.transactionHash,
    receiptStatus: source.receiptStatus,
    responseSha256: source.responseSha256,
    generationManifestSha256: source.generationManifestSha256 ?? '',
    environmentManifestSha256: source.environmentManifestSha256,
    selectedActionKind: source.selectedActionKind,
    selectedActionEventCount: source.selectedActionEventCount,
    selectedActionEventKind: source.selectedActionEventKind,
    selectedActionEventRequestSha256: source.selectedActionEventRequestSha256,
    selectedActionEventSha256: source.selectedActionEventSha256 ?? null,
    selectedOutcome: source.selectedOutcome,
    selectedTransactionHash: source.selectedTransactionHash,
    selectedMeasurementSha256: hashRecoverySourceMeasurement(source.selectedMeasurement),
  });
}

function recoveredSelectedActionToolResponse(
  command: Exclude<TaskActionCommand, { kind: 'purchase' }>,
  source: BefRecoveryOperationSnapshot,
  txHash: string,
  outcome: 'success' | 'reverted',
): Record<string, unknown> | null {
  const measurement = source.selectedMeasurement;
  if (!isObject(measurement) || !isObject(measurement.receipt) || !isObject(measurement.transaction) ||
      !isObject(measurement.selectedAction)) return null;
  const receipt = measurement.receipt;
  const transaction = measurement.transaction;
  if (receipt.transactionHash !== txHash || receipt.status !== outcome || transaction.hash !== txHash ||
      typeof receipt.gasUsed !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(receipt.gasUsed) ||
      typeof receipt.effectiveGasPrice !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(receipt.effectiveGasPrice) ||
      !selectedActionMatches(command, measurement.selectedAction)) return null;
  const responseBody = { ...measurement, operationId: source.operationId, outcome };
  let projected: Record<string, unknown> | undefined;
  try { projected = safeMeasurementProjection(responseBody); }
  catch { return null; }
  if (!projected || projected.operationId !== source.operationId || projected.outcome !== outcome ||
      !isObject(projected.receipt) || !isObject(projected.transaction) ||
      projected.receipt.transactionHash !== txHash || projected.transaction.hash !== txHash) return null;
  return projected;
}

export type RecoveryAttestationKind = 'incident' | 'operation' | 'exhaustion';
export type RecoveryAttestation = {
  kind: RecoveryAttestationKind;
  runId: string; actionId: string; environmentId: string; operationId: string; payloadHash: string;
  evidenceHash: string; evidencePath?: string; status?: OperationClassification['status']; clockExcludedMs?: number;
  transactionHash?: string; toolResponse?: Record<string, unknown>;
  sourceCode?: string; sourceSnapshotHash?: string;
};

export function isSafeRecoveryEvidenceReference(value: { path: string; sha256: string }): boolean {
  return HASH.test(value.sha256) && SAFE_EVIDENCE_PATH.test(value.path);
}

export function digestRecoveryEvidence(value: unknown): string { return hash(value); }

export function makeRecoveryEvidencePacket(action: BetaPlatformRecoveryActionBinding, input: {
  status: SafeTaskActionEvidence['status']; reasonCode: string; befOperationId?: string; transactionHash?: string;
  outcome?: 'success' | 'reverted'; receiptStatus?: 'success' | 'reverted'; rawResponseSha256?: string;
  receiptGasUsed?: string; receiptEffectiveGasPriceWei?: string;
  toolResponse?: Record<string, unknown>; recoverySource?: RecoverySourceEvidence;
}): RecoveryActionEvidence {
  return {
    schema: 'bef-task-action-observation-v1', actionId: action.actionId, runId: action.runId,
    taskIndex: action.taskIndex, actionSequence: action.actionSequence, ownerOperationId: action.ownerOperationId,
    actionKind: action.actionKind, commandSha256: action.payloadHash, environmentId: action.environmentId,
    generationId: action.generationId, manifestSha256: action.manifestSha256,
    applicationSourceSha256: action.applicationSourceSha256, idempotencyKey: `task-action-${action.actionId}`,
    status: input.status, reasonCode: input.reasonCode,
    ...(input.befOperationId ? { befOperationId: input.befOperationId } : {}),
    ...(input.transactionHash ? { transactionHash: input.transactionHash } : {}),
    ...(input.outcome ? { outcome: input.outcome } : {}),
    ...(input.receiptStatus ? { receiptStatus: input.receiptStatus } : {}),
    ...(input.rawResponseSha256 ? { rawResponseSha256: input.rawResponseSha256 } : {}),
    ...(input.receiptGasUsed ? { receiptGasUsed: input.receiptGasUsed } : {}),
    ...(input.receiptEffectiveGasPriceWei ? { receiptEffectiveGasPriceWei: input.receiptEffectiveGasPriceWei } : {}),
    ...(input.toolResponse ? { participantToolResponse: input.toolResponse } : {}),
    ...(input.recoverySource ? { recoverySource: input.recoverySource } : {}),
  };
}

export async function writeRecoveryEvidence(
  sink: TaskActionEvidenceSink,
  action: BetaPlatformRecoveryActionBinding,
  input: Parameters<typeof makeRecoveryEvidencePacket>[1],
): Promise<{ path: string; sha256: string; packet: RecoveryActionEvidence }> {
  const packet = makeRecoveryEvidencePacket(action, input);
  const reference = await sink.write(packet);
  if (!isSafeRecoveryEvidenceReference(reference)) throw new Error('beta_platform_recovery_evidence_reference_invalid');
  return { ...reference, packet };
}

export function sameRecoveryAction(a: BetaPlatformRecoveryActionBinding, b: BetaPlatformRecoveryActionBinding): boolean {
  return a.actionId === b.actionId && a.runId === b.runId && a.ownerId === b.ownerId && a.agentId === b.agentId &&
    a.taskIndex === b.taskIndex && a.taskId === b.taskId && a.accessGeneration === b.accessGeneration && a.grantId === b.grantId &&
    a.environmentId === b.environmentId && a.ownerOperationId === b.ownerOperationId && a.payloadHash === b.payloadHash &&
    a.generationId === b.generationId && a.participantId === b.participantId && a.manifestSha256 === b.manifestSha256 &&
    a.applicationSourceSha256 === b.applicationSourceSha256 && canonicalTaskJson(a.command) === canonicalTaskJson(b.command);
}

export function recoverySourceSnapshotHash(source: BefRecoveryOperationSnapshot): string {
  // Generation fencing can occur between the original observer read and its
  // verification. It does not change the immutable terminal operation facts.
  const { generationStatus: _generationStatus, ...immutableSource } = source;
  return hash(immutableSource);
}

export function safeBefObserverFailureCode(error: unknown): string | null {
  if (!error || typeof error !== 'object') return null;
  const value = error as { name?: unknown; message?: unknown };
  return value.name === 'BefObservationPortError' && typeof value.message === 'string' && OBSERVER_FAILURE_CODES.has(value.message)
    ? value.message : null;
}

export function isTerminalBefRecoverySource(source: BefRecoveryOperationSnapshot): boolean {
  return source.status === 'identity_conflict' || ['settled','reverted','delivered','rejected','settlement_unknown'].includes(source.status);
}

export interface BetaRecoveryFenceSnapshot {
  preparationId: string;
  leaseId: string;
  environmentId: string;
  generationId: string;
  manifestSha256: string;
  applicationSourceSha256: string;
  generationFencedAt: string;
  preparationFenceConfirmedAt: string;
  publicPinsSha256: string;
  preparationManifestSha256: string;
  environmentManifestSha256: string;
}

export async function readBetaPlatformRecoveryFenceSet(
  db: OwnerDatabase,
  portByEnvironment: Readonly<Record<string, BefReadOnlyPostgresPort>>,
  runId: string,
): Promise<BetaRecoveryFenceSnapshot[] | null> {
  if (!UUID.test(runId)) return null;
  const rows = asRows<{
    preparation_id: string; lease_id: string; environment_id: string; lease_status: string; fence_evidence: unknown;
    environment_manifest_sha256: string; application_source_hash: string; latest_status: string | null;
    latest_generation_id: string | null; registered_generation_id: string | null; registered_environment_id: string | null;
    binding_environment_id: string | null; binding_generation_id: string | null; binding_manifest_hash: string | null;
    binding_application_source_hash: string | null;
  }>(await db.execute(sql`SELECT intent.preparation_id::text AS preparation_id,intent.lease_id::text AS lease_id,
      intent.environment_id,lease.state AS lease_status,lease.fence_evidence,
      intent.environment_manifest_sha256,intent.application_source_hash,
      latest.status AS latest_status,latest.generation_id::text AS latest_generation_id,
      registered.generation_id::text AS registered_generation_id,registered.environment_id AS registered_environment_id,
      binding.env_id AS binding_environment_id,binding.generation_id::text AS binding_generation_id,
      binding.manifest_hash AS binding_manifest_hash,binding.application_source_hash AS binding_application_source_hash
    FROM oid_task_preparation_intent intent
    JOIN oid_task_environment_lease lease ON lease.preparation_id=intent.preparation_id AND lease.lease_id=intent.lease_id
    LEFT JOIN oid_task_preparation_generation registered ON registered.preparation_id=intent.preparation_id
    LEFT JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation
      WHERE preparation_id=intent.preparation_id ORDER BY revision DESC LIMIT 1) latest ON true
    LEFT JOIN oid_task_execution_binding binding ON binding.run_id=intent.run_id AND binding.task_index=intent.task_index
    WHERE intent.run_id=${runId} ORDER BY intent.task_index`));
  if (rows.length === 0) return null;
  const proofs: BetaRecoveryFenceSnapshot[] = [];
  for (const row of rows) {
    if (row.lease_status !== 'fenced' || !row.preparation_id || !UUID.test(row.preparation_id) ||
        !row.lease_id || !UUID.test(row.lease_id) || !ENVIRONMENT_ID.test(row.environment_id) ||
        !HASH.test(row.environment_manifest_sha256) || !HASH.test(row.application_source_hash) ||
        !isObject(row.fence_evidence) || row.fence_evidence.confirmed !== true ||
        row.fence_evidence.preparationId !== row.preparation_id || row.fence_evidence.leaseId !== row.lease_id ||
        row.fence_evidence.environmentId !== row.environment_id) return null;
    if (!row.registered_generation_id) continue;
    const generationId = row.registered_generation_id.toLowerCase();
    const manifestSha256 = row.binding_manifest_hash?.toLowerCase();
    const applicationSourceSha256 = row.binding_application_source_hash?.toLowerCase();
    if (!UUID.test(generationId) || row.registered_environment_id !== row.environment_id ||
        !['fenced'].includes(row.latest_status ?? '') || row.latest_generation_id?.toLowerCase() !== generationId ||
        row.binding_environment_id !== row.environment_id || row.binding_generation_id?.toLowerCase() !== generationId ||
        !manifestSha256 || !HASH.test(manifestSha256) || manifestSha256 !== row.environment_manifest_sha256.toLowerCase() ||
        !applicationSourceSha256 || !HASH.test(applicationSourceSha256) ||
        applicationSourceSha256 !== row.application_source_hash.toLowerCase() ||
        row.fence_evidence.generationId !== generationId) return null;
    const port = portByEnvironment[row.environment_id];
    if (!port || port.environmentId !== row.environment_id) return null;
    const proof = await port.readFenceProof({ preparationId: row.preparation_id, generationId }).catch(() => null);
    if (!proof?.generation || !proof.preparation || proof.generation.generation_id.toLowerCase() !== generationId ||
        proof.generation.env_id !== row.environment_id || proof.generation.status !== 'fenced' ||
        !proof.generation.fenced_at || !validTimestamp(proof.generation.fenced_at) ||
        proof.preparation.preparation_id.toLowerCase() !== row.preparation_id ||
        proof.preparation.preparation_generation_id.toLowerCase() !== generationId || proof.preparation.status !== 'fenced' ||
        !proof.preparation.fence_confirmed_at || !validTimestamp(proof.preparation.fence_confirmed_at) ||
        proof.preparation.manifest_sha256.toLowerCase() !== manifestSha256 ||
        proof.preparation.environment_manifest_hash.toLowerCase() !== manifestSha256) return null;
    proofs.push({ preparationId: row.preparation_id, leaseId: row.lease_id, environmentId: row.environment_id,
      generationId, manifestSha256, applicationSourceSha256,
      generationFencedAt: new Date(proof.generation.fenced_at).toISOString(),
      preparationFenceConfirmedAt: new Date(proof.preparation.fence_confirmed_at).toISOString(),
      publicPinsSha256: proof.preparation.public_pins_sha256.toLowerCase(),
      preparationManifestSha256: proof.preparation.manifest_sha256.toLowerCase(),
      environmentManifestSha256: proof.preparation.environment_manifest_hash.toLowerCase() });
  }
  return proofs.length ? proofs : null;
}

export function betaRecoveryFenceSetHash(proofs: readonly BetaRecoveryFenceSnapshot[]): string {
  return hash([...proofs].sort((a, b) => `${a.environmentId}/${a.generationId}/${a.preparationId}`
    .localeCompare(`${b.environmentId}/${b.generationId}/${b.preparationId}`)));
}

export function betaRecoveryExhaustionEvidenceHash(input: {
  action: BetaPlatformRecoveryActionBinding;
  incidentEvidenceHash: string;
  startedAt: string;
  deadlineAt: string;
  clockExcludedMs: number;
  cancellationEvidenceHash: string;
  fenceSetHash: string;
}): string {
  return hash({ schema: 'bpc-platform-recovery-exhaustion/v1', runId: input.action.runId,
    actionId: input.action.actionId, ownerId: input.action.ownerId, agentId: input.action.agentId,
    taskIndex: input.action.taskIndex, environmentId: input.action.environmentId,
    ownerOperationId: input.action.ownerOperationId, payloadHash: input.action.payloadHash,
    preparationId: input.action.preparationId, leaseId: input.action.leaseId, generationId: input.action.generationId,
    manifestSha256: input.action.manifestSha256, applicationSourceSha256: input.action.applicationSourceSha256,
    incidentEvidenceHash: input.incidentEvidenceHash, startedAt: input.startedAt, deadlineAt: input.deadlineAt,
    clockExcludedMs: input.clockExcludedMs, cancellationEvidenceHash: input.cancellationEvidenceHash,
    fenceSetHash: input.fenceSetHash });
}

export interface RecoveryAuthorityContext {
  db: OwnerDatabase;
  sink: TaskActionEvidenceSink;
  portByEnvironment: Readonly<Record<string, BefReadOnlyPostgresPort>>;
}

export interface RecoveryAuthorityRuntime {
  authority: BetaPlatformRecoveryAuthority;
  issue(kind: RecoveryAttestationKind, value: Omit<RecoveryAttestation, 'kind'>): unknown;
  verifyIssued(evidence: unknown, kind: RecoveryAttestationKind): RecoveryAttestation | null;
  context: RecoveryAuthorityContext;
}

/** Factory used only by the in-process monitor. Issued evidence is object-capability based. */
export function createRecoveryAuthorityRuntime(context: RecoveryAuthorityContext): RecoveryAuthorityRuntime {
  const issued = new WeakMap<object, RecoveryAttestation>();
  const issue = (kind: RecoveryAttestationKind, value: Omit<RecoveryAttestation, 'kind'>): object => {
    const capability = Object.freeze({});
    issued.set(capability, { ...value, kind });
    return capability;
  };
  const verifyIssued = (evidence: unknown, kind: RecoveryAttestationKind): RecoveryAttestation | null => {
    if (!evidence || typeof evidence !== 'object') return null;
    const value = issued.get(evidence);
    return value?.kind === kind ? value : null;
  };
  const authority: BetaPlatformRecoveryAuthority = {
    async verifyIncident(evidence) {
      const value = verifyIssued(evidence, 'incident');
      if (!value || !value.sourceCode || !HASH.test(value.evidenceHash)) return null;
      const action = await loadBetaPlatformRecoveryActionBinding(context.db, value.actionId);
      if (!action || action.runId !== value.runId || action.environmentId !== value.environmentId ||
          action.ownerOperationId !== value.operationId || action.payloadHash !== value.payloadHash ||
          !['pending','unknown'].includes(action.receiptStatus) || action.outboxStatus !== 'delivered') return null;
      if (value.sourceCode === 'platform_original_operation_not_found') {
        const port = context.portByEnvironment[action.environmentId];
        if (!port) return null;
        let source: BefRecoveryOperationSnapshot | null;
        try { source = await readBefRecoveryOperation(port, action); } catch { return null; }
        if (source !== null) return null;
      } else if (!OBSERVER_FAILURE_CODES.has(value.sourceCode)) {
        const port = context.portByEnvironment[action.environmentId];
        if (!port || !value.sourceSnapshotHash) return null;
        const source = await readBefRecoveryOperation(port, action).catch(() => null);
        if (!source || recoverySourceSnapshotHash(source) !== value.sourceSnapshotHash || !isTerminalBefRecoverySource(source)) return null;
      }
      return { runId: value.runId, actionId: value.actionId, environmentId: value.environmentId,
        operationId: value.operationId, payloadHash: value.payloadHash, evidenceHash: value.evidenceHash,
        source: 'beta_platform_monitor' as const };
    },
    async verifyOperation(evidence) {
      const value = verifyIssued(evidence, 'operation');
      if (!value || !value.status || !value.evidencePath || typeof value.clockExcludedMs !== 'number' ||
          !Number.isSafeInteger(value.clockExcludedMs) ||
          !HASH.test(value.evidenceHash)) return null;
      const action = await loadBetaPlatformRecoveryActionBinding(context.db, value.actionId);
      if (!action || action.runId !== value.runId || action.environmentId !== value.environmentId ||
          action.ownerOperationId !== value.operationId || action.payloadHash !== value.payloadHash) return null;
      const port = context.portByEnvironment[action.environmentId];
      if (!port) return null;
      let source: BefRecoveryOperationSnapshot | null = null;
      let sourceError: unknown;
      try { source = await readBefRecoveryOperation(port, action); }
      catch (error) { sourceError = error; }
      if (source) {
        const classification = classifyBefRecoveryOperation(action, source);
        const snapshotHash = recoverySourceSnapshotHash(source);
        if (snapshotHash !== value.sourceSnapshotHash || classification.status !== value.status ||
            (classification.transactionHash ?? undefined) !== value.transactionHash ||
            canonicalTaskJson(classification.toolResponse ?? null) !== canonicalTaskJson(value.toolResponse ?? null)) return null;
      } else {
        if (value.status !== 'unknown' || !value.sourceCode) return null;
        if (value.sourceCode === 'platform_original_operation_absent_after_fence') {
          if (sourceError !== undefined || action.receiptStatus !== 'pending' || value.clockExcludedMs !== 0 ||
              value.transactionHash !== undefined || value.toolResponse !== undefined) return null;
          const recoveryRows = asRows<{ started_at: Date | string; deadline_at: Date | string }>(await context.db.execute(sql`SELECT started_at,deadline_at
            FROM oid_run_platform_recovery WHERE action_id=${action.actionId} AND run_id=${action.runId} LIMIT 2`));
          const recovery = recoveryRows[0];
          const startedAt = recovery ? validTimestamp(recovery.started_at) : null;
          const deadlineAt = recovery ? validTimestamp(recovery.deadline_at) : null;
          const nowRows = asRows<{ now: Date | string }>(await context.db.execute(sql`SELECT clock_timestamp() AS now`));
          const now = validTimestamp(nowRows[0]?.now);
          const runRows = asRows<{ status: string; cancellation_reason: string | null; cancellation_evidence_hash: string | null }>(
            await context.db.execute(sql`SELECT status,cancellation_reason,cancellation_evidence_hash
              FROM oid_benchmark_run WHERE id=${action.runId} AND owner_id=${action.ownerId} LIMIT 2`));
          const run = runRows[0];
          const eventRows = run?.cancellation_evidence_hash ? asRows<{ matches: boolean }>(await context.db.execute(sql`SELECT EXISTS(
            SELECT 1 FROM oid_run_event WHERE run_id=${action.runId} AND event_type='run.cancelled.after_start'
              AND payload_json->>'reason'='coordinator_platform_failure'
              AND payload_json->>'fenceEvidenceHash'=${run.cancellation_evidence_hash}) AS matches`)) : [];
          const proofs = await readBetaPlatformRecoveryFenceSet(context.db, context.portByEnvironment, action.runId).catch(() => null);
          if (!startedAt || !deadlineAt || !now || Date.parse(deadlineAt) !== Date.parse(startedAt) + 180_000 ||
              Date.parse(now) < Date.parse(deadlineAt) || !run || !['cancelled','unknown'].includes(run.status) ||
              run.cancellation_reason !== 'coordinator_platform_failure' || !run.cancellation_evidence_hash ||
              !HASH.test(run.cancellation_evidence_hash) || eventRows[0]?.matches !== true ||
              !proofs?.some((proof) => proof.preparationId === action.preparationId && proof.generationId === action.generationId)) return null;
        } else if (OBSERVER_FAILURE_CODES.has(value.sourceCode)) {
          if (safeBefObserverFailureCode(sourceError) !== value.sourceCode) return null;
        } else return null;
      }
      return { runId: value.runId, actionId: value.actionId, environmentId: value.environmentId,
        operationId: value.operationId, payloadHash: value.payloadHash, evidenceHash: value.evidenceHash,
        evidencePath: value.evidencePath, status: value.status, clockExcludedMs: value.clockExcludedMs,
        ...(value.transactionHash ? { transactionHash: value.transactionHash } : {}),
        ...(value.toolResponse ? { toolResponse: value.toolResponse } : {}) };
    },
    async verifyExhaustion(evidence) {
      const value = verifyIssued(evidence, 'exhaustion');
      if (!value || !value.sourceSnapshotHash || !HASH.test(value.evidenceHash)) return null;
      const action = await loadBetaPlatformRecoveryActionBinding(context.db, value.actionId);
      if (!action || action.runId !== value.runId || action.environmentId !== value.environmentId ||
          action.ownerOperationId !== value.operationId || action.payloadHash !== value.payloadHash) return null;
      const recoveryRows = asRows<{ owner_id: string; agent_id: string; task_index: number; environment_id: string;
        operation_id: string; payload_hash: string; incident_evidence_hash: string; started_at: Date | string;
        deadline_at: Date | string; clock_excluded_ms: number }>(await context.db.execute(sql`SELECT owner_id::text,agent_id::text,task_index,
          environment_id,operation_id,payload_hash,incident_evidence_hash,started_at,deadline_at,clock_excluded_ms
        FROM oid_run_platform_recovery WHERE action_id=${action.actionId} AND run_id=${action.runId} LIMIT 2`));
      if (recoveryRows.length !== 1) return null;
      const recovery = recoveryRows[0]!;
      const startedAt = validTimestamp(recovery.started_at);
      const deadlineAt = validTimestamp(recovery.deadline_at);
      const runRows = asRows<{ status: string; cancellation_reason: string | null; cancellation_evidence_hash: string | null }>(
        await context.db.execute(sql`SELECT status,cancellation_reason,cancellation_evidence_hash
          FROM oid_benchmark_run WHERE id=${action.runId} AND owner_id=${action.ownerId} LIMIT 2`));
      const run = runRows[0];
      const nowRows = asRows<{ now: Date | string }>(await context.db.execute(sql`SELECT clock_timestamp() AS now`));
      const now = validTimestamp(nowRows[0]?.now);
      if (!run || !startedAt || !deadlineAt || !now || run.cancellation_reason !== 'coordinator_platform_failure' ||
          !run.cancellation_evidence_hash || !HASH.test(run.cancellation_evidence_hash) ||
          !['cancelled','unknown'].includes(run.status) ||
          Date.parse(deadlineAt) !== Date.parse(startedAt) + 180_000 || Date.parse(now) < Date.parse(deadlineAt) ||
          recovery.owner_id !== action.ownerId || recovery.agent_id !== action.agentId || recovery.task_index !== action.taskIndex ||
          recovery.environment_id !== action.environmentId || recovery.operation_id !== action.ownerOperationId ||
          recovery.payload_hash !== action.payloadHash || !HASH.test(recovery.incident_evidence_hash) ||
          !Number.isSafeInteger(recovery.clock_excluded_ms) || recovery.clock_excluded_ms < 0 || recovery.clock_excluded_ms > 180_000) return null;
      const proofs = await readBetaPlatformRecoveryFenceSet(context.db, context.portByEnvironment, action.runId).catch(() => null);
      if (!proofs || !proofs.some((proof) => proof.preparationId === action.preparationId && proof.generationId === action.generationId)) return null;
      const fenceSetHash = betaRecoveryFenceSetHash(proofs);
      if (fenceSetHash !== value.sourceSnapshotHash) return null;
      const expectedEvidenceHash = betaRecoveryExhaustionEvidenceHash({ action,
        incidentEvidenceHash: recovery.incident_evidence_hash, startedAt, deadlineAt,
        clockExcludedMs: recovery.clock_excluded_ms, cancellationEvidenceHash: run.cancellation_evidence_hash,
        fenceSetHash });
      if (expectedEvidenceHash !== value.evidenceHash) return null;
      const identity = value;
      return { runId: identity.runId, actionId: identity.actionId, environmentId: identity.environmentId,
        operationId: identity.operationId, payloadHash: identity.payloadHash, evidenceHash: identity.evidenceHash,
        source: 'beta_platform_monitor' as const };
    },
  };
  return { authority, issue, verifyIssued, context };
}
