import { sql } from 'drizzle-orm';
import type { BefObservationPorts } from './bef-observation-ports.js';
import type { TaskActionEvidenceSink } from './bef-task-executor.js';
import type { OwnerDatabase } from './db.js';
import {
  beginBetaPlatformRecovery,
  finalizeExhaustedBetaPlatformFailure,
  platformRecoveryWindowExpired,
  recordBetaPlatformRecoveryObservation,
} from './beta-platform-recovery.js';
import {
  betaRecoveryExhaustionEvidenceHash,
  betaRecoveryFenceSetHash,
  classifyBefRecoveryOperation,
  createRecoveryAuthorityRuntime,
  isTerminalBefRecoverySource,
  loadBetaPlatformRecoveryActionBinding,
  readBefRecoveryOperation,
  readBetaPlatformRecoveryFenceSet,
  recoverySourceSnapshotHash,
  recoverySourceEvidenceForOperation,
  safeBefObserverFailureCode,
  writeRecoveryEvidence,
  type BetaPlatformRecoveryActionBinding,
  type BefRecoveryOperationSnapshot,
} from './beta-platform-recovery-authority.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECOVERY_WINDOW_MS = 180_000;
const MAX_CLOCK_EXCLUSION_MS = 180_000;
const MAX_RECOVERY_ROWS = 128;
const ORIGINAL_OPERATION_NOT_FOUND = 'platform_original_operation_not_found';
const ABSENT_OPERATION_AFTER_FENCE = 'platform_original_operation_absent_after_fence';

type RecoveryStatus = 'recovering' | 'recovered' | 'unknown' | 'exhausted' | 'refunded';
interface RecoveryRecord {
  action_id: string; run_id: string; owner_id: string; agent_id: string; task_index: number;
  environment_id: string; operation_id: string; payload_hash: string; incident_evidence_hash: string;
  started_at: Date | string; deadline_at: Date | string; clock_excluded_ms: number; status: RecoveryStatus;
  latest_evidence_hash: string | null;
}

export interface BetaPlatformRecoveryTick {
  recoveringRunIds: readonly string[];
  exhaustedRunIds: readonly string[];
  reconciledActionIds: readonly string[];
  unknownActionIds: readonly string[];
}

export interface BetaPlatformRecoveryMonitor {
  tick(): Promise<BetaPlatformRecoveryTick>;
  finalizeFencedRuns(runIds: readonly string[]): Promise<void>;
}

export interface BetaPlatformRecoveryMonitorOptions {
  db: OwnerDatabase;
  observationPorts: BefObservationPorts;
  actionEvidenceSink: TaskActionEvidenceSink;
  /** Coordinator lease fence. Production must pass the held advisory lease assertion. */
  assertLeaseHeld?: () => Promise<void>;
  now?: () => Date;
}

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('beta_platform_recovery_query_unavailable');
  return value as T[];
}

function timestamp(value: Date | string): Date | null {
  const parsed = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

async function databaseNow(db: OwnerDatabase, fallback: () => Date): Promise<Date> {
  const found = rows<{ now: Date | string }>(await db.execute(sql`SELECT clock_timestamp() AS now`));
  const parsed = found[0]?.now === undefined ? fallback() : timestamp(found[0].now);
  if (!parsed || !Number.isFinite(parsed.getTime())) throw new Error('beta_platform_recovery_clock_unavailable');
  return parsed;
}

async function activeRecoveryRecords(db: OwnerDatabase): Promise<RecoveryRecord[]> {
  return rows<RecoveryRecord>(await db.execute(sql`SELECT recovery.action_id::text AS action_id,recovery.run_id::text AS run_id,
      recovery.owner_id::text AS owner_id,recovery.agent_id::text AS agent_id,recovery.task_index,recovery.environment_id,
      recovery.operation_id,recovery.payload_hash,recovery.incident_evidence_hash,recovery.started_at,recovery.deadline_at,
      recovery.clock_excluded_ms,recovery.status,recovery.latest_evidence_hash
    FROM oid_run_platform_recovery recovery JOIN oid_benchmark_run run ON run.id=recovery.run_id
    WHERE recovery.status IN ('recovering','unknown','exhausted') AND run.status<>'failed'
    ORDER BY recovery.started_at,recovery.run_id,recovery.action_id LIMIT ${MAX_RECOVERY_ROWS}`));
}

async function unresolvedActionIds(db: OwnerDatabase): Promise<string[]> {
  const found = rows<{ action_id: string }>(await db.execute(sql`SELECT action.id::text AS action_id
    FROM oid_run_task_action action JOIN oid_benchmark_run run ON run.id=action.run_id
    JOIN oid_run_task_action_receipt receipt ON receipt.action_id=action.id
    JOIN oid_run_task_action_outbox outbox ON outbox.action_id=action.id
    WHERE run.status='running' AND run.started_at IS NOT NULL AND receipt.receipt_status IN ('pending','unknown')
      AND outbox.status='delivered'
      AND NOT EXISTS (SELECT 1 FROM oid_run_platform_recovery recovery WHERE recovery.action_id=action.id)
    ORDER BY action.run_id,action.task_index,action.action_sequence LIMIT ${MAX_RECOVERY_ROWS}`));
  return found.map((row) => row.action_id).filter((id) => UUID.test(id));
}

async function getRecoveryRecord(db: OwnerDatabase, actionId: string): Promise<RecoveryRecord | null> {
  const found = rows<RecoveryRecord>(await db.execute(sql`SELECT action_id::text AS action_id,run_id::text AS run_id,
      owner_id::text AS owner_id,agent_id::text AS agent_id,task_index,environment_id,operation_id,payload_hash,
      incident_evidence_hash,started_at,deadline_at,clock_excluded_ms,status,latest_evidence_hash
    FROM oid_run_platform_recovery WHERE action_id=${actionId} LIMIT 2`));
  return found.length === 1 ? found[0]! : null;
}

function evidenceSourceForOperation(source: BefRecoveryOperationSnapshot): string {
  return source.status === 'identity_conflict' ? 'platform_recovery_source_conflict' :
    source.status === 'settlement_unknown' ? 'platform_recovery_source_ambiguous' :
      isTerminalBefRecoverySource(source) ? 'platform_recovery_original_operation_terminal' :
        'platform_recovery_original_operation_not_terminal';
}

export function betaRecoveryClockExclusionDelta(
  recovery: Pick<RecoveryRecord, 'started_at' | 'deadline_at' | 'clock_excluded_ms'>,
  now: Date,
): number {
  const started = timestamp(recovery.started_at);
  if (!started) return 0;
  const elapsed = Math.min(MAX_CLOCK_EXCLUSION_MS, Math.max(0, now.getTime() - started.getTime()));
  return Math.max(0, elapsed - recovery.clock_excluded_ms);
}

async function confirmObserverFailure(
  port: NonNullable<BefObservationPorts['postgresByEnvironment'][string]>,
  firstError: unknown,
): Promise<string | null> {
  const firstCode = safeBefObserverFailureCode(firstError);
  if (!firstCode) return null;
  try {
    await port.withRepeatableRead(async (read) => {
      const probe = rows<{ ok: number }>(await read('SELECT 1 AS ok'));
      if (probe.length !== 1 || Number(probe[0]?.ok) !== 1) throw new Error('beta_platform_recovery_observer_probe_invalid');
    });
    return null;
  } catch (probeError) {
    const probeCode = safeBefObserverFailureCode(probeError);
    return probeCode ?? firstCode;
  }
}

export function createBetaPlatformRecoveryMonitor(options: BetaPlatformRecoveryMonitorOptions): BetaPlatformRecoveryMonitor {
  const assertLeaseHeld = options.assertLeaseHeld ?? (async () => undefined);
  const nowProvider = options.now ?? (() => new Date());
  const runtime = createRecoveryAuthorityRuntime({ db: options.db, sink: options.actionEvidenceSink,
    portByEnvironment: options.observationPorts.postgresByEnvironment });

  async function startIncident(
    action: BetaPlatformRecoveryActionBinding,
    sourceCode: string,
    source?: BefRecoveryOperationSnapshot | null,
  ): Promise<void> {
    await assertLeaseHeld();
    const proofHash = source ? recoverySourceSnapshotHash(source) : undefined;
    const file = await writeRecoveryEvidence(options.actionEvidenceSink, action, {
      status: 'unknown', reasonCode: sourceCode,
      ...(source && UUID.test(source.operationId) ? { befOperationId: source.operationId } : {}),
    });
    const evidence = runtime.issue('incident', { runId: action.runId, actionId: action.actionId,
      environmentId: action.environmentId, operationId: action.ownerOperationId, payloadHash: action.payloadHash,
      evidenceHash: file.sha256, sourceCode, ...(proofHash ? { sourceSnapshotHash: proofHash } : {}) });
    await assertLeaseHeld();
    await beginBetaPlatformRecovery({ db: options.db, authority: runtime.authority }, {
      runId: action.runId, actionId: action.actionId, incidentEvidence: evidence,
    });
  }

  async function recordOperation(
    action: BetaPlatformRecoveryActionBinding,
    recovery: RecoveryRecord,
    source: BefRecoveryOperationSnapshot | null,
    sourceCode: string | null,
    now: Date,
    allowFencedUnknown = false,
  ): Promise<'reconciled' | 'unknown' | 'unchanged'> {
    const classification = source ? classifyBefRecoveryOperation(action, source) : { status: 'unknown' as const };
    if (source && !isTerminalBefRecoverySource(source) && classification.status === 'unknown' && !allowFencedUnknown) return 'unchanged';
    if (!source && !sourceCode) return 'unchanged';
    const recoverySource = source && classification.status === 'observed'
      ? recoverySourceEvidenceForOperation(source) ?? undefined : undefined;
    if (source && classification.status === 'observed' && !recoverySource) return 'unchanged';
    const clockExcludedMs = betaRecoveryClockExclusionDelta(recovery, now);
    const reasonCode = source ? evidenceSourceForOperation(source) : sourceCode === ABSENT_OPERATION_AFTER_FENCE
      ? 'platform_recovery_original_operation_absent_after_fence' : 'platform_recovery_observer_unavailable';
    const file = await writeRecoveryEvidence(options.actionEvidenceSink, action, {
      status: classification.status,
      reasonCode,
      ...(source && UUID.test(source.operationId) ? { befOperationId: source.operationId } : {}),
      ...(classification.transactionHash ? { transactionHash: classification.transactionHash } :
        !source && action.receiptTransactionHash ? { transactionHash: action.receiptTransactionHash } : {}),
      ...(classification.outcome ? { outcome: classification.outcome } : {}),
      ...(classification.receiptStatus ? { receiptStatus: classification.receiptStatus } : {}),
      ...(classification.receiptGasUsed ? { receiptGasUsed: classification.receiptGasUsed } : {}),
      ...(classification.receiptEffectiveGasPriceWei ? { receiptEffectiveGasPriceWei: classification.receiptEffectiveGasPriceWei } : {}),
      ...(classification.toolResponse ? { toolResponse: classification.toolResponse } : {}),
      ...(recoverySource ? { recoverySource } : {}),
    });
    const evidencePath = action.receiptEvidenceHash === file.sha256 && action.receiptEvidencePath
      ? action.receiptEvidencePath : file.path;
    const evidence = runtime.issue('operation', { runId: action.runId, actionId: action.actionId,
      environmentId: action.environmentId, operationId: action.ownerOperationId, payloadHash: action.payloadHash,
      evidenceHash: file.sha256, evidencePath, status: classification.status, clockExcludedMs,
      ...(classification.transactionHash ? { transactionHash: classification.transactionHash } :
        !source && action.receiptTransactionHash ? { transactionHash: action.receiptTransactionHash } : {}),
      ...(classification.toolResponse ? { toolResponse: classification.toolResponse } : {}),
      ...(source ? { sourceSnapshotHash: recoverySourceSnapshotHash(source) } : {}),
      ...(sourceCode ? { sourceCode } : {}) });
    await assertLeaseHeld();
    const result = await recordBetaPlatformRecoveryObservation({ db: options.db, authority: runtime.authority }, {
      actionId: action.actionId, evidence,
    });
    return result.receiptStatus === 'unknown' ? 'unknown' : 'reconciled';
  }

  async function inspectAction(action: BetaPlatformRecoveryActionBinding, recovery: RecoveryRecord | null, now: Date): Promise<{
    recovery?: RecoveryRecord; status: 'started' | 'reconciled' | 'unknown' | 'unchanged';
  }> {
    const port = options.observationPorts.postgresByEnvironment[action.environmentId];
    if (!port || port.environmentId !== action.environmentId) return { status: 'unchanged' };
    let source: BefRecoveryOperationSnapshot | null;
    try {
      await assertLeaseHeld();
      source = await readBefRecoveryOperation(port, action);
      await assertLeaseHeld();
    } catch (error) {
      const sourceCode = await confirmObserverFailure(port, error);
      if (!sourceCode) return { status: 'unchanged' };
      if (!recovery) {
        await startIncident(action, sourceCode);
        recovery = await getRecoveryRecord(options.db, action.actionId);
        if (!recovery) return { status: 'unchanged' };
        const status = await recordOperation(action, recovery, null, sourceCode, now);
        return { recovery, status: status === 'reconciled' ? 'reconciled' : status === 'unknown' ? 'unknown' : 'unchanged' };
      }
      const status = await recordOperation(action, recovery, null, sourceCode, now);
      return { recovery, status: status === 'reconciled' ? 'reconciled' : status === 'unknown' ? 'unknown' : 'unchanged' };
    }

    if (!source) {
      if (!recovery) {
        await startIncident(action, ORIGINAL_OPERATION_NOT_FOUND);
        recovery = await getRecoveryRecord(options.db, action.actionId);
        if (!recovery) return { status: 'unchanged' };
        return { recovery, status: 'started' };
      }
      return { recovery, status: 'unchanged' };
    }
    if (!recovery && isTerminalBefRecoverySource(source)) {
      await startIncident(action, evidenceSourceForOperation(source), source);
      recovery = await getRecoveryRecord(options.db, action.actionId);
      if (!recovery) return { status: 'unchanged' };
    }
    if (!recovery) return { status: 'unchanged' };
    const result = await recordOperation(action, recovery, source, null, now);
    return { recovery, status: result === 'reconciled' ? 'reconciled' : result === 'unknown' ? 'unknown' : 'unchanged' };
  }

  return {
    async tick(): Promise<BetaPlatformRecoveryTick> {
      await assertLeaseHeld();
      const now = await databaseNow(options.db, nowProvider);
      const active = await activeRecoveryRecords(options.db);
      const recoveryByAction = new Map(active.map((record) => [record.action_id, record]));
      const recoveryRunIds = new Set(active.map((record) => record.run_id));
      const recoveringRunIds = new Set<string>();
      const exhaustedRunIds = new Set<string>();
      const reconciledActionIds = new Set<string>();
      const unknownActionIds = new Set<string>();

      for (const recovery of active) {
        try {
          await assertLeaseHeld();
          const action = await loadBetaPlatformRecoveryActionBinding(options.db, recovery.action_id);
          if (!action || action.runId !== recovery.run_id || action.ownerId !== recovery.owner_id ||
              action.agentId !== recovery.agent_id || action.taskIndex !== recovery.task_index ||
              action.environmentId !== recovery.environment_id || action.ownerOperationId !== recovery.operation_id ||
              action.payloadHash !== recovery.payload_hash || !['pending','unknown','observed','rejected_before_execution'].includes(action.receiptStatus)) {
            recoveringRunIds.add(recovery.run_id);
            continue;
          }
          if (recovery.status === 'recovered' && ['observed','rejected_before_execution'].includes(action.receiptStatus)) continue;
          const deadline = timestamp(recovery.deadline_at);
          if (!deadline) {
            recoveringRunIds.add(recovery.run_id);
            continue;
          }
          const expired = platformRecoveryWindowExpired(now, deadline);
          if (expired) {
            exhaustedRunIds.add(recovery.run_id);
            // AICODE-NOTE: The persisted cutoff authorizes fencing, not an inferred
            // operation outcome. Do not put another observer connection attempt
            // ahead of cancellation; reconcile the source after the exact fence.
            continue;
          } else {
            recoveringRunIds.add(recovery.run_id);
          }
          const result = await inspectAction(action, recovery, now);
          if (result.status === 'reconciled') reconciledActionIds.add(action.actionId);
          if (result.status === 'unknown') unknownActionIds.add(action.actionId);
        } catch {
          // Keep this run isolated; a malformed/temporarily unavailable source must not starve peers.
          recoveringRunIds.add(recovery.run_id);
        }
      }

      const candidates = await unresolvedActionIds(options.db);
      for (const actionId of candidates) {
        try {
          await assertLeaseHeld();
          const action = await loadBetaPlatformRecoveryActionBinding(options.db, actionId);
          if (!action || action.runStatus !== 'running' || action.outboxStatus !== 'delivered' ||
              !['pending','unknown'].includes(action.receiptStatus) || recoveryRunIds.has(action.runId) || recoveryByAction.has(action.actionId)) continue;
          const result = await inspectAction(action, null, now);
          if (result.recovery) {
            recoveryByAction.set(action.actionId, result.recovery);
            recoveryRunIds.add(action.runId);
            if (result.status === 'reconciled') reconciledActionIds.add(action.actionId);
            if (result.status === 'unknown') unknownActionIds.add(action.actionId);
            const deadline = timestamp(result.recovery.deadline_at);
            if (!deadline || platformRecoveryWindowExpired(now, deadline)) exhaustedRunIds.add(action.runId);
            else if (result.status !== 'reconciled') recoveringRunIds.add(action.runId);
          }
        } catch {
          // Candidate-local failures are retried on the next bounded coordinator tick.
        }
      }
      await assertLeaseHeld();
      return {
        recoveringRunIds: [...recoveringRunIds].sort(), exhaustedRunIds: [...exhaustedRunIds].sort(),
        reconciledActionIds: [...reconciledActionIds].sort(), unknownActionIds: [...unknownActionIds].sort(),
      };
    },

    async finalizeFencedRuns(runIds: readonly string[]): Promise<void> {
      const targets = [...new Set(runIds)].filter((id) => UUID.test(id)).sort();
      for (const runId of targets) {
        try {
          await assertLeaseHeld();
          const recoveryRows = rows<RecoveryRecord>(await options.db.execute(sql`SELECT action_id::text AS action_id,
              run_id::text AS run_id,owner_id::text AS owner_id,agent_id::text AS agent_id,task_index,environment_id,
              operation_id,payload_hash,incident_evidence_hash,started_at,deadline_at,clock_excluded_ms,status,latest_evidence_hash
            FROM oid_run_platform_recovery WHERE run_id=${runId} AND status IN ('recovering','unknown','exhausted')
            ORDER BY started_at,action_id LIMIT ${MAX_RECOVERY_ROWS}`));
          for (const recovery of recoveryRows) {
            try {
              await assertLeaseHeld();
              const action = await loadBetaPlatformRecoveryActionBinding(options.db, recovery.action_id);
              if (!action || action.runId !== recovery.run_id || action.ownerId !== recovery.owner_id ||
                  action.agentId !== recovery.agent_id || action.environmentId !== recovery.environment_id ||
                  action.ownerOperationId !== recovery.operation_id || action.payloadHash !== recovery.payload_hash) continue;
              const now = await databaseNow(options.db, nowProvider);
              const startedAt = timestamp(recovery.started_at);
              const deadlineAt = timestamp(recovery.deadline_at);
              if (!startedAt || !deadlineAt || deadlineAt.getTime() !== startedAt.getTime() + RECOVERY_WINDOW_MS ||
                  !platformRecoveryWindowExpired(now, deadlineAt)) continue;
              const fenceProofs = await readBetaPlatformRecoveryFenceSet(options.db,
                options.observationPorts.postgresByEnvironment, runId);
              if (!fenceProofs || !fenceProofs.some((proof) => proof.preparationId === action.preparationId &&
                  proof.generationId === action.generationId)) continue;
              const fenceSetHash = betaRecoveryFenceSetHash(fenceProofs);
              const runRows = rows<{ cancellation_reason: string | null; cancellation_evidence_hash: string | null; status: string }>(
                await options.db.execute(sql`SELECT status,cancellation_reason,cancellation_evidence_hash
                  FROM oid_benchmark_run WHERE id=${runId} LIMIT 2`));
              const run = runRows[0];
              if (!run || run.cancellation_reason !== 'coordinator_platform_failure' ||
                  !run.cancellation_evidence_hash || !/^[0-9a-f]{64}$/.test(run.cancellation_evidence_hash) ||
                  !['cancelled','unknown'].includes(run.status)) continue;

              const port = options.observationPorts.postgresByEnvironment[action.environmentId];
              if (!port || port.environmentId !== action.environmentId) continue;
              let source: BefRecoveryOperationSnapshot | null = null;
              let sourceError: unknown;
              try {
                await assertLeaseHeld();
                source = await readBefRecoveryOperation(port, action);
                await assertLeaseHeld();
              } catch (error) { sourceError = error; }
              const observationNow = await databaseNow(options.db, nowProvider);
              if (source) {
                await recordOperation(action, recovery, source, null, observationNow, true);
              } else if (action.receiptStatus === 'pending') {
                const sourceCode = sourceError === undefined
                  ? ABSENT_OPERATION_AFTER_FENCE : await confirmObserverFailure(port, sourceError);
                if (!sourceCode) continue;
                await recordOperation(action, recovery, null, sourceCode, observationNow);
              }

              const evidenceHash = betaRecoveryExhaustionEvidenceHash({ action,
                incidentEvidenceHash: recovery.incident_evidence_hash, startedAt: startedAt.toISOString(),
                deadlineAt: deadlineAt.toISOString(), clockExcludedMs: recovery.clock_excluded_ms,
                cancellationEvidenceHash: run.cancellation_evidence_hash, fenceSetHash });
              const evidence = runtime.issue('exhaustion', { runId: action.runId, actionId: action.actionId,
                environmentId: action.environmentId, operationId: action.ownerOperationId, payloadHash: action.payloadHash,
                evidenceHash, sourceSnapshotHash: fenceSetHash });
              await assertLeaseHeld();
              await finalizeExhaustedBetaPlatformFailure({ db: options.db, authority: runtime.authority }, {
                runId, actionId: action.actionId, exhaustionEvidence: evidence,
              });
            } catch {
              // A failed exact-fence proof or refund transaction leaves the run unknown for retry.
            }
          }
        } catch {
          // Isolate run errors so other exhausted runs can still reconcile.
        }
      }
    },
  };
}
