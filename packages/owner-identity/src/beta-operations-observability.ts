import { statfs } from 'node:fs/promises';
import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { readBetaOperationsControl, listBetaOperationsControlEvents } from './beta-operations-control.js';

const MIN_FREE_BYTES = 2n * 1024n * 1024n * 1024n;
const MIN_FREE_PERCENT = 20n;
const SAFE_STORAGE_STATES = ['ready', 'low', 'unavailable', 'not_configured'] as const;

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error('PostgreSQL returned an unexpected beta operations metric result');
  return value as T[];
}

export type BetaStorageObservation = {
  status: (typeof SAFE_STORAGE_STATES)[number];
  capacityBytes: string | null;
  freeBytes: string | null;
  requiredFreeBytes: string | null;
  freePercent: number | null;
};

export async function readBetaStorageObservation(privateDataDir?: string): Promise<BetaStorageObservation> {
  if (!privateDataDir) return { status: 'not_configured', capacityBytes: null, freeBytes: null,
    requiredFreeBytes: null, freePercent: null };
  try {
    const capacity = await statfs(privateDataDir, { bigint: true });
    const capacityBytes = capacity.blocks * capacity.bsize;
    const freeBytes = capacity.bavail * capacity.bsize;
    const percentFloor = (capacityBytes * MIN_FREE_PERCENT + 99n) / 100n;
    const requiredFreeBytes = percentFloor > MIN_FREE_BYTES ? percentFloor : MIN_FREE_BYTES;
    const freePercent = capacityBytes > 0n ? Number((freeBytes * 10_000n) / capacityBytes) / 100 : 0;
    return { status: freeBytes >= requiredFreeBytes ? 'ready' : 'low', capacityBytes: capacityBytes.toString(),
      freeBytes: freeBytes.toString(), requiredFreeBytes: requiredFreeBytes.toString(), freePercent };
  } catch {
    return { status: 'unavailable', capacityBytes: null, freeBytes: null, requiredFreeBytes: null, freePercent: null };
  }
}

export async function readBetaOperationsSnapshot(input: {
  db: OwnerDatabase;
  privateDataDir?: string;
  workerLease: boolean | null;
  betaRuntimeHealth: 'ready' | 'unavailable' | 'not_configured';
  environmentCapacity: 'ready' | 'unavailable' | 'not_configured';
}) {
  const [control, events, storage, queueRows, failureRows, reportRows] = await Promise.all([
    readBetaOperationsControl(input.db),
    listBetaOperationsControlEvents(input.db),
    readBetaStorageObservation(input.privateDataDir),
    input.db.execute(sql`SELECT
        COUNT(*) FILTER (WHERE intent.status='pending' AND intent.expires_at>clock_timestamp())::int AS pending_intents,
        COUNT(*) FILTER (WHERE run.status='queued' AND run.started_at IS NULL)::int AS queued_runs,
        COUNT(*) FILTER (WHERE run.status='preparing' AND run.started_at IS NULL)::int AS preparing_runs,
        COUNT(*) FILTER (WHERE run.status='running')::int AS running_runs,
        COUNT(*) FILTER (WHERE run.status IN ('queued','preparing') AND run.started_at IS NULL)::int AS accepted_unstarted_runs,
        MIN(run.queued_at) FILTER (WHERE run.status IN ('queued','preparing') AND run.started_at IS NULL) AS oldest_unstarted_at,
        COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - MIN(run.queued_at)
          FILTER (WHERE run.status IN ('queued','preparing') AND run.started_at IS NULL)),0)::int AS oldest_unstarted_age_seconds
      FROM oid_run_launch_intent intent LEFT JOIN oid_benchmark_run run ON run.intent_id=intent.id`),
    input.db.execute(sql`SELECT
        COUNT(*) FILTER (WHERE status='failed')::int AS failed_runs,
        COUNT(*) FILTER (WHERE status='unknown')::int AS unknown_runs,
        (SELECT COUNT(*)::int FROM oid_run_task_action_receipt WHERE receipt_status='unknown') AS unknown_actions
      FROM oid_benchmark_run`),
    input.db.execute(sql`SELECT status,COUNT(*)::int AS count FROM oid_support_report GROUP BY status`),
  ]);
  const queue = rows<{ pending_intents: number; queued_runs: number; preparing_runs: number; running_runs: number;
    accepted_unstarted_runs: number; oldest_unstarted_at: Date | string | null; oldest_unstarted_age_seconds: number }>(queueRows)[0];
  const failures = rows<{ failed_runs: number; unknown_runs: number; unknown_actions: number }>(failureRows)[0];
  const reports = rows<{ status: string; count: number }>(reportRows).map(({ status, count }) => ({ status, count }));
  const workerLease = input.workerLease === null ? 'not_configured' : input.workerLease ? 'held' : 'missing';
  const startsReady = control.mode === 'active' && workerLease === 'held' && input.betaRuntimeHealth === 'ready' &&
    input.environmentCapacity === 'ready' && storage.status === 'ready';
  return {
    control,
    recentControlEvents: events,
    api: { database: 'ready' as const },
    starts: { ready: startsReady, workerLease, betaRuntimeHealth: input.betaRuntimeHealth,
      environmentCapacity: input.environmentCapacity, storage: storage.status },
    queue: {
      pendingIntents: queue?.pending_intents ?? 0,
      queuedRuns: queue?.queued_runs ?? 0,
      preparingRuns: queue?.preparing_runs ?? 0,
      runningRuns: queue?.running_runs ?? 0,
      acceptedUnstartedRuns: queue?.accepted_unstarted_runs ?? 0,
      oldestUnstartedAt: queue?.oldest_unstarted_at instanceof Date ? queue.oldest_unstarted_at.toISOString() :
        queue?.oldest_unstarted_at ? new Date(queue.oldest_unstarted_at).toISOString() : null,
      oldestUnstartedAgeSeconds: queue?.oldest_unstarted_age_seconds ?? 0,
    },
    failures: { failedRuns: failures?.failed_runs ?? 0, unknownRuns: failures?.unknown_runs ?? 0,
      unknownActions: failures?.unknown_actions ?? 0 },
    reports,
    storage,
  };
}

export async function checkBetaApiReadiness(db: OwnerDatabase): Promise<boolean> {
  try {
    await db.execute(sql`SELECT 1`);
    await readBetaOperationsControl(db);
    return true;
  } catch {
    return false;
  }
}
