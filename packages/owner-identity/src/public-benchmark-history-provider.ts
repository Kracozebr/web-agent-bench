import { sql } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import type { RunAdmissionRelease, TaskReleaseProvider, ValidatedTaskRelease } from './task-release.js';

export type ActivatedPublicReleaseSnapshot = {
  firstActivatedAt: string;
  isActive: boolean;
  ranked: RunAdmissionRelease;
  training: RunAdmissionRelease;
};

export interface PublicBenchmarkHistoryProvider {
  getActivatedReleaseSnapshots(): Promise<readonly ActivatedPublicReleaseSnapshot[]>;
}

type ActivationReferenceRow = {
  release_identity: string;
  manifest_hash: string;
  first_activated_at: string;
  is_active: boolean;
};

function rows(value: unknown): ActivationReferenceRow[] {
  if (!Array.isArray(value)) throw new Error('public_benchmark_history_query_invalid');
  return value as ActivationReferenceRow[];
}

function admissionProjection(release: ValidatedTaskRelease): RunAdmissionRelease {
  return {
    releaseIdentity: release.releaseIdentity,
    manifestHash: release.manifestHash,
    benchmarkVersion: release.benchmarkVersion,
    benchmarkHash: release.benchmarkHash,
    policyHash: release.policyHash,
    mode: release.mode,
    taskIds: [...release.taskIds],
    weights: [...release.weights],
    priceUnits: release.pricing.priceUnits,
    precision: release.pricing.precision,
  };
}

export function createPostgresPublicBenchmarkHistoryProvider(
  db: OwnerDatabase,
  releaseProvider: TaskReleaseProvider,
): PublicBenchmarkHistoryProvider {
  return {
    async getActivatedReleaseSnapshots() {
      const references = rows(await db.execute(sql`
        SELECT r.release_identity,r.manifest_hash,MIN(j.activated_at)::text AS first_activated_at,
          COALESCE(a.release_identity=r.release_identity AND a.manifest_hash=r.manifest_hash,false) AS is_active
        FROM oid_task_release r
        JOIN oid_task_release_activation_journal j
          ON j.current_release_identity=r.release_identity AND j.current_manifest_hash=r.manifest_hash
        LEFT JOIN oid_task_release_active a ON a.id=1
        GROUP BY r.release_identity,r.manifest_hash,a.release_identity,a.manifest_hash
        ORDER BY MIN(j.activated_at) ASC,r.release_identity ASC`));
      const snapshots = await Promise.all(references.map(async (reference) => {
        const [ranked, training] = await Promise.all([
          releaseProvider.getValidatedRelease(reference.release_identity, reference.manifest_hash, 'ranked'),
          releaseProvider.getValidatedRelease(reference.release_identity, reference.manifest_hash, 'training'),
        ]);
        if (typeof reference.first_activated_at !== 'string' || typeof reference.is_active !== 'boolean') {
          throw new Error('activated_public_release_reference_invalid');
        }
        if (!ranked || !training) {
          if (reference.is_active) throw new Error('active_public_release_failed_validation');
          return null;
        }
        return {
          firstActivatedAt: reference.first_activated_at,
          isActive: reference.is_active,
          ranked: admissionProjection(ranked),
          training: admissionProjection(training),
        };
      }));
      return snapshots.filter((snapshot): snapshot is ActivatedPublicReleaseSnapshot => snapshot !== null);
    },
  };
}
