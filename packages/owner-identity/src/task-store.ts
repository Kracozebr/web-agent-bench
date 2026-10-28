import { sql } from "drizzle-orm";
import type { OwnerDatabase } from "./db.js";
import {
  activateTaskReleaseCandidate,
  admissionProjection,
  canonicalTaskJson,
  createTaskReleaseProvider,
  sha256CanonicalTaskJson,
  TaskReleaseManifestSchema,
  type RunAdmissionRelease,
  type TaskReleaseEvidenceVerifier,
  type TaskReleaseQuerySource,
  type TaskReleaseStore,
  type TaskReleaseTransaction,
  type TaskReleaseValidationEvidence,
  type TaskReleaseValidationResult,
  type ValidatedTaskReleaseRecord,
} from "./task-release.js";
import type { TaskMode } from "./task-catalog.js";

type SqlExecutor = Pick<OwnerDatabase, "execute">;

interface ReleaseRow {
  release_identity: string;
  manifest_hash: string;
  benchmark_version: string;
  benchmark_hash: string;
  policy_hash: string;
  sealed_manifest: unknown;
  validation_evidence: unknown;
}

function executor(db: OwnerDatabase, tx?: TaskReleaseTransaction): SqlExecutor {
  if (tx === undefined) return db;
  if (typeof tx !== "object" || tx === null || !("execute" in tx) || typeof tx.execute !== "function") {
    throw new Error("Task release query received an incompatible transaction");
  }
  return tx as SqlExecutor;
}

function rows<T>(value: unknown): T[] {
  if (!Array.isArray(value)) throw new Error("The PostgreSQL driver returned an unexpected task release result");
  return value as T[];
}

async function query<T>(db: OwnerDatabase, tx: TaskReleaseTransaction | undefined, statement: ReturnType<typeof sql>): Promise<T[]> {
  return rows<T>(await executor(db, tx).execute(statement));
}

function jsonValue(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value) as unknown; }
  catch { return null; }
}

function expectedEvidence(manifest: ValidatedTaskReleaseRecord["manifest"]): TaskReleaseValidationEvidence[] {
  const allCases = [...manifest.cases.training, ...manifest.cases.ranked];
  return [
    { kind: "feasibility", sha256: manifest.feasibilityEvidence.sha256 },
    ...allCases.map((taskCase) => ({ kind: "reference_path" as const, sha256: taskCase.referencePath.evidence.sha256 })),
    { kind: "difficulty_review", sha256: manifest.difficultyReviewEvidence.sha256 },
  ];
}

function validatedRecord(row: ReleaseRow): ValidatedTaskReleaseRecord | null {
  const parsed = TaskReleaseManifestSchema.safeParse(jsonValue(row.sealed_manifest));
  if (!parsed.success) return null;
  const manifest = parsed.data;
  const { manifestHash: _manifestHash, ...manifestWithoutHash } = manifest;
  if (row.release_identity !== manifest.releaseIdentity || row.manifest_hash !== manifest.manifestHash ||
      row.benchmark_version !== manifest.benchmarkVersion || row.benchmark_hash !== manifest.benchmarkHash ||
      row.policy_hash !== manifest.policyHash || manifest.manifestHash !== sha256CanonicalTaskJson(manifestWithoutHash)) return null;
  const evidence = jsonValue(row.validation_evidence);
  if (!Array.isArray(evidence) || canonicalTaskJson(evidence) !== canonicalTaskJson(expectedEvidence(manifest))) return null;
  return {
    releaseIdentity: manifest.releaseIdentity,
    manifestHash: manifest.manifestHash,
    benchmarkVersion: manifest.benchmarkVersion,
    benchmarkHash: manifest.benchmarkHash,
    policyHash: manifest.policyHash,
    manifest,
  };
}

function validateActivationInput(
  release: ValidatedTaskReleaseRecord,
  validationEvidence: readonly TaskReleaseValidationEvidence[],
): { record: ValidatedTaskReleaseRecord; evidence: TaskReleaseValidationEvidence[] } {
  const parsed = TaskReleaseManifestSchema.safeParse(release.manifest);
  if (!parsed.success) throw new Error("Validated task release manifest is not complete");
  const manifest = parsed.data;
  const { manifestHash: _manifestHash, ...manifestWithoutHash } = manifest;
  if (manifestHashMismatch(release, manifest) || manifest.manifestHash !== sha256CanonicalTaskJson(manifestWithoutHash)) {
    throw new Error("Validated task release metadata does not match its sealed manifest");
  }
  const expected = expectedEvidence(manifest);
  const evidence = validationEvidence.map((entry) => ({ kind: entry.kind, sha256: entry.sha256 }));
  if (canonicalTaskJson(evidence) !== canonicalTaskJson(expected)) {
    throw new Error("Task release verification evidence is incomplete or does not match the sealed manifest");
  }
  return {
    record: {
      releaseIdentity: manifest.releaseIdentity,
      manifestHash: manifest.manifestHash,
      benchmarkVersion: manifest.benchmarkVersion,
      benchmarkHash: manifest.benchmarkHash,
      policyHash: manifest.policyHash,
      manifest,
    },
    evidence,
  };
}

function manifestHashMismatch(release: ValidatedTaskReleaseRecord, manifest: ValidatedTaskReleaseRecord["manifest"]): boolean {
  return release.releaseIdentity !== manifest.releaseIdentity || release.manifestHash !== manifest.manifestHash ||
    release.benchmarkVersion !== manifest.benchmarkVersion || release.benchmarkHash !== manifest.benchmarkHash ||
    release.policyHash !== manifest.policyHash;
}

function makeTaskReleaseStore(db: OwnerDatabase): TaskReleaseStore {
  const source: TaskReleaseStore = {
    async getActiveAdmissionRelease(mode: TaskMode, tx?: TaskReleaseTransaction): Promise<RunAdmissionRelease | null> {
      const found = await query<ReleaseRow & { active_manifest_hash: string }>(db, tx, sql`
        SELECT r.release_identity,r.manifest_hash,r.benchmark_version,r.benchmark_hash,r.policy_hash,
          r.sealed_manifest,r.validation_evidence,a.manifest_hash AS active_manifest_hash
        FROM oid_task_release_active a
        JOIN oid_task_release r ON r.release_identity=a.release_identity AND r.manifest_hash=a.manifest_hash
        WHERE a.id=1`);
      const row = found[0];
      if (!row || row.active_manifest_hash !== row.manifest_hash) return null;
      const record = validatedRecord(row);
      return record ? admissionProjection(record, mode) : null;
    },
    async getValidatedReleaseRecord(releaseIdentity: string, manifestHash: string, tx?: TaskReleaseTransaction): Promise<ValidatedTaskReleaseRecord | null> {
      const found = await query<ReleaseRow>(db, tx, sql`
        SELECT release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,sealed_manifest,validation_evidence
        FROM oid_task_release WHERE release_identity=${releaseIdentity} AND manifest_hash=${manifestHash}`);
      const row = found[0];
      return row ? validatedRecord(row) : null;
    },
    async activateValidatedRelease(release, validationEvidence, tx): Promise<void> {
      const sealed = validateActivationInput(release, validationEvidence);
      const activeTx = executor(db, tx);
      // AICODE-NOTE: This is the same transaction lock used by intent creation and agent acceptance; a run cannot cross a release-pointer change.
      await activeTx.execute(sql`SELECT pg_advisory_xact_lock(824731202,21)`);
      await activeTx.execute(sql`
        INSERT INTO oid_task_release(
          release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,sealed_manifest,validation_evidence
        ) VALUES (
          ${sealed.record.releaseIdentity},${sealed.record.manifestHash},${sealed.record.benchmarkVersion},
          ${sealed.record.benchmarkHash},${sealed.record.policyHash},${JSON.stringify(sealed.record.manifest)}::jsonb,
          ${JSON.stringify(sealed.evidence)}::jsonb
        ) ON CONFLICT (release_identity) DO NOTHING`);
      const storedRows = await query<ReleaseRow>(db, tx, sql`
        SELECT release_identity,manifest_hash,benchmark_version,benchmark_hash,policy_hash,sealed_manifest,validation_evidence
        FROM oid_task_release WHERE release_identity=${sealed.record.releaseIdentity} FOR UPDATE`);
      const stored = storedRows[0];
      if (!stored || canonicalTaskJson(jsonValue(stored.sealed_manifest)) !== canonicalTaskJson(sealed.record.manifest) ||
          canonicalTaskJson(jsonValue(stored.validation_evidence)) !== canonicalTaskJson(sealed.evidence) ||
          stored.manifest_hash !== sealed.record.manifestHash || stored.benchmark_version !== sealed.record.benchmarkVersion ||
          stored.benchmark_hash !== sealed.record.benchmarkHash || stored.policy_hash !== sealed.record.policyHash) {
        throw new Error("Task release identity already exists with different immutable content");
      }
      const activeRows = await query<{ release_identity: string; manifest_hash: string }>(db, tx, sql`
        SELECT release_identity,manifest_hash FROM oid_task_release_active WHERE id=1 FOR UPDATE`);
      const previous = activeRows[0];
      if (previous?.release_identity === sealed.record.releaseIdentity && previous.manifest_hash === sealed.record.manifestHash) return;

      const ordinalRows = await query<{ next_ordinal: string }>(db, tx, sql`
        SELECT (COALESCE(max(activation_ordinal),0)+1)::text AS next_ordinal
        FROM oid_task_release_activation_journal`);
      const nextOrdinal = ordinalRows[0]?.next_ordinal;
      if (!nextOrdinal) throw new Error("Could not allocate task release activation ordinal");

      await activeTx.execute(sql`
        INSERT INTO oid_task_release_activation_journal(
          activation_ordinal,previous_release_identity,previous_manifest_hash,current_release_identity,current_manifest_hash,activated_at
        ) VALUES (
          ${nextOrdinal}::bigint,${previous?.release_identity ?? null},${previous?.manifest_hash ?? null},
          ${sealed.record.releaseIdentity},${sealed.record.manifestHash},clock_timestamp()
        )`);

      if (previous) {
        await activeTx.execute(sql`
          UPDATE oid_task_release_active SET release_identity=${sealed.record.releaseIdentity},
            manifest_hash=${sealed.record.manifestHash},activated_at=(
              SELECT activated_at FROM oid_task_release_activation_journal WHERE activation_ordinal=${nextOrdinal}::bigint
            )
          WHERE id=1`);
      } else {
        await activeTx.execute(sql`
          INSERT INTO oid_task_release_active(id,release_identity,manifest_hash,activated_at)
          VALUES (1,${sealed.record.releaseIdentity},${sealed.record.manifestHash},(
            SELECT activated_at FROM oid_task_release_activation_journal WHERE activation_ordinal=${nextOrdinal}::bigint
          ))`);
      }
    },
  };
  return source;
}

export function createPostgresTaskReleaseQuerySource(db: OwnerDatabase): TaskReleaseQuerySource {
  const store = makeTaskReleaseStore(db);
  return {
    getActiveAdmissionRelease: (mode, tx) => store.getActiveAdmissionRelease(mode, tx),
    getValidatedReleaseRecord: (identity, hash, tx) => store.getValidatedReleaseRecord(identity, hash, tx),
  };
}

export function createPostgresTaskReleaseProvider(db: OwnerDatabase) {
  return createTaskReleaseProvider(createPostgresTaskReleaseQuerySource(db));
}

/**
 * Internal activation seam for an offline evidence-verification workflow.
 * There is intentionally no HTTP/MCP registration for this function.
 */
export async function activatePostgresTaskReleaseCandidate(
  db: OwnerDatabase,
  candidate: unknown,
  verifier: TaskReleaseEvidenceVerifier,
): Promise<TaskReleaseValidationResult> {
  return db.transaction(async (tx) => activateTaskReleaseCandidate(candidate, verifier, makeTaskReleaseStore(db), tx));
}
