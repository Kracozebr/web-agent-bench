export interface TaskStoreMigrationTransaction {
  unsafe(query: string): Promise<unknown>;
}

// AICODE-NOTE: Sealed releases and activation history are append-only; the pointer is mutable, and activation serializes on the run admission lock. A legacy pointer is not fabricated into a transition because its predecessor is unknowable; its next real transition records it as previous.
export const taskStoreMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_task_release (
    release_identity text PRIMARY KEY CHECK(release_identity ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    benchmark_version text NOT NULL CHECK(benchmark_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    benchmark_hash text NOT NULL CHECK(benchmark_hash ~ '^[0-9a-f]{64}$'),
    policy_hash text NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
    sealed_manifest jsonb NOT NULL CHECK(jsonb_typeof(sealed_manifest)='object'),
    validation_evidence jsonb NOT NULL CHECK(jsonb_typeof(validation_evidence)='array' AND jsonb_array_length(validation_evidence)>0),
    validated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_task_release_identity_manifest_uq UNIQUE(release_identity,manifest_hash),
    CONSTRAINT oid_task_release_manifest_hash_uq UNIQUE(manifest_hash)
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_release_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'validated task release records are immutable' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_release_immutable_trg ON oid_task_release`,
  `CREATE TRIGGER oid_task_release_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_release
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_release_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_release_immutable_truncate_trg ON oid_task_release`,
  `CREATE TRIGGER oid_task_release_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_release
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_release_mutation()`,
  `CREATE TABLE IF NOT EXISTS oid_task_release_active (
    id smallint PRIMARY KEY CHECK(id=1),
    release_identity text NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    activated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_task_release_active_release_fk FOREIGN KEY(release_identity,manifest_hash)
      REFERENCES oid_task_release(release_identity,manifest_hash) ON DELETE RESTRICT
  )`,
  `CREATE TABLE IF NOT EXISTS oid_task_release_activation_journal (
    activation_ordinal bigint PRIMARY KEY CHECK(activation_ordinal > 0),
    previous_release_identity text,
    previous_manifest_hash text,
    current_release_identity text NOT NULL,
    current_manifest_hash text NOT NULL CHECK(current_manifest_hash ~ '^[0-9a-f]{64}$'),
    activated_at timestamptz NOT NULL,
    CONSTRAINT oid_task_release_activation_previous_pair_ck CHECK(
      (previous_release_identity IS NULL) = (previous_manifest_hash IS NULL)
    ),
    CONSTRAINT oid_task_release_activation_current_fk FOREIGN KEY(current_release_identity,current_manifest_hash)
      REFERENCES oid_task_release(release_identity,manifest_hash) ON DELETE RESTRICT,
    CONSTRAINT oid_task_release_activation_previous_fk FOREIGN KEY(previous_release_identity,previous_manifest_hash)
      REFERENCES oid_task_release(release_identity,manifest_hash) ON DELETE RESTRICT
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_release_activation_journal_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task release activation history is append-only' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_release_activation_journal_immutable_trg ON oid_task_release_activation_journal`,
  `CREATE TRIGGER oid_task_release_activation_journal_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_release_activation_journal
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_release_activation_journal_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_release_activation_journal_immutable_truncate_trg ON oid_task_release_activation_journal`,
  `CREATE TRIGGER oid_task_release_activation_journal_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_release_activation_journal
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_release_activation_journal_mutation()`,
];

export async function migrateTaskStore(tx: TaskStoreMigrationTransaction): Promise<void> {
  for (const statement of taskStoreMigrationStatements) await tx.unsafe(statement);
}
