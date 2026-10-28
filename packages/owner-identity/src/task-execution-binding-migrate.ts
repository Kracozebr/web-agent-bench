export interface TaskExecutionBindingMigrationTransaction { unsafe(query: string): Promise<unknown> }

export const taskExecutionBindingMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_task_execution_binding (
    run_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index BETWEEN 0 AND 11),
    env_id text NOT NULL CHECK(env_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    generation_id uuid NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    application_source_hash text NOT NULL CHECK(application_source_hash ~ '^[0-9a-f]{64}$'),
    participant_id text CHECK(participant_id IS NULL OR length(participant_id) BETWEEN 1 AND 160),
    payer_address text CHECK(payer_address IS NULL OR payer_address ~ '^0x[0-9a-f]{40}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(run_id,task_index), UNIQUE(env_id,generation_id),
    FOREIGN KEY(run_id,task_index) REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_execution_binding_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task execution binding is immutable' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_execution_binding_immutable_trg ON oid_task_execution_binding`,
  `CREATE TRIGGER oid_execution_binding_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_execution_binding
    FOR EACH ROW EXECUTE FUNCTION oid_reject_execution_binding_mutation()`,
  `DROP TRIGGER IF EXISTS oid_execution_binding_immutable_truncate_trg ON oid_task_execution_binding`,
  `CREATE TRIGGER oid_execution_binding_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_execution_binding
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_execution_binding_mutation()`,
];

export async function migrateTaskExecutionBindings(tx: TaskExecutionBindingMigrationTransaction): Promise<void> {
  for (const statement of taskExecutionBindingMigrationStatements) await tx.unsafe(statement);
}
