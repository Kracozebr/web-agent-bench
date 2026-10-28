export interface TaskResultMigrationTransaction { unsafe(query: string): Promise<unknown> }

export const taskResultMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_run_task_evaluation (
    run_id uuid NOT NULL,
    task_index integer NOT NULL,
    closure_id uuid NOT NULL,
    task_id text NOT NULL,
    release_identity text NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    case_hash text NOT NULL CHECK(case_hash ~ '^[0-9a-f]{64}$'),
    rubric_hash text NOT NULL CHECK(rubric_hash ~ '^[0-9a-f]{64}$'),
    input_hash text NOT NULL CHECK(input_hash ~ '^[0-9a-f]{64}$'),
    result_hash text NOT NULL CHECK(result_hash ~ '^[0-9a-f]{64}$'),
    evaluator_source_hash text NOT NULL CHECK(evaluator_source_hash ~ '^[0-9a-f]{64}$'),
    observation_evidence jsonb NOT NULL,
    result_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(run_id,task_index),
    FOREIGN KEY(run_id,task_index) REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT
  )`,
  // AICODE-NOTE: Older audit rows retain their original hash; missing inputs are never fabricated.
  `ALTER TABLE oid_run_task_evaluation ADD COLUMN IF NOT EXISTS input_json jsonb`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_run_task_closure_bound_id_uq ON oid_run_task_closure(id,run_id,task_index)`,
  `DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_task_evaluation_closure_binding_fk') THEN
      ALTER TABLE oid_run_task_evaluation ADD CONSTRAINT oid_task_evaluation_closure_binding_fk
        FOREIGN KEY(closure_id,run_id,task_index) REFERENCES oid_run_task_closure(id,run_id,task_index) ON DELETE RESTRICT;
    END IF;
  END $$`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_evaluation_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task evaluation is immutable; reconstruction is read-only' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_evaluation_immutable_trg ON oid_run_task_evaluation`,
  `CREATE TRIGGER oid_task_evaluation_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_task_evaluation
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_evaluation_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_evaluation_immutable_truncate_trg ON oid_run_task_evaluation`,
  `CREATE TRIGGER oid_task_evaluation_immutable_truncate_trg BEFORE TRUNCATE ON oid_run_task_evaluation
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_evaluation_mutation()`,
];

export async function migrateTaskResults(tx: TaskResultMigrationTransaction): Promise<void> {
  for (const statement of taskResultMigrationStatements) await tx.unsafe(statement);
}
