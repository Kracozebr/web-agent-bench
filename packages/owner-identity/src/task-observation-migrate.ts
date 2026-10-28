export interface TaskObservationMigrationTransaction {
  unsafe(query: string): Promise<unknown>;
}

/** Private, immutable observation bundles bound to the admitted run cutoff. */
export const taskObservationMigrationStatements: readonly string[] = [
  // task-result-migrate creates the same composite uniqueness key before its evaluator table.
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_run_task_closure_bound_id_uq
    ON oid_run_task_closure(id,run_id,task_index)`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_observation_bundle (
    run_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index BETWEEN 0 AND 11),
    owner_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    closure_id uuid NOT NULL,
    closure_operation_id text,
    closure_payload_hash text NOT NULL CHECK(closure_payload_hash ~ '^[0-9a-f]{64}$'),
    closure_reason text NOT NULL CHECK(closure_reason IN ('agent_finish','task_deadline','run_deadline')),
    task_id text NOT NULL CHECK(task_id ~ '^(S[1-4]|M[1-4]|H[1-3]|U1)$'),
    release_identity text NOT NULL,
    release_manifest_hash text NOT NULL CHECK(release_manifest_hash ~ '^[0-9a-f]{64}$'),
    case_id text NOT NULL,
    case_hash text NOT NULL CHECK(case_hash ~ '^[0-9a-f]{64}$'),
    rubric_hash text NOT NULL CHECK(rubric_hash ~ '^[0-9a-f]{64}$'),
    environment_id text NOT NULL CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    preparation_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    environment_manifest_hash text NOT NULL CHECK(environment_manifest_hash ~ '^[0-9a-f]{64}$'),
    application_source_hash text NOT NULL CHECK(application_source_hash ~ '^[0-9a-f]{64}$'),
    execution_identity_hash text NOT NULL CHECK(execution_identity_hash ~ '^[0-9a-f]{64}$'),
    initial_state_sha256 text NOT NULL CHECK(initial_state_sha256 ~ '^[0-9a-f]{64}$'),
    action_cutoff_sequence bigint NOT NULL CHECK(action_cutoff_sequence >= 0),
    reconciled_action_sequence bigint NOT NULL CHECK(reconciled_action_sequence >= action_cutoff_sequence),
    observation_cutoff_sequence bigint NOT NULL CHECK(observation_cutoff_sequence >= 0),
    cutoff_evidence jsonb NOT NULL CHECK(jsonb_typeof(cutoff_evidence)='object'),
    bundle_hash text NOT NULL CHECK(bundle_hash ~ '^[0-9a-f]{64}$'),
    bundle_json jsonb NOT NULL CHECK(jsonb_typeof(bundle_json)='object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(run_id,task_index),
    CONSTRAINT oid_task_observation_bundle_closure_uq UNIQUE(closure_id),
    CONSTRAINT oid_task_observation_bundle_run_task_fk FOREIGN KEY(run_id,task_index)
      REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT,
    CONSTRAINT oid_task_observation_bundle_closure_fk FOREIGN KEY(closure_id,run_id,task_index)
      REFERENCES oid_run_task_closure(id,run_id,task_index) ON DELETE RESTRICT,
    CONSTRAINT oid_task_observation_bundle_execution_fk FOREIGN KEY(run_id,task_index)
      REFERENCES oid_task_execution_binding(run_id,task_index) ON DELETE RESTRICT,
    CONSTRAINT oid_task_observation_bundle_generation_fk FOREIGN KEY(environment_id,generation_id)
      REFERENCES oid_task_execution_binding(env_id,generation_id) ON DELETE RESTRICT,
    CONSTRAINT oid_task_observation_bundle_preparation_fk FOREIGN KEY(preparation_id)
      REFERENCES oid_task_preparation_intent(preparation_id) ON DELETE RESTRICT,
    CONSTRAINT oid_task_observation_bundle_lease_fk FOREIGN KEY(lease_id)
      REFERENCES oid_task_environment_lease(lease_id) ON DELETE RESTRICT
  )`,
  `CREATE INDEX IF NOT EXISTS oid_task_observation_bundle_generation_idx
    ON oid_run_task_observation_bundle(environment_id,generation_id)`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_observation_bundle_insert() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id
        WHERE r.id=NEW.run_id AND t.task_index=NEW.task_index
          AND r.owner_id=NEW.owner_id AND r.agent_id=NEW.agent_id
          AND r.release_identity=NEW.release_identity AND r.manifest_hash=NEW.release_manifest_hash
          AND r.task_ids[NEW.task_index+1]=NEW.task_id
          AND t.task_id=NEW.task_id AND t.closure_status='closed' AND t.closure_id=NEW.closure_id
          AND t.action_cutoff_sequence=NEW.action_cutoff_sequence
          AND t.reconciled_action_sequence=NEW.reconciled_action_sequence
          AND t.reconciled_action_sequence>=t.action_cutoff_sequence
      ) THEN
        RAISE EXCEPTION 'observation bundle does not match the closed, reconciled run task' USING ERRCODE='23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM oid_run_task_closure c
        WHERE c.id=NEW.closure_id AND c.run_id=NEW.run_id AND c.task_index=NEW.task_index
          AND c.owner_id=NEW.owner_id AND c.agent_id=NEW.agent_id
          AND c.operation_id IS NOT DISTINCT FROM NEW.closure_operation_id
          AND c.payload_hash=NEW.closure_payload_hash AND c.reason=NEW.closure_reason
          AND c.action_cutoff_sequence=NEW.action_cutoff_sequence
      ) THEN
        RAISE EXCEPTION 'observation bundle does not match its immutable closure' USING ERRCODE='23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM oid_task_execution_binding b
        WHERE b.run_id=NEW.run_id AND b.task_index=NEW.task_index AND b.env_id=NEW.environment_id
          AND b.generation_id=NEW.generation_id AND b.manifest_hash=NEW.environment_manifest_hash
          AND b.application_source_hash=NEW.application_source_hash
      ) THEN
        RAISE EXCEPTION 'observation bundle does not match its immutable execution binding' USING ERRCODE='23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM oid_task_preparation_intent i
        JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id
        JOIN LATERAL (
          SELECT status,generation_id,baseline_state_sha256 FROM oid_task_preparation_observation
          WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1
        ) o ON true
        WHERE i.preparation_id=NEW.preparation_id AND i.run_id=NEW.run_id AND i.task_index=NEW.task_index
          AND i.lease_id=NEW.lease_id AND i.environment_id=NEW.environment_id
          AND i.release_identity=NEW.release_identity AND i.manifest_hash=NEW.release_manifest_hash
          AND i.task_id=NEW.task_id AND i.case_id=NEW.case_id AND i.case_hash=NEW.case_hash
          AND i.environment_manifest_sha256=NEW.environment_manifest_hash
          AND i.application_source_hash=NEW.application_source_hash
          AND i.execution_identity_hash=NEW.execution_identity_hash
          AND i.initial_state_sha256=NEW.initial_state_sha256
          AND l.state='leased' AND o.status='ready' AND o.generation_id=NEW.generation_id
          AND o.baseline_state_sha256=NEW.initial_state_sha256
      ) THEN
        RAISE EXCEPTION 'observation bundle requires its exact ready preparation and leased environment' USING ERRCODE='23514';
      END IF;
      PERFORM 1 FROM oid_task_environment_lease
        WHERE lease_id=NEW.lease_id AND preparation_id=NEW.preparation_id AND state='leased' FOR UPDATE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'observation bundle environment lease is no longer leased' USING ERRCODE='23514';
      END IF;
      IF NEW.cutoff_evidence IS DISTINCT FROM NEW.bundle_json->'cutoff'->'evidence' OR
         NEW.bundle_json->>'schemaVersion' IS DISTINCT FROM 'bts-task-observation-bundle/v1' OR
         NEW.bundle_json->'binding'->>'ownerId' IS DISTINCT FROM NEW.owner_id::text OR
         NEW.bundle_json->'binding'->>'agentId' IS DISTINCT FROM NEW.agent_id::text OR
         NEW.bundle_json->'binding'->>'runId' IS DISTINCT FROM NEW.run_id::text OR
         NEW.bundle_json->'binding'->>'environmentId' IS DISTINCT FROM NEW.environment_id OR
         NEW.bundle_json->'binding'->>'releaseIdentity' IS DISTINCT FROM NEW.release_identity OR
         NEW.bundle_json->'binding'->>'manifestHash' IS DISTINCT FROM NEW.release_manifest_hash OR
         NEW.bundle_json->'binding'->>'caseId' IS DISTINCT FROM NEW.case_id OR
         NEW.bundle_json->'binding'->>'caseHash' IS DISTINCT FROM NEW.case_hash OR
         NEW.bundle_json->'binding'->>'rubricHash' IS DISTINCT FROM NEW.rubric_hash OR
         NEW.bundle_json->'binding'->>'taskId' IS DISTINCT FROM NEW.task_id OR
         NEW.bundle_json->'closure'->>'closureId' IS DISTINCT FROM NEW.closure_id::text OR
         NEW.bundle_json->'closure'->>'operationId' IS DISTINCT FROM NEW.closure_operation_id OR
         NEW.bundle_json->'closure'->>'payloadHash' IS DISTINCT FROM NEW.closure_payload_hash OR
         NEW.bundle_json->'closure'->>'reason' IS DISTINCT FROM NEW.closure_reason OR
         NEW.bundle_json->'closure'->>'actionCutoffSequence' IS DISTINCT FROM NEW.action_cutoff_sequence::text OR
         NEW.bundle_json->'closure'->>'reconciledActionSequence' IS DISTINCT FROM NEW.reconciled_action_sequence::text OR
         NEW.bundle_json->'execution'->>'preparationId' IS DISTINCT FROM NEW.preparation_id::text OR
         NEW.bundle_json->'execution'->>'leaseId' IS DISTINCT FROM NEW.lease_id::text OR
         NEW.bundle_json->'execution'->>'generationId' IS DISTINCT FROM NEW.generation_id::text OR
         NEW.bundle_json->'execution'->>'environmentManifestHash' IS DISTINCT FROM NEW.environment_manifest_hash OR
         NEW.bundle_json->'execution'->>'applicationSourceHash' IS DISTINCT FROM NEW.application_source_hash OR
         NEW.bundle_json->'execution'->>'executionIdentityHash' IS DISTINCT FROM NEW.execution_identity_hash OR
         NEW.bundle_json->'execution'->>'initialStateSha256' IS DISTINCT FROM NEW.initial_state_sha256 OR
         NEW.bundle_json->'cutoff'->>'observationSequence' IS DISTINCT FROM NEW.observation_cutoff_sequence::text OR
         NEW.bundle_json->'cutoff'->>'status' IS DISTINCT FROM 'authoritative' OR
         NEW.bundle_json->'observations'->>'coveredThroughSequence' IS DISTINCT FROM NEW.observation_cutoff_sequence::text THEN
        RAISE EXCEPTION 'observation bundle envelope does not match its immutable columns' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_observation_bundle_insert_guard_trg ON oid_run_task_observation_bundle`,
  `CREATE TRIGGER oid_task_observation_bundle_insert_guard_trg BEFORE INSERT ON oid_run_task_observation_bundle
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_observation_bundle_insert()`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_observation_bundle_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task observation bundles are immutable; unavailable evidence is not rewritten' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_observation_bundle_immutable_trg ON oid_run_task_observation_bundle`,
  `CREATE TRIGGER oid_task_observation_bundle_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_task_observation_bundle
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_observation_bundle_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_observation_bundle_immutable_truncate_trg ON oid_run_task_observation_bundle`,
  `CREATE TRIGGER oid_task_observation_bundle_immutable_truncate_trg BEFORE TRUNCATE ON oid_run_task_observation_bundle
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_observation_bundle_mutation()`,
  `REVOKE ALL ON TABLE oid_run_task_observation_bundle FROM PUBLIC`,
];

export async function migrateTaskObservations(tx: TaskObservationMigrationTransaction): Promise<void> {
  for (const statement of taskObservationMigrationStatements) await tx.unsafe(statement);
}
