export interface TaskPreparationMigrationTransaction { unsafe(query: string): Promise<unknown> }

export const taskPreparationMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_task_preparation_intent (
    preparation_id uuid PRIMARY KEY,
    run_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index BETWEEN 0 AND 11),
    claim_id uuid NOT NULL,
    lease_id uuid NOT NULL UNIQUE,
    environment_id text NOT NULL CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    release_identity text NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    task_id text NOT NULL CHECK(task_id ~ '^(S[1-4]|M[1-4]|H[1-3]|U1)$'),
    case_id text NOT NULL,
    case_hash text NOT NULL CHECK(case_hash ~ '^[0-9a-f]{64}$'),
    initial_state_sha256 text NOT NULL CHECK(initial_state_sha256 ~ '^[0-9a-f]{64}$'),
    execution_identity_hash text NOT NULL CHECK(execution_identity_hash ~ '^[0-9a-f]{64}$'),
    environment_manifest_sha256 text NOT NULL CHECK(environment_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    application_source_hash text NOT NULL CHECK(application_source_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_task_preparation_task_uq UNIQUE(run_id,task_index),
    CONSTRAINT oid_task_preparation_lease_uq UNIQUE(lease_id),
    CONSTRAINT oid_task_preparation_run_task_fk FOREIGN KEY(run_id,task_index)
      REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_preparation_intent_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task preparation intent is immutable' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_intent_immutable_trg ON oid_task_preparation_intent`,
  `CREATE TRIGGER oid_task_preparation_intent_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_preparation_intent
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_preparation_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_intent_immutable_truncate_trg ON oid_task_preparation_intent`,
  `CREATE TRIGGER oid_task_preparation_intent_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_preparation_intent
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_preparation_intent_mutation()`,
  `CREATE TABLE IF NOT EXISTS oid_task_preparation_dispatch (
    preparation_id uuid PRIMARY KEY REFERENCES oid_task_preparation_intent(preparation_id) ON DELETE RESTRICT,
    dispatch_id uuid NOT NULL UNIQUE,
    state text NOT NULL DEFAULT 'dispatching' CHECK(state IN ('dispatching','completed','unknown')),
    claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    settled_at timestamptz,
    CONSTRAINT oid_task_preparation_dispatch_state_shape_ck CHECK(
      (state='dispatching' AND settled_at IS NULL) OR (state IN ('completed','unknown') AND settled_at IS NOT NULL)
    )
  )`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_preparation_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.state<>'dispatching' OR NEW.settled_at IS NOT NULL THEN
        RAISE EXCEPTION 'task preparation dispatch must begin in dispatching state' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_dispatch_insert_guard_trg ON oid_task_preparation_dispatch`,
  `CREATE TRIGGER oid_task_preparation_dispatch_insert_guard_trg BEFORE INSERT ON oid_task_preparation_dispatch
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_preparation_dispatch_insert()`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_preparation_dispatch_update() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF ROW(NEW.preparation_id,NEW.dispatch_id,NEW.claimed_at) IS DISTINCT FROM ROW(OLD.preparation_id,OLD.dispatch_id,OLD.claimed_at) THEN
        RAISE EXCEPTION 'task preparation dispatch identity is immutable' USING ERRCODE='55000';
      END IF;
      IF OLD.state<>'dispatching' OR NEW.state NOT IN ('completed','unknown') OR NEW.settled_at IS NULL THEN
        RAISE EXCEPTION 'task preparation dispatch can be settled once' USING ERRCODE='55000';
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_dispatch_update_guard_trg ON oid_task_preparation_dispatch`,
  `CREATE TRIGGER oid_task_preparation_dispatch_update_guard_trg BEFORE UPDATE ON oid_task_preparation_dispatch
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_preparation_dispatch_update()`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_preparation_dispatch_delete() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task preparation dispatch history is append-only' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_dispatch_delete_guard_trg ON oid_task_preparation_dispatch`,
  `CREATE TRIGGER oid_task_preparation_dispatch_delete_guard_trg BEFORE DELETE ON oid_task_preparation_dispatch
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_preparation_dispatch_delete()`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_dispatch_immutable_truncate_trg ON oid_task_preparation_dispatch`,
  `CREATE TRIGGER oid_task_preparation_dispatch_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_preparation_dispatch
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_preparation_dispatch_delete()`,
  `CREATE TABLE IF NOT EXISTS oid_task_preparation_generation (
    generation_id uuid PRIMARY KEY,
    preparation_id uuid NOT NULL UNIQUE REFERENCES oid_task_preparation_intent(preparation_id) ON DELETE RESTRICT,
    environment_id text NOT NULL CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    first_observed_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_preparation_generation_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task preparation generation identity is immutable' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_generation_immutable_trg ON oid_task_preparation_generation`,
  `CREATE TRIGGER oid_task_preparation_generation_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_preparation_generation
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_preparation_generation_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_generation_immutable_truncate_trg ON oid_task_preparation_generation`,
  `CREATE TRIGGER oid_task_preparation_generation_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_preparation_generation
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_preparation_generation_mutation()`,
  `CREATE TABLE IF NOT EXISTS oid_task_preparation_observation (
    preparation_id uuid NOT NULL REFERENCES oid_task_preparation_intent(preparation_id) ON DELETE RESTRICT,
    revision integer NOT NULL CHECK(revision > 0),
    status text NOT NULL CHECK(status IN ('preparing','unknown','ready','fenced')),
    generation_id uuid,
    participant_id text CHECK(participant_id IS NULL OR length(participant_id) BETWEEN 1 AND 160),
    payer_address text CHECK(payer_address IS NULL OR payer_address ~ '^0x[0-9a-f]{40}$'),
    baseline_state_sha256 text CHECK(baseline_state_sha256 IS NULL OR baseline_state_sha256 ~ '^[0-9a-f]{64}$'),
    fixture_evidence jsonb,
    baseline_evidence jsonb,
    reason_code text CHECK(reason_code IS NULL OR reason_code IN (
      'adapter_outcome_unknown','adapter_call_failed','restart_reconciliation_required','run_state_changed_before_preparation_completed',
      'preparation_identity_mismatch','baseline_state_mismatch'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(preparation_id,revision),
    CONSTRAINT oid_task_preparation_ready_shape_ck CHECK(status <> 'ready' OR (
      generation_id IS NOT NULL AND baseline_state_sha256 IS NOT NULL AND fixture_evidence IS NOT NULL AND baseline_evidence IS NOT NULL
    )),
    CONSTRAINT oid_task_preparation_unknown_shape_ck CHECK(status <> 'unknown' OR reason_code IS NOT NULL)
  )`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_preparation_observation_insert() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE
      previous oid_task_preparation_observation%ROWTYPE;
      expected_state_sha256 text;
    BEGIN
      SELECT * INTO previous FROM oid_task_preparation_observation
        WHERE preparation_id=NEW.preparation_id ORDER BY revision DESC LIMIT 1;
      IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.status <> 'preparing' THEN
          RAISE EXCEPTION 'preparation observation must begin at revision one in preparing state' USING ERRCODE='23514';
        END IF;
      ELSE
        IF NEW.revision <> previous.revision + 1 THEN
          RAISE EXCEPTION 'preparation observation revision is not contiguous' USING ERRCODE='23514';
        END IF;
        IF NOT (
          (previous.status='preparing' AND NEW.status IN ('preparing','unknown','ready','fenced')) OR
          (previous.status='unknown' AND NEW.status IN ('unknown','ready','fenced')) OR
          (previous.status='ready' AND NEW.status IN ('ready','fenced')) OR
          (previous.status='fenced' AND NEW.status='fenced')
        ) THEN
          RAISE EXCEPTION 'invalid preparation observation transition' USING ERRCODE='23514';
        END IF;
        IF previous.generation_id IS NOT NULL AND NEW.generation_id IS DISTINCT FROM previous.generation_id THEN
          RAISE EXCEPTION 'preparation generation identity is immutable once observed' USING ERRCODE='23514';
        END IF;
        IF previous.status='unknown' AND previous.generation_id IS NULL AND NEW.generation_id IS NOT NULL THEN
          RAISE EXCEPTION 'unknown preparation without an original generation cannot infer one later' USING ERRCODE='23514';
        END IF;
        IF previous.participant_id IS NOT NULL AND NEW.participant_id IS DISTINCT FROM previous.participant_id OR
           previous.payer_address IS NOT NULL AND NEW.payer_address IS DISTINCT FROM previous.payer_address OR
           previous.baseline_state_sha256 IS NOT NULL AND NEW.baseline_state_sha256 IS DISTINCT FROM previous.baseline_state_sha256 OR
           previous.fixture_evidence IS NOT NULL AND NEW.fixture_evidence IS DISTINCT FROM previous.fixture_evidence OR
           previous.baseline_evidence IS NOT NULL AND NEW.baseline_evidence IS DISTINCT FROM previous.baseline_evidence THEN
          RAISE EXCEPTION 'observed task preparation identity and evidence cannot be replaced' USING ERRCODE='23514';
        END IF;
        IF previous.status IN ('ready','fenced') AND NEW.status IN ('ready','fenced') AND
           ROW(NEW.generation_id,NEW.participant_id,NEW.payer_address,NEW.baseline_state_sha256,NEW.fixture_evidence,NEW.baseline_evidence)
             IS DISTINCT FROM ROW(previous.generation_id,previous.participant_id,previous.payer_address,previous.baseline_state_sha256,previous.fixture_evidence,previous.baseline_evidence) THEN
          RAISE EXCEPTION 'ready preparation identity and evidence are immutable' USING ERRCODE='23514';
        END IF;
      END IF;
      IF NEW.generation_id IS NOT NULL THEN
        INSERT INTO oid_task_preparation_generation(generation_id,preparation_id,environment_id)
          SELECT NEW.generation_id,i.preparation_id,i.environment_id FROM oid_task_preparation_intent i
          WHERE i.preparation_id=NEW.preparation_id ON CONFLICT DO NOTHING;
        IF NOT EXISTS (SELECT 1 FROM oid_task_preparation_generation g
            WHERE g.generation_id=NEW.generation_id AND g.preparation_id=NEW.preparation_id) THEN
          RAISE EXCEPTION 'generation identity is already assigned to another preparation' USING ERRCODE='23505';
        END IF;
      END IF;
      IF NEW.status='ready' THEN
        SELECT initial_state_sha256 INTO expected_state_sha256 FROM oid_task_preparation_intent
          WHERE preparation_id=NEW.preparation_id;
        IF NEW.baseline_state_sha256 IS DISTINCT FROM expected_state_sha256 THEN
          RAISE EXCEPTION 'ready preparation baseline differs from its sealed initial state' USING ERRCODE='23514';
        END IF;
        IF jsonb_typeof(NEW.fixture_evidence) IS DISTINCT FROM 'object' OR
           NEW.fixture_evidence->>'boundary' IS DISTINCT FROM 'actual_tool_http_x402_local_evm_application_store' OR
           COALESCE(NEW.fixture_evidence->>'path' !~ '^[A-Za-z0-9._/-]+$',true) OR
           COALESCE(char_length(NEW.fixture_evidence->>'path') NOT BETWEEN 1 AND 512,true) OR
           COALESCE(NEW.fixture_evidence->>'path' ~ '(^|/)\.\.(/|$)',false) OR
           COALESCE(NEW.fixture_evidence->>'path' ~ '^/',false) OR COALESCE(NEW.fixture_evidence->>'path' ~ '^[A-Za-z]:',false) OR
           COALESCE(NEW.fixture_evidence->>'sha256' !~ '^[0-9a-f]{64}$',true) OR
           jsonb_typeof(NEW.baseline_evidence) IS DISTINCT FROM 'object' OR
           NEW.baseline_evidence->>'boundary' IS DISTINCT FROM 'actual_tool_http_x402_local_evm_application_store' OR
           COALESCE(NEW.baseline_evidence->>'path' !~ '^[A-Za-z0-9._/-]+$',true) OR
           COALESCE(char_length(NEW.baseline_evidence->>'path') NOT BETWEEN 1 AND 512,true) OR
           COALESCE(NEW.baseline_evidence->>'path' ~ '(^|/)\.\.(/|$)',false) OR
           COALESCE(NEW.baseline_evidence->>'path' ~ '^/',false) OR COALESCE(NEW.baseline_evidence->>'path' ~ '^[A-Za-z]:',false) OR
           COALESCE(NEW.baseline_evidence->>'sha256' !~ '^[0-9a-f]{64}$',true) THEN
          RAISE EXCEPTION 'ready preparation requires hash-backed raw evidence references' USING ERRCODE='23514';
        END IF;
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_observation_guard_trg ON oid_task_preparation_observation`,
  `CREATE TRIGGER oid_task_preparation_observation_guard_trg BEFORE INSERT ON oid_task_preparation_observation
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_preparation_observation_insert()`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_preparation_observation_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task preparation observations are append-only' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_observation_immutable_trg ON oid_task_preparation_observation`,
  `CREATE TRIGGER oid_task_preparation_observation_immutable_trg BEFORE UPDATE OR DELETE ON oid_task_preparation_observation
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_preparation_observation_mutation()`,
  `DROP TRIGGER IF EXISTS oid_task_preparation_observation_immutable_truncate_trg ON oid_task_preparation_observation`,
  `CREATE TRIGGER oid_task_preparation_observation_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_preparation_observation
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_preparation_observation_mutation()`,
  `CREATE TABLE IF NOT EXISTS oid_task_environment_lease (
    lease_id uuid PRIMARY KEY,
    preparation_id uuid NOT NULL UNIQUE REFERENCES oid_task_preparation_intent(preparation_id) ON DELETE RESTRICT,
    environment_id text NOT NULL CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    state text NOT NULL DEFAULT 'leased' CHECK(state IN ('leased','fenced')),
    fence_evidence jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    fenced_at timestamptz,
    CONSTRAINT oid_task_environment_lease_state_shape_ck CHECK(
      (state='leased' AND fence_evidence IS NULL AND fenced_at IS NULL) OR
      (state='fenced' AND fence_evidence IS NOT NULL AND fenced_at IS NOT NULL AND
        fence_evidence->>'confirmed'='true' AND fence_evidence->>'preparationId'=preparation_id::text AND
        fence_evidence->>'leaseId'=lease_id::text AND fence_evidence->>'environmentId'=environment_id)
    )
  )`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_environment_lease_insert() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.state<>'leased' OR NEW.fence_evidence IS NOT NULL OR NEW.fenced_at IS NOT NULL THEN
        RAISE EXCEPTION 'task environment lease must begin leased and unfenced' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_task_environment_lease_insert_guard_trg ON oid_task_environment_lease`,
  `CREATE TRIGGER oid_task_environment_lease_insert_guard_trg BEFORE INSERT ON oid_task_environment_lease
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_environment_lease_insert()`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_task_environment_lease_active_env_uq
    ON oid_task_environment_lease(environment_id) WHERE state='leased'`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_environment_lease_update() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE observed_generation uuid;
    BEGIN
      IF ROW(NEW.lease_id,NEW.preparation_id,NEW.environment_id,NEW.created_at) IS DISTINCT FROM
         ROW(OLD.lease_id,OLD.preparation_id,OLD.environment_id,OLD.created_at) THEN
        RAISE EXCEPTION 'task environment lease identity is immutable' USING ERRCODE='55000';
      END IF;
      IF OLD.state='fenced' OR NOT (OLD.state='leased' AND NEW.state='fenced' AND NEW.fence_evidence IS NOT NULL AND NEW.fenced_at IS NOT NULL) THEN
        RAISE EXCEPTION 'task environment lease can only be released once with fence evidence' USING ERRCODE='55000';
      END IF;
      SELECT generation_id INTO observed_generation FROM oid_task_preparation_observation
        WHERE preparation_id=OLD.preparation_id ORDER BY revision DESC LIMIT 1;
      IF NOT (NEW.fence_evidence ? 'generationId') OR NEW.fence_evidence->>'generationId' IS DISTINCT FROM observed_generation::text OR
         jsonb_typeof(NEW.fence_evidence->'evidence') IS DISTINCT FROM 'object' OR
         NEW.fence_evidence->'evidence'->>'boundary' IS DISTINCT FROM 'actual_tool_http_x402_local_evm_application_store' OR
         COALESCE(NEW.fence_evidence->'evidence'->>'path' !~ '^[A-Za-z0-9._/-]+$',true) OR
         COALESCE(char_length(NEW.fence_evidence->'evidence'->>'path') NOT BETWEEN 1 AND 512,true) OR
         COALESCE(NEW.fence_evidence->'evidence'->>'path' ~ '(^|/)\.\.(/|$)',false) OR
         COALESCE(NEW.fence_evidence->'evidence'->>'path' ~ '^/',false) OR
         COALESCE(NEW.fence_evidence->'evidence'->>'sha256' !~ '^[0-9a-f]{64}$',true) THEN
        RAISE EXCEPTION 'task environment lease release requires matching hash-backed fence evidence' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_task_environment_lease_update_guard_trg ON oid_task_environment_lease`,
  `CREATE TRIGGER oid_task_environment_lease_update_guard_trg BEFORE UPDATE ON oid_task_environment_lease
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_environment_lease_update()`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_environment_lease_delete() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'task environment lease history is append-only' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_task_environment_lease_delete_guard_trg ON oid_task_environment_lease`,
  `CREATE TRIGGER oid_task_environment_lease_delete_guard_trg BEFORE DELETE ON oid_task_environment_lease
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_environment_lease_delete()`,
  `DROP TRIGGER IF EXISTS oid_task_environment_lease_immutable_truncate_trg ON oid_task_environment_lease`,
  `CREATE TRIGGER oid_task_environment_lease_immutable_truncate_trg BEFORE TRUNCATE ON oid_task_environment_lease
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_environment_lease_delete()`,
];

export async function migrateTaskPreparations(tx: TaskPreparationMigrationTransaction): Promise<void> {
  for (const statement of taskPreparationMigrationStatements) await tx.unsafe(statement);
}
