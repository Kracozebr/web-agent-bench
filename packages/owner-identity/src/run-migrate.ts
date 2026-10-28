export interface RunMigrationTransaction {
  unsafe(query: string): Promise<unknown>;
}

// AICODE-NOTE: Run source holds and their cash/bonus ledger entries commit in
// the same owner database transaction. Catalog/release identities are supplied
// by the independently validated task-release service; this schema does not
// activate or invent a benchmark release.
export const runMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_run_launch_intent (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    operation_id text NOT NULL,
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    mode text NOT NULL CHECK(mode IN ('training','ranked')),
    task_ids text[] NOT NULL CHECK(cardinality(task_ids)>0 AND array_position(task_ids,NULL) IS NULL),
    release_identity text NOT NULL,
    benchmark_version text NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    benchmark_hash text NOT NULL CHECK(benchmark_hash ~ '^[0-9a-f]{64}$'),
    policy_hash text NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
    successor_preparation_policy_version text,
    successor_preparation_timeout_seconds integer,
    quote_price_units bigint NOT NULL CHECK(quote_price_units >= 0),
    precision integer NOT NULL DEFAULT 6 CHECK(precision=6),
    cash_ceiling_units bigint NOT NULL CHECK(cash_ceiling_units >= 0),
    owner_policy_revision integer NOT NULL CHECK(owner_policy_revision >= 0),
    agent_policy_revision integer NOT NULL CHECK(agent_policy_revision > 0),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','cancelled','expired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    terminal_reason text,
    run_id uuid,
    CONSTRAINT oid_run_intent_agent_owner_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_intent_owner_operation_uq UNIQUE(owner_id,operation_id),
    CONSTRAINT oid_run_intent_operation_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    CONSTRAINT oid_run_intent_times_check CHECK(expires_at > created_at),
    CONSTRAINT oid_run_intent_successor_preparation_policy_pair_ck CHECK(
      (successor_preparation_policy_version IS NULL AND successor_preparation_timeout_seconds IS NULL) OR
      (successor_preparation_policy_version IS NOT NULL AND successor_preparation_timeout_seconds IS NOT NULL AND
        successor_preparation_policy_version ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND
        successor_preparation_timeout_seconds BETWEEN 1 AND 3600)
    )
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_intent_owner_created_idx ON oid_run_launch_intent(owner_id,created_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_run_intent_agent_status_idx ON oid_run_launch_intent(agent_id,status,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_benchmark_run (
    id uuid PRIMARY KEY,
    intent_id uuid NOT NULL UNIQUE REFERENCES oid_run_launch_intent(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    mode text NOT NULL CHECK(mode IN ('training','ranked')),
    task_ids text[] NOT NULL CHECK(cardinality(task_ids)>0 AND array_position(task_ids,NULL) IS NULL),
    release_identity text NOT NULL,
    benchmark_version text NOT NULL,
    manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    benchmark_hash text NOT NULL CHECK(benchmark_hash ~ '^[0-9a-f]{64}$'),
    policy_hash text NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
    successor_preparation_policy_version text,
    successor_preparation_timeout_seconds integer,
    quote_price_units bigint NOT NULL CHECK(quote_price_units >= 0),
    cash_ceiling_units bigint NOT NULL CHECK(cash_ceiling_units >= 0),
    access_generation integer NOT NULL CHECK(access_generation > 0),
    agent_policy_revision integer NOT NULL CHECK(agent_policy_revision > 0),
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','preparing','running','cancellation_requested','cancelled','expired','completed','failed','unknown','disqualified')),
    queued_at timestamptz NOT NULL DEFAULT now(),
    queue_deadline timestamptz NOT NULL,
    started_at timestamptz,
    overall_deadline timestamptz,
    finished_at timestamptz,
    terminal_reason text,
    cancellation_reason text,
    cancellation_requested_at timestamptz,
    environment_id text,
    environment_evidence_hash text CHECK(environment_evidence_hash IS NULL OR environment_evidence_hash ~ '^[0-9a-f]{64}$'),
    cancellation_evidence_hash text CHECK(cancellation_evidence_hash IS NULL OR cancellation_evidence_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oid_benchmark_run_agent_owner_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_benchmark_run_times_check CHECK(queue_deadline > queued_at),
    CONSTRAINT oid_benchmark_run_successor_preparation_policy_pair_ck CHECK(
      (successor_preparation_policy_version IS NULL AND successor_preparation_timeout_seconds IS NULL) OR
      (successor_preparation_policy_version IS NOT NULL AND successor_preparation_timeout_seconds IS NOT NULL AND
        successor_preparation_policy_version ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND
        successor_preparation_timeout_seconds BETWEEN 1 AND 3600)
    )
  )`,
  // AICODE-NOTE: Old rows remain NULL; multi-task admission/start must reject absent or unsupported snapshots instead of inventing history.
  `ALTER TABLE oid_run_launch_intent ADD COLUMN IF NOT EXISTS successor_preparation_policy_version text`,
  `ALTER TABLE oid_run_launch_intent ADD COLUMN IF NOT EXISTS successor_preparation_timeout_seconds integer`,
  `ALTER TABLE oid_benchmark_run ADD COLUMN IF NOT EXISTS successor_preparation_policy_version text`,
  `ALTER TABLE oid_benchmark_run ADD COLUMN IF NOT EXISTS successor_preparation_timeout_seconds integer`,
  `DO $$ BEGIN
     IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_intent_successor_preparation_policy_pair_ck') THEN
       ALTER TABLE oid_run_launch_intent ADD CONSTRAINT oid_run_intent_successor_preparation_policy_pair_ck CHECK(
         (successor_preparation_policy_version IS NULL AND successor_preparation_timeout_seconds IS NULL) OR
         (successor_preparation_policy_version IS NOT NULL AND successor_preparation_timeout_seconds IS NOT NULL AND
           successor_preparation_policy_version ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND
           successor_preparation_timeout_seconds BETWEEN 1 AND 3600)
       );
     END IF;
     IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_benchmark_run_successor_preparation_policy_pair_ck') THEN
       ALTER TABLE oid_benchmark_run ADD CONSTRAINT oid_benchmark_run_successor_preparation_policy_pair_ck CHECK(
         (successor_preparation_policy_version IS NULL AND successor_preparation_timeout_seconds IS NULL) OR
         (successor_preparation_policy_version IS NOT NULL AND successor_preparation_timeout_seconds IS NOT NULL AND
           successor_preparation_policy_version ~ '^[a-z0-9][a-z0-9._/-]{0,100}/v[1-9][0-9]*$' AND
           successor_preparation_timeout_seconds BETWEEN 1 AND 3600)
       );
     END IF;
   END; $$`,
  `CREATE OR REPLACE FUNCTION oid_guard_successor_preparation_policy_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF ROW(NEW.successor_preparation_policy_version,NEW.successor_preparation_timeout_seconds) IS DISTINCT FROM
         ROW(OLD.successor_preparation_policy_version,OLD.successor_preparation_timeout_seconds) THEN
        RAISE EXCEPTION 'successor preparation policy snapshot is immutable' USING ERRCODE='55000';
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_run_intent_successor_preparation_policy_immutable_trg ON oid_run_launch_intent`,
  `CREATE TRIGGER oid_run_intent_successor_preparation_policy_immutable_trg
    BEFORE UPDATE OF successor_preparation_policy_version,successor_preparation_timeout_seconds ON oid_run_launch_intent
    FOR EACH ROW EXECUTE FUNCTION oid_guard_successor_preparation_policy_snapshot()`,
  `DROP TRIGGER IF EXISTS oid_benchmark_run_successor_preparation_policy_immutable_trg ON oid_benchmark_run`,
  `CREATE TRIGGER oid_benchmark_run_successor_preparation_policy_immutable_trg
    BEFORE UPDATE OF successor_preparation_policy_version,successor_preparation_timeout_seconds ON oid_benchmark_run
    FOR EACH ROW EXECUTE FUNCTION oid_guard_successor_preparation_policy_snapshot()`,
  `DO $$ BEGIN
     IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_intent_run_fk') THEN
       ALTER TABLE oid_run_launch_intent ADD CONSTRAINT oid_run_intent_run_fk FOREIGN KEY(run_id) REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT;
     END IF;
   END; $$`,
  `CREATE INDEX IF NOT EXISTS oid_benchmark_run_owner_created_idx ON oid_benchmark_run(owner_id,queued_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_benchmark_run_queue_idx ON oid_benchmark_run(status,queue_deadline,queued_at,id)`,
  `CREATE INDEX IF NOT EXISTS oid_benchmark_run_agent_idx ON oid_benchmark_run(agent_id,status)`,
  `CREATE TABLE IF NOT EXISTS oid_run_reservation (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    source_kind text NOT NULL CHECK(source_kind IN ('cash_usdc','tester_bonus')),
    bonus_grant_id uuid,
    cash_provenance text,
    amount_units bigint NOT NULL CHECK(amount_units > 0),
    state text NOT NULL DEFAULT 'held' CHECK(state IN ('held','released','debited')),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz,
    CONSTRAINT oid_run_reservation_owner_bonus_fk FOREIGN KEY(owner_id,bonus_grant_id) REFERENCES oid_bonus_grant(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_reservation_source_shape_check CHECK(
      (source_kind='tester_bonus' AND bonus_grant_id IS NOT NULL AND cash_provenance IS NULL)
      OR (source_kind='cash_usdc' AND bonus_grant_id IS NULL AND cash_provenance IS NOT NULL AND char_length(cash_provenance) BETWEEN 1 AND 120)
    )
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_run_reservation_run_source_uq ON oid_run_reservation(run_id,source_kind,COALESCE(bonus_grant_id,'00000000-0000-0000-0000-000000000000'::uuid),COALESCE(cash_provenance,''))`,
  `CREATE INDEX IF NOT EXISTS oid_run_reservation_owner_state_idx ON oid_run_reservation(owner_id,state)`,
  `CREATE TABLE IF NOT EXISTS oid_run_budget_hold (
    run_id uuid PRIMARY KEY REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    mode text NOT NULL CHECK(mode IN ('training','ranked')),
    utc_day text NOT NULL CHECK(utc_day ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
    amount_units bigint NOT NULL CHECK(amount_units >= 0),
    state text NOT NULL DEFAULT 'held' CHECK(state IN ('held','charged','released')),
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz,
    CONSTRAINT oid_run_budget_hold_agent_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_budget_hold_agent_day_idx ON oid_run_budget_hold(agent_id,utc_day,state)`,
  `CREATE TABLE IF NOT EXISTS oid_run_operation (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    actor_kind text NOT NULL CHECK(actor_kind IN ('owner','agent')),
    actor_agent_id uuid,
    operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    action text NOT NULL CHECK(action IN ('intent_create','intent_cancel','intent_accept','run_start','run_cancel')),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    response_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_run_operation_actor_shape_check CHECK((actor_kind='owner' AND actor_agent_id IS NULL) OR (actor_kind='agent' AND actor_agent_id IS NOT NULL)),
    CONSTRAINT oid_run_operation_actor_agent_fk FOREIGN KEY(owner_id,actor_agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_operation_owner_operation_uq UNIQUE(owner_id,operation_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_operation_agent_created_idx ON oid_run_operation(actor_agent_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_event (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    sequence integer NOT NULL CHECK(sequence > 0),
    source text NOT NULL CHECK(source IN ('owner','agent','coordinator','worker','executor')),
    event_type text NOT NULL,
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    payload_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_run_event_run_sequence_uq UNIQUE(run_id,sequence)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_event_run_created_idx ON oid_run_event(run_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_task (
    run_id uuid NOT NULL REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    task_index integer NOT NULL CHECK(task_index >= 0),
    task_id text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','active','completed','failed','unknown')),
    snapshot_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz,
    deadline_at timestamptz,
    finished_at timestamptz,
    result_json jsonb,
    PRIMARY KEY(run_id,task_index),
    CONSTRAINT oid_run_task_run_task_uq UNIQUE(run_id,task_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_task_status_deadline_idx ON oid_run_task(status,deadline_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_outbox (
    event_id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    event_type text NOT NULL,
    payload_json jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered')),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    CONSTRAINT oid_run_outbox_run_type_uq UNIQUE(run_id,event_type)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_outbox_status_created_idx ON oid_run_outbox(status,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_execution_slot (
    agent_id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    run_id uuid NOT NULL UNIQUE REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    claim_id uuid NOT NULL UNIQUE,
    state text NOT NULL CHECK(state IN ('preparing','running')),
    acquired_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CONSTRAINT oid_run_execution_slot_agent_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE TABLE IF NOT EXISTS oid_run_dispatch_state (
    id integer PRIMARY KEY CHECK(id=1),
    last_owner_id uuid REFERENCES oid_owner(id) ON DELETE SET NULL,
    turn_number bigint NOT NULL DEFAULT 0 CHECK(turn_number >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `INSERT INTO oid_run_dispatch_state(id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
  `CREATE TABLE IF NOT EXISTS oid_run_dispatch_claim (
    run_id uuid PRIMARY KEY REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    claim_id uuid NOT NULL UNIQUE,
    turn_number bigint NOT NULL CHECK(turn_number > 0),
    status text NOT NULL DEFAULT 'claimed' CHECK(status IN ('claimed','released')),
    claimed_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    CONSTRAINT oid_run_dispatch_claim_agent_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_dispatch_claim_owner_turn_idx ON oid_run_dispatch_claim(owner_id,turn_number)`,
  `CREATE TABLE IF NOT EXISTS oid_run_mode_cancellation_outbox (
    event_id uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    mode text NOT NULL CHECK(mode IN ('training','ranked')),
    policy_revision integer NOT NULL CHECK(policy_revision > 0),
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered')),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    CONSTRAINT oid_run_mode_cancellation_agent_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_mode_cancellation_mode_revision_uq UNIQUE(agent_id,mode,policy_revision)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_mode_cancellation_status_created_idx ON oid_run_mode_cancellation_outbox(status,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_cancellation_receipt (
    source_event_id uuid PRIMARY KEY,
    source_kind text NOT NULL CHECK(source_kind IN ('agent_access_revoked','mode_removed')),
    cancelled_run_ids uuid[] NOT NULL DEFAULT '{}',
    pending_run_ids uuid[] NOT NULL DEFAULT '{}',
    evidence_hash text CHECK(evidence_hash IS NULL OR evidence_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
  )`,
  `ALTER TABLE oid_run_cancellation_receipt ADD COLUMN IF NOT EXISTS completed_at timestamptz`,
  `CREATE OR REPLACE FUNCTION oid_run_reject_immutable_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'run event journal is append-only' USING ERRCODE = '55000'; END; $$`,
  `DROP TRIGGER IF EXISTS oid_run_event_immutable_trg ON oid_run_event`,
  `CREATE TRIGGER oid_run_event_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_event FOR EACH ROW EXECUTE FUNCTION oid_run_reject_immutable_event_mutation()`,
  `CREATE OR REPLACE FUNCTION oid_run_record_mode_removal() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.training IS TRUE AND NEW.training IS FALSE THEN
        INSERT INTO oid_run_mode_cancellation_outbox(event_id,owner_id,agent_id,mode,policy_revision)
        SELECT gen_random_uuid(),a.owner_id,NEW.agent_id,'training',NEW.revision FROM oid_agent a WHERE a.id=NEW.agent_id
        ON CONFLICT (agent_id,mode,policy_revision) DO NOTHING;
      END IF;
      IF OLD.ranked IS TRUE AND NEW.ranked IS FALSE THEN
        INSERT INTO oid_run_mode_cancellation_outbox(event_id,owner_id,agent_id,mode,policy_revision)
        SELECT gen_random_uuid(),a.owner_id,NEW.agent_id,'ranked',NEW.revision FROM oid_agent a WHERE a.id=NEW.agent_id
        ON CONFLICT (agent_id,mode,policy_revision) DO NOTHING;
      END IF;
      RETURN NEW;
    END; $$`,
  `DROP TRIGGER IF EXISTS oid_agent_policy_run_mode_removal_trg ON oid_agent_policy`,
  `CREATE TRIGGER oid_agent_policy_run_mode_removal_trg AFTER UPDATE OF training,ranked ON oid_agent_policy FOR EACH ROW EXECUTE FUNCTION oid_run_record_mode_removal()`
];

export async function migrateRuns(tx: RunMigrationTransaction): Promise<void> {
  for (const statement of runMigrationStatements) await tx.unsafe(statement);
}
