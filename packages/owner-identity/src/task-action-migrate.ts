export interface TaskActionMigrationTransaction {
  unsafe(query: string): Promise<unknown>;
}

/** Durable task-scoped action admission and finish-cutoff records. */
export const taskActionMigrationStatements: readonly string[] = [
  `ALTER TABLE oid_run_task
    ADD COLUMN IF NOT EXISTS accepted_action_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS action_cutoff_sequence bigint,
    ADD COLUMN IF NOT EXISTS reconciled_action_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS closure_status text NOT NULL DEFAULT 'open',
    ADD COLUMN IF NOT EXISTS closure_id uuid,
    ADD COLUMN IF NOT EXISTS closure_operation_id text,
    ADD COLUMN IF NOT EXISTS closure_payload_hash text,
    ADD COLUMN IF NOT EXISTS closure_reason text,
    ADD COLUMN IF NOT EXISTS closed_at timestamptz`,
  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_action_sequence_ck') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_action_sequence_ck CHECK (
        accepted_action_sequence >= 0 AND reconciled_action_sequence >= 0 AND
        reconciled_action_sequence <= accepted_action_sequence AND
        (action_cutoff_sequence IS NULL OR (action_cutoff_sequence >= 0 AND action_cutoff_sequence <= accepted_action_sequence))
      );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_closure_shape_ck') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_closure_shape_ck CHECK (
        (closure_status='open' AND closure_id IS NULL AND action_cutoff_sequence IS NULL AND closed_at IS NULL) OR
        (closure_status='closing' AND closure_id IS NOT NULL AND action_cutoff_sequence IS NOT NULL AND closed_at IS NULL) OR
        (closure_status IN ('closed','unknown') AND closure_id IS NOT NULL AND action_cutoff_sequence IS NOT NULL AND closed_at IS NOT NULL)
      );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_closure_reason_ck') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_closure_reason_ck CHECK (
        closure_reason IS NULL OR closure_reason IN ('agent_finish','task_deadline','run_deadline')
      );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_closure_operation_ck') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_closure_operation_ck CHECK (
        closure_operation_id IS NULL OR closure_operation_id ~ '^[A-Za-z0-9_-]{12,128}$'
      );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_closure_hash_ck') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_closure_hash_ck CHECK (
        closure_payload_hash IS NULL OR closure_payload_hash ~ '^[0-9a-f]{64}$'
      );
    END IF;
  END $$`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_action (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index >= 0),
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    access_generation integer NOT NULL CHECK(access_generation > 0),
    grant_id uuid NOT NULL REFERENCES oid_agent_access_grant(id) ON DELETE RESTRICT,
    task_id text NOT NULL,
    environment_id text NOT NULL,
    action_sequence bigint NOT NULL CHECK(action_sequence > 0),
    operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    action_kind text NOT NULL CHECK(action_kind IN ('purchase','pay','retrieve','approve','transfer','wrap','unwrap','swap','inspect_catalog','inspect_offer')),
    command_json jsonb NOT NULL CHECK(jsonb_typeof(command_json)='object'),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_run_task_action_task_fk FOREIGN KEY(run_id,task_index)
      REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT,
    CONSTRAINT oid_run_task_action_owner_agent_fk FOREIGN KEY(owner_id,agent_id)
      REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_task_action_run_sequence_uq UNIQUE(run_id,task_index,action_sequence),
    CONSTRAINT oid_run_task_action_run_operation_uq UNIQUE(run_id,operation_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_task_action_agent_idx ON oid_run_task_action(owner_id,agent_id,run_id,task_index,action_sequence)`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_action_outbox (
    action_id uuid PRIMARY KEY REFERENCES oid_run_task_action(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    CONSTRAINT oid_run_task_action_outbox_delivery_ck CHECK((status='pending' AND delivered_at IS NULL) OR (status='delivered' AND delivered_at IS NOT NULL))
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_task_action_outbox_pending_idx ON oid_run_task_action_outbox(status,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_action_receipt (
    action_id uuid PRIMARY KEY REFERENCES oid_run_task_action(id) ON DELETE RESTRICT,
    receipt_revision integer NOT NULL DEFAULT 0 CHECK(receipt_revision >= 0),
    receipt_status text NOT NULL DEFAULT 'pending' CHECK(receipt_status IN ('pending','observed','rejected_before_execution','unknown')),
    evidence_hash text CHECK(evidence_hash IS NULL OR evidence_hash ~ '^[0-9a-f]{64}$'),
    evidence_path text,
    transaction_hash text CHECK(transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_run_task_action_receipt_state_ck CHECK(
      (receipt_status='pending' AND receipt_revision=0 AND evidence_hash IS NULL AND transaction_hash IS NULL) OR
      (receipt_status<>'pending' AND receipt_revision>0 AND evidence_hash IS NOT NULL)
    )
  )`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_action_reconciliation (
    action_id uuid NOT NULL REFERENCES oid_run_task_action(id) ON DELETE RESTRICT,
    revision integer NOT NULL CHECK(revision > 0),
    receipt_status text NOT NULL CHECK(receipt_status IN ('observed','rejected_before_execution','unknown')),
    evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
    evidence_path text,
    transaction_hash text CHECK(transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(action_id,revision)
  )`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_closure (
    id uuid PRIMARY KEY,
    run_id uuid NOT NULL,
    task_index integer NOT NULL CHECK(task_index >= 0),
    operation_id text CHECK(operation_id IS NULL OR operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    reason text NOT NULL CHECK(reason IN ('agent_finish','task_deadline','run_deadline')),
    answer_json jsonb CHECK(answer_json IS NULL OR jsonb_typeof(answer_json)='object'),
    action_cutoff_sequence bigint NOT NULL CHECK(action_cutoff_sequence >= 0),
    actor_kind text NOT NULL CHECK(actor_kind IN ('agent','coordinator')),
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid NOT NULL,
    access_generation integer,
    grant_id uuid REFERENCES oid_agent_access_grant(id) ON DELETE RESTRICT,
    requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT oid_run_task_closure_task_fk FOREIGN KEY(run_id,task_index)
      REFERENCES oid_run_task(run_id,task_index) ON DELETE RESTRICT,
    CONSTRAINT oid_run_task_closure_owner_agent_fk FOREIGN KEY(owner_id,agent_id)
      REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_run_task_closure_actor_ck CHECK(
      (actor_kind='agent' AND access_generation IS NOT NULL AND access_generation > 0 AND grant_id IS NOT NULL) OR
      (actor_kind='coordinator' AND access_generation IS NULL AND grant_id IS NULL)
    ),
    CONSTRAINT oid_run_task_closure_task_uq UNIQUE(run_id,task_index),
    CONSTRAINT oid_run_task_closure_operation_uq UNIQUE(run_id,operation_id)
  )`,
  `CREATE TABLE IF NOT EXISTS oid_run_task_finish_outbox (
    closure_id uuid PRIMARY KEY REFERENCES oid_run_task_closure(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    CONSTRAINT oid_run_task_finish_outbox_delivery_ck CHECK((status='pending' AND delivered_at IS NULL) OR (status='delivered' AND delivered_at IS NOT NULL))
  )`,
  `CREATE INDEX IF NOT EXISTS oid_run_task_finish_outbox_pending_idx ON oid_run_task_finish_outbox(status,created_at)`,
  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_closure_id_fk') THEN
      ALTER TABLE oid_run_task ADD CONSTRAINT oid_run_task_closure_id_fk
        FOREIGN KEY(closure_id) REFERENCES oid_run_task_closure(id) ON DELETE RESTRICT;
    END IF;
  END $$`,
  `CREATE OR REPLACE FUNCTION oid_reject_task_action_intent_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'admitted task action and closure intents are immutable' USING ERRCODE='55000'; END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_immutable_trg ON oid_run_task_action`,
  `CREATE TRIGGER oid_run_task_action_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_task_action
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_immutable_truncate_trg ON oid_run_task_action`,
  `CREATE TRIGGER oid_run_task_action_immutable_truncate_trg BEFORE TRUNCATE ON oid_run_task_action
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_run_task_closure_immutable_trg ON oid_run_task_closure`,
  `CREATE TRIGGER oid_run_task_closure_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_task_closure
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_run_task_closure_immutable_truncate_trg ON oid_run_task_closure`,
  `CREATE TRIGGER oid_run_task_closure_immutable_truncate_trg BEFORE TRUNCATE ON oid_run_task_closure
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_reconciliation_immutable_trg ON oid_run_task_action_reconciliation`,
  `CREATE TRIGGER oid_run_task_action_reconciliation_immutable_trg BEFORE UPDATE OR DELETE ON oid_run_task_action_reconciliation
    FOR EACH ROW EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_reconciliation_immutable_truncate_trg ON oid_run_task_action_reconciliation`,
  `CREATE TRIGGER oid_run_task_action_reconciliation_immutable_truncate_trg BEFORE TRUNCATE ON oid_run_task_action_reconciliation
    FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_task_action_intent_mutation()`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_action_receipt_update() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.action_id<>OLD.action_id OR NEW.receipt_revision<>OLD.receipt_revision+1 THEN
        RAISE EXCEPTION 'task action receipt revisions must advance by exactly one' USING ERRCODE='55000';
      END IF;
      IF OLD.receipt_status IN ('observed','rejected_before_execution') OR
         (OLD.receipt_status='unknown' AND NEW.receipt_status='pending') THEN
        RAISE EXCEPTION 'resolved task action receipts cannot be erased or replayed' USING ERRCODE='55000';
      END IF;
      IF OLD.receipt_status='unknown' AND OLD.transaction_hash IS NOT NULL AND
         lower(NEW.transaction_hash) IS DISTINCT FROM lower(OLD.transaction_hash) THEN
        RAISE EXCEPTION 'reconciliation must retain the original transaction identity' USING ERRCODE='55000';
      END IF;
      RETURN NEW;
    END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_receipt_revision_trg ON oid_run_task_action_receipt`,
  `CREATE TRIGGER oid_run_task_action_receipt_revision_trg BEFORE UPDATE ON oid_run_task_action_receipt
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_action_receipt_update()`,
  `CREATE OR REPLACE FUNCTION oid_guard_task_action_cutoff_update() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.accepted_action_sequence<OLD.accepted_action_sequence OR NEW.reconciled_action_sequence<OLD.reconciled_action_sequence OR
         (OLD.action_cutoff_sequence IS NOT NULL AND NEW.action_cutoff_sequence IS DISTINCT FROM OLD.action_cutoff_sequence) OR
         (OLD.closure_id IS NOT NULL AND (NEW.closure_id IS DISTINCT FROM OLD.closure_id OR
           NEW.closure_operation_id IS DISTINCT FROM OLD.closure_operation_id OR NEW.closure_payload_hash IS DISTINCT FROM OLD.closure_payload_hash OR
           NEW.closure_reason IS DISTINCT FROM OLD.closure_reason)) OR
         (OLD.closure_status='closed' AND NEW.closure_status<>'closed') OR
         (OLD.closure_status='unknown' AND NEW.closure_status NOT IN ('unknown','closed')) OR
         (OLD.closure_status<>'open' AND NEW.accepted_action_sequence<>OLD.accepted_action_sequence) OR
         (NEW.action_cutoff_sequence IS NOT NULL AND NEW.reconciled_action_sequence>NEW.action_cutoff_sequence) THEN
        RAISE EXCEPTION 'task action sequence or cutoff cannot regress or reopen' USING ERRCODE='55000';
      END IF;
      RETURN NEW;
    END;
  $$`,
  `DROP TRIGGER IF EXISTS oid_run_task_action_cutoff_trg ON oid_run_task`,
  `CREATE TRIGGER oid_run_task_action_cutoff_trg BEFORE UPDATE OF accepted_action_sequence,action_cutoff_sequence,reconciled_action_sequence,
    closure_status,closure_id,closure_operation_id,closure_payload_hash,closure_reason ON oid_run_task
    FOR EACH ROW EXECUTE FUNCTION oid_guard_task_action_cutoff_update()`,
  `ALTER TABLE oid_run_task_action_receipt ADD COLUMN IF NOT EXISTS tool_response_json jsonb,
    ADD COLUMN IF NOT EXISTS tool_response_hash text CHECK(tool_response_hash IS NULL OR tool_response_hash ~ '^[0-9a-f]{64}$')`,
  `ALTER TABLE oid_run_task_action_reconciliation ADD COLUMN IF NOT EXISTS tool_response_json jsonb,
    ADD COLUMN IF NOT EXISTS tool_response_hash text CHECK(tool_response_hash IS NULL OR tool_response_hash ~ '^[0-9a-f]{64}$')`,
  `ALTER TABLE oid_run_task_action_receipt ADD COLUMN IF NOT EXISTS evidence_path text`,
  `ALTER TABLE oid_run_task_action_reconciliation ADD COLUMN IF NOT EXISTS evidence_path text`,
  `ALTER TABLE oid_run_task_action DROP CONSTRAINT IF EXISTS oid_run_task_action_action_kind_check`,
  `ALTER TABLE oid_run_task_action DROP CONSTRAINT IF EXISTS oid_run_task_action_action_kind_ck`,
  `DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_run_task_action_action_kind_ck') THEN
      ALTER TABLE oid_run_task_action ADD CONSTRAINT oid_run_task_action_action_kind_ck CHECK(
        action_kind IN ('purchase','pay','retrieve','approve','transfer','wrap','unwrap','swap','inspect_catalog','inspect_offer'));
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_task_action_receipt_evidence_path_ck') THEN
      ALTER TABLE oid_run_task_action_receipt ADD CONSTRAINT oid_task_action_receipt_evidence_path_ck CHECK(
        evidence_path IS NULL OR (length(evidence_path) BETWEEN 1 AND 512 AND evidence_path ~ '^[A-Za-z0-9._/-]+$'
          AND evidence_path !~ '(^/|(^|/)[.][.](/|$))'));
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_task_action_reconciliation_evidence_path_ck') THEN
      ALTER TABLE oid_run_task_action_reconciliation ADD CONSTRAINT oid_task_action_reconciliation_evidence_path_ck CHECK(
        evidence_path IS NULL OR (length(evidence_path) BETWEEN 1 AND 512 AND evidence_path ~ '^[A-Za-z0-9._/-]+$'
          AND evidence_path !~ '(^/|(^|/)[.][.](/|$))'));
    END IF;
  END $$`,
  `DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_task_action_response_projection_ck') THEN
      ALTER TABLE oid_run_task_action_receipt ADD CONSTRAINT oid_task_action_response_projection_ck CHECK(
        (tool_response_json IS NULL)=(tool_response_hash IS NULL) AND (tool_response_json IS NULL OR jsonb_typeof(tool_response_json)='object'));
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='oid_task_action_response_history_ck') THEN
      ALTER TABLE oid_run_task_action_reconciliation ADD CONSTRAINT oid_task_action_response_history_ck CHECK(
        (tool_response_json IS NULL)=(tool_response_hash IS NULL) AND (tool_response_json IS NULL OR jsonb_typeof(tool_response_json)='object'));
    END IF;
  END $$`,
];

export async function migrateTaskActions(tx: TaskActionMigrationTransaction): Promise<void> {
  for (const statement of taskActionMigrationStatements) await tx.unsafe(statement);
}
