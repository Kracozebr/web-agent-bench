export interface LedgerMigrationTransaction {
  unsafe(query: string): Promise<unknown>;
}

export const ledgerMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_ledger_operation (
    id uuid PRIMARY KEY,
    actor_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    subject_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    operation_id text NOT NULL,
    action text NOT NULL,
    payload_hash text NOT NULL,
    response_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_ledger_operation_actor_operation_uq UNIQUE(actor_owner_id, operation_id),
    CONSTRAINT oid_ledger_operation_id_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    CONSTRAINT oid_ledger_operation_action_check CHECK(action IN ('bonus_grant','agent_financial_policy_update')),
    CONSTRAINT oid_ledger_operation_payload_hash_check CHECK(payload_hash ~ '^[0-9a-f]{64}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_ledger_operation_subject_created_idx ON oid_ledger_operation(subject_owner_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_bonus_grant (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    amount_units bigint NOT NULL,
    issued_by_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    reason text NOT NULL,
    operation_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    CONSTRAINT oid_bonus_grant_positive_amount_check CHECK(amount_units > 0),
    CONSTRAINT oid_bonus_grant_reason_check CHECK(char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT oid_bonus_grant_expiry_check CHECK(expires_at IS NULL OR expires_at > created_at),
    CONSTRAINT oid_bonus_grant_issuer_operation_uq UNIQUE(issued_by_owner_id, operation_id),
    CONSTRAINT oid_bonus_grant_owner_id_uq UNIQUE(owner_id, id),
    CONSTRAINT oid_bonus_grant_operation_id_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_bonus_grant_owner_created_idx ON oid_bonus_grant(owner_id, created_at, id)`,
  `CREATE TABLE IF NOT EXISTS oid_agent_financial_policy (
    owner_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    allow_cash_shortfall boolean NOT NULL DEFAULT false,
    operation_limit_units bigint DEFAULT 0,
    utc_day_limit_units bigint DEFAULT 0,
    category_limits jsonb NOT NULL DEFAULT '{"benchmark":"0.000000","forum":"0.000000"}'::jsonb,
    revision integer NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_agent_financial_policy_owner_agent_pk PRIMARY KEY(owner_id, agent_id),
    CONSTRAINT oid_agent_financial_policy_agent_owner_fk FOREIGN KEY(owner_id, agent_id)
      REFERENCES oid_agent(owner_id, id) ON DELETE CASCADE,
    CONSTRAINT oid_agent_financial_policy_operation_limit_check CHECK(operation_limit_units IS NULL OR operation_limit_units >= 0),
    CONSTRAINT oid_agent_financial_policy_utc_day_limit_check CHECK(utc_day_limit_units IS NULL OR utc_day_limit_units >= 0),
    CONSTRAINT oid_agent_financial_policy_revision_check CHECK(revision > 0),
    CONSTRAINT oid_agent_financial_policy_category_shape_check CHECK(
      jsonb_typeof(category_limits) = 'object'
      AND category_limits ? 'benchmark' AND category_limits ? 'forum'
      AND (category_limits - 'benchmark' - 'forum') = '{}'::jsonb
      AND (category_limits->'benchmark' = 'null'::jsonb OR (jsonb_typeof(category_limits->'benchmark') = 'string' AND category_limits->>'benchmark' ~ '^(0|[1-9][0-9]*)[.][0-9]{6}$'))
      AND (category_limits->'forum' = 'null'::jsonb OR (jsonb_typeof(category_limits->'forum') = 'string' AND category_limits->>'forum' ~ '^(0|[1-9][0-9]*)[.][0-9]{6}$'))
    )
  )`,
  `CREATE TABLE IF NOT EXISTS oid_ledger_entry (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    actor_owner_id uuid REFERENCES oid_owner(id) ON DELETE RESTRICT,
    bonus_grant_id uuid,
    operation_id text NOT NULL,
    entry_type text NOT NULL,
    source_kind text NOT NULL,
    amount_units bigint NOT NULL,
    available_delta_units bigint NOT NULL DEFAULT 0,
    reserved_delta_units bigint NOT NULL DEFAULT 0,
    expired_delta_units bigint NOT NULL DEFAULT 0,
    cash_provenance text,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_ledger_entry_owner_bonus_grant_fk FOREIGN KEY(owner_id, bonus_grant_id)
      REFERENCES oid_bonus_grant(owner_id, id) ON DELETE RESTRICT,
    CONSTRAINT oid_ledger_entry_source_check CHECK(source_kind IN ('cash_usdc','tester_bonus')),
    CONSTRAINT oid_ledger_entry_type_check CHECK(entry_type IN ('bonus_grant','cash_credit','reserve','release','debit','refund','expiry')),
    CONSTRAINT oid_ledger_entry_positive_amount_check CHECK(amount_units > 0),
    CONSTRAINT oid_ledger_entry_delta_check CHECK(available_delta_units <> 0 OR reserved_delta_units <> 0 OR expired_delta_units <> 0),
    CONSTRAINT oid_ledger_entry_bonus_grant_check CHECK(
      (source_kind='tester_bonus' AND bonus_grant_id IS NOT NULL)
      OR (source_kind='cash_usdc' AND bonus_grant_id IS NULL)
    ),
    CONSTRAINT oid_ledger_entry_cash_provenance_check CHECK(
      (source_kind='cash_usdc' AND cash_provenance IS NOT NULL AND char_length(cash_provenance) BETWEEN 1 AND 120)
      OR (source_kind='tester_bonus' AND cash_provenance IS NULL)
    ),
    CONSTRAINT oid_ledger_entry_operation_id_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_ledger_entry_owner_created_idx ON oid_ledger_entry(owner_id, created_at, id)`,
  `CREATE INDEX IF NOT EXISTS oid_ledger_entry_operation_idx ON oid_ledger_entry(operation_id)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_ledger_entry_grant_event_uq ON oid_ledger_entry(bonus_grant_id) WHERE entry_type='bonus_grant' AND bonus_grant_id IS NOT NULL`,
  `CREATE TABLE IF NOT EXISTS oid_ledger_audit (
    id uuid PRIMARY KEY,
    event_type text NOT NULL,
    operation_id text NOT NULL,
    actor_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    subject_owner_id uuid REFERENCES oid_owner(id) ON DELETE RESTRICT,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_ledger_audit_actor_operation_event_uq UNIQUE(actor_owner_id, operation_id, event_type),
    CONSTRAINT oid_ledger_audit_operation_id_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_ledger_audit_type_created_idx ON oid_ledger_audit(event_type, created_at)`,
  `CREATE OR REPLACE FUNCTION oid_ledger_reject_immutable_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'ledger records are append-only' USING ERRCODE = '55000';
    END;
    $$`,
  `DROP TRIGGER IF EXISTS oid_bonus_grant_immutable_trg ON oid_bonus_grant`,
  `CREATE TRIGGER oid_bonus_grant_immutable_trg BEFORE UPDATE OR DELETE ON oid_bonus_grant
    FOR EACH ROW EXECUTE FUNCTION oid_ledger_reject_immutable_mutation()`,
  `DROP TRIGGER IF EXISTS oid_ledger_entry_immutable_trg ON oid_ledger_entry`,
  `CREATE TRIGGER oid_ledger_entry_immutable_trg BEFORE UPDATE OR DELETE ON oid_ledger_entry
    FOR EACH ROW EXECUTE FUNCTION oid_ledger_reject_immutable_mutation()`,
  `DROP TRIGGER IF EXISTS oid_ledger_operation_immutable_trg ON oid_ledger_operation`,
  `CREATE TRIGGER oid_ledger_operation_immutable_trg BEFORE UPDATE OR DELETE ON oid_ledger_operation
    FOR EACH ROW EXECUTE FUNCTION oid_ledger_reject_immutable_mutation()`,
  `DROP TRIGGER IF EXISTS oid_ledger_audit_immutable_trg ON oid_ledger_audit`,
  `CREATE TRIGGER oid_ledger_audit_immutable_trg BEFORE UPDATE OR DELETE ON oid_ledger_audit
    FOR EACH ROW EXECUTE FUNCTION oid_ledger_reject_immutable_mutation()`
];

export async function migrateLedger(tx: LedgerMigrationTransaction): Promise<void> {
  for (const statement of ledgerMigrationStatements) await tx.unsafe(statement);
}
