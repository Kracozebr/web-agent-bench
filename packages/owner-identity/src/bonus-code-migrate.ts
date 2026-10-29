export interface BonusCodeMigrationTransaction {
  unsafe(query: string, parameters?: unknown[]): Promise<unknown>;
}

export const bonusCodeMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_bonus_code (
    id uuid PRIMARY KEY,
    issuer_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    label text NOT NULL,
    kind text NOT NULL,
    amount_units bigint NOT NULL,
    maximum_uses integer NOT NULL,
    used_count integer NOT NULL DEFAULT 0,
    verifier_hash text NOT NULL,
    issue_operation_id text NOT NULL,
    issue_payload_hash text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    disable_operation_id text,
    disable_payload_hash text,
    CONSTRAINT oid_bonus_code_label_check CHECK(char_length(label) BETWEEN 1 AND 100),
    CONSTRAINT oid_bonus_code_kind_check CHECK(kind IN ('group','single_use')),
    CONSTRAINT oid_bonus_code_amount_check CHECK(amount_units > 0),
    CONSTRAINT oid_bonus_code_maximum_uses_check CHECK(maximum_uses > 0),
    CONSTRAINT oid_bonus_code_used_count_check CHECK(used_count >= 0 AND used_count <= maximum_uses),
    CONSTRAINT oid_bonus_code_single_use_check CHECK(kind <> 'single_use' OR maximum_uses = 1),
    CONSTRAINT oid_bonus_code_verifier_hash_check CHECK(verifier_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oid_bonus_code_issue_operation_id_check CHECK(issue_operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    CONSTRAINT oid_bonus_code_issue_payload_hash_check CHECK(issue_payload_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oid_bonus_code_disable_operation_id_check CHECK(disable_operation_id IS NULL OR disable_operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    CONSTRAINT oid_bonus_code_disable_payload_hash_check CHECK(disable_payload_hash IS NULL OR disable_payload_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oid_bonus_code_disable_fields_check CHECK(
      (disabled_at IS NULL AND disable_operation_id IS NULL AND disable_payload_hash IS NULL)
      OR (disabled_at IS NOT NULL AND disable_operation_id IS NOT NULL AND disable_payload_hash IS NOT NULL)
    ),
    CONSTRAINT oid_bonus_code_verifier_uq UNIQUE(verifier_hash),
    CONSTRAINT oid_bonus_code_issuer_operation_uq UNIQUE(issuer_owner_id,issue_operation_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_bonus_code_issuer_issued_idx ON oid_bonus_code(issuer_owner_id,issued_at,id)`,
  `CREATE TABLE IF NOT EXISTS oid_bonus_code_redemption (
    id uuid PRIMARY KEY,
    code_id uuid NOT NULL REFERENCES oid_bonus_code(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    bonus_grant_id uuid NOT NULL,
    financial_operation_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_bonus_code_redemption_grant_fk FOREIGN KEY(owner_id,bonus_grant_id)
      REFERENCES oid_bonus_grant(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_bonus_code_redemption_code_owner_uq UNIQUE(code_id,owner_id),
    CONSTRAINT oid_bonus_code_redemption_grant_uq UNIQUE(bonus_grant_id),
    CONSTRAINT oid_bonus_code_redemption_financial_operation_uq UNIQUE(financial_operation_id),
    CONSTRAINT oid_bonus_code_redemption_financial_operation_id_check CHECK(financial_operation_id ~ '^[A-Za-z0-9_-]{12,128}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_bonus_code_redemption_owner_created_idx ON oid_bonus_code_redemption(owner_id,created_at,id)`,
  `CREATE TABLE IF NOT EXISTS oid_bonus_code_claim_operation (
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    operation_id text NOT NULL,
    code_id uuid NOT NULL REFERENCES oid_bonus_code(id) ON DELETE RESTRICT,
    redemption_id uuid NOT NULL REFERENCES oid_bonus_code_redemption(id) ON DELETE RESTRICT,
    payload_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_bonus_code_claim_operation_owner_key_uq UNIQUE(owner_id,operation_id),
    CONSTRAINT oid_bonus_code_claim_operation_id_check CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    CONSTRAINT oid_bonus_code_claim_operation_payload_hash_check CHECK(payload_hash ~ '^[0-9a-f]{64}$')
  )`,
  `CREATE INDEX IF NOT EXISTS oid_bonus_code_claim_operation_redemption_idx ON oid_bonus_code_claim_operation(redemption_id)`,
  `CREATE OR REPLACE FUNCTION oid_bonus_code_guard_updates() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'bonus code offers are append-only' USING ERRCODE = '55000';
      END IF;
      IF NEW.id IS DISTINCT FROM OLD.id
         OR NEW.issuer_owner_id IS DISTINCT FROM OLD.issuer_owner_id
         OR NEW.label IS DISTINCT FROM OLD.label
         OR NEW.kind IS DISTINCT FROM OLD.kind
         OR NEW.amount_units IS DISTINCT FROM OLD.amount_units
         OR NEW.maximum_uses IS DISTINCT FROM OLD.maximum_uses
         OR NEW.verifier_hash IS DISTINCT FROM OLD.verifier_hash
         OR NEW.issue_operation_id IS DISTINCT FROM OLD.issue_operation_id
         OR NEW.issue_payload_hash IS DISTINCT FROM OLD.issue_payload_hash
         OR NEW.issued_at IS DISTINCT FROM OLD.issued_at THEN
        RAISE EXCEPTION 'bonus code terms are immutable' USING ERRCODE = '55000';
      END IF;
      IF NEW.used_count < OLD.used_count OR NEW.used_count > OLD.used_count + 1 THEN
        RAISE EXCEPTION 'bonus code usage must increase one claim at a time' USING ERRCODE = '55000';
      END IF;
      IF OLD.disabled_at IS NOT NULL AND
         (NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
          OR NEW.disable_operation_id IS DISTINCT FROM OLD.disable_operation_id
          OR NEW.disable_payload_hash IS DISTINCT FROM OLD.disable_payload_hash) THEN
        RAISE EXCEPTION 'bonus code disable state is immutable' USING ERRCODE = '55000';
      END IF;
      IF OLD.disabled_at IS NULL AND NEW.disabled_at IS NULL AND
         (NEW.disable_operation_id IS NOT NULL OR NEW.disable_payload_hash IS NOT NULL) THEN
        RAISE EXCEPTION 'bonus code disable state is incomplete' USING ERRCODE = '55000';
      END IF;
      IF OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL AND NEW.used_count <> OLD.used_count THEN
        RAISE EXCEPTION 'bonus code cannot be disabled and redeemed in one update' USING ERRCODE = '55000';
      END IF;
      RETURN NEW;
    END;
    $$`,
  `DROP TRIGGER IF EXISTS oid_bonus_code_immutable_terms_trg ON oid_bonus_code`,
  `CREATE TRIGGER oid_bonus_code_immutable_terms_trg BEFORE UPDATE OR DELETE ON oid_bonus_code
    FOR EACH ROW EXECUTE FUNCTION oid_bonus_code_guard_updates()`
];

export async function migrateBonusCodes(tx: BonusCodeMigrationTransaction): Promise<void> {
  for (const statement of bonusCodeMigrationStatements) await tx.unsafe(statement);
}
