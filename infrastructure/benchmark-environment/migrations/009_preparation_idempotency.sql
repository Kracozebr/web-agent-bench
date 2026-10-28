BEGIN;

CREATE TABLE bef_preparation (
  preparation_id uuid PRIMARY KEY,
  env_id text NOT NULL REFERENCES bef_environment(env_id),
  public_pins_sha256 char(64),
  request_sha256 char(64),
  participant_id text,
  payer_address text,
  resource_variant text,
  manifest_sha256 char(64),
  generation_id uuid,
  status text NOT NULL CHECK (status IN ('preparing', 'ready', 'unknown', 'fenced')),
  fixture_state text NOT NULL DEFAULT 'not_started'
    CHECK (fixture_state IN ('not_started', 'hash_bound', 'observed', 'unknown', 'reconciled')),
  fixture_transaction_hash text,
  fixture_block_hash text,
  fixture_hash char(64),
  fixture_facts jsonb,
  reset_identity jsonb,
  reset_completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  fence_confirmed_at timestamptz,
  CONSTRAINT bef_preparation_generation_scope_fk
    FOREIGN KEY (env_id, generation_id) REFERENCES bef_generation(env_id, generation_id)
    DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT bef_preparation_generation_unique UNIQUE (env_id, generation_id),
  CONSTRAINT bef_preparation_request_sha256_ck CHECK (
    request_sha256 IS NULL OR (char_length(request_sha256) = 64 AND request_sha256 !~ '[^0-9a-f]')
  ),
  CONSTRAINT bef_preparation_public_pins_sha256_ck CHECK (
    public_pins_sha256 IS NULL OR (char_length(public_pins_sha256) = 64 AND public_pins_sha256 !~ '[^0-9a-f]')
  ),
  CONSTRAINT bef_preparation_manifest_sha256_ck CHECK (
    manifest_sha256 IS NULL OR (char_length(manifest_sha256) = 64 AND manifest_sha256 !~ '[^0-9a-f]')
  ),
  CONSTRAINT bef_preparation_fixture_sha256_ck CHECK (
    fixture_hash IS NULL OR (char_length(fixture_hash) = 64 AND fixture_hash !~ '[^0-9a-f]')
  ),
  CONSTRAINT bef_preparation_payer_address_ck CHECK (
    payer_address IS NULL OR (char_length(payer_address) = 42 AND payer_address ~* '^0x[0-9a-f]{40}$')
  ),
  CONSTRAINT bef_preparation_fixture_tx_hash_ck CHECK (
    fixture_transaction_hash IS NULL OR
    (char_length(fixture_transaction_hash) = 66 AND fixture_transaction_hash ~* '^0x[0-9a-f]{64}$')
  ),
  CONSTRAINT bef_preparation_fixture_block_hash_ck CHECK (
    fixture_block_hash IS NULL OR
    (char_length(fixture_block_hash) = 66 AND fixture_block_hash ~* '^0x[0-9a-f]{64}$')
  ),
  CONSTRAINT bef_preparation_identity_ck CHECK (
    (generation_id IS NULL AND public_pins_sha256 IS NULL AND request_sha256 IS NULL AND participant_id IS NULL AND payer_address IS NULL
      AND resource_variant IS NULL AND manifest_sha256 IS NULL AND status = 'fenced' AND fence_confirmed_at IS NOT NULL)
    OR
    (generation_id IS NULL AND public_pins_sha256 IS NOT NULL AND request_sha256 IS NOT NULL AND participant_id IS NOT NULL
      AND char_length(participant_id) BETWEEN 1 AND 128 AND octet_length(participant_id)=char_length(participant_id)
      AND participant_id !~ '[[:space:][:cntrl:]]'
      AND payer_address IS NOT NULL AND resource_variant IS NOT NULL
      AND resource_variant IN ('canonical', 'mismatched_data', 'verification_without_receipt')
      AND manifest_sha256 IS NOT NULL AND status = 'fenced' AND fence_confirmed_at IS NOT NULL)
    OR
    (public_pins_sha256 IS NOT NULL AND request_sha256 IS NOT NULL AND participant_id IS NOT NULL
      AND char_length(participant_id) BETWEEN 1 AND 128 AND octet_length(participant_id)=char_length(participant_id)
      AND participant_id !~ '[[:space:][:cntrl:]]'
      AND payer_address IS NOT NULL AND resource_variant IS NOT NULL
      AND resource_variant IN ('canonical', 'mismatched_data', 'verification_without_receipt')
      AND manifest_sha256 IS NOT NULL AND (generation_id IS NOT NULL OR status IN ('preparing', 'unknown')))
  ),
  CONSTRAINT bef_preparation_fence_state_ck CHECK (
    (status = 'fenced' AND fence_confirmed_at IS NOT NULL)
    OR (status <> 'fenced' AND fence_confirmed_at IS NULL)
  ),
  CONSTRAINT bef_preparation_ready_fixture_ck CHECK (
    status <> 'ready' OR (fixture_state = 'observed' AND generation_id IS NOT NULL AND reset_completed_at IS NOT NULL)
  ),
  CONSTRAINT bef_preparation_generation_reset_ck CHECK (generation_id IS NULL OR reset_completed_at IS NOT NULL),
  CONSTRAINT bef_preparation_reset_proof_ck CHECK (
    (reset_identity IS NULL AND reset_completed_at IS NULL)
    OR (reset_identity IS NOT NULL AND jsonb_typeof(reset_identity) = 'object' AND reset_completed_at IS NOT NULL)
  ),
  CONSTRAINT bef_preparation_fixture_state_ck CHECK (
    (fixture_state = 'not_started' AND fixture_transaction_hash IS NULL AND fixture_block_hash IS NULL AND fixture_facts IS NULL)
    OR (fixture_state = 'hash_bound' AND fixture_transaction_hash IS NOT NULL)
    OR (fixture_state = 'observed' AND fixture_transaction_hash IS NOT NULL AND fixture_block_hash IS NOT NULL
      AND fixture_hash IS NOT NULL AND fixture_facts IS NOT NULL AND jsonb_typeof(fixture_facts) = 'object')
    OR (fixture_state = 'unknown')
    OR (fixture_state = 'reconciled' AND fixture_transaction_hash IS NOT NULL AND fixture_block_hash IS NOT NULL
      AND fixture_facts IS NOT NULL AND jsonb_typeof(fixture_facts) = 'object')
  )
);

CREATE INDEX bef_preparation_environment_status_idx ON bef_preparation(env_id, status, created_at);

CREATE FUNCTION bef_guard_preparation_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
    RAISE EXCEPTION 'preparation identities are append-only';
  END IF;

  IF TG_OP = 'UPDATE' THEN
    IF NEW.preparation_id IS DISTINCT FROM OLD.preparation_id
      OR NEW.env_id IS DISTINCT FROM OLD.env_id
      OR NEW.public_pins_sha256 IS DISTINCT FROM OLD.public_pins_sha256
      OR NEW.request_sha256 IS DISTINCT FROM OLD.request_sha256
      OR NEW.participant_id IS DISTINCT FROM OLD.participant_id
      OR NEW.payer_address IS DISTINCT FROM OLD.payer_address
      OR NEW.resource_variant IS DISTINCT FROM OLD.resource_variant
      OR NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256
      OR (OLD.generation_id IS NOT NULL AND NEW.generation_id IS DISTINCT FROM OLD.generation_id)
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'preparation identity is immutable';
    END IF;

    IF OLD.generation_id IS NULL AND NEW.generation_id IS NOT NULL
      AND (OLD.status <> 'preparing' OR NEW.status <> 'preparing') THEN
      RAISE EXCEPTION 'preparation generation can only be bound while preparing';
    END IF;

    IF NOT (
      (OLD.status = 'preparing' AND NEW.status IN ('preparing', 'ready', 'unknown', 'fenced'))
      OR (OLD.status = 'ready' AND NEW.status IN ('ready', 'fenced'))
      OR (OLD.status = 'unknown' AND NEW.status IN ('unknown', 'fenced'))
      OR (OLD.status = 'fenced' AND NEW.status = 'fenced')
    ) THEN
      RAISE EXCEPTION 'preparation status cannot move backwards';
    END IF;

    IF NOT (
      (OLD.fixture_state = 'not_started' AND NEW.fixture_state IN ('not_started', 'hash_bound', 'unknown'))
      OR (OLD.fixture_state = 'hash_bound' AND NEW.fixture_state IN ('hash_bound', 'observed', 'unknown', 'reconciled'))
      OR (OLD.fixture_state = 'unknown' AND NEW.fixture_state IN ('unknown', 'reconciled'))
      OR (OLD.fixture_state = 'observed' AND NEW.fixture_state = 'observed')
      OR (OLD.fixture_state = 'reconciled' AND NEW.fixture_state = 'reconciled')
    ) THEN
      RAISE EXCEPTION 'preparation fixture state cannot move backwards';
    END IF;

    IF OLD.fixture_transaction_hash IS NOT NULL AND NEW.fixture_transaction_hash IS DISTINCT FROM OLD.fixture_transaction_hash THEN
      RAISE EXCEPTION 'original fixture transaction hash is immutable';
    END IF;
    IF OLD.fixture_block_hash IS NOT NULL AND NEW.fixture_block_hash IS DISTINCT FROM OLD.fixture_block_hash THEN
      RAISE EXCEPTION 'original fixture block hash is immutable';
    END IF;
    IF OLD.fixture_hash IS NOT NULL AND NEW.fixture_hash IS DISTINCT FROM OLD.fixture_hash THEN
      RAISE EXCEPTION 'fixture identity hash is immutable';
    END IF;
    IF OLD.fixture_facts IS NOT NULL AND NEW.fixture_facts IS DISTINCT FROM OLD.fixture_facts THEN
      RAISE EXCEPTION 'fixture facts are immutable';
    END IF;
    IF OLD.reset_identity IS NOT NULL AND NEW.reset_identity IS DISTINCT FROM OLD.reset_identity THEN
      RAISE EXCEPTION 'preparation reset identity is immutable';
    END IF;
    IF OLD.reset_completed_at IS NOT NULL AND NEW.reset_completed_at IS DISTINCT FROM OLD.reset_completed_at THEN
      RAISE EXCEPTION 'preparation reset time is immutable';
    END IF;
    IF OLD.fence_confirmed_at IS NOT NULL AND NEW.fence_confirmed_at IS DISTINCT FROM OLD.fence_confirmed_at THEN
      RAISE EXCEPTION 'preparation fence receipt is immutable';
    END IF;
  END IF;

  NEW.updated_at := clock_timestamp();
  RETURN NEW;
END;
$$;

CREATE TRIGGER bef_preparation_state_guard
  BEFORE UPDATE OR DELETE ON bef_preparation
  FOR EACH ROW EXECUTE FUNCTION bef_guard_preparation_state();

CREATE TRIGGER bef_preparation_no_truncate
  BEFORE TRUNCATE ON bef_preparation
  FOR EACH STATEMENT EXECUTE FUNCTION bef_guard_preparation_state();

COMMIT;
