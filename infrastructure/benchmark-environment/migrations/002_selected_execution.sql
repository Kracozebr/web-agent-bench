BEGIN;

-- Selected-action receipts and transaction intent are durable; signer material
-- and signed transaction bytes remain process-local and are never stored here.

-- Existing generations cannot be assigned an invented manifest identity.
-- The API fences them on restart and binds new generations to the loaded file.
ALTER TABLE bef_generation ADD COLUMN IF NOT EXISTS manifest_sha256 char(64);
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bef_generation_manifest_sha256_ck') THEN
    ALTER TABLE bef_generation ADD CONSTRAINT bef_generation_manifest_sha256_ck
      CHECK (manifest_sha256 IS NULL OR manifest_sha256 ~ '^[0-9a-f]{64}$');
  END IF;
END $$;

CREATE OR REPLACE FUNCTION bef_protect_generation_manifest_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.manifest_sha256 IS NULL THEN
    RAISE EXCEPTION 'new generation requires a pinned manifest identity';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256 THEN
    RAISE EXCEPTION 'generation manifest identity is immutable';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bef_generation_manifest_identity_immutable ON bef_generation;
CREATE TRIGGER bef_generation_manifest_identity_immutable
  BEFORE INSERT OR UPDATE ON bef_generation
  FOR EACH ROW EXECUTE FUNCTION bef_protect_generation_manifest_identity();

CREATE TABLE IF NOT EXISTS bef_selected_execution (
  operation_id uuid PRIMARY KEY,
  env_id text NOT NULL,
  generation_id uuid NOT NULL,
  action_kind text NOT NULL CHECK (action_kind IN ('approve', 'wrap', 'unwrap', 'swap')),
  selected_action_json jsonb NOT NULL CHECK (jsonb_typeof(selected_action_json) = 'object'),
  prestate_json jsonb CHECK (prestate_json IS NULL OR jsonb_typeof(prestate_json) = 'object'),
  transaction_intent_json jsonb CHECK (transaction_intent_json IS NULL OR jsonb_typeof(transaction_intent_json) = 'object'),
  transaction_hash text CHECK (transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-fA-F]{64}$'),
  outcome text NOT NULL DEFAULT 'prepared'
    CHECK (outcome IN ('prepared', 'settling', 'settlement_unknown', 'success', 'reverted', 'rejected')),
  reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[a-z0-9_]{1,80}$'),
  measurement_json jsonb CHECK (measurement_json IS NULL OR jsonb_typeof(measurement_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CONSTRAINT bef_selected_execution_operation_scope_fk
    FOREIGN KEY (operation_id, env_id, generation_id)
    REFERENCES bef_operation(operation_id, env_id, generation_id),
  CONSTRAINT bef_selected_execution_state_shape_ck CHECK (
    (outcome = 'prepared'
      AND transaction_hash IS NULL AND transaction_intent_json IS NULL
      AND measurement_json IS NULL AND reason_code IS NULL AND completed_at IS NULL)
    OR
    (outcome = 'settling'
      AND transaction_hash IS NOT NULL AND transaction_intent_json IS NOT NULL
      AND measurement_json IS NULL AND reason_code IS NULL AND completed_at IS NULL)
    OR
    (outcome = 'settlement_unknown'
      AND transaction_hash IS NOT NULL AND transaction_intent_json IS NOT NULL
      AND reason_code IS NULL AND completed_at IS NULL)
    OR
    (outcome IN ('success', 'reverted')
      AND transaction_hash IS NOT NULL AND transaction_intent_json IS NOT NULL
      AND measurement_json IS NOT NULL AND reason_code IS NULL AND completed_at IS NOT NULL)
    OR
    (outcome = 'rejected'
      AND transaction_hash IS NULL AND transaction_intent_json IS NULL
      AND measurement_json IS NULL AND reason_code IS NOT NULL AND completed_at IS NOT NULL)
  )
);

-- A local Anvil reset creates a new isolated chain state. Transaction identity
-- is therefore scoped by environment and generation, not chain id alone.
CREATE UNIQUE INDEX IF NOT EXISTS bef_selected_execution_scoped_tx_hash_uq
  ON bef_selected_execution(env_id, generation_id, transaction_hash)
  WHERE transaction_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS bef_selected_execution_outcome_idx
  ON bef_selected_execution(env_id, generation_id, outcome, updated_at);

CREATE TABLE IF NOT EXISTS bef_selected_execution_event (
  event_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  operation_id uuid NOT NULL,
  env_id text NOT NULL,
  generation_id uuid NOT NULL,
  event_kind text NOT NULL CHECK (event_kind IN (
    'selected_action_bound', 'prestate_observed', 'original_tx_hash_bound',
    'settlement_unknown', 'receipt_finalized', 'rejected_before_broadcast'
  )),
  transaction_hash text CHECK (transaction_hash IS NULL OR transaction_hash ~ '^0x[0-9a-fA-F]{64}$'),
  event_json jsonb NOT NULL CHECK (jsonb_typeof(event_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT bef_selected_execution_event_scope_fk
    FOREIGN KEY (operation_id, env_id, generation_id)
    REFERENCES bef_operation(operation_id, env_id, generation_id)
);

CREATE INDEX IF NOT EXISTS bef_selected_execution_event_operation_idx
  ON bef_selected_execution_event(operation_id, event_sequence);

CREATE OR REPLACE FUNCTION bef_protect_selected_execution_event()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'selected execution events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS bef_selected_execution_event_no_mutation ON bef_selected_execution_event;
CREATE TRIGGER bef_selected_execution_event_no_mutation
  BEFORE UPDATE OR DELETE ON bef_selected_execution_event
  FOR EACH ROW EXECUTE FUNCTION bef_protect_selected_execution_event();

-- The runtime role writes events but cannot rewrite or delete their history.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bef_api') THEN
    REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE bef_selected_execution_event FROM bef_api;
  END IF;
END $$;

COMMIT;
