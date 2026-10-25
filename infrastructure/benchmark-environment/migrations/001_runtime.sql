BEGIN;

CREATE TABLE IF NOT EXISTS bef_environment (
  env_id text PRIMARY KEY,
  chain_id bigint NOT NULL,
  node_identity text NOT NULL,
  manifest_sha256 char(64) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS bef_generation (
  generation_id uuid PRIMARY KEY,
  env_id text NOT NULL REFERENCES bef_environment(env_id),
  participant_id text NOT NULL,
  run_token_sha256 char(64) NOT NULL,
  payer_address text NOT NULL,
  resource_variant text NOT NULL DEFAULT 'canonical' CHECK (resource_variant IN ('canonical', 'mismatched_data', 'verification_without_receipt')),
  status text NOT NULL CHECK (status IN ('active', 'fenced', 'reset')),
  fixture_hash char(64),
  fixture_transaction_hash text,
  fixture_block_hash text,
  fixture_token_delta_units numeric(78,0),
  fixture_native_balance_wei numeric(78,0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  fenced_at timestamptz,
  UNIQUE (env_id, generation_id)
);

ALTER TABLE bef_generation ADD COLUMN IF NOT EXISTS fixture_transaction_hash text;
ALTER TABLE bef_generation ADD COLUMN IF NOT EXISTS fixture_block_hash text;
ALTER TABLE bef_generation ADD COLUMN IF NOT EXISTS fixture_token_delta_units numeric(78,0);
ALTER TABLE bef_generation ADD COLUMN IF NOT EXISTS fixture_native_balance_wei numeric(78,0);

CREATE UNIQUE INDEX IF NOT EXISTS bef_one_active_generation_per_env
  ON bef_generation(env_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS bef_operation (
  operation_id uuid PRIMARY KEY,
  env_id text NOT NULL,
  generation_id uuid NOT NULL REFERENCES bef_generation(generation_id),
  participant_id text NOT NULL,
  idempotency_key_sha256 char(64) NOT NULL,
  request_sha256 char(64) NOT NULL,
  operation_kind text NOT NULL,
  status text NOT NULL CHECK (status IN ('accepted', 'awaiting_payment', 'verifying', 'settling', 'settlement_unknown', 'settled', 'delivered', 'rejected', 'reverted')),
  authorization_sha256 char(64),
  transaction_hash text,
  receipt_status text NOT NULL DEFAULT 'unknown' CHECK (receipt_status IN ('unknown', 'not_submitted', 'success', 'reverted')),
  response_sha256 char(64),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  UNIQUE (env_id, generation_id, participant_id, idempotency_key_sha256),
  UNIQUE (operation_id, env_id, generation_id),
  FOREIGN KEY (env_id, generation_id) REFERENCES bef_generation(env_id, generation_id)
);

CREATE TABLE IF NOT EXISTS bef_payment (
  payment_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES bef_operation(operation_id),
  env_id text NOT NULL,
  generation_id uuid NOT NULL,
  authorization_sha256 char(64) NOT NULL,
  payer_address text,
  network text NOT NULL,
  asset_address text NOT NULL,
  amount_units numeric(78,0) NOT NULL,
  facilitator_address text,
  transaction_hash text,
  receipt_status text NOT NULL CHECK (receipt_status IN ('unknown', 'not_submitted', 'success', 'reverted')),
  token_delta_units numeric(78,0),
  payer_balance_before numeric(78,0),
  payer_balance_after numeric(78,0),
  facilitator_balance_before numeric(78,0),
  facilitator_balance_after numeric(78,0),
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (env_id, generation_id) REFERENCES bef_generation(env_id, generation_id),
  CONSTRAINT bef_payment_operation_scope_fk FOREIGN KEY (operation_id, env_id, generation_id) REFERENCES bef_operation(operation_id, env_id, generation_id),
  UNIQUE (env_id, generation_id, network, transaction_hash)
);

ALTER TABLE bef_payment ADD COLUMN IF NOT EXISTS payer_balance_before numeric(78,0);
ALTER TABLE bef_payment ADD COLUMN IF NOT EXISTS payer_balance_after numeric(78,0);
ALTER TABLE bef_payment ADD COLUMN IF NOT EXISTS facilitator_balance_before numeric(78,0);
ALTER TABLE bef_payment ADD COLUMN IF NOT EXISTS facilitator_balance_after numeric(78,0);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bef_payment_operation_scope_fk') THEN
    ALTER TABLE bef_payment ADD CONSTRAINT bef_payment_operation_scope_fk
      FOREIGN KEY (operation_id, env_id, generation_id) REFERENCES bef_operation(operation_id, env_id, generation_id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS bef_x402_observation (
  observation_id uuid PRIMARY KEY,
  env_id text NOT NULL,
  generation_id uuid,
  operation_id uuid,
  variant_id text,
  phase text NOT NULL CHECK (phase IN ('supported', 'verify', 'settle')),
  request_sha256 char(64) NOT NULL,
  safe_request jsonb NOT NULL,
  response_sha256 char(64),
  safe_response jsonb,
  outcome text NOT NULL CHECK (outcome IN ('success', 'rejected', 'unknown', 'error')),
  transaction_hash text,
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (env_id) REFERENCES bef_environment(env_id),
  FOREIGN KEY (env_id, generation_id) REFERENCES bef_generation(env_id, generation_id),
  FOREIGN KEY (operation_id, env_id, generation_id) REFERENCES bef_operation(operation_id, env_id, generation_id)
);

CREATE TABLE IF NOT EXISTS bef_delivery (
  delivery_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES bef_operation(operation_id),
  resource_id text NOT NULL,
  content_sha256 char(64) NOT NULL,
  content_bytes bigint NOT NULL CHECK (content_bytes >= 0),
  delivered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS bef_denial (
  denial_id uuid PRIMARY KEY,
  env_id text,
  generation_id uuid,
  operation_id uuid,
  route text NOT NULL,
  reason_code text NOT NULL,
  request_sha256 char(64) NOT NULL,
  protected_state_sha256 char(64),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS bef_rpc_observation (
  observation_id uuid PRIMARY KEY,
  operation_id uuid,
  boundary text NOT NULL CHECK (boundary IN ('source-readonly-proxy', 'local-chain-readonly-proxy')),
  method text NOT NULL,
  params_sha256 char(64) NOT NULL,
  result_sha256 char(64),
  forwarded boolean NOT NULL,
  response_status text NOT NULL CHECK (response_status IN ('observed', 'denied', 'unknown', 'error')),
  source_block_hash text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS bef_evidence_artifact (
  artifact_id uuid PRIMARY KEY,
  operation_id uuid,
  generation_id uuid,
  relative_path text NOT NULL,
  sha256 char(64) NOT NULL,
  boundary text NOT NULL,
  content_type text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (relative_path, sha256)
);

CREATE TABLE IF NOT EXISTS bef_resource_sample (
  sample_id uuid PRIMARY KEY,
  trial_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('api', 'facilitator', 'anvil-a', 'anvil-b', 'postgres', 'evidence')),
  elapsed_ms bigint,
  cpu_nanoseconds bigint,
  peak_memory_bytes bigint,
  artifact_bytes bigint,
  source_calls integer,
  observed_status text NOT NULL CHECK (observed_status IN ('observed', 'unknown', 'guardrail_stopped')),
  sampled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS bef_operation_generation_idx ON bef_operation(env_id, generation_id, started_at);
CREATE INDEX IF NOT EXISTS bef_rpc_operation_idx ON bef_rpc_observation(operation_id, created_at);
CREATE INDEX IF NOT EXISTS bef_artifact_operation_idx ON bef_evidence_artifact(operation_id, created_at);
CREATE INDEX IF NOT EXISTS bef_x402_operation_idx ON bef_x402_observation(operation_id, observed_at);

COMMIT;
