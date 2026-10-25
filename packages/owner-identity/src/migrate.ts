import { loadConfig } from "./config.js";
import { createDatabase } from "./db.js";

const statements = [
  `CREATE TABLE IF NOT EXISTS oid_auth_user (
    id text PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false, image text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_auth_session (
    id text PRIMARY KEY, expires_at timestamptz NOT NULL, token text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    ip_address text, user_agent text, user_id text NOT NULL REFERENCES oid_auth_user(id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS oid_auth_session_user_idx ON oid_auth_session(user_id)`,
  `CREATE TABLE IF NOT EXISTS oid_auth_account (
    id text PRIMARY KEY, account_id text NOT NULL, provider_id text NOT NULL,
    user_id text NOT NULL REFERENCES oid_auth_user(id) ON DELETE CASCADE,
    access_token text, refresh_token text, id_token text, access_token_expires_at timestamptz,
    refresh_token_expires_at timestamptz, scope text, password text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_auth_account_provider_subject_uq UNIQUE(provider_id, account_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_auth_account_user_idx ON oid_auth_account(user_id)`,
  `CREATE TABLE IF NOT EXISTS oid_auth_verification (
    id text PRIMARY KEY, identifier text NOT NULL, value text NOT NULL, expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS oid_auth_verification_identifier_idx ON oid_auth_verification(identifier)`,
  `CREATE TABLE IF NOT EXISTS oid_auth_wallet_address (
    id text PRIMARY KEY, user_id text NOT NULL REFERENCES oid_auth_user(id) ON DELETE CASCADE,
    address text NOT NULL, chain_id integer NOT NULL, is_primary boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_auth_wallet_address_chain_uq UNIQUE(address,chain_id)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_auth_wallet_user_idx ON oid_auth_wallet_address(user_id)`,
  `CREATE TABLE IF NOT EXISTS oid_owner (
    id uuid PRIMARY KEY, auth_user_id text NOT NULL UNIQUE REFERENCES oid_auth_user(id) ON DELETE CASCADE,
    admission_status text NOT NULL CHECK (admission_status IN ('pending','admitted')),
    created_at timestamptz NOT NULL DEFAULT now(), admitted_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS oid_owner_admission_status_idx ON oid_owner(admission_status)`,
  `CREATE TABLE IF NOT EXISTS oid_agent (
    id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80), description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    client_metadata jsonb NOT NULL DEFAULT '{"clientName":null,"modelName":null}'::jsonb CHECK (jsonb_typeof(client_metadata)='object'),
    declared_version text CHECK (declared_version IS NULL OR length(declared_version) <= 80),
    revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
    access_revision integer NOT NULL DEFAULT 1 CHECK (access_revision > 0),
    access_generation integer NOT NULL DEFAULT 1 CHECK (access_generation > 0),
    access_revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_agent_owner_id_uq UNIQUE(owner_id,id)
  )`,
  `ALTER TABLE oid_agent ADD COLUMN IF NOT EXISTS access_revision integer NOT NULL DEFAULT 1 CHECK (access_revision > 0)`,
  `ALTER TABLE oid_agent ADD COLUMN IF NOT EXISTS access_generation integer NOT NULL DEFAULT 1 CHECK (access_generation > 0)`,
  `ALTER TABLE oid_agent ADD COLUMN IF NOT EXISTS access_revoked_at timestamptz`,
  `CREATE INDEX IF NOT EXISTS oid_agent_owner_updated_idx ON oid_agent(owner_id,updated_at)`,
  `CREATE TABLE IF NOT EXISTS oid_agent_policy (
    agent_id uuid PRIMARY KEY REFERENCES oid_agent(id) ON DELETE CASCADE,
    training boolean NOT NULL DEFAULT false, ranked boolean NOT NULL DEFAULT false,
    forum_messages boolean NOT NULL DEFAULT false, custom_topics boolean NOT NULL DEFAULT false,
    revision integer NOT NULL DEFAULT 1 CHECK (revision > 0), updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_agent_operation (
    operation_id text PRIMARY KEY, owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE CASCADE,
    agent_id uuid REFERENCES oid_agent(id) ON DELETE CASCADE, action text NOT NULL,
    payload_hash text NOT NULL, response_json jsonb, created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS oid_agent_operation_owner_created_idx ON oid_agent_operation(owner_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_agent_access_grant (
    id uuid PRIMARY KEY, owner_id uuid NOT NULL, agent_id uuid NOT NULL,
    operation_id text NOT NULL UNIQUE, source text NOT NULL DEFAULT 'manual' CHECK (source='manual'),
    resource text NOT NULL, role text NOT NULL DEFAULT 'agent' CHECK (role='agent'),
    access_generation integer NOT NULL CHECK (access_generation > 0),
    created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text CHECK (revocation_reason IS NULL OR revocation_reason IN ('replaced','owner_global_revoke')),
    CONSTRAINT oid_agent_access_grant_owner_agent_fk FOREIGN KEY(owner_id,agent_id)
      REFERENCES oid_agent(owner_id,id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS oid_agent_access_grant_agent_created_idx ON oid_agent_access_grant(agent_id,created_at)`,
  `CREATE INDEX IF NOT EXISTS oid_agent_access_grant_agent_generation_idx ON oid_agent_access_grant(agent_id,access_generation)`,
  `CREATE TABLE IF NOT EXISTS oid_agent_manual_credential (
    id uuid PRIMARY KEY, grant_id uuid NOT NULL UNIQUE REFERENCES oid_agent_access_grant(id) ON DELETE CASCADE,
    verifier_hash text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS oid_agent_manual_credential_created_idx ON oid_agent_manual_credential(created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_agent_cancellation_outbox (
    event_id uuid PRIMARY KEY, owner_id uuid NOT NULL, agent_id uuid NOT NULL,
    access_generation integer NOT NULL CHECK (access_generation > 0),
    operation_id text NOT NULL UNIQUE, event_type text NOT NULL DEFAULT 'agent.access.revoked'
      CHECK (event_type='agent.access.revoked'),
    status text NOT NULL DEFAULT 'pending' CHECK (status='pending'),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json)='object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_agent_cancellation_outbox_owner_agent_fk FOREIGN KEY(owner_id,agent_id)
      REFERENCES oid_agent(owner_id,id) ON DELETE CASCADE,
    CONSTRAINT oid_agent_cancellation_outbox_agent_generation_uq UNIQUE(agent_id,access_generation)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_agent_cancellation_outbox_status_created_idx ON oid_agent_cancellation_outbox(status,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_auth_flow (
    id uuid PRIMARY KEY, operation_id text NOT NULL UNIQUE, provider text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('signin','link')),
    owner_id uuid REFERENCES oid_owner(id) ON DELETE CASCADE,
    auth_session_id text REFERENCES oid_auth_session(id) ON DELETE CASCADE,
    attempt_hash text NOT NULL, started_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL, completed_at timestamptz, outcome text
  )`,
  `CREATE INDEX IF NOT EXISTS oid_auth_flow_context_idx ON oid_auth_flow(attempt_hash,started_at)`,
  `CREATE TABLE IF NOT EXISTS oid_identity (
    id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE CASCADE,
    auth_user_id text NOT NULL REFERENCES oid_auth_user(id) ON DELETE CASCADE,
    provider text NOT NULL, subject text NOT NULL, verified_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_identity_provider_subject_uq UNIQUE(provider,subject),
    CONSTRAINT oid_identity_owner_provider_uq UNIQUE(owner_id,provider)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_identity_auth_user_idx ON oid_identity(auth_user_id)`,
  `CREATE TABLE IF NOT EXISTS oid_invitation (
    id uuid PRIMARY KEY, verifier_hash text NOT NULL UNIQUE, issue_operation_id text,
    issued_by_owner_id uuid NOT NULL REFERENCES oid_owner(id), created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL, revoked_at timestamptz, redeemed_at timestamptz
  )`,
  `ALTER TABLE oid_invitation ADD COLUMN IF NOT EXISTS issue_operation_id text`,
  `UPDATE oid_invitation SET issue_operation_id='legacy:' || id::text WHERE issue_operation_id IS NULL`,
  `ALTER TABLE oid_invitation ALTER COLUMN issue_operation_id SET NOT NULL`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_invitation_issue_operation_uq ON oid_invitation(issue_operation_id)`,
  `CREATE INDEX IF NOT EXISTS oid_invitation_issuer_created_idx ON oid_invitation(issued_by_owner_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_registration_policy (
    id integer PRIMARY KEY CHECK (id=1), mode text NOT NULL CHECK (mode IN ('closed','open')),
    revision integer NOT NULL CHECK (revision>0), updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_owner_id uuid REFERENCES oid_owner(id)
  )`,
  `CREATE TABLE IF NOT EXISTS oid_admission (
    owner_id uuid PRIMARY KEY REFERENCES oid_owner(id) ON DELETE CASCADE,
    operation_id text NOT NULL UNIQUE, invitation_id uuid UNIQUE REFERENCES oid_invitation(id),
    policy_revision integer NOT NULL, admitted_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_invitation_redemption (
    invitation_id uuid PRIMARY KEY REFERENCES oid_invitation(id),
    owner_id uuid NOT NULL UNIQUE REFERENCES oid_owner(id), operation_id text NOT NULL UNIQUE,
    policy_revision integer NOT NULL, redeemed_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_siwe_challenge (
    nonce_hash text PRIMARY KEY, purpose text NOT NULL CHECK (purpose IN ('signin','link')),
    owner_id uuid REFERENCES oid_owner(id) ON DELETE CASCADE,
    auth_session_id text REFERENCES oid_auth_session(id) ON DELETE CASCADE,
    operation_id text NOT NULL UNIQUE, attempt_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, consumed_at timestamptz,
    CHECK ((purpose='signin' AND owner_id IS NULL AND auth_session_id IS NULL) OR
           (purpose='link' AND owner_id IS NOT NULL AND auth_session_id IS NOT NULL))
  )`,
  `CREATE INDEX IF NOT EXISTS oid_siwe_challenge_owner_idx ON oid_siwe_challenge(owner_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_google_link_state (
    state_hash text PRIMARY KEY, operation_id text NOT NULL UNIQUE,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE CASCADE,
    auth_session_id text NOT NULL REFERENCES oid_auth_session(id) ON DELETE CASCADE,
    flow_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL, consumed_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS oid_google_link_owner_idx ON oid_google_link_state(owner_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_rate_limit (
    key_hash text PRIMARY KEY, bucket_start integer NOT NULL, request_count integer NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_audit (
    id uuid PRIMARY KEY, event_type text NOT NULL, operation_id text NOT NULL,
    actor_owner_id uuid REFERENCES oid_owner(id), subject_owner_id uuid REFERENCES oid_owner(id),
    invitation_id uuid REFERENCES oid_invitation(id), policy_revision integer,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS oid_audit_operation_idx ON oid_audit(operation_id)`,
  `CREATE INDEX IF NOT EXISTS oid_audit_type_created_idx ON oid_audit(event_type,created_at)`
];

async function main() {
  const config = loadConfig();
  const { client } = createDatabase(config);
  try {
    await client.begin(async (tx) => {
      await tx.unsafe("SELECT pg_advisory_xact_lock(824731201, 17)");
      for (const statement of statements) await tx.unsafe(statement);
      await tx.unsafe(
        "INSERT INTO oid_registration_policy(id,mode,revision) VALUES (1,$1,1) ON CONFLICT (id) DO NOTHING",
        [config.registrationMode]
      );
    });
    console.log("owner-identity schema is ready");
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  console.error("owner-identity migration failed", error);
  process.exitCode = 1;
});
