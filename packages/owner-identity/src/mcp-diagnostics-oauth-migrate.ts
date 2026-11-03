import type { Sql } from 'postgres';

export const diagnosticOAuthStatements = [
  `CREATE TABLE IF NOT EXISTS oid_diagnostic_oauth_request (
    id uuid PRIMARY KEY, challenge text NOT NULL CHECK(challenge ~ '^[A-Za-z0-9_-]{43}$'),
    state text NOT NULL CHECK(length(state) BETWEEN 16 AND 512), resource text NOT NULL,
    owner_id uuid REFERENCES oid_owner(id), auth_session_id text,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
    consent_operation_id text, consent_hash text, helper_grant_id uuid,
    code_hash text UNIQUE, code_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '600 seconds'
  )`,
  `CREATE TABLE IF NOT EXISTS oid_diagnostic_oauth_grant (
    id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES oid_owner(id),
    agent_id uuid NOT NULL REFERENCES oid_agent(id),
    connection_id uuid NOT NULL REFERENCES oid_agent_access_grant(id),
    access_generation integer NOT NULL CHECK(access_generation>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
    revoked_at timestamptz
  )`,
  `CREATE TABLE IF NOT EXISTS oid_diagnostic_oauth_token (
    verifier text PRIMARY KEY CHECK(verifier ~ '^[A-Za-z0-9_-]{43}$'),
    grant_id uuid NOT NULL REFERENCES oid_diagnostic_oauth_grant(id),
    kind text NOT NULL CHECK(kind IN ('access','refresh')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
    consumed_at timestamptz
  )`,
  `CREATE INDEX IF NOT EXISTS oid_diagnostic_oauth_token_grant_idx ON oid_diagnostic_oauth_token(grant_id,kind)`,
  `CREATE INDEX IF NOT EXISTS oid_diagnostic_oauth_request_expiry_idx ON oid_diagnostic_oauth_request(expires_at)`,
  `CREATE INDEX IF NOT EXISTS oid_diagnostic_oauth_grant_connection_idx ON oid_diagnostic_oauth_grant(connection_id)`
];

export async function migrateDiagnosticOAuth(tx: Pick<Sql, 'unsafe'>) {
  for (const statement of diagnosticOAuthStatements) await tx.unsafe(statement);
}
