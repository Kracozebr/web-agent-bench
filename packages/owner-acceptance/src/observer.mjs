import { createHash } from "node:crypto";
import pg from "pg";

const { Pool } = pg;

function normalizeRows(rows) {
  return rows.map((row) => Object.fromEntries(
    Object.entries(row).map(([key, value]) => [key, value instanceof Date ? value.toISOString() : value]),
  ));
}

function sanitizeIdentityRows(rows) {
  return rows.map((row) => ({
    id: row.id,
    owner_id: row.owner_id,
    provider: row.provider,
    subject_sha256: createHash("sha256").update(String(row.subject), "utf8").digest("hex"),
    verified_at: row.verified_at instanceof Date ? row.verified_at.toISOString() : row.verified_at,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  }));
}

export class OwnerDatabaseObserver {
  #pool;

  constructor(connectionString) {
    if (!connectionString) throw new Error("OID_OBSERVER_DATABASE_URL is required");
    this.#pool = new Pool({ connectionString, max: 1, application_name: "oid-acceptance-readonly-observer" });
  }

  async snapshot({ authUserIds = [], ownerIds = [], invitationIds = [], operationIds = [], subjects = [], subjectHashes = [], nonceHashes = [] } = {}) {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN READ ONLY");
      const identity = await client.query(`
        SELECT current_user AS role,
               current_database() AS database,
               current_setting('transaction_read_only') AS transaction_read_only,
               current_setting('default_transaction_read_only') AS default_transaction_read_only
      `);
      if (identity.rows[0]?.role !== "oid_observer" || identity.rows[0]?.transaction_read_only !== "on") {
        throw new Error("Database observer is not the configured read-only oid_observer role");
      }

      const identities = await client.query(`SELECT id::text AS id, owner_id::text AS owner_id, auth_user_id, provider, subject, verified_at, created_at
        FROM oid_identity WHERE auth_user_id = ANY($1::text[]) OR owner_id::text = ANY($2::text[]) OR subject = ANY($3::text[])
          OR encode(sha256(convert_to(subject,'UTF8')),'hex') = ANY($4::text[])
        ORDER BY provider, subject`, [authUserIds, ownerIds, subjects, subjectHashes]);
      const resolvedAuthUserIds = [...new Set([...authUserIds, ...identities.rows.map((row) => row.auth_user_id)])];
      const owners = await client.query(`SELECT id::text AS id, auth_user_id, admission_status, created_at, admitted_at
        FROM oid_owner WHERE auth_user_id = ANY($1::text[]) OR id::text = ANY($2::text[]) ORDER BY id`, [resolvedAuthUserIds, ownerIds]);
      const resolvedOwnerIds = [...new Set([...ownerIds, ...owners.rows.map((row) => row.id)])];
      const [invitations, admissions, redemptions, policies, audits, challenges, sessions, flows] = await Promise.all([
        client.query(`SELECT id::text AS id, issued_by_owner_id::text AS issued_by_owner_id, created_at, expires_at, revoked_at, redeemed_at
          FROM oid_invitation WHERE id::text = ANY($1::text[]) OR issued_by_owner_id::text = ANY($2::text[]) ORDER BY created_at`, [invitationIds, resolvedOwnerIds]),
        client.query(`SELECT owner_id::text AS owner_id, operation_id, invitation_id::text AS invitation_id, policy_revision, admitted_at
          FROM oid_admission WHERE owner_id::text = ANY($1::text[]) OR operation_id = ANY($2::text[]) OR invitation_id::text = ANY($3::text[])
          ORDER BY admitted_at`, [resolvedOwnerIds, operationIds, invitationIds]),
        client.query(`SELECT invitation_id::text AS invitation_id, owner_id::text AS owner_id, operation_id, policy_revision, redeemed_at
          FROM oid_invitation_redemption WHERE invitation_id::text = ANY($1::text[]) OR operation_id = ANY($2::text[])
          ORDER BY redeemed_at`, [invitationIds, operationIds]),
        client.query(`SELECT id, mode, revision, updated_at, updated_by_owner_id::text AS updated_by_owner_id
          FROM oid_registration_policy ORDER BY id`),
        client.query(`SELECT id::text AS id, event_type, operation_id, actor_owner_id::text AS actor_owner_id,
                 subject_owner_id::text AS subject_owner_id, invitation_id::text AS invitation_id,
                 policy_revision, created_at
          FROM oid_audit WHERE operation_id = ANY($1::text[]) OR actor_owner_id::text = ANY($2::text[])
            OR subject_owner_id::text = ANY($2::text[]) OR invitation_id::text = ANY($3::text[])
          ORDER BY created_at`, [operationIds, resolvedOwnerIds, invitationIds]),
        client.query(`SELECT purpose, owner_id::text AS owner_id, (auth_session_id IS NOT NULL) AS has_auth_session,
                 operation_id, created_at, expires_at, consumed_at
          FROM oid_siwe_challenge WHERE nonce_hash = ANY($1::text[]) OR operation_id = ANY($2::text[])
          ORDER BY created_at`, [nonceHashes, operationIds]),
        client.query(`SELECT count(*)::integer AS session_count,
                 count(*) FILTER (WHERE expires_at > now())::integer AS active_session_count
          FROM oid_auth_session WHERE user_id = ANY($1::text[])`, [resolvedAuthUserIds]),
        client.query(`SELECT operation_id, provider, purpose, owner_id::text AS owner_id,
                 (auth_session_id IS NOT NULL) AS has_auth_session,
                 started_at, expires_at, completed_at, outcome
          FROM oid_auth_flow WHERE operation_id = ANY($1::text[]) OR owner_id::text = ANY($2::text[])
          ORDER BY started_at`, [operationIds, resolvedOwnerIds]),
      ]);
      const result = {
        observer: normalizeRows(identity.rows)[0],
        owners: owners.rows.map(({ id, admission_status, created_at, admitted_at }) => ({
          id,
          admission_status,
          created_at: created_at instanceof Date ? created_at.toISOString() : created_at,
          admitted_at: admitted_at instanceof Date ? admitted_at.toISOString() : admitted_at,
        })),
        identities: sanitizeIdentityRows(identities.rows),
        invitations: normalizeRows(invitations.rows),
        admissions: normalizeRows(admissions.rows),
        redemptions: normalizeRows(redemptions.rows),
        policies: normalizeRows(policies.rows),
        audits: normalizeRows(audits.rows),
        challenges: normalizeRows(challenges.rows),
        sessions: normalizeRows(sessions.rows),
        authFlows: normalizeRows(flows.rows),
      };
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async verifierMatches(invitationId, invitationSecret) {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN READ ONLY");
      const verifierHash = createHash("sha256").update(invitationSecret, "utf8").digest("hex");
      const query = await client.query("SELECT verifier_hash = $2 AS matches FROM oid_invitation WHERE id::text = $1", [invitationId, verifierHash]);
      await client.query("COMMIT");
      return query.rows[0]?.matches === true;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async close() {
    await this.#pool.end();
  }
}
