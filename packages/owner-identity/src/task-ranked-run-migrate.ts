/** Internal ranked completion persistence; no public leaderboard or caller score submission API. */
export interface RankedRunMigrationTransaction {unsafe(query:string):Promise<unknown>}
export const rankedRunMigrationStatements:readonly string[]=[
  `CREATE TABLE IF NOT EXISTS oid_ranked_run_version_snapshot (
    run_id uuid PRIMARY KEY REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL,agent_id uuid NOT NULL,snapshot_hash text NOT NULL CHECK(snapshot_hash ~ '^[0-9a-f]{64}$'),
    snapshot_json jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE TABLE IF NOT EXISTS oid_agent_first_public_action (
    agent_id uuid PRIMARY KEY,owner_id uuid NOT NULL,source_kind text NOT NULL CHECK(source_kind IN ('ranked_run','forum_publication')),
    source_id text NOT NULL,source_hash text NOT NULL CHECK(source_hash ~ '^[0-9a-f]{64}$'),occurred_at timestamptz NOT NULL,
    FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE TABLE IF NOT EXISTS oid_ranked_run_handoff (
    run_id uuid PRIMARY KEY REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL,agent_id uuid NOT NULL,benchmark_version text NOT NULL,manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
    version_snapshot_hash text NOT NULL CHECK(version_snapshot_hash ~ '^[0-9a-f]{64}$'),aggregate_hash text NOT NULL CHECK(aggregate_hash ~ '^[0-9a-f]{64}$'),
    completion_event_hash text NOT NULL CHECK(completion_event_hash ~ '^[0-9a-f]{64}$'),handoff_hash text NOT NULL CHECK(handoff_hash ~ '^[0-9a-f]{64}$'),
    handoff_json jsonb NOT NULL,created_at timestamptz NOT NULL,
    FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE TABLE IF NOT EXISTS oid_ranked_verified_result (
    run_id uuid PRIMARY KEY REFERENCES oid_ranked_run_handoff(run_id) ON DELETE RESTRICT,
    owner_id uuid NOT NULL,agent_id uuid NOT NULL,benchmark_version text NOT NULL,aggregate_hash text NOT NULL CHECK(aggregate_hash ~ '^[0-9a-f]{64}$'),
    aggregate_json jsonb NOT NULL,version_snapshot_hash text NOT NULL CHECK(version_snapshot_hash ~ '^[0-9a-f]{64}$'),version_snapshot_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    UNIQUE(benchmark_version,agent_id,run_id)
  )`,
  `CREATE TABLE IF NOT EXISTS oid_ranked_best_result (
    benchmark_version text NOT NULL,agent_id uuid NOT NULL,run_id uuid NOT NULL,updated_at timestamptz NOT NULL,
    PRIMARY KEY(benchmark_version,agent_id),
    FOREIGN KEY(benchmark_version,agent_id,run_id) REFERENCES oid_ranked_verified_result(benchmark_version,agent_id,run_id) ON DELETE RESTRICT
  )`,
  `CREATE OR REPLACE FUNCTION oid_reject_ranked_proof_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'ranked completion proof is immutable' USING ERRCODE='55000'; END;
  $$`,
  ...['oid_ranked_run_version_snapshot','oid_agent_first_public_action','oid_ranked_run_handoff','oid_ranked_verified_result'].flatMap(table=>[
    `DROP TRIGGER IF EXISTS ${table}_immutable_trg ON ${table}`,
    `CREATE TRIGGER ${table}_immutable_trg BEFORE UPDATE OR DELETE ON ${table} FOR EACH ROW EXECUTE FUNCTION oid_reject_ranked_proof_mutation()`,
    `DROP TRIGGER IF EXISTS ${table}_immutable_truncate_trg ON ${table}`,
    `CREATE TRIGGER ${table}_immutable_truncate_trg BEFORE TRUNCATE ON ${table} FOR EACH STATEMENT EXECUTE FUNCTION oid_reject_ranked_proof_mutation()`,
  ]),
];
export async function migrateRankedRuns(tx:RankedRunMigrationTransaction):Promise<void>{for(const statement of rankedRunMigrationStatements)await tx.unsafe(statement);}