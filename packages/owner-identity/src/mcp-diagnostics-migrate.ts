export interface DiagnosticMigrationTransaction { unsafe(query:string,parameters?:unknown[]):Promise<unknown> }

export const mcpDiagnosticsMigrationStatements:readonly string[]=[
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_case (
   id uuid PRIMARY KEY,owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
   agent_id uuid NOT NULL,connection_id uuid NOT NULL REFERENCES oid_agent_access_grant(id) ON DELETE RESTRICT,
   diagnostic_session_id uuid NOT NULL,intent_id uuid REFERENCES oid_run_launch_intent(id) ON DELETE RESTRICT,
   report_id uuid UNIQUE REFERENCES oid_support_report(id) ON DELETE SET NULL,
   capture_state text NOT NULL DEFAULT 'open' CHECK(capture_state IN ('open','complete','partial','partial_quota','unavailable')),
   event_count integer NOT NULL DEFAULT 0 CHECK(event_count BETWEEN 0 AND 4096),error_count integer NOT NULL DEFAULT 0 CHECK(error_count>=0),
   byte_count bigint NOT NULL DEFAULT 512 CHECK(byte_count BETWEEN 0 AND 8388608),
   created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
   FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
 )`,
 `CREATE UNIQUE INDEX IF NOT EXISTS oid_mcp_diagnostic_intent_case_uq ON oid_mcp_diagnostic_case(owner_id,intent_id) WHERE intent_id IS NOT NULL`,
 `CREATE UNIQUE INDEX IF NOT EXISTS oid_mcp_diagnostic_setup_case_uq ON oid_mcp_diagnostic_case(owner_id,diagnostic_session_id) WHERE intent_id IS NULL`,
 `CREATE INDEX IF NOT EXISTS oid_mcp_diagnostic_owner_idx ON oid_mcp_diagnostic_case(owner_id,created_at DESC,id)`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_segment (
   case_id uuid NOT NULL REFERENCES oid_mcp_diagnostic_case(id) ON DELETE CASCADE,segment_id uuid NOT NULL,
   highest_sequence integer NOT NULL DEFAULT -1 CHECK(highest_sequence BETWEEN -1 AND 4095),highest_hash text,
   completion text NOT NULL DEFAULT 'open' CHECK(completion IN ('open','complete','partial')),
   updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(case_id,segment_id),
   CHECK(highest_hash IS NULL OR highest_hash ~ '^[a-f0-9]{64}$')
 )`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_batch (
   case_id uuid NOT NULL,segment_id uuid NOT NULL,batch_sequence integer NOT NULL CHECK(batch_sequence BETWEEN 0 AND 4095),
   payload_hash text NOT NULL CHECK(payload_hash ~ '^[a-f0-9]{64}$'),event_count integer NOT NULL CHECK(event_count BETWEEN 0 AND 128),
   byte_count integer NOT NULL CHECK(byte_count BETWEEN 0 AND 65536),completion text NOT NULL CHECK(completion IN ('open','complete','partial')),
   created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(case_id,segment_id,batch_sequence),
   FOREIGN KEY(case_id,segment_id) REFERENCES oid_mcp_diagnostic_segment(case_id,segment_id) ON DELETE CASCADE
 )`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_event (
   case_id uuid REFERENCES oid_mcp_diagnostic_case(id) ON DELETE CASCADE,event_id uuid NOT NULL,
   trace_id uuid,source text NOT NULL CHECK(source IN ('client','server')),stage text NOT NULL,tool text NOT NULL,outcome text NOT NULL,
   error_code text,payload_hash text NOT NULL CHECK(payload_hash ~ '^[a-f0-9]{64}$'),envelope jsonb NOT NULL,
   byte_count integer NOT NULL CHECK(byte_count BETWEEN 0 AND 2048),responsibility text NOT NULL DEFAULT 'unknown',
   attribution_reason text NOT NULL,evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
   created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
   CHECK(jsonb_typeof(envelope)='object' AND jsonb_typeof(evidence_ids)='array'),
   CHECK(responsibility IN ('client_contract','client_runtime','platform_contract','platform_runtime','external_dependency','expected_policy_denial','unknown'))
 )`,
 `CREATE UNIQUE INDEX IF NOT EXISTS oid_mcp_diagnostic_event_case_uq ON oid_mcp_diagnostic_event(case_id,event_id) WHERE case_id IS NOT NULL`,
 `CREATE UNIQUE INDEX IF NOT EXISTS oid_mcp_diagnostic_event_anonymous_uq ON oid_mcp_diagnostic_event(event_id) WHERE case_id IS NULL`,
 `CREATE INDEX IF NOT EXISTS oid_mcp_diagnostic_event_case_idx ON oid_mcp_diagnostic_event(case_id,created_at,event_id)`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_quota (
   scope text PRIMARY KEY CHECK(scope='deployment' OR scope='anonymous' OR scope ~ '^owner:[a-f0-9-]{36}$'),
   bytes bigint NOT NULL DEFAULT 0 CHECK(bytes>=0),rows bigint NOT NULL DEFAULT 0 CHECK(rows>=0),cases integer NOT NULL DEFAULT 0 CHECK(cases>=0)
 )`,
 `INSERT INTO oid_mcp_diagnostic_quota(scope) VALUES ('deployment'),('anonymous') ON CONFLICT DO NOTHING`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_aggregate (
   bucket integer PRIMARY KEY CHECK(bucket BETWEEN 0 AND 127),dropped_count bigint NOT NULL DEFAULT 0 CHECK(dropped_count>=0),
   updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
 )`,
 `INSERT INTO oid_mcp_diagnostic_aggregate(bucket) SELECT generate_series(0,127) ON CONFLICT DO NOTHING`,
 `CREATE TABLE IF NOT EXISTS oid_mcp_diagnostic_retention_receipt (
   id integer PRIMARY KEY CHECK(id=1),beta_ended_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
   deleted_at timestamptz NOT NULL DEFAULT clock_timestamp(),case_count integer NOT NULL,event_count integer NOT NULL,
   CHECK(case_count>=0 AND event_count>=0 AND expires_at>=beta_ended_at)
 )`,
 `CREATE OR REPLACE FUNCTION oid_mcp_diagnostic_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
   IF TG_OP='DELETE' AND current_setting('w3bench.diagnostic_retention_cleanup',true)='on' THEN RETURN OLD; END IF;
   RAISE EXCEPTION 'diagnostic_evidence_is_append_only' USING ERRCODE='55000';
 END $$`,
 `DROP TRIGGER IF EXISTS oid_mcp_diagnostic_event_immutable_trg ON oid_mcp_diagnostic_event`,
 `CREATE TRIGGER oid_mcp_diagnostic_event_immutable_trg BEFORE UPDATE OR DELETE ON oid_mcp_diagnostic_event FOR EACH ROW EXECUTE FUNCTION oid_mcp_diagnostic_immutable()`,
 `DROP TRIGGER IF EXISTS oid_mcp_diagnostic_batch_immutable_trg ON oid_mcp_diagnostic_batch`,
 `CREATE TRIGGER oid_mcp_diagnostic_batch_immutable_trg BEFORE UPDATE OR DELETE ON oid_mcp_diagnostic_batch FOR EACH ROW EXECUTE FUNCTION oid_mcp_diagnostic_immutable()`
];

export async function migrateMcpDiagnostics(tx:DiagnosticMigrationTransaction):Promise<void>{for(const statement of mcpDiagnosticsMigrationStatements)await tx.unsafe(statement);}
