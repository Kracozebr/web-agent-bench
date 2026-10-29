export interface ReportMigrationTransaction {
  unsafe(query: string, parameters?: unknown[]): Promise<unknown>;
}

// AICODE-NOTE: Reports and screenshots are a private support surface. The durable
// report tables contain no benchmark action, billing, score, or refund mutations.
export const reportMigrationStatements: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS oid_support_report (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    agent_id uuid,
    source text NOT NULL CHECK(source IN ('owner','agent')),
    reporter_kind text NOT NULL CHECK(reporter_kind IN ('owner','agent')),
    reporter_id uuid NOT NULL,
    operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    title text NOT NULL CHECK(char_length(title) BETWEEN 1 AND 160),
    body text NOT NULL CHECK(char_length(body) BETWEEN 1 AND 4000),
    safe_context jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(safe_context)='object'),
    client_version text CHECK(client_version IS NULL OR char_length(client_version) BETWEEN 1 AND 64),
    run_id uuid REFERENCES oid_benchmark_run(id) ON DELETE RESTRICT,
    task_id text CHECK(task_id IS NULL OR char_length(task_id) BETWEEN 1 AND 128),
    action_id uuid REFERENCES oid_run_task_action(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'new' CHECK(status IN ('new','in_progress','closed')),
    revision integer NOT NULL DEFAULT 1 CHECK(revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_support_report_agent_owner_fk FOREIGN KEY(owner_id,agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_support_report_principal_shape_ck CHECK(
      (source='owner' AND reporter_kind='owner' AND reporter_id=owner_id) OR
      (source='agent' AND reporter_kind='agent' AND agent_id IS NOT NULL AND reporter_id=agent_id)
    ),
    CONSTRAINT oid_support_report_links_ck CHECK((task_id IS NULL OR run_id IS NOT NULL) AND (action_id IS NULL OR run_id IS NOT NULL))
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_support_report_principal_operation_uq ON oid_support_report(reporter_kind,reporter_id,operation_id)`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_owner_created_idx ON oid_support_report(owner_id,created_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_status_created_idx ON oid_support_report(status,created_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_source_created_idx ON oid_support_report(source,created_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_agent_created_idx ON oid_support_report(agent_id,created_at DESC,id DESC)`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_run_created_idx ON oid_support_report(run_id,created_at DESC,id DESC)`,
  `CREATE TABLE IF NOT EXISTS oid_support_image_upload (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    uploader_kind text NOT NULL CHECK(uploader_kind IN ('owner','agent')),
    uploader_id uuid NOT NULL,
    uploader_agent_id uuid,
    operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
    input_mime text NOT NULL CHECK(input_mime IN ('image/png','image/jpeg','image/webp')),
    expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[0-9a-f]{64}$'),
    expected_input_bytes integer NOT NULL CHECK(expected_input_bytes BETWEEN 1 AND 5242880),
    input_bytes integer NOT NULL DEFAULT 0 CHECK(input_bytes BETWEEN 0 AND 5242880),
    reserved_output_bytes integer NOT NULL DEFAULT 5242880 CHECK(reserved_output_bytes BETWEEN 0 AND 5242880),
    output_bytes integer CHECK(output_bytes IS NULL OR output_bytes BETWEEN 1 AND 5242880),
    output_sha256 text CHECK(output_sha256 IS NULL OR output_sha256 ~ '^[0-9a-f]{64}$'),
    output_mime text CHECK(output_mime IS NULL OR output_mime='image/webp'),
    width integer CHECK(width IS NULL OR width BETWEEN 1 AND 16000000),
    height integer CHECK(height IS NULL OR height BETWEEN 1 AND 16000000),
    storage_key uuid UNIQUE,
    status text NOT NULL DEFAULT 'receiving' CHECK(status IN ('receiving','processing','ready','attached','failed')),
    report_id uuid REFERENCES oid_support_report(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT oid_support_upload_principal_shape_ck CHECK(
      (uploader_kind='owner' AND uploader_id=owner_id AND uploader_agent_id IS NULL) OR
      (uploader_kind='agent' AND uploader_agent_id IS NOT NULL AND uploader_id=uploader_agent_id)
    ),
    CONSTRAINT oid_support_upload_agent_owner_fk FOREIGN KEY(owner_id,uploader_agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT,
    CONSTRAINT oid_support_upload_status_shape_ck CHECK((status='attached') = (report_id IS NOT NULL)),
    CONSTRAINT oid_support_upload_pixel_count_ck CHECK(
      (width IS NULL AND height IS NULL) OR (width BETWEEN 1 AND 16000000 AND height BETWEEN 1 AND 16000000 AND width::bigint*height::bigint <= 16000000)
    ),
    CONSTRAINT oid_support_upload_output_shape_ck CHECK(
      (status IN ('ready','attached')) =
      (storage_key IS NOT NULL AND output_bytes IS NOT NULL AND output_sha256 IS NOT NULL AND output_mime IS NOT NULL AND width IS NOT NULL AND height IS NOT NULL)
    )
  )`,
  `ALTER TABLE oid_support_image_upload DROP CONSTRAINT IF EXISTS oid_support_image_upload_output_mime_check`,
  `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_support_upload_output_mime_ck') THEN ALTER TABLE oid_support_image_upload ADD CONSTRAINT oid_support_upload_output_mime_ck CHECK(output_mime IS NULL OR output_mime='image/webp'); END IF; END $$`,
  `CREATE UNIQUE INDEX IF NOT EXISTS oid_support_upload_principal_operation_uq ON oid_support_image_upload(uploader_kind,uploader_id,operation_id)`,
  `CREATE INDEX IF NOT EXISTS oid_support_upload_owner_state_idx ON oid_support_image_upload(owner_id,status,created_at)`,
  `CREATE INDEX IF NOT EXISTS oid_support_upload_expiry_idx ON oid_support_image_upload(status,expires_at)`,
  `CREATE INDEX IF NOT EXISTS oid_support_upload_report_idx ON oid_support_image_upload(report_id,created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_support_image_chunk (
    upload_id uuid NOT NULL REFERENCES oid_support_image_upload(id) ON DELETE CASCADE,
    sequence integer NOT NULL CHECK(sequence >= 0),
    sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
    bytes bytea NOT NULL CHECK(octet_length(bytes) BETWEEN 1 AND 24576),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(upload_id,sequence)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_support_image_chunk_created_idx ON oid_support_image_chunk(created_at)`,
  `CREATE TABLE IF NOT EXISTS oid_support_report_audit (
    id uuid PRIMARY KEY,
    report_id uuid NOT NULL REFERENCES oid_support_report(id) ON DELETE CASCADE,
    actor_owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    actor_agent_id uuid,
    operation_id text CHECK(operation_id IS NULL OR operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    payload_hash text CHECK(payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'),
    event_type text NOT NULL CHECK(event_type IN ('created','status_changed','owner_attached_image')),
    previous_status text CHECK(previous_status IS NULL OR previous_status IN ('new','in_progress','closed')),
    next_status text CHECK(next_status IS NULL OR next_status IN ('new','in_progress','closed')),
    revision integer NOT NULL CHECK(revision > 0),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(metadata)='object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_support_report_audit_agent_owner_fk FOREIGN KEY(actor_owner_id,actor_agent_id) REFERENCES oid_agent(owner_id,id) ON DELETE RESTRICT
  )`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_audit_report_idx ON oid_support_report_audit(report_id,created_at,id)`,
  `CREATE TABLE IF NOT EXISTS oid_support_report_rate (
    key text PRIMARY KEY CHECK(char_length(key) BETWEEN 1 AND 200),
    window_start integer NOT NULL,
    request_count integer NOT NULL CHECK(request_count >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS oid_support_report_retention_state (
    id integer PRIMARY KEY CHECK(id=1),
    beta_ended_at timestamptz,
    closed_by_owner_id uuid REFERENCES oid_owner(id) ON DELETE RESTRICT,
    close_operation_id text CHECK(close_operation_id IS NULL OR close_operation_id ~ '^[A-Za-z0-9_-]{12,128}$'),
    close_payload_hash text CHECK(close_payload_hash IS NULL OR close_payload_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oid_support_retention_shape_ck CHECK(
      (beta_ended_at IS NULL AND closed_by_owner_id IS NULL AND close_operation_id IS NULL AND close_payload_hash IS NULL) OR
      (beta_ended_at IS NOT NULL AND closed_by_owner_id IS NOT NULL AND close_operation_id IS NOT NULL AND close_payload_hash IS NOT NULL)
    )
  )`,
  `INSERT INTO oid_support_report_retention_state(id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
  `CREATE TABLE IF NOT EXISTS oid_support_report_deletion_receipt (
    report_id uuid PRIMARY KEY,
    beta_ended_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT now(),
    image_count integer NOT NULL CHECK(image_count >= 0),
    pending_storage_keys uuid[] NOT NULL DEFAULT '{}'::uuid[],
    pending_storage_bytes integer[] NOT NULL DEFAULT '{}'::integer[],
    purge_status text NOT NULL DEFAULT 'pending' CHECK(purge_status IN ('pending','failed','complete')),
    last_attempt_at timestamptz,
    last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$'),
    CONSTRAINT oid_support_report_deletion_storage_shape_ck CHECK(cardinality(pending_storage_keys)=cardinality(pending_storage_bytes)),
    CONSTRAINT oid_support_report_deletion_storage_bytes_ck CHECK(array_position(pending_storage_bytes,NULL) IS NULL AND 0 <= ALL(pending_storage_bytes))
  )`,
  `ALTER TABLE oid_support_report_deletion_receipt ADD COLUMN IF NOT EXISTS pending_storage_bytes integer[] NOT NULL DEFAULT '{}'::integer[]`,
  `UPDATE oid_support_report_deletion_receipt SET pending_storage_bytes=ARRAY(SELECT 5242880 FROM unnest(pending_storage_keys)) WHERE cardinality(pending_storage_keys)>0 AND cardinality(pending_storage_bytes)=0`,
  `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_support_report_deletion_storage_shape_ck') THEN ALTER TABLE oid_support_report_deletion_receipt ADD CONSTRAINT oid_support_report_deletion_storage_shape_ck CHECK(cardinality(pending_storage_keys)=cardinality(pending_storage_bytes)); END IF; END $$`,
  `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_support_report_deletion_storage_bytes_ck') THEN ALTER TABLE oid_support_report_deletion_receipt ADD CONSTRAINT oid_support_report_deletion_storage_bytes_ck CHECK(array_position(pending_storage_bytes,NULL) IS NULL AND 0 <= ALL(pending_storage_bytes)); END IF; END $$`,
  `CREATE INDEX IF NOT EXISTS oid_support_report_deletion_status_idx ON oid_support_report_deletion_receipt(purge_status,deleted_at)`,
  `CREATE TABLE IF NOT EXISTS oid_support_upload_gc_receipt (
    id uuid PRIMARY KEY,
    storage_key uuid,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','complete')),
    cleaned_at timestamptz NOT NULL DEFAULT now(),
    reason text NOT NULL CHECK(reason IN ('unlinked_expired','failed_upload','interrupted_processing')),
    reserved_bytes integer NOT NULL DEFAULT 0 CHECK(reserved_bytes >= 0),
    bytes_removed integer NOT NULL DEFAULT 0 CHECK(bytes_removed >= 0),
    last_error_code text CHECK(last_error_code IS NULL OR last_error_code ~ '^[A-Z0-9_]{1,64}$')
  )`,
  `ALTER TABLE oid_support_upload_gc_receipt ADD COLUMN IF NOT EXISTS reserved_bytes integer NOT NULL DEFAULT 0`,
  `UPDATE oid_support_upload_gc_receipt SET reserved_bytes=5242880 WHERE status IN ('pending','failed') AND storage_key IS NOT NULL AND reserved_bytes=0`,
  `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='oid_support_upload_gc_reserved_bytes_ck') THEN ALTER TABLE oid_support_upload_gc_receipt ADD CONSTRAINT oid_support_upload_gc_reserved_bytes_ck CHECK(reserved_bytes>=0); END IF; END $$`,
  `CREATE INDEX IF NOT EXISTS oid_support_upload_gc_created_idx ON oid_support_upload_gc_receipt(status,cleaned_at)`,
  `CREATE TABLE IF NOT EXISTS oid_support_image_input_usage (
    upload_id uuid NOT NULL,
    sequence integer NOT NULL CHECK(sequence >= 0),
    owner_id uuid NOT NULL REFERENCES oid_owner(id) ON DELETE RESTRICT,
    input_bytes integer NOT NULL CHECK(input_bytes BETWEEN 1 AND 24576),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(upload_id,sequence)
  )`,
  `CREATE INDEX IF NOT EXISTS oid_support_image_input_usage_owner_time_idx ON oid_support_image_input_usage(owner_id,received_at)`
];

export async function migrateReports(tx: ReportMigrationTransaction): Promise<void> {
  for (const statement of reportMigrationStatements) await tx.unsafe(statement);
}
