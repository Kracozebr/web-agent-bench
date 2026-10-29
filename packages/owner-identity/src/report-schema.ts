import { sql } from "drizzle-orm";
import { check, customType, foreignKey, index, integer, jsonb, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { agentProfiles, owners } from "./schema.js";
import { benchmarkRuns } from "./run-schema.js";

const time = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => "bytea" });

// AICODE-NOTE: This ID-only Drizzle reference keeps the report FK aligned with
// task-action-migrate.ts without shadowing the action table's raw-SQL model.
const supportTaskActionReference = pgTable("oid_run_task_action", {
  id: uuid("id").primaryKey()
});

export const supportReports = pgTable("oid_support_report", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  agentId: uuid("agent_id"),
  source: text("source").notNull(),
  reporterKind: text("reporter_kind").notNull(),
  reporterId: uuid("reporter_id").notNull(),
  operationId: text("operation_id").notNull(),
  payloadHash: text("payload_hash").notNull(),
  title: text("title").notNull(),
  body: text("body").notNull(),
  safeContext: jsonb("safe_context").$type<Record<string, unknown>>().notNull().default({}),
  clientVersion: text("client_version"),
  runId: uuid("run_id"),
  taskId: text("task_id"),
  actionId: uuid("action_id"),
  status: text("status").notNull().default("new"),
  revision: integer("revision").notNull().default(1),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_support_report_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.agentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_support_report_agent_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.runId], foreignColumns: [benchmarkRuns.id], name: "oid_support_report_run_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.actionId], foreignColumns: [supportTaskActionReference.id], name: "oid_support_report_action_fk" }).onDelete("restrict"),
  uniqueIndex("oid_support_report_principal_operation_uq").on(table.reporterKind, table.reporterId, table.operationId),
  index("oid_support_report_owner_created_idx").on(table.ownerId, table.createdAt, table.id),
  index("oid_support_report_status_created_idx").on(table.status, table.createdAt, table.id),
  index("oid_support_report_agent_created_idx").on(table.agentId, table.createdAt, table.id),
  index("oid_support_report_run_created_idx").on(table.runId, table.createdAt, table.id),
  check("oid_support_report_source_ck", sql`${table.source} IN ('owner','agent')`),
  check("oid_support_report_reporter_ck", sql`(${table.source}='owner' AND ${table.reporterKind}='owner' AND ${table.reporterId}=${table.ownerId}) OR (${table.source}='agent' AND ${table.reporterKind}='agent' AND ${table.agentId} IS NOT NULL AND ${table.reporterId}=${table.agentId})`),
  check("oid_support_report_safe_context_ck", sql`jsonb_typeof(${table.safeContext})='object'`),
  check("oid_support_report_client_version_ck", sql`${table.clientVersion} IS NULL OR char_length(${table.clientVersion}) BETWEEN 1 AND 64`),
  check("oid_support_report_task_id_ck", sql`${table.taskId} IS NULL OR char_length(${table.taskId}) BETWEEN 1 AND 128`),
  check("oid_support_report_status_ck", sql`${table.status} IN ('new','in_progress','closed')`),
  check("oid_support_report_revision_ck", sql`${table.revision} > 0`),
  check("oid_support_report_operation_ck", sql`${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_support_report_hash_ck", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$'`),
  check("oid_support_report_title_size_ck", sql`char_length(${table.title}) BETWEEN 1 AND 160`),
  check("oid_support_report_body_size_ck", sql`char_length(${table.body}) BETWEEN 1 AND 4000`),
  check("oid_support_report_link_shape_ck", sql`(${table.taskId} IS NULL OR ${table.runId} IS NOT NULL) AND (${table.actionId} IS NULL OR ${table.runId} IS NOT NULL)`)
]);

export const supportImageUploads = pgTable("oid_support_image_upload", {
  id: uuid("id").primaryKey(),
  ownerId: uuid("owner_id").notNull(),
  uploaderKind: text("uploader_kind").notNull(),
  uploaderId: uuid("uploader_id").notNull(),
  uploaderAgentId: uuid("uploader_agent_id"),
  operationId: text("operation_id").notNull(),
  payloadHash: text("payload_hash").notNull(),
  inputMime: text("input_mime").notNull(),
  expectedSha256: text("expected_sha256").notNull(),
  expectedInputBytes: integer("expected_input_bytes").notNull(),
  inputBytes: integer("input_bytes").notNull().default(0),
  reservedOutputBytes: integer("reserved_output_bytes").notNull().default(5_242_880),
  outputBytes: integer("output_bytes"),
  outputSha256: text("output_sha256"),
  outputMime: text("output_mime"),
  width: integer("width"),
  height: integer("height"),
  storageKey: uuid("storage_key").unique(),
  status: text("status").notNull().default("receiving"),
  reportId: uuid("report_id"),
  createdAt: time("created_at").notNull().defaultNow(),
  updatedAt: time("updated_at").notNull().defaultNow(),
  expiresAt: time("expires_at").notNull()
}, (table) => [
  foreignKey({ columns: [table.ownerId], foreignColumns: [owners.id], name: "oid_support_upload_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.ownerId, table.uploaderAgentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_support_upload_agent_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.reportId], foreignColumns: [supportReports.id], name: "oid_support_upload_report_fk" }).onDelete("cascade"),
  uniqueIndex("oid_support_upload_principal_operation_uq").on(table.uploaderKind, table.uploaderId, table.operationId),
  index("oid_support_upload_owner_state_idx").on(table.ownerId, table.status, table.createdAt),
  index("oid_support_upload_expiry_idx").on(table.status, table.expiresAt),
  index("oid_support_upload_report_idx").on(table.reportId, table.createdAt),
  check("oid_support_upload_uploader_ck", sql`(${table.uploaderKind}='owner' AND ${table.uploaderId}=${table.ownerId} AND ${table.uploaderAgentId} IS NULL) OR (${table.uploaderKind}='agent' AND ${table.uploaderAgentId} IS NOT NULL AND ${table.uploaderId}=${table.uploaderAgentId})`),
  check("oid_support_upload_size_ck", sql`${table.expectedInputBytes} BETWEEN 1 AND 5242880 AND ${table.inputBytes} BETWEEN 0 AND 5242880`),
  check("oid_support_upload_reservation_ck", sql`${table.reservedOutputBytes} BETWEEN 0 AND 5242880`),
  check("oid_support_upload_output_size_ck", sql`${table.outputBytes} IS NULL OR ${table.outputBytes} BETWEEN 1 AND 5242880`),
  check("oid_support_upload_output_mime_ck", sql`${table.outputMime} IS NULL OR ${table.outputMime}='image/webp'`),
  check("oid_support_upload_pixel_count_ck", sql`(${table.width} IS NULL AND ${table.height} IS NULL) OR (${table.width} BETWEEN 1 AND 16000000 AND ${table.height} BETWEEN 1 AND 16000000 AND ${table.width}::bigint * ${table.height}::bigint <= 16000000)`),
  check("oid_support_upload_status_ck", sql`${table.status} IN ('receiving','processing','ready','attached','failed')`),
  check("oid_support_upload_status_shape_ck", sql`(${table.status}='attached') = (${table.reportId} IS NOT NULL)`),
  check("oid_support_upload_output_shape_ck", sql`(${table.status} IN ('ready','attached')) = (${table.storageKey} IS NOT NULL AND ${table.outputBytes} IS NOT NULL AND ${table.outputSha256} IS NOT NULL AND ${table.outputMime} IS NOT NULL AND ${table.width} IS NOT NULL AND ${table.height} IS NOT NULL)`),
  check("oid_support_upload_input_mime_ck", sql`${table.inputMime} IN ('image/png','image/jpeg','image/webp')`),
  check("oid_support_upload_hash_ck", sql`${table.payloadHash} ~ '^[0-9a-f]{64}$' AND ${table.expectedSha256} ~ '^[0-9a-f]{64}$' AND (${table.outputSha256} IS NULL OR ${table.outputSha256} ~ '^[0-9a-f]{64}$')`)
]);

export const supportImageChunks = pgTable("oid_support_image_chunk", {
  uploadId: uuid("upload_id").notNull(),
  sequence: integer("sequence").notNull(),
  sha256: text("sha256").notNull(),
  bytes: bytea("bytes").notNull(),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.uploadId], foreignColumns: [supportImageUploads.id], name: "oid_support_image_chunk_upload_fk" }).onDelete("cascade"),
  uniqueIndex("oid_support_image_chunk_sequence_uq").on(table.uploadId, table.sequence),
  index("oid_support_image_chunk_created_idx").on(table.createdAt),
  check("oid_support_image_chunk_sequence_ck", sql`${table.sequence} >= 0`),
  check("oid_support_image_chunk_size_ck", sql`octet_length(${table.bytes}) BETWEEN 1 AND 24576`),
  check("oid_support_image_chunk_hash_ck", sql`${table.sha256} ~ '^[0-9a-f]{64}$'`)
]);

export const supportReportAudit = pgTable("oid_support_report_audit", {
  id: uuid("id").primaryKey(),
  reportId: uuid("report_id").notNull(),
  actorOwnerId: uuid("actor_owner_id").notNull(),
  actorAgentId: uuid("actor_agent_id"),
  operationId: text("operation_id"),
  payloadHash: text("payload_hash"),
  eventType: text("event_type").notNull(),
  previousStatus: text("previous_status"),
  nextStatus: text("next_status"),
  revision: integer("revision").notNull(),
  metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.reportId], foreignColumns: [supportReports.id], name: "oid_support_report_audit_report_fk" }).onDelete("cascade"),
  foreignKey({ columns: [table.actorOwnerId], foreignColumns: [owners.id], name: "oid_support_report_audit_owner_fk" }).onDelete("restrict"),
  foreignKey({ columns: [table.actorOwnerId, table.actorAgentId], foreignColumns: [agentProfiles.ownerId, agentProfiles.id], name: "oid_support_report_audit_agent_owner_fk" }).onDelete("restrict"),
  index("oid_support_report_audit_report_idx").on(table.reportId, table.createdAt, table.id),
  check("oid_support_report_audit_event_ck", sql`${table.eventType} IN ('created','status_changed','owner_attached_image')`),
  check("oid_support_report_audit_revision_ck", sql`${table.revision} > 0`),
  check("oid_support_report_audit_status_ck", sql`(${table.previousStatus} IS NULL OR ${table.previousStatus} IN ('new','in_progress','closed')) AND (${table.nextStatus} IS NULL OR ${table.nextStatus} IN ('new','in_progress','closed'))`),
  check("oid_support_report_audit_operation_ck", sql`${table.operationId} IS NULL OR ${table.operationId} ~ '^[A-Za-z0-9_-]{12,128}$'`),
  check("oid_support_report_audit_hash_ck", sql`${table.payloadHash} IS NULL OR ${table.payloadHash} ~ '^[0-9a-f]{64}$'`)
]);

export const supportReportRateLimits = pgTable("oid_support_report_rate", {
  key: text("key").primaryKey(),
  requestCount: integer("request_count").notNull(),
  windowStart: integer("window_start").notNull(),
  updatedAt: time("updated_at").notNull().defaultNow()
}, (table) => [
  check("oid_support_report_rate_key_ck", sql`char_length(${table.key}) BETWEEN 1 AND 200`),
  check("oid_support_report_rate_count_ck", sql`${table.requestCount} >= 0`)
]);

export const supportReportRetentionState = pgTable("oid_support_report_retention_state", {
  id: integer("id").primaryKey(),
  betaEndedAt: time("beta_ended_at"),
  closedByOwnerId: uuid("closed_by_owner_id"),
  closeOperationId: text("close_operation_id"),
  closePayloadHash: text("close_payload_hash"),
  createdAt: time("created_at").notNull().defaultNow()
}, (table) => [
  foreignKey({ columns: [table.closedByOwnerId], foreignColumns: [owners.id], name: "oid_support_retention_admin_fk" }).onDelete("restrict"),
  check("oid_support_retention_id_ck", sql`${table.id} = 1`),
  check("oid_support_retention_shape_ck", sql`(${table.betaEndedAt} IS NULL AND ${table.closedByOwnerId} IS NULL AND ${table.closeOperationId} IS NULL AND ${table.closePayloadHash} IS NULL) OR (${table.betaEndedAt} IS NOT NULL AND ${table.closedByOwnerId} IS NOT NULL AND ${table.closeOperationId} IS NOT NULL AND ${table.closePayloadHash} ~ '^[0-9a-f]{64}$')`),
  check("oid_support_retention_operation_ck", sql`${table.closeOperationId} IS NULL OR ${table.closeOperationId} ~ '^[A-Za-z0-9_-]{12,128}$'`)
]);

export const supportReportDeletionReceipts = pgTable("oid_support_report_deletion_receipt", {
  reportId: uuid("report_id").primaryKey(),
  betaEndedAt: time("beta_ended_at").notNull(),
  expiresAt: time("expires_at").notNull(),
  deletedAt: time("deleted_at").notNull().defaultNow(),
  imageCount: integer("image_count").notNull(),
  pendingStorageKeys: uuid("pending_storage_keys").array().notNull().default(sql`'{}'::uuid[]`),
  pendingStorageBytes: integer("pending_storage_bytes").array().notNull().default(sql`'{}'::integer[]`),
  purgeStatus: text("purge_status").notNull().default("pending"),
  lastAttemptAt: time("last_attempt_at"),
  lastErrorCode: text("last_error_code")
}, (table) => [
  index("oid_support_report_deletion_status_idx").on(table.purgeStatus, table.deletedAt),
  check("oid_support_report_deletion_counts_ck", sql`${table.imageCount} >= 0`),
  check("oid_support_report_deletion_storage_shape_ck", sql`cardinality(${table.pendingStorageKeys}) = cardinality(${table.pendingStorageBytes})`),
  check("oid_support_report_deletion_storage_bytes_ck", sql`array_position(${table.pendingStorageBytes}, NULL) IS NULL AND 0 <= ALL(${table.pendingStorageBytes})`),
  check("oid_support_report_deletion_status_ck", sql`${table.purgeStatus} IN ('pending','failed','complete')`),
  check("oid_support_report_deletion_error_ck", sql`${table.lastErrorCode} IS NULL OR ${table.lastErrorCode} ~ '^[A-Z0-9_]{1,64}$'`)
]);

export const supportUploadGcReceipts = pgTable("oid_support_upload_gc_receipt", {
  id: uuid("id").primaryKey(),
  storageKey: uuid("storage_key"),
  status: text("status").notNull().default("pending"),
  cleanedAt: time("cleaned_at").notNull().defaultNow(),
  reason: text("reason").notNull(),
  reservedBytes: integer("reserved_bytes").notNull().default(0),
  bytesRemoved: integer("bytes_removed").notNull().default(0),
  lastErrorCode: text("last_error_code")
}, (table) => [
  index("oid_support_upload_gc_created_idx").on(table.status, table.cleanedAt),
  check("oid_support_upload_gc_status_ck", sql`${table.status} IN ('pending','failed','complete')`),
  check("oid_support_upload_gc_reason_ck", sql`${table.reason} IN ('unlinked_expired','failed_upload','interrupted_processing')`),
  check("oid_support_upload_gc_reserved_bytes_ck", sql`${table.reservedBytes} >= 0`),
  check("oid_support_upload_gc_bytes_ck", sql`${table.bytesRemoved} >= 0`),
  check("oid_support_upload_gc_error_ck", sql`${table.lastErrorCode} IS NULL OR ${table.lastErrorCode} ~ '^[A-Z0-9_]{1,64}$'`)
]);

export const supportImageInputUsage = pgTable("oid_support_image_input_usage", {
  uploadId: uuid("upload_id").notNull(),
  sequence: integer("sequence").notNull(),
  ownerId: uuid("owner_id").notNull().references(() => owners.id, { onDelete: "restrict" }),
  inputBytes: integer("input_bytes").notNull(),
  receivedAt: time("received_at").notNull().defaultNow()
}, (table) => [
  primaryKey({ columns: [table.uploadId, table.sequence], name: "oid_support_image_input_usage_pk" }),
  index("oid_support_image_input_usage_owner_time_idx").on(table.ownerId, table.receivedAt),
  check("oid_support_image_input_usage_sequence_ck", sql`${table.sequence} >= 0`),
  check("oid_support_image_input_usage_bytes_ck", sql`${table.inputBytes} BETWEEN 1 AND 24576`)
]);

export const reportSchema = {
  supportReports,
  supportImageUploads,
  supportImageChunks,
  supportReportAudit,
  supportReportRateLimits,
  supportReportRetentionState,
  supportReportDeletionReceipts,
  supportUploadGcReceipts,
  supportImageInputUsage
};
