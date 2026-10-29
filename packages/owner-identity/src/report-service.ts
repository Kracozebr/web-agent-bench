import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, realpath, rename, statfs, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { sql } from "drizzle-orm";
import { z } from "zod";
import type { OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import { normalizeReportImage, REPORT_IMAGE_MAX_OUTPUT_BYTES, REPORT_IMAGE_MAX_PIXELS, REPORT_IMAGE_MAX_PER_REPORT, REPORT_IMAGE_MAX_INPUT_BYTES, withReportImageDecoder } from "./report-images.js";
import { asIso, reportDeletionReceiptStatement, reportFirst, reportHash, reportRetentionDeadline, reportRows, reportUuid, reportUuidList } from "./report-db.js";
import type { ReportClosureStateStore } from "./report-closure-state.js";

const REPORTS_PER_MINUTE_PER_PRINCIPAL = 5;
const REPORTS_PER_HOUR_PER_OWNER = 50;
const REPORT_TITLE_MAX = 160;
const REPORT_BODY_MAX = 4000;
const REPORT_TEXT_BODY_LIMIT_BYTES = 16 * 1024;
const REPORT_UPLOAD_TTL_HOURS = 24;
const REPORT_OWNER_STAGE_LIMIT = 15 * 1024 * 1024;
const REPORT_OWNER_STAGE_IMAGE_LIMIT = 3;
const REPORT_OWNER_ROLLING_INPUT_LIMIT = 75 * 1024 * 1024;
const REPORT_TOTAL_STORAGE_LIMIT = 1024 * 1024 * 1024;
const REPORT_MIN_FREE_DISK_BYTES = 2 * 1024 * 1024 * 1024;
const REPORT_RETENTION_DAYS = 30;

export const reportSubmissionSchema = z.object({
  operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
  title: z.string().min(1).max(REPORT_TITLE_MAX),
  body: z.string().min(1).max(REPORT_BODY_MAX),
  agentId: z.string().uuid().optional(),
  runId: z.string().uuid().optional(),
  taskId: z.string().min(1).max(128).optional(),
  actionId: z.string().uuid().optional(),
  clientVersion: z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,63}$/).optional(),
  imageUploadIds: z.array(z.string().uuid()).max(REPORT_IMAGE_MAX_PER_REPORT).default([])
}).strict();

export const reportStatusUpdateSchema = z.object({
  operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
  expectedRevision: z.number().int().positive(),
  status: z.enum(["new", "in_progress", "closed"])
}).strict();

export const reportAttachImagesSchema = z.object({
  operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
  imageUploadIds: z.array(z.string().uuid()).min(1).max(REPORT_IMAGE_MAX_PER_REPORT)
}).strict();

export const reportUploadBeginSchema = z.object({
  operationId: z.string().regex(/^[A-Za-z0-9_-]{12,128}$/),
  expectedBytes: z.number().int().min(1).max(REPORT_IMAGE_MAX_INPUT_BYTES),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  contentType: z.enum(["image/png", "image/jpeg", "image/webp"])
}).strict();

export const reportUploadChunkSchema = z.object({
  uploadId: z.string().uuid(),
  sequence: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  dataBase64: z.string().min(1).max(32_768)
}).strict();

export const reportUploadFinishSchema = z.object({ uploadId: z.string().uuid() }).strict();

export type ReportSubmission = z.infer<typeof reportSubmissionSchema>;
export type ReportActor =
  | { kind: "owner"; ownerId: string; requestId?: string }
  | { kind: "agent"; ownerId: string; agentId: string; requestId?: string };

export interface ReportServiceDependencies {
  db: OwnerDatabase;
  privateDataDir: string;
  reportClosureState: ReportClosureStateStore;
  backupReserveBytes?: number;
}

type ReportTransaction = Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0];
type ReportExecutor = OwnerDatabase | ReportTransaction;

interface StoredReportRow {
  id: string;
  owner_id: string;
  agent_id: string | null;
  source: "owner" | "agent";
  reporter_kind: "owner" | "agent";
  reporter_id: string;
  operation_id: string;
  payload_hash: string;
  title: string;
  body: string;
  safe_context: Record<string, unknown>;
  client_version: string | null;
  run_id: string | null;
  task_id: string | null;
  action_id: string | null;
  status: "new" | "in_progress" | "closed";
  revision: number;
  created_at: Date | string;
  updated_at: Date | string;
}

interface StoredUploadRow {
  id: string;
  owner_id: string;
  uploader_kind: "owner" | "agent";
  uploader_id: string;
  uploader_agent_id: string | null;
  operation_id: string;
  payload_hash: string;
  input_mime: string;
  expected_sha256: string;
  expected_input_bytes: number;
  input_bytes: number;
  reserved_output_bytes: number;
  output_bytes: number | null;
  output_sha256: string | null;
  output_mime: string | null;
  width: number | null;
  height: number | null;
  storage_key: string | null;
  status: "receiving" | "processing" | "ready" | "attached" | "failed";
  report_id: string | null;
  created_at: Date | string;
  updated_at: Date | string;
  expires_at: Date | string;
}

interface StoredImageRow {
  id: string;
  output_sha256: string;
  output_mime: "image/webp";
  output_bytes: number;
  width: number;
  height: number;
  created_at: Date | string;
}

function reportError(status: number, code: string, message: string): HttpError {
  return new HttpError(status, code, message);
}

function normalizeReportText(value: string, field: "title" | "body"): string {
  const normalized = value.replace(/\r\n?/g, "\n").trim();
  const max = field === "title" ? REPORT_TITLE_MAX : REPORT_BODY_MAX;
  if (!normalized || Array.from(normalized).length > max || normalized.includes("\0")) {
    throw reportError(400, `INVALID_REPORT_${field.toUpperCase()}`, `${field} must contain 1 to ${max} safe text characters`);
  }
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bBearer\s+\S+|(?<![A-Za-z0-9_-])BPC-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])|\baap1_[A-Za-z0-9_-]{20,}|\b(?:access_token|refresh_token|client_secret|api_key)\s*[:=]\s*\S+|\b0x[a-f0-9]{64}\b/i.test(normalized)) {
    throw reportError(400, "REPORT_CONTAINS_CREDENTIAL_MATERIAL", "Remove credentials, signatures, and private keys before submitting a report");
  }
  return normalized;
}

function ensureActor(actor: ReportActor): void {
  if (!reportUuid(actor.ownerId) || (actor.kind === "agent" && !reportUuid(actor.agentId))) {
    throw reportError(401, "UNAUTHORIZED", "A current authenticated report principal is required");
  }
}

async function lockReportPrincipal(tx: ReportTransaction, actor: ReportActor): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('support-report'), hashtext(${`${actor.kind}:${actor.kind === "agent" ? actor.agentId : actor.ownerId}`}))`);
}

async function lockUploadQuota(tx: ReportTransaction, ownerId: string): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('support-upload-global'), 0)`);
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('support-upload-owner'), hashtext(${ownerId}))`);
}

interface RetentionState {
  beta_ended_at: Date | string | null;
  expires_at: Date | string | null;
  expired: boolean;
}

async function retentionStateQuery(executor: ReportExecutor, deps: ReportServiceDependencies, lock: boolean): Promise<RetentionState | undefined> {
  const closure = await deps.reportClosureState.readAuthoritativeClosure();
  const rows = reportRows<RetentionState>(await executor.execute(sql`
    WITH recorded AS (
      SELECT beta_ended_at FROM oid_support_report_retention_state WHERE id=1 ${lock ? sql`FOR SHARE` : sql``}
    ), effective AS (
      SELECT LEAST(recorded.beta_ended_at,${closure.betaEndedAt}::timestamptz) AS beta_ended_at FROM recorded
    )
    SELECT effective.beta_ended_at,
      CASE WHEN effective.beta_ended_at IS NULL THEN NULL ELSE ${reportRetentionDeadline(sql.raw("effective.beta_ended_at"))} END AS expires_at,
      (effective.beta_ended_at IS NOT NULL AND clock_timestamp() >= ${reportRetentionDeadline(sql.raw("effective.beta_ended_at"))}) AS expired
    FROM effective
  `));
  return rows[0];
}

async function readRetentionState(executor: ReportExecutor, deps: ReportServiceDependencies): Promise<RetentionState> {
  const state = await retentionStateQuery(executor, deps, false);
  if (!state) throw new Error("Report retention state is missing; run the schema migration first");
  return state;
}

async function requireReportRetentionOpen(tx: ReportTransaction, deps: ReportServiceDependencies): Promise<void> {
  const state = await retentionStateQuery(tx, deps, true);
  if (!state) throw new Error("Report retention state is missing; run the schema migration first");
  if (state.expired) throw reportError(410, "REPORT_RETENTION_EXPIRED", "Report intake and access have expired");
}

export async function assertReportRetentionOpen(deps: ReportServiceDependencies): Promise<void> {
  try {
    await deps.db.transaction((tx) => requireReportRetentionOpen(tx, deps));
  } catch (error) {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  }
}

async function loadReport(executor: ReportExecutor, reportId: string): Promise<Record<string, unknown> | undefined> {
  const row = reportFirst<StoredReportRow>(await executor.execute(sql`
    SELECT id,owner_id,agent_id,source,reporter_kind,reporter_id,operation_id,payload_hash,title,body,
      safe_context,client_version,run_id,task_id,action_id,status,revision,created_at,updated_at
    FROM oid_support_report WHERE id=${reportId}::uuid
  `));
  if (!row) return undefined;
  const images = reportRows<StoredImageRow>(await executor.execute(sql`
    SELECT id,output_sha256,output_mime,output_bytes,width,height,created_at
    FROM oid_support_image_upload WHERE report_id=${reportId}::uuid AND status='attached'
    ORDER BY created_at,id
  `));
  return {
    id: row.id,
    ownerId: row.owner_id,
    agentId: row.agent_id,
    source: row.source,
    title: row.title,
    body: row.body,
    safeContext: row.safe_context,
    clientVersion: row.client_version,
    links: { runId: row.run_id, taskId: row.task_id, actionId: row.action_id },
    status: row.status,
    revision: row.revision,
    createdAt: asIso(row.created_at),
    updatedAt: asIso(row.updated_at),
    images: images.map((image) => ({
      id: image.id,
      contentType: image.output_mime,
      sha256: image.output_sha256,
      bytes: image.output_bytes,
      width: image.width,
      height: image.height,
      createdAt: asIso(image.created_at),
      imagePath: `/api/owner/reports/${encodeURIComponent(row.id)}/images/${encodeURIComponent(image.id)}`
    }))
  };
}

async function validateReportLinks(
  tx: ReportTransaction,
  actor: ReportActor,
  input: ReportSubmission
): Promise<{ agentId: string | null; run?: { mode: string; status: string } }> {
  if (actor.kind === "agent" && input.agentId) throw reportError(400, "INVALID_REPORT_LINK", "Agent identity is derived from the authenticated credential");
  if (!input.runId && (input.taskId || input.actionId)) throw reportError(400, "INVALID_REPORT_LINK", "Task and action links require a run link");

  const requestedAgentId = actor.kind === "agent" ? actor.agentId : input.agentId;
  let agentId: string | null = requestedAgentId ?? null;
  let run: { mode: string; status: string } | undefined;
  if (input.runId) {
    const runRow = reportFirst<{ id: string; owner_id: string; agent_id: string; task_ids: string[]; mode: string; status: string }>(await tx.execute(sql`
      SELECT id,owner_id,agent_id,task_ids,mode,status
      FROM oid_benchmark_run WHERE id=${input.runId}::uuid
        AND owner_id=${actor.ownerId}::uuid
        AND (${requestedAgentId ?? null}::uuid IS NULL OR agent_id=${requestedAgentId ?? null}::uuid)
        AND (${actor.kind === "agent" ? actor.agentId : null}::uuid IS NULL OR agent_id=${actor.kind === "agent" ? actor.agentId : null}::uuid)
      FOR SHARE
    `));
    if (!runRow) throw reportError(404, "REPORT_LINK_NOT_FOUND", "The linked run is not available to this report principal");
    agentId = runRow.agent_id;
    run = { mode: runRow.mode, status: runRow.status };
    if (input.taskId && !runRow.task_ids.includes(input.taskId)) throw reportError(404, "REPORT_LINK_NOT_FOUND", "The linked task is not available to this report principal");
    if (input.actionId) {
      const action = reportFirst<{ id: string }>(await tx.execute(sql`
        SELECT id FROM oid_run_task_action
        WHERE id=${input.actionId}::uuid AND run_id=${input.runId}::uuid
          AND owner_id=${actor.ownerId}::uuid AND agent_id=${agentId}::uuid
          AND (${input.taskId ?? null}::text IS NULL OR task_id=${input.taskId ?? null}::text)
      `));
      if (!action) throw reportError(404, "REPORT_LINK_NOT_FOUND", "The linked action is not available to this report principal");
    }
  } else if (agentId) {
    const ownedAgent = reportFirst<{ id: string }>(await tx.execute(sql`
      SELECT id FROM oid_agent WHERE id=${agentId}::uuid AND owner_id=${actor.ownerId}::uuid FOR SHARE
    `));
    if (!ownedAgent) throw reportError(404, "REPORT_LINK_NOT_FOUND", "The linked agent is not available to this owner");
  }
  return { agentId, ...(run ? { run } : {}) };
}

async function lockAndValidateUploads(tx: ReportTransaction, actor: ReportActor, uploadIds: string[]): Promise<StoredUploadRow[]> {
  if (uploadIds.length > REPORT_IMAGE_MAX_PER_REPORT || new Set(uploadIds).size !== uploadIds.length) {
    throw reportError(400, "INVALID_REPORT_IMAGES", "A report can include at most three distinct screenshots");
  }
  if (!uploadIds.length) return [];
  const uploads = reportRows<StoredUploadRow>(await tx.execute(sql`
    SELECT * FROM oid_support_image_upload WHERE id IN (${reportUuidList(uploadIds)})
      AND expires_at>clock_timestamp() ORDER BY id FOR UPDATE
  `));
  if (uploads.length !== uploadIds.length || uploads.some((upload) =>
    upload.owner_id !== actor.ownerId || upload.status !== "ready" || upload.report_id !== null ||
    upload.uploader_kind !== actor.kind || upload.uploader_id !== (actor.kind === "agent" ? actor.agentId : actor.ownerId))) {
    throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "One or more screenshots are not available to this report principal");
  }
  return uploads;
}

async function consumeCreateRates(tx: ReportTransaction, actor: ReportActor): Promise<void> {
  const clock = reportFirst<{ now_seconds: number }>(await tx.execute(sql`SELECT floor(extract(epoch from clock_timestamp()))::int AS now_seconds`));
  const nowSeconds = clock?.now_seconds ?? 0;
  const minute = Math.floor(nowSeconds / 60) * 60;
  const hour = Math.floor(nowSeconds / 3600) * 3600;
  const buckets = [
    { key: `principal:${actor.kind}:${actor.kind === "agent" ? actor.agentId : actor.ownerId}:minute`, start: minute, limit: REPORTS_PER_MINUTE_PER_PRINCIPAL, code: "REPORT_RATE_LIMITED" },
    { key: `owner:${actor.ownerId}:hour`, start: hour, limit: REPORTS_PER_HOUR_PER_OWNER, code: "REPORT_RATE_LIMITED" }
  ];
  for (const bucket of buckets) {
    const countRow = reportFirst<{ request_count: number }>(await tx.execute(sql`
      INSERT INTO oid_support_report_rate(key,window_start,request_count,updated_at)
      VALUES (${bucket.key},${bucket.start},1,clock_timestamp())
      ON CONFLICT (key) DO UPDATE SET
        request_count=CASE WHEN oid_support_report_rate.window_start=EXCLUDED.window_start THEN oid_support_report_rate.request_count+1 ELSE 1 END,
        window_start=EXCLUDED.window_start,updated_at=clock_timestamp()
      RETURNING request_count
    `));
    if ((countRow?.request_count ?? 0) > bucket.limit) throw reportError(429, bucket.code, "Report creation rate limit reached; retry later");
  }
  await tx.execute(sql`DELETE FROM oid_support_report_rate WHERE updated_at < clock_timestamp() - interval '2 days'`);
}

function createPayloadHash(input: ReportSubmission, title: string, body: string): string {
  return reportHash({
    title,
    body,
    agentId: input.agentId ?? null,
    runId: input.runId ?? null,
    taskId: input.taskId ?? null,
    actionId: input.actionId ?? null,
    clientVersion: input.clientVersion ?? null,
    imageUploadIds: input.imageUploadIds
  });
}

export async function createSupportReport(
  deps: ReportServiceDependencies,
  actor: ReportActor,
  rawInput: unknown
): Promise<{ report: Record<string, unknown>; replayed: boolean }> {
  ensureActor(actor);
  const parsed = reportSubmissionSchema.safeParse(rawInput);
  if (!parsed.success) throw reportError(400, "INVALID_REPORT", "Report fields are invalid or unsupported");
  const input = parsed.data;
  const title = normalizeReportText(input.title, "title");
  const body = normalizeReportText(input.body, "body");
  const payloadHash = createPayloadHash(input, title, body);

  return deps.db.transaction(async (tx) => {
    await lockReportPrincipal(tx, actor);
    await requireReportRetentionOpen(tx, deps);
    const existing = reportFirst<StoredReportRow>(await tx.execute(sql`
      SELECT * FROM oid_support_report WHERE reporter_kind=${actor.kind}
        AND reporter_id=${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid
        AND operation_id=${input.operationId}
      FOR SHARE
    `));
    if (existing) {
      if (existing.payload_hash !== payloadHash) throw reportError(409, "IDEMPOTENCY_CONFLICT", "This report operation was already used with different data");
      const report = await loadReport(tx, existing.id);
      if (!report) throw reportError(410, "REPORT_RETENTION_EXPIRED", "This report is no longer available");
      return { report, replayed: true };
    }

    const links = await validateReportLinks(tx, actor, input);
    await consumeCreateRates(tx, actor);
    await lockAndValidateUploads(tx, actor, input.imageUploadIds);
    const id = randomUUID();
    const reportContext: Record<string, unknown> = {
      capturedAt: new Date().toISOString(),
      runContext: input.runId ? "linked" : "unavailable",
      requestId: actor.requestId && /^[A-Za-z0-9_.:-]{1,128}$/.test(actor.requestId) ? actor.requestId : undefined,
      ...(links.run ? { runMode: links.run.mode, runStatus: links.run.status } : {})
    };
    if (reportContext.requestId === undefined) delete reportContext.requestId;
    await tx.execute(sql`
      INSERT INTO oid_support_report(
        id,owner_id,agent_id,source,reporter_kind,reporter_id,operation_id,payload_hash,title,body,
        safe_context,client_version,run_id,task_id,action_id,status,revision,created_at,updated_at
      ) VALUES (
        ${id}::uuid,${actor.ownerId}::uuid,${links.agentId}::uuid,${actor.kind},${actor.kind},
        ${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid,${input.operationId},${payloadHash},${title},${body},
        ${JSON.stringify(reportContext)}::jsonb,${input.clientVersion ?? null},${input.runId ?? null}::uuid,${input.taskId ?? null},${input.actionId ?? null}::uuid,
        'new',1,clock_timestamp(),clock_timestamp()
      )
    `);
    if (input.imageUploadIds.length) {
      const attached = reportRows<{ id: string }>(await tx.execute(sql`
        UPDATE oid_support_image_upload SET status='attached',report_id=${id}::uuid,reserved_output_bytes=0,updated_at=clock_timestamp()
        WHERE id IN (${reportUuidList(input.imageUploadIds)})
          AND owner_id=${actor.ownerId}::uuid AND status='ready' AND report_id IS NULL
          AND uploader_kind=${actor.kind} AND uploader_id=${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid
        RETURNING id
      `));
      if (attached.length !== input.imageUploadIds.length) throw reportError(409, "REPORT_IMAGE_CONFLICT", "A screenshot was attached by another report operation");
    }
    await tx.execute(sql`
      INSERT INTO oid_support_report_audit(id,report_id,actor_owner_id,actor_agent_id,event_type,revision,metadata,created_at)
      VALUES (${randomUUID()}::uuid,${id}::uuid,${actor.ownerId}::uuid,${actor.kind === "agent" ? actor.agentId : null}::uuid,
        'created',1,${JSON.stringify({ source: actor.kind, imageCount: input.imageUploadIds.length })}::jsonb,clock_timestamp())
    `);
    const report = await loadReport(tx, id);
    if (!report) throw new Error("The support report disappeared before commit");
    return { report, replayed: false };
  });
}

export async function getOwnerSupportReport(deps: ReportServiceDependencies, ownerId: string, reportId: string): Promise<Record<string, unknown>> {
  if (!reportUuid(reportId)) throw reportError(400, "INVALID_REPORT_ID", "Report identifier must be a UUID");
  return deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    const row = reportFirst<{ id: string }>(await tx.execute(sql`SELECT id FROM oid_support_report WHERE id=${reportId}::uuid AND owner_id=${ownerId}::uuid`));
    if (!row) throw reportError(404, "REPORT_NOT_FOUND", "Report was not found");
    const report = await loadReport(tx, row.id);
    if (!report) throw reportError(404, "REPORT_NOT_FOUND", "Report was not found");
    return report;
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
}

export async function getAgentSupportReportReceipt(deps: ReportServiceDependencies, agentId: string, reportId: string): Promise<Record<string, unknown>> {
  if (!reportUuid(reportId)) throw reportError(400, "INVALID_REPORT_ID", "Report identifier must be a UUID");
  return deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    const row = reportFirst<{ id: string; source: string; status: string; created_at: Date | string; image_count: number }>(await tx.execute(sql`
      SELECT r.id,r.source,r.status,r.created_at,count(u.id)::int AS image_count
      FROM oid_support_report r LEFT JOIN oid_support_image_upload u ON u.report_id=r.id AND u.status='attached'
      WHERE r.id=${reportId}::uuid AND r.reporter_kind='agent' AND r.reporter_id=${agentId}::uuid
      GROUP BY r.id
    `));
    if (!row) throw reportError(404, "REPORT_NOT_FOUND", "Report was not found");
    return { id: row.id, source: row.source, status: row.status, createdAt: asIso(row.created_at), imageCount: row.image_count };
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
}

export interface ReportListOptions {
  limit: number;
  cursor?: string;
  source?: "owner" | "agent";
  status?: "new" | "in_progress" | "closed";
  agentId?: string;
  runId?: string;
}

function encodeReportCursor(createdAt: Date | string, id: string): string {
  return Buffer.from(`${asIso(createdAt)}|${id}`, "utf8").toString("base64url");
}

function decodeReportCursor(cursor?: string): { createdAt: string; id: string } | undefined {
  if (!cursor) return undefined;
  if (cursor.length > 256 || !/^[A-Za-z0-9_-]+$/.test(cursor)) throw reportError(400, "INVALID_REPORT_CURSOR", "Report pagination cursor is invalid");
  try {
    const decoded = Buffer.from(cursor, "base64url").toString("utf8");
    const split = decoded.lastIndexOf("|");
    const createdAt = decoded.slice(0, split);
    const id = decoded.slice(split + 1);
    if (split < 1 || Number.isNaN(Date.parse(createdAt)) || !reportUuid(id)) throw new Error("invalid");
    return { createdAt, id };
  } catch {
    throw reportError(400, "INVALID_REPORT_CURSOR", "Report pagination cursor is invalid");
  }
}

async function listReports(deps: ReportServiceDependencies, options: ReportListOptions, ownerId?: string) {
  const filters = [sql`TRUE`];
  if (ownerId) filters.push(sql`r.owner_id=${ownerId}::uuid`);
  if (options.source) filters.push(sql`r.source=${options.source}`);
  if (options.status) filters.push(sql`r.status=${options.status}`);
  if (options.agentId) filters.push(sql`r.agent_id=${options.agentId}::uuid`);
  if (options.runId) filters.push(sql`r.run_id=${options.runId}::uuid`);
  const cursor = decodeReportCursor(options.cursor);
  if (cursor) filters.push(sql`(r.created_at < ${cursor.createdAt}::timestamptz OR (r.created_at=${cursor.createdAt}::timestamptz AND r.id < ${cursor.id}::uuid))`);
  const rows = await deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    return reportRows<StoredReportRow & { image_count: number }>(await tx.execute(sql`
      SELECT r.id,r.owner_id,r.agent_id,r.source,r.reporter_kind,r.reporter_id,r.operation_id,r.payload_hash,r.title,r.body,
        r.safe_context,r.client_version,r.run_id,r.task_id,r.action_id,r.status,r.revision,r.created_at,r.updated_at,
        count(u.id)::int AS image_count
      FROM oid_support_report r LEFT JOIN oid_support_image_upload u ON u.report_id=r.id AND u.status='attached'
      WHERE ${sql.join(filters, sql` AND `)}
      GROUP BY r.id ORDER BY r.created_at DESC,r.id DESC LIMIT ${options.limit + 1}
    `));
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
  const hasMore = rows.length > options.limit;
  const selected = rows.slice(0, options.limit);
  const reports = selected.map((row) => ({
    id: row.id, ownerId: row.owner_id, agentId: row.agent_id, source: row.source,
    title: row.title, body: row.body, safeContext: row.safe_context, clientVersion: row.client_version,
    links: { runId: row.run_id, taskId: row.task_id, actionId: row.action_id },
    status: row.status, revision: row.revision, imageCount: row.image_count,
    createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at)
  }));
  const last = selected.at(-1);
  return { reports, nextCursor: hasMore && last ? encodeReportCursor(last.created_at, last.id) : null };
}

export async function listOwnerSupportReports(deps: ReportServiceDependencies, ownerId: string, options: ReportListOptions) {
  return listReports(deps, options, ownerId);
}

export async function listAdminSupportReports(deps: ReportServiceDependencies, options: ReportListOptions) {
  return listReports(deps, options);
}

export async function getAdminSupportReport(deps: ReportServiceDependencies, reportId: string) {
  if (!reportUuid(reportId)) throw reportError(400, "INVALID_REPORT_ID", "Report identifier must be a UUID");
  return deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    const report = await loadReport(tx, reportId);
    if (!report) throw reportError(404, "REPORT_NOT_FOUND", "Report was not found");
    const audit = reportRows<Record<string, unknown>>(await tx.execute(sql`
      SELECT id,actor_owner_id,actor_agent_id,event_type,previous_status,next_status,revision,metadata,created_at
      FROM oid_support_report_audit WHERE report_id=${reportId}::uuid ORDER BY created_at,id
    `));
    return { ...report, audit: audit.map((entry) => ({
      id: entry.id,
      actorOwnerId: entry.actor_owner_id,
      actorAgentId: entry.actor_agent_id,
      eventType: entry.event_type,
      previousStatus: entry.previous_status,
      nextStatus: entry.next_status,
      revision: entry.revision,
      metadata: entry.metadata,
      createdAt: asIso(entry.created_at as Date | string)
    })) };
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
}

export async function changeAdminReportStatus(
  deps: ReportServiceDependencies,
  actorOwnerId: string,
  reportId: string,
  rawInput: unknown
): Promise<{ report: Record<string, unknown>; replayed: boolean }> {
  const parsed = reportStatusUpdateSchema.safeParse(rawInput);
  if (!parsed.success || !reportUuid(reportId)) throw reportError(400, "INVALID_REPORT_STATUS", "Report status operation is invalid");
  const input = parsed.data;
  const payloadHash = reportHash({ reportId, expectedRevision: input.expectedRevision, status: input.status });
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('support-report-status'), hashtext(${reportId}))`);
    await requireReportRetentionOpen(tx, deps);
    const replay = reportFirst<{ payload_hash: string; report_id: string }>(await tx.execute(sql`
      SELECT payload_hash,report_id FROM oid_support_report_audit
      WHERE report_id=${reportId}::uuid AND actor_owner_id=${actorOwnerId}::uuid
        AND operation_id=${input.operationId} AND event_type='status_changed'
      LIMIT 1
    `));
    if (replay) {
      if (replay.payload_hash !== payloadHash) throw reportError(409, "IDEMPOTENCY_CONFLICT", "This admin operation was already used with different data");
      const report = await loadReport(tx, reportId);
      if (!report) throw reportError(410, "REPORT_RETENTION_EXPIRED", "This report is no longer available");
      return { report, replayed: true };
    }
    const current = reportFirst<StoredReportRow>(await tx.execute(sql`SELECT * FROM oid_support_report WHERE id=${reportId}::uuid FOR UPDATE`));
    if (!current) throw reportError(404, "REPORT_NOT_FOUND", "Report was not found");
    if (current.revision !== input.expectedRevision) throw reportError(409, "REPORT_REVISION_CONFLICT", "Report status changed in another admin session");
    const allowed = (current.status === "new" && (input.status === "in_progress" || input.status === "closed")) ||
      (current.status === "in_progress" && input.status === "closed") ||
      (current.status === "closed" && input.status === "in_progress");
    if (!allowed) throw reportError(409, "REPORT_STATUS_TRANSITION_INVALID", "Report must be new, in progress, or reopened to in progress");
    const nextRevision = current.revision + 1;
    await tx.execute(sql`
      UPDATE oid_support_report SET status=${input.status},revision=${nextRevision},updated_at=clock_timestamp()
      WHERE id=${reportId}::uuid AND revision=${input.expectedRevision}
    `);
    await tx.execute(sql`
      INSERT INTO oid_support_report_audit(id,report_id,actor_owner_id,operation_id,payload_hash,event_type,previous_status,next_status,revision,metadata,created_at)
      VALUES (${randomUUID()}::uuid,${reportId}::uuid,${actorOwnerId}::uuid,${input.operationId},${payloadHash},
        'status_changed',${current.status},${input.status},${nextRevision},'{}'::jsonb,clock_timestamp())
    `);
    const report = await loadReport(tx, reportId);
    if (!report) throw new Error("The support report disappeared during a status update");
    return { report, replayed: false };
  });
}

export async function attachOwnerImagesToAgentReport(
  deps: ReportServiceDependencies,
  ownerId: string,
  reportId: string,
  rawInput: unknown
): Promise<{ report: Record<string, unknown>; replayed: boolean }> {
  const parsed = reportAttachImagesSchema.safeParse(rawInput);
  if (!parsed.success || !reportUuid(reportId)) throw reportError(400, "INVALID_REPORT_IMAGES", "Screenshot attachment request is invalid");
  const input = parsed.data;
  const payloadHash = reportHash({ reportId, imageUploadIds: input.imageUploadIds });
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('support-report-attach'), hashtext(${reportId}))`);
    await requireReportRetentionOpen(tx, deps);
    const replay = reportFirst<{ payload_hash: string }>(await tx.execute(sql`
      SELECT payload_hash FROM oid_support_report_audit
      WHERE report_id=${reportId}::uuid AND actor_owner_id=${ownerId}::uuid
        AND operation_id=${input.operationId} AND event_type='owner_attached_image' LIMIT 1
    `));
    if (replay) {
      if (replay.payload_hash !== payloadHash) throw reportError(409, "IDEMPOTENCY_CONFLICT", "This screenshot attachment operation was already used with different data");
      const report = await loadReport(tx, reportId);
      if (!report) throw reportError(410, "REPORT_RETENTION_EXPIRED", "This report is no longer available");
      return { report, replayed: true };
    }
    const report = reportFirst<StoredReportRow>(await tx.execute(sql`
      SELECT * FROM oid_support_report WHERE id=${reportId}::uuid AND owner_id=${ownerId}::uuid AND source='agent' FOR UPDATE
    `));
    if (!report) throw reportError(404, "REPORT_NOT_FOUND", "This agent report is not available to the owner");
    const uploads = await lockAndValidateUploads(tx, { kind: "owner", ownerId }, input.imageUploadIds);
    const countRow = reportFirst<{ count: number }>(await tx.execute(sql`SELECT count(*)::int AS count FROM oid_support_image_upload WHERE report_id=${reportId}::uuid AND status='attached'`));
    if ((countRow?.count ?? 0) + uploads.length > REPORT_IMAGE_MAX_PER_REPORT) throw reportError(409, "REPORT_IMAGE_LIMIT", "A report can include at most three screenshots");
    const attached = reportRows<{ id: string }>(await tx.execute(sql`
      UPDATE oid_support_image_upload SET status='attached',report_id=${reportId}::uuid,reserved_output_bytes=0,updated_at=clock_timestamp()
      WHERE id IN (${reportUuidList(input.imageUploadIds)})
        AND owner_id=${ownerId}::uuid AND uploader_kind='owner'
        AND uploader_id=${ownerId}::uuid AND status='ready' AND report_id IS NULL RETURNING id
    `));
    if (attached.length !== uploads.length) throw reportError(409, "REPORT_IMAGE_CONFLICT", "A screenshot was attached by another operation");
    await tx.execute(sql`
      INSERT INTO oid_support_report_audit(id,report_id,actor_owner_id,operation_id,payload_hash,event_type,revision,metadata,created_at)
      VALUES (${randomUUID()}::uuid,${reportId}::uuid,${ownerId}::uuid,${input.operationId},${payloadHash},
        'owner_attached_image',${report.revision},${JSON.stringify({ imageIds: input.imageUploadIds })}::jsonb,clock_timestamp())
    `);
    const updated = await loadReport(tx, reportId);
    if (!updated) throw new Error("The support report disappeared during screenshot attachment");
    return { report: updated, replayed: false };
  });
}

function reportImagePaths(deps: ReportServiceDependencies) {
  const privateRoot = resolve(deps.privateDataDir);
  if (!isAbsolute(privateRoot)) throw new Error("Report image private data root must be absolute");
  const imageRoot = resolve(privateRoot, "reports", "images");
  const stagingRoot = resolve(privateRoot, "reports", "staging");
  for (const path of [imageRoot, stagingRoot]) {
    const relativePath = relative(privateRoot, path);
    if (!relativePath || relativePath.startsWith(`..${sep}`) || relativePath === ".." || isAbsolute(relativePath)) throw new Error("Report storage path escapes its configured private root");
  }
  return { privateRoot, imageRoot, stagingRoot };
}

function pathWithin(root: string, target: string): boolean {
  const rel = relative(root, target);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function verifyDirectoryChain(path: string): Promise<void> {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Private screenshot storage path contains a link or non-directory");
  }
}

async function ensureDirectoryChain(path: string): Promise<void> {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let info;
    try { info = await lstat(current); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      try { await mkdir(current, { mode: 0o700 }); }
      catch (createError) {
        if ((createError as NodeJS.ErrnoException).code !== "EEXIST") throw createError;
      }
      info = await lstat(current);
    }
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Private screenshot storage path contains a link or non-directory");
  }
}

async function ensurePrivateDirectory(path: string, privateRoot: string): Promise<void> {
  await ensureDirectoryChain(path);
  await verifyDirectoryChain(privateRoot);
  await verifyDirectoryChain(path);
  const [rootReal, targetReal] = await Promise.all([realpath(privateRoot), realpath(path)]);
  if (!pathWithin(rootReal, targetReal)) throw new Error("Private screenshot storage resolves outside its configured root");
  await chmod(path, 0o700);
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isDirectory() || (process.platform !== "win32" && (info.mode & 0o077) !== 0)) {
    throw new Error("Private screenshot storage directory is not private");
  }
}

async function assertPrivateImageDirectory(deps: ReportServiceDependencies): Promise<string> {
  const { privateRoot, imageRoot } = reportImagePaths(deps);
  await verifyDirectoryChain(privateRoot);
  await verifyDirectoryChain(imageRoot);
  const [rootReal, imageReal] = await Promise.all([realpath(privateRoot), realpath(imageRoot)]);
  const info = await lstat(imageRoot);
  if (!pathWithin(rootReal, imageReal) || info.isSymbolicLink() || !info.isDirectory() ||
    (process.platform !== "win32" && (info.mode & 0o077) !== 0)) {
    throw new Error("Private screenshot storage directory is unsafe");
  }
  return imageReal;
}

function storagePath(deps: ReportServiceDependencies, storageKey: string): string {
  if (!reportUuid(storageKey)) throw new Error("Invalid internal report storage key");
  const { imageRoot } = reportImagePaths(deps);
  return resolve(imageRoot, `${storageKey}.webp`);
}

async function ensureImageDiskCapacity(deps: ReportServiceDependencies): Promise<void> {
  const { privateRoot, imageRoot } = reportImagePaths(deps);
  await ensurePrivateDirectory(imageRoot, privateRoot);
  const capacity = await statfs(imageRoot, { bigint: true });
  const free = capacity.bavail * capacity.bsize;
  const total = capacity.blocks * capacity.bsize;
  const threshold = [REPORT_MIN_FREE_DISK_BYTES, (total * 20n) / 100n, BigInt(Math.max(0, Math.trunc(deps.backupReserveBytes ?? 0)))].reduce((a, b) => a > b ? a : b);
  if (free < threshold) throw reportError(507, "REPORT_IMAGE_STORAGE_LOW", "Screenshot uploads are paused because private storage or backup capacity is low");
}

function partialStoragePath(deps: ReportServiceDependencies, storageKey: string): string {
  const { imageRoot } = reportImagePaths(deps);
  return resolve(imageRoot, `${storageKey}.partial`);
}

async function writeImageFile(deps: ReportServiceDependencies, storageKey: string, bytes: Buffer): Promise<void> {
  const target = storagePath(deps, storageKey);
  const { privateRoot, imageRoot } = reportImagePaths(deps);
  await ensurePrivateDirectory(imageRoot, privateRoot);
  const temporary = partialStoragePath(deps, storageKey);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, target);
    const directory = await open(dirname(target), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function deleteImageFile(deps: ReportServiceDependencies, storageKey: string): Promise<{ deleted: boolean; bytesRemoved: number }> {
  let bytesRemoved = 0;
  try { await assertPrivateImageDirectory(deps); } catch { return { deleted: false, bytesRemoved }; }
  for (const file of [storagePath(deps, storageKey), partialStoragePath(deps, storageKey)]) {
    try {
      const info = await lstat(file);
      if (!info.isFile() || info.isSymbolicLink()) return { deleted: false, bytesRemoved };
      await unlink(file);
      bytesRemoved += info.size;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return { deleted: false, bytesRemoved };
    }
  }
  try {
    const directory = await open(dirname(storagePath(deps, storageKey)), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    return { deleted: false, bytesRemoved };
  }
  return { deleted: true, bytesRemoved };
}

async function uploadUsage(tx: ReportTransaction, ownerId: string, inputBytes: number): Promise<void> {
  await lockUploadQuota(tx, ownerId);
  const usage = reportFirst<{ pending_count: number; pending_input: number; rolling_input: number; global_storage: number }>(await tx.execute(sql`
    SELECT
      (SELECT count(*)::int FROM oid_support_image_upload WHERE owner_id=${ownerId}::uuid AND report_id IS NULL
        AND status IN ('receiving','processing','ready') AND expires_at>clock_timestamp()) AS pending_count,
      (SELECT coalesce(sum(expected_input_bytes),0)::bigint FROM oid_support_image_upload WHERE owner_id=${ownerId}::uuid AND report_id IS NULL
        AND status IN ('receiving','processing','ready') AND expires_at>clock_timestamp()) AS pending_input,
      (SELECT coalesce(sum(input_bytes),0)::bigint FROM oid_support_image_input_usage
        WHERE owner_id=${ownerId}::uuid AND received_at>clock_timestamp()-interval '24 hours') +
      (SELECT coalesce(sum(greatest(expected_input_bytes-input_bytes,0)),0)::bigint FROM oid_support_image_upload
        WHERE owner_id=${ownerId}::uuid AND status IN ('receiving','processing') AND expires_at>clock_timestamp()) AS rolling_input,
      (SELECT coalesce(sum(CASE WHEN status IN ('receiving','processing') THEN reserved_output_bytes ELSE coalesce(output_bytes,0) END),0)::bigint
        FROM oid_support_image_upload WHERE status IN ('receiving','processing','ready','attached')) +
      (SELECT coalesce(sum(pending_storage.pending_bytes),0)::bigint FROM oid_support_report_deletion_receipt d,
        unnest(d.pending_storage_bytes) AS pending_storage(pending_bytes) WHERE d.purge_status IN ('pending','failed')) +
      (SELECT coalesce(sum(reserved_bytes),0)::bigint FROM oid_support_upload_gc_receipt WHERE status IN ('pending','failed')) AS global_storage
  `));
  const pendingCount = Number(usage?.pending_count ?? 0);
  const pendingInput = Number(usage?.pending_input ?? 0);
  const rollingInput = Number(usage?.rolling_input ?? 0);
  const globalStorage = Number(usage?.global_storage ?? 0);
  if (pendingCount >= REPORT_OWNER_STAGE_IMAGE_LIMIT || pendingInput + inputBytes > REPORT_OWNER_STAGE_LIMIT) {
    throw reportError(429, "REPORT_IMAGE_STAGING_LIMIT", "The owner screenshot staging quota is full");
  }
  if (rollingInput + inputBytes > REPORT_OWNER_ROLLING_INPUT_LIMIT) {
    throw reportError(429, "REPORT_IMAGE_ROLLING_QUOTA", "The owner screenshot upload quota is full for the last 24 hours");
  }
  if (globalStorage + REPORT_IMAGE_MAX_OUTPUT_BYTES > REPORT_TOTAL_STORAGE_LIMIT) {
    throw reportError(507, "REPORT_IMAGE_STORAGE_LIMIT", "Shared private screenshot storage is full");
  }
}

function imageOperationHash(input: { expectedBytes: number; sha256: string; contentType: string }): string {
  return reportHash({ expectedBytes: input.expectedBytes, sha256: input.sha256.toLowerCase(), contentType: input.contentType });
}

export async function beginSupportImageUpload(
  deps: ReportServiceDependencies,
  actor: ReportActor,
  rawInput: unknown
): Promise<{ uploadId: string; status: string; expiresAt: string; nextSequence: number; replayed: boolean }> {
  ensureActor(actor);
  const parsed = reportUploadBeginSchema.safeParse(rawInput);
  if (!parsed.success) throw reportError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload details are invalid");
  await ensureImageDiskCapacity(deps);
  const input = parsed.data;
  const expectedHash = input.sha256.toLowerCase();
  const payloadHash = imageOperationHash({ expectedBytes: input.expectedBytes, sha256: expectedHash, contentType: input.contentType });
  return deps.db.transaction(async (tx) => {
    await lockUploadQuota(tx, actor.ownerId);
    await requireReportRetentionOpen(tx, deps);
    const existing = reportFirst<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE uploader_kind=${actor.kind}
        AND uploader_id=${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid
        AND operation_id=${input.operationId} FOR UPDATE
    `));
    if (existing) {
      if (existing.payload_hash !== payloadHash) throw reportError(409, "IDEMPOTENCY_CONFLICT", "This screenshot upload key was already used with different bytes or metadata");
      if (existing.status === "failed") throw reportError(409, "REPORT_IMAGE_UPLOAD_FAILED", "This screenshot upload failed; start a new upload operation");
      const count = reportFirst<{ count: number }>(await tx.execute(sql`SELECT count(*)::int AS count FROM oid_support_image_chunk WHERE upload_id=${existing.id}::uuid`));
      return { uploadId: existing.id, status: existing.status, expiresAt: asIso(existing.expires_at), nextSequence: count?.count ?? 0, replayed: true };
    }
    await uploadUsage(tx, actor.ownerId, input.expectedBytes);
    const id = randomUUID();
    const created = reportFirst<{ expires_at: Date | string }>(await tx.execute(sql`
      INSERT INTO oid_support_image_upload(
        id,owner_id,uploader_kind,uploader_id,uploader_agent_id,operation_id,payload_hash,input_mime,expected_sha256,
        expected_input_bytes,input_bytes,reserved_output_bytes,storage_key,status,report_id,created_at,updated_at,expires_at
      ) VALUES (
        ${id}::uuid,${actor.ownerId}::uuid,${actor.kind},${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid,
        ${actor.kind === "agent" ? actor.agentId : null}::uuid,${input.operationId},${payloadHash},${input.contentType},${expectedHash},
        ${input.expectedBytes},0,${REPORT_IMAGE_MAX_OUTPUT_BYTES},NULL,'receiving',NULL,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '24 hours'
      ) RETURNING expires_at
    `));
    if (!created) throw new Error("Screenshot upload was not created");
    return { uploadId: id, status: "receiving", expiresAt: asIso(created.expires_at), nextSequence: 0, replayed: false };
  });
}

export async function appendSupportImageChunk(
  deps: ReportServiceDependencies,
  actor: ReportActor,
  rawInput: unknown,
  decodedBytes: Buffer
): Promise<{ uploadId: string; sequence: number; acceptedBytes: number; nextSequence: number; replayed: boolean }> {
  ensureActor(actor);
  const parsed = reportUploadChunkSchema.safeParse(rawInput);
  if (!parsed.success || !Buffer.isBuffer(decodedBytes) || decodedBytes.length < 1 || decodedBytes.length > 24 * 1024) {
    throw reportError(400, "INVALID_REPORT_IMAGE_CHUNK", "Screenshot chunk is invalid");
  }
  const input = parsed.data;
  const chunkHash = createHash("sha256").update(decodedBytes).digest("hex");
  if (chunkHash !== input.sha256.toLowerCase()) throw reportError(400, "REPORT_IMAGE_CHUNK_HASH_MISMATCH", "Screenshot chunk hash does not match its bytes");
  return deps.db.transaction(async (tx) => {
    await lockUploadQuota(tx, actor.ownerId);
    await requireReportRetentionOpen(tx, deps);
    const upload = reportFirst<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE id=${input.uploadId}::uuid AND owner_id=${actor.ownerId}::uuid
        AND uploader_kind=${actor.kind} AND uploader_id=${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid
        AND expires_at>clock_timestamp()
      FOR UPDATE
    `));
    if (!upload) throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "Screenshot upload was not found for this principal");
    if (upload.status !== "receiving") throw reportError(409, "REPORT_IMAGE_UPLOAD_CLOSED", "Screenshot upload is no longer accepting chunks");
    const existing = reportFirst<{ sha256: string; bytes: Buffer }>(await tx.execute(sql`
      SELECT sha256,bytes FROM oid_support_image_chunk WHERE upload_id=${input.uploadId}::uuid AND sequence=${input.sequence}
    `));
    const count = reportFirst<{ count: number; total_bytes: number }>(await tx.execute(sql`
      SELECT count(*)::int AS count,coalesce(sum(octet_length(bytes)),0)::int AS total_bytes FROM oid_support_image_chunk WHERE upload_id=${input.uploadId}::uuid
    `));
    const expectedSequence = count?.count ?? 0;
    if (existing) {
      const exact = existing.sha256 === chunkHash && Buffer.from(existing.bytes).equals(decodedBytes);
      if (!exact) throw reportError(409, "REPORT_IMAGE_CHUNK_CONFLICT", "A screenshot chunk sequence was already used with different bytes");
      return { uploadId: upload.id, sequence: input.sequence, acceptedBytes: decodedBytes.length, nextSequence: expectedSequence, replayed: true };
    }
    if (input.sequence !== expectedSequence) throw reportError(409, "REPORT_IMAGE_CHUNK_ORDER", "Screenshot chunks must arrive in order");
    const received = count?.total_bytes ?? 0;
    if (received + decodedBytes.length > upload.expected_input_bytes) throw reportError(413, "REPORT_IMAGE_TOO_LARGE", "Screenshot chunks exceed the declared input size");
    await tx.execute(sql`
      INSERT INTO oid_support_image_chunk(upload_id,sequence,sha256,bytes,created_at)
      VALUES (${upload.id}::uuid,${input.sequence},${chunkHash},${decodedBytes},clock_timestamp())
    `);
    await tx.execute(sql`UPDATE oid_support_image_upload SET input_bytes=${received + decodedBytes.length},updated_at=clock_timestamp() WHERE id=${upload.id}::uuid`);
    await tx.execute(sql`
      INSERT INTO oid_support_image_input_usage(upload_id,sequence,owner_id,input_bytes,received_at)
      VALUES (${upload.id}::uuid,${input.sequence},${actor.ownerId}::uuid,${decodedBytes.length},clock_timestamp())
    `);
    return { uploadId: upload.id, sequence: input.sequence, acceptedBytes: decodedBytes.length, nextSequence: expectedSequence + 1, replayed: false };
  });
}

async function finishSupportImageUpload(deps: ReportServiceDependencies, actor: ReportActor, uploadId: string): Promise<{ upload: Record<string, unknown>; replayed: boolean }> {
  ensureActor(actor);
  if (!reportUuid(uploadId)) throw reportError(400, "INVALID_REPORT_IMAGE_UPLOAD", "Screenshot upload identifier must be a UUID");
  const pending = await deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    const upload = reportFirst<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE id=${uploadId}::uuid AND owner_id=${actor.ownerId}::uuid
        AND uploader_kind=${actor.kind} AND uploader_id=${actor.kind === "agent" ? actor.agentId : actor.ownerId}::uuid
        AND expires_at>clock_timestamp() FOR UPDATE
    `));
    if (!upload) throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "Screenshot upload was not found for this principal");
    if (upload.status === "ready" || upload.status === "attached") return { upload, bytes: undefined as Buffer | undefined, replayed: true };
    if (upload.status !== "receiving") throw reportError(409, "REPORT_IMAGE_UPLOAD_CLOSED", "Screenshot upload is no longer available");
    const chunks = reportRows<{ sequence: number; bytes: Buffer }>(await tx.execute(sql`SELECT sequence,bytes FROM oid_support_image_chunk WHERE upload_id=${uploadId}::uuid ORDER BY sequence`));
    if (!chunks.length || chunks.some((chunk, index) => chunk.sequence !== index)) throw reportError(409, "REPORT_IMAGE_UPLOAD_INCOMPLETE", "Screenshot upload is missing one or more ordered chunks");
    const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk.bytes)));
    if (bytes.length !== upload.expected_input_bytes || upload.expected_sha256 !== createHash("sha256").update(bytes).digest("hex")) {
      throw reportError(400, "REPORT_IMAGE_UPLOAD_HASH_MISMATCH", "Screenshot bytes do not match the declared size and hash");
    }
    await tx.execute(sql`UPDATE oid_support_image_upload SET status='processing',input_bytes=${bytes.length},updated_at=clock_timestamp() WHERE id=${uploadId}::uuid`);
    return { upload, bytes, replayed: false };
  });
  if (pending.replayed) return { upload: await readUploadReceipt(deps, pending.upload.id), replayed: true };
  if (!pending.bytes) throw new Error("Screenshot processing lost its input bytes");

  let storageKey: string | undefined;
  let normalizedBytes = 0;
  try {
    await ensureImageDiskCapacity(deps);
    const normalized = await withReportImageDecoder(() => normalizeReportImage(pending.bytes!, pending.upload.input_mime));
    if (normalized.width * normalized.height > REPORT_IMAGE_MAX_PIXELS || normalized.bytes.length > REPORT_IMAGE_MAX_OUTPUT_BYTES) {
      throw reportError(400, "INVALID_REPORT_IMAGE", "Normalized screenshot exceeds the configured output bounds");
    }
    normalizedBytes = normalized.bytes.length;
    storageKey = randomUUID();
    await deps.db.transaction(async (tx) => {
      await requireReportRetentionOpen(tx, deps);
      const prepared = reportFirst<{ id: string }>(await tx.execute(sql`
        UPDATE oid_support_image_upload SET storage_key=${storageKey}::uuid,updated_at=clock_timestamp()
        WHERE id=${pending.upload.id}::uuid AND status='processing' AND storage_key IS NULL RETURNING id
      `));
      if (!prepared) throw reportError(409, "REPORT_IMAGE_UPLOAD_CLOSED", "Screenshot upload expired before storage was prepared");
    });
    await writeImageFile(deps, storageKey, normalized.bytes);
    const saved = await deps.db.transaction(async (tx) => {
      await requireReportRetentionOpen(tx, deps);
      const stillProcessing = reportFirst<{ status: string; expires_at: Date | string }>(await tx.execute(sql`
        SELECT status,expires_at FROM oid_support_image_upload WHERE id=${pending.upload.id}::uuid AND expires_at>clock_timestamp() FOR UPDATE
      `));
      if (!stillProcessing || stillProcessing.status !== "processing") {
        throw reportError(409, "REPORT_IMAGE_UPLOAD_CLOSED", "Screenshot upload expired before it could be committed");
      }
      const rows = reportRows<StoredUploadRow>(await tx.execute(sql`
        UPDATE oid_support_image_upload SET status='ready',storage_key=${storageKey}::uuid,
          output_bytes=${normalized.bytes.length},output_sha256=${normalized.sha256},output_mime=${normalized.contentType},
          width=${normalized.width},height=${normalized.height},reserved_output_bytes=0,updated_at=clock_timestamp()
        WHERE id=${pending.upload.id}::uuid AND status='processing' RETURNING *
      `));
      if (rows.length !== 1) throw reportError(409, "REPORT_IMAGE_UPLOAD_CLOSED", "Screenshot upload could not be committed");
      await tx.execute(sql`DELETE FROM oid_support_image_chunk WHERE upload_id=${pending.upload.id}::uuid`);
      return rows[0]!;
    });
    return { upload: uploadProjection(saved), replayed: false };
  } catch (error) {
    const removed = storageKey ? await deleteImageFile(deps, storageKey) : { deleted: true, bytesRemoved: 0 };
    const code = error instanceof HttpError ? error.code : "IMAGE_PROCESSING_FAILED";
    await deps.db.transaction(async (tx) => {
      await tx.execute(sql`
        UPDATE oid_support_image_upload SET status='failed',reserved_output_bytes=0,
          storage_key=NULL,output_bytes=NULL,output_sha256=NULL,
          output_mime=NULL,width=NULL,height=NULL,updated_at=clock_timestamp()
        WHERE id=${pending.upload.id}::uuid AND status='processing'
      `);
      if (storageKey && !removed.deleted) {
        await tx.execute(sql`
          INSERT INTO oid_support_upload_gc_receipt(id,storage_key,status,cleaned_at,reason,reserved_bytes,bytes_removed,last_error_code)
          VALUES (${randomUUID()}::uuid,${storageKey}::uuid,'pending',clock_timestamp(),'failed_upload',${normalizedBytes},0,'STORAGE_DELETE_FAILED')
        `);
      }
    }).catch(() => undefined);
    await deps.db.execute(sql`DELETE FROM oid_support_image_chunk WHERE upload_id=${pending.upload.id}::uuid`).catch(() => undefined);
    throw error instanceof HttpError ? error : reportError(400, code, "Screenshot could not be decoded and normalized");
  }
}

function uploadProjection(row: StoredUploadRow) {
  return {
    id: row.id,
    status: row.status,
    inputBytes: row.input_bytes,
    bytes: row.output_bytes,
    contentType: row.output_mime,
    sha256: row.output_sha256,
    width: row.width,
    height: row.height,
    expiresAt: asIso(row.expires_at)
  };
}

async function readUploadReceipt(deps: ReportServiceDependencies, uploadId: string) {
  const row = reportFirst<StoredUploadRow>(await deps.db.execute(sql`SELECT * FROM oid_support_image_upload WHERE id=${uploadId}::uuid`));
  if (!row) throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "Screenshot upload was not found");
  return uploadProjection(row);
}

export async function uploadSupportImageBytes(
  deps: ReportServiceDependencies,
  actor: ReportActor,
  operationId: string,
  inputBytes: Buffer,
  contentType: string
): Promise<{ upload: Record<string, unknown>; replayed: boolean }> {
  if (!Buffer.isBuffer(inputBytes) || inputBytes.length < 1 || inputBytes.length > REPORT_IMAGE_MAX_INPUT_BYTES) {
    throw reportError(413, "REPORT_IMAGE_TOO_LARGE", "Screenshot input exceeds the 5 MiB limit");
  }
  if (!["image/png", "image/jpeg", "image/webp"].includes(contentType)) throw reportError(415, "REPORT_IMAGE_TYPE_UNSUPPORTED", "Only PNG, JPEG, and WebP images are accepted");
  const sha256 = createHash("sha256").update(inputBytes).digest("hex");
  const begun = await beginSupportImageUpload(deps, actor, {
    operationId, expectedBytes: inputBytes.length, sha256, contentType
  });
  if (begun.status === "ready" || begun.status === "attached") return { upload: await readUploadReceipt(deps, begun.uploadId), replayed: true };
  if (begun.status !== "receiving") throw reportError(409, "REPORT_IMAGE_UPLOAD_IN_PROGRESS", "Screenshot upload is already being processed");
  for (let sequence = 0, offset = 0; offset < inputBytes.length; sequence++, offset += 24 * 1024) {
    const chunk = inputBytes.subarray(offset, Math.min(offset + 24 * 1024, inputBytes.length));
    const chunkHash = createHash("sha256").update(chunk).digest("hex");
    await appendSupportImageChunk(deps, actor, {
      uploadId: begun.uploadId,
      sequence,
      sha256: chunkHash,
      dataBase64: chunk.toString("base64")
    }, chunk);
  }
  return finishSupportImageUpload(deps, actor, begun.uploadId);
}

export async function finishSupportImageUploadForActor(deps: ReportServiceDependencies, actor: ReportActor, uploadId: string) {
  return finishSupportImageUpload(deps, actor, uploadId);
}

export async function readOwnerReportImage(deps: ReportServiceDependencies, ownerId: string, reportId: string, imageId: string): Promise<{ bytes: Buffer; contentType: string; sha256: string }> {
  if (!reportUuid(reportId) || !reportUuid(imageId)) throw reportError(400, "INVALID_REPORT_IMAGE_ID", "Screenshot identifier is invalid");
  const image = await deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    return reportFirst<StoredUploadRow>(await tx.execute(sql`
      SELECT u.* FROM oid_support_image_upload u JOIN oid_support_report r ON r.id=u.report_id
      WHERE r.id=${reportId}::uuid AND r.owner_id=${ownerId}::uuid AND u.id=${imageId}::uuid AND u.status='attached'
    `));
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
  if (!image?.storage_key || image.output_mime !== "image/webp" || !image.output_sha256) throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "Screenshot was not found");
  let imageRoot: string;
  try { imageRoot = await assertPrivateImageDirectory(deps); } catch { throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable"); }
  const file = storagePath(deps, image.storage_key);
  let metadata;
  let resolvedFile: string;
  try { metadata = await lstat(file); resolvedFile = await realpath(file); } catch { throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable"); }
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable");
  if (!pathWithin(imageRoot, resolvedFile)) throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable");
  const bytes = await import("node:fs/promises").then((fs) => fs.readFile(resolvedFile));
  if (bytes.length !== image.output_bytes || createHash("sha256").update(bytes).digest("hex") !== image.output_sha256) {
    throw reportError(410, "REPORT_IMAGE_INTEGRITY_FAILED", "Screenshot integrity verification failed");
  }
  await assertReportRetentionOpen(deps);
  return { bytes, contentType: image.output_mime, sha256: image.output_sha256 };
}

export async function readAdminReportImage(deps: ReportServiceDependencies, reportId: string, imageId: string) {
  if (!reportUuid(reportId) || !reportUuid(imageId)) throw reportError(400, "INVALID_REPORT_IMAGE_ID", "Screenshot identifier is invalid");
  const image = await deps.db.transaction(async (tx) => {
    await requireReportRetentionOpen(tx, deps);
    return reportFirst<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE report_id=${reportId}::uuid AND id=${imageId}::uuid AND status='attached'
    `));
  }).catch(async (error: unknown) => {
    if (error instanceof HttpError && error.code === "REPORT_RETENTION_EXPIRED") await runReportRetentionCleanup(deps);
    throw error;
  });
  if (!image?.storage_key || !image.output_mime || !image.output_sha256) throw reportError(404, "REPORT_IMAGE_NOT_FOUND", "Screenshot was not found");
  let imageRoot: string;
  try { imageRoot = await assertPrivateImageDirectory(deps); } catch { throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable"); }
  const file = storagePath(deps, image.storage_key);
  let metadata;
  let resolvedFile: string;
  try { metadata = await lstat(file); resolvedFile = await realpath(file); } catch { throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable"); }
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable");
  if (!pathWithin(imageRoot, resolvedFile)) throw reportError(410, "REPORT_IMAGE_UNAVAILABLE", "Screenshot storage is unavailable");
  const bytes = await import("node:fs/promises").then((fs) => fs.readFile(resolvedFile));
  if (bytes.length !== image.output_bytes || createHash("sha256").update(bytes).digest("hex") !== image.output_sha256) {
    throw reportError(410, "REPORT_IMAGE_INTEGRITY_FAILED", "Screenshot integrity verification failed");
  }
  await assertReportRetentionOpen(deps);
  return { bytes, contentType: image.output_mime, sha256: image.output_sha256 };
}

export async function closeBetaReportRetention(deps: ReportServiceDependencies, actorOwnerId: string, operationId: string) {
  if (!reportUuid(actorOwnerId) || !/^[A-Za-z0-9_-]{12,128}$/.test(operationId)) throw reportError(400, "INVALID_BETA_CLOSURE", "Beta closure operation is invalid");
  return deps.db.transaction(async (tx) => {
    const state = reportFirst<{ beta_ended_at: Date | string | null; closed_by_owner_id: string | null; close_operation_id: string | null; close_payload_hash: string | null; expires_at: Date | string | null }>(await tx.execute(sql`
      SELECT beta_ended_at,closed_by_owner_id,close_operation_id,close_payload_hash,
        CASE WHEN beta_ended_at IS NULL THEN NULL ELSE ${reportRetentionDeadline(sql.raw("beta_ended_at"))} END AS expires_at
      FROM oid_support_report_retention_state WHERE id=1 FOR UPDATE
    `));
    if (!state) throw new Error("Report retention state is missing; run the schema migration first");
    const authoritative = await deps.reportClosureState.readAuthoritativeClosure();
    if (state.beta_ended_at) {
      const betaEndedAt = asIso(state.beta_ended_at);
      const payloadHash = reportHash({ action: "close_beta_and_start_report_retention_v1", actorOwnerId, operationId, betaEndedAt });
      if (state.close_operation_id !== operationId || state.close_payload_hash !== payloadHash || state.closed_by_owner_id !== actorOwnerId) {
        throw reportError(409, "BETA_ALREADY_CLOSED", "Beta closure has already been recorded and cannot be changed");
      }
      if (authoritative.betaEndedAt === null) {
        await deps.reportClosureState.persistAuthoritativeClosure({ betaEndedAt, sourceEvidenceSha256: payloadHash });
      } else if (authoritative.betaEndedAt !== betaEndedAt || authoritative.sourceEvidenceSha256 !== payloadHash) {
        throw new Error("Database and authoritative beta report closure state do not match");
      }
      return { betaEndedAt: asIso(state.beta_ended_at), expiresAt: asIso(state.expires_at!), replayed: true };
    }
    if (authoritative.betaEndedAt !== null) {
      const betaEndedAt = authoritative.betaEndedAt;
      const payloadHash = reportHash({ action: "close_beta_and_start_report_retention_v1", actorOwnerId, operationId, betaEndedAt });
      if (authoritative.sourceEvidenceSha256 !== payloadHash) {
        throw reportError(409, "BETA_ALREADY_CLOSED", "Authoritative beta closure has already been recorded and cannot be changed");
      }
      const reconciled = reportFirst<{ beta_ended_at: Date | string; expires_at: Date | string }>(await tx.execute(sql`
        UPDATE oid_support_report_retention_state SET beta_ended_at=${betaEndedAt}::timestamptz,closed_by_owner_id=${actorOwnerId}::uuid,
          close_operation_id=${operationId},close_payload_hash=${payloadHash}
        WHERE id=1 AND beta_ended_at IS NULL
        RETURNING beta_ended_at,${reportRetentionDeadline(sql.raw("beta_ended_at"))} AS expires_at
      `));
      if (!reconciled) throw reportError(409, "BETA_ALREADY_CLOSED", "Beta closure has already been recorded");
      return { betaEndedAt: asIso(reconciled.beta_ended_at), expiresAt: asIso(reconciled.expires_at), replayed: true };
    }
    const clock = reportFirst<{ beta_ended_at: Date | string }>(await tx.execute(sql`SELECT clock_timestamp() AS beta_ended_at`));
    if (!clock) throw new Error("Database clock is unavailable for beta report closure");
    const betaEndedAt = asIso(clock.beta_ended_at);
    const payloadHash = reportHash({ action: "close_beta_and_start_report_retention_v1", actorOwnerId, operationId, betaEndedAt });
    // The operator file commits first; a crash before the DB update is reconciled on the same operation retry.
    await deps.reportClosureState.persistAuthoritativeClosure({ betaEndedAt, sourceEvidenceSha256: payloadHash });
    const ended = reportFirst<{ beta_ended_at: Date | string; expires_at: Date | string }>(await tx.execute(sql`
      UPDATE oid_support_report_retention_state SET beta_ended_at=${betaEndedAt}::timestamptz,closed_by_owner_id=${actorOwnerId}::uuid,
        close_operation_id=${operationId},close_payload_hash=${payloadHash}
      WHERE id=1 AND beta_ended_at IS NULL
      RETURNING beta_ended_at,${reportRetentionDeadline(sql.raw("beta_ended_at"))} AS expires_at
    `));
    if (!ended) throw reportError(409, "BETA_ALREADY_CLOSED", "Beta closure has already been recorded");
    return { betaEndedAt: asIso(ended.beta_ended_at), expiresAt: asIso(ended.expires_at), replayed: false };
  });
}

export async function getReportRetentionStatus(deps: ReportServiceDependencies) {
  const state = await readRetentionState(deps.db, deps);
  const pending = reportFirst<{ pending: number; failed: number }>(await deps.db.execute(sql`
    SELECT count(*) FILTER (WHERE purge_status='pending')::int AS pending,count(*) FILTER (WHERE purge_status='failed')::int AS failed
    FROM oid_support_report_deletion_receipt
  `));
  const orphan = reportFirst<{ pending: number; failed: number }>(await deps.db.execute(sql`
    SELECT count(*) FILTER (WHERE status='pending')::int AS pending,count(*) FILTER (WHERE status='failed')::int AS failed
    FROM oid_support_upload_gc_receipt
  `));
  return {
    betaEndedAt: state.beta_ended_at ? asIso(state.beta_ended_at) : null,
    expiresAt: state.expires_at ? asIso(state.expires_at) : null,
    expired: state.expired,
    reportDeletionReceipts: { pending: pending?.pending ?? 0, failed: pending?.failed ?? 0 },
    uploadDeletionReceipts: { pending: orphan?.pending ?? 0, failed: orphan?.failed ?? 0 }
  };
}

async function recordOrphanDeletion(tx: ReportTransaction, upload: StoredUploadRow, reason: "unlinked_expired" | "failed_upload" | "interrupted_processing") {
  await tx.execute(sql`
    INSERT INTO oid_support_upload_gc_receipt(id,storage_key,status,cleaned_at,reason,reserved_bytes,bytes_removed,last_error_code)
    VALUES (${randomUUID()}::uuid,${upload.storage_key ?? null}::uuid,${upload.storage_key ? "pending" : "complete"},
      clock_timestamp(),${reason},${upload.storage_key ? upload.output_bytes ?? upload.reserved_output_bytes : 0},0,NULL)
  `);
}

async function sweepUnlinkedUploads(deps: ReportServiceDependencies): Promise<number> {
  const expired = await deps.db.transaction(async (tx) => {
    const rows = reportRows<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE report_id IS NULL AND (
        expires_at<=clock_timestamp() OR (status='processing' AND updated_at<clock_timestamp()-interval '10 minutes') OR status='failed'
      ) ORDER BY created_at LIMIT 100 FOR UPDATE SKIP LOCKED
    `));
    for (const upload of rows) {
      const reason = upload.status === "processing" ? "interrupted_processing" : upload.status === "failed" ? "failed_upload" : "unlinked_expired";
      await recordOrphanDeletion(tx, upload, reason);
      await tx.execute(sql`DELETE FROM oid_support_image_upload WHERE id=${upload.id}::uuid AND report_id IS NULL`);
    }
    return rows;
  });
  for (const upload of expired) {
    const gc = reportFirst<{ id: string; reserved_bytes: number }>(await deps.db.execute(sql`
      SELECT id,reserved_bytes FROM oid_support_upload_gc_receipt WHERE storage_key=${upload.storage_key ?? null}::uuid AND status='pending'
      ORDER BY cleaned_at DESC LIMIT 1
    `));
    // Failed attempts retain the opaque storage key in the GC receipt for retry.
    if (!gc) continue;
    const deletion = upload.storage_key ? await deleteImageFile(deps, upload.storage_key) : { deleted: true, bytesRemoved: 0 };
    await deps.db.execute(sql`
      UPDATE oid_support_upload_gc_receipt SET status=${deletion.deleted ? "complete" : "failed"},cleaned_at=clock_timestamp(),
        storage_key=${deletion.deleted ? null : upload.storage_key}::uuid,reserved_bytes=${deletion.deleted ? 0 : gc?.reserved_bytes ?? 0},
        bytes_removed=${deletion.bytesRemoved},last_error_code=${deletion.deleted ? null : "STORAGE_DELETE_FAILED"}
      WHERE id=${gc.id}::uuid
    `);
  }
  const retryReceipts = reportRows<{ id: string; storage_key: string }>(await deps.db.execute(sql`
    SELECT id,storage_key FROM oid_support_upload_gc_receipt WHERE status IN ('pending','failed') AND storage_key IS NOT NULL ORDER BY cleaned_at LIMIT 100
  `));
  for (const receipt of retryReceipts) {
    const deletion = await deleteImageFile(deps, receipt.storage_key);
    await deps.db.execute(sql`
      UPDATE oid_support_upload_gc_receipt SET status=${deletion.deleted ? "complete" : "failed"},cleaned_at=clock_timestamp(),
        storage_key=${deletion.deleted ? null : receipt.storage_key}::uuid,reserved_bytes=CASE WHEN ${deletion.deleted} THEN 0 ELSE reserved_bytes END,
        bytes_removed=${deletion.bytesRemoved},last_error_code=${deletion.deleted ? null : "STORAGE_DELETE_FAILED"}
      WHERE id=${receipt.id}::uuid
    `);
  }
  return expired.length;
}

async function deleteExpiredReports(deps: ReportServiceDependencies): Promise<number> {
  const prepared = await deps.db.transaction(async (tx) => {
    const state = await readRetentionState(tx, deps);
    if (!state.expired || !state.beta_ended_at || !state.expires_at) return { reports: [] as Array<{ id: string; keys: string[] }>, unlinked: [] as StoredUploadRow[] };
    await tx.execute(sql`DELETE FROM oid_support_image_input_usage`);
    const reports = reportRows<{ id: string }>(await tx.execute(sql`SELECT id FROM oid_support_report ORDER BY id LIMIT 200 FOR UPDATE SKIP LOCKED`));
    const pendingReports: Array<{ id: string; keys: string[] }> = [];
    for (const report of reports) {
      const images = reportRows<{ storage_key: string | null; output_bytes: number | null }>(await tx.execute(sql`
        SELECT storage_key,output_bytes FROM oid_support_image_upload WHERE report_id=${report.id}::uuid AND status='attached' ORDER BY id FOR UPDATE
      `));
      if (images.some((image) => !image.storage_key || image.output_bytes === null)) throw new Error("Attached report screenshot is missing durable storage metadata");
      const keys = images.map((image) => image.storage_key!);
      const sizes = images.map((image) => image.output_bytes!);
      const count = images.length;
      // Persist the non-content tombstone and file deletion locators before the report FK cascade removes upload metadata.
      await tx.execute(reportDeletionReceiptStatement({ reportId: report.id, betaEndedAt: asIso(state.beta_ended_at),
        expiresAt: asIso(state.expires_at), imageCount: count, storageKeys: keys, storageBytes: sizes }));
      await tx.execute(sql`DELETE FROM oid_support_report WHERE id=${report.id}::uuid`);
      pendingReports.push({ id: report.id, keys });
    }
    const unlinked = reportRows<StoredUploadRow>(await tx.execute(sql`
      SELECT * FROM oid_support_image_upload WHERE report_id IS NULL ORDER BY created_at LIMIT 500 FOR UPDATE SKIP LOCKED
    `));
    for (const upload of unlinked) {
      const reason = upload.status === "processing" ? "interrupted_processing" : upload.status === "failed" ? "failed_upload" : "unlinked_expired";
      await recordOrphanDeletion(tx, upload, reason);
      await tx.execute(sql`DELETE FROM oid_support_image_upload WHERE id=${upload.id}::uuid AND report_id IS NULL`);
    }
    return { reports: pendingReports, unlinked };
  });
  await processReportDeletionReceipts(deps);
  for (const upload of prepared.unlinked) {
    const gc = reportFirst<{ id: string; reserved_bytes: number }>(await deps.db.execute(sql`
      SELECT id,reserved_bytes FROM oid_support_upload_gc_receipt WHERE storage_key=${upload.storage_key ?? null}::uuid AND status='pending'
      ORDER BY cleaned_at DESC LIMIT 1
    `));
    if (!gc) continue;
    const deletion = upload.storage_key ? await deleteImageFile(deps, upload.storage_key) : { deleted: true, bytesRemoved: 0 };
    await deps.db.execute(sql`
      UPDATE oid_support_upload_gc_receipt SET status=${deletion.deleted ? "complete" : "failed"},cleaned_at=clock_timestamp(),
        storage_key=${deletion.deleted ? null : upload.storage_key}::uuid,reserved_bytes=${deletion.deleted ? 0 : gc.reserved_bytes},
        bytes_removed=${deletion.bytesRemoved},last_error_code=${deletion.deleted ? null : "STORAGE_DELETE_FAILED"} WHERE id=${gc.id}::uuid
    `);
  }
  return prepared.reports.length;
}

async function processReportDeletionReceipts(deps: ReportServiceDependencies): Promise<void> {
  const receipts = reportRows<{ report_id: string; pending_storage_keys: string[] }>(await deps.db.execute(sql`
    SELECT report_id,pending_storage_keys FROM oid_support_report_deletion_receipt
    WHERE purge_status IN ('pending','failed') ORDER BY deleted_at LIMIT 100
  `));
  for (const receipt of receipts) {
    let failed = false;
    for (const key of receipt.pending_storage_keys) {
      const deletion = await deleteImageFile(deps, key);
      if (!deletion.deleted) {
        failed = true;
        continue;
      }
      await deps.db.execute(sql`
        UPDATE oid_support_report_deletion_receipt SET
          pending_storage_bytes=coalesce(ARRAY(
            SELECT storage_bytes FROM unnest(pending_storage_keys,pending_storage_bytes) WITH ORDINALITY AS storage_item(storage_key,storage_bytes,ordinal)
            WHERE storage_item.storage_key<>${key}::uuid ORDER BY storage_item.ordinal
          ),'{}'::integer[]),pending_storage_keys=array_remove(pending_storage_keys,${key}::uuid),
          last_attempt_at=clock_timestamp(),last_error_code=NULL WHERE report_id=${receipt.report_id}::uuid
      `);
    }
    await deps.db.execute(sql`
      UPDATE oid_support_report_deletion_receipt SET purge_status=CASE WHEN cardinality(pending_storage_keys)=0 THEN 'complete' ELSE ${failed ? "failed" : "pending"} END,
        last_attempt_at=clock_timestamp(),last_error_code=CASE WHEN cardinality(pending_storage_keys)=0 THEN NULL WHEN ${failed} THEN 'STORAGE_DELETE_FAILED' ELSE last_error_code END
      WHERE report_id=${receipt.report_id}::uuid
    `);
  }
}

/** Run on startup and periodically; expired content is deleted before HTTP reads are served. */
export async function runReportRetentionCleanup(deps: ReportServiceDependencies): Promise<{ reportsDeleted: number; uploadsCleaned: number }> {
  const uploadsCleaned = await sweepUnlinkedUploads(deps);
  const reportsDeleted = await deleteExpiredReports(deps);
  await processReportDeletionReceipts(deps);
  await deps.db.execute(sql`DELETE FROM oid_support_image_input_usage WHERE received_at<=clock_timestamp()-interval '24 hours'`);
  return { reportsDeleted, uploadsCleaned };
}

export async function runReportHousekeeping(deps: ReportServiceDependencies): Promise<void> {
  await runReportRetentionCleanup(deps);
}

export const reportPolicy = {
  maxTitleChars: REPORT_TITLE_MAX,
  maxBodyChars: REPORT_BODY_MAX,
  maxRequestBytes: REPORT_TEXT_BODY_LIMIT_BYTES,
  reportsPerMinutePerPrincipal: REPORTS_PER_MINUTE_PER_PRINCIPAL,
  reportsPerHourPerOwner: REPORTS_PER_HOUR_PER_OWNER,
  maxImagesPerReport: REPORT_IMAGE_MAX_PER_REPORT,
  maxImageInputBytes: REPORT_IMAGE_MAX_INPUT_BYTES,
  maxImageOutputBytes: REPORT_IMAGE_MAX_OUTPUT_BYTES,
  maxImagePixels: REPORT_IMAGE_MAX_PIXELS,
  ownerStageBytes: REPORT_OWNER_STAGE_LIMIT,
  ownerRollingInputBytes: REPORT_OWNER_ROLLING_INPUT_LIMIT,
  totalImageStorageBytes: REPORT_TOTAL_STORAGE_LIMIT,
  reportRetentionDays: REPORT_RETENTION_DAYS
} as const;
