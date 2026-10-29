import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, readFile, readdir, realpath, statfs, writeFile } from "node:fs/promises";
import { basename, isAbsolute, parse, relative, resolve, sep, join } from "node:path";
import { test } from "node:test";
import type { TestContext } from "node:test";
import { sql, type SQL } from "drizzle-orm";
import multipart from "@fastify/multipart";
import Fastify from "fastify";
import postgres from "postgres";
import sharp from "sharp";
import type { FastifyRequest } from "fastify";
import type { AgentPrincipal } from "./agents.js";
import type { OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import { HttpError } from "./http-error.js";
import {
  createReportClosureStateStore,
  initializeReportClosureStateFile,
  REPORT_CLOSURE_STATE_SCHEMA
} from "./report-closure-state.js";
import { reportHash, reportRetentionDeadline } from "./report-db.js";
import { registerSupportReportRoutes, type SupportReportRouteDependencies } from "./report-routes.js";
import { REPORT_IMAGE_MAX_INPUT_BYTES } from "./report-images.js";
import { runReportRetentionCleanup, type ReportServiceDependencies } from "./report-service.js";

const optIn = process.env.OID_REPORT_LIFECYCLE_PG === "true";
const ACCEPTANCE_DATABASE = /^oid_acceptance_[a-f0-9]{32}$/;
const BASE_DATABASE = "owner_identity";
const CAPTURE_BASE = "/local-report-captures";
const ROLLING_INPUT_LIMIT = 75 * 1024 * 1024;
const STAGING_IMAGE_LIMIT = 3;
const CHUNK_BYTES = 24 * 1024;
const RETENTION_SECONDS = 2_592_000;
const RETENTION_MS = RETENTION_SECONDS * 1_000;
const TEST_TIMEOUT_MS = 240_000;
const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

type JsonRecord = Record<string, unknown>;
type TestHttpResponse = {
  status: number;
  errorCode: string | null;
  contentType: string;
  json: unknown;
  bytes: Buffer;
};
type FixtureOwner = { kind: "owner"; key: "owner-a" | "owner-b"; id: string };
type FixtureAgent = { kind: "agent"; key: "agent-a" | "agent-b"; token: string; principal: AgentPrincipal };
type FixtureActor = FixtureOwner | FixtureAgent;
type Snapshot = { counts: Record<string, number>; sha256: string };

function first<T>(result: unknown): T {
  const rows = result as T[];
  if (!Array.isArray(rows) || rows.length === 0) throw new Error("report_lifecycle_expected_row_missing");
  return rows[0]!;
}

function requireAcceptanceUrl(raw: string | undefined, role: "oid_owner" | "oid_observer"): URL {
  if (!raw) throw new Error("report_lifecycle_database_url_missing");
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("report_lifecycle_database_url_invalid"); }
  if (url.protocol !== "postgres:" || url.hostname !== "postgres" || url.username !== role ||
      url.pathname !== `/${BASE_DATABASE}` || url.search || url.hash) {
    throw new Error("report_lifecycle_database_endpoint_rejected");
  }
  return url;
}

function databaseUrl(base: URL, databaseName: string): URL {
  if (!ACCEPTANCE_DATABASE.test(databaseName)) throw new Error("report_lifecycle_database_identity_rejected");
  const result = new URL(base.href);
  result.pathname = `/${databaseName}`;
  return result;
}

async function readonlyRows<T>(database: OwnerDatabase, statement: SQL<unknown>): Promise<T[]> {
  return database.transaction(async (tx) => {
    const identity = first<{ role: string; read_only: string }>(await tx.execute(sql`
      SELECT current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.equal(identity.role, "oid_observer", "every lifecycle observer query uses oid_observer");
    assert.equal(identity.read_only, "on", "every lifecycle observer query is in a read-only transaction");
    return tx.execute(statement) as unknown as T[];
  }, { accessMode: "read only" });
}

async function oneReadonly<T>(database: OwnerDatabase, statement: SQL<unknown>): Promise<T> {
  return first<T>(await readonlyRows<T>(database, statement));
}

async function verifyNoSymlinkPath(path: string): Promise<void> {
  const absolute = resolve(path);
  let current = parse(absolute).root;
  for (const component of absolute.slice(current.length).split(sep).filter(Boolean)) {
    current = resolve(current, component);
    const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error("report_lifecycle_path_has_symlink");
    if (current !== absolute && !info.isDirectory()) throw new Error("report_lifecycle_path_parent_invalid");
  }
}

async function expectMissingPath(path: string): Promise<void> {
  try {
    await lstat(path);
    throw new Error("report_lifecycle_capture_path_already_exists");
  } catch (error) {
    if (error instanceof Error && error.message === "report_lifecycle_capture_path_already_exists") throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function volumeHeadroom(path: string): Promise<{ freeBytes: number; totalBytes: number; freePercent: number }> {
  const info = await statfs(path, { bigint: true });
  const free = info.bavail * info.bsize;
  const total = info.blocks * info.bsize;
  const minimumFree = 2n * 1024n * 1024n * 1024n;
  const twentyPercent = (total * 20n) / 100n;
  const required = minimumFree > twentyPercent ? minimumFree : twentyPercent;
  if (free < required) throw new Error("report_lifecycle_named_volume_reserve_below_20_percent");
  return {
    freeBytes: Number(free),
    totalBytes: Number(total),
    freePercent: Number((free * 10_000n) / total) / 100
  };
}

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function responseCode(response: TestHttpResponse): string | null {
  const error = asRecord(asRecord(response.json).error);
  return typeof error.code === "string" ? error.code : null;
}

function requireStatus(response: TestHttpResponse, status: number, code?: string): void {
  assert.equal(response.status, status, "loopback HTTP status must match the report contract");
  if (code !== undefined) assert.equal(response.errorCode, code, "loopback HTTP error code must match the report contract");
}

function opId(): string { return randomUUID().replaceAll("-", ""); }

async function captureFilesFingerprint(privateDataDir: string): Promise<Snapshot> {
  const imageRoot = join(privateDataDir, "reports", "images");
  let entries: string[];
  try { entries = await readdir(imageRoot); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") entries = [];
    else throw error;
  }
  entries.sort();
  const details: Array<{ name: string; bytes: number; sha256: string }> = [];
  for (const name of entries) {
    const target = join(imageRoot, name);
    const info = await lstat(target);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error("report_lifecycle_storage_entry_not_regular");
    const bytes = await readFile(target);
    details.push({ name, bytes: bytes.length, sha256: sha(bytes) });
  }
  const encoded = JSON.stringify(details);
  return { counts: { files: details.length, bytes: details.reduce((sum, item) => sum + item.bytes, 0) }, sha256: sha(encoded) };
}

const REPORT_SNAPSHOT_QUERY = sql.raw(`
SELECT
  (SELECT count(*)::int FROM oid_support_report) AS reports,
  (SELECT count(*)::int FROM oid_support_report_audit) AS audits,
  (SELECT count(*)::int FROM oid_support_image_upload) AS uploads,
  (SELECT count(*)::int FROM oid_support_image_chunk) AS chunks,
  (SELECT count(*)::int FROM oid_support_image_input_usage) AS usage_rows,
  (SELECT coalesce(sum(input_bytes),0)::bigint FROM oid_support_image_input_usage) AS usage_bytes,
  (SELECT count(*)::int FROM oid_support_report_deletion_receipt) AS deletion_receipts,
  (SELECT count(*)::int FROM oid_support_upload_gc_receipt) AS upload_gc_receipts,
  (SELECT count(*)::int FROM oid_support_report_rate) AS rate_limits,
  (SELECT count(*)::int FROM oid_support_image_upload WHERE status='attached') AS attached_images,
  (SELECT count(*)::int FROM oid_support_image_upload WHERE status='ready' AND report_id IS NULL) AS ready_unlinked_images,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,owner_id::text,agent_id::text,source,reporter_kind,reporter_id::text,
      operation_id,payload_hash,status,revision::text,created_at::text,updated_at::text),E'\\n' ORDER BY id::text),''))
    FROM oid_support_report) AS report_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,report_id::text,actor_owner_id::text,actor_agent_id::text,
      operation_id,payload_hash,event_type,revision::text,metadata::text),E'\\n' ORDER BY id::text),''))
    FROM oid_support_report_audit) AS audit_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,owner_id::text,uploader_kind,uploader_id::text,operation_id,
      payload_hash,expected_sha256,expected_input_bytes::text,input_bytes::text,output_sha256,status,report_id::text,
      storage_key::text,expires_at::text),E'\\n' ORDER BY id::text),''))
    FROM oid_support_image_upload) AS upload_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',upload_id::text,sequence::text,sha256,octet_length(bytes)::text),
      E'\\n' ORDER BY upload_id::text,sequence),'')) FROM oid_support_image_chunk) AS chunk_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',upload_id::text,sequence::text,owner_id::text,input_bytes::text,
      received_at::text),E'\\n' ORDER BY upload_id::text,sequence),'')) FROM oid_support_image_input_usage) AS usage_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',report_id::text,beta_ended_at::text,expires_at::text,image_count::text,
      pending_storage_keys::text,pending_storage_bytes::text,purge_status,last_error_code),E'\\n' ORDER BY report_id::text),''))
    FROM oid_support_report_deletion_receipt) AS deletion_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,storage_key::text,status,reason,reserved_bytes::text,
      bytes_removed::text,last_error_code),E'\\n' ORDER BY id::text),'')) FROM oid_support_upload_gc_receipt) AS gc_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',key,window_start::text,request_count::text,updated_at::text),
      E'\\n' ORDER BY key),'')) FROM oid_support_report_rate) AS rate_rows_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,beta_ended_at::text,closed_by_owner_id::text,
      close_operation_id,close_payload_hash),E'\\n' ORDER BY id),'')) FROM oid_support_report_retention_state) AS retention_rows_hash
`);

async function reportSnapshot(observer: OwnerDatabase): Promise<Snapshot> {
  const row = first<Record<string, unknown>>(await readonlyRows(observer, REPORT_SNAPSHOT_QUERY));
  const countNames = ["reports", "audits", "uploads", "chunks", "usage_rows", "deletion_receipts",
    "upload_gc_receipts", "rate_limits", "attached_images", "ready_unlinked_images"];
  const counts = Object.fromEntries(countNames.map((name) => [name, Number(row[name] ?? 0)]));
  counts.usage_bytes = Number(row.usage_bytes ?? 0);
  const hashes = Object.fromEntries(Object.entries(row).filter(([name]) => name.endsWith("_hash")));
  return { counts, sha256: sha(JSON.stringify({ counts, hashes })) };
}

const PRESERVATION_QUERY = sql.raw(`
SELECT
  (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
  (SELECT count(*)::int FROM oid_run_task) AS tasks,
  (SELECT count(*)::int FROM oid_run_task_action) AS actions,
  (SELECT count(*)::int FROM oid_run_event) AS run_events,
  (SELECT count(*)::int FROM oid_run_task_closure) AS task_closures,
  (SELECT count(*)::int FROM oid_run_task_evaluation) AS evaluations,
  (SELECT count(*)::int FROM oid_ranked_run_handoff) AS ranked_handoffs,
  (SELECT count(*)::int FROM oid_ranked_verified_result) AS ranked_results,
  (SELECT count(*)::int FROM oid_ranked_best_result) AS ranked_best_results,
  (SELECT count(*)::int FROM oid_bonus_code) AS bonus_codes,
  (SELECT count(*)::int FROM oid_bonus_code_redemption) AS bonus_redemptions,
  (SELECT count(*)::int FROM oid_bonus_code_claim_operation) AS bonus_claim_operations,
  (SELECT count(*)::int FROM oid_bonus_grant) AS bonus_grants,
  (SELECT count(*)::int FROM oid_ledger_operation) AS ledger_operations,
  (SELECT count(*)::int FROM oid_ledger_entry) AS ledger_entries,
  (SELECT count(*)::int FROM oid_ledger_audit) AS ledger_audits,
  md5(
    coalesce((SELECT string_agg(concat_ws('|',id::text,intent_id::text,owner_id::text,agent_id::text,mode,
      task_ids::text,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,status,
      quote_price_units::text,cash_ceiling_units::text,queued_at::text,queue_deadline::text,started_at::text,
      overall_deadline::text,finished_at::text,terminal_reason),E'\\n' ORDER BY id::text) FROM oid_benchmark_run),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',run_id::text,task_index::text,task_id,status,snapshot_json::text,
      started_at::text,deadline_at::text,finished_at::text,result_json::text),E'\\n' ORDER BY run_id::text,task_index)
      FROM oid_run_task),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,run_id::text,task_index::text,operation_id,payload_hash,
      reason,answer_json::text,action_cutoff_sequence::text,actor_kind,owner_id::text,agent_id::text),
      E'\\n' ORDER BY id::text) FROM oid_run_task_closure),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',run_id::text,task_index::text,closure_id::text,task_id,release_identity,
      manifest_hash,case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence::text,
      result_json::text,input_json::text),E'\\n' ORDER BY run_id::text,task_index) FROM oid_run_task_evaluation),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',run_id::text,sequence::text,source,event_type,payload_hash,payload_json::text),
      E'\\n' ORDER BY run_id::text,sequence) FROM oid_run_event),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',run_id::text,benchmark_version,manifest_hash,version_snapshot_hash,
      aggregate_hash,completion_event_hash,handoff_hash,handoff_json::text),E'\\n' ORDER BY run_id::text)
      FROM oid_ranked_run_handoff),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',run_id::text,benchmark_version,aggregate_hash,aggregate_json::text,
      version_snapshot_hash,version_snapshot_json::text),E'\\n' ORDER BY run_id::text) FROM oid_ranked_verified_result),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',benchmark_version,agent_id::text,run_id::text,updated_at::text),
      E'\\n' ORDER BY benchmark_version,agent_id::text) FROM oid_ranked_best_result),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,issuer_owner_id::text,label,kind,amount_units::text,
      maximum_uses::text,used_count::text,verifier_hash,issue_operation_id,issue_payload_hash,disabled_at::text),
      E'\\n' ORDER BY id::text) FROM oid_bonus_code),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,code_id::text,owner_id::text,bonus_grant_id::text,
      financial_operation_id),E'\\n' ORDER BY id::text) FROM oid_bonus_code_redemption),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',owner_id::text,operation_id,code_id::text,redemption_id::text,payload_hash),
      E'\\n' ORDER BY owner_id::text,operation_id) FROM oid_bonus_code_claim_operation),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,owner_id::text,amount_units::text,issued_by_owner_id::text,
      reason,operation_id,created_at::text,expires_at::text),E'\\n' ORDER BY id::text) FROM oid_bonus_grant),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,actor_owner_id::text,subject_owner_id::text,operation_id,
      action,payload_hash,response_json::text),E'\\n' ORDER BY id::text) FROM oid_ledger_operation),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,owner_id::text,actor_owner_id::text,bonus_grant_id::text,
      operation_id,entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text,
      expired_delta_units::text,reason,created_at::text),E'\\n' ORDER BY id::text) FROM oid_ledger_entry),'') || E'\\n' ||
    coalesce((SELECT string_agg(concat_ws('|',id::text,event_type,operation_id,actor_owner_id::text,
      subject_owner_id::text,metadata::text,created_at::text),E'\\n' ORDER BY id::text) FROM oid_ledger_audit),'')
  ) AS rows_digest
`);

async function preservationSnapshot(observer: OwnerDatabase): Promise<Snapshot> {
  const row = first<Record<string, unknown>>(await readonlyRows(observer, PRESERVATION_QUERY));
  const countNames = ["runs", "tasks", "actions", "run_events", "task_closures", "evaluations", "ranked_handoffs",
    "ranked_results", "ranked_best_results", "bonus_codes", "bonus_redemptions", "bonus_claim_operations",
    "bonus_grants", "ledger_operations", "ledger_entries", "ledger_audits"];
  const counts = Object.fromEntries(countNames.map((name) => [name, Number(row[name] ?? 0)]));
  return { counts, sha256: sha(JSON.stringify({ counts, rowsDigest: row.rows_digest })) };
}

async function createPng(color: { r: number; g: number; b: number }): Promise<Buffer> {
  return sharp({ create: { width: 8, height: 8, channels: 3, background: color } }).png().toBuffer();
}

function agentFixture(ownerId: string, agentId: string, resource: string): AgentPrincipal {
  return {
    ownerId,
    agentId,
    grantId: randomUUID(),
    credentialId: randomUUID(),
    resource,
    role: "agent",
    accessGeneration: 1,
    accessRevision: 1,
    policyRevision: 1,
    permissions: { training: true, ranked: true, forumMessages: true, customTopics: true }
  };
}

function safeFailure(phase: string, error?: unknown): JsonRecord {
  const failure: JsonRecord = { phase, code: "REPORT_LIFECYCLE_PROBE_FAILED" };
  if (!(error instanceof Error)) return failure;
  if (/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(error.name)) failure.errorName = error.name;
  const driverCode = (error as Error & { code?: unknown }).code;
  if (typeof driverCode === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(driverCode)) failure.errorCode = driverCode;
  for (const line of (error.stack ?? "").split(/\r?\n/).slice(1)) {
    const match = line.match(/report-lifecycle\.pg\.test\.(?:ts|js):(\d+):(\d+)/);
    if (match) {
      failure.testSourceLine = Number(match[1]);
      break;
    }
  }
  return failure;
}

test("report SC024 upload limits and SC026 exact retention purge over isolated PostgreSQL/loopback HTTP", {
  skip: !optIn,
  timeout: TEST_TIMEOUT_MS
}, async (t: TestContext) => {
  const artifact: JsonRecord = {
    schemaVersion: "report-lifecycle-regression/v1",
    evidenceBoundary: "isolated_local_postgres_files_loopback_http",
    fixtureType: "synthetic_rows_are_preservation_sentinels_not_benchmark_acceptance",
    startedAt: new Date().toISOString(),
    preflight: {},
    fixtures: {},
    sc024: {},
    sc026: {},
    steps: []
  };
  let phase = "preflight";
  let captureRoot = "";
  let artifactPath = "";
  let ownerDb: ReturnType<typeof createDatabase> | undefined;
  let observerDb: ReturnType<typeof createDatabase> | undefined;
  let baseOwner: ReturnType<typeof postgres> | undefined;
  let baseObserverDb: ReturnType<typeof createDatabase> | undefined;
  let app: ReturnType<typeof Fastify> | undefined;
  let publicOrigin = "";
  let reportDependencies: ReportServiceDependencies | undefined;
  let ownerA: FixtureOwner | undefined;
  let ownerB: FixtureOwner | undefined;
  let agentA: FixtureAgent | undefined;
  let agentB: FixtureAgent | undefined;
  let observer: OwnerDatabase | undefined;
  let syntheticReportId = "";
  let spareUploadId = "";
  let attachedImageIds: string[] = [];
  let attachedImageHashes: string[] = [];
  let retentionDeadline: Date | undefined;
  let sc024Passed = false;
  let subtestFailure = false;

  const recordStep = (name: string, details: JsonRecord = {}) => {
    (artifact.steps as Array<JsonRecord>).push({ name, at: new Date().toISOString(), ...details });
  };

  async function safeHttp(path: string, method: string, body: JsonRecord | undefined, actor: FixtureActor, admin = false): Promise<TestHttpResponse> {
    const headers: Record<string, string> = { origin: publicOrigin };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (actor.kind === "owner") headers["x-report-fixture-owner"] = actor.key;
    else headers.authorization = `Bearer ${actor.token}`;
    if (admin) headers["x-report-fixture-admin"] = "synthetic-admin";
    const response = await fetch(new URL(path, publicOrigin), {
      method,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(15_000)
    });
    const bytes = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get("content-type") ?? "";
    let json: unknown = null;
    if (contentType.toLowerCase().includes("application/json")) {
      try { json = JSON.parse(bytes.toString("utf8")) as unknown; }
      catch { throw new Error("report_lifecycle_http_json_parse_failed"); }
    }
    const error = asRecord(asRecord(json).error);
    return {
      status: response.status,
      errorCode: typeof error.code === "string" ? error.code : null,
      contentType,
      json,
      bytes
    };
  }

  async function noEffectRequest(
    name: string,
    action: () => Promise<TestHttpResponse>
  ): Promise<TestHttpResponse> {
    if (!observer || !reportDependencies) throw new Error("report_lifecycle_probe_not_ready");
    const beforeDb = await reportSnapshot(observer);
    const beforeFiles = await captureFilesFingerprint(reportDependencies.privateDataDir);
    const response = await action();
    const afterDb = await reportSnapshot(observer);
    const afterFiles = await captureFilesFingerprint(reportDependencies.privateDataDir);
    assert.deepEqual(afterDb, beforeDb, `${name}_must_not_change_durable_report_state`);
    assert.deepEqual(afterFiles, beforeFiles, `${name}_must_not_change_private_files`);
    const evidence = {
      status: response.status,
      code: response.errorCode,
      databaseUnchanged: true,
      filesUnchanged: true,
      snapshotSha256: beforeDb.sha256,
      filesSha256: beforeFiles.sha256
    };
    (artifact.sc024 as JsonRecord)[name] = evidence;
    return response;
  }

  async function beginUpload(actor: FixtureActor, bytes: Buffer, operationId = opId()): Promise<string> {
    const route = actor.kind === "owner" ? "/api/owner/report-images/uploads" : "/api/agent/report-images/uploads";
    const response = await safeHttp(route, "POST", {
      operationId,
      expectedBytes: bytes.length,
      sha256: sha(bytes),
      contentType: "image/png"
    }, actor);
    requireStatus(response, 201);
    const uploadId = asRecord(response.json).uploadId;
    assert.equal(typeof uploadId, "string", "upload begin must return an upload id");
    assert.match(uploadId as string, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    return uploadId as string;
  }

  async function sendChunk(actor: FixtureActor, uploadId: string, sequence: number, bytes: Buffer): Promise<TestHttpResponse> {
    const route = actor.kind === "owner"
      ? `/api/owner/report-images/uploads/${encodeURIComponent(uploadId)}/chunks`
      : `/api/agent/report-images/uploads/${encodeURIComponent(uploadId)}/chunks`;
    return safeHttp(route, "POST", {
      sequence,
      sha256: sha(bytes),
      dataBase64: bytes.toString("base64")
    }, actor);
  }

  async function finishUpload(actor: FixtureActor, uploadId: string): Promise<TestHttpResponse> {
    const route = actor.kind === "owner"
      ? `/api/owner/report-images/uploads/${encodeURIComponent(uploadId)}/finish`
      : `/api/agent/report-images/uploads/${encodeURIComponent(uploadId)}/finish`;
    return safeHttp(route, "POST", {}, actor);
  }

  async function uploadOwnerImage(bytes: Buffer): Promise<string> {
    if (!ownerA) throw new Error("report_lifecycle_owner_fixture_missing");
    const uploadId = await beginUpload(ownerA, bytes);
    for (let sequence = 0, offset = 0; offset < bytes.length; sequence++, offset += CHUNK_BYTES) {
      const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + CHUNK_BYTES));
      requireStatus(await sendChunk(ownerA, uploadId, sequence, chunk), 200);
    }
    requireStatus(await finishUpload(ownerA, uploadId), 200);
    return uploadId;
  }

  async function attachImage(reportId: string, imageId: string, operationId = opId()): Promise<TestHttpResponse> {
    if (!ownerA) throw new Error("report_lifecycle_owner_fixture_missing");
    return safeHttp(`/api/owner/reports/${encodeURIComponent(reportId)}/images`, "POST", {
      operationId,
      imageUploadIds: [imageId]
    }, ownerA);
  }

  async function expireUploads(ids: string[]): Promise<void> {
    if (!ownerDb || ids.length === 0) return;
    const idList = sql.join(ids.map((id) => sql`${id}::uuid`), sql`, `);
    await ownerDb.db.execute(sql`
      UPDATE oid_support_image_upload SET expires_at=clock_timestamp()-interval '1 second',updated_at=clock_timestamp()
      WHERE id IN (${idList}) AND report_id IS NULL
    `);
  }

  async function uploadStorageInfo(uploadId: string): Promise<{ storageKey: string; outputHash: string; outputBytes: number }> {
    if (!observer) throw new Error("report_lifecycle_observer_missing");
    return oneReadonly<{ storageKey: string; outputHash: string; outputBytes: number }>(observer, sql`
      SELECT storage_key::text AS "storageKey",output_sha256 AS "outputHash",output_bytes AS "outputBytes"
      FROM oid_support_image_upload WHERE id=${uploadId}::uuid AND status IN ('ready','attached')
    `);
  }

  try {
    phase = "preflight_database_and_volume_guards";
    const ownerBaseUrl = requireAcceptanceUrl(process.env.OID_DATABASE_URL, "oid_owner");
    const observerBaseUrl = requireAcceptanceUrl(process.env.OID_OBSERVER_DATABASE_URL, "oid_observer");
    if (resolve(process.env.OID_LOCAL_REPORT_CAPTURE_BASE ?? "") !== CAPTURE_BASE) {
      throw new Error("report_lifecycle_requires_the_pinned_named_capture_volume");
    }
    const captureId = randomUUID();
    const databaseName = `oid_acceptance_${captureId.replaceAll("-", "")}`;
    if (!ACCEPTANCE_DATABASE.test(databaseName)) throw new Error("report_lifecycle_generated_database_identity_invalid");
    const root = resolve(CAPTURE_BASE, databaseName);
    const privateDataDir = resolve(root, "private-data");
    const closurePath = resolve(root, "beta-report-closure-state.json");
    if (basename(root) !== databaseName || !isAbsolute(root) || !isAbsolute(privateDataDir) || !isAbsolute(closurePath) ||
        resolve(closurePath) !== resolve(root, "beta-report-closure-state.json") ||
        relative(root, privateDataDir).startsWith("..")) {
      throw new Error("report_lifecycle_capture_path_guard_failed");
    }

    await verifyNoSymlinkPath(CAPTURE_BASE);
    const baseReal = await realpath(CAPTURE_BASE);
    if (baseReal !== CAPTURE_BASE) throw new Error("report_lifecycle_named_volume_path_mismatch");
    const headroom = await volumeHeadroom(CAPTURE_BASE);
    await expectMissingPath(root);

    baseOwner = postgres(ownerBaseUrl.href, { max: 1, connect_timeout: 10 });
    const ownerIdentity = first<{ database: string; role: string; session_role: string; read_only: string }>(await baseOwner`
      SELECT current_database() AS database,current_user AS role,session_user AS session_role,
        current_setting('transaction_read_only') AS read_only
    `);
    assert.deepEqual(ownerIdentity, {
      database: BASE_DATABASE,
      role: "oid_owner",
      session_role: "oid_owner",
      read_only: "off"
    }, "the base owner connection may only create the fresh acceptance database after identity proof");

    baseObserverDb = createDatabase({ databaseUrl: observerBaseUrl.href } as OwnerIdentityConfig);
    const observerIdentity = await oneReadonly<{ database: string; role: string; session_role: string; read_only: string }>(baseObserverDb.db, sql.raw(`
      SELECT current_database() AS database,current_user AS role,session_user AS session_role,
        current_setting('transaction_read_only') AS read_only
    `));
    assert.deepEqual(observerIdentity, {
      database: BASE_DATABASE,
      role: "oid_observer",
      session_role: "oid_observer",
      read_only: "on"
    }, "the base observer must prove the read-only role before any database or file mutation");
    const observerRole = await oneReadonly<{ memberships: number; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolreplication: boolean; rolbypassrls: boolean }>(baseObserverDb.db, sql.raw(`
      SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
        (SELECT count(*)::int FROM pg_auth_members m WHERE m.member=r.oid) AS memberships
      FROM pg_roles r WHERE r.rolname='oid_observer'
    `));
    assert.deepEqual(observerRole, {
      rolsuper: false, rolcreaterole: false, rolcreatedb: false,
      rolreplication: false, rolbypassrls: false, memberships: 0
    }, "the observer role must have no elevated attributes or role memberships");

    const exists = first<{ present: boolean }>(await baseOwner`
      SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=${databaseName}) AS present
    `);
    assert.equal(exists.present, false, "the generated acceptance database must not already exist");

    captureRoot = root;
    artifactPath = resolve(root, "report-lifecycle-regression.json");
    artifact.captureId = captureId;
    artifact.database = databaseName;
    artifact.captureRoot = root;
    artifact.privateDataDir = privateDataDir;
    artifact.externalClosureStateFile = closurePath;
    artifact.preflight = {
      ownerDatabase: ownerIdentity.database,
      ownerRole: ownerIdentity.role,
      observerDatabase: observerIdentity.database,
      observerRole: observerIdentity.role,
      observerReadOnlyTransaction: observerIdentity.read_only === "on",
      observerHasNoElevatedRoleFlagsOrMemberships: observerRole.memberships === 0 && !observerRole.rolsuper && !observerRole.rolcreaterole && !observerRole.rolcreatedb && !observerRole.rolreplication && !observerRole.rolbypassrls,
      targetDatabaseAbsent: true,
      captureRootAbsent: true,
      namedVolume: CAPTURE_BASE,
      freeBytes: headroom.freeBytes,
      totalBytes: headroom.totalBytes,
      freePercent: headroom.freePercent,
      reserveFloorPercent: 20
    };
    recordStep("identity_path_database_and_20_percent_volume_preflight_passed", { freePercent: headroom.freePercent });

    phase = "create_fresh_capture_root_and_closure_file";
    await mkdir(root, { mode: 0o700 });
    await chmod(root, 0o700);
    await mkdir(privateDataDir, { mode: 0o700 });
    await chmod(privateDataDir, 0o700);
    const rootInfo = await lstat(root);
    const privateInfo = await lstat(privateDataDir);
    assert.ok(rootInfo.isDirectory() && !rootInfo.isSymbolicLink() && (rootInfo.mode & 0o077) === 0);
    assert.ok(privateInfo.isDirectory() && !privateInfo.isSymbolicLink() && (privateInfo.mode & 0o077) === 0);
    const initialClosureHash = sha("synthetic-report-lifecycle-open-closure-state-v1");
    await initializeReportClosureStateFile(closurePath, initialClosureHash);
    const closureInfo = await lstat(closurePath);
    assert.ok(closureInfo.isFile() && !closureInfo.isSymbolicLink() && (closureInfo.mode & 0o077) === 0);
    const closure = createReportClosureStateStore(closurePath);
    const openState = await closure.readAuthoritativeClosure();
    assert.equal(openState.betaEndedAt, null);
    assert.equal(openState.sourceEvidenceSha256, initialClosureHash);

    phase = "create_only_the_fresh_acceptance_database";
    await baseOwner.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
    await baseOwner.unsafe(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
    const ownerUrl = databaseUrl(ownerBaseUrl, databaseName);
    const observerUrl = databaseUrl(observerBaseUrl, databaseName);
    ownerDb = createDatabase({ databaseUrl: ownerUrl.href } as OwnerIdentityConfig);
    observerDb = createDatabase({ databaseUrl: observerUrl.href } as OwnerIdentityConfig);
    const targetOwnerIdentity = first<{ database: string; role: string; read_only: string }>(await ownerDb.client`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
    `);
    assert.deepEqual(targetOwnerIdentity, { database: databaseName, role: "oid_owner", read_only: "off" });
    const targetObserverIdentity = await oneReadonly<{ database: string; role: string; session_role: string; read_only: string }>(observerDb.db, sql.raw(`
      SELECT current_database() AS database,current_user AS role,session_user AS session_role,
        current_setting('transaction_read_only') AS read_only
    `));
    assert.deepEqual(targetObserverIdentity, {
      database: databaseName,
      role: "oid_observer",
      session_role: "oid_observer",
      read_only: "on"
    });

    phase = "migrate_only_the_new_acceptance_database";
    const migrationEnv: NodeJS.ProcessEnv = {
      ...process.env,
      OID_DATABASE_URL: ownerUrl.href,
      OID_OBSERVER_DATABASE_URL: observerUrl.href,
      OID_PRIVATE_DATA_DIR: privateDataDir,
      OID_BETA_REPORT_CLOSURE_STATE_FILE: closurePath,
      OID_PUBLIC_ORIGIN: "http://127.0.0.1:8784",
      OID_API_HOST: "127.0.0.1",
      OID_API_PORT: "8784",
      OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "false",
      OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: "false",
      OID_MCP_TRANSPORT_PROFILE: "strict-2026-07-28",
      NODE_ENV: "development"
    };
    delete migrationEnv.OID_BETA_MANIFEST_FILE;
    delete migrationEnv.OID_BETA_BEF_TASK_COORDINATOR_CONFIG;
    delete migrationEnv.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG;
    const migration = spawnSync("pnpm", ["--filter", "@web-agent-bench/owner-identity", "migrate"], {
      cwd: process.cwd(),
      env: migrationEnv,
      encoding: "utf8",
      maxBuffer: 512 * 1024
    });
    assert.equal(migration.error, undefined, "the pinned runtime must start the target-only migration command");
    assert.equal(migration.status, 0, "only the new acceptance database must migrate successfully");
    recordStep("target_database_migrated", { exitCode: migration.status });

    phase = "grant_and_prove_select_only_observer";
    await ownerDb.client.unsafe("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC");
    await ownerDb.client.unsafe("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    await ownerDb.client.unsafe("GRANT USAGE ON SCHEMA public TO oid_observer");
    await ownerDb.client.unsafe("GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer");
    await ownerDb.client.unsafe("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer");
    const grants = await oneReadonly<{ grants: number; select_only: boolean }>(observerDb.db, sql.raw(`
      SELECT count(*)::int AS grants,
        coalesce(bool_and(privilege_type='SELECT'),true) AS select_only
      FROM information_schema.role_table_grants WHERE grantee='oid_observer' AND table_schema='public'
    `));
    assert.ok(grants.grants > 0 && grants.select_only, "observer table grants must be SELECT only");
    const privilege = await oneReadonly<{ can_select: boolean; can_insert: boolean; can_update: boolean; can_delete: boolean }>(observerDb.db, sql.raw(`
      SELECT has_table_privilege('oid_observer','oid_support_report','SELECT') AS can_select,
        has_table_privilege('oid_observer','oid_support_report','INSERT') AS can_insert,
        has_table_privilege('oid_observer','oid_support_report','UPDATE') AS can_update,
        has_table_privilege('oid_observer','oid_support_report','DELETE') AS can_delete
    `));
    assert.deepEqual(privilege, { can_select: true, can_insert: false, can_update: false, can_delete: false });
    observer = observerDb.db;
    reportDependencies = { db: ownerDb.db, privateDataDir, reportClosureState: closure };
    artifact.preflight = {
      ...(artifact.preflight as JsonRecord),
      targetDatabase: databaseName,
      targetOwnerRole: targetOwnerIdentity.role,
      targetObserverRole: targetObserverIdentity.role,
      targetObserverReadOnlyTransaction: targetObserverIdentity.read_only === "on",
      observerTableGrantCount: grants.grants,
      observerTableGrantsSelectOnly: grants.select_only,
      observerCanSelectReports: privilege.can_select,
      observerCannotInsertUpdateDeleteReports: !privilege.can_insert && !privilege.can_update && !privilege.can_delete,
      privateDataMode: "0700",
      captureRootMode: "0700",
      closureFileMode: "0600"
    };
    recordStep("observer_select_only_and_capture_permissions_verified", {
      observerTableGrantCount: grants.grants,
      privateDataMode: "0700",
      closureFileMode: "0600"
    });

    phase = "seed_synthetic_principal_and_preservation_rows";
    const ownerAId = randomUUID();
    const ownerBId = randomUUID();
    const ownerAUserId = `report-lifecycle-${randomUUID()}`;
    const ownerBUserId = `report-lifecycle-${randomUUID()}`;
    const agentAId = randomUUID();
    const agentBId = randomUUID();
    const grantId = randomUUID();
    const ownerAOperationId = opId();
    const ownerBOperationId = opId();
    const agentAToken = `fixture-${randomUUID()}`;
    const agentBToken = `fixture-${randomUUID()}`;
    const fixtureRunId = randomUUID();
    const fixtureIntentId = randomUUID();
    const fixtureTaskClosureId = randomUUID();
    const grantOperationId = `report-lifecycle-${randomUUID().replaceAll("-", "")}`;
    await ownerDb.db.transaction(async (tx) => {
      await tx.execute(sql`INSERT INTO oid_auth_user(id,name,email,email_verified)
        VALUES(${ownerAUserId},'Synthetic report lifecycle owner A',${`${ownerAUserId}@example.invalid`},true)`);
      await tx.execute(sql`INSERT INTO oid_auth_user(id,name,email,email_verified)
        VALUES(${ownerBUserId},'Synthetic report lifecycle owner B',${`${ownerBUserId}@example.invalid`},true)`);
      await tx.execute(sql`INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at)
        VALUES(${ownerAId}::uuid,${ownerAUserId},'admitted',clock_timestamp()),
          (${ownerBId}::uuid,${ownerBUserId},'admitted',clock_timestamp())`);
      await tx.execute(sql`INSERT INTO oid_agent(id,owner_id,name,description)
        VALUES(${agentAId}::uuid,${ownerAId}::uuid,'Synthetic report lifecycle agent A','Isolated PG fixture'),
          (${agentBId}::uuid,${ownerBId}::uuid,'Synthetic report lifecycle agent B','Isolated PG fixture')`);

      // AICODE-NOTE: These synthetic immutable completion/credit rows are sentinels showing that report cleanup leaves unrelated grade and ledger records unchanged; they are not benchmark evidence.
      const fixtureHash = sha(`report-lifecycle-fixture-${fixtureRunId}`);
      await tx.execute(sql`INSERT INTO oid_run_launch_intent(
        id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,
        agent_policy_revision,status,created_at,expires_at,accepted_at
      ) VALUES (
        ${fixtureIntentId}::uuid,${ownerAId}::uuid,${agentAId}::uuid,${opId()},${fixtureHash},'training',ARRAY['S1']::text[],
        'fixture-only/report-lifecycle/v1','fixture-only/v1',${fixtureHash},${fixtureHash},${fixtureHash},0,0,1,1,
        'accepted',clock_timestamp()-interval '2 minutes',clock_timestamp()+interval '1 hour',clock_timestamp()
      )`);
      await tx.execute(sql`INSERT INTO oid_benchmark_run(
        id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,
        policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,
        queued_at,queue_deadline,started_at,overall_deadline,finished_at,terminal_reason
      ) VALUES (
        ${fixtureRunId}::uuid,${fixtureIntentId}::uuid,${ownerAId}::uuid,${agentAId}::uuid,'training',ARRAY['S1']::text[],
        'fixture-only/report-lifecycle/v1','fixture-only/v1',${fixtureHash},${fixtureHash},${fixtureHash},0,0,1,1,'completed',
        clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',clock_timestamp()-interval '30 seconds',
        clock_timestamp()+interval '30 minutes',clock_timestamp()-interval '1 second','fixture_only'
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task(run_id,task_index,task_id,status,snapshot_json,started_at,deadline_at,finished_at,result_json)
        VALUES(${fixtureRunId}::uuid,0,'S1','completed','{"fixtureOnly":true}'::jsonb,
          clock_timestamp()-interval '30 seconds',clock_timestamp()+interval '30 minutes',clock_timestamp()-interval '1 second',
          '{"grade":"fixture_only","creditUnits":"0"}'::jsonb)`);
      await tx.execute(sql`INSERT INTO oid_run_task_closure(
        id,run_id,task_index,operation_id,payload_hash,reason,answer_json,action_cutoff_sequence,actor_kind,owner_id,agent_id
      ) VALUES (
        ${fixtureTaskClosureId}::uuid,${fixtureRunId}::uuid,0,${opId()},${fixtureHash},'agent_finish',
        '{"fixtureOnly":true}'::jsonb,0,'coordinator',${ownerAId}::uuid,${agentAId}::uuid
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task_evaluation(
        run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,input_hash,
        result_hash,evaluator_source_hash,observation_evidence,result_json,input_json
      ) VALUES (
        ${fixtureRunId}::uuid,0,${fixtureTaskClosureId}::uuid,'S1','fixture-only/report-lifecycle/v1',
        ${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},
        '{"fixtureOnly":true}'::jsonb,'{"grade":"fixture_only","creditUnits":"0"}'::jsonb,
        '{"fixtureOnly":true}'::jsonb
      )`);
      await tx.execute(sql`INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id)
        VALUES(${grantId}::uuid,${ownerAId}::uuid,1000000,${ownerBId}::uuid,'Synthetic preservation sentinel',${grantOperationId})`);
      await tx.execute(sql`INSERT INTO oid_ledger_operation(
        id,actor_owner_id,subject_owner_id,operation_id,action,payload_hash,response_json
      ) VALUES(
        ${randomUUID()}::uuid,${ownerBId}::uuid,${ownerAId}::uuid,${grantOperationId},'bonus_grant',${fixtureHash},
        ${JSON.stringify({ fixtureOnly: true, grantId })}::jsonb
      )`);
      await tx.execute(sql`INSERT INTO oid_ledger_entry(
        id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
        available_delta_units,reserved_delta_units,expired_delta_units,reason
      ) VALUES (
        ${randomUUID()}::uuid,${ownerAId}::uuid,${ownerBId}::uuid,${grantId}::uuid,${grantOperationId},
        'bonus_grant','tester_bonus',1000000,1000000,0,0,'Synthetic preservation sentinel'
      )`);
      await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata)
        VALUES(${randomUUID()}::uuid,'bonus_granted',${grantOperationId},${ownerBId}::uuid,${ownerAId}::uuid,'{"fixtureOnly":true}'::jsonb)`);
    });

    ownerA = { kind: "owner", key: "owner-a", id: ownerAId };
    ownerB = { kind: "owner", key: "owner-b", id: ownerBId };
    const resource = "http://127.0.0.1:8784/api/agent";
    agentA = { kind: "agent", key: "agent-a", token: agentAToken, principal: agentFixture(ownerAId, agentAId, resource) };
    agentB = { kind: "agent", key: "agent-b", token: agentBToken, principal: agentFixture(ownerBId, agentBId, resource) };
    const preservationBefore = await preservationSnapshot(observerDb.db);
    assert.equal(preservationBefore.counts.runs, 1);
    assert.equal(preservationBefore.counts.evaluations, 1);
    assert.equal(preservationBefore.counts.bonus_grants, 1);
    assert.equal(preservationBefore.counts.ledger_entries, 1);
    artifact.fixtures = {
      ownerCount: 2,
      agentCount: 2,
      syntheticCompletedRunCount: preservationBefore.counts.runs,
      syntheticTaskEvaluationCount: preservationBefore.counts.evaluations,
      syntheticLedgerGrantCount: preservationBefore.counts.bonus_grants,
      syntheticLedgerEntryCount: preservationBefore.counts.ledger_entries,
      preservationBefore
    };
    reportDependencies = {
      db: ownerDb.db,
      privateDataDir: resolve(captureRoot, "private-data"),
      reportClosureState: createReportClosureStateStore(resolve(captureRoot, "beta-report-closure-state.json"))
    };

    phase = "start_real_loopback_http_routes";
    app = Fastify({ logger: false });
    await app.register(multipart, {
      limits: { fieldNameSize: 32, fieldSize: 128, fields: 4, files: 1,
        fileSize: REPORT_IMAGE_MAX_INPUT_BYTES, headerPairs: 16, parts: 5 },
      throwFileSizeLimit: false
    });
    const agentByToken = new Map([[agentAToken, agentA.principal], [agentBToken, agentB.principal]]);
    const dependencies: SupportReportRouteDependencies = {
      db: ownerDb.db,
      service: reportDependencies,
      publicOrigin: "",
      rateLimitMax: 100,
      resolveOwner: async (request: FastifyRequest) => {
        const fixture = request.headers["x-report-fixture-owner"];
        if (fixture === "owner-a" && ownerA) return { owner: { id: ownerA.id, admissionStatus: "admitted" } };
        if (fixture === "owner-b" && ownerB) return { owner: { id: ownerB.id, admissionStatus: "admitted" } };
        throw new HttpError(401, "UNAUTHORIZED", "Synthetic report fixture identity is missing");
      },
      resolveAgentPrincipal: async (bearer) => agentByToken.get(bearer),
      requireAdmin: async (request) => {
        if (request.headers["x-report-fixture-admin"] !== "synthetic-admin" || !ownerA) {
          throw new HttpError(403, "ADMIN_REQUIRED", "Synthetic report fixture administrator is missing");
        }
        return { context: { owner: { id: ownerA.id, admissionStatus: "admitted" } } };
      },
      requireOrigin: async (request) => {
        if (request.headers.origin !== dependencies.publicOrigin) throw new HttpError(403, "ORIGIN_NOT_ALLOWED", "The report fixture origin does not match");
      },
      rateLimit: async () => undefined
    };
    // The admin route uses its own configured principal callback; this header is only a synthetic test fixture.
    registerSupportReportRoutes(app, dependencies);
    publicOrigin = await app.listen({ host: "127.0.0.1", port: 0 });
    dependencies.publicOrigin = publicOrigin;
    recordStep("loopback_http_routes_listening", { host: new URL(publicOrigin).hostname });

    phase = "create_agent_report_through_loopback_http";
    const created = await safeHttp("/api/agent/reports", "POST", {
      operationId: opId(),
      title: "Synthetic report lifecycle test",
      body: "Synthetic private report body used only in this isolated lifecycle regression."
    }, agentA);
    requireStatus(created, 201);
    syntheticReportId = String(asRecord(asRecord(created.json).report).id ?? "");
    assert.match(syntheticReportId, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      "the actual agent report route must create a report in the isolated database");

    await t.test("BPC-SC-024 local quota, ordered chunk, retry, principal, orphan and concurrent cap variants", async () => {
      try {
        phase = "sc024_real_chunk_order_replay_conflict";
        const chunkImage = await createPng({ r: 23, g: 101, b: 207 });
        const chunkUploadId = await beginUpload(ownerA!, chunkImage);
        const split = Math.max(1, Math.floor(chunkImage.length / 2));
        const firstChunk = chunkImage.subarray(0, split);
        const secondChunk = chunkImage.subarray(split);
        const wrongOrder = await noEffectRequest("chunkOrderDenied", () => sendChunk(ownerA!, chunkUploadId, 1, secondChunk));
        requireStatus(wrongOrder, 409, "REPORT_IMAGE_CHUNK_ORDER");
        const firstAccepted = await sendChunk(ownerA!, chunkUploadId, 0, firstChunk);
        requireStatus(firstAccepted, 200);
        const firstAcceptedPayload = asRecord(firstAccepted.json);
        assert.equal(firstAcceptedPayload.replayed, false);
        const exactReplay = await noEffectRequest("exactChunkReplay", () => sendChunk(ownerA!, chunkUploadId, 0, firstChunk));
        requireStatus(exactReplay, 200);
        assert.equal(asRecord(exactReplay.json).replayed, true);
        const changedChunk = Buffer.from(firstChunk);
        changedChunk[0] = changedChunk[0]! ^ 0xff;
        const conflict = await noEffectRequest("conflictingChunkDenied", () => sendChunk(ownerA!, chunkUploadId, 0, changedChunk));
        requireStatus(conflict, 409, "REPORT_IMAGE_CHUNK_CONFLICT");
        const secondAccepted = await sendChunk(ownerA!, chunkUploadId, 1, secondChunk);
        requireStatus(secondAccepted, 200);
        const completed = await finishUpload(ownerA!, chunkUploadId);
        requireStatus(completed, 200);
        const finishReplay = await noEffectRequest("readyUploadFinishReplay", () => finishUpload(ownerA!, chunkUploadId));
        requireStatus(finishReplay, 200);
        assert.equal(asRecord(finishReplay.json).replayed, true);
        const firstAttached = await attachImage(syntheticReportId, chunkUploadId);
        requireStatus(firstAttached, 201);
        const firstReportImageId = chunkUploadId;

        phase = "sc024_cross_principal_upload_and_report_denials";
        const foreignAgentImage = await createPng({ r: 203, g: 31, b: 81 });
        const agentUploadId = await beginUpload(agentA!, foreignAgentImage);
        const foreignChunk = foreignAgentImage.subarray(0, Math.min(CHUNK_BYTES, foreignAgentImage.length));
        const foreignAgentChunkDenied = await noEffectRequest("foreignAgentChunkDenied", () => sendChunk(agentB!, agentUploadId, 0, foreignChunk));
        requireStatus(foreignAgentChunkDenied, 404, "REPORT_IMAGE_NOT_FOUND");
        const foreignOwnerReadDenied = await noEffectRequest("foreignOwnerReportReadDenied", () =>
          safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerB!));
        requireStatus(foreignOwnerReadDenied, 404, "REPORT_NOT_FOUND");
        const foreignAgentReadDenied = await noEffectRequest("foreignAgentReportReadDenied", () =>
          safeHttp(`/api/agent/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, agentB!));
        requireStatus(foreignAgentReadDenied, 404, "REPORT_NOT_FOUND");

        phase = "sc024_orphan_private_file_cleanup";
        const orphanImage = await createPng({ r: 30, g: 181, b: 114 });
        const orphanUploadId = await uploadOwnerImage(orphanImage);
        const orphanInfo = await uploadStorageInfo(orphanUploadId);
        const orphanPath = resolve(reportDependencies!.privateDataDir, "reports", "images", `${orphanInfo.storageKey}.webp`);
        const orphanBefore = await lstat(orphanPath);
        assert.ok(orphanBefore.isFile() && !orphanBefore.isSymbolicLink());
        const orphanHash = sha(await readFile(orphanPath));
        await expireUploads([agentUploadId, orphanUploadId]);
        const orphanCleanup = await runReportRetentionCleanup(reportDependencies!);
        assert.equal(orphanCleanup.uploadsCleaned, 2, "expired unlinked uploads must each receive orphan cleanup");
        let orphanExists = true;
        try { await lstat(orphanPath); } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") orphanExists = false;
          else throw error;
        }
        assert.equal(orphanExists, false, "orphan normalized bytes must be removed from private storage");
        const orphanReceipt = await oneReadonly<{ count: number; completed: number }>(observer!, sql`
          SELECT count(*)::int AS count,
            count(*) FILTER (WHERE status='complete' AND reason='unlinked_expired')::int AS completed
          FROM oid_support_upload_gc_receipt WHERE reason='unlinked_expired'
        `);
        assert.ok(orphanReceipt.count >= 2 && orphanReceipt.completed >= 2);
        (artifact.sc024 as JsonRecord).orphanCleanup = {
          expiredUploadsCleaned: orphanCleanup.uploadsCleaned,
          completeGcReceipts: orphanReceipt.completed,
          privateFileRemoved: !orphanExists,
          removedFileSha256: orphanHash
        };

        phase = "sc024_rolling_quota_denial";
        const quotaSeed = randomUUID().replaceAll("-", "").slice(0, 16);
        const quotaTime = first<{ at: Date }>(await ownerDb!.client`SELECT date_trunc('milliseconds',clock_timestamp()) AS at`);
        const quotaRows = Math.ceil(ROLLING_INPUT_LIMIT / CHUNK_BYTES);
        const quotaSeedBytes = quotaRows * CHUNK_BYTES;
        await ownerDb!.db.execute(sql`
          INSERT INTO oid_support_image_input_usage(upload_id,sequence,owner_id,input_bytes,received_at)
          SELECT md5(${quotaSeed} || item::text)::uuid,0,${ownerA!.id}::uuid,${CHUNK_BYTES},${quotaTime.at}::timestamptz
          FROM generate_series(1,${quotaRows}) AS item
        `);
        const saturatedUsage = await oneReadonly<{ rows: number; bytes: number | string }>(observer!, sql`
          SELECT count(*)::int AS rows,coalesce(sum(input_bytes),0)::bigint AS bytes
          FROM oid_support_image_input_usage WHERE owner_id=${ownerA!.id}::uuid AND received_at=${quotaTime.at}::timestamptz
        `);
        assert.equal(saturatedUsage.rows, quotaRows);
        assert.ok(Number(saturatedUsage.bytes) >= ROLLING_INPUT_LIMIT);
        const oneByte = Buffer.from([0x41]);
        const rollingDenied = await noEffectRequest("rollingQuotaDenied", () => safeHttp("/api/owner/report-images/uploads", "POST", {
          operationId: opId(), expectedBytes: 1, sha256: sha(oneByte), contentType: "image/png"
        }, ownerA!));
        requireStatus(rollingDenied, 429, "REPORT_IMAGE_ROLLING_QUOTA");
        await ownerDb!.db.execute(sql`
          DELETE FROM oid_support_image_input_usage WHERE owner_id=${ownerA!.id}::uuid AND received_at=${quotaTime.at}::timestamptz
        `);
        const quotaAfterFixtureRemoval = await oneReadonly<{ rows: number }>(observer!, sql`
          SELECT count(*)::int AS rows FROM oid_support_image_input_usage WHERE owner_id=${ownerA!.id}::uuid AND received_at=${quotaTime.at}::timestamptz
        `);
        assert.equal(quotaAfterFixtureRemoval.rows, 0);
        (artifact.sc024 as JsonRecord).rollingQuotaSetup = { seededRows: quotaRows, seededBytes: quotaSeedBytes, requestBytes: 1 };

        phase = "sc024_staging_quota_denial";
        const stageIds: string[] = [];
        for (let index = 0; index < STAGING_IMAGE_LIMIT; index++) {
          const response = await safeHttp("/api/owner/report-images/uploads", "POST", {
            operationId: opId(), expectedBytes: 1, sha256: sha(oneByte), contentType: "image/png"
          }, ownerA!);
          requireStatus(response, 201);
          const id = asRecord(response.json).uploadId;
          assert.equal(typeof id, "string");
          stageIds.push(id as string);
        }
        const stagingDenied = await noEffectRequest("stagingQuotaDenied", () => safeHttp("/api/owner/report-images/uploads", "POST", {
          operationId: opId(), expectedBytes: 1, sha256: sha(oneByte), contentType: "image/png"
        }, ownerA!));
        requireStatus(stagingDenied, 429, "REPORT_IMAGE_STAGING_LIMIT");
        await expireUploads(stageIds);
        const stageCleanup = await runReportRetentionCleanup(reportDependencies!);
        assert.equal(stageCleanup.uploadsCleaned, STAGING_IMAGE_LIMIT);
        const stagingRows = await oneReadonly<{ count: number }>(observer!, sql`
          SELECT count(*)::int AS count FROM oid_support_image_upload WHERE id IN (
            ${sql.join(stageIds.map((id) => sql`${id}::uuid`), sql`, `)}
          )
        `);
        assert.equal(stagingRows.count, 0);
        (artifact.sc024 as JsonRecord).stagingQuotaSetup = {
          stagingImageLimit: STAGING_IMAGE_LIMIT,
          expiredRowsCleaned: stageCleanup.uploadsCleaned
        };

        phase = "sc024_three_image_atomic_concurrent_attachment";
        const image2 = await uploadOwnerImage(await createPng({ r: 101, g: 49, b: 220 }));
        requireStatus(await attachImage(syntheticReportId, image2), 201);
        const image3 = await uploadOwnerImage(await createPng({ r: 17, g: 191, b: 80 }));
        const image4 = await uploadOwnerImage(await createPng({ r: 230, g: 99, b: 9 }));
        const raceCases = [
          { uploadId: image3, operationId: opId() },
          { uploadId: image4, operationId: opId() }
        ];
        const raceBefore = await reportSnapshot(observer!);
        const raceResponses = await Promise.all(raceCases.map((candidate) => attachImage(syntheticReportId, candidate.uploadId, candidate.operationId)));
        const raceSummary = raceResponses.map((response, index) => ({ index, status: response.status, code: response.errorCode }));
        const successfulIndex = raceResponses.findIndex((response) => response.status === 201);
        const deniedIndex = raceResponses.findIndex((response) => response.status === 409 && response.errorCode === "REPORT_IMAGE_LIMIT");
        assert.notEqual(successfulIndex, -1, "one concurrent fourth attachment must succeed");
        assert.notEqual(deniedIndex, -1, "the competing fourth attachment must be rejected at the three-image cap");
        assert.notEqual(successfulIndex, deniedIndex);
        const raceAfter = await reportSnapshot(observer!);
        assert.equal(raceAfter.counts.attached_images, 3);
        assert.equal(raceAfter.counts.ready_unlinked_images, 1);
        const winning = raceCases[successfulIndex]!;
        spareUploadId = raceCases[deniedIndex]!.uploadId;
        const retry = await noEffectRequest("successfulAttachmentReplay", () => attachImage(syntheticReportId, winning.uploadId, winning.operationId));
        requireStatus(retry, 200);
        assert.equal(asRecord(retry.json).replayed, true);
        const attachedRows = await readonlyRows<{ id: string; output_sha256: string }>(observer!, sql`
          SELECT id::text AS id,output_sha256 FROM oid_support_image_upload
          WHERE report_id=${syntheticReportId}::uuid AND status='attached' ORDER BY id::text
        `);
        attachedImageIds = attachedRows.map((row) => row.id);
        attachedImageHashes = attachedRows.map((row) => row.output_sha256);
        assert.equal(attachedRows.length, 3);
        const reportRead = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!);
        requireStatus(reportRead, 200);
        const listedImages = asRecord(asRecord(reportRead.json).report).images;
        assert.ok(Array.isArray(listedImages) && listedImages.length === 3);
        const finalFiles = await captureFilesFingerprint(reportDependencies!.privateDataDir);
        assert.equal(finalFiles.counts.files, 4, "three attached image files and one unlinked ready file must exist before closure");
        assert.deepEqual(raceBefore.counts.attached_images, 2);
        (artifact.sc024 as JsonRecord).concurrentImageCap = {
          outcomes: raceSummary,
          attachedImageCount: attachedRows.length,
          unlinkedReadyCount: raceAfter.counts.ready_unlinked_images,
          exactSuccessReplayStatus: retry.status,
          exactSuccessReplay: asRecord(retry.json).replayed === true,
          beforeDatabaseSha256: raceBefore.sha256,
          afterDatabaseSha256: raceAfter.sha256,
          filesBeforeRetention: finalFiles,
          normalizedImageSha256: attachedImageHashes
        };
        const expectedSpare = await uploadStorageInfo(spareUploadId);
        assert.ok(/^[0-9a-f]{64}$/.test(expectedSpare.outputHash));
        recordStep("sc024_loopback_and_independent_observer_passed", {
          reports: raceAfter.counts.reports,
          attachedImages: attachedRows.length,
          outputHashesRecorded: attachedImageHashes.length
        });
        sc024Passed = true;
      } catch (error) {
        subtestFailure = true;
        (artifact as JsonRecord).failure = safeFailure(phase, error);
        throw new Error("report_lifecycle_sc024_failed");
      }
    });

    if (!sc024Passed || subtestFailure) return;

    await t.test("BPC-SC-026 exact equality predicate, before/after access denial, purge receipts and grade/ledger preservation", async () => {
      try {
        phase = "sc026_exact_30_day_sql_boundary_predicate";
        const equality = await oneReadonly<{ exact_equality_is_expired: boolean; just_before_is_expired: boolean; just_after_is_expired: boolean; retention_seconds: number }>(observer!, sql`
          WITH beta AS (SELECT clock_timestamp() AS beta_ended_at),
          boundary AS (SELECT ${reportRetentionDeadline(sql.raw("beta.beta_ended_at"))} AS deadline FROM beta)
          SELECT
            (boundary.deadline>=boundary.deadline) AS exact_equality_is_expired,
            ((boundary.deadline-interval '1 microsecond')>=boundary.deadline) AS just_before_is_expired,
            ((boundary.deadline+interval '1 microsecond')>=boundary.deadline) AS just_after_is_expired,
            extract(epoch FROM boundary.deadline-(SELECT beta_ended_at FROM beta))::int AS retention_seconds
          FROM boundary
        `);
        assert.deepEqual(equality, {
          exact_equality_is_expired: true,
          just_before_is_expired: false,
          just_after_is_expired: true,
          retention_seconds: RETENTION_SECONDS
        }, "the production deadline expression must expire exactly at beta end plus 2592000 seconds");

        phase = "sc026_external_closure_authority_and_audited_reconciliation";
        const databaseClock = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
        const betaEndedAt = new Date(new Date(databaseClock.now).getTime() - RETENTION_MS + 30_000).toISOString();
        const closeOperationId = opId();
        const closureSourceHash = reportHash({
          action: "close_beta_and_start_report_retention_v1",
          actorOwnerId: ownerA!.id,
          operationId: closeOperationId,
          betaEndedAt
        });
        await reportDependencies!.reportClosureState.persistAuthoritativeClosure({
          betaEndedAt,
          sourceEvidenceSha256: closureSourceHash
        });
        const closureJson = JSON.parse(await readFile(resolve(captureRoot, "beta-report-closure-state.json"), "utf8")) as JsonRecord;
        assert.deepEqual(Object.keys(closureJson).sort(), ["betaEndedAt", "schemaVersion", "sourceEvidenceSha256"]);
        assert.equal(closureJson.schemaVersion, REPORT_CLOSURE_STATE_SCHEMA);
        assert.equal(closureJson.betaEndedAt, betaEndedAt);
        assert.equal(closureJson.sourceEvidenceSha256, closureSourceHash);
        const closureStat = await lstat(resolve(captureRoot, "beta-report-closure-state.json"));
        assert.equal(closureStat.mode & 0o077, 0, "the immutable external closure file must remain private");

        const closeResponse = await safeHttp("/api/admin/reports/retention/close", "POST", { operationId: closeOperationId }, ownerA!, true);
        requireStatus(closeResponse, 200);
        const closeResult = asRecord(closeResponse.json);
        assert.equal(closeResult.replayed, true, "the route must reconcile the already persisted external authority record");
        const closeState = await oneReadonly<{ beta_ended_at: Date | string; expires_at: Date | string; close_operation_id: string; close_payload_hash: string }>(observer!, sql`
          SELECT beta_ended_at,${reportRetentionDeadline(sql.raw("beta_ended_at"))} AS expires_at,
            close_operation_id,close_payload_hash FROM oid_support_report_retention_state WHERE id=1
        `);
        retentionDeadline = new Date(closeState.expires_at as Date | string);
        assert.equal(new Date(closeState.beta_ended_at as Date | string).toISOString(), betaEndedAt);
        assert.equal(new Date(closeState.expires_at as Date | string).getTime() - new Date(betaEndedAt).getTime(), RETENTION_MS);
        assert.equal(closeState.close_operation_id, closeOperationId);
        assert.equal(closeState.close_payload_hash, closureSourceHash);

        phase = "sc026_real_loopback_reads_before_independent_database_deadline";
        const ownerClockBefore = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
        assert.ok(new Date(ownerClockBefore.now).getTime() < retentionDeadline.getTime());
        const ownerReportBefore = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!);
        requireStatus(ownerReportBefore, 200);
        const ownerClockAfter = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
        assert.ok(new Date(ownerClockAfter.now).getTime() < retentionDeadline.getTime(), "the independent database clock brackets owner report access before expiry");
        const adminReportBefore = await safeHttp(`/api/admin/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!, true);
        requireStatus(adminReportBefore, 200);
        const adminClockAfter = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
        assert.ok(new Date(adminClockAfter.now).getTime() < retentionDeadline.getTime(), "the independent database clock brackets admin report access before expiry");
        const imageRows = await readonlyRows<{ id: string; output_sha256: string; storage_key: string }>(observer!, sql`
          SELECT id::text AS id,output_sha256,storage_key::text AS storage_key FROM oid_support_image_upload
          WHERE report_id=${syntheticReportId}::uuid AND status='attached' ORDER BY id::text
        `);
        assert.equal(imageRows.length, 3);
        for (const image of imageRows) {
          const ownerImage = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}/images/${encodeURIComponent(image.id)}`,
            "GET", undefined, ownerA!);
          requireStatus(ownerImage, 200);
          assert.equal(sha(ownerImage.bytes), image.output_sha256, "owner image bytes must match independently read PostgreSQL hash");
          const ownerImageClock = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
          assert.ok(new Date(ownerImageClock.now).getTime() < retentionDeadline.getTime());
          const adminImage = await safeHttp(`/api/admin/reports/${encodeURIComponent(syntheticReportId)}/images/${encodeURIComponent(image.id)}`,
            "GET", undefined, ownerA!, true);
          requireStatus(adminImage, 200);
          assert.equal(sha(adminImage.bytes), image.output_sha256, "admin image bytes must match independently read PostgreSQL hash");
          const adminImageClock = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
          assert.ok(new Date(adminImageClock.now).getTime() < retentionDeadline.getTime());
        }
        const preExpirySupport = await reportSnapshot(observer!);
        const preservationBeforeExpiry = await preservationSnapshot(observer!);
        assert.deepEqual(preservationBeforeExpiry, artifact.fixtures && (artifact.fixtures as JsonRecord).preservationBefore,
          "run, evaluation, ranked, bonus and ledger rows must remain unchanged before expiry");

        phase = "sc026_independent_database_clock_reaches_deadline";
        let clockNow = new Date((await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`)).now);
        const waitStartedAt = new Date().toISOString();
        const waitDeadlineMs = Date.now() + 45_000;
        while (clockNow.getTime() < retentionDeadline.getTime() && Date.now() < waitDeadlineMs) {
          await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
          const row = await oneReadonly<{ now: Date | string }>(observer!, sql`SELECT clock_timestamp() AS now`);
          clockNow = new Date(row.now);
        }
        assert.ok(clockNow.getTime() >= retentionDeadline.getTime(), "the independent PostgreSQL clock must observe the deadline before the after-boundary request");
        const observedAtOrAfter = clockNow.toISOString();

        phase = "sc026_late_attachment_and_upload_denial_at_or_after_deadline";
        const lateAttach = await noEffectRequest("lateAttachmentDenied", () => attachImage(syntheticReportId, spareUploadId));
        requireStatus(lateAttach, 410, "REPORT_RETENTION_EXPIRED");
        const oneByte = Buffer.from([0x41]);
        const lateUpload = await noEffectRequest("lateUploadDenied", () => safeHttp("/api/owner/report-images/uploads", "POST", {
          operationId: opId(), expectedBytes: 1, sha256: sha(oneByte), contentType: "image/png"
        }, ownerA!));
        requireStatus(lateUpload, 410, "REPORT_RETENTION_EXPIRED");

        phase = "sc026_http_access_denial_and_idempotent_purge";
        const reportExpired = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!);
        requireStatus(reportExpired, 410, "REPORT_RETENTION_EXPIRED");
        const imageExpired = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}/images/${encodeURIComponent(attachedImageIds[0]!)}`,
          "GET", undefined, ownerA!);
        requireStatus(imageExpired, 410, "REPORT_RETENTION_EXPIRED");
        const adminReportExpired = await safeHttp(`/api/admin/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!, true);
        requireStatus(adminReportExpired, 410, "REPORT_RETENTION_EXPIRED");
        const adminImageExpired = await safeHttp(`/api/admin/reports/${encodeURIComponent(syntheticReportId)}/images/${encodeURIComponent(attachedImageIds[0]!)}`,
          "GET", undefined, ownerA!, true);
        requireStatus(adminImageExpired, 410, "REPORT_RETENTION_EXPIRED");

        const afterFirstPurge = await reportSnapshot(observer!);
        const receipt = await oneReadonly<{ count: number; complete: number; image_count: number; pending_keys: number; pending_bytes: number; digest: string }>(observer!, sql`
          SELECT count(*)::int AS count,
            count(*) FILTER (WHERE purge_status='complete' AND cardinality(pending_storage_keys)=0
              AND cardinality(pending_storage_bytes)=0 AND last_error_code IS NULL)::int AS complete,
            coalesce(max(image_count),0)::int AS image_count,
            coalesce(max(cardinality(pending_storage_keys)),0)::int AS pending_keys,
            coalesce(max(cardinality(pending_storage_bytes)),0)::int AS pending_bytes,
            md5(coalesce(string_agg(concat_ws('|',report_id::text,beta_ended_at::text,expires_at::text,image_count::text,
              pending_storage_keys::text,pending_storage_bytes::text,purge_status,last_error_code),E'\\n' ORDER BY report_id::text),'')) AS digest
          FROM oid_support_report_deletion_receipt
        `);
        assert.equal(afterFirstPurge.counts.reports, 0);
        assert.equal(afterFirstPurge.counts.uploads, 0);
        assert.equal(afterFirstPurge.counts.chunks, 0);
        assert.equal(receipt.count, 1);
        assert.equal(receipt.complete, 1);
        assert.equal(receipt.image_count, 3);
        assert.equal(receipt.pending_keys, 0);
        assert.equal(receipt.pending_bytes, 0);
        const filesAfterPurge = await captureFilesFingerprint(reportDependencies!.privateDataDir);
        assert.equal(filesAfterPurge.counts.files, 0);
        const orphaningGarbage = await oneReadonly<{ count: number; complete: number }>(observer!, sql`
          SELECT count(*)::int AS count,
            count(*) FILTER (WHERE status='complete' AND storage_key IS NULL AND last_error_code IS NULL)::int AS complete
          FROM oid_support_upload_gc_receipt
        `);
        assert.ok(orphaningGarbage.count >= 3 && orphaningGarbage.complete >= 3);

        phase = "sc026_repeated_read_and_cleanup_idempotence";
        const supportAfterPurge = await reportSnapshot(observer!);
        const repeatOwnerRead = await safeHttp(`/api/owner/reports/${encodeURIComponent(syntheticReportId)}`, "GET", undefined, ownerA!);
        requireStatus(repeatOwnerRead, 410, "REPORT_RETENTION_EXPIRED");
        const cleanupOne = await runReportRetentionCleanup(reportDependencies!);
        const cleanupTwo = await runReportRetentionCleanup(reportDependencies!);
        assert.deepEqual(cleanupOne, { reportsDeleted: 0, uploadsCleaned: 0 });
        assert.deepEqual(cleanupTwo, { reportsDeleted: 0, uploadsCleaned: 0 });
        const supportAfterRepeats = await reportSnapshot(observer!);
        const filesAfterRepeats = await captureFilesFingerprint(reportDependencies!.privateDataDir);
        assert.deepEqual(supportAfterRepeats, supportAfterPurge, "repeated cleanup must not change completed deletion receipts or report state");
        assert.deepEqual(filesAfterRepeats, filesAfterPurge, "repeated cleanup must not recreate private image files");
        const preservationAfter = await preservationSnapshot(observer!);
        assert.deepEqual(preservationAfter, preservationBeforeExpiry, "retention cleanup must preserve task evaluations, run timers, ranked rows, bonus and ledger records");

        (artifact.sc026 as JsonRecord).exactBoundary = {
          retentionSeconds: equality.retention_seconds,
          exactEqualityExpired: equality.exact_equality_is_expired,
          oneMicrosecondBeforeExpired: equality.just_before_is_expired,
          oneMicrosecondAfterExpired: equality.just_after_is_expired,
          databaseDeadline: retentionDeadline.toISOString(),
          independentlyObservedAtOrAfter: observedAtOrAfter,
          waitStartedAt
        };
        (artifact.sc026 as JsonRecord).closure = {
          schemaVersion: closureJson.schemaVersion,
          allowedKeys: Object.keys(closureJson).sort(),
          sourceEvidenceSha256: closureSourceHash,
          routeReconciledPersistedAuthority: true
        };
        (artifact.sc026 as JsonRecord).beforeExpiryHttpReads = {
          ownerReportStatus: ownerReportBefore.status,
          adminReportStatus: adminReportBefore.status,
          attachedImageCount: imageRows.length,
          ownerAndAdminImageHashesMatchedObserver: true,
          supportSnapshot: preExpirySupport
        };
        (artifact.sc026 as JsonRecord).afterExpiryDenials = {
          lateAttach: { status: lateAttach.status, code: lateAttach.errorCode },
          lateUpload: { status: lateUpload.status, code: lateUpload.errorCode },
          ownerReport: { status: reportExpired.status, code: reportExpired.errorCode },
          ownerImage: { status: imageExpired.status, code: imageExpired.errorCode },
          adminReport: { status: adminReportExpired.status, code: adminReportExpired.errorCode },
          adminImage: { status: adminImageExpired.status, code: adminImageExpired.errorCode }
        };
        (artifact.sc026 as JsonRecord).purge = {
          reportsRemaining: afterFirstPurge.counts.reports,
          uploadsRemaining: afterFirstPurge.counts.uploads,
          chunksRemaining: afterFirstPurge.counts.chunks,
          deletionReceiptCount: receipt.count,
          completeDeletionReceipts: receipt.complete,
          deletedImageCount: receipt.image_count,
          pendingStorageKeys: receipt.pending_keys,
          pendingStorageBytes: receipt.pending_bytes,
          deletionReceiptSha256: receipt.digest,
          completedUploadGcReceipts: orphaningGarbage.complete,
          filesAfterPurge: filesAfterPurge,
          repeatedCleanupResults: [cleanupOne, cleanupTwo],
          repeatedSnapshotUnchanged: supportAfterRepeats.sha256 === supportAfterPurge.sha256,
          repeatedFilesUnchanged: filesAfterRepeats.sha256 === filesAfterPurge.sha256
        };
        (artifact.sc026 as JsonRecord).preservation = {
          before: preservationBeforeExpiry,
          after: preservationAfter,
          unchanged: JSON.stringify(preservationAfter) === JSON.stringify(preservationBeforeExpiry)
        };
        assert.equal(JSON.stringify(preservationAfter), JSON.stringify(preservationBeforeExpiry));
        recordStep("sc026_exact_deadline_http_denial_purge_and_preservation_passed", {
          retentionSeconds: RETENTION_SECONDS,
          completeDeletionReceipts: receipt.complete,
          preservedRowsSha256: preservationAfter.sha256
        });
      } catch (error) {
        subtestFailure = true;
        (artifact as JsonRecord).failure = safeFailure(phase, error);
        throw new Error("report_lifecycle_sc026_failed");
      }
    });
  } catch (error) {
    (artifact as JsonRecord).failure ??= safeFailure(phase, error);
    throw new Error("report_lifecycle_fixture_setup_failed");
  } finally {
    if (app) {
      const closing = app.close();
      await Promise.race([closing, new Promise<void>((resolveClose) => setTimeout(resolveClose, 2_000))]);
      app.server.closeAllConnections();
      await Promise.race([closing, new Promise<void>((resolveClose) => setTimeout(resolveClose, 2_000))]);
    }
    const clients = [ownerDb?.client, observerDb?.client, baseObserverDb?.client, baseOwner].filter(Boolean);
    await Promise.all(clients.map((client) => client!.end({ timeout: 5 }).catch(() => undefined)));
    artifact.completedAt = new Date().toISOString();
    artifact.lastPhase = phase;
    if (captureRoot && artifactPath) {
      try {
        await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
        const info = await lstat(artifactPath);
        if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) throw new Error("report_lifecycle_artifact_permissions_invalid");
        process.stdout.write(`${JSON.stringify({ event: "report_lifecycle_artifact_saved", captureId: artifact.captureId, database: artifact.database, path: artifactPath, sha256: sha(await readFile(artifactPath)) })}\n`);
      } catch {
        process.stderr.write("report_lifecycle_artifact_write_failed\n");
      }
    }
  }
});
