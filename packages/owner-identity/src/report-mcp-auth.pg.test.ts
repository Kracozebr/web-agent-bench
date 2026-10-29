import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, readFile, readdir, realpath, rename, statfs, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { test } from "node:test";
import { sql, type SQL } from "drizzle-orm";
import Fastify from "fastify";
import postgres from "postgres";
import sharp from "sharp";
import { createAuth } from "./auth.js";
import { registerAgentRoutes, type AgentPrincipal, type AgentRouteDependencies } from "./agents.js";
import { loadConfig, type OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import { createReportClosureStateStore, initializeReportClosureStateFile } from "./report-closure-state.js";
import { registerSupportReportMcpTools } from "./report-mcp.js";
import type { ReportServiceDependencies } from "./report-service.js";

const OPT_IN = process.env.OID_REPORT_MCP_SMOKE_PG === "true";
const BASE_DATABASE = "owner_identity";
const DATABASE_ID = /^oid_acceptance_[a-f0-9]{32}$/;
const CAPTURE_BASE = "/local-report-captures";
const TEST_TIMEOUT_MS = 240_000;
const CHUNK_BYTES = 24 * 1024;
const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

type JsonRecord = Record<string, unknown>;
type ReadSnapshot = { counts: Record<string, number>; sha256: string };
type HttpResult = { status: number; contentType: string; json: unknown; sessionId: string | null };

function record(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function first<T>(result: unknown): T {
  const rows = result as T[];
  if (!Array.isArray(rows) || rows.length === 0) throw new Error("report_mcp_smoke_expected_row_missing");
  return rows[0]!;
}

function requireDatabaseUrl(raw: string | undefined, role: "oid_owner" | "oid_observer"): URL {
  if (!raw) throw new Error("report_mcp_smoke_database_url_missing");
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("report_mcp_smoke_database_url_invalid"); }
  if (url.protocol !== "postgres:" || url.hostname !== "postgres" || url.username !== role ||
      url.pathname !== `/${BASE_DATABASE}` || url.search || url.hash) {
    throw new Error("report_mcp_smoke_database_endpoint_rejected");
  }
  return url;
}

function acceptanceUrl(base: URL, database: string): URL {
  if (!DATABASE_ID.test(database)) throw new Error("report_mcp_smoke_database_identity_rejected");
  const target = new URL(base.href);
  target.pathname = `/${database}`;
  return target;
}

async function readonlyRows<T>(database: OwnerDatabase, statement: SQL<unknown>): Promise<T[]> {
  return database.transaction(async (tx) => {
    const identity = first<{ role: string; readOnly: string }>(await tx.execute(sql`
      SELECT current_user AS role,current_setting('transaction_read_only') AS "readOnly"
    `));
    assert.equal(identity.role, "oid_observer");
    assert.equal(identity.readOnly, "on");
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
    if (info.isSymbolicLink()) throw new Error("report_mcp_smoke_path_has_symlink");
    if (current !== absolute && !info.isDirectory()) throw new Error("report_mcp_smoke_path_parent_invalid");
  }
}

async function assertMissingPath(path: string): Promise<void> {
  try {
    await lstat(path);
    throw new Error("report_mcp_smoke_capture_path_already_exists");
  } catch (error) {
    if (error instanceof Error && error.message === "report_mcp_smoke_capture_path_already_exists") throw error;
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function volumeHeadroom(path: string): Promise<{ freeBytes: number; totalBytes: number; freePercent: number }> {
  const info = await statfs(path, { bigint: true });
  const free = info.bavail * info.bsize;
  const total = info.blocks * info.bsize;
  const minimum = 2n * 1024n * 1024n * 1024n;
  const reserve = (total * 20n) / 100n;
  if (free < (minimum > reserve ? minimum : reserve)) throw new Error("report_mcp_smoke_volume_reserve_below_20_percent");
  return { freeBytes: Number(free), totalBytes: Number(total), freePercent: Number((free * 10_000n) / total) / 100 };
}

const REPORT_SNAPSHOT_QUERY = sql.raw(`
SELECT
  (SELECT count(*)::int FROM oid_support_report) AS reports,
  (SELECT count(*)::int FROM oid_support_report_audit) AS audits,
  (SELECT count(*)::int FROM oid_support_image_upload) AS uploads,
  (SELECT count(*)::int FROM oid_support_image_chunk) AS chunks,
  (SELECT count(*)::int FROM oid_support_image_input_usage) AS usage_rows,
  (SELECT count(*)::int FROM oid_support_image_upload WHERE status='attached') AS attached_images,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,owner_id::text,agent_id::text,source,reporter_kind,
      reporter_id::text,operation_id,payload_hash,status,revision::text,run_id::text,task_id,action_id::text),E'\\n' ORDER BY id::text),''))
    FROM oid_support_report) AS reports_hash,
  (SELECT md5(coalesce(string_agg(to_jsonb(a)::text,E'\\n' ORDER BY to_jsonb(a)::text),''))
    FROM oid_support_report_audit a) AS audits_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',id::text,owner_id::text,uploader_kind,uploader_id::text,
      uploader_agent_id::text,operation_id,payload_hash,expected_sha256,expected_input_bytes::text,
      input_bytes::text,output_sha256,status,report_id::text,storage_key::text,expires_at::text),
      E'\\n' ORDER BY id::text),'')) FROM oid_support_image_upload) AS uploads_hash,
  (SELECT md5(coalesce(string_agg(concat_ws('|',upload_id::text,sequence::text,sha256,octet_length(bytes)::text),
      E'\\n' ORDER BY upload_id::text,sequence),'')) FROM oid_support_image_chunk) AS chunks_hash,
  (SELECT md5(coalesce(string_agg(to_jsonb(u)::text,E'\\n' ORDER BY to_jsonb(u)::text),''))
    FROM oid_support_image_input_usage u) AS usage_hash
`);

const DOMAIN_SNAPSHOT_QUERY = sql.raw(`
SELECT
  (SELECT count(*)::int FROM oid_ledger_operation) AS ledger_operations,
  (SELECT count(*)::int FROM oid_ledger_entry) AS ledger_entries,
  (SELECT count(*)::int FROM oid_ledger_audit) AS ledger_audits,
  (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
  (SELECT count(*)::int FROM oid_run_task) AS tasks,
  (SELECT count(*)::int FROM oid_run_task_action) AS actions,
  (SELECT count(*)::int FROM oid_run_task_action_outbox) AS action_outbox_rows,
  (SELECT count(*)::int FROM oid_run_task_closure) AS task_closures,
  (SELECT count(*)::int FROM oid_run_task_evaluation) AS task_evaluations,
  (SELECT count(*)::int FROM oid_run_event) AS run_events,
  (SELECT count(*)::int FROM oid_run_launch_intent) AS launch_intents,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_ledger_operation x),'')) AS ledger_operations_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_ledger_entry x),'')) AS ledger_entries_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_ledger_audit x),'')) AS ledger_audits_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_benchmark_run x),'')) AS run_and_timer_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_task x),'')) AS task_and_timer_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_task_action x),'')) AS actions_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_task_action_outbox x),'')) AS action_outbox_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_task_closure x),'')) AS task_closures_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_task_evaluation x),'')) AS task_evaluations_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_event x),'')) AS run_events_hash,
  md5(coalesce((SELECT string_agg(to_jsonb(x)::text,E'\\n' ORDER BY to_jsonb(x)::text) FROM oid_run_launch_intent x),'')) AS launch_intents_hash
`);

async function stateSnapshot(observer: OwnerDatabase): Promise<{ reports: ReadSnapshot; domain: ReadSnapshot }> {
  const reportRow = first<JsonRecord>(await readonlyRows(observer, REPORT_SNAPSHOT_QUERY));
  const domainRow = first<JsonRecord>(await readonlyRows(observer, DOMAIN_SNAPSHOT_QUERY));
  const numeric = (row: JsonRecord) => Object.fromEntries(Object.entries(row)
    .filter(([key]) => !key.endsWith("_hash"))
    .map(([key, value]) => [key, Number(value ?? 0)]));
  const hashes = (row: JsonRecord) => Object.fromEntries(Object.entries(row).filter(([key]) => key.endsWith("_hash")));
  const reports = { counts: numeric(reportRow), sha256: sha(JSON.stringify(hashes(reportRow))) };
  const domain = { counts: numeric(domainRow), sha256: sha(JSON.stringify(hashes(domainRow))) };
  return { reports, domain };
}

async function privateFilesSnapshot(privateDataDir: string): Promise<ReadSnapshot> {
  const imageRoot = join(privateDataDir, "reports", "images");
  let entries: string[];
  try { entries = await readdir(imageRoot); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") entries = [];
    else throw error;
  }
  entries.sort();
  const details: Array<{ bytes: number; sha256: string }> = [];
  let totalBytes = 0;
  for (const name of entries) {
    const target = resolve(imageRoot, name);
    const rel = relative(resolve(privateDataDir), target);
    if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error("report_mcp_smoke_file_path_escape");
    const info = await lstat(target);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error("report_mcp_smoke_storage_entry_not_regular");
    const bytes = await readFile(target);
    totalBytes += bytes.length;
    details.push({ bytes: bytes.length, sha256: sha(bytes) });
  }
  return { counts: { files: entries.length, bytes: totalBytes }, sha256: sha(JSON.stringify(details)) };
}

function safeFailure(phase: string, error: unknown): JsonRecord {
  const failure: JsonRecord = { phase, code: "REPORT_MCP_SMOKE_FAILED" };
  if (!(error instanceof Error)) return failure;
  if (/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(error.name)) failure.errorName = error.name;
  const code = (error as Error & { code?: unknown }).code;
  if ((typeof code === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(code)) || (typeof code === "number" && Number.isInteger(code))) {
    failure.errorCode = String(code);
  }
  for (const line of (error.stack ?? "").split(/\r?\n/).slice(1)) {
    const match = line.match(/report-mcp-auth\.pg\.test\.(?:ts|js):(\d+):(\d+)/);
    if (match) { failure.testSourceLine = Number(match[1]); break; }
  }
  return failure;
}

function mcpErrorCode(response: HttpResult): string | null {
  const rpc = record(response.json);
  const rpcError = record(rpc.error);
  if (typeof rpcError.code === "number" || typeof rpcError.code === "string") return String(rpcError.code);
  const result = record(rpc.result);
  if (result.isError !== true) return null;
  const content = Array.isArray(result.content) ? result.content : [];
  const firstText = record(content[0]).text;
  if (typeof firstText !== "string") return "MCP_TOOL_ERROR";
  try {
    const parsed = record(JSON.parse(firstText) as unknown);
    const nested = record(parsed.error);
    return typeof nested.code === "string" ? nested.code : "MCP_TOOL_ERROR";
  } catch { return "MCP_TOOL_ERROR"; }
}

function mcpToolValue(response: HttpResult): JsonRecord {
  assert.equal(response.status, 200, "authenticated MCP HTTP call must return 200");
  const rpc = record(response.json);
  assert.equal(rpc.error, undefined, "MCP JSON-RPC call must not return a protocol error");
  const result = record(rpc.result);
  assert.notEqual(result.isError, true, "MCP tool call must succeed");
  if (result.structuredContent !== undefined) return record(result.structuredContent);
  const content = Array.isArray(result.content) ? result.content : [];
  const firstText = record(content[0]).text;
  if (typeof firstText !== "string") throw new Error("report_mcp_smoke_tool_result_missing");
  return record(JSON.parse(firstText) as unknown);
}

function toolRejected(response: HttpResult): boolean {
  const rpc = record(response.json);
  return response.status === 400 || typeof rpc.error === "object" || record(rpc.result).isError === true;
}

function operationId(): string { return randomUUID().replaceAll("-", ""); }

test("supplementary local DB-authenticated MCP report and screenshot smoke", {
  skip: !OPT_IN,
  timeout: TEST_TIMEOUT_MS
}, async () => {
  const artifact: JsonRecord = {
    schemaVersion: "bpc-local-authenticated-mcp-report-smoke/v1",
    evidenceBoundary: "single_synthetic_manual_credential_local_mcp",
    scope: "supplementary_not_SC019_gate",
    fixtureType: "synthetic_local_credential_not_owner_ui_issuance",
    nativeClient: false,
    modelInference: false,
    fourClientGateCovered: false,
    sc019GatePromotion: false,
    startedAt: new Date().toISOString(),
    preflight: {},
    protocol: {},
    observations: {},
    steps: []
  };
  let phase = "preflight";
  let artifactPath = "";
  let captureRoot = "";
  let privateDataDir = "";
  let closurePath = "";
  let baseOwner: ReturnType<typeof postgres> | undefined;
  let baseObserverDb: ReturnType<typeof createDatabase> | undefined;
  let ownerDb: ReturnType<typeof createDatabase> | undefined;
  let observerDb: ReturnType<typeof createDatabase> | undefined;
  let app: ReturnType<typeof Fastify> | undefined;
  let reportDeps: ReportServiceDependencies | undefined;
  let agentDeps: AgentRouteDependencies | undefined;
  let observer: OwnerDatabase | undefined;
  let publicOrigin = "";

  const persist = async () => {
    if (!artifactPath) return;
    const temporary = join(captureRoot, `.report-mcp-smoke-${randomUUID()}.tmp`);
    await writeFile(temporary, `${JSON.stringify(artifact, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    await chmod(temporary, 0o600);
    await rename(temporary, artifactPath);
    await chmod(artifactPath, 0o600);
  };
  const checkpoint = async (name: string, details: JsonRecord = {}) => {
    phase = name;
    (artifact.steps as JsonRecord[]).push({ phase: name, startedAt: new Date().toISOString(), ...details });
    await persist();
  };
  const finishStep = async (details: JsonRecord = {}) => {
    const steps = artifact.steps as JsonRecord[];
    const current = steps.at(-1);
    if (current) Object.assign(current, { completedAt: new Date().toISOString(), ...details });
    await persist();
  };
  const recordResponse = async (response: HttpResult) => {
    const steps = artifact.steps as JsonRecord[];
    const current = steps.at(-1);
    if (current) Object.assign(current, { httpStatus: response.status, errorCode: mcpErrorCode(response), contentType: response.contentType });
    await persist();
  };

  async function mcpRequest(token: string, message: JsonRecord): Promise<HttpResult> {
    const method = typeof message.method === "string" ? message.method : "";
    const requestHeaders: Record<string, string> = {
      authorization: `Bearer ${token}`,
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": method,
      origin: publicOrigin
    };
    const params = record(message.params);
    if (method === "tools/call" && typeof params.name === "string") requestHeaders["mcp-name"] = params.name;
    const modernMessage = {
      ...message,
      params: {
        ...params,
        _meta: {
          ...record(params._meta),
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientCapabilities": {}
        }
      }
    };
    const response = await fetch(new URL("/api/agent/mcp", publicOrigin), {
      method: "POST", headers: requestHeaders, body: JSON.stringify(modernMessage), signal: AbortSignal.timeout(20_000)
    });
    const body = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get("content-type") ?? "";
    let json: unknown = null;
    if (body.length > 0 && contentType.toLowerCase().includes("application/json")) {
      try { json = JSON.parse(body.toString("utf8")) as unknown; }
      catch { throw new Error("report_mcp_smoke_mcp_json_parse_failed"); }
    }
    return { status: response.status, contentType, json, sessionId: response.headers.get("mcp-session-id") };
  }

  async function callTool(token: string, toolName: string, args: JsonRecord): Promise<HttpResult> {
    return mcpRequest(token, {
      jsonrpc: "2.0",
      id: randomUUID(),
      method: "tools/call",
      params: { name: toolName, arguments: args }
    });
  }

  async function successfulTool(token: string, toolName: string, args: JsonRecord): Promise<JsonRecord> {
    const response = await callTool(token, toolName, args);
    await recordResponse(response);
    return mcpToolValue(response);
  }

  async function noEffect(name: string, action: () => Promise<HttpResult>): Promise<{ response: HttpResult; before: ReadSnapshot; filesBefore: ReadSnapshot }> {
    if (!observer || !privateDataDir) throw new Error("report_mcp_smoke_observer_not_ready");
    const beforeState = await stateSnapshot(observer);
    const filesBefore = await privateFilesSnapshot(privateDataDir);
    const response = await action();
    await recordResponse(response);
    const afterState = await stateSnapshot(observer);
    const filesAfter = await privateFilesSnapshot(privateDataDir);
    assert.deepEqual(afterState.reports, beforeState.reports, `${name}_must_not_change_report_rows`);
    assert.deepEqual(filesAfter, filesBefore, `${name}_must_not_change_private_files`);
    return { response, before: beforeState.reports, filesBefore };
  }

  try {
    phase = "preflight_unique_database_capture_root_and_volume";
    const ownerBaseUrl = requireDatabaseUrl(process.env.OID_DATABASE_URL, "oid_owner");
    const observerBaseUrl = requireDatabaseUrl(process.env.OID_OBSERVER_DATABASE_URL, "oid_observer");
    if (resolve(process.env.OID_LOCAL_REPORT_CAPTURE_BASE ?? "") !== CAPTURE_BASE) {
      throw new Error("report_mcp_smoke_requires_pinned_named_capture_volume");
    }
    const captureId = randomUUID();
    const databaseName = `oid_acceptance_${captureId.replaceAll("-", "")}`;
    if (!DATABASE_ID.test(databaseName)) throw new Error("report_mcp_smoke_database_identity_invalid");
    captureRoot = resolve(CAPTURE_BASE, databaseName);
    privateDataDir = resolve(captureRoot, "private-data");
    closurePath = resolve(captureRoot, "beta-report-closure-state.json");
    artifactPath = resolve(captureRoot, "report-mcp-local-smoke.json");
    if (basename(captureRoot) !== databaseName || !isAbsolute(captureRoot) || !isAbsolute(privateDataDir) ||
        !isAbsolute(closurePath) || relative(captureRoot, privateDataDir).startsWith("..") ||
        relative(captureRoot, closurePath).startsWith("..")) throw new Error("report_mcp_smoke_capture_path_guard_failed");
    await verifyNoSymlinkPath(CAPTURE_BASE);
    if (await realpath(CAPTURE_BASE) !== CAPTURE_BASE) throw new Error("report_mcp_smoke_named_volume_path_mismatch");
    const headroom = await volumeHeadroom(CAPTURE_BASE);
    await assertMissingPath(captureRoot);

    baseOwner = postgres(ownerBaseUrl.href, { max: 1, connect_timeout: 10 });
    const ownerIdentity = first<{ database: string; role: string; sessionRole: string; readOnly: string }>(await baseOwner`
      SELECT current_database() AS database,current_user AS role,session_user AS "sessionRole",
        current_setting('transaction_read_only') AS "readOnly"
    `);
    assert.deepEqual(ownerIdentity, { database: BASE_DATABASE, role: "oid_owner", sessionRole: "oid_owner", readOnly: "off" });

    baseObserverDb = createDatabase({ databaseUrl: observerBaseUrl.href } as OwnerIdentityConfig);
    const observerIdentity = await oneReadonly<{ database: string; role: string; sessionRole: string; readOnly: string }>(baseObserverDb.db, sql.raw(`
      SELECT current_database() AS database,current_user AS role,session_user AS "sessionRole",
        current_setting('transaction_read_only') AS "readOnly"
    `));
    assert.deepEqual(observerIdentity, { database: BASE_DATABASE, role: "oid_observer", sessionRole: "oid_observer", readOnly: "on" });
    const observerRole = await oneReadonly<{ superuser: boolean; createRole: boolean; createDb: boolean; replication: boolean; bypassRls: boolean; memberships: number }>(baseObserverDb.db, sql.raw(`
      SELECT rolsuper AS "superuser",rolcreaterole AS "createRole",rolcreatedb AS "createDb",
        rolreplication AS replication,rolbypassrls AS "bypassRls",
        (SELECT count(*)::int FROM pg_auth_members m WHERE m.member=r.oid) AS memberships
      FROM pg_roles r WHERE r.rolname='oid_observer'
    `));
    assert.deepEqual(observerRole, { superuser: false, createRole: false, createDb: false, replication: false, bypassRls: false, memberships: 0 });
    const exists = first<{ present: boolean }>(await baseOwner`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=${databaseName}) AS present`);
    assert.equal(exists.present, false);

    artifact.captureId = captureId;
    artifact.database = databaseName;
    artifact.captureRoot = captureRoot;
    artifact.privateDataDir = privateDataDir;
    artifact.externalClosureStateFile = closurePath;
    artifact.preflight = {
      ownerBaseRole: ownerIdentity.role,
      ownerBaseDatabase: ownerIdentity.database,
      observerBaseRole: observerIdentity.role,
      observerBaseDatabase: observerIdentity.database,
      observerReadOnly: observerIdentity.readOnly === "on",
      observerHasNoElevatedFlagsOrMemberships: !observerRole.superuser && !observerRole.createRole && !observerRole.createDb &&
        !observerRole.replication && !observerRole.bypassRls && observerRole.memberships === 0,
      targetDatabaseAbsent: true,
      captureRootAbsent: true,
      namedVolume: CAPTURE_BASE,
      freeBytes: headroom.freeBytes,
      totalBytes: headroom.totalBytes,
      freePercent: headroom.freePercent,
      reserveFloorPercent: 20
    };

    phase = "create_journal_before_database_or_fixture_writes";
    await mkdir(captureRoot, { mode: 0o700 });
    await chmod(captureRoot, 0o700);
    const rootInfo = await lstat(captureRoot);
    assert.ok(rootInfo.isDirectory() && !rootInfo.isSymbolicLink() && (rootInfo.mode & 0o077) === 0);
    await persist();
    await checkpoint("database_and_private_storage_creation_authorized_by_preflight");

    await mkdir(privateDataDir, { mode: 0o700 });
    await chmod(privateDataDir, 0o700);
    const initialClosureHash = sha("synthetic-local-mcp-report-smoke-open-closure-v1");
    await initializeReportClosureStateFile(closurePath, initialClosureHash);
    const privateInfo = await lstat(privateDataDir);
    const closureInfo = await lstat(closurePath);
    assert.ok(privateInfo.isDirectory() && !privateInfo.isSymbolicLink() && (privateInfo.mode & 0o077) === 0);
    assert.ok(closureInfo.isFile() && !closureInfo.isSymbolicLink() && (closureInfo.mode & 0o077) === 0);
    assert.equal((closureInfo.mode & 0o077), 0);

    await checkpoint("create_only_fresh_acceptance_database");
    await baseOwner.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
    await baseOwner.unsafe(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
    const ownerUrl = acceptanceUrl(ownerBaseUrl, databaseName);
    const observerUrl = acceptanceUrl(observerBaseUrl, databaseName);
    ownerDb = createDatabase({ databaseUrl: ownerUrl.href } as OwnerIdentityConfig);
    observerDb = createDatabase({ databaseUrl: observerUrl.href } as OwnerIdentityConfig);
    const targetOwnerIdentity = first<{ database: string; role: string; readOnly: string }>(await ownerDb.client`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS "readOnly"
    `);
    assert.deepEqual(targetOwnerIdentity, { database: databaseName, role: "oid_owner", readOnly: "off" });
    const targetObserverIdentity = await oneReadonly<{ database: string; role: string; readOnly: string }>(observerDb.db, sql.raw(`
      SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS "readOnly"
    `));
    assert.deepEqual(targetObserverIdentity, { database: databaseName, role: "oid_observer", readOnly: "on" });

    await checkpoint("migrate_only_the_fresh_acceptance_database");
    const migrationEnv: NodeJS.ProcessEnv = {
      ...process.env,
      OID_DATABASE_URL: ownerUrl.href,
      OID_OBSERVER_DATABASE_URL: observerUrl.href,
      OID_AUTH_SECRET: randomBytes(32).toString("base64url"),
      OID_PRIVATE_DATA_DIR: privateDataDir,
      OID_BETA_REPORT_CLOSURE_STATE_FILE: closurePath,
      OID_PUBLIC_ORIGIN: "http://127.0.0.1:8784",
      OID_API_HOST: "127.0.0.1",
      OID_API_PORT: "8784",
      OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "false",
      OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: "false",
      OID_MCP_TRANSPORT_PROFILE: "strict-2026-07-28",
      NODE_ENV: "test"
    };
    delete migrationEnv.OID_BETA_MANIFEST_FILE;
    delete migrationEnv.OID_BETA_BEF_TASK_COORDINATOR_CONFIG;
    delete migrationEnv.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG;
    const migration = spawnSync("pnpm", ["--filter", "@web-agent-bench/owner-identity", "migrate"], {
      cwd: process.cwd(), env: migrationEnv, encoding: "utf8", maxBuffer: 512 * 1024
    });
    if (migration.error) throw migration.error;
    if (migration.status !== 0) {
      const error = new Error("report_mcp_smoke_target_database_migration_failed") as Error & { code?: unknown };
      error.code = `MIGRATION_EXIT_${migration.status ?? "SIGNAL"}`;
      throw error;
    }
    await finishStep({ migrationExitCode: migration.status });

    await checkpoint("grant_readonly_observer_select_access");
    await ownerDb.client.unsafe("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC");
    await ownerDb.client.unsafe("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    await ownerDb.client.unsafe("GRANT USAGE ON SCHEMA public TO oid_observer");
    await ownerDb.client.unsafe("GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer");
    await ownerDb.client.unsafe("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer");
    const grants = await oneReadonly<{ tables: number; selectOnly: boolean }>(observerDb.db, sql.raw(`
      SELECT count(*)::int AS tables,coalesce(bool_and(privilege_type='SELECT'),true) AS "selectOnly"
      FROM information_schema.role_table_grants WHERE grantee='oid_observer' AND table_schema='public'
    `));
    const reportPrivileges = await oneReadonly<{ canSelect: boolean; canInsert: boolean; canUpdate: boolean; canDelete: boolean }>(observerDb.db, sql.raw(`
      SELECT has_table_privilege('oid_observer','oid_support_report','SELECT') AS "canSelect",
        has_table_privilege('oid_observer','oid_support_report','INSERT') AS "canInsert",
        has_table_privilege('oid_observer','oid_support_report','UPDATE') AS "canUpdate",
        has_table_privilege('oid_observer','oid_support_report','DELETE') AS "canDelete"
    `));
    assert.ok(grants.tables > 0 && grants.selectOnly);
    assert.deepEqual(reportPrivileges, { canSelect: true, canInsert: false, canUpdate: false, canDelete: false });
    observer = observerDb.db;
    reportDeps = {
      db: ownerDb.db,
      privateDataDir,
      reportClosureState: createReportClosureStateStore(closurePath)
    };

    const runtimeEnv: NodeJS.ProcessEnv = {
      ...process.env,
      OID_DATABASE_URL: ownerUrl.href,
      OID_OBSERVER_DATABASE_URL: observerUrl.href,
      OID_AUTH_SECRET: randomBytes(32).toString("base64url"),
      OID_PRIVATE_DATA_DIR: privateDataDir,
      OID_BETA_REPORT_CLOSURE_STATE_FILE: closurePath,
      OID_LOCAL_REPORT_CAPTURE_ROOT: captureRoot,
      OID_PUBLIC_ORIGIN: "http://127.0.0.1:8784",
      OID_API_HOST: "127.0.0.1",
      OID_API_PORT: "8784",
      OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "false",
      OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: "true",
      OID_MCP_TRANSPORT_PROFILE: "strict-2026-07-28",
      NODE_ENV: "test"
    };
    delete runtimeEnv.OID_BETA_MANIFEST_FILE;
    delete runtimeEnv.OID_BETA_BEF_TASK_COORDINATOR_CONFIG;
    delete runtimeEnv.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG;
    const config = loadConfig(runtimeEnv);
    const closureState = await reportDeps.reportClosureState.readAuthoritativeClosure();
    assert.equal(closureState.betaEndedAt, null);
    assert.equal(closureState.sourceEvidenceSha256, initialClosureHash);
    artifact.preflight = {
      ...(artifact.preflight as JsonRecord),
      targetDatabase: databaseName,
      targetOwnerRole: targetOwnerIdentity.role,
      targetObserverRole: targetObserverIdentity.role,
      targetObserverReadOnly: targetObserverIdentity.readOnly === "on",
      observerTableCount: grants.tables,
      observerSelectOnly: grants.selectOnly,
      observerCanSelectReports: reportPrivileges.canSelect,
      observerCannotWriteReports: !reportPrivileges.canInsert && !reportPrivileges.canUpdate && !reportPrivileges.canDelete,
      privateDataMode: "0700",
      captureRootMode: "0700",
      closureFileMode: "0600"
    };
    await persist();

    await checkpoint("register_production_agent_routes_and_report_mcp_tools");
    app = Fastify({ logger: false });
    const auth = createAuth(config, ownerDb.db);
    agentDeps = {
      db: ownerDb.db,
      auth,
      config,
      resolveOwner: async () => { throw new Error("report_mcp_smoke_unused_owner_route"); },
      requireOrigin: async () => undefined,
      rateLimit: async () => undefined,
      rateLimitMax: 100,
      credentialRateLimitMax: 30,
      preflightRateLimitMax: 60,
      manualCredentialTtlSeconds: config.manualCredentialTtlSeconds,
      agentResource: `${config.publicOrigin}/api/agent`,
      agentPreflightUrl: `${config.publicOrigin}/api/agent/preflight`,
      registerMcpTools: (server, principal) => registerSupportReportMcpTools(server, principal, reportDeps!)
    };
    registerAgentRoutes(app, agentDeps);
    publicOrigin = await app.listen({ host: "127.0.0.1", port: 0 });
    config.publicOrigin = publicOrigin;
    config.apiPort = Number(new URL(publicOrigin).port);
    agentDeps.agentResource = `${publicOrigin}/api/agent`;
    agentDeps.agentPreflightUrl = `${publicOrigin}/api/agent/preflight`;
    assert.equal(new URL(publicOrigin).hostname, "127.0.0.1");
    await finishStep({ loopbackHost: new URL(publicOrigin).hostname, productionRouteRegistration: true });

    const ownerA = randomUUID();
    const ownerB = randomUUID();
    const userA = `mcp-smoke-${randomUUID()}`;
    const userB = `mcp-smoke-${randomUUID()}`;
    const agentA = randomUUID();
    const agentB = randomUUID();
    const grantA = randomUUID();
    const grantB = randomUUID();
    const credentialA = randomUUID();
    const credentialB = randomUUID();
    const grantOperationId = operationId();
    const fixtureRunId = randomUUID();
    const fixtureIntentId = randomUUID();
    const fixtureClosureId = randomUUID();
    const fixtureActionId = randomUUID();
    const fixtureLedgerGrantId = randomUUID();
    const fixtureLedgerOperationId = operationId();
    const fixtureHash = sha("synthetic-local-mcp-report-smoke-preservation-fixture-v1");
    const operationA = operationId();
    const operationB = operationId();
    const tokenA = `aap1_${randomBytes(32).toString("base64url")}`;
    const tokenB = `aap1_${randomBytes(32).toString("base64url")}`;
    const tokenHashA = sha(tokenA);
    const tokenHashB = sha(tokenB);
    await checkpoint("persist_two_synthetic_admitted_principals_and_bearer_hash_grant_bindings");
    await ownerDb.db.transaction(async (tx) => {
      await tx.execute(sql`INSERT INTO oid_auth_user(id,name,email,email_verified)
        VALUES(${userA},'Synthetic local MCP owner A',${`${userA}@example.invalid`},true),
          (${userB},'Synthetic local MCP owner B',${`${userB}@example.invalid`},true)`);
      await tx.execute(sql`INSERT INTO oid_owner(id,auth_user_id,admission_status,admitted_at)
        VALUES(${ownerA}::uuid,${userA},'admitted',clock_timestamp()),
          (${ownerB}::uuid,${userB},'admitted',clock_timestamp())`);
      await tx.execute(sql`INSERT INTO oid_agent(id,owner_id,name,description)
        VALUES(${agentA}::uuid,${ownerA}::uuid,'Synthetic local MCP agent A','Isolated auth fixture'),
          (${agentB}::uuid,${ownerB}::uuid,'Synthetic local MCP agent B','Isolated auth fixture')`);
      await tx.execute(sql`INSERT INTO oid_agent_policy(agent_id,training,ranked,forum_messages,custom_topics)
        VALUES(${agentA}::uuid,false,false,false,false),(${agentB}::uuid,false,false,false,false)`);
      await tx.execute(sql`INSERT INTO oid_agent_access_grant(
          id,owner_id,agent_id,operation_id,source,resource,role,access_generation,expires_at
        ) VALUES
          (${grantA}::uuid,${ownerA}::uuid,${agentA}::uuid,${operationA},'manual',${agentDeps!.agentResource},'agent',1,clock_timestamp()+interval '1 hour'),
          (${grantB}::uuid,${ownerB}::uuid,${agentB}::uuid,${operationB},'manual',${agentDeps!.agentResource},'agent',1,clock_timestamp()+interval '1 hour')`);
      await tx.execute(sql`INSERT INTO oid_agent_manual_credential(id,grant_id,verifier_hash)
        VALUES(${credentialA}::uuid,${grantA}::uuid,${tokenHashA}),(${credentialB}::uuid,${grantB}::uuid,${tokenHashB})`);
      await tx.execute(sql`INSERT INTO oid_run_launch_intent(
        id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,
        agent_policy_revision,status,created_at,expires_at,accepted_at
      ) VALUES (
        ${fixtureIntentId}::uuid,${ownerA}::uuid,${agentA}::uuid,${operationId()},${fixtureHash},'training',ARRAY['S1']::text[],
        'fixture-only/local-mcp-smoke/v1','fixture-only/v1',${fixtureHash},${fixtureHash},${fixtureHash},0,0,1,1,
        'accepted',clock_timestamp()-interval '2 minutes',clock_timestamp()+interval '1 hour',clock_timestamp()
      )`);
      await tx.execute(sql`INSERT INTO oid_benchmark_run(
        id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,
        policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,
        queued_at,queue_deadline,started_at,overall_deadline,finished_at,terminal_reason
      ) VALUES (
        ${fixtureRunId}::uuid,${fixtureIntentId}::uuid,${ownerA}::uuid,${agentA}::uuid,'training',ARRAY['S1']::text[],
        'fixture-only/local-mcp-smoke/v1','fixture-only/v1',${fixtureHash},${fixtureHash},${fixtureHash},0,0,1,1,'completed',
        clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',clock_timestamp()-interval '30 seconds',
        clock_timestamp()+interval '30 minutes',clock_timestamp()-interval '1 second','fixture_only'
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task(run_id,task_index,task_id,status,snapshot_json,started_at,deadline_at,finished_at,result_json)
        VALUES(${fixtureRunId}::uuid,0,'S1','completed','{"fixtureOnly":true}'::jsonb,
          clock_timestamp()-interval '30 seconds',clock_timestamp()+interval '30 minutes',clock_timestamp()-interval '1 second',
          '{"grade":"fixture_only","creditUnits":"0"}'::jsonb)`);
      await tx.execute(sql`INSERT INTO oid_run_task_closure(
        id,run_id,task_index,operation_id,payload_hash,reason,answer_json,action_cutoff_sequence,actor_kind,
        owner_id,agent_id,access_generation,grant_id
      ) VALUES(
        ${fixtureClosureId}::uuid,${fixtureRunId}::uuid,0,${operationId()},${fixtureHash},'agent_finish',
        '{"fixtureOnly":true}'::jsonb,1,'agent',${ownerA}::uuid,${agentA}::uuid,1,${grantA}::uuid
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task_evaluation(
        run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,input_hash,
        result_hash,evaluator_source_hash,observation_evidence,result_json,input_json
      ) VALUES(
        ${fixtureRunId}::uuid,0,${fixtureClosureId}::uuid,'S1','fixture-only/local-mcp-smoke/v1',
        ${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},${fixtureHash},
        '{"fixtureOnly":true}'::jsonb,'{"grade":"fixture_only","creditUnits":"0"}'::jsonb,
        '{"fixtureOnly":true}'::jsonb
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task_action(
        id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,environment_id,
        action_sequence,operation_id,payload_hash,action_kind,command_json
      ) VALUES(
        ${fixtureActionId}::uuid,${fixtureRunId}::uuid,0,${ownerA}::uuid,${agentA}::uuid,1,${grantA}::uuid,
        'S1','fixture-only',1,${operationId()},${fixtureHash},'inspect_catalog','{"fixtureOnly":true}'::jsonb
      )`);
      await tx.execute(sql`INSERT INTO oid_run_task_action_outbox(action_id,status,created_at,delivered_at)
        VALUES(${fixtureActionId}::uuid,'delivered',clock_timestamp()-interval '1 second',clock_timestamp())`);
      await tx.execute(sql`INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id)
        VALUES(${fixtureLedgerGrantId}::uuid,${ownerA}::uuid,1000000,${ownerB}::uuid,'Synthetic local MCP preservation sentinel',${grantOperationId})`);
      await tx.execute(sql`INSERT INTO oid_ledger_operation(id,actor_owner_id,subject_owner_id,operation_id,action,payload_hash,response_json)
        VALUES(${randomUUID()}::uuid,${ownerB}::uuid,${ownerA}::uuid,${fixtureLedgerOperationId},'bonus_grant',${fixtureHash},
          ${JSON.stringify({ fixtureOnly: true, grantId: fixtureLedgerGrantId })}::jsonb)`);
      await tx.execute(sql`INSERT INTO oid_ledger_entry(
        id,owner_id,actor_owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,
        available_delta_units,reserved_delta_units,expired_delta_units,reason
      ) VALUES(
        ${randomUUID()}::uuid,${ownerA}::uuid,${ownerB}::uuid,${fixtureLedgerGrantId}::uuid,${fixtureLedgerOperationId},
        'bonus_grant','tester_bonus',1000000,1000000,0,0,'Synthetic local MCP preservation sentinel'
      )`);
      await tx.execute(sql`INSERT INTO oid_ledger_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata)
        VALUES(${randomUUID()}::uuid,'bonus_granted',${fixtureLedgerOperationId},${ownerB}::uuid,${ownerA}::uuid,'{"fixtureOnly":true}'::jsonb)`);
    });
    artifact.fixtures = {
      syntheticOwners: 2,
      syntheticAgents: 2,
      syntheticManualCredentialHashBindings: 2,
      bearerHashesPersisted: true,
      bearerValuesRecorded: false,
      preservationSentinels: { completedRuns: 1, completedTasks: 1, actions: 1, ledgerEntries: 1 },
      grantResourceBoundToLoopback: true,
      fixtureBoundary: "not_owner_ui_issuance_not_native_client"
    };
    await finishStep({ fixturePrincipalCount: 2, bearerValuesRecorded: false });

    const initialState = await stateSnapshot(observer);
    const initialFiles = await privateFilesSnapshot(privateDataDir);
    artifact.observations = {
      initialReportCounts: initialState.reports.counts,
      initialReportStateSha256: initialState.reports.sha256,
      initialPrivateFileCount: initialFiles.counts.files,
      initialDomainCounts: initialState.domain.counts,
      initialDomainStateSha256: initialState.domain.sha256,
      timerStateSource: ["oid_benchmark_run", "oid_run_task"],
      taskActionSource: "oid_run_task_action"
    };
    assert.equal(initialState.reports.counts.reports, 0);
    assert.equal(initialState.domain.counts.ledger_entries, 1);
    assert.equal(initialState.domain.counts.runs, 1);
    assert.equal(initialState.domain.counts.tasks, 1);
    assert.equal(initialState.domain.counts.actions, 1);
    assert.equal(initialState.domain.counts.action_outbox_rows, 1);
    assert.equal(initialState.domain.counts.task_closures, 1);
    assert.equal(initialState.domain.counts.task_evaluations, 1);
    assert.equal(initialState.domain.counts.launch_intents, 1);

    artifact.protocol = {
      protocolVersion: "2026-07-28",
      initializeHandshake: "not_defined_by_pinned_2026_revision",
      perRequestEnvelope: true,
      requiredEnvelopeKeys: ["io.modelcontextprotocol/protocolVersion", "io.modelcontextprotocol/clientCapabilities"],
      requiredRequestHeaders: ["MCP-Protocol-Version", "Mcp-Method"],
      toolCallHeader: "Mcp-Name mirrors params.name"
    };
    await persist();
    await checkpoint("authenticated_agent_a_first_modern_mcp_tools_list_request");
    const listA = await mcpRequest(tokenA, { jsonrpc: "2.0", id: randomUUID(), method: "tools/list", params: {} });
    await finishStep({ httpStatus: listA.status, errorCode: mcpErrorCode(listA), contentType: listA.contentType });
    assert.equal(listA.status, 200);
    const toolRows = record(listA.json).result && Array.isArray(record(record(listA.json).result).tools)
      ? record(record(listA.json).result).tools as unknown[] : [];
    const toolNames = toolRows.map((item) => record(item).name).filter((item): item is string => typeof item === "string");
    for (const name of ["support.report", "support.report_receipt", "support.screenshot.begin", "support.screenshot.chunk", "support.screenshot.finish"]) {
      assert.ok(toolNames.includes(name), `authenticated MCP tool registry must include ${name}`);
    }
    await finishStep({ reportToolCount: toolNames.filter((name) => name.startsWith("support.")).length });

    await checkpoint("authenticated_agent_b_modern_mcp_tools_list_request");
    const listB = await mcpRequest(tokenB, { jsonrpc: "2.0", id: randomUUID(), method: "tools/list", params: {} });
    await finishStep({ httpStatus: listB.status, errorCode: mcpErrorCode(listB), contentType: listB.contentType });
    assert.equal(listB.status, 200);
    assert.equal(record(listB.json).error, undefined);

    await checkpoint("generate_synthetic_valid_png_with_exact_24kib_first_chunk");
    const width = 192;
    const height = 192;
    const rawImage = Buffer.alloc(width * height * 3);
    for (let index = 0; index < rawImage.length; index++) rawImage[index] = (index * 73 + (index >>> 4) * 29 + 41) & 0xff;
    const imageBytes = await sharp(rawImage, { raw: { width, height, channels: 3 } }).png({ compressionLevel: 0 }).toBuffer();
    assert.ok(imageBytes.length > CHUNK_BYTES + 1);
    const firstChunk = imageBytes.subarray(0, CHUNK_BYTES);
    const remainder = imageBytes.subarray(CHUNK_BYTES);
    assert.equal(firstChunk.length, 24_576);
    assert.equal(remainder.length + firstChunk.length, imageBytes.length);
    const uploadOperationId = operationId();

    await checkpoint("mcp_screenshot_begin_for_agent_a");
    const begin = await successfulTool(tokenA, "support.screenshot.begin", {
      operationId: uploadOperationId,
      expectedBytes: imageBytes.length,
      sha256: sha(imageBytes),
      contentType: "image/png"
    });
    const uploadId = begin.uploadId;
    assert.equal(typeof uploadId, "string");
    await finishStep({ httpStatus: 200, declaredBytes: imageBytes.length, contentType: "image/png" });

    const firstChunkArgs = {
      uploadId: uploadId as string,
      sequence: 0,
      sha256: sha(firstChunk),
      dataBase64: firstChunk.toString("base64")
    };
    await checkpoint("mcp_screenshot_chunk_0_exactly_24576_decoded_bytes");
    const acceptedChunk = await successfulTool(tokenA, "support.screenshot.chunk", firstChunkArgs);
    assert.equal(acceptedChunk.acceptedBytes, 24_576);
    assert.equal(acceptedChunk.replayed, false);
    await finishStep({ httpStatus: 200, decodedBytes: 24_576, sequence: 0 });

    await checkpoint("mcp_exact_chunk_replay_has_no_durable_effect");
    const replay = await noEffect("exact_chunk_replay", () => callTool(tokenA, "support.screenshot.chunk", firstChunkArgs));
    const replayValue = mcpToolValue(replay.response);
    assert.equal(replayValue.replayed, true);
    artifact.observations = { ...(artifact.observations as JsonRecord), exactChunkReplayReplayed: true };
    await finishStep({ httpStatus: replay.response.status, replayed: true, databaseUnchanged: true, filesUnchanged: true,
      snapshotSha256: replay.before.sha256, filesSha256: replay.filesBefore.sha256 });

    const changedChunk = Buffer.from(firstChunk);
    changedChunk[0] = changedChunk[0]! ^ 0xff;
    const conflictArgs = { ...firstChunkArgs, sha256: sha(changedChunk), dataBase64: changedChunk.toString("base64") };
    await checkpoint("mcp_conflicting_same_sequence_replay_rejected_without_effects");
    const conflict = await noEffect("conflicting_chunk_replay", () => callTool(tokenA, "support.screenshot.chunk", conflictArgs));
    assert.equal(mcpErrorCode(conflict.response), "REPORT_IMAGE_CHUNK_CONFLICT");
    await finishStep({ httpStatus: conflict.response.status, errorCode: "REPORT_IMAGE_CHUNK_CONFLICT",
      databaseUnchanged: true, filesUnchanged: true, snapshotSha256: conflict.before.sha256, filesSha256: conflict.filesBefore.sha256 });

    const oversizedChunk = Buffer.alloc(24_577, 0x5a);
    await checkpoint("mcp_24577_decoded_bytes_rejected_without_effects");
    const oversized = await noEffect("decoded_chunk_over_24kib", () => callTool(tokenA, "support.screenshot.chunk", {
      uploadId: uploadId as string,
      sequence: 1,
      sha256: sha(oversizedChunk),
      dataBase64: oversizedChunk.toString("base64")
    }));
    assert.ok(toolRejected(oversized.response), "the MCP schema or image service must reject a 24577-byte decoded chunk");
    assert.notEqual(oversized.response.status, 401, "the valid credential must remain authenticated during chunk validation");
    await finishStep({ httpStatus: oversized.response.status, errorCode: mcpErrorCode(oversized.response), decodedBytes: 24_577,
      rejected: true, databaseUnchanged: true, filesUnchanged: true,
      snapshotSha256: oversized.before.sha256, filesSha256: oversized.filesBefore.sha256 });

    let uploadedChunkCount = 1;
    let uploadedBytes = firstChunk.length;
    const expectedChunkRows = [{ sequence: 0, chunkHash: sha(firstChunk), bytes: firstChunk.length }];
    for (let offset = CHUNK_BYTES, sequence = 1; offset < imageBytes.length; offset += CHUNK_BYTES, sequence++) {
      const chunk = imageBytes.subarray(offset, Math.min(imageBytes.length, offset + CHUNK_BYTES));
      await checkpoint("mcp_screenshot_chunk_ordered_completion", { sequence, decodedBytes: chunk.length });
      const accepted = await successfulTool(tokenA, "support.screenshot.chunk", {
        uploadId: uploadId as string,
        sequence,
        sha256: sha(chunk),
        dataBase64: chunk.toString("base64")
      });
      assert.equal(accepted.acceptedBytes, chunk.length);
      assert.equal(accepted.replayed, false);
      uploadedChunkCount++;
      uploadedBytes += chunk.length;
      expectedChunkRows.push({ sequence, chunkHash: sha(chunk), bytes: chunk.length });
    }
    assert.equal(uploadedBytes, imageBytes.length);
    const acceptedChunkRows = Array.from(await readonlyRows<{ sequence: number; chunkHash: string; bytes: number }>(observer, sql`
      SELECT sequence,sha256 AS "chunkHash",octet_length(bytes)::int AS bytes
      FROM oid_support_image_chunk WHERE upload_id=${uploadId as string}::uuid ORDER BY sequence
    `));
    assert.deepEqual(acceptedChunkRows, expectedChunkRows, "the independent observer must see the exact ordered uploaded chunks before normalization");
    const acceptedChunkEvidence = {
      count: acceptedChunkRows.length,
      decodedBytes: acceptedChunkRows.reduce((sum, row) => sum + row.bytes, 0),
      orderedChunkRowsSha256: sha(JSON.stringify(acceptedChunkRows))
    };
    assert.equal(acceptedChunkEvidence.count, uploadedChunkCount);
    assert.equal(acceptedChunkEvidence.decodedBytes, imageBytes.length);
    artifact.observations = { ...(artifact.observations as JsonRecord), acceptedInputChunksBeforeFinish: acceptedChunkEvidence };
    await checkpoint("independent_readonly_observer_verified_exact_input_chunks_before_finish", acceptedChunkEvidence);
    await finishStep({ matchesExpectedSequencesHashesAndBytes: true });
    await checkpoint("mcp_screenshot_finish_normalization");
    const finish = await successfulTool(tokenA, "support.screenshot.finish", { uploadId });
    assert.equal(record(finish.upload).status, "ready");
    await finishStep({ normalizedReady: true, totalDecodedBytes: uploadedBytes, orderedChunkCount: uploadedChunkCount,
      servicePurgesRawChunkRowsAfterNormalization: true });

    const imageRow = await oneReadonly<{ storageKey: string; outputHash: string; outputBytes: number }>(observer, sql`
      SELECT storage_key::text AS "storageKey",output_sha256 AS "outputHash",output_bytes::int AS "outputBytes"
      FROM oid_support_image_upload WHERE id=${uploadId as string}::uuid AND owner_id=${ownerA}::uuid AND status='ready'
    `);
    assert.match(imageRow.storageKey, /^[0-9a-f-]{36}$/i);
    assert.match(imageRow.outputHash, /^[0-9a-f]{64}$/);
    const imagePath = resolve(privateDataDir, "reports", "images", `${imageRow.storageKey}.webp`);
    const imageRel = relative(resolve(privateDataDir), imagePath);
    assert.ok(imageRel !== ".." && !imageRel.startsWith(`..${sep}`) && !isAbsolute(imageRel));
    await verifyNoSymlinkPath(imagePath);
    const imageStat = await lstat(imagePath);
    assert.ok(imageStat.isFile() && !imageStat.isSymbolicLink());
    const normalizedFile = await readFile(imagePath);
    const fileHash = sha(normalizedFile);
    assert.equal(fileHash, imageRow.outputHash, "normalized private image file hash must match observer metadata");
    assert.equal(normalizedFile.length, imageRow.outputBytes);

    const reportOperationId = operationId();
    const reportArgs: JsonRecord = {
      operationId: reportOperationId,
      title: "Synthetic local MCP support report",
      body: "Synthetic no-run connection report for the isolated authenticated MCP smoke.",
      imageUploadIds: [uploadId as string]
    };
    await checkpoint("mcp_create_private_no_run_report_with_owned_image");
    const created = await successfulTool(tokenA, "support.report", reportArgs);
    const createdReport = record(created.report);
    const reportId = createdReport.id;
    assert.equal(created.replayed, false);
    assert.equal(createdReport.source, "agent");
    assert.equal(createdReport.imageCount, 1);
    assert.equal(createdReport.status, "new");
    assert.equal(typeof reportId, "string");
    await finishStep({ httpStatus: 200, created: true, reportIdSha256: sha(String(reportId)), noRunContext: true, imageCount: 1 });

    await checkpoint("mcp_exact_report_retry_returns_original_private_receipt");
    const reportRetry = await successfulTool(tokenA, "support.report", reportArgs);
    const retryReport = record(reportRetry.report);
    assert.equal(reportRetry.replayed, true);
    assert.equal(retryReport.id, reportId);
    await finishStep({ httpStatus: 200, replayed: true, reportIdSha256: sha(String(retryReport.id)) });

    await checkpoint("mcp_owner_agent_a_reads_own_report_receipt");
    const ownReceipt = await successfulTool(tokenA, "support.report_receipt", { reportId });
    assert.equal(record(ownReceipt.report).id, reportId);
    assert.equal(record(ownReceipt.report).imageCount, 1);
    await finishStep({ httpStatus: 200, ownReceipt: true, imageCount: 1 });

    await checkpoint("mcp_foreign_principal_cannot_read_agent_a_receipt");
    const foreignReceipt = await noEffect("foreign_agent_receipt", () => callTool(tokenB, "support.report_receipt", { reportId }));
    assert.equal(mcpErrorCode(foreignReceipt.response), "REPORT_NOT_FOUND");
    await finishStep({ httpStatus: foreignReceipt.response.status, errorCode: "REPORT_NOT_FOUND", databaseUnchanged: true,
      filesUnchanged: true, snapshotSha256: foreignReceipt.before.sha256, filesSha256: foreignReceipt.filesBefore.sha256 });

    await checkpoint("mcp_foreign_principal_cannot_attach_agent_a_image");
    const foreignAttach = await noEffect("foreign_agent_image_attach", () => callTool(tokenB, "support.report", {
      operationId: operationId(),
      title: "Synthetic foreign attachment denial",
      body: "Synthetic negative principal-ownership probe.",
      imageUploadIds: [uploadId as string]
    }));
    assert.equal(mcpErrorCode(foreignAttach.response), "REPORT_IMAGE_NOT_FOUND");
    await finishStep({ httpStatus: foreignAttach.response.status, errorCode: "REPORT_IMAGE_NOT_FOUND", databaseUnchanged: true,
      filesUnchanged: true, snapshotSha256: foreignAttach.before.sha256, filesSha256: foreignAttach.filesBefore.sha256 });

    await checkpoint("mcp_strict_schema_rejects_forged_owner_and_agent_fields");
    const forged = await noEffect("forged_report_principal_fields", () => callTool(tokenA, "support.report", {
      operationId: operationId(),
      title: "Synthetic forged fields denial",
      body: "Synthetic strict-schema principal-boundary probe.",
      ownerId: ownerB,
      agentId: agentB
    }));
    assert.ok(toolRejected(forged.response), "strict MCP report schema must reject caller-supplied principal fields");
    assert.notEqual(forged.response.status, 401);
    await finishStep({ httpStatus: forged.response.status, errorCode: mcpErrorCode(forged.response), rejected: true,
      databaseUnchanged: true, filesUnchanged: true, snapshotSha256: forged.before.sha256, filesSha256: forged.filesBefore.sha256 });

    await checkpoint("revoke_persisted_manual_grant_before_reusing_bearer");
    await ownerDb.db.execute(sql`
      UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp(),revocation_reason='replaced'
      WHERE id=${grantA}::uuid AND source='manual' AND owner_id=${ownerA}::uuid AND agent_id=${agentA}::uuid
    `);
    const revokedAt = await oneReadonly<{ revoked: boolean }>(observer, sql`
      SELECT revoked_at IS NOT NULL AS revoked FROM oid_agent_access_grant WHERE id=${grantA}::uuid
    `);
    assert.equal(revokedAt.revoked, true);
    await finishStep({ grantRevokedInFreshDatabase: true, bearerValueReusedInMemory: true });

    await checkpoint("revoked_manual_bearer_returns_http_401_without_report_or_file_changes");
    const revoked = await noEffect("revoked_bearer", () => callTool(tokenA, "support.report_receipt", { reportId }));
    assert.equal(revoked.response.status, 401);
    await finishStep({ httpStatus: 401, unauthorized: true, databaseUnchanged: true, filesUnchanged: true,
      snapshotSha256: revoked.before.sha256, filesSha256: revoked.filesBefore.sha256 });

    const finalState = await stateSnapshot(observer);
    const finalFiles = await privateFilesSnapshot(privateDataDir);
    const persistedReport = await oneReadonly<{ source: string; runLinked: boolean; taskLinked: boolean; actionLinked: boolean; imageCount: number }>(observer, sql`
      SELECT r.source,(r.run_id IS NOT NULL) AS "runLinked",(r.task_id IS NOT NULL) AS "taskLinked",
        (r.action_id IS NOT NULL) AS "actionLinked",count(u.id)::int AS "imageCount"
      FROM oid_support_report r LEFT JOIN oid_support_image_upload u ON u.report_id=r.id AND u.status='attached'
      WHERE r.id=${reportId as string}::uuid GROUP BY r.id
    `);
    assert.deepEqual(persistedReport, { source: "agent", runLinked: false, taskLinked: false, actionLinked: false, imageCount: 1 });
    assert.equal(finalState.reports.counts.reports, 1);
    assert.equal(finalState.reports.counts.uploads, 1);
    assert.equal(finalState.reports.counts.chunks, 0, "normalized upload should no longer retain raw chunk rows");
    assert.equal(finalState.reports.counts.usage_rows, uploadedChunkCount, "per-chunk usage receipts should remain durable after raw-byte cleanup");
    assert.equal(finalState.reports.counts.attached_images, 1);
    assert.equal(finalFiles.counts.files, 1);
    assert.equal(finalState.domain.sha256, initialState.domain.sha256);
    assert.deepEqual(finalState.domain.counts, initialState.domain.counts);
    artifact.observations = {
      ...(artifact.observations as JsonRecord),
      finalReportCounts: finalState.reports.counts,
      acceptedInputChunksBeforeFinish: acceptedChunkEvidence,
      rawChunkRowsAfterFinish: finalState.reports.counts.chunks,
      durableInputUsageRowsAfterFinish: finalState.reports.counts.usage_rows,
      finalReportStateSha256: finalState.reports.sha256,
      finalPrivateFileCount: finalFiles.counts.files,
      finalPrivateFileBytes: finalFiles.counts.bytes,
      finalPrivateFileSetSha256: finalFiles.sha256,
      normalizedImageOutputSha256: imageRow.outputHash,
      normalizedImageFileSha256: fileHash,
      normalizedImageOutputBytes: imageRow.outputBytes,
      reportIdSha256: sha(String(reportId)),
      noRunTaskActionLinks: true,
      ledgerRunTaskActionAndTimerStateUnchanged: true,
      ledgerRunTaskActionTimerBefore: initialState.domain,
      ledgerRunTaskActionTimerAfter: finalState.domain
    };
    artifact.status = "completed";
    artifact.completedAt = new Date().toISOString();
    await persist();
  } catch (error) {
    artifact.status = "failed";
    artifact.failure = safeFailure(phase, error);
    artifact.failedAt = new Date().toISOString();
    await persist().catch(() => undefined);
    throw error;
  } finally {
    if (app) await app.close().catch(() => undefined);
    if (ownerDb) await ownerDb.client.end({ timeout: 5 }).catch(() => undefined);
    if (observerDb) await observerDb.client.end({ timeout: 5 }).catch(() => undefined);
    if (baseObserverDb) await baseObserverDb.client.end({ timeout: 5 }).catch(() => undefined);
    if (baseOwner) await baseOwner.end({ timeout: 5 }).catch(() => undefined);
  }
});
