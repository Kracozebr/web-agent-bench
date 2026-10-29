import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { basename, isAbsolute, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { test } from "node:test";
import { sql } from "drizzle-orm";
import multipart from "@fastify/multipart";
import Fastify from "fastify";
import type { OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import { createReportClosureStateStore } from "./report-closure-state.js";
import { registerSupportReportRoutes, type SupportReportRouteDependencies } from "./report-routes.js";
import { REPORT_IMAGE_MAX_INPUT_BYTES } from "./report-images.js";
import { responseError } from "./http-error-response.js";

const optIn = process.env.OID_REPORT_PG_REGRESSION === "true";
const EXPECTED_DB = /^oid_acceptance_[a-f0-9]{32}$/;

function first<T>(result: unknown): T {
  const rows = result as T[];
  if (!rows.length) throw new Error("report_route_pg_probe_expected_row_missing");
  return rows[0]!;
}

function acceptanceUrl(raw: string | undefined, expectedDatabase: string, role: "oid_owner" | "oid_observer"): string {
  if (!raw) throw new Error("report_route_pg_probe_docker_database_url_missing");
  const url = new URL(raw);
  if (url.hostname !== "postgres" || url.username !== role) throw new Error("report_route_pg_probe_database_endpoint_rejected");
  url.pathname = `/${expectedDatabase}`;
  return url.href;
}

async function identity(database: OwnerDatabase) {
  return first<{ database: string; role: string; read_only: string }>(await database.execute(sql`
    SELECT current_database() AS database,current_user AS role,current_setting('transaction_read_only') AS read_only
  `));
}

async function readonlyCounts(database: OwnerDatabase) {
  return database.transaction(async (tx) => {
    const identity = first<{ role: string; read_only: string }>(await tx.execute(sql`
      SELECT current_user AS role,current_setting('transaction_read_only') AS read_only
    `));
    assert.equal(identity.role, "oid_observer");
    assert.equal(identity.read_only, "on");
    const row = first<Record<string, number>>(await tx.execute(sql`
      SELECT
        (SELECT count(*)::int FROM oid_support_report) AS reports,
        (SELECT count(*)::int FROM oid_support_report_audit) AS audits,
        (SELECT count(*)::int FROM oid_support_image_upload) AS uploads,
        (SELECT count(*)::int FROM oid_support_image_chunk) AS chunks,
        (SELECT count(*)::int FROM oid_support_report_deletion_receipt) AS deletion_receipts,
        (SELECT count(*)::int FROM oid_support_upload_gc_receipt) AS upload_gc_receipts,
        (SELECT count(*)::int FROM oid_support_report_rate) AS rate_limits,
        (SELECT count(*)::int FROM oid_ledger_entry) AS ledger,
        (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
        (SELECT count(*)::int FROM oid_run_task) AS tasks,
        (SELECT count(*)::int FROM oid_run_task_action) AS actions
    `));
    return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, Number(value)]));
  }, { accessMode: "read only" });
}

function multipartBody(boundary: string, fields: Array<[string, string]>, file: Buffer, trailingFields: Array<[string, string]> = []) {
  const fieldPart = (name: string, value: string) => Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`, "utf8");
  return Buffer.concat([
    ...fields.map(([name, value]) => fieldPart(name, value)),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="probe.png"\r\nContent-Type: image/png\r\n\r\n`, "utf8"),
    file,
    Buffer.from("\r\n", "utf8"),
    ...trailingFields.map(([name, value]) => fieldPart(name, value)),
    Buffer.from(`--${boundary}--\r\n`, "utf8"),
  ]);
}

function postMultipart(origin: string, boundary: string, body: Buffer, timeoutMs: number, includeContentLength = true) {
  const startedAt = performance.now();
  return new Promise<{ status: number; body: Buffer; elapsedMs: number }>((resolveResponse, rejectResponse) => {
    let settled = false;
    let responseStarted = false;
    let responseBytes = 0;
    const responseChunks: Buffer[] = [];
    let request: ReturnType<typeof httpRequest>;
    const finishError = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rejectResponse(error);
    };
    const timer = setTimeout(() => request.destroy(new Error("report_route_http_timeout")), timeoutMs);
    const headers: Record<string, string> = {
      origin,
      connection: "close",
      "content-type": `multipart/form-data; boundary=${boundary}`,
    };
    if (includeContentLength) headers["content-length"] = String(body.length);
    request = httpRequest(`${origin}/api/owner/report-images/uploads/multipart`, {
      method: "POST",
      agent: false,
      headers,
    }, (response) => {
      responseStarted = true;
      response.on("data", (value: Buffer | string) => {
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        responseBytes += chunk.length;
        if (responseBytes > 64 * 1024) {
          request.destroy(new Error("report_route_http_response_too_large"));
          return;
        }
        responseChunks.push(chunk);
      });
      response.on("error", finishError);
      response.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolveResponse({ status: response.statusCode ?? 0, body: Buffer.concat(responseChunks),
          elapsedMs: Math.round(performance.now() - startedAt) });
      });
    });
    request.on("timeout", () => request.destroy(new Error("report_route_http_timeout")));
    request.on("error", (error) => { if (!responseStarted) finishError(error); });
    request.end(body);
  });
}

test("owner report JSON envelope overflow returns a bounded 413 before route work", async () => {
  const app = Fastify({ logger: false });
  let routeReached = false;
  const entered = async (): Promise<never> => { routeReached = true; throw new Error("oversized_report_route_should_not_run"); };
  const dependencies: SupportReportRouteDependencies = {
    db: {} as OwnerDatabase,
    service: {} as SupportReportRouteDependencies["service"],
    publicOrigin: "http://127.0.0.1",
    rateLimitMax: 10,
    resolveOwner: entered,
    resolveAgentPrincipal: async () => undefined,
    requireAdmin: entered,
    requireOrigin: entered,
    rateLimit: entered,
  };
  app.setErrorHandler((error, _request, reply) => responseError(reply, error));
  registerSupportReportRoutes(app, dependencies);
  try {
    const payload = JSON.stringify({ operationId: "a".repeat(32), title: "Oversized request probe", body: "x".repeat(17 * 1024) });
    assert.ok(Buffer.byteLength(payload, "utf8") > 16 * 1024);
    const response = await app.inject({ method: "POST", url: "/api/owner/reports",
      headers: { origin: "http://127.0.0.1", "content-type": "application/json" }, payload });
    assert.equal(response.statusCode, 413);
    assert.deepEqual(response.json(), { error: { code: "REQUEST_BODY_TOO_LARGE", message: "Request body exceeds the configured limit" } });
    assert.equal(routeReached, false, "body limit must reject before authentication, rate-limit, or service mutations run");
  } finally { await app.close(); }
});

test("malformed report multipart returns bounded errors without durable side effects", { skip: !optIn, timeout: 30_000 }, async () => {
  const expectedDatabase = process.env.OID_REPORT_PG_TEST_DATABASE ?? "";
  assert.match(expectedDatabase, EXPECTED_DB, "the opt-in route regression requires a unique oid_acceptance database identity");
  const owner = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_DATABASE_URL, expectedDatabase, "oid_owner") } as OwnerIdentityConfig);
  const observer = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_OBSERVER_DATABASE_URL, expectedDatabase, "oid_observer") } as OwnerIdentityConfig);
  const app = Fastify({ logger: false });
  try {
    const [ownerIdentity, observerIdentity] = await Promise.all([identity(owner.db), identity(observer.db)]);
    assert.equal(ownerIdentity.database, expectedDatabase, "owner connection must prove the isolated DB identity before HTTP activity");
    assert.equal(ownerIdentity.role, "oid_owner");
    assert.equal(observerIdentity.database, expectedDatabase, "read-only observer must prove the same isolated DB identity before HTTP activity");
    assert.equal(observerIdentity.role, "oid_observer");
    assert.equal(observerIdentity.read_only, "on");

    const privateDataDir = process.env.OID_PRIVATE_DATA_DIR;
    const closurePath = process.env.OID_BETA_REPORT_CLOSURE_STATE_FILE;
    if (!privateDataDir || !isAbsolute(privateDataDir) || !closurePath || !isAbsolute(closurePath)) {
      throw new Error("report_route_pg_probe_capture_paths_missing");
    }
    const captureRoot = resolve(privateDataDir, "..");
    const privateInfo = await lstat(privateDataDir);
    const privateReal = await realpath(privateDataDir);
    const closureInfo = await lstat(closurePath);
    const closureReal = await realpath(closurePath);
    assert.equal(basename(captureRoot), expectedDatabase);
    assert.equal(resolve(closurePath), resolve(captureRoot, "beta-report-closure-state.json"));
    assert.ok(privateInfo.isDirectory() && !privateInfo.isSymbolicLink());
    assert.ok(!relative(captureRoot, privateReal).startsWith(".."));
    assert.ok(closureInfo.isFile() && !closureInfo.isSymbolicLink());
    assert.ok(!relative(captureRoot, closureReal).startsWith(".."));

    const ownerRow = first<{ id: string }>(await observer.db.execute(sql`
      SELECT id::text AS id FROM oid_owner WHERE admission_status='admitted' ORDER BY created_at LIMIT 1
    `));
    const closure = createReportClosureStateStore(closurePath);
    assert.equal((await closure.readAuthoritativeClosure()).betaEndedAt, null,
      "the route regression requires an open external report-closure fixture");
    const service = { db: owner.db, privateDataDir, reportClosureState: closure };
    const deps: SupportReportRouteDependencies = {
      db: owner.db,
      service,
      publicOrigin: "",
      rateLimitMax: 100,
      resolveOwner: async () => ({ owner: { id: ownerRow.id, admissionStatus: "admitted" } }),
      resolveAgentPrincipal: async () => undefined,
      requireAdmin: async () => { throw new Error("report_route_pg_probe_admin_not_used"); },
      requireOrigin: async (request) => {
        if (request.headers.origin !== deps.publicOrigin) throw new Error("report_route_pg_probe_origin_mismatch");
      },
      rateLimit: async () => undefined,
    };
    await app.register(multipart, {
      limits: { fieldNameSize: 32, fieldSize: 128, fields: 4, files: 1,
        fileSize: REPORT_IMAGE_MAX_INPUT_BYTES, headerPairs: 16, parts: 5 },
      throwFileSizeLimit: false,
    });
    registerSupportReportRoutes(app, deps);
    const address = await app.listen({ host: "127.0.0.1", port: 0 });
    deps.publicOrigin = address;

    const before = await readonlyCounts(observer.db);
    const oversized = Buffer.alloc(REPORT_IMAGE_MAX_INPUT_BYTES + 1, 0x41);
    const expectedFields = (operationId: string, bytes: Buffer, expectedBytes: number): Array<[string, string]> => [
      ["operationId", operationId],
      ["expectedBytes", String(expectedBytes)],
      ["sha256", createHash("sha256").update(bytes).digest("hex")],
      ["contentType", "image/png"],
    ];

    const smallBytes = Buffer.from([1, 2, 3, 4]);
    const extraPartBoundary = `----report-${randomUUID()}`;
    const extraPartResponse = await postMultipart(address, extraPartBoundary,
      multipartBody(extraPartBoundary, expectedFields(randomUUID().replaceAll("-", ""), smallBytes, smallBytes.length),
        smallBytes, [["unexpected", "trailing-field"]]), 10_000);
    const extraPartPayload = JSON.parse(extraPartResponse.body.toString("utf8")) as { error?: { code?: unknown } };
    assert.equal(extraPartResponse.status, 400);
    assert.equal(extraPartPayload?.error?.code, "INVALID_REPORT_IMAGE_MULTIPART");
    assert.ok(extraPartResponse.elapsedMs < 10_000, "the bounded malformed-envelope request must complete promptly");

    const chunkedOversized = Buffer.alloc(REPORT_IMAGE_MAX_INPUT_BYTES + 32 * 1024, 0x41);
    const chunkedBoundary = `----report-${randomUUID()}`;
    const chunkedResponse = await postMultipart(address, chunkedBoundary,
      multipartBody(chunkedBoundary, expectedFields(randomUUID().replaceAll("-", ""),
        chunkedOversized.subarray(0, REPORT_IMAGE_MAX_INPUT_BYTES), REPORT_IMAGE_MAX_INPUT_BYTES), chunkedOversized), 10_000, false);
    const chunkedPayload = JSON.parse(chunkedResponse.body.toString("utf8")) as { error?: { code?: unknown } };
    assert.equal(chunkedResponse.status, 413);
    assert.equal(chunkedPayload?.error?.code, "REPORT_IMAGE_TOO_LARGE");
    assert.ok(chunkedResponse.elapsedMs < 10_000, "the chunked envelope overflow must be bounded and promptly rejected");

    let oversizedResponse: { status: number; body: Buffer; elapsedMs: number };
    try {
      const boundary = `----report-${randomUUID()}`;
      oversizedResponse = await postMultipart(address, boundary,
        multipartBody(boundary, expectedFields(randomUUID().replaceAll("-", ""), oversized.subarray(0, REPORT_IMAGE_MAX_INPUT_BYTES),
          REPORT_IMAGE_MAX_INPUT_BYTES), oversized), 10_000);
    } catch (error) {
      const afterTimeout = await readonlyCounts(observer.db);
      assert.deepEqual(afterTimeout, before, "a timed-out malformed multipart request must not leave durable report effects");
      const errorName = error instanceof Error && /^[A-Za-z]+Error$/.test(error.name) ? error.name : "RequestError";
      const errorCode = typeof error === "object" && error !== null && "code" in error
        && typeof (error as { code?: unknown }).code === "string"
        && /^[A-Z0-9_]{2,64}$/.test((error as { code: string }).code)
        ? `/${(error as { code: string }).code}` : "";
      assert.fail(`loopback oversized multipart HTTP response did not arrive within 10 seconds (${errorName}${errorCode})`);
    }
    const oversizedPayload = JSON.parse(oversizedResponse.body.toString("utf8")) as { error?: { code?: unknown } };
    assert.equal(oversizedResponse.status, 413);
    assert.equal(oversizedPayload?.error?.code, "REPORT_IMAGE_TOO_LARGE");
    assert.ok(oversizedResponse.elapsedMs < 10_000, "the bounded oversized request must complete before the acceptance HTTP timeout");
    const after = await readonlyCounts(observer.db);
    assert.deepEqual(after, before, "the independent observer must find no durable report, upload, chunk, receipt, rate, or domain side effects");
  } finally {
    const closing = app.close();
    await Promise.race([closing, new Promise<void>((resolveClose) => setTimeout(resolveClose, 1_000))]);
    app.server.closeAllConnections();
    await Promise.race([closing, new Promise<void>((resolveClose) => setTimeout(resolveClose, 1_000))]);
    await Promise.all([owner.client.end({ timeout: 5 }), observer.client.end({ timeout: 5 })]);
  }
});
