import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve } from "node:path";
import { test } from "node:test";
import { sql } from "drizzle-orm";
import type { OwnerIdentityConfig } from "./config.js";
import { createDatabase, type OwnerDatabase } from "./db.js";
import { createReportClosureStateStore } from "./report-closure-state.js";
import { reportDeletionReceiptStatement, reportRetentionDeadline } from "./report-db.js";
import { createSupportReport, type ReportServiceDependencies } from "./report-service.js";

const optIn = process.env.OID_REPORT_PG_REGRESSION === "true";
const EXPECTED_DB = /^oid_acceptance_[a-f0-9]{32}$/;
const ROLLBACK_SENTINEL = "report_pg_regression_forced_rollback";
const sha = "e".repeat(64);

function first<T>(result: unknown): T {
  const rows = result as T[];
  if (!rows.length) throw new Error("report_pg_probe_expected_row_missing");
  return rows[0]!;
}

function acceptanceUrl(raw: string | undefined, expectedDatabase: string, role: "oid_owner" | "oid_observer"): string {
  if (!raw) throw new Error("report_pg_probe_docker_database_url_missing");
  const url = new URL(raw);
  if (url.hostname !== "postgres" || url.username !== role) throw new Error("report_pg_probe_database_endpoint_rejected");
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
    const current = await tx.execute(sql`SELECT current_user AS role,current_setting('transaction_read_only') AS read_only`);
    const verified = first<{ role: string; read_only: string }>(current);
    assert.equal(verified.role, "oid_observer");
    assert.equal(verified.read_only, "on");
    const row = first<Record<string, number>>(await tx.execute(sql`SELECT
      (SELECT count(*)::int FROM oid_support_report) AS reports,
      (SELECT count(*)::int FROM oid_support_image_upload) AS uploads,
      (SELECT count(*)::int FROM oid_support_report_audit) AS audits,
      (SELECT count(*)::int FROM oid_support_report_rate) AS rate_limits,
      (SELECT count(*)::int FROM oid_support_report_deletion_receipt) AS deletion_receipts,
      (SELECT count(*)::int FROM oid_ledger_entry) AS ledger,
      (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
      (SELECT count(*)::int FROM oid_run_task) AS tasks,
      (SELECT count(*)::int FROM oid_run_task_action) AS actions`));
    return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, Number(value)]));
  }, { accessMode: "read only" });
}

async function insertReadyUpload(tx: Parameters<Parameters<OwnerDatabase["transaction"]>[0]>[0], input: {
  uploadId: string; ownerId: string; uploaderKind: "owner" | "agent"; uploaderId: string;
  uploaderAgentId: string | null; storageKey: string; operationId: string;
}) {
  await tx.execute(sql`INSERT INTO oid_support_image_upload(
    id,owner_id,uploader_kind,uploader_id,uploader_agent_id,operation_id,payload_hash,input_mime,
    expected_sha256,expected_input_bytes,input_bytes,reserved_output_bytes,output_bytes,output_sha256,
    output_mime,width,height,storage_key,status,expires_at
  ) VALUES (
    ${input.uploadId}::uuid,${input.ownerId}::uuid,${input.uploaderKind},${input.uploaderId}::uuid,
    ${input.uploaderAgentId}::uuid,${input.operationId},${sha},'image/png',${sha},1,1,0,1,${sha},
    'image/webp',1,1,${input.storageKey}::uuid,'ready',clock_timestamp()+interval '1 day'
  )`);
}

test("report binding, deletion arrays, and UTC retention survive real PostgreSQL with forced rollback", { skip: !optIn }, async () => {
  const expectedDatabase = process.env.OID_REPORT_PG_TEST_DATABASE ?? "";
  assert.match(expectedDatabase, EXPECTED_DB, "the opt-in regression requires a unique oid_acceptance database identity");
  const owner = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_DATABASE_URL, expectedDatabase, "oid_owner") } as OwnerIdentityConfig);
  const observer = createDatabase({ databaseUrl: acceptanceUrl(process.env.OID_OBSERVER_DATABASE_URL, expectedDatabase, "oid_observer") } as OwnerIdentityConfig);
  try {
    const [ownerIdentity, observerIdentity] = await Promise.all([identity(owner.db), identity(observer.db)]);
    assert.equal(ownerIdentity.database, expectedDatabase, "owner connection must prove its live database identity before the probe");
    assert.equal(ownerIdentity.role, "oid_owner");
    assert.equal(observerIdentity.database, expectedDatabase, "observer connection must prove the same live database identity before the probe");
    assert.equal(observerIdentity.role, "oid_observer");
    assert.equal(observerIdentity.read_only, "on");

    const privateDataDir = process.env.OID_PRIVATE_DATA_DIR;
    const closurePath = process.env.OID_BETA_REPORT_CLOSURE_STATE_FILE;
    if (!privateDataDir || !isAbsolute(privateDataDir) || !closurePath || !isAbsolute(closurePath)) {
      throw new Error("report_pg_probe_capture_paths_missing");
    }
    const captureRoot = resolve(privateDataDir, "..");
    const privateInfo = await lstat(privateDataDir);
    const privateReal = await realpath(privateDataDir);
    const closureReal = await realpath(closurePath);
    assert.equal(basename(captureRoot), expectedDatabase);
    assert.equal(resolve(closurePath), resolve(captureRoot, "beta-report-closure-state.json"));
    assert.ok(privateInfo.isDirectory() && !privateInfo.isSymbolicLink());
    assert.ok(!relative(captureRoot, privateReal).startsWith(".."));
    assert.ok(!relative(captureRoot, closureReal).startsWith(".."));
    const closure = createReportClosureStateStore(closurePath);
    assert.equal((await closure.readAuthoritativeClosure()).betaEndedAt, null,
      "the rollback probe requires an open, immutable external closure fixture");
    const ownerRow = first<{ id: string }>(await observer.db.execute(sql`SELECT id::text AS id FROM oid_owner WHERE admission_status='admitted' ORDER BY created_at LIMIT 1`));
    const before = await readonlyCounts(observer.db);
    const ownerId = ownerRow.id;
    let positiveBinding = false;
    let foreignDenied = false;
    let jsonRoundTrip = false;
    let deletionArraysRoundTrip = false;
    let dstSeconds = 0;
    let dstCalendarDays = 0;
    let rollbackConfirmed = false;
    const ownUploadId = randomUUID();
    const ownStorageKey = randomUUID();
    const foreignAgentId = randomUUID();
    const foreignUploadId = randomUUID();
    const receipts = [randomUUID(), randomUUID()];

    try {
      await owner.db.transaction(async (outerTx) => {
        await outerTx.execute(sql.raw("SET LOCAL TIME ZONE 'America/New_York'"));
        const dst = first<{ seconds: string | number; calendar: string | number }>(await outerTx.execute(sql`
          WITH start_time AS (SELECT '2026-03-07 12:00:00-05'::timestamptz AS value)
          SELECT extract(epoch FROM (${reportRetentionDeadline(sql.raw("value"))})-value)::bigint AS seconds,
            extract(epoch FROM (value+interval '30 days')-value)::bigint AS calendar FROM start_time
        `));
        dstSeconds = Number(dst.seconds);
        dstCalendarDays = Number(dst.calendar);
        assert.equal(dstSeconds, 2592000, "retention must use an absolute 720-hour interval across DST");
        assert.equal(dstCalendarDays, 2588400, "the regression fixture must cross the spring DST boundary");

        await insertReadyUpload(outerTx, { uploadId: ownUploadId, ownerId, uploaderKind: "owner", uploaderId: ownerId,
          uploaderAgentId: null, storageKey: ownStorageKey, operationId: randomUUID().replaceAll("-", "") });
        const wrappedDb = Object.create(owner.db) as OwnerDatabase;
        Object.defineProperty(wrappedDb, "transaction", { value: (callback: (tx: typeof outerTx) => unknown) => callback(outerTx) });
        const dependencies: ReportServiceDependencies = { db: wrappedDb, privateDataDir,
          reportClosureState: closure };
        const ownOperation = randomUUID().replaceAll("-", "");
        const created = await createSupportReport(dependencies, { kind: "owner", ownerId, requestId: "pg-report-regression" }, {
          operationId: ownOperation, title: "Isolated report binding regression", body: "Synthetic forced-rollback report.", imageUploadIds: [ownUploadId]
        });
        const createdReportId = String(created.report.id);
        assert.equal(created.replayed, false);
        assert.equal(Array.isArray(created.report.images) && created.report.images.length === 1, true,
          "the service must create and return its own principal's attached image");
        const persisted = first<{ safe_context: Record<string, unknown>; metadata: Record<string, unknown>; status: string; report_id: string }>(await outerTx.execute(sql`
          SELECT r.safe_context,a.metadata,u.status,u.report_id::text
          FROM oid_support_report r JOIN oid_support_report_audit a ON a.report_id=r.id
          JOIN oid_support_image_upload u ON u.id=${ownUploadId}::uuid WHERE r.id=${createdReportId}::uuid
        `));
        jsonRoundTrip = persisted.safe_context.requestId === "pg-report-regression" && persisted.metadata.imageCount === 1;
        positiveBinding = persisted.status === "attached" && persisted.report_id === createdReportId;
        assert.equal(jsonRoundTrip, true, "raw JSON report context and audit metadata must round-trip through PostgreSQL");
        assert.equal(positiveBinding, true, "the ready screenshot must attach to its own report principal");

        await outerTx.execute(sql`INSERT INTO oid_agent(id,owner_id,name,description) VALUES(
          ${foreignAgentId}::uuid,${ownerId}::uuid,'Report PG foreign principal fixture','Synthetic negative regression')`);
        await insertReadyUpload(outerTx, { uploadId: foreignUploadId, ownerId, uploaderKind: "agent", uploaderId: foreignAgentId,
          uploaderAgentId: foreignAgentId, storageKey: randomUUID(), operationId: randomUUID().replaceAll("-", "") });
        try {
          await createSupportReport(dependencies, { kind: "owner", ownerId }, {
            operationId: randomUUID().replaceAll("-", ""), title: "Foreign image binding regression",
            body: "Synthetic foreign-principal denial probe.", imageUploadIds: [foreignUploadId]
          });
        } catch (error) {
          foreignDenied = typeof error === "object" && error !== null && "code" in error
            && (error as { code?: unknown }).code === "REPORT_IMAGE_NOT_FOUND";
        }
        assert.equal(foreignDenied, true, "an owner must not attach a ready image belonging to an agent principal");

        const statement = reportDeletionReceiptStatement({ reportId: receipts[0]!, betaEndedAt: "2026-01-01T00:00:00.000Z",
          expiresAt: "2026-01-31T00:00:00.000Z", imageCount: 1, storageKeys: [ownStorageKey], storageBytes: [173] });
        await outerTx.execute(statement);
        const populated = first<{ key: string; bytes: number; purge_status: string }>(await outerTx.execute(sql`
          SELECT pending_storage_keys[1]::text AS key,pending_storage_bytes[1] AS bytes,purge_status
          FROM oid_support_report_deletion_receipt WHERE report_id=${receipts[0]}::uuid
        `));
        await outerTx.execute(reportDeletionReceiptStatement({ reportId: receipts[1]!, betaEndedAt: "2026-01-01T00:00:00.000Z",
          expiresAt: "2026-01-31T00:00:00.000Z", imageCount: 0, storageKeys: [], storageBytes: [] }));
        const empty = first<{ keys: number; bytes: number; purge_status: string }>(await outerTx.execute(sql`
          SELECT cardinality(pending_storage_keys) AS keys,cardinality(pending_storage_bytes) AS bytes,purge_status
          FROM oid_support_report_deletion_receipt WHERE report_id=${receipts[1]}::uuid
        `));
        deletionArraysRoundTrip = populated.key === ownStorageKey && Number(populated.bytes) === 173 && populated.purge_status === "pending"
          && Number(empty.keys) === 0 && Number(empty.bytes) === 0 && empty.purge_status === "complete";
        assert.equal(deletionArraysRoundTrip, true, "typed UUID/integer deletion arrays must round-trip, including empty arrays");
        throw new Error(ROLLBACK_SENTINEL);
      });
    } catch (error) {
      rollbackConfirmed = error instanceof Error && error.message === ROLLBACK_SENTINEL;
    }
    assert.equal(rollbackConfirmed, true, "all service and fixture writes must remain inside the forced-rollback transaction");
    const after = await readonlyCounts(observer.db);
    assert.deepEqual(after, before, "the independent observer must find no persistent report, upload, audit, rate, or receipt changes");
    assert.equal(positiveBinding && foreignDenied && jsonRoundTrip && deletionArraysRoundTrip
      && dstSeconds === 2592000 && dstCalendarDays === 2588400, true);
  } finally {
    await Promise.all([owner.client.end({ timeout: 5 }), observer.client.end({ timeout: 5 })]);
  }
});
