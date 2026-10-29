import { createHash, randomUUID } from "node:crypto";
import { lstat, readFile, readdir, realpath, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import pg from "pg";
import { attachSafeBrowserCapture } from "./browser-support.mjs";
import { createCard, issueThroughUi } from "./credential-cases.mjs";
import { runLocalOperationsCases } from "./operations-cases.mjs";

const { Pool } = pg;
const SHA256_RE = /^[0-9a-f]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REPORTS = "/api/owner/reports";
function hash(value) {
  const digest = createHash("sha256");
  if (Buffer.isBuffer(value)) digest.update(value);
  else digest.update(String(value), "utf8");
  return digest.digest("hex");
}
const operationId = () => randomUUID().replaceAll("-", "");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function pathWithin(base, target) {
  const rel = relative(base, target);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`));
}

function safeBrowserError(error) {
  const name = typeof error?.name === "string" && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(error.name) ? error.name : "Error";
  const message = String(error?.message ?? "");
  const messageClass = /crypto.*subtle|subtle.*crypto/i.test(message) ? "crypto_subtle"
    : /randomuuid/i.test(message) ? "crypto_random_uuid"
      : /insecure|not secure|securityerror/i.test(message) ? "secure_context"
        : /too large|size limit|byte limit/i.test(message) ? "input_limit"
          : /failed to fetch|networkerror|network request/i.test(message) ? "network"
            : /not supported|notsupportederror/i.test(message) ? "unsupported"
              : "other";
  return { name, messageClass };
}

function safeAlertClass(text) {
  const value = String(text ?? "").toLowerCase();
  if (!value) return null;
  if (value.includes("screenshot") || value.includes("image")) return "screenshot_upload_or_validation";
  if (value.includes("server")) return "server_rejection";
  if (value.includes("request")) return "generic_request_failure";
  return "other";
}

async function ownerReportFormState(page) {
  return page.locator("form").first().evaluate((form) => {
    const title = form.querySelector("#report-title");
    const body = form.querySelector("#report-body");
    const runId = form.querySelector("#report-run");
    const taskId = form.querySelector("#report-task");
    const actionId = form.querySelector("#report-action");
    const fileInput = form.querySelector("#report-image");
    const submit = form.querySelector('button[type="submit"]');
    const file = fileInput?.files?.[0] ?? null;
    return {
      formValid: form.checkValidity(),
      titleFilled: Boolean(title?.value.trim()),
      titleLength: title?.value.length ?? 0,
      bodyFilled: Boolean(body?.value.trim()),
      bodyLength: body?.value.length ?? 0,
      runContextFilled: Boolean(runId?.value.trim()),
      taskContextFilled: Boolean(taskId?.value.trim()),
      actionContextFilled: Boolean(actionId?.value.trim()),
      screenshotSelected: Boolean(file),
      screenshotTypeAllowed: file ? ["image/png", "image/jpeg", "image/webp"].includes(file.type) : null,
      screenshotWithinLimit: file ? file.size > 0 && file.size <= 5 * 1024 * 1024 : null,
      cryptoSubtleAvailable: Boolean(globalThis.crypto && globalThis.crypto.subtle),
      submitDisabled: Boolean(submit?.disabled),
    };
  }).catch(() => ({ formStateAvailable: false }));
}

async function writeOwnerReportFailureDiagnostic({ captureRoot, page, trace, requestOffset, browserErrors,
  stage = "owner_report_submit", details = undefined }) {
  await trace.flush();
  const alertLocator = page.getByRole("alert");
  const alertText = await alertLocator.first().innerText().catch(() => "");
  const requests = trace.requests.slice(requestOffset)
    .filter((row) => row.method === "POST" && [REPORTS, "/api/owner/report-images/uploads/multipart"].includes(row.path))
    .map((row) => ({ method: row.method, path: row.path, status: row.status,
      ...(row.failed === true ? { failed: true } : {}) }));
  const errorResponses = trace.errorResponses.filter((row) => row.requestIndex >= requestOffset)
    .map(({ path, status, errorCode }) => ({ path, status, errorCode }));
  const uploadResponses = trace.uploadResponses.filter((row) => row.requestIndex >= requestOffset)
    .map(({ status, httpStatus, replayed }) => ({ status, httpStatus, replayed }));
  const diagnostic = {
    schemaVersion: "bpc-report-submit-diagnostic/v1",
    stage,
    requests,
    errorResponses,
    uploadResponses,
    ownerAlert: { visible: Boolean(alertText), messageClass: safeAlertClass(alertText) },
    form: await ownerReportFormState(page),
    pageErrors: browserErrors.slice(-8),
    ...(details ? { details } : {}),
  };
  const path = resolve(captureRoot, "report-submit-failure.json");
  assert(pathWithin(captureRoot, path), "Report failure diagnostic escaped its unique capture root");
  await writeFile(path, `${JSON.stringify(diagnostic, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

async function writeReportHtmlTextDiagnostic({ captureRoot, status, scriptElementCount, expectedTextSha256, observedTextSha256 }) {
  const diagnostic = { status, scriptElementCount, expectedTextSha256, observedTextSha256 };
  const path = resolve(captureRoot, "report-html-text-diagnostic.json");
  assert(pathWithin(captureRoot, path), "Report HTML text diagnostic escaped its unique capture root");
  await writeFile(path, `${JSON.stringify(diagnostic, null, 2)}\n`, { flag: "wx", mode: 0o600 });
}

function webpChunkInventory(bytes) {
  assert(bytes.length >= 12 && bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP",
    "Private screenshot file is not a RIFF/WebP normalized image");
  const chunks = [];
  const declaredEnd = bytes.readUInt32LE(4) + 8;
  assert(declaredEnd === bytes.length, "Normalized WebP RIFF length does not match its file size");
  let offset = 12;
  while (offset + 8 <= declaredEnd) {
    const tag = bytes.toString("ascii", offset, offset + 4);
    const size = bytes.readUInt32LE(offset + 4);
    assert(offset + 8 + size <= declaredEnd, "Normalized WebP contains an incomplete RIFF chunk");
    chunks.push(tag);
    offset += 8 + size + (size & 1);
  }
  assert(offset === declaredEnd, "Normalized WebP has an incomplete trailing RIFF chunk");
  return { chunks, metadataKeys: chunks.filter((tag) => ["EXIF", "ICCP", "XMP "].includes(tag)) };
}

function sanitizedContext(value) {
  const context = value && typeof value === "object" && !Array.isArray(value) ? { ...value } : {};
  if (typeof context.requestId === "string") context.requestId = { sha256: hash(context.requestId) };
  return context;
}

function projectReportRows(rows) {
  return rows.map((row) => ({
    id: row.id,
    ownerIdSha256: hash(row.owner_id),
    agentIdSha256: row.agent_id ? hash(row.agent_id) : null,
    source: row.source,
    reporterKind: row.reporter_kind,
    reporterIdSha256: hash(row.reporter_id),
    operationIdSha256: hash(row.operation_id),
    titleSha256: hash(row.title),
    bodySha256: hash(row.body),
    safeContext: sanitizedContext(row.safe_context),
    safeContextKeys: Object.keys(sanitizedContext(row.safe_context)).sort(),
    clientVersion: row.client_version,
    runId: row.run_id,
    runIdSha256: row.run_id ? hash(row.run_id) : null,
    taskId: row.task_id,
    actionId: row.action_id,
    status: row.status,
    revision: row.revision,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at,
    imageIds: row.image_ids,
  }));
}

async function readSnapshot(pool, ownerIds, reportIds = []) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Report evidence requires an independent read-only oid_observer transaction");
    const reports = await client.query(`SELECT r.id::text,r.owner_id::text,r.agent_id::text,r.source,r.reporter_kind,
        r.reporter_id::text,r.operation_id,r.title,r.body,r.safe_context,r.client_version,r.run_id::text,r.task_id,
        r.action_id::text,r.status,r.revision,r.created_at,r.updated_at,
        CASE WHEN s.beta_ended_at IS NULL THEN NULL ELSE s.beta_ended_at + interval '2592000 seconds' END AS expires_at,
        coalesce(array_agg(u.id::text ORDER BY u.id) FILTER (WHERE u.status='attached'),ARRAY[]::text[]) AS image_ids
      FROM oid_support_report r CROSS JOIN oid_support_report_retention_state s
      LEFT JOIN oid_support_image_upload u ON u.report_id=r.id
      WHERE r.owner_id::text=ANY($1::text[]) OR r.id::text=ANY($2::text[])
      GROUP BY r.id,s.beta_ended_at ORDER BY r.created_at DESC,r.id DESC`, [ownerIds, reportIds]);
    const uploads = await client.query(`SELECT id::text,owner_id::text,uploader_kind,uploader_id::text,operation_id,
        input_mime,expected_sha256,expected_input_bytes,input_bytes,output_bytes,output_sha256,output_mime,width,height,
        storage_key::text,status,report_id::text,created_at,updated_at,expires_at,reserved_output_bytes
      FROM oid_support_image_upload WHERE owner_id::text=ANY($1::text[]) OR report_id::text=ANY($2::text[])
      ORDER BY created_at,id`, [ownerIds, reportIds]);
    const audits = await client.query(`SELECT id::text,report_id::text,actor_owner_id::text,actor_agent_id::text,event_type,
        previous_status,next_status,revision,metadata,created_at
      FROM oid_support_report_audit WHERE report_id::text=ANY($1::text[]) OR actor_owner_id::text=ANY($2::text[])
      ORDER BY created_at,id`, [reportIds, ownerIds]);
    const imageUsageRows = await client.query(`SELECT upload_id::text,sequence,owner_id::text,input_bytes,received_at
      FROM oid_support_image_input_usage WHERE owner_id::text=ANY($1::text[]) ORDER BY received_at,upload_id,sequence`, [ownerIds]);
    const reportDeletionReceipts = await client.query(`SELECT report_id::text,beta_ended_at,expires_at,deleted_at,image_count,
        pending_storage_keys,pending_storage_bytes,purge_status,last_attempt_at,last_error_code
      FROM oid_support_report_deletion_receipt WHERE report_id::text=ANY($1::text[]) ORDER BY deleted_at,report_id`, [reportIds]);
    const uploadGcReceipts = await client.query(`SELECT id::text,storage_key::text,status,cleaned_at,reason,reserved_bytes,bytes_removed,last_error_code
      FROM oid_support_upload_gc_receipt WHERE storage_key::text=ANY($1::text[]) ORDER BY cleaned_at,id`,
      [uploads.rows.map((row) => row.storage_key).filter(Boolean)]);
    const reportRunIds = [...new Set(reports.rows.map((row) => row.run_id).filter(Boolean))];
    const runRows = await client.query(`SELECT id::text,owner_id::text,agent_id::text,mode,status,task_ids,queued_at,queue_deadline,started_at,overall_deadline,finished_at
      FROM oid_benchmark_run WHERE owner_id::text=ANY($1::text[]) OR id::text=ANY($2::text[]) ORDER BY id`, [ownerIds, reportRunIds]);
    const runIds = [...new Set([...reportRunIds, ...runRows.rows.map((row) => row.id)])];
    const taskRows = await client.query(`SELECT run_id::text,task_index,task_id,status FROM oid_run_task WHERE run_id::text=ANY($1::text[]) ORDER BY run_id,task_index`, [runIds]);
    const actionRows = await client.query(`SELECT id::text,run_id::text,owner_id::text,agent_id::text,task_id,action_sequence,action_kind,accepted_at
      FROM oid_run_task_action WHERE owner_id::text=ANY($1::text[]) OR run_id::text=ANY($2::text[]) ORDER BY accepted_at,id`, [ownerIds, runIds]);
    const timerRows = await client.query(`SELECT run_id::text,task_index,task_id,status,started_at,deadline_at,finished_at
      FROM oid_run_task WHERE run_id::text=ANY($1::text[]) ORDER BY run_id,task_index`, [runIds]);
    const financialRows = await client.query(`SELECT id::text,owner_id::text,entry_type,source_kind,operation_id,amount_units::text,
        available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,created_at
      FROM oid_ledger_entry WHERE owner_id::text=ANY($1::text[]) ORDER BY created_at,id`, [ownerIds]);
    const totalCounts = (await client.query(`SELECT
        (SELECT count(*)::int FROM oid_support_report) AS reports,
        (SELECT count(*)::int FROM oid_support_image_upload) AS uploads`)).rows[0];
    const retentionState = (await client.query(`SELECT beta_ended_at,closed_by_owner_id::text,close_operation_id,close_payload_hash
      FROM oid_support_report_retention_state WHERE id=1`)).rows[0];
    const normalize = (rows) => rows.map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, value instanceof Date ? value.toISOString() : value])));
    const mappedAudits = audits.rows.map((row) => ({
      idSha256: hash(row.id), reportId: row.report_id, actorOwnerIdSha256: hash(row.actor_owner_id),
      actorAgentIdSha256: row.actor_agent_id ? hash(row.actor_agent_id) : null, eventType: row.event_type,
      previousStatus: row.previous_status, nextStatus: row.next_status, revision: row.revision,
      metadata: row.event_type === "owner_attached_image" ? { imageCount: row.metadata?.imageIds?.length ?? null } : {}, createdAt: row.created_at,
    }));
    const mappedUploads = uploads.rows.map((row) => ({
      id: row.id, idSha256: hash(row.id), ownerIdSha256: hash(row.owner_id), uploaderKind: row.uploader_kind,
      uploaderIdSha256: hash(row.uploader_id), operationIdSha256: hash(row.operation_id), inputMime: row.input_mime,
      inputSha256: row.expected_sha256, expectedInputBytes: row.expected_input_bytes, inputBytes: row.input_bytes,
      outputBytes: row.output_bytes, outputSha256: row.output_sha256, outputMime: row.output_mime,
      width: row.width, height: row.height, storageKeySha256: row.storage_key ? hash(row.storage_key) : null,
      status: row.status, reportId: row.report_id, reservedOutputBytes: row.reserved_output_bytes,
      createdAt: row.created_at, expiresAt: row.expires_at,
    }));
    const mapReceipts = reportDeletionReceipts.rows.map((row) => ({
      reportId: row.report_id, betaEndedAt: row.beta_ended_at, expiresAt: row.expires_at, deletedAt: row.deleted_at,
      imageCount: row.image_count,
      pendingStorageKeySha256s: row.pending_storage_keys.map((key) => hash(key)),
      pendingStorageBytes: row.pending_storage_bytes, purgeStatus: row.purge_status, lastAttemptAt: row.last_attempt_at,
      lastErrorCode: row.last_error_code,
    }));
    const mapGc = uploadGcReceipts.rows.map((row) => ({
      idSha256: hash(row.id), storageKeySha256: row.storage_key ? hash(row.storage_key) : null,
      status: row.status, cleanedAt: row.cleaned_at, reason: row.reason, reservedBytes: row.reserved_bytes,
      bytesRemoved: row.bytes_removed, lastErrorCode: row.last_error_code,
    }));
    const reportRows = projectReportRows(normalize(reports.rows));
    await client.query("COMMIT");
    return {
      identity: { databaseRole: identity.role, databaseName: identity.database_name, transactionReadOnly: identity.transaction_read_only },
      totalCounts,
      retentionState: retentionState ? {
        betaEndedAt: retentionState.beta_ended_at instanceof Date ? retentionState.beta_ended_at.toISOString() : retentionState.beta_ended_at,
        closedByOwnerIdSha256: retentionState.closed_by_owner_id ? hash(retentionState.closed_by_owner_id) : null,
        closeOperationIdSha256: retentionState.close_operation_id ? hash(retentionState.close_operation_id) : null,
        closePayloadHash: retentionState.close_payload_hash,
      } : null,
      reports: reportRows,
      audits: mappedAudits,
      uploads: mappedUploads,
      imageUsageRows: normalize(imageUsageRows.rows).map((row) => ({ uploadIdSha256: hash(row.upload_id), ownerIdSha256: hash(row.owner_id), sequence: row.sequence, inputBytes: row.input_bytes, receivedAt: row.received_at })),
      reportDeletionReceipts: mapReceipts,
      uploadGcReceipts: mapGc,
      financialRows: normalize(financialRows.rows).map((row) => ({ idSha256: hash(row.id), ownerIdSha256: hash(row.owner_id), entryType: row.entry_type, sourceKind: row.source_kind, operationIdSha256: hash(row.operation_id), amountUnits: row.amount_units, availableDeltaUnits: row.available_delta_units, reservedDeltaUnits: row.reserved_delta_units, expiredDeltaUnits: row.expired_delta_units, createdAt: row.created_at })),
      runRows: normalize(runRows.rows).map((row) => ({ id: row.id, idSha256: hash(row.id), ownerIdSha256: hash(row.owner_id), agentIdSha256: hash(row.agent_id), mode: row.mode, status: row.status, taskIds: row.task_ids, queuedAt: row.queued_at, queueDeadline: row.queue_deadline, startedAt: row.started_at, overallDeadline: row.overall_deadline, finishedAt: row.finished_at })),
      taskRows: normalize(taskRows.rows).map((row) => ({ runId: row.run_id, runIdSha256: hash(row.run_id), taskIndex: row.task_index, taskId: row.task_id, status: row.status })),
      actionRows: normalize(actionRows.rows).map((row) => ({ id: row.id, runId: row.run_id, ownerIdSha256: hash(row.owner_id), agentIdSha256: hash(row.agent_id), taskId: row.task_id, actionSequence: row.action_sequence, actionKind: row.action_kind, acceptedAt: row.accepted_at })),
      timerRows: normalize(timerRows.rows).map((row) => ({ runId: row.run_id, runIdSha256: hash(row.run_id), taskIndex: row.task_index, taskId: row.task_id, status: row.status, startedAt: row.started_at, deadlineAt: row.deadline_at, finishedAt: row.finished_at })),
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function readRateLimitSnapshot(pool, windowSeconds) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Rate-limit evidence requires an independent read-only oid_observer transaction");
    const clock = (await client.query(`SELECT floor(extract(epoch FROM clock_timestamp()))::bigint AS epoch_seconds`)).rows[0];
    const databaseClockEpochSeconds = Number(clock?.epoch_seconds);
    assert(Number.isSafeInteger(databaseClockEpochSeconds) && databaseClockEpochSeconds > 0
      && Number.isSafeInteger(windowSeconds) && windowSeconds > 0,
    "The independent observer returned an invalid rate-limit database clock");
    const bucketIndex = Math.floor(databaseClockEpochSeconds / windowSeconds);
    const currentBucketRows = await client.query(`SELECT key_hash,bucket_start,request_count
      FROM oid_rate_limit WHERE bucket_start=$1 ORDER BY key_hash`, [bucketIndex]);
    const rows = currentBucketRows.rows.map((row) => ({
      keyHashSha256: hash(row.key_hash),
      bucketStart: Number(row.bucket_start),
      requestCount: Number(row.request_count),
    }));
    await client.query("COMMIT");
    return {
      identity: { databaseRole: identity.role, databaseName: identity.database_name,
        transactionReadOnly: identity.transaction_read_only },
      databaseClockEpochSeconds,
      bucketIndex,
      bucketStartSeconds: bucketIndex * windowSeconds,
      rows,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function privateImageSnapshot(privateDataDir, uploads) {
  const root = await realpath(resolve(privateDataDir));
  const directory = resolve(root, "reports", "images");
  const directoryInfo = await lstat(directory);
  const realDirectory = await realpath(directory);
  assert(directoryInfo.isDirectory() && !directoryInfo.isSymbolicLink() && pathWithin(root, realDirectory),
    "Report image storage directory is not a private directory under the configured data root");
  let names = [];
  try { names = await readdir(directory); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  const byStorageHash = new Map(uploads.filter((row) => row.storageKeySha256).map((row) => [row.storageKeySha256, row]));
  const images = [];
  for (const name of names.filter((entry) => /^[0-9a-f-]{36}\.webp$/i.test(entry)).sort()) {
    const storageKeySha256 = hash(name.slice(0, -5));
    const upload = byStorageHash.get(storageKeySha256);
    const path = join(directory, name);
    const info = await lstat(path);
    const bytes = await readFile(path);
    const resolvedPath = await realpath(path);
    assert(info.isFile() && !info.isSymbolicLink() && pathWithin(realDirectory, resolvedPath),
      "Report image file is not a regular file contained in the private image directory");
    const contentHash = hash(bytes);
    const chunks = webpChunkInventory(bytes);
    images.push({
      imageId: upload?.id ?? null,
      reportId: upload?.reportId ?? null,
      sha256FromDatabase: upload?.outputSha256 ?? null,
      sha256FromDisk: contentHash,
      databaseBytes: upload?.outputBytes ?? null,
      diskBytes: info.size,
      modeBits: info.mode & 0o777,
      contentType: "image/webp",
      webpChunks: chunks.chunks,
      metadataKeys: chunks.metadataKeys,
      storageKeySha256,
      privateRootSha256: hash(directory),
      parentDirectorySha256: hash(directory),
    });
  }
  return images;
}

async function createLinkedRunFixture(databaseUrl, ownerId) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1, application_name: "bpc-report-linked-run-fixture" });
  const agentId = randomUUID();
  const intentId = randomUUID();
  const runId = randomUUID();
  const op = operationId();
  const checksum = hash(op);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO oid_agent(id,owner_id,name,description) VALUES($1,$2,'Report acceptance fixture','Private linked run context')", [agentId, ownerId]);
    await client.query("INSERT INTO oid_agent_policy(agent_id,training,ranked) VALUES($1,false,false)", [agentId]);
    await client.query(`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
        benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,precision,cash_ceiling_units,owner_policy_revision,
        agent_policy_revision,status,expires_at)
      VALUES($1,$2,$3,$4,$5,'training',ARRAY['S1'],'report-acceptance-fixture/v1','local-test','${"a".repeat(64)}','${"b".repeat(64)}','${"c".repeat(64)}',0,6,0,0,1,'accepted',clock_timestamp()+interval '1 day')`,
      [intentId, ownerId, agentId, op, checksum]);
    await client.query(`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queue_deadline)
      VALUES($1,$2,$3,$4,'training',ARRAY['S1'],'report-acceptance-fixture/v1','local-test','${"a".repeat(64)}','${"b".repeat(64)}','${"c".repeat(64)}',0,0,1,1,'queued',clock_timestamp()+interval '1 day')`,
      [runId, intentId, ownerId, agentId]);
    await client.query("UPDATE oid_run_launch_intent SET run_id=$2 WHERE id=$1", [intentId, runId]);
    await client.query("COMMIT");
    return { agentId, runId };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); await pool.end(); }
}

async function createForeignAgentUploadFixture(databaseUrl, ownerId) {
  const pool = new Pool({ connectionString: databaseUrl, max: 1, application_name: "bpc-report-foreign-image-fixture" });
  const agentId = randomUUID();
  const uploadId = randomUUID();
  const storageKey = randomUUID();
  const operation = operationId();
  const digest = "d".repeat(64);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO oid_agent(id,owner_id,name,description) VALUES($1,$2,'Foreign image principal fixture','Synthetic SC024 denial fixture')", [agentId, ownerId]);
    await client.query(`INSERT INTO oid_support_image_upload(id,owner_id,uploader_kind,uploader_id,uploader_agent_id,operation_id,payload_hash,
        input_mime,expected_sha256,expected_input_bytes,input_bytes,reserved_output_bytes,output_bytes,output_sha256,output_mime,width,height,
        storage_key,status,expires_at)
      VALUES($1,$2,'agent',$3,$3,$4,$5,'image/png',$5,1,1,0,1,$5,'image/webp',1,1,$6,'ready',clock_timestamp()+interval '1 day')`,
    [uploadId, ownerId, agentId, operation, digest, storageKey]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    await client.release();
    await pool.end();
    throw error;
  }
  client.release();
  let poolEnded = false;
  const endPool = async () => {
    if (poolEnded) return;
    poolEnded = true;
    await pool.end();
  };
  return {
    uploadId,
    async cleanup() {
      const cleanupClient = await pool.connect();
      try {
        await cleanupClient.query("BEGIN");
        const upload = await cleanupClient.query("DELETE FROM oid_support_image_upload WHERE id=$1 AND owner_id=$2 AND report_id IS NULL RETURNING id", [uploadId, ownerId]);
        const agent = await cleanupClient.query("DELETE FROM oid_agent WHERE id=$1 AND owner_id=$2 RETURNING id", [agentId, ownerId]);
        assert(upload.rowCount === 1 && agent.rowCount === 1,
          "The rejected foreign-image fixture changed before its isolated cleanup");
        await cleanupClient.query("COMMIT");
      } catch (error) {
        await cleanupClient.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        cleanupClient.release();
        await endPool();
      }
    },
    close: endPool,
  };
}

export function browserEvidence(capture, publicOrigin, trace) {
  const capturedRows = capture?.capture ?? capture;
  if (!capturedRows || !Array.isArray(capturedRows.actions)) {
    throw new TypeError("Report browser evidence requires a capture with an actions array");
  }
  if (!trace || !Array.isArray(trace.requests) || !Array.isArray(trace.responses)) {
    throw new TypeError("Report browser evidence requires request and response trace arrays");
  }
  const actions = capturedRows.actions.map((row) => {
    if (typeof row?.action !== "string" || typeof row?.selector !== "string") {
      throw new TypeError("Report browser evidence contains an invalid action row");
    }
    return { action: row.action, controlId: row.selector };
  });
  const requests = trace.requests.map((row) => ({
    method: row.method,
    path: row.path,
    status: row.status,
    ...(typeof row.operationId === "string" ? { operationIdSha256: hash(row.operationId) } : {}),
    ...(typeof row.expectedRevision === "number" ? { expectedRevision: row.expectedRevision } : {}),
    ...(row.failed === true ? { failed: true } : {}),
  }));
  return {
    originScheme: new URL(publicOrigin).protocol.slice(0, -1),
    actions,
    requests,
    responses: trace.responses,
  };
}

function mergeBrowserEvidence(left, right) {
  return {
    originScheme: left.originScheme,
    actions: [...left.actions, ...right.actions],
    requests: [...left.requests, ...right.requests],
    responses: [...left.responses, ...right.responses],
  };
}

function trackBrowserRequests(page) {
  const requests = [];
  const records = new WeakMap();
  const errorResponses = [];
  const uploadResponses = [];
  const pendingErrorResponses = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (!["127.0.0.1", "localhost"].includes(url.hostname)) return;
    const row = { method: request.method(), path: url.pathname, status: null };
    try {
      const body = request.postDataJSON();
      if (typeof body?.operationId === "string") row.operationId = body.operationId;
      if (typeof body?.expectedRevision === "number") row.expectedRevision = body.expectedRevision;
    } catch { /* Request bodies are not copied into acceptance evidence. */ }
    records.set(request, row);
    requests.push(row);
  });
  const responses = [];
  page.on("response", (response) => {
    const request = response.request();
    const row = records.get(request);
    if (row) row.status = response.status();
    const url = new URL(response.url());
    if (["127.0.0.1", "localhost"].includes(url.hostname)) {
      responses.push({ method: request.method(), path: url.pathname, status: response.status() });
      if (response.status() >= 400 && request.method() === "POST"
        && [REPORTS, "/api/owner/report-images/uploads/multipart"].includes(url.pathname)) {
        const requestIndex = requests.indexOf(row);
        const pending = response.json().then((payload) => {
          const rawCode = payload?.error?.code ?? payload?.code;
          const errorCode = typeof rawCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawCode) ? rawCode : null;
          errorResponses.push({ requestIndex, path: url.pathname, status: response.status(), errorCode });
        }).catch(() => {
          errorResponses.push({ requestIndex, path: url.pathname, status: response.status(), errorCode: null });
        });
        pendingErrorResponses.push(pending);
      }
      if (request.method() === "POST" && url.pathname === "/api/owner/report-images/uploads/multipart"
        && response.status() < 400) {
        const requestIndex = requests.indexOf(row);
        const pending = response.json().then((payload) => {
          const rawStatus = payload?.upload?.status;
          const status = typeof rawStatus === "string" && ["receiving", "ready", "attached", "processing", "failed"].includes(rawStatus)
            ? rawStatus : null;
          uploadResponses.push({ requestIndex, status, httpStatus: response.status(),
            replayed: typeof payload?.replayed === "boolean" ? payload.replayed : null });
        }).catch(() => {
          uploadResponses.push({ requestIndex, status: null, httpStatus: response.status(), replayed: null });
        });
        pendingErrorResponses.push(pending);
      }
    }
  });
  page.on("requestfailed", (request) => {
    const row = records.get(request);
    if (row) row.failed = true;
  });
  return { requests, responses, errorResponses, uploadResponses, flush: () => Promise.all(pendingErrorResponses) };
}

async function readOwnerCounts(pool, ownerId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Report negative evidence requires a read-only oid_observer transaction");
    const counts = (await client.query(`SELECT
      (SELECT count(*)::int FROM oid_support_report WHERE owner_id=$1::uuid) AS reports,
      (SELECT count(*)::int FROM oid_support_image_upload WHERE owner_id=$1::uuid) AS uploads`, [ownerId])).rows[0];
    await client.query("COMMIT");
    return { databaseRole: identity.role, transactionReadOnly: identity.transaction_read_only,
      reportRows: counts.reports, uploadRows: counts.uploads };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function readMalformedUploadHousekeepingState(pool, uploadIds) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,current_database() AS database_name,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Malformed-upload housekeeping evidence requires an independent read-only oid_observer transaction");
    const uploads = await client.query(`SELECT id::text,status FROM oid_support_image_upload
      WHERE id=ANY($1::uuid[]) ORDER BY id`, [uploadIds]);
    const receiptCount = (await client.query(`SELECT count(*)::int AS count FROM oid_support_upload_gc_receipt
      WHERE status='complete' AND reason='failed_upload'`)).rows[0];
    await client.query("COMMIT");
    return {
      observerIdentity: { databaseRole: identity.role, databaseName: identity.database_name,
        transactionReadOnly: identity.transaction_read_only },
      uploads: uploads.rows,
      completeFailedUploadGcReceiptCount: receiptCount.count,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function waitForMalformedUploadHousekeeping({ observerPool, uploadIds, baseline }) {
  const timeoutMs = 15_000;
  const pollIntervalMs = 350;
  assert(uploadIds.length === 4 && new Set(uploadIds).size === 4,
    "Malformed-upload housekeeping must observe the three corrupt and one SVG staging uploads");
  const startedAt = Date.now();
  const deadline = startedAt + timeoutMs;
  let pollCount = 0;
  let state;
  const observedStatuses = new Set();
  do {
    state = await readMalformedUploadHousekeepingState(observerPool, uploadIds);
    pollCount++;
    for (const upload of state.uploads) {
      observedStatuses.add(upload.status);
      assert(upload.status === "failed",
        "A malformed screenshot upload was not in the failed state while awaiting natural housekeeping");
    }
    if (state.uploads.length === 0) break;
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, Math.min(pollIntervalMs, remainingMs)));
  } while (Date.now() < deadline);

  assert(state?.uploads.length === 0,
    "Malformed screenshot uploads did not disappear through natural housekeeping within 15 seconds");
  assert(state.observerIdentity.databaseRole === baseline.observerIdentity.databaseRole
    && state.observerIdentity.databaseName === baseline.observerIdentity.databaseName
    && state.observerIdentity.transactionReadOnly === baseline.observerIdentity.transactionReadOnly,
  "Malformed-upload housekeeping observer identity changed during the isolated staging probe");
  const receiptDelta = state.completeFailedUploadGcReceiptCount - baseline.completeFailedUploadGcReceiptCount;
  assert(receiptDelta >= 0, "The isolated failed-upload GC receipt count moved backwards during staging cleanup");
  return {
    scope: "fresh_isolated_capture_malformed_staging_housekeeping",
    separateFromAuthorizationEffects: true,
    observerIdentity: state.observerIdentity,
    baselineCapturedAt: "before_malformed_upload_staging",
    namedStagedUploadIdSha256s: uploadIds.map((uploadId) => hash(uploadId)).sort(),
    namedStagedUploadCount: uploadIds.length,
    namedStagedUploadRowsRemaining: state.uploads.length,
    observedStagingStatuses: [...observedStatuses].sort(),
    pollCount,
    pollIntervalMs,
    elapsedMs: Date.now() - startedAt,
    timeoutMs,
    completeFailedUploadGcReceiptCountBeforeStaging: baseline.completeFailedUploadGcReceiptCount,
    completeFailedUploadGcReceiptCountAfterSettlement: state.completeFailedUploadGcReceiptCount,
    completeFailedUploadGcReceiptCountDelta: receiptDelta,
    gcReceiptBinding: "aggregate_only_no_per_upload_id_binding",
  };
}

async function observeOwnerPost({ page, observerPool, ownerId, publicOrigin, name, path, data, multipart, expectedStatuses }) {
  const before = await readOwnerCounts(observerPool, ownerId);
  const requestOptions = { headers: { origin: publicOrigin }, ...(multipart ? { multipart } : { data }) };
  const response = await page.request.post(new URL(path, publicOrigin).toString(), requestOptions);
  const payload = await response.json().catch(() => ({}));
  const after = await readOwnerCounts(observerPool, ownerId);
  assert(expectedStatuses.includes(response.status()), `${name} returned unexpected HTTP ${response.status()}`);
  return {
    name, responseStatus: response.status(), errorCode: payload?.error?.code ?? payload?.code ?? null,
    databaseRole: after.databaseRole, transactionReadOnly: after.transactionReadOnly,
    reportRowsBefore: before.reportRows, reportRowsAfter: after.reportRows,
    uploadRowsBefore: before.uploadRows, uploadRowsAfter: after.uploadRows,
  };
}

async function postOwnerReportAttempt(options) {
  return observeOwnerPost({ ...options, path: REPORTS });
}

function reportNegativeState(snapshot) {
  return {
    totalCounts: snapshot.totalCounts,
    reports: snapshot.reports,
    audits: snapshot.audits,
    uploads: snapshot.uploads,
    imageUsageRows: snapshot.imageUsageRows,
    reportDeletionReceipts: snapshot.reportDeletionReceipts,
    uploadGcReceipts: snapshot.uploadGcReceipts,
  };
}

function domainSideEffectState(snapshot) {
  return {
    financialRows: snapshot.financialRows,
    runRows: snapshot.runRows,
    taskRows: snapshot.taskRows,
    actionRows: snapshot.actionRows,
    timerRows: snapshot.timerRows,
  };
}

function reportDomainEffectEvidence(before, after) {
  const reportStateBeforeJson = JSON.stringify(reportNegativeState(before));
  const reportStateAfterJson = JSON.stringify(reportNegativeState(after));
  const domainStateBeforeJson = JSON.stringify(domainSideEffectState(before));
  const domainStateAfterJson = JSON.stringify(domainSideEffectState(after));
  const noReportOrDomainEffects = reportStateBeforeJson === reportStateAfterJson
    && domainStateBeforeJson === domainStateAfterJson;
  return {
    effectScope: "report_and_domain_rows_excluding_oid_rate_limit",
    reportStateBeforeJson,
    reportStateAfterJson,
    domainStateBeforeJson,
    domainStateAfterJson,
    reportStateBeforeSha256: hash(reportStateBeforeJson),
    reportStateAfterSha256: hash(reportStateAfterJson),
    domainStateBeforeSha256: hash(domainStateBeforeJson),
    domainStateAfterSha256: hash(domainStateAfterJson),
    noReportOrDomainEffects,
  };
}

async function observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds = [ownerId], publicOrigin, name, method = "POST",
  path = REPORTS, data = undefined, expectedStatus, expectedErrorCode }) {
  const before = await readSnapshot(observerPool, observerOwnerIds);
  const url = new URL(path, publicOrigin).toString();
  const options = method === "GET" ? {} : { headers: { origin: publicOrigin }, data };
  const response = method === "GET"
    ? await page.request.get(url, options)
    : await page.request[method.toLowerCase()](url, options);
  const payload = await response.json().catch(() => ({}));
  const after = await readSnapshot(observerPool, observerOwnerIds);
  const rawErrorCode = payload?.error?.code ?? payload?.code;
  const errorCode = typeof rawErrorCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawErrorCode) ? rawErrorCode : null;
  assert(response.status() === expectedStatus && errorCode === expectedErrorCode,
    `${name} returned HTTP ${response.status()} with ${errorCode ?? "no safe error code"}`);
  const reportStateBefore = hash(JSON.stringify(reportNegativeState(before)));
  const reportStateAfter = hash(JSON.stringify(reportNegativeState(after)));
  const domainStateBefore = hash(JSON.stringify(domainSideEffectState(before)));
  const domainStateAfter = hash(JSON.stringify(domainSideEffectState(after)));
  assert(reportStateBefore === reportStateAfter,
    `${name} changed report, upload, audit, receipt, or usage state`);
  assert(domainStateBefore === domainStateAfter,
    `${name} changed financial, run, task, action, or timer state`);
  return {
    name,
    transport: "authenticated_http_request_from_browser_context",
    responseStatus: response.status(),
    errorCode,
    databaseRole: after.identity.databaseRole,
    transactionReadOnly: after.identity.transactionReadOnly,
    reportRowsBefore: before.totalCounts.reports,
    reportRowsAfter: after.totalCounts.reports,
    uploadRowsBefore: before.totalCounts.uploads,
    uploadRowsAfter: after.totalCounts.uploads,
    effectScope: "report_and_domain_rows_excluding_oid_rate_limit",
    reportStateBeforeSha256: reportStateBefore,
    reportStateAfterSha256: reportStateAfter,
    domainStateBeforeSha256: domainStateBefore,
    domainStateAfterSha256: domainStateAfter,
  };
}

async function exerciseOwnerReportFlood({ page, observerPool, observerOwnerIds, publicOrigin }) {
  const rateLimitMax = 120; // The pinned local acceptance API starts with OID_AUTH_RATE_LIMIT_MAX=120.
  const windowSeconds = 60;
  const attemptCap = rateLimitMax + 1;
  const waitMs = windowSeconds * 1000 - (Date.now() % (windowSeconds * 1000));
  if (waitMs < 15_000) await new Promise((resolveDelay) => setTimeout(resolveDelay, waitMs + 50));
  const startedAt = Date.now();
  const before = await readSnapshot(observerPool, observerOwnerIds);
  const rateBefore = await readRateLimitSnapshot(observerPool, windowSeconds);
  const bucketStartSeconds = rateBefore.bucketStartSeconds;
  assert(Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds === bucketStartSeconds,
    "The local API and independent database observer disagree on the rate-limit window");
  const prefillAttempts = [];
  for (let index = 0; index < attemptCap; index++) {
    assert(Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds === bucketStartSeconds,
      "The bounded report flood crossed the configured rate-limit window before receiving a denial");
    const response = await page.request.post(new URL(REPORTS, publicOrigin).toString(), {
      headers: { origin: publicOrigin },
      data: { operationId: operationId(), title: "", body: "" },
    });
    const payload = await response.json().catch(() => ({}));
    const rawCode = payload?.error?.code ?? payload?.code;
    const errorCode = typeof rawCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawCode) ? rawCode : null;
    prefillAttempts.push({ responseStatus: response.status(), errorCode });
    if (response.status() === 429) break;
    assert(response.status() === 400 && errorCode === "INVALID_REPORT",
      "A bounded invalid report submission returned an unexpected response before the rate limit");
    assert(Date.now() - startedAt < 55_000,
      "The bounded report flood exceeded its single-window execution budget");
  }
  assert(prefillAttempts.at(-1)?.responseStatus === 429 && prefillAttempts.at(-1)?.errorCode === "RATE_LIMITED",
    "The bounded report submission loop did not reach the production per-IP 429 limiter");
  const rateBeforeValid = await readRateLimitSnapshot(observerPool, windowSeconds);
  const beforeValidRemainingMs = windowSeconds * 1000 - (Date.now() % (windowSeconds * 1000));
  assert(rateBeforeValid.bucketIndex === rateBefore.bucketIndex
    && rateBeforeValid.identity.databaseName === rateBefore.identity.databaseName
    && Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds === bucketStartSeconds
    && beforeValidRemainingMs > 15_000 && Date.now() - startedAt < 45_000,
  "The bounded prefill reached the limiter too close to a bucket rollover for a safe valid-payload denial");

  const validPayload = { operationId: operationId(), title: "Rate-limit boundary probe", body: "Bounded synthetic report submission." };
  const validPayloadShape = {
    fieldNames: Object.keys(validPayload).sort(),
    operationIdIsCanonical: /^[0-9a-f]{32}$/.test(validPayload.operationId),
    titleLength: validPayload.title.length,
    bodyLength: validPayload.body.length,
  };
  const finalResponse = await page.request.post(new URL(REPORTS, publicOrigin).toString(), {
    headers: { origin: publicOrigin }, data: validPayload,
  });
  const finalPayload = await finalResponse.json().catch(() => ({}));
  const rawFinalCode = finalPayload?.error?.code ?? finalPayload?.code;
  const finalErrorCode = typeof rawFinalCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawFinalCode) ? rawFinalCode : null;
  const rateAfter = await readRateLimitSnapshot(observerPool, windowSeconds);
  const after = await readSnapshot(observerPool, observerOwnerIds);
  const effects = reportDomainEffectEvidence(before, after);
  const elapsedMs = Date.now() - startedAt;
  assert(rateAfter.bucketIndex === rateBefore.bucketIndex && rateAfter.bucketStartSeconds === bucketStartSeconds
    && rateBefore.identity.databaseName === rateAfter.identity.databaseName
    && Math.floor(Date.now() / 1000 / windowSeconds) * windowSeconds === bucketStartSeconds && elapsedMs < 55_000,
  "The rate-limit probe did not remain inside its database-observed window");
  assert(finalResponse.status() === 429 && finalErrorCode === "RATE_LIMITED",
    "A valid report payload was not rejected by the already-saturated production rate limiter");
  assert(effects.noReportOrDomainEffects,
    "The report flood changed report, image, audit, financial, run, task, action, or timer state");
  const requestsMade = prefillAttempts.length + 1;
  const beforeByKeyHash = new Map(rateBefore.rows.map((row) => [row.keyHashSha256, row]));
  const candidates = rateAfter.rows.flatMap((row) => {
    const prior = beforeByKeyHash.get(row.keyHashSha256);
    const priorCount = prior?.bucketStart === rateBefore.bucketIndex ? prior.requestCount : 0;
    const requestCountDelta = row.requestCount - priorCount;
    return row.bucketStart === rateAfter.bucketIndex && priorCount < rateLimitMax && requestCountDelta === requestsMade
      ? [{ keyHashSha256: row.keyHashSha256, priorCount, finalCount: row.requestCount, requestCountDelta }]
      : [];
  });
  assert(candidates.length === 1,
    "The independent rate-table snapshots did not identify one unique counter row for the bounded report flood");
  const rateCounter = candidates[0];
  assert(rateCounter.priorCount + prefillAttempts.length === rateLimitMax + 1
    && rateCounter.finalCount === rateCounter.priorCount + requestsMade,
  "Observed report flood responses do not align with the persisted rate-limit counter transition");
  return {
    name: "report_flood",
    transport: "authenticated_http_request_from_browser_context",
    method: "POST", path: REPORTS,
    responseStatus: finalResponse.status(), errorCode: finalErrorCode,
    databaseRole: after.identity.databaseRole, transactionReadOnly: after.identity.transactionReadOnly,
    reportRowsBefore: before.totalCounts.reports, reportRowsAfter: after.totalCounts.reports,
    uploadRowsBefore: before.totalCounts.uploads, uploadRowsAfter: after.totalCounts.uploads,
    ...effects,
    prefillAttempts, attemptCap, configuredRateLimitMax: rateLimitMax,
    windowSeconds,
    rateLimitObservation: {
      table: "oid_rate_limit",
      group: "support-report-owner-create",
      maxPerWindow: rateLimitMax,
      windowSeconds,
      databaseRole: rateAfter.identity.databaseRole,
      databaseName: rateAfter.identity.databaseName,
      transactionReadOnly: rateAfter.identity.transactionReadOnly,
      before: {
        databaseRole: rateBefore.identity.databaseRole,
        databaseName: rateBefore.identity.databaseName,
        transactionReadOnly: rateBefore.identity.transactionReadOnly,
        databaseClockEpochSeconds: rateBefore.databaseClockEpochSeconds,
        bucketIndex: rateBefore.bucketIndex,
        bucketStartSeconds: rateBefore.bucketStartSeconds,
        rows: rateBefore.rows,
      },
      after: {
        databaseRole: rateAfter.identity.databaseRole,
        databaseName: rateAfter.identity.databaseName,
        transactionReadOnly: rateAfter.identity.transactionReadOnly,
        databaseClockEpochSeconds: rateAfter.databaseClockEpochSeconds,
        bucketIndex: rateAfter.bucketIndex,
        bucketStartSeconds: rateAfter.bucketStartSeconds,
        rows: rateAfter.rows,
      },
      targetKeyHashSha256: rateCounter.keyHashSha256,
      priorRequestCount: rateCounter.priorCount,
      finalRequestCount: rateCounter.finalCount,
      requestCountDelta: rateCounter.requestCountDelta,
    },
    elapsedMs,
    validPayloadShape, validOperationIdSha256: hash(validPayload.operationId),
  };
}

async function readIssuedAgentCredentialBinding(observerPool, { ownerId, agentId, credentialId, grantId, verifierHash }) {
  const client = await observerPool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Issued agent credential verification requires the independent read-only observer");
    const result = await client.query(`SELECT c.id::text AS credential_id,c.grant_id::text AS grant_id,
        g.owner_id::text AS owner_id,g.agent_id::text AS agent_id,g.resource,g.role,g.source,g.revoked_at,g.expires_at,
        clock_timestamp() AS observed_at
      FROM oid_agent_manual_credential c JOIN oid_agent_access_grant g ON g.id=c.grant_id
      WHERE c.id=$1::uuid AND c.grant_id=$2::uuid AND g.owner_id=$3::uuid AND g.agent_id=$4::uuid
        AND c.verifier_hash=$5`, [credentialId, grantId, ownerId, agentId, verifierHash]);
    const row = result.rows[0];
    await client.query("COMMIT");
    const iso = (value) => value instanceof Date ? value.toISOString() : value ? new Date(value).toISOString() : null;
    return {
      databaseRole: identity.role, transactionReadOnly: identity.transaction_read_only,
      matchingCredentialGrantRows: result.rowCount,
      credentialIdSha256: row ? hash(row.credential_id) : null,
      grantIdSha256: row ? hash(row.grant_id) : null,
      ownerIdSha256: row ? hash(row.owner_id) : null,
      agentIdSha256: row ? hash(row.agent_id) : null,
      grantSource: row?.source ?? null, grantRole: row?.role ?? null,
      resourceSha256: row?.resource ? hash(row.resource) : null,
      grantRevokedAt: iso(row?.revoked_at), grantExpiresAt: iso(row?.expires_at),
      observedAt: iso(row?.observed_at),
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function exerciseAgentAdminAttempt({ ownerPage, observerPool, ownerId, observerOwnerIds, publicOrigin,
  reportId, imageId, reportRevision }) {
  const setupPage = await ownerPage.context().newPage();
  let bearer = "";
  let issuedCredential;
  const credentialCapture = attachSafeBrowserCapture(setupPage, "BPC-SC-020");
  const credentialTrace = trackBrowserRequests(setupPage);
  try {
    await setupPage.goto("/agents", { waitUntil: "domcontentloaded" });
    await setupPage.getByTestId("agent-create-form").waitFor({ state: "visible" });
    const agent = await createCard(setupPage, `Report admin probe ${randomUUID().slice(0, 8)}`, credentialCapture);
    issuedCredential = await issueThroughUi(setupPage, agent.id, "issue", credentialCapture);
    bearer = issuedCredential.secret;
    assert(/^aap1_[A-Za-z0-9_-]{43}$/.test(bearer), "Owner UI credential issuance returned an unexpected bearer format");
    const resource = new URL("/api/agent", publicOrigin).toString();
    const preflightHeaders = {
      origin: publicOrigin, authorization: `Bearer ${bearer}`,
      "x-agent-id": agent.id, "x-agent-resource": resource,
    };
    const preflightResponse = await fetch(new URL("/api/agent/preflight", publicOrigin), {
      headers: preflightHeaders, credentials: "omit",
    });
    const preflightPayload = await preflightResponse.json().catch(() => ({}));
    assert(preflightResponse.status === 200 && preflightPayload?.allowed === true
      && preflightPayload?.role === "agent" && preflightPayload?.agentId === agent.id
      && preflightPayload?.resource === resource,
    "The owner-issued bearer did not pass the production cookie-free agent preflight");
    const credentialBinding = await readIssuedAgentCredentialBinding(observerPool, {
      ownerId, agentId: agent.id, credentialId: issuedCredential.credential.id, grantId: issuedCredential.credential.grantId,
      verifierHash: hash(bearer),
    });
    assert(credentialBinding.matchingCredentialGrantRows === 1 && credentialBinding.grantSource === "manual"
      && credentialBinding.grantRole === "agent" && credentialBinding.grantRevokedAt === null
      && credentialBinding.resourceSha256 === hash(resource)
      && Date.parse(credentialBinding.grantExpiresAt) > Date.parse(credentialBinding.observedAt),
      "The owner-issued agent bearer did not match its independently observed persisted verifier/grant binding");
    await credentialTrace.flush();
    const ownerUiIssuance = browserEvidence(credentialCapture, publicOrigin, credentialTrace);
    ownerUiIssuance.issueResponseIdHashes = {
      status: 201,
      agentIdSha256: hash(agent.id),
      credentialIdSha256: hash(issuedCredential.credential.id),
      grantIdSha256: hash(issuedCredential.credential.grantId),
    };
    assert(ownerUiIssuance.actions.some((row) => row.action === "click" && row.controlId === "agent-create")
      && ownerUiIssuance.actions.some((row) => row.action === "click" && row.controlId === `credential-issue-${agent.id}`)
      && ownerUiIssuance.requests.some((row) => row.method === "POST" && row.path === "/api/owner/agents" && row.status === 201)
      && ownerUiIssuance.requests.some((row) => row.method === "POST"
        && row.path === `/api/owner/agents/${agent.id}/manual-credential` && row.status === 201),
    "Owner credential evidence is missing the actual agent-create and one-time-issue UI actions");
    const bearerProof = {
      credentialSource: "owner_ui_issue_once",
      fixtureType: "synthetic_local_agent_credential",
      authorizationScheme: "Bearer",
      sessionCookiePresent: false,
      ownerUiIssuance,
      credentialBinding,
      preflight: {
        method: "GET", path: "/api/agent/preflight", responseStatus: preflightResponse.status,
        allowed: preflightPayload.allowed, role: preflightPayload.role,
        authorizationScheme: "Bearer", sessionCookiePresent: false,
        resourceMatches: preflightPayload.resource === resource,
        agentIdSha256: hash(agent.id), resourceSha256: hash(resource),
      },
      targetReportIdSha256: hash(reportId), targetImageIdSha256: hash(imageId),
    };
    const probes = [
      { probe: "admin_list", method: "GET", path: "/api/admin/reports", pathTemplate: "/api/admin/reports" },
      { probe: "admin_detail", method: "GET", path: `/api/admin/reports/${reportId}`,
        pathTemplate: "/api/admin/reports/{reportId}" },
      { probe: "admin_status", method: "PATCH", path: `/api/admin/reports/${reportId}/status`,
        pathTemplate: "/api/admin/reports/{reportId}/status",
        body: { operationId: operationId(), expectedRevision: reportRevision, status: "in_progress" } },
      { probe: "admin_image", method: "GET", path: `/api/admin/reports/${reportId}/images/${imageId}`,
        pathTemplate: "/api/admin/reports/{reportId}/images/{imageId}" },
    ];
    const attempts = [];
    for (const probe of probes) {
      const before = await readSnapshot(observerPool, observerOwnerIds, [reportId]);
      const headers = { authorization: `Bearer ${bearer}`, origin: publicOrigin };
      const requestOptions = { method: probe.method, headers, credentials: "omit" };
      if (probe.body) {
        headers["content-type"] = "application/json";
        requestOptions.body = JSON.stringify(probe.body);
      }
      let response;
      try { response = await fetch(new URL(probe.path, publicOrigin), requestOptions); }
      catch { throw new Error("Cookie-free authenticated agent admin-route probe failed at transport"); }
      const payload = await response.json().catch(() => ({}));
      const rawCode = payload?.error?.code ?? payload?.code;
      const errorCode = typeof rawCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawCode) ? rawCode : null;
      const after = await readSnapshot(observerPool, observerOwnerIds, [reportId]);
      const effects = reportDomainEffectEvidence(before, after);
      assert(response.status === 401 && errorCode === "UNAUTHORIZED",
        `The valid agent bearer received HTTP ${response.status} on the ${probe.probe} admin route`);
      assert(effects.noReportOrDomainEffects,
        `The valid agent bearer ${probe.probe} denial changed report or domain state`);
      attempts.push({
        name: "agent_admin_attempt", probe: probe.probe, method: probe.method, pathTemplate: probe.pathTemplate,
        transport: "cookie_free_agent_bearer_http", authorizationScheme: "Bearer", sessionCookiePresent: false,
        responseStatus: response.status, errorCode,
        databaseRole: after.identity.databaseRole, transactionReadOnly: after.identity.transactionReadOnly,
        reportRowsBefore: before.totalCounts.reports, reportRowsAfter: after.totalCounts.reports,
        uploadRowsBefore: before.totalCounts.uploads, uploadRowsAfter: after.totalCounts.uploads,
        ...effects,
        credentialIdSha256: credentialBinding.credentialIdSha256, grantIdSha256: credentialBinding.grantIdSha256,
        ownerIdSha256: credentialBinding.ownerIdSha256, agentIdSha256: credentialBinding.agentIdSha256,
        targetReportIdSha256: hash(reportId), targetImageIdSha256: hash(imageId),
      });
    }
    return { proof: bearerProof, attempts };
  } finally {
    bearer = "";
    if (issuedCredential) issuedCredential.secret = "";
    await setupPage.close().catch(() => undefined);
  }
}

async function createForeignRunActionFixture(databaseUrl, ownerId, foreignOwnerId) {
  assert(typeof foreignOwnerId === "string" && foreignOwnerId !== ownerId,
    "The authenticated administrator must be a distinct owner for foreign-link denial");
  const run = await createLinkedRunFixture(databaseUrl, foreignOwnerId);
  const pool = new Pool({ connectionString: databaseUrl, max: 1, application_name: "bpc-report-foreign-action-fixture" });
  const grantId = randomUUID();
  const actionId = randomUUID();
  const actionOperation = operationId();
  const actionHash = hash("synthetic-report-foreign-action-fixture/v1");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,role,access_generation,expires_at)
      VALUES($1,$2::uuid,$3::uuid,$4,'https://127.0.0.1/api/agent','agent',1,clock_timestamp()+interval '1 hour')`,
    [grantId, foreignOwnerId, run.agentId, operationId()]);
    await client.query(`INSERT INTO oid_run_task(run_id,task_index,task_id,status)
      VALUES($1::uuid,0,'S1','queued')`, [run.runId]);
    await client.query(`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,
        task_id,environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json)
      VALUES($1::uuid,$2::uuid,0,$3::uuid,$4::uuid,1,$5::uuid,'S1','report-acceptance-fixture',1,$6,$7,
        'inspect_catalog','{"fixtureOnly":true}'::jsonb)`,
    [actionId, run.runId, foreignOwnerId, run.agentId, grantId, actionOperation, actionHash]);
    await client.query("UPDATE oid_run_task SET accepted_action_sequence=1 WHERE run_id=$1::uuid AND task_index=0", [run.runId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); await pool.end(); }
  return { ownerId: foreignOwnerId, runId: run.runId, agentId: run.agentId, actionId };
}
async function exerciseOwnerReportBoundaryCases({ page, observerPool, ownerId, publicOrigin, observerOwnerIds, linked, runFixture, foreign }) {
  const foreignRun = await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "foreign_run_link", data: { operationId: operationId(), title: "Foreign run link probe",
      body: "Synthetic negative authorization probe.", agentId: foreign.agentId, runId: foreign.runId },
    expectedStatus: 404, expectedErrorCode: "REPORT_LINK_NOT_FOUND" });
  const foreignAction = await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "foreign_action_link", data: { operationId: operationId(), title: "Foreign action link probe",
      body: "Synthetic negative authorization probe.", agentId: runFixture.agentId, runId: runFixture.runId, actionId: foreign.actionId },
    expectedStatus: 404, expectedErrorCode: "REPORT_LINK_NOT_FOUND" });
  const attempts = [
    { ...foreignRun, name: "foreign_run_or_action", runIdSha256: hash(foreign.runId),
      foreignOwnerIdSha256: hash(foreign.ownerId) },
    { ...foreignAction, name: "foreign_action_link", requestRunIdSha256: hash(runFixture.runId),
      requestOwnerIdSha256: hash(ownerId), actionIdSha256: hash(foreign.actionId), actionRunIdSha256: hash(foreign.runId),
      actionOwnerIdSha256: hash(foreign.ownerId) },
  ];
  attempts.push(await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "forbidden_secret_fields", data: { operationId: operationId(), title: "Forbidden field probe",
      body: "Synthetic schema rejection probe.", accessToken: "synthetic-forbidden-field-placeholder",
      privateKey: "synthetic-forbidden-field-placeholder" },
    expectedStatus: 400, expectedErrorCode: "INVALID_REPORT" }));
  attempts.push(await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "oversized_payload", data: { operationId: operationId(), title: "Oversized request probe", body: "x".repeat(17 * 1024) },
    expectedStatus: 413, expectedErrorCode: "REQUEST_BODY_TOO_LARGE" }));
  attempts.push(await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "body_field_overlength", data: { operationId: operationId(), title: "Overlength field probe", body: "x".repeat(4001) },
    expectedStatus: 400, expectedErrorCode: "INVALID_REPORT" }));
  attempts.push(await observeReportHttpNegative({ page, observerPool, ownerId, observerOwnerIds, publicOrigin,
    name: "conflicting_retry", data: { operationId: linked.operationId, title: "Conflicting retry payload",
      body: "The committed operation is retried with a different payload." },
    expectedStatus: 409, expectedErrorCode: "IDEMPOTENCY_CONFLICT" }));
  return attempts;
}
async function exerciseImageBoundaryCases({ page, observerPool, ownerId, publicOrigin, databaseUrl }) {
  const attempts = [];
  const corruptImage = Buffer.from("not an image", "utf8");
  const svgImage = Buffer.from("<svg><script>window.__bad = true</script></svg>", "utf8");
  const staged = [];
  const housekeepingBaseline = await readMalformedUploadHousekeepingState(observerPool, []);
  const beginOne = async (bytes) => {
    const payload = { operationId: operationId(), expectedBytes: bytes.length, sha256: hash(bytes), contentType: "image/png" };
    const response = await page.request.post(new URL("/api/owner/report-images/uploads", publicOrigin).toString(), {
      headers: { origin: publicOrigin }, data: payload,
    });
    const result = await response.json().catch(() => ({}));
    assert(response.status() === 201 && typeof result?.uploadId === "string",
      `Owner screenshot upload reservation failed with HTTP ${response.status()}`);
    staged.push({ uploadId: result.uploadId, bytes, payload });
  };
  await Promise.all(Array.from({ length: 3 }, () => beginOne(corruptImage)));
  const stagingOverflow = await observeOwnerPost({ page, observerPool, ownerId, publicOrigin,
    name: "staging_capacity_race", path: "/api/owner/report-images/uploads",
    data: { operationId: operationId(), expectedBytes: corruptImage.length, sha256: hash(corruptImage), contentType: "image/png" },
    expectedStatuses: [429] });
  attempts.push(stagingOverflow);

  for (let index = 0; index < staged.length; index++) {
    const upload = staged[index];
    const chunkResponse = await page.request.post(new URL(`/api/owner/report-images/uploads/${upload.uploadId}/chunks`, publicOrigin).toString(), {
      headers: { origin: publicOrigin },
      data: { sequence: 0, sha256: hash(upload.bytes), dataBase64: upload.bytes.toString("base64") },
    });
    assert(chunkResponse.status() === 200, `Corrupt screenshot chunk ${index} was not accepted for decoder validation`);
    attempts.push(await observeOwnerPost({ page, observerPool, ownerId, publicOrigin,
      name: index === 0 ? "corrupt_image" : "corrupt_image",
      path: `/api/owner/report-images/uploads/${upload.uploadId}/finish`, data: {}, expectedStatuses: [400] }));
  }

  await beginOne(svgImage);
  const svgUpload = staged.at(-1);
  const svgChunk = await page.request.post(new URL(`/api/owner/report-images/uploads/${svgUpload.uploadId}/chunks`, publicOrigin).toString(), {
    headers: { origin: publicOrigin },
    data: { sequence: 0, sha256: hash(svgImage), dataBase64: svgImage.toString("base64") },
  });
  assert(svgChunk.status() === 200, "SVG-like screenshot bytes did not reach the bounded decoder rejection path");
  attempts.push(await observeOwnerPost({ page, observerPool, ownerId, publicOrigin,
    name: "disguised_html_or_svg", path: `/api/owner/report-images/uploads/${svgUpload.uploadId}/finish`, data: {}, expectedStatuses: [400] }));

  const oversized = Buffer.alloc(5 * 1024 * 1024 + 1, 0x41);
  attempts.push(await observeOwnerPost({ page, observerPool, ownerId, publicOrigin,
    name: "input_over_5mib", path: "/api/owner/report-images/uploads/multipart",
    multipart: {
      operationId: operationId(), expectedBytes: String(5 * 1024 * 1024),
      sha256: hash(oversized.subarray(0, 5 * 1024 * 1024)), contentType: "image/png",
      file: { name: "oversized.png", mimeType: "image/png", buffer: oversized },
    }, expectedStatuses: [413] }));

  const housekeepingObservation = await waitForMalformedUploadHousekeeping({
    observerPool, uploadIds: staged.map((upload) => upload.uploadId), baseline: housekeepingBaseline,
  });
  const foreignUpload = await createForeignAgentUploadFixture(databaseUrl, ownerId);
  try {
    const foreignAttempt = await postOwnerReportAttempt({ page, observerPool, ownerId, publicOrigin,
      name: "foreign_upload_reference", data: { operationId: operationId(), title: "Foreign screenshot reference",
        body: "The owner cannot attach a screenshot uploaded by another principal.", imageUploadIds: [foreignUpload.uploadId] },
      expectedStatuses: [404] });
    assert(foreignAttempt.errorCode === "REPORT_IMAGE_NOT_FOUND"
      && foreignAttempt.reportRowsBefore === foreignAttempt.reportRowsAfter
      && foreignAttempt.uploadRowsBefore === foreignAttempt.uploadRowsAfter,
    "A foreign principal screenshot was not denied without durable report or upload changes");
    foreignAttempt.fixturePreparation = housekeepingObservation;
    await foreignUpload.cleanup();
    attempts.push(foreignAttempt);
  } catch (error) {
    await foreignUpload.close();
    throw error;
  }
  return attempts;
}

async function readOperationReport(pool, ownerId, operation) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(`SELECT current_user AS role,
      current_setting('transaction_read_only') AS transaction_read_only`)).rows[0];
    assert(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "Response-loss evidence requires an independent read-only observer");
    const row = (await client.query(`SELECT count(*)::int AS count,min(id::text) AS id
      FROM oid_support_report WHERE owner_id=$1::uuid AND operation_id=$2`, [ownerId, operation])).rows[0];
    await client.query("COMMIT");
    return { count: row.count, reportId: row.id };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

async function captureResponseLoss({ page, capture, observerPool, ownerId, publicOrigin, captureRoot, trace, browserErrors }) {
  const title = "Report receipt after a lost response";
  const body = "The browser retries the same operation after the server accepted its first request.";
  const listResponsePromise = waitResponse(page, (response) =>
    new URL(response.url()).pathname === REPORTS && response.request().method() === "GET");
  await page.goto("/reports", { waitUntil: "domcontentloaded" });
  const listResponse = await listResponsePromise;
  const listPayload = await listResponse.json().catch(() => ({}));
  assert(listResponse.status() === 200 && Array.isArray(listPayload?.reports) && listPayload.reports.length > 0,
    `Owner report list returned HTTP ${listResponse.status()} or did not include its persisted rows`);
  const reportCards = page.locator("article.report-card");
  await reportCards.first().waitFor({ state: "visible", timeout: 15000 });
  const visibleReportCount = await reportCards.count();
  assert(visibleReportCount === listPayload.reports.length,
    "The owner report list API response did not finish rendering the same number of report cards");
  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("What happened?", { exact: true }).fill(body);
  let receivedAtServer = null;
  const requestOffset = capture.capture.requests.length;
  const postUrl = new URL(REPORTS, publicOrigin).toString();
  let completeInterception;
  const interceptionComplete = new Promise((resolve) => { completeInterception = resolve; });
  let interception = { matched: false, responseStatus: null, errorCode: null, reportReceiptPresent: false, operationIdSha256: null };
  const routeHandler = async (route) => {
    const request = route.request();
    let payload;
    try { payload = request.postDataJSON(); } catch { payload = null; }
    if (request.method() !== "POST" || payload?.title !== title || receivedAtServer) {
      await route.continue();
      return;
    }
    interception = { ...interception, matched: true,
      ...(typeof payload.operationId === "string" ? { operationIdSha256: hash(payload.operationId) } : {}) };
    try {
      const response = await route.fetch();
      const result = await response.json().catch(() => ({}));
      const rawCode = result?.error?.code ?? result?.code;
      const errorCode = typeof rawCode === "string" && /^[A-Z0-9_]{2,80}$/.test(rawCode) ? rawCode : null;
      const reportId = typeof result?.report?.id === "string" ? result.report.id : null;
      receivedAtServer = { status: response.status(), reportId, operationId: payload.operationId };
      interception = { ...interception, responseStatus: response.status(), errorCode, reportReceiptPresent: Boolean(reportId) };
      completeInterception(interception);
      await route.abort("connectionreset");
    } catch (error) {
      interception = { ...interception, routeError: safeBrowserError(error) };
      completeInterception(interception);
      await route.abort("failed").catch(() => undefined);
    }
  };
  await page.route(postUrl, routeHandler);
  await page.getByRole("button", { name: "Submit report" }).click();
  capture.action("click", "owner-report-submit-response-loss");
  let interceptionTimer;
  const interceptResult = await Promise.race([interceptionComplete,
    new Promise((resolve) => { interceptionTimer = setTimeout(() => resolve({ timedOut: true }), 15000); })]);
  clearTimeout(interceptionTimer);
  if (!receivedAtServer || ![200, 201].includes(receivedAtServer.status) || !receivedAtServer.reportId) {
    await writeOwnerReportFailureDiagnostic({ captureRoot, page, trace, requestOffset, browserErrors,
      stage: "response_loss_interception", details: { ...interception,
        timedOut: interceptResult?.timedOut === true } });
    throw new Error(`The response-loss route did not observe a committed report receipt (HTTP ${interception.responseStatus ?? "unknown"}, ${interception.errorCode ?? "no_safe_error_code"})`);
  }
  await page.getByRole("button", { name: "Retry submission" }).waitFor({ state: "visible", timeout: 15000 });
  const firstRequest = capture.capture.requests.slice(requestOffset).find((row) => row.path === REPORTS && row.method === "POST");
  assert(firstRequest?.operationId === receivedAtServer.operationId, "The captured browser operation did not match the accepted request");
  const retryResponsePromise = waitResponse(page, (response) => new URL(response.url()).pathname === REPORTS && response.request().method() === "POST");
  await page.getByRole("button", { name: "Retry submission" }).click();
  capture.action("click", "owner-report-retry-response-loss");
  const retryResponse = await retryResponsePromise;
  const retry = await retryResponse.json();
  await page.unroute(postUrl, routeHandler);
  const retryRequest = capture.capture.requests.slice(requestOffset).filter((row) => row.path === REPORTS && row.method === "POST").at(-1);
  const persisted = await readOperationReport(observerPool, ownerId, receivedAtServer.operationId);
  assert(retryRequest?.operationId === receivedAtServer.operationId && retryResponse.status() === 200
    && retry?.report?.id === receivedAtServer.reportId && persisted.count === 1 && persisted.reportId === retry.report.id,
    "The UI retry did not recover the original persisted report receipt exactly once");
  return {
    firstResponse: "lost", firstStatusAtServer: receivedAtServer.status,
    retryStatus: retryResponse.status(), operationIdSha256: hash(receivedAtServer.operationId),
    originalReportIdSha256: hash(receivedAtServer.reportId), retryReportIdSha256: hash(retry.report.id),
    persistedRowsForOperation: persisted.count, ownerListStatus: listResponse.status(),
    ownerListRows: listPayload.reports.length, ownerListCardsRendered: visibleReportCount,
  };
}

async function waitResponse(page, predicate) {
  return page.waitForResponse(predicate, { timeout: 15000 });
}

export async function captureOwnerReport({ page, capture, title, body, linkedRunId, linkedTaskId, linkedActionId,
  imageBuffer, trace, captureRoot, browserErrors,
  onAcceptedReport }) {
  assert(!linkedTaskId || linkedRunId, "A linked report task requires a linked run");
  assert(!linkedActionId || linkedRunId, "A linked report action requires a linked run");
  await page.goto("/reports", { waitUntil: "domcontentloaded" });
  const requestOffset = capture.capture.requests.length;
  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("What happened?", { exact: true }).fill(body);
  if (linkedRunId) {
    await page.getByText("Optional run context").click();
    await page.getByLabel("Run ID").fill(linkedRunId);
    if (linkedTaskId) await page.getByLabel("Task ID").fill(linkedTaskId);
    if (linkedActionId) await page.getByLabel("Action ID").fill(linkedActionId);
  }
  if (imageBuffer) await page.locator("#report-image").setInputFiles({ name: "private-fixture.png", mimeType: "image/png", buffer: imageBuffer });
  const responsePromise = waitResponse(page, (response) => new URL(response.url()).pathname === REPORTS && response.request().method() === "POST");
  await page.getByRole("button", { name: "Submit report" }).click();
  capture.action("click", linkedRunId ? "owner-report-submit-linked" : "owner-report-submit-unlinked");
  let response;
  try { response = await responsePromise; }
  catch (error) {
    await writeOwnerReportFailureDiagnostic({ captureRoot, page, trace, requestOffset, browserErrors });
    throw error;
  }
  const payload = await response.json().catch(() => ({}));
  if (![200, 201].includes(response.status()) || !payload?.report?.id) {
    await writeOwnerReportFailureDiagnostic({ captureRoot, page, trace, requestOffset, browserErrors });
    throw new Error("Owner report UI did not return its persisted report receipt");
  }
  const operation = capture.capture.requests.slice(requestOffset).find((row) => row.method === "POST" && row.path === REPORTS && typeof row.operationId === "string")?.operationId;
  assert(typeof operation === "string", "The browser request trace did not record the report operation id");
  let requestPayload;
  try { requestPayload = response.request().postDataJSON(); } catch { requestPayload = null; }
  assert(requestPayload && requestPayload.operationId === operation && requestPayload.title === title
    && requestPayload.body === body && requestPayload.runId === (linkedRunId ?? undefined)
    && requestPayload.taskId === (linkedTaskId ?? undefined) && requestPayload.actionId === (linkedActionId ?? undefined)
    && Array.isArray(requestPayload.imageUploadIds),
  "The accepted report request body could not be correlated to the browser operation");
  const successNotice = page.getByRole("status").filter({ hasText: payload.replayed ? "Your report receipt was recovered." : "Your report was submitted." });
  await successNotice.waitFor({ state: "visible", timeout: 15000 });
  if (typeof onAcceptedReport === "function") {
    await onAcceptedReport({ reportId: payload.report.id, operationId: operation, payload: requestPayload,
      responseStatus: response.status(), replayed: payload.replayed === true });
  }
  return { reportId: payload.report.id, replayed: payload.replayed === true, operationId: operation, responseStatus: response.status(), payload };
}

export async function runReportCases({
  adminPage, ownerPage, ownerId, publicOrigin, databaseUrl, observerDatabaseUrl,
  captureIsolationRoot, privateDataDir, closureStatePath, isolatedAcceptance = false,
  genuineRunContext = null, onAcceptedReport,
}) {
  assert(isolatedAcceptance === true, "Report acceptance requires a unique isolated acceptance database");
  assert(typeof captureIsolationRoot === "string" && isAbsolute(captureIsolationRoot),
    "Report acceptance requires the absolute per-capture isolation root");
  assert(typeof privateDataDir === "string" && isAbsolute(privateDataDir),
    "Report acceptance requires a per-capture private data directory");
  assert(typeof closureStatePath === "string" && closureStatePath.length > 0,
    "Report acceptance requires the configured external beta closure-state file");
  assert(isAbsolute(closureStatePath), "The external beta closure-state path must be absolute");
  const ownerCapture = attachSafeBrowserCapture(ownerPage, "BPC-SC-018");
  const ownerTrace = trackBrowserRequests(ownerPage);
  const ownerPageErrors = [];
  ownerPage.on("pageerror", (error) => ownerPageErrors.push(safeBrowserError(error)));
  const adminPageErrors = [];
  adminPage.on("pageerror", (error) => adminPageErrors.push(safeBrowserError(error)));
  const adminCapture = attachSafeBrowserCapture(adminPage, "BPC-SC-020");
  const adminTrace = trackBrowserRequests(adminPage);
  const observerPool = new Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "bpc-report-readonly-observer" });
  const localBoundary = "isolated_local_browser_api_postgresql_private_storage";
  const result = { localBoundary, databaseIsolation: "dedicated_unique_acceptance_database", scenarioData: {} };
  const primaryPool = new Pool({ connectionString: databaseUrl, max: 1, application_name: "bpc-report-capture-db-identity" });
  try {
    const primaryIdentity = (await primaryPool.query("SELECT current_database() AS database_name")).rows[0];
    const initial = await readSnapshot(observerPool, [ownerId]);
    const acceptanceDatabase = primaryIdentity?.database_name;
    assert(typeof acceptanceDatabase === "string" && /^oid_acceptance_[a-f0-9]{32}$/.test(acceptanceDatabase)
      && initial.identity.databaseName === acceptanceDatabase,
    "Primary and read-only observer connections must identify the same unique oid_acceptance database");
    const captureRoot = await realpath(captureIsolationRoot);
    assert(basename(captureRoot) === acceptanceDatabase,
      "The isolated filesystem root must be named for the unique acceptance database");
    const privateRootInfo = await lstat(privateDataDir);
    const privateRootReal = await realpath(privateDataDir);
    const closureInfo = await lstat(closureStatePath);
    const closureReal = await realpath(closureStatePath);
    assert(privateRootInfo.isDirectory() && !privateRootInfo.isSymbolicLink() && pathWithin(captureRoot, privateRootReal)
      && closureInfo.isFile() && !closureInfo.isSymbolicLink() && pathWithin(captureRoot, closureReal),
    "Private storage and operator closure state must be existing, non-symlink test files under this per-capture root");
    const initialClosure = JSON.parse(await readFile(closureReal, "utf8"));
    assert(initialClosure.schemaVersion === "beta-report-closure-state/v1" && initialClosure.betaEndedAt === null
      && typeof initialClosure.sourceEvidenceSha256 === "string" && SHA256_RE.test(initialClosure.sourceEvidenceSha256),
      "The dedicated acceptance closure state must begin open and use the supported schema");
    assert(initial.totalCounts.reports === 0 && initial.totalCounts.uploads === 0,
      "The unique acceptance database must contain no previous report or screenshot rows");
    assert(initial.retentionState?.betaEndedAt === null,
      "The unique acceptance database must not already be closed for retention");
    const runFixture = genuineRunContext === null ? await createLinkedRunFixture(databaseUrl, ownerId) : genuineRunContext;
    assert(runFixture && typeof runFixture.runId === "string" && UUID_RE.test(runFixture.runId)
      && (!genuineRunContext || (typeof runFixture.actionId === "string" && UUID_RE.test(runFixture.actionId)
        && typeof runFixture.taskId === "string" && runFixture.taskId.length > 0)),
    "The genuine report context must bind a completed run, task, and actual action");
    await adminPage.goto("/reports", { waitUntil: "domcontentloaded" });
    await adminPage.locator("#report-title").waitFor();
    const foreignOwnerScreenshot = await adminPage.screenshot({ type: "png", animations: "disabled" });
    assert(foreignOwnerScreenshot.length > 0 && foreignOwnerScreenshot.length <= 5 * 1024 * 1024,
      "The second-owner screenshot fixture is outside the accepted upload bound");
    const foreignOwnerReport = await captureOwnerReport({ page: adminPage, capture: adminCapture,
      title: "Second-owner screenshot fixture", body: "Synthetic local fixture for private image authorization.",
      imageBuffer: foreignOwnerScreenshot, trace: adminTrace, captureRoot, browserErrors: adminPageErrors });
    const foreignOwnerId = foreignOwnerReport.payload?.report?.ownerId;
    assert(typeof foreignOwnerId === "string" && foreignOwnerId !== ownerId,
      "The authenticated admin fixture did not create a report under a distinct owner");
    const foreignRunFixture = await createForeignRunActionFixture(databaseUrl, ownerId, foreignOwnerId);
    const observerOwnerIds = [ownerId, foreignOwnerId];
    const before = await readSnapshot(observerPool, observerOwnerIds);
    assert(before.identity.databaseName === acceptanceDatabase, "The observer database identity changed before report capture");
    const foreignOwnerReportRow = before.reports.find((row) => row.id === foreignOwnerReport.reportId);
    const foreignOwnerImageId = foreignOwnerReportRow?.imageIds[0];
    const foreignOwnerUpload = before.uploads.find((row) => row.id === foreignOwnerImageId);
    const foreignOwnerPrivateImages = await privateImageSnapshot(privateDataDir, before.uploads);
    const foreignOwnerPrivateImage = foreignOwnerPrivateImages.find((row) => row.imageId === foreignOwnerImageId);
    assert(foreignOwnerReportRow?.ownerIdSha256 === hash(foreignOwnerId) && foreignOwnerReportRow.imageIds.length === 1
      && foreignOwnerUpload?.status === "attached" && foreignOwnerUpload.uploaderKind === "owner"
      && foreignOwnerUpload.ownerIdSha256 === hash(foreignOwnerId)
      && foreignOwnerUpload.uploaderIdSha256 === hash(foreignOwnerId)
      && foreignOwnerPrivateImage?.sha256FromDisk === foreignOwnerUpload.outputSha256
      && foreignOwnerPrivateImage.databaseBytes === foreignOwnerUpload.outputBytes,
    "The second-owner UI fixture did not persist one image with matching database and private-file hashes");
    assert(before.totalCounts.reports === 1 && before.totalCounts.uploads === 1,
      "The second-owner UI fixture did not add exactly one report and one retained screenshot before the owner baseline");
    assert(before.runRows.some((row) => row.id === foreignRunFixture.runId)
      && before.taskRows.some((row) => row.runId === foreignRunFixture.runId)
      && before.actionRows.some((row) => row.id === foreignRunFixture.actionId),
    "The no-effects baseline did not include the retained foreign run/task/action fixture");
    await ownerPage.goto("/reports", { waitUntil: "domcontentloaded" });
    await ownerPage.locator("#report-title").waitFor();
    const image = await ownerPage.screenshot({ type: "png", animations: "disabled" });
    assert(image.length > 0 && image.length <= 5 * 1024 * 1024, "The actual browser screenshot is outside the upload bound");
    const linkedTitle = "Report with owned run context";
    const linked = await captureOwnerReport({ page: ownerPage, capture: ownerCapture, title: linkedTitle,
      body: "The test reports a non-secret local fixture observation.", linkedRunId: runFixture.runId,
      linkedTaskId: genuineRunContext ? runFixture.taskId : undefined,
      linkedActionId: genuineRunContext ? runFixture.actionId : undefined, imageBuffer: image,
      trace: ownerTrace, captureRoot, browserErrors: ownerPageErrors,
      onAcceptedReport: genuineRunContext ? onAcceptedReport : undefined });
    const unlinked = await captureOwnerReport({ page: ownerPage, capture: ownerCapture, title: "Report without run context",
      body: "This connection report has no run reference.", imageBuffer: null,
      trace: ownerTrace, captureRoot, browserErrors: ownerPageErrors });
    const retryEvidence = await captureResponseLoss({ page: ownerPage, capture: ownerCapture,
      observerPool, ownerId, publicOrigin, captureRoot, trace: ownerTrace, browserErrors: ownerPageErrors });
    const htmlBody = "<script>window.__supportReportProbe = true</script> ordinary report text";
    const htmlReport = await captureOwnerReport({ page: ownerPage, capture: ownerCapture,
      title: "HTML is displayed as text", body: htmlBody, imageBuffer: null,
      trace: ownerTrace, captureRoot, browserErrors: ownerPageErrors });
    const ownerReportNegativeAttempts = await exerciseOwnerReportBoundaryCases({ page: ownerPage,
      observerPool, ownerId, observerOwnerIds, publicOrigin, linked, runFixture, foreign: foreignRunFixture });
    const imageNegativeAttempts = await exerciseImageBoundaryCases({ page: ownerPage, observerPool, ownerId, publicOrigin, databaseUrl });
    ownerReportNegativeAttempts.push(await exerciseOwnerReportFlood({ page: ownerPage, observerPool,
      observerOwnerIds, publicOrigin }));
    const imagePreviewPromise = waitResponse(ownerPage, (response) =>
      new URL(response.url()).pathname.startsWith(`/api/owner/reports/${linked.reportId}/images/`));
    await ownerPage.locator("article.report-card").filter({ hasText: linkedTitle })
      .getByRole("button", { name: "View private details" }).click();
    ownerCapture.action("click", "owner-report-image-preview");
    const imageResponse = await imagePreviewPromise;
    assert(imageResponse.status() === 200, "The owner clicked a private image preview but the backend did not return it");
    const screenshotHash = hash(await imageResponse.body());
    const after = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId, unlinked.reportId, htmlReport.reportId]);
    const storageImages = await privateImageSnapshot(privateDataDir, after.uploads);
    const linkedPersisted = after.reports.find((row) => row.id === linked.reportId);
    const unlinkedPersisted = after.reports.find((row) => row.id === unlinked.reportId);
    const htmlPersisted = after.reports.find((row) => row.id === htmlReport.reportId);
    const ownerReportRowsBefore = before.reports.filter((row) => row.ownerIdSha256 === hash(ownerId) && row.source === "owner").length;
    const ownerReportRowsAfter = after.reports.filter((row) => row.ownerIdSha256 === hash(ownerId) && row.source === "owner").length;
    const ownerReportRowsCreated = ownerReportRowsAfter - ownerReportRowsBefore;
    assert(ownerReportRowsCreated === 4 && after.totalCounts.reports - before.totalCounts.reports === 4,
      "The owner UI flow did not create exactly four owner reports above the retained second-owner fixture baseline");
    assert(linkedPersisted?.runId === runFixture.runId && linkedPersisted?.taskId === (runFixture.taskId ?? null)
      && linkedPersisted?.actionId === (runFixture.actionId ?? null) && unlinkedPersisted?.runId === null,
      "Independent PostgreSQL observer did not find the two UI-created linked/unlinked reports");
    assert(storageImages.some((row) => row.imageId === linkedPersisted.imageIds[0] && row.sha256FromDisk === screenshotHash),
      "The browser image preview did not match the linked upload and private file recorded independently");
    const ownerRead = ownerTrace.requests.filter((row) => row.method === "GET" && row.path === `/api/owner/reports/${linked.reportId}`).at(-1);
    const foreignCountsBefore = await readOwnerCounts(observerPool, ownerId);
    const foreignRead = await adminPage.request.get(new URL(`/api/owner/reports/${linked.reportId}`, publicOrigin).toString());
    const foreignReadBody = await foreignRead.json().catch(() => ({}));
    const foreignCountsAfter = await readOwnerCounts(observerPool, ownerId);
    const htmlReadResponsePromise = waitResponse(ownerPage, (response) =>
      new URL(response.url()).pathname === `/api/owner/reports/${htmlReport.reportId}`);
    await ownerPage.locator("article.report-card").filter({ hasText: "HTML is displayed as text" })
      .getByRole("button", { name: "View private details" }).click();
    const htmlReadResponse = await htmlReadResponsePromise;
    const htmlReadPayload = await htmlReadResponse.json().catch(() => ({}));
    const htmlDetails = ownerPage.locator('[aria-label="Report details"]');
    let htmlDetailSettled = false;
    try {
      const renderedState = await ownerPage.waitForFunction(({ title, body }) => {
        const details = document.querySelector('[aria-label="Report details"]');
        return details?.querySelector("h2")?.textContent === title
          && details?.querySelector(".report-body-preview")?.textContent === body;
      }, { title: "HTML is displayed as text", body: htmlBody }, { timeout: 5000 });
      await renderedState.dispose();
      htmlDetailSettled = true;
    } catch { /* A bounded mismatch below records only status, script count, and hashes. */ }
    const renderedHtmlText = await htmlDetails.locator(".report-body-preview").innerText().catch(() => "");
    const htmlScriptCount = await htmlDetails.locator("script").count();
    await ownerTrace.flush();
    const htmlRead = ownerTrace.requests.filter((row) => row.method === "GET" && row.path === `/api/owner/reports/${htmlReport.reportId}`).at(-1);
    const textProbe = { probe: "html-report-render", status: htmlReadResponse.status(), scriptElementCount: htmlScriptCount,
      expectedTextSha256: htmlPersisted?.bodySha256 ?? null, observedTextSha256: hash(renderedHtmlText) };
    const htmlTextMatches = htmlDetailSettled && htmlReadResponse.status() === 200
      && htmlReadPayload?.report?.body === htmlBody && htmlScriptCount === 0
      && textProbe.expectedTextSha256 === textProbe.observedTextSha256;
    if (!htmlTextMatches) await writeReportHtmlTextDiagnostic({ captureRoot, ...textProbe });
    const noSideEffectBeforeAdmin = JSON.stringify(before.financialRows) === JSON.stringify(after.financialRows)
      && JSON.stringify(before.runRows) === JSON.stringify(after.runRows)
      && JSON.stringify(before.taskRows) === JSON.stringify(after.taskRows)
      && JSON.stringify(before.timerRows) === JSON.stringify(after.timerRows)
      && JSON.stringify(before.actionRows) === JSON.stringify(after.actionRows);
    assert(noSideEffectBeforeAdmin, "Creating owner reports changed billing, benchmark runs, tasks, actions, or timers");
    assert(ownerRead?.status === 200 && foreignRead.status() === 404,
      "Owner and foreign-owner report projections did not return the expected private access statuses");
    assert(htmlTextMatches,
      "The HTML-like report body was not rendered as inert text");
    result.scenarioData["BPC-SC-018"] = {
      scenarioId: "BPC-SC-018", localStatus: "observed_partial",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1", scenarioId: "BPC-SC-018",
        boundaryDetail: "owner_browser_reports_postgres", captureBoundary: "local_acceptance_runner",
        browser: { ...browserEvidence(ownerCapture, publicOrigin, ownerTrace), previews: [
          { accessRole: "owner", status: imageResponse.status(), sha256: screenshotHash },
        ], textProbes: [textProbe] },
        observer: { databaseRole: after.identity.databaseRole, databaseName: after.identity.databaseName, transactionReadOnly: after.identity.transactionReadOnly,
          reportCountProbe: { globalBefore: before.totalCounts.reports, globalAfter: after.totalCounts.reports,
            targetOwnerBefore: ownerReportRowsBefore, targetOwnerAfter: ownerReportRowsAfter, createdByTargetOwner: ownerReportRowsCreated },
          before: { ...before, identity: undefined }, after: { ...after, identity: undefined } },
        storage: { images: storageImages }, negativeAttempts: ownerReportNegativeAttempts, responseLossRetries: [retryEvidence],
      },
    };

    const linkedImageId = linkedPersisted?.imageIds[0];
    assert(typeof linkedImageId === "string" && Number.isInteger(linkedPersisted?.revision),
      "The authenticated agent admin probe requires the independently observed linked report and image");
    const agentAdminProbe = await exerciseAgentAdminAttempt({ ownerPage, observerPool, ownerId, observerOwnerIds,
      publicOrigin, reportId: linked.reportId, imageId: linkedImageId, reportRevision: linkedPersisted.revision });

    await adminPage.goto(new URL("/admin/reports", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
    const statusFilter = adminPage.getByLabel("Status", { exact: true });
    const sourceFilter = adminPage.getByLabel("Source", { exact: true });
    await statusFilter.click();
    adminCapture.action("click", "admin-report-filter");
    await statusFilter.selectOption("new");
    await sourceFilter.selectOption("owner");
    await adminPage.locator("tbody tr").first().waitFor();
    const listSnapshot = await readSnapshot(observerPool, observerOwnerIds);
    const visibleIds = await adminPage.locator("tbody tr").evaluateAll((rows) => rows.map((row) => row.getAttribute("data-report-id")));
    const observerReportIds = listSnapshot.reports.filter((row) => row.source === "owner" && row.status === "new").map((row) => row.id);
    assert(visibleIds.length > 0 && visibleIds.every((id) => typeof id === "string")
      && JSON.stringify(visibleIds) === JSON.stringify(observerReportIds),
    "Admin report filters did not display the independent database rows in the same order");
    const adminRow = adminPage.locator(`tbody tr[data-report-id="${linked.reportId}"]`);
    const imageId = linkedPersisted.imageIds[0];
    const adminImagePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}/images/${imageId}`);
    await adminRow.getByRole("button", { name: "Open" }).click();
    await adminPage.locator(`[aria-label="Selected private report"] img`).waitFor();
    const adminImageResponse = await adminImagePromise;
    const adminImageHash = hash(await adminImageResponse.body());
    assert(adminImageResponse.status() === 200 && adminImageHash === screenshotHash,
      "Admin private preview did not return the same persisted screenshot bytes as owner preview");
    const foreignAdminRow = adminPage.locator(`tbody tr[data-report-id="${foreignOwnerReport.reportId}"]`);
    const foreignAdminDetailPromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${foreignOwnerReport.reportId}` && response.request().method() === "GET");
    const foreignAdminImagePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${foreignOwnerReport.reportId}/images/${foreignOwnerImageId}`);
    await foreignAdminRow.getByRole("button", { name: "Open" }).click();
    adminCapture.action("click", "admin-foreign-owner-image-fixture-open");
    const foreignAdminDetailResponse = await foreignAdminDetailPromise;
    await adminPage.locator(`[aria-label="Selected private report"] img`).waitFor();
    const foreignAdminImageResponse = await foreignAdminImagePromise;
    const foreignAdminImageHash = hash(await foreignAdminImageResponse.body());
    assert(foreignAdminDetailResponse.status() === 200 && foreignAdminImageResponse.status() === 200
      && foreignAdminImageHash === foreignOwnerUpload.outputSha256
      && foreignAdminImageHash === foreignOwnerPrivateImage.sha256FromDisk,
    "The authorized admin preview did not match the retained foreign report database and private-file hashes");
    const adminHtmlRow = adminPage.locator(`tbody tr[data-report-id="${htmlReport.reportId}"]`);
    const adminHtmlResponsePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${htmlReport.reportId}` && response.request().method() === "GET");
    await adminHtmlRow.getByRole("button", { name: "Open" }).click();
    adminCapture.action("click", "admin-report-html-open");
    const adminHtmlResponse = await adminHtmlResponsePromise;
    const adminHtmlPayload = await adminHtmlResponse.json().catch(() => ({}));
    const adminHtmlDetails = adminPage.locator('[aria-label="Selected private report"]');
    let adminHtmlSettled = false;
    try {
      const renderedState = await adminPage.waitForFunction(({ title, body }) => {
        const details = document.querySelector('[aria-label="Selected private report"]');
        return details?.querySelector("h2")?.textContent === title
          && details?.querySelector(".report-body-preview")?.textContent === body;
      }, { title: "HTML is displayed as text", body: htmlBody }, { timeout: 5000 });
      await renderedState.dispose();
      adminHtmlSettled = true;
    } catch { /* A failed render is recorded by hashes and the safe element count below. */ }
    const adminRenderedHtmlText = await adminHtmlDetails.locator(".report-body-preview").innerText().catch(() => "");
    const adminHtmlScriptCount = await adminHtmlDetails.locator("script").count();
    const adminHtmlTextProbe = { probe: "admin-html-report-render", status: adminHtmlResponse.status(),
      scriptElementCount: adminHtmlScriptCount, expectedTextSha256: htmlPersisted?.bodySha256 ?? null,
      observedTextSha256: hash(adminRenderedHtmlText) };
    assert(adminHtmlSettled && adminHtmlResponse.status() === 200
      && adminHtmlPayload?.report?.body === htmlBody && adminHtmlScriptCount === 0
      && adminHtmlTextProbe.expectedTextSha256 === adminHtmlTextProbe.observedTextSha256,
    "The administrator did not render the HTML-like report body as inert text");
    const linkedDetailResponsePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}` && response.request().method() === "GET");
    await adminRow.getByRole("button", { name: "Open" }).click();
    adminCapture.action("click", "admin-report-linked-reopen-details");
    const linkedDetailResponse = await linkedDetailResponsePromise;
    assert(linkedDetailResponse.status() === 200, "The admin page did not reload the linked report after its HTML probe");
    await adminPage.locator(`[aria-label="Selected private report"] img`).waitFor();

    const statusBefore = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId]);
    const linkedStatusBefore = statusBefore.reports.find((row) => row.id === linked.reportId);
    assert(linkedStatusBefore?.status === "new" && Number.isInteger(linkedStatusBefore.revision),
      "Independent observer did not find the linked report in its expected initial revision");
    const unauthorizedStatusAttempt = await observeReportHttpNegative({ page: ownerPage, observerPool, ownerId, observerOwnerIds, publicOrigin,
      name: "unauthorized_status", method: "PATCH", path: `/api/admin/reports/${linked.reportId}/status`,
      data: { operationId: operationId(), expectedRevision: linkedStatusBefore.revision, status: "closed" },
      expectedStatus: 403, expectedErrorCode: "FORBIDDEN" });
    const foreignAttachmentAttempt = await observeReportHttpNegative({ page: ownerPage, observerPool, ownerId,
      observerOwnerIds, publicOrigin, name: "foreign_attachment_preview", method: "GET",
      path: `/api/owner/reports/${foreignOwnerReport.reportId}/images/${foreignOwnerImageId}`,
      expectedStatus: 404, expectedErrorCode: "REPORT_IMAGE_NOT_FOUND" });
    const secondAdminPage = await adminPage.context().newPage();
    const secondAdminCapture = attachSafeBrowserCapture(secondAdminPage, "BPC-SC-020");
    const secondAdminTrace = trackBrowserRequests(secondAdminPage);
    await secondAdminPage.goto(new URL("/admin/reports", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
    const secondOpenResponse = waitResponse(secondAdminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}`);
    await secondAdminPage.locator(`[data-report-id="${linked.reportId}"]`).getByRole("button", { name: "Open" }).click();
    const secondOpen = await secondOpenResponse;
    const secondOpenPayload = await secondOpen.json().catch(() => ({}));
    assert(secondOpen.status() === 200 && secondOpenPayload?.report?.status === linkedStatusBefore.status
      && secondOpenPayload?.report?.revision === linkedStatusBefore.revision,
    "The independent admin page did not load the expected stale report revision");
    const adminDetails = adminPage.locator('[aria-label="Selected private report"]');
    const expectedClosedRevision = linkedStatusBefore.revision + 1;
    const closeStatusResponsePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}/status` && response.request().method() === "PATCH");
    await adminPage.getByRole("button", { name: "Close report" }).click();
    adminCapture.action("click", "admin-report-close");
    const closeStatusResponse = await closeStatusResponsePromise;
    const closeStatusPayload = await closeStatusResponse.json().catch(() => ({}));
    assert(closeStatusResponse.status() === 200 && closeStatusPayload?.report?.status === "closed"
      && closeStatusPayload?.report?.revision === expectedClosedRevision,
    "The admin close click did not return the expected closed report revision");
    await adminPage.getByText("Report status and audit revision were saved.").waitFor();
    await adminDetails.getByRole("button", { name: "Reopen to in progress", exact: true }).waitFor();
    await adminDetails.getByText(`owner report · revision ${expectedClosedRevision}`, { exact: true }).waitFor();
    const expectedReopenedRevision = expectedClosedRevision + 1;
    const reopenStatusResponsePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}/status` && response.request().method() === "PATCH");
    await adminPage.getByRole("button", { name: "Reopen to in progress" }).click();
    adminCapture.action("click", "admin-report-reopen");
    const reopenStatusResponse = await reopenStatusResponsePromise;
    const reopenStatusPayload = await reopenStatusResponse.json().catch(() => ({}));
    assert(reopenStatusResponse.status() === 200 && reopenStatusPayload?.report?.status === "in_progress"
      && reopenStatusPayload?.report?.revision === expectedReopenedRevision,
    "The admin reopen click did not return the expected in-progress report revision");
    await adminPage.getByText("Report status and audit revision were saved.").waitFor();
    await adminDetails.getByRole("button", { name: "Close report", exact: true }).waitFor();
    await adminDetails.getByText(`owner report · revision ${expectedReopenedRevision}`, { exact: true }).waitFor();
    const reopenedSnapshot = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId]);
    const reopenedPersisted = reopenedSnapshot.reports.find((row) => row.id === linked.reportId);
    assert(reopenedPersisted?.status === "in_progress" && reopenedPersisted.revision === expectedReopenedRevision,
      "The independent observer did not find the UI-confirmed reopened report revision");
    const staleCountsBefore = await readOwnerCounts(observerPool, ownerId);
    const staleResponsePromise = waitResponse(secondAdminPage, (response) =>
      new URL(response.url()).pathname === `/api/admin/reports/${linked.reportId}/status` && response.request().method() === "PATCH");
    await secondAdminPage.getByRole("button", { name: "Close report" }).click();
    secondAdminCapture.action("click", "admin-report-stale-close");
    await secondAdminPage.getByRole("alert").waitFor();
    const staleResponse = await staleResponsePromise;
    const stalePayload = await staleResponse.json().catch(() => ({}));
    const staleCountsAfter = await readOwnerCounts(observerPool, ownerId);
    const statusAfter = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId]);
    const statusAfterLinked = statusAfter.reports.find((row) => row.id === linked.reportId);
    assert(staleResponse.status() === 409 && stalePayload?.error?.code === "REPORT_REVISION_CONFLICT"
      && staleCountsAfter.reportRows === staleCountsBefore.reportRows
      && staleCountsAfter.uploadRows === staleCountsBefore.uploadRows
      && statusAfterLinked?.status === "in_progress" && statusAfterLinked.revision === expectedReopenedRevision
      && JSON.stringify(statusAfter.audits) === JSON.stringify(reopenedSnapshot.audits),
    "The stale admin revision was not rejected without changing the reopened report or audit state");
    const htmlOwnerRead = htmlRead;
    const adminEvidence = mergeBrowserEvidence(browserEvidence(adminCapture, publicOrigin, adminTrace),
      browserEvidence(secondAdminCapture, publicOrigin, secondAdminTrace));
    result.scenarioData["BPC-SC-020"] = {
      scenarioId: "BPC-SC-020", localStatus: "observed_partial",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1", scenarioId: "BPC-SC-020",
        boundaryDetail: "admin_browser_report_triage_postgres", captureBoundary: "local_acceptance_runner",
        browser: { ...adminEvidence, privateReads: [
          { method: "GET", accessRole: "owner", transport: "browser_ui_click", reportId: linked.reportId,
            reportOwnerIdSha256: hash(ownerId), status: ownerRead.status },
          { method: "GET", accessRole: "foreign-owner", transport: "authenticated_http_request_from_browser_context",
            reportId: linked.reportId, status: foreignRead.status() },
        ], adminListProbe: { observerReportIds, displayedReportIds: visibleIds },
        previews: [
          { accessRole: "admin", status: adminImageResponse.status(), sha256: adminImageHash },
          { accessRole: "owner", status: imageResponse.status(), sha256: screenshotHash },
        ], fixturePreviews: [{ accessRole: "admin", reportOwnerIdSha256: hash(foreignOwnerId),
          reportIdSha256: hash(foreignOwnerReport.reportId), imageIdSha256: hash(foreignOwnerImageId),
          status: foreignAdminImageResponse.status(), sha256: foreignAdminImageHash }],
        textProbes: [{ ...textProbe, status: htmlOwnerRead?.status ?? null }, adminHtmlTextProbe] },
        agentBearerProof: agentAdminProbe.proof,
        observer: { databaseRole: statusAfter.identity.databaseRole, databaseName: statusAfter.identity.databaseName, transactionReadOnly: statusAfter.identity.transactionReadOnly,
          before: { ...statusBefore, identity: undefined }, after: { ...statusAfter, identity: undefined } },
        negativeAttempts: [
          { name: "foreign_owner_read", responseStatus: foreignRead.status(), errorCode: foreignReadBody?.error?.code ?? foreignReadBody?.code ?? null,
            databaseRole: foreignCountsAfter.databaseRole, transactionReadOnly: foreignCountsAfter.transactionReadOnly,
            reportRowsBefore: foreignCountsBefore.reportRows, reportRowsAfter: foreignCountsAfter.reportRows,
            uploadRowsBefore: foreignCountsBefore.uploadRows, uploadRowsAfter: foreignCountsAfter.uploadRows },
          { name: "stale_revision", responseStatus: staleResponse.status(), errorCode: stalePayload?.error?.code ?? stalePayload?.code ?? null,
            databaseRole: staleCountsAfter.databaseRole, transactionReadOnly: staleCountsAfter.transactionReadOnly,
            reportRowsBefore: staleCountsBefore.reportRows, reportRowsAfter: staleCountsAfter.reportRows,
            uploadRowsBefore: staleCountsBefore.uploadRows, uploadRowsAfter: staleCountsAfter.uploadRows },
          ...agentAdminProbe.attempts,
          unauthorizedStatusAttempt,
          { ...foreignAttachmentAttempt, targetReportIdSha256: hash(foreignOwnerReport.reportId),
            targetImageIdSha256: hash(foreignOwnerImageId) },
        ],
      },
    };
    await secondAdminPage.close();

    result.scenarioData["BPC-SC-024"] = {
      scenarioId: "BPC-SC-024", localStatus: "observed_partial",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1", scenarioId: "BPC-SC-024",
        boundaryDetail: "authenticated_image_upload_private_storage_postgres", captureBoundary: "local_acceptance_runner",
        browser: { ...mergeBrowserEvidence(browserEvidence(ownerCapture, publicOrigin, ownerTrace),
          browserEvidence(adminCapture, publicOrigin, adminTrace)), previews: [
          { accessRole: "owner", status: imageResponse.status(), sha256: screenshotHash },
          { accessRole: "admin", status: adminImageResponse.status(), sha256: adminImageHash },
        ] },
        observer: { databaseRole: after.identity.databaseRole, databaseName: after.identity.databaseName, transactionReadOnly: after.identity.transactionReadOnly,
          before: { ...before, identity: undefined }, after: { ...after, identity: undefined } },
        storage: { images: storageImages }, mcpFrames: [], uploadRetries: [], imageCapRace: {}, orphanSweep: {},
        negativeAttempts: imageNegativeAttempts,
        localBlockers: ["daily_rolling_upload_quota_not_saturated", "three_image_attach_race_not_run", "native_mcp_client_not_available"],
      },
    };

    result.localOperations = await runLocalOperationsCases({ adminPage, ownerPage, observerPool,
      publicOrigin,captureRoot,reportId:linked.reportId });
    const closureBefore = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId]);
    assert(closureBefore.retentionState?.betaEndedAt === null, "Report retention had already been closed before the UI case");
    await adminPage.goto(new URL("/admin/reports", publicOrigin).toString(), { waitUntil: "domcontentloaded" });
    await adminPage.getByRole("button", { name: "Close beta and start retention" }).click();
    adminCapture.action("click", "admin-close-beta-retention");
    const closeResponsePromise = waitResponse(adminPage, (response) =>
      new URL(response.url()).pathname === "/api/admin/reports/retention/close" && response.request().method() === "POST");
    await adminPage.getByRole("button", { name: "Confirm beta closure" }).click();
    const closeResponse = await closeResponsePromise;
    await adminPage.getByText(/Beta closure recorded at/).waitFor();
    assert(closeResponse.status() === 200 || closeResponse.status() === 201,
      "Admin browser did not receive a successful beta-closure response");
    const closureAfter = await readSnapshot(observerPool, observerOwnerIds, [linked.reportId]);
    const closureState = JSON.parse(await readFile(closureStatePath, "utf8"));
    assert(closureState.schemaVersion === "beta-report-closure-state/v1"
      && typeof closureState.sourceEvidenceSha256 === "string" && SHA256_RE.test(closureState.sourceEvidenceSha256)
      && closureState.betaEndedAt === closureAfter.retentionState.betaEndedAt,
    "The external monotonic closure-state file did not match the independently observed durable closure time");
    const expiresAt = closureAfter.reports.find((row) => row.id === linked.reportId)?.expiresAt ?? null;
    const closureImages = await privateImageSnapshot(privateDataDir, closureAfter.uploads);
    result.scenarioData["BPC-SC-026"] = {
      scenarioId: "BPC-SC-026", localStatus: "observed_partial",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1", scenarioId: "BPC-SC-026",
        boundaryDetail: "report_retention_purge_backup_restore", captureBoundary: "local_acceptance_runner",
        browser: browserEvidence(adminCapture, publicOrigin, adminTrace),
        observer: { databaseRole: closureAfter.identity.databaseRole, databaseName: closureAfter.identity.databaseName, transactionReadOnly: closureAfter.identity.transactionReadOnly,
          before: { ...closureBefore, identity: undefined }, after: { ...closureAfter, identity: undefined } },
        retention: { betaEndedAt: closureState.betaEndedAt, expiresAt, closeAudit: "beta_closed",
          authoritativeBetaEndedAt: closureState.betaEndedAt, closureEvidenceSha256: closureState.sourceEvidenceSha256,
          cleanupAttempts: [], restore: {} },
        storage: { imagesBefore: storageImages, imagesAfter: closureImages }, negativeAttempts: [],
      },
    };
    result.scenarioData["BPC-SC-019"] = {
      scenarioId: "BPC-SC-019", localStatus: "not_run",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1", scenarioId: "BPC-SC-019",
        boundaryDetail: "four_native_clients_support_tool_postgres", captureBoundary: "local_acceptance_runner",
        nativeClients: [], observer: { databaseRole: closureAfter.identity.databaseRole, databaseName: closureAfter.identity.databaseName, transactionReadOnly: closureAfter.identity.transactionReadOnly,
          before: { ...before, identity: undefined }, after: { ...closureAfter, identity: undefined } },
        mcpFrames: [], restartReceipts: [], negativeAttempts: [],
      },
    };
    return result;
  } finally {
    await observerPool.end();
    await primaryPool.end();
  }
}
