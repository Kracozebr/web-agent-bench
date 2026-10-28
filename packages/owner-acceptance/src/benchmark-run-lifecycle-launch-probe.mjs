import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { assertSecretFree, sha256 } from "./evidence.mjs";

const SCENARIOS = ["BRL-SC-023", "BRL-SC-024"];

function requireValue(condition, code) {
  if (!condition) throw Object.assign(new Error(code), {code});
}

function safeBody(value) {
  const body = value && typeof value === "object" ? value : {};
  const error = body.error && typeof body.error === "object" ? body.error : null;
  const output = {};
  if (error && typeof error.code === "string") output.error = { code: error.code };
  if (typeof body.replayed === "boolean") output.replayed = body.replayed;
  const intent = body.intent && typeof body.intent === "object" ? body.intent : null;
  if (intent) output.intent = Object.fromEntries([
    "id", "agentId", "mode", "taskIds", "benchmarkVersion", "manifestHash", "benchmarkHash",
    "policyHash", "successorPreparationPolicyVersion", "successorPreparationTimeoutSeconds",
    "quote", "cashCeiling", "status", "createdAt", "expiresAt", "acceptedAt", "runId",
    "runStatus", "queueDeadline", "terminalReason",
  ].filter((key) => Object.hasOwn(intent, key)).map((key) => [key, intent[key]]));
  const run = body.run && typeof body.run === "object" ? body.run : null;
  if (run) output.run = Object.fromEntries([
    "id", "intentId", "agentId", "mode", "taskIds", "benchmarkVersion", "manifestHash",
    "benchmarkHash", "policyHash", "quotePrice", "cashCeiling", "status", "queuedAt",
    "queueDeadline", "startedAt", "terminalReason",
  ].filter((key) => Object.hasOwn(run, key)).map((key) => [key, run[key]]));
  return output;
}

async function jsonResponse(response) {
  let value = {};
  try { value = await response.json(); } catch { /* Status and route identity remain useful. */ }
  return safeBody(value);
}

function exactUsdc(units) {
  const value = BigInt(units);
  const whole = value / 1_000_000n;
  const fractional = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fractional ? whole.toString() + "." + fractional : whole.toString();
}

function responseStatus(record) {
  return Number.isInteger(record?.status) ? record.status : null;
}

function createMinimumAgentIntervalPacer(intervalMs) {
  let queue = Promise.resolve();
  let nextStartAt = 0;
  return () => {
    const slot = queue.then(async () => {
      const waitMs = Math.max(0, nextStartAt - performance.now());
      if (waitMs > 0) await sleep(waitMs);
      nextStartAt = performance.now() + intervalMs;
    });
    queue = slot.catch(() => undefined);
    return slot;
  };
}

const paceAgentRequest = createMinimumAgentIntervalPacer(1_100);

function baseIntent(input) {
  const value = input.intent?.database ?? input.intent;
  requireValue(value && typeof value === "object", "brl_intent_snapshot_missing");
  const intentId = value.id ?? input.intent.intentId;
  requireValue(typeof intentId === "string" && /^[0-9a-f-]{36}$/i.test(intentId), "brl_intent_id_missing");
  requireValue(value.owner_id === input.ownerId && value.agent_id === input.agentId, "brl_intent_actor_binding_mismatch");
  requireValue(value.status === "pending" && value.run_id == null, "brl_probe_requires_pending_intent");
  const release = input.liveValidatedRelease;
  requireValue(release && value.release_identity === release.releaseIdentity
    && value.manifest_hash === release.manifestHash && value.benchmark_hash === release.benchmarkHash
    && value.policy_hash === release.policyHash, "brl_live_release_binding_mismatch");
  return { value, release, intentId };
}

function createRequestBody(input, intent, operationId = intent.operation_id, agentId = input.agentId) {
  return {
    operationId,
    agentId,
    mode: intent.mode,
    taskIds: intent.task_ids,
    cashCeiling: exactUsdc(intent.cash_ceiling_units),
    expectedReleaseIdentity: intent.release_identity,
    expectedManifestHash: intent.manifest_hash,
    expectedQuotePrice: exactUsdc(intent.quote_price_units),
  };
}

async function readonlySnapshot(pool, { ownerId, agentId, intentIds }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(
      "SELECT current_user AS role,current_setting('transaction_read_only') AS transaction_read_only,current_database() AS database_name",
    )).rows[0];
    const observedAt = (await client.query("SELECT clock_timestamp()::text AS observed_at")).rows[0]?.observed_at ?? null;
    requireValue(identity?.role === "oid_observer" && identity.transaction_read_only === "on",
      "brl_database_observer_not_readonly");
    const ids = [...new Set(intentIds.filter((id) => typeof id === "string"))];
    const pendingCount = (await client.query(
      "SELECT COUNT(*)::text AS count FROM oid_run_launch_intent WHERE owner_id=$1 AND status='pending' AND expires_at>clock_timestamp()",
      [ownerId],
    )).rows[0]?.count ?? "0";
    const intents = (await client.query(
      "SELECT id::text,owner_id::text,agent_id::text,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units::text,precision,cash_ceiling_units::text,status,created_at::text,expires_at::text,accepted_at::text,terminal_reason,run_id::text FROM oid_run_launch_intent WHERE id=ANY($1::uuid[]) ORDER BY id",
      [ids],
    )).rows;
    const runs = (await client.query(
      "SELECT id::text,intent_id::text,owner_id::text,agent_id::text,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units::text,cash_ceiling_units::text,status,queued_at::text,queue_deadline::text,started_at::text FROM oid_benchmark_run WHERE owner_id=$1 AND intent_id=ANY($2::uuid[]) ORDER BY id",
      [ownerId, ids],
    )).rows;
    const runIds = runs.map((row) => row.id);
    const runOperations = runIds.map((id) => "runacc_" + id.replaceAll("-", ""));
    const reservations = runIds.length ? (await client.query(
      "SELECT id::text,run_id::text,owner_id::text,source_kind,amount_units::text,state,created_at::text,changed_at::text FROM oid_run_reservation WHERE run_id=ANY($1::uuid[]) ORDER BY id",
      [runIds],
    )).rows : [];
    const budgetHolds = runIds.length ? (await client.query(
      "SELECT run_id::text,owner_id::text,agent_id::text,mode,utc_day,amount_units::text,state,created_at::text,changed_at::text FROM oid_run_budget_hold WHERE run_id=ANY($1::uuid[]) ORDER BY run_id",
      [runIds],
    )).rows : [];
    const ledgerEntries = runOperations.length ? (await client.query(
      "SELECT id::text,owner_id::text,operation_id,entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text,created_at::text FROM oid_ledger_entry WHERE owner_id=$1 AND operation_id=ANY($2::text[]) ORDER BY id",
      [ownerId, runOperations],
    )).rows : [];
    const events = runIds.length ? (await client.query(
      "SELECT id::text,run_id::text,sequence,source,event_type,payload_hash,created_at::text FROM oid_run_event WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,sequence",
      [runIds],
    )).rows : [];
    const outbox = runIds.length ? (await client.query(
      "SELECT event_id::text,run_id::text,event_type,status,created_at::text,delivered_at::text FROM oid_run_outbox WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,event_type",
      [runIds],
    )).rows : [];
    const slots = (await client.query(
      "SELECT agent_id::text,owner_id::text,run_id::text,claim_id::text,state,acquired_at::text,released_at::text FROM oid_run_execution_slot WHERE agent_id=$1 ORDER BY acquired_at",
      [agentId],
    )).rows;
    const tasks = runIds.length ? (await client.query(
      "SELECT run_id::text,task_index,task_id,status,started_at::text,deadline_at::text FROM oid_run_task WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,task_index",
      [runIds],
    )).rows : [];
    const actions = runIds.length ? (await client.query(
      "SELECT id::text,run_id::text,task_index,action_sequence::text,action_kind,accepted_at::text FROM oid_run_task_action WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,action_sequence",
      [runIds],
    )).rows : [];
    const publicActionMarkers = (await client.query(
      "SELECT agent_id::text,owner_id::text,source_kind,source_id,source_hash,occurred_at::text FROM oid_agent_first_public_action WHERE agent_id=$1 ORDER BY occurred_at",
      [agentId],
    )).rows;
    const rankedBestResults = (await client.query(
      "SELECT benchmark_version,agent_id::text,run_id::text,updated_at::text FROM oid_ranked_best_result WHERE agent_id=$1 ORDER BY benchmark_version",
      [agentId],
    )).rows;
    await client.query("COMMIT");
    return {
      observer: { role: identity.role, transaction_read_only: identity.transaction_read_only, database_name: identity.database_name },
      database: { observedAt: String(observedAt), intents, runs, reservations, budgetHolds, ledgerEntries,
        events, outbox, slots, tasks, actions, publicActionMarkers, rankedBestResults,
        pendingOwnerCount: String(pendingCount) },
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

function cleanHttpRecord({ method, path, requestBody, response, sentAuthorization = false, transportUnknown = false }) {
  const record = { method, path, request: requestBody ? { ...requestBody } : {},
    authorizationHeaderPresent: sentAuthorization, status: Number.isInteger(response?.status) ? response.status : null,
    body: response?.body ?? {}, transportUnknown };
  assertSecretFree(record, "BRL HTTP record");
  return record;
}

async function ownerRequest(input, path, body) {
  const url = new URL(path, input.publicOrigin);
  const response = await input.ownerPage.request.post(url.href, {
    headers: { origin: new URL(input.publicOrigin).origin }, data: body, timeout: 15_000,
  });
  return cleanHttpRecord({ method: "POST", path: url.pathname, requestBody: body,
    response: { status: response.status(), body: await jsonResponse(response) } });
}

async function readOwnerCatalog(input) {
  const response = await input.ownerPage.request.get(new URL("/api/owner/runs/catalog", input.publicOrigin).href,
    { timeout: 15_000 });
  let body = {};
  try { body = await response.json(); } catch { /* The status still identifies a catalog outage. */ }
  const release = body?.activeRelease;
  return {
    status: response.status(),
    intentCreationReady: body?.intentCreationReady === true,
    activeRelease: release && typeof release === "object" ? {
      releaseIdentity: release.releaseIdentity ?? null,
      benchmarkVersion: release.benchmarkVersion ?? null,
      manifestHash: release.manifestHash ?? null,
      benchmarkHash: release.benchmarkHash ?? null,
      policyHash: release.policyHash ?? null,
      rankedPrice: release.rankedPrice ?? null,
      trainingPrice: release.trainingPrice ?? null,
    } : null,
  };
}

async function agentHttpRequest(input, intentId, operationId, { dropResponse = false, bearer = input.agentBearer } = {}) {
  const path = "/api/agent/run-intents/" + intentId + "/accept";
  const body = { operationId };
  try {
    await paceAgentRequest();
    const response = await fetch(new URL(path, input.publicOrigin), {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(15_000),
      headers: { authorization: "Bearer " + bearer, origin: new URL(input.publicOrigin).origin, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const safe = await jsonResponse(response);
    if (dropResponse) {
      return { method: "POST", path, request: body, authorizationHeaderPresent: true,
        status: null, body: {}, transportUnknown: true, responseDroppedAfterCommit: true,
        responseStatusAtDropShim: response.status, serverBodyAtDropShim: safe };
    }
    return cleanHttpRecord({ method: "POST", path, requestBody: body,
      response: { status: response.status, body: safe }, sentAuthorization: true });
  } catch (error) {
    return { method: "POST", path, request: body, authorizationHeaderPresent: true,
      status: null, body: {}, transportUnknown: true, responseDroppedAfterCommit: false,
      errorName: error?.name === "TimeoutError" ? "TimeoutError" : "TransportError" };
  }
}

async function mcpAccept(input, intentId, operationId, bearer = input.agentBearer) {
  await paceAgentRequest();
  const client = new Client({ name: "BRL local acceptance verifier", version: "1.0.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StreamableHTTPClientTransport(new URL("/api/agent/mcp", input.publicOrigin), {
    requestInit: { headers: { authorization: "Bearer " + bearer, origin: new URL(input.publicOrigin).origin } },
    onInsufficientScope: "throw",
  });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "runs.accept_launch_intent", arguments: { intentId, operationId } });
    let payload = result?.structuredContent;
    if (!payload && Array.isArray(result?.content)) {
      const item = result.content.find((row) => row?.type === "text" && typeof row.text === "string");
      try { payload = item ? JSON.parse(item.text) : {}; } catch { payload = {}; }
    }
    const record = { toolName: "runs.accept_launch_intent", operationId, isError: result?.isError === true,
      status: result?.isError === true ? 409 : 200, body: safeBody(payload) };
    assertSecretFree(record, "BRL MCP record");
    return record;
  } catch (error) {
    return { toolName: "runs.accept_launch_intent", operationId, isError: true, status: null,
      body: {}, errorName: error?.name === "TimeoutError" ? "TimeoutError" : "McpTransportError" };
  } finally { await client.close().catch(() => undefined); }
}

async function healthAfterRestart(input) {
  requireValue(typeof input.restartApi === "function", "brl_restart_api_fixture_required");
  await input.restartApi();
  try {
    const response = await fetch(new URL("/healthz", input.publicOrigin), { signal: AbortSignal.timeout(5_000) });
    return { healthStatus: response.status };
  } catch (error) {
    return { healthStatus: null, errorName: error?.name === "TimeoutError" ? "TimeoutError" : "TransportError" };
  }
}

function sleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

const TERMINAL_RUN_STATUSES = new Set(["completed", "failed", "cancelled", "expired", "unknown", "disqualified"]);

async function waitForTerminalAndReleasedSlot(pool, { ownerId, agentId, intentId, timeoutMs = 5 * 60_000 }) {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const snapshot = await readonlySnapshot(pool, { ownerId, agentId, intentIds: [intentId] });
    const { intent, run } = snapshotRowsByIntent(snapshot, intentId);
    const slotReleased = typeof run?.id === "string"
      && !snapshot.database.slots.some((row) => row.run_id === run.id && row.released_at == null);
    if (intent?.status === "accepted" && run && TERMINAL_RUN_STATUSES.has(run.status) && slotReleased) {
      return snapshot;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("brl_cancelled_run_terminal_or_slot_fence_wait_timed_out");
    await sleep(Math.min(1_000, remaining));
  }
}

function captureCompleteness(capture) {
  const gaps = Array.isArray(capture?.missingFixtures) ? capture.missingFixtures : ["capture_fixture_inventory_missing"];
  const complete = gaps.length === 0;
  return { ...capture, status: complete ? "verified" : "blocked", captureStatus: complete ? "complete" : "blocked" };
}

async function freshIntent(input, operationId, agentId = input.agentId) {
  const base = input.intent?.database ?? input.intent;
  const body = createRequestBody(input, base, operationId, agentId);
  const request = await ownerRequest(input, "/api/owner/runs/intents", body);
  const intentId = request.body?.intent?.id;
  return { request, intentId: typeof intentId === "string" ? intentId : null, body };
}

async function runScenario023PreAccept(input, pool, binding) {
  const { value: initialIntent, release, intentId } = binding;
  const before = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [intentId] });
  const duplicateCreate = await ownerRequest(input, "/api/owner/runs/intents", createRequestBody(input, initialIntent));
  const after = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [intentId] });
  const output = {
    schemaVersion: "benchmark-run-lifecycle-runtime-evidence/v1", scenarioId: "BRL-SC-023",
    ownerId: input.ownerId, agentId: input.agentId, database: { observer: before.observer },
    cases: {
      seed: { intent: initialIntent, release: { releaseIdentity: release.releaseIdentity,
        manifestHash: release.manifestHash, benchmarkHash: release.benchmarkHash,
        policyHash: release.policyHash, benchmarkVersion: release.benchmarkVersion } },
      duplicateCreate,
      preAcceptance: { before, after },
    },
    missingFixtures: [],
  };
  assertSecretFree(output, "BRL-SC-023 pre-acceptance evidence");
  return output;
}

function snapshotRowsByIntent(snapshot, intentId) {
  const database = snapshot?.database ?? {};
  const intent = Array.isArray(database.intents) ? database.intents.find((row) => row.id === intentId) : null;
  const run = intent?.run_id && Array.isArray(database.runs)
    ? database.runs.find((row) => row.id === intent.run_id) : null;
  return { intent: intent ?? null, run: run ?? null };
}

function evidenceBody(record) {
  return record?.body && typeof record.body === "object" ? record.body : {};
}

function runIdFromRecord(record) {
  const value = evidenceBody(record).run?.id;
  return typeof value === "string" ? value : null;
}

async function waitForPersistedExpiry(pool, { ownerId, agentId, intentId, expiresAt, timeoutMs = 16 * 60_000 }) {
  const deadline = Date.now() + timeoutMs;
  const expiresMs = Date.parse(expiresAt);
  requireValue(Number.isFinite(expiresMs), "brl_persisted_expiry_missing");
  while (true) {
    const snapshot = await readonlySnapshot(pool, { ownerId, agentId, intentIds: [intentId] });
    const observedMs = Date.parse(snapshot.database.observedAt);
    requireValue(Number.isFinite(observedMs), "brl_database_clock_observation_missing");
    if (observedMs >= expiresMs) return snapshot;
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("brl_post_completion_expiry_wait_timed_out");
    await sleep(Math.min(5_000, Math.max(250, expiresMs - observedMs + 25), remaining));
  }
}

function validatedPreCapture(preCapture) {
  requireValue(preCapture && preCapture["BRL-SC-023"]?.scenarioId === "BRL-SC-023"
    && preCapture["BRL-SC-024"]?.scenarioId === "BRL-SC-024", "brl_preaccept_capture_missing");
  const scenario023 = preCapture["BRL-SC-023"];
  const scenario024 = preCapture["BRL-SC-024"];
  const intent = scenario023.cases?.seed?.intent;
  requireValue(intent?.status === "pending" && intent.run_id == null, "brl_primary_intent_not_pending_after_prephase");
  return { scenario023, scenario024, intent };
}

async function runCapacityBoundary(input, pool) {
  const configuredOwnerLimit = Number.isInteger(input.ownerPendingLimit) ? input.ownerPendingLimit : null;
  if (configuredOwnerLimit === null || configuredOwnerLimit < 1 || configuredOwnerLimit > 100) {
    return { configuredOwnerLimit, observedOwnerLimit: null, maxPendingObserved: null,
      rejectedExtra: null, cleanupComplete: false, reasonCode: "pinned_local_per_owner_pending_intent_limit_missing_or_invalid" };
  }
  const pendingCount = async () => {
    const snapshot = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [] });
    return Number(snapshot.database.pendingOwnerCount);
  };
  let current = await pendingCount();
  const beforeCount = current;
  const intentIds = [];
  const createResponses = [];
  while (current < configuredOwnerLimit && intentIds.length <= configuredOwnerLimit) {
    if (intentIds.length) await new Promise((done) => setTimeout(done, 1_100));
    const result = await freshIntent(input, randomUUID());
    createResponses.push(result.request);
    if (responseStatus(result.request) !== 201 || !result.intentId) break;
    intentIds.push(result.intentId);
    current = await pendingCount();
  }
  const filledSnapshot = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds });
  const rejectedExtra = await ownerRequest(input, "/api/owner/runs/intents", createRequestBody(input,
    input.intent?.database ?? input.intent, randomUUID()));
  const maxPendingObserved = Math.max(beforeCount, Number(filledSnapshot.database.pendingOwnerCount));
  await new Promise((done) => setTimeout(done, 1_100));
  const cancelResponses = [];
  for (const intentId of intentIds) {
    cancelResponses.push(await ownerRequest(input, "/api/owner/runs/intents/" + intentId + "/cancel",
      { operationId: randomUUID() }));
    await new Promise((done) => setTimeout(done, 1_100));
  }
  const afterCleanup = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds });
  const cleanupComplete = afterCleanup.database.intents.length === intentIds.length
    && afterCleanup.database.intents.every((row) => row.status === "cancelled" || row.status === "expired")
    && Number(afterCleanup.database.pendingOwnerCount) === beforeCount;
  return { configuredOwnerLimit, observedOwnerLimit: configuredOwnerLimit, beforeCount,
    maxPendingObserved, createdIntentIds: intentIds, createResponses, rejectedExtra, filledSnapshot,
    cancelResponses, afterCleanup, cleanupComplete };
}

export function brlAuthorizationEvidence(ownerSessionAsAgent, foreignAgent) {
  const evidence = {authorizationChecks: {ownerSessionAsAgent, foreignAgent}};
  assertSecretFree(evidence, 'BRL authorization checks');
  return evidence;
}
async function runScenario024(input, pool, binding) {
  const { value: currentIntent, intentId } = binding;
  const beforeRejected = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [intentId] });
  const ownerOnlyOperationId = randomUUID();
  await paceAgentRequest();
  const ownerSessionAsAgent = await input.ownerPage.request.post(
    new URL("/api/agent/run-intents/" + intentId + "/accept", input.publicOrigin).href,
    { headers: { origin: new URL(input.publicOrigin).origin }, data: { operationId: ownerOnlyOperationId }, timeout: 15_000 },
  ).then(async (response) => cleanHttpRecord({ method: "POST", path: "/api/agent/run-intents/" + intentId + "/accept",
    requestBody: { operationId: ownerOnlyOperationId }, response: { status: response.status(), body: await jsonResponse(response) } }))
    .catch((error) => ({ status: null, body: {}, transportUnknown: true, errorName: error?.name ?? "Error" }));
  const staleQuoteBody = createRequestBody(input, currentIntent, randomUUID());
  staleQuoteBody.expectedQuotePrice = exactUsdc(BigInt(currentIntent.quote_price_units) + 1n);
  const staleCreate = await ownerRequest(input, "/api/owner/runs/intents", staleQuoteBody);
  const conflictingCreateBody = createRequestBody(input, currentIntent);
  conflictingCreateBody.cashCeiling = exactUsdc(BigInt(currentIntent.cash_ceiling_units) + 1n);
  const sameKeyChangedPayload = await ownerRequest(input, "/api/owner/runs/intents", conflictingCreateBody);
  let staleRelease = null;
  if (typeof input.activateNextRelease === "function" && typeof input.restoreRelease === "function") {
    const stale = await freshIntent(input, randomUUID());
    if (stale.intentId) {
      const before = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [stale.intentId] });
      const catalogBefore = await readOwnerCatalog(input);
      try {
        await input.activateNextRelease();
        const catalogAfter = await readOwnerCatalog(input);
        const acceptance = await agentHttpRequest(input, stale.intentId, randomUUID());
        const after = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [stale.intentId] });
        staleRelease = { request: stale.request, before, catalogBefore, catalogAfter, acceptance, after };
      } finally {
        await input.restoreRelease();
      }
    }
  }

  const afterRejected = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [intentId] });
  const cancelled = await freshIntent(input, randomUUID());
  let pendingCancel = null;
  let cancelledAccept = null;
  let cancelBefore = null;
  let cancelAfter = null;
  if (cancelled.intentId) {
    cancelBefore = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [cancelled.intentId] });
    pendingCancel = await ownerRequest(input, "/api/owner/runs/intents/" + cancelled.intentId + "/cancel", { operationId: randomUUID() });
    cancelledAccept = await agentHttpRequest(input, cancelled.intentId, randomUUID());
    cancelAfter = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [cancelled.intentId] });
  }

  const raceAgent = input.raceProbeAgent && typeof input.raceProbeAgent.agentId === "string"
    && typeof input.raceProbeAgent.bearer === "string"
    ? { ...input, agentId: input.raceProbeAgent.agentId, agentBearer: input.raceProbeAgent.bearer } : null;
  const race = raceAgent ? await freshIntent(raceAgent, randomUUID(), raceAgent.agentId) : { intentId: null, request: null };
  let cancelAcceptRace = { intentId: race.intentId, before: null, after: null, outcomes: [] };
  if (raceAgent && race.intentId) {
    cancelAcceptRace.before = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: raceAgent.agentId, intentIds: [race.intentId] });
    const outcomes = await Promise.allSettled([
      ownerRequest(raceAgent, "/api/owner/runs/intents/" + race.intentId + "/cancel", { operationId: randomUUID() }),
      agentHttpRequest(raceAgent, race.intentId, randomUUID()),
    ]);
    cancelAcceptRace.outcomes = outcomes.map((row) => row.status === "fulfilled"
      ? row.value : { rejected: true, errorName: row.reason?.name ?? "Error" });
    cancelAcceptRace.after = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: raceAgent.agentId, intentIds: [race.intentId] });
    const raceIntent = cancelAcceptRace.after.database.intents.find((row) => row.id === race.intentId);
    if (raceIntent?.status === "accepted" && raceIntent.run_id) {
      cancelAcceptRace.cleanup = await ownerRequest(raceAgent,
        "/api/owner/runs/intents/" + race.intentId + "/cancel", { operationId: randomUUID() });
      cancelAcceptRace.after = await waitForTerminalAndReleasedSlot(pool, { ownerId: input.ownerId,
        agentId: raceAgent.agentId, intentId: race.intentId });
    } else {
      cancelAcceptRace.cleanup = null;
    }
  }

  const foreignPrincipal = input.foreignAgent ?? input.raceProbeAgent;
  const foreignAgent = foreignPrincipal?.bearer
    ? await agentHttpRequest(input, intentId, randomUUID(), { bearer: foreignPrincipal.bearer }) : null;
  let foreignOwnerRead = null;
  if (input.foreignOwnerPage?.request) {
    const response = await input.foreignOwnerPage.request.get(
      new URL("/api/owner/runs/intents/" + intentId, input.publicOrigin).href, { timeout: 15_000 });
    foreignOwnerRead = { status: response.status(), body: await jsonResponse(response) };
  }

  const expiryIntent = await freshIntent(input, randomUUID());
  expiryIntent.before = expiryIntent.intentId
    ? await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [expiryIntent.intentId] })
    : null;
  const capacity = await runCapacityBoundary(input, pool);
  const output = {
    schemaVersion: "benchmark-run-lifecycle-runtime-evidence/v1", scenarioId: "BRL-SC-024",
    ownerId: input.ownerId, agentId: input.agentId, database: { observer: afterRejected.observer },
    cases: {
      ...brlAuthorizationEvidence(ownerSessionAsAgent, foreignAgent),
      stalePolicy: { staleCreate, sameKeyChangedPayload, staleRelease,
        postIntentPolicyChangeRejected: Boolean(staleRelease),
        increasedCashRejected: false, cashPermissionRevokedRejected: false, deadlineAcceptanceRejected: false,
        missingFixtures: [
          ...(staleRelease ? [] : ["offline_validated_release_activation_fixture"]),
          "agent_or_cash_policy_revocation_fixture", "available_funds_change_fixture",
          "deadline_acceptance_probe_runs_after_persisted_expiry",
        ] },
      rejectedEffects: { before: beforeRejected, after: afterRejected, pendingCancel, cancelledAccept,
        cancelBefore, cancelAfter },
      cancelAcceptRace,
      expiryIntent,
      postAdmissionCancel: null,
      capacity,
      foreignAccess: { foreignOwnerReadStatus: foreignOwnerRead?.status ?? null,
        foreignOwnerResponseOmitsIntent: !foreignOwnerRead?.body?.intent, foreignAgent,
        foreignAgentResponseOmitsRun: !foreignAgent?.body?.run },
    },
    missingFixtures: [
      ...(!input.foreignAgent ? ["second_active_agent_credential_for_foreign_agent_negative"] : []),
      ...(!input.foreignOwnerPage ? ["second_authenticated_owner_page_for_foreign_owner_negative"] : []),
      ...(!Number.isInteger(input.ownerPendingLimit) ? ["pinned_local_per_owner_pending_intent_limit"] : []),
      ...(!raceAgent ? ["isolated_race_agent_with_current_owner_authority"] : []),
      ...(!staleRelease ? ["post_intent_release_mutation_callback"] : []),
      "post_intent_cash_and_permission_mutation_fixtures",
      "at_deadline_acceptance_requires_completion_wait_for_precreated_expiry_intent",
      ...(capacity.cleanupComplete ? [] : ["capacity_boundary_fixture_and_cleanup"]),
    ],
  };
  assertSecretFree(output, "BRL-SC-024 runtime evidence");
  return output;
}

function validateProbeInput(input) {
  requireValue(input && input.ownerPage && typeof input.ownerPage.request?.post === "function", "brl_owner_page_required");
  requireValue(typeof input.publicOrigin === "string" && new URL(input.publicOrigin).protocol === "http:", "brl_loopback_origin_required");
  requireValue(typeof input.ownerId === "string" && typeof input.agentId === "string", "brl_owner_agent_identity_required");
  requireValue(typeof input.agentBearer === "string" && input.agentBearer.length > 0, "brl_agent_bearer_required");
  requireValue(typeof input.observerDatabaseUrl === "string" && input.observerDatabaseUrl.length > 0, "brl_observer_database_required");
}

/**
 * Run launch-intent checks before primary acceptance. This function deliberately
 * does not accept or cancel the primary intent; the selected Codex agent client
 * must perform its first acceptance in the caller.
 */
export async function runBrlLaunchAdmissionPreAcceptCases(input) {
  validateProbeInput(input);
  const binding = baseIntent(input);
  const pool = new pg.Pool({ connectionString: input.observerDatabaseUrl, max: 1,
    application_name: "brl-launch-admission-readonly-probe" });
  try {
    const observed = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId, intentIds: [binding.intentId] });
    const intent = observed.database.intents.find((row) => row.id === binding.intentId);
    requireValue(intent && intent.status === "pending" && intent.run_id == null
      && intent.owner_id === input.ownerId && intent.agent_id === input.agentId, "brl_intent_not_pending_for_probe");
    const captures = {
      "BRL-SC-023": await runScenario023PreAccept(input, pool, binding),
      "BRL-SC-024": await runScenario024(input, pool, binding),
    };
    return captures;
  } finally { await pool.end(); }
}

/**
 * Capture only the live BRL-023 pending-intent and duplicate-create boundary.
 * BRL-024 is explicitly blocked because the full negative matrix is not selected.
 * This diagnostic profile never accepts, cancels, or creates another intent.
 */
export async function runBrlLaunchAdmissionPrimaryOnlyCase(input) {
  validateProbeInput(input);
  const binding = baseIntent(input);
  const pool = new pg.Pool({ connectionString: input.observerDatabaseUrl, max: 1,
    application_name: "brl-primary-only-readonly-probe" });
  try {
    const observed = await readonlySnapshot(pool, { ownerId: input.ownerId,
      agentId: input.agentId, intentIds: [binding.intentId] });
    const intent = observed.database.intents.find((row) => row.id === binding.intentId);
    requireValue(intent && intent.status === "pending" && intent.run_id == null
      && intent.owner_id === input.ownerId && intent.agent_id === input.agentId,
      "brl_primary_only_intent_not_pending_for_probe");
    const scenario023 = {
      ...await runScenario023PreAccept(input, pool, binding),
      status: "blocked",
      missingFixtures: ["full_launch_negative_matrix_not_selected"],
    };
    const scenario024 = {
      schemaVersion: "benchmark-run-lifecycle-runtime-evidence/v1",
      scenarioId: "BRL-SC-024",
      status: "blocked",
      ownerId: input.ownerId,
      agentId: input.agentId,
      database: { observer: observed.observer },
      cases: {},
      missingFixtures: ["full_launch_negative_matrix_not_selected"],
    };
    assertSecretFree(scenario024, "BRL-SC-024 unselected primary-only diagnostic");
    const captures = { "BRL-SC-023": scenario023, "BRL-SC-024": scenario024 };
    assertSecretFree(captures, "BRL primary-only launch diagnostic");
    return captures;
  } finally { await pool.end(); }
}
/**
 * Bind the real Codex-native MCP acceptance receipt to an independent DB
 * snapshot before the caller starts the worker. No SDK MCP request is sent here.
 */
export async function captureBrlPrimaryMcpAcceptance(input, preCapture, nativeMcpReceipt, observations = {}) {
  validateProbeInput(input);
  const { scenario023, intent } = validatedPreCapture(preCapture);
  requireValue(nativeMcpReceipt && nativeMcpReceipt.toolName === "runs.accept_launch_intent"
    && nativeMcpReceipt.clientBoundary === "codex_native_mcp_agent_case"
    && nativeMcpReceipt.isError !== true && responseStatus(nativeMcpReceipt) === 200,
  "brl_primary_acceptance_must_be_codex_native_mcp_success");
  requireValue(typeof nativeMcpReceipt.operationId === "string" && nativeMcpReceipt.operationId.length >= 12,
    "brl_primary_acceptance_operation_id_missing");
  const acceptedRunId = runIdFromRecord(nativeMcpReceipt);
  requireValue(acceptedRunId, "brl_primary_mcp_receipt_run_missing");
  const pool = new pg.Pool({ connectionString: input.observerDatabaseUrl, max: 1,
    application_name: "brl-primary-mcp-acceptance-readonly-probe" });
  try {
    const after = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId,
      intentIds: [intent.id] });
    const rows = snapshotRowsByIntent(after, intent.id);
    requireValue(rows.intent?.status === "accepted" && rows.intent.run_id === acceptedRunId
      && rows.run?.id === acceptedRunId && rows.run.intent_id === intent.id,
    "brl_primary_mcp_acceptance_database_binding_mismatch");
    const cardPublicationCount = (after.database.publicActionMarkers?.length ?? 0)
      + (after.database.rankedBestResults?.length ?? 0);
    const noHostedModelInvocation = observations.llmBenchmarkInvocation === false
      && observations.externalModelCalls === 0
      && (after.database.actions ?? []).length === 0;
    const record = {
      toolName: nativeMcpReceipt.toolName,
      operationId: nativeMcpReceipt.operationId,
      isError: false,
      status: 200,
      body: safeBody(evidenceBody(nativeMcpReceipt)),
      clientBoundary: nativeMcpReceipt.clientBoundary,
      clientModel: {
        externalModelCalls: Number.isSafeInteger(observations.externalModelCalls) ? observations.externalModelCalls : null,
        llmBenchmarkInvocation: observations.llmBenchmarkInvocation === false ? false : null,
      },
    };
    assertSecretFree(record, "BRL native MCP acceptance record");
    const capture = {
      ...scenario023,
      database: { observer: after.observer },
      cases: {
        ...scenario023.cases,
        acceptance: {
          before: scenario023.cases.preAcceptance.after,
          after,
          attempts: { primaryMcp: record },
          observations: {
            llmBenchmarkInvocation: observations.llmBenchmarkInvocation === false ? false : null,
            externalModelCalls: Number.isSafeInteger(observations.externalModelCalls)
              ? observations.externalModelCalls : null,
            noHostedModelInvocation,
            cardPublicationCount,
          },
        },
      },
      missingFixtures: [...(scenario023.missingFixtures ?? []),
        ...(noHostedModelInvocation ? [] : ["pre_worker_model_invocation_counter"]),
        ...(cardPublicationCount === 0 ? [] : ["pre_worker_card_publication_counter"])],
    };
    assertSecretFree(capture, "BRL-SC-023 native MCP acceptance capture");
    return capture;
  } finally { await pool.end(); }
}

async function runPostAdmissionCancelProbe(input, pool) {
  const probe = input.postCancelProbeAgent;
  if (!probe || typeof probe.agentId !== "string" || typeof probe.bearer !== "string") {
    return { status: "not_run", reasonCode: "separate_post_admission_cancellation_agent_missing" };
  }
  const actor = { ...input, agentId: probe.agentId, agentBearer: probe.bearer };
  const created = await freshIntent(actor, randomUUID(), probe.agentId);
  if (!created.intentId || responseStatus(created.request) !== 201) {
    return { status: "blocked", reasonCode: "post_admission_cancellation_intent_creation_failed", request: created.request };
  }
  const acceptOperationId = randomUUID();
  const before = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: probe.agentId,
    intentIds: [created.intentId] });
  const acceptance = await agentHttpRequest(actor, created.intentId, acceptOperationId);
  const runId = runIdFromRecord(acceptance);
  if (responseStatus(acceptance) !== 200 || !runId) {
    const after = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: probe.agentId,
      intentIds: [created.intentId] });
    return { status: "blocked", reasonCode: "post_admission_cancellation_acceptance_failed",
      request: created.request, before, acceptance, after };
  }
  const accepted = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: probe.agentId,
    intentIds: [created.intentId] });
  const cancel = await ownerRequest(input, "/api/owner/runs/intents/" + created.intentId + "/cancel",
    { operationId: randomUUID() });
  const after = await waitForTerminalAndReleasedSlot(pool, { ownerId: input.ownerId, agentId: probe.agentId,
    intentId: created.intentId });
  const rows = snapshotRowsByIntent(after, created.intentId);
  const terminalAndReleased = rows.intent?.status === "accepted" && rows.run
    && TERMINAL_RUN_STATUSES.has(rows.run.status)
    && !after.database.slots.some((row) => row.run_id === rows.run.id && row.released_at == null);
  return { status: responseStatus(cancel) === 200 && terminalAndReleased ? "observed" : "blocked",
    reasonCode: responseStatus(cancel) === 200 && terminalAndReleased ? null : "post_admission_cancel_or_terminal_fence_unverified",
    intentId: created.intentId, request: created.request, before,
    acceptance, accepted, cancel, after, intent: rows.intent, run: rows.run };
}

/**
 * Run expiry and admitted-retry checks only after the primary worker is terminal.
 * The potentially long wait is based on persisted expires_at and never delays
 * the benchmark run's admission or execution window.
 */
export async function runBrlLaunchAdmissionPostCompletionCases(input, { preCapture, primaryAcceptance, httpReplay }) {
  validateProbeInput(input);
  const { scenario023: pre023, scenario024: pre024, intent } = validatedPreCapture(preCapture);
  requireValue(primaryAcceptance?.scenarioId === "BRL-SC-023"
    && primaryAcceptance.cases?.acceptance?.after, "brl_primary_acceptance_snapshot_missing");
  requireValue(httpReplay && httpReplay.method === "POST" && responseStatus(httpReplay) === 200,
    "brl_primary_http_replay_record_missing");
  const primaryOperationId = primaryAcceptance.cases.acceptance.attempts.primaryMcp.operationId;
  requireValue(typeof primaryOperationId === "string", "brl_primary_operation_id_missing");
  requireValue(httpReplay.request?.operationId === primaryOperationId,
    "brl_primary_http_replay_must_reuse_native_mcp_operation_id");
  const acceptedId = snapshotRowsByIntent(primaryAcceptance.cases.acceptance.after, intent.id).run?.id;
  requireValue(acceptedId && runIdFromRecord(httpReplay) === acceptedId,
    "brl_primary_http_replay_run_mismatch");

  const pool = new pg.Pool({ connectionString: input.observerDatabaseUrl, max: 1,
    application_name: "brl-launch-admission-post-completion-readonly-probe" });
  let restoreRelease = false;
  try {
    const completion = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId,
      intentIds: [intent.id] });
    const terminal = snapshotRowsByIntent(completion, intent.id);
    requireValue(terminal.intent?.status === "accepted" && terminal.run?.id === acceptedId
      && TERMINAL_RUN_STATUSES.has(terminal.run.status)
      && !completion.database.slots.some((row) => row.run_id === acceptedId && row.released_at == null),
    "brl_post_completion_probe_requires_terminal_primary_and_released_slot");

    let postChange = null;
    if (typeof input.activateNextRelease === "function" && typeof input.restoreRelease === "function") {
      const catalogBefore = await readOwnerCatalog(input);
      await input.activateNextRelease();
      restoreRelease = true;
      const catalogAfter = await readOwnerCatalog(input);
      const releaseChanged = catalogBefore.activeRelease?.releaseIdentity !== catalogAfter.activeRelease?.releaseIdentity
        || catalogBefore.activeRelease?.manifestHash !== catalogAfter.activeRelease?.manifestHash
        || catalogBefore.activeRelease?.rankedPrice !== catalogAfter.activeRelease?.rankedPrice
        || catalogBefore.activeRelease?.trainingPrice !== catalogAfter.activeRelease?.trainingPrice;
      let beforeRetry = await waitForPersistedExpiry(pool, { ownerId: input.ownerId, agentId: input.agentId,
        intentId: intent.id, expiresAt: intent.expires_at });
      const expiryIntentId = pre024.cases?.expiryIntent?.intentId;
      const expiryIntent = expiryIntentId
        ? pre024.cases.expiryIntent.before?.database?.intents?.find((row) => row.id === expiryIntentId)
        : null;
      if (expiryIntent && Date.parse(expiryIntent.expires_at) > Date.parse(beforeRetry.database.observedAt)) {
        await waitForPersistedExpiry(pool, { ownerId: input.ownerId, agentId: input.agentId,
          intentId: expiryIntentId, expiresAt: expiryIntent.expires_at });
      }

      const retryOperationId = randomUUID();
      const lostHttp = await agentHttpRequest(input, intent.id, retryOperationId, { dropResponse: true });
      const restart = await healthAfterRestart(input);
      const httpRetry = await agentHttpRequest(input, intent.id, retryOperationId);
      const mcpRetry = await mcpAccept(input, intent.id, retryOperationId);
      const afterRetry = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId,
        intentIds: [intent.id] });
      postChange = { beforeChange: completion, catalogBefore, catalogAfter, releaseChanged,
        primaryOperationId, retryOperationId, beforeRetry, lostHttp, restart, httpRetry, mcpRetry, afterRetry };

      let deadlineAttempt = null;
      let deadlineBefore = null;
      let deadlineAfter = null;
      if (expiryIntentId) {
        deadlineBefore = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId,
          intentIds: [expiryIntentId] });
        deadlineAttempt = await agentHttpRequest(input, expiryIntentId, randomUUID());
        deadlineAfter = await readonlySnapshot(pool, { ownerId: input.ownerId, agentId: input.agentId,
          intentIds: [expiryIntentId] });
      }
      const postAdmissionCancel = await runPostAdmissionCancelProbe(input, pool);
      const capture024 = {
        ...pre024,
        cases: { ...pre024.cases,
          stalePolicy: { ...pre024.cases.stalePolicy,
            deadlineAcceptanceRejected: Boolean(deadlineAttempt && responseStatus(deadlineAttempt) === 410
              && evidenceBody(deadlineAttempt).error?.code === "RUN_INTENT_EXPIRED"
              && !snapshotRowsByIntent(deadlineAfter, expiryIntentId).run),
            deadlineAttempt: deadlineAttempt ? { attempt: deadlineAttempt, before: deadlineBefore, after: deadlineAfter } : null,
          },
          postAdmissionCancel,
        },
      };
      capture024.missingFixtures = (capture024.missingFixtures ?? []).filter((item) =>
        item !== "at_deadline_acceptance_requires_completion_wait_for_precreated_expiry_intent");
      if (!capture024.cases.stalePolicy.deadlineAcceptanceRejected) {
        capture024.missingFixtures.push("expired_pending_intent_agent_acceptance_evidence");
      }
      if (postAdmissionCancel.status !== "observed") {
        capture024.missingFixtures.push("post_admission_cancellation_agent_and_run_fixture");
      }
      const capture023 = {
        ...primaryAcceptance,
        cases: { ...primaryAcceptance.cases,
          acceptance: { ...primaryAcceptance.cases.acceptance,
            attempts: { ...primaryAcceptance.cases.acceptance.attempts, httpReplay, lostHttp, httpRetry, mcpRetry },
            restart, postChangeRetry: postChange,
            noHostedModelInvocation: primaryAcceptance.cases.acceptance.observations?.noHostedModelInvocation === true,
            cardPublicationCount: primaryAcceptance.cases.acceptance.observations?.cardPublicationCount ?? null,
          },
        },
      };
      capture023.missingFixtures = (capture023.missingFixtures ?? []).filter((item) =>
        item !== "offline_validated_release_activation_fixture"
        && item !== "post_completion_expiry_observation");
      if (!releaseChanged) capture023.missingFixtures.push("post_acceptance_catalog_tariff_or_version_change");
      assertSecretFree(capture023, "BRL-SC-023 post-completion evidence");
      assertSecretFree(capture024, "BRL-SC-024 post-completion evidence");
      return { "BRL-SC-023": captureCompleteness(capture023), "BRL-SC-024": captureCompleteness(capture024) };
    }

    const expiryIntentId = pre024.cases?.expiryIntent?.intentId;
    if (expiryIntentId) {
      const expiryIntent = pre024.cases.expiryIntent.before?.database?.intents?.find((row) => row.id === expiryIntentId);
      if (expiryIntent) await waitForPersistedExpiry(pool, { ownerId: input.ownerId, agentId: input.agentId,
        intentId: expiryIntentId, expiresAt: expiryIntent.expires_at });
    }
    return {
      "BRL-SC-023": captureCompleteness({ ...primaryAcceptance,
        missingFixtures: [...(primaryAcceptance.missingFixtures ?? []), "offline_validated_release_activation_fixture"] }),
      "BRL-SC-024": captureCompleteness({ ...pre024, missingFixtures: [...(pre024.missingFixtures ?? []),
        "offline_validated_release_activation_fixture", "post_admission_cancellation_agent_and_run_fixture"] }),
    };
  } finally {
    if (restoreRelease) await input.restoreRelease();
    await pool.end();
  }
}

export async function writeBrlLaunchAdmissionEvidence({ repositoryRoot, captures, provenance = {} }) {
  const repoRoot = resolve(repositoryRoot);
  const contractPath = resolve(repoRoot, "tests/bdd/changes/benchmark-run-lifecycle/harness-contracts.json");
  const contractBytes = await readFile(contractPath);
  const contract = JSON.parse(contractBytes.toString("utf8"));
  const contractSha256 = sha256(contractBytes);
  const sourcePaths = ["packages/owner-identity/src/run-routes.ts", "packages/owner-identity/src/run-service.ts",
    "packages/owner-acceptance/src/benchmark-run-lifecycle-launch-probe.mjs"];
  const hashesBefore = provenance.inputHashesBefore;
  const hashesAfter = provenance.inputHashesAfter;
  let sourceStable = provenance.sourceStableDuringRun === true && hashesBefore && typeof hashesBefore === "object"
    && !Array.isArray(hashesBefore) && Object.keys(hashesBefore).length > 0
    && JSON.stringify(Object.entries(hashesBefore).sort(([left], [right]) => left.localeCompare(right)))
      === JSON.stringify(Object.entries(hashesAfter ?? {}).sort(([left], [right]) => left.localeCompare(right)))
    && sourcePaths.every((relativePath) => typeof hashesBefore[relativePath] === "string");
  if (sourceStable) {
    for (const [relativePath, expectedHash] of Object.entries(hashesBefore)) {
      const sourcePath = resolve(repoRoot, relativePath);
      const relative = sourcePath.slice(repoRoot.length + 1).replaceAll("\\", "/");
      if (relative.startsWith("../") || relative === ".." || relativePath.includes("\\")
          || relativePath.includes(":") || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$/.test(relativePath)
          || !/^[0-9a-f]{64}$/i.test(expectedHash)
          || sha256(await readFile(sourcePath)) !== expectedHash.toLowerCase()) {
        sourceStable = false;
        break;
      }
    }
  }
  const results = {};
  for (const scenarioId of SCENARIOS) {
    const capture = captures?.[scenarioId];
    requireValue(capture?.scenarioId === scenarioId, "brl_capture_scenario_binding_invalid");
    assertSecretFree(capture, scenarioId + " evidence");
    const runId = randomUUID();
    const scenarioRoot = resolve(repoRoot, "artifacts/runs/acceptance", scenarioId);
    const runDirectory = resolve(scenarioRoot, "runs", runId);
    await mkdir(runDirectory, { recursive: true });
    const rawBytes = Buffer.from(JSON.stringify(capture, null, 2) + "\n");
    const rawHash = sha256(rawBytes);
    await writeFile(resolve(runDirectory, "runtime-evidence.json"), rawBytes, { flag: "wx" });
    const provenancePayload = { ...provenance,
      schemaVersion: "benchmark-run-lifecycle-provenance/v1", contractSha256,
      source: "Docker local owner-identity acceptance runtime", sourceStableDuringRun: sourceStable,
    };
    assertSecretFree(provenancePayload, scenarioId + " provenance");
    const provenanceBytes = Buffer.from(JSON.stringify(provenancePayload, null, 2) + "\n");
    await writeFile(resolve(runDirectory, "provenance.json"), provenanceBytes, { flag: "wx" });
    const required = contract.protected_scenarios[scenarioId];
    const gaps = [...(Array.isArray(capture.missingFixtures) ? capture.missingFixtures : []),
      ...(sourceStable ? [] : ["source_inventory_missing_or_changed"])];
    const complete = gaps.length === 0;
    const status = complete ? "passed" : "blocked";
    const observations = Object.fromEntries(required.required_observations.map((name) => [name,
      complete ? { status: "observed" } : { status: "not_run", reasonCode: "required_fixture_missing" }]));
    const negativeVariants = Object.fromEntries(required.negative_variants.map((name) => [name,
      complete ? { status: "observed" } : { status: "not_run", reasonCode: "required_fixture_missing" }]));
    const reason = complete ? null : "required_live_fixture_missing";
    const artifacts = [
      { path: "runtime-evidence.json", sha256: rawHash, boundary: required.boundary_detail, contentType: "application/json" },
      { path: "provenance.json", sha256: sha256(provenanceBytes), boundary: "Docker source and contract hashes", contentType: "application/json" },
    ];
    const manifest = {
      schemaVersion: "benchmark-run-lifecycle-acceptance/v1", specProfile: "active-delta",
      scenarioId, runId, status, ...(reason ? { blockedReasonCode: reason } : {}),
      observationStatus: complete ? "complete" : "not_run", negativeVariantStatus: complete ? "complete" : "not_run",
      observations, negativeVariants, artifacts,
    };
    assertSecretFree(manifest, scenarioId + " manifest");
    await writeFile(resolve(runDirectory, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
    const indexPath = resolve(scenarioRoot, "manifest.json");
    let previousRuns = [];
    try {
      const previous = JSON.parse(await readFile(indexPath, "utf8"));
      if (previous.schemaVersion === "benchmark-run-lifecycle-evidence-index/v1" && Array.isArray(previous.runs)) {
        previousRuns = previous.runs.filter((item) => typeof item === "string" && /^[0-9a-f-]{36}$/i.test(item));
      }
    } catch { /* A malformed prior index is not trusted as provenance. */ }
    const index = { schemaVersion: "benchmark-run-lifecycle-evidence-index/v1", scenarioId, status,
      latestRunId: runId, runs: [...new Set([...previousRuns, runId])], ...(reason ? { blockedReasonCode: reason } : {}) };
    const indexTemp = resolve(scenarioRoot, ".manifest-" + runId + ".tmp");
    await writeFile(indexTemp, JSON.stringify(index, null, 2) + "\n", { flag: "wx" });
    await rename(indexTemp, indexPath);
    results[scenarioId] = { status, runId, rawEvidenceSha256: rawHash, blockedReasonCode: reason };
  }
  return results;
}
