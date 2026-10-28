import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  CODEX_CLI_VERSION,
  runCodexNativeOwnerRevocationProbe,
} from "./codex-client-cases.mjs";
import { assertSecretFree } from "./evidence.mjs";

const MCP_PROTOCOL = "2026-07-28";
const MCP_SDK_VERSION = "2.4.0";
const MIN_AGENT_REQUEST_INTERVAL_MS = 1_100;

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createRequestPacer(intervalMs) {
  let queue = Promise.resolve();
  let nextStart = 0;
  return () => {
    const current = queue.then(async () => {
      const delay = Math.max(0, nextStart - performance.now());
      if (delay > 0) await wait(delay);
      nextStart = performance.now() + intervalMs;
    });
    queue = current.catch(() => undefined);
    return current;
  };
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeCode(value) {
  return typeof value === "string" && /^[A-Za-z0-9_]{1,96}$/.test(value) ? value : null;
}

function safeError(error) {
  return safeCode(error?.code) ?? safeCode(error?.cause?.code) ?? "PROFILE_PROBE_UNAVAILABLE";
}

function profileErrorCode(body) {
  return safeCode(isRecord(body?.error) ? body.error.code : null);
}

function toolPayload(result) {
  if (isRecord(result?.structuredContent)) return result.structuredContent;
  for (const item of Array.isArray(result?.content) ? result.content : []) {
    if (item?.type !== "text" || typeof item.text !== "string" || item.text.length > 64 * 1024) continue;
    try {
      const parsed = JSON.parse(item.text);
      if (isRecord(parsed)) return parsed;
    } catch { /* Retain no raw tool text. */ }
  }
  return {};
}

function runIdFrom(value) {
  const candidate = value?.runId ?? value?.run?.id;
  return typeof candidate === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(candidate)
    ? candidate.toLowerCase() : null;
}

function operationId() {
  return "codex-profile-" + randomUUID();
}

async function installedMcpSdkVersion() {
  try {
    const manifest = JSON.parse(await readFile(
      new URL("../node_modules/@modelcontextprotocol/client/package.json", import.meta.url),
      "utf8",
    ));
    return typeof manifest.version === "string" ? manifest.version : null;
  } catch {
    return null;
  }
}

function localOrigin(value) {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]", "::1"].includes(parsed.hostname)
      || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw Object.assign(new Error("profile_requires_local_loopback_origin"), { code: "PROFILE_LOOPBACK_ORIGIN_REQUIRED" });
  }
  return parsed.origin;
}

function requestHeaders(origin, bearer, extras = {}) {
  return {
    authorization: "Bearer " + bearer,
    origin,
    "content-type": "application/json",
    ...extras,
  };
}

function initializeBody(clientInfo = { name: "codex-mcp-client", version: CODEX_CLI_VERSION }) {
  return {
    jsonrpc: "2.0",
    id: randomUUID(),
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo,
    },
  };
}

async function rawMcpInitialize({ url, origin, bearer, protocol = "2025-06-18", clientInfo,
  modern = false, pacer }) {
  await pacer();
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: requestHeaders(origin, bearer, {
        accept: "application/json, text/event-stream",
        "mcp-protocol-version": protocol,
        ...(modern ? { "mcp-method": "initialize" } : {}),
      }),
      body: JSON.stringify(initializeBody(clientInfo)),
    });
  } catch (error) {
    return { status: null, errorCode: safeError(error) };
  }
  let body = {};
  try {
    const parsed = await response.json();
    if (isRecord(parsed)) body = parsed;
  } catch { /* Status remains useful; raw response text is never retained. */ }
  return { status: response.status, errorCode: profileErrorCode(body) };
}

async function rawPreflight({ origin, bearer, agentId, resource, pacer }) {
  await pacer();
  let response;
  try {
    response = await fetch(new URL("/api/agent/preflight", origin), {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: {
        authorization: "Bearer " + bearer,
        "x-agent-id": agentId,
        "x-agent-resource": resource,
      },
    });
  } catch (error) {
    return { status: null, errorCode: safeError(error) };
  }
  let body = {};
  try {
    const parsed = await response.json();
    if (isRecord(parsed)) body = parsed;
  } catch { /* Status remains useful; raw response text is never retained. */ }
  return { status: response.status, errorCode: profileErrorCode(body) };
}

async function rawHttpAccept({ origin, bearer, intentId, acceptOperationId, pacer }) {
  const path = "/api/agent/run-intents/" + encodeURIComponent(intentId) + "/accept";
  await pacer();
  let response;
  try {
    response = await fetch(new URL(path, origin), {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: requestHeaders(origin, bearer),
      body: JSON.stringify({ operationId: acceptOperationId }),
    });
  } catch (error) {
    return { status: null, replayed: null, runId: null, errorCode: safeError(error) };
  }
  let body = {};
  try {
    const parsed = await response.json();
    if (isRecord(parsed)) body = parsed;
  } catch { /* Do not retain raw response text. */ }
  return {
    status: response.status,
    replayed: typeof body.replayed === "boolean" ? body.replayed : null,
    runId: runIdFrom(body),
    errorCode: profileErrorCode(body),
  };
}

async function readonlySnapshot(observerPool, { runId, intentId, agentId }) {
  const client = await observerPool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query(
      "SELECT current_user AS role,current_setting('transaction_read_only') AS transaction_read_only,current_database() AS database_name",
    )).rows[0] ?? {};
    if (identity.role !== "oid_observer" || identity.transaction_read_only !== "on") {
      throw Object.assign(new Error("profile_observer_not_readonly"), { code: "PROFILE_OBSERVER_NOT_READONLY" });
    }
    const run = (await client.query(
      "SELECT id::text,owner_id::text,agent_id::text,intent_id::text,status,mode,access_generation::text," +
      "quote_price_units::text,cash_ceiling_units::text FROM oid_benchmark_run " +
      "WHERE id=$1::uuid AND intent_id=$2::uuid AND agent_id=$3::uuid",
      [runId, intentId, agentId],
    )).rows[0] ?? null;
    if (!run) throw Object.assign(new Error("profile_primary_run_not_observed"), { code: "PROFILE_PRIMARY_RUN_NOT_OBSERVED" });
    const params = [run.owner_id, agentId];
    const intent = (await client.query(
      "SELECT id::text,owner_id::text,agent_id::text,status,run_id::text,operation_id," +
      "accepted_at::text,expires_at::text FROM oid_run_launch_intent " +
      "WHERE id=$3::uuid AND owner_id=$1::uuid AND agent_id=$2::uuid",
      [...params, intentId],
    )).rows[0] ?? null;
    const profile = (await client.query(
      "SELECT id::text,owner_id::text,access_revision::text,access_generation::text,access_revoked_at::text " +
      "FROM oid_agent WHERE id=$2::uuid AND owner_id=$1::uuid",
      params,
    )).rows[0] ?? null;
    const grants = (await client.query(
      "SELECT id::text,resource,role,source,access_generation::text,expires_at::text,revoked_at::text,revocation_reason " +
      "FROM oid_agent_access_grant WHERE owner_id=$1::uuid AND agent_id=$2::uuid ORDER BY created_at,id",
      params,
    )).rows;
    const reservations = (await client.query(
      "SELECT id::text,source_kind,amount_units::text,state,created_at::text,changed_at::text " +
      "FROM oid_run_reservation WHERE owner_id=$1::uuid AND run_id=$2::uuid ORDER BY id",
      [run.owner_id, runId],
    )).rows;
    const budgetHolds = (await client.query(
      "SELECT run_id::text,owner_id::text,agent_id::text,mode,utc_day,amount_units::text,state,created_at::text,changed_at::text " +
      "FROM oid_run_budget_hold WHERE owner_id=$1::uuid AND agent_id=$2::uuid AND run_id=$3::uuid ORDER BY run_id",
      [...params, runId],
    )).rows;
    const runOperationIds = [
      "runacc_" + runId.replaceAll("-", ""),
      "rundeb_" + runId.replaceAll("-", ""),
    ];
    const ledgerEntries = (await client.query(
      "SELECT id::text,operation_id,entry_type,source_kind,amount_units::text,available_delta_units::text," +
      "reserved_delta_units::text,expired_delta_units::text,created_at::text FROM oid_ledger_entry " +
      "WHERE owner_id=$1::uuid AND operation_id=ANY($2::text[]) ORDER BY operation_id,id",
      [run.owner_id, runOperationIds],
    )).rows;
    await client.query("COMMIT");
    return {
      observer: {
        role: identity.role,
        transactionReadOnly: identity.transaction_read_only,
        databaseName: identity.database_name,
      },
      run,
      intent,
      profile,
      grants,
      reservations,
      budgetHolds,
      ledgerEntries,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function financialProjection(snapshot) {
  if (!snapshot) return null;
  return {
    run: snapshot.run && {
      id: snapshot.run.id,
      status: snapshot.run.status,
      mode: snapshot.run.mode,
      accessGeneration: snapshot.run.access_generation,
      quotePriceUnits: snapshot.run.quote_price_units,
      cashCeilingUnits: snapshot.run.cash_ceiling_units,
    },
    reservations: snapshot.reservations,
    budgetHolds: snapshot.budgetHolds,
    ledgerEntries: snapshot.ledgerEntries,
  };
}

function financialHash(snapshot) {
  if (!snapshot) return null;
  return createHash("sha256").update(JSON.stringify(financialProjection(snapshot))).digest("hex");
}

function databaseBound(snapshot, { runId, intentId, agentId }) {
  return Boolean(snapshot?.observer?.role === "oid_observer"
    && snapshot?.observer?.transactionReadOnly === "on"
    && snapshot?.run?.id === runId
    && snapshot?.run?.intent_id === intentId
    && snapshot?.run?.agent_id === agentId
    && snapshot?.intent?.id === intentId
    && snapshot?.intent?.run_id === runId
    && snapshot?.intent?.owner_id === snapshot?.run?.owner_id
    && snapshot?.intent?.agent_id === agentId
    && snapshot?.intent?.status === "accepted"
    && snapshot?.profile?.id === agentId
    && snapshot?.profile?.owner_id === snapshot?.run?.owner_id);
}

function outputSnapshot(snapshot) {
  if (!snapshot) return null;
  return {
    observer: snapshot.observer,
    run: snapshot.run,
    intent: snapshot.intent,
    profile: snapshot.profile,
    grants: snapshot.grants,
    reservations: snapshot.reservations,
    budgetHolds: snapshot.budgetHolds,
    ledgerEntries: snapshot.ledgerEntries,
    financialStateSha256: financialHash(snapshot),
  };
}

function codeForFailedCheck(name) {
  return "profile_" + name.replace(/[A-Z]/g, (letter) => "_" + letter.toLowerCase()) + "_unverified";
}

/**
 * Exercise the approved local Codex profile and modern SDK replay against one
 * already completed run. Owner revocation is performed only by the real Agents
 * page button; database reads use the configured read-only observer role.
 */
export async function runCodexOwnerProfileCases({
  ownerPage,
  observerPool,
  publicOrigin,
  agentBearer,
  agentId,
  runId,
  intentId,
  acceptOperationId,
  repoRoot,
  nativeClient,
}) {
  const checks = {
    primaryCodexAcceptanceBound: false,
    wrongOriginRejected403: false,
    wrongProtocolRejected400: false,
    wrongClientInitializeRejected400: false,
    modernSdkPinned: false,
    modernSdkConnectedAndListedTools: false,
    modernSdkWrongAgentPreflightDenied: false,
    modernSdkMatchingPreflight: false,
    modernSdkAcceptSameRun: false,
    originalHttpOperationReplaySameRun: false,
    retryFinancialStateUnchanged: false,
    ownerUiRevocationCommitted: false,
    databaseAccessAndGrantsRevoked: false,
    httpBearerRejected401: false,
    mcpBearerRejected401: false,
    nativeCodexBearerRejected: false,
    completedRunAndDebitPreserved: false,
  };
  const blockingCodes = new Set();
  const http = {
    wrongOriginStatus: null,
    wrongProtocolStatus: null,
    wrongProtocolCode: null,
    wrongClientStatus: null,
    wrongClientCode: null,
    acceptReplayStatus: null,
    acceptReplayRunId: null,
    revokedPreflightStatus: null,
    mcpAfterRevokeStatus: null,
  };
  const sdk = {
    package: "@modelcontextprotocol/client",
    version: MCP_SDK_VERSION,
    protocolVersion: MCP_PROTOCOL,
    connected: false,
    listedToolNames: [],
    wrongAgentPreflightStatus: null,
    preflightStatus: null,
    acceptRunId: null,
    acceptReplayed: null,
  };
  const ownerRevoke = {
    status: null,
    accessStatus: null,
    cancellationStatus: null,
    eventId: null,
  };
  const database = {
    beforeRetries: null,
    afterSdk: null,
    afterHttp: null,
    afterRevocation: null,
  };
  let nativeRevocation = null;

  try {
    if (!ownerPage || !observerPool || !repoRoot) {
      throw Object.assign(new Error("profile_acceptance_dependencies_missing"), { code: "PROFILE_DEPENDENCIES_MISSING" });
    }
    const origin = localOrigin(publicOrigin);
    if (typeof agentBearer !== "string" || agentBearer.length < 16 || agentBearer.length > 8192
        || /\s/.test(agentBearer) || /\bBearer\s/i.test(agentBearer)) {
      throw Object.assign(new Error("profile_agent_credential_invalid"), { code: "PROFILE_AGENT_CREDENTIAL_INVALID" });
    }
    const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (![agentId, runId, intentId].every((value) => typeof value === "string" && UUID.test(value))
        || typeof acceptOperationId !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(acceptOperationId)) {
      throw Object.assign(new Error("profile_primary_identity_invalid"), { code: "PROFILE_PRIMARY_IDENTITY_INVALID" });
    }
    const pacer = createRequestPacer(MIN_AGENT_REQUEST_INTERVAL_MS);
    const mcpUrl = new URL("/api/agent/mcp", origin);
    const acceptOperation = operationId();
    const wrongAgentOperation = operationId();
    const preflightOperation = operationId();
    const nativeReceipt = nativeClient?.mcp?.toolResult;
    const nativeRunId = runIdFrom(nativeReceipt);
    checks.primaryCodexAcceptanceBound = nativeClient?.outcome === "accepted_result_observed"
      && nativeClient?.client?.version === CODEX_CLI_VERSION
      && nativeClient?.client?.isolatedCodexHome === true
      && nativeClient?.model?.externalModelCalls === 0
      && nativeClient?.model?.llmBenchmarkInvocation === false
      && nativeClient?.mcp?.ownerMcpServerUsed === true
      && nativeClient?.mcp?.preflight?.callAttemptCount === 1
      && nativeClient?.mcp?.preflight?.status === "allowed"
      && nativeClient?.mcp?.callOrder?.[0] === "identity.preflight"
      && nativeClient?.mcp?.callOrder?.indexOf("identity.preflight") < nativeClient?.mcp?.callOrder?.indexOf("runs.accept_launch_intent")
      && nativeClient?.mcp?.acceptanceCallAttemptCount === 1
      && Array.isArray(nativeClient?.mcp?.allowlistedTools)
      && nativeClient.mcp.allowlistedTools.includes("runs.accept_launch_intent")
      && nativeReceipt?.operationId === acceptOperationId
      && nativeReceipt?.isError === false
      && nativeRunId === runId
      && nativeClient?.handoff?.nativeClient === "codex-cli"
      && nativeClient?.handoff?.manualCopyFallbackUsed === false;

    const wrongOrigin = await rawMcpInitialize({
      url: mcpUrl.href,
      origin: "http://wrong-origin.invalid",
      bearer: agentBearer,
      pacer,
    });
    http.wrongOriginStatus = wrongOrigin.status;
    checks.wrongOriginRejected403 = wrongOrigin.status === 403;

    const wrongProtocol = await rawMcpInitialize({
      url: mcpUrl.href,
      origin,
      bearer: agentBearer,
      protocol: "2025-03-26",
      pacer,
    });
    http.wrongProtocolStatus = wrongProtocol.status;
    http.wrongProtocolCode = wrongProtocol.errorCode;
    checks.wrongProtocolRejected400 = wrongProtocol.status === 400
      && wrongProtocol.errorCode === "UNSUPPORTED_MCP_PROTOCOL";

    const wrongClient = await rawMcpInitialize({
      url: mcpUrl.href,
      origin,
      bearer: agentBearer,
      protocol: "2025-06-18",
      clientInfo: { name: "unapproved-client", version: "0.165.0" },
      pacer,
    });
    http.wrongClientStatus = wrongClient.status;
    http.wrongClientCode = wrongClient.errorCode;
    checks.wrongClientInitializeRejected400 = wrongClient.status === 400
      && wrongClient.errorCode === "UNSUPPORTED_MCP_CLIENT_PROFILE";

    const before = await readonlySnapshot(observerPool, { runId, intentId, agentId });
    database.beforeRetries = outputSnapshot(before);
    const identityOk = databaseBound(before, { runId, intentId, agentId });
    if (!identityOk || before.run.status !== "completed"
        || !before.grants.some((grant) => grant.revoked_at === null
          && grant.access_generation === before.profile.access_generation
          && grant.role === "agent" && grant.source === "manual")
        || !before.ledgerEntries.some((entry) => entry.entry_type === "debit")) {
      blockingCodes.add("profile_primary_completed_run_or_debit_not_observed");
    }

    const installedSdk = await installedMcpSdkVersion();
    sdk.version = installedSdk;
    checks.modernSdkPinned = installedSdk === MCP_SDK_VERSION && MCP_PROTOCOL === "2026-07-28";
    const client = new Client(
      { name: "Web3 Agent Bench modern profile acceptance", version: "1.0.0" },
      { versionNegotiation: { mode: { pin: MCP_PROTOCOL } } },
    );
    const transport = new StreamableHTTPClientTransport(mcpUrl, {
      requestInit: { headers: requestHeaders(origin, agentBearer) },
      onInsufficientScope: "throw",
    });
    try {
      await pacer();
      await client.connect(transport);
      sdk.connected = true;
      await pacer();
      const listed = await client.listTools();
      sdk.listedToolNames = (Array.isArray(listed?.tools) ? listed.tools : [])
        .map((tool) => tool?.name)
        .filter((name) => typeof name === "string")
        .filter((name) => ["identity.preflight", "runs.accept_launch_intent"].includes(name))
        .sort();
      checks.modernSdkConnectedAndListedTools = sdk.connected
        && sdk.listedToolNames.includes("identity.preflight")
        && sdk.listedToolNames.includes("runs.accept_launch_intent");

      if (checks.modernSdkConnectedAndListedTools) {
        await pacer();
        const wrongAgentResult = await client.callTool({
          name: "identity.preflight",
          arguments: { agentId: randomUUID(), operationId: wrongAgentOperation },
        });
        const wrongAgentBody = toolPayload(wrongAgentResult);
        sdk.wrongAgentPreflightStatus = typeof wrongAgentBody.status === "string" ? wrongAgentBody.status : null;
        checks.modernSdkWrongAgentPreflightDenied = wrongAgentResult?.isError !== true
          && wrongAgentBody.status === "denied"
          && wrongAgentBody.operationId === wrongAgentOperation;

        await pacer();
        const preflightResult = await client.callTool({
          name: "identity.preflight",
          arguments: { agentId, operationId: preflightOperation },
        });
        const preflightBody = toolPayload(preflightResult);
        sdk.preflightStatus = typeof preflightBody.status === "string" ? preflightBody.status : null;
        checks.modernSdkMatchingPreflight = preflightResult?.isError !== true
          && preflightBody.status === "allowed"
          && preflightBody.operationId === preflightOperation;

        if (checks.modernSdkMatchingPreflight) {
          await pacer();
          const acceptResult = await client.callTool({
            name: "runs.accept_launch_intent",
            arguments: { intentId, operationId: acceptOperation },
          });
          const acceptBody = toolPayload(acceptResult);
          sdk.acceptRunId = runIdFrom(acceptBody);
          sdk.acceptReplayed = typeof acceptBody.replayed === "boolean" ? acceptBody.replayed : null;
          checks.modernSdkAcceptSameRun = acceptResult?.isError !== true && sdk.acceptRunId === runId;
        }
      }
    } catch (error) {
      blockingCodes.add(safeError(error));
    } finally {
      await client.close().catch(() => undefined);
    }

    database.afterSdk = outputSnapshot(await readonlySnapshot(observerPool, { runId, intentId, agentId }));
    const beforeHash = financialHash(before);
    checks.retryFinancialStateUnchanged = Boolean(beforeHash
      && financialHash(database.afterSdk) === beforeHash
      && database.afterSdk.run?.status === "completed"
      && database.afterSdk.ledgerEntries.some((entry) => entry.entry_type === "debit"));

    const httpReplay = await rawHttpAccept({
      origin,
      bearer: agentBearer,
      intentId,
      acceptOperationId,
      pacer,
    });
    http.acceptReplayStatus = httpReplay.status;
    http.acceptReplayRunId = httpReplay.runId;
    checks.originalHttpOperationReplaySameRun = [200, 201].includes(httpReplay.status)
      && httpReplay.runId === runId;

    database.afterHttp = outputSnapshot(await readonlySnapshot(observerPool, { runId, intentId, agentId }));
    checks.retryFinancialStateUnchanged = checks.retryFinancialStateUnchanged
      && financialHash(database.afterHttp) === beforeHash
      && database.afterHttp.run?.status === "completed"
      && database.afterHttp.ledgerEntries.some((entry) => entry.entry_type === "debit");

    const activeBeforeRevoke = database.afterHttp?.grants?.some((grant) => grant.revoked_at === null) === true;
    if (!activeBeforeRevoke) {
      blockingCodes.add("profile_active_grant_not_observed_before_owner_revoke");
    } else {
      await ownerPage.goto(new URL("/agents", origin).href, { waitUntil: "domcontentloaded" });
      await ownerPage.getByTestId("agent-card-" + agentId).waitFor({ state: "visible", timeout: 15_000 });
      const revokeButton = ownerPage.getByTestId("agent-revoke-" + agentId);
      await revokeButton.waitFor({ state: "visible", timeout: 15_000 });
      if (!(await revokeButton.isEnabled())) {
        blockingCodes.add("profile_owner_revoke_button_disabled");
      } else {
        const revokePath = "/api/owner/agents/" + encodeURIComponent(agentId) + "/access-revoke";
        const responsePromise = ownerPage.waitForResponse((response) =>
          new URL(response.url()).pathname === revokePath && response.request().method() === "POST",
        { timeout: 20_000 });
        await revokeButton.click();
        const response = await responsePromise;
        let body = {};
        try {
          const value = await response.json();
          if (isRecord(value)) body = value;
        } catch { /* Retain only the HTTP status and subsequent database state. */ }
        ownerRevoke.status = response.status();
        ownerRevoke.accessStatus = typeof body.access?.status === "string" ? body.access.status : null;
        ownerRevoke.cancellationStatus = typeof body.cancellation?.status === "string" ? body.cancellation.status : null;
        ownerRevoke.eventId = typeof body.cancellation?.eventId === "string"
          && /^[0-9a-f-]{36}$/i.test(body.cancellation.eventId) ? body.cancellation.eventId : null;
        checks.ownerUiRevocationCommitted = ownerRevoke.status === 200
          && ownerRevoke.accessStatus === "revoked"
          && ownerRevoke.cancellationStatus === "pending"
          && ownerRevoke.eventId !== null;
      }
    }

    const afterRevokeRaw = await readonlySnapshot(observerPool, { runId, intentId, agentId });
    database.afterRevocation = outputSnapshot(afterRevokeRaw);
    const profileBefore = before.profile;
    const profileAfter = afterRevokeRaw.profile;
    const previousActiveGrants = before.grants.filter((grant) => grant.revoked_at === null);
    const allGrantsRevoked = afterRevokeRaw.grants.length > 0
      && afterRevokeRaw.grants.every((grant) => grant.revoked_at !== null)
      && previousActiveGrants.every((grant) => afterRevokeRaw.grants.some((after) =>
        after.id === grant.id && after.revoked_at !== null && after.revocation_reason === "owner_global_revoke"));
    checks.databaseAccessAndGrantsRevoked = Boolean(profileBefore && profileAfter
      && profileAfter.access_revoked_at !== null
      && Number(profileAfter.access_revision) === Number(profileBefore.access_revision) + 1
      && Number(profileAfter.access_generation) === Number(profileBefore.access_generation) + 1
      && allGrantsRevoked);
    checks.completedRunAndDebitPreserved = databaseBound(afterRevokeRaw, { runId, intentId, agentId })
      && afterRevokeRaw.run.status === "completed"
      && afterRevokeRaw.ledgerEntries.some((entry) => entry.entry_type === "debit")
      && financialHash(afterRevokeRaw) === beforeHash;

    const manualGrant = before.grants.find((grant) => grant.revoked_at === null
      && grant.role === "agent" && grant.source === "manual");
    if (manualGrant) {
      const revokedHttp = await rawPreflight({
        origin,
        bearer: agentBearer,
        agentId,
        resource: manualGrant.resource,
        pacer,
      });
      http.revokedPreflightStatus = revokedHttp.status;
      checks.httpBearerRejected401 = revokedHttp.status === 401;
    }

    const revokedMcp = await rawMcpInitialize({
      url: mcpUrl.href,
      origin,
      bearer: agentBearer,
      protocol: MCP_PROTOCOL,
      clientInfo: { name: "modern-profile-revocation-probe", version: MCP_SDK_VERSION },
      modern: true,
      pacer,
    });
    http.mcpAfterRevokeStatus = revokedMcp.status;
    checks.mcpBearerRejected401 = revokedMcp.status === 401;

    try {
      const probe = await runCodexNativeOwnerRevocationProbe({
        publicOrigin: origin,
        agentBearer,
        agentId,
        ownerPage,
        repoRoot,
      });
      const forwardedRequests = Array.isArray(probe.mcp?.forwarder?.requests)
        ? probe.mcp.forwarder.requests.slice(0, 32).map((request) => ({
          methodName: ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"]
            .includes(request?.methodName) ? request.methodName : null,
          responseStatus: Number.isInteger(request?.responseStatus)
            && request.responseStatus >= 100 && request.responseStatus <= 599 ? request.responseStatus : null,
          wwwAuthenticatePresent: request?.wwwAuthenticatePresent === true,
        }))
        : [];
      const upstreamUnauthorizedObserved = Number.isInteger(probe.mcp?.forwarder?.ownerUnauthorizedResponseCount)
        && probe.mcp.forwarder.ownerUnauthorizedResponseCount > 0
        && Number.isInteger(probe.mcp?.forwarder?.requestCount)
        && probe.mcp.forwarder.requestCount > 0
        && probe.mcp.forwarder.ownerAuthChallengeObserved === true
        && forwardedRequests.some((request) => request.responseStatus === 401 && request.wwwAuthenticatePresent);
      nativeRevocation = {
        outcome: probe.outcome,
        cliVersion: probe.client?.version ?? null,
        preflightAttemptCount: probe.mcp?.preflight?.callAttemptCount ?? 0,
        preflightStatus: probe.mcp?.preflight?.status ?? null,
        acceptanceToolConfigured: probe.mcp?.acceptanceToolConfigured === true,
        ownerActionAttemptCount: probe.mcp?.ownerActionAttemptCount ?? null,
        forwarder: {
          requestCount: Number.isInteger(probe.mcp?.forwarder?.requestCount)
            ? probe.mcp.forwarder.requestCount : null,
          ownerUnauthorizedResponseCount: Number.isInteger(probe.mcp?.forwarder?.ownerUnauthorizedResponseCount)
            ? probe.mcp.forwarder.ownerUnauthorizedResponseCount : null,
          ownerAuthChallengeObserved: probe.mcp?.forwarder?.ownerAuthChallengeObserved === true,
          requests: forwardedRequests,
          upstreamUnauthorizedObserved,
        },
        externalModelCalls: probe.model?.externalModelCalls ?? null,
        llmBenchmarkInvocation: probe.model?.llmBenchmarkInvocation ?? null,
        errorCodeClasses: Array.isArray(probe.turn?.errorCodeClasses) ? probe.turn.errorCodeClasses : [],
        safeDiagnostic: probe.turn?.safeDiagnostic ? {
          exitCode: Number.isInteger(probe.turn.safeDiagnostic.exitCode) ? probe.turn.safeDiagnostic.exitCode : null,
          stdoutBytes: Number.isInteger(probe.turn.safeDiagnostic.stdoutBytes) ? probe.turn.safeDiagnostic.stdoutBytes : null,
          stdoutSha256: /^[0-9a-f]{64}$/.test(probe.turn.safeDiagnostic.stdoutSha256 ?? "") ? probe.turn.safeDiagnostic.stdoutSha256 : null,
          stderrBytes: Number.isInteger(probe.turn.safeDiagnostic.stderrBytes) ? probe.turn.safeDiagnostic.stderrBytes : null,
          stderrSha256: /^[0-9a-f]{64}$/.test(probe.turn.safeDiagnostic.stderrSha256 ?? "") ? probe.turn.safeDiagnostic.stderrSha256 : null,
        } : null,
      };
      checks.nativeCodexBearerRejected = probe.client?.version === CODEX_CLI_VERSION
        && probe.model?.externalModelCalls === 0
        && probe.model?.llmBenchmarkInvocation === false
        && probe.mcp?.ownerMcpServerUsed === true
        && probe.mcp?.toolCallCount === 0
        && probe.mcp?.acceptanceToolConfigured === false
        && probe.mcp?.ownerActionAttemptCount === 0
        && probe.mcp?.preflight?.callAttemptCount === 0
        && probe.outcome === "credential_rejected_before_preflight"
        && upstreamUnauthorizedObserved;
    } catch (error) {
      blockingCodes.add(safeError(error));
    }
  } catch (error) {
    blockingCodes.add(safeError(error));
  }

  for (const [name, passed] of Object.entries(checks)) {
    if (!passed) blockingCodes.add(codeForFailedCheck(name));
  }
  const status = Object.values(checks).every(Boolean) ? "verified" : "blocked";
  const result = {
    schemaVersion: "brl-codex-owner-profile-cases/v1",
    status,
    checks,
    blockingCodes: [...blockingCodes].sort(),
    http,
    sdk,
    ownerRevoke,
    nativeRevocation,
    database,
  };
  assertSecretFree(result, "Codex owner profile acceptance");
  return result;
}
