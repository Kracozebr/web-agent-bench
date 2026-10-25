import { randomUUID } from "node:crypto";
import pg from "pg";
import { request as playwrightRequest } from "playwright";
import { assertSecretFree } from "./evidence.mjs";
import { attachSafeBrowserCapture, waitForPath } from "./browser-support.mjs";
import { createCard, issueThroughUi } from "./credential-cases.mjs";

const { Pool } = pg;
const GRANT_PATH = "/api/admin/bonus-grants";
const SC001_REASON = "Synthetic acceptance grant for TBB-SC-001";
const SC002_REASON = "Synthetic acceptance grant for TBB-SC-002";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function operationId() {
  return randomUUID().replaceAll("-", "");
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeGrant(grant) {
  if (!isObject(grant)) return null;
  return {
    id: typeof grant.id === "string" ? grant.id : null,
    ownerId: typeof grant.ownerId === "string" ? grant.ownerId : null,
    amount: typeof grant.amount === "string" ? grant.amount : null,
    reason: typeof grant.reason === "string" ? grant.reason : null,
    createdAt: typeof grant.createdAt === "string" ? grant.createdAt : null,
    expiresAt: typeof grant.expiresAt === "string" ? grant.expiresAt : grant.expiresAt === null ? null : undefined,
  };
}

async function safeOutcome(response) {
  let body = {};
  try { body = await response.json(); } catch { /* Keep only the safe status when no JSON is returned. */ }
  return {
    status: response.status(),
    errorCode: typeof body?.error?.code === "string" ? body.error.code : null,
    operationId: typeof body?.operationId === "string" ? body.operationId : null,
    replayed: body?.replayed === true,
    grant: safeGrant(body?.grant),
  };
}

async function readOwner(page) {
  const response = await page.request.get("/api/owner");
  const body = await response.json().catch(() => ({}));
  assert(response.status() === 200 && isObject(body?.owner) && typeof body.owner.id === "string",
    "Authenticated acceptance owner identity is unavailable");
  return { id: body.owner.id, isAdmin: body.owner.isAdmin === true };
}

async function readBilling(page) {
  const response = await page.request.get("/api/owner/billing");
  const body = await response.json().catch(() => ({}));
  assert(response.status() === 200 && isObject(body?.cash) && isObject(body?.bonus)
    && Array.isArray(body?.grants) && Array.isArray(body?.history),
  "Private owner billing view is unavailable or malformed");
  return body;
}

async function observerSnapshot(pool, { ownerIds, operationIds = [], grantIds = [] }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = await client.query(
      "SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only",
    );
    const observer = identity.rows[0];
    assert(observer?.role === "oid_observer" && observer.transaction_read_only === "on",
      "TBB outcome inspection did not use independent read-only oid_observer PostgreSQL access");
    const grants = await client.query(
      `SELECT id::text, owner_id::text, amount_units::text, issued_by_owner_id::text,
              reason, operation_id, created_at, expires_at
       FROM oid_bonus_grant
       WHERE owner_id=ANY($1::uuid[]) AND (operation_id=ANY($2::text[]) OR id=ANY($3::uuid[]))
       ORDER BY created_at,id`, [ownerIds, operationIds, grantIds],
    );
    const entries = await client.query(
      `SELECT id::text, owner_id::text, actor_owner_id::text, bonus_grant_id::text,
              operation_id, entry_type, source_kind, amount_units::text,
              available_delta_units::text, reserved_delta_units::text, expired_delta_units::text, created_at
       FROM oid_ledger_entry
       WHERE owner_id=ANY($1::uuid[]) AND (operation_id=ANY($2::text[]) OR bonus_grant_id=ANY($3::uuid[]))
       ORDER BY created_at,id`, [ownerIds, operationIds, grantIds],
    );
    const operations = await client.query(
      `SELECT id::text, actor_owner_id::text, subject_owner_id::text, operation_id, action,
              payload_hash, response_json->'grant'->>'id' AS response_grant_id, created_at
       FROM oid_ledger_operation WHERE operation_id=ANY($1::text[])
       ORDER BY created_at,id`, [operationIds],
    );
    const audits = await client.query(
      `SELECT id::text, event_type, operation_id, actor_owner_id::text, subject_owner_id::text,
              metadata, created_at
       FROM oid_ledger_audit WHERE operation_id=ANY($1::text[])
       ORDER BY created_at,id`, [operationIds],
    );
    await client.query("COMMIT");
    return {
      observer,
      grants: grants.rows,
      entries: entries.rows,
      operations: operations.rows,
      audits: audits.rows,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function createForeignOwner({ adminPage, newContext, login, publicOrigin }) {
  const context = await newContext();
  const foreign = await login(context, `oid-tbb-foreign-${randomUUID()}`);
  const inviteResponsePromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/admin/invitations" && response.request().method() === "POST",
  { timeout: 15000 });
  await adminPage.getByTestId("invite-create").click();
  const inviteResponse = await inviteResponsePromise;
  assert(inviteResponse.status() === 201, "Acceptance admin could not issue a foreign-owner invitation");
  let inviteSecret = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
  await foreign.page.getByTestId("invitation-code").fill(inviteSecret);
  const activationPromise = foreign.page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/admission/activate", { timeout: 15000 });
  await foreign.page.getByTestId("activate-owner").click();
  const activation = await activationPromise;
  await waitForPath(foreign.page, ["/account"], 15000);
  inviteSecret = "";
  assert(activation.ok(), "Synthetic foreign owner did not activate through the real owner verifier");
  const owner = await readOwner(foreign.page);
  assert(owner.id !== "", "Synthetic foreign owner has an empty identity");
  return { context, page: foreign.page, ownerId: owner.id, publicOrigin };
}

async function grantThroughUi(page, { ownerId, amount, reason, expiryLocal = "", capture }) {
  const path = GRANT_PATH;
  const form = page.getByTestId("bonus-grant-form");
  await form.waitFor({ state: "visible" });
  await form.getByTestId("bonus-grant-owner-id").fill(ownerId);
  await form.getByTestId("bonus-grant-amount").fill(amount);
  await form.getByTestId("bonus-grant-reason").fill(reason);
  await form.getByTestId("bonus-grant-expiry").fill(expiryLocal);
  const responsePromise = page.waitForResponse((response) =>
    new URL(response.url()).pathname === path && response.request().method() === "POST", { timeout: 15000 });
  capture?.action("click", "bonus-grant-submit");
  await form.getByTestId("bonus-grant-submit").click();
  const response = await responsePromise;
  const result = await safeOutcome(response);
  result.request = response.request().postDataJSON();
  result.browserResultVisible = await page.getByTestId("bonus-grant-result").isVisible().catch(() => false);
  return result;
}

async function formatLocalExpiry(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function asAudit(audits, operationIdValue, eventType) {
  return audits.find((row) => row.operation_id === operationIdValue && row.event_type === eventType) ?? null;
}

function grantRow(snapshot, id) {
  return snapshot.grants.find((row) => row.id === id) ?? null;
}

function amountUnits(amount) {
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,6}))?$/.exec(amount);
  if (!match) return null;
  return BigInt(match[1]) * 1000000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
}

function grantMatches(row, expected) {
  return Boolean(row && row.owner_id === expected.ownerId
    && BigInt(row.amount_units) === amountUnits(expected.amount)
    && (!expected.issuedByOwnerId || row.issued_by_owner_id === expected.issuedByOwnerId)
    && row.reason === expected.reason
    && row.operation_id === expected.operationId
    && (row.expires_at === null) === (expected.expiresAt === null)
    && (expected.expiresAt === null || new Date(row.expires_at).toISOString() === new Date(expected.expiresAt).toISOString()));
}

async function postOutcome(context, path, data, headers = {}) {
  const response = await context.post(path, { headers: { origin: headers.origin, ...headers }, data });
  return { ...(await safeOutcome(response)), requestOperationId: data.operationId };
}

function noFinancialEffect(before, after, operationIds) {
  const ids = new Set(operationIds);
  const touchedGrants = after.grants.filter((row) => ids.has(row.operation_id));
  const touchedEntries = after.entries.filter((row) => ids.has(row.operation_id));
  return touchedGrants.length === 0 && touchedEntries.length === 0;
}

export async function runBillingCases({
  adminPage,
  ownerPage,
  ownerId,
  newContext,
  login,
  restartApi,
  observerDatabaseUrl,
  databaseUrl,
  publicOrigin,
}) {
  if (!adminPage || !ownerPage || typeof ownerId !== "string" || !ownerId
    || typeof newContext !== "function" || typeof login !== "function" || typeof restartApi !== "function"
    || !observerDatabaseUrl || !databaseUrl || !publicOrigin) {
    throw new Error("TBB acceptance needs authenticated admin/owner pages, verifier, database URLs and API restart support");
  }

  const adminIdentity = await readOwner(adminPage);
  const ownerIdentity = await readOwner(ownerPage);
  assert(adminIdentity.isAdmin && ownerIdentity.id === ownerId,
    "TBB acceptance admin/owner session identities do not match the declared roles");
  const observerPool = new Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "tbb-acceptance-readonly-observer" });
  const adminCapture = attachSafeBrowserCapture(adminPage, "TBB-SC-001");
  const ownerCapture = attachSafeBrowserCapture(ownerPage, "TBB-SC-001");
  const operationIds = [];
  const grantIds = [];
  const foreignContexts = [];
  let agentContext;
  let agentSecret = "";
  let initialCommit = null;
  let pageSawInitialResponse = false;
  let foreign;
  let adminNoExpiry;
  let explicitExpiry;
  let laterGrant;
  let expiryInput;
  let sc001Raw;
  let sc002Raw;
  try {
    await adminPage.goto("/admin", { waitUntil: "domcontentloaded" });
    await adminPage.getByTestId("bonus-grant-form").waitFor({ state: "visible" });
    const before = await observerSnapshot(observerPool, { ownerIds: [ownerId, adminIdentity.id], operationIds, grantIds });

    // Create a valid manual agent credential through the real owner UI; the raw token is memory-only.
    await ownerPage.goto("/agents", { waitUntil: "domcontentloaded" });
    const agentCard = await createCard(ownerPage, `TBB acceptance agent ${randomUUID().slice(0, 8)}`, ownerCapture);
    const issuedAgent = await issueThroughUi(ownerPage, agentCard.id, "issue", ownerCapture);
    agentSecret = issuedAgent.secret;
    assert(typeof agentSecret === "string" && agentSecret.length > 0,
      "Owner UI did not issue a real synthetic agent credential for the authorization negative");
    agentContext = await playwrightRequest.newContext({
      baseURL: publicOrigin,
      extraHTTPHeaders: { origin: publicOrigin },
      timeout: 15000,
    });

    // Exercise both a foreign owner session and the actual agent credential without admin cookies.
    foreign = await createForeignOwner({ adminPage, newContext, login, publicOrigin });
    foreignContexts.push(foreign.context);
    const basePayload = { ownerId, amount: "0.250000", reason: "Synthetic unauthorized TBB attempt" };
    const ownerAttemptId = operationId();
    const foreignAttemptId = operationId();
    const agentAttemptId = operationId();
    const ownerDenied = await postOutcome(ownerPage.request, GRANT_PATH, { ...basePayload, operationId: ownerAttemptId }, { origin: publicOrigin });
    const foreignDenied = await postOutcome(foreign.page.request, GRANT_PATH, { ...basePayload, operationId: foreignAttemptId }, { origin: publicOrigin });
    const agentDenied = await postOutcome(agentContext, GRANT_PATH, { ...basePayload, operationId: agentAttemptId }, {
      origin: publicOrigin,
      authorization: `Bearer ${agentSecret}`,
    });
    agentDenied.requestMode = "synthetic-agent-bearer-without-owner-cookies";
    operationIds.push(ownerAttemptId, foreignAttemptId, agentAttemptId);

    // UI submits the first grant; proxy the successful Fastify commit but drop the browser response.
    const initialPayload = {
      operationId: null,
      ownerId,
      amount: "1.250000",
      reason: SC001_REASON,
    };
    let initialRouteUsed = false;
    let resolveInitialRoute;
    const initialRouteDone = new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(false), 15000);
      resolveInitialRoute = (value) => {
        clearTimeout(timeout);
        resolve(value);
      };
    });
    const initialRequestFailed = adminPage.waitForEvent("requestfailed", (request) =>
      new URL(request.url()).pathname === GRANT_PATH && request.method() === "POST", { timeout: 15000 });
    await adminPage.route(`**${GRANT_PATH}`, async (route) => {
      if (initialRouteUsed || route.request().method() !== "POST") return route.continue();
      initialRouteUsed = true;
      try {
        initialPayload.operationId = route.request().postDataJSON()?.operationId ?? null;
        const committed = await route.fetch({ timeout: 15000 });
        const outcome = await safeOutcome(committed);
        initialCommit = { ...outcome, request: route.request().postDataJSON() };
        await route.abort("failed");
        resolveInitialRoute(true);
      } catch (error) {
        resolveInitialRoute(false);
        throw error;
      }
    });
    const initialForm = adminPage.getByTestId("bonus-grant-form");
    await initialForm.getByTestId("bonus-grant-owner-id").fill(initialPayload.ownerId);
    await initialForm.getByTestId("bonus-grant-amount").fill(initialPayload.amount);
    await initialForm.getByTestId("bonus-grant-reason").fill(initialPayload.reason);
    await initialForm.getByTestId("bonus-grant-expiry").fill("");
    const beforeLostResponse = adminCapture.capture.responses.length;
    adminCapture.action("click", "bonus-grant-submit-response-loss");
    await initialForm.getByTestId("bonus-grant-submit").click();
    const [initialFailureObserved, initialRouteObserved] = await Promise.all([
      initialRequestFailed.then(() => true, () => false),
      initialRouteDone,
    ]);
    await adminPage.unroute(`**${GRANT_PATH}`);
    assert(initialFailureObserved && initialRouteObserved,
      "TBB response-loss setup did not await both the committed API response and the browser network failure");
    pageSawInitialResponse = adminCapture.capture.responses.slice(beforeLostResponse)
      .some((row) => row.path === GRANT_PATH && row.method === "POST");
    assert(initialPayload.operationId && initialCommit?.status === 200 && initialCommit.grant?.id,
      "TBB grant response-loss setup did not commit exactly one valid admin grant");
    operationIds.push(initialPayload.operationId);
    grantIds.push(initialCommit.grant.id);

    await restartApi();
    const replayPromise = adminPage.waitForResponse((response) =>
      new URL(response.url()).pathname === GRANT_PATH && response.request().method() === "POST", { timeout: 15000 });
    adminCapture.action("click", "bonus-grant-submit-replay-after-restart");
    await initialForm.getByTestId("bonus-grant-submit").click();
    const replayResponse = await replayPromise;
    const replay = await safeOutcome(replayResponse);
    const replayRequest = replayResponse.request().postDataJSON();
    replay.request = replayRequest;
    replay.browserResultVisible = await adminPage.getByTestId("bonus-grant-result").isVisible().catch(() => false);
    assert(replay.status === 200 && replay.replayed && replay.grant?.id === initialCommit.grant.id
      && replayRequest?.operationId === initialPayload.operationId,
    "TBB browser did not replay the same committed grant operation after API restart");
    adminNoExpiry = { ...initialCommit.grant, operationId: initialPayload.operationId, expiresAt: null };
    const afterFirstGrant = await observerSnapshot(observerPool, { ownerIds: [ownerId, adminIdentity.id], operationIds, grantIds });

    // Conflicting retries and invalid requests are explicit API negatives; preserve only safe response fields.
    const changedAmountId = initialPayload.operationId;
    const changedAmount = await postOutcome(adminPage.request, GRANT_PATH, {
      ...initialPayload, operationId: changedAmountId, amount: "1.250001",
    }, { origin: publicOrigin });
    const zeroId = operationId();
    const zeroAmount = await postOutcome(adminPage.request, GRANT_PATH, {
      operationId: zeroId, ownerId, amount: "0.000000", reason: "Synthetic invalid zero amount",
    }, { origin: publicOrigin });
    const precisionId = operationId();
    const excessPrecision = await postOutcome(adminPage.request, GRANT_PATH, {
      operationId: precisionId, ownerId, amount: "1.0000001", reason: "Synthetic invalid precision",
    }, { origin: publicOrigin });
    const pastExpiryId = operationId();
    const pastExpiry = await postOutcome(adminPage.request, GRANT_PATH, {
      operationId: pastExpiryId, ownerId, amount: "0.500000", reason: "Synthetic expired grant attempt",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    }, { origin: publicOrigin });
    operationIds.push(zeroId, precisionId, pastExpiryId);
    const beforeTbbSc002 = await readBilling(ownerPage);

    // Create an explicit-expiry lot and a later no-expiry lot through the actual admin form.
    await adminPage.goto("/admin", { waitUntil: "domcontentloaded" });
    const targetExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000);
    expiryInput = await formatLocalExpiry(targetExpiry);
    const expectedExplicitExpiry = new Date(expiryInput).toISOString();
    const explicitResult = await grantThroughUi(adminPage, {
      ownerId, amount: "0.750000", reason: SC002_REASON, expiryLocal: expiryInput, capture: adminCapture,
    });
    assert(explicitResult.status === 200 && explicitResult.grant?.id && explicitResult.request?.operationId,
      "Admin UI did not issue the explicit-expiry TBB grant");
    operationIds.push(explicitResult.request.operationId);
    grantIds.push(explicitResult.grant.id);
    explicitExpiry = { ...explicitResult.grant, operationId: explicitResult.request.operationId, expiresAt: expectedExplicitExpiry };
    const beforeLaterGrant = await readBilling(ownerPage);
    const databaseBeforeLaterGrant = await observerSnapshot(observerPool, {
      ownerIds: [ownerId, adminIdentity.id, foreign.ownerId], operationIds, grantIds,
    });

    const laterResult = await grantThroughUi(adminPage, {
      ownerId, amount: "0.125000", reason: "Synthetic later TBB grant with independent terms", capture: adminCapture,
    });
    assert(laterResult.status === 200 && laterResult.grant?.id && laterResult.request?.operationId,
      "Admin UI did not issue the later independent TBB grant");
    operationIds.push(laterResult.request.operationId);
    grantIds.push(laterResult.grant.id);
    laterGrant = { ...laterResult.grant, operationId: laterResult.request.operationId, expiresAt: null };

    const boundaryExpiryId = operationId();
    const boundaryTimestamp = new Date().toISOString();
    const expiryBoundary = await postOutcome(adminPage.request, GRANT_PATH, {
      operationId: boundaryExpiryId, ownerId, amount: "0.100000", reason: "Synthetic expiry boundary rejection",
      expiresAt: boundaryTimestamp,
    }, { origin: publicOrigin });
    operationIds.push(boundaryExpiryId);

    const editOperations = [];
    for (const [field, value] of [
      ["expiresAt", null],
      ["ownerId", foreign.ownerId],
      ["amount", "9.000000"],
    ]) {
      const editOperationId = operationId();
      editOperations.push(editOperationId);
      const response = await adminPage.request.put(`${GRANT_PATH}/${explicitResult.grant.id}`, {
        headers: { origin: publicOrigin },
        data: { operationId: editOperationId, [field]: value },
      });
      const outcome = await safeOutcome(response);
      outcome.field = field;
      outcome.requestOperationId = editOperationId;
      // Keep the attempted value out of the evidence; the field and result are sufficient.
      editOperations[editOperations.length - 1] = { operationId: editOperationId, outcome };
    }
    operationIds.push(...editOperations.map((item) => item.operationId));

    const after = await observerSnapshot(observerPool, {
      ownerIds: [ownerId, adminIdentity.id, foreign.ownerId], operationIds, grantIds,
    });
    const ownerBilling = await readBilling(ownerPage);
    const repeatedOwnerBilling = await readBilling(ownerPage);
    const browserGrants = new Map(ownerBilling.grants.map((row) => [row.id, row]));
    const dbNoExpiry = grantRow(after, adminNoExpiry.id);
    const dbExplicit = grantRow(after, explicitExpiry.id);
    const dbLater = grantRow(after, laterGrant.id);
    const issueAudit = asAudit(after.audits, adminNoExpiry.operationId, "bonus_grant_issued");
    const explicitAudit = asAudit(after.audits, explicitExpiry.operationId, "bonus_grant_issued");
    const laterAudit = asAudit(after.audits, laterGrant.operationId, "bonus_grant_issued");
    const expiryBoundaryAudit = asAudit(after.audits, boundaryExpiryId, "bonus_grant_rejected");
    const immutableEditAudits = editOperations.map((item) => asAudit(after.audits, item.operationId, "bonus_grant_rejected"));
    const rejectionAudit = after.audits.filter((row) =>
      [ownerAttemptId, foreignAttemptId, changedAmountId, zeroId, precisionId, pastExpiryId, boundaryExpiryId,
        ...editOperations.map((item) => item.operationId)]
        .includes(row.operation_id) && row.event_type === "bonus_grant_rejected");
    const baselineFinancialEffect = noFinancialEffect(before, after, [
      ownerAttemptId,
      foreignAttemptId,
      agentAttemptId,
      zeroId,
      precisionId,
      pastExpiryId,
      boundaryExpiryId,
      ...editOperations.map((item) => item.operationId),
    ]);
    const changedRetryPreservedOriginal = JSON.stringify(
      afterFirstGrant.operations.filter((row) => row.operation_id === changedAmountId),
    ) === JSON.stringify(after.operations.filter((row) => row.operation_id === changedAmountId))
      && JSON.stringify(afterFirstGrant.grants.filter((row) => row.operation_id === changedAmountId))
        === JSON.stringify(after.grants.filter((row) => row.operation_id === changedAmountId))
      && JSON.stringify(afterFirstGrant.entries.filter((row) => row.operation_id === changedAmountId))
        === JSON.stringify(after.entries.filter((row) => row.operation_id === changedAmountId));
    const ownerBillingGrants = [adminNoExpiry, explicitExpiry, laterGrant].map((grant) => browserGrants.get(grant.id));

    sc001Raw = {
      admin: { id: adminIdentity.id, isAdmin: adminIdentity.isAdmin },
      owner: { id: ownerIdentity.id },
      foreignOwner: { id: foreign.ownerId },
      agent: { id: agentCard.id, credentialIssued: true },
      ui: {
        capture: adminCapture.capture,
        firstGrant: initialCommit,
        browserSawInitialResponse: pageSawInitialResponse,
        apiRestartedBeforeReplay: true,
        replay,
        changedAmount,
        unauthorized: { ownerDenied, foreignDenied, agentDenied },
        invalid: { zeroAmount, excessPrecision, pastExpiry },
      },
      ownerView: ownerBilling,
      database: {
        observer: after.observer,
        before,
        afterFirstGrant,
        after,
        grants: [dbNoExpiry],
        ledgerEntries: after.entries.filter((row) => row.operation_id === adminNoExpiry.operationId),
        operationRows: after.operations.filter((row) => row.operation_id === adminNoExpiry.operationId),
        issuanceAudit: issueAudit,
        rejectionAudit,
        invalidAttemptsNoFinancialEffect: baselineFinancialEffect,
        changedRetryPreservedOriginal,
      },
    };
    sc002Raw = {
      admin: { id: adminIdentity.id, isAdmin: adminIdentity.isAdmin },
      owner: { id: ownerIdentity.id },
      ui: {
        capture: adminCapture.capture,
        originalNoExpiry: adminNoExpiry,
        explicitExpiry,
        laterGrant,
        expiryBoundary: { submittedExpiresAt: boundaryTimestamp, outcome: expiryBoundary },
        editAttempts: editOperations.map((item) => item.outcome),
      },
      ownerView: { grants: ownerBilling.grants, history: ownerBilling.history },
      beforeLaterGrant: beforeLaterGrant.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)),
      afterLaterGrant: ownerBilling.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)),
      database: {
        observer: after.observer,
        before,
        beforeLaterGrant: databaseBeforeLaterGrant,
        after,
        grants: [dbNoExpiry, dbExplicit, dbLater],
        sourceEntries: after.entries.filter((row) => [adminNoExpiry.id, explicitExpiry.id, laterGrant.id].includes(row.bonus_grant_id)),
        issuanceAudits: [issueAudit, explicitAudit, laterAudit],
        rejectionAudits: rejectionAudit,
      },
      derivedChecks: {
        ownerViewContainsAllTerms: ownerBillingGrants.every((item) => item !== undefined),
        databaseOriginalTermsUnchangedAfterLaterGrant: JSON.stringify(databaseBeforeLaterGrant.grants
          .filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
          === JSON.stringify(after.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id))),
        earlierTermsUnchangedAfterLaterGrant: JSON.stringify(beforeLaterGrant.grants
          .filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
          === JSON.stringify(ownerBilling.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id))),
        repeatedOwnerReadStable: JSON.stringify(ownerBilling.grants) === JSON.stringify(repeatedOwnerBilling.grants),
        ownerViewBeforeExplicitGrant: beforeTbbSc002.grants.some((row) => row.id === adminNoExpiry.id),
      },
    };

    const sc001Ready = Boolean(
      adminNoExpiry && dbNoExpiry && grantMatches(dbNoExpiry, { ...adminNoExpiry, ownerId, issuedByOwnerId: adminIdentity.id })
      && initialCommit.status === 200 && replay.status === 200 && replay.replayed
      && replay.grant?.id === initialCommit.grant.id && replay.request?.operationId === initialPayload.operationId
      && !pageSawInitialResponse && after.operations.filter((row) => row.operation_id === adminNoExpiry.operationId).length === 1
      && after.grants.filter((row) => row.operation_id === adminNoExpiry.operationId).length === 1
      && after.entries.filter((row) => row.operation_id === adminNoExpiry.operationId
        && row.entry_type === "bonus_grant" && row.source_kind === "tester_bonus"
        && row.bonus_grant_id === adminNoExpiry.id && row.actor_owner_id === adminIdentity.id
        && BigInt(row.amount_units) === amountUnits("1.250000")
        && BigInt(row.available_delta_units) === amountUnits("1.250000")
        && BigInt(row.reserved_delta_units) === 0n && BigInt(row.expired_delta_units) === 0n).length === 1
      && issueAudit?.actor_owner_id === adminIdentity.id && issueAudit?.subject_owner_id === ownerId
      && issueAudit?.metadata?.reason === SC001_REASON && issueAudit?.metadata?.amount === "1.250000"
      && (ownerDenied.status === 403 || ownerDenied.status === 401)
      && (foreignDenied.status === 403 || foreignDenied.status === 401)
      && (agentDenied.status === 403 || agentDenied.status === 401)
      && changedAmount.status === 409 && changedAmount.errorCode === "IDEMPOTENCY_CONFLICT"
      && changedRetryPreservedOriginal
      && zeroAmount.status === 400 && excessPrecision.status === 400 && pastExpiry.status === 409
      && baselineFinancialEffect,
    );

    const sc002Ready = Boolean(
      sc001Ready && explicitExpiry && laterGrant
      && grantMatches(dbExplicit, { ...explicitExpiry, ownerId, issuedByOwnerId: adminIdentity.id })
      && grantMatches(dbLater, { ...laterGrant, ownerId, issuedByOwnerId: adminIdentity.id })
      && dbNoExpiry.expires_at === null && dbExplicit.expires_at !== null && dbLater.expires_at === null
      && issueAudit?.metadata?.expiresAt === null
      && explicitAudit?.actor_owner_id === adminIdentity.id && explicitAudit?.subject_owner_id === ownerId
      && laterAudit?.actor_owner_id === adminIdentity.id && laterAudit?.subject_owner_id === ownerId
      && expiryBoundary.status === 409 && expiryBoundary.errorCode === "EXPIRY_NOT_FUTURE"
      && expiryBoundaryAudit?.metadata?.reasonCode === "EXPIRY_NOT_FUTURE"
      && editOperations.every((item) => item.outcome.status === 409 && item.outcome.errorCode === "IMMUTABLE_GRANT")
      && immutableEditAudits.length === 3
      && immutableEditAudits.every((audit) => audit?.actor_owner_id === adminIdentity.id
        && audit?.subject_owner_id === ownerId && audit?.metadata?.grantId === explicitExpiry.id
        && audit?.metadata?.reasonCode === "IMMUTABLE_GRANT")
      && ownerBillingGrants.every((item) => item !== undefined)
      && JSON.stringify(databaseBeforeLaterGrant.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
        === JSON.stringify(after.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
      && JSON.stringify(beforeLaterGrant.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
        === JSON.stringify(ownerBilling.grants.filter((row) => [adminNoExpiry.id, explicitExpiry.id].includes(row.id)))
      && JSON.stringify(ownerBilling.grants) === JSON.stringify(repeatedOwnerBilling.grants),
    );

    assertSecretFree(sc001Raw, "TBB-SC-001 browser and database observations");
    assertSecretFree(sc002Raw, "TBB-SC-002 browser and database observations");
    return {
      browserData: { "TBB-SC-001": sc001Raw, "TBB-SC-002": sc002Raw },
      databaseData: {
        "TBB-SC-001": sc001Raw.database,
        "TBB-SC-002": sc002Raw.database,
        observer: after.observer,
      },
      sc001Ready,
      sc002Ready,
      blockedScenarios: Object.fromEntries(Array.from({ length: 13 }, (_, index) => [
        `TBB-SC-${String(index + 3).padStart(3, "0")}`,
        index + 3 === 13 ? "full_tbb013_contract_not_complete" : "required_forum_run_refund_or_pilot_boundary_not_implemented",
      ])),
    };
  } finally {
    agentSecret = "";
    if (agentContext) await agentContext.dispose();
    if (foreignContexts.length) await Promise.all(foreignContexts.map((context) => context.close().catch(() => undefined)));
    await observerPool.end();
  }
}
