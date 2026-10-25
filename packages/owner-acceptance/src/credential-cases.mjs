import { randomUUID } from "node:crypto";
import pg from "pg";
import { request as playwrightRequest } from "playwright";
import { attachSafeBrowserCapture, waitForPath } from "./browser-support.mjs";

const { Pool } = pg;
const API_RESOURCE_PATH = "/api/agent";
const API_PREFLIGHT_PATH = "/api/agent/preflight";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function operationId() {
  return randomUUID().replaceAll("-", "");
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasForbiddenSecretShape(value, secretValues = []) {
  const secretSet = new Set(secretValues.filter((item) => typeof item === "string" && item.length > 0));
  const visit = (current) => {
    if (Array.isArray(current)) return current.some(visit);
    if (isObject(current)) {
      return Object.entries(current).some(([key, child]) => {
        const normalized = key.replace(/[^a-z]/gi, "").toLowerCase();
        const forbiddenKey = new Set(["secret", "secretvalue", "token", "tokenvalue", "plaintext", "credentialvalue"]);
        return forbiddenKey.has(normalized) || visit(child);
      });
    }
    return typeof current === "string" && secretSet.has(current);
  };
  return visit(value);
}

function extractToken(text) {
  const match = text.match(/\baap1_[A-Za-z0-9_-]{40,60}\b/);
  return match?.[0] ?? null;
}

function isLocalApiResponse(response, path, method) {
  const url = new URL(response.url());
  return url.pathname === path && response.request().method() === method;
}

async function waitForApiResponse(page, path, method) {
  return page.waitForResponse((response) => isLocalApiResponse(response, path, method), { timeout: 15000 });
}

export async function createCard(page, name, captureApi) {
  const form = page.getByTestId("agent-create-form");
  await form.getByTestId("agent-name").fill(name);
  await form.getByTestId("agent-description").fill("Synthetic credential acceptance card");
  const responsePromise = waitForApiResponse(page, "/api/owner/agents", "POST");
  captureApi?.action("click", "agent-create");
  await form.getByTestId("agent-create").click();
  const response = await responsePromise;
  const body = await response.json();
  assert(response.status() === 201 && typeof body?.agent?.id === "string", "Owner UI did not create an acceptance agent card");
  return { id: body.agent.id, operationId: response.request().postDataJSON()?.operationId };
}

async function currentCredentialStatus(page, agentId) {
  const response = await page.request.get(`/api/owner/agents/${agentId}/manual-credential`);
  const body = await response.json().catch(() => ({}));
  assert(response.status() === 200 && isObject(body?.access) && Array.isArray(body.credentials), "Owner credential status read failed");
  assert(!hasForbiddenSecretShape(body), "Safe credential status response contains a plaintext secret field");
  return { response, body };
}

async function waitForTokenAndDismiss(page, agentId, issueBody) {
  const selector = `credential-secret-once-${agentId}`;
  const shown = page.getByTestId(selector);
  await shown.waitFor({ state: "visible", timeout: 10000 });
  const token = extractToken(await shown.innerText());
  assert(typeof token === "string" && issueBody.secret === token && issueBody.secretAvailable === true, "Owner UI did not show the one-time issuance secret");
  await page.getByTestId(`credential-secret-dismiss-${agentId}`).click();
  await shown.waitFor({ state: "detached", timeout: 10000 });
  return token;
}

export async function issueThroughUi(page, agentId, intent = "issue", captureApi) {
  const safeBefore = await currentCredentialStatus(page, agentId);
  const expectedAccessRevision = safeBefore.body.access.revision;
  const path = `/api/owner/agents/${agentId}/manual-credential`;
  const target = intent === "replace"
    ? page.getByTestId(`credential-replace-${safeBefore.body.credentials.find((row) => row.status === "active")?.id}`)
    : page.getByTestId(`credential-issue-${agentId}`);
  await target.waitFor({ state: "visible", timeout: 15000 });
  assert(await target.count() === 1, `Credential ${intent} control is not uniquely available`);
  captureApi?.action("click", await target.getAttribute("data-testid"));
  const [response] = await Promise.all([
    waitForApiResponse(page, path, "POST"),
    target.click()
  ]);
  const body = await response.json();
  const requestBody = response.request().postDataJSON();
  const expectedStatus = intent === "issue" ? 201 : 200;
  assert(response.status() === expectedStatus && body?.access?.revision === expectedAccessRevision + 1, `Credential ${intent} was not committed through the owner UI`);
  assert(requestBody?.intent === intent && typeof requestBody.operationId === "string", `Credential ${intent} request did not use the expected operation contract`);
  assert(isObject(body.credential) && typeof body.credential.id === "string" && typeof body.credential.grantId === "string", "Credential response lacks safe identities");
  const secret = await waitForTokenAndDismiss(page, agentId, body);
  const safeResponse = { access: body.access, credential: body.credential, replayed: body.replayed, secretAvailable: body.secretAvailable };
  assert(!hasForbiddenSecretShape(safeResponse), "Credential safe response projection contains a secret field");
  return { credential: body.credential, access: body.access, secret, operationId: requestBody.operationId, requestBody };
}

async function createForeignOwner({ adminPage, newContext, login, publicOrigin }) {
  const context = await newContext();
  const subject = `oid-aap-cred-${randomUUID()}`;
  const foreign = await login(context, subject);
  const inviteResponsePromise = adminPage.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/admin/invitations" && response.request().method() === "POST", { timeout: 15000 });
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
  const current = await foreign.page.request.get("/api/owner");
  const body = await current.json();
  assert(current.status() === 200 && typeof body.owner?.id === "string", "Synthetic foreign owner lacks an admitted identity");
  return { context, page: foreign.page, ownerId: body.owner.id, activationStatus: activation.status(), publicOrigin };
}

async function createNoCookieClient(publicOrigin) {
  return playwrightRequest.newContext({
    baseURL: publicOrigin,
    extraHTTPHeaders: { origin: publicOrigin },
    timeout: 15000,
  });
}

async function preflight(client, { token, agentId, resource, path = API_PREFLIGHT_PATH }) {
  const headers = {
    "x-agent-id": agentId,
    "x-agent-resource": resource,
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
  const response = await client.get(path, { headers });
  let body = {};
  try { body = await response.json(); } catch { /* Denial may have an empty body. */ }
  return {
    status: response.status(),
    allowed: body?.allowed === true,
    agentId: typeof body?.agentId === "string" ? body.agentId : null,
    resource: typeof body?.resource === "string" ? body.resource : null,
    role: typeof body?.role === "string" ? body.role : null,
    accessRevision: Number.isInteger(body?.accessRevision) ? body.accessRevision : null,
    policyRevision: Number.isInteger(body?.policyRevision) ? body.policyRevision : null,
    permissions: isObject(body?.permissions) ? body.permissions : null,
  };
}

async function readObserverSnapshot(pool, { ownerId, agentIds, operationIds = [], secrets = [] }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = await client.query("SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only");
    const observer = identity.rows[0];
    if (observer.role !== "oid_observer" || observer.transaction_read_only !== "on") {
      throw new Error("Credential outcome inspection did not use the independent read-only oid_observer");
    }
    const agents = await client.query(
      `SELECT id::text, owner_id::text, access_revision, access_generation, access_revoked_at
       FROM oid_agent WHERE owner_id::text=$1 AND id=ANY($2::uuid[]) ORDER BY id`, [ownerId, agentIds],
    );
    const policies = await client.query(
      `SELECT agent_id::text, training, ranked, forum_messages, custom_topics, revision AS policy_revision
       FROM oid_agent_policy WHERE agent_id=ANY($1::uuid[]) ORDER BY agent_id`, [agentIds],
    );
    const grants = await client.query(
      `SELECT id::text, owner_id::text, agent_id::text, operation_id, source, resource, role,
              access_generation, created_at, expires_at, revoked_at, revocation_reason,
              CASE WHEN revoked_at IS NOT NULL AND revocation_reason='replaced' THEN 'replaced'
                   WHEN revoked_at IS NOT NULL AND revocation_reason='owner_global_revoke' THEN 'revoked'
                   WHEN expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END AS status
       FROM oid_agent_access_grant WHERE owner_id::text=$1 AND agent_id=ANY($2::uuid[]) ORDER BY created_at,id`, [ownerId, agentIds],
    );
    const credentials = await client.query(
      `SELECT c.id::text, c.grant_id::text, g.owner_id::text, g.agent_id::text,
              (c.verifier_hash IS NOT NULL AND length(c.verifier_hash)>0) AS verifier_present,
              g.resource, g.role, g.access_generation, c.created_at, g.expires_at, g.revoked_at, g.revocation_reason,
              CASE WHEN g.revoked_at IS NOT NULL AND g.revocation_reason='replaced' THEN 'replaced'
                   WHEN g.revoked_at IS NOT NULL AND g.revocation_reason='owner_global_revoke' THEN 'revoked'
                   WHEN g.expires_at<=clock_timestamp() THEN 'expired' ELSE 'active' END AS status
       FROM oid_agent_manual_credential c JOIN oid_agent_access_grant g ON g.id=c.grant_id
       WHERE g.owner_id::text=$1 AND g.agent_id=ANY($2::uuid[]) ORDER BY c.created_at,c.id`, [ownerId, agentIds],
    );
    const operations = operationIds.length ? await client.query(
      `SELECT operation_id, action, response_json FROM oid_agent_operation WHERE operation_id=ANY($1::text[]) ORDER BY operation_id`, [operationIds],
    ) : { rows: [] };
    const audits = operationIds.length ? await client.query(
      `SELECT event_type, operation_id, actor_owner_id::text, subject_owner_id::text, metadata
       FROM oid_audit WHERE operation_id=ANY($1::text[]) ORDER BY created_at,id`, [operationIds],
    ) : { rows: [] };
    const outbox = await client.query(
      `SELECT event_id::text, owner_id::text, agent_id::text, access_generation, operation_id, event_type, status,
              payload_json->>'scope' AS scope, payload_json->>'reason' AS reason, created_at
       FROM oid_agent_cancellation_outbox WHERE owner_id::text=$1 AND agent_id=ANY($2::uuid[]) ORDER BY created_at,event_id`, [ownerId, agentIds],
    );
    const columns = await client.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema=current_schema() AND table_name='oid_agent_manual_credential' ORDER BY ordinal_position`,
    );
    await client.query("COMMIT");

    const noPlaintextCredentialColumn = !columns.rows.some((row) => /(?:^|_)(?:token|secret|plaintext|raw)(?:_|$)/i.test(row.column_name));
    const safeOperations = operations.rows.map((row) => ({
      operationId: row.operation_id,
      action: row.action,
      responseHasSecret: hasForbiddenSecretShape(row.response_json, secrets),
    }));
    const safeAudits = audits.rows.map((row) => ({
      eventType: row.event_type,
      operationId: row.operation_id,
      actorOwnerId: row.actor_owner_id,
      subjectOwnerId: row.subject_owner_id,
      metadataHasSecret: hasForbiddenSecretShape(row.metadata, secrets),
    }));
    return {
      observer,
      agents: agents.rows,
      policies: policies.rows,
      grants: grants.rows,
      credentials: credentials.rows,
      operations: safeOperations,
      audits: safeAudits,
      outbox: outbox.rows,
      credentialTableColumns: columns.rows.map((row) => row.column_name),
      noPlaintextCredentialColumn,
      secretAbsentFromOperations: safeOperations.every((row) => row.responseHasSecret === false),
      secretAbsentFromAudit: safeAudits.every((row) => row.metadataHasSecret === false),
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setDedicatedGrantExpired(databaseUrl, grantId, credentialId, agentId, ownerId) {
  assert(typeof databaseUrl === "string" && databaseUrl.length > 0, "The dedicated expiry fixture needs the owner database URL");
  const pool = new Pool({ connectionString: databaseUrl, max: 1, application_name: "aap-acceptance-expiry-fixture" });
  try {
    const updated = await pool.query(
      `UPDATE oid_agent_access_grant SET expires_at=clock_timestamp()-interval '1 second'
       WHERE id=$1::uuid AND agent_id=$2::uuid AND owner_id=$3::uuid AND revoked_at IS NULL AND expires_at>clock_timestamp()
       RETURNING id::text`, [grantId, agentId, ownerId],
    );
    assert(updated.rowCount === 1 && updated.rows[0].id === grantId, "Expiry fixture did not update exactly the fresh dedicated grant");
    return { credentialId, grantId, agentId, updatedRows: updated.rowCount, method: "dedicated acceptance DB expiry fixture" };
  } finally {
    await pool.end();
  }
}

async function updatePolicyFromOwnerUi(page, agentId) {
  const card = page.getByTestId(`agent-card-${agentId}`);
  const revisionBefore = Number((await card.getByTestId("agent-policy-revision").innerText()).match(/\d+/)?.[0]);
  await card.getByTestId("agent-permission-training").check();
  const responsePromise = waitForApiResponse(page, `/api/owner/agents/${agentId}/permissions`, "PUT");
  await card.getByTestId("agent-permissions-save").click();
  const response = await responsePromise;
  const body = await response.json();
  return { status: response.status(), policyRevision: body?.agent?.policyRevision ?? null,
    operationId: response.request().postDataJSON()?.operationId ?? null, revisionBefore };
}

export async function runAapCredentialCases({
  page,
  ownerId,
  adminPage,
  newContext,
  login,
  observerDatabaseUrl,
  databaseUrl,
  publicOrigin,
  restartApi,
}) {
  if (!page || typeof ownerId !== "string" || typeof newContext !== "function" || typeof login !== "function") {
    throw new Error("AAP credential acceptance is missing its authenticated browser and synthetic owner-verifier helpers");
  }
  if (!observerDatabaseUrl || !databaseUrl || !publicOrigin || typeof restartApi !== "function") {
    throw new Error("AAP credential acceptance needs the observer, fixture database, public origin and API restart capability");
  }

  const ownerPage = await page.context().newPage();
  const captureApi = attachSafeBrowserCapture(ownerPage, "AAP-SC-004");
  const capture = captureApi.capture;
  const agentClient = await createNoCookieClient(publicOrigin);
  const observerPool = new Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "aap-credential-readonly-observer" });
  const secrets = [];
  const operationIds = [];
  const agentIds = [];
  let foreignContext;
  let expiredAgentToken = "";
  let currentAgentToken = "";
  let foreign;
  try {
    await ownerPage.goto("/agents", { waitUntil: "domcontentloaded" });
    await ownerPage.getByTestId("agent-create-form").waitFor({ state: "visible" });
    const primary = await createCard(ownerPage, `AAP credential primary ${randomUUID().slice(0, 8)}`, captureApi);
    agentIds.push(primary.id);
    if (primary.operationId) operationIds.push(primary.operationId);

    const reference = await createCard(ownerPage, `AAP credential reference ${randomUUID().slice(0, 8)}`, captureApi);
    agentIds.push(reference.id);
    if (reference.operationId) operationIds.push(reference.operationId);

    const expired = await createCard(ownerPage, `AAP credential expiry ${randomUUID().slice(0, 8)}`, captureApi);
    agentIds.push(expired.id);
    if (expired.operationId) operationIds.push(expired.operationId);

    const resource = new URL(API_RESOURCE_PATH, publicOrigin).toString();
    const preflightUrl = new URL(API_PREFLIGHT_PATH, publicOrigin).toString();
    const initialSafeStatus = await currentCredentialStatus(ownerPage, primary.id);
    assert(initialSafeStatus.body.resource === resource && initialSafeStatus.body.preflightUrl === preflightUrl,
      "Owner safe credential status did not expose the configured resource and preflight URL");
    const initial = await issueThroughUi(ownerPage, primary.id, "issue", captureApi);
    currentAgentToken = initial.secret;
    secrets.push(initial.secret);
    operationIds.push(initial.operationId);
    const initialPreflight = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource });
    assert(initialPreflight.status === 200 && initialPreflight.allowed && initialPreflight.agentId === primary.id
      && initialPreflight.resource === resource && initialPreflight.role === "agent", "Cookie-free bearer preflight did not authenticate the issued agent credential");

    const safeReceiptReplayResponse = await ownerPage.request.post(`/api/owner/agents/${primary.id}/manual-credential`, {
      headers: { origin: publicOrigin }, data: initial.requestBody,
    });
    const safeReceiptReplay = await safeReceiptReplayResponse.json().catch(() => ({}));
    const replayCredentialId = safeReceiptReplay?.credential?.id ?? null;
    const replayWasSafe = safeReceiptReplayResponse.status() === 200 && safeReceiptReplay.replayed === true
      && safeReceiptReplay.secretAvailable === false && !Object.hasOwn(safeReceiptReplay, "secret")
      && replayCredentialId === initial.credential.id;
    assert(replayWasSafe, "Replaying the issuance operation returned plaintext or an inconsistent safe receipt");

    const beforeNegatives = await readObserverSnapshot(observerPool, { ownerId, agentIds: [primary.id], operationIds, secrets });
    const ownerCookiesPresent = (await ownerPage.context().cookies(publicOrigin)).length > 0;
    const cookieOnly = await ownerPage.request.get(API_PREFLIGHT_PATH, { headers: { "x-agent-id": primary.id, "x-agent-resource": resource } });
    const cookieOnlyStatus = cookieOnly.status();
    const wrongResource = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource: `${resource}/wrong` });
    const wrongAgent = await preflight(agentClient, { token: currentAgentToken, agentId: reference.id, resource });
    const agentSelfIssuance = await agentClient.post(`/api/owner/agents/${primary.id}/manual-credential`, {
      headers: { authorization: `Bearer ${currentAgentToken}` },
      data: { operationId: operationId(), expectedAccessRevision: initial.access.revision, intent: "issue" },
    });
    const agentSelfIssuanceStatus = agentSelfIssuance.status();
    const forgedWithdrawalScope = await agentClient.put(`/api/owner/agents/${primary.id}/permissions`, {
      headers: { authorization: `Bearer ${currentAgentToken}`, "x-agent-scope": "wallet.withdraw" },
      data: { operationId: operationId(), expectedPolicyRevision: initialPreflight.policyRevision,
        permissions: { training: true, ranked: true, forumMessages: true, customTopics: true } },
    });
    const forgedWithdrawalScopeStatus = forgedWithdrawalScope.status();

    foreign = await createForeignOwner({ adminPage, newContext, login, publicOrigin });
    foreignContext = foreign.context;
    assert(foreign.ownerId !== ownerId, "Foreign-owner verifier resolved the same owner identity");
    const foreignIssuance = await foreign.page.request.post(`/api/owner/agents/${primary.id}/manual-credential`, {
      headers: { origin: publicOrigin },
      data: { operationId: operationId(), expectedAccessRevision: initial.access.revision, intent: "issue" },
    });
    const foreignIssuanceStatus = foreignIssuance.status();
    const afterNegatives = await readObserverSnapshot(observerPool, { ownerId, agentIds: [primary.id], operationIds, secrets });
    const noUnauthorizedCredentialCreated = afterNegatives.credentials.length === beforeNegatives.credentials.length
      && afterNegatives.grants.length === beforeNegatives.grants.length;
    assert(cookieOnlyStatus === 401 && wrongResource.status === 403 && wrongAgent.status === 403
      && agentSelfIssuanceStatus === 401 && forgedWithdrawalScopeStatus === 401 && foreignIssuanceStatus === 404
      && noUnauthorizedCredentialCreated, "An AAP credential negative boundary was not denied without a durable grant");

    captureApi.action("click", "agent-permissions-save");
    const policyChange = await updatePolicyFromOwnerUi(ownerPage, primary.id);
    if (policyChange.operationId) operationIds.push(policyChange.operationId);
    const sameTokenAfterPolicy = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource });
    const afterPolicyStatus = await currentCredentialStatus(ownerPage, primary.id);
    const sameCredentialAfterPolicy = afterPolicyStatus.body.credentials.some((row) => row.id === initial.credential.id && row.status === "active");
    const policyAppliedWithoutReplacement = policyChange.status === 200 && sameCredentialAfterPolicy
      && sameTokenAfterPolicy.status === 200 && sameTokenAfterPolicy.policyRevision === policyChange.policyRevision
      && sameTokenAfterPolicy.permissions?.training === true;
    assert(policyAppliedWithoutReplacement, "The existing credential did not observe current owner policy without replacement");

    const expiryIssue = await issueThroughUi(ownerPage, expired.id, "issue", captureApi);
    expiredAgentToken = expiryIssue.secret;
    secrets.push(expiryIssue.secret);
    operationIds.push(expiryIssue.operationId);
    const expiryFixture = await setDedicatedGrantExpired(databaseUrl, expiryIssue.credential.grantId, expiryIssue.credential.id, expired.id, ownerId);
    const expiredPreflight = await preflight(agentClient, { token: expiredAgentToken, agentId: expired.id, resource });
    assert(expiredPreflight.status === 401 && !expiredPreflight.allowed, "An expired manual credential was not denied at preflight");

    const lostPath = `/api/owner/agents/${primary.id}/manual-credential`;
    const activeBeforeLost = await currentCredentialStatus(ownerPage, primary.id);
    const predecessor = activeBeforeLost.body.credentials.find((row) => row.id === initial.credential.id && row.status === "active");
    assert(predecessor, "The known predecessor credential was not active before lost-response replacement");
    const lostResponse = { committed: false, status: null, browserSawResponse: false, safeStatusRecovered: false, activeCredentialId: null };
    let interceptUsed = false;
    const responseCountBeforeLostAttempt = capture.responses.length;
    await ownerPage.route(`**${lostPath}`, async (route) => {
      if (interceptUsed || route.request().method() !== "POST") return route.continue();
      interceptUsed = true;
      const committed = await route.fetch();
      lostResponse.status = committed.status();
      lostResponse.committed = committed.status() === 200;
      await route.abort("failed");
    });
    const lostPostCountBefore = capture.requests.filter((row) => row.path === lostPath && row.method === "POST").length;
    const lostStatusPromise = waitForApiResponse(ownerPage, lostPath, "GET");
    captureApi.action("click", `credential-replace-${initial.credential.id}`);
    await ownerPage.getByTestId(`credential-replace-${initial.credential.id}`).click();
    const safeStatusResponse = await lostStatusPromise;
    const recoveredStatus = await safeStatusResponse.json();
    await ownerPage.unroute(`**${lostPath}`);
    const lostIssueOperationId = capture.requests.filter((row) => row.path === lostPath && row.method === "POST")
      .map((row) => row.operationId).filter((value) => typeof value === "string").at(-1);
    assert(typeof lostIssueOperationId === "string", "The committed uncertain replacement had no safe operation identity in browser request metadata");
    operationIds.push(lostIssueOperationId);
    lostResponse.browserSawResponse = capture.responses.slice(responseCountBeforeLostAttempt)
      .some((row) => row.path === lostPath && row.method === "POST");
    lostResponse.safeStatusRecovered = safeStatusResponse.status() === 200 && Array.isArray(recoveredStatus.credentials)
      && !hasForbiddenSecretShape(recoveredStatus);
    lostResponse.activeCredentialId = recoveredStatus.credentials.find((row) => row.status === "active")?.id ?? null;
    const lostPostCountAfter = capture.requests.filter((row) => row.path === lostPath && row.method === "POST").length;
    lostResponse.uiDidNotRetryPlaintextIssue = lostPostCountAfter === lostPostCountBefore + 1;
    assert(lostResponse.committed && lostResponse.status === 200 && !lostResponse.browserSawResponse
      && lostResponse.safeStatusRecovered && lostResponse.activeCredentialId && lostResponse.activeCredentialId !== initial.credential.id
      && lostResponse.uiDidNotRetryPlaintextIssue, "Lost issuance response did not recover through safe status without a plaintext retry");

    const oldAfterLostResponse = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource });
    assert(oldAfterLostResponse.status === 401, "The predecessor credential remained valid after the uncertain issuance was fenced");
    const lostCurrent = recoveredStatus.credentials.find((row) => row.id === lostResponse.activeCredentialId);
    assert(lostCurrent?.status === "active", "Safe recovery did not identify the committed uncertain credential");
    const replacementResponsePromise = waitForApiResponse(ownerPage, lostPath, "POST");
    captureApi.action("click", `credential-replace-${lostResponse.activeCredentialId}`);
    await ownerPage.getByTestId(`credential-replace-${lostResponse.activeCredentialId}`).click();
    const replacementResponse = await replacementResponsePromise;
    const replacementBody = await replacementResponse.json();
    const replacementRequest = replacementResponse.request().postDataJSON();
    assert(replacementResponse.status() === 200 && replacementRequest?.intent === "replace", "Explicit replacement after safe status did not commit");
    const replacementToken = await waitForTokenAndDismiss(ownerPage, primary.id, replacementBody);
    currentAgentToken = replacementToken;
    secrets.push(replacementToken);
    operationIds.push(replacementRequest.operationId);
    const replacementPreflight = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource });
    assert(replacementPreflight.status === 200 && replacementPreflight.allowed, "The explicitly replaced credential did not authenticate");

    const referenceIssue = await issueThroughUi(ownerPage, reference.id, "issue", captureApi);
    const referenceToken = referenceIssue.secret;
    secrets.push(referenceToken);
    operationIds.push(referenceIssue.operationId);
    const referenceBeforeRevoke = await preflight(agentClient, { token: referenceToken, agentId: reference.id, resource });
    assert(referenceBeforeRevoke.status === 200 && referenceBeforeRevoke.allowed, "Reference agent credential was not active before global revoke");

    const revoked = { status: null, response: null, oldTokenDeniedAfterRestart: false, otherAgentStillWorksAfterRestart: false };
    const revokePath = `/api/owner/agents/${primary.id}/access-revoke`;
    const revokeResponsePromise = waitForApiResponse(ownerPage, revokePath, "POST");
    captureApi.action("click", `agent-revoke-${primary.id}`);
    await ownerPage.getByTestId(`agent-revoke-${primary.id}`).click();
    const revokeResponse = await revokeResponsePromise;
    const revokeBody = await revokeResponse.json();
    revoked.status = revokeResponse.status();
    revoked.response = {
      access: revokeBody?.access,
      cancellation: revokeBody?.cancellation,
      replayed: revokeBody?.replayed,
    };
    operationIds.push(revokeResponse.request().postDataJSON()?.operationId);
    assert(revoked.status === 200 && revokeBody?.access?.status === "revoked" && revokeBody?.cancellation?.status === "pending"
      && typeof revokeBody?.cancellation?.eventId === "string", "Owner UI global revoke did not return a safe pending cancellation reference");

    await restartApi();
    const oldAfterRestart = await preflight(agentClient, { token: currentAgentToken, agentId: primary.id, resource });
    revoked.oldTokenDeniedAfterRestart = oldAfterRestart.status === 401;

    const referenceAfterRestart = await preflight(agentClient, { token: referenceToken, agentId: reference.id, resource });
    revoked.otherAgentStillWorksAfterRestart = referenceAfterRestart.status === 200 && referenceAfterRestart.allowed;

    const postRevokeStatus = await currentCredentialStatus(ownerPage, primary.id);
    const revokedRevision = postRevokeStatus.body.access.revision;
    const replacementAfterRevoke = await ownerPage.request.post(`/api/owner/agents/${primary.id}/manual-credential`, {
      headers: { origin: publicOrigin },
      data: { operationId: operationId(), expectedAccessRevision: revokedRevision, intent: "replace" },
    });
    const replacementAfterRevokeBody = await replacementAfterRevoke.json().catch(() => ({}));
    const replacementAfterRevokeDenied = replacementAfterRevoke.status() === 409
      && replacementAfterRevokeBody?.error?.code === "REAUTHORIZATION_REQUIRED"
      && !Object.hasOwn(replacementAfterRevokeBody, "secret");
    assert(revoked.oldTokenDeniedAfterRestart && revoked.otherAgentStillWorksAfterRestart && replacementAfterRevokeDenied,
      "Global revoke fence was not durable or incorrectly affected another agent");

    const finalDatabase = await readObserverSnapshot(observerPool, {
      ownerId, agentIds, operationIds, secrets,
    });
    const primaryCredentials = finalDatabase.credentials.filter((row) => row.agent_id === primary.id);
    const primaryGrantIds = new Set(primaryCredentials.map((row) => row.grant_id));
    const primaryGrants = finalDatabase.grants.filter((row) => row.agent_id === primary.id);
    const predecessorRow = primaryCredentials.find((row) => row.id === initial.credential.id);
    const expiredRow = finalDatabase.credentials.find((row) => row.id === expiryIssue.credential.id);
    const outboxRow = finalDatabase.outbox.find((row) => row.agent_id === primary.id);
    const safeDatabaseFacts = {
      observer: finalDatabase.observer,
      agents: finalDatabase.agents,
      policies: finalDatabase.policies,
      grants: finalDatabase.grants,
      credentials: finalDatabase.credentials,
      operations: finalDatabase.operations,
      audits: finalDatabase.audits,
      outbox: finalDatabase.outbox,
      credentialTableColumns: finalDatabase.credentialTableColumns,
      noPlaintextCredentialColumn: finalDatabase.noPlaintextCredentialColumn,
      secretAbsentFromOperations: finalDatabase.secretAbsentFromOperations,
      secretAbsentFromAudit: finalDatabase.secretAbsentFromAudit,
      negativePersistenceCheckpoint: {
        credentialsBefore: beforeNegatives.credentials.map((row) => row.id).sort(),
        credentialsAfter: afterNegatives.credentials.map((row) => row.id).sort(),
        grantsBefore: beforeNegatives.grants.map((row) => row.id).sort(),
        grantsAfter: afterNegatives.grants.map((row) => row.id).sort(),
      },
      initialIssuanceCheckpoint: {
        credentials: beforeNegatives.credentials,
        grants: beforeNegatives.grants,
        operations: beforeNegatives.operations,
        audits: beforeNegatives.audits,
        noPlaintextCredentialColumn: beforeNegatives.noPlaintextCredentialColumn,
        secretAbsentFromOperations: beforeNegatives.secretAbsentFromOperations,
        secretAbsentFromAudit: beforeNegatives.secretAbsentFromAudit,
      },
      expiryFixture,
      policyChange,
    };
    const databaseCredentialBindingValid = primaryCredentials.length >= 3
      && primaryCredentials.every((row) => row.verifier_present === true && row.owner_id === ownerId && row.agent_id === primary.id)
      && primaryGrants.length === primaryCredentials.length
      && primaryGrants.every((row) => row.owner_id === ownerId && row.agent_id === primary.id && row.role === "agent" && row.resource === resource)
      && primaryGrants.every((row) => primaryGrantIds.has(row.id))
      && predecessorRow?.status === "replaced"
      && finalDatabase.noPlaintextCredentialColumn && finalDatabase.secretAbsentFromOperations && finalDatabase.secretAbsentFromAudit;
    const expiredObserved = expiredRow?.status === "expired" && new Date(expiredRow.expires_at).getTime() < Date.now();
    const revokeOutboxObserved = outboxRow?.status === "pending" && outboxRow.event_type === "agent.access.revoked"
      && outboxRow.scope === "all" && outboxRow.reason === "owner_global_revoke"
      && outboxRow.event_id === revokeBody.cancellation.eventId;
    assert(databaseCredentialBindingValid && expiredObserved && revokeOutboxObserved, "Independent SQL evidence did not match the credential lifecycle and safe effects");

    const sc004Facts = {
      ownerIssuance: true,
      tokenAgentBinding: initialPreflight.agentId === primary.id && initialPreflight.resource === resource && initialPreflight.role === "agent",
      headerAuthentication: initialPreflight.status === 200 && initialPreflight.allowed,
      unauthorizedIssuanceDenied: foreignIssuanceStatus === 404 && agentSelfIssuanceStatus === 401 && noUnauthorizedCredentialCreated,
      foreignIssuanceDenied: foreignIssuanceStatus === 404,
      agentSelfIssuanceDenied: agentSelfIssuanceStatus === 401,
      tokenForOtherAgentDenied: wrongAgent.status === 403,
      forgedWithdrawalScopeDenied: forgedWithdrawalScopeStatus === 401,
      wrongResourceDenied: wrongResource.status === 403,
      cookieOnlyDenied: ownerCookiesPresent && cookieOnlyStatus === 401,
      safeReplayReceipt: replayWasSafe,
      persistedVerifierAndGrantBinding: databaseCredentialBindingValid,
      secretAbsentFromAudit: finalDatabase.secretAbsentFromAudit,
    };
    const sc004Ready = Object.values(sc004Facts).every((value) => value === true);
    assert(sc004Ready, "AAP-SC-004 full gate facts were not all independently evidenced");

    return {
      sc004Ready,
      browserData: {
        ownerId,
        primaryAgentId: primary.id,
        referenceAgentId: reference.id,
        expiredAgentId: expired.id,
        capture: captureApi.capture,
        preflightUrl,
        resource,
        initialIssue: {
          credentialId: initial.credential.id,
          grantId: initial.credential.grantId,
          accessRevision: initial.access.revision,
          operationId: initial.operationId,
          responseStatus: 201,
          oneTimeSecretDisplayed: true,
          oneTimeSecretDismissed: true,
          safeStatus: { status: initialSafeStatus.response.status(), access: initialSafeStatus.body.access,
            resource: initialSafeStatus.body.resource, preflightUrl: initialSafeStatus.body.preflightUrl, credentials: initialSafeStatus.body.credentials },
          replay: { status: safeReceiptReplayResponse.status(), replayed: safeReceiptReplay.replayed === true,
            secretAvailable: safeReceiptReplay.secretAvailable === false, secretPropertyAbsent: !Object.hasOwn(safeReceiptReplay, "secret"), credentialIdMatches: replayCredentialId === initial.credential.id },
        },
        preflight: { initial: initialPreflight, cookieOnly: { hasOwnerSessionCookie: ownerCookiesPresent, authorizationHeaderProvided: false, status: cookieOnlyStatus },
          wrongAgent: wrongAgent.status, wrongResource: wrongResource.status, sameTokenAfterPolicy,
          policyAppliedWithoutReplacement, policyRevisionAfterUpdate: policyChange.policyRevision },
        directHttpNegatives: {
          boundary: "direct HTTP negatives using header credentials or foreign owner sessions; distinct from owner UI clicks",
          foreignIssuance: foreignIssuanceStatus,
          foreignOwnerId: foreign.ownerId,
          agentSelfIssuance: agentSelfIssuanceStatus,
          tokenForOtherAgent: wrongAgent.status,
          forgedWithdrawalScope: { status: forgedWithdrawalScopeStatus, method: "PUT", path: `/api/owner/agents/${primary.id}/permissions`, attemptedScope: "wallet.withdraw" },
          unauthorizedRequestsCreatedNoCredential: noUnauthorizedCredentialCreated,
          attempts: [
            { variant: "foreign_issuance", method: "POST", path: `/api/owner/agents/${primary.id}/manual-credential`, status: foreignIssuanceStatus, actorOwnerId: foreign.ownerId },
            { variant: "agent_self_issuance", method: "POST", path: `/api/owner/agents/${primary.id}/manual-credential`, status: agentSelfIssuanceStatus, actorAgentId: primary.id },
            { variant: "token_for_other_agent", method: "GET", path: API_PREFLIGHT_PATH, status: wrongAgent.status, requestedAgentId: reference.id },
            { variant: "forged_withdrawal_scope", method: "PUT", path: `/api/owner/agents/${primary.id}/permissions`, status: forgedWithdrawalScopeStatus, attemptedScope: "wallet.withdraw" },
          ],
        },
        policyChange,
        expiry: { fixture: expiryFixture, preflightStatus: expiredPreflight.status, denied: expiredPreflight.status === 401 },
        lostResponse: {
          boundary: "owner UI replace click; actual POST committed by route.fetch, then browser response aborted",
          upstreamCommitStatus: lostResponse.status,
          committed: lostResponse.committed,
          browserSawResponse: lostResponse.browserSawResponse,
          safeStatusRecovered: lostResponse.safeStatusRecovered,
          activeCredentialId: lostResponse.activeCredentialId,
          uiDidNotRetryPlaintextIssue: lostResponse.uiDidNotRetryPlaintextIssue,
          operationId: lostIssueOperationId,
          predecessorCredentialId: initial.credential.id,
          predecessorDeniedStatus: oldAfterLostResponse.status,
          explicitReplacementCredentialId: replacementBody.credential?.id,
          explicitReplacementStatus: replacementResponse.status(),
          explicitReplacementHeaderPreflightStatus: replacementPreflight.status,
        },
        globalRevoke: {
          boundary: "owner UI revoke click; credential fence and pending cancellation outbox only",
          responseStatus: revoked.status,
          eventId: revokeBody.cancellation.eventId,
          outboxStatus: outboxRow.status,
          oldTokenDeniedAfterRestart: revoked.oldTokenDeniedAfterRestart,
          otherAgentStillWorksAfterRestart: revoked.otherAgentStillWorksAfterRestart,
          replacementAfterRevoke: { status: replacementAfterRevoke.status(), code: replacementAfterRevokeBody?.error?.code ?? null, denied: replacementAfterRevokeDenied },
          coordinatorDelivery: "not_run; no coordinator worker or cancelled-run observation is present",
        },
        sc004Facts,
      },
      databaseData: safeDatabaseFacts,
      partialFacts: {
        "AAP-SC-004": sc004Facts,
        "AAP-SC-005": {
          issuanceResponseLostAfterCommit: lostResponse.committed && !lostResponse.browserSawResponse,
          safeStatusAndExplicitReplacement: lostResponse.safeStatusRecovered && replacementResponse.status() === 200,
          storedVerifierNotPlaintext: finalDatabase.noPlaintextCredentialColumn && primaryCredentials.every((row) => row.verifier_present),
          replacementLineageObserved: predecessorRow?.status === "replaced" && primaryCredentials.some((row) => row.id === replacementBody.credential?.id),
          oldCredentialDenied: oldAfterLostResponse.status === 401,
          safeRetryReceipt: replayWasSafe,
          secretAbsentFromAudit: finalDatabase.secretAbsentFromAudit,
          cancelledRunNonRevival: false,
        },
        "AAP-SC-009": { agentOwnerControlDenied: agentSelfIssuanceStatus === 401, forgedWithdrawalScopeDenied: forgedWithdrawalScopeStatus === 401 },
        "AAP-SC-010": {
          credentialFencePersistedAfterRestart: revoked.oldTokenDeniedAfterRestart,
          otherAgentUnchangedAfterRestart: revoked.otherAgentStillWorksAfterRestart,
          pendingCancellationOutboxObserved: revokeOutboxObserved,
          coordinatorCancellationDelivered: false,
          queuedOrStartedRunsCancelled: false,
        },
        "AAP-SC-011": { expiredCredentialDenied: expiredPreflight.status === 401, expiryFixtureLabelled: true, reconnectDeadlinePreserved: false },
        "AAP-SC-014": { actualOwnerCredentialControlsClicked: true, safeStatusOnly: true, tokenRevokedThroughUi: revoked.status === 200 },
      },
    };
  } finally {
    currentAgentToken = "";
    expiredAgentToken = "";
    secrets.fill("");
    await agentClient.dispose().catch(() => undefined);
    await observerPool.end().catch(() => undefined);
    await ownerPage.close().catch(() => undefined);
    if (foreignContext) await foreignContext.close().catch(() => undefined);
    else if (foreign?.context) await foreign.context.close().catch(() => undefined);
  }
}
