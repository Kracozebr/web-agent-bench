import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { attachSafeBrowserCapture, waitForPath } from "./browser-support.mjs";

async function snapshot(pool, ownerId, agentId, operationIds) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = await client.query("SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only");
    const observer = identity.rows[0];
    if (observer.role !== "oid_observer" || observer.transaction_read_only !== "on") throw new Error("AAP observer is not read-only");
    const agents = await client.query(`SELECT id::text,owner_id::text,name,description,client_metadata,declared_version,revision
      FROM oid_agent WHERE owner_id::text=$1 ORDER BY id`, [ownerId]);
    const policies = await client.query(`SELECT agent_id::text,training,ranked,forum_messages,custom_topics,revision AS policy_revision
      FROM oid_agent_policy WHERE agent_id::text=$1`, [agentId]);
    const operations = await client.query(`SELECT operation_id,owner_id::text,agent_id::text,action,payload_hash
      FROM oid_agent_operation WHERE operation_id=ANY($1::text[]) ORDER BY created_at`, [operationIds]);
    const audits = await client.query(`SELECT event_type,operation_id,actor_owner_id::text,subject_owner_id::text,policy_revision,metadata
      FROM oid_audit WHERE operation_id=ANY($1::text[]) ORDER BY created_at`, [operationIds]);
    await client.query("COMMIT");
    return { observer, agents: agents.rows, policies: policies.rows, operations: operations.rows, audits: audits.rows };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

export async function runAapCardCases({ page, ownerId, adminPage, newContext, login, observerDatabaseUrl }) {
  const pool = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "aap-acceptance-readonly-observer" });
  const contexts = [await newContext(), await newContext(), await newContext()];
  const capture = attachSafeBrowserCapture(page, "AAP-SC-001");
  try {
    await page.goto("/agents");
    const form = page.getByTestId("agent-create-form");
    await form.getByTestId("agent-name").fill(`Acceptance agent ${randomBytes(5).toString("hex")}`);
    await form.getByTestId("agent-description").fill("Synthetic private acceptance profile");
    await form.getByTestId("agent-client-name").fill("Local acceptance client");
    await form.getByTestId("agent-model-name").fill("Owner declared model");
    await form.getByTestId("agent-declared-version").fill("v1");
    const createdResponse = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/owner/agents" && r.request().method() === "POST");
    capture.action("click", "agent-create");
    await form.getByTestId("agent-create").click();
    const created = await createdResponse;
    const createPayload = created.request().postDataJSON();
    const original = (await created.json()).agent;
    if (created.status() !== 201 || !original?.id || Object.values(original.permissions).some(Boolean) || original.metadataTrust !== "owner-declared-unverified") throw new Error("New card did not have private defaults");
    const agentId = original.id;
    const operations = [createPayload.operationId];
    const initial = await snapshot(pool, ownerId, agentId, operations);
    const card = page.getByTestId(`agent-card-${agentId}`);
    await card.waitFor();
    await card.getByTestId(`agent-edit-${agentId}`).click();
    await card.getByTestId("agent-name").fill("Edited private acceptance agent");
    await card.getByTestId("agent-declared-version").fill("v2");
    const editedResponse = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/owner/agents/${agentId}` && r.request().method() === "PATCH");
    capture.action("click", "agent-profile-save");
    await card.getByTestId("agent-profile-save").click();
    const edited = await editedResponse;
    const profile = (await edited.json()).agent;
    operations.push(edited.request().postDataJSON().operationId);
    if (edited.status() !== 200 || profile.revision !== original.revision + 1 || profile.declaredVersion !== "v2") throw new Error("Profile update was not committed");
    await card.getByTestId("agent-permission-training").check();
    await card.getByTestId("agent-permission-forumMessages").check();
    const policyResponse = page.waitForResponse((r) => new URL(r.url()).pathname === `/api/owner/agents/${agentId}/permissions`);
    capture.action("click", "agent-permissions-save");
    await card.getByTestId("agent-permissions-save").click();
    const changed = await policyResponse;
    let policy = (await changed.json()).agent;
    operations.push(changed.request().postDataJSON().operationId);
    if (changed.status() !== 200 || policy.policyRevision !== original.policyRevision + 1 || !policy.permissions.training || !policy.permissions.forumMessages || policy.permissions.ranked || policy.permissions.customTopics) throw new Error("Independent permissions did not persist");
    await page.reload();
    await page.getByTestId(`agent-card-${agentId}`).getByTestId("agent-permission-training").waitFor();
    if (!await page.getByTestId(`agent-card-${agentId}`).getByTestId("agent-permission-training").isChecked()) throw new Error("Policy was lost on reload");

    const secondTab = await page.context().newPage();
    const raceCapture = attachSafeBrowserCapture(secondTab, "AAP-SC-014");
    await secondTab.goto("/agents");
    const tabs = [page, secondTab];
    for (const tab of tabs) await tab.getByTestId(`agent-card-${agentId}`).getByTestId("agent-permission-ranked").check();
    let release;
    const barrier = new Promise((resolve) => { release = resolve; });
    let arrivals = 0;
    const racePattern = `**/api/owner/agents/${agentId}/permissions`;
    await page.context().route(racePattern, async (route) => {
      if (++arrivals === 2) release();
      await barrier;
      await route.continue();
    });
    const raceResponses = tabs.map((tab) => tab.waitForResponse((r) => new URL(r.url()).pathname === `/api/owner/agents/${agentId}/permissions`));
    capture.action("click", "agent-permissions-save");
    raceCapture.action("click", "agent-permissions-save");
    await Promise.all(tabs.map((tab) => tab.getByTestId(`agent-card-${agentId}`).getByTestId("agent-permissions-save").click()));
    const raceResults = await Promise.all(raceResponses);
    await page.context().unroute(racePattern);
    const raceStatuses = raceResults.map((r) => r.status()).sort();
    const raceWinner = raceResults.find((r) => r.status() === 200);
    console.log(JSON.stringify({ event: "aap_policy_race", statuses: raceStatuses,
      expectedRevisions: raceResults.map((r) => r.request().postDataJSON().expectedPolicyRevision) }));
    if (raceStatuses.join(",") !== "200,409" || !raceWinner) throw new Error("Concurrent policy saves did not have one winner");
    policy = (await raceWinner.json()).agent;
    operations.push(raceWinner.request().postDataJSON().operationId);
    if (policy.policyRevision !== original.policyRevision + 2 || !policy.permissions.ranked) throw new Error("Concurrent policy commit had an unexpected revision");
    await secondTab.close();

    const foreign = await login(contexts[0], `oid-aap-foreign-${randomBytes(7).toString("hex")}`);
    const pending = await login(contexts[1], `oid-aap-pending-${randomBytes(7).toString("hex")}`);
    const issued = adminPage.waitForResponse((r) => new URL(r.url()).pathname === "/api/admin/invitations" && r.request().method() === "POST");
    await adminPage.getByTestId("invite-create").click();
    if ((await issued).status() !== 201) throw new Error("Foreign-owner invitation failed");
    const invite = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
    await foreign.page.getByTestId("invitation-code").fill(invite);
    await foreign.page.getByTestId("activate-owner").click();
    await waitForPath(foreign.page, ["/account"]);
    const headers = { origin: "http://127.0.0.1:3000" };
    const foreignRead = await foreign.page.request.get(`/api/owner/agents/${agentId}`);
    const foreignEdit = await foreign.page.request.patch(`/api/owner/agents/${agentId}`, { headers, data: { operationId: randomUUID(), expectedRevision: profile.revision, name: "Foreign overwrite" } });
    const publication = await page.request.patch(`/api/owner/agents/${agentId}`, { headers, data: { operationId: randomUUID(), expectedRevision: profile.revision, isPublic: true } });
    const pendingCreate = await pending.page.request.post("/api/owner/agents", { headers, data: { operationId: randomUUID(), name: "Forbidden pending card" } });
    const anonymous = await contexts[2].newPage();
    const forgedCredential = await anonymous.request.post("/api/owner/agents", { headers: { ...headers, authorization: `Bearer ${randomBytes(32).toString("hex")}` }, data: { operationId: randomUUID(), name: "Forbidden forged credential" } });
    const replay = await page.request.post("/api/owner/agents", { headers, data: createPayload });
    const replayed = (await replay.json()).agent;
    const conflict = await page.request.post("/api/owner/agents", { headers, data: { ...createPayload, name: "Conflicting duplicate" } });
    const stalePolicy = await page.request.put(`/api/owner/agents/${agentId}/permissions`, { headers,
      data: { operationId: randomUUID(), expectedPolicyRevision: original.policyRevision, permissions: original.permissions } });
    const foreignList = await foreign.page.request.get("/api/owner/agents");
    const foreignListSafe = !(await foreignList.json()).agents.some((row) => row.id === agentId);
    if (foreignRead.status() !== 404 || foreignEdit.status() !== 404 || publication.status() !== 400 || pendingCreate.status() !== 403 || forgedCredential.status() !== 401 || replayed?.id !== agentId || conflict.status() !== 409 || stalePolicy.status() !== 409 || !foreignListSafe) throw new Error("AAP owner/isolation/idempotency negative failed");
    const final = await snapshot(pool, ownerId, agentId, operations);
    const finalCard = final.agents.find((row) => row.id === agentId);
    const finalPolicy = final.policies[0];
    if (finalCard?.name !== profile.name || finalCard?.declared_version !== "v2" || final.operations.length !== 4 || final.audits.length !== 4 || finalPolicy?.policy_revision !== policy.policyRevision || !finalPolicy.training || !finalPolicy.forum_messages || !finalPolicy.ranked || finalPolicy.custom_topics) throw new Error("Independent SQL did not match browser commits");
    return { browserData: { ownerId, agentId, capture: capture.capture, operationIds: operations,
      created: { revision: original.revision, policyRevision: original.policyRevision, permissions: original.permissions, metadataTrust: original.metadataTrust },
      edited: { revision: profile.revision, declaredVersion: profile.declaredVersion }, policy: { policyRevision: policy.policyRevision, permissions: policy.permissions },
      concurrentPolicySave: { statuses: raceStatuses, secondTab: raceCapture.capture },
      protocolNegatives: { boundary: "direct HTTP negatives; forged credential is not a real issued agent credential", foreignReadStatus: foreignRead.status(), foreignEditStatus: foreignEdit.status(), foreignListSafe, forgedPublicationStatus: publication.status(), pendingCreateStatus: pendingCreate.status(), forgedCredentialStatus: forgedCredential.status(), replayStatus: replay.status(), replayAgentId: replayed.id, changedPayloadStatus: conflict.status(), stalePolicyStatus: stalePolicy.status() } },
      databaseData: { observer: final.observer, initial, final } };
  } finally {
    await pool.end();
    await Promise.all(contexts.map((context) => context.close()));
  }
}
