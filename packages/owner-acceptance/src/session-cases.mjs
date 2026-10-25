import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { currentOwner, waitForPath } from "./browser-support.mjs";

// AICODE-NOTE: Only expiry setup uses the owner connection. All outcomes are
// independently observed with oid_observer; cookies remain in memory only.
export async function runSessionCases({ adminPage, newContext, login, observer, databaseUrl }) {
  const contexts = [await newContext(), await newContext(), await newContext()];
  const setup = new pg.Pool({ connectionString: databaseUrl, max: 1, application_name: "oid-session-expiry-fixture" });
  try {
    const actor = await login(contexts[0], `oid-session-${randomBytes(8).toString("hex")}`);
    const expired = await login(contexts[1], `oid-expiry-${randomBytes(8).toString("hex")}`);
    const ownerId = actor.owner.owner.id;
    const expiredOwnerId = expired.owner.owner.id;
    if (actor.owner.owner.admissionStatus !== "pending" || expired.owner.owner.admissionStatus !== "pending") throw new Error("Session fixtures must start pending");

    const issued = adminPage.waitForResponse((r) => new URL(r.url()).pathname === "/api/admin/invitations" && r.request().method() === "POST");
    await adminPage.getByTestId("invite-create").click();
    if ((await issued).status() !== 201) throw new Error("Session invitation issuance failed");
    const secret = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
    await actor.page.getByTestId("invitation-code").fill(secret);
    const activated = actor.page.waitForResponse((r) => new URL(r.url()).pathname === "/api/admission/activate");
    actor.captureApi.action("click", "activate-owner");
    await actor.page.getByTestId("activate-owner").click();
    if ((await activated).status() !== 200) throw new Error("Session fixture activation failed");
    await waitForPath(actor.page, ["/account"]);
    const before = await observer.snapshot({ ownerIds: [ownerId] });

    // Protocol negatives are labelled direct HTTP, separate from the UI logout.
    const crossOriginOperation = randomUUID();
    const forgedAdminOperation = randomUUID();
    const crossOrigin = await actor.page.request.post("/api/owner/links/siwe/nonce", {
      headers: { origin: "https://foreign.example.invalid" }, data: { operationId: crossOriginOperation },
    });
    const forgedAdmin = await actor.page.request.post("/api/admin/invitations", {
      headers: { origin: "http://127.0.0.1:3000", "x-owner-id": randomUUID(), "x-admin": "true" },
      data: { operationId: forgedAdminOperation, isAdmin: true, ownerId: randomUUID() },
    });
    if (crossOrigin.status() !== 403 || forgedAdmin.status() !== 403) throw new Error("Owner control authority negative was accepted");
    const denied = await observer.snapshot({ ownerIds: [ownerId], operationIds: [crossOriginOperation, forgedAdminOperation] });
    if (denied.challenges.some((row) => row.operation_id === crossOriginOperation) || denied.invitations.length !== before.invitations.length || denied.admissions.length !== before.admissions.length) throw new Error("Rejected authority created protected effects");

    const cookies = await contexts[0].cookies();
    await contexts[2].addCookies(cookies);
    const replayPage = await contexts[2].newPage();
    if ((await currentOwner(replayPage)).owner?.id !== ownerId) throw new Error("Original session replay control did not authenticate");
    const signout = actor.page.waitForResponse((r) => new URL(r.url()).pathname === "/api/auth/sign-out");
    actor.captureApi.action("click", "sign-out");
    await actor.page.getByTestId("sign-out").click();
    const logoutStatus = (await signout).status();
    await waitForPath(actor.page, ["/sign-in"]);
    const loggedOutStatus = (await currentOwner(actor.page)).status;
    const reusedStatus = (await currentOwner(replayPage)).status;
    const after = await observer.snapshot({ ownerIds: [ownerId] });
    if (logoutStatus !== 200 || loggedOutStatus !== 401 || reusedStatus !== 401 || after.sessions[0].active_session_count !== 0) throw new Error("Logout failed to invalidate the persisted session");
    if (JSON.stringify(before.owners) !== JSON.stringify(after.owners) || JSON.stringify(before.identities) !== JSON.stringify(after.identities) || JSON.stringify(before.admissions) !== JSON.stringify(after.admissions)) throw new Error("Logout changed durable identity or admission");

    const expiryBefore = await observer.snapshot({ ownerIds: [expiredOwnerId] });
    const fixture = await setup.query(`UPDATE oid_auth_session SET expires_at = now() - interval '1 second'
      WHERE user_id = (SELECT auth_user_id FROM oid_owner WHERE id::text = $1 AND admission_status = 'pending')`, [expiredOwnerId]);
    if (fixture.rowCount !== 1) throw new Error("Expiry fixture did not isolate one fresh pending session");
    const expiryPrepared = await observer.snapshot({ ownerIds: [expiredOwnerId] });
    const expiredStatus = (await currentOwner(expired.page)).status;
    const expiredMutation = await expired.page.request.post("/api/admission/activate", {
      headers: { origin: "http://127.0.0.1:3000" }, data: { operationId: randomUUID() },
    });
    const expiryAfter = await observer.snapshot({ ownerIds: [expiredOwnerId] });
    if (expiredStatus !== 401 || expiredMutation.status() !== 401 || expiryPrepared.sessions[0].active_session_count !== 0 || expiryAfter.admissions.length !== 0) throw new Error("Expired session retained owner authority");
    return {
      browserData: { scenarioId: "OID-SC-008", ownerId, expiredOwnerId, capture: actor.capture,
        protocolNegatives: { boundary: "direct HTTP using actual browser session", crossOriginOperation, forgedAdminOperation, crossOriginStatus: crossOrigin.status(), forgedAdminStatus: forgedAdmin.status() },
        logoutStatus, loggedOutStatus, reusedStatus, expiredStatus, expiredMutationStatus: expiredMutation.status(),
        expirySetup: { boundary: "private database fixture, not product action", changedFreshPendingSessions: fixture.rowCount } },
      databaseData: { observer: after.observer, before, denied, after, expiryBefore, expiryPrepared, expiryAfter },
    };
  } finally {
    await setup.end();
    await Promise.all(contexts.map((context) => context.close()));
  }
}
