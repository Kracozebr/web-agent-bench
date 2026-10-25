import { randomBytes } from "node:crypto";
import { currentOwner, waitForPath } from "./browser-support.mjs";

export async function runAdmissionRace({ adminPage, newContext, login, observer, restartApi }) {
  const issueResponse = adminPage.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/invitations" && response.request().method() === "POST");
  await adminPage.getByTestId("invite-create").click();
  if ((await issueResponse).status() !== 201) throw new Error("Race invitation was not issued through UI");
  const block = adminPage.getByTestId("invite-secret-once");
  await block.waitFor();
  const value = (await block.locator("code").first().innerText()).trim();
  const invitationId = /\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/i.exec(await block.innerText())?.[0];
  if (!invitationId) throw new Error("Race fixture has no invitation reference");
  const contexts = [await newContext(), await newContext()];
  try {
    const actors = await Promise.all(contexts.map((context) => login(context, `oid-race-${randomBytes(7).toString("hex")}`)));
    const status = [];
    for (const [index, actor] of actors.entries()) {
      if (actor.owner.owner?.admissionStatus !== "pending") throw new Error("Race actor was not pending");
      await actor.page.getByTestId("invitation-code").fill(value);
      await actor.page.route("**/api/admission/activate", async (route) => {
        const response = await route.fetch();
        status[index] = response.status();
        // Drop the winning response after the actual backend commit. No
        // successful domain response is substituted for an unexecuted action.
        if (response.status() === 200) await route.abort("failed");
        else await route.fulfill({ response });
      });
    }
    await Promise.all(actors.map(async (actor) => {
      actor.captureApi.action("click", "activate-owner");
      await actor.page.getByTestId("activate-owner").click();
      await actor.page.locator(".status-box.status-error").waitFor();
    }));
    if (status.filter((code) => code === 200).length !== 1 || status.filter((code) => code >= 400).length !== 1) throw new Error("Invitation race did not have exactly one winner");
    const winnerIndex = status.indexOf(200);
    const winner = actors[winnerIndex];
    const winnerId = winner.owner.owner.id;
    const loserId = actors[1 - winnerIndex].owner.owner.id;
    const operationId = winner.capture.requests.find((row) => row.path === "/api/admission/activate")?.operationId;
    const before = await observer.snapshot({ ownerIds: [winnerId, loserId], invitationIds: [invitationId], operationIds: [operationId] });
    if (before.redemptions.length !== 1 || before.redemptions[0].owner_id !== winnerId) throw new Error("Race committed duplicate or foreign redemption");
    await restartApi();
    await winner.page.unroute("**/api/admission/activate");
    const retry = winner.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admission/activate");
    winner.captureApi.action("click", "activate-owner");
    await winner.page.getByTestId("activate-owner").click();
    const retryStatus = (await retry).status();
    await waitForPath(winner.page, ["/account"]);
    const confirmed = await currentOwner(winner.page);
    const after = await observer.snapshot({ ownerIds: [winnerId, loserId], invitationIds: [invitationId], operationIds: [operationId] });
    const sameOperation = winner.capture.requests.filter((row) => row.path === "/api/admission/activate").every((row) => row.operationId === operationId);
    if (retryStatus !== 200 || !sameOperation || confirmed.owner?.id !== winnerId || after.redemptions.length !== 1 || after.admissions.filter((row) => row.invitation_id === invitationId).length !== 1) throw new Error("Lost-response retry did not recover one original admission");
    if (after.owners.find((row) => row.id === loserId)?.admission_status !== "pending") throw new Error("The competing identity was admitted");
    return { browserData: { invitationId, winnerId, loserId, operationId, initialStatuses: status, retryStatus, sameOperation,
      backendRestarted: true, winner: winner.capture, loser: actors[1 - winnerIndex].capture }, databaseData: after };
  } finally { await Promise.all(contexts.map((context) => context.close())); }
}
