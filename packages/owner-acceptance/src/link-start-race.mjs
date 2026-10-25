import { attachSafeBrowserCapture, currentOwner, waitForPath } from "./browser-support.mjs";
import { installWalletFixture } from "./wallet-fixture.mjs";

export async function runGoogleLinkStartRace({ adminPage, newContext, observer }) {
  const context = await newContext();
  try {
    const page = await context.newPage();
    const recorder = attachSafeBrowserCapture(page, "OID-SC-006");
    await installWalletFixture(page);
    await page.goto("/sign-in");
    recorder.action("click", "sign-in-wallet");
    await page.getByTestId("sign-in-wallet").click();
    await waitForPath(page, ["/activate"]);
    const ownerId = (await currentOwner(page)).owner?.id;
    if (!ownerId) throw new Error("Link-race wallet owner missing");
    const issued = adminPage.waitForResponse((r) => new URL(r.url()).pathname === "/api/admin/invitations" && r.request().method() === "POST");
    await adminPage.getByTestId("invite-create").click();
    if ((await issued).status() !== 201) throw new Error("Link-race invitation failed");
    const secret = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
    await page.getByTestId("invitation-code").fill(secret);
    recorder.action("click", "activate-owner");
    await page.getByTestId("activate-owner").click();
    await waitForPath(page, ["/account"]);
    const second = await context.newPage();
    const secondRecorder = attachSafeBrowserCapture(second, "OID-SC-006");
    await second.goto("/account");
    await Promise.all([page, second].map((tab) => tab.getByTestId("link-google").waitFor()));
    const before = await observer.snapshot({ ownerIds: [ownerId] });
    // Hold both real browser POSTs until both controls have initiated the action.
    let release;
    const ready = new Promise((resolve) => { release = resolve; });
    let arrivals = 0;
    await context.route("**/api/auth/link-social", async (route) => {
      if (++arrivals === 2) release();
      await ready;
      await route.continue();
    });
    const outcomes = [page, second].map((tab) => tab.waitForResponse((r) => new URL(r.url()).pathname === "/api/auth/link-social"));
    recorder.action("click", "link-google");
    secondRecorder.action("click", "link-google");
    await Promise.all([page, second].map((tab) => tab.getByTestId("link-google").click()));
    const responses = await Promise.all(outcomes);
    const statuses = responses.map((r) => r.status()).sort();
    const rejection = await responses.find((r) => r.status() === 409)?.json();
    const after = await observer.snapshot({ ownerIds: [ownerId] });
    const pending = after.authFlows.filter((row) => row.provider === "google" && row.purpose === "link" && !row.completed_at);
    if (statuses.join(",") !== "200,409" || rejection?.error?.code !== "IDENTITY_LINK_IN_PROGRESS" || pending.length !== 1 || JSON.stringify(before.identities) !== JSON.stringify(after.identities)) throw new Error("Concurrent Google link starts did not preserve one pending flow");
    return { browserData: { ownerId, statuses, rejectionCode: rejection.error.code, first: recorder.capture, second: secondRecorder.capture,
      boundary: "Two actual link-google controls; provider callback intentionally not completed" }, databaseData: { observer: after.observer, before, after } };
  } finally { await context.close(); }
}
