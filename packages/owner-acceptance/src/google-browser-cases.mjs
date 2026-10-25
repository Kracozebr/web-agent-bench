import { randomBytes, createHash } from "node:crypto";
import { attachSafeBrowserCapture, currentOwner } from "./browser-support.mjs";

// The business action is always a browser click. Only the isolated provider's
// authorization transport or an adversarial browser cookie is changed here.
export async function runGoogleBrowserFailures({ browser, fixtureOrigin, publicOrigin, scenarioId }) {
  const results = [];
  for (const kind of ["provider_denied", "abandoned_login", "browser_session_substitution"]) {
    const context = await browser.newContext({ baseURL: publicOrigin });
    try {
      await context.route("**/*", (route) => new URL(route.request().url()).origin === publicOrigin
        ? route.continue() : route.abort("blockedbyclient"));
      const page = await context.newPage();
      const recorder = attachSafeBrowserCapture(page, scenarioId);
      if (kind === "provider_denied") {
        await recorder.providerRoute(context, fixtureOrigin, {
          subject: `oid-denied-${randomBytes(6).toString("hex")}`, claimVariant: "cancelled",
        });
      } else {
        await context.route("https://accounts.google.com/o/oauth2/v2/auth**", async (route) => {
          if (kind === "abandoned_login") return route.abort("aborted");
          const authorization = new URL(route.request().url());
          const callback = new URL(authorization.searchParams.get("redirect_uri"));
          callback.searchParams.set("state", authorization.searchParams.get("state"));
          callback.searchParams.set("error", "access_denied");
          // Lose only the private browser-flow binding, retaining the provider
          // state cookie. The real backend must reject before provider handling.
          await context.clearCookies({ name: "oid_auth_flow" });
          return route.fulfill({ status: 302, headers: { location: callback.toString() } });
        });
      }
      await page.goto("/sign-in");
      const initial = await currentOwner(page);
      if (initial.status !== 401) throw new Error("Negative login fixture was not anonymous");
      recorder.action("click", "sign-in-google");
      const finalResponse = kind === "abandoned_login"
        ? page.waitForEvent("requestfailed", { predicate: (request) => new URL(request.url()).hostname === "accounts.google.com", timeout: 15000 })
        : page.waitForResponse((response) => new URL(response.url()).pathname === "/api/auth/callback/google", { timeout: 15000 });
      await page.getByTestId("sign-in-google").click();
      const completed = await finalResponse;
      const owner = await currentOwner(page);
      if (owner.status !== 401) throw new Error("A failed Google flow created authenticated owner authority");
      results.push({
        kind, ownerStatus: owner.status,
        ...(kind !== "abandoned_login" ? { callbackStatus: completed.status() } : { navigationAbandoned: true }),
        capture: structuredClone(recorder.capture),
      });
    } finally {
      await context.close();
    }
  }
  return results;
}

export async function runGoogleClaimMatrix({ browser, fixtureOrigin, publicOrigin }) {
  const trials = [];
  const subjects = [];
  const operations = [];
  const variants = [
    ["valid", "valid", "valid"], ["wrong_state", "valid", "wrong"],
    ["wrong_issuer", "issuer", "valid"], ["wrong_audience", "audience", "valid"],
    ["expired_token", "expired", "valid"], ["provider_response_missing", "missing-token", "valid"],
  ];
  for (const [name, claimVariant, stateVariant] of variants) {
    const context = await browser.newContext({ baseURL: publicOrigin });
    try {
      await context.route("**/*", (route) => new URL(route.request().url()).origin === publicOrigin ? route.continue() : route.abort("blockedbyclient"));
      const page = await context.newPage();
      const recorder = attachSafeBrowserCapture(page, "OID-SC-001");
      const subject = `oid-claims-${randomBytes(8).toString("hex")}`;
      subjects.push(subject);
      const routeResult = await recorder.providerRoute(context, fixtureOrigin, { subject, claimVariant, stateVariant });
      await page.goto("/sign-in");
      recorder.action("click", "sign-in-google");
      const callback = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/auth/callback/google");
      await page.getByTestId("sign-in-google").click();
      const callbackStatus = (await callback).status();
      const owner = await currentOwner(page);
      console.log(JSON.stringify({ event: "oid_google_claim", trial: name, callbackStatus, ownerStatus: owner.status }));
      if ((name === "valid" && owner.status !== 200) || (name !== "valid" && owner.status !== 401)) {
        const error = new Error("A Google claim crossed the wrong authentication boundary");
        error.code = `GOOGLE_BOUNDARY_${name.toUpperCase()}`;
        throw error;
      }
      const deadline = Date.now() + 5000;
      while (!recorder.capture.authOperations.length && Date.now() < deadline) await new Promise((done) => setTimeout(done, 25));
      const operationId = recorder.capture.authOperations[0]?.operationId;
      if (!operationId) throw new Error("Google trial lacks durable operation correlation");
      operations.push(operationId);
      trials.push({ name, operationId, callbackStatus, ownerStatus: owner.status,
        ...(owner.owner ? { ownerId: owner.owner.id } : {}),
        subjectSha256: createHash("sha256").update(subject).digest("hex"),
        stateCorrelated: routeResult.stateCorrelated, capture: recorder.capture });
    } finally { await context.close(); }
  }
  const context = await browser.newContext({ baseURL: publicOrigin });
  let callerEmailEndpoint;
  try {
    const page = await context.newPage();
    // This is explicitly an HTTP-negative probe, alongside browser-initiated
    // provider operations; no fictitious email login control is added to the UI.
    const response = await page.request.post("/api/auth/sign-in/email", {
      headers: { origin: publicOrigin }, data: { email: "unverified@example.invalid", password: "not-a-real-credential" },
    });
    const owner = await currentOwner(page);
    callerEmailEndpoint = { boundary: "direct_http_negative", path: "/api/auth/sign-in/email", status: response.status(), rejected: response.status() >= 400, ownerStatus: owner.status };
    if (!callerEmailEndpoint.rejected || owner.status !== 401) throw new Error("Unverified caller email established authority");
  } finally { await context.close(); }
  return { trials, subjects, operations, callerEmailEndpoint };
}
