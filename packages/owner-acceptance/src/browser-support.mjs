import { createHash } from "node:crypto";

const EXPECTED_CALLBACK_PATH = "/api/auth/callback/google";

export function attachSafeBrowserCapture(page, scenarioId) {
  const capture = {
    schemaVersion: "oid-browser-observation/v1",
    scenarioId,
    actions: [],
    requests: [],
    responses: [],
    authOperations: [],
    siweChallenges: [],
  };
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (!["127.0.0.1", "localhost"].includes(url.hostname)) return;
    const record = { method: request.method(), path: url.pathname };
    try {
      const body = request.postDataJSON();
      if (body && typeof body.operationId === "string") record.operationId = body.operationId;
      if (body && typeof body.expectedRevision === "number") record.expectedRevision = body.expectedRevision;
      if (body && typeof body.mode === "string") record.mode = body.mode;
    } catch {
      // Request bodies may carry invitation/signature material; never persist them.
    }
    capture.requests.push(record);
  });
  page.on("response", async (response) => {
    const url = new URL(response.url());
    if (!["127.0.0.1", "localhost"].includes(url.hostname)) return;
    const responseRecord = { method: response.request().method(), path: url.pathname, status: response.status() };
    capture.responses.push(responseRecord);
    if (["/api/auth/sign-in/social", "/api/auth/link-social"].includes(url.pathname) && response.ok()) {
      const headerOperation = response.headers()["x-oid-operation-id"];
      if (typeof headerOperation === "string" && /^[A-Za-z0-9_-]{12,128}$/.test(headerOperation)) {
        capture.authOperations.push({ path: url.pathname, operationId: headerOperation });
        return;
      }
      try {
        const body = await response.json();
        const operationId = body?.operationId ?? body?.data?.operationId;
        if (typeof operationId === "string" && /^[A-Za-z0-9_-]{12,128}$/.test(operationId)) {
          capture.authOperations.push({ path: url.pathname, operationId });
        }
      } catch {
        // OAuth URLs and provider payloads are never persisted.
      }
    }
    if (url.pathname === "/api/auth/siwe/nonce" || url.pathname === "/api/owner/links/siwe/nonce") {
      try {
        const body = await response.json();
        if (typeof body?.nonce === "string") {
          capture.siweChallenges.push({
            path: url.pathname,
            nonceSha256: createHash("sha256").update(body.nonce, "utf8").digest("hex"),
            ...(typeof body.operationId === "string" ? { operationId: body.operationId } : {}),
          });
        }
      } catch {
        // Never persist a nonce or a failed response body.
      }
    }
  });
  return {
    capture,
    action: (name, selector) => capture.actions.push({ action: name, selector }),
    providerRoute: async (context, fixtureOrigin, { subject, claimVariant = "valid", stateVariant = "valid", callbackFields = {} }) => {
      const result = { subject, claimVariant, stateVariant, callbackPath: EXPECTED_CALLBACK_PATH, stateCorrelated: false, codeIssued: false };
      await context.route("https://accounts.google.com/o/oauth2/v2/auth**", async (route) => {
        const authorization = new URL(route.request().url());
        const redirectUri = authorization.searchParams.get("redirect_uri") ?? "";
        const state = authorization.searchParams.get("state") ?? "";
        const responseType = authorization.searchParams.get("response_type") ?? "";
        const codeChallenge = authorization.searchParams.get("code_challenge") ?? "";
        const codeChallengeMethod = authorization.searchParams.get("code_challenge_method") ?? "";
        const clientId = authorization.searchParams.get("client_id") ?? "";
        const nonce = authorization.searchParams.get("nonce") ?? undefined;
        const callback = new URL(redirectUri);
        if (callback.pathname !== EXPECTED_CALLBACK_PATH || callback.origin !== "http://127.0.0.1:3000") {
          result.callbackOriginValid = false;
          await route.abort("blockedbyclient");
          return;
        }
        result.callbackOriginValid = true;
        result.stateCorrelated = state.length >= 8 && stateVariant === "valid";
        if (claimVariant === "cancelled") {
          callback.searchParams.set("error", "access_denied");
          callback.searchParams.set("state", state);
          await route.fulfill({ status: 302, headers: { location: callback.toString() } });
          return;
        }
        const registered = await fetch(new URL("/__test__/authorizations", fixtureOrigin), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            clientId,
            redirectUri,
            state,
            responseType,
            codeChallenge,
            codeChallengeMethod,
            nonce,
            subject,
            claimVariant,
          }),
        });
        if (!registered.ok) {
          result.fixtureRegistrationStatus = registered.status;
          await route.abort("failed");
          return;
        }
        const { code } = await registered.json();
        result.codeIssued = typeof code === "string" && code.length >= 32;
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", stateVariant === "wrong" ? `${state}-wrong` : state);
        for (const [field, value] of Object.entries(callbackFields)) callback.searchParams.set(field, String(value));
        result.stateCorrelated = result.stateCorrelated && callback.searchParams.get("state") === state;
        await route.fulfill({ status: 302, headers: { location: callback.toString() } });
      });
      return result;
    },
  };
}

export async function waitForPath(page, paths, timeout = 15000) {
  const accepted = new Set(paths);
  await page.waitForFunction((allowed) => allowed.includes(window.location.pathname), [...accepted], { timeout });
  return new URL(page.url()).pathname;
}

export async function currentOwner(page) {
  const response = await page.request.get("/api/owner");
  if (response.status() === 401) return { status: 401, owner: null };
  const body = await response.json();
  return { status: response.status(), owner: body.owner ?? null };
}
