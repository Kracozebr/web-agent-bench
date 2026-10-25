import { installWalletFixture } from "./wallet-fixture.mjs";
import { attachSafeBrowserCapture, currentOwner, waitForPath } from "./browser-support.mjs";

const LINK_NONCE_PATH = "/api/owner/links/siwe/nonce";
const LINK_VERIFY_PATH = "/api/owner/links/siwe/verify";
const SIGN_IN_VERIFY_PATH = "/api/auth/siwe/verify";

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function ownerProviders(owner) {
  return [...new Set((owner?.identities ?? []).map((identity) => identity.provider))].sort();
}

function walletAudit(audit, signingRequests = audit.signingRequests) {
  return {
    providerInjected: audit.providerInjected === true,
    signingRequests,
    ...(typeof audit.addressSha256 === "string" ? { addressSha256: audit.addressSha256 } : {}),
    ...(typeof audit.lastMessageSha256 === "string" ? { lastMessageSha256: audit.lastMessageSha256 } : {}),
  };
}

function captureCopy(capture) {
  return structuredClone(capture);
}

async function waitForOwner(page, predicate, description, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  let observed;
  while (Date.now() < deadline) {
    try {
      observed = await currentOwner(page);
      if (predicate(observed)) return observed;
    } catch {
      // Retry transient projection and navigation errors until the bounded deadline.
    }
    await pause(100);
  }
  throw new Error(`The browser did not reach the expected ${description} owner projection`);
}

async function waitForCapture(predicate, description, timeout = 5_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await pause(25);
  }
  throw new Error(`Safe browser capture did not observe ${description}`);
}

function validateLoopbackOrigin(value) {
  const parsed = new URL(value);
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || parsed.port !== "3000" || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("Wallet acceptance is pinned to http://127.0.0.1:3000");
  }
  return parsed.origin;
}

async function isolatedContext(browser, origin) {
  const context = await browser.newContext({ baseURL: origin });
  await context.route("**/*", async (route) => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    return route.abort("blockedbyclient");
  });
  return context;
}

function isResponse(response, pathname, method) {
  const url = new URL(response.url());
  return url.pathname === pathname && response.request().method() === method;
}

async function forwardMatchingMutatedProof(page, wallet) {
  await page.route("**/api/auth/siwe/verify", async (route) => {
    const proof = wallet.proof();
    let body;
    try {
      body = route.request().postDataJSON();
    } catch {
      await route.abort("failed");
      return;
    }
    if (!proof || !body || typeof body !== "object" || Array.isArray(body)) {
      await route.abort("failed");
      return;
    }
    await route.continue({ postData: JSON.stringify({ ...body, message: proof.message, signature: proof.signature }) });
  });
}

export async function linkWalletAndReturn({ context, page, scenarioId, expectedOwnerId }) {
  if (!context || !page || page.context() !== context) throw new Error("A page from the supplied browser context is required");
  if (typeof scenarioId !== "string" || !scenarioId) throw new Error("scenarioId is required");
  if (typeof expectedOwnerId !== "string" || !expectedOwnerId) throw new Error("expectedOwnerId is required");

  const initial = await currentOwner(page);
  if (initial.status !== 200 || initial.owner?.id !== expectedOwnerId || initial.owner?.admissionStatus !== "admitted" || !ownerProviders(initial.owner).includes("google")) {
    throw new Error("Wallet linking requires the expected admitted Google owner session");
  }

  const wallet = await installWalletFixture(page, { chainId: 8453 });
  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForPath(page, ["/account"], 20_000);
  const reloaded = await currentOwner(page);
  if (reloaded.status !== 200 || reloaded.owner?.id !== expectedOwnerId || reloaded.owner?.admissionStatus !== "admitted") {
    throw new Error("Reload did not preserve the admitted owner session required for wallet linking");
  }

  const linkRecorder = attachSafeBrowserCapture(page, scenarioId);
  await page.getByTestId("link-wallet").waitFor({ state: "visible", timeout: 15_000 });
  linkRecorder.action("click", "link-wallet");
  const linkResponsePromise = page.waitForResponse((response) => isResponse(response, LINK_VERIFY_PATH, "POST"), { timeout: 30_000 });
  await page.getByTestId("link-wallet").click();
  const linkResponse = await linkResponsePromise;
  if (linkResponse.status() !== 200) throw new Error("The actual wallet-link UI did not receive a successful server verification");

  const linked = await waitForOwner(page, (result) => result.status === 200 && result.owner?.id === expectedOwnerId && result.owner?.admissionStatus === "admitted" && ownerProviders(result.owner).includes("wallet"), "wallet-linked");
  await page.getByTestId("identity-siwe").getByText("Linked", { exact: true }).waitFor({ state: "visible", timeout: 10_000 });

  const linkChallenge = await waitForCapture(
    () => linkRecorder.capture.siweChallenges.find((item) => item.path === LINK_NONCE_PATH),
    "the wallet-link nonce hash",
  );
  const linkVerifyRequest = linkRecorder.capture.requests.find((item) => item.path === LINK_VERIFY_PATH && item.method === "POST");
  const linkOperationId = linkVerifyRequest?.operationId ?? linkChallenge.operationId;
  if (typeof linkOperationId !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(linkOperationId) || typeof linkChallenge.nonceSha256 !== "string") {
    throw new Error("The wallet-link browser flow did not expose safe operation and nonce-hash correlation");
  }
  if (linkChallenge.operationId && linkChallenge.operationId !== linkOperationId) {
    throw new Error("The wallet-link nonce and verification operation identifiers did not match");
  }

  const linkWalletAudit = walletAudit(wallet.audit);
  linkRecorder.capture.walletAudit = linkWalletAudit;
  const linkCapture = captureCopy(linkRecorder.capture);

  const returnRecorder = attachSafeBrowserCapture(page, scenarioId);
  returnRecorder.action("click", "sign-out");
  const signOutResponsePromise = page.waitForResponse((response) => isResponse(response, "/api/auth/sign-out", "POST"), { timeout: 15_000 });
  await page.getByTestId("sign-out").click();
  const signOutResponse = await signOutResponsePromise;
  if (!signOutResponse.ok()) throw new Error("The server did not confirm browser sign-out before wallet return sign-in");
  await waitForPath(page, ["/sign-in"], 15_000);
  const anonymous = await waitForOwner(page, (result) => result.status === 401, "signed-out");
  if (anonymous.status !== 401) throw new Error("Browser sign-out left an authenticated owner session");

  await page.getByTestId("sign-in-wallet").waitFor({ state: "visible", timeout: 15_000 });
  returnRecorder.action("click", "sign-in-wallet");
  const returnResponsePromise = page.waitForResponse((response) => isResponse(response, SIGN_IN_VERIFY_PATH, "POST"), { timeout: 30_000 });
  await page.getByTestId("sign-in-wallet").click();
  const returnResponse = await returnResponsePromise;
  if (returnResponse.status() !== 200) throw new Error("Wallet return sign-in did not receive successful server verification");
  await waitForPath(page, ["/auth/complete", "/account", "/activate"], 20_000);

  const returned = await waitForOwner(page, (result) => result.status === 200 && result.owner?.admissionStatus === "admitted", "wallet-return");
  await waitForPath(page, ["/account"], 15_000);
  const providers = ownerProviders(returned.owner);
  const returnWalletAudit = walletAudit(wallet.audit);
  returnRecorder.capture.walletAudit = returnWalletAudit;

  return {
    sameOwner: linked.owner.id === returned.owner.id && returned.owner.id === expectedOwnerId && providers.includes("google") && providers.includes("wallet"),
    providers,
    linkOperationId,
    linkNonceHash: linkChallenge.nonceSha256,
    linkCapture,
    returnCapture: captureCopy(returnRecorder.capture),
    walletAudit: {
      providerInjected: returnWalletAudit.providerInjected,
      addressSha256: returnWalletAudit.addressSha256,
      signingRequests: returnWalletAudit.signingRequests,
      linkSigningRequests: linkWalletAudit.signingRequests,
      linkMessageSha256: linkWalletAudit.lastMessageSha256,
      returnSigningRequests: returnWalletAudit.signingRequests - linkWalletAudit.signingRequests,
      returnMessageSha256: returnWalletAudit.lastMessageSha256,
    },
  };
}

export async function runInvalidWalletCases({ browser, publicOrigin, scenarioId }) {
  if (!browser) throw new Error("A Playwright browser is required");
  if (typeof scenarioId !== "string" || !scenarioId) throw new Error("scenarioId is required");
  const origin = validateLoopbackOrigin(publicOrigin);
  const cases = [
    { kind: "invalid_signature", fixture: { chainId: 8453, invalidSignature: true }, expectsVerify: true },
    { kind: "wrong_chain", fixture: { chainId: 8453, messageMutation: "wrong-chain" }, expectsVerify: true },
    { kind: "wrong_domain", fixture: { chainId: 8453, messageMutation: "wrong-domain" }, expectsVerify: true },
    { kind: "wrong_uri", fixture: { chainId: 8453, messageMutation: "wrong-uri" }, expectsVerify: true },
    { kind: "not_yet_valid", fixture: { chainId: 8453, messageMutation: "not-yet-valid" }, expectsVerify: true },
    { kind: "expired", fixture: { chainId: 8453, messageMutation: "expired" }, expectsVerify: true },
    { kind: "unsupported_wallet_profile", fixture: { chainId: 8453 }, noProvider: true, expectsVerify: false },
    { kind: "user_denied", fixture: { chainId: 8453 }, denied: true, expectsVerify: false },
  ];
  const failedFlows = [];

  for (const testCase of cases) {
    const context = await isolatedContext(browser, origin);
    try {
      const page = await context.newPage();
      const wallet = await installWalletFixture(page, testCase.fixture);
      if (testCase.noProvider) await page.addInitScript(() => { delete window.ethereum; });
      const recorder = attachSafeBrowserCapture(page, scenarioId);
      await page.goto(new URL("/sign-in", origin).toString(), { waitUntil: "domcontentloaded" });
      await waitForPath(page, ["/sign-in"], 15_000);
      await page.getByTestId("sign-in-wallet").waitFor({ state: "visible", timeout: 15_000 });
      if (testCase.denied) {
        await page.evaluate(() => {
          const provider = window.ethereum;
          if (!provider || typeof provider.request !== "function") throw new Error("The injected wallet provider is unavailable");
          const originalRequest = provider.request.bind(provider);
          window.__oidDeniedSigningRequests = 0;
          provider.request = async (request) => {
            if (request?.method === "personal_sign") {
              window.__oidDeniedSigningRequests += 1;
              const error = new Error("User rejected the wallet signature request");
              error.code = 4001;
              throw error;
            }
            return originalRequest(request);
          };
        });
      }
      if (testCase.fixture.messageMutation) {
        await forwardMatchingMutatedProof(page, wallet);
      }
      recorder.action("click", "sign-in-wallet");
      const verifyPromise = testCase.expectsVerify
        ? page.waitForResponse((response) => isResponse(response, SIGN_IN_VERIFY_PATH, "POST"), { timeout: 20_000 }).catch(() => null)
        : undefined;
      await page.getByTestId("sign-in-wallet").click();
      if (verifyPromise) {
        const response = await verifyPromise;
        if (!response) {
          console.log(JSON.stringify({ event: "oid_wallet_missing_verify", trial: testCase.kind, responses: recorder.capture.responses }));
          throw new Error("No wallet verification request reached the backend");
        }
        console.log(JSON.stringify({ event: "oid_wallet_negative", trial: testCase.kind, status: response.status() }));
        if (response.status() < 400) {
          const error = new Error("An invalid wallet proof was accepted");
          error.code = `WALLET_ACCEPTED_${testCase.kind.toUpperCase()}`;
          throw error;
        }
      }
      const alert = page.locator(".status-box.status-error");
      await alert.waitFor({ state: "visible", timeout: 20_000 });

      if (testCase.expectsVerify || testCase.denied) {
        await waitForCapture(
          () => recorder.capture.siweChallenges.find((item) => item.path === "/api/auth/siwe/nonce"),
          `${testCase.kind} sign-in nonce hash`,
        );
      }
      const owner = await currentOwner(page);
      const deniedSigningRequests = testCase.denied
        ? await page.evaluate(() => window.__oidDeniedSigningRequests ?? 0)
        : 0;
      const signingRequests = testCase.denied
        ? Math.max(wallet.audit.signingRequests, deniedSigningRequests)
        : wallet.audit.signingRequests;
      const safeAudit = walletAudit(wallet.audit, signingRequests);
      recorder.capture.walletAudit = safeAudit;
      const observed = {
        kind: testCase.kind,
        ownerStatus: owner.status,
        signingRequests,
        nonceCount: recorder.capture.siweChallenges.filter((item) => item.path === "/api/auth/siwe/nonce").length,
        capture: captureCopy(recorder.capture),
      };
      if (testCase.denied && deniedSigningRequests > 0) observed.errorCode = 4001;
      failedFlows.push(observed);
    } finally {
      await context.close();
    }
  }

  return { failedFlows };
}
