import { createHash, randomUUID } from "node:crypto";
import { createSiweMessage } from "viem/siwe";
import { installWalletFixture } from "./wallet-fixture.mjs";
import { attachSafeBrowserCapture, currentOwner, waitForPath } from "./browser-support.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

export async function runFreshSiweProtocol({ browser, publicOrigin, admittedPage, failures }) {
  const context = await browser.newContext({ baseURL: publicOrigin });
  const foreignContext = await browser.newContext({ baseURL: publicOrigin });
  try {
    const page = await context.newPage();
    const recorder = attachSafeBrowserCapture(page, "OID-SC-002");
    const wallet = await installWalletFixture(page);
    await page.route("**/api/auth/siwe/verify", async (route) => {
      const body = route.request().postDataJSON();
      await route.continue({ postData: JSON.stringify({ ...body, email: "oid-admin-fixture-sub@example.invalid" }) });
    });
    await page.goto("/sign-in");
    recorder.action("click", "sign-in-wallet");
    const verified = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/auth/siwe/verify");
    await page.getByTestId("sign-in-wallet").click();
    if ((await verified).status() !== 200) throw new Error("Fresh EOA sign-in was rejected");
    await waitForPath(page, ["/activate"]);
    const owner = await currentOwner(page);
    if (owner.status !== 200 || owner.owner?.isAdmin || owner.owner?.identities.some((row) => row.provider === "google")) {
      throw new Error("A caller-supplied wallet email established foreign provider authority");
    }
    const proof = wallet.proof();
    if (!proof) throw new Error("The private wallet fixture did not retain its last proof");
    // These are declared HTTP/crypto adversarial probes alongside the real UI
    // sign-in; replay never re-executes them and proof contents stay in memory.
    const replay = await page.request.post("/api/auth/siwe/verify", { headers: { origin: publicOrigin }, data: proof });
    if (replay.status() < 400) throw new Error("A consumed sign-in proof was accepted again");

    const issued = await admittedPage.request.post("/api/auth/siwe/nonce", { headers: { origin: publicOrigin }, data: {} });
    const nonce = await issued.json();
    if (issued.status() !== 200 || !nonce.nonce) throw new Error("A purpose-binding challenge could not be created");
    const message = createSiweMessage({
      address: wallet.account.address, chainId: 8453, domain: new URL(publicOrigin).host,
      uri: publicOrigin, nonce: nonce.nonce, version: "1", statement: "Sign in to Web3 Agent Bench",
      issuedAt: new Date(), expirationTime: new Date(Date.now() + 900000),
    });
    const signature = await wallet.account.signMessage({ message });
    const crossPurpose = await admittedPage.request.post("/api/owner/links/siwe/verify", {
      headers: { origin: publicOrigin }, data: { operationId: randomUUID(), message, signature },
    });
    const foreignPage = await foreignContext.newPage();
    const crossBrowser = await foreignPage.request.post("/api/auth/siwe/verify", {
      headers: { origin: publicOrigin }, data: { message, signature },
    });
    if (crossPurpose.status() < 400 || crossBrowser.status() < 400) throw new Error("A proof escaped its purpose/browser binding");
    const validNonce = recorder.capture.siweChallenges.find((row) => row.path === "/api/auth/siwe/nonce");
    if (!validNonce?.operationId) throw new Error("Valid sign-in lacks a challenge operation ID");
    return {
      ownerId: owner.owner.id,
      subjectHashes: [wallet.audit.addressSha256, ...failures.map((row) => row.capture.walletAudit?.addressSha256).filter(Boolean)],
      nonceHashes: [validNonce.nonceSha256, hash(nonce.nonce), ...failures.flatMap((row) => row.capture.siweChallenges.map((challenge) => challenge.nonceSha256))],
      operations: [validNonce.operationId, nonce.operationId].filter(Boolean),
      browserData: {
        outcomes: [{ trial: "valid", ownerStatus: owner.status, ownerId: owner.owner.id,
          addressSha256: wallet.audit.addressSha256, signingRequests: wallet.audit.signingRequests, callerEmailSupplied: true,
          capture: structuredClone(recorder.capture) },
          ...failures.map((row) => ({ ...row, trial: row.kind === "invalid_signature" ? "wrong_signature" : row.kind }))],
        siweChallenges: recorder.capture.siweChallenges,
        replayStatus: replay.status(), crossPurposeStatus: crossPurpose.status(), crossBrowserStatus: crossBrowser.status(),
        purposeNonceHash: hash(nonce.nonce), purposeOperationId: nonce.operationId,
        directProbesBoundary: "HTTP/crypto negative probes; positive business action starts at actual sign-in-wallet control",
      },
    };
  } finally {
    await context.close();
    await foreignContext.close();
  }
}
