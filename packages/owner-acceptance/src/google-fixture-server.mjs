import { createHash, createPublicKey, createSign, generateKeyPairSync, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { isIP } from "node:net";

const SUBJECT_RE = /^oid-[a-z0-9-]{1,72}$/;
const CLAIM_VARIANTS = new Set(["valid", "issuer", "audience", "expired", "bad-signature", "missing-token"]);
const MAX_BODY_BYTES = 32 * 1024;

function json(response, status, payload) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(payload));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("fixture_request_too_large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function parseFormOrJson(request, body) {
  const contentType = String(request.headers["content-type"] ?? "").toLowerCase();
  if (contentType.includes("application/json")) return JSON.parse(body);
  return Object.fromEntries(new URLSearchParams(body));
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function equalSecret(left, right) {
  const a = Buffer.from(String(left ?? ""));
  const b = Buffer.from(String(right ?? ""));
  return a.length === b.length && timingSafeEqual(a, b);
}

function makeJwt(privateKey, keyId, payload) {
  const header = base64url(JSON.stringify({ alg: "RS256", kid: keyId, typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const signingInput = `${header}.${body}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(privateKey).toString("base64url")}`;
}

function clientSecretMatches(expected, actual) {
  return typeof expected === "string" && expected.length >= 32 && equalSecret(expected, actual);
}

export async function startGoogleFixtureServer({
  host = "127.0.0.1",
  port = 8786,
  clientId,
  clientSecret,
  publicOrigin,
} = {}) {
  if (host !== "127.0.0.1" && host !== "localhost") throw new Error("Google fixture must bind to loopback");
  if (!isIP(host) && host !== "localhost") throw new Error("Google fixture host is invalid");
  if (typeof clientId !== "string" || !clientId.startsWith("oid-local-") || !clientId.endsWith(".apps.example.invalid")) {
    throw new Error("A synthetic OID_GOOGLE_CLIENT_ID is required for local acceptance");
  }
  if (typeof clientSecret !== "string" || clientSecret.length < 32) throw new Error("A synthetic Google fixture client secret is required");
  const expectedOrigin = new URL(publicOrigin);
  if (!new Set(["127.0.0.1", "localhost"]).has(expectedOrigin.hostname) || expectedOrigin.protocol !== "http:") {
    throw new Error("OID_PUBLIC_ORIGIN must use loopback HTTP for the local Google fixture");
  }

  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const keyId = `oid-fixture-${randomBytes(8).toString("hex")}`;
  const jwk = publicKey.export({ format: "jwk" });
  const signingKey = privateKey;
  const authorizations = new Map();
  const redeemedCodes = new Set();
  const accessTokens = new Map();
  const events = [];
  const fixturePublicJwk = { ...jwk, kid: keyId, alg: "RS256", use: "sig" };
  const roguePair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rogueKey = roguePair.privateKey;

  const server = createServer(async (request, response) => {
    const remoteAddress = request.socket.remoteAddress;
    if (remoteAddress && !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(remoteAddress)) {
      return json(response, 403, { error: "loopback_only" });
    }
    const url = new URL(request.url ?? "/", `http://${host}`);
    try {
      if (request.method === "GET" && url.pathname === "/health") {
        return json(response, 200, { status: "ready", scope: "local_oidc_fixture" });
      }
      if (request.method === "GET" && url.pathname === "/certs") {
        return json(response, 200, { keys: [fixturePublicJwk], cache: "no-store" });
      }
      if (request.method === "GET" && url.pathname === "/userinfo") {
        const authorization = String(request.headers.authorization ?? "");
        const accessToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
        const claims = accessTokens.get(accessToken);
        if (!claims) return json(response, 401, { error: "invalid_token" });
        return json(response, 200, {
          sub: claims.sub,
          id: claims.sub,
          email: claims.email,
          email_verified: claims.email_verified,
          name: claims.name,
        });
      }
      if (request.method === "POST" && url.pathname === "/__test__/authorizations") {
        const payload = JSON.parse(await readBody(request));
        const subject = payload.subject;
        const variant = payload.claimVariant ?? "valid";
        const redirect = new URL(payload.redirectUri);
        if (
          payload.clientId !== clientId ||
          !SUBJECT_RE.test(subject) ||
          !CLAIM_VARIANTS.has(variant) ||
          redirect.origin !== expectedOrigin.origin ||
          redirect.pathname !== "/api/auth/callback/google" ||
          typeof payload.state !== "string" || payload.state.length < 8 ||
          payload.responseType !== "code" ||
          payload.codeChallengeMethod !== "S256" ||
          typeof payload.codeChallenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(payload.codeChallenge)
        ) {
          return json(response, 400, { error: "invalid_fixture_authorization" });
        }
        const code = randomBytes(32).toString("base64url");
        const claimedEmail = typeof payload.claimedEmail === "string" && /^[a-z0-9._+-]{1,64}@example\\.invalid$/.test(payload.claimedEmail)
          ? payload.claimedEmail
          : `${subject}@example.invalid`;
        authorizations.set(code, {
          clientId,
          redirectUri: redirect.href,
          codeChallenge: payload.codeChallenge,
          state: payload.state,
          nonce: typeof payload.nonce === "string" ? payload.nonce : undefined,
          subject,
          claimedEmail,
          variant,
          expiresAt: Date.now() + 5 * 60_000,
        });
        events.push({ kind: "authorization_code_issued", subject, claimVariant: variant });
        return json(response, 201, { code });
      }
      if (request.method === "POST" && url.pathname === "/token") {
        const payload = parseFormOrJson(request, await readBody(request));
        const code = payload.code;
        const entry = authorizations.get(code);
        if (!entry || redeemedCodes.has(code) || entry.expiresAt < Date.now()) {
          events.push({ kind: "token_exchange_rejected", reason: "code_invalid_or_replayed" });
          return json(response, 400, { error: "invalid_grant" });
        }
        if (
          payload.grant_type !== "authorization_code" ||
          payload.client_id !== clientId ||
          !clientSecretMatches(clientSecret, payload.client_secret) ||
          payload.redirect_uri !== entry.redirectUri ||
          typeof payload.code_verifier !== "string" ||
          base64url(createHash("sha256").update(payload.code_verifier).digest()) !== entry.codeChallenge
        ) {
          redeemedCodes.add(code);
          events.push({ kind: "token_exchange_rejected", reason: "client_or_pkce_mismatch" });
          return json(response, 400, { error: "invalid_grant" });
        }
        redeemedCodes.add(code);
        authorizations.delete(code);
        if (entry.variant === "missing-token") {
          events.push({ kind: "token_exchange_unavailable", subject: entry.subject });
          return json(response, 503, { error: "provider_unavailable" });
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        const claims = {
          iss: entry.variant === "issuer" ? "https://attacker.example.invalid" : "https://accounts.google.com",
          aud: entry.variant === "audience" ? "oid-unexpected-client.apps.example.invalid" : clientId,
          exp: entry.variant === "expired" ? nowSeconds - 60 : nowSeconds + 300,
          iat: entry.variant === "expired" ? nowSeconds - 3600 : nowSeconds,
          sub: entry.subject,
          email: entry.claimedEmail,
          email_verified: true,
          name: `OID local ${entry.subject}`,
          ...(entry.nonce ? { nonce: entry.nonce } : {}),
        };
        const token = makeJwt(entry.variant === "bad-signature" ? rogueKey : signingKey, keyId, claims);
        const accessToken = randomBytes(24).toString("base64url");
        accessTokens.set(accessToken, claims);
        events.push({ kind: "token_exchange_verified_pkce", subject: entry.subject, claimVariant: entry.variant });
        return json(response, 200, { access_token: accessToken, token_type: "Bearer", expires_in: 300, id_token: token });
      }
      return json(response, 404, { error: "not_found" });
    } catch {
      if (!response.headersSent) return json(response, 400, { error: "invalid_fixture_request" });
      response.destroy();
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Google fixture server did not bind to a TCP port");
  return {
    origin: `http://${host}:${address.port}`,
    events: () => events.map((event) => ({ ...event })),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
