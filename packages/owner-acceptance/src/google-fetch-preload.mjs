const fixtureOrigin = process.env.OID_GOOGLE_FIXTURE_ORIGIN;
if (!fixtureOrigin) throw new Error("OID_GOOGLE_FIXTURE_ORIGIN is required when the local Google transport preload is enabled");

const fixture = new URL(fixtureOrigin);
if (fixture.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(fixture.hostname) || fixture.pathname !== "/" || fixture.search || fixture.hash) {
  throw new Error("OID_GOOGLE_FIXTURE_ORIGIN must be a loopback HTTP origin without a path");
}

const originalFetch = globalThis.fetch.bind(globalThis);
const mappings = new Map([
  ["oauth2.googleapis.com/token", "/token"],
  ["www.googleapis.com/oauth2/v3/certs", "/certs"],
  ["www.googleapis.com/oauth2/v2/userinfo", "/userinfo"],
]);
const googleHosts = new Set(["accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"]);

globalThis.fetch = async (input, init) => {
  const request = input instanceof Request ? new Request(input, init) : new Request(input, init);
  const url = new URL(request.url);
  const hostPath = `${url.hostname}${url.pathname}`;
  const fixturePath = mappings.get(hostPath);

  if (fixturePath) {
    if (hostPath.endsWith("/token") && request.method !== "POST") {
      throw new Error("Local Google token transport only accepts POST");
    }
    if (hostPath.endsWith("/certs") && request.method !== "GET") {
      throw new Error("Local Google JWKS transport only accepts GET");
    }
    if (hostPath.endsWith("/userinfo") && request.method !== "GET") {
      throw new Error("Local Google userinfo transport only accepts GET");
    }
    const target = new URL(fixturePath, fixture);
    target.search = url.search;
    const rewritten = new Request(target, request);
    return originalFetch(rewritten);
  }

  if (googleHosts.has(url.hostname)) {
    throw new Error(`Unmapped Google network request blocked by OID local acceptance: ${url.hostname}${url.pathname}`);
  }
  return originalFetch(request);
};
