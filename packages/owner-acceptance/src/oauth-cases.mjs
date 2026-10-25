import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import pg from "pg";
import { auth as sdkOAuth, Client, IssuerMismatchError, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { attachSafeBrowserCapture, waitForPath } from "./browser-support.mjs";

const DEFAULT_CLIENT_ID = "oid-local-mcp-client";
const DEFAULT_CALLBACK_URL = "http://127.0.0.1:38765/oauth/callback";
const DEFAULT_RESOURCE = "http://127.0.0.1:3000/api/agent";
const MCP_SCOPE = "agent:operate";
const SAFE_OAUTH_ERROR_CODES = new Set([
  "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type",
  "invalid_scope", "server_error", "temporarily_unavailable",
]);
const CONSENT_TEST_IDS = Object.freeze({
  context: "oauth-consent-context",
  agent: "oauth-consent-agent-select",
  continue: "oauth-agent-continue",
  approve: "oauth-consent-approve",
  deny: "oauth-consent-deny",
});
const PERMISSION_TEST_IDS = Object.freeze({
  training: "oauth-consent-permission-training",
  ranked: "oauth-consent-permission-ranked",
  forumMessages: "oauth-consent-permission-forum-messages",
  customTopics: "oauth-consent-permission-custom-topics",
});

function loopbackHttpUrl(value, label) {
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error(`${label} must be a loopback HTTP URL`);
  }
  if (url.username || url.password || url.search || url.hash) throw new Error(`${label} must not contain credentials or query data`);
  return url;
}

function safePath(url) {
  return `${url.origin}${url.pathname}`;
}

function safeExceptionName(error) {
  return error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(error.name) ? error.name : "Error";
}

function safePositiveOAuthDiagnostic(flow) {
  const browser = flow?.browserData ?? {};
  const consent = browser.consent ?? {};
  const callback = browser.callback ?? {};
  const sdk = browser.sdkAuthorization ?? {};
  const discovery = sdk.discovery ?? {};
  const request = sdk.request ?? {};
  const exchange = browser.exchange ?? {};
  const safeResult = new Set(["success", "rejected", "denied", "no_code", "state_mismatch", "not_attempted"]);
  return {
    consent: {
      continueStatus: Number.isInteger(consent.continueStatus) ? consent.continueStatus : null,
      contextStatus: Number.isInteger(consent.contextStatus) ? consent.contextStatus : null,
      decisionStatus: Number.isInteger(consent.decisionStatus) ? consent.decisionStatus : null,
      scopesDisplayed: consent.scopesDisplayed === true,
    },
    callback: {
      stateMatches: callback.stateMatches === true,
      codePresent: callback.codePresent === true,
      issuerMatches: callback.issuerMatches === true,
      errorPresent: callback.errorPresent === true,
    },
    discovery: Object.fromEntries(["issuerPresent", "issuerLoopback", "tokenEndpointPresent", "tokenEndpointLoopback",
      "authorizationResponseIssuerSupported", "resourceMetadataPresent", "resourceMetadataPathMatchesChallenge",
      "resourceMatchesPinned", "clientIdPinned"].map((key) => [key, discovery[key] === true])),
    issuerBinding: {
      issuerPresent: sdk.issuerBinding?.issuerPresent === true,
      clientInformationIssuerBound: sdk.issuerBinding?.clientInformationIssuerBound === true,
      tokenIssuerBound: sdk.issuerBinding?.tokenIssuerBound === true,
    },
    authorizationRequest: Object.fromEntries(["clientIdMatches", "redirectUriMatches", "responseTypeCode",
      "codeChallengePresent", "codeChallengeMethodS256", "statePresent", "resourceMatches",
      "expectedScopeRequested", "extraScopeRequested"].map((key) => [key, request[key] === true])),
    requestedScopeCount: Number.isInteger(request.requestedScopeCount) ? request.requestedScopeCount : null,
    exchange: {
      result: safeResult.has(exchange.result) ? exchange.result : "other",
      errorName: typeof exchange.errorName === "string" && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(exchange.errorName)
        ? exchange.errorName : null,
      issuerMismatch: exchange.issuerMismatch === true,
      tokenEndpointStatus: Number.isInteger(exchange.tokenEndpointStatus) ? exchange.tokenEndpointStatus : null,
      tokenPresent: exchange.tokenPresent === true,
      tokenRequests: Array.isArray(exchange.tokenRequests) ? exchange.tokenRequests.map((row) => ({
        status: Number.isInteger(row?.status) ? row.status : null,
        clientIdMatches: row?.clientIdMatches === true,
        redirectUriMatches: row?.redirectUriMatches === true,
        resourceMatches: row?.resourceMatches === true,
        codePresent: row?.codePresent === true,
        pkceVerifierPresent: row?.pkceVerifierPresent === true,
        accessTokenPresent: row?.accessTokenPresent === true,
        refreshTokenPresent: row?.refreshTokenPresent === true,
        mutation: ["none", "wrong_redirect", "wrong_resource", "wrong_pkce"].includes(row?.mutation) ? row.mutation : "other",
      })) : [],
    },
  };
}

function challengedResourceMetadataUrl(response, { publicOrigin, resource }) {
  const header = response.headers.get("www-authenticate") ?? "";
  const match = header.match(/(?:^|,\s*|Bearer\s+)resource_metadata\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))/i);
  const raw = match?.[1]?.replace(/\\(["\\])/g, "$1") ?? match?.[2];
  if (!raw) throw new Error("The MCP bearer challenge omitted resource metadata discovery");
  const metadataUrl = new URL(raw);
  const origin = loopbackHttpUrl(publicOrigin, "AAP public origin");
  const expectedResource = loopbackHttpUrl(resource, "AAP resource identifier");
  const expectedMetadataUrl = new URL("/.well-known/oauth-protected-resource/api/agent", origin);
  if (metadataUrl.origin !== origin.origin || metadataUrl.pathname !== expectedMetadataUrl.pathname
    || metadataUrl.search || metadataUrl.hash || metadataUrl.username || metadataUrl.password
    || expectedResource.origin !== origin.origin) {
    throw new Error("The MCP bearer challenge advertised an unexpected protected-resource metadata URL");
  }
  return metadataUrl;
}

async function probeMcpAuthorizationChallenge({ serverUrl, publicOrigin, resource, fetchFn = globalThis.fetch }) {
  const endpoint = loopbackHttpUrl(serverUrl, "MCP server URL");
  const response = await fetchFn(endpoint, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2026-07-28", capabilities: {}, clientInfo: {
        name: "Web3 Agent Bench local OAuth acceptance client", version: "1.0.0",
      },
    } }),
  });
  const resourceMetadataUrl = challengedResourceMetadataUrl(response, { publicOrigin, resource });
  const evidence = {
    method: "unauthenticated MCP initialize POST",
    status: response.status,
    challengePresent: Boolean(response.headers.get("www-authenticate")),
    resourceMetadataPath: resourceMetadataUrl.pathname,
    resourceMetadataOriginMatches: resourceMetadataUrl.origin === new URL(publicOrigin).origin,
    expectedResource: resource,
    protocolVersion: "2026-07-28",
  };
  await response.body?.cancel().catch(() => undefined);
  if (response.status !== 401 || !evidence.challengePresent || !evidence.resourceMetadataOriginMatches) {
    throw new Error("The actual MCP authorization challenge did not match the pinned local profile");
  }
  return { resourceMetadataUrl, evidence };
}

async function startOAuthCallbackReceiver(callbackUrl = DEFAULT_CALLBACK_URL) {
  const callback = loopbackHttpUrl(callbackUrl, "OAuth callback URL");
  const queue = [];
  const waiters = [];
  const server = createServer((request, response) => {
    let incoming;
    try { incoming = new URL(request.url ?? "/", callback.origin); }
    catch {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("Authorization response rejected.");
      return;
    }
    if (request.method !== "GET" || incoming.pathname !== callback.pathname) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      response.end("Not found.");
      return;
    }
    const callbackData = {
      code: incoming.searchParams.get("code") ?? undefined,
      state: incoming.searchParams.get("state") ?? undefined,
      issuer: incoming.searchParams.get("iss") ?? undefined,
      errorPresent: incoming.searchParams.has("error"),
      errorCode: incoming.searchParams.has("error")
        ? (SAFE_OAUTH_ERROR_CODES.has(incoming.searchParams.get("error")) ? incoming.searchParams.get("error") : "other")
        : null,
    };
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(callbackData);
    else queue.push(callbackData);
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" });
    response.end("<!doctype html><title>Authorization response received</title><p>Return to the acceptance run.</p>");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(callback.port), callback.hostname.replace(/^\[|\]$/g, ""), () => {
      server.off("error", reject);
      resolve();
    });
  });
  return {
    waitForCallback(timeoutMs = 15000) {
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        const waiter = { resolve: (value) => { clearTimeout(timer); resolve(value); } };
        const timer = setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) waiters.splice(index, 1);
          reject(new Error("The local OAuth callback did not arrive"));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    async close() {
      for (const value of queue) {
        value.code = undefined;
        value.state = undefined;
        value.issuer = undefined;
      }
      queue.length = 0;
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}

function makeOAuthProvider({
  clientId = DEFAULT_CLIENT_ID,
  callbackUrl = DEFAULT_CALLBACK_URL,
  resource = DEFAULT_RESOURCE,
  resourceMetadataUrl,
  clientName = "Web3 Agent Bench local acceptance client",
} = {}) {
  if (!/^[A-Za-z0-9._-]{3,128}$/.test(clientId)) throw new Error("The pinned OAuth client ID is invalid");
  const redirectUrl = loopbackHttpUrl(callbackUrl, "OAuth callback URL");
  const expectedResource = loopbackHttpUrl(resource, "OAuth resource identifier");
  const protectedResourceMetadataUrl = loopbackHttpUrl(resourceMetadataUrl, "OAuth resource metadata URL");
  if (protectedResourceMetadataUrl.origin !== expectedResource.origin
    || protectedResourceMetadataUrl.pathname !== "/.well-known/oauth-protected-resource/api/agent") {
    throw new Error("The OAuth resource metadata URL does not match the pinned local profile");
  }
  const state = {
    expectedState: undefined,
    codeVerifier: undefined,
    tokens: undefined,
    discovery: undefined,
    authorizationUrl: undefined,
    savedClientId: undefined,
    clientInformation: undefined,
  };

  const provider = {
    redirectUrl: redirectUrl.href,
    clientMetadata: {
      client_name: clientName,
      redirect_uris: [redirectUrl.href],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      application_type: "native",
    },
    clientInformation(context) {
      const issuer = context?.issuer ?? state.discovery?.authorizationServerMetadata?.issuer;
      if (state.clientInformation?.issuer && issuer && state.clientInformation.issuer !== issuer) return undefined;
      if (state.clientInformation) return state.clientInformation;
      return {
        client_id: clientId,
        redirect_uris: [redirectUrl.href],
        token_endpoint_auth_method: "none",
        ...(issuer ? { issuer } : {}),
      };
    },
    saveClientInformation(information, context) {
      const issuer = context?.issuer ?? state.discovery?.authorizationServerMetadata?.issuer;
      if (information?.client_id !== clientId || (context?.issuer && issuer && context.issuer !== issuer)) {
        throw new Error("The OAuth provider attempted to replace the pinned public client");
      }
      state.clientInformation = issuer && information.issuer !== issuer ? { ...information, issuer } : information;
      state.savedClientId = information.client_id;
    },
    tokens(context) {
      const issuer = context?.issuer ?? state.discovery?.authorizationServerMetadata?.issuer;
      if (state.tokens?.issuer && issuer && state.tokens.issuer !== issuer) return undefined;
      if (state.tokens && issuer && state.tokens.issuer !== issuer) state.tokens = { ...state.tokens, issuer };
      return state.tokens;
    },
    saveTokens(tokens, context) {
      const issuer = context?.issuer ?? state.discovery?.authorizationServerMetadata?.issuer;
      state.tokens = issuer && tokens?.issuer !== issuer ? { ...tokens, issuer } : tokens;
    },
    state() {
      state.expectedState = randomBytes(32).toString("base64url");
      return state.expectedState;
    },
    saveDiscoveryState(discovery) { state.discovery = discovery; },
    discoveryState() { return state.discovery; },
    redirectToAuthorization(url) { state.authorizationUrl = new URL(url); },
    saveCodeVerifier(value) { state.codeVerifier = value; },
    codeVerifier() {
      if (!state.codeVerifier) throw new Error("The MCP SDK did not retain the PKCE verifier for this flow");
      return state.codeVerifier;
    },
    validateResourceURL(serverUrl, discoveredResource) {
      const server = loopbackHttpUrl(String(serverUrl), "MCP server URL");
      if (server.origin !== expectedResource.origin) throw new Error("The discovered resource belongs to another local origin");
      if (discoveredResource && new URL(discoveredResource).href !== expectedResource.href) {
        throw new Error("The discovered protected resource does not match the pinned AAP resource");
      }
      return new URL(expectedResource.href);
    },
  };

  const session = {
    provider,
    clientId,
    callbackUrl: redirectUrl.href,
    resource: expectedResource.href,
    resourceMetadataUrl: new URL(protectedResourceMetadataUrl.href),
    getAuthorizationUrl: () => state.authorizationUrl ? new URL(state.authorizationUrl.href) : undefined,
    getTokenEndpoint: () => state.discovery?.authorizationServerMetadata?.token_endpoint,
    hasCodeVerifier: () => typeof state.codeVerifier === "string" && state.codeVerifier.length > 0,
    hasTokens: () => typeof state.tokens?.access_token === "string" && state.tokens.access_token.length > 0,
    tokenScope: () => typeof state.tokens?.scope === "string" ? state.tokens.scope : undefined,
    authorizationRequestSummary: (expectedScope = MCP_SCOPE) => {
      if (!state.authorizationUrl) return null;
      const params = state.authorizationUrl.searchParams;
      const requestedScopes = (params.get("scope") ?? "").split(/\s+/).filter(Boolean);
      return {
        clientIdMatches: params.get("client_id") === clientId,
        redirectUriMatches: params.get("redirect_uri") === redirectUrl.href,
        responseTypeCode: params.get("response_type") === "code",
        codeChallengePresent: typeof params.get("code_challenge") === "string" && params.get("code_challenge").length > 0,
        codeChallengeMethodS256: params.get("code_challenge_method") === "S256",
        statePresent: typeof params.get("state") === "string" && params.get("state").length > 0,
        resourceMatches: params.get("resource") === expectedResource.href,
        expectedScopeRequested: requestedScopes.includes(expectedScope),
        requestedScopeCount: requestedScopes.length,
        extraScopeRequested: requestedScopes.some((value) => value !== expectedScope),
      };
    },
    useAccessToken: async (callback) => {
      if (typeof state.tokens?.access_token !== "string" || !state.tokens.access_token) throw new Error("The MCP SDK did not retain the issued access credential");
      return callback(state.tokens.access_token);
    },
    callbackStateMatches: (candidate) => typeof state.expectedState === "string" && candidate === state.expectedState,
    setCallbackData: (callbackData) => { state.callbackData = callbackData; },
    codeFingerprint: () => {
      const code = state.callbackData?.code;
      if (typeof code !== "string" || !code) throw new Error("The OAuth authorization code is not available in process memory");
      return createHash("sha256").update(code, "utf8").digest("base64url");
    },
    replayAuthorizationCode: async ({ serverUrl, fetchFn = globalThis.fetch } = {}) => {
      const existingTokens = state.tokens;
      state.tokens = undefined;
      try {
        const data = state.callbackData ?? {};
        const params = new URLSearchParams();
        if (data.code) params.set("code", data.code);
        if (data.state) params.set("state", data.state);
        if (data.issuer) params.set("iss", data.issuer);
        return await finishSdkAuthorization(session, { serverUrl, callbackParams: params, fetchFn });
      } finally {
        state.tokens = existingTokens;
      }
    },
    clearTokens: () => { state.tokens = undefined; },
    clearSensitive: () => {
      state.expectedState = undefined;
      state.codeVerifier = undefined;
      state.tokens = undefined;
      state.callbackData = undefined;
      state.authorizationUrl = undefined;
      state.discovery = undefined;
      state.savedClientId = undefined;
      state.clientInformation = undefined;
    },
    finish: async ({ serverUrl, fetchFn = globalThis.fetch, issuerOverride, mutation = "none", stateTamper = false } = {}) => {
      const data = state.callbackData ?? {};
      const params = new URLSearchParams();
      if (data.code) params.set("code", data.code);
      if (data.state) params.set("state", stateTamper ? `${data.state}-tampered` : data.state);
      if (data.issuer) params.set("iss", data.issuer);
      if (!session.callbackStateMatches(params.get("state"))) {
        return { result: "state_mismatch", codePresent: Boolean(data.code), tokenEndpointStatus: null,
          tokenPresent: false, errorName: null, issuerMismatch: false, tokenRequests: [] };
      }
      return finishSdkAuthorization(session, { serverUrl, callbackParams: params, fetchFn, issuerOverride, mutation });
    },
    discoverySummary: () => {
      const authorization = state.discovery?.authorizationServerMetadata;
      const protectedResource = state.discovery?.resourceMetadata;
      const tokenEndpoint = typeof authorization?.token_endpoint === "string" ? new URL(authorization.token_endpoint) : undefined;
      const issuer = typeof authorization?.issuer === "string" ? authorization.issuer : undefined;
      return {
        issuerPresent: Boolean(issuer),
        issuerLoopback: Boolean(issuer && ["127.0.0.1", "localhost"].includes(new URL(issuer).hostname)),
        tokenEndpointPresent: Boolean(tokenEndpoint),
        tokenEndpointLoopback: Boolean(tokenEndpoint && ["127.0.0.1", "localhost"].includes(tokenEndpoint.hostname)),
        authorizationResponseIssuerSupported: authorization?.authorization_response_iss_parameter_supported === true,
        resourceMetadataPresent: Boolean(protectedResource),
        resourceMetadataPathMatchesChallenge: state.discovery?.resourceMetadataUrl?.href === protectedResourceMetadataUrl.href
          || state.discovery?.resourceMetadataUrl === protectedResourceMetadataUrl.href,
        resourceMatchesPinned: protectedResource?.resource === expectedResource.href,
        clientIdPinned: state.savedClientId === undefined || state.savedClientId === clientId,
      };
    },
    issuerBindingSummary: () => {
      const issuer = state.discovery?.authorizationServerMetadata?.issuer;
      return {
        issuerPresent: typeof issuer === "string",
        clientInformationIssuerBound: Boolean(issuer && provider.clientInformation({ issuer })?.issuer === issuer),
        tokenIssuerBound: Boolean(issuer && provider.tokens({ issuer })?.issuer === issuer),
      };
    },
  };
  return session;
}

function tokenRequestProbe(session, { mutation = "none", fetchImpl = globalThis.fetch } = {}) {
  const requests = [];
  const expectedEndpoint = session.getTokenEndpoint();
  if (!expectedEndpoint) throw new Error("OAuth discovery did not provide a token endpoint");
  const endpoint = new URL(expectedEndpoint);
  if (!["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname) || endpoint.protocol !== "http:") {
    throw new Error("The token endpoint is outside the isolated loopback acceptance deployment");
  }

  const fetchFn = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const isTokenEndpoint = url.origin === endpoint.origin && url.pathname === endpoint.pathname;
    if (!isTokenEndpoint) return fetchImpl(input, init);

    let params;
    if (init.body instanceof URLSearchParams) params = new URLSearchParams(init.body);
    else if (typeof init.body === "string") params = new URLSearchParams(init.body);
    else throw new Error("OAuth SDK token request did not use a form-encoded body");

    const original = {
      clientIdMatches: params.get("client_id") === session.clientId,
      redirectUriMatches: params.get("redirect_uri") === session.callbackUrl,
      resourceMatches: params.get("resource") === session.resource,
      codePresent: typeof params.get("code") === "string" && params.get("code").length > 0,
      pkceVerifierPresent: typeof params.get("code_verifier") === "string" && params.get("code_verifier").length > 0,
    };
    if (mutation === "wrong_redirect") params.set("redirect_uri", `${session.callbackUrl}/substituted`);
    if (mutation === "wrong_resource") params.set("resource", `${session.resource}/substituted`);
    if (mutation === "wrong_pkce") params.set("code_verifier", randomBytes(32).toString("base64url"));

    const response = await fetchImpl(input, { ...init, body: params.toString() });
    let body = {};
    try { body = await response.clone().json(); } catch { /* Only status and token-presence booleans are retained. */ }
    requests.push({
      endpointPath: url.pathname,
      method: init.method ?? (input instanceof Request ? input.method : "POST"),
      ...original,
      mutation,
      status: response.status,
      accessTokenPresent: typeof body?.access_token === "string" && body.access_token.length > 0,
      refreshTokenPresent: typeof body?.refresh_token === "string" && body.refresh_token.length > 0,
    });
    return response;
  };

  return { fetchFn, requests };
}

async function beginSdkAuthorization(session, { serverUrl, scope = MCP_SCOPE, fetchFn = globalThis.fetch }) {
  const result = await sdkOAuth(session.provider, { serverUrl, resourceMetadataUrl: session.resourceMetadataUrl, scope, fetchFn });
  const authorizationUrl = session.getAuthorizationUrl();
  if (result !== "REDIRECT" || !authorizationUrl) throw new Error("The MCP SDK did not initiate the expected browser authorization redirect");
  return { authorizationUrl, result, discovery: session.discoverySummary(), codeVerifierPresent: session.hasCodeVerifier() };
}

async function finishSdkAuthorization(session, { serverUrl, callbackParams, fetchFn = globalThis.fetch, issuerOverride, mutation = "none" }) {
  const code = callbackParams.get("code");
  const issuer = issuerOverride ?? callbackParams.get("iss") ?? undefined;
  if (!code) return { result: "no_code", codePresent: false, tokenEndpointStatus: null, tokenPresent: false, errorName: null };
  const probe = tokenRequestProbe(session, { fetchImpl: fetchFn, mutation });
  try {
    const result = await sdkOAuth(session.provider, { serverUrl, resourceMetadataUrl: session.resourceMetadataUrl,
      authorizationCode: code, iss: issuer, fetchFn: probe.fetchFn });
    return { result, codePresent: true, tokenEndpointStatus: probe.requests.at(-1)?.status ?? null,
      tokenPresent: session.hasTokens(), errorName: null, tokenRequests: probe.requests };
  } catch (error) {
    return { result: "rejected", codePresent: true, tokenEndpointStatus: probe.requests.at(-1)?.status ?? null,
      tokenPresent: session.hasTokens(), errorName: safeExceptionName(error), issuerMismatch: error instanceof IssuerMismatchError,
      tokenRequests: probe.requests };
  }
}

async function captureBrowserConsent(page, {
  authorizationUrl,
  callbackUrl = DEFAULT_CALLBACK_URL,
  callbackReceiver,
  agentId,
  agentName,
  foreignAgentId,
  expectConsentContext = true,
  expectedPermissions,
  expectedPolicyRevision,
  decision = "approve",
  selectedAgentId = agentId,
  continueAgentIdOverride,
  decisionFlowIdOverride,
  decisionAgentIdOverride,
  callbackIssuerOverride,
  allowEarlyScopeRejection = false,
  capture,
  clientId = DEFAULT_CLIENT_ID,
  expectedScope = MCP_SCOPE,
  expectedResource = DEFAULT_RESOURCE,
}) {
  if (!page || !agentId || !["approve", "deny"].includes(decision)) throw new Error("Browser consent setup is incomplete");
  const callback = loopbackHttpUrl(callbackUrl, "OAuth callback URL");
  if (!callbackReceiver) throw new Error("The dedicated local OAuth callback listener is required");
  let callbackRouteMatcher;
  let callbackRouteHandler;
  try {
    const authorizationResponse = await page.goto(authorizationUrl.href, { waitUntil: "domcontentloaded" });
    const agentSelect = page.getByTestId(CONSENT_TEST_IDS.agent);
    let selectionVisible = true;
    try {
      await agentSelect.waitFor({ state: "visible", timeout: allowEarlyScopeRejection ? 3000 : 15000 });
    } catch {
      selectionVisible = false;
    }
    if (!selectionVisible && allowEarlyScopeRejection) {
      let callbackData = { errorPresent: false };
      const currentUrl = new URL(page.url());
      if (currentUrl.origin === callback.origin && currentUrl.pathname === callback.pathname) {
        callbackData = await callbackReceiver.waitForCallback(1500).catch(() => callbackData);
      }
      const scopeErrorPresented = callbackData.errorCode === "invalid_scope";
      const authorizationStatus = authorizationResponse?.status() ?? null;
      const providerRejectedBeforeSelection = Boolean((authorizationStatus !== null && authorizationStatus >= 400)
        || callbackData.errorPresent || scopeErrorPresented);
      const callbackParams = new URLSearchParams();
      if (callbackData.code) callbackParams.set("code", callbackData.code);
      if (callbackData.state) callbackParams.set("state", callbackData.state);
      if (callbackData.issuer) callbackParams.set("iss", callbackData.issuer);
      return {
        callbackParams,
        callbackData,
        browser: {
          consentPageLoaded: false,
          selectedAgentMatches: false,
          foreignAgentOptionAbsent: false,
          decisionClicked: false,
          decision,
          scopesDisplayed: false,
          displayed: {},
          contextStatus: null,
          flowId: null,
          consentAgentId: null,
          consentPolicyRevision: null,
          permissionValues: {},
          callbackObserved: callbackData.errorPresent === true || Boolean(callbackData.code),
          callbackHasCode: Boolean(callbackData.code),
          callbackHasError: callbackData.errorPresent === true,
          callbackStatePresent: Boolean(callbackData.state),
          callbackIssuerPresent: Boolean(callbackData.issuer),
          continueStatus: null,
          continueOperationId: null,
          attemptedForeignAgent: false,
          authorizationStatus,
          callbackErrorCode: callbackData.errorCode ?? null,
          providerRejectedBeforeSelection,
          scopeErrorPresented,
        },
      };
    }
    if (!selectionVisible) throw new Error("The owner agent selection control did not appear");
    await agentSelect.selectOption({ value: selectedAgentId });
    capture?.action("select", CONSENT_TEST_IDS.agent);
    const selectedAgent = await agentSelect.inputValue();
    const foreignOptionAvailable = foreignAgentId
      ? (await agentSelect.locator("option").evaluateAll((options, id) => options.some((option) => option.value === id), foreignAgentId))
      : false;
    const continueButton = page.getByTestId(CONSENT_TEST_IDS.continue);
    await continueButton.waitFor({ state: "visible", timeout: 10000 });
    if (await continueButton.isDisabled()) throw new Error("The owner consent continuation remained disabled after selecting an agent");
    const contextResponsePromise = expectConsentContext ? page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/owner/agents/oauth-consent-context" && response.request().method() === "POST";
    }, { timeout: 15000 }).catch(() => undefined) : Promise.resolve(undefined);
    let continuationRequest = null;
    if (continueAgentIdOverride) {
      await page.route("**/api/owner/agents/oauth-select", async (route) => {
        const body = route.request().postDataJSON();
        continuationRequest = { operationId: body?.operationId ?? null,
          attemptedForeignAgent: continueAgentIdOverride === foreignAgentId,
          selectedAgentMatches: body?.agentId === selectedAgentId };
        await route.continue({ postData: JSON.stringify({ ...body, agentId: continueAgentIdOverride }) });
      });
    }
    const continueResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/owner/agents/oauth-select" && response.request().method() === "POST";
    }, { timeout: 15000 });
    capture?.action("click", CONSENT_TEST_IDS.continue);
    await continueButton.click();
    const continueResponse = await continueResponsePromise;
    await page.unroute("**/api/owner/agents/oauth-select").catch(() => undefined);
    if (continueResponse.status() !== 200) {
      return {
        callbackParams: new URLSearchParams(),
        callbackData: { errorPresent: false },
        browser: {
          consentPageLoaded: false,
          selectedAgentMatches: selectedAgent === selectedAgentId,
          foreignAgentOptionAbsent: !foreignOptionAvailable,
          decisionClicked: false,
          decision,
          scopesDisplayed: false,
          displayed: {},
          contextStatus: null,
          flowId: null,
          consentAgentId: null,
          consentPolicyRevision: null,
          permissionValues: {},
          callbackObserved: false,
          callbackHasCode: false,
          callbackHasError: false,
          callbackStatePresent: false,
          callbackIssuerPresent: false,
          continueStatus: continueResponse.status(),
          continueOperationId: continuationRequest?.operationId ?? continueResponse.request().postDataJSON()?.operationId ?? null,
          attemptedForeignAgent: continuationRequest?.attemptedForeignAgent ?? false,
        },
      };
    }
    await waitForPath(page, ["/owner/agents/oauth-consent"], 15000);
    const contextResponse = await contextResponsePromise;
    if (!contextResponse) throw new Error("The OAuth consent context request did not complete");
    if (contextResponse.status() !== 200) throw new Error("The OAuth consent context was not returned for the authenticated owner");
    const serverContext = await contextResponse.json();

    const context = page.getByTestId(CONSENT_TEST_IDS.context);
    await context.waitFor({ state: "visible", timeout: 15000 });
    const contextText = await context.innerText();
    const valueFor = async (testId) => (await page.getByTestId(testId).innerText()).trim();
    const contextClientId = serverContext?.client?.clientId ?? serverContext?.client?.id;
    const clientIdDisplayed = contextClientId === clientId
      && (await valueFor("oauth-consent-client-id")) === contextClientId;
    const clientNameDisplayed = typeof serverContext?.client?.name === "string"
      && (await valueFor("oauth-consent-client")) === serverContext.client.name;
    const resourceDisplayed = serverContext?.resource === expectedResource
      && (await valueFor("oauth-consent-resource")) === serverContext.resource;
    const roleDisplayed = (await valueFor("oauth-consent-role")).toLowerCase().includes("agent");
    const scopeText = await valueFor("oauth-consent-scopes");
    const contextScopes = Array.isArray(serverContext?.scopes) ? serverContext.scopes : String(serverContext?.scopes ?? "").split(/\s+/);
    const scopeDisplayed = contextScopes.includes(expectedScope) && scopeText.split(/\s+/).includes(expectedScope);
    const agentText = await valueFor("oauth-consent-agent");
    const agentDisplayed = serverContext?.agent?.id === agentId
      && (!agentName || serverContext?.agent?.name === agentName)
      && agentText.includes(serverContext?.agent?.name ?? "");
    const policyText = await valueFor("oauth-consent-policy-revision");
    const policyRevision = Number(policyText.match(/\d+/)?.[0]);
    const permissionValues = {};
    for (const [key, testId] of Object.entries(PERMISSION_TEST_IDS)) {
      const locator = page.getByTestId(testId);
      const type = await locator.getAttribute("type");
      const ariaChecked = await locator.getAttribute("aria-checked");
      if (type === "checkbox") permissionValues[key] = await locator.isChecked();
      else if (ariaChecked === "true" || ariaChecked === "false") permissionValues[key] = ariaChecked === "true";
      else {
        const value = (await locator.innerText()).trim().toLowerCase();
        if (/\b(?:disabled|not allowed|off)\b/.test(value)) permissionValues[key] = false;
        else if (/\b(?:enabled|allowed|on)\b/.test(value)) permissionValues[key] = true;
        else permissionValues[key] = null;
      }
    }
    const contextPermissions = serverContext?.agent?.permissions;
    const permissionsDisplayed = Boolean(expectedPermissions && contextPermissions)
      && Object.keys(PERMISSION_TEST_IDS).every((key) => permissionValues[key] === expectedPermissions[key]
        && contextPermissions[key] === expectedPermissions[key]);
    const scopesDisplayed = scopeDisplayed && resourceDisplayed && clientIdDisplayed && clientNameDisplayed && roleDisplayed
      && agentDisplayed && permissionsDisplayed
      && Number.isInteger(serverContext?.agent?.policyRevision)
      && serverContext.agent.policyRevision === policyRevision
      && (!Number.isInteger(expectedPolicyRevision) || serverContext.agent.policyRevision === expectedPolicyRevision)
      && contextText.length > 0;
    const actionSelector = decision === "approve" ? CONSENT_TEST_IDS.approve : CONSENT_TEST_IDS.deny;
    const action = page.getByTestId(actionSelector);
    await action.waitFor({ state: "visible", timeout: 10000 });
    if (await action.isDisabled()) throw new Error("The owner consent action remained disabled after selecting an agent");
    if (callbackIssuerOverride) {
      const wrongIssuer = loopbackHttpUrl(callbackIssuerOverride, "OAuth issuer-negative fixture");
      callbackRouteMatcher = (url) => url.origin === callback.origin && url.pathname === callback.pathname;
      callbackRouteHandler = async (route) => {
        const target = new URL(route.request().url());
        target.searchParams.set("iss", wrongIssuer.href);
        await route.continue({ url: target.href });
      };
      await page.route(callbackRouteMatcher, callbackRouteHandler);
    }
    let consentRequest = null;
    if (decisionFlowIdOverride || decisionAgentIdOverride) {
      await page.route("**/api/owner/agents/oauth-consent", async (route) => {
        const body = route.request().postDataJSON();
        consentRequest = { operationId: body?.operationId ?? null, flowId: body?.flowId ?? null,
          attemptedAgentIdChange: Boolean(decisionAgentIdOverride && decisionAgentIdOverride !== serverContext?.agent?.id) };
        await route.continue({ postData: JSON.stringify({ ...body,
          ...(decisionFlowIdOverride ? { flowId: decisionFlowIdOverride } : {}),
          ...(decisionAgentIdOverride ? { agentId: decisionAgentIdOverride } : {}),
        }) });
      });
    }
    const decisionResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/owner/agents/oauth-consent" && response.request().method() === "POST";
    }, { timeout: 15000 });
    capture?.action("click", actionSelector);
    await action.click();
    const decisionResponse = await decisionResponsePromise;
    await page.unroute("**/api/owner/agents/oauth-consent").catch(() => undefined);
    if (decisionResponse.status() !== 200) {
      return {
        callbackParams: new URLSearchParams(),
        callbackData: { errorPresent: false },
        browser: {
          consentPageLoaded: true,
          selectedAgentMatches: selectedAgent === selectedAgentId,
          foreignAgentOptionAbsent: !foreignOptionAvailable,
          decisionClicked: true,
          decision,
          scopesDisplayed,
          displayed: { clientId: clientIdDisplayed, clientName: clientNameDisplayed, resource: resourceDisplayed, role: roleDisplayed,
            scope: scopeDisplayed, agent: agentDisplayed, permissions: permissionsDisplayed,
            policyRevision: Number.isInteger(serverContext?.agent?.policyRevision)
              && serverContext.agent.policyRevision === policyRevision
              && (!Number.isInteger(expectedPolicyRevision) || serverContext.agent.policyRevision === expectedPolicyRevision) },
          contextStatus: contextResponse.status(),
          flowId: typeof serverContext?.flowId === "string" ? serverContext.flowId : null,
          consentAgentId: serverContext?.agent?.id ?? null,
          consentPolicyRevision: Number.isInteger(serverContext?.agent?.policyRevision) ? serverContext.agent.policyRevision : null,
          permissionValues,
          callbackObserved: false,
          callbackHasCode: false,
          callbackHasError: false,
          callbackStatePresent: false,
          callbackIssuerPresent: false,
          continueStatus: continueResponse.status(),
          decisionStatus: decisionResponse.status(),
          decisionOperationId: consentRequest?.operationId ?? decisionResponse.request().postDataJSON()?.operationId ?? null,
          submittedFlowMatchesContext: consentRequest?.flowId === serverContext?.flowId,
          attemptedAgentIdChange: consentRequest?.attemptedAgentIdChange ?? false,
        },
      };
    }
    await page.waitForFunction(({ origin, path }) => window.location.origin === origin && window.location.pathname === path,
      { origin: callback.origin, path: callback.pathname }, { timeout: 15000 });
    const callbackData = await callbackReceiver.waitForCallback();
    const callbackParams = new URLSearchParams();
    if (callbackData.code) callbackParams.set("code", callbackData.code);
    if (callbackData.state) callbackParams.set("state", callbackData.state);
    if (callbackData.issuer) callbackParams.set("iss", callbackData.issuer);
    return {
      callbackParams,
      callbackData,
      browser: {
        consentPageLoaded: true,
        selectedAgentMatches: selectedAgent === agentId,
        foreignAgentOptionAbsent: !foreignOptionAvailable,
        decisionClicked: true,
        decision,
        scopesDisplayed,
        displayed: { clientId: clientIdDisplayed, clientName: clientNameDisplayed, resource: resourceDisplayed, role: roleDisplayed,
          scope: scopeDisplayed, agent: agentDisplayed, permissions: permissionsDisplayed,
          policyRevision: Number.isInteger(serverContext?.agent?.policyRevision)
            && serverContext.agent.policyRevision === policyRevision
            && (!Number.isInteger(expectedPolicyRevision) || serverContext.agent.policyRevision === expectedPolicyRevision) },
        contextStatus: contextResponse.status(),
        continueStatus: continueResponse.status(),
        continueOperationId: continueResponse.request().postDataJSON()?.operationId ?? null,
        attemptedForeignAgent: continuationRequest?.attemptedForeignAgent ?? false,
        decisionStatus: decisionResponse.status(),
        decisionOperationId: consentRequest?.operationId ?? decisionResponse.request().postDataJSON()?.operationId ?? null,
        submittedFlowMatchesContext: decisionFlowIdOverride
          ? decisionFlowIdOverride === serverContext?.flowId
          : (consentRequest?.flowId ?? decisionResponse.request().postDataJSON()?.flowId) === serverContext?.flowId,
        attemptedAgentIdChange: consentRequest?.attemptedAgentIdChange ?? false,
        flowId: typeof serverContext?.flowId === "string" ? serverContext.flowId : null,
        consentAgentId: serverContext?.agent?.id ?? null,
        consentPolicyRevision: Number.isInteger(serverContext?.agent?.policyRevision) ? serverContext.agent.policyRevision : null,
        permissionValues,
        callbackObserved: true,
        callbackHasCode: Boolean(callbackParams.get("code")),
        callbackHasError: callbackData.errorPresent === true,
        callbackStatePresent: Boolean(callbackParams.get("state")),
        callbackIssuerPresent: Boolean(callbackParams.get("iss")),
      },
    };
  } finally {
    if (callbackRouteMatcher && callbackRouteHandler) {
      await page.unroute(callbackRouteMatcher, callbackRouteHandler).catch(() => undefined);
    }
  }
}

function safeObserverValue(value, path) {
  const forbidden = /^(?:accessToken|refreshToken|token|clientSecret|secret|authorizationCode|codeVerifier|state|cookie|password|verifier)$/i;
  if (Array.isArray(value)) return value.map((item, index) => safeObserverValue(item, `${path}[${index}]`));
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, child] of Object.entries(value)) {
      if (forbidden.test(key)) throw new Error(`OAuth observer selected a forbidden secret field at ${path}.${key}`);
      if (/^(?:accessTokenPresent|refreshTokenPresent|tokenPresent|codePresent|codeVerifierPresent)$/i.test(key) && typeof child !== "boolean") {
        throw new Error(`OAuth observer secret-presence evidence must be boolean at ${path}.${key}`);
      }
      output[key] = safeObserverValue(child, `${path}.${key}`);
    }
    return output;
  }
  if (typeof value === "string" && (/\bBearer\s+\S+/i.test(value)
    || /[?&](?:code|state|access_token|refresh_token|id_token)=/i.test(value)
    || /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(value))) {
    throw new Error(`OAuth observer returned credential-like text at ${path}`);
  }
  return value;
}

export async function readOAuthObserverSnapshot(observerDatabaseUrl, queries) {
  if (!observerDatabaseUrl || !Array.isArray(queries)) throw new Error("OAuth read-only observer inputs are incomplete");
  const pool = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1, application_name: "aap-oauth-readonly-observer" });
  const client = await pool.connect();
  let activeQueryName = "observer_identity";
  try {
    await client.query("BEGIN READ ONLY");
    const identity = await client.query("SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only");
    const observer = identity.rows[0];
    if (observer.role !== "oid_observer" || observer.transaction_read_only !== "on") throw new Error("AAP OAuth outcome inspection did not use the independent read-only oid_observer");
    const results = {};
    for (const query of queries) {
      if (!query || typeof query.name !== "string" || !/^[a-z][A-Za-z0-9_]{0,63}$/.test(query.name)
        || typeof query.text !== "string" || !query.text.trimStart().toUpperCase().startsWith("SELECT")) {
        throw new Error("OAuth observer query must be a named SELECT statement");
      }
      activeQueryName = query.name;
      const result = await client.query(query.text, query.values ?? []);
      results[query.name] = safeObserverValue(result.rows, query.name);
    }
    await client.query("COMMIT");
    return { observer, ...results };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    const sqlState = typeof error?.code === "string" && /^[0-9A-Z]{5}$/.test(error.code) ? error.code : null;
    const wrapped = new Error("OAuth observer snapshot failed at a named read-only query");
    wrapped.code = sqlState ? `AAP_OAUTH_OBSERVER_SQL_${sqlState}` : "AAP_OAUTH_OBSERVER_QUERY";
    wrapped.safeDiagnostic = { queryName: activeQueryName, sqlState };
    throw wrapped;
  } finally {
    client.release();
    await pool.end();
  }
}

export async function runAapOAuthBrowserFlow({
  page,
  serverUrl = "http://127.0.0.1:3000/api/agent/mcp",
  resourceMetadataUrl,
  agentId,
  ownerId,
  decision = "approve",
  scope = MCP_SCOPE,
  captureApi,
  clientId = DEFAULT_CLIENT_ID,
  callbackUrl = DEFAULT_CALLBACK_URL,
  resource = DEFAULT_RESOURCE,
  callbackReceiver,
  agentName,
  foreignAgentId,
  expectedPermissions,
  expectedPolicyRevision,
  exchange = true,
  exchangeMutation = "none",
  issuerOverride,
  stateTamper = false,
  continueAgentIdOverride,
  decisionFlowIdOverride,
  decisionAgentIdOverride,
  callbackIssuerOverride,
}) {
  const session = makeOAuthProvider({ clientId, callbackUrl, resource, resourceMetadataUrl });
  const start = await beginSdkAuthorization(session, { serverUrl, scope });
  const browser = await captureBrowserConsent(page, {
    authorizationUrl: start.authorizationUrl,
    callbackUrl,
    callbackReceiver,
    agentId,
    agentName,
    foreignAgentId,
    expectConsentContext: scope === MCP_SCOPE && !continueAgentIdOverride,
    expectedPermissions,
    expectedPolicyRevision,
    decision,
    continueAgentIdOverride,
    decisionFlowIdOverride,
    decisionAgentIdOverride,
    callbackIssuerOverride,
    allowEarlyScopeRejection: scope !== MCP_SCOPE,
    capture: captureApi,
    clientId,
    expectedScope: MCP_SCOPE,
    expectedResource: resource,
  });
  const stateMatches = session.callbackStateMatches(browser.callbackParams.get("state"));
  session.setCallbackData(browser.callbackData);
  const completed = decision === "approve" && exchange
    ? await session.finish({ serverUrl, issuerOverride, mutation: exchangeMutation, stateTamper })
    : { result: decision === "deny" ? "denied" : exchange ? "state_mismatch" : "not_attempted", codePresent: Boolean(browser.callbackParams.get("code")),
      tokenEndpointStatus: null, tokenPresent: false, errorName: null, tokenRequests: [] };
  const safeBrowser = {
    ownerId,
    agentId,
    clientId,
    resource,
    redirectPath: new URL(callbackUrl).pathname,
    scope,
    sdkAuthorization: { result: start.result, discovery: start.discovery, request: session.authorizationRequestSummary(MCP_SCOPE),
      codeVerifierPresent: start.codeVerifierPresent, resourceMetadataUrlPath: session.resourceMetadataUrl.pathname,
      issuerBinding: session.issuerBindingSummary() },
    consent: browser.browser,
      callback: { stateMatches, issuerMatches: browser.callbackParams.get("iss") === session.provider.discoveryState()?.authorizationServerMetadata?.issuer,
      codePresent: Boolean(browser.callbackParams.get("code")), errorPresent: browser.callbackData.errorPresent === true,
      errorCode: browser.callbackData.errorCode ?? null },
    exchange: { result: completed.result, codePresent: completed.codePresent, tokenEndpointStatus: completed.tokenEndpointStatus,
      tokenPresent: completed.tokenPresent, errorName: completed.errorName, issuerMismatch: completed.issuerMismatch === true,
      stateTamperRejected: stateTamper && completed.result === "state_mismatch", tokenRequests: completed.tokenRequests },
  };
  return { session, browserData: safeBrowser, capture: captureApi?.capture };
}

async function createAgentThroughOwnerUi(page, name) {
  await page.goto("/agents");
  const form = page.getByTestId("agent-create-form");
  await form.getByTestId("agent-name").fill(name);
  await form.getByTestId("agent-description").fill("Synthetic local OAuth acceptance agent");
  const responsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/api/owner/agents" && response.request().method() === "POST";
  }, { timeout: 15000 });
  await form.getByTestId("agent-create").click();
  const response = await responsePromise;
  const payload = await response.json();
  const agent = payload?.agent;
  if (response.status() !== 201 || typeof agent?.id !== "string" || agent.name !== name) {
    throw new Error("The owner UI did not create the OAuth acceptance agent");
  }
  return { id: agent.id, name: agent.name, permissions: agent.permissions, policyRevision: agent.policyRevision };
}

async function createForeignAcceptanceAgent({ adminPage, newContext, login, publicOrigin }) {
  const context = await newContext();
  let inviteSecret = "";
  try {
    const subject = `oid-aap-oauth-foreign-${randomBytes(8).toString("hex")}`;
    const foreign = await login(context, subject);
    const invitationResponsePromise = adminPage.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/admin/invitations" && response.request().method() === "POST";
    }, { timeout: 15000 });
    await adminPage.getByTestId("invite-create").click();
    const invitationResponse = await invitationResponsePromise;
    if (invitationResponse.status() !== 201) throw new Error("The acceptance admin did not issue a synthetic foreign-owner invitation");
    inviteSecret = (await adminPage.getByTestId("invite-secret-once").locator("code").first().innerText()).trim();
    await foreign.page.getByTestId("invitation-code").fill(inviteSecret);
    const activationResponsePromise = foreign.page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === "/api/admission/activate" && response.request().method() === "POST";
    }, { timeout: 15000 });
    await foreign.page.getByTestId("activate-owner").click();
    const activation = await activationResponsePromise;
    await waitForPath(foreign.page, ["/account"], 15000);
    inviteSecret = "";
    const ownerResponse = await foreign.page.request.get("/api/owner");
    const ownerBody = await ownerResponse.json();
    if (!activation.ok() || ownerResponse.status() !== 200 || typeof ownerBody?.owner?.id !== "string") {
      throw new Error("The synthetic foreign owner did not complete the actual owner verifier flow");
    }
    const agent = await createAgentThroughOwnerUi(foreign.page, `OAuth foreign agent ${randomBytes(5).toString("hex")}`);
    return { context, page: foreign.page, ownerId: ownerBody.owner.id, agentId: agent.id, agent, publicOrigin };
  } catch (error) {
    await context.close().catch(() => undefined);
    throw error;
  } finally {
    inviteSecret = "";
  }
}

async function issueManualCredentialThroughOwnerUi(page, agentId, capture, consumeToken) {
  if (typeof consumeToken !== "function") throw new Error("The one-time credential must be consumed only by the local acceptance flow");
  let token = "";
  let displayed = "";
  let responseBody;
  let step = "navigate_agents";
  let statusRequestStatus = null;
  let issueStatus = null;
  let secretPresent = false;
  let formatValid = false;
  let displayMatches = false;
  let credentialIdPresent = false;
  let grantIdPresent = false;
  let issueButtonVisible = false;
  let secretElementVisible = false;
  let dismissButtonVisible = false;
  let dismissCompleted = false;
  try {
    await page.goto("/agents");
    step = "read_manual_credential_status";
    const statusResponse = await page.request.get(`/api/owner/agents/${agentId}/manual-credential`);
    statusRequestStatus = statusResponse.status();
    const statusBody = await statusResponse.json();
    if (statusRequestStatus !== 200 || !statusBody?.access || statusBody.access.status === "revoked") {
      throw new Error("The owner UI cannot issue the paired manual acceptance credential");
    }
    step = "wait_manual_issue_button";
    const selector = `credential-issue-${agentId}`;
    const issueResponsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname === `/api/owner/agents/${agentId}/manual-credential` && response.request().method() === "POST";
    }, { timeout: 15000 });
    const issueButton = page.getByTestId(selector);
    await issueButton.waitFor({ state: "visible", timeout: 10000 });
    issueButtonVisible = true;
    capture?.action("click", selector);
    step = "click_manual_issue_and_wait_response";
    await issueButton.click();
    const response = await issueResponsePromise;
    issueStatus = response.status();
    step = "read_manual_issue_response";
    responseBody = await response.json();
    token = typeof responseBody?.secret === "string" ? responseBody.secret : "";
    secretPresent = token.length > 0;
    formatValid = /^aap1_[A-Za-z0-9_-]{43}$/.test(token);
    credentialIdPresent = typeof responseBody?.credential?.id === "string";
    grantIdPresent = typeof responseBody?.credential?.grantId === "string";
    step = "wait_show_once_secret_element";
    const secretPanel = page.getByTestId(`credential-secret-once-${agentId}`);
    await secretPanel.waitFor({ state: "visible", timeout: 10000 });
    secretElementVisible = true;
    displayed = (await secretPanel.innerText()).trim();
    displayMatches = displayed === token;
    if (issueStatus !== 201 || !formatValid || !displayMatches
      || responseBody?.secretAvailable !== true || typeof responseBody?.credential?.id !== "string"
      || typeof responseBody?.credential?.grantId !== "string") {
      throw new Error("The paired manual credential did not use the approved show-once owner flow");
    }
    step = "dismiss_show_once_secret";
    const dismissButton = page.getByTestId(`credential-secret-dismiss-${agentId}`);
    await dismissButton.waitFor({ state: "visible", timeout: 10000 });
    dismissButtonVisible = true;
    capture?.action("click", `credential-secret-dismiss-${agentId}`);
    await dismissButton.click();
    await secretPanel.waitFor({ state: "detached", timeout: 10000 });
    dismissCompleted = true;
    const safe = { status: issueStatus, credentialId: responseBody.credential.id, grantId: responseBody.credential.grantId,
      operationId: response.request().postDataJSON()?.operationId ?? null, secretShownOnce: true, secretDismissed: true,
      secretAvailableAtIssue: responseBody.secretAvailable === true };
    responseBody.secret = "";
    step = "consume_manual_credential_in_mcp_client";
    await consumeToken(token);
    return safe;
  } catch (error) {
    const wrapped = new Error("The paired manual credential owner flow failed at a safe UI step");
    wrapped.safeDiagnostic = {
      step,
      statusRequestStatus,
      issueStatus,
      secretPresent,
      formatValid,
      displayMatches,
      credentialIdPresent,
      grantIdPresent,
      issueButtonVisible,
      secretElementVisible,
      dismissButtonVisible,
      dismissCompleted,
      originalErrorName: safeExceptionName(error),
    };
    throw wrapped;
  } finally {
    displayed = "";
    if (responseBody && typeof responseBody.secret === "string") responseBody.secret = "";
    token = "";
  }
}

async function revokeAgentThroughOwnerUi(page, agentId, capture) {
  await page.goto("/agents");
  const beforeResponse = await page.request.get(`/api/owner/agents/${agentId}/manual-credential`);
  const before = await beforeResponse.json();
  if (beforeResponse.status() !== 200 || !Number.isInteger(before?.access?.revision)) {
    throw new Error("The owner UI could not read the current access revision before global revocation");
  }
  const path = `/api/owner/agents/${agentId}/access-revoke`;
  const responsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === path
    && response.request().method() === "POST", { timeout: 15000 });
  const selector = `agent-revoke-${agentId}`;
  const revokeButton = page.getByTestId(selector);
  await revokeButton.waitFor({ state: "visible", timeout: 10000 });
  capture?.action("click", selector);
  await revokeButton.click();
  const response = await responsePromise;
  const body = await response.json();
  const result = { status: response.status(), operationId: response.request().postDataJSON()?.operationId ?? null,
    expectedAccessRevision: before.access.revision, accessRevision: body?.access?.revision ?? null,
    accessStatus: body?.access?.status ?? null, cancellationStatus: body?.cancellation?.status ?? null };
  if (response.status() !== 200 || result.accessStatus !== "revoked" || result.cancellationStatus !== "pending") {
    throw new Error("Global agent revocation did not commit through the owner UI");
  }
  return result;
}

async function runMcpSdkPreflight({ serverUrl, token, agentId, operationId }) {
  const requests = [];
  const fetchFn = async (input, init = {}) => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(request?.url ?? String(input));
    const headers = new Headers(request?.headers);
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    const response = await globalThis.fetch(input, init);
    requests.push({ method: init.method ?? request?.method ?? "GET", path: url.pathname, status: response.status,
      authorizationHeaderPresent: headers.has("authorization"), protocolVersionHeader: headers.get("mcp-protocol-version") ?? null });
    return response;
  };
  const client = new Client({ name: "Web3 Agent Bench local OAuth acceptance client", version: "1.0.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
    fetch: fetchFn,
    onInsufficientScope: "throw",
  });
  let toolNames = [];
  let listed = false;
  let preflight;
  let errorName = null;
  let negotiatedProtocolVersion;
  let negotiatedProtocolEra;
  try {
    await client.connect(transport);
    negotiatedProtocolVersion = typeof client.getNegotiatedProtocolVersion === "function"
      ? client.getNegotiatedProtocolVersion() : undefined;
    negotiatedProtocolEra = typeof client.getProtocolEra === "function" ? client.getProtocolEra() : undefined;
    const toolResult = await client.listTools();
    toolNames = Array.isArray(toolResult?.tools) ? toolResult.tools.map((tool) => tool.name).filter((name) => typeof name === "string") : [];
    listed = true;
    if (toolNames.includes("identity.preflight")) {
      const result = await client.callTool({ name: "identity.preflight", arguments: { agentId, operationId } });
      const payload = result?.structuredContent;
      preflight = { called: true, isError: result?.isError === true,
        status: payload?.status === "allowed" || payload?.status === "denied" ? payload.status : null,
        operationIdMatches: payload?.operationId === operationId,
        policyVersion: Number.isInteger(payload?.policyVersion) ? payload.policyVersion : null,
        accessGeneration: Number.isInteger(payload?.accessGeneration) ? payload.accessGeneration : null };
    } else {
      preflight = { called: false, reasonCode: "preflight_tool_not_discovered" };
    }
  } catch (error) {
    errorName = safeExceptionName(error);
    preflight ??= { called: false, isError: true };
  } finally {
    await client.close().catch(() => undefined);
  }
  return { protocolProfile: "2026-07-28", protocolVersion: negotiatedProtocolVersion ?? null, protocolEra: negotiatedProtocolEra ?? null,
    protocolPinned: negotiatedProtocolVersion === "2026-07-28" && negotiatedProtocolEra === "modern", toolNames, toolListSucceeded: listed,
    preflight, errorName, requests };
}

async function runHttpPreflight({ publicOrigin, token, agentId, resource }) {
  const response = await globalThis.fetch(new URL("/api/agent/preflight", publicOrigin), {
    headers: { authorization: `Bearer ${token}`, "x-agent-id": agentId, "x-agent-resource": resource },
  });
  let body = {};
  try { body = await response.json(); } catch { /* A denial body is not retained. */ }
  return { status: response.status, allowed: body?.allowed === true,
    agentIdMatches: body?.agentId === agentId, resourceMatches: body?.resource === resource,
    role: body?.role === "agent" ? "agent" : null, policyRevision: Number.isInteger(body?.policyRevision) ? body.policyRevision : null };
}

export { DEFAULT_CALLBACK_URL, DEFAULT_CLIENT_ID, DEFAULT_RESOURCE, MCP_SCOPE, CONSENT_TEST_IDS };

function oauthObserverQueries({ ownerId, agentIds, flowIds, selectionOperationIds, startedAt }) {
  return [
    {
      name: "authorizations",
      text: `SELECT id::text, operation_id, query_hash, owner_id::text, agent_id::text, grant_id::text,
          client_id, resource, redirect_uri, scopes, access_generation, policy_revision, status,
          created_at::text, expires_at::text, completed_at::text
        FROM oid_agent_oauth_authorization WHERE id=ANY($1::uuid[]) ORDER BY created_at`,
      values: [flowIds],
    },
    {
      name: "authorizationsByOperation",
      text: `SELECT id::text, operation_id, owner_id::text, agent_id::text, grant_id::text,
          client_id, resource, scopes, status
        FROM oid_agent_oauth_authorization WHERE operation_id=ANY($1::text[]) ORDER BY created_at`,
      values: [selectionOperationIds],
    },
    {
      name: "authorizationCodes",
      text: `SELECT a.id::text AS authorization_id,
          (v.identifier IS NOT NULL) AS provider_verification_present,
          (v.expires_at <= now()) AS provider_verification_expired,
          v.expires_at::text AS provider_verification_expires_at
        FROM oid_agent_oauth_authorization a
        LEFT JOIN oid_auth_verification v ON v.identifier=a.authorization_code_hash
        WHERE a.id=ANY($1::uuid[]) ORDER BY a.created_at`,
      values: [flowIds],
    },
    {
      name: "grants",
      text: `SELECT id::text, owner_id::text, agent_id::text, operation_id, source, oauth_client_id,
          resource, role, access_generation, expires_at::text, revoked_at::text, revocation_reason
        FROM oid_agent_access_grant WHERE agent_id=ANY($1::uuid[]) AND source='oauth' ORDER BY created_at`,
      values: [agentIds],
    },
    {
      name: "providerAccess",
      text: `SELECT t.id, t.client_id, t.reference_id, t.authorization_code_id, t.resources, t.scopes,
          (t.revoked IS NOT NULL) AS revoked, (t.expires_at > now()) AS unexpired, t.expires_at::text
        FROM oid_oauth_access_token t
        INNER JOIN oid_agent_oauth_authorization a ON t.reference_id=a.grant_id::text
        WHERE a.id=ANY($1::uuid[]) AND a.agent_id=ANY($2::uuid[]) ORDER BY t.created_at`,
      values: [flowIds, agentIds],
    },
    {
      name: "manualCredentials",
      text: `SELECT c.id::text, c.grant_id::text, g.owner_id::text, g.agent_id::text,
          g.source, g.resource, g.role, g.access_generation, g.revoked_at::text AS grant_revoked_at
        FROM oid_agent_manual_credential c
        INNER JOIN oid_agent_access_grant g ON g.id=c.grant_id
        WHERE g.owner_id=$1::uuid AND g.agent_id=ANY($2::uuid[]) AND g.source='manual'
        ORDER BY c.created_at`,
      values: [ownerId, agentIds],
    },
    {
      name: "exchangeAudits",
      text: `SELECT id::text, event_type, operation_id, actor_owner_id::text, subject_owner_id::text,
          policy_revision, metadata->>'agentId' AS agent_id, metadata->>'grantId' AS grant_id,
          metadata->>'clientId' AS client_id, metadata->>'resource' AS resource,
          metadata->>'authorizationId' AS authorization_id, created_at::text
        FROM oid_audit WHERE actor_owner_id=$1::uuid AND event_type='agent.oauth.code_exchanged'
          AND created_at >= $2::timestamptz ORDER BY created_at`,
      values: [ownerId, startedAt],
    },
    {
      name: "agentFence",
      text: `SELECT id::text, owner_id::text, access_revision, access_generation, access_revoked_at::text
        FROM oid_agent WHERE id=ANY($1::uuid[])`,
      values: [agentIds],
    },
  ];
}

async function expireAuthorizationCodeFixture(databaseUrl, ownerId, authorizationId, codeFingerprint) {
  if (!databaseUrl || !ownerId || !authorizationId || !codeFingerprint) {
    throw new Error("The private OAuth code-expiry fixture inputs are incomplete");
  }
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 1, application_name: "aap-oauth-private-expiry-fixture" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(`UPDATE oid_auth_verification v
      SET expires_at=now() - interval '1 second'
      FROM oid_agent_oauth_authorization a
      WHERE a.id=$1::uuid AND a.owner_id=$2::uuid AND a.authorization_code_hash=$3
        AND v.identifier=a.authorization_code_hash AND v.expires_at > now()
      RETURNING (v.expires_at <= now()) AS expired`, [authorizationId, ownerId, codeFingerprint]);
    await client.query("COMMIT");
    return { method: "dedicated acceptance DB expiry fixture", updatedRows: updated.rowCount,
      flowBound: updated.rowCount === 1, expiryApplied: updated.rows.length === 1 && updated.rows[0].expired === true };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

/**
 * Run the pinned local browser OAuth route against a freshly created owner card.
 * Only booleans, IDs, safe protocol metadata, and SELECT-only database rows leave
 * this function; authorization code, state, verifier, session cookie, and JWT
 * remain inside the SDK/browser process.
 */
export async function runAapOauthCases({ page, ownerId, adminPage, newContext, publicOrigin, login, observerDatabaseUrl, databaseUrl, restartApi }) {
  let phase = "configuration";
  let callbackReceiver;
  let mcpChallenge;
  let foreign;
  let agent;
  let approved;
  let revoked = false;
  const startedAt = new Date().toISOString();
  let beforeRevoke;
  let afterRevoke;
  let activeMcp;
  let revokedMcp;
  let revokeResult;
  let manualCredential;
  let manualMcp;
  let manualPostRevokeMcp;
  let manualPostRestartMcp;
  let postRestartMcp;
  let pairedManualToken = "";
  let denied;
  let foreignSelection;
  let scopeEscalation;
  let agentSelectionChange;
  let selectionSubstitution;
  let expiryFlow;
  let expiryFixture;
  let expiryAttempt;
  let codeReplay;
  const sessions = [];
  const exchangeNegatives = {};
  const captureApi = attachSafeBrowserCapture(page, "AAP-SC-002");
  let foreignCapture;
  const clientId = process.env.OID_MCP_CLIENT_ID ?? DEFAULT_CLIENT_ID;
  const callbackUrl = process.env.OID_MCP_CLIENT_REDIRECT_URI ?? DEFAULT_CALLBACK_URL;
  const resource = new URL("/api/agent", publicOrigin).href;
  const serverUrl = new URL("/api/agent/mcp", publicOrigin).href;
  if (clientId !== DEFAULT_CLIENT_ID || callbackUrl !== DEFAULT_CALLBACK_URL || resource !== DEFAULT_RESOURCE) {
    throw new Error("AAP OAuth acceptance configuration does not match the pinned local profile");
  }
  if (typeof restartApi !== "function") throw new Error("AAP OAuth acceptance requires the isolated API restart helper");

  try {
    phase = "loopback_callback_listener";
    callbackReceiver = await startOAuthCallbackReceiver(callbackUrl);
    phase = "actual_mcp_resource_metadata_challenge";
    mcpChallenge = await probeMcpAuthorizationChallenge({ serverUrl, publicOrigin, resource });
    const runOAuthFlow = (options) => runAapOAuthBrowserFlow({
      ...options, resourceMetadataUrl: mcpChallenge.resourceMetadataUrl,
    });
    phase = "create_fresh_owner_agent_in_browser";
    agent = await createAgentThroughOwnerUi(page, `OAuth acceptance agent ${randomBytes(5).toString("hex")}`);
    if (Object.values(agent.permissions ?? {}).some(Boolean)) throw new Error("The fresh OAuth acceptance agent did not start with all permissions disabled");

    phase = "browser_owner_selection_consent_and_provider_exchange";
    approved = await runOAuthFlow({
      page,
      serverUrl,
      agentId: agent.id,
      agentName: agent.name,
      ownerId,
      captureApi,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      expectedPermissions: agent.permissions,
      expectedPolicyRevision: agent.policyRevision,
    });
    sessions.push(approved.session);
    const consent = approved.browserData.consent;
    const exchange = approved.browserData.exchange;
    if (consent.continueStatus !== 200 || consent.decisionStatus !== 200 || !consent.scopesDisplayed
      || !approved.browserData.callback.stateMatches || !approved.browserData.callback.codePresent
      || exchange.tokenEndpointStatus !== 200 || !exchange.tokenPresent) {
      throw new Error("The local browser OAuth approval or provider code exchange was not observed");
    }

    phase = "actual_pinned_mcp_client_preflight";
    const preflightOperationId = randomBytes(18).toString("base64url");
    activeMcp = await approved.session.useAccessToken((token) => runMcpSdkPreflight({
      serverUrl, token, agentId: agent.id, operationId: preflightOperationId,
    }));

    phase = "paired_manual_credential_issue_and_mcp_preflight";
    const manualPreflightOperationId = randomBytes(18).toString("base64url");
    manualCredential = await issueManualCredentialThroughOwnerUi(page, agent.id, captureApi, async (token) => {
      pairedManualToken = token;
      manualMcp = await runMcpSdkPreflight({
        serverUrl, token, agentId: agent.id, operationId: manualPreflightOperationId,
      });
    });

    phase = "browser_owner_denies_second_consent";
    denied = await runOAuthFlow({
      page,
      serverUrl,
      agentId: agent.id,
      agentName: agent.name,
      ownerId,
      decision: "deny",
      captureApi,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      expectedPermissions: agent.permissions,
      expectedPolicyRevision: agent.policyRevision,
    });
    sessions.push(denied.session);

    phase = "create_foreign_owner_agent_through_ui";
    foreign = await createForeignAcceptanceAgent({ adminPage, newContext, login, publicOrigin });
    foreignCapture = attachSafeBrowserCapture(foreign.page, "AAP-SC-002");

    phase = "foreign_card_selection_rejected_through_browser_request";
    foreignSelection = await runOAuthFlow({
      page,
      serverUrl,
      agentId: agent.id,
      agentName: agent.name,
      ownerId,
      captureApi,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      foreignAgentId: foreign.agentId,
      continueAgentIdOverride: foreign.agentId,
      expectedPermissions: agent.permissions,
      expectedPolicyRevision: agent.policyRevision,
    });
    sessions.push(foreignSelection.session);

    phase = "scope_escalation_rejected_through_browser_request";
    scopeEscalation = await runOAuthFlow({
      page,
      serverUrl,
      agentId: agent.id,
      agentName: agent.name,
      ownerId,
      captureApi,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      scope: "agent:operate wallet:withdraw",
      expectedPermissions: agent.permissions,
      expectedPolicyRevision: agent.policyRevision,
    });
    sessions.push(scopeEscalation.session);

    phase = "agent_selection_changed_after_consent_rejected";
    agentSelectionChange = await runOAuthFlow({
      page,
      serverUrl,
      agentId: agent.id,
      agentName: agent.name,
      ownerId,
      captureApi,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      foreignAgentId: foreign.agentId,
      decisionAgentIdOverride: foreign.agentId,
      expectedPermissions: agent.permissions,
      expectedPolicyRevision: agent.policyRevision,
    });
    sessions.push(agentSelectionChange.session);

    phase = "owner_and_agent_binding_survives_flow_substitution";
    selectionSubstitution = await runOAuthFlow({
      page: foreign.page,
      serverUrl,
      agentId: foreign.agentId,
      agentName: foreign.agent.name,
      ownerId: foreign.ownerId,
      captureApi: foreignCapture,
      clientId,
      callbackUrl,
      resource,
      callbackReceiver,
      expectedPermissions: foreign.agent.permissions,
      expectedPolicyRevision: foreign.agent.policyRevision,
      decisionFlowIdOverride: consent.flowId,
    });
    sessions.push(selectionSubstitution.session);

    const wrongIssuer = new URL("/api/wrong-issuer", new URL(resource).origin).href;
    for (const [name, mutation, callbackIssuerOverride] of [
      ["wrongRedirect", "wrong_redirect", undefined],
      ["wrongResource", "wrong_resource", undefined],
      ["wrongPkce", "wrong_pkce", undefined],
      ["wrongIssuer", "none", wrongIssuer],
    ]) {
      phase = `oauth_exchange_${name}`;
      try {
        const attempt = await runOAuthFlow({
          page,
          serverUrl,
          agentId: agent.id,
          agentName: agent.name,
          ownerId,
          captureApi,
          clientId,
          callbackUrl,
          resource,
          callbackReceiver,
          expectedPermissions: agent.permissions,
          expectedPolicyRevision: agent.policyRevision,
          exchangeMutation: mutation,
          callbackIssuerOverride,
        });
        sessions.push(attempt.session);
        exchangeNegatives[name] = attempt.browserData.exchange;
      } catch (error) {
        exchangeNegatives[name] = { result: "not_observed", errorName: safeExceptionName(error), tokenPresent: false, tokenRequests: [] };
      }
    }

    phase = "oauth_exchange_replay_denial";
    codeReplay = await approved.session.replayAuthorizationCode({ serverUrl });

    phase = "oauth_private_code_expiry_fixture";
    try {
      expiryFlow = await runOAuthFlow({
        page,
        serverUrl,
        agentId: agent.id,
        agentName: agent.name,
        ownerId,
        captureApi,
        clientId,
        callbackUrl,
        resource,
        callbackReceiver,
        exchange: false,
        expectedPermissions: agent.permissions,
        expectedPolicyRevision: agent.policyRevision,
      });
      sessions.push(expiryFlow.session);
      expiryFixture = await expireAuthorizationCodeFixture(databaseUrl, ownerId,
        expiryFlow.browserData.consent.flowId, expiryFlow.session.codeFingerprint());
      expiryAttempt = await expiryFlow.session.finish({ serverUrl });
    } catch (error) {
      expiryFixture = { method: "dedicated acceptance DB expiry fixture", updatedRows: 0,
        flowBound: false, expiryApplied: false, errorName: safeExceptionName(error) };
      expiryAttempt = { result: "not_observed", codePresent: false, tokenPresent: false, tokenRequests: [] };
    }

    const allFlows = [approved, denied, foreignSelection, scopeEscalation, agentSelectionChange, selectionSubstitution, expiryFlow];
    for (const flow of allFlows) if (flow?.session && !sessions.includes(flow.session)) sessions.push(flow.session);
    const flowIds = allFlows.map((flow) => flow?.browserData?.consent?.flowId).filter((value) => typeof value === "string");
    const selectionOperationIds = [captureApi.capture, foreignCapture?.capture]
      .flatMap((capture) => capture?.requests ?? [])
      .filter((row) => row?.path === "/api/owner/agents/oauth-select")
      .map((row) => row.operationId)
      .filter((value) => typeof value === "string");
    const agentIds = [...new Set([agent.id, foreign.agentId])];
    phase = "independent_read_only_postgres_before_revoke";
    beforeRevoke = await readOAuthObserverSnapshot(observerDatabaseUrl,
      oauthObserverQueries({ ownerId, agentIds, flowIds, selectionOperationIds, startedAt }));

    phase = "owner_ui_global_revoke";
    revokeResult = await revokeAgentThroughOwnerUi(page, agent.id, captureApi);
    revoked = true;

    phase = "actual_pinned_mcp_client_post_revoke_denial";
    revokedMcp = await approved.session.useAccessToken((token) => runMcpSdkPreflight({
      serverUrl, token, agentId: agent.id, operationId: randomBytes(18).toString("base64url"),
    }));

    phase = "paired_manual_mcp_post_revoke_denial";
    manualPostRevokeMcp = await runMcpSdkPreflight({
      serverUrl, token: pairedManualToken, agentId: agent.id, operationId: randomBytes(18).toString("base64url"),
    });

    phase = "restart_api_after_global_revoke";
    await restartApi();
    const apiRestart = { completed: true };

    phase = "oauth_and_manual_mcp_denial_after_api_restart";
    postRestartMcp = await approved.session.useAccessToken((token) => runMcpSdkPreflight({
      serverUrl, token, agentId: agent.id, operationId: randomBytes(18).toString("base64url"),
    }));
    manualPostRestartMcp = await runMcpSdkPreflight({
      serverUrl, token: pairedManualToken, agentId: agent.id, operationId: randomBytes(18).toString("base64url"),
    });

    phase = "independent_read_only_postgres_after_revoke_and_restart";
    afterRevoke = await readOAuthObserverSnapshot(observerDatabaseUrl,
      oauthObserverQueries({ ownerId, agentIds, flowIds, selectionOperationIds, startedAt }));

    const approvedRow = beforeRevoke.authorizations.find((row) => row.id === consent.flowId);
    const approvedGrant = beforeRevoke.grants.find((row) => approvedRow && row.id === approvedRow.grant_id);
    const deniedRow = beforeRevoke.authorizations.find((row) => row.id === denied.browserData.consent.flowId);
    const deniedHasGrant = Boolean(deniedRow && beforeRevoke.grants.some((row) => row.id === deniedRow.grant_id));
    const foreignSelectionOperationId = foreignSelection.browserData.consent.continueOperationId;
    const foreignSelectionPersisted = beforeRevoke.authorizationsByOperation.some((row) => row.operation_id === foreignSelectionOperationId);
    const scopeOperationId = scopeEscalation.browserData.consent.continueOperationId;
    const scopeFlowPersisted = beforeRevoke.authorizationsByOperation.some((row) => row.operation_id === scopeOperationId);
    const changedAgentFlow = beforeRevoke.authorizations.find((row) => row.id === agentSelectionChange.browserData.consent.flowId);
    const changedAgentGrant = Boolean(changedAgentFlow && beforeRevoke.grants.some((row) => row.id === changedAgentFlow.grant_id));
    const substitutedFlow = beforeRevoke.authorizations.find((row) => row.id === selectionSubstitution.browserData.consent.flowId);
    const substitutedGrant = Boolean(substitutedFlow && beforeRevoke.grants.some((row) => row.id === substitutedFlow.grant_id));
    const exchangeAudit = beforeRevoke.exchangeAudits.find((row) => row.event_type === "agent.oauth.code_exchanged"
      && row.agent_id === agent.id && row.grant_id === approvedRow?.grant_id
      && row.client_id === clientId && row.resource === resource && row.authorization_id === consent.flowId);
    const approvedCodeRow = beforeRevoke.authorizationCodes.find((row) => row.authorization_id === consent.flowId);
    const deniedRequests = (value) => Array.isArray(value?.tokenRequests) && value.tokenRequests.length > 0
      && value.tokenPresent === false && value.tokenRequests.every((row) => [400, 401, 403].includes(row.status) && row.accessTokenPresent === false);
    const expectedPermissions = { training: false, ranked: false, forumMessages: false, customTopics: false };
    const approvedSdk = approved.browserData.sdkAuthorization;
    const approvedRequest = approvedSdk.request;
    const approvedDiscovery = approvedSdk.discovery;
    const approvedConsent = approved.browserData.consent;
    const approvedGrantBound = Boolean(approvedRow && approvedGrant
      && approvedGrant.owner_id === ownerId && approvedGrant.agent_id === agent.id
      && approvedGrant.source === "oauth" && approvedGrant.oauth_client_id === clientId
      && approvedGrant.resource === resource && approvedGrant.role === "agent"
      && approvedGrant.access_generation === approvedRow.access_generation && approvedGrant.revoked_at === null);
    const approvedBinding = Boolean(approvedConsent.consentPageLoaded && approvedConsent.selectedAgentMatches
      && approvedConsent.decision === "approve" && approvedConsent.decisionStatus === 200
      && approvedConsent.submittedFlowMatchesContext && approvedConsent.consentAgentId === agent.id
      && approvedConsent.displayed.clientId && approvedConsent.displayed.resource && approvedConsent.displayed.role
      && approvedConsent.displayed.scope && approvedConsent.displayed.agent && approvedConsent.displayed.permissions
      && approvedConsent.displayed.policyRevision
      && approvedConsent.permissionValues?.training === expectedPermissions.training
      && approvedConsent.permissionValues?.ranked === expectedPermissions.ranked
      && approvedConsent.permissionValues?.forumMessages === expectedPermissions.forumMessages
      && approvedConsent.permissionValues?.customTopics === expectedPermissions.customTopics
      && approvedConsent.consentPolicyRevision === approvedRow?.policy_revision
      && approvedRow?.owner_id === ownerId && approvedRow?.agent_id === agent.id
      && approvedRow?.client_id === clientId && approvedRow?.resource === resource
      && approvedRow?.redirect_uri === callbackUrl && approvedRow?.scopes?.length === 1
      && approvedRow?.scopes?.[0] === MCP_SCOPE && approvedRow?.status === "approved");
    const deniedBinding = Boolean(denied.browserData.consent.decision === "deny"
      && denied.browserData.consent.decisionStatus === 200 && denied.browserData.callback.errorPresent
      && denied.browserData.callback.codePresent === false && denied.browserData.callback.stateMatches
      && deniedRow?.owner_id === ownerId && deniedRow?.agent_id === agent.id
      && deniedRow?.client_id === clientId && deniedRow?.resource === resource
      && deniedRow?.status === "denied" && !deniedHasGrant);
    const scopeEscalationRequest = scopeEscalation.browserData.sdkAuthorization.request;
    const scopeEscalationConsent = scopeEscalation.browserData.consent;
    const scopeEscalationDenied = Boolean(scopeEscalationRequest.extraScopeRequested
      && scopeEscalationRequest.requestedScopeCount > 1
      && (scopeEscalationConsent.continueStatus === 400
        || (scopeEscalationConsent.providerRejectedBeforeSelection
          && scopeEscalationConsent.callbackErrorCode === "invalid_scope"))
      && !scopeFlowPersisted);
    const selectionChangeDenied = Boolean(agentSelectionChange.browserData.consent.attemptedAgentIdChange
      && agentSelectionChange.browserData.consent.decisionStatus === 400
      && changedAgentFlow?.owner_id === ownerId && changedAgentFlow?.agent_id === agent.id
      && changedAgentFlow?.status === "selected" && !changedAgentGrant);
    const foreignSelectionDenied = Boolean(foreignSelection.browserData.consent.foreignAgentOptionAbsent
      && foreignSelection.browserData.consent.attemptedForeignAgent
      && foreignSelection.browserData.consent.continueStatus === 404 && !foreignSelectionPersisted
      && !beforeRevoke.grants.some((row) => row.agent_id === foreign.agentId));
    const sc002Ready = Boolean(approvedBinding && approvedGrantBound && deniedBinding
      && foreignSelectionDenied && scopeEscalationDenied && selectionChangeDenied);
    const challengeBound = Boolean(mcpChallenge.evidence.status === 401 && mcpChallenge.evidence.challengePresent
      && mcpChallenge.evidence.resourceMetadataPath === "/.well-known/oauth-protected-resource/api/agent"
      && mcpChallenge.evidence.resourceMetadataOriginMatches && mcpChallenge.evidence.expectedResource === resource
      && approvedDiscovery.resourceMetadataPathMatchesChallenge && approvedDiscovery.resourceMatchesPinned
      && approvedDiscovery.issuerLoopback && approvedSdk.issuerBinding.clientInformationIssuerBound
      && approvedSdk.issuerBinding.tokenIssuerBound);
    const oauthRequestBound = Boolean(approvedRequest.clientIdMatches && approvedRequest.redirectUriMatches
      && approvedRequest.responseTypeCode && approvedRequest.codeChallengePresent && approvedRequest.codeChallengeMethodS256
      && approvedRequest.statePresent && approvedRequest.resourceMatches && approvedRequest.expectedScopeRequested
      && !approvedRequest.extraScopeRequested && approvedRequest.requestedScopeCount === 1);
    const exchangeSuccessful = Boolean(oauthRequestBound && challengeBound && approved.browserData.callback.stateMatches
      && approved.browserData.callback.issuerMatches && approved.browserData.callback.codePresent
      && exchange.tokenEndpointStatus === 200 && exchange.tokenPresent
      && exchange.tokenRequests?.[0]?.clientIdMatches && exchange.tokenRequests?.[0]?.redirectUriMatches
      && exchange.tokenRequests?.[0]?.resourceMatches && exchange.tokenRequests?.[0]?.pkceVerifierPresent
      && exchange.tokenRequests?.[0]?.status === 200 && exchange.tokenRequests?.[0]?.accessTokenPresent
      && approvedRow?.scopes?.length === 1 && approvedRow?.scopes?.[0] === MCP_SCOPE);
    const invalidExchangesDenied = ["wrongRedirect", "wrongResource", "wrongPkce"].every((name) => deniedRequests(exchangeNegatives[name]))
      && expiryFixture?.flowBound && expiryFixture.expiryApplied && deniedRequests(expiryAttempt)
      && exchangeNegatives.wrongIssuer?.result === "rejected"
      && exchangeNegatives.wrongIssuer?.issuerMismatch === true
      && exchangeNegatives.wrongIssuer?.errorName === "IssuerMismatchError"
      && exchangeNegatives.wrongIssuer?.tokenPresent === false
      && exchangeNegatives.wrongIssuer?.tokenEndpointStatus === null
      && Array.isArray(exchangeNegatives.wrongIssuer?.tokenRequests)
      && exchangeNegatives.wrongIssuer.tokenRequests.length === 0;
    const exchangeAuditBound = Boolean(exchangeAudit && exchangeAudit.actor_owner_id === ownerId
      && exchangeAudit.subject_owner_id === ownerId && exchangeAudit.event_type === "agent.oauth.code_exchanged"
      && exchangeAudit.agent_id === agent.id && exchangeAudit.grant_id === approvedRow?.grant_id
      && exchangeAudit.client_id === clientId && exchangeAudit.resource === resource
      && exchangeAudit.authorization_id === consent.flowId && approvedRow?.status === "approved");
    const codeConsumed = Boolean(codeReplay.result === "rejected" && deniedRequests(codeReplay)
      && exchangeAuditBound && approvedCodeRow?.provider_verification_present === false);
    const manualCredentialRow = beforeRevoke.manualCredentials.find((row) => row.id === manualCredential?.credentialId);
    const manualGrantRow = beforeRevoke.manualCredentials.find((row) => row.grant_id === manualCredential?.grantId);
    const manualPreflightAllowed = Boolean(manualMcp?.preflight?.status === "allowed"
      && manualMcp.preflight.operationIdMatches && manualMcp.protocolPinned
      && manualMcp.protocolVersion === "2026-07-28" && manualMcp.protocolEra === "modern");
    const oauthPreflightAllowed = Boolean(activeMcp?.preflight?.status === "allowed"
      && activeMcp.preflight.operationIdMatches && activeMcp.protocolPinned
      && activeMcp.protocolVersion === "2026-07-28" && activeMcp.protocolEra === "modern");
    const manualIdentityParity = Boolean(manualCredential?.status === 201 && manualCredential.secretShownOnce
      && manualCredential.secretDismissed && manualCredential.secretAvailableAtIssue
      && manualCredentialRow && manualGrantRow && manualCredentialRow.owner_id === ownerId
      && manualCredentialRow.agent_id === agent.id && manualCredentialRow.source === "manual"
      && manualCredentialRow.grant_id === manualCredential.grantId && manualGrantRow.id === manualCredential.grantId
      && manualCredentialRow.resource === resource && manualCredentialRow.role === "agent"
      && manualCredentialRow.grant_revoked_at === null
      && manualCredentialRow.access_generation === approvedGrant?.access_generation
      && manualPreflightAllowed && oauthPreflightAllowed
      && manualMcp.preflight.policyVersion === activeMcp.preflight.policyVersion
      && manualMcp.preflight.accessGeneration === activeMcp.preflight.accessGeneration);
    const mcpDenied = (result) => Boolean(result?.preflight?.status === "denied"
      || result?.requests?.some((request) => [401, 403].includes(request.status)));
    const durableRevocationAfterRestart = Boolean(apiRestart.completed
      && mcpDenied(revokedMcp) && mcpDenied(manualPostRevokeMcp)
      && mcpDenied(postRestartMcp) && mcpDenied(manualPostRestartMcp)
      && afterRevoke.grants.some((row) => row.id === consent.flowId || row.id === approvedRow?.grant_id
        ? row.revoked_at !== null : false)
      && afterRevoke.manualCredentials.some((row) => row.id === manualCredential?.credentialId
        && row.grant_id === manualCredential?.grantId && row.grant_revoked_at !== null));
    const sc003Ready = Boolean(exchangeSuccessful && approvedGrantBound && codeConsumed && invalidExchangesDenied
      && scopeEscalationDenied);

    const browserData = {
      ownerId,
      agentId: agent.id,
      agentName: agent.name,
      initialPolicyRevision: agent.policyRevision,
      clientId,
      resource,
      serverUrl,
      mcpAuthorizationChallenge: mcpChallenge.evidence,
      redirectPath: new URL(callbackUrl).pathname,
      scope: MCP_SCOPE,
      scopeLabel: "local synthetic owner OAuth and pinned MCP SDK; not Google or third-party-client compatibility",
      freshAgentViaOwnerUi: true,
      foreignOwnerId: foreign.ownerId,
      foreignAgentId: foreign.agentId,
      consentAndExchange: approved.browserData,
      deniedConsent: denied.browserData,
      foreignSelection: foreignSelection.browserData,
      scopeEscalation: scopeEscalation.browserData,
      agentSelectionChange: agentSelectionChange.browserData,
      selectionSubstitution: selectionSubstitution.browserData,
      exchangeNegatives,
      codeReplay,
      codeExpiry: { flow: expiryFlow?.browserData ?? null, fixture: expiryFixture, exchange: expiryAttempt },
      mcp: { preflightOperationId, ...activeMcp },
      pairedManualCredential: { ...manualCredential, preflightOperationId: manualPreflightOperationId,
        manualIdentityParity, mcpPreflight: manualMcp },
      globalRevoke: revokeResult,
      postRevokeMcp: revokedMcp,
      manualPostRevokeMcp,
      apiRestart,
      postRestartMcp,
      manualPostRestartMcp,
      durableRevocationAfterRestart,
      actualDomainOperationAvailable: false,
      selectionOperationIds,
      capture: captureApi.capture,
      foreignCapture: foreignCapture.capture,
    };
    const databaseData = { observer: beforeRevoke.observer, beforeRevoke, afterRevoke };

    // SC015 remains blocked because this MCP surface currently offers only free preflight.
    // The two narrower gates only become ready if browser, verifier, audit, negative
    // and independent PostgreSQL observations all match their approved contracts.
    return { sc002Ready, sc003Ready, browserData, databaseData };
  } catch (error) {
    const safeName = safeExceptionName(error);
    const wrapped = new Error(`AAP OAuth acceptance failed at ${phase} (${safeName})`);
    wrapped.code = `AAP_OAUTH_${phase.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}`;
    if (error?.safeDiagnostic && typeof error.safeDiagnostic === "object") {
      wrapped.safeDiagnostic = error.safeDiagnostic;
    } else if (phase === "browser_owner_selection_consent_and_provider_exchange" && approved) {
      wrapped.safeDiagnostic = safePositiveOAuthDiagnostic(approved);
    }
    throw wrapped;
  } finally {
    if (agent && !revoked) {
      await revokeAgentThroughOwnerUi(page, agent.id, captureApi).catch(() => undefined);
    }
    for (const session of sessions) session.clearSensitive();
    pairedManualToken = "";
    if (foreign?.context) await foreign.context.close().catch(() => undefined);
    if (callbackReceiver) await callbackReceiver.close().catch(() => undefined);
  }
}
