import { randomBytes, randomUUID, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import pg from "pg";
import { assertSecretFree, beginScenarioRun, publishScenarioIndex, sha256, writeJsonArtifact, writeManifest } from "./evidence.mjs";
import { attachSafeBrowserCapture, currentOwner, waitForPath } from "./browser-support.mjs";
import { startGoogleFixtureServer } from "./google-fixture-server.mjs";
import { OwnerDatabaseObserver } from "./observer.mjs";
import { linkWalletAndReturn, runInvalidWalletCases } from "./wallet-cases.mjs";
import { runGoogleBrowserFailures, runGoogleClaimMatrix } from "./google-browser-cases.mjs";
import { runFreshSiweProtocol } from "./siwe-protocol-cases.mjs";
import { runAdmissionRace } from "./admission-race.mjs";
import { runSessionCases } from "./session-cases.mjs";
import { runGoogleLinkStartRace } from "./link-start-race.mjs";
import { runAapCardCases } from "./aap-cases.mjs";
import { saveAapEvidence } from "./aap-evidence.mjs";
import { runAapCredentialCases } from "./credential-cases.mjs";
import { runAapOauthCases } from "./oauth-cases.mjs";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repoRoot = resolve(packageRoot, "../..");
const publicOrigin = process.env.OID_PUBLIC_ORIGIN ?? "http://127.0.0.1:3000";
const apiOrigin = process.env.OID_ACCEPTANCE_API_ORIGIN ?? "http://127.0.0.1:8784";
const adminSubject = "oid-admin-fixture-sub";
const clientId = "oid-local-" + randomBytes(8).toString("hex") + ".apps.example.invalid";
const clientSecret = randomBytes(32).toString("base64url");
const runId = randomUUID();
const activeContract = JSON.parse(await readFile(resolve(repoRoot, "tests/bdd/changes/owner-identity-and-pilot-admission/harness-contracts.json"), "utf8"));
const contractRows = activeContract.protected_scenarios;
const REQUIRED = Object.fromEntries(Object.entries(contractRows).map(([scenarioId, row]) => [scenarioId, row.required_observations]));
const NEGATIVES = Object.fromEntries(Object.entries(contractRows).map(([scenarioId, row]) => [scenarioId, row.negative_variants]));
const children = [];
const digest = (value) => createHash("sha256").update(String(value), "utf8").digest("hex");
const pause = (ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
const pnpm = process.env.OID_PNPM_BIN ?? "pnpm";
let fixture;
let observer;
let browser;
let phase = "startup";
let apiChild;
let apiEnvironment;
let databaseIsolation;

async function isolateAcceptanceDatabase() {
  const ownerUrl = new URL(process.env.OID_DATABASE_URL);
  const observerUrl = new URL(process.env.OID_OBSERVER_DATABASE_URL);
  if (ownerUrl.hostname !== "postgres" || observerUrl.hostname !== "postgres"
    || ownerUrl.username !== "oid_owner" || observerUrl.username !== "oid_observer") {
    throw new Error("Acceptance database creation requires the declared Docker fixture roles and host");
  }
  const databaseName = `oid_acceptance_${runId.replaceAll("-", "")}`;
  if (!/^oid_acceptance_[a-f0-9]{32}$/.test(databaseName)) throw new Error("Invalid acceptance database identity");
  const admin = new pg.Client({ connectionString: ownerUrl.href });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
  } finally { await admin.end(); }
  ownerUrl.pathname = `/${databaseName}`;
  observerUrl.pathname = `/${databaseName}`;
  const setup = new pg.Client({ connectionString: ownerUrl.href });
  await setup.connect();
  try {
    await setup.query(`GRANT CONNECT ON DATABASE "${databaseName}" TO oid_observer`);
    await setup.query("GRANT USAGE ON SCHEMA public TO oid_observer");
    await setup.query("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer");
  } finally { await setup.end(); }
  // AICODE-NOTE: Each run randomizes the auth secret. Persisted JWT private keys
  // are encrypted with that secret, so reusing another run's JWKS breaks login.
  // Keep the whole fixture DB isolated and retained; never delete shared keys.
  process.env.OID_DATABASE_URL = ownerUrl.href;
  process.env.OID_OBSERVER_DATABASE_URL = observerUrl.href;
  databaseIsolation = { databaseName, runId, createdForCapture: true, retainedForInspection: true };
}

function requireLoopbackOrigin(value, name) {
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(url.hostname)) throw new Error(name + " must be loopback HTTP");
  return url.origin;
}

function startChild(args, env, label, executable = pnpm) {
  const child = spawn(executable, args, {
    cwd: repoRoot,
    env,
    stdio: "ignore",
    detached: true,
    windowsHide: true,
  });
  child.label = label;
  children.push(child);
  child.on("exit", (code, signal) => {
    if (code !== null && code !== 0) console.error(JSON.stringify({ event: "oid_child_exit", label, code, signal }));
  });
  return child;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  try { process.kill(-child.pid, "SIGTERM"); } catch { return; }
  await Promise.race([new Promise((done) => child.once("exit", done)), pause(3000)]);
  if (child.exitCode === null) {
    try { process.kill(-child.pid, "SIGKILL"); } catch { /* already exited */ }
  }
}

async function restartOwnerApi() {
  await stopChild(apiChild);
  apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnvironment, "restarted API", process.execPath);
  await waitHttp(new URL("/healthz", apiOrigin), (response) => response.ok, "restarted owner API");
}

async function runCommand(args, env, label) {
  const child = spawn(pnpm, args, { cwd: repoRoot, env, stdio: "ignore" });
  const result = await new Promise((resolvePromise, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolvePromise({ code, signal }));
  });
  if (result.code !== 0) throw new Error(label + " failed with exit " + String(result.code ?? result.signal));
}

async function waitHttp(url, predicate, label) {
  const end = Date.now() + 60_000;
  while (Date.now() < end) {
    try {
      const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(1500) });
      if (await predicate(response)) return response;
    } catch { /* service is still starting */ }
    await pause(250);
  }
  throw new Error(label + " did not become ready");
}

async function startRuntime() {
  phase = "runtime_preflight";
  if (process.platform !== "linux") throw new Error("Run owner acceptance inside the pinned Linux Docker runtime");
  requireLoopbackOrigin(publicOrigin, "OID_PUBLIC_ORIGIN");
  requireLoopbackOrigin(apiOrigin, "OID_ACCEPTANCE_API_ORIGIN");
  if (publicOrigin !== "http://127.0.0.1:3000" || apiOrigin !== "http://127.0.0.1:8784") throw new Error("The acceptance origins are pinned to 127.0.0.1 ports 3000 and 8784");
  if (!process.env.OID_DATABASE_URL || !process.env.OID_OBSERVER_DATABASE_URL) throw new Error("OID_DATABASE_URL and OID_OBSERVER_DATABASE_URL are required");
  if (!process.env.OID_CHROMIUM_EXECUTABLE) throw new Error("OID_CHROMIUM_EXECUTABLE is required");

  phase = "isolated_acceptance_database";
  await isolateAcceptanceDatabase();

  phase = "local_google_fixture";
  fixture = await startGoogleFixtureServer({ host: "127.0.0.1", port: 0, clientId, clientSecret, publicOrigin });
  const preload = resolve(packageRoot, "src/google-fetch-preload.mjs");
  const apiEnv = {
    ...process.env,
    OID_PUBLIC_ORIGIN: publicOrigin,
    OID_API_HOST: "127.0.0.1",
    OID_API_PORT: "8784",
    OID_GOOGLE_CLIENT_ID: clientId,
    OID_GOOGLE_CLIENT_SECRET: clientSecret,
    OID_GOOGLE_FIXTURE_ORIGIN: fixture.origin,
    OID_ADMIN_PROVIDER: "google",
    OID_ADMIN_SUBJECT: adminSubject,
    OID_REGISTRATION_MODE: "closed",
    OID_AUTH_RATE_LIMIT_MAX: "120",
    OID_SIWE_RATE_LIMIT_MAX: "120",
    OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX: "120",
    NODE_ENV: "development",
  };
  // Keep acceptance rate buckets and cookies isolated across independent runs.
  apiEnv.OID_AUTH_SECRET = randomBytes(48).toString("base64url");
  apiEnv.NODE_OPTIONS = [apiEnv.NODE_OPTIONS, "--import=" + preload].filter(Boolean).join(" ");

  phase = "database_migration";
  await runCommand(["--filter", "@web-agent-bench/owner-identity", "build"], apiEnv, "API build");
  await runCommand(["--filter", "@web-agent-bench/owner-identity", "migrate"], apiEnv, "database migration");
  phase = "owner_api_startup";
  apiEnvironment = apiEnv;
  apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnv, "API", process.execPath);
  await waitHttp(new URL("/healthz", apiOrigin), async (response) => {
    if (!response.ok) return false;
    return (await response.json().catch(() => ({}))).status === "ok";
  }, "owner API");

  phase = "owner_web_startup";
  const webEnv = { ...process.env, OID_API_URL: apiOrigin, HOSTNAME: "127.0.0.1", NODE_ENV: "production" };
  startChild(["--filter", "@web-agent-bench/owner-web", "exec", "next", "start", "-p", "3000", "-H", "127.0.0.1"], webEnv, "web");
  await waitHttp(publicOrigin, (response) => response.status >= 200 && response.status < 500, "owner web");
  phase = "observer_and_browser_startup";
  const configResponse = await fetch(new URL("/api/identity/config", publicOrigin));
  if (!configResponse.ok || (await configResponse.json()).googleMode !== "provider-fixture") throw new Error("The real same-origin API proxy did not expose provider-fixture mode");
  observer = new OwnerDatabaseObserver(process.env.OID_OBSERVER_DATABASE_URL);
  const observerCheck = await observer.snapshot();
  if (observerCheck.observer.role !== "oid_observer" || observerCheck.observer.transaction_read_only !== "on") throw new Error("Independent SQL observer is not read-only");
  browser = await chromium.launch({ headless: true, executablePath: process.env.OID_CHROMIUM_EXECUTABLE, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
}

async function newContext() {
  const context = await browser.newContext({ baseURL: publicOrigin });
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (["127.0.0.1", "localhost"].includes(url.hostname)) return route.continue();
    await route.abort("blockedbyclient");
  });
  return context;
}

async function waitOwner(page, expected, timeout = 25000) {
  const end = Date.now() + timeout;
  let state;
  while (Date.now() < end) {
    state = await currentOwner(page).catch(() => ({ status: 0, owner: null }));
    if (expected === "authenticated" && state.status === 200 && state.owner) return state;
    if (expected === "anonymous" && state.status === 401) return state;
    await pause(200);
  }
  throw new Error("Owner API did not reach " + expected + " state");
}

async function googleLogin(context, scenarioId, subject) {
  const page = await context.newPage();
  const captureApi = attachSafeBrowserCapture(page, scenarioId);
  const capture = captureApi.capture;
  const fixtureRoute = await captureApi.providerRoute(context, fixture.origin, { subject });
  await page.goto("/sign-in", { waitUntil: "domcontentloaded" });
  captureApi.action("click", "sign-in-google");
  const callback = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/auth/callback/google", { timeout: 30000 }).catch(() => null);
  await page.getByTestId("sign-in-google").click();
  const callbackResponse = await callback;
  if (!callbackResponse) {
    console.error(JSON.stringify({ event: "oid_callback_missing", scenarioId,
      responses: capture.responses.filter((row) => row.path.startsWith("/api/")).slice(-8) }));
    throw new Error("Google callback route did not complete");
  }
  try {
    await waitForPath(page, ["/account", "/activate", "/sign-in"], 25000);
  } catch (error) {
    const location = callbackResponse.headers().location;
    console.error(JSON.stringify({ event: "oid_callback_navigation_incomplete", scenarioId,
      callbackStatus: callbackResponse.status(), pagePath: new URL(page.url()).pathname,
      callbackLocationPath: location ? new URL(location, publicOrigin).pathname : null,
      responses: capture.responses.filter((row) => row.path.startsWith("/api/")).slice(-8) }));
    throw error;
  }
  const owner = await waitOwner(page, "authenticated", 5000).catch(() => waitOwner(page, "anonymous", 5000));
  return { page, capture, captureApi, fixtureRoute, owner };
}

async function saveScenario011({ adminCapture, ownerCapture, owner, invite, issueOperation, activationOperation, verifierMatches, observerRows, provenance, walletResult, failedFlows, activation, googleSubjectSha256 }) {
  const scenarioId = "OID-SC-011";
  const run = await beginScenarioRun(scenarioId);
  const payloads = [
    ["browser.json", "actual browser click and same-origin request metadata; raw invitation, OAuth code/state, cookies and signatures omitted", {
      scenarioId,
      providerScope: "local synthetic Google OAuth adapter and no external account",
      admin: adminCapture,
      owner: ownerCapture,
      ownerId: owner.id,
      invitationId: invite.id,
      inviteIssueOperationId: issueOperation,
      activationOperationId: activationOperation,
      invitationVerifierMatches: verifierMatches,
      login: ownerCapture,
      googleSubjectSha256,
      activation: { ...ownerCapture, ...activation },
      walletLink: { ...walletResult.linkCapture, linkOperationId: walletResult.linkOperationId, walletAudit: walletResult.walletAudit },
      returnedWalletLogin: { ...walletResult.returnCapture, sameOwner: walletResult.sameOwner, hasBothMethods: walletResult.providers.includes("google") && walletResult.providers.includes("wallet") },
      failedFlows,
    }],
    ["database.json", "independent read-only PostgreSQL observation", observerRows],
    ["provider.json", "local Google fixture events with subjects hashed", {
      events: fixture.events().map(({ subject, ...event }) => ({ ...event, ...(subject ? { subjectSha256: digest(subject) } : {}) })),
      externalProviderUsed: false,
    }],
    ["crypto.json", "provider token signature verification and admission verifier comparison; no signing material", {
      oauthProfile: "RS256, issuer and audience checked by the Better Auth Google adapter",
      invitationVerifierMatches: verifierMatches,
      invocationPrivateKeyOrTokenPersisted: false,
    }],
    ["provenance.json", "local runtime declaration and safe source file hashes", provenance],
  ];
  const artifacts = [];
  for (const [name, boundary, data] of payloads) artifacts.push(await writeJsonArtifact(scenarioId, name, boundary, data, run.directory));
  const observations = {
    actual_auth_admission_link_pages: { status: "observed", evidence: ["browser.json", "database.json"] },
    real_server_verification: { status: "observed", evidence: ["browser.json", "database.json", "provider.json"] },
    failed_flow_no_fake_success: { status: "observed", evidence: ["browser.json", "database.json"] },
    safe_secret_free_evidence: { status: "observed", evidence: ["browser.json", "crypto.json"] },
    local_provider_scope_label: { status: "observed", evidence: ["provenance.json", "provider.json"] },
  };
  const negatives = {
    abandoned_login: { status: "observed", evidence: ["browser.json", "database.json"] },
    provider_denies: { status: "observed", evidence: ["browser.json", "database.json"] },
    invalid_signature: { status: "observed", evidence: ["browser.json", "database.json"] },
    failed_invite_retry: { status: "observed", evidence: ["browser.json", "database.json"] },
    browser_session_substitution: { status: "observed", evidence: ["browser.json", "database.json"] },
  };
  const manifestPath = await writeManifest(scenarioId, {
    runId: run.runId,
    status: provenance.sourceStableDuringRun ? "passed" : "blocked",
    ...(provenance.sourceStableDuringRun ? {} : { blockedReasonCode: "source_inputs_changed_during_run" }),
    statusDetail: provenance.sourceStableDuringRun === false
      ? "Source inputs changed during this acceptance run; this result is blocked and must be rerun against a stable checkout."
      : "Local Google, admission, EOA linking and return, and declared browser negative variants executed with independent SQL evidence.",
    observationStatus: "complete",
    negativeVariantStatus: "complete",
    observations,
    negativeVariants: negatives,
    artifacts,
  }, run.directory);
  const status = provenance.sourceStableDuringRun ? "passed" : "blocked";
  await publishScenarioIndex(scenarioId, run.runId, status, status === "blocked" ? "source_inputs_changed_during_run" : undefined);
  return { scenarioId, status, manifestPath };
}

async function saveScenario009({ browserData, databaseData, providerData, provenance, facts }) {
  const scenarioId = "OID-SC-009";
  const run = await beginScenarioRun(scenarioId);
  const artifacts = [];
  for (const [name, boundary, payload] of [
    ["browser.json", "real administrator and ordinary-owner browser UI/API captures; invitation values excluded", browserData],
    ["database.json", "independent read-only PostgreSQL policy, invitation and audit rows", databaseData],
    ["provider.json", "isolated local Google fixture trace with subjects hashed", providerData],
    ["crypto.json", "invitation verifier equality computed by the read-only observer", { verifierMatches: browserData.invitation.verifierMatches }],
    ["provenance.json", "runtime declaration and pre/post source input hashes", provenance],
  ]) artifacts.push(await writeJsonArtifact(scenarioId, name, boundary, payload, run.directory));
  const obs = (name, detail) => facts[name]
    ? { status: "observed", evidence: ["browser.json", "database.json"], detail }
    : { status: "not_run", reasonCode: "admin_observation_not_established" };
  const negative = (name, detail) => facts[name]
    ? { status: "observed", evidence: ["browser.json", "database.json"], detail }
    : { status: "not_run", reasonCode: name === "agent_invite_issuance" ? "agent_controls_not_installed" : "negative_variant_not_established" };
  const observations = {
    actual_admin_pages: obs("actual_admin_pages", "Configured administrator used actual invitation and registration controls in the browser."),
    configured_admin_only: obs("configured_admin_only", "The configured identity was admin; an ordinary authenticated owner was denied the admin API."),
    invitation_verifier_not_plaintext_history: obs("invitation_verifier_not_plaintext_history", "The one-time code matched only the stored verifier; status listing omitted plaintext and verifier columns."),
    mode_change_audited: obs("mode_change_audited", "Policy updates and invitation revocation correlated to durable SQL audit rows."),
    no_first_signup_admin: obs("no_first_signup_admin", "A first-time ordinary identity stayed non-admin after admission."),
  };
  const negatives = {
    ordinary_owner_admin_api: negative("ordinary_owner_admin_api", "Ordinary authenticated owner received 403 from the real admin API."),
    agent_invite_issuance: negative("agent_invite_issuance", "Agent credential authority is outside this application and was not tested."),
    first_signup_role_claim: negative("first_signup_role_claim", "Ordinary first signup returned isAdmin=false."),
    unused_invite_revocation_retry: negative("unused_invite_revocation_retry", "The administrator revoked the unused invitation through the real UI and SQL confirmed revocation."),
  };
  const manifestPath = await writeManifest(scenarioId, {
    runId: run.runId,
    status: "blocked",
    blockedReasonCode: "agent_control_boundary_unavailable",
    statusDetail: "Owner administration UI/API and SQL audit were exercised; agent issuance authority remains outside the local app.",
    observationStatus: Object.values(observations).every((item) => item.status === "observed") ? "complete" : "partial",
    negativeVariantStatus: Object.values(negatives).every((item) => item.status === "observed") ? "complete" : "partial",
    observations,
    negativeVariants: negatives,
    artifacts,
  }, run.directory);
  await publishScenarioIndex(scenarioId, run.runId, "blocked", "agent_control_boundary_unavailable");
  return { scenarioId, status: "blocked", manifestPath };
}

async function saveBlockedScenario(scenarioId, reasonCode, reason, provenance, databaseData, browserData = undefined) {
  const run = await beginScenarioRun(scenarioId);
  const artifacts = [];
  for (const [name, boundary, payload] of [
    ["browser.json", "Partial local observations do not establish the missing full boundary", browserData ?? {
      scenarioId, noScenarioSpecificMutationAttempted: true, blocker: reasonCode, reason,
    }],
    ["database.json", "independent read-only observer; no scenario-specific mutation asserted", databaseData],
    ["provider.json", "external provider accounts were not used", { externalProviderUsed: false }],
    ["crypto.json", "no cryptographic success claimed for this blocked scenario", { noUnsupportedProofClaimed: true }],
    ["provenance.json", "runtime profile and source hashes", provenance],
  ]) artifacts.push(await writeJsonArtifact(scenarioId, name, boundary, payload, run.directory));
  const notRun = (name) => ({ status: "not_run", reasonCode, detail: reason });
  const observations = Object.fromEntries(REQUIRED[scenarioId].map((name) => [name, notRun(name)]));
  const negatives = Object.fromEntries(NEGATIVES[scenarioId].map((name) => [name, notRun(name)]));
  if (scenarioId === "OID-SC-008" && browserData) {
    const local = { status: "observed", evidence: ["browser.json", "database.json"], detail: "Local session boundary; agent authority is separately blocked." };
    for (const name of ["origin_csrf_checked", "logout_session_invalidated"]) observations[name] = local;
    for (const name of ["expired_session", "forged_owner_admin_id", "cross_origin_mutation", "reused_logged_out_session"]) negatives[name] = local;
  }
  const manifestPath = await writeManifest(scenarioId, {
    runId: run.runId,
    status: "blocked",
    blockedReasonCode: reasonCode,
    statusDetail: reason,
    observationStatus: Object.values(observations).some((row) => row.status === "observed") ? "partial" : "not_run",
    negativeVariantStatus: Object.values(negatives).some((row) => row.status === "observed") ? "partial" : "not_run",
    observations,
    negativeVariants: negatives,
    artifacts,
  }, run.directory);
  await publishScenarioIndex(scenarioId, run.runId, "blocked", reasonCode);
  return { scenarioId, status: "blocked", manifestPath };
}

async function saveCompleteScenario(scenarioId, browserData, databaseData, provenance) {
  const run = await beginScenarioRun(scenarioId);
  const artifacts = [];
  for (const [name, boundary, payload] of [
    ["browser.json", "Actual browser actions and allowlisted HTTP-negative observations", browserData],
    ["database.json", "Independent read-only PostgreSQL rows", databaseData],
    ["provider.json", "Local provider transport events", { events: fixture.events().map(({ subject, ...event }) => ({ ...event, ...(subject ? { subjectSha256: digest(subject) } : {}) })), externalProviderUsed: false }],
    ["crypto.json", "Real local verifier boundary; no signing material retained", { scheme: "RS256 and EOA SIWE", externalProviderUsed: false }],
    ["provenance.json", "Source and container runtime provenance", provenance],
  ]) artifacts.push(await writeJsonArtifact(scenarioId, name, boundary, payload, run.directory));
  const status = provenance.sourceStableDuringRun ? "passed" : "blocked";
  const record = () => ({ status: "observed", evidence: ["browser.json", "database.json", "provider.json"] });
  const manifestPath = await writeManifest(scenarioId, {
    runId: run.runId, status, observationStatus: "complete", negativeVariantStatus: "complete",
    ...(status === "blocked" ? { blockedReasonCode: "source_inputs_changed_during_run" } : {}),
    observations: Object.fromEntries(REQUIRED[scenarioId].map((name) => [name, record()])),
    negativeVariants: Object.fromEntries(NEGATIVES[scenarioId].map((name) => [name, record()])), artifacts,
  }, run.directory);
  await publishScenarioIndex(scenarioId, run.runId, status, status === "blocked" ? "source_inputs_changed_during_run" : undefined);
  return { scenarioId, status, manifestPath };
}

async function collectSourceHashes() {
  const roots = [
    resolve(repoRoot, "packages/owner-acceptance"),
    resolve(repoRoot, "packages/owner-identity"),
    resolve(repoRoot, "packages/owner-web"),
    resolve(repoRoot, "tests/bdd/adapters/owner_identity_and_pilot_admission.py"),
    resolve(repoRoot, "tests/bdd/adapters/oid_evidence_verifier.py"),
    resolve(repoRoot, "tests/bdd/mappers/test_owner_identity_and_pilot_admission_bdd.py"),
    resolve(repoRoot, "tests/bdd/features/owner_identity_and_pilot_admission.feature"),
    resolve(repoRoot, "tests/bdd/changes/owner-identity-and-pilot-admission"),
    resolve(repoRoot, "openspec/changes/owner-identity-and-pilot-admission"),
    resolve(repoRoot, "openspec/changes/agent-access-and-permissions"),
    resolve(repoRoot, "tests/bdd/changes/agent-access-and-permissions"),
    resolve(repoRoot, "tests/bdd/adapters/agent_access_and_permissions.py"),
    resolve(repoRoot, "tests/bdd/adapters/aap_evidence_verifier.py"),
    resolve(repoRoot, "tests/bdd/features/agent_access_and_permissions.feature"),
    resolve(repoRoot, "tests/bdd/mappers/test_agent_access_and_permissions_bdd.py"),
    resolve(repoRoot, "tools/replay_oid_acceptance.py"),
    resolve(repoRoot, "tools/replay_aap_acceptance.py"),
    resolve(repoRoot, "tools/harness_contracts.py"),
    resolve(repoRoot, "tools/run_bdd_acceptance.py"),
    resolve(repoRoot, "package.json"),
    resolve(repoRoot, "pnpm-workspace.yaml"),
    resolve(repoRoot, "pnpm-lock.yaml"),
    resolve(repoRoot, "Dockerfile"),
    resolve(repoRoot, ".dockerignore"),
    resolve(repoRoot, "infrastructure/owner-identity"),
  ];
  const extensions = new Set([".json", ".mjs", ".ts", ".tsx", ".py", ".feature", ".md", ".yaml", ".yml", ".sh", ".ps1", ".css"]);
  const files = [];
  async function visit(path) {
    let info;
    try { info = await stat(path); } catch { return; }
    if (info.isDirectory()) {
      for (const entry of await readdir(path, { withFileTypes: true })) {
        if (["node_modules", ".next", "dist", "artifacts", "coverage", "__pycache__"].includes(entry.name) || entry.name.startsWith(".env")) continue;
        if (entry.name === "scenario-map.md" || entry.name === "acceptance-evidence.json") continue;
        await visit(resolve(path, entry.name));
      }
    } else if (info.isFile()) {
      const extension = path.slice(path.lastIndexOf("."));
      if ((extensions.has(extension) || [".dockerignore", "Dockerfile"].includes(path.slice(path.lastIndexOf(sep) + 1))) && !path.split(sep).includes("node_modules")) files.push(path);
    }
  }
  for (const path of roots) await visit(path);
  const unique = [...new Set(files)].sort();
  const inputs = [];
  for (const path of unique) {
    const content = await readFile(path);
    inputs.push({ path: relative(repoRoot, path).split(sep).join("/"), sha256: sha256(content), bytes: content.length });
  }
  return inputs;
}

async function main() {
  let finalStatus = "failed";
  try {
    await startRuntime();
    phase = "hash_source_inputs_before";
    const sourceHashesBefore = await collectSourceHashes();
    phase = "admin_google_browser_flow";
    const adminContext = await newContext();
    const admin = await googleLogin(adminContext, "OID-SC-011", adminSubject);
    if (admin.owner.status !== 200 || admin.owner.owner?.isAdmin !== true) throw new Error("Configured administrator login was not confirmed by /api/owner");
    await admin.page.goto("/admin", { waitUntil: "domcontentloaded" });
    await admin.page.getByTestId("invite-create").waitFor({ state: "visible", timeout: 15000 });
    await admin.page.getByTestId("invite-expiry").fill("3600");
    admin.captureApi.action("click", "invite-create");
    const issueResponse = admin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/invitations" && response.request().method() === "POST", { timeout: 15000 });
    await admin.page.getByTestId("invite-create").click();
    const issueHttp = await issueResponse;
    if (issueHttp.status() !== 201) throw new Error("Admin UI invitation issuance did not return 201");
    const secretBlock = admin.page.getByTestId("invite-secret-once");
    await secretBlock.waitFor({ state: "visible", timeout: 10000 });
    const inviteSecret = (await secretBlock.locator("code").first().innerText()).trim();
    const inviteDescription = await secretBlock.innerText();
    const idMatch = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.exec(inviteDescription);
    if (!/^oid_[A-Za-z0-9_-]{32,}$/.test(inviteSecret) || !idMatch) throw new Error("The admin UI did not show a one-time invitation secret and ID");
    const inviteId = idMatch[0];
    const issueOperation = admin.capture.requests.find((item) => item.path === "/api/admin/invitations" && item.method === "POST")?.operationId;
    const verifierMatches = await observer.verifierMatches(inviteId, inviteSecret);
    const adminList = await admin.page.request.get("/api/admin/invitations");
    const adminListPayload = await adminList.json();
    const listExcludesSecret = !JSON.stringify(adminListPayload).includes(inviteSecret);
    if (!listExcludesSecret) throw new Error("Invitation status endpoint exposed the one-time secret");

    await admin.page.getByTestId("invite-expiry").fill("3600");
    admin.captureApi.action("click", "invite-create");
    const secondIssueResponse = admin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/invitations" && response.request().method() === "POST", { timeout: 15000 });
    await admin.page.getByTestId("invite-create").click();
    const secondIssueHttp = await secondIssueResponse;
    if (secondIssueHttp.status() !== 201) throw new Error("Admin UI did not issue the separate unused invitation for revocation");
    const secondSecretBlock = admin.page.getByTestId("invite-secret-once");
    await secondSecretBlock.waitFor({ state: "visible", timeout: 10000 });
    const secondSecret = (await secondSecretBlock.locator("code").first().innerText()).trim();
    const secondDescription = await secondSecretBlock.innerText();
    const secondIdMatch = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i.exec(secondDescription);
    if (!/^oid_[A-Za-z0-9_-]{32,}$/.test(secondSecret) || !secondIdMatch || secondIdMatch[0] === inviteId) {
      throw new Error("The second one-time invitation was not uniquely identified");
    }
    const sc009InviteId = secondIdMatch[0];
    const sc009IssueOperation = admin.capture.requests
      .filter((item) => item.path === "/api/admin/invitations" && item.method === "POST")
      .at(-1)?.operationId;
    const sc009VerifierMatches = await observer.verifierMatches(sc009InviteId, secondSecret);
    const adminListAfterSecond = await admin.page.request.get("/api/admin/invitations");
    const adminListAfterSecondPayload = await adminListAfterSecond.json();
    const sc009ListExcludesSecrets = !JSON.stringify(adminListAfterSecondPayload).includes(inviteSecret)
      && !JSON.stringify(adminListAfterSecondPayload).includes(secondSecret);
    if (!sc009ListExcludesSecrets) throw new Error("Invitation status endpoint exposed a one-time secret");

    phase = "owner_invitation_browser_flow";
    const ownerContext = await newContext();
    const ownerSubject = "oid-pilot-" + randomBytes(5).toString("hex");
    const ownerLogin = await googleLogin(ownerContext, "OID-SC-011", ownerSubject);
    if (ownerLogin.owner.status !== 200 || ownerLogin.owner.owner?.admissionStatus !== "pending" || ownerLogin.owner.owner?.isAdmin !== false) {
      throw new Error("Ordinary verified owner was not pending and non-admin under closed registration");
    }
    const ownerId = ownerLogin.owner.owner.id;
    await ownerLogin.page.getByTestId("invitation-code").fill("oid_invalid_fixture_code");
    ownerLogin.captureApi.action("click", "activate-owner");
    const invalidActivationResponse = ownerLogin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admission/activate" && response.request().method() === "POST");
    await ownerLogin.page.getByTestId("activate-owner").click();
    const invalidInvitationStatus = (await invalidActivationResponse).status();
    await ownerLogin.page.locator(".status-box.status-error").waitFor();
    const pendingAfterInvalid = (await currentOwner(ownerLogin.page)).owner?.admissionStatus === "pending";
    const invalidSnapshot = await observer.snapshot({ ownerIds: [ownerId], invitationIds: [inviteId] });
    if (invalidInvitationStatus < 400 || !pendingAfterInvalid || invalidSnapshot.redemptions.length || invalidSnapshot.invitations.find((row) => row.id === inviteId)?.redeemed_at) {
      throw new Error("Invalid activation affected admission or consumed the valid invitation");
    }
    await ownerLogin.page.getByTestId("invitation-code").fill(inviteSecret);
    ownerLogin.captureApi.action("click", "activate-owner");
    const activationResponse = ownerLogin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admission/activate" && response.request().method() === "POST", { timeout: 15000 });
    await ownerLogin.page.getByTestId("activate-owner").click();
    const activationHttp = await activationResponse;
    if (activationHttp.status() !== 200) throw new Error("Activation UI did not receive a successful response");
    await waitForPath(ownerLogin.page, ["/account"], 15000);
    const confirmed = await waitOwner(ownerLogin.page, "authenticated");
    if (confirmed.owner?.id !== ownerId || confirmed.owner?.admissionStatus !== "admitted") throw new Error("Activation did not confirm the same admitted owner in the real owner projection");
    const activationOperation = ownerLogin.capture.requests.filter((item) => item.path === "/api/admission/activate" && item.method === "POST").at(-1)?.operationId;
    phase = "wallet_link_and_return";
    const walletResult = await linkWalletAndReturn({ context: ownerContext, page: ownerLogin.page, scenarioId: "OID-SC-011", expectedOwnerId: ownerId });
    if (!walletResult.sameOwner) throw new Error("Returning wallet login changed the owner identity");
    phase = "negative_wallet_browser_matrix";
    const walletFailures = await runInvalidWalletCases({ browser, publicOrigin, scenarioId: "OID-SC-011" });
    phase = "negative_google_browser_matrix";
    const googleFailures = await runGoogleBrowserFailures({ browser, publicOrigin, fixtureOrigin: fixture.origin, scenarioId: "OID-SC-011" });
    const failedFlows = [...walletFailures.failedFlows, ...googleFailures];
    if (failedFlows.some((row) => row.ownerStatus !== 401)) throw new Error("A negative browser flow established an authenticated owner");
    phase = "google_claim_matrix";
    const googleMatrix = await runGoogleClaimMatrix({ browser, fixtureOrigin: fixture.origin, publicOrigin });
    phase = "siwe_protocol_matrix";
    const siweMatrix = await runFreshSiweProtocol({ browser, publicOrigin, admittedPage: ownerLogin.page, failures: walletFailures.failedFlows });

    phase = "admin_policy_and_revocation_browser_flow";
    const policyBeforeResponse = await admin.page.request.get("/api/admin/registration-policy");
    const policyBefore = await policyBeforeResponse.json();
    await admin.page.getByTestId("registration-mode").selectOption("open");
    admin.captureApi.action("click", "registration-save");
    const openPolicyResponse = admin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/registration-policy" && response.request().method() === "PUT", { timeout: 15000 });
    await admin.page.getByTestId("registration-save").click();
    const openPolicyHttp = await openPolicyResponse;
    if (openPolicyHttp.status() !== 200) throw new Error("Admin UI did not persist the open registration policy");
    await admin.page.getByTestId("registration-mode").selectOption("closed");
    admin.captureApi.action("click", "registration-save");
    const closedPolicyResponse = admin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/registration-policy" && response.request().method() === "PUT", { timeout: 15000 });
    await admin.page.getByTestId("registration-save").click();
    const closedPolicyHttp = await closedPolicyResponse;
    if (closedPolicyHttp.status() !== 200) throw new Error("Admin UI did not restore closed registration policy");
    const policyOperations = admin.capture.requests
      .filter((item) => item.path === "/api/admin/registration-policy" && item.method === "PUT")
      .map((item) => item.operationId);
    const finalPolicy = await admin.page.request.get("/api/admin/registration-policy").then((response) => response.json());
    const revokeTestId = "invite-revoke-" + sc009InviteId;
    admin.captureApi.action("click", "invite-revoke");
    const revokeResponse = admin.page.waitForResponse((response) => new URL(response.url()).pathname === "/api/admin/invitations/" + sc009InviteId + "/revoke" && response.request().method() === "POST", { timeout: 15000 });
    await admin.page.getByTestId(revokeTestId).click();
    const revokeHttp = await revokeResponse;
    if (revokeHttp.status() !== 200) throw new Error("Admin UI did not revoke the unused invitation");
    const revokeOperation = admin.capture.requests.find((item) => item.path === "/api/admin/invitations/" + sc009InviteId + "/revoke")?.operationId;
    const ordinaryAdminResponse = await ownerLogin.page.request.get("/api/admin/invitations");
    if (ordinaryAdminResponse.status() !== 403) throw new Error("An ordinary owner was not denied the admin invitation endpoint");
    phase = "admission_race_response_loss_and_restart";
    const race = await runAdmissionRace({
      adminPage: admin.page, newContext,
      login: (context, subject) => googleLogin(context, "OID-SC-003", subject), observer,
      restartApi: restartOwnerApi,
    });

    phase = "concurrent_google_link_starts";
    const linkStartRace = await runGoogleLinkStartRace({ adminPage: admin.page, newContext, observer });
    phase = "owner_session_logout_and_expiry";
    const sessionCases = await runSessionCases({
      adminPage: admin.page, newContext,
      login: (context, subject) => googleLogin(context, "OID-SC-008", subject),
      observer, databaseUrl: process.env.OID_DATABASE_URL,
    });

    phase = "private_agent_card_and_policy_browser_flow";
    const aap = await runAapCardCases({ page: ownerLogin.page, ownerId, adminPage: admin.page, newContext,
      login: (context, subject) => googleLogin(context, "AAP-SC-001", subject),
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });

    phase = "agent_credential_issue_replace_and_revoke";
    const credentialData = await runAapCredentialCases({ page: ownerLogin.page, ownerId,
      adminPage: admin.page, newContext, publicOrigin,
      login: (context, subject) => googleLogin(context, "AAP-SC-004", subject),
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
      databaseUrl: process.env.OID_DATABASE_URL, restartApi: restartOwnerApi });

    phase = "browser_oauth_consent_and_mcp";
    const oauthData = await runAapOauthCases({ page: ownerLogin.page, ownerId,
      adminPage: admin.page, newContext, publicOrigin,
      login: (context, subject) => googleLogin(context, "AAP-SC-002", subject),
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
      databaseUrl: process.env.OID_DATABASE_URL, restartApi: restartOwnerApi });

    const operations = [
      issueOperation, sc009IssueOperation, activationOperation, revokeOperation, ...policyOperations, walletResult.linkOperationId,
      ...failedFlows.flatMap((row) => row.capture.authOperations.map((operation) => operation.operationId)),
      admin.capture.authOperations[0]?.operationId, ownerLogin.capture.authOperations[0]?.operationId,
    ].filter(Boolean);
    phase = "independent_postgres_observation";
    const observedRows = await observer.snapshot({
      operationIds: operations,
      subjects: [adminSubject, ownerSubject],
      ownerIds: [ownerId, admin.owner.owner.id],
      invitationIds: [inviteId, sc009InviteId],
      subjectHashes: failedFlows.map((row) => row.capture.walletAudit?.addressSha256).filter(Boolean),
      nonceHashes: [walletResult.linkNonceHash, ...failedFlows.flatMap((row) => row.capture.siweChallenges.map((challenge) => challenge.nonceSha256))],
    });
    const invitation = observedRows.invitations.find((item) => item.id === inviteId);
    const sc009Invitation = observedRows.invitations.find((item) => item.id === sc009InviteId);
    const admission = observedRows.admissions.find((item) => item.owner_id === ownerId);
    const redemption = observedRows.redemptions.find((item) => item.invitation_id === inviteId && item.owner_id === ownerId);
    const successAudit = observedRows.audits.find((item) => item.operation_id === activationOperation && item.event_type === "owner.admission_activated");
    if (!verifierMatches || !invitation?.redeemed_at || !admission || !redemption || !successAudit) {
      throw new Error("Read-only SQL did not confirm the invitation verifier, redemption, admission and correlated audit");
    }
    const adminPageVisible = await admin.page.getByTestId("admin-invitations").count() === 1;
    const revokeAudit = observedRows.audits.find((item) => item.operation_id === revokeOperation && item.event_type === "invitation.revoked");
    const policyAudits = policyOperations.map((operationId) => observedRows.audits.find((item) => item.operation_id === operationId && item.event_type === "registration_policy.changed"));
    const sc009Facts = {
      actual_admin_pages: adminPageVisible && admin.capture.actions.some((item) => item.selector === "invite-create") && admin.capture.actions.some((item) => item.selector === "registration-save"),
      configured_admin_only: admin.owner.owner.isAdmin === true && ownerLogin.owner.owner.isAdmin === false && ordinaryAdminResponse.status() === 403,
      invitation_verifier_not_plaintext_history: sc009VerifierMatches && sc009ListExcludesSecrets && sc009Invitation && !Object.hasOwn(sc009Invitation, "verifier_hash"),
      mode_change_audited: policyAudits.length === 2 && policyAudits.every(Boolean) && Boolean(revokeAudit) && Boolean(sc009Invitation?.revoked_at) && finalPolicy.mode === "closed",
      no_first_signup_admin: ownerLogin.owner.owner.isAdmin === false && ordinaryAdminResponse.status() === 403,
      ordinary_owner_admin_api: ordinaryAdminResponse.status() === 403,
      agent_invite_issuance: false,
      first_signup_role_claim: ownerLogin.owner.owner.isAdmin === false,
      unused_invite_revocation_retry: false,
    };
    phase = "hash_source_inputs_after";
    const sourceHashesAfter = await collectSourceHashes();
    const sourceStableDuringRun = JSON.stringify(sourceHashesBefore) === JSON.stringify(sourceHashesAfter);
    const provenance = {
      databaseIsolation,
      acceptanceRateOverrides: { authRequestsPerWindow: 120, siweRequestsPerWindow: 120,
        credentialRequestsPerWindow: 120, productionRateLimitAcceptanceClaimed: false },
      runId,
      node: process.version,
      playwright: "1.56.1",
      browserVersion: browser.version(),
      containerImageDigest: process.env.OID_ACCEPTANCE_IMAGE_DIGEST ?? "not-provided-by-runtime",
      viem: "2.47.4",
      pg: "8.16.3",
      scope: {
        profile: "local Google OAuth adapter fixture plus synthetic EIP-1193 provider",
        externalProviderUsed: false,
        externalWalletUsed: false,
        wallet: "The isMetaMask compatibility flag is simulated; no browser extension or external wallet edition was used.",
      },
      externalProviderUsed: false,
      externalWalletUsed: false,
      paymentOrFundingOperation: false,
      publicOrigin,
      apiOrigin,
      fixtureOrigin: fixture.origin,
      observer: observedRows.observer,
      sourceStableDuringRun,
      inputHashesBefore: sourceHashesBefore,
      inputHashesAfter: sourceHashesAfter,
    };
    const aapSaved = await saveAapEvidence({ ...aap, credentialData, oauthData, provenance });
    const googleMatrixRows = await observer.snapshot({ subjects: googleMatrix.subjects, operationIds: googleMatrix.operations });
    const sc001 = await saveCompleteScenario("OID-SC-001", { trials: googleMatrix.trials, callerEmailEndpoint: googleMatrix.callerEmailEndpoint }, googleMatrixRows, provenance);
    const siweMatrixRows = await observer.snapshot({ ownerIds: [siweMatrix.ownerId], subjectHashes: siweMatrix.subjectHashes, operationIds: siweMatrix.operations, nonceHashes: siweMatrix.nonceHashes });
    const sc002 = await saveCompleteScenario("OID-SC-002", siweMatrix.browserData, siweMatrixRows, provenance);
    const sc009 = await saveScenario009({
      browserData: {
        scenarioId: "OID-SC-009",
        admin: { ...admin.capture, owner: { id: admin.owner.owner.id, isAdmin: admin.owner.owner.isAdmin }, adminPageVisible },
        ordinaryOwner: { ownerId, admissionStatus: confirmed.owner.admissionStatus, isAdmin: ownerLogin.owner.owner.isAdmin, adminReadStatus: ordinaryAdminResponse.status() },
        invitation: {
          id: sc009InviteId,
          operationId: sc009IssueOperation,
          verifierMatches: sc009VerifierMatches,
          listExcludesSecret: sc009ListExcludesSecrets,
          revokeOperation,
          revoked: Boolean(sc009Invitation?.revoked_at),
          revokeAudit: Boolean(revokeAudit),
        },
        policyBefore: { mode: policyBefore.mode, revision: policyBefore.revision },
        policyAfter: { mode: finalPolicy.mode, revision: finalPolicy.revision },
      },
      databaseData: observedRows,
      providerData: { events: fixture.events().map(({ subject, ...event }) => ({ ...event, ...(subject ? { subjectSha256: digest(subject) } : {}) })) },
      provenance,
      facts: sc009Facts,
    });
    const saved = await saveScenario011({
      adminCapture: admin.capture,
      ownerCapture: ownerLogin.capture,
      owner: confirmed.owner,
      invite: { id: inviteId },
      issueOperation,
      activationOperation,
      verifierMatches,
      observerRows: observedRows,
      provenance,
      walletResult,
      failedFlows,
      activation: { invalidInvitationStatus, pendingAfterInvalid, validActivationStatus: activationHttp.status() },
      googleSubjectSha256: digest(ownerSubject),
    });
    await ownerContext.close();
    await adminContext.close();
    const blocked = [];
    const blockers = {
      "OID-SC-003": ["bonus_ledger_boundary_unavailable", "Actual two-owner invitation race, lost response, backend restart and original-operation retry were observed; the downstream no-bonus ledger boundary is unavailable."],
      "OID-SC-004": ["downstream_private_handlers_unavailable", "Local cards and delegated credentials exist; the full private-handler and funding matrix is not proven."],
      "OID-SC-005": ["ledger_boundary_unavailable", "Local agent IDs exist; balance, bonus, deposit, withdrawal and downstream identity-preservation boundaries remain unavailable."],
      "OID-SC-006": ["remaining_identity_conflict_matrix_not_run", "Two real concurrent Google link controls produced one pending flow and one conflict with unchanged identities; existing-identity collision, foreign-session substitution and downstream preservation remain untested."],
      "OID-SC-007": ["policy_race_and_ledger_boundary_not_run", "Policy controls were exercised, but race and existing agent/ledger preservation are not proven."],
      "OID-SC-008": ["downstream_revocation_boundary_unavailable", "UI logout, persisted session invalidation, old-cookie rejection, expired-session denial and origin/forged-admin negatives were observed; full session-to-agent-domain authority and cancellation integration remain unproven."],
      "OID-SC-010": ["downstream_funding_handlers_unavailable", "Local AAP cards and delegated credentials exist; the full pending-owner, bonus and funding matrix remains unproven."],
      "OID-SC-012": ["external_google_and_wallet_gate_not_run", "No external Google account or selected browser wallet was used."],
    };
    const blockedSnapshot = await observer.snapshot();
    for (const [scenarioId, [reasonCode, reason]] of Object.entries(blockers)) {
      blocked.push(await saveBlockedScenario(scenarioId, reasonCode, reason, provenance,
        scenarioId === "OID-SC-003" ? race.databaseData : scenarioId === "OID-SC-006" ? linkStartRace.databaseData : scenarioId === "OID-SC-008" ? sessionCases.databaseData : blockedSnapshot,
        scenarioId === "OID-SC-003" ? race.browserData : scenarioId === "OID-SC-006" ? linkStartRace.browserData : scenarioId === "OID-SC-008" ? sessionCases.browserData : undefined));
    }
    finalStatus = "partial_blocked";
    console.log(JSON.stringify({
      schemaVersion: "owner-identity-acceptance-summary/v1",
      runId,
      status: finalStatus,
      scenarios: [sc001, sc002, sc009, saved, ...blocked],
      counts: { passed: [sc001, sc002, sc009, saved, ...blocked].filter((row) => row.status === "passed").length, blocked: [sc001, sc002, sc009, saved, ...blocked].filter((row) => row.status === "blocked").length, failed: 0 },
      aap: { privateCardAndPolicyObserved: true, manualCredentialObserved: credentialData.sc004Ready === true,
        browserConsentObserved: oauthData.sc002Ready === true, oauthExchangeObserved: oauthData.sc003Ready === true, scenarios: aapSaved },
      observations: { adminOAuth: true, invitationIssuedInUI: true, invitationSecretExcludedFromList: true, inviteVerifierMatches: true, ownerActivationViaUI: true, independentReadOnlyPostgresRows: true },
      blockedReason: "Unsupported downstream boundaries, remaining scenario-specific negative matrices, and external OID-SC-012 compatibility remain blocked.",
    }, null, 2));
    if (!process.argv.includes("--smoke")) process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => undefined);
    await observer?.close().catch(() => undefined);
    for (const child of [...children].reverse()) await stopChild(child);
    await fixture?.close().catch(() => undefined);
  }
}

main().catch((error) => {
  let safeDiagnostic;
  try {
    if (error?.safeDiagnostic && typeof error.safeDiagnostic === "object") {
      assertSecretFree(error.safeDiagnostic, "failureDiagnostic");
      safeDiagnostic = error.safeDiagnostic;
    }
  } catch { /* Never expose a diagnostic that fails the secret filter. */ }
  const safeCode = typeof error?.code === "string" && /^[A-Z0-9_]+$/.test(error.code) ? error.code : undefined;
  const stackFrames = String(error?.stack ?? "").split("\n")
    .filter((line) => line.includes("/src/") || line.includes("\\src\\"))
    .slice(0, 8)
    .map((line) => line.trim().slice(0, 240));
  console.error(JSON.stringify({
    event: "oid_acceptance_failed",
    phase,
    errorName: error instanceof Error ? error.name : "Error",
    ...(safeCode ? { errorCode: safeCode } : {}),
    ...(safeDiagnostic ? { safeDiagnostic } : {}),
    stackFrames,
    messageOmitted: true,
  }));
  process.exitCode = 1;
});
