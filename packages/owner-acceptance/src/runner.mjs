import { randomBytes, randomUUID, createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { stopDetachedChild } from "./bounded-child-stop.mjs";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { isAbsolute, resolve, relative, sep } from "node:path";
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
import { runBillingCases } from "./billing-cases.mjs";
import { saveBillingEvidence } from "./billing-evidence.mjs";
import { runFinancialUiCases } from "./financial-ui-cases.mjs";
import { runBonusCodeCases } from "./bonus-code-cases.mjs";
import { saveBonusCodeEvidence } from "./bonus-code-evidence.mjs";
import { runReportCases } from "./report-cases.mjs";
import { saveReportEvidence } from "./report-evidence.mjs";
import { startBetaRecoveryFaultProxy } from "./beta-recovery-fault-proxy.mjs";
import { startBetaRecoveryObserverProxy } from "./beta-recovery-observer-proxy.mjs";
import { runLaunchBoundaryCases, saveLaunchBoundaryCapture } from "./run-cases.mjs";
import { runTransactionCases } from "./run-transaction-cases.mjs";
import { benchmarkBddCaptureDecision, saveBenchmarkBddEvidence } from "./bdd-evidence.mjs";
import { provisionGenuineS1CoordinatorConfig, runGenuineS1OwnerCase, runGenuineTrainingSequenceOwnerCase, runGenuineRankedOwnerCase,
  writeGenuineS1Capture, writeGenuineS1StartupBlock, writeGenuineTrainingSequenceCapture,
  writeGenuineTrainingSequenceStartupBlock, writeGenuineRankedCapture, writeGenuineRankedStartupBlock,
  OPEN_TASK_IDS } from "./genuine-s1-cases.mjs";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repoRoot = resolve(packageRoot, "../..");
const publicOrigin = process.env.OID_PUBLIC_ORIGIN ?? "http://127.0.0.1:3000";
const apiOrigin = process.env.OID_ACCEPTANCE_API_ORIGIN ?? "http://127.0.0.1:8784";
const adminSubject = "oid-admin-fixture-sub";
const clientId = "oid-local-" + randomBytes(8).toString("hex") + ".apps.example.invalid";
const clientSecret = randomBytes(32).toString("base64url");
const runId = randomUUID();
const bonusCodesOptIn = process.argv.includes("--bonus-codes-only");
const reportsOptIn = process.argv.includes("--reports-only");
const platformRecoveryOptIn = process.argv.includes("--platform-recovery-only");
// AICODE-NOTE: ARC owns only disposable browser/MCP continuity captures, including a native client handoff.
const agentRunContinuityOptIn = process.argv.includes("--agent-run-continuity-only");
// AICODE-NOTE: This explicit BER mode retains the two actual S1 recovery cases without
// entering legacy S4/M3 Training collectors. It is subset evidence, never a full BPC/BER gate.
const berRecoveryCoreOptIn = process.env.OID_BER_RECOVERY_CORE === "1";
const berUnknownGradingOptIn = process.env.OID_BER_UNKNOWN_GRADING === "1";
const berH1CutoffOptIn = process.env.OID_BER_H1_CUTOFF === "1";
const interruptBeforeFirstRefund = process.env.OID_BER_INTERRUPT_BEFORE_FIRST_REFUND === "1";
if ((berRecoveryCoreOptIn || berUnknownGradingOptIn || berH1CutoffOptIn) && !platformRecoveryOptIn) throw new Error("ber_fault_capture_requires_platform_recovery_only");
if ([berRecoveryCoreOptIn,berUnknownGradingOptIn,berH1CutoffOptIn].filter(Boolean).length>1) throw new Error("ber_fault_capture_modes_are_exclusive");
if (interruptBeforeFirstRefund && !berRecoveryCoreOptIn) throw new Error("ber_first_refund_fault_requires_core_mode");
// AICODE-NOTE: This diagnostic isolates the real queue/pause preparation; it never
// substitutes for a complete recovery/checkpoint/restore capture or a BPC gate.
const combinedQueueOptIn = process.argv.includes("--combined-queue-only");
const combinedRestoreOptIn = process.argv.includes("--combined-restore-only") || combinedQueueOptIn;
const privateReportStorageOptIn = reportsOptIn || combinedRestoreOptIn || platformRecoveryOptIn || agentRunContinuityOptIn;
const bonusFundedTrainingOptIn = process.argv.includes("--genuine-bonus-funded-training-sequence-worker-owner-run");
const bonusFundedRankedOptIn = process.argv.includes("--genuine-bonus-funded-ranked-worker-owner-run");
const genuineAllOpenTrainingOptIn = process.argv.includes("--genuine-bonus-funded-training-all-open-worker-owner-run");
const retiredTrainingTaskFlags = ["--genuine-s2-owner-run", "--genuine-s2-worker-owner-run",
  "--genuine-s4-owner-run", "--genuine-s4-worker-owner-run"];
const retiredTrainingTaskFlag = retiredTrainingTaskFlags.find((flag) => process.argv.includes(flag));
if (retiredTrainingTaskFlag) {
  const taskId = retiredTrainingTaskFlag.includes("s2") ? "S2" : "S4";
  process.stderr.write(`${JSON.stringify({ status: "not_run_current_release",
    reasonCode: "training_task_not_open_in_current_release", taskId })}\n`);
  process.exit(2);
}
const bonusFundedOptIn = bonusFundedTrainingOptIn || bonusFundedRankedOptIn || genuineAllOpenTrainingOptIn;
const genuineRankedOptIn = process.argv.includes("--genuine-ranked-worker-owner-run") || bonusFundedRankedOptIn;
const genuineWorkerSequenceOptIn = process.argv.includes("--genuine-training-sequence-worker-owner-run") ||
  bonusFundedTrainingOptIn || genuineAllOpenTrainingOptIn;
const genuineSequenceOptIn = genuineRankedOptIn || genuineWorkerSequenceOptIn || process.argv.includes("--genuine-training-sequence-owner-run");
const genuineWorkerTaskId = OPEN_TASK_IDS.find((id) => process.argv.includes("--genuine-" + id.toLowerCase() + "-worker-owner-run"));
const genuineWorkerOptIn = genuineRankedOptIn || genuineWorkerSequenceOptIn || genuineWorkerTaskId !== undefined;
const genuineTaskId = genuineWorkerTaskId ?? ["S1"].find((id) => process.argv.includes("--genuine-" + id.toLowerCase() + "-owner-run"));
const genuineS1OptIn = genuineTaskId !== undefined || genuineSequenceOptIn;
// AICODE-NOTE: Bonus run-admission negatives use the same guarded local policy as owner-run captures.
const localCoordinatorCaptureOptIn = genuineS1OptIn || bonusCodesOptIn || combinedRestoreOptIn || platformRecoveryOptIn || agentRunContinuityOptIn;
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
let reportCaptureIsolation;
let sourceInputsBeforeCheckpoint;
let recoveryFaultProxy;
let recoveryObserverProxy;
let receiptFaultProxy;
let genuineArtifactWritten = false;
let betaOperationsArtifactWritten = false;

function projectGenuineBrowserCapture(capture, allowedPath) {
  if (!capture || capture.schemaVersion !== "oid-browser-observation/v1" || capture.scenarioId !== "OID-SC-011") return null;
  const keep = (row) => typeof row?.path === "string" && allowedPath(row.path);
  return {
    schemaVersion: capture.schemaVersion,
    scenarioId: capture.scenarioId,
    actions: Array.isArray(capture.actions) ? capture.actions.filter((row) => typeof row?.action === "string" && typeof row?.selector === "string").slice(-32) : [],
    requests: Array.isArray(capture.requests) ? capture.requests.filter(keep).slice(-64).map((row) => ({
      method: row.method, path: row.path,
      ...(typeof row.operationId === "string" ? { operationId: row.operationId } : {}),
      ...(Number.isSafeInteger(row.expectedRevision) ? { expectedRevision: row.expectedRevision } : {}),
      ...(typeof row.mode === "string" ? { mode: row.mode } : {}),
    })) : [],
    responses: Array.isArray(capture.responses) ? capture.responses.filter(keep).slice(-64).map((row) => ({
      method: row.method, path: row.path, status: row.status,
    })) : [],
  };
}

function correlateGenuineUiOperation(capture, label, operationId, pathPrefix) {
  if (!capture || typeof operationId !== "string") return { label, status: "unknown", reasonCode: "operation_not_captured" };
  const requestIndex = capture.requests.findIndex((row) => row.operationId === operationId && row.path.startsWith(pathPrefix));
  if (requestIndex < 0) return { label, status: "unknown", reasonCode: "browser_request_not_captured" };
  const request = capture.requests[requestIndex];
  const sameRouteRequests = capture.requests.filter((row) => row.path === request.path && row.method === request.method);
  const occurrence = sameRouteRequests.findIndex((row) => row.operationId === operationId);
  const sameRouteResponses = capture.responses.filter((row) => row.path === request.path && row.method === request.method);
  return { label, status: "observed", operationId, method: request.method, path: request.path,
    responseStatus: sameRouteResponses[occurrence]?.status ?? null,
    responseCorrelation: "same-origin method/path occurrence order" };
}

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
    await setup.query("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON SEQUENCES TO oid_observer");
    await setup.query("ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer");
  } finally { await setup.end(); }
  // AICODE-NOTE: Each run randomizes the auth secret. Persisted JWT private keys
  // are encrypted with that secret, so reusing another run's JWKS breaks login.
  // Keep the whole fixture DB isolated and retained; never delete shared keys.
  process.env.OID_DATABASE_URL = ownerUrl.href;
  process.env.OID_OBSERVER_DATABASE_URL = observerUrl.href;
  databaseIsolation = { databaseName, runId, createdForCapture: true, uniquePerCapture: true, retainedForInspection: true };
}

async function prepareReportCaptureIsolation(databaseName) {
  const expectedDatabaseName = `oid_acceptance_${runId.replaceAll("-", "")}`;
  if (databaseName !== expectedDatabaseName || !/^oid_acceptance_[a-f0-9]{32}$/.test(databaseName)) {
    throw Object.assign(new Error("report_capture_database_identity_mismatch"), { code: "BPC_REPORT_DB_IDENTITY_MISMATCH" });
  }
  const configuredBase = process.env.OID_LOCAL_REPORT_CAPTURE_BASE;
  if (configuredBase !== undefined && (!privateReportStorageOptIn || !isAbsolute(configuredBase))) {
    throw Object.assign(new Error("report_capture_base_requires_absolute_path_and_reports_opt_in"), { code: "BPC_REPORT_CAPTURE_BASE_INVALID" });
  }
  const captureBase = resolve(configuredBase ?? resolve(repoRoot, "artifacts/runs/bpc-report-captures"));
  const captureIsolationRoot = resolve(captureBase, databaseName);
  if (resolve(captureIsolationRoot, "..") !== captureBase) {
    throw Object.assign(new Error("report_capture_root_escaped_configured_base"), { code: "BPC_REPORT_CAPTURE_ROOT_ESCAPE" });
  }
  const captureParent = resolve(captureIsolationRoot, "..");
  await mkdir(captureParent, { recursive: true, mode: 0o700 });
  // The unique database name is also the filesystem root identity. Never reuse a
  // prior root: reports store private screenshots and closure state beneath it.
  await mkdir(captureIsolationRoot, { recursive: false, mode: 0o700 });
  const privateDataDir = resolve(captureIsolationRoot, "private-data");
  await mkdir(privateDataDir, { recursive: false, mode: 0o700 });
  const closureStatePath = resolve(captureIsolationRoot, "beta-report-closure-state.json");
  const contractPath = resolve(repoRoot, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json");
  const sourceEvidenceSha256 = sha256(await readFile(contractPath));
  const initialClosure = { schemaVersion: "beta-report-closure-state/v1", betaEndedAt: null, sourceEvidenceSha256 };
  await writeFile(closureStatePath, `${JSON.stringify(initialClosure, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  return { captureIsolationRoot, privateDataDir, closureStatePath };
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
  await stopDetachedChild(child);
}

async function restartOwnerApi() {
  await stopChild(apiChild);
  apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnvironment, "restarted API", process.execPath);
  await waitHttp(new URL("/healthz", apiOrigin), (response) => response.ok, "restarted owner API");
  return true;
}

function safeCommandErrorDiagnostic(label, exitCode, signal, stderrBytes) {
  const raw = Buffer.concat(stderrBytes).toString("utf8").slice(0, 64_000);
  const redact = (value) => String(value)
    .replace(/(?:postgres(?:ql)?:\/\/)[^\s'"<>]+/gi, "[redacted database URL]")
    .replace(/\bOID_[A-Z0-9_]+\s*[:=]\s*[^\s,;]+/gi, "[redacted OID setting]")
    .replace(/BPC-[A-Za-z0-9_-]{43}/g, "[redacted bonus code]")
    .replace(/\b(?:aap1|oid1|oat1)_[A-Za-z0-9_-]{32,}\b/gi, "[redacted credential]")
    .replace(/\b(?:sk|pk|rk|ghp|gho|github_pat|xox[baprs])_[A-Za-z0-9_-]{16,}\b/gi, "[redacted token]")
    .replace(/\bBearer\s+\S+/gi, "Bearer [redacted]")
    .replace(/([?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)[^&#\s]+/gi, "$1[redacted]")
    .replace(/\b(password|secret|token|authorization|cookie|client_secret)\s*[:=]\s*[^\s,;]+/gi, "$1=[redacted]")
    .trim()
    .slice(0, 320);
  const diagnostic = {
    command: label,
    exitCode: Number.isInteger(exitCode) ? exitCode : null,
    signal: typeof signal === "string" ? signal : null,
  };
  const databaseCode = /(?:\bcode\b|SQLSTATE)\s*[:=]\s*['"]?([0-9A-Z]{5})/i.exec(raw)?.[1];
  const databaseTable = /\btable\s*[:=]\s*['"]([^'"\r\n]+)['"]/i.exec(raw)?.[1];
  const databaseConstraint = /\bconstraint\s*[:=]\s*['"]([^'"\r\n]+)['"]/i.exec(raw)?.[1];
  const databaseMessage = /(?:PostgresError|error|message)\s*[:=]\s*['"]?([^\r\n'"`]+)/i.exec(raw)?.[1];
  if (databaseCode) diagnostic.databaseCode = redact(databaseCode);
  if (databaseTable) diagnostic.databaseTable = redact(databaseTable);
  if (databaseConstraint) diagnostic.databaseConstraint = redact(databaseConstraint);
  if (databaseMessage) diagnostic.databaseMessage = redact(databaseMessage);
  if (label === "owner web build") {
    const tail = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).slice(-12).map(redact).join("\n").slice(0, 2400);
    if (tail) diagnostic.stderrTail = tail;
  }
  return diagnostic;
}

async function runCommand(args, env, label) {
  const child = spawn(pnpm, args, { cwd: repoRoot, env, stdio: ["ignore", "ignore", "pipe"] });
  const stderrBytes = [];
  let stderrLength = 0;
  child.stderr.on("data", (chunk) => {
    if (stderrLength >= 64_000) return;
    const remaining = 64_000 - stderrLength;
    const bounded = chunk.subarray(0, remaining);
    stderrBytes.push(bounded);
    stderrLength += bounded.length;
  });
  const result = await new Promise((resolvePromise, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolvePromise({ code, signal }));
  });
  if (result.code !== 0) {
    throw Object.assign(new Error(label + " failed with exit " + String(result.code ?? result.signal)), {
      code: label === "API build" ? "API_BUILD_FAILED" : label === "database migration" ? "DATABASE_MIGRATION_FAILED" : "ACCEPTANCE_COMMAND_FAILED",
      safeDiagnostic: safeCommandErrorDiagnostic(label, result.code, result.signal, stderrBytes),
    });
  }
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
  const domainOptIns = [bonusCodesOptIn, reportsOptIn, platformRecoveryOptIn, combinedRestoreOptIn, agentRunContinuityOptIn].filter(Boolean).length;
  if (domainOptIns > 1 || (domainOptIns === 1 && process.argv.slice(2).filter((argument) => argument !== "--").length !== 1)) {
    throw Object.assign(new Error("beta_poc_domain_cli_shape_invalid"), { code: "BPC_CLI_SHAPE_INVALID" });
  }
  if (process.env.OID_LOCAL_REPORT_CAPTURE_BASE !== undefined &&
      (!privateReportStorageOptIn || !isAbsolute(process.env.OID_LOCAL_REPORT_CAPTURE_BASE))) {
    throw Object.assign(new Error("report_capture_base_requires_absolute_path_and_reports_opt_in"), { code: "BPC_REPORT_CAPTURE_BASE_INVALID" });
  }
  if (process.platform !== "linux") throw new Error("Run owner acceptance inside the pinned Linux Docker runtime");
  if (agentRunContinuityOptIn && process.env.OID_BETA_MANIFEST_FILE) {
    throw Object.assign(new Error('arc_requires_disposable_local_manual_transport'), { code: 'ARC_LOCAL_PROFILE_REQUIRED' });
  }
  if (localCoordinatorCaptureOptIn) {
    if (process.argv.length !== 3) throw Object.assign(new Error("genuine_s1_cli_shape_invalid"), { code: "GENUINE_S1_CLI_SHAPE_INVALID" });
    phase = "genuine_s1_private_coordinator_provisioning";
    if (platformRecoveryOptIn || combinedRestoreOptIn) {
      recoveryFaultProxy = await startBetaRecoveryFaultProxy({
        upstreamOrigin: `http://host.docker.internal:${process.env.BEF_API_HOST_PORT || "8783"}`,
      });
      recoveryObserverProxy = await startBetaRecoveryObserverProxy({ upstreamHost: "host.docker.internal",
        upstreamPort: Number(process.env.BEF_DATABASE_HOST_PORT || "55432") });
    }
    if (berUnknownGradingOptIn) {
      receiptFaultProxy = await (await import("./ber-unknown-receipt-proxy.mjs")).startBerUnknownReceiptProxy({
        upstreamOrigin: `http://host.docker.internal:${process.env.BEF_LOCAL_RPC_A_HOST_PORT || "18545"}`,
      });
    }
    await provisionGenuineS1CoordinatorConfig({ repositoryRoot: repoRoot,
      automaticWorkerEvaluation: genuineWorkerOptIn || combinedRestoreOptIn || platformRecoveryOptIn || agentRunContinuityOptIn,
      ...(platformRecoveryOptIn || combinedRestoreOptIn ? { apiBaseUrl: recoveryFaultProxy.origin,
        observerDatabase: { host: "127.0.0.1", port: recoveryObserverProxy.port } } : {}),
      ...(berUnknownGradingOptIn ? { observerRpcUrl: receiptFaultProxy.origin } : {}) });
  }
  requireLoopbackOrigin(publicOrigin, "OID_PUBLIC_ORIGIN");
  requireLoopbackOrigin(apiOrigin, "OID_ACCEPTANCE_API_ORIGIN");
  if (publicOrigin !== "http://127.0.0.1:3000" || apiOrigin !== "http://127.0.0.1:8784") throw new Error("The acceptance origins are pinned to 127.0.0.1 ports 3000 and 8784");
  if (!process.env.OID_DATABASE_URL || !process.env.OID_OBSERVER_DATABASE_URL) throw new Error("OID_DATABASE_URL and OID_OBSERVER_DATABASE_URL are required");
  if (!process.env.OID_CHROMIUM_EXECUTABLE) throw new Error("OID_CHROMIUM_EXECUTABLE is required");

  phase = "isolated_acceptance_database";
  await isolateAcceptanceDatabase();
  if (privateReportStorageOptIn) reportCaptureIsolation = await prepareReportCaptureIsolation(databaseIsolation.databaseName);
  console.log(JSON.stringify({ event: "oid_acceptance_database_isolated", captureId: runId,
    databaseName: databaseIsolation.databaseName, retainedForInspection: true }));

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
    OID_BONUS_CODE_VERIFIER_SECRET: randomBytes(32).toString("base64url"),
    OID_REGISTRATION_MODE: "closed",
    OID_AUTH_RATE_LIMIT_MAX: "120",
    OID_SIWE_RATE_LIMIT_MAX: "120",
    OID_AGENT_CREDENTIAL_RATE_LIMIT_MAX: "120",
    // The private runtime coordinator is available only through an explicit
    // genuine owner-run CLI and its tmpfs override. Compose alone cannot opt in.
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: localCoordinatorCaptureOptIn ? "true" : "false",
    OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG: process.env.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG ?? ".local/owner-identity/bef-task-coordinator.json",
    OID_LOCAL_REPORT_ACCEPTANCE_ENABLED: privateReportStorageOptIn ? "true" : "false",
    NODE_ENV: "development",
    ...(agentRunContinuityOptIn ? { OID_MCP_TRANSPORT_PROFILE: "codex-local-manual-2025-06-18" } : {}),
    ...(privateReportStorageOptIn ? {
      OID_PRIVATE_DATA_DIR: reportCaptureIsolation.privateDataDir,
      OID_BETA_REPORT_CLOSURE_STATE_FILE: reportCaptureIsolation.closureStatePath,
      OID_LOCAL_REPORT_CAPTURE_ROOT: reportCaptureIsolation.captureIsolationRoot,
    } : {}),
  };
  if (berRecoveryCoreOptIn || berUnknownGradingOptIn || berH1CutoffOptIn) {
    const faultDatabaseUrl = new URL(apiEnv.OID_DATABASE_URL);
    if (!/^oid_acceptance_[a-f0-9]{32}$/.test(databaseIsolation.databaseName) ||
        faultDatabaseUrl.pathname !== '/' + databaseIsolation.databaseName || faultDatabaseUrl.hostname !== 'postgres') {
      throw new Error('ber_disconnect_detection_requires_disposable_database');
    }
    // A dead fault-injected API must roll back a lock-blocked transaction before
    // the private barrier is released; no server-wide PostgreSQL setting changes.
    faultDatabaseUrl.searchParams.set('options', [faultDatabaseUrl.searchParams.get('options'),
      '-c client_connection_check_interval=100ms'].filter(Boolean).join(' '));
    apiEnv.OID_DATABASE_URL = faultDatabaseUrl.href;
  }
  // This is a runner-only path selection; the API receives only the per-capture root.
  delete apiEnv.OID_LOCAL_REPORT_CAPTURE_BASE;
  // Keep acceptance rate buckets and cookies isolated across independent runs.
  apiEnv.OID_AUTH_SECRET = randomBytes(48).toString("base64url");
  apiEnv.NODE_OPTIONS = [apiEnv.NODE_OPTIONS, "--import=" + preload].filter(Boolean).join(" ");

  phase = "api_build";
  await runCommand(["--filter", "@web-agent-bench/owner-identity", "build"], apiEnv, "API build");
  phase = "database_migration";
  await runCommand(["--filter", "@web-agent-bench/owner-identity", "migrate"], apiEnv, "database migration");
  const webEnv = { ...process.env, OID_API_URL: apiOrigin, HOSTNAME: "127.0.0.1", NODE_ENV: "production" };
  delete webEnv.OID_LOCAL_REPORT_CAPTURE_BASE;
  phase = "web_build";
  await runCommand(["--filter", "@web-agent-bench/owner-web", "build"], webEnv, "owner web build");
  phase = "owner_api_startup";
  apiEnvironment = apiEnv;
  apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnv, "API", process.execPath);
  await waitHttp(new URL("/healthz", apiOrigin), async (response) => {
    if (!response.ok) return false;
    return (await response.json().catch(() => ({}))).status === "ok";
  }, "owner API");

  phase = "owner_web_startup";
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
    resolve(repoRoot, "openspec/changes/tester-bonus-billing"),
    resolve(repoRoot, "tests/bdd/changes/tester-bonus-billing"),
    resolve(repoRoot, "tests/bdd/adapters/tester_bonus_billing.py"),
    resolve(repoRoot, "tests/bdd/features/tester_bonus_billing.feature"),
    resolve(repoRoot, "tests/bdd/mappers/test_tester_bonus_billing_bdd.py"),
    resolve(repoRoot, "tools/replay_tbb_acceptance.py"),
    resolve(repoRoot, "openspec/changes/beta-poc-delivery"),
    resolve(repoRoot, "tests/bdd/changes/beta-poc-delivery"),
    resolve(repoRoot, "tests/bdd/features/beta_poc_delivery.feature"),
    resolve(repoRoot, "tests/bdd/mappers/test_beta_poc_delivery_bdd.py"),
    resolve(repoRoot, "tests/bdd/adapters/beta_poc_delivery.py"),
    resolve(repoRoot, "tests/bdd/adapters/test_beta_poc_delivery_evidence.py"),
    resolve(repoRoot, "tests/bdd/adapters/beta_poc_report_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/test_beta_poc_report_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/beta_poc_recovery_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/test_beta_poc_recovery_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/beta_poc_combined_restore_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/test_beta_poc_combined_restore_verifier.py"),
    resolve(repoRoot, "tools/replay_bpc_bonus_local.py"),
    resolve(repoRoot, "tools/replay_bpc_reports_local.py"),
    resolve(repoRoot, "tools/replay_bpc_recovery_restore_local.py"),
    resolve(repoRoot, "tools/replay_bpc_combined_restore_live.mjs"),
    resolve(repoRoot, "tools/replay_bpc_operations_local.mjs"),
    resolve(repoRoot, "infrastructure/owner-identity/compose.reports-acceptance.yaml"),
    resolve(repoRoot, "openspec/changes/benchmark-run-lifecycle"),
    resolve(repoRoot, "openspec/changes/benchmark-task-suite"),
    resolve(repoRoot, "tests/bdd/changes/benchmark-run-lifecycle"),
    resolve(repoRoot, "tests/bdd/changes/benchmark-task-suite"),
    resolve(repoRoot, "tests/bdd/adapters/benchmark_task_suite.py"),
    resolve(repoRoot, "tests/bdd/adapters/benchmark_task_suite_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/benchmark_run_lifecycle.py"),
    resolve(repoRoot, "tests/bdd/adapters/benchmark_run_lifecycle_verifier.py"),
    resolve(repoRoot, "tests/bdd/adapters/benchmark_run_lifecycle_codex_verifier.py"),
    resolve(repoRoot, "tests/bdd/mappers/test_benchmark_task_suite_bdd.py"),
    resolve(repoRoot, "tests/bdd/mappers/test_benchmark_run_lifecycle_bdd.py"),
    resolve(repoRoot, "tests/bdd/features/benchmark_task_suite.feature"),
    resolve(repoRoot, "tests/bdd/features/benchmark_run_lifecycle.feature"),
    resolve(repoRoot, "tools/harness_contracts.py"),
    resolve(repoRoot, "tools/run_bdd_acceptance.py"),
    resolve(repoRoot, "package.json"),
    resolve(repoRoot, "pnpm-workspace.yaml"),
    resolve(repoRoot, "pnpm-lock.yaml"),
    resolve(repoRoot, "Dockerfile"),
    resolve(repoRoot, ".dockerignore"),
    resolve(repoRoot, "infrastructure/owner-identity"),
    ...(agentRunContinuityOptIn ? [
      resolve(repoRoot, "openspec/changes/agent-run-continuity"),
      resolve(repoRoot, "tests/bdd/changes/agent-run-continuity"),
      resolve(repoRoot, "tests/bdd/features/agent_run_continuity.feature"),
      resolve(repoRoot, "tests/bdd/mappers/test_agent_run_continuity_bdd.py"),
      resolve(repoRoot, "tests/bdd/adapters/agent_run_continuity.py"),
      resolve(repoRoot, "tests/bdd/adapters/test_agent_run_continuity.py"),
      resolve(repoRoot, "tests/bdd/adapters/ber_recovery_replay.py"),
      resolve(repoRoot, "tools/arc-native-bridge.mjs"),
      resolve(repoRoot, "tools/arc-native-bridge.test.mjs"),
      resolve(repoRoot, "tools/run_arc_native.mjs"),
    ] : []),
    ...(berRecoveryCoreOptIn || berUnknownGradingOptIn || berH1CutoffOptIn ? [
      resolve(repoRoot, "openspec/changes/benchmark-execution-reliability/specs"),
      resolve(repoRoot, "openspec/changes/benchmark-execution-reliability/bdd-design.md"),
      resolve(repoRoot, "tests/bdd/changes/benchmark-execution-reliability/harness-contracts.json"),
      resolve(repoRoot, "tools/capture_ber_replay_history.mjs"),
      ...(berUnknownGradingOptIn ? [
        resolve(repoRoot, "tools/ber_completed_callbacks.mjs"),
        resolve(repoRoot, "tools/ber_pending_transition_interruption.mjs"),
        resolve(repoRoot, "tools/ber_completion_handoff_interruption.mjs"),
      ] : []),
    ] : []),
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
      // AICODE-NOTE: ARC qualification bookkeeping is updated after evidence collection.
      // Exclude only these metadata names under this change; code, approval, normative
      // specs/design, BDD contracts, features and readers remain hash-pinned.
      const relativeInput = relative(repoRoot, path).split(sep).join('/');
      const arcMetadata = /^(?:openspec|tests\/bdd)\/changes\/agent-run-continuity\/(?:tasks\.md|runtime-inputs\.json|acceptance-evidence\.(?:md|json))$/;
      if (agentRunContinuityOptIn && arcMetadata.test(relativeInput)) return;
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
    // AICODE-NOTE: Keep the exact DB and source inventory even if a fixture throws
    // before its final capture; a later source hash cannot stand in for this one.
    const beforeProof = { schemaVersion: "owner-acceptance-source-inputs-before/v1", captureId: runId,
      databaseIsolation, sourceInputs: sourceHashesBefore };
    assertSecretFree(beforeProof, "source-inputs-before");
    const beforeBytes = Buffer.from(JSON.stringify(beforeProof, null, 2) + "\n");
    const beforeDirectory = resolve(repoRoot, "artifacts/runs/owner-acceptance-inputs", runId);
    await mkdir(beforeDirectory, { recursive: true, mode: 0o700 });
    await writeFile(resolve(beforeDirectory, "source-inputs-before.json"), beforeBytes, { flag: "wx", mode: 0o600 });
    sourceInputsBeforeCheckpoint = { path: relative(repoRoot, resolve(beforeDirectory, "source-inputs-before.json")).split(sep).join("/"),
      sha256: sha256(beforeBytes), sourceInputCount: sourceHashesBefore.length };
    console.log(JSON.stringify({ event: "oid_acceptance_source_inputs_pinned", captureId: runId,
      databaseName: databaseIsolation.databaseName, checkpoint: sourceInputsBeforeCheckpoint }));
    if (process.argv.includes("--run-transactions-only")) {
      phase = "coordinator_postgres_transaction_integration";
      await stopChild(apiChild);
      const result = await runTransactionCases({ databaseUrl: process.env.OID_DATABASE_URL,
        observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      const startResult = await (await import("./run-start-cases.mjs")).runStartCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      const storeResult = await (await import("./task-store-cases.mjs")).runTaskStoreCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL, repoRoot });
      const evaluationResult = await (await import("./task-result-cases.mjs")).runTaskResultCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      const actionResult = await (await import("./task-action-cases.mjs")).runTaskActionCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      result.atomicStartIntegration = startResult;
      result.releaseStoreIntegration = storeResult;
      result.evaluationStoreIntegration = evaluationResult;
      result.taskActionIntegration = actionResult;
      result.executionBindingIntegration = await (await import("./task-execution-binding-cases.mjs")).runTaskExecutionBindingCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      result.taskPreparationIntegration = await (await import("./task-preparation-cases.mjs")).runTaskPreparationCases({
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
      const sourceHashesAfter = await collectSourceHashes();
      const provenance = { runId, databaseIsolation, inputHashesBefore: sourceHashesBefore,
        inputHashesAfter: sourceHashesAfter, sourceStableDuringRun: JSON.stringify(sourceHashesBefore) === JSON.stringify(sourceHashesAfter) };
      if (!provenance.sourceStableDuringRun) throw new Error("Sources changed during transaction integration capture");
      const saved = await saveLaunchBoundaryCapture({ result, provenance, repoRoot });
      console.log(JSON.stringify({ ...saved, integration: { status: result.status, boundary: result.boundary,
        observations: result.observations }, atomicStart: { status: startResult.status, observations: startResult.observations },
        releaseStore: { status: storeResult.status, observations: storeResult.observations },
        evaluationStore: { status: evaluationResult.status, observations: evaluationResult.observations },
        taskActions: { status: actionResult.status, observations: actionResult.observations },
        executionBindings: result.executionBindingIntegration,
        taskPreparation: result.taskPreparationIntegration }, null, 2));
      return;
    }
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
    if (platformRecoveryOptIn || combinedRestoreOptIn || agentRunContinuityOptIn) {
      const genuineCaptureInput = {
        captureId: runId, repoRoot, databaseUrl: process.env.OID_DATABASE_URL,
        observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL, publicOrigin,
        adminPage: admin.page, adminCapture: admin.captureApi, foreignOwnerPage: admin.page,
        ownerPage: ownerLogin.page, ownerCapture: ownerLogin.captureApi, ownerId,
        restartApi: restartOwnerApi, automaticWorkerEvaluation: true, bonusCodeFunding: true,
        taskId: "S1", mode: "training", bddProbes: false, primaryClientOnly: false,
        setup: { adminProviderFixture: true, invitationId: inviteId,
          ownerInvitationIssueOperationId: issueOperation, ownerActivationOperationId: activationOperation,
          ownerSubjectSha256: digest(ownerSubject), ownerActivationHttpStatus: activationHttp.status(),
          ownerAdmissionStatus: confirmed.owner?.admissionStatus },
      };
      const commonCapture = { runId, repoRoot, databaseIsolation, genuineCaptureInput,
        sourceInputsBeforeCheckpoint,
        sourceInputsBefore: Object.fromEntries(sourceHashesBefore.map((row) => [row.path, row.sha256])),
        sourceBuildSha256: sha256(Buffer.from(JSON.stringify(sourceHashesBefore))),
        databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
        publicOrigin, apiOrigin, adminPage: admin.page, adminCapture: admin.captureApi,
        adminOwnerId: admin.owner.owner.id,
        ownerPage: ownerLogin.page, ownerCapture: ownerLogin.captureApi, ownerId,
        newContext, login: (context, scenarioId, subject) => googleLogin(context, scenarioId, subject),
        restartApi: async (options = undefined) => {
          if (options !== undefined) {
            if (!berH1CutoffOptIn || !options || Object.keys(options).join(',') !== 'coordinatorEnabled' ||
                typeof options.coordinatorEnabled !== 'boolean' ||
                !/^oid_acceptance_[a-f0-9]{32}$/.test(databaseIsolation.databaseName) ||
                new URL(apiEnvironment.OID_DATABASE_URL).pathname !== '/' + databaseIsolation.databaseName ||
                !['127.0.0.1','localhost'].includes(new URL(apiOrigin).hostname) || apiEnvironment.OID_BETA_MANIFEST_FILE ||
                (apiEnvironment.OID_MCP_TRANSPORT_PROFILE ?? 'strict-2026-07-28') !== 'strict-2026-07-28') {
              throw new Error('ber_h1_coordinator_pause_requires_disposable_capture');
            }
            apiEnvironment = { ...apiEnvironment, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: String(options.coordinatorEnabled) };
          }
          const previousPid = apiChild?.pid;
          const startedAt = new Date().toISOString();
          await restartOwnerApi();
          const health = await fetch(new URL("/healthz", apiOrigin), { signal: AbortSignal.timeout(5000) });
          return { schemaVersion: "beta-local-api-restart-receipt/v1", startedAt,
            finishedAt: new Date().toISOString(), previousPid, currentPid: apiChild?.pid,
            healthHttpStatus: health.status, coordinatorEnabled: apiEnvironment.OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED === 'true',
            boundary: "runner_owned_process_stop_start_and_real_health_http" };
        },
        stopApi: async () => {
          const previousPid = apiChild?.pid, startedAt = new Date().toISOString();
          await stopChild(apiChild);
          return { schemaVersion: "beta-local-api-stop-receipt/v1", previousPid, startedAt,
            finishedAt: new Date().toISOString(), exitCode: apiChild?.exitCode ?? null,
            signal: apiChild?.signalCode ?? null, boundary: "runner_owned_bounded_process_stop_no_business_write" };
        },
        getRuntimeRecoverySecrets: () => ({ authSecret: apiEnvironment.OID_AUTH_SECRET,
          bonusCodeVerifierSecret: apiEnvironment.OID_BONUS_CODE_VERIFIER_SECRET,
          googleClientId: apiEnvironment.OID_GOOGLE_CLIENT_ID, googleClientSecret: apiEnvironment.OID_GOOGLE_CLIENT_SECRET }),
        reportCaptureIsolation,
        executeReportCases: async (options = {}) => {
          const coordinatorWasEnabled = apiEnvironment.OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED === "true";
          // Report authorization negatives intentionally seed non-executable
          // foreign run contexts. Keep the real worker from claiming those
          // fixtures while report-side-effect baselines are being observed.
          if (coordinatorWasEnabled) {
            apiEnvironment = { ...apiEnvironment, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "false" };
            await restartOwnerApi();
          }
          try {
            return await runReportCases({ adminPage: admin.page, ownerPage: ownerLogin.page,
              ownerId, publicOrigin, databaseUrl: process.env.OID_DATABASE_URL,
              observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL, ...reportCaptureIsolation,
              ...options, isolatedAcceptance: true });
          } finally {
            if (coordinatorWasEnabled) {
              apiEnvironment = { ...apiEnvironment, OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "true" };
              await restartOwnerApi();
            }
          }
        },
        startRestoredApi: async ({ databaseUrl, privateDataDir, closureStatePath, captureIsolationRoot, recoveredSecrets }) => {
          const restoredName = new URL(databaseUrl).pathname.slice(1);
          if (!/^oid_restore_[a-f0-9]{32}$/.test(restoredName) || !isAbsolute(privateDataDir) ||
              !isAbsolute(closureStatePath) || !isAbsolute(captureIsolationRoot) ||
              !recoveredSecrets || typeof recoveredSecrets.authSecret !== "string" || recoveredSecrets.authSecret.length < 32 ||
              typeof recoveredSecrets.bonusCodeVerifierSecret !== "string" || recoveredSecrets.bonusCodeVerifierSecret.length < 32 ||
              typeof recoveredSecrets.googleClientId !== "string" || typeof recoveredSecrets.googleClientSecret !== "string") {
            throw new Error("combined_restore_api_target_invalid");
          }
          await stopChild(apiChild);
          apiEnvironment = { ...apiEnvironment, OID_DATABASE_URL: databaseUrl,
            OID_AUTH_SECRET: recoveredSecrets.authSecret, OID_BONUS_CODE_VERIFIER_SECRET: recoveredSecrets.bonusCodeVerifierSecret,
            OID_GOOGLE_CLIENT_ID: recoveredSecrets.googleClientId, OID_GOOGLE_CLIENT_SECRET: recoveredSecrets.googleClientSecret,
            OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED: "false", OID_PRIVATE_DATA_DIR: privateDataDir,
            OID_BETA_REPORT_CLOSURE_STATE_FILE: closureStatePath, OID_LOCAL_REPORT_CAPTURE_ROOT: captureIsolationRoot };
          apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnvironment,
            "isolated restored API without executor", process.execPath);
          await waitHttp(new URL("/healthz", apiOrigin), (response) => response.ok, "isolated restored owner API");
        },
        authenticateRestoredOwners: async () => {
          // AICODE-NOTE: Each clone has its own restored session store. A session
          // refreshed in another clone is not proof of identity in this one.
          await commonCapture.ownerPage.close();
          await commonCapture.adminPage.close();
          const restoredOwner = await googleLogin(await newContext(), "BPC-SC-022", ownerSubject);
          const restoredAdmin = await googleLogin(await newContext(), "BPC-SC-022", adminSubject);
          if (restoredOwner.owner.status !== 200 || restoredOwner.owner.owner?.id !== ownerId ||
              restoredOwner.owner.owner?.admissionStatus !== "admitted" ||
              restoredAdmin.owner.status !== 200 || restoredAdmin.owner.owner?.id !== commonCapture.adminOwnerId ||
              restoredAdmin.owner.owner?.isAdmin !== true) {
            throw Object.assign(new Error("combined_restored_identity_mismatch"), { code: "combined_restored_identity_mismatch" });
          }
          commonCapture.ownerPage = restoredOwner.page;
          commonCapture.ownerCapture = restoredOwner.captureApi;
          commonCapture.adminPage = restoredAdmin.page;
          commonCapture.adminCapture = restoredAdmin.captureApi;
          return { schemaVersion: "beta-restored-browser-authentication/v1",
            boundary: "fresh_google_fixture_browser_sign_in_and_owner_api_in_each_clone",
            owner: { httpStatus: restoredOwner.owner.status, ownerId },
            admin: { httpStatus: restoredAdmin.owner.status, ownerId: commonCapture.adminOwnerId, isAdmin: true } };
        },
      };
      const progress = (value) => {
        assertSecretFree(value, "beta operations progress");
        console.log(JSON.stringify({ event: "beta_operations_progress", ...value }));
      };
      if (agentRunContinuityOptIn) {
        const { runArcContinuityOwnerCase } = await import("./arc-continuity-cases.mjs");
        const { createArcNativeIntentRunner } = await import("../../../tools/arc-native-bridge.mjs");
        const savedProfiles = [];
        for (const profile of ['paid_without_retrieve', 'native_handoff']) {
          phase = "agent_run_continuity_" + profile;
          const result = await runArcContinuityOwnerCase({ ...genuineCaptureInput, continuityCase: profile,
            ...(profile === 'native_handoff' ? { onArcNativeIntentReady: createArcNativeIntentRunner({ repoRoot, captureId: runId }) } : {}) });
          const sourceHashesAfter = await collectSourceHashes();
          const map = (rows) => Object.fromEntries(rows.map((row) => [row.path, row.sha256]));
          const inputHashesBefore = map(sourceHashesBefore), inputHashesAfter = map(sourceHashesAfter);
          const provenance = { databaseIsolation, sourceInputsBeforeCheckpoint, inputHashesBefore, inputHashesAfter,
            sourceStableDuringRun: JSON.stringify(inputHashesBefore) === JSON.stringify(inputHashesAfter) };
          const artifactRoot = profile === 'native_handoff' ? 'agent-run-continuity-native' : 'agent-run-continuity-controlled';
          const directory = resolve(repoRoot, 'artifacts/runs', artifactRoot, runId);
          await mkdir(directory, { recursive: true, mode: 0o700 });
          const capture = { schemaVersion: 'agent-run-continuity-capture/v1', captureId: runId,
            boundary: 'isolated_local_browser_backend_postgres_bef_files', profile, result, provenance,
            targetHostAcceptance: 'blocked_target_not_selected' };
          assertSecretFree(capture, artifactRoot);
          const bytes = Buffer.from(JSON.stringify(capture, null, 2) + '\n');
          await writeFile(resolve(directory, 'capture.json'), bytes, { flag: 'wx', mode: 0o600 });
          const saved = { profile, path: `artifacts/runs/${artifactRoot}/${runId}/capture.json`, sha256: sha256(bytes),
            status: result.continuity?.status ?? 'blocked', blocker: result.blocker ?? null,
            sourceStableDuringRun: provenance.sourceStableDuringRun };
          savedProfiles.push(saved);
          console.log(JSON.stringify({ event: 'agent_run_continuity_capture_saved', captureId: runId, ...saved }));
          betaOperationsArtifactWritten = true;
          if (!provenance.sourceStableDuringRun || result.continuity?.status !== 'verified') { process.exitCode = 2; break; }
        }
        console.log(JSON.stringify({ event: 'agent_run_continuity_profiles_complete', captureId: runId, profiles: savedProfiles,
          nativeProfileExecuted: savedProfiles.some((row) => row.profile === 'native_handoff') }));
        return;
      }
      commonCapture.createCombinedBackup = async ({ officialEvidenceRefs, kind = "pre_migration" }) => {
        const { createLocalCombinedBackup } = await import("../../../infrastructure/owner-identity/beta-backup-local.mjs");
        return createLocalCombinedBackup({ repoRoot, databaseUrl: commonCapture.databaseUrl,
          observerDatabaseUrl: commonCapture.observerDatabaseUrl,
          privateDataDir: reportCaptureIsolation.privateDataDir, closureStatePath: reportCaptureIsolation.closureStatePath,
          sourceBuildSha256: commonCapture.sourceBuildSha256, officialEvidenceRefs,
          getRuntimeRecoverySecrets: commonCapture.getRuntimeRecoverySecrets,
          stopApi: commonCapture.stopApi, restartApi: commonCapture.restartApi,
          resumeSourceAfterCheckpoint: false,
          hostBridgeRoot: resolve(repoRoot, ".local/beta-backup-jobs"),
          hostOperatorRoot: resolve(repoRoot, ".local/beta-backup-operator"),
          backupRoot: "/local-report-captures/beta-backups", restoreRoot: "/local-report-captures/beta-restores",
          checkpointId: runId, kind });
      };
      phase = combinedQueueOptIn ? "combined_queue_preparation_runtime"
        : platformRecoveryOptIn ? "platform_recovery_runtime" : "combined_backup_restore_runtime";
      const result = combinedQueueOptIn
        ? await (await import("./beta-combined-restore-cases.mjs")).runBetaQueuePreparationCases({ commonCapture, progress })
        : platformRecoveryOptIn
        ? berUnknownGradingOptIn
        ? await (await import("./ber-unknown-grading-cases.mjs")).runBerUnknownGradingCases({
          commonCapture, receiptFaultProxy, recoveryFaultProxy, progress })
        : berH1CutoffOptIn
        ? await (await import("./ber-h1-cutoff-cases.mjs")).runBerH1CutoffCases({commonCapture,recoveryFaultProxy,progress})
        : await (await import("./beta-recovery-cases.mjs"))[berRecoveryCoreOptIn
          ? "runBetaRecoveryCoreCases" : "runBetaRecoveryCases"]({
          commonCapture, recoveryFaultProxy, recoveryObserverProxy, progress,
          ...(berRecoveryCoreOptIn ? { exactQuoteBonusFunding: true, interruptBeforeFirstRefund } : {}) })
        : await (await import("./beta-combined-restore-cases.mjs")).runBetaCombinedRestoreCases({
          commonCapture, recoveryFaultProxy, recoveryObserverProxy, progress });
      phase = "beta_operations_source_provenance_after";
      const sourceHashesAfter = await collectSourceHashes();
      const sourceHashMap = (rows) => Object.fromEntries(rows.map((row) => [row.path, row.sha256]));
      const inputHashesBefore = sourceHashMap(sourceHashesBefore);
      const inputHashesAfter = sourceHashMap(sourceHashesAfter);
      const provenance = { databaseIsolation, inputHashesBefore, inputHashesAfter,
        sourceStableDuringRun: JSON.stringify(inputHashesBefore) === JSON.stringify(inputHashesAfter) };
      const artifactRoot = combinedQueueOptIn ? "beta-combined-queue"
        : platformRecoveryOptIn ? (berH1CutoffOptIn ? "ber-h1-cutoff-matrix" : berUnknownGradingOptIn ? "ber-unknown-grading"
          : berRecoveryCoreOptIn ? "ber-fault-recovery-core" : "beta-platform-recovery") : "beta-combined-restore";
      await mkdir(resolve(repoRoot, "artifacts/runs", artifactRoot), { recursive: true, mode: 0o700 });
      const directory = resolve(repoRoot, "artifacts/runs", artifactRoot, runId);
      await mkdir(directory, { recursive: false, mode: 0o700 });
      const capture = { schemaVersion: `${artifactRoot}-capture/v1`, captureId: runId,
        boundary: "isolated_local_browser_backend_postgres_bef_files", result, provenance,
        ...(berRecoveryCoreOptIn ? { scope: { executedCases: ["committedActionRecovery", "recoveryDeadlineExhaustion"],
          taskFamily: "S1", completeBpc017: false, completeBer003: false, completeBer004: false,
          note: "S1 recovery subset only; H1 cutoff/grading and the other approved negatives remain unproven" } } : {}),
        targetHostAcceptance: "blocked_target_not_selected" };
      assertSecretFree(capture, artifactRoot);
      const bytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
      await writeFile(resolve(directory, "capture.json"), bytes, { flag: "wx", mode: 0o600 });
      betaOperationsArtifactWritten = true;
      console.log(JSON.stringify({ event: "beta_operations_capture_saved", captureId: runId,
        path: `artifacts/runs/${artifactRoot}/${runId}/capture.json`, sha256: sha256(bytes),
        status: result.status, sourceStableDuringRun: provenance.sourceStableDuringRun }));
      if (!provenance.sourceStableDuringRun || result.status !== "verified") process.exitCode = 2;
      return;
    }
    if (bonusCodesOptIn) {
      phase = "bonus_code_browser_and_postgres_capture";
      const result = await runBonusCodeCases({
        adminPage: admin.page,
        ownerPage: ownerLogin.page,
        ownerId,
        newContext,
        publicOrigin,
        login: (context, scenarioId, subject) => googleLogin(context, scenarioId, subject),
        observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
        databaseUrl: process.env.OID_DATABASE_URL,
        restartApi: restartOwnerApi,
        rerunMigrations: async () => {
          await stopChild(apiChild);
          await runCommand(["--filter", "@web-agent-bench/owner-identity", "migrate"], apiEnvironment,
            "bonus-code migration preservation replay");
          apiChild = startChild([resolve(repoRoot, "packages/owner-identity/dist/server.js")], apiEnvironment,
            "API after migration preservation replay", process.execPath);
          await waitHttp(new URL("/healthz", apiOrigin), (response) => response.ok, "owner API after migration replay");
        },
      });
      phase = "bonus_code_source_provenance_after";
      const sourceHashesAfter = await collectSourceHashes();
      const contractPath = resolve(repoRoot, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json");
      const sourceHashMap = (rows) => Object.fromEntries(rows.map((row) => [row.path, row.sha256]));
      const inputHashesBefore = sourceHashMap(sourceHashesBefore);
      const inputHashesAfter = sourceHashMap(sourceHashesAfter);
      const provenance = {
        runId,
        databaseIsolation,
        inputHashesBefore,
        inputHashesAfter,
        sourceStableDuringRun: JSON.stringify(inputHashesBefore) === JSON.stringify(inputHashesAfter),
        contractSha256: sha256(await readFile(contractPath)),
      };
      const saved = await saveBonusCodeEvidence({ result, provenance, repositoryRoot: repoRoot });
      await ownerContext.close();
      await adminContext.close();
      const localFailures = [
        ...Object.values(result.scenarioData).filter((scenario) => scenario.localStatus === "failed").map((scenario) => scenario.scenarioId),
        ...(result.migrationPreservation?.status === "failed" ? ["migration_preservation"] : []),
      ];
      const localBlockers = [
        ...Object.values(result.scenarioData).filter((scenario) => scenario.localStatus === "partial").map((scenario) => scenario.scenarioId),
        ...(result.migrationPreservation?.status === "observed" || result.migrationPreservation?.status === "failed"
          ? [] : ["migration_preservation"]),
      ];
      const captureStatus = !provenance.sourceStableDuringRun
        ? "invalidated_source_changed"
        : localFailures.length > 0 ? "local_failed"
          : localBlockers.length > 0 ? "blocked_local_evidence" : "blocked_beta_gates";
      console.log(JSON.stringify({
        schemaVersion: "beta-poc-delivery-capture-summary/v1",
        runId,
        captureStatus,
        localBoundary: result.localBoundary,
        migrationPreservationStatus: result.migrationPreservation?.status ?? "not_run",
        sourceStableDuringRun: provenance.sourceStableDuringRun,
        localFailures,
        localBlockers,
        sourceInputCount: sourceHashesBefore.length,
        ...saved,
      }, null, 2));
      if (!provenance.sourceStableDuringRun || localFailures.length > 0) process.exitCode = 2;
      return;
    }
    if (reportsOptIn) {
      phase = "report_browser_and_postgres_capture";
      const result = await runReportCases({
        adminPage: admin.page,
        ownerPage: ownerLogin.page,
        ownerId,
        publicOrigin,
        databaseUrl: process.env.OID_DATABASE_URL,
        observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
        captureIsolationRoot: reportCaptureIsolation.captureIsolationRoot,
        privateDataDir: reportCaptureIsolation.privateDataDir,
        closureStatePath: reportCaptureIsolation.closureStatePath,
        isolatedAcceptance: true,
      });
      phase = "report_source_provenance_after";
      const sourceHashesAfter = await collectSourceHashes();
      const sourceHashMap = (rows) => Object.fromEntries(rows.map((row) => [row.path, row.sha256]));
      const inputHashesBefore = sourceHashMap(sourceHashesBefore);
      const inputHashesAfter = sourceHashMap(sourceHashesAfter);
      const provenance = {
        runId,
        databaseIsolation,
        inputHashesBefore,
        inputHashesAfter,
        sourceStableDuringRun: JSON.stringify(inputHashesBefore) === JSON.stringify(inputHashesAfter),
      };
      const saved = await saveReportEvidence({ result, provenance, repositoryRoot: repoRoot });
      await ownerContext.close();
      await adminContext.close();
      const localFailures = Object.values(result.scenarioData)
        .filter((scenario) => scenario.localStatus === "failed").map((scenario) => scenario.scenarioId);
      const localBlockers = Object.values(result.scenarioData)
        .filter((scenario) => scenario.localStatus !== "complete").map((scenario) => scenario.scenarioId);
      const captureStatus = !provenance.sourceStableDuringRun
        ? "invalidated_source_changed"
        : localFailures.length > 0 ? "local_failed" : "blocked_local_evidence";
      console.log(JSON.stringify({
        schemaVersion: "beta-poc-delivery-report-capture-summary/v1",
        runId,
        captureStatus,
        localBoundary: result.localBoundary,
        localOperations: result.localOperations,
        sourceStableDuringRun: provenance.sourceStableDuringRun,
        localFailures,
        localBlockers,
        sourceInputCount: sourceHashesBefore.length,
        databaseName: databaseIsolation.databaseName,
        ...saved,
      }, null, 2));
      if (!provenance.sourceStableDuringRun || localFailures.length > 0) process.exitCode = 2;
      return;
    }
    if (genuineS1OptIn) {
      phase = genuineRankedOptIn ? "genuine_ranked_worker_owner_run" : genuineSequenceOptIn ? "genuine_training_sequence_owner_run" : "genuine_s1_first_task_owner_run";
      const captureInput = {
        captureId: runId,
        bddProbes: process.env.OID_ACCEPTANCE_BDD_PROBES === "true",
        primaryClientOnly: process.env.OID_ACCEPTANCE_PRIMARY_CLIENT_ONLY === "true",
        bonusCodeFunding: bonusFundedOptIn,
        restartApi: restartOwnerApi,
        mode: genuineRankedOptIn ? "ranked" : "training",
        automaticWorkerEvaluation: genuineWorkerOptIn,
        ...(genuineRankedOptIn ? { sequenceMode: true, taskIds: ["S1", "S2", "S3", "S4", "M1", "M2", "M3", "M4", "H1", "H2", "H3", "U1"] }
          : genuineAllOpenTrainingOptIn ? { sequenceMode: true, taskIds: OPEN_TASK_IDS } : {}),
        ...(genuineSequenceOptIn ? {} : { taskId: genuineTaskId }),
        repoRoot,
        databaseUrl: process.env.OID_DATABASE_URL,
        observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
        publicOrigin,
        apiOrigin,
        adminPage: admin.page,
        adminCapture: admin.captureApi,
        foreignOwnerPage: admin.page,
        ownerPage: ownerLogin.page,
        ownerCapture: ownerLogin.captureApi,
        ownerId,
        setup: {
          adminProviderFixture: true,
          invitationId: inviteId,
          ownerInvitationIssueOperationId: issueOperation,
          ownerActivationOperationId: activationOperation,
          ownerSubjectSha256: digest(ownerSubject),
          ownerActivationHttpStatus: activationHttp.status(),
          ownerAdmissionStatus: confirmed.owner?.admissionStatus,
        },
      };
      const capture = genuineRankedOptIn
        ? await runGenuineRankedOwnerCase(captureInput)
        : genuineSequenceOptIn
        ? await runGenuineTrainingSequenceOwnerCase(captureInput)
        : await runGenuineS1OwnerCase(captureInput);
      if (bonusFundedTrainingOptIn) {
        phase = "bonus_only_cash_substitution_negative";
        let negativeProof;
        try {
          const { runBonusOnlyCashSubstitutionCase } = await import("./bonus-funding-cases.mjs");
          negativeProof = await runBonusOnlyCashSubstitutionCase({
            databaseUrl: process.env.OID_DATABASE_URL,
            observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
            captureId: runId,
          });
        } catch (error) {
          const reasonCode = typeof error?.code === "string" && /^[A-Za-z0-9_]{1,96}$/.test(error.code)
            ? error.code : "bonus_only_cash_substitution_probe_failed";
          negativeProof = {
            schemaVersion: "bpc-sc005-bonus-only-cash-substitution/v1",
            boundary: "local_isolated_direct_service_with_independent_read_only_postgres",
            status: "failed",
            reasonCode,
            productBoundaryClaims: { browser: false, targetHost: false, externalModel: false, fullScenarioAcceptance: false },
          };
        }
        if (!negativeProof || typeof negativeProof !== "object" || Array.isArray(negativeProof)) {
          negativeProof = {
            schemaVersion: "bpc-sc005-bonus-only-cash-substitution/v1",
            boundary: "local_isolated_direct_service_with_independent_read_only_postgres",
            status: "failed",
            reasonCode: "bonus_only_cash_substitution_invalid_result",
            productBoundaryClaims: { browser: false, targetHost: false, externalModel: false, fullScenarioAcceptance: false },
          };
        }
        const negativeVerified = negativeProof.status === "verified";
        const negativeReasonCode = typeof negativeProof.reasonCode === "string" ? negativeProof.reasonCode
          : "bonus_only_cash_substitution_unverified";
        capture.bonusOnlyCashSubstitutionNegative = negativeProof;
        capture.stages ??= [];
        capture.stages.push({ name: "bonus_only_cash_substitution_negative",
          status: negativeVerified ? "verified" : "blocked",
          ...(!negativeVerified ? { reasonCode: negativeReasonCode } : {}) });
        if (!negativeVerified) {
          const secondaryBlocker = { stage: "bonus_only_cash_substitution_negative", reasonCode: negativeReasonCode };
          if (capture.blocker) {
            capture.supplementaryBlockers ??= [];
            capture.supplementaryBlockers.push(secondaryBlocker);
          } else {
            capture.blocker = secondaryBlocker;
          }
          capture.status = "blocked";
        }
      }
      const adminBrowser = projectGenuineBrowserCapture(admin.capture, (path) => path === "/api/admin/bonus-grants"
        || path.startsWith("/api/admin/bonus-codes") || path.startsWith("/api/admin/invitations"));
      const ownerBrowser = projectGenuineBrowserCapture(ownerLogin.capture, (path) => path === "/api/admission/activate" ||
        path === "/api/owner/runs/catalog" || path === "/api/owner/runs/intents" || path.endsWith("/results") ||
        path.startsWith("/api/owner/bonus-codes") ||
        /^\/api\/owner\/runs\/[^/]+\/cancel$/.test(path) ||
        path === "/api/owner/agents" || /^\/api\/owner\/agents\/[^/]+\/(?:permissions|credentials|manual-credential|financial-policy)$/.test(path));
      capture.browserWitness = { classification: "safe_same_origin_browser_request_response_metadata_no_bodies_or_headers",
        admin: adminBrowser, owner: ownerBrowser };
      const ownerRequests = ownerLogin.capture.requests;
      const operationForPath = (pathPattern, method) => ownerRequests.find((row) => row.method === method && pathPattern.test(row.path))?.operationId ?? null;
      const fundingActionManifest = capture.bonusFunding
        ? [
          correlateGenuineUiOperation(admin.capture, "admin_bonus_code_issue", capture.bonusFunding.issue?.operationId, "/api/admin/bonus-codes"),
          correlateGenuineUiOperation(ownerLogin.capture, "owner_bonus_code_redeem", capture.bonusFunding.redemption?.operationId, "/api/owner/bonus-codes/redeem"),
        ]
        : [correlateGenuineUiOperation(admin.capture, "admin_bonus_grant_submit", capture.bonusGrant?.operationId, "/api/admin/bonus-grants")];
      capture.browserActionManifest = [
        ...fundingActionManifest,
        correlateGenuineUiOperation(ownerLogin.capture, "owner_activation", capture.setup?.ownerActivationOperationId, "/api/admission/activate"),
        correlateGenuineUiOperation(ownerLogin.capture, "owner_agent_create", capture.agent?.createdOperationId, "/api/owner/agents"),
        correlateGenuineUiOperation(ownerLogin.capture, "owner_mode_permission_save",
          operationForPath(/^\/api\/owner\/agents\/[^/]+\/permissions$/, "PUT"), "/api/owner/agents/"),
        correlateGenuineUiOperation(ownerLogin.capture, "owner_financial_policy_save",
          capture.agent?.financialPolicy?.operationId, "/api/owner/agents/"),
        correlateGenuineUiOperation(ownerLogin.capture, "owner_agent_credential_issue",
          capture.agent?.credentialOperationId, "/api/owner/agents/"),
        correlateGenuineUiOperation(ownerLogin.capture, "owner_run_intent_create",
          capture.launchIntent?.operationId, "/api/owner/runs/intents"),
      ];
      const sourceHashesAfter = await collectSourceHashes();
      const provenance = { runId, databaseIsolation, inputHashesBefore: sourceHashesBefore,
        inputHashesAfter: sourceHashesAfter, sourceStableDuringRun: JSON.stringify(sourceHashesBefore) === JSON.stringify(sourceHashesAfter),
        runtimeBoundary: { apiNodeEnv: "development", webNodeEnv: "production", coordinatorEnabledByCli: true } };
      if (!provenance.sourceStableDuringRun) {
        capture.status = "blocked";
        capture.blocker = { stage: "source_provenance", reasonCode: "source_inputs_changed_during_run" };
        capture.stages.push({ name: "source_provenance", status: "blocked", reasonCode: "source_inputs_changed_during_run" });
      }
      if (process.env.OID_ACCEPTANCE_BDD_PROBES === "true") {
        capture.bddEvidence = [];
        const scenarioCaptures = {
          "BTS-SC-001": capture.bdd?.release,
          "BTS-SC-002": capture.bdd?.release,
          "BTS-SC-009": capture.bdd?.ranked,
          ...(capture.bdd?.launch ?? {}),
          ...(capture.bdd?.client ? {"BRL-SC-025": {
            schemaVersion: "benchmark-run-lifecycle-codex-runtime-evidence/v1", scenarioId: "BRL-SC-025",
            status: "blocked", client: capture.bdd.client, launchCaptures: capture.bdd.launch ?? {},
            observations: {browser: capture.bdd.browser ?? {}, browserWitness: capture.browserWitness,
              browserActionManifest: capture.browserActionManifest},
            reasonCode: "remaining_client_negative_variants_unverified",
          }} : {}),
        };
        for (const [scenarioId, raw] of Object.entries(scenarioCaptures)) {
          if (!raw) continue;
          const decision = benchmarkBddCaptureDecision(raw, provenance.sourceStableDuringRun);
          capture.bddEvidence.push(await saveBenchmarkBddEvidence({ repositoryRoot: repoRoot,
            changeName: scenarioId.startsWith("BTS") ? "benchmark-task-suite" : "benchmark-run-lifecycle",
            scenarioId, capture: raw, provenance, ...decision }));
        }
      }
      const savedGenuine = genuineRankedOptIn
        ? await writeGenuineRankedCapture({ repositoryRoot: repoRoot, capture, provenance })
        : genuineSequenceOptIn
        ? await writeGenuineTrainingSequenceCapture({ repositoryRoot: repoRoot, capture, provenance })
        : await writeGenuineS1Capture({ repositoryRoot: repoRoot, capture, provenance });
      genuineArtifactWritten = true;
      await ownerContext.close();
      await adminContext.close();
      console.log(JSON.stringify({ ...savedGenuine, status: capture.status, fullScenarioAcceptance: false,
        runId: capture.runId ?? null, stageCount: capture.stages.length, blocker: capture.blocker ?? null }, null, 2));
      if (capture.status === "blocked" || capture.bddEvidence?.some(row => row.status === "failed")) process.exitCode = 2;
      return;
    }
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

    phase = "browser_bonus_grants_and_immutable_terms";
    const billingData = await runBillingCases({ adminPage: admin.page, ownerPage: ownerLogin.page,
      ownerId, newContext, publicOrigin,
      login: (context, subject) => googleLogin(context, "TBB-SC-001", subject),
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL,
      databaseUrl: process.env.OID_DATABASE_URL, restartApi: restartOwnerApi });

    phase = "browser_financial_controls_and_owner_billing";
    const financialUi = await runFinancialUiCases({ page: ownerLogin.page, ownerId,
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL, billingData });
    billingData.browserData["TBB-SC-013"] = financialUi.browserData;
    billingData.databaseData["TBB-SC-013"] = financialUi.databaseData;

    phase = "browser_launch_release_boundary";
    const launchBoundary = await runLaunchBoundaryCases({ page: ownerLogin.page, ownerId,
      agentId: financialUi.browserData.financialPolicy.agentId,
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    phase = "coordinator_postgres_transaction_integration";
    await stopChild(apiChild);
    const runTransactions = await runTransactionCases({ databaseUrl: process.env.OID_DATABASE_URL,
      observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    runTransactions.atomicStartIntegration = await (await import("./run-start-cases.mjs")).runStartCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    runTransactions.releaseStoreIntegration = await (await import("./task-store-cases.mjs")).runTaskStoreCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL, repoRoot });
    runTransactions.evaluationStoreIntegration = await (await import("./task-result-cases.mjs")).runTaskResultCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    runTransactions.taskActionIntegration = await (await import("./task-action-cases.mjs")).runTaskActionCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    runTransactions.executionBindingIntegration = await (await import("./task-execution-binding-cases.mjs")).runTaskExecutionBindingCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    runTransactions.taskPreparationIntegration = await (await import("./task-preparation-cases.mjs")).runTaskPreparationCases({
      databaseUrl: process.env.OID_DATABASE_URL, observerDatabaseUrl: process.env.OID_OBSERVER_DATABASE_URL });
    await restartOwnerApi();
    launchBoundary.transactionIntegration = runTransactions;

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
    const billingSaved = await saveBillingEvidence({ ...billingData, provenance });
    const launchSaved = await saveLaunchBoundaryCapture({ result: launchBoundary, provenance, repoRoot });
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
      billing: { grantObserved: billingData.sc001Ready === true, immutableTermsObserved: billingData.sc002Ready === true, scenarios: billingSaved },
      launch: launchSaved,
      observations: { adminOAuth: true, invitationIssuedInUI: true, invitationSecretExcludedFromList: true, inviteVerifierMatches: true, ownerActivationViaUI: true, independentReadOnlyPostgresRows: true },
      blockedReason: "Unsupported downstream boundaries, remaining scenario-specific negative matrices, and external OID-SC-012 compatibility remain blocked.",
    }, null, 2));
    if (!process.argv.includes("--smoke")) process.exitCode = 1;
  } finally {
    await browser?.close().catch(() => undefined);
    await observer?.close().catch(() => undefined);
    for (const child of [...children].reverse()) await stopChild(child);
    await fixture?.close().catch(() => undefined);
    await recoveryFaultProxy?.close().catch(() => undefined);
    await recoveryObserverProxy?.close().catch(() => undefined);
    await receiptFaultProxy?.close().catch(() => undefined);
  }
}

main().catch(async (error) => {
  if (agentRunContinuityOptIn && !betaOperationsArtifactWritten) {
    try {
      const directory = resolve(repoRoot, 'artifacts/runs/agent-run-continuity-controlled', runId);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const reasonCode = typeof error?.code === 'string' && /^[A-Za-z0-9_]{1,96}$/.test(error.code)
        ? error.code : 'arc_startup_or_owner_setup_failed';
      const blocked = { schemaVersion: 'agent-run-continuity-capture/v1', captureId: runId,
        boundary: 'isolated_local_browser_backend_postgres_bef_files', profile: 'paid_without_retrieve',
        result: { status: 'blocked', phase, reasonCode },
        provenance: { databaseIsolation, sourceInputsBeforeCheckpoint, sourceStability: 'not_verified' } };
      assertSecretFree(blocked, 'arc-startup-block');
      await writeFile(resolve(directory, 'capture.json'), JSON.stringify(blocked, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      betaOperationsArtifactWritten = true;
    } catch { /* Keep the original safe startup diagnostic if a blocked artifact cannot be retained. */ }
  }
  if ((platformRecoveryOptIn || combinedRestoreOptIn) && !betaOperationsArtifactWritten) {
    const artifactRoot = combinedQueueOptIn ? "beta-combined-queue"
      : platformRecoveryOptIn ? (berH1CutoffOptIn ? "ber-h1-cutoff-matrix" : berUnknownGradingOptIn ? "ber-unknown-grading"
        : berRecoveryCoreOptIn ? "ber-fault-recovery-core" : "beta-platform-recovery") : "beta-combined-restore";
    const reasonCode = typeof error?.code === "string" && /^[A-Za-z0-9_]{1,96}$/.test(error.code)
      ? error.code : "beta_operations_startup_or_runtime_failed";
    try {
      const directory = resolve(repoRoot, "artifacts/runs", artifactRoot, runId);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const capture = { schemaVersion: `${artifactRoot}-capture/v1`, captureId: runId,
        boundary: "isolated_local_browser_backend_postgres_bef_files", result: { status: "blocked", phase, reasonCode },
        provenance: { databaseIsolation, sourceInputsBeforeCheckpoint, sourceStability: "not_verified" },
        targetHostAcceptance: "blocked_target_not_selected" };
      if (error?.safeDiagnostic && typeof error.safeDiagnostic === "object") {
        // AICODE-NOTE: Preserve only explicitly projected diagnostics; raw error
        // messages can contain browser request bodies or one-time credentials.
        assertSecretFree(error.safeDiagnostic, `${artifactRoot}-safe-diagnostic`);
        capture.result.safeDiagnostic = error.safeDiagnostic;
      }
      assertSecretFree(capture, artifactRoot);
      await writeFile(resolve(directory, "capture.json"), `${JSON.stringify(capture, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    } catch { /* Preserve the original sanitized runtime diagnostic. */ }
  }
  if (genuineS1OptIn && !genuineArtifactWritten) {
    const code = typeof error?.code === "string" && /^[A-Za-z0-9_]{1,96}$/.test(error.code)
      ? error.code : "genuine_s1_startup_or_owner_setup_failed";
    try {
      const saved = genuineRankedOptIn
        ? await writeGenuineRankedStartupBlock({ repositoryRoot: repoRoot, captureId: runId, phase, reasonCode: code })
        : genuineSequenceOptIn
        ? await writeGenuineTrainingSequenceStartupBlock({ repositoryRoot: repoRoot, captureId: runId, phase, reasonCode: code,
          automaticWorkerEvaluation: genuineWorkerOptIn, taskIds: genuineAllOpenTrainingOptIn ? OPEN_TASK_IDS : undefined })
        : await writeGenuineS1StartupBlock({ repositoryRoot: repoRoot, captureId: runId, phase, reasonCode: code, taskId: genuineTaskId,
          automaticWorkerEvaluation: genuineWorkerOptIn });
      genuineArtifactWritten = true;
      console.error(JSON.stringify({ event: "genuine_s1_capture_blocked", ...saved, phase, reasonCode: code }));
    } catch { /* Preserve the original safe startup diagnostic if artifact writing is unavailable. */ }
  }
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
    captureId: runId,
    ...(databaseIsolation ? { databaseIsolation } : {}),
    ...(sourceInputsBeforeCheckpoint ? { sourceInputsBeforeCheckpoint } : {}),
    phase,
    errorName: error instanceof Error ? error.name : "Error",
    ...(safeCode ? { errorCode: safeCode } : {}),
    ...(safeDiagnostic ? { safeDiagnostic } : {}),
    stackFrames,
    messageOmitted: true,
  }));
  process.exitCode = 1;
});
