import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startCodexMcpFixture, startCodexResponsesFixture, startCodexStrictMcpSdkFixture } from "./codex-responses-fixture.mjs";

export const CODEX_CLI_PACKAGE = "@openai/codex";
export const CODEX_CLI_VERSION = "0.165.0";
export const CODEX_FIXTURE_MODEL = "fixture-model";
const MAX_STDOUT_BYTES = 2 * 1024 * 1024;
const MAX_STDERR_BYTES = 256 * 1024;
const MAX_DIAGNOSTIC_STDERR_BYTES = 16 * 1024;
const MAX_RUNTIME_MS = 90_000;

function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function safeName(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.:/-]{1,160}$/.test(value) ? value : null;
}
function tomlString(value) {
  return JSON.stringify(String(value));
}
function loopbackMcpUrl(value, allowedPaths = ["/api/agent/mcp"]) {
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(url.hostname) ||
      url.username || url.password || url.search || url.hash || !allowedPaths.includes(url.pathname)) {
    throw new Error("codex_mcp_server_must_be_the_local_owner_agent_endpoint");
  }
  return `${url.origin}${url.pathname}`;
}

function safeRunMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const candidateRunId = value.runId ?? value.run?.id;
  const runId = typeof candidateRunId === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(candidateRunId)
    ? candidateRunId.toLowerCase() : null;
  const status = safeName(value.status ?? value.state ?? value.run?.status);
  return { ...(runId ? { runId } : {}), ...(status ? { status } : {}) };
}

function mcpResultMetadata(item, depth = 0) {
  if (depth > 4 || !item || typeof item !== "object") return {};
  for (const candidate of [item?.structuredContent, item?.structured_content, item?.result, item?.output, item?.content]) {
    if (typeof candidate === "string" && candidate.length <= 64 * 1024) {
      try {
        const safe = safeRunMetadata(JSON.parse(candidate));
        if (Object.keys(safe).length) return safe;
      } catch { /* Tool text is intentionally not retained. */ }
      if (Array.isArray(item?.content)) {
        for (const content of item.content) {
          if (typeof content?.text !== "string" || content.text.length > 64 * 1024) continue;
          try {
            const safe = safeRunMetadata(JSON.parse(content.text));
            if (Object.keys(safe).length) return safe;
          } catch { /* Tool text is intentionally not retained. */ }
        }
      }
    } else if (Array.isArray(candidate)) {
      for (const content of candidate) {
        if (typeof content?.text !== "string" || content.text.length > 64 * 1024) continue;
        try {
          const safe = safeRunMetadata(JSON.parse(content.text));
          if (Object.keys(safe).length) return safe;
        } catch { /* Tool text is intentionally not retained. */ }
      }
    } else {
      const safe = safeRunMetadata(candidate);
      if (Object.keys(safe).length) return safe;
      if (candidate && typeof candidate === "object") {
        const nested = mcpResultMetadata(candidate, depth + 1);
        if (Object.keys(nested).length) return nested;
      }
    }
  }
  return {};
}

export function parseCodexTurnEvents(buffer, expectedMessage = "READY") {
  const lines = buffer.toString("utf8").split(/\r?\n/).filter(Boolean);
  const eventTypes = [];
  const terminalEventKeys = [];
  const mcpTools = new Map();
  let terminalTurnEventSeen = false;
  let expectedMessageSeen = false;
  for (const line of lines) {
    let event;
    try { event = JSON.parse(line); } catch { continue; }
    if (!event || typeof event !== "object" || Array.isArray(event)) continue;
    const type = safeName(event.type);
    if (type) eventTypes.push(type);
    if (type === "turn.completed") {
      terminalTurnEventSeen = true;
      terminalEventKeys.push(...Object.keys(event).map(safeName).filter(Boolean));
    }
    if (type === "item.completed" || type === "item.started") {
      const item = event.item;
      if (!item || typeof item !== "object" || Array.isArray(item)) continue;
      if (item.type === "agent_message" && typeof item.text === "string" && item.text.trim() === expectedMessage) expectedMessageSeen = true;
      const itemType = String(item.type ?? "").toLowerCase();
      if (itemType.includes("mcp_tool_call")) {
        const tool = item.tool;
        const server = item.server;
        const name = safeName(item.tool_name ?? item.name ?? item.toolName ??
          (typeof tool === "string" ? tool : tool?.name ?? tool?.toolName));
        const key = safeName(item.call_id ?? item.id) ?? `${name ?? "mcp"}:${mcpTools.size}`;
        const argumentsText = typeof item.arguments === "string" ? item.arguments : JSON.stringify(item.arguments ?? null);
        mcpTools.set(key, { event: type, name,
          serverLabel: safeName(item.server_label ?? item.serverLabel ??
            (typeof server === "string" ? server : server?.name ?? server?.label)),
          itemKeys: Object.keys(item).map(safeName).filter(Boolean).slice(0, 48),
          status: safeName(item.status), isError: item.isError === true || item.is_error === true,
          argumentsSha256: argumentsText ? sha256(argumentsText) : null, result: mcpResultMetadata(item) });
      }
    }
  }
  return { eventTypes: [...new Set(eventTypes)].slice(0, 64), terminalTurnEventSeen,
    terminalEventKeys: [...new Set(terminalEventKeys)].slice(0, 32), expectedMessageSeen,
    mcpToolEventCount: mcpTools.size, mcpToolNames: [...new Set([...mcpTools.values()].map((item) => item.name)
      .filter(Boolean))].slice(0, 64), mcpTools: [...mcpTools.values()].slice(0, 64) };
}

function classifyCliError(text, parsedEvents) {
  const classes = new Set(["nonzero_exit"]);
  if (/\bstrict[\s_-]?config\b|\bunknown config(?:uration)? key\b|\b(?:invalid|unsupported|failed to parse|failed to load) config(?:uration)?\b/i.test(text)) {
    classes.add("strict_config_error");
  }
  if (/\b(?:invalid|unknown|failed to (?:parse|load)|parse error).*\b(?:config|toml|setting)\b|\b(?:config|toml|setting).*\b(?:invalid|unknown|parse error)\b/i.test(text)) {
    classes.add("configuration_error");
  }
  if (/\b(?:mcp|json[ -]?rpc)\b.{0,120}\b(?:handshake|initialize|initialization|protocol|version mismatch|invalid response|malformed|tools\/list)\b|\b(?:handshake|initialize|initialization|protocol version|invalid response|malformed json[ -]?rpc)\b.{0,120}\b(?:mcp|json[ -]?rpc)\b/i.test(text)) {
    classes.add("mcp_handshake_error");
  }
  if (/\bmcp\b.{0,100}\b(?:failed|error|timeout|unavailable|initialize|connect)\b|\bmcp\b.{0,100}\b(?:server|tool)\b.{0,60}\b(?:failed|error|timeout)\b/i.test(text)) {
    classes.add("mcp_transport_error");
  }
  if (/\b(?:unauthorized|authentication failed|invalid api key|credential rejected)\b/i.test(text)) {
    classes.add("authentication_error");
  }
  if (/\b(?:request failed|connection refused|http status|response status|model request)\b/i.test(text)) {
    classes.add("model_transport_error");
  }
  if (parsedEvents.mcpTools.some((item) => item.isError)) classes.add("mcp_tool_error");
  if (classes.size === 1 && /\b(?:error|failed|failure)\b/i.test(text)) classes.add("generic_cli_error");
  return [...classes].sort();
}

/** Project bounded in-memory CLI output into safe diagnostics without retaining text. */
export function projectCodexFailureDiagnostic({ exitCode = null, signal = null, stdoutBuffer = Buffer.alloc(0),
  stderrBuffer = Buffer.alloc(0), stdoutBytes = stdoutBuffer.length, stderrBytes = stderrBuffer.length,
  stdoutSha256 = sha256(stdoutBuffer), stderrSha256 = sha256(stderrBuffer),
  stderrHashedBytes = stderrBuffer.length, stderrTruncated = false } = {}) {
  const parsedEvents = parseCodexTurnEvents(stdoutBuffer);
  const diagnosticText = `${stdoutBuffer.toString("utf8")}\n${stderrBuffer.toString("utf8")}`;
  return {
    exitCode: Number.isInteger(exitCode) ? exitCode : null,
    signal: safeName(signal),
    stdoutBytes: Number.isSafeInteger(stdoutBytes) ? stdoutBytes : stdoutBuffer.length,
    stdoutSha256,
    stderrBytes: Number.isSafeInteger(stderrBytes) ? stderrBytes : stderrBuffer.length,
    stderrCapturedBytes: stderrBuffer.length,
    stderrHashedBytes: Number.isSafeInteger(stderrHashedBytes) ? stderrHashedBytes : stderrBuffer.length,
    stderrSha256,
    stderrTruncated: stderrTruncated === true,
    parsedEventTypes: parsedEvents.eventTypes,
    errorCodeClasses: classifyCliError(diagnosticText, parsedEvents),
  };
}

function runProcess(executable, args, { cwd, env, timeoutMs = MAX_RUNTIME_MS, expectedMessage = null } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false, windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderrDiagnostic = [];
    const stderrHash = createHash("sha256");
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stderrHashedBytes = 0;
    let stderrDiagnosticBytes = 0;
    let stderrTruncated = false;
    let settled = false;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(null, "codex_client_timeout", null, "SIGKILL");
    }, timeoutMs);
    const finish = (value, error, exitCode = null, signal = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        const stdoutBuffer = Buffer.concat(stdout);
        const stderrBuffer = Buffer.concat(stderrDiagnostic);
        const failure = new Error(error);
        failure.code = error;
        failure.safeDiagnostic = projectCodexFailureDiagnostic({ exitCode, signal, stdoutBuffer, stderrBuffer,
          stdoutBytes, stderrBytes, stdoutSha256: sha256(stdoutBuffer),
          stderrSha256: stderrHash.copy().digest("hex"), stderrHashedBytes,
          stderrTruncated: stderrTruncated || stderrBytes > stderrDiagnosticBytes });
        reject(failure);
      }
      else resolve(value);
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        child.kill("SIGKILL");
        finish(null, "codex_client_stdout_limit", null, "SIGKILL");
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      const hashLength = Math.max(0, Math.min(chunk.length, MAX_STDERR_BYTES - stderrHashedBytes));
      if (hashLength > 0) {
        stderrHash.update(chunk.subarray(0, hashLength));
        stderrHashedBytes += hashLength;
      }
      const captureLength = Math.max(0, Math.min(chunk.length, MAX_DIAGNOSTIC_STDERR_BYTES - stderrDiagnosticBytes));
      if (captureLength > 0) {
        stderrDiagnostic.push(Buffer.from(chunk.subarray(0, captureLength)));
        stderrDiagnosticBytes += captureLength;
      }
      if (captureLength < chunk.length) stderrTruncated = true;
      if (stderrBytes > MAX_STDERR_BYTES) {
        child.kill("SIGKILL");
        finish(null, "codex_client_stderr_limit", null, "SIGKILL");
      }
    });
    child.once("error", () => finish(null, "codex_client_spawn_failed"));
    child.once("close", (code, signal) => {
      if (settled) return;
      const bytes = Buffer.concat(stdout);
      if (code !== 0) return finish(null, "codex_client_nonzero_exit", code, signal);
      finish({ code, signal: signal ?? null, stdoutBytes, stderrBytes, stdoutText: bytes.toString("utf8"),
        stdoutSha256: sha256(bytes), stderrSha256: stderrHash.digest("hex"),
        ...(expectedMessage !== null ? parseCodexTurnEvents(bytes, expectedMessage) : {}) });
    });
  });
}

function codexConfig(baseUrl, mcp) {
  const lines = [
    `model = ${tomlString(CODEX_FIXTURE_MODEL)}`,
    'model_provider = "oid_local_fixture"',
    'model_reasoning_effort = "minimal"',
    "check_for_update_on_startup = false",
    "cli_auth_credentials_store = \"ephemeral\"",
    "",
    "[model_providers.oid_local_fixture]",
    'name = "BRL-025 local deterministic fixture"',
    `base_url = ${tomlString(baseUrl)}`,
    'wire_api = "responses"',
    "requires_openai_auth = false",
    "supports_websockets = false",
    "request_max_retries = 0",
    "stream_max_retries = 0",
    "stream_idle_timeout_ms = 30000",
    "",
    "[agents]",
    "enabled = false",
  ];
  if (mcp) {
    lines.push("", `[mcp_servers.${mcp.serverId ?? "owner_agent"}]`, `url = ${tomlString(mcp.serverUrl)}`,
      ...(mcp.bearerTokenEnvironmentVariable ? [`bearer_token_env_var = ${tomlString(mcp.bearerTokenEnvironmentVariable)}`] : []),
      `startup_timeout_sec = ${mcp.startupTimeoutSeconds ?? 15}`,
      `tool_timeout_sec = ${mcp.toolTimeoutSeconds ?? 60}`,
      `default_tools_approval_mode = ${tomlString(mcp.approvalMode ?? "auto")}`,
      ...(Array.isArray(mcp.enabledTools) ? [`enabled_tools = ${JSON.stringify(mcp.enabledTools)}`] : []),
      `required = ${mcp.required === true}`, "enabled = true");
  }
  return `${lines.join("\n")}\n`;
}

async function prepareCodexHome(baseUrl, mcp) {
  const root = await mkdtemp(join(tmpdir(), "oid-brl025-codex-"));
  const codexHome = join(root, "codex-home");
  const cache = join(root, "npm-cache");
  const workingDirectory = join(root, "empty-workspace");
  const npmrc = join(root, "empty.npmrc");
  await Promise.all([mkdir(codexHome, { recursive: true }), mkdir(cache, { recursive: true }),
    mkdir(workingDirectory, { recursive: true }), writeFile(npmrc, "", { mode: 0o600 })]);
  await writeFile(join(codexHome, "config.toml"), codexConfig(baseUrl, mcp), { mode: 0o600 });
  const env = {
    PATH: process.env.PATH ?? "",
    CODEX_HOME: codexHome,
    npm_config_cache: cache,
    npm_config_userconfig: npmrc,
    NO_COLOR: "1",
    CI: "1",
  };
  return { root, codexHome, workingDirectory, npmrc, env };
}

async function verifyCodexVersion(env, workingDirectory) {
  const result = await runProcess("npm", ["exec", "--yes", `--package=${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}`,
    "--", "codex", "--version"], { cwd: workingDirectory, env, timeoutMs: 120_000 });
  const versionOutput = result.stdoutText.trim();
  if (versionOutput !== `codex-cli ${CODEX_CLI_VERSION}`) throw new Error("codex_cli_version_pin_mismatch");
  return { package: CODEX_CLI_PACKAGE, version: CODEX_CLI_VERSION, outputSha256: result.stdoutSha256 };
}

async function runCodexTurn({ env, workingDirectory, prompt, expectedMessage = "READY", timeoutMs = MAX_RUNTIME_MS }) {
  const result = await runProcess("npm", ["exec", "--yes", `--package=${CODEX_CLI_PACKAGE}@${CODEX_CLI_VERSION}`,
    "--", "codex", "exec", "--ephemeral", "--strict-config", "--json", "--color", "never", "--skip-git-repo-check",
    "--cd", workingDirectory, "--sandbox", "read-only", "--model", CODEX_FIXTURE_MODEL, prompt],
  { cwd: workingDirectory, env, timeoutMs, expectedMessage });
  return { exitCode: result.code, completed: result.terminalTurnEventSeen && result.expectedMessageSeen,
    outputBytes: result.stdoutBytes, outputSha256: result.stdoutSha256,
    stderrBytes: result.stderrBytes, stderrSha256: result.stderrSha256, eventTypes: result.eventTypes,
    terminalTurnEventSeen: result.terminalTurnEventSeen, terminalEventKeys: result.terminalEventKeys,
    expectedMessageSeen: result.expectedMessageSeen,
    mcpToolEventCount: result.mcpToolEventCount, mcpToolNames: result.mcpToolNames, mcpTools: result.mcpTools };
}

/**
 * First-stage BRL-025 smoke: run the real pinned Codex CLI against a local
 * deterministic Responses endpoint. It intentionally configures no MCP server,
 * so it cannot submit a launch intent or other owner action.
 */
export async function runCodexFixtureTransportSmoke() {
  const fixture = await startCodexResponsesFixture({ model: CODEX_FIXTURE_MODEL });
  const sandbox = await prepareCodexHome(fixture.baseUrl, null);
  try {
    const clientPin = await verifyCodexVersion(sandbox.env, sandbox.workingDirectory);
    const turn = await runCodexTurn({ ...sandbox, prompt: "Reply with exactly READY. Do not call tools." });
    const fixtureEvidence = fixture.evidence();
    const boundaryOk = fixture.requestCount() === 1 && turn.mcpToolEventCount === 0 && fixtureEvidence.requests.every((item) =>
      !item.authorizationHeaderPresent && !item.credentialLikeInputRejected &&
      item.model === CODEX_FIXTURE_MODEL);
    const completed = turn.completed && boundaryOk;
    return {
      schemaVersion: "brl-codex-client-transport-observation/v1",
      outcome: completed ? "passed" : "blocked",
      reason: completed ? null : !turn.completed ? "codex_local_fixture_turn_not_completed" :
        "codex_fixture_transport_boundary_mismatch",
      fixtureBoundaryOk: boundaryOk,
      client: { name: "Codex CLI", package: clientPin.package, version: clientPin.version,
        isolatedCodexHome: true, ephemeralTurn: true, workspaceWritable: false },
      model: { providerId: "oid_local_fixture", model: CODEX_FIXTURE_MODEL, baseUrlOrigin: new URL(fixture.baseUrl).origin,
        providerClass: "deterministic_local_responses_fixture", providerAuthConfigured: false, externalModelCalls: 0,
        llmBenchmarkInvocation: false },
      mcp: { configured: false, toolCalls: 0, ownerActions: 0 },
      turn,
      fixture: fixtureEvidence,
      executionBoundary: "docker_codex_cli_local_responses_fixture_no_owner_actions",
    };
  } finally {
    await fixture.close().catch(() => undefined);
    await rm(sandbox.root, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Verifies Codex's native MCP request/approval path against a non-owner stub. */
export async function runCodexMcpFixtureSmoke({ serverProtocolVersion = null } = {}) {
  const mcpFixture = await startCodexMcpFixture({ serverProtocolVersion });
  const responsesFixture = await startCodexResponsesFixture({ model: CODEX_FIXTURE_MODEL,
    respond: ({ request, index }) => {
      if (index > 1) return { type: "message", text: "MCP_FIXTURE_OK" };
      const namespace = (Array.isArray(request.tools) ? request.tools : []).find((tool) =>
        tool?.type === "namespace" && String(tool.name).toLowerCase().includes("codex_fixture"));
      const target = Array.isArray(namespace?.tools) ? namespace.tools.find((tool) =>
        String(tool?.name).toLowerCase().includes("fixture_ping") || String(tool?.name).toLowerCase().includes("fixture.ping")) : null;
      if (!namespace || !target || typeof target.name !== "string") return { type: "message", text: "MCP_TOOL_NOT_ADVERTISED" };
      return { type: "function_call", namespace: namespace.name, name: target.name, arguments: {} };
    } });
  const mcp = { serverId: "codex_fixture", serverUrl: loopbackMcpUrl(mcpFixture.serverUrl, ["/mcp"]),
    enabledTools: ["fixture.ping"], approvalMode: "approve", required: true };
  const sandbox = await prepareCodexHome(responsesFixture.baseUrl, mcp);
  try {
    const clientPin = await verifyCodexVersion(sandbox.env, sandbox.workingDirectory);
    let turn;
    try {
      turn = await runCodexTurn({ ...sandbox,
        prompt: "Call the fixture.ping MCP tool exactly once. Do not use other tools. Then reply with exactly MCP_FIXTURE_OK.",
        expectedMessage: "MCP_FIXTURE_OK" });
    } catch (error) {
      turn = { completed: false, mcpToolEventCount: 0, mcpTools: [],
        safeDiagnostic: error?.safeDiagnostic && typeof error.safeDiagnostic === "object" ? error.safeDiagnostic : null };
    }
    const mcpEvidence = mcpFixture.evidence();
    const toolEvent = turn.mcpTools.find((item) => item.name?.toLowerCase().includes("fixture_ping") ||
      item.name?.toLowerCase().includes("fixture.ping"));
    const completed = turn.completed && mcpFixture.callCount() === 1 && Boolean(toolEvent) && !toolEvent.isError;
    return { schemaVersion: "brl-codex-native-mcp-fixture-observation/v1",
      outcome: completed ? "passed" : "blocked",
      reason: completed ? null : mcpFixture.callCount() === 0 ? "codex_native_mcp_call_not_executed" :
        "codex_native_mcp_fixture_result_unverified",
      client: { name: "Codex CLI", package: clientPin.package, version: clientPin.version,
        isolatedCodexHome: true, ephemeralTurn: true, workspaceWritable: false },
      provider: { providerId: "oid_local_fixture", model: CODEX_FIXTURE_MODEL,
        providerClass: "deterministic_local_responses_fixture", providerAuthConfigured: false,
        externalModelCalls: 0, llmBenchmarkInvocation: false },
      mcp: { configured: true, serverId: "codex_fixture", allowlistedTools: ["fixture.ping"],
        approvalMode: "approve", nativeApprovalPromptCount: 0, toolCalls: mcpFixture.callCount(),
        ownerActions: 0, ownerMcpServerUsed: false },
      turn, responsesFixture: responsesFixture.evidence(), mcpFixture: mcpEvidence,
      executionBoundary: "docker_codex_cli_local_mcp_fixture_no_owner_actions" };
  } finally {
    await responsesFixture.close().catch(() => undefined);
    await mcpFixture.close().catch(() => undefined);
    await rm(sandbox.root, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Checks whether the pinned CLI rejects a fixture's different MCP protocol before any tool call. */
export async function runCodexMcpProtocolCompatibilityProbe({ serverProtocolVersion }) {
  if (typeof serverProtocolVersion !== "string") throw new Error("codex_mcp_probe_protocol_version_required");
  const result = await runCodexMcpFixtureSmoke({ serverProtocolVersion });
  const initialization = result.mcpFixture.initializations[0] ?? null;
  const requestedProtocolVersion = initialization?.protocolVersion ?? null;
  const protocolVersionsDiffer = requestedProtocolVersion !== null && requestedProtocolVersion !== serverProtocolVersion;
  const protocolRejectedBeforeToolCall = protocolVersionsDiffer && result.mcp.toolCalls === 0 &&
    result.turn.safeDiagnostic?.errorCodeClasses?.includes("mcp_handshake_error") === true;
  const protocolMismatchTolerated = protocolVersionsDiffer && result.turn.completed === true &&
    result.mcp.toolCalls === 1;
  return {
    schemaVersion: "brl-codex-mcp-protocol-compatibility-probe/v1",
    outcome: protocolRejectedBeforeToolCall ? "protocol_rejected_before_tool_call" :
      protocolMismatchTolerated ? "protocol_mismatch_tolerated_tool_call" : "inconclusive",
    client: { package: result.client.package, version: result.client.version,
      name: initialization?.clientInfo?.name ?? null },
    protocol: { requested: requestedProtocolVersion, serverResponse: serverProtocolVersion },
    errorCodeClasses: result.turn.safeDiagnostic?.errorCodeClasses ?? [],
    toolCalls: result.mcp.toolCalls,
    turnCompleted: result.turn.completed === true,
    ownerActions: result.mcp.ownerActions,
  };
}

/** Runs the pinned CLI against the owner package's real 2.4.0 SDK handler and legacy rejection policy. */
export async function runCodexMcpSdkStrictCompatibilityProbe() {
  const mcpFixture = await startCodexStrictMcpSdkFixture();
  const responsesFixture = await startCodexResponsesFixture({ model: CODEX_FIXTURE_MODEL,
    respond: ({ request, index }) => {
      if (index > 1) return { type: "message", text: "MCP_FIXTURE_OK" };
      const namespace = (Array.isArray(request.tools) ? request.tools : []).find((tool) =>
        tool?.type === "namespace" && String(tool.name).toLowerCase().includes("codex_fixture"));
      const target = Array.isArray(namespace?.tools) ? namespace.tools.find((tool) =>
        String(tool?.name).toLowerCase().includes("fixture_ping") || String(tool?.name).toLowerCase().includes("fixture.ping")) : null;
      if (!namespace || !target || typeof target.name !== "string") return { type: "message", text: "MCP_TOOL_NOT_ADVERTISED" };
      return { type: "function_call", namespace: namespace.name, name: target.name, arguments: {} };
    } });
  const mcp = { serverId: "codex_fixture", serverUrl: loopbackMcpUrl(mcpFixture.serverUrl, ["/mcp"]),
    enabledTools: ["fixture.ping"], approvalMode: "approve", required: true };
  const sandbox = await prepareCodexHome(responsesFixture.baseUrl, mcp);
  try {
    const clientPin = await verifyCodexVersion(sandbox.env, sandbox.workingDirectory);
    let turn;
    try {
      turn = await runCodexTurn({ ...sandbox,
        prompt: "Call the fixture.ping MCP tool exactly once. Do not use other tools. Then reply with exactly MCP_FIXTURE_OK.",
        expectedMessage: "MCP_FIXTURE_OK" });
    } catch (error) {
      turn = { completed: false, safeDiagnostic: error?.safeDiagnostic && typeof error.safeDiagnostic === "object"
        ? error.safeDiagnostic : null };
    }
    const fixture = mcpFixture.evidence();
    const initializeRejected = fixture.requests.some((item) => item.methodName === "initialize" &&
      item.jsonRpcEnvelopePresent && item.requestStatus === "rejected" && item.responseStatus >= 400);
    const rejectedBeforeToolCall = initializeRejected && mcpFixture.callCount() === 0;
    return {
      schemaVersion: "brl-codex-mcp-sdk-strict-protocol-probe/v1",
      outcome: rejectedBeforeToolCall ? "legacy_initialize_rejected_before_tool_call" : "inconclusive",
      client: { package: clientPin.package, version: clientPin.version },
      server: { sdkPackage: fixture.sdkPackage, sdkVersion: fixture.sdkVersion,
        protocolVersion: fixture.serverProtocolVersion, legacyPolicy: fixture.legacyPolicy,
        responseMode: fixture.responseMode },
      requests: fixture.requests,
      toolCalls: mcpFixture.callCount(),
      turnCompleted: turn.completed === true,
      errorCodeClasses: turn.safeDiagnostic?.errorCodeClasses ?? [],
      ownerActions: 0,
    };
  } finally {
    await responsesFixture.close().catch(() => undefined);
    await mcpFixture.close().catch(() => undefined);
    await rm(sandbox.root, { recursive: true, force: true }).catch(() => undefined);
  }
}

function validIntentId(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function ownerAcceptTool(request) {
  const namespace = (Array.isArray(request?.tools) ? request.tools : []).find((tool) =>
    tool?.type === "namespace" && tool.name === "mcp__owner_agent");
  const child = Array.isArray(namespace?.tools) ? namespace.tools.find((tool) =>
    typeof tool?.name === "string" && tool.name.toLowerCase().replaceAll("_", ".").includes("runs.accept.launch.intent")) : null;
  return namespace && child ? { namespace: namespace.name, name: child.name } : null;
}

/**
 * Invoke the real local owner MCP route through the pinned Codex CLI. The
 * caller must have already obtained an agent bearer from the owner browser flow
 * and passed the resulting opaque intent and operation IDs. The bearer is only
 * placed in the child process environment; evidence contains allowlisted
 * tool-result metadata and hashes, never the credential or raw tool payload.
 */
export async function runCodexNativeOwnerAcceptance({ publicOrigin, agentBearer, intentId,
  acceptOperationId, ownerPage = null, repoRoot }) {
  if (!validIntentId(intentId)) throw new Error("codex_owner_intent_id_invalid");
  if (typeof acceptOperationId !== "string" || !/^[A-Za-z0-9_-]{12,128}$/.test(acceptOperationId)) {
    throw new Error("codex_owner_accept_operation_id_invalid");
  }
  if (typeof agentBearer !== "string" || agentBearer.length < 16 || agentBearer.length > 8192 ||
      /\s/.test(agentBearer) || /\bBearer\s/i.test(agentBearer)) throw new Error("codex_owner_agent_bearer_invalid");
  if (typeof repoRoot !== "string" || !repoRoot) throw new Error("codex_owner_repo_root_required");
  const repository = await stat(repoRoot).catch(() => null);
  if (!repository?.isDirectory()) throw new Error("codex_owner_repo_root_unavailable");
  const endpoint = loopbackMcpUrl(new URL("/api/agent/mcp", publicOrigin).href);
  const responsesFixture = await startCodexResponsesFixture({ model: CODEX_FIXTURE_MODEL,
    respond: ({ request, index }) => {
      if (index > 1) return { type: "message", text: "OWNER_MCP_RESULT_RECEIVED" };
      const target = ownerAcceptTool(request);
      if (!target) return { type: "message", text: "OWNER_ACCEPT_TOOL_NOT_ADVERTISED" };
      return { type: "function_call", namespace: target.namespace, name: target.name,
        arguments: { intentId, operationId: acceptOperationId } };
    } });
  const mcp = { serverId: "owner_agent", serverUrl: endpoint,
    bearerTokenEnvironmentVariable: "OID_CODEX_MCP_BEARER_TOKEN",
    enabledTools: ["runs.accept_launch_intent"], approvalMode: "approve", required: true,
    startupTimeoutSeconds: 20, toolTimeoutSeconds: 90 };
  const sandbox = await prepareCodexHome(responsesFixture.baseUrl, mcp);
  try {
    const clientPin = await verifyCodexVersion(sandbox.env, sandbox.workingDirectory);
    sandbox.env.OID_CODEX_MCP_BEARER_TOKEN = agentBearer;
    // Use the same empty workspace as the local transport smoke. The repository
    // path is only a required fixture-presence check; loading its agent files or
    // local Codex configuration would make this handoff depend on repo policy.
    const turn = await runCodexTurn({ ...sandbox, workingDirectory: sandbox.workingDirectory,
      prompt: `Accept the owner-authorized benchmark run request by calling runs.accept_launch_intent exactly once with intentId ${intentId} and operationId ${acceptOperationId}. Do not call any other tool. After the MCP tool returns, reply with exactly OWNER_MCP_RESULT_RECEIVED.`,
      expectedMessage: "OWNER_MCP_RESULT_RECEIVED", timeoutMs: 120_000 });
    const acceptCalls = turn.mcpTools.filter((item) =>
      item.name?.toLowerCase().replaceAll("_", ".").includes("runs.accept.launch.intent"));
    const successfulCall = acceptCalls.find((item) => !item.isError && typeof item.result?.runId === "string");
    const runId = successfulCall?.result?.runId ?? null;
    const runStatus = successfulCall?.result?.status ?? null;
    const confirmed = Boolean(runId && successfulCall);
    return {
      schemaVersion: "brl-codex-owner-mcp-observation/v1",
      outcome: confirmed ? "accepted_result_observed" : "acceptance_result_unverified",
      reason: confirmed ? null : acceptCalls.length === 0 ? "codex_owner_accept_tool_not_observed" :
        acceptCalls.some((item) => item.isError) ? "codex_owner_accept_tool_returned_error" :
          "codex_owner_accept_result_metadata_missing",
      client: { name: "Codex CLI", package: clientPin.package, version: clientPin.version,
        isolatedCodexHome: true, ephemeralTurn: true, workspaceWritable: false, repoRootDirectoryAvailable: true },
      model: { providerId: "oid_local_fixture", model: CODEX_FIXTURE_MODEL,
        providerClass: "deterministic_local_responses_fixture", providerAuthConfigured: false,
        externalModelCalls: 0, llmBenchmarkInvocation: false },
      mcp: { configured: true, serverId: "owner_agent", allowlistedTools: ["runs.accept_launch_intent"],
        approvalMode: "approve", nativeApprovalPromptCount: 0, ownerMcpServerUsed: true,
        toolCallCount: turn.mcpToolEventCount, acceptanceCallAttemptCount: acceptCalls.length,
        ownerActionAttemptCount: acceptCalls.length, confirmedAcceptanceResultCount: confirmed ? 1 : 0,
        durableOwnerRunCount: null,
        toolResult: { toolName: "runs.accept_launch_intent", operationId: acceptOperationId,
          runId, status: runStatus, argumentsSha256: successfulCall?.argumentsSha256 ??
            acceptCalls[0]?.argumentsSha256 ?? null, isError: acceptCalls[0]?.isError ?? null } },
      turn,
      responsesFixture: responsesFixture.evidence(),
      handoff: { ownerPageProvided: Boolean(ownerPage), nativeClient: "codex-cli",
        manualCopyFallbackUsed: false, clientApprovalPromptCount: 0 },
      executionBoundary: "docker_codex_cli_local_owner_mcp_single_allowlisted_acceptance",
    };
  } finally {
    delete sandbox.env.OID_CODEX_MCP_BEARER_TOKEN;
    await responsesFixture.close().catch(() => undefined);
    await rm(sandbox.root, { recursive: true, force: true }).catch(() => undefined);
  }
}

/**
 * Creates fresh per-run IDs for a future script-driven native MCP turn. This is
 * exported for the acceptance adapter; callers must supply the real OAuth token
 * from the browser fixture in memory and must not persist it in evidence.
 */
export function createCodexToolOperationIds() {
  return { preflightOperationId: `codex-${randomUUID()}`, acceptanceOperationId: `codex-${randomUUID()}` };
}

/**
 * Build only the safe MCP configuration fields used by the future BRL-025
 * client case. The bearer value belongs exclusively in the child's environment.
 */
export function codexLocalMcpConfiguration(serverUrl) {
  return { serverUrl: loopbackMcpUrl(serverUrl), bearerTokenEnvironmentVariable: "OID_CODEX_MCP_BEARER_TOKEN" };
}
