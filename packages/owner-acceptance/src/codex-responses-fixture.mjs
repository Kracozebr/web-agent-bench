import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const SECRET_PATTERNS = [
  /\bBearer\s+[^\s"']+/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\bsk-[A-Za-z0-9_-]{12,}\b/,
  /[?&](?:access_token|refresh_token|id_token|authorization_code)=/i,
];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function containsCredentialLikeText(value, ancestors = new Set()) {
  if (typeof value === "string") return SECRET_PATTERNS.some((pattern) => pattern.test(value));
  if (value === null || typeof value !== "object" || ancestors.has(value)) return false;
  ancestors.add(value);
  const found = (Array.isArray(value) ? value : Object.values(value))
    .some((item) => containsCredentialLikeText(item, ancestors));
  ancestors.delete(value);
  return found;
}

function safeProtocolVersion(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value ? value : null;
}

function safeMcpClientField(value, field) {
  const pattern = field === "name" ? /^[A-Za-z0-9][A-Za-z0-9._ +:/-]{0,79}$/ : /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/;
  return typeof value === "string" && pattern.test(value) && !containsCredentialLikeText(value) ? value : null;
}

function requestSummary(request, authorizationHeaderPresent, requestHash, requestBytes) {
  const input = request.input;
  const inputItems = Array.isArray(input) ? input : typeof input === "string" ? [input] : [];
  const tools = Array.isArray(request.tools) ? request.tools : [];
  const toolContracts = tools.map((tool) => {
    const schema = tool?.parameters ?? tool?.input_schema ?? tool?.inputSchema ?? tool?.function?.parameters ?? {};
    const properties = schema?.properties && typeof schema.properties === "object" ? Object.keys(schema.properties) : [];
    const children = Array.isArray(tool?.tools) ? tool.tools.map((child) => ({
      name: typeof child?.name === "string" ? child.name.slice(0, 160) : null,
      parameterNames: child?.parameters?.properties && typeof child.parameters.properties === "object"
        ? Object.keys(child.parameters.properties).filter((name) => /^[A-Za-z0-9_.-]{1,100}$/.test(name)).slice(0, 48) : [],
    })).slice(0, 128) : [];
    return { type: typeof tool?.type === "string" ? tool.type.slice(0, 40) : null,
      name: typeof tool?.name === "string" ? tool.name.slice(0, 160) : null,
      functionName: typeof tool?.function?.name === "string" ? tool.function.name.slice(0, 160) : null,
      parameterNames: properties.filter((name) => /^[A-Za-z0-9_.-]{1,100}$/.test(name)).slice(0, 48),
      requiredParameterNames: Array.isArray(schema?.required) ? schema.required
        .filter((name) => typeof name === "string" && /^[A-Za-z0-9_.-]{1,100}$/.test(name)).slice(0, 48) : [],
      children };
  }).slice(0, 128);
  return {
    method: "POST",
    path: "/v1/responses",
    model: typeof request.model === "string" ? request.model.slice(0, 80) : null,
    stream: request.stream === true,
    requestSha256: requestHash,
    requestBytes,
    authorizationHeaderPresent,
    inputItemCount: inputItems.length,
    inputKinds: inputItems.map((item) => typeof item === "string" ? "text" :
      item && typeof item === "object" && typeof item.role === "string" ? `role:${item.role.slice(0, 32)}` : "structured").slice(0, 64),
    toolNames: tools.map((item) => item && typeof item.name === "string" ? item.name.slice(0, 160) : null)
      .filter((item) => item !== null).slice(0, 128),
    toolContracts,
    credentialLikeInputRejected: false,
  };
}

function responseObject(id, model, output, textUsage = 1) {
  return {
    id,
    object: "response",
    created_at: 1_800_000_000,
    status: "completed",
    error: null,
    incomplete_details: null,
    instructions: null,
    max_output_tokens: null,
    model,
    output,
    parallel_tool_calls: true,
    previous_response_id: null,
    prompt_cache_key: null,
    prompt_cache_retention: null,
    reasoning: { effort: null, summary: null },
    store: false,
    temperature: 1,
    tool_choice: "auto",
    tools: [],
    top_p: 1,
    truncation: "disabled",
    usage: { input_tokens: 1, input_tokens_details: { cached_tokens: 0 }, output_tokens: textUsage,
      output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 1 + textUsage },
    user: null,
    metadata: {},
  };
}

function makeOutputItem({ id, model, responseId, output }) {
  if (output?.type === "function_call") {
    const callId = `call_${id}`;
    return {
      type: "function_call",
      id: `fc_${id}`,
      call_id: callId,
      name: output.name,
      ...(typeof output.namespace === "string" ? { namespace: output.namespace } : {}),
      arguments: JSON.stringify(output.arguments ?? {}),
      status: "completed",
      _responseId: responseId,
    };
  }
  const text = typeof output?.text === "string" ? output.text : "READY";
  return {
    type: "message",
    id: `msg_${id}`,
    status: "completed",
    role: "assistant",
    content: [{ type: "output_text", text, annotations: [], logprobs: [] }],
    _responseId: responseId,
  };
}

function responseSseEvents(response, item) {
  let sequence = 0;
  const emit = (type, fields = {}) => ({ type, ...fields, sequence_number: sequence++ });
  const inProgress = { ...response, status: "in_progress", output: [], usage: null };
  const events = [emit("response.created", { response: { ...inProgress, status: "in_progress" } }),
    emit("response.in_progress", { response: inProgress }),
    emit("response.output_item.added", { output_index: 0, item: { ...item,
      ...(item.type === "message" ? { content: [] } : { arguments: "", status: "in_progress" }) } })];

  if (item.type === "message") {
    const part = item.content[0];
    events.push(emit("response.content_part.added", { item_id: item.id, output_index: 0, content_index: 0,
      part: { type: "output_text", text: "", annotations: [], logprobs: [] } }));
    events.push(emit("response.output_text.delta", { item_id: item.id, output_index: 0, content_index: 0, delta: part.text, logprobs: [] }));
    events.push(emit("response.output_text.done", { item_id: item.id, output_index: 0, content_index: 0, text: part.text, logprobs: [] }));
    events.push(emit("response.content_part.done", { item_id: item.id, output_index: 0, content_index: 0, part }));
  } else {
    events.push(emit("response.function_call_arguments.delta", { item_id: item.id, output_index: 0, delta: item.arguments }));
    events.push(emit("response.function_call_arguments.done", { item_id: item.id, output_index: 0, arguments: item.arguments }));
  }
  const completedItem = { ...item };
  delete completedItem._responseId;
  events.push(emit("response.output_item.done", { output_index: 0, item: completedItem }));
  events.push(emit("response.completed", { response }));
  return events;
}

async function readJsonBody(request, maxBytes = MAX_REQUEST_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error("fixture_request_too_large"), { code: "fixture_request_too_large" });
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  try { return { body: JSON.parse(text), bytes: size, sha256: sha256(text) }; }
  catch { throw Object.assign(new Error("fixture_request_invalid_json"), { code: "fixture_request_invalid_json" }); }
}

function sendResponse(response, item, request, reply) {
  const cleanItem = { ...item };
  delete cleanItem._responseId;
  const completed = responseObject(response.id, response.model, [cleanItem], response.usage?.output_tokens ?? 1);
  const expectedSse = request.stream === true;
  if (!expectedSse) {
    reply.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    reply.end(JSON.stringify(completed));
    return;
  }
  reply.writeHead(200, { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-cache, no-store",
    connection: "keep-alive" });
  for (const event of responseSseEvents(completed, item)) reply.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
  reply.end("data: [DONE]\n\n");
}

export async function startCodexResponsesFixture({ model = "fixture-model", respond } = {}) {
  if (typeof model !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(model)) throw new Error("codex_fixture_model_invalid");
  const requests = [];
  let requestNumber = 0;
  const server = createServer(async (request, reply) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && url.pathname === "/healthz") {
      reply.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ ok: true }));
      return;
    }
    if (request.method !== "POST" || url.pathname !== "/v1/responses") {
      reply.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: "fixture_route_not_found" }));
      return;
    }
    try {
      const parsed = await readJsonBody(request);
      if (!parsed.body || typeof parsed.body !== "object" || Array.isArray(parsed.body) || parsed.body.model !== model ||
          containsCredentialLikeText(parsed.body)) {
        const reasonCode = parsed.body?.model !== model ? "fixture_model_mismatch" : "fixture_secret_input_rejected";
        reply.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
        reply.end(JSON.stringify({ error: reasonCode }));
        return;
      }
      const index = ++requestNumber;
      const summary = requestSummary(parsed.body, typeof request.headers.authorization === "string", parsed.sha256, parsed.bytes);
      requests.push(summary);
      const scripted = typeof respond === "function" ? await respond({ request: parsed.body, index, summary }) : null;
      const output = scripted && typeof scripted === "object" ? scripted : { type: "message", text: "READY" };
      const responseId = `resp_fixture_${index}`;
      const item = makeOutputItem({ id: String(index), model, responseId, output });
      const cleanItem = { ...item };
      delete cleanItem._responseId;
      const full = responseObject(responseId, model, [cleanItem], output.type === "function_call" ? 1 :
        Math.max(1, String(output.text ?? "READY").length));
      sendResponse(full, item, parsed.body, reply);
    } catch (error) {
      const reasonCode = error?.code === "fixture_request_too_large" ? error.code : "fixture_request_invalid";
      if (!reply.headersSent) reply.writeHead(reasonCode === "fixture_request_too_large" ? 413 : 400,
        { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: reasonCode }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("codex_fixture_bind_failed");
  return {
    baseUrl: `http://127.0.0.1:${address.port}/v1`,
    requestCount: () => requests.length,
    evidence: () => ({ schemaVersion: "brl-codex-responses-fixture/v1", transport: "local_http_responses_sse_or_json",
      baseUrlOrigin: `http://127.0.0.1:${address.port}`, model, requests: structuredClone(requests) }),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

/** A no-owner-action MCP peer for verifying Codex's native MCP transport. */
export async function startCodexMcpFixture({ toolName = "fixture.ping", serverProtocolVersion = null } = {}) {
  if (typeof toolName !== "string" || !/^[A-Za-z0-9_.-]{1,80}$/.test(toolName)) {
    throw new Error("codex_mcp_fixture_tool_name_invalid");
  }
  if (serverProtocolVersion !== null && safeProtocolVersion(serverProtocolVersion) !== serverProtocolVersion) {
    throw new Error("codex_mcp_fixture_protocol_version_invalid");
  }
  const calls = [];
  const initializations = [];
  const server = createServer(async (request, reply) => {
    if (request.method !== "POST" || new URL(request.url ?? "/", "http://127.0.0.1").pathname !== "/mcp") {
      reply.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: "fixture_route_not_found" }));
      return;
    }
    try {
      const parsed = await readJsonBody(request);
      const message = parsed.body;
      if (!message || typeof message !== "object" || Array.isArray(message) || message.jsonrpc !== "2.0") {
        throw Object.assign(new Error("fixture_mcp_request_invalid"), { code: "fixture_mcp_request_invalid" });
      }
      if (typeof message.method === "string" && message.method.startsWith("notifications/")) {
        reply.writeHead(202, { "cache-control": "no-store" });
        reply.end();
        return;
      }
      let result;
      if (message.method === "initialize") {
        const params = message.params && typeof message.params === "object" && !Array.isArray(message.params)
          ? message.params : {};
        const requested = params.protocolVersion;
        const clientInfo = params.clientInfo && typeof params.clientInfo === "object" && !Array.isArray(params.clientInfo)
          ? params.clientInfo : {};
        if (initializations.length < 8) initializations.push({
          protocolVersion: safeProtocolVersion(requested),
          clientInfo: { name: safeMcpClientField(clientInfo.name, "name"),
            version: safeMcpClientField(clientInfo.version, "version") },
        });
        result = { protocolVersion: serverProtocolVersion ?? (typeof requested === "string" ? requested : "2026-07-28"),
          capabilities: { tools: { listChanged: false } }, serverInfo: { name: "BRL-025 local MCP fixture", version: "1.0.0" } };
      } else if (message.method === "tools/list") {
        result = { tools: [{ name: toolName, description: "Return the local fixture success value.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false },
          annotations: { readOnlyHint: true } }] };
      } else if (message.method === "tools/call") {
        if (message.params?.name !== toolName) {
          result = { content: [{ type: "text", text: "fixture_tool_not_found" }], isError: true };
        } else {
          calls.push({ toolName, argumentSha256: sha256(JSON.stringify(message.params?.arguments ?? {})),
            argumentBytes: Buffer.byteLength(JSON.stringify(message.params?.arguments ?? {})) });
          result = { content: [{ type: "text", text: "MCP_FIXTURE_OK" }], isError: false,
            structuredContent: { status: "ok" } };
        }
      } else {
        reply.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
        reply.end(JSON.stringify({ jsonrpc: "2.0", id: message.id ?? null,
          error: { code: -32601, message: "Method not found" } }));
        return;
      }
      reply.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ jsonrpc: "2.0", id: message.id ?? null, result }));
    } catch (error) {
      const reasonCode = error?.code === "fixture_request_too_large" ? error.code : "fixture_mcp_request_invalid";
      if (!reply.headersSent) reply.writeHead(reasonCode === "fixture_request_too_large" ? 413 : 400,
        { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: reasonCode }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("codex_mcp_fixture_bind_failed");
  return {
    serverUrl: `http://127.0.0.1:${address.port}/mcp`,
    callCount: () => calls.length,
    evidence: () => ({ schemaVersion: "brl-codex-mcp-fixture/v1", transport: "local_streamable_http",
      serverUrlOrigin: `http://127.0.0.1:${address.port}`, serverProtocolVersion, toolNames: [toolName],
      initializations: structuredClone(initializations), calls: structuredClone(calls) }),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

/** A no-owner-action fixture using the owner package's actual MCP SDK and strict protocol policy. */
export async function startCodexStrictMcpSdkFixture() {
  const ownerPackageUrl = new URL("../../owner-identity/package.json", import.meta.url);
  const ownerRequire = createRequire(ownerPackageUrl);
  const sdkModulePath = ownerRequire.resolve("@modelcontextprotocol/server");
  const zodModulePath = ownerRequire.resolve("zod");
  const [{ createMcpHandler, McpServer }, { z }] = await Promise.all([
    import(pathToFileURL(sdkModulePath).href),
    import(pathToFileURL(zodModulePath).href),
  ]);
  if (typeof createMcpHandler !== "function" || typeof McpServer !== "function" || !z?.object) {
    throw new Error("codex_strict_mcp_sdk_unavailable");
  }

  const calls = [];
  const requests = [];
  const server = createServer(async (request, reply) => {
    if (request.method !== "POST" || new URL(request.url ?? "/", "http://127.0.0.1").pathname !== "/mcp") {
      reply.writeHead(404, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: "fixture_route_not_found" }));
      return;
    }

    let parsed;
    try {
      parsed = await readJsonBody(request, 64 * 1024);
    } catch {
      const record = { requestStatus: "invalid_json", methodName: null, jsonRpcEnvelopePresent: false,
        headerPresence: { protocolVersion: false, method: false, name: false }, responseStatus: 400 };
      if (requests.length < 32) requests.push(record);
      reply.writeHead(400, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: "fixture_mcp_request_invalid" }));
      return;
    }

    const message = parsed.body;
    const methodName = typeof message?.method === "string" &&
      ["initialize", "notifications/initialized", "tools/list", "tools/call"].includes(message.method)
      ? message.method : null;
    const incomingHeaders = request.headers;
    const headerPresence = {
      protocolVersion: typeof incomingHeaders["mcp-protocol-version"] === "string",
      method: typeof incomingHeaders["mcp-method"] === "string",
      name: typeof incomingHeaders["mcp-name"] === "string",
    };
    let handler;
    let responseStatus = 500;
    let requestStatus = "handler_error";
    try {
      handler = createMcpHandler(() => {
        const mcpServer = new McpServer({ name: "Web3 Agent Bench", version: "1.0.0" }, {
          supportedProtocolVersions: ["2026-07-28"], maxToolInputElements: 8,
        });
        mcpServer.registerTool("fixture.ping", {
          title: "Fixture ping", description: "Return the local fixture success value.",
          inputSchema: z.object({}),
        }, async () => {
          calls.push({ methodName: "tools/call" });
          return { content: [{ type: "text", text: "MCP_FIXTURE_OK" }], structuredContent: { status: "ok" } };
        });
        return mcpServer;
      }, { legacy: "reject", responseMode: "json", keepAliveMs: 0, maxRequestBodySize: 64 * 1024 });

      const headers = new Headers();
      for (const key of ["accept", "content-type", "mcp-protocol-version", "mcp-method", "mcp-name",
        "mcp-session-id", "last-event-id", "origin", "user-agent"]) {
        const value = incomingHeaders[key];
        if (typeof value === "string") headers.set(key, value);
      }
      const webRequest = new Request(new URL(request.url ?? "/mcp", `http://127.0.0.1:${server.address().port}`), {
        method: "POST", headers, body: JSON.stringify(message),
      });
      const webResponse = await handler.fetch(webRequest, { parsedBody: message });
      responseStatus = webResponse.status;
      requestStatus = responseStatus >= 200 && responseStatus < 300 ? "accepted" : "rejected";
      for (const [key, value] of webResponse.headers) reply.setHeader(key, value);
      reply.setHeader("cache-control", "no-store");
      reply.writeHead(responseStatus);
      reply.end(Buffer.from(await webResponse.arrayBuffer()));
    } catch {
      responseStatus = 500;
      requestStatus = "handler_error";
      if (!reply.headersSent) reply.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
      reply.end(JSON.stringify({ error: "fixture_mcp_handler_failed" }));
    } finally {
      if (requests.length < 32) requests.push({ requestStatus, methodName,
        jsonRpcEnvelopePresent: message?.jsonrpc === "2.0", headerPresence, responseStatus });
      await handler?.close().catch(() => undefined);
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("codex_strict_mcp_fixture_bind_failed");
  return {
    serverUrl: `http://127.0.0.1:${address.port}/mcp`,
    callCount: () => calls.length,
    evidence: () => ({ schemaVersion: "brl-codex-strict-mcp-sdk-fixture/v1",
      transport: "local_streamable_http", sdkPackage: "@modelcontextprotocol/server", sdkVersion: "2.4.0",
      serverProtocolVersion: "2026-07-28", legacyPolicy: "reject", responseMode: "json",
      requests: structuredClone(requests), calls: structuredClone(calls) }),
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
