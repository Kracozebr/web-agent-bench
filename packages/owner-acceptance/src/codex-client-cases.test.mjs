import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { parseCodexTurnEvents, projectCodexFailureDiagnostic, runCodexMcpFixtureSmoke,
  runCodexMcpProtocolCompatibilityProbe, runCodexMcpSdkStrictCompatibilityProbe,
  projectCodexOwnerMcpEvents, codexOwnerPreflightWasAllowed,
  runCodexNativeOwnerAcceptance, runCodexNativeOwnerRevocationProbe,
  createCodexToolOperationIds } from './codex-client-cases.mjs';

const RUN_ID = '22222222-2222-4222-8222-222222222222';

async function startLocalOwnerMcpPeer({ unauthorized = false } = {}) {
  const calls = [];
  const server = createServer(async (request, response) => {
    if (request.method !== 'POST' || new URL(request.url ?? '/', 'http://127.0.0.1').pathname !== '/api/agent/mcp') {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'fixture_route_not_found' }));
      return;
    }
    const chunks = [];
    let size = 0;
    try {
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 64 * 1024) throw new Error('fixture_request_too_large');
        chunks.push(chunk);
      }
      const message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const method = message?.method;
      if (unauthorized) {
        response.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store',
          'www-authenticate': 'Bearer realm="local synthetic owner"' });
        response.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      if (method === 'notifications/initialized') {
        response.writeHead(202);
        response.end();
        return;
      }
      let result;
      if (method === 'initialize') {
        result = { protocolVersion: '2025-06-18', capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'Local owner MCP choreography fixture', version: '1.0.0' } };
      } else if (method === 'tools/list') {
        result = { tools: [
          { name: 'identity.preflight', description: 'Local fixture preflight.', inputSchema: {
            type: 'object', properties: { agentId: { type: 'string' }, operationId: { type: 'string' } },
            required: ['agentId', 'operationId'], additionalProperties: false } },
          { name: 'runs.accept_launch_intent', description: 'Local fixture acceptance.', inputSchema: {
            type: 'object', properties: { intentId: { type: 'string' }, operationId: { type: 'string' } },
            required: ['intentId', 'operationId'], additionalProperties: false } },
        ] };
      } else if (method === 'tools/call') {
        const toolName = String(message.params?.name ?? '').toLowerCase().replaceAll('_', '.');
        const args = message.params?.arguments && typeof message.params.arguments === 'object' ? message.params.arguments : {};
        calls.push({ toolName, argumentsSha256: createHash('sha256').update(JSON.stringify(args)).digest('hex') });
        if (toolName === 'identity.preflight') {
          const value = { status: 'allowed', operationId: args.operationId, policyVersion: 1, accessGeneration: 1 };
          result = { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
        } else if (toolName === 'runs.accept.launch.intent') {
          if (calls.filter((call) => call.toolName === 'identity.preflight').length !== 1) {
            result = { content: [{ type: 'text', text: 'fixture_preflight_required' }], isError: true };
          } else {
            const value = { run: { id: RUN_ID, status: 'queued' }, replayed: false };
            result = { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value };
          }
        } else {
          result = { content: [{ type: 'text', text: 'fixture_tool_not_found' }], isError: true };
        }
      } else {
        response.writeHead(400, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ jsonrpc: '2.0', id: message?.id ?? null,
          error: { code: -32601, message: 'Method not found' } }));
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: message.id ?? null, result }));
    } catch {
      response.writeHead(400, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'fixture_request_invalid' }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return {
    publicOrigin: `http://127.0.0.1:${address.port}`,
    calls,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

test('native Codex MCP events retain only allowlisted result metadata and argument hashes', () => {
  const privateArgument = JSON.stringify({ intentId: '11111111-1111-4111-8111-111111111111',
    operationId: '33333333-3333-4333-8333-333333333333', note: 'Bearer should-never-be-retained' });
  const lines = [
    { type: 'item.completed', item: { type: 'mcp_tool_call', tool_name: 'runs_accept_launch_intent',
      server_label: 'owner_agent', status: 'completed', arguments: privateArgument,
      structuredContent: { run: { id: RUN_ID, status: 'queued' }, replayed: false },
      call_id: 'call_safe_1' } },
    { type: 'item.completed', item: { type: 'agent_message', text: 'OWNER_MCP_RESULT_RECEIVED' } },
    { type: 'turn.completed', turn_id: 'turn_safe_1' },
  ].map((event) => JSON.stringify(event)).join('\n');

  const receipt = parseCodexTurnEvents(Buffer.from(lines), 'OWNER_MCP_RESULT_RECEIVED');
  assert.equal(receipt.terminalTurnEventSeen, true);
  assert.equal(receipt.expectedMessageSeen, true);
  assert.equal(receipt.mcpToolEventCount, 1);
  assert.equal(receipt.mcpTools[0].name, 'runs_accept_launch_intent');
  assert.equal(receipt.mcpTools[0].serverLabel, 'owner_agent');
  assert.equal(receipt.mcpTools[0].result.runId, RUN_ID);
  assert.equal(receipt.mcpTools[0].result.status, 'queued');
  assert.match(receipt.mcpTools[0].argumentsSha256, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(receipt.mcpTools[0], 'arguments'), false);
  assert.equal(Object.hasOwn(receipt.mcpTools[0], 'argv'), false);
  const serialized = JSON.stringify(receipt);
  assert.equal(serialized.includes('should-never-be-retained'), false);
  assert.equal(serialized.includes(privateArgument), false);
});

test('native event parser does not turn a failed or absent tool result into a run identity', () => {
  const failed = [{ type: 'item.completed', item: { type: 'mcp_tool_call', tool_name: 'runs_accept_launch_intent',
    server_label: 'owner_agent', status: 'completed', is_error: true, arguments: '{}',
    content: [{ type: 'text', text: 'Bearer never-retain-this' }] } }].map((event) => JSON.stringify(event)).join('\n');
  const receipt = parseCodexTurnEvents(Buffer.from(failed));
  assert.equal(receipt.mcpToolEventCount, 1);
  assert.equal(receipt.mcpTools[0].isError, true);
  assert.deepEqual(receipt.mcpTools[0].result, {});
  assert.equal(JSON.stringify(receipt).includes('never-retain-this'), false);
});

test('owner MCP projection binds preflight status and argument hash before acceptance', () => {
  const preflightArguments = JSON.stringify({ agentId: '11111111-1111-4111-8111-111111111111',
    operationId: 'preflight-operation-0001', note: 'Bearer should-never-be-retained' });
  const acceptArguments = JSON.stringify({ intentId: '33333333-3333-4333-8333-333333333333',
    operationId: 'accept-operation-000001' });
  const lines = [
    { type: 'item.completed', item: { type: 'mcp_tool_call', tool_name: 'identity_preflight',
      server_label: 'owner_agent', status: 'completed', arguments: preflightArguments,
      structuredContent: { status: 'allowed', operationId: 'preflight-operation-0001' }, call_id: 'preflight_1' } },
    { type: 'item.completed', item: { type: 'mcp_tool_call', tool_name: 'runs_accept_launch_intent',
      server_label: 'owner_agent', status: 'completed', arguments: acceptArguments,
      structuredContent: { run: { id: RUN_ID, status: 'queued' }, replayed: false }, call_id: 'accept_1' } },
  ].map((event) => JSON.stringify(event)).join('\n');
  const parsed = parseCodexTurnEvents(Buffer.from(lines));
  const summary = projectCodexOwnerMcpEvents(parsed.mcpTools);
  assert.deepEqual(summary.callOrder, ['identity.preflight', 'runs.accept_launch_intent']);
  assert.equal(summary.preflight.callCount, 1);
  assert.equal(summary.preflight.status, 'allowed');
  assert.equal(summary.preflight.argumentsSha256, parsed.mcpTools[0].argumentsSha256);
  assert.match(summary.preflight.argumentsSha256, /^[0-9a-f]{64}$/);
  assert.equal(summary.acceptance.callCount, 1);
  assert.equal(summary.acceptance.runId, RUN_ID);
  const serialized = JSON.stringify({ parsed, summary });
  assert.equal(serialized.includes('should-never-be-retained'), false);
  assert.equal(serialized.includes(preflightArguments), false);
  assert.equal(serialized.includes(acceptArguments), false);
});

test('Codex fixture gates acceptance on the matching allowed preflight result', () => {
  const operationId = 'preflight-operation-0001';
  const requestFor = (output) => ({ input: [
    { type: 'function_call', name: 'identity_preflight', call_id: 'preflight_call_1' },
    { type: 'function_call_output', call_id: 'preflight_call_1', output },
  ] });
  assert.equal(codexOwnerPreflightWasAllowed(requestFor(`MCP tool result: ${JSON.stringify({ status: 'allowed', operationId })}`), operationId), true);
  assert.equal(codexOwnerPreflightWasAllowed(requestFor(JSON.stringify({ status: 'denied', operationId })), operationId), false);
  assert.equal(codexOwnerPreflightWasAllowed(requestFor(JSON.stringify({ status: 'allowed', operationId: 'different-operation-id' })), operationId), false);
  assert.equal(codexOwnerPreflightWasAllowed({ input: [
    { role: 'user', content: 'Only accept if status is allowed.' },
    { type: 'function_call_output', call_id: 'unrelated_call', output: JSON.stringify({ status: 'allowed', operationId }) },
  ] }, operationId), false);
});

test('native owner helpers reject invalid agent identity before any network setup', async () => {
  const validIntent = '11111111-1111-4111-8111-111111111111';
  const validOperation = 'accept-operation-000001';
  const args = { publicOrigin: 'http://127.0.0.1:3000', agentBearer: 'aap1_' + 'x'.repeat(43),
    intentId: validIntent, acceptOperationId: validOperation, repoRoot: '/workspace' };
  await assert.rejects(() => runCodexNativeOwnerAcceptance({ ...args, agentId: 'invalid' }),
    /codex_owner_agent_id_invalid/);
  await assert.rejects(() => runCodexNativeOwnerRevocationProbe({ ...args, agentId: 'invalid' }),
    /codex_owner_agent_id_invalid/);
});

test('pinned Codex performs preflight before acceptance against a local synthetic MCP peer', async () => {
  const peer = await startLocalOwnerMcpPeer();
  try {
    const operations = createCodexToolOperationIds();
    const result = await runCodexNativeOwnerAcceptance({ publicOrigin: peer.publicOrigin,
      agentBearer: 'aap1_' + 'x'.repeat(43), agentId: '11111111-1111-4111-8111-111111111111',
      preflightOperationId: operations.preflightOperationId,
      intentId: '33333333-3333-4333-8333-333333333333',
      acceptOperationId: operations.acceptanceOperationId, repoRoot: '/workspace' });
    assert.equal(result.outcome, 'accepted_result_observed', JSON.stringify(result));
    assert.equal(result.mcp.preflight.status, 'allowed');
    assert.match(result.mcp.preflight.argumentsSha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(result.mcp.callOrder, ['identity.preflight', 'runs.accept_launch_intent']);
    assert.equal(result.mcp.acceptanceCallAttemptCount, 1);
    assert.equal(result.mcp.ownerActionAttemptCount, 1);
    assert.deepEqual(peer.calls.map((call) => call.toolName), ['identity.preflight', 'runs.accept.launch.intent']);
    assert.ok(peer.calls.every((call) => /^[0-9a-f]{64}$/.test(call.argumentsSha256)));
    assert.equal(JSON.stringify(result).includes('aap1_' + 'x'.repeat(43)), false);
  } finally {
    await peer.close();
  }
});

test('pinned Codex revocation probe proves an upstream 401 challenge through a loopback relay', async () => {
  const peer = await startLocalOwnerMcpPeer({ unauthorized: true });
  try {
    const result = await runCodexNativeOwnerRevocationProbe({ publicOrigin: peer.publicOrigin,
      agentBearer: 'aap1_' + 'x'.repeat(43), agentId: '11111111-1111-4111-8111-111111111111',
      preflightOperationId: 'revocation-probe-operation-01', repoRoot: '/workspace' });
    assert.equal(result.outcome, 'credential_rejected_before_preflight', JSON.stringify(result));
    assert.equal(result.mcp.forwarder.requestCount > 0, true);
    assert.equal(result.mcp.forwarder.ownerUnauthorizedResponseCount > 0, true);
    assert.equal(result.mcp.forwarder.ownerAuthChallengeObserved, true);
    assert.equal(result.mcp.preflight.callAttemptCount, 0);
    assert.equal(result.mcp.ownerActionAttemptCount, 0);
    assert.ok(result.mcp.forwarder.requests.some((item) => item.methodName === 'initialize' &&
      item.responseStatus === 401 && item.wwwAuthenticatePresent));
    assert.equal(peer.calls.length, 0);
    assert.equal(JSON.stringify(result).includes('aap1_' + 'x'.repeat(43)), false);
  } finally {
    await peer.close();
  }
});

test('CLI failure diagnostics classify bounded output without retaining raw stderr or arguments', () => {
  const secretText = 'MCP server connection failed: Bearer raw-fixture-token-value';
  const stdout = Buffer.from([
    JSON.stringify({ type: 'item.completed', item: { type: 'mcp_tool_call', tool_name: 'fixture_ping',
      server_label: 'codex_fixture', is_error: true, arguments: '{"sentinel":"raw-argument-value"}' } }),
    JSON.stringify({ type: 'turn.failed', error: { message: 'MCP server failed' } }),
  ].join('\n'));
  const stderr = Buffer.from(secretText);
  const diagnostic = projectCodexFailureDiagnostic({ exitCode: 2, stdoutBuffer: stdout, stderrBuffer: stderr,
    stdoutBytes: stdout.length, stderrBytes: stderr.length });

  assert.equal(diagnostic.exitCode, 2);
  assert.deepEqual(diagnostic.parsedEventTypes, ['item.completed', 'turn.failed']);
  assert.ok(diagnostic.errorCodeClasses.includes('mcp_transport_error'));
  assert.ok(diagnostic.errorCodeClasses.includes('mcp_tool_error'));
  assert.match(diagnostic.stdoutSha256, /^[0-9a-f]{64}$/);
  assert.match(diagnostic.stderrSha256, /^[0-9a-f]{64}$/);
  const serialized = JSON.stringify(diagnostic);
  assert.equal(serialized.includes('raw-fixture-token-value'), false);
  assert.equal(serialized.includes('raw-argument-value'), false);
  assert.equal(serialized.includes(secretText), false);

  const strictConfig = projectCodexFailureDiagnostic({ exitCode: 2,
    stderrBuffer: Buffer.from('strict-config rejected MCP initialize handshake for Bearer private-fixture-value') });
  assert.ok(strictConfig.errorCodeClasses.includes('strict_config_error'));
  assert.ok(strictConfig.errorCodeClasses.includes('mcp_handshake_error'));
  assert.equal(JSON.stringify(strictConfig).includes('private-fixture-value'), false);
});

test('pinned Codex CLI executes a native MCP call against the local non-owner fixture', async () => {
  const result = await runCodexMcpFixtureSmoke();
  assert.equal(result.schemaVersion, 'brl-codex-native-mcp-fixture-observation/v1');
  assert.equal(result.outcome, 'passed');
  assert.equal(result.mcp.ownerActions, 0);
  assert.equal(result.turn.completed, true);
  assert.equal(result.turn.mcpToolEventCount, 1);
  assert.equal(result.mcpFixture.initializations.length, 1);
  const initialization = result.mcpFixture.initializations[0];
  assert.equal(result.client.version, '0.165.0');
  assert.equal(initialization.protocolVersion, '2025-06-18');
  assert.equal(initialization.clientInfo.name, 'codex-mcp-client');
  assert.equal(initialization.clientInfo.version, '0.165.0');
  assert.deepEqual(Object.keys(initialization).sort(), ['clientInfo', 'protocolVersion']);
  assert.deepEqual(Object.keys(initialization.clientInfo).sort(), ['name', 'version']);
});

test('pinned Codex CLI tolerates a different fixture protocol version and completes the tool call', async () => {
  const result = await runCodexMcpProtocolCompatibilityProbe({ serverProtocolVersion: '2026-07-28' });
  assert.equal(result.schemaVersion, 'brl-codex-mcp-protocol-compatibility-probe/v1');
  assert.equal(result.outcome, 'protocol_mismatch_tolerated_tool_call', JSON.stringify(result));
  assert.equal(result.client.package, '@openai/codex');
  assert.equal(result.client.version, '0.165.0');
  assert.equal(result.client.name, 'codex-mcp-client');
  assert.deepEqual(result.protocol, { requested: '2025-06-18', serverResponse: '2026-07-28' });
  assert.deepEqual(result.errorCodeClasses, []);
  assert.equal(result.turnCompleted, true);
  assert.equal(result.toolCalls, 1);
  assert.equal(result.ownerActions, 0);
  assert.equal(JSON.stringify(result).includes('stderr'), false);
});

test('pinned Codex CLI receives the owner SDK strict legacy rejection before tool calls', async () => {
  const result = await runCodexMcpSdkStrictCompatibilityProbe();
  assert.equal(result.schemaVersion, 'brl-codex-mcp-sdk-strict-protocol-probe/v1');
  assert.equal(result.outcome, 'legacy_initialize_rejected_before_tool_call', JSON.stringify(result));
  assert.deepEqual(result.client, { package: '@openai/codex', version: '0.165.0' });
  assert.deepEqual(result.server, { sdkPackage: '@modelcontextprotocol/server', sdkVersion: '2.4.0',
    protocolVersion: '2026-07-28', legacyPolicy: 'reject', responseMode: 'json' });
  assert.equal(result.requests.length > 0, true);
  assert.equal(result.requests[0].methodName, 'initialize');
  assert.equal(result.requests[0].jsonRpcEnvelopePresent, true);
  assert.deepEqual(result.requests[0].headerPresence, { protocolVersion: false, method: false, name: false });
  assert.equal(result.toolCalls, 0);
  assert.equal(result.ownerActions, 0);
});
