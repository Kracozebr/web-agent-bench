import assert from 'node:assert/strict';
import test from 'node:test';
import { parseCodexTurnEvents, projectCodexFailureDiagnostic, runCodexMcpFixtureSmoke,
  runCodexMcpProtocolCompatibilityProbe, runCodexMcpSdkStrictCompatibilityProbe } from './codex-client-cases.mjs';

const RUN_ID = '22222222-2222-4222-8222-222222222222';

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
