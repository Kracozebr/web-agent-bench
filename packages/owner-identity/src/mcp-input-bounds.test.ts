import assert from 'node:assert/strict';
import test from 'node:test';
import { z } from 'zod';
import { AGENT_MCP_BODY_BYTES, AGENT_MCP_INPUT_ELEMENTS, boundedMcpArguments } from './mcp-input-bounds.js';
import { TaskActionCommandSchema, TaskFinishAnswerSchemas, parseTaskFinishAnswer } from './task-action-service.js';
import { issuedTaskAnswerContract } from './task-issuance.js';

const envelope = (arguments_: unknown) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'runs.finish_task', arguments: arguments_ } });
const target = { runId: '11111111-1111-4111-8111-111111111111', taskIndex: 1, operationId: 'test_operation_001' };

test('minimum/full swap and maximum escaped S2 answer fit finite MCP bounds', () => {
  const command = { kind: 'swap', inputAssetId: 'WETH', outputAssetId: 'USDC', amountInUnits: '1', amountOutMinimumUnits: '1', recipient: '0x'+'1'.repeat(40), gasLimit: '1' };
  assert.equal(TaskActionCommandSchema.safeParse(command).success, true);
  assert.equal(boundedMcpArguments(envelope({ ...target, command })), true);
  assert.equal(boundedMcpArguments(envelope({ ...target, command: { ...command, feeTier: 3000 } })), true);
  const answer: Record<string, unknown> = Object.fromEntries(['amountUnits','network','assetId','recipient','scheme','resourceId','offerId','version'].map(key => [key, '\u0001'.repeat(512)]));
  answer.authFields = Array.from({length: 128}, () => ({ name: '\u0001'.repeat(128), value: '\u0001'.repeat(512) }));
  assert.equal(TaskFinishAnswerSchemas.S2.safeParse(answer).success, true);
  const request = envelope({ ...target, answer });
  assert.ok(Buffer.byteLength(JSON.stringify(request)) < AGENT_MCP_BODY_BYTES);
  assert.equal(boundedMcpArguments(request), true);
});

test('answer errors identify safe schema paths without rejected values or unknown field names', () => {
  assert.throws(()=>parseTaskFinishAnswer('S2',{ authFields:[{name:'x',value:42}] }),/answer.authFields\[0\].value/);
  assert.throws(()=>parseTaskFinishAnswer('S3',{ secret_bearer_material:'sensitive' }),error => {
    assert.doesNotMatch(String(error),/secret_bearer_material|sensitive/);return true;
  });
  assert.throws(()=>parseTaskFinishAnswer('S1',{}),/does not accept/);
  assert.throws(()=>parseTaskFinishAnswer('S2',{authFields:[{name:'x',value:'\u0000'}]}),/answer.authFields\[0\].value/);
  assert.throws(()=>parseTaskFinishAnswer('S3',{offerId:'\u0000'}),/answer.offerId/);
});

test('excess recursive collection and nesting are denied without traversing unbounded input', () => {
  assert.equal(boundedMcpArguments(envelope(Array(AGENT_MCP_INPUT_ELEMENTS+1).fill(1))), false);
  let nested: unknown = {};
  for (let i=0;i<10;i++) nested={ child:nested };
  assert.equal(boundedMcpArguments(envelope(nested)), false);
});

test('issued answer contracts use actual schema and never embed reference solutions', () => {
  for (const id of ['S1','S4','M1','M2','M3','M4','H1','H2','H3','U1']) assert.equal(issuedTaskAnswerContract(id).acceptsStructuredAnswer,false);
  assert.deepEqual(issuedTaskAnswerContract('S2').schema,z.toJSONSchema(TaskFinishAnswerSchemas.S2));
  assert.deepEqual(issuedTaskAnswerContract('S3').schema,z.toJSONSchema(TaskFinishAnswerSchemas.S3));
  assert.doesNotMatch(JSON.stringify(issuedTaskAnswerContract('S3')),/caseHash|referencePath|initialState/);
});
