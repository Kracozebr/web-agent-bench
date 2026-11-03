import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash,randomUUID} from 'node:crypto';
import postgres from 'postgres';
import {drizzle} from 'drizzle-orm/postgres-js';
import {getTaskActionState} from './task-action-service.js';
import type {OwnerDatabase} from './db.js';
import type {AgentPrincipal} from './agents.js';
import {makeRejectedSwapFamilyFixture} from './task-rejected-swap-proof.fixture.js';
import {canonicalTaskJson} from './task-release.js';
import {createMcpHandler,McpServer} from '@modelcontextprotocol/server';
import {registerRunIntentMcpTools} from './run-routes.js';
import {AGENT_MCP_INPUT_ELEMENTS} from './mcp-input-bounds.js';
const enabled=process.env.OID_REJECTED_SWAP_RECEIPT_PG_TEST==='1';
test('actual PostgreSQL scoped status serializer binds rejection marker to retained bytes and original null-TX receipt', {skip:!enabled},async()=>{
 const value=process.env.OID_DATABASE_URL;assert(value);const source=new URL(value);assert.equal(source.hostname,'postgres');assert.equal(source.pathname,'/owner_identity');
 const name='oid_rejected_swap_'+randomUUID().replaceAll('-',''),admin=postgres(value,{max:1}),url=new URL(value);url.pathname='/'+name;const client=postgres(url.toString(),{max:1});let created=false;
 try{
  await admin.unsafe(`CREATE DATABASE ${name}`);created=true;
  // Isolated session-local schema exercises the actual authorization/status SELECTs, never original platform tables.
  await client.unsafe(`CREATE TEMP TABLE oid_owner(id uuid,admission_status text);CREATE TEMP TABLE oid_agent(id uuid,owner_id uuid,access_generation integer,access_revoked_at timestamptz);CREATE TEMP TABLE oid_agent_policy(agent_id uuid,training boolean,ranked boolean);CREATE TEMP TABLE oid_agent_access_grant(id uuid,owner_id uuid,agent_id uuid,resource text,role text,access_generation integer,revoked_at timestamptz,expires_at timestamptz);CREATE TEMP TABLE oid_benchmark_run(id uuid,owner_id uuid,agent_id uuid,access_generation integer,mode text,agent_policy_revision integer);CREATE TEMP TABLE oid_run_mode_cancellation_outbox(owner_id uuid,agent_id uuid,mode text,policy_revision integer);CREATE TEMP TABLE oid_run_task_action(id uuid,run_id uuid,owner_id uuid,agent_id uuid,task_index integer,task_id text,action_sequence bigint,operation_id text,payload_hash text,environment_id text,action_kind text);CREATE TEMP TABLE oid_run_task_action_receipt(action_id uuid,receipt_status text,receipt_revision integer,evidence_hash text,evidence_path text,transaction_hash text,tool_response_json jsonb,tool_response_hash text);`);
  await client.unsafe('CREATE TEMP TABLE oid_run_task_action_reconciliation(action_id uuid,revision integer,receipt_status text,evidence_hash text,evidence_path text,transaction_hash text)');
  const f=makeRejectedSwapFamilyFixture(),owner=randomUUID(),agent=randomUUID(),grant=randomUUID(),d=f.document,bytes=Buffer.from(canonicalTaskJson(d)),digest=createHash('sha256').update(bytes).digest('hex'),resource='https://example.invalid/api/agent';
  await client`INSERT INTO oid_owner VALUES(${owner},'admitted')`;await client`INSERT INTO oid_agent VALUES(${agent},${owner},1,null)`;await client`INSERT INTO oid_agent_policy VALUES(${agent},true,true)`;await client`INSERT INTO oid_agent_access_grant VALUES(${grant},${owner},${agent},${resource},'agent',1,null,clock_timestamp()+interval '1 hour')`;await client`INSERT INTO oid_benchmark_run VALUES(${d.runId},${owner},${agent},1,'training',1)`;
  await client`INSERT INTO oid_run_task_action VALUES(${d.actionId},${d.runId},${owner},${agent},0,'S1',1,${d.ownerOperationId},${d.commandSha256},${d.environmentId},'swap')`;
  await client`INSERT INTO oid_run_task_action_receipt VALUES(${d.actionId},'rejected_before_execution',1,${digest},${f.action.actionEvidence.path},null,null,null)`;
  await client`INSERT INTO oid_run_task_action_reconciliation VALUES(${d.actionId},1,'rejected_before_execution',${digest},${f.action.actionEvidence.path},null)`;
  const db=drizzle(client) as unknown as OwnerDatabase,principal={ownerId:owner,agentId:agent,role:'agent',accessGeneration:1,grantId:grant,resource} as AgentPrincipal;
  let retained:Uint8Array=bytes;const deps={db,readActionEvidence:async()=>retained},target={runId:d.runId,actionId:d.actionId};
  const actual=await getTaskActionState(deps,principal,target);assert.equal(actual.status,'rejected_before_execution');assert.equal(actual.transactionHash,null);assert.equal(actual.toolResponse,null);assert.deepEqual(actual.rejectionProof,f.marker);assert.equal(Object.hasOwn(actual.rejectionProof!,'code'),false);
  const handler=createMcpHandler(()=>{const server=new McpServer({name:'receipt-wire-test',version:'1'},{supportedProtocolVersions:['2025-06-18'],maxToolInputElements:AGENT_MCP_INPUT_ELEMENTS});registerRunIntentMcpTools(server,principal,deps as never);return server;});
  async function wire(method:string,params?:unknown){const body={jsonrpc:'2.0',id:1,method,...(params?{params}:{})},response=await handler.fetch(new Request('http://127.0.0.1/api/agent/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'},body:JSON.stringify(body)}),{parsedBody:body});assert.equal(response.status,200);const text=await response.text(),data=text.split('\n').find(line=>line.startsWith('data:'));return JSON.parse(data?data.slice(5):text) as {result:Record<string,any>};}
  try{
   const listed=await wire('tools/list');const tool=listed.result.tools.find((t:{name:string})=>t.name==='runs.task_action_status');assert(tool);assert.equal(tool.inputSchema.properties.runId.type,'string');assert.equal(tool.inputSchema.properties.actionId.type,'string');assert.deepEqual(tool.inputSchema.required,['runId','actionId']);
   const called=await wire('tools/call',{name:'runs.task_action_status',arguments:target});assert.notEqual(called.result.isError,true);const receipt=JSON.parse(called.result.content[0].text);assert.deepEqual(receipt.rejectionProof,f.marker);assert.equal(receipt.toolResponse,null);assert.equal(receipt.transactionHash,null);assert.equal(Object.hasOwn(receipt,'grade'),false);
   const {validateContractRecipientReceipt}=await import(new URL('../../owner-acceptance/src/ber-contract-recipient-rejection.mjs',import.meta.url).href);
   const accepted=validateContractRecipientReceipt(receipt,{task:{runId:d.runId},actionId:d.actionId});assert.equal(accepted.operationId,f.marker.operationId);assert.notEqual(accepted.operationId,d.ownerOperationId);assert.notEqual(accepted.operationId,d.actionId);
  }finally{await handler.close();}
  await client`UPDATE oid_run_task_action_reconciliation SET evidence_hash=${'f'.repeat(64)} WHERE action_id=${d.actionId}`;assert.equal((await getTaskActionState(deps,principal,target)).rejectionProof,undefined);await client`UPDATE oid_run_task_action_reconciliation SET evidence_hash=${digest} WHERE action_id=${d.actionId}`;
  retained=Buffer.from(canonicalTaskJson({...d,rejectionProof:{...f.marker,operationId:randomUUID()}}));assert.equal((await getTaskActionState(deps,principal,target)).rejectionProof,undefined);
  retained=bytes;await client`UPDATE oid_run_task_action_receipt SET transaction_hash=${'0x'+'a'.repeat(64)},receipt_status='unknown' WHERE action_id=${d.actionId}`;const unknown=await getTaskActionState(deps,principal,target);assert.equal(unknown.status,'unknown');assert.equal(unknown.transactionHash,'0x'+'a'.repeat(64));assert.equal(unknown.rejectionProof,undefined);
  await assert.rejects(()=>getTaskActionState(deps,{...principal,agentId:randomUUID()},target));
 }finally{await client.end();if(created)await admin.unsafe(`DROP DATABASE ${name} WITH (FORCE)`);await admin.end();}
});
