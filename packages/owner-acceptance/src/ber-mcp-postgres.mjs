/** Actual authenticated HTTP/MCP + isolated PostgreSQL, synthetic task fixtures.
 * No browser, participant model, executor or chain-effect acceptance is claimed.
 * Run with node --import tsx. Only a fresh oid_acceptance_* database is writable.
 */
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import pg from 'pg';
import { createRequire } from 'node:module';
const Fastify = createRequire(new URL('../../owner-identity/package.json',import.meta.url))('fastify');
import { seedActionRun } from './task-action-cases.mjs';
import { createDatabase } from '../../owner-identity/src/db.ts';
import { loadConfig } from '../../owner-identity/src/config.ts';
import { createAuth } from '../../owner-identity/src/auth.ts';
import { registerAgentRoutes } from '../../owner-identity/src/agents.ts';
import { registerRunIntentMcpTools } from '../../owner-identity/src/run-routes.ts';

const sha=v=>createHash('sha256').update(v).digest('hex');
const id=randomUUID(), database='oid_acceptance_'+id.replaceAll('-','');
assert.match(database,/^oid_acceptance_[a-f0-9]{32}$/);
const url=(role,password,db)=>{const u=new URL(`postgres://${role}@postgres:5432/${db}`);u.password=password;return u.href;};
const password=(await readFile('/run/secrets/owner_password','utf8')).trim();
const observerPassword=(await readFile('/run/secrets/observer_password','utf8')).trim();
const base=new pg.Client({connectionString:url('oid_owner',password,'owner_identity')});
const ownerUrl=url('oid_owner',password,database), observerUrl=url('oid_observer',observerPassword,database);
const env={...process.env,NODE_ENV:'test',OID_DATABASE_URL:ownerUrl,OID_OBSERVER_DATABASE_URL:observerUrl,
  OID_AUTH_SECRET:randomBytes(32).toString('base64url'),OID_PUBLIC_ORIGIN:'http://127.0.0.1:8784',OID_API_HOST:'127.0.0.1',OID_API_PORT:'8784',
  OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'false',OID_LOCAL_REPORT_ACCEPTANCE_ENABLED:'false',OID_MCP_TRANSPORT_PROFILE:'strict-2026-07-28'};
delete env.OID_BETA_MANIFEST_FILE; delete env.OID_LOCAL_BEF_TASK_COORDINATOR_CONFIG; delete env.OID_BETA_BEF_TASK_COORDINATOR_CONFIG;
const capture={schemaVersion:'ber-authenticated-mcp-postgres/v1',boundary:'synthetic_tasks_actual_authenticated_http_mcp_postgres_no_executor_or_model',database,sourceHashes:{},exchanges:[],observations:[],status:'running'};
const captureRoot=`/workspace/artifacts/runs/ber-mcp-postgres/${id}`;
let db,setup,observer,app;
try{
  await mkdir(captureRoot,{recursive:true});capture.sourceHashes.producer=sha(await readFile(new URL(import.meta.url)));
  for(const file of ['agents.ts','mcp-input-bounds.ts','task-action-service.ts','task-issuance.ts','run-routes.ts']) capture.sourceHashes[file]=sha(await readFile(`/workspace/packages/owner-identity/src/${file}`));
  await base.connect();await base.query(`CREATE DATABASE "${database}" TEMPLATE template0`);await base.query(`GRANT CONNECT ON DATABASE "${database}" TO oid_observer`);
  const migration=spawnSync('node',['--import','tsx','src/migrate.ts'],{cwd:'/workspace/packages/owner-identity',env,encoding:'utf8',maxBuffer:1024*1024});
  assert.equal(migration.status,0,'isolated migration must succeed');
  setup=new pg.Pool({connectionString:ownerUrl});observer=new pg.Client({connectionString:observerUrl});await observer.connect();
  await setup.query('GRANT USAGE ON SCHEMA public TO oid_observer');await setup.query('GRANT SELECT ON ALL TABLES IN SCHEMA public TO oid_observer');
  assert.deepEqual((await observer.query("select current_user as role,current_setting('transaction_read_only') as readonly")).rows[0],{role:'oid_observer',readonly:'on'});
  db=createDatabase({databaseUrl:ownerUrl});const config=loadConfig(env);app=Fastify({logger:false});
  const deps={db:db.db,config,auth:createAuth(config,db.db),resolveOwner:async()=>{throw Error('unused');},requireOrigin:async()=>{},rateLimit:async()=>{},rateLimitMax:1000,credentialRateLimitMax:1000,preflightRateLimitMax:1000,manualCredentialTtlSeconds:86400,agentResource:'',agentPreflightUrl:'',registerMcpTools:(server,principal)=>registerRunIntentMcpTools(server,principal,{db:db.db})};
  registerAgentRoutes(app,deps);const origin=await app.listen({host:'127.0.0.1',port:0});config.publicOrigin=origin;config.apiPort=Number(new URL(origin).port);deps.agentResource=origin+'/api/agent';deps.agentPreflightUrl=origin+'/api/agent/preflight';
  async function fixture(taskId){const f=await seedActionRun(setup,{taskId});f.grantId=randomUUID();const token='aap1_'+randomBytes(32).toString('base64url');await setup.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,resource,role,access_generation,expires_at) VALUES($1,$2,$3,$4,'manual',$5,'agent',1,clock_timestamp()+interval '1 hour')`,[f.grantId,f.ownerId,f.agentId,randomUUID(),deps.agentResource]);await setup.query('INSERT INTO oid_agent_manual_credential(id,grant_id,verifier_hash) VALUES($1,$2,$3)',[randomUUID(),f.grantId,sha(token)]);return {...f,token};}
  async function call(f,name,args,label){const body={jsonrpc:'2.0',id:randomUUID(),method:'tools/call',params:{name,arguments:args,_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':{}}}};const response=await fetch(origin+'/api/agent/mcp',{method:'POST',headers:{authorization:'Bearer '+f.token,origin,accept:'application/json, text/event-stream','content-type':'application/json','mcp-protocol-version':'2026-07-28','mcp-method':'tools/call','mcp-name':name},body:JSON.stringify(body)});const text=await response.text();capture.exchanges.push({label,request:body,httpStatus:response.status,responseText:text});let parsed;try{parsed=JSON.parse(text);}catch{parsed={};}const content=parsed.result?.content?.[0]?.text;return {httpStatus:response.status,envelope:parsed,value:content?(()=>{try{return JSON.parse(content);}catch{return {validationText:content};}})():null};}
  const snap=async f=>(await observer.query(`select closure_status,closure_operation_id,(select md5(coalesce(string_agg(to_jsonb(e)::text,'' order by id),'')) from oid_ledger_entry e) as ledger_hash,(select count(*)::int from oid_run_task_action where run_id=$1) as actions,(select count(*)::int from oid_run_task_closure where run_id=$1) as closures from oid_run_task where run_id=$1 and task_index=0`,[f.runId])).rows[0];
  const f=await fixture('S2'), op=randomUUID(),target={runId:f.runId,taskIndex:0,operationId:op};
  const before=await snap(f);const bad=await call(f,'runs.finish_task',{...target,answer:{score:1}},'invalid_finish');assert.equal(bad.value?.error?.code,'INVALID_TASK_ANSWER');assert.deepEqual(await snap(f),before);
  const nul=await call(f,'runs.finish_task',{...target,answer:{authFields:[{name:'x',value:'\u0000'}]}},'nul_answer_denied_before_write');assert.equal(nul.value?.error?.code,'INVALID_TASK_ANSWER');assert.deepEqual(await snap(f),before);
  const answer=Object.fromEntries(['amountUnits','network','assetId','recipient','scheme','resourceId','offerId','version'].map(k=>[k,'\u0001'.repeat(512)]));answer.authFields=Array.from({length:128},()=>({name:'\u0001'.repeat(128),value:'\u0001'.repeat(512)}));
  const good=await call(f,'runs.finish_task',{...target,answer},'valid_retry_same_operation_max_s2');assert.equal(good.value?.error,undefined);const after=await snap(f);assert.equal(after.closures,1);assert.equal(after.closure_operation_id,op);capture.observations.push({label:'invalid_finish_unchanged_then_same_operation_closure',before,after});
  const s=await fixture('M3'),t={runId:s.runId,taskIndex:0,operationId:randomUUID()};const command={kind:'swap',inputAssetId:'WETH',outputAssetId:'USDC',amountInUnits:'1',amountOutMinimumUnits:'1',recipient:'0x'+'1'.repeat(40),gasLimit:'1',feeTier:3000};
  const admitted=await call(s,'runs.task_action',{...t,command},'full_swap_admitted');assert.equal(admitted.value?.admitted,true);assert.equal((await snap(s)).actions,1);
  const state=await snap(s);const unknown=await call(s,'runs.task_action',{...t,operationId:randomUUID(),command:{...command,arbitraryRpc:'forbidden'}},'unknown_field_denied');assert.equal(unknown.envelope.result?.isError,true);assert.deepEqual(await snap(s),state);
  let nested={};for(let i=0;i<12;i++)nested={child:nested};const depth=await call(s,'runs.finish_task',{...t,answer:nested},'depth_denied');assert.equal(depth.httpStatus,400);assert.deepEqual(await snap(s),state);
  const elements=await call(s,'runs.finish_task',{...t,answer:{authFields:Array(513).fill({name:'x',value:'y'})}},'element_bound_denied');assert.equal(elements.httpStatus,400);assert.deepEqual(await snap(s),state);
  const foreign=await call(f,'runs.task_action',{...t,operationId:randomUUID(),command},'foreign_run_denied');assert.equal(foreign.value?.error?.code,'RUN_NOT_FOUND');assert.deepEqual(await snap(s),state);
  const bytes=await call(s,'runs.finish_task',{...t,answer:{offerId:'x'.repeat(530000)}},'bytes_denied');assert.equal(bytes.httpStatus,413);assert.deepEqual(await snap(s),state);
  capture.observations.push({label:'one_swap_admission_and_denials_preserve_rows',before:state,after:await snap(s)});capture.status='passed';
}catch(error){capture.status='failed';capture.failure={name:error.name,message:error.message};process.exitCode=1;}
finally{await writeFile(captureRoot+'/capture.json',JSON.stringify(capture,null,2));await app?.close();await db?.client.end();await setup?.end();await observer?.end();await base.end();console.log(JSON.stringify({status:capture.status,database,capturePath:captureRoot+'/capture.json',exchanges:capture.exchanges.length,failure:capture.failure}));}
