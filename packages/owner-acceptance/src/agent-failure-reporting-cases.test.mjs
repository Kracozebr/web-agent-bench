import test from 'node:test';
import assert from 'node:assert/strict';
import {platformFailureReportArguments,buildNativeFailureReportingPrompt,verifyFailureRunIntent,readAgentFailureProductionHandoff,findAgentFailureReceiptTarget} from './agent-failure-reporting-cases.mjs';
const runId='11111111-1111-4111-8111-111111111111',agentId='22222222-2222-4222-8222-222222222222',actionId='33333333-3333-4333-8333-333333333333';
const terminal={run:{runId,status:'cancelled',terminal:true,terminalReason:null,cancellationReason:'coordinator_evaluation_unknown'},task:null};

test('bounded successor preparation failure reports after authoritative terminal refresh, never from elapsed time alone',()=>{
 const waiting={run:{runId,status:'running',terminal:false,terminalReason:null,cancellationReason:null,overallDeadline:'2000-01-01T00:00:00Z'},task:null,state:'awaiting_terminal'};
 assert.equal(platformFailureReportArguments({runId,terminal:waiting}),null);
 const closed={...waiting,run:{...waiting.run,status:'cancelled',terminal:true,cancellationReason:'coordinator_preparation_failed'}};
 const args=platformFailureReportArguments({runId,terminal:closed});
 assert.deepEqual(args,{operationId:'afr_'+runId.replaceAll('-',''),title:'Platform run failure',body:'Server-confirmed platform failure; runStatus=cancelled; reason=coordinator_preparation_failed.',runId});
 assert.deepEqual(platformFailureReportArguments({runId,terminal:closed}),args);
 assert.equal(platformFailureReportArguments({runId,terminal:{...closed,run:{...closed.run,cancellationReason:'coordinator_run_deadline'}}}),null);
});
test('only authoritative terminal platform categories create a deterministic safe private report',()=>{
 const input={terminal,runId,taskId:'H1',actionId,hiddenRankedAnswer:'never-copy',authorization:'never-copy'};
 const args=platformFailureReportArguments(input);
 assert.deepEqual(args,{operationId:'afr_'+runId.replaceAll('-',''),title:'Platform run failure',body:'Server-confirmed platform failure; runStatus=cancelled; reason=coordinator_evaluation_unknown.',runId,taskId:'H1',actionId});
 assert.deepEqual(platformFailureReportArguments(input),args);assert.ok(!JSON.stringify(args).includes('never-copy'));
 const prompt=buildNativeFailureReportingPrompt({agentId,runId,args});assert.ok(prompt.includes(JSON.stringify(args)));assert.ok(prompt.includes('support.report_receipt'));assert.ok(prompt.includes('Do not create, accept or relaunch a run'));assert.ok(!prompt.includes('support.screenshot'));
 for(const status of ['failed','partial','completed','running'])for(const reason of [null,'task_deadline','coordinator_run_deadline','owner_cancelled'])assert.equal(platformFailureReportArguments({runId,terminal:{run:{runId,status,terminal:status!=='running',terminalReason:reason},task:null}}),null);
 assert.equal(platformFailureReportArguments({runId,terminal:{...terminal,run:{...terminal.run,terminal:false}}}),null);
 assert.equal(platformFailureReportArguments({runId,terminal:{...terminal,run:{...terminal.run,status:'completed'}}}),null);
 assert.equal(platformFailureReportArguments({runId,terminal:{...terminal,run:{...terminal.run,runId:agentId}}}),null);
 assert.throws(()=>platformFailureReportArguments({runId,terminal,taskId:'secret-task-variant'}));
 assert.throws(()=>platformFailureReportArguments({runId,terminal,actionId:'arbitrary-payload'}));
});

test('readonly failure projection requires the immutable run intent and current agent',()=>{
 const intentId='44444444-4444-4444-8444-444444444444';
 const row={id:runId,intent_id:intentId,agent_id:agentId};
 assert.doesNotThrow(()=>verifyFailureRunIntent(row,{runId,intentId,agentId}));
 for(const changed of [{...row,intent_id:actionId},{...row,agent_id:actionId},{...row,id:actionId},{...row,intent_id:null}])assert.throws(()=>verifyFailureRunIntent(changed,{runId,intentId,agentId}),/AFR_IMMUTABLE_RUN_INTENT_BINDING/);
});

test('genuine callback grants clipboard permissions for its exact origin before copy/read and retains safe read failures',async()=>{
 const order=[],text='Automatic private support reporting: safe production handoff';
 const ctx={intentId:runId,publicOrigin:'http://127.0.0.1:3000',launchIntent:{database:{id:runId}},ownerPage:{
  context:()=>({grantPermissions:async(names,options)=>{assert.deepEqual(names,['clipboard-read','clipboard-write']);assert.deepEqual(options,{origin:'http://127.0.0.1:3000'});order.push('permission');}}),
  getByTestId:id=>id.startsWith('run-intent-handoff-text-')?{innerText:async()=>{order.push('visible');return text;}}:{click:async()=>{order.push('click');},innerText:async()=>'Copied safe handoff'},
  evaluate:async()=>{order.push('read');return text;},url:()=> 'http://127.0.0.1:3000/runs'}};
 const proof=await readAgentFailureProductionHandoff(ctx);assert.deepEqual(order,['permission','visible','click','read']);assert.equal(proof.clipboard,proof.visible);assert.deepEqual(proof.intentSnapshot,{id:runId});
 ctx.ownerPage.evaluate=async()=>{throw new Error('private browser exception with credential-like text');};
 await assert.rejects(readAgentFailureProductionHandoff(ctx),error=>error.code==='AFR_CLIPBOARD_READ_UNAVAILABLE'&&error.message==='AFR_CLIPBOARD_READ_UNAVAILABLE');
 ctx.ownerPage.evaluate=async()=>text+'truncated';await assert.rejects(readAgentFailureProductionHandoff(ctx),error=>error.code==='AFR_PRODUCTION_HANDOFF_REQUIRED');
});

test('real Chromium genuine callback copies the exact production handoff with explicit clipboard permissions',{skip:!process.env.OID_CHROMIUM_EXECUTABLE},async()=>{
 const {createServer}=await import('node:http'),{chromium}=await import('playwright');
 const {buildRunHandoffPrompt}=await import('../../owner-web/lib/run-handoff.ts');
 const intent={id:runId,agentId,mode:'training',taskIds:['S1','M1','H1'],quote:{price:'0.500000',token:'USDC',precision:6},cashCeiling:'0'};
 const text=buildRunHandoffPrompt(intent),escape=value=>value.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
 const server=createServer((req,res)=>{res.setHeader('content-type','text/html; charset=utf-8');res.end(`<button data-testid="run-intent-handoff-${runId}">Copy safe handoff prompt</button><p style="white-space:pre-wrap" data-testid="run-intent-handoff-text-${runId}">${escape(text)}</p><script>document.querySelector('button').onclick=async()=>{await navigator.clipboard.writeText(document.querySelector('p').textContent);document.querySelector('button').textContent='Copied safe handoff';}</script>`);});
 await new Promise(done=>server.listen(0,'127.0.0.1',done));let browser;
 try{browser=await chromium.launch({executablePath:process.env.OID_CHROMIUM_EXECUTABLE,headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const context=await browser.newContext(),page=await context.newPage(),publicOrigin=`http://127.0.0.1:${server.address().port}`;await page.goto(publicOrigin);
  const proof=await readAgentFailureProductionHandoff({ownerPage:page,publicOrigin,intentId:runId,launchIntent:{database:{id:runId}}});
  assert.equal(proof.clipboard,text);assert.equal(proof.visible,text);assert.equal(proof.clicked,true);
 }finally{await browser?.close();server.closeAllConnections();await new Promise(done=>server.close(done));}
});

test('actual PostgreSQL receipt predicate uses current production columns and targets only exact closed H1 payments',{skip:process.env.OID_AFR_PREDICATE_PG_TEST!=='1'},async()=>{
 const {default:pg}=await import('pg'),{randomUUID}=await import('node:crypto');
 const url=new URL(process.env.OID_DATABASE_URL);assert.equal(url.hostname,'postgres');assert.equal(url.username,'oid_owner');assert.equal(url.pathname,'/owner_identity');
 const client=new pg.Client({connectionString:url.href});await client.connect();
 try{
  // Copy TYPES/column names from the actual migrated schema, with NO production rows or writes.
  await client.query('CREATE TEMP TABLE oid_benchmark_run AS SELECT id,intent_id,owner_id,agent_id FROM public.oid_benchmark_run WITH NO DATA');
  await client.query('CREATE TEMP TABLE oid_run_task AS SELECT run_id,task_index,task_id,closure_id,closure_status FROM public.oid_run_task WITH NO DATA');
  await client.query('CREATE TEMP TABLE oid_run_task_action AS SELECT id,run_id,task_index,task_id,owner_id,agent_id,action_kind FROM public.oid_run_task_action WITH NO DATA');
  await client.query('CREATE TEMP TABLE oid_run_task_action_receipt AS SELECT action_id,receipt_revision,transaction_hash FROM public.oid_run_task_action_receipt WITH NO DATA');
  await client.query('SET search_path=pg_temp');
  const ownerId=randomUUID(),localAgent=randomUUID(),intentId=randomUUID(),localRun=randomUUID(),closureId=randomUUID(),payId=randomUUID(),retrieveId=randomUUID(),txHash='0x'+'a'.repeat(64);
  const readonlyQuery=async(text,args)=>{await client.query('BEGIN READ ONLY');try{const result=await client.query(text,args);await client.query('COMMIT');return result.rows;}catch(error){await client.query('ROLLBACK');throw error;}};
  const ctx={ownerId,agentId:localAgent,intentId,readonlyQuery};
  // The old nonexistent revision reference failed even for an empty/pre-H1 result.
  assert.equal(await findAgentFailureReceiptTarget(ctx,txHash),null);
  await client.query('INSERT INTO oid_benchmark_run VALUES($1,$2,$3,$4)',[localRun,intentId,ownerId,localAgent]);
  await client.query("INSERT INTO oid_run_task VALUES($1,0,'S1',$2,'closed'),($1,2,'H1',$3,'open')",[localRun,randomUUID(),closureId]);
  await client.query("INSERT INTO oid_run_task_action VALUES($1,$2,2,'H1',$3,$4,'pay'),($5,$2,2,'H1',$3,$4,'retrieve')",[payId,localRun,ownerId,localAgent,retrieveId]);
  await client.query('INSERT INTO oid_run_task_action_receipt VALUES($1,3,$2),($3,2,$2)',[payId,txHash,retrieveId]);
  assert.equal(await findAgentFailureReceiptTarget(ctx,txHash),null,'an open H1 must not be affected');
  await client.query("UPDATE oid_run_task SET closure_status='closed' WHERE task_id='H1'");
  assert.deepEqual(await findAgentFailureReceiptTarget(ctx,txHash),{runId:localRun,taskIndex:2,taskId:'H1',closureId});
  for(const foreign of [{...ctx,intentId:randomUUID()},{...ctx,ownerId:randomUUID()},{...ctx,agentId:randomUUID()}])assert.equal(await findAgentFailureReceiptTarget(foreign,txHash),null);
  assert.equal(await findAgentFailureReceiptTarget(ctx,'0x'+'b'.repeat(64)),null);
  await client.query("UPDATE oid_run_task_action SET agent_id=$1 WHERE id=$2",[randomUUID(),payId]);
  assert.equal(await findAgentFailureReceiptTarget(ctx,txHash),null,'foreign actor cannot become the receipt fault target');
 }finally{await client.end();}
});
