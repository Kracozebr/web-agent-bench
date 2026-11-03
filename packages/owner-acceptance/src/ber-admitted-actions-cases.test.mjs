import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {observeBerS1PayRunTerminal} from './ber-admitted-actions-cases.mjs';
import {selectControlledS1PayOffer,assertControlledS1OfferRead,performBerAdmittedS1PayOnly,runBerAdmittedS1PaySmoke,finishBerControlledS1Task} from './ber-admitted-actions-cases.mjs';
// Pure operator-boundary controls only. They are not a real MCP/chain smoke.
const conditions={tokenAssetId:'USDC',recipient:'0x'+'1'.repeat(40),exactPrincipalUnits:'200000'};
const payment={scheme:'exact',network:'eip155:8453',asset:'0x'+'2'.repeat(40),amount:'100000',payTo:'0x'+'3'.repeat(40),transferMethod:'transfer_with_authorization',name:'USD Coin',version:'2',paymentFlow:'authorization'};
const resource=(id='public_resource',terms=payment)=>({resourceId:id,resourceSha256:'a'.repeat(64),contentType:'application/json',offers:[{id:'canonical',payment:structuredClone(terms)}]});
const smokeInput=()=>({berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,taskId:'S1',mode:'training'});
test('paid completion retains actual MCP terminal records without another admission and never retains callback bearer',async()=>{
 const runId=randomUUID(),agentId=randomUUID(),seen=[];let callbackCount=0;
 const result=await runBerAdmittedS1PaySmoke({...smokeInput(),onGenuineRunCompleted:()=>{callbackCount++;}},{
  async runGenuineS1OwnerCase(options){seen.push('original_run');await options.onGenuineRunCompleted({runId,agentId,mode:'training',taskIds:['S1'],agentBearer:'PRIVATE_CALLBACK_CANARY'});return {status:'blocked',runId,agent:{agentId},runCompletion:{status:'verified'}};},
  async observeTerminal(options){seen.push('terminal_read');assert.equal(options.agentBearer,'PRIVATE_CALLBACK_CANARY');const body={run:{runId,status:'completed',terminal:true,terminalReason:null}};options.record({observedAt:'2026-11-03T00:00:00.000Z',body});return {...body.run};}
 });
 assert.deepEqual(seen,['original_run','terminal_read']);assert.equal(callbackCount,1);
 assert.equal(result.berAdmittedS1PayQualification.terminalMcp.records[0].body.run.runId,runId);
 assert.equal(result.berAdmittedS1PayQualification.terminalMcp.result.status,'completed');assert(!JSON.stringify(result).includes('PRIVATE_CALLBACK_CANARY'));
});
test('paid completion rejects foreign context, foreign run result, cancelled, nonterminal and missing callback',async()=>{
 for(const variant of ['foreign_context','foreign_run','cancelled','nonterminal','timeout','missing_callback','duplicate_callback']){
  const runId=randomUUID(),agentId=randomUUID();let observed=0,primary;
  const result=await runBerAdmittedS1PaySmoke(smokeInput(),{
   async runGenuineS1OwnerCase(options){const context={runId,agentId,mode:variant==='foreign_context'?'ranked':'training',taskIds:['S1']};try{if(variant!=='missing_callback'){await options.onGenuineRunCompleted(context);if(variant==='duplicate_callback')await options.onGenuineRunCompleted(context);}}catch(error){primary=error.code;}return {status:primary?'blocked':'captured',runId,agent:{agentId},runCompletion:{status:'verified'}};},
   async observeTerminal(){observed++;if(variant==='timeout')throw Object.assign(new Error('safe timeout'),{code:'ber_matrix_monitor_response_invalid'});return {runId:variant==='foreign_run'?randomUUID():runId,status:variant==='cancelled'?'cancelled':variant==='nonterminal'?'running':'completed',terminal:variant!=='nonterminal'};}
  });
  assert.equal(result.status,'blocked',variant);assert.equal(observed,variant==='foreign_context'||variant==='missing_callback'?0:1,variant);
  if(variant==='duplicate_callback')assert.equal(primary,'ber_s1_completion_identity_mismatch');
 }
});
test('paid terminal read-only SDK boundary polls only current_task and closes for success, malformed identity, tool error and timeout',async()=>{
 for(const variant of ['completed','foreign_run','tool_error','timeout']){
  const runId=randomUUID(),agentId=randomUUID(),calls=[],records=[];let closed=0,clock=0;
  const attempt=observeBerS1PayRunTerminal({runId,agentId,agentBearer:'PRIVATE_CALLBACK_CANARY',deadlineMs:5000,record:r=>records.push(r)},{
   async openSession(){return {async callTool(tool,args){calls.push({tool,args});return {isError:variant==='tool_error',structuredContent:{run:{runId:variant==='foreign_run'?randomUUID():runId,status:variant==='timeout'?'running':'completed',terminal:variant!=='timeout'},retryAfterMs:2100}};},async close(){closed++;}};},clock:{now:()=>clock,sleep:async ms=>{clock+=ms;}}
  });
  if(variant==='foreign_run'||variant==='tool_error')await assert.rejects(attempt,/ber_matrix_monitor_response_invalid/);
  else{const result=await attempt;assert.equal(result.terminal,variant==='completed');if(variant==='timeout')assert.equal(result.reason,'monitor_deadline_reached_without_server_terminal');}
  assert.equal(closed,1);assert(calls.length>0);assert(calls.every(c=>c.tool==='runs.current_task'&&c.args.runId===runId));assert(!JSON.stringify(records).includes('PRIVATE_CALLBACK_CANARY'));
 }
});
test('controlled mistake selects original public canonical terms without repairing them toward S1 goal',()=>{
 const body={catalog:[resource()]},before=structuredClone(body),selection=selectControlledS1PayOffer(body,conditions);
 assert.deepEqual(selection,{resourceId:'public_resource',resourceSha256:'a'.repeat(64),contentType:'application/json',offerId:'canonical',publicPayment:payment});assert.deepEqual(body,before);
 assert.notEqual(selection.publicPayment.payTo,conditions.recipient);assert.notEqual(selection.publicPayment.amount,conditions.exactPrincipalUnits);
});
test('actual catalog shape has no root payment; only observed /offer root and first terms establish canonical identity before pay',()=>{
 const r=resource(),selection=selectControlledS1PayOffer({catalog:[r]},conditions);assert.equal(Object.hasOwn(r,'payment'),false);
 const id='11111111-1111-4111-8111-111111111111',body={...structuredClone(r),payment:structuredClone(payment),freeInspection:true,deliveryState:'not_delivered',operationId:id,readHandle:{kind:'offer',operationId:id}};
 assertControlledS1OfferRead(selection,body);
 for(const key of ['version','name','payTo','amount','asset','network','transferMethod'])for(const location of ['root','first']){const changed=structuredClone(body);(location==='root'?changed.payment:changed.offers[0].payment)[key]='changed';assert.throws(()=>assertControlledS1OfferRead(selection,changed),/ber_s1_actual_canonical_offer_terms_mismatch/);}
 for(const changed of [{...body,payment:undefined},{...body,resourceSha256:'b'.repeat(64)},{...body,readHandle:{kind:'offer',operationId:'22222222-2222-4222-8222-222222222222'}},{...body,offers:[{id:'substituted',payment},...body.offers]}])assert.throws(()=>assertControlledS1OfferRead(selection,changed),/ber_s1_actual_canonical_offer_identity_mismatch/);
 const exact=resource('goal_equivalent',{...payment,payTo:conditions.recipient,amount:conditions.exactPrincipalUnits});assert.throws(()=>selectControlledS1PayOffer({catalog:[exact]},conditions),/ber_s1_no_scoped_nonobjective_canonical_offer/);
 assert.throws(()=>selectControlledS1PayOffer({catalog:[]},conditions),/ber_s1_no_scoped_nonobjective_canonical_offer/);
});
test('operator refuses non-optin, Ranked, arbitrary tasks and original Google observer before any actual transport',async()=>{
 await assert.rejects(runBerAdmittedS1PaySmoke({berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,taskId:'S1',mode:'ranked'}),/ber_s1_exact_smoke_profile_required/);
 const input={berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,observerDatabaseUrl:'postgres://oid_observer@postgres:5432/oid_google_local_0123456789abcdef0123456789abcdef'};
 await assert.rejects(performBerAdmittedS1PayOnly({input,mode:'training',taskId:'S1',taskIndex:0,output:{taskIds:['S1']}},{}),/ber_s1_disposable_observer_required/);
 await assert.rejects(performBerAdmittedS1PayOnly({input:{...input,berAdmittedS1PayOnly:false},mode:'training',taskId:'S1',taskIndex:0,output:{taskIds:['S1']}},{}),/ber_s1_exact_controlled_boundary_required/);
});

test('reference closure allows only the exact execution-pinned manifest and keeps namespace/path/hash guards',async()=>{
 const {mkdtemp,mkdir,writeFile,rm}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{join}=await import('node:path'),{createHash}=await import('node:crypto');
 const {retainEvidenceClosure}=await import('./ber-admitted-actions-cases.mjs');const root=await mkdtemp(join(tmpdir(),'ber-ref-'));const hash=b=>createHash('sha256').update(b).digest('hex');
 try{
  const path='infrastructure/benchmark-environment/manifest.json',bytes=Buffer.from('{}\n'),sha256=hash(bytes);await mkdir(join(root,'infrastructure/benchmark-environment'),{recursive:true});await writeFile(join(root,path),bytes);
  const bundle={execution:{environmentManifestHash:sha256},reference:{path,sha256}};assert.equal((await retainEvidenceClosure(root,bundle)).length,1);
  for(const changed of [{...bundle,reference:{path:'infrastructure/benchmark-environment/other.json',sha256}},{...bundle,execution:{environmentManifestHash:'0'.repeat(64)}},{reference:{path,sha256}},{...bundle,reference:{path:'artifacts/runs/../../../outside.json',sha256}},{...bundle,reference:{path:'infrastructure\\benchmark-environment\\manifest.json',sha256}}])await assert.rejects(retainEvidenceClosure(root,changed),/ber_s1_evidence_(namespace|path)_invalid/);
  await writeFile(join(root,path),'changed');await assert.rejects(retainEvidenceClosure(root,bundle),/ber_s1_evidence_hash_mismatch/);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('fault seam surrounds one actual finish call with the same generated operation and returned closure identity',async()=>{
 const runId='11111111-1111-4111-8111-111111111111',closureId='22222222-2222-4222-8222-222222222222',calls=[];
 const fault={variant:'missing_child',beforeFinish:async x=>calls.push({phase:'before',...x}),afterFinish:async x=>calls.push({phase:'after',...x}),close:async()=>calls.push({phase:'close'})};
 const result=await finishBerControlledS1Task({input:{berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,berGenericSealFault:fault},mode:'training',taskIds:['S1'],runId,taskIndex:0,taskId:'S1',call:async(tool,args)=>{calls.push({phase:'mcp',tool,...args});return{closureId};}});
 assert.deepEqual(calls.map(x=>x.phase),['before','mcp','after','close']);assert.equal(calls[1].tool,'runs.finish_task');assert.equal(calls[1].operationId,result.operationId);assert.equal(calls[2].operationId,result.operationId);assert.equal(calls[2].closureId,closureId);assert.equal(calls[1].runId,runId);assert.equal(calls.filter(x=>x.phase==='mcp').length,1);
});

test('finish rejection or fault observation failure never retries finish and always releases the holder',async()=>{
 for(const failure of ['before','mcp','after']){
  const calls=[],primary=Object.assign(new Error('synthetic-unit-boundary'),{code:'UNIT_PRIMARY'}),fault={variant:'corrupt_child',beforeFinish:async()=>{calls.push('before');if(failure==='before')throw primary;},afterFinish:async()=>{calls.push('after');if(failure==='after')throw primary;},close:async()=>calls.push('close')};
  await assert.rejects(finishBerControlledS1Task({input:{berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,berGenericSealFault:fault},mode:'training',taskIds:['S1'],runId:'11111111-1111-4111-8111-111111111111',taskIndex:0,taskId:'S1',call:async()=>{calls.push('mcp');if(failure==='mcp')throw primary;return{closureId:'22222222-2222-4222-8222-222222222222'};}}),e=>e===primary);
  assert.equal(calls.filter(x=>x==='mcp').length,failure==='before'?0:1);assert.equal(calls.at(-1),'close');
 }
});

test('cleanup failure preserves the primary failure and cannot skip other actor cleanup via a retry',async()=>{
 const primary=Object.assign(new Error('primary synthetic'),{code:'UNIT_PRIMARY'}),cleanup=Object.assign(new Error('cleanup synthetic'),{code:'UNIT_CLEANUP'});let closeCount=0;
 const fault={variant:'restart_blocked_seal',beforeFinish:async()=>{},afterFinish:async()=>{throw primary;},close:async()=>{closeCount++;throw cleanup;}};
 await assert.rejects(finishBerControlledS1Task({input:{berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,berGenericSealFault:fault},mode:'training',taskIds:['S1'],runId:'11111111-1111-4111-8111-111111111111',taskIndex:0,taskId:'S1',call:async()=>({closureId:'22222222-2222-4222-8222-222222222222'})}),e=>e.code==='BER_GENERIC_SEAL_FAULT_CLEANUP_FAILED'&&e.errors[0]===primary&&e.errors[1]===cleanup);assert.equal(closeCount,1);
});

test('a foreign actor profile cannot invoke any generic fault callback or finish transport',async()=>{
 let calls=0;const fault={variant:'missing_child',beforeFinish:async()=>calls++,afterFinish:async()=>calls++,close:async()=>calls++};
 await assert.rejects(finishBerControlledS1Task({input:{berAdmittedS1PayOnly:true,automaticWorkerEvaluation:true,berGenericSealFault:fault},mode:'ranked',taskIds:['S1'],taskIndex:0,taskId:'S1',call:async()=>calls++}),/EXACT_ACTOR_REQUIRED/);assert.equal(calls,0);
});
