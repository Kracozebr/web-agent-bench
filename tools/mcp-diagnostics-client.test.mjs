import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,readdir,lstat,writeFile,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,basename,sep} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {DIAGNOSTIC_RUN_STATUSES,DIAGNOSTIC_ERROR_CODES,DIAGNOSTIC_TOOLS,DIAGNOSTIC_FIELD_PATHS,canonicalDiagnosticJson,diagnosticHash,NativeDiagnosticCollector,openDiagnosticSpool,createDiagnosticTransport,deliverDiagnosticOutbox,validateClientDiagnosticEnvelope} from './mcp-diagnostics-client.mjs';

const ID='81cc2a3b-bde3-4ec4-b426-1a92064d04bb',INTENT='1f6c98f3-c7b4-428e-856d-e0dd15634c5d',REMOTE='2f6c98f3-c7b4-428e-856d-e0dd15634c5d',REPORT='3f6c98f3-c7b4-428e-856d-e0dd15634c5d';
const envelope=extra=>({eventId:randomUUID(),source:'client',stage:'client_validation',tool:'runs.task_action',outcome:'error',errorCode:'INPUT_VALIDATION_ERROR',startedAt:'2026-11-02T10:00:00.000Z',completedAt:'2026-11-02T10:00:00.100Z',durationMs:100,...extra});
async function fixture(t,options={}){const dir=await mkdtemp(join(tmpdir(),'mcd-unit-'));const spool=await openDiagnosticSpool({directory:dir,...options});t.after(async()=>{spool.close();await rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:20});});return {spool,dir};}

test('client finite envelope/code registry exactly matches the independent server contract',async()=>{
  const source=await readFile(new URL('../packages/owner-identity/src/mcp-diagnostics-contract.ts',import.meta.url),'utf8');
  for(const [name,actual] of [['DIAGNOSTIC_RUN_STATUSES',DIAGNOSTIC_RUN_STATUSES],['DIAGNOSTIC_ERROR_CODES',DIAGNOSTIC_ERROR_CODES],['DIAGNOSTIC_TOOLS',DIAGNOSTIC_TOOLS],['DIAGNOSTIC_FIELD_PATHS',DIAGNOSTIC_FIELD_PATHS]]){
    const match=source.match(new RegExp('export const '+name+' = (\\[[^;]+?\\]) as const;'));assert(match,name);assert.deepEqual(actual,[...match[1].matchAll(/'([^']+)'/g)].map(x=>x[1]));
  }
  assert.equal(canonicalDiagnosticJson({b:1,a:{z:3,a:4},missing:undefined}),'{'+'"a":{"a":4,"z":3},"b":1}');
});

test('native failed calls retain exact safe code/known field and metadata, deduplicate updates, never retain messages or arguments',()=>{
  const rows=[],gaps=[],secret='sk_CANARY_SECRET_RANKED_9a4d129',trace=randomUUID();let clock=Date.parse('2026-11-02T10:00:00Z');
  const c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e),onGap:g=>gaps.push(g),now:()=>new Date(clock),model:secret,clientVersion:'0.165.0'});
  const start={type:'item.started',item:{id:'call_'+secret,type:'mcp_tool_call',server:'w3bench_user',tool:'runs.task_action',status:'in_progress',arguments:{operationId:secret,taskIndex:1,command:{recipient:secret,amount:secret}}}};
  c.feed(Buffer.from(JSON.stringify(start)+'\n'));clock+=100;
  const done={type:'item.completed',item:{...start.item,status:'failed',error:{message:'Input validation error: Invalid arguments for tool runs.task_action: operationId: '+secret},result:{_meta:{w3benchDiagnostics:{traceId:trace,capture:'recorded'}}}}};
  c.feed(Buffer.from(JSON.stringify(done)+'\n'+JSON.stringify(done)+'\n'));assert.equal(c.close().complete,true);
  assert.equal(rows.length,1);assert.equal(rows.find(e=>e.callIdHash).errorCode,'INPUT_VALIDATION_ERROR');assert.equal(rows.find(e=>e.callIdHash).stage,'client_validation');assert.deepEqual(rows.find(e=>e.callIdHash).fieldPaths,['operationId']);assert.equal(rows.find(e=>e.callIdHash).traceId,trace);assert.equal(rows.find(e=>e.callIdHash).model,'unknown');assert.equal(rows.find(e=>e.callIdHash).durationMs,100);assert(rows.find(e=>e.callIdHash).callIdHash);assert(rows.find(e=>e.callIdHash).operationIdHash);assert(!JSON.stringify(rows).includes(secret));assert.deepEqual(gaps,[]);
});

test('unregistered error and attacker controlled field/code names become UNKNOWN_ERROR with no secret excerpt',()=>{
  const rows=[];const c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e)});
  c.consume(JSON.stringify({type:'item.completed',item:{id:'x',type:'mcp_tool_call',server:'w3bench_user',tool:'arbitrary-secret-tool',status:'failed',error:{message:'sk-secret: detail'},result:{structuredContent:{error:{code:'sk-secret'}}}}}));
  assert.equal(rows.find(e=>e.callIdHash).tool,'unknown');assert.equal(rows.find(e=>e.callIdHash).errorCode,'UNKNOWN_ERROR');assert(!JSON.stringify(rows).includes('sk-secret'));
  assert.throws(()=>validateClientDiagnosticEnvelope(envelope({secret:'raw'})),/INVALID_ENVELOPE/);assert.throws(()=>validateClientDiagnosticEnvelope(envelope({errorCode:'sk-secret'})),/INVALID_ENVELOPE/);
});

test('native parser interruption/overflow are explicit gaps and a final complete JSONL line needs no newline',()=>{
  const rows=[],gaps=[];const c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e),onGap:e=>gaps.push(e),maxLineChars:400});
  c.feed(Buffer.from('x'.repeat(500)+'\n'));c.feed(Buffer.from('{broken\n'));
  c.consume(JSON.stringify({type:'item.started',item:{id:'open',type:'mcp_tool_call',server:'w3bench_user',tool:'runs.current_task',status:'in_progress'}}));
  const state=c.close({interrupted:true});assert.equal(state.complete,false);assert(gaps.includes('DIAGNOSTICS_PARSER_FAILURE'));assert(gaps.includes('CLIENT_RUNTIME_ERROR'));assert.equal(rows.find(e=>e.callIdHash).outcome,'unknown');
  const final=[];const clean=new NativeDiagnosticCollector({onEnvelope:e=>final.push(e)});clean.feed(Buffer.from(JSON.stringify({type:'item.completed',item:{id:'last',type:'mcp_tool_call',server:'w3bench_user',tool:'runs.current_task',status:'completed',result:{_meta:{'w3bench/diagnostics':{traceId:randomUUID(),capture:'recorded'}}}}})));assert.equal(clean.close().complete,true);assert.equal(final.length,1);
});

test('spool preserves case, segment and canonical batch across close/reopen; changed event identities conflict',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'mcd-reopen-'));t.after(()=>rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:20}));
  let spool=await openDiagnosticSpool({directory:dir});const c=spool.createCase({diagnosticSessionId:ID,intentId:INTENT}),segment=spool.createSegment(c.local_id),e=envelope();assert.equal(spool.append(segment,e),true);assert.equal(spool.append(segment,e),false);assert.throws(()=>spool.append(segment,{...e,durationMs:11}),/EVENT_CONFLICT/);
  const batch=spool.stageBatch(segment,{completion:'complete'});assert.equal(batch.payloadHash,diagnosticHash({segmentId:segment,batchSequence:0,events:[e],completion:'complete'}));spool.close();
  spool=await openDiagnosticSpool({directory:dir});try{const again=spool.createCase({diagnosticSessionId:randomUUID(),intentId:INTENT});assert.equal(again.local_id,c.local_id);assert.equal(again.session_id,ID);assert.deepEqual(spool.pendingBatches(c.local_id),[batch]);const bundle=spool.exportBundle(c.local_id);assert.equal(bundle.diagnosticSessionId,ID);assert.deepEqual(bundle.segments[0].batches,[batch]);}finally{spool.close();}
});

test('spool quotas preserve older evidence, mark partial, and reject new case allocation',async t=>{
  const {spool}=await fixture(t,{limits:{caseRows:2,spoolCases:1}});const c=spool.createCase({intentId:INTENT}),s=spool.createSegment(c.local_id);assert(spool.append(s,envelope()));assert(spool.append(s,envelope()));assert.equal(spool.append(s,envelope()),false);assert.equal(spool.usage().rows,2);assert.equal(spool.caseState(c.local_id).gap,'DIAGNOSTICS_QUOTA_EXCEEDED');assert.throws(()=>spool.createCase({}),/QUOTA_EXCEEDED/);const batch=spool.stageBatch(s,{completion:'partial'});assert.equal(batch.events.length,2);assert.equal(batch.completion,'partial');
});

test('lost batch response retries unchanged payload then confirms report and final watermark exactly once',async t=>{
  const {spool}=await fixture(t);const c=spool.createCase({diagnosticSessionId:ID,intentId:INTENT}),s=spool.createSegment(c.local_id);spool.append(s,envelope());const batch=spool.stageBatch(s,{completion:'complete'});let registrations=0,sends=0,creates=0,saved;
  const transport={async register(input){registrations++;assert.deepEqual(input,{diagnosticSessionId:ID,intentId:INTENT});return {caseId:REMOTE};},async sendBatch(caseId,payload){sends++;assert.equal(caseId,REMOTE);if(!saved){saved=canonicalDiagnosticJson(payload);creates++;throw new Error('DIAGNOSTICS_TRANSPORT_UNAVAILABLE');}assert.equal(canonicalDiagnosticJson(payload),saved);},async receipt(){return {caseId:REMOTE,reportId:REPORT,segmentId:s,highestContiguousSequence:0,highestContiguousHash:batch.payloadHash,completion:'complete',reportCreated:true,diagnosticsSynced:true};}};
  const result=await deliverDiagnosticOutbox({spool,transport,sleep:async()=>{},maxAttempts:2});assert.equal(result[0].state,'synced');assert.equal(result[0].attempts,2);assert.equal(registrations,1);assert.equal(sends,2);assert.equal(creates,1);assert.equal(spool.pendingBatches(c.local_id).length,0);
  const late=spool.createSegment(c.local_id);spool.append(late,envelope());assert.equal(spool.caseState(c.local_id).remote_id,REMOTE);assert.equal(spool.caseState(c.local_id).report_id,REPORT);
});

test('unverified watermark cannot mark delivery or enable payload collection',async t=>{
  const {spool}=await fixture(t);const c=spool.createCase({}),s=spool.createSegment(c.local_id);spool.append(s,envelope());spool.stageBatch(s,{completion:'complete'});spool.bindRemote(c.local_id,{caseId:REMOTE});
  assert.throws(()=>spool.acknowledge(c.local_id,{caseId:REMOTE,reportId:REPORT,segmentId:s,highestContiguousSequence:0,highestContiguousHash:'0'.repeat(64),completion:'complete',reportCreated:true,diagnosticsSynced:true}),/WATERMARK_MISMATCH/);assert.equal(spool.caseState(c.local_id).state,'open');assert.equal(spool.collectAcknowledged(),0);assert.equal(spool.usage().rows,1);
});

test('revoked auth does not retry as another case/report and remains pending_auth',async t=>{
  const {spool}=await fixture(t);const c=spool.createCase({}),s=spool.createSegment(c.local_id);spool.append(s,envelope());spool.stageBatch(s,{completion:'complete'});let calls=0;
  const result=await deliverDiagnosticOutbox({spool,transport:{async register(){calls++;throw new Error('DIAGNOSTICS_AUTH_REQUIRED');}},sleep:async()=>{throw Error('must not retry');}});assert.equal(calls,1);assert.equal(result[0].state,'pending_auth');assert.equal(spool.pendingBatches(c.local_id).length,1);assert.equal(spool.caseState(c.local_id).remote_id,null);
});

test('local expiry is evaluated before network work and removes only managed unreceived payloads',async t=>{
  let time=Date.parse('2026-11-02T00:00:00Z');const {spool}=await fixture(t,{now:()=>new Date(time)});const c=spool.createCase({}),s=spool.createSegment(c.local_id);spool.append(s,envelope());spool.stageBatch(s,{completion:'partial'});time+=31*86400000;let calls=0;
  assert.deepEqual(await deliverDiagnosticOutbox({spool,transport:{async register(){calls++;}},sleep:async()=>{}}),[]);assert.equal(calls,0);assert.equal(spool.caseState(c.local_id).state,'expired');assert.equal(spool.usage().rows,0);
});

test('diagnostic HTTP transport scopes path/body, does not follow redirects, and reports only safe failure enums',async()=>{
  let call;const transport=createDiagnosticTransport({origin:'http://127.0.0.1:3000',development:true,getAccessToken:async()=>'T'.repeat(32),fetchImpl:async(url,args)=>{call={url,args};return new Response(JSON.stringify({caseId:REMOTE,diagnosticSessionId:ID,intentId:INTENT,runId:null,reportId:null,captureState:'open'}),{status:200});}});
  assert.deepEqual(await transport.register({diagnosticSessionId:ID,intentId:INTENT}),{caseId:REMOTE,diagnosticSessionId:ID,intentId:INTENT,runId:null,reportId:null,captureState:'open'});assert.equal(call.url,'http://127.0.0.1:3000/api/diagnostics/cases');assert.equal(call.args.redirect,'error');assert.equal(call.args.headers.authorization,'Bearer '+'T'.repeat(32));assert(!call.args.body.includes('agentId'));
  const denied=createDiagnosticTransport({origin:'https://bench.example',getAccessToken:async()=>'T'.repeat(32),fetchImpl:async()=>new Response('secret',{status:403})});await assert.rejects(denied.register({diagnosticSessionId:ID}),/^Error: DIAGNOSTICS_AUTH_REQUIRED$/);
  assert.throws(()=>createDiagnosticTransport({origin:'http://foreign.example',development:true,getAccessToken:async()=>''}),/ORIGIN_INVALID/);
});

test('outbox never uploads a capture through another helper binding and canonical intent cannot silently change binding',async t=>{
  const {spool}=await fixture(t),binding={agentId:randomUUID(),connectionId:randomUUID()},other={agentId:randomUUID(),connectionId:randomUUID()},local=spool.createCase({intentId:INTENT,binding});
  assert.throws(()=>spool.createCase({intentId:INTENT,binding:other}),/BINDING_INVALID/);const segmentId=spool.createSegment(local.local_id);spool.append(segmentId,envelope());spool.stageBatch(segmentId,{completion:'complete'});assert.deepEqual(spool.exportBundle(local.local_id).binding,binding);assert.throws(()=>spool.exportBundle(local.local_id,{binding:other}),/BINDING_INVALID/);
  let calls=0;assert.deepEqual(await deliverDiagnosticOutbox({spool,binding:other,transport:{register:async()=>{calls++;}}}),[]);assert.equal(calls,0);assert.equal(spool.pendingCases({binding}).length,1);
});
test('retry budget is five attempts for the entire helper delivery lifetime across all pending cases',async t=>{
  const {spool}=await fixture(t);for(let i=0;i<3;i++){const local=spool.createCase(),segmentId=spool.createSegment(local.local_id);spool.append(segmentId,envelope());spool.stageBatch(segmentId,{completion:'complete'});}
  let calls=0;const results=await deliverDiagnosticOutbox({spool,sleep:async()=>{},transport:{register:async()=>{calls++;throw new Error('DIAGNOSTICS_TRANSPORT_UNAVAILABLE');}}});assert.equal(calls,5);assert.equal(results.reduce((sum,r)=>sum+r.attempts,0),5);assert.equal(spool.pendingCases().length,3);
});
test('new server response metadata safely exposes trace UUID without retaining arbitrary capture metadata',()=>{
  const rows=[],traceId=randomUUID(),collector=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e)});collector.consume(JSON.stringify({type:'item.completed',item:{id:'trace',type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:'completed',result:{_meta:{'w3bench/diagnostics':{traceId,capture:'secret arbitrary value'}}}}}));assert.equal(rows.find(e=>e.callIdHash).traceId,traceId);assert(!JSON.stringify(rows).includes('secret'));
});

test('final watermark without diagnostic report receipt retains final batch for idempotent rate-limit retry',async t=>{
  const {spool}=await fixture(t),local=spool.createCase(),segmentId=spool.createSegment(local.local_id);spool.append(segmentId,envelope());const batch=spool.stageBatch(segmentId,{completion:'complete'});let sends=0;const sent=[];
  await deliverDiagnosticOutbox({spool,sleep:async()=>{},transport:{register:async()=>({caseId:REMOTE}),sendBatch:async(id,b)=>{sends++;sent.push(canonicalDiagnosticJson(b));},receipt:async()=>({caseId:REMOTE,reportId:sends===1?null:REPORT,segmentId,highestContiguousSequence:0,highestContiguousHash:batch.payloadHash,completion:'complete',reportCreated:sends>1,diagnosticsSynced:sends>1})}});
  assert.equal(sends,2);assert.equal(sent[0],sent[1]);assert.equal(spool.caseState(local.local_id).state,'synced');assert.equal(spool.caseState(local.local_id).report_id,REPORT);
});

async function preservePhysicalFailure(directory,error){
  const target=resolve(directory);assert(target.startsWith(resolve(tmpdir())+sep)&&/^mcd-(?:disk-unit|process-disk)-/.test(basename(target)),'only this test-owned spool may be observed');
  const entries=[];for(const name of await readdir(target)){try{const info=await lstat(join(target,name));entries.push({name,bytes:info.size,nlink:info.nlink,isFile:info.isFile(),isSymbolicLink:info.isSymbolicLink(),modifiedAt:info.mtime.toISOString(),...(info.isFile()&&!info.isSymbolicLink()&&info.nlink===1&&info.size<=2*1024*1024?{sha256:createHash('sha256').update(await readFile(join(target,name))).digest('hex')}:{})});}catch(e){entries.push({name,statCode:e.code});}}
  // Evidence is a sibling: never add a forbidden file or alter retained spool
  // bytes while investigating the storage boundary itself.
  const proof=target+'-failure-proof';await mkdir(proof,{mode:0o700});
  await writeFile(join(proof,'failure-observation.json'),JSON.stringify({boundary:'disposable_test_spool_only',spoolBaseName:basename(target),errorName:error.name,errorCode:error.code??null,errorMessage:error.message.replaceAll(target,'[test-owned-spool]'),errorSourceStack:String(error.stack??'').replaceAll(target,'[test-owned-spool]').replaceAll(target.replaceAll('\\','/'),'[test-owned-spool]').replaceAll(process.cwd(),'[checkout]').replaceAll(process.cwd().replaceAll('\\','/'),'[checkout]'),entries},null,2));
  error.spoolFailureDirectory=target;error.spoolFailureProofDirectory=proof;
}
test('real SQLite database and rollback journal remain within shared reduced disk budget across concurrent open helpers, retained rows survive SQLITE_FULL',async t=>{
  const directory=await mkdtemp(join(tmpdir(),'mcd-disk-unit-'));let a,b,primaryError;try{
    const limit=256*1024;a=await openDiagnosticSpool({directory,limits:{diskBytes:limit}});b=await openDiagnosticSpool({directory,limits:{diskBytes:limit}});
    const ca=a.createCase(),cb=b.createCase(),sa=a.createSegment(ca.local_id),sb=b.createSegment(cb.local_id);let accepted=0,full=false;
    for(let i=0;i<2000;i++){const writer=i%2?a:b,segment=i%2?sa:sb;try{writer.append(segment,envelope({fieldPaths:['agentId','operationId','intentId','runId','taskIndex','actionId','command','answer'],callIdHash:'a'.repeat(64),operationIdHash:'b'.repeat(64),schemaHash:'c'.repeat(64),contractHash:'d'.repeat(64)}));accepted++;}catch(error){assert.match(error.message,/QUOTA_EXCEEDED/);full=true;break;}const disk=writer.diskUsage();assert(disk.bytes<=limit);assert(disk.physicalPeakBytes<=limit);}
    assert(full);assert(accepted>0);assert.equal(a.usage().rows,accepted);assert.equal(b.usage().rows,accepted);assert.equal(a.diskUsage().journalMode,'delete');assert(a.diskUsage().journalPeakBytes>0);assert(b.diskUsage().journalPeakBytes>0);assert(!a.diskUsage().files.some(f=>/-wal$|-shm$/.test(f.name)));assert.equal(a.diskUsage().maxPages,b.diskUsage().maxPages);
    const before=a.usage().rows;assert.throws(()=>a.append(sa,envelope({callIdHash:'e'.repeat(64),operationIdHash:'f'.repeat(64)})),/QUOTA_EXCEEDED/);assert.equal(a.usage().rows,before);const oldB=b;b=null;oldB.close();const oldA=a;a=null;oldA.close();a=await openDiagnosticSpool({directory,limits:{diskBytes:limit}});assert.equal(a.usage().rows,before);assert(a.diskUsage().bytes<=limit);
  }catch(error){primaryError=error;}finally{for(const instance of [b,a])try{instance?.close();}catch(error){primaryError??=error;}if(primaryError){await preservePhysicalFailure(directory,primaryError);throw primaryError;}await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:20});}
});

test('two actual helper processes compete for one physical database budget without evicting admitted evidence',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'mcd-process-disk-')),limit=256*1024;let primaryError;
  try{const initialized=await openDiagnosticSpool({directory,limits:{diskBytes:limit}});initialized.close();
    const moduleUrl=new URL('./mcp-diagnostics-client.mjs',import.meta.url).href;
    const script=`import {openDiagnosticSpool} from ${JSON.stringify(moduleUrl)}; import {randomUUID,createHash} from 'node:crypto'; const spool=await openDiagnosticSpool({directory:${JSON.stringify(directory)},limits:{diskBytes:${limit}}}); const c=spool.createCase(),s=spool.createSegment(c.local_id);let accepted=0;for(let i=0;i<500;i++){try{spool.append(s,{eventId:randomUUID(),source:'client',stage:'client_validation',tool:'identity.preflight',outcome:'error',errorCode:'INPUT_VALIDATION_ERROR',startedAt:'2026-11-02T10:00:00Z',completedAt:'2026-11-02T10:00:00Z',durationMs:0,callIdHash:'a'.repeat(64),operationIdHash:'b'.repeat(64)});accepted++;}catch(error){if(error.message!=='DIAGNOSTICS_QUOTA_EXCEEDED')throw error;break;}}const disk=spool.diskUsage();spool.close();process.stdout.write(JSON.stringify({accepted,disk}));`;
    const worker=()=>new Promise((done,reject)=>{const child=spawn(process.execPath,['--input-type=module','-e',script],{windowsHide:true,stdio:['ignore','pipe','pipe']});let output='',error='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>error+=b);child.once('error',reject);child.once('close',code=>{if(code!==0)reject(new Error('subprocess failed '+error));else try{done(JSON.parse(output));}catch(e){reject(e);}});});
    const results=await Promise.all([worker(),worker()]);for(const result of results){assert(result.disk.bytes<=limit);assert(result.disk.physicalPeakBytes<=limit);assert.equal(result.disk.journalMode,'delete');}
    const spool=await openDiagnosticSpool({directory,limits:{diskBytes:limit}});try{assert.equal(spool.usage().rows,results.reduce((n,r)=>n+r.accepted,0));assert(spool.diskUsage().bytes<=limit);assert(!spool.diskUsage().files.some(f=>/-wal$|-shm$/.test(f.name)));}finally{spool.close();}
  }catch(error){primaryError=error;}finally{if(primaryError){await preservePhysicalFailure(directory,primaryError);throw primaryError;}await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:20});}
});

test('server metadata projects only validated hashes/field vocabulary and unavailable capture remains partial',()=>{
  const rows=[],gaps=[],traceId=randomUUID(),c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e),onGap:g=>gaps.push(g)});
  c.consume(JSON.stringify({type:'item.completed',item:{id:'meta',type:'mcp_tool_call',server:'w3bench_user',tool:'runs.task_action',status:'failed',error:{code:'INVALID_ARGUMENTS'},result:{_meta:{'w3bench/diagnostics':{traceId,capture:'unavailable',schemaHash:'a'.repeat(64),contractHash:'not-a-hash-secret',fieldPaths:['agentId','arbitrary-secret','command.amount','agentId']}}}}}));
  assert.equal(rows.find(e=>e.callIdHash).traceId,traceId);assert.equal(rows.find(e=>e.callIdHash).schemaHash,'a'.repeat(64));assert.equal(rows.find(e=>e.callIdHash).contractHash,undefined);assert.deepEqual(rows.find(e=>e.callIdHash).fieldPaths,['agentId','command.amount']);assert.deepEqual(gaps,['CORRELATION_UNAVAILABLE']);assert.equal(c.close().complete,false);assert(!JSON.stringify(rows).includes('secret'));
});
test('hidden server carrier makes actual server call capture partial, while SDK-only input validation can legitimately lack a server trace',()=>{
  for(const outcome of ['completed','failed']){const gaps=[],c=new NativeDiagnosticCollector({onEnvelope:()=>true,onGap:g=>gaps.push(g)});c.consume(JSON.stringify({type:'item.completed',item:{id:outcome,type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:outcome,...(outcome==='failed'?{error:{code:'FORBIDDEN'}}:{result:{structuredContent:{status:'allowed'}}})}}));assert.deepEqual(gaps,['CORRELATION_UNAVAILABLE']);assert.equal(c.close().complete,false);}
  const gaps=[],rows=[],c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e),onGap:g=>gaps.push(g)});c.consume(JSON.stringify({type:'item.completed',item:{id:'local-sdk',type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:'failed',error:{message:'Input validation error: Invalid arguments for tool identity.preflight: agentId: Invalid UUID'}}}));assert.equal(rows.find(e=>e.callIdHash).stage,'client_validation');assert.equal(rows.find(e=>e.callIdHash).traceId,undefined);assert.deepEqual(gaps,[]);assert.equal(c.close().complete,true);
});

test('failed native lookup never promotes unverified caller action/task claims into imported relation links',()=>{
  const rows=[],foreignAction=randomUUID(),traceId=randomUUID(),c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e)});c.consume(JSON.stringify({type:'item.completed',item:{id:'foreign-lookup',type:'mcp_tool_call',server:'w3bench_user',tool:'runs.task_action_status',status:'failed',arguments:{actionId:foreignAction,taskId:'U1',taskIndex:11,operationId:'safe-operation-id'},error:{code:'TASK_ACTION_NOT_FOUND'},result:{_meta:{'w3bench/diagnostics':{traceId,capture:'recorded'}}}}}));assert.equal(rows.length,1);assert.equal(rows.find(e=>e.callIdHash).errorCode,'TASK_ACTION_NOT_FOUND');assert.equal(rows.find(e=>e.callIdHash).traceId,traceId);assert.equal(rows.find(e=>e.callIdHash).actionId,undefined);assert.equal(rows.find(e=>e.callIdHash).taskId,undefined);assert.equal(rows.find(e=>e.callIdHash).taskIndex,undefined);assert.match(rows.find(e=>e.callIdHash).operationIdHash,/^[a-f0-9]{64}$/);assert(!JSON.stringify(rows).includes(foreignAction));validateClientDiagnosticEnvelope(rows.find(e=>e.callIdHash));
});

test('SDK HTTP200 isError plain text uses finite metadata code and field paths without language parsing or raw message retention',()=>{
  const rows=[],gaps=[],traceId=randomUUID(),c=new NativeDiagnosticCollector({onEnvelope:e=>rows.push(e),onGap:g=>gaps.push(g)}),secret='SK-CANARY-RAW-ARG-VALUE';
  c.consume(JSON.stringify({type:'item.completed',item:{id:'sdk-plain-response',type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:'completed',result:{isError:true,content:[{type:'text',text:'Не получилось: '+secret}],structuredContent:{error:{code:'FORBIDDEN'}},_meta:{'w3bench/diagnostics':{traceId,capture:'recorded',errorCode:'INPUT_VALIDATION_ERROR',schemaHash:'a'.repeat(64),fieldPaths:['agentId',secret]}}}}}));
  assert.equal(rows.length,1);assert.equal(rows.find(e=>e.callIdHash).outcome,'error');assert.equal(rows.find(e=>e.callIdHash).errorCode,'INPUT_VALIDATION_ERROR');assert.equal(rows.find(e=>e.callIdHash).stage,'client_validation');assert.equal(rows.find(e=>e.callIdHash).traceId,traceId);assert.deepEqual(rows.find(e=>e.callIdHash).fieldPaths,['agentId']);assert.equal(rows.find(e=>e.callIdHash).schemaHash,'a'.repeat(64));assert(!JSON.stringify(rows).includes(secret));assert.deepEqual(gaps,[]);
  const other=[];new NativeDiagnosticCollector({onEnvelope:e=>other.push(e)}).consume(JSON.stringify({type:'item.completed',item:{id:'unregistered-meta',type:'mcp_tool_call',server:'w3bench_user',tool:'identity.preflight',status:'completed',result:{isError:true,content:[{type:'text',text:secret}],_meta:{'w3bench/diagnostics':{traceId,capture:'recorded',errorCode:secret}}}}}));assert.equal(other[0].errorCode,'UNKNOWN_ERROR');assert(!JSON.stringify(other).includes(secret));
});

 test('finite platform error-call literals, response fallbacks and static template callsites stay registered in all three boundaries',async()=>{
  const {PARTICIPANT_ERROR_SOURCES,declaredParticipantErrorCodes}=await import('./mcp-diagnostics-code-registry.mjs');
  const ui=await readFile(new URL('../packages/owner-web/lib/diagnostics.ts',import.meta.url),'utf8'),uiMatch=ui.match(/errorCode:(\[[^\n]+\]),/);assert(uiMatch);assert.deepEqual([...uiMatch[1].matchAll(/'([^']+)'/g)].map(m=>m[1]),DIAGNOSTIC_ERROR_CODES);
  for(const file of PARTICIPANT_ERROR_SOURCES){const source=await readFile(new URL('../packages/owner-identity/src/'+file,import.meta.url),'utf8');for(const code of declaredParticipantErrorCodes(source,file))assert(DIAGNOSTIC_ERROR_CODES.includes(code),file+' public error literal missing from registry: '+code);}
  const hypothetical=declaredParticipantErrorCodes("throw new HttpError(503, 'FUTURE_PUBLIC_LITERAL', 'safe'); throw new HttpError(400, request.body.code, 'untrusted');",'agents.ts');assert.deepEqual(hypothetical,['FUTURE_PUBLIC_LITERAL']);assert(!DIAGNOSTIC_ERROR_CODES.includes('FUTURE_PUBLIC_LITERAL'));assert.throws(()=>validateClientDiagnosticEnvelope(envelope({errorCode:'FUTURE_PUBLIC_LITERAL'})),/INVALID_ENVELOPE/);
  assert.equal(DIAGNOSTIC_ERROR_CODES.indexOf('CORRELATION_UNAVAILABLE'),28);assert.equal(DIAGNOSTIC_ERROR_CODES.indexOf('TASK_CUTOFF_CONFLICT'),44);assert.equal(new Set(DIAGNOSTIC_ERROR_CODES).size,DIAGNOSTIC_ERROR_CODES.length);
});

test('parser collection gap keeps one registered reason envelope in actual durable upload batch without raw parser text',async t=>{
  const {spool}=await fixture(t),local=spool.createCase(),segmentId=spool.createSegment(local.local_id),c=new NativeDiagnosticCollector({onEnvelope:e=>spool.append(segmentId,e),onGap:code=>spool.markGap(local.local_id,code)});c.feed(Buffer.from('{CANARY-RAW-PARSER-INPUT\n'));c.gap('DIAGNOSTICS_PARSER_FAILURE');assert.equal(c.close().complete,false);const batch=spool.stageBatch(segmentId,{completion:'partial'});assert.equal(batch.events.length,1);assert.equal(batch.events[0].stage,'client_runtime');assert.equal(batch.events[0].tool,'unknown');assert.equal(batch.events[0].errorCode,'DIAGNOSTICS_PARSER_FAILURE');assert.equal(batch.events[0].callIdHash,undefined);assert(!JSON.stringify(batch).includes('CANARY'));assert.equal(spool.caseState(local.local_id).gap,'DIAGNOSTICS_PARSER_FAILURE');
});
test('gap reason delivery is nonrecursive when storage throws or quota returns false, preserving completeness markers',()=>{
  for(const returnsFalse of [false,true]){let calls=0;const gaps=[],c=new NativeDiagnosticCollector({onEnvelope:()=>{calls++;if(returnsFalse)return false;throw new Error('secret-storage-error');},onGap:code=>gaps.push(code)});c.gap('DIAGNOSTICS_STORAGE_FAILURE');c.gap('DIAGNOSTICS_STORAGE_FAILURE');assert.equal(calls,1);assert.deepEqual(gaps,['DIAGNOSTICS_STORAGE_FAILURE']);assert.equal(c.close().complete,false);}
});

test('matched genuine current_task running observation survives interruption in paired runtime error fields without persisting run identity',async t=>{
  const {spool}=await fixture(t),intentId=randomUUID(),runId=randomUUID(),local=spool.createCase({intentId}),segment=spool.createSegment(local.local_id);let clock=Date.parse('2026-11-02T15:00:00.000Z');
  const c=new NativeDiagnosticCollector({expectedIntentId:intentId,now:()=>new Date(clock),onEnvelope:e=>spool.append(segment,e),onGap:code=>spool.markGap(local.local_id,code)});assert.equal(c.bindRegisteredRun({runId,intentId}),true);
  c.consume(JSON.stringify({type:'item.completed',item:{id:'real-current',type:'mcp_tool_call',server:'w3bench_user',tool:'runs.current_task',status:'completed',result:{structuredContent:{task:null,run:{runId,status:'running',terminal:false}},_meta:{'w3bench/diagnostics':{traceId:randomUUID(),capture:'recorded'}}}}}));clock+=1000;c.close({interrupted:true});const batch=spool.stageBatch(segment,{completion:'partial'}),runtime=batch.events.find(e=>e.errorCode==='CLIENT_RUNTIME_ERROR');assert.equal(runtime.clientRunStatus,'running');assert.equal(runtime.clientRunObservedAt,'2026-11-02T15:00:00.000Z');assert.equal(runtime.stage,'client_runtime');assert.equal(runtime.outcome,'error');assert(!JSON.stringify(batch).includes(runId));assert.equal(batch.events.find(e=>e.callIdHash).clientRunStatus,undefined);assert.deepEqual(c.runObservation(),{clientRunStatus:'running',clientRunObservedAt:'2026-11-02T15:00:00.000Z'});
});
test('only matching reviewed acceptance may establish run; unrelated or malformed run state cannot forge crash status',()=>{
  const intentId=randomUUID(),runId=randomUUID(),rows=[],c=new NativeDiagnosticCollector({expectedIntentId:intentId,onEnvelope:e=>rows.push(e)});
  const response=(tool,run,id)=>c.consume(JSON.stringify({type:'item.completed',item:{id,type:'mcp_tool_call',server:'w3bench_user',tool,status:'completed',arguments:{runId},result:{structuredContent:{run},_meta:{'w3bench/diagnostics':{traceId:randomUUID(),capture:'recorded'}}}}}));
  response('runs.current_task',{runId,status:'completed'},'unbound-current');assert.deepEqual(c.runObservation(),{});
  response('runs.accept_launch_intent',{id:runId,intentId:randomUUID(),status:'completed'},'foreign-accept');assert.deepEqual(c.runObservation(),{});
  response('runs.accept_launch_intent',{id:runId,intentId,status:'queued'},'matched-accept');const known=c.runObservation();assert.equal(known.clientRunStatus,'queued');
  response('runs.current_task',{runId:randomUUID(),status:'completed'},'other-run');assert.deepEqual(c.runObservation(),known);response('runs.current_task',{runId,status:'invented-success'},'invalid-state');assert.deepEqual(c.runObservation(),known);c.close({interrupted:true});const runtime=rows.find(e=>e.errorCode==='CLIENT_RUNTIME_ERROR');assert.equal(runtime.clientRunStatus,'queued');assert(!JSON.stringify(rows).includes(runId));
});
test('run status observation fields are paired, finite and restricted to client runtime errors',()=>{
  const valid=envelope({stage:'client_runtime',clientRunStatus:'running',clientRunObservedAt:'2026-11-02T15:00:00.000Z'});validateClientDiagnosticEnvelope(valid);
  for(const e of [{...valid,clientRunStatus:undefined},{...valid,clientRunObservedAt:undefined},{...valid,clientRunStatus:'succeeded'},{...valid,clientRunObservedAt:'2026-11-02T15:00:00Z'},{...valid,stage:'handler'},{...valid,outcome:'unknown'},{...valid,clientRunId:randomUUID()}])assert.throws(()=>validateClientDiagnosticEnvelope(e),/INVALID_ENVELOPE/);
});
