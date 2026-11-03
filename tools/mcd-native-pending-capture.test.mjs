import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {prepareMcdNativePendingCapture} from './mcd-native-pending-capture.mjs';
import {deliverDiagnosticOutbox,createDiagnosticTransport} from './mcp-diagnostics-client.mjs';

async function fixture(t){
  const repoRoot=await mkdtemp(join(tmpdir(),'mcd-pending-unit-'));t.after(()=>rm(repoRoot,{recursive:true,force:true,maxRetries:5,retryDelay:20}));
  const captureId=randomUUID(),binding={agentId:randomUUID(),connectionId:randomUUID()},caseId=randomUUID(),reportId=randomUUID(),requests=[],retryBudget={attempts:2};let spawns=0;
  const options={repoRoot,captureId,profile:'invalid-schema-preflight',outputDirectory:'.local/capture/'+captureId,binding,getAccessToken:async()=> 'FIXTURE-SECRET-TOKEN-NOT-REAL',retryBudget};
  const dependencies={verifyBundle:async()=>{},collectSources:async()=>({'fixture-source':'a'.repeat(64)}),metadata:async(exe,args)=>args[1]==='list'?[{name:'w3bench_user',transport:{type:'streamable_http',url:'http://127.0.0.1:3000/api/agent/mcp'}}]:{name:'w3bench_user',transport:{type:'streamable_http',url:'http://127.0.0.1:3000/api/agent/mcp'}},fetchImpl:async(url,init)=>{
    requests.push({path:new URL(url).pathname,body:init.body?JSON.parse(init.body):null});
    const request=requests.at(-1);if(request.path.endsWith('/cases'))return Response.json({caseId,diagnosticSessionId:request.body.diagnosticSessionId,intentId:null,runId:null,reportId:null,captureState:'open'});
    if(request.path.endsWith('/batches'))return Response.json({});
    const batch=requests.find(r=>r.path.endsWith('/batches')).body;return Response.json({caseId,reportId,segmentId:batch.segmentId,highestContiguousSequence:batch.batchSequence,highestContiguousHash:batch.payloadHash,completion:batch.completion,reportCreated:true,diagnosticsSynced:true});
  },spawnImpl(exe,args,opts){spawns++;assert(args.includes('--json'));assert(!args.some(x=>x.includes('FIXTURE-SECRET')));const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();child.kill=()=>true;child.stdin.on('finish',()=>{
    const events=[{type:'item.completed',item:{type:'mcp_tool_call',id:'call-fixture-1',server:'w3bench_user',tool:'identity.preflight',status:'completed',result:{structuredContent:{status:'allowed'},_meta:{'w3bench/diagnostics':{capture:'recorded',traceId:randomUUID()}}}}},{type:'item.completed',item:{type:'mcp_tool_call',id:'call-fixture-2',server:'w3bench_user',tool:'identity.preflight',status:'failed',error:{message:'Input validation error: Invalid arguments for tool identity.preflight: agentId: SECRET-CANARY'}}},{type:'turn.completed'}];child.stdout.write(events.map(e=>JSON.stringify(e)).join('\n')+'\n');child.emit('close',0);
  });return child;}};
  return {options,dependencies,requests,caseId,spawns:()=>spawns};
}
test('local injected fixture prepares real SQLite pending evidence with zero implicit batch delivery and one shared budget',async t=>{
  const f=await fixture(t),p=await prepareMcdNativePendingCapture(f.options,f.dependencies);t.after(()=>p.close());
  assert.equal(f.spawns(),1);assert.deepEqual(f.requests.map(r=>r.path),['/api/diagnostics/cases']);assert.equal(p.delivery,'not_attempted');assert.equal(p.context.retryBudget,f.options.retryBudget);assert.equal(p.context.retryBudget.attempts,2);
  const pending=p.observe();assert.equal(pending.acknowledgedBatchCount,0);assert.equal(pending.pendingBatchCount,1);assert.equal(pending.calls.length,2);assert.equal(pending.calls[1].errorCode,'INPUT_VALIDATION_ERROR');
  const bytes=await readFile(resolve(f.options.repoRoot,p.clientOutboxRef.path));assert.equal(createHash('sha256').update(bytes).digest('hex'),p.clientOutboxRef.sha256);assert(!bytes.includes('SECRET-CANARY'));assert(!bytes.includes('FIXTURE-SECRET'));
  const transport=createDiagnosticTransport({origin:p.context.origin,development:true,getAccessToken:p.context.getAccessToken,fetchImpl:f.dependencies.fetchImpl});
  await deliverDiagnosticOutbox({spool:p.context.spool,transport,binding:p.context.binding,retryBudget:p.context.retryBudget});assert.equal(p.context.retryBudget.attempts,3);assert.equal(p.observe().pendingBatchCount,0);assert.deepEqual(await readFile(resolve(f.options.repoRoot,p.clientOutboxRef.path)),bytes);
  p.close();p.close();assert.throws(()=>p.observe(),/MCD_PENDING_CAPTURE_CLOSED/);assert.throws(()=>p.context.spool.caseState(p.context.localCaseId),/MCD_PENDING_CAPTURE_CLOSED/);
  const native=JSON.parse(await readFile(resolve(f.options.repoRoot,p.nativeRef.path)));assert.equal(native.implementation,'local_injected_fixture');assert.equal(native.boundary,'local_primitive_not_native_acceptance');
});
test('registration failure never launches native; finite failure artifact survives closed durable local evidence',async t=>{
  const f=await fixture(t);f.dependencies.fetchImpl=async()=>new Response('',{status:401});let failure;
  await assert.rejects(prepareMcdNativePendingCapture(f.options,f.dependencies),error=>{failure=error;return error.message==='MCD_PENDING_CASE_UNREGISTERED';});assert.equal(f.spawns(),0);
  const artifact=JSON.parse(await readFile(resolve(f.options.repoRoot,failure.failureRef.path)));assert.equal(artifact.nativeStarted,false);assert.equal(artifact.rawMessageOmitted,true);
  const db=new DatabaseSync(resolve(f.options.repoRoot,f.options.outputDirectory,'spool/diagnostics.sqlite'),{readOnly:true});try{assert(db.prepare('SELECT count(*) AS n FROM events').get().n>0);assert.equal(db.prepare('SELECT count(*) AS n FROM batches WHERE acked=1').get().n,0);}finally{db.close();}
});
test('source drift closes capture and retains immutable finite failure receipt without raw exception text',async t=>{
  const f=await fixture(t);let n=0;f.dependencies.collectSources=async()=>({'fixture-source':(++n===1?'a':'b').repeat(64)});let failure;
  await assert.rejects(prepareMcdNativePendingCapture(f.options,f.dependencies),error=>{failure=error;return error.message==='MCD_PENDING_SOURCE_CHANGED';});
  assert.equal(JSON.parse(await readFile(resolve(f.options.repoRoot,failure.failureRef.path))).errorCode,'MCD_PENDING_SOURCE_CHANGED');assert.equal(f.spawns(),1);assert.equal(f.requests.length,1);
});
test('only reviewed free profiles accepted; arbitrary prompt, active profile and capture reuse cannot start another native process',async t=>{
  const f=await fixture(t);for(const patch of [{prompt:'arbitrary'},{profile:'crash-after-active-run'},{origin:'https://example.invalid'}])await assert.rejects(prepareMcdNativePendingCapture({...f.options,...patch},f.dependencies),/MCD_PENDING_OPTIONS_INVALID/);
  const p=await prepareMcdNativePendingCapture(f.options,f.dependencies);p.close();await assert.rejects(prepareMcdNativePendingCapture(f.options,f.dependencies),/MCD_PENDING_CAPTURE_ALREADY_CLAIMED/);assert.equal(f.spawns(),1);
});
