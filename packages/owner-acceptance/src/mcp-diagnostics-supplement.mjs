/** Actual SC005 browser/parser/replica boundaries. Synthetic authorization is
 * explicitly separate from native OAuth qualification and benchmark execution. */
import assert from 'node:assert/strict';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import http from 'node:http';
import pg from 'pg';
import {NativeDiagnosticCollector} from '../../../tools/mcp-diagnostics-client.mjs';
import {observeMcdRestoreDiagnostics} from './mcp-diagnostics-cold-restore.mjs';

const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).filter(([,x])=>x!==undefined).sort(([a],[b])=>a.localeCompare(b,'en')).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const sha=b=>createHash('sha256').update(b).digest('hex');
const digest=v=>sha(canonical(v));
const delay=ms=>new Promise(done=>setTimeout(done,ms));
let helperSequence=0;
const errorEvent=()=>{const at=new Date().toISOString();return {eventId:randomUUID(),source:'client',stage:'client_runtime',tool:'unknown',outcome:'error',errorCode:'CLIENT_PARSE_ERROR',startedAt:at,completedAt:at,durationMs:0};};
const makeBundle=(binding,events=[errorEvent()],extra={})=>{const batch={segmentId:randomUUID(),batchSequence:0,events,completion:'partial'};return {schemaVersion:'w3bench-diagnostic-bundle/v1',diagnosticSessionId:randomUUID(),binding,...extra,segments:[{segmentId:batch.segmentId,batches:[{...batch,payloadHash:digest(batch)}]}]};};
const bodyOf=bundle=>({diagnosticSessionId:bundle.diagnosticSessionId,...(bundle.caseId?{caseId:bundle.caseId}:{}),...(bundle.binding?{binding:bundle.binding}:{}),batch:bundle.segments[0].batches[0]});

async function bytesRef(input,label,bytes){
  assert(bytes.length<=8*1024*1024+1);const file=resolve(input.writer.directory,label+'-'+randomUUID()+'.json');
  await writeFile(file,bytes,{flag:'wx',mode:0o600});return {path:relative(input.repoRoot,file).split(sep).join('/'),sha256:sha(bytes)};
}

async function chooseFile(page,bytes){
  await page.goto('/diagnostics',{waitUntil:'domcontentloaded'});
  await page.getByLabel('Diagnostic helper export').setInputFiles({name:'synthetic-boundary.json',mimeType:'application/json',buffer:bytes});
}

async function submitUi(page,bytes){
  await chooseFile(page,bytes);const button=page.getByRole('button',{name:'Import diagnostics',exact:true});
  const responsePromise=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/diagnostics/import'&&r.request().method()==='POST');
  await button.click();const response=await responsePromise;return {httpStatus:response.status(),receipt:await response.json()};
}

async function helperRequest(origin,path,bearer,body){
  const startedAt=new Date().toISOString(),bytes=Buffer.from(JSON.stringify(body));
  return new Promise((done,reject)=>{const req=http.request(new URL(path,origin),{method:'POST',localAddress:'127.0.0.'+(90+helperSequence++%64),headers:{'content-type':'application/json',authorization:'Bearer '+bearer,'content-length':bytes.length}},response=>{
    const chunks=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>65536)response.destroy();else chunks.push(chunk);});response.on('error',reject);response.on('end',()=>{let data={};try{data=JSON.parse(Buffer.concat(chunks));}catch{}
      done({httpStatus:response.statusCode,startedAt,completedAt:new Date().toISOString(),transport:{localAddress:req.socket.localAddress,remoteAddress:req.socket.remoteAddress,remotePort:req.socket.remotePort},...(data.caseId?{receipt:data}:{}),...(data.error?.code?{errorCode:data.error.code}:{})});});
    });req.setTimeout(30000,()=>req.destroy(new Error('mcd_supplement_http_timeout')));req.on('error',reject);req.end(bytes);});
}

async function seedOwnedHelper(input){
  const client=new pg.Client({connectionString:input.databaseUrl});await client.connect();
  const helperGrantId=randomUUID(),bearer='mcd_a_'+randomBytes(32).toString('base64url');
  try{const result=await client.query(`INSERT INTO oid_diagnostic_oauth_grant(id,owner_id,agent_id,connection_id,access_generation,expires_at)
    SELECT $1,g.owner_id,g.agent_id,g.id,g.access_generation,LEAST(g.expires_at,clock_timestamp()+interval '1 day')
    FROM oid_agent_access_grant g WHERE g.id=$2 AND g.owner_id=$3 AND g.agent_id=$4 AND g.source='oauth' AND g.revoked_at IS NULL RETURNING id`,[helperGrantId,input.connection.connectionId,input.ownerId,input.connection.agentId]);assert.equal(result.rowCount,1);
    await client.query("INSERT INTO oid_diagnostic_oauth_token(verifier,grant_id,kind,expires_at) VALUES($1,$2,'access',clock_timestamp()+interval '1 day')",[createHash('sha256').update(bearer).digest('base64url'),helperGrantId]);
  }finally{await client.end();}
  await input.writer.write('supplement-helper-fixture',{classification:'synthetic_diagnostics_authorization_only_not_native_consent',helperGrantId,ownerId:input.ownerId,agentId:input.connection.agentId,connectionId:input.connection.connectionId});return bearer;
}

function scoped(input,caseIds){return {business:()=>input.observer.business(),diagnostics:()=>observeMcdRestoreDiagnostics(input.observerDatabaseUrl,caseIds)};}

async function fillOwnerReservationBoundary(input,bearer){
  const {observeMcdAllocations}=await import('./mcp-diagnostics-capacity-restore.mjs');
  const observe=()=>observeMcdAllocations(input.observer,{ownerId:input.ownerId});
  const count=value=>value.groups.reduce((sum,g)=>sum+(g.kind==='case'?0:g.count),0);
  let observation=await observe(),current=count(observation),active,batches=0;
  assert(current<16381);
  const send=async(path,body)=>{for(let n=0;n<3;n++){const result=await helperRequest(input.apiOrigin,path,bearer,body);if(result.httpStatus!==429||result.errorCode==='DIAGNOSTICS_QUOTA_EXCEEDED')return result;input.onProgress?.({phase:'mcd_capacity_supplement_rate_window_wait',ownerRows:current});await delay(61000);}throw Error('mcd_supplement_rate_window_not_recovered');};
  while(current<16381){
    if(!active||active.events===4096&&16381-current>1){const response=await send('/api/diagnostics/cases',{diagnosticSessionId:randomUUID()});assert.equal(response.httpStatus,200);active={caseId:response.receipt.caseId,segmentId:randomUUID(),sequence:0,events:0};}
    const fixed=1+(active.sequence===0?1:0),remaining=16381-current;
    assert(remaining>=fixed,'capacity fill needs an already-open segment for final metadata row');
    const n=Math.min(128,4096-active.events,remaining-fixed),events=Array.from({length:n},()=>({...errorEvent(),stage:'client_validation',tool:'runs.task_action',outcome:'success',errorCode:undefined}));
    const batch={segmentId:active.segmentId,batchSequence:active.sequence,events,completion:'open'};
    const response=await send(`/api/diagnostics/cases/${active.caseId}/batches`,{...batch,payloadHash:digest(batch)});assert.equal(response.httpStatus,200);
    active.sequence++;active.events+=n;observation=await observe();const next=count(observation);assert.equal(next-current,n+fixed);current=next;
    if(++batches%8===0)input.onProgress?.({phase:'mcd_capacity_supplement_owner_rows',actualAllocatedRows:current});
  }
  assert.equal(current,16381);return {observation,observe,count};
}

async function waitForOriginalReport(input,bearer,bundle,reservation){
  const original=bundle.segments[0].batches[0];
  for(let attempt=0;attempt<3;attempt++){
    // AICODE-NOTE: Earlier privacy probes can consume the real report rate
    // window. Replay the identical final batch; never add an event/segment or
    // bypass the limit to make the later independent quota race pass.
    const response=await helperRequest(input.apiOrigin,`/api/diagnostics/cases/${bundle.caseId}/batches`,bearer,original);
    assert.equal(response.httpStatus,200);
    assert.equal(response.receipt?.highestContiguousHash,original.payloadHash);
    if(response.receipt.reportId&&response.receipt.reportCreated){
      const observed=await reservation.observe();assert.equal(reservation.count(observed),16381);reservation.observation=observed;
      await input.writer.write('capacity-original-canonical-report-ready',{caseId:bundle.caseId,segmentId:original.segmentId,payloadHash:original.payloadHash,attempt:attempt+1,response});return;
    }
    input.onProgress?.({phase:'mcd_capacity_waiting_for_canonical_report',attempt:attempt+1});
    if(attempt<2)await delay(61000);
  }
  throw new Error('mcd_original_canonical_report_receipt_unavailable');
}

/** Called before deployment quotas are filled: every import and race below
 * crosses the actual owner UI or actual HTTP server, never fulfilled requests. */
export async function captureMcdSupplementBeforeCapacity(input){
  assert.equal(typeof input.startDiagnosticReplica,'function');const variants=[],sizeProbes=[],binding={agentId:input.connection.agentId,connectionId:input.connection.connectionId};
  let bundle=makeBundle(binding),originalBytes=Buffer.from(JSON.stringify(bundle)),accepted;
  variants.push(await input.captureMcdVariant({name:'bundle_8mib_and_over',request:{boundary:'owner_browser_file_size_guard',maximumBytes:8*1024*1024},observer:input.observer,writer:input.writer,execute:async()=>{
    const exact=Buffer.concat([originalBytes,Buffer.alloc(8*1024*1024-originalBytes.length,0x20)]);accepted=await submitUi(input.ownerPage,exact);assert.equal(accepted.httpStatus,200);
    sizeProbes.push({kind:'bundle',bytes:exact.length,inputRef:await bytesRef(input,'bundle-exact-8mib',exact),httpStatus:accepted.httpStatus,browser:{action:'file_select_and_click',url:input.ownerPage.url(),fileBytes:exact.length}});
    const over=Buffer.concat([exact,Buffer.from(' ')]),requests=[];const onRequest=request=>{if(new URL(request.url()).pathname==='/api/owner/diagnostics/import'&&request.method()==='POST')requests.push({method:request.method(),path:new URL(request.url()).pathname});};input.ownerPage.on('request',onRequest);
    let errorText,disabled;try{await chooseFile(input.ownerPage,over);await input.ownerPage.getByRole('alert').filter({hasText:'Diagnostic export exceeds 8 MiB.'}).waitFor();errorText=await input.ownerPage.getByRole('alert').filter({hasText:'Diagnostic export exceeds 8 MiB.'}).innerText();disabled=await input.ownerPage.getByRole('button',{name:'Import diagnostics',exact:true}).isDisabled();await delay(50);}finally{input.ownerPage.off('request',onRequest);}
    assert.equal(requests.length,0);assert(disabled);sizeProbes.push({kind:'bundle',bytes:over.length,inputRef:await bytesRef(input,'bundle-over-8mib',over),boundary:'owner_browser_file_size_guard',browser:{action:'file_select',url:input.ownerPage.url(),fileBytes:over.length,validationText:errorText,importDisabled:disabled,uploadRequests:requests}});
    return {httpStatus:accepted.httpStatus,receipt:accepted.receipt,overBoundary:'owner_browser_file_size_guard'};
  }}));
  bundle={...bundle,caseId:accepted.receipt.caseId};
  const retainedCaseId=accepted.receipt.caseId;
  for(const name of ['truncated_input','parser_or_storage_failure']){
    const events=[],collector=new NativeDiagnosticCollector({onEnvelope:e=>events.push(e)});
    // These are real public parser invocations on synthetic input. They do not
    // claim that a native model process encountered these faults.
    collector.feed(Buffer.from(name==='truncated_input'?'{"type":"item.completed",':'not-json\n'));const result=collector.close();assert.equal(result.complete,false);assert(events.length);
    const captureBundle=makeBundle(binding,events);variants.push(await input.captureMcdVariant({name,request:{boundary:'actual_native_event_parser_reference',inputKind:name,nativeModel:false},observer:input.observer,writer:input.writer,execute:async()=>{const response=await submitUi(input.ownerPage,Buffer.from(JSON.stringify(captureBundle)));assert.equal(response.httpStatus,200);return {...response,parserResult:result,observedEventIds:events.map(e=>e.eventId)};}}));
  }
  const bearer=await seedOwnedHelper(input),reservation=await fillOwnerReservationBoundary(input,bearer);
  await waitForOriginalReport(input,bearer,bundle,reservation);
  const replica=await input.startDiagnosticReplica();let concurrentReservations;
  try{
    const bundles=Array.from({length:3},()=>makeBundle(binding,[errorEvent()],{caseId:retainedCaseId,diagnosticSessionId:bundle.diagnosticSessionId})),batches=bundles.map(b=>bodyOf(b).batch);
    const before=await observeMcdRestoreDiagnostics(input.observerDatabaseUrl,[retainedCaseId]),ownerReservationBeforeRef=await input.writer.write('capacity-owner-reservation-before',reservation.observation);
    variants.push(await input.captureMcdVariant({name:'concurrent_helper_import_replica_reservations',request:{boundary:'actual_two_api_and_owner_ui_distinct_batches_at_last_owner_rows',caseId:retainedCaseId,batches:batches.map(batch=>({segmentId:batch.segmentId,payloadHash:batch.payloadHash,eventId:batch.events[0].eventId}))},observer:scoped(input,[retainedCaseId]),writer:input.writer,execute:async()=>{
      await chooseFile(input.ownerPage,Buffer.from(JSON.stringify(bundles[2])));const lock=new pg.Client({connectionString:input.databaseUrl});await lock.connect();let outcomes;
      try{await lock.query('BEGIN');await lock.query('SELECT id FROM oid_mcp_diagnostic_case WHERE id=$1 FOR UPDATE',[retainedCaseId]);
        const ownerResponse=input.ownerPage.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/diagnostics/import'&&r.request().method()==='POST');ownerResponse.catch(()=>{});
        const helper=helperRequest(input.apiOrigin,`/api/diagnostics/cases/${retainedCaseId}/batches`,bearer,batches[0]),other=helperRequest(replica.origin,`/api/diagnostics/cases/${retainedCaseId}/batches`,bearer,batches[1]),nativeResponses=Promise.all([helper,other]);nativeResponses.catch(()=>{});
        await input.ownerPage.getByRole('button',{name:'Import diagnostics',exact:true}).click({noWaitAfter:true});
        let waiting=0,lockRows;for(let n=0;n<40&&waiting<3;n++){await delay(50);lockRows=await input.observer.query("SELECT count(DISTINCT l.pid)::int AS n FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.usename='oid_owner' AND NOT l.granted");waiting=lockRows[0].n;}assert(waiting>=3,'actual diagnostic race did not overlap at the held case lock');
        const lockObservationRef=await input.writer.write('capacity-concurrent-lock-observer',{source:'postgresql_observer',observer:input.observer.identity,queryKind:'ungranted_locks_same_disposable_database_owner_role',rows:lockRows});
        await lock.query('COMMIT');const response=await ownerResponse,data=await response.json();outcomes=await nativeResponses;outcomes.push({httpStatus:response.status(),...(data.caseId?{receipt:data}:{}),...(data.error?.code?{errorCode:data.error.code}:{}),browser:{action:'click',url:input.ownerPage.url(),requestPath:new URL(response.url()).pathname}});
        assert.equal(outcomes.filter(r=>r.httpStatus===200).length,1);assert.equal(outcomes.filter(r=>r.httpStatus===429&&r.errorCode==='DIAGNOSTICS_QUOTA_EXCEEDED').length,2);
        const ownerAfter=await reservation.observe();assert.equal(reservation.count(ownerAfter),16384);const ownerReservationAfterRef=await input.writer.write('capacity-owner-reservation-after',ownerAfter);
        const after=await observeMcdRestoreDiagnostics(input.observerDatabaseUrl,[retainedCaseId]),priorEvents=new Set(before.events.map(e=>e.eventId)),priorBatches=new Set(before.batches.map(b=>b.segmentId+':'+b.batchSequence));
        const freshEvents=after.events.filter(e=>!priorEvents.has(e.eventId)),freshBatches=after.batches.filter(b=>!priorBatches.has(b.segmentId+':'+b.batchSequence));assert.equal(freshEvents.length,1);assert.equal(freshBatches.length,1);assert.equal(after.reports.length,before.reports.length);
        const fingerprints=value=>Object.fromEntries(value.events.filter(e=>priorEvents.has(e.eventId)).map(e=>[e.eventId,digest(e)]));
        const attempts=outcomes.map((outcome,index)=>({actor:['helper','replica','owner_import'][index],request:{segmentId:batches[index].segmentId,payloadHash:batches[index].payloadHash,eventId:batches[index].events[0].eventId},...outcome})),winner=attempts.find(a=>a.httpStatus===200);
        concurrentReservations={actors:['helper','owner_import','replica'],source:'postgresql_observer',ownerId:input.ownerId,retainedBeforeHashes:fingerprints(before),retainedAfterHashes:fingerprints(after),caseId:retainedCaseId,segmentId:winner.request.segmentId,payloadHash:winner.request.payloadHash,waitingLockConnections:waiting,lockObservationRef,ownerReservationBeforeRef,ownerReservationAfterRef,newEventIds:freshEvents.map(e=>e.eventId),newBatches:freshBatches,attempts,replica:replica.evidence};return {httpStatus:200,receipt:winner.receipt,attempts};
      }finally{await lock.query('ROLLBACK').catch(()=>{});await lock.end();}
    }}));
  }finally{await replica.stop();}
  return {variants,sizeProbes,concurrentReservations,scopeCaseIds:[input.caseId,retainedCaseId]};
}

/** Assemble only complete actual parts. Missing server/local pieces stay blocked. */
export async function assembleMcdCapacitySupplement(input){
  const {server,local}=input;if(!server?.server?.supplemental)return null;
  const supplement=server.server.supplemental,variants=[...server.variants,...supplement.variants],control=server.privateControls.canonical,transport=server.privateControls.transport;
  const observer=scoped(input,[...supplement.scopeCaseIds,control.caseId]);
  const send=()=>{const batch={segmentId:randomUUID(),batchSequence:0,events:[errorEvent()],completion:'partial'};return transport.request(`/api/diagnostics/cases/${control.caseId}/batches`,{bearer:control.bearer,body:{...batch,payloadHash:digest(batch)}});};
  for(const name of ['canonical_case_events_4096_4097','reachable_exact_over_or_proven_dominated_quotas','rotating_session_ids','anonymous_overflow_fixed_buckets']){
    variants.push(await input.captureMcdVariant({name,request:{boundary:'actual_post_capacity_rejection',caseId:control.caseId},observer,writer:input.writer,execute:async()=>{
      if(name==='rotating_session_ids'){const attempts=[];for(let i=0;i<2;i++)attempts.push(await transport.request('/api/diagnostics/cases',{bearer:control.bearer,body:{diagnosticSessionId:randomUUID()}}));assert(attempts.every(r=>r.httpStatus===429));return {httpStatus:429,attempts};}
      if(name==='anonymous_overflow_fixed_buckets')return input.connection.mcp({method:'tools/list'},{authorized:false});
      const response=await send();assert(response.httpStatus>=400);return response;
    }}));
  }
  const quotas={...server.server,capacityProbes:[...server.capacityProbes,...local.capacityProbes],sizeProbes:[...server.server.sizeProbes,...supplement.sizeProbes],concurrentReservations:supplement.concurrentReservations,hostCapacityEvidenceRef:local.hostCapacityEvidenceRef};delete quotas.supplemental;
  quotas.retainedSurfaces=[...quotas.retainedSurfaces,await input.writer.write('capacity-final-scoped-surfaces',await observer.diagnostics())];
  return {scenario005:{variants,raw:{quotas:await input.writer.write('capacity-assembled-quotas',quotas)}}};
}
