/** Real helper HTTP delivery primitives and exact SC002 assembler.
 * Never reads native credentials, impersonates a native client, or edits rate counters. */
import assert from 'node:assert/strict';
import {createServer,connect} from 'node:net';
import {randomUUID} from 'node:crypto';
import {readFile,lstat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {setTimeout as pause} from 'node:timers/promises';
import {DIAGNOSTIC_ERROR_CODES,canonicalDiagnosticJson,diagnosticHash,validateClientDiagnosticEnvelope,createDiagnosticTransport,deliverDiagnosticOutbox} from '../../../tools/mcp-diagnostics-client.mjs';
import {readBoundedDiagnosticText} from '../../../tools/mcp-diagnostics-io.mjs';
import {collectNativeMcdSourceInputs} from './mcd-native-source-inputs.mjs';

export const MCD_NATIVE_VARIANTS=['client_only_validation','refused_endpoint_and_recovery','lost_admission_response','lost_report_response','crash_with_active_known_run','owner_import_races_helper','late_run_binding_and_batches','same_key_different_payload','missing_consent_wrong_scope_audience','helper_denied_task_admin_diagnostic_read','foreign_case_header_or_hidden_trace_carrier','revoked_auth','restart_and_restore','failed_report_retry_no_recursion'];
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i,HASH=/^[a-f0-9]{64}$/;
const need=(v,c)=>{if(!v)throw new Error(c);};
const validOrigin=value=>{const u=new URL(value);need(u.origin===value&&!u.username&&!u.password&&(u.protocol==='https:'||u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname)),'MCD_DELIVERY_ORIGIN_INVALID');return u.origin;};
function pathFor(value){need(typeof value==='string'&&(/^\/api\/diagnostics\/cases(?:\/[a-f0-9-]{36}\/(?:batches|receipt)(?:\?segmentId=[a-f0-9-]{36})?)?$/.test(value)||['/api/agent/mcp','/api/admin/diagnostics/cases','/api/owner/diagnostics/cases'].includes(value)),'MCD_DELIVERY_PATH_INVALID');return value;}
export function safeMcdReceipt(value){
 need(value&&UUID.test(value.caseId)&&(value.reportId==null||UUID.test(value.reportId))&&(value.segmentId==null||UUID.test(value.segmentId))&&Number.isSafeInteger(value.highestContiguousSequence)&&value.highestContiguousSequence>=-1&&value.highestContiguousSequence<=4095&&(value.highestContiguousHash==null||HASH.test(value.highestContiguousHash))&&['open','complete','partial'].includes(value.completion)&&typeof value.reportCreated==='boolean'&&typeof value.diagnosticsSynced==='boolean','MCD_DELIVERY_RECEIPT_INVALID');
 return Object.fromEntries(['caseId','reportId','segmentId','highestContiguousSequence','highestContiguousHash','completion','reportCreated','diagnosticsSynced'].map(k=>[k,value[k]??null]));
}
function retryAfterMs(headers){const value=headers.get('retry-after');if(!value)return undefined;const n=/^\d+$/.test(value)?Number(value)*1000:Date.parse(value)-Date.now();return Number.isFinite(n)&&n>0&&n<=3600000?Math.ceil(n):undefined;}
async function projectResponse(response){
 let body;try{body=JSON.parse(await readBoundedDiagnosticText(response,65536,'MCD_DELIVERY_RESPONSE_INVALID'));}catch{body=null;}
 const code=body?.error?.code??body?.code,receipt=body?.caseId&&Object.hasOwn(body,'highestContiguousSequence')?safeMcdReceipt(body):undefined;
 return {httpStatus:response.status,...(typeof code==='string'?{errorCode:DIAGNOSTIC_ERROR_CODES.includes(code)?code:'UNKNOWN_ERROR'}:{}),...(receipt?{receipt}:{}),...(retryAfterMs(response.headers)?{retryAfterMs:retryAfterMs(response.headers)}:{})};
}
export function createMcdHelperHttp({origin,getAccessToken,fetchImpl=fetch}){
 origin=validOrigin(origin);need(typeof getAccessToken==='function','MCD_DELIVERY_TOKEN_PROVIDER_REQUIRED');
 return {async request(path,{method='GET',body,authorization='helper'}={}){pathFor(path);need(['GET','POST'].includes(method)&&['helper','none'].includes(authorization),'MCD_DELIVERY_REQUEST_INVALID');const token=authorization==='helper'?await getAccessToken():null;if(token)need(typeof token==='string'&&token.length>=20&&token.length<=4096&&!/\s/.test(token),'MCD_DELIVERY_AUTH_UNAVAILABLE');const encoded=body===undefined?undefined:canonicalDiagnosticJson(body);need(!encoded||Buffer.byteLength(encoded)<=65536,'MCD_DELIVERY_REQUEST_TOO_LARGE');const response=await fetchImpl(origin+path,{method,headers:{...(token?{authorization:'Bearer '+token}:{}),...(encoded?{'content-type':'application/json'}:{}),...(path==='/api/agent/mcp'?{accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18'}:{})},...(encoded?{body:encoded}:{}),redirect:'error',signal:AbortSignal.timeout(15000)});return projectResponse(response);}};
}
function checkedBatch(context){
 const c=context.spool.caseState(context.localCaseId);need(c&&UUID.test(c.remote_id)&&UUID.test(context.segmentId),'MCD_DELIVERY_CONTEXT_UNBOUND');
 const batch=context.batch??context.spool.pendingBatches(context.localCaseId).filter(b=>b.segmentId===context.segmentId).at(-1);need(batch&&batch.segmentId===context.segmentId&&batch.events.length<=128&&['open','complete','partial'].includes(batch.completion),'MCD_DELIVERY_BATCH_MISSING');batch.events.forEach(validateClientDiagnosticEnvelope);const {payloadHash,...body}=batch;need(payloadHash===diagnosticHash(body),'MCD_DELIVERY_BATCH_HASH_INVALID');return {c,batch};
}
/** Produces an actual TCP ECONNREFUSED without sending a credential to the probe port. */
export async function observeRealSocketRefusal(){
 const server=createServer();await new Promise((done,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',done);});const port=server.address().port;await new Promise(done=>server.close(done));
 return new Promise((done,reject)=>{const socket=connect({host:'127.0.0.1',port});socket.setTimeout(2000);socket.once('connect',()=>{socket.destroy();reject(new Error('MCD_SOCKET_REFUSAL_NOT_OBSERVED'));});socket.once('timeout',()=>{socket.destroy();reject(new Error('MCD_SOCKET_REFUSAL_NOT_OBSERVED'));});socket.once('error',error=>{socket.destroy();if(error.code==='ECONNREFUSED')done({transport:'tcp',endpoint:'loopback_reserved_then_closed',errorCode:'CONNECTION_REFUSED',credentialBytesSent:0});else reject(new Error('MCD_SOCKET_REFUSAL_NOT_OBSERVED'));});});
}
async function receiptResult(context,transport,attempts,extra={}){
 const c=context.spool.caseState(context.localCaseId);need(c&&UUID.test(c.remote_id),'MCD_DELIVERY_CONTEXT_UNBOUND');const receipt=safeMcdReceipt(await transport.receipt(c.remote_id,context.segmentId));return {httpStatus:attempts.at(-1)?.httpStatus??null,receipt,outboxState:context.spool.caseState(context.localCaseId).state,attempts,proofBoundary:'actual_helper_http_only_not_native_qualification',...extra};
}
export async function captureMcdDeliveryRecovery(context,{fault='none',sleep,fetchImpl=fetch}={}){
 need(['none','refused','lost_response'].includes(fault),'MCD_DELIVERY_FAULT_INVALID');checkedBatch(context);const attempts=[];let injected=false;
 const observedFetch=async(url,init)=>{
  const path=new URL(url).pathname,isBatch=init?.method==='POST'&&path.endsWith('/batches');
  if(isBatch&&fault==='refused'&&!injected){const socketRefusal=await observeRealSocketRefusal();injected=true;attempts.push({errorCode:'CONNECTION_REFUSED',socketRefusal});throw new Error('MCD_CONTROLLED_TCP_REFUSAL');}
  const response=await fetchImpl(url,init);const projected=await projectResponse(response.clone());attempts.push(projected);
  if(isBatch&&fault==='lost_response'&&!injected&&response.ok&&projected.receipt?.reportCreated&&projected.receipt.completion!=='open'){await response.arrayBuffer();injected=true;attempts.at(-1).controlledResponseLoss=true;throw new Error('MCD_CONTROLLED_SUCCESSFUL_RESPONSE_LOSS');}return response;
 };
 const transport=createDiagnosticTransport({origin:context.origin,development:new URL(context.origin).protocol==='http:',getAccessToken:context.getAccessToken,fetchImpl:observedFetch});
 const result=await deliverDiagnosticOutbox({spool:context.spool,transport,binding:context.binding,retryBudget:context.retryBudget??={attempts:0},...(sleep?{sleep}:{})});
 if(fault!=='none'&&!injected)throw Object.assign(new Error('MCD_DELIVERY_FAULT_NOT_OBSERVED'),{safeDiagnostic:{deliveryAttempts:result.reduce((n,r)=>n+r.attempts,0),deliveryStates:result.map(r=>r.state).join(","),attempts,caseState:context.spool.caseState(context.localCaseId)?.state}});const observed=await receiptResult(context,transport,attempts,{delivery:result});need(observed.receipt.diagnosticsSynced,'MCD_DELIVERY_REMAINS_PENDING');return observed;
}
export async function captureMcdPayloadConflict(context){
 const {c,batch}=checkedBatch(context),http=createMcdHelperHttp(context),before=await http.request(`/api/diagnostics/cases/${c.remote_id}/receipt?segmentId=${context.segmentId}`);need(before.receipt?.highestContiguousSequence===batch.batchSequence&&before.receipt?.highestContiguousHash===batch.payloadHash,'MCD_CONFLICT_ORIGINAL_NOT_DURABLE');const changed={...batch,completion:batch.completion==='partial'?'complete':'partial'};const {payloadHash,...body}=changed;changed.payloadHash=diagnosticHash(body);const response=await http.request(`/api/diagnostics/cases/${c.remote_id}/batches`,{method:'POST',body:changed});need(response.httpStatus===409,'MCD_PAYLOAD_CONFLICT_NOT_REJECTED');return response;
}
export async function captureMcdHelperDenials(context,{missing=false}={}){
 const http=createMcdHelperHttp(context),attempts=[];
 if(missing)attempts.push(await http.request('/api/diagnostics/cases',{method:'POST',authorization:'none',body:{diagnosticSessionId:randomUUID()}}));
 else for(const [path,method,body] of [['/api/agent/mcp','POST',{jsonrpc:'2.0',id:1,method:'tools/list'}],['/api/admin/diagnostics/cases','GET'],['/api/owner/diagnostics/cases','GET']])attempts.push(await http.request(path,{method,...(body?{body}:{})}));
 need(attempts.length&&attempts.every(r=>[401,403,404].includes(r.httpStatus)),'MCD_HELPER_CAPABILITY_NOT_DENIED');
 const transport=createDiagnosticTransport({origin:context.origin,development:new URL(context.origin).protocol==='http:',getAccessToken:context.getAccessToken,fetchImpl:async(url,init)=>{
  // Real negative wire boundaries: no bearer on the diagnostic write, or a
  // helper bearer at a private owner-read audience. No fabricated Response.
  const headers=new Headers(init.headers);if(missing)headers.delete('authorization');
  return fetch(missing?url:context.origin+'/api/owner/diagnostics/cases',{...init,...(!missing?{method:'GET',body:undefined}:{}),headers,redirect:'error'});
 }});
 await deliverDiagnosticOutbox({spool:context.spool,transport,binding:context.binding,maxAttempts:1,retryBudget:context.retryBudget??={attempts:0}});
 need(context.spool.caseState(context.localCaseId).state==='pending_auth','MCD_ACTUAL_DENIAL_OUTBOX_NOT_PENDING_AUTH');return {attempts,outboxState:'pending_auth',capabilityCoverage:missing?'actual_no_consent_request_only':'actual_helper_denied_task_admin_private_read',missingCapabilities:missing?['distinct_wrong_scope_or_audience_grant_unavailable_without_caller_boundary']:[]};
}
export async function captureMcdActualAuthFailure(context){
 checkedBatch(context);const attempts=[],transport=createDiagnosticTransport({origin:context.origin,development:new URL(context.origin).protocol==='http:',getAccessToken:context.getAccessToken,fetchImpl:async(url,init)=>{const response=await fetch(url,init);attempts.push(await projectResponse(response.clone()));return response;}});await deliverDiagnosticOutbox({spool:context.spool,transport,binding:context.binding,maxAttempts:1,retryBudget:context.retryBudget??={attempts:0}});need(context.spool.caseState(context.localCaseId).state==='pending_auth'&&attempts.some(r=>[401,403].includes(r.httpStatus)),'MCD_ACTUAL_AUTH_DENIAL_NOT_OBSERVED');return {attempts,outboxState:'pending_auth'};
}
function takeDeliveryAttempt(context){const budget=context.retryBudget??={attempts:0};need(Number.isInteger(budget.attempts)&&budget.attempts>=0&&budget.attempts<5,'MCD_HELPER_LIFETIME_RETRY_BUDGET_EXHAUSTED');budget.attempts++;}
export async function captureMcdReportRateRecovery(context,{minimumWaitMs=61000,wait=pause,onProgress=()=>{}}={}){
 const {c,batch}=checkedBatch(context);need(batch.completion!=='open','MCD_REPORT_FINAL_BATCH_REQUIRED');const http=createMcdHelperHttp(context),path=`/api/diagnostics/cases/${c.remote_id}/batches`;
 takeDeliveryAttempt(context);const first=await http.request(path,{method:'POST',body:batch});need(first.httpStatus===429&&first.errorCode==='REPORT_RATE_LIMITED'||first.httpStatus>=200&&first.httpStatus<300&&first.receipt?.reportCreated===false&&first.receipt?.diagnosticsSynced===false,'MCD_ACTUAL_REPORT_RATE_FAILURE_NOT_OBSERVED');
 let rateFailureRef;if(first.errorCode!=='REPORT_RATE_LIMITED'){
  need(context.observer?.query&&context.writer?.write&&context.repoRoot,'MCD_REPORT_RATE_CAUSE_UNAVAILABLE');
  const sourcePath=resolve(context.repoRoot,'packages/owner-identity/src/report-service.ts'),info=await lstat(sourcePath);need(info.isFile()&&!info.isSymbolicLink()&&info.size<1024*1024,'MCD_REPORT_RATE_POLICY_UNAVAILABLE');const source=await readFile(sourcePath,'utf8'),minute=Number(source.match(/const REPORTS_PER_MINUTE_PER_PRINCIPAL\s*=\s*(\d+)/)?.[1]),hour=Number(source.match(/const REPORTS_PER_HOUR_PER_OWNER\s*=\s*(\d+)/)?.[1]);need(Number.isSafeInteger(minute)&&minute>0&&Number.isSafeInteger(hour)&&hour>0,'MCD_REPORT_RATE_POLICY_UNAVAILABLE');
  const rows=await context.observer.query(`SELECT CASE WHEN r.key LIKE 'principal:%' THEN 'principal_minute' ELSE 'owner_hour' END AS scope,r.window_start AS "windowStart",r.request_count AS "requestCount",floor(extract(epoch from clock_timestamp()))::bigint AS "observedSeconds" FROM oid_mcp_diagnostic_case c JOIN oid_support_report_rate r ON r.key IN ('principal:agent:'||c.agent_id::text||':minute','owner:'||c.owner_id::text||':hour') WHERE c.id=$1::uuid ORDER BY r.key`,[c.remote_id]);
  need(rows.some(r=>{const seconds=Number(r.observedSeconds),width=r.scope==='principal_minute'?60:3600,limit=r.scope==='principal_minute'?minute:hour;return Number(r.windowStart)===Math.floor(seconds/width)*width&&Number(r.requestCount)>=limit;}),'MCD_REPORT_RATE_CAUSE_NOT_OBSERVED');
  rateFailureRef=await context.writer.write('actual-report-rate-observation',{source:'postgresql_observer',observer:context.observer.identity,rows,limits:{minute,hour}});
 }
 need(Number.isSafeInteger(minimumWaitMs)&&minimumWaitMs>=1000&&minimumWaitMs<=3600000,'MCD_REPORT_WINDOW_INVALID');const delay=Math.max(minimumWaitMs,first.retryAfterMs??0),start=performance.now();onProgress({phase:'actual_report_window_wait',milliseconds:delay});await wait(delay);need(performance.now()-start>=delay-5,'MCD_ACTUAL_REPORT_WINDOW_NOT_ELAPSED');
 takeDeliveryAttempt(context);const retried=await http.request(path,{method:'POST',body:batch}),receipt=await http.request(`/api/diagnostics/cases/${c.remote_id}/receipt?segmentId=${context.segmentId}`);need(retried.httpStatus>=200&&retried.httpStatus<300&&receipt.receipt?.reportCreated&&receipt.receipt?.diagnosticsSynced,'MCD_REPORT_RETRY_STILL_PENDING');context.spool.acknowledge(context.localCaseId,receipt.receipt);return {httpStatus:retried.httpStatus,receipt:receipt.receipt,attempts:[first,retried,receipt],actualWaitMs:performance.now()-start,identicalPayloadHash:batch.payloadHash,outboxState:context.spool.caseState(context.localCaseId).state,...(rateFailureRef?{rateFailureRef}:{})};
}
export function safeMcdVariantResponse(value,depth=0){
 need(value&&typeof value==='object'&&!Array.isArray(value)&&depth<=3,'MCD_VARIANT_RESPONSE_INVALID');const out={};
 if(value.httpStatus!==undefined){need(value.httpStatus===null||Number.isInteger(value.httpStatus)&&value.httpStatus>=100&&value.httpStatus<=599,'MCD_VARIANT_RESPONSE_INVALID');out.httpStatus=value.httpStatus;}
 for(const k of ['errorCode'])if(value[k]!==undefined)out[k]=DIAGNOSTIC_ERROR_CODES.includes(value[k])?value[k]:'UNKNOWN_ERROR';
 if(value.rpcErrorCode!==undefined){need(Number.isSafeInteger(value.rpcErrorCode),'MCD_VARIANT_RESPONSE_INVALID');out.rpcErrorCode=value.rpcErrorCode;}
 for(const k of ['traceId','caseId','reportId'])if(value[k]!==undefined){need(UUID.test(value[k]),'MCD_VARIANT_RESPONSE_INVALID');out[k]=value[k];}
 if(value.receipt!==undefined)out.receipt=safeMcdReceipt(value.receipt);
 if(value.outboxState!==undefined){need(['synced','pending_auth','pending','open','partial','conflict','retention_expired'].includes(value.outboxState),'MCD_VARIANT_RESPONSE_INVALID');out.outboxState=value.outboxState;}
 if(value.captureState!==undefined){need(['partial','unavailable','open','complete','partial_quota'].includes(value.captureState),'MCD_VARIANT_RESPONSE_INVALID');out.captureState=value.captureState;}
 for(const k of ['nativeRef','clientOutboxRef','transportRef','rateFailureRef','evidenceRef'])if(value[k]!==undefined){need(safeReference(value[k]),'MCD_VARIANT_RESPONSE_INVALID');out[k]={path:value[k].path,sha256:value[k].sha256};}
 if(value.attempts!==undefined){need(Array.isArray(value.attempts)&&value.attempts.length<=128,'MCD_VARIANT_RESPONSE_INVALID');out.attempts=value.attempts.map(r=>safeMcdVariantResponse(r,depth+1));}
 if(value.controlledResponseLoss===true)out.controlledResponseLoss=true;
 for(const k of ['retryAfterMs','actualWaitMs'])if(value[k]!==undefined){need(Number.isFinite(value[k])&&value[k]>=0&&value[k]<=3601000,'MCD_VARIANT_RESPONSE_INVALID');out[k]=value[k];}
 if(value.identicalPayloadHash!==undefined){need(HASH.test(value.identicalPayloadHash),'MCD_VARIANT_RESPONSE_INVALID');out.identicalPayloadHash=value.identicalPayloadHash;}
 if(value.socketRefusal!==undefined){const v=value.socketRefusal;need(v?.transport==='tcp'&&v.endpoint==='loopback_reserved_then_closed'&&v.errorCode==='CONNECTION_REFUSED'&&v.credentialBytesSent===0,'MCD_VARIANT_RESPONSE_INVALID');out.socketRefusal={transport:'tcp',endpoint:'loopback_reserved_then_closed',errorCode:'CONNECTION_REFUSED',credentialBytesSent:0};}
 if(value.proofBoundary==='actual_helper_http_only_not_native_qualification')out.proofBoundary=value.proofBoundary;
 if(value.delivery!==undefined){need(Array.isArray(value.delivery)&&value.delivery.length<=128,'MCD_VARIANT_RESPONSE_INVALID');out.delivery=value.delivery.map(v=>{need(UUID.test(v.localCaseId)&&['synced','pending_auth','pending','open','partial','conflict','retention_expired'].includes(v.state)&&Number.isInteger(v.attempts)&&v.attempts>=0&&v.attempts<=5,'MCD_VARIANT_RESPONSE_INVALID');return {localCaseId:v.localCaseId,state:v.state,attempts:v.attempts};});}
 if(value.missingCapabilities!==undefined){need(Array.isArray(value.missingCapabilities)&&value.missingCapabilities.every(v=>['distinct_wrong_scope_or_audience_grant_unavailable_without_caller_boundary'].includes(v)),'MCD_VARIANT_RESPONSE_INVALID');out.missingCapabilities=[...value.missingCapabilities];}
 return out;
}
function safeReference(v){return v&&typeof v.path==='string'&&v.path.length>0&&v.path.length<=512&&!/[:\\\x00-\x1f]/.test(v.path)&&v.path.split('/').every(part=>part!==''&&part!=='.'&&part!=='..')&&HASH.test(v.sha256);}
function checkRawRefs(raw){return ['native','oauth','carrier','delivery','clientOutbox'].every(k=>safeReference(raw?.[k]));}
/** Root callbacks prepare native actions before diagnostic before/after snapshots. */
export async function captureMcdNativeDeliveryCases(input){
 const {observer,writer,captureMcdVariant}=input;need(observer&&writer&&typeof captureMcdVariant==='function','MCD_ASSEMBLER_BOUNDARY_REQUIRED');const collect=input.collectSourceHashes??(()=>collectNativeMcdSourceInputs(input.repoRoot)),before=await collect();if(input.sourceInputsBefore)assert.deepEqual(before,input.sourceInputsBefore,'full current native source inventory differs');
 const variants=[],missing=[],sharedRetryBudget=input.retryBudget??{attempts:0};const builtins={refused_endpoint_and_recovery:c=>captureMcdDeliveryRecovery(c,{fault:'refused'}),lost_report_response:c=>captureMcdDeliveryRecovery(c,{fault:'lost_response'}),same_key_different_payload:c=>captureMcdPayloadConflict(c),missing_consent_wrong_scope_audience:c=>captureMcdHelperDenials(c,{missing:true}),helper_denied_task_admin_diagnostic_read:c=>captureMcdHelperDenials(c),revoked_auth:c=>captureMcdActualAuthFailure(c),failed_report_retry_no_recursion:c=>captureMcdReportRateRecovery(c,{onProgress:input.onProgress})};
 for(const name of MCD_NATIVE_VARIANTS){
  let prepared;try{prepared=typeof input.prepareVariant==='function'?await input.prepareVariant(name):input.contexts?.[name];}catch{missing.push({variant:name,reason:'actual_boundary_preparation_unavailable'});continue;}const callback=input.callbacks?.[name];
  if(!prepared&&!callback){missing.push({variant:name,reason:'actual_boundary_context_or_callback_missing'});continue;}
  const context=prepared?{...prepared,observer,writer,repoRoot:input.repoRoot,retryBudget:prepared.retryBudget??sharedRetryBudget,origin:input.origin,getAccessToken:prepared.getAccessToken??input.getAccessToken}:null;
  try{if(name==='same_key_different_payload'&&!callback&&context){context.batch=checkedBatch(context).batch;await captureMcdDeliveryRecovery(context);}
   const execute=callback?()=>callback({context,observer,writer}):builtins[name]&&context?()=>builtins[name](context):null;if(!execute){missing.push({variant:name,reason:'actual_native_ui_backup_boundary_callback_missing'});continue;}
   let actualResponse;const variant=await captureMcdVariant({name,observer,writer,request:{method:'POST',path:name==='helper_denied_task_admin_diagnostic_read'?'/api/agent/mcp':'/api/diagnostics/cases/:caseId/batches',boundary:'actual_diagnostic_delivery_after_native_actions_settled'},execute:async()=>{actualResponse=safeMcdVariantResponse(await execute());return actualResponse;}});variants.push(variant);if(actualResponse.missingCapabilities?.length)missing.push({variant:name,reason:'actual_distinct_scope_audience_boundary_unavailable'});
  }catch(error){missing.push({variant:name,reason:/^MCD_[A-Z_]+$/.test(error?.message)?error.message:'actual_boundary_capture_incomplete'});}
 }
 const after=await collect();assert.deepEqual(after,before,'native delivery source inventory changed during capture');
 const raw=Object.fromEntries(['native','oauth','carrier','delivery','clientOutbox'].filter(k=>safeReference(input.rawReferences?.[k])).map(k=>[k,{path:input.rawReferences[k].path,sha256:input.rawReferences[k].sha256}])),complete=variants.length===MCD_NATIVE_VARIANTS.length&&!missing.length&&checkRawRefs(raw),fragment={schemaVersion:'mcd-physical-capture/v1',scenarioId:'MCD-SC-002',observer:observer.identity,sourceInputs:{before,after},variants,raw};
 const reference=await writer.write(complete?'MCD-SC-002':'MCD-SC-002-incomplete',fragment);return {captures:complete?{'MCD-SC-002':reference}:{},blocked:complete?{}:{'MCD-SC-002':{reason:'actual_native_delivery_variants_or_common_boundaries_missing',missing,...(!checkRawRefs(raw)?{missingRaw:['native','oauth','carrier','delivery','clientOutbox'].filter(k=>!safeReference(raw[k]))}:{})}},partialReference:reference,scenario:fragment};
}
