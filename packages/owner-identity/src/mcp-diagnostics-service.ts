import { randomUUID } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { OwnerDatabase } from './db.js';
import type { ReportClosureStateStore } from './report-closure-state.js';
import { HttpError } from './http-error.js';
import { consumeDiagnosticReportCreationRate } from './report-service.js';
import { asIso, reportFirst, reportRows, reportUuid } from './report-db.js';
import { canonicalDiagnosticJson, diagnosticHash, diagnosticEnvelopeSchema, diagnosticCaseInputSchema, diagnosticBatchInputSchema,
  classifyDiagnosticResponsibility, DIAGNOSTIC_LIMITS as LIMIT, DIAGNOSTIC_STAGES, DIAGNOSTIC_ERROR_CODES,
  type DiagnosticEnvelope, type DiagnosticEvidence } from './mcp-diagnostics-contract.js';

export interface DiagnosticPrincipal { ownerId:string;agentId:string;connectionId:string }
export interface DiagnosticDependencies { db:OwnerDatabase;reportClosureState:ReportClosureStateStore }
type Tx=Parameters<Parameters<OwnerDatabase['transaction']>[0]>[0];
interface CaseRow {id:string;owner_id:string;agent_id:string;connection_id:string;diagnostic_session_id:string;intent_id:string|null;report_id:string|null;capture_state:string;event_count:number;error_count:number;byte_count:string;created_at:Date|string;updated_at:Date|string;run_id?:string|null}
export interface DiagnosticCaseView {caseId:string;kind:'client_diagnostics';ownerId:string;agentId:string;connectionId:string;diagnosticSessionId:string;intentId:string|null;runId:string|null;reportId:string|null;createdAt:string;updatedAt:string;captureState:string;eventCount:number;errorCount:number;sourceTrust:'client_observed_unverified'|'server_observed'|'mixed';countsByTool:Record<string,number>;countsByCode:Record<string,number>;countsByStage:Record<string,number>}
export interface DiagnosticReceipt {caseId:string;reportId:string|null;segmentId:string|null;highestContiguousSequence:number;highestContiguousHash:string|null;completion:'open'|'complete'|'partial';reportCreated:boolean;diagnosticsSynced:boolean}
const error=(status:number,code:string,message:string)=>new HttpError(status,code,message);
const uuid=z.string().uuid();
const principalSchema=z.object({ownerId:uuid,agentId:uuid,connectionId:uuid}).strict();
function requirePrincipal(p:DiagnosticPrincipal){if(!principalSchema.safeParse(p).success)throw error(401,'DIAGNOSTICS_UNAUTHORIZED','A verified diagnostic principal is required');}
async function closure(deps:DiagnosticDependencies){return (await deps.reportClosureState.readAuthoritativeClosure()).betaEndedAt;}
async function retention(tx:Tx,external:string|null){
 const state=reportFirst<{expired:boolean}>(await tx.execute(sql`SELECT
  LEAST(beta_ended_at,${external}::timestamptz) IS NOT NULL AND clock_timestamp()>=LEAST(beta_ended_at,${external}::timestamptz)+interval '2592000 seconds' AS expired
  FROM oid_support_report_retention_state WHERE id=1 FOR SHARE`));
 if(!state)throw error(503,'DIAGNOSTICS_UNAVAILABLE','Diagnostic retention authority is unavailable');
 if(state.expired)throw error(410,'REPORT_RETENTION_EXPIRED','Diagnostic intake and access have expired');
}
async function lock(tx:Tx){await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('mcp-diagnostics-global'),0)`);}
async function validateBinding(tx:Tx,p:DiagnosticPrincipal,intentId?:string){
 const grant=reportFirst(await tx.execute(sql`SELECT id FROM oid_agent_access_grant WHERE id=${p.connectionId}::uuid AND owner_id=${p.ownerId}::uuid AND agent_id=${p.agentId}::uuid`));
 if(!grant)throw error(404,'DIAGNOSTICS_LINK_NOT_FOUND','The diagnostic binding is not available');
 if(intentId){
  const intent=reportFirst(await tx.execute(sql`SELECT id FROM oid_run_launch_intent WHERE id=${intentId}::uuid AND owner_id=${p.ownerId}::uuid AND agent_id=${p.agentId}::uuid`));
  const binding=reportRows<{metadata:{connectionId?:string;agentId?:string}}>(await tx.execute(sql`SELECT metadata FROM oid_audit
   WHERE event_type='agent.connection.intent_bound' AND operation_id=${`connection-intent:${intentId}`} AND actor_owner_id=${p.ownerId}::uuid`));
  if(!intent||binding.length!==1||binding[0]!.metadata.connectionId!==p.connectionId||binding[0]!.metadata.agentId!==p.agentId)
   throw error(404,'DIAGNOSTICS_LINK_NOT_FOUND','The diagnostic intent binding is not available');
 }
}
async function findCase(tx:Tx,caseId:string,ownerId:string|null,p?:DiagnosticPrincipal){
 const row=reportFirst<CaseRow>(await tx.execute(sql`SELECT c.*,r.id AS run_id FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id
   WHERE c.id=${caseId}::uuid ${ownerId?sql`AND c.owner_id=${ownerId}::uuid`:sql``} FOR UPDATE OF c`));
 if(!row||(p&&(row.agent_id!==p.agentId||row.connection_id!==p.connectionId)))throw error(404,'DIAGNOSTICS_CASE_NOT_FOUND','The diagnostic case is not available');
 return row;
}
async function reserve(tx:Tx,ownerId:string|null,bytes:number,rows:number,cases=0,anonymous=false){
 const scopes=['deployment',...(ownerId?[`owner:${ownerId}`]:[]),...(anonymous?['anonymous']:[])];
 for(const scope of scopes){
  if(scope.startsWith('owner:'))await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_quota(scope) VALUES (${scope}) ON CONFLICT DO NOTHING`);
  const q=reportFirst<{bytes:string;rows:string;cases:number}>(await tx.execute(sql`SELECT * FROM oid_mcp_diagnostic_quota WHERE scope=${scope} FOR UPDATE`));
  if(!q)throw error(503,'DIAGNOSTICS_UNAVAILABLE','Diagnostic quota authority is unavailable');
  const isOwner=scope.startsWith('owner:'),anon=scope==='anonymous';
  const byteMax=anon?LIMIT.anonymousBytes:isOwner?LIMIT.ownerBytes:LIMIT.deploymentBytes-LIMIT.controlBytes;
  const rowMax=anon?LIMIT.anonymousRows:isOwner?LIMIT.ownerRows:LIMIT.deploymentRows;
  const caseMax=isOwner?LIMIT.ownerCases:LIMIT.deploymentCases;
  if(BigInt(q.bytes)+BigInt(bytes)>BigInt(byteMax)||BigInt(q.rows)+BigInt(rows)>BigInt(rowMax)||q.cases+cases>caseMax)return false;
 }
 for(const scope of scopes)await tx.execute(sql`UPDATE oid_mcp_diagnostic_quota SET bytes=bytes+${bytes},rows=rows+${rows},cases=cases+${cases} WHERE scope=${scope}`);
 return true;
}
async function dropped(tx:Tx,event?:DiagnosticEnvelope){
 const stage=event?DIAGNOSTIC_STAGES.indexOf(event.stage):0,code=event?.errorCode?DIAGNOSTIC_ERROR_CODES.indexOf(event.errorCode):0;
 const bucket=(stage*10+(code%10))%128;
 await tx.execute(sql`UPDATE oid_mcp_diagnostic_aggregate SET dropped_count=CASE WHEN dropped_count<9223372036854775807::bigint THEN dropped_count+1 ELSE dropped_count END,updated_at=clock_timestamp() WHERE bucket=${bucket}`);
}
async function receiptIn(tx:Tx,row:CaseRow,segmentId?:string):Promise<DiagnosticReceipt>{
 const segment=segmentId?reportFirst<{highest_sequence:number;highest_hash:string|null;completion:'open'|'complete'|'partial'}>(await tx.execute(sql`SELECT * FROM oid_mcp_diagnostic_segment WHERE case_id=${row.id}::uuid AND segment_id=${segmentId}::uuid`)):undefined;
 return {caseId:row.id,reportId:row.report_id,segmentId:segmentId??null,highestContiguousSequence:segment?.highest_sequence??-1,highestContiguousHash:segment?.highest_hash??null,
  completion:segment?.completion??'open',reportCreated:!!row.report_id,diagnosticsSynced:!!segment&&segment.completion!=='open'&&(!!row.report_id||row.error_count===0&&segment.completion==='complete')&&row.capture_state!=='partial_quota'};
}
async function ensureReport(tx:Tx,row:CaseRow){
 if(row.report_id)return;
 try{await tx.transaction(async reportTx=>{
 await consumeDiagnosticReportCreationRate(reportTx,{kind:'agent',ownerId:row.owner_id,agentId:row.agent_id});
 // Case locking/mapping is the canonical key. A server-chosen report ID also
 // prevents a generic agent report from preempting a predictable operation ID.
 const id=randomUUID(),operationId=`mcd_${id.replaceAll('-','')}`;
 const title='Client diagnostics',body=`Client-observed diagnostic evidence. Case reference: ${row.id}. See private diagnostics for current counts, completeness and verified attribution.`;
 const safeContext={kind:'client_diagnostics',diagnosticCaseId:row.id,sourceTrust:'client_observed_unverified'};
 await reportTx.execute(sql`INSERT INTO oid_support_report(id,owner_id,agent_id,source,reporter_kind,reporter_id,operation_id,payload_hash,title,body,safe_context,run_id,status,revision)
  VALUES (${id}::uuid,${row.owner_id}::uuid,${row.agent_id}::uuid,'agent','agent',${row.agent_id}::uuid,${operationId},${diagnosticHash({caseId:row.id,title,body})},${title},${body},${JSON.stringify(safeContext)}::jsonb,NULL,'new',1)`);
 await reportTx.execute(sql`INSERT INTO oid_support_report_audit(id,report_id,actor_owner_id,actor_agent_id,operation_id,payload_hash,event_type,revision,metadata)
  VALUES (${randomUUID()}::uuid,${id}::uuid,${row.owner_id}::uuid,${row.agent_id}::uuid,${operationId},${diagnosticHash(safeContext)},'created',1,${JSON.stringify(safeContext)}::jsonb)`);
 await reportTx.execute(sql`UPDATE oid_mcp_diagnostic_case SET report_id=${id}::uuid,updated_at=clock_timestamp() WHERE id=${row.id}::uuid`);row.report_id=id;
 });}catch(cause){
  // AICODE-NOTE: Report throttling must not discard the diagnostic batch. Its
  // unchanged receipt remains unsynced; retrying the same batch retries only report creation.
  if(!(cause instanceof HttpError&&cause.code==='REPORT_RATE_LIMITED'))throw cause;
 }
}

export async function registerDiagnosticCase(deps:DiagnosticDependencies,p:DiagnosticPrincipal,input:unknown){
 requirePrincipal(p);const parsed=diagnosticCaseInputSchema.safeParse(input);if(!parsed.success)throw error(400,'INVALID_DIAGNOSTICS','Diagnostic case fields are invalid');const body=parsed.data,external=await closure(deps);
 return deps.db.transaction(async tx=>{await retention(tx,external);await lock(tx);await validateBinding(tx,p,body.intentId);
  const existing=reportFirst<CaseRow>(await tx.execute(sql`SELECT c.*,r.id AS run_id FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id
   WHERE c.owner_id=${p.ownerId}::uuid AND ${body.intentId?sql`c.intent_id=${body.intentId}::uuid`:sql`c.intent_id IS NULL AND c.diagnostic_session_id=${body.diagnosticSessionId}::uuid`} FOR UPDATE OF c`));
  if(existing){if(existing.agent_id!==p.agentId||existing.connection_id!==p.connectionId)throw error(404,'DIAGNOSTICS_CASE_NOT_FOUND','The diagnostic case is not available');return {...await receiptIn(tx,existing),diagnosticSessionId:existing.diagnostic_session_id,intentId:existing.intent_id,runId:existing.run_id??null,captureState:existing.capture_state};}
  if(!await reserve(tx,p.ownerId,512,0,1)){await dropped(tx);return {quotaDenied:true as const};}
  const id=randomUUID();await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_case(id,owner_id,agent_id,connection_id,diagnostic_session_id,intent_id)
   VALUES (${id}::uuid,${p.ownerId}::uuid,${p.agentId}::uuid,${p.connectionId}::uuid,${body.diagnosticSessionId}::uuid,${body.intentId??null}::uuid)`);
  const row=await findCase(tx,id,p.ownerId,p);return {...await receiptIn(tx,row),diagnosticSessionId:row.diagnostic_session_id,intentId:row.intent_id,runId:row.run_id??null,captureState:row.capture_state};
 }).then(result=>{if('quotaDenied'in result)throw error(429,'DIAGNOSTICS_QUOTA_EXCEEDED','Diagnostic case capacity is exhausted');return result;});
}

export async function appendDiagnosticBatch(deps:DiagnosticDependencies,p:DiagnosticPrincipal,caseId:string,input:unknown):Promise<DiagnosticReceipt>{
 requirePrincipal(p);if(!reportUuid(caseId))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic case identifier is invalid');
 const parsed=diagnosticBatchInputSchema.safeParse(input);if(!parsed.success)throw error(400,'INVALID_DIAGNOSTICS','Diagnostic batch fields are invalid');
 const body=parsed.data,{payloadHash,...payload}=body;
 if(diagnosticHash(payload)!==payloadHash||Buffer.byteLength(canonicalDiagnosticJson(body))>LIMIT.batchBytes||body.events.some(e=>e.source!=='client'))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic batch integrity is invalid');
 if(new Set(body.events.map(e=>e.eventId)).size!==body.events.length)throw error(400,'INVALID_DIAGNOSTICS','Diagnostic event identities must be unique');
 const external=await closure(deps);
 return deps.db.transaction(async tx=>{await retention(tx,external);await lock(tx);const row=await findCase(tx,caseId,p.ownerId,p);
  const prior=reportFirst<{payload_hash:string}>(await tx.execute(sql`SELECT payload_hash FROM oid_mcp_diagnostic_batch WHERE case_id=${caseId}::uuid AND segment_id=${body.segmentId}::uuid AND batch_sequence=${body.batchSequence}`));
  if(prior){if(prior.payload_hash!==payloadHash)throw error(409,'IDEMPOTENCY_CONFLICT','Diagnostic batch identity was already used with different data');if(body.completion!=='open'&&(row.error_count>0||body.completion==='partial'))await ensureReport(tx,row);return receiptIn(tx,row,body.segmentId);}
  const segment=reportFirst<{highest_sequence:number;completion:string}>(await tx.execute(sql`SELECT * FROM oid_mcp_diagnostic_segment WHERE case_id=${caseId}::uuid AND segment_id=${body.segmentId}::uuid FOR UPDATE`));
  if(body.batchSequence!==(segment?.highest_sequence??-1)+1)throw error(409,'DIAGNOSTICS_SEQUENCE_GAP','Diagnostic batch sequence is not contiguous');
  if(segment&&segment.completion!=='open')throw error(409,'DIAGNOSTICS_SEGMENT_CLOSED','A final diagnostic segment cannot be appended');
  const fresh:DiagnosticEnvelope[]=[];
  for(const event of body.events){
   if(event.actionId){const action=reportFirst(await tx.execute(sql`SELECT id FROM oid_run_task_action WHERE id=${event.actionId}::uuid AND run_id=${row.run_id??null}::uuid AND owner_id=${p.ownerId}::uuid AND agent_id=${p.agentId}::uuid`));if(!action)throw error(404,'DIAGNOSTICS_LINK_NOT_FOUND','The diagnostic action link is unavailable');}
   if(event.taskId!==undefined||event.taskIndex!==undefined){const task=reportFirst(await tx.execute(sql`SELECT task_index FROM oid_run_task WHERE run_id=${row.run_id??null}::uuid ${event.taskId!==undefined?sql`AND task_id=${event.taskId}`:sql``} ${event.taskIndex!==undefined?sql`AND task_index=${event.taskIndex}`:sql``}`));if(!task)throw error(404,'DIAGNOSTICS_LINK_NOT_FOUND','The diagnostic task link is unavailable');}
   const previous=reportFirst<{payload_hash:string}>(await tx.execute(sql`SELECT payload_hash FROM oid_mcp_diagnostic_event WHERE case_id=${caseId}::uuid AND event_id=${event.eventId}::uuid`));
   if(previous&&previous.payload_hash!==diagnosticHash(event))throw error(409,'IDEMPOTENCY_CONFLICT','Diagnostic event identity was already used with different data');if(!previous)fresh.push(event);
  }
  const bytes=fresh.reduce((n,e)=>n+Buffer.byteLength(canonicalDiagnosticJson(e)),0)+512+(segment?0:256),rows=fresh.length+1+(segment?0:1);
  if(row.event_count+fresh.length>LIMIT.caseRows||BigInt(row.byte_count)+BigInt(bytes)>BigInt(LIMIT.bundleBytes)||!await reserve(tx,p.ownerId,bytes,rows)){
   await dropped(tx,fresh[0]);await tx.execute(sql`UPDATE oid_mcp_diagnostic_case SET capture_state='partial_quota',updated_at=clock_timestamp() WHERE id=${caseId}::uuid`);
   // Fixed canonical report/control metadata uses the reserved capacity. A
   // permanently full detail store cannot depend on accepting a final batch.
   await ensureReport(tx,{...row,capture_state:'partial_quota'});return {quotaDenied:true as const};
  }
  if(!segment)await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_segment(case_id,segment_id) VALUES (${caseId}::uuid,${body.segmentId}::uuid)`);
  for(const e of fresh)await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_event(case_id,event_id,trace_id,source,stage,tool,outcome,error_code,payload_hash,envelope,byte_count,attribution_reason)
   VALUES (${caseId}::uuid,${e.eventId}::uuid,${e.traceId??null}::uuid,'client',${e.stage},${e.tool},${e.outcome},${e.errorCode??null},${diagnosticHash(e)},${JSON.stringify(e)}::jsonb,${Buffer.byteLength(canonicalDiagnosticJson(e))},'client_observed_unverified')`);
  await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_batch(case_id,segment_id,batch_sequence,payload_hash,event_count,byte_count,completion)
   VALUES (${caseId}::uuid,${body.segmentId}::uuid,${body.batchSequence},${payloadHash},${fresh.length},${Buffer.byteLength(canonicalDiagnosticJson(body))},${body.completion})`);
  await tx.execute(sql`UPDATE oid_mcp_diagnostic_segment SET highest_sequence=${body.batchSequence},highest_hash=${payloadHash},completion=${body.completion},updated_at=clock_timestamp() WHERE case_id=${caseId}::uuid AND segment_id=${body.segmentId}::uuid`);
  const errors=fresh.filter(e=>e.outcome==='error').length;
  await tx.execute(sql`UPDATE oid_mcp_diagnostic_case SET event_count=event_count+${fresh.length},error_count=error_count+${errors},byte_count=byte_count+${bytes},
    capture_state=CASE WHEN capture_state='partial_quota' THEN capture_state WHEN ${body.completion}='partial' THEN 'partial' WHEN capture_state='partial' THEN capture_state WHEN ${body.completion}='complete' THEN 'complete' ELSE 'open' END,updated_at=clock_timestamp() WHERE id=${caseId}::uuid`);
  const updated=await findCase(tx,caseId,p.ownerId,p);if(body.completion!=='open'&&(updated.error_count>0||body.completion==='partial'))await ensureReport(tx,updated);
  return receiptIn(tx,updated,body.segmentId);
 }).then(result=>{if('quotaDenied'in result)throw error(429,'DIAGNOSTICS_QUOTA_EXCEEDED','Diagnostic detailed capacity is exhausted; the original batch remains unacknowledged');return result;});
}

export async function diagnosticReceipt(deps:DiagnosticDependencies,p:DiagnosticPrincipal,caseId:string,segmentId?:string){
 requirePrincipal(p);if(!reportUuid(caseId)||(segmentId&&!reportUuid(segmentId)))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic receipt identity is invalid');const external=await closure(deps);
 return deps.db.transaction(async tx=>{await retention(tx,external);const row=await findCase(tx,caseId,p.ownerId,p);return receiptIn(tx,row,segmentId);});
}

export async function recordServerDiagnostic(deps:DiagnosticDependencies,input:{principal?:DiagnosticPrincipal;caseId?:string;event:DiagnosticEnvelope;evidence?:DiagnosticEvidence}){
 const parsed=diagnosticEnvelopeSchema.safeParse(input.event);if(!parsed.success||parsed.data.source!=='server')throw error(400,'INVALID_DIAGNOSTICS','Server diagnostic fields are invalid');
 const event={...parsed.data};if(input.principal)requirePrincipal(input.principal);const external=await closure(deps);
 return deps.db.transaction(async tx=>{await retention(tx,external);await lock(tx);let row:CaseRow|undefined;
  if(input.caseId&&input.principal){if(!reportUuid(input.caseId))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic case identifier is invalid');row=await findCase(tx,input.caseId,input.principal.ownerId,input.principal);}
  if(!row){delete event.actionId;delete event.taskId;delete event.taskIndex;}
  else {
   if(event.actionId&&!reportFirst(await tx.execute(sql`SELECT id FROM oid_run_task_action WHERE id=${event.actionId}::uuid AND run_id=${row.run_id??null}::uuid AND owner_id=${row.owner_id}::uuid AND agent_id=${row.agent_id}::uuid`)))delete event.actionId;
   if((event.taskId!==undefined||event.taskIndex!==undefined)&&!reportFirst(await tx.execute(sql`SELECT task_index FROM oid_run_task WHERE run_id=${row.run_id??null}::uuid ${event.taskId!==undefined?sql`AND task_id=${event.taskId}`:sql``} ${event.taskIndex!==undefined?sql`AND task_index=${event.taskIndex}`:sql``}`))){delete event.taskId;delete event.taskIndex;}
  }
  const bytes=Buffer.byteLength(canonicalDiagnosticJson(event));
  if(row){const prior=reportFirst<{payload_hash:string}>(await tx.execute(sql`SELECT payload_hash FROM oid_mcp_diagnostic_event WHERE case_id=${row.id}::uuid AND event_id=${event.eventId}::uuid`));if(prior){if(prior.payload_hash!==diagnosticHash(event))throw error(409,'IDEMPOTENCY_CONFLICT','Diagnostic event identity conflict');return {recorded:true,replayed:true};}}
  else {const prior=reportFirst<{payload_hash:string}>(await tx.execute(sql`SELECT payload_hash FROM oid_mcp_diagnostic_event WHERE case_id IS NULL AND event_id=${event.eventId}::uuid`));if(prior){if(prior.payload_hash!==diagnosticHash(event))throw error(409,'IDEMPOTENCY_CONFLICT','Diagnostic event identity conflict');return {recorded:true,replayed:true};}}
  if(row&&row.event_count>=LIMIT.caseRows||row&&BigInt(row.byte_count)+BigInt(bytes)>BigInt(LIMIT.bundleBytes)||!await reserve(tx,row?.owner_id??null,bytes,1,0,!row)){
   await dropped(tx,event);if(row){await tx.execute(sql`UPDATE oid_mcp_diagnostic_case SET capture_state='partial_quota' WHERE id=${row.id}::uuid`);await ensureReport(tx,{...row,capture_state:'partial_quota'});}return {recorded:false,captureState:'partial_quota'};
  }
  const attribution=classifyDiagnosticResponsibility(input.evidence);
  await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_event(case_id,event_id,trace_id,source,stage,tool,outcome,error_code,payload_hash,envelope,byte_count,responsibility,attribution_reason,evidence_ids)
    VALUES (${row?.id??null}::uuid,${event.eventId}::uuid,${event.traceId??null}::uuid,'server',${event.stage},${event.tool},${event.outcome},${event.errorCode??null},${diagnosticHash(event)},${JSON.stringify(event)}::jsonb,${bytes},${attribution.responsibility},${attribution.attributionReason},${JSON.stringify(attribution.evidenceIds)}::jsonb)`);
  if(row){
   await tx.execute(sql`UPDATE oid_mcp_diagnostic_case SET event_count=event_count+1,error_count=error_count+${event.outcome==='error'?1:0},byte_count=byte_count+${bytes},updated_at=clock_timestamp() WHERE id=${row.id}::uuid`);
   // AICODE-NOTE: A late server observation may arrive after the client's
   // final all-clear marker. It must materialize the same canonical report.
   if(row.capture_state!=='open'&&event.outcome==='error')await ensureReport(tx,await findCase(tx,row.id,row.owner_id));
  }
  return {recorded:true,traceId:event.traceId??null};
 });
}

async function caseView(tx:Tx,row:CaseRow):Promise<DiagnosticCaseView>{
 const counts=reportRows<{source:string;tool:string;stage:string;error_code:string|null;outcome:string;count:number}>(await tx.execute(sql`SELECT source,tool,stage,error_code,outcome,count(*)::int AS count FROM oid_mcp_diagnostic_event WHERE case_id=${row.id}::uuid GROUP BY source,tool,stage,error_code,outcome`));
 const byTool:Record<string,number>={},byCode:Record<string,number>={},byStage:Record<string,number>={};let client=false,server=false;
 for(const x of counts){client ||=x.source==='client';server ||=x.source==='server';if(x.outcome==='error'){byTool[x.tool]=(byTool[x.tool]??0)+x.count;byStage[x.stage]=(byStage[x.stage]??0)+x.count;if(x.error_code)byCode[x.error_code]=(byCode[x.error_code]??0)+x.count;}}
 return {caseId:row.id,kind:'client_diagnostics',ownerId:row.owner_id,agentId:row.agent_id,connectionId:row.connection_id,diagnosticSessionId:row.diagnostic_session_id,intentId:row.intent_id,runId:row.run_id??null,reportId:row.report_id,
  createdAt:asIso(row.created_at),updatedAt:asIso(row.updated_at),captureState:row.capture_state,eventCount:row.event_count,errorCount:row.error_count,
  sourceTrust:client&&server?'mixed':server?'server_observed':'client_observed_unverified',countsByTool:byTool,countsByCode:byCode,countsByStage:byStage};
}
export async function listDiagnosticCases(deps:DiagnosticDependencies,ownerId:string|null,filters:{runId?:string;limit?:number}={}){
 if(ownerId&&!reportUuid(ownerId)||filters.runId&&!reportUuid(filters.runId))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic filter is invalid');const external=await closure(deps),limit=Math.min(100,Math.max(1,Number.isInteger(filters.limit)?filters.limit!:25));
 return deps.db.transaction(async tx=>{await retention(tx,external);const rows=reportRows<CaseRow>(await tx.execute(sql`SELECT c.*,r.id AS run_id FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id
  WHERE true ${ownerId?sql`AND c.owner_id=${ownerId}::uuid`:sql``} ${filters.runId?sql`AND r.id=${filters.runId}::uuid`:sql``} ORDER BY c.created_at DESC,c.id DESC LIMIT ${limit}`));
  return {cases:await Promise.all(rows.map(row=>caseView(tx,row)))};
 });
}
export async function getDiagnosticCase(deps:DiagnosticDependencies,ownerId:string|null,caseId:string){
 if(!reportUuid(caseId)||ownerId&&!reportUuid(ownerId))throw error(400,'INVALID_DIAGNOSTICS','Diagnostic case identity is invalid');const external=await closure(deps);
 return deps.db.transaction(async tx=>{await retention(tx,external);const row=await findCase(tx,caseId,ownerId);
  const events=reportRows<{envelope:DiagnosticEnvelope;responsibility:string;attribution_reason:string;evidence_ids:string[]}>(await tx.execute(sql`SELECT envelope,responsibility,attribution_reason,evidence_ids FROM oid_mcp_diagnostic_event WHERE case_id=${caseId}::uuid ORDER BY created_at,event_id LIMIT 4096`));
  const segments=reportRows<{segment_id:string}>(await tx.execute(sql`SELECT segment_id FROM oid_mcp_diagnostic_segment WHERE case_id=${caseId}::uuid ORDER BY segment_id`));
  return {case:await caseView(tx,row),events:events.map(e=>({...e.envelope,responsibility:e.responsibility,attributionReason:e.attribution_reason,evidenceIds:e.evidence_ids})),segments:await Promise.all(segments.map(s=>receiptIn(tx,row,s.segment_id)))};
 });
}

const importSchema=z.object({diagnosticSessionId:uuid,intentId:uuid.optional(),binding:z.object({agentId:uuid,connectionId:uuid}).strict().optional(),caseId:uuid.optional(),batch:diagnosticBatchInputSchema}).strict();
export async function importDiagnosticBatch(deps:DiagnosticDependencies,ownerId:string,input:unknown){
 if(!reportUuid(ownerId))throw error(401,'DIAGNOSTICS_UNAUTHORIZED','A verified owner is required');const parsed=importSchema.safeParse(input);
 if(!parsed.success||Buffer.byteLength(canonicalDiagnosticJson(input))>LIMIT.batchBytes)throw error(400,'INVALID_DIAGNOSTICS','Diagnostic import fields are invalid');const body=parsed.data;
 // AICODE-NOTE: A retained original export can outlive its purged server case.
 // Global expiry precedes case/binding lookups so cleanup cannot turn 410 into
 // an existence-dependent 404. Route authentication still runs before import.
 const external=await closure(deps);
 const {p,canonicalIntentId,canonicalSessionId}=await deps.db.transaction(async tx=>{
 await retention(tx,external);let p:DiagnosticPrincipal;
 let canonicalIntentId=body.intentId,canonicalSessionId=body.diagnosticSessionId;
 if(body.caseId){const row=reportFirst<{agent_id:string;connection_id:string;intent_id:string|null;diagnostic_session_id:string}>(await tx.execute(sql`SELECT agent_id,connection_id,intent_id,diagnostic_session_id FROM oid_mcp_diagnostic_case WHERE id=${body.caseId}::uuid AND owner_id=${ownerId}::uuid`));if(!row)throw error(404,'DIAGNOSTICS_CASE_NOT_FOUND','The diagnostic case is not available');p={ownerId,agentId:row.agent_id,connectionId:row.connection_id};
  if(body.binding&&(body.binding.agentId!==p.agentId||body.binding.connectionId!==p.connectionId))throw error(404,'DIAGNOSTICS_LINK_NOT_FOUND','The diagnostic binding is unavailable');
  if(body.intentId&&body.intentId!==row.intent_id||!row.intent_id&&body.diagnosticSessionId!==row.diagnostic_session_id)throw error(409,'DIAGNOSTICS_CASE_CONFLICT','Diagnostic case references do not agree');
  canonicalIntentId=row.intent_id??undefined;canonicalSessionId=row.diagnostic_session_id;
 }else{if(!body.binding)throw error(400,'INVALID_DIAGNOSTICS','An owned diagnostic binding is required');p={ownerId,...body.binding};}
 return {p,canonicalIntentId,canonicalSessionId};
 });
 const registered=await registerDiagnosticCase(deps,p,{diagnosticSessionId:canonicalSessionId,...(canonicalIntentId?{intentId:canonicalIntentId}:{})});
 if(body.caseId&&registered.caseId!==body.caseId)throw error(409,'DIAGNOSTICS_CASE_CONFLICT','Diagnostic case references do not agree');
 return appendDiagnosticBatch(deps,p,registered.caseId,body.batch);
}

export async function cleanupDiagnosticRetention(deps:DiagnosticDependencies){
 const external=await closure(deps);
 return deps.db.transaction(async tx=>{
  const state=reportFirst<{beta_ended_at:Date|string|null;expires_at:Date|string|null;expired:boolean}>(await tx.execute(sql`
   SELECT LEAST(beta_ended_at,${external}::timestamptz) AS beta_ended_at,
    LEAST(beta_ended_at,${external}::timestamptz)+interval '2592000 seconds' AS expires_at,
    LEAST(beta_ended_at,${external}::timestamptz) IS NOT NULL AND clock_timestamp()>=LEAST(beta_ended_at,${external}::timestamptz)+interval '2592000 seconds' AS expired
   FROM oid_support_report_retention_state WHERE id=1 FOR UPDATE`));
  if(!state)throw error(503,'DIAGNOSTICS_UNAVAILABLE','Diagnostic retention authority is unavailable');
  if(!state.expired)return {expired:false,removedCases:0,removedEvents:0};
  await lock(tx);
  const counts=reportFirst<{cases:number;events:number}>(await tx.execute(sql`SELECT (SELECT count(*)::int FROM oid_mcp_diagnostic_case) AS cases,(SELECT count(*)::int FROM oid_mcp_diagnostic_event) AS events`))!;
  await tx.execute(sql`INSERT INTO oid_mcp_diagnostic_retention_receipt(id,beta_ended_at,expires_at,case_count,event_count)
   VALUES (1,${asIso(state.beta_ended_at!)}::timestamptz,${asIso(state.expires_at!)}::timestamptz,${counts.cases},${counts.events}) ON CONFLICT(id) DO NOTHING`);
  await tx.execute(sql`SELECT set_config('w3bench.diagnostic_retention_cleanup','on',true)`);
  await tx.execute(sql`DELETE FROM oid_mcp_diagnostic_case`);
  await tx.execute(sql`DELETE FROM oid_mcp_diagnostic_event WHERE case_id IS NULL`);
  await tx.execute(sql`DELETE FROM oid_mcp_diagnostic_quota WHERE scope LIKE 'owner:%'`);
  await tx.execute(sql`UPDATE oid_mcp_diagnostic_quota SET bytes=0,rows=0,cases=0`);
  return {expired:true,removedCases:counts.cases,removedEvents:counts.events};
 });
}

/** Server-owned safe stores only. Offline native spools and helper credentials are never claimed as backed up. */
export async function diagnosticBackupInventory(deps:DiagnosticDependencies){
 const stores=['oid_mcp_diagnostic_case','oid_mcp_diagnostic_segment','oid_mcp_diagnostic_batch','oid_mcp_diagnostic_event','oid_mcp_diagnostic_quota','oid_mcp_diagnostic_aggregate','oid_mcp_diagnostic_retention_receipt'] as const;
 const tables:Record<string,{count:number;sha256:string}>={};
 await deps.db.transaction(async tx=>{
  for(const table of stores){
   const value=reportFirst<{count:number;sha256:string}>(await tx.execute(sql`SELECT count(*)::int AS count,
    encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(r)::text,'' ORDER BY to_jsonb(r)::text),''),'UTF8')),'hex') AS sha256 FROM ${sql.raw(table)} r`))!;
   tables[table]=value;
  }
 },{accessMode:'read only',isolationLevel:'repeatable read'});
 return {schemaVersion:'mcp-diagnostic-server-inventory/v1',tables,nativeClientFilesIncluded:false,remoteClientCoverage:'not_backed_up' as const};
}
