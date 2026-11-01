import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { sql, type SQL } from 'drizzle-orm';
import type { OwnerDatabase } from './db.js';
import { HttpError } from './http-error.js';
import { intentView, runView, type DbIntentRow, type DbRunRow } from './run-service.js';
import type { OwnerBillingView, BillingHistoryItem } from './ledger.js';
import { sha256CanonicalTaskJson } from './task-release.js';
import type { EvaluateTaskInput, TaskEvaluationResult } from './task-evaluator.js';

type Resource = 'runs'|'intents'|'grants'|'history';
type PageQuery = { limit?: unknown; cursor?: unknown; agentId?: unknown };
type Cursor = {v:1;owner:string;resource:Resource;filter:string;t:string;id:string};
type Stamp = {id:string;cursor_time:string};
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const invalid=():never=>{throw new HttpError(400,'INVALID_HISTORY_CURSOR','The history cursor or page query is invalid')};
const iso=(v:unknown)=>v===null||v===undefined?null:new Date(v as string).toISOString();
const money=(v:unknown)=>{const n=BigInt(String(v));if(n<0n)throw new Error('Negative ledger source');return `${n/1000000n}.${String(n%1000000n).padStart(6,'0')}`};
const json=<T>(v:unknown):T=>(typeof v==='string'?JSON.parse(v):v) as T;

export function parseCabinetPageQuery(query:Record<string,unknown>, allowAgent=false):PageQuery {
  if(Object.keys(query).some(k=>!['limit','cursor',...(allowAgent?['agentId']:[])].includes(k)))invalid();
  if(query.agentId!==undefined&&(typeof query.agentId!=='string'||!UUID.test(query.agentId)))invalid();
  return query;
}
function paging(owner:string,resource:Resource,query:PageQuery,secret:string|undefined){
  if(!UUID.test(owner))invalid();
  if(!secret||secret.length<32)throw new HttpError(503,'HISTORY_CURSOR_UNAVAILABLE','History pagination is unavailable');
  const limit=query.limit===undefined?5:typeof query.limit==='string'&&/^[1-9][0-9]?$/.test(query.limit)?Number(query.limit):NaN;
  if(!Number.isInteger(limit)||limit<1||limit>50)invalid();
  const key=createHash('sha256').update('participant-cabinet-cursor/v1\0').update(secret).digest();
  const filter=typeof query.agentId==='string'?query.agentId:'';
  let cursor:Cursor|null=null;
  if(query.cursor!==undefined){
    const token=typeof query.cursor==='string'?query.cursor:invalid();
    if(token.length>2048||!/^[A-Za-z0-9_-]+$/.test(token))invalid();
    try{
      const bytes=Buffer.from(token,'base64url');
      if(bytes.length<29||bytes.toString('base64url')!==token)invalid();
      const decipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));decipher.setAuthTag(bytes.subarray(12,28));
      cursor=JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString('utf8')) as Cursor;
      if(cursor.v!==1||cursor.owner!==owner||cursor.resource!==resource||cursor.filter!==filter||!UUID.test(cursor.id)||
        !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(cursor.t)||!Number.isFinite(Date.parse(cursor.t)))invalid();
    }catch{invalid()}
  }
  const next=(last:Stamp)=>{
    const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,nonce);
    const payload=Buffer.from(JSON.stringify({v:1,owner,resource,filter,t:last.cursor_time,id:last.id} satisfies Cursor));
    const encrypted=Buffer.concat([cipher.update(payload),cipher.final()]);
    return Buffer.concat([nonce,cipher.getAuthTag(),encrypted]).toString('base64url');
  };
  return {limit,cursor,next};
}
const timestamp=(column:SQL)=>sql`to_char(${column} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_time`;

export async function listParticipantRuns(db:OwnerDatabase,owner:string,query:PageQuery,secret?:string){
  const p=paging(owner,'runs',query,secret);
  const rows=await db.execute(sql`SELECT r.*,${timestamp(sql`r.queued_at`)} FROM oid_benchmark_run r WHERE r.owner_id=${owner}
    ${p.cursor?sql`AND (r.queued_at,r.id)<(${p.cursor.t}::timestamptz,${p.cursor.id}::uuid)`:sql``}
    ORDER BY r.queued_at DESC,r.id DESC LIMIT ${p.limit+1}`) as unknown as Array<DbRunRow&Stamp>;
  return {runs:rows.slice(0,p.limit).map(r=>runView(r,r.cancellation_evidence_hash)),nextCursor:rows.length>p.limit?p.next(rows[p.limit-1]!):null};
}
export async function listParticipantIntents(db:OwnerDatabase,owner:string,query:PageQuery,secret?:string){
  const p=paging(owner,'intents',query,secret);
  const rows=await db.execute(sql`SELECT i.*,r.status AS run_status,r.queue_deadline,r.started_at AS run_started_at,
    r.cancellation_reason AS run_cancellation_reason,(i.status='pending' AND i.expires_at<=clock_timestamp()) AS expired_by_clock,
    ${timestamp(sql`i.created_at`)} FROM oid_run_launch_intent i LEFT JOIN oid_benchmark_run r ON r.id=i.run_id
    WHERE i.owner_id=${owner} ${query.agentId?sql`AND i.agent_id=${query.agentId as string}`:sql``}
    ${p.cursor?sql`AND (i.created_at,i.id)<(${p.cursor.t}::timestamptz,${p.cursor.id}::uuid)`:sql``}
    ORDER BY i.created_at DESC,i.id DESC LIMIT ${p.limit+1}`) as unknown as Array<DbIntentRow&Stamp>;
  return {intents:rows.slice(0,p.limit).map(intentView),nextCursor:rows.length>p.limit?p.next(rows[p.limit-1]!):null};
}
export async function listParticipantGrants(db:OwnerDatabase,owner:string,query:PageQuery,secret?:string){
  const p=paging(owner,'grants',query,secret);
  const rows=await db.execute(sql`SELECT g.*,${timestamp(sql`g.created_at`)},clock_timestamp() AS observed_at,
    COALESCE(b.available,0)::text AS available,COALESCE(b.reserved,0)::text AS reserved,COALESCE(b.expired,0)::text AS expired
    FROM oid_bonus_grant g LEFT JOIN LATERAL(SELECT SUM(available_delta_units) AS available,SUM(reserved_delta_units) AS reserved,
    SUM(expired_delta_units) AS expired FROM oid_ledger_entry e WHERE e.owner_id=g.owner_id AND e.bonus_grant_id=g.id)b ON true
    WHERE g.owner_id=${owner} ${p.cursor?sql`AND (g.created_at,g.id)<(${p.cursor.t}::timestamptz,${p.cursor.id}::uuid)`:sql``}
    ORDER BY g.created_at DESC,g.id DESC LIMIT ${p.limit+1}`) as unknown as Array<Stamp&Record<string,unknown>>;
  const grants:OwnerBillingView['grants']=rows.slice(0,p.limit).map(r=>{
    let a=BigInt(String(r.available)),e=BigInt(String(r.expired));const reserved=BigInt(String(r.reserved)),issued=BigInt(String(r.amount_units));
    if(r.expires_at&&new Date(r.expires_at as string)<=new Date(r.observed_at as string)){e+=a;a=0n}
    if(a<0n||reserved<0n||e<0n||a+reserved+e>issued)throw new Error('Ledger invariant violation');
    return {id:r.id,amount:money(issued),available:money(a),reserved:money(reserved),expired:money(e),createdAt:iso(r.created_at)!,
      expiresAt:iso(r.expires_at),reason:String(r.reason),status:e>0n&&a===0n?'expired':reserved>0n&&a>0n?'partially_reserved':reserved>0n?'reserved':a>0n?'available':'spent'};
  });
  return {grants,nextCursor:rows.length>p.limit?p.next(rows[p.limit-1]!):null};
}
export async function listParticipantBillingHistory(db:OwnerDatabase,owner:string,query:PageQuery,secret?:string){
  const p=paging(owner,'history',query,secret);
  const rows=await db.execute(sql`SELECT e.*,g.expires_at,g.reason AS grant_reason,${timestamp(sql`e.created_at`)} FROM oid_ledger_entry e
    LEFT JOIN oid_bonus_grant g ON g.id=e.bonus_grant_id AND g.owner_id=e.owner_id WHERE e.owner_id=${owner}
    ${p.cursor?sql`AND (e.created_at,e.id)<(${p.cursor.t}::timestamptz,${p.cursor.id}::uuid)`:sql``}
    ORDER BY e.created_at DESC,e.id DESC LIMIT ${p.limit+1}`) as unknown as Array<Stamp&Record<string,unknown>>;
  const history:BillingHistoryItem[]=rows.slice(0,p.limit).map(r=>({id:r.id,type:r.entry_type==='bonus_grant'?'grant':String(r.entry_type),
    source:r.source_kind as BillingHistoryItem['source'],amount:money(r.amount_units),createdAt:iso(r.created_at)!,
    ...(r.bonus_grant_id?{expiresAt:iso(r.expires_at),reason:String(r.reason??r.grant_reason)}:r.reason?{reason:String(r.reason)}:{}),
    ...(r.entry_type==='bonus_grant'?{status:'issued'}:{})}));
  return {history,nextCursor:rows.length>p.limit?p.next(rows[p.limit-1]!):null};
}

type CheckStatus='passed'|'failed'|'unknown';
type Check={code:string;status:CheckStatus;evidenceRefs:string[]};
const hashRef=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)?[`sha256:${v}`]:[];
/** Narrow completed Training projection: never serializes cases, answers, payloads or provider errors. */
export async function getParticipantTrainingDiagnostics(db:OwnerDatabase,owner:string,runId:string,taskId:string){
  if(!UUID.test(owner)||!UUID.test(runId)||!['S1','M1','H1'].includes(taskId))throw new HttpError(404,'TASK_DIAGNOSTICS_NOT_FOUND','Training diagnostics are unavailable');
  return db.transaction(async tx=>{
    await tx.execute(sql`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY`);
    const rows=await tx.execute(sql`SELECT b.mode,t.*,e.input_json,e.input_hash,e.result_json AS evaluation_result,e.result_hash
      FROM oid_benchmark_run b JOIN oid_run_task t ON t.run_id=b.id LEFT JOIN oid_run_task_evaluation e ON e.run_id=t.run_id AND e.task_index=t.task_index
      WHERE b.id=${runId} AND b.owner_id=${owner} AND t.task_id=${taskId}`) as unknown as Array<Record<string,unknown>>;
    const row=rows[0];
    if(!row||row.mode!=='training'||!['completed','failed','unknown'].includes(String(row.status))||!['closed','unknown'].includes(String(row.closure_status)))
      throw new HttpError(404,'TASK_DIAGNOSTICS_NOT_FOUND','Training diagnostics are unavailable');
    const result=row.evaluation_result?json<TaskEvaluationResult>(row.evaluation_result):null;
    const input=row.input_json?json<EvaluateTaskInput>(row.input_json):null;
    if(result&&(result.taskId!==taskId||sha256CanonicalTaskJson(result)!==row.result_hash)||input&&sha256CanonicalTaskJson(input)!==row.input_hash)
      throw new HttpError(409,'TASK_DIAGNOSTICS_EVIDENCE_MISMATCH','The retained diagnostics could not be verified');
    if(result&&(!['known','unknown'].includes(result.status)||!['passed','partial','failed','unknown'].includes(result.outcome)||
      (result.status==='unknown'&&(result.credit!==null||result.outcome!=='unknown'))||
      (result.status==='known'&&(!result.credit||!/^\d+$/.test(result.credit.numerator)||! /^[1-9]\d*$/.test(result.credit.denominator)||
        BigInt(result.credit.numerator)>BigInt(result.credit.denominator)))))
      throw new HttpError(409,'TASK_DIAGNOSTICS_EVIDENCE_MISMATCH','The retained diagnostics could not be verified');
    if(input&&(input.taskCase.taskId!==taskId||input.run.runId!==runId||input.run.ownerId!==owner||
      !Array.isArray(input.observations.payments)||!Array.isArray(input.observations.deliveries)))
      throw new HttpError(409,'TASK_DIAGNOSTICS_EVIDENCE_MISMATCH','The retained diagnostics could not be verified');
    if(input&&input.observations.payments.length>4096)throw new HttpError(503,'TASK_DIAGNOSTICS_CAPACITY','The task detail exceeds the safe response capacity');
    const evidenceRefs=[...hashRef(row.result_hash),...hashRef(row.input_hash)];
    const goalChecks:Check[]=[{code:'task_goal',status:!result||result.status==='unknown'?'unknown':result.outcome==='passed'?'passed':'failed',evidenceRefs}];
    if(input)for(const [index,payment] of input.observations.payments.entries()){
      const delivered=input.observations.deliveries.some(d=>d.paymentAttemptId===payment.paymentAttemptId);
      goalChecks.push({code:`paid_resource_delivery_recorded_${index+1}`,status:delivered?'passed':payment.deliveryRequestAbsence?'failed':'unknown',evidenceRefs});
    }
    const actionRows=await tx.execute(sql`SELECT a.id,a.action_sequence::text,a.action_kind,a.accepted_at,r.receipt_status,r.evidence_hash
      FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
      WHERE a.run_id=${runId} AND a.owner_id=${owner} AND a.task_index=${row.task_index as number} ORDER BY a.action_sequence LIMIT 4097`) as unknown as Array<Record<string,unknown>>;
    if(actionRows.length>4096)throw new HttpError(503,'TASK_DIAGNOSTICS_CAPACITY','The task detail exceeds the safe response capacity');
    return {runId,taskId,taskIndex:Number(row.task_index),status:result?.status??'unknown',outcome:result?.outcome??'unknown',
      credit:result?.credit?{numerator:result.credit.numerator,denominator:result.credit.denominator}:null,
      goalChecks,constraintChecks:[{code:'mandatory_constraints',status:result?.mandatoryViolation?'failed':result?.status==='known'?'passed':'unknown',evidenceRefs}] as Check[],
      actions:actionRows.map(a=>({actionId:String(a.id),sequence:String(a.action_sequence),kind:['purchase','pay','retrieve','approve','transfer','wrap','unwrap','swap','inspect_catalog','inspect_offer'].includes(String(a.action_kind))?String(a.action_kind):'unknown',
        status:['observed','pending','unknown','rejected_before_execution'].includes(String(a.receipt_status))?String(a.receipt_status):'unknown',createdAt:iso(a.accepted_at)!,evidenceRefs:hashRef(a.evidence_hash)})),
      timing:{issuedAt:iso(row.started_at),deadlineAt:iso(row.deadline_at),closedAt:iso(row.closed_at)},evidenceRefs};
  });
}
