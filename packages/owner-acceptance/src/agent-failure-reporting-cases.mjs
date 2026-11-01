/** Actual support MCP/admin UI/readonly PG proof after a separately retained browser-started terminal failure. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {assertSecretFree} from './evidence.mjs';
import {runGenuineS1OwnerCase} from './genuine-s1-cases.mjs';
import {createArcNativeIntentRunner,ARC_NATIVE_REPORT_TOOLS} from '../../../tools/arc-native-bridge.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const REASONS=new Set(['coordinator_evaluation_unknown','coordinator_preparation_failed','coordinator_interrupted_preparation','coordinator_executor_session_lost','coordinator_platform_failure']);
const sha=value=>createHash('sha256').update(value).digest('hex');
const need=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
export function verifyFailureRunIntent(row,{runId,intentId,agentId}){
 need(UUID.test(runId)&&UUID.test(intentId)&&UUID.test(agentId)&&row?.id===runId&&row.intent_id===intentId&&row.agent_id===agentId,'AFR_IMMUTABLE_RUN_INTENT_BINDING');
}
export function platformFailureReportArguments({terminal,runId,taskId,actionId}){
 need(UUID.test(runId),'AFR_RUN_ID_INVALID');
 const run=terminal?.run,reason=[run?.terminalReason,run?.cancellationReason].find(value=>REASONS.has(value));
 if(run?.runId!==runId||run.terminal!==true||!reason||!['cancelled','failed','unknown','expired','disqualified'].includes(run.status))return null;
 need(typeof run.status==='string'&&/^[a-z_]{1,64}$/.test(run.status),'AFR_STATUS_INVALID');
 if(taskId!==undefined)need(/^[SMHU][1-4]$/.test(taskId),'AFR_TASK_ID_INVALID');
 if(actionId!==undefined)need(UUID.test(actionId),'AFR_ACTION_ID_INVALID');
 return {operationId:'afr_'+runId.replaceAll('-',''),title:'Platform run failure',
  body:`Server-confirmed platform failure; runStatus=${run.status}; reason=${reason}.`,runId,
  ...(taskId?{taskId}:{}),...(actionId?{actionId}:{})};
}
export function buildNativeFailureReportingPrompt({agentId,runId,args}){
 need(UUID.test(agentId)&&args?.runId===runId,'AFR_NATIVE_SCOPE_INVALID');
 return `Continue only private failure reporting for the existing run ${runId} and agent ${agentId}. Use only MCP server w3bench_user. Do not create, accept or relaunch a run, execute tasks, pay, finish tasks or change permissions. No local files, shell, browser, provider data or other identity.
First call runs.current_task with runId ${runId}. Continue only if run.terminal === true and terminalReason or cancellationReason confirms the supplied platform failure. Ordinary failed/partial tasks, deadlines alone and nonterminal task:null are not platform-bug reporting triggers.
Then call support.report exactly with these safe arguments (no other fields or hidden task content):
${JSON.stringify(args)}
Retain operationId and exact arguments; an uncertain response permits at most one unchanged retry. When report.id is returned call support.report_receipt with that reportId and confirm the same id. Do not claim delivery without receipt. Report failure never authorizes another run, payment, finish_task or credential. If any check fails, stop and say support reporting unresolved with safe error code only. Finally state runId, confirmed terminal status, reportId and receipt state; never invent success.`;
}
/** The genuine launch callback supplies ownerPage/publicOrigin/intentId; grant only this fixture origin. */
export async function readAgentFailureProductionHandoff(ctx){
 try{await ctx.ownerPage.context().grantPermissions(['clipboard-read','clipboard-write'],{origin:new URL(ctx.publicOrigin).origin});}
 catch{throw Object.assign(new Error('AFR_CLIPBOARD_PERMISSION_UNAVAILABLE'),{code:'AFR_CLIPBOARD_PERMISSION_UNAVAILABLE'});}
 const visible=await ctx.ownerPage.getByTestId('run-intent-handoff-text-'+ctx.intentId).innerText();
 const copy=ctx.ownerPage.getByTestId('run-intent-handoff-'+ctx.intentId);await copy.click();
 const copyUntil=Date.now()+5000;while(Date.now()<copyUntil&&!(await copy.innerText()).includes('Copied safe handoff'))await new Promise(done=>setTimeout(done,50));
 need((await copy.innerText()).includes('Copied safe handoff'),'AFR_CLIPBOARD_COPY_UNCONFIRMED');
 let clipboard;try{clipboard=await ctx.ownerPage.evaluate(()=>navigator.clipboard.readText());}
 catch{throw Object.assign(new Error('AFR_CLIPBOARD_READ_UNAVAILABLE'),{code:'AFR_CLIPBOARD_READ_UNAVAILABLE'});}
 need(clipboard===visible&&clipboard.includes('Automatic private support reporting:'),'AFR_PRODUCTION_HANDOFF_REQUIRED');
 return {clicked:true,visible,clipboard,url:ctx.ownerPage.url(),intentSnapshot:ctx.launchIntent.database};
}
/** Current receipt has one row per action (receipt_revision, not a history revision column). */
export async function findAgentFailureReceiptTarget(ctx,transactionHash){
 const rows=await ctx.readonlyQuery(`SELECT t.run_id,t.task_index,t.task_id,t.closure_id FROM oid_run_task t JOIN oid_benchmark_run r ON r.id=t.run_id
  JOIN oid_run_task_action a ON a.run_id=t.run_id AND a.task_index=t.task_index
  JOIN oid_run_task_action_receipt receipt ON receipt.action_id=a.id
  WHERE r.intent_id=$1 AND r.owner_id=$2 AND r.agent_id=$3 AND t.task_id='H1' AND t.closure_status='closed'
    AND a.task_id='H1' AND a.owner_id=r.owner_id AND a.agent_id=r.agent_id AND a.action_kind IN ('pay','purchase')
    AND lower(receipt.transaction_hash)=lower($4)`,[ctx.intentId,ctx.ownerId,ctx.agentId,transactionHash]);
 if(rows.length!==1)return null;const row=rows[0];return {runId:row.run_id,taskIndex:row.task_index,taskId:row.task_id,closureId:row.closure_id};
}
async function domainSnapshot(query,runId){
 const rows=await query(`SELECT 'run' domain,md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')) digest,count(*)::int count FROM oid_benchmark_run t WHERE id=$1
 UNION ALL SELECT 'tasks',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_run_task t WHERE run_id=$1
 UNION ALL SELECT 'actions',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_run_task_action t WHERE run_id=$1
 UNION ALL SELECT 'closures',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_run_task_closure t WHERE run_id=$1
 UNION ALL SELECT 'grades',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_run_task_evaluation t WHERE run_id=$1
 UNION ALL SELECT 'events',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_run_event t WHERE run_id=$1
 UNION ALL SELECT 'ledger',md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')),count(*)::int FROM oid_ledger_entry t WHERE owner_id=(SELECT owner_id FROM oid_benchmark_run WHERE id=$1) ORDER BY domain`,[runId]);
 need(rows.length===7,'AFR_DOMAIN_SNAPSHOT_MISSING');return rows;
}

export async function captureAgentFailureReporting(input){
 const {publicOrigin,agentBearer,agentId,runId,taskId,actionId,intentId,adminPage,readonlyQuery,onNativeFailureReady,browserAdmission}=input;
 need(UUID.test(agentId)&&UUID.test(runId)&&browserAdmission?.clicked===true,'AFR_BROWSER_ADMISSION_REQUIRED');
 const identity=(await readonlyQuery("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only"))[0];
 need(identity?.role==='oid_observer'&&identity.read_only==='on'&&/^oid_acceptance_[a-f0-9]{32}$/.test(identity.database_name),'AFR_DISPOSABLE_READONLY_DB_REQUIRED');
 const client=new Client({name:'Web3 Agent Bench report reference observer',version:'1.0.0'},{versionNegotiation:{mode:{pin:'2026-07-28'}}});
 const transport=new StreamableHTTPClientTransport(new URL('/api/agent/mcp',publicOrigin),{requestInit:{headers:{authorization:'Bearer '+agentBearer,origin:new URL(publicOrigin).origin}},onInsufficientScope:'throw'});
 const proof={schemaVersion:'agent-failure-reporting-physical-capture/v1',status:'running',agentId,runId,intentId,browserAdmission,
  database:identity,mcp:[],boundary:'browser_started_run_terminal_failure_native_mcp_admin_ui_readonly_postgres',
  observerClient:{implementation:'reference_mcp_sdk_not_native',packageVersion:'2.4.0',protocolVersion:'2026-07-28'}};
 const call=async(name,args)=>{const startedAt=new Date().toISOString();const result=await client.callTool({name,arguments:args});
  let body=result.structuredContent;if(!body){try{body=JSON.parse(result.content?.find(x=>x.type==='text')?.text??'{}');}catch{body={error:{code:'INVALID_JSON'}};}}
  // Only these already safe report/status arguments and response projections are retained.
  const row={name,args,startedAt,finishedAt:new Date().toISOString(),isError:result.isError===true,body};assertSecretFree(row,'afr-mcp');proof.mcp.push(row);need(!row.isError&&!body.error,'AFR_MCP_'+(body.error?.code??'ERROR'));return body;};
 try{
  await client.connect(transport);proof.terminal=await call('runs.current_task',{runId});
  let args=platformFailureReportArguments({terminal:proof.terminal,runId,taskId,actionId});need(args,'AFR_CONFIRMED_PLATFORM_FAILURE_REQUIRED');proof.reportArguments=args;
  const runRows=await readonlyQuery('SELECT id,intent_id,owner_id,agent_id,status,terminal_reason,cancellation_reason,finished_at::text,overall_deadline::text FROM oid_benchmark_run WHERE id=$1 AND agent_id=$2',[runId,agentId]);
  need(runRows.length===1&&runRows[0].status===proof.terminal.run.status,'AFR_TERMINAL_PG_BINDING');
  verifyFailureRunIntent(runRows[0],{runId,intentId,agentId});proof.run=runRows[0];
  proof.failureTasks=await readonlyQuery(`SELECT t.task_index,t.task_id,t.status,t.closure_id,t.closed_at::text,t.deadline_at::text,
    (t.closed_at+interval '180 seconds')::text evaluation_retry_deadline,t.action_cutoff_sequence::text,t.reconciled_action_sequence::text,
    EXISTS(SELECT 1 FROM oid_run_task_evaluation e WHERE e.run_id=t.run_id AND e.task_index=t.task_index) evaluation_present
    FROM oid_run_task t WHERE run_id=$1 ORDER BY task_index`,[runId]);
  const existing=await readonlyQuery('SELECT id FROM oid_support_report WHERE owner_id=$1 AND operation_id=$2',[proof.run.owner_id,args.operationId]);need(existing.length===(input.nativeCompleted?1:0),'AFR_EXISTING_REPORT_SCOPE');
  proof.domainBefore=input.beforeReportingSnapshot??await domainSnapshot(readonlyQuery,runId);
  if(!input.nativeCompleted)need(typeof onNativeFailureReady==='function','AFR_NATIVE_REPORTER_REQUIRED');
  const prompt=input.handoff?.clipboard??buildNativeFailureReportingPrompt({agentId,runId,args});proof.nativePrompt=prompt;proof.nativePromptSha256=sha(Buffer.from(prompt));
  proof.native=input.nativeCompleted??await onNativeFailureReady({agentBearer,agentId,intentId,handoffPrompt:prompt,publicOrigin,runId});
  if(input.handoff)proof.handoff=input.handoff;
  assertSecretFree(proof.native,'afr-native');
  const reports=await readonlyQuery(`SELECT id,owner_id,agent_id,source,reporter_kind,reporter_id,operation_id,title,body,run_id,task_id,action_id,status,revision,client_version FROM oid_support_report WHERE owner_id=$1 AND operation_id=$2`,[proof.run.owner_id,args.operationId]);
  need(reports.length===1,'AFR_NATIVE_REPORT_NOT_PERSISTED');const report=reports[0];proof.report=report;
  if(input.nativeCompleted){
    // The production handoff permits any already known validated task/action link, or omission.
    if(report.task_id)need((await readonlyQuery('SELECT task_id FROM oid_run_task WHERE run_id=$1 AND task_id=$2',[runId,report.task_id])).length===1,'AFR_NATIVE_TASK_LINK');
    if(report.action_id)need((await readonlyQuery('SELECT id FROM oid_run_task_action WHERE id=$1 AND run_id=$2 AND agent_id=$3 AND ($4::text IS NULL OR task_id=$4)',[report.action_id,runId,agentId,report.task_id])).length===1,'AFR_NATIVE_ACTION_LINK');
    args={...args,...(report.task_id?{taskId:report.task_id}:{}),...(report.action_id?{actionId:report.action_id}:{}),...(report.client_version?{clientVersion:report.client_version}:{})};proof.reportArguments=args;
  }
  need(report.agent_id===agentId&&report.reporter_kind==='agent'&&report.reporter_id===agentId&&report.source==='agent'&&report.run_id===runId&&report.task_id===(args.taskId??null)&&report.action_id===(args.actionId??null)&&report.title===args.title&&report.body===args.body,'AFR_PRIVATE_REPORT_BINDING');
  const retry=await call('support.report',args);need(retry.replayed===true&&retry.report?.id===report.id,'AFR_RETRY_NOT_IDEMPOTENT');
  const receipt=await call('support.report_receipt',{reportId:report.id});need(receipt.report?.id===report.id&&receipt.report.status===report.status,'AFR_RECEIPT_MISMATCH');proof.receipt=receipt;
  proof.reportAudit=await readonlyQuery('SELECT report_id,event_type,revision FROM oid_support_report_audit WHERE report_id=$1 ORDER BY created_at,id',[report.id]);
  need(proof.reportAudit.length===1&&proof.reportAudit[0].event_type==='created','AFR_SINGLE_CREATE_AUDIT_REQUIRED');
  await adminPage.goto(new URL('/admin/reports',publicOrigin).href,{waitUntil:'domcontentloaded'});
  const row=adminPage.locator(`tr[data-report-id="${report.id}"]`);await row.waitFor({state:'visible',timeout:15000});
  const responsePromise=adminPage.waitForResponse(response=>new URL(response.url()).pathname==='/api/admin/reports/'+report.id&&response.request().method()==='GET');
  await row.getByRole('button',{name:'Open',exact:true}).click();const response=await responsePromise;const detail=await response.json();
  need(response.status()===200&&detail.report?.id===report.id&&detail.report.body===args.body&&detail.report.links?.runId===runId,'AFR_ADMIN_DETAIL_BINDING');
  const selected=adminPage.getByRole('region',{name:'Selected private report'});await selected.getByRole('heading',{name:args.title,exact:true}).waitFor();
  const text=await selected.innerText();need(text.includes(args.body)&&text.includes(runId),'AFR_ADMIN_UI_BODY_MISSING');
  proof.adminUI={clicked:true,url:adminPage.url(),reportId:report.id,httpStatus:response.status(),title:args.title,body:args.body,links:detail.report.links};
  proof.domainAfter=await domainSnapshot(readonlyQuery,runId);assert.deepEqual(proof.domainAfter,proof.domainBefore,'support reporting must not mutate benchmark or financial state');
  need((await readonlyQuery('SELECT id FROM oid_support_report WHERE owner_id=$1 AND operation_id=$2',[proof.run.owner_id,args.operationId])).length===1,'AFR_DUPLICATE_REPORT');
  proof.status='verified';assertSecretFree(proof,'afr-proof');return proof;
 }finally{await client.close().catch(()=>{});}
}

/** One actual production UI handoff: native agent runs tasks, observes real unknown, reports without a second turn. */
export async function runAgentFailureReportingOwnerCase(input){
 need((input.receiptFaultProxy||input.preparationFailureControl)&&input.automaticWorkerEvaluation===true,'AFR_REAL_WORKER_FAULT_REQUIRED');
 need(!(input.receiptFaultProxy&&input.preparationFailureControl),'AFR_ONE_FAULT_BOUNDARY_REQUIRED');
 const execute=async ctx=>{
  const handoff=await readAgentFailureProductionHandoff(ctx),clipboard=handoff.clipboard;
  const preparationFailure=input.preparationFailureControl;
  const fault=preparationFailure??input.receiptFaultProxy;let beforeReportingSnapshot,confirmedRunId,terminalCapture;
  if(preparationFailure)await preparationFailure.arm(ctx);
  else {fault.setTargetPredicate(({transactionHash})=>findAgentFailureReceiptTarget(ctx,transactionHash));fault.setMode('missing');}
  try{
   const nativeRunner=createArcNativeIntentRunner({repoRoot:ctx.repoRoot,captureId:input.captureId,enabledTools:ARC_NATIVE_REPORT_TOOLS,
    onResponseProjection:async({response})=>{
     if(beforeReportingSnapshot)return;
     const terminal=[response.projection.result,...(response.projection.content??[])].find(value=>value?.run?.terminal===true);
     const id=terminal?.run?.runId,args=platformFailureReportArguments({terminal,runId:id});need(args,'AFR_NATIVE_TERMINAL_REASON');
     if(preparationFailure)need(terminal.run.terminalReason==='coordinator_preparation_failed'||terminal.run.cancellationReason==='coordinator_preparation_failed','AFR_PREPARATION_FAILURE_REASON');
     const rows=await ctx.readonlyQuery('SELECT id FROM oid_benchmark_run WHERE id=$1 AND intent_id=$2 AND owner_id=$3 AND agent_id=$4',[id,ctx.intentId,ctx.ownerId,ctx.agentId]);need(rows.length===1,'AFR_NATIVE_TERMINAL_SCOPE');
     need((await ctx.readonlyQuery('SELECT id FROM oid_support_report WHERE owner_id=$1 AND operation_id=$2',[ctx.ownerId,args.operationId])).length===0,'AFR_REPORT_PRECEDES_TERMINAL_CAPTURE');
     const snapshot=await domainSnapshot(ctx.readonlyQuery,id);confirmedRunId=id;terminalCapture=terminal;beforeReportingSnapshot=snapshot;
    }});
   const nativeCompleted=await nativeRunner({agentBearer:ctx.agentBearer,agentId:ctx.agentId,intentId:ctx.intentId,handoffPrompt:clipboard,publicOrigin:ctx.publicOrigin});
   // Retain safe protocol diagnostics even if the intended H1 fault was never reached.
   ctx.captureProgress({schemaVersion:'agent-failure-reporting-physical-capture/v1',status:'running',
    ...(confirmedRunId?{runId:confirmedRunId}:{}),agentId:ctx.agentId,intentId:ctx.intentId,handoff,native:nativeCompleted,
    fault:fault.snapshot(),terminalBeforeReport:terminalCapture??null,domainBefore:beforeReportingSnapshot??null});
   need(beforeReportingSnapshot&&confirmedRunId&&nativeCompleted.nativeObservationErrors.length===0,'AFR_TERMINAL_OBSERVATION_FAILED');
   need(fault.snapshot().interventions.length>0,'AFR_ACTUAL_OBSERVER_FAULT_MISSING');
   const proof=await captureAgentFailureReporting({...ctx,adminPage:input.adminPage,runId:confirmedRunId,browserAdmission:{clicked:true,...ctx.launchIntentHttp},nativeCompleted,beforeReportingSnapshot,handoff});
   proof.terminalBeforeReport=terminalCapture;proof.fault=fault.snapshot();proof.failureBoundary=preparationFailure?'successor_preparation_unavailable':'closed_task_observation_unavailable';
   if(preparationFailure){
    const rows=await ctx.readonlyQuery(`SELECT r.id AS run_id,r.status,r.cancellation_reason,r.finished_at::text,r.successor_preparation_timeout_seconds,
      p.task_id AS predecessor_task_id,p.finished_at::text AS predecessor_finished_at,p.status AS predecessor_status,
      n.task_id AS successor_task_id,n.status AS successor_status,n.started_at::text AS successor_started_at,
      (SELECT count(*)::int FROM oid_task_preparation_intent i WHERE i.run_id=r.id AND i.task_index=n.task_index) AS successor_preparations,
      EXISTS(SELECT 1 FROM oid_run_task_evaluation e WHERE e.run_id=r.id AND e.task_index=p.task_index AND e.result_json->>'status'='known') AS predecessor_known,
      EXISTS(SELECT 1 FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id AND l.lease_id=i.lease_id WHERE i.run_id=r.id AND i.task_index=p.task_index AND l.state='fenced') AS predecessor_fenced
      FROM oid_benchmark_run r JOIN oid_run_task p ON p.run_id=r.id AND p.task_index=0 JOIN oid_run_task n ON n.run_id=r.id AND n.task_index=1 WHERE r.id=$1`,[confirmedRunId]);
    need(rows.length===1,'AFR_PREPARATION_FAILURE_PG');proof.successorFailure=rows[0];
   }
   proof.nativeExecutionMode='same_production_handoff';ctx.captureProgress(proof);return proof;
  }finally{if(preparationFailure)await preparationFailure.reset();else fault.setMode('pass');}
 };
 const result=await runGenuineS1OwnerCase({...input,continuityCase:'native_handoff',continuityTaskIds:['S1','M1','H1'],
  taskId:'M1',exactQuoteBonusFunding:true,bonusCodeFunding:true,bddProbes:false,onGenuineLaunchIntentReady:execute});
 result.afr=result.continuity;delete result.continuity;result.status=result.afr?.status==='verified'?'captured_afr_run':'blocked';
 result.automaticWorkerEvaluationVerified=false;result.automaticPlatformFailureVerified=result.afr?.status==='verified';
 if(result.afr?.runId)result.runCompletion={status:'verified_platform_failure',runId:result.afr.runId};return result;
}
