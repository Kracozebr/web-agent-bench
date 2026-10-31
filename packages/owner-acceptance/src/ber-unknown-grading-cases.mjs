import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFile,readdir,mkdir,writeFile} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
import pg from 'pg';
import {runGenuineRankedOwnerCase} from './genuine-s1-cases.mjs';
import {assertSecretFree} from './evidence.mjs';
import {runBerCompletedCallbacks} from '../../../tools/ber_completed_callbacks.mjs';
import {runBerPendingTransitionInterruption} from '../../../tools/ber_pending_transition_interruption.mjs';
import {armBerCompletionHandoffInterruption} from '../../../tools/ber_completion_handoff_interruption.mjs';

const CASES=['missing_recover','conflicting_recover','missing_exhaust_restart','cancel_before_recover','recover_before_cancel'];
const sha=value=>createHash('sha256').update(typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value)).digest('hex');
const delay=ms=>new Promise(done=>setTimeout(done,ms));
const check=(value,code)=>{if(!value)throw Object.assign(new Error(code),{code});};
const object=value=>typeof value==='string'?JSON.parse(value):value;

async function readonly(pool,callback,expectedDatabase,expectedRole='oid_observer'){
  const client=await pool.connect();
  try{
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const identity=(await client.query("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only,clock_timestamp() database_now")).rows[0];
    check(identity.role===expectedRole&&identity.read_only==='on'&&identity.database_name===expectedDatabase,'ber_unknown_observer_identity');
    const result=await callback(client);await client.query('COMMIT');
    return {identity:{...identity,database_now:new Date(identity.database_now).toISOString()},result};
  }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}

async function snapshot(pool,database,runId){return readonly(pool,async client=>{
  const run=(await client.query('SELECT id::text,owner_id::text,agent_id::text,mode,status,release_identity,manifest_hash,terminal_reason,cancellation_reason,cancellation_evidence_hash,cancellation_requested_at::text,overall_deadline::text,finished_at::text FROM oid_benchmark_run WHERE id=$1',[runId])).rows[0];
  const tasks=(await client.query(`SELECT task_index,task_id,status,closure_status,closure_id::text,closure_payload_hash,closure_reason,
    closed_at::text,deadline_at::text,accepted_action_sequence::text,action_cutoff_sequence::text,reconciled_action_sequence::text,
    (closed_at+interval '180 seconds')::text AS evaluation_retry_deadline,
    clock_timestamp()>=closed_at+interval '180 seconds' AS evaluation_retry_expired
    FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`,[runId])).rows;
  const actions=(await client.query(`SELECT a.id::text,a.task_index,a.action_sequence::text,a.operation_id,a.payload_hash,a.action_kind,
    a.accepted_at::text,r.receipt_revision,r.receipt_status,r.evidence_hash,r.evidence_path,r.transaction_hash,
    o.status outbox_status FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id
    JOIN oid_run_task_action_outbox o ON o.action_id=a.id WHERE a.run_id=$1 ORDER BY a.task_index,a.action_sequence`,[runId])).rows;
  const evaluations=(await client.query('SELECT task_index,task_id,closure_id::text,release_identity,manifest_hash,case_hash,rubric_hash,evaluator_source_hash,input_hash,input_json,result_hash,result_json,created_at::text FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index',[runId])).rows;
  const events=(await client.query('SELECT id::text,sequence,event_type,source,payload_hash,payload_json,created_at::text FROM oid_run_event WHERE run_id=$1 ORDER BY sequence',[runId])).rows;
  const execution=(await client.query(`SELECT b.task_index,b.env_id,b.generation_id::text,b.participant_id,i.preparation_id::text,i.lease_id::text,
    l.state lease_state,l.fence_evidence FROM oid_task_execution_binding b JOIN oid_task_preparation_intent i ON i.run_id=b.run_id AND i.task_index=b.task_index
    JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id WHERE b.run_id=$1 ORDER BY b.task_index`,[runId])).rows;
  const preparations=(await client.query(`SELECT i.task_index,i.preparation_id::text,i.lease_id::text,i.environment_id,
    l.state lease_state,l.fenced_at::text,l.fence_evidence,o.status observation_status,
    COALESCE(b.generation_id,o.generation_id)::text generation_id,b.env_id bound_environment_id
    FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.lease_id=i.lease_id AND l.preparation_id=i.preparation_id
    LEFT JOIN oid_task_execution_binding b ON b.run_id=i.run_id AND b.task_index=i.task_index
    LEFT JOIN LATERAL (SELECT status,generation_id FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1)o ON true
    WHERE i.run_id=$1 ORDER BY i.task_index`,[runId])).rows;
  const money=(await client.query('SELECT id::text,entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text,expired_delta_units::text,operation_id FROM oid_ledger_entry WHERE owner_id=$1 ORDER BY created_at,id',[run.owner_id])).rows;
  const claims=(await client.query('SELECT claim_id::text,status,released_at::text FROM oid_run_dispatch_claim WHERE run_id=$1 ORDER BY claim_id',[runId])).rows;
  const slots=(await client.query('SELECT claim_id::text,state,released_at::text FROM oid_run_execution_slot WHERE run_id=$1',[runId])).rows;
  const recoveries=(await client.query('SELECT action_id::text,status,started_at::text,deadline_at::text FROM oid_run_platform_recovery WHERE run_id=$1',[runId])).rows;
  const publications=(await client.query(`SELECT (SELECT count(*)::int FROM oid_ranked_run_handoff WHERE run_id=$1) handoffs,
    (SELECT count(*)::int FROM oid_ranked_verified_result WHERE run_id=$1) results`,[runId])).rows[0];
  const reports=(await client.query('SELECT id::text,run_id::text,operation_id,payload_hash FROM oid_support_report WHERE run_id=$1 ORDER BY id',[runId])).rows;
  return{run,tasks,actions,evaluations,events,execution,preparations,money,claims,slots,recoveries,publications,reports};
},database);}

async function rawObservationPackets(repoRoot,runId){
  const folder=resolve(repoRoot,'artifacts/runs/owner-identity-bef-task-coordinator/observation',runId,'H1');let names=[];
  try{names=await readdir(folder);}catch{return[];}
  const references=[];
  for(const name of names.filter(name=>/^[0-9a-f]{64}\.json$/.test(name))){
    const path=resolve(folder,name),bytes=await readFile(path),document=JSON.parse(bytes);
    if(document.binding?.runId===runId&&document.binding?.taskId==='H1')references.push({path:relative(repoRoot,path).split('\\').join('/'),sha256:sha(bytes)});
  }
  return references;
}

async function lifecycle(repoRoot,runId){
  const folder=resolve(repoRoot,'artifacts/runs/owner-identity-bef-task-coordinator/lifecycle');let names=[];
  try{names=await readdir(folder);}catch{return[];}
  const out=[];
  for(const name of names.filter(name=>name.startsWith(runId+'-')&&name.endsWith('.json'))){
    const path=resolve(folder,name),bytes=await readFile(path);let value;try{value=JSON.parse(bytes);}catch{continue;}
    if(value.runId===runId&&value.taskIndex===8)out.push({path:relative(repoRoot,path).split('\\').join('/'),sha256:sha(bytes),document:value});
  }
  return out;
}

async function until(read,predicate,timeoutMs,code){
  const end=Date.now()+timeoutMs;let last;
  do{last=await read();if(await predicate(last))return last;await delay(500);}while(Date.now()<end);
  throw Object.assign(new Error(code),{code,lastObservation:last});
}
function h1(state){return state.result.tasks.find(task=>task.task_index===8&&task.task_id==='H1');}
function closedStable(task){const {status,evaluation_retry_expired,...stable}=task;return stable;}
function noPublication(state){assert.deepEqual(state.result.publications,{handoffs:0,results:0});}
function moneyUnchanged(before,after){assert.deepEqual(after.result.money,before.result.money,'unknown evidence must not mint a refund or change original charges');}

async function observePayments(befPool,state){
  const binding=state.result.execution.find(row=>row.task_index===8);check(binding,'ber_unknown_h1_binding');
  return readonly(befPool,async client=>{
    const generation=(await client.query('SELECT generation_id::text,env_id,status,fenced_at::text FROM bef_generation WHERE generation_id=$1::uuid',[binding.generation_id])).rows[0];
    const payments=(await client.query('SELECT payment_id::text,operation_id::text,transaction_hash,receipt_status,amount_units::text,token_delta_units::text FROM bef_payment WHERE env_id=$1 AND generation_id=$2::uuid ORDER BY payment_id',[binding.env_id,binding.generation_id])).rows;
    check(payments.length===3&&payments.every(row=>row.receipt_status==='success'&&/^0x[0-9a-f]{64}$/i.test(row.transaction_hash)&&row.amount_units===row.token_delta_units),'ber_unknown_requires_three_actual_paid_effects');
    return{binding,generation,payments};
  },'bef','bef_observer');
}

async function cancelFromBrowser(common,runId){
  const page=common.ownerPage;common.genuineCaptureInput.ownerCapture?.action('navigate','/runs');
  await page.goto(common.publicOrigin+'/runs',{waitUntil:'domcontentloaded'});
  await page.getByTestId('run-intents-refresh').click();
  const button=page.getByTestId('run-cancel-'+runId);await button.waitFor({state:'visible',timeout:15000});
  const response=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/owner/runs/'+runId+'/cancel'&&response.request().method()==='POST');
  common.genuineCaptureInput.ownerCapture?.action('click','run-cancel-'+runId);await button.click();
  const actual=await response;check(actual.status()===200,'ber_unknown_owner_cancel_http');
  return{boundary:'actual_owner_browser_cancel_control_backend',runId,httpStatus:actual.status(),observedAt:new Date().toISOString()};
}

/** Actual full Ranked prefixes and H1 paid effects; every unfinished fault run is explicitly incomplete. */
export async function runBerUnknownGradingCases({commonCapture,receiptFaultProxy,recoveryFaultProxy,progress}){
  const database=commonCapture.databaseIsolation.databaseName;
  check(/^oid_acceptance_[a-f0-9]{32}$/.test(database),'ber_unknown_requires_disposable_database');
  const selected=process.env.OID_BER_UNKNOWN_CASES?process.env.OID_BER_UNKNOWN_CASES.split(','):CASES;
  check(selected.length>0&&selected.every(name=>CASES.includes(name))&&new Set(selected).size===selected.length,'ber_unknown_case_selection_invalid');
  const root=resolve(commonCapture.repoRoot,'artifacts/runs/ber-unknown-grading-source',commonCapture.runId);
  await mkdir(root,{recursive:true,mode:0o700});
  const ownerPool=new pg.Pool({connectionString:commonCapture.observerDatabaseUrl,max:2});
  const befPassword=(await readFile('/run/secrets/bef_database_observer_password','utf8')).trim();
  const befUrl=new URL(`postgres://bef_observer@host.docker.internal:${process.env.BEF_DATABASE_HOST_PORT||'55432'}/bef`);befUrl.password=befPassword;
  const befPool=new pg.Pool({connectionString:befUrl.href,max:1});
  const result={schemaVersion:'ber-unknown-grading-matrix/v1',boundary:'actual_browser_ranked_prefix_real_h1_payments_worker_observation_restart_readonly_postgres',
    caseInventory:CASES,selectedCases:selected,caseResults:[],status:'running',fullScenarioAcceptance:false};
  try{
    for(const name of selected){
      const entry={name,status:'running',runId:null,checkpoints:[],restart:null,cancel:null,expectedIntentionalInterruption:false};result.caseResults.push(entry);
      let activeRun=null,closedCaptureComplete=false,completionGate=null,output;
      const snap=()=>snapshot(ownerPool,database,activeRun);
      receiptFaultProxy.setMode(name==='conflicting_recover'?'conflicting':'missing');
      receiptFaultProxy.setTargetPredicate(async({transactionHash})=>{
        if(!activeRun)return null;const current=await snap(),task=h1(current);
        const exactPayment=current.result.actions.find(action=>action.task_index===8&&action.action_kind==='pay'&&
          action.receipt_status==='observed'&&action.transaction_hash?.toLowerCase()===transactionHash);
        return current.result.run.status==='running'&&task?.closure_status==='closed'&&exactPayment&&
          task.accepted_action_sequence===task.action_cutoff_sequence&&task.reconciled_action_sequence===task.action_cutoff_sequence?
          {runId:activeRun,taskIndex:8,taskId:'H1',closureId:task.closure_id}:null;
      });
      await progress?.({component:'ber_unknown_grading',phase:'case_started',case:name});
      try{output=await runGenuineRankedOwnerCase({...commonCapture.genuineCaptureInput,captureId:randomUUID(),automaticWorkerEvaluation:true,
        bonusCodeFunding:true,bddProbes:false,primaryClientOnly:false,
        onGenuineFirstTaskActive:async context=>{activeRun=context.runId;entry.runId=activeRun;
          await progress?.({component:'ber_unknown_grading',phase:'ranked_prefix_started',case:name,runId:activeRun});},
        onGenuineRunCompleted:async context=>{
          if(!['missing_recover','conflicting_recover'].includes(name))return;
          entry.completedCallbacks=await runBerCompletedCallbacks({databaseUrl:commonCapture.databaseUrl,
            observerDatabaseUrl:commonCapture.observerDatabaseUrl,repoRoot:commonCapture.repoRoot,
            runId:context.runId,ownerId:context.ownerId,agentId:context.agentId});
          check(entry.completedCallbacks.status==='verified_subset','ber_unknown_completed_callbacks_failed');
        },
        onGenuineTaskClosed:async context=>{
          if(context.taskId==='U1'&&completionGate){
            entry.completionHandoff=await completionGate.interruptAwait();
            check(entry.completionHandoff.status==='verified_subset','ber_unknown_completion_handoff_interruption_failed');
            return;
          }
          if(context.taskId!=='H1')return;
          const initial=await until(async()=>({state:await snap(),progress:await lifecycle(commonCapture.repoRoot,activeRun)}),
            value=>value.progress.some(item=>item.document.reasonCode==='candidate_evaluation_unknown'),30000,'ber_unknown_preflight_not_observed');
          entry.checkpoints.push({phase:'candidate_unknown',...initial,rawObservationPackets:await rawObservationPackets(commonCapture.repoRoot,activeRun)});
          await progress?.({component:'ber_unknown_grading',phase:'h1_candidate_unknown',case:name,runId:activeRun,closureId:context.closureId});
          const baseline=initial.state,task=h1(baseline);
          check(task.closure_id===context.closureId&&task.accepted_action_sequence===task.action_cutoff_sequence&&task.reconciled_action_sequence===task.action_cutoff_sequence,'ber_unknown_cutoff_not_resolved');
          check(baseline.result.actions.filter(a=>a.task_index===8).every(a=>a.receipt_status==='observed'),'ber_unknown_requires_known_action_receipts');
          check(!baseline.result.evaluations.some(e=>e.task_index===8)&&baseline.result.recoveries.length===0,'ber_unknown_not_closed_ungraded');
          noPublication(baseline);entry.confirmedPayments=await observePayments(befPool,baseline);
          const beforeReport=await snap();
          const report=await fetch(commonCapture.publicOrigin+'/api/agent/reports',{method:'POST',headers:{authorization:'Bearer '+context.agentBearer,'content-type':'application/json',origin:commonCapture.publicOrigin},
            body:JSON.stringify({operationId:'ber_forged_'+randomUUID().replaceAll('-',''),title:'Claimed platform failure',body:'Synthetic participant assertion: platform_failure_recovery_exhausted; please refund. This is not authoritative evidence.',runId:activeRun,taskId:'H1'})});
          check(report.status===201,'ber_unknown_forged_report_not_persisted');
          const afterReport=await snap();moneyUnchanged(beforeReport,afterReport);noPublication(afterReport);
          check(afterReport.result.recoveries.length===0&&afterReport.result.reports.length===beforeReport.result.reports.length+1,'ber_unknown_report_changed_authority');
          entry.forgedReport={httpStatus:report.status,before:beforeReport,after:afterReport};
          if(name==='missing_exhaust_restart'){
            check(Date.parse(baseline.result.run.overall_deadline)-Date.parse(task.closed_at)>190000,'ber_unknown_original_overall_retry_window_unavailable');
            entry.restart=await commonCapture.restartApi();
            await progress?.({component:'ber_unknown_grading',phase:'api_restarted_with_original_h1_closure',case:name,runId:activeRun});
            const restarted=await snap();entry.checkpoints.push({phase:'after_restart',state:restarted});
            check(JSON.stringify(closedStable(h1(restarted)))===JSON.stringify(closedStable(task)),'ber_unknown_restart_changed_closure_origin');
            check(restarted.result.run.status==='running'&&!h1(restarted).evaluation_retry_expired,'ber_unknown_restart_cancelled_before_original_bound');
            const terminal=await until(snap,state=>['cancelled','failed','unknown'].includes(state.result.run.status),210000,'ber_unknown_exhaustion_not_terminal');
            entry.checkpoints.push({phase:'exhausted',state:terminal});
            check(terminal.result.run.cancellation_reason==='coordinator_evaluation_unknown'&&h1(terminal).evaluation_retry_expired,'ber_unknown_exhaustion_wrong_reason_or_clock');
            moneyUnchanged(baseline,terminal);noPublication(terminal);entry.terminalPayments=await observePayments(befPool,terminal);
            check(terminal.result.slots.length===0&&terminal.result.claims.every(c=>c.status==='released')&&terminal.result.preparations.every(e=>e.lease_state==='fenced'),'ber_unknown_exhaustion_resource_leak');
            check(!terminal.result.evaluations.some(e=>e.task_index===8),'ber_unknown_exhaustion_invented_grade');
          }else if(name==='cancel_before_recover'){
            entry.cancel=await cancelFromBrowser(commonCapture,activeRun);
            const terminal=await until(snap,state=>state.result.run.status==='cancelled',30000,'ber_unknown_owner_cancel_not_terminal');
            receiptFaultProxy.setMode('pass');await delay(1500);
            const after=await snap();moneyUnchanged(baseline,after);noPublication(after);
            check(!after.result.evaluations.some(e=>e.task_index===8)&&after.result.slots.length===0,'ber_unknown_cancel_then_recover_published_grade');
            entry.checkpoints.push({phase:'cancelled_before_recovery',state:terminal},{phase:'after_stale_recovery',state:after});
          }else{
            if(name==='missing_recover'){
              entry.restart=await commonCapture.restartApi();
              const grace=await until(async()=>({state:await snap(),progress:await lifecycle(commonCapture.repoRoot,activeRun)}),
                value=>Date.parse(value.state.identity.database_now)>=Date.parse(entry.restart.finishedAt)+2000&&
                  value.progress.length>initial.progress.length,15000,'ber_unknown_restart_grace_not_observed');
              entry.checkpoints.push({phase:'restart_grace_unknown',...grace,rawObservationPackets:await rawObservationPackets(commonCapture.repoRoot,activeRun)});
              check(grace.state.result.run.status==='running'&&!grace.state.result.evaluations.some(e=>e.task_index===8)&&
                JSON.stringify(closedStable(h1(grace.state)))===JSON.stringify(closedStable(task)),
              'ber_unknown_restart_failed_to_preserve_unknown_window');
            }
            if(name==='missing_recover'||name==='conflicting_recover'){
              entry.pendingTransition=await runBerPendingTransitionInterruption({commonCapture,runId:activeRun,
                phase:name==='missing_recover'?'evaluation':'successor_dispatch',
                releaseReceiptFault:()=>receiptFaultProxy.setMode('pass')});
              check(entry.pendingTransition.status==='verified_subset','ber_unknown_pending_transition_failed');
            }else receiptFaultProxy.setMode('pass');
            const recovered=await until(snap,state=>state.result.evaluations.some(e=>e.task_index===8&&object(e.result_json)?.status==='known'),45000,'ber_unknown_recovery_not_known');
            moneyUnchanged(baseline,recovered);entry.checkpoints.push({phase:'recovered_known',state:recovered,rawObservationPackets:await rawObservationPackets(commonCapture.repoRoot,activeRun)});
            check(JSON.stringify(closedStable(h1(recovered)))===JSON.stringify(closedStable(task)),'ber_unknown_recovery_changed_cutoff');
            if(name==='conflicting_recover'){
              try{completionGate=await armBerCompletionHandoffInterruption({commonCapture,runId:activeRun});}
              catch(error){if(error.berCompletionHandoffCapture)entry.completionHandoff=error.berCompletionHandoffCapture;throw error;}
            }
            if(name==='recover_before_cancel'){
              entry.cancel=await cancelFromBrowser(commonCapture,activeRun);
              const terminal=await until(snap,state=>state.result.run.status==='cancelled',30000,'ber_unknown_post_recovery_cancel_not_terminal');
              moneyUnchanged(baseline,terminal);noPublication(terminal);entry.checkpoints.push({phase:'cancelled_after_recovery',state:terminal});
            }else return;
          }
          closedCaptureComplete=true;entry.expectedIntentionalInterruption=true;
          throw Object.assign(new Error('BER_INTENTIONAL_UNKNOWN_TERMINAL_CAPTURED'),{code:'BER_INTENTIONAL_UNKNOWN_TERMINAL_CAPTURED'});
        }});}finally{await completionGate?.close();completionGate=null;}
      entry.genuineCapture={captureId:output.captureId,status:output.status,blocker:output.blocker??null,stages:output.stages,
        taskEvaluations:output.taskEvaluations,participantActions:output.participantActions,trainingRunCompletion:output.trainingRunCompletion??null};
      const genuineBytes=Buffer.from(JSON.stringify(output,null,2)+'\n'),genuinePath=resolve(root,'genuine-'+output.captureId+'.json');
      await writeFile(genuinePath,genuineBytes,{flag:'wx',mode:0o600});
      entry.genuineCapture.evidence={path:relative(commonCapture.repoRoot,genuinePath).split('\\').join('/'),sha256:sha(genuineBytes)};
      entry.fault=receiptFaultProxy.snapshot();
      if(name==='missing_recover'||name==='conflicting_recover'){
        check(output.trainingRunCompletion?.status==='verified'&&output.run?.runId===activeRun,
          output.blocker?.reasonCode??'ber_unknown_recovered_ranked_not_completed');
        entry.checkpoints.push({phase:'full_ranked_completed',state:await snap()});
      }else check(closedCaptureComplete,output.blocker?.reasonCode??'ber_unknown_expected_terminal_case_incomplete');
      entry.status='passed';receiptFaultProxy.setMode('pass');
      await progress?.({component:'ber_unknown_grading',phase:'case_passed',case:name,runId:activeRun});
    }
    result.status='verified';
  }catch(error){
    result.status='failed';const entry=result.caseResults.at(-1);if(entry){entry.status='failed';entry.fault=receiptFaultProxy.snapshot();
      entry.errorCode=/^[A-Za-z0-9_]{1,100}$/.test(error.code??error.message)?error.code??error.message:'ber_unknown_matrix_failed';
      if(error.lastObservation)entry.lastObservation=error.lastObservation;}
  }finally{
    result.transport=recoveryFaultProxy?.snapshot()??null;
    receiptFaultProxy.setMode('pass');await ownerPool.end();await befPool.end();
    assertSecretFree(result,'ber-unknown-grading');
    const bytes=Buffer.from(JSON.stringify(result,null,2)+'\n'),path=resolve(root,'matrix.json');await writeFile(path,bytes,{flag:'wx',mode:0o600});
    result.evidence={path:relative(commonCapture.repoRoot,path).split('\\').join('/'),sha256:sha(bytes)};
  }
  return result;
}
