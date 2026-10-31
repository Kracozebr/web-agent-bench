import {createHash,randomUUID} from 'node:crypto';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import pg from 'pg';
import {assertSecretFree} from './evidence.mjs';

const {Client,Pool}=pg;
const digest=value=>createHash('sha256').update(value).digest('hex');
const delay=ms=>new Promise(done=>setTimeout(done,ms));
function demand(value,code){if(!value)throw Object.assign(new Error(code),{code});}
function sourceBody(source){return{result:source.result,selectedExecutions:source.selectedExecutions,recoverySource:source.recoverySource};}
function sourceHash(source){return digest(JSON.stringify(sourceBody(source)));}

/** Private fixture barrier only: no INSERT/UPDATE/DELETE and no direct refund invocation. */
export async function armFirstRefundCrash({commonCapture:common,target,readSourceSnapshot}){
 const database=common.databaseIsolation?.databaseName;
 const ownerUrl=new URL(common.databaseUrl),observerUrl=new URL(common.observerDatabaseUrl);
 demand(/^oid_acceptance_[a-f0-9]{32}$/.test(database??'')&&ownerUrl.hostname==='postgres'&&ownerUrl.username==='oid_owner'&&
  observerUrl.hostname==='postgres'&&observerUrl.username==='oid_observer'&&ownerUrl.pathname==='/'+database&&observerUrl.pathname==='/'+database,
 'ber_first_refund_requires_isolated_database');
 demand(typeof common.stopApi==='function'&&typeof common.restartApi==='function'&&typeof readSourceSnapshot==='function','ber_first_refund_runtime_callbacks_missing');
 const controller=new Client({connectionString:ownerUrl.href,application_name:'ber-first-refund-fault-barrier'});
 const observer=new Pool({connectionString:observerUrl.href,max:1,application_name:'ber-first-refund-readonly-observer'});
 let controllerPid,holding=false,controllerClosed=false,apiStopped=false,resumed=false,beforeSourceHash,result;
 const directory='artifacts/runs/ber-first-refund-crash/'+common.runId+'/'+randomUUID();
 const save=async(name,value)=>{assertSecretFree(value,'ber-first-refund-crash');const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');
  await mkdir(resolve(common.repoRoot,directory),{recursive:true,mode:0o700});const path=directory+'/'+name+'.json';
  await writeFile(resolve(common.repoRoot,path),bytes,{flag:'wx',mode:0o600});return{path,sha256:digest(bytes),bytes:bytes.length};};
 const observe=async()=>{const c=await observer.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const q=async(text,args=[target.runId])=>(await c.query(text,args)).rows;
  const identity=(await q("SELECT current_user AS role,current_database() AS database_name,current_setting('transaction_read_only') AS readonly,clock_timestamp() AS observed_at",[]))[0];
  demand(identity.role==='oid_observer'&&identity.database_name===database&&identity.readonly==='on','ber_first_refund_observer_invalid');
  const run=(await q('SELECT id,owner_id,agent_id,status,terminal_reason,cancellation_reason,cancellation_evidence_hash FROM oid_benchmark_run WHERE id=$1'))[0];
  const recovery=(await q(`SELECT action_id,run_id,status,started_at,deadline_at,clock_excluded_ms,latest_evidence_hash
   FROM oid_run_platform_recovery WHERE run_id=$1 AND action_id=$2`,[target.runId,target.actionId]))[0];
  const refunds=await q('SELECT run_id,operation_id,evidence_hash,bonus_refunded_units::text FROM oid_run_platform_refund WHERE run_id=$1');
  const prefix='runref_'+target.runId.replaceAll('-','')+'_';
  const refundLedger=await q(`SELECT id,operation_id,entry_type,source_kind,amount_units::text,available_delta_units::text,expired_delta_units::text
   FROM oid_ledger_entry WHERE entry_type='refund' AND left(operation_id,length($1))=$1 ORDER BY id`,[prefix]);
  const execution=await q(`SELECT i.run_id,i.preparation_id,i.environment_id,l.lease_id,l.state AS lease_state,l.fence_evidence,
   o.generation_id FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id
   JOIN LATERAL(SELECT generation_id FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1)o ON true
   WHERE i.run_id=$1`);
  const actions=await q(`SELECT a.id,a.operation_id,a.payload_hash,a.action_kind,r.receipt_status,r.transaction_hash,o.status AS outbox_status
   FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id JOIN oid_run_task_action_outbox o ON o.action_id=a.id WHERE a.run_id=$1`);
  const cancellation=await q(`SELECT event_type,payload_hash,payload_json,created_at FROM oid_run_event WHERE run_id=$1 AND event_type='run.cancelled.after_start'`);
  const locks=await q(`SELECT pid,mode,granted,waitstart,pg_blocking_pids(pid) AS blocking_pids
   FROM pg_locks WHERE locktype='relation' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
    AND relation='public.oid_run_platform_refund'::regclass ORDER BY pid,mode`,[]);
  await c.query('COMMIT');return{identity,run,recovery,refunds,refundLedger,execution,actions,cancellation,locks};
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}};
 const exactFencedCancelled=state=>state.run?.id===target.runId&&state.run.status==='cancelled'&&state.run.cancellation_reason==='coordinator_platform_failure'&&
  state.execution.length===1&&state.execution[0].lease_state==='fenced'&&state.execution[0].fence_evidence?.confirmed===true&&
  /^[0-9a-f]{64}$/.test(state.run.cancellation_evidence_hash??'')&&/^[0-9a-f]{64}$/.test(state.execution[0].fence_evidence?.evidence?.sha256??'')&&
  state.cancellation.length===1&&state.cancellation[0].payload_json?.fenceEvidenceHash===state.run.cancellation_evidence_hash&&
  state.execution[0].fence_evidence?.preparationId===state.execution[0].preparation_id&&
  state.execution[0].fence_evidence?.environmentId===state.execution[0].environment_id&&
  state.execution[0].fence_evidence?.leaseId===state.execution[0].lease_id&&state.execution[0].fence_evidence?.generationId===state.execution[0].generation_id;
 const noCommittedRefund=state=>state.refunds.length===0&&state.refundLedger.length===0;
 const waitState=async(predicate,maxMs)=>{const until=Date.now()+maxMs;let state;do{state=await observe();if(predicate(state))return state;await delay(100);}while(Date.now()<until);
  throw Object.assign(new Error('ber_first_refund_barrier_not_exercised'),{code:'BER_FIRST_REFUND_BARRIER_NOT_EXERCISED',
   safeDiagnostic:{runId:target.runId,actionId:target.actionId,runStatus:state?.run?.status??null,refundCount:state?.refunds?.length??null,
    refundLedgerCount:state?.refundLedger?.length??null,waitingWriterCount:state?.locks?.filter(l=>!l.granted&&l.mode==='RowExclusiveLock').length??null}});};
 const releaseController=async()=>{if(controllerClosed)return;if(holding){await controller.query('COMMIT');holding=false;}await controller.end();controllerClosed=true;};
 await controller.connect();controllerPid=(await controller.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
 try{
  const initial=await observe();demand(noCommittedRefund(initial),'ber_first_refund_already_committed_before_fault');
  await controller.query('BEGIN');await controller.query("SET LOCAL lock_timeout='1000ms'");
  await controller.query('LOCK TABLE public.oid_run_platform_refund IN SHARE MODE');holding=true;
 }catch(e){await controller.query('ROLLBACK').catch(()=>{});await controller.end();await observer.end();throw e;}
 const armedAt=new Date().toISOString();
 let armed;try{armed=await save('armed-before-observer-restoration',{schemaVersion:'ber-first-refund-barrier-armed/v1',databaseName:database,
  runId:target.runId,actionId:target.actionId,controllerPid,armedAt,control:'share_table_lock_no_business_write',observation:await observe()});}
 catch(e){await releaseController();await observer.end();throw e;}
 return{
  async interruptAndRestart(){
   const before=await waitState(state=>state.locks.some(l=>!l.granted&&l.mode==='RowExclusiveLock'&&l.blocking_pids.includes(controllerPid))&&
    exactFencedCancelled(state)&&noCommittedRefund(state),20000);
   const sourceBefore=await readSourceSnapshot();beforeSourceHash=sourceHash(sourceBefore);
   demand(sourceBefore.result?.length===1&&sourceBefore.result[0].status==='settled'&&sourceBefore.result[0].receiptStatus==='success'&&
    sourceBefore.result[0].generationStatus==='fenced','ber_first_refund_original_effect_not_bound');
   const beforeCrash=await save('before-crash-blocked-first-refund',{schemaVersion:'ber-first-refund-before-crash/v1',runId:target.runId,actionId:target.actionId,
    controllerPid,armed,observation:before,source:sourceBefore,sourceStableBodySha256:beforeSourceHash,
    checks:{actual_waiting_refund_writer:true,blocking_controller_share_lock:true,exact_fenced_cancelled_run:true,official_refund_zero:true,ledger_refund_zero:true}});
   const immediatelyBeforeStop=await observe();
   demand(immediatelyBeforeStop.locks.some(l=>!l.granted&&l.mode==='RowExclusiveLock'&&l.blocking_pids.includes(controllerPid))&&
    noCommittedRefund(immediatelyBeforeStop),'ber_first_refund_writer_no_longer_blocked_before_stop');
   const stopStartedAt=new Date().toISOString();apiStopped=true;const stopReceipt=await common.stopApi();
   const after=await waitState(state=>state.locks.every(l=>l.granted||!l.blocking_pids.includes(controllerPid))&&
    exactFencedCancelled(state)&&noCommittedRefund(state),5000);
   let apiUnavailable=false;try{const health=await fetch(new URL('/healthz',common.apiOrigin),{signal:AbortSignal.timeout(2000)});apiUnavailable=!health.ok;}catch{apiUnavailable=true;}
   demand(apiUnavailable,'ber_first_refund_api_not_stopped');
   const sourceAfterStop=await readSourceSnapshot();demand(sourceHash(sourceAfterStop)===beforeSourceHash,'ber_first_refund_source_changed_during_crash');
   const afterStop=await save('after-api-stop-before-barrier-release',{schemaVersion:'ber-first-refund-after-stop/v1',runId:target.runId,actionId:target.actionId,
    controllerPid,stopStartedAt,stopFinishedAt:new Date().toISOString(),stopReceipt:stopReceipt??null,immediatelyBeforeStop,
    apiUnavailable,observation:after,source:sourceAfterStop,
    sourceStableBodySha256:sourceHash(sourceAfterStop),checks:{waiting_refund_transaction_gone:true,official_refund_still_zero:true,ledger_refund_still_zero:true,original_effect_unchanged:true}});
   await releaseController();const restartReceipt=await common.restartApi();resumed=true;
   demand(restartReceipt?.healthHttpStatus===200&&restartReceipt.previousPid!==restartReceipt.currentPid,'ber_first_refund_restart_unverified');
   result={schemaVersion:'ber-first-refund-crash/v1',runId:target.runId,actionId:target.actionId,armed,beforeCrash,afterStop,restartReceipt,
    sourceStableBodySha256:beforeSourceHash,claims:{directRefundInvocation:false,businessSqlMutation:false,economicResubmission:false,completeBer007:false}};
   return result;
  },
  async observeAfterFinalization(){
   demand(result,'ber_first_refund_crash_not_run');const after=await observe();
   demand(after.run?.status==='failed'&&after.run.terminal_reason==='platform_failure_recovery_exhausted'&&after.recovery?.status==='refunded'&&
    after.refunds.length===1&&after.refundLedger.length===1&&after.refunds[0].evidence_hash===after.recovery.latest_evidence_hash,
   'ber_first_refund_once_only_finalization_missing');
   const source=await readSourceSnapshot();demand(sourceHash(source)===beforeSourceHash,'ber_first_refund_source_changed_after_finalization');
   const afterFinalization=await save('after-normal-restart-first-refund-committed',{schemaVersion:'ber-first-refund-after-finalization/v1',runId:target.runId,
    actionId:target.actionId,observation:after,source,sourceStableBodySha256:sourceHash(source),checks:{first_refund_committed_once:true,original_effect_unchanged:true}});
   return{...result,afterFinalization};
  },
  async close(){try{await releaseController();if(apiStopped&&!resumed){await common.restartApi();resumed=true;}}finally{await observer.end();}},
 };
}
