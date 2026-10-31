import {createHash,randomUUID} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import pg from 'pg';
import {runGenuineS1OwnerCase} from './genuine-s1-cases.mjs';
import {assertSecretFree} from './evidence.mjs';

const {Pool,Client}=pg;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/;
const VARIANTS=['before_cutoff_dispatch_after','at_cutoff_new_denied','after_cutoff_new_denied',
  'admission_reply_lost_before_dispatch','worker_restart_pending','revoked_agent_pending',
  'tool_reply_lost_after_dispatch','worker_restart_delivered'];
const digest=v=>createHash('sha256').update(v).digest('hex');
const sleep=ms=>new Promise(done=>setTimeout(done,Math.max(0,ms)));
function need(ok,code){if(!ok)throw Object.assign(new Error(code),{code});}
const stamp=v=>new Date(v).getTime();
function selectedVariants(){const raw=process.env.OID_BER_H1_CASES;const selected=raw?raw.split(','):VARIANTS;
 need(selected.length>0&&selected.length<=VARIANTS.length&&new Set(selected).size===selected.length&&selected.every(v=>VARIANTS.includes(v)),'ber_h1_case_selection_invalid');return selected;}
async function saved(root,path,value){assertSecretFree(value,'ber-h1-cutoff');const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');
 await mkdir(resolve(root,path,'..'),{recursive:true,mode:0o700});await writeFile(resolve(root,path),bytes,{flag:'wx',mode:0o600});return{path,sha256:digest(bytes),bytes:bytes.length};}
async function ro(pool,databaseName,fn){const c=await pool.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const who=(await c.query("SELECT current_user AS role,current_database() AS database_name,current_setting('transaction_read_only') AS readonly,clock_timestamp() AS observed_at")).rows[0];
 need(who.role==='oid_observer'&&who.database_name===databaseName&&who.readonly==='on','ber_h1_observer_identity_invalid');
 const result=await fn(c);await c.query('COMMIT');return{identity:who,result};}catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}}
async function clock(c,runId,taskIndex){return(await c.query(`SELECT t.task_id,t.deadline_at,i.environment_id,clock_timestamp() AS observed_at
 FROM oid_run_task t JOIN oid_task_preparation_intent i USING(run_id,task_index) WHERE t.run_id=$1 AND t.task_index=$2`,[runId,taskIndex])).rows[0];}
async function ownerSnapshot(pool,databaseName,runId,taskIndex){return ro(pool,databaseName,async c=>{
 const q=async(sql,args=[runId])=>(await c.query(sql,args)).rows;
 const run=(await q(`SELECT id,owner_id,agent_id,mode,status,terminal_reason,cancellation_reason,cancellation_evidence_hash,
  access_generation,started_at,finished_at,overall_deadline,quote_price_units::text,manifest_hash,release_identity
  FROM oid_benchmark_run WHERE id=$1`))[0];
 const tasks=await q(`SELECT run_id,task_index,task_id,status,deadline_at,closure_status,closure_reason,closure_id,
  action_cutoff_sequence::text,accepted_action_sequence::text,reconciled_action_sequence::text,closed_at FROM oid_run_task WHERE run_id=$1 ORDER BY task_index`);
 const actions=await q(`SELECT a.id,a.run_id,a.owner_id,a.agent_id,a.access_generation,a.environment_id,a.grant_id,a.task_id,
  a.operation_id,a.task_index,a.action_sequence::text,a.action_kind,a.payload_hash,a.command_json,a.accepted_at,
  r.receipt_status,r.receipt_revision,r.transaction_hash,r.evidence_hash,r.evidence_path,o.status AS outbox_status,o.delivered_at
  FROM oid_run_task_action a JOIN oid_run_task_action_receipt r ON r.action_id=a.id JOIN oid_run_task_action_outbox o ON o.action_id=a.id
  WHERE a.run_id=$1 ORDER BY a.action_sequence`);
 const preparation=await q(`SELECT i.run_id,i.preparation_id,i.task_index,i.claim_id,i.environment_id,l.lease_id,
  i.task_id,i.release_identity,i.manifest_hash,i.case_id,i.case_hash,i.initial_state_sha256,i.execution_identity_hash,
  i.environment_manifest_sha256,i.application_source_hash,l.state AS lease_state,l.fence_evidence,
  o.status AS observation_status,o.generation_id FROM oid_task_preparation_intent i JOIN oid_task_environment_lease l ON l.preparation_id=i.preparation_id
  JOIN LATERAL(SELECT status,generation_id FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1)o ON true
  WHERE i.run_id=$1 ORDER BY i.task_index`);
 const claim=await q('SELECT run_id,claim_id,status,claimed_at,released_at FROM oid_run_dispatch_claim WHERE run_id=$1');
 const slots=await q('SELECT run_id,agent_id,claim_id,state,released_at FROM oid_run_execution_slot WHERE run_id=$1');
 const events=await q('SELECT sequence::text,source,event_type,payload_hash,payload_json,created_at FROM oid_run_event WHERE run_id=$1 ORDER BY oid_run_event.sequence');
 const evaluations=await q('SELECT task_index,input_hash,result_hash,result_json FROM oid_run_task_evaluation WHERE run_id=$1 ORDER BY task_index');
 const closures=await q('SELECT id,task_index,operation_id,payload_hash,reason,action_cutoff_sequence::text,requested_at FROM oid_run_task_closure WHERE run_id=$1 ORDER BY task_index');
 const recovery=await q(`SELECT action_id,run_id,owner_id,agent_id,task_index,environment_id,operation_id,payload_hash,incident_evidence_hash,
  status,started_at,deadline_at,clock_excluded_ms,latest_evidence_hash FROM oid_run_platform_recovery WHERE run_id=$1 ORDER BY action_id`);
 const compact=runId.replaceAll('-',''),ops=['runacc_'+compact,'rundeb_'+compact,'runrel_'+compact];
 const ledger=await q(`SELECT id,entry_type,source_kind,operation_id,amount_units::text,available_delta_units::text,reserved_delta_units::text,
  expired_delta_units::text,bonus_grant_id FROM oid_ledger_entry WHERE operation_id=ANY($1::text[]) OR left(operation_id,length($2))=$2 ORDER BY id`,[ops,'runref_'+compact+'_']);
 const refunds=await q('SELECT run_id,operation_id,evidence_hash,bonus_refunded_units::text FROM oid_run_platform_refund WHERE run_id=$1');
 const currentAccess=run?(await q('SELECT id,access_generation,access_revoked_at FROM oid_agent WHERE id=$1',[run.agent_id]))[0]:null;
 return{run,tasks,actions,preparation,claim,slots,events,evaluations,closures,recovery,ledger,refunds,currentAccess};});}
async function befSnapshot(snapshot,targetActionId){
 const p=snapshot.result.preparation.find(p=>p.task_index===0);need(p&&UUID.test(p.generation_id),'ber_h1_generation_missing');
 const port=Number(process.env.BEF_DATABASE_HOST_PORT||'56432');need(port>=1&&port<=65535,'ber_h1_bef_port_invalid');
 const u=new URL('postgres://bef_observer@host.docker.internal:'+port+'/bef');u.password=(await readFile('/run/secrets/bef_database_observer_password','utf8')).trim();
 const c=new Client({connectionString:u.href});try{await c.connect();await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const who=(await c.query("SELECT current_user AS role,current_setting('transaction_read_only') AS readonly")).rows[0];need(who.role==='bef_observer'&&who.readonly==='on','ber_h1_bef_observer_invalid');
 const generation=(await c.query('SELECT env_id,generation_id,status,fenced_at,manifest_sha256,payer_address FROM bef_generation WHERE env_id=$1 AND generation_id=$2',[p.environment_id,p.generation_id])).rows;
 const preparations=(await c.query(`SELECT preparation_id,env_id,generation_id,public_pins_sha256,request_sha256,
  manifest_sha256,status,fixture_state,fixture_hash,reset_completed_at,fence_confirmed_at
  FROM bef_preparation WHERE preparation_id=$1`,[p.preparation_id])).rows;
 const payments=(await c.query(`SELECT operation_id,env_id,generation_id,authorization_sha256,network,transaction_hash,
  amount_units::text,token_delta_units::text,payer_balance_before::text,payer_balance_after::text,
  facilitator_balance_before::text,facilitator_balance_after::text,receipt_status,asset_address,payer_address,facilitator_address
  FROM bef_payment WHERE generation_id=$1 ORDER BY operation_id`,[p.generation_id])).rows;
 const operations=targetActionId?(await c.query(`SELECT o.operation_id,o.env_id,o.generation_id,o.participant_id,o.authorization_sha256,o.operation_kind,o.payment_response_mode,o.status,o.transaction_hash,o.receipt_status,
  o.idempotency_key_sha256,o.request_sha256,o.response_sha256,o.selected_offer_id,o.selected_amount_units::text,o.selected_resource_id,o.selected_resource_sha256,
  trim(g.manifest_sha256) AS generation_manifest_sha256,trim(e.manifest_sha256) AS environment_manifest_sha256
  FROM bef_operation o JOIN bef_generation g USING(env_id,generation_id) JOIN bef_environment e USING(env_id)
  WHERE o.env_id=$1 AND o.generation_id=$2 AND o.idempotency_key_sha256=$3`,[p.environment_id,p.generation_id,digest('task-action-'+targetActionId)])).rows:[];
 const selected=operations.length?(await c.query(`SELECT operation_id,env_id,generation_id,action_kind,selected_action_json,transaction_hash,outcome,reason_code,measurement_json
  FROM bef_selected_execution WHERE operation_id=ANY($1::uuid[])`,[operations.map(o=>o.operation_id)])).rows:[];
 const selectedEvents=operations.length?(await c.query(`SELECT operation_id,env_id,generation_id,event_sequence,event_kind,event_json
  FROM bef_selected_execution_event WHERE operation_id=ANY($1::uuid[]) ORDER BY operation_id,event_sequence`,[operations.map(o=>o.operation_id)])).rows:[];
 await c.query('COMMIT');return{identity:who,generation,preparations,payments,operations,selected,selectedEvents};
 }finally{await c.end();}}
async function rpcReceipts(bef){const port=Number(process.env.BEF_LOCAL_RPC_A_HOST_PORT||'18545');const receipts=[];
 const rpc=async(method,params)=>{
  const reply=await fetch('http://host.docker.internal:'+port,{method:'POST',headers:{'content-type':'application/json'},redirect:'error',signal:AbortSignal.timeout(10000),
   body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  const body=await reply.json();need(reply.status===200&&body.jsonrpc==='2.0'&&body.id===1&&!Object.hasOwn(body,'error')&&Object.hasOwn(body,'result'),'ber_h1_chain_observation_unavailable');return body.result;};
 for(const p of bef.payments){need(/^0x[0-9a-f]{64}$/i.test(p.transaction_hash),'ber_h1_payment_hash_missing');receipts.push(await rpc('eth_getTransactionReceipt',[p.transaction_hash]));}
 if(!receipts.length)return{receipts,generationTransfers:null};
 need(receipts.every(r=>r&&/^0x[0-9a-f]+$/i.test(r.blockNumber??'')),'ber_h1_chain_receipt_missing');
 const first=bef.payments[0],topicAddress=a=>'0x'+a.slice(2).toLowerCase().padStart(64,'0');
 const topic='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
 const from=receipts.reduce((min,r)=>BigInt(r.blockNumber)<min?BigInt(r.blockNumber):min,BigInt(receipts[0].blockNumber));
 const latest=await rpc('eth_blockNumber',[]);need(/^0x[0-9a-f]+$/i.test(latest??'')&&BigInt(latest)>=from&&BigInt(latest)-from<=2000n,'ber_h1_chain_log_range_unavailable');
 const filter={address:first.asset_address,fromBlock:'0x'+from.toString(16),toBlock:latest,topics:[topic,topicAddress(first.payer_address),topicAddress(first.facilitator_address)]};
 const logs=await rpc('eth_getLogs',[filter]);need(Array.isArray(logs),'ber_h1_chain_logs_unavailable');return{receipts,generationTransfers:{filter,logs}};}
async function revokeThroughUi(common,run){const path='/api/owner/agents/'+run.agent_id+'/access-revoke';await common.ownerPage.goto('/agents',{waitUntil:'domcontentloaded'});
 const button=common.ownerPage.getByTestId('agent-revoke-'+run.agent_id);await button.waitFor({state:'visible',timeout:15000});
 const response=common.ownerPage.waitForResponse(r=>new URL(r.url()).pathname===path&&r.request().method()==='POST',{timeout:15000});
 common.ownerCapture?.action('click','agent-revoke-'+run.agent_id);await button.click();const actual=await response;const body=await actual.json();
 need(actual.status()===200&&body.access?.status==='revoked','ber_h1_revoke_ui_failed');
 return{httpStatus:actual.status(),path,operationId:actual.request().postDataJSON()?.operationId,accessStatus:body.access.status,cancellationStatus:body.cancellation?.status};}
async function rawEvidence(root,owner){const refs=[];const seen=new Set();for(const row of owner.result.actions){if(row.evidence_path&&row.evidence_hash&&!seen.has(row.evidence_path)){
 seen.add(row.evidence_path);const path=resolve(root,row.evidence_path);need(relative(root,path)&&!relative(root,path).startsWith('..')&&!row.evidence_path.includes('\\'),'ber_h1_evidence_path_invalid');
 const bytes=await readFile(path);need(digest(bytes)===row.evidence_hash,'ber_h1_action_evidence_hash_invalid');refs.push({path:row.evidence_path,sha256:row.evidence_hash});}}
 for(const p of owner.result.preparation){const e=p.fence_evidence?.evidence;if(e&&!seen.has(e.path)){const path=resolve(root,e.path);need(!relative(root,path).startsWith('..')&&HASH.test(e.sha256),'ber_h1_fence_path_invalid');
 const bytes=await readFile(path);need(digest(bytes)===e.sha256,'ber_h1_fence_hash_invalid');refs.push({path:e.path,sha256:e.sha256});seen.add(e.path);}}return refs;}

async function executeCase(common,recoveryProxy,variant,progress){
 const databaseName=common.databaseIsolation.databaseName;
 const pool=new Pool({connectionString:common.observerDatabaseUrl,max:2,application_name:'ber-h1-cutoff-observer'});
 const ownerUrl=new URL(common.databaseUrl);need(ownerUrl.hostname==='postgres'&&ownerUrl.username==='oid_owner'&&ownerUrl.pathname==='/'+databaseName,'ber_h1_fault_database_invalid');
 const control=new Client({connectionString:ownerUrl.href});await control.connect();
 const captureId=randomUUID(),fault={schemaVersion:'ber-h1-cutoff-fault/v1',variant,captureId,targetPaymentOrdinal:3,
  events:[],checks:{},ownerAdmissionCalls:0,target:null,exercised:false,proxyArmed:false};
 let targetCount=0,transaction=false;
 const event=async(stage,details={})=>{fault.events.push({stage,observedAt:new Date().toISOString(),...details});
  if(progress)await progress({component:'ber_h1_cutoff',captureId,variant,stage,...details});};
 const sendOriginal=async send=>{const original=fault.ownerAdmissionCalls++===0;
  if(original)fault.admissionRequestStartedAt=new Date().toISOString();
  const reply=await send();if(original)fault.admissionResponseObservedAt=new Date().toISOString();return reply;};
 const unlock=async()=>{if(transaction){await control.query('COMMIT');transaction=false;}};
 const transport=async meta=>{
  if(meta.taskId!=='H1'||meta.command.kind!=='pay'||++targetCount!==3)return meta.send();
  const initial=await clock(control,meta.runId,meta.taskIndex);need(initial?.task_id==='H1','ber_h1_target_not_h1');
  need(/^[a-z0-9][a-z0-9_-]{0,63}$/.test(initial.environment_id),'ber_h1_environment_route_invalid');
  fault.target={runId:meta.runId,taskIndex:meta.taskIndex,taskId:meta.taskId,operationId:meta.operationId,command:meta.command,
   environmentId:initial.environment_id,payRoute:'/tools/'+initial.environment_id+'/pay',
   initialDeadline:initial.deadline_at,initialClock:initial.observed_at};
  await event('target_third_payment_reached',{runId:meta.runId,taskIndex:meta.taskIndex});
  if(variant==='worker_restart_pending'||variant==='revoked_agent_pending'){
   let paused=false;
   try{
    fault.workerPauseBefore=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
    need(fault.workerPauseBefore.result.run.status==='running'&&
     fault.workerPauseBefore.result.actions.filter(a=>a.action_kind==='pay').length===2&&
     fault.workerPauseBefore.result.actions.every(a=>a.receipt_status==='observed'&&a.outbox_status==='delivered')&&
     fault.workerPauseBefore.result.tasks[0]?.closure_status==='open'&&!fault.workerPauseBefore.result.tasks[0]?.closure_id,
    'ber_h1_worker_pause_requires_resolved_prefix');
    fault.workerPauseReceipt=await common.restartApi({coordinatorEnabled:false});paused=true;
    const afterPause=await clock(control,meta.runId,meta.taskIndex);
    need(stamp(afterPause.deadline_at)===stamp(initial.deadline_at),'ber_h1_deadline_changed_while_paused');
    const left=stamp(afterPause.deadline_at)-stamp(afterPause.observed_at);
    need(left>500,'ber_h1_worker_pause_missed_original_admission_window');
    await sleep(left-200);
    const reply=await sendOriginal(meta.send);fault.admission={httpStatus:reply.status,actionId:reply.payload?.actionId??null,errorCode:reply.payload?.error?.code??null,admitted:reply.payload?.admitted??null,reason:reply.payload?.reason??null,closureId:reply.payload?.closureId??null};
    if(!UUID.test(fault.admission.actionId??'')){await event('worker_paused_target_not_admitted');return reply;}
    fault.pendingCheckpoint=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
    const pending=fault.pendingCheckpoint.result.actions.find(a=>a.id===fault.admission.actionId);
    need(pending?.receipt_status==='pending'&&pending.outbox_status==='pending'&&pending.operation_id===meta.operationId,'ber_h1_paused_original_not_pending');
    fault.exercised=true;await event('original_pending_action_observed_while_worker_paused',{actionId:pending.id});
    const until=Date.now()+15000;let committed;
    do{committed=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
     const task=committed.result.tasks.find(t=>t.task_index===meta.taskIndex);
     if(task?.closure_id&&task.action_cutoff_sequence===pending.action_sequence)break;
     await sleep(100);
    }while(Date.now()<until);
    const task=committed.result.tasks.find(t=>t.task_index===meta.taskIndex);
    need(task?.closure_id&&task.action_cutoff_sequence===pending.action_sequence,'ber_h1_paused_cutoff_not_committed');
    fault.committedCutoffBeforeInterruption=committed;
    await event('original_task_cutoff_committed_while_worker_paused',{closureId:task.closure_id,cutoffSequence:task.action_cutoff_sequence});
    if(variant==='revoked_agent_pending'){fault.revoke=await revokeThroughUi(common,committed.result.run);
     await event('agent_revoked_through_owner_ui',{httpStatus:fault.revoke.httpStatus});}
    fault.restartBefore=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
    fault.restartReceipt=await common.restartApi({coordinatorEnabled:true});paused=false;
    await event('normal_worker_resumed_with_original_pending_cutoff',{runId:meta.runId});return reply;
   }finally{if(paused){fault.pauseCleanupRestartReceipt=await common.restartApi({coordinatorEnabled:true});}}
  }
  const remaining=stamp(initial.deadline_at)-stamp(initial.observed_at);need(remaining>500&&remaining<360000,'ber_h1_original_deadline_window_missed');
  await sleep(remaining+(variant==='after_cutoff_new_denied'?50:variant==='at_cutoff_new_denied'?0:-200));
  if(variant==='at_cutoff_new_denied'||variant==='after_cutoff_new_denied'){
   const until=Date.now()+15000;let boundary;
   do{boundary=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
    const task=boundary.result.tasks.find(t=>t.task_index===meta.taskIndex);
    if(variant==='at_cutoff_new_denied'||task?.closure_id&&task.closure_status==='closed')break;
    await sleep(100);
   }while(Date.now()<until);
   fault.preRequestBoundarySnapshot=boundary;
   const task=boundary.result.tasks.find(t=>t.task_index===meta.taskIndex);
   if(variant==='after_cutoff_new_denied')need(task?.closure_id&&task.closure_status==='closed','ber_h1_committed_after_boundary_not_observed');
   await event('pre_request_boundary_observed',{closureId:task?.closure_id??null,closureStatus:task?.closure_status??null});
  }
  const reply=await sendOriginal(meta.send);fault.admission={httpStatus:reply.status,actionId:reply.payload?.actionId??null,errorCode:reply.payload?.error?.code??null,admitted:reply.payload?.admitted??null,reason:reply.payload?.reason??null,closureId:reply.payload?.closureId??null};
  if(variant==='at_cutoff_new_denied'||variant==='after_cutoff_new_denied'){
   fault.exercised=!fault.admission.actionId;await event('new_admission_after_boundary_observed',{httpStatus:reply.status,actionAdmitted:!!fault.admission.actionId});return reply;
  }
  if(!UUID.test(fault.admission.actionId??'')){await event('pending_lock_not_exercised_no_admission');return reply;}
  await control.query('BEGIN');transaction=true;await control.query("SET LOCAL lock_timeout='100ms'");await control.query("SET LOCAL statement_timeout='10000ms'");
  let locked;
  try{locked=(await control.query(`SELECT a.id,a.operation_id,a.accepted_at,a.payload_hash,a.action_sequence::text,t.deadline_at,
   o.status AS outbox_status,r.receipt_status,clock_timestamp() AS lock_observed_at FROM oid_run_task_action a
   JOIN oid_run_task t ON t.run_id=a.run_id AND t.task_index=a.task_index
   JOIN oid_run_task_action_outbox o ON o.action_id=a.id JOIN oid_run_task_action_receipt r ON r.action_id=a.id
   WHERE a.id=$1 AND a.run_id=$2 AND a.task_index=$3 FOR UPDATE OF o`,[fault.admission.actionId,meta.runId,meta.taskIndex])).rows[0];}
  catch(e){await control.query('ROLLBACK');transaction=false;await event('pending_lock_not_exercised',{reason:e.code==='55P03'?'worker_won_lock_race':'lock_unavailable'});return reply;}
  fault.pendingLock=locked;
  if(!locked||locked.outbox_status!=='pending'||locked.receipt_status!=='pending'||locked.operation_id!==meta.operationId){
   await unlock();await event('pending_lock_not_exercised_wrong_state');return reply;}
  fault.exercised=true;await event('original_pending_outbox_locked',{actionId:locked.id,acceptedAt:locked.accepted_at,deadlineAt:locked.deadline_at});
  if(variant==='tool_reply_lost_after_dispatch'||variant==='worker_restart_delivered'){
   recoveryProxy.arm({path:fault.target.payRoute});fault.proxyArmed=true;await event('upstream_reply_fault_armed_after_original_pending_lock');
  }
  await sleep(stamp(locked.deadline_at)+250-stamp(locked.lock_observed_at));
  if(variant==='admission_reply_lost_before_dispatch'){
   fault.admissionReplyWithheldBeforeDispatch=await ownerSnapshot(pool,databaseName,meta.runId,meta.taskIndex);
   fault.admissionReplyWithheld=true;fault.admissionReplyWithheldAt=new Date().toISOString();
   await event('successful_admission_reply_held_before_dispatch');
  }
  fault.releaseClock=(await control.query('SELECT clock_timestamp() AS released_at')).rows[0];await unlock();
  await event('original_pending_outbox_released');
  if(variant==='before_cutoff_dispatch_after'||variant==='admission_reply_lost_before_dispatch'){
   const duplicate=await sendOriginal(meta.send);fault.duplicate={httpStatus:duplicate.status,actionId:duplicate.payload?.actionId??null,errorCode:duplicate.payload?.error?.code??null};
   await event('late_same_operation_retransmission',{sameAction:duplicate.payload?.actionId===fault.admission.actionId});
  }
  if(variant==='admission_reply_lost_before_dispatch'){
   await event('successful_admission_reply_withheld');
   throw Object.assign(new Error('agent_http_transport_unknown'),{code:'agent_http_transport_unknown'});
  }
  return reply;
 };
 let outcome;
 try{
  const afterDispatch=variant==='tool_reply_lost_after_dispatch'||variant==='worker_restart_delivered';
  const recoveryFault=afterDispatch?{waitTimeoutMs:210000,beforeFirstAction:async()=>{},onInitialUnknown:async current=>{
   const incident=recoveryProxy.snapshot().fault;
   need(current.actionId===fault.admission?.actionId&&incident?.actionId===current.actionId&&incident.path===fault.target?.payRoute&&
    incident.upstreamResponseComplete===true&&incident.upstreamStatus>=200&&incident.upstreamStatus<300&&incident.downstreamResponseDelivered===false,
    'ber_h1_unknown_not_original_third_payment_fault');
   await event('dispatched_payment_reply_unknown',{actionId:current.actionId});
   const until=Date.now()+15000;let committed;
   do{committed=await ownerSnapshot(pool,databaseName,current.runId,0);
    const task=committed.result.tasks[0],action=committed.result.actions.find(a=>a.id===current.actionId);
    if(task?.closure_id&&task.action_cutoff_sequence===action?.action_sequence&&task.closure_status==='unknown'&&action.receipt_status==='unknown')break;
    await sleep(100);
   }while(Date.now()<until);
   const task=committed.result.tasks[0],action=committed.result.actions.find(a=>a.id===current.actionId);
   need(task?.closure_id&&task.action_cutoff_sequence===action?.action_sequence&&task.closure_status==='unknown'&&action.receipt_status==='unknown',
    'ber_h1_reply_loss_cutoff_not_committed_unknown');
   fault.committedCutoffAfterReplyLoss=committed;
   await event('original_unknown_cutoff_committed_after_reply_loss',{closureId:task.closure_id,cutoffSequence:task.action_cutoff_sequence});
   if(variant==='worker_restart_delivered'&&!fault.restartReceipt){fault.restartBefore=await ownerSnapshot(pool,databaseName,current.runId,0);
    fault.restartReceipt=await common.restartApi();await event('worker_restarted_after_committed_payment_reply_loss');}
  }}:undefined;
  outcome=await runGenuineS1OwnerCase({...common.genuineCaptureInput,captureId,mode:'training',taskId:'H1',
   automaticWorkerEvaluation:true,bonusCodeFunding:true,exactQuoteBonusFunding:true,bddProbes:false,primaryClientOnly:false,
   genuineActionTransport:transport,...(recoveryFault?{platformRecoveryFault:recoveryFault}:{})});
 }finally{if(transaction)await control.query('ROLLBACK').catch(()=>{});await control.end();}
 const base='artifacts/runs/ber-h1-cutoff-source/'+common.runId+'/'+captureId;
 const genuineAttempt=await saved(common.repoRoot,base+'/genuine.json',outcome);
 if(!fault.target){const remaining=await ro(pool,databaseName,async c=>(await c.query(`SELECT
  (SELECT count(*)::int FROM oid_benchmark_run WHERE status NOT IN('completed','failed','cancelled','expired')) AS unfinished_runs,
  (SELECT count(*)::int FROM oid_run_execution_slot WHERE released_at IS NULL) AS live_slots,
  (SELECT count(*)::int FROM oid_run_dispatch_claim WHERE status='claimed') AS live_claims,
  (SELECT count(*)::int FROM oid_task_environment_lease WHERE state<>'fenced') AS unfenced_leases`)).rows[0]);
  await pool.end();return{variant,status:'not_exercised',reasonCode:'third_payment_not_reached',genuineAttempt,fault,remaining,proxy:recoveryProxy.snapshot(),
   proxyReusable:remaining.result.unfinished_runs===0&&remaining.result.live_slots===0&&remaining.result.live_claims===0&&remaining.result.unfenced_leases===0};}
 const owner=await ownerSnapshot(pool,databaseName,fault.target.runId,fault.target.taskIndex);await pool.end();
 const target=owner.result.actions.filter(a=>a.operation_id===fault.target.operationId);
 const bef=await befSnapshot(owner,target[0]?.id??fault.admission?.actionId??null);
 const chain=await rpcReceipts(bef),receipts=chain.receipts;
 const evidenceRefs=await rawEvidence(common.repoRoot,owner);
 const proxy=recoveryProxy.snapshot();
 const task=owner.result.tasks.find(t=>t.task_index===fault.target.taskIndex);
 const closure=owner.result.closures.find(c=>c.task_index===fault.target.taskIndex);
 const paymentActions=owner.result.actions.filter(a=>a.action_kind==='pay');
 const debit=owner.result.ledger.filter(e=>e.entry_type==='debit');
 const dispatch=owner.result.events.find(e=>e.event_type==='task.action.dispatch_claimed'&&e.payload_json?.actionId===target[0]?.id);
 const afterReplyLoss=variant==='tool_reply_lost_after_dispatch'||variant==='worker_restart_delivered';
 const isNewDenied=variant==='at_cutoff_new_denied'||variant==='after_cutoff_new_denied';
 const totalRefund=owner.result.ledger.filter(e=>e.entry_type==='refund').reduce((sum,e)=>sum+BigInt(e.available_delta_units??0)+BigInt(e.expired_delta_units??0),0n);
 const targetRequests=(proxy.actionRequests??[]).filter(r=>r.actionId===target[0]?.id);
 const targetSubmissions=proxy.submissions.find(r=>r.actionId===target[0]?.id)?.count??0;
 const challenge=targetRequests[0],settlement=targetRequests[1];
 // AICODE-NOTE: Event created_at is transaction-start time; a claim can wait on
 // the fault gate. The outbox clock_timestamp and real HTTP send prove dispatch.
 const dispatchedAfterOriginalCutoff=!!dispatch&&!!target[0]&&stamp(target[0].delivered_at)>=stamp(fault.target.initialDeadline)&&
  stamp(challenge?.requestStartedAt)>=stamp(target[0].delivered_at);
 const oneEconomicWire=proxy.omittedActionRequests===0&&targetSubmissions===targetRequests.length&&
  (bef.operations.length===0?targetRequests.length===0:targetRequests.length===2&&
   challenge.ordinal===1&&challenge.method==='POST'&&challenge.path===fault.target.payRoute&&challenge.paymentProofPresent===false&&
   challenge.upstreamStatus===402&&challenge.upstreamResponseComplete===true&&challenge.downstreamResponseFinished===true&&
   settlement.ordinal===2&&settlement.method==='POST'&&settlement.path===fault.target.payRoute&&settlement.paymentProofPresent===true&&
   settlement.upstreamStatus>=200&&settlement.upstreamStatus<300&&settlement.upstreamResponseComplete===true&&
   settlement.upstreamResponseSha256===bef.operations[0].response_sha256&&
   targetRequests.filter(r=>r.paymentProofPresent===true).length===1);
 const authoritativeRefund=owner.result.refunds.length===0?totalRefund===0n:owner.result.refunds.length===1&&
  totalRefund===BigInt(owner.result.refunds[0].bonus_refunded_units)&&owner.result.recovery.some(r=>r.status==='refunded'&&r.latest_evidence_hash===owner.result.refunds[0].evidence_hash);
 const authorizedClockExcluded=owner.result.events.filter(e=>e.event_type==='run.platform_recovery_clock_excluded'&&e.payload_json?.actionId===target[0]?.id)
  .reduce((sum,e)=>sum+Number(e.payload_json.clockExcludedMs),0);
 const checks={fault_exercised:fault.exercised,actual_h1_third_shape:fault.target.taskId==='H1'&&fault.target.command.kind==='pay',
  source_authorized_task_clock:Number.isSafeInteger(authorizedClockExcluded)&&authorizedClockExcluded>=0&&
   stamp(task.deadline_at)===stamp(fault.target.initialDeadline)+authorizedClockExcluded,
  one_original_admission:isNewDenied?target.length===0:target.length===1,
  accepted_before_original_cutoff:isNewDenied?true:target.length===1&&stamp(target[0].accepted_at)<stamp(fault.target.initialDeadline),
  exact_task_cutoff:!!task?.closure_id&&task.reconciled_action_sequence===task.action_cutoff_sequence,
  no_silent_pending:owner.result.actions.every(a=>a.receipt_status!=='pending'),
  no_extra_payment:bef.payments.length<=paymentActions.length&&new Set(bef.payments.map(p=>p.operation_id)).size===bef.payments.length&&
   bef.payments.every(p=>p.receipt_status==='success'&&p.amount_units===p.token_delta_units)&&bef.operations.length<=1,
  chain_receipts_match:receipts.length===bef.payments.length&&receipts.every((r,i)=>r.status==='0x1'&&r.transactionHash===bef.payments[i].transaction_hash),
  exact_chain_transfer_count:chain.generationTransfers?.logs.length===bef.payments.length&&new Set(chain.generationTransfers.logs.map(l=>l.transactionHash)).size===bef.payments.length&&
   chain.generationTransfers.logs.every(l=>{const p=bef.payments.find(p=>p.transaction_hash===l.transactionHash),f=chain.generationTransfers.filter;
    return p&&l.address?.toLowerCase()===f.address.toLowerCase()&&f.topics.every((topic,i)=>l.topics?.[i]?.toLowerCase()===topic.toLowerCase())&&
     /^0x[0-9a-f]+$/i.test(l.data??'')&&BigInt(l.data)===BigInt(p.amount_units);}),
  target_signed_economic_wire_at_most_once:oneEconomicWire,
  once_bonus_debit:debit.length===1&&debit[0].source_kind==='tester_bonus'&&debit[0].amount_units===owner.result.run.quote_price_units,
  no_cash:owner.result.ledger.every(e=>e.source_kind==='tester_bonus'),
  source_linked_refund_only:authoritativeRefund,
  exact_owner_fence:owner.result.preparation.length===1&&owner.result.preparation[0].lease_state==='fenced'&&owner.result.preparation[0].observation_status==='fenced',
  exact_bef_fence:bef.generation.length===1&&bef.generation[0].status==='fenced'&&bef.preparations.length===1&&bef.preparations[0].status==='fenced',
  terminal_resource_release:['completed','failed','cancelled'].includes(owner.result.run.status)&&owner.result.slots.every(s=>s.released_at!==null)&&owner.result.claim.length===1&&owner.result.claim[0].status==='released',
  bounded_original_recovery:owner.result.recovery.every(r=>stamp(r.deadline_at)-stamp(r.started_at)===180000&&r.clock_excluded_ms<=180000)};
 if(isNewDenied){checks.new_admission_rejected=!fault.admission.actionId&&target.length===0&&paymentActions.length===2&&bef.payments.length===2;
  checks.original_deadline_unchanged=stamp(task.deadline_at)===stamp(fault.target.initialDeadline);
  const before=fault.preRequestBoundarySnapshot?.result.tasks.find(t=>t.task_index===fault.target.taskIndex);
  checks.boundary_clock=variant==='at_cutoff_new_denied'?!before?.closure_id&&before?.closure_status==='open'&&
   fault.admission.httpStatus===200&&fault.admission.admitted===false&&fault.admission.reason==='task_deadline'&&
   fault.admission.closureId===closure?.id&&stamp(closure?.requested_at)>=stamp(task.deadline_at):
   before?.closure_id===closure?.id&&before?.closure_status==='closed'&&fault.admission.httpStatus===409&&
   stamp(closure?.requested_at)>=stamp(task.deadline_at);}
 if(['before_cutoff_dispatch_after','admission_reply_lost_before_dispatch'].includes(variant)){
  checks.accepted_before_cutoff=target.length===1&&stamp(target[0].accepted_at)<stamp(fault.target.initialDeadline);
  checks.dispatched_after_cutoff=dispatchedAfterOriginalCutoff;
  checks.original_outbox_locked_through_cutoff=!!fault.pendingLock&&stamp(fault.releaseClock?.released_at)>=stamp(fault.target.initialDeadline);
  checks.late_duplicate_same_action=fault.duplicate?.actionId===target[0]?.id&&target.length===1;
  checks.third_effect_exact=bef.payments.length===3&&bef.operations.length===1;
 }
 if(variant==='admission_reply_lost_before_dispatch')checks.admission_reply_lost=fault.admissionReplyWithheld===true&&outcome.participantActions.some(a=>a.operationId===fault.target.operationId&&a.transportUnknown===true);
 if(variant==='worker_restart_pending'||variant==='worker_restart_delivered')checks.actual_worker_restart=fault.restartReceipt?.previousPid!==fault.restartReceipt?.currentPid&&fault.restartReceipt?.healthHttpStatus===200;
 if(variant==='worker_restart_pending'||variant==='revoked_agent_pending')checks.worker_pause_retained_original_pending_cutoff=
  fault.workerPauseReceipt?.coordinatorEnabled===false&&fault.restartReceipt?.coordinatorEnabled===true&&
  fault.pendingCheckpoint?.result.actions.some(a=>a.id===target[0]?.id&&a.receipt_status==='pending'&&a.outbox_status==='pending')&&
  fault.committedCutoffBeforeInterruption?.result.tasks[0]?.action_cutoff_sequence===target[0]?.action_sequence;
 if(variant==='worker_restart_pending')checks.pending_restart_retained_identity=!!fault.committedCutoffBeforeInterruption&&
  fault.pendingCheckpoint?.result.actions.some(a=>a.id===target[0]?.id&&a.receipt_status==='pending'&&a.outbox_status==='pending')&&
  fault.workerPauseReceipt?.coordinatorEnabled===false&&fault.restartReceipt?.coordinatorEnabled===true&&
  target.length===1&&['observed','unknown','rejected_before_execution'].includes(target[0].receipt_status);
 if(variant==='revoked_agent_pending')checks.revocation_denies_third_effect=!!fault.committedCutoffBeforeInterruption&&!!fault.revoke&&owner.result.currentAccess.access_revoked_at!==null&&bef.operations.length===0&&bef.payments.length===2&&target[0]?.receipt_status==='rejected_before_execution';
 if(afterReplyLoss){checks.actual_committed_reply_withheld=proxy.fault?.actionId===target[0]?.id&&proxy.fault?.upstreamResponseComplete===true&&proxy.fault?.downstreamResponseDelivered===false;
  checks.original_outbox_held_until_deadline=!!fault.pendingLock&&stamp(fault.releaseClock?.released_at)>=stamp(fault.target.initialDeadline)&&
   dispatchedAfterOriginalCutoff;
  const unknownCutoff=fault.committedCutoffAfterReplyLoss?.result;
  checks.actual_unknown_cutoff_before_restart=unknownCutoff?.tasks[0]?.closure_status==='unknown'&&
   unknownCutoff.actions.some(a=>a.id===target[0]?.id&&a.receipt_status==='unknown')&&unknownCutoff.evaluations.length===0;
  checks.one_target_signed_economic_wire=oneEconomicWire&&!!settlement&&!!proxy.fault&&settlement.upstreamResponseSha256===proxy.fault.upstreamResponseSha256&&
   settlement.downstreamResponseFinished===false;
  checks.original_effect_retained=bef.operations.length===1&&bef.payments.length===3;}
 const onlyAtMiss=variant==='at_cutoff_new_denied'&&Object.entries(checks).every(([key,value])=>key==='boundary_clock'||value);
 const result={schemaVersion:'ber-h1-cutoff-case/v1',variant,captureId,runId:fault.target.runId,taskIndex:fault.target.taskIndex,
  status:Object.values(checks).every(Boolean)?'verified':onlyAtMiss?'not_exercised':'failed',checks,fault,genuineAttempt,owner,bef,chain,evidenceRefs,proxy};
 const reference=await saved(common.repoRoot,base+'/case.json',result);
 if(fault.proxyArmed&&proxy.fault)recoveryProxy.resetAfterIncident();
 return{...result,reference,proxyReusable:(!fault.proxyArmed||!!proxy.fault)&&checks.terminal_resource_release&&
  checks.exact_owner_fence&&checks.exact_bef_fence};
}

/** Actual private fault injection; no deadline rewrite, actor credential exposure or economic replay. */
export async function runBerH1CutoffCases({commonCapture,recoveryFaultProxy,progress}){
 const common=commonCapture;need(/^oid_acceptance_[a-f0-9]{32}$/.test(common.databaseIsolation?.databaseName??''),'ber_h1_requires_disposable_database');
 const cases=[];let transportDiagnostics;
 try{for(const variant of selectedVariants()){
  const entry=await executeCase(common,recoveryFaultProxy,variant,progress);cases.push(entry);
  if(progress)await progress({component:'ber_h1_cutoff',variant,status:entry.status,reference:entry.reference??null});
  if(entry.proxyReusable===false)break;
 }}finally{transportDiagnostics=await saved(common.repoRoot,'artifacts/runs/ber-h1-cutoff-source/'+common.runId+'/transport-final.json',{
  schemaVersion:'ber-h1-cutoff-final-transport/v1',captureId:common.runId,cases:cases.map(c=>({variant:c.variant,status:c.status,reference:c.reference??null})),
  proxy:recoveryFaultProxy.snapshot()});}
 const missing=VARIANTS.filter(v=>!cases.some(c=>c.variant===v&&c.status==='verified'));
 return{schemaVersion:'ber-h1-cutoff-matrix/v1',status:missing.length?'observed_partial':'verified',boundary:'actual_owner_browser_admission_worker_bef_postgres_local_rpc',
  cases,transportDiagnostics,missingVariants:missing,claims:{newEconomicOperationRetry:false,deadlineRewritten:false,nativeClientAcceptance:false,completeBer003:missing.length===0,targetHostAcceptance:false}};
}
