/** Acceptance-only interruption at an actually blocked first grade or successor dispatch. */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
const{Client,Pool}=createRequire('/workspace/packages/owner-acceptance/package.json')('pg');
const canon=v=>Array.isArray(v)?v.map(canon):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,canon(x)])):v;
const sha=b=>createHash('sha256').update(b).digest('hex'),hash=v=>sha(JSON.stringify(canon(v)));
const delay=ms=>new Promise(done=>setTimeout(done,ms));
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const TABLES={evaluation:'oid_run_task_evaluation',successor_dispatch:'oid_task_preparation_dispatch'};

async function state(pool,runId,controllerPid,table,advisoryKeys){
 const client=await pool.connect();try{await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const identity=(await client.query("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only,clock_timestamp() observed_at")).rows[0];
  assert.equal(identity.role,'oid_observer');assert.equal(identity.read_only,'on');assert.match(identity.database_name,/^oid_acceptance_[a-f0-9]{32}$/);
  const q=async(sql,args=[runId])=>(await client.query(sql,args)).rows.map(x=>x.row);
  const result={};result.run=await q('SELECT to_jsonb(t) row FROM oid_benchmark_run t WHERE id=$1');
  assert.equal(result.run.length,1);assert.equal(result.run[0].mode,'ranked');assert.equal(result.run[0].task_ids.length,12);
  result.tasks=await q("SELECT to_jsonb(t)-'snapshot_json' row FROM oid_run_task t WHERE run_id=$1 AND task_index IN(8,9) ORDER BY task_index");
  for(const[key,t]of Object.entries({evaluations:'oid_run_task_evaluation',bundles:'oid_run_task_observation_bundle',actions:'oid_run_task_action',bindings:'oid_task_execution_binding',preparations:'oid_task_preparation_intent'}))result[key]=await q(`SELECT to_jsonb(t) row FROM ${t} t WHERE run_id=$1 AND task_index IN(8,9)`);
  result.receipts=await q('SELECT to_jsonb(t) row FROM oid_run_task_action_receipt t WHERE action_id IN(SELECT id FROM oid_run_task_action WHERE run_id=$1 AND task_index=8)');
  result.leases=await q('SELECT to_jsonb(t) row FROM oid_task_environment_lease t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1 AND task_index IN(8,9))');
  result.dispatch=await q('SELECT to_jsonb(t) row FROM oid_task_preparation_dispatch t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1 AND task_index IN(8,9))');
  result.generations=await q('SELECT to_jsonb(t) row FROM oid_task_preparation_generation t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1 AND task_index IN(8,9))');
  result.observations=await q(`SELECT to_jsonb(o) row FROM oid_task_preparation_intent i JOIN LATERAL
   (SELECT * FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1) o ON true
   WHERE i.run_id=$1 AND i.task_index IN(8,9)`);
  result.events=await q('SELECT to_jsonb(t) row FROM oid_run_event t WHERE run_id=$1 ORDER BY sequence');
  result.claims=await q('SELECT to_jsonb(t) row FROM oid_run_dispatch_claim t WHERE run_id=$1');
  result.ledger=await q('SELECT to_jsonb(t) row FROM oid_ledger_entry t WHERE operation_id=$1 OR left(operation_id,length($2))=$2',['rundeb_'+runId.replaceAll('-',''),'runref_'+runId.replaceAll('-','')+'_']);
  const locks=advisoryKeys?(await client.query(`SELECT pid,locktype,mode,granted,classid::text,objid::text,objsubid,pg_blocking_pids(pid) blocking_pids FROM pg_locks
    WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::oid AND objid=$2::oid AND objsubid=2
    AND (pid=$3 OR $3::int=ANY(pg_blocking_pids(pid))) ORDER BY pid,mode`,[...advisoryKeys,controllerPid])).rows:(await client.query(`SELECT pid,locktype,mode,granted,pg_blocking_pids(pid) blocking_pids FROM pg_locks
    WHERE locktype='relation' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND relation=to_regclass($1)
    AND (pid=$2 OR $2::int=ANY(pg_blocking_pids(pid))) ORDER BY pid,mode`,[table,controllerPid])).rows;
  await client.query('COMMIT');return{identity,result,locks,controllerPid,table,advisoryKeys:advisoryKeys??null};
 }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}
const task=(s,index)=>s.result.tasks.find(t=>t.task_index===index);
const prep=(s,index)=>s.result.preparations.find(p=>p.task_index===index);
const evaluation=s=>s.result.evaluations.find(e=>e.task_index===8);
const h1Stable=s=>({actions:s.result.actions.filter(a=>a.task_index===8).sort((a,b)=>a.id<b.id?-1:1),receipts:[...s.result.receipts].sort((a,b)=>a.action_id<b.action_id?-1:1),ledger:[...s.result.ledger].sort((a,b)=>a.id<b.id?-1:1)});
const waiting=s=>s.locks.find(l=>l.pid!==s.controllerPid&&l.mode===(s.advisoryKeys?'ExclusiveLock':'RowExclusiveLock')&&l.granted===false&&l.blocking_pids.includes(s.controllerPid));
async function until(read,predicate,timeout,reason){const end=Date.now()+timeout;let last;do{last=await read();if(predicate(last))return last;await delay(250);}while(Date.now()<end);throw Object.assign(Error(reason),{code:reason,lastObservation:last});}

export async function runBerPendingTransitionInterruption({commonCapture,runId,phase,releaseReceiptFault}){
 assert.ok(UUID.test(runId));assert.ok(Object.hasOwn(TABLES,phase));assert.equal(typeof releaseReceiptFault,'function');
 const ownerUrl=new URL(commonCapture.databaseUrl),observerUrl=new URL(commonCapture.observerDatabaseUrl);
 assert.equal(ownerUrl.hostname,'postgres');assert.equal(observerUrl.hostname,'postgres');assert.equal(ownerUrl.username,'oid_owner');assert.equal(observerUrl.username,'oid_observer');
 assert.match(ownerUrl.pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);assert.equal(ownerUrl.pathname,observerUrl.pathname);
 assert.equal(typeof commonCapture.stopApi,'function');assert.equal(typeof commonCapture.restartApi,'function');
 const root=commonCapture.repoRoot,id=randomUUID(),directory=resolve(root,'artifacts/runs/ber-pending-transition-interruption',id);
 await mkdir(directory,{recursive:true,mode:0o700});
 const sourcePaths=['tools/ber_pending_transition_interruption.mjs','packages/owner-identity/src/bef-task-coordinator.ts','packages/owner-identity/src/task-preparation.ts','packages/owner-identity/src/task-result-service.ts','packages/owner-identity/src/task-run-completion.ts',
  'packages/owner-identity/dist/bef-task-coordinator.js','packages/owner-identity/dist/task-preparation.js','packages/owner-identity/dist/task-result-service.js','packages/owner-identity/dist/task-run-completion.js'];
 const sourceHashes=async()=>Object.fromEntries(await Promise.all(sourcePaths.map(async p=>[p,sha(await readFile(resolve(root,p)))])));
 const capture={schemaVersion:'ber-pending-transition-interruption/v1',boundary:'actual_blocked_postgres_worker_transaction_stop_restart_without_economic_replay',captureId:id,
  runId,phase,databaseName:ownerUrl.pathname.slice(1),sourceBefore:await sourceHashes(),checkpoints:{},status:'running',fullScenarioAcceptance:false};
 const controller=new Client({connectionString:commonCapture.databaseUrl}),observer=new Pool({connectionString:commonCapture.observerDatabaseUrl,max:1});
 let held=false,stopped=false,controllerPid,triggerCreated=false,functionCreated=false;
 const suffix=id.replaceAll('-',''),functionName='ber_gate_'+suffix,triggerName='ber_gate_dispatch_'+suffix;
 assert.match(functionName,/^ber_gate_[a-f0-9]{32}$/);assert.match(triggerName,/^ber_gate_dispatch_[a-f0-9]{32}$/);
 const advisoryKeys=phase==='successor_dispatch'?[174004007,1+(Number.parseInt(suffix.slice(0,8),16)%2147483000)]:null;
 const dropOwnGate=async()=>{
  if(held){if(advisoryKeys)await controller.query('SELECT pg_advisory_unlock($1,$2)',advisoryKeys);else await controller.query('ROLLBACK');held=false;}
  if(triggerCreated){await controller.query(`DROP TRIGGER "${triggerName}" ON oid_task_preparation_dispatch`);triggerCreated=false;}
  if(functionCreated){await controller.query(`DROP FUNCTION "${functionName}"()`);functionCreated=false;}
  if(advisoryKeys)capture.gateCleanup=(await controller.query(`SELECT
   (SELECT count(*)::int FROM pg_trigger WHERE tgname=$1) trigger_count,
   (SELECT count(*)::int FROM pg_proc WHERE proname=$2) function_count`,[triggerName,functionName])).rows[0];
 };
 const save=async(name,value)=>{const path=resolve(directory,name+'.json'),bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');await writeFile(path,bytes,{flag:'wx',mode:0o600});return{path:relative(root,path).split('\\').join('/'),sha256:sha(bytes)};};
 try{
  await controller.connect();await controller.query("SET lock_timeout='5s'");
  controllerPid=(await controller.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  if(advisoryKeys){
   await controller.query('SELECT pg_advisory_lock($1,$2)',advisoryKeys);held=true;
   const functionSql=`CREATE FUNCTION "${functionName}"() RETURNS trigger LANGUAGE plpgsql AS $ber_gate$ BEGIN
    IF EXISTS(SELECT 1 FROM oid_task_preparation_intent WHERE preparation_id=NEW.preparation_id AND run_id='${runId}'::uuid AND task_index=9) THEN
      PERFORM pg_advisory_xact_lock(${advisoryKeys[0]},${advisoryKeys[1]}); END IF; RETURN NEW; END; $ber_gate$`;
   const triggerSql=`CREATE TRIGGER "${triggerName}" BEFORE INSERT ON oid_task_preparation_dispatch FOR EACH ROW EXECUTE FUNCTION "${functionName}"()`;
   await controller.query(functionSql);functionCreated=true;await controller.query(triggerSql);triggerCreated=true;
   const installed=(await controller.query(`SELECT pg_get_triggerdef(t.oid) trigger_definition,pg_get_functiondef(p.oid) function_definition
    FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgname=$1 AND p.proname=$2`,[triggerName,functionName])).rows;
   assert.equal(installed.length,1);capture.privateFaultGate={kind:'run_scoped_acceptance_only_before_dispatch_insert_advisory_trigger',
    functionName,triggerName,advisoryKeys,declaredDDL:[functionSql,triggerSql],declaredDdlSha256:hash([functionSql,triggerSql]),installed};
  }else{await controller.query('BEGIN');await controller.query(`LOCK TABLE ${TABLES[phase]} IN SHARE MODE`);held=true;}
  const read=()=>state(observer,runId,controllerPid,TABLES[phase],advisoryKeys);
  const armed=await read();assert.equal(armed.result.run[0].status,'running');assert.equal(task(armed,8).task_id,'H1');assert.equal(task(armed,8).closure_status,'closed');
  assert.equal(evaluation(armed),undefined);assert.equal(prep(armed,9),undefined);
  capture.checkpoints.armed=await save('armed',armed);
  await releaseReceiptFault();
  const blocked=await until(read,s=>{
   if(!waiting(s)||s.result.run[0].status!=='running')return false;
   if(phase==='evaluation')return s.result.bundles.some(b=>b.task_index===8)&&!evaluation(s);
   const p=prep(s,9),h1=prep(s,8);return evaluation(s)&&['completed','failed'].includes(task(s,8).status)&&p&&
    s.result.leases.some(l=>l.preparation_id===h1.preparation_id&&l.state==='fenced')&&
    !s.result.dispatch.some(d=>d.preparation_id===p.preparation_id)&&!s.result.generations.some(g=>g.preparation_id===p.preparation_id)&&!s.result.bindings.some(b=>b.task_index===9);
  },45000,'BER_TRANSITION_NOT_ACTUALLY_BLOCKED');
  assert.deepEqual(h1Stable(blocked),h1Stable(armed));capture.checkpoints.beforeCrash=await save('before-crash',blocked);
  capture.blockedPid=waiting(blocked).pid;
  capture.stopReceipt=await commonCapture.stopApi();stopped=true;
  assert.equal(capture.stopReceipt?.schemaVersion,'beta-local-api-stop-receipt/v1');
  assert.ok(capture.stopReceipt.exitCode!==null||capture.stopReceipt.signal!==null,'API child exit not observed');
  let health;try{health=await fetch(new URL('/healthz',commonCapture.apiOrigin),{signal:AbortSignal.timeout(2000)});}catch{}
  capture.apiUnavailableAfterStop=!health?.ok;assert.equal(capture.apiUnavailableAfterStop,true);
  const afterStop=await until(read,s=>!s.locks.some(l=>l.pid===capture.blockedPid),10000,'BER_STOP_DID_NOT_ROLL_BACK_BLOCKED_TRANSACTION');
  assert.deepEqual(h1Stable(afterStop),h1Stable(blocked));
  if(phase==='evaluation')assert.equal(evaluation(afterStop),undefined);
  else{assert.deepEqual(prep(afterStop,9),prep(blocked,9));assert.equal(afterStop.result.dispatch.some(d=>d.preparation_id===prep(blocked,9).preparation_id),false);}
  capture.checkpoints.afterStop=await save('after-stop',afterStop);
  await dropOwnGate();
  capture.restart=await commonCapture.restartApi();stopped=false;
  const resumed=await until(read,s=>{
   if(s.result.run[0].status!=='running'||!evaluation(s)||!['completed','failed'].includes(task(s,8).status))return false;
   if(phase==='evaluation')return true;
   const p=prep(s,9);return p&&task(s,9).status==='active'&&s.result.bindings.some(b=>b.task_index===9)&&
    s.result.dispatch.some(d=>d.preparation_id===p.preparation_id&&d.state==='completed')&&
    s.result.observations.some(o=>o.preparation_id===p.preparation_id&&o.status==='ready');
  },90000,'BER_PENDING_TRANSITION_DID_NOT_RESUME');
  assert.deepEqual(h1Stable(resumed),h1Stable(armed));
  assert.equal(resumed.result.evaluations.filter(e=>e.task_index===8).length,1);
  assert.equal(evaluation(resumed).closure_id,task(armed,8).closure_id);assert.equal(task(resumed,8).closed_at,task(armed,8).closed_at);
  if(phase==='successor_dispatch'){
   assert.deepEqual(prep(resumed,9),prep(blocked,9));
   assert.equal(resumed.result.dispatch.filter(d=>d.preparation_id===prep(blocked,9).preparation_id).length,1);
   assert.equal(resumed.result.events.filter(e=>e.event_type==='task.activated'&&e.payload_json.toTaskIndex===9).length,1);
  }
  capture.checkpoints.resumed=await save('resumed',resumed);capture.status='verified_subset';
 }catch(error){capture.status='failed';capture.failureCode=/^[A-Z0-9_]{1,100}$/.test(error.code??'')?error.code:'BER_PENDING_TRANSITION_PROBE_FAILED';
  if(error.lastObservation)capture.failureObservation=await save('failure-observation',error.lastObservation);}
 finally{await dropOwnGate().catch(()=>{capture.gateCleanupFailure=true;capture.status='failed';});await controller.end();await observer.end();if(stopped)await commonCapture.restartApi().catch(()=>{});}
 capture.sourceAfter=await sourceHashes();if(hash(capture.sourceBefore)!==hash(capture.sourceAfter)){capture.status='failed';capture.failureCode='BER_PENDING_TRANSITION_SOURCE_CHANGED';}
 const{assertSecretFree}=await import('../packages/owner-acceptance/src/evidence.mjs');assertSecretFree(capture,'ber-pending-transition');
 const evidence=await save('capture',capture);return{status:capture.status,evidence,phase,scope:'one_pending_worker_transition_not_full_BER007'};
}
