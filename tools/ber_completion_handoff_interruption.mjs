/** Acceptance-only first owed Ranked handoff interruption; never targets retained databases. */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
const{Client,Pool}=createRequire('/workspace/packages/owner-acceptance/package.json')('pg');
const canon=v=>Array.isArray(v)?v.map(canon):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,canon(x)])):v;
const sha=b=>createHash('sha256').update(b).digest('hex'),hash=v=>sha(JSON.stringify(canon(v)));
const delay=ms=>new Promise(done=>setTimeout(done,ms));
const TASKS=['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'];
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function isBerUncommittedRankedHandoff(state,runId,admissionVersions=null){
 const rows=state?.rows,run=rows?.run?.length===1?rows.run[0]:null,version=rows?.versions?.length===1?rows.versions[0]:null,snapshot=version?.snapshot_json;
 if(!run||!version||!snapshot||run.id!==runId||run.mode!=='ranked'||version.run_id!==runId||version.owner_id!==run.owner_id||version.agent_id!==run.agent_id||
  snapshot.schemaVersion!=='ranked-agent-version-snapshot/v1'||snapshot.runId!==runId||snapshot.ownerId!==run.owner_id||snapshot.agentId!==run.agent_id||
  hash(snapshot)!==version.snapshot_hash||!Number.isFinite(Date.parse(version.created_at))||!Number.isFinite(Date.parse(run.started_at))||Date.parse(version.created_at)>Date.parse(run.started_at))return false;
 // AICODE-NOTE: admission already commits version1; only handoff/result are first owed completion writes.
 return Array.isArray(rows.handoffs)&&rows.handoffs.length===0&&Array.isArray(rows.results)&&rows.results.length===0&&
  (admissionVersions===null||hash(rows.versions)===hash(admissionVersions));
}

export async function armBerCompletionHandoffInterruption({commonCapture,runId}){
 assert.match(runId,UUID);
 const ownerUrl=new URL(commonCapture.databaseUrl),observerUrl=new URL(commonCapture.observerDatabaseUrl);
 assert.equal(ownerUrl.hostname,'postgres');assert.equal(observerUrl.hostname,'postgres');assert.equal(ownerUrl.username,'oid_owner');assert.equal(observerUrl.username,'oid_observer');
 assert.match(ownerUrl.pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);assert.equal(ownerUrl.pathname,observerUrl.pathname);
 assert.equal(typeof commonCapture.stopApi,'function');assert.equal(typeof commonCapture.restartApi,'function');
 const root=commonCapture.repoRoot,id=randomUUID(),directory=resolve(root,'artifacts/runs/ber-completion-handoff-interruption',id);
 await mkdir(directory,{recursive:true,mode:0o700});
 const save=async(name,value)=>{const{assertSecretFree}=await import('../packages/owner-acceptance/src/evidence.mjs');assertSecretFree(value,'ber-completion-handoff');
  const path=resolve(directory,name+'.json'),bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');await writeFile(path,bytes,{flag:'wx',mode:0o600});return{path:relative(root,path).split('\\').join('/'),sha256:sha(bytes)};};
 const sourcePaths=['tools/ber_completion_handoff_interruption.mjs',...['bef-task-coordinator','task-run-completion','task-ranked-handoff','task-ranked-aggregate','task-result-service','task-preparation'].flatMap(p=>['packages/owner-identity/src/'+p+'.ts','packages/owner-identity/dist/'+p+'.js'])];
 const sources=async()=>Object.fromEntries(await Promise.all(sourcePaths.map(async p=>[p,sha(await readFile(resolve(root,p)))])));
 const capture={schemaVersion:'ber-completion-handoff-interruption/v1',captureId:id,runId,databaseName:ownerUrl.pathname.slice(1),
  boundary:'actual_first_owed_ranked_handoff_transaction_process_crash_postgres_rollback_normal_restart',sourceBefore:await sources(),checkpoints:{},status:'armed'};
 const controller=new Client({connectionString:commonCapture.databaseUrl}),observer=new Pool({connectionString:commonCapture.observerDatabaseUrl,max:1});
 let controllerPid,held=false,stopped=false,closed=false,admissionVersions;
 const read=async()=>{const c=await observer.connect();try{await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const identity=(await c.query("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only,clock_timestamp() observed_at")).rows[0];
  assert.equal(identity.role,'oid_observer');assert.equal(identity.read_only,'on');assert.equal(identity.database_name,capture.databaseName);
  const q=async(sql,args=[runId])=>(await c.query(sql,args)).rows.map(x=>x.row),rows={};
  rows.run=await q('SELECT to_jsonb(t) row FROM oid_benchmark_run t WHERE id=$1');
  rows.tasks=await q("SELECT to_jsonb(t)-'snapshot_json' row FROM oid_run_task t WHERE run_id=$1 ORDER BY task_index");
  for(const[key,t]of Object.entries({evaluations:'oid_run_task_evaluation',bundles:'oid_run_task_observation_bundle',actions:'oid_run_task_action',bindings:'oid_task_execution_binding',preparations:'oid_task_preparation_intent',handoffs:'oid_ranked_run_handoff',results:'oid_ranked_verified_result',versions:'oid_ranked_run_version_snapshot',claims:'oid_run_dispatch_claim',slots:'oid_run_execution_slot'}))rows[key]=await q(`SELECT to_jsonb(t) row FROM ${t} t WHERE run_id=$1`);
  rows.receipts=await q('SELECT to_jsonb(t) row FROM oid_run_task_action_receipt t WHERE action_id IN(SELECT id FROM oid_run_task_action WHERE run_id=$1)');
  rows.leases=await q('SELECT to_jsonb(t) row FROM oid_task_environment_lease t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1)');
  rows.events=await q('SELECT to_jsonb(t) row FROM oid_run_event t WHERE run_id=$1 ORDER BY sequence');
  rows.ledger=await q('SELECT to_jsonb(t) row FROM oid_ledger_entry t WHERE operation_id=$1 OR left(operation_id,length($2))=$2',['rundeb_'+runId.replaceAll('-',''),'runref_'+runId.replaceAll('-','')+'_']);
  const locks=(await c.query("SELECT pid,mode,granted,pg_blocking_pids(pid) blocking_pids FROM pg_locks WHERE locktype='relation' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND relation='public.oid_ranked_run_handoff'::regclass AND (pid=$1 OR $1::int=ANY(pg_blocking_pids(pid))) ORDER BY pid,mode",[controllerPid])).rows;
  await c.query('COMMIT');return{identity,rows,locks,controllerPid};
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}};
 const wait=async(predicate,ms,code)=>{const deadline=Date.now()+ms;let last;do{last=await read();if(predicate(last))return last;await delay(100);}while(Date.now()<deadline);throw Object.assign(Error(code),{code,lastObservation:last});};
 const unchanged=state=>Object.fromEntries(['evaluations','actions','receipts','ledger','bindings','preparations','leases','bundles','versions'].map(k=>[k,[...state.rows[k]].sort((a,b)=>JSON.stringify(canon(a))<JSON.stringify(canon(b))?-1:1)]));
 const terminalTasks=(s,completed=false)=>s.rows.tasks.length===12&&s.rows.evaluations.length===12&&s.rows.evaluations.every(e=>e.result_json.status==='known')&&
  s.rows.tasks.every(t=>(t.task_index===11&&!completed?t.status==='active'&&t.finished_at===null:['completed','failed'].includes(t.status))&&t.closure_status==='closed')&&
  s.rows.leases.length===12&&s.rows.leases.every(l=>l.state==='fenced'&&l.fence_evidence?.confirmed===true);
 const absent=s=>isBerUncommittedRankedHandoff(s,runId,admissionVersions??null);
 const release=async()=>{if(held){await controller.query('ROLLBACK');held=false;}};
 try{await controller.connect();controllerPid=(await controller.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  await controller.query('BEGIN');await controller.query("SET LOCAL lock_timeout='5s'");await controller.query('LOCK TABLE oid_ranked_run_handoff IN SHARE MODE');held=true;
  const armed=await read();
  capture.checkpoints.armed=await save('armed-before-final-task',armed);
  assert.equal(armed.rows.run.length,1);assert.equal(armed.rows.run[0].status,'running');assert.equal(armed.rows.run[0].mode,'ranked');assert.deepEqual(armed.rows.run[0].task_ids,TASKS);assert.ok(absent(armed));
  admissionVersions=structuredClone(armed.rows.versions);
 }catch(error){
  try{capture.status='failed';capture.failurePhase='arm';capture.failureCode=/^[A-Z0-9_]{1,100}$/.test(error.code??'')?error.code:'BER_HANDOFF_ARM_FAILED';
   capture.sourceAfter=await sources();const evidence=await save('capture',capture);
   error.berCompletionHandoffCapture={status:'failed',evidence,scope:'first_owed_ranked_handoff_not_full_BER007'};
  }finally{await release();await controller.end();await observer.end();}
  throw error;
 }
 return{
  async interruptAwait(){
   try{
    const before=await wait(s=>terminalTasks(s)&&absent(s)&&s.rows.run[0].status==='running'&&s.locks.some(l=>!l.granted&&l.mode==='RowExclusiveLock'&&l.blocking_pids.includes(controllerPid)),45000,'BER_HANDOFF_NOT_ACTUALLY_BLOCKED');
    capture.blockedPid=before.locks.find(l=>!l.granted&&l.mode==='RowExclusiveLock'&&l.blocking_pids.includes(controllerPid)).pid;
    capture.checkpoints.beforeCrash=await save('before-crash-first-handoff',before);
    capture.stopReceipt=await commonCapture.stopApi();stopped=true;
    assert.equal(capture.stopReceipt?.schemaVersion,'beta-local-api-stop-receipt/v1');assert.ok(capture.stopReceipt.exitCode!==null||capture.stopReceipt.signal!==null);
    let health;try{health=await fetch(new URL('/healthz',commonCapture.apiOrigin),{signal:AbortSignal.timeout(2000)});}catch{}
    capture.apiUnavailableAfterStop=!health?.ok;assert.equal(capture.apiUnavailableAfterStop,true);
    const afterStop=await wait(s=>!s.locks.some(l=>l.pid===capture.blockedPid),10000,'BER_HANDOFF_STOP_DID_NOT_ROLL_BACK_TRANSACTION');
    assert.ok(absent(afterStop));assert.deepEqual(unchanged(afterStop),unchanged(before));capture.checkpoints.afterStop=await save('after-stop-before-release',afterStop);
    await release();capture.restart=await commonCapture.restartApi();stopped=false;
    const resumed=await wait(s=>s.rows.run[0].status==='completed'&&terminalTasks(s,true)&&s.rows.handoffs.length===1&&s.rows.results.length===1&&s.rows.versions.length===1&&s.rows.slots.length===0&&s.rows.claims.every(c=>c.status==='released'),45000,'BER_HANDOFF_FIRST_COMMIT_NOT_RESUMED');
    assert.deepEqual(resumed.rows.versions,admissionVersions);assert.deepEqual(unchanged(resumed),unchanged(before));capture.checkpoints.resumed=await save('resumed-first-handoff-committed',resumed);capture.status='verified_subset';
   }catch(error){capture.status='failed';capture.failureCode=/^[A-Z0-9_]{1,100}$/.test(error.code??'')?error.code:'BER_HANDOFF_PROBE_FAILED';if(error.lastObservation)capture.failureObservation=await save('failure-observation',error.lastObservation);}
   finally{await release();if(stopped){await commonCapture.restartApi();stopped=false;}}
   capture.sourceAfter=await sources();assert.deepEqual(capture.sourceAfter,capture.sourceBefore);
   const evidence=await save('capture',capture);return{status:capture.status,evidence,scope:'first_owed_ranked_handoff_not_full_BER007'};
  },
  async close(){if(closed)return;closed=true;try{await release();if(stopped)await commonCapture.restartApi();}finally{await controller.end();await observer.end();}},
 };
}
