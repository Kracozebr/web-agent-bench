/** Private service callback probes on a fresh completed acceptance run. Never a participant API or artifact replay. */
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHash,randomUUID} from 'node:crypto';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
const {Pool}=createRequire('/workspace/packages/owner-acceptance/package.json')('pg');
const canon=v=>Array.isArray(v)?v.map(canon):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,canon(x)])):v;
const hash=v=>createHash('sha256').update(JSON.stringify(canon(v))).digest('hex');
const sha=b=>createHash('sha256').update(b).digest('hex');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SOURCE_PATHS=['tools/ber_completed_callbacks.mjs','packages/owner-identity/src/task-run-completion.ts',
  'packages/owner-identity/src/task-successor-activation.ts','packages/owner-identity/src/task-ranked-handoff.ts',
  'packages/owner-identity/src/task-sealed-evidence-source.ts','packages/owner-identity/src/task-store.ts',
  'packages/owner-identity/dist/task-run-completion.js','packages/owner-identity/dist/task-successor-activation.js',
  'packages/owner-identity/dist/task-ranked-handoff.js','packages/owner-identity/dist/task-sealed-evidence-source.js',
  'packages/owner-identity/dist/task-store.js'];

async function snapshot(pool,target,raw=false){
 const client=await pool.connect();
 try{await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  const identity=(await client.query("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only,clock_timestamp() observed_at")).rows[0];
  assert.equal(identity.role,'oid_observer');assert.equal(identity.read_only,'on');assert.match(identity.database_name,/^oid_acceptance_[a-f0-9]{32}$/);
  const rows={};const query=async(sql,args=[target.runId])=>(await client.query(sql,args)).rows.map(x=>x.row);
  rows.run=await query('SELECT to_jsonb(t) row FROM oid_benchmark_run t WHERE id=$1');
  assert.equal(rows.run.length,1);const run=rows.run[0];assert.equal(run.owner_id,target.ownerId);assert.equal(run.agent_id,target.agentId);
  assert.equal(run.status,'completed');assert.equal(run.mode,'ranked');assert.equal(run.terminal_reason,null);assert.equal(run.cancellation_reason,null);assert.equal(run.task_ids.length,12);
  rows.tasks=await query("SELECT to_jsonb(t)-'snapshot_json' row FROM oid_run_task t WHERE run_id=$1");
  for(const[key,table]of Object.entries({evaluations:'oid_run_task_evaluation',actions:'oid_run_task_action',closures:'oid_run_task_closure',bundles:'oid_run_task_observation_bundle',events:'oid_run_event',bindings:'oid_task_execution_binding',preparations:'oid_task_preparation_intent',claims:'oid_run_dispatch_claim',slots:'oid_run_execution_slot',handoffs:'oid_ranked_run_handoff',results:'oid_ranked_verified_result',versions:'oid_ranked_run_version_snapshot'}))rows[key]=await query(`SELECT to_jsonb(t) row FROM ${table} t WHERE run_id=$1`);
  for(const[key,table]of Object.entries({receipts:'oid_run_task_action_receipt',outboxes:'oid_run_task_action_outbox',reconciliations:'oid_run_task_action_reconciliation'}))rows[key]=await query(`SELECT to_jsonb(t) row FROM ${table} t WHERE action_id IN(SELECT id FROM oid_run_task_action WHERE run_id=$1)`);
  rows.leases=await query('SELECT to_jsonb(t) row FROM oid_task_environment_lease t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1)');
  rows.ledger=await query('SELECT to_jsonb(t) row FROM oid_ledger_entry t WHERE operation_id=$1 OR left(operation_id,length($2))=$2',['rundeb_'+target.runId.replaceAll('-',''),'runref_'+target.runId.replaceAll('-','')+'_']);
  const sets={};for(const[key,list]of Object.entries(rows)){list.sort((a,b)=>JSON.stringify(canon(a))<JSON.stringify(canon(b))?-1:JSON.stringify(canon(a))>JSON.stringify(canon(b))?1:0);sets[key]={count:list.length,sha256:hash(list)};}
  await client.query('COMMIT');return{identity,sets,...(raw?{rows}:{})};
 }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
}

export async function runBerCompletedCallbacks(input){
 const {databaseUrl,observerDatabaseUrl,repoRoot,runId,ownerId,agentId}=input;
 assert.ok([runId,ownerId,agentId].every(v=>UUID.test(v)));
 const ownerUrl=new URL(databaseUrl),observerUrl=new URL(observerDatabaseUrl);
 assert.equal(ownerUrl.hostname,'postgres');assert.equal(observerUrl.hostname,'postgres');
 assert.match(ownerUrl.pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);assert.equal(observerUrl.pathname,ownerUrl.pathname);
 assert.equal(ownerUrl.username,'oid_owner');assert.equal(observerUrl.username,'oid_observer');
 const sourceHashes=async()=>Object.fromEntries(await Promise.all(SOURCE_PATHS.map(async p=>[p,sha(await readFile(resolve(repoRoot,p)))])));
 const sourceBefore=await sourceHashes();
 const observer=new Pool({connectionString:observerDatabaseUrl,max:1});let created;
 const target={runId,ownerId,agentId};
 const capture={schemaVersion:'ber-private-completed-callback-probes/v1',boundary:'isolated_completed_ranked_private_worker_services_actual_postgres_no_executor_dispatch',
  target,databaseName:ownerUrl.pathname.slice(1),observedAt:new Date().toISOString(),sourceBefore,probes:[],preparedPortCalls:0,fullScenarioAcceptance:false};
 try{
  capture.before=await snapshot(observer,target,true);
  const{createDatabase}=await import('../packages/owner-identity/dist/db.js');
  const{createPostgresTaskReleaseQuerySource}=await import('../packages/owner-identity/dist/task-store.js');
  const{TaskSealedEvidenceSource}=await import('../packages/owner-identity/dist/task-sealed-evidence-source.js');
  const{completeKnownRankedRun,finalizeKnownRankedTask}=await import('../packages/owner-identity/dist/task-run-completion.js');
  const{activatePreparedRankedSuccessor}=await import('../packages/owner-identity/dist/task-successor-activation.js');
  created=createDatabase({databaseUrl});const taskReleaseSource=createPostgresTaskReleaseQuerySource(created.db);
  const deps={db:created.db,taskReleaseSource,evidenceSource:new TaskSealedEvidenceSource({taskReleaseSource,evidenceRoot:repoRoot})};
  const finishedAt=new Date(capture.before.rows.run[0].finished_at).toISOString();
  const record=async(name,request,invoke,expected)=>{
   const startedAt=new Date().toISOString();let response,error=null;
   try{response=await invoke();}catch(e){error={code:/^[A-Z0-9_]{1,100}$/.test(e.code??'')?e.code:'UNEXPECTED_CALLBACK_ERROR',status:Number.isInteger(e.status)?e.status:null};}
   const after=await snapshot(observer,target);capture.probes.push({name,request,startedAt,finishedAt:new Date().toISOString(),response:response??null,error,after});
   assert.deepEqual(after.sets,capture.before.sets,'private callback must preserve all original business rows');
   expected(response,error);
  };
  for(const ordinal of [1,2])await record('duplicate_completion_'+ordinal,{runId},()=>completeKnownRankedRun(deps,{runId}),
   (response,error)=>{assert.equal(error,null);assert.deepEqual(response,{runId,status:'completed',finishedAt,replayed:true});});
  for(const taskIndex of [10,0,10])await record('out_of_order_terminal_callback_'+taskIndex,{runId,taskIndex},()=>finalizeKnownRankedTask(deps,{runId,taskIndex}),
   (response,error)=>{assert.equal(error,null);assert.equal(response.replayed,true);assert.equal(response.runId,runId);assert.equal(response.taskIndex,taskIndex);});
  const forbidden=async()=>{capture.preparedPortCalls++;throw Error('unexpected_executor_port');};
  const preparedTaskStart=new Proxy({},{get:()=>forbidden});
  for(const predecessorTaskIndex of [10,0])await record('late_successor_callback_'+predecessorTaskIndex,{runId,predecessorTaskIndex},
   ()=>activatePreparedRankedSuccessor({...deps,preparedTaskStart},{runId,predecessorTaskIndex}),
   (response,error)=>{assert.equal(response,undefined);assert.equal(error?.code,'SUCCESSOR_RUN_NOT_CURRENT');assert.equal(error?.status,409);});
  assert.equal(capture.preparedPortCalls,0);
  capture.status='verified_subset';
 }catch(error){capture.status='failed';capture.failureCode=/^[A-Z0-9_]{1,100}$/.test(error.code??'')?error.code:'COMPLETED_CALLBACK_PROBE_FAILED';}
 finally{await created?.client.end({timeout:5});await observer.end();}
 capture.sourceAfter=await sourceHashes();assert.deepEqual(capture.sourceAfter,capture.sourceBefore,'callback sources changed');
 const{assertSecretFree}=await import('../packages/owner-acceptance/src/evidence.mjs');assertSecretFree(capture,'ber-callbacks');
 const directory=resolve(repoRoot,'artifacts/runs/ber-completed-callbacks',randomUUID());await mkdir(directory,{recursive:true,mode:0o700});
 const path=resolve(directory,'capture.json'),bytes=Buffer.from(JSON.stringify(capture,null,2)+'\n');await writeFile(path,bytes,{flag:'wx',mode:0o600});
 return{evidence:{path:relative(repoRoot,path).split('\\').join('/'),sha256:sha(bytes)},status:capture.status,
  probes:capture.probes.length,scope:'completed_callback_subset_not_interrupted_first_commit_or_full_BER007'};
}
