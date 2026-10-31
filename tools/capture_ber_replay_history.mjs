/** Read-only raw history collector. Docker tools profile only; never invokes a worker or finalizer. */
import {createRequire} from 'node:module';
import {readFile, mkdir, writeFile} from 'node:fs/promises';
import {createHash, randomUUID} from 'node:crypto';
const {Client} = createRequire('/workspace/packages/owner-acceptance/package.json')('pg');
const root='/workspace';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>[k,canonical(x)])):v;
const hash=v=>sha(JSON.stringify(canonical(v)));
const args=process.argv.slice(2);
if(args.length!==3||!/^oid_(?:google_local|acceptance)_[a-f0-9]{32}$/.test(args[0])||!args[1].split(',').every(id=>/^[a-f0-9-]{36}$/.test(id))||!['history','fingerprint'].includes(args[2]))throw Error('Expected database, comma-separated run UUIDs, history|fingerprint');
const [databaseName,runIdsText,mode]=args,runIds=runIdsText.split(',');
const id=randomUUID(),directory=`artifacts/runs/ber-independent-replay-history/${id}`;
const sourcePaths=['tools/capture_ber_replay_history.mjs','packages/owner-identity/src/task-run-completion.ts','packages/owner-identity/src/task-ranked-handoff.ts','packages/owner-identity/src/task-ranked-aggregate.ts','packages/owner-identity/src/task-result-service.ts','packages/owner-identity/src/task-evaluator.ts','packages/owner-identity/src/task-release.ts'];
const sourceHashes=async()=>Object.fromEntries(await Promise.all(sourcePaths.map(async p=>[p,sha(await readFile(root+'/'+p))])));
const beforeSources=await sourceHashes();
const capture={schemaVersion:'ber-independent-replay-raw-history/v1',classification:'new_readonly_observation_of_retained_native_history_not_fresh_execution_or_full_BER007',captureId:id,databaseName,mode,observedAt:new Date().toISOString(),observer:null,runs:[],sourceHashes:beforeSources,artifacts:[]};
const url=new URL(`postgres://oid_observer@postgres:5432/${databaseName}`);url.password=(await readFile('/run/secrets/observer_password','utf8')).trim();
const db=new Client({connectionString:url.href});
try{
 await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 capture.observer=(await db.query("SELECT current_user AS role,current_setting('transaction_read_only') AS read_only,current_setting('transaction_isolation') AS isolation,current_database() AS database")).rows[0];
 if(capture.observer.role!=='oid_observer'||capture.observer.read_only!=='on'||capture.observer.database!==databaseName)throw Error('readonly observer required');
 for(const runId of runIds){
  const q=async(sql,args=[runId])=>(await db.query(sql,args)).rows;
  const raw={};
  raw.run=await q('SELECT to_jsonb(t) AS row FROM oid_benchmark_run t WHERE id=$1');
  if(raw.run.length!==1||raw.run[0].row.status!=='completed')throw Error('Only retained completed runs are accepted');
  raw.tasks=await q(`SELECT to_jsonb(t)-'snapshot_json' AS row FROM oid_run_task t WHERE run_id=$1 ORDER BY task_index`);
  for(const [key,table]of Object.entries({evaluations:'oid_run_task_evaluation',bundles:'oid_run_task_observation_bundle',actions:'oid_run_task_action',closures:'oid_run_task_closure',events:'oid_run_event',bindings:'oid_task_execution_binding',preparations:'oid_task_preparation_intent',handoffs:'oid_ranked_run_handoff',results:'oid_ranked_verified_result',version:'oid_ranked_run_version_snapshot',claims:'oid_run_dispatch_claim',slots:'oid_run_execution_slot',reservations:'oid_run_reservation'}))raw[key]=await q(`SELECT to_jsonb(t) AS row FROM ${table} t WHERE run_id=$1`);
  for(const [key,table]of Object.entries({receipts:'oid_run_task_action_receipt',outboxes:'oid_run_task_action_outbox',reconciliations:'oid_run_task_action_reconciliation'}))raw[key]=await q(`SELECT to_jsonb(t) AS row FROM ${table} t WHERE action_id IN(SELECT id FROM oid_run_task_action WHERE run_id=$1)`);
  raw.leases=await q('SELECT to_jsonb(t) AS row FROM oid_task_environment_lease t WHERE preparation_id IN(SELECT preparation_id FROM oid_task_preparation_intent WHERE run_id=$1)');
  raw.release=await q('SELECT to_jsonb(t) AS row FROM oid_task_release t WHERE release_identity=(SELECT release_identity FROM oid_benchmark_run WHERE id=$1)');
  raw.ledger=await q("SELECT to_jsonb(t) AS row FROM oid_ledger_entry t WHERE operation_id=$1 OR left(operation_id,length($2))=$2",['rundeb_'+runId.replaceAll('-',''),'runref_'+runId.replaceAll('-','')+'_']);
  const rows=Object.fromEntries(Object.entries(raw).map(([key,list])=>[key,list.map(x=>x.row).sort((a,b)=>JSON.stringify(canonical(a))<JSON.stringify(canonical(b))?-1:JSON.stringify(canonical(a))>JSON.stringify(canonical(b))?1:0)]));
  const sets=Object.fromEntries(Object.entries(rows).map(([key,list])=>[key,{count:list.length,sha256:hash(list)}]));
  capture.runs.push({runId,sets,...(mode==='history'?{rows}:{})});
 }
 await db.query('COMMIT');
}finally{await db.end();}
const references=new Map();
function visit(v){if(Array.isArray(v)){for(const x of v)visit(x);return;}if(!v||typeof v!=='object')return;
 if(typeof v.path==='string'&&/^[a-f0-9]{64}$/.test(v.sha256??''))references.set(v.path,v.sha256);
 for(const x of Object.values(v))visit(x);
}
if(mode==='history'){
 for(const run of capture.runs){visit(run.rows);for(const r of run.rows.receipts)if(r.evidence_path&&r.evidence_hash)references.set(r.evidence_path,r.evidence_hash);}
 for(const [path,digest]of references){
  if(!/^(artifacts\/runs|infrastructure|packages|openspec|tests)\/[A-Za-z0-9._/-]+$/.test(path)||path.split('/').some(x=>x==='..'||x==='.'||x===''))throw Error('unsafe evidence reference');
  const bytes=await readFile(root+'/'+path);if(sha(bytes)!==digest)throw Error('evidence hash mismatch');
  capture.artifacts.push({path,sha256:digest,sizeBytes:bytes.length});
 }
 capture.artifacts.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
}
capture.sourceHashesAfter=await sourceHashes();
if(hash(capture.sourceHashes)!==hash(capture.sourceHashesAfter))throw Error('collector/product sources changed during capture');
await mkdir(root+'/'+directory,{recursive:true});
const bytes=Buffer.from(JSON.stringify(capture,null,2)+'\n'),path=directory+'/'+mode+'.json';
await writeFile(root+'/'+path,bytes,{flag:'wx',mode:0o600});
console.log(JSON.stringify({path,sha256:sha(bytes),mode,runCount:capture.runs.length,artifactCount:capture.artifacts.length,observer:capture.observer}));
