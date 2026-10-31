/** Clone an existing disposable completed fixture and probe current private callback services on the clone only. */
import {createRequire} from 'node:module';
import {randomUUID,createHash} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,relative} from 'node:path';
import assert from 'node:assert/strict';
import {runBerCompletedCallbacks} from './ber_completed_callbacks.mjs';
const{Client}=createRequire('/workspace/packages/owner-acceptance/package.json')('pg');
const root='/workspace',args=process.argv.slice(2);
assert.equal(args.length,2);assert.match(args[0],/^artifacts\/runs\/[A-Za-z0-9._/-]+\.json$/);assert.ok(!args[0].split('/').includes('..'));assert.match(args[1],/^[a-f0-9]{64}$/);
const sha=b=>createHash('sha256').update(b).digest('hex');
const sourceBytes=await readFile(resolve(root,args[0]));assert.equal(sha(sourceBytes),args[1]);
const source=JSON.parse(sourceBytes),sourceDatabase=source.database.databaseName;
assert.match(sourceDatabase,/^oid_acceptance_[a-f0-9]{32}$/);assert.equal(source.mode,'ranked');assert.equal(source.runCompletion.status,'verified');
const target={runId:source.run.runId,ownerId:source.identity.ownerId,agentId:source.agent.agentId};
assert.ok(Object.values(target).every(id=>/^[a-f0-9-]{36}$/.test(id)));
const captureId=randomUUID(),database='oid_acceptance_'+captureId.replaceAll('-','');
const ownerPassword=(await readFile('/run/secrets/owner_password','utf8')).trim(),observerPassword=(await readFile('/run/secrets/observer_password','utf8')).trim();
const url=(role,password,db)=>{const u=new URL(`postgres://${role}@postgres:5432/${db}`);u.password=password;return u.href;};
async function sourceFingerprint(){const db=new Client({connectionString:url('oid_observer',observerPassword,sourceDatabase)});try{
 await db.connect();await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const identity=(await db.query("SELECT current_user role,current_database() database_name,current_setting('transaction_read_only') read_only")).rows[0];assert.equal(identity.role,'oid_observer');assert.equal(identity.read_only,'on');
 const hashes={};for(const[table,column]of[['oid_benchmark_run','id'],['oid_run_task','run_id'],['oid_run_task_evaluation','run_id'],['oid_run_task_action','run_id'],['oid_run_event','run_id'],['oid_ranked_run_handoff','run_id'],['oid_ranked_verified_result','run_id']]){
  const rows=(await db.query(`SELECT to_jsonb(t)::text row FROM ${table} t WHERE ${column}=$1 ORDER BY to_jsonb(t)::text`,[target.runId])).rows.map(x=>x.row);
  hashes[table]={count:rows.length,sha256:sha(JSON.stringify(rows))};}
 await db.query('COMMIT');return{identity,hashes};
}finally{await db.end();}}
const before=await sourceFingerprint();
const admin=new Client({connectionString:url('oid_owner',ownerPassword,'owner_identity')});
try{await admin.connect();await admin.query(`CREATE DATABASE "${database}" WITH TEMPLATE "${sourceDatabase}" OWNER oid_owner`);
 await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO oid_observer`);
}finally{await admin.end();}
const result=await runBerCompletedCallbacks({databaseUrl:url('oid_owner',ownerPassword,database),observerDatabaseUrl:url('oid_observer',observerPassword,database),repoRoot:root,...target});
const after=await sourceFingerprint();assert.deepEqual(after,before,'original fixture database must remain unchanged');
const receipt={schemaVersion:'ber-completed-callback-clone/v1',classification:'current_private_services_on_new_clone_of_retained_completed_fixture_not_fresh_benchmark_execution',captureId,
 sourceCapture:{path:args[0],sha256:args[1]},sourceDatabase,databaseName:database,target,originalFixtureBefore:before,originalFixtureAfter:after,
 callbackCapture:result.evidence,status:result.status,fullScenarioAcceptance:false};
const directory=resolve(root,'artifacts/runs/ber-completed-callback-clone',captureId);await mkdir(directory,{recursive:true,mode:0o700});
const path=resolve(directory,'capture.json'),bytes=Buffer.from(JSON.stringify(receipt,null,2)+'\n');await writeFile(path,bytes,{flag:'wx',mode:0o600});
console.log(JSON.stringify({path:relative(root,path).split('\\').join('/'),sha256:sha(bytes),status:result.status,callbackCapture:result.evidence,originalFixtureUnchanged:true}));
if(result.status!=='verified_subset')process.exitCode=1;
