import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {test} from 'node:test';
import Fastify, {type FastifyRequest} from 'fastify';
import postgres from 'postgres';
import {createDatabase} from './db.js';
import {loadConfig} from './config.js';
import {registerParticipantCabinetRoutes} from './participant-cabinet-routes.js';
import {listParticipantRuns,listParticipantIntents,listParticipantGrants,listParticipantBillingHistory} from './participant-cabinet-service.js';
import {registerRunRoutes} from './run-routes.js';
import {sha256CanonicalTaskJson} from './task-release.js';

const enabled=process.env.OID_PARTICIPANT_CABINET_PG_TEST==='1';
const secret='participant-cabinet-fixture-cursor-secret-32';
test('PCU pagination and completed Training diagnostics use isolated PostgreSQL, owner cookies and unchanged durable records',
 {skip:!enabled,timeout:180000},async t=>{
  const base=new URL(process.env.OID_DATABASE_URL!);
  assert.equal(base.hostname,'postgres');assert.equal(base.username,'oid_owner');assert.equal(base.pathname,'/owner_identity');
  const database='oid_acceptance_'+randomUUID().replaceAll('-',''),admin=postgres(base.href,{max:1});
  assert.match(database,/^oid_acceptance_[a-f0-9]{32}$/);
  await admin.unsafe(`CREATE DATABASE "${database}" TEMPLATE template0`);
  const target=new URL(base);target.pathname='/'+database;
  const config=loadConfig({...process.env,OID_DATABASE_URL:target.href}),{db,client}=createDatabase(config);
  const app=Fastify();
  try{
    const migration=spawnSync(process.execPath,['--import','tsx','src/migrate.ts'],{cwd:process.cwd(),
      env:{...process.env,OID_DATABASE_URL:target.href},encoding:'utf8',timeout:120000});
    assert.equal(migration.status,0,'fresh disposable schema migration must succeed');
    const owner=randomUUID(),foreign=randomUUID(),agent=randomUUID(),stamp='2026-10-30T00:00:00.123456Z',hash='a'.repeat(64);
    for(const id of [owner,foreign]){
      await client`INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES(${id},'Fixture',${id+'@example.invalid'},true)`;
      await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${id},${id},'admitted')`;
    }
    await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agent},${owner},'Fixture')`;
    const pairs:Array<{run:string;intent:string}>=[];
    async function seedPair(at:string,mode='training'){
      const run=randomUUID(),intent=randomUUID();
      await client`INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,
        benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,created_at,expires_at)
        VALUES(${intent},${owner},${agent},${'fixture_'+intent},${hash},${mode},ARRAY['S1'],'fixture','fixture',${hash},${hash},${hash},1,0,1,1,${at},'2027-01-01')`;
      await client`INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,
        manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queued_at,queue_deadline)
        VALUES(${run},${intent},${owner},${agent},${mode},ARRAY['S1'],'fixture','fixture',${hash},${hash},${hash},1,0,1,1,'completed',${at},'2027-01-01')`;
      return {run,intent};
    }
    for(let i=0;i<12;i++)pairs.push(await seedPair(stamp));
    for(let i=0;i<12;i++){
      const grant=randomUUID();
      await client`INSERT INTO oid_bonus_grant(id,owner_id,amount_units,issued_by_owner_id,reason,operation_id,created_at)
        VALUES(${grant},${owner},10001,${owner},'Fixture',${'fixture_'+grant},${stamp})`;
      await client`INSERT INTO oid_ledger_entry(id,owner_id,bonus_grant_id,operation_id,entry_type,source_kind,amount_units,available_delta_units,created_at)
        VALUES(${randomUUID()},${owner},${grant},${'fixture_'+grant},'bonus_grant','tester_bonus',10001,10001,${stamp})`;
    }
    const fingerprint=async()=>{
      const state=[];for(const table of ['oid_benchmark_run','oid_run_launch_intent','oid_bonus_grant','oid_ledger_entry','oid_run_task','oid_run_task_evaluation','oid_run_task_action','oid_run_task_action_receipt'])
        state.push(await client.unsafe(`SELECT row_to_json(t)::text AS row FROM ${table} t ORDER BY row_to_json(t)::text`));
      return sha256CanonicalTaskJson(state);
    };
    const resolveOwner=async(request:FastifyRequest)=>{
      const id=request.headers.cookie==='owner=fixture'?owner:request.headers.cookie==='owner=foreign'?foreign:null;
      if(!id){const {HttpError}=await import('./http-error.js');throw new HttpError(401,'UNAUTHORIZED','Owner session required')}
      return {owner:{id,admissionStatus:'admitted'}};
    };
    registerParticipantCabinetRoutes(app,{db,cabinetCursorSecret:secret,resolveOwner,rateLimit:async()=>{},rateLimitMax:100});
    registerRunRoutes(app,{db,cabinetCursorSecret:secret,resolveOwner,resolveAgentPrincipal:async()=>undefined,
      requireOrigin:async()=>{},rateLimit:async()=>{},rateLimitMax:100,publicOrigin:'http://127.0.0.1:3000'});
    await app.ready();
    await t.test('all four keyset pages preserve microsecond ties, complete traversal, owner/resource scope and exact units',async()=>{
      for(const [path,key,fn] of [
        ['/api/owner/runs','runs',listParticipantRuns],['/api/owner/runs/intents','intents',listParticipantIntents],
        ['/api/owner/billing/grants','grants',listParticipantGrants],['/api/owner/billing/history','history',listParticipantBillingHistory]
      ] as const){
        const before=await fingerprint();
        const first=await app.inject({url:path+'?limit=5',headers:{cookie:'owner=fixture'}});
        assert.equal(first.statusCode,200);assert.match(String(first.headers['cache-control']),/no-store/);
        const initial=first.json();assert.equal(initial[key].length,5);assert.ok(initial.nextCursor);
        assert.ok(!Buffer.from(initial.nextCursor,'base64url').toString('utf8').includes(owner));
        const ids=initial[key].map((x:{id:string})=>x.id);let cursor=initial.nextCursor;
        while(cursor){const response=await app.inject({url:path+'?limit=5&cursor='+cursor,headers:{cookie:'owner=fixture'}});
          assert.equal(response.statusCode,200);const body=response.json();ids.push(...body[key].map((x:{id:string})=>x.id));cursor=body.nextCursor}
        assert.equal(ids.length,12);assert.equal(new Set(ids).size,12);
        const cross=await app.inject({url:path+'?limit=5&cursor='+initial.nextCursor,headers:{cookie:'owner=foreign'}});
        assert.equal(cross.statusCode,400);
        const tampered=initial.nextCursor.slice(0,-2)+'AA';
        assert.equal((await app.inject({url:path+'?limit=5&cursor='+tampered,headers:{cookie:'owner=fixture'}})).statusCode,400);
        assert.equal((await app.inject({url:path+'?limit=51',headers:{cookie:'owner=fixture'}})).statusCode,400);
        assert.equal((await app.inject({url:path+'?limit=5',headers:{authorization:'Bearer fixture'}})).statusCode,401);
        assert.deepEqual((await fn(db,foreign,{limit:'5'},secret) as any)[key],[]);
        if(key==='grants'||key==='history')assert.equal(initial[key][0].amount,'0.010001');
        assert.equal(await fingerprint(),before,'all list and denial reads leave durable state unchanged');
      }
    });
    await t.test('a concurrent new top row does not skip or duplicate an existing row',async()=>{
      const first=await listParticipantRuns(db,owner,{limit:'5'},secret);
      const inserted=await seedPair('2026-10-31T00:00:00.000001Z');
      const ids=first.runs.map(r=>r.id);let cursor=first.nextCursor;
      while(cursor){const page=await listParticipantRuns(db,owner,{limit:'5',cursor},secret);ids.push(...page.runs.map(r=>r.id));cursor=page.nextCursor}
      assert.equal(ids.length,12);assert.equal(new Set(ids).size,12);assert.ok(!ids.includes(inserted.run));
      assert.equal((await listParticipantRuns(db,owner,{limit:'5'},secret)).runs[0]!.id,inserted.run);
      await assert.rejects(listParticipantIntents(db,owner,{limit:'5',cursor:first.nextCursor},secret));
      await assert.rejects(listParticipantRuns(db,owner,{limit:'5',cursor:first.nextCursor},secret+'rotated'));
    });
    await t.test('only completed owned Training releases diagnostics, unknown is not zero and forged evaluation hashes fail closed',async()=>{
      const run=pairs[0]!.run,closure=randomUUID(),grant=randomUUID(),action=randomUUID();
      await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status,started_at,deadline_at) VALUES(${run},0,'S1','unknown',${stamp},'2026-10-30T00:02:00Z')`;
      await client`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,resource,access_generation,expires_at)
        VALUES(${grant},${owner},${agent},${'fixture_'+grant},'http://127.0.0.1:3000/api/agent',1,'2027-01-01')`;
      await client`INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json)
        VALUES(${action},${run},0,${owner},${agent},1,${grant},'S1','fixture',1,${'fixture_'+action},${hash},'inspect_catalog','{"kind":"inspect_catalog"}')`;
      await client`INSERT INTO oid_run_task_action_receipt(action_id,receipt_revision,receipt_status,evidence_hash,evidence_path)
        VALUES(${action},1,'unknown',${hash},'artifacts/private-token-canary.json')`;
      await client`UPDATE oid_run_task SET accepted_action_sequence=1,reconciled_action_sequence=1 WHERE run_id=${run}`;
      await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,payload_hash,reason,action_cutoff_sequence,actor_kind,owner_id,agent_id)
        VALUES(${closure},${run},0,${hash},'task_deadline',1,'coordinator',${owner},${agent})`;
      await client`UPDATE oid_run_task SET closure_status='unknown',closure_id=${closure},action_cutoff_sequence=1,closed_at='2026-10-30T00:02:00Z' WHERE run_id=${run}`;
      const path=`/api/owner/runs/${run}/tasks/S1/diagnostics`,before=await fingerprint();
      const response=await app.inject({url:path,headers:{cookie:'owner=fixture'}});assert.equal(response.statusCode,200);
      const d=response.json().diagnostics;assert.equal(d.status,'unknown');assert.equal(d.credit,null);assert.equal(d.goalChecks[0].status,'unknown');
      assert.equal(d.actions.length,1);assert.equal(d.actions[0].actionId,action);assert.equal(d.actions[0].sequence,'1');assert.equal(d.actions[0].status,'unknown');
      assert.deepEqual(d.actions[0].evidenceRefs,['sha256:'+hash]);assert.ok(!response.body.includes('snapshot_json'));
      assert.ok(!response.body.includes('private-token-canary'));assert.equal(await fingerprint(),before);
      assert.equal((await app.inject({url:path,headers:{cookie:'owner=foreign'}})).statusCode,404);
      assert.equal((await app.inject({url:path.replace('/S1/','/M1/'),headers:{cookie:'owner=fixture'}})).statusCode,404);
      const active=pairs[1]!.run;
      await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES(${active},0,'S1','active')`;
      assert.equal((await app.inject({url:path.replace(run,active),headers:{cookie:'owner=fixture'}})).statusCode,404);
      const ranked=await seedPair(stamp,'ranked');
      await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES(${ranked.run},0,'S1','completed')`;
      assert.equal((await app.inject({url:path.replace(run,ranked.run),headers:{cookie:'owner=fixture'}})).statusCode,404);
      const forged={taskId:'S1',status:'known',outcome:'passed',credit:{numerator:'1',denominator:'1'},mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:null};
      await client`INSERT INTO oid_run_task_evaluation(run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json)
        VALUES(${run},0,${closure},'S1','fixture',${hash},${hash},${hash},${hash},${hash},${hash},'{}',${JSON.stringify(forged)}::jsonb)`;
      assert.equal((await app.inject({url:path,headers:{cookie:'owner=fixture'}})).statusCode,409);
    });
    await t.test('known partial feedback exposes exact original credit and allowlisted checks without retained answer/provider fields',async()=>{
      const {run}=await seedPair(stamp),closure=randomUUID();
      await client`INSERT INTO oid_run_task(run_id,task_index,task_id,status,started_at,deadline_at) VALUES(${run},0,'S1','completed',${stamp},'2026-10-30T00:02:00Z')`;
      await client`INSERT INTO oid_run_task_closure(id,run_id,task_index,payload_hash,reason,action_cutoff_sequence,actor_kind,owner_id,agent_id)
        VALUES(${closure},${run},0,${hash},'agent_finish',0,'coordinator',${owner},${agent})`;
      await client`UPDATE oid_run_task SET closure_status='closed',closure_id=${closure},action_cutoff_sequence=0,closed_at='2026-10-30T00:02:00Z' WHERE run_id=${run}`;
      const input={taskCase:{taskId:'S1',referenceAnswer:'retained-answer-canary'},run:{runId:run,ownerId:owner},
        observations:{payments:[],deliveries:[],providerUrl:'https://provider.invalid/private-token-canary'}};
      const result={taskId:'S1',status:'known',outcome:'partial',credit:{numerator:'2',denominator:'3',privateNote:'retained-credit-canary'},
        mandatoryViolation:null,unknownReasons:[],operatingExpenseUsdcUnits:'1',providerUrl:'https://provider.invalid/private-token-canary'};
      await client`INSERT INTO oid_run_task_evaluation(run_id,task_index,closure_id,task_id,release_identity,manifest_hash,case_hash,rubric_hash,input_hash,result_hash,evaluator_source_hash,observation_evidence,result_json,input_json)
        VALUES(${run},0,${closure},'S1','fixture',${hash},${hash},${hash},${sha256CanonicalTaskJson(input)},${sha256CanonicalTaskJson(result)},${hash},'{}',${JSON.stringify(result)}::jsonb,${JSON.stringify(input)}::jsonb)`;
      const before=await fingerprint(),response=await app.inject({url:`/api/owner/runs/${run}/tasks/S1/diagnostics`,headers:{cookie:'owner=fixture'}});
      assert.equal(response.statusCode,200);const d=response.json().diagnostics;
      assert.equal(d.status,'known');assert.equal(d.outcome,'partial');assert.deepEqual(d.credit,{numerator:'2',denominator:'3'});
      assert.equal(d.goalChecks[0].status,'failed');assert.equal(d.constraintChecks[0].status,'passed');
      assert.ok(!response.body.includes('canary'));assert.ok(!response.body.includes('provider.invalid'));
      assert.equal(await fingerprint(),before);
    });
  }finally{
    await app.close();await client.end({timeout:5});
    await admin.unsafe(`DROP DATABASE "${database}"`);await admin.end({timeout:5});
  }
});
