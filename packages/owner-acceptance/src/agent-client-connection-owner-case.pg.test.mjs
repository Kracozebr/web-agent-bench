/** Component SQL contract only; this test never qualifies native/browser ACI acceptance. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {observeAgentClientConnection} from './agent-client-connection-owner-case.mjs';
const enabled=process.env.OID_ACI_OBSERVER_PG_TEST==='1';
test('ACI read-only observer executes production-schema queries and binds exact grant, audit, scope and zero business effects',{skip:!enabled,timeout:120000},async()=>{
  const source=new URL(process.env.OID_DATABASE_URL??'postgres://oid_owner@postgres/owner_identity');
  if(!source.password)source.password=(await readFile('/run/secrets/owner_password','utf8')).trim();
  assert.equal(source.hostname,'postgres');assert.equal(source.username,'oid_owner');assert.equal(source.pathname,'/owner_identity');
  const name='oid_acceptance_'+randomUUID().replaceAll('-',''),target=new URL(source);target.pathname='/'+name;
  const observer=new URL(process.env.OID_OBSERVER_DATABASE_URL??source.href);observer.username='oid_observer';observer.password=(await readFile('/run/secrets/observer_password','utf8')).trim();observer.pathname='/'+name;
  const admin=new pg.Pool({connectionString:source.href,max:1}),owner=new pg.Pool({connectionString:target.href,max:1}),pool=new pg.Pool({connectionString:observer.href,max:1});
  try{
    assert.match(name,/^oid_acceptance_[a-f0-9]{32}$/);await admin.query(`CREATE DATABASE "${name}" TEMPLATE template0`);
    await owner.query(`GRANT CONNECT ON DATABASE "${name}" TO oid_observer`);await owner.query('GRANT USAGE ON SCHEMA public TO oid_observer');await owner.query('ALTER DEFAULT PRIVILEGES FOR ROLE oid_owner IN SCHEMA public GRANT SELECT ON TABLES TO oid_observer');
    const migration=spawnSync(process.execPath,['--import','./packages/owner-identity/node_modules/tsx/dist/loader.mjs','packages/owner-identity/src/migrate.ts'],{cwd:'/workspace',env:{...process.env,NODE_ENV:'test',OID_DATABASE_URL:target.href,OID_AUTH_SECRET:'isolated-ACI-observer-contract-auth-secret-32-chars',OID_PUBLIC_ORIGIN:'http://127.0.0.1:3000',OID_MCP_TRANSPORT_PROFILE:'remote-oauth-v1',OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'false'},timeout:60000,encoding:'utf8'});
    assert.equal(migration.status,0,'isolated observer schema migration failed');
    const ownerId=randomUUID(),authUserId=randomUUID(),agentId=randomUUID(),grantId=randomUUID();
    await owner.query('INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,$2,$3,true)',[authUserId,'Synthetic ACI observer',authUserId+'@example.invalid']);
    await owner.query("INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES($1,$2,'admitted')",[ownerId,authUserId]);
    await owner.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,'Synthetic ACI observer')",[agentId,ownerId]);
    await owner.query('INSERT INTO oid_agent_policy(agent_id,training) VALUES($1,true)',[agentId]);
    await owner.query('INSERT INTO oid_agent_financial_policy(owner_id,agent_id,revision) VALUES($1,$2,1)',[ownerId,agentId]);
    const before=await observeAgentClientConnection(pool,{ownerId,agentId,stage:'before_consent'});assert.equal(before.grants.length,0);assert.equal(Object.keys(before.domainDigests).length,6);
    await owner.query(`INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,oauth_client_id,resource,access_generation,expires_at)
      VALUES($1,$2,$3,$4,'oauth','synthetic-public','http://127.0.0.1:3000/api/agent/mcp',1,now()+interval '1 day')`,[grantId,ownerId,agentId,randomUUID()]);
    await owner.query(`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata)
      VALUES($1,'agent.connection.preflight',$2,$3,$3,$4::jsonb)`,[randomUUID(),'preflight:'+randomUUID(),ownerId,JSON.stringify({agentId,connectionId:grantId,protocolVersion:'2025-06-18'})]);
    const after=await observeAgentClientConnection(pool,{ownerId,agentId,stage:'after_preflight'});
    assert.deepEqual(after.domainDigests,before.domainDigests);assert.deepEqual(after.caps,before.caps);assert.equal(before.financialPolicyRevision,1);assert.equal(after.financialPolicyRevision,1);assert.equal(after.grants.length,1);assert.equal(after.grants[0].id,grantId);assert.equal(after.grants[0].protocol_version,'2025-06-18');assert(after.grants[0].last_preflight_at);
    assert.match(after.grants[0].permissions_hash,/^[a-f0-9]{64}$/);assert.match(after.grants[0].caps_hash,/^[a-f0-9]{64}$/);
    assert.deepEqual(after.admission,{reservationCount:0,reservationLotCount:0,reservationUnits:'0',debitCount:0,debitLotCount:0,debitUnits:'0'});
    const foreign=await observeAgentClientConnection(pool,{ownerId:randomUUID(),agentId,stage:'foreign_owner'});assert.equal(foreign.grants.length,0);assert.equal(foreign.intents.length,0);assert.equal(foreign.runs.length,0);assert.equal(foreign.policy,undefined);assert.equal(foreign.caps,undefined);
    const role=await pool.query('SHOW default_transaction_read_only');assert.equal(role.rows[0].default_transaction_read_only,'on');
  }finally{
    await pool.end();await owner.end();
    assert.match(name,/^oid_acceptance_[a-f0-9]{32}$/);assert.notEqual(name,source.pathname.slice(1));
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH(FORCE)`);await admin.end();
  }
});
