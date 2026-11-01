import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import Fastify from 'fastify';
import postgres from 'postgres';
import { createAuth } from './auth.js';
import { registerAgentRoutes } from './agents.js';
import { loadConfig } from './config.js';
import { createDatabase } from './db.js';
import { HttpError } from './http-error.js';

// Component fixture: private owner/session setup; real signed OAuth query,
// consent-context HTTP handler, authoritative financial policy and PostgreSQL.
// This does not replace native/browser authorization acceptance.
test('consent context reads exact owner-scoped limits without granting or changing authority',
  { skip: process.env.OID_ACI_CONSENT_LIMITS_PG_TEST !== '1', timeout: 120_000 }, async () => {
  const source = new URL(process.env.OID_DATABASE_URL ?? `postgres://oid_owner:${(await readFile('/run/secrets/owner_password','utf8')).trim()}@postgres/owner_identity`);
  assert.equal(source.hostname,'postgres'); assert.equal(source.username,'oid_owner'); assert.equal(source.pathname,'/owner_identity');
  const databaseName=`oid_acceptance_${randomUUID().replaceAll('-','')}`;
  const target=new URL(source); target.pathname=`/${databaseName}`;
  const admin=postgres(source.href,{max:1});
  const config=loadConfig({...process.env,NODE_ENV:'test',OID_DATABASE_URL:target.href,
    OID_AUTH_SECRET:'disposable-consent-fixture-secret-thirty-two-characters',OID_MCP_TRANSPORT_PROFILE:'remote-oauth-v1',
    OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'false',OID_PUBLIC_ORIGIN:'http://127.0.0.1:3000'});
  const {client,db}=createDatabase(config);
  const app=Fastify({logger:false});
  try {
    await admin.unsafe(`CREATE DATABASE "${databaseName}" TEMPLATE template0`);
    const migration=spawnSync(process.execPath,['--import','./packages/owner-identity/node_modules/tsx/dist/loader.mjs','packages/owner-identity/src/migrate.ts'],
      {cwd:'/workspace',env:{...process.env,NODE_ENV:'test',OID_DATABASE_URL:target.href,OID_AUTH_SECRET:config.authSecret,
        OID_MCP_TRANSPORT_PROFILE:'remote-oauth-v1',OID_LOCAL_BEF_TASK_COORDINATOR_ENABLED:'false',OID_PUBLIC_ORIGIN:config.publicOrigin},encoding:'utf8',timeout:60000});
    assert.equal(migration.status,0,'Disposable consent fixture migration');
    const userId=randomUUID(),ownerId=randomUUID(),agentId=randomUUID(),sessionId=randomUUID();
    await client`INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES(${userId},'Consent fixture',${`${userId}@example.invalid`},true)`;
    await client`INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES(${ownerId},${userId},'admitted')`;
    await client`INSERT INTO oid_agent(id,owner_id,name) VALUES(${agentId},${ownerId},'Consent fixture')`;
    await client`INSERT INTO oid_agent_policy(agent_id,training,ranked,revision) VALUES(${agentId},true,false,1)`;
    await client`INSERT INTO oid_auth_session(id,user_id,token,expires_at) VALUES(${sessionId},${userId},${randomUUID()},now()+interval '1 day')`;
    const resource=`${config.publicOrigin}/api/agent/mcp`, state=randomUUID();
    const challenge=createHash('sha256').update(randomUUID()).digest('base64url');
    const scopes=['agent:operate','offline_access'];
    const params=new URLSearchParams({response_type:'code',client_id:config.mcpClientId,redirect_uri:config.mcpClientRedirectUri,
      code_challenge:challenge,code_challenge_method:'S256',state,resource,scope:scopes.join(' ')});
    const auth=createAuth(config,db);
    const authorization=await auth.handler(new Request(`${config.publicOrigin}/api/auth/oauth2/authorize?${params}`));
    const location=authorization.headers.get('location'); assert.ok(location,'Provider returns signed authorization continuation');
    const signedQuery=new URL(location,config.publicOrigin).search.slice(1);
    const queryHash=createHash('sha256').update(JSON.stringify({responseType:'code',clientId:config.mcpClientId,
      redirectUri:config.mcpClientRedirectUri,state,codeChallenge:challenge,codeChallengeMethod:'S256',resource,scopes})).digest('hex');
    const flowId=randomUUID(),grantId=randomUUID();
    await client`INSERT INTO oid_agent_oauth_authorization(id,operation_id,query_hash,owner_id,auth_user_id,auth_session_id,agent_id,grant_id,client_id,resource,redirect_uri,scopes,access_generation,policy_revision,status,created_at,expires_at)
      VALUES(${flowId},${randomUUID()},${queryHash},${ownerId},${userId},${sessionId},${agentId},${grantId},${config.mcpClientId},${resource},${config.mcpClientRedirectUri},${scopes},1,1,'selected',now(),now()+interval '10 minutes')`;
    let selectedOwner=ownerId;
    // Session establishment is private setup only. It does not bypass the real
    // signed-query, flow, owner/agent or resource checks in the context handler.
    const fixtureAuth={...auth,api:{...auth.api,getSession:async()=>({user:{id:userId},session:{id:sessionId}})}} as unknown as typeof auth;
    app.setErrorHandler((error,_request,reply)=>reply.code(error instanceof HttpError?error.status:500).send({error:error instanceof HttpError?error.code:'INTERNAL_ERROR'}));
    registerAgentRoutes(app,{db,auth:fixtureAuth,config,async resolveOwner(){return {owner:{id:selectedOwner,authUserId:userId,admissionStatus:'admitted'}};},
      async requireOrigin(request){if(request.headers.origin!==config.publicOrigin)throw new HttpError(403,'ORIGIN_NOT_ALLOWED','Origin required');},
      async rateLimit(){},rateLimitMax:30,credentialRateLimitMax:30,preflightRateLimitMax:60,manualCredentialTtlSeconds:3600,
      agentResource:resource,agentPreflightUrl:`${config.publicOrigin}/api/agent/preflight`});
    const request={method:'POST' as const,url:'/api/owner/agents/oauth-consent-context',headers:{origin:config.publicOrigin},payload:{oauth_query:signedQuery}};
    const authority=async()=>(await client`SELECT
      (SELECT count(*)::int FROM oid_agent_access_grant) AS grants,
      (SELECT count(*)::int FROM oid_oauth_access_token) AS access,
      (SELECT count(*)::int FROM oid_oauth_refresh_token) AS refresh,
      (SELECT count(*)::int FROM oid_ledger_entry) AS ledger,
      (SELECT count(*)::int FROM oid_benchmark_run) AS runs,
      (SELECT jsonb_agg(to_jsonb(p) ORDER BY agent_id) FROM oid_agent_policy p) AS permissions`)[0];
    const before=await authority();
    const empty=await app.inject(request); assert.equal(empty.statusCode,200);
    assert.deepEqual(empty.json().financialPolicy,{revision:0,configured:false,allowCashShortfall:false,
      operationLimit:'0.000000',utcDayLimit:'0.000000',categoryLimits:{benchmark:'0.000000',forum:'0.000000'},token:'USDC',precision:6});
    assert.deepEqual(await authority(),before,'Reading context creates no usable grant, credential, run or financial effect');
    await client`INSERT INTO oid_agent_financial_policy(owner_id,agent_id,allow_cash_shortfall,operation_limit_units,utc_day_limit_units,category_limits,revision)
      VALUES(${ownerId},${agentId},true,1234567890123456789,9007199254740993000,'{"benchmark":"1.000001","forum":null}'::jsonb,7)`;
    const configured=await app.inject(request); assert.equal(configured.statusCode,200);
    assert.deepEqual(configured.json().financialPolicy,{revision:7,configured:true,allowCashShortfall:true,
      operationLimit:'1234567890123.456789',utcDayLimit:'9007199254740.993000',categoryLimits:{benchmark:'1.000001',forum:null},token:'USDC',precision:6});
    assert.equal(configured.json().agent.policyRevision,1,'Financial and action-permission revisions remain separate');
    assert.equal(configured.json().agent.permissions.training,true);
    selectedOwner=randomUUID();
    const foreign=await app.inject(request); assert.equal(foreign.statusCode,403); assert.equal(foreign.json().financialPolicy,undefined);
    selectedOwner=ownerId;
    const badOrigin=await app.inject({...request,headers:{origin:'https://foreign.invalid'}}); assert.equal(badOrigin.statusCode,403);
    assert.deepEqual(await authority(),before,'Configured/denied context reads do not mutate credentials, permissions or business rows');
    assert.equal((await client`SELECT count(*)::int AS count FROM oid_agent_financial_policy`)[0]!.count,1,'Unconfigured read must not create a default policy row');
  } finally {
    await app.close(); await client.end();
    await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await admin.end();
  }
});
