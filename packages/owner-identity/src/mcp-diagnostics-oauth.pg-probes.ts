import assert from 'node:assert/strict';
import { createHash,randomUUID } from 'node:crypto';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type postgres from 'postgres';
import type { OwnerDatabase } from './db.js';
import { createAgentConnectionInvalidationStore,externalConnectionAllowed,initializeAgentConnectionInvalidationState,reconcileAgentConnectionInvalidation } from './agent-connection-invalidation-state.js';
import { DIAGNOSTIC_CALLBACK,DIAGNOSTIC_CLIENT_ID,DIAGNOSTIC_SCOPE,consentDiagnosticAuthorization,createDiagnosticAuthorization,exchangeDiagnosticToken,getDiagnosticAuthorization,resolveDiagnosticOAuthPrincipal,validateDiagnosticAuthorization,validateDiagnosticTokenRequest } from './mcp-diagnostics-oauth.js';

// AICODE-NOTE: Called only inside the disposable database suite. Synthetic OAuth
// credentials stay in memory; this probes actual SQL and external antirollback files.
export async function diagnosticOAuthPgProbes(db:OwnerDatabase,client:postgres.Sql,p:{ownerId:string;agentId:string;connectionId:string}){
 const root=await mkdtemp(join(tmpdir(),'mcd-oauth-')),journalPath=join(root,'journal.json'),floorPath=join(root,'floor.json'),journalId=randomUUID();
 try{
  await initializeAgentConnectionInvalidationState({journalPath,floorPath,journalId});
  const invalidationStore=createAgentConnectionInvalidationStore({journalPath,floorPath,expectedJournalId:journalId});
  const config={publicOrigin:'https://bench.example',nodeEnv:'test',authSecret:'synthetic-diagnostic-helper-secret-not-live-123456',mcpTransportProfile:'remote-oauth-v1' as const};
  const d={db,config,invalidationStore},resource=config.publicOrigin+'/api/diagnostics',owner={ownerId:p.ownerId,authSessionId:randomUUID()};
  const userId=(await client`SELECT auth_user_id FROM oid_owner WHERE id=${p.ownerId}`)[0]!.auth_user_id;
  await client`INSERT INTO oid_auth_session(id,user_id,token,expires_at) VALUES(${owner.authSessionId},${userId},${randomUUID()},clock_timestamp()+interval '1 day')`;
  await client`UPDATE oid_agent_access_grant SET oauth_client_id='synthetic-native-client' WHERE id=${p.connectionId}`;
  await client`INSERT INTO oid_agent_oauth_authorization(id,operation_id,query_hash,owner_id,auth_user_id,auth_session_id,agent_id,grant_id,client_id,resource,redirect_uri,scopes,authorization_code_hash,access_generation,policy_revision,status,expires_at)
   VALUES(${randomUUID()},${randomUUID()},${randomUUID()},${p.ownerId},${userId},${owner.authSessionId},${p.agentId},${p.connectionId},'synthetic-native-client','https://bench.example/api/agent/mcp','http://127.0.0.1:38765/oauth/callback',ARRAY['agent:operate'],${randomUUID()},1,1,'approved',clock_timestamp()+interval '1 day')`;
  const verifier='synthetic-test-verifier-12345678901234567890123456789',challenge=createHash('sha256').update(verifier).digest('base64url');
  const authorization={client_id:DIAGNOSTIC_CLIENT_ID,redirect_uri:DIAGNOSTIC_CALLBACK,response_type:'code',code_challenge_method:'S256',code_challenge:challenge,state:'synthetic-diagnostic-state-12345',scope:DIAGNOSTIC_SCOPE,resource};
  for(const invalid of [{scope:'agent:operate'},{redirect_uri:'http://127.0.0.1:39999/stolen'},{resource:'https://foreign.invalid/api/diagnostics'},{code_challenge_method:'plain'}])assert.throws(()=>validateDiagnosticAuthorization(d,{...authorization,...invalid}));
  const ownRequest=await createDiagnosticAuthorization(d,authorization);
  const view=await getDiagnosticAuthorization(d,owner,ownRequest.requestId);assert.ok(view.agents.some(a=>a.agentId===p.agentId));
  await assert.rejects(getDiagnosticAuthorization(d,{...owner,ownerId:randomUUID()},ownRequest.requestId));
  await assert.rejects(getDiagnosticAuthorization(d,{...owner,authSessionId:randomUUID()},ownRequest.requestId));
  const approved=await consentDiagnosticAuthorization(d,owner,{requestId:ownRequest.requestId,operationId:'synthetic_diag_consent',approved:true,agentId:p.agentId,connectionId:p.connectionId});
  const code=new URL(approved.redirectUrl).searchParams.get('code')!;
  const tokenRequest={grant_type:'authorization_code',client_id:DIAGNOSTIC_CLIENT_ID,redirect_uri:DIAGNOSTIC_CALLBACK,resource,scope:DIAGNOSTIC_SCOPE,code,code_verifier:verifier};
  assert.throws(()=>validateDiagnosticTokenRequest(d,{...tokenRequest,scope:'agent:operate'}));
  await assert.rejects(exchangeDiagnosticToken(d,{...tokenRequest,code_verifier:'wrong-verifier-123456789012345678901234567890123456'}));
  const tokens=await exchangeDiagnosticToken(d,tokenRequest),principal=await resolveDiagnosticOAuthPrincipal(d,tokens.access_token);assert.equal(principal.connectionId,p.connectionId);
  await assert.rejects(exchangeDiagnosticToken(d,tokenRequest));
  await client`UPDATE oid_diagnostic_oauth_request SET code_used_at=NULL WHERE id=${ownRequest.requestId}`;
  await assert.rejects(exchangeDiagnosticToken(d,tokenRequest),'external code-consumption receipt must defeat restored SQL');
  await client`UPDATE oid_diagnostic_oauth_request SET code_used_at=clock_timestamp() WHERE id=${ownRequest.requestId}`;
  const refresh={grant_type:'refresh_token',client_id:DIAGNOSTIC_CLIENT_ID,resource,scope:DIAGNOSTIC_SCOPE,refresh_token:tokens.refresh_token};
  const renewed=await exchangeDiagnosticToken(d,refresh);await resolveDiagnosticOAuthPrincipal(d,renewed.access_token);await assert.rejects(exchangeDiagnosticToken(d,refresh));
  await client`UPDATE oid_agent_access_grant SET revoked_at=clock_timestamp() WHERE id=${p.connectionId}`;
  await assert.rejects(resolveDiagnosticOAuthPrincipal(d,renewed.access_token));
  await client`UPDATE oid_agent_access_grant SET revoked_at=NULL WHERE id=${p.connectionId}`;
  await client`UPDATE oid_agent SET access_generation=2 WHERE id=${p.agentId}`;
  await assert.rejects(resolveDiagnosticOAuthPrincipal(d,renewed.access_token));
  await client`UPDATE oid_agent SET access_generation=1 WHERE id=${p.agentId}`;
  const unavailableStore={...invalidationStore,async read():ReturnType<typeof invalidationStore.read>{throw new Error('synthetic external journal unavailable');}};
  await assert.rejects(resolveDiagnosticOAuthPrincipal({...d,invalidationStore:unavailableStore},renewed.access_token));
  await reconcileAgentConnectionInvalidation(db,invalidationStore);
  assert.equal((await client`SELECT revoked_at FROM oid_agent_access_grant WHERE id=${p.connectionId}`)[0]!.revoked_at,null,'helper refresh must not revoke solver connection');
  assert.equal(await externalConnectionAllowed(invalidationStore,{ownerId:p.ownerId,agentId:p.agentId,grantId:p.connectionId,accessGeneration:1},db),true);
  // Restoring consumed SQL refresh state while retaining the external journal
  // must fence the helper and leave the independent native connection usable.
  const consumedHash=createHash('sha256').update(tokens.refresh_token).digest('base64url');
  await client`UPDATE oid_diagnostic_oauth_token SET consumed_at=NULL WHERE verifier=${consumedHash}`;
  await assert.rejects(resolveDiagnosticOAuthPrincipal(d,renewed.access_token));
  await client`UPDATE oid_diagnostic_oauth_token SET consumed_at=clock_timestamp() WHERE verifier=${consumedHash}`;
  await invalidationStore.appendIntent({kind:'connection_revoke',operationId:'synthetic_helper_revoke',ownerId:p.ownerId,agentId:p.agentId,connectionId:principal.helperGrantId});
  await assert.rejects(resolveDiagnosticOAuthPrincipal(d,renewed.access_token));
  assert.equal(await externalConnectionAllowed(invalidationStore,{ownerId:p.ownerId,agentId:p.agentId,grantId:p.connectionId,accessGeneration:1},db),true);
  const freshRequest=await createDiagnosticAuthorization(d,authorization);await getDiagnosticAuthorization(d,owner,freshRequest.requestId);
  const freshApproval=await consentDiagnosticAuthorization(d,owner,{requestId:freshRequest.requestId,operationId:'synthetic_diag_consent_2',approved:true,agentId:p.agentId,connectionId:p.connectionId});
  const freshTokens=await exchangeDiagnosticToken(d,{...tokenRequest,code:new URL(freshApproval.redirectUrl).searchParams.get('code')!});
  await resolveDiagnosticOAuthPrincipal(d,freshTokens.access_token);
  await invalidationStore.appendIntent({kind:'agent_revoke',operationId:'synthetic_global_revoke',ownerId:p.ownerId,agentId:p.agentId,generationFloor:2});
  await assert.rejects(resolveDiagnosticOAuthPrincipal(d,freshTokens.access_token),'external global revoke must fence even stale SQL generation');
 }finally{await rm(root,{recursive:true,force:true});}
}
