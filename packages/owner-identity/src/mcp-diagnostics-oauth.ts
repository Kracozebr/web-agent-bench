import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { OwnerDatabase } from './db.js';
import type { OwnerIdentityConfig } from './config.js';
import { HttpError } from './http-error.js';
import { CONNECTION_ACCESS_TTL_SECONDS, CONNECTION_GRANT_TTL_SECONDS, agentOAuthResource } from './agent-connection-profile.js';
import { externalConnectionAllowed, type AgentConnectionInvalidationStore } from './agent-connection-invalidation-state.js';

export const DIAGNOSTIC_CLIENT_ID = 'w3bench-diagnostics-helper-v1';
export const DIAGNOSTIC_CALLBACK = 'http://127.0.0.1:38766/diagnostics/callback';
export const DIAGNOSTIC_SCOPE = 'diagnostics:write offline_access';
export interface DiagnosticOAuthDependencies {
  db: OwnerDatabase;
  config: Pick<OwnerIdentityConfig, 'publicOrigin'|'nodeEnv'|'authSecret'|'mcpTransportProfile'>;
  invalidationStore?: AgentConnectionInvalidationStore;
}
export interface DiagnosticOAuthOwner { ownerId: string; authSessionId: string }
export interface DiagnosticOAuthPrincipal { ownerId: string; agentId: string; connectionId: string; helperGrantId: string }
type Executor = Pick<OwnerDatabase, 'execute'>;
type Grant = { id:string; owner_id:string; agent_id:string; connection_id:string; access_generation:number };
const UUID=z.string().uuid();
const OP=z.string().regex(/^[A-Za-z0-9_-]{12,128}$/);
const CODE=/^[A-Za-z0-9_-]{43}$/;
const hash=(s:string)=>createHash('sha256').update(s).digest('base64url');
const rows=<T>(v:unknown)=>v as T[];
const first=<T>(v:unknown)=>rows<T>(v)[0];
const denied=()=>new HttpError(400,'invalid_grant','Reauthorize the diagnostic helper');
const safeEqual=(a:string,b:string)=>a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const resource=(d:DiagnosticOAuthDependencies)=>`${d.config.publicOrigin}/api/diagnostics`;

export function diagnosticOAuthProfile(config:DiagnosticOAuthDependencies['config']) {
  const u=new URL(config.publicOrigin);
  if(u.origin!==config.publicOrigin||u.username||u.password||
      (u.protocol!=='https:'&&!(config.nodeEnv!=='production'&&u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname))))
    throw new HttpError(503,'DIAGNOSTIC_ORIGIN_UNAVAILABLE','Diagnostic OAuth requires HTTPS or an explicit loopback development origin');
  return {clientId:DIAGNOSTIC_CLIENT_ID,clientName:'Web3 Agent Bench diagnostic helper',
    resource:`${u.origin}/api/diagnostics`,scopes:DIAGNOSTIC_SCOPE.split(' '),redirectUri:DIAGNOSTIC_CALLBACK,
    authorizationEndpointUrl:`${u.origin}/api/diagnostics/oauth/authorize`,tokenEndpointUrl:`${u.origin}/api/diagnostics/oauth/token`};
}

const authorizationSchema=z.object({client_id:z.literal(DIAGNOSTIC_CLIENT_ID),redirect_uri:z.literal(DIAGNOSTIC_CALLBACK),
  response_type:z.literal('code'),code_challenge_method:z.literal('S256'),code_challenge:z.string().regex(CODE),
  state:z.string().regex(/^[A-Za-z0-9_-]{16,512}$/),scope:z.literal(DIAGNOSTIC_SCOPE),resource:z.string().max(2048)}).strict();
export function validateDiagnosticAuthorization(d:DiagnosticOAuthDependencies, input:unknown) {
  diagnosticOAuthProfile(d.config);
  const parsed=authorizationSchema.safeParse(input);
  if(!parsed.success||parsed.data.resource!==resource(d))throw new HttpError(400,'INVALID_DIAGNOSTIC_AUTHORIZATION','Diagnostic OAuth request is invalid');
  return parsed.data;
}

export async function createDiagnosticAuthorization(d:DiagnosticOAuthDependencies,input:unknown) {
  const p=validateDiagnosticAuthorization(d,input);
  return d.db.transaction(async tx=>{
    await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('diagnostic-oauth-request-cap'))`);
    // Expired OAuth challenges are not diagnostic evidence. Never retain raw tokens.
    await tx.execute(sql`DELETE FROM oid_diagnostic_oauth_request WHERE expires_at<clock_timestamp()-interval '1 day'`);
    const n=first<{n:number}>(await tx.execute(sql`SELECT count(*)::int AS n FROM oid_diagnostic_oauth_request`))!.n;
    if(n>=4096)throw new HttpError(429,'DIAGNOSTIC_AUTHORIZATION_CAPACITY','Diagnostic authorization is at capacity');
    const id=randomUUID();
    await tx.execute(sql`INSERT INTO oid_diagnostic_oauth_request(id,challenge,state,resource) VALUES(${id}::uuid,${p.code_challenge},${p.state},${p.resource})`);
    return {requestId:id,consentPath:`/diagnostics/connect?requestId=${id}`};
  });
}

async function activeNative(d:DiagnosticOAuthDependencies,executor:Executor,ownerId:string,connectionId:string) {
  const g=first<{id:string;owner_id:string;agent_id:string;access_generation:number;expires_at:Date}>(await executor.execute(sql`
    SELECT g.id,g.owner_id,g.agent_id,g.access_generation,g.expires_at FROM oid_agent_access_grant g
    JOIN oid_agent a ON a.id=g.agent_id AND a.owner_id=g.owner_id JOIN oid_owner o ON o.id=g.owner_id
    JOIN oid_agent_oauth_authorization c ON c.grant_id=g.id AND c.status='approved'
    WHERE g.id=${connectionId}::uuid AND g.owner_id=${ownerId}::uuid AND g.source='oauth' AND g.role='agent'
      AND g.resource=${agentOAuthResource(d.config)} AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp()
      AND a.access_revoked_at IS NULL AND a.access_generation=g.access_generation AND o.admission_status='admitted'
      AND c.owner_id=g.owner_id AND c.agent_id=g.agent_id AND c.access_generation=g.access_generation
      AND c.resource=g.resource AND c.client_id=g.oauth_client_id AND c.authorization_code_hash IS NOT NULL`));
  if(!g||!(await externalConnectionAllowed(d.invalidationStore,{ownerId:g.owner_id,agentId:g.agent_id,grantId:g.id,accessGeneration:g.access_generation},d.db)))throw denied();
  return g;
}

export async function getDiagnosticAuthorization(d:DiagnosticOAuthDependencies,owner:DiagnosticOAuthOwner,requestId:string) {
  if(!UUID.safeParse(requestId).success)throw denied();
  return d.db.transaction(async tx=>{
    const r=first<{id:string;expires_at:Date;owner_id:string|null;auth_session_id:string|null}>(await tx.execute(sql`
      SELECT id,expires_at,owner_id,auth_session_id FROM oid_diagnostic_oauth_request WHERE id=${requestId}::uuid
      AND expires_at>clock_timestamp() AND status='pending' FOR UPDATE`));
    if(!r||(r.owner_id&&r.owner_id!==owner.ownerId)||(r.auth_session_id&&r.auth_session_id!==owner.authSessionId))throw denied();
    await tx.execute(sql`UPDATE oid_diagnostic_oauth_request SET owner_id=${owner.ownerId}::uuid,auth_session_id=${owner.authSessionId} WHERE id=${requestId}::uuid`);
    const candidates=rows<{agent_id:string;name:string;connection_id:string}>(await tx.execute(sql`
      SELECT a.id AS agent_id,a.name,g.id AS connection_id FROM oid_agent a JOIN oid_agent_access_grant g ON g.agent_id=a.id
      WHERE a.owner_id=${owner.ownerId}::uuid AND g.owner_id=a.owner_id AND g.source='oauth' AND g.revoked_at IS NULL
      AND g.expires_at>clock_timestamp() AND g.access_generation=a.access_generation AND a.access_revoked_at IS NULL ORDER BY a.created_at,g.created_at`));
    const agents=new Map<string,{agentId:string;name:string;connections:Array<{connectionId:string;label:string}>}>();
    for(const c of candidates){try{await activeNative(d,tx,owner.ownerId,c.connection_id);}catch{continue;}
      const a=agents.get(c.agent_id)??{agentId:c.agent_id,name:c.name,connections:[]};a.connections.push({connectionId:c.connection_id,label:'Existing OAuth connection'});agents.set(c.agent_id,a);}
    return {requestId,clientName:'Web3 Agent Bench diagnostic helper',scopes:DIAGNOSTIC_SCOPE.split(' '),expiresAt:r.expires_at,agents:[...agents.values()]};
  });
}

const consentSchema=z.object({requestId:UUID,operationId:OP,approved:z.boolean(),agentId:UUID.optional(),connectionId:UUID.optional()}).strict();
function codeFor(d:DiagnosticOAuthDependencies,requestId:string,grantId:string){return createHmac('sha256',d.config.authSecret).update(`diagnostic-code:${requestId}:${grantId}`).digest('base64url');}
export async function consentDiagnosticAuthorization(d:DiagnosticOAuthDependencies,owner:DiagnosticOAuthOwner,input:unknown) {
  const parsed=consentSchema.safeParse(input);if(!parsed.success)throw denied();const p=parsed.data;
  const payloadHash=hash(JSON.stringify({approved:p.approved,agentId:p.agentId??null,connectionId:p.connectionId??null}));
  return d.db.transaction(async tx=>{
    const r=first<{id:string;state:string;resource:string;status:string;owner_id:string|null;auth_session_id:string|null;consent_operation_id:string|null;consent_hash:string|null;helper_grant_id:string|null}>(await tx.execute(sql`
      SELECT * FROM oid_diagnostic_oauth_request WHERE id=${p.requestId}::uuid AND expires_at>clock_timestamp() FOR UPDATE`));
    if(!r||r.owner_id!==owner.ownerId||r.auth_session_id!==owner.authSessionId)throw denied();
    if(r.status!=='pending'&&(r.consent_operation_id!==p.operationId||r.consent_hash!==payloadHash))throw new HttpError(409,'IDEMPOTENCY_CONFLICT','Diagnostic consent operation changed');
    const url=new URL(DIAGNOSTIC_CALLBACK);url.searchParams.set('state',r.state);
    if(!p.approved){
      if(r.status==='pending')await tx.execute(sql`UPDATE oid_diagnostic_oauth_request SET status='denied',consent_operation_id=${p.operationId},consent_hash=${payloadHash} WHERE id=${p.requestId}::uuid`);
      url.searchParams.set('error','access_denied');return {redirectUrl:url.href};
    }
    if(!p.agentId||!p.connectionId)throw denied();
    const native=await activeNative(d,tx,owner.ownerId,p.connectionId);if(native.agent_id!==p.agentId)throw denied();
    const grantId=r.helper_grant_id??randomUUID(),code=codeFor(d,p.requestId,grantId);
    if(r.status==='pending'){
      await tx.execute(sql`INSERT INTO oid_diagnostic_oauth_grant(id,owner_id,agent_id,connection_id,access_generation,expires_at)
        VALUES(${grantId}::uuid,${owner.ownerId}::uuid,${p.agentId}::uuid,${p.connectionId}::uuid,${native.access_generation},
        LEAST(${native.expires_at},clock_timestamp()+${CONNECTION_GRANT_TTL_SECONDS}::integer*interval '1 second'))`);
      await tx.execute(sql`UPDATE oid_diagnostic_oauth_request SET status='approved',consent_operation_id=${p.operationId},consent_hash=${payloadHash},helper_grant_id=${grantId}::uuid,code_hash=${hash(code)} WHERE id=${p.requestId}::uuid`);
      await tx.execute(sql`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,subject_owner_id,metadata)
        VALUES(${randomUUID()}::uuid,'diagnostics.helper.consent',${p.operationId},${owner.ownerId}::uuid,${owner.ownerId}::uuid,
        ${JSON.stringify({agentId:p.agentId,connectionId:p.connectionId,helperGrantId:grantId,scope:'diagnostics:write'})}::jsonb)`);
    }
    url.searchParams.set('code',code);return {redirectUrl:url.href};
  });
}

async function activeHelper(d:DiagnosticOAuthDependencies,executor:Executor,grantId:string):Promise<Grant> {
  const g=first<Grant>(await executor.execute(sql`SELECT id,owner_id,agent_id,connection_id,access_generation FROM oid_diagnostic_oauth_grant
    WHERE id=${grantId}::uuid AND revoked_at IS NULL AND expires_at>clock_timestamp()`));
  if(!g)throw denied();const native=await activeNative(d,executor,g.owner_id,g.connection_id);
  if(native.agent_id!==g.agent_id||native.access_generation!==g.access_generation)throw denied();
  if(d.invalidationStore){const s=await d.invalidationStore.read();
    if(s.events.some(e=>e.ownerId===g.owner_id&&e.agentId===g.agent_id&&e.kind==='connection_revoke'&&e.connectionId===g.id))throw denied();
    for(const e of s.events.filter(e=>e.ownerId===g.owner_id&&e.agentId===g.agent_id&&e.kind==='diagnostic_refresh_consume'&&e.connectionId===g.id)){
      const consumed=first(await executor.execute(sql`SELECT verifier FROM oid_diagnostic_oauth_token WHERE verifier=${e.consumedRefreshHash!} AND grant_id=${g.id}::uuid AND kind='refresh' AND consumed_at IS NOT NULL`));
      if(!consumed)throw denied();
    }
  }
  return g;
}

export function validateDiagnosticTokenRequest(d:DiagnosticOAuthDependencies,input:unknown) {
  const p=z.object({grant_type:z.enum(['authorization_code','refresh_token']),client_id:z.literal(DIAGNOSTIC_CLIENT_ID),
    resource:z.string().max(2048),scope:z.literal(DIAGNOSTIC_SCOPE).optional(),redirect_uri:z.literal(DIAGNOSTIC_CALLBACK).optional(),
    code:z.string().regex(CODE).optional(),code_verifier:z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/).optional(),
    refresh_token:z.string().regex(/^mcd_r_[A-Za-z0-9_-]{43}$/).optional()}).strict().safeParse(input);
  if(!p.success||p.data.resource!==resource(d))throw denied();
  if(p.data.grant_type==='authorization_code'&&(!p.data.code||!p.data.code_verifier||p.data.redirect_uri!==DIAGNOSTIC_CALLBACK||p.data.refresh_token)||
     p.data.grant_type==='refresh_token'&&(!p.data.refresh_token||p.data.code||p.data.code_verifier))throw denied();
  return p.data;
}

export async function exchangeDiagnosticToken(d:DiagnosticOAuthDependencies,input:unknown) {
  const p=validateDiagnosticTokenRequest(d,input);
  return d.db.transaction(async tx=>{
    let g:Grant;
    if(p.grant_type==='authorization_code'){
      const r=first<{id:string;challenge:string;helper_grant_id:string;code_used_at:Date|null}>(await tx.execute(sql`
        SELECT id,challenge,helper_grant_id,code_used_at FROM oid_diagnostic_oauth_request WHERE code_hash=${hash(p.code!)}
        AND status='approved' AND expires_at>clock_timestamp() FOR UPDATE`));
      if(!r||r.code_used_at||!safeEqual(r.challenge,hash(p.code_verifier!)))throw denied();g=await activeHelper(d,tx,r.helper_grant_id);
      const consumedHash=hash(p.code!);
      if(d.invalidationStore){const state=await d.invalidationStore.read();
        if(state.events.some(e=>e.kind==='diagnostic_code_consume'&&e.connectionId===g.id&&e.consumedRefreshHash===consumedHash))throw denied();
        await d.invalidationStore.appendIntent({kind:'diagnostic_code_consume',operationId:`diagnostic-code:${r.id}`,ownerId:g.owner_id,agentId:g.agent_id,connectionId:g.id,consumedRefreshHash:consumedHash});}
      await tx.execute(sql`UPDATE oid_diagnostic_oauth_request SET code_used_at=clock_timestamp() WHERE id=${r.id}::uuid`);
    }else{
      const tokenHash=hash(p.refresh_token!);
      const r=first<{grant_id:string;consumed_at:Date|null}>(await tx.execute(sql`SELECT grant_id,consumed_at FROM oid_diagnostic_oauth_token
        WHERE verifier=${tokenHash} AND kind='refresh' AND expires_at>clock_timestamp() FOR UPDATE`));
      if(!r||r.consumed_at)throw denied();g=await activeHelper(d,tx,r.grant_id);
      await d.invalidationStore?.appendIntent({kind:'diagnostic_refresh_consume',operationId:`diagnostic-refresh:${tokenHash}`,ownerId:g.owner_id,agentId:g.agent_id,connectionId:g.id,consumedRefreshHash:tokenHash});
      await tx.execute(sql`UPDATE oid_diagnostic_oauth_token SET consumed_at=clock_timestamp() WHERE verifier=${tokenHash}`);
    }
    const access='mcd_a_'+randomBytes(32).toString('base64url'),refresh='mcd_r_'+randomBytes(32).toString('base64url');
    await tx.execute(sql`UPDATE oid_diagnostic_oauth_grant SET expires_at=LEAST((SELECT expires_at FROM oid_agent_access_grant WHERE id=${g.connection_id}::uuid),clock_timestamp()+${CONNECTION_GRANT_TTL_SECONDS}::integer*interval '1 second') WHERE id=${g.id}::uuid`);
    await tx.execute(sql`INSERT INTO oid_diagnostic_oauth_token(verifier,grant_id,kind,expires_at) VALUES
      (${hash(access)},${g.id}::uuid,'access',clock_timestamp()+${CONNECTION_ACCESS_TTL_SECONDS}::integer*interval '1 second'),
      (${hash(refresh)},${g.id}::uuid,'refresh',clock_timestamp()+${CONNECTION_GRANT_TTL_SECONDS}::integer*interval '1 second')`);
    return {access_token:access,refresh_token:refresh,token_type:'Bearer',expires_in:CONNECTION_ACCESS_TTL_SECONDS,scope:DIAGNOSTIC_SCOPE,
      diagnosticBinding:{agentId:g.agent_id,connectionId:g.connection_id}};
  });
}

export async function resolveDiagnosticOAuthPrincipal(d:DiagnosticOAuthDependencies,bearer:string):Promise<DiagnosticOAuthPrincipal> {
  if(!/^mcd_a_[A-Za-z0-9_-]{43}$/.test(bearer))throw new HttpError(401,'DIAGNOSTIC_AUTH_REQUIRED','Valid diagnostic helper authorization is required');
  const t=first<{grant_id:string}>(await d.db.execute(sql`SELECT grant_id FROM oid_diagnostic_oauth_token
    WHERE verifier=${hash(bearer)} AND kind='access' AND consumed_at IS NULL AND expires_at>clock_timestamp()`));
  if(!t)throw new HttpError(401,'DIAGNOSTIC_AUTH_REQUIRED','Valid diagnostic helper authorization is required');
  let g:Grant;try{g=await activeHelper(d,d.db,t.grant_id);}catch{throw new HttpError(401,'DIAGNOSTIC_AUTH_REQUIRED','Reauthorize the diagnostic helper');}
  return {ownerId:g.owner_id,agentId:g.agent_id,connectionId:g.connection_id,helperGrantId:g.id};
}
