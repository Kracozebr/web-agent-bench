/** Physical diagnostic allocation producer. All allocations use actual HTTP;
 * SQL writes below create explicitly synthetic authorization/link fixtures only.
 * No application quota totals are seeded or used as acceptance observations. */
import assert from 'node:assert/strict';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {resolve,relative,sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import http from 'node:http';
import pg from 'pg';
import {parseMcdWireText} from './mcp-diagnostics-wire.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=v=>JSON.stringify(Array.isArray(v)?v.map(x=>JSON.parse(canonical(x))):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).filter(([,x])=>x!==undefined).sort(([a],[b])=>a.localeCompare(b,'en')).map(([k,x])=>[k,JSON.parse(canonical(x))])):v);
const digest=v=>sha(canonical(v));
const now=()=>new Date().toISOString();
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const finiteEvent=()=>({eventId:randomUUID(),source:'client',stage:'client_validation',tool:'runs.task_action',outcome:'success',startedAt:now(),completedAt:now(),durationMs:0});
const successful=r=>r.httpStatus>=200&&r.httpStatus<300;

function validateInput(input){
 const db=new URL(input.databaseUrl),observer=new URL(input.observerDatabaseUrl),origin=new URL(input.apiOrigin??input.publicOrigin);
 assert.equal(db.hostname,'postgres');assert.equal(db.username,'oid_owner');assert.match(db.pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);
 assert.equal(observer.pathname,db.pathname);assert.equal(observer.username,'oid_observer');
 assert.equal(origin.protocol,'http:');assert.equal(origin.hostname,'127.0.0.1');assert.equal(origin.pathname,'/');
 assert(input.observer&&input.writer&&typeof input.captureMcdVariant==='function');return {origin:origin.origin,databaseName:db.pathname.slice(1)};
}

export function createMcdCapacityHttp({origins,sourceCount=64}){
 assert(Array.isArray(origins)&&origins.length>0);assert.equal(sourceCount,64);
 const endpoints=origins.map(value=>{const u=new URL(value);assert.equal(u.protocol,'http:');assert.equal(u.hostname,'127.0.0.1');return u;});
 let sequence=0;const sourceObservations=[];
 return {sourceObservations,async request(path,{method='POST',body,bodyBytes,bearer}={}){
  assert.match(path,/^\/api\/(?:diagnostics|agent\/mcp|owner\/diagnostics)/);
  const n=sequence++,endpoint=endpoints[n%endpoints.length],localAddress='127.0.0.'+(2+n%sourceCount);
  const payload=bodyBytes??(method==='GET'&&body===undefined?Buffer.alloc(0):Buffer.from(JSON.stringify(body??{})));
  return new Promise((done,reject)=>{
   const mcp=path==='/api/agent/mcp';
   const req=http.request(new URL(path,endpoint),{method,localAddress,headers:{'content-type':'application/json',accept:mcp?'application/json, text/event-stream':'application/json',...(mcp?{'mcp-protocol-version':'2025-06-18'}:{}),...(bearer?{authorization:'Bearer '+bearer}:{}),'content-length':payload.length}},response=>{
    const chunks=[];let size=0;response.on('data',part=>{size+=part.length;if(size>1024*1024){response.destroy();reject(new Error('mcd_capacity_response_bound'));}else chunks.push(part);});
    response.on('end',()=>{const text=Buffer.concat(chunks).toString('utf8'),decoded=mcp?parseMcdWireText(text,response.headers['content-type']):null;let data=decoded?.value??{};if(!mcp)try{data=JSON.parse(text);}catch{}
     const record={httpStatus:response.statusCode,...(typeof data?.error?.code==='string'&&/^[A-Za-z_]{1,80}$/.test(data.error.code)?{errorCode:data.error.code}:{}),
      ...(response.headers['x-w3bench-diagnostic-capture']?{captureState:response.headers['x-w3bench-diagnostic-capture']}:{}),
      ...(mcp?{wire:decoded.proof,resultKind:Array.isArray(data.result?.tools)?'tools':data.result!==undefined?'other':'none',...(Array.isArray(data.result?.tools)?{toolCount:data.result.tools.length}:{})}:{}),
      ...(data.caseId?{receipt:data}:{}),transport:{localAddress:req.socket.localAddress,remoteAddress:req.socket.remoteAddress,remotePort:req.socket.remotePort}};
     sourceObservations.push({sequence:n,...record.transport,httpStatus:record.httpStatus,...(record.errorCode?{errorCode:record.errorCode}:{}),...(mcp?{wire:record.wire,resultKind:record.resultKind,...(record.toolCount!==undefined?{toolCount:record.toolCount}:{}),...(record.captureState?{captureState:record.captureState}:{})}:{})});done(record);
    });
   });req.setTimeout(30000,()=>req.destroy(new Error('mcd_capacity_http_timeout')));req.on('error',()=>reject(new Error('mcd_capacity_http_transport_failed')));req.end(payload);
  });
 }};
}

export async function observeMcdAllocations(observer,{ownerId,anonymous=false}={}){
 return observer.read(async c=>{
  const filter=ownerId?'c.owner_id=$1::uuid':anonymous?'e.case_id IS NULL':'true',values=ownerId?[ownerId]:[];
  const groups=[];
  for(const kind of ['event','batch','segment','case']){
   let from,where;
   if(kind==='event'){from='oid_mcp_diagnostic_event e LEFT JOIN oid_mcp_diagnostic_case c ON c.id=e.case_id';where=filter;}
   else if(anonymous){groups.push({kind,count:0,sumBytes:0,maxBytes:0,rowsSha256:sha('')});continue;}
   else{from=kind==='case'?'oid_mcp_diagnostic_case c':`oid_mcp_diagnostic_${kind} r JOIN oid_mcp_diagnostic_case c ON c.id=r.case_id`;where=ownerId?'c.owner_id=$1::uuid':'true';}
   const row=kind==='case'?'c':kind==='event'?'e':'r',weight=kind==='event'?"octet_length(convert_to(regexp_replace(e.envelope::text,'[[:space:]]','','g'),'UTF8'))":kind==='segment'?'256':'512';
   // The pinned finite schema permits no whitespace in string values. Removing
   // JSONB's display whitespace therefore yields the actual canonical byte
   // length independently of application byte_count/quota usage projections.
   {
    const projection=kind==='case'?"jsonb_build_object('id',c.id,'ownerId',c.owner_id,'agentId',c.agent_id,'connectionId',c.connection_id,'diagnosticSessionId',c.diagnostic_session_id,'intentId',c.intent_id,'createdAt',c.created_at)":`to_jsonb(${row})`;
    const r=(await c.query(`SELECT count(*)::int AS count,COALESCE(sum(${weight}),0)::bigint::text AS bytes,COALESCE(max(${weight}),0)::int AS maximum,encode(sha256(convert_to(COALESCE(string_agg(${projection}::text,E'\\n' ORDER BY ${projection}::text),''),'UTF8')),'hex') AS hash FROM ${from} WHERE ${where}`,values)).rows[0];
    groups.push({kind,count:r.count,sumBytes:Number(r.bytes),maxBytes:r.maximum,rowsSha256:r.hash});
   }
  }
  return {source:'postgresql_observer',queryKind:'diagnostic_allocation_aggregates',observer:{role:'oid_observer',readOnly:true},scope:ownerId?{ownerId}:anonymous?'anonymous':'deployment',allocationByteBasis:'SQL UTF8 JSONB lexical whitespace removal under pinned finite whitespace-free string vocabulary; actual row counts and fixed metadata charges',groups,reservedGroups:[]};
 });
}

const occupancy=value=>value.groups.reduce((r,g)=>({rows:r.rows+(g.kind==='case'?0:g.count),bytes:r.bytes+g.sumBytes,cases:r.cases+(g.kind==='case'?g.count:0)}),{rows:0,bytes:0,cases:0});

async function seedIdentity(client,publicOrigin,index){
 const ownerId=randomUUID(),agentId=randomUUID(),connectionId=randomUUID(),authUserId=randomUUID(),authSessionId=randomUUID(),helperId=randomUUID(),bearer='mcd_a_'+randomBytes(32).toString('base64url');
 const codeHash=randomBytes(32).toString('base64url'),resource=publicOrigin+'/api/agent/mcp';
 await client.query('BEGIN');try{
  await client.query("INSERT INTO oid_auth_user(id,name,email,email_verified) VALUES($1,'Synthetic MCD capacity owner',$2,true)",[authUserId,authUserId+'@example.invalid']);
  await client.query("INSERT INTO oid_owner(id,auth_user_id,admission_status) VALUES($1,$2,'admitted')",[ownerId,authUserId]);
  await client.query("INSERT INTO oid_agent(id,owner_id,name) VALUES($1,$2,$3)",[agentId,ownerId,'Synthetic capacity fixture '+index]);
  await client.query('INSERT INTO oid_auth_session(id,user_id,token,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval \'1 day\')',[authSessionId,authUserId,randomUUID()]);
  await client.query("INSERT INTO oid_agent_access_grant(id,owner_id,agent_id,operation_id,source,oauth_client_id,resource,role,access_generation,expires_at) VALUES($1,$2,$3,$4,'oauth','synthetic-mcd-capacity-client',$5,'agent',1,clock_timestamp()+interval '1 day')",[connectionId,ownerId,agentId,randomUUID(),resource]);
  await client.query("INSERT INTO oid_agent_oauth_authorization(id,operation_id,query_hash,owner_id,auth_user_id,auth_session_id,agent_id,grant_id,client_id,resource,redirect_uri,scopes,authorization_code_hash,access_generation,policy_revision,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'synthetic-mcd-capacity-client',$9,'http://127.0.0.1:38765/oauth/callback',ARRAY['agent:operate'],$10,1,1,'approved',clock_timestamp()+interval '1 day')",[randomUUID(),randomUUID(),randomUUID(),ownerId,authUserId,authSessionId,agentId,connectionId,resource,codeHash]);
  await client.query("INSERT INTO oid_diagnostic_oauth_grant(id,owner_id,agent_id,connection_id,access_generation,expires_at) VALUES($1,$2,$3,$4,1,clock_timestamp()+interval '1 day')",[helperId,ownerId,agentId,connectionId]);
  await client.query("INSERT INTO oid_diagnostic_oauth_token(verifier,grant_id,kind,expires_at) VALUES($1,$2,'access',clock_timestamp()+interval '1 day')",[createHash('sha256').update(bearer).digest('base64url'),helperId]);
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e;}
 return {ownerId,agentId,connectionId,helperGrantId:helperId,bearer,cases:[],index};
}

async function rawReference(input,label,bytes){
 assert(bytes.length<=8*1024*1024+1);const path=resolve(input.writer.directory,label+'-'+randomUUID()+'.json');await writeFile(path,bytes,{flag:'wx',mode:0o600});return {path:relative(input.repoRoot,path).split(sep).join('/'),sha256:sha(bytes)};
}

export function deriveMcdEnvelopeMaximum(schema){
 if(schema.enum)return schema.enum.reduce((a,b)=>Buffer.byteLength(canonical(b))>Buffer.byteLength(canonical(a))?b:a);
 if(schema.type==='object'){assert.equal(schema.additionalProperties,false);const maximum=Object.fromEntries(Object.entries(schema.properties).map(([k,v])=>[k,deriveMcdEnvelopeMaximum(v)]));if('clientRunStatus' in maximum&&'clientRunObservedAt' in maximum){maximum.source='client';maximum.stage='client_runtime';maximum.outcome='error';}return maximum;}
 if(schema.type==='array'){assert(Number.isInteger(schema.maxItems));return Array.from({length:schema.maxItems},()=>deriveMcdEnvelopeMaximum(schema.items));}
 if(schema.type==='integer')return String(schema.minimum).length>String(schema.maximum).length?schema.minimum:schema.maximum;
 if(schema.format==='uuid')return randomUUID();if(schema.format==='date-time')return '2026-11-02T00:00:00.000Z';
 if(schema.pattern==='^[a-f0-9]{64}$')return 'a'.repeat(64);throw Error('mcd_unbounded_schema_maximum');
}

async function seedMaximumLink(client,actor){
 const intentId=randomUUID(),runId=randomUUID(),actionId=randomUUID(),pin=digest({classification:'synthetic_diagnostic_link_only_no_benchmark_execution',runId});
 await client.query("INSERT INTO oid_run_launch_intent(id,owner_id,agent_id,operation_id,payload_hash,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,owner_policy_revision,agent_policy_revision,status,expires_at) VALUES($1,$2,$3,$4,$5,'ranked',ARRAY['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'],'synthetic-mcd-link-only','synthetic-not-benchmark',$5,$5,$5,0,0,0,1,'cancelled',clock_timestamp()+interval '1 day')",[intentId,actor.ownerId,actor.agentId,randomUUID(),pin]);
 await client.query("INSERT INTO oid_benchmark_run(id,intent_id,owner_id,agent_id,mode,task_ids,release_identity,benchmark_version,manifest_hash,benchmark_hash,policy_hash,quote_price_units,cash_ceiling_units,access_generation,agent_policy_revision,status,queue_deadline) VALUES($1,$2,$3,$4,'ranked',ARRAY['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'],'synthetic-mcd-link-only','synthetic-not-benchmark',$5,$5,$5,0,0,1,1,'cancelled',clock_timestamp()+interval '1 day')",[runId,intentId,actor.ownerId,actor.agentId,pin]);
 await client.query("INSERT INTO oid_run_task(run_id,task_index,task_id,status) VALUES($1,11,'U1','queued')",[runId]);
 await client.query("INSERT INTO oid_run_task_action(id,run_id,task_index,owner_id,agent_id,access_generation,grant_id,task_id,environment_id,action_sequence,operation_id,payload_hash,action_kind,command_json) VALUES($1,$2,11,$3,$4,1,$5,'U1','synthetic-mcd-link-only',1,$6,$7,'inspect_catalog','{\"kind\":\"inspect_catalog\"}'::jsonb)",[actionId,runId,actor.ownerId,actor.agentId,actor.connectionId,randomUUID(),pin]);
 await client.query("INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES($1,'agent.connection.intent_bound',$2,$3,$4::jsonb)",[randomUUID(),'connection-intent:'+intentId,actor.ownerId,JSON.stringify({agentId:actor.agentId,connectionId:actor.connectionId})]);
 return {intentId,runId,actionId,mode:'ranked',taskIndex:11,taskId:'U1'};
}

async function capacityServer(input){
 const {origin}=validateInput(input),{observer,writer}=input;
 const owner=new pg.Client({connectionString:input.databaseUrl,application_name:'mcd-synthetic-auth-fixture-only'});await owner.connect();
 const transport=createMcdCapacityHttp({origins:input.replicaOrigins??[origin]});
 const identities=[],capacityProbes=[],variants=[],partial={};let phase='synthetic_fixture_setup',canonicalSpool;
 const write=(name,value)=>writer.write('capacity-'+name,value);
 const request=async(path,opts)=>{for(let n=0;n<3;n++){const r=await transport.request(path,opts);if(r.httpStatus!==429||r.errorCode==='DIAGNOSTICS_QUOTA_EXCEEDED')return r;await pause(61000);}throw Error('mcd_actual_ip_rate_limit_still_active');};
 const registration=async actor=>{const diagnosticSessionId=randomUUID(),intentId=actor.maximumLink&&actor.cases.length===0?actor.maximumLink.intentId:undefined;const response=await request('/api/diagnostics/cases',{bearer:actor.bearer,body:{diagnosticSessionId,...(intentId?{intentId}:{})}});if(successful(response)){actor.cases.push({id:response.receipt.caseId,sessionId:diagnosticSessionId,segmentId:randomUUID(),sequence:0,eventCount:0});}return response;};
 const send=async(actor,c,events,completion='open',managed=true)=>{const value={segmentId:c.segmentId,batchSequence:c.sequence,events,completion};
  if(managed&&c.managed){for(const event of events)assert.equal(c.managed.spool.append(c.segmentId,event),true);const staged=c.managed.spool.stageBatch(c.segmentId,{completion});assert.equal(staged?.payloadHash,digest(value));}
  const response=await request(`/api/diagnostics/cases/${c.id}/batches`,{bearer:actor.bearer,body:{...value,payloadHash:digest(value)}});if(successful(response)){c.sequence++;c.eventCount+=events.length;}return response;};
 const remember=async(limit,mode,scope,accepted,blocked,before)=>{
  const after=await observeMcdAllocations(observer,scope);capacityProbes.push({limit,mode,observationRef:await write(limit+'-before',before),afterObservationRef:await write(limit+'-after',after),blockingResponseRef:await write(limit+'-blocked',blocked),...(accepted?{acceptedResponseRef:await write(limit+'-accepted',accepted)}:{})});
 };
 try{
  // These fixtures grant diagnostics only; no benchmark execution, balance,
  // OAuth consent, economic result or native-client support is claimed.
  for(let i=0;i<33;i++)identities.push(await seedIdentity(owner,input.publicOrigin,i));
  partial.fixtureDeclaration=await write('synthetic-auth-fixtures',{classification:'synthetic_authorization_only_not_native_consent_or_benchmark_evidence',identities:identities.map(({ownerId,agentId,connectionId})=>({ownerId,agentId,connectionId}))});
  const first=identities[0];first.maximumLink=await seedMaximumLink(owner,first);let lastAccepted;
  phase='owner_case_registration';
  partial.maximumLinkFixtureRef=await write('synthetic-maximum-link',{classification:'cancelled_synthetic_run_task_action_link_only_no_outbox_no_execution_no_payment',ownerId:first.ownerId,agentId:first.agentId,...first.maximumLink});
  for(let i=0;i<128;i++){lastAccepted=await registration(first);assert(successful(lastAccepted));}
  const {openDiagnosticSpool}=await import('../../../tools/mcp-diagnostics-client.mjs');
  const spoolDirectory=resolve(input.repoRoot,'.local/mcd-canonical-outboxes',input.captureId);await mkdir(spoolDirectory,{recursive:true,mode:0o700});
  canonicalSpool=await openDiagnosticSpool({directory:spoolDirectory});const canonicalLocal=canonicalSpool.createCase({diagnosticSessionId:first.cases[0].sessionId,intentId:first.maximumLink.intentId,binding:{agentId:first.agentId,connectionId:first.connectionId}});
  canonicalSpool.bindRemote(canonicalLocal.local_id,{caseId:first.cases[0].id});first.cases[0].segmentId=canonicalSpool.createSegment(canonicalLocal.local_id);first.cases[0].managed={spool:canonicalSpool,localId:canonicalLocal.local_id};
  const contractPath='packages/owner-identity/src/mcp-diagnostics-contract.ts',contractSource=await readFile(resolve(input.repoRoot,contractPath));
  phase='actual_maximal_envelope_and_privacy';
  const contract=await import(pathToFileURL(resolve(input.repoRoot,contractPath)).href),{z}=createRequire(resolve(input.repoRoot,'packages/owner-identity/package.json'))('zod');
  const schema=z.toJSONSchema(contract.diagnosticEnvelopeSchema),maximum=deriveMcdEnvelopeMaximum(schema);maximum.actionId=first.maximumLink.actionId;maximum.taskIndex=11;maximum.taskId='U1';maximum.source='client';
  const maximumResponse=await send(first,first.cases[0],[maximum]);assert(successful(maximumResponse));
  partial.envelopeBound={schemaSourceRef:{path:contractPath,sha256:sha(contractSource)},schemaRef:await write('actual-zod-schema',schema),maximumEnvelopeRef:await write('maximum-envelope',maximum),maximumResponseRef:await write('maximum-envelope-response',maximumResponse)};
  partial.sizeProbes=[];
  const canary='mcd_synthetic_sensitive_CANARY_20261102_not_real_data';partial.syntheticCanaries=[canary];
  variants.push(await input.captureMcdVariant({name:'canaries_in_messages_keys_codes_identifiers',request:{method:'POST',path:'/api/diagnostics/cases/:caseId/batches',syntheticCanary:canary},observer,writer,execute:async()=>send(first,first.cases[0],[{...finiteEvent(),rawMessage:canary,errorCode:canary}],'open',false)}));
  variants.push(await input.captureMcdVariant({name:'maximal_envelope_and_strict_2048_2049_rejection',request:{method:'POST',path:'/api/diagnostics/cases/:caseId/batches',source:'actual maximum plus strict overlong-field inputs'},observer,writer,execute:async()=>{
   let result;for(const size of [2048,2049]){const base={...finiteEvent(),unsupportedPadding:''},initial=Buffer.byteLength(JSON.stringify(base));base.unsupportedPadding='x'.repeat(size-initial);const bytes=Buffer.from(JSON.stringify(base));assert.equal(bytes.length,size);result=await send(first,first.cases[0],[base],'open',false);partial.sizeProbes.push({kind:'envelope',bytes:size,inputRef:await rawReference(input,'strict-envelope-'+size,bytes),httpStatus:result.httpStatus});}return result;
  }}));
  partial.retainedSurfaces=[await write('initial-retained-diagnostics',await observer.diagnostics())];
  const {captureMcdSupplementBeforeCapacity}=await import('./mcp-diagnostics-supplement.mjs');
  partial.supplemental=await captureMcdSupplementBeforeCapacity(input);
  const ownerCaseBefore=await observeMcdAllocations(observer,{ownerId:first.ownerId}),ownerCaseBlock=await registration(first);
  await remember('ownerCases','exact_over',{ownerId:first.ownerId},lastAccepted,ownerCaseBlock,ownerCaseBefore);
  await remember('ownerBytes','dominated',{ownerId:first.ownerId},null,ownerCaseBlock,await observeMcdAllocations(observer,{ownerId:first.ownerId}));
  // Fill the actual deployment case ceiling, respecting every per-source-IP
  // limiter. Distinct localAddress sockets are real loopback clients, never
  // forwarded headers, disabled limits, synthetic usage counters or replicas.
  phase='deployment_case_registration';for(let a=1;a<identities.length;a++){
   for(let n=0;n<128;n++){const response=await registration(identities[a]);if(!successful(response)){assert.equal(response.errorCode,'DIAGNOSTICS_QUOTA_EXCEEDED');break;}lastAccepted=response;}
   input.onProgress?.({phase:'mcd_capacity_actual_http_cases',owners:a+1,cases:identities.reduce((n,o)=>n+o.cases.length,0)});
   const observed=await observeMcdAllocations(observer);if(occupancy(observed).cases===4096)break;
  }
  const deploymentCaseBefore=await observeMcdAllocations(observer),deploymentCaseBlock=await registration(identities.find(o=>o.cases.length<128)??identities.at(-1));
  await remember('deploymentCases','exact_over',{},lastAccepted,deploymentCaseBlock,deploymentCaseBefore);
  await remember('deploymentBytes','dominated',{},null,deploymentCaseBlock,await observeMcdAllocations(observer));
  // Independent anonymous ingress rows, including actual auth/parser failures.
  phase='anonymous_actual_ingress_capacity';let anon=await observeMcdAllocations(observer,{anonymous:true}),anonymousAccepted;
  assert(input.connection?.session?.useAccessToken,'real native OAuth connection required for accepted unbound anonymous allocation probes');
  while(occupancy(anon).rows<2048){anonymousAccepted=await input.connection.session.useAccessToken(bearer=>request('/api/agent/mcp',{bearer,body:{jsonrpc:'2.0',id:randomUUID(),method:'tools/list'}}));assert(successful(anonymousAccepted)&&anonymousAccepted.resultKind==='tools'&&anonymousAccepted.toolCount>0&&anonymousAccepted.wire.hasMcpResponse&&!anonymousAccepted.wire.resultIsError&&anonymousAccepted.wire.rpcErrorCode===null);anon=await observeMcdAllocations(observer,{anonymous:true});}
  const bucketBefore=await observer.query('SELECT bucket,dropped_count::text FROM oid_mcp_diagnostic_aggregate ORDER BY bucket');
  // AICODE-NOTE: Telemetry exhaustion must not reject a valid business request.
  // A malformed JSON failure is a parser control, not evidence of a quota cause.
  const anonymousBlock=await input.connection.session.useAccessToken(bearer=>request('/api/agent/mcp',{bearer,body:{jsonrpc:'2.0',id:randomUUID(),method:'tools/list'}}));
  assert.equal(anonymousBlock.httpStatus,200);assert.equal(anonymousBlock.captureState,'unavailable');assert.equal(anonymousBlock.resultKind,'tools');assert(anonymousBlock.toolCount>0&&anonymousBlock.wire.hasMcpResponse&&!anonymousBlock.wire.resultIsError&&anonymousBlock.wire.rpcErrorCode===null);
  const bucketAfter=await observer.query('SELECT bucket,dropped_count::text FROM oid_mcp_diagnostic_aggregate ORDER BY bucket');
  await remember('anonymousRows','exact_over',{anonymous:true},anonymousAccepted,anonymousBlock,anon);
  await remember('anonymousBytes','dominated',{anonymous:true},null,anonymousBlock,await observeMcdAllocations(observer,{anonymous:true}));
  const beforeBucketIds=new Set(bucketBefore.map(row=>row.bucket));
  partial.anonymousBuckets={before:bucketBefore.length,after:bucketAfter.length,newAllocationRows:bucketAfter.filter(row=>!beforeBucketIds.has(row.bucket)),beforeRef:await write('buckets-before',{source:'postgresql_observer',observer:observer.identity,rows:bucketBefore}),afterRef:await write('buckets-after',{source:'postgresql_observer',observer:observer.identity,rows:bucketAfter})};
  // One canonical case reaches 4096 actual envelopes before the one-over call.
  phase='canonical_case_event_capacity';const canonicalCase=first.cases[0];let canonicalAccepted;
  while(canonicalCase.eventCount<4096){canonicalAccepted=await send(first,canonicalCase,Array.from({length:Math.min(128,4096-canonicalCase.eventCount)},finiteEvent));assert(successful(canonicalAccepted));}
  const eventOver=await send(first,canonicalCase,[finiteEvent()],'open',false);assert.equal(eventOver.errorCode,'DIAGNOSTICS_QUOTA_EXCEEDED');
  const canonicalReceipt=await request(`/api/diagnostics/cases/${canonicalCase.id}/receipt?segmentId=${canonicalCase.segmentId}`,{method:'GET',bearer:first.bearer});assert(successful(canonicalReceipt));assert.equal(canonicalReceipt.receipt.reportCreated,true);
  canonicalSpool.acknowledge(canonicalLocal.local_id,canonicalReceipt.receipt);
  const pendingFinalBatch=canonicalSpool.stageBatch(canonicalCase.segmentId,{completion:'partial'});assert(pendingFinalBatch);
  const observedEvents=await observer.query('SELECT count(*)::int AS n FROM oid_mcp_diagnostic_event WHERE case_id=$1::uuid',[canonicalCase.id]);
  partial.canonicalCaseCounts={accepted:canonicalCase.eventCount,attempted:canonicalCase.eventCount+1,durable:observedEvents[0].n};
  // Add only allocations accepted by actual HTTP. Exact occupancy comes from
  // fresh independent rows; empty batches can reach a final one-row boundary.
  phase='owner_and_deployment_actual_row_capacity';let ownerRowProof=false,global=occupancy(await observeMcdAllocations(observer));
  for(const actor of identities){
   if(!actor.cases.length)continue;let current=occupancy(await observeMcdAllocations(observer,{ownerId:actor.ownerId})),latest;
   for(const c of actor.cases){
    while(current.rows<16384&&global.rows<131072&&c.eventCount<4096){
     const fixed=1+(c.sequence===0?1:0),left=Math.min(16384-current.rows,131072-global.rows);if(left<fixed)break;
     const count=Math.min(128,4096-c.eventCount,left-fixed);latest=await send(actor,c,Array.from({length:count},finiteEvent));assert(successful(latest));
     current.rows+=count+fixed;global.rows+=count+fixed;
    }
    if(current.rows===16384||global.rows===131072)break;
   }
   if(current.rows===16384&&!ownerRowProof){const before=await observeMcdAllocations(observer,{ownerId:actor.ownerId}),c=actor.cases.find(c=>c.sequence>0&&c.eventCount<4096)??actor.cases[0],block=await send(actor,c,[]);await remember('ownerRows','exact_over',{ownerId:actor.ownerId},latest,block,before);ownerRowProof=true;}
   input.onProgress?.({phase:'mcd_capacity_actual_http_rows',actualAllocatedRows:global.rows,ownerRows:current.rows});
   if(global.rows===131072){const before=await observeMcdAllocations(observer),c=actor.cases.find(c=>c.sequence>0&&c.eventCount<4096)??actor.cases[0],block=await send(actor,c,[]);await remember('deploymentRows','exact_over',{},latest,block,before);break;}
  }
  assert.equal(occupancy(await observeMcdAllocations(observer)).rows,131072);
  partial.capacityProbes=capacityProbes;
  partial.transportSourcesRef=await write('real-source-sockets',transport.sourceObservations);
  // No complete SC005 is emitted until the remaining actual local/UI schema,
  // bundle, parser/fault and concurrent-replica boundary parts are supplied.
  partial.allocationSources={server:{path:'packages/owner-identity/src/mcp-diagnostics-service.ts',sha256:sha(await readFile(resolve(input.repoRoot,'packages/owner-identity/src/mcp-diagnostics-service.ts')))},local:{path:'tools/mcp-diagnostics-client.mjs',sha256:sha(await readFile(resolve(input.repoRoot,'tools/mcp-diagnostics-client.mjs')))}};
  const result={server:partial,capacityProbes,variants,canonicalCaseCounts:partial.canonicalCaseCounts,anonymousBuckets:partial.anonymousBuckets};
  Object.defineProperty(result,'privateControls',{enumerable:false,value:{canonical:{ownerId:first.ownerId,agentId:first.agentId,connectionId:first.connectionId,helperGrantId:first.helperGrantId,bearer:first.bearer,caseId:canonicalCase.id,diagnosticSessionId:canonicalCase.sessionId,segmentId:canonicalCase.segmentId,localId:canonicalLocal.local_id,spoolDirectory,pendingFinalBatch},spare:identities.at(-1),active:identities[1],transport}});
  return result;
 }catch(error){
  const partialRef=await write('interrupted-physical-server-capacity',{phase,...partial,capacityProbes,variants,transportSources:transport.sourceObservations});
  const failure=new Error('mcd_actual_server_capacity_probe_incomplete');failure.partialReference=partialRef;failure.phase=phase;throw failure;
 }finally{canonicalSpool?.close();await owner.end();}
}

export async function runMcdCapacityRestoreCases(input){
 validateInput(input);const captures={},blocked={};let server;
 try{server=await capacityServer(input);}catch(error){blocked['MCD-SC-005']={reason:'actual_server_capacity_probe_incomplete',phase:error.phase??'unknown',partialReference:error.partialReference};}
 const local=await (await import('./mcp-diagnostics-host-capacity.mjs')).runMcdHostCapacity(input);
 const supplement=typeof input.captureMcdLocalCapacity==='function'?await input.captureMcdLocalCapacity({...input,server,local})
   :await (await import('./mcp-diagnostics-supplement.mjs')).assembleMcdCapacitySupplement({...input,server,local});
 if(server&&supplement?.scenario005)captures['MCD-SC-005']=supplement.scenario005;
 else blocked['MCD-SC-005']??={reason:'remaining_ui_bundle_parser_fault_and_replica_proofs_required',serverPartial:server,localPartial:local};
 const captureCold=input.captureMcdColdRestore??(await import('./mcp-diagnostics-cold-restore.mjs')).captureMcdColdRestore;
 const restore=await captureCold({...input,server,local});if(restore?.scenario006)captures['MCD-SC-006']=restore.scenario006;else blocked['MCD-SC-006']={reason:restore?.blocked?.reason??'actual_unified_checkpoint_cold_restore_and_client_spool_parts_missing',partial:restore,localPartial:local};
 return {captures,blocked,serverParts:server,localParts:local};
}

