/** Real HTTP/browser/readonly-PostgreSQL MCD capture helpers. No native impersonation. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import pg from 'pg';
import {assertSecretFree} from './evidence.mjs';
import {runAapOAuthBrowserFlow,startOAuthCallbackReceiver} from './oauth-cases.mjs';
import {mcdOAuthEvidence,mcdOAuthAuthorized} from './mcp-diagnostics-oauth-evidence.mjs';
import {ensureMcdTrainingAllowed} from './mcp-diagnostics-ui-support.mjs';
import {readMcdWireResponse} from './mcp-diagnostics-wire.mjs';

const uuid=value=>typeof value==='string'&&/^[a-f0-9-]{36}$/i.test(value);
const canonical=value=>JSON.stringify(Array.isArray(value)?value.map(v=>JSON.parse(canonical(v))):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b,'en')).map(([k,v])=>[k,JSON.parse(canonical(v))])):value);
const sha=value=>createHash('sha256').update(value).digest('hex');
const delay=ms=>new Promise(done=>setTimeout(done,ms));
const BUSINESS={runs:'oid_benchmark_run',tasks:'oid_run_task',actions:'oid_run_task_action',receipts:'oid_run_task_action_receipt',evaluations:'oid_run_task_evaluation',ledger:'oid_ledger_entry',bonuses:'oid_bonus_grant'};
let registeredCodes=new Set(['UNKNOWN_ERROR','INPUT_VALIDATION_ERROR','UNAUTHORIZED','FORBIDDEN']);

export class McdObserver {
  #url;
  constructor(url){const u=new URL(url);assert.equal(u.hostname,'postgres');assert.equal(u.username,'oid_observer');assert.match(u.pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);this.#url=url;this.resume();}
  async read(work){const c=await this.pool.connect();try{await c.query('BEGIN READ ONLY');const row=(await c.query("SELECT current_user AS role,current_database() AS database,current_setting('transaction_read_only') AS mode")).rows[0];assert.equal(row.role,'oid_observer');assert.equal(row.mode,'on');this.identity={role:row.role,readOnly:true,databaseName:row.database};const result=await work(c);await c.query('COMMIT');return result;}catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}}
  async business(){return this.read(async c=>{const domainHashes={};for(const [key,table] of Object.entries(BUSINESS))domainHashes[key]=(await c.query(`SELECT encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(r)::text,E'\\n' ORDER BY to_jsonb(r)::text),''),'UTF8')),'hex') AS sha FROM ${table} r`)).rows[0].sha;return {source:'postgresql_observer',observer:this.identity,domainHashes};});}
  async diagnostics(){return this.read(async c=>{
    const cases=(await c.query(`SELECT c.id AS "caseId",'client_diagnostics' AS kind,c.owner_id AS "ownerId",c.agent_id AS "agentId",c.connection_id AS "connectionId",c.diagnostic_session_id AS "diagnosticSessionId",c.intent_id AS "intentId",r.id AS "runId",c.report_id AS "reportId",c.created_at AS "createdAt",c.updated_at AS "updatedAt",c.capture_state AS "captureState",c.event_count AS "eventCount",c.error_count AS "errorCount" FROM oid_mcp_diagnostic_case c LEFT JOIN oid_benchmark_run r ON r.intent_id=c.intent_id ORDER BY c.id`)).rows;
    const events=(await c.query(`SELECT envelope,case_id AS "caseId",responsibility,attribution_reason AS "attributionReason",evidence_ids AS "evidenceIds" FROM oid_mcp_diagnostic_event ORDER BY created_at,event_id`)).rows.map(({envelope,...rest})=>({...envelope,...rest}));
    const reports=(await c.query(`SELECT r.id,c.id AS "caseId",c.owner_id AS "ownerId",'client_diagnostics' AS kind FROM oid_mcp_diagnostic_case c JOIN oid_support_report r ON r.id=c.report_id ORDER BY r.id`)).rows;
    const batches=(await c.query(`SELECT case_id AS "caseId",segment_id AS "segmentId",batch_sequence AS "batchSequence",payload_hash AS "payloadHash",completion FROM oid_mcp_diagnostic_batch ORDER BY case_id,segment_id,batch_sequence`)).rows;
    const audits=(await c.query(`SELECT a.report_id AS "reportId",a.event_type AS "eventType",a.revision FROM oid_support_report_audit a JOIN oid_mcp_diagnostic_case c ON c.report_id=a.report_id ORDER BY a.report_id,a.revision,a.event_type`)).rows;
    return JSON.parse(JSON.stringify({source:'postgresql_observer',observer:this.identity,cases,events,reports,batches,audits}));
  });}
  async query(text,values=[]){return this.read(async c=>(await c.query(text,values)).rows);}
  async waitFor(predicate){for(let i=0;i<40;i++){const value=await this.diagnostics();if(predicate(value))return value;await delay(50);}throw new Error('mcd_independent_observation_timeout');}
  async settledDiagnostics(){let prior=await this.diagnostics();for(let i=0;i<20;i++){await delay(50);const current=await this.diagnostics();if(JSON.stringify(prior)===JSON.stringify(current))return current;prior=current;}throw new Error('mcd_diagnostics_did_not_quiesce');}
  async suspend(){if(this.pool){const current=this.pool;this.pool=null;await current.end();}}
  resume(){if(!this.pool)this.pool=new pg.Pool({connectionString:this.#url,max:1,application_name:'mcd-independent-readonly-observer'});}
  async close(){await this.suspend();}
}

export async function createMcdWriter({repoRoot,captureId}){
  assert(uuid(captureId));const directory=resolve(repoRoot,'artifacts/runs/mcp-call-diagnostics',captureId);await mkdir(directory,{recursive:true,mode:0o700});
  let sequence=0;
  return {directory,async write(label,value){assert.match(label,/^[a-zA-Z0-9_-]{1,100}$/);assertSecretFree(value,'mcd-'+label);const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');assert(bytes.length<=32*1024*1024);const file=resolve(directory,String(sequence++).padStart(5,'0')+'-'+label+'.json');await writeFile(file,bytes,{flag:'wx',mode:0o600});return {path:relative(repoRoot,file).split(sep).join('/'),sha256:sha(bytes)};}};
}

export async function captureMcdVariant({name,request,execute,observer,writer,waitFor}){
  const diagnostics=()=>typeof observer.settledDiagnostics==='function'?observer.settledDiagnostics():observer.diagnostics();
  assert.equal(typeof execute,'function');const beforeBusiness=await observer.business(),beforeDiagnostic=await diagnostics();
  const beforeRefs={};for(const [key,value] of Object.entries({request,beforeBusiness,beforeDiagnostic}))beforeRefs[key+'Ref']=await writer.write(name+'-'+key,value);
  const response=await execute();
  const responseRef=await writer.write(name+'-response',response);
  if(waitFor)try{await observer.waitFor(value=>waitFor(value,response));}catch{
    const afterDiagnostic=await diagnostics(),afterBusiness=await observer.business();
    const partialReference=await writer.write(name+'-missing-observation',{schemaVersion:'mcd-incomplete-variant/v1',name,...beforeRefs,responseRef,afterBusinessRef:await writer.write(name+'-afterBusiness',afterBusiness),afterDiagnosticRef:await writer.write(name+'-afterDiagnostic',afterDiagnostic)});
    throw Object.assign(new Error('Expected independent diagnostic observation missing'),{code:'MCD_EXPECTED_OBSERVATION_MISSING',safeDiagnostic:{variant:name,httpStatus:response.httpStatus??null,errorCode:response.errorCode??'UNKNOWN_ERROR',traceId:response.traceId??null,partialReference}});
  }
  const afterDiagnostic=await diagnostics();
  const afterBusiness=await observer.business();assert.deepEqual(afterBusiness,beforeBusiness,'diagnostic probe mutated business state');
  const result={name,...beforeRefs,responseRef};for(const [key,value] of Object.entries({afterBusiness,afterDiagnostic}))result[key+'Ref']=await writer.write(name+'-'+key,value);
  return result;
}

function safeResponse(response,body){
  const result=body?.result,structured=result?.structuredContent;
  let projection=structured;
  const meta=result?._meta?.['w3bench/diagnostics']??body?.error?.data?._meta?.['w3bench/diagnostics'];
  let errorCode=meta?.errorCode??body?.error?.data?.code??structured?.error?.code??(typeof body?.error?.code==='string'?body.error.code:undefined);
  if(Array.isArray(result?.content))for(const item of result.content.slice(0,8))if(typeof item.text==='string'&&Buffer.byteLength(item.text)<=65536)try{const v=JSON.parse(item.text);projection??=v;if(!errorCode&&result.isError)errorCode=v?.error?.code??v?.code;}catch{}
  const validationText=Array.isArray(result?.content)&&result.content.some(item=>typeof item?.text==='string'&&item.text.startsWith('Input validation error:'));
  return {httpStatus:response.status,...(typeof body?.error?.code==='number'?{rpcErrorCode:body.error.code}:{}),...(result?.isError?{toolError:true}:{}),
    rpcShape:{hasResult:body?.result!==undefined,hasError:body?.error!==undefined,resultIsError:result?.isError===true,hasStructuredContent:structured!==undefined,validationText},
    errorCode:registeredCodes.has(errorCode)?errorCode:body?.error?.code===-32602?'INPUT_VALIDATION_ERROR':response.status===401?'UNAUTHORIZED':response.status===403?'FORBIDDEN':'UNKNOWN_ERROR',
    ...(uuid(response.headers.get('x-w3bench-diagnostic-trace'))?{traceId:response.headers.get('x-w3bench-diagnostic-trace')}:{}),
    ...(projection?.admitted===true?{admitted:true}:{}),...(uuid(projection?.actionId)?{actionId:projection.actionId}:{}),
    ...(response.headers.get('x-w3bench-diagnostic-capture')?{captureState:response.headers.get('x-w3bench-diagnostic-capture')}:{}),};
}

export async function createMcdBrowserConnection(input){
  registeredCodes=new Set((await import('../../owner-identity/dist/mcp-diagnostics-contract.js')).DIAGNOSTIC_ERROR_CODES);
  const page=input.ownerPage;await page.goto('/agents',{waitUntil:'domcontentloaded'});const form=page.getByTestId('agent-create-form');const name='MCD reference '+input.captureId.slice(0,8);
  await form.getByTestId('agent-name').fill(name);await form.getByTestId('agent-description').fill('Synthetic diagnostic boundary reference client');
  const created=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/agents'&&r.request().method()==='POST');await form.getByTestId('agent-create').click();const response=await created;assert.equal(response.status(),201);const agentId=(await response.json()).agent.id;
  // AICODE-NOTE: The normal completion consumer correctly requires current mode
  // access. Enable it through owner UI before consent/reference history setup.
  await ensureMcdTrainingAllowed(page,agentId);
  const policies=await input.observer.query('SELECT p.training,a.access_generation FROM oid_agent_policy p JOIN oid_agent a ON a.id=p.agent_id WHERE a.id=$1::uuid AND a.owner_id=$2::uuid',[agentId,input.ownerId]);
  assert.equal(policies.length,1);assert.equal(policies[0].training,true);
  const receiver=await startOAuthCallbackReceiver('http://127.0.0.1:38765/oauth/callback');let flow;
  try{flow=await runAapOAuthBrowserFlow({page,agentId,ownerId:input.ownerId,serverUrl:input.publicOrigin+'/api/agent/mcp',resource:input.publicOrigin+'/api/agent/mcp',resourceMetadataUrl:input.publicOrigin+'/.well-known/oauth-protected-resource/api/agent/mcp',callbackUrl:'http://127.0.0.1:38765/oauth/callback',callbackReceiver:receiver,clientId:'oid-local-mcp-client',captureApi:input.ownerCapture});}
  finally{await receiver.close();}
  if(!mcdOAuthAuthorized(flow))throw Object.assign(new Error('MCD reference OAuth did not authorize'),{code:'MCD_REFERENCE_OAUTH_NOT_AUTHORIZED',safeDiagnostic:mcdOAuthEvidence(flow)});
  const grants=await input.observer.query(`SELECT id FROM oid_agent_access_grant WHERE owner_id=$1::uuid AND agent_id=$2::uuid AND source='oauth' AND revoked_at IS NULL ORDER BY created_at DESC`,[input.ownerId,agentId]);assert.equal(grants.length,1);const connectionId=grants[0].id;
  return {agentId,connectionId,session:flow.session,async mcp(params,{authorized=true,caseId,raw}={}){
    return flow.session.useAccessToken(async token=>{const http=await fetch(input.publicOrigin+'/api/agent/mcp',{method:'POST',headers:{'content-type':'application/json',accept:'application/json, text/event-stream','mcp-protocol-version':'2025-06-18',...(authorized?{authorization:'Bearer '+token}:{}),...(caseId?{'x-w3bench-diagnostic-case':caseId}:{})},body:raw??JSON.stringify({jsonrpc:'2.0',id:randomUUID(),...params}),signal:AbortSignal.timeout(10000)});const decoded=await readMcdWireResponse(http);const view={...safeResponse(http,decoded.value),wireFraming:decoded.proof};if(input.writer)await input.writer.write('mcp-wire-safe-response',view);return view;});
  }};
}

export async function importMcdBundleThroughUi({page,binding,completion='complete',error=true,intentId}){
  const now=new Date().toISOString(),payload={segmentId:randomUUID(),batchSequence:0,completion,events:error?[{eventId:randomUUID(),source:'client',stage:'client_validation',tool:'identity.preflight',outcome:'error',errorCode:'INPUT_VALIDATION_ERROR',startedAt:now,completedAt:now,durationMs:0}]:[]};
  const bundle={schemaVersion:'w3bench-diagnostic-bundle/v1',diagnosticSessionId:randomUUID(),binding,...(intentId?{intentId}:{}),segments:[{segmentId:payload.segmentId,batches:[{...payload,payloadHash:sha(canonical(payload))}]}]};
  await page.goto('/diagnostics',{waitUntil:'domcontentloaded'});await page.getByLabel('Diagnostic helper export').setInputFiles({name:'synthetic-mcd-export.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(bundle))});
  const button=page.getByRole('button',{name:'Import diagnostics',exact:true});await button.waitFor({state:'visible'});const sent=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/owner/diagnostics/import'&&r.request().method()==='POST');await button.click();const response=await sent;assert.equal(response.status(),200);const receipt=await response.json();assert(uuid(receipt.caseId));return {bundle,receipt};
}

async function browserView({page,admin,caseId,observer,writer,ownerId}){
  const url=admin?'/admin/diagnostics':'/diagnostics';const response=await page.goto(url+'?caseId='+caseId,{waitUntil:'domcontentloaded'});assert.equal(response.status(),200);await page.getByTestId('diagnostic-details').waitFor({state:'visible'});
  const list=page.waitForResponse(r=>new URL(r.url()).pathname===(admin?'/api/admin/diagnostics/cases':'/api/owner/diagnostics/cases')&&r.request().method()==='GET');await page.getByRole('button',{name:'Refresh diagnostics',exact:true}).click();assert.equal((await list).status(),200);
  const cases=await page.locator('[data-testid^="diagnostic-case-"]').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('data-testid').slice('diagnostic-case-'.length)));
  const domText=await page.locator('body').innerText();return {action:'click',url:new URL(url,page.url()).href,httpStatus:200,ownerId,caseIds:cases,domText,databaseRef:await writer.write(admin?'admin-browser-database':'owner-browser-database',await observer.diagnostics())};
}

async function completedReferenceFixtures(input,connection,observer){
  // Declared reference business history only. These rows have synthetic sealed
  // evidence and never qualify a native client, chain executor or benchmark run.
  const [{createDatabase},{addFixture},completion]=await Promise.all([import('../../owner-identity/dist/db.js'),import('../../owner-identity/dist/task-run-completion.test-fixture.js'),import('../../owner-identity/dist/task-run-completion.js')]);
  const {client,db}=createDatabase({databaseUrl:input.databaseUrl});const fixtures=[];
  try{
    const identity=await observer.query('SELECT auth_user_id FROM oid_owner WHERE id=$1::uuid',[input.ownerId]);assert.equal(identity.length,1);
    for(const failedOutcome of [false,true]){
      const f=await addFixture(client,{existingIdentity:{userId:identity[0].auth_user_id,ownerId:input.ownerId,agentId:connection.agentId},failedOutcome});fixtures.push(f);
      const deps={db,taskReleaseSource:{async getActiveAdmissionRelease(){return null;},async getValidatedReleaseRecord(identity,manifest){return fixtures.find(x=>x.record.releaseIdentity===identity&&x.record.manifestHash===manifest)?.record??null;}},evidenceSource:{async load({runId}){return structuredClone(fixtures.find(x=>x.runId===runId)?.evaluationInput??null);}}};
      const completed=await completion.completeKnownTrainingRun(deps,{runId:f.runId});assert.equal(completed.status,'completed');
      const intentId=(await client`SELECT intent_id FROM oid_benchmark_run WHERE id=${f.runId}`)[0].intent_id;
      await client`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES (${randomUUID()},'agent.connection.intent_bound',${'connection-intent:'+intentId},${input.ownerId},${JSON.stringify({connectionId:connection.connectionId,agentId:connection.agentId,referenceFixture:'synthetic-completion-nonchain'})}::jsonb)`;
      f.intentId=intentId;
    }
    return {completed:fixtures[0],failed:fixtures[1]};
  }finally{await client.end();}
}

export async function runMcdDiagnosticCases(input){
  assert.equal(new URL(input.databaseUrl).pathname,'/'+input.databaseIsolation.databaseName);assert.match(input.databaseIsolation.databaseName,/^oid_acceptance_[a-f0-9]{32}$/);
  const writer=await createMcdWriter(input),observer=new McdObserver(input.observerDatabaseUrl),captures={},blocked={};
  try{
    await observer.business();const connection=await createMcdBrowserConnection({...input,observer,writer});const binding={agentId:connection.agentId,connectionId:connection.connectionId};
    const first=await importMcdBundleThroughUi({page:input.ownerPage,binding});const caseId=first.receipt.caseId;
    const reference=await completedReferenceFixtures(input,connection,observer);
    const protocolVariants=[];
    const probes=[['malformed_json_rpc',{method:'POST',path:'/api/agent/mcp'},()=>connection.mcp({}, {raw:'{synthetic-malformed'})],
      ['sdk_rejected_fields',{method:'POST',path:'/api/agent/mcp',binding:{ownerId:input.ownerId,...binding}},()=>connection.mcp({method:'tools/call',params:{name:'identity.preflight',arguments:{operationId:'bad'}}},{caseId})],
      ['expired_or_revoked_auth',{method:'POST',path:'/api/agent/mcp'},()=>connection.mcp({method:'tools/list'},{authorized:false})]];
    for(const [name,request,execute] of probes)protocolVariants.push(await captureMcdVariant({name,request,execute,observer,writer,waitFor:(rows,response)=>rows.events.some(e=>e.traceId===response.traceId&&e.outcome==='error')}));
    const fault=new pg.Client({connectionString:input.databaseUrl});await fault.connect();
    try{
      await fault.query(`CREATE FUNCTION oid_mcd_preflight_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='agent.connection.preflight' THEN RAISE EXCEPTION 'synthetic diagnostic handler failure'; END IF; RETURN NEW; END $$`);
      await fault.query(`CREATE TRIGGER oid_mcd_preflight_fault_trg BEFORE INSERT ON oid_audit FOR EACH ROW EXECUTE FUNCTION oid_mcd_preflight_fault()`);
      protocolVariants.push(await captureMcdVariant({name:'handler_failure',request:{method:'POST',path:'/api/agent/mcp',binding:{ownerId:input.ownerId,...binding}},execute:()=>connection.mcp({method:'tools/call',params:{name:'identity.preflight',arguments:{operationId:'mcd_handler_'+randomUUID().replaceAll('-','')}}},{caseId}),observer,writer,waitFor:(rows,response)=>rows.events.some(e=>e.traceId===response.traceId&&e.stage==='handler'&&e.outcome==='error')}));
    }finally{await fault.query('DROP TRIGGER IF EXISTS oid_mcd_preflight_fault_trg ON oid_audit');await fault.query('DROP FUNCTION IF EXISTS oid_mcd_preflight_fault()');await fault.end();}
    const restartBefore=await writer.write('before-api-restart',await observer.diagnostics());await input.restartApi();const restartAfter=await writer.write('after-api-restart',await observer.diagnostics());
    // Remaining actual fault boundaries are supplied by the coordinator, never
    // by inserting a diagnostic event or by marking a reference unit test passed.
    try{
      const captureProtocolFaults=input.captureProtocolFaults??(await import('./mcp-diagnostics-worker-faults.mjs')).captureMcdWorkerFaults;
      protocolVariants.push(...await captureProtocolFaults({...input,connection,caseId,binding,observer,writer,captureMcdVariant,importMcdBundleThroughUi}));
    }catch(error){blocked['MCD-SC-001']={reason:'actual_worker_reference_fault_incomplete',errorName:error instanceof Error?error.name:'Error'};}
    const protocol=await writer.write('protocol',{beforeRestartRef:restartBefore,afterRestartRef:restartAfter});
    const scenario001={variants:protocolVariants,raw:{protocol}};
    if(protocolVariants.length===6)captures['MCD-SC-001']=scenario001;else blocked['MCD-SC-001']={...blocked['MCD-SC-001'],reason:blocked['MCD-SC-001']?.reason??'actual_dispatch_admission_fault_boundaries_missing',partial:scenario001};
    try{
      const captureClassification=input.captureClassification??(await import('./mcp-diagnostics-classification.mjs')).captureMcdClassificationControls;
      captures['MCD-SC-003']=await captureClassification({...input,connection,caseId,binding,observer,writer,captureMcdVariant,importMcdBundleThroughUi});
    }catch(error){blocked['MCD-SC-003']={reason:'controlled_reference_causal_matrix_incomplete',errorName:error instanceof Error?error.name:'Error'};}
    const viewCase=await importMcdBundleThroughUi({page:input.ownerPage,binding});
    const browser={owner:await browserView({page:input.ownerPage,admin:false,caseId:viewCase.receipt.caseId,observer,writer,ownerId:input.ownerId}),admin:await browserView({page:input.adminPage,admin:true,caseId:viewCase.receipt.caseId,observer,writer,ownerId:input.adminOwnerId})};
    const diagnosticVariants=[];
    for(const [name,page] of [['foreign_owner',input.adminPage],['anonymous',null],['task_agent_read',null]]){
      diagnosticVariants.push(await captureMcdVariant({name,request:{method:'GET',path:'/api/owner/diagnostics/cases/'+caseId},observer,writer,execute:async()=>{
        const http=page?await page.request.get('/api/owner/diagnostics/cases/'+caseId):await fetch(input.publicOrigin+'/api/owner/diagnostics/cases/'+caseId,{headers:name==='task_agent_read'?await connection.session.useAccessToken(token=>({authorization:'Bearer '+token})):undefined,signal:AbortSignal.timeout(10000)});
        return {httpStatus:typeof http.status==='function'?http.status():http.status,caseIds:[]};}}));
    }
    for(const [name,change] of [['forged_run_action_reference',event=>({...event,actionId:randomUUID()})],['client_claim_of_server_authority',event=>({...event,source:'server'})]]){
      const payload={...first.bundle.segments[0].batches[0],segmentId:randomUUID()};delete payload.payloadHash;payload.events=payload.events.map(change);const batch={...payload,payloadHash:sha(canonical(payload))};
      diagnosticVariants.push(await captureMcdVariant({name,request:{method:'POST',path:'/api/owner/diagnostics/import',caseId},observer,writer,execute:async()=>{const response=await input.ownerPage.request.post('/api/owner/diagnostics/import',{data:{diagnosticSessionId:first.bundle.diagnosticSessionId,caseId,batch}});return {httpStatus:response.status(),caseIds:[]};}}));
    }
    diagnosticVariants.push(await captureMcdVariant({name:'error_free_capture',request:{method:'POST',path:'/api/owner/diagnostics/import'},observer,writer,execute:async()=>{const result=await importMcdBundleThroughUi({page:input.ownerPage,binding,error:false});return {httpStatus:200,receipt:result.receipt};}}));
    diagnosticVariants.push(await captureMcdVariant({name:'ordinary_failed_grade_only',request:{method:'GET',path:'/api/owner/runs/'+reference.failed.runId+'/results',referenceFixture:'synthetic-completion-nonchain'},observer,writer,execute:async()=>{
      const state=await observer.query(`SELECT r.status,t.status AS task_status FROM oid_benchmark_run r JOIN oid_run_task t ON t.run_id=r.id WHERE r.id=$1::uuid`,[reference.failed.runId]);assert.equal(state[0].status,'completed');assert.equal(state[0].task_status,'failed');
      const response=await input.ownerPage.request.get('/api/owner/runs/'+reference.failed.runId+'/results');return {httpStatus:response.status(),runId:reference.failed.runId,runObservationRef:await writer.write('failed-grade-reference',{source:'postgresql_observer',observer:observer.identity,runId:reference.failed.runId,rows:state,referenceFixture:'synthetic-completion-nonchain'})};
    }}));
    diagnosticVariants.push(await captureMcdVariant({name:'completed_run_with_client_errors',request:{method:'POST',path:'/api/owner/diagnostics/import',runId:reference.completed.runId,referenceFixture:'synthetic-completion-nonchain'},observer,writer,execute:async()=>{
      const state=await observer.query(`SELECT status FROM oid_benchmark_run WHERE id=$1::uuid`,[reference.completed.runId]);assert.equal(state[0].status,'completed');const result=await importMcdBundleThroughUi({page:input.ownerPage,binding,intentId:reference.completed.intentId});return {httpStatus:200,receipt:result.receipt,runId:reference.completed.runId,runObservationRef:await writer.write('completed-reference',{source:'postgresql_observer',observer:observer.identity,runId:reference.completed.runId,rows:state,referenceFixture:'synthetic-completion-nonchain'})};
    }}));
    if(typeof input.captureDiagnosticNegatives==='function')diagnosticVariants.push(...await input.captureDiagnosticNegatives({connection,caseId,binding,observer,writer,captureMcdVariant,importMcdBundleThroughUi}));
    const scenario004={variants:diagnosticVariants,raw:{browser:await writer.write('browser',browser)}};
    if(diagnosticVariants.length===8)captures['MCD-SC-004']=scenario004;else blocked['MCD-SC-004']={reason:'completed_reference_run_and_remaining_negatives_missing',partial:scenario004};
    if(typeof input.runAdditionalMcdCases==='function'){
      const additional=await input.runAdditionalMcdCases({...input,observer,writer,connection,binding,caseId,captureMcdVariant,
        originalOwnedExport:{diagnosticSessionId:first.bundle.diagnosticSessionId,binding,caseId,batch:first.bundle.segments[0].batches[0]}});
      Object.assign(captures,additional.captures??{});Object.assign(blocked,additional.blocked??{});
    }
    const sourceAfter=await input.collectSourceHashes();const sourceBefore=input.sourceInputsBefore;
    assert.deepEqual(sourceAfter,sourceBefore,'MCD source inventory changed during physical capture');
    const references={};for(const [id,capture] of Object.entries(captures))references[id]=await writer.write(id,{schemaVersion:'mcd-physical-capture/v1',scenarioId:id,observer:observer.identity,sourceInputs:{before:sourceBefore,after:sourceAfter},...capture});
    const partial=await writer.write('partial-boundaries',{schemaVersion:'mcd-partial-boundaries/v1',captureId:input.captureId,blocked});
    return {status:Object.keys(blocked).length?'blocked':'captured',captures:references,blocked:Object.fromEntries(Object.entries(blocked).map(([id,b])=>[id,b.reason])),partialReference:partial,directory:writer.directory};
  }catch(error){
    // AICODE-NOTE: A later capacity/restore failure must not erase completed
    // physical boundaries. These retain actual source snapshots; drift remains
    // fail-closed in the independent reader and no runtime selector is changed.
    try{
      const after=await input.collectSourceHashes(),before=input.sourceInputsBefore,references={};
      for(const [scenarioId,capture] of Object.entries(captures))references[scenarioId]=await writer.write('interrupted-'+scenarioId,{schemaVersion:'mcd-physical-capture/v1',scenarioId,observer:observer.identity,sourceInputs:{before,after},...capture});
      const sourceStable=canonical(before)===canonical(after);
      await writer.write('interrupted-completed-boundaries',{schemaVersion:'mcd-interrupted-boundaries/v1',captureId:input.captureId,captures:references,sourceStable,runtimeInputsActivated:false});
      input.onProgress?.({phase:'mcd_completed_boundaries_preserved',scenarios:Object.keys(references),sourceStable});
    }catch{/* Preserve the original failure if artifact capture itself failed. */}
    throw error;
  }finally{await observer.close();}
}
