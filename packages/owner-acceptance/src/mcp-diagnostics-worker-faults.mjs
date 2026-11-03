/** Real admission/claim rollback on a declared non-chain reference fixture. */
import assert from 'node:assert/strict';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {ensureMcdTrainingAllowed} from './mcp-diagnostics-ui-support.mjs';
const requireOwner=createRequire(new URL('../../owner-identity/package.json',import.meta.url));

export async function captureMcdWorkerFaults(input){
  const {connection,binding,observer,writer,captureMcdVariant,importMcdBundleThroughUi}=input;
  const [{createDatabase},{addFixture},{BefTaskExecutor},{registerDiagnosticIngress},{default:Fastify}]=await Promise.all([
    import('../../owner-identity/dist/db.js'),import('../../owner-identity/dist/task-run-completion.test-fixture.js'),import('../../owner-identity/dist/bef-task-executor.js'),import('../../owner-identity/dist/mcp-diagnostics-ingress.js'),import(pathToFileURL(requireOwner.resolve('fastify')).href)]);
  assert.match(new URL(input.databaseUrl).pathname,/^\/oid_acceptance_[a-f0-9]{32}$/);
  const {client,db}=createDatabase({databaseUrl:input.databaseUrl}),diagnosticApp=Fastify({logger:false});let health,worker,executor,f,toolsRequests=0;const variants=[];
  try{
    // Exercise the current owner policy through the real UI before setup admits
    // the one free reference command. No bonus/payment command is submitted.
    await input.ownerPage.goto('/agents',{waitUntil:'domcontentloaded'});await ensureMcdTrainingAllowed(input.ownerPage,connection.agentId);
    const identity=await observer.query('SELECT auth_user_id FROM oid_owner WHERE id=$1::uuid',[input.ownerId]);
    f=await addFixture(client,{existingIdentity:{userId:identity[0].auth_user_id,ownerId:input.ownerId,agentId:connection.agentId},actionOpen:true,includeEvaluation:false,fence:false,overallDeadlineSecondsFromNow:3600});
    const intentId=(await client`SELECT intent_id FROM oid_benchmark_run WHERE id=${f.runId}`)[0].intent_id;
    await client`INSERT INTO oid_audit(id,event_type,operation_id,actor_owner_id,metadata) VALUES (${randomUUID()},'agent.connection.intent_bound',${'connection-intent:'+intentId},${input.ownerId},${JSON.stringify({connectionId:connection.connectionId,agentId:connection.agentId,referenceFixture:'synthetic-action-no-payment'})}::jsonb)`;
    const registered=await importMcdBundleThroughUi({page:input.ownerPage,binding,intentId});const caseId=registered.receipt.caseId,operationId='mcd_reference_'+randomUUID().replaceAll('-','');
    const admitted=await connection.mcp({method:'tools/call',params:{name:'runs.task_action',arguments:{runId:f.runId,taskIndex:0,operationId,command:{kind:'inspect_catalog'}}}},{caseId});assert.equal(admitted.admitted,true);assert(admitted.actionId);
    await observer.waitFor(snapshot=>snapshot.events.some(e=>e.actionId===admitted.actionId&&e.stage==='admission'&&e.outcome==='success'));
    variants.push(await captureMcdVariant({name:'duplicate_operation',request:{method:'POST',path:'/api/agent/mcp',binding:{ownerId:input.ownerId,...binding},referenceFixture:'synthetic-action-no-payment'},observer,writer,execute:()=>connection.mcp({method:'tools/call',params:{name:'runs.task_action',arguments:{runId:f.runId,taskIndex:0,operationId,command:{kind:'inspect_offer',resourceId:'synthetic-reference-resource'}}}},{caseId}),waitFor:(snapshot,response)=>snapshot.events.some(e=>e.traceId===response.traceId&&e.stage==='admission'&&e.outcome==='error')}));
    const proof=(await observer.query('SELECT env_id,generation_id,manifest_hash,application_source_hash,participant_id,payer_address FROM oid_task_execution_binding WHERE run_id=$1::uuid AND task_index=0',[f.runId]))[0];
    // A real loopback reference health endpoint satisfies the unchanged normal
    // executor readiness checks for the fixture's sealed synthetic identity.
    // It is not a BEF release qualification and serves no participant tools.
    health=createServer((request,response)=>{response.setHeader('content-type','application/json');if(request.url!=='/healthz'){toolsRequests++;response.writeHead(503);response.end(JSON.stringify({error:{code:'SYNTHETIC_TOOLS_FORBIDDEN'}}));return;}response.end(JSON.stringify({status:'ready',boundary:'benchmark-environment-api',manifestSha256:proof.manifest_hash,applicationSourceSha256:proof.application_source_hash,environments:[{envId:proof.env_id}],referenceFixture:'synthetic-action-no-payment'}));});
    await new Promise((done,reject)=>{health.once('error',reject);health.listen(0,'127.0.0.1',done);});const healthOrigin='http://127.0.0.1:'+health.address().port;
    const deps={db,reportClosureState:{async readAuthoritativeClosure(){return {betaEndedAt:null,sourceEvidenceSha256:'a'.repeat(64)};},async persistAuthoritativeClosure(){throw new Error('reference worker cannot change beta closure');}}};registerDiagnosticIngress(diagnosticApp,deps);
    executor=new BefTaskExecutor({db,taskReleaseSource:{async getActiveAdmissionRelease(){return null;},async getValidatedReleaseRecord(identity,manifest){return identity===f.record.releaseIdentity&&manifest===f.record.manifestHash?f.record:null;}},participantApiByEnvironment:{[proof.env_id]:healthOrigin},evidenceSink:{async write(){throw new Error('mcd_claim_failure_must_precede_execution_evidence');}}});
    await executor.attachStartedSession({runId:f.runId,taskIndex:0,envId:proof.env_id,generationId:proof.generation_id,manifestHash:proof.manifest_hash,applicationSourceHash:proof.application_source_hash,participantId:proof.participant_id,payerAddress:proof.payer_address,runToken:randomBytes(48).toString('base64url')});
    const triggerBody=`CREATE FUNCTION oid_mcd_dispatch_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action_id='${admitted.actionId}'::uuid AND NEW.status='delivered' THEN RAISE EXCEPTION 'synthetic_reference_dispatch_claim_failure'; END IF; RETURN NEW; END $$`;
    await client.unsafe(triggerBody);await client.unsafe('CREATE TRIGGER oid_mcd_dispatch_fault_trg BEFORE UPDATE ON oid_run_task_action_outbox FOR EACH ROW EXECUTE FUNCTION oid_mcd_dispatch_fault()');
    const nonce=randomBytes(32).toString('base64url');worker=createServer(async(request,response)=>{
      response.setHeader('content-type','application/json');if(request.method!=='POST'||request.url!=='/dispatch'||request.headers['x-mcd-worker-control']!==nonce){response.writeHead(403);response.end('{}');return;}
      try{await executor.executeNext(f.runId,0);response.writeHead(200);response.end(JSON.stringify({status:'unexpectedly_dispatched'}));}
      catch{
        const trace=await observer.query(`SELECT trace_id FROM oid_mcp_diagnostic_event WHERE case_id=$1::uuid AND stage='admission' AND envelope->>'actionId'=$2 ORDER BY created_at LIMIT 1`,[caseId,admitted.actionId]);
        response.writeHead(500);response.end(JSON.stringify({errorCode:'INTERNAL_ERROR',traceId:trace[0]?.trace_id,actionId:admitted.actionId}));
      }
    });await new Promise((done,reject)=>{worker.once('error',reject);worker.listen(0,'127.0.0.1',done);});
    variants.push(await captureMcdVariant({name:'dispatch_failure',request:{method:'POST',path:'/dispatch',binding:{ownerId:input.ownerId,...binding},referenceFixture:'synthetic-action-no-payment'},observer,writer,execute:async()=>{
      const http=await fetch('http://127.0.0.1:'+worker.address().port+'/dispatch',{method:'POST',headers:{'x-mcd-worker-control':nonce},signal:AbortSignal.timeout(10000)}),body=await http.json();assert.equal(http.status,500);assert.equal(toolsRequests,0);
      return {httpStatus:http.status,errorCode:body.errorCode,traceId:body.traceId,actionId:body.actionId,externalParticipantRequests:toolsRequests,claimFaultSourceSha256:createHash('sha256').update(triggerBody).digest('hex'),referenceFixture:'synthetic-action-no-payment'};
    },waitFor:(snapshot,response)=>snapshot.events.some(e=>e.actionId===response.actionId&&e.stage==='dispatch'&&e.outcome==='error')}));
    return variants;
  }finally{
    executor?.unbindSession(f?.runId,0);
    await client.unsafe('DROP TRIGGER IF EXISTS oid_mcd_dispatch_fault_trg ON oid_run_task_action_outbox').catch(()=>{});await client.unsafe('DROP FUNCTION IF EXISTS oid_mcd_dispatch_fault()').catch(()=>{});
    await Promise.all([worker?new Promise(done=>worker.close(done)):Promise.resolve(),health?new Promise(done=>health.close(done)):Promise.resolve()]);await diagnosticApp.close();await client.end();
  }
}
