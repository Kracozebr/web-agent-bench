import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {once} from 'node:events';
import {validateMcdNativeJob,buildMcdNativeProbe,createMcdObservedSpawn,isMcdNativeCrashBoundary} from './mcd-native-qualification.mjs';
const base=()=>({schemaVersion:'mcd-native-fault-job/v1',captureId:randomUUID(),profile:'free-own-preflight',origin:'http://127.0.0.1:3000',outputDirectory:'.local/qualification-fixture'});
test('finite qualification jobs reject arbitrary prompts, remote endpoints, unreviewed active selection and missing proxy',()=>{
  const job=base();assert.equal(validateMcdNativeJob(job),job);
  for(const bad of [{...job,prompt:'arbitrary'}, {...job,origin:'https://example.com'},{...job,profile:'shell'}, {...job,handoffFile:'unreviewed.txt'},{...job,profile:'lost-admission-response',handoffFile:'a'},{...job,timeoutMs:31*60000}])assert.throws(()=>validateMcdNativeJob(bad));
  assert.throws(()=>buildMcdNativeProbe({profile:'crash-after-active-run',captureId:job.captureId,selection:{agentId:randomUUID(),intentId:randomUUID(),mode:'ranked'}}),/CONTROLLED_TRAINING/);
});
test('predetermined profiles keep free probes free and loss qualification limited to one idempotent catalog action',()=>{
  const captureId=randomUUID(),selection={agentId:randomUUID(),intentId:randomUUID(),mode:'training'};
  const invalid=buildMcdNativeProbe({profile:'invalid-schema-preflight',captureId});assert.deepEqual(invalid.tools,['identity.preflight']);assert(invalid.prompt.includes('"operationId":"short"'));assert(invalid.prompt.includes('exactly TWO identity.preflight calls'));assert(invalid.prompt.includes('FIRST call identity.preflight exactly once with {"operationId":"mcd_preflight_'+captureId.replaceAll('-','')+'"}'));assert(invalid.prompt.includes('SAME configured connection'));assert(invalid.prompt.includes('Do not repair or retry either call'));assert(!invalid.tools.includes('runs.accept_launch_intent'));
  const free=buildMcdNativeProbe({profile:'free-own-preflight',captureId});assert.deepEqual(free.tools,['identity.preflight']);assert(free.prompt.includes('Do not accept any intent'));
  const crash=buildMcdNativeProbe({profile:'crash-after-active-run',captureId,selection});assert(!crash.tools.includes('runs.task_action'));assert(crash.prompt.includes(selection.intentId));
  const lost=buildMcdNativeProbe({profile:'lost-admission-response',captureId,selection});assert.equal(lost.operationIdHash.length,64);assert(lost.prompt.includes('SAME operationId'));assert(lost.prompt.includes('{"kind":"inspect_catalog"}'));assert(!lost.tools.includes('runs.finish_task'));
  for(const profile of ['invalid-schema-preflight','free-own-preflight','foreign-case-header','crash-after-active-run','lost-admission-response']){const probe=buildMcdNativeProbe({profile,captureId,selection});assert(probe.prompt.includes('"operationId":"mcd_preflight_'+captureId.replaceAll('-','')+'"'));assert(!probe.prompt.includes('with {}'));}
});
test('observed spawn wrapper launches and kills its actual child only; this Node primitive is NOT native qualification',async()=>{
  const actual=createMcdObservedSpawn(),child=actual.spawnImpl(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore',windowsHide:true});await once(child,'spawn');
  const closed=once(child,'close'),receipt=actual.killObserved();assert.equal(receipt.pid,child.pid);assert.equal(receipt.killRequested,true);await closed;
  assert.throws(()=>actual.killObserved(),/KILL_TARGET/);assert.throws(()=>actual.spawnImpl(process.execPath,[],{}),/SINGLE_PROCESS/);
});
test('crash trigger excludes acceptance/queued/preparation and terminal or uncorrelated observations',()=>{
  const observation={sourceTool:'runs.current_task',runId:randomUUID(),status:'running',terminal:false,sourceCallIdHash:'a'.repeat(64)};assert(isMcdNativeCrashBoundary(observation));
  for(const change of [{sourceTool:'runs.accept_launch_intent'},{status:'queued'},{status:'preparing'},{terminal:true},{runId:'invalid'},{sourceCallIdHash:''}])assert.equal(isMcdNativeCrashBoundary({...observation,...change}),false);
});
