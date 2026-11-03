/** Explicit controlled diagnostic qualification; never an alternate public benchmark launcher. */
import {spawn} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {mkdir,lstat,readFile,writeFile,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {NativeDiagnosticCollector,openDiagnosticSpool,createDiagnosticTransport,deliverDiagnosticOutbox,canonicalDiagnosticJson} from './mcp-diagnostics-client.mjs';
import {createDiagnosticCredentialStore,createDiagnosticTokenProvider,validateDiagnosticOAuthProfile} from './mcp-diagnostics-oauth.mjs';
import {readReviewedHandoff,instrumentedNativeArguments,nativeEnvironment,validateNativeMetadata,runProjectedNative} from './mcp-diagnostics-launcher.mjs';
import {verifyExecutableBundle} from '../infrastructure/owner-identity/run-codex-google-local.mjs';
import {projectActualClientRows} from './run-mcd-client-capture.mjs';
import {DatabaseSync} from 'node:sqlite';
import {startMcdNativeFaultProxy} from './mcd-native-fault-proxy.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const need=(v,c)=>{if(!v)throw new Error(c);};
const sha=v=>createHash('sha256').update(v).digest('hex');
export const MCD_NATIVE_PROFILES=Object.freeze(['invalid-schema-preflight','free-own-preflight','foreign-case-header','crash-after-active-run','lost-admission-response']);
const SOURCES=['tools/mcd-native-qualification.mjs','tools/mcd-native-fault-proxy.mjs','tools/mcp-diagnostics-client.mjs','tools/mcp-diagnostics-oauth.mjs','tools/mcp-diagnostics-launcher.mjs','tools/run-mcd-client-capture.mjs','tools/run_aci_native.mjs','infrastructure/owner-identity/run-codex-google-local.mjs','packages/owner-web/lib/run-handoff.ts','packages/owner-acceptance/src/mcp-diagnostics-wire.mjs'];
function inside(root,path){need(typeof path==='string','MCD_NATIVE_PATH_INVALID');const absolute=resolve(root,path),part=relative(root,absolute);need(part&&!isAbsolute(part)&&!part.startsWith('..'),'MCD_NATIVE_PATH_INVALID');return absolute;}
async function regular(file,max=65536){const st=await lstat(file);need(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=max,'MCD_NATIVE_FILE_INVALID');return readFile(file);}
async function verifiedPath(root,path){const absolute=inside(root,path);need((await realpath(absolute)).toLowerCase()===absolute.toLowerCase(),'MCD_NATIVE_PATH_INVALID');return absolute;}
async function inventory(root){return Object.fromEntries(await Promise.all(SOURCES.map(async file=>[file,sha(await regular(resolve(root,file),1024*1024))])));}
export function validateMcdNativeJob(job){
  need(job&&Object.keys(job).every(k=>['schemaVersion','captureId','profile','origin','handoffFile','foreignCaseId','outputDirectory','timeoutMs','originProxy'].includes(k))&&job.schemaVersion==='mcd-native-fault-job/v1'&&UUID.test(job.captureId)&&MCD_NATIVE_PROFILES.includes(job.profile)&&job.origin==='http://127.0.0.1:3000'&&typeof job.outputDirectory==='string','MCD_NATIVE_JOB_INVALID');
  need(job.timeoutMs===undefined||Number.isInteger(job.timeoutMs)&&job.timeoutMs>=1000&&job.timeoutMs<=30*60000,'MCD_NATIVE_JOB_INVALID');
  need(job.originProxy===undefined||typeof job.originProxy==='boolean','MCD_NATIVE_JOB_INVALID');
  const active=['crash-after-active-run','lost-admission-response'].includes(job.profile);
  need(active?typeof job.handoffFile==='string':job.handoffFile===undefined,'MCD_NATIVE_JOB_INVALID');
  need(job.profile==='foreign-case-header'?UUID.test(job.foreignCaseId):job.foreignCaseId===undefined,'MCD_NATIVE_JOB_INVALID');
  need(!['lost-admission-response','foreign-case-header'].includes(job.profile)||job.originProxy===true,'MCD_NATIVE_ORIGIN_PROXY_REQUIRED');
  return job;
}
export function buildMcdNativeProbe({profile,captureId,selection}){
  need(MCD_NATIVE_PROFILES.includes(profile)&&UUID.test(captureId),'MCD_NATIVE_PROFILE_INVALID');
  const preflightArgs=JSON.stringify({operationId:'mcd_preflight_'+captureId.replaceAll('-','')});
  const intro='This is a controlled Web3 Agent Bench diagnostic qualification, not a benchmark score attempt. Use only MCP server w3bench_user. Do not use shell, files, browser, local tools, direct HTTP or RPC. Do not submit support reports. Do not switch identity or create any additional run. ';
  if(profile==='invalid-schema-preflight')return {prompt:intro+`Make exactly TWO identity.preflight calls on this SAME configured connection. FIRST call identity.preflight exactly once with ${preflightArgs}, omitting agentId to use the native-bound identity, to retain the actual server trace/canonical carrier. If this free probe is denied or fails, stop without another call. Only after its successful response, SECOND call identity.preflight exactly once with {"agentId":"invalid","operationId":"short"}. These deliberately invalid synthetic fields test local SDK validation and do not request another identity. Do not repair or retry either call. Do not accept an intent or launch a run. Report the two actual outcomes.`,tools:['identity.preflight']};
  if(['free-own-preflight','foreign-case-header'].includes(profile))return {prompt:intro+`Call identity.preflight exactly once with ${preflightArgs}, omitting agentId for the native-bound configured connection. Do not accept any intent or start tasks. Report the response or exact tool failure, without retrying.`,tools:['identity.preflight']};
  need(selection&&UUID.test(selection.agentId)&&UUID.test(selection.intentId)&&selection.mode==='training','MCD_NATIVE_CONTROLLED_TRAINING_REQUIRED');
  const operationId='mcd_admission_'+captureId.replaceAll('-','');
  const acceptance=`Run identity.preflight with ${preflightArgs} once, omitting agentId for the native-bound identity. Only if it allows training, accept exactly private launch intent ${selection.intentId} with operationId mcd_accept_${captureId.replaceAll('-','')}. After acceptance, call runs.current_task with the returned runId. Poll only that run while no task is issued and it is not terminal; respect retryAfterMs. `;
  if(profile==='crash-after-active-run')return {prompt:intro+acceptance+'Continue polling runs.current_task until its run status is running and terminal is not true. The operator will interrupt this Codex process immediately after that matching current_task observation. A queued/preparing acceptance is not the crash boundary. Never call runs.task_action or runs.finish_task; do not launch another run.',tools:['identity.preflight','runs.accept_launch_intent','runs.current_task']};
  return {prompt:intro+acceptance+`When a task is issued, read its conditions. Submit ONLY one harmless inspect_catalog command through runs.task_action for that current runId/taskIndex, operationId ${operationId}, command {"kind":"inspect_catalog"}. No transfers, payments, purchases, retrievals or other commands are permitted. If the admission response is lost, retry ONLY that identical command with the SAME operationId, never a new operation. Once its actionId is known read runs.task_action_status for that actionId. Then stop without finish_task and without another action. If the issued task does not allow inspect_catalog, stop and report the limitation.`,tools:['identity.preflight','runs.accept_launch_intent','runs.current_task','runs.task_action','runs.task_action_status'],operationIdHash:sha(operationId)};
}

export function createMcdObservedSpawn({onSpawn=()=>{}}={}){
  let child;
  return {spawnImpl(executable,args,options){need(!child,'MCD_NATIVE_SINGLE_PROCESS_ONLY');child=spawn(executable,args,options);onSpawn(child);return child;},killObserved(){need(child&&Number.isInteger(child.pid)&&child.exitCode===null&&!child.killed,'MCD_NATIVE_KILL_TARGET_UNAVAILABLE');return {pid:child.pid,signal:'SIGTERM',killRequested:child.kill('SIGTERM'),at:new Date().toISOString()};}};
}
export function isMcdNativeCrashBoundary(observation){return observation?.sourceTool==='runs.current_task'&&observation.status==='running'&&observation.terminal!==true&&UUID.test(observation.runId??'')&&/^[a-f0-9]{64}$/.test(observation.sourceCallIdHash??'');}
async function metadata(executable,args){return new Promise((done,reject)=>{let bytes=0,parts=[],failed=false;const child=spawn(executable,['--no-daemon','-c','mcp_oauth_credentials_store="file"',...args],{windowsHide:true,env:nativeEnvironment(process.env,executable),stdio:['ignore','pipe','pipe']});const timer=setTimeout(()=>{failed=true;child.kill();},15000);child.stdout.on('data',b=>{bytes+=b.length;if(bytes>1024*1024){failed=true;child.kill();}else parts.push(b);});child.stderr.on('data',()=>{});child.once('error',()=>{failed=true;});child.once('close',code=>{clearTimeout(timer);try{need(!failed&&code===0,'MCD_NATIVE_METADATA_FAILED');done(JSON.parse(Buffer.concat(parts).toString('utf8')));}catch{reject(new Error('MCD_NATIVE_METADATA_FAILED'));}parts=[];});});}
function observeSpool(directory,localId,segmentId,native){const db=new DatabaseSync(resolve(directory,'diagnostics.sqlite'),{readOnly:true});try{db.exec('PRAGMA query_only=ON');const observed=db.prepare('SELECT projection FROM run_observations WHERE segment_id=?').get(segmentId);return {source:'sqlite_observer',observer:{role:'client_sqlite_observer',readOnly:true},queryKind:'actual_safe_client_events_and_batches',...projectActualClientRows({caseRow:db.prepare('SELECT * FROM cases WHERE local_id=?').get(localId),eventRows:db.prepare('SELECT segment_id,payload FROM events WHERE segment_id=? ORDER BY rowid').all(segmentId),batchRows:db.prepare('SELECT segment_id,payload,acked FROM batches WHERE segment_id=? ORDER BY sequence').all(segmentId),segmentId,nativeSummary:native,runObservation:observed?JSON.parse(observed.projection):undefined})};}finally{db.close();}}

export async function runMcdNativeQualification({jobFile,repoRoot=resolve(dirname(fileURLToPath(import.meta.url)),'..'),onBoundary=async()=>{}}){
  const job=validateMcdNativeJob(JSON.parse((await regular(await verifiedPath(repoRoot,jobFile),16384)).toString('utf8'))),output=inside(repoRoot,job.outputDirectory);
  need(relative(repoRoot,output).replaceAll('\\','/').startsWith('.local/'),'MCD_NATIVE_PATH_INVALID');
  await mkdir(output,{recursive:true,mode:0o700});need((await realpath(output)).toLowerCase()===output.toLowerCase(),'MCD_NATIVE_PATH_INVALID');
  const before=await inventory(repoRoot),selection=job.handoffFile?(await readReviewedHandoff(await verifiedPath(repoRoot,job.handoffFile))).selection:undefined,probe=buildMcdNativeProbe({...job,selection});
  const helper=JSON.parse((await regular(await verifiedPath(repoRoot,'.local/diagnostics-helper/helper.json'),8192)).toString('utf8'));
  need(helper.origin===job.origin&&UUID.test(helper.binding?.agentId)&&UUID.test(helper.binding?.connectionId)&&(!selection||selection.agentId===helper.binding.agentId),'MCD_NATIVE_HELPER_BINDING_INVALID');
  const profile=validateDiagnosticOAuthProfile(helper.profile,{origin:job.origin,development:true}),tokens=createDiagnosticTokenProvider({profile,origin:job.origin,development:true,binding:helper.binding,store:createDiagnosticCredentialStore()});
  const executable=resolve(repoRoot,'.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe');await verifyExecutableBundle(executable);
  const version=await new Promise((done,reject)=>{let out='';const c=spawn(executable,['--version'],{windowsHide:true,env:nativeEnvironment(process.env,executable),stdio:['ignore','pipe','ignore']});const timer=setTimeout(()=>c.kill(),15000);c.stdout.on('data',b=>{if(out.length<1024)out+=b.toString('utf8');});c.once('error',()=>reject(new Error('MCD_NATIVE_VERSION_UNAVAILABLE')));c.once('close',code=>{clearTimeout(timer);code===0&&out.trim()==='codex-cli 0.165.0'?done('0.165.0'):reject(new Error('MCD_NATIVE_VERSION_UNAVAILABLE'));});});
  // One explicit capture ID may start at most one real native process, even if an earlier attempt failed.
  const claims=resolve(repoRoot,'.local/mcd-native-claims');await mkdir(claims,{recursive:true,mode:0o700});need((await realpath(claims)).toLowerCase()===claims.toLowerCase(),'MCD_NATIVE_PATH_INVALID');
  try{await writeFile(resolve(claims,job.captureId+'.json'),JSON.stringify({captureId:job.captureId,profile:job.profile,claimedAt:new Date().toISOString()})+'\n',{flag:'wx',mode:0o600});}catch{throw new Error('MCD_NATIVE_CAPTURE_ALREADY_CLAIMED');}
  let proxy,spool;
  try{
    if(job.originProxy)proxy=await startMcdNativeFaultProxy({publicOrigin:job.origin,...(job.foreignCaseId?{foreignCaseId:job.foreignCaseId}:{})});
    const list=await metadata(executable,['mcp','list','--json']);const names=validateNativeMetadata({list,server:await metadata(executable,['mcp','get','w3bench_user','--json']),origin:job.origin});
    // AICODE-NOTE: The helper owns only its own Credential Manager namespace. No native OAuth credential is read, copied or replaced.
    await tokens.getAccessToken();const transport=createDiagnosticTransport({origin:job.origin,development:true,getAccessToken:()=>tokens.getAccessToken()});
    const directory=resolve(output,'spool');spool=await openDiagnosticSpool({directory});
    const local=spool.createCase({binding:helper.binding,...(selection?{intentId:selection.intentId}:{})}),segmentId=spool.createSegment(local.local_id);
    const registered=await transport.register({diagnosticSessionId:local.session_id,...(selection?{intentId:selection.intentId}:{})});spool.bindRemote(local.local_id,registered);
    let crashObservation,killReceipt;const actual=createMcdObservedSpawn();
    const collector=new NativeDiagnosticCollector({clientVersion:version,expectedIntentId:selection?.intentId,onEnvelope:e=>spool.append(segmentId,e),onGap:code=>spool.markGap(local.local_id,code),onRunObservation:observation=>{
      const recorded=spool.recordRunObservation(segmentId,observation);
      if(recorded&&selection&&['queued','preparing','running','cancellation_requested'].includes(observation.status)&&observation.terminal!==true){
        if(probe.operationIdHash&&!proxy.dropped)proxy.arm({runId:observation.runId,operationIdHash:probe.operationIdHash});
        if(job.profile==='crash-after-active-run'&&isMcdNativeCrashBoundary(observation)&&!killReceipt){crashObservation=observation;killReceipt=actual.killObserved();}
      }return recorded;
    }});collector.bindRegisteredRun(registered);
    const args=instrumentedNativeArguments({caseId:job.foreignCaseId??registered.caseId,otherServers:list,executable});args.pop();args.push('--config','mcp_servers.w3bench_user.enabled_tools='+JSON.stringify(probe.tools),'-');
    const workspace=resolve(output,'workspace');await mkdir(workspace,{mode:0o700});const startedAt=new Date().toISOString();
    await onBoundary({phase:'before_native',captureId:job.captureId,profile:job.profile,caseId:registered.caseId,segmentId});
    const native=await runProjectedNative({executable,args,cwd:workspace,prompt:probe.prompt,collector,spawnImpl:actual.spawnImpl,timeoutMs:job.timeoutMs??180000});
    for(;;){const b=spool.stageBatch(segmentId,{completion:spool.caseState(local.local_id).gap?'partial':'complete'});if(!b||b.completion!=='open')break;}
    const preDelivery=observeSpool(directory,local.local_id,segmentId,native);
    await onBoundary({phase:'after_native_before_delivery',captureId:job.captureId,profile:job.profile,caseId:registered.caseId,segmentId});
    const delivery=await deliverDiagnosticOutbox({spool,transport,binding:helper.binding,maxAttempts:1}),postDelivery=observeSpool(directory,local.local_id,segmentId,native);
    await onBoundary({phase:'after_delivery',captureId:job.captureId,profile:job.profile,caseId:registered.caseId,segmentId});
    const after=await inventory(repoRoot);need(canonicalDiagnosticJson(before)===canonicalDiagnosticJson(after),'MCD_NATIVE_SOURCE_CHANGED');
    const write=async(name,value)=>{const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');need(bytes.length<=8*1024*1024,'MCD_NATIVE_ARTIFACT_BOUND');const path=resolve(output,name);await writeFile(path,bytes,{flag:'wx',mode:0o600});return {path:relative(repoRoot,path).replaceAll('\\','/'),sha256:sha(bytes)};};
    const nativeRef=await write('native.json',{implementation:'native_codex_cli',clientVersion:version,boundary:'actual_pinned_native_model_process',profile:job.profile,startedAt,finishedAt:new Date().toISOString(),calls:postDelivery.calls,localToolCalls:postDelivery.localToolCalls,summary:native,lastRunObservation:native.clientRunObservation??{},selection:selection?{agentId:selection.agentId,intentId:selection.intentId,mode:selection.mode}:{agentId:helper.binding.agentId},qualificationOnly:true});
    const preDeliveryRef=await write('outbox-before-delivery.json',preDelivery),clientOutboxRef=await write('client-outbox.json',postDelivery),transportRef=await write('transport-faults.json',{boundary:'actual_origin_preserving_loopback_proxy',enabled:!!proxy,observations:proxy?.observations??[],observationOverflowCount:proxy?.observationOverflowCount??0,captureOutcome:proxy?.captureOutcome??'not_used',crashObservation:crashObservation??null,killReceipt:killReceipt??null});
    const preflightCalls=postDelivery.calls.filter(c=>c.tool==='identity.preflight');
    const observed=job.profile==='invalid-schema-preflight'?preflightCalls.length===2&&preflightCalls[0].outcome==='success'&&UUID.test(preflightCalls[0].traceId??'')&&preflightCalls[1].outcome==='error'&&preflightCalls[1].errorCode==='INPUT_VALIDATION_ERROR':job.profile==='free-own-preflight'?preflightCalls.length===1&&preflightCalls[0].outcome==='success':job.profile==='crash-after-active-run'?!!crashObservation&&killReceipt?.killRequested===true:job.profile==='lost-admission-response'?proxy.dropped:proxy.observations.some(o=>o.kind==='foreign_case_transport'&&[403,404].includes(o.httpStatus));
    const manifest={schemaVersion:'mcd-native-fault-fragments/v1',scenarioId:'MCD-SC-002',captureId:job.captureId,profile:job.profile,sourceInputs:{before,after},raw:{native:nativeRef,clientOutbox:clientOutboxRef,preDelivery:preDeliveryRef,transport:transportRef},delivery:{mechanism:'deterministic_helper',trigger:native.exitCode===0?'native_exit':'native_error',attempts:delivery,caseId:registered.caseId,segmentId,reportId:postDelivery.case.reportId},boundaryOutcome:postDelivery.localToolCalls.length?'blocked_local_tool_observed':proxy?.observationOverflowCount?'blocked_transport_observation_overflow':observed?'observed_requires_independent_replay':'blocked_required_native_fault_not_observed',runtimeStatus:'incomplete',missingBoundaries:['before_after_business_and_diagnostic_postgresql_observer','actual_helper_browser_pkce_consent','actual_http_receipt_and_contiguous_server_watermarks','admin_browser_click_and_database_match','remaining_exact_sc002_variants']};
    return {manifestRef:await write('fragments.json',manifest),nativeRef,clientOutboxRef,transportRef,caseId:registered.caseId,segmentId,boundaryOutcome:manifest.boundaryOutcome,runtimeStatus:'incomplete'};
  }finally{spool?.close();await proxy?.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const args=process.argv.slice(2);if(args.length!==2||args[0]!=='--job'){process.stderr.write('Usage: node tools/mcd-native-qualification.mjs --job <private qualification job JSON>\n');process.exitCode=1;}else runMcdNativeQualification({jobFile:args[1]}).then(result=>process.stdout.write(JSON.stringify(result,null,2)+'\n')).catch(error=>{process.stderr.write(/^MCD_NATIVE_[A-Z_]+$/.test(error?.message)?error.message:'MCD_NATIVE_QUALIFICATION_BLOCKED');process.exitCode=1;});}
