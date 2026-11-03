/** Operator qualification seam. Captures native evidence; never delivers a batch. */
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {mkdir,realpath,lstat,writeFile} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {captureInstrumentedRun,runProjectedNative,instrumentedNativeArguments,validateNativeMetadata,metadataCommand} from './mcp-diagnostics-launcher.mjs';
import {openDiagnosticSpool,createDiagnosticTransport} from './mcp-diagnostics-client.mjs';
import {buildMcdNativeProbe} from './mcd-native-qualification.mjs';
import {projectActualClientRows} from './run-mcd-client-capture.mjs';
import {verifyExecutableBundle} from '../infrastructure/owner-identity/run-codex-google-local.mjs';
import {collectNativeMcdSourceInputs} from '../packages/owner-acceptance/src/mcd-native-source-inputs.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const need=(value,code)=>{if(!value)throw new Error(code);};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export const MCD_PENDING_PROFILES=Object.freeze(['free-own-preflight','invalid-schema-preflight']);

async function privateDirectory(root,path){
  const full=resolve(root,path),part=relative(root,full);need(part&&!isAbsolute(part)&&!part.startsWith('..')&&part.split(sep)[0]==='.local','MCD_PENDING_PATH_INVALID');
  let current=resolve(root);need((await realpath(current)).toLowerCase()===current.toLowerCase(),'MCD_PENDING_PATH_INVALID');
  for(const component of part.split(sep)){current=resolve(current,component);await mkdir(current,{mode:0o700}).catch(error=>{if(error.code!=='EEXIST')throw error;});const stat=await lstat(current);need(stat.isDirectory()&&!stat.isSymbolicLink()&&(await realpath(current)).toLowerCase()===current.toLowerCase(),'MCD_PENDING_PATH_INVALID');}
  return full;
}

export async function prepareMcdNativePendingCapture(options,dependencies={}){
  const {repoRoot,captureId,profile,outputDirectory,binding,getAccessToken,retryBudget={attempts:0},origin='http://127.0.0.1:3000'}=options;
  need(Object.keys(options).every(key=>['repoRoot','captureId','profile','outputDirectory','binding','getAccessToken','retryBudget','origin','timeoutMs'].includes(key))&&typeof repoRoot==='string'&&typeof outputDirectory==='string'&&UUID.test(captureId)&&MCD_PENDING_PROFILES.includes(profile)&&origin==='http://127.0.0.1:3000'&&UUID.test(binding?.agentId)&&UUID.test(binding?.connectionId)&&Object.keys(binding).length===2&&typeof getAccessToken==='function'&&Number.isInteger(retryBudget.attempts)&&retryBudget.attempts>=0&&retryBudget.attempts<=5,'MCD_PENDING_OPTIONS_INVALID');
  need(options.timeoutMs===undefined||Number.isInteger(options.timeoutMs)&&options.timeoutMs>=1000&&options.timeoutMs<=180000,'MCD_PENDING_OPTIONS_INVALID');
  need(Object.keys(dependencies).every(key=>['verifyBundle','metadata','spawnImpl','fetchImpl','collectSources'].includes(key)),'MCD_PENDING_DEPENDENCIES_INVALID');
  const root=resolve(repoRoot),output=await privateDirectory(root,outputDirectory),claims=await privateDirectory(root,'.local/mcd-native-claims');
  await writeFile(resolve(claims,captureId+'.json'),JSON.stringify({captureId,profile,claimedAt:new Date().toISOString()})+'\n',{flag:'wx',mode:0o600}).catch(()=>{throw new Error('MCD_PENDING_CAPTURE_ALREADY_CLAIMED');});
  const collect=dependencies.collectSources??collectNativeMcdSourceInputs,before=await collect(root),fixture=Object.keys(dependencies).length>0;
  let spool,closed=false,started=false,capture;
  const write=async(name,value)=>{const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');need(bytes.length<=8*1024*1024,'MCD_PENDING_ARTIFACT_BOUND');const path=resolve(output,name+'.json');await writeFile(path,bytes,{flag:'wx',mode:0o600});return {path:relative(root,path).split(sep).join('/'),sha256:hash(bytes)};};
  const ensureOpen=()=>need(!closed,'MCD_PENDING_CAPTURE_CLOSED');
  const close=()=>{if(closed)return;closed=true;try{spool?.close();}catch{throw new Error('MCD_PENDING_CLOSE_FAILED');}};
  try{
    const executable=resolve(root,'.local/codex-runner-inspection/package/vendor/x86_64-pc-windows-msvc/bin/codex.exe');
    await (dependencies.verifyBundle??verifyExecutableBundle)(executable);
    const metadata=dependencies.metadata??metadataCommand,list=await metadata(executable,['mcp','list','--json']);
    validateNativeMetadata({list,server:await metadata(executable,['mcp','get','w3bench_user','--json']),origin});
    const transport=createDiagnosticTransport({origin,development:true,getAccessToken,fetchImpl:dependencies.fetchImpl??fetch});
    const directory=resolve(output,'spool');spool=await openDiagnosticSpool({directory});
    const workspace=await privateDirectory(root,relative(root,resolve(output,'workspace'))),probe=buildMcdNativeProbe({profile,captureId});
    const startedAt=new Date().toISOString();
    capture=await captureInstrumentedRun({spool,transport,binding,selection:{},prompt:probe.prompt,deliver:undefined,execute:async({caseId,collector,prompt})=>{
      need(UUID.test(caseId),'MCD_PENDING_CASE_UNREGISTERED');
      const args=instrumentedNativeArguments({caseId,otherServers:list,executable});args.pop();args.push('--config','mcp_servers.w3bench_user.enabled_tools='+JSON.stringify(probe.tools),'-');
      started=true;return runProjectedNative({executable,args,cwd:workspace,prompt,collector,timeoutMs:options.timeoutMs??180000,...(dependencies.spawnImpl?{spawnImpl:dependencies.spawnImpl}:{})});
    }});
    need(UUID.test(capture.caseId)&&started,'MCD_PENDING_CASE_UNREGISTERED');
    const observe=()=>{ensureOpen();need(capture.localCaseId&&capture.segmentId,'MCD_PENDING_CASE_UNAVAILABLE');const db=new DatabaseSync(resolve(directory,'diagnostics.sqlite'),{readOnly:true});try{
      db.exec('PRAGMA query_only=ON; PRAGMA busy_timeout=5000; BEGIN');
      const caseRow=db.prepare('SELECT * FROM cases WHERE local_id=?').get(capture.localCaseId),batchRows=db.prepare('SELECT segment_id,payload,acked FROM batches WHERE segment_id=? ORDER BY sequence').all(capture.segmentId),eventRows=db.prepare('SELECT segment_id,payload FROM events WHERE segment_id=? ORDER BY rowid').all(capture.segmentId),observation=db.prepare('SELECT projection FROM run_observations WHERE segment_id=?').get(capture.segmentId);
      return {source:'sqlite_observer',observer:{role:'client_sqlite_observer',readOnly:true},queryKind:'actual_safe_client_events_and_batches',...projectActualClientRows({caseRow,batchRows,eventRows,segmentId:capture.segmentId,nativeSummary:capture.native,runObservation:observation?JSON.parse(observation.projection):undefined}),pendingBatchCount:batchRows.filter(row=>!row.acked).length,acknowledgedBatchCount:batchRows.filter(row=>row.acked).length};
    }finally{db.close();}};
    const pending=observe();need(pending.acknowledgedBatchCount===0&&pending.pendingBatchCount>0,'MCD_PENDING_IMPLICIT_DELIVERY');
    const after=await collect(root);try{assert.deepEqual(after,before);}catch{throw new Error('MCD_PENDING_SOURCE_CHANGED');}
    const nativeRef=await write('native',{implementation:fixture?'local_injected_fixture':'native_codex_cli',clientVersion:'0.165.0',boundary:fixture?'local_primitive_not_native_acceptance':started?'actual_verified_native_attempt':'native_not_started',profile,captureId,startedAt,finishedAt:new Date().toISOString(),summary:capture.native,calls:pending.calls,localToolCalls:pending.localToolCalls,lastRunObservation:capture.native.clientRunObservation??{},selection:{agentId:binding.agentId},qualificationOnly:true,sourceInputs:{before,after}}),clientOutboxRef=await write('outbox-before-delivery',pending);
    const guardedSpool=new Proxy(spool,{get(target,key){if(key==='close')return close;const value=Reflect.get(target,key);return typeof value==='function'?(...args)=>{ensureOpen();return value.apply(target,args);}:value;}});
    return {captureId,profile,nativeRef,clientOutboxRef,sourceInputs:{before,after},native:capture.native,context:{spool:guardedSpool,localCaseId:capture.localCaseId,segmentId:capture.segmentId,batch:spool.pendingBatches(capture.localCaseId).at(-1),binding,origin,getAccessToken,retryBudget},observe,close,delivery:'not_attempted',nativeStarted:started};
  }catch(error){
    const errorCode=/^(MCD_PENDING|DIAGNOSTICS)_[A-Z_]+$/.test(error?.message)?error.message:'MCD_PENDING_CAPTURE_FAILED';
    let closeFailed=false;try{close();}catch{closeFailed=true;}
    const failureRef=await write('failure',{schemaVersion:'mcd-pending-failure/v1',captureId,profile,errorCode,nativeStarted:started,closeFailed,rawMessageOmitted:true}).catch(()=>null);
    throw Object.assign(new Error(errorCode),{failureRef});
  }
}
