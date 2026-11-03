/** Acceptance-only approved BER seal/evidence fault capture. No entrypoint; never original Google DB.
 * Implements approved BER010/012 boundaries; importing does not connect or mutate.
 */
import {readFile,writeFile,mkdir,realpath,lstat,open,rename,unlink,chmod,readdir} from 'node:fs/promises';
import {createHash,randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import {resolve,relative,isAbsolute,sep,dirname} from 'node:path';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/,MAX_FILE=8*1024*1024,MAX_ALL=32*1024*1024;
export const BER_GENERIC_SEAL_FAULT_VARIANTS=Object.freeze(['missing_child','corrupt_child','restart_blocked_seal']);
const TRAINING_TASKS=Object.freeze(['S1','M1','H1']),RANKED_TASKS=Object.freeze(['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1']);
export const BER_GENERIC_SEAL_FAULT_TARGETS=Object.freeze({
 paid_s1:Object.freeze({flag:'--ber-admitted-s1-pay-only',mode:'training',taskIds:Object.freeze(['S1']),taskId:'S1',taskIndex:0,child:'paid',childSchema:'bts-paid-family-observation-capture/v1'}),
 chain_s1:Object.freeze({flag:'--ber-admitted-matrix-training-b',mode:'training',taskIds:TRAINING_TASKS,taskId:'S1',taskIndex:0,child:'chain',childSchema:'bts-chain-family-observation-capture/v1'}),
 composite_u1:Object.freeze({flag:'--ber-composite-mixed-ranked',mode:'ranked',taskIds:RANKED_TASKS,taskId:'U1',taskIndex:11,child:'chain',childSchema:'bts-chain-family-observation-capture/v1'}),
});
const targetDefinition=profile=>{need(Object.hasOwn(BER_GENERIC_SEAL_FAULT_TARGETS,profile),'BER_FAULT_TARGET_PROFILE');return BER_GENERIC_SEAL_FAULT_TARGETS[profile];};
export function resolveBerGenericSealFaultTarget(argv,env){
 need(Array.isArray(argv)&&argv.length===1,'BER_GENERIC_SEAL_FAULT_PROFILE_REQUIRED');const match=Object.entries(BER_GENERIC_SEAL_FAULT_TARGETS).find(([,v])=>v.flag===argv[0]);
 need(match&& (env.OID_BER_GENERIC_SEAL_FAULT_TARGET===undefined||env.OID_BER_GENERIC_SEAL_FAULT_TARGET===match[0]),'BER_GENERIC_SEAL_FAULT_PROFILE_REQUIRED');return match[0];
}
const canonical=v=>JSON.stringify(v,(_,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.keys(x).sort().map(k=>[k,x[k]])):x);

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sleep=ms=>new Promise(done=>setTimeout(done,ms));
const need=(ok,code)=>{if(!ok)throw Object.assign(new Error(code),{code});};

/** Explicit finite operator selector; never enabled by an ordinary participant run. */
export function parseBerGenericSealFault(argv,env){
 const variant=env.OID_BER_GENERIC_SEAL_FAULT;if(variant===undefined){need(env.OID_BER_GENERIC_SEAL_FAULT_TARGET===undefined,'BER_GENERIC_SEAL_FAULT_PROFILE_REQUIRED');return null;}
 need(BER_GENERIC_SEAL_FAULT_VARIANTS.includes(variant),'BER_GENERIC_SEAL_FAULT_VARIANT');
 need(resolveBerGenericSealFaultTarget(argv,env)&&
  env.OID_BETA_MANIFEST_FILE===undefined&&
  !['OID_BER_RECOVERY_CORE','OID_BER_UNKNOWN_GRADING','OID_BER_H1_CUTOFF','OID_BER_INTERRUPT_BEFORE_FIRST_REFUND','OID_AFR_SUCCESSOR_PREPARATION_FAILURE'].some(key=>env[key]==='1'),
  'BER_GENERIC_SEAL_FAULT_PROFILE_REQUIRED');
 return variant;
}

/** Holder stays in process memory. Only snapshot() may enter a capture. */
export function createBerGenericSealFaultSeam(input,{arm=armBerGenericSealFault}={}){
 need(BER_GENERIC_SEAL_FAULT_VARIANTS.includes(input.variant)&&UUID.test(input.captureId??''),'BER_GENERIC_SEAL_FAULT_SCOPE');
 const targetProfile=input.targetProfile??'paid_s1',definition=targetDefinition(targetProfile);
 let state='idle',handle,selected,reference,primaryReference,closed=false;
 return{
  variant:input.variant,
  matchesTarget(target){return target?.taskId===definition.taskId&&target.taskIndex===definition.taskIndex;},
  async beforeFinish(target){
   need(state==='idle'&&target.taskId===definition.taskId&&target.taskIndex===definition.taskIndex&&UUID.test(target.runId??''),'BER_GENERIC_SEAL_FAULT_SINGLE_S1_TARGET');
   state='arming';selected={runId:target.runId,taskIndex:definition.taskIndex,taskId:definition.taskId,targetProfile};
   try{handle=await arm({...input,...selected,privateDirectory:resolve(input.repoRoot,'.local/ber-generic-fault',input.captureId,input.variant)});state='armed';}
   catch(error){state='blocked';throw error;}
  },
  async afterFinish(finish){
   need(state==='armed'&&selected.runId===finish.runId&&finish.taskIndex===definition.taskIndex&&finish.taskId===definition.taskId&&UUID.test(finish.closureId??'')&&UUID.test(finish.operationId??''),'BER_GENERIC_SEAL_FAULT_FINISH_IDENTITY');
   state='observing';try{reference=await handle.afterNormalFinish({closureId:finish.closureId,operationId:finish.operationId});state='captured';return reference;}
   catch(error){state='blocked';reference=error.berGenericFaultCapture??error.cleanupRef;throw error;}
  },
  async close(){if(closed)return;closed=true;try{await handle?.close();}catch(error){state='blocked';const ref=error?.cleanupRef;if(typeof ref?.path==='string'&&ref.path.startsWith('.local/ber-generic-fault/'+input.captureId+'/')&&ref.path.length<=512&&/^[A-Za-z0-9._/-]+$/.test(ref.path)&&!ref.path.split('/').some(p=>!p||p==='.'||p==='..')&&SHA.test(ref.sha256??'')){primaryReference=reference;reference={path:ref.path,sha256:ref.sha256};}throw error;}},
  snapshot(){return{schemaVersion:'ber-generic-seal-fault-seam/v1',variant:input.variant,targetProfile,status:state,...(reference?{evidence:reference}:{}),...(primaryReference?{primaryEvidence:primaryReference}:{})};},
 };
}

export function validateGenericSealFaultScope(input){
 need(input&&BER_GENERIC_SEAL_FAULT_VARIANTS.includes(input.variant),'BER_FAULT_VARIANT');
 need(UUID.test(input.runId??'')&&Number.isInteger(input.taskIndex)&&input.taskIndex>=0&&input.taskIndex<12&&/^(S[1-4]|M[1-4]|H[1-3]|U1)$/.test(input.taskId??''),'BER_FAULT_TASK_SCOPE');
 const targetProfile=input.targetProfile??'paid_s1',definition=targetDefinition(targetProfile);need(input.taskId===definition.taskId&&input.taskIndex===definition.taskIndex,'BER_FAULT_EXACT_PROFILE_TASK');
 need(typeof input.repoRoot==='string'&&typeof input.privateDirectory==='string','BER_FAULT_PRIVATE_ROOT');
 const owner=new URL(input.databaseUrl),observer=new URL(input.observerDatabaseUrl);
 need(owner.protocol==='postgres:'&&owner.hostname==='postgres'&&owner.username==='oid_owner'&&/^\/oid_acceptance_[a-f0-9]{32}$/.test(owner.pathname),'BER_FAULT_DISPOSABLE_OWNER_REQUIRED');
 need(observer.protocol==='postgres:'&&observer.hostname===owner.hostname&&observer.port===owner.port&&observer.pathname===owner.pathname&&observer.username==='oid_observer','BER_FAULT_DISPOSABLE_OBSERVER_REQUIRED');
 need(typeof input.stopApi==='function'&&typeof input.restartApi==='function','BER_FAULT_LIFECYCLE_CALLBACKS');
 // Never serialize these URLs: credentials remain caller-owned process memory.
 return {databaseName:owner.pathname.slice(1),runId:input.runId,taskIndex:input.taskIndex,taskId:input.taskId,variant:input.variant,targetProfile};
}

function inside(root,path){const r=relative(root,path);return r!==''&&!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+sep);}
export async function resolveGenericSealFaultPrivateDirectory(repoRoot,privateDirectory,{create=false}={}){
 const root=await realpath(repoRoot),path=resolve(privateDirectory),local=resolve(root,'.local');
 need(inside(local,path),'BER_FAULT_PRIVATE_LOCAL_REQUIRED');
 let cursor=root;for(const part of relative(root,path).split(sep)){cursor=resolve(cursor,part);let st;try{st=await lstat(cursor);}catch(e){if(e.code!=='ENOENT'||!create)throw e;await mkdir(cursor,{mode:0o700});st=await lstat(cursor);}need(st.isDirectory()&&!st.isSymbolicLink(),'BER_FAULT_PRIVATE_SYMLINK');}
 need(await realpath(path)===path,'BER_FAULT_PRIVATE_REALPATH');return path;
}
export function projectGenericSealFaultLifecycleReceipt(value,kind){
 const schema=kind==='stop'?'beta-local-api-stop-receipt/v1':'beta-local-api-restart-receipt/v1';
 need(value&&value.schemaVersion===schema,'BER_FAULT_LIFECYCLE_RECEIPT_SCHEMA');
 const out={schemaVersion:schema};for(const key of ['previousPid','currentPid','exitCode','healthHttpStatus'])if(Number.isSafeInteger(value[key]))out[key]=value[key];
 if(value.exitCode===null)out.exitCode=null;
 if(value.signal===null||typeof value.signal==='string'&&/^SIG[A-Z]{2,12}$/.test(value.signal))out.signal=value.signal;
 for(const key of ['startedAt','finishedAt'])if(typeof value[key]==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value[key]))out[key]=value[key];
 need(Number.isSafeInteger(out.previousPid)&&out.previousPid>0,'BER_FAULT_REAL_PREVIOUS_PID_REQUIRED');
 if(kind==='restart')need(Number.isSafeInteger(out.currentPid)&&out.currentPid>0&&out.currentPid!==out.previousPid&&out.healthHttpStatus===200,'BER_FAULT_REAL_HEALTHY_RESTART_REQUIRED');
 else need(Number.isSafeInteger(out.exitCode)||typeof out.signal==='string','BER_FAULT_REAL_STOP_EXIT_REQUIRED');
 return out;
}
/** Every cleanup boundary runs even if restoration fails. Errors are safe finite projections. */
export async function runGenericSealFaultCleanupSteps(steps){const failures=[];for(const [step,fn]of steps){try{await fn();}catch(e){failures.push({step,errorClass:e?.constructor?.name??'Error',code:/^[A-Z0-9_]{1,100}$/.test(e?.code??'')?e.code:'BER_FAULT_CLEANUP_STEP_FAILED'});}}return failures;}
export async function resolveGenericSealFaultCaptureFile(repoRoot,target,ref){
 need(ref&&typeof ref.path==='string'&&SHA.test(ref.sha256??''),'BER_FAULT_EVIDENCE_REFERENCE');
 const prefix=`artifacts/runs/owner-identity-bef-task-coordinator/observation/${target.runId}/${target.taskId}/`;
 need(ref.path.startsWith(prefix)&&ref.path===prefix+ref.sha256+'.json'&&!ref.path.includes('\\'),'BER_FAULT_EXACT_CAPTURE_CHILD_REQUIRED');
 const root=await realpath(repoRoot),path=resolve(root,...ref.path.split('/'));
 need(inside(root,path),'BER_FAULT_PATH_ESCAPE');
 let cursor=root;for(const part of ref.path.split('/')){cursor=resolve(cursor,part);need(!(await lstat(cursor)).isSymbolicLink(),'BER_FAULT_SYMLINK');}
 need(await realpath(path)===path,'BER_FAULT_REALPATH');return path;
}
export async function readGenericSealFaultEvidence(path,expectedSha){
 const file=await open(path,'r');try{
  const before=await file.stat();need(before.isFile()&&before.size>0&&before.size<=MAX_FILE,'BER_FAULT_EVIDENCE_SIZE');
  const bytes=Buffer.alloc(before.size+1);let offset=0;while(offset<bytes.length){const {bytesRead}=await file.read(bytes,offset,bytes.length-offset,offset);if(!bytesRead)break;offset+=bytesRead;}
  const after=await file.stat();need(offset===before.size&&before.size===after.size&&before.mtimeMs===after.mtimeMs&&before.ctimeMs===after.ctimeMs&&before.ino===after.ino,'BER_FAULT_EVIDENCE_CHANGED');
  const result=bytes.subarray(0,offset);need(hash(result)===expectedSha,'BER_FAULT_EVIDENCE_HASH');return result;
 }finally{await file.close();}
}

/** Actual file mechanics only, separately unit-tested. Original bytes always retained.
 * Caller must FIRST prove exact blocked SQL window. This helper cannot claim unknown.
 */
export async function stageGenericSealChildFault({repoRoot,target,ref,privateDirectory,variant}){
 need(['missing_child','corrupt_child'].includes(variant),'BER_FAULT_FILE_VARIANT');
 const source=await resolveGenericSealFaultCaptureFile(repoRoot,target,ref),bytes=await readGenericSealFaultEvidence(source,ref.sha256),privateRoot=await resolveGenericSealFaultPrivateDirectory(repoRoot,privateDirectory);
 const id=randomUUID(),archive=resolve(privateRoot,`original-${id}.bin`),held=resolve(privateRoot,`held-${id}.bin`);
 await writeFile(archive,bytes,{flag:'wx',mode:0o600});await chmod(archive,0o400);
 let changed=false,restored=false,changedArchive;
 const restore=async()=>{
  if(restored)return;
  if(changed){
   if(variant==='missing_child')await rename(held,source);
   else{const temp=resolve(dirname(source),`.ber-restore-${id}.tmp`);await writeFile(temp,bytes,{flag:'wx',mode:0o600});await rename(temp,source);}
  }
  await readGenericSealFaultEvidence(source,ref.sha256);restored=true;
 };
 try{
  if(variant==='missing_child'){await rename(source,held);changed=true;}
  else{const altered=Buffer.from(bytes);altered[altered.length-1]^=1;const temp=resolve(dirname(source),`.ber-corrupt-${id}.tmp`);await writeFile(temp,altered,{flag:'wx',mode:0o600});await rename(temp,source);changed=true;
   const actualChanged=await readFile(source),changedPath=resolve(privateRoot,`changed-${id}.bin`);await writeFile(changedPath,actualChanged,{flag:'wx',mode:0o600});await chmod(changedPath,0o400);changedArchive={path:relative(repoRoot,changedPath).split(sep).join('/'),sha256:hash(actualChanged),size:actualChanged.length};}
  return {ref,originalArchive:{path:relative(repoRoot,archive).split(sep).join('/'),sha256:hash(bytes),size:bytes.length},...(changedArchive?{changedArchive}:{}),variant,
   async observe(){const directoryEntries=(await readdir(dirname(source))).sort();need(directoryEntries.length<=256,'BER_FAULT_DIRECTORY_BOUND');try{const current=await readFile(source);return {exists:true,size:current.length,sha256:hash(current),matchesOriginal:hash(current)===ref.sha256,directoryEntries};}catch(e){if(e.code==='ENOENT')return {exists:false,matchesOriginal:false,directoryEntries};throw e;}},restore};
 }catch(error){try{await restore();}catch(restoration){throw new AggregateError([error,restoration],'BER_FAULT_RESTORATION_FAILED');}throw error;}
}

export async function observeGenericSealFaultSelectedChild(repoRoot,target,rootPacket,ownerActions){
 const definition=targetDefinition(target.targetProfile??'paid_s1'),ref=rootPacket?.children?.[definition.child]?.evidence;
 need(rootPacket?.binding?.runId===target.runId&&rootPacket.binding.taskId===definition.taskId&&rootPacket.taskIndex===definition.taskIndex,'BER_FAULT_ROOT_TARGET_BINDING');
 const path=await resolveGenericSealFaultCaptureFile(repoRoot,target,ref),bytes=await readGenericSealFaultEvidence(path,ref.sha256),child=JSON.parse(bytes);
 need(child.schemaVersion===definition.childSchema&&canonical(child.binding)===canonical(rootPacket.binding)&&canonical(child.execution)===canonical(rootPacket.execution)&&(definition.child==='paid'?canonical(child.closure)===canonical(rootPacket.closure):canonical(child.closure)===canonical({closureId:rootPacket.closure?.closureId,actionCutoffSequence:rootPacket.closure?.actionCutoffSequence,reconciledActionSequence:rootPacket.closure?.reconciledActionSequence})),'BER_FAULT_SELECTED_CHILD_BINDING');
 const selectedTransactions=[];
 if(definition.child==='chain'){
  const rows=child.ownerActions;need(Array.isArray(ownerActions)&&Array.isArray(rows)&&Array.isArray(child.rpc?.transactions),'BER_FAULT_SELECTED_CHAIN_ROWS');
  for(const action of rows)if(['approve','transfer','wrap','unwrap','swap'].includes(action.actionKind)){
   need(UUID.test(action.actionId??'')&&UUID.test(action.befOperationId??'')&&/^0x[a-f0-9]{64}$/i.test(action.transactionHash??''),'BER_FAULT_SELECTED_CHAIN_IDENTITY');
   need(Number.isSafeInteger(action.actionSequence)&&action.actionSequence>0&&Number.isSafeInteger(rootPacket.closure?.actionCutoffSequence)&&action.actionSequence<=rootPacket.closure.actionCutoffSequence,'BER_FAULT_SELECTED_CHAIN_CUTOFF');
   const original=ownerActions.filter(a=>a.id===action.actionId&&a.run_id===target.runId&&a.task_id===target.taskId&&a.task_index===target.taskIndex&&a.receipt_status==='observed'&&a.action_kind===action.actionKind&&a.operation_id===action.ownerOperationId&&a.payload_hash===action.commandSha256&&String(a.action_sequence)===String(action.actionSequence)&&a.transaction_hash?.toLowerCase()===action.transactionHash.toLowerCase()&&a.evidence_hash===action.actionEvidence?.sha256&&a.evidence_path===action.actionEvidence?.path);need(original.length===1,'BER_FAULT_SELECTED_CHAIN_OWNER_RECEIPT');
   const source=child.bef?.before;need(Array.isArray(source?.operations)&&Array.isArray(source?.selectedExecutions),'BER_FAULT_SELECTED_CHAIN_SOURCE');
   const operation=source.operations.filter(o=>o.operationId===action.befOperationId&&o.environmentId===child.execution.environmentId&&o.generationId===child.execution.generationId&&o.actionKind===action.actionKind&&o.idempotencyKeySha256===hash('task-action-'+action.actionId)&&o.transactionHash?.toLowerCase()===action.transactionHash.toLowerCase());
   const selected=source.selectedExecutions.filter(o=>o.operationId===action.befOperationId&&o.environmentId===child.execution.environmentId&&o.generationId===child.execution.generationId&&o.actionKind===action.actionKind&&o.transactionHash?.toLowerCase()===action.transactionHash.toLowerCase()&&['success','reverted'].includes(o.outcome));need(operation.length===1&&selected.length===1,'BER_FAULT_SELECTED_CHAIN_SOURCE_JOIN');
   const txs=child.rpc.transactions.filter(t=>t.hash?.toLowerCase()===action.transactionHash.toLowerCase());need(txs.length===1&&['success','reverted'].includes(txs[0].status)&&txs[0].status===selected[0].outcome,'BER_FAULT_SELECTED_CHAIN_TRANSACTION');
   selectedTransactions.push({actionId:action.actionId,befOperationId:action.befOperationId,transactionHash:action.transactionHash.toLowerCase(),status:txs[0].status});
  }
  need(selectedTransactions.length>0&&new Set(selectedTransactions.map(t=>t.transactionHash)).size===selectedTransactions.length,'BER_FAULT_SELECTED_CHAIN_REQUIRED');
 }
 return{family:definition.child,evidence:{path:ref.path,sha256:hash(bytes),size:bytes.length},schemaVersion:child.schemaVersion,selectedTransactions};
}

export async function discoverRoot(repoRoot,target){
 const prefix=`artifacts/runs/owner-identity-bef-task-coordinator/observation/${target.runId}/${target.taskId}`,folder=resolve(repoRoot,prefix);
 const names=(await readdir(folder)).filter(x=>/^[a-f0-9]{64}\.json$/.test(x));need(names.length<=256,'BER_FAULT_EVIDENCE_DIRECTORY_BOUND');
 let total=0;const roots=[];
 for(const name of names){const ref={path:prefix+'/'+name,sha256:name.slice(0,64)},path=await resolveGenericSealFaultCaptureFile(repoRoot,target,ref),bytes=await readGenericSealFaultEvidence(path,ref.sha256);total+=bytes.length;need(total<=MAX_ALL,'BER_FAULT_AGGREGATE_BOUND');const value=JSON.parse(bytes);
  if(value.schemaVersion==='bts-admitted-actions-observation-capture/v1'&&value.binding?.runId===target.runId&&value.taskIndex===target.taskIndex&&value.binding?.taskId===target.taskId)roots.push({ref,value});
 }
 // A new attempt can write another identical-source root; fault must target the
 // root actually present before first seal. Ambiguous roots remain blocked.
 need(roots.length===1,'BER_FAULT_UNAMBIGUOUS_ROOT_REQUIRED');return roots[0];
}

const EVIDENCE_FAILURE_CODES=Object.freeze({missing_child:'TASK_EVIDENCE_FILE_UNAVAILABLE',corrupt_child:'TASK_EVIDENCE_FILE_HASH_MISMATCH'});
export function isExpectedGenericSealEvidenceFailure(variant,value,target){return Object.hasOwn(EVIDENCE_FAILURE_CODES,variant)&&value?.schemaVersion==='local-bef-task-observation-progress/v1'&&value.runId===target.runId&&value.taskIndex===target.taskIndex&&['blocked','unavailable'].includes(value.status)&&['seal','reload'].includes(value.stage)&&value.reasonCode===EVIDENCE_FAILURE_CODES[variant];}
async function safeProgress(repoRoot,target,since,excludedHashes=new Set()){
 const prefix='artifacts/runs/owner-identity-bef-task-coordinator/lifecycle',folder=resolve(repoRoot,prefix),names=(await readdir(folder)).filter(x=>x.startsWith(target.runId+'-')&&x.endsWith('.json'));need(names.length<=1024,'BER_FAULT_PROGRESS_BOUND');
 for(const name of names){const path=resolve(folder,name),st=await lstat(path);if(st.isSymbolicLink()||!st.isFile()||st.size>512*1024||st.mtimeMs<since)continue;const bytes=await readFile(path),v=JSON.parse(bytes);
  if(isExpectedGenericSealEvidenceFailure(target.variant,v,target)&&!excludedHashes.has(hash(bytes)))return {path:prefix+'/'+name,sha256:hash(bytes),document:{schemaVersion:v.schemaVersion,runId:v.runId,taskIndex:v.taskIndex,status:v.status,stage:v.stage,reasonCode:v.reasonCode},modifiedAt:st.mtime.toISOString()};
 }return null;
}
async function progressHashes(repoRoot,target){const folder=resolve(repoRoot,'artifacts/runs/owner-identity-bef-task-coordinator/lifecycle'),names=(await readdir(folder)).filter(x=>x.startsWith(target.runId+'-')&&x.endsWith('.json'));need(names.length<=1024,'BER_FAULT_PROGRESS_BOUND');const hashes=new Set();for(const name of names){const st=await lstat(resolve(folder,name));need(!st.isSymbolicLink()&&st.isFile()&&st.size<=512*1024,'BER_FAULT_PROGRESS_SOURCE');hashes.add(hash(await readFile(resolve(folder,name))));}return hashes;}
export async function readClosureReference(repoRoot,ref){
 need(typeof ref.path==='string'&&SHA.test(ref.sha256??'')&&!ref.path.includes('\\')&&ref.path.split('/').every(p=>p&&p!=='.'&&p!=='..')&&!isAbsolute(ref.path),'BER_FAULT_CLOSURE_REF');
 const root=await realpath(repoRoot),path=resolve(root,...ref.path.split('/'));need(inside(root,path),'BER_FAULT_CLOSURE_ESCAPE');let cursor=root;for(const part of ref.path.split('/')){cursor=resolve(cursor,part);need(!(await lstat(cursor)).isSymbolicLink(),'BER_FAULT_CLOSURE_SYMLINK');}return readGenericSealFaultEvidence(path,ref.sha256);
}
export async function closureIntegrity(repoRoot,rootRef){
 const refs=[],seen=new Map(),pending=[rootRef];let total=0;
 const scan=v=>{if(!v||typeof v!=='object')return;if(typeof v.path==='string'&&typeof v.sha256==='string'){need(SHA.test(v.sha256),'BER_FAULT_CLOSURE_REF_HASH');pending.push({path:v.path,sha256:v.sha256});}for(const child of Object.values(v))scan(child);};
 while(pending.length){need(pending.length+refs.length<=1024,'BER_FAULT_CLOSURE_REF_BOUND');const ref=pending.shift();if(seen.has(ref.path)){need(seen.get(ref.path)===ref.sha256,'BER_FAULT_CONFLICTING_CLOSURE_REF');continue;}seen.set(ref.path,ref.sha256);const bytes=await readClosureReference(repoRoot,ref);total+=bytes.length;need(total<=MAX_ALL,'BER_FAULT_CLOSURE_AGGREGATE');refs.push({...ref,size:bytes.length});let parsed;try{parsed=JSON.parse(bytes);}catch{continue;}scan(parsed);}
 return refs;
}
export async function observeUnaffectedGenericSealClosure(repoRoot,refs,except){const inventory=[];for(const ref of refs)if(ref.path!==except.path){const bytes=await readClosureReference(repoRoot,ref);inventory.push({path:ref.path,sha256:hash(bytes),size:bytes.length});}return inventory;}

/** Acceptance integration API: arm before existing actor finish; execute after normal
 * finish response. No task actions, score computation, receipts or SQL updates.
 */
export async function armBerGenericSealFault(input){
 const target=validateGenericSealFaultScope(input),root=await realpath(input.repoRoot);await resolveGenericSealFaultPrivateDirectory(root,input.privateDirectory,{create:true});
 const {Client}=createRequire(resolve(root,'packages/owner-acceptance/package.json'))('pg');
 const controller=new Client({connectionString:input.databaseUrl,application_name:'ber-generic-seal-fault-controller-capture'}),observer=new Client({connectionString:input.observerDatabaseUrl,options:'-c default_transaction_read_only=on -c statement_timeout=5000'});
 let held=false,stopped=false,closed=false,controllerPid,staged;
 const proof={schemaVersion:'ber-generic-seal-evidence-fault/v1',classification:'acceptance_fault_raw_NOT_gate',target,checkpoints:[],fileIntervention:null};
 const save=async(name,value)=>{const path=resolve(input.privateDirectory,`${name}-${randomUUID()}.json`),bytes=JSON.stringify(value,null,2)+'\n';need(Buffer.byteLength(bytes)<=32*1024*1024,'BER_FAULT_PROOF_BOUND');await writeFile(path,bytes,{flag:'wx',mode:0o600});await chmod(path,0o400);return{path:relative(root,path).split(sep).join('/'),sha256:hash(bytes)};};
 const snapshot=async()=>{
  await observer.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');try{
   const identity=(await observer.query("SELECT current_user AS role,current_database() AS database_name,current_setting('transaction_read_only') AS read_only,current_setting('transaction_isolation') AS isolation,clock_timestamp() AS observed_at")).rows[0];
   need(identity.role==='oid_observer'&&identity.database_name===target.databaseName&&identity.read_only==='on'&&identity.isolation==='repeatable read','BER_FAULT_READONLY_IDENTITY');
   const q=async sql=>(await observer.query(sql,[target.runId,target.taskIndex])).rows;
   const run=await q('SELECT id,owner_id,agent_id,release_identity,manifest_hash,benchmark_hash,benchmark_version,policy_hash,mode,task_ids,quote_price_units::text,status,terminal_reason,cancellation_reason,overall_deadline FROM oid_benchmark_run WHERE id=$1::uuid AND $2::int>=0');
   const task=await q("SELECT run_id,task_index,task_id,status,closure_status,closure_id,closure_operation_id,closed_at,action_cutoff_sequence::text,reconciled_action_sequence::text,closed_at+interval '180 seconds' AS original_recovery_deadline FROM oid_run_task WHERE run_id=$1::uuid AND task_index=$2");
   const bundle=await q('SELECT run_id,task_index,bundle_hash,bundle_json FROM oid_run_task_observation_bundle WHERE run_id=$1::uuid AND task_index=$2');
   const evaluation=await q('SELECT run_id,task_index,closure_id,input_hash,input_json,result_hash,evaluator_source_hash,result_json FROM oid_run_task_evaluation WHERE run_id=$1::uuid AND task_index=$2');
   const actions=await q('SELECT a.id,a.run_id,a.owner_id,a.agent_id,a.task_id,a.environment_id,a.task_index,a.operation_id,a.action_sequence::text,a.payload_hash,a.action_kind,a.command_json,r.receipt_status,r.receipt_revision,r.evidence_path,r.evidence_hash,r.transaction_hash,h.revision AS history_revision,h.receipt_status AS history_status,h.evidence_hash AS history_evidence_hash,h.evidence_path AS history_evidence_path,h.transaction_hash AS history_transaction_hash FROM oid_run_task_action a LEFT JOIN oid_run_task_action_receipt r ON r.action_id=a.id LEFT JOIN LATERAL(SELECT * FROM oid_run_task_action_reconciliation WHERE action_id=a.id ORDER BY revision DESC LIMIT 1)h ON true WHERE a.run_id=$1::uuid AND a.task_index=$2 ORDER BY a.action_sequence');
   const closures=await q('SELECT id,run_id,task_index,reason,operation_id,payload_hash,answer_json,action_cutoff_sequence::text,requested_at FROM oid_run_task_closure WHERE run_id=$1::uuid AND task_index=$2');
   const preparations=await q('SELECT preparation_id,run_id,task_index,claim_id,lease_id,environment_id,release_identity,manifest_hash,task_id,case_id,case_hash,initial_state_sha256,execution_identity_hash,environment_manifest_sha256,application_source_hash,created_at::text AS created_at FROM oid_task_preparation_intent WHERE run_id=$1::uuid AND task_index=$2');
   const preparationObservations=await q('SELECT i.task_index,o.preparation_id,o.revision,o.status,o.generation_id,o.baseline_state_sha256,o.fixture_evidence,o.baseline_evidence FROM oid_task_preparation_intent i JOIN LATERAL(SELECT * FROM oid_task_preparation_observation WHERE preparation_id=i.preparation_id ORDER BY revision DESC LIMIT 1)o ON true WHERE i.run_id=$1::uuid AND i.task_index=$2');
   const executionBindings=await q('SELECT run_id,task_index,env_id,generation_id,manifest_hash,application_source_hash,participant_id,payer_address FROM oid_task_execution_binding WHERE run_id=$1::uuid AND task_index=$2');
   const money=await q("SELECT id,operation_id,entry_type,source_kind,amount_units::text,available_delta_units::text,reserved_delta_units::text FROM oid_ledger_entry WHERE owner_id=(SELECT owner_id FROM oid_benchmark_run WHERE id=$1::uuid) AND operation_id=ANY(ARRAY['runacc_'||replace($1::text,'-',''),'rundeb_'||replace($1::text,'-',''),'runrel_'||replace($1::text,'-','')]) AND $2::int>=0 ORDER BY operation_id,entry_type,id");
   const locks=(await observer.query("SELECT l.pid,l.mode,l.granted,pg_blocking_pids(l.pid) AS blocking_pids FROM pg_locks l WHERE l.relation='oid_run_task_observation_bundle'::regclass AND l.pid<>$1",[controllerPid])).rows;
   await observer.query('COMMIT');return{identity,run,task,bundle,evaluation,actions,closures,preparations,preparationObservations,executionBindings,money,locks};
  }catch(e){await observer.query('ROLLBACK').catch(()=>{});throw e;}
 };
 const release=async()=>{if(held){await controller.query('ROLLBACK');held=false;}};
 const wait=async(predicate,budget,code)=>{const until=Date.now()+budget;let last;do{last=await snapshot();if(await predicate(last))return last;await sleep(200);}while(Date.now()<until);throw Object.assign(new Error(code),{code,lastSafeSnapshot:last});};
 try{
  await controller.connect();await observer.connect();
  const identity=(await controller.query('SELECT current_user AS role,current_database() AS database_name,pg_backend_pid() AS pid')).rows[0];need(identity.role==='oid_owner'&&identity.database_name===target.databaseName,'BER_FAULT_CONTROLLER_IDENTITY');controllerPid=identity.pid;
  proof.controller={role:identity.role,databaseName:identity.database_name,pid:controllerPid};
  await controller.query('BEGIN');await controller.query("SET LOCAL lock_timeout='5s'");await controller.query('LOCK TABLE oid_run_task_observation_bundle IN SHARE MODE');held=true;
  proof.checkpoints.push({phase:'armed',ref:await save('armed',await snapshot())});
 }catch(e){await release().catch(()=>{});await observer.end().catch(()=>{});await controller.end().catch(()=>{});throw e;}
 return{
  async afterNormalFinish(finish){
   try{
    need(UUID.test(finish?.closureId??'')&&UUID.test(finish?.operationId??''),'BER_FAULT_ACTUAL_MCP_FINISH_REQUIRED');
    const blocked=await wait(s=>s.run[0]?.status==='running'&&s.run[0]?.mode===targetDefinition(target.targetProfile).mode&&JSON.stringify(s.run[0]?.task_ids)===JSON.stringify(targetDefinition(target.targetProfile).taskIds)&&s.task[0]?.task_id===target.taskId&&s.task[0]?.closure_status==='closed'&&s.task[0]?.action_cutoff_sequence===s.task[0]?.reconciled_action_sequence&&s.bundle.length===0&&s.evaluation.length===0&&s.locks.some(l=>!l.granted&&l.mode==='RowExclusiveLock'&&l.blocking_pids.includes(controllerPid)),15000,'BER_FAULT_SEAL_NOT_ACTUALLY_BLOCKED');
    const deadline=Date.parse(blocked.task[0].original_recovery_deadline);need(deadline-Date.now()>45000,'BER_FAULT_ORIGINAL_RECOVERY_HEADROOM');
    need(blocked.task[0].closure_id===finish.closureId&&blocked.task[0].closure_operation_id===finish.operationId,'BER_FAULT_MCP_CLOSURE_CHANGED');proof.actualMcpFinish={closureId:finish.closureId,operationId:finish.operationId};
    const retained=await discoverRoot(root,target);need(retained.value.closure.closureId===blocked.task[0].closure_id&&String(retained.value.closure.actionCutoffSequence)===blocked.task[0].action_cutoff_sequence,'BER_FAULT_ROOT_CLOSURE');
    proof.root=retained.ref;proof.selectedChild=await observeGenericSealFaultSelectedChild(root,target,retained.value,blocked.actions);proof.originalClosureIntegrity=await closureIntegrity(root,retained.ref);const priorProgressHashes=await progressHashes(root,target);proof.excludedPriorProgressHashes=[...priorProgressHashes];proof.checkpoints.push({phase:'seal_actually_blocked',ref:await save('seal-blocked',blocked)});
    if(target.variant==='restart_blocked_seal'){
     stopped=true;proof.stop=projectGenericSealFaultLifecycleReceipt(await input.stopApi(),'stop');
     const rolled=await wait(s=>!s.locks.some(l=>!l.granted&&l.blocking_pids.includes(controllerPid))&&s.bundle.length===0&&s.evaluation.length===0,10000,'BER_FAULT_STOP_ROLLBACK');proof.checkpoints.push({phase:'stopped_uncommitted_seal',ref:await save('stopped',rolled)});
     await release();proof.restart=projectGenericSealFaultLifecycleReceipt(await input.restartApi(),'restart');stopped=false;
    }else{
     const childRef=proof.selectedChild.evidence; // One declared child, never release/preparation/global material.
     staged=await stageGenericSealChildFault({repoRoot:root,target,ref:childRef,privateDirectory:input.privateDirectory,variant:target.variant});const since=Date.now();
     proof.fileIntervention={variant:target.variant,ref:childRef,originalArchive:staged.originalArchive,...(staged.changedArchive?{changedArchive:staged.changedArchive}:{}),afterIntervention:await staged.observe()};await release();
     let progress;const unavailable=await wait(async s=>{progress=await safeProgress(root,target,since,priorProgressHashes);if(!progress||s.run[0]?.status!=='running'||s.evaluation.length!==0)return false;proof.unaffectedClosureAtUnavailable=await observeUnaffectedGenericSealClosure(root,proof.originalClosureIntegrity,childRef);const changed=await staged.observe();need(!changed.matchesOriginal,'BER_FAULT_INTERVENTION_NOT_PRESENT');proof.fileIntervention.atUnavailable=changed;return true;},15000,'BER_FAULT_NO_ACTUAL_UNKNOWN_BOUNDARY');
     // Missing/corrupt file alone is not success: retain actual worker outcome and no-evaluation SQL.
     proof.checkpoints.push({phase:'actual_unavailable_no_evaluation',progress,ref:await save('unavailable',unavailable)});
     await staged.restore();proof.fileIntervention.afterRestoration=await staged.observe();need(proof.fileIntervention.afterRestoration.matchesOriginal,'BER_FAULT_EXACT_RESTORATION');
    }
    const known=await wait(s=>s.evaluation.length===1&&s.bundle.length===1&&s.evaluation[0].result_json?.status==='known',Math.min(20000,Math.max(1,deadline-Date.now()-1000)),'BER_FAULT_SAME_ID_KNOWN_RECOVERY_NOT_OBSERVED');
    need(known.task[0].closure_id===blocked.task[0].closure_id&&known.task[0].action_cutoff_sequence===blocked.task[0].action_cutoff_sequence,'BER_FAULT_CLOSURE_CHANGED');
    need(JSON.stringify(known.actions)===JSON.stringify(blocked.actions)&&JSON.stringify(known.money)===JSON.stringify(blocked.money),'BER_FAULT_ORIGINAL_ACTION_OR_FINANCE_CHANGED');
    proof.checkpoints.push({phase:'normal_worker_known_once',ref:await save('known-once',known)});proof.status='captured_subset_requires_independent_raw_replay';return await save('fault-capture',proof);
   }catch(e){proof.status='blocked';proof.failure={code:/^[A-Z0-9_]{1,100}$/.test(e.code??'')?e.code:'BER_GENERIC_FAULT_FAILED',errorClass:e?.constructor?.name};if(e.lastSafeSnapshot)proof.failure.snapshotRef=await save('failed-last-safe',e.lastSafeSnapshot);proof.failureRef=await save('fault-failure',proof);throw Object.assign(e,{berGenericFaultCapture:proof.failureRef});}
   finally{const failures=await runGenericSealFaultCleanupSteps([['restore_original_child',async()=>staged?.restore()],['release_database_lock',release],['restart_stopped_api',async()=>{if(stopped){projectGenericSealFaultLifecycleReceipt(await input.restartApi(),'restart');stopped=false;}}]]);if(failures.length){const cleanupRef=await save('cleanup-failures',{schemaVersion:'ber-generic-fault-cleanup-failures/v1',primaryFailureRef:proof.failureRef??null,failures});throw Object.assign(new Error('BER_FAULT_CLEANUP_FAILED'),{code:'BER_FAULT_CLEANUP_FAILED',cleanupRef,primaryFailureRef:proof.failureRef??null});}}
  },
  async close(){if(closed)return;closed=true;const failures=await runGenericSealFaultCleanupSteps([['restore_original_child',async()=>staged?.restore()],['release_database_lock',release],['restart_stopped_api',async()=>{if(stopped){projectGenericSealFaultLifecycleReceipt(await input.restartApi(),'restart');stopped=false;}}],['close_observer',async()=>observer.end()],['close_controller',async()=>controller.end()]]);if(failures.length){const ref=await save('close-failures',{schemaVersion:'ber-generic-fault-cleanup-failures/v1',primaryFailureRef:proof.failureRef??null,failures});throw Object.assign(new Error('BER_FAULT_CLEANUP_FAILED'),{code:'BER_FAULT_CLEANUP_FAILED',cleanupRef:ref});}},
 };
}
