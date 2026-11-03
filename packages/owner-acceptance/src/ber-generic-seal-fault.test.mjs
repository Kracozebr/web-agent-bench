import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {BER_GENERIC_SEAL_FAULT_TARGETS,resolveBerGenericSealFaultTarget,observeGenericSealFaultSelectedChild,observeUnaffectedGenericSealClosure,validateGenericSealFaultScope,resolveGenericSealFaultCaptureFile,readGenericSealFaultEvidence,stageGenericSealChildFault,resolveGenericSealFaultPrivateDirectory,projectGenericSealFaultLifecycleReceipt,runGenericSealFaultCleanupSteps,isExpectedGenericSealEvidenceFailure,parseBerGenericSealFault,createBerGenericSealFaultSeam} from './ber-generic-seal-fault.mjs';
const runId='a54e5788-82ac-4d34-9eb4-3a650dc2f45d';
const target={runId,taskIndex:0,taskId:'S1'};
const hash=b=>createHash('sha256').update(b).digest('hex');
const scope={...target,variant:'missing_child',repoRoot:'/workspace',privateDirectory:'/workspace/.local/unit-only',databaseUrl:'postgres://oid_owner:synthetic@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',observerDatabaseUrl:'postgres://oid_observer:synthetic@postgres/oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',stopApi:async()=>{},restartApi:async()=>{}};
test('only exact isolated acceptance database and finite scope can arm',()=>{
 assert.equal(validateGenericSealFaultScope(scope).databaseName,'oid_acceptance_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
 for(const patch of [{variant:'anything'},{databaseUrl:'postgres://oid_owner:synthetic@postgres/oid_google_local_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'},{observerDatabaseUrl:'postgres://oid_observer:synthetic@postgres/oid_acceptance_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'},{observerDatabaseUrl:scope.databaseUrl},{runId:'not-a-uuid'},{taskIndex:12},{stopApi:null}])assert.throws(()=>validateGenericSealFaultScope({...scope,...patch}));
});
async function fixture(){const root=await mkdtemp(join(tmpdir(),'ber-seal-unit-')),privateDirectory=join(root,'.local','fault');await mkdir(privateDirectory,{recursive:true});const bytes=Buffer.from('{"schemaVersion":"unit-not-physical","amount":"7"}\n'),sha256=hash(bytes),path=`artifacts/runs/owner-identity-bef-task-coordinator/observation/${runId}/S1/${sha256}.json`;await mkdir(join(root,...path.split('/').slice(0,-1)),{recursive:true});await writeFile(join(root,path),bytes);return{root,privateDirectory,bytes,ref:{path,sha256},async cleanup(){assert.ok(resolve(root).startsWith(resolve(tmpdir())+'/')||resolve(root).startsWith(resolve(tmpdir())+'\\'));assert.match(root,/ber-seal-unit-/);await rm(root,{recursive:true,force:true});}};}
for(const variant of ['missing_child','corrupt_child'])test(`actual temporary-file ${variant} preserves original bytes and exact restore, never claims an unknown grade`,async()=>{
 const f=await fixture();try{const unrelated=join(f.privateDirectory,'unrelated.txt');await writeFile(unrelated,'preserve');const staged=await stageGenericSealChildFault({repoRoot:f.root,target,ref:f.ref,privateDirectory:f.privateDirectory,variant});
  const changed=await staged.observe();assert.equal(changed.matchesOriginal,false);assert.equal(changed.exists,variant==='corrupt_child');assert.equal(hash(await readFile(join(f.root,staged.originalArchive.path))),f.ref.sha256);
  if(variant==='corrupt_child'){assert.equal(hash(await readFile(join(f.root,staged.changedArchive.path))),changed.sha256);assert.notEqual(staged.changedArchive.sha256,f.ref.sha256);}else assert.equal(changed.directoryEntries.includes(f.ref.sha256+'.json'),false);
  assert.equal(staged.status,undefined);assert.equal(staged.grade,undefined);assert.equal(staged.facts,undefined);
  await staged.restore();await staged.restore();assert.deepEqual(await readFile(join(f.root,f.ref.path)),f.bytes);assert.equal((await staged.observe()).matchesOriginal,true);assert.equal(await readFile(unrelated,'utf8'),'preserve');
 }finally{await f.cleanup();}
});
test('wrong hash fails before archiving or changing original capture file',async()=>{const f=await fixture();try{await assert.rejects(stageGenericSealChildFault({repoRoot:f.root,target,ref:{...f.ref,sha256:'0'.repeat(64)},privateDirectory:f.privateDirectory,variant:'missing_child'}));assert.deepEqual(await readFile(join(f.root,f.ref.path)),f.bytes);assert.equal((await readdir(f.privateDirectory)).length,0);}finally{await f.cleanup();}});
test('foreign run, preparation path, filename/hash mismatch and symlink are rejected',async()=>{const f=await fixture();try{
 for(const path of [f.ref.path.replace(runId,'b54e5788-82ac-4d34-9eb4-3a650dc2f45d'),f.ref.path.replace('/observation/','/preparation/'),f.ref.path.replace(f.ref.sha256,'0'.repeat(64))])await assert.rejects(resolveGenericSealFaultCaptureFile(f.root,target,{...f.ref,path}));
 const foreign=join(f.root,'foreign.json');await writeFile(foreign,f.bytes);await rm(join(f.root,f.ref.path));await symlink(foreign,join(f.root,f.ref.path));await assert.rejects(resolveGenericSealFaultCaptureFile(f.root,target,f.ref),/BER_FAULT_SYMLINK/);
 }finally{await f.cleanup();}
});
test('read boundary rejects over-8MiB file without treating truncation as valid evidence',async()=>{const f=await fixture();try{await writeFile(join(f.root,f.ref.path),Buffer.alloc(8*1024*1024+1,0x20));await assert.rejects(readGenericSealFaultEvidence(join(f.root,f.ref.path),f.ref.sha256),/BER_FAULT_EVIDENCE_SIZE/);}finally{await f.cleanup();}});
test('archive root is strictly .local and rejects symlink ancestry before creation',async()=>{const f=await fixture();try{
 await assert.rejects(resolveGenericSealFaultPrivateDirectory(f.root,join(f.root,'docs','private-by-mistake'),{create:true}),/BER_FAULT_PRIVATE_LOCAL_REQUIRED/);
 const foreign=await mkdtemp(join(tmpdir(),'ber-archive-negative-'));try{await symlink(foreign,join(f.root,'.local','escape'));await assert.rejects(resolveGenericSealFaultPrivateDirectory(f.root,join(f.root,'.local','escape','new'),{create:true}),/BER_FAULT_PRIVATE_SYMLINK/);assert.equal((await readdir(foreign)).length,0);}finally{assert.match(foreign,/ber-archive-negative-/);await rm(foreign,{recursive:true,force:true});}
 }finally{await f.cleanup();}});
test('cleanup restoration failure never skips lock release or required restart',async()=>{const calls=[];const errors=await runGenericSealFaultCleanupSteps([['restore',async()=>{calls.push('restore');throw Error('synthetic-private-message-not-persisted');}],['release',async()=>{calls.push('release');}],['restart',async()=>{calls.push('restart');}]]);assert.deepEqual(calls,['restore','release','restart']);assert.deepEqual(errors,[{step:'restore',errorClass:'Error',code:'BER_FAULT_CLEANUP_STEP_FAILED'}]);});
test('actual lifecycle receipts require real PID/exit/health and retain only finite known safe fields',()=>{const value={schemaVersion:'beta-local-api-restart-receipt/v1',previousPid:123,currentPid:124,healthHttpStatus:200,startedAt:'2026-11-02T12:00:00.000Z',password:'synthetic-do-not-store',authorization:'synthetic',unexpected:{secret:'synthetic'}},out=projectGenericSealFaultLifecycleReceipt(value,'restart');assert.deepEqual(Object.keys(out).sort(),['schemaVersion','previousPid','currentPid','healthHttpStatus','startedAt'].sort());for(const patch of [{previousPid:undefined},{currentPid:undefined},{previousPid:0},{currentPid:123},{healthHttpStatus:503}])assert.throws(()=>projectGenericSealFaultLifecycleReceipt({...value,...patch},'restart'));assert.throws(()=>projectGenericSealFaultLifecycleReceipt({schemaVersion:'wrong'},'stop'));assert.throws(()=>projectGenericSealFaultLifecycleReceipt({schemaVersion:'beta-local-api-stop-receipt/v1',previousPid:123},'stop'));assert.equal(projectGenericSealFaultLifecycleReceipt({schemaVersion:'beta-local-api-stop-receipt/v1',previousPid:123,exitCode:0},'stop').exitCode,0);});
test('only exact actual variant-specific sealed-file code and target can prove the failure boundary',()=>{const v={schemaVersion:'local-bef-task-observation-progress/v1',runId,taskIndex:0,status:'unavailable',stage:'seal',reasonCode:'TASK_EVIDENCE_FILE_UNAVAILABLE'};assert.equal(isExpectedGenericSealEvidenceFailure('missing_child',v,target),true);assert.equal(isExpectedGenericSealEvidenceFailure('corrupt_child',{...v,stage:'reload',reasonCode:'TASK_EVIDENCE_FILE_HASH_MISMATCH'},target),true);for(const patch of [{reasonCode:'TASK_EVIDENCE_CAPTURE_BINDING_MISMATCH'},{reasonCode:'TASK_EVIDENCE_FILE_HASH_MISMATCH'},{stage:'observe'},{taskIndex:1},{runId:'b54e5788-82ac-4d34-9eb4-3a650dc2f45d'},{status:'task_terminalized'}])assert.equal(isExpectedGenericSealEvidenceFailure('missing_child',{...v,...patch},target),false);assert.equal(isExpectedGenericSealEvidenceFailure('restart_blocked_seal',v,target),false);});
test('finite environment selector is legal only with the exact existing disposable S1 CLI profile',()=>{
 assert.equal(parseBerGenericSealFault(['--ber-admitted-s1-pay-only'],{}),null);
 for(const variant of ['missing_child','corrupt_child','restart_blocked_seal'])assert.equal(parseBerGenericSealFault(['--ber-admitted-s1-pay-only'],{OID_BER_GENERIC_SEAL_FAULT:variant}),variant);
 for(const argv of [[],['--ber-admitted-matrix-training-a'],['--ber-admitted-s1-pay-only','--smoke'],['--platform-recovery-only']])assert.throws(()=>parseBerGenericSealFault(argv,{OID_BER_GENERIC_SEAL_FAULT:'missing_child'}),/PROFILE_REQUIRED/);
 for(const env of [{OID_BETA_MANIFEST_FILE:'private.json'},{OID_BER_RECOVERY_CORE:'1'},{OID_BER_H1_CUTOFF:'1'},{OID_BER_UNKNOWN_GRADING:'1'},{OID_BER_INTERRUPT_BEFORE_FIRST_REFUND:'1'}])assert.throws(()=>parseBerGenericSealFault(['--ber-admitted-s1-pay-only'],{OID_BER_GENERIC_SEAL_FAULT:'missing_child',...env}),/PROFILE_REQUIRED/);
 assert.throws(()=>parseBerGenericSealFault(['--ber-admitted-s1-pay-only'],{OID_BER_GENERIC_SEAL_FAULT:'arbitrary'}),/VARIANT/);
});
test('acceptance holder binds the one actual finish identity and exposes no callback or database credentials',async()=>{
 const calls=[],evidence={path:'.local/unit-proof.json',sha256:'1'.repeat(64)};
 const seam=createBerGenericSealFaultSeam({...scope,captureId:runId},{arm:async input=>{calls.push({phase:'arm',runId:input.runId,privateDirectory:input.privateDirectory});return{afterNormalFinish:async f=>{calls.push({phase:'after',...f});return evidence;},close:async()=>{calls.push({phase:'close'});}};}});
 await assert.rejects(seam.beforeFinish({...target,taskId:'S2'}),/SINGLE_S1_TARGET/);assert.equal(calls.length,0);
 await seam.beforeFinish(target);await assert.rejects(seam.beforeFinish(target),/SINGLE_S1_TARGET/);
 const finish={...target,closureId:'b54e5788-82ac-4d34-9eb4-3a650dc2f45d',operationId:'c54e5788-82ac-4d34-9eb4-3a650dc2f45d'};
 await assert.rejects(seam.afterFinish({...finish,runId:finish.closureId}),/FINISH_IDENTITY/);
 await seam.afterFinish(finish);await assert.rejects(seam.afterFinish(finish),/FINISH_IDENTITY/);await seam.close();await seam.close();
 assert.deepEqual(calls.map(x=>x.phase),['arm','after','close']);assert.deepEqual(calls[1],{phase:'after',closureId:finish.closureId,operationId:finish.operationId});
 assert.deepEqual(seam.snapshot(),{schemaVersion:'ber-generic-seal-fault-seam/v1',variant:'missing_child',targetProfile:'paid_s1',status:'captured',evidence});assert.equal(JSON.stringify(seam.snapshot()).includes('synthetic'),false);
});

test('unavailable-window inventory retains actual unaffected bytes and excludes only the selected child',async()=>{
 const f=await fixture();try{
  const bytes=Buffer.from('{"schemaVersion":"unit-unaffected","value":3}\n'),ref={path:f.ref.path.replace(f.ref.sha256,hash(bytes)),sha256:hash(bytes)};await writeFile(join(f.root,ref.path),bytes);
  const staged=await stageGenericSealChildFault({repoRoot:f.root,target,ref:f.ref,privateDirectory:f.privateDirectory,variant:'missing_child'});
  try{assert.equal((await staged.observe()).exists,false);const proof={unaffectedClosureAtUnavailable:await observeUnaffectedGenericSealClosure(f.root,[{...f.ref,size:f.bytes.length},{...ref,size:bytes.length}],f.ref)},retained=JSON.stringify(proof);
   assert.deepEqual(proof.unaffectedClosureAtUnavailable,[{...ref,size:bytes.length}]);
   await writeFile(join(f.root,ref.path),'different-later-bytes');assert.deepEqual(JSON.parse(retained).unaffectedClosureAtUnavailable,[{...ref,size:bytes.length}]);
   await assert.rejects(observeUnaffectedGenericSealClosure(f.root,[f.ref,ref],f.ref),/BER_FAULT_EVIDENCE_HASH/);
  }finally{await staged.restore();}
 }finally{await f.cleanup();}
});

test('finite paid/chain/composite target registry binds exactly one CLI and optional matching target, never arbitrary task/profile',()=>{
 for(const [targetProfile,d]of Object.entries(BER_GENERIC_SEAL_FAULT_TARGETS))for(const variant of ['missing_child','corrupt_child','restart_blocked_seal']){
  assert.equal(parseBerGenericSealFault([d.flag],{OID_BER_GENERIC_SEAL_FAULT:variant}),variant);assert.equal(resolveBerGenericSealFaultTarget([d.flag],{OID_BER_GENERIC_SEAL_FAULT_TARGET:targetProfile}),targetProfile);
  const value={...scope,targetProfile,taskId:d.taskId,taskIndex:d.taskIndex};assert.equal(validateGenericSealFaultScope(value).targetProfile,targetProfile);
  for(const other of Object.keys(BER_GENERIC_SEAL_FAULT_TARGETS).filter(k=>k!==targetProfile))assert.throws(()=>parseBerGenericSealFault([d.flag],{OID_BER_GENERIC_SEAL_FAULT:variant,OID_BER_GENERIC_SEAL_FAULT_TARGET:other}));
  assert.throws(()=>validateGenericSealFaultScope({...value,taskIndex:d.taskIndex===0?1:10}));
 }
 assert.throws(()=>parseBerGenericSealFault(['--ber-admitted-matrix-ranked-b'],{OID_BER_GENERIC_SEAL_FAULT:'missing_child'}));assert.throws(()=>parseBerGenericSealFault(['--ber-composite-mixed'],{OID_BER_GENERIC_SEAL_FAULT:'missing_child'}));assert.throws(()=>parseBerGenericSealFault(['--ber-admitted-s1-pay-only'],{OID_BER_GENERIC_SEAL_FAULT_TARGET:'paid_s1'}));assert.throws(()=>validateGenericSealFaultScope({...scope,targetProfile:'arbitrary'}));
});
test('matrix holder targets only selected task and retains original single finish identity for chain and composite',async()=>{
 for(const targetProfile of ['chain_s1','composite_u1']){const d=BER_GENERIC_SEAL_FAULT_TARGETS[targetProfile],calls=[],seam=createBerGenericSealFaultSeam({...scope,captureId:runId,targetProfile},{arm:async input=>{calls.push(input);return {afterNormalFinish:async finish=>{calls.push(finish);return {path:'.local/unit.json',sha256:'a'.repeat(64)};},close:async()=>calls.push('close')};}});
  assert.equal(seam.matchesTarget({taskId:d.taskId,taskIndex:d.taskIndex}),true);assert.equal(seam.matchesTarget({taskId:'H1',taskIndex:8}),false);assert.equal(calls.length,0);
  await assert.rejects(seam.beforeFinish({runId,taskId:'H1',taskIndex:8}));await seam.beforeFinish({runId,taskId:d.taskId,taskIndex:d.taskIndex});const operationId='b54e5788-82ac-4d34-9eb4-3a650dc2f45d',closureId='c54e5788-82ac-4d34-9eb4-3a650dc2f45d';
  await seam.afterFinish({runId,taskId:d.taskId,taskIndex:d.taskIndex,operationId,closureId});await seam.close();assert.equal(calls[0].targetProfile,targetProfile);assert.deepEqual(calls[1],{operationId,closureId});assert.equal(calls.filter(x=>x==='close').length,1);
 }
});
test('selected chain fault child must be actual same-bound family with a retained original owner receipt and real transaction row',async()=>{
 const f=await fixture();try{
  const actionId='b54e5788-82ac-4d34-9eb4-3a650dc2f45d',befOperationId='c54e5788-82ac-4d34-9eb4-3a650dc2f45d',tx='0x'+'d'.repeat(64),actionEvidence={path:'artifacts/runs/unit/source.json',sha256:'c'.repeat(64)},binding={runId,taskId:'S1'},execution={environmentId:'bef-env-a',generationId:befOperationId},closure={closureId:actionId,actionCutoffSequence:1,reconciledActionSequence:1};
  const child={schemaVersion:'bts-chain-family-observation-capture/v1',binding,execution,closure,ownerActions:[{actionId,befOperationId,ownerOperationId:runId,commandSha256:'a'.repeat(64),actionSequence:1,actionKind:'wrap',transactionHash:tx,actionEvidence}],bef:{before:{operations:[{operationId:befOperationId,environmentId:'bef-env-a',generationId:befOperationId,actionKind:'wrap',idempotencyKeySha256:hash('task-action-'+actionId),transactionHash:tx}],selectedExecutions:[{operationId:befOperationId,environmentId:'bef-env-a',generationId:befOperationId,actionKind:'wrap',transactionHash:tx,outcome:'success'}]}},rpc:{transactions:[{hash:tx,status:'success'}]}};
  const owner=[{id:actionId,run_id:runId,task_id:'S1',task_index:0,action_kind:'wrap',operation_id:runId,payload_hash:'a'.repeat(64),action_sequence:'1',receipt_status:'observed',transaction_hash:tx,evidence_path:actionEvidence.path,evidence_hash:actionEvidence.sha256}];
  const save=async value=>{const bytes=Buffer.from(JSON.stringify(value)),ref={path:f.ref.path.replace(f.ref.sha256,hash(bytes)),sha256:hash(bytes)};await writeFile(join(f.root,ref.path),bytes);return ref;};
  const ref=await save(child),root={binding,execution,closure:{...closure,operationId:runId,payloadHash:'e'.repeat(64),reason:'agent_finish'},taskIndex:0,children:{chain:{evidence:ref}}},t={...target,targetProfile:'chain_s1'};
  const actual=await observeGenericSealFaultSelectedChild(f.root,t,root,owner);assert.equal(actual.selectedTransactions.length,1);assert.equal(actual.evidence.sha256,ref.sha256);
  for(const change of [x=>{x.binding.runId=befOperationId;},x=>{x.schemaVersion='bts-paid-family-observation-capture/v1';},x=>{x.ownerActions=[];},x=>{x.rpc.transactions=[];},x=>{x.rpc.transactions[0].status='reverted';},x=>{x.ownerActions[0].actionSequence=2;},x=>{x.bef.before.operations[0].idempotencyKeySha256='0'.repeat(64);},x=>{x.bef.before.selectedExecutions[0].operationId=runId;},x=>{x.ownerActions[0].transactionHash='0x'+'e'.repeat(64);}]){const bad=structuredClone(child);change(bad);await assert.rejects(observeGenericSealFaultSelectedChild(f.root,t,{...root,children:{chain:{evidence:await save(bad)}}},owner));}
  for(const patch of [{receipt_status:'unknown'},{evidence_hash:'f'.repeat(64)},{task_id:'H1'},{transaction_hash:'0x'+'e'.repeat(64)}])await assert.rejects(observeGenericSealFaultSelectedChild(f.root,t,root,[{...owner[0],...patch}]));
 }finally{await f.cleanup();}
});

test('holder close failure retains validated cleanup evidence and the original fault capture independently',async()=>{
 const evidence={path:'.local/original-fault.json',sha256:'1'.repeat(64)},cleanupRef={path:'.local/ber-generic-fault/'+runId+'/missing_child/cleanup.json',sha256:'2'.repeat(64)};
 const seam=createBerGenericSealFaultSeam({...scope,captureId:runId},{arm:async()=>({afterNormalFinish:async()=>evidence,close:async()=>{throw Object.assign(Error('private-not-retained'),{cleanupRef});}})});
 await seam.beforeFinish(target);await seam.afterFinish({...target,operationId:'b54e5788-82ac-4d34-9eb4-3a650dc2f45d',closureId:'c54e5788-82ac-4d34-9eb4-3a650dc2f45d'});await assert.rejects(seam.close());assert.equal(seam.snapshot().status,'blocked');assert.deepEqual(seam.snapshot().evidence,cleanupRef);assert.deepEqual(seam.snapshot().primaryEvidence,evidence);assert(!JSON.stringify(seam.snapshot()).includes('private-not-retained'));await seam.close();
});

test('foreign or malformed cleanup refs cannot enter holder capture even if thrown by a callback',async()=>{
 for(const cleanupRef of [{path:'https://outside.invalid/secret',sha256:'2'.repeat(64)},{path:'.local/ber-generic-fault/'+runId+'/../foreign.json',sha256:'2'.repeat(64)},{path:'.local/ber-generic-fault/'+runId+'/missing_child/a.json',sha256:'invalid'}]){const seam=createBerGenericSealFaultSeam({...scope,captureId:runId},{arm:async()=>({close:async()=>{throw Object.assign(Error('unretained'),{cleanupRef});}})});await seam.beforeFinish(target);await assert.rejects(seam.close());assert.equal(seam.snapshot().evidence,undefined);assert.equal(seam.snapshot().status,'blocked');}
});
