import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,lstat,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,dirname,sep} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {finalizeAgentClientConnectionCapture} from './agent-client-connection-finalize.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
async function fixture(){
  const root=await mkdtemp(resolve(tmpdir(),'aci-finalizer-unit-')),captureId=randomUUID(),directory=`artifacts/runs/agent-client-connection/${captureId}`,epoch=randomUUID();
  async function put(path,value){await mkdir(dirname(resolve(root,path)),{recursive:true});const text=typeof value==='string'?value:JSON.stringify(value);await writeFile(resolve(root,path),text);return {path,sha256:hash(text)};}
  const paths=['packages/owner-acceptance/src/agent-client-connection-cases.mjs','packages/owner-acceptance/src/agent-client-connection-owner-case.mjs','packages/owner-acceptance/src/agent-client-connection-finalize.mjs','tools/run_aci_native.mjs','infrastructure/owner-identity/run-codex-google-local.mjs','packages/owner-identity/src/agent-mcp-acceptance-observer.ts'];
  const hashes={};for(const path of paths){const ref=await put(path,'synthetic source fixture '+path);hashes[path]=ref.sha256;}
  const turn={schemaVersion:'aci-native-turn/v1',captureId,kind:'preflight',authMethod:'native_oauth',client:'codex_cli',clientVersion:'0.165.0',promptSha256:'a'.repeat(64),sourcePins:{helperSha256:hashes['tools/run_aci_native.mjs'],baseHelperSha256:hashes['infrastructure/owner-identity/run-codex-google-local.mjs']},exitCode:0,terminalEvent:'turn.completed',mcpToolCallCount:1,localToolCallCount:0};
  await put(`.local/aci-native/${captureId}/response-1.json`,{...turn,arbitrarySecret:'DO_NOT_PERSIST_PRIVATE_SUMMARY_EXTRA_FIELDS'});
  await put(`${directory}/mcp-projections.jsonl`,JSON.stringify({epoch,sequence:1,phase:'request',projection:{method:'tools/list'}})+'\n');
  const statusPath=`${directory}/observer-${epoch}-status.json`;await put(statusPath,{schemaVersion:'aci-mcp-observer-status/v1',epoch,processId:12345,records:1,errors:[]});
  const partialRef=await put(`${directory}/capture-partial.json`,{schemaVersion:'agent-client-connection-partial/v1',captureId,provenance:{sourceStableDuringRun:true,inputHashesBefore:hashes,inputHashesAfter:hashes},result:{aci:{captureId,nativeTurns:[turn]}}});
  return {root,captureId,partialRef,put,directory,statusPath};
}
async function cleanup(root){if(!resolve(root).startsWith(resolve(tmpdir())+sep)||!root.split(sep).at(-1).startsWith('aci-finalizer-unit-'))throw new Error('unsafe_test_cleanup');await rm(root,{recursive:true,force:false});}
test('ACI finalizer emits a new immutable source-bound capture only after closed observer and preserves original partial',async()=>{
  const f=await fixture();try{
    const before=await readFile(resolve(f.root,f.partialRef.path));
    const ref=await finalizeAgentClientConnectionCapture({partialRef:f.partialRef,repoRoot:f.root,captureId:f.captureId,apiStopReceipt:{requested:true,exitCode:143,signal:null,processId:12345}});
    const text=await readFile(resolve(f.root,ref.path),'utf8'),proof=JSON.parse(text);
    assert.equal(hash(text),ref.sha256);assert.equal(text.includes('DO_NOT_PERSIST_PRIVATE_SUMMARY_EXTRA_FIELDS'),false);
    assert.equal(proof.schemaVersion,'agent-client-connection-capture/v1');assert.equal(proof.result.aci.finalizedAfterApiClose,true);
    assert.equal(proof.result.aci.nativeSourceReferences.length,1);assert.equal(proof.result.aci.observerStatusReferences.length,1);
    assert.deepEqual(await readFile(resolve(f.root,f.partialRef.path)),before);
    await assert.rejects(finalizeAgentClientConnectionCapture({partialRef:f.partialRef,repoRoot:f.root,captureId:f.captureId,apiStopReceipt:{requested:true,exitCode:143,signal:null,processId:12345}}),e=>e.code==='EEXIST');
  }finally{await cleanup(f.root);}
});
test('ACI finalizer fails closed on changed source, open/error observer and wrong native capture',async()=>{
  for(const variant of ['changed_source','missing_epoch','observer_error','wrong_capture','api_open']){
    const f=await fixture();try{
      if(variant==='changed_source')await f.put('tools/run_aci_native.mjs','new bytes after capture');
      if(variant==='missing_epoch')await rm(resolve(f.root,f.statusPath));
      if(variant==='observer_error'){const status=JSON.parse(await readFile(resolve(f.root,f.statusPath),'utf8'));await f.put(f.statusPath,{...status,errors:['write_failed']});}
      if(variant==='wrong_capture'){const path=`.local/aci-native/${f.captureId}/response-1.json`,turn=JSON.parse(await readFile(resolve(f.root,path),'utf8'));await f.put(path,{...turn,captureId:randomUUID()});}
      await assert.rejects(finalizeAgentClientConnectionCapture({partialRef:f.partialRef,repoRoot:f.root,captureId:f.captureId,apiStopReceipt:{requested:variant!=='api_open',exitCode:143,signal:null,processId:12345}}));
      assert.equal(await lstat(resolve(f.root,f.directory,'capture-final.json')).then(()=>true,()=>false),false);
    }finally{await cleanup(f.root);}
  }
});
